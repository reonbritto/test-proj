"""FastAPI application for CWE Explorer - PureSecure."""
import logging
import os
import time
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.routing import Route
from typing import List
from .models import CWEEntry, CVEDetail, CVESearchResult, CWEStats, CWERiskScore
from .cwe_parser import get_cwe_data, fetch_cwe_from_nvd
from .nvd_client import get_cve, search_cves
from .security import validate_cve_id, validate_cwe_id, sanitize_search_query
from .metrics import PrometheusMiddleware, metrics_endpoint
from .auth import get_current_user
from . import cache
from . import analytics

logger = logging.getLogger("cwe-explorer")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

# In-memory CWE data loaded at startup
cwe_data: List[CWEEntry] = []
cwe_dict: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load CWE data and clean expired cache at startup."""
    global cwe_data, cwe_dict
    cwe_data = get_cwe_data()
    cwe_dict = {entry.id: entry for entry in cwe_data}
    removed = cache.cleanup_expired()
    logger.info("Startup: loaded %d CWEs, purged %d expired cache entries",
                len(cwe_data), removed)
    yield


app = FastAPI(
    title="CWE Explorer - PureSecure",
    description="Security weakness database powered by MITRE CWE XML "
                "with NVD CVE cross-referencing, built for Assimilate.",
    version="1.0.0",
    lifespan=lifespan,
    routes=[Route("/metrics", metrics_endpoint)],
)

# CORS — allow browser-based MSAL.js auth flow
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_headers=["Authorization", "Content-Type"],
    allow_methods=["GET"],
)

# Prometheus instrumentation
app.add_middleware(PrometheusMiddleware)


# -- Request logging ---------------------------------------------------


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log every request with method, path, status, and duration."""
    start = time.perf_counter()
    response = await call_next(request)
    ms = (time.perf_counter() - start) * 1000
    logger.info("%s %s %d %.0fms",
                request.method, request.url.path,
                response.status_code, ms)
    return response


# -- Public Endpoints (no auth) ----------------------------------------


@app.get("/api/health")
def api_health():
    """Health check with cache stats (public)."""
    stats = cache.get_cache_stats()
    return {
        "status": "healthy",
        "cwe_count": len(cwe_data),
        "cache": stats,
    }


@app.get("/api/config")
def api_config():
    """Return Entra ID client config for MSAL.js (public)."""
    return {
        "client_id": os.environ.get("AZURE_CLIENT_ID", ""),
        "tenant_id": os.environ.get("AZURE_TENANT_ID", ""),
    }


# -- CWE Endpoints (auth required) ------------------------------------


@app.get("/api/cwe", response_model=List[CWEEntry])
def api_search_cwes(
    query: str = Query(
        None, description="Search by ID or Name substring"
    ),
    limit: int = Query(10, le=100),
    _user: dict = Depends(get_current_user),
):
    """Search for CWEs by string query."""
    if not query:
        return cwe_data[:limit]

    query_lower = sanitize_search_query(query).lower()
    results = [
        cwe for cwe in cwe_data
        if query_lower in cwe.name.lower()
        or query_lower in cwe.id.lower()
        or query_lower in cwe.description.lower()
    ]
    return results[:limit]


@app.get("/api/cwe/suggestions")
def api_cwe_suggestions(
    q: str = Query(..., min_length=1, description="Search prefix"),
    _user: dict = Depends(get_current_user),
):
    """Get CWE search suggestions based on partial input."""
    q = sanitize_search_query(q)
    suggestions = []

    q_lower = q.lower()

    # Check if it looks like a CWE ID
    cwe_match = q.replace("CWE-", "").replace("cwe-", "").strip()
    if cwe_match.isdigit():
        matched = [
            cwe for cwe in cwe_data
            if cwe.id.startswith(cwe_match)
        ][:5]
        for cwe in matched:
            suggestions.append({
                "type": "cwe",
                "text": f"CWE-{cwe.id}: {cwe.name}",
                "action": f"/cwe.html?id={cwe.id}"
            })
        if not matched:
            suggestions.append({
                "type": "tip",
                "text": f"No CWE found with ID starting with {cwe_match}",
                "action": ""
            })
        return suggestions[:8]

    # Suggest matching CWEs by name
    matched_cwes = [
        cwe for cwe in cwe_data
        if q_lower in cwe.name.lower()
        or q_lower in cwe.description.lower()
    ][:6]
    for cwe in matched_cwes:
        suggestions.append({
            "type": "cwe",
            "text": f"CWE-{cwe.id}: {cwe.name}",
            "action": f"/cwe.html?id={cwe.id}"
        })

    # Suggest keyword searches for common weakness categories
    common_topics = [
        "injection", "authentication", "authorization",
        "buffer overflow", "cross-site scripting", "cryptographic",
        "input validation", "memory", "race condition",
        "deserialization", "path traversal", "privilege",
        "resource management", "information disclosure",
        "command injection", "file upload"
    ]
    matched_topics = [
        t for t in common_topics if q_lower in t
    ][:3]
    for topic in matched_topics:
        suggestions.append({
            "type": "keyword",
            "text": topic.title(),
            "action": f"/search.html?keyword={topic}"
        })

    return suggestions[:8]


@app.get("/api/cwe/{cwe_id}", response_model=CWEEntry)
async def api_get_cwe(
    cwe_id: str,
    _user: dict = Depends(get_current_user),
):
    """Retrieve a single CWE by its numeric ID."""
    cwe_id = validate_cwe_id(cwe_id)
    if cwe_id in cwe_dict:
        return cwe_dict[cwe_id]
    result = await fetch_cwe_from_nvd(cwe_id)
    if not result:
        raise HTTPException(status_code=404, detail="CWE not found")
    return result


@app.get("/api/cwe/{cwe_id}/cves", response_model=List[CVESearchResult])
async def api_get_cwe_cves(
    cwe_id: str,
    _user: dict = Depends(get_current_user),
):
    """Get CVEs associated with a specific CWE."""
    cwe_id = validate_cwe_id(cwe_id)
    results = await search_cves(cwe_id=f"CWE-{cwe_id}")
    return results


# -- CVE Detail Endpoint (cross-reference from CWE pages) -----------


@app.get("/api/cve/{cve_id}", response_model=CVEDetail)
async def api_get_cve(
    cve_id: str,
    _user: dict = Depends(get_current_user),
):
    """Get full details for a specific CVE."""
    cve_id = validate_cve_id(cve_id)
    result = await get_cve(cve_id)
    if not result:
        raise HTTPException(status_code=404, detail="CVE not found")
    return result


# -- Analytics Endpoints ---------------------------------------------


@app.get("/api/analytics/top-cwes", response_model=List[CWEStats])
def api_top_cwes(
    limit: int = Query(10, le=50),
    _user: dict = Depends(get_current_user),
):
    """Get CWEs with the most associated CVEs."""
    all_cves = cache.get_all_cached_cves()
    return analytics.top_cwes(all_cves, cwe_dict, limit=limit)


@app.get("/api/analytics/cwe-risk", response_model=List[CWERiskScore])
def api_cwe_risk_scores(
    limit: int = Query(15, le=50),
    _user: dict = Depends(get_current_user),
):
    """CWE risk scores combining real-world frequency and severity.

    Cross-references CWE definitions (from MITRE XML) with cached
    CVE data (from NVD) to produce a composite risk ranking not
    available from either source alone.
    """
    all_cves = cache.get_all_cached_cves()
    return analytics.cwe_risk_scores(all_cves, cwe_dict, limit=limit)


# -- Static Files (must be last) ------------------------------------

static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir)

app.mount(
    "/", StaticFiles(directory=static_dir, html=True), name="static"
)
