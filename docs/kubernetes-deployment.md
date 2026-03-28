# Kubernetes Deployment Guide — PureSecure CVE Explorer

Deploy the PureSecure CVE Explorer on **Docker Desktop Kubernetes** for local development and testing.

---

## Prerequisites

| Tool | Install |
|------|---------|
| **Docker Desktop** | <https://docs.docker.com/desktop/install/windows-install/> |
| **kubectl** | Bundled with Docker Desktop |

Enable Kubernetes in Docker Desktop: **Settings > Kubernetes > Enable Kubernetes > Apply & Restart**.

Verify:

```bash
docker --version
kubectl version --client
kubectl get nodes
```

Expected node output:

```
NAME             STATUS   ROLES           AGE   VERSION
docker-desktop   Ready    control-plane   ...   v1.x.x
```

---

## Architecture Overview

The application deploys 4 services into a `puresecure` namespace:

```
                        ┌──────────────────────────────────┐
                        │         puresecure namespace      │
                        │                                   │
  User ──► localhost ─► │  ┌──────────┐                    │
         (port-forward) │  │   web     │ ◄── FastAPI app    │
                        │  │  :8000    │     (port 8000)    │
                        │  └────┬─────┘                     │
                        │       │ /metrics                  │
                        │  ┌────▼──────┐  ┌────────────┐   │
                        │  │prometheus │  │   locust    │   │
                        │  │  :9090    │  │   :8089     │   │
                        │  └────┬──────┘  └────────────┘   │
                        │       │                           │
                        │  ┌────▼──────┐                    │
                        │  │  grafana  │ ◄── Dashboards     │
                        │  │  :3000    │     (port 3000)    │
                        │  └───────────┘                    │
                        └──────────────────────────────────┘
```

| Component | Image | Purpose |
|-----------|-------|---------|
| **web** | `reonbritto/puresecure-cve-explorer:latest` | FastAPI application |
| **prometheus** | `prom/prometheus:v2.51.2` | Metrics collection |
| **grafana** | `grafana/grafana:10.4.2` | Monitoring dashboards |
| **locust** | `locustio/locust:2.24.1` | Load testing UI |

---

## Quick Start

```bash
cp .env.example .env
# Edit .env with your actual Azure, API key, and Grafana values

export $(grep -v '^#' .env | xargs)
chmod +x k8s/setup.sh
./k8s/setup.sh
```

The script will:
1. Create the `puresecure` namespace
2. Create secrets from environment variables
3. Deploy all services (app, Prometheus, Grafana, Locust)
4. Wait for pods to be ready
5. Print access URLs

> **Note:** `setup.sh` requires `SERVICE_API_KEY` and `GF_ADMIN_PASSWORD` environment variables to be set. It will exit with an error if they are missing.

---

## Step-by-Step Deployment

### 1. Enable Kubernetes

Open Docker Desktop > **Settings > Kubernetes > Enable Kubernetes** > Apply & Restart.

Wait for the Kubernetes status icon (bottom-left) to turn green.

### 2. Build or Load the Docker Image

**Option A: Pull from Docker Hub**

No action needed. The deployment pulls `reonbritto/puresecure-cve-explorer:latest` automatically.

**Option B: Build locally**

```bash
docker build -t reonbritto/puresecure-cve-explorer:latest .
```

Since Docker Desktop Kubernetes shares the Docker daemon, locally built images are immediately available — no extra loading step required.

### 3. Create the Namespace

```bash
kubectl apply -f k8s/namespace.yaml
```

### 4. Create Secrets

**Both keys are required** — `SERVICE_API_KEY` is used by the app for Locust/monitoring auth, and `GF_ADMIN_PASSWORD` is used by Grafana. If either is missing, the corresponding pod will fail to start.

First, copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
# Edit .env with your actual values
```

Then create the secret from your `.env` file:

```bash
export $(grep -v '^#' .env | xargs)

kubectl create secret generic app-secrets \
  --namespace=puresecure \
  --from-literal=SERVICE_API_KEY="$SERVICE_API_KEY" \
  --from-literal=GF_ADMIN_PASSWORD="$GF_ADMIN_PASSWORD" \
  --dry-run=client -o yaml | kubectl apply -f -
```

> **Tip:** If Grafana fails with `couldn't find key GF_ADMIN_PASSWORD in Secret`, re-run the command above to recreate the secret with both keys, then restart Grafana: `kubectl rollout restart deployment/grafana -n puresecure`

### 5. Update the ConfigMap

Edit `k8s/app/configmap.yaml` and set your Azure Entra ID values:

```yaml
AZURE_TENANT_ID: "your-tenant-id"
AZURE_CLIENT_ID: "your-client-id"
```

### 6. Deploy All Services

```bash
kubectl apply -f k8s/app/ -f k8s/prometheus/ -f k8s/grafana/ -f k8s/locust/
```

### 6. Verify the Deployment

```bash
kubectl rollout status deployment/cwe-explorer -n puresecure --timeout=300s
kubectl rollout status deployment/prometheus -n puresecure --timeout=60s
kubectl rollout status deployment/grafana -n puresecure --timeout=60s
kubectl rollout status deployment/locust -n puresecure --timeout=60s
```

Check pods:

```bash
kubectl get pods -n puresecure
```

Expected:

```
NAME                            READY   STATUS    RESTARTS   AGE
cwe-explorer-xxxxxxxxxx-xxxxx   1/1     Running   0          1m
prometheus-xxxxxxxxxx-xxxxx     1/1     Running   0          1m
grafana-xxxxxxxxxx-xxxxx        1/1     Running   0          1m
locust-xxxxxxxxxx-xxxxx         1/1     Running   0          1m
```

### 7. Access the Application

Use port-forwarding to access each service:

```bash
# Terminal 1 — Web app
kubectl port-forward svc/web 8000:8000 -n puresecure

# Terminal 2 — Grafana
kubectl port-forward svc/grafana 3000:3000 -n puresecure

# Terminal 3 — Prometheus
kubectl port-forward svc/prometheus 9090:9090 -n puresecure

# Terminal 4 — Locust
kubectl port-forward svc/locust 8089:8089 -n puresecure
```

| Service | URL |
|---------|-----|
| **App** | <http://localhost:8000> |
| **Grafana** | <http://localhost:3000> (admin / admin) |
| **Prometheus** | <http://localhost:9090> |
| **Locust** | <http://localhost:8089> |

---

## Environment Variables

The ConfigMap (`k8s/app/configmap.yaml`) supports these variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AZURE_TENANT_ID` | *(required)* | Microsoft Entra ID tenant |
| `AZURE_CLIENT_ID` | *(required)* | App registration client ID |
| `CORS_ORIGINS` | `http://localhost:8000,http://127.0.0.1:8000` | Comma-separated allowed origins for CORS |
| `GRAFANA_URL` | `http://localhost:3000` | Grafana dashboard URL for nav links |
| `PROMETHEUS_URL` | `http://localhost:9090` | Prometheus URL for nav links |
| `LOCUST_URL` | `http://localhost:8089` | Locust URL for nav links (empty to hide) |

---

## Useful Commands

```bash
# View logs
kubectl logs -f deployment/cwe-explorer -n puresecure
kubectl logs -f deployment/prometheus -n puresecure

# Get all resources
kubectl get all -n puresecure

# Describe a pod
kubectl describe pod -l app=cwe-explorer -n puresecure

# Check PVCs
kubectl get pvc -n puresecure

# Shell into the app container
kubectl exec -it deployment/cwe-explorer -n puresecure -- /bin/sh

# Restart the app
kubectl rollout restart deployment/cwe-explorer -n puresecure

# Scale (web app must stay at 1 due to SQLite)
kubectl scale deployment/grafana --replicas=0 -n puresecure
```

---

## Troubleshooting

### Pod stuck in `CrashLoopBackOff`

```bash
kubectl describe pod -l app=cwe-explorer -n puresecure
kubectl logs -l app=cwe-explorer -n puresecure --previous
```

Common causes:
- Missing secret key (e.g. `couldn't find key GF_ADMIN_PASSWORD in Secret`) — the `app-secrets` secret must contain **both** `SERVICE_API_KEY` and `GF_ADMIN_PASSWORD`. Recreate using step 4, then restart the failing deployment: `kubectl rollout restart deployment/<name> -n puresecure`
- Insufficient memory — increase Docker Desktop resources: **Settings > Resources > Memory**

### Pod stuck in `Pending`

```bash
kubectl describe pod -l app=cwe-explorer -n puresecure
```

Common causes:
- PVC not bound — check StorageClass: `kubectl get sc`
- Insufficient resources — increase Docker Desktop CPU/Memory in Settings

### Infinite page refresh after login

If the page keeps refreshing after signing in with Microsoft:

1. **Check Azure AD redirect URI** — ensure `http://localhost:8000` is registered as a redirect URI in your Azure AD app registration (Azure Portal > App registrations > Authentication).

2. **Clear browser storage** — open DevTools > Application > Local Storage and clear all entries for the site, then try logging in again.

3. **Check pod logs** for 401 errors:
   ```bash
   kubectl logs -f deployment/cwe-explorer -n puresecure
   ```

### Image pull errors

Since Docker Desktop shares its daemon with Kubernetes, build locally:

```bash
docker build -t reonbritto/puresecure-cve-explorer:latest .

kubectl patch deployment cwe-explorer -n puresecure \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"cwe-explorer","imagePullPolicy":"Never"}]}}}}'
```

---

## Tearing Down

Remove all resources:

```bash
kubectl delete namespace puresecure
```

Disable Kubernetes: Docker Desktop > **Settings > Kubernetes > uncheck Enable Kubernetes**.
