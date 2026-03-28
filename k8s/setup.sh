#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────
#  PureSecure CVE Explorer — Docker Desktop Kubernetes Setup
# ─────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "==> Checking Kubernetes cluster..."
kubectl cluster-info > /dev/null 2>&1 || { echo "Kubernetes is not running. Please enable it in Docker Desktop."; exit 1; }

echo "==> Creating namespace..."
kubectl apply -f "$SCRIPT_DIR/namespace.yaml"

# ── Create secrets imperatively (avoids committing encoded values) ──
echo "==> Creating secrets..."
SERVICE_API_KEY="${SERVICE_API_KEY:?ERROR: SERVICE_API_KEY environment variable is required}"
GF_ADMIN_PASSWORD="${GF_ADMIN_PASSWORD:?ERROR: GF_ADMIN_PASSWORD environment variable is required}"

kubectl create secret generic app-secrets \
  --namespace=puresecure \
  --from-literal=SERVICE_API_KEY="$SERVICE_API_KEY" \
  --from-literal=GF_ADMIN_PASSWORD="$GF_ADMIN_PASSWORD" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Deploying application..."
kubectl apply -f "$SCRIPT_DIR/app/"

echo "==> Deploying Prometheus..."
kubectl apply -f "$SCRIPT_DIR/prometheus/"

echo "==> Deploying Grafana..."
kubectl apply -f "$SCRIPT_DIR/grafana/"

echo "==> Deploying Locust..."
kubectl apply -f "$SCRIPT_DIR/locust/"

echo "==> Waiting for deployments to roll out..."
kubectl rollout status deployment/cwe-explorer -n puresecure --timeout=300s
kubectl rollout status deployment/prometheus -n puresecure --timeout=60s
kubectl rollout status deployment/grafana -n puresecure --timeout=60s
kubectl rollout status deployment/locust -n puresecure --timeout=60s

# ── Print access info ──

echo ""
echo "============================================="
echo "  Deployment complete!"
echo "============================================="
echo ""
echo "Use port-forward to access the services:"
echo ""
echo "  kubectl port-forward svc/web 8000:8000 -n puresecure"
echo "  kubectl port-forward svc/grafana 3000:3000 -n puresecure"
echo "  kubectl port-forward svc/prometheus 9090:9090 -n puresecure"
echo "  kubectl port-forward svc/locust 8089:8089 -n puresecure"
echo ""
echo "Then open:"
echo "  App:        http://localhost:8000"
echo "  Grafana:    http://localhost:3000  (admin / ${GF_ADMIN_PASSWORD})"
echo "  Prometheus: http://localhost:9090"
echo "  Locust:     http://localhost:8089"
echo ""
