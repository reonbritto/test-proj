#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────
#  PureSecure CVE Explorer — Docker Desktop Kubernetes Setup
# ─────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "==> Checking Kubernetes cluster..."
kubectl cluster-info > /dev/null 2>&1 || { echo "Kubernetes is not running. Please enable it in Docker Desktop."; exit 1; }

echo "==> Applying ingress controller (if not present)..."
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.10.1/deploy/static/provider/cloud/deploy.yaml

echo "==> Creating namespace..."
kubectl apply -f "$SCRIPT_DIR/namespace.yaml"

# ── Create secrets imperatively (avoids committing encoded values) ──
echo "==> Creating secrets..."
SERVICE_API_KEY="${SERVICE_API_KEY:-puresecure-locust-key-2026}"
GF_ADMIN_PASSWORD="${GF_ADMIN_PASSWORD:-admin}"

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

echo "==> Deploying Ingress..."
kubectl apply -f "$SCRIPT_DIR/ingress.yaml"

echo "==> Waiting for deployments to roll out..."
kubectl rollout status deployment/cwe-explorer -n puresecure --timeout=300s
kubectl rollout status deployment/prometheus -n puresecure --timeout=60s
kubectl rollout status deployment/grafana -n puresecure --timeout=60s

# ── Print access info ──

echo ""
echo "============================================="
echo "  Deployment complete!"
echo "============================================="
echo ""
echo "Add these to your hosts file:"
echo "  Windows: C:\\Windows\\System32\\drivers\\etc\\hosts (run Notepad as Admin)"
echo "  Linux/Mac: /etc/hosts"
echo ""
echo "  127.0.0.1  puresecure.local grafana.puresecure.local prometheus.puresecure.local"
echo ""
echo "Then access:"
echo "  App:        http://puresecure.local"
echo "  Grafana:    http://grafana.puresecure.local  (admin / ${GF_ADMIN_PASSWORD})"
echo "  Prometheus: http://prometheus.puresecure.local"
echo ""
echo "─── OR use port-forward (no hosts file needed) ───"
echo ""
echo "  kubectl port-forward svc/web 8000:8000 -n puresecure"
echo "  kubectl port-forward svc/grafana 3000:3000 -n puresecure"
echo "  kubectl port-forward svc/prometheus 9090:9090 -n puresecure"
echo ""
echo "  Then open: http://localhost:8000"
echo ""
