import { Link, useLocation } from 'react-router-dom';
import { useMsal } from '@azure/msal-react';
import { useEffect, useState, useRef } from 'react';
import { useTheme } from '../hooks/useTheme';
import { fetchServiceLinks } from '../utils/api';
import type { ServiceLinks } from '../utils/types';
import {
  Search, Crosshair, Sun, Moon, LogOut,
  ChevronDown, ExternalLink, LayoutDashboard,
  Activity, Bell, BookOpen, Database, FlaskConical,
  FileCode, Gauge, Server, MonitorDot, GitBranch,
  Container, Cpu, Layers, Cloud, Lock, Shield,
  BarChart3, Workflow, Blocks, FileCheck,
  ShieldCheck, Bug, Zap, Globe, KeyRound, Menu, X,
} from 'lucide-react';

export default function Navbar() {
  const location = useLocation();
  const { instance } = useMsal();
  const { isDark, toggle } = useTheme();
  const [services, setServices] = useState<ServiceLinks>({});
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLElement>(null);
  const account = instance.getActiveAccount();

  useEffect(() => {
    fetchServiceLinks().then(setServices);
  }, []);

  // Close mobile menu on route change
  useEffect(() => { setMenuOpen(false); }, [location.pathname]);

  // Close mobile menu on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const isActive = (path: string) =>
    location.pathname === path ? 'nav-active' : '';

  const handleLogout = () => {
    instance.logoutRedirect({
      account: account,
      postLogoutRedirectUri: window.location.origin + '/login',
    });
  };

  return (
    <header className="navbar">
      <Link to="/" className="logo">
        <img src="/favicon.svg" alt="PureSecure" className="logo-favicon" />
        PureSecure <span>CWE Explorer</span>
      </Link>

      {/* Hamburger toggle — only visible on mobile */}
      <div className="navbar-mobile-controls">
        <button className="theme-toggle" aria-label="Toggle Dark Mode" onClick={toggle}>
          {isDark ? <Sun size={18} /> : <Moon size={18} />}
        </button>
        <button
          className="nav-hamburger"
          aria-label={menuOpen ? 'Close menu' : 'Open menu'}
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen(o => !o)}
        >
          {menuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </div>

      <nav ref={menuRef} className={menuOpen ? 'nav-open' : ''}>
        <Link to="/" className={isActive('/')}>
          <LayoutDashboard size={15} />
          Weaknesses
        </Link>
        <Link to="/search" className={isActive('/search')}>
          <Search size={15} />
          Search
        </Link>
        <Link to="/attack" className={isActive('/attack')}>
          <Crosshair size={15} />
          ATT&CK
        </Link>

        <div className="nav-dropdown">
          <button className="nav-dropdown-btn">
            <Layers size={14} />
            Tech Stack <ChevronDown size={13} className="dropdown-chevron" />
          </button>
          <div className="nav-dropdown-menu services-mega">
            <div className="mega-header">
              <span className="mega-title">Project Tech Stack</span>
              <span className="mega-subtitle">Everything implemented in PureSecure CWE Explorer</span>
            </div>
            <div className="mega-grid">
              {/* Column 1: Observability */}
              <div className="mega-column">
                <span className="mega-section-label">
                  <BarChart3 size={12} /> Observability
                </span>
                {services.grafana && (
                  <a href={services.grafana.replace(/\/$/, '') + '/dashboards'} target="_blank" rel="noopener noreferrer" className="mega-item">
                    <div className="mega-item-icon mega-icon-grafana"><Gauge size={16} /></div>
                    <div className="mega-item-text">
                      <span className="mega-item-name">Grafana</span>
                      <span className="mega-item-desc">3 dashboards · API, Infra, Logs</span>
                    </div>
                    <ExternalLink size={10} className="mega-ext" />
                  </a>
                )}
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-prometheus"><Activity size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Prometheus</span>
                    <span className="mega-item-desc">17 recording rules · 11 alerts</span>
                  </div>
                  <span className="mega-badge">Internal</span>
                </div>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-alert"><Bell size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Alertmanager</span>
                    <span className="mega-item-desc">Email alerts via Gmail SMTP</span>
                  </div>
                  <span className="mega-badge">Internal</span>
                </div>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-loki"><BookOpen size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Loki + Promtail</span>
                    <span className="mega-item-desc">Log aggregation · DaemonSet shipper</span>
                  </div>
                  <span className="mega-badge">Internal</span>
                </div>

                <span className="mega-section-label" style={{ marginTop: '0.25rem' }}>
                  <MonitorDot size={12} /> Exporters
                </span>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-exporter"><MonitorDot size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Redis Exporter</span>
                    <span className="mega-item-desc">Redis metrics → Prometheus</span>
                  </div>
                  <span className="mega-badge">Internal</span>
                </div>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-kube"><Cpu size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Kube State Metrics</span>
                    <span className="mega-item-desc">K8s object metrics</span>
                  </div>
                  <span className="mega-badge">Internal</span>
                </div>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-node"><Container size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Node Exporter</span>
                    <span className="mega-item-desc">CPU · Memory · Disk · Network</span>
                  </div>
                  <span className="mega-badge">Internal</span>
                </div>
              </div>

              {/* Column 2: Infrastructure & Data */}
              <div className="mega-column">
                <span className="mega-section-label">
                  <Cloud size={12} /> Cloud & Infrastructure
                </span>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-azure"><Cloud size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Azure AKS</span>
                    <span className="mega-item-desc">Kubernetes cluster · Free tier</span>
                  </div>
                </div>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-terraform"><Blocks size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Terraform</span>
                    <span className="mega-item-desc">IaC · AKS, Key Vault, Identities</span>
                  </div>
                </div>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-helm"><Server size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Helm Chart</span>
                    <span className="mega-item-desc">41 templates · 12 services</span>
                  </div>
                </div>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-keyvault"><KeyRound size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Azure Key Vault + ESO</span>
                    <span className="mega-item-desc">Secret management · Workload Identity</span>
                  </div>
                </div>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-traefik"><Globe size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Traefik + cert-manager</span>
                    <span className="mega-item-desc">Ingress · Let's Encrypt TLS</span>
                  </div>
                </div>

                <span className="mega-section-label" style={{ marginTop: '0.25rem' }}>
                  <Database size={12} /> Data & Cache
                </span>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-redis"><Database size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Redis 7</span>
                    <span className="mega-item-desc">Cache · LRU · Concurrent users</span>
                  </div>
                  <span className="mega-badge">Internal</span>
                </div>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-mitre"><Shield size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">MITRE CWE + ATT&CK</span>
                    <span className="mega-item-desc">969+ CWEs · CAPEC · ATT&CK mapping</span>
                  </div>
                </div>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-nvd"><Bug size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">NIST NVD API 2.0</span>
                    <span className="mega-item-desc">Real-time CVE data · Rate-limited</span>
                  </div>
                </div>
              </div>

              {/* Column 3: DevSecOps & Application */}
              <div className="mega-column">
                <span className="mega-section-label">
                  <Workflow size={12} /> CI/CD & DevSecOps
                </span>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-github"><Workflow size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">GitHub Actions</span>
                    <span className="mega-item-desc">10-stage CI/CD pipeline</span>
                  </div>
                </div>
                {services.argocd && (
                  <a href={services.argocd} target="_blank" rel="noopener noreferrer" className="mega-item">
                    <div className="mega-item-icon mega-icon-argocd"><GitBranch size={16} /></div>
                    <div className="mega-item-text">
                      <span className="mega-item-name">ArgoCD</span>
                      <span className="mega-item-desc">GitOps · Auto-sync from main</span>
                    </div>
                    <ExternalLink size={10} className="mega-ext" />
                  </a>
                )}
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-docker"><Container size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Docker + Compose</span>
                    <span className="mega-item-desc">Multi-stage build · 9 services</span>
                  </div>
                </div>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-security"><ShieldCheck size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Security Scanning</span>
                    <span className="mega-item-desc">CodeQL · Snyk · Trivy · Gitleaks</span>
                  </div>
                </div>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-sbom"><FileCheck size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">SBOM (CycloneDX)</span>
                    <span className="mega-item-desc">Python + npm bill of materials</span>
                  </div>
                </div>

                <span className="mega-section-label" style={{ marginTop: '0.25rem' }}>
                  <Zap size={12} /> Application
                </span>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-fastapi"><Zap size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">FastAPI + React</span>
                    <span className="mega-item-desc">Python backend · TypeScript SPA</span>
                  </div>
                </div>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-auth"><Lock size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Microsoft Entra ID</span>
                    <span className="mega-item-desc">OAuth 2.0 · JWT · MSAL React</span>
                  </div>
                </div>
                <div className="mega-item mega-item-static">
                  <div className="mega-item-icon mega-icon-locust"><FlaskConical size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Locust</span>
                    <span className="mega-item-desc">Load testing · 7 weighted tasks</span>
                  </div>
                  <span className="mega-badge">Internal</span>
                </div>
                <a href="/docs" target="_blank" rel="noopener noreferrer" className="mega-item">
                  <div className="mega-item-icon mega-icon-api"><FileCode size={16} /></div>
                  <div className="mega-item-text">
                    <span className="mega-item-name">Swagger / OpenAPI</span>
                    <span className="mega-item-desc">Interactive API documentation</span>
                  </div>
                  <ExternalLink size={10} className="mega-ext" />
                </a>
              </div>
            </div>
          </div>
        </div>

        {/* Desktop-only theme toggle (inside nav) */}
        <button
          className="theme-toggle nav-desktop-only"
          aria-label="Toggle Dark Mode"
          onClick={toggle}
        >
          {isDark ? <Sun size={18} /> : <Moon size={18} />}
        </button>

        {account && (
          <span className="nav-user">
            <span className="nav-user-name">{account.name || account.username}</span>
            <button onClick={handleLogout} className="nav-logout">
              <LogOut size={14} />
              Sign Out
            </button>
          </span>
        )}
      </nav>
    </header>
  );
}
