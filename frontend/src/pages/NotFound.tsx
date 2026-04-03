import { Link } from 'react-router-dom';
import { ShieldOff, Home } from 'lucide-react';

export default function NotFound() {
  return (
    <main className="container" style={{ textAlign: 'center', padding: '5rem 2rem' }}>
      <ShieldOff size={56} style={{ color: 'var(--green)', marginBottom: '1.5rem', opacity: 0.6 }} />
      <h1 style={{ fontSize: '4rem', marginBottom: '0.5rem', color: 'var(--green-dark)', fontWeight: 800, letterSpacing: '-0.03em' }}>404</h1>
      <p style={{ fontSize: '1.15rem', marginBottom: '2.5rem', color: 'var(--text-secondary)' }}>
        The page you're looking for doesn't exist.
      </p>
      <Link
        to="/"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.5rem',
          color: 'var(--bg-secondary)',
          background: 'var(--green)',
          padding: '0.65rem 1.5rem',
          borderRadius: '8px',
          fontWeight: 600,
          fontSize: '0.9rem',
          textDecoration: 'none',
          transition: 'all 0.2s',
        }}
      >
        <Home size={16} />
        Return to Home
      </Link>
    </main>
  );
}
