export default function Footer() {
  return (
    <footer className="site-footer">
      <div className="footer-inner">
        <div className="footer-brand">
          <img src="/favicon.svg" alt="PureSecure" width="16" height="16" />
          <span>PureSecure CWE Explorer</span>
        </div>
        <p>
          Data sourced from{' '}
          <a href="https://cwe.mitre.org" target="_blank" rel="noopener noreferrer">
            MITRE CWE
          </a>{' '}
          and{' '}
          <a href="https://nvd.nist.gov" target="_blank" rel="noopener noreferrer">
            NVD
          </a>
        </p>
      </div>
    </footer>
  );
}
