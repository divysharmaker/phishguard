import styles from './AboutModel.module.css'

const FEATURES = [
  { name: 'PctExtHyperlinks',                   desc: 'Ratio of external hyperlinks on the page',       weight: 'High'   },
  { name: 'PctExtNullSelfRedirectHyperlinksRT', desc: 'Null/self-redirect hyperlink ratio',              weight: 'High'   },
  { name: 'NumDash',                             desc: 'Number of dashes in the URL',                    weight: 'Medium' },
  { name: 'PathLevel',                           desc: 'Depth of the URL path',                          weight: 'Medium' },
  { name: 'NumDots',                             desc: 'Number of dots in the domain',                   weight: 'Medium' },
  { name: 'IframeOrFrame',                       desc: 'Whether the page contains iframe/frame elements',weight: 'Low'    },
]

const STATS = [
  { label: 'Dataset Size',   value: '235,795',  sub: 'labeled URLs',       color: 'var(--cyan)'  },
  { label: 'Model Type',     value: 'RF',        sub: 'Random Forest',      color: 'var(--purple)'},
  { label: 'Estimators',     value: '100',       sub: 'decision trees',     color: 'var(--cyan)'  },
  { label: 'Test Accuracy',  value: '97.4%',     sub: 'on held-out data',   color: 'var(--green)' },
  { label: 'Precision',      value: '96.8%',     sub: 'phishing class',     color: 'var(--green)' },
  { label: 'Recall',         value: '97.9%',     sub: 'phishing class',     color: 'var(--amber)' },
]

const LAYERS = [
  { icon: '🔗', title: 'URL Heuristics (60%)', desc: 'Typosquatting detection, brand impersonation check, suspicious TLDs, IP hostname, entropy analysis, @ symbol tricks', color: 'var(--cyan)' },
  { icon: '🤖', title: 'ML Model (40%)',       desc: 'Random Forest trained on PhiUSIIL dataset (235k URLs). Extracts 6 structural features for classification.',           color: 'var(--purple)' },
  { icon: '🛡️', title: 'VirusTotal API',       desc: 'Cross-checks against 70+ antivirus engines. 2+ detections override ML result to PHISHING automatically.',           color: 'var(--amber)' },
  { icon: '✅', title: 'Whitelist',             desc: 'Trusted domains (Google, HDFC, gov.in, etc.) bypass ML scoring and return TRUSTED instantly.',                       color: 'var(--green)' },
]

export default function AboutModel() {
  return (
    <div className={styles.page}>
      {/* Hero */}
      <div className={styles.hero}>
        <div className={styles.heroIcon}>🧠</div>
        <div>
          <h1 className={styles.heroTitle}>About the Model</h1>
          <p className={styles.heroSub}>PhishGuard uses a multi-layer hybrid detection system combining machine learning, URL heuristics, and real-time threat intelligence.</p>
        </div>
      </div>

      {/* Stats */}
      <div className={styles.statsGrid}>
        {STATS.map((s, i) => (
          <div key={i} className={styles.statCard}>
            <div className={styles.statVal} style={{ color: s.color }}>{s.value}</div>
            <div className={styles.statLabel}>{s.label}</div>
            <div className={styles.statSub}>{s.sub}</div>
          </div>
        ))}
      </div>

      {/* Detection layers */}
      <div className={styles.section}>
        <div className="sec-lbl">Detection Architecture</div>
        <div className={styles.layersGrid}>
          {LAYERS.map((l, i) => (
            <div key={i} className={styles.layerCard} style={{ borderTopColor: l.color }}>
              <div className={styles.layerIcon}>{l.icon}</div>
              <div className={styles.layerTitle} style={{ color: l.color }}>{l.title}</div>
              <div className={styles.layerDesc}>{l.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Scoring formula */}
      <div className={styles.section}>
        <div className="sec-lbl">Scoring Formula</div>
        <div className="panel">
          <div className={styles.formula}>
            <span className={styles.formulaPart} style={{ color: 'var(--cyan)' }}>Final Score</span>
            <span className={styles.formulaOp}>=</span>
            <span className={styles.formulaPart} style={{ color: 'var(--amber)' }}>0.60 × URL Risk</span>
            <span className={styles.formulaOp}>+</span>
            <span className={styles.formulaPart} style={{ color: 'var(--purple)' }}>0.40 × ML Probability</span>
          </div>
          <div className={styles.verdictRules}>
            <div className={styles.ruleRow}>
              <span className={styles.ruleLabel} style={{ color: 'var(--red)' }}>🔴 PHISHING</span>
              <span className={styles.ruleDesc}>Score ≥ 35% OR 2+ high-severity flags OR VirusTotal 2+ detections</span>
            </div>
            <div className={styles.ruleRow}>
              <span className={styles.ruleLabel} style={{ color: 'var(--amber)' }}>🟡 SUSPICIOUS</span>
              <span className={styles.ruleDesc}>Score ≥ 15% OR 1 high-severity flag OR VirusTotal 1 detection</span>
            </div>
            <div className={styles.ruleRow}>
              <span className={styles.ruleLabel} style={{ color: 'var(--green)' }}>🟢 SAFE</span>
              <span className={styles.ruleDesc}>Score &lt; 15% AND no high flags AND VirusTotal clean</span>
            </div>
            <div className={styles.ruleRow}>
              <span className={styles.ruleLabel} style={{ color: 'var(--cyan)' }}>🔵 TRUSTED</span>
              <span className={styles.ruleDesc}>Domain found in whitelist (skips ML entirely)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Features */}
      <div className={styles.section}>
        <div className="sec-lbl">ML Features Used</div>
        <div className="panel" style={{ padding: 0, overflowX: 'auto' }}>
          <table className={styles.featTable}>
            <thead>
              <tr>
                <th>Feature</th>
                <th>Description</th>
                <th>Importance</th>
              </tr>
            </thead>
            <tbody>
              {FEATURES.map((f, i) => (
                <tr key={i}>
                  <td className={styles.featName}>{f.name}</td>
                  <td className={styles.featDesc}>{f.desc}</td>
                  <td>
                    <span className={styles.weightBadge}
                      style={{
                        color: f.weight === 'High' ? 'var(--red)' : f.weight === 'Medium' ? 'var(--amber)' : 'var(--green)',
                        borderColor: f.weight === 'High' ? 'var(--red)' : f.weight === 'Medium' ? 'var(--amber)' : 'var(--green)',
                      }}>
                      {f.weight}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Dataset info */}
      <div className={styles.section}>
        <div className="sec-lbl">Dataset</div>
        <div className="panel">
          <div className={styles.datasetInfo}>
            <div className={styles.datasetItem}>
              <span className={styles.datasetKey}>Name</span>
              <span className={styles.datasetVal}>PhiUSIIL Phishing URL Dataset</span>
            </div>
            <div className={styles.datasetItem}>
              <span className={styles.datasetKey}>Source</span>
              <span className={styles.datasetVal}>UCI ML Repository / Kaggle</span>
            </div>
            <div className={styles.datasetItem}>
              <span className={styles.datasetKey}>Total URLs</span>
              <span className={styles.datasetVal}>235,795</span>
            </div>
            <div className={styles.datasetItem}>
              <span className={styles.datasetKey}>Phishing</span>
              <span className={styles.datasetVal} style={{ color: 'var(--red)' }}>134,850 (57.2%)</span>
            </div>
            <div className={styles.datasetItem}>
              <span className={styles.datasetKey}>Legitimate</span>
              <span className={styles.datasetVal} style={{ color: 'var(--green)' }}>100,945 (42.8%)</span>
            </div>
            <div className={styles.datasetItem}>
              <span className={styles.datasetKey}>Train/Test Split</span>
              <span className={styles.datasetVal}>80% / 20%</span>
            </div>
            <div className={styles.datasetItem}>
              <span className={styles.datasetKey}>Model File</span>
              <span className={styles.datasetVal}>phishing_pipeline_v2.pkl (6.6 MB)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Limitations */}
      <div className={styles.section}>
        <div className="sec-lbl">Known Limitations</div>
        <div className="panel">
          <ul className={styles.limitList}>
            <li>URL-only analysis — does not fetch or parse webpage content</li>
            <li>Short, clean typosquatted domains may occasionally be missed without VirusTotal hit</li>
            <li>New phishing domains not yet indexed by VirusTotal may return SUSPICIOUS instead of PHISHING</li>
            <li>Complex legitimate URLs with many path segments may trigger false positives</li>
          </ul>

        </div>
      </div>


    </div>
  )
}