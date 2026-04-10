import styles from './ScanResult.module.css'

const VERDICT_CONFIG = {
  PHISHING:   { cls: styles.vPhishing,   icon: '🚨', label: 'PHISHING DETECTED'  },
  SUSPICIOUS: { cls: styles.vSuspicious, icon: '⚠️',  label: 'SUSPICIOUS URL'    },
  SAFE:       { cls: styles.vSafe,       icon: '✅',  label: 'SAFE'              },
  TRUSTED:    { cls: styles.vTrusted,    icon: '🔒',  label: 'TRUSTED DOMAIN'    },
}

const SEV_CLS = { hi: styles.flagHi, md: styles.flagMd, lo: styles.flagLo }

export default function ScanResult({ result }) {
  const cfg = VERDICT_CONFIG[result.verdict] ?? VERDICT_CONFIG.SAFE

  return (
    <div className={styles.wrap}>
      {/* Verdict banner */}
      <div className={`${styles.verdictBanner} ${cfg.cls}`}>
        <span>{cfg.icon}</span>
        <span>{cfg.label}</span>
      </div>

      {/* Score cards */}
      <div className={styles.scoreRow}>
        {[
          { lbl: 'Final Score', val: `${(result.final_proba * 100).toFixed(1)}%`, color: cfg.cls },
          { lbl: 'ML Score',    val: `${(result.model_proba * 100).toFixed(1)}%`, color: '' },
          { lbl: 'URL Risk',    val: `${(result.url_risk * 100).toFixed(1)}%`,    color: '' },
          { lbl: 'Flags',       val: result.flags?.length ?? 0,                  color: '' },
        ].map(s => (
          <div key={s.lbl} className={styles.scoreCard}>
            <span className={`${styles.scoreVal} ${s.color}`}>{s.val}</span>
            <span className={styles.scoreLbl}>{s.lbl}</span>
          </div>
        ))}
      </div>

      {/* Progress bar */}
      <div className={styles.barWrap}>
        <div className={styles.barHdr}>
          <span className={styles.barTitle}>COMPOSITE THREAT PROBABILITY</span>
          <span className={`${styles.barPct} ${cfg.cls}`}>{(result.final_proba * 100).toFixed(1)}%</span>
        </div>
        <div className={styles.barTrack}>
          <div className={`${styles.barFill} ${cfg.cls}`}
            style={{ width: `${result.final_proba * 100}%` }} />
        </div>
      </div>

      {/* URL anatomy */}
      {result.anatomy && (
        <>
          <div className="sec-lbl" style={{ marginTop: 18 }}>URL Anatomy</div>
          <div className={styles.anatomy}>
            <span className={styles.aScheme}>{result.anatomy.scheme}://</span>
            {result.anatomy.subdomain && <span className={styles.aSub}>{result.anatomy.subdomain}.</span>}
            <span className={styles.aDomain}>{result.anatomy.domain}</span>
            {result.anatomy.path && <span className={styles.aPath}>{result.anatomy.path}</span>}
            {result.anatomy.query && <span className={styles.aQuery}>?{result.anatomy.query}</span>}
          </div>
        </>
      )}

      <div className={styles.cols}>
        {/* Flags */}
        {result.flags?.length > 0 && (
          <div>
            <div className="sec-lbl">Threat Indicators ({result.flags.length})</div>
            <div className={styles.flagsPanel}>
              {result.flags.map((f, i) => (
                <div key={i} className={`${styles.flagItem} ${SEV_CLS[f.severity] ?? styles.flagLo}`}>
                  <div className={`${styles.fdot} ${SEV_CLS[f.severity] ?? styles.flagLo}`} />
                  {f.text}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Features */}
        {result.features && Object.keys(result.features).length > 0 && (
          <div>
            <div className="sec-lbl">ML Features</div>
            <div className={styles.featGrid}>
              {Object.entries(result.features).map(([k, v]) => (
                <div key={k} className={styles.featPill}>
                  <span className={styles.featVal}>{typeof v === 'number' ? v.toFixed(2) : v}</span>
                  <span className={styles.featName}>{k.replace(/([A-Z])/g, ' $1').trim()}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
