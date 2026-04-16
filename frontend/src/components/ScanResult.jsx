import styles from './ScanResult.module.css'

// ── Verdict config — strict score-based ──────────────────────
// Score 0–39% = SAFE, 40–69% = SUSPICIOUS, 70–100% = PHISHING
const VERDICT_CONFIG = {
  PHISHING:   { cls: styles.vPhishing,   icon: '🚨', label: 'PHISHING DETECTED', color: 'var(--red)'    },
  SUSPICIOUS: { cls: styles.vSuspicious, icon: '⚠️',  label: 'SUSPICIOUS URL',    color: 'var(--amber)'  },
  SAFE:       { cls: styles.vSafe,       icon: '✅',  label: 'SAFE',              color: 'var(--green)'  },
  TRUSTED:    { cls: styles.vTrusted,    icon: '🔒',  label: 'TRUSTED DOMAIN',    color: 'var(--cyan)'   },
}

const SEV_CLS   = { hi: styles.flagHi, md: styles.flagMd, lo: styles.flagLo }
const SEV_LABEL = { hi: 'HIGH', md: 'MED', lo: 'LOW' }

// ── Why suspicious explanation ────────────────────────────────
function WhyPanel({ result }) {
  const pct    = Math.round((result.final_proba ?? 0) * 100)
  const verdict = result.verdict

  if (verdict === 'TRUSTED' || verdict === 'SAFE') return null

  const reasons = []

  // From flags
  result.flags?.forEach(f => {
    if (f.severity === 'hi') reasons.push({ icon: '🚨', text: f.text, level: 'HIGH' })
    else if (f.severity === 'md') reasons.push({ icon: '⚠️', text: f.text, level: 'MED' })
  })

  // Score-based generic reasons
  if (pct >= 70) reasons.push({ icon: '📊', text: `Composite threat score very high (${pct}%)`, level: 'HIGH' })
  else if (pct >= 40) reasons.push({ icon: '📊', text: `Threat score in suspicious range (${pct}%)`, level: 'MED' })

  // ML signal
  const mlPct = Math.round((result.model_proba ?? 0) * 100)
  if (mlPct >= 50) reasons.push({ icon: '🤖', text: `ML model detected phishing patterns (${mlPct}% confidence)`, level: 'HIGH' })

  // URL risk signal
  const riskPct = Math.round((result.url_risk ?? 0) * 100)
  if (riskPct >= 60) reasons.push({ icon: '🔗', text: `URL structure highly suspicious (risk ${riskPct}%)`, level: 'HIGH' })
  else if (riskPct >= 30) reasons.push({ icon: '🔗', text: `URL has suspicious structural patterns (risk ${riskPct}%)`, level: 'MED' })

  // Protocol
  if (result.url?.startsWith('http://') && !result.url?.startsWith('http://localhost')) {
    reasons.push({ icon: '🔓', text: 'No HTTPS — connection is unencrypted', level: 'MED' })
  }

  if (!reasons.length) return null

  return (
    <div className={styles.whyPanel}>
      <div className={styles.whyTitle}>
        {verdict === 'PHISHING' ? '🚨 Why Phishing?' : '⚠️ Why Suspicious?'}
      </div>
      <div className={styles.whyList}>
        {reasons.slice(0, 6).map((r, i) => (
          <div key={i} className={`${styles.whyItem} ${r.level === 'HIGH' ? styles.whyHi : styles.whyMd}`}>
            <span className={styles.whyIcon}>{r.icon}</span>
            <span className={styles.whyText}>{r.text}</span>
            <span className={`${styles.whyBadge} ${r.level === 'HIGH' ? styles.whyHiBadge : styles.whyMdBadge}`}>
              {r.level}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── VirusTotal status panel ───────────────────────────────────
function VTPanel({ vt }) {
  if (!vt) return null
  return (
    <div className={styles.vtPanel}>
      <div className={styles.vtTitle}>🛡️ VirusTotal</div>
      {!vt.checked ? (
        <div className={styles.vtRow}>
          <span className={styles.vtDot} style={{ background: 'var(--txt3)' }} />
          <span className={styles.vtText}>Not yet indexed — submitted for analysis</span>
        </div>
      ) : (
        <>
          <div className={styles.vtRow}>
            <span className={styles.vtDot} style={{ background: vt.malicious > 0 ? 'var(--red)' : 'var(--green)' }} />
            <span className={styles.vtText}>
              {vt.malicious > 0
                ? `${vt.malicious} engine(s) flagged as malicious`
                : 'No engines flagged as malicious'}
            </span>
          </div>
          {vt.suspicious > 0 && (
            <div className={styles.vtRow}>
              <span className={styles.vtDot} style={{ background: 'var(--amber)' }} />
              <span className={styles.vtText}>{vt.suspicious} engine(s) flagged as suspicious</span>
            </div>
          )}
          {vt.harmless > 0 && (
            <div className={styles.vtRow}>
              <span className={styles.vtDot} style={{ background: 'var(--green)' }} />
              <span className={styles.vtText}>{vt.harmless} engine(s) confirmed harmless</span>
            </div>
          )}
        </>
      )}
    </div>
  )
}

// ── Main ScanResult ───────────────────────────────────────────
export default function ScanResult({ result }) {
  const cfg  = VERDICT_CONFIG[result.verdict] ?? VERDICT_CONFIG.SAFE
  const pct  = Math.round((result.final_proba ?? 0) * 100)

  // Score zone label
  const scoreZone = pct >= 70 ? 'HIGH RISK' : pct >= 40 ? 'MODERATE RISK' : 'LOW RISK'
  const scoreZoneColor = pct >= 70 ? 'var(--red)' : pct >= 40 ? 'var(--amber)' : 'var(--green)'

  return (
    <div className={styles.wrap}>

      {/* Verdict banner */}
      <div className={`${styles.verdictBanner} ${cfg.cls}`}>
        <span className={styles.verdictIcon}>{cfg.icon}</span>
        <div>
          <div className={styles.verdictLabel}>{cfg.label}</div>
          <div className={styles.verdictSub}>
            Threat Score: <strong>{pct}%</strong>
            <span className={styles.scoreZone} style={{ color: scoreZoneColor }}> · {scoreZone}</span>
          </div>
        </div>
      </div>

      {/* Score cards */}
      <div className={styles.scoreRow}>
        {[
          { lbl: 'Threat Score', val: `${pct}%`,                                      color: cfg.color },
          { lbl: 'ML Model',     val: `${(result.model_proba * 100).toFixed(1)}%`,    color: '' },
          { lbl: 'URL Risk',     val: `${(result.url_risk * 100).toFixed(1)}%`,       color: '' },
          { lbl: 'Flags',        val: result.flags?.length ?? 0,                      color: result.flags?.length > 0 ? 'var(--amber)' : '' },
        ].map(s => (
          <div key={s.lbl} className={styles.scoreCard}>
            <span className={styles.scoreVal} style={s.color ? { color: s.color } : {}}>{s.val}</span>
            <span className={styles.scoreLbl}>{s.lbl}</span>
          </div>
        ))}
      </div>

      {/* Threat bar */}
      <div className={styles.barWrap}>
        <div className={styles.barHdr}>
          <span className={styles.barTitle}>THREAT PROBABILITY</span>
          <span className={styles.barPct} style={{ color: scoreZoneColor }}>{pct}%</span>
        </div>
        <div className={styles.barTrack}>
          {/* Zone markers */}
          <div className={styles.barZone} style={{ left: '40%', borderColor: 'var(--amber)' }} />
          <div className={styles.barZone} style={{ left: '70%', borderColor: 'var(--red)' }} />
          <div className={styles.barFill}
            style={{ width: `${pct}%`, background: scoreZoneColor }} />
        </div>
        <div className={styles.barLabels}>
          <span style={{ color: 'var(--green)' }}>SAFE (0–39%)</span>
          <span style={{ color: 'var(--amber)', marginLeft: '40%' }}>SUSPICIOUS (40–69%)</span>
          <span style={{ color: 'var(--red)' }}>PHISHING (70%+)</span>
        </div>
      </div>

      {/* WHY panel — most important for viva */}
      <WhyPanel result={result} />

      {/* VirusTotal status */}
      <VTPanel vt={result.virustotal} />

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
        {/* Threat indicators */}
        {result.flags?.length > 0 && (
          <div>
            <div className="sec-lbl">Threat Indicators ({result.flags.length})</div>
            <div className={styles.flagsPanel}>
              {result.flags.map((f, i) => (
                <div key={i} className={`${styles.flagItem} ${SEV_CLS[f.severity] ?? styles.flagLo}`}>
                  <div className={`${styles.fdot} ${SEV_CLS[f.severity] ?? styles.flagLo}`} />
                  <span style={{ flex: 1 }}>{f.text}</span>
                  <span className={styles.sevBadge}>{SEV_LABEL[f.severity] ?? 'LOW'}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ML Features */}
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