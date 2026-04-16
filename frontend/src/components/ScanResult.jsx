import { useState } from 'react'
import styles from './ScanResult.module.css'

const VERDICT_CONFIG = {
  PHISHING:     { cls: styles.vPhishing,   icon: '🚨', label: 'PHISHING DETECTED',    color: 'var(--red)'   },
  SUSPICIOUS:   { cls: styles.vSuspicious, icon: '⚠️',  label: 'SUSPICIOUS URL',        color: 'var(--amber)' },
  SAFE:         { cls: styles.vSafe,       icon: '✅',  label: 'SAFE',                  color: 'var(--green)' },
  SAFE_WARNING: { cls: styles.vSafeWarn,   icon: '✅',  label: 'SAFE (Minor Warnings)', color: 'var(--green)' },
  TRUSTED:      { cls: styles.vTrusted,    icon: '🔒',  label: 'TRUSTED DOMAIN',        color: 'var(--cyan)'  },
}
const SEV_CLS   = { hi: styles.flagHi, md: styles.flagMd, lo: styles.flagLo }
const SEV_LABEL = { hi: 'HIGH', md: 'MED', lo: 'LOW' }

function vtToScore(vt) {
  if (!vt?.checked) return null
  const total = (vt.malicious??0)+(vt.suspicious??0)+(vt.harmless??0)+(vt.undetected??0)
  if (total === 0) return null
  return (vt.malicious??0) / total
}

function computeWeightedScore(result) {
  const ml   = result.model_proba ?? 0
  const risk = result.url_risk    ?? 0
  const vts  = vtToScore(result.virustotal)
  if (vts === null) return result.final_proba ?? 0
  return Math.min(1.0, ml*0.4 + risk*0.2 + vts*0.4)
}

function getDisplayVerdict(result) {
  const verdict = result.verdict
  const mlPct   = Math.round((result.model_proba ?? 0) * 100)
  const vt      = result.virustotal ?? {}
  const vtMal   = vt.malicious ?? 0
  if (verdict === 'SAFE') {
    const hasMinorWarning = (vt.checked && vtMal===1) || (mlPct>=35 && mlPct<50) || result.url?.startsWith('http://')
    if (hasMinorWarning) return 'SAFE_WARNING'
  }
  return verdict
}

function getSummary(dv, pct, vt) {
  if (dv==='TRUSTED')      return '🔒 Verified trusted domain — no risk detected'
  if (dv==='PHISHING')     return '🚨 High-risk URL — likely phishing. Do not visit.'
  if (dv==='SUSPICIOUS')   return '⚠️ Suspicious URL detected — proceed with extreme caution'
  if (dv==='SAFE_WARNING') return '🔎 Low risk URL with minor warnings — safe to visit, stay alert'
  return '✅ URL appears safe — no significant threats detected'
}

function getHumanVerdict(dv, pct, vt) {
  const vtMal  = vt?.malicious  ?? 0
  const vtHarm = vt?.harmless   ?? 0
  if (dv==='TRUSTED')      return 'This domain is on our trusted whitelist. It is a well-known, legitimate website.'
  if (dv==='PHISHING')     return `This URL shows strong phishing indicators with a threat score of ${pct}%. Avoid visiting and do not enter any personal information.`
  if (dv==='SUSPICIOUS')   return `This URL has suspicious characteristics (score: ${pct}%). It may be a phishing attempt. Verify the source before proceeding.`
  if (dv==='SAFE_WARNING') return `This URL appears safe overall (score: ${pct}%), but minor risk signals were detected. ${vtMal===1?`One security engine flagged it, though ${vtHarm} confirmed it harmless. `:''}Proceed normally but stay cautious.`
  return `This URL appears safe with a low threat score of ${pct}%. No significant phishing indicators were found.`
}

function getConfidence(dv, pct, vt) {
  const vtHarm  = vt?.harmless  ?? 0
  const vtTotal = (vt?.malicious??0)+(vt?.suspicious??0)+vtHarm+(vt?.undetected??0)
  const vtConf  = vtTotal > 0 ? (vtHarm/vtTotal)*100 : 50
  if (dv==='TRUSTED')      return { val: 99, label: 'Trusted',    color: 'var(--cyan)'  }
  if (dv==='PHISHING')     return { val: Math.min(99,pct+10),     label: 'Phishing',    color: 'var(--red)'   }
  if (dv==='SUSPICIOUS')   return { val: Math.round(pct/100*80+20), label: 'Suspicious',color: 'var(--amber)' }
  if (dv==='SAFE_WARNING') return { val: Math.round(vtConf*0.6+(100-pct)*0.4), label: 'Safe', color: 'var(--green)' }
  return { val: Math.min(99,Math.round((100-pct)*0.7+vtConf*0.3)), label: 'Safe', color: 'var(--green)' }
}

// ── Trust Badge ───────────────────────────────────────────────
function TrustBadge({ dv }) {
  const cfg = {
    TRUSTED:      { label: '🔵 Verified',  color: 'var(--cyan)'  },
    SAFE:         { label: '🟢 Trusted',   color: 'var(--green)' },
    SAFE_WARNING: { label: '🟡 Caution',   color: 'var(--amber)' },
    SUSPICIOUS:   { label: '🟠 Warning',   color: '#ff6400'      },
    PHISHING:     { label: '🔴 Dangerous', color: 'var(--red)'   },
  }[dv] ?? { label: '🟢 Trusted', color: 'var(--green)' }
  return <span className={styles.trustBadge} style={{ color: cfg.color, borderColor: cfg.color+'60' }}>{cfg.label}</span>
}

// ── Decision Panel ────────────────────────────────────────────
function DecisionPanel({ result }) {
  const dv        = getDisplayVerdict(result)
  const cfg       = VERDICT_CONFIG[dv] ?? VERDICT_CONFIG.SAFE
  const mlPct     = Math.round((result.model_proba??0)*100)
  const riskPct   = Math.round((result.url_risk??0)*100)
  const vt        = result.virustotal ?? {}
  const vtMal     = vt.malicious??0
  const vtHarm    = vt.harmless??0
  const vts       = vtToScore(vt)
  const vtPct     = vts!==null ? (vts*100).toFixed(1) : null
  const weighted  = Math.round(computeWeightedScore(result)*100)
  const hasVT     = vts !== null

  const mlColor   = mlPct>=70?'var(--red)':mlPct>=40?'var(--amber)':'var(--green)'
  const riskColor = riskPct>=60?'var(--red)':riskPct>=30?'var(--amber)':'var(--green)'
  const vtSummary = !vt.checked ? { text:'Not yet indexed', color:'var(--txt3)' }
    : vtMal>=3 ? { text:`${vtMal} engines flagged malicious`, color:'var(--red)' }
    : vtMal>=1 ? { text:`${vtMal} engine flagged — ${vtHarm} confirmed harmless`, color:'var(--amber)' }
    : { text:`All ${vtHarm} engines confirmed safe`, color:'var(--green)' }
  const formula = hasVT
    ? `(ML ${mlPct}% × 40%) + (URL Risk ${riskPct}% × 20%) + (VT ${vtPct}% × 40%) = ${weighted}%`
    : `(ML ${mlPct}% × 60%) + (URL Risk ${riskPct}% × 40%) = ${weighted}%`

  return (
    <div className={styles.decisionPanel}>
      <div className={styles.decisionTitle}>🧠 Final Decision Breakdown</div>
      <div className={styles.decisionGrid}>
        <div className={styles.decisionRow}>
          <span className={styles.decisionKey}>🤖 ML Model <span className={styles.weight}>(40%)</span></span>
          <span className={styles.decisionVal}>
            <span style={{color:mlColor}}>{mlPct>=70?'High Risk':mlPct>=40?'Medium Risk':'Low Risk'}</span>
            <span className={styles.decisionPct}> ({mlPct}%)</span>
          </span>
        </div>
        <div className={styles.decisionRow}>
          <span className={styles.decisionKey}>🔗 URL Risk <span className={styles.weight}>{hasVT?'(20%)':'(60%)'}</span></span>
          <span className={styles.decisionVal}>
            <span style={{color:riskColor}}>{riskPct>=60?'High Risk':riskPct>=30?'Medium Risk':'Low Risk'}</span>
            <span className={styles.decisionPct}> ({riskPct}%)</span>
          </span>
        </div>
        <div className={styles.decisionRow}>
          <span className={styles.decisionKey}>🛡️ VirusTotal <span className={styles.weight}>{hasVT?'(40%)':'(N/A)'}</span></span>
          <span className={styles.decisionVal}><span style={{color:vtSummary.color}}>{vtSummary.text}</span></span>
        </div>
        <div className={`${styles.decisionRow} ${styles.decisionFinal}`}>
          <span className={styles.decisionKey}>📊 Final Verdict</span>
          <span className={styles.decisionVal}><span style={{color:cfg.color}}>{weighted}% → {cfg.label}</span></span>
        </div>
      </div>
      <div className={styles.decisionFormula}>{formula}</div>
    </div>
  )
}

// ── Why Panel ─────────────────────────────────────────────────
function WhyPanel({ result }) {
  const dv = getDisplayVerdict(result)
  if (dv==='TRUSTED') return null
  const pct=Math.round((result.final_proba??0)*100), mlPct=Math.round((result.model_proba??0)*100)
  const riskPct=Math.round((result.url_risk??0)*100), vt=result.virustotal??{}
  const reasons=[]
  result.flags?.forEach(f => {
    if(f.severity==='hi') reasons.push({icon:'🚨',text:f.text,level:'HIGH'})
    else if(f.severity==='md') reasons.push({icon:'⚠️',text:f.text,level:'MED'})
  })
  if(pct>=70)       reasons.push({icon:'📊',text:`Composite threat score very high (${pct}%)`,level:'HIGH'})
  else if(pct>=40)  reasons.push({icon:'📊',text:`Threat score in suspicious range (${pct}%)`,level:'MED'})
  if(mlPct>=50)     reasons.push({icon:'🤖',text:`ML model detected phishing patterns (${mlPct}% confidence)`,level:'HIGH'})
  else if(mlPct>=35)reasons.push({icon:'🤖',text:`ML model shows moderate risk signal (${mlPct}%)`,level:'MED'})
  if(riskPct>=60)   reasons.push({icon:'🔗',text:`URL structure highly suspicious (${riskPct}%)`,level:'HIGH'})
  else if(riskPct>=30)reasons.push({icon:'🔗',text:`URL has suspicious structural patterns (${riskPct}%)`,level:'MED'})
  if(vt.checked&&(vt.malicious??0)===1)
    reasons.push({icon:'🛡️',text:'1 security engine flagged this URL — low confidence signal',level:'LOW'})
  if(result.url?.startsWith('http://')&&!result.url?.startsWith('http://localhost'))
    reasons.push({icon:'🔓',text:'No HTTPS — data can be intercepted (medium risk)',level:'MED'})
  if(!reasons.length) return null
  const titles={PHISHING:'🚨 Why Phishing?',SUSPICIOUS:'⚠️ Why Suspicious?',SAFE_WARNING:'⚠️ Minor Warnings Detected',SAFE:'✅ Why Safe?'}
  return (
    <div className={styles.whyPanel}>
      <div className={styles.whyTitle}>{titles[dv]??'⚠️ Details'}</div>
      <div className={styles.whyList}>
        {reasons.slice(0,6).map((r,i)=>(
          <div key={i} className={`${styles.whyItem} ${r.level==='HIGH'?styles.whyHi:r.level==='MED'?styles.whyMd:styles.whyLo}`}>
            <span className={styles.whyIcon}>{r.icon}</span>
            <span className={styles.whyText}>{r.text}</span>
            <span className={`${styles.whyBadge} ${r.level==='HIGH'?styles.whyHiBadge:r.level==='MED'?styles.whyMdBadge:styles.whyLoBadge}`}>{r.level}</span>
          </div>
        ))}
      </div>
      {(dv==='SAFE'||dv==='SAFE_WARNING')&&(vt.harmless??0)>=5&&(
        <div className={styles.safeNote}>✅ {vt.harmless} security engines confirmed this URL as harmless</div>
      )}
    </div>
  )
}

// ── VT Panel ──────────────────────────────────────────────────
function VTPanel({ vt }) {
  if(!vt) return null
  const vtMal=vt.malicious??0
  return (
    <div className={styles.vtPanel}>
      <div className={styles.vtTitle}>🛡️ VirusTotal Analysis</div>
      {!vt.checked?(
        <div className={styles.vtRow}>
          <span className={styles.vtDot} style={{background:'var(--txt3)'}}/>
          <span className={styles.vtText}>Not yet indexed — submitted for analysis</span>
          <span className={styles.vtBadge} style={{background:'var(--bg-card2)',color:'var(--txt3)'}}>PENDING</span>
        </div>
      ):(
        <>
          <div className={styles.vtRow}>
            <span className={styles.vtDot} style={{background:vtMal>0?'var(--red)':'var(--green)'}}/>
            <span className={styles.vtText}>{vtMal>0?`${vtMal} engine(s) flagged as malicious`:'No engines flagged as malicious'}</span>
            <span className={styles.vtBadge} style={{
              background:vtMal>=3?'rgba(255,45,85,0.15)':vtMal>=1?'rgba(255,171,0,0.15)':'rgba(0,230,118,0.15)',
              color:vtMal>=3?'var(--red)':vtMal>=1?'var(--amber)':'var(--green)',
            }}>{vtMal>=3?'HIGH RISK':vtMal>=1?'LOW SIGNAL':'CLEAN'}</span>
          </div>
          {(vt.suspicious??0)>0&&<div className={styles.vtRow}><span className={styles.vtDot} style={{background:'var(--amber)'}}/><span className={styles.vtText}>{vt.suspicious} engine(s) flagged as suspicious</span></div>}
          {(vt.harmless??0)>0&&<div className={styles.vtRow}><span className={styles.vtDot} style={{background:'var(--green)'}}/><span className={styles.vtText}>{vt.harmless} engine(s) confirmed harmless</span></div>}
        </>
      )}
    </div>
  )
}

// ── Confidence explainer ──────────────────────────────────────
function ConfidenceExplainer({ confidence, weighted }) {
  const [open, setOpen] = useState(false)
  const explain = confidence.val>=90
    ? `Highly confident (${confidence.val}%) — multiple signals agree this URL is ${confidence.label.toLowerCase()}.`
    : confidence.val>=70
    ? `Moderately confident (${confidence.val}%) — most signals agree but minor uncertainty remains.`
    : `Lower confidence (${confidence.val}%) — mixed signals detected. Manual review recommended.`
  return (
    <div className={styles.confExplainer}>
      <button className={styles.confToggle} onClick={()=>setOpen(o=>!o)}>
        <span style={{color:confidence.color}}>Confidence: {confidence.val}% {confidence.label}</span>
        <span className={styles.confArrow}>{open?'▲':'▼'}</span>
      </button>
      {open&&<div className={styles.confExplainText}>{explain}</div>}
    </div>
  )
}

// ── Simple mode ───────────────────────────────────────────────
function SimpleExplain({ dv, weighted, vt }) {
  const vtMal=vt?.malicious??0, vtHarm=vt?.harmless??0
  const texts = {
    TRUSTED:      '🔒 This is a well-known, trusted website. Completely safe to visit.',
    SAFE:         '✅ This website looks safe. No warning signs were found.',
    SAFE_WARNING: `🟡 This website is mostly safe but has small warning signs. ${vtMal===1?`One security tool flagged it, but ${vtHarm} others said it's fine. `:''}You can visit it, but stay alert.`,
    SUSPICIOUS:   '⚠️ This website looks suspicious. Be careful — do not enter your personal information.',
    PHISHING:     '🚨 This website is likely a scam or phishing site. Do NOT visit it.',
  }
  return (
    <div className={styles.simpleExplain}>
      <div className={styles.simpleTitle}>💬 In Simple Terms</div>
      <div className={styles.simpleText}>{texts[dv]??texts.SAFE}</div>
    </div>
  )
}

// ── Feedback ──────────────────────────────────────────────────
function FeedbackWidget() {
  const [voted, setVoted] = useState(null)
  if(voted) return <div className={styles.feedbackDone}>{voted==='yes'?'✅ Thanks for confirming!':'👎 Feedback noted — helps improve accuracy!'}</div>
  return (
    <div className={styles.feedbackPanel}>
      <span className={styles.feedbackQ}>Was this result correct?</span>
      <div className={styles.feedbackBtns}>
        <button className={`${styles.fbBtn} ${styles.fbYes}`} onClick={()=>setVoted('yes')}>👍 Yes</button>
        <button className={`${styles.fbBtn} ${styles.fbNo}`}  onClick={()=>setVoted('no')}>👎 No</button>
      </div>
    </div>
  )
}

// ── Main ──────────────────────────────────────────────────────
export default function ScanResult({ result }) {
  const [mode, setMode] = useState('simple')
  const dv       = getDisplayVerdict(result)
  const cfg      = VERDICT_CONFIG[dv] ?? VERDICT_CONFIG.SAFE
  const weighted = Math.round(computeWeightedScore(result)*100)
  const scoreZoneColor = weighted>=70?'var(--red)':weighted>=40?'var(--amber)':'var(--green)'
  const scoreZone      = weighted>=70?'HIGH RISK':weighted>=40?'MODERATE RISK':'LOW RISK'
  const confidence     = getConfidence(dv, weighted, result.virustotal)
  const humanText      = getHumanVerdict(dv, weighted, result.virustotal)
  const summary        = getSummary(dv, weighted, result.virustotal)

  return (
    <div className={styles.wrap}>
      {/* Summary banner */}
      <div className={styles.summaryBanner}>{summary}</div>

      {/* Verdict banner */}
      <div className={`${styles.verdictBanner} ${cfg.cls}`}>
        <span className={styles.verdictIcon}>{cfg.icon}</span>
        <div style={{flex:1}}>
          <div style={{display:'flex',alignItems:'center',gap:8,flexWrap:'wrap'}}>
            <span className={styles.verdictLabel}>{cfg.label}</span>
            <TrustBadge dv={dv} />
          </div>
          <div className={styles.verdictSub}>
            Threat Score: <strong>{weighted}%</strong>
            <span className={styles.scoreZone} style={{color:scoreZoneColor}}> · {scoreZone}</span>
          </div>
        </div>
        <div className={styles.confidenceBadge}>
          <div className={styles.confVal} style={{color:confidence.color}}>{confidence.val}%</div>
          <div className={styles.confLbl}>Confidence<br/>{confidence.label}</div>
        </div>
      </div>

      {/* Mode toggle */}
      <div className={styles.modeToggle}>
        <button className={`${styles.modeBtn} ${mode==='simple'?styles.modeActive:''}`} onClick={()=>setMode('simple')}>💬 Simple</button>
        <button className={`${styles.modeBtn} ${mode==='technical'?styles.modeActive:''}`} onClick={()=>setMode('technical')}>🔬 Technical</button>
      </div>

      {/* Simple mode */}
      {mode==='simple' && <SimpleExplain dv={dv} weighted={weighted} vt={result.virustotal} />}

      {/* Technical mode */}
      {mode==='technical' && (
        <>
          {/* Score cards */}
          <div className={styles.scoreRow}>
            {[
              {lbl:'Threat Score', val:`${weighted}%`,                             color:cfg.color},
              {lbl:'ML Model',     val:`${(result.model_proba*100).toFixed(1)}%`,  color:(result.model_proba*100)>=50?'var(--amber)':''},
              {lbl:'URL Risk',     val:`${(result.url_risk*100).toFixed(1)}%`,     color:''},
              {lbl:'Flags',        val:result.flags?.length??0,                    color:(result.flags?.length??0)>0?'var(--amber)':''},
            ].map(s=>(
              <div key={s.lbl} className={styles.scoreCard}>
                <span className={styles.scoreVal} style={s.color?{color:s.color}:{}}>{s.val}</span>
                <span className={styles.scoreLbl}>{s.lbl}</span>
              </div>
            ))}
          </div>

          {/* Bar */}
          <div className={styles.barWrap}>
            <div className={styles.barHdr}>
              <span className={styles.barTitle}>THREAT PROBABILITY</span>
              <span className={styles.barPct} style={{color:scoreZoneColor}}>{weighted}%</span>
            </div>
            <div className={styles.barTrack}>
              <div className={styles.barZone} style={{left:'40%',borderColor:'var(--amber)'}}/>
              <div className={styles.barZone} style={{left:'70%',borderColor:'var(--red)'}}/>
              <div className={styles.barFill} style={{width:`${weighted}%`,background:scoreZoneColor}}/>
            </div>
            <div className={styles.barLabels}>
              <span style={{color:'var(--green)'}}>SAFE (0–39%)</span>
              <span style={{color:'var(--amber)'}}>SUSPICIOUS (40–69%)</span>
              <span style={{color:'var(--red)'}}>PHISHING (70%+)</span>
            </div>
          </div>

          <DecisionPanel result={result} />
          <WhyPanel result={result} />
          <ConfidenceExplainer confidence={confidence} weighted={weighted} />
          <VTPanel vt={result.virustotal} />

          {result.anatomy && (
            <>
              <div className="sec-lbl" style={{marginTop:18}}>URL Anatomy</div>
              <div className={styles.anatomy}>
                <span className={styles.aScheme}>{result.anatomy.scheme}://</span>
                {result.anatomy.subdomain&&<span className={styles.aSub}>{result.anatomy.subdomain}.</span>}
                <span className={styles.aDomain}>{result.anatomy.domain}</span>
                {result.anatomy.path&&<span className={styles.aPath}>{result.anatomy.path}</span>}
                {result.anatomy.query&&<span className={styles.aQuery}>?{result.anatomy.query}</span>}
              </div>
            </>
          )}

          <div className={styles.cols}>
            {result.flags?.length>0&&(
              <div>
                <div className="sec-lbl">Threat Indicators ({result.flags.length})</div>
                <div className={styles.flagsPanel}>
                  {result.flags.map((f,i)=>(
                    <div key={i} className={`${styles.flagItem} ${SEV_CLS[f.severity]??styles.flagLo}`}>
                      <div className={`${styles.fdot} ${SEV_CLS[f.severity]??styles.flagLo}`}/>
                      <span style={{flex:1}}>{f.text}</span>
                      <span className={styles.sevBadge}>{SEV_LABEL[f.severity]??'LOW'}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {result.features&&Object.keys(result.features).length>0&&(
              <div>
                <div className="sec-lbl">ML Features</div>
                <div className={styles.featGrid}>
                  {Object.entries(result.features).map(([k,v])=>(
                    <div key={k} className={styles.featPill}>
                      <span className={styles.featVal}>{typeof v==='number'?v.toFixed(2):v}</span>
                      <span className={styles.featName}>{k.replace(/([A-Z])/g,' $1').trim()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {/* Human verdict — always visible */}
      <div className={styles.humanVerdict}>
        <div className={styles.hvTitle}>🧾 Final Verdict</div>
        <div className={styles.hvText}>{humanText}</div>
      </div>

      <FeedbackWidget />
    </div>
  )
}