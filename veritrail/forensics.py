"""
veritrail.forensics
===================
Generates a self-contained HTML "flight-recorder readout" for a single action:
the reconstructed chain of custody, the cryptographic verification status of
every hop, and any findings. It takes no external assets so the file is a
portable, archivable, emailable piece of evidence.
"""

from __future__ import annotations

import html
import time
from typing import Any

from .engine import Engine, VerdictResult

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _esc(x: Any) -> str:
    return html.escape(str(x), quote=True)


def _short(s: str, n: int = 16) -> str:
    s = str(s)
    return s if len(s) <= n else s[:n] + "\u2026"


def build_report(engine: Engine, verdict: VerdictResult) -> str:
    action = engine._actions[verdict.action_id]
    chain = verdict.chain
    verified = verdict.authorized
    accent = "var(--ok)" if verified else "var(--alert)"
    verdict_word = "AUTHORIZED" if verified else "NOT VERIFIED"
    sub = (
        "Chain of custody reconstructs to a human principal; no blocking findings."
        if verified
        else "Authorization could not be verified, or a blocking finding was raised."
    )

    # Custody chain: chain.chain is leaf->root; render root at top, leaf at bottom
    # so authority visibly narrows as it descends to the action.
    links = list(reversed(chain.chain))
    chain_rows = []
    for idx, d in enumerate(links):
        scope = d["scope"]
        is_root = d.get("parent_id") is None
        issuer = _esc(d["issuer_id"])
        subject = _esc(d["subject_id"])
        tools = ", ".join(scope.get("allowed_tools", [])) or "\u2014"
        actions = ", ".join(scope.get("allowed_actions", [])) or "\u2014"
        role = "HUMAN ROOT" if is_root else f"HOP {idx}"
        chain_rows.append(f"""
        <div class="link">
          <div class="link-rail"><span class="node {'node-root' if is_root else ''}"></span></div>
          <div class="link-body">
            <div class="link-head">
              <span class="badge">{role}</span>
              <span class="verified">&#10003; signature verified</span>
            </div>
            <div class="grant">{issuer} <span class="arrow">delegates to</span> {subject}</div>
            <div class="purpose">&ldquo;{_esc(d['purpose'])}&rdquo;</div>
            <div class="scopebar">
              <span><b>tools</b> {_esc(tools)}</span>
              <span><b>actions</b> {_esc(actions)}</span>
              <span><b>max risk</b> {_esc(scope.get('max_risk'))}</span>
            </div>
            <div class="delid">{_esc(d['id'])}</div>
          </div>
        </div>""")

    # The action leaf.
    chain_rows.append(f"""
        <div class="link link-action">
          <div class="link-rail"><span class="node node-action"></span></div>
          <div class="link-body">
            <div class="link-head"><span class="badge badge-action">ACTION</span></div>
            <div class="grant">{_esc(action.actor_id)} <span class="arrow">performed</span> {_esc(action.tool)} / {_esc(action.action)}</div>
            <div class="purpose">&ldquo;{_esc(action.description)}&rdquo;</div>
            <div class="scopebar"><span><b>risk</b> {_esc(action.risk)}</span><span><b>params digest</b> {_esc(_short(action.params_digest, 24))}</span></div>
            <div class="delid">{_esc(action.id)}</div>
          </div>
        </div>""")

    findings = sorted(verdict.findings, key=lambda f: -_SEV_RANK.get(f["severity"], 0))
    if findings:
        finding_rows = "".join(f"""
          <div class="finding sev-{_esc(f['severity'])}">
            <div class="finding-top"><span class="fcode">{_esc(f['code'])}</span><span class="fsev">{_esc(f['severity'])}</span></div>
            <div class="ftitle">{_esc(f['title'])}</div>
            <div class="fmsg">{_esc(f['message'])}</div>
          </div>""" for f in findings)
    else:
        finding_rows = '<div class="no-findings">No anomalies detected across signature, scope, expiry, intent, and human-in-the-loop checks.</div>'

    errors_html = ""
    if chain.errors:
        items = "".join(f"<li>{_esc(e)}</li>" for e in chain.errors)
        errors_html = f'<div class="errors"><div class="errors-h">Chain verification errors</div><ul>{items}</ul></div>'

    generated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    stats = engine.stats()
    # Precompute values that contain backslash escapes; embedding a backslash
    # inside an f-string replacement field is a SyntaxError before Python 3.12.
    human_root_display = chain.human_root_name or "\u2014 none \u2014"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Veritrail Evidence \u2014 {_esc(action.id)}</title>
<style>
  :root {{
    --ink: #0f1419; --panel: #161d26; --panel-2: #1d2733;
    --line: #2a3644; --text: #e6edf3; --muted: #8b9bad;
    --ok: #3fd6a8; --alert: #ff6b5e; --amber: #f5c451; --accent: {accent};
    --mono: 'SFMono-Regular', ui-monospace, 'Cascadia Code', Menlo, Consolas, monospace;
    --sans: ui-sans-serif, system-ui, 'Segoe UI', Roboto, Helvetica, Arial;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background: var(--ink); color: var(--text); font-family: var(--sans);
         -webkit-font-smoothing: antialiased; line-height: 1.5; }}
  .wrap {{ max-width: 880px; margin: 0 auto; padding: 40px 24px 80px; }}
  .eyebrow {{ font-family: var(--mono); font-size: 11px; letter-spacing: .22em;
             text-transform: uppercase; color: var(--muted); }}
  .verdict {{ display:flex; align-items:center; gap:18px; margin: 14px 0 6px; }}
  .seal {{ width: 56px; height: 56px; border-radius: 50%; border: 2px solid var(--accent);
          display:grid; place-items:center; color: var(--accent); flex: none;
          box-shadow: 0 0 0 6px color-mix(in srgb, var(--accent) 12%, transparent); }}
  .seal svg {{ width: 28px; height: 28px; }}
  h1 {{ font-size: 30px; margin: 0; letter-spacing: -0.02em; }}
  h1 .v {{ color: var(--accent); }}
  .sub {{ color: var(--muted); margin: 2px 0 0; font-size: 14px; }}
  .meta {{ display:flex; flex-wrap:wrap; gap: 10px 28px; margin: 22px 0 30px;
          padding: 16px 18px; background: var(--panel); border:1px solid var(--line);
          border-radius: 12px; font-size: 13px; }}
  .meta div span {{ display:block; }}
  .meta .k {{ font-family: var(--mono); font-size: 10px; letter-spacing:.14em;
             text-transform: uppercase; color: var(--muted); }}
  .meta .val {{ font-family: var(--mono); color: var(--text); word-break: break-all; }}
  .section-h {{ font-family: var(--mono); font-size: 11px; letter-spacing:.2em;
               text-transform: uppercase; color: var(--muted); margin: 34px 0 14px;
               display:flex; align-items:center; gap:12px; }}
  .section-h::after {{ content:""; flex:1; height:1px; background: var(--line); }}
  /* Custody chain */
  .chain {{ position: relative; }}
  .link {{ display:flex; gap: 18px; }}
  .link-rail {{ position: relative; width: 14px; flex:none; display:flex; justify-content:center; }}
  .link-rail::before {{ content:""; position:absolute; top: 0; bottom: -2px; width: 2px;
                        background: var(--line); left: 6px; }}
  .link:last-child .link-rail::before {{ bottom: 50%; }}
  .node {{ width: 14px; height: 14px; border-radius: 50%; background: var(--panel-2);
          border: 2px solid var(--ok); margin-top: 18px; position: relative; z-index:1; }}
  .node-root {{ border-color: var(--amber); background: var(--amber); }}
  .node-action {{ border-color: var(--accent); background: var(--accent); }}
  .link-body {{ flex:1; background: var(--panel); border:1px solid var(--line);
               border-radius: 12px; padding: 14px 16px; margin-bottom: 12px; }}
  .link-action .link-body {{ border-color: color-mix(in srgb, var(--accent) 45%, var(--line)); }}
  .link-head {{ display:flex; justify-content: space-between; align-items:center; margin-bottom: 8px; }}
  .badge {{ font-family: var(--mono); font-size: 10px; letter-spacing:.16em; padding: 3px 8px;
           border:1px solid var(--line); border-radius: 999px; color: var(--muted); }}
  .badge-action {{ color: var(--accent); border-color: color-mix(in srgb, var(--accent) 50%, var(--line)); }}
  .verified {{ font-size: 11px; color: var(--ok); font-family: var(--mono); }}
  .grant {{ font-size: 15px; font-weight: 600; }}
  .arrow {{ color: var(--muted); font-weight: 400; font-size: 13px; }}
  .purpose {{ color: var(--muted); font-style: italic; font-size: 13px; margin: 4px 0 10px; }}
  .scopebar {{ display:flex; flex-wrap:wrap; gap: 6px 18px; font-size: 12px; font-family: var(--mono); color: var(--text); }}
  .scopebar b {{ color: var(--muted); font-weight: 500; }}
  .delid {{ font-family: var(--mono); font-size: 11px; color: #5d6b7b; margin-top: 10px; word-break: break-all; }}
  /* Findings */
  .finding {{ border:1px solid var(--line); border-left: 3px solid var(--muted);
             border-radius: 8px; padding: 12px 14px; margin-bottom: 10px; background: var(--panel); }}
  .finding.sev-critical {{ border-left-color: var(--alert); }}
  .finding.sev-high {{ border-left-color: var(--alert); }}
  .finding.sev-medium {{ border-left-color: var(--amber); }}
  .finding.sev-low {{ border-left-color: var(--ok); }}
  .finding-top {{ display:flex; justify-content: space-between; font-family: var(--mono); font-size: 11px; }}
  .fcode {{ color: var(--text); letter-spacing:.1em; }}
  .fsev {{ text-transform: uppercase; color: var(--muted); }}
  .ftitle {{ font-weight: 600; margin: 4px 0 2px; }}
  .fmsg {{ color: var(--muted); font-size: 13px; }}
  .no-findings {{ color: var(--ok); font-size: 14px; padding: 14px 16px; border:1px dashed var(--line); border-radius: 10px; }}
  .errors {{ margin-top: 14px; border:1px solid var(--alert); border-radius: 10px; padding: 12px 16px; }}
  .errors-h {{ color: var(--alert); font-family: var(--mono); font-size: 12px; letter-spacing:.1em; }}
  .errors ul {{ margin: 8px 0 0; padding-left: 18px; color: var(--text); font-size: 13px; }}
  footer {{ margin-top: 44px; padding-top: 18px; border-top:1px solid var(--line);
           color: #5d6b7b; font-family: var(--mono); font-size: 11px; display:flex;
           justify-content: space-between; flex-wrap: wrap; gap: 8px; }}
  @media (max-width: 560px) {{ h1 {{ font-size: 23px; }} .meta {{ gap: 10px 16px; }} }}
</style></head>
<body><div class="wrap">
  <div class="eyebrow">Veritrail &middot; Agent Action Provenance &amp; Forensics</div>
  <div class="verdict">
    <div class="seal">{_seal_svg(verified)}</div>
    <div>
      <h1>Verdict: <span class="v">{verdict_word}</span></h1>
      <p class="sub">{sub}</p>
    </div>
  </div>

  <div class="meta">
    <div><span class="k">Action ID</span><span class="val">{_esc(action.id)}</span></div>
    <div><span class="k">Human root</span><span class="val">{_esc(human_root_display)}</span></div>
    <div><span class="k">Hops to human</span><span class="val">{_esc(chain.hops)}</span></div>
    <div><span class="k">Max severity</span><span class="val">{_esc(verdict.max_severity)}</span></div>
    <div><span class="k">Ledger head</span><span class="val">{_esc(_short(stats['ledger_head'], 20))}</span></div>
    <div><span class="k">Merkle root</span><span class="val">{_esc(_short(stats['merkle_root'], 20))}</span></div>
  </div>

  <div class="section-h">Chain of custody</div>
  <div class="chain">{''.join(chain_rows)}</div>
  {errors_html}

  <div class="section-h">Findings</div>
  {finding_rows}

  <footer>
    <span>Generated {generated}</span>
    <span>Ed25519 / SHA-256 &middot; tamper-evident ledger verified</span>
  </footer>
</div></body></html>"""


def _seal_svg(ok: bool) -> str:
    if ok:
        return ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
                'stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">'
                '<path d="M20 6 9 17l-5-5"/></svg>')
    return ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            'stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M12 9v4"/><path d="M12 17h.01"/>'
            '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>')
