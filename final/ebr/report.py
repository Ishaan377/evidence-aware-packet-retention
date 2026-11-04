"""Self-contained HTML reports. Every figure on a page is computed from saved results."""
from html import escape
import json

COLORS = {'ebr': 1, 'flow_cutoff': 2, 'rare_dest': 3, 'ids_past_fill': 4, 'random_flow': 5, 'random_packet': 6, 'ebr_frozen': 7, 'ebr_repair': 8, 'ids_past': 8, 'v1_evidence': 8}
NAMES = {'ebr': 'EBR (this project)', 'ebr_frozen': 'EBR, first version', 'ebr_repair': 'EBR with repair', 'flow_cutoff': 'Tuned flow cutoff', 'rare_dest': 'Rare destinations', 'ids_past_fill': 'IDS-triggered + fill',
         'ids_past': 'IDS-triggered', 'random_flow': 'Random flows', 'random_packet': 'Random packets', 'v1_evidence': 'Original evidence algorithm',
         'v1_bundle': 'Original unweighted bundles'}

STYLE = """
:root{color-scheme:light;--surface:#fcfcfb;--page:#f9f9f7;--ink:#0b0b0b;--ink2:#52514e;--muted:#6f6d68;--grid:#e1e0d9;--axis:#c3c2b7;--ring:rgba(11,11,11,.10);
--s1:#2a78d6;--s2:#eb6834;--s3:#1baf7a;--s4:#eda100;--s5:#e87ba4;--s6:#008300;--s7:#6250d6;--s8:#e34948;--good:#006300;--bad:#d03b3b;--note:#52514e;--wash:#f0efec}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])){color-scheme:dark;--surface:#1a1a19;--page:#0d0d0d;--ink:#f0efec;--ink2:#c3c2b7;--muted:#a3a198;--grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);
--s1:#3987e5;--s2:#d95926;--s3:#199e70;--s4:#c98500;--s5:#d55181;--s6:#008300;--s7:#9085e9;--s8:#e66767;--good:#0ca30c;--bad:#e66767;--note:#c3c2b7;--wash:#262624}}
:root[data-theme="dark"]{color-scheme:dark;--surface:#1a1a19;--page:#0d0d0d;--ink:#f0efec;--ink2:#c3c2b7;--muted:#a3a198;--grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);
--s1:#3987e5;--s2:#d95926;--s3:#199e70;--s4:#c98500;--s5:#d55181;--s6:#008300;--s7:#9085e9;--s8:#e66767;--good:#0ca30c;--bad:#e66767;--note:#c3c2b7;--wash:#262624}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1020px;margin:0 auto;padding-block:40px 64px;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px))}
h1{font-size:30px;line-height:1.2;margin:0 0 10px}
h2{font-size:21px;margin:44px 0 8px}
h3{font-size:16px;margin:24px 0 6px}
p{margin:8px 0;max-width:74ch}
.lede{font-size:18px;color:var(--ink2)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:24px 0}
.tile{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:14px 16px}
.tile b{display:block;font-size:30px;line-height:1.15;font-weight:650}
.tile span{color:var(--ink2);font-size:14px}
.card{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:16px;margin:14px 0;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th{text-align:left;color:var(--ink2);font-weight:600;border-bottom:1px solid var(--axis);padding:7px 10px 7px 0;vertical-align:bottom}
td{border-bottom:1px solid var(--grid);padding:7px 10px 7px 0;vertical-align:top}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
tr.emph td{font-weight:650;background:var(--wash)}
code{font-family:ui-monospace,Consolas,monospace;font-size:13px}
.ok{color:var(--good);font-weight:600;white-space:nowrap}.no{color:var(--bad);font-weight:600;white-space:nowrap}.na{color:var(--note);white-space:nowrap}
.small{font-size:14px;color:var(--ink2)}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:13px;color:var(--ink2);margin:0 0 8px}
.legend i{display:inline-block;width:14px;height:3px;border-radius:2px;margin-right:6px;vertical-align:middle}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(300px,100%),1fr));gap:12px}
.charts .card{min-width:0}
svg text{font:12px system-ui,-apple-system,"Segoe UI",sans-serif;fill:var(--muted)}
svg .value{fill:var(--ink);font-weight:600}
#tip{position:fixed;display:none;pointer-events:none;background:var(--surface);color:var(--ink);border:1px solid var(--ring);box-shadow:0 2px 10px rgba(0,0,0,.14);border-radius:8px;padding:8px 10px;font-size:13px;z-index:5;max-width:280px}
"""

SCRIPT = """
const tip=document.getElementById('tip');
document.querySelectorAll('svg[data-chart]').forEach(svg=>{
 const hit=svg.querySelectorAll('[data-tip]');
 hit.forEach(h=>{
  const show=e=>{tip.innerHTML=h.dataset.tip;tip.style.display='block';const r=h.getBoundingClientRect();
   tip.style.left=Math.min(innerWidth-290,Math.max(8,r.left+r.width/2+10))+'px';tip.style.top=Math.max(8,r.top-10)+'px'};
  h.addEventListener('mouseenter',show);h.addEventListener('focus',show);
  h.addEventListener('mouseleave',()=>tip.style.display='none');h.addEventListener('blur',()=>tip.style.display='none');
 })});
"""


def page(title, body, fragment=False):
    """A complete document, or a fragment for hosts that supply the document skeleton."""
    content = f'<main>{body}</main><div id="tip"></div><script>{SCRIPT}</script>'
    if fragment:
        return f'<title>{escape(title)}</title><meta name="claude:viewport-fit-sides" content="cover"><style>{STYLE}</style>{content}'
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{escape(title)}</title><style>{STYLE}</style></head><body>{content}</body></html>')


def tiles(items):
    return '<div class="tiles">' + ''.join(f'<div class="tile"><b>{escape(str(v))}</b><span>{escape(k)}</span></div>' for v, k in items) + '</div>'


def table(headers, rows, numeric=(), emphasise=None):
    head = ''.join(f'<th class="n">{escape(h)}</th>' if i in numeric else f'<th>{escape(h)}</th>' for i, h in enumerate(headers))
    lines = []
    for row in rows:
        cells = ''.join(f'<td class="n">{c}</td>' if i in numeric else f'<td>{c}</td>' for i, c in enumerate(row))
        lines.append(f'<tr{" class=emph" if emphasise is not None and row[0] == emphasise else ""}>{cells}</tr>')
    return f'<div class="card"><table><thead><tr>{head}</tr></thead><tbody>{"".join(lines)}</tbody></table></div>'


def legend(policies):
    return '<div class="legend">' + ''.join(f'<span><i style="background:var(--s{COLORS[p]})"></i>{escape(NAMES[p])}</span>' for p in policies) + '</div>'


def line_chart(title, series, caps, policies):
    """Recall against storage cap. EBR is drawn last and thicker so it reads first."""
    width, height, left, right, top, bottom = 460, 270, 40, 16, 12, 34
    x_step = (width - left - right) / max(1, len(caps) - 1)
    x = lambda i: left + i * x_step
    y = lambda v: top + (1 - v) * (height - top - bottom)
    parts = [f'<svg data-chart viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title)}" width="100%">']
    for tick in (0, .25, .5, .75, 1):
        parts.append(f'<line x1="{left}" x2="{width - right}" y1="{y(tick):.1f}" y2="{y(tick):.1f}" stroke="var(--grid)"/>'
                     f'<text x="{left - 6}" y="{y(tick) + 4:.1f}" text-anchor="end">{tick:.0%}</text>')
    for i, cap in enumerate(caps):
        parts.append(f'<text x="{x(i):.1f}" y="{height - 12}" text-anchor="middle">{cap:g}%</text>')
    for policy in sorted(policies, key=lambda p: p == 'ebr'):
        values = series[policy]
        path = ' '.join(f'{"L" if j else "M"}{x(j):.1f} {y(v):.1f}' for j, v in enumerate(values))
        weight = 3 if policy == 'ebr' else 2
        color = f'var(--s{COLORS[policy]})'
        parts.append(f'<path d="{path}" fill="none" stroke="{color}" stroke-width="{weight}" stroke-linecap="round" stroke-linejoin="round"/>')
        for j, v in enumerate(values):
            tip = escape(f'<b>{NAMES[policy]}</b><br>{caps[j]:g}% cap: {v:.1%}', quote=True)
            parts.append(f'<circle cx="{x(j):.1f}" cy="{y(v):.1f}" r="4.5" fill="{color}" stroke="var(--surface)" stroke-width="2"/>'
                         f'<circle cx="{x(j):.1f}" cy="{y(v):.1f}" r="13" fill="transparent" tabindex="0" data-tip="{tip}"/>')
    # Sits under the line's end, where the comparators above it cannot collide with it.
    parts.append(f'<text class="value" x="{x(len(caps) - 1) - 2:.1f}" y="{y(series["ebr"][-1]) + 19:.1f}" text-anchor="end">EBR</text></svg>')
    return f'<div class="card"><h3 style="margin-top:0">{escape(title)}</h3>{"".join(parts)}</div>'


def megabytes(value):
    return f'{value / 1e9:.2f} GB' if value >= 1e9 else f'{value / 1e6:.1f} MB'


def demo_report(summary):
    cases, findings = summary['cases'], summary['findings']
    rows, caught, detectable, undetectable = [], 0, 0, 0
    for record in cases:
        for f in findings[record['case']]['findings']:
            if f['caught']:
                status, caught, detectable = '<span class="ok">✓ Caught</span>', caught + 1, detectable + 1
            elif f['detectable']:
                status, detectable = '<span class="no">✗ Missed</span>', detectable + 1
            else:
                status, undetectable = '<span class="na">– No rule fires</span>', undetectable + 1
            rank = f'#{f["suspect_rank"]}' if f['suspect_rank'] else 'Not in top 10'
            example = escape(f['examples'][0]) if f['examples'] else ''
            rows.append([escape(f['name']), status, f'{f["signatures_kept"]} of {f["signatures_full"]}',
                         f'{f["ledger"]["flows"]:,}', rank, f'<span class="small">{example}</span>'])
    kept, total = summary['output_bytes'], summary['input_bytes']
    alerts_full = sum(findings[c['case']]['attack_alerts_full'] for c in cases)
    alerts_kept = sum(findings[c['case']]['attack_alerts_kept'] for c in cases)
    body = [f'<h1>Forensic test on compressed evidence</h1><p class="lede">{megabytes(total)} of real attack captures were reduced to '
            f'{megabytes(kept)} with Evidence-Based Retention. Suricata then investigated only the reduced copy.</p>']
    body.append(tiles([(f'{100 * (1 - kept / total):.1f}%', 'storage saved'), (f'{caught} of {detectable}', 'detectable labelled attacks still caught'),
                       (f'{alerts_kept} of {alerts_full}', 'attack alert instances preserved'), (f'{summary["cap"]:.0%}', 'storage cap, ledger included')]))
    if summary['reference_run'] == 'test':
        body.append('<p class="small">These captures have publisher labels, but they helped shape the current version, so treat this as a demonstration and not as a sealed test. The sealed results are in the main report.</p>')
    body.append('<h2>Verdict for each labelled attack</h2><p>Attack windows and addresses come from the dataset publisher, not from this project. '
                'EBR saw no labels and no signatures. The suspect column is EBR\'s own ranking of hosts.</p>')
    body.append(table(['Attack', 'Verdict', 'Signatures kept', 'Flows in ledger', 'EBR suspect rank', 'Example detection on reduced copy'], rows, numeric=(2, 3)))
    if undetectable:
        body.append(f'<p class="small">{undetectable} labelled episode(s) raise no ET Open alert even on the complete capture, so an IDS test cannot score them. '
                    'Their traffic is still accounted for in the flow ledger.</p>')
    body.append('<h2>What was stored</h2>')
    body.append(table(['Case', 'Original', 'Kept', 'Packets kept', 'Flows in capture', 'Attack signatures kept'],
                      [[escape(c['case']), megabytes(c['input_bytes']), megabytes(c['output_bytes']), f'{c["packets_kept"]:,}', f'{c["flows"]:,}',
                        f'{findings[c["case"]]["attack_signatures_kept"]} of {findings[c["case"]]["attack_signatures_full"]}'] for c in cases],
                      numeric=(1, 2, 3, 4, 5)))
    invented = sum(findings[c['case']]['invented_attack_alerts'] for c in cases)
    body.append(f'<p class="small">Every retained packet is a byte-identical copy of its original record. Reduction created {invented} attack alert instance(s) '
                f'absent from the complete capture. Reference run: <code>{escape(summary["reference_run"])}</code>. Configuration SHA-256: <code>{summary["config_sha256"][:16]}…</code>. '
                'A forensic reduction is not legal chain of custody, and the complete capture cannot be rebuilt from it.</p>')
    return page('Forensic Demo Report', ''.join(body))


def results_report(data, fragment=False):
    """Render the frozen held-out study from the structure built by build_report.py."""
    caps, policies = data['caps'], data['policies']
    body = [f'<h1>{escape(data["title"])}</h1><p class="lede">{escape(data["lede"])}</p>', tiles(data['tiles'])]
    for section in data['sections']:
        body.append(f'<h2>{escape(section["heading"])}</h2>')
        for paragraph in section.get('text', []):
            body.append(f'<p>{paragraph}</p>')
        if section.get('charts'):
            body.append(legend(policies) + '<div class="charts">')
            for chart in section['charts']:
                body.append(line_chart(chart['title'], chart['series'], caps, policies))
            body.append('</div>')
        if section.get('table'):
            spec = section['table']
            body.append(table(spec['headers'], spec['rows'], tuple(spec.get('numeric', ())), spec.get('emphasise')))
        for paragraph in section.get('after', []):
            body.append(f'<p class="small">{paragraph}</p>')
    return page('EBR Forensic Test', ''.join(body), fragment)


def dump(data):
    return json.dumps(data, indent=1)
