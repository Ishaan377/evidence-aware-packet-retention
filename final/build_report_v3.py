"""Build the third sealed test's report. Verdicts follow the rule in sealed3_plan.json."""
import json
from pathlib import Path
from statistics import mean
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from build_report import CAPS, bootstrap_difference, collapse, curve, escape_time, percent, rows_of  # noqa: E402
from ebr.report import NAMES, results_report  # noqa: E402

FORENSIC = ROOT / 'results' / 'forensic'
METRICS = {'attack_sig_recall': 'Attack signatures preserved', 'attack_recall': 'Attack alert instances preserved'}
LINES = ['ebr_repair', 'ebr', 'ebr_frozen', 'ids_past_fill', 'rare_dest', 'flow_cutoff']
SCREEN_SHARE = 0.30


def label(case):
    words = case.replace('sealed3_', '').split('_')
    return f'IoT-23 {words[1]}-{words[2]}' if words[0] == 'iot' else f'WRCCDC {words[0][-4:]} at {words[1][1:]}%'


def supported(result):
    return bool(result) and result['mean'] > 0 and result['low'] > 0


def interval(result):
    return f'{result["mean"] * 100:+.1f} ({result["low"] * 100:+.1f} to {result["high"] * 100:+.1f})' if result else 'not scoreable'


def main():
    run, verify_run = FORENSIC / 'sealed3', FORENSIC / 'sealed3_verify'
    rows = rows_of(run / 'metrics.csv')
    verified = json.loads((verify_run / 'summary.json').read_text(encoding='utf8'))
    engaged = json.loads((run / 'cap_engaged.json').read_text(encoding='utf8'))
    plan = json.loads((ROOT / 'sealed3_plan.json').read_text(encoding='utf8'))
    freeze = json.loads((ROOT / 'FREEZE_v3.json').read_text(encoding='utf8'))
    lossless = json.loads((run / 'lossless.json').read_text(encoding='utf8')) if (run / 'lossless.json').exists() else {}
    tables = {metric: collapse(rows, metric) for metric in METRICS}
    cases = sorted({r['case'] for r in rows})
    references = {c: next(r for r in rows if r['case'] == c) for c in cases}
    scored = [c for c in cases if int(references[c]['attack_sig_refs'])]
    heavy = [c for c in scored if engaged[c]['silent_share_of_budget_without_cap']['0.05'] >= SCREEN_SHARE]
    curves = {m: {p: curve(table, p) for p in ('ebr', 'ebr_frozen', 'ids_past_fill', 'ids_past', 'rare_dest', 'flow_cutoff', 'random_flow')} for m, table in tables.items()}
    for metric in METRICS:
        curves[metric]['ebr_repair'] = verified['table']['past'][metric]['after']
    sig = tables['attack_sig_recall']
    h1 = {str(c): bootstrap_difference({k: v for k, v in sig.items() if k[0] in heavy}, 'ebr_frozen', c, heavy) for c in CAPS}
    h2, h3 = verified['comparisons']['signatures']['first'], verified['comparisons']['signatures']['ids']
    later_change = verified['comparisons']['later_rules']['first']
    spot = verified['blind_spot']
    h1_pass = all(supported(h1[k]) for k in ('0.05', '0.1'))
    h2_pass = all(supported(h2[str(c)]) for c in CAPS)
    h3_pass = all(supported(h3[str(c)]) for c in CAPS)
    later_values = [later_change[str(c)]['mean'] for c in CAPS if later_change[str(c)]]
    h4_pass = bool(later_values) and min(later_values) >= -0.05
    h5_ready = spot['pairs'] >= 10 and 'guess_the_mean' in spot
    h5_pass = h5_ready and spot['hidden_vs_later_after'] < spot['guess_the_mean']
    verdicts = dict(H1=h1_pass, H2=h2_pass, H3=h3_pass, H4=h4_pass, H5=h5_pass if h5_ready else None)
    input_bytes = sum(e['input_bytes'] for c, e in engaged.items() if c in cases)
    packets = sum(e['packets'] for c, e in engaged.items() if c in cases)
    summary = dict(freeze_time=freeze['frozen_at'], cases=cases, scored=scored, scan_heavy=heavy, input_bytes=input_bytes, packets=packets, verdicts=verdicts, h1=h1, curves=curves,
                   scan_noise=verified['scan_noise'], blind_spot=spot, lossless=lossless)
    (run / 'summary.json').write_text(json.dumps(summary, indent=1), encoding='utf8')

    word = lambda value: 'Not scoreable' if value is None else ('Supported' if value else 'Not supported')
    five = CAPS.index(0.05)
    tiles = [(f'{sum(1 for v in verdicts.values() if v)} of {len(verdicts)}', 'pre-registered hypotheses supported'), (percent(curves['attack_sig_recall']['ebr_repair'][five]), 'attack signatures kept with repair at 5%'),
             (percent(curves['attack_sig_recall']['ids_past_fill'][five]), 'IDS-triggered capture on the same data'), (f'{input_bytes / 1e9:.1f} GB', f'sealed evidence, {packets / 1e6:.1f} million packets')]
    rows_h = [['H1', plan['hypotheses']['H1'], word(h1_pass), f'5%: {interval(h1["0.05"])}; 10%: {interval(h1["0.1"])}'],
              ['H2', plan['hypotheses']['H2'], word(h2_pass), '; '.join(f'{c:.0%}: {interval(h2[str(c)])}' for c in CAPS)],
              ['H3', plan['hypotheses']['H3'], word(h3_pass), '; '.join(f'{c:.0%}: {interval(h3[str(c)])}' for c in CAPS)],
              ['H4', plan['hypotheses']['H4'], word(h4_pass), '; '.join(f'{c:.0%}: {later_change[str(c)]["mean"] * 100:+.1f}' for c in CAPS if later_change[str(c)])],
              ['H5', plan['hypotheses']['H5'], word(verdicts['H5']), f'{spot["pairs"]} usable pairs against the 10 required. Estimate error {spot["hidden_vs_later_after"] * 100:.1f} points, guessing {spot["guess_the_mean"] * 100:.1f}']]
    screen_rows = [[label(c), f'{engaged[c]["input_bytes"] / 1e6:,.0f} MB', f'{engaged[c]["flows"]:,}', f'{engaged[c]["silent_share_of_budget_without_cap"]["0.05"]:.0%}', 'Yes' if c in heavy else ('No' if c in scored else 'No alerts, not scored'), references[c]['attack_sig_refs']] for c in cases]
    case_rows = []
    for case in scored:
        cells = [label(case)]
        for policy in ('ebr', 'ebr_frozen', 'ids_past_fill'):
            cells.append(percent(sig.get((case, policy, 0.05)), 0))
        cells.append(percent(next(r['attack_sig_recall'] for r in json.loads((verify_run / 'results.json').read_text(encoding='utf8'))[::-1] if r['case'] == case and r['cap'] == 0.05 and r['condition'] == 'past'), 0))
        case_rows.append(cells)
    t = verified['table']['past']
    helped = [c for c in scored if any(sig[(c, 'ebr', cap)] > sig[(c, 'ebr_frozen', cap)] + 1e-9 for cap in CAPS)]
    hurt = [c for c in scored if any(sig[(c, 'ebr', cap)] < sig[(c, 'ebr_frozen', cap)] - 1e-9 for cap in CAPS)]
    earlier_one = json.loads((FORENSIC / 'test' / 'summary.json').read_text(encoding='utf8'))
    earlier_two = json.loads((FORENSIC / 'sealed2' / 'summary.json').read_text(encoding='utf8'))
    together = [
        ['First', f'{earlier_one["input_bytes"] / 1e9:.1f} GB, CIC attacks and WRCCDC', percent(earlier_one['curves']['attack_sig_recall']['ebr'][five]), '–', percent(earlier_one['curves']['attack_sig_recall']['ids_past_fill'][five])],
        ['Second', f'{earlier_two["input_bytes"] / 1e9:.1f} GB, WRCCDC, CTU and CIC', percent(earlier_two['curves']['attack_sig_recall']['ebr'][five]), '–', percent(earlier_two['curves']['attack_sig_recall']['ids_past_fill'][five])],
        ['Third', f'{input_bytes / 1e9:.1f} GB, IoT botnets and WRCCDC', percent(curves['attack_sig_recall']['ebr'][five]), percent(curves['attack_sig_recall']['ebr_repair'][five]), percent(curves['attack_sig_recall']['ids_past_fill'][five])]]
    sections = [dict(heading='What this means', text=[
        f'<b>The verification loop is the strongest result.</b> Repair beat EBR alone at every cap by a clear margin, and it beat IDS-triggered capture at 2%, 5% and 10% with the same rule knowledge. At 1% that comparison is inconclusive.',
        f'<b>EBR alone is not always ahead.</b> On these scan-dominated captures it fell behind IDS-triggered capture at 1% and 2%, was level at 5%, and led at 10%. Earlier tests were kinder to it, so traffic type matters.',
        f'<b>The scan cap was not confirmed.</b> It helped in {len(helped)} of {len(scored)} scored cases and hurt signature recall in {len(hurt)}, but it failed the pre-registered test at 5% and 10%. It is better described as a safeguard against a rare failure than as a general improvement.',
        f'<b>The blind-spot estimate did not hold up.</b> Too few later-published rules fired here for a formal verdict, but on the {spot["pairs"]} usable pairs it missed by {spot["hidden_vs_later_after"] * 100:.1f} points, worse than the {spot["guess_the_mean"] * 100:.1f} from simply guessing the mean. The promising figure from the unsealed prototype should not be relied on.']),
        dict(heading='All three sealed tests', text=['Attack signatures kept at a 5% cap. Repair was only sealed-tested in the third test.'],
             table=dict(headers=['Test', 'Data', 'EBR alone', 'EBR with repair', 'IDS + fill'], rows=together, numeric=(2, 3, 4))),
        dict(heading='What was tested', text=[
        f'Version 3 was frozen on {escape_time(freeze["frozen_at"])}, with hashes of {len(freeze["files"])} files that include the pre-registered plan, before any of these captures was opened. The plan fixed the hypotheses, the primary measure and the rule for calling each one supported.',
        f'A blind screen then found which captures have scan storms, from packet headers alone, before any detection ran. {len(heavy)} of the {len(scored)} scored cases qualified. Of {len(cases)} captures in total, the ones with no attack alerts on the complete capture cannot be scored.',
        'A hypothesis counts as supported at a cap only if the mean difference favours it and the 95% interval excludes zero. Intervals resample the cases.']),
        dict(heading='Verdict on each hypothesis', table=dict(headers=['', 'Hypothesis', 'Result', 'Difference in points (95% interval)'], rows=rows_h)),
        dict(heading='Attack signatures kept', text=[f'Means across {len(scored)} scored cases. Signature recall is the primary measure because repeated scans did not change it.'],
             charts=[dict(title=METRICS[m], series={p: [v or 0 for v in curves[m][p]] for p in LINES}) for m in METRICS],
             table=dict(headers=['Attack signatures preserved'] + [f'{c:.0%} cap' for c in CAPS], rows=[[NAMES[p]] + [percent(v) for v in curves['attack_sig_recall'][p]] for p in LINES], numeric=(1, 2, 3, 4), emphasise=NAMES['ebr_repair'])),
        dict(heading='The scan screen', text=['Each capture\'s share is how much of the packet budget payload-free flows would take at a 5% cap with the scan cap removed.'],
             table=dict(headers=['Capture', 'Size', 'Flows', 'Scan share', 'Scan-heavy', 'Attack signatures'], rows=screen_rows, numeric=(1, 2, 3, 5))),
        dict(heading='Case by case at a 5% cap', table=dict(headers=['Case', 'EBR', 'First version', 'IDS + fill', 'EBR with repair'], rows=case_rows, numeric=(1, 2, 3, 4))),
        dict(heading='What repair cost', text=[
            f'Repaired flows used {percent(t["repair_share_of_budget"][0])}, {percent(t["repair_share_of_budget"][1])}, {percent(t["repair_share_of_budget"][2])} and {percent(t["repair_share_of_budget"][3])} of the budget at the four caps. '
            f'Repair made {len(verified["repair_made_worse"])} of {len(scored) * 8} case comparisons worse. {t["lost_after"][five]} of {t["known_total"][five]} usable alerts stayed lost at 5%.']),
        dict(heading='Why the results came out this way', text=[
            '<b>The cap had little to protect on IoT captures.</b> A botnet host produces millions of scan flows but few flows with content, so that content usually fits with or without the cap.',
            '<b>EBR alone missed login sprays.</b> On the Hide and Seek capture it lost 110 of 158 attack alert instances at a 10% cap, mostly telnet logins using known default passwords. Each attempt has the same size and shape, and the difference lies in the password, so diminishing returns treats them as repeats. This is a real blind spot in the idea that does most of EBR\'s work.',
            '<b>Repair struggles with rate-based rules.</b> Most alerts still lost at 5% come from scan rules that need many flows close together, and restoring those can take more budget than exists.']),
        dict(heading='Scan noise', text=[f'Scanning identical selections twice changed {verified["scan_noise"]["differing"]} of {verified["scan_noise"]["comparisons"]} comparisons, by {verified["scan_noise"]["mean_instance_gap"] * 100:.1f} points of alert instance recall on average and {verified["scan_noise"]["max_instance_gap"] * 100:.1f} at most.',
                                         f'<b>A correction.</b> Earlier reports said signature recall did not move between scans. Here it moved by {verified["scan_noise"]["mean_signature_gap"] * 100:.1f} points on average and by {verified["scan_noise"]["max_signature_gap"] * 100:.1f} on one case with only 8 signatures. It is still the steadier measure, but small differences on small cases should not be read as real.']),
        dict(heading='Limits', text=[plan['disclosures'], f'{len(scored)} scored cases is a small test, and several come from a few malware families.',
                                     'IoT-23 captures are the first 300 MB of longer recordings, and they are dominated by scanning from one infected host.',
                                     'This report covers a rule-based detector only. It says nothing about what a human analyst could reconstruct.'])]
    report = dict(title='EBR third sealed test', lede=f'The scan cap and the verification loop, tested on {input_bytes / 1e9:.1f} GB of captures opened only after the plan was frozen.',
                  tiles=tiles, sections=sections, caps=[c * 100 for c in CAPS], policies=LINES)
    (run / 'report.html').write_text(results_report(report), encoding='utf8')
    (run / 'report_fragment.html').write_text(results_report(report, True), encoding='utf8')
    print('Wrote', run / 'report.html')
    print('verdicts', verdicts)
    print('scored', len(scored), 'heavy', heavy)
    for name, data in (('H1', h1), ('H2', h2), ('H3', h3)):
        print(name, {k: interval(v) for k, v in data.items()})
    for metric in METRICS:
        print(metric)
        for p in LINES:
            print(f'  {p:<14}', [None if v is None else round(v, 3) for v in curves[metric][p]])


if __name__ == '__main__':
    main()
