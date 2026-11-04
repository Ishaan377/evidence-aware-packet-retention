"""Summarise the verify-before-delete prototype into verify/summary.json and a readable table.

Gains are compared with EBR's first selection on the same case and cap. The blind-spot
estimate is judged against later-rule alerts, which no system could have used at capture.
"""
import csv
import json
from pathlib import Path
from statistics import mean
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from build_report import CAPS, bootstrap_difference, number  # noqa: E402

FORENSIC = ROOT / 'results' / 'forensic'
SOURCES = sys.argv[2:] or ['test', 'sealed2']


def mean_of(values):
    usable = [v for v in values if v is not None]
    return mean(usable) if usable else None


def comparator(policy, metric):
    """Mean of an earlier run's policy on the same cases, averaged per case then across cases."""
    rows = []
    for run in SOURCES:
        with (FORENSIC / run / 'metrics.csv').open(encoding='utf8') as stream:
            rows += [r for r in csv.DictReader(stream) if r['policy'] == policy and r[metric] not in ('', 'None')]
    return [mean_of([float(r[metric]) for r in rows if float(r['fraction']) == cap]) for cap in CAPS]


def main():
    run = FORENSIC / sys.argv[1]
    rows = json.loads((run / 'results.json').read_text(encoding='utf8'))
    first = {(r['case'], r['cap'], r['condition']): r for r in rows if r['round'] == 0}
    last = {}
    for row in rows:
        key = (row['case'], row['cap'], row['condition'])
        if key not in last or row['round'] > last[key]['round']:
            last[key] = row
    cases = sorted({r['case'] for r in rows})
    scored = [c for c in cases if first[(c, CAPS[0], 'all')]['attack_refs']]
    table = {}
    for condition in ('all', 'past', 'half'):
        table[condition] = {}
        for metric in ('attack_recall', 'attack_sig_recall', 'known_recall', 'unseen_recall', 'later_recall', 'hidden_recall'):
            table[condition][metric] = dict(
                before=[mean_of([first[(c, cap, condition)][metric] for c in scored]) for cap in CAPS],
                after=[mean_of([last[(c, cap, condition)][metric] for c in scored]) for cap in CAPS])
        table[condition]['repair_share_of_budget'] = [mean_of([last[(c, cap, condition)]['repaired_bytes'] / last[(c, cap, condition)]['budget'] for c in scored]) for cap in CAPS]
        table[condition]['rounds_used'] = [mean_of([last[(c, cap, condition)]['round'] for c in scored]) for cap in CAPS]
        table[condition]['lost_after'] = [sum(round((1 - (last[(c, cap, condition)]['known_recall'] or 1)) * last[(c, cap, condition)]['known_refs']) for c in scored) for cap in CAPS]
        table[condition]['known_total'] = [sum(last[(c, cap, condition)]['known_refs'] for c in scored) for cap in CAPS]
        table[condition]['invented_before'] = [sum(first[(c, cap, condition)]['invented'] for c in scored) for cap in CAPS]
        table[condition]['invented_after'] = [sum(last[(c, cap, condition)]['invented'] for c in scored) for cap in CAPS]

    # How well does what is measurable before deletion predict what nothing could see?
    pairs = []
    for case in scored:
        for cap in CAPS:
            start, finish = first[(case, cap, 'past')], last[(case, cap, 'past')]
            if finish['later_refs'] >= 5 and start['known_refs'] >= 5:
                pairs.append(dict(case=case, cap=cap, later_refs=finish['later_refs'], estimate=start['known_recall'], hidden=last[(case, cap, 'half')]['hidden_recall'],
                                  later_before=start['later_recall'], later_after=finish['later_recall']))
    errors = dict(pairs=len(pairs),
                  estimate_vs_later_before=mean_of([abs(p['estimate'] - p['later_before']) for p in pairs]),
                  estimate_bias=mean_of([p['estimate'] - p['later_before'] for p in pairs]),
                  hidden_vs_later_after=mean_of([abs(p['hidden'] - p['later_after']) for p in pairs if p['hidden'] is not None]),
                  hidden_bias=mean_of([p['hidden'] - p['later_after'] for p in pairs if p['hidden'] is not None]))
    if len(pairs) > 2:
        xs, ys = [p['estimate'] for p in pairs], [p['later_before'] for p in pairs]
        mx, my = mean(xs), mean(ys)
        cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
        norm = (sum((x - mx) ** 2 for x in xs) * sum((y - my) ** 2 for y in ys)) ** 0.5
        errors['correlation'] = cov / norm if norm else None
    # Paired comparisons by case, because cases are the independent units.
    ids = {}
    for name in SOURCES:
        with (FORENSIC / name / 'metrics.csv').open(encoding='utf8') as stream:
            for r in csv.DictReader(stream):
                if r['policy'] == 'ids_past_fill':
                    ids[(r['case'], float(r['fraction']))] = r
    def paired(metric, ids_metric):
        table_for = {}
        for case in scored:
            for cap in CAPS:
                table_for[(case, 'ebr', cap)] = last[(case, cap, 'past')][metric]
                table_for[(case, 'first', cap)] = first[(case, cap, 'past')][metric]
                value = number(ids[(case, cap)][ids_metric])
                if value is not None:
                    table_for[(case, 'ids', cap)] = value
        table_for = {k: v for k, v in table_for.items() if v is not None}
        return {other: {str(cap): bootstrap_difference(table_for, other, cap, scored) for cap in CAPS} for other in ('first', 'ids')}
    comparisons = dict(signatures=paired('attack_sig_recall', 'attack_sig_recall'), instances=paired('attack_recall', 'attack_recall'), later_rules=paired('later_recall', 'future_recall'))
    fresh = [c for c in scored if c.startswith(SOURCES[-1])]
    fresh_view = {metric: dict(ebr=[mean_of([first[(c, cap, 'past')][metric] for c in fresh]) for cap in CAPS], verified=[mean_of([last[(c, cap, 'past')][metric] for c in fresh]) for cap in CAPS],
                               ids=[mean_of([number(ids[(c, cap)][{'later_recall': 'future_recall'}.get(metric, metric)]) for c in fresh]) for cap in CAPS]) for metric in ('attack_sig_recall', 'attack_recall', 'later_recall')}
    # The sealed run and this run's first round scanned identical selections, so any gap is scan noise.
    noise_rows = []
    with (FORENSIC / SOURCES[-1] / 'metrics.csv').open(encoding='utf8') as stream:
        for r in csv.DictReader(stream):
            key = (r['case'], float(r['fraction']), 'all')
            if r['policy'] == 'ebr' and r['attack_recall'] not in ('', 'None') and key in first:
                noise_rows.append((abs(float(r['attack_recall']) - first[key]['attack_recall']), abs(float(r['attack_sig_recall']) - first[key]['attack_sig_recall'])))
    scan_noise = dict(comparisons=len(noise_rows), differing=sum(1 for a, b in noise_rows if a > 1e-9 or b > 1e-9), mean_instance_gap=mean_of([a for a, _ in noise_rows]),
                      max_instance_gap=max((a for a, _ in noise_rows), default=None), mean_signature_gap=mean_of([b for _, b in noise_rows]), max_signature_gap=max((b for _, b in noise_rows), default=None))
    guesses = [p for p in pairs if p['hidden'] is not None]
    if guesses:
        average = mean(p['later_after'] for p in guesses)
        errors['guess_the_mean'] = mean(abs(p['later_after'] - average) for p in guesses)
        errors['worst_error'] = max(abs(p['hidden'] - p['later_after']) for p in guesses)
        mh = mean(p['hidden'] for p in guesses)
        spread = (sum((p['hidden'] - mh) ** 2 for p in guesses) * sum((p['later_after'] - average) ** 2 for p in guesses)) ** 0.5
        errors['hidden_correlation'] = sum((p['hidden'] - mh) * (p['later_after'] - average) for p in guesses) / spread if spread else None
    worse = []
    for case in scored:
        for cap in CAPS:
            for metric in ('attack_sig_recall', 'attack_recall'):
                before, after = first[(case, cap, 'past')][metric], last[(case, cap, 'past')][metric]
                if before is not None and after is not None and after < before - 1e-9:
                    worse.append(dict(case=case, cap=cap, metric=metric, before=before, after=after))
    summary = dict(cases=cases, scored=scored, table=table, blind_spot=errors, pairs=pairs, comparisons=comparisons, fresh_cases=fresh_view, repair_made_worse=worse, scan_noise=scan_noise,
                   ids_fill=dict(attack_recall=comparator('ids_past_fill', 'attack_recall'), attack_sig_recall=comparator('ids_past_fill', 'attack_sig_recall'), future_recall=comparator('ids_past_fill', 'future_recall')),
                   timing=[json.loads(line) for line in (run / 'timing.jsonl').read_text(encoding='utf8').splitlines()])
    (run / 'summary.json').write_text(json.dumps(summary, indent=1), encoding='utf8')

    show = lambda values: ' '.join('   -  ' if v is None else f'{v * 100:5.1f}%' for v in values)
    print(f'{len(scored)} scored cases of {len(cases)}')
    for condition in ('all', 'past', 'half'):
        t = table[condition]
        print(f'\n[{condition}]  caps 1/2/5/10%')
        for metric in ('attack_recall', 'attack_sig_recall', 'known_recall', 'unseen_recall', 'later_recall', 'hidden_recall'):
            print(f'  {metric:<18} before {show(t[metric]["before"])}   after {show(t[metric]["after"])}')
        print(f'  repair share of budget  {show(t["repair_share_of_budget"])}   mean last round {[round(v, 2) for v in t["rounds_used"]]}')
        print(f'  known alerts still lost {t["lost_after"]} of {t["known_total"]}   invented before {t["invented_before"]} after {t["invented_after"]}')
    print('\nIDS + fill for comparison:', {k: [None if x is None else round(x, 3) for x in v] for k, v in summary['ids_fill'].items()})
    print('blind spot:', {k: (round(v, 3) if isinstance(v, float) else v) for k, v in errors.items()})
    print('timing:', [(t['round'], t['scans'], round(t['scanned_bytes'] / 1e9, 2), int(t['scan_seconds'])) for t in summary['timing']])
    for name, block in comparisons.items():
        for other, results in block.items():
            print(f'{name} verified-past vs {other}:', [f'{r["mean"] * 100:+.1f} [{r["low"] * 100:+.1f},{r["high"] * 100:+.1f}] {r["wins"]}/{r["ties"]}/{r["losses"]}' for r in results.values() if r])
    print('previously sealed cases only:')
    for metric, block in fresh_view.items():
        print(f'  {metric:<18}', {k: [None if x is None else round(x, 3) for x in v] for k, v in block.items()})
    print('scan noise:', {k: (round(v, 4) if isinstance(v, float) else v) for k, v in scan_noise.items()})
    print('repair made a case worse:', len(worse))
    for item in sorted(worse, key=lambda w: w['after'] - w['before'])[:8]:
        print(f'   {item["case"]:<26}{item["cap"]:>5.0%} {item["metric"]:<18}{item["before"]:.3f} -> {item["after"]:.3f}')


if __name__ == '__main__':
    main()
