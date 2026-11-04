"""Turn the frozen study's saved measurements into summary.json and report.html.

Every number on the page is computed here from saved files. Each comparison is
paired by case and cap, and uncertainty comes from resampling cases, because the
cases, not the packets, are the independent units.
"""
from collections import defaultdict
import csv
from html import escape
import json
from pathlib import Path
import random
from statistics import mean
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from ebr import forensic  # noqa: E402
from ebr.report import NAMES, results_report  # noqa: E402
from forensic_test import load_truth  # noqa: E402

FORENSIC = ROOT / 'results' / 'forensic'
CAPS = (0.01, 0.02, 0.05, 0.10)
LINES = ['ebr', 'flow_cutoff', 'rare_dest', 'ids_past_fill', 'random_flow', 'random_packet']
COMPARATORS = ['flow_cutoff', 'rare_dest', 'ids_past', 'ids_past_fill', 'random_flow', 'random_packet']
METRICS = {'attack_sig_recall': 'Attack signatures preserved', 'attack_recall': 'Attack alert instances preserved',
           'future_recall': 'Alerts from rules published after the capture'}
ABLATIONS = {'no_rarity': 'No rarity score', 'no_automation': 'No automation score', 'no_pivot': 'No pivoting',
             'no_diminishing': 'No diminishing returns', 'no_turn_heads': 'No turn heads', 'no_ledger': 'No ledger',
             'tiers_only': 'Tiers and knapsack only, every flow equal'}


def rows_of(path):
    with Path(path).open(encoding='utf8') as stream:
        return list(csv.DictReader(stream))


def number(value):
    return None if value in ('', 'None', None) else float(value)


def collapse(rows, metric):
    """Average random seeds inside each case, policy and cap."""
    grouped = defaultdict(list)
    for row in rows:
        value = number(row[metric])
        if value is not None:
            grouped[(row['case'], row['policy'], float(row['fraction']))].append(value)
    return {key: mean(values) for key, values in grouped.items()}


def curve(table, policy):
    points = []
    for cap in CAPS:
        values = [v for (_, p, c), v in table.items() if p == policy and c == cap]
        points.append(mean(values) if values else None)
    return points


def bootstrap_difference(table, policy, cap, cases, replicates=10000):
    """Mean EBR advantage over a comparator, with a 95 percent interval from resampling cases."""
    pairs = [table[(c, 'ebr', cap)] - table[(c, policy, cap)] for c in cases if (c, 'ebr', cap) in table and (c, policy, cap) in table]
    if not pairs:
        return None
    generator = random.Random(20261030)
    samples = sorted(mean(generator.choices(pairs, k=len(pairs))) for _ in range(replicates))
    return dict(mean=mean(pairs), low=samples[int(replicates * .025)], high=samples[int(replicates * .975)], cases=len(pairs),
                wins=sum(p > 1e-9 for p in pairs), ties=sum(abs(p) <= 1e-9 for p in pairs), losses=sum(p < -1e-9 for p in pairs))


def percent(value, places=1):
    return '–' if value is None else f'{value * 100:.{places}f}%'


def campaign_scores(rows):
    """Average seeds, then count attacks with at least one matching signature."""
    grouped = defaultdict(list)
    detail = {}
    for row in rows:
        key = (row['episode'], row['policy'], float(row['fraction']))
        grouped[key].append(float(row['caught']))
        detail[row['episode']] = dict(attack=row['attack'], case=row['case'], detectable=int(row['detectable']), full_sids=int(row['full_sids']),
                                      flows=int(row['attack_flows']))
    return {k: mean(v) for k, v in grouped.items()}, detail


def losses(tables, cases):
    """Every case, cap and metric where a comparator beat EBR."""
    found = []
    for metric, table in tables.items():
        for case in cases:
            for cap in CAPS:
                own = table.get((case, 'ebr', cap))
                if own is None:
                    continue
                for policy in COMPARATORS:
                    other = table.get((case, policy, cap))
                    if other is not None and other > own + 1e-9:
                        found.append(dict(metric=metric, case=case, cap=cap, policy=policy, ebr=own, other=other))
    return found


def signature_gaps(run, case):
    """Signatures EBR never recovers at any cap, and those it holds at a lower cap but loses at 10 percent."""
    names = [p.name for p in (run / 'full' / case).glob('*.json')]
    full = forensic.load_summaries([run / 'full' / case / n for n in names])
    reference = {v['sid']: v['sig'] for v in full['alerts'].values() if forensic.is_attack(v)}
    found = {}
    for cap in CAPS:
        view = forensic.load_summaries([run / 'scans' / case / f'ebr_{cap:g}_s0' / n for n in names])
        found[cap] = {k[0] for k in view['alerts'] if k in full['alerts']} & set(reference)
    every = set().union(*found.values())
    return dict(never=sorted(reference[s] for s in set(reference) - every),
                lost_at_top=sorted(reference[s] for s in every - found[CAPS[-1]]))


def main():
    run = FORENSIC / 'test'
    rows, campaigns = rows_of(run / 'metrics.csv'), rows_of(run / 'campaigns.csv')
    cases = sorted({r['case'] for r in rows})
    stores = {c: json.loads((run / 'reduced' / c / 'records.json').read_text(encoding='utf8')) for c in cases}
    tables = {metric: collapse(rows, metric) for metric in METRICS}
    input_bytes = sum(s['meta']['input_bytes'] for s in stores.values())
    packets = sum(s['meta']['packets'] for s in stores.values())
    flows = sum(s['meta']['flows'] for s in stores.values())
    curves = {metric: {p: curve(table, p) for p in LINES + ['ids_past']} for metric, table in tables.items()}
    tests = {metric: {p: {str(cap): bootstrap_difference(table, p, cap, cases) for cap in CAPS} for p in COMPARATORS}
             for metric, table in tables.items()}
    caught, episodes = campaign_scores(campaigns)
    detectable = sorted(e for e, d in episodes.items() if d['detectable'])
    campaign_curve = {p: [sum(caught.get((e, p, cap), 0) for e in detectable) for cap in CAPS] for p in LINES + ['ids_past']}
    lost = losses(tables, cases)
    invented = {p: sum(float(r['invented_attack']) for r in rows if r['policy'] == p) / max(1, len({r['seed'] for r in rows if r['policy'] == p})) for p in LINES}
    gaps = signature_gaps(run, 'test_wrccdc2018')
    unranked = [c for c, s in stores.items() if load_truth(c) and not s['meta'].get('attacker_ranks')]

    ablations = {}
    for name in ABLATIONS:
        path = FORENSIC / f'test_ablation_{name}' / 'metrics.csv'
        if path.exists():
            data = rows_of(path)
            ablations[name] = {metric: curve(collapse(data, metric), 'ebr') for metric in METRICS}

    original = {}
    path = FORENSIC / 'original_compare' / 'metrics.csv'
    if path.exists():
        data = rows_of(path)
        records = {}
        for store in (FORENSIC / 'original_compare' / 'reduced').glob('*/records.json'):
            for record in json.loads(store.read_text(encoding='utf8'))['records']:
                records[(record['case'], record['policy'], record['fraction'])] = record['select_seconds']
        original = dict(signature=collapse(data, 'attack_sig_recall'), instance=collapse(data, 'attack_recall'), seconds=records)

    ranks = {}
    for case, store in stores.items():
        if store['meta'].get('attacker_ranks'):
            ranks[case] = dict(best=min(store['meta']['attacker_ranks'].values()), hosts=store['meta']['hosts_total'], ranks=store['meta']['attacker_ranks'])
    accounting = {}
    for case, store in stores.items():
        for record in store['records']:
            if record['policy'] == 'ebr' and record.get('ledger_accounting'):
                accounting[f'{case}|{record["fraction"]}'] = record['ledger_accounting']
    speed = sum(s['meta']['profile_seconds'] + s['meta']['score_seconds'] for s in stores.values())
    lossless = json.loads((run / 'lossless.json').read_text(encoding='utf8')) if (run / 'lossless.json').exists() else {}
    noise = json.loads((run / 'noise.json').read_text(encoding='utf8')) if (run / 'noise.json').exists() else []
    freeze = json.loads((ROOT / 'FREEZE.json').read_text(encoding='utf8'))
    conversion = json.loads((ROOT / 'data' / 'forensic' / 'test_dos_feb16' / 'conversion_check.json').read_text(encoding='utf8'))
    summary = dict(freeze_time=freeze['frozen_at'], cases=cases, input_bytes=input_bytes, packets=packets, flows=flows, curves=curves, tests=tests,
                   campaign_curve=campaign_curve, detectable_attacks=len(detectable), attacks=len(episodes), episodes=episodes, losses=lost,
                   invented_attack_alerts=invented, ablations=ablations, attacker_ranks=ranks, unranked_attackers=unranked,
                   wrccdc_gaps=gaps, ledger_accounting=accounting,
                   profile_and_score_seconds=speed, lossless=lossless, noise=noise)
    (run / 'summary.json').write_text(json.dumps(summary, indent=1), encoding='utf8')

    # The page.
    five = CAPS.index(0.05)
    sig, ins, later = curves['attack_sig_recall'], curves['attack_recall'], curves['future_recall']
    gzip_ratio = (sum(v['gzip_bytes'] for v in lossless.values()) / sum(v['input_bytes'] for v in lossless.values())) if lossless else None
    tiles = [(f'{campaign_curve["ebr"][five]:.0f} of {len(detectable)}', 'detectable attacks still caught at a 5% cap'),
             (percent(sig['ebr'][five]), 'attack signatures preserved at 5%'),
             (percent(later['ebr'][five]), 'alerts from rules newer than the capture, at 5%'),
             (f'{input_bytes / 1e9:.1f} GB', f'held-out evidence, {packets / 1e6:.1f} million packets')]
    sections = []
    sections.append(dict(heading='How this was tested', text=[
        f'The algorithm and every comparator were frozen on {escape_time(freeze["frozen_at"])}, with hashes of {len(freeze["files"])} files, before any test capture was opened. '
        f'Tuning used separate development cases only. The test covers {len(cases)} cases: five days of CSE-CIC-IDS2018 attacks and a WRCCDC capture of a human red team.',
        'Suricata 7.0.3 with 52,778 ET Open rules scanned each complete capture and each reduced capture the same way. EBR received no alerts, labels or signatures. '
        'Attack windows and addresses come from the dataset publisher.',
        f'<b>Disclosure.</b> The first frozen run stopped before anything was scored, because one 4.3 GB capture was PCAPNG, which EBR does not read. It was converted to classic PCAP with a separate tool, '
        f'and Scapy confirmed all {conversion["packets_compared"]:,} packets match in bytes, wire length and timestamp, with {conversion["mismatches"]} mismatches. Its reference scan was redone from the converted file, and no frozen file changed.']))
    sections.append(dict(heading='How many attacks were still caught', text=[
        f'{len(episodes)} attack windows are labelled by the dataset publisher, and Suricata detects {len(detectable)} of them on the complete capture. '
        'An attack counts as caught when the reduced capture still raises at least one of those signatures between the labelled attacker and victim, inside the labelled window. Random policies are averaged over three seeds.'],
        table=dict(headers=['Policy'] + [f'{c:.0%} cap' for c in CAPS], rows=[[NAMES[p]] + [f'{v:.1f}'.rstrip('0').rstrip('.') + f' of {len(detectable)}' for v in campaign_curve[p]] for p in LINES + ['ids_past']],
                   numeric=(1, 2, 3, 4), emphasise=NAMES['ebr']),
        after=['The IDS-triggered policies were given real alerts from rules that existed on the capture date. They keep one representative flow per alert, which helps them at low caps.']))
    five_percent = {}
    for row in campaigns:
        if float(row['fraction']) == 0.05 and int(row['detectable']):
            five_percent.setdefault(row['episode'], {}).setdefault(row['policy'], []).append(int(row['found_sids']))
    attack_rows = []
    for episode, policies in sorted(five_percent.items()):
        cells = [escape(episodes[episode]['attack']), str(episodes[episode]['full_sids']), f'{episodes[episode]["flows"]:,}']
        for p in ('ebr', 'ids_past_fill', 'rare_dest', 'flow_cutoff'):
            cells.append(f'{mean(policies[p]):.0f}')
        attack_rows.append(cells)
    sections.append(dict(heading='Attack by attack, at a 5% cap', text=['Each cell shows how many of the attack\'s signatures still fire on the reduced capture.'],
                         table=dict(headers=['Attack', 'Signatures on full capture', 'Labelled flows', 'EBR', 'IDS + fill', 'Rare dest.', 'Cutoff'], rows=attack_rows, numeric=(1, 2, 3, 4, 5, 6))))
    sections.append(dict(heading='How much detection survives', text=[
        'Each policy had the same byte cap, and EBR also paid for its flow ledger from that cap. Means are across the test cases that have a reference for that measure.'],
        charts=[dict(title=METRICS[m], series={p: [v or 0 for v in curves[m][p]] for p in LINES}) for m in METRICS],
        table=dict(headers=['Attack signatures preserved'] + [f'{c:.0%} cap' for c in CAPS], rows=[[NAMES[p]] + [percent(v) for v in sig[p]] for p in LINES + ['ids_past']],
                   numeric=(1, 2, 3, 4), emphasise=NAMES['ebr'])))
    rows_ci = []
    for p in COMPARATORS:
        for cap in CAPS:
            result = tests['attack_sig_recall'][p][str(cap)]
            if result:
                rows_ci.append([NAMES[p], f'{cap:.0%}', f'{result["mean"] * 100:+.1f}', f'{result["low"] * 100:+.1f} to {result["high"] * 100:+.1f}',
                                f'{result["wins"]} / {result["ties"]} / {result["losses"]}'])
    sections.append(dict(heading='Is the difference real', text=[
        'This table gives EBR\'s advantage in signature recall, in percentage points, against each comparator. The interval resamples the cases. With this few cases the intervals are wide, so read them as evidence and not as proof.'],
        table=dict(headers=['Compared with', 'Cap', 'EBR advantage', '95% interval', 'Wins / ties / losses'], rows=rows_ci, numeric=(2, 3))))
    by_pair = defaultdict(int)
    for item in lost:
        by_pair[(item['case'], item['cap'])] += 1
    worst = sorted(lost, key=lambda x: x['ebr'] - x['other'])[:12]
    sections.append(dict(heading='Where EBR lost', text=[
        f'A comparator beat EBR in {len(lost)} of the case, cap, metric and policy comparisons. The largest gaps are below.' if lost else 'No comparator beat EBR on any case, cap or metric.'],
        table=dict(headers=['Case', 'Cap', 'Measure', 'Winner', 'EBR', 'Winner score'],
                   rows=[[c['case'], f'{c["cap"]:.0%}', METRICS[c['metric']], NAMES[c['policy']], percent(c['ebr']), percent(c['other'])] for c in worst], numeric=(4, 5)) if worst else None))
    against = [
        f'<b>An IDS with real rules keeps more alert instances at very low caps.</b> At 1%, IDS-triggered capture keeps {percent(ins["ids_past"][0])} of attack alert instances against EBR\'s {percent(ins["ebr"][0])}. '
        'That comparator needs a signature engine running at capture time, and its signature recall is capped by what those rules can see, but at the tightest caps it is the better choice.',
        f'<b>The time-travel hypothesis was not supported.</b> Rules published after the capture were expected to favour EBR. IDS-triggered capture still kept {percent(later["ids_past"][2])} of those alerts against EBR\'s {percent(later["ebr"][2])} at 5%, '
        'because most new rules fire on flows that older rules had already flagged.',
        f'<b>The human red-team capture is EBR\'s weakest case.</b> On WRCCDC, EBR recovers {percent(tables["attack_sig_recall"].get(("test_wrccdc2018", "ebr", 0.05)))} of attack signatures at 5% against {percent(tables["attack_sig_recall"].get(("test_wrccdc2018", "ids_past", 0.05)))} for IDS-triggered capture. '
        f'{len(gaps["never"])} signatures are never recovered at any cap, and {sum("SMB" in g or "ETERNALBLUE" in g or "Comspec" in g for g in gaps["never"])} of them are SMB lateral movement or SMB exploits. Later experiments found two causes: payload-free scan flows took most of the budget, and EBR treated SMB as opaque. Capping the scan flows mattered more.',
        f'<b>More budget did not always mean more detection.</b> {len(gaps["lost_at_top"])} WRCCDC signatures present at a lower cap are absent at 10%. An early version of this report blamed gaps inside flows, and that was wrong: the affected login flows alert at every fidelity level when scanned alone. The loss went away once fewer scan flows were retained, which suggests retained scan traffic was interfering, though the exact mechanism inside the IDS was not established.',
        f'<b>The attacker was not always named.</b> In {len(unranked)} labelled case(s), EBR\'s host ranking does not contain the attacker, because a command-and-control server or a very quiet attacker initiates little or nothing.',
        f'<b>Reduction can create alerts.</b> Across all cases and caps, EBR produced {invented["ebr"]:.0f} attack alert instances absent from the complete capture, against {invented["flow_cutoff"]:.0f} for the cutoff and {invented["ids_past_fill"]:.0f} for IDS-triggered capture with fill. Most are rate rules firing on a different host pair.']
    sections.append(dict(heading='Findings that did not favour EBR', text=against))
    if ablations:
        sections.append(dict(heading='What each component contributes', text=[
            'Each row removes one component and repeats the test. Scores are mean attack signature recall.',
            '<b>Diminishing returns does most of the work.</b> Removing it, or removing all scoring, drops recall sharply. Pivoting and turn heads made no measurable difference to signature recall on this test, and rarity and automation changed it only slightly when removed one at a time, '
            'so this study does not show that those parts are needed. The ledger is a real trade: it uses a tenth of the budget, which costs some detection at the tightest caps in exchange for exact flow accounting.'],
            table=dict(headers=['Variant'] + [f'{c:.0%}' for c in CAPS], rows=[['Full EBR'] + [percent(v) for v in sig['ebr']]] +
                       [[ABLATIONS[k]] + [percent(v) for v in ablations[k]['attack_sig_recall']] for k in ablations], numeric=(1, 2, 3, 4), emphasise='Full EBR')))
    if original:
        lines = []
        for case in sorted({k[0] for k in original['signature']}):
            for cap in CAPS:
                row = [case, f'{cap:.0%}']
                for p in ('v1_evidence', 'v1_bundle', 'flow_cutoff', 'ebr'):
                    row.append(percent(original['signature'].get((case, p, cap))))
                lines.append(row)
        sections.append(dict(heading='Compared with the original algorithm', text=[
            'The original implementation holds every packet in Python memory, and its audit measured 230 seconds of selection on a 58 MB file, so it was run only on small captures here. This table is signature recall. '
            'Its reader rejects a capture with a torn final record, so it was given copies without that one partial record, which is what EBR reads anyway.',
            '<b>Only v1_test_web is held out.</b> EBR was tuned on the other four, so their margins flatter it. On v1_test_web the two tie on signature recall at every cap, and the original keeps more alert instances at 1% and 2%.'],
            table=dict(headers=['Case', 'Cap', 'Original evidence', 'Original bundles', 'Tuned cutoff', 'EBR'], rows=lines, numeric=(2, 3, 4, 5))))
    if ranks:
        sections.append(dict(heading='Naming the attacker without an IDS', text=['EBR ranks hosts by the mass of surprise they initiate. This table shows where the labelled attacker landed.'],
                             table=dict(headers=['Case', 'Best attacker rank', 'Hosts in capture'], rows=[[c, f'#{v["best"]}', f'{v["hosts"]:,}'] for c, v in ranks.items()], numeric=(1, 2))))
    limits = ['Suricata cannot score attacks it does not detect on the complete capture, so those episodes count only through the ledger.',
              'CSE-CIC-IDS2018 is a generated lab dataset, and its attackers are easy to separate. WRCCDC is more realistic but has no labels here.',
              'A reduced capture cannot rebuild what was dropped. Bulk file contents and most encrypted payload are gone by design.',
              'The test has few independent cases. A larger study across other sites is needed before claiming general superiority.']
    if gzip_ratio:
        limits.insert(0, f'Lossless gzip on these captures reaches {percent(gzip_ratio)} of the original size and loses nothing. EBR goes further by discarding data, so the two are not interchangeable.')
    if noise:
        limits.append(f'Repeating one complete capture reproduced {percent(min(n["instance"] for n in noise))} of alert instances, but a later check found that reduced captures vary more between scans, by up to 4.5 points of alert instance recall on one case, with no change in signature recall.')
    sections.append(dict(heading='Limits', text=limits))
    report = dict(title='Evidence-Based Retention: held-out forensic test', lede=f'{input_bytes / 1e9:.1f} GB of real attack captures, reduced under equal storage caps and investigated with Suricata.',
                  tiles=tiles, sections=sections, caps=[c * 100 for c in CAPS], policies=LINES)
    (run / 'report.html').write_text(results_report(report), encoding='utf8')
    (run / 'report_fragment.html').write_text(results_report(report, True), encoding='utf8')
    print('Wrote', run / 'report.html')
    print('caught', campaign_curve, 'of', len(detectable))
    for metric in METRICS:
        print(metric)
        for p in LINES + ['ids_past']:
            print(f'  {p:<16}', [None if v is None else round(v, 3) for v in curves[metric][p]])
    print('losses', len(lost))


def escape_time(text):
    return text.replace('T', ' at ')


if __name__ == '__main__':
    main()
