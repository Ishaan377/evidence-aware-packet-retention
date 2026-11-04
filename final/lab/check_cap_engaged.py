"""How much of the packet budget would payload-free flows take with the scan cap removed?

The cap can only act where this share exceeds it, so this decides which captures
give the cap a fair trial. It uses packet headers and first bytes only, runs no
detection and prints no alerts, so it can screen sealed captures.

    python final/lab/check_cap_engaged.py <run folder> <case> [<case> ...]
"""
from concurrent.futures import ProcessPoolExecutor
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import forensic_test as harness  # noqa: E402
from ebr.allocate import allocate  # noqa: E402
from ebr.profile import build_profile  # noqa: E402
from ebr.value import score_flows  # noqa: E402

CAPS = (0.01, 0.02, 0.05, 0.10)


def measure(case):
    catalogue = json.loads((ROOT / 'forensic_cases.json').read_text(encoding='utf8'))
    config = json.loads((ROOT / 'ebr_config.json').read_text(encoding='utf8'))
    uncapped = dict(config, silent_budget_share=None)
    profile = build_profile(harness.case_files(case, catalogue), config)
    values = score_flows(profile.flows, config)['value']
    result = {}
    for cap in CAPS:
        budget = int(profile.input_bytes * cap * (1 - config['ledger_max_share']))
        levels, used = allocate(profile.flows, values, budget, uncapped)
        silent = sum(sum(f.cost) for f in profile.flows if not f.data_seen and levels[f.id] >= 0)
        result[str(cap)] = round(silent / used, 3) if used else 0.0
    total_silent = sum(1 for f in profile.flows if not f.data_seen)
    return case, dict(flows=len(profile.flows), packets=profile.packets, input_bytes=profile.input_bytes, silent_flows=total_silent,
                      silent_share_of_budget_without_cap=result)


def main(run, cases):
    with ProcessPoolExecutor(2) as pool:
        results = dict(pool.map(measure, cases))
    folder = ROOT / 'results' / 'forensic' / run
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'cap_engaged.json').write_text(json.dumps(results, indent=1), encoding='utf8')
    for case, entry in results.items():
        share = entry['silent_share_of_budget_without_cap']['0.05']
        print(f'{case:<26} flows {entry["flows"]:>10,}  silent {entry["silent_flows"]:>10,}  share at 5% {share:>5.1%}  {"SCAN-HEAVY" if share >= 0.3 else "not scan-heavy"}', flush=True)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2:])
