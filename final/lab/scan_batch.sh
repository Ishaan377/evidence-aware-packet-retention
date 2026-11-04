#!/bin/bash
# Scan many captures with one loaded ruleset. Input: tab-separated "<pcap>\t<summary.json>" lines.
# Suricata's unix-socket mode loads the rules once, which matters with tens of thousands of rules.
set -uo pipefail
export TZ=UTC  # alert minutes must line up with the UTC attack schedule
batch="$1"
here="$(dirname "$(readlink -f "$0")")"
run=$(mktemp -d /var/tmp/ebrscan.XXXXXX)
sock="$run/sock"
suricata -c /opt/ebr/suricata.yaml -k none --unix-socket="$sock" -l "$run" --runmode autofp > "$run/daemon.log" 2>&1 &
daemon=$!
trap 'kill $daemon 2>/dev/null; rm -rf "$run"' EXIT
for _ in $(seq 1 600); do
  [ -S "$sock" ] && suricatasc -c version "$sock" > /dev/null 2>&1 && break
  sleep 0.5
done
n=0
while IFS=$'\t' read -r pcap summary; do
  [ -n "$pcap" ] || continue
  n=$((n + 1))
  out="$run/o$n"
  mkdir -p "$out" "$(dirname "$summary")"
  # suricatasc splits on spaces, so hand it a space-free link to the capture.
  ln -s "$pcap" "$run/in$n.pcap"
  suricatasc -c "pcap-file $run/in$n.pcap $out" "$sock" > /dev/null
  while :; do
    pending=$(suricatasc -c pcap-file-number "$sock" | python3 -c 'import json,sys; print(json.load(sys.stdin)["message"])')
    current=$(suricatasc -c pcap-current "$sock" | python3 -c 'import json,sys; print(json.load(sys.stdin)["message"])')
    [ "$pending" = "0" ] && [ "$current" = "None" ] && break
    sleep 0.2
  done
  python3 "$here/summarize_eve.py" "$out/eve.json" "$summary"
  rm -rf "$out"
  echo "scanned $pcap"
done < "$batch"
