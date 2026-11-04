#!/bin/bash
# Freeze one ET Open ruleset and a Suricata configuration inside the ebr-lab distro.
set -euo pipefail
mkdir -p /opt/ebr/rules
cd /opt/ebr/rules
if [ ! -f emerging.rules.tar.gz ]; then
  curl -sS -L --fail -o emerging.rules.tar.gz https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz
fi
tar -xzf emerging.rules.tar.gz
# Evaluation rules only: decoder and stream rules would fire on any gap and measure nothing forensic.
cat rules/*.rules | grep -E '^alert ' | grep -v 'msg:"SURICATA ' > ebr.rules
rm -f rules/*.rules
python3 - <<'PY'
import yaml
source = open('/etc/suricata/suricata.yaml').read()
config = yaml.safe_load(source)
config['vars']['address-groups']['HOME_NET'] = 'any'
config['vars']['address-groups']['EXTERNAL_NET'] = 'any'
config['outputs'] = [{'eve-log': {'enabled': True, 'filetype': 'regular', 'filename': 'eve.json', 'types': [
    {'alert': {'metadata': True, 'tagged-packets': False}}, {'http': {'extended': False}}, {'ssh': {}}, {'ftp': {}},
    {'tls': {'extended': False}}, {'smtp': {}}, {'dns': {'version': 2, 'requests': True, 'responses': False}}]}}]
for output in config['logging']['outputs']:
    for settings in output.values():
        settings['enabled'] = False
config['default-rule-path'] = '/opt/ebr/rules'
config['rule-files'] = ['ebr.rules']
config['classification-file'] = '/etc/suricata/classification.config'
config['reference-config-file'] = '/etc/suricata/reference.config'
with open('/opt/ebr/suricata.yaml', 'w') as stream:
    stream.write('%YAML 1.1\n---\n')
    yaml.safe_dump(config, stream)
PY
wc -l ebr.rules
sha256sum ebr.rules emerging.rules.tar.gz
suricata --build-info | grep -iE 'hyperscan|^This is|AF_PACKET support' || true
