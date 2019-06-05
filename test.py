#!/usr/bin/env python
import os
import sys
from glob import glob
from idstools import rule
import subprocess
import tempfile
import json


def test_rule_with_pcap(base_path):
    errors = []
    # Run suricata instance against the rule files pcap
    # suricata -S example.rules -k none -r test.pcap -vvv -l ./logs
    rule_dirs = os.listdir(base_path)
    for rule_dir in rule_dirs:
        temp_dir = tempfile.mkdtemp()
        rule_category, rule_name = rule_dir.split('_')
        rule_dir = os.path.join(base_path, rule_dir)
        rule_file = '%s.rules' % rule_name
        # Run suricata on the rule, log to the temp dir
        r = subprocess.call(
            'suricata -S {rule_dir}/{rule_file} -k none -r {rule_dir}/test.pcap -l {temp_dir}'.format(
                rule_dir=rule_dir,
                rule_file=rule_file,
                temp_dir=temp_dir,
            ),
            shell=True,
        )
        if r != 0:
            errors.append('Suricata process exited non zero')
        eve_logs = open(os.path.join(temp_dir, 'eve.json')).readlines()
        eve_logs = [json.loads(x) for x in eve_logs]
        alert_logs = [x for x in eve_logs if x.get('event_type') == 'alert']
        if not alert_logs:
            errors.append('No events triggered for %s' % rule_dir)
    return errors


def test_signature_content(base_path):
    errors = []
    # Parse signature using idstools
    rule_files = glob(os.path.join(base_path, '*/*.rules'))
    rules = {}
    rule_ids = {}
    # Parse the rules:
    for rule_file in rule_files:
        try:
            parsed_rulefile = rule.parse_file(rule_file)
            if not parsed_rulefile:
                errors.append('Rule file %s failed to parse/is blank' % rule_file)
                continue
            rules[rule_file] = parsed_rulefile
        except:
            errors.append('Parsing error on %s' % rule_file)
    for rname, ruleset in rules.items():
        for r in ruleset:
            # check if msg name contains MONA
            if not r.get('msg', '').startswith('MONA - '):
                errors.append('on %s msg doesn\'t start with MONA - ' % rname)
            if 'sid' not in r:
                errors.append('No SID defined on %s' % rname)
                r['sid'] = 0
            if not r['sid'] >= 8000000 and r['sid'] < 9000000:
                errors.append('Invalid signature id on %s' % rname)
            if r['sid'] in rule_ids:
                errors.append('Duplicate SID: %s on %s and %s' % (r['sid'], rule_ids[r['sid']], rname))
            else:
                rule_ids[r['sid']] = rname
    return errors


def test_paths(base_path):
    errors = []
    print('Testing %s' % base_path)
    # get a list of all the rules
    rule_dirs = os.listdir(base_path)
    for rule_dir in rule_dirs:
        rule_dir_abspath = os.path.join(base_path, rule_dir)
        if not os.path.isdir(rule_dir_abspath):
            errors.append('%s is a file, should be a directory' % rule_dir)
        if '_' not in rule_dir:
            errors.append('%s does not have category_rulename format' % rule_dir)
            # Since this isn't recoverable, we need to move on to the next rule directory
            continue
        rule_category, rule_name = rule_dir.split('_')
        rule_dir_files = os.listdir(rule_dir_abspath)
        rule_file = '%s.rules' % rule_name
        if rule_file not in rule_dir_files:
            errors.append('Missing %s' % os.path.join(rule_dir_abspath, rule_file))
        if 'test.pcap' not in rule_dir_files:
            errors.append('Missing %s/test.pcap' % rule_dir_abspath)
        if 'README.md' not in rule_dir_files:
            errors.append('Missing %s/README.md' % rule_dir_abspath)
    return errors


def main():
    errors = []
    if len(sys.argv) != 2:
        print('Invalid args, requires path to rules')
        sys.exit(1)
    base_path = os.path.abspath(os.path.expandvars(sys.argv[1]))
    errors.extend(test_paths(base_path))
    errors.extend(test_signature_content(base_path))
    errors.extend(test_rule_with_pcap(base_path))
    if errors:
        print('\n'.join(errors))
        sys.exit(2)
    print('Done!')
    sys.exit(0)


if __name__ == '__main__':
    main()