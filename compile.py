#!/usr/bin/env python
import sys
import os
from glob import glob


def main():
    rules = {}
    if len(sys.argv) != 3:
        print('Requires 2 args, src and dest')
        sys.exit(1)
    src_path = os.path.abspath(os.path.expandvars(sys.argv[1]))
    dest_path = os.path.abspath(os.path.expandvars(sys.argv[2]))
    print('Compiling rules from %s to %s' % (src_path, dest_path))
    for rule_filename in glob(os.path.join(src_path, '*/*.rules')):
        print('Processing %s' % rule_filename)
        category = rule_filename.split(os.path.sep)[-2].split('_')[0]
        # Remove any blank lines and commented lines.
        rule_content = [x for x in open(rule_filename).readlines() if x and not x.startswith('#')]
        # Add the category to the rule dict if needed
        if category not in rules:
            rules[category] = []
        # Append the rules to the category
        rules[category].extend(rule_content)
    for category, rule_content in rules.items():
        # Iterate through the categories and write the rule content
        category_file = os.path.join(dest_path, category + '.rules')
        print('Writing %s' % category_file)
        open(category_file, 'w').writelines(rule_content)
    print('Done!')
    sys.exit(0)


if __name__ == '__main__':
    main()
