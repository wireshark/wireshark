#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# By Zoran Bošnjak <zoran.bosnjak@sloveniacontrol.si>
#
# Use asterix specifications in JSON format,
# to generate C/C++ structures, suitable for wireshark.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse

import urllib.request
import json
from copy import copy, deepcopy
from itertools import chain, repeat, takewhile
from functools import reduce
import os
import sys
import re

import convertspec as convert

# Path to default upstream repository
upstream_repo = 'https://zoranbosnjak.github.io/asterix-specs'
dissector_file = 'epan/dissectors/packet-asterix.c'

class Offset(object):
    """Keep track of number of added bits.
    It's like integer, except when offsets are added together,
    a 'modulo 8' is applied, such that offset is always between [0,7].
    """

    def __init__(self):
        self.current = 0

    def __add__(self, other):
        self.current = (self.current + other) % 8
        return self

    @property
    def get(self):
        return self.current

class Context(object):
    """Support class to be used as a context manager.
    The 'tell' method is used to output (print) some data.
    All output is first collected to a buffer, then rendered
    using a template file.
    """
    def __init__(self):
        self.buffer = {}
        self.offset = Offset()
        self.inside_repetitive = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        pass

    def tell(self, channel, s):
        """Append string 's' to an output channel."""
        lines = self.buffer.get(channel, [])
        lines.append(s)
        self.buffer[channel] = lines

    def reset_offset(self):
        self.offset = Offset()

def get_number(value):
    t = value['type']
    if t == 'Integer':
        return float(value['value'])
    if t == 'Div':
        a = get_number(value['numerator'])
        b = get_number(value['denominator'])
        return a/b
    if t == 'Pow':
        return float(pow(value['base'], value['exponent']))
    raise Exception('unexpected value type {}'.format(t))

def replace_string(s, mapping):
    """Helper function to replace each entry from the mapping."""
    for (key,val) in mapping.items():
        s = s.replace(key, val)
    return s

def safe_string(s):
    """String replacement table."""
    return replace_string(s, {
        # from C reference manual
        chr(92): r"\\", # Backslash character.
        '?':    r"\?",  # Question mark character.
        "'":    r"\'",  # Single quotation mark.
        '"':    r'\"',  # Double quotation mark.
        "\a":   "",     # Audible alert.
        "\b":   "",     # Backspace character.
        "\e":   "",     # <ESC> character. (This is a GNU extension.)
        "\f":   "",     # Form feed.
        "\n":   "",     # Newline character.
        "\r":   "",     # Carriage return.
        "\t":   " ",    # Horizontal tab.
        "\v":   "",     # Vertical tab.
    })

def get_scaling(content):
    """Get scaling factor from the content."""
    lsb = content.get('lsb')
    if lsb is None:
        return None
    return '{}'.format(get_number(lsb))

def get_fieldpart(content):
    """Get FIELD_PART* from the content."""
    t = content['type']
    if t == 'Raw': return 'FIELD_PART_HEX'
    elif t == 'Table': return 'FIELD_PART_UINT'
    elif t == 'String':
        var = content['variation']
        if var == 'StringAscii': return 'FIELD_PART_ASCII'
        elif var == 'StringICAO': return 'FIELD_PART_CALLSIGN'
        elif var == 'StringOctal': return 'FIELD_PART_SQUAWK'
        else:
            raise Exception('unexpected string variation: {}'.format(var))
    elif t == 'Integer':
        if content['signed']:
            return 'FIELD_PART_INT'
        else:
            return 'FIELD_PART_UINT'
    elif t == 'Quantity':
        if content['signed']:
            return 'FIELD_PART_FLOAT'
        else:
            return 'FIELD_PART_UFLOAT'
    elif t == 'Bds':
        return 'FIELD_PART_HEX'
    else:
        raise Exception('unexpected content type: {}'.format(t))

def download_url(path):
    """Download url and return content as a string."""
    with urllib.request.urlopen(upstream_repo + path) as url:
        return url.read()

def read_file(path):
    """Read file content, return string."""
    with open(path) as f:
        return f.read()

def load_jsons(paths):
    """Load json files from either URL or from local disk."""

    # load from url
    if paths == []:
        manifest = download_url('/manifest.json').decode()
        listing = []
        for spec in json.loads(manifest):
            cat = spec['category']
            for edition in spec['cats']:
                listing.append('/specs/cat{}/cats/cat{}/definition.json'.format(cat, edition))
            for edition in spec['refs']:
                listing.append('/specs/cat{}/refs/ref{}/definition.json'.format(cat, edition))
        return [download_url(i).decode() for i in listing]

    # load from disk
    else:
        listing = []
        for path in paths:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for i in files:
                        (a,b) = os.path.splitext(i)
                        if (a,b) != ('definition', '.json'):
                            continue
                        listing.append(os.path.join(root, i))
            elif os.path.isfile(path):
                listing.append(path)
            else:
                raise Exception('unexpected path type: {}'.path)
        return [read_file(f) for f in listing]

def load_gitrev(paths):
    """Read git revision reference."""

    # load from url
    if paths == []:
        gitrev = download_url('/gitrev.txt').decode().strip()
        return [upstream_repo, 'git revision: {}'.format(gitrev)]

    # load from disk
    else:
        return ['(local disk)']

def get_ft(ref, n, content, offset):
    """Get FT... from the content."""
    a = offset.get

    # bruto bit size (next multiple of 8)
    (m, b) = divmod(a+n, 8)
    m = m if b == 0 else m + 1
    m *= 8

    mask = '0x00'
    if a != 0 or b != 0:
        bits = chain(repeat(0, a), repeat(1, n), repeat(0, m-n-a))
        mask = 0
        for (a,b) in zip(bits, reversed(range(m))):
            mask += a*pow(2,b)
        mask = hex(mask)
        # prefix mask with zeros '0x000...', to adjust mask size
        assert mask[0:2] == '0x'
        mask = mask[2:]
        required_mask_size = (m//8)*2
        add_some = required_mask_size - len(mask)
        mask = '0x' + '0'*add_some + mask

    t = content['type']

    if t == 'Raw':
        if n > 64:          # very long items
            assert (n % 8) == 0, "very long items require byte alignment"
            return 'FT_NONE, BASE_NONE, NULL, 0x00'

        if (n % 8):         # not byte aligned
            base = 'DEC'
        else:               # byte aligned
            if n >= 32:             # long items
                base = 'HEX'
            else:                   # short items
                base = 'HEX_DEC'
        return 'FT_UINT{}, BASE_{}, NULL, {}'.format(m, base, mask)
    elif t == 'Table':
        return 'FT_UINT{}, BASE_DEC, VALS (valstr_{}), {}'.format(m, ref, mask)
    elif t == 'String':
        var = content['variation']
        if var == 'StringAscii':
            return 'FT_STRING, BASE_NONE, NULL, {}'.format(mask)
        elif var == 'StringICAO':
            return 'FT_STRING, BASE_NONE, NULL, {}'.format(mask)
        elif var == 'StringOctal':
            return 'FT_UINT{}, BASE_OCT, NULL, {}'.format(m, mask)
        else:
            raise Exception('unexpected string variation: {}'.format(var))
    elif t == 'Integer':
        signed = content['signed']
        if signed:
            return 'FT_INT{}, BASE_DEC, NULL, {}'.format(m, mask)
        else:
            return 'FT_UINT{}, BASE_DEC, NULL, {}'.format(m, mask)
    elif t == 'Quantity':
        return 'FT_DOUBLE, BASE_NONE, NULL, 0x00'
    elif t == 'Bds':
        return 'FT_UINT{}, BASE_DEC, NULL, {}'.format(m, mask)
    else:
        raise Exception('unexpected content type: {}'.format(t))

def reference(cat, edition, path):
    """Create reference string."""
    name = '_'.join(path)
    if edition is None:
        return('{:03d}_{}'.format(cat, name))
    return('{:03d}_V{}_{}_{}'.format(cat, edition['major'], edition['minor'], name))

def get_rule(rule):
    t = rule['type']
    if t == 'ContextFree':
        return rule['value']
    elif t == 'Dependent':
        return rule['default']
    else:
        raise Exception('unexpected type: {}'.format(t))

def get_bit_size(item):
    """Return bit size of a (spare) item."""
    if item['spare']:
        return item['length']
    else:
        return get_rule(item['rule'])['size']

def get_description(item, content=None):
    """Return item description."""
    name = item['name'] if not is_generated(item) else None
    title = item.get('title')
    if content is not None and content.get('unit'):
        unit = '[{}]'.format(safe_string(content['unit']))
    else:
        unit = None

    parts = filter(lambda x: bool(x), [name, title, unit])
    if not parts:
        return ''
    return reduce(lambda a,b: a + ', ' + b, parts)

def generate_group(item, variation=None):
    """Generate group-item from element-item."""
    level2 = copy(item)
    level2['name'] = 'VALUE'
    level2['is_generated'] = True
    if variation is None:
        level1 = copy(item)
        level1['rule'] = {
            'type': 'ContextFree',
            'value': {
                'type': 'Group',
                'items': [level2],
            },
        }
    else:
        level2['rule'] = {
            'type': 'ContextFree',
            'value': variation,
        }
        level1 = {
            'type': "Group",
            'items': [level2],
        }
    return level1

def is_generated(item):
    return item.get('is_generated') is not None

def ungroup(item):
    """Convert group of items of known size to element"""
    n = sum([get_bit_size(i) for i in get_rule(item['rule'])['items']])
    result = copy(item)
    result['rule'] = {
        'type': 'ContextFree',
        'value': {
            'type': 'Element',
            'size': n,
            'rule': {
                'type': 'ContextFree',
                'value': {'type': 'Raw'},
            },
        },
    }
    return result

def part1(ctx, get_ref, catalogue):
    """Generate components in order
    - static int hf_...
    - FiledPart
    - FieldPart[]
    - AsterixField
    """

    tell = lambda s: ctx.tell('insert1', s)
    tell_pr = lambda s: ctx.tell('insert2', s)

    ctx.reset_offset()

    def handle_item(path, item):
        """Handle 'spare' or regular 'item'.
        This function is used recursively, depending on the item structure.
        """

        def handle_variation(path, variation):
            """Handle 'Element, Group...' variations.
            This function is used recursively, depending on the item structure."""

            t = variation['type']

            ref = get_ref(path)

            def part_of(item):
                if item['spare']:
                    return '&IXXX_{}bit_spare'.format(item['length'])
                return '&I{}_{}'.format(ref, item['name'])

            if t == 'Element':
                tell('static int hf_{};'.format(ref))
                n = variation['size']
                content = get_rule(variation['rule'])
                scaling = get_scaling(content)
                scaling = scaling if scaling is not None else 1.0
                fp = get_fieldpart(content)

                if content['type'] == 'Table':
                    tell('static const value_string valstr_{}[] = {}'.format(ref, '{'))
                    for (a,b) in content['values']:
                        tell('    {} {}, "{}" {},'.format('{', a, safe_string(b), '}'))
                    tell('    {} 0, NULL {}'.format('{', '}'))
                    tell('};')

                tell('static const FieldPart I{} = {} {}, {}, {}, &hf_{}, NULL {};'.format(ref, '{', n, scaling, fp, ref, '}'))
                description = get_description(item, content)

                ft = get_ft(ref, n, content, ctx.offset)
                tell_pr('        {} &hf_{}, {} "{}", "asterix.{}", {}, NULL, HFILL {} {},'.format('{', ref, '{', description, ref, ft, '}', '}'))

                ctx.offset += n

            elif t == 'Group':
                ctx.reset_offset()

                description = get_description(item)
                tell_pr('        {} &hf_{}, {} "{}", "asterix.{}", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL {} {},'.format('{', ref, '{', description, ref, '}', '}'))

                tell('static int hf_{};'.format(ref))
                for i in variation['items']:
                    handle_item(path, i)

                # FieldPart[]
                tell('static const FieldPart * const I{}_PARTS[] = {}'.format(ref,'{'))
                for i in variation['items']:
                    tell('    {},'.format(part_of(i)))
                tell('    NULL')
                tell('};')

                # AsterixField
                bit_size = sum([get_bit_size(i) for i in variation['items']])
                byte_size = bit_size // 8
                parts = 'I{}_PARTS'.format(ref)
                comp = '{ NULL }'
                if not ctx.inside_repetitive:
                    tell('static const AsterixField I{} = {} FIXED, {}, 0, 0, &hf_{}, {}, {} {};'.format
                        (ref, '{', byte_size, ref, parts, comp, '}'))

            elif t == 'Extended':
                ctx.reset_offset()

                description = get_description(item)
                tell_pr('        {} &hf_{}, {} "{}", "asterix.{}", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL {} {},'.format('{', ref, '{', description, ref, '}', '}'))
                tell('static int hf_{};'.format(ref))

                items = []
                for i in variation['items']:
                    if i is None:
                        items.append(i)
                        continue
                    if i.get('rule') is not None:
                        if get_rule(i['rule'])['type'] == 'Group':
                            i = ungroup(i)
                    items.append(i)

                for i in items:
                    if i is None:
                        ctx.offset += 1
                    else:
                        handle_item(path, i)

                tell('static const FieldPart * const I{}_PARTS[] = {}'.format(ref,'{'))
                for i in items:
                    if i is None:
                        tell('    &IXXX_FX,')
                    else:
                        tell('    {},'.format(part_of(i)))

                tell('    NULL')
                tell('};')

                # AsterixField
                first_part = list(takewhile(lambda x: x is not None, items))
                n = (sum([get_bit_size(i) for i in first_part]) + 1) // 8
                parts = 'I{}_PARTS'.format(ref)
                comp = '{ NULL }'
                tell('static const AsterixField I{} = {} FX, {}, 0, {}, &hf_{}, {}, {} {};'.format
                    (ref, '{', n, 0, ref, parts, comp, '}'))

            elif t == 'Repetitive':
                ctx.reset_offset()
                ctx.inside_repetitive = True

                # Group is required below this item.
                if variation['variation']['type'] == 'Element':
                    subvar = generate_group(item, variation['variation'])
                else:
                    subvar = variation['variation']
                handle_variation(path, subvar)

                # AsterixField
                bit_size = sum([get_bit_size(i) for i in subvar['items']])
                byte_size = bit_size // 8
                rep = variation['rep']['size'] // 8
                parts = 'I{}_PARTS'.format(ref)
                comp = '{ NULL }'
                tell('static const AsterixField I{} = {} REPETITIVE, {}, {}, 0, &hf_{}, {}, {} {};'.format
                    (ref, '{', byte_size, rep, ref, parts, comp, '}'))
                ctx.inside_repetitive = False

            elif t == 'Explicit':
                ctx.reset_offset()
                tell('static int hf_{};'.format(ref))
                description = get_description(item)
                tell_pr('        {} &hf_{}, {} "{}", "asterix.{}", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL {} {},'.format('{', ref, '{', description, ref, '}', '}'))
                tell('static const AsterixField I{} = {} EXP, 0, 0, 1, &hf_{}, NULL, {} NULL {} {};'.format(ref, '{', ref, '{', '}', '}'))

            elif t == 'Compound':
                ctx.reset_offset()
                tell('static int hf_{};'.format(ref))
                description = get_description(item)
                tell_pr('        {} &hf_{}, {} "{}", "asterix.{}", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL {} {},'.format('{', ref, '{', description, ref, '}', '}'))
                comp = '{'
                for i in variation['items']:
                    if i is None:
                        comp += ' &IX_SPARE,'
                        continue
                    # Group is required below this item.
                    if get_rule(i['rule'])['type'] == 'Element':
                        subitem = generate_group(i)
                    else:
                        subitem = i
                    comp += ' &I{}_{},'.format(ref, subitem['name'])
                    handle_item(path, subitem)
                comp += ' NULL }'

                # AsterixField
                tell('static const AsterixField I{} = {} COMPOUND, 0, 0, 0, &hf_{}, NULL, {} {};'.format
                    (ref, '{', ref, comp, '}'))

            else:
                raise Exception('unexpected variation type: {}'.format(t))

        if item['spare']:
            ctx.offset += item['length']
            return

        # Group is required on the first level.
        if path == [] and get_rule(item['rule'])['type'] == 'Element':
            variation = get_rule(generate_group(item)['rule'])
        else:
            variation = get_rule(item['rule'])
        handle_variation(path + [item['name']], variation)

    for item in catalogue:
        # adjust 'repetitive fx' item
        if get_rule(item['rule'])['type'] == 'Repetitive' and get_rule(item['rule'])['rep']['type'] == 'Fx':
            var = get_rule(item['rule'])['variation'].copy()
            if var['type'] != 'Element':
                raise Exception("Expecting 'Element'")
            item = item.copy()
            item['rule'] = {
                'type': 'ContextFree',
                'value': {
                    'type': 'Extended',
                    'items': [{
                        'definition': None,
                        'description': None,
                        'name': 'Subitem',
                        'remark': None,
                        'spare': False,
                        'title': 'Subitem',
                        'rule': {
                            'type': 'ContextFree',
                            'value': var,
                        },
                    }, None]
                }
            }
        handle_item([], item)
    tell('')

def part2(ctx, ref, uap):
    """Generate UAPs"""

    tell = lambda s: ctx.tell('insert1', s)

    ut = uap['type']
    if ut == 'uap':
        variations = [{'name': 'uap', 'items': uap['items']}]
    elif ut == 'uaps':
        variations = uap['variations']
    else:
        raise Exception('unexpected uap type {}'.format(ut))

    for var in variations:
        tell('static const AsterixField * const I{}_{}[] = {}'.format(ref, var['name'], '{'))
        for i in var['items']:
            if i is None:
                tell('    &IX_SPARE,')
            else:
                tell('    &I{}_{},'.format(ref, i))
        tell('    NULL')
        tell('};')

    tell('static const AsterixField * const * const I{}[] = {}'.format(ref, '{'))
    for var in variations:
        tell('    I{}_{},'.format(ref, var['name']))
    tell('    NULL')
    tell('};')
    tell('')

def part3(ctx, specs):
    """Generate
        - static const AsterixField ***...
        - static const enum_val_t ..._versions[]...
    """
    tell = lambda s: ctx.tell('insert1', s)
    def fmt_edition(cat, edition):
        return 'I{:03d}_V{}_{}'.format(cat, edition['major'], edition['minor'])

    cats = set([spec['number'] for spec in specs])
    for cat in sorted(cats):
        lst = [spec for spec in specs if spec['number'] == cat]
        editions = sorted([val['edition'] for val in lst], key = lambda x: (x['major'], x['minor']), reverse=True)
        editions_fmt = [fmt_edition(cat, edition) for edition in editions]
        editions_str = ', '.join(['I{:03d}'.format(cat)] + editions_fmt)
        tell('static const AsterixField * const * const * const I{:03d}all[] = {} {} {};'.format(cat, '{', editions_str, '}'))
        tell('')

        tell('static const enum_val_t I{:03d}_versions[] = {}'.format(cat, '{'))
        edition = editions[0]
        a = edition['major']
        b = edition['minor']
        tell('    {} "I{:03d}", "Version {}.{} (latest)", 0 {},'.format('{', cat, a, b, '}'))
        for ix, edition in enumerate(editions, start=1):
            a = edition['major']
            b = edition['minor']
            tell('    {} "I{:03d}_v{}_{}", "Version {}.{}", {} {},'.format('{', cat, a, b, a, b, ix, '}'))
        tell('    { NULL, NULL, 0 }')
        tell('};')
        tell('')

def part4(ctx, cats):
    """Generate
        - static const AsterixField ****categories[]...
        - prefs_register_enum_preference ...
    """
    tell = lambda s: ctx.tell('insert1', s)
    tell_pr = lambda s: ctx.tell('insert3', s)

    tell('static const AsterixField * const * const * const * const categories[] = {')
    for i in range(0, 256):
        val = 'I{:03d}all'.format(i) if i in cats else 'NULL'
        tell('    {}, /* {:03d} */'.format(val, i))
    tell('    NULL')
    tell('};')

    for cat in sorted(cats):
        tell_pr('    prefs_register_enum_preference (asterix_prefs_module, "i{:03d}_version", "I{:03d} version", "Select the CAT{:03d} version", &global_categories_version[{}], I{:03d}_versions, false);'.format(cat, cat, cat, cat, cat))

class Output(object):
    """Output context manager. Write either to stdout or to a dissector
    file directly, depending on 'update' argument"""
    def __init__(self, update):
        self.update = update
        self.f = None

    def __enter__(self):
        if self.update:
            self.f = open(dissector_file, 'w')
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if self.f is not None:
            self.f.close()

    def dump(self, line):
        if self.f is None:
            print(line)
        else:
            self.f.write(line+'\n')

def remove_rfs(spec):
    """Remove RFS item. It's present in specs, but not used."""
    catalogue = []  # create new catalogue without RFS
    rfs_items = []
    for i in spec['catalogue']:
        if get_rule(i['rule'])['type'] == 'Rfs':
            rfs_items.append(i['name'])
        else:
            catalogue.append(i)
    if not rfs_items:
        return spec
    spec2 = copy(spec)
    spec2['catalogue'] = catalogue
    # remove RFS from UAP(s)
    uap = deepcopy(spec['uap'])
    ut = uap['type']
    if ut == 'uap':
        items = [None if i in rfs_items else i for i in uap['items']]
        if items[-1] is None: items = items[:-1]
        uap['items'] = items
    elif ut == 'uaps':
        variations = []
        for var in uap['variations']:
            items = [None if i in rfs_items else i for i in var['items']]
            if items[-1] is None: items = items[:-1]
            var['items'] = items
            variations.append(var)
        uap['variations'] = variations
    else:
        raise Exception('unexpected uap type {}'.format(ut))
    spec2['uap'] = uap
    return spec2

def is_valid(spec):
    """Check spec"""
    def check_item(item):
        if item['spare']:
            return True
        return check_variation(get_rule(item['rule']))
    def check_variation(variation):
        t = variation['type']
        if t == 'Element':
            return True
        elif t == 'Group':
            return all([check_item(i) for i in variation['items']])
        elif t == 'Extended':
            trailing_fx = variation['items'][-1] == None
            if not trailing_fx:
                return False
            return all([check_item(i) for i in variation['items'] if i is not None])
        elif t == 'Repetitive':
            return check_variation(variation['variation'])
        elif t == 'Explicit':
            return True
        elif t == 'Compound':
            items = [i for i in variation['items'] if i is not None]
            return all([check_item(i) for i in items])
        else:
            raise Exception('unexpected variation type {}'.format(t))
    return all([check_item(i) for i in spec['catalogue']])

def main():
    parser = argparse.ArgumentParser(description='Process asterix specs files.')
    parser.add_argument('paths', metavar='PATH', nargs='*',
        help='json spec file(s), use upstream repository in no input is given')
    parser.add_argument('--reference', action='store_true',
        help='print upstream reference and exit')
    parser.add_argument("--update", action="store_true",
        help="Update %s as needed instead of writing to stdout" % dissector_file)
    args = parser.parse_args()

    if args.reference:
        gitrev_short = download_url('/gitrev.txt').decode().strip()[0:10]
        print(gitrev_short)
        sys.exit(0)

    # read and json-decode input files
    jsons = load_jsons(args.paths)
    jsons = [json.loads(i) for i in jsons]
    jsons = [convert.handle_asterix(i) for i in jsons]
    jsons = sorted(jsons, key = lambda x: (x['number'], x['edition']['major'], x['edition']['minor']))
    jsons = [spec for spec in jsons if spec['type'] == 'Basic']
    jsons = [remove_rfs(spec) for spec in jsons]
    jsons = [spec for spec in jsons if is_valid(spec)]

    cats = list(set([x['number'] for x in jsons]))
    latest_editions = {cat: sorted(
        filter(lambda x: x['number'] == cat, jsons),
        key = lambda x: (x['edition']['major'], x['edition']['minor']), reverse=True)[0]['edition']
        for cat in cats}

    # regular expression for template rendering
    ins = re.compile(r'---\{([A-Za-z0-9_]*)\}---')

    gitrev = load_gitrev(args.paths)
    with Context() as ctx:
        for i in gitrev:
            ctx.tell('gitrev', i)

        # generate parts into the context buffer
        for spec in jsons:
            is_latest = spec['edition'] == latest_editions[spec['number']]

            ctx.tell('insert1', '/* Category {:03d}, edition {}.{} */'.format(
                spec['number'], spec['edition']['major'], spec['edition']['minor']))

            # handle part1
            get_ref = lambda path: reference(spec['number'], spec['edition'], path)
            part1(ctx, get_ref, spec['catalogue'])
            if is_latest:
                ctx.tell('insert1', '/* Category {:03d}, edition {}.{} (latest) */'.format(
                    spec['number'], spec['edition']['major'], spec['edition']['minor']))
                get_ref = lambda path: reference(spec['number'], None, path)
                part1(ctx, get_ref, spec['catalogue'])

            # handle part2
            cat = spec['number']
            edition = spec['edition']
            ref = '{:03d}_V{}_{}'.format(cat, edition['major'], edition['minor'])
            part2(ctx, ref, spec['uap'])
            if is_latest:
                ref = '{:03d}'.format(cat)
                part2(ctx, ref, spec['uap'])

        part3(ctx, jsons)
        part4(ctx, set([spec['number'] for spec in jsons]))

        # use context buffer to render template
        script_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(script_path, 'packet-asterix-template.c')) as f:
            template_lines = f.readlines()

        # All input is collected and rendered.
        # It's safe to update the disector.

        # copy each line of the template to required output,
        # if the 'insertion' is found in the template,
        # replace it with the buffer content
        with Output(args.update) as out:
            for line in template_lines:
                line = line.rstrip()

                insertion = ins.match(line)
                if insertion is None:
                    out.dump(line)
                else:
                    segment = insertion.group(1)
                    [out.dump(i) for i in ctx.buffer[segment]]

if __name__ == '__main__':
    main()
