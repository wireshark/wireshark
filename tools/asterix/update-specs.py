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
from copy import copy
from itertools import chain, repeat
from functools import reduce
import os
import sys
import re

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
        self.inside_extended = None
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
    """Get Natural/Real/Rational number as an object."""
    class Integer(object):
        def __init__(self, val):
            self.val = val
        def __str__(self):
            return '{}'.format(self.val)
        def __float__(self):
            return float(self.val)

    class Ratio(object):
        def __init__(self, a, b):
            self.a = a
            self.b = b
        def __str__(self):
            return '{}/{}'.format(self.a, self.b)
        def __float__(self):
            return float(self.a) / float(self.b)

    class Real(object):
        def __init__(self, val):
            self.val = val
        def __str__(self):
            return '{0:f}'.format(self.val).rstrip('0')
        def __float__(self):
            return float(self.val)

    t = value['type']
    val = value['value']

    if t == 'Integer':
        return Integer(int(val))
    if t == 'Ratio':
        x, y = val['numerator'], val['denominator']
        return Ratio(x, y)
    if t == 'Real':
        return Real(float(val))
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
    k = content.get('scaling')
    if k is None:
        return None
    k = get_number(k)

    fract = content['fractionalBits']

    if fract > 0:
        scale = format(float(k) / (pow(2, fract)), '.29f')
        scale = scale.rstrip('0')
    else:
        scale = format(float(k))
    return scale

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

def get_content(rule):
    t = rule['type']
    # Most cases are 'ContextFree', use as specified.
    if t == 'ContextFree':
        return rule['content']
    # Handle 'Dependent' contents as 'Raw'.
    elif t == 'Dependent':
        return {'type': "Raw"}
    else:
        raise Exception('unexpected type: {}'.format(t))

def get_bit_size(item):
    """Return bit size of a (spare) item."""
    if item['spare']:
        return item['length']
    else:
        return item['variation']['size']

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
        level1['variation'] = {
            'type': 'Group',
            'items': [level2],
        }
    else:
        level2['variation'] = variation['variation']
        level1 = {
            'type': "Group",
            'items': [level2],
        }
    return level1

def is_generated(item):
    return item.get('is_generated') is not None

def ungroup(item):
    """Convert group of items of known size to element"""
    n = sum([get_bit_size(i) for i in item['variation']['items']])
    result = copy(item)
    result['variation'] = {
        'rule': {
            'content': {'type': 'Raw'},
            'type': 'ContextFree',
        },
        'size': n,
        'type': 'Element',
    }
    return result

def part1(ctx, get_ref, catalogue):
    """Generate components in order
    - static gint hf_...
    - FiledPart
    - FieldPart[]
    - AsterixField
    """

    tell = lambda s: ctx.tell('insert1', s)
    tell_pr = lambda s: ctx.tell('insert2', s)

    ctx.reset_offset()
    ctx.inside_extended = None

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
                tell('static gint hf_{} = -1;'.format(ref))
                n = variation['size']
                content = get_content(variation['rule'])
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

                if ctx.inside_extended is not None:
                    n, rest = ctx.inside_extended
                    if ctx.offset.get + 1 > n:
                        raise Exception("unexpected offset")
                    # FX bit
                    if ctx.offset.get + 1 == n:
                        ctx.offset += 1
                        m = next(rest)
                        ctx.inside_extended = (m, rest)

            elif t == 'Group':
                ctx.reset_offset()

                description = get_description(item)
                tell_pr('        {} &hf_{}, {} "{}", "asterix.{}", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL {} {},'.format('{', ref, '{', description, ref, '}', '}'))

                tell('static gint hf_{} = -1;'.format(ref))
                for i in variation['items']:
                    handle_item(path, i)

                # FieldPart[]
                tell('static const FieldPart *I{}_PARTS[] = {}'.format(ref,'{'))
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
                n1 = variation['first']
                n2 = variation['extents']
                ctx.reset_offset()
                ctx.inside_extended = (n1, chain(repeat(n1,1), repeat(n2)))

                description = get_description(item)
                tell_pr('        {} &hf_{}, {} "{}", "asterix.{}", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL {} {},'.format('{', ref, '{', description, ref, '}', '}'))
                tell('static gint hf_{} = -1;'.format(ref))

                items = []
                for i in variation['items']:
                    if i.get('variation') is not None:
                        if i['variation']['type'] == 'Group':
                            i = ungroup(i)
                    items.append(i)

                for i in items:
                    handle_item(path, i)

                tell('static const FieldPart *I{}_PARTS[] = {}'.format(ref,'{'))
                chunks = chain(repeat(n1,1), repeat(n2))
                # iterate over items, reinsert FX bits
                while True:
                    bit_size = next(chunks)
                    assert (bit_size % 8) == 0, "bit alignment error"
                    byte_size = bit_size // 8
                    bits_from = bit_size
                    while True:
                        i = items[0]
                        items = items[1:]
                        n = get_bit_size(i)
                        tell('    {},'.format(part_of(i)))
                        bits_from -= n
                        if bits_from <= 1:
                            break
                    tell('    &IXXX_FX,')
                    if not items:
                        break
                tell('    NULL')
                tell('};')

                # AsterixField
                n1 = variation['first'] // 8
                n2 = variation['extents'] // 8
                parts = 'I{}_PARTS'.format(ref)
                comp = '{ NULL }'
                tell('static const AsterixField I{} = {} FX, {}, 0, {}, &hf_{}, {}, {} {};'.format
                    (ref, '{', n2, n1 - 1, ref, parts, comp, '}'))

                ctx.inside_extended = None

            elif t == 'Repetitive':
                ctx.reset_offset()
                ctx.inside_repetitive = True

                # Group is required below this item.
                if variation['variation']['type'] == 'Element':
                    subvar = generate_group(item, variation)
                else:
                    subvar = variation['variation']
                handle_variation(path, subvar)

                # AsterixField
                bit_size = sum([get_bit_size(i) for i in subvar['items']])
                byte_size = bit_size // 8
                rep = variation['rep'] // 8
                parts = 'I{}_PARTS'.format(ref)
                comp = '{ NULL }'
                tell('static const AsterixField I{} = {} REPETITIVE, {}, {}, 0, &hf_{}, {}, {} {};'.format
                    (ref, '{', byte_size, rep, ref, parts, comp, '}'))
                ctx.inside_repetitive = False

            elif t == 'Explicit':
                ctx.reset_offset()
                tell('static gint hf_{} = -1;'.format(ref))
                description = get_description(item)
                tell_pr('        {} &hf_{}, {} "{}", "asterix.{}", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL {} {},'.format('{', ref, '{', description, ref, '}', '}'))
                tell('static const AsterixField I{} = {} EXP, 0, 0, 1, &hf_{}, NULL, {} NULL {} {};'.format(ref, '{', ref, '{', '}', '}'))

            elif t == 'Compound':
                ctx.reset_offset()
                tell('static gint hf_{} = -1;'.format(ref))
                description = get_description(item)
                tell_pr('        {} &hf_{}, {} "{}", "asterix.{}", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL {} {},'.format('{', ref, '{', description, ref, '}', '}'))
                comp = '{'
                for i in variation['items']:
                    if i is None:
                        comp += ' &IX_SPARE,'
                        continue
                    # Group is required below this item.
                    if i['variation']['type'] == 'Element':
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
        if path == [] and item['variation']['type'] == 'Element':
            variation = generate_group(item)['variation']
        else:
            variation = item['variation']
        handle_variation(path + [item['name']], variation)

    for i in catalogue:
        handle_item([], i)
    tell('')

def part2(ctx, ref, uap):
    """Generate UAPs"""

    tell = lambda s: ctx.tell('insert1', s)
    tell('DIAG_OFF_PEDANTIC')

    ut = uap['type']
    if ut == 'uap':
        variations = [{'name': 'uap', 'items': uap['items']}]
    elif ut == 'uaps':
        variations = uap['variations']
    else:
        raise Exception('unexpected uap type {}'.format(ut))

    for var in variations:
        tell('static const AsterixField *I{}_{}[] = {}'.format(ref, var['name'], '{'))
        for i in var['items']:
            if i is None:
                tell('    &IX_SPARE,')
            else:
                tell('    &I{}_{},'.format(ref, i))
        tell('    NULL')
        tell('};')

    tell('static const AsterixField **I{}[] = {}'.format(ref, '{'))
    for var in variations:
        tell('    I{}_{},'.format(ref, var['name']))
    tell('    NULL')
    tell('};')
    tell('DIAG_ON_PEDANTIC')
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
        tell('DIAG_OFF_PEDANTIC')
        tell('static const AsterixField ***I{:03d}all[] = {} {} {};'.format(cat, '{', editions_str, '}'))
        tell('DIAG_ON_PEDANTIC')
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

    tell('static const AsterixField ****categories[] = {')
    for i in range(0, 256):
        val = 'I{:03d}all'.format(i) if i in cats else 'NULL'
        tell('    {}, /* {:03d} */'.format(val, i))
    tell('    NULL')
    tell('};')

    for cat in sorted(cats):
        tell_pr('    prefs_register_enum_preference (asterix_prefs_module, "i{:03d}_version", "I{:03d} version", "Select the CAT{:03d} version", &global_categories_version[{}], I{:03d}_versions, FALSE);'.format(cat, cat, cat, cat, cat))

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
    jsons = sorted(jsons, key = lambda x: (x['number'], x['edition']['major'], x['edition']['minor']))
    jsons = [spec for spec in jsons if spec['type'] == 'Basic']

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

            ctx.tell('insert1', '/* Category {:03d}, edition {}.{} */'.format(spec['number'], spec['edition']['major'], spec['edition']['minor']))

            # handle part1
            get_ref = lambda path: reference(spec['number'], spec['edition'], path)
            part1(ctx, get_ref, spec['catalogue'])
            if is_latest:
                ctx.tell('insert1', '/* Category {:03d}, edition {}.{} (latest) */'.format(spec['number'], spec['edition']['major'], spec['edition']['minor']))
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

