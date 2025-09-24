#!/usr/bin/env python3
#
# By Zoran Bošnjak <zoran.bosnjak@sloveniacontrol.si>
#
# Use asterix specifications in JSON format,
# to generate C/C++ structures, suitable for wireshark.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import sys
import os
import argparse
import urllib.request
import json
import generate_dissector

# Path to default upstream repository
upstream_repo = 'https://zoranbosnjak.github.io/asterix-specs'

class BitOffset(object):
    """Int with 'modulo 8' on addition."""

    def __init__(self, val):
        self.val = val % 8

    def __int__(self):
        return self.val

    def __add__(self, other):
        return self.__class__(self.val + int(other))

def download_url(path):
    with urllib.request.urlopen(upstream_repo + path) as url:
        return url.read()

def read_file(path):
    """Read file content, return string."""
    with open(path) as f:
        return f.read()

def load_files(paths):
    """Load (json) files from either URL or from local disk."""

    # load from default url
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

# Global bit offset for item iterration
bit_offset = BitOffset(0)

class Database:
    def __init__(self):
        self.db = {}

    def insert(self, key, obj):
        (last, sub) = self.db.get(key, (0, {}))
        ix = sub.get(obj)
        if ix is not None:
            return ix
        ix = last + 1
        sub[obj] = ix
        self.db[key] = (ix, sub)
        return ix

    def __getattr__(self, name):
        return self.db[name][1]

# Global asterix objects database
db = Database()

class Obj:
    def __init__(self, val):
        self.val = val

    def __str__(self):
        return str(self.val)

    def __int__(self):
        return int(self.val)

    def __bool__(self):
        return bool(self.val)

    def __iter__(self):
        for i in self.val:
            yield(Obj(i))

    def __getattr__(self, name):
        return Obj(self.val[name])

def number_to_float(obj):
    cont = obj.contents
    match str(obj.tag):
        case 'NumDiv':
            a = number_to_float(cont.numerator)
            b = number_to_float(cont.denominator)
            return a / b
        case 'NumInt':
            return float(int(cont))
        case 'NumPow':
            return float(pow(int(cont.base), int(cont.exponent)))
        case _:
            raise Exception(obj.tag)

def save_rule(what, f, obj):
    tag = str(obj.tag)
    def insert(val):
        return db.insert('rule'+what, (tag, val))
    cont = obj.contents
    match tag:
        case 'ContextFree':
            ix = f(cont)
            return insert(ix)
        case 'Dependent':
            _path = cont.path
            dv = cont.default
            _cases = cont.cases
            ix = f(dv)
            return insert(ix)
        case _:
            raise Exception(tag)

def save_content(obj):
    tag = str(obj.tag)
    def insert(val):
        return db.insert('content', (tag, val))
    cont = obj.contents
    match tag:
        case 'ContentRaw':
            return insert(())
        case 'ContentTable':
            return insert(tuple([tuple(i) for i in cont.val]))
        case 'ContentString':
            str_type = getattr(cont, 'tag')
            return insert(str(str_type))
        case 'ContentInteger':
            sig = str(cont.signedness.tag)
            return insert(sig)
        case 'ContentQuantity':
            sig = str(cont.signedness.tag)
            lsb = number_to_float(cont.lsb)
            unit = str(cont.unit)
            return insert((sig, lsb, unit))
        case 'ContentBds':
            return insert(())
        case _:
            raise Exception(tag)

def save_variation(obj):
    global bit_offset
    tag = str(obj.tag)
    def insert(val):
        return db.insert('variation', (tag, val))
    cont = obj.contents
    match tag:
        case 'Element':
            o = int(bit_offset)
            n = int(cont.bitSize)
            bit_offset += n
            rule = save_rule('Content', save_content, cont.rule)
            return insert((o, n, rule))
        case 'Group':
            lst = [save_item(i) for i in cont]
            return insert(tuple(lst))
        case 'Extended':
            bit_offset = BitOffset(0)
            lst = []
            for i in cont:
                if i:
                    ix = save_item(i)
                    lst.append(ix)
                else:
                    lst.append(None)
            return insert(tuple(lst))
        case 'Repetitive':
            bit_offset = BitOffset(0)
            match str(cont.type.tag):
                case 'RepetitiveRegular':
                    t = int(cont.type.contents.byteSize)
                case 'RepetitiveFx':
                    t = None
                case _:
                    raise Exception(cont.type)
            var = save_variation(cont.variation)
            return insert((t, var))
        case 'Explicit':
            bit_offset = BitOffset(0)
            if cont:
                return insert(str(cont.tag))
            else:
                return insert(None)
        case 'Compound':
            bit_offset = BitOffset(0)
            lst = []
            for i in cont:
                if i:
                    ix = save_nonspare(i)
                    lst.append(ix)
                else:
                    lst.append(None)
            return insert(tuple(lst))
        case _:
            raise Exception(tag)

def save_item(obj):
    global bit_offset
    tag = str(obj.tag)
    def insert(val):
        return db.insert('item', (tag, val))
    cont = obj.contents
    match tag:
        case 'Item':
            ix = save_nonspare(cont)
            return insert(ix)
        case 'Spare':
            o = int(bit_offset)
            n = int(cont)
            bit_offset += n
            return insert(n)
        case _:
            raise Exception(tag)

def save_nonspare(obj):
    name = str(obj.name)
    title = str(obj.title)
    rule = save_rule('Variation', save_variation, obj.rule)
    return db.insert('nonspare', (name, title, rule))

def save_uap(obj):
    tag = str(obj.tag)
    cont = obj.contents
    def insert(val):
        return db.insert('uap', (tag, val))

    def single(uap):
        lst = []
        for i in uap:
            match str(i.tag):
                case 'UapItem':
                    lst.append(str(i.contents))
                case 'UapItemSpare':
                    lst.append(None)
                case 'UapItemRFS':
                    lst.append(None)
                case _:
                    raise Exception(i.tag)
        return tuple(lst)

    match tag:
        case 'Uap':
            lst = single(cont)
            return insert(tuple(lst))
        case 'Uaps':
            lsts = []
            for name, r in cont.cases:
                lst = single(r)
                lsts.append((str(name), tuple(lst)))
            return insert(tuple(lsts))
        case _:
            raise Exception(tag)

def save_asterix(obj):
    global bit_offset
    bit_offset = BitOffset(0)
    tag = str(obj.tag)
    def insert(val):
        return db.insert('asterix', (tag, val))
    cont = obj.contents
    cat = int(cont.category)
    ed = cont.edition
    ed = (int(ed.major), int(ed.minor))
    match tag:
        case 'AsterixBasic':
            catalogue = tuple([save_nonspare(i) for i in cont.catalogue])
            uap = save_uap(cont.uap)
            return insert((cat, ed, catalogue, uap))
        case 'AsterixExpansion':
            n = int(cont.fspecByteSize)
            lst = []
            for i in cont.items:
                if i:
                    ix = save_nonspare(i)
                    lst.append(ix)
                else:
                    lst.append(None)
            return insert((cat, ed, n, tuple(lst)))
        case _:
            raise Exception(tag)

def compare_asterix(obj):
    obj = obj.contents
    ed = obj.edition
    return (int(obj.category), int(ed.major), int(ed.minor))

def main():
    parser = argparse.ArgumentParser(description='Generate asterix definitions.')
    parser.add_argument('paths', metavar='PATH', nargs='*',
        help='json spec file(s), or upstream repository if no input is given')
    parser.add_argument('--reference', action='store_true',
        help='print upstream reference and exit')
    parser.add_argument("--update", nargs='?', type=argparse.FileType('w'),
        default=sys.stdout, metavar='FILE',
        help="Update file instead of writing to stdout")
    args = parser.parse_args()

    gitrev = load_gitrev(args.paths)

    if args.reference:
        print(gitrev[0:10])
        sys.exit(0)

    # read and json-decode input files
    specs = [Obj(json.loads(i)) for i in load_files(args.paths)]
    specs = sorted(specs, key = compare_asterix)
    refs = [save_asterix(i) for i in specs]

    # print(db.db.keys())
    # [print(i) for i in db.content]
    # [print(i) for i in db.rule_content]
    # [print(i) for i in db.variation]
    # [print(i) for i in db.item]
    # [print(i) for i in db.nonspare]
    # [print(i) for i in db.uap]
    # [print(i) for i in db.asterix]

    result = generate_dissector.generate_file(gitrev, db)
    if args.update:
        args.update.write(result)
    else:
        print(result, end="")

if __name__ == '__main__':
    main()

