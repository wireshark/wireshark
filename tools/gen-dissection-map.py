#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Generate test/dissection_map.json.

The map lists, for each coverage test class in test/suite_dissection.py,
the dissector source files its captures exercise. pytest uses it with
--changed-since=<ref> to skip the coverage classes that the changed files
cannot affect (see test/dissection_select.py).

Only classes whose captures all have "_coverage" in their file name are
mapped. Every other class always runs.

For each mapped class the protocols are:
  - the leaf protocols of its captures: the last entry of each frame's
    frame.protocols after dropping generic trailers such as "data" and
    "_ws.malformed". Link, network and transport protocols (eth, ip,
    tcp, ...) are never leaves, and neither is a protocol that carries
    another protocol in the same capture;
  - the protocol the capture is named after ("foo" for foo_coverage.pcap);
  - the protocols the class names itself: Decode As targets, preference
    prefixes and the fields it filters on or checks.
The protocols are then mapped to the files that register them.

Rerun this script after adding or changing coverage captures or coverage
test classes, with a tshark built from the same tree:

    tools/gen-dissection-map.py --program-path build/run

A class that is missing from the map always runs, so a stale map costs
test time but does not skip new tests.
'''

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'test'))
import dissection_select  # noqa: E402

SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPTURE_DIR = os.path.join(SRC_DIR, 'test', 'captures')
MAP_FILE = dissection_select.MAP_FILE
COVERAGE_TAG = dissection_select.COVERAGE_TAG
DISSECTOR_DIRS = ('epan/dissectors', 'plugins/epan')

# Protocols that are never a leaf: dropped from the end of frame.protocols.
GENERIC_TRAILERS = {'data', 'media', 'text', 'malformed', 'expert', 'short'}
# Link, network and transport layers: never a leaf, and their fields do not
# count (a test that picks frames by udp.dstport does not test UDP). A
# capture named after one of them still maps to its file.
LOWER_LAYERS = {'eth', 'ethertype', 'vlan', 'llc', 'snap', 'sll', 'null',
                'loop', 'raw', 'ppp', 'pppoes', 'mpls', 'gre', 'ip', 'ipv6',
                'ipv6.hopopts', 'ipv6.dstopts', 'ipv6.routing', 'ipv6.fraghdr',
                'tcp', 'udp', 'udplite', 'sctp', 'dccp', 'icmp', 'icmpv6'}
# Protocols named by almost every test; they say nothing about the class.
# Synthetic captures often use port 9 as the other port, which Discard claims.
IGNORED_PROTOCOLS = {'frame', 'data', 'media', 'text', 'malformed', 'expert',
                     'short', 'pkt_comment', 'fake-field-wrapper', 'discard'}

IDENT_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]*')
DECODE_AS_RE = re.compile(r'^[\w.-]+(?:==|:)[^,\s]+,([\w.-]+)$')
PREF_RE = re.compile(r'^([\w.-]+)\.[\w.-]+:')
FILTER_RE = re.compile(r'^[\s!()]*[\w.-]+(?:[\s()]*(?:&&|\|\||\band\b|\bor\b)[\s!()]*[\w.-]+)*[\s()]*$')
REGISTER_RE = re.compile(
    r'\bproto_register_protocol(?:_in_name_only)?\s*\(([^;]*?)\)\s*;', re.S)
DEFINE_RE = re.compile(r'^\s*#\s*define\s+(\w+)\s+"([^"]*)"', re.M)
STRVAR_RE = re.compile(r'\b(\w+)\s*(?:\[\s*\])?\s*=\s*"([^"]*)"\s*;')


def coverage_classes():
    '''Yield (class name, captures, strings) for the mapped classes.'''
    for cls in dissection_select.parse_classes():
        if cls.coverage:
            yield cls.name, cls.captures, cls.strings


def tshark_protocols(tshark):
    '''Return the set of protocol filter names known to tshark.'''
    out = subprocess.check_output([tshark, '-G', 'protocols'],
                                  encoding='utf-8', errors='replace')
    return {line.split('\t')[2] for line in out.splitlines()
            if line.count('\t') >= 2}


def class_options(strings):
    '''Decode As and preference arguments named in a class.'''
    opts = []
    for i, s in enumerate(strings):
        prev = strings[i - 1] if i > 0 else None
        if DECODE_AS_RE.match(s):
            opts += ['-d', s]
        elif prev == '-o' and PREF_RE.match(s):
            opts += ['-o', s]
        elif prev in ('--enable-heuristic', '--enable-protocol'):
            opts += [prev, s]
    return opts


def leaf_protocols(tshark, capture, opts):
    '''Return the leaf protocol of every frame of a capture.'''
    path = os.path.join(CAPTURE_DIR, capture)
    env = dict(os.environ, TZ='UTC', HOME='/wireshark-tests-unused')
    env.pop('XDG_CONFIG_HOME', None)
    # Retry without the preferences (one may be unknown), then plain.
    no_prefs = []
    for i in range(0, len(opts), 2):
        if opts[i] != '-o':
            no_prefs += opts[i:i + 2]
    for args in (opts, no_prefs, []):
        proc = subprocess.run([tshark, '-n', '-r', path, *args, '-Tfields',
                               '-e', 'frame.protocols'],
                              capture_output=True, encoding='utf-8',
                              errors='replace', env=env, timeout=600)
        if proc.returncode == 0 or proc.stdout:
            break
    leaves = set()
    carriers = set()
    for line in proc.stdout.splitlines():
        protos = [p for p in line.strip().split(':') if p]
        while protos and (protos[-1] in GENERIC_TRAILERS or protos[-1].startswith('_ws')):
            protos.pop()
        if protos:
            if protos[-1] not in LOWER_LAYERS:
                leaves.add(protos[-1])
            carriers.update(protos[:-1])
    # A protocol that carries another one in this capture is a lower layer,
    # even in the frames where it is last (a bare TCP ACK, for example).
    return leaves - carriers, carriers


def longest_protocol(token, known):
    parts = token.split('.')
    for n in range(len(parts), 0, -1):
        name = '.'.join(parts[:n])
        if name in known:
            return name
    return None


def named_protocols(strings, known):
    '''Protocols a class names: (Decode As targets, protocols named in
    preferences, filters and fields).'''
    targets = set()
    found = set()
    for s in strings:
        m = DECODE_AS_RE.match(s)
        if m:
            targets.add(m.group(1))
            continue
        m = PREF_RE.match(s)
        if m and m.group(1) in known:
            found.add(m.group(1))
            continue
        if s in known:
            found.add(s)
            continue
        bare_ok = bool(FILTER_RE.match(s))
        # Values in quotes are not field names ("ipv6.example.com").
        for tok in IDENT_RE.findall(re.sub(r'"[^"]*"', '', s)):
            tok = tok.rstrip('.-')
            if '.' in tok:
                p = longest_protocol(tok, known)
                if p:
                    found.add(p)
            elif bare_ok and tok in known:
                found.add(tok)
    return targets, found


def resolve_arg(arg, defines):
    arg = arg.strip()
    m = re.fullmatch(r'"([^"]*)"', arg)
    if m:
        return m.group(1)
    return defines.get(arg)


def split_args(text):
    args, depth, cur = [], 0, ''
    for ch in text:
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        if ch == ',' and depth == 0:
            args.append(cur)
            cur = ''
        else:
            cur += ch
    args.append(cur)
    return args


def protocol_files():
    '''Map protocol filter names to the source files that register them.'''
    files = {}
    for top in DISSECTOR_DIRS:
        for dirpath, dirnames, filenames in os.walk(os.path.join(SRC_DIR, top)):
            rel = os.path.relpath(dirpath, SRC_DIR).replace(os.sep, '/')
            # Templates; the generated files are scanned instead.
            dirnames[:] = [d for d in dirnames
                           if f'{rel}/{d}' not in ('epan/dissectors/asn1', 'epan/dissectors/pidl')]
            for fn in filenames:
                if not fn.endswith(('.c', '.cpp')):
                    continue
                path = os.path.join(dirpath, fn)
                with open(path, encoding='utf-8', errors='replace') as f:
                    src = f.read()
                if 'proto_register_protocol' not in src:
                    continue
                defines = dict(DEFINE_RE.findall(src))
                defines.update(STRVAR_RE.findall(src))
                relpath = os.path.relpath(path, SRC_DIR).replace(os.sep, '/')
                for m in REGISTER_RE.finditer(src):
                    args = split_args(m.group(1))
                    if len(args) >= 3:
                        name = resolve_arg(args[2], defines)
                        if name:
                            files.setdefault(name, set()).add(relpath)
    return files


def file_for_name(name):
    for top in DISSECTOR_DIRS[:1]:
        for cand in (name, name.replace('_', '-'), name.replace('-', '_'),
                     name.replace('.', '_'), name.replace('.', '-')):
            rel = f'{top}/packet-{cand}.c'
            if os.path.exists(os.path.join(SRC_DIR, rel)):
                return rel
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--program-path', required=True,
                        help='directory with the tshark to use')
    parser.add_argument('-j', '--jobs', type=int, default=os.cpu_count(),
                        help='parallel tshark runs')
    parser.add_argument('-o', '--output', default=MAP_FILE)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='print the protocols of each class')
    args = parser.parse_args()

    tshark = os.path.join(args.program_path, 'tshark')
    known = tshark_protocols(tshark)
    reg = protocol_files()
    classes = list(coverage_classes())

    jobs = {}
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        for name, caps, strings in classes:
            opts = class_options(strings)
            for cap in caps:
                jobs[(name, cap)] = pool.submit(leaf_protocols, tshark, cap, opts)

    result = {}
    unmapped = {}
    for name, caps, strings in classes:
        protos = set()
        carriers = set()
        files = set()
        for cap in caps:
            leaves, below = jobs[(name, cap)].result()
            protos |= leaves
            carriers |= below
            prefix = cap.split(COVERAGE_TAG)[0]
            if prefix in known:
                protos.add(prefix)
            f = file_for_name(prefix)
            if f:
                files.add(f)
        targets, named = named_protocols(strings, known)
        # A field of a lower layer (udp.dstport to pick frames, for
        # example) does not make the class depend on that layer.
        protos |= targets | (named - carriers - LOWER_LAYERS)
        protos -= IGNORED_PROTOCOLS
        protos = {p for p in protos if not p.startswith('_ws')}
        for p in sorted(protos):
            hit = reg.get(p) or ({file_for_name(p)} - {None})
            if hit:
                files |= hit
            else:
                unmapped.setdefault(p, []).append(name)
        if args.verbose:
            print(f'{name}: {" ".join(sorted(protos))}')
        if files:
            result[name] = sorted(files)

    out = {
        'comment': 'Generated by tools/gen-dissection-map.py. Do not edit; '
                   'rerun it after changing coverage captures or tests.',
        'classes': dict(sorted(result.items())),
    }
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=1)
        f.write('\n')

    print(f'{len(result)} of {len(classes)} coverage classes mapped to '
          f'{len({x for v in result.values() for x in v})} files; '
          f'wrote {os.path.relpath(args.output)}', file=sys.stderr)
    if unmapped:
        print(f'{len(unmapped)} protocols without a source file: '
              + ', '.join(sorted(unmapped)), file=sys.stderr)


if __name__ == '__main__':
    main()
