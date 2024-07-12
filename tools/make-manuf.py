#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''Update the "manuf" file.

Make-manuf creates a file containing ethernet OUIs and their company
IDs from the databases at IEEE.
'''

import csv
import html
import io
import os
import re
import sys
import urllib.request, urllib.error, urllib.parse

have_icu = False
try:
    # Use the grapheme or segments module instead?
    import icu
    have_icu = True
except ImportError:
    pass

def exit_msg(msg=None, status=1):
    if msg is not None:
        sys.stderr.write(msg + '\n\n')
    sys.stderr.write(__doc__ + '\n')
    sys.exit(status)

def open_url(url):
    '''Open a URL.
    Returns a tuple containing the body and response dict. The body is a
    str in Python 3 and bytes in Python 2 in order to be compatible with
    csv.reader.
    '''

    if len(sys.argv) > 1:
        url_path = os.path.join(sys.argv[1], url[1])
        url_fd = open(url_path)
        body = url_fd.read()
        url_fd.close()
    else:
        url_path = '/'.join(url)

        req_headers = { 'User-Agent': 'Wireshark make-manuf' }
        try:
            req = urllib.request.Request(url_path, headers=req_headers)
            response = urllib.request.urlopen(req)
            body = response.read().decode('UTF-8', 'replace')
        except Exception:
            exit_msg('Error opening ' + url_path)

    return body

# These are applied after punctuation has been removed.
# More examples at https://en.wikipedia.org/wiki/Incorporation_(business)
general_terms = '|'.join([
    ' a +s\\b', # A/S and A.S. but not "As" as in "Connect As".
    ' ab\\b', # Also follows "Oy", which is covered below.
    ' ag\\b',
    ' b ?v\\b',
    ' closed joint stock company\\b',
    ' co\\b',
    ' company\\b',
    ' corp\\b',
    ' corporation\\b',
    ' corporate\\b',
    ' de c ?v\\b', # Follows "S.A.", which is covered separately below.
    ' gmbh\\b',
    ' holding\\b',
    ' inc\\b',
    ' incorporated\\b',
    ' jsc\\b',
    ' kg\\b',
    ' k k\\b', # "K.K." as in "kabushiki kaisha", but not "K+K" as in "K+K Messtechnik".
    ' limited\\b',
    ' llc\\b',
    ' ltd\\b',
    ' n ?v\\b',
    ' oao\\b',
    ' of\\b',
    ' open joint stock company\\b',
    ' ooo\\b',
    ' oü\\b',
    ' oy\\b',
    ' oyj\\b',
    ' plc\\b',
    ' pty\\b',
    ' pvt\\b',
    ' s ?a ?r ?l\\b',
    ' s ?a\\b',
    ' s ?p ?a\\b',
    ' sp ?k\\b',
    ' s ?r ?l\\b',
    ' systems\\b',
    '\\bthe\\b',
    ' zao\\b',
    ' z ?o ?o\\b'
    ])

# Chinese company names tend to start with the location, skip it (non-exhaustive list).
skip_start = [
    'shengzen',
    'shenzhen',
    'beijing',
    'shanghai',
    'wuhan',
    'hangzhou',
    'guangxi',
    'guangdong',
    'chengdu',
]

# Special cases handled directly
special_case = {
    "Advanced Micro Devices": "AMD",
    "杭州德澜科技有限公司": "DelanTech" # 杭州德澜科技有限公司（HangZhou Delan Technology Co.,Ltd）
}

def shorten(manuf):
    '''Convert a long manufacturer name to abbreviated and short names'''
    # Normalize whitespace.
    manuf = ' '.join(manuf.split())
    orig_manuf = manuf
    # Convert all caps to title case
    if manuf.isupper():
        manuf = manuf.title()
    # Remove the contents of parenthesis as ancillary data
    manuf = re.sub(r"\(.*\)", '', manuf)
    # Remove the contents of fullwidth parenthesis (mostly in Asian names)
    manuf = re.sub(r"（.*）", '', manuf)
    # Remove "a" before removing punctuation ("Aruba, a Hewlett [...]" etc.)
    manuf = manuf.replace(" a ", " ")
    # Remove any punctuation
    # XXX Use string.punctuation? Note that it includes '-' and '*'.
    manuf = re.sub(r"[\"',./:()+-]", ' ', manuf)
    # XXX For some reason including the double angle brackets in the above
    # regex makes it bomb
    manuf = re.sub(r"[«»“”]", ' ', manuf)
    # & isn't needed when Standalone
    manuf = manuf.replace(" & ", " ")
    # Remove business types and other general terms ("the", "inc", "plc", etc.)
    plain_manuf = re.sub(general_terms, '', manuf, flags=re.IGNORECASE)
    # ...but make sure we don't remove everything.
    if not all(s == ' ' for s in plain_manuf):
        manuf = plain_manuf

    manuf = manuf.strip()

    # Check for special case
    if manuf in special_case.keys():
        manuf = special_case[manuf]

    # XXX: Some of the entries have Chinese city or other location
    # names written with spaces between each character, like
    # Bei jing, Wu Han, Shen Zhen, etc. We should remove that too.
    split = manuf.split()
    if len(split) > 1 and split[0].lower() in skip_start:
        manuf = ' '.join(split[1:])

    # Remove all spaces
    manuf = re.sub(r'\s+', '', manuf)

    if len(manuf) < 1:
        sys.stderr.write('Manufacturer "{}" shortened to nothing.\n'.format(orig_manuf))
        sys.exit(1)

    # Truncate names to a reasonable length, say, 12 characters. If
    # the string contains UTF-8, this may be substantially more than
    # 12 bytes. It might also be less than 12 visible characters. Plain
    # Python slices Unicode strings by code point, which is better
    # than raw bytes but not as good as grapheme clusters. PyICU
    # supports grapheme clusters. https://bugs.python.org/issue30717
    #

    # Truncate by code points
    trunc_len = 12

    if have_icu:
        # Truncate by grapheme clusters
        bi_ci = icu.BreakIterator.createCharacterInstance(icu.Locale('en_US'))
        bi_ci.setText(manuf)
        bounds = list(bi_ci)
        bounds = bounds[0:trunc_len]
        trunc_len = bounds[-1]

    manuf = manuf[:trunc_len]

    if manuf.lower() == orig_manuf.lower():
        # Original manufacturer name was short and simple.
        return [manuf, None]

    mixed_manuf = orig_manuf
    # At least one entry has whitespace in front of a period.
    mixed_manuf = re.sub(r'\s+\.', '.', mixed_manuf)
    #If company is all caps, convert to mixed case (so it doesn't look like we're screaming the company name)
    if mixed_manuf.upper() == mixed_manuf:
        mixed_manuf = mixed_manuf.title()

    return [manuf, mixed_manuf]

MA_L = 'MA_L'
MA_M = 'MA_M'
MA_S = 'MA_S'

def prefix_to_oui(prefix, prefix_map):
    pfx_len = int(len(prefix) * 8 / 2)
    prefix24 = prefix[:6]
    oui24 = ':'.join(hi + lo for hi, lo in zip(prefix24[0::2], prefix24[1::2]))

    if pfx_len == 24:
        # 24-bit OUI assignment, no mask
        return oui24, MA_L

    # Other lengths which require a mask.
    oui = prefix.ljust(12, '0')
    oui = ':'.join(hi + lo for hi, lo in zip(oui[0::2], oui[1::2]))
    if pfx_len == 28:
        kind = MA_M
    elif pfx_len == 36:
        kind = MA_S
    prefix_map[oui24] = kind

    return '{}/{:d}'.format(oui, int(pfx_len)), kind

def main():
    manuf_path = os.path.join('epan', 'manuf-data.c')

    ieee_d = {
        'OUI':   { 'url': ["https://standards-oui.ieee.org/oui/", "oui.csv"], 'min_entries': 1000 },
        'CID':   { 'url': ["https://standards-oui.ieee.org/cid/", "cid.csv"], 'min_entries': 75 },
        'IAB':   { 'url': ["https://standards-oui.ieee.org/iab/", "iab.csv"], 'min_entries': 1000 },
        'OUI28': { 'url': ["https://standards-oui.ieee.org/oui28/", "mam.csv"], 'min_entries': 1000 },
        'OUI36': { 'url': ["https://standards-oui.ieee.org/oui36/", "oui36.csv"], 'min_entries': 1000 },
    }
    oui_d = {
        MA_L: { '00:00:00' : ['00:00:00', 'Officially Xerox, but 0:0:0:0:0:0 is more common'] },
        MA_M: {},
        MA_S: {},
    }

    min_total = 35000 # 35830 as of 2018-09-05
    total_added = 0

    # Add IEEE entries from each of their databases
    ieee_db_l = ['OUI', 'OUI28', 'OUI36', 'CID', 'IAB']

    # map a 24-bit prefix to MA-M/MA-S or none (MA-L by default)
    prefix_map = {}

    for db in ieee_db_l:
        db_url = ieee_d[db]['url']
        ieee_d[db]['skipped'] = 0
        ieee_d[db]['added'] = 0
        ieee_d[db]['total'] = 0
        print('Merging {} data from {}'.format(db, db_url))
        body = open_url(db_url)
        ieee_csv = csv.reader(body.splitlines())

        # Pop the title row.
        next(ieee_csv)
        for ieee_row in ieee_csv:
            #Registry,Assignment,Organization Name,Organization Address
            #IAB,0050C2DD6,Transas Marine Limited,Datavagen 37 Askim Vastra Gotaland SE 436 32
            oui, kind = prefix_to_oui(ieee_row[1].upper(), prefix_map)
            manuf = ieee_row[2].strip()
            # The Organization Name field occasionally contains HTML entities. Undo them.
            manuf = html.unescape(manuf)
            # "Watts A\S"
            manuf = manuf.replace('\\', '/')
            if manuf == 'IEEE Registration Authority':
                # These are held for subdivision into MA-M/MA-S
                continue
            #if manuf == 'Private':
            #    continue
            if oui in oui_d[kind]:
                action = 'Skipping'
                print('{} - {} IEEE "{}" in favor of "{}"'.format(oui, action, manuf, oui_d[kind][oui]))
                ieee_d[db]['skipped'] += 1
            else:
                oui_d[kind][oui] = shorten(manuf)
                ieee_d[db]['added'] += 1
            ieee_d[db]['total'] += 1

        if ieee_d[db]['total'] < ieee_d[db]['min_entries']:
            exit_msg("Too few {} entries. Got {}, wanted {}".format(db, ieee_d[db]['total'], ieee_d[db]['min_entries']))
        total_added += ieee_d[db]['total']

    if total_added < min_total:
        exit_msg("Too few total entries ({})".format(total_added))

    try:
        manuf_fd = io.open(manuf_path, 'w', encoding='UTF-8')
    except Exception:
        exit_msg("Couldn't open manuf file for reading ({}) ".format(manuf_path))

    manuf_fd.write('''/*
 * This file was generated by running ./tools/make-manuf.py.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The data below has been assembled from the following sources:
 *
 * The IEEE public OUI listings available from:
 * <http://standards-oui.ieee.org/oui/oui.csv>
 * <http://standards-oui.ieee.org/cid/cid.csv>
 * <http://standards-oui.ieee.org/iab/iab.csv>
 * <http://standards-oui.ieee.org/oui28/mam.csv>
 * <http://standards-oui.ieee.org/oui36/oui36.csv>
 *
 */

''')

    # Write the prefix map
    manuf_fd.write("static const manuf_registry_t ieee_registry_table[] = {\n")
    keys = list(prefix_map.keys())
    keys.sort()
    for oui in keys:
        manuf_fd.write("    {{ {{ 0x{}, 0x{}, 0x{} }}, {} }},\n".format(oui[0:2], oui[3:5], oui[6:8], prefix_map[oui]))
    manuf_fd.write("};\n\n")

    # write the MA-L table
    manuf_fd.write("static const manuf_oui24_t global_manuf_oui24_table[] = {\n")
    keys = list(oui_d[MA_L].keys())
    keys.sort()
    for oui in keys:
        short = oui_d[MA_L][oui][0]
        if oui_d[MA_L][oui][1]:
            long = oui_d[MA_L][oui][1]
        else:
            long = short
        line = "    {{ {{ 0x{}, 0x{}, 0x{} }}, \"{}\", ".format(oui[0:2], oui[3:5], oui[6:8], short)
        sep = 44 - len(line)
        if sep <= 0:
            sep = 0
        line += sep * ' '
        line += "\"{}\" }},\n".format(long.replace('"', '\\"'))
        manuf_fd.write(line)
    manuf_fd.write("};\n\n")

    # write the MA-M table
    manuf_fd.write("static const manuf_oui28_t global_manuf_oui28_table[] = {\n")
    keys = list(oui_d[MA_M].keys())
    keys.sort()
    for oui in keys:
        short = oui_d[MA_M][oui][0]
        if oui_d[MA_M][oui][1]:
            long = oui_d[MA_M][oui][1]
        else:
            long = short
        line = "    {{ {{ 0x{}, 0x{}, 0x{}, 0x{} }}, \"{}\", ".format(oui[0:2], oui[3:5], oui[6:8], oui[9:11], short)
        sep = 50 - len(line)
        if sep <= 0:
            sep = 0
        line += sep * ' '
        line += "\"{}\" }},\n".format(long.replace('"', '\\"'))
        manuf_fd.write(line)
    manuf_fd.write("};\n\n")

    #write the MA-S table
    manuf_fd.write("static const manuf_oui36_t global_manuf_oui36_table[] = {\n")
    keys = list(oui_d[MA_S].keys())
    keys.sort()
    for oui in keys:
        short = oui_d[MA_S][oui][0]
        if oui_d[MA_S][oui][1]:
            long = oui_d[MA_S][oui][1]
        else:
            long = short
        line = "    {{ {{ 0x{}, 0x{}, 0x{}, 0x{}, 0x{} }}, \"{}\", ".format(oui[0:2], oui[3:5], oui[6:8], oui[9:11], oui[12:14], short)
        sep = 56 - len(line)
        if sep <= 0:
            sep = 0
        line += sep * ' '
        line += "\"{}\" }},\n".format(long.replace('"', '\\"'))
        manuf_fd.write(line)
    manuf_fd.write("};\n")

    manuf_fd.close()

    for db in ieee_d:
        print('{:<20}: {}'.format('IEEE ' + db + ' added', ieee_d[db]['added']))
    print('{:<20}: {}'.format('Total added', total_added))

    print()
    for db in ieee_d:
        print('{:<20}: {}'.format('IEEE ' + db + ' total', ieee_d[db]['total']))

    print()
    for db in ieee_d:
        print('{:<20}: {}'.format('IEEE ' + db + ' skipped', ieee_d[db]['skipped']))

if __name__ == '__main__':
    main()
