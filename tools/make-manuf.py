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
    str in Python 3 and bytes in Python 2 in order to be compatibile with
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
    'a +s', # A/S and A.S. but not "As" as in "Connect As".
    'ab', # Also follows "Oy", which is covered below.
    'ag',
    'b ?v',
    'closed joint stock company',
    'co',
    'company',
    'corp',
    'corporation',
    'de c ?v', # Follows "S.A.", which is covered separately below.
    'gmbh',
    'holding',
    'inc',
    'incorporated',
    'jsc',
    'kg',
    'k k', # "K.K." as in "kabushiki kaisha", but not "K+K" as in "K+K Messtechnik".
    'limited',
    'llc',
    'ltd',
    'n ?v',
    'oao',
    'of',
    'open joint stock company',
    'ooo',
    'oü',
    'oy',
    'oyj',
    'plc',
    'pty',
    'pvt',
    's ?a ?r ?l',
    's ?a',
    's ?p ?a',
    'sp ?k',
    's ?r ?l',
    'systems',
    'the',
    'zao',
    'z ?o ?o'
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
]


def shorten(manuf):
    '''Convert a long manufacturer name to abbreviated and short names'''
    # Normalize whitespace.
    manuf = ' '.join(manuf.split())
    orig_manuf = manuf
    # Add exactly one space on each end.
    # XXX This appears to be for the re.sub below.
    manuf = ' {} '.format(manuf)
    # Convert all caps to title case
    if manuf.isupper():
        manuf = manuf.title()
    # Remove any punctuation
    # XXX Use string.punctuation? Note that it includes '-' and '*'.
    manuf = re.sub(r"[\"',./:()]", ' ', manuf)
    # & isn't needed when Standalone
    manuf = manuf.replace(" & ", " ")
    # Remove business types and other general terms ("the", "inc", "plc", etc.)
    plain_manuf = re.sub(r'\W(' + general_terms + ')(?= )', '', manuf, flags=re.IGNORECASE)
    # ...but make sure we don't remove everything.
    if not all(s == ' ' for s in plain_manuf):
        manuf = plain_manuf

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

def prefix_to_oui(prefix):
    pfx_len = len(prefix) * 8 / 2

    if pfx_len == 24:
        # 24-bit OUI assignment, no mask
        return ':'.join(hi + lo for hi, lo in zip(prefix[0::2], prefix[1::2]))

    # Other lengths which require a mask.
    oui = prefix.ljust(12, '0')
    oui = ':'.join(hi + lo for hi, lo in zip(oui[0::2], oui[1::2]))
    return '{}/{:d}'.format(oui, int(pfx_len))

def main():
    this_dir = os.path.dirname(__file__)
    manuf_path = os.path.join(this_dir, '..', 'manuf')

    ieee_d = {
        'OUI':   { 'url': ["https://standards-oui.ieee.org/oui/", "oui.csv"], 'min_entries': 1000 },
        'CID':   { 'url': ["https://standards-oui.ieee.org/cid/", "cid.csv"], 'min_entries': 75 },
        'IAB':   { 'url': ["https://standards-oui.ieee.org/iab/", "iab.csv"], 'min_entries': 1000 },
        'OUI28': { 'url': ["https://standards-oui.ieee.org/oui28/", "mam.csv"], 'min_entries': 1000 },
        'OUI36': { 'url': ["https://standards-oui.ieee.org/oui36/", "oui36.csv"], 'min_entries': 1000 },
    }
    oui_d = {}

    min_total = 35000; # 35830 as of 2018-09-05
    total_added = 0

    # Add IEEE entries from each of their databases
    ieee_db_l = ['OUI', 'OUI28', 'OUI36', 'CID', 'IAB']

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
            oui = prefix_to_oui(ieee_row[1].upper())
            manuf = ieee_row[2].strip()
            # The Organization Name field occasionally contains HTML entities. Undo them.
            manuf = html.unescape(manuf)
            if oui in oui_d:
                action = 'Skipping'
                print('{} - {} IEEE "{}" in favor of "{}"'.format(oui, action, manuf, oui_d[oui]))
                ieee_d[db]['skipped'] += 1
            else:
                oui_d[oui] = shorten(manuf)
                ieee_d[db]['added'] += 1
            ieee_d[db]['total'] += 1

        if ieee_d[db]['total'] < ieee_d[db]['min_entries']:
            exit_msg("Too few {} entries. Got {}, wanted {}".format(db, ieee_d[db]['total'], ieee_d[db]['min_entries']))
        total_added += ieee_d[db]['total']

    if total_added < min_total:
        exit_msg("Too few total entries ({})".format(total_added))

    # Write the output file.

    try:
        manuf_fd = io.open(manuf_path, 'w', encoding='UTF-8')
    except Exception:
        exit_msg("Couldn't open manuf file for reading ({}) ".format(manuf_path))

    manuf_fd.write("# This file was generated by running ./tools/make-manuf.py.\n")
    manuf_fd.write(
'''#
# /etc/manuf - Ethernet vendor codes, and well-known MAC addresses
#
# Laurent Deniel <laurent.deniel [AT] free.fr>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald [AT] wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# The data below has been assembled from the following sources:
#
# The IEEE public OUI listings available from:
# <http://standards-oui.ieee.org/oui/oui.csv>
# <http://standards-oui.ieee.org/cid/cid.csv>
# <http://standards-oui.ieee.org/iab/iab.csv>
# <http://standards-oui.ieee.org/oui28/mam.csv>
# <http://standards-oui.ieee.org/oui36/oui36.csv>
#
# This file is in the same format as ethers(4) except that vendor names
# are truncated to eight characters when used with Wireshark, and
# that well-known MAC addresses need not have a full 6 octets and may
# have a netmask following them specifying how many bits of the address
# are relevant (the other bits are wildcards).  Also, either ":", "-",
# or "." can be used to separate the octets.
#
# You can get the latest version of this file from
# https://gitlab.com/wireshark/wireshark/-/raw/master/manuf

''')

    for db in ieee_db_l:
        manuf_fd.write(
            '''\

'''.format( **ieee_d[db]))

    oui_l = list(oui_d.keys())
    oui_l.sort()
    for oui in oui_l:
        manuf = oui_d[oui]
        line = oui
        sep_len = (24 - len(line)) // 8
        if sep_len <= 0:
            sep_len = 1
        line += '\t' * sep_len + manuf[0]
        if manuf[1]:
            if len(manuf[0]) < 8:
                sep_len = 2
            else:
                sep_len = 1
            line += '\t' * sep_len + manuf[1]
        line += '\n'
        manuf_fd.write(line)

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
