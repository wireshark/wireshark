#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''Update the "manuf" file.

Make-manuf creates a file containing ethernet OUIs and their company
IDs. It merges the databases at IEEE with entries in our template file.
Our file in turn contains entries from
http://www.cavebear.com/archive/cavebear/Ethernet/Ethernet.txt along
with our own.

The script reads the comments at the top of "manuf.tmpl" and writes them
to "manuf".  It then joins the manufacturer listing in "manuf.tmpl" with
the listing in "oui.txt", "iab.txt", etc, with the entries in
"manuf.tmpl" taking precedence.
'''

import codecs
import csv
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
    req_headers = { 'User-Agent': 'Wireshark make-manuf' }
    try:
        req = urllib.request.Request(url, headers=req_headers)
        response = urllib.request.urlopen(req)
        body = response.read().decode('UTF-8', 'replace')
    except:
        exit_msg('Error opening ' + url)

    return (body, dict(response.info()))

# These are applied after punctuation has been removed.
# More examples at https://en.wikipedia.org/wiki/Incorporation_(business)
general_terms = '|'.join([
    'a/s',
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

def shorten(manuf):
    '''Convert a long manufacturer name to abbreviated and short names'''
    # Normalize whitespace.
    manuf = ' '.join(manuf.split())
    orig_manuf = manuf
    # Add exactly one space on each end.
    # XXX This appears to be for the re.sub below.
    manuf = u' {} '.format(manuf)
    # Convert all caps to title case
    if manuf.isupper():
        manuf = manuf.title()
    # Remove any punctuation
    # XXX Use string.punctuation? Note that it includes '-' and '*'.
    manuf = re.sub(u"[\"',.()]", ' ', manuf)
    # & isn't needed when Standalone
    manuf = manuf.replace(" & ", " ")
    # Remove business types and other general terms ("the", "inc", "plc", etc.)
    plain_manuf = re.sub('\W(' + general_terms + ')(?= )', '', manuf, flags=re.IGNORECASE)
    # ...but make sure we don't remove everything.
    if not all(s == ' ' for s in plain_manuf):
        manuf = plain_manuf
    # Remove all spaces
    manuf = re.sub('\s+', '', manuf)

    if len(manuf) < 1:
        sys.stderr.write('Manufacturer "{}" shortened to nothing.\n'.format(orig_manuf))
        sys.exit(1)

    # Truncate names to a reasonable length, say, 8 characters. If
    # the string contains UTF-8, this may be substantially more than
    # 8 bytes. It might also be less than 8 visible characters. Plain
    # Python slices Unicode strings by code point, which is better
    # than raw bytes but not as good as grapheme clusters. PyICU
    # supports grapheme clusters. https://bugs.python.org/issue30717
    #
    # In our case plain Python truncates 'Savroni̇k Elektroni̇k'
    # to 'Savroni̇', which is 7 visible characters, 8 code points,
    # and 9 bytes.

    # Truncate by code points
    trunc_len = 8

    if have_icu:
        # Truncate by grapheme clusters
        bi_ci = icu.BreakIterator.createCharacterInstance(icu.Locale('en_US'))
        bi_ci.setText(manuf)
        bounds = list(bi_ci)
        bounds = bounds[0:8]
        trunc_len = bounds[-1]

    manuf = manuf[:trunc_len]

    if manuf.lower() == orig_manuf.lower():
        # Original manufacturer name was short and simple.
        return manuf

    mixed_manuf = orig_manuf
    # At least one entry has whitespace in front of a period.
    mixed_manuf = re.sub('\s+\.', '.', mixed_manuf)
    #If company is all caps, convert to mixed case (so it doesn't look like we're screaming the company name)
    if mixed_manuf.upper() == mixed_manuf:
        mixed_manuf = mixed_manuf.title()

    return u'{}\t{}'.format(manuf, mixed_manuf)

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
    if sys.version_info[0] < 3:
        print("This requires Python 3")
        sys.exit(2)

    this_dir = os.path.dirname(__file__)
    template_path = os.path.join(this_dir, '..', 'manuf.tmpl')
    manuf_path = os.path.join(this_dir, '..', 'manuf')
    header_l = []
    in_header = True

    ieee_d = {
        'OUI':   { 'url': "http://standards-oui.ieee.org/oui/oui.csv", 'min_entries': 1000 },
        'CID':   { 'url': "http://standards-oui.ieee.org/cid/cid.csv", 'min_entries': 75 },
        'IAB':   { 'url': "http://standards-oui.ieee.org/iab/iab.csv", 'min_entries': 1000 },
        'OUI28': { 'url': "http://standards-oui.ieee.org/oui28/mam.csv", 'min_entries': 1000 },
        'OUI36': { 'url': "http://standards-oui.ieee.org/oui36/oui36.csv", 'min_entries': 1000 },
    }
    oui_d = {}
    hp = "[0-9a-fA-F]{2}"
    manuf_re = re.compile('^({}:{}:{})\s+(\S.*)$'.format(hp, hp, hp))

    min_total = 35000; # 35830 as of 2018-09-05
    tmpl_added  = 0
    total_added = 0

    # Write out the header and populate the OUI list with our entries.

    try:
        tmpl_fd = io.open(template_path, 'r', encoding='UTF-8')
    except:
        exit_msg("Couldn't open template file for reading ({}) ".format(template_path))
    for tmpl_line in tmpl_fd:
        tmpl_line = tmpl_line.strip()
        m = manuf_re.match(tmpl_line)
        if not m and in_header:
            header_l.append(tmpl_line)
        elif m:
            in_header = False
            oui = m.group(1).upper()
            oui_d[oui] = m.group(2)
            tmpl_added += 1
    tmpl_fd.close()

    total_added += tmpl_added

    # Add IEEE entries from each of their databases
    ieee_db_l = list(ieee_d.keys())
    ieee_db_l.sort()

    for db in ieee_db_l:
        db_url = ieee_d[db]['url']
        ieee_d[db]['skipped'] = 0
        ieee_d[db]['added'] = 0
        ieee_d[db]['total'] = 0
        print('Merging {} data from {}'.format(db, db_url))
        (body, response_d) = open_url(db_url)
        ieee_csv = csv.reader(body.splitlines())
        ieee_d[db]['last-modified'] = response_d['Last-Modified']
        ieee_d[db]['length'] = response_d['Content-Length']

        # Pop the title row.
        next(ieee_csv)
        for ieee_row in ieee_csv:
            #Registry,Assignment,Organization Name,Organization Address
            #IAB,0050C2DD6,Transas Marine Limited,Datavagen 37 Askim Vastra Gotaland SE 436 32
            oui = prefix_to_oui(ieee_row[1].upper())
            manuf = ieee_row[2].strip()
            if oui in oui_d:
                print(u'{} - Skipping IEEE "{}" in favor of "{}"'.format(oui, manuf, oui_d[oui]))
                ieee_d[db]['skipped'] += 1
            else:
                oui_d[oui] = shorten(manuf)
                ieee_d[db]['added'] += 1
            ieee_d[db]['total'] += 1

        if ieee_d[db]['total'] < ieee_d[db]['min_entries']:
            exit_msg("Too few {} entries ({})".format(ieee_db, ieee_d[db]['total']))
        total_added += ieee_d[db]['total']

    if total_added < min_total:
        exit_msg("Too few total entries ({})".format(total_added))

    # Write the output file.

    try:
        manuf_fd = io.open(manuf_path, 'w', encoding='UTF-8')
    except:
        exit_msg("Couldn't open manuf file for reading ({}) ".format(manuf_path))

    manuf_fd.write(u"# This file was generated by running ./tools/make-manuf.py.\n")
    manuf_fd.write(u"# Don't change it directly, change manuf.tmpl instead.\n#\n")
    manuf_fd.write('\n'.join(header_l))

    for db in ieee_db_l:
        manuf_fd.write(
            u'''\
# {url}:
#   Content-Length: {length}
#   Last-Modified: {last-modified}

'''.format( **ieee_d[db]))

    oui_l = list(oui_d.keys())
    oui_l.sort()
    for oui in oui_l:
        manuf_fd.write(u'{}\t{}\n'.format(oui, oui_d[oui]))

    manuf_fd.close()

    print('{:<20}: {}'.format('Original entries', tmpl_added))
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
