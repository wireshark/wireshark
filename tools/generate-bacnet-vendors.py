#!/usr/bin/env python2

'''
 Copyright 2014 Anish Bhatt <anish@chelsio.com>

SPDX-License-Identifier: GPL-2.0-or-later
'''

from bs4 import BeautifulSoup
import urllib
import sys
import string
# Required to convert accents/diaeresis etc.
import translitcodec

f = urllib.urlopen("http://www.bacnet.org/VendorID/BACnet%20Vendor%20IDs.htm")
html = f.read()
soup = BeautifulSoup(''.join(html))

entry = "static const value_string\nBACnetVendorIdentifiers [] = {"
table = soup.find('table')

rows = table.findAll('tr')

for tr in rows:
  cols = tr.findAll('td')
  for index,td in enumerate(cols[0:2]):
    text = ''.join(td.find(text=True))
    if index == 0:
      entry = "    { %3s" % text
    else:
      entry += ", \"%s\" }," % text.rstrip()
  # Required specially for "Dorsette's Inc." due to malformed html
  entry = entry.replace(u'\u0092', u'\'')
  # Required to convert accents/diaeresis etc.
  entry = entry.encode('translit/long')
  # Encode to ascii so we can out to file
  entry = entry.encode("ascii",'ignore')
  print entry

entry = "    { 0, NULL }\n};"
print entry.encode("ascii")
