#!/usr/bin/env python
#
# Looks for registration routines in the taps,
# and assembles C code to call all the routines.
#
# This is a Python version of the make-reg-dotc shell script.
# Running the shell script on Win32 is very very slow because of
# all the process-launching that goes on --- multiple greps and
# seds for each input file.  I wrote this python version so that
# less processes would have to be started.
#
# Copyright 2010 Anders Broman <anders.broman@ericsson.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import os
import sys
import re
import pickle
from stat import *

#
# The first argument is the directory in which the source files live.
#
srcdir = sys.argv[1]

#
# The second argument is  "taps".
#
registertype = sys.argv[2]
if registertype == "taps":
    tmp_filename = "wireshark-tap-register.c-tmp"
    final_filename = "wireshark-tap-register.c"
    cache_filename = "wireshark-tap-register-cache.pkl"
elif registertype == "tshark-taps":
    tmp_filename = "tshark-tap-register.c-tmp"
    final_filename = "tshark-tap-register.c"
    cache_filename = "tshark-tap-register-cache.pkl"
else:
    print("Unknown output type '%s'" % registertype)
    sys.exit(1)


#
# All subsequent arguments are the files to scan.
#
files = sys.argv[3:]

# Create the proper list of filenames
filenames = []
for file in files:
    if os.path.isfile(file):
        filenames.append(file)
    else:
        filenames.append("%s/%s" % (srcdir, file))

if len(filenames) < 1:
    print("No files found")
    sys.exit(1)


# Look through all files, applying the regex to each line.
# If the pattern matches, save the "symbol" section to the
# appropriate array.
regs = {
        'tap_reg': [],
        }

# For those that don't know Python, r"" indicates a raw string,
# devoid of Python escapes.
tap_regex0 = r"^(?P<symbol>register_tap_listener_[_A-Za-z0-9]+)\s*\([^;]+$"
tap_regex1 = r"void\s+(?P<symbol>register_tap_listener_[_A-Za-z0-9]+)\s*\([^;]+$"

# This table drives the pattern-matching and symbol-harvesting
patterns = [
        ( 'tap_reg', re.compile(tap_regex0) ),
        ( 'tap_reg', re.compile(tap_regex1) ),
        ]

# Open our registration symbol cache
cache = None
if cache_filename:
    try:
        cache_file = open(cache_filename, 'rb')
        cache = pickle.load(cache_file)
        cache_file.close()
    except:
        cache = {}

# Grep
for filename in filenames:
    file = open(filename)
    cur_mtime = os.fstat(file.fileno())[ST_MTIME]
    if cache and filename in cache:
        cdict = cache[filename]
        if cur_mtime == cdict['mtime']:
#                       print "Pulling %s from cache" % (filename)
            regs['tap_reg'].extend(cdict['tap_reg'])
            file.close()
            continue
    # We don't have a cache entry
    if cache is not None:
        cache[filename] = {
                'mtime': cur_mtime,
                'tap_reg': [],
                }
#       print "Searching %s" % (filename)
    for line in file.readlines():
        for action in patterns:
            regex = action[1]
            match = regex.search(line)
            if match:
                symbol = match.group("symbol")
                sym_type = action[0]
                regs[sym_type].append(symbol)
                if cache is not None:
#                                       print "Caching %s for %s: %s" % (sym_type, filename, symbol)
                    cache[filename][sym_type].append(symbol)
    file.close()

if cache is not None and cache_filename is not None:
    cache_file = open(cache_filename, 'wb')
    pickle.dump(cache, cache_file)
    cache_file.close()

# Make sure we actually processed something
if len(regs['tap_reg']) < 1:
    print("No protocol registrations found")
    sys.exit(1)

# Sort the lists to make them pretty
regs['tap_reg'].sort()

reg_code = open(tmp_filename, "w")

reg_code.write("/* Do not modify this file. Changes will be overwritten.  */\n")
reg_code.write("/* Generated automatically from %s  */\n" % (sys.argv[0]))

# Make the routine to register all taps
reg_code.write("""
#include "register.h"
void register_all_tap_listeners(void) {
""");

for symbol in regs['tap_reg']:
    line = "    {extern void %s (void); %s ();}\n" % (symbol, symbol)
    reg_code.write(line)

reg_code.write("}\n")


# Close the file
reg_code.close()

# Remove the old final_file if it exists.
try:
    os.stat(final_filename)
    os.remove(final_filename)
except OSError:
    pass

# Move from tmp file to final file
os.rename(tmp_filename, final_filename)

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 4
# indent-tabs-mode: nil
# End:
#
# vi: set shiftwidth=4 expandtab:
# :indentSize=4:noTabs=true:
#
