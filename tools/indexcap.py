#!/usr/bin/python
#
# Tool to index protocols that appears in the given capture files
#
# Copyright 2009, Kovarththanan Rajaratnam <kovarththanan.rajaratnam@gmail.com>
#
# $Id$
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

from optparse import OptionParser
import sys
import os
import subprocess
import re

def main():
    parser = OptionParser(usage="usage: %prog [options] cache_file file_1|dir_1 [.. file_n|dir_n]")
    parser.add_option("-n", "--no-append", dest="append", default=True, action="store_false", help="Do not append to existing cache file")
    parser.add_option("-m", "--max-files", dest="max_files", default=sys.maxint, type="int", help="Max number of files to process")
    parser.add_option("-b", "--binary-dir", dest="bin_dir", default=os.getcwd(), help="Directory containing tshark executable")

    (options, args) = parser.parse_args()

    if len(args) == 0:
        parser.error("cache_file is a required argument")

    if len(args) == 1:
        parser.error("one capture file/directory must be specified")

    tshark = os.path.join(options.bin_dir, "tshark")
    print "tshark:", tshark, "\n"

    cache_file = args.pop(0)
    paths = args
    cap_files = []
    for path in paths:
        if os.path.isdir(path):
            path = os.path.normpath(path)
            for root, dirs, files in os.walk(path):
                cap_files += [os.path.join(root, name) for name in files]
        else:
            cap_files.append(path)

    cap_files.sort()
    cap_files = cap_files[:options.max_files]

    cap_hash = {}
    for file in cap_files:
        p = subprocess.Popen([tshark, "-Tfields", "-e", "frame.protocols", "-r", file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout, stderr) = p.communicate()
        if p.returncode != 0:
            print "SKIP:", file
        else:
            print "PROCESSED:", file

        proto_hash = {}
        for line in re.split(r'\r\n|\n', stdout):
            if not re.match(r'^[\w:-]+$', line):
                continue

            for proto in line.split(':'):
                num = proto_hash.setdefault(proto, 0)
                proto_hash[proto] = num+1

        #print proto_hash
        cap_hash[file] = proto_hash

    print cap_hash

if __name__ == "__main__":
    main()
