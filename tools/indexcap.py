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
from multiprocessing import Process, Pool
import sys
import os
import subprocess
import re
import pickle

def process_capture_file(args):
    tshark, file = args
    cmd = [tshark, "-Tfields", "-e", "frame.protocols", "-r", file]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout, stderr) = p.communicate()
    if p.returncode != 0:
        print "SKIP:", file
    else:
        print "PROCESSED:", file

    proto_hash = {}
    for line in stdout.splitlines():
        if not re.match(r'^[\w:-]+$', line):
            continue

        for proto in line.split(':'):
            num = proto_hash.setdefault(proto, 0)
            proto_hash[proto] = num+1

    return (file, proto_hash)

def main():
    parser = OptionParser(usage="usage: %prog [options] index_file file_1|dir_1 [.. file_n|dir_n]")
    parser.add_option("-n", "--no-append", dest="append", default=True, action="store_false", help="Do not append to existing cache file")
    parser.add_option("-m", "--max-files", dest="max_files", default=sys.maxint, type="int", help="Max number of files to process")
    parser.add_option("-b", "--binary-dir", dest="bin_dir", default=os.getcwd(), help="Directory containing tshark executable")
    parser.add_option("-j", dest="num_procs", default=1, type=int, help="Max number of processes to spawn")

    (options, args) = parser.parse_args()

    if len(args) == 0:
        parser.error("index_file is a required argument")

    if len(args) == 1:
        parser.error("one capture file/directory must be specified")

    tshark = os.path.join(options.bin_dir, "tshark.exe")
    if os.access(tshark, os.X_OK):
        print "tshark:", tshark, "[FOUND]"
    else:
        print "tshark:", tshark, "[MISSING]"
        exit(1)

    index_file_name = args.pop(0)
    index_file = open(index_file_name, "r")
    print "index_file:", index_file.name, "[OPENED]",

    try:
        cap_hash = pickle.load(index_file)
        print "[REUSING]"
    except IOError:
        cap_hash = {}
        print "[NEW]"
    finally:
        index_file.close()

    paths = args
    cap_files = []
    for path in paths:
        if os.path.isdir(path):
            path = os.path.normpath(path)
            for root, dirs, files in os.walk(path):
                cap_files += [os.path.join(root, name) for name in files if os.path.join(root, name) not in cap_hash]
        elif path not in cap_hash:
            cap_files.append(path)

    cap_files.sort()
    cap_files = cap_files[:options.max_files]

    pool = Pool(options.num_procs)
    proc_args = [(tshark, file) for file in cap_files]
    results = pool.map(process_capture_file, proc_args)
    cap_hash = dict(results)

    print cap_hash
    index_file = open(index_file_name, "a")
    pickle.dump(cap_hash, index_file)
    index_file.close()

if __name__ == "__main__":
    main()
