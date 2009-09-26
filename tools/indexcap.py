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
import multiprocessing
import sys
import os
import subprocess
import re
import pickle

def process_capture_file(tshark, file):
    try:
        cmd = [tshark, "-Tfields", "-e", "frame.protocols", "-r", file]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout, stderr) = p.communicate()
        if p.returncode != 0:
            return (file, {})

        proto_hash = {}
        for line in stdout.splitlines():
            if not re.match(r'^[\w:-]+$', line):
                continue

            for proto in line.split(':'):
                proto_hash[proto] = 1 + proto_hash.setdefault(proto, 0)

        return (file, proto_hash)
    except KeyboardInterrupt:
        return None

def list_all_proto(cap_hash):
    proto_hash = {}
    for files_hash in cap_hash.itervalues():
        for proto,count in files_hash.iteritems():
            proto_hash[proto] = count + proto_hash.setdefault(proto, 0)

    print proto_hash

def list_all_files(cap_hash):
    files = cap_hash.keys()
    files.sort()

    print files

def list_all_proto_files(cap_hash, proto_comma_delit):
    protos = [ x.strip() for x in proto_comma_delit.split(',') ]
    files = []
    for (file, files_hash) in cap_hash.iteritems():
        for proto in files_hash.iterkeys():
            if proto in protos:
                files.append(file)
                break

    print files

def index_file_action(options):
    return options.list_all_proto or \
           options.list_all_files or \
           options.list_all_proto_files

def find_capture_files(paths, cap_hash):
    cap_files = []
    for path in paths:
        if os.path.isdir(path):
            path = os.path.normpath(path)
            for root, dirs, files in os.walk(path):
                cap_files += [os.path.join(root, name) for name in files if os.path.join(root, name) not in cap_hash]
        elif path not in cap_hash:
            cap_files.append(path)
    return cap_files

def main():
    parser = OptionParser(usage="usage: %prog [options] index_file [file_1|dir_1 [.. file_n|dir_n]]")
    parser.add_option("-m", "--max-files", dest="max_files", default=sys.maxint, type="int", 
                      help="Max number of files to process")
    parser.add_option("-b", "--binary-dir", dest="bin_dir", default=os.getcwd(), 
                      help="Directory containing tshark executable")
    parser.add_option("-j", dest="num_procs", default=1, type=int, 
                      help="Max number of processes to spawn")
    parser.add_option("", "--list-all-proto", dest="list_all_proto", default=False, action="store_true", 
                      help="List all protocols in index file")
    parser.add_option("", "--list-all-files", dest="list_all_files", default=False, action="store_true", 
                      help="List all files in index file")
    parser.add_option("", "--list-all-proto-files", dest="list_all_proto_files", default=False,
                      metavar="PROTO_1[, .. PROTO_N]",
                      help="List all files in index file containing the given protocol")

    (options, args) = parser.parse_args()

    if len(args) == 0:
        parser.error("index_file is a required argument")

    if len(args) == 1 and not index_file_action(options):
        parser.error("one capture file/directory must be specified")

    index_file_name = args.pop(0)
    cap_hash = {}
    try:
        index_file = open(index_file_name, "r")
        print "index file:", index_file.name, "[OPENED]",
        cap_hash = pickle.load(index_file)
        index_file.close()
        print len(cap_hash), "files"
    except IOError:
        print "index file:", index_file_name, "[NEW]"

    if options.list_all_proto:
        list_all_proto(cap_hash)
        exit(0)

    if options.list_all_files:
        list_all_files(cap_hash)
        exit(0)

    if options.list_all_proto_files:
        list_all_proto_files(cap_hash, options.list_all_proto_files)
        exit(0)

    tshark = os.path.join(options.bin_dir, "tshark.exe")
    if os.access(tshark, os.X_OK):
        print "tshark:", tshark, "[FOUND]"
    else:
        print "tshark:", tshark, "[MISSING]"
        exit(1)

    paths = args
    cap_files = find_capture_files(paths, cap_hash)
    cap_files.sort()
    options.max_files = min(options.max_files, len(cap_files))
    print "%u total files, %u indexable files\n" % (len(cap_files), options.max_files)
    cap_files = cap_files[:options.max_files]

    pool = multiprocessing.Pool(options.num_procs)
    results = [pool.apply_async(process_capture_file, [tshark, file]) for file in cap_files]
    try:
        for (cur_item_idx,result) in enumerate(results):
            file_result = result.get()
            action = "SKIPPED" if file_result[1] is {} else "PROCESSED"
            print "%s [%u/%u] %s %u bytes" % (action, cur_item_idx+1, options.max_files, file_result[0], os.path.getsize(file_result[0]))
            cap_hash.update(dict([file_result]))
    except KeyboardInterrupt:
        print "%s was interrupted by user" % (sys.argv[0])
        pool.terminate()

    index_file = open(index_file_name, "w")
    pickle.dump(cap_hash, index_file)
    index_file.close()

if __name__ == "__main__":
    main()
