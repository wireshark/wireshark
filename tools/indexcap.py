#!/usr/bin/python
#
# Tool to index protocols that appears in the given capture files
#
# The script list_protos_in_cap.sh does the same thing.
#
# Copyright 2009, Kovarththanan Rajaratnam <kovarththanan.rajaratnam@gmail.com>
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
#

from optparse import OptionParser
import multiprocessing
import sys
import os
import subprocess
import re
import pickle
import tempfile
import filecmp
import random

def extract_protos_from_file_proces(tshark, file):
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

def extract_protos_from_file(tshark, num_procs, max_files, cap_files, cap_hash, index_file_name):
    pool = multiprocessing.Pool(num_procs)
    results = [pool.apply_async(extract_protos_from_file_proces, [tshark, file]) for file in cap_files]
    try:
        for (cur_item_idx,result_async) in enumerate(results):
            file_result = result_async.get()
            action = "SKIPPED" if file_result[1] is {} else "PROCESSED"
            print "%s [%u/%u] %s %u bytes" % (action, cur_item_idx+1, max_files, file_result[0], os.path.getsize(file_result[0]))
            cap_hash.update(dict([file_result]))
    except KeyboardInterrupt:
        print "%s was interrupted by user" % (sys.argv[0])
        pool.terminate()
        exit(1)

    index_file = open(index_file_name, "w")
    pickle.dump(cap_hash, index_file)
    index_file.close()
    exit(0)

def dissect_file_process(tshark, tmpdir, file):
    try:
        (handle_o, tmpfile_o) = tempfile.mkstemp(suffix='_stdout', dir=tmpdir)
        (handle_e, tmpfile_e) = tempfile.mkstemp(suffix='_stderr', dir=tmpdir)
        cmd = [tshark, "-nxVr", file]
        p = subprocess.Popen(cmd, stdout=handle_o, stderr=handle_e)
        (stdout, stderr) = p.communicate()
        if p.returncode == 0:
            return (file, True, tmpfile_o, tmpfile_e)
        else:
            return (file, False, tmpfile_o, tmpfile_e)

    except KeyboardInterrupt:
        return False

    finally:
        os.close(handle_o)
        os.close(handle_e)

def dissect_files(tshark, tmpdir, num_procs, max_files, cap_files):
    pool = multiprocessing.Pool(num_procs)
    results = [pool.apply_async(dissect_file_process, [tshark, tmpdir, file]) for file in cap_files]
    try:
        for (cur_item_idx,result_async) in enumerate(results):
            file_result = result_async.get()
            action = "FAILED" if file_result[1] is False else "PASSED"
            print "%s [%u/%u] %s %u bytes" % (action, cur_item_idx+1, max_files, file_result[0], os.path.getsize(file_result[0]))
    except KeyboardInterrupt:
        print "%s was interrupted by user" % (sys.argv[0])
        pool.terminate()
        exit(1)

def compare_files(tshark_bin, tmpdir, tshark_cmp, num_procs, max_files, cap_files):
    pool = multiprocessing.Pool(num_procs)
    results_bin = [pool.apply_async(dissect_file_process, [tshark_bin, tmpdir, file]) for file in cap_files]
    results_cmp = [pool.apply_async(dissect_file_process, [tshark_cmp, tmpdir, file]) for file in cap_files]
    try:
        for (cur_item_idx,(result_async_bin, result_async_cmp)) in enumerate(zip(results_bin, results_cmp)):
            file_result_bin = result_async_bin.get()
            file_result_cmp = result_async_cmp.get()
            if file_result_cmp[1] is False or file_result_bin[1] is False:
                action = "FAILED (exitcode)"
            if not filecmp.cmp(file_result_bin[2], file_result_cmp[2]):
                action = "FAILED (stdout)"
            if not filecmp.cmp(file_result_bin[3], file_result_cmp[3]):
                action = "FAILED (stderr)"
            else:
                action = "PASSED"
                os.remove(file_result_bin[2])
                os.remove(file_result_cmp[2])
                os.remove(file_result_bin[3])
                os.remove(file_result_cmp[3])

            print "%s [%u/%u] %s %u bytes" % (action, cur_item_idx+1, max_files, file_result_bin[0], os.path.getsize(file_result_bin[0]))
            print "%s [%u/%u] %s %u bytes" % (action, cur_item_idx+1, max_files, file_result_cmp[0], os.path.getsize(file_result_cmp[0]))
    except KeyboardInterrupt:
        print "%s was interrupted by user" % (sys.argv[0])
        pool.terminate()
        exit(1)

def list_all_proto(cap_hash):
    proto_hash = {}
    for files_hash in cap_hash.itervalues():
        for proto,count in files_hash.iteritems():
            proto_hash[proto] = count + proto_hash.setdefault(proto, 0)

    return proto_hash

def list_all_files(cap_hash):
    files = cap_hash.keys()
    files.sort()

    return files

def list_all_proto_files(cap_hash, proto_comma_delit):
    protos = [ x.strip() for x in proto_comma_delit.split(',') ]
    files = []
    for (file, files_hash) in cap_hash.iteritems():
        for proto in files_hash.iterkeys():
            if proto in protos:
                files.append(file)
                break

    return files

def index_file_action(options):
    return options.list_all_proto or \
           options.list_all_files or \
           options.list_all_proto_files or \
           options.dissect_files

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

def find_tshark_executable(bin_dir):
    for file in ["tshark.exe", "tshark"]:
        tshark = os.path.join(bin_dir, file)
        if os.access(tshark, os.X_OK):
            return tshark

    return None

def main():
    parser = OptionParser(usage="usage: %prog [options] index_file [file_1|dir_1 [.. file_n|dir_n]]")
    parser.add_option("-d", "--dissect-files", dest="dissect_files", default=False, action="store_true",
                      help="Dissect all matching files")
    parser.add_option("-m", "--max-files", dest="max_files", default=sys.maxint, type="int",
                      help="Max number of files to process")
    parser.add_option("-b", "--binary-dir", dest="bin_dir", default=os.getcwd(),
                      help="Directory containing tshark executable")
    parser.add_option("-c", "--compare-dir", dest="compare_dir", default=None,
                      help="Directory containing tshark executable which is used for comparison")
    parser.add_option("-j", dest="num_procs", default=multiprocessing.cpu_count(), type=int,
                      help="Max number of processes to spawn")
    parser.add_option("-r", "--randomize", default=False, action="store_true",
                      help="Randomize the file list order")
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

    if options.dissect_files and not options.list_all_files and not options.list_all_proto_files:
        parser.error("--list-all-files or --list-all-proto-files must be specified")

    if options.dissect_files and not options.compare_dir is None:
        parser.error("--dissect-files and --compare-dir cannot be specified at the same time")

    index_file_name = args.pop(0)
    paths = args
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
        print list_all_proto(cap_hash)
        exit(0)

    indexed_files = []
    if options.list_all_files:
        indexed_files = list_all_files(cap_hash)
        print indexed_files

    if options.list_all_proto_files:
        indexed_files = list_all_proto_files(cap_hash, options.list_all_proto_files)
        print indexed_files

    tshark_bin = find_tshark_executable(options.bin_dir)
    if not tshark_bin is None:
        print "tshark:", tshark_bin, "[FOUND]"
    else:
        print "tshark:", tshark_bin, "[MISSING]"
        exit(1)

    if not options.compare_dir is None:
        tshark_cmp = find_tshark_executable(options.compare_dir)
        if not tshark_cmp is None:
            print "tshark:", tshark_cmp, "[FOUND]"
        else:
            print "tshark:", tshark_cmp, "[MISSING]"
            exit(1)

    if options.dissect_files or options.compare_dir:
        cap_files = indexed_files
    elif options.list_all_proto_files or options.list_all_files:
        exit(0)
    else:
        cap_files = find_capture_files(paths, cap_hash)

    if options.randomize:
        random.shuffle(cap_files)
    else:
        cap_files.sort()

    options.max_files = min(options.max_files, len(cap_files))
    print "%u total files, %u working files" % (len(cap_files), options.max_files)
    cap_files = cap_files[:options.max_files]
    tmpdir = tempfile.mkdtemp()
    print "Temporary working dir: %s" % tmpdir

    if options.compare_dir:
        compare_files(tshark_bin, tmpdir, tshark_cmp, options.num_procs, options.max_files, cap_files)
    elif options.dissect_files:
        dissect_files(tshark_bin, tmpdir, options.num_procs, options.max_files, cap_files)
    else:
        extract_protos_from_file(tshark_bin, options.num_procs, options.max_files, cap_files, cap_hash, index_file_name)

    os.rmdir(tmpdir)
if __name__ == "__main__":
    main()
