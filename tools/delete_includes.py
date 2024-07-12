#!/usr/bin/python3

# Martin Mathieson
# Look for and removes unnecessary includes in .cpp or .c files
# Run from wireshark source folder as e.g.,
#    ./tools/delete_includes.py --build-folder ~/wireshark-build/ --folder epan/dissectors/
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import subprocess
import os
import sys
import shutil
import argparse
import signal
from pathlib import Path


# Try to exit soon after Ctrl-C is pressed.
should_exit = False

def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)

# For text colouring/highlighting.
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    ADDED = '\033[45m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



# command-line args
#
# Controls which dissector files should be checked.  If no args given, will just
# scan whole epan/dissectors folder.
parser = argparse.ArgumentParser(description='Check calls in dissectors')
# required
parser.add_argument('--build-folder', action='store', required=True,
                    help='specify individual dissector file to test')
parser.add_argument('--file', action='append',
                    help='specify individual dissector file to test')
parser.add_argument('--folder', action='store', default=os.path.join('epan', 'dissectors'),
                    help='specify folder to test, relative to current/wireshark folder')
parser.add_argument('--commits', action='store',
                    help='last N commits to check')
parser.add_argument('--open', action='store_true',
                    help='check open files')
parser.add_argument('--first-file', action='store',
                    help='first file in folder to test')
parser.add_argument('--last-file', action='store',
                    help='last file in folder to test')
args = parser.parse_args()


test_folder = os.path.join(os.getcwd(), args.folder)


# Usually only building one module, so no -j benefit?
make_command = ['cmake', '--build', args.build_folder]
if sys.platform.startswith('win'):
    make_command += ['--config', 'RelWithDebInfo']



# A list of header files that it is not safe to uninclude, as doing so
# has been seen to cause link failures against implemented functions...
# TODO: some of these could probably be removed on more permissive platforms.
includes_to_keep = {
    'config.h',
    'epan/packet.h',
    'stdlib.h',
    'math.h',
    'errno.h',
    'string.h',
    'prefs.h',
    # These are probably mostly redundant in that they are now covered by the check
    # for 'self-includes'...
    'x11-keysym.h',
    'packet-atm.h',
    'packet-atalk.h',
    'packet-ppp.h',
    'packet-scsi-mmc.h',
    'packet-tls.h'
}


# Build stats.
class BuildStats:
    def __init__(self):
        self.files_examined = 0
        self.includes_tested = 0
        self.includes_deleted = 0
        self.files_not_built_list = []
        self.generated_files_ignored = []
        self.includes_to_keep_kept = 0

    def showSummary(self):
        print('\n\n')
        print('Summary')
        print('=========')
        print('files examined:   %d' %  self.files_examined)
        print('includes tested:  %d' %  self.includes_tested)
        print('includes deleted: %d' %  self.includes_deleted)
        print('files not built:  %d' %  len(self.files_not_built_list))
        for abandoned_file in self.files_not_built_list:
            print('     %s' % abandoned_file)
        print('generated files not tested: %d' % len(self.generated_files_ignored))
        for generated_file in self.generated_files_ignored:
            print('     %s' % generated_file)
        print('includes kept as not safe to remove: %d' % self.includes_to_keep_kept)

stats = BuildStats()


# We want to confirm that this file is actually built as part of the build.
# To do this, add some nonsense to the front of the file and confirm that the
# build then fails.  If it doesn't, won't want to remove #includes from that file!
def test_file_is_built(filename):
    print('test_file_is_built(', filename, ')')
    temp_filename = filename + '.tmp'

    f_read = open(filename, 'r')
    write_filename = filename + '.new'
    f_write = open(write_filename, 'w')
    # Write the file with nonsense at start.
    f_write.write('NO WAY THIS FILE BUILDS!!!!!')
    # Copy remaining lines as-is.
    for line in f_read:
        f_write.write(line)
    f_read.close()
    f_write.close()
    # Backup file, and do this build with the one we wrote.
    shutil.copy(filename, temp_filename)
    shutil.copy(write_filename, filename)

    # Try the build.
    result = subprocess.call(make_command)
    # Restore proper file & delete temp files
    shutil.copy(temp_filename, filename)
    os.remove(temp_filename)
    os.remove(write_filename)

    if result == 0:
        # Build succeeded so this file wasn't in it
        return False
    else:
        # Build failed so this file *is* part of it
        return True


# Function to test removal of each #include from a file in turn.
# At the end, only those that appear to be needed will be left.
def test_file(filename):
    global stats

    print('\n------------------------------')
    print(bcolors.OKBLUE, bcolors.BOLD, 'Testing', filename, bcolors.ENDC)

    temp_filename = filename + '.tmp'

    # Test if file seems to be part of the build.
    is_built = test_file_is_built(filename)
    if not is_built:
        print(bcolors.WARNING, '***** File not used in build, so ignore!!!!', bcolors.ENDC)
        # TODO: should os.path.join with root before adding?
        stats.files_not_built_list.append(filename)
        return
    else:
        print('This file is part of the build')

    # OK, we are going to test removing includes from this file.
    tested_line_number = 0

    # Don't want to delete 'self-includes', so prepare filename.
    module_name = Path(filename).stem
    module_header = module_name + '.h'

    # Loop around, finding all possible include lines to comment out
    while (True):
        if should_exit:
            exit(1)

        have_deleted_line = False
        result = 0

        # Open read & write files
        f_read = open(filename, 'r')
        write_filename = filename + '.new'
        f_write = open(write_filename, 'w')

        # Walk the file again looking for another place to comment out an include
        this_line_number = 1
        hash_if_level = 0

        for line in f_read:
            this_line_deleted = False

            # Maintain view of how many #if or #ifdefs we are in.
            # Don't want to remove any includes that may not be active in this build.
            if line.startswith('#if'):
                hash_if_level = hash_if_level + 1

            if line.startswith('#endif'):
                if hash_if_level > 1:
                    hash_if_level = hash_if_level - 1

            # Consider deleting this line have haven't already reached.
            if (not have_deleted_line and (tested_line_number < this_line_number)):

                # Test line for starting with #include, and eligible for deletion.
                if line.startswith('#include ') and hash_if_level == 0 and line.find(module_header) == -1:
                    # Check that this isn't a header file that known unsafe to uninclude.
                    allowed_to_delete = True
                    for entry in includes_to_keep:
                        if line.find(entry) != -1:
                            allowed_to_delete = False
                            stats.includes_to_keep_kept += 1
                            continue

                    if allowed_to_delete:
                        # OK, actually doing it.
                        have_deleted_line = True
                        this_line_deleted = True
                        tested_line_number = this_line_number

            # Write line to output file, unless this very one was deleted.
            if not this_line_deleted:
                f_write.write(line)
                this_line_number = this_line_number + 1

        # Close both files.
        f_read.close()
        f_write.close()

        # If we commented out a line, try to build file without it.
        if (have_deleted_line):
            # Test a build.  0 means success, others are failures.
            shutil.copy(filename, temp_filename)
            shutil.copy(write_filename, filename)

            # Try build
            result = subprocess.call(make_command)
            if result == 0:
                print(bcolors.OKGREEN +bcolors.BOLD + 'Good build' + bcolors.ENDC)
                # Line was eliminated so decrement line counter
                tested_line_number = tested_line_number - 1
                # Inc successes counter
                stats.includes_deleted += 1
                # Good - promote this version by leaving it here!

                # Occasionally fails so delete this file each time.
                # TODO: this is very particular to dissector target...
                if sys.argv[1] == 'dissectors':
                    os.remove(os.path.join(args.build_folder, 'vc100.pdb'))
            else:
                print(bcolors.FAIL +bcolors.BOLD + 'Bad build' + bcolors.ENDC)
                # Never mind, go back to previous building version
                shutil.copy(temp_filename, filename)

            # Inc counter of tried
            stats.includes_tested += 1

        else:
            # Reached the end of the file without making changes, so nothing doing.
            # Delete temporary files
            if os.path.isfile(temp_filename):
                os.remove(temp_filename)
            if os.path.isfile(write_filename):
                os.remove(write_filename)
            return

# Test for whether a the given file is under source control
def under_version_control(filename):
    # TODO: git command to see if under version control. Check retcode of 'git log <filename>' ?
    return True

# Test for whether the given file was automatically generated.
def generated_file(filename):
    # Special known case.
    if filename == 'register.c':
        return True

    # Open file
    f_read = open(filename, 'r')
    lines_tested = 0
    for line in f_read:
        # The comment to say that its generated is near the top, so give up once
        # get a few lines down.
        if lines_tested > 10:
            f_read.close()
            return False
        if (line.find('Generated automatically') != -1 or
            line.find('Generated Automatically') != -1 or
            line.find('Autogenerated from') != -1 or
            line.find('is autogenerated') != -1 or
            line.find('automatically generated by Pidl') != -1 or
            line.find('Created by: The Qt Meta Object Compiler') != -1 or
            line.find('This file was generated') != -1 or
            line.find('This filter was automatically generated') != -1 or
            line.find('This file is auto generated, do not edit!') != -1):

            f_read.close()
            return True
        lines_tested = lines_tested + 1

    # OK, looks like a hand-written file!
    f_read.close()
    return False

def isBuildableFile(filename):
    return filename.endswith('.c') or filename.endswith('.cpp')


def findFilesInFolder(folder, recursive=False):
    dissector_files = []

    if recursive:
        for root, subfolders, files in os.walk(folder):
            for f in files:
                if should_exit:
                    return
                f = os.path.join(root, f)
                dissector_files.append(f)
    else:
        for f in sorted(os.listdir(folder)):
            if should_exit:
                return
            filename = os.path.join(folder, f)
            dissector_files.append(filename)

    return [x for x in filter(isBuildableFile, dissector_files)]


######################################################################################
# MAIN PROGRAM STARTS HERE
######################################################################################

# Work out which files we want to look at.
files = []
if args.file:
    # Add specified file(s)
    for f in args.file:
        if not os.path.isfile(f):
            print('Chosen file', f, 'does not exist.')
            exit(1)
        else:
            files.append(f)
elif args.folder:
    # Add all files from a given folder.
    folder = args.folder
    if not os.path.isdir(folder):
        print('Folder', folder, 'not found!')
        exit(1)
    # Find files from folder.
    print('Looking for files in', folder)
    files = findFilesInFolder(folder, recursive=False)


# If first-file/last-file are given, will need to trim files accordingly
if args.first_file:
    idx = files.index(args.first_file)
    if idx == -1:
        print('first-file entry', args.first_file, 'not in list of files to be checked')
        exit(1)
    else:
        files = files[idx:]

if args.last_file:
    idx = files.index(args.last_file)
    if idx == -1:
        print('last-file entry', args.last_file, 'not in list of files to be checked')
        exit(1)
    else:
        files = files[:idx+1]


# Confirm that the build is currently passing, if not give up now.
print(bcolors.OKBLUE,bcolors.BOLD,
      'Doing an initial build to check we have a stable base.',
      bcolors.ENDC)
result = subprocess.call(make_command)
if result != 0:
    print(bcolors.FAIL, bcolors.BOLD, 'Initial build failed - give up now!!!!', bcolors.ENDC)
    exit (-1)



# Test each file.
for filename in files:

    # Want to filter out generated files that are not checked in.
    if not generated_file(filename) and under_version_control(filename):
        # OK, try this file
        test_file(filename)

        # Inc counter
        stats.files_examined += 1
    else:
        if generated_file(filename):
            reason = 'generated file...'
        if not under_version_control(filename):
            reason = 'not under source control'
        print('Ignoring %s: %s' % (filename, reason))



# Show summary stats of run
stats.showSummary()
