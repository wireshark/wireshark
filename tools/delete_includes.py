#!/usr/bin/python

# Martin Mathieson
# Look for and removes unnecessary includes in .cpp or .c files
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

def show_usage():
    print('Usage:   ./delete_includes.py <dissectors | wsutil | wiretap | ui | qt | plugins > [start_file] [stop_file]')


# Work out wireshark folder based upon CWD.  Assume run in wireshark folder
# or from tools folder...
wireshark_root = os.getcwd()
root,lastdir = os.path.split(wireshark_root)
if lastdir == 'tools':
    wireshark_root = root

# Make command depends upon platform.
if sys.platform.startswith('win'):
    default_make_command = ['msbuild', '/m', '/p:Configuration=RelWithDebInfo', 'Wireshark.sln']
else:
    default_make_command = ['make']


# Set parameters based upon string passed as argument.
if len(sys.argv) > 1:
    if sys.argv[1] == 'dissectors':
        print('dissectors target chosen!')
        test_folder = os.path.join(wireshark_root, 'epan', 'dissectors')
        run_folder = test_folder
        make_command = default_make_command
    elif sys.argv[1] == 'wsutil':
        print('wsutils target chosen!')
        test_folder = os.path.join(wireshark_root, 'wsutil')
        run_folder = test_folder
        make_command = default_make_command
    elif sys.argv[1] == 'wiretap':
        print('wiretap target chosen!')
        test_folder = os.path.join(wireshark_root, 'wiretap')
        run_folder = test_folder
        make_command = default_make_command
    elif sys.argv[1] == 'ui':
        print('ui target chosen!')
        test_folder = os.path.join(wireshark_root, 'ui')
        run_folder = wireshark_root
        make_command = default_make_command
    elif sys.argv[1] == 'qt':
        print('qt target chosen!')
        test_folder = os.path.join(wireshark_root, 'ui', 'qt')
        run_folder = wireshark_root
        default_make_command.append('qt')
        make_command = default_make_command
    elif sys.argv[1] == 'plugins':
        print('plugins target chosen!')
        test_folder = os.path.join(wireshark_root, 'plugins')
        run_folder = os.path.join(wireshark_root, 'plugins')
        make_command = default_make_command
    else:
        print('Unrecognised command line option %s' % sys.argv[1])
        show_usage()
        sys.exit()
else:
    # Print usage and bug out!
    show_usage()
    sys.exit()

# i.e. not looking for a first file to begin testing, and haven't found last one yet.
first_file_found = True
last_file_found = False

# Optional 2nd arg gives first filename to use. Useful for long runs that may
# sometimes be stopped early
if len(sys.argv) > 2:
    first_file_to_test = sys.argv[2]
    first_file_found = False

# Optional 3rd arg gives last filename to use. Useful for long runs that may
# sometimes be stopped early
last_file_to_test = ''
if len(sys.argv) > 3:
    last_file_to_test = sys.argv[3]



# A list of header files that it is not safe to uninclude, as doing so
# has been seen to cause link failures against implemented functions...
# TODO: some of these could probably be removed on more permissive platforms.
includes_to_keep = []
includes_to_keep.append('config.h')
includes_to_keep.append('epan/packet.h')
includes_to_keep.append('stdlib.h')
includes_to_keep.append('math.h')
includes_to_keep.append('errno.h')
includes_to_keep.append('string.h')
# These are probably mostly redundant in that they are now covered by the check
# for 'self-includes'...
includes_to_keep.append('x11-keysym.h')
includes_to_keep.append('packet-dcom-dispatch.h')
includes_to_keep.append('packet-ax25.h')
includes_to_keep.append('packet-atm.h')
includes_to_keep.append('packet-atalk.h')
includes_to_keep.append('packet-ppp.h')
includes_to_keep.append('packet-scsi-mmc.h')
includes_to_keep.append('packet-t30.h')
includes_to_keep.append('packet-tls.h')



# Stats
files_examined = 0
includes_tested = 0
includes_deleted = 0
files_not_built = 0
files_not_built_list = []
generated_files_ignored = []
skipped_before_first = 0
includes_to_keep_kept = 0

# We want to confirm that this file is actually built as part of the make target.
# To do this, add some garbage to the front of the file and confirm that the
# build then fails.  If it doesn't, won't want to remove #includes from that file!
def test_file_is_built(root, filename):
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
    os.chdir(run_folder)
    result = subprocess.call(make_command)
    # Restore proper file & delete temp files
    os.chdir(root)
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
def test_file(root, filename):

    print('')
    print('------------------------------')
    print('Testing %s' % filename)

    temp_filename = filename + '.tmp'

    # Test if file seems to be part of the build.
    is_built = test_file_is_built(root, filename)
    if not is_built:
        print('***** File not used in build, so ignore!!!!')
        global files_not_built
        global files_not_built_list
        files_not_built = files_not_built + 1
        # TODO: should os.path.join with root before adding?
        files_not_built_list.append(filename)
        return
    else:
        print('This file is part of the build')

    # OK, we are going to test removing includes from this file.
    tested_line_number = 0

    # Don't want to delete 'self-includes', so prepare filename.
    module_name,extension = os.path.splitext(filename)
    module_header = module_name + '.h'

    # Loop around, finding all possible include lines to comment out
    while (True):
        have_deleted_line = False
        result = 0

        # Go into folder
        os.chdir(root)

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
                    global includes_to_keep
                    for entry in includes_to_keep:
                        if line.find(entry) != -1:
                            allowed_to_delete = False
                            global includes_to_keep_kept
                            includes_to_keep_kept = includes_to_keep_kept + 1
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

            # Assuming Makefile is in root of test folder, need to go there to do make!
            os.chdir(run_folder)
            result = subprocess.call(make_command)
            if result == 0:
                print('***** Good build')
                # Line was eliminated so decrement line counter
                tested_line_number = tested_line_number - 1
                # Inc successes counter
                global includes_deleted
                includes_deleted = includes_deleted + 1
                # Good - promote this version by leaving it here!

                # Occasionally fails so delete this file each time.
                # TODO: this is very particular to dissector target...
                if sys.argv[1] == 'dissectors':
                    os.remove(os.path.join(run_folder, 'vc100.pdb'))
            else:
                print('***** Bad build')
                # Never mind, go back to previous building version
                os.chdir(root)
                shutil.copy(temp_filename, filename)

            # Inc counter of tried
            global includes_tested
            includes_tested = includes_tested + 1

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
    # TODO: is there a git module to allow testing like pysvn?  Else actually
    # shell out command-line 'git' and check output...?
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
        if line.find('Generated automatically') != -1 or line.find('Autogenerated from') != -1 or line.find('is autogenerated') != -1 or line.find('automatically generated by Pidl') != -1 or line.find('Created by: The Qt Meta Object Compiler') != -1:
            f_read.close()
            # This file was generated.
            global generated_files_ignored
            generated_files_ignored.append(filename)
            return True
        lines_tested = lines_tested + 1

    # OK, looks like a hand-written file!
    f_read.close()
    return False


######################################################################################
# MAIN PROGRAM STARTS HERE
######################################################################################

# First, confirm that the build is currently passing, if not give up now.
print('chdir into %s' % run_folder)
os.chdir(run_folder)
print('***** Doing an initial build to check we have a stable base.')
result = subprocess.call(make_command)
if result != 0:
    print('***** Initial build failed - give up now!!!!')
    exit (-1)

# OK, loop over files in test_folder and see what can be removed from each one
for root, subFolders, files in os.walk(test_folder):
    for filename in files:
        # Don't look for source files in folders containing a . (i.e. avoid .svn, .git)
        if (root.find('.') == -1):
            # Only looking for c/cpp files - changing header files would make each
            # attempted build take much longer
            if filename.endswith(".c") or filename.endswith(".cpp"):
                os.chdir(root)

                # May be waiting for first file to test - check.
                if not first_file_found:
                    if first_file_to_test == filename:
                        first_file_found = True

                # May be waiting for last file to test - check.
                if not last_file_found:
                    if last_file_to_test == filename:
                        last_file_found = True

                # Also want to filter out generated files that are not checked in.
                if not generated_file(filename) and under_version_control(filename) and first_file_found and not last_file_found:
                    # OK, try this file
                    test_file(root, filename)

                    # Inc counter
                    files_examined = files_examined + 1
                else:
                    if generated_file(filename):
                        reason = 'generated file...'
                    if not under_version_control(filename):
                        reason = 'not under source control'
                    if not first_file_found:
                        reason = 'not seen starting file', first_file_to_test, 'yet'
                        skipped_before_first = skipped_before_first + 1
                    print('Ignoring %s: %s' % (filename, reason))


# Show summary stats of run
print('\n\n')
print('Summary')
print('=========')
print('files examined:   %d' %  files_examined)
print('includes tested:  %d' %  includes_tested)
print('includes deleted: %d' %  includes_deleted)
print('files not built:  %d' %  files_not_built)
for abandoned_file in files_not_built_list:
    print('     %s' % abandoned_file)
print('%d generated files not tested:' % len(generated_files_ignored))
for generated_file in generated_files_ignored:
    print('     %s' % generated_file)
print('includes kept as not safe to remove: %d' % includes_to_keep_kept)
print('skipped before first: %d' % skipped_before_first)

