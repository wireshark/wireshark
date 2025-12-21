#!/usr/bin/env python
# ------------------------------------------------------------------------------------------------------------------
# list or check dependencies for binary distributions based on MSYS2 (requires the package mingw-w64-ntldd)
#
# run './msys2checkdeps.py --help' for usage information
# ------------------------------------------------------------------------------------------------------------------
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

from __future__ import print_function


import argparse
import os
import subprocess
import sys


SYSTEMROOT = os.environ['SYSTEMROOT']


class Dependency:
    def __init__(self):
        self.location = None
        self.dependents = set()


def warning(msg):
    print("Warning: " + msg, file=sys.stderr)


def error(msg):
    print("Error: " + msg, file=sys.stderr)
    exit(1)


def call_ntldd(filename):
    try:
        output = subprocess.check_output(['ntldd', '-R', filename], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        error("'ntldd' failed with '" + str(e) + "'")
    except WindowsError as e:
        error("Calling 'ntldd' failed with '" + str(e) + "' (have you installed 'mingw-w64-ntldd-git'?)")
    except Exception as e:
        error("Calling 'ntldd' failed with '" + str(e) + "'")
    return output.decode('utf-8')


def get_dependencies(filename, deps):
    raw_list = call_ntldd(filename)

    skip_indent = float('Inf')
    parents = {}
    parents[0] = os.path.basename(filename)
    for line in raw_list.splitlines():
        line = line[1:]
        indent = len(line) - len(line.lstrip())
        if indent > skip_indent:
            continue
        else:
            skip_indent = float('Inf')

        # if the dependency is not found in the working directory ntldd tries to find it on the search path
        # which is indicated by the string '=>' followed by the determined location or 'not found'
        if ('=>' in line):
            (lib, location) = line.lstrip().split(' => ')
            if location == 'not found':
                location = None
            else:
                location = location.rsplit('(', 1)[0].strip()
        else:
            lib = line.rsplit('(', 1)[0].strip()
            location = os.getcwd()

        parents[indent+1] = lib

        # we don't care about Microsoft libraries and their dependencies
        if location and SYSTEMROOT in location:
            skip_indent = indent
            continue

        if lib not in deps:
            deps[lib] = Dependency()
            deps[lib].location = location
        deps[lib].dependents.add(parents[indent])
    return deps


def collect_dependencies(path):
    # collect dependencies
    #   - each key in 'deps' will be the filename of a dependency
    #   - the corresponding value is an instance of class Dependency (containing full path and dependents)
    deps = {}
    if os.path.isfile(path):
        deps = get_dependencies(path, deps)
    elif os.path.isdir(path):
        extensions = ['.exe', '.pyd', '.dll']
        exclusions = ['distutils/command/wininst']  # python
        for base, dirs, files in os.walk(path):
            for f in files:
                filepath = os.path.join(base, f)
                (_, ext) = os.path.splitext(f)
                if (ext.lower() not in extensions) or any(exclusion in filepath for exclusion in exclusions):
                    continue
                deps = get_dependencies(filepath, deps)
    return deps


if __name__ == '__main__':
    modes = ['list', 'list-compact', 'check', 'check-missing', 'check-unused']

    # parse arguments from command line
    parser = argparse.ArgumentParser(description="List or check dependencies for binary distributions based on MSYS2.\n"
                                                 "(requires the package 'mingw-w64-ntldd')",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('mode', metavar="MODE", choices=modes,
                        help="One of the following:\n"
                             "  list          - list dependencies in human-readable form\n"
                             "                  with full path and list of dependents\n"
                             "  list-compact  - list dependencies in compact form (as a plain list of filenames)\n"
                             "  check         - check for missing or unused dependencies (see below for details)\n"
                             "  check-missing - check if all required dependencies are present in PATH\n"
                             "                  exits with error code 2 if missing dependencies are found\n"
                             "                  and prints the list to stderr\n"
                             "  check-unused  - check if any of the libraries in the root of PATH are unused\n"
                             "                  and prints the list to stderr")
    parser.add_argument('path', metavar='PATH',
                        help="full or relative path to a single file or a directory to work on\n"
                             "(directories will be checked recursively)")
    parser.add_argument('-w', '--working-directory', metavar="DIR",
                        help="Use custom working directory (instead of 'dirname PATH')")
    args = parser.parse_args()

    # check if path exists
    args.path = os.path.abspath(args.path)
    if not os.path.exists(args.path):
        error("Can't find file/folder '" + args.path + "'")

    # get root and set it as working directory (unless one is explicitly specified)
    if args.working_directory:
        root = os.path.abspath(args.working_directory)
    elif os.path.isdir(args.path):
        root = args.path
    elif os.path.isfile(args.path):
        root = os.path.dirname(args.path)
    os.chdir(root)

    # get dependencies for path recursively
    deps = collect_dependencies(args.path)

    # print output / prepare exit code
    exit_code = 0
    for dep in sorted(deps):
        location = deps[dep].location
        dependents = deps[dep].dependents

        if args.mode == 'list':
            if (location is None):
                location = '---MISSING---'
            print(dep + " - " + location + " (" + ", ".join(dependents) + ")")
        elif args.mode == 'list-compact':
            print(dep)
        elif args.mode in ['check', 'check-missing']:
            if ((location is None) or (root not in os.path.abspath(location))):
                warning("Missing dependency " + dep + " (" + ", ".join(dependents) + ")")
                exit_code = 2

    # check for unused libraries
    if args.mode in ['check', 'check-unused']:
        installed_libs = [file for file in os.listdir(root) if file.endswith(".dll")]
        deps_lower = [dep.lower() for dep in deps]
        top_level_libs = [lib for lib in installed_libs if lib.lower() not in deps_lower]
        for top_level_lib in top_level_libs:
            warning("Unused dependency " + top_level_lib)

    exit(exit_code)
