#!/usr/bin/env python
# Copyright (c) 2013 The Chromium Authors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""Makes sure that all files contain proper licensing information."""


import optparse
import os.path
import subprocess
import sys


def PrintUsage():
  print("""Usage: python checklicenses.py [--root <root>] [tocheck]
  --root   Specifies the repository root. This defaults to ".." relative
           to the script file. This will be correct given the normal location
           of the script in "<root>/tools".

  --ignore-suppressions  Ignores path-specific allowed license. Useful when
                         trying to remove a suppression/allowed entry.

  --list-allowed  Print a list of allowed licenses and exit.

  tocheck  Specifies the directory, relative to root, to check. This defaults
           to "." so it checks everything.

Examples:
  python checklicenses.py
  python checklicenses.py --root ~/chromium/src third_party""")


ALLOWED_LICENSES = [
    'BSD',
    'BSD (2 clause)',
    'BSD (2 clause) GPL (v2 or later)',
    'BSD (3 clause)',
    'GPL (v2 or later)',
    'GPL (v3 or later) (with Bison parser exception)',
    'ISC',
    'ISC GPL (v2 or later)',
    'LGPL (v2 or later)',
    'LGPL (v2.1 or later)',
    'MIT/X11 (BSD like)',
    'Public domain',
    'Public domain GPL (v2 or later)',
    'Public domain MIT/X11 (BSD like)',
    'zlib/libpng',
    'zlib/libpng GPL (v2 or later)',
]


PATH_SPECIFIC_ALLOWED_LICENSES = {
    'caputils/airpcap.h': [
        'BSD-3-Clause',
    ],
    'wsutil/strnatcmp.c': [
        'Zlib',
    ],
    'wsutil/strnatcmp.h': [
        'Zlib',
    ],
    'dtds': [
        'UNKNOWN',
    ],
    'diameter/dictionary.dtd': [
        'UNKNOWN',
    ],
    'wimaxasncp/dictionary.dtd': [
        'UNKNOWN',
    ],
    'doc/': [
        'UNKNOWN',
    ],
    'docbook/custom_layer_chm.xsl': [
        'UNKNOWN',
    ],
    'docbook/custom_layer_single_html.xsl': [
        'UNKNOWN',
    ],
    'docbook/ws.css' : [
        'UNKNOWN'
    ],
    'fix': [
        'UNKNOWN',
    ],
    'wsutil/g711.c': [
        'UNKNOWN',
    ],
    'packaging/macosx': [
        'UNKNOWN',
    ],
    'epan/except.c': [
        'UNKNOWN',
    ],
    'epan/except.h': [
        'UNKNOWN',
    ],
    'cmake/TestFileOffsetBits.c': [
        'UNKNOWN',
    ],
    # Generated header files by lex/yacc/whatever
    'epan/dtd_grammar.h': [
        'UNKNOWN',
    ],
    'epan/dfilter/grammar.h': [
        'UNKNOWN',
    ],
    'epan/dfilter/grammar.c': [
        'UNKNOWN',
    ],
    'epan/dissectors/packet-ieee80211-radiotap-iter.': [ # Using ISC license only
         'ISC GPL (v2)'
    ],
    'plugins/mate/mate_grammar.h': [
        'UNKNOWN',
    ],
    'version.h': [
        'UNKNOWN',
    ],
    # Special IDL license that appears to be compatible as far as I (not a
    # lawyer) can tell. See
    # https://www.wireshark.org/lists/wireshark-dev/201310/msg00234.html
    'epan/dissectors/pidl/idl_types.h': [
        'UNKNOWN',
    ],
    # Written by Ronnie Sahlberg and correctly licensed, but cannot include
    # a license header despite the file extension as they need to be
    # parsed by the pidl tool
    'epan/dissectors/pidl/mapi/request.cnf.c': [
        'UNKNOWN',
    ],
    'epan/dissectors/pidl/mapi/response.cnf.c': [
        'UNKNOWN',
    ],
    # The following tools are under incompatible licenses (mostly GPLv3 or
    # GPLv3+), but this is OK since they are not actually linked into Wireshark
    'tools/pidl': [
        'UNKNOWN',
    ],
    'tools/lemon': [
        'UNKNOWN',
    ],
    'tools/licensecheck.pl': [
        'GPL (v2)'
    ],
}

def check_licenses(options, args):
  if options.list_allowed:
    print('\n'.join(ALLOWED_LICENSES))
    sys.exit(0)

  # Figure out which directory we have to check.
  if len(args) == 0:
    # No directory to check specified, use the repository root.
    start_dir = options.base_directory
  elif len(args) == 1:
    # Directory specified. Start here. It's supposed to be relative to the
    # base directory.
    start_dir = os.path.abspath(os.path.join(options.base_directory, args[0]))
  else:
    # More than one argument, we don't handle this.
    PrintUsage()
    return 1

  print("Using base directory: %s" % options.base_directory)
  print("Checking: %s" % start_dir)
  print("")

  licensecheck_path = os.path.abspath(os.path.join(options.base_directory,
                                                    'tools',
                                                    'licensecheck.pl'))

  licensecheck = subprocess.Popen([licensecheck_path,
                                   '-l', '150',
                                   '-r', start_dir],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
  stdout, stderr = licensecheck.communicate()
  if sys.version_info[0] >= 3:
      stdout = stdout.decode('utf-8')
      stderr = stderr.decode('utf-8')
  if options.verbose:
    print('----------- licensecheck stdout -----------')
    print(stdout)
    print('--------- end licensecheck stdout ---------')
  if licensecheck.returncode != 0 or stderr:
    print('----------- licensecheck stderr -----------')
    print(stderr)
    print('--------- end licensecheck stderr ---------')
    print("\nFAILED\n")
    return 1

  success = True
  exit_status = 0
  for line in stdout.splitlines():
    filename, license = line.split(':', 1)
    filename = os.path.relpath(filename.strip(), options.base_directory)

    # All files in the build output directory are generated one way or another.
    # There's no need to check them.
    if filename.startswith('out/') or filename.startswith('sconsbuild/'):
      continue

    # For now we're just interested in the license.
    license = license.replace('*No copyright*', '').strip()

    # Skip generated files.
    if 'GENERATED FILE' in license:
      continue

    # Support files which provide a choice between licenses.
    if any(item in ALLOWED_LICENSES for item in license.split(';')):
      continue

    if not options.ignore_suppressions:
      found_path_specific = False
      for prefix in PATH_SPECIFIC_ALLOWED_LICENSES:
        if (filename.startswith(prefix) and
            license in PATH_SPECIFIC_ALLOWED_LICENSES[prefix]):
          found_path_specific = True
          break
      if found_path_specific:
        continue

    reason = "License '%s' for '%s' is not allowed." % (license, filename)
    success = False
    print(reason)
    exit_status = 1

  if success:
    print("\nSUCCESS\n")
    return 0
  else:
    print("\nFAILED\n")
    return exit_status


def main():
  default_root = os.path.abspath(
      os.path.join(os.path.dirname(__file__), '..'))
  option_parser = optparse.OptionParser()
  option_parser.add_option('--root', default=default_root,
                           dest='base_directory',
                           help='Specifies the repository root. This defaults '
                           'to "../.." relative to the script file, which '
                           'will normally be the repository root.')
  option_parser.add_option('-v', '--verbose', action='store_true',
                           default=False, help='Print debug logging')
  option_parser.add_option('--list-allowed',
                           action='store_true',
                           default=False,
                           help='Print a list of allowed licenses and exit.')
  option_parser.add_option('--ignore-suppressions',
                           action='store_true',
                           default=False,
                           help='Ignore path-specific allowed license.')
  options, args = option_parser.parse_args()
  return check_licenses(options, args)


if '__main__' == __name__:
  sys.exit(main())
