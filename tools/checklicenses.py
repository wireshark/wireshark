#!/usr/bin/env python
# Copyright (c) 2013 The Chromium Authors. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#    * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#    * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Makes sure that all files contain proper licensing information."""


import optparse
import os.path
import subprocess
import sys


def PrintUsage():
  print """Usage: python checklicenses.py [--root <root>] [tocheck]
  --root   Specifies the repository root. This defaults to ".." relative
           to the script file. This will be correct given the normal location
           of the script in "<root>/tools".

  --ignore-suppressions  Ignores path-specific license whitelist. Useful when
                         trying to remove a suppression/whitelist entry.

  tocheck  Specifies the directory, relative to root, to check. This defaults
           to "." so it checks everything.

Examples:
  python checklicenses.py
  python checklicenses.py --root ~/chromium/src third_party"""


WHITELISTED_LICENSES = [
    'Apache (v2.0)',
    'Apache (v2.0) BSD (2 clause)',
    'Apache (v2.0) GPL (v2)',
    'Apple MIT',  # https://fedoraproject.org/wiki/Licensing/Apple_MIT_License
    'APSL (v2)',
    'APSL (v2) BSD (4 clause)',
    'BSD',
    'BSD (2 clause)',
    'BSD (2 clause) MIT/X11 (BSD like)',
    'BSD (3 clause)',
    'BSD (3 clause) ISC',
    'BSD (3 clause) LGPL (v2 or later)',
    'BSD (3 clause) LGPL (v2.1 or later)',
    'BSD (3 clause) MIT/X11 (BSD like)',
    'BSD (4 clause)',
    'BSD-like',

    # TODO(phajdan.jr): Make licensecheck not print BSD-like twice.
    'BSD-like MIT/X11 (BSD like)',

    'BSL (v1.0)',
    'GPL (v2 or later)',
    'GPL (v2 or later) with Bison parser exception',
    'GPL (v2 or later) with libtool exception',
    'GPL (v3 or later) with Bison parser exception',
    'GPL with Bison parser exception',
    'ISC',
    'LGPL',
    'LGPL (v2)',
    'LGPL (v2 or later)',
    'LGPL (v2.1)',
    'LGPL (v3 or later)',

    # TODO(phajdan.jr): Make licensecheck convert that comma to a dot.
    'LGPL (v2,1 or later)',

    'LGPL (v2.1 or later)',
    'MPL (v1.0) LGPL (v2 or later)',
    'MPL (v1.1)',
    'MPL (v1.1) BSD-like',
    'MPL (v1.1) BSD-like GPL (unversioned/unknown version)',
    'MPL (v1.1,) BSD (3 clause) GPL (unversioned/unknown version) '
        'LGPL (v2.1 or later)',
    'MPL (v1.1) GPL (unversioned/unknown version)',
    'MPL (v2.0)',

    # TODO(phajdan.jr): Make licensecheck not print the comma after 1.1.
    'MPL (v1.1,) GPL (unversioned/unknown version) LGPL (v2 or later)',
    'MPL (v1.1,) GPL (unversioned/unknown version) LGPL (v2.1 or later)',

    'MIT/X11 (BSD like)',
    'Ms-PL',
    'Public domain',
    'Public domain BSD',
    'Public domain BSD (3 clause)',
    'Public domain BSD-like',
    'Public domain LGPL (v2.1 or later)',
    'libpng',
    'zlib/libpng',
    'SGI Free Software License B',
    'University of Illinois/NCSA Open Source License (BSD like)',
]


PATH_SPECIFIC_WHITELISTED_LICENSES = {
    'base/hash.cc': [  # http://crbug.com/98100
        'UNKNOWN',
    ],
    'base/third_party/icu': [  # http://crbug.com/98087
        'UNKNOWN',
    ],

    # http://code.google.com/p/google-breakpad/issues/detail?id=450
    'breakpad/src': [
        'UNKNOWN',
    ],

    'chrome/common/extensions/docs/examples': [  # http://crbug.com/98092
        'UNKNOWN',
    ],
    'chrome/test/data/gpu/vt': [
        'UNKNOWN',
    ],
    'chrome/test/data/layout_tests/LayoutTests': [
        'UNKNOWN',
    ],
    'courgette/third_party/bsdiff_create.cc': [  # http://crbug.com/98095
        'UNKNOWN',
    ],
    'data/mozilla_js_tests': [
        'UNKNOWN',
    ],
    'data/page_cycler': [
        'UNKNOWN',
        'GPL (v2 or later)',
    ],
    'data/tab_switching': [
        'UNKNOWN',
    ],
    'googleurl': [  # http://code.google.com/p/google-url/issues/detail?id=15
        'UNKNOWN',
    ],

    'native_client': [  # http://crbug.com/98099
        'UNKNOWN',
    ],
    'native_client/toolchain': [
        'BSD GPL (v2 or later)',
        'BSD (2 clause) GPL (v2 or later)',
        'BSD (3 clause) GPL (v2 or later)',
        'BSL (v1.0) GPL',
        'BSL (v1.0) GPL (v3.1)',
        'GPL',
        'GPL (unversioned/unknown version)',
        'GPL (v2)',
        'GPL (v2 or later)',
        'GPL (v3.1)',
        'GPL (v3 or later)',
    ],
    'net/tools/spdyshark': [
        'GPL (v2 or later)',
        'UNKNOWN',
    ],
    'third_party/WebKit': [
        'UNKNOWN',
    ],
    'third_party/WebKit/Websites/webkit.org/blog/wp-content/plugins/'
        'akismet/akismet.php': [
        'GPL (v2 or later)'
    ],
    'third_party/WebKit/Source/JavaScriptCore/tests/mozilla': [
        'GPL',
        'GPL (v2 or later)',
        'GPL (unversioned/unknown version)',
    ],
    'third_party/active_doc': [  # http://crbug.com/98113
        'UNKNOWN',
    ],

    # http://code.google.com/p/angleproject/issues/detail?id=217
    'third_party/angle': [
        'UNKNOWN',
    ],

    'third_party/bsdiff/mbsdiff.cc': [
        'UNKNOWN',
    ],
    'third_party/bzip2': [
        'UNKNOWN',
    ],

    # http://crbug.com/222828
    # http://bugs.python.org/issue17514
    'third_party/chromite/third_party/argparse.py': [
        'UNKNOWN',
    ],

    # Not used. http://crbug.com/156020
    # Using third_party/cros_dbus_cplusplus/cros_dbus_cplusplus.gyp instead.
    'third_party/cros_dbus_cplusplus/source/autogen.sh': [
        'UNKNOWN',
    ],
    # Included in the source tree but not built. http://crbug.com/156020
    'third_party/cros_dbus_cplusplus/source/examples': [
        'UNKNOWN',
    ],
    'third_party/devscripts': [
        'GPL (v2 or later)',
    ],
    'third_party/expat/files/lib': [  # http://crbug.com/98121
        'UNKNOWN',
    ],
    'third_party/ffmpeg': [
        'GPL',
        'GPL (v2)',
        'GPL (v2 or later)',
        'UNKNOWN',  # http://crbug.com/98123
    ],
    'third_party/findbugs/doc': [ # http://crbug.com/157206
        'UNKNOWN',
    ],
    'third_party/freetype2': [ # http://crbug.com/177319
        'UNKNOWN',
    ],
    'third_party/gles2_book': [  # http://crbug.com/98130
        'UNKNOWN',
    ],
    'third_party/gles2_conform/GTF_ES': [  # http://crbug.com/98131
        'UNKNOWN',
    ],
    'third_party/harfbuzz': [  # http://crbug.com/98133
        'UNKNOWN',
    ],
    'third_party/hunspell': [  # http://crbug.com/98134
        'UNKNOWN',
    ],
    'third_party/hyphen/hyphen.tex': [ # http://crbug.com/157375
        'UNKNOWN',
    ],
    'third_party/iccjpeg': [  # http://crbug.com/98137
        'UNKNOWN',
    ],
    'third_party/icu': [  # http://crbug.com/98301
        'UNKNOWN',
    ],
    'third_party/jemalloc': [  # http://crbug.com/98302
        'UNKNOWN',
    ],
    'third_party/lcov': [  # http://crbug.com/98304
        'UNKNOWN',
    ],
    'third_party/lcov/contrib/galaxy/genflat.pl': [
        'GPL (v2 or later)',
    ],
    'third_party/lcov-1.9/contrib/galaxy/genflat.pl': [
        'GPL (v2 or later)',
    ],
    'third_party/libevent': [  # http://crbug.com/98309
        'UNKNOWN',
    ],
    'third_party/libjingle/source/talk': [  # http://crbug.com/98310
        'UNKNOWN',
    ],
    'third_party/libjingle/source_internal/talk': [  # http://crbug.com/98310
        'UNKNOWN',
    ],
    'third_party/libjpeg': [  # http://crbug.com/98313
        'UNKNOWN',
    ],
    'third_party/libjpeg_turbo': [  # http://crbug.com/98314
        'UNKNOWN',
    ],
    'third_party/libpng': [  # http://crbug.com/98318
        'UNKNOWN',
    ],

    # The following files lack license headers, but are trivial.
    'third_party/libusb/src/libusb/os/poll_posix.h': [
        'UNKNOWN',
    ],
    'third_party/libusb/src/libusb/version.h': [
        'UNKNOWN',
    ],
    'third_party/libusb/src/autogen.sh': [
        'UNKNOWN',
    ],
    'third_party/libusb/src/config.h': [
        'UNKNOWN',
    ],
    'third_party/libusb/src/msvc/config.h': [
        'UNKNOWN',
    ],

    'third_party/libvpx/source': [  # http://crbug.com/98319
        'UNKNOWN',
    ],
    'third_party/libvpx/source/libvpx/examples/includes': [
        'GPL (v2 or later)',
    ],
    'third_party/libwebp': [  # http://crbug.com/98448
        'UNKNOWN',
    ],
    'third_party/libxml': [
        'UNKNOWN',
    ],
    'third_party/libxslt': [
        'UNKNOWN',
    ],
    'third_party/lzma_sdk': [
        'UNKNOWN',
    ],
    'third_party/mesa/MesaLib': [
        'GPL (v2)',
        'GPL (v3 or later)',
        'MIT/X11 (BSD like) GPL (v3 or later) with Bison parser exception',
        'UNKNOWN',  # http://crbug.com/98450
    ],
    'third_party/modp_b64': [
        'UNKNOWN',
    ],
    'third_party/npapi/npspy/extern/java': [
        'GPL (unversioned/unknown version)',
    ],
    'third_party/openmax_dl/dl' : [
        'Khronos Group',
    ],
    'third_party/openssl': [  # http://crbug.com/98451
        'UNKNOWN',
    ],
    'third_party/ots/tools/ttf-checksum.py': [  # http://code.google.com/p/ots/issues/detail?id=2
        'UNKNOWN',
    ],
    'third_party/molokocacao': [  # http://crbug.com/98453
        'UNKNOWN',
    ],
    'third_party/npapi/npspy': [
        'UNKNOWN',
    ],
    'third_party/ocmock/OCMock': [  # http://crbug.com/98454
        'UNKNOWN',
    ],
    'third_party/ply/__init__.py': [
        'UNKNOWN',
    ],
    'third_party/protobuf': [  # http://crbug.com/98455
        'UNKNOWN',
    ],

    # http://crbug.com/222831
    # https://bitbucket.org/eliben/pyelftools/issue/12
    'third_party/pyelftools': [
        'UNKNOWN',
    ],

    'third_party/pylib': [
        'UNKNOWN',
    ],
    'third_party/scons-2.0.1/engine/SCons': [  # http://crbug.com/98462
        'UNKNOWN',
    ],
    'third_party/simplejson': [
        'UNKNOWN',
    ],
    'third_party/skia': [  # http://crbug.com/98463
        'UNKNOWN',
    ],
    'third_party/snappy/src': [  # http://crbug.com/98464
        'UNKNOWN',
    ],
    'third_party/smhasher/src': [  # http://crbug.com/98465
        'UNKNOWN',
    ],
    'third_party/sqlite': [
        'UNKNOWN',
    ],
    'third_party/swig/Lib/linkruntime.c': [  # http://crbug.com/98585
        'UNKNOWN',
    ],
    'third_party/talloc': [
        'GPL (v3 or later)',
        'UNKNOWN',  # http://crbug.com/98588
    ],
    'third_party/tcmalloc': [
        'UNKNOWN',  # http://crbug.com/98589
    ],
    'third_party/tlslite': [
        'UNKNOWN',
    ],
    'third_party/webdriver': [  # http://crbug.com/98590
        'UNKNOWN',
    ],
    'third_party/webrtc': [  # http://crbug.com/98592
        'UNKNOWN',
    ],
    'third_party/xdg-utils': [  # http://crbug.com/98593
        'UNKNOWN',
    ],
    'third_party/yasm/source': [  # http://crbug.com/98594
        'UNKNOWN',
    ],
    'third_party/zlib/contrib/minizip': [
        'UNKNOWN',
    ],
    'third_party/zlib/trees.h': [
        'UNKNOWN',
    ],
    'tools/dromaeo_benchmark_runner/dromaeo_benchmark_runner.py': [
        'UNKNOWN',
    ],
    'tools/emacs': [  # http://crbug.com/98595
        'UNKNOWN',
    ],
    'tools/grit/grit/node/custom/__init__.py': [
        'UNKNOWN',
    ],
    'tools/gyp/test': [
        'UNKNOWN',
    ],
    'tools/histograms': [
        'UNKNOWN',
    ],
    'tools/memory_watcher': [
        'UNKNOWN',
    ],
    'tools/playback_benchmark': [
        'UNKNOWN',
    ],
    'tools/python/google/__init__.py': [
        'UNKNOWN',
    ],
    'tools/site_compare': [
        'UNKNOWN',
    ],
    'tools/stats_viewer/Properties/AssemblyInfo.cs': [
        'UNKNOWN',
    ],
    'tools/symsrc/pefile.py': [
        'UNKNOWN',
    ],
    'v8/test/cctest': [  # http://crbug.com/98597
        'UNKNOWN',
    ],
    'webkit/data/ico_decoder': [
        'UNKNOWN',
    ],
}


def check_licenses(options, args):
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

  print "Using base directory:", options.base_directory
  print "Checking:", start_dir
  print

  #licensecheck_path = os.path.abspath(os.path.join(options.base_directory,
  #                                                 'third_party',
  #                                                 'devscripts',
  #                                                 'licensecheck.pl'))
  licensecheck_path = 'licensecheck'

  licensecheck = subprocess.Popen([licensecheck_path,
                                   '-l', '100',
                                   '-r', start_dir],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
  stdout, stderr = licensecheck.communicate()
  if options.verbose:
    print '----------- licensecheck stdout -----------'
    print stdout
    print '--------- end licensecheck stdout ---------'
  if licensecheck.returncode != 0 or stderr:
    print '----------- licensecheck stderr -----------'
    print stderr
    print '--------- end licensecheck stderr ---------'
    print "\nFAILED\n"
    return 1

  success = True
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

    if license in WHITELISTED_LICENSES:
      continue

    if not options.ignore_suppressions:
      found_path_specific = False
      for prefix in PATH_SPECIFIC_WHITELISTED_LICENSES:
        if (filename.startswith(prefix) and
            license in PATH_SPECIFIC_WHITELISTED_LICENSES[prefix]):
          found_path_specific = True
          break
      if found_path_specific:
        continue

    print "'%s' has non-whitelisted license '%s'" % (filename, license)
    success = False

  if success:
    print "\nSUCCESS\n"
    return 0
  else:
    print "\nFAILED\n"
    print "Please read",
    print "http://www.chromium.org/developers/adding-3rd-party-libraries"
    print "for more info how to handle the failure."
    print
    print "Please respect OWNERS of checklicenses.py. Changes violating"
    print "this requirement may be reverted."
    return 1


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
  option_parser.add_option('--ignore-suppressions',
                           action='store_true',
                           default=False,
                           help='Ignore path-specific license whitelist.')
  options, args = option_parser.parse_args()
  return check_licenses(options, args)


if '__main__' == __name__:
  sys.exit(main())
