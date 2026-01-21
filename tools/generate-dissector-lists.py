#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''\
Generate the DISSECTOR_PUBLIC_HEADERS and CLEAN_ASN1_DISSECTOR_SRC lists in epan/dissectors/CMakeLists.txt.

For DISSECTOR_PUBLIC_HEADERS, each header must contain at least one exported function.
'''

import concurrent.futures
import os
import os.path
import re
import sys

from enum import Enum

State = Enum('State', ['Normal', 'InAsn1Dissectors', 'InPublicHeaders'])

DISSECTORS_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'epan', 'dissectors'))
CMAKELISTS_TXT = os.path.join(DISSECTORS_PATH, 'CMakeLists.txt')
THIS_FILE = os.path.basename(__file__)

PACKET_SOURCE_FILE_PATTERN = r'^(data|packet)-.*\.c$'
ASN1_SOURCE_PATTERN = r'Generated automatically by the ASN.1 to Wireshark dissector compiler'

PACKET_HEADER_FILE_PATTERN = r'^(data|file|packet)-.*\.h$'
PUBLIC_HEADER_PATTERN = r'(^\s*WS_DLL_PUBLIC\b|\bstruct\s.*tap_|\bPUBLIC_HEADER\b)'
PACKET_HEADER_INCLUDE_PATTERN = r'^\s*#\s*include\s.*\b(packet-.*\.h)\b'

MIN_ASN1_SOURCE_COUNT = 130 # 130 on 2025-12-03
MIN_HEADER_COUNT = 120 # 121 on 2025-12-03

def exit_msg(msg=None, status=1):
    if msg is not None:
        sys.stderr.write(msg + '\n\n')
    sys.stderr.write(__doc__ + '\n')
    sys.exit(status)

def search_asn1_source(source_file):
    with open (os.path.join(DISSECTORS_PATH, source_file)) as f:
        if re.search(ASN1_SOURCE_PATTERN, f.read(512), re.MULTILINE):
            return source_file
    return None

def get_asn1_sources():
    '''Search for public packet-*.h headers.
    Returns a list of filenames.
    '''
    packet_sources = [e.name for e in os.scandir(DISSECTORS_PATH) if e.is_file() and re.match(PACKET_SOURCE_FILE_PATTERN, e.name) ]

    asn1_sources = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        sources = executor.map(search_asn1_source, packet_sources)
        asn1_sources.extend([s for s in sources if s is not None])

    if len(asn1_sources) < MIN_ASN1_SOURCE_COUNT:
        exit_msg(f'Too few ASN.1 sources. Found {len(asn1_sources)}, need {MIN_ASN1_SOURCE_COUNT}')

    print(f'Found {len(asn1_sources)} ASN.1 source files.')
    return sorted(asn1_sources, key=str.lower)

def get_packet_includes(header_file, depth=0):
    if depth > 10:
        return []
    includes = []
    with open (os.path.join(DISSECTORS_PATH, header_file)) as f:
        for include in re.findall(PACKET_HEADER_INCLUDE_PATTERN, f.read(), re.MULTILINE):
            includes.append(include)
            includes.extend(get_packet_includes(include, depth+1))
    return includes

def search_packet_header(header_file):
    with open (os.path.join(DISSECTORS_PATH, header_file)) as f:
        if re.search(PUBLIC_HEADER_PATTERN, f.read(), re.MULTILINE):
            header_files = [header_file]
            header_files.extend(get_packet_includes(header_file))
            return header_files
    return []

def get_public_headers():
    '''Search for public packet-*.h headers.
    Returns a list of filenames.
    '''
    packet_headers = [e.name for e in os.scandir(DISSECTORS_PATH) if e.is_file() and re.match(PACKET_HEADER_FILE_PATTERN, e.name) ]

    public_headers = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        header_lists = executor.map(search_packet_header, packet_headers)
        for header_list in header_lists:
            public_headers.extend(header_list)

    if len(public_headers) < MIN_HEADER_COUNT:
        exit_msg(f'Too few public headers. Found {len(public_headers)}, need {MIN_HEADER_COUNT}')

    print(f'Found {len(public_headers)} public header files.')
    return sorted(set(public_headers), key=str.lower)


def main():
    warning = f'# Do not edit this list by hand. Generate it by running tools/{THIS_FILE} instead.'
    public_headers = [warning] + get_public_headers()
    asn1_sources = get_asn1_sources()

    cmakelists_f = open(CMAKELISTS_TXT, 'r')
    cm_lines = list(cmakelists_f)
    cmakelists_f = open(CMAKELISTS_TXT, 'w+')
    cm_out = ''
    state = State.Normal

    for line in cm_lines:
        if state == State.Normal:
            cm_out += line
            if re.match(r'^\s*set\s*\(\s*DISSECTOR_PUBLIC_HEADERS', line):
                state = State.InPublicHeaders
                cm_out += ''.join([f'\t{ph}\n' for ph in public_headers])
            elif re.match(r'^\s*set\s*\(\s*CLEAN_ASN1_DISSECTOR_SRC', line):
                state = State.InAsn1Dissectors
                cm_out += f'\t{warning}\n'
                cm_out += ''.join([f'\t${{CMAKE_CURRENT_SOURCE_DIR}}/{af}\n' for af in asn1_sources])
        elif re.match(r'^\s*\)', line):
            state = State.Normal
            cm_out += line

    cmakelists_f.write(cm_out)
    cmakelists_f.close()

#
# On with the show
#

if __name__ == "__main__":
    sys.exit(main())
