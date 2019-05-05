#!/usr/bin/env python
#
# Looks for registration routines in the source files
# and assembles C code to call all the routines.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import sys
import re

preamble = """\
/*
 * Do not modify this file. Changes will be overwritten.
 *
 * Generated automatically using \"make-regs.py\".
 */

"""

def gen_prototypes(funcs):
    output = ""
    for f in funcs:
        output += "void {}(void);\n".format(f)
    return output

def gen_array(funcs, name):
    output = "{}[] = {{\n".format(name)
    for f in funcs:
        output += "    {{ \"{0}\", {0} }},\n".format(f)
    output += "    { NULL, NULL }\n};\n"
    return output

def scan_files(infiles, regs):
    for path in infiles:
        with open(path, 'r', encoding='utf8') as f:
            source = f.read()
            for array, regex in regs:
                matches = re.findall(regex, source)
                array.extend(matches)

def make_dissectors(outfile, infiles):
    protos = []
    protos_regex = r"void\s+(proto_register_[\w]+)\s*\(\s*void\s*\)\s*{"
    handoffs = []
    handoffs_regex = r"void\s+(proto_reg_handoff_[\w]+)\s*\(\s*void\s*\)\s*{"

    scan_files(infiles, [(protos, protos_regex), (handoffs, handoffs_regex)])

    if len(protos) < 1:
        sys.exit("No protocol registrations found.")

    protos.sort()
    handoffs.sort()

    output = preamble
    output += """\
#include "dissectors.h"

const gulong dissector_reg_proto_count = {0};
const gulong dissector_reg_handoff_count = {1};

""".format(len(protos), len(handoffs))

    output += gen_prototypes(protos)
    output += "\n"
    output += gen_array(protos, "dissector_reg_t dissector_reg_proto")
    output += "\n"
    output += gen_prototypes(handoffs)
    output += "\n"
    output += gen_array(handoffs, "dissector_reg_t dissector_reg_handoff")

    with open(outfile, "w") as f:
        f.write(output)

    print("Found {0} registrations and {1} handoffs.".format(len(protos), len(handoffs)))

def make_taps(outfile, infiles):
    taps = []
    taps_regex = r"void\s+(register_tap_listener_[\w]+)\s*\(\s*void\s*\)\s*{"

    scan_files(infiles, [(taps, taps_regex)])

    if len(taps) < 1:
        sys.exit("No tap registrations found.")

    taps.sort()

    output = preamble
    output += """\
#include "ui/taps.h"

const gulong tap_reg_listener_count = {0};

""".format(len(taps))

    output += gen_prototypes(taps)
    output += "\n"
    output += gen_array(taps, "tap_reg_t tap_reg_listener")

    with open(outfile, "w") as f:
        f.write(output)

    print("Found {0} registrations.".format(len(taps)))


def print_usage():
    sys.exit("Usage: {0} <dissectors|taps> <outfile> <infiles...|@filelist>\n".format(sys.argv[0]))

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print_usage()

    mode = sys.argv[1]
    outfile = sys.argv[2]
    if sys.argv[3].startswith("@"):
        with open(sys.argv[3][1:]) as f:
            infiles = [l.strip() for l in f.readlines()]
    else:
        infiles = sys.argv[3:]

    if mode == "dissectors":
        make_dissectors(outfile, infiles)
    elif mode == "taps":
        make_taps(outfile, infiles)
    else:
        print_usage()
