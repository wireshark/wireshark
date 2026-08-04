#!/usr/bin/env python3
#
# Looks for registration routines in the source files
# and assembles C code to call all the routines.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import re
import sys

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
        output += f"void {f}(void);\n"
    return output

def gen_array(funcs, name):
    output = f"{name}[] = {{\n"
    for f in funcs:
        output += f"    {{ \"{f}\", {f} }},\n"
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
    output += f"""\
#include "dissectors.h"

const unsigned long dissector_reg_proto_count = {len(protos)};
const unsigned long dissector_reg_handoff_count = {len(handoffs)};

"""

    output += gen_prototypes(protos)
    output += "\n"
    output += gen_array(protos, "dissector_reg_t const dissector_reg_proto")
    output += "\n"
    output += gen_prototypes(handoffs)
    output += "\n"
    output += gen_array(handoffs, "dissector_reg_t const dissector_reg_handoff")

    with open(outfile, "w") as f:
        f.write(output)

    print(f"Found {len(protos)} registrations and {len(handoffs)} handoffs.")

def make_event_dissectors(outfile, infiles):
    protos = []
    protos_regex = r"void\s+(event_register_[\w]+)\s*\(\s*void\s*\)\s*{"
    handoffs = []
    handoffs_regex = r"void\s+(event_reg_handoff_[\w]+)\s*\(\s*void\s*\)\s*{"

    scan_files(infiles, [(protos, protos_regex), (handoffs, handoffs_regex)])

    if len(protos) < 1:
        sys.exit("No protocol registrations found.")

    protos.sort()
    handoffs.sort()

    output = preamble
    output += f"""\
#include "event-dissectors.h"

const unsigned long event_dissector_reg_proto_count = {len(protos)};
const unsigned long event_dissector_reg_handoff_count = {len(handoffs)};

"""

    output += gen_prototypes(protos)
    output += "\n"
    output += gen_array(protos, "dissector_reg_t const event_dissector_reg_proto")
    output += "\n"
    output += gen_prototypes(handoffs)
    output += "\n"
    output += gen_array(handoffs, "dissector_reg_t const event_dissector_reg_handoff")

    with open(outfile, "w") as f:
        f.write(output)

    print(f"Found {len(protos)} registrations and {len(handoffs)} handoffs.")

def make_wtap_modules(outfile, infiles):
    wtap_modules = []
    wtap_modules_regex = r"void\s+(register_[\w]+)\s*\(\s*void\s*\)\s*{"

    scan_files(infiles, [(wtap_modules, wtap_modules_regex)])

    if len(wtap_modules) < 1:
        sys.exit("No wiretap registrations found.")

    wtap_modules.sort()

    output = preamble
    output += f"""\
#include <glib.h>
#include "wtap_modules.h"

const unsigned wtap_module_count = {len(wtap_modules)};

"""

    output += gen_prototypes(wtap_modules)
    output += "\n"
    output += gen_array(wtap_modules, "wtap_module_reg_t const wtap_module_reg")

    with open(outfile, "w") as f:
        f.write(output)

    print(f"Found {len(wtap_modules)} registrations.")

def make_taps(outfile, infiles):
    taps = []
    taps_regex = r"void\s+(register_tap_listener_[\w]+)\s*\(\s*void\s*\)\s*{"

    scan_files(infiles, [(taps, taps_regex)])

    if len(taps) < 1:
        sys.exit("No tap registrations found.")

    taps.sort()

    output = preamble
    output += f"""\
#include "ui/taps.h"

const unsigned long tap_reg_listener_count = {len(taps)};

"""

    output += gen_prototypes(taps)
    output += "\n"
    output += gen_array(taps, "tap_reg_t const tap_reg_listener")

    with open(outfile, "w") as f:
        f.write(output)

    print(f"Found {len(taps)} registrations.")


def print_usage():
    sys.exit(f"Usage: {sys.argv[0]} <dissectors|taps> <outfile> <infiles...|@filelist>\n")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print_usage()

    mode = sys.argv[1]
    outfile = sys.argv[2]
    if sys.argv[3].startswith("@"):
        with open(sys.argv[3][1:]) as f:
            infiles = [line.strip() for line in f]
    else:
        infiles = sys.argv[3:]

    if mode == "dissectors":
        make_dissectors(outfile, infiles)
    elif mode == "event_dissectors":
        make_event_dissectors(outfile, infiles)
    elif mode == "wtap_modules":
        make_wtap_modules(outfile, infiles)
    elif mode == "taps":
        make_taps(outfile, infiles)
    else:
        print_usage()
