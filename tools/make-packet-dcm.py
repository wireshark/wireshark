#!/usr/bin/env python3
import os.path
import sys
import itertools
import lxml.etree

# This utility scrapes the DICOM standard document in DocBook format, finds the appropriate tables,
# and extracts the data needed to build the lists of DICOM attributes, UIDs and value representations.

# If the files part05.xml, part06.xml and part07.xml exist in the current directory, use them.
# Otherwise, download the current release from the current DICOM official sources.
if os.path.exists("part05.xml"):
    print("Using local part05 docbook.", file=sys.stderr)
    part05 = lxml.etree.parse("part05.xml")
else:
    print("Downloading part05 docbook...", file=sys.stderr)
    part05 = lxml.etree.parse("http://dicom.nema.org/medical/dicom/current/source/docbook/part05/part05.xml")
if os.path.exists("part06.xml"):
    print("Using local part06 docbook.", file=sys.stderr)
    part06 = lxml.etree.parse("part06.xml")
else:
    print("Downloading part06 docbook...", file=sys.stderr)
    part06 = lxml.etree.parse("http://dicom.nema.org/medical/dicom/current/source/docbook/part06/part06.xml")
if os.path.exists("part07.xml"):
    print("Using local part07 docbook.", file=sys.stderr)
    part07 = lxml.etree.parse("part07.xml")
else:
    print("Downloading part07 docbook...", file=sys.stderr)
    part07 = lxml.etree.parse("http://dicom.nema.org/medical/dicom/current/source/docbook/part07/part07.xml")
dbns = {'db':'http://docbook.org/ns/docbook', 'xml':'http://www.w3.org/XML/1998/namespace'}

# When displaying the dissected packets, some attributes are nice to include in the description of their parent.
include_in_parent = {"Patient Position",
                     "ROI Number",
                     "ROI Name",
                     "Contour Geometric Type",
                     "Observation Number",
                     "ROI Observation Label",
                     "RT ROI Interpreted Type",
                     "Dose Reference Structure Type",
                     "Dose Reference Description",
                     "Dose Reference Type",
                     "Target Prescription Dose",
                     "Tolerance Table Label",
                     "Beam Limiting Device Position Tolerance",
                     "Number of Fractions Planned",
                     "Treatment Machine Name",
                     "RT Beam Limiting Device Type",
                     "Beam Number",
                     "Beam Name",
                     "Beam Type",
                     "Radiation Type",
                     "Wedge Type",
                     "Wedge ID",
                     "Wedge Angle",
                     "Material ID",
                     "Block Tray ID",
                     "Block Name",
                     "Applicator ID",
                     "Applicator Type",
                     "Control Point Index",
                     "Nominal Beam Energy",
                     "Cumulative Meterset Weight",
                     "Patient Setup Number"}

# Data elements are listed in three tables in Part 6:
# * Table 6-1. Registry of DICOM Data Elements
# * Table 7-1. Registry of DICOM File Meta Elements
# * Table 8-1. Registry of DICOM Directory Structuring Elements
# All three tables are in the same format and can be merged for processing.

# The Command data elements (used only in networking), are listed in two tables in Part 7:
# * Table E.1-1. Command Fields
# * Table E.2-1. Retired Command Fields
# The Retired Command Fields are missing the last column. For processing here,
# we just add a last column with "RET", and they can be parsed with the same
# as for the Data elements.

data_element_tables=["table_6-1", "table_7-1", "table_8-1"]

def get_trs(document, table_id):
    return document.findall(f"//db:table[@xml:id='{table_id}']/db:tbody/db:tr",
                            namespaces=dbns)

data_trs = sum((get_trs(part06, table_id) for table_id in data_element_tables), [])
cmd_trs = get_trs(part07, "table_E.1-1")
retired_cmd_trs = get_trs(part07, "table_E.2-1")

def get_texts_in_row(tr):
    tds = tr.findall("db:td", namespaces=dbns)
    texts = [" ".join(x.replace('\u200b', '').replace('\u00b5', 'u').strip() for x in td.itertext() if x.strip() != '') for td in tds]
    return texts

data_rows = [get_texts_in_row(x) for x in data_trs]
retired_cmd_rows = [get_texts_in_row(x) for x in retired_cmd_trs]
cmd_rows = ([get_texts_in_row(x) for x in cmd_trs] +
            [x + ["RET"] for x in retired_cmd_rows])

def parse_tag(tag):
    # To handle some old cases where "x" is included as part of the tag number
    tag = tag.replace("x", "0")
    return f"0x{tag[1:5]}{tag[6:10]}"
def parse_ret(ret):
    if ret.startswith("RET"):
        return -1
    else:
        return 0
def include_in_parent_bit(name):
    if name in include_in_parent:
        return -1
    else:
        return 0
def text_for_row(row):
    return f'    {{ {parse_tag(row[0])}, "{row[1]}", "{row[3]}", "{row[4]}", {parse_ret(row[5])}, {include_in_parent_bit(row[1])}}},'

def text_for_rows(rows):
    return "\n".join(text_for_row(row) for row in rows)

vrs = {i+1: get_texts_in_row(x)[0].split(maxsplit=1) for i,x in enumerate(get_trs(part05, "table_6.2-1"))}


# Table A-1. UID Values
uid_trs = get_trs(part06, "table_A-1")
uid_rows = [get_texts_in_row(x) for x in uid_trs]

wkfr_trs = get_trs(part06, "table_A-2")
wkfr_rows = [get_texts_in_row(x) for x in wkfr_trs]
uid_rows += [x[:3] + ['Well-known frame of reference'] + x[3:] for x in wkfr_rows]

def uid_define_name(uid):
    if uid[1] == "(Retired)":
        return f'"{uid[0]}"'
    uid_type = uid[3]
    uid_name = uid[1]
    uid_name = re.sub(":.*", "", uid[1])
    if uid_name.endswith(uid_type):
        uid_name = uid_name[:-len(uid_type)].strip()
    return f"DCM_UID_{definify(uid_type)}_{definify(uid_name)}"

import re
def definify(s):
    return re.sub('[^A-Z0-9]+', '_', re.sub('  +', ' ', re.sub('[^-A-Z0-9 ]+', '', s.upper())))

uid_rows = sorted(uid_rows, key=lambda uid_row: [int(i) for i in uid_row[0].split(".")])
packet_dcm_h = """/* packet-dcm.h
 * Definitions for DICOM dissection
 * Copyright 2003, Rich Coe <richcoe2@gmail.com>
 * Copyright 2008-2018, David Aggeler <david_aggeler@hispeed.ch>
 *
 * DICOM communication protocol: https://www.dicomstandard.org/current/
 *
 * Generated automatically by """ + os.path.basename(sys.argv[0]) + """ from the following sources:
 *
 * """ + part05.find("./db:subtitle", namespaces=dbns).text + """
 * """ + part06.find("./db:subtitle", namespaces=dbns).text + """
 * """ + part07.find("./db:subtitle", namespaces=dbns).text + """
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_DCM_H__
#define __PACKET_DCM_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

""" + "\n".join(f"#define DCM_VR_{vr[0]} {i:2d}  /* {vr[1]:25s} */" for i,vr in vrs.items()) + """

/* Following must be in the same order as the definitions above */
static const char* dcm_tag_vr_lookup[] = {
    "  ",
    """ + ",\n    ".join(",".join(f'"{x[1][0]}"' for x in j[1]) for j in itertools.groupby(vrs.items(), lambda i: (i[0]-1)//8)) + """
};


/* ---------------------------------------------------------------------
 * DICOM Tag Definitions
 *
 * Some Tags can have different VRs
 *
 * Group 1000 is not supported, multiple tags with same description  (retired anyhow)
 * Group 7Fxx is not supported, multiple tags with same description  (retired anyhow)
 *
 * Tags (0020,3100 to 0020, 31FF) not supported, multiple tags with same description  (retired anyhow)
 *
 * Repeating groups (50xx & 60xx) are manually added. Declared as 5000 & 6000
 */

typedef struct dcm_tag {
    const uint32_t tag;
    const char *description;
    const char *vr;
    const char *vm;
    const bool is_retired;
    const bool add_to_summary;          /* Add to parent's item description */
} dcm_tag_t;

static dcm_tag_t const dcm_tag_data[] = {

    /* Command Tags */
""" + text_for_rows(cmd_rows) + """

    /* Data Tags */
""" + text_for_rows(data_rows) + """
};

/* ---------------------------------------------------------------------
 * DICOM UID Definitions

 * Part 6 lists following different UID Types (2006-2008)

 * Application Context Name
 * Coding Scheme
 * DICOM UIDs as a Coding Scheme
 * LDAP OID
 * Meta SOP Class
 * SOP Class
 * Service Class
 * Transfer Syntax
 * Well-known Print Queue SOP Instance
 * Well-known Printer SOP Instance
 * Well-known SOP Instance
 * Well-known frame of reference
 */

typedef struct dcm_uid {
    const char *value;
    const char *name;
    const char *type;
} dcm_uid_t;

""" + "\n".join(f'#define {uid_define_name(uid)} "{uid[0]}"'
                for uid in uid_rows if uid[1] != '(Retired)') + """

static dcm_uid_t const dcm_uid_data[] = {
""" + "\n".join(f'    {{ {uid_define_name(uid)}, "{uid[1]}", "{uid[3]}"}},'
                            for uid in uid_rows)+ """
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* packet-dcm.h */"""

print(packet_dcm_h)
