#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''
make-bluetooth - Generate value_strings containing bluetooth uuids and company identifiers.
It makes use of the databases from
The Bluetooth SIG Repository: https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/
and processes the YAML into human-readable strings to go into packet-bluetooth.c.
'''

import sys
import urllib.request, urllib.error, urllib.parse
import yaml

base_url = "https://bitbucket.org/bluetooth-SIG/public/raw/HEAD/assigned_numbers/"

MIN_UUIDS = 1400       # 1424 as of 31-12-2023
MIN_COMPANY_IDS = 3400 # 3405 as of 31-12-2023

##
## UUIDs
##

'''
List of all YAML files to retrieve, the lists of UUIDs to put into the value_string
and other information.
Unfortunately the encoding of the names among the YAML files is inconsistent,
to say the least. This will need post-processing.
Also the previous value_string contained additional uuids, which are not currently
present in the databases. Prepare the lists with these uuids so they are not lost.
When they do appear in the databases they must be removed here.
'''

uuids_sources = [
{   # 0x0001
    "yaml": "protocol_identifiers.yaml",
    "description": "Protocol Identifiers",
    "unCamelCase": True,
    "unlist": [],
    "list": [
        { "uuid": 0x001D, "name": "UDI C-Plane" },
    ]
},
{   # 0x1000
    "yaml": "service_class.yaml",
    "description": "Service Class",
    "unCamelCase": True,
    "unlist": [],
    "list": [
        # Then we have this weird one stuck in between "Service Class"
        # from browse_group_identifiers.yaml
        { "uuid": 0x1002, "name": "Public Browse Group" },
        # And some from other sources
        { "uuid": 0x1129, "name": "Video Conferencing GW" },
        { "uuid": 0x112A, "name": "UDI MT" },
        { "uuid": 0x112B, "name": "UDI TA" },
        { "uuid": 0x112C, "name": "Audio/Video" },
    ]
},
{   # 0x1600
    "yaml": "mesh_profile_uuids.yaml",
    "description": "Mesh Profile",
    "unCamelCase": False,
    "unlist": [],
    "list": []
},
{   # 0x1800
    "yaml": "service_uuids.yaml",
    "description": "Service",
    "unCamelCase": False,
    "unlist": [],
    "list": []
},
{   # 0x2700
    "yaml": "units.yaml",
    "description": "Units",
    "unCamelCase": False,
    "unlist": [],
    "list": []
},
{   # 0x2800
    "yaml": "declarations.yaml",
    "description": "Declarations",
    "unCamelCase": False,
    "unlist": [],
    "list": []
},
{   # 0x2900
    "yaml": "descriptors.yaml",
    "description": "Descriptors",
    "unCamelCase": False,
    "unlist": [],
    "list": []
},
{   # 0x2a00
    "yaml": "characteristic_uuids.yaml",
    "description": "Characteristics",
    "unCamelCase": False,
    "unlist": [],
    "list": [
        # Then we have these weird ones stuck in between "Characteristics"
        # from object_types.yaml
        { "uuid": 0x2ACA, "name": "Unspecified" },
        { "uuid": 0x2ACB, "name": "Directory Listing" },
        # And some from other sources
        { "uuid": 0x2A0B, "name": "Exact Time 100" },
        { "uuid": 0x2A10, "name": "Secondary Time Zone" },
        { "uuid": 0x2A15, "name": "Time Broadcast" },
        { "uuid": 0x2A1A, "name": "Battery Power State" },
        { "uuid": 0x2A1B, "name": "Battery Level State" },
        { "uuid": 0x2A1F, "name": "Temperature Celsius" },
        { "uuid": 0x2A20, "name": "Temperature Fahrenheit" },
        { "uuid": 0x2A2F, "name": "Position 2D" },
        { "uuid": 0x2A30, "name": "Position 3D" },
        { "uuid": 0x2A3A, "name": "Removable" },
        { "uuid": 0x2A3B, "name": "Service Required" },
        { "uuid": 0x2A3C, "name": "Scientific Temperature Celsius" },
        { "uuid": 0x2A3D, "name": "String" },
        { "uuid": 0x2A3E, "name": "Network Availability" },
        { "uuid": 0x2A56, "name": "Digital" },
        { "uuid": 0x2A57, "name": "Digital Output" },
        { "uuid": 0x2A58, "name": "Analog" },
        { "uuid": 0x2A59, "name": "Analog Output" },
        { "uuid": 0x2A62, "name": "Pulse Oximetry Control Point" },
        # These have somehow disappeared. We keep them for if they were used.
        { "uuid": 0x2BA9, "name": "Media Player Icon Object Type" },
        { "uuid": 0x2BAA, "name": "Track Segments Object Type" },
        { "uuid": 0x2BAB, "name": "Track Object Type" },
        { "uuid": 0x2BAC, "name": "Group Object Type" },
    ]
},
{   # 0xfxxx
    "yaml": "member_uuids.yaml",
    "description": "Members",
    "unCamelCase": False,
    "unlist": [],
    "list": [
        # This they really screwed up. The UUID was moved to sdo_uuids,
        # thereby breaking the range and ordering completely.
        { "uuid": 0xFCCC, "name": "Wi-Fi Easy Connect Specification" },
    ]
},
{   # 0xffef (and 0xfccc)
    "yaml": "sdo_uuids.yaml",
    "description": "SDO",
    "unCamelCase": False,
    "unlist": [ 0xFCCC,
    ],
    "list": []
}]

'''
Retrieve the YAML files defining the UUIDs and add them to the lists
'''
for uuids in uuids_sources:
    req_headers = { 'User-Agent': 'Wireshark make-bluetooth' }
    try:
        req = urllib.request.Request(base_url + 'uuids/' + uuids["yaml"], headers=req_headers)
        response = urllib.request.urlopen(req)
        lines = response.read().decode('UTF-8', 'replace')
    except Exception as e:
        print("Failed to get UUIDs at {url}, because of: {e}".format(url=base_url + 'uuids/' + uuids["yaml"], e=e), file=sys.stderr)
        sys.exit(1)

    uuids_dir = yaml.safe_load(lines)
    for uuid in uuids_dir["uuids"]:
        if uuid["uuid"] not in uuids["unlist"]:
            uuids["list"].append(uuid)

'''
Go through the lists and perform general and specific transforms.
Several exceptional cases are addressed directly by their UUID, because of the inconsistent nature
by which their name is constructed.
When they appear more sensibly in the databases they must be removed here.
When new inconsistent entries appear in the databases their transforms can be added here,
but also add their UUID below.
'''
for uuids in uuids_sources:
    for uuid in uuids["list"]:
        # Handle a few exceptional cases
        if uuid["uuid"] == 0x001E:
            uuid["name"] = "MCAP Control Channel"
        elif uuid["uuid"] == 0x001F:
            uuid["name"] = "MCAP Data Channel"
        elif uuid["uuid"] == 0x1102:
            uuid["name"] = "LAN Access Using PPP"
        elif uuid["uuid"] == 0x1104:
            uuid["name"] = "IrMC Sync"
        elif uuid["uuid"] == 0x1105:
            uuid["name"] = "OBEX Object Push"
        elif uuid["uuid"] == 0x1106:
            uuid["name"] = "OBEX File Transfer"
        elif uuid["uuid"] == 0x1107:
            uuid["name"] = "IrMC Sync Command"
        elif uuid["uuid"] == 0x1200:
            uuid["name"] = "PnP Information"
        elif uuid["uuid"] == 0x2B8C:
            uuid["name"] = "CO\u2082 Concentration"
        else:
        # And these in general
            uuid["name"] = uuid["name"].replace("_", " ")
            uuid["name"] = uuid["name"].replace('"', '\\"')

'''
Go through the lists and, for those lists flagged as such, perform the unCamelCase transform
on all the names in that list.
Several exceptional cases were addressed directly by their UUID and must be excluded from this
transform.
When additional characters indicating a break in words appear in database entries they can be
added to break_chars.
'''
for uuids in uuids_sources:
    if uuids["unCamelCase"]:
        for uuid in uuids["list"]:
            # if not a few exceptional cases (see above)
            if uuid["uuid"] not in [0x001E, 0x001F, 0x1102, 0x1104, 0x1105, 0x1106, 0x1107, 0x1200, 0x2B8C]:
                # Parse through the names and look for capital letters; when
                # not preceded by another capital letter or one of break_chars, insert a space
                break_chars = [" ", "-", "+", "/", "(", ".", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
                was_break = True # fake space at beginning of string
                was_upper = False
                name = ""
                for character in uuid["name"]:
                    is_upper = True if character.isupper() else False
                    if is_upper and not was_break and not was_upper:
                        name += " "
                    name += character
                    was_break = True if character in break_chars else False
                    was_upper = is_upper
                uuid["name"] = name

'''
To be able to generate a value_string_ext array the entries need to be sorted.
'''
for uuids in uuids_sources:
    uuids_sorted = sorted(uuids["list"], key=lambda uuid: uuid["uuid"])
    uuids["list"] = uuids_sorted

'''
Do a check on duplicate entries.
While at it, do a count of the number of UUIDs retrieved.
'''
prev_uuid = 0
uuid_count = 0
for uuids in uuids_sources:
    for uuid in uuids["list"]:
        if uuid["uuid"] > prev_uuid:
            prev_uuid = uuid["uuid"]
        else:
            print("Duplicate UUID detected: 0x{uuid:04X}".format(uuid=uuid["uuid"]), file=sys.stderr)
            sys.exit(1)
    uuid_count += len(uuids["list"])

'''
Sanity check to see if enough entries were retrieved
'''
if (uuid_count < MIN_UUIDS):
    print("There are fewer UUIDs than expected: got {count} but was expecting {minimum}".format(count=uuid_count, minimum=MIN_UUIDS), file=sys.stderr)
    sys.exit(1)

'''
Finally output the annotated source code for the value_string
'''
print("const value_string bluetooth_uuid_vals[] = {")

for uuids in uuids_sources:
    print("    /* {description} - {base_url}uuids/{yaml} */".format(description=uuids["description"], base_url=base_url, yaml=uuids["yaml"]))
    for uuid in uuids["list"]:
        print("    {{ 0x{uuid:04X},   \"{name}\" }},".format(uuid=uuid["uuid"], name=uuid["name"]))

print("    {      0,   NULL }")
print("};")
print("value_string_ext bluetooth_uuid_vals_ext = VALUE_STRING_EXT_INIT(bluetooth_uuid_vals);")
print("")

##
## Company Identifiers
##

'''
List of the YAML files to retrieve and the lists of values to put into the value_string.
Also the previous value_string contained additional company IDs, which are not currently
present in the databases. Prepare the lists with these company IDs so they are not lost.
When they do appear in the databases they must be removed here.
'''

company_ids_sources = [
{
    "yaml": "company_identifiers.yaml",
    "list": [
        # Some from other sources
        { "value": 0x0418, "name": "Alpine Electronics Inc." },
        { "value": 0x0943, "name": "Inovonics Corp." },
        { "value": 0xFFFF, "name": "For use in internal and interoperability tests" },
    ]
}]

'''
Retrieve the YAML files defining the company IDs and add them to the lists
'''
for company_ids in company_ids_sources:
    req_headers = { 'User-Agent': 'Wireshark make-bluetooth' }
    try:
        req = urllib.request.Request(base_url + 'company_identifiers/' + company_ids["yaml"], headers=req_headers)
        response = urllib.request.urlopen(req)
        lines = response.read().decode('UTF-8', 'replace')
    except Exception as e:
        print("Failed to get company IDs at {url}, because of: {e}".format(url=base_url + 'company_identifiers/' + company_ids["yaml"], e=e), file=sys.stderr)
        sys.exit(-1)

    company_ids_dir = yaml.safe_load(lines)
    company_ids["list"].extend(company_ids_dir["company_identifiers"])

'''
Go through the lists and perform general transforms.
'''
for company_ids in company_ids_sources:
    for company_id in company_ids["list"]:
        company_id["name"] = company_id["name"].replace('"', '\\"')

'''
To be able to generate a value_string_ext array the entries need to be sorted.
'''
for company_ids in company_ids_sources:
    company_ids_sorted = sorted(company_ids["list"], key=lambda company_id: company_id['value'])
    company_ids["list"] = company_ids_sorted

'''
Do a check on duplicate entries.
While at it, do a count of the number of company IDs retrieved.
'''
prev_company_id = -1
company_id_count = 0
for company_ids in company_ids_sources:
    for company_id in company_ids["list"]:
        if company_id["value"] > prev_company_id:
            prev_company_id = company_id["value"]
        else:
            print("Duplicate company ID detected: 0x{company_id:04X}".format(company_id=company_id["value"]), file=sys.stderr)
            sys.exit(1)
    company_id_count += len(company_ids["list"])

'''
Sanity check to see if enough entries were retrieved
'''
if company_id_count < MIN_COMPANY_IDS:
    print("There are fewer company IDs than expected: got {count} but was expecting {minimum}".format(count=company_id_count, minimum=MIN_COMPANY_IDS), file=sys.stderr)
    sys.exit(1)

'''
Finally output the source code for the value_string
'''
print("/* Taken from {base_url}company_identifiers/{yaml} */".format(base_url=base_url, yaml=company_ids_sources[0]["yaml"]))
print("static const value_string bluetooth_company_id_vals[] = {")

for company_ids in company_ids_sources:
    for company_id in company_ids["list"]:
        print("    {{ 0x{company_id:04X},   \"{name}\" }},".format(company_id=company_id["value"], name=company_id["name"]))

print("    {      0,   NULL }")
print("};")
print("value_string_ext bluetooth_company_id_vals_ext = VALUE_STRING_EXT_INIT(bluetooth_company_id_vals);")

