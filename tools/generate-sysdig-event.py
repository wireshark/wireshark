#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
'''\
Generate Sysdig event dissector sections from the sysdig sources.

Reads driver/event_table.c and driver/ppm_events_public.h and generates
corresponding dissection code in packet-sysdig-event.c. Updates are
performed in-place in the dissector code.

Requires an Internet connection. Assets are loaded from GitHub over HTTPS.
'''

import os
import os.path
import re
import urllib2
import sys

sysdig_repo_pfx = 'https://raw.githubusercontent.com/draios/sysdig/0.5.0/'

ppm_ev_pub = urllib2.urlopen(sysdig_repo_pfx + 'driver/ppm_events_public.h')
ppm_ev_pub_lines = ppm_ev_pub.readlines()
ppm_ev_pub.close()

ppme_re = re.compile('^\s+PPME_([A-Z0-9_]+_[EX])\s*=\s*([0-9]+)\s*,')

event_info_d = {}

def get_event_defines():
    event_d = {}
    for line in ppm_ev_pub_lines:
        m = ppme_re.match(line)
        if m:
            event_d[int(m.group(2))] = m.group(1)
    return event_d

ppm_ev_table = urllib2.urlopen(sysdig_repo_pfx + 'driver/event_table.c')
ppm_ev_table_lines = ppm_ev_table.readlines()
ppm_ev_table.close()

hf_d = {}

event_info_re = re.compile('^\s+/\*\s*PPME_.*\*\/\s*{\s*"([A-Za-z0-9_]+)"\s*,[^,]+,[^,]+,\s*([0-9]+)\s*[,{}]')
event_param_re = re.compile('{\s*"([A-Za-z0-9_]+)"\s*,\s*PT_([A-Z0-9_]+)\s*,\s*PF_([A-Z0-9_]+)\s*[,}]')

def get_event_names():
    '''Return a contiguous list of event names. Names are lower case.'''
    event_name_l = []
    for line in ppm_ev_table_lines:
        ei = event_info_re.match(line)
        if ei:
            event_name_l.append(ei.group(1))
    return event_name_l

# PT_xxx to FT_xxx
pt_to_ft = {
    'BYTEBUF': 'BYTES',
    'CHARBUF': 'STRING',
    'FD': 'INT64',
    'FSPATH': 'STRING',
}

def get_event_params():
    '''Return a list of dictionaries containing event names and parameter info.'''
    event_param_l = []
    event_num = 0
    force_string_l = ['args', 'env']
    for line in ppm_ev_table_lines:
        ei = event_info_re.match(line)
        ep = event_param_re.findall(line)
        if ei and ep:
            src_param_count = int(ei.group(2))
            if len(ep) != src_param_count:
                err_msg = '{}: found {} parameters. Expected {}. Params: {}'.format(
                    ei.group(1), len(ep), src_param_count, repr(ep))
                raise NameError(err_msg)
            for p in ep:
                if p[0] in force_string_l:
                    param_type = 'STRING'
                elif p[1] in pt_to_ft:
                    param_type = pt_to_ft[p[1]]
                elif p[0] == 'flags' and p[1].startswith('INT') and 'HEX' in p[2]:
                    param_type = 'U' + p[1]
                elif 'INT' in p[1]:
                    # Ints
                    param_type = p[1]
                else:
                    # Fall back to bytes
                    param_type = 'BYTES'

                if p[2] == 'NA':
                    if 'INT' in param_type:
                        param_format = 'DEC'
                    else:
                        param_format = 'NONE'
                elif param_type == 'BYTES':
                    param_format = 'NONE'
                else:
                    param_format = p[2]
                param_d = {
                    'event_name': ei.group(1),
                    'event_num': event_num,
                    'param_name': p[0],
                    'param_type': param_type,
                    'param_format': param_format,
                }
                event_param_l.append(param_d)
        if ei:
            event_num += 1
    return event_param_l

def param_to_hf_name(param):
    return 'hf_param_{}_{}'.format(param['param_name'], param['param_type'].lower())

def param_to_value_string_name(param):
    return '{}_{}_vals'.format(param['param_name'], param['param_type'].lower())

def get_param_desc(param):
    # Try to coerce event names and parameters into human-friendly
    # strings.
    # XXX This could use some work.

    # Specific descriptions. Event name + parameter name.
    param_descs = {
        'accept.queuepct': 'Accept queue per connection',
        'execve.args': 'Program arguments',
        'execve.comm': 'Command',
        'execve.cwd': 'Current working directory',
    }
    # General descriptions. Event name only.
    event_descs = {
        'ioctl': 'I/O control',
    }

    event_name = param['event_name']
    param_id = '{}.{}'.format(event_name, param['param_name'])
    if param_id in param_descs:
        param_desc = param_descs[param_id]
    elif event_name in event_descs:
        param_desc = '{}: {}'.format(event_descs[event_name], param['param_name'])
    else:
        param_desc = param['param_name']
    return param_desc

def main():
    # Event list
    event_d = get_event_defines()
    event_nums = event_d.keys()
    event_nums.sort()

    event_name_l = get_event_names()
    event_param_l = get_event_params()

    hf_d = {}
    for param in event_param_l:
        hf_name = param_to_hf_name(param)
        hf_d[hf_name] = param

    idx_id_to_name = { '': 'no' }
    parameter_index_l = []

    for en in range (0, len(event_nums)):
        param_id = ''
        param_l = []
        event_var = event_d[en].lower()
        for param in event_param_l:
            if param['event_num'] == en:
                hf_name = param_to_hf_name(param)
                param_l.append(hf_name)
                param_id += ':' + param['param_name'] + '_' + param['param_type']

        ei_str = ''
        if param_id not in idx_id_to_name:
            idx_id_to_name[param_id] = event_var
            ei_str = 'static const int *{}_indexes[] = {{ &{}, NULL }};'.format(
                event_var,
                ', &'.join(param_l)
            )
        else:
            ei_str = '#define {}_indexes {}_indexes'.format(event_var, idx_id_to_name[param_id])

        parameter_index_l.append(ei_str)

    dissector_path = os.path.join(os.path.dirname(__file__),
        '..', 'epan', 'dissectors', 'packet-sysdig-event.c')
    dissector_f = open(dissector_path, 'r')
    dissector_lines = list(dissector_f)
    dissector_f = open(dissector_path, 'w+')

    # Strip out old content
    strip_re_l = []
    strip_re_l.append(re.compile('^static\s+int\s+hf_param_.*;'))
    strip_re_l.append(re.compile('^#define\s+EVT_STR_[A-Z0-9_]+\s+"[A-Za-z0-9_]+"'))
    strip_re_l.append(re.compile('^#define\s+EVT_[A-Z0-9_]+\s+[0-9]+'))
    strip_re_l.append(re.compile('^\s*{\s*EVT_[A-Z0-9_]+\s*,\s*EVT_STR_[A-Z0-9_]+\s*}'))
    strip_re_l.append(re.compile('^static\s+const\s+int\s+\*\s*[a-z0-9_]+_[ex]_indexes\[\]\s*=\s*\{\s*&hf_param_.*NULL\s*\}\s*;'))
    strip_re_l.append(re.compile('^\s*#define\s+[a-z0-9_]+_[ex]_indexes\s+[a-z0-9_]+_indexes'))
    strip_re_l.append(re.compile('^\s*\{\s*EVT_[A-Z0-9_]+_[EX]\s*,\s*[a-z0-9_]+_[ex]_indexes\s*}\s*,'))
    strip_re_l.append(re.compile('^\s*{\s*&hf_param_.*},')) # Must all be on one line

    for strip_re in strip_re_l:
        dissector_lines = [l for l in dissector_lines if not strip_re.search(l)]

    # Find our value strings
    value_string_re = re.compile('static\s+const\s+value_string\s+([A-Za-z0-9_]+_vals)')
    value_string_l = []
    for line in dissector_lines:
        vs = value_string_re.match(line)
        if vs:
            value_string_l.append(vs.group(1))

    # Add in new content after comments.

    header_fields_c = 'Header fields'
    header_fields_re = re.compile('/\*\s+' + header_fields_c, flags = re.IGNORECASE)
    header_fields_l = []
    for hf_name in sorted(hf_d.keys()):
        header_fields_l.append('static int {} = -1;'.format(hf_name))

    event_names_c = 'Event names'
    event_names_re = re.compile('/\*\s+' + event_names_c, flags = re.IGNORECASE)
    event_names_l = []
    event_str_l = list(set(event_name_l))
    event_str_l.sort()
    for evt_str in event_str_l:
        event_names_l.append('#define EVT_STR_{0:24s} "{1:s}"'.format(evt_str.upper(), evt_str))

    event_definitions_c = 'Event definitions'
    event_definitions_re = re.compile('/\*\s+' + event_definitions_c, flags = re.IGNORECASE)
    event_definitions_l = []
    for evt in event_nums:
        event_definitions_l.append('#define EVT_{0:24s} {1:3d}'.format(event_d[evt], evt))

    value_strings_c = 'Value strings'
    value_strings_re = re.compile('/\*\s+' + value_strings_c, flags = re.IGNORECASE)
    value_strings_l = []
    for evt in event_nums:
        evt_num = 'EVT_{},'.format(event_d[evt])
        evt_str = 'EVT_STR_' + event_name_l[evt].upper()
        value_strings_l.append('    {{ {0:<32s} {1:s} }},'.format(evt_num, evt_str))

    parameter_index_c = 'Parameter indexes'
    parameter_index_re = re.compile('/\*\s+' + parameter_index_c, flags = re.IGNORECASE)
    # parameter_index_l defined above.

    event_tree_c = 'Event tree'
    event_tree_re = re.compile('/\*\s+' + event_tree_c, flags = re.IGNORECASE)
    event_tree_l = []
    for evt in event_nums:
        evt_num = 'EVT_{}'.format(event_d[evt])
        evt_idx = '{}_indexes'.format(event_d[evt].lower())
        event_tree_l.append('    {{ {}, {} }},'.format(evt_num, evt_idx))

    header_field_reg_c = 'Header field registration'
    header_field_reg_re = re.compile('/\*\s+' + header_field_reg_c, flags = re.IGNORECASE)
    header_field_reg_l = []
    for hf_name in sorted(hf_d.keys()):
        param = hf_d[hf_name]
        event_name = param['event_name']
        param_desc = get_param_desc(param)
        param_name = param['param_name']
        param_type = param['param_type']
        param_format = param['param_format']
        fieldconvert = 'NULL'
        vs_name = param_to_value_string_name(param)
        if vs_name in value_string_l and 'INT' in param_type:
            fieldconvert = 'VALS({})'.format(vs_name)
        header_field_reg_l.append('        {{ &{}, {{ "{}", "sysdig.param.{}.{}", FT_{}, BASE_{}, {}, 0, NULL, HFILL }} }},'.format(
            hf_name,
            param_desc,
            event_name,
            param_name,
            param_type,
            param_format,
            fieldconvert
            ))

    for line in dissector_lines:
        fill_comment = None
        fill_l = []

        if header_fields_re.match(line):
            fill_comment = header_fields_c
            fill_l = header_fields_l
        elif event_names_re.match(line):
            fill_comment = event_names_c
            fill_l = event_names_l
        elif event_definitions_re.match(line):
            fill_comment = event_definitions_c
            fill_l = event_definitions_l
        elif value_strings_re.match(line):
            fill_comment = value_strings_c
            fill_l = value_strings_l
        elif parameter_index_re.match(line):
            fill_comment = parameter_index_c
            fill_l = parameter_index_l
        elif event_tree_re.match(line):
            fill_comment = event_tree_c
            fill_l = event_tree_l
        elif header_field_reg_re.match(line):
            fill_comment = header_field_reg_c
            fill_l = header_field_reg_l

        if fill_comment is not None:
            # Write our comment followed by the content
            print('Generating {}, {:d} lines'.format(fill_comment, len(fill_l)))
            dissector_f.write('/* {}. Automatically generated by tools/{} */\n'.format(
                fill_comment,
                os.path.basename(__file__)
                ))
            for line in fill_l:
                dissector_f.write('{}\n'.format(line))
            # Fill each section only once
            del fill_l[:]
        else:
            # Existing content
            dissector_f.write(line)

    dissector_f.close()

#
# On with the show
#

if __name__ == "__main__":
    sys.exit(main())
