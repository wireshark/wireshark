#!/usr/bin/env python3
#
# make-taps.py
#
# By Gerald Combs <gerald@wireshark.org>
# Based on make-taps.pl by Luis E. Garcia Onatnon <luis.ontanon@gmail.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''\
Extract structs from C headers to generate a function that pushes a lua table
into the stack containing the elements of the struct.
'''

import argparse
import configparser
import os
import re
import sys


this_dir = os.path.dirname(__file__)


def get_tap_info(tap_name, header_file, struct_name, enum_types):
    code = f'#include "{header_file}"\n'
    doc = f'Tap: {tap_name}\n'
    enums = {}
    buf = ''

    types = {
        'gchar[]': 'lua_pushstring(L,(const char*)v->STR);',
        'gchar*': 'lua_pushstring(L,(const char*)v->STR);',
        'guint': 'lua_pushnumber(L,(lua_Number)v->STR);',
        'guint8': 'lua_pushnumber(L,(lua_Number)v->STR);',
        'guint16': 'lua_pushnumber(L,(lua_Number)v->STR);',
        'guint32': 'lua_pushnumber(L,(lua_Number)v->STR);',
        'gint': 'lua_pushnumber(L,(lua_Number)v->STR);',
        'gint8': 'lua_pushnumber(L,(lua_Number)v->STR);',
        'gint16': 'lua_pushnumber(L,(lua_Number)v->STR);',
        'gint32': 'lua_pushnumber(L,(lua_Number)v->STR);',
        'gboolean': 'lua_pushboolean(L,(int)v->STR);',
        'address': '{ Address a = (Address)g_malloc(sizeof(address)); copy_address(a, &(v->STR)); pushAddress(L,a); }',
        'address*': '{ Address a = (Address)g_malloc(sizeof(address)); copy_address(a, v->STR); pushAddress(L,a); }',
        'int': 'lua_pushnumber(L,(lua_Number)v->STR);',
        'nstime_t': 'lua_pushnumber(L,(lua_Number)nstime_to_sec(&(v->STR)));',
        'nstime_t*': 'lua_pushnumber(L,(lua_Number)nstime_to_sec(v->STR));',
    }

    comments = {
        'gchar[]': 'string',
        'gchar*': 'string',
        'guint': 'number',
        'guint8': 'number',
        'guint16': 'number',
        'guint32': 'number',
        'gint': 'number',
        'gint8': 'number',
        'gint16': 'number',
        'gint32': 'number',
        'gboolean': 'boolean',
        'address': 'Address',
        'address*': 'Address',
        'int': 'number',
        'nstime_t': 'number (seconds, since 1-1-1970 if absolute)',
        'nstime_t*': 'number (seconds, since 1-1-1970 if absolute)',
    }

    with open(os.path.join(this_dir, header_file), encoding='utf-8') as header_f:
        for line in header_f:
            # Remove comments
            line = re.sub(r'\/\*.*?\*/', '', line)
            line = re.sub(r'//.*', '', line)
            buf += line

    for enum in enum_types:
        m = re.search(fr'typedef\s+enum[^{{]*{{([^}}]*)}}[\s\n]*{enum}[\s\n]*;', buf, flags=re.DOTALL)
        if m:
            types[enum] = f'lua_pushnumber(L,(lua_Number)v->STR); /* {enum} */'
            econsts = m.group(1).splitlines()
            econsts = [re.sub('\s+', '', item) for item in econsts]
            econsts = [re.sub(',', '', item) for item in econsts]
            econsts = [item for item in econsts if item]
            enums[enum] = econsts
            ebody = '|'.join(econsts)
            comments[enum] = f'{enum}: {{ {ebody} }}'

    m = re.search(fr'typedef\s+struct.*?{{([^}}]*)}}[\s\n]*({struct_name})[\s\n]*;', buf, flags=re.DOTALL)
    if not m:
        sys.stderr.write(f'could not find typedef {struct_name} in {header_file}')
        sys.exit(1)

    body = m.group(1)

    elems = {}

    for line in body.splitlines():
        k = None
        v = None

        m = re.search(r'\s*(.*?)([\w\d_]+)\s*\[\s*\d+\s*\]\s*;', line)
        if m:
            k = m.group(2)
            v = m.group(1)
            v += '[]'

        m = re.search(r'\s*(.*?)([\w\d_]+)\s*;', line)
        if m:
            k = m.group(2)
            v = m.group(1)

        if v and k:
            v = re.sub(r'const ', '', v)
            v = re.sub(r'\s+', '', v)
            elems[k] = v

    code += f'static void wslua_{tap_name}_to_table(lua_State* L, const void* p) {{\n\tconst {struct_name}* v;\n\n\tv = (const {struct_name}*)p;\n\tlua_newtable(L);\n\n'

    for el in sorted(elems):
        try:
            fmt = types[elems[el]]
            code += f'\tlua_pushstring(L,\"{el}\");\n\t'
            lua_type = re.sub(r'\bSTR\b', el, fmt)
            code += lua_type
            code += '\n\tlua_settable(L,-3);\n'
            doc += f'\t{el}: {comments[elems[el]]}\n'
        except KeyError:
            pass

    code += "}\n\n"
    doc += "\n"

    return (code, doc, enums)


def main():
    parser = argparse.ArgumentParser(description="Generate bindings required for Lua taps.")
    parser.add_argument("out_c", metavar='C file', help="output C file")
    parser.add_argument("out_doc", metavar='documentation file', help="output text file")
    args = parser.parse_args()

    tap_config = configparser.ConfigParser()
    tap_config.read(os.path.join(this_dir, 'taps.ini'))

    enums = {}
    c_body = '''\
/*  This file is autogenerated from ./taps by ./make-taps.py */
/* DO NOT EDIT! */

#include "config.h"

#include "wslua.h"

#include <wsutil/nstime.h>

'''
    doc_body = '\n'

    for tap_name in tap_config.sections():
        tap_d = tap_config[tap_name]
        enum_types = []
        if 'enum_types' in tap_d.keys():
            enum_types = tap_d['enum_types'].split(' ')
        (code, doc, file_enums) = get_tap_info(tap_name, tap_d['header_file'], tap_d['struct_name'], enum_types)
        c_body += code
        doc_body += doc
        enums.update(file_enums)

    c_body += 'static tappable_t tappables[] =  {\n'
    for tap_name in sorted(tap_config.sections()):
        c_body += f'\t{{"{tap_name}", wslua_{tap_name}_to_table }},\n'
    c_body += '''\
	{"frame",NULL},
	{NULL,NULL}
};
'''

    c_body += '\nint wslua_set_tap_enums(lua_State* L) {\n'
    for enum in sorted(enums):
        c_body += f'\n\t/*\n\t * {enum}\n\t */\n\tlua_newtable(L);\n'
        for econst in enums[enum]:
            c_body += f'''\
	lua_pushnumber(L,(lua_Number){econst});
	lua_setglobal(L,"{econst}");
	lua_pushnumber(L,(lua_Number){econst});
	lua_pushstring(L,"{econst}");
	lua_settable(L,-3);
'''
        c_body += f'\tlua_setglobal(L,\"{enum}\");\n'
    c_body += '\treturn 0;\n}\n'

    c_body += '''\


tap_extractor_t wslua_get_tap_extractor(const gchar* name) {
	tappable_t* t;
	for(t = tappables; t->name; t++ ) {
		if (g_str_equal(t->name,name)) return t->extractor;
	}

	return NULL;
}
'''

    with open(args.out_c, mode='w', encoding='utf-8') as out_c_f:
        out_c_f.write(c_body)

    with open(args.out_doc, mode='w', encoding='utf-8') as out_doc_f:
        out_doc_f.write(doc_body)

if __name__ == '__main__':
    main()
