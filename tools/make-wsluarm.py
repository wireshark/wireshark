#!/usr/bin/env python3
#
# make-wsluarm.py
#
# By Gerald Combs <gerald@wireshark.org>
# Based on make-wsluarm.pl by Luis E. Garcia Onatnon <luis.ontanon@gmail.com> and Hadriel Kaplan
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''\
WSLUA's Reference Manual Generator

This reads Doxygen-style comments in C code and generates wslua API documentation
formatted as AsciiDoc.

Behavior as documented by Hadriel:
- Allows modules (i.e., WSLUA_MODULE) to have detailed descriptions
- Two (or more) line breaks in comments result in separate paragraphs
- Any indent with a single leading star '*' followed by space is a bulleted list item
  reducing indent or having an extra linebreak stops the list
- Any indent with a leading digits-dot followed by space, i.e. "1. ", is a numbered list item
  reducing indent or having an extra linebreak stops the list
'''

import argparse
import logging
import os
import re
import sys

from enum import Enum
from string import Template

def parse_desc(description):
    '''\
Break up descriptions based on newlines and keywords. Some processing
is done for code blocks and lists, but the output is otherwise left
intact. Assumes the input has been stripped.
'''

    c_lines = description.strip().splitlines()

    if len(c_lines) < 1:
        return ''

    adoc_lines = []
    cli = iter(c_lines)
    for line in cli:
        raw_len = len(line)
        line = line.lstrip()
        indent = raw_len - len(line)

        # If we find "[source,...]" then treat it as a block
        if re.search(r'\[source.*\]', line):
            # The next line *should* be a delimiter...
            block_delim = next(cli).strip()
            line += f'\n{block_delim}\n'
            block_line = next(cli)
            # XXX try except StopIteration
            while block_line.strip() != block_delim:
                # Keep eating lines until the closing delimiter.
                # XXX Strip indent spaces?
                line += block_line + '\n'
                block_line = next(cli)
            line += block_delim + '\n'

            adoc_lines.append(line)
        elif re.match(r'^\s*$', line):
            # line is either empty or just whitespace, and we're not in a @code block
            # so it's the end of a previous paragraph, beginning of new one
            adoc_lines.append('')
        else:
            # We have a regular line, not in a @code block.
            # Add it as-is.

            # if line starts with "@version" or "@since", make it a "Since:"
            if re.match(r'^@(version|since)\s+', line):
                line = re.sub(r'^@(version|since)\s+', 'Since: ', line)
                adoc_lines.append(line)

            # If line starts with single "*" and space, leave it mostly intact.
            elif re.match(r'^\*\s', line):
                adoc_lines += ['', line]
                # keep eating until we find a blank line or end
                line = next(cli)
                try:
                    while not re.match(r'^\s*$', line):
                        raw_len = len(line)
                        line = line.lstrip()
                        # if this is less indented than before, break out
                        if raw_len - len(line) < indent:
                            break
                        adoc_lines += [line]
                        line = next(cli)
                except StopIteration:
                    pass
                adoc_lines.append('')

            # if line starts with "1." and space, leave it mostly intact.
            elif re.match(r'^1\.\s', line):
                adoc_lines += ['', line]
                # keep eating until we find a blank line or end
                line = next(cli)
                try:
                    while not re.match(r'^\s*$', line):
                        raw_len = len(line)
                        line = line.lstrip()
                        # if this is less indented than before, break out
                        if raw_len - len(line) < indent:
                            break
                        adoc_lines += [line]
                        line = next(cli)
                except StopIteration:
                    pass
                adoc_lines.append('')

            # Just a normal line, add it to array
            else:
                # Nested Lua arrays
                line = re.sub(r'\[\[(.*)\]\]', r'$$\1$$', line)
                adoc_lines += [line]

    # Strip out consecutive empty lines.
    # This isn't strictly necessary but makes the AsciiDoc output prettier.
    adoc_lines = '\n'.join(adoc_lines).splitlines()
    adoc_lines = [val for idx, val in enumerate(adoc_lines) if idx == 0 or not (val == '' and val == adoc_lines[idx - 1])]

    return '\n'.join(adoc_lines)


class LuaFunction:
    def __init__(self, c_file, id, start, name, raw_description):
        self.c_file = c_file
        self.id = id
        self.start = start
        self.name = name
        if not raw_description:
            raw_description = ''
        self.description = parse_desc(raw_description)
        self.arguments = [] # (name, description, optional)
        self.returns = [] # description
        self.errors = [] # description
        logging.info(f'Created function {id} ({name}) at {start}')

    def add_argument(self, id, raw_name, raw_description, raw_optional):
        if id != self.id:
            logging.critical(f'Invalid argument ID {id} in function {self.id}')
            sys.exit(1)
        if not raw_description:
            raw_description = ''
        optional = False
        if raw_optional == 'OPT':
            optional = True
        self.arguments.append((raw_name.lower(), parse_desc(raw_description), optional))

    def extract_buf(self, buf):
        "Extract arguments, errors, and return values from a function's buffer."

        # Splits "WSLUA_OPTARG_ProtoField_int8_NAME /* food */" into
        # "OPT" (1), "ProtoField_int8" (2), "NAME" (3), ..., ..., " food " (6)
        # Handles functions like "loadfile(filename)" too.
        for m in re.finditer(r'#define WSLUA_(OPT)?ARG_((?:[A-Za-z0-9]+_)?[a-z0-9_]+)_([A-Z0-9_]+)\s+\d+' + TRAILING_COMMENT_RE, buf, re.MULTILINE|re.DOTALL):
            self.add_argument(m.group(2), m.group(3), m.group(6), m.group(1))
            logging.info(f'Created arg {m.group(3)} for {self.id} at {m.start()}')

        # Same as above, except that there is no macro but a (multi-line) comment.
        for m in re.finditer(r'/\*\s*WSLUA_(OPT)?ARG_((?:[A-Za-z0-9]+_)?[a-z0-9_]+)_([A-Z0-9_]+)\s*(.*?)\*/', buf, re.MULTILINE|re.DOTALL):
            self.add_argument(m.group(2), m.group(3), m.group(4), m.group(1))
            logging.info(f'Created arg {m.group(3)} for {self.id} at {m.start()}')

        for m in re.finditer(r'/\*\s+WSLUA_MOREARGS\s+([A-Za-z_]+)\s+(.*?)\*/', buf, re.MULTILINE|re.DOTALL):
            self.add_argument(m.group(1), '...', m.group(2), False)
            logging.info(f'Created morearg for {self.id}')

        for m in re.finditer(r'WSLUA_(FINAL_)?RETURN\(\s*.*?\s*\)\s*;' + TRAILING_COMMENT_RE, buf, re.MULTILINE|re.DOTALL):
            if m.group(4) and len(m.group(4)) > 0:
                self.returns.append(m.group(4).strip())
                logging.info(f'Created return for {self.id} at {m.start()}')

        for m in re.finditer(r'/\*\s*_WSLUA_RETURNS_\s*(.*?)\*/', buf, re.MULTILINE|re.DOTALL):
            if m.group(1) and len(m.group(1)) > 0:
                self.returns.append(m.group(1).strip())
                logging.info(f'Created return for {self.id} at {m.start()}')

        for m in re.finditer(r'WSLUA_ERROR\s*\(\s*(([A-Z][A-Za-z]+)_)?([a-z_]+),' + QUOTED_RE, buf, re.MULTILINE|re.DOTALL):
            self.errors.append(m.group(4).strip())
            logging.info(f'Created error {m.group(4)[:10]} for {self.id} at {m.start()}')

    def to_adoc(self):
        # The Perl script wrapped optional args in '[]', joined them with ', ', and
        # converted non-alphabetic characters to underscores.
        mangled_names = [f'_{a}_' if optional else a for a, _, optional in self.arguments]
        section_name = re.sub('[^A-Za-z0-9]', '_', f'{self.name}_{"__".join(mangled_names)}_')
        opt_names = [f'[{a}]' if optional else a for a, _, optional in self.arguments]
        adoc_buf = f'''
// {self.c_file}
[#lua_fn_{section_name}]
===== {self.name}({', '.join(opt_names)})

{self.description}
'''
        if len(self.arguments) > 0:
            adoc_buf += '''
[float]
===== Arguments
'''
        for (name, description, optional) in self.arguments:
            if optional:
                name += ' (optional)'
            adoc_buf += f'\n{name}::\n'

            if len(description) > 0:
                adoc_buf += f'\n{description}\n'

            adoc_buf += f'\n// function_arg_footer: {name}'

        if len(self.arguments) > 0:
            adoc_buf += '\n// end of function_args\n'

        if len(self.returns) > 0:
            adoc_buf += '''
[float]
===== Returns
'''
        for description in self.returns:
            adoc_buf += f'\n{description}\n'

        if len(self.returns) > 0:
            adoc_buf += f'\n// function_returns_footer: {self.name}'

        if len(self.errors) > 0:
            adoc_buf += '''
[float]
===== Errors
'''
        for description in self.errors:
            adoc_buf += f'\n* {description}\n'

        if len(self.errors) > 0:
            adoc_buf += f'\n// function_errors_footer: {self.name}'

        adoc_buf += f'\n// function_footer: {section_name}\n'

        return adoc_buf


# group 1: whole trailing comment (possibly empty), e.g. " /* foo */"
# group 2: any leading whitespace. XXX why is this not removed using (?:...)
# group 3: actual comment text, e.g. " foo ".
TRAILING_COMMENT_RE = r'((\s*|[\n\r]*)/\*(.*?)\*/)?'
IN_COMMENT_RE       = r'[\s\r\n]*((.*?)\s*\*/)?'
QUOTED_RE           = r'"([^"]*)"'

# XXX We might want to create a "LuaClass" class similar to LuaFunction
# and move these there.
def extract_class_definitions(c_file, c_buf, module, classes, functions):
    for m in re.finditer(r'WSLUA_CLASS_DEFINE(?:_BASE)?\(\s*([A-Z][a-zA-Z0-9]+).*?\);' + TRAILING_COMMENT_RE, c_buf, re.MULTILINE|re.DOTALL):
        raw_desc = m.group(4)
        if raw_desc is None:
            raw_desc = ''
        name = m.group(1)
        mod_class = {
            'description': parse_desc(raw_desc),
            'constructors': [],
            'methods': [],
            'attributes': [],
        }
        classes[name] = mod_class
        logging.info(f'Created class {name}')
    return 0

def extract_function_definitions(c_file, c_buf, module, classes, functions):
    for m in re.finditer(r'WSLUA_FUNCTION\s+wslua_([a-z_0-9]+)[^\{]*\{' + TRAILING_COMMENT_RE, c_buf, re.MULTILINE|re.DOTALL):
        id = m.group(1)
        functions[id] = LuaFunction(c_file, id, m.start(), id, m.group(4))

def extract_constructor_definitions(c_file, c_buf, module, classes, functions):
    for m in re.finditer(r'WSLUA_CONSTRUCTOR\s+([A-Za-z0-9]+)_([a-z0-9_]+).*?\{' + TRAILING_COMMENT_RE, c_buf, re.MULTILINE|re.DOTALL):
        class_name = m.group(1)
        id = f'{class_name}_{m.group(2)}'
        name = f'{class_name}.{m.group(2)}'
        functions[id] = LuaFunction(c_file, id, m.start(), name, m.group(5))
        classes[class_name]['constructors'].append(id)

def extract_constructor_markups(c_file, c_buf, module, classes, functions):
    for m in re.finditer(r'_WSLUA_CONSTRUCTOR_\s+([A-Za-z0-9]+)_([a-z0-9_]+)\s*(.*?)\*/', c_buf, re.MULTILINE|re.DOTALL):
        class_name = m.group(1)
        id = f'{class_name}_{m.group(2)}'
        name = f'{class_name}.{m.group(2)}'
        functions[id] = LuaFunction(c_file, id, m.start(), name, m.group(3))
        classes[class_name]['constructors'].append(id)

def extract_method_definitions(c_file, c_buf, module, classes, functions):
    for m in re.finditer(r'WSLUA_METHOD\s+([A-Za-z0-9]+)_([a-z0-9_]+)[^\{]*\{' + TRAILING_COMMENT_RE, c_buf, re.MULTILINE|re.DOTALL):
        class_name = m.group(1)
        id = f'{class_name}_{m.group(2)}'
        name = f'{class_name.lower()}:{m.group(2)}'
        functions[id] = LuaFunction(c_file, id, m.start(), name, m.group(5))
        classes[class_name]['methods'].append(id)

def extract_metamethod_definitions(c_file, c_buf, module, classes, functions):
    for m in re.finditer(r'WSLUA_METAMETHOD\s+([A-Za-z0-9]+)(__[a-z0-9]+)[^\{]*\{' + TRAILING_COMMENT_RE, c_buf, re.MULTILINE|re.DOTALL):
        class_name = m.group(1)
        id = f'{class_name}{m.group(2)}'
        name = f'{class_name.lower()}:{m.group(2)}'
        functions[id] = LuaFunction(c_file, id, m.start(), name, m.group(5))
        classes[class_name]['methods'].append(id)

def extract_attribute_markups(c_file, c_buf, module, classes, functions):
    for m in re.finditer(r'/\*\s+WSLUA_ATTRIBUTE\s+([A-Za-z0-9]+)_([a-z0-9_]+)\s+([A-Z]*)\s*(.*?)\*/', c_buf, re.MULTILINE|re.DOTALL):
        class_name = m.group(1)
        name = f'{m.group(1).lower()}.{m.group(2)}'
        mode = m.group(3)
        mode_desc = 'Mode: '
        if 'RO' in mode:
            mode_desc += 'Retrieve only.\n'
        elif 'WO' in mode:
            mode_desc += 'Assign only.\n'
        elif 'RW' in mode or 'WR' in mode:
            mode_desc += 'Retrieve or assign.\n'
        else:
            sys.stderr.write(f'Attribute does not have a RO/WO/RW mode {mode}\n')
            sys.exit(1)

        attribute = {
            'name': name,
            'description': parse_desc(f'{mode_desc}\n{m.group(4)}'),
        }
        classes[class_name]['attributes'].append(attribute)
        logging.info(f'Created attribute {name} for class {class_name}')

def main():
    parser = argparse.ArgumentParser(description="WSLUA's Reference Manual Generator")
    parser.add_argument("c_files", nargs='+', metavar='C file', help="C file")
    parser.add_argument('--output-directory', help='Output directory')
    parser.add_argument('--verbose', action='store_true', help='Show more output')
    args = parser.parse_args()

    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG if args.verbose else logging.WARNING)

    modules = {}

    for c_file in args.c_files:
        with open(c_file, encoding='utf-8') as c_f:
            c_buf = c_f.read()

            # Peek for modules vs continuations.
            m = re.search(r'WSLUA_(|CONTINUE_)MODULE\s*(\w+)', c_buf)
            if m:
                module_name = m.group(2)
                c_pair = (os.path.basename(c_file), c_buf)
                try:
                    if m.group(1) == 'CONTINUE_':
                        modules[module_name]['c'].append(c_pair)
                    else:
                        modules[module_name]['c'].insert(0, c_pair)
                except KeyError:
                    modules[module_name] = {}
                    modules[module_name]['c'] = [c_pair]
                    modules[module_name]['file_base'] = os.path.splitext(c_pair[0])[0]
            else:
                logging.warning(f'No module found in {c_file}')

    extractors = [
        extract_class_definitions,
        extract_function_definitions,
        extract_constructor_definitions,
        extract_constructor_markups,
        extract_method_definitions,
        extract_metamethod_definitions,
        extract_attribute_markups,
    ]

    for module_name in sorted(modules):
        adoc_file = f'{modules[module_name]["file_base"]}.adoc'
        logging.info(f'Writing module {module_name} to {adoc_file} from {len(modules[module_name]["c"])} input(s)')
        functions = {}
        classes = {}

        # Extract our module's description.
        m = re.search(r'WSLUA_MODULE\s*[A-Z][a-zA-Z0-9]+' + IN_COMMENT_RE, modules[module_name]['c'][0][1], re.MULTILINE|re.DOTALL)
        if not m:
            return
        modules[module_name]['description'] = parse_desc(f'{m.group(2)}')

        # Extract module-level information from each file.
        for (c_file, c_buf) in modules[module_name]['c']:
            for extractor in extractors:
                extractor(c_file, c_buf, modules[module_name], classes, functions)

        # Extract function-level information from each file.
        for (c_file, c_buf) in modules[module_name]['c']:
            c_file_ids = filter(lambda k: functions[k].c_file == c_file, functions.keys())
            func_ids = sorted(c_file_ids, key=lambda k: functions[k].start)
            id = func_ids.pop(0)
            for next_id in func_ids:
                functions[id].extract_buf(c_buf[functions[id].start:functions[next_id].start])
                id = next_id
            functions[id].extract_buf(c_buf[functions[id].start:])

        with open(os.path.join(args.output_directory, adoc_file), 'w', encoding='utf-8') as adoc_f:
            adoc_f.write(f'''\
// {c_file}
[#lua_module_{module_name}]
=== {modules[module_name]["description"]}
''')
            for class_name in sorted(classes.keys()):
                lua_class = classes[class_name]
                adoc_f.write(f'''
// {c_file}
[#lua_class_{class_name}]
==== {class_name}
''')

                if not lua_class["description"] == '':
                    adoc_f.write(f'\n{lua_class["description"]}\n')

                for constructor_id in sorted(lua_class['constructors'], key=lambda id: functions[id].start):
                    adoc_f.write(functions[constructor_id].to_adoc())
                    del functions[constructor_id]

                for method_id in sorted(lua_class['methods'], key=lambda id: functions[id].start):
                    adoc_f.write(functions[method_id].to_adoc())
                    del functions[method_id]

                for attribute in lua_class['attributes']:
                    attribute_id = re.sub('[^A-Za-z0-9]', '_', f'{attribute["name"]}')
                    adoc_f.write(f'''
[#lua_class_attrib_{attribute_id}]
===== {attribute["name"]}

{attribute["description"]}

// End {attribute["name"]}
''')


                adoc_f.write(f'\n// class_footer: {class_name}\n')

            if len(functions.keys()) > 0:
                adoc_f.write(f'''\
[#global_functions_{module_name}]
==== Global Functions
''')

            for global_id in sorted(functions.keys(), key=lambda id: functions[id].start):
                adoc_f.write(functions[global_id].to_adoc())

            if len(functions.keys()) > 0:
                adoc_f.write(f'// Global function\n')

            adoc_f.write('// end of module\n')

if __name__ == '__main__':
    main()
