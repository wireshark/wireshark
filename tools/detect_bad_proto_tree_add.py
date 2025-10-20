#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: MIT

"""
Detect use of the 'wrong' proto_tree_add_* function.

There are three versions of each proto_tree_add_* function:
* proto_tree_add_uint              (proto_tree *tree, int hfindex, tvbuff_t *tvb, int start, int length, uint32_t value)
* proto_tree_add_uint_format_value (proto_tree *tree, int hfindex, tvbuff_t *tvb, int start, int length, uint32_t value, const char *format,...)
* proto_tree_add_uint_format       (proto_tree *tree, int hfindex, tvbuff_t *tvb, int start, int length, uint32_t value, const char *format,...)

These all operate slightly differently:
* proto_tree_add_uint adds a value using the hfindex's label.
* proto_tree_add_uint_format_value adds a value using the hfindex's label and the supplied format string.
* proto_tree_add_uint_format adds a label and a value using the supplied format string.

Additionally, proto_tree_add_item will directly extract the item from the tvb and use that

For memory and performance efficiency, our preference is the following:

If the generated field name is hardcoded in the format string and the same as the hfindex's label,
instead of using:
    proto_tree_add_uint_format
use:
    proto_tree_add_uint_format_value

If the format string is a single value, instead of using:
    proto_tree_add_uint_format_value
use:
    proto_tree_add_uint

This script attempts to detect these across the entire codebase.

Additional notes on function calls:
    //                                                                           Value and Displayed Value
    proto_tree_add_string(             tree, hf_http_x_forwarded_for, tvb, 0, 3, "proto_tree_add_string()");
    //                                                                           Value                           Displayed Label + Value
    proto_tree_add_string_format(      tree, hf_http_x_forwarded_for, tvb, 0, 4, "proto_tree_add_string_format", "proto_tree_add_string_format(abc)");
    //                                                                           Value                           Displayed Value
    proto_tree_add_string_format_value(tree, hf_http_x_forwarded_for, tvb, 0, 5, "proto_tree_add_string_format", "proto_tree_add_string_format(def)");
    //                                                 Extract Value and type
    proto_tree_add_item(tree, hf_http_x_forwarded_for, tvb, 0, 6, FT_STRING);
"""

import argparse
import os
import re
import sys


def replace_file(fpath, make_replacements):
    replace_cnt = 0
    replace_cnt += replace_proto_tree_add_STAR_format(fpath, make_replacements)
    replace_cnt += replace_proto_tree_add_STAR_format_value(fpath, make_replacements)
    return replace_cnt


def extract_arg_by_index(func_str, target_index):
    """
    Extract the Nth argument from a string of a C function call.

    Args:
        func_str (str): The full function call string.
        target_index (int): Zero-based index of the argument to extract.

    Returns:
        str: The extracted argument, or None if not found.
    """
    # Find the opening parenthesis
    start = func_str.find('(')
    if start == -1:
        return None

    args = []
    current = ''
    depth = 0
    in_string = False
    escape = False

    for c in func_str[start + 1:]:
        if escape:
            current += c
            escape = False
            continue

        if c == '\\':
            current += c
            escape = True
            continue

        if c == '"':
            in_string = not in_string
            current += c
            continue

        if in_string:
            current += c
            continue

        if c == '(':
            depth += 1
            current += c
        elif c == ')':
            if depth == 0:
                args.append(current.strip())
                break
            depth -= 1
            current += c
        elif c == ',' and depth == 0:
            args.append(current.strip())
            current = ''
        else:
            current += c

    if len(args) > target_index:
        return args[target_index]
    return None


def remove_argument_by_position(func_str, target_index):
    """
    Remove the Nth argument from a C-style function call string while preserving
    original whitespace and formatting as much as possible.

    Args:
        func_str (str): The full function call string (one function call).
        target_index (int): Zero-based index of the argument to remove.

    Returns:
        str: The function call string with the specified argument removed.
    """
    start = func_str.find('(')
    if start == -1:
        return func_str

    args_spans = []       # list of (arg_start, arg_end) for argument contents
    sep_spans = []        # list of (sep_start, sep_end) for separator AFTER each arg (comma + whitespace)
    i = start + 1
    length = len(func_str)
    depth = 0
    in_string = False
    escape = False
    arg_start = i

    while i < length:
        c = func_str[i]

        if escape:
            escape = False
            i += 1
            continue

        if c == '\\':
            escape = True
            i += 1
            continue

        if c == '"':
            in_string = not in_string
            i += 1
            continue

        if in_string:
            i += 1
            continue

        if c == '(':
            depth += 1
            i += 1
            continue

        if c == ')':
            if depth == 0:
                # end of final arg
                arg_end = i
                args_spans.append((arg_start, arg_end))
                sep_spans.append(None)
                break
            depth -= 1
            i += 1
            continue

        if c == ',' and depth == 0:
            # end of current arg at i (comma position)
            arg_end = i
            args_spans.append((arg_start, arg_end))
            # compute separator span: comma plus following whitespace
            sep_start = i
            j = i + 1
            while j < length and func_str[j].isspace():
                j += 1
            sep_spans.append((sep_start, j))
            # next arg starts at j
            arg_start = j
            i = j
            continue

        i += 1

    # If parsing failed to collect any args, bail
    if not args_spans:
        return func_str

    if target_index < 0 or target_index >= len(args_spans):
        return func_str

    # Decide removal span
    arg_start, arg_end = args_spans[target_index]
    # if there's a following separator, remove arg + that separator
    if sep_spans[target_index]:
        sep_start, sep_end = sep_spans[target_index]
        remove_start = arg_start
        remove_end = sep_end
        result = func_str[:remove_start] + func_str[remove_end:]
        return result
    else:
        # last argument: try to remove preceding comma + whitespace before arg
        # look backwards from arg_start to find comma, skipping whitespace
        j = arg_start - 1
        while j >= 0 and func_str[j].isspace():
            j -= 1
        if j >= 0 and func_str[j] == ',':
            # include the comma and preceding whitespace between previous token and comma
            # remove from comma to arg_end
            comma_idx = j
            # also remove any whitespace between comma and arg_start (we already skipped them)
            # return string with that region removed
            return func_str[:comma_idx] + func_str[arg_end:]
        else:
            # no preceding comma found, just remove arg content
            return func_str[:arg_start] + func_str[arg_end:]


def replace_argument_by_position(func_str, target_index, new_value):
    """
    Replace the Nth argument in a C-style function call string with new_value,
    preserving original separators and whitespace as much as possible.

    Args:
        func_str (str): The full function call string (one function call).
        target_index (int): Zero-based index of the argument to replace.
        new_value (str): The replacement text to place for that argument.

    Returns:
        str: The function call string with the specified argument replaced.
    """
    start = func_str.find('(')
    if start == -1:
        return func_str

    args_spans = []       # list of (arg_start, arg_end) for argument contents
    sep_spans = []        # list of (sep_start, sep_end) for separator AFTER each arg (comma + whitespace) or None for final arg
    i = start + 1
    length = len(func_str)
    depth = 0
    in_string = False
    escape = False
    arg_start = i

    while i < length:
        c = func_str[i]

        if escape:
            escape = False
            i += 1
            continue

        if c == '\\':
            escape = True
            i += 1
            continue

        if c == '"':
            in_string = not in_string
            i += 1
            continue

        if in_string:
            i += 1
            continue

        if c == '(':
            depth += 1
            i += 1
            continue

        if c == ')':
            if depth == 0:
                arg_end = i
                args_spans.append((arg_start, arg_end))
                sep_spans.append(None)
                break
            depth -= 1
            i += 1
            continue

        if c == ',' and depth == 0:
            arg_end = i
            args_spans.append((arg_start, arg_end))
            sep_start = i
            j = i + 1
            while j < length and func_str[j].isspace():
                j += 1
            sep_spans.append((sep_start, j))
            arg_start = j
            i = j
            continue

        i += 1

    if not args_spans:
        return func_str

    if target_index < 0 or target_index >= len(args_spans):
        return func_str

    # Replace argument content
    arg_start, arg_end = args_spans[target_index]

    # For non-final args, arg_end points at the comma; for final args arg_end points at ')'.
    # Replace the exact span [arg_start:arg_end) with new_value.
    return func_str[:arg_start] + new_value + func_str[arg_end:]


def replace_proto_tree_add_STAR_format_value(fpath, make_replacements):
    """
    Attempts to replace calls to proto_tree_add_*_format_value with proto_tree_add_*
    For example, this would replace:
    * proto_tree_add_uint_format_value (proto_tree *tree, int hfindex, tvbuff_t *tvb, int start, int length, uint32_t value, const char *format,...)
    With:
    * proto_tree_add_uint              (proto_tree *tree, int hfindex, tvbuff_t *tvb, int start, int length, uint32_t value)

    This is only equivalent if the 'format' (post-string formatting) is equal to the 'value'.
    The easiest way to determine that is if the format string only has a single value (like %d), and then you have something like:
        proto_tree_add_uint_format_value(tree, hfindex, tvb, start, length, value, "%d", value)

    """
    with open(fpath, 'r') as fh:
        fdata_orig = fh.read()
    replace_cnt = 0
    pattern = r"proto_tree_add_([a-z0-9]+)_format_value\s*.+?\)\s*;"
    FORMAT_ARG_INDEX = 6

    def repl(match):
        nonlocal replace_cnt
        # match.group(0) contains the entire function call
        # match.group(1) contains the object type
        func_call_str = match.group(0)

        format_arg = extract_arg_by_index(func_call_str, FORMAT_ARG_INDEX)
        if format_arg is None:
            # For whatever reason, there is no 6th argument:
            sys.stderr.write(f"Failed to extract arg #{FORMAT_ARG_INDEX} from {fpath}: {func_call_str}\n")
            return func_call_str
        # Now that we have the 'format' arg, see if the format string only contains that single value:
        if not re.match(r'^"%l*[a-zA-Z]"', format_arg):
            return func_call_str
        # Now we need that the displayed value is the same as the actual value:
        field_value = extract_arg_by_index(func_call_str, FORMAT_ARG_INDEX - 1)
        display_value = extract_arg_by_index(func_call_str, FORMAT_ARG_INDEX + 1)
        if field_value != display_value:
            return func_call_str
        # proto_tree_add_uint_format (proto_tree *tree, int hfindex, tvbuff_t *tvb, int start, int length, uint32_t value, const char *format,...)

        print(f"Candidate match found in {fpath}!")
        print(f"{func_call_str}")
        # Now make the replacement:
        new_func_call_str = re.sub(r"^proto_tree_add_(\w+)_format_value", r"proto_tree_add_\1", func_call_str)
        new_func_call_str = remove_argument_by_position(new_func_call_str, FORMAT_ARG_INDEX + 1)
        new_func_call_str = remove_argument_by_position(new_func_call_str, FORMAT_ARG_INDEX)
        print(f"{new_func_call_str}")
        print("*"*80)
        replace_cnt += 1
        return new_func_call_str
    fdata_out = re.sub(pattern, repl, fdata_orig, flags=re.DOTALL)

    if make_replacements and replace_cnt:
        with open(fpath, 'w', encoding='utf-8') as fh:
            fh.write(fdata_out)
    return replace_cnt


def replace_proto_tree_add_STAR_format(fpath, make_replacements):
    """
    Attempts to replace calls to proto_tree_add_*_format with proto_tree_add_*_format_value
    For example, this would replace:
    * proto_tree_add_uint_format       (proto_tree *tree, int hfindex, tvbuff_t *tvb, int start, int length, uint32_t value, "Foo : Bar ",...)
    With:
    * proto_tree_add_uint_format_value (proto_tree *tree, int hfindex, tvbuff_t *tvb, int start, int length, uint32_t value, "Bar",...)

    This is only equivalent if proto_tree_add_uint_format's 'format' begins with the label from the hfindex.

    The easiest way to determine that is if the format string only has a single value (like %d), and then you have something like:
        proto_tree_add_uint_format_value(tree, hfindex, tvb, start, length, value, "%d", value)

    """
    with open(fpath, 'r') as fh:
        fdata_orig = fh.read()
    replace_cnt = 0
    pattern = r"proto_tree_add_([a-z0-9]+)_format\s*\(\s*.+?\)\s*;"
    HFINDEX_ARG_INDEX = 1
    FORMAT_ARG_INDEX = 6

    def repl(match):
        nonlocal replace_cnt
        # match.group(0) contains the entire function call
        # match.group(1) contains the object type
        func_call_str = match.group(0)
        object_type = match.group(1)

        # Ignore proto_tree_add_protocol_format
        if object_type == 'protocol':
            return func_call_str

        # TODO: Should this be revisited?
        # Ignore proto_tree_add_none_format
        if object_type == 'none':
            return func_call_str

        # Try to ignore references in comments
        if func_call_str.startswith("proto_tree_add_bytes_format()"):
            return func_call_str
        if func_call_str.startswith("proto_tree_add_subtree_format(tree, tvb, offset, -1, */"):
            return func_call_str

        format_arg = extract_arg_by_index(func_call_str, FORMAT_ARG_INDEX)
        if format_arg is None:
            sys.stderr.write(f"Failed to extract arg #{FORMAT_ARG_INDEX} from {fpath}: {func_call_str}\n")
            return func_call_str
        # Now that we have the 'format' arg, see if the format string contains a label (Label : Value):
        if ":" not in format_arg:
            return func_call_str
        label, value = format_arg.split(":", 1)
        # remove leading double quote and whitespace
        label = label.rstrip()[1:]
        # This is not guaranteed to end with a double quote, so we'll have to check for that
        value = value.lstrip()

        # Confirm the label is static:
        if "%" in label:
            return func_call_str

        # Confirm the hfindex has this label
        hfindex_arg = extract_arg_by_index(func_call_str, HFINDEX_ARG_INDEX)
        hfindex_patt = f'&{hfindex_arg}' + r'\s*,\s*\{\s*"([^"]+)"'
        hfindex_label_match = re.search(hfindex_patt, fdata_orig, flags=re.DOTALL)
        if hfindex_label_match is None:
            return func_call_str
        hfindex_label = hfindex_label_match.groups()[0]
        if label != hfindex_label:
            return func_call_str

        print(f"Candidate match found in {fpath}!")
        print(f"{func_call_str}")
        # If the format string is non-empty, call proto_tree_add_(\w+)_format:
        if value and value != '"':
            # Now replace the function call:
            new_func_call_str = re.sub(r"^proto_tree_add_(\w+)_format", r"proto_tree_add_\1_format_value", func_call_str)
            # And replace the format string with the version without the label
            new_func_call_str = replace_argument_by_position(new_func_call_str, FORMAT_ARG_INDEX, f'"{value}')
        else:
            # Now replace the function call:
            new_func_call_str = re.sub(r"^proto_tree_add_(\w+)_format", r"proto_tree_add_\1", func_call_str)
            # And remove the label, but re-add the quotation mark
            new_func_call_str = remove_argument_by_position(new_func_call_str, FORMAT_ARG_INDEX)
        print(f"{new_func_call_str}")
        print("*"*80)
        replace_cnt += 1
        return new_func_call_str
    fdata_out = re.sub(pattern, repl, fdata_orig, flags=re.DOTALL)

    if make_replacements and replace_cnt:
        with open(fpath, 'w', encoding='utf-8') as fh:
            fh.write(fdata_out)
    return replace_cnt


def run_specific_file(fpath, make_replacements):
    replace_cnt = 0
    if (fpath.endswith('.c') or fpath.endswith('.cpp')):
        replace_cnt += replace_file(fpath, make_replacements)
    return replace_cnt


def run_recursive(fpath, make_replacements):
    replace_cnt = 0
    if os.path.isdir(fpath):
        for root, dirs, files in os.walk(fpath):
            for fname in files:
                target_fpath = os.path.join(root, fname)
                replace_cnt += run_specific_file(target_fpath, make_replacements)
    elif os.path.isfile(fpath):
        replace_cnt += run_specific_file(fpath, make_replacements)
    return replace_cnt


def test_replacements():
    test_string = """\
"""
    expected_output = """\
"""
    output = test_string
    # Do processing here

    assert (output == expected_output)


def main():
    test_replacements()
    parser = argparse.ArgumentParser(
        description="Examine one or more .c/cpp files or directories for bad proto_tree_add_* calls"
    )
    parser.add_argument('--make-replacements', help="If present, enables inline replacements", action='store_true')
    parser.add_argument("paths", nargs="*", help=("File or directory to process."))

    args = parser.parse_args()
    make_replacements = args.make_replacements

    replace_cnt = 0
    # Args can be passed either as CLI args:
    if args.paths:
        for fpath in args.paths:
            replace_cnt += run_recursive(fpath, make_replacements)
    # Or as stdin:
    else:
        fpaths = []
        for line in sys.stdin:
            line = line.strip()
            if line:
                fpaths.append(line)
        for fpath in fpaths:
            replace_cnt += run_recursive(fpath, make_replacements)
    if replace_cnt > 0:
        if make_replacements:
            print(f"Total replacements made: {replace_cnt}")
        else:
            print(f"Total suggested replacements: {replace_cnt}")


if __name__ == "__main__":
    main()
