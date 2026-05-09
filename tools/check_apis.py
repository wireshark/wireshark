#!/usr/bin/env python3
#
# Copyright 2006, Jeff Morriss <jeff.morriss.ws[AT]gmail.com>
# A simple tool to check source code for function calls that should not
# be called by Wireshark code and to perform certain other checks.
#
# This was originally written in Perl, and translated to Python
# using AI assistance.
#
#
# Usage:
# check-apis.py [-M] [-g group1] [-g group2] ...
#               [-s summary-group1] [-s summary-group2] ...
#               [--nocheck-hf]
#               [--nocheck-value-string-array]
#               [--nocheck-shadow]
#               [--debug]
#               file1 file2 ...
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse
import os
import re
import sys


APIs = {
    # API groups.
    # Group name, e.g. 'prohibited'
    # '<name>': {
    #   'count_errors'   : True,                  # True if these are errors, False if warnings
    #   'functions'      : [ 'f1', 'f2', ...],    # Function array
    #   'function-counts': {'f1',0, 'f2',0, ...}, # Function Counts hash (initialized in the code)
    # }
    #
    # APIs that MUST NOT be used in Wireshark
    'prohibited': {'count_errors': True, 'functions': (
        # Memory-unsafe APIs
        # Use something that won't overwrite the end of your buffer instead
        # of these.
        #
        # Microsoft provides lists of unsafe functions and their
        # recommended replacements in "Security Development Lifecycle
        # (SDL) Banned Function Calls"
        # https://docs.microsoft.com/en-us/previous-versions/bb288454(v=msdn.10)
        # and "Deprecated CRT Functions"
        # https://docs.microsoft.com/en-us/previous-versions/ms235384(v=vs.100)
        #
        'atoi',  # use wsutil/strtoi.h functions
        'gets',
        'sprintf',
        'g_sprintf',
        'vsprintf',
        'g_vsprintf',
        'strcpy',
        'strncpy',
        'strcat',
        'strncat',
        'cftime',
        'ascftime',
        ### non-portable APIs
        # use glib (g_*) versions instead of these:
        'ntohl',
        'ntohs',
        'htonl',
        'htons',
        # These two are coming in C23, but use GLib version for now:
        'strdup',
        'strndup',
        # Windows doesn't have this; use g_ascii_strtoull() instead
        'strtoull',
        ### non-portable: fails on Windows Wireshark built with VC newer than VC6
        # See https://gitlab.com/wireshark/wireshark/-/issues/6695#note_400659130
        'g_fprintf',
        'g_vfprintf',
        # use native snprintf() and vsnprintf() instead of these:
        'g_snprintf',
        'g_vsnprintf',
        ### non-ANSI C
        # use memset, memcpy, memcmp instead of these:
        'bzero',
        'bcopy',
        'bcmp',
        # The MSDN page for ZeroMemory recommends SecureZeroMemory
        # instead.
        'ZeroMemory',
        # use wmem_*, ep_*, or g_* functions instead of these:
        # (One thing to be aware of is that space allocated with malloc()
        # may not be freeable--at least on Windows--with g_free() and
        # vice-versa.)
        'malloc',
        'calloc',
        'realloc',
        'valloc',
        'free',
        'cfree',
        # Locale-unsafe APIs
        # These may have unexpected behaviors in some locales (e.g.,
        # "I" isn't always the upper-case form of "i", and "i" isn't
        # always the lower-case form of "I").  Use the g_ascii_* version
        # instead.
        'isalnum',
        'isascii',
        'isalpha',
        'iscntrl',
        'isdigit',
        'islower',
        'isgraph',
        'isprint',
        'ispunct',
        'isspace',
        'isupper',
        'isxdigit',
        'tolower',
        'toupper',
        'atof',
        'strtod',
        'strcasecmp',
        'strncasecmp',
        # Deprecated in glib 2.68 in favor of g_memdup2
        # We have our local implementation for older versions
        'g_memdup',
        'g_strcasecmp',
        'g_strncasecmp',
        'g_strup',
        'g_strdown',
        'g_string_up',
        'g_string_down',
        'strerror',  # use g_strerror
        # Use the ws_* version of these:
        # (Necessary because on Windows we use UTF8 for throughout the code
        # so we must tweak that to UTF16 before operating on the file.  Code
        # using these functions will work unless the file/path name contains
        # non-ASCII chars.)
        'open',
        'rename',
        'mkdir',
        'stat',
        'unlink',
        'remove',
        'fopen',
        'freopen',
        'fstat',
        'lseek',
        # GnuTLS session APIs
        # We use and configure GnuTLS for dissection only.
        'gnutls_init',
        # Misc
        'tmpnam',    # use mkstemp
        '_snwprintf',  # use StringCchPrintf
        'system',
    )},

    ### Soft-Deprecated functions that should not be used in new code but
    # have not been entirely removed from old code. These will become errors
    # once they've been removed from all existing code.
    'soft-deprecated': {'count_errors': False, 'functions': (
    )},

    # APIs that SHOULD NOT be used in Wireshark (any more)
    'deprecated': {'count_errors': True, 'functions': (
        'perror',                                         # Use g_strerror() and report messages in whatever
                                                          #  fashion is appropriate for the code in question.
        'ctime',                                          # Use abs_time_secs_to_str()
        'next_tvb_add_port',                              # Use next_tvb_add_uint() (and a matching change
                                                          #  of NTVB_PORT -> NTVB_UINT)

        ### Deprecated GLib/GObject functions/macros
        # (The list is based upon the GLib 2.30.2 & GObject 2.30.2 documentation;
        #  An entry may be commented out if it is currently
        #  being used in Wireshark and if the replacement functionality
        #  is not available in all the GLib versions that Wireshark
        #  currently supports.
        # Note:
        #  The Wireshark build currently defines G_DISABLE_DEPRECATED so use of any of
        #  the following should cause the Wireshark build to fail and therefore the
        #  tests for obsolete GLib function usage in checkAPIs should not be needed.
        'G_ALLOC_AND_FREE',
        'G_ALLOC_ONLY',
        'g_allocator_free',                               # "use slice allocator" (avail since 2.10,2.14)
        'g_allocator_new',                                # "use slice allocator" (avail since 2.10,2.14)
        'g_async_queue_ref_unlocked',                     # g_async_queue_ref()   (OK since 2.8)
        'g_async_queue_unref_and_unlock',                 # g_async_queue_unref() (OK since 2.8)
        'g_atomic_int_exchange_and_add',                  # since 2.30
        'g_basename',
        'g_blow_chunks',                                  # "use slice allocator" (avail since 2.10,2.14)
        'g_cache_value_foreach',                          # g_cache_key_foreach()
        'g_chunk_free',                                   # g_slice_free (avail since 2.10)
        'g_chunk_new',                                    # g_slice_new  (avail since 2.10)
        'g_chunk_new0',                                   # g_slice_new0 (avail since 2.10)
        'g_completion_add_items',                         # since 2.26
        'g_completion_clear_items',                       # since 2.26
        'g_completion_complete',                          # since 2.26
        'g_completion_complete_utf8',                     # since 2.26
        'g_completion_free',                              # since 2.26
        'g_completion_new',                               # since 2.26
        'g_completion_remove_items',                      # since 2.26
        'g_completion_set_compare',                       # since 2.26
        'G_CONST_RETURN',                                 # since 2.26
        'g_date_set_time',                                # g_date_set_time_t (avail since 2.10)
        'g_dirname',
        'g_format_size_for_display',                      # since 2.30: use g_format_size()
        'G_GNUC_FUNCTION',
        'G_GNUC_PRETTY_FUNCTION',
        'g_hash_table_freeze',
        'g_hash_table_thaw',
        'G_HAVE_GINT64',
        'g_io_channel_close',
        'g_io_channel_read',
        'g_io_channel_seek',
        'g_io_channel_write',
        'g_list_pop_allocator',                           # "does nothing since 2.10"
        'g_list_push_allocator',                          # "does nothing since 2.10"
        'g_main_destroy',
        'g_main_is_running',
        'g_main_iteration',
        'g_main_new',
        'g_main_pending',
        'g_main_quit',
        'g_main_run',
        'g_main_set_poll_func',
        'g_mapped_file_free',                             # [as of 2.22: use g_map_file_unref]
        'g_mem_chunk_alloc',                              # "use slice allocator" (avail since 2.10)
        'g_mem_chunk_alloc0',                             # "use slice allocator" (avail since 2.10)
        'g_mem_chunk_clean',                              # "use slice allocator" (avail since 2.10)
        'g_mem_chunk_create',                             # "use slice allocator" (avail since 2.10)
        'g_mem_chunk_destroy',                            # "use slice allocator" (avail since 2.10)
        'g_mem_chunk_free',                               # "use slice allocator" (avail since 2.10)
        'g_mem_chunk_info',                               # "use slice allocator" (avail since 2.10)
        'g_mem_chunk_new',                                # "use slice allocator" (avail since 2.10)
        'g_mem_chunk_print',                              # "use slice allocator" (avail since 2.10)
        'g_mem_chunk_reset',                              # "use slice allocator" (avail since 2.10)
        'g_node_pop_allocator',                           # "does nothing since 2.10"
        'g_node_push_allocator',                          # "does nothing since 2.10"
        'g_relation_count',                               # since 2.26
        'g_relation_delete',                              # since 2.26
        'g_relation_destroy',                             # since 2.26
        'g_relation_exists',                              # since 2.26
        'g_relation_index',                               # since 2.26
        'g_relation_insert',                              # since 2.26
        'g_relation_new',                                 # since 2.26
        'g_relation_print',                               # since 2.26
        'g_relation_select',                              # since 2.26
        'g_scanner_add_symbol',
        'g_scanner_remove_symbol',
        'g_scanner_foreach_symbol',
        'g_scanner_freeze_symbol_table',
        'g_scanner_thaw_symbol_table',
        'g_slist_pop_allocator',                          # "does nothing since 2.10"
        'g_slist_push_allocator',                         # "does nothing since 2.10"
        'g_source_get_current_time',                      # since 2.28: use g_source_get_time()
        'g_strcasecmp',                                   #
        'g_strdown',                                      #
        'g_string_down',                                  #
        'g_string_sprintf',                               # use g_string_printf() instead
        'g_string_sprintfa',                              # use g_string_append_printf instead
        'g_string_up',                                    #
        'g_strncasecmp',                                  #
        'g_strup',                                        #
        'g_tree_traverse',
        'g_tuples_destroy',                               # since 2.26
        'g_tuples_index',                                 # since 2.26
        'g_unicode_canonical_decomposition',              # since 2.30: use g_unichar_fully_decompose()
        'G_UNICODE_COMBINING_MARK',                       # since 2.30:use G_UNICODE_SPACING_MARK
        'g_value_set_boxed_take_ownership',               # GObject
        'g_value_set_object_take_ownership',              # GObject
        'g_value_set_param_take_ownership',               # GObject
        'g_value_set_string_take_ownership',              # Gobject
        'G_WIN32_DLLMAIN_FOR_DLL_NAME',
        'g_win32_get_package_installation_directory',
        'g_win32_get_package_installation_subdirectory',
        'qVariantFromValue',
    )},

    'dissectors-prohibited': {'count_errors': True, 'functions': (
        # APIs that make the program exit. Dissectors shouldn't call these.
        'abort',
        'assert',
        'assert_perror',
        'exit',
        'g_assert',
        'g_error',
    )},

    'dissectors-restricted': {'count_errors': False, 'functions': (
        # APIs that print to the terminal. Dissectors shouldn't call these.
        # FIXME: Explain what to use instead.
        'printf',
        'g_warning',
    )},
}

# Default API groups to check
DEFAULT_API_GROUPS = ['prohibited', 'deprecated', 'soft-deprecated']

# APIs which (generally) should not be called with an argument of tvb_get_ptr()
TvbPtrAPIs = [
    # Use NULL for the value_ptr instead of tvb_get_ptr() (only if the
    # given offset and length are equal) with these:
    'proto_tree_add_bytes_format',
    'proto_tree_add_bytes_format_value',
    'proto_tree_add_ether',
    # Use the tvb_* version of these:
    # Use tvb_bytes_to_str[_punct] instead of:
    'bytes_to_str',
    'bytes_to_str_punct',
    'SET_ADDRESS',
    'SET_ADDRESS_HF',
]

# List of possible shadow variables (Majority coming from macOS)
ShadowVariables = [
    'index',
    'time',
    'strlen',
    'system',
]

# Defines pairs function/variable which are excluded
# from prefs_register_*_preference checks
EXCLUDE_PREFS_CHECK = [
    ('prefs_register_password_preference', '(const char **)arg->pref_valptr'),
    ('prefs_register_string_preference', '(const char **)arg->pref_valptr'),
]


# XXX We should do this via a Result from check_common.py
def red(text):
    """ANSI color helper"""
    return f"\033[31m{text}\033[0m"


def find_api_in_file(group_hash, file_contents, found_apis):
    """Find APIs from the group that appear in the file contents."""
    for api in group_hash['functions']:
        count = 0
        # Match function calls, but ignore false positives from:
        # C++ method definition: int MyClass::open(...)
        # Method invocation: myClass->open(...);
        # Function declaration: int open(...);
        # Method invocation: QString().sprintf(...)
        # The pattern below is very slow, so do a quick "in" check first.
        if api in file_contents:
            pattern = pattern = re.compile(r'\W(?<!::)(?<!->)(?<!\w )(?<!\.)' + re.escape(api) + r'\W*\(')
            count = len(pattern.findall(file_contents))
        if count > 0:
            found_apis.append(api)
            group_hash['function_counts'][api] = group_hash['function_counts'].get(api, 0) + 1


def check_apis_called_with_tvb_get_ptr(api_list, file_contents, found_apis):
    """Check for APIs called with tvb_get_ptr()."""
    for api in api_list:
        items = re.findall(re.escape(api) + r'[^;]*;', file_contents, re.DOTALL)
        count = 0
        for item in items:
            if 'tvb_get_ptr' in item:
                count += 1
        if count > 0:
            found_apis.append(api)


def check_shadow_variable(shadow_list, file_contents, found_apis):
    """Check for shadow variables."""
    for api in shadow_list:
        pattern = re.compile(r'\s' + re.escape(api) + r'\s*[^\(\w\s]')
        count = len(pattern.findall(file_contents))
        if count > 0:
            found_apis.append(api)


def check_snprintf_plus_strlen(file_contents, filename):
    """Check for snprintf + strlen usage."""
    error_count = 0
    items = re.findall(r'snprintf[^;]*;', file_contents, re.DOTALL)
    for item in items:
        if re.search(r'strlen\s*\(', item):
            print(red(f"Error: {filename} uses snprintf + strlen to assemble strings."), file=sys.stderr)
            error_count += 1
            break
    return error_count


def check_complex_snprintf(file_contents, filename):
    """Check for complex snprintf usage."""
    error_count = 0
    items = re.findall(r'=\s*snprintf', file_contents)
    if items:
        print(f"Warning: {filename} appears to use snprintf to assemble\n"
              "strings. Consider using a wmem_strbuf or GString instead.", file=sys.stderr)
        # error_count += 1
    return error_count


def check_value_string_arrays(file_contents, filename, debug_flag):
    """Check value_string and enum_val_t arrays for proper termination."""
    count = 0

    static_re = r'static\s+'
    const_re = r'const\s+'
    static_or_const_re = rf'(?:{static_re}{const_re}|{static_re}|{const_re})'
    vs_varname_re = r'(?:value|val64|string|range|bytes)_string'
    vs_re = rf'{static_or_const_re}({vs_varname_re})\s+[^;*#]+=\s*[^;]+\{{.+?\}}\s*?;'
    enum_val_re = rf'{static_or_const_re}enum_val_t\s+[^;*]+=\s*[^;]+\{{.+?\}}\s*?;'
    newline_string_re = r'"[^"]*\\n[^"]*"'

    # Brute force check for value_string (and string_string or range_string) arrays
    # which are missing {0, NULL} as the final (terminating) array entry

    #  Assumption: definition is of form (pseudo-Regex):
    #    " (static const|static|const) (value|string|range)_string .+ = { .+ ;"
    #  (possibly over multiple lines)
    for m in re.finditer(vs_re, file_contents, re.DOTALL):
        vs = vsx = m.group(0)
        type_name = m.group(1)
        if debug_flag:
            decl_m = re.search(rf'(.+{vs_varname_re}[^=]+)=', vsx)
            if decl_m:
                print(f"==> {filename:<35.35s}: {decl_m.group(1)}", file=sys.stderr)
            print(vs, file=sys.stderr)
        vs_nospace = re.sub(r'\s', '', vs)

        # Check for expected trailer
        if type_name == "string_string":
            expected_trailer = r'\{(?:NULL|0),NULL\}'
            trailer_hint = "NULL, NULL"
        elif type_name == "range_string":
            expected_trailer = r'\{0(?:x0+)?,0(?:x0+)?,NULL\}'
            trailer_hint = "0, 0, NULL"
        elif type_name == "bytes_string":
            expected_trailer = r'\{(?:NULL|0),0,NULL\}'
            trailer_hint = "NULL, NULL"
        else:
            expected_trailer = r'\{0(?:x?0+)?,NULL\}'
            trailer_hint = "0, NULL"

        if not re.search(expected_trailer + r',?\};$', vs_nospace):
            decl_m = re.search(rf'({vs_varname_re}[^=]+)=', vsx)
            decl = decl_m.group(1) if decl_m else "?"
            print(f"Error: {filename:<35.35s}: {{{trailer_hint}}} is required as the last {type_name} array entry: {decl}", file=sys.stderr)
            count += 1

        if not re.search(rf'(?:static)?const{vs_varname_re}', vs_nospace):
            decl_m = re.search(rf'({vs_varname_re}[^=]+)=', vsx)
            decl = decl_m.group(1) if decl_m else "?"
            print(f"Error: {filename:<35.35s}: Missing 'const': {decl}", file=sys.stderr)
            count += 1

        if re.search(newline_string_re, vs) and type_name != "bytes_string":
            decl_m = re.search(rf'({vs_varname_re}[^=]+)=', vsx)
            decl = decl_m.group(1) if decl_m else "?"
            print(f"Error: {filename:<35.35s}: XXX_string contains a newline: {decl}", file=sys.stderr)
            count += 1

    # Brute force check for enum_val_t arrays which are missing {NULL, NULL, ...}
    # as the final (terminating) array entry
    # For now use the same option to turn this and value_string checking on and off.
    # (Is the option even necessary?)

    #  Assumption: definition is of form (pseudo-Regex):
    #    " (static const|static|const) enum_val_t .+ = { .+ ;"
    #  (possibly over multiple lines)
    for m in re.finditer(enum_val_re, file_contents, re.DOTALL):
        vs = vsx = m.group(0)
        if debug_flag:
            decl_m = re.search(r'(.+enum_val_t[^=]+)=', vsx)
            if decl_m:
                print(f"==> {filename:<35.35s}: {decl_m.group(1)}", file=sys.stderr)
            print(vs, file=sys.stderr)
        vs_nospace = re.sub(r'\s', '', vs)

        # README.developer says
        #  "Don't put a comma after the last tuple of an initializer of an array"
        # However: since this usage is present in some number of cases, we'll allow for now
        if not re.search(r'NULL,NULL,-?[0-9]\},?\};$', vs_nospace):
            decl_m = re.search(r'(enum_val_t[^=]+)=', vsx)
            decl = decl_m.group(1) if decl_m else "?"
            print(f"Error: {filename:<35.35s}: {{NULL, NULL, ...}} is required as the last enum_val_t array entry: {decl}", file=sys.stderr)
            count += 1

        if not re.search(r'(?:static)?constenum_val_t', vs_nospace):
            decl_m = re.search(r'(enum_val_t[^=]+)=', vsx)
            decl = decl_m.group(1) if decl_m else "?"
            print(f"Error: {filename:<35.35s}: Missing 'const': {decl}", file=sys.stderr)
            count += 1

        if re.search(newline_string_re, vs):
            decl_m = re.search(r'((?:value|string|range)_string[^=]+)=', vsx)
            decl = decl_m.group(1) if decl_m else "?"
            print(f"Error: {filename:<35.35s}: enum_val_t contains a newline: {decl}", file=sys.stderr)
            count += 1

    return count


def check_included_files(file_contents, filename):
    """Check for files that should use #include <> instead of #include ""."""
    inc_files = re.findall(r'#include\s*([<"].+[>"])', file_contents)

    # files in the ui/qt directory should include the ui class includes
    # by using #include <>
    # this ensures that Visual Studio picks up these files from the
    # build directory if we're compiling with cmake
    if 'ui/qt/' in filename:
        for inc in inc_files:
            if re.search(r'"ui_.*\.h"$', inc):
                base = inc.strip('"')
                print(f"{filename}: Please use #include <{base}> instead of #include \"{base}\".", file=sys.stderr)


def check_proto_tree_add_XXX(file_contents, filename):
    """Check for incorrect proto_tree_add_XXX usage."""
    error_count = 0

    items = re.findall(r'(proto_tree_add_[_a-z0-9]+)\s*\(\s*([^;]*)\)\s*;', file_contents, re.DOTALL)

    for func, args in items:
        # Check to make sure tvb_get* isn't used to pass into a
        # proto_tree_add_<datatype>, when proto_tree_add_item could be used
        if re.search(r',\s*tvb_get_', args, re.DOTALL):
            if re.match(r'^proto_tree_add_(time|bytes|ipxnet|ipv4|ipv6|ether|guid|oid|string|boolean|float|double|uint|uint64|int|int64|eui64|bitmask_list_value)$', func):
                print(red(f"Error: {filename} uses {func} with tvb_get_*. Use proto_tree_add_item instead"), file=sys.stderr)
                error_count += 1
                # Print out the function args to make it easier
                # to find the offending code.  But first make
                # it readable by eliminating extra white space.
                clean_args = re.sub(r'\s+', ' ', args)
                print(f"\tArgs: {clean_args}", file=sys.stderr)

        # Remove anything inside parentheses in the arguments so we
        # don't get false positives
        args_no_parens = re.sub(r'\(.*?\)', '', args, flags=re.DOTALL)

        # Check for accidental usage of ENC_ parameter
        if re.search(r',\s*ENC_', args_no_parens, re.DOTALL):
            if not re.search(r'proto_tree_add_(time|item|bitmask|[a-z0-9]+_bits_format_value|bits_item|bits_ret_val|item_ret_int|item_ret_uint|bytes_item|checksum)', func):
                print(red(f"Error: {filename} uses {func} with ENC_*."), file=sys.stderr)
                error_count += 1
                # Print out the function args to make it easier
                # to find the offending code.  But first make
                # it readable by eliminating extra white space.
                clean_args = re.sub(r'\s+', ' ', args)
                print(f"\tArgs: {clean_args}", file=sys.stderr)

    return error_count


def check_ett_registration(file_contents, filename):
    """Verify that all declared ett_ variables are registered."""
    # Don't bother trying to check usage (for now)...
    error_count = 0

    # A pattern to match ett variable names.  Obviously this assumes that
    # they start with `ett_`
    ett_var_re = r'ett_[a-z0-9_]+(?:\[[0-9]+\])?'

    # Find all the ett_ variables declared in the file
    ett_declarations = re.findall(
        r'^(?:static\s+)?g?int\s+(' + ett_var_re + r')\s*=\s*-1\s*;',
        file_contents, re.MULTILINE | re.IGNORECASE)

    if not ett_declarations:
        # Only complain if the file looks like a dissector
        return 0

    # Find all the uses of the *addresses* of ett variables in the file.
    # (We assume if someone is using the address they're using it to
    # register the ett.)
    ett_address_uses = re.findall(r'&\s*(' + ett_var_re + r')', file_contents, re.IGNORECASE | re.MULTILINE)

    if not ett_address_uses:
        print(f"Found no ett address uses in {filename}", file=sys.stderr)
        return 0

    # Convert to a set for fast lookup
    ett_uses = set(ett_address_uses)

    # Find which declared etts are not used.
    unused_etts = [ett for ett in ett_declarations if ett not in ett_uses]

    if unused_etts:
        print(red(f"Error: found these unused ett variables in {filename}: {' '.join(unused_etts)}"), file=sys.stderr)
        error_count += 1

    return error_count


def check_hf_entries(file_contents, filename):
    """Check all hf entries for various problems."""
    error_count = 0

    hf_re = (
        r'\{\s*&\s*([A-Z0-9_\[\]-]+)\s*,\s*'        # &hf
        r'\{\s*'
        r'("[A-Z0-9 \'./()_:-]+")\s*,\s*'           # name
        r'(NULL|"[A-Z0-9_.-]*")\s*,\s*'             # abbrev
        r'(FT_[A-Z0-9_]+)\s*,\s*'                   # field type
        r'([A-Z0-9x|_\s]+)\s*,\s*'                  # display
        r'([^,]+?)\s*,\s*'                          # convert
        r'([A-Z0-9_]+)\s*,\s*'                      # bitmask
        r'(NULL|"[A-Z0-9 \'./()?\n_:-]+")\s*,\s*'   # blurb
        r'HFILL'
    )

    for m in re.finditer(hf_re, file_contents, re.IGNORECASE | re.DOTALL):
        hf, name, abbrev, ft, display, convert, bitmask, blurb = m.groups()

        display = re.sub(r'\s+', '', display)
        convert = re.sub(r'\s+', '', convert)
        # GET_VALS_EXTP is a macro in packet-mq.h
        convert = re.sub(r'\bGET_VALS_EXTP\(', 'VALS_EXT_PTR(', convert)

        if abbrev in ('""', 'NULL'):
            print(red(f"Error: {hf} does not have an abbreviation in {filename}"), file=sys.stderr)
            error_count += 1
        if re.search(r'\.\.+', abbrev):
            print(red(f"Error: the abbreviation for {hf} ({abbrev}) contains two or more sequential periods in {filename}"), file=sys.stderr)
            error_count += 1
        if name == abbrev:
            print(red(f"Error: the abbreviation for {hf} ({abbrev}) matches the field name ({name}) in {filename}"), file=sys.stderr)
            error_count += 1
        if name.lower() == blurb.lower():
            print(red(f"Error: the blurb for {hf} ({blurb}) matches the field name ({name}) in {filename}"), file=sys.stderr)
            error_count += 1
        if re.match(r'"\s+', name):
            print(red(f"Error: the name for {hf} ({name}) has leading space in {filename}"), file=sys.stderr)
            error_count += 1
        if re.search(r'\s+"', name):
            print(red(f"Error: the name for {hf} ({name}) has trailing space in {filename}"), file=sys.stderr)
            error_count += 1
        if re.match(r'"\s+', blurb):
            print(red(f"Error: the blurb for {hf} ({blurb}) has leading space in {filename}"), file=sys.stderr)
            error_count += 1
        if re.search(r'\s+"', blurb):
            print(red(f"Error: the blurb for {hf} ({blurb}) has trailing space in {filename}"), file=sys.stderr)
            error_count += 1
        if re.search(r'\s+', abbrev):
            print(red(f"Error: the abbreviation for {hf} ({abbrev}) has white space in {filename}"), file=sys.stderr)
            error_count += 1
        if f'"{hf}"' == name:
            print(red(f"Error: name is the hf_variable_name in field {name} ({abbrev}) in {filename}"), file=sys.stderr)
            error_count += 1
        if f'"{hf}"' == abbrev:
            print(red(f"Error: abbreviation is the hf_variable_name in field {name} ({abbrev}) in {filename}"), file=sys.stderr)
            error_count += 1
        if ft != "FT_BOOLEAN" and re.match(r'^TFS\(.*\)', convert):
            print(red(f"Error: {hf} uses a true/false string but is an {ft} instead of FT_BOOLEAN in {filename}"), file=sys.stderr)
            error_count += 1
        if ft == "FT_BOOLEAN" and re.match(r'^VALS\(.*\)', convert):
            print(red(f"Error: {hf} uses a value_string but is an FT_BOOLEAN in {filename}"), file=sys.stderr)
            error_count += 1
        if ft == "FT_BOOLEAN" and not re.match(r'^(?:0x)?0+$', bitmask) and re.match(r'^BASE_', display):
            print(red(f"Error: {hf}: FT_BOOLEAN with a bitmask must specify a 'parent field width' for 'display' in {filename}"), file=sys.stderr)
            error_count += 1
        if ft == "FT_BOOLEAN" and not re.match(r'^(?:(?:0[xX]0?)?0$|NULL$|TFS)', convert):
            print(red(f"Error: {hf}: FT_BOOLEAN with non-null 'convert' field missing TFS in {filename}"), file=sys.stderr)
            error_count += 1
        if re.search(r'RVALS', convert) and 'BASE_RANGE_STRING' not in display:
            print(red(f"Error: {hf} uses RVALS but 'display' does not include BASE_RANGE_STRING in {filename}"), file=sys.stderr)
            error_count += 1
        if re.search(r'VALS64', convert) and 'BASE_VAL64_STRING' not in display:
            print(red(f"Error: {hf} uses VALS64 but 'display' does not include BASE_VAL64_STRING in {filename}"), file=sys.stderr)
            error_count += 1
        if 'BASE_EXT_STRING' in display and not re.match(r'^(?:VALS_EXT_PTR\(|&)', convert):
            print(red(f"Error: {hf}: BASE_EXT_STRING should use VALS_EXT_PTR for 'strings' instead of '{convert}' in {filename}"), file=sys.stderr)
            error_count += 1
        if 'BASE_UNIT_STRING' in display and not re.match(r'^(?:(?:0[xX]0?)?0$|NULL$|UNS)', convert):
            print(red(f"Error: {hf}: BASE_UNIT_STRING with non-null 'convert' field missing UNS in {filename}"), file=sys.stderr)
            error_count += 1
        if re.match(r'^FT_U?INT(?:8|16|24|32)$', ft) and re.match(r'^VALS64\(', convert):
            print(red(f"Error: {hf}: 32-bit field must use VALS instead of VALS64 in {filename}"), file=sys.stderr)
            error_count += 1
        if re.match(r'^FT_U?INT(?:40|48|56|64)$', ft) and re.match(r'^VALS\(', convert):
            print(red(f"Error: {hf}: 64-bit field must use VALS64 instead of VALS in {filename}"), file=sys.stderr)
            error_count += 1
        if re.match(r'^(?:VALS|VALS64|RVALS)\(&.*\)', convert):
            m2 = re.match(r'^(VALS|VALS64|RVALS)', convert)
            print(red(f"Error: {hf} is passing the address of a pointer to {m2.group(1)} in {filename}"), file=sys.stderr)
            error_count += 1
        if (not re.match(r'^(?:(?:0[xX]0?)?0$|NULL$|VALS|VALS64|VALS_EXT_PTR|RVALS|TIME_VALS|TFS|UNS|CF_FUNC|FRAMENUM_TYPE|&|STRINGS_ENTERPRISES)', convert)
                and 'BASE_CUSTOM' not in display):
            print(red(f"Error: non-null {hf} 'convert' field missing 'VALS|VALS64|VALS_EXT_PTR|RVALS|TIME_VALS|TFS|UNS|CF_FUNC|FRAMENUM_TYPE|&|STRINGS_ENTERPRISES' in {filename} ?"), file=sys.stderr)
            error_count += 1

    return error_count


def extract_balanced_parens(text):
    """Extract text within balanced parentheses starting at the beginning of text.

    Returns the content including outer parentheses, or None if not balanced.
    """
    if not text or text[0] != '(':
        return None
    depth = 0
    for i, ch in enumerate(text):
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return text[:i + 1]
    return None


def check_pref_var_dupes(file_contents, filename):
    """Check for duplicate preference variable usage."""
    error_count = 0

    # Avoid flagging the actual prototypes
    if re.search(r'prefs\.[ch]$', filename):
        return 0

    # Remove macro lines
    contents = re.sub(r'^\s*#.*$', '', file_contents, flags=re.MULTILINE)

    # At what position is the variable in the prefs_register_*_preference() call?
    prefs_register_var_pos = {
        'static_text': None, 'obsolete': None,  # ignore
        'decode_as_range': -2, 'range': -2, 'filename': -2,  # second to last
        'enum': -3,  # third to last
        # everything else is the last argument
    }

    dupes = []
    count = {}

    for m in re.finditer(r'prefs_register_(\w+?)_preference', contents):
        pref_type = m.group(1)
        func = f'prefs_register_{pref_type}_preference'

        # Find the balanced parentheses after the function name
        rest = contents[m.end():]
        args_with_parens = extract_balanced_parens(rest)
        if args_with_parens is None:
            continue
        args = args_with_parens[1:-1]  # strip outer parens

        if pref_type in prefs_register_var_pos:
            pos = prefs_register_var_pos[pref_type]
            if pos is None:
                continue
        else:
            pos = -1

        # Split on commas that are not inside parentheses
        parts = []
        depth = 0
        current = []
        for ch in args:
            if ch == '(':
                depth += 1
                current.append(ch)
            elif ch == ')':
                depth -= 1
                current.append(ch)
            elif ch == ',' and depth == 0:
                parts.append(''.join(current).strip())
                current = []
            else:
                current.append(ch)
        parts.append(''.join(current).strip())

        if abs(pos) > len(parts):
            continue
        var = parts[pos]

        ignore = False
        for rfunc, rvar in EXCLUDE_PREFS_CHECK:
            if rfunc == func and rvar == var:
                ignore = True
                break

        if not ignore:
            if var in count:
                count[var] += 1
                if count[var] == 2:
                    dupes.append(var)
            else:
                count[var] = 1

    if dupes:
        print(f"{filename}: error: found these preference variables used in more than one prefs_register_*_preference:\n\t{', '.join(dupes)}", file=sys.stderr)
        error_count += 1

    return error_count


def check_try_catch(file_contents, filename):
    """Check for forbidden control flow changes in TRY/CATCH blocks."""
    error_count = 0

    # Match TRY { ... } ENDTRY (with an optional '\' in case of a macro).
    items = re.findall(r'\bTRY\s*\{(.+?)\}\s*\\?\s*ENDTRY\b', file_contents, re.DOTALL)
    for block in items:
        if re.search(r'\breturn\b', block):
            print(red(f"Error: return is forbidden in TRY/CATCH in {filename}"), file=sys.stderr)
            error_count += 1

        goto_labels = re.findall(r'\bgoto\s+(\w+)', block)
        seen = set()
        for goto_label in goto_labels:
            if goto_label in seen:
                continue
            seen.add(goto_label)

            if not re.search(r'^\s*' + re.escape(goto_label) + r'\s*:', block, re.MULTILINE):
                print(red(f"Error: goto to label '{goto_label}' outside TRY/CATCH is forbidden in {filename}"), file=sys.stderr)
                error_count += 1

    return error_count


def remove_if0_code(code, filename):
    """Remove '#if 0'd code from the input string."""
    # Preprocess: ensure trailing LF and no leading WS before '#'
    code = re.sub(r'^\s*#', '#', code, flags=re.MULTILINE)
    if not code.endswith('\n'):
        code += '\n'

    # Split into blocks of normal code or lines with conditionals.
    if_regexp = r'if 0|if|else|endif'
    blocks = re.split(r'^(#\s*(?:' + if_regexp + r').*\n)', code, flags=re.MULTILINE)

    if_lvl = 0
    if0_lvl = 0
    if0 = 0
    lines = []

    for block in blocks:
        directive = None
        m = re.match(r'^#\s*(' + if_regexp + r')', block)
        if m:
            directive = m.group(1)
            if directive == 'if':
                if_lvl += 1
            elif directive == 'if 0':
                if_lvl += 1
                if if0_lvl == 0:
                    if0_lvl = if_lvl
                    if0 = 1  # inside #if 0
            elif directive == 'else':
                if if0_lvl == if_lvl:
                    if0 = 0
            elif directive == 'endif':
                if if0_lvl == if_lvl:
                    if0 = 0
                    if0_lvl = 0
                if_lvl -= 1
                if if_lvl < 0:
                    raise RuntimeError(f"patsub: #if/#endif mismatch in {filename}")

        # Keep preprocessor lines and blocks that are not enclosed in #if 0
        if directive or if0 != 1:
            lines.append(block)

    return ''.join(lines)


# Regex for removing C/C++ comments
def remove_comments(code):
    """Remove C and C++ style comments, preserving newlines."""
    # This pattern handles:
    # 1. Block comments /* ... */
    # 2. Line comments // ... \n
    # 3. Double-quoted strings
    # 4. Single-quoted strings
    # 5. Everything else
    pattern = re.compile(
        r'/\*[^*]*\*+(?:[^/*][^*]*\*+)*/|'  # block comment
        r'//(?:[^\\]|[^\n][\n]?)*?\n|'       # line comment
        r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|.[^/"\'\\]*)',  # strings and other
        re.DOTALL
    )

    def replacer(m):
        if m.group(1) is not None:
            return m.group(1)
        return '\n'

    return pattern.sub(replacer, code)


def has_utf8_bom(filename):
    """Check for UTF-8 BOM at start of file, which can cause problems with some tools and compilers."""
    with open(filename, 'rb') as f:
        return f.read(3) == b'\xef\xbb\xbf'


def print_usage():
    print("Usage: check-apis.py [-M] [-h] [-g group1[:count]] [-g group2] ...")
    print("                     [-summary-group group1] [-summary-group group2] ...")
    print("                     [--sourcedir=srcdir]")
    print("                     [--nocheck-hf]")
    print("                     [--nocheck-value-string-array]")
    print("                     [--nocheck-shadow]")
    print("                     [--debug]")
    print("                     [--file=/path/to/file_list]")
    print("                     file1 file2 ...")
    print()
    print("       -M: Generate output for -g in 'machine-readable' format")
    print("       -p: used by the git pre-commit hook")
    print("       -h: help, print usage message")
    print("       -g <group>:  Check input files for use of APIs in <group>")
    print("                    (in addition to the default groups)")
    print("                    Maximum uses can be specified with <group>:<count>")
    print("       -summary-group <group>:  Output summary (count) for each API in <group>")
    print("                    (-g <group> also req'd)")
    print("       --nocheck-hf: Skip header field definition checks")
    print("       --nocheck-value-string-array: Skip value string array checks")
    print("       --nocheck-shadow: Skip shadow variable checks")
    print("       --debug: UNDOCUMENTED")
    print()
    print(f"   Default Groups[-g]: {', '.join(sorted(DEFAULT_API_GROUPS))}")
    print(f"   Available Groups:   {', '.join(sorted(APIs.keys()))}")


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-g', '--group', action='append', default=[], dest='groups')
    parser.add_argument('-s', '--summary-group', action='append', default=[], dest='summary_groups')
    parser.add_argument('-M', '--Machine-readable', action='store_true', dest='machine_readable')
    parser.add_argument('--check-hf', action='store_true', default=True, dest='check_hf')
    parser.add_argument('--nocheck-hf', action='store_false', dest='check_hf')
    parser.add_argument('--check-value-string-array', action='store_true', default=True, dest='check_value_string_array')
    parser.add_argument('--nocheck-value-string-array', action='store_false', dest='check_value_string_array')
    parser.add_argument('--check-shadow', action='store_true', default=True, dest='check_shadow')
    parser.add_argument('--nocheck-shadow', action='store_false', dest='check_shadow')
    parser.add_argument('--sourcedir', default='', dest='source_dir')
    parser.add_argument('--debug', action='store_true', default=False, dest='debug_flag')
    parser.add_argument('-p', '--pre-commit', action='store_true', default=False, dest='pre_commit')
    parser.add_argument('--file', default='', dest='filenamelist')
    parser.add_argument('-h', '--help', action='store_true', default=False, dest='help_flag')
    parser.add_argument('files', nargs='*')

    args = parser.parse_args()

    if args.help_flag:
        print_usage()
        sys.exit(1)

    # Build the API groups list
    api_groups = list(DEFAULT_API_GROUPS)
    api_groups.extend(args.groups)

    # the pre-commit hook only calls checkAPIs one file at a time
    if args.pre_commit and args.files:
        filename = args.files[0]
        if re.search(r'\bpacket-[^/\\]+\.[ch]$', filename):
            api_groups.append('abort')
            api_groups.append('termoutput')

    # Add function_counts to each API group
    for api_group in APIs:
        functions = APIs[api_group]['functions']
        APIs[api_group]['function_counts'] = {f: 0 for f in functions}
        APIs[api_group]['max_function_count'] = -1
        if APIs[api_group]['count_errors']:
            APIs[api_group]['max_function_count'] = 0
        APIs[api_group]['cur_function_count'] = 0

    # Build file list
    filelist = list(args.files)
    if args.filenamelist:
        with open(args.filenamelist) as f:
            for line in f:
                filelist.extend(line.strip().split(';'))

    if not filelist:
        print("no files to process", file=sys.stderr)
        sys.exit(1)

    error_count = 0

    # Read through the files; do various checks
    filelist.sort()
    for filename in filelist:
        file_contents = ''
        found_apis = []

        if args.source_dir and not os.path.exists(filename):
            filename = os.path.join(args.source_dir, filename)
        if not os.path.exists(filename):
            print(f'Warning: No such file: "{filename}"', file=sys.stderr)
            continue

        # delete leading './'
        filename = re.sub(r'^\.\/', '', filename)
        if not os.path.isfile(filename):
            print(f"Warning: {filename} is not of type file - skipping.", file=sys.stderr)
            continue

        if has_utf8_bom(filename):
            print(red(f"Error: Found UTF-8 BOM at start of file {filename}"), file=sys.stderr)
            error_count += 1
            continue

        # Read in the file
        line_num = 0
        with open(filename, 'rb') as f:
            raw = f.read()

        for line_num, line_bytes in enumerate(raw.split(b'\n'), 1):
            try:
                line_bytes.decode('utf-8')
            except UnicodeDecodeError:
                print(red(f"Error: Found an invalid UTF-8 sequence on line {line_num} of {filename}"), file=sys.stderr)
                error_count += 1

        file_contents = raw.decode('utf-8', errors='replace')

        if re.search(r'\$Id.*\$', file_contents):
            print(f"Warning: {filename} has an SVN Id tag. Please remove it!", file=sys.stderr)

        if re.search(r'tab-width:\s*[0-7|9]+|tabstop=[0-7|9]+|tabSize=[0-7|9]+', file_contents):
            print(red(f"Error: Found modelines with tabstops set to something other than 8 in {filename}"), file=sys.stderr)
            error_count += 1

        # Remove C/C++ comments
        file_contents = remove_comments(file_contents)

        # Optionally check the hf entries (including those under #if 0)
        if args.check_hf:
            error_count += check_hf_entries(file_contents, filename)

        if re.search(r'%\d*?ll', file_contents):
            # use PRI[dux...]N instead of ll
            print(red(f"Error: Found %ll in {filename}"), file=sys.stderr)
            error_count += 1

        # check for files that we should not include directly
        check_included_files(file_contents, filename)

        # Check for value_string and enum_val_t errors
        if args.check_value_string_array:
            error_count += check_value_string_arrays(file_contents, filename, args.debug_flag)

        # Remove all the quoted strings, even across line continuations.
        # (?s:.) matches a newline (well, any character) without re.DOTALL.
        file_contents = re.sub(r'"(?:\\(?s:.)|[^\"\\])*\"|\'(?:\\(?s:.)|[^\'\\])*\'', '', file_contents)

        error_count += check_pref_var_dupes(file_contents, filename)

        # Remove all blank lines
        file_contents = re.sub(r'^\s*$\n', '', file_contents, flags=re.MULTILINE)

        # Remove all '#if 0'd' code
        file_contents = remove_if0_code(file_contents, filename)

        error_count += check_ett_registration(file_contents, filename)

        #check_apis_called_with_tvb_get_ptr(api_list, file_contents, found_apis);
        #if (found_apis) {
        #    print(f"Found APIs with embedded tvb_get_ptr() calls in {filename} : {','.join(found_apis)}", file=sys.stderr)

        if args.check_shadow:
            found_apis = []
            check_shadow_variable(ShadowVariables, file_contents, found_apis)
            if found_apis:
                print(f"Warning: Found shadow variable(s) in {filename} : {','.join(found_apis)}", file=sys.stderr)

        error_count += check_snprintf_plus_strlen(file_contents, filename)

        error_count += check_complex_snprintf(file_contents, filename)

        error_count += check_proto_tree_add_XXX(file_contents, filename)

        error_count += check_try_catch(file_contents, filename)

        # Check and count APIs
        for group_arg in api_groups:
            pfx = "Warning"
            found_apis = []
            group_parts = group_arg.split(':')
            api_group = group_parts[0]

            if api_group not in APIs:
                print(f"Warning: Unknown API group '{api_group}'", file=sys.stderr)
                continue

            if len(group_parts) > 1:
                APIs[api_group]['max_function_count'] = int(group_parts[1])

            find_api_in_file(APIs[api_group], file_contents, found_apis)

            cur_func_count = sum(APIs[api_group]['function_counts'].values())

            # If we have a max function count and we've exceeded it, treat it
            # as an error.
            if not APIs[api_group]['count_errors'] and APIs[api_group]['max_function_count'] >= 0:
                if cur_func_count > APIs[api_group]['max_function_count']:
                    print(f"{pfx}: {api_group} exceeds maximum function count: {APIs[api_group]['max_function_count']}", file=sys.stderr)
                    APIs[api_group]['count_errors'] = True

            if cur_func_count <= APIs[api_group]['max_function_count']:
                continue

            if APIs[api_group]['count_errors']:
                error_count += len(found_apis)
                pfx = "Error"

            if found_apis and not args.machine_readable:
                print(f"{pfx}: Found {api_group} APIs in {filename}: {','.join(found_apis)}", file=sys.stderr)
            if found_apis and args.machine_readable:
                for api in found_apis:
                    print(f"{pfx:<8.8s} {api_group:<20.20s} {filename:<30.30s} {api:<45.45s}", file=sys.stderr)

    # Summary: Print Use Counts of each API in each requested summary group
    if args.summary_groups:
        fileline = ', '.join(args.files)
        print(f"\nSummary for {fileline[:65]}\u2026")

        for api_group in args.summary_groups:
            if api_group not in APIs:
                continue
            print(f"\nUse counts for {api_group} (maximum allowed total is {APIs[api_group]['max_function_count']})")
            for api in sorted(APIs[api_group]['function_counts'].keys(), key=str.lower):
                if APIs[api_group]['function_counts'][api] < 1:
                    continue
                print(f"{APIs[api_group]['function_counts'][api]:5d}  {api:<40.40s}")

    sys.exit(min(error_count, 120))


if __name__ == '__main__':
    main()
