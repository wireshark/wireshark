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
#               [--folder]
#               file1 file2 ...
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

# TODO:
# - continue to check for overlap between this script and check_typed_item_calls.py and rationalize
# - use more check_common.py functions for working out lists of files to check (--commit, --open)
# - speedup using concurrent.futures.ProcessPoolExecutor() - one file per future
# - see if we need to do anything special with respect to Python's regex cache. We create a *lot*
#   of expressions.


import argparse
import os
import re
import sys
import concurrent.futures
from check_common import findDissectorFilesInFolder, HFEntriesParser, Result, OutputType, isDissectorFile


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
    'prohibited': {'count_errors': True, 'functions': set((
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
    ))},

    ### Soft-Deprecated functions that should not be used in new code but
    # have not been entirely removed from old code. These will become errors
    # once they've been removed from all existing code.
    'soft-deprecated': {'count_errors': False, 'functions': set((
    ))},

    # APIs that SHOULD NOT be used in Wireshark (any more)
    'deprecated': {'count_errors': True, 'functions': set((
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
    ))},

    'dissectors-prohibited': {'count_errors': True, 'functions': set((
        # APIs that make the program exit. Dissectors shouldn't call these.
        'abort',
        'assert',
        'assert_perror',
        'exit',
        'g_assert',
        'g_error',
    ))},

    'dissectors-restricted': {'count_errors': False, 'functions': set((
        # APIs that print to the terminal. Dissectors shouldn't call these.
        # FIXME: Explain what to use instead.
        'printf',
        'g_warning',
    ))},
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
ShadowVariables = set((
    'index',
    'time',
    'strlen',
    'system',
))

# Defines pairs function/variable which are excluded
# from prefs_register_*_preference checks
EXCLUDE_PREFS_CHECK = [
    ('prefs_register_password_preference', '(const char **)arg->pref_valptr'),
    ('prefs_register_string_preference', '(const char **)arg->pref_valptr'),
]


def find_api_in_file(group_hash, file_words, file_contents, found_apis, function_counts):
    """Find APIs from the group that appear in the file contents."""
    # Match function calls, but ignore false positives from:
    # C++ method definition: int MyClass::open(...)
    # Method invocation: myClass->open(...);
    # Function declaration: int open(...);
    # Method invocation: QString().sprintf(...)
    found_set = group_hash['functions'] & file_words
    if found_set:
        for api in found_set:
            pattern = pattern = re.compile(r'\W(?<!::)(?<!->)(?<!\w )(?<!\.)' + re.escape(api) + r'\W*\(')
            count = len(pattern.findall(file_contents))
            if count > 0:
                found_apis.append(api)
                function_counts[api] = function_counts.get(api, 0) + 1


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


def check_shadow_variable(shadow_set, file_words, file_contents, found_apis):
    """Check for shadow variables."""
    found_set = shadow_set & file_words
    if found_set:
        for api in found_set:
            pattern = re.compile(r'\s' + re.escape(api) + r'\s*[^\(\w\s]')
            count = len(pattern.findall(file_contents))
            if count > 0:
                found_apis.append(api)


def check_snprintf_plus_strlen(file_contents, filename, result):
    """Check for snprintf + strlen usage."""
    items = re.findall(r'snprintf[^;]*;', file_contents, re.DOTALL)
    for item in items:
        if re.search(r'strlen\s*\(', item):
            result.error(f"{filename} uses snprintf + strlen to assemble strings.")
            break


def check_complex_snprintf(file_contents, filename, result):
    """Check for complex snprintf usage."""
    items = re.findall(r'=\s*snprintf', file_contents)
    if items:
        result.warn(f"{filename} appears to use snprintf to assemble\n"
                    "strings. Consider using a wmem_strbuf or GString instead.")


# N.B. more detailed value_string checks are done in check_typed_item_calls.py
# XXX We might be able to speed this up by checking for *_string in file_words,
# but file_words is created after we strip out our strings.
def check_value_string_arrays(file_contents, filename, debug_flag, result):
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
                result.note(f"==> {filename:<35.35s}: {decl_m.group(1)}")
            result.note(vs)
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
            result.error(f"{filename:<35.35s}: {{{trailer_hint}}} is required as the last {type_name} array entry: {decl}")
            count += 1

        if not re.search(rf'(?:static)?const{vs_varname_re}', vs_nospace):
            decl_m = re.search(rf'({vs_varname_re}[^=]+)=', vsx)
            decl = decl_m.group(1) if decl_m else "?"
            result.error(f"{filename:<35.35s}: Missing 'const': {decl}")
            count += 1

        if re.search(newline_string_re, vs) and type_name != "bytes_string":
            decl_m = re.search(rf'({vs_varname_re}[^=]+)=', vsx)
            decl = decl_m.group(1) if decl_m else "?"
            result.error(f"{filename:<35.35s}: XXX_string contains a newline: {decl}")
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
                result.note(f"==> {filename:<35.35s}: {decl_m.group(1)}")
            result.note(vs)
        vs_nospace = re.sub(r'\s', '', vs)

        # README.developer says
        #  "Don't put a comma after the last tuple of an initializer of an array"
        # However: since this usage is present in some number of cases, we'll allow for now
        if not re.search(r'NULL,NULL,-?[0-9]\},?\};$', vs_nospace):
            decl_m = re.search(r'(enum_val_t[^=]+)=', vsx)
            decl = decl_m.group(1) if decl_m else "?"
            result.error(f"{filename:<35.35s}: {{NULL, NULL, ...}} is required as the last enum_val_t array entry: {decl}")
            count += 1

        if not re.search(r'(?:static)?constenum_val_t', vs_nospace):
            decl_m = re.search(r'(enum_val_t[^=]+)=', vsx)
            decl = decl_m.group(1) if decl_m else "?"
            result.error(f"{filename:<35.35s}: Missing 'const': {decl}")
            count += 1

        if re.search(newline_string_re, vs):
            decl_m = re.search(r'((?:value|string|range)_string[^=]+)=', vsx)
            decl = decl_m.group(1) if decl_m else "?"
            result.error(f"{filename:<35.35s}: enum_val_t contains a newline: {decl}")
            count += 1

    return count


def check_included_files(file_contents, filename, result):
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
                result.note(f"{filename}: Please use #include <{base}> instead of #include \"{base}\".")


def check_proto_tree_add_XXX(file_contents, filename, result):
    """Check for incorrect proto_tree_add_XXX usage."""

    items = re.findall(r'(proto_tree_add_[_a-z0-9]+)\s*\(\s*([^;]*)\)\s*;', file_contents, re.DOTALL)

    for func, args in items:
        # Check to make sure tvb_get* isn't used to pass into a
        # proto_tree_add_<datatype>, when proto_tree_add_item could be used
        if re.search(r',\s*tvb_get_', args, re.DOTALL):
            if re.match(r'^proto_tree_add_(time|bytes|ipxnet|ipv4|ipv6|ether|guid|oid|string|boolean|float|double|uint|uint64|int|int64|eui64|bitmask_list_value)$', func):
                result.error(": {filename} uses {func} with tvb_get_*. Use proto_tree_add_item instead")
                # Print out the function args to make it easier
                # to find the offending code.  But first make
                # it readable by eliminating extra white space.
                clean_args = re.sub(r'\s+', ' ', args)
                result.note(f"\tArgs: {clean_args}")

        # Remove anything inside parenthesis in the arguments so we
        # don't get false positives when someone calls
        # proto_tree_add_XXX(..., tvb_YYY(..., ENC_ZZZ))
        # and allow there to be newlines inside
        args_no_parens = re.sub(r'\(.*\)', '', args, flags=re.DOTALL)

        # Check for accidental usage of ENC_ parameter
        if re.search(r',\s*ENC_', args_no_parens, re.DOTALL):
            if not re.search(r'proto_tree_add_(time|item|bitmask|[a-z0-9]+_bits_format_value|bits_item|bits_ret_val|item_ret_int|item_ret_uint|bytes_item|checksum)', func):
                result.error(": {filename} uses {func} with ENC_*.")
                # Print out the function args to make it easier
                # to find the offending code.  But first make
                # it readable by eliminating extra white space.
                clean_args = re.sub(r'\s+', ' ', args)
                result.note(f"\tArgs: {clean_args}")


def check_ett_registration(file_contents, filename, result):
    """Verify that all declared ett_ variables are registered."""
    # Don't bother trying to check usage (for now)...

    # A pattern to match ett variable names.  Obviously this assumes that
    # they start with `ett_`
    ett_var_re = r'ett_[a-z0-9_]+(?:\[[0-9]+\])?'

    # Find all the ett_ variables declared in the file
    ett_declarations = re.findall(
        r'^(?:static\s+)int\s+(' + ett_var_re + r');',
        file_contents, re.MULTILINE | re.IGNORECASE)

    if not ett_declarations:
        # Only complain if the file looks like a dissector
        return 0

    # Find all the uses of the *addresses* of ett variables in the file.
    # (We assume if someone is using the address they're using it to
    # register the ett.)
    ett_address_uses = re.findall(r'&\s*(' + ett_var_re + r')', file_contents, re.IGNORECASE | re.MULTILINE)

    if not ett_address_uses:
        result.note(f"Found no ett address uses in {filename}")
        return 0

    # Convert to a set for fast lookup
    ett_uses = set(ett_address_uses)

    # Find which declared etts appear not to have been registered.
    unused_etts = [ett for ett in ett_declarations if ett not in ett_uses and '[' not in ett]

    if unused_etts:
        result.error(f"found these unregistered ett variables in {filename}: {' '.join(unused_etts)}")


def check_hf_entries(file_contents, filename, result):
    """Check all hf entries for various problems."""

    for i in HFEntriesParser(file_contents).items:
        hf, name, abbrev, ft, display, convert, bitmask, blurb = i

        display = re.sub(r'\s+', '', display)
        convert = re.sub(r'\s+', '', convert)
        # GET_VALS_EXTP is a macro in packet-mq.h
        convert = re.sub(r'\bGET_VALS_EXTP\(', 'VALS_EXT_PTR(', convert)

        if abbrev in ('""', 'NULL'):
            result.error(f"{hf} does not have an abbreviation in {filename}")
        if re.search(r'\.\.+', abbrev):
            result.error(f"the abbreviation for {hf} ({abbrev}) contains two or more sequential periods in {filename}")
        if name == abbrev:
            result.error(f"the abbreviation for {hf} ({abbrev}) matches the field name ({name}) in {filename}")
        if blurb != 'NULL' and name.lower() == blurb.lower():
            result.error(f"the blurb for {hf} ({blurb}) matches the field name ({name}) in {filename}")
        if re.match(r'"\s+', name):
            result.error(f"the name for {hf} ({name}) has leading space in {filename}")
        if re.search(r'\s+"', name):
            result.error(f"the name for {hf} ({name}) has trailing space in {filename}")
        if re.match(r'"\s+', blurb):
            result.error(f"the blurb for {hf} ({blurb}) has leading space in {filename}")
        if re.search(r'\s+"', blurb):
            result.error(": the blurb for {hf} ({blurb}) has trailing space in {filename}")
        if re.search(r'\s+', abbrev):
            result.error(": the abbreviation for {hf} ({abbrev}) has white space in {filename}")
        if f'"{hf}"' == name:
            result.error(": name is the hf_variable_name in field {name} ({abbrev}) in {filename}")
        if f'"{hf}"' == abbrev:
            result.error(": abbreviation is the hf_variable_name in field {name} ({abbrev}) in {filename}")
        if ft != "FT_BOOLEAN" and re.match(r'^TFS\(.*\)', convert):
            result.error(": {hf} uses a true/false string but is an {ft} instead of FT_BOOLEAN in {filename}")
        if ft == "FT_BOOLEAN" and re.match(r'^VALS\(.*\)', convert):
            result.error(": {hf} uses a value_string but is an FT_BOOLEAN in {filename}")
        if ft == "FT_BOOLEAN" and not re.match(r'^(?:0x)?0+$', bitmask) and re.match(r'^BASE_', display):
            result.error(": {hf}: FT_BOOLEAN with a bitmask must specify a 'parent field width' for 'display' in {filename}")
        if ft == "FT_BOOLEAN" and not re.match(r'^(?:(?:0[xX]0?)?0$|NULL$|TFS)', convert):
            result.error(": {hf}: FT_BOOLEAN with non-null 'convert' field missing TFS in {filename}")
        if re.search(r'RVALS', convert) and 'BASE_RANGE_STRING' not in display:
            result.error(": {hf} uses RVALS but 'display' does not include BASE_RANGE_STRING in {filename}")
        if re.search(r'VALS64', convert) and 'BASE_VAL64_STRING' not in display:
            result.error(": {hf} uses VALS64 but 'display' does not include BASE_VAL64_STRING in {filename}")
        if 'BASE_EXT_STRING' in display and not re.match(r'^(?:VALS_EXT_PTR\(|&)', convert):
            result.error(": {hf}: BASE_EXT_STRING should use VALS_EXT_PTR for 'strings' instead of '{convert}' in {filename}")
        if 'BASE_UNIT_STRING' in display and not re.match(r'^(?:(?:0[xX]0?)?0$|NULL$|UNS)', convert):
            result.error(": {hf}: BASE_UNIT_STRING with non-null 'convert' field missing UNS in {filename}")
        if re.match(r'^FT_U?INT(?:8|16|24|32)$', ft) and re.match(r'^VALS64\(', convert):
            result.error(": {hf}: 32-bit field must use VALS instead of VALS64 in {filename}")
        if re.match(r'^FT_U?INT(?:40|48|56|64)$', ft) and re.match(r'^VALS\(', convert):
            result.error(": {hf}: 64-bit field must use VALS64 instead of VALS in {filename}")
        if re.match(r'^(?:VALS|VALS64|RVALS)\(&.*\)', convert):
            m2 = re.match(r'^(VALS|VALS64|RVALS)', convert)
            result.error(f": {hf} is passing the address of a pointer to {m2.group(1)} in {filename}")
        if (not re.match(r'^(?:(?:0[xX]0?)?0$|NULL$|VALS|VALS64|VALS_EXT_PTR|RVALS|TIME_VALS|TFS|UNS|CF_FUNC|FRAMENUM_TYPE|&|STRINGS_ENTERPRISES)', convert) and
                'BASE_CUSTOM' not in display):
            result.error(": non-null {hf} 'convert' field missing 'VALS|VALS64|VALS_EXT_PTR|RVALS|TIME_VALS|TFS|UNS|CF_FUNC|FRAMENUM_TYPE|&|STRINGS_ENTERPRISES' in {filename} ?")


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


def check_pref_var_dupes(file_contents, filename, result):
    """Check for duplicate preference variable usage."""

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
        result.error(f"{filename}: found these preference variables used in more than one prefs_register_*_preference:\n\t{', '.join(dupes)}")


def check_try_catch(file_words, file_contents, filename, result):
    """Check for forbidden control flow changes in TRY/CATCH blocks."""
    if not set(('TRY', 'ENDTRY')) & file_words:
        return 0

    # Match TRY { ... } ENDTRY (with an optional '\' in case of a macro).
    items = re.findall(r'\bTRY\s*\{(.+?)\}\s*\\?\s*ENDTRY\b', file_contents, re.DOTALL)
    for block in items:
        if re.search(r'\breturn\b', block):
            result.error(": return is forbidden in TRY/CATCH in {filename}")

        goto_labels = re.findall(r'\bgoto\s+(\w+)', block)
        seen = set()
        for goto_label in goto_labels:
            if goto_label in seen:
                continue
            seen.add(goto_label)

            if not re.search(r'^\s*' + re.escape(goto_label) + r'\s*:', block, re.MULTILINE):
                result.error(": goto to label '{goto_label}' outside TRY/CATCH is forbidden in {filename}")


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


def checkFile(filename, source_dir, check_hf, check_value_string_array, debug_flag, check_shadow, machine_readable, api_groups):
    result = Result()

    file_contents = ''
    found_apis = []

    if source_dir and not os.path.exists(filename):
        filename = os.path.join(source_dir, filename)
    if not os.path.exists(filename):
        result.error(f'Warning: No such file: "{filename}"')
        return result

    # delete leading './'
    filename = re.sub(r'^\.\/', '', filename)
    if not os.path.isfile(filename):
        result.warn(f"{filename} is not of type file - skipping.")
        return result

    if has_utf8_bom(filename):
        result.error(f"Found UTF-8 BOM at start of file {filename}")
        return result

    # Read in the file
    line_num = 0
    with open(filename, 'rb') as f:
        raw = f.read()

    for line_num, line_bytes in enumerate(raw.split(b'\n'), 1):
        try:
            line_bytes.decode('utf-8')
        except UnicodeDecodeError:
            result.error(f"Found an invalid UTF-8 sequence on line {line_num} of {filename}")

    file_contents = raw.decode('utf-8', errors='replace')

    if re.search(r'\$Id.*\$', file_contents):
        result.warn(f"{filename} has an SVN Id tag. Please remove it!")

    if re.search(r'tab-width:\s*[0-7|9]+|tabstop=[0-7|9]+|tabSize=[0-7|9]+', file_contents):
        result.error("Found modelines with tabstops set to something other than 8 in {filename}")

    # Remove C/C++ comments
    file_contents = remove_comments(file_contents)

    # Optionally check the hf entries (including those under #if 0)
    if check_hf:
        check_hf_entries(file_contents, filename, result)

    if re.search(r'%\d*?ll', file_contents):
        # use PRI[dux...]N instead of ll
        result.error(f"Found %ll in {filename}")

    # check for files that we should not include directly
    check_included_files(file_contents, filename, result)

    # Check for value_string and enum_val_t errors
    if check_value_string_array:
        check_value_string_arrays(file_contents, filename, debug_flag, result)

    # Remove all the quoted strings, even across line continuations.
    # (?s:.) matches a newline (well, any character) without re.DOTALL.
    file_contents = re.sub(r'"(?:\\(?s:.)|[^\"\\])*\"|\'(?:\\(?s:.)|[^\'\\])*\'', '', file_contents)

    check_pref_var_dupes(file_contents, filename, result)

    # Remove all blank lines
    file_contents = re.sub(r'^\s*$\n', '', file_contents, flags=re.MULTILINE)

    # Remove all '#if 0'd' code
    file_contents = remove_if0_code(file_contents, filename)

    # The re patterns in find_api_in_file and check_shadow_variable
    # are slow. Create a set of words so that we can do a quick,
    # naive match first; this is faster than `api in file_contents`.
    # https://stackoverflow.com/a/58238304/82195

    # string.punctuation minus '_'; we could probably reduce this.
    c_punctuation = '!"#$%&\'()*+,-./:;<=>?@[\\]^`{|}~'
    file_words = set(file_contents.translate(str.maketrans(c_punctuation, ' ' * len(c_punctuation))).split())

    check_ett_registration(file_contents, filename, result)

    # check_apis_called_with_tvb_get_ptr(api_list, file_contents, found_apis);
    # if (found_apis) {
    #     print(f"Found APIs with embedded tvb_get_ptr() calls in {filename} : {','.join(found_apis)}")

    if check_shadow:
        found_apis = []
        check_shadow_variable(ShadowVariables, file_words, file_contents, found_apis)
        if found_apis:
            result.warn(f"Found shadow variable(s) in {filename} : {','.join(found_apis)}")

    check_snprintf_plus_strlen(file_contents, filename, result)

    check_complex_snprintf(file_contents, filename, result)

    check_proto_tree_add_XXX(file_contents, filename, result)

    check_try_catch(file_words, file_contents, filename, result)

    # Check and count APIs for this file
    for group in api_groups:
        pfx = OutputType.NOTE
        found_apis = []

        function_counts = {}
        find_api_in_file(APIs[group], file_words, file_contents, found_apis, function_counts)
        if function_counts:
            result.api_counts[group] = function_counts

        cur_func_count = sum(function_counts.values())

        # If we have a max function count and we've exceeded it, treat it
        # as an error.
        if 'max_function_count' in APIs[group]:
            if not APIs[group]['count_errors'] and APIs[group]['max_function_count'] >= 0:
                if cur_func_count > APIs[group]['max_function_count']:
                    result.output(pfx, f"{group} exceeds maximum function count: {APIs[group]['max_function_count']}")
                    APIs[group]['count_errors'] = True

            if cur_func_count <= APIs[group]['max_function_count']:
                continue

        # Do we care about the count of this type?
        if APIs[group]['count_errors']:
            pfx = OutputType.WARN

        if found_apis and not machine_readable:
            result.output(pfx, f"Found {group} APIs in {filename}: {','.join(found_apis)}")
        if found_apis and machine_readable:
            for api in found_apis:
                result.output(pfx, f"{group:<20.20s} {filename:<30.30s} {api:<45.45s}")

    return result


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
    parser.add_argument('--folder', action='store', default='',
                        help='specify folder to test')
    parser.add_argument('-h', '--help', action='store_true', default=False, dest='help_flag')
    parser.add_argument('files', nargs='*')

    args = parser.parse_args()

    if args.help_flag:
        print_usage()
        sys.exit(1)

    # Build the API groups list
    api_groups = list(DEFAULT_API_GROUPS)

    # Extra groups may have limits in them - split them up here
    for extra_group in args.groups:
        # Might be split into group:<max_count>
        group_parts = extra_group.split(':')

        if group_parts[0] not in APIs:
            print(f"Unknown API group '{group_parts[0]}'")
            continue

        if len(group_parts) > 1:
            APIs[group_parts[0]]['max_function_count'] = int(group_parts[1])

        api_groups.append(group_parts[0])

    # the pre-commit hook only calls checkAPIs one file at a time
    if args.pre_commit and args.files:
        filename = args.files[0]
        if isDissectorFile(filename):
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

    if args.folder:
        # Add all files from a given folder.
        folder = args.folder
        if not os.path.isdir(folder):
            print('Folder', folder, 'not found!')
            exit(1)
        # Find files from folder.
        print('Looking for files in', folder)
        filelist = findDissectorFilesInFolder(folder, recursive=True)

    if not filelist:
        print("no files to process")
        sys.exit(1)

    # Examine each chosen file.
    warnings_found = 0
    errors_found = 0

    filelist.sort()

    with concurrent.futures.ProcessPoolExecutor() as executor:
        future_to_file_output = {executor.submit(checkFile, file, args.source_dir, args.check_hf,
                                                 args.check_value_string_array, args.debug_flag, args.check_shadow,
                                                 args.machine_readable, api_groups): file for file in filelist}
        for future in concurrent.futures.as_completed(future_to_file_output):
            # File is done - show any output and update warning, error counts
            result = future.result()
            output = result.out.getvalue()
            if len(output):
                print(output[:-1])

            warnings_found += result.warnings
            errors_found += result.errors

            for api_group in result.api_counts:
                for fun, num in result.api_counts[api_group].items():
                    APIs[api_group]['function_counts'][fun] += num

            if result.should_exit:
                exit(1)

        # Show summary
        print()
        print(warnings_found, 'warnings found')
        if errors_found:
            print(errors_found, 'errors found')

    # Summary: Print Use Counts of each API in each requested summary group
    if args.summary_groups:
        fileline = ', '.join(args.files)
        print(f"\nSummary for {fileline[:65]}\u2026")

        for api_group in args.summary_groups:
            print(f'api_group is {api_group}')
            if api_group not in APIs:
                print(api_group, 'not in APIs')
                continue
            print(f"\nUse counts for {api_group} (maximum allowed total is {APIs[api_group]['max_function_count']})")
            for api in sorted(APIs[api_group]['function_counts'].keys(), key=str.lower):
                if APIs[api_group]['function_counts'][api] < 1:
                    continue
                print(f"{APIs[api_group]['function_counts'][api]:5d}  {api:<40.40s}")

    sys.exit(min(errors_found, 120))


if __name__ == '__main__':
    main()
