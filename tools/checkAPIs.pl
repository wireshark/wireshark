#!/usr/bin/env perl

#
# Copyright 2006, Jeff Morriss <jeff.morriss.ws[AT]gmail.com>
#
# A simple tool to check source code for function calls that should not
# be called by Wireshark code and to perform certain other checks.
#
# Usage:
# checkAPIs.pl [-M] [-g group1] [-g group2] ...
#              [-s summary-group1] [-s summary-group2] ...
#              [--nocheck-value-string-array]
#              [--nocheck-addtext] [--nocheck-hf] [--debug] file1 file2 ...
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

use strict;
use Getopt::Long;
use Text::Balanced qw(extract_bracketed);

my %APIs = (
        # API groups.
        # Group name, e.g. 'prohibited'
        # '<name>' => {
        #   'count_errors'      => 1,                     # 1 if these are errors, 0 if warnings
        #   'functions'         => [ 'f1', 'f2', ...],    # Function array
        #   'function-counts'   => {'f1',0, 'f2',0, ...}, # Function Counts hash (initialized in the code)
        # }
        #
        # APIs that MUST NOT be used in Wireshark
        'prohibited' => { 'count_errors' => 1, 'functions' => [
                # Memory-unsafe APIs
                # Use something that won't overwrite the end of your buffer instead
                # of these.
                #
                # Microsoft provides lists of unsafe functions and their
                # recommended replacements in "Security Development Lifecycle
                # (SDL) Banned Function Calls"
                # https://msdn.microsoft.com/en-us/library/bb288454.aspx
                # and "Deprecated CRT Functions"
                # https://msdn.microsoft.com/en-us/library/ms235384.aspx
                #
                'atoi', # use wsutil/strtoi.h functions
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
                'strdup',
                'strndup',
                # Windows doesn't have this; use g_ascii_strtoull() instead
                'strtoull',
                ### non-portable: fails on Windows Wireshark built with VC newer than VC6
                # See https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6695#c2
                'g_fprintf',
                'g_vfprintf',
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
                'atof',
                'strtod',
                'strcasecmp',
                'strncasecmp',
                'g_strcasecmp',
                'g_strncasecmp',
                'g_strup',
                'g_strdown',
                'g_string_up',
                'g_string_down',
                'strerror',     # use g_strerror
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
                # Misc
                'tmpnam',       # use mkstemp
                '_snwprintf'    # use StringCchPrintf
                ] },

        ### Soft-Deprecated functions that should not be used in new code but
        # have not been entirely removed from old code. These will become errors
        # once they've been removed from all existing code.
        'soft-deprecated' => { 'count_errors' => 0, 'functions' => [
                'tvb_length_remaining', # replaced with tvb_captured_length_remaining

                # Locale-unsafe APIs
                # These may have unexpected behaviors in some locales (e.g.,
                # "I" isn't always the upper-case form of "i", and "i" isn't
                # always the lower-case form of "I").  Use the g_ascii_* version
                # instead.
                'toupper'
            ] },

        # APIs that SHOULD NOT be used in Wireshark (any more)
        'deprecated' => { 'count_errors' => 1, 'functions' => [
                'perror',                                       # Use g_strerror() and report messages in whatever
                                                                #  fashion is appropriate for the code in question.
                'ctime',                                        # Use abs_time_secs_to_str()
                'next_tvb_add_port',                            # Use next_tvb_add_uint() (and a matching change
                                                                #  of NTVB_PORT -> NTVB_UINT)

                ### Deprecated GLib/GObject functions/macros
                # (The list is based upon the GLib 2.30.2 & GObject 2.30.2 documentation;
                #  An entry may be commented out if it is currently
                #  being used in Wireshark and if the replacement functionality
                #  is not available in all the GLib versions that Wireshark
                #  currently supports.
                # Note: Wireshark currently (Jan 2012) requires GLib 2.14 or newer.
                #  The Wireshark build currently (Jan 2012) defines G_DISABLE_DEPRECATED
                #  so use of any of the following should cause the Wireshark build to fail and
                #  therefore the tests for obsolete GLib function usage in checkAPIs should not be needed.
                'G_ALLOC_AND_FREE',
                'G_ALLOC_ONLY',
                'g_allocator_free',                             # "use slice allocator" (avail since 2.10,2.14)
                'g_allocator_new',                              # "use slice allocator" (avail since 2.10,2.14)
                'g_async_queue_ref_unlocked',                   # g_async_queue_ref()   (OK since 2.8)
                'g_async_queue_unref_and_unlock',               # g_async_queue_unref() (OK since 2.8)
                'g_atomic_int_exchange_and_add',                # since 2.30
                'g_basename',
                'g_blow_chunks',                                # "use slice allocator" (avail since 2.10,2.14)
                'g_cache_value_foreach',                        # g_cache_key_foreach()
                'g_chunk_free',                                 # g_slice_free (avail since 2.10)
                'g_chunk_new',                                  # g_slice_new  (avail since 2.10)
                'g_chunk_new0',                                 # g_slice_new0 (avail since 2.10)
                'g_completion_add_items',                       # since 2.26
                'g_completion_clear_items',                     # since 2.26
                'g_completion_complete',                        # since 2.26
                'g_completion_complete_utf8',                   # since 2.26
                'g_completion_free',                            # since 2.26
                'g_completion_new',                             # since 2.26
                'g_completion_remove_items',                    # since 2.26
                'g_completion_set_compare',                     # since 2.26
                'G_CONST_RETURN',                               # since 2.26
                'g_date_set_time',                              # g_date_set_time_t (avail since 2.10)
                'g_dirname',
                'g_format_size_for_display',                    # since 2.30: use g_format_size()
                'G_GNUC_FUNCTION',
                'G_GNUC_PRETTY_FUNCTION',
                'g_hash_table_freeze',
                'g_hash_table_thaw',
                'G_HAVE_GINT64',
                'g_io_channel_close',
                'g_io_channel_read',
                'g_io_channel_seek',
                'g_io_channel_write',
                'g_list_pop_allocator',                         # "does nothing since 2.10"
                'g_list_push_allocator',                        # "does nothing since 2.10"
                'g_main_destroy',
                'g_main_is_running',
                'g_main_iteration',
                'g_main_new',
                'g_main_pending',
                'g_main_quit',
                'g_main_run',
                'g_main_set_poll_func',
                'g_mapped_file_free',                           # [as of 2.22: use g_map_file_unref]
                'g_mem_chunk_alloc',                            # "use slice allocator" (avail since 2.10)
                'g_mem_chunk_alloc0',                           # "use slice allocator" (avail since 2.10)
                'g_mem_chunk_clean',                            # "use slice allocator" (avail since 2.10)
                'g_mem_chunk_create',                           # "use slice allocator" (avail since 2.10)
                'g_mem_chunk_destroy',                          # "use slice allocator" (avail since 2.10)
                'g_mem_chunk_free',                             # "use slice allocator" (avail since 2.10)
                'g_mem_chunk_info',                             # "use slice allocator" (avail since 2.10)
                'g_mem_chunk_new',                              # "use slice allocator" (avail since 2.10)
                'g_mem_chunk_print',                            # "use slice allocator" (avail since 2.10)
                'g_mem_chunk_reset',                            # "use slice allocator" (avail since 2.10)
                'g_node_pop_allocator',                         # "does nothing since 2.10"
                'g_node_push_allocator',                        # "does nothing since 2.10"
                'g_relation_count',                             # since 2.26
                'g_relation_delete',                            # since 2.26
                'g_relation_destroy',                           # since 2.26
                'g_relation_exists',                            # since 2.26
                'g_relation_index',                             # since 2.26
                'g_relation_insert',                            # since 2.26
                'g_relation_new',                               # since 2.26
                'g_relation_print',                             # since 2.26
                'g_relation_select',                            # since 2.26
                'g_scanner_add_symbol',
                'g_scanner_remove_symbol',
                'g_scanner_foreach_symbol',
                'g_scanner_freeze_symbol_table',
                'g_scanner_thaw_symbol_table',
                'g_slist_pop_allocator',                        # "does nothing since 2.10"
                'g_slist_push_allocator',                       # "does nothing since 2.10"
                'g_source_get_current_time',                    # since 2.28: use g_source_get_time()
                'g_strcasecmp',                                 #
                'g_strdown',                                    #
                'g_string_down',                                #
                'g_string_sprintf',                             # use g_string_printf() instead
                'g_string_sprintfa',                            # use g_string_append_printf instead
                'g_string_up',                                  #
                'g_strncasecmp',                                #
                'g_strup',                                      #
                'g_tree_traverse',
                'g_tuples_destroy',                             # since 2.26
                'g_tuples_index',                               # since 2.26
                'g_unicode_canonical_decomposition',            # since 2.30: use g_unichar_fully_decompose()
                'G_UNICODE_COMBINING_MARK',                     # since 2.30:use G_UNICODE_SPACING_MARK
                'g_value_set_boxed_take_ownership',             # GObject
                'g_value_set_object_take_ownership',            # GObject
                'g_value_set_param_take_ownership',             # GObject
                'g_value_set_string_take_ownership',            # Gobject
                'G_WIN32_DLLMAIN_FOR_DLL_NAME',
                'g_win32_get_package_installation_directory',
                'g_win32_get_package_installation_subdirectory',
                'qVariantFromValue'
                ] },

        # APIs that make the program exit. Dissectors shouldn't call these
        'abort' => { 'count_errors' => 1, 'functions' => [
                'abort',
                'assert',
                'assert_perror',
                'exit',
                'g_assert',
                'g_error',
                ] },

        # APIs that print to the terminal. Dissectors shouldn't call these
        'termoutput' => { 'count_errors' => 0, 'functions' => [
                'printf',
                'g_warning',
                ] },

);

my @apiGroups = qw(prohibited deprecated soft-deprecated);


# Given a ref to a hash containing "functions" and "functions_count" entries:
# Determine if any item of the list of APIs contained in the array referenced by "functions"
# exists in the file.
# For each API which appears in the file:
#     Push the API onto the provided list;
#     Add the number of times the API appears in the file to the total count
#      for the API (stored as the value of the API key in the hash referenced by "function_counts").

sub findAPIinFile($$$)
{
        my ($groupHashRef, $fileContentsRef, $foundAPIsRef) = @_;

        for my $api ( @{$groupHashRef->{functions}} )
        {
                my $cnt = 0;
                # Match function calls, but ignore false positives from:
                # C++ method definition: int MyClass::open(...)
                # Method invocation: myClass->open(...);
                # Function declaration: int open(...);
                # Method invocation: QString().sprintf(...)
                while (${$fileContentsRef} =~ m/ \W (?<!::|->|\w\ ) (?<!\.) $api \W* \( /gx)
                {
                        $cnt += 1;
                }
                if ($cnt > 0) {
                        push @{$foundAPIsRef}, $api;
                        $groupHashRef->{function_counts}->{$api} += 1;
                }
        }
}

# APIs which (generally) should not be called with an argument of tvb_get_ptr()
my @TvbPtrAPIs = (
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
);

sub checkAPIsCalledWithTvbGetPtr($$$)
{
        my ($APIs, $fileContentsRef, $foundAPIsRef) = @_;

        for my $api (@{$APIs}) {
                my @items;
                my $cnt = 0;

                @items = (${$fileContentsRef} =~ m/ ($api [^;]* ; ) /xsg);
                while (@items) {
                        my ($item) = @items;
                        shift @items;
                        if ($item =~ / tvb_get_ptr /xos) {
                                $cnt += 1;
                        }
                }

                if ($cnt > 0) {
                        push @{$foundAPIsRef}, $api;
                }
        }
}

# List of possible shadow variable (Majority coming from macOS..)
my @ShadowVariable = (
        'index',
        'time',
        'strlen',
        'system'
);

sub checkShadowVariable($$$)
{
        my ($groupHashRef, $fileContentsRef, $foundAPIsRef) = @_;

        for my $api ( @{$groupHashRef} )
        {
                my $cnt = 0;
                while (${$fileContentsRef} =~ m/ \s $api \s*+ [^\(\w] /gx)
                {
                        $cnt += 1;
                }
                if ($cnt > 0) {
                        push @{$foundAPIsRef}, $api;
                }
        }
}

sub check_snprintf_plus_strlen($$)
{
        my ($fileContentsRef, $filename) = @_;
        my @items;

        # This catches both snprintf() and g_snprint.
        # If we need to do more APIs, we can make this function look more like
        # checkAPIsCalledWithTvbGetPtr().
        @items = (${$fileContentsRef} =~ m/ (snprintf [^;]* ; ) /xsg);
        while (@items) {
                my ($item) = @items;
                shift @items;
                if ($item =~ / strlen\s*\( /xos) {
                        print STDERR "Warning: ".$filename." uses snprintf + strlen to assemble strings.\n";
                        last;
                }
        }
}

#### Regex for use when searching for value-string definitions
my $StaticRegex             = qr/ static \s+                                                            /xs;
my $ConstRegex              = qr/ const  \s+                                                            /xs;
my $Static_andor_ConstRegex = qr/ (?: $StaticRegex $ConstRegex | $StaticRegex | $ConstRegex)            /xs;
my $ValueStringVarnameRegex = qr/ (?:value|val64|string|range|bytes)_string                             /xs;
my $ValueStringRegex        = qr/ ^ \s* $Static_andor_ConstRegex ($ValueStringVarnameRegex) \ + [^;*]+ = [^;]+ [{] .+? [}] \s*? ;  /xms;
my $EnumValRegex            = qr/ $Static_andor_ConstRegex enum_val_t \ + [^;*]+ = [^;]+ [{] .+? [}] \s*? ;  /xs;
my $NewlineStringRegex      = qr/ ["] [^"]* \\n [^"]* ["] /xs;

sub check_value_string_arrays($$$)
{
        my ($fileContentsRef, $filename, $debug_flag) = @_;
        my $cnt = 0;
        # Brute force check for value_string (and string_string or range_string) arrays
        # which are missing {0, NULL} as the final (terminating) array entry

        #  Assumption: definition is of form (pseudo-Regex):
        #    " (static const|static|const) (value|string|range)_string .+ = { .+ ;"
        #  (possibly over multiple lines)
        while (${$fileContentsRef} =~ / ( $ValueStringRegex ) /xsog) {
                # XXX_string array definition found; check if NULL terminated
                my $vs = my $vsx = $1;
                my $type = $2;
                if ($debug_flag) {
                        $vsx =~ / ( .+ $ValueStringVarnameRegex [^=]+ ) = /xo;
                        printf STDERR "==> %-35.35s: %s\n", $filename, $1;
                        printf STDERR "%s\n", $vs;
                }
                $vs =~ s{ \s } {}xg;

                # Check for expected trailer
                my $expectedTrailer;
                my $trailerHint;
                if ($type eq "string_string") {
                        # XXX shouldn't we reject 0 since it is gchar*?
                        $expectedTrailer = "(NULL|0), NULL";
                        $trailerHint = "NULL, NULL";
                } elsif ($type eq "range_string") {
                        $expectedTrailer = "0(x0+)?, 0(x0+)?, NULL";
                        $trailerHint = "0, 0, NULL";
                } elsif ($type eq "bytes_string") {
                        # XXX shouldn't we reject 0 since it is guint8*?
                        $expectedTrailer = "(NULL|0), 0, NULL";
                        $trailerHint = "NULL, NULL";
                } else {
                        $expectedTrailer = "0(x?0+)?, NULL";
                        $trailerHint = "0, NULL";
                }
                if ($vs !~ / [{] $expectedTrailer [}] ,? [}] ; $/x) {
                        $vsx =~ /( $ValueStringVarnameRegex [^=]+ ) = /xo;
                        printf STDERR "Error: %-35.35s: {%s} is required as the last %s array entry: %s\n", $filename, $trailerHint, $type, $1;
                        $cnt++;
                }

                if ($vs !~ / (static)? const $ValueStringVarnameRegex /xo)  {
                        $vsx =~ /( $ValueStringVarnameRegex [^=]+ ) = /xo;
                        printf STDERR "Error: %-35.35s: Missing 'const': %s\n", $filename, $1;
                        $cnt++;
                }
                if ($vs =~ / $NewlineStringRegex /xo && $type ne "bytes_string")  {
                        $vsx =~ /( $ValueStringVarnameRegex [^=]+ ) = /xo;
                        printf STDERR "Error: %-35.35s: XXX_string contains a newline: %s\n", $filename, $1;
                        $cnt++;
                }
        }

        # Brute force check for enum_val_t arrays which are missing {NULL, NULL, ...}
        # as the final (terminating) array entry
        # For now use the same option to turn this and value_string checking on and off.
        # (Is the option even necessary?)

        #  Assumption: definition is of form (pseudo-Regex):
        #    " (static const|static|const) enum_val_t .+ = { .+ ;"
        #  (possibly over multiple lines)
        while (${$fileContentsRef} =~ / ( $EnumValRegex ) /xsog) {
                # enum_val_t array definition found; check if NULL terminated
                my $vs = my $vsx = $1;
                if ($debug_flag) {
                        $vsx =~ / ( .+ enum_val_t [^=]+ ) = /xo;
                        printf STDERR "==> %-35.35s: %s\n", $filename, $1;
                        printf STDERR "%s\n", $vs;
                }
                $vs =~ s{ \s } {}xg;
                # README.developer says
                #  "Don't put a comma after the last tuple of an initializer of an array"
                # However: since this usage is present in some number of cases, we'll allow for now
                if ($vs !~ / NULL, NULL, -?[0-9] [}] ,? [}] ; $/xo) {
                        $vsx =~ /( enum_val_t [^=]+ ) = /xo;
                        printf STDERR "Error: %-35.35s: {NULL, NULL, ...} is required as the last enum_val_t array entry: %s\n", $filename, $1;
                        $cnt++;
                }
                if ($vs !~ / (static)? const enum_val_t /xo)  {
                        $vsx =~ /( enum_val_t [^=]+ ) = /xo;
                        printf STDERR "Error: %-35.35s: Missing 'const': %s\n", $filename, $1;
                        $cnt++;
                }
                if ($vs =~ / $NewlineStringRegex /xo)  {
                        $vsx =~ /( (?:value|string|range)_string [^=]+ ) = /xo;
                        printf STDERR "Error: %-35.35s: enum_val_t contains a newline: %s\n", $filename, $1;
                        $cnt++;
                }
        }

        return $cnt;
}


sub check_included_files($$)
{
        my ($fileContentsRef, $filename) = @_;
        my @incFiles;

        @incFiles = (${$fileContentsRef} =~ m/\#include \s* ([<"].+[>"])/gox);

        # only our wrapper file wsutils/wsgcrypt.h may include gcrypt.h
        # all other files should include the wrapper
        if ($filename !~ /wsgcrypt\.h/) {
                foreach (@incFiles) {
                        if ( m#([<"]|/+)gcrypt\.h[>"]$# ) {
                                print STDERR "Warning: ".$filename.
                                        " includes gcrypt.h directly. ".
                                        "Include wsutil/wsgrypt.h instead.\n";
                                last;
                        }
                }
        }

        # only our wrapper file wsutils/wspcap.h may include pcap.h
        # all other files should include the wrapper
        if ($filename !~ /wspcap\.h/) {
                foreach (@incFiles) {
                        if ( m#([<"]|/+)pcap\.h[>"]$# ) {
                                print STDERR "Warning: ".$filename.
                                        " includes pcap.h directly. ".
                                        "Include wsutil/wspcap.h instead.\n";
                                last;
                        }
                }
        }

        # files in the ui/qt directory should include the ui class includes
        # by using #include <>
        # this ensures that Visual Studio picks up these files from the
        # build directory if we're compiling with cmake
        if ($filename =~ m#ui/qt/# ) {
                foreach (@incFiles) {
                        if ( m#"ui_.*\.h"$# ) {
                                # strip the quotes to get the base name
                                # for the error message
                                s/\"//g;

                                print STDERR "$filename: ".
                                        "Please use #include <$_> ".
                                        "instead of #include \"$_\".\n";
                        }
                }
        }
}


sub check_proto_tree_add_XXX($$)
{
        my ($fileContentsRef, $filename) = @_;
        my @items;
        my $errorCount = 0;

        @items = (${$fileContentsRef} =~ m/ (proto_tree_add_[_a-z0-9]+) \( ([^;]*) \) \s* ; /xsg);

        while (@items) {
                my ($func) = @items;
                shift @items;
                my ($args) = @items;
                shift @items;

                #Check to make sure tvb_get* isn't used to pass into a proto_tree_add_<datatype>, when
                #proto_tree_add_item could just be used instead
                if ($args =~ /,\s*tvb_get_/xos) {
                        if (($func =~ m/^proto_tree_add_(time|bytes|ipxnet|ipv4|ipv6|ether|guid|oid|string|boolean|float|double|uint|uint64|int|int64|eui64|bitmask_list_value)$/)
                           ) {
                                print STDERR "Error: ".$filename." uses $func with tvb_get_*. Use proto_tree_add_item instead\n";
                                $errorCount++;

                                # Print out the function args to make it easier
                                # to find the offending code.  But first make
                                # it readable by eliminating extra white space.
                                $args =~ s/\s+/ /g;
                                print STDERR "\tArgs: " . $args . "\n";
                        }
                }

                # Remove anything inside parenthesis in the arguments so we
                # don't get false positives when someone calls
                # proto_tree_add_XXX(..., tvb_YYY(..., ENC_ZZZ))
                # and allow there to be newlines inside
                $args =~ s/\(.*\)//sg;

                #Check for accidental usage of ENC_ parameter
                if ($args =~ /,\s*ENC_/xos) {
                        if (!($func =~ /proto_tree_add_(time|item|bitmask|bits_item|bits_ret_val|item_ret_int|item_ret_uint|bytes_item|checksum)/xos)
                           ) {
                                print STDERR "Error: ".$filename." uses $func with ENC_*.\n";
                                $errorCount++;

                                # Print out the function args to make it easier
                                # to find the offending code.  But first make
                                # it readable by eliminating extra white space.
                                $args =~ s/\s+/ /g;
                                print STDERR "\tArgs: " . $args . "\n";
                        }
                }
        }

        return $errorCount;
}


# Verify that all declared ett_ variables are registered.
# Don't bother trying to check usage (for now)...
sub check_ett_registration($$)
{
        my ($fileContentsRef, $filename) = @_;
        my @ett_declarations;
        my %ett_registrations;
        my @unRegisteredEtts;
        my $errorCount = 0;

        # A pattern to match ett variable names.  Obviously this assumes that
        # they start with ett_
        my $EttVarName = qr{ (?: ett_[a-z0-9_]+ (?:\[[0-9]+\])? ) }xi;

        # Remove macro lines
        my $fileContents = ${$fileContentsRef};
        $fileContents =~ s { ^\s*\#.*$} []xogm;

        # Find all the ett_ variables declared in the file
        @ett_declarations = ($fileContents =~ m{
                ^\s*static              # assume declarations are on their own line
                \s+
                g?int                   # could be int or gint
                \s+
                ($EttVarName)           # variable name
                \s*=\s*
                -1\s*;
        }xgiom);

        if (!@ett_declarations) {
                print STDERR "Found no etts in ".$filename."\n";
                return;
        }

        #print "Found these etts in ".$filename.": ".join(',', @ett_declarations)."\n\n";

        # Find the array used for registering the etts
        # Save off the block of code containing just the variables
        my @reg_blocks;
        @reg_blocks = ($fileContents =~ m{
                static
                \s+
                g?int
                \s*\*\s*                # it's an array of pointers
                [a-z0-9_]+              # array name; usually (always?) "ett"
                \s*\[\s*\]\s*           # array brackets
                =
                \s*\{
                ((?:\s*&\s*             # address of the following variable
                $EttVarName             # variable name
                \s*,?                   # the comma is optional (for the last entry)
                \s*)+)                  # match one or more variable names
                \}
                \s*
                ;
        }xgios);
        #print "Found this ett registration block in ".$filename.": ".join(',', @reg_blocks)."\n";

        if (@reg_blocks == 0) {
                print STDERR "Hmm, found ".@reg_blocks." ett registration blocks in ".$filename."\n";
                # For now...
                return;
        }

        while (@reg_blocks) {
                my ($block) = @reg_blocks;
                shift @reg_blocks;

                # Convert the list returned by the match into a hash of the
                # form ett_variable_name -> 1.  Then combine this new hash with
                # the hash from the last registration block.
                # (Of course) using hashes makes the lookups much faster.
                %ett_registrations = map { $_ => 1 } ($block =~ m{
                        \s*&\s*                 # address of the following variable
                        ($EttVarName)           # variable name
                        \s*,?                   # the comma is optional (for the last entry)
                }xgios, %ett_registrations);
        }
        #print "Found these ett registrations in ".$filename.": ";
        #while( my ($k, $v) = each %ett_registrations ) {
        #          print "$k\n";
        #}

        # Find which declared etts are not registered.
        # XXX - using <@ett_declarations> and $_ instead of $ett_var makes this
        # MUCH slower...  Why?
        while (@ett_declarations) {
                my ($ett_var) = @ett_declarations;
                shift @ett_declarations;

                push(@unRegisteredEtts, $ett_var) if (!$ett_registrations{$ett_var});
        }

        if (@unRegisteredEtts) {
                print STDERR "Error: found these unregistered ett variables in ".$filename.": ".join(',', @unRegisteredEtts)."\n";
                $errorCount++;
        }

        return $errorCount;
}

# Given the file contents and a file name, check all of the hf entries for
# various problems (such as those checked for in proto.c).
sub check_hf_entries($$)
{
        my ($fileContentsRef, $filename) = @_;
        my $errorCount = 0;

        my @items;
        @items = (${$fileContentsRef} =~ m{
                                  \{
                                  \s*
                                  &\s*([A-Z0-9_\[\]-]+)         # &hf
                                  \s*,\s*
                                  \{\s*
                                  ("[A-Z0-9 '\./\(\)_:-]+")     # name
                                  \s*,\s*
                                  (NULL|"[A-Z0-9_\.-]*")        # abbrev
                                  \s*,\s*
                                  (FT_[A-Z0-9_]+)               # field type
                                  \s*,\s*
                                  ([A-Z0-9x\|_]+)               # display
                                  \s*,\s*
                                  ([^,]+?)                      # convert
                                  \s*,\s*
                                  ([A-Z0-9_]+)                  # bitmask
                                  \s*,\s*
                                  (NULL|"[A-Z0-9 '\./\(\)\?_:-]+")      # blurb (NULL or a string)
                                  \s*,\s*
                                  HFILL                         # HFILL
        }xgios);

        #print "Found @items items\n";
        while (@items) {
                ##my $errorCount_save = $errorCount;
                my ($hf, $name, $abbrev, $ft, $display, $convert, $bitmask, $blurb) = @items;
                shift @items; shift @items; shift @items; shift @items; shift @items; shift @items; shift @items; shift @items;

                #print "name=$name, abbrev=$abbrev, ft=$ft, display=$display, convert=>$convert<, bitmask=$bitmask, blurb=$blurb\n";

                if ($abbrev eq '""' || $abbrev eq "NULL") {
                        print STDERR "Error: $hf does not have an abbreviation in $filename\n";
                        $errorCount++;
                }
                if ($abbrev =~ m/\.\.+/) {
                        print STDERR "Error: the abbreviation for $hf ($abbrev) contains two or more sequential periods in $filename\n";
                        $errorCount++;
                }
                if ($name eq $abbrev) {
                        print STDERR "Error: the abbreviation for $hf ($abbrev) matches the field name ($name) in $filename\n";
                        $errorCount++;
                }
                if (lc($name) eq lc($blurb)) {
                        print STDERR "Error: the blurb for $hf ($blurb) matches the field name ($name) in $filename\n";
                        $errorCount++;
                }
                if ($name =~ m/"\s+/) {
                        print STDERR "Error: the name for $hf ($name) has leading space in $filename\n";
                        $errorCount++;
                }
                if ($name =~ m/\s+"/) {
                        print STDERR "Error: the name for $hf ($name) has trailing space in $filename\n";
                        $errorCount++;
                }
                if ($blurb =~ m/"\s+/) {
                        print STDERR "Error: the blurb for $hf ($blurb) has leading space in $filename\n";
                        $errorCount++;
                }
                if ($blurb =~ m/\s+"/) {
                        print STDERR "Error: the blurb for $hf ($blurb) has trailing space in $filename\n";
                        $errorCount++;
                }
                if ($abbrev =~ m/\s+/) {
                        print STDERR "Error: the abbreviation for $hf ($abbrev) has white space in $filename\n";
                        $errorCount++;
                }
                if ("\"".$hf ."\"" eq $name) {
                        print STDERR "Error: name is the hf_variable_name in field $name ($abbrev) in $filename\n";
                        $errorCount++;
                }
                if ("\"".$hf ."\"" eq $abbrev) {
                        print STDERR "Error: abbreviation is the hf_variable_name in field $name ($abbrev) in $filename\n";
                        $errorCount++;
                }
                if ($ft ne "FT_BOOLEAN" && $convert =~ m/^TFS\(.*\)/) {
                        print STDERR "Error: $hf uses a true/false string but is an $ft instead of FT_BOOLEAN in $filename\n";
                        $errorCount++;
                }
                if ($ft eq "FT_BOOLEAN" && $convert =~ m/^VALS\(.*\)/) {
                        print STDERR "Error: $hf uses a value_string but is an FT_BOOLEAN in $filename\n";
                        $errorCount++;
                }
                if (($ft eq "FT_BOOLEAN") && ($bitmask !~ /^(0x)?0+$/) && ($display =~ /^BASE_/)) {
                        print STDERR "Error: $hf: FT_BOOLEAN with a bitmask must specify a 'parent field width' for 'display' in $filename\n";
                        $errorCount++;
                }
                if (($ft eq "FT_BOOLEAN") && ($convert !~ m/^((0[xX]0?)?0$|NULL$|TFS)/)) {
                        print STDERR "Error: $hf: FT_BOOLEAN with non-null 'convert' field missing TFS in $filename\n";
                        $errorCount++;
                }
                if ($convert =~ m/RVALS/ && $display !~ m/BASE_RANGE_STRING/) {
                        print STDERR "Error: $hf uses RVALS but 'display' does not include BASE_RANGE_STRING in $filename\n";
                        $errorCount++;
                }
                if ($convert =~ m/^VALS\(&.*\)/) {
                        print STDERR "Error: $hf is passing the address of a pointer to VALS in $filename\n";
                        $errorCount++;
                }
                if ($convert =~ m/^RVALS\(&.*\)/) {
                        print STDERR "Error: $hf is passing the address of a pointer to RVALS in $filename\n";
                        $errorCount++;
                }
                if ($convert !~ m/^((0[xX]0?)?0$|NULL$|VALS|VALS64|VALS_EXT_PTR|RVALS|TFS|CF_FUNC|FRAMENUM_TYPE|&|STRINGS_ENTERPRISES)/ && $display !~ /BASE_CUSTOM/) {
                        print STDERR "Error: non-null $hf 'convert' field missing 'VALS|VALS64|RVALS|TFS|CF_FUNC|FRAMENUM_TYPE|&|STRINGS_ENTERPRISES' in $filename ?\n";
                        $errorCount++;
                }
## Benign...
##              if (($ft eq "FT_BOOLEAN") && ($bitmask =~ /^(0x)?0+$/) && ($display ne "BASE_NONE")) {
##                      print STDERR "Error: $abbrev: FT_BOOLEAN with no bitmask must use BASE_NONE for 'display' in $filename\n";
##                      $errorCount++;
##              }
                ##if ($errorCount != $errorCount_save) {
                ##        print STDERR "name=$name, abbrev=$abbrev, ft=$ft, display=$display, convert=>$convert<, bitmask=$bitmask, blurb=$blurb\n";
                ##}

        }

        return $errorCount;
}

sub check_pref_var_dupes($$)
{
        my ($filecontentsref, $filename) = @_;
        my $errorcount = 0;

        # Avoid flagging the actual prototypes
        return 0 if $filename =~ /prefs\.[ch]$/;

        # remove macro lines
        my $filecontents = ${$filecontentsref};
        $filecontents =~ s { ^\s*\#.*$} []xogm;

        # At what position is the variable in the prefs_register_*_preference() call?
        my %prefs_register_var_pos = (
                static_text => undef, obsolete => undef, # ignore
                decode_as_range => -2, range => -2, filename => -2, # second to last
                enum => -3, # third to last
                # everything else is the last argument
        );

        my @dupes;
        my %count;
        while ($filecontents =~ /prefs_register_(\w+?)_preference/gs) {
                my ($args) = extract_bracketed(substr($filecontents, $+[0]), '()');
                $args = substr($args, 1, -1); # strip parens

                my $pos = $prefs_register_var_pos{$1};
                next if exists $prefs_register_var_pos{$1} and not defined $pos;
                $pos //= -1;
                my $var = (split /\s*,\s*(?![^(]*\))/, $args)[$pos]; # only commas outside parens
                push @dupes, $var if $count{$var}++ == 1;
        }

        if (@dupes) {
                print STDERR "$filename: error: found these preference variables used in more than one prefs_register_*_preference:\n\t".join(', ', @dupes)."\n";
                $errorcount++;
        }

        return $errorcount;
}

sub print_usage
{
        print "Usage: checkAPIs.pl [-M] [-h] [-g group1] [-g group2] ... \n";
        print "                    [--build] [-s group1] [-s group2] ... \n";
        print "                    [--sourcedir=srcdir] \n";
        print "                    [--nocheck-value-string-array] \n";
        print "                    [--nocheck-addtext] [--nocheck-hf] [--debug]\n";
        print "                    [--file=/path/to/file_list]\n";
        print "                    file1 file2 ...\n";
        print "\n";
        print "       -M: Generate output for -g in 'machine-readable' format\n";
        print "       -p: used by the git pre-commit hook\n";
        print "       -h: help, print usage message\n";
        print "       -g <group>:  Check input files for use of APIs in <group>\n";
        print "                    (in addition to the default groups)\n";
        print "       -s <group>:  Output summary (count) for each API in <group>\n";
        print "                    (-g <group> also req'd)\n";
        print "       ---nocheck-value-string-array: UNDOCUMENTED\n";
        print "       ---nocheck-addtext: UNDOCUMENTED\n";
        print "       ---nocheck-hf: UNDOCUMENTED\n";
        print "       ---debug: UNDOCUMENTED\n";
        print "       ---build: UNDOCUMENTED\n";
        print "\n";
        print "   Default Groups[-g]: ", join (", ", sort @apiGroups), "\n";
        print "   Available Groups:   ", join (", ", sort keys %APIs), "\n";
}

# -------------
# action:  remove '#if 0'd code from the input string
# args     codeRef, fileName
# returns: codeRef
#
# Essentially: Use s//patsub/meg to pass each line to patsub.
#              patsub monitors #if/#if 0/etc and determines
#               if a particular code line should be removed.
# XXX: This is probably pretty inefficient;
#      I could imagine using another approach such as converting
#       the input string to an array of lines and then making
#       a pass through the array deleting lines as needed.

{  # block begin
my ($if_lvl, $if0_lvl, $if0); # shared vars
my $debug = 0;

    sub remove_if0_code {
        my ($codeRef, $fileName)  = @_;

        my ($preprocRegEx) = qr {
                                    (                                    # $1 [complete line)
                                        ^
                                        (?:                              # non-capturing
                                            \s* \# \s*
                                            (if \s 0| if | else | endif) # $2 (only if #...)
                                        ) ?
                                        .*
                                        $
                                    )
                            }xom;

        ($if_lvl, $if0_lvl, $if0) = (0,0,0);
        $$codeRef =~ s{ $preprocRegEx }{patsub($1,$2,$fileName)}xegm;

        ($debug == 2) && print "==> After Remove if0: code: [$fileName]\n$$codeRef\n===<\n";
        return $codeRef;
    }

    sub patsub {
        my $fileName = @_[2];

        if ($debug == 99) {
            print "-->$_[0]\n";
            (defined $_[1]) && print "  >$_[1]<\n";
        }

        # #if/#if 0/#else/#endif processing
        if (defined $_[1]) {
            my ($if) = $_[1];
            if ($if eq 'if') {
                $if_lvl += 1;
            } elsif ($if eq 'if 0') {
                $if_lvl += 1;
                if ($if0_lvl == 0) {
                    $if0_lvl = $if_lvl;
                    $if0     = 1;  # inside #if 0
                }
            } elsif ($if eq 'else') {
                if ($if0_lvl == $if_lvl) {
                    $if0 = 0;
                }
            } elsif ($if eq 'endif') {
                if ($if0_lvl == $if_lvl) {
                    $if0     = 0;
                    $if0_lvl = 0;
                }
                $if_lvl -= 1;
                if ($if_lvl < 0) {
                    die "patsub: #if/#endif mismatch in $fileName"
                }
            }
            return $_[0];  # don't remove preprocessor lines themselves
        }

        # not preprocessor line: See if under #if 0: If so, remove
        if ($if0 == 1) {
            return '';  # remove
        }
        return $_[0];
    }
}  # block end

# The below Regexp are based on those from:
# http://aspn.activestate.com/ASPN/Cookbook/Rx/Recipe/59811
# They are in the public domain.

# 1. A complicated regex which matches "classic C"-style comments.
my $CComment = qr{ / [*] [^*]* [*]+ (?: [^/*] [^*]* [*]+ )* / }x;

# 1.a A regex that matches C++/C99-and-later-style comments.
# XXX handle comments after a statement and not just at the beginning of a line.
my $CppComment = qr{ ^ \s* // (.*?) \n }xm;

# 2. A regex which matches double-quoted strings.
#    ?s added so that strings containing a 'line continuation'
#    ( \ followed by a new-line) will match.
my $DoubleQuotedStr = qr{ (?: ["] (?s: \\. | [^\"\\])* ["]) }x;

# 3. A regex which matches single-quoted strings.
my $SingleQuotedStr = qr{ (?: \' (?: \\. | [^\'\\])* [']) }x;

# 4. Now combine 1 through 3 to produce a regex which
#    matches _either_ double or single quoted strings
#    OR comments. We surround the comment-matching
#    regex in capturing parenthesis to store the contents
#    of the comment in $1.
#    my $commentAndStringRegex = qr{(?:$DoubleQuotedStr|$SingleQuotedStr)|($CComment)|($CppComment)};

#
# MAIN
#
my $errorCount = 0;

# The default list, which can be expanded.
my @apiSummaryGroups = ();
my $check_value_string_array= 1;                        # default: enabled
my $machine_readable_output = 0;                        # default: disabled
my $check_hf = 1;                                       # default: enabled
my $check_addtext = 1;                                  # default: enabled
my $debug_flag = 0;                                     # default: disabled
my $buildbot_flag = 0;
my $source_dir = "";
my $filenamelist = "";
my $help_flag = 0;
my $pre_commit = 0;

my $result = GetOptions(
                        'group=s' => \@apiGroups,
                        'summary-group=s' => \@apiSummaryGroups,
                        'check-value-string-array!' => \$check_value_string_array,
                        'Machine-readable' => \$machine_readable_output,
                        'check-hf!' => \$check_hf,
                        'check-addtext!' => \$check_addtext,
                        'build' => \$buildbot_flag,
                        'sourcedir=s' => \$source_dir,
                        'debug' => \$debug_flag,
                        'pre-commit' => \$pre_commit,
                        'file=s' => \$filenamelist,
                        'help' => \$help_flag
                        );
if (!$result || $help_flag) {
        print_usage();
        exit(1);
}

# the pre-commit hook only calls checkAPIs one file at a time, so this
# is safe to do globally (and easier)
if ($pre_commit) {
    my $filename = $ARGV[0];
    # if the filename is packet-*.c or packet-*.h, then we set the abort and termoutput groups.
    if ($filename =~ /\bpacket-[^\/\\]+\.[ch]$/) {
        push @apiGroups, "abort";
        push @apiGroups, "termoutput";
    }
}

# Add a 'function_count' anonymous hash to each of the 'apiGroup' entries in the %APIs hash.
for my $apiGroup (keys %APIs) {
        my @functions = @{$APIs{$apiGroup}{functions}};

        $APIs{$apiGroup}->{function_counts}   = {};
        @{$APIs{$apiGroup}->{function_counts}}{@functions} = ();  # Add fcn names as keys to the anonymous hash
}

my @filelist;
push @filelist, @ARGV;
if ("$filenamelist" ne "") {
        # We have a file containing a list of files to check (possibly in
        # addition to those on the command line).
        open(FC, $filenamelist) || die("Couldn't open $filenamelist");

        while (<FC>) {
                # file names can be separated by ;
                push @filelist, split(';');
        }
        close(FC);
}

die "no files to process" unless (scalar @filelist);

# Read through the files; do various checks
while ($_ = pop @filelist)
{
        my $filename = $_;
        my $fileContents = '';
        my @foundAPIs = ();
        my $line;

        if ($source_dir and ! -e $filename) {
                $filename = $source_dir . '/' . $filename;
        }
        if (! -e $filename) {
                warn "No such file: \"$filename\"";
                next;
        }

        # delete leading './'
        $filename =~ s{ ^ \. / } {}xo;
        unless (-f $filename) {
                print STDERR "Warning: $filename is not of type file - skipping.\n";
                next;
        }

        # Read in the file (ouch, but it's easier that way)
        open(FC, $filename) || die("Couldn't open $filename");
        $line = 1;
        while (<FC>) {
                $fileContents .= $_;
                if ($_ =~ m{ [\x80-\xFF] }xo) {
                        print STDERR "Error: Found non-ASCII characters on line " .$line. " of " .$filename."\n";
                        $errorCount++;
                }
                $line++;
        }
        close(FC);

        if (($fileContents =~ m{ \$Id .* \$ }xo))
        {
                print STDERR "Warning: ".$filename." has an SVN Id tag. Please remove it!\n";
        }

        if (($fileContents =~ m{ tab-width:\s*[0-7|9]+ | tabstop=[0-7|9]+ | tabSize=[0-7|9]+ }xo))
        {
                # To quote Icf0831717de10fc615971fa1cf75af2f1ea2d03d :
                # HT tab stops are set every 8 spaces on UN*X; UN*X tools that treat an HT character
                # as tabbing to 4-space tab stops, or that even are configurable but *default* to
                # 4-space tab stops (I'm looking at *you*, Xcode!) are broken. tab-width: 4,
                # tabstop=4, and tabSize=4 are errors if you ever expect anybody to look at your file
                # with a UN*X tool, and every text file will probably be looked at by a UN*X tool at
                # some point, so Don't Do That.
                #
                # Can I get an "amen!"?
                print STDERR "Error: Found modelines with tabstops set to something other than 8 in " .$filename."\n";
                $errorCount++;
        }

        # Remove all the C/C++ comments
        $fileContents =~ s{ $CComment | $CppComment } []xog;

        # optionally check the hf entries (including those under #if 0)
        if ($check_hf) {
            $errorCount += check_hf_entries(\$fileContents, $filename);
        }

        if ($fileContents =~ m{ __func__ }xo)
        {
                print STDERR "Error: Found __func__ (which is not portable, use G_STRFUNC) in " .$filename."\n";
                $errorCount++;
        }
        if ($fileContents =~ m{ %ll }xo)
        {
                # use G_GINT64_MODIFIER instead of ll
                print STDERR "Error: Found %ll in " .$filename."\n";
                $errorCount++;
        }
        if ($fileContents =~ m{ %hh }xo)
        {
                # %hh is C99 and Windows doesn't like it:
                # http://connect.microsoft.com/VisualStudio/feedback/details/416843/sscanf-cannot-not-handle-hhd-format
                # Need to use temporary variables instead.
                print STDERR "Error: Found %hh in " .$filename."\n";
                $errorCount++;
        }

        # check for files that we should not include directly
        # this must be done before quoted strings (#include "file.h") are removed
        check_included_files(\$fileContents, $filename);

        # Check for value_string and enum_val_t errors: NULL termination,
        # const-nes, and newlines within strings
        if ($check_value_string_array) {
                $errorCount += check_value_string_arrays(\$fileContents, $filename, $debug_flag);
        }

        # Remove all the quoted strings
        $fileContents =~ s{ $DoubleQuotedStr | $SingleQuotedStr } []xog;

        #$errorCount += check_ett_registration(\$fileContents, $filename);
        $errorCount += check_pref_var_dupes(\$fileContents, $filename);

        # Remove all blank lines
        $fileContents =~ s{ ^ \s* $ } []xog;

        # Remove all '#if 0'd' code
        remove_if0_code(\$fileContents, $filename);

        #checkAPIsCalledWithTvbGetPtr(\@TvbPtrAPIs, \$fileContents, \@foundAPIs);
        #if (@foundAPIs) {
        #       print STDERR "Found APIs with embedded tvb_get_ptr() calls in ".$filename." : ".join(',', @foundAPIs)."\n"
        #}

        checkShadowVariable(\@ShadowVariable, \$fileContents, \@foundAPIs);
        if (@foundAPIs) {
               print STDERR "Warning: Found shadow variable(s) in ".$filename." : ".join(',', @foundAPIs)."\n"
        }


        check_snprintf_plus_strlen(\$fileContents, $filename);

        $errorCount += check_proto_tree_add_XXX(\$fileContents, $filename);


        # Check and count APIs
        for my $apiGroup (@apiGroups) {
                my $pfx = "Warning";
                @foundAPIs = ();

                findAPIinFile($APIs{$apiGroup}, \$fileContents, \@foundAPIs);

                if ($APIs{$apiGroup}->{count_errors}) {
                        # the use of "prohibited" APIs is an error, increment the error count
                        $errorCount += @foundAPIs;
                        $pfx = "Error";
                }

                if (@foundAPIs && ! $machine_readable_output) {
                        print STDERR $pfx . ": Found " . $apiGroup . " APIs in ".$filename.": ".join(',', @foundAPIs)."\n";
                }
                if (@foundAPIs && $machine_readable_output) {
                        for my $api (@foundAPIs) {
                                printf STDERR "%-8.8s %-20.20s %-30.30s %-45.45s\n", $pfx, $apiGroup, $filename, $api;
                        }
                }
        }
}

# Summary: Print Use Counts of each API in each requested summary group

for my $apiGroup (@apiSummaryGroups) {
        printf "\n\nUse Counts\n";
        for my $api (sort {"\L$a" cmp "\L$b"} (keys %{$APIs{$apiGroup}->{function_counts}}   )) {
                printf "%-20.20s %5d  %-40.40s\n", $apiGroup . ':', $APIs{$apiGroup}{function_counts}{$api}, $api;
        }
}

exit($errorCount);

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: nil
# End:
#
# vi: set shiftwidth=8 tabstop=8 expandtab:
# :indentSize=8:tabSize=8:noTabs=true:
#
