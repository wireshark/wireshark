#!/usr/bin/env perl
#
# Copyright 2013, William Meier (See AUTHORS file)
#
# Validate hf_... usage for a dissector file;
#
# Usage: checkhf.pl [--debug=?] <file or files>
#
# $Id$
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

## Note: This program is a re-implementation of the
##       original checkhf.pl written and (C) by Joerg Mayer.
##       The overall objective of the new implementation was to reduce
##         the number of false positives which occurred with the
##         original checkhf.pl
##
##       This program can be used to scan original .c source files or source
##        files which have been passed through a C pre-processor.
##       Operating on pre-prosessed source files is optimal; There should be
##        minimal false positives.
##       If the .c input is an original source file there may very well be
##        false positives/negatives due to the fact that the hf_... variables & etc
##        may be created via macros.
##
## ----- (The following is extracted from the original checkhf.pl with thanks to Joerg) -------
## Example:
## ~/work/wireshark/trunk/epan/dissectors> ../../tools/checkhf.pl packet-afs.c
## Unused entry: packet-afs.c, hf_afs_ubik_voteend
## Unused entry: packet-afs.c, hf_afs_ubik_errcode
## Unused entry: packet-afs.c, hf_afs_ubik_votetype
## ERROR: NO ARRAY: packet-afs.c, hf_afs_fs_ipaddr
##
## or checkhf.pl packet-*.c, which will check all the dissector files.
##
## NOTE: This tool currently generates false positives!
##
## The "NO ARRAY" messages - if accurate - points to an error that will
## cause (t|wire)shark to terminate with an assertion when a packet containing
## this particular element is being dissected.
##
## The "Unused entry" message indicates the opposite: We define an entry but
## never use it in a proto_...add... function.
## ------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------
# Main
#
# Logic:
# 1. Clean the input: remove blank lines, comments, quoted strings and code under '#if 0'.
# 2. hfDefs:
#            Find (and remove from input) list of hf_... variable
#            definitions ('static? g?int hf_... ;')
# 2. hfArrayEntries:
#            Find (and remove from input) list of hf_... variables
#            referenced in the hf[] entries;
# 3. hfUsage:
#            From the remaining input, extract list of all strings of form hf_...
#             (which may include strings which are not actually valid
#              hf_... variable references).
# 4. Checks:
#            If entries in hfDefs not in hfUsage then "unused" (or static hfDefs only)
#            If entries in hfDefs not in hfArrayEntries then "ERROR: NO ARRAY";

use strict;
use warnings;

use Getopt::Long;

my $helpFlag  = '';
my $debug     = 0;  # default: off; 1=cmt; 2=#if0; 3=hfDefs; 4=hfArrayEntries; 5=hfusage (See code)

my $sts = GetOptions(
                     'debug=i' => \$debug,
                     'help|?'  => \$helpFlag
                    );
if (!$sts || $helpFlag || !$ARGV[0]) {
    usage();
}

my $error = 0;

while (my $fileName = $ARGV[0]) {
    shift;

    my ($fileContents);
    my (%hfDefs, %hfStaticDefs, %hfArrayEntries, %hfUsage);
    my ($unUsedHRef, $noArrayHRef);

    read_file(\$fileName, \$fileContents);

    remove_blank_lines   (\$fileContents, $fileName);
    remove_comments      (\$fileContents, $fileName);
    remove_quoted_strings(\$fileContents, $fileName);
    remove_if0_code      (\$fileContents, $fileName);

    find_remove_hf_defs                    (\$fileContents, $fileName, \%hfDefs);
    find_remove_hf_array_entries           (\$fileContents, $fileName, \%hfArrayEntries);
    find_remove_proto_get_id_hf_assignments(\$fileContents, $fileName, \%hfArrayEntries);
    find_hf_usage                          (\$fileContents, $fileName, \%hfUsage);

# Tests (See above)
# 1. Are all the static hfDefs entries in hfUsage ?
#    if not: "Unused entry:"
#

    # create a hash containing entries just for the static definitions
    @hfStaticDefs{grep {$hfDefs{$_} == 0} keys %hfDefs} = ();  # All values in the new hash will be undef

    $unUsedHRef = diff_hash(\%hfStaticDefs, \%hfUsage);
    remove_hf_pid_from_unused_if_add_oui_call(\$fileContents, $fileName, $unUsedHRef);

    print_list("Unused entry: $fileName, ", $unUsedHRef);

# 2. Are all the hfDefs entries (static and global) in hfArrayEntries ?
#    (Note: if a static hfDef is "unused", don't check for same in hfArrayEntries)
#    if not: "ERROR: NO ARRAY"

##    Checking for missing global defs currently gives false positives
##    So: only check static defs for now.
##    $noArrayHRef  = diff_hash(\%hfDefs, \%hfArrayEntries);
    $noArrayHRef  = diff_hash(\%hfStaticDefs, \%hfArrayEntries);
    $noArrayHRef  = diff_hash($noArrayHRef, $unUsedHRef);     # Remove "unused" hf_... from noArray list

    print_list("ERROR: NO ARRAY: $fileName, ", $noArrayHRef);

    if ((keys %$noArrayHRef) != 0) {
        $error += 1;
    }
}

exit (($error == 0) ? 0 : 1);  # exit 1 if ERROR


# ---------------------------------------------------------------------
#
sub usage {
    print "Usage: $0 [--debug=n] Filename [...]\n";
    exit(1);
}

# ---------------------------------------------------------------------
# action:  read contents of a file to specified string
# arg:     fileNameRef, fileContentsRef

sub read_file {
    my ($fileNameRef, $fileContentsRef) = @_;

    die "No such file: \"$$fileNameRef\"\n" if (! -e $$fileNameRef);

    # delete leading './'
    $$fileNameRef =~ s{ ^ [.] / } {}xmso;

    # Read in the file (ouch, but it's easier that way)
    open(my $fci, "<:crlf", $$fileNameRef) || die("Couldn't open $$fileNameRef");

    $$fileContentsRef = do { local( $/ ) ; <$fci> } ;

    close($fci);

    return;
}

# ---------------------------------------------------------------------
# action:  Create a hash containing entries in 'a' that are not in 'b'
# arg:     aHRef, bHref
# returns: pointer to hash

sub diff_hash {
    my ($aHRef, $bHRef) = @_;

    my %diffs;

    @diffs{grep {! exists $bHRef->{$_}} keys %$aHRef} = ();  # All values in the new hash will be undef

    return \%diffs;
}

# ---------------------------------------------------------------------
# action:  print a list
# arg:     hdr, listHRef

sub print_list {
    my ($hdr, $listHRef) = @_;

    print
      map {"$hdr$_\n"}
        sort
          keys %$listHRef;

    return;
}

# ------------
# action:  remove blank lines from input string
# arg:     codeRef, fileName

sub remove_blank_lines {
    my ($codeRef, $fileName) = @_;

    $$codeRef =~ s{ ^ \s* \n ? } {}xmsog;

    return;
}

# ------------
# action:  remove comments from input string
# arg:     codeRef, fileName

sub remove_comments {
    my ($codeRef, $fileName) = @_;

    # The below Regexp is based on one from:
    # http://aspn.activestate.com/ASPN/Cookbook/Rx/Recipe/59811
    # It is in the public domain.
    # A complicated regex which matches C-style comments.
    # (Added: include trailing \n (if any) in deletion)
    my $CCommentRegEx = qr{ / [*] [^*]* [*]+ (?: [^/*] [^*]* [*]+ )* / \n ? }xmso;

    $$codeRef =~ s{ $CCommentRegEx } {}xmsog;

    ($debug == 1) && print "==> After Remove Comments: code: [$fileName]\n$$codeRef\n===<\n";

    return;
}

# ------------
# action:  remove quoted strings from input string
# arg:     codeRef, fileName

sub remove_quoted_strings {
    my ($codeRef, $fileName) = @_;

    # A regex which matches double-quoted strings.
    #    's' modifier added so that strings containing a 'line continuation'
    #    ( \ followed by a new-line) will match.
    my $DoubleQuotedStr = qr{ (?: ["] (?: \\. | [^\"\\])* ["]) }xmso;

    # A regex which matches single-quoted strings.
    my $SingleQuotedStr = qr{ (?: ['] (?: \\. | [^\'\\])* [']) }xmso;

    $$codeRef =~ s{ $DoubleQuotedStr | $SingleQuotedStr } {}xmsog;

    ($debug == 1) && print "==> After Remove quoted strings: code: [$fileName]\n$$codeRef\n===<\n";

    return;
}

# -------------
# action:  remove '#if 0'd code from the input string
# args     codeRef, fileName
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

    sub remove_if0_code {
        my ($codeRef, $fileName)  = @_;

        # First see if any '#if 0' lines which need to be handled
        if ($$codeRef !~ m{ \# \s* if \s+ 0 }xmso ) {
            return;
        }

        my ($preprocRegEx) = qr{
                                   (                                    # $1 [complete line)
                                       ^
                                       (?:                              # non-capturing
                                           \s* \# \s*
                                           (if \s 0| if | else | endif) # $2 (only if #...)
                                       ) ?
                                       [^\n]*
                                       \n ?
                                   )
                           }xmso;

        ($if_lvl, $if0_lvl, $if0) = (0,0,0);
        $$codeRef =~ s{ $preprocRegEx } { patsub($1,$2) }xmsoeg;

        ($debug == 2) && print "==> After Remove if0: code: [$fileName]\n$$codeRef\n===<\n";
        return;
    }

    sub patsub {
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
                    die "patsub: #if/#endif mismatch"
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

# ---------------------------------------------------------------------
# action:  Add to hash an entry for each
#             'static? g?int hf_...' definition (including array names)
#             in the input string.
#          The entry value will be 0 for 'static' definitions and 1 for 'global' definitions;
#          Remove each definition found from the input string.
# args:    codeRef, fileName, hfDefsHRef
# returns: ref to the hash

sub find_remove_hf_defs {
    my ($codeRef, $fileName, $hfDefsHRef) = @_;

    # Build pattern to match any of the following
    #  static? g?int hf_foo = -1;
    #  static? g?int hf_foo = HF_EMPTY;
    #  static? g?int hf_foo[xxx];
    #  static? g?int hf_foo[xxx] = {

    # p1: 'static? g?int hf_foo'
    my $p1RegEx = qr{
                        ^
                        \s*
                        (static)?
                        \s+
                        g?int
                        \s+
                        (hf_[a-zA-Z0-9_]+)          # hf_..
                }xmso;

    # p2a: ' = -1;' or ' = HF_EMPTY;'
    my  $p2aRegEx = qr{
                          \s* = \s*
                          (?:
                              - \s* 1 | HF_EMPTY
                          )
                          \s* ;
                  }xmso;

    # p2b: '[xxx];' or '[xxx] = {'
    my  $p2bRegEx = qr/
                          \s* \[ [^\]]+ \] \s*
                          (?:
                              = \s* [{] | ;
                          )
                      /xmso;

    my $hfDefRegEx = qr{ $p1RegEx (?: $p2aRegEx | $p2bRegEx ) }xmso;

    while ($$codeRef =~ m{ $hfDefRegEx }xmsog) {
        #print ">%s< >$2<\n", (defined $1) ? $1 ; "";
        $hfDefsHRef->{$2} = (defined $1) ? 0 : 1;  # 'static' if $1 is defined.
    }
    ($debug == 3) && debug_print_hash("VD: $fileName", $hfDefsHRef); # VariableDefinition

    # remove all
    $$codeRef =~ s{ $hfDefRegEx } {}xmsog;
    ($debug == 3) && print "==> After remove hfDefs: code: [$fileName]\n$$codeRef\n===<\n";

    return;
}

# ---------------------------------------------------------------------
# action:  Add to hash an entry (hf_...) for each hf[] entry.
#          Remove each hf[] entries found from the input string.
# args:    codeRef, fileName, hfArrayEntriesHRef

sub find_remove_hf_array_entries {
    my ($codeRef, $fileName, $hfArrayEntriesHRef) = @_;

#    hf[] entry regex (to extract an hf_index_name and associated field type)
    my $hfArrayEntryRegEx = qr /
                                   [{]
                                   \s*
                                   & \s* ( [a-zA-Z0-9_]+ )   # &hf
                                   (?:
                                       \s* [[] [^]]+ []]     # optional array ref
                                   ) ?
                                   \s* , \s*
                                   [{]
                                   [^}]+
                                   , \s*
                                   (FT_[a-zA-Z0-9_]+)        # field type
                                   \s* ,
                                   [^}]+
                                   , \s*
                                   (?:
                                       HFILL | HF_REF_TYPE_NONE
                                   )
                                   [^}]*
                                   }
                                   [\s,]*
                                   [}]
                           /xmso;

    # find all the hf[] entries (searching $$codeRef).
    while ($$codeRef =~ m{ $hfArrayEntryRegEx }xmsog) {
        ($debug == 98) && print "+++ $1 $2\n";
        $hfArrayEntriesHRef->{$1} = undef;
    }

    ($debug == 4) && debug_print_hash("AE: $fileName", $hfArrayEntriesHRef);  # ArrayEntry

    # now remove all
    $$codeRef =~ s{ $hfArrayEntryRegEx } {}xmsog;
    ($debug == 4) && print "==> After remove hfArrayEntries: code: [$fileName]\n$$codeRef\n===<\n";

    return;
}

# ---------------------------------------------------------------------
# action:  Add to hash an entry (hf_...) for each hf_... var
#          found in statements of the form:
#            'hf_...  = proto_registrar_get_id_byname ...'
#            'hf_...  = proto_get_id_by_filtername ...'
#          Remove each such statement found from the input string.
# args:    codeRef, fileName, hfArrayEntriesHRef

sub find_remove_proto_get_id_hf_assignments {
    my ($codeRef, $fileName, $hfArrayEntriesHRef) = @_;

    my $RegEx = qr{ ( hf_ [a-zA-Z0-9_]+ )
                    \s* = \s*
                    (?: proto_registrar_get_id_byname | proto_get_id_by_filter_name )
                  }xmso;

    my @hfvars = $$codeRef =~ m{ $RegEx }xmsog;

    if (@hfvars == 0) {
        return;
    }

    # found:
    #  Sanity check: hf_vars shouldn't already be in hfArrayEntries
    if (defined @$hfArrayEntriesHRef{@hfvars}) {
        printf "? one or more of [@hfvars] initialized via proto_registrar_get_by_name() also in hf[] ??\n";
    }

    #  Now: add to hfArrayEntries
    @$hfArrayEntriesHRef{@hfvars} = ();

    ($debug == 4) && debug_print_hash("PR: $fileName", $hfArrayEntriesHRef);

    # remove from input (so not considered as 'usage')
    $$codeRef =~ s{ $RegEx } {}xmsog;

    ($debug == 4) && print "==> After remove proto_registrar_by_name: code: [$fileName]\n$$codeRef\n===<\n";

    return;
}

# ---------------------------------------------------------------------
# action: Add to hash all hf_... strings remaining in input string.
# arga:   codeRef, fileName, hfUsageHRef
# return: ref to hfUsage hash
#
# The hash will include *all* strings of form hf_...
#   which are in the input string (even strings which
#   aren't actually vars).
#   We don't care since we'll be checking only
#   known valid vars against these strings.

sub find_hf_usage {
    my ($codeRef, $fileName, $hfUsageHRef) = @_;

    my $hfUsageRegEx = qr{
                             \b ( hf_[a-zA-Z0-9_]+ )      # hf_...
                     }xmso;

    while ($$codeRef =~ m{ $hfUsageRegEx }xmsog) {
        #print "$1\n";
        $hfUsageHRef->{$1} += 1;
    }

    ($debug == 5) && debug_print_hash("VU: $fileName", $hfUsageHRef); # VariableUsage

    return;
}

# ---------------------------------------------------------------------
# action: Remove from 'unused' hash an instance of a variable named hf_..._pid
#          if the source has a call to llc_add_oui() or ieee802a_add_oui().
#          (This is rather a bit of a hack).
# arga:   codeRef, fileName, unUsedHRef

sub remove_hf_pid_from_unused_if_add_oui_call {
    my ($codeRef, $fileName, $unUsedHRef) = @_;

    if ((keys %$unUsedHRef) == 0) {
        return;
    }

    my @hfvars = grep { m/ ^ hf_ [a-zA-Z0-9_]+ _pid $ /xmso} keys $unUsedHRef;

    if ((@hfvars == 0) || (@hfvars > 1)) {
        return;  # if multiple unused hf_..._pid
    }

    if ($$codeRef !~ m{ llc_add_oui | ieee802a_add_oui }xmso) {
        return;
    }

    # hf_...pid unused var && a call to ..._add_oui(); delete entry from unused
    # XXX: maybe hf_..._pid should really be added to hfUsed ?
    delete @$unUsedHRef{@hfvars};

    return;
}

# ---------------------------------------------------------------------
sub debug_print_hash {
    my ($title, $HRef) = @_;

    ##print "==> $title\n";
    for my $k (sort keys %$HRef) {
        printf "%-40.40s %5.5s %s\n", $title, $HRef->{$k} // "undef", $k;
    }
}
