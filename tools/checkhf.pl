#!/usr/bin/perl
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
# 1. Clean the input: remove comments and code under '#if 0'.
# 2. hfDefs:
#            Find (and remove from input) list of static hf_ variable
#            definitions ('static int hf_... ;')
# 2. hfArrayEntries:
#            Find (and remove from input) list of hf_... variables
#            referenced in the hf[] entries;
# 3. hfUsage:
#            From the remaining input, extract list of all strings of form hf_...
#             (which may include strings which are not actually valid
#              hf_... variable references).
# 4. Checks:
#            If entries in hfDefs not in hfUsage then "unused";
#            If entries in hfDefs not in hfArrayEntries then "ERROR: NO ARRAY";

use strict;
use warnings;

use Getopt::Long;

my $helpFlag  = '';
my $debug     = 0;  # default: off; 1=cmt; 2=#if0; 3=hfDefs; 4=hfArrayEntry; 5=hfusage (See code)

my $sts = GetOptions(
                     'debug=i' => \$debug,
                     'help|?'  => \$helpFlag
                    );
if (!$sts || $helpFlag || !$ARGV[0]) {
    usage();
}

while (my $fileName = $ARGV[0]) {
    shift;

    my ($fileContents, $fileCleanedContents);
    my ($hfDefHRef, $hfArrayEntryHRef, $hfUsageHRef);
    my ($unUsedHRef, $noArrayHRef);

    read_file(\$fileName, \$fileContents);

    $fileCleanedContents = $fileContents;

    remove_comments(\$fileCleanedContents, $fileName);
    remove_if0_code(\$fileCleanedContents, $fileName);

    $hfDefHRef        = find_remove_hf_defs(\$fileCleanedContents, $fileName);
    $hfArrayEntryHRef = find_remove_hf_array_entries(\$fileCleanedContents, $fileName);
    $hfUsageHRef      = find_hf_usage(\$fileCleanedContents);

# Tests (See above)
# 1. Are all the hfDef entries in hfUsage ?
#    if not: "Unused entry:"
#
    $unUsedHRef = diff_hash($hfDefHRef, $hfUsageHRef);
    print_list("Unused entry: $fileName, ", $unUsedHRef);

# 2. Are all the hfDef entries in hfArrayEntry ?
#    (Note: if hfDef is "unused", don't check for same in hfArrayEntry)
#    if not: "ERROR: NO ARRAY"

    $noArrayHRef  = diff_hash($hfDefHRef, $hfArrayEntryHRef);
    $noArrayHRef  = diff_hash($noArrayHRef, $unUsedHRef);     # Remove "unused" hf_... from noArray list
    print_list("ERROR: NO ARRAY: $fileName, ", $noArrayHRef);
}

# ---------------------------------------------------------------------
#
sub usage {
    print "Usage: $0 [--debug=n] Filename [...] #debug: 1=cmt; 2=#if0; 3=hfDefs; 4=hfArrayEntry; 5=hfUsage\n";
    exit(1);
}

# ---------------------------------------------------------------------
# action:  read contents of a file to specified string
# arg:     fileNameRef, fileContentsRef
# returns: fileContentsRef (containing the contents of the file)

sub read_file {
    my ($fileNameRef, $fileContentsRef) = @_;

    die "No such file: \"$$fileNameRef\"\n" if (! -e $$fileNameRef);

    # delete leading './'
    $$fileNameRef =~ s{ ^ \. / } {}xo;

    $$fileContentsRef = '';
    # Read in the file (ouch, but it's easier that way)
    open(FCI, "<", $$fileNameRef) || die("Couldn't open $$fileNameRef");
    while (<FCI>) {
        $$fileContentsRef .= $_;
    }
    close(FCI);

    return $fileContentsRef;
}

# ---------------------------------------------------------------------
# action:  Create a hash containing entries in 'a' that are not in 'b'
# arg:     aHRef, bHref
# returns: pointer to hash

sub diff_hash {
    my ($aHRef, $bHRef) = @_;

    my %diffs;

    @diffs{grep {! exists $$bHRef{$_}} keys %$aHRef} = {};  # each key in the new hash
                                                            #  will have value 'undef'

    return \%diffs;
}

# ---------------------------------------------------------------------
# action:  print a list
# arg:     hdr, listHRef
# returns: nothing

sub print_list {
    my ($hdr, $listHRef) = @_;

    print
      map {"$hdr$_\n"}
        sort
          keys %$listHRef;
}

# ------------
# action:  remove comments from input string
# arg:     codeRef, fileName
# returns: codeRef

sub remove_comments {
    my ($codeRef, $fileName) = @_;

    # The below Regexp is based on one from:
    # http://aspn.activestate.com/ASPN/Cookbook/Rx/Recipe/59811
    # It is in the public domain.
    # A complicated regex which matches C-style comments.
    my $CCommentRegEx = qr{ / [*] [^*]* [*]+ (?: [^/*] [^*]* [*]+ )* / }xo;

    $$codeRef =~ s {$CCommentRegEx} []xg;

    ($debug == 1) && print "==> After Remove Comments: code: [$fileName]\n$$codeRef\n===<\n";

    return $codeRef
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
        $$codeRef =~ s{ $preprocRegEx }{patsub($1,$2)}xegm;

        ($debug == 2) && print "==> After Remove if0: code: [$fileName]\n$$codeRef\n===<\n";
        return $codeRef;
    }

    sub patsub {
        if ($debug == 99) {
            print "-->$_[0]\n";
            (defined $_[1]) && print "  >$_[1]<\n";
        }

        # #if/#if 0/#else/#ndif processing
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
# action:  Create a hash containing an entry (hf_... => 1) for each
#             'static g?int hf_...' definition (including array names)
#             in the input string.
#          Remove each definition found from the input string.
# args:    codeRef, fileName
# returns: ref to the hash

sub find_remove_hf_defs {
    my ($codeRef, $fileName) = @_;

    # Build pattern to match any of the following
    #  static g?int hf_foo = -1;
    #  static g?int hf_foo = HF_EMPTY;
    #  static g?int hf_foo[xxx];
    #  static g?int hf_foo[xxx] = {

    # p1: 'static g?int hf_foo'
    my $p1RegEx = qr {
                          ^
                          \s*
                          static
                          \s+
                          g?int
                          \s+
                          (hf_[a-zA-Z0-9_]+)          # hf_..
                  }xom;

    # p2a: ' = -1;' or ' = HF_EMPTY;'
    my  $p2aRegEx = qr {
                           \s* = \s*
                           (?:
                               - \s* 1 | HF_EMPTY
                           )
                           \s* ;
                   }xom;

    # p2b: '[xxx];' or '[xxx] = {'
    my  $p2bRegEx = qr !
                           \s* \[ [^]]+ \] \s*
                           (?:
                               = \s* \{ | ;
                           )
                       !xom;

    my $hfDefRegEx = qr { $p1RegEx (?: $p2aRegEx | $p2bRegEx ) }xom;

    my %hfDefs;
    while ($$codeRef =~ m{ $hfDefRegEx }xogm) {
        #print "$1\n";
        $hfDefs{$1} = 1;
    }
    ($debug == 3) && print_hash("VD: $fileName", \%hfDefs); # VariableDefinition

    # remove all
    $$codeRef =~ s{ $hfDefRegEx }{}xiogm;
    ($debug == 3) && print "==> After remove hfDefs: code: [$fileName]\n$$codeRef\n===<\n";

    return \%hfDefs;
}

# ---------------------------------------------------------------------
# action:  Create a hash containing an entry (hf_...) for each hf[] entry.
#          Remove each hf[] entry found from the input string.
# args:    codeRef, fileName
# returns: ref to the hfArrayEntry hash

sub find_remove_hf_array_entries {
    my ($codeRef, $fileName) = @_;

#    hf[] entry regex (to extract an hf_index_name and associated field type)
    my $hfArrayEntryRegEx = qr {
                                   \{
                                   \s*
                                   & \s* ( [a-zA-Z0-9_]+ )   # &hf
                                   (?:
                                       \s* \[ [^]]+ \]       # optional array ref
                                   ) ?
                                   \s* , \s*
                                   \{ \s*
                                   .+?                       # Fix: (a bit dangerous)
                                   \s* , \s*
                                   (FT_[a-zA-Z0-9_]+)        # field type
                                   \s* , \s*
                                   .+?                       # Fix: (also a bit dangerous)
                                   \s* , \s*
                                   HFILL ,?                  # HFILL
                                   \s* \}
                           }xos;

    # find all the hf[] entries (searching $$codeRef).
    # Create a hash keyed by the hf_... string
    my %hfArrayEntry;
    while ($$codeRef =~ m{ $hfArrayEntryRegEx }xgos) {
        ($debug == 98) && print "+++ $1 $2\n";
        $hfArrayEntry{$1} = 1;
    }

    ($debug == 4) && print_hash("AE: $fileName", \%hfArrayEntry);  # ArrayEntry

    # now remove all
    $$codeRef =~ s{ $hfArrayEntryRegEx }{}xgois;
    ($debug == 4) && print "==> After remove hfArrayEntry: code: [$fileName]\n$$codeRef\n===<\n";

    return \%hfArrayEntry;
}

# ---------------------------------------------------------------------
# action: create hash of all hf_... strings remaining in input string.
# arga:   codeRef, fileName
# return: ref to hfUsage hash
#
# The hash will include *all* strings of form hf_...
#   which are in the input string (even strings which
#   aren't actually vars).
#   We don't care since we'll be checking only
#   known valid vars against these strings.

sub find_hf_usage {
    my ($codeRef, $fileName) = @_;

    my $hfUsageRegEx = qr {
                              \b ( hf_[a-zA-Z0-9_]+ )      # hf_...
                      }ox;
    my %hfUsage;

    while ($$codeRef =~ m{ $hfUsageRegEx }xog) {
        #print "$1\n";
        $hfUsage{$1} += 1;
    }

    ($debug == 5) && print_hash("VU: $fileName", \%hfUsage); # VariableUsage

    return \%hfUsage;
}

# ---------------------------------------------------------------------
sub print_hash {
    my ($title, $HRef) = @_;

    ##print "==> $title\n";
    for my $k (sort keys %$HRef) {
        printf "%-40.40s %s\n", $title, $k;
    }
}
