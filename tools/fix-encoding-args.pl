#!/usr/bin/perl -w
#
# Copyright 2011, William Meier <wmeier[AT]newsguy.com>
#
# A program to fix proto_tree_add_item() encoding args from TRUE/FALSE to ENC_?? as appropriate (and possible)
#
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

use strict;
use Getopt::Long;

# Conversion "Requests"

# Standard conversions
my $searchReplaceFalseTrueHRef =
  {
   "FALSE"              => "ENC_BIG_ENDIAN",
   "0"                  => "ENC_BIG_ENDIAN",
   "TRUE"               => "ENC_LITTLE_ENDIAN",
   "1"                  => "ENC_LITTLE_ENDIAN"
  };

my $searchReplaceEncNAHRef =
   {
    "FALSE"             => "ENC_NA",
    "0"                 => "ENC_NA",
    "TRUE"              => "ENC_NA",
    "1"                 => "ENC_NA",
    "ENC_LITTLE_ENDIAN" => "ENC_NA",
    "ENC_BIG_ENDIAN"    => "ENC_NA"
   };


# Conversion "request" structure
# (
#   [ <list of field types for which this conversion request applies> ],
#   { <hash of desired encoding arg conversions> }
# }

my @types_NA  =
  (
   [ qw (FT_NONE FT_BYTES FT_ETHER FT_IPv6 FT_IPXNET FT_OID)],
   $searchReplaceEncNAHRef
  );

my @types_INT =
  (
   [ qw (FT_UINT8 FT_UINT16 FT_UINT24 FT_UINT32 FT_UINT64 FT_INT8
         FT_INT16 FT_INT24 FT_INT32 FT_INT64 FT_FLOAT FT_DOUBLE)],
   $searchReplaceFalseTrueHRef
  );

my @types_MISC =
  (
   [ qw (FT_BOOLEAN FT_IPv4 FT_GUID FT_EUI64)],
   $searchReplaceFalseTrueHRef
  );

my @types_STRING =
  (
   [qw (FT_STRING FT_STRINGZ)],
   {
    "FALSE"                        => "ENC_ASCII|ENC_NA",
    "0"                            => "ENC_ASCII|ENC_NA",
    "TRUE"                         => "ENC_ASCII|ENC_NA",
    "1"                            => "ENC_ASCII|ENC_NA",
    "ENC_LITTLE_ENDIAN"            => "ENC_ASCII|ENC_NA",
    "ENC_BIG_ENDIAN"               => "ENC_ASCII|ENC_NA",
    "ENC_NA"                       => "ENC_ASCII|ENC_NA",

    "ENC_ASCII"                    => "ENC_ASCII|ENC_NA",
    "ENC_ASCII|ENC_LITTLE_ENDIAN"  => "ENC_ASCII|ENC_NA",
    "ENC_ASCII|ENC_BIG_ENDIAN"     => "ENC_ASCII|ENC_NA",

    "ENC_UTF_8"                    => "ENC_UTF_8|ENC_NA",
    "ENC_UTF_8|ENC_LITTLE_ENDIAN"  => "ENC_UTF_8|ENC_NA",
    "ENC_UTF_8|ENC_BIG_ENDIAN"     => "ENC_UTF_8|ENC_NA",

    "ENC_EBCDIC"                   => "ENC_EBCDIC|ENC_NA",
    "ENC_EBCDIC|ENC_LITTLE_ENDIAN" => "ENC_EBCDIC|ENC_NA",
    "ENC_EBCDIC|ENC_BIG_ENDIAN"    => "ENC_EBCDIC|ENC_NA",
   }
  );

my @types_UINT_STRING =
  (
   [qw (FT_UINT_STRING)],
   {
    "FALSE"                   => "ENC_ASCII|ENC_BIG_ENDIAN",
    "0"                       => "ENC_ASCII|ENC_BIG_ENDIAN",
    "TRUE"                    => "ENC_ASCII|ENC_LITTLE_ENDIAN",
    "1"                       => "ENC_ASCII|ENC_LITTLE_ENDIAN",
    "ENC_BIG_ENDIAN"          => "ENC_ASCII|ENC_BIG_ENDIAN",
    "ENC_LITTLE_ENDIAN"       => "ENC_ASCII|ENC_LITTLE_ENDIAN",
   }
  );

my @types_REG_PROTO  =
  (
   [ qw (REG_PROTO)],
   $searchReplaceEncNAHRef
  );

# For searching with no substitutions
my @types_TIME =  (
                    [qw (FT_ABSOLUTE_TIME FT_RELATIVE_TIME)],
                    {}
                   );

my @types_ALL =
  (
   [qw (
           FT_NONE
           FT_PROTOCOL
           FT_BOOLEAN
           FT_UINT8
           FT_UINT16
           FT_UINT24
           FT_UINT32
           FT_UINT64
           FT_INT8
           FT_INT16
           FT_INT24
           FT_INT32
           FT_INT64
           FT_FLOAT
           FT_DOUBLE
           FT_ABSOLUTE_TIME
           FT_RELATIVE_TIME
           FT_STRING
           FT_STRINGZ
           FT_UINT_STRING
           FT_ETHER
           FT_BYTES
           FT_UINT_BYTES
           FT_IPv4
           FT_IPv6
           FT_IPXNET
           FT_FRAMENUM
           FT_PCRE
           FT_GUID
           FT_OID
           FT_EUI64
      )],
   {# valid encoding args
    "a"=>"ENC_NA",
    "b"=>"ENC_LITTLE_ENDIAN",
    "c"=>"ENC_BIG_ENDIAN",

    "d"=>"ENC_ASCII|ENC_NA",
    "e"=>"ENC_ASCII|ENC_LITTLE_ENDIAN",
    "f"=>"ENC_ASCII|ENC_BIG_ENDIAN",

    "g"=>"ENC_UTF_8|ENC_NA",
    "h"=>"ENC_UTF_8|ENC_LITTLE_ENDIAN",
    "i"=>"ENC_UTF_8|ENC_BIG_ENDIAN",

    "j"=>"ENC_EBCDIC|ENC_NA",
    "k"=>"ENC_EBCDIC|ENC_LITTLE_ENDIAN",
    "l"=>"ENC_EBCDIC|ENC_BIG_ENDIAN",
   }
  );

#
# MAIN
#
my $writeFlag = '';
my $helpFlag  = '';

my $result = GetOptions(
                        'write'   => \$writeFlag,
                        'help|?'  => \$helpFlag
			);

if (!$result || $helpFlag || !$ARGV[0]) {
	print "\nUsage: $0 [--write] FILENAME [...]\n\n";
        print "  Fix proto_tree_add_item() encoding arg when possible in file(s)\n";
        print "  Fixes (if any) are listed on stdout)\n\n";
        print "  --write     create FILENAME.encoding-arg-fixes (original file with fixes)\n";
	exit(1);
}

# Read through the files; fix up encoding parameter of proto_tree_add_item() calls
# Essentially:
#  For each file {
#  .  Create a hash of the hf_index_names & associated field types from the entries in hf[]
#  .  For each requested "conversion request" {
#  .  .  For each hf[] entry hf_index_name with a field type in a set of specified field types {
#  .  .  .  For each proto_tree_add_item() statement
#  .  .  .  .  - replace encoding arg in proto_tree_add_item(..., hf_index_name, ..., 'encoding-arg')
#                  specific values ith new values
#  .  .  .  .  - print the statement showing the change
#  .  .  .  }
#  .  .  }
#  .  }
#  .  If requested and if replacements done: write new file "orig-filename.encoding-arg-fixes"
#  }
#
# Note: The proto_tree_add_item() encoding arg will be converted only if
#        the hf_index_name referenced is in one of the entries in hf[] in the same file

while (my $fileName = $ARGV[0]) {
    shift;
    my $fileContents = '';

    die "No such file: \"$fileName\"\n" if (! -e $fileName);

    # delete leading './'
    $fileName =~ s{ ^ \. / } {}xo;

    # Read in the file (ouch, but it's easier that way)
    open(FCI, "<", $fileName) || die("Couldn't open $fileName");
    while (<FCI>) {
        $fileContents .= $_;
    }
    close(FCI);

    # Create a hash of the hf[] entries (name_index_name=>field_type)
    my $hfArrayEntryFieldTypeHRef = find_hf_array_entries(\$fileContents, $fileName);

    my $found = 0;

    # Find and replace: alters proto_tree_add_item() encoding arg in $fileContents for:
    #     - hf[] entries with specified field types;
    #     - 'proto' as returned from proto_register_protocol()
    $found += fix_encoding_args(1, \@types_NA,          \$fileContents, $hfArrayEntryFieldTypeHRef, $fileName);
    $found += fix_encoding_args(1, \@types_INT,         \$fileContents, $hfArrayEntryFieldTypeHRef, $fileName);
    $found += fix_encoding_args(1, \@types_MISC,        \$fileContents, $hfArrayEntryFieldTypeHRef, $fileName);
    $found += fix_encoding_args(1, \@types_STRING,      \$fileContents, $hfArrayEntryFieldTypeHRef, $fileName);
    $found += fix_encoding_args(1, \@types_UINT_STRING, \$fileContents, $hfArrayEntryFieldTypeHRef, $fileName);
    $found += fix_encoding_args(1, \@types_REG_PROTO,   \$fileContents, $hfArrayEntryFieldTypeHRef, $fileName);

    # If desired and if any changes, write out the changed version to a file
    if (($writeFlag) && ($found > 0)) {
        open(FCO, ">", $fileName . ".encoding-arg-fixes");
#        open(FCO, ">", $fileName );
        print FCO "$fileContents";
        close(FCO);
    }
    exit $found;

# Optional searches:
# search for (and output) proto_tree_add_item() statements with invalid encoding arg for specified field types
#    fix_encoding_args(2, \@types_NA,          \$fileContents, $hfArrayEntryFieldTypeHRef, $fileName);
#    fix_encoding_args(2, \@types_INT,         \$fileContents, $hfArrayEntryFieldTypeHRef, $fileName);
#    fix_encoding_args(2, \@types_MISC,        \$fileContents, $hfArrayEntryFieldTypeHRef, $fileName);
#    fix_encoding_args(2, \@types_STRING,      \$fileContents, $hfArrayEntryFieldTypeHRef, $fileName);
#    fix_encoding_args(2, \@types_UINT_STRING, \$fileContents, $hfArrayEntryFieldTypeHRef, $fileName);
#    fix_encoding_args(2, \@types_ALL,         \$fileContents, $hfArrayEntryFieldTypeHRef, $fileName);
# search for (and output) proto_tree_add_item() statements with any encoding arg for specified field types
#    fix_encoding_args(3, \@types_TIME,        \$fileContents, $hfArrayEntryFieldTypeHRef, $fileName);
#
# Find all proto_tree_add_item() statements
#  and output same highlighting the encoding arg
#    find_all(\$fileContents, $fileName);

}

#==================================================================================

# Create a hash containing an entry (hf_index_name => field_type) for each hf[]entry.
# also: create an entry in the hash for the 'protocol name' variable (proto... => FT_PROTOCOL)
# returns: ref to the hash

sub find_hf_array_entries {
    my ($fileContentsRef, $fileName) = @_;

    # The below Regexp is based on one from:
    # http://aspn.activestate.com/ASPN/Cookbook/Rx/Recipe/59811
    # It is in the public domain.
    # A complicated regex which matches C-style comments.
    my $CCommentRegEx = qr{ / [*] [^*]* [*]+ (?: [^/*] [^*]* [*]+ )* / }xo;

    # hf[] entry regex (to extract an hf_index_name and associated field type)
    my $hfArrayFieldTypeRegEx = qr {
                                       \{
                                       \s*
                                       &\s*([A-Z0-9_\[\]-]+)                # &hf
                                       \s*,\s*
                                       \{\s*
                                       .+?                                  # (a bit dangerous)
                                       \s*,\s*
                                       (FT_[A-Z0-9_]+)                      # field type
                                       \s*,\s*
                                       .+?
                                       \s*,\s*
                                       HFILL                                # HFILL
                               }xios;

    # create a copy of $fileContents with comments removed
    my $fileContentsWithoutComments = $$fileContentsRef;
    $fileContentsWithoutComments =~ s {$CCommentRegEx} []xg;

    # find all the hf[] entries (searching $fileContentsWithoutComments).
    # Create a hash keyed by the hf_index_name with the associated value being the field_type
    my %hfArrayEntryFieldType;
    while ($fileContentsWithoutComments =~ m{ $hfArrayFieldTypeRegEx }xgis) {
#        print "$1 $2\n";
        if (exists $hfArrayEntryFieldType{$1}) {
            printf "%-35.35s: ? duplicate hf[] entry: no fixes done for: $1; manual action may be req'd\n", $fileName;
            $hfArrayEntryFieldType{$1} = "???"; # prevent any substitutions for this hf_index_name
        } else {
            $hfArrayEntryFieldType{$1} = $2;
        }
    }

    # RegEx to get "proto" variable name
    my $protoRegEx = qr /
                            ^ \s*                     # note m modifier below
                            (
                                [a-zA-Z0-9_]+
                            )
                            \s*
                            =
                            \s*
                            proto_register_protocol
                            \s*
                            \(
                        /xoms;

    # Find all registered protocols
    while ($fileContentsWithoutComments =~ m { $protoRegEx }xgioms ) {
        ##print "$1\n";
        if (exists $hfArrayEntryFieldType{$1}) {
            printf "%-35.35s: ? duplicate 'proto': no fixes done for: $1; manual action may be req'd\n", $fileName;
            $hfArrayEntryFieldType{$1} = "???"; # prevent any substitutions for this protocol
        } else {
            $hfArrayEntryFieldType{$1} = "REG_PROTO";
        }
    }

    return \%hfArrayEntryFieldType;
}

{  # block begin

# shared variables
    my $fileName;
    my $searchReplaceHRef;
    my $found;
    my $hf_field_type;

# Substitute new values for certain proto_tree_add_item() encoding arg values (for specified hf field types)
#  Variants: search for and display for "exceptions" to allowed encoding arg values;
#            search for and display all encoding arg values
# args:
#   substitute_flag: 1: replace specified encoding arg values by a new value (keys/values in search hash);
#                    2: search for "exceptions" to allowed encoding arg values (values in search hash);
#                    3: search for all encoding arg values
#   ref to array containing two elements:
#      - ref to array containing hf[] types to be processed (FT_STRING, etc)
#      - ref to hash containing search (keys) and replacement (values) for encoding arg
#   ref to hfArrayEntries hash (key: hf name; value: field type)
#   ref to string containing file contents
#   filename

    sub fix_encoding_args {

        (my $subFlag, my $mapArg, my $fileContentsRef, my $hfArrayEntryFieldTypeHRef, $fileName) = @_;

        my $hf_index_name;
        my $hfTypesARef;
        my $encArgPat;

        $hfTypesARef       = $$mapArg[0];
        $searchReplaceHRef = $$mapArg[1];

        my %hfTypes;
        @hfTypes{@$hfTypesARef}=();

        # set up the encoding arg match pattern
        if ($subFlag == 1) {
            # just match for proto_tree_add_item() statements which have an encoding arg matching one of the
            #   keys in the searchReplace hash.
            # Escape any "|" characters in the keys
            #  and then create "alternatives" string containing all the values (A|B|C\|D|...)
            $encArgPat = join "|",  map { s{ ( \| ) }{\\$1}gx; $_ } keys %$searchReplaceHRef;
        } elsif ($subFlag == 2) {
            # Find all the proto_tree_add_item statements wherein the encoding arg is a value other than
            #      one of the "replace" values.
            #  Uses zero-length negative-lookahead to find proto_tree_add_item statements for which the encoding
            #    arg is something other than one of the the provided replace values.
            # Escape any "|" characters in the values to be matched
            #  and then create "alternatives" string containing all the values (A|B|C\|D|...)
            my $match_str = join "|",  map { s{ ( \| ) }{\\$1}gx; $_ } values %$searchReplaceHRef;
            $encArgPat = qr /
                                (?!                  # negative zero-length look-ahead
                                    \s*
                                    (?: $match_str ) # alternatives we don't want to match
                                    \s*
                                )
                                [^,)]+?              # OK: enoding arg is other than one of the alternatives:
                                                     #   match to end of the arg
                            /x;
        } elsif ($subFlag == 3) {
            # match for proto_tree_add_item statements for any value of the encoding parameter
            # IOW: find all the proto_tree_add_item statements with an hf entry of the desired types
            $encArgPat = qr / [^,)]+? /x;
        }

        # For each hf[] entry which matches a type in %hfTypes do replacements
        $found = 0;
        foreach my $key (keys %$hfArrayEntryFieldTypeHRef) {
            $hf_index_name = $key;
            $hf_index_name =~ s{ ( \[ | \] ) }{\\$1}xg;     # escape any "[" or "]" characters
            $hf_field_type = $$hfArrayEntryFieldTypeHRef{$key};
            ##printf "--> %-35.35s: %s\n", $hf_index_name,  $hf_field_type;

            next unless exists $hfTypes{$hf_field_type};    # Do we want to process for this hf[] entry type ?

            # build the complete pattern
            my $patRegEx = qr /
                                  ( # part 1: $1
                                      proto_tree_add_item \s* \(
                                      [^;]+?
                                      ,\s*
                                      $hf_index_name
                                      \s*,
                                      [^;]+
                                      ,\s*
                                  )
                                  ( # part 2: $2
                                      $encArgPat
                                  )
                                  ( # part 3: $3
                                      \s* \)
                                      \s* ;
                                  )
                              /xs;

            ##print "\n$hf_index_name $hf_field_type\n";

            ## Match and substitute as specified
            $$fileContentsRef =~ s/ $patRegEx /patsub($1,$2,$3)/xges;

        }

        return $found;
    }

    # Called from fix_encoding_args to determine replacement string when a regex match is encountered
    #  $_[0]: part 1
    #  $_[1]: part 2: encoding arg
    #  $_[2]: part 3
    #  lookup the desired replacement value for the encoding arg
    #  print match string showing and highlighting the encoding arg replacement
    #  return "replacement" string
    sub patsub {
        $found += 1;
        my $substr = exists $$searchReplaceHRef{$_[1]} ? $$searchReplaceHRef{$_[1]} : "???";
        my $str = sprintf("%s[[%s]-->[%s]]%s", $_[0], $_[1], $substr,  $_[2]);
        $str =~ tr/\t\n\r/ /d;
        printf "%s:  %-17.17s $str\n", $fileName, $hf_field_type . ":";
        return $_[0] . $substr . $_[2];
    }
}  # block end


# Find all proto_tree_add_item() statements
#  and output same highlighting the encoding arg
sub find_all {
    my( $fileContentsRef, $fileName) = @_;

    my $pat = qr /
                     (
                         proto_tree_add_item \s* \(
                         [^;]+
                         , \s*
                     )
                     (
                         [^ \t,)]+?
                     )
                     (
                         \s* \)
                         \s* ;
                     )
                 /xs;

    while ($$fileContentsRef =~ / $pat /xgso) {
        my $str = "${1}[[${2}]]${3}\n";
        $str =~ tr/\t\n\r/ /d;
        $str =~ s/ \s+ / /xg;
        print "$fileName: $str\n";
    }
}

