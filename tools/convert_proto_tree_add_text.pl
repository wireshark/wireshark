#!/usr/bin/env perl
#
# Copyright 2013 Michael Mann (see AUTHORS file)
#
# A program to help convert proto_tree_add_text calls into filterable "items" that
# use proto_tree_add_item.  The program requires 2 passes.  "Pass 1" (generate) collects 
# the eligible proto_tree_add_text calls and outputs the necessary data into a delimited
# file.  "Pass 2" (fix-all) takes the data from the delimited file and replaces the
# proto_tree_add_text calls with proto_tree_add_item as well as generating separate files
# for the hf variable declarations and hf array data.  The hf "files" can be copy/pasted
# into the dissector where appropriate (until such time as its done automatically)
#
# Note that the output from "Pass 1" won't always be a perfect conversion for "Pass 2", so
# "human interaction" is needed as an intermediary to verify and update the delimited file
# before "Pass 2" is done.
# It is also recommended to run checkhf.pl and checkAPIs.pl after "Pass 2" is completed.
#
# Delimited file field format:
# <convert proto_tree_add_text_call><add hf variable><proto_tree var><hf var><tvb var><offset><length><encoding>
# <[FIELDNAME]><[FIELDTYPE]><[FIELDABBREV]><[FIELDDISPLAY]><[FIELDCONVERT]><[BITMASK]>
#
# Usage: convert_proto_tree_add_text.pl action=<generate|fix-all> <file or files>
#
# Lots of code shamelessly borrowed from fix-encoding-args.pl (Thanks Bill!)
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

use strict;
use warnings;

use Getopt::Long;

my @proto_tree_list;
my $protabbrev = "";

# Perl trim function to remove whitespace from the start and end of the string
sub trim($)
{
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

# ---------------------------------------------------------------------
#
# MAIN
#
my $helpFlag  = '';
my $action    = 'generate';
my $encoding  = '';

my $result = GetOptions(
						'action=s' => \$action,
						'encoding=s' => \$encoding,
						'help|?'   => \$helpFlag
						);

if (!$result || $helpFlag || !$ARGV[0]) {
	usage();
}

sub usage {
	print "\nUsage: $0 [--action=generate|fix-all|find-all] [--encoding=ENC_BIG_ENDIAN|ENC_LITTLE_ENDIAN] FILENAME [...]\n\n";
		print "  --action = generate (default)\n";
		print "    generate - create a delimited file (FILENAME.proto_tree_input) with\n";
		print "               proto_tree_add_text fields in FILENAME(s)\n";
		print "    fix-all  - Use delimited file (FILENAME.proto_tree_input) to convert\n";
		print "               proto_tree_add_text to proto_tree_add_item\n";
		print "               Also generates FILENAME.hf and FILENAME.hf_array to be\n";
		print "               copy/pasted into the dissector where appropriate\n";
		print "    find-all - Output the number of eligible proto_tree_add_text calls\n";
		print "               for conversion\n\n";
		print "  --encoding   (Optional) Default encoding if one can't be determined\n";
		print "               (effective only for generate)\n";
		print "               If not specified, an encoding will not be auto-populated\n";
		print "               if undetermined\n\n";

	exit(1);
}

#
# XXX Outline general algorithm here
#
my $found_total = 0;
my $protabbrev_index;

while (my $fileName = $ARGV[0]) {
	shift;
	my $fileContents = '';

	die "No such file: \"$fileName\"\n" if (! -e $fileName);

	# delete leading './'
	$fileName =~ s{ ^ \. / } {}xo;

	#determine PROTABBREV for dissector based on file name format of (dirs)/packet-PROTABBREV.c
	$protabbrev_index = rindex($fileName, "packet-");
	if ($protabbrev_index == -1) {
		print "$fileName doesn't fit format of packet-PROTABBREV.c\n";
		next;
	}

	$protabbrev = substr($fileName, $protabbrev_index+length("packet-"));
	$protabbrev_index = rindex($protabbrev, ".");
	if ($protabbrev_index == -1) {
		print "$fileName doesn't fit format of packet-PROTABBREV.c\n";
		next;
	}
	$protabbrev = lc(substr($protabbrev, 0, $protabbrev_index));

	# Read in the file (ouch, but it's easier that way)
	open(FCI, "<", $fileName) || die("Couldn't open $fileName");
	while (<FCI>) {
		$fileContents .= $_;
	}
	close(FCI);

	if ($action eq "generate") {
		generate_hfs(\$fileContents, $fileName);
	}

	if ($action eq "fix-all") {
		# Read in the hf "input" file
		open(FCI, "<", $fileName . ".proto_tree_input") || die("Couldn't open $fileName.proto_tree_input");
		while(my $line=<FCI>){
			my @proto_tree_item = split(/;|\n/, $line);
			push(@proto_tree_list, \@proto_tree_item);
		}
		close(FCI);

		fix_proto_tree_add_text(\$fileContents, $fileName);

		# Write out the changed version to a file
		open(FCO, ">", $fileName . ".proto_tree_add_text");
		print FCO "$fileContents";
		close(FCO);

		output_hf($fileName);
		output_hf_array($fileName);
	}

	if ($action eq "find-all") {
		# Find all proto_tree_add_text() statements eligible for conversion
		$found_total += find_all(\$fileContents, $fileName);
		print "Found $found_total proto_tree_add_text calls eligible for conversion.\n";
	}

} # while

exit $found_total;


sub generate_hfs {
	my( $fileContentsRef, $fileName) = @_;
	my @args;
	my $num_items = 0;
	my @temp;
	my $str_temp;

	my $pat = qr /
					(
						 (?:proto_tree_add_text)\s* \(
						 (([^[\,;])*\,){5}
						 [^;]*
						 \s* \) \s* ;
					)
				/xs;

	while ($$fileContentsRef =~ / $pat /xgso) {
		my @proto_tree_item = (1, 1, "tree", "hf_name", "tvb", "offset", "length", "encoding",
							   "fieldname", "fieldtype", "filtername", "BASE_NONE", "NULL", "0x0");
		my $str = "${1}\n";
		$str =~ tr/\t\n\r/ /d;
		$str =~ s/ \s+ / /xg;
		#print "$fileName: $str\n";

		@args = split(/,/, $str);
		#printf "ARGS: %s\n", join("# ", @args);
		$args[0] =~ s/proto_tree_add_text\s*\(\s*//;
		$proto_tree_item[2] = $args[0];			#tree
		$proto_tree_item[4] = trim($args[1]);	#tvb
		$proto_tree_item[5] = trim($args[2]);	#offset
		$proto_tree_item[6] = trim($args[3]);	#length

		#encoding
		if (($proto_tree_item[6] eq "1") ||
			($args[5] =~ /tvb_get_guint8/))  {
			$proto_tree_item[7] = "ENC_NA";
		} elsif ($args[5] =~ /tvb_get_ntoh/) {
			$proto_tree_item[7] = "ENC_BIG_ENDIAN";
		} elsif ($args[5] =~ /tvb_get_letoh/) {
			$proto_tree_item[7] = "ENC_LITTLE_ENDIAN";
		} elsif ($args[5] =~ /tvb_get_ephemeral_string/) {
			$proto_tree_item[7] = "ENC_NA|ENC_ASCII";
		} elsif ($encoding ne "") {
			$proto_tree_item[7] = $encoding;
		}

		#Field name
		my @arg_temp = split(/=|:/, $args[4]);
		$proto_tree_item[8] = $arg_temp[0];
		$proto_tree_item[8] =~ s/\"//;
		$proto_tree_item[8] = trim($proto_tree_item[8]);

		#hf name
		$proto_tree_item[3] = sprintf("hf_%s_%s", $protabbrev, lc($proto_tree_item[8]));
		$proto_tree_item[3] =~ s/\s+/_/g;

		#filter name
		$proto_tree_item[10] = sprintf("%s.%s", $protabbrev, lc($proto_tree_item[8]));
		$proto_tree_item[10] =~ s/\s+/_/g;

		#VALS
		if ($str =~ /val_to_str(_const)?\([^\,]*\,([^\,]*)\,/) {
			$proto_tree_item[12] = sprintf("VALS(%s)", trim($2));
		}

		#field type
		if ($args[5] =~ /tvb_get_guint8/) {
			if ($args[4] =~ /%[0-9]*[di]/) {
				$proto_tree_item[9] = "FT_INT8";
			} else {
				$proto_tree_item[9] = "FT_UINT8";
			}
		} elsif ($args[5] =~ /tvb_get_(n|"le")tohs/) {
			if ($args[4] =~ /%[0-9]*[di]/) {
				$proto_tree_item[9] = "FT_INT16";
			} else {
				$proto_tree_item[9] = "FT_UINT16";
			}
		} elsif ($args[5] =~ /tvb_get_(n|"le")toh24/) {
			if ($args[4] =~ /%[0-9]*[di]/) {
				$proto_tree_item[9] = "FT_INT24";
			} else {
				$proto_tree_item[9] = "FT_UINT24";
			}
		} elsif ($args[5] =~ /tvb_get_(n|"le")tohl/) {
			if ($args[4] =~ /%[0-9]*[di]/) {
				$proto_tree_item[9] = "FT_INT32";
			} else {
				$proto_tree_item[9] = "FT_UINT32";
			}
		} elsif ($args[5] =~ /tvb_get_(n|"le")toh("40"|"48"|"56"|"64")/) {
			if ($args[4] =~ /%[0-9]*[di]/) {
				$proto_tree_item[9] = "FT_INT64";
			} else {
				$proto_tree_item[9] = "FT_UINT64";
			}
		} elsif (($args[5] =~ /tvb_get_(n|"le")tohieee_float/) ||
				 ($args[4] =~ /%[0-9\.]*[fFeEgG]/)) {
			$proto_tree_item[9] = "FT_FLOAT";
		} elsif ($args[5] =~ /tvb_get_(n|"le")tohieee_double/) {
			$proto_tree_item[9] = "FT_DOUBLE";
		} elsif ($args[5] =~ /tvb_get_ipv4/) {
			$proto_tree_item[9] = "FT_IPv4";
		} elsif ($args[5] =~ /tvb_get_ipv6/) {
			$proto_tree_item[9] = "FT_IPv6";
		} elsif ($args[5] =~ /tvb_get_(n|"le")tohguid/) {
			$proto_tree_item[9] = "FT_GUID";
		} elsif ($args[5] =~ /tvb_get_ephemeral_stringz/) {
			$proto_tree_item[9] = "FT_STRINGZ";
		} elsif ($args[5] =~ /tvb_get_ephemeral_string/) {
			$proto_tree_item[9] = "FT_STRING";
		} 


		#display base
		if ($args[4] =~ /%[0-9]*[xX]/) {
			$proto_tree_item[11] = "BASE_HEX";
		} elsif ($args[4] =~ /%[0-9]*[uld]/) {
			$proto_tree_item[11] = "BASE_DEC";
		} elsif ($args[4] =~ /%[0-9]*o/) {
			$proto_tree_item[11] = "BASE_OCT";
		}

		push(@proto_tree_list, \@proto_tree_item);

		$num_items += 1;
	}

	if ($num_items > 0) {
		open(FCO, ">", $fileName . ".proto_tree_input");
		for my $item (@proto_tree_list) {
			print FCO join(";", @{$item}), "\n";
		}
		close(FCO);
	}
}

# ---------------------------------------------------------------------
# Find all proto_tree_add_text calls and replace them with the data
# found in proto_tree_list
sub fix_proto_tree_add_text {
	my( $fileContentsRef, $fileName) = @_;
	my $found = 0;
	my $pat = qr /
					(
						 (?:proto_tree_add_text)\s* \(
						 (([^[\,;])*\,){5}
						 [^;]*
						 \s* \) \s* ;
					)
				/xs;

	$$fileContentsRef =~ s/ $pat /patsub($found, $1)/xges;
}

# ---------------------------------------------------------------------
# Format proto_tree_add_item function with proto_tree_list data
sub patsub {
	my $item_str;
	if ($proto_tree_list[$_[0]][0] ne "0") {
		$item_str = sprintf("proto_tree_add_item(%s, %s, %s, %s, %s, %s);",
						 $proto_tree_list[$_[0]][2], $proto_tree_list[$_[0]][3],
						 $proto_tree_list[$_[0]][4], $proto_tree_list[$_[0]][5],
						 $proto_tree_list[$_[0]][6], $proto_tree_list[$_[0]][7]);
	} else {
		$item_str = $1;
	}

	$_[0] += 1;

	return $item_str;
}

# ---------------------------------------------------------------------
# Output the hf variable declarations.  For now, write them to a file.
# XXX - Eventually find the right place to add it to the modified dissector file
sub output_hf {
	my( $fileName) = @_;
	my %hfs = ();
	my $index;
	my $key;

	#add hfs to hash table to prevent against (accidental) duplicates
	for ($index=0;$index<@proto_tree_list;$index++) {
		if ($proto_tree_list[$index][1] ne "0") {
			$hfs{$proto_tree_list[$index][3]} = $proto_tree_list[$index][3];
		}
	}

	open(FCO, ">", $fileName . ".hf");

	print FCO "/* Generated from convert_proto_tree_add_text.pl */\n";

	foreach $key (keys %hfs) {
		print FCO "static int $key = -1;\n";
	}
	close(FCO);

}

# ---------------------------------------------------------------------
# Output the hf array items.  For now, write them to a file.
# XXX - Eventually find the right place to add it to the modified dissector file
# (bonus points if formatting of hf array in dissector file is kept)
sub output_hf_array {
	my( $fileName) = @_;
	my $index;

	open(FCO, ">", $fileName . ".hf_array");

	print FCO "      /* Generated from convert_proto_tree_add_text.pl */\n";

	for ($index=0;$index<@proto_tree_list;$index++) {
		if ($proto_tree_list[$index][1] ne "0") {
			print FCO "      { &$proto_tree_list[$index][3], { \"$proto_tree_list[$index][8]\", \"$proto_tree_list[$index][10]\", ";
			print FCO "$proto_tree_list[$index][9], $proto_tree_list[$index][11], $proto_tree_list[$index][12], $proto_tree_list[$index][13], NULL, HFILL }},\n";
		}
	}

	close(FCO);
}

# ---------------------------------------------------------------------
# Find all proto_tree_add_text calls that have parameters passed in them
# and output number found

sub find_all {
	my( $fileContentsRef, $fileName) = @_;

	my $found = 0;

	my $pat = qr /
					(
						 (?:proto_tree_add_text)\s* \(
						 (([^[\,;])*\,){5}
						 [^;]*
						 \s* \) \s* ;
					)
				/xs;

	while ($$fileContentsRef =~ / $pat /xgso) {
		my $str = "${1}\n";
		$str =~ tr/\t\n\r/ /d;
		$str =~ s/ \s+ / /xg;
		#print "$fileName: $str\n";

		$found += 1;
	}

	return $found;
}
