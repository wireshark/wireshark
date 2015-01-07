#!/usr/bin/env perl
#
# Copyright 2013 Michael Mann (see AUTHORS file)
#
# A program to help convert proto_tree_add_text calls into filterable "items" that
# use proto_tree_add_item.  The program requires 2 passes.  "Pass 1" (generate) collects 
# the eligible proto_tree_add_text calls and outputs the necessary data into a delimited
# file.  "Pass 2" (fix-all) takes the data from the delimited file and replaces the
# proto_tree_add_text calls with proto_tree_add_item or "expert info" calls as well as 
# generating separate files for the hf and/or ei variable declarations and hf and/or ei array data.
# The hf "files" can be copy/pasted into the dissector where appropriate (until such time as 
# its done automatically)
#
# Note that the output from "Pass 1" won't always be a perfect conversion for "Pass 2", so
# "human interaction" is needed as an intermediary to verify and update the delimited file
# before "Pass 2" is done.
# It is also recommended to run checkhf.pl and checkAPIs.pl after "Pass 2" is completed.
#
# Delimited file field format:
# <convert proto_tree_add_text_call[0|1|10-13]><add hf or ei variable[0|1|2]><proto_tree var><hf var><tvb var><offset><length><encoding|[EXPERT_GROUPS]>
# <[FIELDNAME]><[FIELDTYPE]|[EXPERT_SEVERITY]><[FIELDABBREV]><[FIELDDISPLAY]><[FIELDCONVERT]><[BITMASK]>
#
# convert proto_tree_add_text_call enumerations:
# 0  - no conversions
# 1  - proto_tree_add_item
# 10 - expert_add_info
# 11 - expert_add_info_format
# 12 - proto_tree_add_expert
# 13 - proto_tree_add_expert_format
#
# Usage: convert_proto_tree_add_text.pl action=<generate|fix-all> <file or files>
#
# Lots of code shamelessly borrowed from fix-encoding-args.pl (Thanks Bill!)
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

my %DISPLAY_BASE = ('BASE_NONE' => "BASE_NONE",
					   'BASE_DEC' => "BASE_DEC",
					   'BASE_HEX' => "BASE_HEX",
					   'BASE_OCT' => "BASE_OCT",
					   'BASE_DEC_HEX' => "BASE_DEC_HEX",
					   'BASE_HEX_DEC' => "BASE_HEX_DEC",
					   'BASE_EXT_STRING' => "BASE_EXT_STRING",
					   'BASE_RANGE_STRING' => "BASE_RANGE_STRING",
					   'ABSOLUTE_TIME_LOCAL' => "ABSOLUTE_TIME_LOCAL",
					   'ABSOLUTE_TIME_UTC' => "ABSOLUTE_TIME_UTC",
					   'ABSOLUTE_TIME_DOY_UTC' => "ABSOLUTE_TIME_DOY_UTC",
					   'BASE_CUSTOM' => "BASE_CUSTOM");

my %ENCODINGS = ('ENC_BIG_ENDIAN' => "ENC_BIG_ENDIAN",
					   'ENC_LITTLE_ENDIAN' => "ENC_LITTLE_ENDIAN",
					   'ENC_TIME_TIMESPEC' => "ENC_TIME_TIMESPEC",
					   'ENC_TIME_NTP' => "ENC_TIME_NTP",
					   'ENC_ASCII' => "ENC_ASCII",
					   'ENC_UTF_8' => "ENC_UTF_8",
					   'ENC_UTF_16' => "ENC_UTF_16",
					   'ENC_UCS_2' => "ENC_UCS_2",
					   'ENC_EBCDIC' => "ENC_EBCDIC",
					   'ENC_NA' => "ENC_NA");

my %FIELD_TYPE = ('FT_NONE' => "FT_NONE", 'FT_PROTOCOL' => "FT_PROTOCOL", 'FT_BOOLEAN' => "FT_BOOLEAN",
				   'FT_UINT8' => "FT_UINT8", 'FT_UINT16' => "FT_UINT16", 'FT_UINT24' => "FT_UINT24", 'FT_UINT32' => "FT_UINT32", 'FT_UINT64' => "FT_UINT64",
				   'FT_INT8' => "FT_INT8", 'FT_INT16' => "FT_INT16", 'FT_INT24' => "FT_INT24", 'FT_INT32' => "FT_INT32", 'FT_INT64' => "FT_INT64",
				   'FT_FLOAT' => "FT_FLOAT", 'FT_DOUBLE' => "FT_DOUBLE",
				   'FT_ABSOLUTE_TIME' => "FT_ABSOLUTE_TIME", 'FT_RELATIVE_TIME' => "FT_RELATIVE_TIME",
				   'FT_STRING' => "FT_STRING", 'FT_STRINGZ' => "FT_STRINGZ", 'FT_UINT_STRING' => "FT_UINT_STRING",
				   'FT_ETHER' => "FT_ETHER", 'FT_BYTES' => "FT_BYTES", 'FT_UINT_BYTES' => "FT_UINT_BYTES",
				   'FT_IPv4' => "FT_IPv4", 'FT_IPv6' => "FT_IPv6", 'FT_IPXNET' => "FT_IPXNET", 'FT_AX25' => "FT_AX25", 'FT_VINES' => "FT_VINES",
				   'FT_FRAMENUM' => "FT_FRAMENUM", 'FT_PCRE' => "FT_PCRE", 'FT_GUID' => "FT_GUID", 'FT_OID' => "FT_OID", 'FT_REL_OID' => "FT_REL_OID", 'FT_EUI64' => "FT_EUI64");

my %EXPERT_SEVERITY = ('PI_COMMENT' => "PI_COMMENT",
					   'PI_CHAT' => "PI_CHAT",
					   'PI_NOTE' => "PI_NOTE",
					   'PI_WARN' => "PI_WARN",
					   'PI_ERROR' => "PI_ERROR");

my %EXPERT_GROUPS = ('PI_CHECKSUM' => "PI_CHECKSUM",
					   'PI_SEQUENCE' => "PI_SEQUENCE",
					   'PI_RESPONSE_CODE' => "PI_RESPONSE_CODE",
					   'PI_REQUEST_CODE' => "PI_REQUEST_CODE",
					   'PI_UNDECODED' => "PI_UNDECODED",
					   'PI_REASSEMBLE' => "PI_REASSEMBLE",
					   'PI_MALFORMED' => "PI_MALFORMED",
					   'PI_DEBUG' => "PI_DEBUG",
					   'PI_PROTOCOL' => "PI_PROTOCOL",
					   'PI_SECURITY' => "PI_SECURITY",
					   'PI_COMMENTS_GROUP' => "PI_COMMENTS_GROUP");

my @proto_tree_list;
my @expert_list;
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
my $expert  = '';

my $result = GetOptions(
						'action=s' => \$action,
						'encoding=s' => \$encoding,
						'expert'   => \$expert,
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
		print "  --expert     (Optional) Includes proto_tree_add_text calls with no printf arguments in\n";
		print "               the .proto_tree_input file as they could be converted to expert info\n";
		print "               (otherwise they are ignored)\n";
		print "               Must be called for 'fix-all' if called on 'generate'\n";
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
my $line_number = 0;

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
		$line_number = 0;
		my $errors = 0;
		open(FCI, "<", $fileName . ".proto_tree_input") || die("Couldn't open $fileName.proto_tree_input");
		while(my $line=<FCI>){
			my @proto_tree_item = split(/;|\n/, $line);

			$line_number++;
			$errors += verify_line(@proto_tree_item);

			push(@proto_tree_list, \@proto_tree_item);
			if ($proto_tree_item[1] eq "2") {
				push(@expert_list, \@proto_tree_item);
			}
		}
		close(FCI);

		if ($errors > 0) {
			print "Aborting conversion.\n";
			exit(-1);
		}

		fix_proto_tree_add_text(\$fileContents, $fileName);

		# Write out the hf data
		output_hf_array($fileName);
		output_hf($fileName);

		# Write out the changed version to a file
		open(FCO, ">", $fileName . ".proto_tree_add_text");
		print FCO "$fileContents";
		close(FCO);
	}

	if ($action eq "find-all") {
		# Find all proto_tree_add_text() statements eligible for conversion
		$found_total += find_all(\$fileContents, $fileName);
	}

} # while

exit $found_total;

# ---------------------------------------------------------------------
# Sanity check the data in the .proto_tree_input file
sub verify_line {
	my( @proto_tree_item) = @_;
	my $errors = 0;

	#do some basic error checking of the file
	if ($proto_tree_item[0] eq "1") {
		if (!($proto_tree_item[3] =~ /^hf_/)) {
			print "$line_number: Poorly formed hf_ variable ($proto_tree_item[3])!\n";
			$errors++;
		}

		foreach (split(/\|/, $proto_tree_item[7])) {
			if (!exists($ENCODINGS{$_})) {
				print "$line_number: Encoding value '$_' unknown!\n";
				$errors++;
			}
		}
	} elsif (($proto_tree_item[0] eq "10") ||
			 ($proto_tree_item[0] eq "11") ||
			 ($proto_tree_item[0] eq "12") ||
			 ($proto_tree_item[0] eq "13")) {
		#expert info conversions
		if (!($proto_tree_item[3] =~ /^ei_/)) {
			print "$line_number: Poorly formed ei_ variable ($proto_tree_item[3])!\n";
			$errors++;
		}
	} elsif ($proto_tree_item[0] ne "0") {
		print "Bad conversion value!  Aborting conversion.\n";
		$errors++;
	}

	if ($proto_tree_item[1] eq "1") {
		if (!($proto_tree_item[3] =~ /^hf_/)) {
			print "$line_number: Poorly formed hf_ variable ($proto_tree_item[3])!\n";
			$errors++;
		}
		if (!exists($FIELD_TYPE{$proto_tree_item[9]})) {
			print "$line_number: Field type '$proto_tree_item[9]' unknown!\n";
			$errors++;
		}
		foreach (split(/\|/, $proto_tree_item[11])) {
			if ((!exists($DISPLAY_BASE{$_})) &&
				(!($proto_tree_item[11] =~ /\d+/))) {
				print "$line_number: Display base '$proto_tree_item[11]' unknown!\n";
				$errors++;
			}
		}
		if (($proto_tree_item[9] eq "FT_UINT8") ||
			($proto_tree_item[9] eq "FT_UINT16") ||
			($proto_tree_item[9] eq "FT_UINT24") ||
			($proto_tree_item[9] eq "FT_UINT32") ||
			($proto_tree_item[9] eq "FT_UINT64") ||
			($proto_tree_item[9] eq "FT_INT8") ||
			($proto_tree_item[9] eq "FT_INT16") ||
			($proto_tree_item[9] eq "FT_INT24") ||
			($proto_tree_item[9] eq "FT_INT32") ||
			($proto_tree_item[9] eq "FT_INT64")) {
			if ($proto_tree_item[11] eq "BASE_NONE") {
				print "$line_number: Interger type should not be BASE_NONE!\n";
				$errors++;
			}
		}

	} elsif ($proto_tree_item[1] eq "2") {
		if (!($proto_tree_item[3] =~ /^ei_/)) {
			print "$line_number: Poorly formed ei_ variable ($proto_tree_item[3])!\n";
			$errors++;
		}
		if (!exists($EXPERT_SEVERITY{$proto_tree_item[9]})) {
			print "$line_number: Expert severity value '$proto_tree_item[9]' unknown!\n";
			$errors++;
		}
		if (!exists($EXPERT_GROUPS{$proto_tree_item[7]})) {
			print "$line_number: Expert group value '$proto_tree_item[7]' unknown!\n";
			$errors++;
		}

	} elsif ($proto_tree_item[1] ne "0") {
			print "$line_number: Bad hf/ei variable generation value!\n";
			$errors++;
	}

	return $errors;
}

sub generate_hfs {
	my( $fileContentsRef, $fileName) = @_;
	my @args;
	my $num_items = 0;
	my @temp;
	my $str_temp;
	my $pat;

	if ($expert ne "") {
		$pat = qr /
					(
						 (?:proto_tree_add_text)\s* \(
						 (([^[\,;])*\,){4,}
						 [^;]*
						 \s* \) \s* ;
					)
				/xs;
	} else {
		$pat = qr /
					(
						 (?:proto_tree_add_text)\s* \(
						 (([^[\,;])*\,){5,}
						 [^;]*
						 \s* \) \s* ;
					)
				/xs;
	}

	while ($$fileContentsRef =~ / $pat /xgso) {
		my @proto_tree_item = (1, 1, "tree", "hf_name", "tvb", "offset", "length", "encoding",
							   "fieldfullname", "fieldtype", "fieldabbrevname", "BASE_NONE", "NULL", "0x0");
		my $str = "${1}\n";
		$str =~ tr/\t\n\r/ /d;
		$str =~ s/ \s+ / /xg;
		#print "$fileName: $str\n";

		@args = split(/,/, $str);
		#printf "ARGS(%d): %s\n", scalar @args, join("# ", @args);
		$args[0] =~ s/proto_tree_add_text\s*\(\s*//;
		$proto_tree_item[2] = $args[0];			#tree
		$proto_tree_item[4] = trim($args[1]);	#tvb
		$proto_tree_item[5] = trim($args[2]);	#offset
		$proto_tree_item[6] = trim($args[3]);	#length
		if (scalar @args == 5) {
			#remove the "); at the end
			$args[4] =~ s/\"\s*\)\s*;$//;
		}

		#encoding
		if (scalar @args > 5) {
			if (($proto_tree_item[6] eq "1") ||
				($args[5] =~ /tvb_get_guint8/) ||
				($args[5] =~ /tvb_bytes_to_str/) ||
				($args[5] =~ /tvb_ether_to_str/))  {
				$proto_tree_item[7] = "ENC_NA";
			} elsif ($args[5] =~ /tvb_get_ntoh/) {
				$proto_tree_item[7] = "ENC_BIG_ENDIAN";
			} elsif ($args[5] =~ /tvb_get_letoh/) {
				$proto_tree_item[7] = "ENC_LITTLE_ENDIAN";
			} elsif (($args[5] =~ /tvb_get_ephemeral_string/) || 
					 ($args[5] =~ /tvb_format_text/)){
				$proto_tree_item[7] = "ENC_NA|ENC_ASCII";
			} elsif ($encoding ne "") {
				$proto_tree_item[7] = $encoding;
			}
		}

		#field full name
		if (($expert ne "") || (scalar @args > 5)) {
			my @arg_temp = split(/=|:/, $args[4]);
			$proto_tree_item[8] = $arg_temp[0];
		} else {
			$proto_tree_item[8] = $args[4];
		}
		$proto_tree_item[8] =~ s/\"//;
		$proto_tree_item[8] = trim($proto_tree_item[8]);

		if ($proto_tree_item[8] eq "%s\"") {
			#assume proto_tree_add_text will not be converted
			$proto_tree_item[0] = 0;
			$proto_tree_item[1] = 0;
			$proto_tree_item[3] = sprintf("hf_%s_", $protabbrev);
			$proto_tree_item[10] = sprintf("%s.", $protabbrev);
		} else {
			#hf variable name
			$proto_tree_item[3] = sprintf("hf_%s_%s", $protabbrev, lc($proto_tree_item[8]));
			$proto_tree_item[3] =~ s/\s+|-|:/_/g;

			#field abbreviated name
			$proto_tree_item[10] = sprintf("%s.%s", $protabbrev, lc($proto_tree_item[8]));
			$proto_tree_item[10] =~ s/\s+|-|:/_/g;
		}

		#VALS
		if ($str =~ /val_to_str(_const)?\(\s*tvb_get_[^\(]*\([^\,]*,[^\)]*\)\s*\,\s*([^\,]*)\s*\,\s*([^\)]*)\)/) {
			$proto_tree_item[12] = sprintf("VALS(%s)", trim($2));
		} elsif ($str =~ /val_to_str(_const)?\([^\,]*\,([^\,]*)\,/) {
			$proto_tree_item[12] = sprintf("VALS(%s)", trim($2));
		} elsif ($str =~ /val_to_str_ext(_const)?\(\s*tvb_get_[^\(]*\([^\,]*,[^\)]*\)\s*\,\s*([^\,]*)\s*\,\s*([^\)]*)\)/) {
			$proto_tree_item[12] = trim($2);
		} elsif ($str =~ /val_to_str_ext(_const)?\([^\,]*\,([^\,]*)\,/) {
			$proto_tree_item[12] = trim($2);
		}

		#field type
		if (scalar @args > 5) {
			if ($args[5] =~ /tvb_get_guint8/) {
				if ($args[4] =~ /%[0-9]*[i]/) {
					$proto_tree_item[9] = "FT_INT8";
				} else {
					$proto_tree_item[9] = "FT_UINT8";
				}
			} elsif ($args[5] =~ /tvb_get_(n|"le")tohs/) {
				if ($args[4] =~ /%[0-9]*[i]/) {
					$proto_tree_item[9] = "FT_INT16";
				} else {
					$proto_tree_item[9] = "FT_UINT16";
				}
			} elsif ($args[5] =~ /tvb_get_(n|"le")toh24/) {
				if ($args[4] =~ /%[0-9]*[i]/) {
					$proto_tree_item[9] = "FT_INT24";
				} else {
					$proto_tree_item[9] = "FT_UINT24";
				}
			} elsif ($args[5] =~ /tvb_get_(n|"le")tohl/) {
				if ($args[4] =~ /%[0-9]*[i]/) {
					$proto_tree_item[9] = "FT_INT32";
				} else {
					$proto_tree_item[9] = "FT_UINT32";
				}
			} elsif ($args[5] =~ /tvb_get_(n|"le")toh("40"|"48"|"56"|"64")/) {
				if ($args[4] =~ /%[0-9]*[i]/) {
					$proto_tree_item[9] = "FT_INT64";
				} else {
					$proto_tree_item[9] = "FT_UINT64";
				}
			} elsif (($args[5] =~ /tvb_get_(n|"le")tohieee_float/) ||
					 ($args[4] =~ /%[0-9\.]*[fFeEgG]/)) {
				$proto_tree_item[9] = "FT_FLOAT";
			} elsif ($args[5] =~ /tvb_get_(n|"le")tohieee_double/) {
				$proto_tree_item[9] = "FT_DOUBLE";
			} elsif (($args[5] =~ /tvb_get_ipv4/) ||
					 ($args[5] =~ /tvb_ip_to_str/)) {
				$proto_tree_item[9] = "FT_IPv4";
			} elsif (($args[5] =~ /tvb_get_ipv6/) ||
					 ($args[5] =~ /tvb_ip6_to_str/)) {
				$proto_tree_item[9] = "FT_IPv6";
			} elsif ($args[5] =~ /tvb_get_(n|"le")tohguid/) {
				$proto_tree_item[9] = "FT_GUID";
			} elsif ($args[5] =~ /tvb_get_ephemeral_stringz/) {
				$proto_tree_item[9] = "FT_STRINGZ";
			} elsif (($args[5] =~ /tvb_get_ephemeral_string/) || 
					 ($args[5] =~ /tvb_format_text/)){
				$proto_tree_item[9] = "FT_STRING";
			} elsif (($args[5] =~ /tvb_bytes_to_str/)) {
				$proto_tree_item[9] = "FT_BYTES";
			} elsif ($args[5] =~ /tvb_ether_to_str/) {
				$proto_tree_item[9] = "FT_ETHER";
			}

			#if we still can't determine type, assume a constant length
			#value means we have an unsigned value
			if ($proto_tree_item[9] eq "fieldtype") {
				my $len_str = trim($args[3]);
				if ($len_str eq "1") {
					$proto_tree_item[9] = "FT_UINT8";
				} elsif ($len_str eq "2") {
					$proto_tree_item[9] = "FT_UINT16";
				} elsif ($len_str eq "3") {
					$proto_tree_item[9] = "FT_UINT24";
				} elsif ($len_str eq "4") {
					$proto_tree_item[9] = "FT_UINT32";
				} elsif ($len_str eq "8") {
					$proto_tree_item[9] = "FT_UINT64";
				}
			}
		}

		#display base
		if ($args[4] =~ /%[0-9]*[xX]/) {
			$proto_tree_item[11] = "BASE_HEX";
		} elsif ($args[4] =~ /%[0-9]*[uld]/) {
			$proto_tree_item[11] = "BASE_DEC";
		} elsif ($args[4] =~ /%[0-9]*o/) {
			$proto_tree_item[11] = "BASE_OCT";
		}
		if ($str =~ /val_to_str_ext(_const)?\([^\,]*\,([^\,]*)\,/) {
			$proto_tree_item[11] .= "|BASE_EXT_STRING";
		}

		if (($proto_tree_item[7] eq "encoding") && ($proto_tree_item[9] eq "FT_BYTES")) {
			$proto_tree_item[7] = "ENC_NA";
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
	my $pat;

	if ($expert ne "") {
		$pat = qr /
					(
						 (?:proto_tree_add_text)\s* \(
						 (([^[\,;])*\,){4,}
						 [^;]*
						 \s* \) \s* ;
					)
				/xs;
	} else {
		$pat = qr /
					(
						 (?:proto_tree_add_text)\s* \(
						 (([^[\,;])*\,){5,}
						 [^;]*
						 \s* \) \s* ;
					)
				/xs;
	}

	$$fileContentsRef =~ s/ $pat /patsub($found, $1)/xges;
}

# ---------------------------------------------------------------------
# Format proto_tree_add_item or expert info functions with proto_tree_list data
sub patsub {
	my $item_str;
	if ($proto_tree_list[$_[0]][0] eq "1") {
		$item_str = sprintf("proto_tree_add_item(%s, %s, %s, %s, %s, %s);",
						 $proto_tree_list[$_[0]][2], $proto_tree_list[$_[0]][3],
						 $proto_tree_list[$_[0]][4], $proto_tree_list[$_[0]][5],
						 $proto_tree_list[$_[0]][6], $proto_tree_list[$_[0]][7]);
	} elsif ($proto_tree_list[$_[0]][0] eq "10") {
		$item_str = sprintf("expert_add_info(pinfo, %s, &%s);",
						 $proto_tree_list[$_[0]][2], $proto_tree_list[$_[0]][3]);
	} elsif ($proto_tree_list[$_[0]][0] eq "11") {
		$item_str = sprintf("expert_add_info_format(pinfo, %s, &%s, \"%s\"",
						 $proto_tree_list[$_[0]][2], $proto_tree_list[$_[0]][3],
						 $proto_tree_list[$_[0]][8]);
		if ($proto_tree_list[$_[0]][11] ne "") {
			$item_str .= ", $proto_tree_list[$_[0]][11]";
		}
		$item_str .= ");";
	} elsif ($proto_tree_list[$_[0]][0] eq "12") {
		$item_str = sprintf("proto_tree_add_expert(%s, pinfo, &%s, %s, %s, %s);",
						 $proto_tree_list[$_[0]][2], $proto_tree_list[$_[0]][3],
						 $proto_tree_list[$_[0]][4], $proto_tree_list[$_[0]][5],
						 $proto_tree_list[$_[0]][6]);
	} elsif ($proto_tree_list[$_[0]][0] eq "13") {
		$item_str = sprintf("proto_tree_add_expert_format(%s, pinfo, &%s, %s, %s, %s, \"%s\"",
						 $proto_tree_list[$_[0]][2], $proto_tree_list[$_[0]][3],
						 $proto_tree_list[$_[0]][4], $proto_tree_list[$_[0]][5],
						 $proto_tree_list[$_[0]][6], $proto_tree_list[$_[0]][8]);
		if ($proto_tree_list[$_[0]][11] ne "") {
			$item_str .= ", $proto_tree_list[$_[0]][11]";
		}
		$item_str .= ");";
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
	my %eis = ();
	my $index;
	my $key;

	open(FCO, ">", $fileName . ".hf");

	print FCO "/* Generated from convert_proto_tree_add_text.pl */\n";

	#add hfs to hash table to prevent against (accidental) duplicates
	for ($index=0;$index<@proto_tree_list;$index++) {
		if ($proto_tree_list[$index][1] eq "1") {
			$hfs{$proto_tree_list[$index][3]} = $proto_tree_list[$index][3];
			print FCO "static int $proto_tree_list[$index][3] = -1;\n";
		} elsif ($proto_tree_list[$index][1] eq "2") {
			$eis{$proto_tree_list[$index][3]} = $proto_tree_list[$index][3];
		}
	}

	if (scalar keys %hfs > 0) {
		print FCO "\n\n";
	}

	print FCO "/* Generated from convert_proto_tree_add_text.pl */\n";

	foreach $key (keys %eis) {
		print FCO "static expert_field $key = EI_INIT;\n";
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
	my %hfs = ();
	my %eis = ();

	open(FCO, ">", $fileName . ".hf_array");

	print FCO "      /* Generated from convert_proto_tree_add_text.pl */\n";

	for ($index=0;$index<@proto_tree_list;$index++) {
		if ($proto_tree_list[$index][1] eq "1") {
			if (exists($hfs{$proto_tree_list[$index][3]})) {
				print "duplicate hf entry '$proto_tree_list[$index][3]' found!  Aborting conversion.\n";
				exit(-1);
			}
			$hfs{$proto_tree_list[$index][3]} = $proto_tree_list[$index][3];
			print FCO "      { &$proto_tree_list[$index][3], { \"$proto_tree_list[$index][8]\", \"$proto_tree_list[$index][10]\", ";
			print FCO "$proto_tree_list[$index][9], $proto_tree_list[$index][11], $proto_tree_list[$index][12], $proto_tree_list[$index][13], NULL, HFILL }},\r\n";
		}
	}

	if ($index > 0) {
		print FCO "\n\n";
	}

	print FCO "      /* Generated from convert_proto_tree_add_text.pl */\n";
	for ($index=0;$index<@expert_list;$index++) {
		if (exists($eis{$expert_list[$index][3]})) {
			print "duplicate ei entry '$expert_list[$index][3]' found!  Aborting conversion.\n";
			exit(-1);
		}
		$eis{$expert_list[$index][3]} = $expert_list[$index][3];

		print FCO "      { &$expert_list[$index][3], { \"$expert_list[$index][10]\", $expert_list[$index][7], ";
		print FCO "$expert_list[$index][9], \"$expert_list[$index][8]\", EXPFILL }},\r\n";
	}

	close(FCO);
}

# ---------------------------------------------------------------------
# Find all proto_tree_add_text calls that have parameters passed in them
# and output number found

sub find_all {
	my( $fileContentsRef, $fileName) = @_;

	my $found = 0;
	my $tvb_found = 0;
	my $pat;
	my $tvb_percent;

	if ($expert ne "") {
		$pat = qr /
					(
						 (?:proto_tree_add_text)\s* \(
						 (([^[\,;])*\,){4,}
						 [^;]*
						 \s* \) \s* ;
					)
				/xs;
	} else {
		$pat = qr /
					(
						 (?:proto_tree_add_text)\s* \(
						 (([^[\,;])*\,){5,}
						 [^;]*
						 \s* \) \s* ;
					)
				/xs;
	}

	while ($$fileContentsRef =~ / $pat /xgso) {
		my $str = "${1}\n";
		my @args = split(/,/, ${1});

		#cleanup whitespace to show proto_tree_add_text in single line (easier for seeing grep results)
		$str =~ tr/\t\n\r/ /d;
		$str =~ s/ \s+ / /xg;
		#print "$fileName: $str\n";

		#find all instances where proto_tree_add_text has a tvb_get (or similar) call, because
		#convert_proto_tree_add_text.pl has an easier time determining hf_ field values with it
		if (scalar @args > 5) {
			my $tvb = trim($args[5]);
			if ($tvb =~ /^tvb_/) {
				$tvb_found += 1;
			}
		}

		$found += 1;
	}

	if ($found > 0) {
		if ($tvb_found > 0) {
			$tvb_percent = 100*$tvb_found/$found;

			printf "%s: Found %d proto_tree_add_text calls eligible for conversion, %d contain a \"tvb get\" call (%.2f%%).\n",
				$fileName, $found, $tvb_found, $tvb_percent;
		} else {
			print "$fileName: Found $found proto_tree_add_text calls eligible for conversion, 0 \"tvb get\" calls.\n";
		}
	}
	return $found;
}
