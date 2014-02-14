#!/usr/bin/env perl
#
# Copyright 2013 Michael Mann (see AUTHORS file)
#
# A program to help convert the "old" expert_add_info_format API calls into filterable "items" that
# use the other expert API calls.  The program requires 2 passes.  "Pass 1" (generate) collects 
# the eligible expert_add_info_format calls and outputs the necessary data into a delimited
# file.  "Pass 2" (fix-all) takes the data from the delimited file and replaces the
# expert_add_info_format calls with filterable "expert info" calls as well as 
# generating a separate files for the  ei variable declarations and array data.
# The ei "file" can be copy/pasted into the dissector where appropriate
#
# Note that the output from "Pass 1" won't always be a perfect conversion for "Pass 2", so
# "human interaction" is needed as an intermediary to verify and update the delimited file
# before "Pass 2" is done.
#
# Delimited file field format:
# <convert expert_add_info_format_call[1-4]><add ei variable[0|1]><ei var><[GROUP]><[SEVERITY]><[FIELDNAME]><[EXPERTABBREV]>
# <pinfo var><proto_item var><tvb var><offset><length><params>
#
# convert proto_tree_add_text_call enumerations:
# 1  - expert_add_info
# 2  - expert_add_info_format
# 3  - proto_tree_add_expert
# 4  - proto_tree_add_expert_format
#
# Usage: convert_expert_add_info_format.pl action=<generate|fix-all> <file or files>
#
# Based off of convert_proto_tree_add_text.pl
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
my $register  = '';

my $result = GetOptions(
						'action=s' => \$action,
						'register' => \$register,
						'help|?'   => \$helpFlag
						);

if (!$result || $helpFlag || !$ARGV[0]) {
	usage();
}

sub usage {
	print "\nUsage: $0 [--action=generate|fix-all|find-all] FILENAME [...]\n\n";
		print "  --action = generate (default)\n";
		print "    generate - create a delimited file (FILENAME.expert_add_info_input) with\n";
		print "               expert_add_info_format fields in FILENAME(s)\n";
		print "    fix-all  - Use delimited file (FILENAME.expert_add_info_input) to convert\n";
		print "               expert_add_info_format to \"filterable\" expert API\n";
		print "               Also generates FILENAME.ei to be copy/pasted into\n";
		print "               the dissector where appropriate\n\n";
		print "  --register = generate ei_register_info and expert register function calls\n\n";

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
		generate_eis(\$fileContents, $fileName);
	}

	if ($action eq "fix-all") {
		# Read in the ei "input" file
		$line_number = 0;
		my $errors = 0;
		open(FCI, "<", $fileName . ".expert_add_info_input") || die("Couldn't open $fileName.expert_add_info_input");
		while(my $line=<FCI>){
			my @expert_item = split(/;|\n/, $line);

			$line_number++;
			$errors += verify_line(@expert_item);

			push(@expert_list, \@expert_item);
		}
		close(FCI);

		if ($errors > 0) {
			print "Aborting conversion.\n";
			exit(-1);
		}

		fix_expert_add_info_format(\$fileContents, $fileName);

		# Write out the ei data
		output_ei_data($fileName);

		# Write out the changed version to a file
		open(FCO, ">", $fileName . ".expert_add_info_format");
		print FCO "$fileContents";
		close(FCO);
	}

} # while

exit $found_total;

# ---------------------------------------------------------------------
# Sanity check the data in the .proto_tree_input file
sub verify_line {
	my( @expert_item) = @_;
	my $errors = 0;

	#do some basic error checking of the file
	if (($expert_item[0] eq "1") ||
		($expert_item[0] eq "2") ||
		($expert_item[0] eq "3") ||
		($expert_item[0] eq "4")) {
		#expert info conversions
		if (!($expert_item[2] =~ /^ei_/)) {
			print "$line_number: Poorly formed ei_ variable ($expert_item[2])!\n";
			$errors++;
		}
	} else {
		print "$line_number: Bad conversion value!\n";
		$errors++;
	}

	if ($expert_item[1] eq "1") {
		if (!($expert_item[2] =~ /^ei_/)) {
			print "$line_number: Poorly formed ei_ variable ($expert_item[2])!\n";
			$errors++;
		}
		if (!exists($EXPERT_SEVERITY{$expert_item[4]})) {
			print "$line_number: Expert severity value '$expert_item[5]' unknown!\n";
			$errors++;
		}
		if (!exists($EXPERT_GROUPS{$expert_item[3]})) {
			print "$line_number: Expert group value '$expert_item[4]' unknown!\n";
			$errors++;
		}

	} elsif ($expert_item[1] ne "0") {
			print "$line_number: Bad ei variable generation value!\n";
			$errors++;
	}

	return $errors;
}

sub generate_eis {
	my( $fileContentsRef, $fileName) = @_;
	my @args;
	my $num_items = 0;
	my @temp;
	my $str_temp;
	my $pat;

	$pat = qr /
				(
					(?:expert_add_info_format)\s* \(
					(([^[\,;])*\,){4,}
					[^;]*
					\s* \) \s* ;
				)
			/xs;

	while ($$fileContentsRef =~ / $pat /xgso) {

		my @expert_item = (1, 1, "ei_name", "GROUP", "SEVERITY", "fieldfullname", "fieldabbrevname", 
							 "pinfo", "item", "tvb", "offset", "length", "params");
		my $arg_loop = 5;
		my $str = "${1}\n";
		$str =~ tr/\t\n\r/ /d;
		$str =~ s/ \s+ / /xg;
		#print "$fileName: $str\n";

		@args = split(/,/, $str);
		#printf "ARGS(%d): %s\n", scalar @args, join("# ", @args);
		$args[0] =~ s/expert_add_info_format\s*\(\s*//;

		$expert_item[7] = $args[0];			#pinfo
		$expert_item[8] = trim($args[1]);	#item
		$expert_item[3] = trim($args[2]);	#GROUP
		$expert_item[4] = trim($args[3]);	#SEVERITY
		$expert_item[5] = trim($args[4]);	#fieldfullname
		$expert_item[5] =~ s/\"//;

		#XXX - conditional?
		$expert_item[5] =~ s/\"\s*\)\s*;$//;
		$expert_item[5] =~ s/\"$//;

		#params
		$expert_item[12] = "";
		while ($arg_loop < scalar @args) {
			$expert_item[12] .= trim($args[$arg_loop]);
			if ($arg_loop+1 < scalar @args) {
				$expert_item[12] .= ", ";
			}
			$arg_loop += 1;
		}
		$expert_item[12] =~ s/\s*\)\s*;$//;

		#ei variable name
		$expert_item[2] = sprintf("ei_%s_%s", $protabbrev, lc($expert_item[5]));
		$expert_item[2] =~ s/\s+|-|:/_/g;

		#field abbreviated name
		$expert_item[6] = sprintf("%s.%s", $protabbrev, lc($expert_item[5]));
		$expert_item[6] =~ s/\s+|-|:/_/g;

		push(@expert_list, \@expert_item);

		$num_items += 1;
	}

	if ($num_items > 0) {
		open(FCO, ">", $fileName . ".expert_add_info_input");
		for my $item (@expert_list) {
			print FCO join(";", @{$item}), "\n";
		}
		close(FCO);
	}
}

# ---------------------------------------------------------------------
# Find all expert_add_info_format calls and replace them with the data
# found in expert_list
sub fix_expert_add_info_format {
	my( $fileContentsRef, $fileName) = @_;
	my $found = 0;
	my $pat;

	$pat = qr /
				(
					(?:expert_add_info_format)\s* \(
					(([^[\,;])*\,){4,}
					[^;]*
					\s* \) \s* ;
				)
			/xs;

	$$fileContentsRef =~ s/ $pat /patsub($found, $1)/xges;
}

# ---------------------------------------------------------------------
# Format expert info functions with expert_list data
sub patsub {
	my $item_str;

	#print $expert_list[$_[0]][2] . " = ";
	#print $#{$expert_list[$_[0]]}+1;
	#print "\n";

	if ($expert_list[$_[0]][0] eq "1") {
		$item_str = sprintf("expert_add_info(%s, %s, &%s);",
						 $expert_list[$_[0]][7], $expert_list[$_[0]][8], $expert_list[$_[0]][2]);
	} elsif ($expert_list[$_[0]][0] eq "2") {
		$item_str = sprintf("expert_add_info_format(%s, %s, &%s, \"%s\"",
						 $expert_list[$_[0]][7], $expert_list[$_[0]][8],
						 $expert_list[$_[0]][2], $expert_list[$_[0]][5]);
		if (($#{$expert_list[$_[0]]}+1 > 12 ) && ($expert_list[$_[0]][12] ne "")) {
			$item_str .= ", $expert_list[$_[0]][12]";
		}
		$item_str .= ");";
	} elsif ($expert_list[$_[0]][0] eq "3") {
		$item_str = sprintf("proto_tree_add_expert(%s, %s, &%s, %s, %s, %s);",
						 $expert_list[$_[0]][8], $expert_list[$_[0]][7],
						 $expert_list[$_[0]][2], $expert_list[$_[0]][9],
						 $expert_list[$_[0]][10], $expert_list[$_[0]][11]);
	} elsif ($expert_list[$_[0]][0] eq "4") {
		$item_str = sprintf("proto_tree_add_expert_format(%s, %s, &%s, %s, %s, %s, \"%s\"",
						 $expert_list[$_[0]][8], $expert_list[$_[0]][7], $expert_list[$_[0]][2],
						 $expert_list[$_[0]][9], $expert_list[$_[0]][10],
						 $expert_list[$_[0]][11], $expert_list[$_[0]][5]);
		if (($#{$expert_list[$_[0]]}+1 > 12) && ($expert_list[$_[0]][12] ne "")) {
			$item_str .= ", $expert_list[$_[0]][12]";
		}
		$item_str .= ");";
	}

	$_[0] += 1;

	return $item_str;
}

# ---------------------------------------------------------------------
# Output the ei variable declarations and expert array.  For now, write them to a file.
# XXX - Eventually find the right place to add it to the modified dissector file
sub output_ei_data {
	my( $fileName) = @_;
	my %eis = ();
	my $index;
	my $key;

	#add ei to hash table to prevent against (accidental) duplicates
	for ($index=0;$index<@expert_list;$index++) {
		if ($expert_list[$index][1] eq "1") {
			$eis{$expert_list[$index][2]} = $expert_list[$index][2];
		}
	}

	open(FCO, ">", $fileName . ".ei");

	print FCO "/* Generated from convert_expert_add_info_format.pl */\n";

	foreach $key (keys %eis) {
		print FCO "static expert_field $key = EI_INIT;\n";
	}
	print FCO "\n\n";

	if ($register ne "") {
		print FCO "  static ei_register_info ei[] = {\n";
	}

	%eis = ();
	for ($index=0;$index<@expert_list;$index++) {
		if ($expert_list[$index][1] eq "1") {
			if (exists($eis{$expert_list[$index][2]})) {
				print "duplicate ei entry '$expert_list[$index][2]' found!  Aborting conversion.\n";
				exit(-1);
			}
			$eis{$expert_list[$index][2]} = $expert_list[$index][2];

			print FCO "      { &$expert_list[$index][2], { \"$expert_list[$index][6]\", $expert_list[$index][3], ";
			print FCO "$expert_list[$index][4], \"$expert_list[$index][5]\", EXPFILL }},\r\n";
		}
	}

	if ($register ne "") {
		print FCO "  };\n\n\n";
		print FCO "  expert_module_t* expert_$protabbrev;\n\n";
		  
		print FCO "  expert_$protabbrev = expert_register_protocol(proto_$protabbrev);\n";
		print FCO "  expert_register_field_array(expert_$protabbrev, ei, array_length(ei));\n\n";
	}


	close(FCO);
}
