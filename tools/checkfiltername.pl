#!/usr/bin/perl

my $debug = 0;
# 0: off
# 1: specific debug
# 2: full debug

#
# verify that display filter names correspond with the PROTABBREV of 
# of the dissector.  Enforces the dissector to have a source 
# filename of format packet-PROTABBREV.c
#
# Usage: checkfiltername.pl <file or files>

# $Id:

#
# Copyright 2011 Michael Mann (see AUTHORS file)
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

#
# Example:
# ~/work/wireshark/trunk/epan/dissectors> ../../tools/checkfiltername.pl packet-3com-xns.c
# packet-3com-xns.c (2 (of 2) fields)
# 102 3comxns.type doesn't match PROTOABBREV of 3com-xns
# 106 3comxns.type doesn't match PROTOABBREV of 3com-xns
#
# or checkfiltername.pl packet-*.c, which will check all the dissector files.
#
#

use warnings;
use strict;

my @elements;
my @elements_dup;
my @protocols;
my %filters;
my @acceptedprefixes = ("dcerpc-");
my @asn1automatedfilelist;
my @dcerpcautomatedfilelist;
my @filemanipulationfilelist;
my @prefixfilelist;
my @nofieldfilelist;
my %unique;
my @uniquefilelist;
my @noregprotocolfilelist;

my $state;
# "s_unknown",
# "s_start",
# "s_in_hf_register_info",
# "s_hf_register_info_entry",
# "s_header_field_info_entry",
# "s_header_field_info_entry_start",
# "s_header_field_info_entry_name",
# "s_header_field_info_entry_abbrev",
# "s_header_field_info_entry_abbrev_end",
# "s_nofields"

my $restofline;
my $currfile = "";
my $protabbrev = "";
my $protabbrev_index;
my $linenumber = 1;
my $totalerrorcount = 0;
my $errorfilecount = 0;
my $onefield = 0;
my $nofields = 0;
my $noregprotocol = 1;
my $automated = 0;
my $more_tokens;
my $showall = 0;

my $comment = 0;

my $error = 0;

sub checkprotoabbrev {
	my $abbrev = "";
	my $abbrevpos;
	my $afterabbrev = "";
	my $modprotabbrev = "";
	my $errorline = 0;
	my $prefix;
	
	if (($automated == 0) || ($showall == 1)) {
		$abbrevpos = index($_[0], ".");
		if ($abbrevpos == -1) {
			$abbrev = $_[0];
		}
		else {
			$abbrev = substr($_[0], 0, $abbrevpos);
			$afterabbrev = substr($_[0], $abbrevpos+1, length($_[0])-$abbrevpos);
			$afterabbrev = substr($afterabbrev, 0, length($abbrev));
		}
				
		if ($abbrev ne $protabbrev) {
			$errorline = 1;
						
			#check if there is a supported protocol that matches the abbrev.
			#This may be a case of filename != PROTOABBREV
			foreach (@protocols) {
				if ($abbrev eq $_) {
					$errorline = 0;
				}
			}			
		}

		if (($errorline == 1) && ($showall == 0)) {
			#try some "accepted" variations of PROTOABBREV
			
			#replace '-' with '_'
			$modprotabbrev = $protabbrev;
			$modprotabbrev =~ s/-/_/g;
			if ($abbrev eq $modprotabbrev) {
				$errorline = 0;
			}

			#remove '-'		
			if ($errorline == 1) {
				$modprotabbrev = $protabbrev;
				$modprotabbrev =~ s/-//g;
				if ($abbrev eq $modprotabbrev) {
					$errorline = 0;
				}
			}

			#remove '_'		
			if ($errorline == 1) {
				$modprotabbrev = $protabbrev;
				$modprotabbrev =~ s/_//g;
				if ($abbrev eq $modprotabbrev) {
					$errorline = 0;
				}
			}
			
			if ($errorline == 1) {
				#remove any "accepted" prefix to see if there is still a problem
				foreach (@acceptedprefixes) {
					if ($protabbrev =~ /^$_/) {
						$modprotabbrev = substr($protabbrev, length($_));
						if ($abbrev eq $modprotabbrev) {
							push(@prefixfilelist, "$currfile\n");
							$errorline = 0;
						}
					}
				}
			} else {
				push(@filemanipulationfilelist, "$currfile\n");
			}
		}
		
		if ($errorline == 1) {
			$debug>1 && print "$_[1] $_[0] doesn't match PROTOABBREV of $protabbrev\n";
			push(@elements, "$_[1] $_[0] doesn't match PROTOABBREV of $protabbrev\n");
		}
		
		if (lc($abbrev) eq lc($afterabbrev)) {
			push(@elements_dup, "$_[1] $_[0] duplicates PROTOABBREV of $abbrev\n");
		}
	}	
}

sub printprevfile {
	my $totalfields = keys(%filters);
	my $count_ele;
	my $count_dup;
	my $total_count;

	foreach (sort keys %filters) {
		checkprotoabbrev ($filters{$_}, $_);
	}
	
	$count_ele = @elements;
	$count_dup = @elements_dup;
	$total_count = $count_ele+$count_dup;

	if ($noregprotocol == 1) {
		#if no protocol is registered, only worry about duplicates
		if ($currfile ne "") {
			push(@noregprotocolfilelist, "$currfile\n");
		}
		
		if ($count_dup > 0) {
			$errorfilecount++;
			$totalerrorcount += $count_dup;
		}
			
		if (($showall == 1) || ($count_dup > 0))  {
			print "\n\n$currfile  - NO PROTOCOL REGISTERED\n";
			if ($showall == 1) {
				#everything is included, so count all errors
				$totalerrorcount += $count_ele;
				if (($count_ele > 0) && ($count_dup == 0)) {
					$errorfilecount++;
				}
			
				foreach (@elements) {
					print $_;
				}
			}
			foreach (@elements_dup) {
				print $_;
			}
		}	
	} else {
		if ($total_count > 0) {
			$errorfilecount++;
			$totalerrorcount += $total_count;
		}
	
		if (($automated == 0) || ($showall == 1)) {
			if ($total_count > 0) {
				if ($automated == 1) {
					if ($showall == 1) {
						print "\n\n$currfile - AUTOMATED ($total_count (of $totalfields) fields)\n";
					}
				} else {
					print "\n\n$currfile ($total_count (of $totalfields) fields)\n";
				}
				
				foreach (@elements) {
					print $_;
				}
				foreach (@elements_dup) {
					print $_;
				}
			}
			
			if ((($nofields) || ($totalfields == 0)) && ($currfile ne "")) {
				if ($showall == 1) {
					print "\n\n$currfile  - NO FIELDS\n";
				}
				push(@nofieldfilelist, "$currfile\n");
			}
		}
	}	
}

while (<>) {
	if ($currfile !~ /$ARGV/) {
		&printprevfile();

		# New file - reset array and state
		$currfile = $ARGV;
		
		#determine PROTABBREV for dissector based on file name format of (dirs)/packet-PROTABBREV.c
		$protabbrev_index = rindex($currfile, "packet-");
		if ($protabbrev_index == -1) {
			print "$currfile doesn't fit format of packet-PROTABBREV.c\n";
			next;
		}
				
		$protabbrev = substr($currfile, $protabbrev_index+length("packet-"));
		$protabbrev_index = rindex($protabbrev, ".");
		if ($protabbrev_index == -1) {
			print "$currfile doesn't fit format of packet-PROTABBREV.c\n";
			next;
		}
		$protabbrev = substr($protabbrev, 0, $protabbrev_index);		

		$noregprotocol = 1;
		$automated = 0;
		$nofields = 0;
		$onefield = 0;
		$linenumber = 1;
		%filters = ( );
		@protocols = ( );
		@elements = ( );
		@elements_dup = ( );
		$state = "s_unknown";
	}
	
	if ($automated == 0) {
		#DCERPC automated files
		if ($_ =~ "DO NOT EDIT") {
			push(@dcerpcautomatedfilelist, "$currfile\n");
			$automated = 1;
			next;
		}
		#ASN.1 automated files 
		elsif ($_ =~ "It is created automatically by the ASN.1 to Wireshark dissector compiler") {
			push(@asn1automatedfilelist, "$currfile\n");
			$automated = 1;
			next;
		}
	}
		
	# opening then closing comment
	if (/(.*?)\/\*.*\*\/(.*)/) {
		$comment = 0;
		$_ = "$1$2";
	# closing then opening comment
	} elsif (/.*?\*\/(.*?)\/\*/) {
		$comment = 1;
		$_ = "$1";
	# opening comment
	} elsif (/(.*?)\/\*/) {
		$comment = 1;
		$_ = "$1";
	# closing comment
	} elsif (/\*\/(.*?)/) {
		$comment = 0;
		$_ = "$1";
	} elsif ($comment == 1) {
		$linenumber++;
		next;
	}
	# unhandled: more than one complete comment per line
	
	chomp;

	#proto_register_protocol state machine
	$restofline = $_;
	$more_tokens = 1;
	
	until ($more_tokens == 0) {
		if ($restofline =~ /proto_register_protocol\s*\((.*)/) {
			$noregprotocol = 0;
			$restofline = $1;
			$state = "s_proto_start";
		} elsif (($state eq "s_proto_start") && ($restofline =~ /^(\s*\"([^\"]*)\"\s*,)\s*(.*)/)) {
			$restofline = $3;
			$state = "s_proto_long_name";
			$debug>1 && print "proto long name: '$2'\n";
		} elsif (($state eq "s_proto_start") && ($restofline =~ /^(\s*(([\w\d])+)\s*,)\s*(.*)/)) {
			$restofline = $4;
			$state = "s_proto_long_name";
			$debug>1 && print "proto long name: '$2'\n";
		} elsif (($state eq "s_proto_long_name") && ($restofline =~ /^(\s*\"([^\"]*)\"\s*,)\s*(.*)/)) {
			$restofline = $3;
			$state = "s_proto_short_name";
			$debug>1 && print "proto short name: '$2'\n";
		} elsif (($state eq "s_proto_long_name") && ($restofline =~ /^(\s*(([\w\d])+)\s*,)\s*(.*)/)) {
			$restofline = $4;
			$state = "s_proto_short_name";
			$debug>1 && print "proto short name: '$2'\n";
		} elsif (($state eq "s_proto_short_name") && ($restofline =~ /\s*\"([^\"]*)\"\s*(.*)/)) {
			$more_tokens = 0;
			$state = "s_proto_filter_name";
			push(@protocols, $1);
			$debug>1 && print "proto filter name: '$1'\n";
		} elsif (($state eq "s_proto_short_name") && ($restofline =~ /\s*(([\w\d])+)\s*(.*)/)) {
			$more_tokens = 0;
			$state = "s_proto_filter_name";
			$debug>1 && print "proto filter name: '$1'\n";
		} else {
			$more_tokens = 0;
		}
	}
	
	#retrieving display filters state machine
	$restofline = $_;
	$more_tokens = 1;
	until ($more_tokens == 0) {
		if ($restofline =~ /\s*static\s*hf_register_info\s*(\w+)\[\](.*)/) {
			$restofline = $2;
			$state = "s_start";
			$debug>1 && print "$linenumber $state\n";
		} elsif (($state eq "s_start") && ($restofline =~ /\W+{(.*)/)) {
			$restofline = $1;
			$state = "s_in_hf_register_info";
			$debug>1 && print "$linenumber $state\n";
		} elsif (($state eq "s_in_hf_register_info") && ($restofline =~ /\W+{(.*)/)) {	
			$restofline = $1;
			$state = "s_hf_register_info_entry";
			$debug>1 && print "$linenumber $state\n";
			$onefield = 1;
		} elsif (($state eq "s_in_hf_register_info") && ($restofline =~ /\s*};(.*)/)) {
			$restofline = $1;
			if ($onefield == 0) {
				$debug && print "$linenumber NO FIELDS!!!\n";
				$nofields =	1;
				$state = "s_nofields";
				$more_tokens = 0;
			} else {
				$state = "s_unknown";
			}
		} elsif (($state eq "s_hf_register_info_entry") && ($restofline =~ /\s*&\s*(hf_\w*(\[w*\])?)\s*,?(.*)/)) {
			$restofline = $3;
			$debug>1 && print "$linenumber hf_register_info_entry: $1\n";
			$state = "s_header_field_info_entry";
		} elsif (($state eq "s_header_field_info_entry") && ($restofline =~ /\s*{(.*)/)) {
			$restofline = $1;
			$state = "s_header_field_info_entry_start";
			$debug>1 && print "$linenumber $state\n";
		} elsif (($state eq "s_header_field_info_entry_start") && ($restofline =~ /\"([^\"]*)\"\s*,(.*)/)) {
			$restofline = $2;
			$debug>1 && print "$linenumber header_field_info_entry_name: $1\n";
			$state = "s_header_field_info_entry_name";
		} elsif (($state eq "s_header_field_info_entry_name") && ($restofline =~ /\"([^\"]*)\"\s*,?(.*)/)) {
			$restofline = $2;
			$debug>1 && print "$linenumber header_field_info_entry_abbrev: $1\n";
			$state = "s_header_field_info_entry_abbrev";
			$filters{$linenumber} = $1;
		} elsif (($state eq "s_header_field_info_entry_abbrev") && ($restofline =~ /[^}]*}(.*)/)) {
			$restofline = $1;
			$state = "s_header_field_info_entry_abbrev_end";
			$debug>1 && print "$linenumber $state\n";
		} elsif (($state eq "s_header_field_info_entry_abbrev_end") && ($restofline =~ /[^}]*}(.*)/)) {
			$restofline = $1;
			$state = "s_in_hf_register_info";
			$debug>1 && print "$linenumber $state\n";
		} else {
			$more_tokens = 0;
		}
	}
		
	$linenumber++;	
}

&printprevfile();

print "\n\nTOTAL ERRORS: $totalerrorcount ($errorfilecount files)\n";
print "NO FIELDS: " . scalar(@nofieldfilelist) . "\n";
print "AUTOMATED: " . (scalar(@asn1automatedfilelist) + scalar(@dcerpcautomatedfilelist)) . "\n";
print "NO PROTOCOL: " . scalar(@noregprotocolfilelist) . "\n";

print "\nASN.1 AUTOMATED FILE LIST\n";
foreach (@asn1automatedfilelist) {
	print $_;
}
print "\nDCE/RPC AUTOMATED FILE LIST\n";
foreach (@dcerpcautomatedfilelist) {
	print $_;
}
print "\n\"FILE MANIPULATION\" FILE LIST\n";
@uniquefilelist = grep{ not $unique{$_}++} @filemanipulationfilelist;
foreach (@uniquefilelist) {
	print $_;
}
print "\nREMOVE PREFIX FILE LIST\n";
@uniquefilelist = grep{ not $unique{$_}++} @prefixfilelist;
foreach (@uniquefilelist) {
	print $_;
}
print "\nNO PROTOCOL REGISTERED FILE LIST\n";
foreach (@noregprotocolfilelist) {
	print $_;
}
print "\nNO FIELDS FILE LIST\n";
foreach (@nofieldfilelist) {
	print $_;
}
print "\n";


exit $error;

__END__
