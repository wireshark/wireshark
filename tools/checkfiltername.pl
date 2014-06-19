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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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
use Getopt::Long;

my @elements;
my @elements_dup;
my @protocols;
my %filters;
my %expert_filters;
my @acceptedprefixes = ("dcerpc-");
my @asn1automatedfilelist;
my @dcerpcautomatedfilelist;
my @idl2wrsautomatedfilelist;
my @filemanipulationfilelist;
my @prefixfilelist;
my @nofieldfilelist;
my %unique;
my @uniquefilelist;
my @noregprotocolfilelist;
my @periodinfilternamefilelist;

my $showlinenoFlag = '';
my $showautomatedFlag = '';

my $state = "";
# "s_unknown",
# "s_start",
# "s_in_hf_register_info",
# "s_hf_register_info_entry",
# "s_header_field_info_entry",
# "s_header_field_info_entry_start",
# "s_header_field_info_entry_name",
# "s_header_field_info_entry_abbrev",
# "s_header_field_info_entry_abbrev_end",
# "s_start_expert",
# "s_in_ei_register_info",
# "s_ei_register_info_entry",
# "s_ei_register_info_entry_start",
# "s_ei_register_info_entry_abbrev_end",
# "s_nofields"

my $restofline;
my $filecount = 0;
my $currfile = "";
my $protabbrev = "";
my $protabbrev_index;
my $PFNAME_value = "";
my $linenumber = 1;
my $totalerrorcount = 0;
my $errorfilecount = 0;
my $onefield = 0;
my $nofields = 0;
my $noperiod = 0;
my $noregprotocol = 1;
my $automated = 0;
my $more_tokens;
my $showall = 0;

my $comment = 0;

my $error = 0;

sub checkprotoabbrev {
	my $abbrev = "";
	my $abbrevpos;
	my $proto_abbrevpos1;
	my $proto_abbrevpos2;
	my $afterabbrev = "";
	my $check_dup_abbrev = "";
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
			$check_dup_abbrev = $afterabbrev;
			$afterabbrev = substr($afterabbrev, 0, length($abbrev));
		}

		if ($abbrev ne $protabbrev) {
			$errorline = 1;
						
			#check if there is a supported protocol that matches the abbrev.
			#This may be a case of filename != PROTOABBREV
			foreach (@protocols) {
				if ($abbrev eq $_) {
					$errorline = 0;
				} elsif (index($_, ".") != -1) {
				
					#compare from start of string for each period found
					$proto_abbrevpos1 = 0;
					while ((($proto_abbrevpos2 = index($_, ".", $proto_abbrevpos1)) != -1) &&
							($errorline == 1)) {
						if ($abbrev eq substr($_, 0, $proto_abbrevpos2)) {
							$errorline = 0;
						}

						$proto_abbrevpos1 = $proto_abbrevpos2+1;
					}
				}
			}			
		}

		# find any underscores that preface or follow a period
		if (((index($_[0], "._") >= 0) || (index($_[0], "_.") >= 0)) &&
			#ASN.1 dissectors can intentionally generating this field name, so don't fault the dissector
			(index($_[0], "_untag_item_element") < 0)) {
			if ($showlinenoFlag) {
				push(@elements, "$_[1] $_[0] contains an unnecessary \'_\'\n");
			} else {
				push(@elements, "$_[0] contains an unnecessary \'_\'\n");
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
			}
			else {
				push(@filemanipulationfilelist, "$currfile\n");
			}

			#now check the acceptable "fields from a different protocol"
			if ($errorline == 1) {
				if (is_from_other_protocol_whitelist($_[0], $currfile) == 1) {
					$errorline = 0;
				}
			}

			#now check the acceptable "fields that include a version number"
			if ($errorline == 1) {
				if (is_protocol_version_whitelist($_[0], $currfile) == 1) {
					$errorline = 0;
				}
			}
		}
		
		if ($errorline == 1) {
			$debug>1 && print "$_[1] $_[0] doesn't match PROTOABBREV of $protabbrev\n";
			if ($showlinenoFlag) {
				push(@elements, "$_[1] $_[0] doesn't match PROTOABBREV of $protabbrev\n");
			} else {
				push(@elements, "$_[0] doesn't match PROTOABBREV of $protabbrev\n");
			}
		}

		if (($abbrev ne "") && (lc($abbrev) eq lc($afterabbrev))) {
			#Allow ASN.1 generated files to duplicate part of proto name
			if ((grep($currfile, @asn1automatedfilelist) == 0) &&
				#Check "approved" whitelist
				(is_proto_dup_whitelist($abbrev, $check_dup_abbrev) == 0)) {
				if ($showlinenoFlag) {
					push(@elements_dup, "$_[1] $_[0] duplicates PROTOABBREV of $abbrev\n");
				} else {
					push(@elements_dup, "$_[0] duplicates PROTOABBREV of $abbrev\n");
				}
			}
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

	foreach (sort keys %expert_filters) {
		checkprotoabbrev ($expert_filters{$_}, $_);
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

#--------------------------------------------------------------------
# This is a list of dissectors that intentionally have filter names
# where the second segment duplicates (at least partially) the name
# of the first.  The most common case is in ASN.1 dissectors, but
# those can be dealt with by looking at the first few lines of the
# dissector. This list has been vetted and justification will need
# to be provided to add to it. Acknowledge these dissectors aren't
# a problem for the pre-commit script
#--------------------------------------------------------------------
sub is_proto_dup_whitelist {
	if (($_[0] eq "bat") && (index($_[1], "batman") >= 0)) {return 1;}

	return 0;
}

#--------------------------------------------------------------------
# This is a list of dissectors that intentionally have filter names
# shared with other dissectors.  This list has been vetted and
# justification will need to be provided to add to it.
# Acknowledge these dissectors aren't a problem for the pre-commit script
#--------------------------------------------------------------------
sub is_from_other_protocol_whitelist {
	my $proto_filename;
	my $dir_index = rindex($_[1], "\\");

	#handle directory names on all platforms
	if ($dir_index < 0) {
		$dir_index = rindex($_[1], "/");
	}

	if ($dir_index < 0) {
		$proto_filename = $_[1];
	}
	else {
		$proto_filename = substr($_[1], $dir_index+1);
	}

	# XXX - may be faster to hash this (note 1-many relationship)?
	if (($proto_filename eq "packet-bpdu.c") && (index($_[0], "mstp") >= 0)) {return 1;}
	if (($proto_filename eq "packet-cimetrics.c") && (index($_[0], "llc") >= 0)) {return 1;}
	if (($proto_filename eq "packet-cipsafety.c") && (index($_[0], "cip") >= 0)) {return 1;}
	if (($proto_filename eq "packet-cipsafety.c") && (index($_[0], "enip") >= 0)) {return 1;}
	if (($proto_filename eq "packet-dcerpc-netlogon.c") && (index($_[0], "ntlmssp") >= 0)) {return 1;}
	if (($proto_filename eq "packet-dcom-oxid.c") && (index($_[0], "dcom") >= 0)) {return 1;}
	if (($proto_filename eq "packet-dvb-data-mpe.c") && (index($_[0], "mpeg_sect") >= 0)) {return 1;}
	if (($proto_filename eq "packet-dvb-ipdc.c") && (index($_[0], "ipdc") >= 0)) {return 1;}
	if (($proto_filename eq "packet-enip.c") && (index($_[0], "cip") >= 0)) {return 1;}
	if (($proto_filename eq "packet-extreme.c") && (index($_[0], "llc") >= 0)) {return 1;}
	if (($proto_filename eq "packet-fmp_notify.c") && (index($_[0], "fmp") >= 0)) {return 1;}
	if (($proto_filename eq "packet-foundry.c") && (index($_[0], "llc") >= 0)) {return 1;}
	if (($proto_filename eq "packet-glusterfs.c") && (index($_[0], "gluster") >= 0)) {return 1;}
	if (($proto_filename eq "packet-h248_annex_e.c") && (index($_[0], "h248") >= 0)) {return 1;}
	if (($proto_filename eq "packet-h248_q1950.c") && (index($_[0], "h248") >= 0)) {return 1;}
	if (($proto_filename eq "packet-ieee80211.c") && (index($_[0], "eapol") >= 0)) {return 1;}
	if (($proto_filename eq "packet-ieee80211-radio.c") && (index($_[0], "wlan") >= 0)) {return 1;}
	if (($proto_filename eq "packet-ieee80211-wlancap.c") && (index($_[0], "wlan") >= 0)) {return 1;}
	if (($proto_filename eq "packet-ieee802154.c") && (index($_[0], "wpan") >= 0)) {return 1;}
	if (($proto_filename eq "packet-k12.c") && (index($_[0], "aal2") >= 0)) {return 1;}
	if (($proto_filename eq "packet-k12.c") && (index($_[0], "atm") >= 0)) {return 1;}
	if (($proto_filename eq "packet-m3ua.c") && (index($_[0], "mtp3") >= 0)) {return 1;}
	if (($proto_filename eq "packet-mpeg-dsmcc.c") && (index($_[0], "mpeg_sect") >= 0)) {return 1;}
	if (($proto_filename eq "packet-mpeg-dsmcc.c") && (index($_[0], "etv.dsmcc") >= 0)) {return 1;}
	if (($proto_filename eq "packet-mpeg1.c") && (index($_[0], "rtp.payload_mpeg_") >= 0)) {return 1;}
	if (($proto_filename eq "packet-ndps.c") && (index($_[0], "spx.ndps_") >= 0)) {return 1;}
	if (($proto_filename eq "packet-pw-atm.c") && (index($_[0], "atm") >= 0)) {return 1;}
	if (($proto_filename eq "packet-pw-atm.c") && (index($_[0], "pw") >= 0)) {return 1;}
	if (($proto_filename eq "packet-scsi.c") && (index($_[0], "scsi_sbc") >= 0)) {return 1;}
	if (($proto_filename eq "packet-sndcp-xid.c") && (index($_[0], "llcgprs") >= 0)) {return 1;}
	if (($proto_filename eq "packet-wlccp.c") && (index($_[0], "llc") >= 0)) {return 1;}
	if (($proto_filename eq "packet-wps.c") && (index($_[0], "eap") >= 0)) {return 1;}
	if (($proto_filename eq "packet-wsp.c") && (index($_[0], "wap") >= 0)) {return 1;}
	if (($proto_filename eq "packet-xot.c") && (index($_[0], "x25") >= 0)) {return 1;}

	#XXX - HACK to get around nested "s in field name
	if (($proto_filename eq "packet-gsm_sim.c") && (index($_[0], "e\\") >= 0)) {return 1;}

	return 0;
}

#--------------------------------------------------------------------
# This is a list of dissectors that use their (protocol) version number
# as part of the first display filter segment, which checkfiltername
# usually complains about.  Whitelist them so it can pass
# pre-commit script
#--------------------------------------------------------------------
sub is_protocol_version_whitelist {
	my $proto_filename;
	my $dir_index = rindex($_[1], "\\");

	#handle directory names on all platforms
	if ($dir_index < 0) {
		$dir_index = rindex($_[1], "/");
	}

	if ($dir_index < 0) {
		$proto_filename = $_[1];
	}
	else {
		$proto_filename = substr($_[1], $dir_index+1);
	}

	# XXX - may be faster to hash this?
	if (($proto_filename eq "packet-ehs.c") && (index($_[0], "ehs2") >= 0)) {return 1;}
	if (($proto_filename eq "packet-hsrp.c") && (index($_[0], "hsrp2") >= 0)) {return 1;}
	if (($proto_filename eq "packet-ipv6.c") && (index($_[0], "ip") >= 0)) {return 1;}
	if (($proto_filename eq "packet-openflow_v1.c") && (index($_[0], "openflow") >= 0)) {return 1;}
	if (($proto_filename eq "packet-rtnet.c") && (index($_[0], "tdma-v1") >= 0)) {return 1;}
	if (($proto_filename eq "packet-scsi-osd.c") && (index($_[0], "scsi_osd2") >= 0)) {return 1;}
	if (($proto_filename eq "packet-sflow.c") && (index($_[0], "sflow_5") >= 0)) {return 1;}
	if (($proto_filename eq "packet-sflow.c") && (index($_[0], "sflow_245") >= 0)) {return 1;}
	if (($proto_filename eq "packet-tipc.c") && (index($_[0], "tipcv2") >= 0)) {return 1;}


	return 0;
}

# ---------------------------------------------------------------------
#
# MAIN
#
GetOptions(
		   'showlineno'    => \$showlinenoFlag,
		   'showautomated' => \$showautomatedFlag,
		  );

while (<>) {
	if ($currfile !~ /$ARGV/) {
		&printprevfile();

		# New file - reset array and state
		$filecount++;
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

		$PFNAME_value = "";
		$noregprotocol = 1;
		$automated = 0;
		$nofields = 0;
		$onefield = 0;
		$noperiod = 0;
		$linenumber = 1;
		%filters = ( );
		%expert_filters = ( );
		@protocols = ( );
		@elements = ( );
		@elements_dup = ( );
		$state = "s_unknown";
	}
	
	if (($automated == 0) && ($showautomatedFlag eq "")) {
		#DCERPC automated files
		if ($_ =~ "DO NOT EDIT") {
			push(@dcerpcautomatedfilelist, "$currfile\n");
			$automated = 1;
			next;
		}
		#ASN.1 automated files 
		elsif ($_ =~ "Generated automatically by the ASN.1 to Wireshark dissector compiler") {
			push(@asn1automatedfilelist, "$currfile\n");
			$automated = 1;
			next;
		}
		#idl2wrs automated files
		elsif ($_ =~ "Autogenerated from idl2wrs") {
			push(@idl2wrsautomatedfilelist, "$currfile\n");
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
	
	#PFNAME is a popular #define for the proto filter name, so use it for testing	
	if ($restofline =~ /#define\s*PFNAME\s*\"([^\"]*)\"/) {
		$PFNAME_value = $1;
		$debug>1 && print "PFNAME: '$1'\n";
	}
	
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
		} elsif (($state eq "s_proto_short_name") && ($restofline =~ /\s*PFNAME\s*(.*)/)) {
			$more_tokens = 0;
			$state = "s_proto_filter_name";
			if ((index($PFNAME_value, ".") != -1) && ($noperiod == 0)) {
				push(@periodinfilternamefilelist, "$currfile\n");
				$noperiod = 1;
			}
			push(@protocols, $PFNAME_value);
			$debug>1 && print "proto filter name: '$PFNAME_value'\n";
		} elsif (($state eq "s_proto_short_name") && ($restofline =~ /\s*\"([^\"]*)\"\s*(.*)/)) {
			$more_tokens = 0;
			$state = "s_proto_filter_name";
			if ((index($1, ".") != -1) && ($noperiod == 0)) {
				push(@periodinfilternamefilelist, "$currfile\n");
				$noperiod = 1;
			}
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
		} elsif ($restofline =~ /\s*static\s*ei_register_info\s*(\w+)\[\](.*)/) {
			$restofline = $2;
			$state = "s_start_expert";
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
		} elsif (($state eq "s_header_field_info_entry_start") && ($restofline =~ /((\"([^\"]*)\")|(\w+))\s*,(.*)/)) {
			$restofline = $5;
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
		} elsif (($state eq "s_start_expert") && ($restofline =~ /\W+{(.*)/)) {
			$restofline = $1;
			$state = "s_in_ei_register_info";
			$debug>1 && print "$linenumber $state\n";
		} elsif (($state eq "s_in_ei_register_info") && ($restofline =~ /\W+{(.*)/)) {	
			$restofline = $1;
			$state = "s_ei_register_info_entry";
			$debug>1 && print "$linenumber $state\n";
		} elsif (($state eq "s_in_ei_register_info") && ($restofline =~ /\s*};(.*)/)) {
			$restofline = $1;
			$state = "s_unknown";
		} elsif (($state eq "s_ei_register_info_entry") && ($restofline =~ /\s*{(.*)/)) {
			$restofline = $1;
			$state = "s_ei_register_info_entry_start";
			$debug>1 && print "$linenumber $state\n";
		} elsif (($state eq "s_ei_register_info_entry_start") && ($restofline =~ /\"([^\"]*)\"\s*,(.*)/)) {
			$restofline = $2;
			$debug>1 && print "$linenumber ei_register_info_entry_abbrev: $1\n";
			$expert_filters{$linenumber} = $1;
			$state = "s_ei_register_info_entry_abbrev_end";
		} elsif (($state eq "s_ei_register_info_entry_abbrev_end") && ($restofline =~ /[^}]*}(.*)/)) {
			$restofline = $1;
			$state = "s_in_ei_register_info";
			$debug>1 && print "$linenumber $state\n";
		} else {
			$more_tokens = 0;
		}
	}
		
	$linenumber++;	
}

&printprevfile();

print "\n\nTOTAL ERRORS: $totalerrorcount";
if ($filecount > 1) {
	print " ($errorfilecount files)\n";

	print "NO FIELDS: " . scalar(@nofieldfilelist) . "\n";
	print "AUTOMATED: " . (scalar(@asn1automatedfilelist) + scalar(@dcerpcautomatedfilelist) + scalar(@idl2wrsautomatedfilelist)) . "\n";
	print "NO PROTOCOL: " . scalar(@noregprotocolfilelist) . "\n";

	print "\nASN.1 AUTOMATED FILE LIST\n";
	foreach (@asn1automatedfilelist) {
		print $_;
	}
	print "\nDCE/RPC AUTOMATED FILE LIST\n";
	foreach (@dcerpcautomatedfilelist) {
		print $_;
	}
	print "\nIDL2WRS AUTOMATED FILE LIST\n";
	foreach (@idl2wrsautomatedfilelist) {
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

	print "\nPERIOD IN PROTO FILTER NAME FILE LIST\n";
	foreach (@periodinfilternamefilelist) {
		print $_;
	}
}

print "\n";

exit $error;

__END__
