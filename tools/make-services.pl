#!/usr/bin/perl -w
# create the services file from
# http://www.iana.org/assignments/enterprise-numbers
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2004 Gerald Combs
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
use strict;
use English;

my $svc_file = "services";
my $in = shift;
my $min_size = 2000000; # Size was 2654612 on 2011-08-31
my @exclude_pats = qw(
	^spr-itunes
	^spl-itunes
	^shilp
);
my $iana_port_url = "http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt";

# As of August 2011, the page linked from http://www.iana.org/protocols/
# is XML. Perhaps we should parse that instead.
$in = $iana_port_url unless(defined $in);

my $body = "";

if($in =~ m/^http:/i) {
	eval "require LWP::UserAgent;";
	die "LWP isn't installed. It is part of the standard Perl module libwww." if $@;

	my $agent    = LWP::UserAgent->new;
	$agent->env_proxy;

	warn "starting to fetch $in ...\n";

	my $request  = HTTP::Request->new(GET => $in);


	if (-f $svc_file) {
		my $mtime;
		(undef,undef,undef,undef,undef,undef,undef,$min_size,undef,$mtime,undef,undef,undef) = stat($svc_file);
		$request->if_modified_since( $mtime );
	}

	my $result   = $agent->request($request);

	if ($result->code eq 200) {
		warn "done fetching $in\n";
		my @in_lines = split /\n/, $result->content;
		my $prefix = "";
		my $exclude_match;
		my $line;
		my $pat;
		foreach $line (@in_lines) {
			$prefix = "# ";
			$exclude_match = 0;

			if ($line =~ /^(\S+)\s+(\d+)\s+(tcp|udp|sctp|dccp)\s+(\S.*)/) {
				$line = "$1	$2/$3	# $4";

				foreach $pat (@exclude_pats) {
					if ($line =~ $pat) {
						$exclude_match = 1;
						last;
					}
				}

				if ($exclude_match) {
					$body .= "# Excluded by $PROGRAM_NAME\n";
				} else {
					$prefix = "";
				}
			}

			$line =~ s/^\s+|\s+$//g;

			$body .= $prefix . $line . "\n";
		}
	} elsif ($result->code eq 304) {
		warn "$svc_file was up-to-date\n";
		exit 0;
	} else {
		die "request for $in failed with result code:" . $result->code;
	}

} else {
  open IN, "< $in";
  $body = <IN>;
  close IN;
}

if (length($body) < $min_size * 0.9) {
	die "$in doesn't have enough data\n";
}

open OUT, "> $svc_file";

print OUT <<"_HEADER";
# This is a local copy of the IANA port-numbers file.
#
# \$Id\$
#
# Wireshark uses it to resolve port numbers into human readable
# service names, e.g. TCP port 80 -> http.
#
# It is subject to copyright and being used with IANA's permission:
# http://www.wireshark.org/lists/wireshark-dev/200708/msg00160.html
#
# The original file can be found at:
# $iana_port_url
#
$body
_HEADER

close OUT;
