#!/usr/bin/perl -w
# create the enterprises file from
# http://www.iana.org/assignments/enterprise-numbers
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

use strict;
use File::Spec;

my ($vol, $script_dir) = File::Spec->splitpath( __FILE__ );
my $root_dir = File::Spec->catpath($vol, $script_dir, "..");
chdir($root_dir) || die("Can't find $root_dir");

my $in = shift;

$in = "http://www.iana.org/assignments/enterprise-numbers" unless(defined $in);

my @in_lines;
my $revision = '2014-04-27';

my $min_entries = 100;
my $smi_total = 0;

if($in =~ m/^http:/i) {
	eval "require LWP::UserAgent;";
	die "LWP isn't installed. It is part of the standard Perl module libwww." if $@;

	my $agent    = LWP::UserAgent->new;
	$agent->env_proxy;
	$agent->agent("Wireshark make-sminmpec.pl/$revision");

	warn "starting to fetch $in ...\n";

	my $request  = HTTP::Request->new(GET => $in);

	my $result   = $agent->request($request);

	if ($result->code eq 200) {
		warn "done fetching $in\n";
		@in_lines = split /\n/, $result->content;
	} else {
		die "request for $in failed with result code:" . $result->code;
	}
} else {
  open IN, "< $in";
  @in_lines = <IN>;
  close IN;
}

my $body = '';
my $code;
my $name;
my $last_updated = "(last updated ???)";
my $end_of_document = 0;

for(@in_lines) {
	chomp;

	if (/^(\d+)/) {
		$code = sprintf("%d", $1);
	} elsif (/^   ?(\S.*)/ ) { # up to three spaces because of formatting errors in the source
		$name = $1;
		next if (/^\s*\(?\s*unassigned/i);
		$name =~ s/\s+$//;
		$name =~ s/ \((formerly .*)\)/\t# $1/;
		$body .= "\n$code\t$name";
	} elsif (/\(last updated/i) {
		$last_updated = $_;
	} elsif (/^ *End of Document/) {
		$end_of_document = 1;
	}
}

die "\"End of Document\" not found. Truncated source file?" unless ($end_of_document);

open OUT, "> enterprises.tsv";

print OUT <<"_SMINMPEC";
#
# generated from http://www.iana.org/assignments/enterprise-numbers
# run "tools/make-sminmpec.pl [infile]" to regenerate
#
# The format used here is: <NUMERICAL_ID><SPACE><NAME>
# Where SPACE can be any sequence of spaces and tabs.
#
# $last_updated
$body
_SMINMPEC

close OUT;
