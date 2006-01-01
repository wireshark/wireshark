# Some simple utility functions for pidl tests
# Copyright (C) 2005 Jelmer Vernooij
# Published under the GNU General Public License

package Util;

require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(test_samba4_ndr);

use strict;

use Test::More;
use Parse::Pidl::IDL;
use Parse::Pidl::NDR;
use Parse::Pidl::Samba4::NDR::Parser;
use Parse::Pidl::Samba4::Header;

my $sanecc = 0;

# Generate a Samba4 parser for an IDL fragment and run it with a specified 
# piece of code to check whether the parser works as expected
sub test_samba4_ndr($$$)
{
	my ($name,$idl,$c) = @_;
	my $pidl = Parse::Pidl::IDL::parse_string("interface echo { $idl }; ", "<$name>");
	
	ok (defined($pidl), "($name) parse idl");
	my $header = Parse::Pidl::Samba4::Header::Parse($pidl);
	ok(defined($header), "($name) generate generic header");
	my $pndr = Parse::Pidl::NDR::Parse($pidl);
	ok(defined($pndr), "($name) generate NDR tree");
	my ($ndrheader,$ndrparser) = Parse::Pidl::Samba4::NDR::Parser::Parse($pndr, "foo");
	ok(defined($ndrparser), "($name) generate NDR parser");
	ok(defined($ndrheader), "($name) generate NDR header");

SKIP: {

	my $insamba = -f "include/includes.h";
	my $link = $insamba && 0; # FIXME

	skip "no samba environment available, skipping compilation", 3 
		if not $insamba;

	skip "no sane C compiler, skipping compilation", 3
		if not $sanecc;

	my $outfile = "test-$name";

	#my $cflags = $ENV{CFLAGS};
	my $cflags = "-Iinclude -Ilib -I.";

	if ($insamba and $link) {
		open CC, "|cc -x c -o $outfile $cflags -";
	} elsif ($insamba) {
			open CC, "|cc -x c -c -o $outfile $cflags -";
	}
	print CC "#include \"includes.h\"\n";
	print CC $header;
	print CC $ndrheader;
	print CC $ndrparser;
	print CC "int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx = talloc_init(NULL);
	
	$c
 
	talloc_free(mem_ctx);
	
	return 0; }\n";
	close CC;

	ok(-f $outfile, "($name) compile");

	unless ($link) {
		skip "no shared libraries of Samba available yet, can't run test", 2;
		unlink($outfile);
	}

	ok(system($outfile), "($name) run");

	ok(unlink($outfile), "($name) remove");

	}
}

my $outfile = "test"; # FIXME: Somewhat more unique name

# Test whether CC is sane. The real 'fix' here would be using the 
# Samba build system, but unfortunately, we have no way of hooking into that 
# yet so we're running CC directly for now
$sanecc = 1 if system('echo "main() {}"'." | cc -I. -x c -c - -o $outfile") == 0;

1;
