# Some simple utility functions for pidl tests
# Copyright (C) 2005-2006 Jelmer Vernooij
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

# Generate a Samba4 parser for an IDL fragment and run it with a specified 
# piece of code to check whether the parser works as expected
sub test_samba4_ndr
{
	my ($name,$idl,$c,$extra) = @_;
	my $pidl = Parse::Pidl::IDL::parse_string("interface echo { $idl }; ", "<$name>");
	
	ok(defined($pidl), "($name) parse idl");
	my $header = Parse::Pidl::Samba4::Header::Parse($pidl);
	ok(defined($header), "($name) generate generic header");
	my $pndr = Parse::Pidl::NDR::Parse($pidl);
	ok(defined($pndr), "($name) generate NDR tree");
	my ($ndrheader,$ndrparser) = Parse::Pidl::Samba4::NDR::Parser::Parse($pndr, undef, undef);
	ok(defined($ndrparser), "($name) generate NDR parser");
	ok(defined($ndrheader), "($name) generate NDR header");

SKIP: {

	skip "no samba environment available, skipping compilation", 3 
		if (system("pkg-config --exists ndr") != 0);

	my $test_data_prefix = $ENV{TEST_DATA_PREFIX};

	my $outfile;
	if (defined($test_data_prefix)) {
		$outfile = "$test_data_prefix/test-$name";	
	} else {
		$outfile = "test-$name";
	}

	my $cflags = `pkg-config --libs --cflags ndr`;

	open CC, "|cc -x c - -o $outfile $cflags";
	print CC "#define uint_t unsigned int\n";
	print CC "#define _GNU_SOURCE\n";
	print CC "#include <stdint.h>\n";
	print CC "#include <stdlib.h>\n";
	print CC "#include <stdio.h>\n";
	print CC "#include <stdbool.h>\n";
	print CC "#include <stdarg.h>\n";
	print CC "#include <core.h>\n";
	print CC $header;
	print CC $ndrheader;
	print CC $extra if ($extra);
	print CC $ndrparser;
	print CC "int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx = talloc_init(NULL);
	
	$c
 
	talloc_free(mem_ctx);
	
	return 0; }\n";
	close CC;

	ok(-f $outfile, "($name) compile");

	my $ret = system("./$outfile", ()) >> 8;
	print "# return code: $ret\n" if ($ret != 0);

	ok($ret == 0, "($name) run");

	ok(unlink($outfile), "($name) remove");

	}
}

1;
