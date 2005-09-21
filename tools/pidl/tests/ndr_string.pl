#!/usr/bin/perl
# String tests for pidl
# (C) 2005 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;

use Parse::Pidl::Test;

my %settings = Parse::Pidl::Test::GetSettings(@ARGV);

$settings{'IDL-Arguments'} = ['--quiet', '--parse', '--parser=ndr_test.c', '--header=ndr_test.h'];
$settings{'IncludeFiles'} = ['ndr_test.h'];
$settings{'ExtraFiles'} = ['ndr_test.c'];

Parse::Pidl::Test::test_idl("string-pull-empty", \%settings,
' [public] void TestString([in,flag(STR_ASCII|LIBNDR_FLAG_STR_SIZE4)] string data);',
'
	uint8_t data[] = { 0x00, 0x00, 0x00, 0x00 };
	DATA_BLOB b = { data, 4 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct TestString r;
	r.in.data = NULL;

	if (NT_STATUS_IS_ERR(ndr_pull_TestString(ndr, NDR_IN, &r))) 
		return 1;
	
	if (r.in.data == NULL)
		return 2;

	if (r.in.data[0] != 0)
		return 3;
');

Parse::Pidl::Test::test_idl("string-ascii-pull", \%settings,
'
	[public] void TestString([in,flag(STR_ASCII|LIBNDR_FLAG_STR_SIZE4)] string data);
',
'
	uint8_t data[] = { 0x03, 0x00, 0x00, 0x00, 
					   \'f\', \'o\', \'o\', 0 };
	DATA_BLOB b = { data, 8 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct TestString r;
	r.in.data = NULL;

	if (NT_STATUS_IS_ERR(ndr_pull_TestString(ndr, NDR_IN, &r))) 
		return 1;
	
	if (r.in.data == NULL)
		return 2;

	if (strncmp(r.in.data, "foo", 3) != 0)
		return 3;

	if (r.in.data[4] != 0)
		return 4;
');
