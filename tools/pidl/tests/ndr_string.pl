#!/usr/bin/perl
# String tests for pidl
# (C) 2005 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;

use Test::More tests => 6 * 8;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util qw(test_samba4_ndr);

test_samba4_ndr("string-pull-empty", 
' [public] void TestString([in,flag(STR_ASCII|LIBNDR_FLAG_STR_SIZE4)] string data);',
'
	uint8_t data[] = { 0x00, 0x00, 0x00, 0x00 };
	DATA_BLOB b = { data, 4 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct TestString r;
	r.in.data = NULL;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_pull_TestString(ndr, NDR_IN, &r)))
		return 1;
	
	if (r.in.data == NULL)
		return 2;

	if (r.in.data[0] != 0)
		return 3;
');

test_samba4_ndr("string-ascii-pull", 
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

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_pull_TestString(ndr, NDR_IN, &r)))
		return 1;
	
	if (r.in.data == NULL)
		return 2;

	if (strncmp(r.in.data, "foo", 3) != 0)
		return 3;

	if (r.in.data[4] != 0)
		return 4;
');

test_samba4_ndr("string-wchar-fixed-array-01",
'
	typedef struct {
		uint32 l1;
		[string,charset(UTF16)] uint16 str[6];
		uint32 l2;
	} TestStringStruct;

	[public] void TestString([in,ref] TestStringStruct *str);
',
'
	uint8_t data[] = { 0x01,  0x00, 0x00,  0x00,
			   0x00,  0x00, 0x00,  0x00,
			   0x04,  0x00, 0x00,  0x00,
			   \'f\', 0x00, \'o\', 0x00,
			   \'o\', 0x00, 0x00,  0x00,
			   0x02,  0x00, 0x00,  0x00
	};
	DATA_BLOB b = { data, sizeof(data) };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct TestString r;
	struct TestStringStruct str;
	r.in.str = &str;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_pull_TestString(ndr, NDR_IN, &r)))
		return 1;

	if (r.in.str == NULL)
		return 2;

	if (r.in.str->l1 != 0x00000001)
		return 3;

	if (strncmp(str.str, "foo", 3) != 0)
		return 4;

	if (r.in.str->str[4] != 0)
		return 5;

	if (r.in.str->l2 != 0x00000002)
		return 6;
');

test_samba4_ndr("string-wchar-fixed-array-02",
'
	typedef struct {
		uint32 l1;
		[string,charset(UTF16)] uint16 str[6];
		uint32 l2;
	} TestStringStruct;

	[public] void TestString([in,ref] TestStringStruct *str);
',
'
	uint8_t data[] = { 0x01,  0x00, 0x00,  0x00,
			   0x00,  0x00, 0x00,  0x00,
			   0x06,  0x00, 0x00,  0x00,
			   \'f\', 0x00, \'o\', 0x00,
			   \'o\', 0x00, \'b\', 0x00,
			   \'a\', 0x00, \'r\', 0x00,
			   0x00,  0x00, 0x00,  0x00,
			   0x02,  0x00, 0x00,  0x00
	};
	DATA_BLOB b = { data, sizeof(data) };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct TestString r;
	struct TestStringStruct str;
	r.in.str = &str;

	/* the string terminator is wrong */
	if (NDR_ERR_CODE_IS_SUCCESS(ndr_pull_TestString(ndr, NDR_IN, &r)))
		return 1;
');

test_samba4_ndr("string-wchar-fixed-array-03",
'
	typedef struct {
		uint32 l1;
		[string,charset(UTF16)] uint16 str[6];
		uint32 l2;
	} TestStringStruct;

	[public] void TestString([in,ref] TestStringStruct *str);
',
'
	uint8_t data[] = { 0x01,  0x00, 0x00,  0x00,
			   0x00,  0x00, 0x00,  0x00,
			   0x07,  0x00, 0x00,  0x00,
			   \'f\', 0x00, \'o\', 0x00,
			   \'o\', 0x00, \'b\', 0x00,
			   \'a\', 0x00, \'r\', 0x00,
			   0x00,  0x00, 0x00,  0x00,
			   0x02,  0x00, 0x00,  0x00
	};
	DATA_BLOB b = { data, sizeof(data) };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct TestString r;
	struct TestStringStruct str;
	r.in.str = &str;

	/* the length 0x07 is to large */
	if (NDR_ERR_CODE_IS_SUCCESS(ndr_pull_TestString(ndr, NDR_IN, &r)))
		return 1;
');

SKIP: {
	skip "doesn't seem to work yet", 8;

test_samba4_ndr("string-out", 
'
	[public] void TestString([out,string,charset(UNIX)] uint8 **data);
',
'
	uint8_t data[] = { 0x03, 0x00, 0x00, 0x00, 
					   \'f\', \'o\', \'o\', 0 };
	DATA_BLOB b = { data, 8 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct TestString r;
	char *str = NULL;
	r.out.data = &str;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_pull_TestString(ndr, NDR_IN, &r)))
		return 1;

	if (r.out.data == NULL)
		return 2;

	if (*r.out.data == NULL)
		return 3;

	if (strncmp(r.out.data, "foo", 3) != 0)
		return 4;

	if (r.out.data[4] != 0)
		return 5;
');
}
