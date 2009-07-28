#!/usr/bin/perl
# NDR represent_as() / transmit_as() tests
# (C) 2006 Jelmer Vernooij. Published under the GNU GPL
use strict;

use Test::More tests => 2 * 8;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util qw(test_samba4_ndr);

test_samba4_ndr('represent_as-simple', 
'
	void bla([in,represent_as(uint32)] uint8 x);
',
'
	uint8_t expected[] = { 0x0D };
	DATA_BLOB in_blob = { expected, 1 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&in_blob, NULL, NULL);
	struct bla r;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_pull_bla(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	if (r.in.x != 13)
		return 2;
',
'
enum ndr_err_code ndr_uint8_to_uint32(uint8_t from, uint32_t *to)
{
	*to = from;
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_uint32_to_uint8(uint32_t from, uint8_t *to)
{
	*to = from;
	return NDR_ERR_SUCCESS;
}
'
);

test_samba4_ndr('transmit_as-simple', 
'
	void bla([in,transmit_as(uint32)] uint8 x);
',
'
	uint8_t expected[] = { 0x0D };
	DATA_BLOB in_blob = { expected, 1 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&in_blob, NULL, NULL);
	struct bla r;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_pull_bla(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	if (r.in.x != 13)
		return 2;
',
'
enum ndr_err_code ndr_uint8_to_uint32(uint8_t from, uint32_t *to)
{
	*to = from;
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_uint32_to_uint8(uint32_t from, uint8_t *to)
{
	*to = from;
	return NDR_ERR_SUCCESS;
}
'
);
