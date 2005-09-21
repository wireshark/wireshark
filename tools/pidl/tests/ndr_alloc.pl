#!/usr/bin/perl
# NDR allocation tests
# (C) 2005 Jelmer Vernooij. Published under the GNU GPL
use strict;

use Parse::Pidl::Test;

my %settings = Parse::Pidl::Test::GetSettings(@ARGV);
$settings{'IDL-Arguments'} = ['--quiet', '--parse', '--parser=ndr_test.c', '--header=ndr_test.h'];
$settings{'IncludeFiles'} = ['ndr_test.h'];
$settings{'ExtraFiles'} = ['ndr_test.c'];

# Check that an outgoing scalar pointer is allocated correctly

Parse::Pidl::Test::test_idl("alloc-scalar", \%settings, 
'	
	typedef struct {
		uint8 *x;
	} bla;
	
	[public] void TestAlloc([in] bla foo);
','
	uint8_t data[] = { 0xde, 0xad, 0xbe, 0xef, 0x03 };
	DATA_BLOB b = { data, 5 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct TestAlloc r;

	if (NT_STATUS_IS_ERR(ndr_pull_TestAlloc(ndr, NDR_IN, &r))) 
		return 1;

	if (r.in.foo.x == NULL)
		return 2;
	
	if (*r.in.foo.x != 0x03)
		return 3;
'
);

# Check that an outgoing buffer pointer is allocated correctly
Parse::Pidl::Test::test_idl("alloc-buffer", \%settings, 
'	
	typedef struct {
		uint8 data;
	} blie;

	typedef struct {
		blie *x;
	} bla;
	
	[public] void TestAlloc([in] bla foo);
','
	uint8_t data[] = { 0xde, 0xad, 0xbe, 0xef, 0x03 };
	DATA_BLOB b = { data, 5 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct TestAlloc r;

	if (NT_STATUS_IS_ERR(ndr_pull_TestAlloc(ndr, NDR_IN, &r))) 
		return 1;

	if (r.in.foo.x == NULL)
		return 2;
	
	if (r.in.foo.x->data != 0x03)
		return 3;
'
);

# Check that ref pointers aren't allocated by default
Parse::Pidl::Test::test_idl("ref-noalloc-null", \%settings, 
'	
	[public] void TestAlloc([in,ref] uint8 *t);
','
	uint8_t data[] = { 0x03 };
	DATA_BLOB b = { data, 1 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct TestAlloc r;
	r.in.t = NULL;

	if (NT_STATUS_IS_OK(ndr_pull_TestAlloc(ndr, NDR_IN, &r))) 
		return 1;
'
);

# Check that ref pointers aren't allocated by default
Parse::Pidl::Test::test_idl("ref-noalloc", \%settings, 
'	
	[public] void TestAlloc([in,ref] uint8 *t);
','
	uint8_t data[] = { 0x03 };
	DATA_BLOB b = { data, 1 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct TestAlloc r;
	uint8_t x;
	r.in.t = &x;

	if (NT_STATUS_IS_ERR(ndr_pull_TestAlloc(ndr, NDR_IN, &r))) 
		return 1;

	if (*r.in.t != 0x03)
		return 2;
'
);

# Check that an outgoing ref pointer is allocated correctly
Parse::Pidl::Test::test_idl("ref-alloc", \%settings, 
'	
	[public] void TestAlloc([in,ref] uint8 *t);
','
	uint8_t data[] = { 0x03 };
	DATA_BLOB b = { data, 1 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct TestAlloc r;
	ndr->flags |= LIBNDR_FLAG_REF_ALLOC;
	r.in.t = NULL;

	if (NT_STATUS_IS_ERR(ndr_pull_TestAlloc(ndr, NDR_IN, &r))) 
		return 1;

	if (r.in.t == NULL)
		return 2;

	if (*r.in.t != 0x03)
		return 3;
'
);
