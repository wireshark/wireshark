#!/usr/bin/perl
# Simple tests for pidl's handling of ref pointers, based
# on tridge's ref_notes.txt
# (C) 2005 Jelmer Vernooij <jelmer@samba.org>.
# Published under the GNU General Public License.
use strict;

use Parse::Pidl::Test;

my %settings = Parse::Pidl::Test::GetSettings(@ARGV);
$settings{'IDL-Arguments'} = ['--quiet', '--parse', '--parser=ndr_test.c', '--header=ndr_test.h'];
$settings{'IncludeFiles'} = ['ndr_test.h'];
$settings{'ExtraFiles'} = ['ndr_test.c'];

Parse::Pidl::Test::test_idl("noptr-push", \%settings, 
'	typedef struct {
		uint16 x;
	} xstruct;

	[public] uint16 echo_TestRef([in] xstruct foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	uint16_t v = 13;
	struct echo_TestRef r;
	r.in.foo.x = v; 

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, NDR_IN, &r))) {
		fprintf(stderr, "push failed\n");
		return 1;
	}

	if (ndr->offset != 2) {
		fprintf(stderr, "Offset(%d) != 2\n", ndr->offset);
		return 2;
	}

	if (ndr->data[0] != 13 || ndr->data[1] != 0) {
		fprintf(stderr, "Data incorrect\n");
		return 3;
	}
');

Parse::Pidl::Test::test_idl("ptr-embedded-push", \%settings,
'   typedef struct {
		uint16 *x;
	} xstruct;

	[public] uint16 echo_TestRef([in] xstruct foo);
',
'
	uint16_t v = 13;
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo.x = &v; 

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;

	if (ndr->offset != 6)
		return 2;

	if (ndr->data[0] == 0 && ndr->data[1] == 0 && 
	    ndr->data[2] == 0 && ndr->data[3] == 0)
		return 3;

	if (ndr->data[4] != 13 || ndr->data[5] != 0)
		return 4;
');

Parse::Pidl::Test::test_idl("ptr-embedded-push-null", \%settings,
'   typedef struct {
		uint16 *x;
	} xstruct;

	[public] uint16 echo_TestRef([in] xstruct foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo.x = NULL; 

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;

	if (ndr->offset != 4)
		return 2;

	if (ndr->data[0] != 0 || ndr->data[1] != 0 || 
	    ndr->data[2] != 0 || ndr->data[3] != 0)
		return 3;
');

Parse::Pidl::Test::test_idl("refptr-embedded-push", \%settings,
'
	typedef struct {
		[ref] uint16 *x;
	} xstruct;

	[public] uint16 echo_TestRef([in] xstruct foo);
',
'
	uint16_t v = 13;
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo.x = &v; 

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;

	if (ndr->offset != 6)
		return 2;

	if (ndr->data[0] == 0 && ndr->data[1] == 0 && 
	    ndr->data[2] == 0 && ndr->data[3] == 0)
		return 3;

	if (ndr->data[4] != 13 || ndr->data[5] != 0)
		return 4;
');

Parse::Pidl::Test::test_idl("refptr-embedded-push-null", \%settings,
'
	typedef struct {
		[ref] uint16 *x;
	} xstruct;

	[public] uint16 echo_TestRef([in] xstruct foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo.x = NULL; 

	if (NT_STATUS_IS_OK(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;
	/* Windows gives [client runtime error 0x6f4] */
');

Parse::Pidl::Test::test_idl("ptr-top-push", \%settings,
'
	typedef struct {
		uint16 x;
	} xstruct;

	[public] uint16 echo_TestRef([in] xstruct *foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	struct xstruct s;
	s.x = 13;
	r.in.foo = &s;

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;

	if (ndr->offset != 2)
		return 2;

	if (ndr->data[0] != 13 || ndr->data[1] != 0)
		return 3;
');

Parse::Pidl::Test::test_idl("ptr-top-push-null", \%settings,
'
	typedef struct {
		uint16 x;
	} xstruct;

	[public] uint16 echo_TestRef([in] xstruct *foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo = NULL;

	if (NT_STATUS_IS_OK(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;

	/* Windows gives [client runtime error 0x6f4] */
');


Parse::Pidl::Test::test_idl("refptr-top-push", \%settings,
'
	typedef struct {
		uint16 x;
	} xstruct;

	[public] uint16 echo_TestRef([in,ref] xstruct *foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	struct xstruct s;
	s.x = 13;
	r.in.foo = &s;

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;

	if (ndr->offset != 2)
		return 2;

	if (ndr->data[0] != 13 || ndr->data[1] != 0)
		return 3;
');

Parse::Pidl::Test::test_idl("refptr-top-push-null", \%settings,
'
	typedef struct {
		uint16 x;
	} xstruct;

	[public] uint16 echo_TestRef([in,ref] xstruct *foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo = NULL;

	if (NT_STATUS_IS_OK(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;

	/* Windows gives [client runtime error 0x6f4] */
');


Parse::Pidl::Test::test_idl("uniqueptr-top-push", \%settings,
'	typedef struct {
		uint16 x;
	} xstruct;

	[public] uint16 echo_TestRef([in,unique] xstruct *foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	struct xstruct s;
	s.x = 13;
	r.in.foo = &s;

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;

	if (ndr->offset != 6)
		return 2;

	if (ndr->data[0] == 0 && ndr->data[1] == 0 && 
	    ndr->data[2] == 0 && ndr->data[3] == 0)
		return 3;

	if (ndr->data[4] != 13 || ndr->data[5] != 0)
		return 4;
');

Parse::Pidl::Test::test_idl("uniqueptr-top-push-null", \%settings,
'	typedef struct {
		uint16 x;
	} xstruct;

	[public] uint16 echo_TestRef([in,unique] xstruct *foo);
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo = NULL;

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;

	if (ndr->offset != 4)
		return 2;

	if (ndr->data[0] != 0 || ndr->data[1] != 0 || 
	    ndr->data[2] != 0 || ndr->data[3] != 0)
		return 3;
');


Parse::Pidl::Test::test_idl("ptr-top-out-pull", \%settings,
'
	typedef struct {
		uint16 x;
	} xstruct;

	[public] void echo_TestRef([out] xstruct *foo);
',
'
	uint8_t data[] = { 0x0D, 0x00 };
	DATA_BLOB b = { data, 2 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct xstruct s;
	struct echo_TestRef r;

	r.out.foo = &s;

	if (NT_STATUS_IS_ERR(ndr_pull_echo_TestRef(ndr, NDR_OUT, &r)))
		return 1;

	if (!r.out.foo)
		return 2;

	if (r.out.foo->x != 13)
		return 3;
');	

Parse::Pidl::Test::test_idl("ptr-top-out-pull-null", \%settings,
'
	typedef struct {
		uint16 x;
	} xstruct;

	[public] void echo_TestRef([out] xstruct *foo);
',
'
	uint8_t data[] = { 0x0D, 0x00 };
	DATA_BLOB b = { data, 2 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct echo_TestRef r;

	r.out.foo = NULL;

	if (NT_STATUS_IS_OK(ndr_pull_echo_TestRef(ndr, NDR_OUT, &r)))
		return 1;
	
	/* Windows gives [client runtime error 0x6f4] */
');


Parse::Pidl::Test::test_idl("refptr-top-out-pull", \%settings,
'
	typedef struct {
		uint16 x;
	} xstruct;

	[public] void echo_TestRef([out,ref] xstruct *foo);
',
'
	uint8_t data[] = { 0x0D, 0x00 };
	DATA_BLOB b = { data, 2 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct xstruct s;
	struct echo_TestRef r;

	r.out.foo = &s;

	if (NT_STATUS_IS_ERR(ndr_pull_echo_TestRef(ndr, NDR_OUT, &r)))
		return 1;

	if (!r.out.foo)
		return 2;

	if (r.out.foo->x != 13)
		return 3;
');	

Parse::Pidl::Test::test_idl("refptr-top-out-pull-null", \%settings,
'
	typedef struct {
		uint16 x;
	} xstruct;

	[public] void echo_TestRef([out,ref] xstruct *foo);
',
'
	uint8_t data[] = { 0x0D, 0x00 };
	DATA_BLOB b = { data, 2 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL);
	struct echo_TestRef r;

	r.out.foo = NULL;

	if (NT_STATUS_IS_OK(ndr_pull_echo_TestRef(ndr, NDR_OUT, &r)))
		return 1;
	
	/* Windows gives [client runtime error 0x6f4] */
');


Parse::Pidl::Test::test_idl("ptr-top-push-double", \%settings,
'
	[public] void echo_TestRef([in] uint16 **foo);
',
'	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	uint16_t v = 13;
	uint16_t *pv = &v;
	r.in.foo = &pv;

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;

	if (ndr->offset != 6)
		return 2;

	if (ndr->data[0] == 0 && ndr->data[1] == 0 && 
	    ndr->data[2] == 0 && ndr->data[3] == 0)
		return 3;

	if (ndr->data[4] != 0x0D || ndr->data[5] != 0x00)
		return 4;
');

Parse::Pidl::Test::test_idl("ptr-top-push-double-sndnull", \%settings,
'
	[public] void echo_TestRef([in] uint16 **foo);
',
'	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	uint16_t *pv = NULL;
	r.in.foo = &pv;

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;

	if (ndr->offset != 4)
		return 2;

	if (ndr->data[0] != 0 || ndr->data[1] != 0 || 
	    ndr->data[2] != 0 || ndr->data[3] != 0)
		return 3;
');

Parse::Pidl::Test::test_idl("ptr-top-push-double-fstnull", \%settings,
'
	[public] void echo_TestRef([in] uint16 **foo);
',
'	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo = NULL;

	if (NT_STATUS_IS_OK(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;
	
	/* Windows gives [client runtime error 0x6f4] */

');


Parse::Pidl::Test::test_idl("refptr-top-push-double", \%settings,
'
	[public] void echo_TestRef([in,ref] uint16 **foo);
',
'	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	uint16_t v = 13;
	uint16_t *pv = &v;
	r.in.foo = &pv;

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;

	if (ndr->offset != 6)
		return 2;

	if (ndr->data[0] == 0 && ndr->data[1] == 0 && 
	    ndr->data[2] == 0 && ndr->data[3] == 0)
		return 3;

	if (ndr->data[4] != 0x0D || ndr->data[5] != 0x00)
		return 4;
');

Parse::Pidl::Test::test_idl("refptr-top-push-double-sndnull", \%settings,
'
	[public] void echo_TestRef([in,ref] uint16 **foo);
',
'	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	uint16_t *pv = NULL;
	r.in.foo = &pv;

	if (NT_STATUS_IS_ERR(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;

	if (ndr->offset != 4)
		return 2;

	if (ndr->data[0] != 0 || ndr->data[1] != 0 || 
	    ndr->data[2] != 0 || ndr->data[3] != 0)
		return 3;
');

Parse::Pidl::Test::test_idl("refptr-top-push-double-fstnull", \%settings,
'
	[public] void echo_TestRef([in,ref] uint16 **foo);
',
'	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	r.in.foo = NULL;

	if (NT_STATUS_IS_OK(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;
	
	/* Windows gives [client runtime error 0x6f4] */

');

Parse::Pidl::Test::test_idl("ignore-ptr", \%settings,
'
	[public] void echo_TestRef([in,ignore] uint16 *foo, [in] uint16 *bar);
',
'	struct ndr_push *ndr = ndr_push_init();
	struct echo_TestRef r;
	uint16_t v = 10;
	r.in.foo = &v; 
	r.in.bar = &v;

	if (NT_STATUS_IS_OK(ndr_push_echo_TestRef(ndr, NDR_IN, &r)))
		return 1;

	if (ndr->offset != 4)
		return 2;
');
