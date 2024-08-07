/* packet-dcerpc-rs_unix.c
 *
 * Routines for dcerpc Unix ops
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz security/idl/rs_unix.idl
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include "packet-dcerpc.h"

void proto_register_rs_unix (void);
void proto_reg_handoff_rs_unix (void);

static int proto_rs_unix;
static int hf_rs_unix_opnum;

static int ett_rs_unix;


static e_guid_t uuid_rs_unix = { 0x361993c0, 0xb000, 0x0000, { 0x0d, 0x00, 0x00, 0x87, 0x84, 0x00, 0x00, 0x00 } };
static uint16_t ver_rs_unix = 1;


static const dcerpc_sub_dissector rs_unix_dissectors[] = {
	{ 0, "getpwents", NULL, NULL },
	{ 0, NULL, NULL, NULL },
};

void
proto_register_rs_unix (void)
{
	static hf_register_info hf[] = {
		{ &hf_rs_unix_opnum,
		  { "Operation", "rs_unix.opnum", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }}
	};

	static int *ett[] = {
		&ett_rs_unix,
	};
	proto_rs_unix = proto_register_protocol ("DCE/RPC RS_UNIX", "RS_UNIX", "rs_unix");
	proto_register_field_array (proto_rs_unix, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rs_unix (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_rs_unix, ett_rs_unix, &uuid_rs_unix, ver_rs_unix, rs_unix_dissectors, hf_rs_unix_opnum);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
