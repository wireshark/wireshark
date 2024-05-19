/* packet-dcerpc-rs_repadm.c
 *
 * Routines for dcerpc Registry server administration operations.
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz  security/idl/rs_repadm.idl
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

void proto_register_rs_repadm (void);
void proto_reg_handoff_rs_repadm (void);

static int proto_rs_repadm;
static int hf_rs_repadm_opnum;


static gint ett_rs_repadm;


static e_guid_t uuid_rs_repadm = { 0x5b8c2fa8, 0xb60b, 0x11c9, { 0xbe, 0x0f, 0x08, 0x00, 0x1e, 0x01, 0x8f, 0xa0 } };
static guint16  ver_rs_repadm = 1;




static const dcerpc_sub_dissector rs_repadm_dissectors[] = {
	{ 0, "stop",              NULL, NULL},
	{ 1, "maint",             NULL, NULL},
	{ 2, "mkey",              NULL, NULL},
	{ 3, "info",              NULL, NULL},
	{ 4, "info_full",         NULL, NULL},
	{ 5, "destroy",           NULL, NULL},
	{ 6, "init_replica",      NULL, NULL},
	{ 7, "change_master",     NULL, NULL},
	{ 8, "become_master",     NULL, NULL},
	{ 9, "become_slave",      NULL, NULL},
	{ 10, "set_sw_rev",       NULL, NULL},
	{ 11, "get_sw_vers_info", NULL, NULL},
	{ 0, NULL, NULL, NULL }
};


void
proto_register_rs_repadm (void)
{
	static hf_register_info hf[] = {
	{ &hf_rs_repadm_opnum,
		{ "Operation", "rs_repadm.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_rs_repadm,
	};
	proto_rs_repadm = proto_register_protocol ("Registry server administration operations.", "RS_REPADM", "rs_repadm");
	proto_register_field_array (proto_rs_repadm, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rs_repadm (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_rs_repadm, ett_rs_repadm, &uuid_rs_repadm, ver_rs_repadm, rs_repadm_dissectors, hf_rs_repadm_opnum);
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
