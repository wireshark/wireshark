/* packet-dcerpc-roverride.c
 *
 * Routines for Remote Override Interface
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz security/idl/roverride.idl
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

void proto_register_roverride (void);
void proto_reg_handoff_roverride (void);

static int proto_roverride;
static int hf_roverride_opnum;


static int ett_roverride;


static e_guid_t uuid_roverride = { 0x5d978990, 0x4851, 0x11ca, { 0x99, 0x37, 0x08, 0x00, 0x1e, 0x03, 0x94, 0x48 } };
static uint16_t ver_roverride = 1;


static const dcerpc_sub_dissector roverride_dissectors[] = {
	{ 0, "roverride_get_login_info",        NULL, NULL},
	{ 1, "roverride_check_passwd",          NULL, NULL},
	{ 2, "roverride_is_passwd_overridden",  NULL, NULL},
	{ 3, "roverride_get_by_unix_num",       NULL, NULL},
	{ 4, "roverride_get_group_info",        NULL, NULL},
	{ 5, "roverride_check_group_passwd",    NULL, NULL},
	{ 6, "roverride_is_grp_pwd_overridden", NULL, NULL},
	{ 0, NULL, NULL, NULL }
};

void
proto_register_roverride (void)
{
	static hf_register_info hf[] = {
		{ &hf_roverride_opnum,
		  { "Operation", "roverride.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_roverride,
	};
	proto_roverride = proto_register_protocol ("Remote Override interface", "roverride", "roverride");
	proto_register_field_array (proto_roverride, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_roverride (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_roverride, ett_roverride, &uuid_roverride, ver_roverride, roverride_dissectors, hf_roverride_opnum);
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
