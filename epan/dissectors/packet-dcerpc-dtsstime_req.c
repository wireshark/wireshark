/* packet-dcerpc-dtsstime_req.c
 * Routines for Time services stuff.
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/time.tar.gz time/service/dtsstime_req.idl
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

void proto_register_dtsstime_req (void);
void proto_reg_handoff_dtsstime_req (void);

static int proto_dtsstime_req = -1;
static int hf_dtsstime_req_opnum = -1;


static gint ett_dtsstime_req = -1;


static e_guid_t uuid_dtsstime_req = { 0x019ee420, 0x682d, 0x11c9, { 0xa6, 0x07, 0x08, 0x00, 0x2b, 0x0d, 0xea, 0x7a } };
static guint16  ver_dtsstime_req = 1;


static dcerpc_sub_dissector dtsstime_req_dissectors[] = {
	{ 0, "ClerkRequestTime",  NULL, NULL},
	{ 1, "ServerRequestTime", NULL, NULL},
	{ 0, NULL, NULL, NULL }
};

void
proto_register_dtsstime_req (void)
{
	static hf_register_info hf[] = {
	{ &hf_dtsstime_req_opnum,
		{ "Operation", "dtsstime_req.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_dtsstime_req,
	};
	proto_dtsstime_req = proto_register_protocol ("DCE Distributed Time Service Local Server", "DTSSTIME_REQ", "dtsstime_req");
	proto_register_field_array (proto_dtsstime_req, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_dtsstime_req (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_dtsstime_req, ett_dtsstime_req, &uuid_dtsstime_req, ver_dtsstime_req, dtsstime_req_dissectors, hf_dtsstime_req_opnum);
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
