/* packet-dcerpc-rep_proc.c
 *
 * Routines for dcerpc Replica Server Call dissection
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tgz  file/fsint/rep_proc.idl
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

void proto_register_rep_proc (void);
void proto_reg_handoff_rep_proc (void);

static int proto_rep_proc;
static int hf_rep_proc_opnum;


static gint ett_rep_proc;


static e_guid_t uuid_rep_proc = { 0x4d37f2dd, 0xed43, 0x0005, { 0x02, 0xc0, 0x37, 0xcf, 0x1e, 0x00, 0x00, 0x00 } };
static guint16  ver_rep_proc = 4;


static const dcerpc_sub_dissector rep_proc_dissectors[] = {
	{ 0, "CheckReplicationConfig",    NULL, NULL },
	{ 1, "AllCheckReplicationConfig", NULL, NULL },
	{ 2, "KeepFilesAlive",            NULL , NULL},
	{ 3, "GetVolChangedFiles",        NULL, NULL },
	{ 4, "GetRepStatus",              NULL, NULL},
	{ 5, "GetRepServerStatus",        NULL, NULL},
	{ 6, "UpdateSelf",                NULL, NULL},
	{ 7, "Probe",                     NULL, NULL},
	{ 8, "GetOneRepStatus",           NULL, NULL },
	{ 9, "GetServerInterfaces",       NULL, NULL},
	{ 0, NULL, NULL, NULL }
};


void
proto_register_rep_proc (void)
{
	static hf_register_info hf[] = {
	  { &hf_rep_proc_opnum,
	    { "Operation", "rep_proc.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_rep_proc,
	};
	proto_rep_proc = proto_register_protocol ("DCE DFS Replication Server", "REP_PROC", "rep_proc");
	proto_register_field_array (proto_rep_proc, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rep_proc (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_rep_proc, ett_rep_proc, &uuid_rep_proc, ver_rep_proc, rep_proc_dissectors, hf_rep_proc_opnum);
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
