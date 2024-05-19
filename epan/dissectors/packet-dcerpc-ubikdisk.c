/* packet-dcerpc-ubikdisk.c
 *
 * Routines for DCE DFS UBIK Disk routines
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz file/ncsubik/ubikdisk_proc.idl
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

void proto_register_ubikdisk (void);
void proto_reg_handoff_ubikdisk (void);

static int proto_ubikdisk;
static int hf_ubikdisk_opnum;


static gint ett_ubikdisk;


static e_guid_t uuid_ubikdisk = { 0x4d37f2dd, 0xed43, 0x0002, { 0x02, 0xc0, 0x37, 0xcf, 0x1e, 0x00, 0x00, 0x00 } };
static guint16  ver_ubikdisk = 4;


static const dcerpc_sub_dissector ubikdisk_dissectors[] = {
	{  0, "Begin", NULL, NULL},
	{  1, "Commit", NULL, NULL},
	{  2, "Lock", NULL, NULL},
	{  3, "Write", NULL, NULL},
	{  4, "GetVersion", NULL, NULL},
	{  5, "GetFile", NULL, NULL},
	{  6, "SendFile", NULL, NULL},
	{  7, "Abort", NULL, NULL},
	{  8, "ReleaseLocks", NULL, NULL},
	{  9, "Truncate", NULL, NULL},
	{ 10, "Probe", NULL, NULL},
	{ 11, "GetServerInterfaces", NULL, NULL},
	{ 12, "BulkUpdate", NULL, NULL},
	{ 0, NULL, NULL, NULL }
};

void
proto_register_ubikdisk (void)
{
	static hf_register_info hf[] = {
	  { &hf_ubikdisk_opnum,
	    { "Operation", "ubikdisk.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_ubikdisk,
	};
	proto_ubikdisk = proto_register_protocol ("DCE DFS FLDB UBIK TRANSFER", "UBIKDISK", "ubikdisk");
	proto_register_field_array (proto_ubikdisk, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_ubikdisk (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_ubikdisk, ett_ubikdisk, &uuid_ubikdisk, ver_ubikdisk, ubikdisk_dissectors, hf_ubikdisk_opnum);
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
