/* packet-dcerpc-butc.c
 * Routines for butc dissection
 * Copyright 2002, Jaime Fournier <jafour1@yahoo.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz bubasics/butc.idl
 *      
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"

static int proto_butc = -1;
static int hf_butc_opnum = -1;


static gint ett_butc = -1;


static e_uuid_t uuid_butc = { 0x1d193c08, 0x000b, 0x11ca, { 0xba, 0x1d, 0x02, 0x60, 0x8c, 0x2e, 0xa9, 0x6e } };
static guint16  ver_butc = 4;


#define TC_DEFAULT_STACK_SIZE  (150*1024) /* stack size for tc threads */
#define TC_MAXGENNAMELEN  512      /* length of generic name */
#define TC_MAXDUMPPATH    256      /* dump path names*/
#define TC_MAXNAMELEN     128      /* name length */
#define TC_MAXFORMATLEN   100      /*size of the format statement */
#define TC_MAXHOSTLEN     128      /*for server/machine names */
#define TC_MAXTAPELEN     256      /*max tape name allowed */
#define TC_STAT_DONE      1        /* all done */
#define TC_STAT_OPRWAIT   2        /* waiting for user interaction */
#define TC_STAT_DUMP      4        /* true if dump, false if restore */
#define TC_STAT_ABORTED   8        /* the operation was aborted */
#define TC_STAT_ERROR     16       /* error ocuured in the operation */
#define TSK_STAT_FIRST    0x1      /* get id of first task */
#define TSK_STAT_END      0x2     /* no more tasks */
#define TSK_STAT_NOTFOUND 0x4      /* couldn't find task id requested */

#define TCOP_NONE             0
#define TCOP_READLABEL        1
#define TCOP_LABELTAPE        2
#define TCOP_DUMP             3
#define TCOP_RESTORE          4
#define TCOP_SCANTAPE         5
#define TCOP_SAVEDB           6
#define TCOP_RESTOREDB        7
#define TCOP_STATUS           8
#define TCOP_SPARE            9


static dcerpc_sub_dissector butc_dissectors[] = {
	{ 0, "PerformDump", NULL, NULL},
	{ 1, "PerformRestore", NULL, NULL},
	{ 2, "AbortDump", NULL, NULL},
	{ 3, "LabelTape", NULL, NULL},
	{ 4, "ReadLabel", NULL, NULL},
	{ 5, "ScanDumps", NULL, NULL},
	{ 6, "TCInfo", NULL, NULL},
	{ 7, "SaveDb", NULL, NULL},
	{ 8, "RestoreDb", NULL, NULL},
	{ 9, "EndStatus", NULL, NULL},
	{ 10, "GetStatus", NULL, NULL},
	{ 11, "RequestAbort", NULL, NULL},
	{ 12, "ScanStatus", NULL, NULL},
	{ 13, "GetServerInterfaces", NULL, NULL},
	{ 0, NULL, NULL, NULL }
};

void
proto_register_butc (void)
{
	static hf_register_info hf[] = {
	{ &hf_butc_opnum,
		{ "Operation", "butc.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "Operation", HFILL }},
	};

	static gint *ett[] = {
		&ett_butc,
	};
	proto_butc = proto_register_protocol ("DCE/RPC BUTC", "BUTC", "butc");
	proto_register_field_array (proto_butc, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_butc (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_butc, ett_butc, &uuid_butc, ver_butc, butc_dissectors, hf_butc_opnum);
}
