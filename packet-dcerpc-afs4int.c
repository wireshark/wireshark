/* packet-dcerpc-afs4int.c
 *
 * Routines for dcerpc Afs4Int dissection
 * Copyright 2002, Jaime Fournier <jafour1@yahoo.com> 
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz file/fsint/afs4int.idl
 *
 * $Id: packet-dcerpc-afs4int.c,v 1.1 2002/09/13 10:36:55 sahlberg Exp $
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


static int proto_afs4int = -1;
static int hf_afs4int_opnum = -1;


static gint ett_afs4int = -1;


static e_uuid_t uuid_afs4int = { 0x4d37f2dd, 0xed93, 0x0000, { 0x02, 0xc0, 0x37, 0xcf, 0x1e, 0x00, 0x00, 0x00 } };
static guint16  ver_afs4int = 4;



static dcerpc_sub_dissector afs4int_dissectors[] = {
	{  0, "SetContext", NULL, NULL },
	{  1, "LookupRoot", NULL, NULL },
	{  2, "FetchData", NULL, NULL },
	{  3, "FetchACL", NULL, NULL },
	{  4, "FetchStatus", NULL, NULL },
	{  5, "StoreData", NULL, NULL },
	{  6, "StoreACL", NULL, NULL },
	{  7, "StoreStatus", NULL, NULL },
	{  8, "RemoveFile", NULL, NULL },
	{  9, "CreateFile", NULL, NULL },
	{ 10, "Rename", NULL, NULL },
	{ 11, "Symlink", NULL, NULL },
	{ 12, "HardLink", NULL, NULL },
	{ 13, "MakeDir", NULL, NULL },
	{ 14, "RemoveDir", NULL, NULL },
	{ 15, "Readdir", NULL, NULL },
	{ 16, "Lookup", NULL, NULL },
	{ 17, "GetToken", NULL, NULL },
	{ 18, "ReleaseTokens", NULL, NULL },
	{ 19, "GetTime", NULL, NULL },
	{ 20, "MakeMountPoint", NULL, NULL },
	{ 21, "GetStatistics", NULL, NULL },
	{ 22, "BulkFetchVV", NULL, NULL },
	{ 23, "BulkKeepAlive", NULL, NULL },
	{ 24, "ProcessQuota", NULL, NULL },
	{ 25, "GetServerInterfaces", NULL, NULL },
	{ 26, "SetParams", NULL, NULL },
	{ 27, "BulkFetchStatus", NULL, NULL },
	{  0, NULL, NULL, NULL }
};


static const value_string afs4int_opnum_vals[] = {
	{  0, "SetContext" },
	{  1, "LookupRoot" },
	{  2, "FetchData" },
	{  3, "FetchACL" },
	{  4, "FetchStatus" },
	{  5, "StoreData" },
	{  6, "StoreACL" },
	{  7, "StoreStatus" },
	{  8, "RemoveFile" },
	{  9, "CreateFile" },
	{ 10, "Rename" },
	{ 11, "Symlink" },
	{ 12, "HardLink" },
	{ 13, "MakeDir" },
	{ 14, "RemoveDir" },
	{ 15, "Readdir" },
	{ 16, "Lookup" },
	{ 17, "GetToken" },
	{ 18, "ReleaseTokens" },
	{ 19, "GetTime" },
	{ 20, "MakeMountPoint" },
	{ 21, "GetStatistics" },
	{ 22, "BulkFetchVV" },
	{ 23, "BulkKeepAlive" },
	{ 24, "ProcessQuota" },
	{ 25, "GetServerInterfaces" },
	{ 26, "SetParams" },
	{ 27, "BulkFetchStatus" },
	{  0, NULL }
};



void
proto_register_afs4int (void)
{
	static hf_register_info hf[] = {
	  { &hf_afs4int_opnum,
	    { "Operation", "afs4int.opnum", FT_UINT16, BASE_DEC,
	      VALS(afs4int_opnum_vals), 0x0, "Operation", HFILL }}
	};  


	static gint *ett[] = {
		&ett_afs4int,
	};
	proto_afs4int = proto_register_protocol ("DCE DFS Calls", "DCE_DFS", "dce_dfs");
	proto_register_field_array (proto_afs4int, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));

}
void
proto_reg_handoff_afs4int (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_afs4int, ett_afs4int, &uuid_afs4int, ver_afs4int, afs4int_dissectors, hf_afs4int_opnum);
}

