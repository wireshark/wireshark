/* packet-9P.c
 * Routines for 9P dissection
 * Copyright 2005, Nils O. SelÃ¥sdal
 *
 * $Id: $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#define NINEPORT 564

/*Message types for 9P */
/*See man 5 intro on Plan9 - or;
	http://www.cs.bell-labs.com/sys/man/5/INDEX.html
*/
enum {
	TVERSION	= 100,
	RVERSION	= 101,
	TAUTH 		= 102,
	RAUTH 		= 103,
	TATTACH		= 104,
	RATTACH		= 105,
	TERROR		= 106,	/* Not used */
	RERROR		= 107,
	TFLUSH		= 108,
	RFLUSH		= 109,
	TWALK		= 110,
	RWALK		= 111,
	TOPEN = 112,
	ROPEN,
	TCREATE = 114,
	RCREATE,
	TREAD = 116,
	RREAD,
	TWRITE = 118,
	RWRITE,
	TCLUNK = 120,
	RCLUNK,
	TREMOVE = 122,
	RREMOVE,
	TSTAT = 124,
	RSTAT,
	TWSTAT = 126,
	RWSTAT
};

/* Initialize the protocol and registered fields */
static int proto_9P = -1;
static int hf_9P_msgsz = -1;
static int hf_9P_msgtype = -1;
static int hf_9P_tag = -1;
static int hf_9P_oldtag = -1;
static int hf_9P_parmsz = -1;
static int hf_9P_maxsize = -1;
static int hf_9P_fid = -1;
static int hf_9P_nqid = -1;
static int hf_9P_mode = -1;
static int hf_9P_iounit = -1;
static int hf_9P_count = -1;
static int hf_9P_offset = -1;
static int hf_9P_perm = -1;
static int hf_9P_qidtype = -1;
static int hf_9P_qidvers = -1;
static int hf_9P_qidpath = -1;
static int hf_9P_stattype = -1;
static int hf_9P_statmode = -1;
static int hf_9P_atime = -1;
static int hf_9P_mtime = -1;
static int hf_9P_length = -1;
static int hf_9P_dev = -1;
static int hf_9P_wname = -1;
static int hf_9P_version = -1;
static int hf_9P_afid = -1;
static int hf_9P_uname = -1;
static int hf_9P_aname = -1;
static int hf_9P_ename = -1;
static int hf_9P_name = -1;
static int hf_9P_filename = -1;
static int hf_9P_sdlen = -1;
static int hf_9P_uid = -1;
static int hf_9P_gid = -1;
static int hf_9P_muid = -1;
static int hf_9P_nwalk = -1;
static int hf_9P_newfid = -1;

/*handle for dissecting data in 9P msgs*/
static dissector_handle_t data_handle;

/* subtree pointers */
static gint ett_9P = -1;

/*9P Msg types to name mapping */
static const value_string ninep_msg_type[] = 
{	{TVERSION,	"Tversion"},
	{RVERSION,	"Rversion"},
	{TAUTH,		"Tauth"},
	{RAUTH,		"Rauth"},
	{TATTACH,	"Tattach"},
	{RATTACH,	"Rattach"},
	{RERROR,	"Rerror"},
	{TFLUSH,	"Tflush"},
	{RFLUSH,	"Rflush"},
	{TWALK, 	"Twalk"},
	{RWALK,		"Rwalk"},
	{TOPEN, 	"Topen"},
	{ROPEN,		"Ropen"},
	{TCREATE, 	"Tcreate"},
	{RCREATE,	"Rcreate"},
	{TREAD,		"Tread"},
	{RREAD,		"Rread"},
	{TWRITE, 	"Twrite"},
	{RWRITE,	"Rwrite"},
	{TCLUNK, 	"Tclunk"},
	{RCLUNK,	"Rclunk"},
	{TREMOVE, 	"Tremove"},
	{RREMOVE,	"Rremove"},
	{TSTAT,		"Tstat"},
	{RSTAT,		"Rstat"},
	{TWSTAT,	"Twstat"},
	{RWSTAT,	"Rwstat"},
	{0,		NULL},
};

/* Dissect 9P messages*/
static void dissect_9P(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
	guint32 ninesz,tmp,i;
	guint16 tmp16;
	guint8 ninemsg;
	guint offset = 0;
	const char *mname;
	gint len,reportedlen;
	tvbuff_t *next_tvb;
	proto_item *ti;
	proto_tree *ninep_tree;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "9P");
	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_clear(pinfo->cinfo, COL_INFO);

	ninesz = tvb_get_letohl(tvb, offset);
	ninemsg = tvb_get_guint8(tvb, offset + 4);

	mname = val_to_str(ninemsg, ninep_msg_type,NULL);
	
	if (check_col(pinfo->cinfo, COL_INFO)) {
		if(mname == NULL) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "Data Continuitation ? (Tag %d %s)", ninemsg,mname);
			return;
		} else {
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s Tag=%u",mname,(guint)tvb_get_letohs(tvb,offset+5));
		}
		
	} else if (mname == NULL)
		return;

	if (!tree) /*not much more of one line summary interrest yet.. */
		return;

	ti = proto_tree_add_item(tree, proto_9P, tvb, 0, -1, FALSE);
	ninep_tree = proto_item_add_subtree(ti, ett_9P);
	proto_tree_add_item(ninep_tree, hf_9P_msgsz, tvb, offset, 4, TRUE);
	offset+=4;

	proto_tree_add_item(ninep_tree, hf_9P_msgtype, tvb, offset, 1, TRUE);
	++offset;
	proto_tree_add_item(ninep_tree, hf_9P_tag, tvb, offset, 2, TRUE);
	offset += 2;

	switch(ninemsg) {
	case RVERSION:
	case TVERSION:
		proto_tree_add_item(ninep_tree, hf_9P_maxsize, tvb, offset, 4, TRUE);
		offset +=4;

		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;
		proto_tree_add_item(ninep_tree, hf_9P_version, tvb, offset, tmp16, TRUE);
		break;
	case TAUTH:
		proto_tree_add_item(ninep_tree, hf_9P_afid, tvb, offset, 4, TRUE);
		offset +=4;

		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;
		proto_tree_add_item(ninep_tree, hf_9P_uname, tvb, offset, tmp16, TRUE);
		offset += tmp16;

		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;
		proto_tree_add_item(ninep_tree, hf_9P_aname, tvb, offset, tmp16, TRUE);
		break;
	case RAUTH:
		proto_tree_add_item(ninep_tree, hf_9P_qidtype, tvb, offset, 1, TRUE);
		++offset;

		proto_tree_add_item(ninep_tree, hf_9P_qidvers, tvb, offset, 4, TRUE);
		offset +=4;
		
		proto_tree_add_item(ninep_tree, hf_9P_qidpath, tvb, offset, 8, TRUE);

		break;
	case RERROR:
		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;
		proto_tree_add_item(ninep_tree, hf_9P_ename, tvb, offset, tmp16, TRUE);

		break;
	case TFLUSH:
		proto_tree_add_item(ninep_tree, hf_9P_oldtag, tvb, offset, 2, TRUE);
		break;
	case RFLUSH:
		break;
	case TATTACH:
		proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, TRUE);
		offset +=4;

		proto_tree_add_item(ninep_tree, hf_9P_afid, tvb, offset, 4, TRUE);
		offset +=4;

		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;
		proto_tree_add_item(ninep_tree, hf_9P_uname, tvb, offset, tmp16, TRUE);
		offset += tmp16;

		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;
		proto_tree_add_item(ninep_tree, hf_9P_aname, tvb, offset, tmp16, TRUE);
		break;
	case RATTACH:
		proto_tree_add_item(ninep_tree, hf_9P_qidtype, tvb, offset, 1, TRUE);
		++offset;

		proto_tree_add_item(ninep_tree, hf_9P_qidvers, tvb, offset, 4, TRUE);
		offset +=4;
		
		proto_tree_add_item(ninep_tree, hf_9P_qidpath, tvb, offset, 8, TRUE);
		break;
	case TWALK:
		proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, TRUE);
		offset +=4;

		proto_tree_add_item(ninep_tree, hf_9P_newfid, tvb, offset, 4, TRUE);
		offset +=4;
		
		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_nwalk, tvb, offset, 2, TRUE);
		offset +=2;
		for(i = 0 ; i < tmp16; i++) {
			guint16 tmplen;

			tmplen = tvb_get_letohs(tvb,offset);
			proto_tree_add_uint_format(ninep_tree, hf_9P_parmsz, tvb, offset, 2, tmplen, "%d. param length: %u",i,tmplen);
			offset +=2;
			proto_tree_add_item(ninep_tree, hf_9P_wname, tvb, offset, tmplen, TRUE);
			offset += tmplen;
		}

		break;
	case RWALK:
		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_nqid, tvb, offset, 2, TRUE);
		offset +=2;
		for(i = 0; i < tmp16; i++) {
			proto_tree_add_item(ninep_tree, hf_9P_qidtype, tvb, offset, 1, TRUE);
			++offset;

			proto_tree_add_item(ninep_tree, hf_9P_qidvers, tvb, offset, 4, TRUE);
			offset +=4;
		
			proto_tree_add_item(ninep_tree, hf_9P_qidpath, tvb, offset, 8, TRUE);
			offset +=8;
		}	
		break;	
	case TOPEN:
		proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, TRUE);
		offset +=4;
		proto_tree_add_item(ninep_tree, hf_9P_mode, tvb, offset, 1, TRUE);
		break;
	case ROPEN:

		proto_tree_add_item(ninep_tree, hf_9P_qidtype, tvb, offset, 1, TRUE);
		++offset;

		proto_tree_add_item(ninep_tree, hf_9P_qidvers, tvb, offset, 4, TRUE);
		offset +=4;
		
		proto_tree_add_item(ninep_tree, hf_9P_qidpath, tvb, offset, 8, TRUE);
		offset +=8;

		proto_tree_add_item(ninep_tree, hf_9P_iounit, tvb, offset, 4, TRUE);
		break;
	case TCREATE:
		proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, TRUE);
		offset +=4;

		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;
		proto_tree_add_item(ninep_tree, hf_9P_name, tvb, offset, tmp16, TRUE);
		offset += tmp16;

		proto_tree_add_item(ninep_tree, hf_9P_perm, tvb, offset, 4, TRUE);
		offset +=4;

		proto_tree_add_item(ninep_tree, hf_9P_mode, tvb, offset, 1, TRUE);

		break;
	case RCREATE:
		proto_tree_add_item(ninep_tree, hf_9P_qidtype, tvb, offset, 1, TRUE);
		++offset;

		proto_tree_add_item(ninep_tree, hf_9P_qidvers, tvb, offset, 4, TRUE);
		offset +=4;
		
		proto_tree_add_item(ninep_tree, hf_9P_qidpath, tvb, offset, 8, TRUE);
		offset +=8;

		proto_tree_add_item(ninep_tree, hf_9P_iounit, tvb, offset, 4, TRUE);
		break;
	case TREAD:
		proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, TRUE);
		offset +=4;

		proto_tree_add_item(ninep_tree, hf_9P_offset, tvb, offset, 8, TRUE);
		offset +=8;

		proto_tree_add_item(ninep_tree, hf_9P_count, tvb, offset, 4, TRUE);
		break;	
	case RREAD:
		tmp = tvb_get_letohl(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_count, tvb, offset, 4, TRUE);
		offset += 4;

		len = tvb_reported_length_remaining(tvb, offset);
		reportedlen = ((gint)tmp&0xffff) > len ? len : (gint)tmp&0xffff;
		next_tvb = tvb_new_subset(tvb, offset, len, reportedlen);
		call_dissector(data_handle,next_tvb, pinfo, tree);
		break;
	case TWRITE:
		proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, TRUE);
		offset +=4;

		proto_tree_add_item(ninep_tree, hf_9P_offset, tvb, offset, 8, TRUE);
		offset +=8;

		tmp = tvb_get_letohl(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_count, tvb, offset, 4, TRUE);
		offset += 4;
		len = tvb_reported_length_remaining(tvb, offset);
		reportedlen = ((gint)tmp&0xffff) > len ? len : (gint)tmp&0xffff;
		next_tvb = tvb_new_subset(tvb, offset, len, reportedlen);
		call_dissector(data_handle,next_tvb, pinfo, tree);
		break;
	case RWRITE:
		proto_tree_add_item(ninep_tree, hf_9P_count, tvb, offset, 4, TRUE);
		break;
	case TCLUNK:
		proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, TRUE);

		break;
	case RCLUNK:
		break;
	case TREMOVE:
		proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, TRUE);

		break;
	case RREMOVE:
		break;
	case TSTAT:
		proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, TRUE);
		break;
	case RSTAT:
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;

		proto_tree_add_item(ninep_tree, hf_9P_sdlen, tvb, offset, 2, TRUE);
		offset +=2;

		proto_tree_add_item(ninep_tree, hf_9P_stattype, tvb, offset, 2, TRUE);
		offset +=2;

		proto_tree_add_item(ninep_tree, hf_9P_dev, tvb, offset, 4, TRUE);
		offset +=4;

		proto_tree_add_item(ninep_tree, hf_9P_qidtype, tvb, offset, 1, TRUE);
		++offset;

		proto_tree_add_item(ninep_tree, hf_9P_qidvers, tvb, offset, 4, TRUE);
		offset +=4;
		
		proto_tree_add_item(ninep_tree, hf_9P_qidpath, tvb, offset, 8, TRUE);
		offset +=8;

		proto_tree_add_item(ninep_tree, hf_9P_statmode, tvb, offset, 4, TRUE);
		offset +=4;

		proto_tree_add_item(ninep_tree, hf_9P_atime, tvb, offset, 4, TRUE);
		offset +=4;

		proto_tree_add_item(ninep_tree, hf_9P_mtime, tvb, offset, 4, TRUE);
		offset +=4;

		proto_tree_add_item(ninep_tree, hf_9P_length, tvb, offset, 8, TRUE);
		offset +=8;

		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;

		proto_tree_add_item(ninep_tree, hf_9P_filename, tvb, offset, tmp16, TRUE);
		offset += tmp16;

		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;

		proto_tree_add_item(ninep_tree, hf_9P_uid, tvb, offset, tmp16, TRUE);
		offset += tmp16;

		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;

		proto_tree_add_item(ninep_tree, hf_9P_gid, tvb, offset, tmp16, TRUE);
		offset += tmp16;

		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;
		proto_tree_add_item(ninep_tree, hf_9P_muid, tvb, offset, tmp16, TRUE);
		offset += tmp16;
		break;
	case TWSTAT:
		proto_tree_add_item(ninep_tree, hf_9P_fid, tvb, offset, 4, TRUE);
		offset += 4;

		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;

		proto_tree_add_item(ninep_tree, hf_9P_sdlen, tvb, offset, 2, TRUE);
		offset +=2;

		proto_tree_add_item(ninep_tree, hf_9P_stattype, tvb, offset, 2, TRUE);
		offset +=2;

		proto_tree_add_item(ninep_tree, hf_9P_dev, tvb, offset, 4, TRUE);
		offset +=4;

		proto_tree_add_item(ninep_tree, hf_9P_qidtype, tvb, offset, 1, TRUE);
		++offset;

		proto_tree_add_item(ninep_tree, hf_9P_qidvers, tvb, offset, 4, TRUE);
		offset +=4;
		
		proto_tree_add_item(ninep_tree, hf_9P_qidpath, tvb, offset, 8, TRUE);
		offset +=8;

		proto_tree_add_item(ninep_tree, hf_9P_statmode, tvb, offset, 4, TRUE);
		offset +=4;

		proto_tree_add_item(ninep_tree, hf_9P_atime, tvb, offset, 4, TRUE);
		offset +=4;

		proto_tree_add_item(ninep_tree, hf_9P_mtime, tvb, offset, 4, TRUE);
		offset +=4;

		proto_tree_add_item(ninep_tree, hf_9P_length, tvb, offset, 8, TRUE);
		offset +=8;

		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;

		proto_tree_add_item(ninep_tree, hf_9P_filename, tvb, offset, tmp16, TRUE);
		offset += tmp16;

		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;

		proto_tree_add_item(ninep_tree, hf_9P_uid, tvb, offset, tmp16, TRUE);
		offset += tmp16;

		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;

		proto_tree_add_item(ninep_tree, hf_9P_gid, tvb, offset, tmp16, TRUE);
		offset += tmp16;

		tmp16 = tvb_get_letohs(tvb,offset);
		proto_tree_add_item(ninep_tree, hf_9P_parmsz, tvb, offset, 2, TRUE);
		offset +=2;
		proto_tree_add_item(ninep_tree, hf_9P_muid, tvb, offset, tmp16, TRUE);
		offset += tmp16;
		break;
	}

}


/* Register 9P with Ethereal */
void proto_register_9P(void)
{
	static hf_register_info hf[] = {
		{&hf_9P_msgsz,
		 {"Msg length", "9p.msglen", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "9P Message Length", HFILL}},
		{&hf_9P_msgtype,
		 {"Msg Type", "9p.msgtype", FT_UINT8, BASE_DEC, VALS(ninep_msg_type), 0x0,
		  "Message Type", HFILL}},
		{&hf_9P_tag,
		 {"Tag", "9p.tag", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "9P Tag", HFILL}},
		{&hf_9P_oldtag,
		 {"Old tag", "9p.oldtag", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Old tag", HFILL}},
		{&hf_9P_parmsz,
		 {"Param length", "9p.paramsz", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Parameter length", HFILL}},
		{&hf_9P_maxsize,
		 {"Max msg size", "9p.maxsize", FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Max message size", HFILL}},
		{&hf_9P_fid,
		 {"Fid", "9p.fid", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "File ID", HFILL}},
		{&hf_9P_nqid,
		 {"Nr Qids", "9p.nqid", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Number of Qids", HFILL}},
		{&hf_9P_mode,
		 {"Mode", "9p.mode", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Mode", HFILL}},
		{&hf_9P_iounit,
		 {"I/O Unit", "9p.iounit", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "I/O Unit", HFILL}},
		{&hf_9P_count,
		 {"Count", "9p.count", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count", HFILL}},
		{&hf_9P_offset,
		 {"Offset", "9p.offset", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Offset", HFILL}},
		{&hf_9P_perm,
		 {"Permissions", "9p.perm", FT_UINT32, BASE_OCT, NULL, 0x0,
		  "Permission bits", HFILL}},
		{&hf_9P_qidpath,
		 {"Qid path", "9p.qidpath", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Qid path", HFILL}},
		{&hf_9P_qidvers,
		 {"Qid version", "9p.qidvers", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Qid version", HFILL}},
		{&hf_9P_qidtype,
		 {"Qid type", "9p.qidtype", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Qid type", HFILL}},
		{&hf_9P_statmode,
		 {"Stat mode", "9p.statmode", FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Stat mode", HFILL}},
		{&hf_9P_stattype,
		 {"Stat type", "9p.stattype", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Stat type", HFILL}},
		{&hf_9P_atime,
		 {"Atime", "9p.atime", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Access Time", HFILL}},
		{&hf_9P_mtime,
		 {"Mtime", "9p.mtime", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Modified Time", HFILL}},
		{&hf_9P_length,
		 {"Length", "9p.length", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "File Length", HFILL}},
		{&hf_9P_dev,
		 {"Dev", "9p.dev", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "", HFILL}},
		{&hf_9P_wname,
		 {"Wname", "9p.wname", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Path Name Element", HFILL}},
		{&hf_9P_version,
		 {"Version", "9p.version", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Version", HFILL}},
		{&hf_9P_afid,
		 {"AFid", "9p.fid", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Authenticating FID", HFILL}},
		{&hf_9P_uname,
		 {"Uname", "9p.uname", FT_STRING, BASE_NONE, NULL, 0x0,
		  "User Name", HFILL}},
		{&hf_9P_aname,
		 {"Aname", "9p.aname", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Attach Name", HFILL}},
		{&hf_9P_ename,
		 {"Ename", "9p.ename", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Error", HFILL}},
		{&hf_9P_name,
		 {"Name", "9p.name", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Name (of file)", HFILL}},
		{&hf_9P_sdlen,
		 {"Stat data length", "9p.sdlen", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Stat data length", HFILL}},
		{&hf_9P_filename,
		 {"File name", "9p.filename", FT_STRING, BASE_NONE, NULL, 0x0,
		  "File name", HFILL}},
		{&hf_9P_uid,
		 {"Uid", "9p.uid", FT_STRING, BASE_NONE, NULL, 0x0,
		  "User ID", HFILL}},
		{&hf_9P_gid,
		 {"Gid", "9p.gid", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Group ID", HFILL}},
		{&hf_9P_muid,
		 {"Muid", "9p.muid", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Modified Uid", HFILL}},
		{&hf_9P_newfid,
		 {"New fid", "9p.newfid", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "New file ID", HFILL}},
		{&hf_9P_nwalk,
		 {"Nr Walks", "9p.nwalk", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Nr of walk results", HFILL}}

	};

	static gint *ett[] = {
		&ett_9P
	};

	proto_9P = proto_register_protocol("Plan9 9P", "9P", "9p");

	proto_register_field_array(proto_9P, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_9P(void)
{
	dissector_handle_t ninep_handle;

	data_handle = find_dissector("data");

	ninep_handle = create_dissector_handle(dissect_9P, proto_9P);

	dissector_add("tcp.port", NINEPORT, ninep_handle);
}


