/* packet-smb2.c
 * Routines for smb2 packet dissection
 *
 * $Id: packet-smb2.c 16113 2005-10-04 10:23:40Z guy $
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
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/tap.h>
#include <epan/emem.h>

#include "packet-dcerpc.h"
#include "packet-ntlmssp.h"
#include "packet-windows-common.h"



static int proto_smb2 = -1;
static int hf_smb2_cmd = -1;
static int hf_smb2_nt_status = -1;
static int hf_smb2_header_len = -1;
static int hf_smb2_seqnum = -1;
static int hf_smb2_pid = -1;
static int hf_smb2_tid = -1;
static int hf_smb2_uid = -1;
static int hf_smb2_suid = -1;
static int hf_smb2_flags_response = -1;
static int hf_smb2_security_blob_len = -1;
static int hf_smb2_security_blob = -1;
static int hf_smb2_unknown = -1;


static gint ett_smb2 = -1;
static gint ett_smb2_header = -1;
static gint ett_smb2_command = -1;
static gint ett_smb2_secblob = -1;

static dissector_handle_t gssapi_handle = NULL;

typedef struct _smb2_function {
       int (*request)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
       int (*response)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
} smb2_function;

#define SMB2_FLAGS_RESPONSE	0x01

static const true_false_string tfs_flags_response = {
	"This is a RESPONSE",
	"This is a REQUEST"
};


static int
dissect_smb2_session_setup_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_item *blob_item;
	proto_tree *blob_tree;
	tvbuff_t *blob_tvb;
	guint16 sbloblen;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 14, FALSE);
	offset += 14;

	/* length of security blob */
	sbloblen = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb2_security_blob_len, tvb, offset, 2, sbloblen);
	offset += 2;

	/* the security blob itself */
	blob_item = proto_tree_add_item(tree, hf_smb2_security_blob, tvb, offset, sbloblen, TRUE);
	blob_tree = proto_item_add_subtree(blob_item, ett_smb2_secblob);

	blob_tvb = tvb_new_subset(tvb, offset, sbloblen, sbloblen);
	call_dissector(gssapi_handle, blob_tvb, pinfo, blob_tree);
	offset += sbloblen;

	return offset;
}

static int
dissect_smb2_session_setup_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_item *blob_item;
	proto_tree *blob_tree;
	tvbuff_t *blob_tvb;
	guint16 sbloblen;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 6, FALSE);
	offset += 6;

	/* length of security blob */
	sbloblen = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb2_security_blob_len, tvb, offset, 2, sbloblen);
	offset += 2;

	/* the security blob itself */
	blob_item = proto_tree_add_item(tree, hf_smb2_security_blob, tvb, offset, sbloblen, TRUE);
	blob_tree = proto_item_add_subtree(blob_item, ett_smb2_secblob);

	blob_tvb = tvb_new_subset(tvb, offset, sbloblen, sbloblen);
	call_dissector(gssapi_handle, blob_tvb, pinfo, blob_tree);
	offset += sbloblen;

	return offset;
}

/* names here are just until we find better names for these functions */
const value_string smb2_cmd_vals[] = {
  { 0x00, "NegotiateProtocol" },
  { 0x01, "SessionSetupAndX" },
  { 0x02, "unknown-0x02" },
  { 0x03, "TreeConnectAndX" },
  { 0x04, "TreeDisconnect" },
  { 0x05, "Create" },
  { 0x06, "Close" },
  { 0x07, "unknown-0x07" },
  { 0x08, "unknown-0x08" },
  { 0x09, "unknown-0x09" },
  { 0x0A, "unknown-0x0A" },
  { 0x0B, "unknown-0x0B" },
  { 0x0C, "unknown-0x0C" },
  { 0x0D, "unknown-0x0D" },
  { 0x0E, "Find" },
  { 0x0F, "unknown-0x0F" },
  { 0x10, "GetFileInfo" },
  { 0x11, "SetFileInfo" },
  { 0x12, "unknown-0x12" },
  { 0x13, "unknown-0x13" },
  { 0x14, "unknown-0x14" },
  { 0x15, "unknown-0x15" },
  { 0x16, "unknown-0x16" },
  { 0x17, "unknown-0x17" },
  { 0x18, "unknown-0x18" },
  { 0x19, "unknown-0x19" },
  { 0x1A, "unknown-0x1A" },
  { 0x1B, "unknown-0x1B" },
  { 0x1C, "unknown-0x1C" },
  { 0x1D, "unknown-0x1D" },
  { 0x1E, "unknown-0x1E" },
  { 0x1F, "unknown-0x1F" },
  { 0x20, "unknown-0x20" },
  { 0x21, "unknown-0x21" },
  { 0x22, "unknown-0x22" },
  { 0x23, "unknown-0x23" },
  { 0x24, "unknown-0x24" },
  { 0x25, "unknown-0x25" },
  { 0x26, "unknown-0x26" },
  { 0x27, "unknown-0x27" },
  { 0x28, "unknown-0x28" },
  { 0x29, "unknown-0x29" },
  { 0x2A, "unknown-0x2A" },
  { 0x2B, "unknown-0x2B" },
  { 0x2C, "unknown-0x2C" },
  { 0x2D, "unknown-0x2D" },
  { 0x2E, "unknown-0x2E" },
  { 0x2F, "unknown-0x2F" },
  { 0x30, "unknown-0x30" },
  { 0x31, "unknown-0x31" },
  { 0x32, "unknown-0x32" },
  { 0x33, "unknown-0x33" },
  { 0x34, "unknown-0x34" },
  { 0x35, "unknown-0x35" },
  { 0x36, "unknown-0x36" },
  { 0x37, "unknown-0x37" },
  { 0x38, "unknown-0x38" },
  { 0x39, "unknown-0x39" },
  { 0x3A, "unknown-0x3A" },
  { 0x3B, "unknown-0x3B" },
  { 0x3C, "unknown-0x3C" },
  { 0x3D, "unknown-0x3D" },
  { 0x3E, "unknown-0x3E" },
  { 0x3F, "unknown-0x3F" },
  { 0x40, "unknown-0x40" },
  { 0x41, "unknown-0x41" },
  { 0x42, "unknown-0x42" },
  { 0x43, "unknown-0x43" },
  { 0x44, "unknown-0x44" },
  { 0x45, "unknown-0x45" },
  { 0x46, "unknown-0x46" },
  { 0x47, "unknown-0x47" },
  { 0x48, "unknown-0x48" },
  { 0x49, "unknown-0x49" },
  { 0x4A, "unknown-0x4A" },
  { 0x4B, "unknown-0x4B" },
  { 0x4C, "unknown-0x4C" },
  { 0x4D, "unknown-0x4D" },
  { 0x4E, "unknown-0x4E" },
  { 0x4F, "unknown-0x4F" },
  { 0x50, "unknown-0x50" },
  { 0x51, "unknown-0x51" },
  { 0x52, "unknown-0x52" },
  { 0x53, "unknown-0x53" },
  { 0x54, "unknown-0x54" },
  { 0x55, "unknown-0x55" },
  { 0x56, "unknown-0x56" },
  { 0x57, "unknown-0x57" },
  { 0x58, "unknown-0x58" },
  { 0x59, "unknown-0x59" },
  { 0x5A, "unknown-0x5A" },
  { 0x5B, "unknown-0x5B" },
  { 0x5C, "unknown-0x5C" },
  { 0x5D, "unknown-0x5D" },
  { 0x5E, "unknown-0x5E" },
  { 0x5F, "unknown-0x5F" },
  { 0x60, "unknown-0x60" },
  { 0x61, "unknown-0x61" },
  { 0x62, "unknown-0x62" },
  { 0x63, "unknown-0x63" },
  { 0x64, "unknown-0x64" },
  { 0x65, "unknown-0x65" },
  { 0x66, "unknown-0x66" },
  { 0x67, "unknown-0x67" },
  { 0x68, "unknown-0x68" },
  { 0x69, "unknown-0x69" },
  { 0x6A, "unknown-0x6A" },
  { 0x6B, "unknown-0x6B" },
  { 0x6C, "unknown-0x6C" },
  { 0x6D, "unknown-0x6D" },
  { 0x6E, "unknown-0x6E" },
  { 0x6F, "unknown-0x6F" },
  { 0x70, "unknown-0x70" },
  { 0x71, "unknown-0x71" },
  { 0x72, "unknown-0x72" },
  { 0x73, "unknown-0x73" },
  { 0x74, "unknown-0x74" },
  { 0x75, "unknown-0x75" },
  { 0x76, "unknown-0x76" },
  { 0x77, "unknown-0x77" },
  { 0x78, "unknown-0x78" },
  { 0x79, "unknown-0x79" },
  { 0x7A, "unknown-0x7A" },
  { 0x7B, "unknown-0x7B" },
  { 0x7C, "unknown-0x7C" },
  { 0x7D, "unknown-0x7D" },
  { 0x7E, "unknown-0x7E" },
  { 0x7F, "unknown-0x7F" },
  { 0x80, "unknown-0x80" },
  { 0x81, "unknown-0x81" },
  { 0x82, "unknown-0x82" },
  { 0x83, "unknown-0x83" },
  { 0x84, "unknown-0x84" },
  { 0x85, "unknown-0x85" },
  { 0x86, "unknown-0x86" },
  { 0x87, "unknown-0x87" },
  { 0x88, "unknown-0x88" },
  { 0x89, "unknown-0x89" },
  { 0x8A, "unknown-0x8A" },
  { 0x8B, "unknown-0x8B" },
  { 0x8C, "unknown-0x8C" },
  { 0x8D, "unknown-0x8D" },
  { 0x8E, "unknown-0x8E" },
  { 0x8F, "unknown-0x8F" },
  { 0x90, "unknown-0x90" },
  { 0x91, "unknown-0x91" },
  { 0x92, "unknown-0x92" },
  { 0x93, "unknown-0x93" },
  { 0x94, "unknown-0x94" },
  { 0x95, "unknown-0x95" },
  { 0x96, "unknown-0x96" },
  { 0x97, "unknown-0x97" },
  { 0x98, "unknown-0x98" },
  { 0x99, "unknown-0x99" },
  { 0x9A, "unknown-0x9A" },
  { 0x9B, "unknown-0x9B" },
  { 0x9C, "unknown-0x9C" },
  { 0x9D, "unknown-0x9D" },
  { 0x9E, "unknown-0x9E" },
  { 0x9F, "unknown-0x9F" },
  { 0xA0, "unknown-0xA0" },
  { 0xA1, "unknown-0xA1" },
  { 0xA2, "unknown-0xA2" },
  { 0xA3, "unknown-0xA3" },
  { 0xA4, "unknown-0xA4" },
  { 0xA5, "unknown-0xA5" },
  { 0xA6, "unknown-0xA6" },
  { 0xA7, "unknown-0xA7" },
  { 0xA8, "unknown-0xA8" },
  { 0xA9, "unknown-0xA9" },
  { 0xAA, "unknown-0xAA" },
  { 0xAB, "unknown-0xAB" },
  { 0xAC, "unknown-0xAC" },
  { 0xAD, "unknown-0xAD" },
  { 0xAE, "unknown-0xAE" },
  { 0xAF, "unknown-0xAF" },
  { 0xB0, "unknown-0xB0" },
  { 0xB1, "unknown-0xB1" },
  { 0xB2, "unknown-0xB2" },
  { 0xB3, "unknown-0xB3" },
  { 0xB4, "unknown-0xB4" },
  { 0xB5, "unknown-0xB5" },
  { 0xB6, "unknown-0xB6" },
  { 0xB7, "unknown-0xB7" },
  { 0xB8, "unknown-0xB8" },
  { 0xB9, "unknown-0xB9" },
  { 0xBA, "unknown-0xBA" },
  { 0xBB, "unknown-0xBB" },
  { 0xBC, "unknown-0xBC" },
  { 0xBD, "unknown-0xBD" },
  { 0xBE, "unknown-0xBE" },
  { 0xBF, "unknown-0xBF" },
  { 0xC0, "unknown-0xC0" },
  { 0xC1, "unknown-0xC1" },
  { 0xC2, "unknown-0xC2" },
  { 0xC3, "unknown-0xC3" },
  { 0xC4, "unknown-0xC4" },
  { 0xC5, "unknown-0xC5" },
  { 0xC6, "unknown-0xC6" },
  { 0xC7, "unknown-0xC7" },
  { 0xC8, "unknown-0xC8" },
  { 0xC9, "unknown-0xC9" },
  { 0xCA, "unknown-0xCA" },
  { 0xCB, "unknown-0xCB" },
  { 0xCC, "unknown-0xCC" },
  { 0xCD, "unknown-0xCD" },
  { 0xCE, "unknown-0xCE" },
  { 0xCF, "unknown-0xCF" },
  { 0xD0, "unknown-0xD0" },
  { 0xD1, "unknown-0xD1" },
  { 0xD2, "unknown-0xD2" },
  { 0xD3, "unknown-0xD3" },
  { 0xD4, "unknown-0xD4" },
  { 0xD5, "unknown-0xD5" },
  { 0xD6, "unknown-0xD6" },
  { 0xD7, "unknown-0xD7" },
  { 0xD8, "unknown-0xD8" },
  { 0xD9, "unknown-0xD9" },
  { 0xDA, "unknown-0xDA" },
  { 0xDB, "unknown-0xDB" },
  { 0xDC, "unknown-0xDC" },
  { 0xDD, "unknown-0xDD" },
  { 0xDE, "unknown-0xDE" },
  { 0xDF, "unknown-0xDF" },
  { 0xE0, "unknown-0xE0" },
  { 0xE1, "unknown-0xE1" },
  { 0xE2, "unknown-0xE2" },
  { 0xE3, "unknown-0xE3" },
  { 0xE4, "unknown-0xE4" },
  { 0xE5, "unknown-0xE5" },
  { 0xE6, "unknown-0xE6" },
  { 0xE7, "unknown-0xE7" },
  { 0xE8, "unknown-0xE8" },
  { 0xE9, "unknown-0xE9" },
  { 0xEA, "unknown-0xEA" },
  { 0xEB, "unknown-0xEB" },
  { 0xEC, "unknown-0xEC" },
  { 0xED, "unknown-0xED" },
  { 0xEE, "unknown-0xEE" },
  { 0xEF, "unknown-0xEF" },
  { 0xF0, "unknown-0xF0" },
  { 0xF1, "unknown-0xF1" },
  { 0xF2, "unknown-0xF2" },
  { 0xF3, "unknown-0xF3" },
  { 0xF4, "unknown-0xF4" },
  { 0xF5, "unknown-0xF5" },
  { 0xF6, "unknown-0xF6" },
  { 0xF7, "unknown-0xF7" },
  { 0xF8, "unknown-0xF8" },
  { 0xF9, "unknown-0xF9" },
  { 0xFA, "unknown-0xFA" },
  { 0xFB, "unknown-0xFB" },
  { 0xFC, "unknown-0xFC" },
  { 0xFD, "unknown-0xFD" },
  { 0xFE, "unknown-0xFE" },
  { 0xFF, "unknown-0xFF" },
  { 0x00, NULL },
};
static const char *decode_smb2_name(guint8 cmd)
{
  return(smb2_cmd_vals[cmd].strptr);
}

static smb2_function smb2_dissector[256] = {
  /* 0x00 */  {NULL, NULL},
  /* 0x01 SessionSetup*/  
	{dissect_smb2_session_setup_request, 
	 dissect_smb2_session_setup_response},
  /* 0x02 */  {NULL, NULL},
  /* 0x03 */  {NULL, NULL},
  /* 0x04 */  {NULL, NULL},
  /* 0x05 */  {NULL, NULL},
  /* 0x06 */  {NULL, NULL},
  /* 0x07 */  {NULL, NULL},
  /* 0x08 */  {NULL, NULL},
  /* 0x09 */  {NULL, NULL},
  /* 0x0a */  {NULL, NULL},
  /* 0x0b */  {NULL, NULL},
  /* 0x0c */  {NULL, NULL},
  /* 0x0d */  {NULL, NULL},
  /* 0x0e */  {NULL, NULL},
  /* 0x0f */  {NULL, NULL},
  /* 0x10 */  {NULL, NULL},
  /* 0x11 */  {NULL, NULL},
  /* 0x12 */  {NULL, NULL},
  /* 0x13 */  {NULL, NULL},
  /* 0x14 */  {NULL, NULL},
  /* 0x15 */  {NULL, NULL},
  /* 0x16 */  {NULL, NULL},
  /* 0x17 */  {NULL, NULL},
  /* 0x18 */  {NULL, NULL},
  /* 0x19 */  {NULL, NULL},
  /* 0x1a */  {NULL, NULL},
  /* 0x1b */  {NULL, NULL},
  /* 0x1c */  {NULL, NULL},
  /* 0x1d */  {NULL, NULL},
  /* 0x1e */  {NULL, NULL},
  /* 0x1f */  {NULL, NULL},
  /* 0x20 */  {NULL, NULL},
  /* 0x21 */  {NULL, NULL},
  /* 0x22 */  {NULL, NULL},
  /* 0x23 */  {NULL, NULL},
  /* 0x24 */  {NULL, NULL},
  /* 0x25 */  {NULL, NULL},
  /* 0x26 */  {NULL, NULL},
  /* 0x27 */  {NULL, NULL},
  /* 0x28 */  {NULL, NULL},
  /* 0x29 */  {NULL, NULL},
  /* 0x2a */  {NULL, NULL},
  /* 0x2b */  {NULL, NULL},
  /* 0x2c */  {NULL, NULL},
  /* 0x2d */  {NULL, NULL},
  /* 0x2e */  {NULL, NULL},
  /* 0x2f */  {NULL, NULL},
  /* 0x30 */  {NULL, NULL},
  /* 0x31 */  {NULL, NULL},
  /* 0x32 */  {NULL, NULL},
  /* 0x33 */  {NULL, NULL},
  /* 0x34 */  {NULL, NULL},
  /* 0x35 */  {NULL, NULL},
  /* 0x36 */  {NULL, NULL},
  /* 0x37 */  {NULL, NULL},
  /* 0x38 */  {NULL, NULL},
  /* 0x39 */  {NULL, NULL},
  /* 0x3a */  {NULL, NULL},
  /* 0x3b */  {NULL, NULL},
  /* 0x3c */  {NULL, NULL},
  /* 0x3d */  {NULL, NULL},
  /* 0x3e */  {NULL, NULL},
  /* 0x3f */  {NULL, NULL},
  /* 0x40 */  {NULL, NULL},
  /* 0x41 */  {NULL, NULL},
  /* 0x42 */  {NULL, NULL},
  /* 0x43 */  {NULL, NULL},
  /* 0x44 */  {NULL, NULL},
  /* 0x45 */  {NULL, NULL},
  /* 0x46 */  {NULL, NULL},
  /* 0x47 */  {NULL, NULL},
  /* 0x48 */  {NULL, NULL},
  /* 0x49 */  {NULL, NULL},
  /* 0x4a */  {NULL, NULL},
  /* 0x4b */  {NULL, NULL},
  /* 0x4c */  {NULL, NULL},
  /* 0x4d */  {NULL, NULL},
  /* 0x4e */  {NULL, NULL},
  /* 0x4f */  {NULL, NULL},
  /* 0x50 */  {NULL, NULL},
  /* 0x51 */  {NULL, NULL},
  /* 0x52 */  {NULL, NULL},
  /* 0x53 */  {NULL, NULL},
  /* 0x54 */  {NULL, NULL},
  /* 0x55 */  {NULL, NULL},
  /* 0x56 */  {NULL, NULL},
  /* 0x57 */  {NULL, NULL},
  /* 0x58 */  {NULL, NULL},
  /* 0x59 */  {NULL, NULL},
  /* 0x5a */  {NULL, NULL},
  /* 0x5b */  {NULL, NULL},
  /* 0x5c */  {NULL, NULL},
  /* 0x5d */  {NULL, NULL},
  /* 0x5e */  {NULL, NULL},
  /* 0x5f */  {NULL, NULL},
  /* 0x60 */  {NULL, NULL},
  /* 0x61 */  {NULL, NULL},
  /* 0x62 */  {NULL, NULL},
  /* 0x63 */  {NULL, NULL},
  /* 0x64 */  {NULL, NULL},
  /* 0x65 */  {NULL, NULL},
  /* 0x66 */  {NULL, NULL},
  /* 0x67 */  {NULL, NULL},
  /* 0x68 */  {NULL, NULL},
  /* 0x69 */  {NULL, NULL},
  /* 0x6a */  {NULL, NULL},
  /* 0x6b */  {NULL, NULL},
  /* 0x6c */  {NULL, NULL},
  /* 0x6d */  {NULL, NULL},
  /* 0x6e */  {NULL, NULL},
  /* 0x6f */  {NULL, NULL},
  /* 0x70 */  {NULL, NULL},
  /* 0x71 */  {NULL, NULL},
  /* 0x72 */  {NULL, NULL},
  /* 0x73 */  {NULL, NULL},
  /* 0x74 */  {NULL, NULL},
  /* 0x75 */  {NULL, NULL},
  /* 0x76 */  {NULL, NULL},
  /* 0x77 */  {NULL, NULL},
  /* 0x78 */  {NULL, NULL},
  /* 0x79 */  {NULL, NULL},
  /* 0x7a */  {NULL, NULL},
  /* 0x7b */  {NULL, NULL},
  /* 0x7c */  {NULL, NULL},
  /* 0x7d */  {NULL, NULL},
  /* 0x7e */  {NULL, NULL},
  /* 0x7f */  {NULL, NULL},
  /* 0x80 */  {NULL, NULL},
  /* 0x81 */  {NULL, NULL},
  /* 0x82 */  {NULL, NULL},
  /* 0x83 */  {NULL, NULL},
  /* 0x84 */  {NULL, NULL},
  /* 0x85 */  {NULL, NULL},
  /* 0x86 */  {NULL, NULL},
  /* 0x87 */  {NULL, NULL},
  /* 0x88 */  {NULL, NULL},
  /* 0x89 */  {NULL, NULL},
  /* 0x8a */  {NULL, NULL},
  /* 0x8b */  {NULL, NULL},
  /* 0x8c */  {NULL, NULL},
  /* 0x8d */  {NULL, NULL},
  /* 0x8e */  {NULL, NULL},
  /* 0x8f */  {NULL, NULL},
  /* 0x90 */  {NULL, NULL},
  /* 0x91 */  {NULL, NULL},
  /* 0x92 */  {NULL, NULL},
  /* 0x93 */  {NULL, NULL},
  /* 0x94 */  {NULL, NULL},
  /* 0x95 */  {NULL, NULL},
  /* 0x96 */  {NULL, NULL},
  /* 0x97 */  {NULL, NULL},
  /* 0x98 */  {NULL, NULL},
  /* 0x99 */  {NULL, NULL},
  /* 0x9a */  {NULL, NULL},
  /* 0x9b */  {NULL, NULL},
  /* 0x9c */  {NULL, NULL},
  /* 0x9d */  {NULL, NULL},
  /* 0x9e */  {NULL, NULL},
  /* 0x9f */  {NULL, NULL},
  /* 0xa0 */  {NULL, NULL},
  /* 0xa1 */  {NULL, NULL},
  /* 0xa2 */  {NULL, NULL},
  /* 0xa3 */  {NULL, NULL},
  /* 0xa4 */  {NULL, NULL},
  /* 0xa5 */  {NULL, NULL},
  /* 0xa6 */  {NULL, NULL},
  /* 0xa7 */  {NULL, NULL},
  /* 0xa8 */  {NULL, NULL},
  /* 0xa9 */  {NULL, NULL},
  /* 0xaa */  {NULL, NULL},
  /* 0xab */  {NULL, NULL},
  /* 0xac */  {NULL, NULL},
  /* 0xad */  {NULL, NULL},
  /* 0xae */  {NULL, NULL},
  /* 0xaf */  {NULL, NULL},
  /* 0xb0 */  {NULL, NULL},
  /* 0xb1 */  {NULL, NULL},
  /* 0xb2 */  {NULL, NULL},
  /* 0xb3 */  {NULL, NULL},
  /* 0xb4 */  {NULL, NULL},
  /* 0xb5 */  {NULL, NULL},
  /* 0xb6 */  {NULL, NULL},
  /* 0xb7 */  {NULL, NULL},
  /* 0xb8 */  {NULL, NULL},
  /* 0xb9 */  {NULL, NULL},
  /* 0xba */  {NULL, NULL},
  /* 0xbb */  {NULL, NULL},
  /* 0xbc */  {NULL, NULL},
  /* 0xbd */  {NULL, NULL},
  /* 0xbe */  {NULL, NULL},
  /* 0xbf */  {NULL, NULL},
  /* 0xc0 */  {NULL, NULL},
  /* 0xc1 */  {NULL, NULL},
  /* 0xc2 */  {NULL, NULL},
  /* 0xc3 */  {NULL, NULL},
  /* 0xc4 */  {NULL, NULL},
  /* 0xc5 */  {NULL, NULL},
  /* 0xc6 */  {NULL, NULL},
  /* 0xc7 */  {NULL, NULL},
  /* 0xc8 */  {NULL, NULL},
  /* 0xc9 */  {NULL, NULL},
  /* 0xca */  {NULL, NULL},
  /* 0xcb */  {NULL, NULL},
  /* 0xcc */  {NULL, NULL},
  /* 0xcd */  {NULL, NULL},
  /* 0xce */  {NULL, NULL},
  /* 0xcf */  {NULL, NULL},
  /* 0xd0 */  {NULL, NULL},
  /* 0xd1 */  {NULL, NULL},
  /* 0xd2 */  {NULL, NULL},
  /* 0xd3 */  {NULL, NULL},
  /* 0xd4 */  {NULL, NULL},
  /* 0xd5 */  {NULL, NULL},
  /* 0xd6 */  {NULL, NULL},
  /* 0xd7 */  {NULL, NULL},
  /* 0xd8 */  {NULL, NULL},
  /* 0xd9 */  {NULL, NULL},
  /* 0xda */  {NULL, NULL},
  /* 0xdb */  {NULL, NULL},
  /* 0xdc */  {NULL, NULL},
  /* 0xdd */  {NULL, NULL},
  /* 0xde */  {NULL, NULL},
  /* 0xdf */  {NULL, NULL},
  /* 0xe0 */  {NULL, NULL},
  /* 0xe1 */  {NULL, NULL},
  /* 0xe2 */  {NULL, NULL},
  /* 0xe3 */  {NULL, NULL},
  /* 0xe4 */  {NULL, NULL},
  /* 0xe5 */  {NULL, NULL},
  /* 0xe6 */  {NULL, NULL},
  /* 0xe7 */  {NULL, NULL},
  /* 0xe8 */  {NULL, NULL},
  /* 0xe9 */  {NULL, NULL},
  /* 0xea */  {NULL, NULL},
  /* 0xeb */  {NULL, NULL},
  /* 0xec */  {NULL, NULL},
  /* 0xed */  {NULL, NULL},
  /* 0xee */  {NULL, NULL},
  /* 0xef */  {NULL, NULL},
  /* 0xf0 */  {NULL, NULL},
  /* 0xf1 */  {NULL, NULL},
  /* 0xf2 */  {NULL, NULL},
  /* 0xf3 */  {NULL, NULL},
  /* 0xf4 */  {NULL, NULL},
  /* 0xf5 */  {NULL, NULL},
  /* 0xf6 */  {NULL, NULL},
  /* 0xf7 */  {NULL, NULL},
  /* 0xf8 */  {NULL, NULL},
  /* 0xf9 */  {NULL, NULL},
  /* 0xfa */  {NULL, NULL},
  /* 0xfb */  {NULL, NULL},
  /* 0xfc */  {NULL, NULL},
  /* 0xfd */  {NULL, NULL},
  /* 0xfe */  {NULL, NULL},
  /* 0xff */  {NULL, NULL},
};


static int
dissect_smb2_command(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, guint8 cmd, guint8 response)
{
	int (*cmd_dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
	proto_item *cmd_item;
	proto_tree *cmd_tree;


	cmd_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s %s (0x%02x)",
			decode_smb2_name(cmd),
			response?"Response":"Request",
			cmd);
	cmd_tree = proto_item_add_subtree(cmd_item, ett_smb2_command);


	cmd_dissector=response?
		smb2_dissector[cmd&0xff].response:
		smb2_dissector[cmd&0xff].request;
	if(cmd_dissector){
		offset=(*cmd_dissector)(tvb, pinfo, cmd_tree, offset);
	} else {
		proto_tree_add_item(cmd_tree, hf_smb2_unknown, tvb, offset, -1, FALSE);
		offset=tvb_length(tvb);
	}

	return offset;
}

static void
dissect_smb2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	proto_item *header_item=NULL;
	proto_tree *header_tree=NULL;
	int offset=0;
	int old_offset;
	guint8 cmd, response;
	guint16 header_len;
	guint32 nt_status;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMB2");
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_smb2, tvb, offset,
			-1, FALSE);
		tree = proto_item_add_subtree(item, ett_smb2);
	}

	if (tree) {
		header_item = proto_tree_add_text(tree, tvb, offset, -1, "SMB2 Header");
		header_tree = proto_item_add_subtree(header_item, ett_smb2_header);
	}
	old_offset=offset;

	/* Decode the header */
	/* SMB2 marker */
	proto_tree_add_text(header_tree, tvb, offset, 4, "Server Component: SMB2");
	offset += 4;

	/* header length */
	header_len=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(header_tree, hf_smb2_header_len, tvb, offset, 2, TRUE);
	offset += 2;

	/* padding */
	offset += 2;

	/* Status Code */
	nt_status=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(header_tree, hf_smb2_nt_status, tvb, offset, 4, TRUE);
	offset += 4;


	/* CMD either 1 or two bytes*/
	cmd=tvb_get_guint8(tvb, offset);
	proto_tree_add_item(header_tree, hf_smb2_cmd, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(header_tree, hf_smb2_unknown, tvb, offset, 2, FALSE);
	offset += 2;

	/* flags */
	response=tvb_get_guint8(tvb, offset)&SMB2_FLAGS_RESPONSE;
	proto_tree_add_item(header_tree, hf_smb2_flags_response, tvb, offset, 1, FALSE);
	offset += 1;

	/* some unknown bytes */
	proto_tree_add_item(header_tree, hf_smb2_unknown, tvb, offset, 7, FALSE);
	offset += 7;

	/* command sequence number*/
	proto_tree_add_item(header_tree, hf_smb2_seqnum, tvb, offset, 8, TRUE);
	offset += 8;

	/* Process ID */
	proto_tree_add_item(header_tree, hf_smb2_pid, tvb, offset, 4, TRUE);
	offset += 4;

	/* Tree ID */
	proto_tree_add_item(header_tree, hf_smb2_tid, tvb, offset, 4, TRUE);
	offset += 4;

	/* User ID */
	proto_tree_add_item(header_tree, hf_smb2_uid, tvb, offset, 4, TRUE);
	offset += 4;

	/* Secondary User ID */
	proto_tree_add_item(header_tree, hf_smb2_suid, tvb, offset, 4, TRUE);
	offset += 4;

	/* some unknown bytes */
	proto_tree_add_item(header_tree, hf_smb2_unknown, tvb, offset, 4, FALSE);
	offset += 4;

	/* some unknown bytes */
	proto_tree_add_item(header_tree, hf_smb2_unknown, tvb, offset, 12, FALSE);
	offset += 12;

	proto_item_set_len(header_item, offset-old_offset);



	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s",
			decode_smb2_name(cmd),
			response?"Response":"Request");
		if(nt_status){
			col_append_fstr(
				pinfo->cinfo, COL_INFO, ", Error: %s",
				val_to_str(nt_status, NT_errors,
				"Unknown (0x%08X)"));
		}
	}

	/* Decode the payload */
	dissect_smb2_command(pinfo, tree, tvb, offset, cmd, response);
}

static gboolean
dissect_smb2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	/* must check that this really is a smb2 packet */
	if (!tvb_bytes_exist(tvb, 0, 4))
		return FALSE;

	if( (tvb_get_guint8(tvb, 0) != 0xfe)
	    || (tvb_get_guint8(tvb, 1) != 'S')
	    || (tvb_get_guint8(tvb, 2) != 'M')
	    || (tvb_get_guint8(tvb, 3) != 'B') ){
		return FALSE;
	}

	dissect_smb2(tvb, pinfo, parent_tree);
	return TRUE;
}

void
proto_register_smb2(void)
{
	static hf_register_info hf[] = {
	{ &hf_smb2_cmd,
		{ "Command", "smb2.cmd", FT_UINT16, BASE_DEC,
		VALS(smb2_cmd_vals), 0, "SMB2 Command Opcode", HFILL }},
	{ &hf_smb2_header_len,
		{ "Header Length", "smb2.header_len", FT_UINT16, BASE_DEC,
		NULL, 0, "SMB2 Size of Header", HFILL }},
	{ &hf_smb2_nt_status,
		{ "NT Status", "smb2.nt_status", FT_UINT32, BASE_HEX,
		VALS(NT_errors), 0, "NT Status code", HFILL }},
	{ &hf_smb2_seqnum,
		{ "Command Sequence Number", "smb2.seq_num", FT_UINT64, BASE_DEC,
		NULL, 0, "SMB2 Command Sequence Number", HFILL }},
	{ &hf_smb2_tid,
		{ "Tree Id", "smb2.tid", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 Tree Id", HFILL }},
	{ &hf_smb2_uid,
		{ "User Id", "smb2.uid", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 User Id", HFILL }},
	{ &hf_smb2_suid,
		{ "Secondary User Id", "smb2.suid", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 Secondary User Id", HFILL }},
	{ &hf_smb2_pid,
		{ "Process Id", "smb2.pid", FT_UINT32, BASE_HEX,
		NULL, 0, "SMB2 Process Id", HFILL }},
	{ &hf_smb2_flags_response,
		{ "Response", "smb2.flags.response", FT_BOOLEAN, 8,
		TFS(&tfs_flags_response), SMB2_FLAGS_RESPONSE, "Whether this is an SMB2 Request or Response", HFILL }},
	{ &hf_smb2_security_blob_len,
		{ "Security Blob Length", "smb2.security_blob_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Security blob length", HFILL }},

	{ &hf_smb2_security_blob,
		{ "Security Blob", "smb2.security_blob", FT_BYTES, BASE_HEX,
		NULL, 0, "Security blob", HFILL }},

	{ &hf_smb2_unknown,
		{ "unknown", "smb2.unknown", FT_BYTES, BASE_HEX,
		NULL, 0, "Unknown bytes", HFILL }},
	};

	static gint *ett[] = {
		&ett_smb2,
		&ett_smb2_header,
		&ett_smb2_command,
		&ett_smb2_secblob,
	};

	proto_smb2 = proto_register_protocol("SMB2 (Server Message Block Protocol version 2)",
	    "SMB2", "smb2");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_smb2, hf, array_length(hf));
}

void
proto_reg_handoff_smb2(void)
{
	gssapi_handle = find_dissector("gssapi");
	heur_dissector_add("netbios", dissect_smb2_heur, proto_smb2);
}
