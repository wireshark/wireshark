/* packet-smb.c
 * Routines for smb packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-smb.c,v 1.80 2001/03/18 03:23:30 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <time.h>
#include <string.h>
#include <glib.h>
#include <ctype.h>
#include "packet.h"
#include "conversation.h"
#include "smb.h"
#include "alignment.h"
#include "strutil.h"

#include "packet-smb-mailslot.h"
#include "packet-smb-pipe.h"

static int proto_smb = -1;

static int hf_smb_cmd = -1;

static gint ett_smb = -1;
static gint ett_smb_fileattributes = -1;
static gint ett_smb_capabilities = -1;
static gint ett_smb_aflags = -1;
static gint ett_smb_dialects = -1;
static gint ett_smb_mode = -1;
static gint ett_smb_rawmode = -1;
static gint ett_smb_flags = -1;
static gint ett_smb_flags2 = -1;
static gint ett_smb_desiredaccess = -1;
static gint ett_smb_search = -1;
static gint ett_smb_file = -1;
static gint ett_smb_openfunction = -1;
static gint ett_smb_filetype = -1;
static gint ett_smb_action = -1;
static gint ett_smb_writemode = -1;
static gint ett_smb_lock_type = -1;



/*
 * Struct passed to each SMB decode routine of info it may need
 */

char *decode_smb_name(unsigned char);

int smb_packet_init_count = 200;

struct smb_request_key {
  guint32 conversation;
  guint16 mid;
};


GHashTable *smb_request_hash = NULL;
GMemChunk *smb_request_keys = NULL;
GMemChunk *smb_request_vals = NULL;

/* Hash Functions */
gint
smb_equal(gconstpointer v, gconstpointer w)
{
  struct smb_request_key *v1 = (struct smb_request_key *)v;
  struct smb_request_key *v2 = (struct smb_request_key *)w;

#if defined(DEBUG_SMB_HASH)
  printf("Comparing %08X:%u\n      and %08X:%u\n",
	 v1 -> conversation, v1 -> mid,
	 v2 -> conversation, v2 -> mid);
#endif

  if (v1 -> conversation == v2 -> conversation &&
      v1 -> mid          == v2 -> mid) {

    return 1;

  }

  return 0;
}

guint 
smb_hash (gconstpointer v)
{
  struct smb_request_key *key = (struct smb_request_key *)v;
  guint val;

  val = key -> conversation + key -> mid;

#if defined(DEBUG_SMB_HASH)
  printf("SMB Hash calculated as %u\n", val);
#endif

  return val;

}

/*
 * Free up any state information we've saved, and re-initialize the
 * tables of state information.
 */
static void
smb_init_protocol(void)
{
#if defined(DEBUG_SMB_HASH)
  printf("Initializing SMB hashtable area\n");
#endif

  if (smb_request_hash)
    g_hash_table_destroy(smb_request_hash);
  if (smb_request_keys)
    g_mem_chunk_destroy(smb_request_keys);
  if (smb_request_vals)
    g_mem_chunk_destroy(smb_request_vals);

  smb_request_hash = g_hash_table_new(smb_hash, smb_equal);
  smb_request_keys = g_mem_chunk_new("smb_request_keys",
				     sizeof(struct smb_request_key),
				     smb_packet_init_count * sizeof(struct smb_request_key), G_ALLOC_AND_FREE);
  smb_request_vals = g_mem_chunk_new("smb_request_vals",
				     sizeof(struct smb_request_val),
				     smb_packet_init_count * sizeof(struct smb_request_val), G_ALLOC_AND_FREE);
}

void (*dissect[256])(const u_char *, int, frame_data *, proto_tree *, proto_tree *, struct smb_info si, int, int, int, int);

static const value_string smb_cmd_vals[] = {
  { 0x00, "SMBcreatedirectory" },
  { 0x01, "SMBdeletedirectory" },
  { 0x02, "SMBopen" },
  { 0x03, "SMBcreate" },
  { 0x04, "SMBclose" },
  { 0x05, "SMBflush" },
  { 0x06, "SMBunlink" },
  { 0x07, "SMBmv" },
  { 0x08, "SMBgetatr" },
  { 0x09, "SMBsetatr" },
  { 0x0A, "SMBread" },
  { 0x0B, "SMBwrite" },
  { 0x0C, "SMBlock" },
  { 0x0D, "SMBunlock" },
  { 0x0E, "SMBctemp" },
  { 0x0F, "SMBmknew" },
  { 0x10, "SMBchkpth" },
  { 0x11, "SMBexit" },
  { 0x12, "SMBlseek" },
  { 0x13, "SMBlockread" },
  { 0x14, "SMBwriteunlock" },
  { 0x15, "unknown-0x15" },
  { 0x16, "unknown-0x16" },
  { 0x17, "unknown-0x17" },
  { 0x18, "unknown-0x18" },
  { 0x19, "unknown-0x19" },
  { 0x1A, "SMBreadBraw" },
  { 0x1B, "SMBreadBmpx" },
  { 0x1C, "SMBreadBs" },
  { 0x1D, "SMBwriteBraw" },
  { 0x1E, "SMBwriteBmpx" },
  { 0x1F, "SMBwriteBs" },
  { 0x20, "SMBwriteC" },
  { 0x21, "unknown-0x21" },
  { 0x22, "SMBsetattrE" },
  { 0x23, "SMBgetattrE" },
  { 0x24, "SMBlockingX" },
  { 0x25, "SMBtrans" },
  { 0x26, "SMBtranss" },
  { 0x27, "SMBioctl" },
  { 0x28, "SMBioctls" },
  { 0x29, "SMBcopy" },
  { 0x2A, "SMBmove" },
  { 0x2B, "SMBecho" },
  { 0x2C, "SMBwriteclose" },
  { 0x2D, "SMBopenX" },
  { 0x2E, "SMBreadX" },
  { 0x2F, "SMBwriteX" },
  { 0x30, "unknown-0x30" },
  { 0x31, "SMBcloseandtreedisc" },
  { 0x32, "SMBtrans2" },
  { 0x33, "SMBtrans2secondary" },
  { 0x34, "SMBfindclose2" },
  { 0x35, "SMBfindnotifyclose" },
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
  { 0x70, "SMBtcon" },
  { 0x71, "SMBtdis" },
  { 0x72, "SMBnegprot" },
  { 0x73, "SMBsesssetupX" },
  { 0x74, "SMBlogoffX" },
  { 0x75, "SMBtconX" },
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
  { 0x80, "SMBdskattr" },
  { 0x81, "SMBsearch" },
  { 0x82, "SMBffirst" },
  { 0x83, "SMBfunique" },
  { 0x84, "SMBfclose" },
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
  { 0xA0, "SMBnttransact" },
  { 0xA1, "SMBnttransactsecondary" },
  { 0xA2, "SMBntcreateX" },
  { 0xA3, "unknown-0xA3" },
  { 0xA4, "SMBntcancel" },
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
  { 0xC0, "SMBsplopen" },
  { 0xC1, "SMBsplwr" },
  { 0xC2, "SMBsplclose" },
  { 0xC3, "SMBsplretq" },
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
  { 0xD0, "SMBsends" },
  { 0xD1, "SMBsendb" },
  { 0xD2, "SMBfwdname" },
  { 0xD3, "SMBcancelf" },
  { 0xD4, "SMBgetmac" },
  { 0xD5, "SMBsendstrt" },
  { 0xD6, "SMBsendend" },
  { 0xD7, "SMBsendtxt" },
  { 0xD8, "SMBreadbulk" },
  { 0xD9, "SMBwritebulk" },
  { 0xDA, "SMBwritebulkdata" },
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
  { 0xFE, "SMBinvalid" },
  { 0xFF, "unknown-0xFF" },
  { 0x00, NULL },
};

char *SMB_names[256] = {
  "SMBcreatedirectory",
  "SMBdeletedirectory",
  "SMBopen",
  "SMBcreate",
  "SMBclose",
  "SMBflush",
  "SMBunlink",
  "SMBmv",
  "SMBgetatr",
  "SMBsetatr",
  "SMBread",
  "SMBwrite",
  "SMBlock",
  "SMBunlock",
  "SMBctemp",
  "SMBmknew",
  "SMBchkpth",
  "SMBexit",
  "SMBlseek",
  "SMBlockread",
  "SMBwriteunlock",
  "unknown-0x15",
  "unknown-0x16",
  "unknown-0x17",
  "unknown-0x18",
  "unknown-0x19",
  "SMBreadBraw",
  "SMBreadBmpx",
  "SMBreadBs",
  "SMBwriteBraw",
  "SMBwriteBmpx",
  "SMBwriteBs",
  "SMBwriteC",
  "unknown-0x21",
  "SMBsetattrE",
  "SMBgetattrE",
  "SMBlockingX",
  "SMBtrans",
  "SMBtranss",
  "SMBioctl",
  "SMBioctls",
  "SMBcopy",
  "SMBmove",
  "SMBecho",
  "SMBwriteclose",
  "SMBopenX",
  "SMBreadX",
  "SMBwriteX",
  "unknown-0x30",
  "SMBcloseandtreedisc",
  "SMBtrans2",
  "SMBtrans2secondary",
  "SMBfindclose2",
  "SMBfindnotifyclose",
  "unknown-0x36",
  "unknown-0x37",
  "unknown-0x38",
  "unknown-0x39",
  "unknown-0x3A",
  "unknown-0x3B",
  "unknown-0x3C",
  "unknown-0x3D",
  "unknown-0x3E",
  "unknown-0x3F",
  "unknown-0x40",
  "unknown-0x41",
  "unknown-0x42",
  "unknown-0x43",
  "unknown-0x44",
  "unknown-0x45",
  "unknown-0x46",
  "unknown-0x47",
  "unknown-0x48",
  "unknown-0x49",
  "unknown-0x4A",
  "unknown-0x4B",
  "unknown-0x4C",
  "unknown-0x4D",
  "unknown-0x4E",
  "unknown-0x4F",
  "unknown-0x50",
  "unknown-0x51",
  "unknown-0x52",
  "unknown-0x53",
  "unknown-0x54",
  "unknown-0x55",
  "unknown-0x56",
  "unknown-0x57",
  "unknown-0x58",
  "unknown-0x59",
  "unknown-0x5A",
  "unknown-0x5B",
  "unknown-0x5C",
  "unknown-0x5D",
  "unknown-0x5E",
  "unknown-0x5F",
  "unknown-0x60",
  "unknown-0x61",
  "unknown-0x62",
  "unknown-0x63",
  "unknown-0x64",
  "unknown-0x65",
  "unknown-0x66",
  "unknown-0x67",
  "unknown-0x68",
  "unknown-0x69",
  "unknown-0x6A",
  "unknown-0x6B",
  "unknown-0x6C",
  "unknown-0x6D",
  "unknown-0x6E",
  "unknown-0x6F",
  "SMBtcon",
  "SMBtdis",
  "SMBnegprot",
  "SMBsesssetupX",
  "SMBlogoffX",
  "SMBtconX",
  "unknown-0x76",
  "unknown-0x77",
  "unknown-0x78",
  "unknown-0x79",
  "unknown-0x7A",
  "unknown-0x7B",
  "unknown-0x7C",
  "unknown-0x7D",
  "unknown-0x7E",
  "unknown-0x7F",
  "SMBdskattr",
  "SMBsearch",
  "SMBffirst",
  "SMBfunique",
  "SMBfclose",
  "unknown-0x85",
  "unknown-0x86",
  "unknown-0x87",
  "unknown-0x88",
  "unknown-0x89",
  "unknown-0x8A",
  "unknown-0x8B",
  "unknown-0x8C",
  "unknown-0x8D",
  "unknown-0x8E",
  "unknown-0x8F",
  "unknown-0x90",
  "unknown-0x91",
  "unknown-0x92",
  "unknown-0x93",
  "unknown-0x94",
  "unknown-0x95",
  "unknown-0x96",
  "unknown-0x97",
  "unknown-0x98",
  "unknown-0x99",
  "unknown-0x9A",
  "unknown-0x9B",
  "unknown-0x9C",
  "unknown-0x9D",
  "unknown-0x9E",
  "unknown-0x9F",
  "SMBnttransact",
  "SMBnttransactsecondary",
  "SMBntcreateX",
  "unknown-0xA3",
  "SMBntcancel",
  "unknown-0xA5",
  "unknown-0xA6",
  "unknown-0xA7",
  "unknown-0xA8",
  "unknown-0xA9",
  "unknown-0xAA",
  "unknown-0xAB",
  "unknown-0xAC",
  "unknown-0xAD",
  "unknown-0xAE",
  "unknown-0xAF",
  "unknown-0xB0",
  "unknown-0xB1",
  "unknown-0xB2",
  "unknown-0xB3",
  "unknown-0xB4",
  "unknown-0xB5",
  "unknown-0xB6",
  "unknown-0xB7",
  "unknown-0xB8",
  "unknown-0xB9",
  "unknown-0xBA",
  "unknown-0xBB",
  "unknown-0xBC",
  "unknown-0xBD",
  "unknown-0xBE",
  "unknown-0xBF",
  "SMBsplopen",
  "SMBsplwr",
  "SMBsplclose",
  "SMBsplretq",
  "unknown-0xC4",
  "unknown-0xC5",
  "unknown-0xC6",
  "unknown-0xC7",
  "unknown-0xC8",
  "unknown-0xC9",
  "unknown-0xCA",
  "unknown-0xCB",
  "unknown-0xCC",
  "unknown-0xCD",
  "unknown-0xCE",
  "unknown-0xCF",
  "SMBsends",
  "SMBsendb",
  "SMBfwdname",
  "SMBcancelf",
  "SMBgetmac",
  "SMBsendstrt",
  "SMBsendend",
  "SMBsendtxt",
  "SMBreadbulk",
  "SMBwritebulk",
  "SMBwritebulkdata",
  "unknown-0xDB",
  "unknown-0xDC",
  "unknown-0xDD",
  "unknown-0xDE",
  "unknown-0xDF",
  "unknown-0xE0",
  "unknown-0xE1",
  "unknown-0xE2",
  "unknown-0xE3",
  "unknown-0xE4",
  "unknown-0xE5",
  "unknown-0xE6",
  "unknown-0xE7",
  "unknown-0xE8",
  "unknown-0xE9",
  "unknown-0xEA",
  "unknown-0xEB",
  "unknown-0xEC",
  "unknown-0xED",
  "unknown-0xEE",
  "unknown-0xEF",
  "unknown-0xF0",
  "unknown-0xF1",
  "unknown-0xF2",
  "unknown-0xF3",
  "unknown-0xF4",
  "unknown-0xF5",
  "unknown-0xF6",
  "unknown-0xF7",
  "unknown-0xF8",
  "unknown-0xF9",
  "unknown-0xFA",
  "unknown-0xFB",
  "unknown-0xFC",
  "unknown-0xFD",
  "SMBinvalid",
  "unknown-0xFF"
};

void 
dissect_unknown_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)
{

  if (tree) {

    proto_tree_add_text(tree, NullTVB, offset, END_OF_FRAME, "Data (%u bytes)", 
			END_OF_FRAME); 

  }

}

/* 
 * Dissect a UNIX like date ...
 */

struct tm *_gtime; /* Add leading underscore ("_") to prevent symbol
                      conflict with /usr/include/time.h on some NetBSD
                      systems */

static char *
dissect_smbu_date(guint16 date, guint16 time)

{
  static char         datebuf[4+2+2+2+1+10];
  time_t              ltime = (date << 16) + time;

  _gtime = gmtime(&ltime);

  if (_gtime)
    sprintf(datebuf, "%04d-%02d-%02d",
	    1900 + (_gtime -> tm_year), 1 + (_gtime -> tm_mon), _gtime -> tm_mday);
  else 
    sprintf(datebuf, "Bad date format");

  return datebuf;

}

/*
 * Relies on time
 */
static char *
dissect_smbu_time(guint16 date, guint16 time)

{
  static char timebuf[2+2+2+2+1+10];

  if (_gtime)
    sprintf(timebuf, "%02d:%02d:%02d",
	    _gtime -> tm_hour, _gtime -> tm_min, _gtime -> tm_sec);
  else
    sprintf(timebuf, "Bad time format");

  return timebuf;

}

/*
 * Dissect a DOS-format date.
 */
static char *
dissect_dos_date(guint16 date)
{
	static char datebuf[4+2+2+1];

	sprintf(datebuf, "%04d-%02d-%02d",
	    ((date>>9)&0x7F) + 1980, (date>>5)&0x0F, date&0x1F);
	return datebuf;
}

/*
 * Dissect a DOS-format time.
 */
static char *
dissect_dos_time(guint16 time)
{
	static char timebuf[2+2+2+1];

	sprintf(timebuf, "%02d:%02d:%02d",
	    (time>>11)&0x1F, (time>>5)&0x3F, (time&0x1F)*2);
	return timebuf;
}

/* Max string length for displaying Unicode strings.  */
#define	MAX_UNICODE_STR_LEN	256

/* Turn a little-endian Unicode '\0'-terminated string into a string we
   can display.
   XXX - for now, we just handle the ISO 8859-1 characters. */
static gchar *
unicode_to_str(const guint8 *us, int *us_lenp) {
  static gchar  str[3][MAX_UNICODE_STR_LEN+3+1];
  static gchar *cur;
  gchar        *p;
  int           len;
  int           us_len;
  int           overflow = 0;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }
  p = cur;
  len = MAX_UNICODE_STR_LEN;
  us_len = 0;
  while (*us != 0 || *(us + 1) != 0) {
    if (len > 0) {
      *p++ = *us;
      len--;
    } else
      overflow = 1;
    us += 2;
    us_len += 2;
  }
  if (overflow) {
    /* Note that we're not showing the full string.  */
    *p++ = '.';
    *p++ = '.';
    *p++ = '.';
  }
  *p = '\0';
  *us_lenp = us_len;
  return cur;
}

/*
 * Each dissect routine is passed an offset to wct and works from there 
 */

void
dissect_flush_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint16       FID;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Byte Count */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count: %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_get_disk_attr_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint16       TotalUnits;
  guint16       Reserved;
  guint16       FreeUnits;
  guint16       ByteCount;
  guint16       BlocksPerUnit;
  guint16       BlockSize;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: Total Units */

      TotalUnits = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Total Units: %u", TotalUnits);

      }

      offset += 2; /* Skip Total Units */

      /* Build display for: Blocks Per Unit */

      BlocksPerUnit = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Blocks Per Unit: %u", BlocksPerUnit);

      }

      offset += 2; /* Skip Blocks Per Unit */

      /* Build display for: Block Size */

      BlockSize = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Block Size: %u", BlockSize);

      }

      offset += 2; /* Skip Block Size */

      /* Build display for: Free Units */

      FreeUnits = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Free Units: %u", FreeUnits);

      }

      offset += 2; /* Skip Free Units */

      /* Build display for: Reserved */

      Reserved = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved: %u", Reserved);

      }

      offset += 2; /* Skip Reserved */

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_set_file_attr_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  proto_tree    *Attributes_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        ByteCount;
  guint8        BufferFormat;
  guint16       Reserved5;
  guint16       Reserved4;
  guint16       Reserved3;
  guint16       Reserved2;
  guint16       Reserved1;
  guint16       LastWriteTime;
  guint16       LastWriteDate;
  guint16       Attributes;
  const char    *FileName;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: Attributes */

      Attributes = GSHORT(pd, offset);

      if (tree) {

	ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Attributes: 0x%02x", Attributes);
	Attributes_tree = proto_item_add_subtree(ti, ett_smb_fileattributes);
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x01, 16, "Read-only file", "Not a read-only file"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x02, 16, "Hidden file", "Not a hidden file"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x04, 16, "System file", "Not a system file"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x08, 16, " Volume", "Not a volume"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x10, 16, " Directory", "Not a directory"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x20, 16, " Archived", "Not archived"));
	
      }

      offset += 2; /* Skip Attributes */

      /* Build display for: Last Write Time */

      LastWriteTime = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Last Write Time: %s", dissect_dos_time(LastWriteTime));

      }

      offset += 2; /* Skip Last Write Time */

      /* Build display for: Last Write Date */

      LastWriteDate = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Last Write Date: %s", dissect_dos_date(LastWriteDate));

      }

      offset += 2; /* Skip Last Write Date */

      /* Build display for: Reserved 1 */

      Reserved1 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 1: %u", Reserved1);

      }

      offset += 2; /* Skip Reserved 1 */

      /* Build display for: Reserved 2 */

      Reserved2 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 2: %u", Reserved2);

      }

      offset += 2; /* Skip Reserved 2 */

      /* Build display for: Reserved 3 */

      Reserved3 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 3: %u", Reserved3);

      }

      offset += 2; /* Skip Reserved 3 */

      /* Build display for: Reserved 4 */

      Reserved4 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 4: %u", Reserved4);

      }

      offset += 2; /* Skip Reserved 4 */

      /* Build display for: Reserved 5 */

      Reserved5 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 5: %u", Reserved5);

      }

      offset += 2; /* Skip Reserved 5 */

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: File Name */

    FileName = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(FileName) + 1, "File Name: %s", FileName);

    }

    offset += strlen(FileName) + 1; /* Skip File Name */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 1; /* Skip Byte Count (BCC) */

  }

}

void
dissect_write_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint32       Offset;
  guint16       Remaining;
  guint16       FID;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Count */

    Count = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

    }

    offset += 2; /* Skip Count */

    /* Build display for: Offset */

    Offset = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

    }

    offset += 4; /* Skip Offset */

    /* Build display for: Remaining */

    Remaining = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Remaining: %u", Remaining);

    }

    offset += 2; /* Skip Remaining */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

    if (ByteCount > 0 && tree) {

	if(END_OF_FRAME >= ByteCount)
	    proto_tree_add_text(tree, NullTVB, offset, ByteCount, "Data (%u bytes)", ByteCount);
	else
	    proto_tree_add_text(tree, NullTVB, offset, END_OF_FRAME, "Data (first %u bytes)", END_OF_FRAME);

    }

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Count */

    Count = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

    }

    offset += 2; /* Skip Count */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_read_mpx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *arent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        Pad;
  guint32       Reserved1;
  guint32       Offset;
  guint16       Reserved2;
  guint16       Reserved;
  guint16       MinCount;
  guint16       MaxCount;
  guint16       FID;
  guint16       DataOffset;
  guint16       DataLength;
  guint16       DataCompactionMode;
  guint16       Count;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Offset */

    Offset = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

    }

    offset += 4; /* Skip Offset */

    /* Build display for: Max Count */

    MaxCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Count: %u", MaxCount);

    }

    offset += 2; /* Skip Max Count */

    /* Build display for: Min Count */

    MinCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Min Count: %u", MinCount);

    }

    offset += 2; /* Skip Min Count */

    /* Build display for: Reserved 1 */

    Reserved1 = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved 1: %u", Reserved1);

    }

    offset += 4; /* Skip Reserved 1 */

    /* Build display for: Reserved 2 */

    Reserved2 = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 2: %u", Reserved2);

    }

    offset += 2; /* Skip Reserved 2 */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count: %u", WordCount);

    }

    offset += 1; /* Skip Word Count */

    if (WordCount > 0) {

      /* Build display for: Offset */

      Offset = GWORD(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

      }

      offset += 4; /* Skip Offset */

      /* Build display for: Count */

      Count = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

      }

      offset += 2; /* Skip Count */

      /* Build display for: Reserved */

      Reserved = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved: %u", Reserved);

      }

      offset += 2; /* Skip Reserved */

      /* Build display for: Data Compaction Mode */

      DataCompactionMode = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Data Compaction Mode: %u", DataCompactionMode);

      }

      offset += 2; /* Skip Data Compaction Mode */

      /* Build display for: Reserved */

      Reserved = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved: %u", Reserved);

      }

      offset += 2; /* Skip Reserved */

      /* Build display for: Data Length */

      DataLength = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

      }

      offset += 2; /* Skip Data Length */

      /* Build display for: Data Offset */

      DataOffset = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

      }

      offset += 2; /* Skip Data Offset */

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Pad */

    Pad = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Pad: %u", Pad);

    }

    offset += 1; /* Skip Pad */

  }

}

void
dissect_delete_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *paernt, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       SearchAttributes;
  guint16       ByteCount;
  const char    *FileName;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: SearchAttributes */

    SearchAttributes = GSHORT(pd, offset);

    if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Search Attributes: %u", SearchAttributes);
    }

    offset += 2; /* Skip SearchAttributes */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: File Name */

    FileName = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(FileName) + 1, "File Name: %s", FileName);

    }

    offset += strlen(FileName) + 1; /* Skip File Name */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_query_info2_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  proto_tree    *Attributes_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint32       FileDataSize;
  guint32       FileAllocationSize;
  guint16       LastWriteTime;
  guint16       LastWriteDate;
  guint16       LastAccessTime;
  guint16       LastAccessDate;
  guint16       FID;
  guint16       CreationTime;
  guint16       CreationDate;
  guint16       ByteCount;
  guint16       Attributes;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Byte Count */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count: %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: Creation Date */

      CreationDate = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Creation Date: %s", dissect_dos_date(CreationDate));

      }

      offset += 2; /* Skip Creation Date */

      /* Build display for: Creation Time */

      CreationTime = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Creation Time: %s", dissect_dos_time(CreationTime));

      }

      offset += 2; /* Skip Creation Time */

      /* Build display for: Last Access Date */

      LastAccessDate = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Last Access Date: %s", dissect_dos_date(LastAccessDate));

      }

      offset += 2; /* Skip Last Access Date */

      /* Build display for: Last Access Time */

      LastAccessTime = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Last Access Time: %s", dissect_dos_time(LastAccessTime));

      }

      offset += 2; /* Skip Last Access Time */

      /* Build display for: Last Write Date */

      LastWriteDate = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Last Write Date: %s", dissect_dos_date(LastWriteDate));

      }

      offset += 2; /* Skip Last Write Date */

      /* Build display for: Last Write Time */

      LastWriteTime = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Last Write Time: %s", dissect_dos_time(LastWriteTime));

      }

      offset += 2; /* Skip Last Write Time */

      /* Build display for: File Data Size */

      FileDataSize = GWORD(pd, offset);

      if (tree) {
	
	proto_tree_add_text(tree, NullTVB, offset, 4, "File Data Size: %u", FileDataSize);

      }

      offset += 4; /* Skip File Data Size */

      /* Build display for: File Allocation Size */

      FileAllocationSize = GWORD(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 4, "File Allocation Size: %u", FileAllocationSize);

      }

      offset += 4; /* Skip File Allocation Size */

      /* Build display for: Attributes */

      Attributes = GSHORT(pd, offset);
      
      if (tree) {

	ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Attributes: 0x%02x", Attributes);
	Attributes_tree = proto_item_add_subtree(ti, ett_smb_fileattributes);
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x01, 16, "Read-only file", "Not a read-only file"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x02, 16, "Hidden file", "Not a hidden file"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x04, 16, "System file", "Not a system file"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x08, 16, " Volume", "Not a volume"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x10, 16, " Directory", "Not a directory"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x20, 16, " Archived", "Not archived"));
    
      }

      offset += 2; /* Skip Attributes */

    }

    /* Build display for: Byte Count */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count: %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count */

  }

}

void
dissect_treecon_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        BufferFormat3;
  guint8        BufferFormat2;
  guint8        BufferFormat1;
  guint16       TID;
  guint16       MaxBufferSize;
  guint16       ByteCount;
  const char    *SharePath;
  const char    *Service;
  const char    *Password;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: BufferFormat1 */

    BufferFormat1 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "BufferFormat1: %u", BufferFormat1);

    }

    offset += 1; /* Skip BufferFormat1 */

    /* Build display for: Share Path */

    SharePath = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(SharePath) + 1, "Share Path: %s", SharePath);

    }

    offset += strlen(SharePath) + 1; /* Skip Share Path */

    /* Build display for: BufferFormat2 */

    BufferFormat2 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "BufferFormat2: %u", BufferFormat2);

    }

    offset += 1; /* Skip BufferFormat2 */

    /* Build display for: Password */

    Password = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(Password) + 1, "Password: %s", Password);

    }

    offset += strlen(Password) + 1; /* Skip Password */

    /* Build display for: BufferFormat3 */

    BufferFormat3 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "BufferFormat3: %u", BufferFormat3);

    }

    offset += 1; /* Skip BufferFormat3 */

    /* Build display for: Service */

    Service = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(Service) + 1, "Service: %s", Service);

    }

    offset += strlen(Service) + 1; /* Skip Service */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    if (errcode != 0) return;

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Max Buffer Size */

    MaxBufferSize = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Buffer Size: %u", MaxBufferSize);

    }

    offset += 2; /* Skip Max Buffer Size */

    /* Build display for: TID */

    TID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "TID: %u", TID);

    }

    offset += 2; /* Skip TID */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

/* Generated by build-dissect.pl Vesion 0.6 27-Jun-1999, ACT */
void
dissect_ssetup_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  proto_tree    *Capabilities_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        AndXReserved;
  guint8        AndXCommand = 0xFF;
  guint32       SessionKey;
  guint32       Reserved;
  guint32       Capabilities;
  guint16       VcNumber;
  guint16       UNICODEAccountPasswordLength;
  guint16       PasswordLen;
  guint16       MaxMpxCount;
  guint16       MaxBufferSize;
  guint16       ByteCount;
  guint16       AndXOffset = 0;
  guint16       Action;
  guint16       ANSIAccountPasswordLength;
  const char    *UNICODEPassword;
  const char    *Password;
  const char    *PrimaryDomain;
  const char    *NativeOS;
  const char    *NativeLanManType;
  const char    *NativeLanMan;
  const char    *AccountName;
  const char    *ANSIPassword;

  if (dirn == 1) { /* Request(s) dissect code */

    WordCount = GBYTE(pd, offset);

    switch (WordCount) {

    case 10:

      /* Build display for: Word Count (WCT) */

      WordCount = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

      }

      offset += 1; /* Skip Word Count (WCT) */

      /* Build display for: AndXCommand */

      AndXCommand = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s", 
			    (AndXCommand == 0xFF ? "No further commands" : decode_smb_name(AndXCommand)));

      }

      offset += 1; /* Skip AndXCommand */

      /* Build display for: AndXReserved */

      AndXReserved = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

      }

      offset += 1; /* Skip AndXReserved */

      /* Build display for: AndXOffset */

      AndXOffset = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

      }

      offset += 2; /* Skip AndXOffset */

      /* Build display for: MaxBufferSize */

      MaxBufferSize = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "MaxBufferSize: %u", MaxBufferSize);

      }

      offset += 2; /* Skip MaxBufferSize */

      /* Build display for: MaxMpxCount */

      MaxMpxCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "MaxMpxCount: %u", MaxMpxCount);

      }

      offset += 2; /* Skip MaxMpxCount */

      /* Build display for: VcNumber */

      VcNumber = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "VcNumber: %u", VcNumber);

      }

      offset += 2; /* Skip VcNumber */

      /* Build display for: SessionKey */

      SessionKey = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "SessionKey: %u", SessionKey);

      }

      offset += 4; /* Skip SessionKey */

      /* Build display for: PasswordLen */

      PasswordLen = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "PasswordLen: %u", PasswordLen);

      }

      offset += 2; /* Skip PasswordLen */

      /* Build display for: Reserved */

      Reserved = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved: %u", Reserved);

      }

      offset += 4; /* Skip Reserved */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      if (ByteCount > 0) {

 	/* Build displat for: Password */

        Password = pd + offset;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, strlen(Password) + 1, "Password: %s", Password);

	}

	offset += PasswordLen;

	/* Build display for: AccountName */

	AccountName = pd + offset;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, strlen(AccountName) + 1, "AccountName: %s", AccountName);

	}

	offset += strlen(AccountName) + 1; /* Skip AccountName */

	/* Build display for: PrimaryDomain */

	PrimaryDomain = pd + offset;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, strlen(PrimaryDomain) + 1, "PrimaryDomain: %s", PrimaryDomain);

	}

	offset += strlen(PrimaryDomain) + 1; /* Skip PrimaryDomain */

	/* Build display for: NativeOS */

	NativeOS = pd + offset;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, strlen(NativeOS) + 1, "Native OS: %s", NativeOS);

	}

	offset += strlen(NativeOS) + 1; /* Skip NativeOS */

	/* Build display for: NativeLanMan */

	NativeLanMan = pd + offset;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, strlen(NativeLanMan) + 1, "Native Lan Manager: %s", NativeLanMan);

	}

	offset += strlen(NativeLanMan) + 1; /* Skip NativeLanMan */

      }

    break;

    case 13:

      /* Build display for: Word Count (WCT) */

      WordCount = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

      }

      offset += 1; /* Skip Word Count (WCT) */

      /* Build display for: AndXCommand */

      AndXCommand = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s", 
			    (AndXCommand == 0xFF ? "No further commands" : decode_smb_name(AndXCommand)));

      }

      offset += 1; /* Skip AndXCommand */

      /* Build display for: AndXReserved */

      AndXReserved = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

      }

      offset += 1; /* Skip AndXReserved */

      /* Build display for: AndXOffset */

      AndXOffset = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

      }

      offset += 2; /* Skip AndXOffset */

      /* Build display for: MaxBufferSize */

      MaxBufferSize = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "MaxBufferSize: %u", MaxBufferSize);

      }

      offset += 2; /* Skip MaxBufferSize */

      /* Build display for: MaxMpxCount */

      MaxMpxCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "MaxMpxCount: %u", MaxMpxCount);

      }

      offset += 2; /* Skip MaxMpxCount */

      /* Build display for: VcNumber */

      VcNumber = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "VcNumber: %u", VcNumber);

      }

      offset += 2; /* Skip VcNumber */

      /* Build display for: SessionKey */

      SessionKey = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "SessionKey: %u", SessionKey);

      }

      offset += 4; /* Skip SessionKey */

      /* Build display for: ANSI Account Password Length */

      ANSIAccountPasswordLength = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "ANSI Account Password Length: %u", ANSIAccountPasswordLength);

      }

      offset += 2; /* Skip ANSI Account Password Length */

      /* Build display for: UNICODE Account Password Length */

      UNICODEAccountPasswordLength = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "UNICODE Account Password Length: %u", UNICODEAccountPasswordLength);

      }

      offset += 2; /* Skip UNICODE Account Password Length */

      /* Build display for: Reserved */

      Reserved = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved: %u", Reserved);

      }

      offset += 4; /* Skip Reserved */

      /* Build display for: Capabilities */

      Capabilities = GWORD(pd, offset);

      if (tree) {

        ti = proto_tree_add_text(tree, NullTVB, offset, 4, "Capabilities: 0x%04x", Capabilities);
        Capabilities_tree = proto_item_add_subtree(ti, ett_smb_capabilities);
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0001, 32, " Raw Mode supported", " Raw Mode not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0002, 32, " Raw Mode supported", " MPX Mode not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0004, 32," Unicode supported", " Unicode not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0008, 32, " Large Files supported", " Large Files not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0010, 32, " NT LM 0.12 SMBs supported", " NT LM 0.12 SMBs not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0020, 32, " RPC Remote APIs supported", " RPC Remote APIs not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0040, 32, " NT Status Codes supported", " NT Status Codes not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0080, 32, " Level 2 OpLocks supported", " Level 2 OpLocks not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0100, 32, " Lock&Read supported", " Lock&Read not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0200, 32, " NT Find supported", " NT Find not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x1000, 32, " DFS supported", " DFS not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x4000, 32, " Large READX supported", " Large READX not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x8000, 32, " Large WRITEX supported", " Large WRITEX not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x80000000, 32, " Extended Security Exchanges supported", " Extended Security Exchanges not supported"));
      
}

      offset += 4; /* Skip Capabilities */

      /* Build display for: Byte Count */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count: %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count */

      if (ByteCount > 0) {

	  /* Build display for: ANSI Password */

	  ANSIPassword = pd + offset;

	  if (ANSIAccountPasswordLength > 0) {

	      if (tree) {

		  proto_tree_add_text(tree, NullTVB, offset, ANSIAccountPasswordLength, "ANSI Password: %s", format_text(ANSIPassword, ANSIAccountPasswordLength));

	      }

	      offset += ANSIAccountPasswordLength; /* Skip ANSI Password */
	  }

	/* Build display for: UNICODE Password */

	UNICODEPassword = pd + offset;

	if (UNICODEAccountPasswordLength > 0) {

	  if (tree) {

	    proto_tree_add_text(tree, NullTVB, offset, UNICODEAccountPasswordLength, "UNICODE Password: %s", format_text(UNICODEPassword, UNICODEAccountPasswordLength));

	  }

	  offset += UNICODEAccountPasswordLength; /* Skip UNICODE Password */

	}

	/* Build display for: Account Name */

	AccountName = pd + offset;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, strlen(AccountName) + 1, "Account Name: %s", AccountName);

	}

	offset += strlen(AccountName) + 1; /* Skip Account Name */

	/* Build display for: Primary Domain */

	PrimaryDomain = pd + offset;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, strlen(PrimaryDomain) + 1, "Primary Domain: %s", PrimaryDomain);

	}

	offset += strlen(PrimaryDomain) + 1; /* Skip Primary Domain */

	/* Build display for: Native OS */

	NativeOS = pd + offset;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, strlen(NativeOS) + 1, "Native OS: %s", NativeOS);

	}

	offset += strlen(NativeOS) + 1; /* Skip Native OS */

	/* Build display for: Native LanMan Type */

	NativeLanManType = pd + offset;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, strlen(NativeLanManType) + 1, "Native LanMan Type: %s", NativeLanManType);

	}

	offset += strlen(NativeLanManType) + 1; /* Skip Native LanMan Type */

      }

      break;

    }


    if (AndXCommand != 0xFF) {

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset, errcode, dirn);

    }

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: AndXCommand */

      AndXCommand = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s",
			    (AndXCommand == 0xFF ? "No futher commands" : decode_smb_name(AndXCommand)));

      }

      offset += 1; /* Skip AndXCommand */

      /* Build display for: AndXReserved */

      AndXReserved = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

      }

      offset += 1; /* Skip AndXReserved */

      /* Build display for: AndXOffset */

      AndXOffset = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

      }


      offset += 2; /* Skip AndXOffset */

      /* Build display for: Action */

      Action = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Action: %u", Action);

      }

      offset += 2; /* Skip Action */

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    if (errcode != 0 && WordCount == 0xFF) return;  /* No more here ... */

    offset += 2; /* Skip Byte Count (BCC) */

    if (ByteCount > 0) {

      /* Build display for: NativeOS */

      NativeOS = pd + offset;

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, strlen(NativeOS) + 1, "NativeOS: %s", NativeOS);

      }

      offset += strlen(NativeOS) + 1; /* Skip NativeOS */

      /* Build display for: NativeLanMan */

      NativeLanMan = pd + offset;

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, strlen(NativeLanMan) + 1, "NativeLanMan: %s", NativeLanMan);

      }

      offset += strlen(NativeLanMan) + 1; /* Skip NativeLanMan */

      /* Build display for: PrimaryDomain */

      PrimaryDomain = pd + offset;

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, strlen(PrimaryDomain) + 1, "PrimaryDomain: %s", PrimaryDomain);

      }

      offset += strlen(PrimaryDomain) + 1; /* Skip PrimaryDomain */

    }

    if (AndXCommand != 0xFF) {

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset, errcode, dirn);

    }

  }

}

void
dissect_tcon_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8      wct, andxcmd = 0xFF;
  guint16     andxoffs = 0, flags, passwdlen, bcc, optionsup;
  const char  *str;
  proto_tree  *flags_tree;
  proto_item  *ti;

  wct = pd[offset];

  /* Now figure out what format we are talking about, 2, 3, or 4 response
   * words ...
   */

  if (!((dirn == 1) && (wct == 4)) && !((dirn == 0) && (wct == 2)) &&
      !((dirn == 0) && (wct == 3)) && !(wct == 0)) {

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Invalid TCON_ANDX format. WCT should be 0, 2, 3, or 4 ..., not %u", wct);

      proto_tree_add_text(tree, NullTVB, offset, END_OF_FRAME, "Data");

      return;

    }
    
  }

  if (tree) {

    proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", wct);

  }

  offset += 1;

  if (wct > 0) {

    andxcmd = pd[offset];

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Next Command: %s",
			  (andxcmd == 0xFF) ? "No further commands":
			  decode_smb_name(andxcmd));
		
      proto_tree_add_text(tree, NullTVB, offset + 1, 1, "Reserved (MBZ): %u", pd[offset+1]);

    }

    offset += 2;

    andxoffs = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Offset to next command: %u", andxoffs);

    }

    offset += 2;

  }

  switch (wct) {

  case 0:

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    break;

  case 4:

    flags = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Additional Flags: 0x%02x", flags);
      flags_tree = proto_item_add_subtree(ti, ett_smb_aflags);
      proto_tree_add_text(flags_tree, NullTVB, offset, 2, "%s", 
			  decode_boolean_bitfield(flags, 0x01, 16,
						  "Disconnect TID",
						  "Don't disconnect TID"));

    }

    offset += 2;

    passwdlen = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Password Length: %u", passwdlen);

    }

    offset += 2;

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2;

    str = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(str) + 1, "Password: %s", format_text(str, passwdlen));

    }

    offset += passwdlen;

    str = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(str) + 1, "Path: %s", str);

    }

    offset += strlen(str) + 1;

    str = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(str) + 1, "Service: %s", str);

    }

    break;

  case 2:

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2;

    str = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(str) + 1, "Service Type: %s",
			  str);

    }

    offset += strlen(str) + 1;

    break;

  case 3:

    optionsup = GSHORT(pd, offset);

    if (tree) {  /* Should break out the bits */

      proto_tree_add_text(tree, NullTVB, offset, 2, "Optional Support: 0x%04x", 
			  optionsup);

    }

    offset += 2;

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2;

    str = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(str) + 1, "Service: %s", str);

    }

    offset += strlen(str) + 1;

    str = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(str) + 1, "Native File System: %s", str);

    }

    offset += strlen(str) + 1;

    
    break;

  default:
	; /* nothing */
	break;
  }

  if (andxcmd != 0xFF) /* Process that next command ... ??? */

    (dissect[andxcmd])(pd, SMB_offset + andxoffs, fd, parent, tree, si, max_data - offset, SMB_offset, errcode, dirn);

}

void 
dissect_negprot_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)
{
  guint8        wct, enckeylen;
  guint16       bcc, mode, rawmode, dialect;
  guint32       caps;
  proto_tree    *dialects = NULL, *mode_tree, *caps_tree, *rawmode_tree;
  proto_item    *ti;
  const char    *str;
  char          *ustr;
  int           ustr_len;

  wct = pd[offset];    /* Should be 0, 1 or 13 or 17, I think */

  if (!((wct == 0) && (dirn == 1)) && !((wct == 1) && (dirn == 0)) &&
      !((wct == 13) && (dirn == 0)) && !((wct == 17) && (dirn == 0))) {
    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Invalid Negotiate Protocol format. WCT should be zero or 1 or 13 or 17 ..., not %u", wct);

      proto_tree_add_text(tree, NullTVB, offset, END_OF_FRAME, "Data");

      return;
    }
  }

  if (tree) {

    proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %d", wct);

  }

  if (dirn == 0 && errcode != 0) return;  /* No more info ... */

  offset += 1; 

  /* Now decode the various formats ... */

  switch (wct) {

  case 0:     /* A request */

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2;

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, END_OF_FRAME, "Dialects");
      dialects = proto_item_add_subtree(ti, ett_smb_dialects);

    }

    while (IS_DATA_IN_FRAME(offset)) {
      const char *str;

      if (tree) {

	proto_tree_add_text(dialects, NullTVB, offset, 1, "Dialect Marker: %d", pd[offset]);

      }

      offset += 1;

      str = pd + offset;

      if (tree) {

	proto_tree_add_text(dialects, NullTVB, offset, strlen(str)+1, "Dialect: %s", str);

      }

      offset += strlen(str) + 1;

    }
    break;

  case 1:     /* PC NETWORK PROGRAM 1.0 */

    dialect = GSHORT(pd, offset);

    if (tree) {  /* Hmmmm, what if none of the dialects is recognized */

      if (dialect == 0xFFFF) { /* Server didn't like them dialects */

	proto_tree_add_text(tree, NullTVB, offset, 2, "Supplied dialects not recognized");

      }
      else {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Dialect Index: %u, PC NETWORK PROTGRAM 1.0", dialect);

      }

    }

    offset += 2;

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    break;

  case 13:    /* Greater than Core and up to and incl LANMAN2.1  */

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Dialect Index: %u, Greater than CORE PROTOCOL and up to LANMAN2.1", GSHORT(pd, offset));

    }

    /* Much of this is similar to response 17 below */

    offset += 2;

    mode = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Security Mode: 0x%04x", mode);
      mode_tree = proto_item_add_subtree(ti, ett_smb_mode);
      proto_tree_add_text(mode_tree, NullTVB, offset, 2, "%s",
			  decode_boolean_bitfield(mode, 0x0001, 16,
						  "Security  = User",
						  "Security  = Share"));
      proto_tree_add_text(mode_tree, NullTVB, offset, 2, "%s",
			  decode_boolean_bitfield(mode, 0x0002, 16,
						  "Passwords = Encrypted",
						  "Passwords = Plaintext"));

    }

    offset += 2;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max buffer size:     %u", GSHORT(pd, offset));

    }

    offset += 2;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max multiplex count: %u", GSHORT(pd, offset));

    }
    
    offset += 2;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max vcs:             %u", GSHORT(pd, offset));

    }

    offset += 2;

    rawmode = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Raw Mode: 0x%04x", rawmode);
      rawmode_tree = proto_item_add_subtree(ti, ett_smb_rawmode);
      proto_tree_add_text(rawmode_tree, NullTVB, offset, 2, "%s",
			  decode_boolean_bitfield(rawmode, 0x01, 16,
						  "Read Raw supported",
						  "Read Raw not supported"));
      proto_tree_add_text(rawmode_tree, NullTVB, offset, 2, "%s",
			  decode_boolean_bitfield(rawmode, 0x02, 16,
						  "Write Raw supported",
						  "Write Raw not supported"));

    }

    offset += 2;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Session key:         %08x", GWORD(pd, offset));

    }

    offset += 4;

    /* Now the server time, two short parameters ... */

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Server Time: %s",
			dissect_dos_time(GSHORT(pd, offset)));
      proto_tree_add_text(tree, NullTVB, offset + 2, 2, "Server Date: %s",
			dissect_dos_date(GSHORT(pd, offset + 2)));

    }

    offset += 4;

    /* Server Time Zone, SHORT */

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Server time zone: %i min from UTC",
			  (signed)GSSHORT(pd, offset));

    }

    offset += 2;

    /* Challenge Length */

    enckeylen = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Challenge Length: %u", enckeylen);

    }

    offset += 2;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved: %u (MBZ)", GSHORT(pd, offset));

    }

    offset += 2;

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2;

    if (enckeylen) { /* only if non-zero key len */

      str = pd + offset;

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, enckeylen, "Challenge: %s",
				bytes_to_str(str, enckeylen));
      }

      offset += enckeylen;

    }

    /* Primary Domain ... */

    str = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(str)+1, "Primary Domain: %s", str);

    }

    break;

  case 17:    /* Greater than LANMAN2.1 */

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Dialect Index: %u, Greater than LANMAN2.1", GSHORT(pd, offset));

    }

    offset += 2;

    mode = GBYTE(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 1, "Security Mode: 0x%02x", mode);
      mode_tree = proto_item_add_subtree(ti, ett_smb_mode);
      proto_tree_add_text(mode_tree, NullTVB, offset, 1, "%s",
			  decode_boolean_bitfield(mode, 0x01, 8,
						  "Security  = User",
						  "Security  = Share"));
      proto_tree_add_text(mode_tree, NullTVB, offset, 1, "%s",
			  decode_boolean_bitfield(mode, 0x02, 8,
						  "Passwords = Encrypted",
						  "Passwords = Plaintext"));
      proto_tree_add_text(mode_tree, NullTVB, offset, 1, "%s",
			  decode_boolean_bitfield(mode, 0x04, 8,
						  "Security signatures enabled",
						  "Security signatures not enabled"));
      proto_tree_add_text(mode_tree, NullTVB, offset, 1, "%s",
			  decode_boolean_bitfield(mode, 0x08, 8,
						  "Security signatures required",
						  "Security signatures not required"));

    }

    offset += 1;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max multiplex count: %u", GSHORT(pd, offset));

    }
    
    offset += 2;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max vcs:             %u", GSHORT(pd, offset));

    }

    offset += 2;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max buffer size:     %u", GWORD(pd, offset));

    }

    offset += 4;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Max raw size:        %u", GWORD(pd, offset));

    }

    offset += 4;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Session key:         %08x", GWORD(pd, offset));

    }

    offset += 4;

    caps = GWORD(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 4, "Capabilities: 0x%04x", caps);
      caps_tree = proto_item_add_subtree(ti, ett_smb_capabilities);
      proto_tree_add_text(caps_tree, NullTVB, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0001, 32,
						  "Raw Mode supported",
						  "Raw Mode not supported"));
      proto_tree_add_text(caps_tree, NullTVB, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0002, 32,
						  "MPX Mode supported",
						  "MPX Mode not supported"));
      proto_tree_add_text(caps_tree, NullTVB, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0004, 32,
						  "Unicode supported",
						  "Unicode not supported"));
      proto_tree_add_text(caps_tree, NullTVB, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0008, 32,
						  "Large files supported",
						  "Large files not supported"));
      proto_tree_add_text(caps_tree, NullTVB, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0010, 32, 
						  "NT LM 0.12 SMBs supported",
						  "NT LM 0.12 SMBs not supported"));
      proto_tree_add_text(caps_tree, NullTVB, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0020, 32,
						  "RPC remote APIs supported",
						  "RPC remote APIs not supported"));
      proto_tree_add_text(caps_tree, NullTVB, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0040, 32,
						  "NT status codes supported",
						  "NT status codes  not supported"));
      proto_tree_add_text(caps_tree, NullTVB, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0080, 32,
						  "Level 2 OpLocks supported",
						  "Level 2 OpLocks not supported"));
      proto_tree_add_text(caps_tree, NullTVB, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0100, 32,
						  "Lock&Read supported",
						  "Lock&Read not supported"));
      proto_tree_add_text(caps_tree, NullTVB, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0200, 32,
						  "NT Find supported",
						  "NT Find not supported"));
      proto_tree_add_text(caps_tree, NullTVB, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x1000, 32,
						  "DFS supported",
						  "DFS not supported"));
      proto_tree_add_text(caps_tree, NullTVB, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x4000, 32,
						  "Large READX supported",
						  "Large READX not supported"));
      proto_tree_add_text(caps_tree, NullTVB, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x8000, 32,
						  "Large WRITEX supported",
						  "Large WRITEX not supported"));
      proto_tree_add_text(caps_tree, NullTVB, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x80000000, 32,
						  "Extended security exchanges supported",
						  "Extended security exchanges not supported"));
    }

    offset += 4;

    /* Server time, 2 WORDS */

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "System Time Low: 0x%08x", GWORD(pd, offset));
      proto_tree_add_text(tree, NullTVB, offset + 4, 4, "System Time High: 0x%08x", GWORD(pd, offset + 4)); 

    }

    offset += 8;

    /* Server Time Zone, SHORT */

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Server time zone: %i min from UTC",
			  (signed)GSSHORT(pd, offset));

    }

    offset += 2;

    /* Encryption key len */

    enckeylen = pd[offset];

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Encryption key len: %u", enckeylen);

    }

    offset += 1;

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte count (BCC): %u", bcc);

    }

    offset += 2;

    if (enckeylen) { /* only if non-zero key len */

      /* Encryption challenge key */

      str = pd + offset;

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, enckeylen, "Challenge encryption key: %s",
				bytes_to_str(str, enckeylen));

      }

      offset += enckeylen;

    }

    /* The domain, a null terminated string; Unicode if "caps" has
       the 0x0004 bit set, ASCII (OEM character set) otherwise.
       XXX - for now, we just handle the ISO 8859-1 subset of Unicode. */

    str = pd + offset;

    if (tree) {

      if (caps & 0x0004) {
      	ustr = unicode_to_str(str, &ustr_len);
	proto_tree_add_text(tree, NullTVB, offset, ustr_len+2, "OEM domain name: %s", ustr);
      } else {
	proto_tree_add_text(tree, NullTVB, offset, strlen(str)+1, "OEM domain name: %s", str);
      }

    }

    break;

  default:    /* Baddd */

    if (tree)
      proto_tree_add_text(tree, NullTVB, offset, 1, "Bad format, should never get here");
    return;

  }

}

void
dissect_deletedir_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       ByteCount;
  const char    *DirectoryName;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Directory Name */

    DirectoryName = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(DirectoryName) + 1, "Directory Name: %s", DirectoryName);

    }

    offset += strlen(DirectoryName) + 1; /* Skip Directory Name */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_createdir_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       ByteCount;
  const char    *DirectoryName;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Directory Name */

    DirectoryName = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(DirectoryName) + 1, "Directory Name: %s", DirectoryName);

    }

    offset += strlen(DirectoryName) + 1; /* Skip Directory Name */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}


void
dissect_checkdir_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       ByteCount;
  const char    *DirectoryName;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Directory Name */

    DirectoryName = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(DirectoryName) + 1, "Directory Name: %s", DirectoryName);

    }

    offset += strlen(DirectoryName) + 1; /* Skip Directory Name */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_open_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  static const value_string OpenFunction_0x10[] = {
	{ 0, "Fail if file does not exist"},
	{ 16, "Create file if it does not exist"},
	{ 0, NULL}
  };
  static const value_string OpenFunction_0x03[] = {
	{ 0, "Fail if file exists"},
	{ 1, "Open file if it exists"},
	{ 2, "Truncate File if it exists"},
	{ 0, NULL}
  };
  static const value_string FileType_0xFFFF[] = {
	{ 0, "Disk file or directory"},
	{ 1, "Named pipe in byte mode"},
	{ 2, "Named pipe in message mode"},
	{ 3, "Spooled printer"},
	{ 0, NULL}
  };
  static const value_string DesiredAccess_0x70[] = {
	{ 00, "Compatibility mode"},
	{ 16, "Deny read/write/execute (exclusive)"},
	{ 32, "Deny write"},
	{ 48, "Deny read/execute"},
	{ 64, "Deny none"},
	{ 0, NULL}
  };
  static const value_string DesiredAccess_0x700[] = {
	{ 0, "Locality of reference unknown"},
	{ 256, "Mainly sequential access"},
	{ 512, "Mainly random access"},
	{ 768, "Random access with some locality"},
	{0, NULL}
  };
  static const value_string DesiredAccess_0x4000[] = {
	{ 0, "Write through mode disabled"},
	{ 16384, "Write through mode enabled"},
	{0, NULL}
  };
  static const value_string DesiredAccess_0x1000[] = {
	{ 0, "Normal file (caching permitted)"},
	{ 4096, "Do not cache this file"},
	{0, NULL}
  };
  static const value_string DesiredAccess_0x07[] = {
	{ 0, "Open for reading"},
	{ 1, "Open for writing"},
	{ 2, "Open for reading and writing"},
	{ 3, "Open for execute"},
	{0, NULL}
  };
  static const value_string Action_0x8000[] = {
	{ 0, "File opened by another user (or mode not supported by server)"},
	{ 32768, "File is opened only by this user at present"},
	{0, NULL}
  };
  static const value_string Action_0x0003[] = {
	{ 0, "No action taken?"},
	{ 1, "The file existed and was opened"},
	{ 2, "The file did not exist but was created"},
	{ 3, "The file existed and was truncated"},
	{0, NULL}
  };
  proto_tree    *Search_tree;
  proto_tree    *OpenFunction_tree;
  proto_tree    *Flags_tree;
  proto_tree    *File_tree;
  proto_tree    *FileType_tree;
  proto_tree    *FileAttributes_tree;
  proto_tree    *DesiredAccess_tree;
  proto_tree    *Action_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        AndXReserved;
  guint8        AndXCommand = 0xFF;
  guint32       ServerFID;
  guint32       Reserved2;
  guint32       Reserved1;
  guint32       DataSize;
  guint32       AllocatedSize;
  guint16       Search;
  guint16       Reserved;
  guint16       OpenFunction;
  guint16       LastWriteTime;
  guint16       LastWriteDate;
  guint16       GrantedAccess;
  guint16       Flags;
  guint16       FileType;
  guint16       FileAttributes;
  guint16       File;
  guint16       FID;
  guint16       DeviceState;
  guint16       DesiredAccess;
  guint16       CreationTime;
  guint16       CreationDate;
  guint16       ByteCount;
  guint16       AndXOffset = 0;
  guint16       Action;
  const char    *FileName;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: AndXCommand */

    AndXCommand = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s", 
			  (AndXCommand == 0xFF ? "No further commands" : decode_smb_name(AndXCommand)));

    }

    offset += 1; /* Skip AndXCommand */

    /* Build display for: AndXReserved */

    AndXReserved = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

    }

    offset += 1; /* Skip AndXReserved */

    /* Build display for: AndXOffset */

    AndXOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

    }

    offset += 2; /* Skip AndXOffset */

    /* Build display for: Flags */

    Flags = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Flags: 0x%02x", Flags);
      Flags_tree = proto_item_add_subtree(ti, ett_smb_flags);
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Flags, 0x01, 16, "Dont Return Additional Info", "Return Additional Info"));
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Flags, 0x02, 16, "Exclusive OpLock not Requested", "Exclusive OpLock Requested"));
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Flags, 0x04, 16, "Batch OpLock not Requested", "Batch OpLock Requested"));
    
}

    offset += 2; /* Skip Flags */

    /* Build display for: Desired Access */

    DesiredAccess = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Desired Access: 0x%02x", DesiredAccess);
      DesiredAccess_tree = proto_item_add_subtree(ti, ett_smb_desiredaccess);
      proto_tree_add_text(DesiredAccess_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(DesiredAccess, 0x07, 16, DesiredAccess_0x07, "%s"));
      proto_tree_add_text(DesiredAccess_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(DesiredAccess, 0x70, 16, DesiredAccess_0x70, "%s"));
      proto_tree_add_text(DesiredAccess_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(DesiredAccess, 0x700, 16, DesiredAccess_0x700, "%s"));
      proto_tree_add_text(DesiredAccess_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(DesiredAccess, 0x1000, 16, DesiredAccess_0x1000, "%s"));
      proto_tree_add_text(DesiredAccess_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(DesiredAccess, 0x4000, 16, DesiredAccess_0x4000, "%s"));
    
}

    offset += 2; /* Skip Desired Access */

    /* Build display for: Search */

    Search = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Search: 0x%02x", Search);
      Search_tree = proto_item_add_subtree(ti, ett_smb_search);
      proto_tree_add_text(Search_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Search, 0x01, 16, "Read only file", "Not a read only file"));
      proto_tree_add_text(Search_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Search, 0x02, 16, "Hidden file", "Not a hidden file"));
      proto_tree_add_text(Search_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Search, 0x04, 16, "System file", "Not a system file"));
      proto_tree_add_text(Search_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Search, 0x08, 16, " Volume", "Not a volume"));
      proto_tree_add_text(Search_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Search, 0x10, 16, " Directory", "Not a directory"));
      proto_tree_add_text(Search_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Search, 0x20, 16, "Archive file", "Do not archive file"));
    
}

    offset += 2; /* Skip Search */

    /* Build display for: File */

    File = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "File: 0x%02x", File);
      File_tree = proto_item_add_subtree(ti, ett_smb_file);
      proto_tree_add_text(File_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(File, 0x01, 16, "Read only file", "Not a read only file"));
      proto_tree_add_text(File_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(File, 0x02, 16, "Hidden file", "Not a hidden file"));
      proto_tree_add_text(File_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(File, 0x04, 16, "System file", "Not a system file"));
      proto_tree_add_text(File_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(File, 0x08, 16, " Volume", "Not a volume"));
      proto_tree_add_text(File_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(File, 0x10, 16, " Directory", "Not a directory"));
      proto_tree_add_text(File_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(File, 0x20, 16, "Archive file", "Do not archive file"));
    
}

    offset += 2; /* Skip File */

    /* Build display for: Creation Time */

    CreationTime = GSHORT(pd, offset);

    if (tree) {


    }

    offset += 2; /* Skip Creation Time */

    /* Build display for: Creation Date */

    CreationDate = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Creation Date: %s", dissect_smbu_date(CreationDate, CreationTime));
      proto_tree_add_text(tree, NullTVB, offset, 2, "Creation Time: %s", dissect_smbu_time(CreationDate, CreationTime));

    }

    offset += 2; /* Skip Creation Date */

    /* Build display for: Open Function */

    OpenFunction = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Open Function: 0x%02x", OpenFunction);
      OpenFunction_tree = proto_item_add_subtree(ti, ett_smb_openfunction);
      proto_tree_add_text(OpenFunction_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(OpenFunction, 0x10, 16, OpenFunction_0x10, "%s"));
      proto_tree_add_text(OpenFunction_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(OpenFunction, 0x03, 16, OpenFunction_0x03, "%s"));
    
}

    offset += 2; /* Skip Open Function */

    /* Build display for: Allocated Size */

    AllocatedSize = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Allocated Size: %u", AllocatedSize);

    }

    offset += 4; /* Skip Allocated Size */

    /* Build display for: Reserved1 */

    Reserved1 = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved1: %u", Reserved1);

    }

    offset += 4; /* Skip Reserved1 */

    /* Build display for: Reserved2 */

    Reserved2 = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved2: %u", Reserved2);

    }

    offset += 4; /* Skip Reserved2 */

    /* Build display for: Byte Count */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count: %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count */

    /* Build display for: File Name */

    FileName = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(FileName) + 1, "File Name: %s", FileName);

    }

    offset += strlen(FileName) + 1; /* Skip File Name */


    if (AndXCommand != 0xFF) {

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset, errcode, dirn);

    }

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: AndXCommand */

      AndXCommand = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s", 
			    (AndXCommand == 0xFF ? "No further commands" : decode_smb_name(AndXCommand)));

      }

      offset += 1; /* Skip AndXCommand */

      /* Build display for: AndXReserved */

      AndXReserved = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

      }

      offset += 1; /* Skip AndXReserved */

      /* Build display for: AndXOffset */

      AndXOffset = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

      }

      offset += 2; /* Skip AndXOffset */

      /* Build display for: FID */

      FID = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

      }

      offset += 2; /* Skip FID */

      /* Build display for: FileAttributes */

      FileAttributes = GSHORT(pd, offset);

      if (tree) {

	ti = proto_tree_add_text(tree, NullTVB, offset, 2, "FileAttributes: 0x%02x", FileAttributes);
	FileAttributes_tree = proto_item_add_subtree(ti, ett_smb_fileattributes);
	proto_tree_add_text(FileAttributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(FileAttributes, 0x01, 16, "Read only file", "Not a read only file"));
	proto_tree_add_text(FileAttributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(FileAttributes, 0x02, 16, "Hidden file", "Not a hidden file"));
	proto_tree_add_text(FileAttributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(FileAttributes, 0x04, 16, "System file", "Not a system file"));
	proto_tree_add_text(FileAttributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(FileAttributes, 0x08, 16, " Volume", "Not a volume"));
	proto_tree_add_text(FileAttributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(FileAttributes, 0x10, 16, " Directory", "Not a directory"));
	proto_tree_add_text(FileAttributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(FileAttributes, 0x20, 16, "Archive file", "Do not archive file"));
    
      }

      offset += 2; /* Skip FileAttributes */

      /* Build display for: Last Write Time */

      LastWriteTime = GSHORT(pd, offset);

      if (tree) {

      }

      offset += 2; /* Skip Last Write Time */

      /* Build display for: Last Write Date */

      LastWriteDate = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Last Write Date: %s", dissect_smbu_date(LastWriteDate, LastWriteTime));
	proto_tree_add_text(tree, NullTVB, offset, 2, "Last Write Time: %s", dissect_smbu_time(LastWriteDate, LastWriteTime));


      }

      offset += 2; /* Skip Last Write Date */

      /* Build display for: Data Size */

      DataSize = GWORD(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 4, "Data Size: %u", DataSize);

      }

      offset += 4; /* Skip Data Size */

      /* Build display for: Granted Access */

      GrantedAccess = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Granted Access: %u", GrantedAccess);

      }

      offset += 2; /* Skip Granted Access */

      /* Build display for: File Type */

      FileType = GSHORT(pd, offset);

      if (tree) {

	ti = proto_tree_add_text(tree, NullTVB, offset, 2, "File Type: 0x%02x", FileType);
	FileType_tree = proto_item_add_subtree(ti, ett_smb_filetype);
	proto_tree_add_text(FileType_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(FileType, 0xFFFF, 16, FileType_0xFFFF, "%s"));
    
      }

      offset += 2; /* Skip File Type */

      /* Build display for: Device State */

      DeviceState = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Device State: %u", DeviceState);

      }

      offset += 2; /* Skip Device State */

      /* Build display for: Action */

      Action = GSHORT(pd, offset);

      if (tree) {

	ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Action: 0x%02x", Action);
	Action_tree = proto_item_add_subtree(ti, ett_smb_action);
	proto_tree_add_text(Action_tree, NullTVB, offset, 2, "%s",
			    decode_enumerated_bitfield(Action, 0x8000, 16, Action_0x8000, "%s"));
	proto_tree_add_text(Action_tree, NullTVB, offset, 2, "%s",
			    decode_enumerated_bitfield(Action, 0x0003, 16, Action_0x0003, "%s"));
	
      }
      
      offset += 2; /* Skip Action */

      /* Build display for: Server FID */
      
      ServerFID = GWORD(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 4, "Server FID: %u", ServerFID);

      }

      offset += 4; /* Skip Server FID */

      /* Build display for: Reserved */

      Reserved = GSHORT(pd, offset);

      if (tree) {
	
	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved: %u", Reserved);

      }

      offset += 2; /* Skip Reserved */

    }

    /* Build display for: Byte Count */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count: %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count */


    if (AndXCommand != 0xFF) {

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset, errcode, dirn);

    }

  }

}

void
dissect_write_raw_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  proto_tree    *WriteMode_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        Pad;
  guint32       Timeout;
  guint32       Reserved2;
  guint32       Offset;
  guint16       WriteMode;
  guint16       Reserved1;
  guint16       Remaining;
  guint16       FID;
  guint16       DataOffset;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    WordCount = GBYTE(pd, offset);

    switch (WordCount) {

    case 12:

      /* Build display for: Word Count (WCT) */

      WordCount = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

      }

      offset += 1; /* Skip Word Count (WCT) */

      /* Build display for: FID */

      FID = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

      }

      offset += 2; /* Skip FID */

      /* Build display for: Count */

      Count = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

      }

      offset += 2; /* Skip Count */

      /* Build display for: Reserved 1 */

      Reserved1 = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 1: %u", Reserved1);

      }

      offset += 2; /* Skip Reserved 1 */

      /* Build display for: Offset */

      Offset = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

      }

      offset += 4; /* Skip Offset */

      /* Build display for: Timeout */

      Timeout = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Timeout: %u", Timeout);

      }

      offset += 4; /* Skip Timeout */

      /* Build display for: WriteMode */

      WriteMode = GSHORT(pd, offset);

      if (tree) {

        ti = proto_tree_add_text(tree, NullTVB, offset, 2, "WriteMode: 0x%02x", WriteMode);
        WriteMode_tree = proto_item_add_subtree(ti, ett_smb_writemode);
        proto_tree_add_text(WriteMode_tree, NullTVB, offset, 2, "%s",
                            decode_boolean_bitfield(WriteMode, 0x01, 16, "Write through requested", "Write through not requested"));
        proto_tree_add_text(WriteMode_tree, NullTVB, offset, 2, "%s",
                            decode_boolean_bitfield(WriteMode, 0x02, 16, "Return Remaining (pipe/dev)", "Dont return Remaining (pipe/dev)"));
      
}

      offset += 2; /* Skip WriteMode */

      /* Build display for: Reserved 2 */

      Reserved2 = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved 2: %u", Reserved2);

      }

      offset += 4; /* Skip Reserved 2 */

      /* Build display for: Data Length */

      DataLength = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

      }

      offset += 2; /* Skip Data Length */

      /* Build display for: Data Offset */

      DataOffset = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

      }

      offset += 2; /* Skip Data Offset */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      /* Build display for: Pad */

      Pad = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "Pad: %u", Pad);

      }

      offset += 1; /* Skip Pad */

    break;

    case 14:

      /* Build display for: Word Count (WCT) */

      WordCount = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

      }

      offset += 1; /* Skip Word Count (WCT) */

      /* Build display for: FID */

      FID = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

      }

      offset += 2; /* Skip FID */

      /* Build display for: Count */

      Count = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

      }

      offset += 2; /* Skip Count */

      /* Build display for: Reserved 1 */

      Reserved1 = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 1: %u", Reserved1);

      }

      offset += 2; /* Skip Reserved 1 */

      /* Build display for: Timeout */

      Timeout = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Timeout: %u", Timeout);

      }

      offset += 4; /* Skip Timeout */

      /* Build display for: WriteMode */

      WriteMode = GSHORT(pd, offset);

      if (tree) {

        ti = proto_tree_add_text(tree, NullTVB, offset, 2, "WriteMode: 0x%02x", WriteMode);
        WriteMode_tree = proto_item_add_subtree(ti, ett_smb_writemode);
        proto_tree_add_text(WriteMode_tree, NullTVB, offset, 2, "%s",
                            decode_boolean_bitfield(WriteMode, 0x01, 16, "Write through requested", "Write through not requested"));
        proto_tree_add_text(WriteMode_tree, NullTVB, offset, 2, "%s",
                            decode_boolean_bitfield(WriteMode, 0x02, 16, "Return Remaining (pipe/dev)", "Dont return Remaining (pipe/dev)"));
      
}

      offset += 2; /* Skip WriteMode */

      /* Build display for: Reserved 2 */

      Reserved2 = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved 2: %u", Reserved2);

      }

      offset += 4; /* Skip Reserved 2 */

      /* Build display for: Data Length */

      DataLength = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

      }

      offset += 2; /* Skip Data Length */

      /* Build display for: Data Offset */

      DataOffset = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

      }

      offset += 2; /* Skip Data Offset */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      /* Build display for: Pad */

      Pad = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "Pad: %u", Pad);

      }

      offset += 1; /* Skip Pad */

    break;

    }

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: Remaining */

      Remaining = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Remaining: %u", Remaining);

      }

      offset += 2; /* Skip Remaining */

    }

    /* Build display for: Byte Count */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count: %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count */

  }

}

void
dissect_tdis_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_move_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  static const value_string Flags_0x03[] = {
	{ 0, "Target must be a file"},
	{ 1, "Target must be a directory"},
	{ 2, "Reserved"},
	{ 3, "Reserved"},
	{ 4, "Verify all writes"},
	{ 0, NULL}
};
  proto_tree    *Flags_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        ErrorFileFormat;
  guint16       TID2;
  guint16       OpenFunction;
  guint16       Flags;
  guint16       Count;
  guint16       ByteCount;
  const char    *ErrorFileName;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: TID2 */

    TID2 = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "TID2: %u", TID2);

    }

    offset += 2; /* Skip TID2 */

    /* Build display for: Open Function */

    OpenFunction = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Open Function: %u", OpenFunction);

    }

    offset += 2; /* Skip Open Function */

    /* Build display for: Flags */

    Flags = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Flags: 0x%02x", Flags);
      Flags_tree = proto_item_add_subtree(ti, ett_smb_flags);
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(Flags, 0x03, 16, Flags_0x03, "%s"));
    
}

    offset += 2; /* Skip Flags */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: Count */

      Count = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

      }

      offset += 2; /* Skip Count */

    }

    /* Build display for: Byte Count */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count: %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count */

    /* Build display for: Error File Format */

    ErrorFileFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Error File Format: %u", ErrorFileFormat);

    }

    offset += 1; /* Skip Error File Format */

    /* Build display for: Error File Name */

    ErrorFileName = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(ErrorFileName) + 1, "Error File Name: %s", ErrorFileName);

    }

    offset += strlen(ErrorFileName) + 1; /* Skip Error File Name */

  }

}

void
dissect_rename_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        BufferFormat2;
  guint8        BufferFormat1;
  guint16       SearchAttributes;
  guint16       ByteCount;
  const char    *OldFileName;
  const char    *NewFileName;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Search Attributes */

    SearchAttributes = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Search Attributes: %u", SearchAttributes);

    }

    offset += 2; /* Skip Search Attributes */

    /* Build display for: Byte Count */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count: %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count */

    /* Build display for: Buffer Format 1 */

    BufferFormat1 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format 1: %u", BufferFormat1);

    }

    offset += 1; /* Skip Buffer Format 1 */

    /* Build display for: Old File Name */

    OldFileName = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(OldFileName) + 1, "Old File Name: %s", OldFileName);

    }

    offset += strlen(OldFileName) + 1; /* Skip Old File Name */

    /* Build display for: Buffer Format 2 */

    BufferFormat2 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format 2: %u", BufferFormat2);

    }

    offset += 1; /* Skip Buffer Format 2 */

    /* Build display for: New File Name */

    NewFileName = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(NewFileName) + 1, "New File Name: %s", NewFileName);

    }

    offset += strlen(NewFileName) + 1; /* Skip New File Name */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_open_print_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  static const value_string Mode_0x03[] = {
	{ 0, "Text mode (DOS expands TABs)"},
	{ 1, "Graphics mode"},
	{ 0, NULL}
};
  proto_tree    *Mode_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       SetupLength;
  guint16       Mode;
  guint16       FID;
  guint16       ByteCount;
  const char    *IdentifierString;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Setup Length */

    SetupLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Setup Length: %u", SetupLength);

    }

    offset += 2; /* Skip Setup Length */

    /* Build display for: Mode */

    Mode = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Mode: 0x%02x", Mode);
      Mode_tree = proto_item_add_subtree(ti, ett_smb_mode);
      proto_tree_add_text(Mode_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(Mode, 0x03, 16, Mode_0x03, "%s"));
    
}

    offset += 2; /* Skip Mode */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Identifier String */

    IdentifierString = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(IdentifierString) + 1, "Identifier String: %s", IdentifierString);

    }

    offset += strlen(IdentifierString) + 1; /* Skip Identifier String */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_close_print_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint16       FID;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count: %u", WordCount);

    }

    offset += 1; /* Skip Word Count */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_read_raw_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint32       Timeout;
  guint32       OffsetHigh;
  guint32       Offset;
  guint16       Reserved;
  guint16       MinCount;
  guint16       MaxCount;
  guint16       FID;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    WordCount = GBYTE(pd, offset);

    switch (WordCount) {

    case 8:

      /* Build display for: Word Count (WCT) */

      WordCount = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

      }

      offset += 1; /* Skip Word Count (WCT) */

      /* Build display for: FID */

      FID = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

      }

      offset += 2; /* Skip FID */

      /* Build display for: Offset */

      Offset = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

      }

      offset += 4; /* Skip Offset */

      /* Build display for: Max Count */

      MaxCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Max Count: %u", MaxCount);

      }

      offset += 2; /* Skip Max Count */

      /* Build display for: Min Count */

      MinCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Min Count: %u", MinCount);

      }

      offset += 2; /* Skip Min Count */

      /* Build display for: Timeout */

      Timeout = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Timeout: %u", Timeout);

      }

      offset += 4; /* Skip Timeout */

      /* Build display for: Reserved */

      Reserved = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved: %u", Reserved);

      }

      offset += 2; /* Skip Reserved */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

    break;

    case 10:

      /* Build display for: Word Count (WCT) */

      WordCount = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

      }

      offset += 1; /* Skip Word Count (WCT) */

      /* Build display for: FID */

      FID = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

      }

      offset += 2; /* Skip FID */

      /* Build display for: Offset */

      Offset = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

      }

      offset += 4; /* Skip Offset */

      /* Build display for: Max Count */

      MaxCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Max Count: %u", MaxCount);

      }

      offset += 2; /* Skip Max Count */

      /* Build display for: Min Count */

      MinCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Min Count: %u", MinCount);

      }

      offset += 2; /* Skip Min Count */

      /* Build display for: Timeout */

      Timeout = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Timeout: %u", Timeout);

      }

      offset += 4; /* Skip Timeout */

      /* Build display for: Reserved */

      Reserved = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved: %u", Reserved);

      }

      offset += 2; /* Skip Reserved */

      /* Build display for: Offset High */

      OffsetHigh = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Offset High: %u", OffsetHigh);

      }

      offset += 4; /* Skip Offset High */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

    break;

    }

  }

  if (dirn == 0) { /* Response(s) dissect code */

  }

}

void
dissect_read_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        AndXReserved;
  guint8        AndXCommand = 0xFF;
  guint16       ByteCount;
  guint16       AndXOffset = 0;
  guint16       FID;
  guint16       DataCompactionMode;
  guint16       DataLength;
  guint16       DataOffset;
  guint16       Remaining;
  guint16       MaxCount;
  guint16       MinCount;
  guint16       Reserved;
  guint32       Offset;
  guint32       OffsetHigh;
  int           i;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: AndXCommand */

    AndXCommand = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %u", AndXCommand);

    }

    offset += 1; /* Skip AndXCommand */

    /* Build display for: AndXReserved */

    AndXReserved = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

    }

    offset += 1; /* Skip AndXReserved */

    /* Build display for: AndXOffset */

    AndXOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

    }

    offset += 2; /* Skip AndXOffset */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {
	
      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);
	
    }

    offset += 2; /* Skip FID */

    /* Build display for: Offset */

    Offset = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

    }

    offset += 4; /* Skip Offset */

    /* Build display for: Max Count */

    MaxCount = GSHORT(pd, offset);

    if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Max Count: %u", MaxCount);

    }

    offset += 2; /* Skip Max Count */

    /* Build display for: Min Count */

    MinCount = GSHORT(pd, offset);

    if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Min Count: %u", MinCount);

    }

    offset += 2; /* Skip Min Count */

    /* Build display for: Reserved */

    Reserved = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved: %u", Reserved);

    }

    offset += 4; /* Skip Reserved */

    /* Build display for: Remaining */

    Remaining = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Remaining: %u", Remaining);

    }

    offset += 2; /* Skip Remaining */

    if (WordCount == 12) {

	/* Build display for: Offset High */

	OffsetHigh = GWORD(pd, offset);

	if (tree) {

	    proto_tree_add_text(tree, NullTVB, offset, 4, "Offset High: %u", OffsetHigh);

	}

	offset += 4; /* Skip Offset High */
    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */


    if (AndXCommand != 0xFF) {

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset, errcode, dirn);

    }

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: AndXCommand */

    AndXCommand = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %u", AndXCommand);

    }

    offset += 1; /* Skip AndXCommand */

    /* Build display for: AndXReserved */

    AndXReserved = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

    }

    offset += 1; /* Skip AndXReserved */

    /* Build display for: AndXOffset */

    AndXOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

    }

    offset += 2; /* Skip AndXOffset */

    /* Build display for: Remaining */

    Remaining = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Remaining: %u", Remaining);

    }

    offset += 2; /* Skip Remaining */

    /* Build display for: Data Compaction Mode */

    DataCompactionMode = GSHORT(pd, offset);

    if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Data Compaction Mode: %u", DataCompactionMode);

    }

    offset += 2; /* Skip Data Compaction Mode */

    /* Build display for: Reserved */

    Reserved = GSHORT(pd, offset);

    if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved: %u", Reserved);

    }

    offset += 2; /* Skip Reserved */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

    /* Build display for: Data Offset */

    DataOffset = GSHORT(pd, offset);

    if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

    }

    offset += 2; /* Skip Data Offset */

    /* Build display for: Reserved[5] */
 
    for(i = 1; i <= 5; ++i) {

	Reserved = GSHORT(pd, offset);

	if (tree) {

	    proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved%u: %u", i, Reserved);

	}
	offset += 2;
    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for data */

    if (tree) {

	offset = SMB_offset + DataOffset;
	if(END_OF_FRAME >= DataLength)
	    proto_tree_add_text(tree, NullTVB, offset, DataLength, "Data (%u bytes)", DataLength);
	else
	    proto_tree_add_text(tree, NullTVB, offset, END_OF_FRAME, "Data (first %u bytes)", END_OF_FRAME);

    }

    if (AndXCommand != 0xFF) {

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset, errcode, dirn);

    }

  }

}

void
dissect_logoff_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        AndXReserved;
  guint8        AndXCommand = 0xFF;
  guint16       ByteCount;
  guint16       AndXOffset = 0;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: AndXCommand */

    AndXCommand = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %u", AndXCommand);

    }

    offset += 1; /* Skip AndXCommand */

    /* Build display for: AndXReserved */

    AndXReserved = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

    }

    offset += 1; /* Skip AndXReserved */

    /* Build display for: AndXOffset */

    AndXOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

    }

    offset += 2; /* Skip AndXOffset */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */


    if (AndXCommand != 0xFF) {

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset, errcode, dirn);

    }

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: AndXCommand */

    AndXCommand = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %u", AndXCommand);

    }

    offset += 1; /* Skip AndXCommand */

    /* Build display for: AndXReserved */

    AndXReserved = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

    }

    offset += 1; /* Skip AndXReserved */

    /* Build display for: AndXOffset */

    AndXOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

    }

    offset += 2; /* Skip AndXOffset */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */


    if (AndXCommand != 0xFF) {

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset, errcode, dirn);

    }

  }

}

void
dissect_seek_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  static const value_string Mode_0x03[] = {
	{ 0, "Seek from start of file"},
	{ 1, "Seek from current position"},
	{ 2, "Seek from end of file"},
	{ 0, NULL}
};
  proto_tree    *Mode_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint32       Offset;
  guint16       Mode;
  guint16       FID;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Mode */

    Mode = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Mode: 0x%02x", Mode);
      Mode_tree = proto_item_add_subtree(ti, ett_smb_mode);
      proto_tree_add_text(Mode_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(Mode, 0x03, 16, Mode_0x03, "%s"));
    
}

    offset += 2; /* Skip Mode */

    /* Build display for: Offset */

    Offset = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

    }

    offset += 4; /* Skip Offset */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Offset */

    Offset = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

    }

    offset += 4; /* Skip Offset */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_write_and_unlock_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint32       Offset;
  guint16       Remaining;
  guint16       FID;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Count */

    Count = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

    }

    offset += 2; /* Skip Count */

    /* Build display for: Offset */

    Offset = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

    }

    offset += 4; /* Skip Offset */

    /* Build display for: Remaining */

    Remaining = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Remaining: %u", Remaining);

    }

    offset += 2; /* Skip Remaining */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Count */

    Count = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

    }

    offset += 2; /* Skip Count */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_set_info2_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint16       LastWriteTime;
  guint16       LastWriteDate;
  guint16       LastAccessTime;
  guint16       LastAccessDate;
  guint16       FID;
  guint16       CreationTime;
  guint16       CreationDate;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count: %u", WordCount);

    }

    offset += 1; /* Skip Word Count */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Creation Date */

    CreationDate = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Creation Date: %s", dissect_dos_date(CreationDate));

    }

    offset += 2; /* Skip Creation Date */

    /* Build display for: Creation Time */

    CreationTime = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Creation Time: %s", dissect_dos_time(CreationTime));

    }

    offset += 2; /* Skip Creation Time */

    /* Build display for: Last Access Date */

    LastAccessDate = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Last Access Date: %s", dissect_dos_date(LastAccessDate));

    }

    offset += 2; /* Skip Last Access Date */

    /* Build display for: Last Access Time */

    LastAccessTime = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Last Access Time: %s", dissect_dos_time(LastAccessTime));

    }

    offset += 2; /* Skip Last Access Time */

    /* Build display for: Last Write Date */

    LastWriteDate = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Last Write Date: %s", dissect_dos_date(LastWriteDate));

    }

    offset += 2; /* Skip Last Write Date */

    /* Build display for: Last Write Time */

    LastWriteTime = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Last Write Time: %s", dissect_dos_time(LastWriteTime));

    }

    offset += 2; /* Skip Last Write Time */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCC) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCC): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCC) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_lock_bytes_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint32       Offset;
  guint32       Count;
  guint16       FID;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Count */

    Count = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Count: %u", Count);

    }

    offset += 4; /* Skip Count */

    /* Build display for: Offset */

    Offset = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

    }

    offset += 4; /* Skip Offset */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_get_print_queue_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       StartIndex;
  guint16       RestartIndex;
  guint16       MaxCount;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count: %u", WordCount);

    }

    offset += 1; /* Skip Word Count */

    /* Build display for: Max Count */

    MaxCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Count: %u", MaxCount);

    }

    offset += 2; /* Skip Max Count */

    /* Build display for: Start Index */

    StartIndex = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Start Index: %u", StartIndex);

    }

    offset += 2; /* Skip Start Index */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: Count */

      Count = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

      }

      offset += 2; /* Skip Count */

      /* Build display for: Restart Index */

      RestartIndex = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Restart Index: %u", RestartIndex);

      }

      offset += 2; /* Skip Restart Index */

      /* Build display for: Byte Count (BCC) */

    }

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

  }

}

void
dissect_locking_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  proto_tree    *LockType_tree;
  proto_item    *ti;
  guint8        LockType;
  guint8        WordCount;
  guint8        OplockLevel;
  guint8        AndXReserved;
  guint8        AndXCommand = 0xFF;
  guint32       Timeout;
  guint16       NumberofLocks;
  guint16       NumberOfUnlocks;
  guint16       FID;
  guint16       ByteCount;
  guint16       AndXoffset;
  guint16       AndXOffset = 0;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: AndXCommand */

    AndXCommand = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %u", AndXCommand);

    }

    offset += 1; /* Skip AndXCommand */

    /* Build display for: AndXReserved */

    AndXReserved = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

    }

    offset += 1; /* Skip AndXReserved */

    /* Build display for: AndXOffset */

    AndXOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

    }

    offset += 2; /* Skip AndXOffset */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Lock Type */

    LockType = GBYTE(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 1, "Lock Type: 0x%01x", LockType);
      LockType_tree = proto_item_add_subtree(ti, ett_smb_lock_type);
      proto_tree_add_text(LockType_tree, NullTVB, offset, 1, "%s",
                          decode_boolean_bitfield(LockType, 0x01, 16, "Read-only lock", "Not a Read-only lock"));
      proto_tree_add_text(LockType_tree, NullTVB, offset, 1, "%s",
                          decode_boolean_bitfield(LockType, 0x02, 16, "Oplock break notification", "Not an Oplock break notification"));
      proto_tree_add_text(LockType_tree, NullTVB, offset, 1, "%s",
                          decode_boolean_bitfield(LockType, 0x04, 16, "Change lock type", "Not a lock type change"));
      proto_tree_add_text(LockType_tree, NullTVB, offset, 1, "%s",
                          decode_boolean_bitfield(LockType, 0x08, 16, "Cancel outstanding request", "Dont cancel outstanding request"));
      proto_tree_add_text(LockType_tree, NullTVB, offset, 1, "%s",
                          decode_boolean_bitfield(LockType, 0x10, 16, "Large file locking format", "Not a large file locking format"));
    
}

    offset += 1; /* Skip Lock Type */

    /* Build display for: OplockLevel */

    OplockLevel = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "OplockLevel: %u", OplockLevel);

    }

    offset += 1; /* Skip OplockLevel */

    /* Build display for: Timeout */

    Timeout = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Timeout: %u", Timeout);

    }

    offset += 4; /* Skip Timeout */

    /* Build display for: Number Of Unlocks */

    NumberOfUnlocks = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Number Of Unlocks: %u", NumberOfUnlocks);

    }

    offset += 2; /* Skip Number Of Unlocks */

    /* Build display for: Number of Locks */

    NumberofLocks = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Number of Locks: %u", NumberofLocks);

    }

    offset += 2; /* Skip Number of Locks */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */


    if (AndXCommand != 0xFF) {

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset, errcode, dirn);

    }

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: AndXCommand */

      AndXCommand = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s", 
			    (AndXCommand == 0xFF ? "No further commands" : decode_smb_name(AndXCommand)));

      }

      offset += 1; /* Skip AndXCommand */

      /* Build display for: AndXReserved */

      AndXReserved = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

      }

      offset += 1; /* Skip AndXReserved */

      /* Build display for: AndXoffset */

      AndXoffset = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "AndXoffset: %u", AndXoffset);

      }

      offset += 2; /* Skip AndXoffset */

    }

    /* Build display for: Byte Count */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count: %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count */


    if (AndXCommand != 0xFF) {

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset, errcode, dirn);

    }

  }

}

void
dissect_unlock_bytes_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint32       Offset;
  guint32       Count;
  guint16       FID;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Count */

    Count = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Count: %u", Count);

    }

    offset += 4; /* Skip Count */

    /* Build display for: Offset */

    Offset = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

    }

    offset += 4; /* Skip Offset */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_create_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  proto_tree    *Attributes_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       FID;
  guint16       CreationTime;
  guint16       ByteCount;
  guint16       Attributes;
  const char    *FileName;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Attributes */

    Attributes = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Attributes: 0x%02x", Attributes);
      Attributes_tree = proto_item_add_subtree(ti, ett_smb_fileattributes);
      proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Attributes, 0x01, 16, "Read-only file", "Not a read-only file"));
      proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Attributes, 0x02, 16, "Hidden file", "Not a hidden file"));
      proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Attributes, 0x04, 16, "System file", "Not a system file"));
      proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Attributes, 0x08, 16, " Volume", "Not a volume"));
      proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Attributes, 0x10, 16, " Directory", "Not a directory"));
      proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Attributes, 0x20, 16, " Archived", "Not archived"));
    
}

    offset += 2; /* Skip Attributes */

    /* Build display for: Creation Time */

    CreationTime = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Creation Time: %s", dissect_dos_time(CreationTime));

    }

    offset += 2; /* Skip Creation Time */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: File Name */

    FileName = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(FileName) + 1, "File Name: %s", FileName);

    }

    offset += strlen(FileName) + 1; /* Skip File Name */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: FID */

      FID = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

      }

      offset += 2; /* Skip FID */
      
    }
    
    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_search_dir_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        BufferFormat2;
  guint8        BufferFormat1;
  guint8        BufferFormat;
  guint16       SearchAttributes;
  guint16       ResumeKeyLength;
  guint16       MaxCount;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;
  const char    *FileName;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Max Count */

    MaxCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Count: %u", MaxCount);

    }

    offset += 2; /* Skip Max Count */

    /* Build display for: Search Attributes */

    SearchAttributes = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Search Attributes: %u", SearchAttributes);

    }

    offset += 2; /* Skip Search Attributes */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format 1 */

    BufferFormat1 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format 1: %u", BufferFormat1);

    }

    offset += 1; /* Skip Buffer Format 1 */

    /* Build display for: File Name */

    FileName = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(FileName) + 1, "File Name: %s", FileName);

    }

    offset += strlen(FileName) + 1; /* Skip File Name */

    /* Build display for: Buffer Format 2 */

    BufferFormat2 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format 2: %u", BufferFormat2);

    }

    offset += 1; /* Skip Buffer Format 2 */

    /* Build display for: Resume Key Length */

    ResumeKeyLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Resume Key Length: %u", ResumeKeyLength);

    }

    offset += 2; /* Skip Resume Key Length */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: Count */

      Count = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

      }

      offset += 2; /* Skip Count */

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

  }

}

void
dissect_create_temporary_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       Reserved;
  guint16       FID;
  guint16       CreationTime;
  guint16       CreationDate;
  guint16       ByteCount;
  const char    *FileName;
  const char    *DirectoryName;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Reserved */

    Reserved = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved: %u", Reserved);

    }

    offset += 2; /* Skip Reserved */

    /* Build display for: Creation Time */

    CreationTime = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Creation Time: %s", dissect_dos_time(CreationTime));

    }

    offset += 2; /* Skip Creation Time */

    /* Build display for: Creation Date */

    CreationDate = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Creation Date: %s", dissect_dos_date(CreationDate));

    }

    offset += 2; /* Skip Creation Date */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Directory Name */

    DirectoryName = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(DirectoryName) + 1, "Directory Name: %s", DirectoryName);

    }

    offset += strlen(DirectoryName) + 1; /* Skip Directory Name */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: FID */

      FID = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

      }

      offset += 2; /* Skip FID */

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: File Name */

    FileName = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(FileName) + 1, "File Name: %s", FileName);

    }

    offset += strlen(FileName) + 1; /* Skip File Name */

  }

}

void
dissect_close_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint16       LastWriteTime;
  guint16       LastWriteDate;
  guint16       FID;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Last Write Time */

    LastWriteTime = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Last Write Time: %s", dissect_dos_time(LastWriteTime));

    }

    offset += 2; /* Skip Last Write Time */

    /* Build display for: Last Write Date */

    LastWriteDate = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Last Write Date: %s", dissect_dos_date(LastWriteDate));

    }

    offset += 2; /* Skip Last Write Date */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_write_print_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       FID;
  guint16       DataLength;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_lock_and_read_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint32       Offset;
  guint16       Reserved4;
  guint16       Reserved3;
  guint16       Reserved2;
  guint16       Reserved1;
  guint16       Remaining;
  guint16       FID;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Count */

    Count = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

    }

    offset += 2; /* Skip Count */

    /* Build display for: Offset */

    Offset = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

    }

    offset += 4; /* Skip Offset */

    /* Build display for: Remaining */

    Remaining = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Remaining: %u", Remaining);

    }

    offset += 2; /* Skip Remaining */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: Count */

      Count = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

      }

      offset += 2; /* Skip Count */

      /* Build display for: Reserved 1 */

      Reserved1 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 1: %u", Reserved1);

      }

      offset += 2; /* Skip Reserved 1 */

      /* Build display for: Reserved 2 */

      Reserved2 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 2: %u", Reserved2);

      }

      offset += 2; /* Skip Reserved 2 */

      /* Build display for: Reserved 3 */

      Reserved3 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 3: %u", Reserved3);

      }

      offset += 2; /* Skip Reserved 3 */

      /* Build display for: Reserved 4 */

      Reserved4 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 4: %u", Reserved4);

      }

      offset += 2; /* Skip Reserved 4 */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

  }

}

void
dissect_process_exit_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_get_file_attr_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  proto_tree    *Attributes_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        BufferFormat;
  guint32       FileSize;
  guint16       Reserved5;
  guint16       Reserved4;
  guint16       Reserved3;
  guint16       Reserved2;
  guint16       Reserved1;
  guint16       LastWriteTime;
  guint16       LastWriteDate;
  guint16       ByteCount;
  guint16       Attributes;
  const char    *FileName;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %u", BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: File Name */

    FileName = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(FileName) + 1, "File Name: %s", FileName);

    }

    offset += strlen(FileName) + 1; /* Skip File Name */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: Attributes */

      Attributes = GSHORT(pd, offset);

      if (tree) {

	ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Attributes: 0x%02x", Attributes);
	Attributes_tree = proto_item_add_subtree(ti, ett_smb_fileattributes);
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x01, 16, "Read-only file", "Not a read-only file"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x02, 16, "Hidden file", "Not a hidden file"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x04, 16, "System file", "Not a system file"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x08, 16, " Volume", "Not a volume"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x10, 16, " Directory", "Not a directory"));
	proto_tree_add_text(Attributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Attributes, 0x20, 16, " Archived", "Not archived"));
	
      }

      offset += 2; /* Skip Attributes */

      /* Build display for: Last Write Time */

      LastWriteTime = GSHORT(pd, offset);

      if (tree) {

      }

      offset += 2; /* Skip Last Write Time */

      /* Build display for: Last Write Date */

      LastWriteDate = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Last Write Date: %s", dissect_smbu_date(LastWriteDate, LastWriteTime));

	proto_tree_add_text(tree, NullTVB, offset - 2, 2, "Last Write Time: %s", dissect_smbu_time(LastWriteDate, LastWriteTime));

      }

      offset += 2; /* Skip Last Write Date */

      /* Build display for: File Size */

      FileSize = GWORD(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 4, "File Size: %u", FileSize);

      }

      offset += 4; /* Skip File Size */

      /* Build display for: Reserved 1 */

      Reserved1 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 1: %u", Reserved1);

      }

      offset += 2; /* Skip Reserved 1 */

      /* Build display for: Reserved 2 */

      Reserved2 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 2: %u", Reserved2);

      }

      offset += 2; /* Skip Reserved 2 */

      /* Build display for: Reserved 3 */

      Reserved3 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 3: %u", Reserved3);

      }

      offset += 2; /* Skip Reserved 3 */

      /* Build display for: Reserved 4 */

      Reserved4 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 4: %u", Reserved4);

      }

      offset += 2; /* Skip Reserved 4 */

      /* Build display for: Reserved 5 */

      Reserved5 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 5: %u", Reserved5);

      }

      offset += 2; /* Skip Reserved 5 */

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_read_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint32       Offset;
  guint16       Reserved4;
  guint16       Reserved3;
  guint16       Reserved2;
  guint16       Reserved1;
  guint16       Remaining;
  guint16       FID;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;
  guint16       BufferFormat;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Count */

    Count = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

    }

    offset += 2; /* Skip Count */

    /* Build display for: Offset */

    Offset = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

    }

    offset += 4; /* Skip Offset */

    /* Build display for: Remaining */

    Remaining = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Remaining: %u", Remaining);

    }

    offset += 2; /* Skip Remaining */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: Count */

      Count = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

      }

      offset += 2; /* Skip Count */

      /* Build display for: Reserved 1 */

      Reserved1 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 1: %u", Reserved1);

      }

      offset += 2; /* Skip Reserved 1 */

      /* Build display for: Reserved 2 */

      Reserved2 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 2: %u", Reserved2);

      }

      offset += 2; /* Skip Reserved 2 */

      /* Build display for: Reserved 3 */

      Reserved3 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 3: %u", Reserved3);

      }

      offset += 2; /* Skip Reserved 3 */

      /* Build display for: Reserved 4 */

      Reserved4 = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 4: %u", Reserved4);

      }

      offset += 2; /* Skip Reserved 4 */

    }
    
    /* Build display for: Byte Count (BCC) */
    
    ByteCount = GSHORT(pd, offset);
      
    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Buffer Format: %u", BufferFormat);

    }

    offset += 2; /* Skip Buffer Format */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

  }

}

void
dissect_write_mpx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  proto_tree    *WriteMode_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        Pad;
  guint32       Timeout;
  guint32       ResponseMask;
  guint32       RequestMask;
  guint16       WriteMode;
  guint16       Reserved1;
  guint16       FID;
  guint16       DataOffset;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Count */

    Count = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

    }

    offset += 2; /* Skip Count */

    /* Build display for: Reserved 1 */

    Reserved1 = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 1: %u", Reserved1);

    }

    offset += 2; /* Skip Reserved 1 */

    /* Build display for: Timeout */

    Timeout = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Timeout: %u", Timeout);

    }

    offset += 4; /* Skip Timeout */

    /* Build display for: WriteMode */

    WriteMode = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "WriteMode: 0x%02x", WriteMode);
      WriteMode_tree = proto_item_add_subtree(ti, ett_smb_writemode);
      proto_tree_add_text(WriteMode_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(WriteMode, 0x01, 16, "Write through requested", "Write through not requested"));
      proto_tree_add_text(WriteMode_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(WriteMode, 0x02, 16, "Return Remaining", "Dont return Remaining"));
      proto_tree_add_text(WriteMode_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(WriteMode, 0x40, 16, "Connectionless mode requested", "Connectionless mode not requested"));
    
}

    offset += 2; /* Skip WriteMode */

    /* Build display for: Request Mask */

    RequestMask = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Request Mask: %u", RequestMask);

    }

    offset += 4; /* Skip Request Mask */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

    /* Build display for: Data Offset */

    DataOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

    }

    offset += 2; /* Skip Data Offset */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Pad */

    Pad = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Pad: %u", Pad);

    }

    offset += 1; /* Skip Pad */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount > 0) {

      /* Build display for: Response Mask */

      ResponseMask = GWORD(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 4, "Response Mask: %u", ResponseMask);

      }

      offset += 4; /* Skip Response Mask */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_find_close2_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  guint8        WordCount;
  guint8        ByteCount;
  guint16       FID;

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WTC) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WTC): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WTC) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: %u", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 1; /* Skip Byte Count (BCC) */

  }

}

char *trans2_cmd_names[] = {
  "TRANS2_OPEN",
  "TRANS2_FIND_FIRST2",
  "TRANS2_FIND_NEXT2",
  "TRANS2_QUERY_FS_INFORMATION",
  "no such command",
  "TRANS2_QUERY_PATH_INFORMATION",
  "TRANS2_SET_PATH_INFORMATION",
  "TRANS2_QUERY_FILE_INFORMATION",
  "TRANS2_SET_FILE_INFORMATION",
  "TRANS2_FSCTL",
  "TRANS2_IOCTL2",
  "TRANS2_FIND_NOTIFY_FIRST",
  "TRANS2_FIND_NOTIFY_NEXT",
  "TRANS2_CREATE_DIRECTORY",
  "TRANS2_SESSION_SETUP",
  "TRANS2_GET_DFS_REFERRAL",
  "no such command",
  "TRANS2_REPORT_DFS_INCONSISTENCY"};

char *decode_trans2_name(int code)
{

  if (code > 17 || code < 0) {

    return("no such command");

  }

  return trans2_cmd_names[code];

}


void
dissect_transact2_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  proto_tree    *Flags_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        SetupCount;
  guint8        Reserved3;
  guint8        Reserved1;
  guint8        MaxSetupCount;
  guint8        Data;
  guint32       Timeout;
  guint16       TotalParameterCount;
  guint16       TotalDataCount;
  guint16       Setup = 0;
  guint16       Reserved2;
  guint16       ParameterOffset;
  guint16       ParameterDisplacement;
  guint16       ParameterCount;
  guint16       MaxParameterCount;
  guint16       MaxDataCount;
  guint16       Flags;
  guint16       DataOffset;
  guint16       DataDisplacement;
  guint16       DataCount;
  guint16       ByteCount;
  conversation_t *conversation;
  struct smb_request_key      request_key, *new_request_key;
  struct smb_request_val      *request_val;

  /*
   * Find out what conversation this packet is part of.
   * XXX - this should really be done by the transport-layer protocol,
   * although for connectionless transports, we may not want to do that
   * unless we know some higher-level protocol will want it - or we
   * may want to do it, so you can say e.g. "show only the packets in
   * this UDP 'connection'".
   *
   * Note that we don't have to worry about the direction this packet
   * was going - the conversation code handles that for us, treating
   * packets from A:X to B:Y as being part of the same conversation as
   * packets from B:Y to A:X.
   */
  conversation = find_conversation(&pi.src, &pi.dst, pi.ptype,
				pi.srcport, pi.destport, 0);
  if (conversation == NULL) {
    /* It's not part of any conversation - create a new one. */
    conversation = conversation_new(&pi.src, &pi.dst, pi.ptype,
				pi.srcport, pi.destport, NULL, 0);
  }

  si.conversation = conversation;  /* Save this for later */

  /*
   * Check for and insert entry in request hash table if does not exist
   */
  request_key.conversation = conversation->index;
  request_key.mid          = si.mid;

  request_val = (struct smb_request_val *) g_hash_table_lookup(smb_request_hash, &request_key);

  if (!request_val) { /* Create one */

    new_request_key = g_mem_chunk_alloc(smb_request_keys);
    new_request_key -> conversation = conversation->index;
    new_request_key -> mid          = si.mid;

    request_val = g_mem_chunk_alloc(smb_request_vals);
    request_val -> mid = si.mid;
    request_val -> last_transact2_command = 0xFFFF;

    g_hash_table_insert(smb_request_hash, new_request_key, request_val);
    
  }
  else { /* Update the transact request */

    request_val -> mid = si.mid;

  }

  si.request_val = request_val;  /* Save this for later */


  if (dirn == 1) { /* Request(s) dissect code */
  
    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Total Parameter Count */

    TotalParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Parameter Count: %u", TotalParameterCount);

    }

    offset += 2; /* Skip Total Parameter Count */

    /* Build display for: Total Data Count */

    TotalDataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Data Count: %u", TotalDataCount);

    }

    offset += 2; /* Skip Total Data Count */

    /* Build display for: Max Parameter Count */

    MaxParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Parameter Count: %u", MaxParameterCount);

    }

    offset += 2; /* Skip Max Parameter Count */

    /* Build display for: Max Data Count */

    MaxDataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Data Count: %u", MaxDataCount);

    }

    offset += 2; /* Skip Max Data Count */

    /* Build display for: Max Setup Count */

    MaxSetupCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Max Setup Count: %u", MaxSetupCount);

    }

    offset += 1; /* Skip Max Setup Count */

    /* Build display for: Reserved1 */

    Reserved1 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Reserved1: %u", Reserved1);

    }

    offset += 1; /* Skip Reserved1 */

    /* Build display for: Flags */

    Flags = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Flags: 0x%02x", Flags);
      Flags_tree = proto_item_add_subtree(ti, ett_smb_flags);
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Flags, 0x01, 16, "Also disconnect TID", "Dont disconnect TID"));
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Flags, 0x02, 16, "One way transaction", "Two way transaction"));
    
    }

    offset += 2; /* Skip Flags */

    /* Build display for: Timeout */

    Timeout = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Timeout: %u", Timeout);

    }

    offset += 4; /* Skip Timeout */

    /* Build display for: Reserved2 */

    Reserved2 = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved2: %u", Reserved2);

    }

    offset += 2; /* Skip Reserved2 */

    /* Build display for: Parameter Count */

    ParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Count: %u", ParameterCount);

    }

    offset += 2; /* Skip Parameter Count */

    /* Build display for: Parameter Offset */

    ParameterOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Offset: %u", ParameterOffset);

    }

    offset += 2; /* Skip Parameter Offset */

    /* Build display for: Data Count */

    DataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Count: %u", DataCount);

    }

    offset += 2; /* Skip Data Count */

    /* Build display for: Data Offset */

    DataOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

    }

    offset += 2; /* Skip Data Offset */

    /* Build display for: Setup Count */

    SetupCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Setup Count: %u", SetupCount);

    }

    offset += 1; /* Skip Setup Count */

    /* Build display for: Reserved3 */

    Reserved3 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Reserved3: %u", Reserved3);

    }

    offset += 1; /* Skip Reserved3 */

    /* Build display for: Setup */

    if (SetupCount > 0) {

      int i = SetupCount;

      Setup = GSHORT(pd, offset);

      request_val -> last_transact2_command = Setup;  /* Save for later */

      if (check_col(fd, COL_INFO)) {

	col_add_fstr(fd, COL_INFO, "%s %s", decode_trans2_name(Setup), (dirn ? "Request" : "Response"));

      }

      for (i = 1; i <= SetupCount; i++) {
	int Setup1;

	Setup1 = GSHORT(pd, offset);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, 2, "Setup%i: %u", i, Setup1);

	}

	offset += 2; /* Skip Setup */

      }

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Transact Name */

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Transact Name: %s", decode_trans2_name(Setup));

    }

    if (offset < (SMB_offset + ParameterOffset)) {

      int pad1Count = SMB_offset + ParameterOffset - offset;

      /* Build display for: Pad1 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad1Count, "Pad1: %s", format_text(pd + offset, pad1Count));
      }

      offset += pad1Count; /* Skip Pad1 */

    }

    if (ParameterCount > 0) {

      /* Build display for: Parameters */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, SMB_offset + ParameterOffset, ParameterCount, "Parameters: %s", format_text(pd + SMB_offset + ParameterOffset, ParameterCount));

      }

      offset += ParameterCount; /* Skip Parameters */

    }

    if (DataCount > 0 && offset < (SMB_offset + DataOffset)) {

      int pad2Count = SMB_offset + DataOffset - offset;
	
      /* Build display for: Pad2 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad2Count, "Pad2: %s", format_text(pd + offset, pad2Count));

      }

      offset += pad2Count; /* Skip Pad2 */

    }

    if (DataCount > 0) {

      /* Build display for: Data */

      Data = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, SMB_offset + DataOffset, DataCount, "Data: %s", format_text(&pd[offset], DataCount));

      }

      offset += DataCount; /* Skip Data */

    }
  }

  if (dirn == 0) { /* Response(s) dissect code */

    /* Pick up the last transact2 command and put it in the right places */

    if (check_col(fd, COL_INFO)) {

      col_add_fstr(fd, COL_INFO, "%s %s", decode_trans2_name(request_val -> last_transact2_command), "response");

    }

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Total Parameter Count */

    TotalParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Parameter Count: %u", TotalParameterCount);

    }

    offset += 2; /* Skip Total Parameter Count */

    /* Build display for: Total Data Count */

    TotalDataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Data Count: %u", TotalDataCount);

    }

    offset += 2; /* Skip Total Data Count */

    /* Build display for: Reserved2 */

    Reserved2 = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved2: %u", Reserved2);

    }

    offset += 2; /* Skip Reserved2 */

    /* Build display for: Parameter Count */

    ParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Count: %u", ParameterCount);

    }

    offset += 2; /* Skip Parameter Count */

    /* Build display for: Parameter Offset */

    ParameterOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Offset: %u", ParameterOffset);

    }

    offset += 2; /* Skip Parameter Offset */

    /* Build display for: Parameter Displacement */

    ParameterDisplacement = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Displacement: %u", ParameterDisplacement);

    }

    offset += 2; /* Skip Parameter Displacement */

    /* Build display for: Data Count */

    DataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Count: %u", DataCount);

    }

    offset += 2; /* Skip Data Count */

    /* Build display for: Data Offset */

    DataOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

    }

    offset += 2; /* Skip Data Offset */

    /* Build display for: Data Displacement */

    DataDisplacement = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Displacement: %u", DataDisplacement);

    }

    offset += 2; /* Skip Data Displacement */

    /* Build display for: Setup Count */

    SetupCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Setup Count: %u", SetupCount);

    }

    offset += 1; /* Skip Setup Count */

    /* Build display for: Reserved3 */

    Reserved3 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Reserved3: %u", Reserved3);

    }

    offset += 1; /* Skip Reserved3 */

    if (SetupCount > 0) {

      int i = SetupCount;

      Setup = GSHORT(pd, offset);

      for (i = 1; i <= SetupCount; i++) {
	
	Setup = GSHORT(pd, offset);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, 2, "Setup%i: %u", i, Setup);

	}

	offset += 2; /* Skip Setup */

      }
    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    if (offset < (SMB_offset + ParameterOffset)) {

      int pad1Count = SMB_offset + ParameterOffset - offset;

      /* Build display for: Pad1 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad1Count, "Pad1: %s", format_text(pd + offset, pad1Count));
      }

      offset += pad1Count; /* Skip Pad1 */

    }

    /* Build display for: Parameter */

    if (ParameterCount > 0) {

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, ParameterCount, "Parameter: %s", format_text(pd + SMB_offset + ParameterOffset, ParameterCount));

      }

      offset += ParameterCount; /* Skip Parameter */

    }

    if (DataCount > 0 && offset < (SMB_offset + DataOffset)) {

      int pad2Count = SMB_offset + DataOffset - offset;
	
      /* Build display for: Pad2 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad2Count, "Pad2: %s", format_text(pd + offset, pad2Count));

      }

      offset += pad2Count; /* Skip Pad2 */

    }

    /* Build display for: Data */

    if (DataCount > 0) {

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, DataCount, "Data: %s", format_text(pd + SMB_offset + DataOffset, DataCount));

      }

      offset += DataCount; /* Skip Data */

    }

  }

}


static void 
dissect_transact_params(const u_char *pd, int offset, frame_data *fd,
    proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data,
    int SMB_offset, int errcode, int dirn, int DataOffset, int DataCount,
    int ParameterOffset, int ParameterCount, int SetupAreaOffset,
    int SetupCount, const char *TransactName)
{
  char             *TransactNameCopy;
  char             *trans_type = NULL, *trans_cmd, *loc_of_slash = NULL;
  int              index;
  const gchar      *Data;

  if (!TransactName)
	  return;

  TransactNameCopy = g_malloc(TransactName ? strlen(TransactName) + 1 : 1);

  /* Should check for error here ... */

  strcpy(TransactNameCopy, TransactName ? TransactName : "");
  if (TransactNameCopy[0] == '\\') {
    trans_type = TransactNameCopy + 1;  /* Skip the slash */
    loc_of_slash = trans_type ? strchr(trans_type, '\\') : NULL;
  }

  if (loc_of_slash) {
    index = loc_of_slash - trans_type;  /* Make it a real index */
    trans_cmd = trans_type + index + 1;
    trans_type[index] = '\0';
  }
  else
    trans_cmd = NULL;

  if ((trans_cmd == NULL) ||
      (((trans_type == NULL || strcmp(trans_type, "MAILSLOT") != 0) ||
       !dissect_mailslot_smb(pd, SetupAreaOffset, fd, parent, tree, si,
			     max_data, SMB_offset, errcode, dirn, trans_cmd,
			     SMB_offset + DataOffset, DataCount,
			     SMB_offset + ParameterOffset, ParameterCount)) &&
      ((trans_type == NULL || strcmp(trans_type, "PIPE") != 0) ||
       !dissect_pipe_smb(pd, offset, fd, parent, tree, si, max_data,
			 SMB_offset, errcode, dirn, trans_cmd, DataOffset,
			 DataCount, ParameterOffset, ParameterCount)))) {
    
    if (ParameterCount > 0) {

      /* Build display for: Parameters */
      
      if (tree) {

	proto_tree_add_text(tree, NullTVB, SMB_offset + ParameterOffset, ParameterCount, "Parameters: %s", format_text(pd + SMB_offset + ParameterOffset, ParameterCount));
	  
      }
	
      offset = SMB_offset + ParameterOffset + ParameterCount; /* Skip Parameters */

    }

    if (DataCount > 0 && offset < (SMB_offset + DataOffset)) {

      int pad2Count = SMB_offset + DataOffset - offset;
	
      /* Build display for: Pad2 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad2Count, "Pad2: %s", format_text(pd + offset, pad2Count));

      }

      offset += pad2Count; /* Skip Pad2 */

    }

    if (DataCount > 0) {

      /* Build display for: Data */

      Data = pd + SMB_offset + DataOffset;

      if (tree) {

	proto_tree_add_text(tree, NullTVB, SMB_offset + DataOffset, DataCount, "Data: %s", format_text(pd + SMB_offset + DataOffset, DataCount));

      }

      offset += DataCount; /* Skip Data */

    }
  }

}

void
dissect_transact_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn)

{
  proto_tree    *Flags_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        SetupCount;
  guint8        Reserved3;
  guint8        Reserved1;
  guint8        MaxSetupCount;
  guint32       Timeout;
  guint16       TotalParameterCount;
  guint16       TotalDataCount;
  guint16       Setup = 0;
  guint16       Reserved2;
  guint16       ParameterOffset;
  guint16       ParameterDisplacement;
  guint16       ParameterCount;
  guint16       MaxParameterCount;
  guint16       MaxDataCount;
  guint16       Flags;
  guint16       DataOffset;
  guint16       DataDisplacement;
  guint16       DataCount;
  guint16       ByteCount;
  int           TNlen;
  const char    *TransactName;
  conversation_t *conversation;
  struct smb_request_key   request_key, *new_request_key;
  struct smb_request_val   *request_val;
 
  guint16	SetupAreaOffset;


  /*
   * Find out what conversation this packet is part of
   */

  conversation = find_conversation(&pi.src, &pi.dst, pi.ptype,
				   pi.srcport, pi.destport, 0);

  if (conversation == NULL) {  /* Create a new conversation */

    conversation = conversation_new(&pi.src, &pi.dst, pi.ptype,
				    pi.srcport, pi.destport, NULL, 0);

  }

  si.conversation = conversation;  /* Save this */

  /*
   * Check for and insert entry in request hash table if does not exist
   */
  request_key.conversation = conversation->index;
  request_key.mid          = si.mid;

  request_val = (struct smb_request_val *) g_hash_table_lookup(smb_request_hash, &request_key);

  if (!request_val) { /* Create one */

    new_request_key = g_mem_chunk_alloc(smb_request_keys);
    new_request_key -> conversation = conversation -> index;
    new_request_key -> mid          = si.mid;

    request_val = g_mem_chunk_alloc(smb_request_vals);
    request_val -> mid = si.mid;
    request_val -> last_transact_command = NULL;
    request_val -> last_param_descrip = NULL;
    request_val -> last_data_descrip = NULL;

    g_hash_table_insert(smb_request_hash, new_request_key, request_val);

  }

  si.request_val = request_val;  /* Save this for later */

  if (dirn == 1) { /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Total Parameter Count */

    TotalParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Parameter Count: %u", TotalParameterCount);

    }

    offset += 2; /* Skip Total Parameter Count */

    /* Build display for: Total Data Count */

    TotalDataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Data Count: %u", TotalDataCount);

    }

    offset += 2; /* Skip Total Data Count */

    /* Build display for: Max Parameter Count */

    MaxParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Parameter Count: %u", MaxParameterCount);

    }

    offset += 2; /* Skip Max Parameter Count */

    /* Build display for: Max Data Count */

    MaxDataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Data Count: %u", MaxDataCount);

    }

    offset += 2; /* Skip Max Data Count */

    /* Build display for: Max Setup Count */

    MaxSetupCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Max Setup Count: %u", MaxSetupCount);

    }

    offset += 1; /* Skip Max Setup Count */

    /* Build display for: Reserved1 */

    Reserved1 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Reserved1: %u", Reserved1);

    }

    offset += 1; /* Skip Reserved1 */

    /* Build display for: Flags */

    Flags = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Flags: 0x%02x", Flags);
      Flags_tree = proto_item_add_subtree(ti, ett_smb_flags);
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Flags, 0x01, 16, "Also disconnect TID", "Dont disconnect TID"));
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Flags, 0x02, 16, "One way transaction", "Two way transaction"));
    
    }

    offset += 2; /* Skip Flags */

    /* Build display for: Timeout */

    Timeout = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Timeout: %u", Timeout);

    }

    offset += 4; /* Skip Timeout */

    /* Build display for: Reserved2 */

    Reserved2 = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved2: %u", Reserved2);

    }

    offset += 2; /* Skip Reserved2 */

    /* Build display for: Parameter Count */

    ParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Count: %u", ParameterCount);

    }

    offset += 2; /* Skip Parameter Count */

    /* Build display for: Parameter Offset */

    ParameterOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Offset: %u", ParameterOffset);

    }

    offset += 2; /* Skip Parameter Offset */

    /* Build display for: Data Count */

    DataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Count: %u", DataCount);

    }

    offset += 2; /* Skip Data Count */

    /* Build display for: Data Offset */

    DataOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

    }

    offset += 2; /* Skip Data Offset */

    /* Build display for: Setup Count */

    SetupCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Setup Count: %u", SetupCount);

    }

    offset += 1; /* Skip Setup Count */

    /* Build display for: Reserved3 */

    Reserved3 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Reserved3: %u", Reserved3);
    }

    offset += 1; /* Skip Reserved3 */
 
    SetupAreaOffset = offset;

    /* Build display for: Setup */

    if (SetupCount > 0) {

      int i = SetupCount;

      Setup = GSHORT(pd, offset);

      for (i = 1; i <= SetupCount; i++) {
	
	Setup = GSHORT(pd, offset);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, 2, "Setup%i: %u", i, Setup);

	}

	offset += 2; /* Skip Setup */

      }

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Transact Name */

    /* Watch out for Unicode names */

    if (si.unicode) {

      if (offset % 2) offset++;   /* Looks like a pad byte there sometimes */

      TransactName = unicode_to_str(pd + offset, &TNlen);
      TNlen += 2;

    }
    else { 
      TransactName = pd + offset;
      TNlen = strlen(TransactName) + 1;
    }

    if (request_val -> last_transact_command) g_free(request_val -> last_transact_command);

    request_val -> last_transact_command = g_malloc(strlen(TransactName) + 1);

    if (request_val -> last_transact_command) 
      strcpy(request_val -> last_transact_command, TransactName);

    if (check_col(fd, COL_INFO)) {

      col_add_fstr(fd, COL_INFO, "%s %s", TransactName, (dirn ? "Request" : "Response"));

    }

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, TNlen, "Transact Name: %s", TransactName);

    }

    offset += TNlen; /* Skip Transact Name */
    if (si.unicode) offset += 2;   /* There are two more extraneous bytes there*/

    if (offset < (SMB_offset + ParameterOffset)) {

      int pad1Count = SMB_offset + ParameterOffset - offset;

      /* Build display for: Pad1 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad1Count, "Pad1: %s", format_text(pd + offset, pad1Count));
      }

      offset += pad1Count; /* Skip Pad1 */

    }

    /* Let's see if we can decode this */

    dissect_transact_params(pd, offset, fd, parent, tree, si, max_data, SMB_offset, errcode, dirn, DataOffset, DataCount, ParameterOffset, ParameterCount, SetupAreaOffset, SetupCount, TransactName);

  }

  if (dirn == 0) { /* Response(s) dissect code */

    if (check_col(fd, COL_INFO)) {
      if ( request_val -> last_transact_command )
        col_add_fstr(fd, COL_INFO, "%s %s", request_val -> last_transact_command, "Response");
      else col_add_fstr(fd, COL_INFO, "Response to unknown message");

    }

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount == 0) {

      /* Interim response.
         XXX - should we tag it as such? */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      /* Dissect the interim response by showing the type of request to
         which it's a reply. */
      dissect_transact_params(pd, offset, fd, parent, tree, si, max_data,
          SMB_offset, errcode, dirn, -1, -1, -1, -1, -1, -1,
	  si.request_val -> last_transact_command);

      return;

    }

    /* Build display for: Total Parameter Count */

    TotalParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Parameter Count: %u", TotalParameterCount);

    }

    offset += 2; /* Skip Total Parameter Count */

    /* Build display for: Total Data Count */

    TotalDataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Data Count: %u", TotalDataCount);

    }

    offset += 2; /* Skip Total Data Count */

    /* Build display for: Reserved2 */

    Reserved2 = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved2: %u", Reserved2);

    }

    offset += 2; /* Skip Reserved2 */

    /* Build display for: Parameter Count */

    ParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Count: %u", ParameterCount);

    }

    offset += 2; /* Skip Parameter Count */

    /* Build display for: Parameter Offset */

    ParameterOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Offset: %u", ParameterOffset);

    }

    offset += 2; /* Skip Parameter Offset */

    /* Build display for: Parameter Displacement */

    ParameterDisplacement = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Displacement: %u", ParameterDisplacement);

    }

    offset += 2; /* Skip Parameter Displacement */

    /* Build display for: Data Count */

    DataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Count: %u", DataCount);

    }

    offset += 2; /* Skip Data Count */

    /* Build display for: Data Offset */

    DataOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

    }

    offset += 2; /* Skip Data Offset */

    /* Build display for: Data Displacement */

    DataDisplacement = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Displacement: %u", DataDisplacement);

    }

    offset += 2; /* Skip Data Displacement */

    /* Build display for: Setup Count */

    SetupCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Setup Count: %u", SetupCount);

    }

    offset += 1; /* Skip Setup Count */

 
    /* Build display for: Reserved3 */

    Reserved3 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Reserved3: %u", Reserved3);

    }

 
    offset += 1; /* Skip Reserved3 */
 
    SetupAreaOffset = offset;	

    /* Build display for: Setup */

    if (SetupCount > 0) {

      int i = SetupCount;

      Setup = GSHORT(pd, offset);

      for (i = 1; i <= SetupCount; i++) {
	
	Setup = GSHORT(pd, offset);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, 2, "Setup%i: %u", i, Setup);

	}

	offset += 2; /* Skip Setup */

      }

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Pad1 */

    if (offset < (SMB_offset + ParameterOffset)) {

      int pad1Count = SMB_offset + ParameterOffset - offset;

      /* Build display for: Pad1 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad1Count, "Pad1: %s", format_text(pd + offset, pad1Count));
      }

      offset += pad1Count; /* Skip Pad1 */

    }

    dissect_transact_params(pd, offset, fd, parent, tree, si, max_data, SMB_offset, errcode, dirn, DataOffset, DataCount, ParameterOffset, ParameterCount, SetupAreaOffset, SetupCount, si.request_val -> last_transact_command);

  }

}





void (*dissect[256])(const u_char *, int, frame_data *, proto_tree *, proto_tree *, struct smb_info, int, int, int, int) = {

  dissect_createdir_smb,    /* unknown SMB 0x00 */
  dissect_deletedir_smb,    /* unknown SMB 0x01 */
  dissect_unknown_smb,      /* SMBopen open a file */
  dissect_create_file_smb,  /* SMBcreate create a file */
  dissect_close_smb,        /* SMBclose close a file */
  dissect_flush_file_smb,   /* SMBflush flush a file */
  dissect_delete_file_smb,  /* SMBunlink delete a file */
  dissect_rename_file_smb,  /* SMBmv rename a file */
  dissect_get_file_attr_smb,/* SMBgetatr get file attributes */
  dissect_set_file_attr_smb,/* SMBsetatr set file attributes */
  dissect_read_file_smb,    /* SMBread read from a file */
  dissect_write_file_smb,   /* SMBwrite write to a file */
  dissect_lock_bytes_smb,   /* SMBlock lock a byte range */
  dissect_unlock_bytes_smb, /* SMBunlock unlock a byte range */
  dissect_create_temporary_file_smb,/* SMBctemp create a temporary file */
  dissect_unknown_smb,      /* SMBmknew make a new file */
  dissect_checkdir_smb,     /* SMBchkpth check a directory path */
  dissect_process_exit_smb,      /* SMBexit process exit */
  dissect_unknown_smb,      /* SMBlseek seek */
  dissect_lock_and_read_smb,/* SMBlockread Lock a range and read it */
  dissect_write_and_unlock_smb,/* SMBwriteunlock Unlock a range and then write */
  dissect_unknown_smb,      /* unknown SMB 0x15 */
  dissect_unknown_smb,      /* unknown SMB 0x16 */
  dissect_unknown_smb,      /* unknown SMB 0x17 */
  dissect_unknown_smb,      /* unknown SMB 0x18 */
  dissect_unknown_smb,      /* unknown SMB 0x19 */
  dissect_read_raw_smb,     /* SMBreadBraw read block raw */
  dissect_read_mpx_smb,     /* SMBreadBmpx read block multiplexed */
  dissect_unknown_smb,      /* SMBreadBs read block (secondary response) */
  dissect_write_raw_smb,    /* SMBwriteBraw write block raw */
  dissect_write_mpx_smb,    /* SMBwriteBmpx write block multiplexed */
  dissect_unknown_smb,      /* SMBwriteBs write block (secondary request) */
  dissect_unknown_smb,      /* SMBwriteC write complete response */
  dissect_unknown_smb,      /* unknown SMB 0x21 */
  dissect_set_info2_smb,    /* SMBsetattrE set file attributes expanded */
  dissect_query_info2_smb,  /* SMBgetattrE get file attributes expanded */
  dissect_locking_andx_smb, /* SMBlockingX lock/unlock byte ranges and X */
  dissect_transact_smb,      /* SMBtrans transaction - name, bytes in/out */
  dissect_unknown_smb,      /* SMBtranss transaction (secondary request/response) */
  dissect_unknown_smb,      /* SMBioctl IOCTL */
  dissect_unknown_smb,      /* SMBioctls IOCTL (secondary request/response) */
  dissect_unknown_smb,      /* SMBcopy copy */
  dissect_move_smb,      /* SMBmove move */
  dissect_unknown_smb,      /* SMBecho echo */
  dissect_unknown_smb,      /* SMBwriteclose write a file and then close it */
  dissect_open_andx_smb,      /* SMBopenX open and X */
  dissect_read_andx_smb,    /* SMBreadX read and X */
  dissect_unknown_smb,      /* SMBwriteX write and X */
  dissect_unknown_smb,      /* unknown SMB 0x30 */
  dissect_unknown_smb,      /* unknown SMB 0x31 */
  dissect_transact2_smb,    /* unknown SMB 0x32 */
  dissect_unknown_smb,      /* unknown SMB 0x33 */
  dissect_find_close2_smb,  /* unknown SMB 0x34 */
  dissect_unknown_smb,      /* unknown SMB 0x35 */
  dissect_unknown_smb,      /* unknown SMB 0x36 */
  dissect_unknown_smb,      /* unknown SMB 0x37 */
  dissect_unknown_smb,      /* unknown SMB 0x38 */
  dissect_unknown_smb,      /* unknown SMB 0x39 */
  dissect_unknown_smb,      /* unknown SMB 0x3a */
  dissect_unknown_smb,      /* unknown SMB 0x3b */
  dissect_unknown_smb,      /* unknown SMB 0x3c */
  dissect_unknown_smb,      /* unknown SMB 0x3d */
  dissect_unknown_smb,      /* unknown SMB 0x3e */
  dissect_unknown_smb,      /* unknown SMB 0x3f */
  dissect_unknown_smb,      /* unknown SMB 0x40 */
  dissect_unknown_smb,      /* unknown SMB 0x41 */
  dissect_unknown_smb,      /* unknown SMB 0x42 */
  dissect_unknown_smb,      /* unknown SMB 0x43 */
  dissect_unknown_smb,      /* unknown SMB 0x44 */
  dissect_unknown_smb,      /* unknown SMB 0x45 */
  dissect_unknown_smb,      /* unknown SMB 0x46 */
  dissect_unknown_smb,      /* unknown SMB 0x47 */
  dissect_unknown_smb,      /* unknown SMB 0x48 */
  dissect_unknown_smb,      /* unknown SMB 0x49 */
  dissect_unknown_smb,      /* unknown SMB 0x4a */
  dissect_unknown_smb,      /* unknown SMB 0x4b */
  dissect_unknown_smb,      /* unknown SMB 0x4c */
  dissect_unknown_smb,      /* unknown SMB 0x4d */
  dissect_unknown_smb,      /* unknown SMB 0x4e */
  dissect_unknown_smb,      /* unknown SMB 0x4f */
  dissect_unknown_smb,      /* unknown SMB 0x50 */
  dissect_unknown_smb,      /* unknown SMB 0x51 */
  dissect_unknown_smb,      /* unknown SMB 0x52 */
  dissect_unknown_smb,      /* unknown SMB 0x53 */
  dissect_unknown_smb,      /* unknown SMB 0x54 */
  dissect_unknown_smb,      /* unknown SMB 0x55 */
  dissect_unknown_smb,      /* unknown SMB 0x56 */
  dissect_unknown_smb,      /* unknown SMB 0x57 */
  dissect_unknown_smb,      /* unknown SMB 0x58 */
  dissect_unknown_smb,      /* unknown SMB 0x59 */
  dissect_unknown_smb,      /* unknown SMB 0x5a */
  dissect_unknown_smb,      /* unknown SMB 0x5b */
  dissect_unknown_smb,      /* unknown SMB 0x5c */
  dissect_unknown_smb,      /* unknown SMB 0x5d */
  dissect_unknown_smb,      /* unknown SMB 0x5e */
  dissect_unknown_smb,      /* unknown SMB 0x5f */
  dissect_unknown_smb,      /* unknown SMB 0x60 */
  dissect_unknown_smb,      /* unknown SMB 0x61 */
  dissect_unknown_smb,      /* unknown SMB 0x62 */
  dissect_unknown_smb,      /* unknown SMB 0x63 */
  dissect_unknown_smb,      /* unknown SMB 0x64 */
  dissect_unknown_smb,      /* unknown SMB 0x65 */
  dissect_unknown_smb,      /* unknown SMB 0x66 */
  dissect_unknown_smb,      /* unknown SMB 0x67 */
  dissect_unknown_smb,      /* unknown SMB 0x68 */
  dissect_unknown_smb,      /* unknown SMB 0x69 */
  dissect_unknown_smb,      /* unknown SMB 0x6a */
  dissect_unknown_smb,      /* unknown SMB 0x6b */
  dissect_unknown_smb,      /* unknown SMB 0x6c */
  dissect_unknown_smb,      /* unknown SMB 0x6d */
  dissect_unknown_smb,      /* unknown SMB 0x6e */
  dissect_unknown_smb,      /* unknown SMB 0x6f */
  dissect_treecon_smb,      /* SMBtcon tree connect */
  dissect_tdis_smb,         /* SMBtdis tree disconnect */
  dissect_negprot_smb,      /* SMBnegprot negotiate a protocol */
  dissect_ssetup_andx_smb,  /* SMBsesssetupX Session Set Up & X (including User Logon) */
  dissect_logoff_andx_smb,  /* SMBlogof Logoff & X */
  dissect_tcon_andx_smb,    /* SMBtconX tree connect and X */
  dissect_unknown_smb,      /* unknown SMB 0x76 */
  dissect_unknown_smb,      /* unknown SMB 0x77 */
  dissect_unknown_smb,      /* unknown SMB 0x78 */
  dissect_unknown_smb,      /* unknown SMB 0x79 */
  dissect_unknown_smb,      /* unknown SMB 0x7a */
  dissect_unknown_smb,      /* unknown SMB 0x7b */
  dissect_unknown_smb,      /* unknown SMB 0x7c */
  dissect_unknown_smb,      /* unknown SMB 0x7d */
  dissect_unknown_smb,      /* unknown SMB 0x7e */
  dissect_unknown_smb,      /* unknown SMB 0x7f */
  dissect_get_disk_attr_smb,/* SMBdskattr get disk attributes */
  dissect_search_dir_smb,   /* SMBsearch search a directory */
  dissect_unknown_smb,      /* SMBffirst find first */
  dissect_unknown_smb,      /* SMBfunique find unique */
  dissect_unknown_smb,      /* SMBfclose find close */
  dissect_unknown_smb,      /* unknown SMB 0x85 */
  dissect_unknown_smb,      /* unknown SMB 0x86 */
  dissect_unknown_smb,      /* unknown SMB 0x87 */
  dissect_unknown_smb,      /* unknown SMB 0x88 */
  dissect_unknown_smb,      /* unknown SMB 0x89 */
  dissect_unknown_smb,      /* unknown SMB 0x8a */
  dissect_unknown_smb,      /* unknown SMB 0x8b */
  dissect_unknown_smb,      /* unknown SMB 0x8c */
  dissect_unknown_smb,      /* unknown SMB 0x8d */
  dissect_unknown_smb,      /* unknown SMB 0x8e */
  dissect_unknown_smb,      /* unknown SMB 0x8f */
  dissect_unknown_smb,      /* unknown SMB 0x90 */
  dissect_unknown_smb,      /* unknown SMB 0x91 */
  dissect_unknown_smb,      /* unknown SMB 0x92 */
  dissect_unknown_smb,      /* unknown SMB 0x93 */
  dissect_unknown_smb,      /* unknown SMB 0x94 */
  dissect_unknown_smb,      /* unknown SMB 0x95 */
  dissect_unknown_smb,      /* unknown SMB 0x96 */
  dissect_unknown_smb,      /* unknown SMB 0x97 */
  dissect_unknown_smb,      /* unknown SMB 0x98 */
  dissect_unknown_smb,      /* unknown SMB 0x99 */
  dissect_unknown_smb,      /* unknown SMB 0x9a */
  dissect_unknown_smb,      /* unknown SMB 0x9b */
  dissect_unknown_smb,      /* unknown SMB 0x9c */
  dissect_unknown_smb,      /* unknown SMB 0x9d */
  dissect_unknown_smb,      /* unknown SMB 0x9e */
  dissect_unknown_smb,      /* unknown SMB 0x9f */
  dissect_unknown_smb,      /* unknown SMB 0xa0 */
  dissect_unknown_smb,      /* unknown SMB 0xa1 */
  dissect_unknown_smb,      /* unknown SMB 0xa2 */
  dissect_unknown_smb,      /* unknown SMB 0xa3 */
  dissect_unknown_smb,      /* unknown SMB 0xa4 */
  dissect_unknown_smb,      /* unknown SMB 0xa5 */
  dissect_unknown_smb,      /* unknown SMB 0xa6 */
  dissect_unknown_smb,      /* unknown SMB 0xa7 */
  dissect_unknown_smb,      /* unknown SMB 0xa8 */
  dissect_unknown_smb,      /* unknown SMB 0xa9 */
  dissect_unknown_smb,      /* unknown SMB 0xaa */
  dissect_unknown_smb,      /* unknown SMB 0xab */
  dissect_unknown_smb,      /* unknown SMB 0xac */
  dissect_unknown_smb,      /* unknown SMB 0xad */
  dissect_unknown_smb,      /* unknown SMB 0xae */
  dissect_unknown_smb,      /* unknown SMB 0xaf */
  dissect_unknown_smb,      /* unknown SMB 0xb0 */
  dissect_unknown_smb,      /* unknown SMB 0xb1 */
  dissect_unknown_smb,      /* unknown SMB 0xb2 */
  dissect_unknown_smb,      /* unknown SMB 0xb3 */
  dissect_unknown_smb,      /* unknown SMB 0xb4 */
  dissect_unknown_smb,      /* unknown SMB 0xb5 */
  dissect_unknown_smb,      /* unknown SMB 0xb6 */
  dissect_unknown_smb,      /* unknown SMB 0xb7 */
  dissect_unknown_smb,      /* unknown SMB 0xb8 */
  dissect_unknown_smb,      /* unknown SMB 0xb9 */
  dissect_unknown_smb,      /* unknown SMB 0xba */
  dissect_unknown_smb,      /* unknown SMB 0xbb */
  dissect_unknown_smb,      /* unknown SMB 0xbc */
  dissect_unknown_smb,      /* unknown SMB 0xbd */
  dissect_unknown_smb,      /* unknown SMB 0xbe */
  dissect_unknown_smb,      /* unknown SMB 0xbf */
  dissect_unknown_smb,      /* SMBsplopen open a print spool file */
  dissect_write_print_file_smb,/* SMBsplwr write to a print spool file */
  dissect_close_print_file_smb,/* SMBsplclose close a print spool file */
  dissect_get_print_queue_smb, /* SMBsplretq return print queue */
  dissect_unknown_smb,      /* unknown SMB 0xc4 */
  dissect_unknown_smb,      /* unknown SMB 0xc5 */
  dissect_unknown_smb,      /* unknown SMB 0xc6 */
  dissect_unknown_smb,      /* unknown SMB 0xc7 */
  dissect_unknown_smb,      /* unknown SMB 0xc8 */
  dissect_unknown_smb,      /* unknown SMB 0xc9 */
  dissect_unknown_smb,      /* unknown SMB 0xca */
  dissect_unknown_smb,      /* unknown SMB 0xcb */
  dissect_unknown_smb,      /* unknown SMB 0xcc */
  dissect_unknown_smb,      /* unknown SMB 0xcd */
  dissect_unknown_smb,      /* unknown SMB 0xce */
  dissect_unknown_smb,      /* unknown SMB 0xcf */
  dissect_unknown_smb,      /* SMBsends send a single block message */
  dissect_unknown_smb,      /* SMBsendb send a broadcast message */
  dissect_unknown_smb,      /* SMBfwdname forward user name */
  dissect_unknown_smb,      /* SMBcancelf cancel forward */
  dissect_unknown_smb,      /* SMBgetmac get a machine name */
  dissect_unknown_smb,      /* SMBsendstrt send start of multi-block message */
  dissect_unknown_smb,      /* SMBsendend send end of multi-block message */
  dissect_unknown_smb,      /* SMBsendtxt send text of multi-block message */
  dissect_unknown_smb,      /* unknown SMB 0xd8 */
  dissect_unknown_smb,      /* unknown SMB 0xd9 */
  dissect_unknown_smb,      /* unknown SMB 0xda */
  dissect_unknown_smb,      /* unknown SMB 0xdb */
  dissect_unknown_smb,      /* unknown SMB 0xdc */
  dissect_unknown_smb,      /* unknown SMB 0xdd */
  dissect_unknown_smb,      /* unknown SMB 0xde */
  dissect_unknown_smb,      /* unknown SMB 0xdf */
  dissect_unknown_smb,      /* unknown SMB 0xe0 */
  dissect_unknown_smb,      /* unknown SMB 0xe1 */
  dissect_unknown_smb,      /* unknown SMB 0xe2 */
  dissect_unknown_smb,      /* unknown SMB 0xe3 */
  dissect_unknown_smb,      /* unknown SMB 0xe4 */
  dissect_unknown_smb,      /* unknown SMB 0xe5 */
  dissect_unknown_smb,      /* unknown SMB 0xe6 */
  dissect_unknown_smb,      /* unknown SMB 0xe7 */
  dissect_unknown_smb,      /* unknown SMB 0xe8 */
  dissect_unknown_smb,      /* unknown SMB 0xe9 */
  dissect_unknown_smb,      /* unknown SMB 0xea */
  dissect_unknown_smb,      /* unknown SMB 0xeb */
  dissect_unknown_smb,      /* unknown SMB 0xec */
  dissect_unknown_smb,      /* unknown SMB 0xed */
  dissect_unknown_smb,      /* unknown SMB 0xee */
  dissect_unknown_smb,      /* unknown SMB 0xef */
  dissect_unknown_smb,      /* unknown SMB 0xf0 */
  dissect_unknown_smb,      /* unknown SMB 0xf1 */
  dissect_unknown_smb,      /* unknown SMB 0xf2 */
  dissect_unknown_smb,      /* unknown SMB 0xf3 */
  dissect_unknown_smb,      /* unknown SMB 0xf4 */
  dissect_unknown_smb,      /* unknown SMB 0xf5 */
  dissect_unknown_smb,      /* unknown SMB 0xf6 */
  dissect_unknown_smb,      /* unknown SMB 0xf7 */
  dissect_unknown_smb,      /* unknown SMB 0xf8 */
  dissect_unknown_smb,      /* unknown SMB 0xf9 */
  dissect_unknown_smb,      /* unknown SMB 0xfa */
  dissect_unknown_smb,      /* unknown SMB 0xfb */
  dissect_unknown_smb,      /* unknown SMB 0xfc */
  dissect_unknown_smb,      /* unknown SMB 0xfd */
  dissect_unknown_smb,      /* SMBinvalid invalid command */
  dissect_unknown_smb       /* unknown SMB 0xff */

};

static const value_string errcls_types[] = {
  { SMB_SUCCESS, "Success"},
  { SMB_ERRDOS, "DOS Error"},
  { SMB_ERRSRV, "Server Error"},
  { SMB_ERRHRD, "Hardware Error"},
  { SMB_ERRCMD, "Command Error - Not an SMB format command"},
  { 0, NULL }
};

char *decode_smb_name(unsigned char cmd)
{

  return(SMB_names[cmd]);

}

static const value_string DOS_errors[] = {
  {SMBE_badfunc, "Invalid function (or system call)"},
  {SMBE_badfile, "File not found (pathname error)"},
  {SMBE_badpath, "Directory not found"},
  {SMBE_nofids, "Too many open files"},
  {SMBE_noaccess, "Access denied"},
  {SMBE_badfid, "Invalid fid"},
  {SMBE_nomem,  "Out of memory"},
  {SMBE_badmem, "Invalid memory block address"},
  {SMBE_badenv, "Invalid environment"},
  {SMBE_badaccess, "Invalid open mode"},
  {SMBE_baddata, "Invalid data (only from ioctl call)"},
  {SMBE_res, "Reserved error code?"}, 
  {SMBE_baddrive, "Invalid drive"},
  {SMBE_remcd, "Attempt to delete current directory"},
  {SMBE_diffdevice, "Rename/move across different filesystems"},
  {SMBE_nofiles, "no more files found in file search"},
  {SMBE_badshare, "Share mode on file conflict with open mode"},
  {SMBE_lock, "Lock request conflicts with existing lock"},
  {SMBE_unsup, "Request unsupported, returned by Win 95"},
  {SMBE_nosuchshare, "Requested share does not exist"},
  {SMBE_filexists, "File in operation already exists"},
  {SMBE_cannotopen, "Cannot open the file specified"},
  {SMBE_unknownlevel, "Unknown level??"},
  {SMBE_badpipe, "Named pipe invalid"},
  {SMBE_pipebusy, "All instances of pipe are busy"},
  {SMBE_pipeclosing, "Named pipe close in progress"},
  {SMBE_notconnected, "No process on other end of named pipe"},
  {SMBE_moredata, "More data to be returned"},
  {SMBE_baddirectory,  "Invalid directory name in a path."},
  {SMBE_eas_didnt_fit, "Extended attributes didn't fit"},
  {SMBE_eas_nsup, "Extended attributes not supported"},
  {SMBE_notify_buf_small, "Buffer too small to return change notify."},
  {SMBE_unknownipc, "Unknown IPC Operation"},
  {SMBE_noipc, "Don't support ipc"},
  {0, NULL}
  };

/* Error codes for the ERRSRV class */

static const value_string SRV_errors[] = {
  {SMBE_error, "Non specific error code"},
  {SMBE_badpw, "Bad password"},
  {SMBE_badtype, "Reserved"},
  {SMBE_access, "No permissions to perform the requested operation"},
  {SMBE_invnid, "TID invalid"},
  {SMBE_invnetname, "Invalid network name. Service not found"},
  {SMBE_invdevice, "Invalid device"},
  {SMBE_unknownsmb, "Unknown SMB, from NT 3.5 response"},
  {SMBE_qfull, "Print queue full"},
  {SMBE_qtoobig, "Queued item too big"},
  {SMBE_qeof, "EOF on print queue dump"},
  {SMBE_invpfid, "Invalid print file in smb_fid"},
  {SMBE_smbcmd, "Unrecognised command"},
  {SMBE_srverror, "SMB server internal error"},
  {SMBE_filespecs, "Fid and pathname invalid combination"},
  {SMBE_badlink, "Bad link in request ???"},
  {SMBE_badpermits, "Access specified for a file is not valid"},
  {SMBE_badpid, "Bad process id in request"},
  {SMBE_setattrmode, "Attribute mode invalid"},
  {SMBE_paused, "Message server paused"},
  {SMBE_msgoff, "Not receiving messages"},
  {SMBE_noroom, "No room for message"},
  {SMBE_rmuns, "Too many remote usernames"},
  {SMBE_timeout, "Operation timed out"},
  {SMBE_noresource, "No resources currently available for request."},
  {SMBE_toomanyuids, "Too many userids"},
  {SMBE_baduid, "Bad userid"},
  {SMBE_useMPX, "Temporarily unable to use raw mode, use MPX mode"},
  {SMBE_useSTD, "Temporarily unable to use raw mode, use standard mode"},
  {SMBE_contMPX, "Resume MPX mode"},
  {SMBE_badPW, "Bad Password???"},
  {SMBE_nosupport, "Operation not supported"},
  { 0, NULL}
};

/* Error codes for the ERRHRD class */

static const value_string HRD_errors[] = {
  {SMBE_nowrite, "read only media"},
  {SMBE_badunit, "Unknown device"},
  {SMBE_notready, "Drive not ready"},
  {SMBE_badcmd, "Unknown command"},
  {SMBE_data, "Data (CRC) error"},
  {SMBE_badreq, "Bad request structure length"},
  {SMBE_seek, "Seek error???"},
  {SMBE_badmedia, "Bad media???"},
  {SMBE_badsector, "Bad sector???"},
  {SMBE_nopaper, "No paper in printer???"},
  {SMBE_write, "Write error???"},
  {SMBE_read, "Read error???"},
  {SMBE_general, "General error???"},
  {SMBE_badshare, "A open conflicts with an existing open"},
  {SMBE_lock, "Lock/unlock error"},
  {SMBE_wrongdisk,  "Wrong disk???"},
  {SMBE_FCBunavail, "FCB unavailable???"},
  {SMBE_sharebufexc, "Share buffer excluded???"},
  {SMBE_diskfull, "Disk full???"},
  {0, NULL}
};

char *decode_smb_error(guint8 errcls, guint16 errcode)
{

  switch (errcls) {

  case SMB_SUCCESS:

    return("No Error");   /* No error ??? */
    break;

  case SMB_ERRDOS:

    return(val_to_str(errcode, DOS_errors, "Unknown DOS error (%x)"));
    break;

  case SMB_ERRSRV:

    return(val_to_str(errcode, SRV_errors, "Unknown SRV error (%x)"));
    break;

  case SMB_ERRHRD:

    return(val_to_str(errcode, HRD_errors, "Unknown HRD error (%x)"));
    break;

  default:

    return("Unknown error class!");

  }

}

#define SMB_FLAGS_DIRN 0x80

void
dissect_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int max_data)
{
        proto_tree      *smb_tree = tree, *flags_tree, *flags2_tree;
	proto_item      *ti, *tf;
	guint8          cmd, errcls, errcode1, flags;
	guint16         flags2, errcode, tid, pid, uid, mid;
	guint32         status;
	int             SMB_offset = offset;
	struct smb_info si;

	OLD_CHECK_DISPLAY_AS_DATA(proto_smb, pd, offset, fd, tree);

	si.unicode = 0;

	cmd = pd[offset + SMB_hdr_com_offset];

	if (check_col(fd, COL_PROTOCOL))
		col_set_str(fd, COL_PROTOCOL, "SMB");

	/* Hmmm, poor coding here ... Also, should check the type */

	if (check_col(fd, COL_INFO)) {

	  col_add_fstr(fd, COL_INFO, "%s %s", decode_smb_name(cmd), (pi.match_port == pi.destport)? "Request" : "Response");

	}

	if (tree) {

	  ti = proto_tree_add_item(tree, proto_smb, NullTVB, offset, END_OF_FRAME, FALSE);
	  smb_tree = proto_item_add_subtree(ti, ett_smb);

	  /* 0xFFSMB is actually a 1 byte msg type and 3 byte server
	   * component ... SMB is only one used
	   */

	  proto_tree_add_text(smb_tree, NullTVB, offset, 1, "Message Type: 0xFF");
	  proto_tree_add_text(smb_tree, NullTVB, offset+1, 3, "Server Component: SMB");

	}

	offset += 4;  /* Skip the marker */

	if (tree) {

	  proto_tree_add_uint(smb_tree, hf_smb_cmd, NullTVB, offset, 1, cmd);

	}

	offset += 1;

	/* Handle error code */

	if (GSHORT(pd, SMB_offset + 10) & 0x4000) {

	    /* handle NT 32 bit error code */
	    errcode = 0;	/* better than a random number */
	    status = GWORD(pd, offset); 

	    if (tree) {

		proto_tree_add_text(smb_tree, NullTVB, offset, 4, "Status: 0x%08x",
				    status);

	    }

	    offset += 4;

	}
	else {
	    /* handle DOS error code & class */

	    /* Next, look at the error class, SMB_RETCLASS */

	    errcls = pd[offset];

	    if (tree) {

		proto_tree_add_text(smb_tree, NullTVB, offset, 1, "Error Class: %s", 
				    val_to_str((guint8)pd[offset], errcls_types, "Unknown Error Class (%x)"));
	    }

	    offset += 1;

	    /* Error code, SMB_HEINFO ... */

	    errcode1 = pd[offset];

	    if (tree) {

		proto_tree_add_text(smb_tree, NullTVB, offset, 1, "Reserved: %i", errcode1); 

	    }

	    offset += 1;

	    errcode = GSHORT(pd, offset); 

	    if (tree) {

		proto_tree_add_text(smb_tree, NullTVB, offset, 2, "Error Code: %s",
				    decode_smb_error(errcls, errcode));

	    }

	    offset += 2;
	}

	/* Now for the flags: Bit 0 = 0 means cmd, 0 = 1 means resp */

	flags = pd[offset];

	if (tree) {

	  tf = proto_tree_add_text(smb_tree, NullTVB, offset, 1, "Flags: 0x%02x", flags);

	  flags_tree = proto_item_add_subtree(tf, ett_smb_flags);
	  proto_tree_add_text(flags_tree, NullTVB, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x01, 8,
						      "Lock&Read, Write&Unlock supported",
						      "Lock&Read, Write&Unlock not supported"));
	  proto_tree_add_text(flags_tree, NullTVB, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x02, 8,
						      "Receive buffer posted",
						      "Receive buffer not posted"));
	  proto_tree_add_text(flags_tree, NullTVB, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x08, 8, 
						      "Path names caseless",
						      "Path names case sensitive"));
	  proto_tree_add_text(flags_tree, NullTVB, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x10, 8,
						      "Pathnames canonicalized",
						      "Pathnames not canonicalized"));
	  proto_tree_add_text(flags_tree, NullTVB, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x20, 8,
						      "OpLocks requested/granted",
						      "OpLocks not requested/granted"));
	  proto_tree_add_text(flags_tree, NullTVB, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x40, 8, 
						      "Notify all",
						      "Notify open only"));

	  proto_tree_add_text(flags_tree, NullTVB, offset, 1, "%s",
			      decode_boolean_bitfield(flags, SMB_FLAGS_DIRN,
						      8, "Response to client/redirector", "Request to server"));

	}

	offset += 1;

	flags2 = GSHORT(pd, offset);

	if (tree) {

	  tf = proto_tree_add_text(smb_tree, NullTVB, offset, 2, "Flags2: 0x%04x", flags2);

	  flags2_tree = proto_item_add_subtree(tf, ett_smb_flags2);
	  proto_tree_add_text(flags2_tree, NullTVB, offset, 2, "%s",
			      decode_boolean_bitfield(flags2, 0x0001, 16,
						      "Long file names supported",
						      "Long file names not supported"));
	  proto_tree_add_text(flags2_tree, NullTVB, offset, 2, "%s",
			      decode_boolean_bitfield(flags2, 0x0002, 16,
						      "Extended attributes supported",
						      "Extended attributes not supported"));
	  proto_tree_add_text(flags2_tree, NullTVB, offset, 1, "%s",
			      decode_boolean_bitfield(flags2, 0x0004, 16,
						      "Security signatures supported",
						      "Security signatures not supported"));
	  proto_tree_add_text(flags2_tree, NullTVB, offset, 2, "%s",
			      decode_boolean_bitfield(flags2, 0x0800, 16,
						      "Extended security negotiation supported",
						      "Extended security negotiation not supported"));
	  proto_tree_add_text(flags2_tree, NullTVB, offset, 2, "%s",
			      decode_boolean_bitfield(flags2, 0x1000, 16, 
						      "Resolve pathnames with DFS",
						      "Don't resolve pathnames with DFS"));
	  proto_tree_add_text(flags2_tree, NullTVB, offset, 2, "%s",
			      decode_boolean_bitfield(flags2, 0x2000, 16,
						      "Permit reads if execute-only",
						      "Don't permit reads if execute-only"));
	  proto_tree_add_text(flags2_tree, NullTVB, offset, 2, "%s",
			      decode_boolean_bitfield(flags2, 0x4000, 16,
						      "Error codes are NT error codes",
						      "Error codes are DOS error codes"));
	  proto_tree_add_text(flags2_tree, NullTVB, offset, 2, "%s",
			      decode_boolean_bitfield(flags2, 0x8000, 16, 
						      "Strings are Unicode",
						      "Strings are ASCII"));

	}

	if (flags2 & 0x8000) si.unicode = 1; /* Mark them as Unicode */

	offset += 2;

	if (tree) {

	  proto_tree_add_text(smb_tree, NullTVB, offset, 12, "Reserved: 6 WORDS");

	}

	offset += 12;

	/* Now the TID, tree ID */

	tid = GSHORT(pd, offset);
	si.tid = tid;

	if (tree) {

	  proto_tree_add_text(smb_tree, NullTVB, offset, 2, "Network Path/Tree ID (TID): %i (%04x)", tid, tid); 

	}

	offset += 2;

	/* Now the PID, Process ID */

	pid = GSHORT(pd, offset);
	si.pid = pid;

	if (tree) {

	  proto_tree_add_text(smb_tree, NullTVB, offset, 2, "Process ID (PID): %i (%04x)", pid, pid); 

	}

	offset += 2;

        /* Now the UID, User ID */

	uid = GSHORT(pd, offset);
	si.uid = uid;

	if (tree) {

	  proto_tree_add_text(smb_tree, NullTVB, offset, 2, "User ID (UID): %i (%04x)", uid, uid); 

	}
	
	offset += 2;

        /* Now the MID, Multiplex ID */

	mid = GSHORT(pd, offset);
	si.mid = mid;

	if (tree) {

	  proto_tree_add_text(smb_tree, NullTVB, offset, 2, "Multiplex ID (MID): %i (%04x)", mid, mid); 

	}

	offset += 2;

	/* Now vector through the table to dissect them */

	(dissect[cmd])(pd, offset, fd, tree, smb_tree, si, max_data, SMB_offset, errcode,
		       ((flags & 0x80) == 0));


}

/*** External routines called during the registration process */

extern void register_proto_smb_browse( void);
extern void register_proto_smb_logon( void);
extern void register_proto_smb_mailslot( void);
extern void register_proto_smb_pipe( void);
extern void register_proto_smb_mailslot( void);


void
proto_register_smb(void)
{
  static hf_register_info hf[] = {
    { &hf_smb_cmd,
      { "SMB Command", "smb.cmd",
	FT_UINT8, BASE_HEX, VALS(smb_cmd_vals), 0x0, "" }}


  };
	static gint *ett[] = {
		&ett_smb,
		&ett_smb_fileattributes,
		&ett_smb_capabilities,
		&ett_smb_aflags,
		&ett_smb_dialects,
		&ett_smb_mode,
		&ett_smb_rawmode,
		&ett_smb_flags,
		&ett_smb_flags2,
		&ett_smb_desiredaccess,
		&ett_smb_search,
		&ett_smb_file,
		&ett_smb_openfunction,
		&ett_smb_filetype,
		&ett_smb_action,
		&ett_smb_writemode,
		&ett_smb_lock_type,
	};

        proto_smb = proto_register_protocol("SMB (Server Message Block Protocol)",
	    "SMB", "smb");

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_smb, hf, array_length(hf));
	register_init_routine(&smb_init_protocol);
	
	register_proto_smb_browse();
	register_proto_smb_logon( );
	register_proto_smb_mailslot();
	register_proto_smb_pipe();

}
