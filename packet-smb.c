/* packet-smb.c
 * Routines for smb packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-smb.c,v 1.123 2001/11/03 00:58:49 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
static int hf_smb_status = -1;
static int hf_smb_errcls = -1;
static int hf_smb_flags = -1;
static int hf_smb_flags2 = -1;
static int hf_smb_tid = -1;
static int hf_smb_pid = -1;
static int hf_smb_uid = -1;
static int hf_smb_mid = -1;

static gint ett_smb = -1;
static gint ett_smb_hdr = -1;
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
static gint ett_smb_openaction = -1;
static gint ett_smb_writemode = -1;
static gint ett_smb_lock_type = -1;
static gint ett_smb_ssetupandxaction = -1;
static gint ett_smb_optionsup = -1;


/*
 * Struct passed to each SMB decode routine of info it may need
 */

char *decode_smb_name(unsigned char);

int smb_packet_init_count = 200;

/*
 * This is a hash table matching transaction requests and replies.
 *
 * Unfortunately, the MID is not a transaction ID in, say, the ONC RPC
 * sense; instead, it's a "multiplex ID" used when there's more than one
 * request *currently* in flight, to distinguish replies.
 *
 * This means that the MID and PID don't uniquely identify a request in
 * a conversation.
 *
 * Therefore, we have to use some other value to distinguish between
 * requests with the same MID and PID.
 *
 * On the first pass through the capture, when we first see a request,
 * we hash it by conversation, MID, and PID.
 *
 * When we first see a reply to it, we add it to a new hash table,
 * hashing it by conversation, MID, PID, and frame number of the reply.
 *
 * This works as long as
 *
 *	1) a client doesn't screw up and have multiple requests outstanding
 *	   with the same MID and PID
 *
 * and
 *
 *	2) we don't have, within the same frame, replies to multiple
 *	   requests with the same MID and PID.
 *
 * 2) should happen only if the server screws up and puts the wrong MID or
 * PID into a reply (in which case not only can we not handle this, the
 * client can't handle it either) or if the client has screwed up as per
 * 1) and the server's dutifully replied to both of the requests with the
 * same MID and PID (in which case, again, neither we nor the client can
 * handle this).
 *
 * We don't have to correctly dissect screwups; we just have to keep from
 * dumping core on them.
 *
 * XXX - in addition, we need to keep a hash table of replies, so that we
 * can associate continuations with the reply to which they're a continuation.
 */
struct smb_request_key {
  guint32 conversation;
  guint16 mid;
  guint16 pid;
  guint32 frame_num;
};

static GHashTable *smb_request_hash = NULL;
static GMemChunk *smb_request_keys = NULL;
static GMemChunk *smb_request_vals = NULL;

/*
 * This is a hash table matching continued transation replies and their
 * continuations.
 *
 * It works similarly to the request/reply hash table.
 */
static GHashTable *smb_continuation_hash = NULL;

static GMemChunk *smb_continuation_vals = NULL;

/* Hash Functions */
static gint
smb_equal(gconstpointer v, gconstpointer w)
{
  struct smb_request_key *v1 = (struct smb_request_key *)v;
  struct smb_request_key *v2 = (struct smb_request_key *)w;

#if defined(DEBUG_SMB_HASH)
  printf("Comparing %08X:%u:%u:%u\n      and %08X:%u:%u:%u\n",
	 v1 -> conversation, v1 -> mid, v1 -> pid, v1 -> frame_num,
	 v2 -> conversation, v2 -> mid, v2 -> pid, v2 -> frame_num);
#endif

  if (v1 -> conversation == v2 -> conversation &&
      v1 -> mid          == v2 -> mid &&
      v1 -> pid          == v2 -> pid &&
      v1 -> frame_num    == v2 -> frame_num) {

    return 1;

  }

  return 0;
}

static guint
smb_hash (gconstpointer v)
{
  struct smb_request_key *key = (struct smb_request_key *)v;
  guint val;

  val = (key -> conversation) + (key -> mid) + (key -> pid) +
	(key -> frame_num);

#if defined(DEBUG_SMB_HASH)
  printf("SMB Hash calculated as %u\n", val);
#endif

  return val;

}

/*
 * Free up any state information we've saved, and re-initialize the
 * tables of state information.
 */

/*
 * For a hash table entry, free the address data to which the key refers
 * and the fragment data to which the value refers.
 * (The actual key and value structures get freed by "reassemble_init()".)
 */
static gboolean
free_request_val_data(gpointer key, gpointer value, gpointer user_data)
{
  struct smb_request_val *request_val = value;

  if (request_val->last_transact_command != NULL)
    g_free(request_val->last_transact_command);
  if (request_val->last_param_descrip != NULL)
    g_free(request_val->last_param_descrip);
  if (request_val->last_data_descrip != NULL)
    g_free(request_val->last_data_descrip);
  if (request_val->last_aux_data_descrip != NULL)
    g_free(request_val->last_aux_data_descrip);
  return TRUE;
}

static struct smb_request_val *
do_transaction_hashing(conversation_t *conversation, struct smb_info si,
		       frame_data *fd)
{
  struct smb_request_key request_key, *new_request_key;
  struct smb_request_val *request_val = NULL;
  gpointer               new_request_key_ret, request_val_ret;

  if (si.request) {
    /*
     * This is a request.
     *
     * If this is the first time the frame has been seen, check for
     * an entry for the request in the hash table.  If it's not found,
     * insert an entry for it.
     *
     * If it's the first time it's been seen, then we can't have seen
     * the reply yet, so the reply frame number should be 0, for
     * "unknown".
     */
    if (!fd->flags.visited) {
      request_key.conversation = conversation->index;
      request_key.mid          = si.mid;
      request_key.pid          = si.pid;
      request_key.frame_num    = 0;

      request_val = (struct smb_request_val *) g_hash_table_lookup(smb_request_hash, &request_key);

      if (request_val == NULL) {
	/*
	 * Not found.
	 */
	new_request_key = g_mem_chunk_alloc(smb_request_keys);
	new_request_key -> conversation = conversation->index;
	new_request_key -> mid          = si.mid;
	new_request_key -> pid          = si.pid;
	new_request_key -> frame_num    = 0;

	request_val = g_mem_chunk_alloc(smb_request_vals);
	request_val -> frame = fd->num;
	request_val -> last_transact2_command = -1;		/* unknown */
	request_val -> last_transact_command = NULL;
	request_val -> last_param_descrip = NULL;
	request_val -> last_data_descrip = NULL;
	request_val -> last_aux_data_descrip = NULL;

	g_hash_table_insert(smb_request_hash, new_request_key, request_val);
      } else {
	/*
	 * This means that we've seen another request in this conversation
	 * with the same request and reply, and without an intervening
	 * reply to that first request, and thus won't be using this
	 * "request_val" structure for that request (as we'd use it only
	 * for the reply).
	 *
	 * Clean out the structure, and set it to refer to this frame.
	 */
	request_val -> frame = fd->num;
	request_val -> last_transact2_command = -1;		/* unknown */
	if (request_val -> last_transact_command)
	  g_free(request_val -> last_transact_command);
	request_val -> last_transact_command = NULL;
	if (request_val -> last_param_descrip)
	  g_free(request_val -> last_param_descrip);
	request_val -> last_param_descrip = NULL;
	if (request_val -> last_data_descrip)
	  g_free(request_val -> last_data_descrip);
	request_val -> last_data_descrip = NULL;
	if (request_val -> last_aux_data_descrip)
	  g_free(request_val -> last_aux_data_descrip);
	request_val -> last_aux_data_descrip = NULL;
      }
    }
  } else {
    /*
     * This is a reply.
     */
    if (!fd->flags.visited) {
      /*
       * This is the first time the frame has been seen; check for
       * an entry for a matching request, with an unknown reply frame
       * number, in the hash table.
       *
       * If we find it, re-hash it with this frame's number as the
       * reply frame number.
       */
      request_key.conversation = conversation->index;
      request_key.mid          = si.mid;
      request_key.pid          = si.pid;
      request_key.frame_num    = 0;

      /*
       * Look it up - and, if we find it, get pointers to the key and
       * value structures for it.
       */
      if (g_hash_table_lookup_extended(smb_request_hash, &request_key,
				       &new_request_key_ret,
				       &request_val_ret)) {
	new_request_key = new_request_key_ret;
	request_val = request_val_ret;

	/*
	 * We found it.
	 * Remove the old entry.
	 */
	g_hash_table_remove(smb_request_hash, &request_key);

	/*
	 * Now update the key, and put it back into the hash table with
	 * the new key.
	 */
	new_request_key->frame_num = fd->num;
	g_hash_table_insert(smb_request_hash, new_request_key, request_val);
      }
    } else {
      /*
       * This is not the first time the frame has been seen; check for
       * an entry for a matching request, with this frame's frame
       * number as the reply frame number, in the hash table.
       */
      request_key.conversation = conversation->index;
      request_key.mid          = si.mid;
      request_key.pid          = si.pid;
      request_key.frame_num    = fd->num;

      request_val = (struct smb_request_val *) g_hash_table_lookup(smb_request_hash, &request_key);
    }
  }

  return request_val;
}

static struct smb_continuation_val *
do_continuation_hashing(conversation_t *conversation, struct smb_info si,
		       frame_data *fd, guint16 TotalDataCount,
		       guint16 DataCount, const char **TransactName)
{
  struct smb_request_key request_key, *new_request_key;
  struct smb_continuation_val *continuation_val, *new_continuation_val;
  gpointer               new_request_key_ret, continuation_val_ret;

  continuation_val = NULL;
  if (si.ddisp != 0) {
    /*
     * This reply isn't the first in the series; there should be a
     * reply of which it is a continuation.
     */
    if (!fd->flags.visited) {
      /*
       * This is the first time the frame has been seen; check for
       * an entry for a matching continued message, with an unknown
       * continuation frame number, in the hash table.
       *
       * If we find it, re-hash it with this frame's number as the
       * continuation frame number.
       */
      request_key.conversation = conversation->index;
      request_key.mid          = si.mid;
      request_key.pid          = si.pid;
      request_key.frame_num    = 0;

      /*
       * Look it up - and, if we find it, get pointers to the key and
       * value structures for it.
       */
      if (g_hash_table_lookup_extended(smb_continuation_hash, &request_key,
				       &new_request_key_ret,
				       &continuation_val_ret)) {
	new_request_key = new_request_key_ret;
	continuation_val = continuation_val_ret;

	/*
	 * We found it.
	 * Remove the old entry.
	 */
	g_hash_table_remove(smb_continuation_hash, &request_key);

	/*
	 * Now update the key, and put it back into the hash table with
	 * the new key.
	 */
	new_request_key->frame_num = fd->num;
	g_hash_table_insert(smb_continuation_hash, new_request_key,
			    continuation_val);
      }
    } else {
      /*
       * This is not the first time the frame has been seen; check for
       * an entry for a matching request, with this frame's frame
       * number as the continuation frame number, in the hash table.
       */
      request_key.conversation = conversation->index;
      request_key.mid          = si.mid;
      request_key.pid          = si.pid;
      request_key.frame_num    = fd->num;

      continuation_val = (struct smb_continuation_val *)
		g_hash_table_lookup(smb_continuation_hash, &request_key);
    }
  }

  /*
   * If we found the entry for the message of which this is a continuation,
   * and our caller cares, get the transaction name for that message, as
   * it's the transaction name for this message as well.
   */
  if (continuation_val != NULL && TransactName != NULL)
    *TransactName = continuation_val -> transact_name;

  if (TotalDataCount > DataCount + si.ddisp) {
    /*
     * This reply isn't the last in the series; there should be a
     * continuation for it later in the capture.
     *
     * If this is the first time the frame has been seen, check for
     * an entry for the reply in the hash table.  If it's not found,
     * insert an entry for it.
     *
     * If it's the first time it's been seen, then we can't have seen
     * the continuation yet, so the continuation frame number should
     * be 0, for "unknown".
     */
    if (!fd->flags.visited) {
      request_key.conversation = conversation->index;
      request_key.mid          = si.mid;
      request_key.pid          = si.pid;
      request_key.frame_num    = 0;

      new_continuation_val = (struct smb_continuation_val *)
		g_hash_table_lookup(smb_continuation_hash, &request_key);

      if (new_continuation_val == NULL) {
	/*
	 * Not found.
	 */
	new_request_key = g_mem_chunk_alloc(smb_request_keys);
	new_request_key -> conversation = conversation->index;
	new_request_key -> mid          = si.mid;
	new_request_key -> pid          = si.pid;
	new_request_key -> frame_num    = 0;

	new_continuation_val = g_mem_chunk_alloc(smb_continuation_vals);
	new_continuation_val -> frame = fd->num;
	if (TransactName != NULL)
	  new_continuation_val -> transact_name = *TransactName;
	else
	  new_continuation_val -> transact_name = NULL;

	g_hash_table_insert(smb_continuation_hash, new_request_key,
			    new_continuation_val);
      } else {
	/*
	 * This presumably means we never saw the continuation of
	 * the message we found, and this is a reply to a different
	 * request; as we never saw the continuation of that message,
	 * we won't be using this "request_val" structure for that
	 * message (as we'd use it only for the continuation).
	 *
	 * Clean out the structure, and set it to refer to this frame.
	 */
	new_continuation_val -> frame = fd->num;
      }
    }
  }

  return continuation_val;
}

static void
smb_init_protocol(void)
{
#if defined(DEBUG_SMB_HASH)
  printf("Initializing SMB hashtable area\n");
#endif

  if (smb_request_hash) {
    /*
     * Remove all entries from the hash table and free all strings
     * attached to the keys and values.  (The keys and values
     * themselves are freed with "g_mem_chunk_destroy()" calls
     * below.)
     */
    g_hash_table_foreach_remove(smb_request_hash, free_request_val_data, NULL);
    g_hash_table_destroy(smb_request_hash);
  }
  if (smb_continuation_hash)
    g_hash_table_destroy(smb_continuation_hash);
  if (smb_request_keys)
    g_mem_chunk_destroy(smb_request_keys);
  if (smb_request_vals)
    g_mem_chunk_destroy(smb_request_vals);
  if (smb_continuation_vals)
    g_mem_chunk_destroy(smb_continuation_vals);

  smb_request_hash = g_hash_table_new(smb_hash, smb_equal);
  smb_continuation_hash = g_hash_table_new(smb_hash, smb_equal);
  smb_request_keys = g_mem_chunk_new("smb_request_keys",
				     sizeof(struct smb_request_key),
				     smb_packet_init_count * sizeof(struct smb_request_key), G_ALLOC_AND_FREE);
  smb_request_vals = g_mem_chunk_new("smb_request_vals",
				     sizeof(struct smb_request_val),
				     smb_packet_init_count * sizeof(struct smb_request_val), G_ALLOC_AND_FREE);
  smb_continuation_vals = g_mem_chunk_new("smb_continuation_vals",
				     sizeof(struct smb_continuation_val),
				     smb_packet_init_count * sizeof(struct smb_continuation_val), G_ALLOC_AND_FREE);
}

static void (*dissect[256])(const u_char *, int, frame_data *, proto_tree *, proto_tree *, struct smb_info si, int, int);

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
  { 0x1A, "SMBreadBraw" },
  { 0x1B, "SMBreadBmpx" },
  { 0x1C, "SMBreadBs" },
  { 0x1D, "SMBwriteBraw" },
  { 0x1E, "SMBwriteBmpx" },
  { 0x1F, "SMBwriteBs" },
  { 0x20, "SMBwriteC" },
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
  { 0x31, "SMBcloseandtreedisc" },
  { 0x32, "SMBtrans2" },
  { 0x33, "SMBtrans2secondary" },
  { 0x34, "SMBfindclose2" },
  { 0x35, "SMBfindnotifyclose" },
  { 0x70, "SMBtcon" },
  { 0x71, "SMBtdis" },
  { 0x72, "SMBnegprot" },
  { 0x73, "SMBsesssetupX" },
  { 0x74, "SMBlogoffX" },
  { 0x75, "SMBtconX" },
  { 0x80, "SMBdskattr" },
  { 0x81, "SMBsearch" },
  { 0x82, "SMBffirst" },
  { 0x83, "SMBfunique" },
  { 0x84, "SMBfclose" },
  { 0xA0, "SMBnttransact" },
  { 0xA1, "SMBnttransactsecondary" },
  { 0xA2, "SMBntcreateX" },
  { 0xA4, "SMBntcancel" },
  { 0xC0, "SMBsplopen" },
  { 0xC1, "SMBsplwr" },
  { 0xC2, "SMBsplclose" },
  { 0xC3, "SMBsplretq" },
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
  { 0xFE, "SMBinvalid" },
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
dissect_unknown_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)
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

/* Get a null terminated string, which is Unicode if "is_unicode" is true
   and ASCII (OEM character set) otherwise.
   XXX - for now, we just handle the ISO 8859-1 subset of Unicode. */
static const gchar *
get_unicode_or_ascii_string(const u_char *pd, int *offsetp, int SMB_offset,
    gboolean is_unicode, int *len)
{
  int offset = *offsetp;
  const gchar *string;
  int string_len;

  if (is_unicode) {
    if ((offset - SMB_offset) % 2) {
      /*
       * XXX - this should be an offset relative to the beginning of the SMB,
       * not an offset relative to the beginning of the frame; if the stuff
       * before the SMB has an odd number of bytes, an offset relative to
       * the beginning of the frame will give the wrong answer.
       */
      offset++;   /* Looks like a pad byte there sometimes */
      *offsetp = offset;
    }
    string = unicode_to_str(pd + offset, &string_len);
    string_len += 2;
  } else {
    string = pd + offset;
    string_len = strlen(string) + 1;
  }
  *len = string_len;
  return string;
}

static const value_string buffer_format_vals[] = {
	{ 1, "Data block" },
	{ 2, "Dialect" },
	{ 3, "Pathname" },
	{ 4, "ASCII" },
	{ 5, "Variable block" },
	{ 0, NULL }
};

/*
 * Each dissect routine is passed an offset to wct and works from there 
 */

void
dissect_flush_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint16       FID;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

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
dissect_get_disk_attr_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint16       TotalUnits;
  guint16       Reserved;
  guint16       FreeUnits;
  guint16       ByteCount;
  guint16       BlocksPerUnit;
  guint16       BlockSize;

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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
dissect_set_file_attr_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: File Name */

    FileName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "File Name: %s", FileName);

    }

    offset += string_len; /* Skip File Name */

  } else {
    /* Response(s) dissect code */

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
dissect_write_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint32       Offset;
  guint16       Remaining;
  guint16       FID;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

    if (DataLength > 0 && tree) {

	if(END_OF_FRAME >= DataLength)
	    proto_tree_add_text(tree, NullTVB, offset, DataLength, "Data (%u bytes)", DataLength);
	else
	    proto_tree_add_text(tree, NullTVB, offset, END_OF_FRAME, "Data (first %u bytes)", END_OF_FRAME);

    }

  } else {
    /* Response(s) dissect code */

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
dissect_read_mpx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *arent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count: %u", WordCount);

    }

    offset += 1; /* Skip Word Count */

    if (WordCount != 0) {

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
dissect_delete_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *paernt, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       SearchAttributes;
  guint16       ByteCount;
  const char    *FileName;
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: File Name */

    FileName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "File Name: %s", FileName);

    }

    offset += string_len; /* Skip File Name */

  } else {
    /* Response(s) dissect code */

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
dissect_query_info2_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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
dissect_treecon_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format 1: %s (%u)",
			  val_to_str(BufferFormat1, buffer_format_vals, "Unknown"),
			  BufferFormat1);

    }

    offset += 1; /* Skip BufferFormat1 */

    /* Build display for: Share Path */

    SharePath = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "Share Path: %s", SharePath);

    }

    offset += string_len; /* Skip Share Path */

    /* Build display for: BufferFormat2 */

    BufferFormat2 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format 2: %s (%u)",
			  val_to_str(BufferFormat2, buffer_format_vals, "Unknown"),
			  BufferFormat2);

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format 3: %s (%u)",
			  val_to_str(BufferFormat3, buffer_format_vals, "Unknown"),
			  BufferFormat3);

    }

    offset += 1; /* Skip BufferFormat3 */

    /* Build display for: Service */

    Service = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(Service) + 1, "Service: %s", Service);

    }

    offset += strlen(Service) + 1; /* Skip Service */

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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

    }

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
dissect_ssetup_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  proto_tree    *Capabilities_tree;
  proto_tree    *Action_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        AndXReserved;
  guint8        AndXCommand = 0xFF;
  guint32       SessionKey;
  guint32       Reserved;
  guint32       Capabilities;
  guint16       VcNumber;
  guint16       SecurityBlobLength;
  guint16       ANSIAccountPasswordLength;
  guint16       UNICODEAccountPasswordLength;
  guint16       PasswordLen;
  guint16       MaxMpxCount;
  guint16       MaxBufferSize;
  guint16       ByteCount;
  guint16       AndXOffset = 0;
  guint16       Action;
  const char    *ANSIPassword;
  const char    *UNICODEPassword;
  const char    *SecurityBlob;
  const char    *Password;
  const char    *PrimaryDomain;
  const char    *NativeOS;
  const char    *NativeLanManType;
  const char    *NativeLanMan;
  const char    *AccountName;
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    switch (WordCount) {

    case 10:

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

 	/* Build display for: Password */

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

    case 12:

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

      /* Build display for: Security Blob Length */

      SecurityBlobLength = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Security Blob Length: %u", SecurityBlobLength);

      }

      offset += 2; /* Skip Security Blob Length */

      /* Build display for: Reserved */

      Reserved = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved: %u", Reserved);

      }

      offset += 4; /* Skip Reserved */

      /* Build display for: Capabilities */

      Capabilities = GWORD(pd, offset);

      if (tree) {

        ti = proto_tree_add_text(tree, NullTVB, offset, 4, "Capabilities: 0x%08x", Capabilities);
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

        /* Build display for: Security Blob */

        SecurityBlob = pd + offset;

        if (SecurityBlobLength > 0) {

          /* XXX - is this ASN.1-encoded?  Is it a Kerberos data structure,
             at least in NT 5.0-and-later server replies? */

          if (tree) {

            proto_tree_add_text(tree, NullTVB, offset, SecurityBlobLength, "Security Blob: %s",
                                bytes_to_str(SecurityBlob, SecurityBlobLength));

          }

          offset += SecurityBlobLength; /* Skip Security Blob */

        }

        /* Build display for: Native OS */

        NativeOS = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

        if (tree) {

          proto_tree_add_text(tree, NullTVB, offset, string_len, "Native OS: %s", NativeOS);

        }

        offset += string_len; /* Skip Native OS */

        /* Build display for: Native LanMan Type */

        NativeLanManType = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

        if (tree) {

          proto_tree_add_text(tree, NullTVB, offset, string_len, "Native LanMan Type: %s", NativeLanManType);

        }

        offset += string_len; /* Skip Native LanMan Type */

        /* Build display for: Primary Domain */

        PrimaryDomain = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

        if (tree) {

          proto_tree_add_text(tree, NullTVB, offset, string_len, "Primary Domain: %s", PrimaryDomain);

        }

        offset += string_len; /* Skip Primary Domain */

      }

      break;

    case 13:

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

        ti = proto_tree_add_text(tree, NullTVB, offset, 4, "Capabilities: 0x%08x", Capabilities);
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

	AccountName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, string_len, "Account Name: %s", AccountName);

	}

	offset += string_len; /* Skip Account Name */

	/* Build display for: Primary Domain */

	/*
	 * XXX - pre-W2K NT systems sometimes appear to stick an extra
	 * byte in front of this, at least if all the strings are
	 * ASCII and the account name is empty.  Another bug?
	 */

	PrimaryDomain = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, string_len, "Primary Domain: %s", PrimaryDomain);

	}

	offset += string_len; /* Skip Primary Domain */

	/* Build display for: Native OS */

	NativeOS = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, string_len, "Native OS: %s", NativeOS);

	}

	offset += string_len; /* Skip Native OS */

	/* Build display for: Native LanMan Type */

	/*
	 * XXX - pre-W2K NT systems appear to stick an extra 2 bytes of
	 * padding/null string/whatever in front of this.  W2K doesn't
	 * appear to.  I suspect that's a bug that got fixed; I also
	 * suspect that, in practice, nobody ever looks at that field
	 * because the bug didn't appear to get fixed until NT 5.0....
	 */

	NativeLanManType = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, string_len, "Native LanMan Type: %s", NativeLanManType);

	}

	offset += string_len; /* Skip Native LanMan Type */

      }

      break;

    default:

      /* XXX - dump the parameter words, one word at a time? */

      offset += WordCount;

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      break;

    }

    if (AndXCommand != 0xFF) {

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset);

    }

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    switch (WordCount) {

    case 3:

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

      /* Build display for: Action */

      Action = GSHORT(pd, offset);

      if (tree) {

        ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Action: %u", Action);
        Action_tree = proto_item_add_subtree(ti, ett_smb_ssetupandxaction);
        proto_tree_add_text(Action_tree, NullTVB, offset, 2, "%s",
                            decode_boolean_bitfield(Action, 0x0001, 16, "Logged in as GUEST", "Not logged in as GUEST"));

      }

      offset += 2; /* Skip Action */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      if (ByteCount > 0) {

        /* Build display for: NativeOS */

        NativeOS = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

        if (tree) {

          proto_tree_add_text(tree, NullTVB, offset, string_len, "NativeOS: %s", NativeOS);

        }

        offset += string_len; /* Skip NativeOS */

        /* Build display for: NativeLanMan */

        NativeLanMan = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

        if (tree) {

          proto_tree_add_text(tree, NullTVB, offset, string_len, "NativeLanMan: %s", NativeLanMan);

        }

        offset += string_len; /* Skip NativeLanMan */

        /* Build display for: PrimaryDomain */

        PrimaryDomain = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

        if (tree) {

          proto_tree_add_text(tree, NullTVB, offset, string_len, "PrimaryDomain: %s", PrimaryDomain);

        }

        offset += string_len; /* Skip PrimaryDomain */

      }

      break;

    case 4:

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

      /* Build display for: Action */

      Action = GSHORT(pd, offset);

      if (tree) {

	ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Action: %u", Action);
	Action_tree = proto_item_add_subtree(ti, ett_smb_ssetupandxaction);
	proto_tree_add_text(Action_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Action, 0x0001, 16, "Logged in as GUEST", "Not logged in as GUEST"));

      }

      offset += 2; /* Skip Action */

      /* Build display for: Security Blob Length */

      SecurityBlobLength = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Security Blob Length: %u", SecurityBlobLength);

      }

      offset += 2; /* Skip Security Blob Length */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      if (ByteCount > 0) {

	SecurityBlob = pd + offset;

	if (SecurityBlobLength > 0) {

	  /* XXX - is this ASN.1-encoded?  Is it a Kerberos data structure,
	     at least in NT 5.0-and-later server replies? */

	  if (tree) {

	    proto_tree_add_text(tree, NullTVB, offset, SecurityBlobLength, "Security Blob: %s",
				bytes_to_str(SecurityBlob, SecurityBlobLength));

	  }

	  offset += SecurityBlobLength; /* Skip Security Blob */

	}

	/* Build display for: NativeOS */

	NativeOS = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, string_len, "NativeOS: %s", NativeOS);

	}

	offset += string_len; /* Skip NativeOS */

	/* Build display for: NativeLanMan */

	NativeLanMan = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, string_len, "NativeLanMan: %s", NativeLanMan);

	}

	offset += string_len; /* Skip NativeLanMan */

      }

      break;

    default:

      /* XXX - dump the parameter words, one word at a time? */

      offset += WordCount;

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      break;

    }

    if (AndXCommand != 0xFF) {

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset);

    }

  }

}

void
dissect_tcon_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8      wct, andxcmd = 0xFF;
  guint16     andxoffs = 0, flags, passwdlen, bcc, optionsup;
  const char  *str;
  int         string_len;
  proto_tree  *flags_tree;
  proto_tree  *optionsup_tree;
  proto_item  *ti;

  wct = pd[offset];

  /* Now figure out what format we are talking about, 2, 3, or 4 response
   * words ...
   */

  if (!(si.request && (wct == 4)) && !(!si.request && (wct == 2)) &&
      !(!si.request && (wct == 3)) && !(wct == 0)) {

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

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Additional Flags: 0x%04x", flags);
      flags_tree = proto_item_add_subtree(ti, ett_smb_aflags);
      proto_tree_add_text(flags_tree, NullTVB, offset, 2, "%s", 
			  decode_boolean_bitfield(flags, 0x0001, 16,
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

    str = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "Path: %s", str);

    }

    offset += string_len;

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

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Optional Support: 0x%04x", 
			  optionsup);
      optionsup_tree = proto_item_add_subtree(ti, ett_smb_optionsup);
      proto_tree_add_text(optionsup_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(optionsup, 0x0001, 16, "Share supports Search", "Share doesn't support Search"));
      proto_tree_add_text(optionsup_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(optionsup, 0x0002, 16, "Share is in DFS", "Share isn't in DFS"));
      
    }

    offset += 2;

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2;

    /*
     * NOTE: the Service string is always ASCII, even if the "strings are
     * Unicode" bit is set in the flags2 field of the SMB.
     */

    str = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(str) + 1, "Service: %s", str);

    }

    offset += strlen(str) + 1;

    str = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "Native File System: %s", str);

    }

    offset += string_len;

    
    break;

  default:
	; /* nothing */
	break;
  }

  if (andxcmd != 0xFF) /* Process that next command ... ??? */

    (dissect[andxcmd])(pd, SMB_offset + andxoffs, fd, parent, tree, si, max_data - offset, SMB_offset);

}

void 
dissect_negprot_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)
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

  if (!((wct == 0) && si.request) && !((wct == 1) && !si.request) &&
      !((wct == 13) && !si.request) && !((wct == 17) && !si.request)) {
    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Invalid Negotiate Protocol format. WCT should be zero or 1 or 13 or 17 ..., not %u", wct);

      proto_tree_add_text(tree, NullTVB, offset, END_OF_FRAME, "Data");

      return;
    }
  }

  if (tree) {

    proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %d", wct);

  }

  offset += 1; 

  if (!si.request && wct == 0) {

    /* Build display for: Byte Count (BCC) */

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    return;

  }

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
			  (signed short)GSSHORT(pd, offset));

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
			  (signed short)GSSHORT(pd, offset));

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

    if (caps & 0x80000000) {
      /* Extended security */

      /* GUID */

      if (tree) {

	/* XXX - show it in GUID form, with dashes or whatever */
	proto_tree_add_text(tree, NullTVB, offset, 16, "GUID: %s",
				bytes_to_str(&pd[offset], 16));

      }

      offset += 16;

      /* Security blob */
      /* XXX - is this ASN.1-encoded?  Is it a Kerberos data structure,
	 at least in NT 5.0-and-later server replies? */

      if (bcc > 16) {
	bcc -= 16;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, bcc, "Security blob: %s",
				bytes_to_str(&pd[offset], bcc));

	}
      }
    } else {
      /* Non-extended security */

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
    }

    break;

  default:    /* Baddd */

    if (tree)
      proto_tree_add_text(tree, NullTVB, offset, 1, "Bad format, should never get here");
    return;

  }

}

void
dissect_deletedir_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       ByteCount;
  const char    *DirectoryName;
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Directory Name */

    DirectoryName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "Directory Name: %s", DirectoryName);

    }

    offset += string_len; /* Skip Directory Name */

  } else {
    /* Response(s) dissect code */

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
dissect_createdir_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       ByteCount;
  const char    *DirectoryName;
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Directory Name */

    DirectoryName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "Directory Name: %s", DirectoryName);

    }

    offset += string_len; /* Skip Directory Name */

  } else {
    /* Response(s) dissect code */

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
dissect_checkdir_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       ByteCount;
  const char    *DirectoryName;
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Directory Name */

    DirectoryName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "Directory Name: %s", DirectoryName);

    }

    offset += string_len; /* Skip Directory Name */

  } else {
    /* Response(s) dissect code */

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
dissect_open_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

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

    FileName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "File Name: %s", FileName);

    }

    offset += string_len; /* Skip File Name */


    if (AndXCommand != 0xFF) {

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset);

    }

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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
	Action_tree = proto_item_add_subtree(ti, ett_smb_openaction);
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

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset);

    }

  }

}

void
dissect_write_raw_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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
dissect_tdis_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

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
dissect_move_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Error File Format: %s (%u)",
			  val_to_str(ErrorFileFormat, buffer_format_vals, "Unknown"),
			  ErrorFileFormat);

    }

    offset += 1; /* Skip Error File Format */

    /* Build display for: Error File Name */

    ErrorFileName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "Error File Name: %s", ErrorFileName);

    }

    offset += string_len; /* Skip Error File Name */

  }

}

void
dissect_rename_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        BufferFormat2;
  guint8        BufferFormat1;
  guint16       SearchAttributes;
  guint16       ByteCount;
  const char    *OldFileName;
  const char    *NewFileName;
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format 1: %s (%u)",
			  val_to_str(BufferFormat1, buffer_format_vals, "Unknown"),
			  BufferFormat1);

    }

    offset += 1; /* Skip Buffer Format 1 */

    /* Build display for: Old File Name */

    OldFileName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "Old File Name: %s", OldFileName);

    }

    offset += string_len; /* Skip Old File Name */

    /* Build display for: Buffer Format 2 */

    BufferFormat2 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format 2: %s (%u)",
			  val_to_str(BufferFormat2, buffer_format_vals, "Unknown"),
			  BufferFormat2);

    }

    offset += 1; /* Skip Buffer Format 2 */

    /* Build display for: New File Name */

    NewFileName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "New File Name: %s", NewFileName);

    }

    offset += string_len; /* Skip New File Name */

  } else {
    /* Response(s) dissect code */

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
dissect_open_print_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Identifier String */

    IdentifierString = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "Identifier String: %s", IdentifierString);

    }

    offset += string_len; /* Skip Identifier String */

  } else {
    /* Response(s) dissect code */

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
dissect_close_print_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint16       FID;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

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
dissect_read_raw_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

  }

}

void
dissect_read_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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

  if (si.request) {
    /* Request(s) dissect code */

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

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset);

    }

  } else {
    /* Response(s) dissect code */

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

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset);

    }

  }

}

void
dissect_logoff_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        AndXReserved;
  guint8        AndXCommand = 0xFF;
  guint16       ByteCount;
  guint16       AndXOffset = 0;

  if (si.request) {
    /* Request(s) dissect code */

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

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset);

    }

  } else {
    /* Response(s) dissect code */

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

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset);

    }

  }

}

void
dissect_seek_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

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
dissect_write_and_unlock_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint32       Offset;
  guint16       Remaining;
  guint16       FID;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

  } else {
    /* Response(s) dissect code */

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
dissect_set_info2_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

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
dissect_lock_bytes_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint32       Offset;
  guint32       Count;
  guint16       FID;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

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
dissect_get_print_queue_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       StartIndex;
  guint16       RestartIndex;
  guint16       MaxCount;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

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
dissect_locking_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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

  if (si.request) {
    /* Request(s) dissect code */

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

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset);

    }

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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

      (dissect[AndXCommand])(pd, SMB_offset + AndXOffset, fd, parent, tree, si, max_data, SMB_offset);

    }

  }

}

void
dissect_unlock_bytes_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint32       Offset;
  guint32       Count;
  guint16       FID;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

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
dissect_create_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: File Name */

    FileName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "File Name: %s", FileName);

    }

    offset += string_len; /* Skip File Name */

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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
dissect_search_dir_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format 1: %s (%u)",
			  val_to_str(BufferFormat1, buffer_format_vals, "Unknown"),
			  BufferFormat1);

    }

    offset += 1; /* Skip Buffer Format 1 */

    /* Build display for: File Name */

    FileName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "File Name: %s", FileName);

    }

    offset += string_len; /* Skip File Name */

    /* Build display for: Buffer Format 2 */

    BufferFormat2 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format 2: %s (%u)",
			  val_to_str(BufferFormat2, buffer_format_vals, "Unknown"),
			  BufferFormat2);

    }

    offset += 1; /* Skip Buffer Format 2 */

    /* Build display for: Resume Key Length */

    ResumeKeyLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Resume Key Length: %u", ResumeKeyLength);

    }

    offset += 2; /* Skip Resume Key Length */

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

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
dissect_create_temporary_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Directory Name */

    DirectoryName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "Directory Name: %s", DirectoryName);

    }

    offset += string_len; /* Skip Directory Name */

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: File Name */

    FileName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "File Name: %s", FileName);

    }

    offset += string_len; /* Skip File Name */

  }

}

void
dissect_close_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint16       LastWriteTime;
  guint16       LastWriteDate;
  guint16       FID;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

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
dissect_write_print_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       FID;
  guint16       DataLength;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

  } else {
    /* Response(s) dissect code */

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
dissect_lock_and_read_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

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
dissect_process_exit_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

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
dissect_get_file_attr_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

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

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: File Name */

    FileName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "File Name: %s", FileName);

    }

    offset += string_len; /* Skip File Name */

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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
dissect_read_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

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

      proto_tree_add_text(tree, NullTVB, offset, 2, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

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
dissect_write_mpx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

      /* Build display for: Response Mask */

      ResponseMask = GWORD(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 4, "Response Mask: %u", ResponseMask);

      }

      offset += 4; /* Skip Response Mask */

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
dissect_find_close2_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        ByteCount;
  guint16       FID;

  if (si.request) {
    /* Request(s) dissect code */

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

  } else {
    /* Response(s) dissect code */

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

static const value_string trans2_cmd_vals[] = {
  { 0x00, "TRANS2_OPEN" },
  { 0x01, "TRANS2_FIND_FIRST2" },
  { 0x02, "TRANS2_FIND_NEXT2" },
  { 0x03, "TRANS2_QUERY_FS_INFORMATION" },
  { 0x05, "TRANS2_QUERY_PATH_INFORMATION" },
  { 0x06, "TRANS2_SET_PATH_INFORMATION" },
  { 0x07, "TRANS2_QUERY_FILE_INFORMATION" },
  { 0x08, "TRANS2_SET_FILE_INFORMATION" },
  { 0x09, "TRANS2_FSCTL" },
  { 0x0A, "TRANS2_IOCTL2" },
  { 0x0B, "TRANS2_FIND_NOTIFY_FIRST" },
  { 0x0C, "TRANS2_FIND_NOTIFY_NEXT" },
  { 0x0D, "TRANS2_CREATE_DIRECTORY" },
  { 0x0E, "TRANS2_SESSION_SETUP" },
  { 0x10, "TRANS2_GET_DFS_REFERRAL" },
  { 0x11, "TRANS2_REPORT_DFS_INCONSISTENCY" },
  { 0,    NULL }
};

void
dissect_transact2_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

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
  guint16       Setup;
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
  struct smb_request_val *request_val;
  struct smb_continuation_val *continuation_val;

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
				pi.srcport, pi.destport, 0);
  }

  si.conversation = conversation;  /* Save this for later */

  request_val = do_transaction_hashing(conversation, si, fd);

  si.request_val = request_val;  /* Save this for later */

  if (si.request) {
    /* Request(s) dissect code */
  
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

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    ParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Count: %u", ParameterCount);

    }

    offset += 2; /* Skip Parameter Count */

    /* Build display for: Parameter Offset */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    ParameterOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Offset: %u", ParameterOffset);

    }

    offset += 2; /* Skip Parameter Offset */

    /* Build display for: Data Count */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    DataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Count: %u", DataCount);

    }

    offset += 2; /* Skip Data Count */

    /* Build display for: Data Offset */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    DataOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

    }

    offset += 2; /* Skip Data Offset */

    /* Build display for: Setup Count */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

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

    if (SetupCount != 0) {

      int i;

      if (!BYTES_ARE_IN_FRAME(offset, 2))
	return;

      /*
       * First Setup word is transaction code.
       */
      Setup = GSHORT(pd, offset);

      if (!fd->flags.visited) {
	/*
	 * This is the first time this frame has been seen; remember
	 * the transaction code.
	 */
	g_assert(request_val -> last_transact2_command == -1);
        request_val -> last_transact2_command = Setup;  /* Save for later */
      }

      if (check_col(fd, COL_INFO)) {

	col_add_fstr(fd, COL_INFO, "%s Request",
		     val_to_str(Setup, trans2_cmd_vals, "Unknown (0x%02X)"));

      }

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Setup1: %s",
			  val_to_str(Setup, trans2_cmd_vals, "Unknown (0x%02X)"));

      }

      offset += 2; /* Skip Setup word */

      for (i = 2; i <= SetupCount; i++) {

	if (!BYTES_ARE_IN_FRAME(offset, 2))
	  return;

	Setup = GSHORT(pd, offset);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, 2, "Setup%i: %u", i, Setup);

	}

	offset += 2; /* Skip Setup word */

      }

    }

    /* Build display for: Byte Count (BCC) */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    if (offset < (SMB_offset + ParameterOffset)) {

      int pad1Count = SMB_offset + ParameterOffset - offset;

      /* Build display for: Pad1 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad1Count, "Pad1: %s",
			    bytes_to_str(pd + offset, pad1Count));
      }

      offset += pad1Count; /* Skip Pad1 */

    }

    if (ParameterCount > 0) {

      /* Build display for: Parameters */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, SMB_offset + ParameterOffset,
			    ParameterCount, "Parameters: %s",
			    bytes_to_str(pd + SMB_offset + ParameterOffset,
					 ParameterCount));

      }

      offset += ParameterCount; /* Skip Parameters */

    }

    if (DataCount > 0 && offset < (SMB_offset + DataOffset)) {

      int pad2Count = SMB_offset + DataOffset - offset;
	
      /* Build display for: Pad2 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad2Count, "Pad2: %s",
			    bytes_to_str(pd + offset, pad2Count));

      }

      offset += pad2Count; /* Skip Pad2 */

    }

    if (DataCount > 0) {

      /* Build display for: Data */

      Data = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, SMB_offset + DataOffset,
			    DataCount, "Data: %s",
			    bytes_to_str(pd + offset, DataCount));

      }

      offset += DataCount; /* Skip Data */

    }
  } else {
    /* Response(s) dissect code */

    /* Pick up the last transact2 command and put it in the right places */

    if (check_col(fd, COL_INFO)) {

      if (request_val == NULL)
	col_set_str(fd, COL_INFO, "Response to unknown SMBtrans2");
      else if (request_val -> last_transact2_command == -1)
	col_set_str(fd, COL_INFO, "Response to SMBtrans2 of unknown type");
      else
	col_add_fstr(fd, COL_INFO, "%s Response",
		     val_to_str(request_val -> last_transact2_command,
				trans2_cmd_vals, "Unknown (0x%02X)"));

    }

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount == 0) {

      /* Interim response. */

      if (check_col(fd, COL_INFO)) {

	if (request_val == NULL)
	  col_set_str(fd, COL_INFO, "Interim response to unknown SMBtrans2");
	else if (request_val -> last_transact2_command == -1)
	  col_set_str(fd, COL_INFO, "Interim response to SMBtrans2 of unknown type");
	else
	  col_add_fstr(fd, COL_INFO, "%s interim response",
		       val_to_str(request_val -> last_transact2_command,
				  trans2_cmd_vals, "Unknown (0x%02X)"));

      }

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

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

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    DataDisplacement = GSHORT(pd, offset);
    si.ddisp = DataDisplacement;

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

    if (SetupCount != 0) {

      int i;

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

	proto_tree_add_text(tree, NullTVB, offset, pad1Count, "Pad1: %s",
			    bytes_to_str(pd + offset, pad1Count));
      }

      offset += pad1Count; /* Skip Pad1 */

    }

    /* Build display for: Parameters */

    if (ParameterCount > 0) {

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, ParameterCount,
			    "Parameters: %s",
			    bytes_to_str(pd + offset, ParameterCount));

      }

      offset += ParameterCount; /* Skip Parameters */

    }

    if (DataCount > 0 && offset < (SMB_offset + DataOffset)) {

      int pad2Count = SMB_offset + DataOffset - offset;
	
      /* Build display for: Pad2 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad2Count, "Pad2: %s",
			    bytes_to_str(pd + offset, pad2Count));

      }

      offset += pad2Count; /* Skip Pad2 */

    }

    /* Build display for: Data */

    if (DataCount > 0) {

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, DataCount,
			    "Data: %s",
			    bytes_to_str(pd + offset, DataCount));

      }

      offset += DataCount; /* Skip Data */

    }

  }

}


static void 
dissect_transact_params(const u_char *pd, int offset, frame_data *fd,
    proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data,
    int SMB_offset, int DataOffset, int DataCount,
    int ParameterOffset, int ParameterCount, int SetupAreaOffset,
    int SetupCount, const char *TransactName)
{
  char             *TransactNameCopy;
  char             *trans_type = NULL, *trans_cmd, *loc_of_slash = NULL;
  int              index;
  const gchar      *Data;
  packet_info      *pinfo;
  tvbuff_t         *next_tvb;
  tvbuff_t         *setup_tvb;

  if (TransactName != NULL) {
    /* Should check for error here ... */

    TransactNameCopy = g_strdup(TransactName);

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
  } else
    trans_cmd = NULL;

  pinfo = &pi;

  /*
   * Number of bytes of parameter.
   */
  si.parameter_count = ParameterCount;

  if (DataOffset < 0) {
    /*
     * This is an interim response, so there're no parameters or data
     * to dissect.
     */
    si.is_interim_response = TRUE;

    /*
     * Create a zero-length tvbuff.
     */
    next_tvb = tvb_create_from_top(pi.captured_len);
  } else {
    /*
     * This isn't an interim response.
     */
    si.is_interim_response = FALSE;

    /*
     * Create a tvbuff for the parameters and data.
     */
    next_tvb = tvb_create_from_top(SMB_offset + ParameterOffset);
  }

  /*
   * Offset of beginning of data from beginning of next_tvb.
   */
  si.data_offset = DataOffset - ParameterOffset;

  /*
   * Number of bytes of data.
   */
  si.data_count = DataCount;

  /*
   * Command.
   */
  si.trans_cmd = trans_cmd;

  /*
   * Pass "si" to the subdissector.
   */
  pinfo->private_data = &si;

  /*
   * Tvbuff for setup area, for mailslot call.
   */
  /*
   * Is there a setup area?
   */
  if (SetupAreaOffset < 0) {
    /*
     * No - create a zero-length tvbuff.
     */
    setup_tvb = tvb_create_from_top(pi.captured_len);
  } else {
    /*
     * Create a tvbuff for the setup area.
     */
    setup_tvb = tvb_create_from_top(SetupAreaOffset);
  }

  if ((trans_cmd == NULL) ||
      (((trans_type == NULL || strcmp(trans_type, "MAILSLOT") != 0) ||
       !dissect_mailslot_smb(setup_tvb, next_tvb, pinfo, parent)) &&
      ((trans_type == NULL || strcmp(trans_type, "PIPE") != 0) ||
       !dissect_pipe_smb(next_tvb, pinfo, parent)))) {

    if (ParameterCount > 0) {

      /* Build display for: Parameters */
      
      if (tree) {

	proto_tree_add_text(tree, NullTVB, SMB_offset + ParameterOffset,
			    ParameterCount, "Parameters: %s",
			    bytes_to_str(pd + SMB_offset + ParameterOffset,
					 ParameterCount));
	  
      }
	
      offset = SMB_offset + ParameterOffset + ParameterCount; /* Skip Parameters */

    }

    if (DataCount > 0 && offset < (SMB_offset + DataOffset)) {

      int pad2Count = SMB_offset + DataOffset - offset;
	
      /* Build display for: Pad2 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad2Count, "Pad2: %s",
			    bytes_to_str(pd + offset, pad2Count));

      }

      offset += pad2Count; /* Skip Pad2 */

    }

    if (DataCount > 0) {

      /* Build display for: Data */

      Data = pd + SMB_offset + DataOffset;

      if (tree) {

	proto_tree_add_text(tree, NullTVB, SMB_offset + DataOffset, DataCount,
			    "Data: %s",
			    bytes_to_str(pd + SMB_offset + DataOffset, DataCount));

      }

      offset += DataCount; /* Skip Data */

    }
  }

}

void
dissect_transact_smb(const u_char *pd, int offset, frame_data *fd,
		     proto_tree *parent, proto_tree *tree,
		     struct smb_info si, int max_data, int SMB_offset)
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
  struct smb_request_val *request_val;
  guint16	SetupAreaOffset;

  /*
   * Find out what conversation this packet is part of
   */

  conversation = find_conversation(&pi.src, &pi.dst, pi.ptype,
				   pi.srcport, pi.destport, 0);

  if (conversation == NULL) {  /* Create a new conversation */

    conversation = conversation_new(&pi.src, &pi.dst, pi.ptype,
				    pi.srcport, pi.destport, 0);

  }

  si.conversation = conversation;  /* Save this */

  request_val = do_transaction_hashing(conversation, si, fd);

  si.request_val = request_val;  /* Save this for later */

  if (si.request) {
    /* Request(s) dissect code */

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

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

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

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    ParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Count: %u", ParameterCount);

    }

    offset += 2; /* Skip Parameter Count */

    /* Build display for: Parameter Offset */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    ParameterOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Offset: %u", ParameterOffset);

    }

    offset += 2; /* Skip Parameter Offset */

    /* Build display for: Data Count */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    DataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Count: %u", DataCount);

    }

    offset += 2; /* Skip Data Count */

    /* Build display for: Data Offset */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    DataOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

    }

    offset += 2; /* Skip Data Offset */

    /* Build display for: Setup Count */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

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

      if (!BYTES_ARE_IN_FRAME(offset, 2))
	return;

      Setup = GSHORT(pd, offset);

      for (i = 1; i <= SetupCount; i++) {
	
	if (!BYTES_ARE_IN_FRAME(offset, 2))
	  return;

	Setup = GSHORT(pd, offset);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, 2, "Setup%i: %u", i, Setup);

	}

	offset += 2; /* Skip Setup */

      }

    }

    /* Build display for: Byte Count (BCC) */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Transact Name */

    TransactName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &TNlen);

    if (!fd->flags.visited) {
      /*
       * This is the first time this frame has been seen; remember
       * the transaction name.
       */
      g_assert(request_val -> last_transact_command == NULL);
      request_val -> last_transact_command = g_strdup(TransactName);
    }

    if (check_col(fd, COL_INFO)) {

      col_add_fstr(fd, COL_INFO, "%s Request", TransactName);

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

	proto_tree_add_text(tree, NullTVB, offset, pad1Count, "Pad1: %s",
			    bytes_to_str(pd + offset, pad1Count));
      }

      offset += pad1Count; /* Skip Pad1 */

    }

    /* Let's see if we can decode this */

    dissect_transact_params(pd, offset, fd, parent, tree, si, max_data,
			    SMB_offset, DataOffset, DataCount,
			    ParameterOffset, ParameterCount,
			    SetupAreaOffset, SetupCount, TransactName);

  } else {
    /* Response(s) dissect code */

    if (check_col(fd, COL_INFO)) {
      if ( request_val == NULL )
	col_set_str(fd, COL_INFO, "Response to unknown SMBtrans");
      else if (request_val -> last_transact_command == NULL)
	col_set_str(fd, COL_INFO, "Response to SMBtrans of unknown type");
      else
	col_add_fstr(fd, COL_INFO, "%s Response",
		     request_val -> last_transact_command);

    }

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount == 0) {

      /* Interim response. */

      if (check_col(fd, COL_INFO)) {
	if ( request_val == NULL )
	  col_set_str(fd, COL_INFO, "Interim response to unknown SMBtrans");
	else if (request_val -> last_transact_command == NULL)
	  col_set_str(fd, COL_INFO, "Interim response to SMBtrans of unknown type");
	else
	  col_add_fstr(fd, COL_INFO, "%s interim response",
		       request_val -> last_transact_command);

      }

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      /* Dissect the interim response by showing the type of request to
         which it's a reply, if we have that information. */
      if (request_val != NULL) {
	dissect_transact_params(pd, offset, fd, parent, tree, si, max_data,
				SMB_offset, -1, -1, -1, -1, -1, -1,
	  			request_val -> last_transact_command);
      }

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

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    DataDisplacement = GSHORT(pd, offset);
    si.ddisp = DataDisplacement;

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

	proto_tree_add_text(tree, NullTVB, offset, pad1Count, "Pad1: %s",
			    bytes_to_str(pd + offset, pad1Count));
      }

      offset += pad1Count; /* Skip Pad1 */

    }

    if (request_val != NULL)
      TransactName = request_val -> last_transact_command;
    else
      TransactName = NULL;

    /*
     * Make an entry for this, if it's continued; get the entry for
     * the message of which it's a continuation, and get the transaction
     * name for that message, if it's a continuation.
     *
     * XXX - eventually, do reassembly of all the continuations, so
     * we can dissect the entire reply.
     */
    si.continuation_val = do_continuation_hashing(conversation, si, fd,
					          TotalDataCount, DataCount,
					          &TransactName);
    dissect_transact_params(pd, offset, fd, parent, tree, si, max_data,
			    SMB_offset, DataOffset, DataCount,
			    ParameterOffset, ParameterCount,
			    SetupAreaOffset, SetupCount, TransactName);

  }

}





static void (*dissect[256])(const u_char *, int, frame_data *, proto_tree *, proto_tree *, struct smb_info, int, int) = {

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

/*
 * NT error codes.
 *
 * From
 *
 *	http://www.wildpackets.com/elements/SMB_NT_Status_Codes.txt
 */
static const value_string NT_errors[] = {
  { 0x00000000, "STATUS_SUCCESS" },
  { 0x00000000, "STATUS_WAIT_0" },
  { 0x00000001, "STATUS_WAIT_1" },
  { 0x00000002, "STATUS_WAIT_2" },
  { 0x00000003, "STATUS_WAIT_3" },
  { 0x0000003F, "STATUS_WAIT_63" },
  { 0x00000080, "STATUS_ABANDONED" },
  { 0x00000080, "STATUS_ABANDONED_WAIT_0" },
  { 0x000000BF, "STATUS_ABANDONED_WAIT_63" },
  { 0x000000C0, "STATUS_USER_APC" },
  { 0x00000100, "STATUS_KERNEL_APC" },
  { 0x00000101, "STATUS_ALERTED" },
  { 0x00000102, "STATUS_TIMEOUT" },
  { 0x00000103, "STATUS_PENDING" },
  { 0x00000104, "STATUS_REPARSE" },
  { 0x00000105, "STATUS_MORE_ENTRIES" },
  { 0x00000106, "STATUS_NOT_ALL_ASSIGNED" },
  { 0x00000107, "STATUS_SOME_NOT_MAPPED" },
  { 0x00000108, "STATUS_OPLOCK_BREAK_IN_PROGRESS" },
  { 0x00000109, "STATUS_VOLUME_MOUNTED" },
  { 0x0000010A, "STATUS_RXACT_COMMITTED" },
  { 0x0000010B, "STATUS_NOTIFY_CLEANUP" },
  { 0x0000010C, "STATUS_NOTIFY_ENUM_DIR" },
  { 0x0000010D, "STATUS_NO_QUOTAS_FOR_ACCOUNT" },
  { 0x0000010E, "STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED" },
  { 0x00000110, "STATUS_PAGE_FAULT_TRANSITION" },
  { 0x00000111, "STATUS_PAGE_FAULT_DEMAND_ZERO" },
  { 0x00000112, "STATUS_PAGE_FAULT_COPY_ON_WRITE" },
  { 0x00000113, "STATUS_PAGE_FAULT_GUARD_PAGE" },
  { 0x00000114, "STATUS_PAGE_FAULT_PAGING_FILE" },
  { 0x00000115, "STATUS_CACHE_PAGE_LOCKED" },
  { 0x00000116, "STATUS_CRASH_DUMP" },
  { 0x00000117, "STATUS_BUFFER_ALL_ZEROS" },
  { 0x00000118, "STATUS_REPARSE_OBJECT" },
  { 0x40000000, "STATUS_OBJECT_NAME_EXISTS" },
  { 0x40000001, "STATUS_THREAD_WAS_SUSPENDED" },
  { 0x40000002, "STATUS_WORKING_SET_LIMIT_RANGE" },
  { 0x40000003, "STATUS_IMAGE_NOT_AT_BASE" },
  { 0x40000004, "STATUS_RXACT_STATE_CREATED" },
  { 0x40000005, "STATUS_SEGMENT_NOTIFICATION" },
  { 0x40000006, "STATUS_LOCAL_USER_SESSION_KEY" },
  { 0x40000007, "STATUS_BAD_CURRENT_DIRECTORY" },
  { 0x40000008, "STATUS_SERIAL_MORE_WRITES" },
  { 0x40000009, "STATUS_REGISTRY_RECOVERED" },
  { 0x4000000A, "STATUS_FT_READ_RECOVERY_FROM_BACKUP" },
  { 0x4000000B, "STATUS_FT_WRITE_RECOVERY" },
  { 0x4000000C, "STATUS_SERIAL_COUNTER_TIMEOUT" },
  { 0x4000000D, "STATUS_NULL_LM_PASSWORD" },
  { 0x4000000E, "STATUS_IMAGE_MACHINE_TYPE_MISMATCH" },
  { 0x4000000F, "STATUS_RECEIVE_PARTIAL" },
  { 0x40000010, "STATUS_RECEIVE_EXPEDITED" },
  { 0x40000011, "STATUS_RECEIVE_PARTIAL_EXPEDITED" },
  { 0x40000012, "STATUS_EVENT_DONE" },
  { 0x40000013, "STATUS_EVENT_PENDING" },
  { 0x40000014, "STATUS_CHECKING_FILE_SYSTEM" },
  { 0x40000015, "STATUS_FATAL_APP_EXIT" },
  { 0x40000016, "STATUS_PREDEFINED_HANDLE" },
  { 0x40000017, "STATUS_WAS_UNLOCKED" },
  { 0x40000018, "STATUS_SERVICE_NOTIFICATION" },
  { 0x40000019, "STATUS_WAS_LOCKED" },
  { 0x4000001A, "STATUS_LOG_HARD_ERROR" },
  { 0x4000001B, "STATUS_ALREADY_WIN32" },
  { 0x4000001C, "STATUS_WX86_UNSIMULATE" },
  { 0x4000001D, "STATUS_WX86_CONTINUE" },
  { 0x4000001E, "STATUS_WX86_SINGLE_STEP" },
  { 0x4000001F, "STATUS_WX86_BREAKPOINT" },
  { 0x40000020, "STATUS_WX86_EXCEPTION_CONTINUE" },
  { 0x40000021, "STATUS_WX86_EXCEPTION_LASTCHANCE" },
  { 0x40000022, "STATUS_WX86_EXCEPTION_CHAIN" },
  { 0x40000023, "STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE" },
  { 0x40000024, "STATUS_NO_YIELD_PERFORMED" },
  { 0x40000025, "STATUS_TIMER_RESUME_IGNORED" },
  { 0x80000001, "STATUS_GUARD_PAGE_VIOLATION" },
  { 0x80000002, "STATUS_DATATYPE_MISALIGNMENT" },
  { 0x80000003, "STATUS_BREAKPOINT" },
  { 0x80000004, "STATUS_SINGLE_STEP" },
  { 0x80000005, "STATUS_BUFFER_OVERFLOW" },
  { 0x80000006, "STATUS_NO_MORE_FILES" },
  { 0x80000007, "STATUS_WAKE_SYSTEM_DEBUGGER" },
  { 0x8000000A, "STATUS_HANDLES_CLOSED" },
  { 0x8000000B, "STATUS_NO_INHERITANCE" },
  { 0x8000000C, "STATUS_GUID_SUBSTITUTION_MADE" },
  { 0x8000000D, "STATUS_PARTIAL_COPY" },
  { 0x8000000E, "STATUS_DEVICE_PAPER_EMPTY" },
  { 0x8000000F, "STATUS_DEVICE_POWERED_OFF" },
  { 0x80000010, "STATUS_DEVICE_OFF_LINE" },
  { 0x80000011, "STATUS_DEVICE_BUSY" },
  { 0x80000012, "STATUS_NO_MORE_EAS" },
  { 0x80000013, "STATUS_INVALID_EA_NAME" },
  { 0x80000014, "STATUS_EA_LIST_INCONSISTENT" },
  { 0x80000015, "STATUS_INVALID_EA_FLAG" },
  { 0x80000016, "STATUS_VERIFY_REQUIRED" },
  { 0x80000017, "STATUS_EXTRANEOUS_INFORMATION" },
  { 0x80000018, "STATUS_RXACT_COMMIT_NECESSARY" },
  { 0x8000001A, "STATUS_NO_MORE_ENTRIES" },
  { 0x8000001B, "STATUS_FILEMARK_DETECTED" },
  { 0x8000001C, "STATUS_MEDIA_CHANGED" },
  { 0x8000001D, "STATUS_BUS_RESET" },
  { 0x8000001E, "STATUS_END_OF_MEDIA" },
  { 0x8000001F, "STATUS_BEGINNING_OF_MEDIA" },
  { 0x80000020, "STATUS_MEDIA_CHECK" },
  { 0x80000021, "STATUS_SETMARK_DETECTED" },
  { 0x80000022, "STATUS_NO_DATA_DETECTED" },
  { 0x80000023, "STATUS_REDIRECTOR_HAS_OPEN_HANDLES" },
  { 0x80000024, "STATUS_SERVER_HAS_OPEN_HANDLES" },
  { 0x80000025, "STATUS_ALREADY_DISCONNECTED" },
  { 0x80000026, "STATUS_LONGJUMP" },
  { 0xC0000001, "STATUS_UNSUCCESSFUL" },
  { 0xC0000002, "STATUS_NOT_IMPLEMENTED" },
  { 0xC0000003, "STATUS_INVALID_INFO_CLASS" },
  { 0xC0000004, "STATUS_INFO_LENGTH_MISMATCH" },
  { 0xC0000005, "STATUS_ACCESS_VIOLATION" },
  { 0xC0000006, "STATUS_IN_PAGE_ERROR" },
  { 0xC0000007, "STATUS_PAGEFILE_QUOTA" },
  { 0xC0000008, "STATUS_INVALID_HANDLE" },
  { 0xC0000009, "STATUS_BAD_INITIAL_STACK" },
  { 0xC000000A, "STATUS_BAD_INITIAL_PC" },
  { 0xC000000B, "STATUS_INVALID_CID" },
  { 0xC000000C, "STATUS_TIMER_NOT_CANCELED" },
  { 0xC000000D, "STATUS_INVALID_PARAMETER" },
  { 0xC000000E, "STATUS_NO_SUCH_DEVICE" },
  { 0xC000000F, "STATUS_NO_SUCH_FILE" },
  { 0xC0000010, "STATUS_INVALID_DEVICE_REQUEST" },
  { 0xC0000011, "STATUS_END_OF_FILE" },
  { 0xC0000012, "STATUS_WRONG_VOLUME" },
  { 0xC0000013, "STATUS_NO_MEDIA_IN_DEVICE" },
  { 0xC0000014, "STATUS_UNRECOGNIZED_MEDIA" },
  { 0xC0000015, "STATUS_NONEXISTENT_SECTOR" },
  { 0xC0000016, "STATUS_MORE_PROCESSING_REQUIRED" },
  { 0xC0000017, "STATUS_NO_MEMORY" },
  { 0xC0000018, "STATUS_CONFLICTING_ADDRESSES" },
  { 0xC0000019, "STATUS_NOT_MAPPED_VIEW" },
  { 0xC000001A, "STATUS_UNABLE_TO_FREE_VM" },
  { 0xC000001B, "STATUS_UNABLE_TO_DELETE_SECTION" },
  { 0xC000001C, "STATUS_INVALID_SYSTEM_SERVICE" },
  { 0xC000001D, "STATUS_ILLEGAL_INSTRUCTION" },
  { 0xC000001E, "STATUS_INVALID_LOCK_SEQUENCE" },
  { 0xC000001F, "STATUS_INVALID_VIEW_SIZE" },
  { 0xC0000020, "STATUS_INVALID_FILE_FOR_SECTION" },
  { 0xC0000021, "STATUS_ALREADY_COMMITTED" },
  { 0xC0000022, "STATUS_ACCESS_DENIED" },
  { 0xC0000023, "STATUS_BUFFER_TOO_SMALL" },
  { 0xC0000024, "STATUS_OBJECT_TYPE_MISMATCH" },
  { 0xC0000025, "STATUS_NONCONTINUABLE_EXCEPTION" },
  { 0xC0000026, "STATUS_INVALID_DISPOSITION" },
  { 0xC0000027, "STATUS_UNWIND" },
  { 0xC0000028, "STATUS_BAD_STACK" },
  { 0xC0000029, "STATUS_INVALID_UNWIND_TARGET" },
  { 0xC000002A, "STATUS_NOT_LOCKED" },
  { 0xC000002B, "STATUS_PARITY_ERROR" },
  { 0xC000002C, "STATUS_UNABLE_TO_DECOMMIT_VM" },
  { 0xC000002D, "STATUS_NOT_COMMITTED" },
  { 0xC000002E, "STATUS_INVALID_PORT_ATTRIBUTES" },
  { 0xC000002F, "STATUS_PORT_MESSAGE_TOO_LONG" },
  { 0xC0000030, "STATUS_INVALID_PARAMETER_MIX" },
  { 0xC0000031, "STATUS_INVALID_QUOTA_LOWER" },
  { 0xC0000032, "STATUS_DISK_CORRUPT_ERROR" },
  { 0xC0000033, "STATUS_OBJECT_NAME_INVALID" },
  { 0xC0000034, "STATUS_OBJECT_NAME_NOT_FOUND" },
  { 0xC0000035, "STATUS_OBJECT_NAME_COLLISION" },
  { 0xC0000037, "STATUS_PORT_DISCONNECTED" },
  { 0xC0000038, "STATUS_DEVICE_ALREADY_ATTACHED" },
  { 0xC0000039, "STATUS_OBJECT_PATH_INVALID" },
  { 0xC000003A, "STATUS_OBJECT_PATH_NOT_FOUND" },
  { 0xC000003B, "STATUS_OBJECT_PATH_SYNTAX_BAD" },
  { 0xC000003C, "STATUS_DATA_OVERRUN" },
  { 0xC000003D, "STATUS_DATA_LATE_ERROR" },
  { 0xC000003E, "STATUS_DATA_ERROR" },
  { 0xC000003F, "STATUS_CRC_ERROR" },
  { 0xC0000040, "STATUS_SECTION_TOO_BIG" },
  { 0xC0000041, "STATUS_PORT_CONNECTION_REFUSED" },
  { 0xC0000042, "STATUS_INVALID_PORT_HANDLE" },
  { 0xC0000043, "STATUS_SHARING_VIOLATION" },
  { 0xC0000044, "STATUS_QUOTA_EXCEEDED" },
  { 0xC0000045, "STATUS_INVALID_PAGE_PROTECTION" },
  { 0xC0000046, "STATUS_MUTANT_NOT_OWNED" },
  { 0xC0000047, "STATUS_SEMAPHORE_LIMIT_EXCEEDED" },
  { 0xC0000048, "STATUS_PORT_ALREADY_SET" },
  { 0xC0000049, "STATUS_SECTION_NOT_IMAGE" },
  { 0xC000004A, "STATUS_SUSPEND_COUNT_EXCEEDED" },
  { 0xC000004B, "STATUS_THREAD_IS_TERMINATING" },
  { 0xC000004C, "STATUS_BAD_WORKING_SET_LIMIT" },
  { 0xC000004D, "STATUS_INCOMPATIBLE_FILE_MAP" },
  { 0xC000004E, "STATUS_SECTION_PROTECTION" },
  { 0xC000004F, "STATUS_EAS_NOT_SUPPORTED" },
  { 0xC0000050, "STATUS_EA_TOO_LARGE" },
  { 0xC0000051, "STATUS_NONEXISTENT_EA_ENTRY" },
  { 0xC0000052, "STATUS_NO_EAS_ON_FILE" },
  { 0xC0000053, "STATUS_EA_CORRUPT_ERROR" },
  { 0xC0000054, "STATUS_FILE_LOCK_CONFLICT" },
  { 0xC0000055, "STATUS_LOCK_NOT_GRANTED" },
  { 0xC0000056, "STATUS_DELETE_PENDING" },
  { 0xC0000057, "STATUS_CTL_FILE_NOT_SUPPORTED" },
  { 0xC0000058, "STATUS_UNKNOWN_REVISION" },
  { 0xC0000059, "STATUS_REVISION_MISMATCH" },
  { 0xC000005A, "STATUS_INVALID_OWNER" },
  { 0xC000005B, "STATUS_INVALID_PRIMARY_GROUP" },
  { 0xC000005C, "STATUS_NO_IMPERSONATION_TOKEN" },
  { 0xC000005D, "STATUS_CANT_DISABLE_MANDATORY" },
  { 0xC000005E, "STATUS_NO_LOGON_SERVERS" },
  { 0xC000005F, "STATUS_NO_SUCH_LOGON_SESSION" },
  { 0xC0000060, "STATUS_NO_SUCH_PRIVILEGE" },
  { 0xC0000061, "STATUS_PRIVILEGE_NOT_HELD" },
  { 0xC0000062, "STATUS_INVALID_ACCOUNT_NAME" },
  { 0xC0000063, "STATUS_USER_EXISTS" },
  { 0xC0000064, "STATUS_NO_SUCH_USER" },
  { 0xC0000065, "STATUS_GROUP_EXISTS" },
  { 0xC0000066, "STATUS_NO_SUCH_GROUP" },
  { 0xC0000067, "STATUS_MEMBER_IN_GROUP" },
  { 0xC0000068, "STATUS_MEMBER_NOT_IN_GROUP" },
  { 0xC0000069, "STATUS_LAST_ADMIN" },
  { 0xC000006A, "STATUS_WRONG_PASSWORD" },
  { 0xC000006B, "STATUS_ILL_FORMED_PASSWORD" },
  { 0xC000006C, "STATUS_PASSWORD_RESTRICTION" },
  { 0xC000006D, "STATUS_LOGON_FAILURE" },
  { 0xC000006E, "STATUS_ACCOUNT_RESTRICTION" },
  { 0xC000006F, "STATUS_INVALID_LOGON_HOURS" },
  { 0xC0000070, "STATUS_INVALID_WORKSTATION" },
  { 0xC0000071, "STATUS_PASSWORD_EXPIRED" },
  { 0xC0000072, "STATUS_ACCOUNT_DISABLED" },
  { 0xC0000073, "STATUS_NONE_MAPPED" },
  { 0xC0000074, "STATUS_TOO_MANY_LUIDS_REQUESTED" },
  { 0xC0000075, "STATUS_LUIDS_EXHAUSTED" },
  { 0xC0000076, "STATUS_INVALID_SUB_AUTHORITY" },
  { 0xC0000077, "STATUS_INVALID_ACL" },
  { 0xC0000078, "STATUS_INVALID_SID" },
  { 0xC0000079, "STATUS_INVALID_SECURITY_DESCR" },
  { 0xC000007A, "STATUS_PROCEDURE_NOT_FOUND" },
  { 0xC000007B, "STATUS_INVALID_IMAGE_FORMAT" },
  { 0xC000007C, "STATUS_NO_TOKEN" },
  { 0xC000007D, "STATUS_BAD_INHERITANCE_ACL" },
  { 0xC000007E, "STATUS_RANGE_NOT_LOCKED" },
  { 0xC000007F, "STATUS_DISK_FULL" },
  { 0xC0000080, "STATUS_SERVER_DISABLED" },
  { 0xC0000081, "STATUS_SERVER_NOT_DISABLED" },
  { 0xC0000082, "STATUS_TOO_MANY_GUIDS_REQUESTED" },
  { 0xC0000083, "STATUS_GUIDS_EXHAUSTED" },
  { 0xC0000084, "STATUS_INVALID_ID_AUTHORITY" },
  { 0xC0000085, "STATUS_AGENTS_EXHAUSTED" },
  { 0xC0000086, "STATUS_INVALID_VOLUME_LABEL" },
  { 0xC0000087, "STATUS_SECTION_NOT_EXTENDED" },
  { 0xC0000088, "STATUS_NOT_MAPPED_DATA" },
  { 0xC0000089, "STATUS_RESOURCE_DATA_NOT_FOUND" },
  { 0xC000008A, "STATUS_RESOURCE_TYPE_NOT_FOUND" },
  { 0xC000008B, "STATUS_RESOURCE_NAME_NOT_FOUND" },
  { 0xC000008C, "STATUS_ARRAY_BOUNDS_EXCEEDED" },
  { 0xC000008D, "STATUS_FLOAT_DENORMAL_OPERAND" },
  { 0xC000008E, "STATUS_FLOAT_DIVIDE_BY_ZERO" },
  { 0xC000008F, "STATUS_FLOAT_INEXACT_RESULT" },
  { 0xC0000090, "STATUS_FLOAT_INVALID_OPERATION" },
  { 0xC0000091, "STATUS_FLOAT_OVERFLOW" },
  { 0xC0000092, "STATUS_FLOAT_STACK_CHECK" },
  { 0xC0000093, "STATUS_FLOAT_UNDERFLOW" },
  { 0xC0000094, "STATUS_INTEGER_DIVIDE_BY_ZERO" },
  { 0xC0000095, "STATUS_INTEGER_OVERFLOW" },
  { 0xC0000096, "STATUS_PRIVILEGED_INSTRUCTION" },
  { 0xC0000097, "STATUS_TOO_MANY_PAGING_FILES" },
  { 0xC0000098, "STATUS_FILE_INVALID" },
  { 0xC0000099, "STATUS_ALLOTTED_SPACE_EXCEEDED" },
  { 0xC000009A, "STATUS_INSUFFICIENT_RESOURCES" },
  { 0xC000009B, "STATUS_DFS_EXIT_PATH_FOUND" },
  { 0xC000009C, "STATUS_DEVICE_DATA_ERROR" },
  { 0xC000009D, "STATUS_DEVICE_NOT_CONNECTED" },
  { 0xC000009E, "STATUS_DEVICE_POWER_FAILURE" },
  { 0xC000009F, "STATUS_FREE_VM_NOT_AT_BASE" },
  { 0xC00000A0, "STATUS_MEMORY_NOT_ALLOCATED" },
  { 0xC00000A1, "STATUS_WORKING_SET_QUOTA" },
  { 0xC00000A2, "STATUS_MEDIA_WRITE_PROTECTED" },
  { 0xC00000A3, "STATUS_DEVICE_NOT_READY" },
  { 0xC00000A4, "STATUS_INVALID_GROUP_ATTRIBUTES" },
  { 0xC00000A5, "STATUS_BAD_IMPERSONATION_LEVEL" },
  { 0xC00000A6, "STATUS_CANT_OPEN_ANONYMOUS" },
  { 0xC00000A7, "STATUS_BAD_VALIDATION_CLASS" },
  { 0xC00000A8, "STATUS_BAD_TOKEN_TYPE" },
  { 0xC00000A9, "STATUS_BAD_MASTER_BOOT_RECORD" },
  { 0xC00000AA, "STATUS_INSTRUCTION_MISALIGNMENT" },
  { 0xC00000AB, "STATUS_INSTANCE_NOT_AVAILABLE" },
  { 0xC00000AC, "STATUS_PIPE_NOT_AVAILABLE" },
  { 0xC00000AD, "STATUS_INVALID_PIPE_STATE" },
  { 0xC00000AE, "STATUS_PIPE_BUSY" },
  { 0xC00000AF, "STATUS_ILLEGAL_FUNCTION" },
  { 0xC00000B0, "STATUS_PIPE_DISCONNECTED" },
  { 0xC00000B1, "STATUS_PIPE_CLOSING" },
  { 0xC00000B2, "STATUS_PIPE_CONNECTED" },
  { 0xC00000B3, "STATUS_PIPE_LISTENING" },
  { 0xC00000B4, "STATUS_INVALID_READ_MODE" },
  { 0xC00000B5, "STATUS_IO_TIMEOUT" },
  { 0xC00000B6, "STATUS_FILE_FORCED_CLOSED" },
  { 0xC00000B7, "STATUS_PROFILING_NOT_STARTED" },
  { 0xC00000B8, "STATUS_PROFILING_NOT_STOPPED" },
  { 0xC00000B9, "STATUS_COULD_NOT_INTERPRET" },
  { 0xC00000BA, "STATUS_FILE_IS_A_DIRECTORY" },
  { 0xC00000BB, "STATUS_NOT_SUPPORTED" },
  { 0xC00000BC, "STATUS_REMOTE_NOT_LISTENING" },
  { 0xC00000BD, "STATUS_DUPLICATE_NAME" },
  { 0xC00000BE, "STATUS_BAD_NETWORK_PATH" },
  { 0xC00000BF, "STATUS_NETWORK_BUSY" },
  { 0xC00000C0, "STATUS_DEVICE_DOES_NOT_EXIST" },
  { 0xC00000C1, "STATUS_TOO_MANY_COMMANDS" },
  { 0xC00000C2, "STATUS_ADAPTER_HARDWARE_ERROR" },
  { 0xC00000C3, "STATUS_INVALID_NETWORK_RESPONSE" },
  { 0xC00000C4, "STATUS_UNEXPECTED_NETWORK_ERROR" },
  { 0xC00000C5, "STATUS_BAD_REMOTE_ADAPTER" },
  { 0xC00000C6, "STATUS_PRINT_QUEUE_FULL" },
  { 0xC00000C7, "STATUS_NO_SPOOL_SPACE" },
  { 0xC00000C8, "STATUS_PRINT_CANCELLED" },
  { 0xC00000C9, "STATUS_NETWORK_NAME_DELETED" },
  { 0xC00000CA, "STATUS_NETWORK_ACCESS_DENIED" },
  { 0xC00000CB, "STATUS_BAD_DEVICE_TYPE" },
  { 0xC00000CC, "STATUS_BAD_NETWORK_NAME" },
  { 0xC00000CD, "STATUS_TOO_MANY_NAMES" },
  { 0xC00000CE, "STATUS_TOO_MANY_SESSIONS" },
  { 0xC00000CF, "STATUS_SHARING_PAUSED" },
  { 0xC00000D0, "STATUS_REQUEST_NOT_ACCEPTED" },
  { 0xC00000D1, "STATUS_REDIRECTOR_PAUSED" },
  { 0xC00000D2, "STATUS_NET_WRITE_FAULT" },
  { 0xC00000D3, "STATUS_PROFILING_AT_LIMIT" },
  { 0xC00000D4, "STATUS_NOT_SAME_DEVICE" },
  { 0xC00000D5, "STATUS_FILE_RENAMED" },
  { 0xC00000D6, "STATUS_VIRTUAL_CIRCUIT_CLOSED" },
  { 0xC00000D7, "STATUS_NO_SECURITY_ON_OBJECT" },
  { 0xC00000D8, "STATUS_CANT_WAIT" },
  { 0xC00000D9, "STATUS_PIPE_EMPTY" },
  { 0xC00000DA, "STATUS_CANT_ACCESS_DOMAIN_INFO" },
  { 0xC00000DB, "STATUS_CANT_TERMINATE_SELF" },
  { 0xC00000DC, "STATUS_INVALID_SERVER_STATE" },
  { 0xC00000DD, "STATUS_INVALID_DOMAIN_STATE" },
  { 0xC00000DE, "STATUS_INVALID_DOMAIN_ROLE" },
  { 0xC00000DF, "STATUS_NO_SUCH_DOMAIN" },
  { 0xC00000E0, "STATUS_DOMAIN_EXISTS" },
  { 0xC00000E1, "STATUS_DOMAIN_LIMIT_EXCEEDED" },
  { 0xC00000E2, "STATUS_OPLOCK_NOT_GRANTED" },
  { 0xC00000E3, "STATUS_INVALID_OPLOCK_PROTOCOL" },
  { 0xC00000E4, "STATUS_INTERNAL_DB_CORRUPTION" },
  { 0xC00000E5, "STATUS_INTERNAL_ERROR" },
  { 0xC00000E6, "STATUS_GENERIC_NOT_MAPPED" },
  { 0xC00000E7, "STATUS_BAD_DESCRIPTOR_FORMAT" },
  { 0xC00000E8, "STATUS_INVALID_USER_BUFFER" },
  { 0xC00000E9, "STATUS_UNEXPECTED_IO_ERROR" },
  { 0xC00000EA, "STATUS_UNEXPECTED_MM_CREATE_ERR" },
  { 0xC00000EB, "STATUS_UNEXPECTED_MM_MAP_ERROR" },
  { 0xC00000EC, "STATUS_UNEXPECTED_MM_EXTEND_ERR" },
  { 0xC00000ED, "STATUS_NOT_LOGON_PROCESS" },
  { 0xC00000EE, "STATUS_LOGON_SESSION_EXISTS" },
  { 0xC00000EF, "STATUS_INVALID_PARAMETER_1" },
  { 0xC00000F0, "STATUS_INVALID_PARAMETER_2" },
  { 0xC00000F1, "STATUS_INVALID_PARAMETER_3" },
  { 0xC00000F2, "STATUS_INVALID_PARAMETER_4" },
  { 0xC00000F3, "STATUS_INVALID_PARAMETER_5" },
  { 0xC00000F4, "STATUS_INVALID_PARAMETER_6" },
  { 0xC00000F5, "STATUS_INVALID_PARAMETER_7" },
  { 0xC00000F6, "STATUS_INVALID_PARAMETER_8" },
  { 0xC00000F7, "STATUS_INVALID_PARAMETER_9" },
  { 0xC00000F8, "STATUS_INVALID_PARAMETER_10" },
  { 0xC00000F9, "STATUS_INVALID_PARAMETER_11" },
  { 0xC00000FA, "STATUS_INVALID_PARAMETER_12" },
  { 0xC00000FB, "STATUS_REDIRECTOR_NOT_STARTED" },
  { 0xC00000FC, "STATUS_REDIRECTOR_STARTED" },
  { 0xC00000FD, "STATUS_STACK_OVERFLOW" },
  { 0xC00000FE, "STATUS_NO_SUCH_PACKAGE" },
  { 0xC00000FF, "STATUS_BAD_FUNCTION_TABLE" },
  { 0xC0000100, "STATUS_VARIABLE_NOT_FOUND" },
  { 0xC0000101, "STATUS_DIRECTORY_NOT_EMPTY" },
  { 0xC0000102, "STATUS_FILE_CORRUPT_ERROR" },
  { 0xC0000103, "STATUS_NOT_A_DIRECTORY" },
  { 0xC0000104, "STATUS_BAD_LOGON_SESSION_STATE" },
  { 0xC0000105, "STATUS_LOGON_SESSION_COLLISION" },
  { 0xC0000106, "STATUS_NAME_TOO_LONG" },
  { 0xC0000107, "STATUS_FILES_OPEN" },
  { 0xC0000108, "STATUS_CONNECTION_IN_USE" },
  { 0xC0000109, "STATUS_MESSAGE_NOT_FOUND" },
  { 0xC000010A, "STATUS_PROCESS_IS_TERMINATING" },
  { 0xC000010B, "STATUS_INVALID_LOGON_TYPE" },
  { 0xC000010C, "STATUS_NO_GUID_TRANSLATION" },
  { 0xC000010D, "STATUS_CANNOT_IMPERSONATE" },
  { 0xC000010E, "STATUS_IMAGE_ALREADY_LOADED" },
  { 0xC000010F, "STATUS_ABIOS_NOT_PRESENT" },
  { 0xC0000110, "STATUS_ABIOS_LID_NOT_EXIST" },
  { 0xC0000111, "STATUS_ABIOS_LID_ALREADY_OWNED" },
  { 0xC0000112, "STATUS_ABIOS_NOT_LID_OWNER" },
  { 0xC0000113, "STATUS_ABIOS_INVALID_COMMAND" },
  { 0xC0000114, "STATUS_ABIOS_INVALID_LID" },
  { 0xC0000115, "STATUS_ABIOS_SELECTOR_NOT_AVAILABLE" },
  { 0xC0000116, "STATUS_ABIOS_INVALID_SELECTOR" },
  { 0xC0000117, "STATUS_NO_LDT" },
  { 0xC0000118, "STATUS_INVALID_LDT_SIZE" },
  { 0xC0000119, "STATUS_INVALID_LDT_OFFSET" },
  { 0xC000011A, "STATUS_INVALID_LDT_DESCRIPTOR" },
  { 0xC000011B, "STATUS_INVALID_IMAGE_NE_FORMAT" },
  { 0xC000011C, "STATUS_RXACT_INVALID_STATE" },
  { 0xC000011D, "STATUS_RXACT_COMMIT_FAILURE" },
  { 0xC000011E, "STATUS_MAPPED_FILE_SIZE_ZERO" },
  { 0xC000011F, "STATUS_TOO_MANY_OPENED_FILES" },
  { 0xC0000120, "STATUS_CANCELLED" },
  { 0xC0000121, "STATUS_CANNOT_DELETE" },
  { 0xC0000122, "STATUS_INVALID_COMPUTER_NAME" },
  { 0xC0000123, "STATUS_FILE_DELETED" },
  { 0xC0000124, "STATUS_SPECIAL_ACCOUNT" },
  { 0xC0000125, "STATUS_SPECIAL_GROUP" },
  { 0xC0000126, "STATUS_SPECIAL_USER" },
  { 0xC0000127, "STATUS_MEMBERS_PRIMARY_GROUP" },
  { 0xC0000128, "STATUS_FILE_CLOSED" },
  { 0xC0000129, "STATUS_TOO_MANY_THREADS" },
  { 0xC000012A, "STATUS_THREAD_NOT_IN_PROCESS" },
  { 0xC000012B, "STATUS_TOKEN_ALREADY_IN_USE" },
  { 0xC000012C, "STATUS_PAGEFILE_QUOTA_EXCEEDED" },
  { 0xC000012D, "STATUS_COMMITMENT_LIMIT" },
  { 0xC000012E, "STATUS_INVALID_IMAGE_LE_FORMAT" },
  { 0xC000012F, "STATUS_INVALID_IMAGE_NOT_MZ" },
  { 0xC0000130, "STATUS_INVALID_IMAGE_PROTECT" },
  { 0xC0000131, "STATUS_INVALID_IMAGE_WIN_16" },
  { 0xC0000132, "STATUS_LOGON_SERVER_CONFLICT" },
  { 0xC0000133, "STATUS_TIME_DIFFERENCE_AT_DC" },
  { 0xC0000134, "STATUS_SYNCHRONIZATION_REQUIRED" },
  { 0xC0000135, "STATUS_DLL_NOT_FOUND" },
  { 0xC0000136, "STATUS_OPEN_FAILED" },
  { 0xC0000137, "STATUS_IO_PRIVILEGE_FAILED" },
  { 0xC0000138, "STATUS_ORDINAL_NOT_FOUND" },
  { 0xC0000139, "STATUS_ENTRYPOINT_NOT_FOUND" },
  { 0xC000013A, "STATUS_CONTROL_C_EXIT" },
  { 0xC000013B, "STATUS_LOCAL_DISCONNECT" },
  { 0xC000013C, "STATUS_REMOTE_DISCONNECT" },
  { 0xC000013D, "STATUS_REMOTE_RESOURCES" },
  { 0xC000013E, "STATUS_LINK_FAILED" },
  { 0xC000013F, "STATUS_LINK_TIMEOUT" },
  { 0xC0000140, "STATUS_INVALID_CONNECTION" },
  { 0xC0000141, "STATUS_INVALID_ADDRESS" },
  { 0xC0000142, "STATUS_DLL_INIT_FAILED" },
  { 0xC0000143, "STATUS_MISSING_SYSTEMFILE" },
  { 0xC0000144, "STATUS_UNHANDLED_EXCEPTION" },
  { 0xC0000145, "STATUS_APP_INIT_FAILURE" },
  { 0xC0000146, "STATUS_PAGEFILE_CREATE_FAILED" },
  { 0xC0000147, "STATUS_NO_PAGEFILE" },
  { 0xC0000148, "STATUS_INVALID_LEVEL" },
  { 0xC0000149, "STATUS_WRONG_PASSWORD_CORE" },
  { 0xC000014A, "STATUS_ILLEGAL_FLOAT_CONTEXT" },
  { 0xC000014B, "STATUS_PIPE_BROKEN" },
  { 0xC000014C, "STATUS_REGISTRY_CORRUPT" },
  { 0xC000014D, "STATUS_REGISTRY_IO_FAILED" },
  { 0xC000014E, "STATUS_NO_EVENT_PAIR" },
  { 0xC000014F, "STATUS_UNRECOGNIZED_VOLUME" },
  { 0xC0000150, "STATUS_SERIAL_NO_DEVICE_INITED" },
  { 0xC0000151, "STATUS_NO_SUCH_ALIAS" },
  { 0xC0000152, "STATUS_MEMBER_NOT_IN_ALIAS" },
  { 0xC0000153, "STATUS_MEMBER_IN_ALIAS" },
  { 0xC0000154, "STATUS_ALIAS_EXISTS" },
  { 0xC0000155, "STATUS_LOGON_NOT_GRANTED" },
  { 0xC0000156, "STATUS_TOO_MANY_SECRETS" },
  { 0xC0000157, "STATUS_SECRET_TOO_LONG" },
  { 0xC0000158, "STATUS_INTERNAL_DB_ERROR" },
  { 0xC0000159, "STATUS_FULLSCREEN_MODE" },
  { 0xC000015A, "STATUS_TOO_MANY_CONTEXT_IDS" },
  { 0xC000015B, "STATUS_LOGON_TYPE_NOT_GRANTED" },
  { 0xC000015C, "STATUS_NOT_REGISTRY_FILE" },
  { 0xC000015D, "STATUS_NT_CROSS_ENCRYPTION_REQUIRED" },
  { 0xC000015E, "STATUS_DOMAIN_CTRLR_CONFIG_ERROR" },
  { 0xC000015F, "STATUS_FT_MISSING_MEMBER" },
  { 0xC0000160, "STATUS_ILL_FORMED_SERVICE_ENTRY" },
  { 0xC0000161, "STATUS_ILLEGAL_CHARACTER" },
  { 0xC0000162, "STATUS_UNMAPPABLE_CHARACTER" },
  { 0xC0000163, "STATUS_UNDEFINED_CHARACTER" },
  { 0xC0000164, "STATUS_FLOPPY_VOLUME" },
  { 0xC0000165, "STATUS_FLOPPY_ID_MARK_NOT_FOUND" },
  { 0xC0000166, "STATUS_FLOPPY_WRONG_CYLINDER" },
  { 0xC0000167, "STATUS_FLOPPY_UNKNOWN_ERROR" },
  { 0xC0000168, "STATUS_FLOPPY_BAD_REGISTERS" },
  { 0xC0000169, "STATUS_DISK_RECALIBRATE_FAILED" },
  { 0xC000016A, "STATUS_DISK_OPERATION_FAILED" },
  { 0xC000016B, "STATUS_DISK_RESET_FAILED" },
  { 0xC000016C, "STATUS_SHARED_IRQ_BUSY" },
  { 0xC000016D, "STATUS_FT_ORPHANING" },
  { 0xC000016E, "STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT" },
  { 0xC0000172, "STATUS_PARTITION_FAILURE" },
  { 0xC0000173, "STATUS_INVALID_BLOCK_LENGTH" },
  { 0xC0000174, "STATUS_DEVICE_NOT_PARTITIONED" },
  { 0xC0000175, "STATUS_UNABLE_TO_LOCK_MEDIA" },
  { 0xC0000176, "STATUS_UNABLE_TO_UNLOAD_MEDIA" },
  { 0xC0000177, "STATUS_EOM_OVERFLOW" },
  { 0xC0000178, "STATUS_NO_MEDIA" },
  { 0xC000017A, "STATUS_NO_SUCH_MEMBER" },
  { 0xC000017B, "STATUS_INVALID_MEMBER" },
  { 0xC000017C, "STATUS_KEY_DELETED" },
  { 0xC000017D, "STATUS_NO_LOG_SPACE" },
  { 0xC000017E, "STATUS_TOO_MANY_SIDS" },
  { 0xC000017F, "STATUS_LM_CROSS_ENCRYPTION_REQUIRED" },
  { 0xC0000180, "STATUS_KEY_HAS_CHILDREN" },
  { 0xC0000181, "STATUS_CHILD_MUST_BE_VOLATILE" },
  { 0xC0000182, "STATUS_DEVICE_CONFIGURATION_ERROR" },
  { 0xC0000183, "STATUS_DRIVER_INTERNAL_ERROR" },
  { 0xC0000184, "STATUS_INVALID_DEVICE_STATE" },
  { 0xC0000185, "STATUS_IO_DEVICE_ERROR" },
  { 0xC0000186, "STATUS_DEVICE_PROTOCOL_ERROR" },
  { 0xC0000187, "STATUS_BACKUP_CONTROLLER" },
  { 0xC0000188, "STATUS_LOG_FILE_FULL" },
  { 0xC0000189, "STATUS_TOO_LATE" },
  { 0xC000018A, "STATUS_NO_TRUST_LSA_SECRET" },
  { 0xC000018B, "STATUS_NO_TRUST_SAM_ACCOUNT" },
  { 0xC000018C, "STATUS_TRUSTED_DOMAIN_FAILURE" },
  { 0xC000018D, "STATUS_TRUSTED_RELATIONSHIP_FAILURE" },
  { 0xC000018E, "STATUS_EVENTLOG_FILE_CORRUPT" },
  { 0xC000018F, "STATUS_EVENTLOG_CANT_START" },
  { 0xC0000190, "STATUS_TRUST_FAILURE" },
  { 0xC0000191, "STATUS_MUTANT_LIMIT_EXCEEDED" },
  { 0xC0000192, "STATUS_NETLOGON_NOT_STARTED" },
  { 0xC0000193, "STATUS_ACCOUNT_EXPIRED" },
  { 0xC0000194, "STATUS_POSSIBLE_DEADLOCK" },
  { 0xC0000195, "STATUS_NETWORK_CREDENTIAL_CONFLICT" },
  { 0xC0000196, "STATUS_REMOTE_SESSION_LIMIT" },
  { 0xC0000197, "STATUS_EVENTLOG_FILE_CHANGED" },
  { 0xC0000198, "STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT" },
  { 0xC0000199, "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT" },
  { 0xC000019A, "STATUS_NOLOGON_SERVER_TRUST_ACCOUNT" },
  { 0xC000019B, "STATUS_DOMAIN_TRUST_INCONSISTENT" },
  { 0xC000019C, "STATUS_FS_DRIVER_REQUIRED" },
  { 0xC0000202, "STATUS_NO_USER_SESSION_KEY" },
  { 0xC0000203, "STATUS_USER_SESSION_DELETED" },
  { 0xC0000204, "STATUS_RESOURCE_LANG_NOT_FOUND" },
  { 0xC0000205, "STATUS_INSUFF_SERVER_RESOURCES" },
  { 0xC0000206, "STATUS_INVALID_BUFFER_SIZE" },
  { 0xC0000207, "STATUS_INVALID_ADDRESS_COMPONENT" },
  { 0xC0000208, "STATUS_INVALID_ADDRESS_WILDCARD" },
  { 0xC0000209, "STATUS_TOO_MANY_ADDRESSES" },
  { 0xC000020A, "STATUS_ADDRESS_ALREADY_EXISTS" },
  { 0xC000020B, "STATUS_ADDRESS_CLOSED" },
  { 0xC000020C, "STATUS_CONNECTION_DISCONNECTED" },
  { 0xC000020D, "STATUS_CONNECTION_RESET" },
  { 0xC000020E, "STATUS_TOO_MANY_NODES" },
  { 0xC000020F, "STATUS_TRANSACTION_ABORTED" },
  { 0xC0000210, "STATUS_TRANSACTION_TIMED_OUT" },
  { 0xC0000211, "STATUS_TRANSACTION_NO_RELEASE" },
  { 0xC0000212, "STATUS_TRANSACTION_NO_MATCH" },
  { 0xC0000213, "STATUS_TRANSACTION_RESPONDED" },
  { 0xC0000214, "STATUS_TRANSACTION_INVALID_ID" },
  { 0xC0000215, "STATUS_TRANSACTION_INVALID_TYPE" },
  { 0xC0000216, "STATUS_NOT_SERVER_SESSION" },
  { 0xC0000217, "STATUS_NOT_CLIENT_SESSION" },
  { 0xC0000218, "STATUS_CANNOT_LOAD_REGISTRY_FILE" },
  { 0xC0000219, "STATUS_DEBUG_ATTACH_FAILED" },
  { 0xC000021A, "STATUS_SYSTEM_PROCESS_TERMINATED" },
  { 0xC000021B, "STATUS_DATA_NOT_ACCEPTED" },
  { 0xC000021C, "STATUS_NO_BROWSER_SERVERS_FOUND" },
  { 0xC000021D, "STATUS_VDM_HARD_ERROR" },
  { 0xC000021E, "STATUS_DRIVER_CANCEL_TIMEOUT" },
  { 0xC000021F, "STATUS_REPLY_MESSAGE_MISMATCH" },
  { 0xC0000220, "STATUS_MAPPED_ALIGNMENT" },
  { 0xC0000221, "STATUS_IMAGE_CHECKSUM_MISMATCH" },
  { 0xC0000222, "STATUS_LOST_WRITEBEHIND_DATA" },
  { 0xC0000223, "STATUS_CLIENT_SERVER_PARAMETERS_INVALID" },
  { 0xC0000224, "STATUS_PASSWORD_MUST_CHANGE" },
  { 0xC0000225, "STATUS_NOT_FOUND" },
  { 0xC0000226, "STATUS_NOT_TINY_STREAM" },
  { 0xC0000227, "STATUS_RECOVERY_FAILURE" },
  { 0xC0000228, "STATUS_STACK_OVERFLOW_READ" },
  { 0xC0000229, "STATUS_FAIL_CHECK" },
  { 0xC000022A, "STATUS_DUPLICATE_OBJECTID" },
  { 0xC000022B, "STATUS_OBJECTID_EXISTS" },
  { 0xC000022C, "STATUS_CONVERT_TO_LARGE" },
  { 0xC000022D, "STATUS_RETRY" },
  { 0xC000022E, "STATUS_FOUND_OUT_OF_SCOPE" },
  { 0xC000022F, "STATUS_ALLOCATE_BUCKET" },
  { 0xC0000230, "STATUS_PROPSET_NOT_FOUND" },
  { 0xC0000231, "STATUS_MARSHALL_OVERFLOW" },
  { 0xC0000232, "STATUS_INVALID_VARIANT" },
  { 0xC0000233, "STATUS_DOMAIN_CONTROLLER_NOT_FOUND" },
  { 0xC0000234, "STATUS_ACCOUNT_LOCKED_OUT" },
  { 0xC0000235, "STATUS_HANDLE_NOT_CLOSABLE" },
  { 0xC0000236, "STATUS_CONNECTION_REFUSED" },
  { 0xC0000237, "STATUS_GRACEFUL_DISCONNECT" },
  { 0xC0000238, "STATUS_ADDRESS_ALREADY_ASSOCIATED" },
  { 0xC0000239, "STATUS_ADDRESS_NOT_ASSOCIATED" },
  { 0xC000023A, "STATUS_CONNECTION_INVALID" },
  { 0xC000023B, "STATUS_CONNECTION_ACTIVE" },
  { 0xC000023C, "STATUS_NETWORK_UNREACHABLE" },
  { 0xC000023D, "STATUS_HOST_UNREACHABLE" },
  { 0xC000023E, "STATUS_PROTOCOL_UNREACHABLE" },
  { 0xC000023F, "STATUS_PORT_UNREACHABLE" },
  { 0xC0000240, "STATUS_REQUEST_ABORTED" },
  { 0xC0000241, "STATUS_CONNECTION_ABORTED" },
  { 0xC0000242, "STATUS_BAD_COMPRESSION_BUFFER" },
  { 0xC0000243, "STATUS_USER_MAPPED_FILE" },
  { 0xC0000244, "STATUS_AUDIT_FAILED" },
  { 0xC0000245, "STATUS_TIMER_RESOLUTION_NOT_SET" },
  { 0xC0000246, "STATUS_CONNECTION_COUNT_LIMIT" },
  { 0xC0000247, "STATUS_LOGIN_TIME_RESTRICTION" },
  { 0xC0000248, "STATUS_LOGIN_WKSTA_RESTRICTION" },
  { 0xC0000249, "STATUS_IMAGE_MP_UP_MISMATCH" },
  { 0xC0000250, "STATUS_INSUFFICIENT_LOGON_INFO" },
  { 0xC0000251, "STATUS_BAD_DLL_ENTRYPOINT" },
  { 0xC0000252, "STATUS_BAD_SERVICE_ENTRYPOINT" },
  { 0xC0000253, "STATUS_LPC_REPLY_LOST" },
  { 0xC0000254, "STATUS_IP_ADDRESS_CONFLICT1" },
  { 0xC0000255, "STATUS_IP_ADDRESS_CONFLICT2" },
  { 0xC0000256, "STATUS_REGISTRY_QUOTA_LIMIT" },
  { 0xC0000257, "STATUS_PATH_NOT_COVERED" },
  { 0xC0000258, "STATUS_NO_CALLBACK_ACTIVE" },
  { 0xC0000259, "STATUS_LICENSE_QUOTA_EXCEEDED" },
  { 0xC000025A, "STATUS_PWD_TOO_SHORT" },
  { 0xC000025B, "STATUS_PWD_TOO_RECENT" },
  { 0xC000025C, "STATUS_PWD_HISTORY_CONFLICT" },
  { 0xC000025E, "STATUS_PLUGPLAY_NO_DEVICE" },
  { 0xC000025F, "STATUS_UNSUPPORTED_COMPRESSION" },
  { 0xC0000260, "STATUS_INVALID_HW_PROFILE" },
  { 0xC0000261, "STATUS_INVALID_PLUGPLAY_DEVICE_PATH" },
  { 0xC0000262, "STATUS_DRIVER_ORDINAL_NOT_FOUND" },
  { 0xC0000263, "STATUS_DRIVER_ENTRYPOINT_NOT_FOUND" },
  { 0xC0000264, "STATUS_RESOURCE_NOT_OWNED" },
  { 0xC0000265, "STATUS_TOO_MANY_LINKS" },
  { 0xC0000266, "STATUS_QUOTA_LIST_INCONSISTENT" },
  { 0xC0000267, "STATUS_FILE_IS_OFFLINE" },
  { 0xC0000268, "STATUS_EVALUATION_EXPIRATION" },
  { 0xC0000269, "STATUS_ILLEGAL_DLL_RELOCATION" },
  { 0xC000026A, "STATUS_LICENSE_VIOLATION" },
  { 0xC000026B, "STATUS_DLL_INIT_FAILED_LOGOFF" },
  { 0xC000026C, "STATUS_DRIVER_UNABLE_TO_LOAD" },
  { 0xC000026D, "STATUS_DFS_UNAVAILABLE" },
  { 0xC000026E, "STATUS_VOLUME_DISMOUNTED" },
  { 0xC000026F, "STATUS_WX86_INTERNAL_ERROR" },
  { 0xC0000270, "STATUS_WX86_FLOAT_STACK_CHECK" },
  { 0xC0009898, "STATUS_WOW_ASSERTION" },
  { 0xC0020001, "RPC_NT_INVALID_STRING_BINDING" },
  { 0xC0020002, "RPC_NT_WRONG_KIND_OF_BINDING" },
  { 0xC0020003, "RPC_NT_INVALID_BINDING" },
  { 0xC0020004, "RPC_NT_PROTSEQ_NOT_SUPPORTED" },
  { 0xC0020005, "RPC_NT_INVALID_RPC_PROTSEQ" },
  { 0xC0020006, "RPC_NT_INVALID_STRING_UUID" },
  { 0xC0020007, "RPC_NT_INVALID_ENDPOINT_FORMAT" },
  { 0xC0020008, "RPC_NT_INVALID_NET_ADDR" },
  { 0xC0020009, "RPC_NT_NO_ENDPOINT_FOUND" },
  { 0xC002000A, "RPC_NT_INVALID_TIMEOUT" },
  { 0xC002000B, "RPC_NT_OBJECT_NOT_FOUND" },
  { 0xC002000C, "RPC_NT_ALREADY_REGISTERED" },
  { 0xC002000D, "RPC_NT_TYPE_ALREADY_REGISTERED" },
  { 0xC002000E, "RPC_NT_ALREADY_LISTENING" },
  { 0xC002000F, "RPC_NT_NO_PROTSEQS_REGISTERED" },
  { 0xC0020010, "RPC_NT_NOT_LISTENING" },
  { 0xC0020011, "RPC_NT_UNKNOWN_MGR_TYPE" },
  { 0xC0020012, "RPC_NT_UNKNOWN_IF" },
  { 0xC0020013, "RPC_NT_NO_BINDINGS" },
  { 0xC0020014, "RPC_NT_NO_PROTSEQS" },
  { 0xC0020015, "RPC_NT_CANT_CREATE_ENDPOINT" },
  { 0xC0020016, "RPC_NT_OUT_OF_RESOURCES" },
  { 0xC0020017, "RPC_NT_SERVER_UNAVAILABLE" },
  { 0xC0020018, "RPC_NT_SERVER_TOO_BUSY" },
  { 0xC0020019, "RPC_NT_INVALID_NETWORK_OPTIONS" },
  { 0xC002001A, "RPC_NT_NO_CALL_ACTIVE" },
  { 0xC002001B, "RPC_NT_CALL_FAILED" },
  { 0xC002001C, "RPC_NT_CALL_FAILED_DNE" },
  { 0xC002001D, "RPC_NT_PROTOCOL_ERROR" },
  { 0xC002001F, "RPC_NT_UNSUPPORTED_TRANS_SYN" },
  { 0xC0020021, "RPC_NT_UNSUPPORTED_TYPE" },
  { 0xC0020022, "RPC_NT_INVALID_TAG" },
  { 0xC0020023, "RPC_NT_INVALID_BOUND" },
  { 0xC0020024, "RPC_NT_NO_ENTRY_NAME" },
  { 0xC0020025, "RPC_NT_INVALID_NAME_SYNTAX" },
  { 0xC0020026, "RPC_NT_UNSUPPORTED_NAME_SYNTAX" },
  { 0xC0020028, "RPC_NT_UUID_NO_ADDRESS" },
  { 0xC0020029, "RPC_NT_DUPLICATE_ENDPOINT" },
  { 0xC002002A, "RPC_NT_UNKNOWN_AUTHN_TYPE" },
  { 0xC002002B, "RPC_NT_MAX_CALLS_TOO_SMALL" },
  { 0xC002002C, "RPC_NT_STRING_TOO_LONG" },
  { 0xC002002D, "RPC_NT_PROTSEQ_NOT_FOUND" },
  { 0xC002002E, "RPC_NT_PROCNUM_OUT_OF_RANGE" },
  { 0xC002002F, "RPC_NT_BINDING_HAS_NO_AUTH" },
  { 0xC0020030, "RPC_NT_UNKNOWN_AUTHN_SERVICE" },
  { 0xC0020031, "RPC_NT_UNKNOWN_AUTHN_LEVEL" },
  { 0xC0020032, "RPC_NT_INVALID_AUTH_IDENTITY" },
  { 0xC0020033, "RPC_NT_UNKNOWN_AUTHZ_SERVICE" },
  { 0xC0020034, "EPT_NT_INVALID_ENTRY" },
  { 0xC0020035, "EPT_NT_CANT_PERFORM_OP" },
  { 0xC0020036, "EPT_NT_NOT_REGISTERED" },
  { 0xC0020037, "RPC_NT_NOTHING_TO_EXPORT" },
  { 0xC0020038, "RPC_NT_INCOMPLETE_NAME" },
  { 0xC0020039, "RPC_NT_INVALID_VERS_OPTION" },
  { 0xC002003A, "RPC_NT_NO_MORE_MEMBERS" },
  { 0xC002003B, "RPC_NT_NOT_ALL_OBJS_UNEXPORTED" },
  { 0xC002003C, "RPC_NT_INTERFACE_NOT_FOUND" },
  { 0xC002003D, "RPC_NT_ENTRY_ALREADY_EXISTS" },
  { 0xC002003E, "RPC_NT_ENTRY_NOT_FOUND" },
  { 0xC002003F, "RPC_NT_NAME_SERVICE_UNAVAILABLE" },
  { 0xC0020040, "RPC_NT_INVALID_NAF_ID" },
  { 0xC0020041, "RPC_NT_CANNOT_SUPPORT" },
  { 0xC0020042, "RPC_NT_NO_CONTEXT_AVAILABLE" },
  { 0xC0020043, "RPC_NT_INTERNAL_ERROR" },
  { 0xC0020044, "RPC_NT_ZERO_DIVIDE" },
  { 0xC0020045, "RPC_NT_ADDRESS_ERROR" },
  { 0xC0020046, "RPC_NT_FP_DIV_ZERO" },
  { 0xC0020047, "RPC_NT_FP_UNDERFLOW" },
  { 0xC0020048, "RPC_NT_FP_OVERFLOW" },
  { 0xC0030001, "RPC_NT_NO_MORE_ENTRIES" },
  { 0xC0030002, "RPC_NT_SS_CHAR_TRANS_OPEN_FAIL" },
  { 0xC0030003, "RPC_NT_SS_CHAR_TRANS_SHORT_FILE" },
  { 0xC0030004, "RPC_NT_SS_IN_NULL_CONTEXT" },
  { 0xC0030005, "RPC_NT_SS_CONTEXT_MISMATCH" },
  { 0xC0030006, "RPC_NT_SS_CONTEXT_DAMAGED" },
  { 0xC0030007, "RPC_NT_SS_HANDLES_MISMATCH" },
  { 0xC0030008, "RPC_NT_SS_CANNOT_GET_CALL_HANDLE" },
  { 0xC0030009, "RPC_NT_NULL_REF_POINTER" },
  { 0xC003000A, "RPC_NT_ENUM_VALUE_OUT_OF_RANGE" },
  { 0xC003000B, "RPC_NT_BYTE_COUNT_TOO_SMALL" },
  { 0xC003000C, "RPC_NT_BAD_STUB_DATA" },
  { 0xC0020049, "RPC_NT_CALL_IN_PROGRESS" },
  { 0xC002004A, "RPC_NT_NO_MORE_BINDINGS" },
  { 0xC002004B, "RPC_NT_GROUP_MEMBER_NOT_FOUND" },
  { 0xC002004C, "EPT_NT_CANT_CREATE" },
  { 0xC002004D, "RPC_NT_INVALID_OBJECT" },
  { 0xC002004F, "RPC_NT_NO_INTERFACES" },
  { 0xC0020050, "RPC_NT_CALL_CANCELLED" },
  { 0xC0020051, "RPC_NT_BINDING_INCOMPLETE" },
  { 0xC0020052, "RPC_NT_COMM_FAILURE" },
  { 0xC0020053, "RPC_NT_UNSUPPORTED_AUTHN_LEVEL" },
  { 0xC0020054, "RPC_NT_NO_PRINC_NAME" },
  { 0xC0020055, "RPC_NT_NOT_RPC_ERROR" },
  { 0x40020056, "RPC_NT_UUID_LOCAL_ONLY" },
  { 0xC0020057, "RPC_NT_SEC_PKG_ERROR" },
  { 0xC0020058, "RPC_NT_NOT_CANCELLED" },
  { 0xC0030059, "RPC_NT_INVALID_ES_ACTION" },
  { 0xC003005A, "RPC_NT_WRONG_ES_VERSION" },
  { 0xC003005B, "RPC_NT_WRONG_STUB_VERSION" },
  { 0xC003005C, "RPC_NT_INVALID_PIPE_OBJECT" },
  { 0xC003005D, "RPC_NT_INVALID_PIPE_OPERATION" },
  { 0xC003005E, "RPC_NT_WRONG_PIPE_VERSION" },
  { 0x400200AF, "RPC_NT_SEND_INCOMPLETE" },
  { 0,          NULL }
};

#define SMB_FLAGS_DIRN 0x80

static gboolean
dissect_smb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int		offset = 0;
	struct          smb_info si;
	static const char smb_signature[4] = { 0xFF, 'S', 'M', 'B' };
	proto_tree      *smb_tree = tree, *smb_hdr_tree = NULL, *flags_tree, *flags2_tree;
	proto_item      *ti, *tf, *th;
	guint8          cmd, errcls, errcode1, flags;
	guint16         flags2, errcode, tid, pid, uid, mid;
	guint32         status;
	const u_char	*pd;
	int             SMB_offset;

	/* OK, is this an SMB message? */
	if (!tvb_bytes_exist(tvb, 0, 4))
	  return FALSE;
	if (memcmp(tvb_get_ptr(tvb, 0, 4), smb_signature, 4) != 0) {
	  /* No. */
	  return FALSE;
	}

	/* Yes. */
	si.unicode = FALSE;
    	si.ddisp = 0;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "SMB");
	if (check_col(pinfo->fd, COL_INFO))
		col_clear(pinfo->fd, COL_INFO);

	cmd = tvb_get_guint8(tvb, SMB_hdr_com_offset);
	if (check_col(pinfo->fd, COL_INFO)) {

	  col_add_fstr(pinfo->fd, COL_INFO, "%s", decode_smb_name(cmd));

	}

	if (tree) {

	  ti = proto_tree_add_item(tree, proto_smb, tvb, offset, tvb_length(tvb), FALSE);
	  smb_tree = proto_item_add_subtree(ti, ett_smb);

	  th = proto_tree_add_text(smb_tree, NullTVB, offset, 32, "SMB Header");

	  smb_hdr_tree = proto_item_add_subtree(th, ett_smb_hdr);

	  /* 0xFFSMB is actually a 1 byte msg type and 3 byte server
	   * component ... SMB is only one used
	   */

	  proto_tree_add_text(smb_hdr_tree, tvb, offset, 1, "Message Type: 0xFF");
	  proto_tree_add_text(smb_hdr_tree, tvb, offset+1, 3, "Server Component: SMB");

	}

	offset += 4;  /* Skip the marker */

	if (tree) {

	  proto_tree_add_uint(smb_hdr_tree, hf_smb_cmd, tvb, offset, 1, cmd);

	}

	offset += 1;

	/* Get flags2; we need it to know whether the error code is
	   an NT error code or a DOS error code. */

	flags2 = tvb_get_letohs(tvb, 10);

	/* Handle error code */

	if (flags2 & 0x4000) {

	    /* handle NT 32 bit error code */
	    status = tvb_get_letohl(tvb, offset); 

	    if (tree) {

		/*
		 * XXX - break the value down into severity code,
		 * customer code, facility, and error?
		 */
		proto_tree_add_uint(smb_hdr_tree, hf_smb_status,
				    tvb, offset, 4, status);

	    }

	    offset += 4;

	}
	else {
	    /* handle DOS error code & class */

	    /* Next, look at the error class, SMB_RETCLASS */

	    errcls = tvb_get_guint8(tvb, offset);

	    if (tree) {

		proto_tree_add_uint(smb_hdr_tree, hf_smb_errcls,
				    tvb, offset, 1, errcls);
	    }

	    offset += 1;

	    /* Error code, SMB_HEINFO ... */

	    errcode1 = tvb_get_guint8(tvb, offset);

	    if (tree) {

		proto_tree_add_text(smb_hdr_tree, tvb, offset, 1, "Reserved: %i", errcode1); 

	    }

	    offset += 1;

	    errcode = tvb_get_letohs(tvb, offset); 

	    if (tree) {

		/*
		 * XXX - the type of this field depends on the value of
		 * "errcls", so there isn't a single value_string array
		 * for it, so there can't be a single field for it.
		 */
		proto_tree_add_text(smb_hdr_tree, tvb, offset, 2, "Error Code: %s",
				    decode_smb_error(errcls, errcode));

	    }

	    offset += 2;
	}

	/* Now for the flags: Bit 0 = 0 means cmd, 0 = 1 means resp */

	flags = tvb_get_guint8(tvb, offset);
	si.request = !(flags&SMB_FLAGS_DIRN);

	if (check_col(pinfo->fd, COL_INFO)) {

	  col_append_fstr(pinfo->fd, COL_INFO, " %s", si.request ? "Request" : "Response");

	}

	if (tree) {

	  tf = proto_tree_add_uint(smb_hdr_tree, hf_smb_flags, tvb, offset, 1, flags);

	  flags_tree = proto_item_add_subtree(tf, ett_smb_flags);
	  proto_tree_add_text(flags_tree, tvb, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x01, 8,
						      "Lock&Read, Write&Unlock supported",
						      "Lock&Read, Write&Unlock not supported"));
	  proto_tree_add_text(flags_tree, tvb, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x02, 8,
						      "Receive buffer posted",
						      "Receive buffer not posted"));
	  proto_tree_add_text(flags_tree, tvb, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x08, 8, 
						      "Path names caseless",
						      "Path names case sensitive"));
	  proto_tree_add_text(flags_tree, tvb, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x10, 8,
						      "Pathnames canonicalized",
						      "Pathnames not canonicalized"));
	  proto_tree_add_text(flags_tree, tvb, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x20, 8,
						      "OpLocks requested/granted",
						      "OpLocks not requested/granted"));
	  proto_tree_add_text(flags_tree, tvb, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x40, 8, 
						      "Notify all",
						      "Notify open only"));

	  proto_tree_add_text(flags_tree, tvb, offset, 1, "%s",
			      decode_boolean_bitfield(flags, SMB_FLAGS_DIRN,
						      8, "Response to client/redirector", "Request to server"));

	}

	offset += 1;

	/* Now put flags2 into the tree */

	if (tree) {

	  tf = proto_tree_add_uint(smb_hdr_tree, hf_smb_flags2, tvb, offset, 2, flags2);

	  flags2_tree = proto_item_add_subtree(tf, ett_smb_flags2);
	  proto_tree_add_text(flags2_tree, tvb, offset, 2, "%s",
			      decode_boolean_bitfield(flags2, 0x0001, 16,
						      "Long file names supported",
						      "Long file names not supported"));
	  proto_tree_add_text(flags2_tree, tvb, offset, 2, "%s",
			      decode_boolean_bitfield(flags2, 0x0002, 16,
						      "Extended attributes supported",
						      "Extended attributes not supported"));
	  proto_tree_add_text(flags2_tree, tvb, offset, 1, "%s",
			      decode_boolean_bitfield(flags2, 0x0004, 16,
						      "Security signatures supported",
						      "Security signatures not supported"));
	  proto_tree_add_text(flags2_tree, tvb, offset, 2, "%s",
			      decode_boolean_bitfield(flags2, 0x0800, 16,
						      "Extended security negotiation supported",
						      "Extended security negotiation not supported"));
	  proto_tree_add_text(flags2_tree, tvb, offset, 2, "%s",
			      decode_boolean_bitfield(flags2, 0x1000, 16, 
						      "Resolve pathnames with DFS",
						      "Don't resolve pathnames with DFS"));
	  proto_tree_add_text(flags2_tree, tvb, offset, 2, "%s",
			      decode_boolean_bitfield(flags2, 0x2000, 16,
						      "Permit reads if execute-only",
						      "Don't permit reads if execute-only"));
	  proto_tree_add_text(flags2_tree, tvb, offset, 2, "%s",
			      decode_boolean_bitfield(flags2, 0x4000, 16,
						      "Error codes are NT error codes",
						      "Error codes are DOS error codes"));
	  proto_tree_add_text(flags2_tree, tvb, offset, 2, "%s",
			      decode_boolean_bitfield(flags2, 0x8000, 16, 
						      "Strings are Unicode",
						      "Strings are ASCII"));

	}

	if (flags2 & 0x8000) si.unicode = TRUE; /* Mark them as Unicode */

	offset += 2;

	if (tree) {

	  /*
	   * The document at
	   *
	   *	http://www.samba.org/samba/ftp/specs/smbpub.txt
	   *
	   * (a text version of "Microsoft Networks SMB FILE SHARING
	   * PROTOCOL, Document Version 6.0p") says that:
	   *
	   *	the first 2 bytes of these 12 bytes are, for NT Create and X,
	   *	the "High Part of PID";
	   *
	   *	the next four bytes are reserved;
	   *
	   *	the next four bytes are, for SMB-over-IPX (with no
	   *	NetBIOS involved) two bytes of Session ID and two bytes
	   *	of SequenceNumber.
	   *
	   * If we ever implement SMB-over-IPX (which I suspect goes over
	   * IPX sockets 0x0550, 0x0552, and maybe 0x0554, as per the
	   * document in question), we'd probably want to have some way
	   * to determine whether this is SMB-over-IPX or not (which could
	   * be done by adding a PT_IPXSOCKET port type, having the
	   * IPX dissector set "pinfo->srcport" and "pinfo->destport",
	   * and having the SMB dissector check for a port type of
	   * PT_IPXSOCKET and for "pinfo->match_port" being either
	   * IPX_SOCKET_NWLINK_SMB_SERVER or IPX_SOCKET_NWLINK_SMB_REDIR
	   * or, if it also uses 0x0554, IPX_SOCKET_NWLINK_SMB_MESSENGER).
	   */
	  proto_tree_add_text(smb_hdr_tree, tvb, offset, 12, "Reserved: 6 WORDS");

	}

	offset += 12;

	/* Now the TID, tree ID */

	tid = tvb_get_letohs(tvb, offset);
	si.tid = tid;

	if (tree) {

	  proto_tree_add_uint(smb_hdr_tree, hf_smb_tid, tvb, offset, 2, tid); 

	}

	offset += 2;

	/* Now the PID, Process ID */

	pid = tvb_get_letohs(tvb, offset);
	si.pid = pid;

	if (tree) {

	  proto_tree_add_uint(smb_hdr_tree, hf_smb_pid, tvb, offset, 2, pid); 

	}

	offset += 2;

	/* Now the UID, User ID */

	uid = tvb_get_letohs(tvb, offset);
	si.uid = uid;

	if (tree) {

	  proto_tree_add_uint(smb_hdr_tree, hf_smb_uid, tvb, offset, 2, uid); 

	}
	
	offset += 2;

	/* Now the MID, Multiplex ID */

	mid = tvb_get_letohs(tvb, offset);
	si.mid = mid;

	if (tree) {

	  proto_tree_add_uint(smb_hdr_tree, hf_smb_mid, tvb, offset, 2, mid); 

	}

	offset += 2;

	/*
	 * Get old-style information from the tvbuff we've been handed.
	 */
	tvb_compat(tvb, &pd, &SMB_offset);
	offset += SMB_offset;

	/* Now vector through the table to dissect them */

	(dissect[cmd])(pd, offset, pinfo->fd, tree, smb_tree, si,
		       tvb_length(tvb), SMB_offset);

	return TRUE;
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
	      FT_UINT8, BASE_HEX, VALS(smb_cmd_vals), 0x0, "", HFILL }},
	  { &hf_smb_status,
	    { "Status", "smb.status",
	      FT_UINT32, BASE_HEX, VALS(NT_errors), 0x0, "", HFILL }},
	  { &hf_smb_errcls,
	    { "Error Class", "smb.errcls",
	      FT_UINT8, BASE_HEX, VALS(errcls_types), 0x0, "", HFILL }},
	  { &hf_smb_flags,
	    { "Flags", "smb.flags",
	      FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
	  { &hf_smb_flags2,
	    { "Flags2", "smb.flags2",
	      FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
	  { &hf_smb_tid,
	    { "Network Path/Tree ID (TID)", "smb.tid",
	      FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
	  { &hf_smb_pid,
	    { "Process ID (PID)", "smb.pid",
	      FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
	  { &hf_smb_uid,
	    { "User ID (UID)", "smb.uid",
	      FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
	  { &hf_smb_mid,
	    { "Multiplex ID (MID)", "smb.mid",
	      FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
	};
	static gint *ett[] = {
		&ett_smb,
		&ett_smb_hdr,
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
		&ett_smb_openaction,
		&ett_smb_writemode,
		&ett_smb_lock_type,
		&ett_smb_ssetupandxaction,
		&ett_smb_optionsup,
	};

	proto_smb = proto_register_protocol("SMB (Server Message Block Protocol)",
	    "SMB", "smb");

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_smb, hf, array_length(hf));
	register_init_routine(&smb_init_protocol);

	register_proto_smb_browse();
	register_proto_smb_logon();
	register_proto_smb_mailslot();
	register_proto_smb_pipe();
}

void
proto_reg_handoff_smb(void)
{
	heur_dissector_add("netbios", dissect_smb, proto_smb);
}
