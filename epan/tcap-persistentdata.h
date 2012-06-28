/*
 * tcap-persistentdata.h
 * Definitions for lists and hash tables used in wireshark's tcap dissector
 * for calculation of delays in tcap-transactions
 * Copyright 2006 Florent Drouin (based on h225-persistentdata from Lars Roland)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * $Id$
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __tcapsrt_HASH__
#define __tcapsrt_HASH__

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcap.h>
/** @file
 * lists and hash tables used in wireshark's tcap dissector
 * for calculation of delays in tcap-calls
 */

#define LENGTH_OID 23
struct tcaphash_context_t {
  struct tcaphash_context_key_t * key;
  guint32 session_id;
  guint32 first_frame;
  guint32 last_frame;
  nstime_t begin_time;	/**< time of arrival of TC_BEGIN */
  nstime_t end_time;	/**< time of closing message */
  gboolean responded;	/**< true, if request has been responded */
  gboolean closed;
  gboolean upper_dissector;
  gboolean oid_present;
  gchar oid[LENGTH_OID+1];
  gboolean subdissector_present;
  dissector_handle_t subdissector_handle;
  void (* callback) (tvbuff_t *,packet_info *, proto_tree *, struct tcaphash_context_t *);
  struct tcaphash_begincall_t * begincall;
  struct tcaphash_contcall_t * contcall;
  struct tcaphash_endcall_t * endcall;
  struct tcaphash_ansicall_t * ansicall;
};

struct tcaphash_begincall_t {
  struct tcaphash_begin_info_key_t * beginkey;
  struct tcaphash_context_t * context;
  gboolean father;
  struct tcaphash_begincall_t * next_begincall;
  struct tcaphash_begincall_t * previous_begincall;
};

struct tcaphash_contcall_t {
  struct tcaphash_cont_info_key_t * contkey;
  struct tcaphash_context_t * context;
  gboolean father;
  struct tcaphash_contcall_t * next_contcall;
  struct tcaphash_contcall_t * previous_contcall;
};

struct tcaphash_endcall_t {
  struct tcaphash_end_info_key_t * endkey;
  struct tcaphash_context_t * context;
  gboolean father;
  struct tcaphash_endcall_t * next_endcall;
  struct tcaphash_endcall_t * previous_endcall;
};

struct tcaphash_ansicall_t {
  struct tcaphash_ansi_info_key_t * ansikey;
  struct tcaphash_context_t * context;
  gboolean father;
  struct tcaphash_ansicall_t * next_ansicall;
  struct tcaphash_ansicall_t * previous_ansicall;
};

/** The Key for the hash table is the TCAP origine transaction identifier
   of the TC_BEGIN containing the InitialDP */

struct tcaphash_context_key_t {
  guint32 session_id;
};

struct tcaphash_begin_info_key_t {
  guint32 hashKey;
  guint32 tid;
  guint32 opc_hash;
  guint32 dpc_hash;
};

struct tcaphash_cont_info_key_t {
  guint32 hashKey;
  guint32 src_tid;
  guint32 dst_tid;
  guint32 opc_hash;
  guint32 dpc_hash;
};

struct tcaphash_end_info_key_t {
  guint32 hashKey;
  guint32 tid;
  guint32 opc_hash;
  guint32 dpc_hash;
};

struct tcaphash_ansi_info_key_t {
  guint32 hashKey;
  guint32 tid;
  guint32 opc_hash;
  guint32 dpc_hash;
};


/** List of infos to store for the analyse */
struct tcapsrt_info_t {
  guint32 tcap_session_id;
  guint32 src_tid;
  guint32 dst_tid;
  guint8 ope;
};

/**
 * Routine called when the TAP is initialized.
 * so hash table are (re)created
 */
void tcapsrt_init_routine(void);

/**
 * Initialize the Message Info used by the main dissector
 * Data are linked to a TCAP transaction
 */
struct tcapsrt_info_t * tcapsrt_razinfo(void);

void tcapsrt_close(struct tcaphash_context_t * p_tcaphash_context,
		   packet_info * pinfo _U_);

/**
 * Service Response Time analyze
 * Called just after dissector call
 * Associate a TCAP context to a tcap session and display session related infomations
 * like the first frame, the last, the session duration,
 * and a uniq session identifier for the filtering
 *
 * For ETSI tcap, the TCAP context can be reached through three keys
 * - a key (BEGIN) identifying the session according to the tcap source identifier
 * - a key (CONT) identifying the established session (src_id and dst_id)
 * - a key (END) identifying the session according to the tcap destination identifier
 *
 * For ANSI tcap, the TCAP context is reached through a uniq key
 * - a key (ANSI) identifying the session according to the tcap identifier
*/
struct tcaphash_context_t * tcapsrt_call_matching(tvbuff_t *tvb,
						  packet_info * pinfo _U_,
						  proto_tree *tree,
						  struct tcapsrt_info_t * p_tcap_info);

WS_VAR_IMPORT gboolean gtcap_StatSRT;

#endif /* __tcapsrt_HASH__*/
