/* packet-tcap-template.c
 * Routines for  TCAP
 * Copyright 2004 - 2005, Tim Endean <endeant@hotmail.com>
 * Built from the gsm-map dissector Copyright 2004 - 2005, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * References: ETSI 300 374
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/strutil.h>
#include <epan/show_exception.h>

#include <string.h>
#include "packet-ber.h"
#include "packet-tcap.h"
#include "packet-mtp3.h"


#define PNAME  "Transaction Capabilities Application Part"
#define PSNAME "TCAP"
#define PFNAME "tcap"

/* Initialize the protocol and registered fields */
static int proto_tcap = -1;
static int hf_tcap_tag = -1;
static int hf_tcap_length = -1;
static int hf_tcap_data = -1;
static int hf_tcap_tid = -1;

int hf_tcapsrt_SessionId=-1;
int hf_tcapsrt_Duplicate=-1;
int hf_tcapsrt_BeginSession=-1;
int hf_tcapsrt_EndSession=-1;
int hf_tcapsrt_SessionTime=-1;

#include "packet-tcap-hf.c"

/* Initialize the subtree pointers */
static gint ett_tcap = -1;
static gint ett_param = -1;

static gint ett_otid = -1;
static gint ett_dtid = -1;
gint ett_tcap_stat = -1;

static struct tcapsrt_info_t * gp_tcapsrt_info;
static gboolean tcap_subdissector_used=FALSE;
static dissector_handle_t requested_subdissector_handle = NULL;

static struct tcaphash_context_t * gp_tcap_context=NULL;

#include "packet-tcap-ett.c"

/* When several Tcap components are received in a single TCAP message,
   we have to use several buffers for the stored parameters
   because else this data are erased during TAP dissector call */
#define MAX_TCAP_INSTANCE 10
static int tcapsrt_global_current=0;
static struct tcapsrt_info_t tcapsrt_global_info[MAX_TCAP_INSTANCE];

#define MAX_SSN 254
static range_t *global_ssn_range;
static range_t *ssn_range;
struct tcap_private_t tcap_private;

gboolean gtcap_HandleSRT=FALSE;
/* These two timeout (in second) are used when some message are lost,
   or when the same TCAP transcation identifier is reused */
guint gtcap_RepetitionTimeout = 10;
guint gtcap_LostTimeout = 30;
gboolean gtcap_PersistentSRT=FALSE;
gboolean gtcap_DisplaySRT=FALSE;
gboolean gtcap_StatSRT=FALSE;

/* Global hash tables*/
static GHashTable *tcaphash_context = NULL;
static GHashTable *tcaphash_begin = NULL;
static GHashTable *tcaphash_cont = NULL;
static GHashTable *tcaphash_end = NULL;
static GHashTable *tcaphash_ansi = NULL;

static guint32 tcapsrt_global_SessionId=1;

static dissector_handle_t	tcap_handle = NULL;
static dissector_table_t ber_oid_dissector_table;
static const char * cur_oid;
static const char * tcapext_oid;
static proto_tree * tcap_top_tree=NULL;
static proto_tree * tcap_stat_tree=NULL;

static dissector_handle_t data_handle;
static dissector_handle_t ansi_tcap_handle;

static void raz_tcap_private(struct tcap_private_t * p_tcap_private);
static int dissect_tcap_param(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_tcap_ITU_ComponentPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_);

static GHashTable* ansi_sub_dissectors = NULL;
static GHashTable* itu_sub_dissectors = NULL;

static void dissect_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree);

extern void add_ansi_tcap_subdissector(guint32 ssn, dissector_handle_t dissector) {
    g_hash_table_insert(ansi_sub_dissectors,GUINT_TO_POINTER(ssn),dissector);
    dissector_add_uint("sccp.ssn",ssn,tcap_handle);
}

extern void add_itu_tcap_subdissector(guint32 ssn, dissector_handle_t dissector) {
    g_hash_table_insert(itu_sub_dissectors,GUINT_TO_POINTER(ssn),dissector);
    dissector_add_uint("sccp.ssn",ssn,tcap_handle);
}

extern void delete_ansi_tcap_subdissector(guint32 ssn, dissector_handle_t dissector _U_) {
    g_hash_table_remove(ansi_sub_dissectors,GUINT_TO_POINTER(ssn));
    if (!get_itu_tcap_subdissector(ssn))
      dissector_delete_uint("sccp.ssn",ssn,tcap_handle);
}
extern void delete_itu_tcap_subdissector(guint32 ssn, dissector_handle_t dissector _U_) {
    g_hash_table_remove(itu_sub_dissectors,GUINT_TO_POINTER(ssn));
    if (!get_ansi_tcap_subdissector(ssn))
      dissector_delete_uint("sccp.ssn", ssn,tcap_handle);
}

dissector_handle_t get_ansi_tcap_subdissector(guint32 ssn) {
    return (dissector_handle_t)g_hash_table_lookup(ansi_sub_dissectors,GUINT_TO_POINTER(ssn));
}

dissector_handle_t get_itu_tcap_subdissector(guint32 ssn) {
    return (dissector_handle_t)g_hash_table_lookup(itu_sub_dissectors,GUINT_TO_POINTER(ssn));
}

#include "packet-tcap-fn.c"

/*
 * DEBUG functions
 */
#undef MEM_TCAPSRT
/* #define MEM_TCAPSRT */

#undef DEBUG_TCAPSRT
/* #define DEBUG_TCAPSRT */

#ifdef DEBUG_TCAPSRT
#include <stdio.h>
#include <stdarg.h>
static guint debug_level = 99;

static void
dbg(guint level, char* fmt, ...)
{
  va_list ap;

  if (level > debug_level) return;
  va_start(ap,fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}
#endif

static gint
tcaphash_context_equal(gconstpointer k1, gconstpointer k2)
{
  const struct tcaphash_context_key_t *key1 = (const struct tcaphash_context_key_t *) k1;
  const struct tcaphash_context_key_t *key2 = (const struct tcaphash_context_key_t *) k2;

  return (key1->session_id == key2->session_id);
}

/* calculate a hash key */
static guint
tcaphash_context_calchash(gconstpointer k)
{
  const struct tcaphash_context_key_t *key = (const struct tcaphash_context_key_t *) k;
  return key->session_id;
}


static gint
tcaphash_begin_equal(gconstpointer k1, gconstpointer k2)
{
  const struct tcaphash_begin_info_key_t *key1 = (const struct tcaphash_begin_info_key_t *) k1;
  const struct tcaphash_begin_info_key_t *key2 = (const struct tcaphash_begin_info_key_t *) k2;

  if (key1->hashKey == key2->hashKey) {

    if ( ( (key1->opc_hash == key2->opc_hash) &&
	   (key1->dpc_hash == key2->dpc_hash) &&
	   (key1->tid == key2->tid) )
	 ||
	 ( (key1->opc_hash == key2->dpc_hash) &&
	   (key1->dpc_hash == key2->opc_hash) &&
	   (key1->tid == key2->tid) )
	 )
      return TRUE;
  }
  return FALSE;
}

/* calculate a hash key */
static guint
tcaphash_begin_calchash(gconstpointer k)
{
  const struct tcaphash_begin_info_key_t *key = (const struct tcaphash_begin_info_key_t *) k;
  guint hashkey;
  /* hashkey = key->opc_hash<<16 + key->dpc_hash<<8 + key->src_tid; */
  hashkey = key->tid;
  return hashkey;
}

static gint
tcaphash_cont_equal(gconstpointer k1, gconstpointer k2)
{
  const struct tcaphash_cont_info_key_t *key1 = (const struct tcaphash_cont_info_key_t *) k1;
  const struct tcaphash_cont_info_key_t *key2 = (const struct tcaphash_cont_info_key_t *) k2;

  if (key1->hashKey == key2->hashKey) {

    if ( (key1->opc_hash == key2->opc_hash) &&
	 (key1->dpc_hash == key2->dpc_hash) &&
	 (key1->src_tid == key2->src_tid) &&
	 (key1->dst_tid == key2->dst_tid) ) {
      return TRUE;
    }
    else if ( (key1->opc_hash == key2->dpc_hash) &&
	      (key1->dpc_hash == key2->opc_hash) &&
	      (key1->src_tid == key2->dst_tid) &&
	      (key1->dst_tid == key2->src_tid) ) {
      return TRUE;
    }
  }
  return FALSE;
}

/* calculate a hash key */
static guint
tcaphash_cont_calchash(gconstpointer k)
{
  const struct tcaphash_cont_info_key_t *key = (const struct tcaphash_cont_info_key_t *) k;
  guint hashkey;
  hashkey = key->src_tid + key->dst_tid;
  return hashkey;
}


static gint
tcaphash_end_equal(gconstpointer k1, gconstpointer k2)
{
  const struct tcaphash_end_info_key_t *key1 = (const struct tcaphash_end_info_key_t *) k1;
  const struct tcaphash_end_info_key_t *key2 = (const struct tcaphash_end_info_key_t *) k2;

  if (key1->hashKey == key2->hashKey) {
    if ( ( (key1->opc_hash == key2->opc_hash) &&
	   (key1->dpc_hash == key2->dpc_hash) &&
	   (key1->tid == key2->tid) )
	 ||
	 ( (key1->opc_hash == key2->dpc_hash) &&
	   (key1->dpc_hash == key2->opc_hash) &&
	   (key1->tid == key2->tid) ) )
      return TRUE;
  }
  return FALSE;
}

/* calculate a hash key */
static guint
tcaphash_end_calchash(gconstpointer k)
{
  const struct tcaphash_end_info_key_t *key = (const struct tcaphash_end_info_key_t *) k;
  guint hashkey;
  hashkey = key->tid;
  return hashkey;
}

static gint
tcaphash_ansi_equal(gconstpointer k1, gconstpointer k2)
{
  const struct tcaphash_ansi_info_key_t *key1 = (const struct tcaphash_ansi_info_key_t *) k1;
  const struct tcaphash_ansi_info_key_t *key2 = (const struct tcaphash_ansi_info_key_t *) k2;

  if (key1->hashKey == key2->hashKey) {

    if ( ( (key1->opc_hash == key2->opc_hash) &&
	   (key1->dpc_hash == key2->dpc_hash) &&
	   (key1->tid == key2->tid) )
	 ||
	 ( (key1->opc_hash == key2->dpc_hash) &&
	   (key1->dpc_hash == key2->opc_hash) &&
	   (key1->tid == key2->tid) )
	 )
      return TRUE;
  }
  return FALSE;
}

/* calculate a hash key */
static guint
tcaphash_ansi_calchash(gconstpointer k)
{
  const struct tcaphash_ansi_info_key_t *key = (const struct tcaphash_ansi_info_key_t *) k;
  guint hashkey;
  /* hashkey = key->opc_hash<<16 + key->dpc_hash<<8 + key->src_tid; */
  hashkey = key->tid;
  return hashkey;
}

/*
 * Update a record with the data of the Request
 */
static void
update_tcaphash_begincall(struct tcaphash_begincall_t *p_tcaphash_begincall,
			  packet_info *pinfo)
{
  p_tcaphash_begincall->context->first_frame = pinfo->fd->num;
  p_tcaphash_begincall->context->last_frame = 0;
  p_tcaphash_begincall->context->responded = FALSE;
  p_tcaphash_begincall->context->begin_time = pinfo->fd->abs_ts;
}

/*
 * Append a new dialogue, using the same Key, to the chained list
 * The time is stored too
 */
static struct tcaphash_begincall_t *
append_tcaphash_begincall(struct tcaphash_begincall_t *prev_begincall,
			  struct tcaphash_context_t *p_tcaphash_context,
			  packet_info *pinfo)
{
  struct tcaphash_begincall_t *p_new_tcaphash_begincall = NULL;

  /* Append the transaction to the list, when the same key is found
     This should append when the tcap-transaction Id is reused  */

#ifdef MEM_TCAPSRT
  p_new_tcaphash_begincall = (struct tcaphash_begincall_t *)g_malloc0(sizeof(struct tcaphash_begincall_t));
#else
  p_new_tcaphash_begincall = wmem_new0(wmem_file_scope(), struct tcaphash_begincall_t);
#endif
  p_new_tcaphash_begincall->context=p_tcaphash_context;
  p_tcaphash_context->begincall=p_new_tcaphash_begincall;
  p_new_tcaphash_begincall->beginkey=prev_begincall->beginkey;
  p_new_tcaphash_begincall->context->first_frame = pinfo->fd->num;
  p_new_tcaphash_begincall->next_begincall=NULL;
  p_new_tcaphash_begincall->previous_begincall=prev_begincall;
  p_new_tcaphash_begincall->father=FALSE;

#ifdef DEBUG_TCAPSRT
  dbg(10,"+B%d ", p_new_tcaphash_begincall->context->session_id);
#endif
  /* Insert in the chained list */
  prev_begincall->next_begincall = p_new_tcaphash_begincall;
  if (prev_begincall->context->last_frame == 0) {
#ifdef DEBUG_TCAPSRT
    dbg(10,"last ");
#endif
    prev_begincall->context->last_frame = pinfo->fd->num-1;
  }
  return p_new_tcaphash_begincall;
}

/*
 * Update a record with the data of the Request
 */
static void
update_tcaphash_ansicall(struct tcaphash_ansicall_t *p_tcaphash_ansicall,
			  packet_info *pinfo)
{
  p_tcaphash_ansicall->context->first_frame = pinfo->fd->num;
  p_tcaphash_ansicall->context->last_frame = 0;
  p_tcaphash_ansicall->context->responded = FALSE;
  p_tcaphash_ansicall->context->begin_time = pinfo->fd->abs_ts;
}

/*
 * Append a new dialogue, using the same Key, to the chained list
 * The time is stored too
 */
static struct tcaphash_ansicall_t *
append_tcaphash_ansicall(struct tcaphash_ansicall_t *prev_ansicall,
			  struct tcaphash_context_t *p_tcaphash_context,
			  packet_info *pinfo)
{
  struct tcaphash_ansicall_t *p_new_tcaphash_ansicall = NULL;

  /* Append the transaction to the list, when the same key is found
     This should append when the tcap-transaction Id is reused  */

#ifdef MEM_TCAPSRT
  p_new_tcaphash_ansicall = (struct tcaphash_ansicall_t *)g_malloc0(sizeof(struct tcaphash_ansicall_t));
#else
  p_new_tcaphash_ansicall = wmem_new0(wmem_file_scope(), struct tcaphash_ansicall_t);
#endif
  p_new_tcaphash_ansicall->context=p_tcaphash_context;
  p_tcaphash_context->ansicall=p_new_tcaphash_ansicall;
  p_new_tcaphash_ansicall->ansikey=prev_ansicall->ansikey;
  p_new_tcaphash_ansicall->context->first_frame = pinfo->fd->num;
  p_new_tcaphash_ansicall->next_ansicall=NULL;
  p_new_tcaphash_ansicall->previous_ansicall=prev_ansicall;
  p_new_tcaphash_ansicall->father=FALSE;

#ifdef DEBUG_TCAPSRT
  dbg(10,"+A%d ", p_new_tcaphash_ansicall->context->session_id);
#endif
  /* Insert in the chained list */
  prev_ansicall->next_ansicall = p_new_tcaphash_ansicall;
  if (prev_ansicall->context->last_frame == 0) {
#ifdef DEBUG_TCAPSRT
    dbg(10,"last ");
#endif
    prev_ansicall->context->last_frame = pinfo->fd->num-1;
  }
  return p_new_tcaphash_ansicall;
}


static struct tcaphash_contcall_t *
append_tcaphash_contcall(struct tcaphash_contcall_t *prev_contcall,
			 struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_contcall_t *p_new_tcaphash_contcall = NULL;

  /* Append the transaction to the list, when the same key is found
     This should append when the tcap-transaction Id is reused  */

#ifdef MEM_TCAPSRT
  p_new_tcaphash_contcall = (struct tcaphash_contcall_t *)g_malloc0(sizeof(struct tcaphash_contcall_t));
#else
  p_new_tcaphash_contcall = wmem_new0(wmem_file_scope(), struct tcaphash_contcall_t);
#endif
  p_new_tcaphash_contcall->context=p_tcaphash_context;
  p_tcaphash_context->contcall=p_new_tcaphash_contcall;
  p_new_tcaphash_contcall->contkey=prev_contcall->contkey;
  p_new_tcaphash_contcall->next_contcall=NULL;
  p_new_tcaphash_contcall->previous_contcall=prev_contcall;
  p_new_tcaphash_contcall->father=FALSE;

#ifdef DEBUG_TCAPSRT
  dbg(10,"+C%d ", p_new_tcaphash_contcall->context->session_id);
#endif
  /* Insert in the chained list */
  prev_contcall->next_contcall = p_new_tcaphash_contcall;
  return p_new_tcaphash_contcall;
}


static struct tcaphash_endcall_t *
append_tcaphash_endcall(struct tcaphash_endcall_t *prev_endcall,
			struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_endcall_t *p_new_tcaphash_endcall = NULL;

  /* Append the transaction to the list, when the same key is found
     This should append when the tcap-transaction Id is reused  */

#ifdef MEM_TCAPSRT
  p_new_tcaphash_endcall = (struct tcaphas_endcall_t *)g_malloc0(sizeof(struct tcaphash_endcall_t));
#else
  p_new_tcaphash_endcall = wmem_new0(wmem_file_scope(), struct tcaphash_endcall_t);
#endif
  p_new_tcaphash_endcall->context=p_tcaphash_context;
  p_tcaphash_context->endcall=p_new_tcaphash_endcall;
  p_new_tcaphash_endcall->endkey=prev_endcall->endkey;
  p_new_tcaphash_endcall->next_endcall=NULL;
  p_new_tcaphash_endcall->previous_endcall=prev_endcall;
  p_new_tcaphash_endcall->father=FALSE;

#ifdef DEBUG_TCAPSRT
  dbg(10,"+E%d ", p_new_tcaphash_endcall->context->session_id);
#endif
  /* Insert in the chained list */
  prev_endcall->next_endcall = p_new_tcaphash_endcall;
  return p_new_tcaphash_endcall;
}


/*
 * Find the dialog by Key and Time
 */
static struct tcaphash_begincall_t *
find_tcaphash_begin(struct tcaphash_begin_info_key_t *p_tcaphash_begin_key,
		    packet_info *pinfo, gboolean isBegin)
{
  struct tcaphash_begincall_t *p_tcaphash_begincall = NULL;
  p_tcaphash_begincall = (struct tcaphash_begincall_t *)g_hash_table_lookup(tcaphash_begin, p_tcaphash_begin_key);

  if(p_tcaphash_begincall) {
    do {
      if ( p_tcaphash_begincall->context ) {
        if ( ( isBegin &&
               pinfo->fd->num == p_tcaphash_begincall->context->first_frame )
             ||
             ( !isBegin &&
               pinfo->fd->num >= p_tcaphash_begincall->context->first_frame &&
               ( p_tcaphash_begincall->context->last_frame?pinfo->fd->num <= p_tcaphash_begincall->context->last_frame:1 )
               )
             ) {
          /* We have a dialogue, with this key, opened before this request */
#ifdef DEBUG_TCAPSRT
          dbg(10,"B%d ", p_tcaphash_begincall->context->session_id);
#endif
          return p_tcaphash_begincall;
        }
#ifdef DEBUG_TCAPSRT
      dbg(60,"[B%d] ", p_tcaphash_begincall->context->session_id);
#endif
      }
      /* Break when list end is reached */
      if(p_tcaphash_begincall->next_begincall == NULL) {
#ifdef DEBUG_TCAPSRT
        dbg(23,"End of Blist ");
#endif
        break;
      }
      p_tcaphash_begincall = p_tcaphash_begincall->next_begincall;
    } while (p_tcaphash_begincall != NULL) ;
  } else {
#ifdef DEBUG_TCAPSRT
    dbg(23,"Not in Bhash ");
#endif
  }
  return NULL;
}



static struct tcaphash_contcall_t *
find_tcaphash_cont(struct tcaphash_cont_info_key_t *p_tcaphash_cont_key,
		   packet_info *pinfo)
{
  struct tcaphash_contcall_t *p_tcaphash_contcall = NULL;
  p_tcaphash_contcall = (struct tcaphash_contcall_t *)g_hash_table_lookup(tcaphash_cont, p_tcaphash_cont_key);

  if(p_tcaphash_contcall) {
    do {
      if ( p_tcaphash_contcall->context ) {
	if (pinfo->fd->num >= p_tcaphash_contcall->context->first_frame &&
	    (p_tcaphash_contcall->context->last_frame?pinfo->fd->num <= p_tcaphash_contcall->context->last_frame:1) ) {
	  /* We have a dialogue, with this key, opened before this request */
#ifdef DEBUG_TCAPSRT
	  dbg(10,"C%d ", p_tcaphash_contcall->context->session_id);
#endif
	  return p_tcaphash_contcall;
	}
#ifdef DEBUG_TCAPSRT
	dbg(60,"[C%d] ", p_tcaphash_contcall->context->session_id);
#endif
      }
      /* Break when list end is reached */
      if(p_tcaphash_contcall->next_contcall == NULL) {
#ifdef DEBUG_TCAPSRT
	dbg(23,"End of Clist ");
#endif
	break;
      }
      p_tcaphash_contcall = p_tcaphash_contcall->next_contcall;
    } while (p_tcaphash_contcall != NULL) ;
  } else {
#ifdef DEBUG_TCAPSRT
    dbg(23,"Not in Chash ");
#endif
  }
  return NULL;
}

static struct tcaphash_endcall_t *
find_tcaphash_end(struct tcaphash_end_info_key_t *p_tcaphash_end_key,
		  packet_info *pinfo, gboolean isEnd)
{
  struct tcaphash_endcall_t *p_tcaphash_endcall = NULL;
  p_tcaphash_endcall = (struct tcaphash_endcall_t *)g_hash_table_lookup(tcaphash_end, p_tcaphash_end_key);

  if(p_tcaphash_endcall) {
    do {
      if ( p_tcaphash_endcall->context ) {
	if ( ( isEnd &&
	       (p_tcaphash_endcall->context->last_frame?pinfo->fd->num == p_tcaphash_endcall->context->last_frame:1)
	       )
	     ||
	     ( !isEnd &&
	       pinfo->fd->num >= p_tcaphash_endcall->context->first_frame &&
	       (p_tcaphash_endcall->context->last_frame?pinfo->fd->num <= p_tcaphash_endcall->context->last_frame:1)
	       )
	     ) {
	  /* We have a dialogue, with this key, opened before this request */
#ifdef DEBUG_TCAPSRT
	  dbg(10,"E%d ", p_tcaphash_endcall->context->session_id);
#endif
	  return p_tcaphash_endcall;
	}
#ifdef DEBUG_TCAPSRT
	  dbg(60,"[E%d] ", p_tcaphash_endcall->context->session_id);
#endif
      }
      /* Break when list end is reached */
      if(p_tcaphash_endcall->next_endcall == NULL) {
#ifdef DEBUG_TCAPSRT
	dbg(23,"End of Elist ");
#endif
	break;
      }
      p_tcaphash_endcall = p_tcaphash_endcall->next_endcall;
    } while (p_tcaphash_endcall != NULL) ;
  } else {
#ifdef DEBUG_TCAPSRT
    dbg(23,"Not in Ehash ");
#endif
  }
  return NULL;
}

/*
 * New record to create, to identify a new transaction
 */
static struct tcaphash_context_t *
new_tcaphash_context(struct tcaphash_context_key_t *p_tcaphash_context_key,
		     packet_info *pinfo)
{
  struct tcaphash_context_key_t *p_new_tcaphash_context_key;
  struct tcaphash_context_t *p_new_tcaphash_context = NULL;

  /* Register the transaction in the hash table
     with the tcap transaction Id as Main Key
     Once created, this entry will be updated later */

#ifdef MEM_TCAPSRT
  p_new_tcaphash_context_key = (struct tcaphash_context_key_t *)g_malloc(sizeof(struct tcaphash_context_key_t));
#else
  p_new_tcaphash_context_key = wmem_new(wmem_file_scope(), struct tcaphash_context_key_t);
#endif
  p_new_tcaphash_context_key->session_id = p_tcaphash_context_key->session_id;

#ifdef MEM_TCAPSRT
  p_new_tcaphash_context = (struct tcaphash_context_t *)g_malloc0(sizeof(struct tcaphash_context_t));
#else
  p_new_tcaphash_context = wmem_new0(wmem_file_scope(), struct tcaphash_context_t);
#endif
  p_new_tcaphash_context->key = p_new_tcaphash_context_key;
  p_new_tcaphash_context->session_id = p_tcaphash_context_key->session_id;
  p_new_tcaphash_context->first_frame = pinfo->fd->num;
#ifdef DEBUG_TCAPSRT
  dbg(10,"S%d ", p_new_tcaphash_context->session_id);
#endif
  /* store it */
  g_hash_table_insert(tcaphash_context, p_new_tcaphash_context_key, p_new_tcaphash_context);
  return p_new_tcaphash_context;
}

/*
 * New record to create, to identify a new transaction
 */
static struct tcaphash_begincall_t *
new_tcaphash_begin(struct tcaphash_begin_info_key_t *p_tcaphash_begin_key,
		   struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_begin_info_key_t *p_new_tcaphash_begin_key;
  struct tcaphash_begincall_t *p_new_tcaphash_begincall = NULL;

  /* Register the transaction in the hash table
     with the tcap transaction Id as Main Key
     Once created, this entry will be updated later */

#ifdef MEM_TCAPSRT
  p_new_tcaphash_begin_key = (struct tcaphash_begin_info_key_t *)g_malloc(sizeof(struct tcaphash_begin_info_key_t));
#else
  p_new_tcaphash_begin_key = wmem_new(wmem_file_scope(), struct tcaphash_begin_info_key_t);
#endif
  p_new_tcaphash_begin_key->hashKey = p_tcaphash_begin_key->hashKey;
  p_new_tcaphash_begin_key->tid = p_tcaphash_begin_key->tid;
  p_new_tcaphash_begin_key->opc_hash = p_tcaphash_begin_key->opc_hash;
  p_new_tcaphash_begin_key->dpc_hash = p_tcaphash_begin_key->dpc_hash;

#ifdef MEM_TCAPSRT
  p_new_tcaphash_begincall = (struct tcaphash_begincall_t *)g_malloc0(sizeof(struct tcaphash_begincall_t));
#else
 p_new_tcaphash_begincall = wmem_new0(wmem_file_scope(), struct tcaphash_begincall_t);
#endif
  p_new_tcaphash_begincall->beginkey=p_new_tcaphash_begin_key;
  p_new_tcaphash_begincall->context=p_tcaphash_context;
  p_tcaphash_context->begincall=p_new_tcaphash_begincall;
  p_new_tcaphash_begincall->father=TRUE;
  p_new_tcaphash_begincall->next_begincall=NULL;
  p_new_tcaphash_begincall->previous_begincall=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(10,"B%d ", p_new_tcaphash_begincall->context->session_id);
#endif
  /* store it */
  g_hash_table_insert(tcaphash_begin, p_new_tcaphash_begin_key, p_new_tcaphash_begincall);
  return p_new_tcaphash_begincall;
}



/*
 * New record to create, to identify a new transaction
 */
static struct tcaphash_contcall_t *
new_tcaphash_cont(struct tcaphash_cont_info_key_t *p_tcaphash_cont_key,
		  struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_cont_info_key_t *p_new_tcaphash_cont_key;
  struct tcaphash_contcall_t *p_new_tcaphash_contcall = NULL;

  /* Register the transaction in the hash table
     with the tcap transaction Id as Main Key
     Once created, this entry will be updated later */

#ifdef MEM_TCAPSRT
  p_new_tcaphash_cont_key = (struct tcaphash_cont_info_key_t *)g_malloc(sizeof(struct tcaphash_cont_info_key_t));
#else
  p_new_tcaphash_cont_key = wmem_new(wmem_file_scope(), struct tcaphash_cont_info_key_t);
#endif
  p_new_tcaphash_cont_key->hashKey = p_tcaphash_cont_key->hashKey;
  p_new_tcaphash_cont_key->src_tid = p_tcaphash_cont_key->src_tid;
  p_new_tcaphash_cont_key->dst_tid = p_tcaphash_cont_key->dst_tid;
  p_new_tcaphash_cont_key->opc_hash = p_tcaphash_cont_key->opc_hash;
  p_new_tcaphash_cont_key->dpc_hash = p_tcaphash_cont_key->dpc_hash;

#ifdef MEM_TCAPSRT
  p_new_tcaphash_contcall = (struct tcaphash_contcall_t *)g_malloc0(sizeof(struct tcaphash_contcall_t));
#else
  p_new_tcaphash_contcall = wmem_new0(wmem_file_scope(), struct tcaphash_contcall_t);
#endif
  p_new_tcaphash_contcall->contkey=p_new_tcaphash_cont_key;
  p_new_tcaphash_contcall->context=p_tcaphash_context;
  p_tcaphash_context->contcall=p_new_tcaphash_contcall;
  p_new_tcaphash_contcall->father=TRUE;
  p_new_tcaphash_contcall->next_contcall=NULL;
  p_new_tcaphash_contcall->previous_contcall=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(10,"C%d ", p_new_tcaphash_contcall->context->session_id);
#endif
  /* store it */
  g_hash_table_insert(tcaphash_cont, p_new_tcaphash_cont_key, p_new_tcaphash_contcall);
  return p_new_tcaphash_contcall;
}


/*
 * New record to create, to identify a new transaction
 */
static struct tcaphash_endcall_t *
new_tcaphash_end(struct tcaphash_end_info_key_t *p_tcaphash_end_key,
		 struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_end_info_key_t *p_new_tcaphash_end_key;
  struct tcaphash_endcall_t *p_new_tcaphash_endcall = NULL;

  /* Register the transaction in the hash table
     with the tcap transaction Id as Main Key
     Once created, this entry will be updated later */

#ifdef MEM_TCAPSRT
  p_new_tcaphash_end_key = (struct tcaphash_end_info_key_t *)g_malloc(sizeof(struct tcaphash_end_info_key_t));
#else
  p_new_tcaphash_end_key = wmem_new(wmem_file_scope(), struct tcaphash_end_info_key_t);
#endif
  p_new_tcaphash_end_key->hashKey = p_tcaphash_end_key->hashKey;
  p_new_tcaphash_end_key->tid = p_tcaphash_end_key->tid;
  p_new_tcaphash_end_key->opc_hash = p_tcaphash_end_key->opc_hash;
  p_new_tcaphash_end_key->dpc_hash = p_tcaphash_end_key->dpc_hash;

#ifdef MEM_TCAPSRT
  p_new_tcaphash_endcall = (struct tcaphash_endcall_t *)g_malloc0(sizeof(struct tcaphash_endcall_t));
#else
  p_new_tcaphash_endcall = wmem_new0(wmem_file_scope(), struct tcaphash_endcall_t);
#endif
  p_new_tcaphash_endcall->endkey=p_new_tcaphash_end_key;
  p_new_tcaphash_endcall->context=p_tcaphash_context;
  p_tcaphash_context->endcall=p_new_tcaphash_endcall;
  p_new_tcaphash_endcall->father=TRUE;
  p_new_tcaphash_endcall->next_endcall=NULL;
  p_new_tcaphash_endcall->previous_endcall=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(10,"E%d ", p_new_tcaphash_endcall->context->session_id);
#endif
  /* store it */
  g_hash_table_insert(tcaphash_end, p_new_tcaphash_end_key, p_new_tcaphash_endcall);
  return p_new_tcaphash_endcall;
}
/*
 * New record to create, to identify a new transaction
 */
static struct tcaphash_ansicall_t *
new_tcaphash_ansi(struct tcaphash_ansi_info_key_t *p_tcaphash_ansi_key,
		   struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_ansi_info_key_t *p_new_tcaphash_ansi_key;
  struct tcaphash_ansicall_t *p_new_tcaphash_ansicall = NULL;

  /* Register the transaction in the hash table
     with the tcap transaction Id as Main Key
     Once created, this entry will be updated later */

#ifdef MEM_TCAPSRT
  p_new_tcaphash_ansi_key = (struct tcaphash_ansi_info_key_t *)g_malloc(sizeof(struct tcaphash_ansi_info_key_t));
#else
  p_new_tcaphash_ansi_key = wmem_new(wmem_file_scope(), struct tcaphash_ansi_info_key_t);
#endif
  p_new_tcaphash_ansi_key->hashKey = p_tcaphash_ansi_key->hashKey;
  p_new_tcaphash_ansi_key->tid = p_tcaphash_ansi_key->tid;
  p_new_tcaphash_ansi_key->opc_hash = p_tcaphash_ansi_key->opc_hash;
  p_new_tcaphash_ansi_key->dpc_hash = p_tcaphash_ansi_key->dpc_hash;

#ifdef MEM_TCAPSRT
  p_new_tcaphash_ansicall = (struct tcaphash_ansicall_t *)g_malloc0(sizeof(struct tcaphash_ansicall_t));
#else
  p_new_tcaphash_ansicall = wmem_new0(wmem_file_scope(), struct tcaphash_ansicall_t);
#endif
  p_new_tcaphash_ansicall->ansikey=p_new_tcaphash_ansi_key;
  p_new_tcaphash_ansicall->context=p_tcaphash_context;
  p_tcaphash_context->ansicall=p_new_tcaphash_ansicall;
  p_new_tcaphash_ansicall->father=TRUE;
  p_new_tcaphash_ansicall->next_ansicall=NULL;
  p_new_tcaphash_ansicall->previous_ansicall=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(10,"A%d ", p_new_tcaphash_ansicall->context->session_id);
#endif
  /* store it */
  g_hash_table_insert(tcaphash_ansi, p_new_tcaphash_ansi_key, p_new_tcaphash_ansicall);
  return p_new_tcaphash_ansicall;
}

static struct tcaphash_contcall_t *
create_tcaphash_cont(struct tcaphash_cont_info_key_t *p_tcaphash_cont_key,
		     struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_contcall_t *p_tcaphash_contcall1 = NULL;
  struct tcaphash_contcall_t *p_tcaphash_contcall = NULL;

  p_tcaphash_contcall1 = (struct tcaphash_contcall_t *)
    g_hash_table_lookup(tcaphash_cont, p_tcaphash_cont_key);

  if (p_tcaphash_contcall1) {
    /* Walk through list of transaction with identical keys */
    /* go the the end to insert new record */
    do {
      if (!p_tcaphash_contcall1->next_contcall) {
	p_tcaphash_contcall=append_tcaphash_contcall(p_tcaphash_contcall1,
						     p_tcaphash_context);
	break;
      }
      p_tcaphash_contcall1 = p_tcaphash_contcall1->next_contcall;
    } while (p_tcaphash_contcall1 != NULL );
  } else {
    p_tcaphash_contcall = new_tcaphash_cont(p_tcaphash_cont_key,
					    p_tcaphash_context);
  }
  return p_tcaphash_contcall;
}


static struct tcaphash_endcall_t *
create_tcaphash_end(struct tcaphash_end_info_key_t *p_tcaphash_end_key,
		    struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_endcall_t *p_tcaphash_endcall1 = NULL;
  struct tcaphash_endcall_t *p_tcaphash_endcall = NULL;

  p_tcaphash_endcall1 = (struct tcaphash_endcall_t *)
    g_hash_table_lookup(tcaphash_end, p_tcaphash_end_key);

  if (p_tcaphash_endcall1) {
    /* Walk through list of transaction with identical keys */
    /* go the the end to insert new record */
    do {
      if (!p_tcaphash_endcall1->next_endcall) {
	p_tcaphash_endcall=append_tcaphash_endcall(p_tcaphash_endcall1,
						   p_tcaphash_context);
	break;
      }
      p_tcaphash_endcall1 = p_tcaphash_endcall1->next_endcall;
    } while (p_tcaphash_endcall1 != NULL );
  } else {
    p_tcaphash_endcall = new_tcaphash_end(p_tcaphash_end_key,
					  p_tcaphash_context);
  }
  return p_tcaphash_endcall;
}


/*
 * Routine called when the TAP is initialized.
 * so hash table are (re)created
 */
void
tcapsrt_init_routine(void)
{

  /* free hash-table for SRT */
  if (tcaphash_context != NULL) {
#ifdef DEBUG_TCAPSRT
    dbg(16,"Destroy hash_context \n");
#endif
    g_hash_table_destroy(tcaphash_context);
  }

  if (tcaphash_begin != NULL) {
#ifdef DEBUG_TCAPSRT
    dbg(16,"Destroy hash_begin \n");
#endif
    g_hash_table_destroy(tcaphash_begin);
  }

  if (tcaphash_cont != NULL) {
#ifdef DEBUG_TCAPSRT
    dbg(16,"Destroy hash_cont \n");
#endif
    g_hash_table_destroy(tcaphash_cont);
  }

  if (tcaphash_end != NULL) {
#ifdef DEBUG_TCAPSRT
    dbg(16,"Destroy hash_end \n");
#endif
    g_hash_table_destroy(tcaphash_end);
  }

  if (tcaphash_ansi != NULL) {
#ifdef DEBUG_TCAPSRT
    dbg(16,"Destroy hash_ansi \n");
#endif
    g_hash_table_destroy(tcaphash_ansi);
  }

#ifdef DEBUG_TCAPSRT
  dbg(16,"Create hash \n");
#endif
  /* create new hash-tables for SRT */
  tcaphash_context = g_hash_table_new(tcaphash_context_calchash, tcaphash_context_equal);
  tcaphash_begin   = g_hash_table_new(tcaphash_begin_calchash, tcaphash_begin_equal);
  tcaphash_cont    = g_hash_table_new(tcaphash_cont_calchash, tcaphash_cont_equal);
  tcaphash_end     = g_hash_table_new(tcaphash_end_calchash, tcaphash_end_equal);
  tcaphash_ansi    = g_hash_table_new(tcaphash_ansi_calchash, tcaphash_ansi_equal);

  /* Reset the session counter */
  tcapsrt_global_SessionId=1;

  /* Display of SRT only if Persistent Stat */
  gtcap_DisplaySRT=gtcap_PersistentSRT || gtcap_HandleSRT&gtcap_StatSRT;
}

/*
 * Create the record identifiying the TCAP transaction
 * When the identifier for the transaction is reused, check
 * the following criteria before to append a new record:
 * - a timeout corresponding to a message retransmission is detected,
 * - a message hast been lost
 * - or the previous transaction has been  be closed
 */
static struct tcaphash_context_t *
tcaphash_begin_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			struct tcapsrt_info_t *p_tcapsrt_info)
{
  struct tcaphash_context_t *p_tcaphash_context=NULL;
  struct tcaphash_context_key_t tcaphash_context_key;
  struct tcaphash_begincall_t *p_tcaphash_begincall, *p_new_tcaphash_begincall=NULL;
  struct tcaphash_begin_info_key_t tcaphash_begin_key;
  proto_item *pi;
  proto_item *stat_item=NULL;
  proto_tree *stat_tree=NULL;

  /* prepare the key data */
  tcaphash_begin_key.tid = p_tcapsrt_info->src_tid;
  if (pinfo->src.type == AT_SS7PC && pinfo->dst.type == AT_SS7PC)
  {
    /* We have MTP3 PCs (so we can safely do this cast) */
    tcaphash_begin_key.opc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
    tcaphash_begin_key.dpc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
  } else {
    /* Don't have MTP3 PCs (maybe we're over SUA?) */
    tcaphash_begin_key.opc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->src));
    tcaphash_begin_key.dpc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->dst));
  }
  tcaphash_begin_key.hashKey=tcaphash_begin_calchash(&tcaphash_begin_key);

  /* look up the request */
#ifdef DEBUG_TCAPSRT
  dbg(10,"\n Hbegin #%u ", pinfo->fd->num);
  dbg(11,"key %lx ",tcaphash_begin_key.hashKey);
  dbg(51,"PC %s %s ",address_to_str(wmem_packet_scope(), &pinfo->src), address_to_str(wmem_packet_scope(), &pinfo->dst));
  dbg(51,"Tid %lx \n",tcaphash_begin_key.tid);
#endif

  p_tcaphash_begincall = (struct tcaphash_begincall_t *)
  g_hash_table_lookup(tcaphash_begin, &tcaphash_begin_key);

  if (p_tcaphash_begincall) {
    /* Walk through list of transaction with identical keys */
    do {
      /* Check if the request with this reqSeqNum has been seen, with the same Message Type */
      if (pinfo->fd->num == p_tcaphash_begincall->context->first_frame) {
	/* We have seen this request before -> do nothing */
#ifdef DEBUG_TCAPSRT
	dbg(22,"Already seen ");
#endif
	p_tcaphash_context=p_tcaphash_begincall->context;
	break;
      }
      /* If the last record for Tcap transaction with identifier has not been reached */
      if (!p_tcaphash_begincall->next_begincall) {
	/* check if we have to create a new record or not */
	/* if last request has been responded (response number is known)
	   and this request appears after last response (has bigger frame number)
	   and last request occurred after the timeout for repetition,
	   or
	   if last request hasn't been responded (so number unknown)
	   and this request appears after last request (has bigger frame number)
	   and this request occurred after the timeout for message lost */
	if ( ( p_tcaphash_begincall->context->last_frame != 0
	       && pinfo->fd->num > p_tcaphash_begincall->context->first_frame
	       && (guint) pinfo->fd->abs_ts.secs > (guint)(p_tcaphash_begincall->context->begin_time.secs + gtcap_RepetitionTimeout)
	       ) ||
	     ( p_tcaphash_begincall->context->last_frame == 0
	       && pinfo->fd->num > p_tcaphash_begincall->context->first_frame
	       && (guint)pinfo->fd->abs_ts.secs > (guint)(p_tcaphash_begincall->context->begin_time.secs + gtcap_LostTimeout)
	       )
	     )
	  {
	    /* we decide that we have a new request */
	    /* Append new record to the list */
#ifdef DEBUG_TCAPSRT
	    dbg(12,"(timeout) Append key %lx ",tcaphash_begin_key.hashKey);
	    dbg(12,"Frame %u rsp %u ",pinfo->fd->num,p_tcaphash_begincall->context->last_frame );
#endif
	    tcaphash_context_key.session_id = tcapsrt_global_SessionId++;
	    p_tcaphash_context = new_tcaphash_context(&tcaphash_context_key, pinfo);

	    p_new_tcaphash_begincall = append_tcaphash_begincall(p_tcaphash_begincall,
								 p_tcaphash_context,
								 pinfo);
#ifdef DEBUG_TCAPSRT
	    dbg(12,"Update key %lx ",tcaphash_begin_key.hashKey);
#endif
	    update_tcaphash_begincall(p_new_tcaphash_begincall, pinfo);
	  } else { /* timeout or message lost */

	  /* If the Tid is reused for a closed Transaction */
	  /* Or if we received an TC_BEGIN for a Transaction marked as "closed" */
	  /* (this is the case, for pre-arranged END, the transaction is marked as closed */
	  /* by the upper layer, thank to a callback method close) */
	  if ( p_tcaphash_begincall->context->closed) {
#ifdef DEBUG_TCAPSRT
	    dbg(12,"(closed) Append key %lu ",tcaphash_begin_key.hashKey);
	    dbg(12,"Frame %u rsp %u ",pinfo->fd->num,p_tcaphash_begincall->context->last_frame );
#endif
	    tcaphash_context_key.session_id = tcapsrt_global_SessionId++;
	    p_tcaphash_context = new_tcaphash_context(&tcaphash_context_key, pinfo);
	    p_new_tcaphash_begincall = append_tcaphash_begincall(p_tcaphash_begincall,
								 p_tcaphash_context,
								 pinfo);

#ifdef DEBUG_TCAPSRT
	    dbg(12,"Update key %lu ",tcaphash_begin_key.hashKey);
#endif
	    update_tcaphash_begincall(p_new_tcaphash_begincall, pinfo);

	  } else {
	    /* the TCAP session is not closed, so, either messages have been lost */
	    /* or it's a duplicate request. Mark it as such. */
#ifdef DEBUG_TCAPSRT
	    dbg(21,"Display_duplicate %d ",p_tcaphash_begincall->context->first_frame);
#endif
	    p_tcaphash_context=p_tcaphash_begincall->context;
	    if (gtcap_DisplaySRT && tree) {
	      stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
	      PROTO_ITEM_SET_GENERATED(stat_item);
	      pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_Duplicate, tvb, 0, 0,
					      p_tcaphash_context->first_frame,
					      "Duplicate with session %u in frame %u",
					      p_tcaphash_context->session_id,p_tcaphash_context->first_frame);
	      PROTO_ITEM_SET_GENERATED(pi);
	    }
	    return p_tcaphash_context;
	  } /* Previous session closed */
	} /* test with Timeout or message Lost */
	break;
      } /* Next call is NULL */
      /* Repeat the tests for the next record with the same transaction identifier */
      p_tcaphash_begincall = p_tcaphash_begincall->next_begincall;
    } while (p_tcaphash_begincall != NULL );
    /*
     * End of analyze for the list be TC_BEGIN with same transaction ID
     */
  } else { /* p_tcaphash_begincall has not been found */
    /*
     * Create a new TCAP context
     */
#ifdef DEBUG_TCAPSRT
    dbg(10,"New key %lx ",tcaphash_begin_key.hashKey);
#endif

    tcaphash_context_key.session_id = tcapsrt_global_SessionId++;
    p_tcaphash_context = new_tcaphash_context(&tcaphash_context_key, pinfo);
    p_tcaphash_begincall = new_tcaphash_begin(&tcaphash_begin_key, p_tcaphash_context);

#ifdef DEBUG_TCAPSRT
    dbg(11,"Update key %lx ",tcaphash_begin_key.hashKey);
    dbg(11,"Frame reqlink #%u ", pinfo->fd->num);
#endif
    update_tcaphash_begincall(p_tcaphash_begincall, pinfo);
  }

  /* display tcap session, if available */
  if ( gtcap_DisplaySRT && tree &&
       p_tcaphash_context &&
       p_tcaphash_context->session_id) {
    stat_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_tcap_stat, &stat_item, "Stat");
    PROTO_ITEM_SET_GENERATED(stat_item);
    pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
    PROTO_ITEM_SET_GENERATED(pi);

    /* add link to response frame, if available */
    /* p_tcaphash_begincall->context->last_frame) */
    if( p_tcaphash_context->last_frame != 0 ){
#ifdef DEBUG_TCAPSRT
      dbg(20,"Display_frameRsplink %d ",p_tcaphash_context->last_frame);
#endif
      pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_BeginSession, tvb, 0, 0,
				      p_tcaphash_context->last_frame,
				      "End of session in frame %u",
				      p_tcaphash_context->last_frame);
      PROTO_ITEM_SET_GENERATED(pi);
    }
  }
  return p_tcaphash_context;
}

/*
* Try to find a TCAP session according to the source and destination
* Identifier given in the TC_CONT
* If nothing is found, it is probably a session in opening state, so try to find
* a tcap session registered with a TC_BEGIN "key", matching the destination Id of the TC_CONT
* Then associate the TC_CONT "key" to the TCAP context, and create a TC_END "key"
* and display the available info for the TCAP context
*/
static struct tcaphash_context_t *
tcaphash_cont_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		       struct tcapsrt_info_t *p_tcapsrt_info)
{
  struct tcaphash_context_t *p_tcaphash_context=NULL;
  struct tcaphash_contcall_t *p_tcaphash_contcall;
  struct tcaphash_cont_info_key_t tcaphash_cont_key;
  struct tcaphash_begin_info_key_t tcaphash_begin_key;
  struct tcaphash_begincall_t *p_tcaphash_begincall;
  struct tcaphash_end_info_key_t tcaphash_end_key;
  proto_item *pi;
  proto_item *stat_item=NULL;
  proto_tree *stat_tree=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(10,"\n Hcont #%u ", pinfo->fd->num);
#endif

  /* look only for matching request, if matching conversation is available. */
  tcaphash_cont_key.src_tid = p_tcapsrt_info->src_tid;
  tcaphash_cont_key.dst_tid = p_tcapsrt_info->dst_tid;
  if (pinfo->src.type == AT_SS7PC && pinfo->dst.type == AT_SS7PC)
  {
    /* We have MTP3 PCs (so we can safely do this cast) */
    tcaphash_cont_key.opc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
    tcaphash_cont_key.dpc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
  } else {
    /* Don't have MTP3 PCs (maybe we're over SUA?) */
    tcaphash_cont_key.opc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->src));
    tcaphash_cont_key.dpc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->dst));
  }
  tcaphash_cont_key.hashKey=tcaphash_cont_calchash(&tcaphash_cont_key);

#ifdef DEBUG_TCAPSRT
  dbg(11,"Ckey %lx ", tcaphash_cont_key.hashKey);
  dbg(51,"PC %s %s ",address_to_str(wmem_packet_scope(), &pinfo->src), address_to_str(wmem_packet_scope(), &pinfo->dst));
  dbg(51,"Tid %lx %lx \n",tcaphash_cont_key.src_tid, tcaphash_cont_key.dst_tid);
#endif
  p_tcaphash_contcall = find_tcaphash_cont(&tcaphash_cont_key, pinfo);
  if(p_tcaphash_contcall) {
#ifdef DEBUG_TCAPSRT
    dbg(12,"CFound ");
#endif
    p_tcaphash_context=p_tcaphash_contcall->context;
  } else { /* cont not found */
#ifdef DEBUG_TCAPSRT
    dbg(12,"CnotFound ");
#endif
    /* Find the TCAP transaction according to the TC_BEGIN */
    tcaphash_begin_key.tid = p_tcapsrt_info->dst_tid;
    if (pinfo->src.type == AT_SS7PC && pinfo->dst.type == AT_SS7PC)
    {
      /* We have MTP3 PCs (so we can safely do this cast) */
      tcaphash_begin_key.opc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
      tcaphash_begin_key.dpc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
    } else {
      /* Don't have MTP3 PCs (maybe we're over SUA?) */
      tcaphash_begin_key.opc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->src));
      tcaphash_begin_key.dpc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->dst));
    }
    tcaphash_begin_key.hashKey=tcaphash_begin_calchash(&tcaphash_begin_key);

#ifdef DEBUG_TCAPSRT
    dbg(11,"Bkey %lx ", tcaphash_begin_key.hashKey);
    dbg(51,"PC %s %s ",address_to_str(wmem_packet_scope(), &pinfo->src), address_to_str(wmem_packet_scope(), &pinfo->dst));
    dbg(51,"Tid %lx \n",tcaphash_begin_key.tid);
#endif
    p_tcaphash_begincall = find_tcaphash_begin(&tcaphash_begin_key, pinfo, FALSE);
    if(!p_tcaphash_begincall){
        /* Do we have a continue from the same source? */
        tcaphash_begin_key.tid = p_tcapsrt_info->src_tid;
        tcaphash_begin_key.hashKey=tcaphash_begin_calchash(&tcaphash_begin_key);
        p_tcaphash_begincall = find_tcaphash_begin(&tcaphash_begin_key, pinfo,FALSE);
    }
    if(p_tcaphash_begincall &&
       !p_tcaphash_begincall->context->contcall ) {
#ifdef DEBUG_TCAPSRT
      dbg(12,"BFound \n");
#endif
      p_tcaphash_context=p_tcaphash_begincall->context;
      p_tcaphash_context->responded=TRUE;

#ifdef DEBUG_TCAPSRT
      dbg(10,"New Ckey %lx ",tcaphash_cont_key.hashKey);
      dbg(11,"Frame reqlink #%u \n", pinfo->fd->num);
#endif
      create_tcaphash_cont(&tcaphash_cont_key,
                           p_tcaphash_begincall->context);

      tcaphash_end_key.tid = p_tcapsrt_info->src_tid;
      if (pinfo->src.type == AT_SS7PC && pinfo->dst.type == AT_SS7PC)
      {
        /* We have MTP3 PCs (so we can safely do this cast) */
        tcaphash_end_key.opc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
        tcaphash_end_key.dpc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
      } else {
        /* Don't have MTP3 PCs (maybe we're over SUA?) */
        tcaphash_end_key.opc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->src));
        tcaphash_end_key.dpc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->dst));
      }
      tcaphash_end_key.hashKey=tcaphash_end_calchash(&tcaphash_end_key);

#ifdef DEBUG_TCAPSRT
      dbg(10,"New Ekey %lx ",tcaphash_end_key.hashKey);
      dbg(11,"Frame reqlink #%u ", pinfo->fd->num);
#endif
      create_tcaphash_end(&tcaphash_end_key,
                          p_tcaphash_begincall->context);

    } else { /* Begin not found */
#ifdef DEBUG_TCAPSRT
      dbg(12,"BnotFound ");
#endif
    } /* begin found */
  } /* cont found */
    /* display tcap session, if available */
  if (gtcap_DisplaySRT && tree &&
      p_tcaphash_context &&
      p_tcaphash_context->session_id) {
    stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
    PROTO_ITEM_SET_GENERATED(stat_item);
    pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
    PROTO_ITEM_SET_GENERATED(pi);
  }

  return p_tcaphash_context;
}

/*
* Try to find a TCAP session according to the destination Identifier given in the TC_END/TC_ABORT
* If nothing is found,
* - either it is a session in opening state,
* - or the session is closed/aborted by the remote, ( so we switch the src and dst tid )
* so try to find a tcap session registered with a TC_BEGIN "key",
* matching the destination Id of the TC_END
* Then associate the TC_CONT "key" to the TCAP context
* and display the available info for the TCAP context
*/

static struct tcaphash_context_t *
tcaphash_end_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		      struct tcapsrt_info_t *p_tcapsrt_info)
{
  struct tcaphash_context_t *p_tcaphash_context=NULL;

  struct tcaphash_end_info_key_t tcaphash_end_key;
  struct tcaphash_endcall_t *p_tcaphash_endcall=NULL;

  struct tcaphash_begin_info_key_t tcaphash_begin_key;
  struct tcaphash_begincall_t *p_tcaphash_begincall=NULL;
  proto_item *pi;
  nstime_t delta;
  proto_item *stat_item=NULL;
  proto_tree *stat_tree=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(10,"\n Hend #%u ", pinfo->fd->num);
#endif
  /* look only for matching request, if matching conversation is available. */
  tcaphash_end_key.tid = p_tcapsrt_info->dst_tid;
  if (pinfo->src.type == AT_SS7PC && pinfo->dst.type == AT_SS7PC)
  {
    /* We have MTP3 PCs (so we can safely do this cast) */
    tcaphash_end_key.opc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
    tcaphash_end_key.dpc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
  } else {
    /* Don't have MTP3 PCs (maybe we're over SUA?) */
    tcaphash_end_key.opc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->src));
    tcaphash_end_key.dpc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->dst));
  }
  tcaphash_end_key.hashKey=tcaphash_end_calchash(&tcaphash_end_key);

#ifdef DEBUG_TCAPSRT
  dbg(11,"Ekey %lx ",tcaphash_end_key.hashKey);
  dbg(11,"PC %s %s ",address_to_str(wmem_packet_scope(), &pinfo->src), address_to_str(wmem_packet_scope(), &pinfo->dst));
  dbg(51,"Tid %lx ",tcaphash_end_key.tid);
#endif
  p_tcaphash_endcall = find_tcaphash_end(&tcaphash_end_key, pinfo,TRUE);

  if(!p_tcaphash_endcall) {
#ifdef DEBUG_TCAPSRT
    dbg(12,"EnotFound ");
#endif
    tcaphash_begin_key.tid = p_tcapsrt_info->dst_tid;
    if (pinfo->src.type == AT_SS7PC && pinfo->dst.type == AT_SS7PC)
    {
      /* We have MTP3 PCs (so we can safely do this cast) */
      tcaphash_begin_key.opc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
      tcaphash_begin_key.dpc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
    } else {
      /* Don't have MTP3 PCs (maybe we're over SUA?) */
      tcaphash_begin_key.opc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->src));
      tcaphash_begin_key.dpc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->dst));
    }
    tcaphash_begin_key.hashKey=tcaphash_begin_calchash(&tcaphash_begin_key);

#ifdef DEBUG_TCAPSRT
    dbg(11,"Bkey %lx ", tcaphash_begin_key.hashKey);
    dbg(51,"PC %s %s ",address_to_str(wmem_packet_scope(), &pinfo->src), address_to_str(wmem_packet_scope(), &pinfo->dst));
    dbg(51,"Tid %lx ",tcaphash_begin_key.tid);
#endif
    p_tcaphash_begincall = find_tcaphash_begin(&tcaphash_begin_key, pinfo,FALSE);
    if(!p_tcaphash_begincall) {
#ifdef DEBUG_TCAPSRT
      dbg(12,"BnotFound ");
#endif
    }
  }
  if (p_tcaphash_endcall) {
    /* Use the TC_BEGIN Destination reference */
    p_tcaphash_context=p_tcaphash_endcall->context;
  } else if (p_tcaphash_begincall) {
    /* Use the TC_BEGIN Source reference */
    p_tcaphash_context=p_tcaphash_begincall->context;
  }

  if (p_tcaphash_context) {

#ifdef DEBUG_TCAPSRT
    dbg(12,"Found, req=%d ",p_tcaphash_context->first_frame);
#endif
    if (gtcap_DisplaySRT && tree) {
      stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
      PROTO_ITEM_SET_GENERATED(stat_item);

      pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
      PROTO_ITEM_SET_GENERATED(pi);
    }

#ifdef DEBUG_TCAPSRT
    dbg(20,"Display framereqlink %d ",p_tcaphash_context->first_frame);
#endif
    /* Indicate the frame to which this is a reply. */
    if (gtcap_DisplaySRT && stat_tree) {
      pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_EndSession, tvb, 0, 0,
				      p_tcaphash_context->first_frame,
				      "Begin of session in frame %u",
				      p_tcaphash_context->first_frame);
      PROTO_ITEM_SET_GENERATED(pi);
      /* Calculate Service Response Time */
      nstime_delta(&delta, &pinfo->fd->abs_ts, &p_tcaphash_context->begin_time);

      /* display Service Response Time and make it filterable */
      pi = proto_tree_add_time(stat_tree, hf_tcapsrt_SessionTime, tvb, 0, 0, &delta);
      PROTO_ITEM_SET_GENERATED(pi);
    }
    /* Close the context and remove it (if needed) */
    tcapsrt_close(p_tcaphash_context,pinfo);

  } else {/* context present */
#ifdef DEBUG_TCAPSRT
    dbg(12,"Context notFound ");
#endif
  }
  return p_tcaphash_context;
}

/*
 * ANSI PART
 * Create the record identifiying the TCAP transaction
 * When the identifier for the transaction is reused, check
 * the following criteria before to append a new record:
 * - a timeout corresponding to a message retransmission is detected,
 * - a message hast been lost
 * - or the previous transaction has been  be closed
 */
static struct tcaphash_context_t *
tcaphash_ansi_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		       struct tcapsrt_info_t *p_tcapsrt_info)
{
  struct tcaphash_context_t *p_tcaphash_context=NULL;
  struct tcaphash_context_key_t tcaphash_context_key;
  struct tcaphash_ansicall_t *p_tcaphash_ansicall, *p_new_tcaphash_ansicall;
  struct tcaphash_ansi_info_key_t tcaphash_ansi_key;
  proto_item *pi;
  nstime_t delta;
  gboolean isResponse=FALSE;
  proto_tree * stat_tree=NULL;
  proto_item * stat_item=NULL;

  /* prepare the key data */
  tcaphash_ansi_key.tid = p_tcapsrt_info->src_tid;
  if (pinfo->src.type == AT_SS7PC && pinfo->dst.type == AT_SS7PC)
  {
    /* We have MTP3 PCs (so we can safely do this cast) */
    tcaphash_ansi_key.opc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
    tcaphash_ansi_key.dpc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
  } else {
    /* Don't have MTP3 PCs (maybe we're over SUA?) */
    tcaphash_ansi_key.opc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->src));
    tcaphash_ansi_key.dpc_hash = g_str_hash(address_to_str(wmem_packet_scope(), &pinfo->dst));
  }
  tcaphash_ansi_key.hashKey=tcaphash_ansi_calchash(&tcaphash_ansi_key);

  /* look up the request */
#ifdef DEBUG_TCAPSRT
  dbg(10,"\n Hansi #%u ", pinfo->fd->num);
  dbg(11,"key %lx ",tcaphash_ansi_key.hashKey);
  dbg(51,"PC %s %s ",address_to_str(wmem_packet_scope(), &pinfo->src), address_to_str(wmem_packet_scope(), &pinfo->dst));
  dbg(51,"Tid %lx ",tcaphash_ansi_key.tid);
#endif
  p_tcaphash_ansicall = (struct tcaphash_ansicall_t *)
    g_hash_table_lookup(tcaphash_ansi, &tcaphash_ansi_key);

  if (p_tcaphash_ansicall) {
    /* Walk through list of transaction with identical keys */
    do {
      /* Check if the request with this reqSeqNum has been seen */
      if (pinfo->fd->num == p_tcaphash_ansicall->context->first_frame) {
	/* We have seen this request before -> do nothing */
#ifdef DEBUG_TCAPSRT
	dbg(22,"Request already seen ");
#endif
	isResponse=FALSE;
	p_tcaphash_context=p_tcaphash_ansicall->context;
	break;
      }

      /* Check if the reponse with this reqSeqNum has been seen */
      if (pinfo->fd->num == p_tcaphash_ansicall->context->last_frame) {
	/* We have seen this response before -> do nothing */
#ifdef DEBUG_TCAPSRT
	dbg(22,"Response already seen ");
#endif
	isResponse=TRUE;
	p_tcaphash_context=p_tcaphash_ansicall->context;
	break;
      }

      /* Check for the first Request without Response
       received before this frame */
      if ( pinfo->fd->num > p_tcaphash_ansicall->context->first_frame &&
	   p_tcaphash_ansicall->context->last_frame==0 ) {
	/* Take it, and update the context */

#ifdef DEBUG_TCAPSRT
	dbg(12,"Update key %lx ",tcaphash_ansi_key.hashKey);
#endif
	p_tcaphash_ansicall->context->last_frame = pinfo->fd->num;
	p_tcaphash_ansicall->context->responded = TRUE;
	p_tcaphash_ansicall->context->closed = TRUE;
	p_tcaphash_context=p_tcaphash_ansicall->context;
	isResponse=TRUE;

	if (gtcap_DisplaySRT && tree) {
	  stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
	  PROTO_ITEM_SET_GENERATED(stat_item);

	  pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
	  PROTO_ITEM_SET_GENERATED(pi);

#ifdef DEBUG_TCAPSRT
	  dbg(20,"Display framereqlink %d ",p_tcaphash_context->first_frame);
#endif
	  /* Indicate the frame to which this is a reply. */
	  pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_EndSession, tvb, 0, 0,
					  p_tcaphash_context->first_frame,
					  "Begin of session in frame %u",
					  p_tcaphash_context->first_frame);
	  PROTO_ITEM_SET_GENERATED(pi);
	  /* Calculate Service Response Time */
	  nstime_delta(&delta, &pinfo->fd->abs_ts, &p_tcaphash_context->begin_time);

	  /* display Service Response Time and make it filterable */
	  pi = proto_tree_add_time(stat_tree, hf_tcapsrt_SessionTime, tvb, 0, 0, &delta);
	  PROTO_ITEM_SET_GENERATED(pi);
	}
	break;
      } /* Lastframe=0, so take it */


      /* If the last record for Tcap transaction with identifier has been reached */
      if (!p_tcaphash_ansicall->next_ansicall) {
	/* check if we have to create a new record or not */
	/* if last request has been responded (response number in known)
	   and this request appears after last response (has bigger frame number)
	   and last request occurred after the timeout for repetition,
	   or
	   if last request hasn't been responded (so number unknown)
	   and this request appears after last request (has bigger frame number)
	   and this request occurred after the timeout for message lost */
	if ( ( p_tcaphash_ansicall->context->last_frame != 0
	       && pinfo->fd->num > p_tcaphash_ansicall->context->first_frame
	       && (guint) pinfo->fd->abs_ts.secs > (guint)(p_tcaphash_ansicall->context->begin_time.secs + gtcap_RepetitionTimeout)
	       ) ||
	     ( p_tcaphash_ansicall->context->last_frame == 0
	       && pinfo->fd->num > p_tcaphash_ansicall->context->first_frame
	       && (guint)pinfo->fd->abs_ts.secs > (guint)(p_tcaphash_ansicall->context->begin_time.secs + gtcap_LostTimeout)
	       )
	     )
	  {
	    /* we decide that we have a new request */
	    /* Append new record to the list */
#ifdef DEBUG_TCAPSRT
	    dbg(12,"(timeout) Append key %lx ",tcaphash_ansi_key.hashKey);
	    dbg(12,"Frame %u rsp %u ",pinfo->fd->num,p_tcaphash_ansicall->context->last_frame );
#endif
	    tcaphash_context_key.session_id = tcapsrt_global_SessionId++;
	    p_tcaphash_context = new_tcaphash_context(&tcaphash_context_key, pinfo);
	    p_new_tcaphash_ansicall = append_tcaphash_ansicall(p_tcaphash_ansicall,
								 p_tcaphash_context,
								 pinfo);

#ifdef DEBUG_TCAPSRT
	    dbg(12,"Update key %lx ",tcaphash_ansi_key.hashKey);
#endif
	    update_tcaphash_ansicall(p_new_tcaphash_ansicall, pinfo);
	    p_tcaphash_ansicall=p_new_tcaphash_ansicall;
	  } else {

	  /* If the Tid is reused for a closed Transaction */
	  if ( p_tcaphash_ansicall->context->closed) {
#ifdef DEBUG_TCAPSRT
	    dbg(12,"(closed) Append key %lu ",tcaphash_ansi_key.hashKey);
	    dbg(12,"Frame %u rsp %u ",pinfo->fd->num,p_tcaphash_ansicall->context->last_frame );
#endif
	    tcaphash_context_key.session_id = tcapsrt_global_SessionId++;
	    p_tcaphash_context = new_tcaphash_context(&tcaphash_context_key, pinfo);
	    p_new_tcaphash_ansicall = append_tcaphash_ansicall(p_tcaphash_ansicall,
								 p_tcaphash_context,
								 pinfo);

#ifdef DEBUG_TCAPSRT
	    dbg(12,"Update key %lu ",tcaphash_ansi_key.hashKey);
#endif
	    update_tcaphash_ansicall(p_new_tcaphash_ansicall, pinfo);
	    p_tcaphash_ansicall=p_new_tcaphash_ansicall;

	  } else {
	    /* the Tid is reused for an opened Transaction */
	    /* so, this is the reply to the request of our context */
	    p_tcaphash_context=p_tcaphash_ansicall->context;
#ifdef DEBUG_TCAPSRT
	    dbg(12,"Found, req=%d ",p_tcaphash_context->first_frame);
#endif

	    if (gtcap_DisplaySRT && tree) {
	      stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
	      PROTO_ITEM_SET_GENERATED(stat_item);

	      pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
	      PROTO_ITEM_SET_GENERATED(pi);

#ifdef DEBUG_TCAPSRT
	      dbg(20,"Display framereqlink %d ",p_tcaphash_context->first_frame);
#endif
	      /* Indicate the frame to which this is a reply. */
	      pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_EndSession, tvb, 0, 0,
					      p_tcaphash_context->first_frame,
					      "Begin of session in frame %u",
					      p_tcaphash_context->first_frame);
	      PROTO_ITEM_SET_GENERATED(pi);
	      /* Calculate Service Response Time */
	      nstime_delta(&delta, &pinfo->fd->abs_ts, &p_tcaphash_context->begin_time);

	      /* display Service Response Time and make it filterable */
	      pi = proto_tree_add_time(stat_tree, hf_tcapsrt_SessionTime, tvb, 0, 0, &delta);
	      PROTO_ITEM_SET_GENERATED(pi);
	    }
	    p_tcaphash_context=p_tcaphash_ansicall->context;
	  } /* test with Timeout */
	} /* closed */
	break;
      } /* Next call is NULL */
      p_tcaphash_ansicall = p_tcaphash_ansicall->next_ansicall;
    } while (p_tcaphash_ansicall != NULL );
    /*
     * New TCAP context
     */
  } else { /* p_tcaphash_ansicall has not been found */
#ifdef DEBUG_TCAPSRT
    dbg(10,"New key %lx ",tcaphash_ansi_key.hashKey);
#endif

    tcaphash_context_key.session_id = tcapsrt_global_SessionId++;
    p_tcaphash_context = new_tcaphash_context(&tcaphash_context_key, pinfo);
    p_tcaphash_ansicall = new_tcaphash_ansi(&tcaphash_ansi_key, p_tcaphash_context);

#ifdef DEBUG_TCAPSRT
    dbg(11,"Update key %lx ",tcaphash_ansi_key.hashKey);
    dbg(11,"Frame reqlink #%u ", pinfo->fd->num);
#endif
    update_tcaphash_ansicall(p_tcaphash_ansicall, pinfo);
  }

  /* display tcap session, if available */
  if ( gtcap_DisplaySRT && tree &&
       p_tcaphash_context &&
       p_tcaphash_context->session_id) {
    stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
    PROTO_ITEM_SET_GENERATED(stat_item);
    pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
    PROTO_ITEM_SET_GENERATED(pi);
  }


  /* add link to response frame, if available */
  if( gtcap_DisplaySRT && stat_tree &&
      p_tcaphash_ansicall->context->last_frame != 0){
    if (!isResponse) { /* Request */
#ifdef DEBUG_TCAPSRT
      dbg(20,"Display_frameRsplink %d ",p_tcaphash_ansicall->context->last_frame);
#endif
      pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_BeginSession, tvb, 0, 0,
				      p_tcaphash_ansicall->context->last_frame,
				      "End of session in frame %u",
				      p_tcaphash_ansicall->context->last_frame);
      PROTO_ITEM_SET_GENERATED(pi);
    } else { /* Response */
#ifdef DEBUG_TCAPSRT
      dbg(20,"Display framereqlink %d ",p_tcaphash_context->first_frame);
#endif
      /* Indicate the frame to which this is a reply. */
      if (gtcap_DisplaySRT) {
	pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_EndSession, tvb, 0, 0,
					p_tcaphash_context->first_frame,
					"Begin of session in frame %u",
					p_tcaphash_context->first_frame);
	PROTO_ITEM_SET_GENERATED(pi);
	/* Calculate Service Response Time */
	nstime_delta(&delta, &pinfo->fd->abs_ts, &p_tcaphash_context->begin_time);

	/* display Service Response Time and make it filterable */
	pi = proto_tree_add_time(stat_tree, hf_tcapsrt_SessionTime, tvb, 0, 0, &delta);
	PROTO_ITEM_SET_GENERATED(pi);
      }
    } /* Request or Response */
  }
  return p_tcaphash_context;
}

/*
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
struct tcaphash_context_t *
tcapsrt_call_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		      struct tcapsrt_info_t *p_tcapsrt_info)
{
  struct tcaphash_context_t *tcap_context=NULL;

  /* if this packet isn't loaded because of a read filter, don't output anything */
  if(pinfo == NULL || pinfo->fd->num == 0) {
    return NULL;
  }

  switch (p_tcapsrt_info->ope) {

  case TC_BEGIN:
#ifdef DEBUG_TCAPSRT
    dbg(1,"\nTC_BEGIN ");
#endif
    tcap_context=tcaphash_begin_matching(tvb, pinfo, tree, p_tcapsrt_info);
    break;

  case TC_CONT:
#ifdef DEBUG_TCAPSRT
    dbg(1,"\nTC_CONT ");
#endif
    tcap_context=tcaphash_cont_matching(tvb, pinfo, tree, p_tcapsrt_info);
    break;

  case TC_ABORT:
#ifdef DEBUG_TCAPSRT
    dbg(1,"\nTC_ABORT ");
#endif
    tcap_context=tcaphash_end_matching(tvb, pinfo, tree, p_tcapsrt_info);
    break;

  case TC_END:
#ifdef DEBUG_TCAPSRT
    dbg(1,"\nTC_END ");
#endif
    tcap_context=tcaphash_end_matching(tvb, pinfo, tree, p_tcapsrt_info);
    break;

  case TC_ANSI_ALL:
  case TC_ANSI_ABORT:
#ifdef DEBUG_TCAPSRT
    dbg(1,"\nTC_ANSI ");
#endif
    tcap_context=tcaphash_ansi_matching(tvb, pinfo, tree, p_tcapsrt_info);
    break;

  default:
#ifdef DEBUG_TCAPSRT
    dbg(1,"\nUnknown %d ", p_tcapsrt_info->ope);
#endif
    break;
  } /* switch tcapop */
#ifdef DEBUG_TCAPSRT
  if (tcap_context)
    dbg(1,"session %d ", tcap_context->session_id);
#endif
  return tcap_context;
}

/*
 * Initialize the Message Info used by the main dissector
 * Data are linked to a TCAP transaction
 */
struct tcapsrt_info_t *
tcapsrt_razinfo(void)
{
  struct tcapsrt_info_t *p_tcapsrt_info ;

  /* Global buffer for packet extraction */
  tcapsrt_global_current++;
  if(tcapsrt_global_current==MAX_TCAP_INSTANCE){
    tcapsrt_global_current=0;
  }

  p_tcapsrt_info=&tcapsrt_global_info[tcapsrt_global_current];
  memset(p_tcapsrt_info,0,sizeof(struct tcapsrt_info_t));

  return p_tcapsrt_info;
}

void
tcapsrt_close(struct tcaphash_context_t *p_tcaphash_context,
	      packet_info *pinfo)
{
#ifdef DEBUG_TCAPSRT
  dbg(60,"Force close ");
#endif
  if (p_tcaphash_context) {
    p_tcaphash_context->responded=TRUE;
    p_tcaphash_context->last_frame = pinfo->fd->num;
    p_tcaphash_context->end_time = pinfo->fd->abs_ts;
    p_tcaphash_context->closed=TRUE;

    /* If the endkey is present */
    if (p_tcaphash_context->endcall
	&& !gtcap_PersistentSRT) {
      if (p_tcaphash_context->endcall->next_endcall) {
	if (p_tcaphash_context->endcall->previous_endcall ) {
#ifdef DEBUG_TCAPSRT
	  dbg(20,"deplace Ehash ");
#endif
	  p_tcaphash_context->endcall->previous_endcall->next_endcall
	    = p_tcaphash_context->endcall->next_endcall;
	  p_tcaphash_context->endcall->next_endcall->previous_endcall
	    = p_tcaphash_context->endcall->previous_endcall;
	  g_hash_table_remove(tcaphash_end, p_tcaphash_context->endcall->endkey);
#ifdef MEM_TCAPSRT
	  g_free(p_tcaphash_context->endcall);
#endif
	} else {
	  /* cannot remove the father */
#ifdef DEBUG_TCAPSRT
	  dbg(20,"father Ehash ");
#endif
	} /* no previous link, so father */
      } else if (!gtcap_PersistentSRT) {
#ifdef DEBUG_TCAPSRT
	dbg(20,"remove Ehash ");
#endif
	g_hash_table_remove(tcaphash_end, p_tcaphash_context->endcall->endkey);
#ifdef MEM_TCAPSRT
	g_free(p_tcaphash_context->endcall->endkey);
	g_free(p_tcaphash_context->endcall);
#endif

      } /* endcall without chained string */
    } /* no endcall */


    /* If the contkey is present */
    if (p_tcaphash_context->contcall
	&& !gtcap_PersistentSRT) {
      if (p_tcaphash_context->contcall->next_contcall) {
	if (p_tcaphash_context->contcall->previous_contcall ) {
#ifdef DEBUG_TCAPSRT
	  dbg(20,"deplace Chash ");
#endif
	  p_tcaphash_context->contcall->previous_contcall->next_contcall
	    = p_tcaphash_context->contcall->next_contcall;
	  p_tcaphash_context->contcall->next_contcall->previous_contcall
	    = p_tcaphash_context->contcall->previous_contcall;
	  g_hash_table_remove(tcaphash_cont, p_tcaphash_context->contcall->contkey);
#ifdef MEM_TCAPSRT
	  g_free(p_tcaphash_context->contcall);
#endif
	} else {
	  /* cannot remove the father */
#ifdef DEBUG_TCAPSRT
	  dbg(20,"father Chash ");
#endif
	} /* no previous link, so father */
      } else if (!gtcap_PersistentSRT) {
#ifdef DEBUG_TCAPSRT
	dbg(20,"remove Chash ");
#endif
	g_hash_table_remove(tcaphash_cont, p_tcaphash_context->contcall->contkey);
#ifdef MEM_TCAPSRT
	g_free(p_tcaphash_context->contcall->contkey);
	g_free(p_tcaphash_context->contcall);
#endif
      } /* contcall without chained string */
    } /* no contcall */


    /* If the beginkey is present */
    if (p_tcaphash_context->begincall
	&& !gtcap_PersistentSRT) {
      if (p_tcaphash_context->begincall->next_begincall) {
	if (p_tcaphash_context->begincall->previous_begincall ) {
#ifdef DEBUG_TCAPSRT
	  dbg(20,"deplace Bhash ");
#endif
	  p_tcaphash_context->begincall->previous_begincall->next_begincall
	    = p_tcaphash_context->begincall->next_begincall;
	  p_tcaphash_context->begincall->next_begincall->previous_begincall
	    = p_tcaphash_context->begincall->previous_begincall;
	  g_hash_table_remove(tcaphash_begin, p_tcaphash_context->begincall->beginkey);
#ifdef MEM_TCAPSRT
	  g_free(p_tcaphash_context->begincall);
#endif
	} else {
	  /* cannot remove the father */
#ifdef DEBUG_TCAPSRT
	  dbg(20,"father Bhash ");
#endif
	}
      } else  if (!gtcap_PersistentSRT) {
#ifdef DEBUG_TCAPSRT
	dbg(20,"remove Bhash ");
#endif
	g_hash_table_remove(tcaphash_begin, p_tcaphash_context->begincall->beginkey);
#ifdef MEM_TCAPSRT
	g_free(p_tcaphash_context->begincall->beginkey);
	g_free(p_tcaphash_context->begincall);
#endif
      } /* begincall without chained string */
    } /* no begincall */

    /* If the ansikey is present */
    if (p_tcaphash_context->ansicall
	&& !gtcap_PersistentSRT) {
      if (p_tcaphash_context->ansicall->next_ansicall) {
	if (p_tcaphash_context->ansicall->previous_ansicall ) {
#ifdef DEBUG_TCAPSRT
	  dbg(20,"deplace Ahash ");
#endif
	  p_tcaphash_context->ansicall->previous_ansicall->next_ansicall
	    = p_tcaphash_context->ansicall->next_ansicall;
	  p_tcaphash_context->ansicall->next_ansicall->previous_ansicall
	    = p_tcaphash_context->ansicall->previous_ansicall;
	  g_hash_table_remove(tcaphash_ansi, p_tcaphash_context->ansicall->ansikey);
#ifdef MEM_TCAPSRT
	  g_free(p_tcaphash_context->ansicall);
#endif
	} else {
	  /* cannot remove the father */
#ifdef DEBUG_TCAPSRT
	  dbg(20,"father Ahash ");
#endif
	}
      } else  if (!gtcap_PersistentSRT) {
#ifdef DEBUG_TCAPSRT
	dbg(20,"remove Ahash ");
#endif
	g_hash_table_remove(tcaphash_ansi, p_tcaphash_context->ansicall->ansikey);
#ifdef MEM_TCAPSRT
	g_free(p_tcaphash_context->ansicall->ansikey);
	g_free(p_tcaphash_context->ansicall);
#endif
      } /* ansicall without chained string */
    } /* no ansicall */

    if (!gtcap_PersistentSRT) {
#ifdef DEBUG_TCAPSRT
      dbg(20,"remove context ");
#endif
      g_hash_table_remove(tcaphash_context, p_tcaphash_context->key);
#ifdef MEM_TCAPSRT
      g_free(p_tcaphash_context->key);
      g_free(p_tcaphash_context);
#endif
    }
  } else { /* no context */
#ifdef DEBUG_TCAPSRT
    dbg(20,"No context to remove ");
#endif
  }
}

const value_string tcap_component_type_str[] = {
    { TCAP_COMP_INVOKE,		"Invoke" },
    { TCAP_COMP_RRL,		"Return Result(L)" },
    { TCAP_COMP_RE,			"Return Error" },
    { TCAP_COMP_REJECT,		"Reject" },
    { TCAP_COMP_RRN,		"Return Result(NL)" },
    { 0,			NULL } };


static void
dissect_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item		*item=NULL;
    proto_tree		*tree=NULL;

    struct tcaphash_context_t * p_tcap_context;
    dissector_handle_t subdissector_handle;
	asn1_ctx_t asn1_ctx;
	gint8 ber_class;
	gboolean pc;
	gint tag;

	/* Check if ANSI TCAP and call the ANSI TCAP dissector if that's the case
	 * PackageType ::= CHOICE { unidirectional			[PRIVATE 1] IMPLICIT UniTransactionPDU,
	 * 						 queryWithPerm				[PRIVATE 2] IMPLICIT TransactionPDU,
	 * 						 queryWithoutPerm			[PRIVATE 3] IMPLICIT TransactionPDU,
	 * 						 response					[PRIVATE 4] IMPLICIT TransactionPDU,
	 * 						 conversationWithPerm		[PRIVATE 5] IMPLICIT TransactionPDU,
	 * 						 conversationWithoutPerm	[PRIVATE 6] IMPLICIT TransactionPDU,
	 * 						 abort						[PRIVATE 22] IMPLICIT Abort
	 * 						 }
	 *
	 *
	 */
	get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);

	if(ber_class == BER_CLASS_PRI){
		switch(tag){
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 22:
			call_dissector(ansi_tcap_handle, tvb, pinfo, parent_tree);
			return;
			break;
		default:
			return;
		}
	}

	/* ITU TCAP */
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    tcap_top_tree = parent_tree;
    tcap_stat_tree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCAP");

    /* create display subtree for the protocol */
    if(parent_tree){
      item = proto_tree_add_item(parent_tree, proto_tcap, tvb, 0, -1, ENC_NA);
      tree = proto_item_add_subtree(item, ett_tcap);
      tcap_stat_tree=tree;
    }
    cur_oid = NULL;
    tcapext_oid = NULL;
    raz_tcap_private(&tcap_private);

    asn1_ctx.value_ptr = &tcap_private;
    gp_tcapsrt_info=tcapsrt_razinfo();
    tcap_subdissector_used=FALSE;
    gp_tcap_context=NULL;
    dissect_tcap_TCMessage(FALSE, tvb, 0, &asn1_ctx, tree, -1);

    if (gtcap_HandleSRT && !tcap_subdissector_used ) {
      p_tcap_context=tcapsrt_call_matching(tvb, pinfo, tcap_stat_tree, gp_tcapsrt_info);
      tcap_private.context=p_tcap_context;

		/* If the current message is TCAP only,
		 * save the Application Context Name for the next messages
		 */
		if ( p_tcap_context && cur_oid && !p_tcap_context->oid_present ) {
			/* Save the application context and the sub dissector */
			g_strlcpy(p_tcap_context->oid, cur_oid, sizeof(p_tcap_context->oid));
			p_tcap_context->oid_present=TRUE;
			if ( (subdissector_handle = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
				p_tcap_context->subdissector_handle=subdissector_handle;
				p_tcap_context->subdissector_present=TRUE;
			}
		}
		if (gtcap_HandleSRT && p_tcap_context && p_tcap_context->callback) {
			/* Callback fonction for the upper layer */
			(p_tcap_context->callback)(tvb, pinfo, tcap_stat_tree, p_tcap_context);
		}
	}
}

void
proto_reg_handoff_tcap(void)
{

    data_handle = find_dissector("data");
    ansi_tcap_handle = find_dissector("ansi_tcap");
    ber_oid_dissector_table = find_dissector_table("ber.oid");

#include "packet-tcap-dis-tab.c"
}

static void init_tcap(void);

void
proto_register_tcap(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
	{ &hf_tcap_tag,
		{ "Tag",           "tcap.msgtype",
		FT_UINT8, BASE_HEX, NULL, 0,
		NULL, HFILL }
	},
	{ &hf_tcap_length,
		{ "Length", "tcap.len",
		FT_UINT8, BASE_DEC, NULL, 0,
		NULL, HFILL }
	},
	{ &hf_tcap_data,
		{ "Data", "tcap.data",
		FT_BYTES, BASE_NONE, NULL, 0,
		NULL, HFILL }
	},
		{ &hf_tcap_tid,
		{ "Transaction Id", "tcap.tid",
		FT_BYTES, BASE_NONE, NULL, 0,
		NULL, HFILL }
	},
	/* Tcap Service Response Time */
	{ &hf_tcapsrt_SessionId,
	  { "Session Id",
	    "tcap.srt.session_id",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }
	},
	{ &hf_tcapsrt_BeginSession,
	  { "Begin Session",
	    "tcap.srt.begin",
	    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	    "SRT Begin of Session", HFILL }
	},
	{ &hf_tcapsrt_EndSession,
	  { "End Session",
	    "tcap.srt.end",
	    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	    "SRT End of Session", HFILL }
	},
	{ &hf_tcapsrt_SessionTime,
	  { "Session duration",
	    "tcap.srt.sessiontime",
	    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
	    "Duration of the TCAP session", HFILL }
	},
	{ &hf_tcapsrt_Duplicate,
	  { "Session Duplicate",
	    "tcap.srt.duplicate",
	    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	    "SRT Duplicated with Session", HFILL }
	},
#include "packet-tcap-hfarr.c"
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_tcap,
	&ett_param,
	&ett_otid,
	&ett_dtid,
	&ett_tcap_stat,
	#include "packet-tcap-ettarr.c"
    };

    /*static enum_val_t tcap_options[] = {
	{ "itu", "ITU",  ITU_TCAP_STANDARD },
	{ "ansi", "ANSI", ANSI_TCAP_STANDARD },
	{ NULL, NULL, 0 }
    };*/

    module_t *tcap_module;

/* Register the protocol name and description */
    proto_tcap = proto_register_protocol(PNAME, PSNAME, PFNAME);

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_tcap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    tcap_module = prefs_register_protocol(proto_tcap, NULL);

#if 0
    prefs_register_enum_preference(tcap_module, "standard", "ITU TCAP standard",
	"The SS7 standard used in ITU TCAP packets",
	&tcap_standard, tcap_options, FALSE);
#else
    prefs_register_obsolete_preference(tcap_module, "standard");
#endif

#if 0
    prefs_register_bool_preference(tcap_module, "lock_info_col", "Lock Info column",
	"Always show TCAP in Info column",
	&lock_info_col);
#else
    prefs_register_obsolete_preference(tcap_module, "lock_info_col");
#endif

    /* Set default SSNs */
    range_convert_str(&global_ssn_range, "", MAX_SSN);
    ssn_range = range_empty();

    prefs_register_range_preference(tcap_module, "ssn", "SCCP SSNs",
	"SCCP (and SUA) SSNs to decode as TCAP",
	&global_ssn_range, MAX_SSN);

    prefs_register_bool_preference(tcap_module, "srt",
				   "Service Response Time Analyse",
				   "Activate the analyse for Response Time",
				   &gtcap_HandleSRT);

    prefs_register_bool_preference(tcap_module, "persistentsrt",
				   "Persistent stats for SRT",
				   "Statistics for Response Time",
				   &gtcap_PersistentSRT);

    prefs_register_uint_preference(tcap_module, "repetitiontimeout",
				   "Repetition timeout",
				   "Maximal delay for message repetion",
				   10, &gtcap_RepetitionTimeout);

    prefs_register_uint_preference(tcap_module, "losttimeout",
				   "lost timeout",
				   "Maximal delay for message lost",
				   10, &gtcap_LostTimeout);

    ansi_sub_dissectors = g_hash_table_new(g_direct_hash,g_direct_equal);
    itu_sub_dissectors = g_hash_table_new(g_direct_hash,g_direct_equal);

    /* 'globally' register dissector */
    register_dissector("tcap", dissect_tcap, proto_tcap);

    tcap_handle = create_dissector_handle(dissect_tcap, proto_tcap);

    register_init_routine(&init_tcap);
}


static void range_delete_callback(guint32 ssn)
{
    if ( ssn && !get_ansi_tcap_subdissector(ssn) && !get_itu_tcap_subdissector(ssn) ) {
        dissector_delete_uint("sccp.ssn", ssn, tcap_handle);
    }
}

static void range_add_callback(guint32 ssn)
{
    if (ssn && !get_ansi_tcap_subdissector(ssn) && !get_itu_tcap_subdissector(ssn) ) {
        dissector_add_uint("sccp.ssn", ssn, tcap_handle);
    }
}


static void init_tcap(void) {
    if (ssn_range) {
        range_foreach(ssn_range, range_delete_callback);
        g_free(ssn_range);
    }

    ssn_range = range_copy(global_ssn_range);
    range_foreach(ssn_range, range_add_callback);
    tcapsrt_init_routine();
}

static int
dissect_tcap_param(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset)
{
    gint tag_offset, saved_offset, len_offset;
    tvbuff_t	*next_tvb;
    proto_tree *subtree;
    gint8 ber_class;
    gboolean pc;
    gint32 tag;
    guint32 len;
    guint32 tag_length;
    guint32 len_length;
    gboolean ind_field;

    while (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        saved_offset = offset;

        offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
        tag_offset = offset;
        offset = get_ber_length(tvb, offset, &len, &ind_field);
        len_offset = offset;

        tag_length = tag_offset - saved_offset;
        len_length = len_offset - tag_offset;

        if (pc)
        {
            subtree = proto_tree_add_subtree(tree, tvb, saved_offset,
                len + (len_offset - saved_offset), ett_param, NULL,
                "CONSTRUCTOR");
            proto_tree_add_uint_format(subtree, hf_tcap_tag, tvb,
                saved_offset, tag_length, tag,
                "CONSTRUCTOR Tag");
            proto_tree_add_uint(subtree, hf_tcap_tag, tvb, saved_offset,
                tag_length, ber_class);

            proto_tree_add_uint(subtree, hf_tcap_length, tvb, tag_offset,
                len_length, len);

            if (len-(2*ind_field)) /*should always be positive unless we get an empty contructor pointless? */
            {
                next_tvb = tvb_new_subset_length(tvb, offset, len-(2*ind_field));
                dissect_tcap_param(actx, subtree,next_tvb,0);
            }

            if (ind_field)
                proto_tree_add_text(subtree, tvb, offset+len-2, 2, "CONSTRUCTOR EOC");

            offset += len;
        }
        else
        {
            subtree = proto_tree_add_subtree_format(tree, tvb, saved_offset,
                len + (len_offset - saved_offset), ett_param, NULL,
                "Parameter (0x%.2x)", tag);

            proto_tree_add_uint(subtree, hf_tcap_tag, tvb, saved_offset,
                tag_length, tag);

            proto_tree_add_uint(subtree, hf_tcap_length, tvb,
                saved_offset+tag_length, len_length, len);

            if (len) /* check for NULLS */
            {
                next_tvb = tvb_new_subset_length(tvb, offset, len);
                dissect_ber_octet_string(TRUE, actx, tree, next_tvb, 0,
                    hf_tcap_data, NULL);
            }

            offset += len;
        }
    }
    return offset;
}

static void raz_tcap_private(struct tcap_private_t * p_tcap_private)
{
  memset(p_tcap_private,0,sizeof(struct tcap_private_t) );
}

/*
 * Call ITU Subdissector to decode the Tcap Component
 */
static int
dissect_tcap_ITU_ComponentPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_)
{
  dissector_handle_t subdissector_handle=NULL;
  gboolean is_subdissector=FALSE;
  struct tcaphash_context_t * p_tcap_context=NULL;

  /*
   * ok lets look at the oid and ssn and try and find a dissector, otherwise lets decode it.
   */

  /*
   * Handle The TCAP Service Response Time
   */
  if ( gtcap_HandleSRT ) {
	  if (!tcap_subdissector_used) {
	    p_tcap_context=tcapsrt_call_matching(tvb, actx->pinfo, tcap_stat_tree, gp_tcapsrt_info);
	    tcap_subdissector_used=TRUE;
	    gp_tcap_context=p_tcap_context;
	    tcap_private.context=p_tcap_context;
	  }else{
		  /* Take the last TCAP context */
		  p_tcap_context = gp_tcap_context;
		  tcap_private.context=p_tcap_context;
	  }
  }
  if (p_tcap_context) {
	  if (cur_oid) {
		  if (p_tcap_context->oid_present) {
			  /* We have already an Application Context, check if we have
			     to fallback to a lower version */
			  if ( strncmp(p_tcap_context->oid, cur_oid, sizeof(p_tcap_context->oid))!=0) {
				  /* ACN, changed, Fallback to lower version
				   * and update the subdissector (purely formal)
				   */
				  g_strlcpy(p_tcap_context->oid,cur_oid, sizeof(p_tcap_context->oid));
				  if ( (subdissector_handle = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
					  p_tcap_context->subdissector_handle=subdissector_handle;
					  p_tcap_context->subdissector_present=TRUE;
				  }
			  }
		  } else {
			  /* We do not have the OID in the TCAP context, so store it */
			  g_strlcpy(p_tcap_context->oid, cur_oid, sizeof(p_tcap_context->oid));
			  p_tcap_context->oid_present=TRUE;
			  /* Try to find a subdissector according to OID */
			  if ( (subdissector_handle
				  = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
				  p_tcap_context->subdissector_handle=subdissector_handle;
				  p_tcap_context->subdissector_present=TRUE;
			  } else {
			    /* Not found, so try to find a subdissector according to SSN */
			    if ( (subdissector_handle = get_itu_tcap_subdissector(actx->pinfo->match_uint))) {
			      /* Found according to SSN */
			      p_tcap_context->subdissector_handle=subdissector_handle;
			      p_tcap_context->subdissector_present=TRUE;
			    }
			  }
		  } /* context OID */
	  } else {
		  /* Copy the OID from the TCAP context to the current oid */
		  if (p_tcap_context->oid_present) {
			  tcap_private.oid= (void*) p_tcap_context->oid;
			  tcap_private.acv=TRUE;
		  }
	  } /* no OID */
  } /* no TCAP context */


  if ( p_tcap_context
       && p_tcap_context->subdissector_present) {
    /* Take the subdissector from the context */
    subdissector_handle=p_tcap_context->subdissector_handle;
    is_subdissector=TRUE;
  }

  /* Have SccpUsersTable protocol taking precedence over sccp.ssn table */
  if (!is_subdissector && requested_subdissector_handle) {
	  is_subdissector = TRUE;
	  subdissector_handle = requested_subdissector_handle;
  }

  if (!is_subdissector) {
    /*
     * If we do not currently know the subdissector, we have to find it
     * - first, according to the OID
     * - then according to the SSN
     * - and at least, take the default Data handler
     */
    if (ber_oid_dissector_table && cur_oid) {
      /* Search if we can find the sub protocol according to the A.C.N */
      if ( (subdissector_handle
	    = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
		  /* found */
		  is_subdissector=TRUE;
      } else {
		  /* Search if we can found the sub protocol according to the SSN table */
		  if ( (subdissector_handle
			  = get_itu_tcap_subdissector(actx->pinfo->match_uint))) {
			  /* Found according to SSN */
			  is_subdissector=TRUE;
		  } else {
			  /* Nothing found, take the Data handler */
			  subdissector_handle = data_handle;
			  is_subdissector=TRUE;
		  } /* SSN */
	  } /* ACN */
	} else {
		/* There is no A.C.N for this transaction, so search in the SSN table */
		if ( (subdissector_handle = get_itu_tcap_subdissector(actx->pinfo->match_uint))) {
			/* Found according to SSN */
			is_subdissector=TRUE;
		} else {
			subdissector_handle = data_handle;
			is_subdissector=TRUE;
		}
	} /* OID */
  } else {
	  /* We have it already */
  }

  /* Call the sub dissector if present, and not already called */
  if (is_subdissector) {
    call_dissector_with_data(subdissector_handle, tvb, actx->pinfo, tree, actx->value_ptr);
    col_set_fence(actx->pinfo->cinfo, COL_INFO);
  }

  return offset;
}

void call_tcap_dissector(dissector_handle_t handle, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree) {

	requested_subdissector_handle = handle;

	TRY {
		dissect_tcap(tvb, pinfo, tree);
	} CATCH_ALL {
		requested_subdissector_handle = NULL;
		RETHROW;
	} ENDTRY;

	requested_subdissector_handle = NULL;

}


