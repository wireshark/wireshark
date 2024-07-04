/* packet-tcap-template.c
 * Routines for  TCAP
 * Copyright 2004 - 2005, Tim Endean <endeant@hotmail.com>
 * Built from the gsm-map dissector Copyright 2004 - 2005, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * References: ETSI 300 374
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/address_types.h>
#include <epan/strutil.h>
#include <epan/show_exception.h>

#include "packet-ber.h"
#include "packet-tcap.h"
#include "packet-mtp3.h"


#define PNAME  "Transaction Capabilities Application Part"
#define PSNAME "TCAP"
#define PFNAME "tcap"

/* Initialize the protocol and registered fields */
static int proto_tcap;
static int hf_tcap_tag;
static int hf_tcap_length;
static int hf_tcap_data;
static int hf_tcap_tid;
static int hf_tcap_constructor_eoc;

int hf_tcapsrt_SessionId;
int hf_tcapsrt_Duplicate;
int hf_tcapsrt_BeginSession;
int hf_tcapsrt_EndSession;
int hf_tcapsrt_SessionTime;

#include "packet-tcap-hf.c"

/* Initialize the subtree pointers */
static int ett_tcap;
static int ett_param;

static int ett_otid;
static int ett_dtid;
int ett_tcap_stat;

static struct tcapsrt_info_t * gp_tcapsrt_info;
static bool tcap_subdissector_used=false;
static dissector_handle_t requested_subdissector_handle;

static int ss7pc_address_type = -1;

static struct tcaphash_context_t * gp_tcap_context;

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

/* These two timeout (in second) are used when some message are lost,
   or when the same TCAP transcation identifier is reused */
static unsigned gtcap_RepetitionTimeout = 10;
static unsigned gtcap_LostTimeout = 30;
static bool gtcap_PersistentSRT=false;
bool gtcap_DisplaySRT=false;
bool gtcap_StatSRT=false;

/* Global hash tables*/
static wmem_map_t *tcaphash_context;
static wmem_map_t *tcaphash_begin;
static wmem_map_t *tcaphash_cont;
static wmem_map_t *tcaphash_end;
static wmem_map_t *tcaphash_ansi;

static uint32_t tcapsrt_global_SessionId=1;

static dissector_handle_t tcap_handle;
static dissector_table_t ber_oid_dissector_table;
static const char * cur_oid;
static const char * tcapext_oid;
static proto_tree * tcap_top_tree;
static proto_tree * tcap_stat_tree;

static dissector_handle_t data_handle;
static dissector_handle_t ansi_tcap_handle;

static int dissect_tcap_param(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset);
static bool dissect_tcap_ITU_ComponentPDU(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);

static dissector_table_t ansi_sub_dissectors;
static dissector_table_t itu_sub_dissectors;

extern void add_ansi_tcap_subdissector(uint32_t ssn, dissector_handle_t dissector) {
  dissector_add_uint("ansi_tcap.ssn",ssn,dissector);
  dissector_add_uint("sccp.ssn",ssn,tcap_handle);
}

extern void add_itu_tcap_subdissector(uint32_t ssn, dissector_handle_t dissector) {
  dissector_add_uint("itu_tcap.ssn",ssn,dissector);
  dissector_add_uint("sccp.ssn",ssn,tcap_handle);
}

extern void delete_ansi_tcap_subdissector(uint32_t ssn, dissector_handle_t dissector) {
  dissector_delete_uint("ansi_tcap.ssn",ssn,dissector);
  if (!get_itu_tcap_subdissector(ssn))
      dissector_delete_uint("sccp.ssn",ssn,tcap_handle);
}
extern void delete_itu_tcap_subdissector(uint32_t ssn, dissector_handle_t dissector _U_) {
  dissector_delete_uint("itu_tcap.ssn",ssn,dissector);
  if (!get_ansi_tcap_subdissector(ssn))
    dissector_delete_uint("sccp.ssn", ssn,tcap_handle);
}

dissector_handle_t get_ansi_tcap_subdissector(uint32_t ssn) {
  return dissector_get_uint_handle(ansi_sub_dissectors, ssn);
}

dissector_handle_t get_itu_tcap_subdissector(uint32_t ssn) {
  return dissector_get_uint_handle(itu_sub_dissectors, ssn);
}

#include "packet-tcap-fn.c"

/*
 * DEBUG functions
 */
#undef DEBUG_TCAPSRT
/* #define DEBUG_TCAPSRT */

#ifdef DEBUG_TCAPSRT
#include <stdio.h>
#include <stdarg.h>
static unsigned debug_level = 99;

static void
dbg(unsigned level, const char* fmt, ...)
{
  va_list ap;

  if (level > debug_level) return;
  va_start(ap,fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}
#endif

static int
tcaphash_context_equal(const void *k1, const void *k2)
{
  const struct tcaphash_context_key_t *key1 = (const struct tcaphash_context_key_t *) k1;
  const struct tcaphash_context_key_t *key2 = (const struct tcaphash_context_key_t *) k2;

  return (key1->session_id == key2->session_id);
}

/* calculate a hash key */
static unsigned
tcaphash_context_calchash(const void *k)
{
  const struct tcaphash_context_key_t *key = (const struct tcaphash_context_key_t *) k;
  return key->session_id;
}


static int
tcaphash_begin_equal(const void *k1, const void *k2)
{
  const struct tcaphash_begin_info_key_t *key1 = (const struct tcaphash_begin_info_key_t *) k1;
  const struct tcaphash_begin_info_key_t *key2 = (const struct tcaphash_begin_info_key_t *) k2;

  if (key1->hashKey == key2->hashKey) {
    if ( (key1->pc_hash == key2->pc_hash) && (key1->tid == key2->tid) )
      return true;
  }
  return false;
}

/* calculate a hash key */
static unsigned
tcaphash_begin_calchash(const void *k)
{
  const struct tcaphash_begin_info_key_t *key = (const struct tcaphash_begin_info_key_t *) k;
  unsigned hashkey;
  /* hashkey = key->opc_hash<<16 + key->dpc_hash<<8 + key->src_tid; */
  hashkey = key->tid;
  return hashkey;
}

static int
tcaphash_cont_equal(const void *k1, const void *k2)
{
  const struct tcaphash_cont_info_key_t *key1 = (const struct tcaphash_cont_info_key_t *) k1;
  const struct tcaphash_cont_info_key_t *key2 = (const struct tcaphash_cont_info_key_t *) k2;

  if (key1->hashKey == key2->hashKey) {

    if ( (key1->opc_hash == key2->opc_hash) &&
         (key1->dpc_hash == key2->dpc_hash) &&
         (key1->src_tid == key2->src_tid) &&
         (key1->dst_tid == key2->dst_tid) ) {
      return true;
    }
    else if ( (key1->opc_hash == key2->dpc_hash) &&
              (key1->dpc_hash == key2->opc_hash) &&
              (key1->src_tid == key2->dst_tid) &&
              (key1->dst_tid == key2->src_tid) ) {
      return true;
    }
  }
  return false;
}

/* calculate a hash key */
static unsigned
tcaphash_cont_calchash(const void *k)
{
  const struct tcaphash_cont_info_key_t *key = (const struct tcaphash_cont_info_key_t *) k;
  unsigned hashkey;
  hashkey = key->src_tid + key->dst_tid;
  return hashkey;
}


static int
tcaphash_end_equal(const void *k1, const void *k2)
{
  const struct tcaphash_end_info_key_t *key1 = (const struct tcaphash_end_info_key_t *) k1;
  const struct tcaphash_end_info_key_t *key2 = (const struct tcaphash_end_info_key_t *) k2;

  if (key1->hashKey == key2->hashKey) {
    if ( (key1->opc_hash == key2->opc_hash) &&
         (key1->dpc_hash == key2->dpc_hash) &&
         (key1->tid == key2->tid) )
      return true;
  }
  return false;
}

/* calculate a hash key */
static unsigned
tcaphash_end_calchash(const void *k)
{
  const struct tcaphash_end_info_key_t *key = (const struct tcaphash_end_info_key_t *) k;
  unsigned hashkey;
  hashkey = key->tid;
  return hashkey;
}

static int
tcaphash_ansi_equal(const void *k1, const void *k2)
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
      return true;
  }
  return false;
}

/* calculate a hash key */
static unsigned
tcaphash_ansi_calchash(const void *k)
{
  const struct tcaphash_ansi_info_key_t *key = (const struct tcaphash_ansi_info_key_t *) k;
  unsigned hashkey;
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
  p_tcaphash_begincall->context->first_frame = pinfo->num;
  p_tcaphash_begincall->context->last_frame = 0;
  p_tcaphash_begincall->context->responded = false;
  p_tcaphash_begincall->context->begin_time = pinfo->abs_ts;
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

  p_new_tcaphash_begincall = wmem_new0(wmem_file_scope(), struct tcaphash_begincall_t);
  p_new_tcaphash_begincall->context=p_tcaphash_context;
  p_tcaphash_context->begincall=p_new_tcaphash_begincall;
  p_new_tcaphash_begincall->beginkey=prev_begincall->beginkey;
  p_new_tcaphash_begincall->context->first_frame = pinfo->num;
  p_new_tcaphash_begincall->next_begincall=NULL;
  p_new_tcaphash_begincall->previous_begincall=prev_begincall;
  p_new_tcaphash_begincall->father=false;

#ifdef DEBUG_TCAPSRT
  dbg(10,"+B%d ", p_new_tcaphash_begincall->context->session_id);
#endif
  /* Insert in the chained list */
  prev_begincall->next_begincall = p_new_tcaphash_begincall;
  if (prev_begincall->context->last_frame == 0) {
#ifdef DEBUG_TCAPSRT
    dbg(10,"last ");
#endif
    prev_begincall->context->last_frame = pinfo->num-1;
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
  p_tcaphash_ansicall->context->first_frame = pinfo->num;
  p_tcaphash_ansicall->context->last_frame = 0;
  p_tcaphash_ansicall->context->responded = false;
  p_tcaphash_ansicall->context->begin_time = pinfo->abs_ts;
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

  p_new_tcaphash_ansicall = wmem_new0(wmem_file_scope(), struct tcaphash_ansicall_t);
  p_new_tcaphash_ansicall->context=p_tcaphash_context;
  p_tcaphash_context->ansicall=p_new_tcaphash_ansicall;
  p_new_tcaphash_ansicall->ansikey=prev_ansicall->ansikey;
  p_new_tcaphash_ansicall->context->first_frame = pinfo->num;
  p_new_tcaphash_ansicall->next_ansicall=NULL;
  p_new_tcaphash_ansicall->previous_ansicall=prev_ansicall;
  p_new_tcaphash_ansicall->father=false;

#ifdef DEBUG_TCAPSRT
  dbg(10,"+A%d ", p_new_tcaphash_ansicall->context->session_id);
#endif
  /* Insert in the chained list */
  prev_ansicall->next_ansicall = p_new_tcaphash_ansicall;
  if (prev_ansicall->context->last_frame == 0) {
#ifdef DEBUG_TCAPSRT
    dbg(10,"last ");
#endif
    prev_ansicall->context->last_frame = pinfo->num-1;
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

  p_new_tcaphash_contcall = wmem_new0(wmem_file_scope(), struct tcaphash_contcall_t);
  p_new_tcaphash_contcall->context=p_tcaphash_context;
  p_tcaphash_context->contcall=p_new_tcaphash_contcall;
  p_new_tcaphash_contcall->contkey=prev_contcall->contkey;
  p_new_tcaphash_contcall->next_contcall=NULL;
  p_new_tcaphash_contcall->previous_contcall=prev_contcall;
  p_new_tcaphash_contcall->father=false;

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

  p_new_tcaphash_endcall = wmem_new0(wmem_file_scope(), struct tcaphash_endcall_t);
  p_new_tcaphash_endcall->context=p_tcaphash_context;
  p_tcaphash_context->endcall=p_new_tcaphash_endcall;
  p_new_tcaphash_endcall->endkey=prev_endcall->endkey;
  p_new_tcaphash_endcall->next_endcall=NULL;
  p_new_tcaphash_endcall->previous_endcall=prev_endcall;
  p_new_tcaphash_endcall->father=false;

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
                    packet_info *pinfo, bool isBegin)
{
  struct tcaphash_begincall_t *p_tcaphash_begincall = NULL;
  p_tcaphash_begincall = (struct tcaphash_begincall_t *)wmem_map_lookup(tcaphash_begin, p_tcaphash_begin_key);

  if(p_tcaphash_begincall) {
    do {
      if ( p_tcaphash_begincall->context ) {
        if ( ( isBegin &&
               pinfo->num == p_tcaphash_begincall->context->first_frame )
             ||
             ( !isBegin &&
               pinfo->num >= p_tcaphash_begincall->context->first_frame &&
               ( p_tcaphash_begincall->context->last_frame?pinfo->num <= p_tcaphash_begincall->context->last_frame:1 )
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
  p_tcaphash_contcall = (struct tcaphash_contcall_t *)wmem_map_lookup(tcaphash_cont, p_tcaphash_cont_key);

  if(p_tcaphash_contcall) {
    do {
      if ( p_tcaphash_contcall->context ) {
        if (pinfo->num >= p_tcaphash_contcall->context->first_frame &&
            (p_tcaphash_contcall->context->last_frame?pinfo->num <= p_tcaphash_contcall->context->last_frame:1) ) {
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
                  packet_info *pinfo, bool isEnd)
{
  struct tcaphash_endcall_t *p_tcaphash_endcall = NULL;
  p_tcaphash_endcall = (struct tcaphash_endcall_t *)wmem_map_lookup(tcaphash_end, p_tcaphash_end_key);

  if(p_tcaphash_endcall) {
    do {
      if ( p_tcaphash_endcall->context ) {
        if ( ( isEnd &&
               (p_tcaphash_endcall->context->last_frame?pinfo->num == p_tcaphash_endcall->context->last_frame:1)
               )
             ||
             ( !isEnd &&
               pinfo->num >= p_tcaphash_endcall->context->first_frame &&
               (p_tcaphash_endcall->context->last_frame?pinfo->num <= p_tcaphash_endcall->context->last_frame:1)
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

  p_new_tcaphash_context_key = wmem_new(wmem_file_scope(), struct tcaphash_context_key_t);
  p_new_tcaphash_context_key->session_id = p_tcaphash_context_key->session_id;

  p_new_tcaphash_context = wmem_new0(wmem_file_scope(), struct tcaphash_context_t);
  p_new_tcaphash_context->key = p_new_tcaphash_context_key;
  p_new_tcaphash_context->session_id = p_tcaphash_context_key->session_id;
  p_new_tcaphash_context->first_frame = pinfo->num;
#ifdef DEBUG_TCAPSRT
  dbg(10,"S%d ", p_new_tcaphash_context->session_id);
#endif
  /* store it */
  wmem_map_insert(tcaphash_context, p_new_tcaphash_context_key, p_new_tcaphash_context);
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

  p_new_tcaphash_begin_key = wmem_new(wmem_file_scope(), struct tcaphash_begin_info_key_t);
  p_new_tcaphash_begin_key->hashKey = p_tcaphash_begin_key->hashKey;
  p_new_tcaphash_begin_key->tid = p_tcaphash_begin_key->tid;
  p_new_tcaphash_begin_key->pc_hash = p_tcaphash_begin_key->pc_hash;

 p_new_tcaphash_begincall = wmem_new0(wmem_file_scope(), struct tcaphash_begincall_t);
  p_new_tcaphash_begincall->beginkey=p_new_tcaphash_begin_key;
  p_new_tcaphash_begincall->context=p_tcaphash_context;
  p_tcaphash_context->begincall=p_new_tcaphash_begincall;
  p_new_tcaphash_begincall->father=true;
  p_new_tcaphash_begincall->next_begincall=NULL;
  p_new_tcaphash_begincall->previous_begincall=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(10,"B%d ", p_new_tcaphash_begincall->context->session_id);
#endif
  /* store it */
  wmem_map_insert(tcaphash_begin, p_new_tcaphash_begin_key, p_new_tcaphash_begincall);
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

  p_new_tcaphash_cont_key = wmem_new(wmem_file_scope(), struct tcaphash_cont_info_key_t);
  p_new_tcaphash_cont_key->hashKey = p_tcaphash_cont_key->hashKey;
  p_new_tcaphash_cont_key->src_tid = p_tcaphash_cont_key->src_tid;
  p_new_tcaphash_cont_key->dst_tid = p_tcaphash_cont_key->dst_tid;
  p_new_tcaphash_cont_key->opc_hash = p_tcaphash_cont_key->opc_hash;
  p_new_tcaphash_cont_key->dpc_hash = p_tcaphash_cont_key->dpc_hash;

  p_new_tcaphash_contcall = wmem_new0(wmem_file_scope(), struct tcaphash_contcall_t);
  p_new_tcaphash_contcall->contkey=p_new_tcaphash_cont_key;
  p_new_tcaphash_contcall->context=p_tcaphash_context;
  p_tcaphash_context->contcall=p_new_tcaphash_contcall;
  p_new_tcaphash_contcall->father=true;
  p_new_tcaphash_contcall->next_contcall=NULL;
  p_new_tcaphash_contcall->previous_contcall=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(10,"C%d ", p_new_tcaphash_contcall->context->session_id);
#endif
  /* store it */
  wmem_map_insert(tcaphash_cont, p_new_tcaphash_cont_key, p_new_tcaphash_contcall);
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

  p_new_tcaphash_end_key = wmem_new(wmem_file_scope(), struct tcaphash_end_info_key_t);
  p_new_tcaphash_end_key->hashKey = p_tcaphash_end_key->hashKey;
  p_new_tcaphash_end_key->tid = p_tcaphash_end_key->tid;
  p_new_tcaphash_end_key->opc_hash = p_tcaphash_end_key->opc_hash;
  p_new_tcaphash_end_key->dpc_hash = p_tcaphash_end_key->dpc_hash;

  p_new_tcaphash_endcall = wmem_new0(wmem_file_scope(), struct tcaphash_endcall_t);
  p_new_tcaphash_endcall->endkey=p_new_tcaphash_end_key;
  p_new_tcaphash_endcall->context=p_tcaphash_context;
  p_tcaphash_context->endcall=p_new_tcaphash_endcall;
  p_new_tcaphash_endcall->father=true;
  p_new_tcaphash_endcall->next_endcall=NULL;
  p_new_tcaphash_endcall->previous_endcall=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(10,"E%d ", p_new_tcaphash_endcall->context->session_id);
#endif
  /* store it */
  wmem_map_insert(tcaphash_end, p_new_tcaphash_end_key, p_new_tcaphash_endcall);
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

  p_new_tcaphash_ansi_key = wmem_new(wmem_file_scope(), struct tcaphash_ansi_info_key_t);
  p_new_tcaphash_ansi_key->hashKey = p_tcaphash_ansi_key->hashKey;
  p_new_tcaphash_ansi_key->tid = p_tcaphash_ansi_key->tid;
  p_new_tcaphash_ansi_key->opc_hash = p_tcaphash_ansi_key->opc_hash;
  p_new_tcaphash_ansi_key->dpc_hash = p_tcaphash_ansi_key->dpc_hash;

  p_new_tcaphash_ansicall = wmem_new0(wmem_file_scope(), struct tcaphash_ansicall_t);
  p_new_tcaphash_ansicall->ansikey=p_new_tcaphash_ansi_key;
  p_new_tcaphash_ansicall->context=p_tcaphash_context;
  p_tcaphash_context->ansicall=p_new_tcaphash_ansicall;
  p_new_tcaphash_ansicall->father=true;
  p_new_tcaphash_ansicall->next_ansicall=NULL;
  p_new_tcaphash_ansicall->previous_ansicall=NULL;

#ifdef DEBUG_TCAPSRT
  dbg(10,"A%d ", p_new_tcaphash_ansicall->context->session_id);
#endif
  /* store it */
  wmem_map_insert(tcaphash_ansi, p_new_tcaphash_ansi_key, p_new_tcaphash_ansicall);
  return p_new_tcaphash_ansicall;
}

static struct tcaphash_contcall_t *
create_tcaphash_cont(struct tcaphash_cont_info_key_t *p_tcaphash_cont_key,
                     struct tcaphash_context_t *p_tcaphash_context)
{
  struct tcaphash_contcall_t *p_tcaphash_contcall1 = NULL;
  struct tcaphash_contcall_t *p_tcaphash_contcall = NULL;

  p_tcaphash_contcall1 = (struct tcaphash_contcall_t *)
    wmem_map_lookup(tcaphash_cont, p_tcaphash_cont_key);

  if (p_tcaphash_contcall1) {
    /* Walk through list of transaction with identical keys */
    /* go to the end to insert new record */
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
    wmem_map_lookup(tcaphash_end, p_tcaphash_end_key);

  if (p_tcaphash_endcall1) {
    /* Walk through list of transaction with identical keys */
    /* go to the end to insert new record */
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

#ifdef DEBUG_TCAPSRT
  dbg(51,"src %s srcTid %lx dst %s ", address_to_str(pinfo->pool, &pinfo->src), p_tcapsrt_info->src_tid, address_to_str(pinfo->pool, &pinfo->dst));
#endif

  /* prepare the key data */
  tcaphash_begin_key.tid = p_tcapsrt_info->src_tid;
  if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
  {
    /* We have MTP3 PCs (so we can safely do this cast) */
    tcaphash_begin_key.pc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
  } else {
    /* Don't have MTP3 PCs (have SCCP GT ?) */
    tcaphash_begin_key.pc_hash = g_str_hash(address_to_str(pinfo->pool, &pinfo->src));
  }
  tcaphash_begin_key.hashKey=tcaphash_begin_calchash(&tcaphash_begin_key);

  /* look up the request */
#ifdef DEBUG_TCAPSRT
  dbg(10,"\n Hbegin #%u ", pinfo->num);
  dbg(11,"key %lx ",tcaphash_begin_key.hashKey);
  dbg(51,"addr %s ", address_to_str(pinfo->pool, &pinfo->src));
  dbg(51,"Tid %lx \n",tcaphash_begin_key.tid);
#endif

  p_tcaphash_begincall = (struct tcaphash_begincall_t *)
  wmem_map_lookup(tcaphash_begin, &tcaphash_begin_key);

  if (p_tcaphash_begincall) {
    /* Walk through list of transaction with identical keys */
    do {
      /* Check if the request with this reqSeqNum has been seen, with the same Message Type */
      if (pinfo->num == p_tcaphash_begincall->context->first_frame) {
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
               && pinfo->num > p_tcaphash_begincall->context->first_frame
               && (unsigned) pinfo->abs_ts.secs > (unsigned)(p_tcaphash_begincall->context->begin_time.secs + gtcap_RepetitionTimeout)
               ) ||
             ( p_tcaphash_begincall->context->last_frame == 0
               && pinfo->num > p_tcaphash_begincall->context->first_frame
               && (unsigned)pinfo->abs_ts.secs > (unsigned)(p_tcaphash_begincall->context->begin_time.secs + gtcap_LostTimeout)
               )
             )
          {
            /* we decide that we have a new request */
            /* Append new record to the list */
#ifdef DEBUG_TCAPSRT
            dbg(12,"(timeout) Append key %lx ",tcaphash_begin_key.hashKey);
            dbg(12,"Frame %u rsp %u ",pinfo->num,p_tcaphash_begincall->context->last_frame );
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
            dbg(12,"Frame %u rsp %u ",pinfo->num,p_tcaphash_begincall->context->last_frame );
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
              proto_item_set_generated(stat_item);
              pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_Duplicate, tvb, 0, 0,
                                              p_tcaphash_context->first_frame,
                                              "Duplicate with session %u in frame %u",
                                              p_tcaphash_context->session_id,p_tcaphash_context->first_frame);
              proto_item_set_generated(pi);
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
    dbg(11,"Frame reqlink #%u ", pinfo->num);
#endif
    update_tcaphash_begincall(p_tcaphash_begincall, pinfo);
  }

  /* display tcap session, if available */
  if ( gtcap_DisplaySRT && tree &&
       p_tcaphash_context &&
       p_tcaphash_context->session_id) {
    stat_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_tcap_stat, &stat_item, "Stat");
    proto_item_set_generated(stat_item);
    pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
    proto_item_set_generated(pi);

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
      proto_item_set_generated(pi);
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
  bool use_dst = false;

#ifdef DEBUG_TCAPSRT
  dbg(51,"src %s srcTid %lx dst %s dstTid %lx ", address_to_str(pinfo->pool, &pinfo->src), p_tcapsrt_info->src_tid, address_to_str(pinfo->pool, &pinfo->dst), p_tcapsrt_info->dst_tid);
  dbg(10,"\n Hcont #%u ", pinfo->num);
#endif

  /* look only for matching request, if matching conversation is available. */
  tcaphash_cont_key.src_tid = p_tcapsrt_info->src_tid;
  tcaphash_cont_key.dst_tid = p_tcapsrt_info->dst_tid;
  if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
  {
    /* We have MTP3 PCs (so we can safely do this cast) */
    tcaphash_cont_key.opc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
    tcaphash_cont_key.dpc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
  } else {
    /* Don't have MTP3 PCs (have SCCP GT ?) */
    tcaphash_cont_key.opc_hash = g_str_hash(address_to_str(pinfo->pool, &pinfo->src));
    tcaphash_cont_key.dpc_hash = g_str_hash(address_to_str(pinfo->pool, &pinfo->dst));
  }
  tcaphash_cont_key.hashKey=tcaphash_cont_calchash(&tcaphash_cont_key);

#ifdef DEBUG_TCAPSRT
  dbg(11,"Ckey %lx ", tcaphash_cont_key.hashKey);
  dbg(51,"addr %s %s ", address_to_str(pinfo->pool, &pinfo->src), address_to_str(pinfo->pool, &pinfo->dst));
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
    /* Find the TCAP transaction according to the TC_BEGIN (from dtid,dst) */
    tcaphash_begin_key.tid = p_tcapsrt_info->dst_tid;
    if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
    {
      /* We have MTP3 PCs (so we can safely do this cast) */
      tcaphash_begin_key.pc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
    } else {
      /* Don't have MTP3 PCs (have SCCP GT ?) */
      tcaphash_begin_key.pc_hash = g_str_hash(address_to_str(pinfo->pool, &pinfo->dst));
    }
    tcaphash_begin_key.hashKey=tcaphash_begin_calchash(&tcaphash_begin_key);

#ifdef DEBUG_TCAPSRT
    dbg(11,"Bkey %lx ", tcaphash_begin_key.hashKey);
    dbg(51,"addr %s ", address_to_str(pinfo->pool, &pinfo->dst));
    dbg(51,"Tid %lx \n",tcaphash_begin_key.tid);
#endif
    p_tcaphash_begincall = find_tcaphash_begin(&tcaphash_begin_key, pinfo, false);
    if(!p_tcaphash_begincall){
      try_src:
/* can this actually happen? */
#ifdef DEBUG_TCAPSRT
        dbg(12,"BNotFound trying stid,src");
#endif
        /* Do we have a continue from the same source? (stid,src) */
        use_dst = true;
        tcaphash_begin_key.tid = p_tcapsrt_info->src_tid;
        if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
        {
          /* We have MTP3 PCs (so we can safely do this cast) */
          tcaphash_begin_key.pc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
        } else {
          /* Don't have MTP3 PCs (have SCCP GT ?) */
          tcaphash_begin_key.pc_hash = g_str_hash(address_to_str(pinfo->pool, &pinfo->src));
        }
        tcaphash_begin_key.hashKey=tcaphash_begin_calchash(&tcaphash_begin_key);
#ifdef DEBUG_TCAPSRT
        dbg(11,"Bkey %lx ", tcaphash_begin_key.hashKey);
        dbg(51,"addr %s ", address_to_str(pinfo->pool, &pinfo->src));
        dbg(51,"Tid %lx \n",tcaphash_begin_key.tid);
#endif
        p_tcaphash_begincall = find_tcaphash_begin(&tcaphash_begin_key, pinfo,false);
    }
    if(p_tcaphash_begincall &&
       !p_tcaphash_begincall->context->contcall ) {
#ifdef DEBUG_TCAPSRT
      dbg(12,"BFound \n");
#endif
      p_tcaphash_context=p_tcaphash_begincall->context;
      p_tcaphash_context->responded=true;

#ifdef DEBUG_TCAPSRT
      dbg(10,"New Ckey %lx ",tcaphash_cont_key.hashKey);
      dbg(11,"Frame reqlink #%u \n", pinfo->num);
#endif
      create_tcaphash_cont(&tcaphash_cont_key,
                           p_tcaphash_begincall->context);

      /* Create END for (stid,src) or (dtid,dst) */
      tcaphash_end_key.tid = use_dst ? p_tcapsrt_info->dst_tid : p_tcapsrt_info->src_tid;
      if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
      {
        /* We have MTP3 PCs (so we can safely do this cast) */
        tcaphash_end_key.dpc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)(use_dst ? pinfo->dst.data : pinfo->src.data));
        tcaphash_end_key.opc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)(use_dst ? pinfo->src.data : pinfo->dst.data));
    } else {
        /* Don't have MTP3 PCs (have SCCP GT ?) */
        tcaphash_end_key.dpc_hash = g_str_hash(address_to_str(pinfo->pool, use_dst ? &pinfo->dst : &pinfo->src));
        tcaphash_end_key.opc_hash = g_str_hash(address_to_str(pinfo->pool, use_dst ? &pinfo->src : &pinfo->dst));
    }
      tcaphash_end_key.hashKey=tcaphash_end_calchash(&tcaphash_end_key);

#ifdef DEBUG_TCAPSRT
      dbg(10,"New Ekey %lx ",tcaphash_end_key.hashKey);
      dbg(51,"addr %s ", address_to_str(pinfo->pool, use_dst ? &pinfo->dst : &pinfo->src));
      dbg(51,"Tid %lx ",tcaphash_end_key.tid);
      dbg(11,"Frame reqlink #%u ", pinfo->num);
#endif
      create_tcaphash_end(&tcaphash_end_key,
                          p_tcaphash_begincall->context);

    } else { /* Begin not found */
#ifdef DEBUG_TCAPSRT
      dbg(12,"BnotFound ");
#endif
      if (!use_dst) {
        /* make another try with src tid / address */
        goto try_src;
      }
    } /* begin found */
  } /* cont found */
    /* display tcap session, if available */
  if (gtcap_DisplaySRT && tree &&
      p_tcaphash_context &&
      p_tcaphash_context->session_id) {
    stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
    proto_item_set_generated(stat_item);
    pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
    proto_item_set_generated(pi);
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
  dbg(51,"src %s dst %s dstTid %lx ", address_to_str(pinfo->pool, &pinfo->src), address_to_str(pinfo->pool, &pinfo->dst), p_tcapsrt_info->dst_tid);
  dbg(10,"\n Hend #%u ", pinfo->num);
#endif
  /* look only for matching request, if matching conversation is available. */
  tcaphash_end_key.tid = p_tcapsrt_info->dst_tid;
  if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
  {
    /* We have MTP3 PCs (so we can safely do this cast) */
    tcaphash_end_key.opc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
    tcaphash_end_key.dpc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
  } else {
    /* Don't have MTP3 PCs (have SCCP GT ?) */
    tcaphash_end_key.opc_hash = g_str_hash(address_to_str(pinfo->pool, &pinfo->src));
    tcaphash_end_key.dpc_hash = g_str_hash(address_to_str(pinfo->pool, &pinfo->dst));
}
  tcaphash_end_key.hashKey=tcaphash_end_calchash(&tcaphash_end_key);

#ifdef DEBUG_TCAPSRT
  dbg(11,"Ekey %lx ",tcaphash_end_key.hashKey);
  dbg(11,"addr %s ", address_to_str(pinfo->pool, &pinfo->dst));
  dbg(51,"Tid %lx ",tcaphash_end_key.tid);
#endif
  p_tcaphash_endcall = find_tcaphash_end(&tcaphash_end_key, pinfo,true);

  if(!p_tcaphash_endcall) {
#ifdef DEBUG_TCAPSRT
    dbg(12,"EnotFound ");
#endif
    tcaphash_begin_key.tid = p_tcapsrt_info->dst_tid;
    if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
    {
      /* We have MTP3 PCs (so we can safely do this cast) */
      tcaphash_begin_key.pc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
    } else {
      /* Don't have MTP3 PCs (have SCCP GT ?) */
      tcaphash_begin_key.pc_hash = g_str_hash(address_to_str(pinfo->pool, &pinfo->dst));
    }
    tcaphash_begin_key.hashKey=tcaphash_begin_calchash(&tcaphash_begin_key);

#ifdef DEBUG_TCAPSRT
    dbg(11,"Bkey %lx ", tcaphash_begin_key.hashKey);
    dbg(51,"addr %s ", address_to_str(pinfo->pool, &pinfo->dst));
    dbg(51,"Tid %lx ",tcaphash_begin_key.tid);
#endif
    p_tcaphash_begincall = find_tcaphash_begin(&tcaphash_begin_key, pinfo,false);
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
      proto_item_set_generated(stat_item);

      pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
      proto_item_set_generated(pi);
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
      proto_item_set_generated(pi);
      /* Calculate Service Response Time */
      nstime_delta(&delta, &pinfo->abs_ts, &p_tcaphash_context->begin_time);

      /* display Service Response Time and make it filterable */
      pi = proto_tree_add_time(stat_tree, hf_tcapsrt_SessionTime, tvb, 0, 0, &delta);
      proto_item_set_generated(pi);
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
  bool isResponse=false;
  proto_tree * stat_tree=NULL;
  proto_item * stat_item=NULL;

  /* prepare the key data */
  tcaphash_ansi_key.tid = p_tcapsrt_info->src_tid;
  if (pinfo->src.type == ss7pc_address_type && pinfo->dst.type == ss7pc_address_type)
  {
    /* We have MTP3 PCs (so we can safely do this cast) */
    tcaphash_ansi_key.opc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->src.data);
    tcaphash_ansi_key.dpc_hash = mtp3_pc_hash((const mtp3_addr_pc_t *)pinfo->dst.data);
  } else {
    /* Don't have MTP3 PCs (have SCCP GT ?) */
    tcaphash_ansi_key.opc_hash = g_str_hash(address_to_str(pinfo->pool, &pinfo->src));
    tcaphash_ansi_key.dpc_hash = g_str_hash(address_to_str(pinfo->pool, &pinfo->dst));
  }
  tcaphash_ansi_key.hashKey=tcaphash_ansi_calchash(&tcaphash_ansi_key);

  /* look up the request */
#ifdef DEBUG_TCAPSRT
  dbg(10,"\n Hansi #%u ", pinfo->num);
  dbg(11,"key %lx ",tcaphash_ansi_key.hashKey);
  dbg(51,"PC %s %s ",address_to_str(pinfo->pool, &pinfo->src), address_to_str(pinfo->pool, &pinfo->dst));
  dbg(51,"Tid %lx ",tcaphash_ansi_key.tid);
#endif
  p_tcaphash_ansicall = (struct tcaphash_ansicall_t *)
    wmem_map_lookup(tcaphash_ansi, &tcaphash_ansi_key);

  if (p_tcaphash_ansicall) {
    /* Walk through list of transaction with identical keys */
    do {
      /* Check if the request with this reqSeqNum has been seen */
      if (pinfo->num == p_tcaphash_ansicall->context->first_frame) {
        /* We have seen this request before -> do nothing */
#ifdef DEBUG_TCAPSRT
        dbg(22,"Request already seen ");
#endif
        isResponse=false;
        p_tcaphash_context=p_tcaphash_ansicall->context;
        break;
      }

      /* Check if the response with this reqSeqNum has been seen */
      if (pinfo->num == p_tcaphash_ansicall->context->last_frame) {
        /* We have seen this response before -> do nothing */
#ifdef DEBUG_TCAPSRT
        dbg(22,"Response already seen ");
#endif
        isResponse=true;
        p_tcaphash_context=p_tcaphash_ansicall->context;
        break;
      }

      /* Check for the first Request without Response
       received before this frame */
      if ( pinfo->num > p_tcaphash_ansicall->context->first_frame &&
           p_tcaphash_ansicall->context->last_frame==0 ) {
        /* Take it, and update the context */

#ifdef DEBUG_TCAPSRT
        dbg(12,"Update key %lx ",tcaphash_ansi_key.hashKey);
#endif
        p_tcaphash_ansicall->context->last_frame = pinfo->num;
        p_tcaphash_ansicall->context->responded = true;
        p_tcaphash_ansicall->context->closed = true;
        p_tcaphash_context=p_tcaphash_ansicall->context;
        isResponse=true;

        if (gtcap_DisplaySRT && tree) {
          stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
          proto_item_set_generated(stat_item);

          pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
          proto_item_set_generated(pi);

#ifdef DEBUG_TCAPSRT
          dbg(20,"Display framereqlink %d ",p_tcaphash_context->first_frame);
#endif
          /* Indicate the frame to which this is a reply. */
          pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_EndSession, tvb, 0, 0,
                                          p_tcaphash_context->first_frame,
                                          "Begin of session in frame %u",
                                          p_tcaphash_context->first_frame);
          proto_item_set_generated(pi);
          /* Calculate Service Response Time */
          nstime_delta(&delta, &pinfo->abs_ts, &p_tcaphash_context->begin_time);

          /* display Service Response Time and make it filterable */
          pi = proto_tree_add_time(stat_tree, hf_tcapsrt_SessionTime, tvb, 0, 0, &delta);
          proto_item_set_generated(pi);
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
               && pinfo->num > p_tcaphash_ansicall->context->first_frame
               && (unsigned) pinfo->abs_ts.secs > (unsigned)(p_tcaphash_ansicall->context->begin_time.secs + gtcap_RepetitionTimeout)
               ) ||
             ( p_tcaphash_ansicall->context->last_frame == 0
               && pinfo->num > p_tcaphash_ansicall->context->first_frame
               && (unsigned)pinfo->abs_ts.secs > (unsigned)(p_tcaphash_ansicall->context->begin_time.secs + gtcap_LostTimeout)
               )
             )
          {
            /* we decide that we have a new request */
            /* Append new record to the list */
#ifdef DEBUG_TCAPSRT
            dbg(12,"(timeout) Append key %lx ",tcaphash_ansi_key.hashKey);
            dbg(12,"Frame %u rsp %u ",pinfo->num,p_tcaphash_ansicall->context->last_frame );
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
            dbg(12,"Frame %u rsp %u ",pinfo->num,p_tcaphash_ansicall->context->last_frame );
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
              proto_item_set_generated(stat_item);

              pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
              proto_item_set_generated(pi);

#ifdef DEBUG_TCAPSRT
              dbg(20,"Display framereqlink %d ",p_tcaphash_context->first_frame);
#endif
              /* Indicate the frame to which this is a reply. */
              pi = proto_tree_add_uint_format(stat_tree, hf_tcapsrt_EndSession, tvb, 0, 0,
                                              p_tcaphash_context->first_frame,
                                              "Begin of session in frame %u",
                                              p_tcaphash_context->first_frame);
              proto_item_set_generated(pi);
              /* Calculate Service Response Time */
              nstime_delta(&delta, &pinfo->abs_ts, &p_tcaphash_context->begin_time);

              /* display Service Response Time and make it filterable */
              pi = proto_tree_add_time(stat_tree, hf_tcapsrt_SessionTime, tvb, 0, 0, &delta);
              proto_item_set_generated(pi);
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
    dbg(11,"Frame reqlink #%u ", pinfo->num);
#endif
    update_tcaphash_ansicall(p_tcaphash_ansicall, pinfo);
  }

  /* display tcap session, if available */
  if ( gtcap_DisplaySRT && tree &&
       p_tcaphash_context &&
       p_tcaphash_context->session_id) {
    stat_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_tcap_stat, &stat_item, "Stat");
    proto_item_set_generated(stat_item);
    pi = proto_tree_add_uint(stat_tree, hf_tcapsrt_SessionId, tvb, 0,0, p_tcaphash_context->session_id);
    proto_item_set_generated(pi);
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
      proto_item_set_generated(pi);
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
        proto_item_set_generated(pi);
        /* Calculate Service Response Time */
        nstime_delta(&delta, &pinfo->abs_ts, &p_tcaphash_context->begin_time);

        /* display Service Response Time and make it filterable */
        pi = proto_tree_add_time(stat_tree, hf_tcapsrt_SessionTime, tvb, 0, 0, &delta);
        proto_item_set_generated(pi);
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
  if(pinfo == NULL || pinfo->num == 0) {
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
    p_tcaphash_context->responded=true;
    p_tcaphash_context->last_frame = pinfo->num;
    p_tcaphash_context->end_time = pinfo->abs_ts;
    p_tcaphash_context->closed=true;

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
          wmem_map_remove(tcaphash_end, p_tcaphash_context->endcall->endkey);
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
        wmem_map_remove(tcaphash_end, p_tcaphash_context->endcall->endkey);

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
          wmem_map_remove(tcaphash_cont, p_tcaphash_context->contcall->contkey);
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
        wmem_map_remove(tcaphash_cont, p_tcaphash_context->contcall->contkey);
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
          wmem_map_remove(tcaphash_begin, p_tcaphash_context->begincall->beginkey);
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
        wmem_map_remove(tcaphash_begin, p_tcaphash_context->begincall->beginkey);
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
          wmem_map_remove(tcaphash_ansi, p_tcaphash_context->ansicall->ansikey);
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
        wmem_map_remove(tcaphash_ansi, p_tcaphash_context->ansicall->ansikey);
      } /* ansicall without chained string */
    } /* no ansicall */

    if (!gtcap_PersistentSRT) {
#ifdef DEBUG_TCAPSRT
      dbg(20,"remove context ");
#endif
      wmem_map_remove(tcaphash_context, p_tcaphash_context->key);
    }
  } else { /* no context */
#ifdef DEBUG_TCAPSRT
    dbg(20,"No context to remove ");
#endif
  }
}

const value_string tcap_component_type_str[] = {
  { TCAP_COMP_INVOKE, "Invoke" },
  { TCAP_COMP_RRL,    "Return Result(L)" },
  { TCAP_COMP_RE,     "Return Error" },
  { TCAP_COMP_REJECT, "Reject" },
  { TCAP_COMP_RRN,    "Return Result(NL)" },
  { 0,                NULL }
};

static int
dissect_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
  proto_item *item=NULL;
  proto_tree *tree=NULL;

  struct tcaphash_context_t * p_tcap_context;
  dissector_handle_t subdissector_handle;
  asn1_ctx_t asn1_ctx;
  int8_t ber_class;
  bool pc;
  int tag;
  struct tcap_private_t *p_tcap_private;

  /* Check if ANSI TCAP and call the ANSI TCAP dissector if that's the case
   * PackageType ::= CHOICE { unidirectional            [PRIVATE 1] IMPLICIT UniTransactionPDU,
   *                          queryWithPerm             [PRIVATE 2] IMPLICIT TransactionPDU,
   *                          queryWithoutPerm          [PRIVATE 3] IMPLICIT TransactionPDU,
   *                          response                  [PRIVATE 4] IMPLICIT TransactionPDU,
   *                          conversationWithPerm      [PRIVATE 5] IMPLICIT TransactionPDU,
   *                          conversationWithoutPerm   [PRIVATE 6] IMPLICIT TransactionPDU,
   *                          abort                     [PRIVATE 22] IMPLICIT Abort
   *                          }
   *
   *
   */
  get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);

  if(ber_class == BER_CLASS_PRI){
    switch (tag){

    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 22:
      return call_dissector(ansi_tcap_handle, tvb, pinfo, parent_tree);

    default:
      return tvb_captured_length(tvb);
    }
  }

  /* ITU TCAP */
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

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

  p_tcap_private = wmem_new0(pinfo->pool, struct tcap_private_t);
  asn1_ctx.value_ptr = p_tcap_private;
  gp_tcapsrt_info=tcapsrt_razinfo();
  tcap_subdissector_used=false;
  gp_tcap_context=NULL;
  dissect_tcap_TCMessage(false, tvb, 0, &asn1_ctx, tree, -1);

  if (!tcap_subdissector_used ) {
    p_tcap_context=tcapsrt_call_matching(tvb, pinfo, tcap_stat_tree, gp_tcapsrt_info);
    p_tcap_private->context=p_tcap_context;

    /* If the current message is TCAP only,
     * save the Application Context Name for the next messages
     */
    if ( p_tcap_context && cur_oid && !p_tcap_context->oid_present ) {
      /* Save the application context and the sub dissector */
      (void) g_strlcpy(p_tcap_context->oid, cur_oid, sizeof(p_tcap_context->oid));
      p_tcap_context->oid_present=true;
      if ( (subdissector_handle = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
        p_tcap_context->subdissector_handle=subdissector_handle;
        p_tcap_context->subdissector_present=true;
      }
    }
    if (p_tcap_context && p_tcap_context->callback) {
      /* Callback function for the upper layer */
      (p_tcap_context->callback)(tvb, pinfo, tcap_stat_tree, p_tcap_context);
    }
  }
  return tvb_captured_length(tvb);
}

void
proto_reg_handoff_tcap(void)
{

  data_handle = find_dissector("data");
  ansi_tcap_handle = find_dissector_add_dependency("ansi_tcap", proto_tcap);
  ber_oid_dissector_table = find_dissector_table("ber.oid");

  ss7pc_address_type = address_type_get_by_name("AT_SS7PC");

#include "packet-tcap-dis-tab.c"
}

static void init_tcap(void);
static void cleanup_tcap(void);

void
proto_register_tcap(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_tcap_tag,
      { "Tag",
        "tcap.msgtype",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_tcap_length,
      { "Length",
        "tcap.len",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_tcap_data,
      { "Data",
        "tcap.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_tcap_tid,
      { "Transaction Id",
         "tcap.tid",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_tcap_constructor_eoc,
      { "CONSTRUCTOR EOC",
         "tcap.constructor_eoc",
        FT_UINT16, BASE_HEX, NULL, 0,
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
  static int *ett[] = {
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

  ansi_sub_dissectors = register_dissector_table("ansi_tcap.ssn", "ANSI SSN", proto_tcap, FT_UINT8, BASE_DEC);
  itu_sub_dissectors = register_dissector_table("itu_tcap.ssn", "ITU SSN", proto_tcap, FT_UINT8, BASE_DEC);

  tcap_module = prefs_register_protocol(proto_tcap, NULL);

#if 0
  prefs_register_enum_preference(tcap_module, "standard", "ITU TCAP standard",
                                 "The SS7 standard used in ITU TCAP packets",
                                 &tcap_standard, tcap_options, false);
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
  range_convert_str(wmem_epan_scope(), &global_ssn_range, "", MAX_SSN);

  prefs_register_range_preference(tcap_module, "ssn", "SCCP SSNs",
                                  "SCCP (and SUA) SSNs to decode as TCAP",
                                  &global_ssn_range, MAX_SSN);

  prefs_register_obsolete_preference(tcap_module, "srt");

  prefs_register_bool_preference(tcap_module, "persistentsrt",
                                 "Persistent stats for SRT",
                                 "Statistics for Response Time",
                                 &gtcap_PersistentSRT);

  prefs_register_uint_preference(tcap_module, "repetitiontimeout",
                                 "Repetition timeout",
                                 "Maximal delay for message repetition",
                                 10, &gtcap_RepetitionTimeout);

  prefs_register_uint_preference(tcap_module, "losttimeout",
                                 "Lost timeout",
                                 "Maximal delay for message lost",
                                 10, &gtcap_LostTimeout);

  /* 'globally' register dissector */
  tcap_handle = register_dissector("tcap", dissect_tcap, proto_tcap);

  /* hash-tables for SRT */
  tcaphash_context = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), tcaphash_context_calchash, tcaphash_context_equal);
  tcaphash_begin   = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), tcaphash_begin_calchash, tcaphash_begin_equal);
  tcaphash_cont    = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), tcaphash_cont_calchash, tcaphash_cont_equal);
  tcaphash_end     = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), tcaphash_end_calchash, tcaphash_end_equal);
  tcaphash_ansi    = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), tcaphash_ansi_calchash, tcaphash_ansi_equal);

  register_init_routine(&init_tcap);
  register_cleanup_routine(&cleanup_tcap);
}


static void range_delete_callback(uint32_t ssn, void *ptr _U_)
{
  if ( ssn && !get_ansi_tcap_subdissector(ssn) && !get_itu_tcap_subdissector(ssn) ) {
    dissector_delete_uint("sccp.ssn", ssn, tcap_handle);
  }
}

static void range_add_callback(uint32_t ssn, void *ptr _U_)
{
  if (ssn && !get_ansi_tcap_subdissector(ssn) && !get_itu_tcap_subdissector(ssn) ) {
    dissector_add_uint("sccp.ssn", ssn, tcap_handle);
  }
}


static void init_tcap(void)
{
  ssn_range = range_copy(wmem_epan_scope(), global_ssn_range);
  range_foreach(ssn_range, range_add_callback, NULL);

  /* Reset the session counter */
  tcapsrt_global_SessionId=1;

  /* Display of SRT is enabled
   * 1) For wireshark only if Persistent Stat is enabled
   * 2) For tshark, if the CLI SRT tap is registered
   */
  gtcap_DisplaySRT=gtcap_PersistentSRT || gtcap_StatSRT;
}

static void cleanup_tcap(void)
{
  range_foreach(ssn_range, range_delete_callback, NULL);
  wmem_free(wmem_epan_scope(), ssn_range);
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_tcap_param(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset)
{
  int tag_offset, saved_offset, len_offset;
  tvbuff_t *next_tvb;
  proto_tree *subtree;
  int8_t ber_class;
  bool pc;
  int32_t tag;
  uint32_t len;
  uint32_t tag_length;
  uint32_t len_length;
  bool ind_field;

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

      if (len - (ind_field ? 2 : 0)) /*should always be positive unless we get an empty constructor pointless? */
      {
        next_tvb = tvb_new_subset_length(tvb, offset, len - (ind_field ? 2 : 0));
        increment_dissection_depth(actx->pinfo);
        dissect_tcap_param(actx, subtree,next_tvb,0);
        decrement_dissection_depth(actx->pinfo);
      }

      if (ind_field)
        proto_tree_add_item(subtree, hf_tcap_constructor_eoc, tvb, offset+len-2, 2, ENC_BIG_ENDIAN);

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
        dissect_ber_octet_string(true, actx, tree, next_tvb, 0,
          hf_tcap_data, NULL);
      }

      offset += len;
    }
  }
  return offset;
}

/*
 * Call ITU Subdissector to decode the Tcap Component
 */
static bool
dissect_tcap_ITU_ComponentPDU(bool implicit_tag _U_, tvbuff_t *tvb, int offset _U_, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_)
{
  dissector_handle_t subdissector_handle=NULL;
  bool is_subdissector=false;
  struct tcaphash_context_t * p_tcap_context=NULL;
  struct tcap_private_t *p_tcap_private = (struct tcap_private_t*)actx->value_ptr;

  /*
   * ok lets look at the oid and ssn and try and find a dissector, otherwise lets decode it.
   */

  /*
   * Handle The TCAP Service Response Time
   */
  if (!tcap_subdissector_used) {
    p_tcap_context=tcapsrt_call_matching(tvb, actx->pinfo, tcap_stat_tree, gp_tcapsrt_info);
    tcap_subdissector_used=false;
    gp_tcap_context=p_tcap_context;
    p_tcap_private->context=p_tcap_context;
  } else {
    /* Take the last TCAP context */
    p_tcap_context = gp_tcap_context;
    p_tcap_private->context=p_tcap_context;
  }
  if (p_tcap_context) {
      if (cur_oid) {
          if (p_tcap_context->oid_present) {
              /* We have already an Application Context, check if we have
                 to fallback to a lower version */
              if (strncmp(p_tcap_context->oid, cur_oid, sizeof(p_tcap_context->oid)) != 0) {
                  /* ACN, changed, Fallback to lower version
                   * and update the subdissector (purely formal)
                   */
                  (void) g_strlcpy(p_tcap_context->oid, cur_oid, sizeof(p_tcap_context->oid));
                  if ((subdissector_handle = dissector_get_string_handle(ber_oid_dissector_table, cur_oid))) {
                      p_tcap_context->subdissector_handle = subdissector_handle;
                      p_tcap_context->subdissector_present = true;
                  }
              }
          } else {
              /* We do not have the OID in the TCAP context, so store it */
              (void) g_strlcpy(p_tcap_context->oid, cur_oid, sizeof(p_tcap_context->oid));
              p_tcap_context->oid_present = true;
              /* Try to find a subdissector according to OID */
              if ((subdissector_handle
                  = dissector_get_string_handle(ber_oid_dissector_table, cur_oid))) {
                  p_tcap_context->subdissector_handle = subdissector_handle;
                  p_tcap_context->subdissector_present = true;
              } else {
                  /* Not found, so try to find a subdissector according to SSN */
                  if ((subdissector_handle = get_itu_tcap_subdissector(actx->pinfo->match_uint))) {
                      /* Found according to SSN */
                      p_tcap_context->subdissector_handle = subdissector_handle;
                      p_tcap_context->subdissector_present = true;
                  }
              }
          } /* context OID */
      } else {
          /* Copy the OID from the TCAP context to the current oid */
          if (p_tcap_context->oid_present) {
              p_tcap_private->oid = (void*)p_tcap_context->oid;
              p_tcap_private->acv = true;
          }
      } /* no OID */
  } /* no TCAP context */


  if (p_tcap_context
      && p_tcap_context->subdissector_present) {
      /* Take the subdissector from the context */
      subdissector_handle = p_tcap_context->subdissector_handle;
      is_subdissector = true;
  }

  /* Have SccpUsersTable protocol taking precedence over sccp.ssn table */
  if (!is_subdissector && requested_subdissector_handle) {
      is_subdissector = true;
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
          if ((subdissector_handle
              = dissector_get_string_handle(ber_oid_dissector_table, cur_oid))) {
              /* found */
              is_subdissector = true;
          } else {
              /* Search if we can found the sub protocol according to the SSN table */
              if ((subdissector_handle
                  = get_itu_tcap_subdissector(actx->pinfo->match_uint))) {
                  /* Found according to SSN */
                  is_subdissector = true;
              } else {
                  /* Nothing found, take the Data handler */
                  subdissector_handle = data_handle;
                  is_subdissector = true;
              } /* SSN */
          } /* ACN */
      } else {
          /* There is no A.C.N for this transaction, so search in the SSN table */
          if ((subdissector_handle = get_itu_tcap_subdissector(actx->pinfo->match_uint))) {
              /* Found according to SSN */
              is_subdissector = true;
          } else {
              subdissector_handle = data_handle;
              is_subdissector = true;
          }
      } /* OID */
  } else {
      /* We have it already */
  }

  /* Call the sub dissector if present, and not already called */
  if (is_subdissector) {
      bool is_active = call_dissector_only(subdissector_handle, tvb, actx->pinfo, tree, actx->value_ptr);
      col_set_fence(actx->pinfo->cinfo, COL_INFO);
      if(!is_active){
          return false;
    }
  }
  return true;
}

void
call_tcap_dissector(dissector_handle_t handle, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
  requested_subdissector_handle = handle;

  TRY {
    dissect_tcap(tvb, pinfo, tree, NULL);
  } CATCH_ALL {
    requested_subdissector_handle = NULL;
    RETHROW;
  } ENDTRY;

  requested_subdissector_handle = NULL;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
