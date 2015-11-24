/* asn1.h
 * Common data for ASN.1
 * 2007  Anders Broman
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
 */

#ifndef __ASN1_H__
#define __ASN1_H__

#include "ws_symbol_export.h"

typedef enum {
  ASN1_ENC_BER,  /* X.690 - BER, CER, DER */
  ASN1_ENC_PER,  /* X.691 - PER */
  ASN1_ENC_ECN,  /* X.692 - ECN */
  ASN1_ENC_XER   /* X.693 - XER */
} asn1_enc_e;

typedef enum {
  CB_ASN1_ENC,
  CB_NEW_DISSECTOR,
  CB_DISSECTOR_HANDLE
} asn1_cb_variant;

typedef enum {
  ASN1_PAR_IRR, /* irrelevant parameter */
  /* value */
  ASN1_PAR_BOOLEAN,
  ASN1_PAR_INTEGER,
  /* type */
  ASN1_PAR_TYPE
} asn1_par_type;

typedef struct _asn1_par_def_t {
  const gchar *name;
  asn1_par_type ptype;
} asn1_par_def_t;

typedef struct _asn1_par_t {
  const gchar *name;
  asn1_par_type ptype;
  union {
    gboolean v_boolean;
    gint32 v_integer;
    void *v_type;
  } value;
  struct _asn1_par_t *next;
} asn1_par_t;

typedef struct _asn1_stack_frame_t {
  const gchar *name;
  struct _asn1_par_t *par;
  struct _asn1_stack_frame_t *next;
} asn1_stack_frame_t;

#define ASN1_CTX_SIGNATURE 0x41435458  /* "ACTX" */

typedef struct _asn1_ctx_t {
  guint32 signature;
  asn1_enc_e encoding;
  gboolean aligned;
  packet_info *pinfo;
  proto_item *created_item;
  struct _asn1_stack_frame_t *stack;
  void *value_ptr;
  void *private_data;
  struct {
    int hf_index;
    gboolean data_value_descr_present;
    gboolean direct_ref_present;
    gboolean indirect_ref_present;
    tvbuff_t *data_value_descriptor;
    const char *direct_reference;
    gint32 indirect_reference;
    gint encoding;
      /*
         0 : single-ASN1-type,
         1 : octet-aligned,
         2 : arbitrary
      */
    tvbuff_t *single_asn1_type;
    tvbuff_t *octet_aligned;
    tvbuff_t *arbitrary;
    union {
      struct {
        int (*ber_callback)(gboolean imp_tag, tvbuff_t *tvb, int offset, struct _asn1_ctx_t* ,proto_tree *tree, int hf_index );
      } ber;
      struct {
        int (*type_cb)(tvbuff_t*, int, struct _asn1_ctx_t*, proto_tree*, int);
      } per;
    } u;
  } external;
  struct {
      proto_tree *tree;
      proto_tree *top_tree;
      void* tree_ctx;
  } subtree;
  struct {
    int hf_index;
    gboolean data_value_descr_present;
    tvbuff_t *data_value_descriptor;
    gint identification;
      /*
         0 : syntaxes,
         1 : syntax,
         2 : presentation-context-id,
         3 : context-negotiation,
         4 : transfer-syntax,
         5 : fixed
      */
    gint32 presentation_context_id;
    const char *abstract_syntax;
    const char *transfer_syntax;
    tvbuff_t *data_value;
    union {
      struct {
        int (*ber_callback)(gboolean imp_tag, tvbuff_t *tvb, int offset, struct _asn1_ctx_t* ,proto_tree *tree, int hf_index );
      } ber;
      struct {
        int (*type_cb)(tvbuff_t*, int, struct _asn1_ctx_t*, proto_tree*, int);
      } per;
    } u;
  } embedded_pdv;
  struct _rose_ctx_t *rose_ctx;
} asn1_ctx_t;

#define ROSE_CTX_SIGNATURE 0x524F5345  /* "ROSE" */

typedef struct _rose_ctx_t {
  guint32 signature;
  dissector_table_t arg_global_dissector_table;
  dissector_table_t arg_local_dissector_table;
  dissector_table_t res_global_dissector_table;
  dissector_table_t res_local_dissector_table;
  dissector_table_t err_global_dissector_table;
  dissector_table_t err_local_dissector_table;
  /* filling in description into tree, info column, any buffer */
  int apdu_depth;
  gboolean fillin_info;
  gchar *fillin_ptr;
  gsize fillin_buf_size;
  struct {  /* "dynamic" data */
    gint pdu;
      /*
         1 : invoke,
         2 : returnResult,
         3 : returnError,
         4 : reject
      */
    gint code;
      /*
        -1 : none (optional in ReturnResult)
         0 : local,
         1 : global
      */
    gint32 code_local;
    const char *code_global;
    proto_item *code_item;
  } d;
  void *private_data;
} rose_ctx_t;

WS_DLL_PUBLIC void asn1_ctx_init(asn1_ctx_t *actx, asn1_enc_e encoding, gboolean aligned, packet_info *pinfo);
extern gboolean asn1_ctx_check_signature(asn1_ctx_t *actx);
extern void asn1_ctx_clean_external(asn1_ctx_t *actx);
extern void asn1_ctx_clean_epdv(asn1_ctx_t *actx);

extern void asn1_stack_frame_push(asn1_ctx_t *actx, const gchar *name);
extern void asn1_stack_frame_pop(asn1_ctx_t *actx, const gchar *name);
extern void asn1_stack_frame_check(asn1_ctx_t *actx, const gchar *name, const asn1_par_def_t *par_def);

extern void asn1_param_push_boolean(asn1_ctx_t *actx, gboolean value);
extern void asn1_param_push_integer(asn1_ctx_t *actx, gint32 value);
extern gboolean asn1_param_get_boolean(asn1_ctx_t *actx, const gchar *name);
extern gint32 asn1_param_get_integer(asn1_ctx_t *actx, const gchar *name);

WS_DLL_PUBLIC void rose_ctx_init(rose_ctx_t *rctx);
extern gboolean rose_ctx_check_signature(rose_ctx_t *rctx);
WS_DLL_PUBLIC void rose_ctx_clean_data(rose_ctx_t *rctx);

WS_DLL_PUBLIC asn1_ctx_t *get_asn1_ctx(void *ptr);
WS_DLL_PUBLIC rose_ctx_t *get_rose_ctx(void *ptr);

extern double asn1_get_real(const guint8 *real_ptr, gint len);

/* flags */
#define ASN1_EXT_ROOT 0x01
#define ASN1_EXT_EXT  0x02
#define ASN1_OPT      0x04
#define ASN1_DFLT     0x08

#define ASN1_HAS_EXT(f) ((f)&(ASN1_EXT_ROOT|ASN1_EXT_EXT))


#endif  /* __ASN1_H__ */
