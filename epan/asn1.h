/** @file
 *
 * Common data for ASN.1
 * 2007  Anders Broman
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __ASN1_H__
#define __ASN1_H__

#include "ws_symbol_export.h"

typedef enum {
  ASN1_ENC_BER,  /* X.690 - BER, CER, DER */
  ASN1_ENC_PER,  /* X.691 - PER */
  ASN1_ENC_ECN,  /* X.692 - ECN */
  ASN1_ENC_XER,  /* X.693 - XER */
  ASN1_ENC_OER   /* X.696 - OER */
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
  const char *name;
  asn1_par_type ptype;
} asn1_par_def_t;

typedef struct _asn1_par_t {
  const char *name;
  asn1_par_type ptype;
  union {
    bool v_boolean;
    int32_t v_integer;
    void *v_type;
  } value;
  struct _asn1_par_t *next;
} asn1_par_t;

typedef struct _asn1_stack_frame_t {
  const char *name;
  struct _asn1_par_t *par;
  struct _asn1_stack_frame_t *next;
} asn1_stack_frame_t;

#define ASN1_CTX_SIGNATURE 0x41435458  /* "ACTX" */

typedef struct _asn1_ctx_t {
  uint32_t signature;
  asn1_enc_e encoding;
  bool aligned;
  packet_info *pinfo;
  proto_item *created_item;
  struct _asn1_stack_frame_t *stack;
  void *value_ptr;
  void *private_data;
  struct {
    int hf_index;
    bool data_value_descr_present;
    bool direct_ref_present;
    bool indirect_ref_present;
    tvbuff_t *data_value_descriptor;
    const char *direct_reference;
    int32_t indirect_reference;
    int encoding;
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
        int (*ber_callback)(bool imp_tag, tvbuff_t *tvb, int offset, struct _asn1_ctx_t* ,proto_tree *tree, int hf_index );
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
    bool data_value_descr_present;
    tvbuff_t *data_value_descriptor;
    int identification;
      /*
         0 : syntaxes,
         1 : syntax,
         2 : presentation-context-id,
         3 : context-negotiation,
         4 : transfer-syntax,
         5 : fixed
      */
    int32_t presentation_context_id;
    const char *abstract_syntax;
    const char *transfer_syntax;
    tvbuff_t *data_value;
    union {
      struct {
        int (*ber_callback)(bool imp_tag, tvbuff_t *tvb, int offset, struct _asn1_ctx_t* ,proto_tree *tree, int hf_index );
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
  uint32_t signature;
  dissector_table_t arg_global_dissector_table;
  dissector_table_t arg_local_dissector_table;
  dissector_table_t res_global_dissector_table;
  dissector_table_t res_local_dissector_table;
  dissector_table_t err_global_dissector_table;
  dissector_table_t err_local_dissector_table;
  /* filling in description into tree, info column, any buffer */
  int apdu_depth;
  bool fillin_info;
  char *fillin_ptr;
  size_t fillin_buf_size;
  struct {  /* "dynamic" data */
    int pdu;
      /*
         1 : invoke,
         2 : returnResult,
         3 : returnError,
         4 : reject
      */
    int code;
      /*
        -1 : none (optional in ReturnResult)
         0 : local,
         1 : global
      */
    int32_t code_local;
    const char *code_global;
    proto_item *code_item;
  } d;
  void *private_data;
} rose_ctx_t;

WS_DLL_PUBLIC void asn1_ctx_init(asn1_ctx_t *actx, asn1_enc_e encoding, bool aligned, packet_info *pinfo);
extern bool asn1_ctx_check_signature(asn1_ctx_t *actx);
extern void asn1_ctx_clean_external(asn1_ctx_t *actx);
extern void asn1_ctx_clean_epdv(asn1_ctx_t *actx);

extern void asn1_stack_frame_push(asn1_ctx_t *actx, const char *name);
extern void asn1_stack_frame_pop(asn1_ctx_t *actx, const char *name);
extern void asn1_stack_frame_check(asn1_ctx_t *actx, const char *name, const asn1_par_def_t *par_def);

extern void asn1_param_push_boolean(asn1_ctx_t *actx, bool value);
extern void asn1_param_push_integer(asn1_ctx_t *actx, int32_t value);
extern bool asn1_param_get_boolean(asn1_ctx_t *actx, const char *name);
extern int32_t asn1_param_get_integer(asn1_ctx_t *actx, const char *name);

WS_DLL_PUBLIC void rose_ctx_init(rose_ctx_t *rctx);
extern bool rose_ctx_check_signature(rose_ctx_t *rctx);
WS_DLL_PUBLIC void rose_ctx_clean_data(rose_ctx_t *rctx);

WS_DLL_PUBLIC asn1_ctx_t *get_asn1_ctx(void *ptr);
WS_DLL_PUBLIC rose_ctx_t *get_rose_ctx(void *ptr);

extern double asn1_get_real(const uint8_t *real_ptr, int len);

/* flags */
#define ASN1_EXT_ROOT 0x01
#define ASN1_EXT_EXT  0x02
#define ASN1_OPT      0x04
#define ASN1_DFLT     0x08

#define ASN1_HAS_EXT(f) ((f)&(ASN1_EXT_ROOT|ASN1_EXT_EXT))


#endif  /* __ASN1_H__ */
