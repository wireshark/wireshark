/* packet-sscop.c
 * Routines for SSCOP (Q.2110, Q.SAAL) frame disassembly
 * Guy Harris <guy@alum.mit.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

#include <wiretap/wtap.h>
#include "packet-sscop.h"

void proto_register_sscop(void);
void proto_reg_handoff_sscop(void);

int proto_sscop = -1;

static int hf_sscop_type = -1;
static int hf_sscop_sq = -1;
static int hf_sscop_mr = -1;
static int hf_sscop_s = -1;
static int hf_sscop_ps = -1;
static int hf_sscop_r = -1;
static int hf_sscop_stat_s = -1;
static int hf_sscop_pad_length = -1;
static int hf_sscop_source = -1;
/* static int hf_sscop_stat_count = -1; */

static gint ett_sscop = -1;
static gint ett_stat = -1;

static dissector_handle_t q2931_handle;
static dissector_handle_t data_handle;
static dissector_handle_t sscf_nni_handle;
static dissector_handle_t alcap_handle;
static dissector_handle_t nbap_handle;

static dissector_handle_t sscop_handle;


static const enum_val_t sscop_payload_dissector_options[] = {
  { "data",     "Data (no further dissection)", DATA_DISSECTOR },
  { "Q.2931",   "Q.2931",                       Q2931_DISSECTOR },
  { "SSCF-NNI", "SSCF-NNI (MTP3-b)",            SSCF_NNI_DISSECTOR },
  { "ALCAP",    "ALCAP",                        ALCAP_DISSECTOR },
  { "NBAP",     "NBAP",                         NBAP_DISSECTOR },
  { NULL,       NULL,                           0 }
};

static guint sscop_payload_dissector = Q2931_DISSECTOR;
static dissector_handle_t default_handle;

static sscop_info_t sscop_info;
/*
 * See
 *
 *   http://web.archive.org/web/20150408122122/http://www.protocols.com/pbook/atmsig.htm
 *
 * for some information on SSCOP, although, alas, not the actual PDU
 * type values - those I got from the FreeBSD 3.2 ATM code.
 */

/*
 * SSCOP PDU types.
 */
#define SSCOP_TYPE_MASK 0x0f

#define SSCOP_BGN       0x01    /* Begin */
#define SSCOP_BGAK      0x02    /* Begin Acknowledge */
#define SSCOP_END       0x03    /* End */
#define SSCOP_ENDAK     0x04    /* End Acknowledge */
#define SSCOP_RS        0x05    /* Resynchronization */
#define SSCOP_RSAK      0x06    /* Resynchronization Acknowledge */
#define SSCOP_BGREJ     0x07    /* Begin Reject */
#define SSCOP_SD        0x08    /* Sequenced Data */
#if 0
#define SSCOP_SDP       0x09    /* Sequenced Data with Poll */
#endif
#define SSCOP_ER        0x09    /* Error Recovery */
#define SSCOP_POLL      0x0a    /* Status Request */
#define SSCOP_STAT      0x0b    /* Solicited Status Response */
#define SSCOP_USTAT     0x0c    /* Unsolicited Status Response */
#define SSCOP_UD        0x0d    /* Unnumbered Data */
#define SSCOP_MD        0x0e    /* Management Data */
#define SSCOP_ERAK      0x0f    /* Error Acknowledge */

#define SSCOP_S         0x10    /* Source bit in End PDU */

/*
 * XXX - how to distinguish SDP from ER?
 */
static const value_string sscop_type_vals[] = {
  { SSCOP_BGN,   "Begin" },
  { SSCOP_BGAK,  "Begin Acknowledge" },
  { SSCOP_END,   "End" },
  { SSCOP_ENDAK, "End Acknowledge" },
  { SSCOP_RS,    "Resynchronization" },
  { SSCOP_RSAK,  "Resynchronization Acknowledge" },
  { SSCOP_BGREJ, "Begin Reject" },
  { SSCOP_SD,    "Sequenced Data" },
#if 0
  { SSCOP_SDP,   "Sequenced Data with Poll" },
#endif
  { SSCOP_ER,    "Error Recovery" },
  { SSCOP_POLL,  "Status Request" },
  { SSCOP_STAT,  "Solicited Status Response" },
  { SSCOP_USTAT, "Unsolicited Status Response" },
  { SSCOP_UD,    "Unnumbered Data" },
  { SSCOP_MD,    "Management Data" },
  { SSCOP_ERAK,  "Error Acknowledge" },
  { 0,            NULL }
};
static value_string_ext sscop_type_vals_ext = VALUE_STRING_EXT_INIT(sscop_type_vals);

/*
 * The SSCOP "header" is a trailer, so the "offsets" are computed based
 * on the length of the packet.
 */

/*
 * PDU type.
 */
#define SSCOP_PDU_TYPE  (reported_length - 4)   /* single byte */

/*
 * Begin PDU, Begin Acknowledge PDU (no N(SQ) in it), Resynchronization
 * PDU, Resynchronization Acknowledge PDU (no N(SQ) in it in Q.SAAL),
 * Error Recovery PDU, Error Recovery Acknoledge PDU (no N(SQ) in it).
 */
#define SSCOP_N_SQ      (reported_length - 5)   /* One byte */
#define SSCOP_N_MR      (reported_length - 4)   /* lower 3 bytes thereof */

/*
 * Sequenced Data PDU (no N(PS) in it), Sequenced Data with Poll PDU,
 * Poll PDU.
 */
#define SSCOP_N_PS      (reported_length - 8)   /* lower 3 bytes thereof */
#define SSCOP_N_S       (reported_length - 4)   /* lower 3 bytes thereof */

/*
 * Solicited Status PDU, Unsolicited Status PDU (no N(PS) in it).
 */
#define SSCOP_SS_N_PS   (reported_length - 12)  /* lower 3 bytes thereof */
#define SSCOP_SS_N_MR   (reported_length - 8)   /* lower 3 bytes thereof */
#define SSCOP_SS_N_R    (reported_length - 4)   /* lower 3 bytes thereof */

static void dissect_stat_list(proto_tree *tree, tvbuff_t *tvb,guint h) {
  gint n,i;

  if ((n = (tvb_reported_length(tvb))/4 - h)) {
    tree = proto_tree_add_subtree(tree,tvb,0,n*4,ett_stat,NULL,"SD List");

    for (i = 0; i < n; i++) {
      proto_tree_add_item(tree, hf_sscop_stat_s, tvb, i*4 + 1,3,ENC_BIG_ENDIAN);
    }
  }
}

extern void
dissect_sscop_and_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dissector_handle_t payload_handle)
{
  guint reported_length;
  proto_item *ti;
  proto_tree *sscop_tree = NULL;
  guint8 sscop_pdu_type;
  int pdu_len;
  int pad_len;
  tvbuff_t *next_tvb;

  reported_length = tvb_reported_length(tvb);   /* frame length */
  sscop_pdu_type = tvb_get_guint8(tvb, SSCOP_PDU_TYPE);
  sscop_info.type = sscop_pdu_type & SSCOP_TYPE_MASK;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSCOP");
  col_add_str(pinfo->cinfo, COL_INFO, val_to_str_ext(sscop_info.type, &sscop_type_vals_ext,
                                                 "Unknown PDU type (0x%02x)"));

  /*
   * Find the length of the PDU and, if there's any payload and
   * padding, the length of the padding.
   */
  switch (sscop_info.type) {

  case SSCOP_SD:
    pad_len = (sscop_pdu_type >> 6) & 0x03;
    pdu_len = 4;
    break;

  case SSCOP_BGN:
  case SSCOP_BGAK:
  case SSCOP_BGREJ:
  case SSCOP_END:
  case SSCOP_RS:
#if 0
  case SSCOP_SDP:
#endif
    pad_len = (sscop_pdu_type >> 6) & 0x03;
    sscop_info.payload_len = pdu_len = 8;
    break;

  case SSCOP_UD:
    pad_len = (sscop_pdu_type >> 6) & 0x03;
    sscop_info.payload_len = pdu_len = 4;
    break;

  default:
    pad_len = 0;
    pdu_len = reported_length;  /* No payload, just SSCOP */
    sscop_info.payload_len = 0;
    break;
  }

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_sscop, tvb,
                                        reported_length - pdu_len,
                                        pdu_len, "SSCOP");
    sscop_tree = proto_item_add_subtree(ti, ett_sscop);

    proto_tree_add_item(sscop_tree, hf_sscop_type, tvb, SSCOP_PDU_TYPE, 1,ENC_BIG_ENDIAN);

    switch (sscop_info.type) {

    case SSCOP_BGN:
    case SSCOP_RS:
    case SSCOP_ER:
      proto_tree_add_item(sscop_tree, hf_sscop_sq, tvb, SSCOP_N_SQ, 1,ENC_BIG_ENDIAN);
      proto_tree_add_item(sscop_tree, hf_sscop_mr, tvb, SSCOP_N_MR + 1, 3, ENC_BIG_ENDIAN);
      break;

    case SSCOP_END:
      proto_tree_add_string(sscop_tree, hf_sscop_source, tvb, SSCOP_PDU_TYPE, 1,
                                (sscop_pdu_type & SSCOP_S) ? "SSCOP" : "User");
      break;

    case SSCOP_BGAK:
    case SSCOP_RSAK:
      proto_tree_add_item(sscop_tree, hf_sscop_mr, tvb, SSCOP_N_MR + 1, 3, ENC_BIG_ENDIAN);
      break;

    case SSCOP_ERAK:
      proto_tree_add_item(sscop_tree, hf_sscop_mr, tvb, SSCOP_N_MR + 1, 3, ENC_BIG_ENDIAN);
      break;

    case SSCOP_SD:
      proto_tree_add_item(sscop_tree, hf_sscop_s, tvb, SSCOP_N_S + 1, 3, ENC_BIG_ENDIAN);
      break;

#if 0
    case SSCOP_SDP:
#endif
    case SSCOP_POLL:
      proto_tree_add_item(sscop_tree, hf_sscop_ps, tvb, SSCOP_N_PS + 1, 3,ENC_BIG_ENDIAN);
      proto_tree_add_item(sscop_tree, hf_sscop_s, tvb, SSCOP_N_S + 1, 3,ENC_BIG_ENDIAN);
      break;

    case SSCOP_STAT:
      proto_tree_add_item(sscop_tree, hf_sscop_ps, tvb, SSCOP_SS_N_PS + 1, 3,ENC_BIG_ENDIAN);
      proto_tree_add_item(sscop_tree, hf_sscop_mr, tvb, SSCOP_SS_N_MR + 1, 3, ENC_BIG_ENDIAN);
      proto_tree_add_item(sscop_tree, hf_sscop_r, tvb, SSCOP_SS_N_R + 1, 3,ENC_BIG_ENDIAN);
      dissect_stat_list(sscop_tree,tvb,3);
      break;

    case SSCOP_USTAT:
      proto_tree_add_item(sscop_tree, hf_sscop_mr, tvb, SSCOP_SS_N_MR + 1, 3, ENC_BIG_ENDIAN);
      proto_tree_add_item(sscop_tree, hf_sscop_r, tvb, SSCOP_SS_N_R + 1, 3,ENC_BIG_ENDIAN);
      dissect_stat_list(sscop_tree,tvb,2);
      break;
    }
  }

  /*
   * Dissect the payload, if any.
   *
   * XXX - what about a Management Data PDU?
   */
  switch (sscop_info.type) {

  case SSCOP_SD:
  case SSCOP_UD:
  case SSCOP_BGN:
  case SSCOP_BGAK:
  case SSCOP_BGREJ:
  case SSCOP_END:
  case SSCOP_RS:
#if 0
  case SSCOP_SDP:
#endif
    if (tree) {
      proto_tree_add_uint(sscop_tree, hf_sscop_pad_length, tvb, SSCOP_PDU_TYPE, 1, pad_len);
    }

    /*
     * Compute length of data in PDU - subtract the trailer length
     * and the pad length from the reported length.
     */
    reported_length -= (pdu_len + pad_len);

    if (reported_length != 0) {
      /*
       * We know that we have all of the payload, because we know we have
       * at least 4 bytes of data after the payload, i.e. the SSCOP trailer.
       * Therefore, we know that the captured length of the payload is
       * equal to the length of the payload.
       */
      next_tvb = tvb_new_subset_length(tvb, 0, reported_length);
      if (sscop_info.type == SSCOP_SD)
      {
        call_dissector(payload_handle, next_tvb, pinfo, tree);
      }
    break;
  }
}
}

static int dissect_sscop(tvbuff_t* tvb, packet_info* pinfo,proto_tree* tree, void* data _U_)
{
  struct _sscop_payload_info  *p_sscop_info;
  dissector_handle_t subdissector;

  /* Look for packet info for subdissector information */
  p_sscop_info = (struct _sscop_payload_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_sscop, 0);

  if ( p_sscop_info
       && ( subdissector = p_sscop_info->subdissector )
       && ( subdissector == data_handle
            || subdissector == q2931_handle
            || subdissector == sscf_nni_handle
            || subdissector == alcap_handle
            || subdissector == nbap_handle) )
    dissect_sscop_and_payload(tvb,pinfo,tree,subdissector);
  else
    dissect_sscop_and_payload(tvb,pinfo,tree,default_handle);

  return tvb_captured_length(tvb);
}

/* Make sure handles for various protocols are initialized */
static void initialize_handles_once(void) {
  static gboolean initialized = FALSE;
  if (!initialized) {
    q2931_handle = find_dissector("q2931");
    data_handle = find_dissector("data");
    sscf_nni_handle = find_dissector("sscf-nni");
    alcap_handle = find_dissector("alcap");
    nbap_handle = find_dissector("nbap");

    initialized = TRUE;
  }
}

gboolean sscop_allowed_subdissector(dissector_handle_t handle)
{
  initialize_handles_once();
  if (handle == q2931_handle || handle == data_handle
      || handle == sscf_nni_handle || handle == alcap_handle
      || handle == nbap_handle)
    return TRUE;
  return FALSE;
}

void
proto_reg_handoff_sscop(void)
{
  static gboolean prefs_initialized = FALSE;

  if (!prefs_initialized) {
    initialize_handles_once();
    dissector_add_uint_range_with_preference("udp.port", "", sscop_handle);
    dissector_add_uint("atm.aal5.type", TRAF_SSCOP, sscop_handle);

    prefs_initialized = TRUE;
  }

  switch(sscop_payload_dissector) {
  case DATA_DISSECTOR:     default_handle = data_handle;     break;
  case Q2931_DISSECTOR:    default_handle = q2931_handle;    break;
  case SSCF_NNI_DISSECTOR: default_handle = sscf_nni_handle; break;
  case ALCAP_DISSECTOR:    default_handle = alcap_handle;    break;
  case NBAP_DISSECTOR:     default_handle = nbap_handle;     break;
  }

}

void
proto_register_sscop(void)
{
  static hf_register_info hf[] = {
    { &hf_sscop_type, { "PDU Type", "sscop.type", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &sscop_type_vals_ext, SSCOP_TYPE_MASK, NULL, HFILL }},
    { &hf_sscop_sq, { "N(SQ)", "sscop.sq", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_sscop_mr, { "N(MR)", "sscop.mr", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_sscop_s, { "N(S)", "sscop.s", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_sscop_ps, { "N(PS)", "sscop.ps", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_sscop_r, { "N(R)", "sscop.r", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_sscop_stat_s, { "N(S)", "sscop.stat.s", FT_UINT24, BASE_DEC, NULL, 0x0,NULL, HFILL }},
    { &hf_sscop_pad_length, { "Pad length", "sscop.pad_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_sscop_source, { "Source", "sscop.source", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
#if 0
    { &hf_sscop_stat_count, { "Number of NACKed pdus", "sscop.stat.count", FT_UINT32, BASE_DEC, NULL, 0x0,NULL, HFILL }}
#endif
  };

  static gint *ett[] = {
    &ett_sscop,
    &ett_stat
  };

  module_t *sscop_module;

  proto_sscop = proto_register_protocol("SSCOP", "SSCOP", "sscop");
  proto_register_field_array(proto_sscop, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  sscop_handle = register_dissector("sscop", dissect_sscop, proto_sscop);

  sscop_module = prefs_register_protocol(proto_sscop, proto_reg_handoff_sscop);

  prefs_register_enum_preference(sscop_module, "payload",
                                 "SSCOP payload protocol",
                                 "SSCOP payload (dissector to call on SSCOP payload)",
                                 (gint *)&sscop_payload_dissector,
                                 sscop_payload_dissector_options, FALSE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
