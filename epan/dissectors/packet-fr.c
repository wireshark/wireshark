/* packet-fr.c
 * Routines for Frame Relay  dissection
 *
 * Copyright 2001, Paul Ionescu <paul@acorp.ro>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References:
 *
 * https://web.archive.org/web/20150510093619/http://www.protocols.com/pbook/frame.htm
 * https://www.broadband-forum.org/wp-content/uploads/2018/12/FRF.3.2.pdf
 * ITU Recommendations Q.922 and Q.933
 * RFC-1490
 * RFC-2427
 * Cisco encapsulation
 * https://web.archive.org/web/20030422173700/https://www.trillium.com/assets/legacyframe/white_paper/8771019.pdf
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/arptypes.h>
#include <wiretap/wtap.h>

#include "packet-llc.h"
#include "packet-chdlc.h"
#include "packet-eth.h"
#include "packet-ip.h"
#include "packet-ppp.h"
#include "packet-juniper.h"
#include "packet-sflow.h"
#include "packet-l2tp.h"
#include <epan/xdlc.h>
#include <epan/etypes.h>
#include <epan/nlpid.h>

void proto_register_fr(void);
void proto_reg_handoff_fr(void);

/*
 * Bits in the address field.
 */
#define FRELAY_EA               0x01    /* Address field extension bit */

#define FRELAY_UPPER_DLCI       0xFC    /* Upper DLCI */
#define FRELAY_CR               0x02    /* Command/response bit in first octet */

#define FRELAY_SECOND_DLCI      0xF0    /* DLCI bits in FECN/BECN/DE octet */
#define FRELAY_FECN             0x08    /* Forward Explicit Congestion Notification */
#define FRELAY_BECN             0x04    /* Backward Explicit Congestion Notification */
#define FRELAY_DE               0x02    /* Discard Eligibility */

#define FRELAY_THIRD_DLCI       0xFE    /* DLCI bits in third octet, if any */

#define FRELAY_LOWER_DLCI       0xFC    /* Lower DLCI */
#define FRELAY_DC               0x02    /* DLCI or DL-CORE control indicator in last octet */

#define FROM_DCE                0x80    /* for direction setting */

static gint proto_fr              = -1;
static gint ett_fr                = -1;
static gint ett_fr_address        = -1;
static gint ett_fr_control        = -1;
static gint hf_fr_ea              = -1;
static gint hf_fr_upper_dlci      = -1;
static gint hf_fr_cr              = -1;
static gint hf_fr_second_dlci     = -1;
static gint hf_fr_fecn            = -1;
static gint hf_fr_becn            = -1;
static gint hf_fr_de              = -1;
static gint hf_fr_third_dlci      = -1;
static gint hf_fr_dlcore_control  = -1;
static gint hf_fr_lower_dlci      = -1;
static gint hf_fr_dc              = -1;
static gint hf_fr_dlci            = -1;
static gint hf_fr_control         = -1;
static gint hf_fr_n_r             = -1;
static gint hf_fr_n_s             = -1;
static gint hf_fr_p               = -1;
static gint hf_fr_p_ext           = -1;
static gint hf_fr_f               = -1;
static gint hf_fr_f_ext           = -1;
static gint hf_fr_s_ftype         = -1;
static gint hf_fr_u_modifier_cmd  = -1;
static gint hf_fr_u_modifier_resp = -1;
static gint hf_fr_ftype_i         = -1;
static gint hf_fr_ftype_s_u       = -1;
static gint hf_fr_ftype_s_u_ext   = -1;
static gint hf_fr_nlpid           = -1;
static gint hf_fr_oui             = -1;
static gint hf_fr_pid             = -1;
static gint hf_fr_snaptype        = -1;
static gint hf_fr_chdlctype       = -1;
static gint hf_fr_first_addr_octet  = -1;
static gint hf_fr_second_addr_octet  = -1;
static gint hf_fr_third_addr_octet  = -1;

static expert_field ei_fr_bogus_address = EI_INIT;
static expert_field ei_fr_frame_relay_lapf = EI_INIT;
static expert_field ei_fr_frame_relay_xid = EI_INIT;

static dissector_handle_t eth_withfcs_handle;
static dissector_handle_t gprs_ns_handle;
static dissector_handle_t lapb_handle;
static dissector_handle_t data_handle;
static dissector_handle_t fr_handle;

static capture_dissector_handle_t chdlc_cap_handle;
static capture_dissector_handle_t eth_cap_handle;

static dissector_table_t chdlc_subdissector_table;
static dissector_table_t osinl_incl_subdissector_table;
static dissector_table_t ethertype_subdissector_table;

/*
 * Encapsulation type.
 * XXX - this should be per-DLCI as well.
 */
#define FRF_3_2         0       /* FRF 3.2 or Cisco HDLC */
#define GPRS_NS         1       /* GPRS Network Services (3GPP TS 08.16) */
#define RAW_ETHER       2       /* Raw Ethernet */
#define LAPB            3       /* T.617a-1994 Annex G encapsuation of LAPB */

static gint fr_encap = FRF_3_2;

static const true_false_string ctrl_string = {
  "DLCI Address",
  "Control"
};
static const true_false_string ea_string = {
  "Last Octet",
  "More Follows"
};

/*
 * This isn't the same as "nlpid_vals[]"; 0x08 is Q.933, not Q.931,
 * and 0x09 is LMI, not Q.2931, and we assume that it's an initial
 * protocol identifier, so 0x01 is T.70, not X.29.
 */
static const value_string fr_nlpid_vals[] = {
  { NLPID_NULL,            "NULL" },
  { NLPID_IPI_T_70,        "T.70" },  /* XXX - IPI, or SPI? */
  { NLPID_X_633,           "X.633" },
  { NLPID_Q_931,           "Q.933" },
  { NLPID_LMI,             "LMI" },
  { NLPID_Q_2119,          "Q.2119" },
  { NLPID_SNAP,            "SNAP" },
  { NLPID_ISO8473_CLNP,    "CLNP" },
  { NLPID_ISO9542_ESIS,    "ESIS" },
  { NLPID_ISO10589_ISIS,   "ISIS" },
  { NLPID_ISO10747_IDRP,   "IDRP" },
  { NLPID_ISO9542X25_ESIS, "ESIS (X.25)" },
  { NLPID_ISO10030,        "ISO 10030" },
  { NLPID_ISO11577,        "ISO 11577" },
  { NLPID_COMPRESSED,      "Data compression protocol" },
  { NLPID_IP,              "IP" },
  { NLPID_IP6,             "IPv6" },
  { NLPID_PPP,             "PPP" },
  { 0,                     NULL },
};

static dissector_table_t fr_subdissector_table;
static dissector_table_t fr_osinl_subdissector_table;

static void dissect_fr_nlpid(tvbuff_t *tvb, int offset, packet_info *pinfo,
                             proto_tree *tree, proto_item *ti,
                             proto_tree *fr_tree, guint8 fr_ctrl);
static void dissect_lapf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_fr_xid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Used only for U frames */
static const xdlc_cf_items fr_cf_items = {
  NULL,
  NULL,
  &hf_fr_p,
  &hf_fr_f,
  NULL,
  &hf_fr_u_modifier_cmd,
  &hf_fr_u_modifier_resp,
  NULL,
  &hf_fr_ftype_s_u
};

/* Used only for I and S frames */
static const xdlc_cf_items fr_cf_items_ext = {
  &hf_fr_n_r,
  &hf_fr_n_s,
  &hf_fr_p_ext,
  &hf_fr_f_ext,
  &hf_fr_s_ftype,
  NULL,
  NULL,
  &hf_fr_ftype_i,
  &hf_fr_ftype_s_u_ext
};

static gboolean
capture_fr(const guchar *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
  guint8  fr_octet;
  guint32 addr;
  guint8  fr_ctrl;
  guint8  fr_nlpid;

  /*
   * OK, fetch the address field - keep going until we get an EA bit.
   */
  if (!BYTES_ARE_IN_FRAME(offset, len, 1))
    return FALSE;

  fr_octet = pd[offset];
  if (fr_octet & FRELAY_EA) {
    /*
     * Bogus!  There should be at least 2 octets.
     * XXX - is this FRF.12 frame relay fragmentation?  If so, can
     * we handle that?
     */
     return FALSE;
  }
  /*
   * The first octet contains the upper 6 bits of the DLCI, as well
   * as the C/R bit.
   */
  addr = (fr_octet & FRELAY_UPPER_DLCI) >> 2;
  offset++;

  /*
   * The second octet contains 4 more bits of DLCI, as well as FECN,
   * BECN, and DE.
   */
  if (!BYTES_ARE_IN_FRAME(offset, len, 1))
    return FALSE;

  fr_octet = pd[offset];
  addr = (addr << 4) | ((fr_octet & FRELAY_SECOND_DLCI) >> 4);
  offset++;

  if (!(fr_octet & FRELAY_EA)) {
    /*
     * We have 3 or more address octets.
     *
     * The third octet contains 7 more bits of DLCI if EA isn't set,
     * and lower DLCI or DL-CORE control plus the DLCI or DL-CORE
     * control indicator flag if EA is set.
     */
    if (!BYTES_ARE_IN_FRAME(offset, len, 1))
      return FALSE;

    fr_octet = pd[offset];
    if (!(fr_octet & FRELAY_EA)) {
      /*
       * 7 more bits of DLCI.
       */
      addr = (addr << 7) | ((fr_octet & FRELAY_THIRD_DLCI) >> 1);
      offset++;
      if (!BYTES_ARE_IN_FRAME(offset, len, 1))
        return FALSE;

      fr_octet = pd[offset];
      while (!(fr_octet & FRELAY_EA)) {
        /*
         * Bogus!  More than 4 octets of address.
         */
        offset++;
        if (!BYTES_ARE_IN_FRAME(offset, len, 1))
          return FALSE;

        fr_octet = pd[offset];
      }
    }

    /*
     * Last octet - contains lower DLCI or DL-CORE control, DLCI or
     * DL-CORE control indicator flag.
     */
    if (fr_octet & FRELAY_DC) {
      /*
       * DL-CORE.
       */
    } else {
      /*
       * Last 6 bits of DLCI.
       */
      addr = (addr << 6) | ((fr_octet & FRELAY_LOWER_DLCI) >> 2);
    }
  }

  switch (fr_encap) {

  case FRF_3_2:
    if (!BYTES_ARE_IN_FRAME(offset, len, 1))
      return FALSE;

    fr_ctrl = pd[offset];
    if (fr_ctrl == XDLC_U) {
      offset++;

      /*
       * XXX - treat DLCI 0 specially?  On DLCI 0, an NLPID of 0x08
       * means Q.933, but on other circuits it could be the "for
       * protocols which do not have an NLPID assigned or do not
       * have a SNAP encapsulation" stuff from RFC 2427.
       */
      if (!BYTES_ARE_IN_FRAME(offset, len, 1))
        return FALSE;

      fr_nlpid = pd[offset];
      if (fr_nlpid == 0) {
        offset++;
        if (!BYTES_ARE_IN_FRAME(offset, len, 1))
          return FALSE;

        fr_nlpid = pd[offset];
      }
      offset++;
      return try_capture_dissector("fr.nlpid", fr_nlpid, pd, offset, len, cpinfo, pseudo_header);
    } else {
      if (addr == 0) {
        /*
         * This must be some sort of LAPF on DLCI 0 for SVC
         * because DLCI 0 is reserved for LMI and SVC signaling
         * encapsulated in LAPF, and LMI is transmitted in
         * unnumbered information (03), so this must be LAPF
         * (guessing).
         *
         * XXX - but what is it?  Is Q.933 carried inside UI
         * frames or other types of frames or both?
         */
        return FALSE;
      }
      if (fr_ctrl == (XDLC_U|XDLC_XID)) {
        /*
         * XID.
         */
        return FALSE;
      }

      /*
       * If the data does not start with unnumbered information (03) and
       * the DLCI# is not 0, then there may be Cisco Frame Relay encapsulation.
       */
      return call_capture_dissector(chdlc_cap_handle, pd, offset, len, cpinfo, pseudo_header);
    }
    break;

  case GPRS_NS:
    return FALSE;

  case RAW_ETHER:
    if (addr != 0)
      return call_capture_dissector(eth_cap_handle, pd, offset, len, cpinfo, pseudo_header);

    return FALSE;
  }

  return FALSE;
}

static void
dissect_fr_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  gboolean has_direction, gboolean decode_address )
{
  int         offset      = 0;
  proto_item *ti          = NULL;
  proto_tree *fr_tree     = NULL;
  proto_tree *octet_tree  = NULL;
  guint8      fr_octet;
  int         is_response = FALSE;
  guint32     addr        = 0;
  gboolean    encap_is_frf_3_2;
  guint8      fr_ctrl;
  guint16     fr_type;
  int         nlpid_offset;
  guint8      fr_nlpid;
  int         control;
  dissector_handle_t sub_dissector;
  tvbuff_t   *next_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "FR");
  col_clear(pinfo->cinfo, COL_INFO);

  if (has_direction) {
    if (pinfo->pseudo_header->dte_dce.flags & FROM_DCE) {
      col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DTE");
      col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DCE");
    } else {
      col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DCE");
      col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DTE");
    }
  }

  if (tree) {
      ti = proto_tree_add_protocol_format(tree, proto_fr, tvb, 0, -1, "Frame Relay");
      fr_tree = proto_item_add_subtree(ti, ett_fr);
  }

  if (decode_address)
  {
    /*
     * OK, fetch the address field - keep going until we get an EA bit.
     */
    fr_octet = tvb_get_guint8(tvb, offset);

    if (fr_octet & FRELAY_EA) {
      /*
       * Bogus!  There should be at least 2 octets.
       * XXX - is this FRF.12 frame relay fragmentation?  If so, we
       * should dissect it as such, if possible.
       */
      addr = 0;
      proto_tree_add_expert_format(fr_tree, pinfo, &ei_fr_bogus_address, tvb, offset, 1,
                            "Bogus 1-octet address field");
      offset++;
    } else {
        static int * const first_address_bits[] = {&hf_fr_upper_dlci, &hf_fr_cr, &hf_fr_ea, NULL};
        static int * const second_address_bits[] = {&hf_fr_second_dlci, &hf_fr_fecn,
                                        &hf_fr_becn, &hf_fr_de, &hf_fr_ea, NULL};
        static int * const third_address_bits[] = {&hf_fr_third_dlci, &hf_fr_ea, NULL};

      /*
       * The first octet contains the upper 6 bits of the DLCI, as well
       * as the C/R bit.
       */
      addr = (fr_octet & FRELAY_UPPER_DLCI) >> 2;
      is_response = (fr_octet & FRELAY_CR);

      proto_tree_add_bitmask(fr_tree, tvb, offset, hf_fr_first_addr_octet,
                                         ett_fr_address, first_address_bits, ENC_NA);
      offset++;

      /*
       * The second octet contains 4 more bits of DLCI, as well as FECN,
       * BECN, and DE.
       */
      fr_octet = tvb_get_guint8(tvb, offset);
      addr = (addr << 4) | ((fr_octet & FRELAY_SECOND_DLCI) >> 4);
      proto_tree_add_bitmask(fr_tree, tvb, offset, hf_fr_second_addr_octet,
                                         ett_fr_address, second_address_bits, ENC_NA);
      offset++;

      if (!(fr_octet & FRELAY_EA)) {
        /*
         * We have 3 or more address octets.
         *
         * The third octet contains 7 more bits of DLCI if EA isn't set,
         * and lower DLCI or DL-CORE control plus the DLCI or DL-CORE
         * control indicator flag if EA is set.
         */
        fr_octet = tvb_get_guint8(tvb, offset);
        if (!(fr_octet & FRELAY_EA)) {
          /*
           * 7 more bits of DLCI.
           */
          addr = (addr << 7) | ((fr_octet & FRELAY_THIRD_DLCI) >> 1);
          proto_tree_add_bitmask(fr_tree, tvb, offset, hf_fr_third_addr_octet,
                                         ett_fr_address, third_address_bits, ENC_NA);
          offset++;
          fr_octet = tvb_get_guint8(tvb, offset);
          while (!(fr_octet & FRELAY_EA)) {
            /*
             * Bogus!  More than 4 octets of address.
             */
            proto_tree_add_expert_format(fr_tree, pinfo, &ei_fr_bogus_address, tvb, offset, 1,
                                 "Bogus extra address octet");
            offset++;
            fr_octet = tvb_get_guint8(tvb, offset);
          }
        }

        octet_tree = proto_tree_add_subtree_format(fr_tree, tvb, offset, 1,
                                           ett_fr_address, NULL, "Final address octet: 0x%02x",
                                           fr_octet);

        /*
         * Last octet - contains lower DLCI or DL-CORE control, DLCI or
         * DL-CORE control indicator flag.
         */
        if (fr_octet & FRELAY_DC) {
          /*
           * DL-CORE.
           */
          proto_tree_add_uint(octet_tree, hf_fr_dlcore_control, tvb, offset, 1, fr_octet);
        } else {
          /*
           * Last 6 bits of DLCI.
           */
          addr = (addr << 6) | ((fr_octet & FRELAY_LOWER_DLCI) >> 2);
          proto_tree_add_uint(octet_tree, hf_fr_lower_dlci, tvb, offset, 1, fr_octet);
        }
        proto_tree_add_boolean(octet_tree, hf_fr_dc, tvb, offset, 1, fr_octet);
        proto_tree_add_boolean(octet_tree, hf_fr_ea, tvb, offset, 1, fr_octet);

        offset++;
      }
    }
    if (tree) {
      /* Put the full DLCI into the protocol tree. */
      proto_tree_add_uint(fr_tree, hf_fr_dlci, tvb, 0, offset, addr);
    }

    conversation_create_endpoint_by_id(pinfo, ENDPOINT_DLCI, addr);
    col_add_fstr(pinfo->cinfo, COL_INFO, "DLCI %u", addr);
  }

  switch (fr_encap) {

  case FRF_3_2:
    encap_is_frf_3_2 = FALSE;
    fr_ctrl = tvb_get_guint8(tvb, offset);
    if (fr_ctrl == XDLC_U) {
      /*
       * It looks like an RFC 2427-encapsulation frame, with the
       * default UI control field.
       */
      encap_is_frf_3_2 = TRUE;
    } else {
      if (addr == 0) {
        /*
         * This must be some sort of LAPF on DLCI 0 for SVC
         * because DLCI 0 is reserved for LMI and SVC signaling
         * encapsulated in LAPF, and LMI is transmitted in
         * unnumbered information (03), so this must be LAPF
         * (guessing).
         *
         * XXX - but what is it?  Is Q.933 carried inside UI
         * frames or other types of frames or both?
         */
        dissect_xdlc_control(tvb, offset, pinfo, fr_tree,
                             hf_fr_control, ett_fr_control,
                             &fr_cf_items, &fr_cf_items_ext,
                             NULL, NULL, is_response, TRUE, TRUE);
        dissect_lapf(tvb_new_subset_remaining(tvb,offset),pinfo,tree);
        return;
      }
      if (fr_ctrl == (XDLC_U|XDLC_XID)) {
        /*
         * It looks like an RFC 2427-encapsulation frame, with the
         * a UI control field and an XID command.
         */
        dissect_xdlc_control(tvb, offset, pinfo, fr_tree,
                             hf_fr_control, ett_fr_control,
                             &fr_cf_items, &fr_cf_items_ext,
                             NULL, NULL, is_response, TRUE, TRUE);
        dissect_fr_xid(tvb_new_subset_remaining(tvb,offset),pinfo,tree);
        return;
      }

      /*
       * If the data does not start with unnumbered information (03) and
       * the DLCI# is not 0, then there may be Cisco Frame Relay encapsulation.
       * See if, were we to treat the two octets after the DLCI as a Cisco
       * HDLC type, we have a dissector for it.
       */
      if (tvb_bytes_exist(tvb, offset, 2)) {
        fr_type  = tvb_get_ntohs(tvb, offset);
        sub_dissector = dissector_get_uint_handle(chdlc_subdissector_table,
                                                  fr_type);
        if (sub_dissector != NULL) {
          /* We have a dissector, so assume it's Cisco encapsulation. */
          if (ti != NULL) {
            /* Include the Cisco HDLC type in the top-level protocol
               tree item. */
            proto_item_set_end(ti, tvb, offset+2);
          }
          chdlctype(sub_dissector, fr_type, tvb, offset+2, pinfo, tree, fr_tree,
                    hf_fr_chdlctype);
          return;
        }

        /*
         * We don't have a dissector; this might be an RFC 2427-encapsulated
         * See if we have a dissector for the putative NLPID.
         */
        nlpid_offset = offset;
        control = tvb_get_guint8(tvb, nlpid_offset);
        if (control == 0) {
          /* Presumably a padding octet; the NLPID would be in the next octet. */
          nlpid_offset++;
          control = tvb_get_guint8(tvb, nlpid_offset);
        }
        switch (control & 0x03) {

        case XDLC_S:
          /*
           * Supervisory frame.
           * We assume we're in extended mode, with 2-octet supervisory
           * control fields.
           */
          nlpid_offset += 2;
          break;

        case XDLC_U:
          /*
           * Unnumbered frame.
           *
           * XXX - one octet or 2 in extended mode?
           */
          nlpid_offset++;
          break;

        default:
          /*
           * Information frame.
           * We assume we're in extended mode, with 2-octet supervisory
           * control fields.
           */
          nlpid_offset += 2;
          break;
        }
        if (tvb_bytes_exist(tvb, nlpid_offset, 1)) {
          fr_nlpid = tvb_get_guint8(tvb, nlpid_offset);
          sub_dissector = dissector_get_uint_handle(fr_osinl_subdissector_table,
                                                    fr_nlpid);
          if (sub_dissector != NULL)
            encap_is_frf_3_2 = TRUE;
          else {
            sub_dissector = dissector_get_uint_handle(osinl_incl_subdissector_table,
                                                      fr_nlpid);
            if (sub_dissector != NULL)
              encap_is_frf_3_2 = TRUE;
            else {
              if (fr_nlpid == NLPID_SNAP)
                encap_is_frf_3_2 = TRUE;
              else {
                sub_dissector = dissector_get_uint_handle(fr_subdissector_table,
                                                          fr_nlpid);
                if (sub_dissector != NULL)
                  encap_is_frf_3_2 = TRUE;
              }
            }
          }
        }
      }
    }

    if (encap_is_frf_3_2) {
      /*
       * We appear to have an NLPID for this dissector, so dissect
       * it as RFC 2427.
       */
      control = dissect_xdlc_control(tvb, offset, pinfo, fr_tree,
                                     hf_fr_control, ett_fr_control,
                                     &fr_cf_items, &fr_cf_items_ext,
                                     NULL, NULL, is_response, TRUE, TRUE);
      offset += XDLC_CONTROL_LEN(control, TRUE);

      /*
       * XXX - treat DLCI 0 specially?  On DLCI 0, an NLPID of 0x08
       * means Q.933, but on other circuits it could be the "for
       * protocols which do not have an NLPID assigned or do not
       * have a SNAP encapsulation" stuff from RFC 2427.
       */
      dissect_fr_nlpid(tvb, offset, pinfo, tree, ti, fr_tree, fr_ctrl);
    } else {
      /*
       * See if it looks like raw Ethernet.
       */
      guint16 type_length;

      if (tvb_bytes_exist(tvb, offset + 12, 2) &&
          ((type_length = tvb_get_ntohs(tvb, offset + 12)) <= IEEE_802_3_MAX_LEN ||
           dissector_get_uint_handle(ethertype_subdissector_table, type_length) != NULL)) {
        /* It looks like a length or is a known Ethertype; dissect as raw Etheret */
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(eth_withfcs_handle, next_tvb, pinfo, tree);
        return;
      } else {
        /* It doesn't - just dissect it as data. */
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(next_tvb, pinfo, tree);
      }
    }
    break;

  case GPRS_NS:
    if (addr == 0) {
      fr_ctrl = tvb_get_guint8(tvb, offset);
      control = dissect_xdlc_control(tvb, offset, pinfo, fr_tree,
                                     hf_fr_control, ett_fr_control,
                                     &fr_cf_items, &fr_cf_items_ext,
                                     NULL, NULL, is_response, TRUE, TRUE);
      offset += XDLC_CONTROL_LEN(control, TRUE);
      dissect_fr_nlpid(tvb, offset, pinfo, tree, ti, fr_tree, fr_ctrl);
    } else {
      next_tvb = tvb_new_subset_remaining(tvb, offset);
      call_dissector(gprs_ns_handle, next_tvb, pinfo, tree);
    }
    break;

  case RAW_ETHER:
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (addr != 0)
      call_dissector(eth_withfcs_handle, next_tvb, pinfo, tree);
    else
      dissect_lapf(next_tvb, pinfo, tree);
    break;

  case LAPB:
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (addr != 0)
      call_dissector(lapb_handle, next_tvb, pinfo, tree);
    else
      dissect_lapf(next_tvb, pinfo, tree);
    break;
  }
}

static int
dissect_fr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_fr_common(tvb, pinfo, tree, FALSE, TRUE );
  return tvb_captured_length(tvb);
}

static int
dissect_fr_phdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_fr_common(tvb, pinfo, tree, TRUE, TRUE );
  return tvb_captured_length(tvb);
}

static int
dissect_fr_stripped_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_fr_common(tvb, pinfo, tree, TRUE, FALSE );
  return tvb_captured_length(tvb);
}

static int
dissect_fr_uncompressed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  proto_tree *fr_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "FR");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_protocol_format(tree, proto_fr, tvb, 0, -1, "Frame Relay");
  fr_tree = proto_item_add_subtree(ti, ett_fr);

  dissect_fr_nlpid(tvb, 0, pinfo, tree, ti, fr_tree, XDLC_U);
  return tvb_captured_length(tvb);
}

static void
dissect_fr_nlpid(tvbuff_t *tvb, int offset, packet_info *pinfo,
                             proto_tree *tree, proto_item *ti,
                             proto_tree *fr_tree, guint8 fr_ctrl)
{
  guint8    fr_nlpid;
  tvbuff_t *next_tvb;

  /*
   * Tentatively set the Frame Relay item not to include the NLPID,
   * as OSI network layer protocols consider it to be part of
   * the OSI PDU.
   */
  proto_item_set_end(ti, tvb, offset);
  fr_nlpid = tvb_get_guint8 (tvb,offset);
  if (fr_nlpid == 0) {
    proto_tree_add_uint_format(fr_tree, hf_fr_nlpid, tvb, offset, 1, fr_nlpid, "Padding");
    offset++;
    if (ti != NULL) {
      /* Include the padding in the top-level protocol tree item. */
      proto_item_set_end(ti, tvb, offset);
    }
    fr_nlpid=tvb_get_guint8( tvb,offset);
  }

  /*
   * OSI network layer protocols consider the NLPID to be part
   * of the frame, so we'll pass it as part of the payload and,
   * if the protocol is one of those, add it as a hidden item here.
   * We check both the generic OSI NLPID dissector table and
   * the Frame Relay OSI NLPID dissector table - the latter is for
   * NLPID's such as 0x08, which is Q.933 in Frame Relay but
   * other protocols (e.g., Q.931) on other network layers.
   *
   * "OSI network layer protocols" includes Q.933.
   *
   * We check the Frame Relay table first, so that protocols for which
   * the NLPID means something different on Frame Relay, i.e. Q.933 vs.
   * Q.931, are handled appropriately for Frame Relay.
   *
   * XXX - note that an NLPID of 0x08 for Q.933 could either be a
   * Q.933 signaling message or a message for a protocol
   * identified by a 2-octet layer 2 protocol type and a
   * 2-octet layer 3 protocol type, those protocol type
   * octets having the values from octets 6, 6a, 7, and 7a
   * of a Q.931 low layer compatibility information element
   * (section 4.5.19 of Q.931; Q.933 says they have the values
   * from a Q.933 low layer compatibility information element,
   * but Q.933 low layer compatibility information elements
   * don't have protocol values in them).
   *
   * Assuming that, as Q.933 seems to imply, that Q.933 messages
   * look just like Q.931 messages except where it explicitly
   * says they differ, then the octet after the NLPID would,
   * in a Q.933 message, have its upper 4 bits zero (that's
   * the length of the call reference value, in Q.931, and
   * is limited to 15 or fewer octets).  As appears to be the case,
   * octet 6 of a Q.931 low layer compatibility element has the
   * 0x40 bit set, so you can distinguish between a Q.933
   * message and an encapsulated packet by checking whether
   * the upper 4 bits of the octet after the NLPID are zero.
   *
   * Either that, or it's Q.933 iff the DLCI is 0.
   */
  next_tvb = tvb_new_subset_remaining(tvb,offset);
  if (dissector_try_uint(fr_osinl_subdissector_table, fr_nlpid, next_tvb,
                         pinfo, tree) ||
      dissector_try_uint(osinl_incl_subdissector_table, fr_nlpid, next_tvb,
                         pinfo, tree)) {
    /*
     * Yes, we got a match.  Add the NLPID as a hidden item,
     * so you can, at least, filter on it.
     */
    if (tree) {
      proto_item *hidden_item;
      hidden_item = proto_tree_add_uint(fr_tree, hf_fr_nlpid,
                                        tvb, offset, 1, fr_nlpid );
      proto_item_set_hidden(hidden_item);
    }
    return;
  }

  /*
   * All other protocols don't.
   *
   * XXX - what about Cisco/Gang-of-Four LMI?  Is the 0x09 considered
   * to be part of the LMI PDU?
   */
  if (tree)
    proto_tree_add_uint(fr_tree, hf_fr_nlpid, tvb, offset, 1, fr_nlpid );
  offset++;

  switch (fr_nlpid) {

  case NLPID_SNAP:
    if (ti != NULL) {
      /* Include the NLPID and SNAP header in the top-level
         protocol tree item. */
      proto_item_set_end(ti, tvb, offset+5);
    }
    dissect_snap(tvb, offset, pinfo, tree, fr_tree, fr_ctrl,
                 hf_fr_oui, hf_fr_snaptype, hf_fr_pid, 0);
    return;

  default:
    if (ti != NULL) {
      /* Include the NLPID in the top-level protocol tree item. */
      proto_item_set_end(ti, tvb, offset);
    }
    next_tvb = tvb_new_subset_remaining(tvb,offset);
    if (!dissector_try_uint(fr_subdissector_table,fr_nlpid,
                            next_tvb, pinfo, tree))
      call_dissector(data_handle,next_tvb, pinfo, tree);
    break;
  }
}

static void
dissect_lapf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree_add_expert(tree, pinfo, &ei_fr_frame_relay_lapf, tvb, 0, 0);
  call_dissector(data_handle,tvb_new_subset_remaining(tvb,0),pinfo,tree);
}

static void
dissect_fr_xid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree_add_expert(tree, pinfo, &ei_fr_frame_relay_xid, tvb, 0, 0);
  call_dissector(data_handle,tvb_new_subset_remaining(tvb,0),pinfo,tree);
}

/* Register the protocol with Wireshark */
void
proto_register_fr(void)
{
  static hf_register_info hf[] = {
    { &hf_fr_ea,
      { "EA", "fr.ea",
        FT_BOOLEAN, 8, TFS(&ea_string), FRELAY_EA,
        "Extended Address", HFILL }},

    { &hf_fr_upper_dlci,
      { "Upper DLCI", "fr.upper_dlci",
        FT_UINT8, BASE_HEX, NULL, FRELAY_UPPER_DLCI,
        "Upper bits of DLCI", HFILL }},

    { &hf_fr_cr,
      { "CR", "fr.cr",
        FT_BOOLEAN, 8, TFS(&tfs_command_response), FRELAY_CR,
        "Command/Response", HFILL }},

    { &hf_fr_second_dlci,
      { "Second DLCI", "fr.second_dlci",
        FT_UINT8, BASE_HEX, NULL, FRELAY_SECOND_DLCI,
        "Bits below upper bits of DLCI", HFILL }},

    { &hf_fr_fecn,
      { "FECN", "fr.fecn",
        FT_BOOLEAN, 8, NULL, FRELAY_FECN,
        "Forward Explicit Congestion Notification", HFILL }},

    { &hf_fr_becn,
      { "BECN", "fr.becn",
        FT_BOOLEAN, 8, NULL, FRELAY_BECN,
        "Backward Explicit Congestion Notification", HFILL }},

    { &hf_fr_de,
      { "DE", "fr.de",
        FT_BOOLEAN, 8, NULL, FRELAY_DE,
        "Discard Eligibility", HFILL }},

    { &hf_fr_third_dlci,
      { "Third DLCI", "fr.third_dlci",
        FT_UINT8, BASE_HEX, NULL, FRELAY_THIRD_DLCI,
        "Additional bits of DLCI", HFILL }},

    { &hf_fr_dlcore_control,
      { "DL-CORE Control", "fr.dlcore_control",
        FT_UINT8, BASE_HEX, NULL, FRELAY_LOWER_DLCI,
        "DL-Core control bits", HFILL }},

    { &hf_fr_lower_dlci,
      { "Lower DLCI", "fr.lower_dlci",
        FT_UINT8, BASE_HEX, NULL, FRELAY_LOWER_DLCI,
        "Lower bits of DLCI", HFILL }},

    { &hf_fr_dc,
      { "DC", "fr.dc",
        FT_BOOLEAN, 16, TFS(&ctrl_string), FRELAY_CR,
        "Address/Control", HFILL }},

    { &hf_fr_dlci,
      { "DLCI", "fr.dlci",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Data-Link Connection Identifier", HFILL }},

    { &hf_fr_control,
      { "Control Field", "fr.control",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_fr_n_r,
      { "N(R)", "fr.control.n_r",
        FT_UINT16, BASE_DEC, NULL, XDLC_N_R_EXT_MASK,
        NULL, HFILL }},

    { &hf_fr_n_s,
      { "N(S)", "fr.control.n_s",
        FT_UINT16, BASE_DEC, NULL, XDLC_N_S_EXT_MASK,
        NULL, HFILL }},

    { &hf_fr_p,
      { "Poll", "fr.control.p",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), XDLC_P_F,
        NULL, HFILL }},

    { &hf_fr_p_ext,
      { "Poll", "fr.control.p",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), XDLC_P_F_EXT,
        NULL, HFILL }},

    { &hf_fr_f,
      { "Final", "fr.control.f",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), XDLC_P_F,
        NULL, HFILL }},

    { &hf_fr_f_ext,
      { "Final", "fr.control.f",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), XDLC_P_F_EXT,
        NULL, HFILL }},

    { &hf_fr_s_ftype,
      { "Supervisory frame type", "fr.control.s_ftype",
        FT_UINT16, BASE_HEX, VALS(stype_vals), XDLC_S_FTYPE_MASK,
        NULL, HFILL }},

    { &hf_fr_u_modifier_cmd,
      { "Command", "fr.control.u_modifier_cmd",
        FT_UINT8, BASE_HEX, VALS(modifier_vals_cmd), XDLC_U_MODIFIER_MASK,
        NULL, HFILL }},

    { &hf_fr_u_modifier_resp,
      { "Response", "fr.control.u_modifier_resp",
        FT_UINT8, BASE_HEX, VALS(modifier_vals_resp), XDLC_U_MODIFIER_MASK,
        NULL, HFILL }},

    { &hf_fr_ftype_i,
      { "Frame type", "fr.control.ftype",
        FT_UINT16, BASE_HEX, VALS(ftype_vals), XDLC_I_MASK,
        NULL, HFILL }},

    { &hf_fr_ftype_s_u,
      { "Frame type", "fr.control.ftype",
        FT_UINT8, BASE_HEX, VALS(ftype_vals), XDLC_S_U_MASK,
        NULL, HFILL }},

    { &hf_fr_ftype_s_u_ext,
      { "Frame type", "fr.control.ftype",
        FT_UINT16, BASE_HEX, VALS(ftype_vals), XDLC_S_U_MASK,
        NULL, HFILL }},

    { &hf_fr_nlpid,
      { "NLPID", "fr.nlpid",
        FT_UINT8, BASE_HEX, VALS(fr_nlpid_vals), 0x0,
        "Frame Relay Encapsulated Protocol NLPID", HFILL }},

    { &hf_fr_oui,
      { "Organization Code", "fr.snap.oui",
        FT_UINT24, BASE_OUI, NULL, 0x0,
        NULL, HFILL }},

    { &hf_fr_pid,
      { "Protocol ID", "fr.snap.pid",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_fr_snaptype,
      { "Type", "fr.snaptype",
        FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
        "Frame Relay SNAP Encapsulated Protocol", HFILL }},

    { &hf_fr_chdlctype,
      { "Type", "fr.chdlctype",
        FT_UINT16, BASE_HEX, VALS(chdlc_vals), 0x0,
        "Frame Relay Cisco HDLC Encapsulated Protocol", HFILL }},

    { &hf_fr_first_addr_octet,
      { "First address octet", "fr.first_addr_octet",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_fr_second_addr_octet,
      { "Second address octet", "fr.second_addr_octet",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_fr_third_addr_octet,
      { "Third address octet", "fr.third_addr_octet",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_fr,
    &ett_fr_address,
    &ett_fr_control,
  };
  static ei_register_info ei[] = {
    { &ei_fr_bogus_address, { "fr.bogus_address", PI_PROTOCOL, PI_WARN, "Bogus address", EXPFILL }},
    { &ei_fr_frame_relay_lapf, { "fr.frame_relay.lapf", PI_UNDECODED, PI_WARN, "Frame relay lapf not yet implemented", EXPFILL }},
    { &ei_fr_frame_relay_xid, { "fr.frame_relay.xid", PI_UNDECODED, PI_WARN, "Frame relay xid not yet implemented", EXPFILL }},
  };

  static const enum_val_t fr_encap_options[] = {
    { "frf-3.2", "FRF 3.2/Cisco HDLC", FRF_3_2 },
    { "gprs-ns", "GPRS Network Service", GPRS_NS },
    { "ethernet", "Raw Ethernet", RAW_ETHER },
    { "lapb", "LAPB (T1.617a-1994 Annex G)", LAPB },
    { NULL, NULL, 0 },
  };
  module_t *frencap_module;
  expert_module_t* expert_fr;

  proto_fr = proto_register_protocol("Frame Relay", "FR", "fr");
  proto_register_field_array(proto_fr, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_fr = expert_register_protocol(proto_fr);
  expert_register_field_array(expert_fr, ei, array_length(ei));

  fr_subdissector_table = register_dissector_table("fr.nlpid",
                                                   "Frame Relay NLPID", proto_fr, FT_UINT8, BASE_HEX);
  fr_osinl_subdissector_table = register_dissector_table("fr.osinl",
                                                         "Frame Relay OSI NLPID", proto_fr, FT_UINT8, BASE_HEX);

  register_dissector("fr_uncompressed", dissect_fr_uncompressed, proto_fr);
  fr_handle = register_dissector("fr", dissect_fr, proto_fr);
  register_dissector("fr_stripped_address", dissect_fr_stripped_address, proto_fr);

  frencap_module = prefs_register_protocol(proto_fr, NULL);
  /*
   * XXX - this should really be per-circuit - I've seen at least one
   * capture where different DLCIs have different encapsulations - but
   * we don't yet have any support for per-circuit encapsulations.
   *
   * Even with that, though, we might want a default encapsulation,
   * so that people dealing with GPRS can make gprs-ns the default.
   */
  prefs_register_enum_preference(frencap_module, "encap", "Encapsulation",
                                 "Encapsulation", &fr_encap,
                                 fr_encap_options, FALSE);

  register_capture_dissector_table("fr.nlpid", "Frame Relay NLPID");
}

void
proto_reg_handoff_fr(void)
{
  dissector_handle_t fr_phdr_handle;
  capture_dissector_handle_t fr_cap_handle;

  dissector_add_uint("gre.proto", ETHERTYPE_RAW_FR, fr_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_FRELAY, fr_handle);
  dissector_add_uint("juniper.proto", JUNIPER_PROTO_FRELAY, fr_handle);
  dissector_add_uint("sflow_245.header_protocol", SFLOW_245_HEADER_FRAME_RELAY, fr_handle);
  dissector_add_uint("atm.aal5.type", TRAF_FR, fr_handle);
  dissector_add_uint("l2tp.pw_type", L2TPv3_PW_FR, fr_handle);
  dissector_add_uint("sll.hatype", ARPHRD_FRAD, fr_handle);

  fr_phdr_handle = create_dissector_handle(dissect_fr_phdr, proto_fr);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_FRELAY_WITH_PHDR, fr_phdr_handle);

  fr_cap_handle = create_capture_dissector_handle(capture_fr, proto_fr);
  capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_FRELAY, fr_cap_handle);
  capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_FRELAY_WITH_PHDR, fr_cap_handle);

  eth_withfcs_handle = find_dissector_add_dependency("eth_withfcs", proto_fr);
  gprs_ns_handle = find_dissector_add_dependency("gprs_ns", proto_fr);
  lapb_handle = find_dissector_add_dependency("lapb", proto_fr);
  data_handle = find_dissector_add_dependency("data", proto_fr);

  chdlc_subdissector_table = find_dissector_table("chdlc.protocol");
  osinl_incl_subdissector_table = find_dissector_table("osinl.incl");
  ethertype_subdissector_table = find_dissector_table("ethertype");

  chdlc_cap_handle = find_capture_dissector("chdlc");
  eth_cap_handle = find_capture_dissector("eth");
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
