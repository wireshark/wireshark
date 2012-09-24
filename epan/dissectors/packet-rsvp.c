/* packet-rsvp.c
 * Routines for RSVP packet disassembly
 *
 * (c) Copyright Ashok Narayanan <ashokn@cisco.com>
 *
 * $Id$
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

/*
 * NOTES
 *
 * This module defines routines to disassemble RSVP packets, as defined in
 * RFC 2205. All objects from RFC2205 are supported, in IPv4 and IPv6 mode.
 * In addition, the Integrated Services traffic specification objects
 * defined in RFC2210 are also supported.
 *
 * IPv6 support is not completely tested
 *
 * Mar 3, 2000: Added support for MPLS/TE objects, as defined in
 * <draft-ietf-mpls-rsvp-lsp-tunnel-04.txt>
 *
 * May 6, 2004: Added support for E-NNI objects, as defined in
 * <OIF-E-NNI-01.0>   (Roberto Morro)
 * <roberto.morro[AT]tilab.com>
 *
 * May 6, 2004: Modified some UNI objects, as defined in
 * <OIF2003.249.09>   (Roberto Morro)
 * <roberto.morro[AT]tilab.com>
 *
 * June 2, 2005: Modified more UNI objects to show correct TNA
 * addresses; Fixed LSP interface ID subobject (Richard Rabbat)
 * <richard[AT]us.fujitsu.com>
 *
 * July 25, 2005: improved ERROR and LABEL_SET objects dissector;
 * new ASSOCIATION object dissector (Roberto Morro)
 * <roberto.morro[AT]tilab.com>
 *
 * August 22, 2005: added support for tapping and conversations.
 * (Manu Pathak) <mapathak[AT]cisco.com>
 *
 * July 4, 2006: added support for RFC4124; new CLASSTYPE object dissector
 * (FF) <francesco.fondelli[AT]gmail.com>
 *
 * June 9, 2007: added support for draft-ietf-ccamp-ethernet-traffic-parameters-02
 * and draft-ietf-ccamp-lsp-hierarchy-bis-02; added support for NOTIFY_REQUEST
 * and RECOVERY_LABEL objects (Roberto Morro) * <roberto.morro[AT]tilab.com>
 *
 * Oct 21, 2009: add support for RFC4328, new G.709 traffic parameters,
 * update gpid, switching and encoding type values to actual IANA numbers.
 * (FF) <francesco.fondelli[AT]gmail.com>
 *
 * Gen 20, 2010: add support for ERROR_STRING IF_ID TLV (see RFC 4783)
 * (FF) <francesco.fondelli[AT]gmail.com>
 *
 * Feb 12, 2010: add support for generalized label interpretation: SUKLM
 * format for SONET/SDH label (RFC 4606), t3t2t1 format for G.709 ODUk label
 * (RFC 4328), G.694 format for lambda label (draft-ietf-ccamp-gmpls-g-694-lamb
 * da-labels-05).  Add related user preference option.
 * (FF) <francesco.fondelli[AT]gmail.com>
 *
 * Dec 3, 2010: add support for vendor private class object and ERO/RRO
 * sub-object (see RFC 3936).
 * (FF) <francesco.fondelli[AT]gmail.com>
 *
 * Dec 21, 2010: add new PROTECTION obj c-type 2 (RFC4872),
 * new TLVs for IF_ID (RFC4920), Path Key subobj in ERO (RFC5520),
 * new ASSOCIATION obj c-type 4 (oif2008.389), new LSP_ATTRIBUTES and
 * LSP_REQUIRED_ATTRIBUTES objects (RFC5420), improved ERROR object dissection,
 * new ADMIN_STATUS flags and fix to conversation (not applied to ACK, SREFRESH
 * and HELLO messages).
 * (Roberto Morro) <roberto.morro[AT]telecomitalia.it>
 *
 */


#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <glib.h>

#include <epan/packet.h>
#include <prefs.h>
#include <epan/in_cksum.h>
#include <epan/etypes.h>
#include <epan/ipproto.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/emem.h>
#include <epan/sminmpec.h>

#include "packet-rsvp.h"
#include "packet-ip.h"
#include "packet-frame.h"
#include "packet-diffserv-mpls-common.h"
#include "packet-osi.h"

/* RSVP over UDP encapsulation */
#define UDP_PORT_PRSVP 3455

static int proto_rsvp = -1;

static int hf_rsvp_error_flags = -1;
static int hf_rsvp_error_flags_path_state_removed = -1;
static int hf_rsvp_error_flags_not_guilty = -1;
static int hf_rsvp_error_flags_in_place = -1;
static int hf_rsvp_eth_tspec_tlv_color_mode = -1;
static int hf_rsvp_eth_tspec_tlv_coupling_flag = -1;
static int hf_rsvp_sender_tspec_standard_contiguous_concatenation = -1;
static int hf_rsvp_sender_tspec_arbitrary_contiguous_concatenation = -1;
static int hf_rsvp_sender_tspec_regenerator_section = -1;
static int hf_rsvp_sender_tspec_multiplex_section = -1;
static int hf_rsvp_sender_tspec_J0_transparency = -1;
static int hf_rsvp_sender_tspec_SOH_RSOH_DCC_transparency = -1;
static int hf_rsvp_sender_tspec_LOH_MSOH_DCC_transparency = -1;
static int hf_rsvp_sender_tspec_LOH_MSOH_extended_DCC_transparency = -1;
static int hf_rsvp_sender_tspec_K1_K2_transparency = -1;
static int hf_rsvp_sender_tspec_E1_transparency = -1;
static int hf_rsvp_sender_tspec_F1_transparency = -1;
static int hf_rsvp_sender_tspec_E2_transparency = -1;
static int hf_rsvp_sender_tspec_B1_transparency = -1;
static int hf_rsvp_sender_tspec_B2_transparency = -1;
static int hf_rsvp_sender_tspec_M0_transparency = -1;
static int hf_rsvp_sender_tspec_M1_transparency = -1;
static int hf_rsvp_flowspec_standard_contiguous_concatenation = -1;
static int hf_rsvp_flowspec_arbitrary_contiguous_concatenation = -1;
static int hf_rsvp_flowspec_regenerator_section = -1;
static int hf_rsvp_flowspec_multiplex_section = -1;
static int hf_rsvp_flowspec_J0_transparency = -1;
static int hf_rsvp_flowspec_SOH_RSOH_DCC_transparency = -1;
static int hf_rsvp_flowspec_LOH_MSOH_DCC_transparency = -1;
static int hf_rsvp_flowspec_LOH_MSOH_extended_DCC_transparency = -1;
static int hf_rsvp_flowspec_K1_K2_transparency = -1;
static int hf_rsvp_flowspec_E1_transparency = -1;
static int hf_rsvp_flowspec_F1_transparency = -1;
static int hf_rsvp_flowspec_E2_transparency = -1;
static int hf_rsvp_flowspec_B1_transparency = -1;
static int hf_rsvp_flowspec_B2_transparency = -1;
static int hf_rsvp_flowspec_M0_transparency = -1;
static int hf_rsvp_flowspec_M1_transparency = -1;
static int hf_rsvp_integrity_flags_handshake = -1;
static int hf_rsvp_sa_flags_local = -1;
static int hf_rsvp_sa_flags_label = -1;
static int hf_rsvp_sa_flags_se_style = -1;
static int hf_rsvp_sa_flags_bandwidth = -1;
static int hf_rsvp_sa_flags_node = -1;
static int hf_rsvp_rro_flags_local_avail = -1;
static int hf_rsvp_rro_flags_local_in_use = -1;
static int hf_rsvp_rro_flags_bandwidth = -1;
static int hf_rsvp_rro_flags_node = -1;
static int hf_rsvp_rro_flags_node_address = -1;
static int hf_rsvp_rro_flags_backup_tunnel_bandwidth = -1;
static int hf_rsvp_rro_flags_backup_tunnel_hop = -1;
static int hf_rsvp_lsp_attr_e2e = -1;
static int hf_rsvp_lsp_attr_boundary = -1;
static int hf_rsvp_lsp_attr_segment = -1;
static int hf_rsvp_gen_uni_direction = -1;
static int hf_rsvp_protection_info_flags_secondary_lsp = -1;
static int hf_rsvp_pi_link_flags_extra_traffic = -1;
static int hf_rsvp_pi_link_flags_unprotected = -1;
static int hf_rsvp_pi_link_flags_shared = -1;
static int hf_rsvp_pi_link_flags_dedicated1_1 = -1;
static int hf_rsvp_pi_link_flags_dedicated1plus1 = -1;
static int hf_rsvp_pi_link_flags_enhanced = -1;
static int hf_rsvp_pi_link_flags_extra = -1;
static int hf_rsvp_pi_link_flags_dedicated_1_1 = -1;
static int hf_rsvp_pi_link_flags_dedicated_1plus1 = -1;
static int hf_rsvp_rfc4872_secondary = -1;
static int hf_rsvp_rfc4872_protecting = -1;
static int hf_rsvp_rfc4872_notification_msg = -1;
static int hf_rsvp_rfc4872_operational = -1;
static int hf_rsvp_pi_lsp_flags_full_rerouting = -1;
static int hf_rsvp_pi_lsp_flags_rerouting_extra = -1;
static int hf_rsvp_pi_lsp_flags_1_n_protection = -1;
static int hf_rsvp_pi_lsp_flags_1plus1_unidirectional = -1;
static int hf_rsvp_pi_lsp_flags_1plus1_bidirectional = -1;
static int hf_rsvp_protection_info_in_place = -1;
static int hf_rsvp_protection_info_required = -1;
static int hf_rsvp_pi_seg_flags_full_rerouting = -1;
static int hf_rsvp_pi_seg_flags_rerouting_extra = -1;
static int hf_rsvp_pi_seg_flags_1_n_protection = -1;
static int hf_rsvp_pi_seg_flags_1plus1_unidirectional = -1;
static int hf_rsvp_pi_seg_flags_1plus1_bidirectional = -1;
static int hf_rsvp_frr_flags_one2one_backup = -1;
static int hf_rsvp_frr_flags_facility_backup = -1;

static dissector_table_t rsvp_dissector_table;

static int rsvp_tap = -1;

/*
 * All RSVP packets belonging to a particular flow  belong to the same
 * conversation. The following structure definitions are for auxillary
 * structures which have all the relevant flow information to make up the
 * RSVP five-tuple. Note that the values of the five-tuple are determined
 * from the session object and sender template/filter spec for PATH/RESV
 * messages.
 * Update rsvp_request_equal() when you add stuff here. You might also
 * have to update rsvp_request_hash().
 * TODO: Support for IPv6 conversations.
 */

typedef struct rsvp_session_ipv4_info {
    address destination;
    guint8 protocol;
    guint16 udp_dest_port;
} rsvp_session_ipv4_info;

typedef struct rsvp_session_ipv6_info {
    /* not supported yet */

    guint8 dummy;
} rsvp_session_ipv6_info;

typedef struct rsvp_session_ipv4_lsp_info {
    address destination;
    guint16 udp_dest_port;
    guint32 ext_tunnel_id;
} rsvp_session_ipv4_lsp_info;

typedef struct rsvp_session_agg_ipv4_info {
    address destination;
    guint8 dscp;
} rsvp_session_agg_ipv4_info;

typedef struct rsvp_session_ipv4_uni_info {
    address destination;
    guint16 udp_dest_port;
    guint32 ext_tunnel_id;
} rsvp_session_ipv4_uni_info;

typedef struct rsvp_session_ipv4_enni_info {
    address destination;
    guint16 udp_dest_port;
    guint32 ext_tunnel_id;
} rsvp_session_ipv4_enni_info;

typedef struct rsvp_template_filter_info {
    address source;
    guint16 udp_source_port;
} rsvp_template_filter_info;

/*
 * The actual request key consists of a union of the various session objects
 * (which are uniquely identified based on the session type), and the
 * source_info structure, which has the information derived from the sender
 * template or the filter spec.
 * The request key is populated by copying the information from the
 * rsvp_conversation_info structure (rsvph), which in turn is populated when
 * the session, filter and sender template objects are dissected.
 */
struct rsvp_request_key {
    guint32 session_type;

    union { /* differentiated by session_type field */
        rsvp_session_ipv4_info session_ipv4;
        rsvp_session_ipv6_info session_ipv6;
        rsvp_session_ipv4_lsp_info session_ipv4_lsp;
        rsvp_session_agg_ipv4_info session_agg_ipv4;
        rsvp_session_ipv4_uni_info session_ipv4_uni;
        rsvp_session_ipv4_enni_info session_ipv4_enni;
    } u;

    rsvp_template_filter_info source_info;
    guint32 conversation;
};

/*
 * At present, there is nothing particularly important that we need to
 * store for the request value for each rsvp_request_key, so we just
 * store the unique 32-bit identifier internally allocated for the key
 * (and stored in the conversation attribute of rsvp_request_key above.
 * If this changes in the future, then other stuff can be added here.
 */
struct rsvp_request_val {
    guint32 value;
};

/*
 * Initialize the conversation related data structures.
 */
static GHashTable *rsvp_request_hash = NULL;

/*
 * The list of tree types
 */
enum {
    TT_RSVP,
    TT_HDR,
    TT_SESSION,
    TT_HOP,
    TT_HOP_SUBOBJ,
    TT_TIME_VALUES,
    TT_ERROR,
    TT_ERROR_SUBOBJ,
    TT_ERROR_FLAGS,
    TT_SCOPE,
    TT_STYLE,
    TT_CONFIRM,
    TT_SENDER_TEMPLATE,
    TT_FILTER_SPEC,
    TT_TSPEC,
    TT_TSPEC_SUBTREE,
    TT_FLOWSPEC,
    TT_FLOWSPEC_SUBTREE,
    TT_ETHSPEC_SUBTREE,
    TT_ADSPEC,
    TT_ADSPEC_SUBTREE,
    TT_INTEGRITY,
    TT_INTEGRITY_FLAGS,
    TT_DCLASS,
    TT_LSP_TUNNEL_IF_ID,
    TT_LSP_TUNNEL_IF_ID_SUBTREE,
    TT_POLICY,
    TT_MESSAGE_ID,
    TT_MESSAGE_ID_ACK,
    TT_MESSAGE_ID_LIST,
    TT_LABEL,
    TT_LABEL_SET,
    TT_LABEL_REQUEST,
    TT_SESSION_ATTRIBUTE,
    TT_SESSION_ATTRIBUTE_FLAGS,
    TT_HELLO_OBJ,
    TT_EXPLICIT_ROUTE,
    TT_EXPLICIT_ROUTE_SUBOBJ,
    TT_RECORD_ROUTE,
    TT_RECORD_ROUTE_SUBOBJ,
    TT_RECORD_ROUTE_SUBOBJ_FLAGS,
    TT_ADMIN_STATUS,
    TT_ADMIN_STATUS_FLAGS,
    TT_LSP_ATTRIBUTES,
    TT_LSP_ATTRIBUTES_FLAGS,
    TT_ASSOCIATION,
    TT_GEN_UNI,
    TT_GEN_UNI_SUBOBJ,
    TT_CALL_ID,
    TT_BUNDLE_COMPMSG,
    TT_RESTART_CAP,
    TT_PROTECTION_INFO,
    TT_PROTECTION_INFO_LINK,
    TT_PROTECTION_INFO_LSP,
    TT_PROTECTION_INFO_SEG,
    TT_FAST_REROUTE,
    TT_FAST_REROUTE_FLAGS,
    TT_DETOUR,
    TT_DIFFSERV,
    TT_DIFFSERV_MAP,
    TT_DIFFSERV_MAP_PHBID,
    TT_CLASSTYPE,
    TT_PRIVATE_CLASS,
    TT_UNKNOWN_CLASS,

    TT_MAX
};
static gint ett_treelist[TT_MAX];
#define TREE(X) ett_treelist[(X)]

/* Should we dissect bundle messages? */
static gboolean rsvp_bundle_dissect = TRUE;

/* FF: How should we dissect generalized label? */
static enum_val_t rsvp_generalized_label_options[] = {
    /* see RFC 3471 Section 3.2.1.2 */
    { "data", "data (no interpretation)", 1 },
    /* see RFC 4606 Section 3 */
    { "SUKLM", "SONET/SDH (\"S, U, K, L, M\" scheme)", 2 },
    /* see I-D draft-ietf-ccamp-gmpls-g-694-lambda-labels-05 */
    { "G694", "Wavelength Label (G.694 frequency grid)", 3 },
    /* see RFC 4328 Section 4.1 */
    { "G709", "ODUk Label", 4 },
    { NULL, NULL, 0 }
};

static guint rsvp_generalized_label_option = 1;

/*
 * RSVP message types.
 * See
 *
 *      http://www.iana.org/assignments/rsvp-parameters
 */
typedef enum {
    RSVP_MSG_PATH          =  1,        /* RFC 2205 */
    RSVP_MSG_RESV,                      /* RFC 2205 */
    RSVP_MSG_PERR,                      /* RFC 2205 */
    RSVP_MSG_RERR,                      /* RFC 2205 */
    RSVP_MSG_PTEAR,                     /* RFC 2205 */
    RSVP_MSG_RTEAR,                     /* RFC 2205 */
    RSVP_MSG_CONFIRM,                   /* XXX - DREQ, RFC 2745? */
                                        /* 9 is DREP, RFC 2745 */
    RSVP_MSG_RTEAR_CONFIRM = 10,        /* from Fred Baker at Cisco */
                                        /* 11 is unassigned */
    RSVP_MSG_BUNDLE        = 12,        /* RFC 2961 */
    RSVP_MSG_ACK,                       /* RFC 2961 */
                                        /* 14 is reserved */
    RSVP_MSG_SREFRESH      = 15,        /* RFC 2961 */
                                        /* 16, 17, 18, 19 not listed */
    RSVP_MSG_HELLO         = 20,        /* RFC 3209 */
    RSVP_MSG_NOTIFY                     /* [RFC3473] */
                                        /* 25 is Integrity Challenge RFC 2747, RFC 3097 */
                                        /* 26 is Integrity Response RFC 2747, RFC 3097 */
                                        /* 66 is DSBM_willing [SBM] */
                                        /* 67 is I_AM_DSBM [SBM] */
                                        /* [SBM] is Subnet Bandwidth Manager ID from July 1997 */
} rsvp_message_types;

static const value_string message_type_vals[] = {
    { RSVP_MSG_PATH,            "PATH Message. "},
    { RSVP_MSG_RESV,            "RESV Message. "},
    { RSVP_MSG_PERR,            "PATH ERROR Message. "},
    { RSVP_MSG_RERR,            "RESV ERROR Message. "},
    { RSVP_MSG_PTEAR,           "PATH TEAR Message. "},
    { RSVP_MSG_RTEAR,           "RESV TEAR Message. "},
    { RSVP_MSG_CONFIRM,         "CONFIRM Message. "},
    { RSVP_MSG_RTEAR_CONFIRM,   "RESV TEAR CONFIRM Message. "},
    { RSVP_MSG_BUNDLE,          "BUNDLE Message. "},
    { RSVP_MSG_ACK,             "ACK Message. "},
    { RSVP_MSG_SREFRESH,        "SREFRESH Message. "},
    { RSVP_MSG_HELLO,           "HELLO Message. "},
    { RSVP_MSG_NOTIFY,          "NOTIFY Message. "},
    { 0, NULL}
};
static value_string_ext message_type_vals_ext = VALUE_STRING_EXT_INIT(message_type_vals);

/*
 * FF: please keep this list in sync with
 * http://www.iana.org/assignments/rsvp-parameters
 * Registry Name: 'Class'
 */
enum rsvp_classes {
    RSVP_CLASS_NULL              =   0,
    RSVP_CLASS_SESSION,

    RSVP_CLASS_HOP               =   3,
    RSVP_CLASS_INTEGRITY,
    RSVP_CLASS_TIME_VALUES,
    RSVP_CLASS_ERROR,
    RSVP_CLASS_SCOPE,
    RSVP_CLASS_STYLE,
    RSVP_CLASS_FLOWSPEC,
    RSVP_CLASS_FILTER_SPEC,
    RSVP_CLASS_SENDER_TEMPLATE,
    RSVP_CLASS_SENDER_TSPEC,
    RSVP_CLASS_ADSPEC,
    RSVP_CLASS_POLICY,
    RSVP_CLASS_CONFIRM,
    RSVP_CLASS_LABEL,
    RSVP_CLASS_HOP_COUNT,
    RSVP_CLASS_STRICT_SOURCE_ROUTE,
    RSVP_CLASS_LABEL_REQUEST     =  19,
    RSVP_CLASS_EXPLICIT_ROUTE,
    RSVP_CLASS_RECORD_ROUTE,

    RSVP_CLASS_HELLO,

    RSVP_CLASS_MESSAGE_ID,
    RSVP_CLASS_MESSAGE_ID_ACK,
    RSVP_CLASS_MESSAGE_ID_LIST,

    /* 26-29  Unassigned */

    RSVP_CLASS_DIAGNOSTIC        = 30,
    RSVP_CLASS_ROUTE,
    RSVP_CLASS_DIAG_RESPONSE,
    RSVP_CLASS_DIAG_SELECT,
    RSVP_CLASS_RECOVERY_LABEL,
    RSVP_CLASS_UPSTREAM_LABEL,
    RSVP_CLASS_LABEL_SET,
    RSVP_CLASS_PROTECTION,

    /* 38-41  Unassigned */
    RSVP_CLASS_DSBM_IP_ADDRESS   = 42,
    RSVP_CLASS_SBM_PRIORITY,
    RSVP_CLASS_DSBM_TIMER_INTERVALS,
    RSVP_CLASS_SBM_INFO,

    /* 46-62  Unassigned */

    RSVP_CLASS_DETOUR            = 63,
    RSVP_CLASS_CHALLENGE,
    RSVP_CLASS_DIFFSERV,
    RSVP_CLASS_CLASSTYPE, /* FF: RFC4124 */
    RSVP_CLASS_LSP_REQUIRED_ATTRIBUTES,

    /* 68-123  Unassigned */

    RSVP_CLASS_VENDOR_PRIVATE_1  = 124,
    RSVP_CLASS_VENDOR_PRIVATE_2  = 125,
    RSVP_CLASS_VENDOR_PRIVATE_3  = 126,
    RSVP_CLASS_VENDOR_PRIVATE_4  = 127,

    RSVP_CLASS_NODE_CHAR         = 128,
    RSVP_CLASS_SUGGESTED_LABEL,
    RSVP_CLASS_ACCEPTABLE_LABEL_SET,
    RSVP_CLASS_RESTART_CAP,

    /* 132-160 Unassigned */

    /* 166-187 Unassigned */

    RSVP_CLASS_VENDOR_PRIVATE_5  = 188,
    RSVP_CLASS_VENDOR_PRIVATE_6  = 189,
    RSVP_CLASS_VENDOR_PRIVATE_7  = 190,
    RSVP_CLASS_VENDOR_PRIVATE_8  = 191,

    RSVP_CLASS_SESSION_ASSOC     = 192,
    RSVP_CLASS_LSP_TUNNEL_IF_ID,
    /* 194 Unassigned */
    RSVP_CLASS_NOTIFY_REQUEST    = 195,
    RSVP_CLASS_ADMIN_STATUS,
    RSVP_CLASS_LSP_ATTRIBUTES,
    RSVP_CLASS_ALARM_SPEC,
    RSVP_CLASS_ASSOCIATION,

    /* 203-204  Unassigned */
    RSVP_CLASS_FAST_REROUTE      = 205,
    /* 206 Unassigned */
    RSVP_CLASS_SESSION_ATTRIBUTE = 207,
    /* 208-223 Unassigned */
    /*
      Class Numbers 224-255 are assigned by IANA using FCFS allocation.
      RSVP will silently ignore, but FORWARD an object with a Class Number
      in this range that it does not understand.
    */
    /* 224  Unassigned */
    RSVP_CLASS_DCLASS            = 225,
    RSVP_CLASS_PACKETCABLE_EXTENSIONS,
    RSVP_CLASS_ATM_SERVICECLASS,
    RSVP_CLASS_CALL_OPS,
    RSVP_CLASS_GENERALIZED_UNI,
    RSVP_CLASS_CALL_ID,
    RSVP_CLASS_3GPP2_OBJECT,

    /* 232-251 Unassigned */

    RSVP_CLASS_VENDOR_PRIVATE_9  = 252,
    RSVP_CLASS_VENDOR_PRIVATE_10 = 253,
    RSVP_CLASS_VENDOR_PRIVATE_11 = 254,
    RSVP_CLASS_VENDOR_PRIVATE_12 = 255
};

/* XXX: are any/all of the "missing" values below supposed to have value-strings */
static const value_string rsvp_class_vals[] = {
    { RSVP_CLASS_NULL,                  "NULL object"},
    { RSVP_CLASS_SESSION,               "SESSION object"},

    { RSVP_CLASS_HOP,                   "HOP object"},
    { RSVP_CLASS_INTEGRITY,             "INTEGRITY object"},
    { RSVP_CLASS_TIME_VALUES,           "TIME VALUES object"},
    { RSVP_CLASS_ERROR,                 "ERROR object"},
    { RSVP_CLASS_SCOPE,                 "SCOPE object"},
    { RSVP_CLASS_STYLE,                 "STYLE object"},
    { RSVP_CLASS_FLOWSPEC,              "FLOWSPEC object"},
    { RSVP_CLASS_FILTER_SPEC,           "FILTER SPEC object"},
    { RSVP_CLASS_SENDER_TEMPLATE,       "SENDER TEMPLATE object"},
    { RSVP_CLASS_SENDER_TSPEC,          "SENDER TSPEC object"},
    { RSVP_CLASS_ADSPEC,                "ADSPEC object"},
    { RSVP_CLASS_POLICY,                "POLICY object"},
    { RSVP_CLASS_CONFIRM,               "CONFIRM object"},
    { RSVP_CLASS_LABEL,                 "LABEL object"},
    { RSVP_CLASS_HOP_COUNT,             "HOP_COUNT object"},
    { RSVP_CLASS_STRICT_SOURCE_ROUTE,   "STRICT_SOURCE_ROUTE object"},
    { RSVP_CLASS_LABEL_REQUEST,         "LABEL REQUEST object"},
    { RSVP_CLASS_EXPLICIT_ROUTE,        "EXPLICIT ROUTE object"},
    { RSVP_CLASS_RECORD_ROUTE,          "RECORD ROUTE object"},

    { RSVP_CLASS_HELLO,                 "HELLO object"},

    { RSVP_CLASS_MESSAGE_ID,            "MESSAGE-ID object"},
    { RSVP_CLASS_MESSAGE_ID_ACK,        "MESSAGE-ID ACK/NACK object"},
    { RSVP_CLASS_MESSAGE_ID_LIST,       "MESSAGE-ID LIST object"},

/*
    RSVP_CLASS_DIAGNOSTIC
    RSVP_CLASS_ROUTE,
    RSVP_CLASS_DIAG_RESPONSE,
    RSVP_CLASS_DIAG_SELECT,
*/

    { RSVP_CLASS_RECOVERY_LABEL,        "RECOVERY-LABEL object"},
    { RSVP_CLASS_UPSTREAM_LABEL,        "UPSTREAM-LABEL object"},
    { RSVP_CLASS_LABEL_SET,             "LABEL-SET object"},
    { RSVP_CLASS_PROTECTION,            "PROTECTION object"},

/*
    RSVP_CLASS_DSBM_IP_ADDRESS
    RSVP_CLASS_SBM_PRIORITY,
    RSVP_CLASS_DSBM_TIMER_INTERVALS,
    RSVP_CLASS_SBM_INFO,
*/

    { RSVP_CLASS_DETOUR,                "DETOUR object"},
/*
    RSVP_CLASS_CHALLENGE,
*/
    { RSVP_CLASS_DIFFSERV,              "DIFFSERV object"},
    { RSVP_CLASS_CLASSTYPE,             "CLASSTYPE object"},
/*
    RSVP_CLASS_LSP_REQUIRED_ATTRIBUTES,
*/

    { RSVP_CLASS_VENDOR_PRIVATE_1,      "VENDOR PRIVATE object (0bbbbbbb: "
                                        "reject if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_2,      "VENDOR PRIVATE object (0bbbbbbb: "
                                         "reject if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_3,      "VENDOR PRIVATE object (0bbbbbbb: "
                                         "reject if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_4,      "VENDOR PRIVATE object (0bbbbbbb: "
                                         "reject if unknown)"},

/*
    RSVP_CLASS_NODE_CHAR
*/
    { RSVP_CLASS_SUGGESTED_LABEL,       "SUGGESTED-LABEL object"},
    { RSVP_CLASS_ACCEPTABLE_LABEL_SET,  "ACCEPTABLE-LABEL-SET object"},
    { RSVP_CLASS_RESTART_CAP,           "RESTART-CAPABILITY object"},

    { RSVP_CLASS_VENDOR_PRIVATE_5,      "VENDOR PRIVATE object (10bbbbbb: "
                                         "ignore if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_6,      "VENDOR PRIVATE object (10bbbbbb: "
                                         "ignore if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_7,      "VENDOR PRIVATE object (10bbbbbb: "
                                         "ignore if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_8,      "VENDOR PRIVATE object (10bbbbbb: "
                                         "ignore if unknown)"},
/*
    RSVP_CLASS_SESSION_ASSOC
*/
    { RSVP_CLASS_LSP_TUNNEL_IF_ID,      "LSP-TUNNEL INTERFACE-ID object"},

    { RSVP_CLASS_NOTIFY_REQUEST,        "NOTIFY-REQUEST object"},
    { RSVP_CLASS_ADMIN_STATUS,          "ADMIN-STATUS object"},
    { RSVP_CLASS_LSP_ATTRIBUTES,        "LSP ATTRIBUTES object"},
/*
    RSVP_CLASS_ALARM_SPEC,
*/
    { RSVP_CLASS_ASSOCIATION,           "ASSOCIATION object"},

    { RSVP_CLASS_FAST_REROUTE,          "FAST-REROUTE object"},

    { RSVP_CLASS_SESSION_ATTRIBUTE,     "SESSION ATTRIBUTE object"},

    { RSVP_CLASS_DCLASS,                "DCLASS object"},
/*
    RSVP_CLASS_PACKETCABLE_EXTENSIONS,
    RSVP_CLASS_ATM_SERVICECLASS,
    RSVP_CLASS_CALL_OPS,
*/
    { RSVP_CLASS_GENERALIZED_UNI,       "GENERALIZED-UNI object"},
    { RSVP_CLASS_CALL_ID,               "CALL-ID object"},
/*
    RSVP_CLASS_3GPP2_OBJECT,
*/

    { RSVP_CLASS_VENDOR_PRIVATE_9,      "VENDOR PRIVATE object (11bbbbbb: "
                                         "forward if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_10,     "VENDOR PRIVATE object (11bbbbbb: "
                                          "forward if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_11,     "VENDOR PRIVATE object (11bbbbbb: "
                                          "forward if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_12,     "VENDOR PRIVATE object (11bbbbbb: "
                                          "forward if unknown)"},
    { 0, NULL}
};
static value_string_ext rsvp_class_vals_ext = VALUE_STRING_EXT_INIT(rsvp_class_vals);

/*
 * RSVP error values
 */
enum rsvp_error_types {
    RSVP_ERROR_CONFIRM   = 0,
    RSVP_ERROR_ADMISSION,
    RSVP_ERROR_POLICY,
    RSVP_ERROR_NO_PATH,
    RSVP_ERROR_NO_SENDER,
    RSVP_ERROR_CONFLICT_RESV_STYLE,
    RSVP_ERROR_UNKNOWN_RESV_STYLE,
    RSVP_ERROR_CONFLICT_DEST_PORTS,
    RSVP_ERROR_CONFLICT_SRC_PORTS,
    RSVP_ERROR_PREEMPTED =12,
    RSVP_ERROR_UNKNOWN_CLASS,
    RSVP_ERROR_UNKNOWN_C_TYPE,
    RSVP_ERROR_TRAFFIC   = 21,
    RSVP_ERROR_TRAFFIC_SYSTEM,
    RSVP_ERROR_SYSTEM,
    RSVP_ERROR_ROUTING,
    RSVP_ERROR_NOTIFY,
    RSVP_ERROR_NEW_AGGR,          /* RFC3175 */
    RSVP_ERROR_DIFFSERV,
    RSVP_ERROR_DSTE,          /* FF: RFC4124 */
    RSVP_ERROR_UNKNOWN_ATTR_TLV,  /* RFC5420 */
    RSVP_ERROR_UNKNOWN_ATTR_BIT,  /* RFC5420 */
    RSVP_ERROR_ALARMS,            /* RFC4783 */
    RSVP_ERROR_CALL_MGMT,         /* RFC4974 */
    RSVP_ERROR_USER_ERROR_SPEC    /* RFC5284 */
};

static const value_string rsvp_error_codes[] = {
    { RSVP_ERROR_CONFIRM,              "Confirmation"},
    { RSVP_ERROR_ADMISSION,            "Admission Control Failure "},
    { RSVP_ERROR_POLICY,               "Policy Control Failure"},
    { RSVP_ERROR_NO_PATH,              "No PATH information for this RESV message"},
    { RSVP_ERROR_NO_SENDER,            "No sender information for this RESV message"},
    { RSVP_ERROR_CONFLICT_RESV_STYLE,  "Conflicting reservation styles"},
    { RSVP_ERROR_UNKNOWN_RESV_STYLE,   "Unknown reservation style"},
    { RSVP_ERROR_CONFLICT_DEST_PORTS,  "Conflicting destination ports"},
    { RSVP_ERROR_CONFLICT_SRC_PORTS,   "Conflicting source ports"},
    { RSVP_ERROR_PREEMPTED,            "Service preempted"},
    { RSVP_ERROR_UNKNOWN_CLASS,        "Unknown object class"},
    { RSVP_ERROR_UNKNOWN_C_TYPE,       "Unknown object C-type"},
    { RSVP_ERROR_TRAFFIC,              "Traffic Control Error"},
    { RSVP_ERROR_TRAFFIC_SYSTEM,       "Traffic Control System Error"},
    { RSVP_ERROR_SYSTEM,               "RSVP System Error"},
    { RSVP_ERROR_ROUTING,              "Routing Error"},
    { RSVP_ERROR_NOTIFY,               "RSVP Notify Error"},
    { RSVP_ERROR_NEW_AGGR,             "New aggregate needed"},
    { RSVP_ERROR_DIFFSERV,             "RSVP Diff-Serv Error"},
    { RSVP_ERROR_DSTE,                 "RSVP DiffServ-aware TE Error"},
    { RSVP_ERROR_UNKNOWN_ATTR_TLV,     "Unknown attributes TLV"},
    { RSVP_ERROR_UNKNOWN_ATTR_BIT,     "Unknown attributes bit"},
    { RSVP_ERROR_ALARMS,               "Alarms"},
    { RSVP_ERROR_CALL_MGMT,            "Call management"},
    { RSVP_ERROR_USER_ERROR_SPEC,      "User error spec"},
    { 0, NULL}
};
static value_string_ext rsvp_error_codes_ext = VALUE_STRING_EXT_INIT(rsvp_error_codes);

static const value_string rsvp_admission_control_error_vals[] = {
    { 1, "Delay bound cannot be met"},
    { 2, "Requested bandwidth unavailable"},
    { 3, "MTU in flowspec larger than interface MTU"},
    { 4, "LSP Admission Failure"},
    { 5, "Bad Association Type"},
    { 0, NULL}
};
static value_string_ext rsvp_admission_control_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_admission_control_error_vals);

static const value_string rsvp_policy_control_error_vals[] = {
    {   0, "Information reporting"},
    {   1, "Warning"},
    {   2, "Reason unknown"},
    {   3, "Generic Policy Rejection"},
    {   4, "Quota or Accounting violation"},
    {   5, "Flow was preempted"},
    {   6, "Previously installed policy expired (not refreshed)"},
    {   7, "Previous policy data was replaced & caused rejection"},
    {   8, "Policies could not be merged (multicast)"},
    {   9, "PDP down or non functioning"},
    {  10, "Third Party Server (e.g., Kerberos) unavailable"},
    {  11, "POLICY_DATA object has bad syntax"},
    {  12, "POLICY_DATA object failed Integrity Check"},
    {  13, "POLICY_ELEMENT object has bad syntax"},
    {  14, "Mandatory PE Missing (Empty PE is in the PD object)"},
    {  15, "PEP Out of resources to handle policies."},
    {  16, "PDP encountered bad RSVP objects or syntax"},
    {  17, "Service type was rejected"},
    {  18, "Reservation Style was rejected"},
    {  19, "FlowSpec was rejected (too large)"},
    {  20, "Hard Pre-empted"},
    { 100, "Unauthorized sender"},
    { 101, "Unauthorized receiver"},
    { 102, "ERR_PARTIAL_PREEMPT"},
    { 103, "Inter-domain policy failure"},
    { 104, "Inter-domain explicit route rejected"},
    {   0, NULL}
};
static value_string_ext rsvp_policy_control_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_policy_control_error_vals);

static const value_string rsvp_traffic_control_error_vals[] = {
    { 1, "Service conflict"},
    { 2, "Service unsupported"},
    { 3, "Bad Flowspec value"},
    { 4, "Bad Tspec value"},
    { 5, "Bad Adspec value"},
    { 0, NULL}
};
static value_string_ext rsvp_traffic_control_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_traffic_control_error_vals);

static const value_string rsvp_routing_error_vals[] = {
    {   1, "Bad EXPLICIT_ROUTE object"},
    {   2, "Bad strict node"},
    {   3, "Bad loose node"},
    {   4, "Bad initial subobject"},
    {   5, "No route available toward destination"},
    {   6, "Unacceptable label value"},
    {   7, "RRO indicated routing loops"},
    {   8, "non-RSVP-capable router stands in the path"},
    {   9, "MPLS label allocation failure"},
    {  10, "Unsupported L3PID"},
    {  11, "Label Set"},
    {  12, "Switching Type"},
    {  13, "Unassigned"},
    {  14, "Unsupported Encoding"},
    {  15, "Unsupported Link Protection"},
    {  16, "Unknown Interface Index"},
    {  17, "Unsupported LSP Protection"},
    {  18, "PROTECTION object not applicable"},
    {  19, "Bad PRIMARY_PATH_ROUTE object"},
    {  20, "PRIMARY_PATH_ROUTE object not applicable"},
    {  21, "LSP Segment Protection Failed"},
    {  22, "Re-routing limit exceeded"},
    {  23, "Unable to Branch"},
    {  24, "Unsupported LSP Integrity"},
    {  25, "P2MP Re-Merge Detected"},
    {  26, "P2MP Re-Merge Parameter Mismatch"},
    {  27, "ERO Resulted in Re-Merge"},
    {  28, "Contiguous LSP type not supported"},
    {  29, "ERO conflicts with inter-domain signaling method"},
    {  30, "Stitching unsupported"},
    {  31, "Unknown PCE-ID for PKS expansion"},
    {  32, "Unreachable PCE for PKS expansion"},
    {  33, "Unknown Path Key for PKS expansion"},
    {  34, "ERO too large for MTU"},
    {  64, "Unsupported Exclude Route Subobject Type"},
    {  65, "Inconsistent Subobject"},
    {  66, "Local Node in Exclude Route"},
    {  67, "Route Blocked by Exclude Route"},
    {  68, "XRO Too Complex"},
    {  69, "EXRS Too Complex"},
    { 100, "Diversity not available"},
    { 101, "Service level not available"},
    { 102, "Invalid/Unknown connection ID"},
    { 103, "No route available toward source (ASON)"},
    { 104, "Unacceptable interface ID (ASON)"},
    { 105, "Invalid/unknown call ID (ASON)"},
    { 106, "Invalid SPC interface ID/label (ASON)"},
    {   0, NULL}
};
static value_string_ext rsvp_routing_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_routing_error_vals);

static const value_string rsvp_notify_error_vals[] = {
    {  1, "RRO too large for MTU"},
    {  2, "RRO Notification"},
    {  3, "Tunnel locally repaired"},
    {  4, "Control Channel Active State"},
    {  5, "Control Channel Degraded State"},
    {  6, "Preferable path exists"},
    {  7, "Link maintenance required"},
    {  8, "Node maintenance required"},
    {  9, "LSP Failure"},
    { 10, "LSP recovered"},
    { 11, "LSP Local Failure"},
    {  0, NULL}
};
static value_string_ext rsvp_notify_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_notify_error_vals);

static const value_string rsvp_diffserv_error_vals[] = {
    { 1, "Unexpected DIFFSERV object"},
    { 2, "Unsupported PHB"},
    { 3, "Invalid `EXP<->PHB mapping'"},
    { 4, "Unsupported PSC"},
    { 5, "Per-LSP context allocation failure"},
    { 0, NULL}
};
static value_string_ext rsvp_diffserv_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_diffserv_error_vals);

/* FF: RFC4124 */
static const value_string rsvp_diffserv_aware_te_error_vals[] = {
    { 1, "Unexpected CLASSTYPE object"},
    { 2, "Unsupported Class-Type"},
    { 3, "Invalid Class-Type value"},
    { 4, "CT and setup priority do not form a configured TE-Class"},
    { 5, "CT and holding priority do not form a configured TE-Class"},
    { 6, "CT and setup priority do not form a configured TE-Class AND CT and holding priority do not form a configured TE-Class"},
    { 7, "Inconsistency between signaled PSC and signaled CT"},
    { 8, "Inconsistency between signaled PHBs and signaled CT"},
    { 0, NULL}
};
static value_string_ext rsvp_diffserv_aware_te_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_diffserv_aware_te_error_vals);

static const value_string rsvp_call_mgmt_error_vals[] = {
    { 1, "Call ID Contention"},
    { 2, "Connections still Exist"},
    { 3, "Unknown Call ID"},
    { 4, "Duplicate Call"},
    { 0, NULL}
};
static value_string_ext rsvp_call_mgmt_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_call_mgmt_error_vals);

/*
 * Defines the reservation style plus style-specific information that
 * is not a FLOWSPEC or FILTER_SPEC object, in a RESV message.
 */
#define RSVP_DISTINCT (1 << 3)
#define RSVP_SHARED   (2 << 3)
#define RSVP_SHARING_MASK (RSVP_DISTINCT | RSVP_SHARED)

#define RSVP_SCOPE_WILD     1
#define RSVP_SCOPE_EXPLICIT 2
#define RSVP_SCOPE_MASK     0x07

#define RSVP_WF (RSVP_SHARED   | RSVP_SCOPE_WILD)
#define RSVP_FF (RSVP_DISTINCT | RSVP_SCOPE_EXPLICIT)
#define RSVP_SE (RSVP_SHARED   | RSVP_SCOPE_EXPLICIT)

static const value_string style_vals[] = {
    { RSVP_WF, "Wildcard Filter" },
    { RSVP_FF, "Fixed Filter" },
    { RSVP_SE, "Shared-Explicit" },
    { 0,       NULL }
};

enum {
    RSVP_SESSION_TYPE_IPV4 = 1,
    RSVP_SESSION_TYPE_IPV6,

    RSVP_SESSION_TYPE_IPV4_LSP = 7,
    RSVP_SESSION_TYPE_IPV6_LSP,

    RSVP_SESSION_TYPE_AGGREGATE_IPV4 = 9,
    RSVP_SESSION_TYPE_AGGREGATE_IPV6,

    RSVP_SESSION_TYPE_IPV4_UNI = 11,
    RSVP_SESSION_TYPE_IPV4_E_NNI = 15
};

/*
 * Defines a desired QoS, in a RESV message.
 */
enum    qos_service_type {
    QOS_QUALITATIVE =     128,          /* Qualitative service */
    QOS_NULL =              6,          /* Null service (RFC2997) */
    QOS_CONTROLLED_LOAD=    5,          /* Controlled Load Service */
    QOS_GUARANTEED =        2,          /* Guaranteed service */
    QOS_TSPEC =             1           /* Traffic specification */
};

static const value_string qos_vals[] = {
    { QOS_QUALITATIVE,     "Qualitative QoS" },
    { QOS_NULL,            "Null-Service QoS" },
    { QOS_CONTROLLED_LOAD, "Controlled-load QoS" },
    { QOS_GUARANTEED,      "Guaranteed rate QoS" },
    { QOS_TSPEC,           "Traffic specification" },
    { 0, NULL }
};

static const value_string svc_vals[] = {
    { 126, "Compression Hint" },
    { 127, "Token bucket" },
    { 128, "Null Service" },
    { 130, "Guaranteed-rate RSpec" },
    { 0, NULL }
};
static value_string_ext svc_vals_ext = VALUE_STRING_EXT_INIT(svc_vals);

enum rsvp_spec_types { INTSRV = 2 };

enum intsrv_services {
    INTSRV_GENERAL     =   1,
    INTSRV_GTD         =   2,
    INTSRV_CLOAD       =   5,
    INTSRV_NULL        =   6,
    INTSRV_QUALITATIVE = 128
};

static const value_string intsrv_services_str[] = {
    { INTSRV_GENERAL,     "Default General Parameters"},
    { INTSRV_GTD,         "Guaranteed Rate"},
    { INTSRV_CLOAD,       "Controlled Load"},
    { INTSRV_NULL,        "Null Service"},
    { INTSRV_QUALITATIVE, "Null Service"},
    { 0, NULL }
};
static value_string_ext intsrv_services_str_ext = VALUE_STRING_EXT_INIT(intsrv_services_str);

#if 0
enum intsrv_field_name {
    INTSRV_NON_IS_HOPS           = 1,
    INTSRV_COMPOSED_NON_IS_HOPS,
    INTSRV_IS_HOPS,
    INTSRV_COMPOSED_IS_HOPS,
    INTSRV_PATH_BANDWIDTH,
    INTSRV_MIN_PATH_BANDWIDTH,
    INTSRV_IF_LATENCY,
    INTSRV_PATH_LATENCY,
    INTSRV_MTU,
    INTSRV_COMPOSED_MTU,

    INTSRV_TOKEN_BUCKET_TSPEC    = 127,
    INTSRV_QUALITATIVE_TSPEC     = 128,
    INTSRV_GTD_RSPEC             = 130,

    INTSRV_DELAY = 131,         /* Gtd Parameter C - Max Delay Bound - bytes */
    INTSRV_MAX_JITTER,          /* Gtd Parameter D - Max Jitter */
    INTSRV_E2E_DELAY,           /* Gtd Parameter Ctot */
    INTSRV_E2E_MAX_JITTER,      /* Gtd Parameter Dtot */
    INTSRV_SHP_DELAY,           /* Gtd Parameter Csum */
    INTSRV_SHP_MAX_JITTER       /* Gtd Parameter Dsum */
};
#endif

static const value_string adspec_params[] = {
    {   4, "IS Hop Count"},
    {   6, "Path b/w estimate"},
    {   8, "Minimum path latency"},
    {  10, "Composed MTU"},
    { 133, "End-to-end composed value for C"},
    { 134, "End-to-end composed value for D"},
    { 135, "Since-last-reshaping point composed C"},
    { 136, "Since-last-reshaping point composed D"},
    {   0, NULL }
};
static value_string_ext adspec_params_ext = VALUE_STRING_EXT_INIT(adspec_params);

/*
 * FF: please keep this list in sync with
 * http://www.iana.org/assignments/gmpls-sig-parameters
 * Registry Name: 'LSP Encoding Types'
 */
const range_string gmpls_lsp_enc_rvals[] = {
    {   1,   1, "Packet" },
    {   2,   2, "Ethernet" },
    {   3,   3, "ANSI/ETSI PDH" },
    {   4,   4, "Reserved" },
    {   5,   5, "SDH ITU-T G.707 / SONET ANSI T1.105" },
    {   6,   6, "Reserved" },
    {   7,   7, "Digital Wrapper" },
    {   8,   8, "Lambda (photonic)" },
    {   9,   9, "Fiber" },
    {  10,  10, "Reserved" },
    {  11,  11, "FiberChannel" },
    {  12,  12, "G.709 ODUk (Digital Path)" },
    {  13,  13, "G.709 Optical Channel" },
    {  14, 239, "Unassigned" },
    { 240, 255, "Experimental Usage/temporarily" },
    {   0,   0, NULL }
};

/*
 * FF: please keep this list in sync with
 * http://www.iana.org/assignments/gmpls-sig-parameters
 * Registry Name: 'Switching Types'
 */
const range_string gmpls_switching_type_rvals[] = {
    {   1,   1, "Packet-Switch Capable-1 (PSC-1)" },
    {   2,   2, "Packet-Switch Capable-2 (PSC-2)" },
    {   3,   3, "Packet-Switch Capable-3 (PSC-3)" },
    {   4,   4, "Packet-Switch Capable-4 (PSC-4)" },
    {   5,  29, "Unassigned" },
    {  30,  30, "Ethernet Virtual Private Line (EVPL)" },
    {  31,  39, "Unassigned" },
    {  40,  40, "802.1 PBB-TE" },
    {  41,  50, "Unassigned" },
    {  51,  51, "Layer-2 Switch Capable (L2SC)" },
    {  52,  99, "Unassigned" },
    { 100, 100, "Time-Division-Multiplex Capable (TDM)" },
    { 101, 124, "Unassigned" },
    { 125, 125, "Data Channel Switching Capable (DCSC)" },
    { 126, 149, "Unassigned" },
    { 150, 150, "Lambda-Switch Capable (LSC)" },
    { 151, 169, "Unassigned" },
    { 200, 200, "Fiber-Switch Capable (FSC)" },
    { 201, 255, "Unassigned" },
    {   0,   0, NULL }
};

/*
 * FF: please keep this list in sync with
 * http://www.iana.org/assignments/gmpls-sig-parameters
 * Registry Name: 'Generalized PID (G-PID)'
 */
static const range_string gmpls_gpid_rvals[] = {
    {      0,     0, "Unknown" },
    {      1,     4, "Reserved" },
    {      5,     5, "Asynchronous mapping of E4" },
    {      6,     6, "Asynchronous mapping of DS3/T3" },
    {      7,     7, "Asynchronous mapping of E3" },
    {      8,     8, "Bit synchronous mapping of E3" },
    {      9,     9, "Byte synchronous mapping of E3" },
    {     10,    10, "Asynchronous mapping of DS2/T2" },
    {     11,    11, "Bit synchronous mapping of DS2/T2" },
    {     12,    12, "Reserved" },
    {     13,    13, "Asynchronous mapping of E1" },
    {     14,    14, "Byte synchronous mapping of E1" },
    {     15,    15, "Byte synchronous mapping of 31 * DS0" },
    {     16,    16, "Asynchronous mapping of DS1/T1" },
    {     17,    17, "Bit synchronous mapping of DS1/T1" },
    {     18,    18, "Byte synchronous mapping of DS1/T1" },
    {     19,    19, "VC-11 in VC-12" },
    {     20,    21, "Reserved" },
    {     22,    22, "DS1 SF Asynchronous" },
    {     23,    23, "DS1 ESF Asynchronous" },
    {     24,    24, "DS3 M23 Asynchronous" },
    {     25,    25, "DS3 C-Bit Parity Asynchronous" },
    {     26,    26, "VT/LOVC" },
    {     27,    27, "STS SPE/HOVC" },
    {     28,    28, "POS - No Scrambling, 16 bit CRC" },
    {     29,    29, "POS - No Scrambling, 32 bit CRC" },
    {     30,    30, "POS - Scrambling, 16 bit CRC" },
    {     31,    31, "POS - Scrambling, 32 bit CRC" },
    {     32,    32, "ATM mapping" },
    {     33,    33, "Ethernet PHY" },
    {     34,    34, "SONET/SDH" },
    {     35,    35, "Reserved (SONET deprecated)" },
    {     36,    36, "Digital Wrapper" },
    {     37,    37, "Lambda" },
    {     38,    38, "ANSI/ETSI PDH" },
    {     39,    39, "Reserved" },
    {     40,    40, "Link Access Protocol SDH (LAPS - X.85 and X.86)" },
    {     41,    41, "FDDI" },
    {     42,    42, "DQDB (ETSI ETS 300 216)" },
    {     43,    43, "FiberChannel-3 (Services)" },
    {     44,    44, "HDLC" },
    {     45,    45, "Ethernet V2/DIX (only)" },
    {     46,    46, "Ethernet 802.3 (only)" },
    {     47,    47, "G.709 ODUj" },
    {     48,    48, "G.709 OTUk(v)" },
    {     49,    49, "CBR/CBRa" },
    {     50,    50, "CBRb" },
    {     51,    51, "BSOT" },
    {     52,    52, "BSNT" },
    {     53,    53, "IP/PPP (GFP)" },
    {     54,    54, "Ethernet MAC (framed GFP)" },
    {     55,    55, "Ethernet PHY (transparent GFP" },
    {     56,    56, "ESCON" },
    {     57,    57, "FICON" },
    {     58,    58, "Fiber Channel" },
    {     59, 31743, "Unassigned" },
    {  31744, 32767, "Experimental Usage/temporarily" },
    {  32768, 65535, "Reserved" },
    {      0,     0, NULL },
};

const value_string gmpls_protection_cap_str[] = {
    {   1, "Extra Traffic"},
    {   2, "Unprotected"},
    {   4, "Shared"},
    {   8, "Dedicated 1:1"},
    {  16, "Dedicated 1+1"},
    {  32, "Enhanced"},
    {  64, "Reserved"},
    { 128, "Reserved"},
    {   0, NULL }
};

static const value_string gmpls_sonet_signal_type_str[] = {
    {  1, "VT1.5 SPE / VC-11"},
    {  2, "VT2 SPE / VC-12"},
    {  3, "VT3 SPE"},
    {  4, "VT6 SPE / VC-2"},
    {  5, "STS-1 SPE / VC-3"},
    {  6, "STS-3c SPE / VC-4"},
    {  7, "STS-1 / STM-0 (transp)"},
    {  8, "STS-3 / STM-1 (transp)"},
    {  9, "STS-12 / STM-4 (transp)"},
    { 10, "STS-48 / STM-16 (transp)"},
    { 11, "STS-192 / STM-64 (transp)"},
    { 12, "STS-768 / STM-256 (transp)"},

    /* Extended non-SONET signal types */
    { 13, "VTG / TUG-2"},
    { 14, "TUG-3"},
    { 15, "STSG-3 / AUG-1"},
    { 16, "STSG-12  / AUG-4"},
    { 17, "STSG-48  / AUG-16"},
    { 18, "STSG-192 / AUG-64"},
    { 19, "STSG-768 / AUG-256"},

    /* Other SONEt signal types */
    { 21, "STS-12c SPE / VC-4-4c"},
    { 22, "STS-48c SPE / VC-4-16c"},
    { 23, "STS-192c SPE / VC-4-64c"},
    {  0, NULL}
};
value_string_ext gmpls_sonet_signal_type_str_ext = VALUE_STRING_EXT_INIT(gmpls_sonet_signal_type_str);

static const value_string ouni_guni_diversity_str[] = {
    { 1, "Node Diverse"},
    { 2, "Link Diverse"},
    { 3, "Shared-Risk Link Group Diverse"},
    { 4, "Shared Path"},
    { 0, NULL}
};

/* FF: RFC 4328 G.709 signal type */
static const range_string gmpls_g709_signal_type_rvals[] = {
    { 0,   0, "Not significant"},
    { 1,   1, "ODU1 (i.e., 2.5 Gbps)"},
    { 2,   2, "ODU2 (i.e., 10  Gbps)"},
    { 3,   3, "ODU3 (i.e., 40  Gbps)"},
    { 4,   5, "Reserved (for future use)"},
    { 6,   6, "OCh at 2.5 Gbps"},
    { 7,   7, "OCh at 10  Gbps"},
    { 8,   8, "OCh at 40  Gbps"},
    { 9, 255, "Reserved (for future use)"},
    { 0,   0, NULL}
};

/* -------------------- Stuff for MPLS/TE objects -------------------- */

static const value_string proto_vals[] = {
    { IP_PROTO_ICMP, "ICMP"},
    { IP_PROTO_IGMP, "IGMP"},
    { IP_PROTO_TCP,  "TCP" },
    { IP_PROTO_UDP,  "UDP" },
    { IP_PROTO_OSPF, "OSPF"},
    { 0,             NULL  }
};

/* Filter keys */
enum hf_rsvp_filter_keys {

    /* Message types */
    RSVPF_MSG,          /* Message type */
    /* Shorthand for message types */
    RSVPF_PATH,
    RSVPF_RESV,
    RSVPF_PATHERR,
    RSVPF_RESVERR,
    RSVPF_PATHTEAR,
    RSVPF_RESVTEAR,
    RSVPF_RCONFIRM,
    RSVPF_JUNK_MSG8,
    RSVPF_JUNK_MSG9,
    RSVPF_RTEARCONFIRM,
    RSVPF_JUNK11,
    RSVPF_BUNDLE,
    RSVPF_ACK,
    RSVPF_JUNK14,
    RSVPF_SREFRESH,
    RSVPF_JUNK16,
    RSVPF_JUNK17,
    RSVPF_JUNK18,
    RSVPF_JUNK19,
    RSVPF_HELLO,
    RSVPF_NOTIFY,
    /* Does the message contain an object of this type? */
    RSVPF_OBJECT,
    /* Object present shorthands */
    RSVPF_SESSION,
    RSVPF_DUMMY_1,
    RSVPF_HOP,
    RSVPF_INTEGRITY,
    RSVPF_TIME_VALUES,
    RSVPF_ERROR,
    RSVPF_SCOPE,
    RSVPF_STYLE,
    RSVPF_FLOWSPEC,
    RSVPF_FILTER_SPEC,
    RSVPF_SENDER,
    RSVPF_TSPEC,
    RSVPF_ADSPEC,
    RSVPF_POLICY,
    RSVPF_CONFIRM,
    RSVPF_LABEL,
    RSVPF_DUMMY_2,
    RSVPF_DUMMY_3,
    RSVPF_LABEL_REQUEST,
    RSVPF_EXPLICIT_ROUTE,
    RSVPF_RECORD_ROUTE,
    RSVPF_HELLO_OBJ,
    RSVPF_MESSAGE_ID,
    RSVPF_MESSAGE_ID_ACK,
    RSVPF_MESSAGE_ID_LIST,
    RSVPF_RECOVERY_LABEL,
    RSVPF_UPSTREAM_LABEL,
    RSVPF_LABEL_SET,
    RSVPF_PROTECTION,
    RSVPF_DIFFSERV,
    RSVPF_DSTE,

    RSVPF_SUGGESTED_LABEL,
    RSVPF_ACCEPTABLE_LABEL_SET,
    RSVPF_RESTART_CAP,

    RSVPF_SESSION_ATTRIBUTE,
    RSVPF_DCLASS,
    RSVPF_LSP_TUNNEL_IF_ID,
    RSVPF_NOTIFY_REQUEST,
    RSVPF_ADMIN_STATUS,
    RSVPF_ADMIN_STATUS_REFLECT,
    RSVPF_ADMIN_STATUS_HANDOVER,
    RSVPF_ADMIN_STATUS_LOCKOUT,
    RSVPF_ADMIN_STATUS_INHIBIT,
    RSVPF_ADMIN_STATUS_CALL_MGMT,
    RSVPF_ADMIN_STATUS_TESTING,
    RSVPF_ADMIN_STATUS_DOWN,
    RSVPF_ADMIN_STATUS_DELETE,
    RSVPF_LSP_ATTRIBUTES,
    RSVPF_ASSOCIATION,
    RSVPF_GENERALIZED_UNI,
    RSVPF_CALL_ID,
    RSVPF_UNKNOWN_OBJ,

    /* Session object */
    RSVPF_SESSION_IP,
    RSVPF_SESSION_PROTO,
    RSVPF_SESSION_PORT,
    RSVPF_SESSION_TUNNEL_ID,
    RSVPF_SESSION_EXT_TUNNEL_ID,

    /* Sender template */
    RSVPF_SENDER_IP,
    RSVPF_SENDER_PORT,
    RSVPF_SENDER_LSP_ID,

    /* Diffserv object */
    RSVPF_DIFFSERV_MAPNB,
    RSVPF_DIFFSERV_MAP,
    RSVPF_DIFFSERV_MAP_EXP,
    RSVPF_DIFFSERV_PHBID,
    RSVPF_DIFFSERV_PHBID_DSCP,
    RSVPF_DIFFSERV_PHBID_CODE,
    RSVPF_DIFFSERV_PHBID_BIT14,
    RSVPF_DIFFSERV_PHBID_BIT15,

    /* Diffserv-aware TE object */
    RSVPF_DSTE_CLASSTYPE,

    /* Generalized UNI object */
    RSVPF_GUNI_SRC_IPV4,
    RSVPF_GUNI_DST_IPV4,
    RSVPF_GUNI_SRC_IPV6,
    RSVPF_GUNI_DST_IPV6,

    /* CALL ID object */
    RSVPF_CALL_ID_SRC_ADDR_IPV4,
    RSVPF_CALL_ID_SRC_ADDR_IPV6,

    /* Vendor Private objects */
    RSVPF_PRIVATE_OBJ,
    RSVPF_ENT_CODE,

    /* Sentinel */
    RSVPF_MAX
};

static const true_false_string tfs_desired_not_desired = { "Desired", "Not Desired" };
static const true_false_string tfs_next_next_hop_next_hop = { "Next-Next-Hop", "Next-Hop" };
static const true_false_string tfs_gen_uni_direction = { "U: 1 - Upstream label/port ID", "U: 0 - Downstream label/port ID" };

static int hf_rsvp_filter[RSVPF_MAX] = { -1 };

/* RSVP Conversation related Hash functions */

/*
 * Compare two RSVP request keys to see if they are equal. Return 1 if they
 * are, 0 otherwise.
 * Two RSVP request keys are equal if and only if they have the exactly the
 * same internal conversation identifier, session type, and matching values in
 * the session info and source info structures.
 */
static gint
rsvp_equal(gconstpointer k1, gconstpointer k2)
{
    const struct rsvp_request_key *key1 = (const struct rsvp_request_key*) k1;
    const struct rsvp_request_key *key2 = (const struct rsvp_request_key*) k2;

    if (key1->conversation != key2->conversation) {
        return 0;
    }

    if (key1->session_type != key2->session_type) {
        return 0;
    }

    switch (key1->session_type) {
    case RSVP_SESSION_TYPE_IPV4:
        if (ADDRESSES_EQUAL(&key1->u.session_ipv4.destination,
                            &key2->u.session_ipv4.destination) == FALSE)
            return 0;

        if (key1->u.session_ipv4.protocol != key2->u.session_ipv4.protocol)
            return 0;

        if (key1->u.session_ipv4.udp_dest_port != key2->u.session_ipv4.udp_dest_port)
            return 0;

        break;

    case RSVP_SESSION_TYPE_IPV6:
        /* this is not supported yet for conversations */
        break;

    case RSVP_SESSION_TYPE_IPV4_LSP:
        if (ADDRESSES_EQUAL(&key1->u.session_ipv4_lsp.destination,
                            &key2->u.session_ipv4_lsp.destination) == FALSE)
            return 0;

        if (key1->u.session_ipv4_lsp.udp_dest_port !=
            key2->u.session_ipv4_lsp.udp_dest_port)
            return 0;


        if (key1->u.session_ipv4_lsp.ext_tunnel_id !=
            key2->u.session_ipv4_lsp.ext_tunnel_id)
            return 0;

        break;

    case RSVP_SESSION_TYPE_AGGREGATE_IPV4:
        if (ADDRESSES_EQUAL(&key1->u.session_agg_ipv4.destination,
                            &key2->u.session_agg_ipv4.destination) == FALSE)
            return 0;

        if (key1->u.session_agg_ipv4.dscp != key2->u.session_agg_ipv4.dscp)
            return 0;

        break;

    case RSVP_SESSION_TYPE_AGGREGATE_IPV6:
        /* this is not supported yet for conversations */
        break;

    case RSVP_SESSION_TYPE_IPV4_UNI:
        if (ADDRESSES_EQUAL(&key1->u.session_ipv4_uni.destination,
                            &key2->u.session_ipv4_uni.destination) == FALSE)
            return 0;

        if (key1->u.session_ipv4_uni.udp_dest_port !=
            key2->u.session_ipv4_uni.udp_dest_port)
            return 0;


        if (key1->u.session_ipv4_uni.ext_tunnel_id !=
            key2->u.session_ipv4_uni.ext_tunnel_id)
            return 0;

        break;

    case RSVP_SESSION_TYPE_IPV4_E_NNI:
        if (ADDRESSES_EQUAL(&key1->u.session_ipv4_enni.destination,
                            &key2->u.session_ipv4_enni.destination) == FALSE)
            return 0;

        if (key1->u.session_ipv4_enni.udp_dest_port !=
            key2->u.session_ipv4_enni.udp_dest_port)
            return 0;


        if (key1->u.session_ipv4_enni.ext_tunnel_id !=
            key2->u.session_ipv4_enni.ext_tunnel_id)
            return 0;

        break;

    default:
        /* This should never happen. */
        break;
    }

    if (ADDRESSES_EQUAL(&key1->source_info.source,
                        &key2->source_info.source) == FALSE)
        return 0;

    if (key1->source_info.udp_source_port != key2->source_info.udp_source_port)
        return 0;

    /* If we get here, the two keys are equal. */
    return 1;
}

/*
 * Calculate a hash key for the supplied RSVP request. The internally allocated
 * conversation-id is unique, so we just use that.
 */
static guint
rsvp_hash(gconstpointer k)
{
    const struct rsvp_request_key *key = (const struct rsvp_request_key*) k;
    return key->conversation;
}

/*
 * Conversation specific initialization code that deletes any unused memory that
 * might need to be freed, and allocates the memory for the various conversation
 * hash tables.
 */
static void
rsvp_init_protocol(void)
{
    if (rsvp_request_hash)
        g_hash_table_destroy(rsvp_request_hash);

    rsvp_request_hash = g_hash_table_new(rsvp_hash, rsvp_equal);
}

static inline int
rsvp_class_to_filter_num(int classnum)
{
    switch(classnum) {
    case RSVP_CLASS_SESSION :
    case RSVP_CLASS_HOP :
    case RSVP_CLASS_INTEGRITY :
    case RSVP_CLASS_TIME_VALUES :
    case RSVP_CLASS_ERROR :
    case RSVP_CLASS_SCOPE :
    case RSVP_CLASS_STYLE :
    case RSVP_CLASS_FLOWSPEC :
    case RSVP_CLASS_FILTER_SPEC :
    case RSVP_CLASS_SENDER_TEMPLATE :
    case RSVP_CLASS_SENDER_TSPEC :
    case RSVP_CLASS_ADSPEC :
    case RSVP_CLASS_POLICY :
    case RSVP_CLASS_CONFIRM :
    case RSVP_CLASS_LABEL :
    case RSVP_CLASS_LABEL_REQUEST :
    case RSVP_CLASS_HELLO :
    case RSVP_CLASS_EXPLICIT_ROUTE :
    case RSVP_CLASS_RECORD_ROUTE :
    case RSVP_CLASS_MESSAGE_ID :
    case RSVP_CLASS_MESSAGE_ID_ACK :
    case RSVP_CLASS_MESSAGE_ID_LIST :
        return classnum + RSVPF_OBJECT;
        break;

    case RSVP_CLASS_RECOVERY_LABEL :
    case RSVP_CLASS_UPSTREAM_LABEL :
    case RSVP_CLASS_LABEL_SET :
    case RSVP_CLASS_PROTECTION :
        return RSVPF_RECOVERY_LABEL + (classnum - RSVP_CLASS_RECOVERY_LABEL);

    case RSVP_CLASS_SUGGESTED_LABEL :
    case RSVP_CLASS_ACCEPTABLE_LABEL_SET :
    case RSVP_CLASS_RESTART_CAP :
        return RSVPF_SUGGESTED_LABEL + (classnum - RSVP_CLASS_SUGGESTED_LABEL);

    case RSVP_CLASS_DIFFSERV :
        return RSVPF_DIFFSERV;

    case RSVP_CLASS_CLASSTYPE :
        return RSVPF_DSTE;

    case RSVP_CLASS_NOTIFY_REQUEST :
        return RSVPF_NOTIFY_REQUEST;
    case RSVP_CLASS_ADMIN_STATUS :
        return RSVPF_ADMIN_STATUS;
    case RSVP_CLASS_LSP_ATTRIBUTES :
        return RSVPF_LSP_ATTRIBUTES;
    case RSVP_CLASS_ASSOCIATION :
        return RSVPF_ASSOCIATION;

    case RSVP_CLASS_SESSION_ATTRIBUTE :
        return RSVPF_SESSION_ATTRIBUTE;
    case RSVP_CLASS_GENERALIZED_UNI :
        return RSVPF_GENERALIZED_UNI;
    case RSVP_CLASS_CALL_ID :
        return RSVPF_CALL_ID;
    case RSVP_CLASS_DCLASS :
        return RSVPF_DCLASS;
    case RSVP_CLASS_LSP_TUNNEL_IF_ID :
        return RSVPF_LSP_TUNNEL_IF_ID;

    case RSVP_CLASS_VENDOR_PRIVATE_1:
    case RSVP_CLASS_VENDOR_PRIVATE_2:
    case RSVP_CLASS_VENDOR_PRIVATE_3:
    case RSVP_CLASS_VENDOR_PRIVATE_4:
    case RSVP_CLASS_VENDOR_PRIVATE_5:
    case RSVP_CLASS_VENDOR_PRIVATE_6:
    case RSVP_CLASS_VENDOR_PRIVATE_7:
    case RSVP_CLASS_VENDOR_PRIVATE_8:
    case RSVP_CLASS_VENDOR_PRIVATE_9:
    case RSVP_CLASS_VENDOR_PRIVATE_10:
    case RSVP_CLASS_VENDOR_PRIVATE_11:
    case RSVP_CLASS_VENDOR_PRIVATE_12:
       return RSVPF_PRIVATE_OBJ;

    default:
        return RSVPF_UNKNOWN_OBJ;
    }
}

static inline int
rsvp_class_to_tree_type(int classnum)
{
    switch(classnum) {
    case RSVP_CLASS_SESSION :
        return TT_SESSION;
    case RSVP_CLASS_HOP :
        return TT_HOP;
    case RSVP_CLASS_INTEGRITY :
        return TT_INTEGRITY;
    case RSVP_CLASS_TIME_VALUES :
        return TT_TIME_VALUES;
    case RSVP_CLASS_ERROR :
        return TT_ERROR;
    case RSVP_CLASS_SCOPE :
        return TT_SCOPE;
    case RSVP_CLASS_STYLE :
        return TT_STYLE;
    case RSVP_CLASS_FLOWSPEC :
        return TT_FLOWSPEC;
    case RSVP_CLASS_FILTER_SPEC :
        return TT_FILTER_SPEC;
    case RSVP_CLASS_SENDER_TEMPLATE :
        return TT_SENDER_TEMPLATE;
    case RSVP_CLASS_SENDER_TSPEC :
        return TT_TSPEC;
    case RSVP_CLASS_ADSPEC :
        return TT_ADSPEC;
    case RSVP_CLASS_POLICY :
        return TT_POLICY;
    case RSVP_CLASS_CONFIRM :
        return TT_CONFIRM;
    case RSVP_CLASS_RECOVERY_LABEL :
    case RSVP_CLASS_UPSTREAM_LABEL :
    case RSVP_CLASS_SUGGESTED_LABEL :
    case RSVP_CLASS_LABEL :
        return TT_LABEL;
    case RSVP_CLASS_LABEL_REQUEST :
        return TT_LABEL_REQUEST;
    case RSVP_CLASS_HELLO :
        return TT_HELLO_OBJ;
    case RSVP_CLASS_EXPLICIT_ROUTE :
        return TT_EXPLICIT_ROUTE;
    case RSVP_CLASS_RECORD_ROUTE :
        return TT_RECORD_ROUTE;
    case RSVP_CLASS_MESSAGE_ID :
        return TT_MESSAGE_ID;
    case RSVP_CLASS_MESSAGE_ID_ACK :
        return TT_MESSAGE_ID_ACK;
    case RSVP_CLASS_MESSAGE_ID_LIST :
        return TT_MESSAGE_ID_LIST;
    case RSVP_CLASS_LABEL_SET :
        return TT_LABEL_SET;
    case RSVP_CLASS_PROTECTION :
        return TT_PROTECTION_INFO;
    case RSVP_CLASS_ACCEPTABLE_LABEL_SET :
        return TT_UNKNOWN_CLASS;
    case RSVP_CLASS_RESTART_CAP :
        return TT_RESTART_CAP;
    case RSVP_CLASS_DIFFSERV :
        return TT_DIFFSERV;
    case RSVP_CLASS_CLASSTYPE:
        return TT_CLASSTYPE;
    case RSVP_CLASS_NOTIFY_REQUEST :
        return TT_UNKNOWN_CLASS;
    case RSVP_CLASS_ADMIN_STATUS :
        return TT_ADMIN_STATUS;
    case RSVP_CLASS_LSP_ATTRIBUTES :
    case RSVP_CLASS_LSP_REQUIRED_ATTRIBUTES :
        return TT_LSP_ATTRIBUTES;
    case RSVP_CLASS_ASSOCIATION :
        return TT_ASSOCIATION;
    case RSVP_CLASS_SESSION_ATTRIBUTE :
        return TT_SESSION_ATTRIBUTE;
    case RSVP_CLASS_GENERALIZED_UNI :
        return TT_GEN_UNI;
    case RSVP_CLASS_CALL_ID :
        return TT_CALL_ID;
    case RSVP_CLASS_DCLASS :
        return TT_DCLASS;
    case RSVP_CLASS_LSP_TUNNEL_IF_ID :
        return TT_LSP_TUNNEL_IF_ID;
    case RSVP_CLASS_VENDOR_PRIVATE_1:
    case RSVP_CLASS_VENDOR_PRIVATE_2:
    case RSVP_CLASS_VENDOR_PRIVATE_3:
    case RSVP_CLASS_VENDOR_PRIVATE_4:
    case RSVP_CLASS_VENDOR_PRIVATE_5:
    case RSVP_CLASS_VENDOR_PRIVATE_6:
    case RSVP_CLASS_VENDOR_PRIVATE_7:
    case RSVP_CLASS_VENDOR_PRIVATE_8:
    case RSVP_CLASS_VENDOR_PRIVATE_9:
    case RSVP_CLASS_VENDOR_PRIVATE_10:
    case RSVP_CLASS_VENDOR_PRIVATE_11:
    case RSVP_CLASS_VENDOR_PRIVATE_12:
        return TT_PRIVATE_CLASS;
    default:
        return TT_UNKNOWN_CLASS;
    }
}

static void
find_rsvp_session_tempfilt(tvbuff_t *tvb, int hdr_offset, int *session_offp, int *tempfilt_offp)
{
    int   s_off = 0, t_off = 0;
    int   len, off;
    guint obj_length;

    if (!tvb_bytes_exist(tvb, hdr_offset+6, 2))
        goto done;

    len = tvb_get_ntohs(tvb, hdr_offset+6) + hdr_offset;
    off = hdr_offset + 8;
    for (off = hdr_offset + 8; (off < len) && tvb_bytes_exist(tvb, off, 3); off += obj_length) {
        obj_length = tvb_get_ntohs(tvb, off);
        if (obj_length == 0)
            break;
        switch(tvb_get_guint8(tvb, off+2)) {
        case RSVP_CLASS_SESSION:
            s_off = off;
            break;
        case RSVP_CLASS_SENDER_TEMPLATE:
        case RSVP_CLASS_FILTER_SPEC:
            t_off = off;
            break;
        default:
            break;
        }
    }

 done:
    if (session_offp)  *session_offp  = s_off;
    if (tempfilt_offp) *tempfilt_offp = t_off;
}

static char *
summary_session(tvbuff_t *tvb, int offset)
{
    switch(tvb_get_guint8(tvb, offset+3)) {
    case RSVP_SESSION_TYPE_IPV4:
        return ep_strdup_printf("SESSION: IPv4, Destination %s, Protocol %d, Port %d. ",
                                tvb_ip_to_str(tvb, offset+4),
                                tvb_get_guint8(tvb, offset+8),
                                tvb_get_ntohs(tvb, offset+10));
        break;
    case RSVP_SESSION_TYPE_IPV4_LSP:
        return ep_strdup_printf("SESSION: IPv4-LSP, Destination %s, Tunnel ID %d, Ext ID %0x. ",
                                tvb_ip_to_str(tvb, offset+4),
                                tvb_get_ntohs(tvb, offset+10),
                                tvb_get_ntohl(tvb, offset+12));
        break;
    case RSVP_SESSION_TYPE_AGGREGATE_IPV4:
        return ep_strdup_printf("SESSION: IPv4-Aggregate, Destination %s, DSCP %d. ",
                                tvb_ip_to_str(tvb, offset+4),
                                tvb_get_guint8(tvb, offset+11));
        break;
    case RSVP_SESSION_TYPE_IPV4_UNI:
        return ep_strdup_printf("SESSION: IPv4-UNI, Destination %s, Tunnel ID %d, Ext Address %s. ",
                                tvb_ip_to_str(tvb, offset+4),
                                tvb_get_ntohs(tvb, offset+10),
                                tvb_ip_to_str(tvb, offset+12));
        break;
    case RSVP_SESSION_TYPE_IPV4_E_NNI:
        return ep_strdup_printf("SESSION: IPv4-E-NNI, Destination %s, Tunnel ID %d, Ext Address %s. ",
                                tvb_ip_to_str(tvb, offset+4),
                                tvb_get_ntohs(tvb, offset+10),
                                tvb_ip_to_str(tvb, offset+12));
        break;
    default:
        return ep_strdup_printf("SESSION: Type %d. ", tvb_get_guint8(tvb, offset+3));
        break;
    }
    DISSECTOR_ASSERT_NOT_REACHED();
}

static char *
summary_template(tvbuff_t *tvb, int offset)
{
    const char *objtype;

    if (tvb_get_guint8(tvb, offset+2) == RSVP_CLASS_FILTER_SPEC)
        objtype = "FILTERSPEC";
    else
        objtype = "SENDER TEMPLATE";

    switch(tvb_get_guint8(tvb, offset+3)) {
    case 1:
        return ep_strdup_printf("%s: IPv4, Sender %s, Port %d. ", objtype,
                                tvb_ip_to_str(tvb, offset+4),
                                tvb_get_ntohs(tvb, offset+10));
        break;
    case 7:
        return ep_strdup_printf("%s: IPv4-LSP, Tunnel Source: %s, LSP ID: %d. ", objtype,
                                tvb_ip_to_str(tvb, offset+4),
                                tvb_get_ntohs(tvb, offset+10));
        break;
    case 9:
        return ep_strdup_printf("%s: IPv4-Aggregate, Aggregator %s. ", objtype,
                                tvb_ip_to_str(tvb, offset+4));
        break;
    default:
        return ep_strdup_printf("%s: Type %d. ", objtype, tvb_get_guint8(tvb, offset+3));
        break;
    }
    DISSECTOR_ASSERT_NOT_REACHED();
}

/*------------------------------------------------------------------------------
 * SESSION
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_session(proto_item *ti, proto_tree *rsvp_object_tree,
                     tvbuff_t *tvb,
                     int offset, int obj_length,
                     int rsvp_class _U_, int type,
                     rsvp_conversation_info *rsvph)
{
    proto_item *hidden_item;
    int         offset2 = offset + 4;

    proto_item_set_text(ti, "%s", summary_session(tvb, offset));

    switch(type) {
    case RSVP_SESSION_TYPE_IPV4:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1 - IPv4");
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_IP],
                            tvb, offset2, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_PROTO], tvb,
                            offset2+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+5, 1,
                            "Flags: %x",
                            tvb_get_guint8(tvb, offset2+5));
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_PORT], tvb,
                            offset2+6, 2, ENC_BIG_ENDIAN);

        /*
         * Save this information to build the conversation request key
         * later.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_IPV4;
        SET_ADDRESS(&rsvph->destination, AT_IPv4, 4,
                    tvb_get_ptr(tvb, offset2, 4));
        rsvph->protocol = tvb_get_guint8(tvb, offset2+4);
        rsvph->udp_dest_port = tvb_get_ntohs(tvb, offset2+6);

        break;

    case RSVP_SESSION_TYPE_IPV6:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 2 - IPv6");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 16,
                            "Destination address: %s",
                            tvb_ip6_to_str(tvb, offset2));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+16, 1,
                            "Protocol: %u",
                            tvb_get_guint8(tvb, offset2+16));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+17, 1,
                            "Flags: %x",
                            tvb_get_guint8(tvb, offset2+17));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+18, 2,
                            "Destination port: %u",
                            tvb_get_ntohs(tvb, offset2+18));
        /*
         * Save this information to build the conversation request key
         * later. IPv6 conversatiuon support is not implemented yet, so only
         * the session type is stored.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_IPV6;

        break;

    case RSVP_SESSION_TYPE_IPV4_LSP:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 7 - IPv4 LSP");
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_IP],
                            tvb, offset2, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_TUNNEL_ID],
                            tvb, offset2+6, 2, ENC_BIG_ENDIAN);

        proto_tree_add_text(rsvp_object_tree, tvb, offset2+8, 4,
                            "Extended Tunnel ID: %u (%s)",
                            tvb_get_ntohl(tvb, offset2+8),
                            tvb_ip_to_str(tvb, offset2+8));
        hidden_item = proto_tree_add_item(rsvp_object_tree,
                                   hf_rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID],
                                   tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        /*
         * Save this information to build the conversation request key
         * later.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_IPV4_LSP;
        SET_ADDRESS(&rsvph->destination, AT_IPv4, 4,
                    tvb_get_ptr(tvb, offset2, 4));
        rsvph->udp_dest_port = tvb_get_ntohs(tvb, offset2+6);
        rsvph->ext_tunnel_id = tvb_get_ntohl(tvb, offset2 + 8);
        break;

    case RSVP_SESSION_TYPE_AGGREGATE_IPV4:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 9 - IPv4 Aggregate");
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_IP],
                            tvb, offset2, 4, ENC_BIG_ENDIAN);

        proto_tree_add_text(rsvp_object_tree, tvb, offset2+7, 1,
                            "DSCP: %u (%s)",
                            tvb_get_guint8(tvb, offset2+7),
                            val_to_str_ext(tvb_get_guint8(tvb, offset2+7),
                                       &dscp_vals_ext, "Unknown (%d)"));
        /*
         * Save this information to build the conversation request key
         * later.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_AGGREGATE_IPV4;
        SET_ADDRESS(&rsvph->destination, AT_IPv4, 4,
                    tvb_get_ptr(tvb, offset2, 4));
        rsvph->dscp = tvb_get_guint8(tvb, offset2+7);
        rsvph->ext_tunnel_id = tvb_get_ntohl(tvb, offset2 + 8);
        break;

    case RSVP_SESSION_TYPE_IPV4_UNI:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 11 - IPv4 UNI");
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_IP],
                            tvb, offset2, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_TUNNEL_ID],
                            tvb, offset2+6, 2, ENC_BIG_ENDIAN);

        proto_tree_add_text(rsvp_object_tree, tvb, offset2+8, 4,
                            "Extended IPv4 Address: %s",
                            tvb_ip_to_str(tvb, offset2+8));
        hidden_item = proto_tree_add_item(rsvp_object_tree,
                                   hf_rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID],
                                   tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        /*
         * Save this information to build the conversation request key
         * later.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_IPV4_UNI;
        SET_ADDRESS(&rsvph->destination, AT_IPv4, 4,
                    tvb_get_ptr(tvb, offset2, 4));
        rsvph->udp_dest_port = tvb_get_ntohs(tvb, offset2+6);
        rsvph->ext_tunnel_id = tvb_get_ntohl(tvb, offset2 + 8);

        break;

    case RSVP_SESSION_TYPE_IPV4_E_NNI:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 15 - IPv4 E-NNI");
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_IP],
                            tvb, offset2, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_TUNNEL_ID],
                            tvb, offset2+6, 2, ENC_BIG_ENDIAN);

        proto_tree_add_text(rsvp_object_tree, tvb, offset2+8, 4,
                            "Extended IPv4 Address: %s",
                            tvb_ip_to_str(tvb, offset2+8));
        hidden_item = proto_tree_add_item(rsvp_object_tree,
                                   hf_rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID],
                                   tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        /*
         * Save this information to build the conversation request key
         * later.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_IPV4_E_NNI;
        SET_ADDRESS(&rsvph->destination, AT_IPv4, 4,
                    tvb_get_ptr(tvb, offset2, 4));
        rsvph->udp_dest_port = tvb_get_ntohs(tvb, offset2+6);
        rsvph->ext_tunnel_id = tvb_get_ntohl(tvb, offset2 + 8);

        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length-4,
                            "Data (%d bytes)", obj_length-4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * TLVs for HOP, ERROR and other IF_ID extended objects (RFC4920)
 * (TODO: TLV type 12, 13, 25)
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_ifid_tlv(proto_tree *ti, proto_tree *rsvp_object_tree,
                      tvbuff_t *tvb, int offset, int length,
                      int subtree_type)
{
    int         tlv_off, padding;
    guint16     tlv_type;
    int         tlv_len;
    guint8      isis_len;
    const char *tlv_name;
    proto_tree *rsvp_ifid_subtree=NULL, *ti2;

    for (tlv_off = 0; tlv_off < length; ) {
        tlv_type = tvb_get_ntohs(tvb, offset+tlv_off);
        tlv_len = tvb_get_ntohs(tvb, offset+tlv_off+2);

        if ((tlv_len == 0) || (tlv_off+tlv_len > length)) {
            proto_tree_add_text(rsvp_object_tree, tvb, offset+tlv_off+2, 2,
                                "Invalid TLV length");
            return;
        }
        switch(tlv_type) {
        case 1:                         /* IPv4 */
            tlv_name = "";
            goto ifid_ipv4;
        case 14:                        /* PREVIOUS_HOP_IPV4 */
            tlv_name = "Previous-Hop ";
            goto ifid_ipv4;
        case 16:                        /* INCOMING_IPV4 */
            tlv_name = "Incoming ";
        ifid_ipv4:
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      "%sIPv4 TLV - %s", tlv_name,
                                      tvb_ip_to_str(tvb, offset+tlv_off+4));

            rsvp_ifid_subtree = proto_item_add_subtree(ti2, subtree_type);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off, 2,
                                "Type: %d (%sIPv4)", tlv_type, tlv_name);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+2, 2,
                                "Length: %u",
                                tvb_get_ntohs(tvb, offset+tlv_off+2));
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+4, 4,
                                "IPv4 address: %s",
                                tvb_ip_to_str(tvb, offset+tlv_off+4));
            proto_item_append_text(ti, "%sIPv4: %s. ", tlv_name,
                                   tvb_ip_to_str(tvb, offset+tlv_off+4));
            break;

        case 2:                         /* IPv6 */
            tlv_name = "";
            goto ifid_ipv6;
        case 15:                        /* PREVIOUS_HOP_IPV6 */
            tlv_name = "Previous-Hop ";
            goto ifid_ipv6;
        case 17:                        /* INCOMING_IPV6 */
            tlv_name = "Incoming ";
        ifid_ipv6:
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      "%sIPv6 TLV - %s", tlv_name,
                                      tvb_ip6_to_str(tvb, offset+tlv_off+4));

            rsvp_ifid_subtree = proto_item_add_subtree(ti2, subtree_type);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off, 2,
                                "Type: %d (%sIPv6)", tlv_type, tlv_name);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+2, 2,
                                "Length: %u",
                                tvb_get_ntohs(tvb, offset+tlv_off+2));
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+4, 4,
                                "IPv6 address: %s",
                                tvb_ip6_to_str(tvb, offset+tlv_off+4));
            proto_item_append_text(ti, "%sIPv6: %s. ", tlv_name,
                                   tvb_ip6_to_str(tvb, offset+tlv_off+4));
            break;

        case 3:                         /* IF_INDEX */
            tlv_name = "";
            goto ifid_ifindex;
        case 4:                         /* COMPONENT_IF_DOWNSTREAM */
            tlv_name = " Forward";
            goto ifid_ifindex;
        case 5:                         /* COMPONENT_IF_UPSTREAM */
            tlv_name = " Reverse";
            goto ifid_ifindex;
        case 18:                        /* INCOMING_IF_INDEX */
            tlv_name = " Incoming";
        ifid_ifindex:
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      "Interface-Index%s TLV - %s, %d",
                                      tlv_name,
                                      tvb_ip_to_str(tvb, offset+tlv_off+4),
                                      tvb_get_ntohl(tvb, offset+tlv_off+8));
            rsvp_ifid_subtree = proto_item_add_subtree(ti2, subtree_type);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off, 2,
                                "Type: %d (Interface Index%s)", tlv_type, tlv_name);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+2, 2,
                                "Length: %u",
                                tvb_get_ntohs(tvb, offset+tlv_off+2));
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+4, 4,
                                "IPv4 address: %s",
                                tvb_ip_to_str(tvb, offset+tlv_off+4));
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+8, 4,
                                "Interface-ID: %d (0x%0x)",
                                tvb_get_ntohl(tvb, offset+tlv_off+8),
                                tvb_get_ntohl(tvb, offset+tlv_off+8));
            proto_item_append_text(ti, "Data If-Index%s: %s, %d. ", tlv_name,
                                   tvb_ip_to_str(tvb, offset+tlv_off+4),
                                   tvb_get_ntohl(tvb, offset+tlv_off+8));
            break;

        case 6:                         /* DOWNSTREAM_LABEL */
            tlv_name = "Downstream";
            goto ifid_label;
        case 7:                         /* UPSTREAM_LABEL */
            tlv_name = "Upstream";
            goto ifid_label;
        case 19:                        /* INCOMING_DOWN_LABEL */
            tlv_name = "Incoming-Downstream";
            goto ifid_label;
        case 20:                        /* INCOMING_UP_LABEL */
            tlv_name = "Incoming-Upstream";
        ifid_label:
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      "%s-Label TLV - %u", tlv_name,
                                      tvb_get_ntohl(tvb, offset+tlv_off+4));
            rsvp_ifid_subtree = proto_item_add_subtree(ti2, subtree_type);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off, 2,
                                "Type: %d (%s-Label)", tlv_type, tlv_name);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+2, 2,
                                "Length: %u",
                                tvb_get_ntohs(tvb, offset+tlv_off+2));
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+4, 4,
                                "Label: %u",
                                tvb_get_ntohl(tvb, offset+tlv_off+4));
            proto_item_append_text(ti, "%s-Label: %u. ", tlv_name,
                                   tvb_get_ntohl(tvb, offset+tlv_off+4));
            break;


        case 8:                         /* NODE_ID */
            tlv_name = "";
            goto ifid_nodeid;
        case 21:                        /* REPORTING_NODE_ID */
            tlv_name = "Reporting-";
        ifid_nodeid:
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      "%sNode-ID TLV - %s", tlv_name,
                                      tvb_ip_to_str(tvb, offset+tlv_off+4));
            rsvp_ifid_subtree = proto_item_add_subtree(ti2, subtree_type);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off, 2,
                                "Type: %d (%sNode-ID)", tlv_type, tlv_name);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+2, 2,
                                "Length: %u",
                                tvb_get_ntohs(tvb, offset+tlv_off+2));
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+4, 4,
                                "Node ID: %s",
                                tvb_ip_to_str(tvb, offset+tlv_off+4));
            proto_item_append_text(ti, "%sNode-ID: %s. ", tlv_name,
                                   tvb_ip_to_str(tvb, offset+tlv_off+4));
            break;

        case 9:                         /* OSPF_AREA */
            tlv_name = "";
            goto ifid_ospf;
        case 22:                        /* REPORTING_OSPF_AREA */
            tlv_name = "Reporting-";
        ifid_ospf:
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      "%sOSPF-Area TLV - %u", tlv_name,
                                      tvb_get_ntohl(tvb, offset+tlv_off+4));
            rsvp_ifid_subtree = proto_item_add_subtree(ti2, subtree_type);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off, 2,
                                "Type: %d (%sOSPF-Area)", tlv_type, tlv_name);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+2, 2,
                                "Length: %u",
                                tvb_get_ntohs(tvb, offset+tlv_off+2));
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+4, 4,
                                "Area: %u",
                                tvb_get_ntohl(tvb, offset+tlv_off+4));
            proto_item_append_text(ti, "%sOSPF-Area: %u. ", tlv_name,
                                   tvb_get_ntohl(tvb, offset+tlv_off+4));
            break;

        case 10:                        /* ISIS_AREA */
            tlv_name = "";
            goto ifid_isis;
        case 23:                        /* REPORTING_ISIS_AREA */
            tlv_name = "Reporting-";
        ifid_isis:
            isis_len = tvb_get_guint8(tvb, offset+tlv_off+4);
            if ((isis_len < 2) || (isis_len > 11))
            {
              proto_tree_add_text(rsvp_object_tree, tvb, offset+tlv_off, tlv_len,
                                  "%sISIS-Area TLV - Invalid Length field", tlv_name);
              break;
            }
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      "%sISIS-Area TLV - %s", tlv_name,
                                      print_nsap_net(tvb_get_ptr(tvb, offset+tlv_off+5, isis_len),
                                                     isis_len));
            rsvp_ifid_subtree = proto_item_add_subtree(ti2, subtree_type);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off, 2,
                                "Type: %d (%sISIS-Area)", tlv_type, tlv_name);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+2, 2,
                                "Length: %u",
                                tvb_get_ntohs(tvb, offset+tlv_off+2));
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+4, 4,
                                "IS-IS Area Identifier: %s",
                                 print_nsap_net(tvb_get_ptr(tvb, offset+tlv_off+5, isis_len), isis_len));
            proto_item_append_text(ti, "%sISIS-Area: %s. ", tlv_name,
                                   print_nsap_net(tvb_get_ptr(tvb, offset+tlv_off+5, isis_len), isis_len));
            break;

        case 11:                        /* AUTONOMOUS_SYSTEM */
            tlv_name = "";
            goto ifid_as;
        case 24:                        /* REPORTING_AUTONOMOUS_SYSTEM */
            tlv_name = "Reporting-";
        ifid_as:
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      "%sAS TLV - %u", tlv_name,
                                      tvb_get_ntohl(tvb, offset+tlv_off+4));
            rsvp_ifid_subtree = proto_item_add_subtree(ti2, subtree_type);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off, 2,
                                "Type: %d (%sAS)", tlv_type, tlv_name);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+2, 2,
                                "Length: %u",
                                tvb_get_ntohs(tvb, offset+tlv_off+2));
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+4, 4,
                                "Autonomous System: %u",
                                tvb_get_ntohl(tvb, offset+tlv_off+4));
            proto_item_append_text(ti, "%sAS: %u. ", tlv_name,
                                   tvb_get_ntohl(tvb, offset+tlv_off+4));
            break;

        case 26:                        /* NODE_EXCLUSIONS */
            tlv_name = "Node";
            goto ifid_ex;
        case 27:                        /* LINK_EXCLUSIONS */
            tlv_name = "Link";
        ifid_ex:
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      "%s-Exclusions TLV - ", tlv_name);
            rsvp_ifid_subtree = proto_item_add_subtree(ti2, subtree_type);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off, 2,
                                "Type: %d (%s-Exclusions)", tlv_type, tlv_name);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset+tlv_off+2, 2,
                                "Length: %u",
                                tvb_get_ntohs(tvb, offset+tlv_off+2));
            dissect_rsvp_ifid_tlv(ti2, rsvp_ifid_subtree, tvb, offset+tlv_off+4,
                                  tlv_len-4, TREE(TT_HOP_SUBOBJ));
            break;
        case 516:
            /* FF: ERROR_STRING TLV, RFC 4783 */
            ti2 =
              proto_tree_add_text(rsvp_object_tree,
                                  tvb, offset + tlv_off,
                                  tlv_len,
                                  "ERROR_STRING TLV - %s",
                                  tvb_format_text(tvb, offset + tlv_off + 4,
                                                  tlv_len - 4));
            rsvp_ifid_subtree = proto_item_add_subtree(ti2, subtree_type);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset + tlv_off, 2,
                                "Type: 516 (ERROR_STRING)");
            proto_tree_add_text(rsvp_ifid_subtree,
                                tvb, offset + tlv_off + 2, 2,
                                "Length: %u",
                                tvb_get_ntohs(tvb, offset + tlv_off + 2));
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset + tlv_off + 4,
                                tlv_len - 4,
                                "Error String: %s",
                                tvb_format_text(tvb, offset + tlv_off + 4,
                                                tlv_len - 4));
            break;

        default:
            /* FF: not yet known TLVs are displayed as raw data */
            ti2 = proto_tree_add_text(rsvp_object_tree,
                                      tvb, offset + tlv_off,
                                      tlv_len,
                                      "Unknown TLV (%u)", tlv_type);
            rsvp_ifid_subtree = proto_item_add_subtree(ti2, subtree_type);
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset + tlv_off, 2,
                                "Type: %u (Unknown)", tlv_type);
            proto_tree_add_text(rsvp_ifid_subtree,
                                tvb, offset + tlv_off + 2, 2,
                                "Length: %u",
                                tvb_get_ntohs(tvb, offset + tlv_off + 2));
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset + tlv_off + 4,
                                tlv_len - 4,
                                "Data: %s",
                                tvb_bytes_to_str_punct(tvb, offset + tlv_off + 4, tlv_len - 4, ' '));
            break;
        }

        padding = (4 - (tlv_len % 4)) % 4;
        if (padding != 0)
            proto_tree_add_text(rsvp_ifid_subtree, tvb, offset + tlv_off + tlv_len, padding, "Padding: %s",
                                tvb_bytes_to_str_punct(tvb, offset + tlv_off + tlv_len, padding, ' '));
        tlv_off += tlv_len + padding;
    }
}

/*------------------------------------------------------------------------------
 * HOP
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_hop(proto_item *ti, proto_tree *rsvp_object_tree,
                 tvbuff_t *tvb,
                 int offset, int obj_length,
                 int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;

    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1 - IPv4");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4,
                            "Neighbor address: %s",
                            tvb_ip_to_str(tvb, offset2));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 4,
                            "Logical interface: %u",
                            tvb_get_ntohl(tvb, offset2+4));
        proto_item_set_text(ti, "HOP: IPv4, %s",
                            tvb_ip_to_str(tvb, offset2));
        break;

    case 2:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 2 - IPv6");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 16,
                            "Neighbor address: %s",
                            tvb_ip6_to_str(tvb, offset2));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+16, 4,
                            "Logical interface: 0x%08x",
                            tvb_get_ntohl(tvb, offset2+16));
        break;

    case 3:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 3 - IPv4 IF-ID");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4,
                            "Neighbor address: %s",
                            tvb_ip_to_str(tvb, offset2));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 4,
                            "Logical interface: %u",
                            tvb_get_ntohl(tvb, offset2+4));

        proto_item_set_text(ti, "HOP: IPv4 IF-ID. Control IPv4: %s. ",
                            tvb_ip_to_str(tvb, offset2));

        dissect_rsvp_ifid_tlv(ti, rsvp_object_tree, tvb, offset+12, obj_length-12,
                              TREE(TT_HOP_SUBOBJ));

        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * TIME VALUES
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_time_values(proto_item *ti, proto_tree *rsvp_object_tree,
                         tvbuff_t *tvb,
                         int offset, int obj_length,
                         int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;

    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4,
                            "Refresh interval: %u ms (%u seconds)",
                            tvb_get_ntohl(tvb, offset2),
                            tvb_get_ntohl(tvb, offset2)/1000);
        proto_item_set_text(ti, "TIME VALUES: %d ms",
                            tvb_get_ntohl(tvb, offset2));
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * Error value field in ERROR object
 *------------------------------------------------------------------------------*/
static guint16
dissect_rsvp_error_value(proto_tree *ti, tvbuff_t *tvb,
                         int offset, guint8 error_code)
{
    guint16           error_val;
    guint8            error_class, error_ctype;
    value_string_ext *rsvp_error_vals_ext_p = NULL;

    error_val = tvb_get_ntohs(tvb, offset);
    switch (error_code) {
    case RSVP_ERROR_ADMISSION:
        rsvp_error_vals_ext_p = &rsvp_admission_control_error_vals_ext;
        break;
    case RSVP_ERROR_POLICY:
        rsvp_error_vals_ext_p = &rsvp_policy_control_error_vals_ext;
        break;
    case RSVP_ERROR_TRAFFIC:
        rsvp_error_vals_ext_p = &rsvp_traffic_control_error_vals_ext;
        break;
    case RSVP_ERROR_ROUTING:
        rsvp_error_vals_ext_p = &rsvp_routing_error_vals_ext;
        break;
    case RSVP_ERROR_NOTIFY:
        rsvp_error_vals_ext_p = &rsvp_notify_error_vals_ext;
        break;
    case RSVP_ERROR_DIFFSERV:
        rsvp_error_vals_ext_p = &rsvp_diffserv_error_vals_ext;
        break;
    case RSVP_ERROR_DSTE:
        rsvp_error_vals_ext_p = &rsvp_diffserv_aware_te_error_vals_ext;
        break;
    case RSVP_ERROR_CALL_MGMT:
        rsvp_error_vals_ext_p = &rsvp_call_mgmt_error_vals_ext;
        break;
    }

    switch (error_code) {
    case RSVP_ERROR_ADMISSION:
    case RSVP_ERROR_TRAFFIC:
        if ((error_val & 0xc0) == 0) {
            DISSECTOR_ASSERT(rsvp_error_vals_ext_p != NULL);
            proto_tree_add_text(ti, tvb, offset, 2,
                "Error value: %u - %s", error_val,
                                val_to_str_ext(error_val, rsvp_error_vals_ext_p, "Unknown (%d)"));
        }
        else if ((error_val & 0xc0) == 0x80) {
            proto_tree_add_text(ti, tvb, offset, 2,
                "Error value: %u - Organization specific subcode (%u)", error_val,
                error_val);
        }
        else if ((error_val & 0xc0) == 0xc0) {
            proto_tree_add_text(ti, tvb, offset, 2,
                "Error value: %u - Service specific subcode (%u)", error_val,
                error_val);
        }
        break;
    case RSVP_ERROR_UNKNOWN_CLASS:
    case RSVP_ERROR_UNKNOWN_C_TYPE:
        error_class = error_val / 256;
        error_ctype = error_val % 256;
        proto_tree_add_text(ti, tvb, offset, 2, "Class: %u (%s) - CType: %u",
                            error_class, val_to_str_ext_const(error_class, &rsvp_class_vals_ext, "Unknown"),
                            error_ctype);
        break;
    case RSVP_ERROR_POLICY:
    case RSVP_ERROR_NOTIFY:
    case RSVP_ERROR_ROUTING:
    case RSVP_ERROR_DIFFSERV:
    case RSVP_ERROR_DSTE:
    case RSVP_ERROR_CALL_MGMT:
        DISSECTOR_ASSERT(rsvp_error_vals_ext_p != NULL);
        proto_tree_add_text(ti, tvb, offset, 2, "Error value: %u - %s", error_val,
                            val_to_str_ext(error_val, rsvp_error_vals_ext_p, "Unknown (%d)"));
        break;
    default:
        proto_tree_add_text(ti, tvb, offset, 2, "Error value: %u", error_val);
        break;
    }
    return error_val;
}

/*------------------------------------------------------------------------------
 * ERROR
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_error(proto_item *ti, proto_tree *rsvp_object_tree,
                   tvbuff_t *tvb,
                   int offset, int obj_length,
                   int rsvp_class _U_, int type)
{
    int         offset2 = offset + 4;
    int         offset3;
    guint8      error_flags;
    guint8      error_code;
    guint16     error_val;
    proto_tree *ti2, *rsvp_error_subtree;

    switch(type) {
    case 1: {
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1 - IPv4");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4,
                            "Error node: %s",
                            tvb_ip_to_str(tvb, offset2));
        offset3 = offset2+4;
        break;
    }

    case 2: {
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 2 - IPv6");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 16,
                            "Error node: %s",
                            tvb_ip6_to_str(tvb, offset2));
        offset3 = offset2+16;
        break;
    }

    case 3: {
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 3 - IPv4 IF-ID");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4,
                            "Error node: %s",
                            tvb_ip_to_str(tvb, offset2));
        offset3 = offset2+4;
        break;
    }

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        return;
    }

    error_flags = tvb_get_guint8(tvb, offset3);
    ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_error_flags,
                             tvb, offset3, 1, ENC_BIG_ENDIAN);
    rsvp_error_subtree = proto_item_add_subtree(ti2, TREE(TT_ERROR_FLAGS));
    proto_tree_add_item(rsvp_error_subtree, hf_rsvp_error_flags_path_state_removed,
                             tvb, offset3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(rsvp_error_subtree, hf_rsvp_error_flags_not_guilty,
                             tvb, offset3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(rsvp_error_subtree, hf_rsvp_error_flags_in_place,
                             tvb, offset3, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(ti2, " %s %s %s",
                           (error_flags & (1<<2))  ? "Path-State-Removed" : "",
                           (error_flags & (1<<1))  ? "NotGuilty" : "",
                           (error_flags & (1<<0))  ? "InPlace" : "");
    error_code = tvb_get_guint8(tvb, offset3+1);
    proto_tree_add_text(rsvp_object_tree, tvb, offset3+1, 1,
                        "Error code: %u - %s", error_code,
                        val_to_str_ext(error_code, &rsvp_error_codes_ext, "Unknown (%d)"));
    error_val = dissect_rsvp_error_value(rsvp_object_tree, tvb, offset3+2, error_code);

    switch (type) {
    case 1:
        proto_item_set_text(ti, "ERROR: IPv4, Error code: %s, Value: %d, Error Node: %s",
                            val_to_str_ext(error_code, &rsvp_error_codes_ext, "Unknown (%d)"),
                            error_val, tvb_ip_to_str(tvb, offset2));
        break;
    case 3:
        proto_item_set_text(ti, "ERROR: IPv4 IF-ID, Error code: %s, Value: %d, Control Node: %s. ",
                            val_to_str_ext(error_code, &rsvp_error_codes_ext, "Unknown (%d)"),
                            error_val, tvb_ip_to_str(tvb, offset2));
        dissect_rsvp_ifid_tlv(ti, rsvp_object_tree, tvb, offset+12, obj_length-12,
                              TREE(TT_ERROR_SUBOBJ));
        break;
    }
}

/*------------------------------------------------------------------------------
 * SCOPE
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_scope(proto_item *ti _U_, proto_tree *rsvp_object_tree,
                   tvbuff_t *tvb,
                   int offset, int obj_length,
                   int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    int mylen;

    mylen = obj_length - 4;
    switch(type) {
    case 1: {
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1 - IPv4");
        while (mylen > 0) {
            proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4,
                                "IPv4 Address: %s",
                                tvb_ip_to_str(tvb, offset2));
            offset2 += 4;
            mylen -= 4;
        }
        break;
    }

    case 2: {
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 2 - IPv6");
        while (mylen > 0) {
            proto_tree_add_text(rsvp_object_tree, tvb, offset2, 16,
                                "IPv6 Address: %s",
                                tvb_ip6_to_str(tvb, offset2));
            offset2 += 16;
            mylen -= 16;
        }
        break;
    }

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
                            "Data (%d bytes)", mylen);
        break;
    }
}

/*------------------------------------------------------------------------------
 * STYLE
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_style(proto_item *ti, proto_tree *rsvp_object_tree,
                   tvbuff_t *tvb,
                   int offset, int obj_length,
                   int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;

    switch(type) {
    case 1: {
        guint32 style;

        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
                            "Flags: 0x%02x",
                            tvb_get_guint8(tvb, offset2));
        style = tvb_get_ntoh24(tvb, offset2+1);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+1,
                            3, "Style: 0x%06X - %s", style,
                            val_to_str_const(style, style_vals, "Unknown"));
        proto_item_set_text(ti, "STYLE: %s (%d)",
                            val_to_str_const(style, style_vals, "Unknown"),
                            style);
        break;
    }

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * CONFIRM
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_confirm(proto_item *ti, proto_tree *rsvp_object_tree,
                     tvbuff_t *tvb,
                     int offset, int obj_length,
                     int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;

    switch(type) {
    case 1: {
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1 - IPv4");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4,
                            "Receiver address: %s",
                            tvb_ip_to_str(tvb, offset2));
        proto_item_set_text(ti, "CONFIRM: Receiver %s",
                            tvb_ip_to_str(tvb, offset2));
        break;
    }

    case 2: {
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 2 - IPv6");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 16,
                            "Receiver address: %s",
                            tvb_ip6_to_str(tvb, offset2));
        break;
    }

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * SENDER TEMPLATE and FILTERSPEC
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_template_filter(proto_item *ti, proto_tree *rsvp_object_tree,
                             tvbuff_t *tvb,
                             int offset, int obj_length,
                             int rsvp_class _U_, int type,
                             rsvp_conversation_info *rsvph)
{
    int offset2 = offset + 4;

    proto_item_set_text(ti, "%s", summary_template(tvb, offset));
    switch(type) {
    case 1:
         proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                             "C-type: 1 - IPv4");
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_IP],
                             tvb, offset2, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_PORT],
                             tvb, offset2+6, 2, ENC_BIG_ENDIAN);

         /*
          * Save this information to build the conversation request key later.
          */
         SET_ADDRESS(&rsvph->source, AT_IPv4, 4, tvb_get_ptr(tvb, offset2, 4));
         rsvph->udp_source_port = tvb_get_ntohs(tvb, offset2+6);
         break;

     case 2:
         proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                             "C-type: 2 - IPv6");
         proto_tree_add_text(rsvp_object_tree, tvb, offset2, 16,
                             "Source address: %s",
                             tvb_ip6_to_str(tvb, offset2));
         proto_tree_add_text(rsvp_object_tree, tvb, offset2+18, 2,
                             "Source port: %u",
                             tvb_get_ntohs(tvb, offset2+18));
         break;

     case 7:
         proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                             "C-type: 7 - IPv4 LSP");
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_IP],
                             tvb, offset2, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_LSP_ID],
                             tvb, offset2+6, 2, ENC_BIG_ENDIAN);

         /*
          * Save this information to build the conversation request key later.
          */
         SET_ADDRESS(&rsvph->source, AT_IPv4, 4, tvb_get_ptr(tvb, offset2, 4));
         rsvph->udp_source_port = tvb_get_ntohs(tvb, offset2+6);
         break;

    case 9:
         proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                             "C-type: 9 - IPv4 Aggregate");
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_IP],
                             tvb, offset2, 4, ENC_BIG_ENDIAN);

         /*
          * Save this information to build the conversation request key later.
          */
         SET_ADDRESS(&rsvph->source, AT_IPv4, 4, tvb_get_ptr(tvb, offset2, 4));
         break;

     default:
         proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                             "C-type: Unknown (%u)",
                             type);
         proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                             "Data (%d bytes)", obj_length - 4);
         break;
 }
}

/*------------------------------------------------------------------------------
 * TLVs for Ethernet SENDER TSPEC and FLOWSPEC (RFC6003)
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_eth_tspec_tlv(proto_item *ti, proto_tree *rsvp_object_tree,
                           tvbuff_t *tvb, int offset, int tlv_length,
                           int subtree_type)
{
    int         tlv_off;
    guint16     tlv_type;
    int         tlv_len;
    guint8      profile;
    proto_tree *rsvp_ethspec_subtree, *ethspec_profile_subtree, *ti2, *ti3;

    for (tlv_off = 0; tlv_off < tlv_length; ) {
        tlv_type = tvb_get_ntohs(tvb, offset+tlv_off);
        tlv_len = tvb_get_ntohs(tvb, offset+tlv_off+2);

        if ((tlv_len == 0) || (tlv_off+tlv_len > tlv_length)) {
            proto_tree_add_text(rsvp_object_tree, tvb, offset+tlv_off+2, 2,
                                "Invalid length");
            return;
        }
        switch(tlv_type) {
        case 0:
        case 1:
        case 255:
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      "RESERVED (RFC6003)");
            rsvp_ethspec_subtree = proto_item_add_subtree(ti2, subtree_type);
            proto_tree_add_text(rsvp_ethspec_subtree, tvb, offset+tlv_off, 2,
                                "Type: %u (RESERVED)", tlv_type);
            proto_tree_add_text(rsvp_ethspec_subtree, tvb, offset+tlv_off+2, 2,
                                "Length: %u", tlv_len);
            break;

        case 2:
        case 129:     /* OIF demo 2009 */
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      "Ethernet Bandwidth Profile TLV: CIR=%.10g, CBS=%.10g, "
                                      "EIR=%.10g, EBS=%.10g",
                                      tvb_get_ntohieee_float(tvb, offset+tlv_off+8),
                                      tvb_get_ntohieee_float(tvb, offset+tlv_off+12),
                                      tvb_get_ntohieee_float(tvb, offset+tlv_off+16),
                                      tvb_get_ntohieee_float(tvb, offset+tlv_off+20));
            rsvp_ethspec_subtree = proto_item_add_subtree(ti2, subtree_type);
            proto_tree_add_text(rsvp_ethspec_subtree, tvb, offset+tlv_off, 2,
                                "Type: %u - Ethernet Bandwidth Profile", tlv_type);
            proto_tree_add_text(rsvp_ethspec_subtree, tvb, offset+tlv_off+2, 2,
                                "Length: %u", tlv_len);
            profile = tvb_get_guint8(tvb, offset+tlv_off+4);
            ti3 = proto_tree_add_text(rsvp_ethspec_subtree, tvb, offset+tlv_off+4, 1,
                                      "Profile: 0x%02x", profile);
            ethspec_profile_subtree = proto_item_add_subtree(ti3, TREE(TT_ETHSPEC_SUBTREE));
            proto_tree_add_item(ethspec_profile_subtree, hf_rsvp_eth_tspec_tlv_color_mode,
                             tvb, offset+tlv_off+4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ethspec_profile_subtree, hf_rsvp_eth_tspec_tlv_coupling_flag,
                             tvb, offset+tlv_off+4, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(ti3, " %s %s",
                                   (profile & (1<<1))  ? "CM" : "",
                                   (profile & (1<<0))  ? "CF" : "");
            proto_tree_add_text(rsvp_ethspec_subtree, tvb, offset+tlv_off+5, 1,
                                "Index: %x", tvb_get_guint8(tvb, offset+tlv_off+5));
            proto_tree_add_text(rsvp_ethspec_subtree, tvb, offset+tlv_off+6, 2,
                                "Reserved: %x", tvb_get_ntohs(tvb, offset+tlv_off+6));
            proto_tree_add_text(rsvp_ethspec_subtree, tvb, offset+tlv_off+8, 4, "CIR: %.10g",
                                tvb_get_ntohieee_float(tvb, offset+tlv_off+8));
            proto_tree_add_text(rsvp_ethspec_subtree, tvb, offset+tlv_off+12, 4, "CBS: %.10g",
                                tvb_get_ntohieee_float(tvb, offset+tlv_off+12));
            proto_tree_add_text(rsvp_ethspec_subtree, tvb, offset+tlv_off+16, 4, "EIR: %.10g",
                                tvb_get_ntohieee_float(tvb, offset+tlv_off+16));
            proto_tree_add_text(rsvp_ethspec_subtree, tvb, offset+tlv_off+20, 4, "EBS: %.10g",
                                tvb_get_ntohieee_float(tvb, offset+tlv_off+20));

            proto_item_append_text(ti, "ETH profile: CIR=%.10g, CBS=%.10g, EIR=%.10g, "
                                       "EBS=%.10g",
                                   tvb_get_ntohieee_float(tvb, offset+tlv_off+8),
                                   tvb_get_ntohieee_float(tvb, offset+tlv_off+12),
                                   tvb_get_ntohieee_float(tvb, offset+tlv_off+16),
                                   tvb_get_ntohieee_float(tvb, offset+tlv_off+20));
            break;

        default:
            proto_tree_add_text(rsvp_object_tree, tvb, offset+tlv_off, 2,
                                "Unknown TLV: %u", tlv_type);
            break;
        }
        tlv_off += tlv_len;
    }
}

/*------------------------------------------------------------------------------
 * SENDER TSPEC
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_tspec(proto_item *ti, proto_tree *rsvp_object_tree,
                   tvbuff_t *tvb,
                   int offset, int obj_length,
                   int rsvp_class _U_, int type)
{
    int         offset2 = offset + 4;
    int         mylen;
    proto_tree *tspec_tree, *ti2;
    guint8      signal_type;
    guint16     switch_gran;

    mylen = obj_length - 4;

    switch(type) {
    case 2:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 2 - Integrated Services");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
                            "Message format version: %u",
                            tvb_get_guint8(tvb, offset2)>>4);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
                            "Data length: %u words, not including header",
                            tvb_get_ntohs(tvb, offset2+2));

        mylen -= 4;
        offset2 += 4;

        proto_item_set_text(ti, "SENDER TSPEC: IntServ, ");

        while (mylen > 0) {
            guint8 service_num;
            guint8 param_id;
            guint param_len;
            guint param_len_processed;
            guint length;

            service_num = tvb_get_guint8(tvb, offset2);
            proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
                                "Service header: %u - %s",
                                service_num,
                                val_to_str_const(service_num, qos_vals, "Unknown"));
            length = tvb_get_ntohs(tvb, offset2+2);
            proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
                                "Length of service %u data: %u words, "
                                "not including header",
                                service_num, length);

            mylen -= 4;
            offset2 += 4;

            /* Process all known service headers as a set of parameters */
            param_len_processed = 0;
            while (param_len_processed < length) {
                param_id = tvb_get_guint8(tvb, offset2);
                param_len = tvb_get_ntohs(tvb, offset2+2) + 1;
                if (param_len < 1)
                    THROW(ReportedBoundsError);
                switch(param_id) {
                case 127:
                    /* Token Bucket */
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2, param_len*4,
                                              "Token Bucket TSpec: ");
                    tspec_tree = proto_item_add_subtree(ti2, TREE(TT_TSPEC_SUBTREE));

                    proto_tree_add_text(tspec_tree, tvb, offset2, 1,
                                        "Parameter %u - %s",
                                        param_id,
                                        val_to_str_ext_const(param_id, &svc_vals_ext, "Unknown"));
                    proto_tree_add_text(tspec_tree, tvb, offset2+1, 1,
                                        "Parameter %u flags: 0x%02x",
                                        param_id,
                                        tvb_get_guint8(tvb, offset2+1));
                    proto_tree_add_text(tspec_tree, tvb, offset2+2, 2,
                                        "Parameter %u data length: %u words, "
                                        "not including header",
                                        param_id,
                                        tvb_get_ntohs(tvb, offset2+2));
                    proto_tree_add_text(tspec_tree, tvb, offset2+4, 4,
                                        "Token bucket rate: %.10g",
                                        tvb_get_ntohieee_float(tvb, offset2+4));
                    proto_tree_add_text(tspec_tree, tvb, offset2+8, 4,
                                        "Token bucket size: %.10g",
                                        tvb_get_ntohieee_float(tvb, offset2+8));
                    proto_tree_add_text(tspec_tree, tvb, offset2+12, 4,
                                        "Peak data rate: %.10g",
                                        tvb_get_ntohieee_float(tvb, offset2+12));
                    proto_tree_add_text(tspec_tree, tvb, offset2+16, 4,
                                        "Minimum policed unit [m]: %u",
                                        tvb_get_ntohl(tvb, offset2+16));
                    proto_tree_add_text(tspec_tree, tvb, offset2+20, 4,
                                        "Maximum packet size [M]: %u",
                                        tvb_get_ntohl(tvb, offset2+20));
                    proto_item_append_text(ti, "Token Bucket, %.10g bytes/sec. ",
                                           tvb_get_ntohieee_float(tvb, offset2+4));
                    proto_item_append_text(ti2, "Rate=%.10g Burst=%.10g Peak=%.10g m=%u M=%u",
                                           tvb_get_ntohieee_float(tvb, offset2+4),
                                           tvb_get_ntohieee_float(tvb, offset2+8),
                                           tvb_get_ntohieee_float(tvb, offset2+12),
                                           tvb_get_ntohl(tvb, offset2+16),
                                           tvb_get_ntohl(tvb, offset2+20));
                    break;

                case 128:
                    /* Null Service (RFC2997) */
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2, param_len*4,
                                              "Null Service TSpec: ");
                    tspec_tree = proto_item_add_subtree(ti2, TREE(TT_TSPEC_SUBTREE));

                    proto_tree_add_text(tspec_tree, tvb, offset2, 1,
                                        "Parameter %u - %s",
                                        param_id,
                                        val_to_str_ext_const(param_id, &svc_vals_ext, "Unknown"));
                    proto_tree_add_text(tspec_tree, tvb, offset2+1, 1,
                                        "Parameter %u flags: %x",
                                        param_id,
                                        tvb_get_guint8(tvb, offset2+1));
                    proto_tree_add_text(tspec_tree, tvb, offset2+2, 2,
                                        "Parameter %u data length: %u words, "
                                        "not including header",
                                        param_id,
                                        tvb_get_ntohs(tvb, offset2+2));
                    proto_tree_add_text(tspec_tree, tvb, offset2+4, 4,
                                        "Maximum packet size [M]: %u",
                                        tvb_get_ntohl(tvb, offset2+4));
                    proto_item_append_text(ti, "Null Service. M=%u",
                                           tvb_get_ntohl(tvb, offset2+4));
                    proto_item_append_text(ti2, "Max pkt size=%u",
                                           tvb_get_ntohl(tvb, offset2+4));
                    break;

                case 126:
                    /* Compression hint (RFC3006) */
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2, param_len*4,
                                              "Compression Hint: ");
                    tspec_tree = proto_item_add_subtree(ti2, TREE(TT_TSPEC_SUBTREE));

                    proto_tree_add_text(tspec_tree, tvb, offset2, 1,
                                        "Parameter %u - %s",
                                        param_id,
                                        val_to_str_ext_const(param_id, &svc_vals_ext, "Unknown"));
                    proto_tree_add_text(tspec_tree, tvb, offset2+1, 1,
                                        "Parameter %u flags: %x",
                                        param_id,
                                        tvb_get_guint8(tvb, offset2+1));
                    proto_tree_add_text(tspec_tree, tvb, offset2+2, 2,
                                        "Parameter %u data length: %u words, "
                                        "not including header",
                                        param_id,
                                        tvb_get_ntohs(tvb, offset2+2));
                    proto_tree_add_text(tspec_tree, tvb, offset2+4, 4,
                                        "Hint: %u",
                                        tvb_get_ntohl(tvb, offset2+4));
                    proto_tree_add_text(tspec_tree, tvb, offset2+4, 4,
                                        "Compression Factor: %u",
                                        tvb_get_ntohl(tvb, offset2+8));
                    proto_item_append_text(ti, "Compression Hint. Hint=%u, Factor=%u",
                                           tvb_get_ntohl(tvb, offset2+4),
                                           tvb_get_ntohl(tvb, offset2+8));
                    proto_item_append_text(ti2, "Hint=%u, Factor=%u",
                                           tvb_get_ntohl(tvb, offset2+4),
                                           tvb_get_ntohl(tvb, offset2+8));
                    break;

                default:
                    proto_tree_add_text(rsvp_object_tree, tvb, offset2, param_len*4,
                                        "Unknown parameter %d, %d words",
                                        param_id, param_len);
                    break;
                }
                param_len_processed += param_len;
                offset2 += param_len*4;
            }
            mylen -= length*4;
        }
        break;

    case 4: /* SONET/SDH Tspec */
        proto_item_set_text(ti, "SENDER TSPEC: SONET/SDH, ");

        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 4 - SONET/SDH");
        signal_type = tvb_get_guint8(tvb, offset2);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
                            "Signal Type: %d - %s", signal_type,
                            val_to_str_ext_const(signal_type,
                                                 &gmpls_sonet_signal_type_str_ext, "Unknown"));
        ti2 = proto_tree_add_text(rsvp_object_tree, tvb, offset2+1, 1,
                            "Requested Concatenation (RCC): %d", tvb_get_guint8(tvb, offset2+1));
        tspec_tree = proto_item_add_subtree(ti2, TREE(TT_TSPEC_SUBTREE));
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_standard_contiguous_concatenation,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_arbitrary_contiguous_concatenation,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
                            "Number of Contiguous Components (NCC): %d", tvb_get_ntohs(tvb, offset2+2));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 2,
                            "Number of Virtual Components (NVC): %d", tvb_get_ntohs(tvb, offset2+4));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+6, 2,
                            "Multiplier (MT): %d", tvb_get_ntohs(tvb, offset2+6));
        ti2 = proto_tree_add_text(rsvp_object_tree, tvb, offset2+8, 4,
                                  "Transparency (T): 0x%0x", tvb_get_ntohl(tvb, offset2+8));
        tspec_tree = proto_item_add_subtree(ti2, TREE(TT_TSPEC_SUBTREE));

        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_regenerator_section,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_multiplex_section,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_J0_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_SOH_RSOH_DCC_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_LOH_MSOH_DCC_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_LOH_MSOH_extended_DCC_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_K1_K2_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_E1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_F1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_E2_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_B1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_B2_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_M0_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_M1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);

        proto_tree_add_text(rsvp_object_tree, tvb, offset2+12, 4,
                            "Profile (P): %d", tvb_get_ntohl(tvb, offset2+12));

        proto_item_append_text(ti, "Signal [%s], RCC %d, NCC %d, NVC %d, MT %d, Transparency %d, Profile %d",
                               val_to_str_ext_const(signal_type, &gmpls_sonet_signal_type_str_ext, "Unknown"),
                               tvb_get_guint8(tvb, offset2+1), tvb_get_ntohs(tvb, offset2+2),
                               tvb_get_ntohs(tvb, offset2+4), tvb_get_ntohs(tvb, offset2+6),
                               tvb_get_ntohl(tvb, offset2+8), tvb_get_ntohl(tvb, offset2+12));
        break;

    case 5: /* FF: G.709 TSPEC, RFC 4328 */
        proto_item_set_text(ti, "SENDER TSPEC: G.709, ");

        proto_tree_add_text(rsvp_object_tree, tvb, offset + 3, 1,
                            "C-type: 5 - G.709");
        signal_type = tvb_get_guint8(tvb, offset2);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
                            "Signal Type: %d - %s", signal_type,
                            rval_to_str(signal_type,
                                        gmpls_g709_signal_type_rvals,
                                        "Unknown"));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2 + 2, 2,
                            "Number of Multiplexed Components (NMC): %d",
                            tvb_get_ntohs(tvb, offset2 + 2));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2 + 4, 2,
                            "Number of Virtual Components (NVC): %d",
                            tvb_get_ntohs(tvb, offset2 + 4));

        proto_tree_add_text(rsvp_object_tree, tvb, offset2 + 6, 2,
                            "Multiplier (MT): %d",
                            tvb_get_ntohs(tvb, offset2 + 6));
        proto_item_append_text(ti, "Signal [%s], NMC %d, NVC %d, MT %d",
                               rval_to_str(signal_type,
                                           gmpls_g709_signal_type_rvals,
                                           "Unknown"),
                               tvb_get_ntohs(tvb, offset2 + 2),
                               tvb_get_ntohs(tvb, offset2 + 4),
                               tvb_get_ntohs(tvb, offset2 + 6));
        break;

    case 6:   /* Ethernet TSPEC (RFC6003)  */
        proto_item_set_text(ti, "SENDER TSPEC: Ethernet, ");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 6 - Ethernet");
        switch_gran = tvb_get_ntohs(tvb, offset2);
        if (switch_gran == 0)
          proto_tree_add_text(rsvp_object_tree, tvb, offset2, 2,
                              "Switching granularity: 0 - Provided in signaling");
        else if (switch_gran == 1)
          proto_tree_add_text(rsvp_object_tree, tvb, offset2, 2,
                              "Switching granularity: 1 - Ethernet port");
        else if (switch_gran == 2)
          proto_tree_add_text(rsvp_object_tree, tvb, offset2, 2,
                              "Switching granularity: 2 - Ethernet frame");
        else
          proto_tree_add_text(rsvp_object_tree, tvb, offset2, 2,
                              "Switching granularity: %u - ???", switch_gran);

        proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
                            "MTU: %u", tvb_get_ntohs(tvb, offset2+2));

        dissect_rsvp_eth_tspec_tlv(ti, rsvp_object_tree, tvb, offset+8, obj_length-8,
                                   TREE(TT_TSPEC_SUBTREE));
        break;

    default: /* Unknown TSpec */
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;

    }
}

/*------------------------------------------------------------------------------
 * FLOWSPEC
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_flowspec(proto_item *ti, proto_tree *rsvp_object_tree,
                      tvbuff_t *tvb,
                      int offset, int obj_length,
                      int rsvp_class _U_, int type)
{
    int         offset2 = offset + 4;
    int         mylen, signal_type;
    proto_tree *flowspec_tree, *ti2;
    proto_item *item;
    guint16     switch_gran;

    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                        "C-type: %u", type);
    mylen = obj_length - 4;

    switch(type) {

    case 2:
        if (mylen < 4) {
            item = proto_tree_add_text(rsvp_object_tree, tvb, 0, 0,
                                       "Object length %u < 8", obj_length);
            PROTO_ITEM_SET_GENERATED(item);
            return;
        }
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
                            "Message format version: %u",
                            tvb_get_guint8(tvb, offset2)>>4);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
                            "Data length: %u words, not including header",
                            tvb_get_ntohs(tvb, offset2+2));

        proto_item_set_text(ti, "FLOWSPEC: ");

        mylen -= 4;
        offset2+= 4;
        while (mylen > 0) {
            guint8 service_num;
            guint length;
            guint8 param_id;
            guint param_len;
            guint param_len_processed;

            if (mylen < 4) {
                item = proto_tree_add_text(rsvp_object_tree, tvb, 0, 0,
                                           "Object length %u not large enough",
                                           obj_length);
                PROTO_ITEM_SET_GENERATED(item);
                return;
            }
            service_num = tvb_get_guint8(tvb, offset2);
            proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
                                "Service header: %u - %s",
                                service_num,
                                val_to_str_ext_const(service_num, &intsrv_services_str_ext, "Unknown"));
            length = tvb_get_ntohs(tvb, offset2+2);
            proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
                                "Length of service %u data: %u words, "
                                "not including header",
                                service_num,
                                length);

            mylen   -= 4;
            offset2 += 4;

            proto_item_append_text(ti, "%s: ",
                                   val_to_str_ext(service_num, &intsrv_services_str_ext,
                                                  "Unknown (%d)"));

            /* Process all known service headers as a set of parameters */
            param_len_processed = 0;
            while (param_len_processed < length) {
                param_id = tvb_get_guint8(tvb, offset2);
                param_len = tvb_get_ntohs(tvb, offset2+2) + 1;
                if (param_len < 1)
                    THROW(ReportedBoundsError);
                switch(param_id) {
                case 127:
                    /* Token Bucket */
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2, param_len*4,
                                              "Token Bucket: ");
                    flowspec_tree = proto_item_add_subtree(ti2, TREE(TT_FLOWSPEC_SUBTREE));

                    proto_tree_add_text(flowspec_tree, tvb, offset2, 1,
                                        "Parameter %u - %s",
                                        param_id,
                                        val_to_str_ext_const(param_id, &svc_vals_ext, "Unknown"));
                    proto_tree_add_text(flowspec_tree, tvb, offset2+1, 1,
                                        "Parameter %u flags: 0x%02x",
                                        param_id,
                                        tvb_get_guint8(tvb, offset2+1));
                    proto_tree_add_text(flowspec_tree, tvb, offset2+2, 2,
                                        "Parameter %u data length: %u words, "
                                        "not including header",
                                        param_id,
                                        tvb_get_ntohs(tvb, offset2+2));
                    proto_tree_add_text(flowspec_tree, tvb, offset2+4, 4,
                                        "Token bucket rate: %.10g",
                                        tvb_get_ntohieee_float(tvb, offset2+4));
                    proto_tree_add_text(flowspec_tree, tvb, offset2+8, 4,
                                        "Token bucket size: %.10g",
                                        tvb_get_ntohieee_float(tvb, offset2+8));
                    proto_tree_add_text(flowspec_tree, tvb, offset2+12, 4,
                                        "Peak data rate: %.10g",
                                        tvb_get_ntohieee_float(tvb, offset2+12));
                    proto_tree_add_text(flowspec_tree, tvb, offset2+16, 4,
                                        "Minimum policed unit [m]: %u",
                                        tvb_get_ntohl(tvb, offset2+16));
                    proto_tree_add_text(flowspec_tree, tvb, offset2+20, 4,
                                        "Maximum packet size [M]: %u",
                                        tvb_get_ntohl(tvb, offset2+20));
                    proto_item_append_text(ti, "Token Bucket, %.10g bytes/sec. ",
                                           tvb_get_ntohieee_float(tvb, offset2+4));
                    proto_item_append_text(ti2, "Rate=%.10g Burst=%.10g Peak=%.10g m=%u M=%u",
                                           tvb_get_ntohieee_float(tvb, offset2+4),
                                           tvb_get_ntohieee_float(tvb, offset2+8),
                                           tvb_get_ntohieee_float(tvb, offset2+12),
                                           tvb_get_ntohl(tvb, offset2+16),
                                           tvb_get_ntohl(tvb, offset2+20));
                    break;

                case 130:
                    /* Guaranteed-rate RSpec */
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2, param_len*4,
                                              "Guaranteed-Rate RSpec: ");
                    flowspec_tree = proto_item_add_subtree(ti2, TREE(TT_FLOWSPEC_SUBTREE));
                    proto_tree_add_text(flowspec_tree, tvb, offset2, 1,
                                        "Parameter %u - %s",
                                        param_id,
                                        val_to_str_ext_const(param_id, &svc_vals_ext, "Unknown"));
                    proto_tree_add_text(flowspec_tree, tvb, offset2+1, 1,
                                        "Parameter %u flags: %x",
                                        param_id,
                                        tvb_get_guint8(tvb, offset2+1));
                    proto_tree_add_text(flowspec_tree, tvb, offset2+2, 2,
                                        "Parameter %u data length: %u words, "
                                        "not including header",
                                        param_id,
                                        tvb_get_ntohs(tvb, offset2+2));

                    proto_tree_add_text(flowspec_tree, tvb, offset2+4, 4,
                                        "Rate: %.10g",
                                        tvb_get_ntohieee_float(tvb, offset2+4));
                    proto_tree_add_text(flowspec_tree, tvb, offset2+8, 4,
                                        "Slack term: %u",
                                        tvb_get_ntohl(tvb, offset2+8));
                    proto_item_append_text(ti, "RSpec, %.10g bytes/sec. ",
                                           tvb_get_ntohieee_float(tvb, offset2+4));
                    proto_item_append_text(ti2, "R=%.10g, s=%u",
                                           tvb_get_ntohieee_float(tvb, offset2+4),
                                           tvb_get_ntohl(tvb, offset2+8));
                    break;

                case 128:
                    /* Null Service (RFC2997) */
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2, param_len*4,
                                              "Null Service Flowspec: ");
                    flowspec_tree = proto_item_add_subtree(ti2, TREE(TT_FLOWSPEC_SUBTREE));

                    proto_tree_add_text(flowspec_tree, tvb, offset2, 1,
                                        "Parameter %u - %s",
                                        param_id,
                                        val_to_str_ext_const(param_id, &svc_vals_ext, "Unknown"));
                    proto_tree_add_text(flowspec_tree, tvb, offset2+1, 1,
                                        "Parameter %u flags: %x",
                                        param_id,
                                        tvb_get_guint8(tvb, offset2+1));
                    proto_tree_add_text(flowspec_tree, tvb, offset2+2, 2,
                                        "Parameter %u data length: %u words, "
                                        "not including header",
                                        param_id,
                                        tvb_get_ntohs(tvb, offset2+2));
                    proto_tree_add_text(flowspec_tree, tvb, offset2+4, 4,
                                        "Maximum packet size [M]: %u",
                                        tvb_get_ntohl(tvb, offset2+4));
                    proto_item_append_text(ti, "Null Service. M=%u",
                                           tvb_get_ntohl(tvb, offset2+4));
                    proto_item_append_text(ti2, "Max pkt size=%u",
                                           tvb_get_ntohl(tvb, offset2+4));
                    break;

                default:
                    proto_tree_add_text(rsvp_object_tree, tvb, offset2, param_len*4,
                                        "Unknown parameter %d, %d words",
                                        param_id, param_len);
                    break;
                }
                param_len_processed += param_len;
                offset2 += param_len * 4;
            }

            /* offset2 += length*4; */
            mylen -= length*4;
        }
        break;

    case 4:
        proto_item_set_text(ti, "FLOWSPEC: SONET/SDH, ");

        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 4 - SONET/SDH");
        signal_type = tvb_get_guint8(tvb, offset2);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
                            "Signal Type: %d - %s", signal_type,
                            val_to_str_ext_const(signal_type,
                                                 &gmpls_sonet_signal_type_str_ext, "Unknown"));
        ti2 = proto_tree_add_text(rsvp_object_tree, tvb, offset2+1, 1,
                                  "Requested Concatenation (RCC): %d", tvb_get_guint8(tvb, offset2+1));
        flowspec_tree = proto_item_add_subtree(ti2, TREE(TT_FLOWSPEC_SUBTREE));
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_standard_contiguous_concatenation,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_arbitrary_contiguous_concatenation,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
                            "Number of Contiguous Components (NCC): %d", tvb_get_ntohs(tvb, offset2+2));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 2,
                            "Number of Virtual Components (NVC): %d", tvb_get_ntohs(tvb, offset2+4));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+6, 2,
                            "Multiplier (MT): %d", tvb_get_ntohs(tvb, offset2+6));
        ti2 = proto_tree_add_text(rsvp_object_tree, tvb, offset2+8, 4,
                                  "Transparency (T): 0x%0x", tvb_get_ntohl(tvb, offset2+8));
        flowspec_tree = proto_item_add_subtree(ti2, TREE(TT_FLOWSPEC_SUBTREE));

        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_regenerator_section,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_multiplex_section,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_J0_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_SOH_RSOH_DCC_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_LOH_MSOH_DCC_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_LOH_MSOH_extended_DCC_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_K1_K2_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_E1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_F1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_E2_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_B1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_B2_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_M0_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_M1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);

        proto_tree_add_text(rsvp_object_tree, tvb, offset2+12, 4,
                            "Profile (P): %d", tvb_get_ntohl(tvb, offset2+12));

        proto_item_append_text(ti, "Signal [%s], RCC %d, NCC %d, NVC %d, MT %d, Transparency %d, Profile %d",
                               val_to_str_ext_const(signal_type, &gmpls_sonet_signal_type_str_ext, "Unknown"),
                               tvb_get_guint8(tvb, offset2+1), tvb_get_ntohs(tvb, offset2+2),
                               tvb_get_ntohs(tvb, offset2+4), tvb_get_ntohs(tvb, offset2+6),
                               tvb_get_ntohl(tvb, offset2+8), tvb_get_ntohl(tvb, offset2+12));
        break;

    case 5: /* FF: G.709 FLOWSPEC, RFC 4328 */
        proto_item_set_text(ti, "FLOWSPEC: G.709, ");

        proto_tree_add_text(rsvp_object_tree, tvb, offset + 3, 1,
                            "C-type: 5 - G.709");
        signal_type = tvb_get_guint8(tvb, offset2);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
                            "Signal Type: %d - %s", signal_type,
                            rval_to_str(signal_type,
                                        gmpls_g709_signal_type_rvals,
                                        "Unknown"));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2 + 2, 2,
                            "Number of Multiplexed Components (NMC): %d",
                            tvb_get_ntohs(tvb, offset2 + 2));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2 + 4, 2,
                            "Number of Virtual Components (NVC): %d",
                            tvb_get_ntohs(tvb, offset2 + 4));

        proto_tree_add_text(rsvp_object_tree, tvb, offset2 + 6, 2,
                            "Multiplier (MT): %d",
                            tvb_get_ntohs(tvb, offset2 + 6));
        proto_item_append_text(ti, "Signal [%s], NMC %d, NVC %d, MT %d",
                               rval_to_str(signal_type,
                                           gmpls_g709_signal_type_rvals,
                                           "Unknown"),
                               tvb_get_ntohs(tvb, offset2 + 2),
                               tvb_get_ntohs(tvb, offset2 + 4),
                               tvb_get_ntohs(tvb, offset2 + 6));
        break;

    case 6:   /* Ethernet FLOWSPEC (RFC6003)  */
        proto_item_set_text(ti, "FLOWSPEC: Ethernet, ");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 6 - Ethernet");
        switch_gran = tvb_get_ntohs(tvb, offset2);
        if (switch_gran == 0)
            proto_tree_add_text(rsvp_object_tree, tvb, offset2, 2,
                                "Switching granularity: 0 - Provided in signaling");
        else if (switch_gran == 1)
            proto_tree_add_text(rsvp_object_tree, tvb, offset2, 2,
                                "Switching granularity: 1 - Ethernet port");
        else if (switch_gran == 2)
            proto_tree_add_text(rsvp_object_tree, tvb, offset2, 2,
                                "Switching granularity: 2 - Ethernet frame");
        else
            proto_tree_add_text(rsvp_object_tree, tvb, offset2, 2,
                                "Switching granularity: %u - ???", switch_gran);

        proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
                            "MTU: %u", tvb_get_ntohs(tvb, offset2+2));

        dissect_rsvp_eth_tspec_tlv(ti, rsvp_object_tree, tvb, offset+8, obj_length-8,
                                   TREE(TT_FLOWSPEC_SUBTREE));
        break;

    default:
        break;
    }
}

/*------------------------------------------------------------------------------
 * ADSPEC
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_adspec(proto_item *ti, proto_tree *rsvp_object_tree,
                    tvbuff_t *tvb,
                    int offset, int obj_length,
                    int rsvp_class _U_, int type)
{
    int         offset2 = offset + 4;
    int         mylen, i;
    proto_tree *adspec_tree;

    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                        "C-type: %u", type);
    mylen = obj_length - 4;

    proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
                        "Message format version: %u",
                        tvb_get_guint8(tvb, offset2)>>4);
    proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
                        "Data length: %u words, not including header",
                        tvb_get_ntohs(tvb, offset2+2));
    mylen -= 4;
    offset2 += 4;
    while (mylen > 0) {
        guint8 service_num;
        guint8 break_bit;
        guint length;
        const char *str;

        service_num = tvb_get_guint8(tvb, offset2);
        str = val_to_str_ext_const(service_num, &intsrv_services_str_ext, "Unknown");
        break_bit = tvb_get_guint8(tvb, offset2+1);
        length = tvb_get_ntohs(tvb, offset2+2);
        ti = proto_tree_add_text(rsvp_object_tree, tvb, offset2,
                                 (length+1)*4, "%s",
                                 str);
        adspec_tree = proto_item_add_subtree(ti,
                                             TREE(TT_ADSPEC_SUBTREE));
        proto_tree_add_text(adspec_tree, tvb, offset2, 1,
                            "Service header %u - %s",
                            service_num, str);
        proto_tree_add_text(adspec_tree, tvb, offset2+1, 1,
                            (break_bit&0x80)?
                            "Break bit set":"Break bit not set");
        proto_tree_add_text(adspec_tree, tvb, offset2+2, 2,
                            "Data length: %u words, not including header",
                            length);
        mylen -= 4;
        offset2 += 4;
        i = length*4;
        while (i > 0) {
            guint8 id;
            guint phdr_length;

            id = tvb_get_guint8(tvb, offset2);
            phdr_length = tvb_get_ntohs(tvb, offset2+2);
            str = match_strval_ext(id, &adspec_params_ext);
            if (str) {
                switch(id) {
                case 4:
                case 8:
                case 10:
                case 133:
                case 134:
                case 135:
                case 136:
                    /* 32-bit unsigned integer */
                    proto_tree_add_text(adspec_tree, tvb, offset2,
                                        (phdr_length+1)<<2,
                                        "%s - %u (type %u, length %u)",
                                        str,
                                        tvb_get_ntohl(tvb, offset2+4),
                                        id, phdr_length);
                    break;

                case 6:
                    /* IEEE float */
                    proto_tree_add_text(adspec_tree, tvb, offset2,
                                        (phdr_length+1)<<2,
                                        "%s - %.10g (type %u, length %u)",
                                        str,
                                        tvb_get_ntohieee_float(tvb, offset2+4),
                                        id, phdr_length);
                    break;
                default:
                    proto_tree_add_text(adspec_tree, tvb, offset2,
                                        (phdr_length+1)<<2,
                                        "%s (type %u, length %u)",
                                        str,
                                        id, phdr_length);
                    break;
                }
            } else {
                proto_tree_add_text(adspec_tree, tvb, offset2,
                                    (phdr_length+1)<<2,
                                    "Unknown (type %u, length %u)",
                                    id, phdr_length);
            }
            offset2 += (phdr_length+1)<<2;
            i -= (phdr_length+1)<<2;
            mylen -= (phdr_length+1)<<2;
        }
    }
}

/*------------------------------------------------------------------------------
 * INTEGRITY
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_integrity(proto_item *ti _U_, proto_tree *rsvp_object_tree,
                       tvbuff_t *tvb,
                       int offset, int obj_length,
                       int rsvp_class _U_, int type)
{
    int         offset2 = offset + 4;
    proto_tree *ti2, *rsvp_integ_flags_tree;
    int         flags;

    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                        "C-type: %u", type);
    flags = tvb_get_guint8(tvb, offset2);
    ti2 = proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
                              "Flags: 0x%02x", flags);
    rsvp_integ_flags_tree = proto_item_add_subtree(ti2, TREE(TT_INTEGRITY_FLAGS));
    proto_tree_add_item(rsvp_integ_flags_tree, hf_rsvp_integrity_flags_handshake,
                             tvb, offset2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 6,
                        "Key Identifier: %s", tvb_bytes_to_str(tvb, offset2+2, 6));
    proto_tree_add_text(rsvp_object_tree, tvb, offset2+8, 8,
                        "Sequence Number: %" G_GINT64_MODIFIER "u", tvb_get_ntoh64(tvb, offset2+8));
    proto_tree_add_text(rsvp_object_tree, tvb, offset2+16, obj_length - 20,
                        "Hash: %s", tvb_bytes_to_str(tvb, offset2+16, obj_length - 20));
}

/*------------------------------------------------------------------------------
 * POLICY
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_policy(proto_item *ti _U_, proto_tree *rsvp_object_tree,
                    tvbuff_t *tvb,
                    int offset, int obj_length,
                    int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;

    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                        "C-type: %u", type);
    proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                        "Data (%d bytes)", obj_length - 4);
}

/*------------------------------------------------------------------------------
 * LABEL_REQUEST
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_label_request(proto_item *ti, proto_tree *rsvp_object_tree,
                           tvbuff_t *tvb,
                           int offset, int obj_length,
                           int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    static const value_string lab_req_type_str[] = {
        { 1, ""},
        { 2, "(Label Request with ATM label Range)"},
        { 3, "(Label Request with Frame-Relay label Range)"},
        { 4, "(Generalized Label Request)"},
        { 5, "(Generalized Channel_set Label Request)"},
        { 0, NULL }
    };
    static value_string_ext lab_req_type_str_ext = VALUE_STRING_EXT_INIT(lab_req_type_str);

    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                        "C-type: %d %s", type,
                        val_to_str_ext_const(type, &lab_req_type_str_ext, "Unknown"));
    switch(type) {
    case 1: {
        unsigned short l3pid = tvb_get_ntohs(tvb, offset2+2);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
                            "L3PID: %s (0x%04x)",
                            val_to_str_const(l3pid, etype_vals, "Unknown"),
                            l3pid);
        proto_item_set_text(ti, "LABEL REQUEST: Basic: L3PID: %s (0x%04x)",
                            val_to_str_const(l3pid, etype_vals, "Unknown"),
                            l3pid);
        break;
    }

    case 2: {
        unsigned short l3pid = tvb_get_ntohs(tvb, offset2+2);
        unsigned short min_vpi, min_vci, max_vpi, max_vci;
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
                            "L3PID: %s (0x%04x)",
                            val_to_str_const(l3pid, etype_vals, "Unknown"),
                            l3pid);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 1,
                            "M: %s Merge in Data Plane",
                            (tvb_get_guint8(tvb, offset2+4) & 0x80) ?
                            "1: Can" : "0: Cannot");
        min_vpi = tvb_get_ntohs(tvb, offset2+4) & 0x7f;
        min_vci = tvb_get_ntohs(tvb, offset2+6);
        max_vpi = tvb_get_ntohs(tvb, offset2+8) & 0x7f;
        max_vci = tvb_get_ntohs(tvb, offset2+10);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 2,
                            "Min VPI: %d", min_vpi);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+6, 2,
                            "Min VCI: %d", min_vci);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+8, 2,
                            "Max VPI: %d", max_vpi);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+10, 2,
                            "Max VCI: %d", max_vci);
        proto_item_set_text(ti, "LABEL REQUEST: ATM: L3PID: %s (0x%04x). VPI/VCI: Min: %d/%d, Max: %d/%d. %s Merge. ",
                            val_to_str_const(l3pid, etype_vals, "Unknown"), l3pid,
                            min_vpi, min_vci, max_vpi, max_vci,
                            (tvb_get_guint8(tvb, offset2+4) & 0x80) ? "Can" : "Cannot");
        break;
    }

    case 3: {
        guint16 l3pid = tvb_get_ntohs(tvb, offset2+2);
        guint32 min_dlci, max_dlci, dlci_len, dlci_len_code;
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
                            "L3PID: %s (0x%04x)",
                            val_to_str_const(l3pid, etype_vals, "Unknown"),
                            l3pid);
        dlci_len_code = (tvb_get_ntohs(tvb, offset2+4) & 0x0180) >> 7;
        min_dlci = tvb_get_ntohl(tvb, offset2+4) & 0x7fffff;
        max_dlci = tvb_get_ntohl(tvb, offset2+8) & 0x7fffff;
        switch(dlci_len_code) {
        case 0:
            /* 10-bit DLCIs */
            dlci_len = 10;
            min_dlci &= 0x3ff;
            max_dlci &= 0x3ff;
            break;
        case 2:
            dlci_len = 23;
            break;
        default:
            dlci_len = 0;
            min_dlci = 0;
            max_dlci = 0;
            break;
        }
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 2,
                            "DLCI Length: %s (%d)",
                            (dlci_len==10) ? "10 bits" :
                            (dlci_len==23) ? "23 bits" :
                            "INVALID", dlci_len_code);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+5, 3,
                            "Min DLCI: %d", min_dlci);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+8, 2,
                            "Max DLCI: %d", max_dlci);
        proto_item_set_text(ti, "LABEL REQUEST: Frame: L3PID: %s (0x%04x). DLCI Len: %s. Min DLCI: %d. Max DLCI: %d",
                            val_to_str_const(l3pid, etype_vals, "Unknown"), l3pid,
                            (dlci_len==10) ? "10 bits" :
                            (dlci_len==23) ? "23 bits" :
                            "INVALID", min_dlci, max_dlci);
        break;
    }
    case 4:
    case 5: {
        unsigned short l3pid = tvb_get_ntohs(tvb, offset2+2);
        unsigned char  lsp_enc = tvb_get_guint8(tvb,offset2);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
                            "LSP Encoding Type: %s",
                            rval_to_str(lsp_enc, gmpls_lsp_enc_rvals, "Unknown (%d)"));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+1, 1,
                            "Switching Type: %s",
                            rval_to_str(tvb_get_guint8(tvb,offset2+1),
                                        gmpls_switching_type_rvals, "Unknown (%d)"));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 2,
                            "G-PID: %s (0x%0x)",
                            rval_to_str(l3pid, gmpls_gpid_rvals,
                                        val_to_str(l3pid, etype_vals,
                                                   "Unknown G-PID(0x%04x)")),
                            l3pid);
        proto_item_set_text(ti, "LABEL REQUEST: Generalized: LSP Encoding=%s, "
                            "Switching Type=%s, G-PID=%s ",
                            rval_to_str(lsp_enc, gmpls_lsp_enc_rvals, "Unknown (%d)"),
                            rval_to_str(tvb_get_guint8(tvb,offset2+1),
                                       gmpls_switching_type_rvals, "Unknown (%d)"),
                            rval_to_str(l3pid, gmpls_gpid_rvals,
                                        val_to_str(l3pid, etype_vals,
                                                   "Unknown (0x%04x)")));
        break;
    }

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    } /* switch(type) */
}

/*-----------------------------------------------------------------------------
 * LABEL
 *---------------------------------------------------------------------------*/

/*
   FF: G.694 lambda label, see draft-ietf-ccamp-gmpls-g-694-lambda-labels-05

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Grid | C.S   |    Reserved     |              n                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void
dissect_glabel_lambda(proto_tree *ti _U_, proto_tree *rsvp_object_tree,
                      tvbuff_t *tvb,
                      int offset)
{
    float   freq       = 0.0;
    guint32 wavelength = 0;
    float   cs_thz     = 0.0;

    guint8 grid = ((tvb_get_guint8(tvb, offset) & 0xE0) >> 5);
    guint8 cs   = ((tvb_get_guint8(tvb, offset) & 0x1E) >> 1);
    gint16 n    = tvb_get_ntohs(tvb, offset + 2);

    if (grid == 1) {
        /* DWDM grid: Frequency (THz) = 193.1 THz + n * channel spacing (THz) */
        cs_thz =
            cs == 1 ? 0.1f :
            cs == 2 ? 0.05f :
            cs == 3 ? 0.025f :
            cs == 4 ? 0.0125f :
        0.0f;
        freq = 193.1f + (n * cs_thz);
        proto_tree_add_text(rsvp_object_tree, tvb, offset, 4,
                            "Wavelength Label: "
                            "grid=%s, "
                            "channel spacing=%s, "
                            "n=%d, "
                            "freq=%.2fTHz",
                            /* grid */
                            grid == 1 ? "DWDM" :
                            grid == 2 ? "CWDM" :
                            "unknown",
                            /* channel spacing */
                            cs == 1 ? "100GHz" :
                            cs == 2 ? "50GHz" :
                            cs == 3 ? "25GHz" :
                            cs == 4 ? "12.5GHz" :
                            "unknown",
                            /* n */
                            n,
                            /* frequency */
                            freq);
        proto_item_append_text(ti, ": Wavelength: "
                               "grid=%s, "
                               "channel spacing=%s, "
                               "n=%d, "
                               "freq=%.2fTHz",
                               grid == 1 ? "DWDM" :
                               grid == 2 ? "CWDM" :
                               "unknown",
                               cs == 1 ? "100GHz" :
                               cs == 2 ? "50GHz" :
                               cs == 3 ? "25GHz" :
                               cs == 4 ? "12.5GHz" :
                               "unknown",
                               n,
                               freq);
    } else if (grid == 2) {
        /* CWDM grid: Wavelength (nm) = 1471 nm + n * 20 nm  */
        wavelength = 1471 + (n * 20);
        proto_tree_add_text(rsvp_object_tree, tvb, offset, 4,
                            "Wavelength Label: "
                            "grid=%s, "
                            "channel spacing=%s, "
                            "n=%d, "
                            "wavelength=%unm",
                            /* grid */
                            grid == 1 ? "DWDM" :
                            grid == 2 ? "CWDM" :
                            "unknown",
                            /* channel spacing */
                            cs == 1 ? "20nm" :
                            "unknown",
                            /* n */
                            n,
                            /* wavelength */
                            wavelength);
        proto_item_append_text(ti, ": Wavelength: "
                               "grid=%s, "
                               "channel spacing=%s, "
                               "n=%d, "
                               "wavelength=%unm",
                               grid == 1 ? "DWDM" :
                               grid == 2 ? "CWDM" :
                               "unknown",
                               cs == 1 ? "20nm" :
                               "unknown",
                               n,
                               wavelength);
    } else {
        /* unknown grid: */
        proto_tree_add_text(rsvp_object_tree, tvb, offset, 4,
                            "Wavelength Label: "
                            "grid=%u, "
                            "channel spacing=%u, "
                            "n=%d",
                            grid, cs, n);
        proto_item_append_text(ti, ": Wavelength: "
                               "grid=%u, "
                               "channel spacing=%u, "
                               "n=%d",
                               grid, cs, n);
    }
    return;
}

/*
   FF: SONET/SDH label, see RFC 4606

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               S               |   U   |   K   |   L   |   M   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static void
dissect_glabel_sdh(proto_tree *ti _U_, proto_tree *rsvp_object_tree,
                   tvbuff_t *tvb,
                   int offset)
{
    guint16 s = tvb_get_ntohs(tvb, offset);
    guint8 u = ((tvb_get_guint8(tvb, offset + 2) & 0xF0) >> 4);
    guint8 k = ((tvb_get_guint8(tvb, offset + 2) & 0x0F) >> 0);
    guint8 l = ((tvb_get_guint8(tvb, offset + 3) & 0xF0) >> 4);
    guint8 m = ((tvb_get_guint8(tvb, offset + 3) & 0x0F) >> 0);

    proto_tree_add_text(rsvp_object_tree, tvb, offset, 4,
                        "SONET/SDH Label: "
                        "S=%u, "
                        "U=%u, "
                        "K=%u, "
                        "L=%u, "
                        "M=%u",
                        s, u, k, l, m);
    proto_item_append_text(ti, ": SONET/SDH: "
                           "S=%u, "
                           "U=%u, "
                           "K=%u, "
                           "L=%u, "
                           "M=%u",
                           s, u, k, l, m);
}

/*
    FF: G.709 label (aka ODUk label), see RFC 4328

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                   Reserved                |     t3    | t2  |t1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static void
dissect_glabel_g709(proto_tree *ti _U_, proto_tree *rsvp_object_tree,
                    tvbuff_t *tvb,
                    int offset)
{
    guint8 t2 = ((tvb_get_guint8(tvb, offset + 3) & 0x0E) >> 1);
    guint8 t1 = ((tvb_get_guint8(tvb, offset + 3) & 0x01) >> 0);

    guint8 t3 = ((tvb_get_guint8(tvb, offset + 2) & 0x03) << 4);
    t3 |= ((tvb_get_guint8(tvb, offset + 3) & 0xF0) >> 4);

    proto_tree_add_text(rsvp_object_tree, tvb, offset, 4,
                        "G.709 ODUk Label: "
                        "t3=%u, "
                        "t2=%u, "
                        "t1=%u",
                        t3, t2, t1);
    proto_item_append_text(ti, ": G.709 ODUk: "
                        "t3=%u, "
                        "t2=%u, "
                        "t1=%u",
                        t3, t2, t1);
}

static void
dissect_rsvp_label(proto_tree *ti, proto_tree *rsvp_object_tree,
                   tvbuff_t *tvb,
                   int offset, int obj_length,
                   int rsvp_class, int type)
{
    int         offset2 = offset + 4;
    int         mylen, i;
    const char *name;

    name = (rsvp_class==RSVP_CLASS_SUGGESTED_LABEL ? "SUGGESTED LABEL":
            (rsvp_class==RSVP_CLASS_UPSTREAM_LABEL ? "UPSTREAM LABEL":
             (rsvp_class==RSVP_CLASS_RECOVERY_LABEL ? "RECOVERY LABEL":
             "LABEL")));
    mylen = obj_length - 4;
    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1 (Packet Label)");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4,
                            "Label: %u",
                            tvb_get_ntohl(tvb, offset2));
        proto_item_set_text(ti, "%s: %u", name,
                            tvb_get_ntohl(tvb, offset2));
        break;

    case 2:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 2 (Generalized Label)");
        if (rsvp_generalized_label_option == 1) {
            /* FF: no generalized label interpretation */
            proto_item_set_text(ti, "%s: Generalized: ", name);
            for (i = 0; i < mylen; i += 4) {
                proto_tree_add_text(rsvp_object_tree, tvb, offset2+i, 4,
                                    "Generalized Label: %u (0x%x)",
                                    tvb_get_ntohl(tvb, offset2+i),
                                    tvb_get_ntohl(tvb, offset2+i));
                if (i < 16) {
                    proto_item_append_text(ti, "0x%x%s",
                                           tvb_get_ntohl(tvb, offset2+i),
                                           i+4<mylen?", ":"");
                } else if (i == 16) {
                    proto_item_append_text(ti, "...");
                }
            }
        } else if (rsvp_generalized_label_option == 2) {
            dissect_glabel_sdh(ti, rsvp_object_tree, tvb, offset2);
        } else if (rsvp_generalized_label_option == 4) {
            dissect_glabel_g709(ti, rsvp_object_tree, tvb, offset2);
        } else if (rsvp_generalized_label_option == 3) {
            dissect_glabel_lambda(ti, rsvp_object_tree, tvb, offset2);
        }
        break;

    case 4:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 4 (Generalized Channel_set)");
        proto_item_append_text(ti, ": Generalized Channel_set");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
                            "Data (%d bytes)", mylen);
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)", type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
                            "Data (%d bytes)", mylen);
        break;
    }
}
/*------------------------------------------------------------------------------
 * LABEL_SET
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_label_set(proto_item *ti, proto_tree *rsvp_object_tree,
                       tvbuff_t *tvb,
                       int offset, int obj_length,
                       int rsvp_class _U_, int type)
{
    int    offset2 = offset + 8;
    guint8 label_type;
    int    len, i;

    static const value_string action_type_vals[] = {
        { 0, "Inclusive list"},
        { 1, "Exclusive list"},
        { 2, "Inclusive range"},
        { 3, "Exclusive range"},
        { 0, NULL}
   };
    static value_string_ext action_type_vals_ext = VALUE_STRING_EXT_INIT(action_type_vals);

    len = obj_length - 8;
    proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, "C-type: %u", type);
    proto_tree_add_text(rsvp_object_tree, tvb, offset+4, 1, "Action: %s",
                        val_to_str_ext(tvb_get_guint8(tvb, offset+4),
                                       &action_type_vals_ext, "Unknown (%u)"));
    proto_item_append_text(ti, ": %s",
                           val_to_str_ext(tvb_get_guint8(tvb, offset+4),
                           &action_type_vals_ext, "Unknown (%u)"));
    label_type = tvb_get_guint8 (tvb, offset+7);
    proto_tree_add_text(rsvp_object_tree, tvb, offset+7, 1, "Label type: %s",
                        (label_type == 1) ? "Packet Label" : "Generalized Label");
    proto_item_append_text(ti, ", %s",
                           (label_type == 1) ? "Packet Label: " : "Generalized Label: ");

    for (i = 0; i < len/4; i++) {
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+i*4, 4,
                            "Subchannel %u: %u (0x%x)", i+1,
                            tvb_get_ntohl(tvb, offset2+i*4),
                            tvb_get_ntohl(tvb, offset2+i*4));

        if (i<5) {
            if (i!=0)
                proto_item_append_text(ti, ", ");

            proto_item_append_text(ti, "%u",
                                   tvb_get_ntohl(tvb, offset2+i*4));
        }
    }
}

/*------------------------------------------------------------------------------
 * SESSION ATTRIBUTE
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_session_attribute(proto_item *ti, proto_tree *rsvp_object_tree,
                               tvbuff_t *tvb,
                               int offset, int obj_length,
                               int rsvp_class _U_, int type)
{
    int         offset2 = offset + 4;
    guint8      flags;
    guint8      name_len;
    proto_tree *ti2, *rsvp_sa_flags_tree;

    switch(type) {
    case 1:
    case 7:

        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: %u - IPv4 LSP (%sResource Affinities)",
                            type, (type == 1) ? "" : "No ");

        if (type == 1) {
            proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4,
                            "Exclude-Any: 0x%0x", tvb_get_ntohl(tvb, offset2));
            proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 4,
                            "Include-Any: 0x%0x", tvb_get_ntohl(tvb, offset2+4));
            proto_tree_add_text(rsvp_object_tree, tvb, offset2+8, 4,
                            "Include-All: 0x%0x", tvb_get_ntohl(tvb, offset2+8));
            offset2 = offset2+12;
        }

        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1,
                            "Setup priority: %u",
                            tvb_get_guint8(tvb, offset2));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+1, 1,
                            "Hold priority: %u",
                            tvb_get_guint8(tvb, offset2+1));
        flags = tvb_get_guint8(tvb, offset2+2);
        ti2 = proto_tree_add_text(rsvp_object_tree, tvb, offset2+2, 1,
                                  "Flags: 0x%02x", flags);
        rsvp_sa_flags_tree = proto_item_add_subtree(ti2,
                                                    TREE(TT_SESSION_ATTRIBUTE_FLAGS));
        proto_tree_add_item(rsvp_sa_flags_tree, hf_rsvp_sa_flags_local,
                             tvb, offset2+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_sa_flags_tree, hf_rsvp_sa_flags_label,
                             tvb, offset2+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_sa_flags_tree, hf_rsvp_sa_flags_se_style,
                             tvb, offset2+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_sa_flags_tree, hf_rsvp_sa_flags_bandwidth,
                             tvb, offset2+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_sa_flags_tree, hf_rsvp_sa_flags_node,
                             tvb, offset2+2, 1, ENC_BIG_ENDIAN);

        name_len = tvb_get_guint8(tvb, offset2+3);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+3, 1,
                            "Name length: %u", name_len);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, name_len,
                            "Name: %s",
                            tvb_format_text(tvb, offset2+4, name_len));

        proto_item_set_text(ti, "SESSION ATTRIBUTE: SetupPrio %d, HoldPrio %d, %s%s%s%s%s [%s]",
                            tvb_get_guint8(tvb, offset2),
                            tvb_get_guint8(tvb, offset2+1),
                            flags &0x01 ? "Local Protection, " : "",
                            flags &0x02 ? "Label Recording, " : "",
                            flags &0x04 ? "SE Style, " : "",
                            flags &0x08 ? "Bandwidth Protection, " : "",
                            flags &0x10 ? "Node Protection, " : "",
                            name_len ? tvb_format_text(tvb, offset2+4, name_len) : "");
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * EXPLICIT ROUTE AND RECORD ROUTE SUBOBJECTS
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_ero_rro_subobjects(proto_tree *ti, proto_tree *rsvp_object_tree,
                                tvbuff_t *tvb,
                                int offset, int obj_length, int rsvp_class)
{
    int         i, j, k, l, flags;
    proto_tree *ti2, *rsvp_ro_subtree, *rsvp_rro_flags_subtree;
    int         tree_type;

    switch(rsvp_class) {
    case RSVP_CLASS_EXPLICIT_ROUTE:
        tree_type = TREE(TT_EXPLICIT_ROUTE_SUBOBJ);
        break;
    case RSVP_CLASS_RECORD_ROUTE:
        tree_type = TREE(TT_RECORD_ROUTE_SUBOBJ);
        break;
    default:
        /* Bail out */
        return;
    }

    for (i=1, l = 0; l < obj_length - 4; i++) {
        j = tvb_get_guint8(tvb, offset+l) & 0x7f;
        switch(j) {
        case 1: /* IPv4 */
            k = tvb_get_guint8(tvb, offset+l) & 0x80;
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+l, 8,
                                      "IPv4 Subobject - %s%s",
                                      tvb_ip_to_str(tvb, offset+l+2),
                                      rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE ?
                                      (k ? ", Loose" : ", Strict") : "");
            rsvp_ro_subtree =
                proto_item_add_subtree(ti2, tree_type);
            if (rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE)
                proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                    k ? "Loose Hop " : "Strict Hop");
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                "Type: 1 (IPv4)");
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+1, 1,
                                "Length: %u",
                                tvb_get_guint8(tvb, offset+l+1));
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+2, 4,
                                "IPv4 hop: %s",
                                tvb_ip_to_str(tvb, offset+l+2));
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+6, 1,
                                "Prefix length: %u",
                                tvb_get_guint8(tvb, offset+l+6));
            if (i < 4) {
                proto_item_append_text(ti, "IPv4 %s%s",
                                       tvb_ip_to_str(tvb, offset+l+2),
                                       k ? " [L]" : "");
            }
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE) {
                flags = tvb_get_guint8(tvb, offset+l+7);
                if (flags&0x10) {
                    proto_item_append_text(ti,  " (Node-id)");
                    proto_item_append_text(ti2, " (Node-id)");
                }
                if (flags&0x01) proto_item_append_text(ti2, ", Local Protection Available");
                if (flags&0x02) proto_item_append_text(ti2, ", Local Protection In Use");
                if (flags&0x04) proto_item_append_text(ti2, ", Backup BW Avail");
                if (flags&0x08) proto_item_append_text(ti2, ", Backup is Next-Next-Hop");
                ti2 = proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+7, 1,
                                          "Flags: 0x%02x", flags);
                rsvp_rro_flags_subtree =
                    proto_item_add_subtree(ti2, TREE(TT_RECORD_ROUTE_SUBOBJ_FLAGS));
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_local_avail,
                             tvb, offset+l+7, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_local_in_use,
                             tvb, offset+l+7, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_bandwidth,
                             tvb, offset+l+7, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_node,
                             tvb, offset+l+7, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_node_address,
                             tvb, offset+l+7, 1, ENC_BIG_ENDIAN);
            }

            break;

        case 2: /* IPv6 */
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+l, 20,
                                      "IPv6 Subobject");
            rsvp_ro_subtree =
                proto_item_add_subtree(ti2, tree_type);
            k = tvb_get_guint8(tvb, offset+l) & 0x80;
            if (rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE)
                proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                    k ? "Loose Hop " : "Strict Hop");
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                "Type: 2 (IPv6)");
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+1, 1,
                                "Length: %u",
                                tvb_get_guint8(tvb, offset+l+1));
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+2, 16,
                                "IPv6 hop: %s",
                                tvb_ip6_to_str(tvb, offset+l+2));
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+18, 1,
                                "Prefix length: %u",
                                tvb_get_guint8(tvb, offset+l+18));
            if (i < 4) {
                proto_item_append_text(ti, "IPv6 [...]%s", k ? " [L]":"");
            }
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE) {
                flags = tvb_get_guint8(tvb, offset+l+19);
                if (flags&0x10) {
                    proto_item_append_text(ti,  " (Node-id)");
                    proto_item_append_text(ti2, " (Node-id)");
                }
                if (flags&0x01) proto_item_append_text(ti2, ", Local Protection Available");
                if (flags&0x02) proto_item_append_text(ti2, ", Local Protection In Use");
                if (flags&0x04) proto_item_append_text(ti2, ", Backup BW Avail");
                if (flags&0x08) proto_item_append_text(ti2, ", Backup is Next-Next-Hop");
                ti2 = proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+19, 1,
                                          "Flags: 0x%02x", flags);
                rsvp_rro_flags_subtree =
                    proto_item_add_subtree(ti2, TREE(TT_RECORD_ROUTE_SUBOBJ_FLAGS));

                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_local_avail,
                             tvb, offset+l+19, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_local_in_use,
                             tvb, offset+l+19, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_backup_tunnel_bandwidth,
                             tvb, offset+l+19, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_backup_tunnel_hop,
                             tvb, offset+l+19, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_node_address,
                             tvb, offset+l+19, 1, ENC_BIG_ENDIAN);

            }

            break;

        case 3: /* Label */
            k = tvb_get_guint8(tvb, offset+l) & 0x80;
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+l, 8,
                                      "Label Subobject - %d, %s",
                                      tvb_get_ntohl(tvb, offset+l+4),
                                      rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE ?
                                      (k ? "Loose" : "Strict") : "");
            rsvp_ro_subtree =
                proto_item_add_subtree(ti2, tree_type);
            if (rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE)
                proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                    k ? "Loose Hop " : "Strict Hop");
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                "Type: 3 (Label)");
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+1, 1,
                                "Length: %u",
                                tvb_get_guint8(tvb, offset+l+1));
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE) {
                flags = tvb_get_guint8(tvb, offset+l+2);
                if (flags&0x01) proto_item_append_text(ti2, ", Local Protection Available");
                if (flags&0x02) proto_item_append_text(ti2, ", Local Protection In Use");
                if (flags&0x04) proto_item_append_text(ti2, ", Backup BW Avail");
                if (flags&0x08) proto_item_append_text(ti2, ", Backup is Next-Next-Hop");
                ti2 = proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+2, 1,
                                          "Flags: 0x%02x", flags);
                rsvp_rro_flags_subtree =
                    proto_item_add_subtree(ti2, TREE(TT_RECORD_ROUTE_SUBOBJ_FLAGS));

                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_local_avail,
                             tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_local_in_use,
                             tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_backup_tunnel_bandwidth,
                             tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_backup_tunnel_hop,
                             tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
            }
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+3, 1,
                                "C-Type: %u",
                                tvb_get_guint8(tvb, offset+l+3));
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+4, 4,
                                "Label: %d",
                                tvb_get_ntohl(tvb, offset+l+4));
            if (i < 4) {
                proto_item_append_text(ti, "Label %d%s",
                                       tvb_get_ntohl(tvb, offset+l+4),
                                       k ? " [L]":"");
            }
            break;

        case 4: /* Unnumbered Interface-ID */
            k = tvb_get_guint8(tvb, offset+l) & 0x80;
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+l, 8,
                                      "Unnumbered Interface-ID - %s, %d, %s",
                                      tvb_ip_to_str(tvb, offset+l+4),
                                      tvb_get_ntohl(tvb, offset+l+8),
                                      rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE ?
                                      (k ? "Loose" : "Strict") : "");
            rsvp_ro_subtree =
                proto_item_add_subtree(ti2, tree_type);
            if (rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE)
                proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                    k ? "Loose Hop " : "Strict Hop");
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                "Type: 4 (Unnumbered Interface-ID)");
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+1, 1,
                                "Length: %u",
                                tvb_get_guint8(tvb, offset+l+1));
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE) {
                flags = tvb_get_guint8(tvb, offset+l+2);
                if (flags&0x01) proto_item_append_text(ti2, ", Local Protection Available");
                if (flags&0x02) proto_item_append_text(ti2, ", Local Protection In Use");
                if (flags&0x04) proto_item_append_text(ti2, ", Backup BW Avail");
                if (flags&0x08) proto_item_append_text(ti2, ", Backup is Next-Next-Hop");
                ti2 = proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+2, 1,
                                          "Flags: 0x%02x", flags);
                rsvp_rro_flags_subtree =
                    proto_item_add_subtree(ti2, TREE(TT_RECORD_ROUTE_SUBOBJ_FLAGS));
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_local_avail,
                             tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_local_in_use,
                             tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_backup_tunnel_bandwidth,
                             tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_backup_tunnel_hop,
                             tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
            }
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+4, 4,
                                "Router-ID: %s",
                                tvb_ip_to_str(tvb, offset+l+4));
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+8, 4,
                                "Interface-ID: %d",
                                tvb_get_ntohl(tvb, offset+l+8));
            if (i < 4) {
                proto_item_append_text(ti, "Unnum %s/%d%s",
                                       tvb_ip_to_str(tvb, offset+l+4),
                                       tvb_get_ntohl(tvb, offset+l+8),
                                       k ? " [L]":"");
            }
            break;

        case 32: /* AS */
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE) goto defaultsub;
            k = tvb_get_ntohs(tvb, offset+l+2);
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+l, 4,
                                      "Autonomous System %u",
                                      k);
            rsvp_ro_subtree =
                proto_item_add_subtree(ti2, tree_type);
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                "Type: 32 (Autonomous System Number)");
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+1, 1,
                                "Length: %u",
                                tvb_get_guint8(tvb, offset+l+1));
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+2, 2,
                                "Autonomous System %u", k);
            if (i < 4) {
                proto_item_append_text(ti, "AS %d",
                                       tvb_get_ntohs(tvb, offset+l+2));
            }
            break;

        case 64: /* PKSv4 - RFC5520 */
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE) goto defaultsub;
            k = tvb_get_ntohs(tvb, offset+l+2);
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+l, 8,
                                      "Path Key subobject - %s, %u",
                                      tvb_ip_to_str(tvb, offset+l+4),
                                      k);
            rsvp_ro_subtree =
                proto_item_add_subtree(ti2, tree_type);
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                "Type: 64 (Path Key with IPv4 PCE-ID)");
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+1, 1,
                                "Length: %u",
                                tvb_get_guint8(tvb, offset+l+1));
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+2, 2,
                                "Path Key: %u", k);
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+4, 4,
                                "PCE-ID: %s",
                                tvb_ip_to_str(tvb, offset+l+4));
            if (i < 4) {
                proto_item_append_text(ti, "Path Key %d", k);
            }
            break;

        case 65: /* PKSv6 - RFC5520 */
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE) goto defaultsub;
            k = tvb_get_ntohs(tvb, offset+l+2);
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+l, 8,
                                      "Path Key subobject - %s, %u",
                                      tvb_ip6_to_str(tvb, offset+l+4),
                                      k);
            rsvp_ro_subtree =
                proto_item_add_subtree(ti2, tree_type);
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                "Type: 65 (Path Key with IPv6 PCE-ID)");
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+1, 1,
                                "Length: %u",
                                tvb_get_guint8(tvb, offset+l+1));
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+2, 2,
                                "Path Key: %u", k);
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+4, 4,
                                "PCE-ID: %s",
                                tvb_ip6_to_str(tvb, offset+l+4));
            if (i < 4) {
                proto_item_append_text(ti, "Path Key %d", k);
            }
            break;

        case 124:
        case 125:
        case 126:
        case 127:
            /*
             * FF: Types 124 through 127 are to be reserved for Vendor
             * Private Use (see RFC 3936, Section 2.3.1) in case of
             * EXPLICIT_ROUTE (aka ERO).
             */
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE)
                goto defaultsub;
            else
                goto privatesub;
            break;

        case 252:
        case 253:
        case 254:
        case 255:
            /*
             * FF: Types 252 through 255 are to be reserved for Vendor
             * Private Use (see RFC 3936, Section 2.3.1) in case of
             * RECORD_ROUTE (aka RRO).
             */
            if (rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE)
                goto defaultsub;
            else
                goto privatesub;
            break;

        privatesub: /* Private subobject */
            /*
             * FF: The first four octets of the sub-object contents of
             * a Vendor Private sub-object of an EXPLICIT_ROUTE or
             * RECORD_ROUTE object MUST be that vendor's SMI enterprise
             * code in network octet order.
             */
            {
                guint8 private_so_len = tvb_get_guint8(tvb, offset+l+1);
                k = tvb_get_guint8(tvb, offset+l) & 0x80;
                ti2 = proto_tree_add_text(rsvp_object_tree, tvb, offset+l,
                                          tvb_get_guint8(tvb, offset+l+1),
                                          "Private Subobject: %d", j);
                rsvp_ro_subtree =
                    proto_item_add_subtree(ti2, tree_type);
                proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                    k ? "Loose Hop " : "Strict Hop");
                proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                    "Type: %u (Private)", j);
                proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+1, 1,
                                    "Length: %u",
                                    private_so_len);

                proto_tree_add_item(rsvp_ro_subtree,
                                    hf_rsvp_filter[RSVPF_ENT_CODE],
                                    tvb, offset+l+4, 4, ENC_BIG_ENDIAN);
                if (private_so_len > 8) {
                    /* some private data */
                    proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+8,
                                        private_so_len - 8,
                                        "Data (%d bytes)",
                                        private_so_len - 8);
                }
            }
            break;

        default: /* Unknown subobject */
        defaultsub:
            k = tvb_get_guint8(tvb, offset+l) & 0x80;
            ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                      offset+l,
                                      tvb_get_guint8(tvb, offset+l+1),
                                      "Unknown subobject: %d", j);
            rsvp_ro_subtree =
                proto_item_add_subtree(ti2, tree_type);
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                k ? "Loose Hop " : "Strict Hop");
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l, 1,
                                "Type: %u (Unknown)", j);
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+1, 1,
                                "Length: %u",
                                tvb_get_guint8(tvb, offset+l+1));
            break;
        }

        if (tvb_get_guint8(tvb, offset+l+1) < 1) {
            proto_tree_add_text(rsvp_ro_subtree, tvb, offset+l+1, 1,
                "Invalid length: %u", tvb_get_guint8(tvb, offset+l+1));
            return;
        }
        l += tvb_get_guint8(tvb, offset+l+1);
        if (l < obj_length - 4) {
            if (i < 4)
                proto_item_append_text(ti, ", ");
            else if (i==4)
                proto_item_append_text(ti, "...");
        }
    }
}

/*------------------------------------------------------------------------------
 * EXPLICIT ROUTE OBJECT
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_explicit_route(proto_item *ti, proto_tree *rsvp_object_tree,
                            tvbuff_t *tvb,
                            int offset, int obj_length,
                            int rsvp_class, int type)
{
    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1");
        proto_item_set_text(ti, "EXPLICIT ROUTE: ");

        dissect_rsvp_ero_rro_subobjects(ti, rsvp_object_tree, tvb,
                                        offset + 4, obj_length, rsvp_class);
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * RECORD ROUTE OBJECT
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_record_route(proto_item *ti, proto_tree *rsvp_object_tree,
                          tvbuff_t *tvb,
                          int offset, int obj_length,
                          int rsvp_class, int type)
{
    proto_item_set_text(ti, "RECORD ROUTE: ");
    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1");

        dissect_rsvp_ero_rro_subobjects(ti, rsvp_object_tree, tvb,
                                        offset + 4, obj_length, rsvp_class);
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * MESSAGE ID
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_message_id(proto_tree *ti, proto_tree *rsvp_object_tree,
                        tvbuff_t *tvb,
                        int offset, int obj_length,
                        int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;

    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, 1,
                            "Flags: %d", tvb_get_guint8(tvb, offset+4));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+5, 3,
                            "Epoch: %d", tvb_get_ntoh24(tvb, offset+5));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+8, 4,
                            "Message-ID: %d", tvb_get_ntohl(tvb, offset+8));
        proto_item_set_text(ti, "MESSAGE-ID: %d %s",
                            tvb_get_ntohl(tvb, offset+8),
                            tvb_get_guint8(tvb, offset+4) & 1 ? "(Ack Desired)" : "");
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * MESSAGE ID ACK
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_message_id_ack(proto_tree *ti, proto_tree *rsvp_object_tree,
                            tvbuff_t *tvb,
                            int offset, int obj_length,
                            int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;

    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, 1,
                            "Flags: %d", tvb_get_guint8(tvb, offset+4));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+5, 3,
                            "Epoch: %d", tvb_get_ntoh24(tvb, offset+5));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+8, 4,
                            "Message-ID: %d", tvb_get_ntohl(tvb, offset+8));
        proto_item_set_text(ti, "MESSAGE-ID ACK: %d", tvb_get_ntohl(tvb, offset+8));
        break;

    case 2:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 2");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, 1,
                            "Flags: %d", tvb_get_guint8(tvb, offset+4));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+5, 3,
                            "Epoch: %d", tvb_get_ntoh24(tvb, offset+5));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+8, 4,
                            "Message-ID: %d", tvb_get_ntohl(tvb, offset+8));
        proto_item_set_text(ti, "MESSAGE-ID NACK: %d", tvb_get_ntohl(tvb, offset+8));
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * MESSAGE ID LIST
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_message_id_list(proto_tree *ti, proto_tree *rsvp_object_tree,
                             tvbuff_t *tvb,
                             int offset, int obj_length,
                             int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    int mylen;

    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, 1,
                            "Flags: %d", tvb_get_guint8(tvb, offset+4));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+5, 3,
                            "Epoch: %d", tvb_get_ntoh24(tvb, offset+5));
        for (mylen = 8; mylen < obj_length; mylen += 4)
            proto_tree_add_text(rsvp_object_tree, tvb, offset+mylen, 4,
                                "Message-ID: %d", tvb_get_ntohl(tvb, offset+mylen));
        proto_item_set_text(ti, "MESSAGE-ID LIST: %d IDs",
                            (obj_length - 8)/4);
        break;

    default:
        mylen = obj_length - 4;
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * HELLO
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_hello(proto_tree *ti, proto_tree *rsvp_object_tree,
                   tvbuff_t *tvb,
                   int offset, int obj_length _U_,
                   int rsvp_class _U_, int type)
{
    switch(type) {
    case 1:
    case 2:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-Type: %d - HELLO %s object",
                            tvb_get_guint8 (tvb, offset+3),
                            type==1 ? "REQUEST" : "ACK");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, 4,
                            "Source Instance: 0x%x",tvb_get_ntohl(tvb, offset+4));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+8, 4,
                            "Destination Instance: 0x%x",tvb_get_ntohl(tvb, offset+8));
        proto_item_append_text(ti, ": %s. Src Instance: 0x%0x. Dest Instance: 0x%0x. ",
                               type==1 ? "REQUEST" : "ACK",
                               tvb_get_ntohl(tvb, offset+4),
                               tvb_get_ntohl(tvb, offset+8));
        break;
    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-Type: %d - UNKNOWN", type);
        break;
    };
}

/*------------------------------------------------------------------------------
 * DCLASS
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_dclass(proto_tree *ti, proto_tree *rsvp_object_tree,
                    tvbuff_t *tvb,
                    int offset, int obj_length,
                    int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    int mylen;

    proto_item_set_text(ti, "DCLASS: ");
    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1");
        for (mylen = 4; mylen < obj_length; mylen += 4) {
            proto_tree_add_text(rsvp_object_tree, tvb, offset+mylen+3, 1,
                                "DSCP: %s",
                                val_to_str_ext(tvb_get_guint8(tvb, offset+mylen+3),
                                               &dscp_vals_ext, "Unknown (%d)"));
            proto_item_append_text(ti, "%d%s",
                                   tvb_get_guint8(tvb, offset+mylen+3)>>2,
                                   mylen==obj_length-4 ? "":
                                   mylen<16 ? ", ":
                                   mylen==16 ? ", ..." : "");
        }
        break;

    default:
        mylen = obj_length - 4;
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
                            "Data (%d bytes)", mylen);
        break;
    }
}

/*------------------------------------------------------------------------------
 * ADMINISTRATIVE STATUS
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_admin_status(proto_tree *ti, proto_tree *rsvp_object_tree,
                          tvbuff_t *tvb,
                          int offset, int obj_length,
                          int rsvp_class _U_, int type)
{
    int         offset2 = offset + 4;
    proto_tree *ti2, *rsvp_admin_subtree;
    guint32     status;

    proto_item_set_text(ti, "ADMIN STATUS: ");
    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1");
        status = tvb_get_ntohl(tvb, offset2);
        ti2 = proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4,
                                  "Admin Status: 0x%08x", status);
        rsvp_admin_subtree =
            proto_item_add_subtree(ti2, TREE(TT_ADMIN_STATUS_FLAGS));

        proto_tree_add_boolean(rsvp_admin_subtree,
                               hf_rsvp_filter[RSVPF_ADMIN_STATUS_REFLECT],
                               tvb, offset2, 4, status);
        proto_tree_add_boolean(rsvp_admin_subtree,
                               hf_rsvp_filter[RSVPF_ADMIN_STATUS_HANDOVER],
                               tvb, offset2, 4, status);
        proto_tree_add_boolean(rsvp_admin_subtree,
                               hf_rsvp_filter[RSVPF_ADMIN_STATUS_LOCKOUT],
                               tvb, offset2, 4, status);
        proto_tree_add_boolean(rsvp_admin_subtree,
                               hf_rsvp_filter[RSVPF_ADMIN_STATUS_INHIBIT],
                               tvb, offset2, 4, status);
        proto_tree_add_boolean(rsvp_admin_subtree,
                               hf_rsvp_filter[RSVPF_ADMIN_STATUS_CALL_MGMT],
                               tvb, offset2, 4, status);
        proto_tree_add_boolean(rsvp_admin_subtree,
                               hf_rsvp_filter[RSVPF_ADMIN_STATUS_TESTING],
                               tvb, offset2, 4, status);
        proto_tree_add_boolean(rsvp_admin_subtree,
                               hf_rsvp_filter[RSVPF_ADMIN_STATUS_DOWN],
                               tvb, offset2, 4, status);
        proto_tree_add_boolean(rsvp_admin_subtree,
                               hf_rsvp_filter[RSVPF_ADMIN_STATUS_DELETE],
                               tvb, offset2, 4, status);
        proto_item_set_text(ti, "ADMIN-STATUS: %s%s%s%s%s%s%s%s",
                            (status & (1<<31)) ? "Reflect " : "",
                            (status & (1<<6)) ? "Handover " : "",
                            (status & (1<<5)) ? "Lockout " : "",
                            (status & (1<<4)) ? "Inhibit " : "",
                            (status & (1<<3)) ? "Call " : "",
                            (status & (1<<2)) ? "Testing " : "",
                            (status & (1<<1)) ? "Admin-Down " : "",
                            (status & (1<<0)) ? "Deleting " : "");
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * LSP ATTRIBUTES
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_lsp_attributes(proto_tree *ti, proto_tree *rsvp_object_tree,
                            tvbuff_t *tvb, int offset, int obj_length,
                            int rsvp_class _U_, int type)
{
    int         tlv_off;
    guint32     attributes;
    guint16     tlv_type, tlv_len;
    proto_tree *ti2, *rsvp_lsp_attr_subtree;

    if (rsvp_class == RSVP_CLASS_LSP_REQUIRED_ATTRIBUTES)
        proto_item_set_text(ti, "LSP REQUIRED ATTRIBUTES: ");
    else
        proto_item_set_text(ti, "LSP ATTRIBUTES: ");

    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1");
        for (tlv_off = 4; tlv_off < obj_length-4; ) {
            tlv_type = tvb_get_ntohs(tvb, offset+tlv_off);
            tlv_len = tvb_get_ntohs(tvb, offset+tlv_off+2);

            if ((tlv_len == 0) || (tlv_off+tlv_len > (obj_length-4))) {
                proto_tree_add_text(rsvp_object_tree, tvb, offset+tlv_off+2, 2,
                                    "Invalid length");
                return;
            }
            switch(tlv_type) {
            case 1:
                attributes = tvb_get_ntohl(tvb, offset+tlv_off+4);
                ti2 = proto_tree_add_text(rsvp_object_tree, tvb, offset+tlv_off, tlv_len,
                                          "LSP attributes TLV: 0x%08x", attributes);
                rsvp_lsp_attr_subtree = proto_item_add_subtree(ti2, TREE(TT_LSP_ATTRIBUTES_FLAGS));
                proto_tree_add_item(rsvp_lsp_attr_subtree, hf_rsvp_lsp_attr_e2e,
                             tvb, offset+tlv_off+4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_lsp_attr_subtree, hf_rsvp_lsp_attr_boundary,
                             tvb, offset+tlv_off+4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_lsp_attr_subtree, hf_rsvp_lsp_attr_segment,
                             tvb, offset+tlv_off+4, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(ti, "LSP Attribute:%s%s%s",
                                       (attributes & 0x01) ? " End-to-end re-routing" : "",
                                       (attributes & 0x02) ? " Boundary re-routing" : "",
                                       (attributes & 0x04) ? " Segment-based re-routing" : "");
                break;

            default:
                proto_tree_add_text(rsvp_object_tree, tvb, offset+tlv_off, tlv_len,
                                    "Unknown TLV");
                break;
            }
            tlv_off += tlv_len;
        }
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * ASSOCIATION
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_association(proto_tree *ti, proto_tree *rsvp_object_tree,
                         tvbuff_t *tvb,
                         int offset, int obj_length,
                         int rsvp_class _U_, int type)
{
    guint16 association_type;
    guint16 association_id;

    static const value_string association_type_vals[] = {
        { 0, "Reserved"},
        { 1, "Recovery"},
        { 2, "Resource Sharing"},
        { 3, "Segment Recovery"},
        { 4, "Inter-domain Recovery"},
        { 0, NULL}
    };
    static value_string_ext association_type_vals_ext = VALUE_STRING_EXT_INIT(association_type_vals);

    proto_item_set_text(ti, "ASSOCIATION ");
    association_type = tvb_get_ntohs (tvb, offset + 4);
    association_id = tvb_get_ntohs (tvb, offset + 6);
    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1 (IPv4)");
        proto_item_append_text(ti, "(IPv4): ");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, 2,
                            "Association type: %s",
                            val_to_str_ext(association_type, &association_type_vals_ext, "Unknown (%u)"));
        proto_item_append_text(ti, "%s. ",
                               val_to_str_ext(association_type, &association_type_vals_ext, "Unknown (%u)"));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+6, 2,
                            "Association ID: %u", association_id);
        proto_item_append_text(ti, "ID: %u. ", association_id);
        proto_tree_add_text(rsvp_object_tree, tvb, offset+8, 4,
                            "Association source: %s", tvb_ip_to_str(tvb, offset+8));
        proto_item_append_text(ti, "Src: %s", tvb_ip_to_str(tvb, offset+8));
        break;

    case 2:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 2 (IPv6)");
        proto_item_append_text(ti, "(IPv6): ");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, 2,
                            "Association type: %s",
                            val_to_str_ext(association_type, &association_type_vals_ext, "Unknown (%u)"));
        proto_item_append_text(ti, "%s. ",
                               val_to_str_ext(association_type, &association_type_vals_ext, "Unknown (%u)"));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+6, 2,
                            "Association ID: %u", association_id);
        proto_item_append_text(ti, "ID: %u. ", association_id);
        proto_tree_add_text(rsvp_object_tree, tvb, offset+8, 16,
                            "Association source: %s", tvb_ip6_to_str(tvb, offset+8));
        proto_item_append_text(ti, "Src: %s", tvb_ip6_to_str(tvb, offset+8));
        break;

    case 4:       /* oif2008.389 */
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 4 (Routing Area)");
        proto_item_append_text(ti, "(Routing Area): ");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, 2,
                            "Association type: %s",
                            val_to_str_ext(association_type, &association_type_vals_ext, "Unknown (%u)"));
        proto_item_append_text(ti, "%s. ",
                               val_to_str_ext(association_type, &association_type_vals_ext, "Unknown (%u)"));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+6, 2,
                            "Association ID: %u", association_id);
        proto_item_append_text(ti, "Association ID: %u, ", association_id);
        proto_tree_add_text(rsvp_object_tree, tvb, offset+8, 4,
                            "Routing Area ID: %u", tvb_get_ntohl (tvb, offset+8));
        proto_item_append_text(ti, "Routing Area ID: %u, ", tvb_get_ntohl (tvb, offset+8));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+12, 4,
                            "Node ID: %s", tvb_ip_to_str(tvb, offset+12));
        proto_item_append_text(ti, "Node ID: %s", tvb_ip_to_str(tvb, offset+12));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+8, 16,
                            "Padding: %s", tvb_bytes_to_str_punct(tvb, offset+16, 8, ' '));
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)", type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}
/*------------------------------------------------------------------------------
 * TLVs for LSP TUNNEL IF ID object
 * draft-ietf-ccamp-lsp-hierarchy-bis-02
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_lsp_tunnel_if_id_tlv(proto_tree *rsvp_object_tree,
                                  tvbuff_t *tvb, int offset, int tlv_length,
                                  int subtree_type)
{
    int       tlv_off;
    guint16   tlv_type;
    int       tlv_len;
    proto_tree *ti, *rsvp_lsp_tunnel_if_id_subtree;

    for (tlv_off = 0; tlv_off < tlv_length; ) {
        tlv_type = tvb_get_ntohs(tvb, offset+tlv_off);
        tlv_len = tvb_get_ntohs(tvb, offset+tlv_off+2);

        if ((tlv_len == 0) || ((tlv_off+tlv_len) > tlv_length)) {
            proto_tree_add_text(rsvp_object_tree, tvb, offset+tlv_off+2, 2,
                                "Invalid length");
            return;
        }
        switch(tlv_type) {
        case 1:
            ti = proto_tree_add_text(rsvp_object_tree, tvb,
                                     offset+tlv_off, tlv_len,
                                     "Unnumbered component link identifier: %u",
                                     tvb_get_ntohl(tvb, offset+tlv_off+4));
            rsvp_lsp_tunnel_if_id_subtree = proto_item_add_subtree(ti, subtree_type);
            proto_tree_add_text(rsvp_lsp_tunnel_if_id_subtree, tvb, offset+tlv_off, 2,
                                "Type: 1 (Unnumbered component link identifier)");
            proto_tree_add_text(rsvp_lsp_tunnel_if_id_subtree, tvb, offset+tlv_off+2, 2,
                                "Length: %u", tlv_len);
            proto_tree_add_text(rsvp_lsp_tunnel_if_id_subtree, tvb, offset+tlv_off+4, 4,
                                "Component link identifier: %u",
                                tvb_get_ntohl(tvb, offset+tlv_off+4));
            break;

        case 2:
            ti = proto_tree_add_text(rsvp_object_tree, tvb,
                                     offset+tlv_off, tlv_len,
                                     "IPv4 component link identifier: %s",
                                     tvb_ip_to_str(tvb, offset+tlv_off+4));
            rsvp_lsp_tunnel_if_id_subtree = proto_item_add_subtree(ti, subtree_type);
            proto_tree_add_text(rsvp_lsp_tunnel_if_id_subtree, tvb, offset+tlv_off, 2,
                                "Type: 2 (IPv4 component link identifier)");
            proto_tree_add_text(rsvp_lsp_tunnel_if_id_subtree, tvb, offset+tlv_off+2, 2,
                                "Length: %u", tlv_len);
            proto_tree_add_text(rsvp_lsp_tunnel_if_id_subtree, tvb, offset+tlv_off+4, 4,
                                "Component link identifier: %s",
                                tvb_ip_to_str(tvb, offset+tlv_off+4));
            break;

        case 32769:  /* oif-p0040.002.09 demo spec */
            ti = proto_tree_add_text(rsvp_object_tree, tvb,
                                     offset+tlv_off, tlv_len,
                                     "Targeted client layer: ");
            rsvp_lsp_tunnel_if_id_subtree = proto_item_add_subtree(ti, subtree_type);
            proto_tree_add_text(rsvp_lsp_tunnel_if_id_subtree, tvb, offset+tlv_off, 2,
                                "Type: 32769 (Targeted client layer)");
            proto_tree_add_text(rsvp_lsp_tunnel_if_id_subtree, tvb, offset+tlv_off+2, 2,
                                "Length: %u", tlv_len);
            proto_tree_add_text(rsvp_lsp_tunnel_if_id_subtree, tvb, offset+tlv_off+4, 1,
                                "LSP Encoding Type: %s",
                                rval_to_str(tvb_get_guint8(tvb,offset+tlv_off+4),
                                           gmpls_lsp_enc_rvals, "Unknown (%d)"));
            proto_tree_add_text(rsvp_lsp_tunnel_if_id_subtree, tvb, offset+tlv_off+5, 1,
                                "Switching Type: %s",
                                rval_to_str(tvb_get_guint8(tvb,offset+tlv_off+5),
                                           gmpls_switching_type_rvals, "Unknown (%d)"));
            proto_tree_add_text(rsvp_lsp_tunnel_if_id_subtree, tvb, offset+tlv_off+6, 1,
                                "Signal Type: %s",
                                val_to_str_ext(tvb_get_guint8(tvb,offset+tlv_off+6),
                                               &gmpls_sonet_signal_type_str_ext, "Unknown (%d)"));
            proto_tree_add_text(rsvp_lsp_tunnel_if_id_subtree, tvb, offset+tlv_off+8, 8,
                                "Sub Interface/Connection ID: %" G_GINT64_MODIFIER "u (0x%s)",
                                tvb_get_ntoh64(tvb, offset+tlv_off+8),
                                tvb_bytes_to_str(tvb, offset+tlv_off+8, 8));
            proto_tree_add_text(rsvp_lsp_tunnel_if_id_subtree, tvb, offset+tlv_off+16, 4,
                                "SC PC ID: %s",
                                tvb_ip_to_str(tvb, offset+tlv_off+16));
            proto_tree_add_text(rsvp_lsp_tunnel_if_id_subtree, tvb, offset+tlv_off+20, 4,
                                "SC PC SCN Address: %s",
                                tvb_ip_to_str(tvb, offset+tlv_off+20));
            proto_item_append_text(ti, "LSP Encoding=%s, Switching Type=%s, Signal Type=%s",
                                   rval_to_str(tvb_get_guint8(tvb,offset+tlv_off+4),
                                              gmpls_lsp_enc_rvals, "Unknown (%d)"),
                                   rval_to_str(tvb_get_guint8(tvb,offset+tlv_off+5),
                                              gmpls_switching_type_rvals, "Unknown (%d)"),
                                   val_to_str_ext(tvb_get_guint8(tvb,offset+tlv_off+6),
                                                  &gmpls_sonet_signal_type_str_ext, "Unknown (%d)"));
            break;

        default:
            proto_tree_add_text(rsvp_object_tree, tvb, offset+tlv_off, 2,
                                "Unknown TLV: %u", tlv_type);
            break;
        }
        tlv_off += tlv_len;
    }
}

/*------------------------------------------------------------------------------
 * LSP TUNNEL INTERFACE ID
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_lsp_tunnel_if_id(proto_tree *ti, proto_tree *rsvp_object_tree,
                              tvbuff_t *tvb,
                              int offset, int obj_length,
                              int rsvp_class _U_, int type)
{
    guint8  action;

    static const value_string lsp_tunnel_if_id_action_str[] = {
        { 0, "LSP is FA (MPLS-TE topology advertisement only)"},
        { 1, "LSP is RA (IP network advertisement only)"},
        { 2, "LSP is RA (both IP and MPLS-TE topology advertisement)"},
        { 3, "LSP is to be used as a virtual local link"},
        { 0, NULL}
    };

    proto_item_set_text(ti, "LSP INTERFACE-ID: ");
    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1 - Unnumbered interface");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, 4,
                            "Router ID: %s",
                            tvb_ip_to_str(tvb, offset+4));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+8, 4,
                            "Interface ID: %u", tvb_get_ntohl(tvb, offset+8));
        proto_item_set_text(ti, "LSP INTERFACE-ID: Unnumbered, Router-ID %s, Interface-ID %d",
                            tvb_ip_to_str(tvb, offset+4),
                            tvb_get_ntohl(tvb, offset+8));
        break;

    case 2:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 2 - IPv4");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, 4,
                            "IPv4 interface address: %s",
                            tvb_ip_to_str(tvb, offset+4));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+8, 4,
                            "Target IGP instance: %s",
                            tvb_ip_to_str(tvb, offset+8));
        proto_item_set_text(ti, "LSP INTERFACE-ID: IPv4, interface address %s,"
                            "IGP instance %s",
                            tvb_ip_to_str(tvb, offset+4),
                            tvb_ip_to_str(tvb, offset+8));
        action = tvb_get_guint8(tvb, offset+12);
        action >>= 4;
        proto_tree_add_text(rsvp_object_tree, tvb, offset+12, 1, "Action: %d - %s",
                            action,
                            val_to_str_const(action, lsp_tunnel_if_id_action_str, "Unknown"));
        dissect_rsvp_lsp_tunnel_if_id_tlv(rsvp_object_tree, tvb, offset+16, obj_length-16,
                                          TREE(TT_LSP_TUNNEL_IF_ID_SUBTREE));
        break;

    case 3:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 3 - IPv6");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, 16,
                            "IPv6 interface address: %s",
                            tvb_ip6_to_str(tvb, offset+4));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+20, 4,
                            "Target IGP instance: %s",
                            tvb_ip_to_str(tvb, offset+20));
        proto_item_set_text(ti, "LSP INTERFACE-ID: IPv6, interface address %s,"
                            "IGP instance %s",
                            tvb_ip6_to_str(tvb, offset+4),
                            tvb_ip_to_str(tvb, offset+20));
        action = tvb_get_guint8(tvb, offset+24);
        action >>= 4;
        proto_tree_add_text(rsvp_object_tree, tvb, offset+24, 1, "Action: %d - %s",
                            action,
                            val_to_str_const(action, lsp_tunnel_if_id_action_str, "Unknown"));
        dissect_rsvp_lsp_tunnel_if_id_tlv(rsvp_object_tree, tvb, offset+28, obj_length-28,
                                          TREE(TT_LSP_TUNNEL_IF_ID_SUBTREE));
        break;

    case 4:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 4 - Unnumbered interface with target");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, 4,
                            "Router ID: %s",
                            tvb_ip_to_str(tvb, offset+4));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+8, 4,
                            "Interface ID: %u", tvb_get_ntohl(tvb, offset+8));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+12, 4,
                            "Target IGP instance: %s",
                            tvb_ip_to_str(tvb, offset+12));
        proto_item_set_text(ti, "LSP INTERFACE-ID: Unnumbered with target, Router-ID %s,"
                            " Interface-ID %d, IGP instance %s",
                            tvb_ip_to_str(tvb, offset+4),
                            tvb_get_ntohl(tvb, offset+8),
                            tvb_ip_to_str(tvb, offset+12));
        action = tvb_get_guint8(tvb, offset+16);
        action >>= 4;
        proto_tree_add_text(rsvp_object_tree, tvb, offset+16, 1, "Action: %d - %s",
                            action,
                            val_to_str_const(action, lsp_tunnel_if_id_action_str, "Unknown"));
        dissect_rsvp_lsp_tunnel_if_id_tlv(rsvp_object_tree, tvb, offset+20, obj_length-20,
                                          TREE(TT_LSP_TUNNEL_IF_ID_SUBTREE));
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, obj_length-4,
                            "Data (%d bytes)", obj_length-4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * NOTIFY REQUEST
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_notify_request(proto_item *ti, proto_tree *rsvp_object_tree,
                            tvbuff_t *tvb,
                            int offset, int obj_length,
                            int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;

    switch(type) {
    case 1: {
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1 - IPv4");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4,
                            "Notify node address: %s",
                            tvb_ip_to_str(tvb, offset2));
        proto_item_append_text(ti, ": Notify node: %s",
                            tvb_ip_to_str(tvb, offset2));
        break;
    }

    case 2: {
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 2 - IPv6");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 16,
                            "Notify node address: %s",
                            tvb_ip6_to_str(tvb, offset2));
        proto_item_append_text(ti, ": Notify node: %s",
                               tvb_ip6_to_str(tvb, offset2));
        break;
    }

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * GENERALIZED UNI
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_gen_uni(proto_tree *ti, proto_tree *rsvp_object_tree,
                     tvbuff_t *tvb,
                     int offset, int obj_length,
                     int rsvp_class _U_, int type,
                     rsvp_conversation_info *rsvph)
{
    int         offset2 = offset + 4;
    int         mylen, i, j, k, l, m;
    proto_item *ti2;
    proto_tree *rsvp_gen_uni_subtree, *rsvp_session_subtree, *rsvp_template_subtree;
    int         s_len, s_class, s_type, sobj_len, nsap_len;
    int         offset3;

    proto_item_set_text(ti, "GENERALIZED UNI: ");

    mylen = obj_length - 4;
    switch(type) {
    case 1: {
        const char *c;
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1");
        for (i=1, l = 0; l < mylen; i++) {
            sobj_len = tvb_get_ntohs(tvb, offset2+l);
            j = tvb_get_guint8(tvb, offset2+l+2);
            switch(j) {
            case 1:
            case 2: /* We do source and destination TNA together */
                c = (j==1) ? "Source" : "Destination";
                k = tvb_get_guint8(tvb, offset2+l+3);
                switch(k) {
                case 1:
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2+l, 8,
                                              "%s IPv4 TNA: %s", c,
                                              tvb_ip_to_str(tvb, offset2+l+4));
                    rsvp_gen_uni_subtree =
                        proto_item_add_subtree(ti2, TREE(TT_GEN_UNI_SUBOBJ));
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+2, 1,
                                        "Class: %d (%s)", j, c);
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+3, 1,
                                        "Type: 1 (IPv4)");
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l, 2,
                                        "Length: %u", sobj_len);
                    if (j==1)
                      proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_filter[RSVPF_GUNI_SRC_IPV4],
                                          tvb, offset2+l+4, 4, ENC_BIG_ENDIAN);
                    else
                      proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_filter[RSVPF_GUNI_DST_IPV4],
                                          tvb, offset2+l+4, 4, ENC_BIG_ENDIAN);
                    if (i < 4) {
                        proto_item_append_text(ti, "%s IPv4 TNA: %s", c,
                                               tvb_ip_to_str(tvb, offset2+l+4));
                    }
                    break;

                case 2:
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2+l, 20,
                                              "%s IPv6 TNA:", c);
                    rsvp_gen_uni_subtree =
                        proto_item_add_subtree(ti2, TREE(TT_GEN_UNI_SUBOBJ));
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+2, 1,
                                        "Class: %d (%s)", j, c);
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+3, 1,
                                        "Type: 2 (IPv6)");
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l, 2,
                                        "Length: %u", sobj_len);
                    if (j==1)
                      proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_filter[RSVPF_GUNI_SRC_IPV6],
                                          tvb, offset2+l+4, 16, ENC_NA);
                    else
                      proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_filter[RSVPF_GUNI_DST_IPV6],
                                          tvb, offset2+l+4, 16, ENC_NA);
                    if (i < 4) {
                        proto_item_append_text(ti, "%s IPv6 TNA: %s", c,
                                               tvb_ip6_to_str(tvb, offset2+l+4));
                    }
                    break;

                case 3:
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2+l, tvb_get_ntohs(tvb, offset2+l),
                                              "%s NSAP TNA: ", c);
                    rsvp_gen_uni_subtree =
                        proto_item_add_subtree(ti2, TREE(TT_GEN_UNI_SUBOBJ));
                    nsap_len = tvb_get_guint8(tvb, offset2+l+4);
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+2, 1,
                                        "Class: %d (%s)", j, c);
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+3, 1,
                                        "Type: 3 (NSAP)");
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l, 2,
                                        "Length: %u", sobj_len);
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+4, 1,
                                        "NSAP Length: %u", nsap_len);
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+5,
                                        sobj_len-4,
                                        "NSAP address: %s",
                                        print_nsap_net(tvb_get_ptr(tvb, offset2+l+5, nsap_len), nsap_len));
                    if (i < 4) {
                        proto_item_append_text(ti, "%s NSAP TNA: %s", c,
                                               print_nsap_net(tvb_get_ptr(tvb, offset2+l+5, nsap_len), nsap_len));
                    }
                    break;

                default:
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2+l, tvb_get_ntohs(tvb, offset2+l),
                                              "%s UNKNOWN TNA", c);
                    rsvp_gen_uni_subtree =
                        proto_item_add_subtree(ti2, TREE(TT_GEN_UNI_SUBOBJ));
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+2, 1,
                                        "Class: %d (%s)", j, c);
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+3, 1,
                                        "Type: %d (UNKNOWN)", j);
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l, 2,
                                        "Length: %u", sobj_len);
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+4,
                                        sobj_len-4,
                                        "Data");
                    if (i < 4) {
                        proto_item_append_text(ti, "%s UNKNOWN", c);
                    }
                    break;
                }
                break;

            case 3: /* Diversity subobject */
                k = tvb_get_guint8(tvb, offset2+l+3);
                switch(k) {
                default:
                case 1:
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2+l, tvb_get_ntohs(tvb, offset2+l),
                                              "Diversity Subobject");
                    rsvp_gen_uni_subtree =
                        proto_item_add_subtree(ti2, TREE(TT_GEN_UNI_SUBOBJ));
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+2, 1,
                                        "Class: %d (Diversity)", j);
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+3, 1,
                                        "Type: %d", tvb_get_guint8(tvb, offset2+l+3));
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l, 2,
                                        "Length: %u", sobj_len);
                    m = tvb_get_guint8(tvb, offset2+l+4) >> 4;
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+4, 1,
                                        "Diversity: %d - %s", m,
                                        val_to_str_const(m, ouni_guni_diversity_str, "Unknown"));
                    s_len = tvb_get_ntohs(tvb, offset2+l+8);
                    s_class = tvb_get_guint8(tvb, offset2+l+10);
                    s_type = tvb_get_guint8(tvb, offset2+l+11);
                    ti2 = proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+8,
                                              s_len, "Session");
                    rsvp_session_subtree =
                        proto_item_add_subtree(ti2, TREE(rsvp_class_to_tree_type(s_class)));
                    if (s_len < 4) {
                        proto_tree_add_text(rsvp_object_tree, tvb, offset2+l+8, 2,
                            "Length: %u (bogus, must be >= 4)", s_len);
                        break;
                    }
                    proto_tree_add_text(rsvp_session_subtree, tvb, offset2+l+8, 2,
                                "Length: %u", s_len);
                    proto_tree_add_uint(rsvp_session_subtree, hf_rsvp_filter[RSVPF_OBJECT], tvb,
                                offset2+8+l+10, 1, s_class);
                    dissect_rsvp_session(ti2, rsvp_session_subtree, tvb, offset2+l+8,
                                         s_len, s_class, s_type, rsvph);
                    offset3 = offset2 + s_len;
                    s_len = tvb_get_ntohs(tvb, offset3+l+8);
                    s_class = tvb_get_guint8(tvb, offset3+l+10);
                    s_type = tvb_get_guint8(tvb, offset3+l+11);
                    ti2 = proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset3+l+8,
                                              s_len, "Template");
                    rsvp_template_subtree =
                        proto_item_add_subtree(ti2, TREE(rsvp_class_to_tree_type(s_class)));
                    if (s_len < 4) {
                        proto_tree_add_text(rsvp_object_tree, tvb, offset3+l+8, 2,
                            "Length: %u (bogus, must be >= 4)", s_len);
                        break;
                    }
                    proto_tree_add_text(rsvp_template_subtree, tvb, offset3+l+8, 2,
                                "Length: %u", s_len);
                    proto_tree_add_uint(rsvp_template_subtree, hf_rsvp_filter[RSVPF_OBJECT], tvb,
                                offset3+8+l+10, 1, s_class);
                    dissect_rsvp_template_filter(ti2, rsvp_template_subtree, tvb, offset3+l+8,
                                                 s_len, s_class, s_type, rsvph);

                    if (i < 4) {
                        proto_item_append_text(ti, "Diversity");
                    }
                    break;

                }
                break;

            case 4: /* Egress Label */
                k = tvb_get_guint8(tvb, offset2+l+3);
                if (k == 1)             /* Egress label sub-type */
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2+l, sobj_len,
                                              "Egress Label Subobject");
                else if (k == 2)        /* SPC_label sub-type (see G.7713.2) */
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2+l, sobj_len,
                                              "SPC Label Subobject");
                else
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2+l, sobj_len,
                                              "Unknown Label Subobject");
                rsvp_gen_uni_subtree = proto_item_add_subtree(ti2, TREE(TT_GEN_UNI_SUBOBJ));
                proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+2, 1,
                                    "Class: %d (Egress/SPC Label)", j);
                proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+3, 1,
                                    "Type: %d", k);
                proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l, 2,
                                    "Length: %u", sobj_len);
                proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_gen_uni_direction,
                             tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+7, 1,
                                    "Label type: %u", tvb_get_guint8(tvb, offset2+l+7));
                proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+8, 4,
                                    "Logical Port ID: %u", tvb_get_ntohl(tvb, offset2+l+8));
                proto_item_append_text(ti2, ": %s, Label type %d, Port ID %d, Label ",
                                       tvb_get_guint8(tvb, offset2+l+4) & 0x80 ?
                                       "Upstream" : "Downstream",
                                       tvb_get_guint8(tvb, offset2+l+7),
                                       tvb_get_ntohl(tvb, offset2+l+8));
                for (j=12; j < sobj_len; j+=4) {
                        proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+j, 4,
                                            "Label: %u", tvb_get_ntohl(tvb, offset2+l+j));
                        proto_item_append_text(ti2, "%u ", tvb_get_ntohl(tvb, offset2+l+j));
                }
                if (i < 4) {
                        if (k == 1)
                            proto_item_append_text(ti, "Egress Label");
                        else if (k == 2)
                            proto_item_append_text(ti, "SPC Label");
                }
                break;

            case 5: /* Service Level */
                k = tvb_get_guint8(tvb, offset2+l+3);
                switch(k) {
                default:
                case 1:
                    ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                              offset2+l, sobj_len,
                                              "Service Level Subobject");
                    rsvp_gen_uni_subtree =
                        proto_item_add_subtree(ti2, TREE(TT_GEN_UNI_SUBOBJ));
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+2, 1,
                                        "Class: %d (Service Level)", j);
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+3, 1,
                                        "Type: %d", tvb_get_guint8(tvb, offset2+l+3));
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l, 2,
                                        "Length: %u", sobj_len);
                    proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+4, 1,
                                        "Service Level: %u", tvb_get_guint8(tvb, offset2+l+4));
                    proto_item_append_text(ti2, ": %u", tvb_get_guint8(tvb, offset2+l+4));
                    if (i < 4) {
                        proto_item_append_text(ti, "Service Level %d", tvb_get_guint8(tvb, offset2+l+4));
                    }
                    break;
                }
                break;

            default: /* Unknown subobject */
                ti2 = proto_tree_add_text(rsvp_object_tree, tvb,
                                          offset2+l, sobj_len,
                                          "Unknown subobject: %u",
                                          j);
                rsvp_gen_uni_subtree =
                    proto_item_add_subtree(ti2, TREE(TT_GEN_UNI_SUBOBJ));
                proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l, 1,
                                    "Type: %u (Unknown)", j);
                proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+1, 1,
                                    "Length: %u",
                                    tvb_get_guint8(tvb, offset2+l+1));
                break;
            }

            if (tvb_get_guint8(tvb, offset2+l+1) < 1) {
                proto_tree_add_text(rsvp_gen_uni_subtree, tvb, offset2+l+1, 1,
                    "Invalid length: %u", tvb_get_guint8(tvb, offset2+l+1));
                return;
            }
            l += tvb_get_guint8(tvb, offset2+l+1);
            if (l < mylen) {
                if (i < 4)
                    proto_item_append_text(ti, ", ");
                else if (i==4)
                    proto_item_append_text(ti, "...");
            }
        }
        break;
    }

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, mylen,
                            "Data (%d bytes)", mylen);
        break;
    }
}

/*------------------------------------------------------------------------------
 * CALL_ID
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_call_id(proto_tree *ti, proto_tree *rsvp_object_tree,
                     tvbuff_t *tvb,
                     int offset, int obj_length,
                     int rsvp_class _U_, int c_type)
{
    int         type    = 0;
    const char *str;
    int         offset2 = offset + 4;
    int         offset3, offset4, len;

    static const value_string address_type_vals[] = {
        { 1, "1 (IPv4)"},
        { 2, "2 (IPv6)"},
        { 3, "3 (NSAP)"},
        { 4, "4 (MAC)"},
        { 0x7f, "0x7f (Vendor-defined)"},
        { 0, NULL}
    };
    static value_string_ext address_type_vals_ext = VALUE_STRING_EXT_INIT(address_type_vals);

    proto_item_set_text(ti, "CALL-ID: ");
    switch(c_type) {
    case 0:
        proto_item_append_text(ti,"Empty");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Empty (%u)", c_type);
        if (obj_length > 4)
          proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length-4,
                              "Data (%d bytes)", obj_length-4);
        break;
    case 1:
    case 2:
        type = tvb_get_guint8 (tvb, offset2);
        if (c_type == 1) {
            offset3 = offset2 + 4;
            len = obj_length - 16;
            proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                                "C-type: 1 (operator specific)");
            proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1, "Address type: %s",
                                val_to_str_ext(type, &address_type_vals_ext, "Unknown (%u)"));
            proto_tree_add_text(rsvp_object_tree, tvb, offset2+1, 3, "Reserved: %u",
                                tvb_get_ntoh24(tvb, offset2+1));
            proto_item_append_text(ti, "Operator-Specific. Addr Type: %s. ",
                                   val_to_str_ext(type, &address_type_vals_ext, "Unknown (%u)"));
        }
        else {
            offset3 = offset2 + 16;
            len = obj_length - 28;
            proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                                "C-type: 2 (globally unique)");
            proto_tree_add_text(rsvp_object_tree, tvb, offset2, 1, "Address type: %s",
                                val_to_str_ext(type, &address_type_vals_ext, "Unknown (%u)"));
            str = tvb_get_ephemeral_string (tvb, offset2 + 1, 3);
            proto_tree_add_text(rsvp_object_tree, tvb, offset2 + 1, 3,
                                "International Segment: %s", str);
            proto_item_append_text(ti, "Globally-Unique. Addr Type: %s. Intl Segment: %s. ",
                                   val_to_str_ext(type, &address_type_vals_ext, "Unknown (%u)"), str);
            str = tvb_get_ephemeral_string (tvb, offset2 + 4, 12);
            proto_tree_add_text(rsvp_object_tree, tvb, offset2 + 4, 12,
                                "National Segment: %s", str);
            proto_item_append_text(ti, "Natl Segment: %s. ", str);
        }

        switch(type) {
        case 1:
            offset4 = offset3 + 4;
            str = tvb_ip_to_str(tvb, offset3);
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_filter[RSVPF_CALL_ID_SRC_ADDR_IPV4],
                                tvb, offset3, 4, ENC_BIG_ENDIAN);
            break;

        case 2:
            offset4 = offset3 + 16;
            str = tvb_ip6_to_str(tvb, offset3);
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_filter[RSVPF_CALL_ID_SRC_ADDR_IPV6],
                                tvb, offset3, 16, ENC_NA);
            break;

        case 3:
            offset4 = offset3 + 20;
            str = print_nsap_net(tvb_get_ptr(tvb, offset3, 20), 20);
            proto_tree_add_text(rsvp_object_tree, tvb, offset3, 20,
                                "Source Transport Network addr: %s", str);
            break;

        case 4:
            offset4 = offset3 + 6;
            str = tvb_ether_to_str(tvb, offset3);
            proto_tree_add_text(rsvp_object_tree, tvb, offset3, 6,
                                "Source Transport Network addr: %s", str);
            break;

        case 0x7F:
            offset4 = offset3 + len;
            str = tvb_bytes_to_str(tvb, offset3, len);
            proto_tree_add_text(rsvp_object_tree, tvb, offset3, len,
                                "Source Transport Network addr: %s", str);
            break;

        default:
            offset4 = offset3 + len;
            str = "???";
            proto_tree_add_text(rsvp_object_tree, tvb, offset3, len, "Unknown Transport Network type: %d",
                                type);
            break;
        }

        proto_item_append_text(ti, "Src: %s. ", str);
        proto_tree_add_text(rsvp_object_tree, tvb, offset4, 8, "Local Identifier: %s",
                            tvb_bytes_to_str(tvb, offset4, 8));
        proto_item_append_text(ti, "Local ID: %s. ", tvb_bytes_to_str(tvb, offset4, 8));
        break;

    default:
        proto_item_append_text(ti, " Unknown");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)", c_type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length-4,
                            "Data (%d bytes)", obj_length-4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * RESTART CAPABILITY
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_restart_cap(proto_tree *ti, proto_tree *rsvp_object_tree,
                         tvbuff_t *tvb,
                         int offset, int obj_length,
                         int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;

    proto_item_set_text(ti, "RESTART CAPABILITY: ");
    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1");
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, 4,
                            "Restart Time: %d ms",
                            tvb_get_ntohl(tvb, offset2));
        proto_tree_add_text(rsvp_object_tree, tvb, offset2+4, 4,
                            "Recovery Time: %d ms",
                            tvb_get_ntohl(tvb, offset2+4));
        proto_item_append_text(ti, "Restart Time: %d ms. Recovery Time: %d ms.",
                            tvb_get_ntohl(tvb, offset2), tvb_get_ntohl(tvb, offset2+4));
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * PROTECTION INFORMATION
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_protection_info(proto_tree *ti, proto_tree *rsvp_object_tree,
                             tvbuff_t *tvb,
                             int offset, int obj_length,
                             int rsvp_class _U_, int type)
{
    guint8      flags1, lsp_flags, link_flags, seg_flags;
    proto_tree *ti2, *ti3, *ti4, *rsvp_pi_link_flags_tree, *rsvp_pi_lsp_flags_tree, *rsvp_pi_seg_flags_tree;
    int         offset2 = offset + 4;

    proto_item_set_text(ti, "PROTECTION_INFO: ");
    switch(type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: 1");
        flags1 = tvb_get_guint8(tvb, offset2);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_protection_info_flags_secondary_lsp,
                             tvb, offset2, 1, ENC_BIG_ENDIAN);

        link_flags = tvb_get_guint8(tvb, offset2+3);
        ti2 = proto_tree_add_text(rsvp_object_tree, tvb, offset2+3, 1,
                                  "Link Flags: 0x%02x", link_flags);
        rsvp_pi_link_flags_tree = proto_item_add_subtree(ti2, TREE(TT_PROTECTION_INFO_LINK));
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_extra_traffic,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_unprotected,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_shared,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_dedicated1_1,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_dedicated1plus1,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_enhanced,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "%s%s%s%s%s%s%s.",
                               flags1&0x80 ? "SecondaryLSP ":"",
                               link_flags&0x01 ? "ExtraTraffic ":"",
                               link_flags&0x02 ? "Unprotected ":"",
                               link_flags&0x04 ? "Shared ":"",
                               link_flags&0x08 ? "Dedicated1:1 ":"",
                               link_flags&0x10 ? "Dedicated1+1 ":"",
                               link_flags&0x20 ? "Enhanced ":"");
        break;

    case 2:       /* RFC4872 */
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type:2");
        flags1 = tvb_get_guint8(tvb, offset2);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_rfc4872_secondary,
                             tvb, offset2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_rfc4872_protecting,
                             tvb, offset2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_rfc4872_notification_msg,
                             tvb, offset2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_rfc4872_operational,
                             tvb, offset2, 1, ENC_BIG_ENDIAN);

        lsp_flags = tvb_get_guint8(tvb, offset2+1);
        ti3 = proto_tree_add_text(rsvp_object_tree, tvb, offset2+1, 1,
                                  "LSP Flags: 0x%02x -%s%s%s%s%s%s", lsp_flags,
                                  lsp_flags == 0 ? " Unprotected":"",
                                  lsp_flags&0x01 ? " Rerouting":"",
                                  lsp_flags&0x02 ? " Rerouting with extra-traffic":"",
                                  lsp_flags&0x04 ? " 1:N Protection with extra-traffic":"",
                                  lsp_flags&0x08 ? " 1+1 Unidirectional protection":"",
                                  lsp_flags&0x10 ? " 1+1 Bidirectional protection":"");
        rsvp_pi_lsp_flags_tree = proto_item_add_subtree(ti3, TREE(TT_PROTECTION_INFO_LSP));
        proto_tree_add_item(rsvp_pi_lsp_flags_tree, hf_rsvp_pi_lsp_flags_full_rerouting,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_lsp_flags_tree, hf_rsvp_pi_lsp_flags_rerouting_extra,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_lsp_flags_tree, hf_rsvp_pi_lsp_flags_1_n_protection,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_lsp_flags_tree, hf_rsvp_pi_lsp_flags_1plus1_unidirectional,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_lsp_flags_tree, hf_rsvp_pi_lsp_flags_1plus1_bidirectional,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);

        link_flags = tvb_get_guint8(tvb, offset2+3);
        ti2 = proto_tree_add_text(rsvp_object_tree, tvb, offset2+3, 1,
                                  "Link Flags: 0x%02x -%s%s%s%s%s%s", link_flags,
                                  link_flags&0x01 ? " ExtraTraffic":"",
                                  link_flags&0x02 ? " Unprotected":"",
                                  link_flags&0x04 ? " Shared":"",
                                  link_flags&0x08 ? " Dedicated1:1":"",
                                  link_flags&0x10 ? " Dedicated1+1":"",
                                  link_flags&0x20 ? " Enhanced":"");
        rsvp_pi_link_flags_tree = proto_item_add_subtree(ti2, TREE(TT_PROTECTION_INFO_LINK));
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_extra,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_unprotected,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_shared,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_dedicated_1_1,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_dedicated_1plus1,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_enhanced,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_protection_info_in_place,
                             tvb, offset2+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_protection_info_required,
                             tvb, offset2+4, 1, ENC_BIG_ENDIAN);

        seg_flags = tvb_get_guint8(tvb, offset2+5);
        ti4 = proto_tree_add_text(rsvp_object_tree, tvb, offset2+5, 1,
                                 "Segment recovery Flags: 0x%02x - %s%s%s%s%s%s", seg_flags,
                                  seg_flags == 0 ? " Unprotected":"",
                                  seg_flags&0x01 ? " Rerouting":"",
                                  seg_flags&0x02 ? " Rerouting with extra-traffic":"",
                                  seg_flags&0x04 ? " 1:N Protection with extra-traffic":"",
                                  seg_flags&0x08 ? " 1+1 Unidirectional protection":"",
                                  seg_flags&0x10 ? " 1+1 Bidirectional protection":"");
        rsvp_pi_seg_flags_tree = proto_item_add_subtree(ti4, TREE(TT_PROTECTION_INFO_SEG));
        proto_tree_add_item(rsvp_pi_seg_flags_tree, hf_rsvp_pi_seg_flags_full_rerouting,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_seg_flags_tree, hf_rsvp_pi_seg_flags_rerouting_extra,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_seg_flags_tree, hf_rsvp_pi_seg_flags_1_n_protection,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_seg_flags_tree, hf_rsvp_pi_seg_flags_1plus1_unidirectional,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_seg_flags_tree, hf_rsvp_pi_seg_flags_1plus1_bidirectional,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);

        proto_item_append_text(ti, "%s%s%s%s Link:%s%s%s%s%s%s, LSP:%s%s%s%s%s%s.",
                               flags1&0x80 ? "SecondaryLSP ":"",
                               flags1&0x40 ? "ProtectingLSP ":"",
                               flags1&0x20 ? "Notification ":"",
                               flags1&0x10 ? "OperationalLSP ":"",
                               link_flags&0x01 ? " ExtraTraffic":"",
                               link_flags&0x02 ? " Unprotected":"",
                               link_flags&0x04 ? " Shared":"",
                               link_flags&0x08 ? " Dedicated1:1":"",
                               link_flags&0x10 ? " Dedicated1+1":"",
                               link_flags&0x20 ? " Enhanced":"",
                               lsp_flags == 0 ? " Unprotected":"",
                               lsp_flags&0x01 ? " Rerouting":"",
                               lsp_flags&0x02 ? " Rerouting with extra-traffic":"",
                               lsp_flags&0x04 ? " 1:N Protection with extra-traffic":"",
                               lsp_flags&0x08 ? " 1+1 Unidirectional protection":"",
                               lsp_flags&0x10 ? " 1+1 Bidirectional protection":"");
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * FAST REROUTE
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_fast_reroute(proto_tree *ti, proto_tree *rsvp_object_tree,
                          tvbuff_t *tvb,
                          int offset, int obj_length,
                          int rsvp_class _U_, int type)
{
    guint8      flags;
    proto_tree *ti2, *rsvp_frr_flags_tree;

    proto_item_set_text(ti, "FAST_REROUTE: ");
    switch(type) {
    case 1:
    case 7:
        if (((type == 1) && (obj_length != 24)) || ((type == 7) && (obj_length != 20))) {
            proto_tree_add_text(rsvp_object_tree, tvb, offset, obj_length,
                                "<<<Invalid length: cannot decode>>>");
            proto_item_append_text(ti, "Invalid length");
            break;
        }
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: %u", type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, 1,
                            "Setup Priority: %d", tvb_get_guint8(tvb, offset+4));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+5, 1,
                            "Hold Priority: %d", tvb_get_guint8(tvb, offset+5));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+6, 1,
                            "Hop Limit: %d", tvb_get_guint8(tvb, offset+6));

        flags = tvb_get_guint8(tvb, offset+7);
        ti2 = proto_tree_add_text(rsvp_object_tree, tvb, offset+7, 1,
                                  "Flags: 0x%02x", flags);
        rsvp_frr_flags_tree = proto_item_add_subtree(ti2, TREE(TT_FAST_REROUTE_FLAGS));
        proto_tree_add_item(rsvp_frr_flags_tree, hf_rsvp_frr_flags_one2one_backup,
                             tvb, offset+7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_frr_flags_tree, hf_rsvp_frr_flags_facility_backup,
                             tvb, offset+7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_text(rsvp_object_tree, tvb, offset+8, 4,
                            "Bandwidth: %.10g", tvb_get_ntohieee_float(tvb, offset+8));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+12, 4,
                            "Include-Any: 0x%0x", tvb_get_ntohl(tvb, offset+12));
        proto_tree_add_text(rsvp_object_tree, tvb, offset+16, 4,
                            "Exclude-Any: 0x%0x", tvb_get_ntohl(tvb, offset+16));
        if (type == 1) {
            proto_tree_add_text(rsvp_object_tree, tvb, offset+20, 4,
                                "Include-All: 0x%0x", tvb_get_ntohl(tvb, offset+20));
        }

        proto_item_append_text(ti, "%s%s",
                               flags &0x01 ? "One-to-One Backup, " : "",
                               flags &0x02 ? "Facility Backup" : "");
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * DETOUR
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_detour(proto_tree *ti, proto_tree *rsvp_object_tree,
                    tvbuff_t *tvb,
                    int offset, int obj_length,
                    int rsvp_class _U_, int type)
{
    int remaining_length, count;
    int iter;

    proto_item_set_text(ti, "DETOUR: ");
    switch(type) {
    case 7:
        iter = 0;
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: %u", type);
        for (remaining_length = obj_length - 4, count = 1;
             remaining_length > 0; remaining_length -= 8, count++) {
            if (remaining_length < 8) {
                proto_tree_add_text(rsvp_object_tree, tvb, offset+remaining_length,
                                    obj_length-remaining_length,
                                    "<<<Invalid length: cannot decode>>>");
                proto_item_append_text(ti, "Invalid length");
                break;
            }
            iter++;
            proto_tree_add_text(rsvp_object_tree, tvb, offset+(4*iter), 4,
                                "PLR ID %d: %s", count,
                                tvb_ip_to_str(tvb, offset+(4*iter)));
            iter++;
            proto_tree_add_text(rsvp_object_tree, tvb, offset+(4*iter), 4,
                                "Avoid Node ID %d: %s", count,
                                tvb_ip_to_str(tvb, offset+(4*iter)));
        }
        break;

    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)",
                            type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset+4, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * DIFFSERV
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_diffserv(proto_tree *ti, proto_tree *rsvp_object_tree,
                      tvbuff_t *tvb,
                      int offset, int obj_length,
                      int rsvp_class _U_, int type)
{
    int mapnb, count;
    int *hfindexes[] = {
        &hf_rsvp_filter[RSVPF_DIFFSERV_MAP],
        &hf_rsvp_filter[RSVPF_DIFFSERV_MAP_EXP],
        &hf_rsvp_filter[RSVPF_DIFFSERV_PHBID],
        &hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_DSCP],
        &hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_CODE],
        &hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_BIT14],
        &hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_BIT15]
    };
    gint *etts[] = {
        &TREE(TT_DIFFSERV_MAP),
        &TREE(TT_DIFFSERV_MAP_PHBID)
    };

    proto_item_set_text(ti, "DIFFSERV: ");
    offset += 3;
    switch (type) {
    case 1:
        proto_tree_add_text(rsvp_object_tree, tvb, offset, 1,
                            "C-type: 1 - E-LSP");
        proto_tree_add_uint(rsvp_object_tree, hf_rsvp_filter[RSVPF_DIFFSERV_MAPNB],
                            tvb, offset + 4, 1,
                            mapnb = tvb_get_guint8(tvb, offset + 4) & 15);
        proto_item_append_text(ti, "E-LSP, %u MAP%s", mapnb,
                               (mapnb == 0) ? "" : "s");
        offset += 5;

        for (count = 0; count < mapnb; count++) {
            dissect_diffserv_mpls_common(tvb, rsvp_object_tree, type,
                                         offset, hfindexes, etts);
            offset += 4;
        }
        break;
    case 2:
        proto_item_append_text(ti, "L-LSP");
        proto_tree_add_text(rsvp_object_tree, tvb, offset, 1,
                            "C-type: 2 - L-LSP");
        dissect_diffserv_mpls_common(tvb, rsvp_object_tree, type,
                                     offset + 3, hfindexes, etts);
        break;
    default:
        proto_tree_add_text(rsvp_object_tree, tvb, offset, 1,
                            "C-type: Unknown (%u)", type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset + 1, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*------------------------------------------------------------------------------
 * CLASSTYPE
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_diffserv_aware_te(proto_tree *ti, proto_tree *rsvp_object_tree,
                               tvbuff_t *tvb,
                               int offset, int obj_length,
                               int rsvp_class _U_, int type)
{
    proto_item *hidden_item;
    int         offset2 = offset + 4;
    guint8      ct      = 0;

    hidden_item = proto_tree_add_item(rsvp_object_tree,
                               hf_rsvp_filter[RSVPF_DSTE],
                               tvb, offset, 8, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    switch(type) {
    case 1:
        ct = tvb_get_guint8(tvb, offset2+3);
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1, "C-type: 1");
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_DSTE_CLASSTYPE],
                            tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "CLASSTYPE: CT %u", ct);
        break;
    default:
        proto_item_set_text(ti, "CLASSTYPE: (Unknown C-type)");
        proto_tree_add_text(rsvp_object_tree, tvb, offset+3, 1,
                            "C-type: Unknown (%u)", type);
        proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                            "Data (%d bytes)", obj_length - 4);
        break;
    }
}

/*----------------------------------------------------------------------------
 * VENDOR PRIVATE USE
 *---------------------------------------------------------------------------*/
static void
dissect_rsvp_vendor_private_use(proto_tree *ti _U_,
                                proto_tree *rsvp_object_tree,
                                tvbuff_t *tvb,
                                int offset, int obj_length,
                                int rsvp_class _U_, int type)
{
    /*
     * FF: from Section 2, RFC 3936
     *
     * "Organization/Vendor Private" ranges refer to values that are
     * enterprise-specific;  these MUST NOT be registered with IANA.  For
     * Vendor Private values, the first 4-octet word of the data field MUST
     * be an enterprise code [ENT: www.iana.org/assignments/enterprise-numbers]
     * (network order) as registered with the IANA SMI Network Management
     * Private Enterprise Codes, and the rest of the data thereafter is for
     * the private use of the registered enterprise.
     */
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree,
                                      hf_rsvp_filter[RSVPF_PRIVATE_OBJ],
                                      tvb, offset, obj_length, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    proto_tree_add_text(rsvp_object_tree, tvb, offset + 3, 1,
                        "C-type: %u", type);
    proto_tree_add_item(rsvp_object_tree,
                        hf_rsvp_filter[RSVPF_ENT_CODE],
                        tvb, offset + 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_text(rsvp_object_tree, tvb, offset + 8, obj_length - 8,
                        "Data (%d bytes)", obj_length - 8);
}

/*------------------------------------------------------------------------------
 * Dissect a single RSVP message in a tree
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_msg_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      int tree_mode, rsvp_conversation_info *rsvph)
{
    proto_tree *rsvp_tree;
    proto_tree *rsvp_header_tree;
    proto_tree *rsvp_object_tree;
    proto_tree *ti;
    proto_item *hidden_item;
    guint16     cksum, computed_cksum;
    vec_t       cksum_vec[1];
    int         offset    = 0;
    int         len;
    guint8      ver_flags;
    guint8      message_type;
    int         session_off, tempfilt_off;
    int         msg_length;
    int         obj_length;
    int         offset2;

    offset       = 0;
    len          = 0;
    ver_flags    = tvb_get_guint8(tvb, 0);
    msg_length   = tvb_get_ntohs(tvb, 6);
    message_type = tvb_get_guint8(tvb, 1);

    ti = proto_tree_add_item(tree, proto_rsvp, tvb, offset, msg_length,
                             ENC_NA);
    rsvp_tree = proto_item_add_subtree(ti, tree_mode);
    if (pinfo->ipproto == IP_PROTO_RSVPE2EI)
        proto_item_append_text(rsvp_tree, " (E2E-IGNORE)");
    proto_item_append_text(rsvp_tree, ": ");
    proto_item_append_text(rsvp_tree, "%s", val_to_str_ext(message_type, &message_type_vals_ext,
                                                 "Unknown (%u). "));
    find_rsvp_session_tempfilt(tvb, 0, &session_off, &tempfilt_off);
    if (session_off)
        proto_item_append_text(rsvp_tree, "%s", summary_session(tvb, session_off));
    if (tempfilt_off)
        proto_item_append_text(rsvp_tree, "%s", summary_template(tvb, tempfilt_off));

    ti = proto_tree_add_text(rsvp_tree, tvb, offset, 8, "RSVP Header. %s",
                             val_to_str_ext(message_type, &message_type_vals_ext,
                                        "Unknown Message (%u). "));
    if (pinfo->ipproto == IP_PROTO_RSVPE2EI)
        proto_item_append_text(ti, " (E2E-IGNORE)");
    rsvp_header_tree = proto_item_add_subtree(ti, TREE(TT_HDR));

    proto_tree_add_text(rsvp_header_tree, tvb, offset, 1, "RSVP Version: %u",
                        (ver_flags & 0xf0)>>4);
    proto_tree_add_text(rsvp_header_tree, tvb, offset, 1, "Flags: %02x",
                        ver_flags & 0xf);
    proto_tree_add_uint(rsvp_header_tree, hf_rsvp_filter[RSVPF_MSG], tvb,
                        offset+1, 1, message_type);
    switch (RSVPF_MSG + message_type) {

    case RSVPF_PATH:
    case RSVPF_RESV:
    case RSVPF_PATHERR:
    case RSVPF_RESVERR:
    case RSVPF_PATHTEAR:
    case RSVPF_RESVTEAR:
    case RSVPF_RCONFIRM:
    case RSVPF_RTEARCONFIRM:
    case RSVPF_BUNDLE:
    case RSVPF_ACK:
    case RSVPF_SREFRESH:
    case RSVPF_HELLO:
    case RSVPF_NOTIFY:
        hidden_item = proto_tree_add_boolean(rsvp_header_tree, hf_rsvp_filter[RSVPF_MSG + message_type], tvb,
                                      offset+1, 1, 1);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        break;

    default:
        proto_tree_add_protocol_format(rsvp_header_tree, proto_malformed, tvb, offset+1, 1,
                                       "Invalid message type: %u", message_type);
        return;
    }

    cksum = tvb_get_ntohs(tvb, offset+2);
    if (!pinfo->fragmented && ((int) tvb_length(tvb) >= msg_length)) {
        /* The packet isn't part of a fragmented datagram and isn't
           truncated, so we can checksum it. */
        cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, msg_length);
        cksum_vec[0].len = msg_length;
        computed_cksum = in_cksum(&cksum_vec[0], 1);
        if (computed_cksum == 0) {
            proto_tree_add_text(rsvp_header_tree, tvb, offset+2, 2,
                                "Message Checksum: 0x%04x [correct]",
                                cksum);
        } else {
            proto_tree_add_text(rsvp_header_tree, tvb, offset+2, 2,
                                "Message Checksum: 0x%04x [incorrect, should be 0x%04x]",
                                cksum,
                                in_cksum_shouldbe(cksum, computed_cksum));
        }
    } else {
        proto_tree_add_text(rsvp_header_tree, tvb, offset+2, 2,
                            "Message Checksum: 0x%04x",
                            cksum);
    }
    proto_tree_add_text(rsvp_header_tree, tvb, offset+4, 1,
                        "Sending TTL: %u",
                        tvb_get_guint8(tvb, offset+4));
    proto_tree_add_text(rsvp_header_tree, tvb, offset+6, 2,
                        "Message length: %u", msg_length);

    offset = 8;
    len    = 8;

    if (message_type == RSVP_MSG_BUNDLE) {
        /* Bundle message. Dissect component messages */
        if (rsvp_bundle_dissect) {
            int len2 = 8;
            while (len2 < msg_length) {
                gint      sub_len;
                tvbuff_t *tvb_sub;
                sub_len = tvb_get_ntohs(tvb, len2+6);
                tvb_sub = tvb_new_subset(tvb, len2, sub_len, sub_len);
                dissect_rsvp_msg_tree(tvb_sub, pinfo, rsvp_tree, TREE(TT_BUNDLE_COMPMSG), rsvph);
                len2 += sub_len;
            }
        } else {
            proto_tree_add_text(rsvp_tree, tvb, offset, msg_length - len,
                                "Bundle Component Messages Not Dissected");
        }
        return;
    }

    while (len < msg_length) {
        guint8 rsvp_class;
        guint8 type;

        obj_length = tvb_get_ntohs(tvb, offset);
        rsvp_class = tvb_get_guint8(tvb, offset+2);
        type = tvb_get_guint8(tvb, offset+3);
        ti = proto_tree_add_item(rsvp_tree, hf_rsvp_filter[rsvp_class_to_filter_num(rsvp_class)],
                                 tvb, offset, obj_length, ENC_BIG_ENDIAN);
        rsvp_object_tree = proto_item_add_subtree(ti, TREE(rsvp_class_to_tree_type(rsvp_class)));
        if (obj_length < 4) {
            proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
                                "Length: %u (bogus, must be >= 4)", obj_length);
            break;
        }
        proto_tree_add_text(rsvp_object_tree, tvb, offset, 2,
                            "Length: %u", obj_length);
        proto_tree_add_uint(rsvp_object_tree, hf_rsvp_filter[RSVPF_OBJECT], tvb,
                            offset+2, 1, rsvp_class);

        offset2 = offset+4;

        switch(rsvp_class) {

        case RSVP_CLASS_SESSION:
            dissect_rsvp_session(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type, rsvph);
            break;

        case RSVP_CLASS_HOP:
            dissect_rsvp_hop(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_TIME_VALUES:
            dissect_rsvp_time_values(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_ERROR:
            dissect_rsvp_error(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_SCOPE:
            dissect_rsvp_scope(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_STYLE:
            dissect_rsvp_style(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_CONFIRM:
            dissect_rsvp_confirm(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_SENDER_TEMPLATE:
        case RSVP_CLASS_FILTER_SPEC:
            dissect_rsvp_template_filter(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type, rsvph);
            break;

        case RSVP_CLASS_SENDER_TSPEC:
            dissect_rsvp_tspec(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_FLOWSPEC:
            dissect_rsvp_flowspec(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_ADSPEC:
            dissect_rsvp_adspec(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_INTEGRITY:
            dissect_rsvp_integrity(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_POLICY:
            dissect_rsvp_policy(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_LABEL_REQUEST:
            dissect_rsvp_label_request(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_RECOVERY_LABEL:
        case RSVP_CLASS_UPSTREAM_LABEL:
        case RSVP_CLASS_SUGGESTED_LABEL:
        case RSVP_CLASS_LABEL:
            dissect_rsvp_label(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_LABEL_SET:
            dissect_rsvp_label_set(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_SESSION_ATTRIBUTE:
            dissect_rsvp_session_attribute(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_EXPLICIT_ROUTE:
            dissect_rsvp_explicit_route(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_RECORD_ROUTE:
            dissect_rsvp_record_route(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_MESSAGE_ID:
            dissect_rsvp_message_id(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_MESSAGE_ID_ACK:
            dissect_rsvp_message_id_ack(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_MESSAGE_ID_LIST:
            dissect_rsvp_message_id_list(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_HELLO:
            dissect_rsvp_hello(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_DCLASS:
            dissect_rsvp_dclass(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_ADMIN_STATUS:
            dissect_rsvp_admin_status(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_LSP_ATTRIBUTES:
        case RSVP_CLASS_LSP_REQUIRED_ATTRIBUTES:
            dissect_rsvp_lsp_attributes(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_ASSOCIATION:
            dissect_rsvp_association(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_LSP_TUNNEL_IF_ID:
            dissect_rsvp_lsp_tunnel_if_id(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_NOTIFY_REQUEST:
            dissect_rsvp_notify_request(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_GENERALIZED_UNI:
            dissect_rsvp_gen_uni(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type, rsvph);
            break;

        case RSVP_CLASS_CALL_ID:
            dissect_rsvp_call_id(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_RESTART_CAP:
            dissect_rsvp_restart_cap(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_PROTECTION:
            dissect_rsvp_protection_info(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_FAST_REROUTE:
            dissect_rsvp_fast_reroute(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_DETOUR:
            dissect_rsvp_detour(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_DIFFSERV:
            dissect_rsvp_diffserv(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_CLASSTYPE:
            dissect_rsvp_diffserv_aware_te(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_VENDOR_PRIVATE_1:
        case RSVP_CLASS_VENDOR_PRIVATE_2:
        case RSVP_CLASS_VENDOR_PRIVATE_3:
        case RSVP_CLASS_VENDOR_PRIVATE_4:
        case RSVP_CLASS_VENDOR_PRIVATE_5:
        case RSVP_CLASS_VENDOR_PRIVATE_6:
        case RSVP_CLASS_VENDOR_PRIVATE_7:
        case RSVP_CLASS_VENDOR_PRIVATE_8:
        case RSVP_CLASS_VENDOR_PRIVATE_9:
        case RSVP_CLASS_VENDOR_PRIVATE_10:
        case RSVP_CLASS_VENDOR_PRIVATE_11:
        case RSVP_CLASS_VENDOR_PRIVATE_12:
            dissect_rsvp_vendor_private_use(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_NULL:
        default:
            proto_tree_add_text(rsvp_object_tree, tvb, offset2, obj_length - 4,
                                "Data (%d bytes)", obj_length - 4);
            break;
        }

        offset += obj_length;
        len += obj_length;
    }
}

/*------------------------------------------------------------------------------
 * The main loop
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 message_type;
    int    session_off, tempfilt_off;

    rsvp_conversation_info  *rsvph;
    conversation_t          *conversation;
    struct rsvp_request_key  request_key, *new_request_key;
    struct rsvp_request_val *request_val;

    col_set_str(pinfo->cinfo, COL_PROTOCOL,
                (pinfo->ipproto == IP_PROTO_RSVPE2EI) ? "RSVP-E2EI" : "RSVP");
    col_clear(pinfo->cinfo, COL_INFO);

    message_type = tvb_get_guint8(tvb, 1);

    rsvph = ep_new0(rsvp_conversation_info);

    /* Copy over the source and destination addresses from the pinfo strucutre */
    SET_ADDRESS(&rsvph->source, pinfo->src.type, pinfo->src.len, pinfo->src.data);
    SET_ADDRESS(&rsvph->destination, pinfo->dst.type, pinfo->dst.len, pinfo->dst.data);

    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str_ext(message_type, &message_type_vals_ext, "Unknown (%u). "));

    if (message_type == RSVP_MSG_BUNDLE) {
        col_set_str(pinfo->cinfo, COL_INFO,
                    rsvp_bundle_dissect ?
                    "Component Messages Dissected" :
                    "Component Messages Not Dissected");
    } else {
        find_rsvp_session_tempfilt(tvb, 0, &session_off, &tempfilt_off);
        if (session_off)
            col_append_str(pinfo->cinfo, COL_INFO, summary_session(tvb, session_off));
        if (tempfilt_off)
            col_append_str(pinfo->cinfo, COL_INFO, summary_template(tvb, tempfilt_off));
    }

    if (tree) {
        dissect_rsvp_msg_tree(tvb, pinfo, tree, TREE(TT_RSVP), rsvph);
    }

    /* ACK, SREFRESH and HELLO messages don't have any associated SESSION and,
       therefore, no conversation */
    if ((message_type == RSVP_MSG_ACK)      ||
        (message_type == RSVP_MSG_SREFRESH) ||
        (message_type == RSVP_MSG_HELLO))
      return;

    /* Find out what conversation this packet is part of. */
    conversation = find_or_create_conversation(pinfo);

    /* Now build the request key */
    memset(&request_key, 0, sizeof(request_key));
    request_key.conversation = conversation->index;
    request_key.session_type = rsvph->session_type;

    switch (request_key.session_type) {
    case RSVP_SESSION_TYPE_IPV4:
        SET_ADDRESS(&request_key.u.session_ipv4.destination,
                    rsvph->destination.type, rsvph->destination.len,
                    rsvph->destination.data);
        request_key.u.session_ipv4.protocol = rsvph->protocol;
        request_key.u.session_ipv4.udp_dest_port = rsvph->udp_dest_port;
        break;

    case RSVP_SESSION_TYPE_IPV6:
        /* Not supported yet */
        break;

    case RSVP_SESSION_TYPE_IPV4_LSP:
        SET_ADDRESS(&request_key.u.session_ipv4_lsp.destination,
                    rsvph->destination.type, rsvph->destination.len,
                    rsvph->destination.data);
        request_key.u.session_ipv4_lsp.udp_dest_port = rsvph->udp_dest_port;
        request_key.u.session_ipv4_lsp.ext_tunnel_id = rsvph->ext_tunnel_id;
        break;

    case RSVP_SESSION_TYPE_AGGREGATE_IPV4:
        SET_ADDRESS(&request_key.u.session_agg_ipv4.destination,
                    rsvph->destination.type, rsvph->destination.len,
                    rsvph->destination.data);
        request_key.u.session_agg_ipv4.dscp = rsvph->dscp;
        break;

    case RSVP_SESSION_TYPE_IPV4_UNI:
        SET_ADDRESS(&request_key.u.session_ipv4_uni.destination,
                    rsvph->destination.type, rsvph->destination.len,
                    rsvph->destination.data);
        request_key.u.session_ipv4_uni.udp_dest_port = rsvph->udp_dest_port;
        request_key.u.session_ipv4_uni.ext_tunnel_id = rsvph->ext_tunnel_id;
        break;

    case RSVP_SESSION_TYPE_IPV4_E_NNI:
        SET_ADDRESS(&request_key.u.session_ipv4_enni.destination,
                    rsvph->destination.type, rsvph->destination.len,
                    rsvph->destination.data);
        request_key.u.session_ipv4_enni.udp_dest_port = rsvph->udp_dest_port;
        request_key.u.session_ipv4_enni.ext_tunnel_id = rsvph->ext_tunnel_id;
        break;
    default:
        /* This should never happen. */
        if (tree) {
            proto_tree_add_text(tree, tvb, 0, 0, "Unknown session type");
        }
        break;
    }

    SE_COPY_ADDRESS(&request_key.source_info.source, &rsvph->source);
    request_key.source_info.udp_source_port = rsvph->udp_source_port;

    /* See if a request with this key already exists */
    request_val =
        (struct rsvp_request_val *) g_hash_table_lookup(rsvp_request_hash,
                                                        &request_key);

    /* If not, insert the new request key into the hash table */
    if (!request_val) {
        new_request_key = se_memdup(&request_key, sizeof(struct rsvp_request_key));

        request_val = se_new(struct rsvp_request_val);
        request_val->value = conversation->index;

        g_hash_table_insert(rsvp_request_hash, new_request_key, request_val);
    }

    tap_queue_packet(rsvp_tap, pinfo, rsvph);
}

static void
register_rsvp_prefs(void)
{
    module_t *rsvp_module;

    rsvp_module = prefs_register_protocol(proto_rsvp, NULL);
    prefs_register_bool_preference(
        rsvp_module, "process_bundle",
        "Dissect sub-messages in BUNDLE message",
        "Specifies whether Wireshark should decode and display sub-messages within BUNDLE messages",
        &rsvp_bundle_dissect);
    prefs_register_enum_preference(
        rsvp_module, "generalized_label_options",
        "Dissect generalized labels as",
        "Specifies how Wireshark should dissect generalized labels",
        (gint *)&rsvp_generalized_label_option,
        rsvp_generalized_label_options,
        FALSE);
}

void
proto_register_rsvp(void)
{
    gint i;

    static hf_register_info rsvpf_info[] = {

        /* Message type number */
        {&hf_rsvp_filter[RSVPF_MSG],
         { "Message Type", "rsvp.msg",
           FT_UINT8, BASE_DEC | BASE_EXT_STRING, &message_type_vals_ext, 0x0,
           NULL, HFILL }
        },

        /* Message type shorthands */
        {&hf_rsvp_filter[RSVPF_PATH],
         { "Path Message", "rsvp.path",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RESV],
         { "Resv Message", "rsvp.resv",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_PATHERR],
         { "Path Error Message", "rsvp.perr",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RESVERR],
         { "Resv Error Message", "rsvp.rerr",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_PATHTEAR],
         { "Path Tear Message", "rsvp.ptear",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RESVTEAR],
         { "Resv Tear Message", "rsvp.rtear",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RCONFIRM],
         { "Resv Confirm Message", "rsvp.resvconf",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RTEARCONFIRM],
         { "Resv Tear Confirm Message", "rsvp.rtearconf",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_BUNDLE],
         { "Bundle Message", "rsvp.bundle",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ACK],
         { "Ack Message", "rsvp.ack",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SREFRESH],
         { "Srefresh Message", "rsvp.srefresh",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_HELLO],
         { "HELLO Message", "rsvp.hello",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        /* Object class */
        {&hf_rsvp_filter[RSVPF_OBJECT],
         { "Object class", "rsvp.object",
           FT_UINT8, BASE_DEC | BASE_EXT_STRING, &rsvp_class_vals_ext, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_NOTIFY],
         { "Notify Message", "rsvp.notify",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        /* Object present shorthands */
        {&hf_rsvp_filter[RSVPF_SESSION],
         { "SESSION", "rsvp.session",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_HOP],
         { "HOP", "rsvp.hop",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_HELLO_OBJ],
         { "HELLO Request/Ack", "rsvp.hello_obj",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_INTEGRITY],
         { "INTEGRITY", "rsvp.integrity",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_TIME_VALUES],
         { "TIME VALUES", "rsvp.time",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ERROR],
         { "ERROR", "rsvp.error",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SCOPE],
         { "SCOPE", "rsvp.scope",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_STYLE],
         { "STYLE", "rsvp.style",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_FLOWSPEC],
         { "FLOWSPEC", "rsvp.flowspec",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_FILTER_SPEC],
         { "FILTERSPEC", "rsvp.filter",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SENDER],
         { "SENDER TEMPLATE", "rsvp.sender",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_TSPEC],
         { "SENDER TSPEC", "rsvp.tspec",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADSPEC],
         { "ADSPEC", "rsvp.adspec",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_POLICY],
         { "POLICY", "rsvp.policy",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_CONFIRM],
         { "CONFIRM", "rsvp.confirm",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_LABEL],
         { "LABEL", "rsvp.label",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RECOVERY_LABEL],
         { "RECOVERY LABEL", "rsvp.recovery_label",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_UPSTREAM_LABEL],
         { "UPSTREAM LABEL", "rsvp.upstream_label",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SUGGESTED_LABEL],
         { "SUGGESTED LABEL", "rsvp.suggested_label",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_LABEL_SET],
         { "LABEL SET", "rsvp.label_set",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ACCEPTABLE_LABEL_SET],
         { "ACCEPTABLE LABEL SET", "rsvp.acceptable_label_set",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_PROTECTION],
         { "PROTECTION", "rsvp.protection",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV],
         { "DIFFSERV", "rsvp.diffserv",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DSTE],
         { "CLASSTYPE", "rsvp.dste",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RESTART_CAP],
         { "RESTART CAPABILITY", "rsvp.restart",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_LABEL_REQUEST],
         { "LABEL REQUEST", "rsvp.label_request",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SESSION_ATTRIBUTE],
         { "SESSION ATTRIBUTE", "rsvp.session_attribute",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_EXPLICIT_ROUTE],
         { "EXPLICIT ROUTE", "rsvp.explicit_route",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RECORD_ROUTE],
         { "RECORD ROUTE", "rsvp.record_route",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_MESSAGE_ID],
         { "MESSAGE-ID", "rsvp.msgid",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_MESSAGE_ID_ACK],
         { "MESSAGE-ID ACK", "rsvp.msgid_ack",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_MESSAGE_ID_LIST],
         { "MESSAGE-ID LIST", "rsvp.msgid_list",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DCLASS],
         { "DCLASS", "rsvp.dclass",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_LSP_TUNNEL_IF_ID],
         { "LSP INTERFACE-ID", "rsvp.lsp_tunnel_if_id",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS],
         { "ADMIN STATUS", "rsvp.admin_status",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_REFLECT],
         { "Reflect", "rsvp.admin_status.reflect",
           FT_BOOLEAN, 32, NULL, 0x80000000,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_HANDOVER],
         { "Handover", "rsvp.admin_status.handover",
           FT_BOOLEAN, 32, NULL, 0x40,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_LOCKOUT],
         { "Lockout", "rsvp.admin_status.lockout",
           FT_BOOLEAN, 32, NULL, 0x20,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_INHIBIT],
         { "Inhibit Alarm Communication", "rsvp.admin_status.inhibit",
           FT_BOOLEAN, 32, NULL, 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_CALL_MGMT],
         { "Call Management", "rsvp.admin_status.callmgmt",
           FT_BOOLEAN, 32, NULL, 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_TESTING],
         { "Testing", "rsvp.admin_status.testing",
           FT_BOOLEAN, 32, NULL, 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_DOWN],
         { "Administratively down", "rsvp.admin_status.down",
           FT_BOOLEAN, 32, NULL, 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_DELETE],
         { "Delete in progress", "rsvp.admin_status.delete",
           FT_BOOLEAN, 32, NULL, 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_LSP_ATTRIBUTES],
         { "LSP ATTRIBUTES", "rsvp.lsp_attributes",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ASSOCIATION],
         { "ASSOCIATION", "rsvp.association",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_NOTIFY_REQUEST],
         { "NOTIFY REQUEST", "rsvp.notify_request",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_GENERALIZED_UNI],
         { "GENERALIZED UNI", "rsvp.generalized_uni",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_CALL_ID],
         { "CALL ID", "rsvp.call_id",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_PRIVATE_OBJ],
         { "Private object", "rsvp.obj_private",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_UNKNOWN_OBJ],
         { "Unknown object", "rsvp.obj_unknown",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        /* Session fields */
        {&hf_rsvp_filter[RSVPF_SESSION_IP],
         { "Destination address", "rsvp.session.ip",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SESSION_PORT],
         { "Port number", "rsvp.session.port",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SESSION_PROTO],
         { "Protocol", "rsvp.session.proto",
           FT_UINT8, BASE_DEC, VALS(proto_vals), 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SESSION_TUNNEL_ID],
         { "Tunnel ID", "rsvp.session.tunnel_id",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID],
         { "Extended tunnel ID", "rsvp.session.ext_tunnel_id",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        /* Sender template/Filterspec fields */
        {&hf_rsvp_filter[RSVPF_SENDER_IP],
         { "Sender IPv4 address", "rsvp.sender.ip",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SENDER_PORT],
         { "Sender port number", "rsvp.sender.port",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SENDER_LSP_ID],
         { "Sender LSP ID", "rsvp.sender.lsp_id",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        /* Diffserv object fields */
        {&hf_rsvp_filter[RSVPF_DIFFSERV_MAPNB],
         { "MAPnb", "rsvp.diffserv.mapnb",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           MAPNB_DESCRIPTION, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV_MAP],
         { "MAP", "rsvp.diffserv.map",
           FT_NONE, BASE_NONE, NULL, 0x0,
           MAP_DESCRIPTION, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV_MAP_EXP],
         { "EXP", "rsvp.diffserv.map.exp",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           EXP_DESCRIPTION, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV_PHBID],
         { PHBID_DESCRIPTION, "rsvp.diffserv.phbid",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_DSCP],
         { PHBID_DSCP_DESCRIPTION, "rsvp.diffserv.phbid.dscp",
           FT_UINT16, BASE_DEC, NULL, PHBID_DSCP_MASK,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_CODE],
         { PHBID_CODE_DESCRIPTION, "rsvp.diffserv.phbid.code",
           FT_UINT16, BASE_DEC, NULL, PHBID_CODE_MASK,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_BIT14],
         { PHBID_BIT14_DESCRIPTION, "rsvp.diffserv.phbid.bit14",
           FT_UINT16, BASE_DEC, VALS(phbid_bit14_vals), PHBID_BIT14_MASK,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_BIT15],
         { PHBID_BIT15_DESCRIPTION, "rsvp.diffserv.phbid.bit15",
           FT_UINT16, BASE_DEC, VALS(phbid_bit15_vals), PHBID_BIT15_MASK,
           NULL, HFILL }
        },

        /* Diffserv-aware TE object field */
        {&hf_rsvp_filter[RSVPF_DSTE_CLASSTYPE],
         { "CT", "rsvp.dste.classtype",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        /* Generalized UNI object field */
        {&hf_rsvp_filter[RSVPF_GUNI_SRC_IPV4],
         { "Source TNA", "rsvp.guni.srctna.ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_GUNI_DST_IPV4],
         { "Destination TNA", "rsvp.guni.dsttna.ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_GUNI_SRC_IPV6],
         { "Source TNA", "rsvp.guni.srctna.ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_GUNI_DST_IPV6],
         { "Destination TNA", "rsvp.guni.dsttna.ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        /* Generalized UNI object field */
        {&hf_rsvp_filter[RSVPF_CALL_ID_SRC_ADDR_IPV4],
         { "Source Transport Network Address", "rsvp.callid.srcaddr.ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_CALL_ID_SRC_ADDR_IPV6],
         { "Source Transport Network Address", "rsvp.callid.srcaddr.ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },
        /*
         * FF: Vendor Private object field, please see
         * http://www.iana.org/assignments/enterprise-numbers
         */
        {&hf_rsvp_filter[RSVPF_ENT_CODE],
         { "Enterprise Code", "rsvp.obj_private.enterprise",
           FT_UINT32, BASE_DEC|BASE_EXT_STRING, &sminmpec_values_ext, 0x0,
           "IANA Network Management Private Enterprise Code", HFILL }
        },

        {&hf_rsvp_error_flags,
         { "Flags", "rsvp.error_flags",
           FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_error_flags_path_state_removed,
         { "Path State Removed", "rsvp.error_flags.path_state_removed",
           FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_error_flags_not_guilty,
         { "NotGuilty", "rsvp.error_flags.not_guilty",
           FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_error_flags_in_place,
         { "InPlace", "rsvp.error_flags.in_place",
           FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_eth_tspec_tlv_color_mode,
         { "Color Mode (CM)", "rsvp.eth_tspec_tlv.color_mode",
           FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_eth_tspec_tlv_coupling_flag,
         { "Coupling Flag (CF)", "rsvp.eth_tspec_tlv.coupling_flag",
           FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_standard_contiguous_concatenation,
         { "Standard contiguous concatenation", "rsvp.sender_tspec.standard_contiguous_concatenation",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_arbitrary_contiguous_concatenation,
         { "Arbitrary contiguous concatenation", "rsvp.sender_tspec.arbitrary_contiguous_concatenation",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_regenerator_section,
         { "Section/Regenerator Section layer transparency", "rsvp.sender_tspec.regenerator_section",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0001,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_multiplex_section,
         { "Line/Multiplex Section layer transparency", "rsvp.sender_tspec.multiplex_section",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0002,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_J0_transparency,
         { "J0 transparency", "rsvp.sender_tspec.J0_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0004,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_SOH_RSOH_DCC_transparency,
         { "SOH/RSOH DCC transparency", "rsvp.sender_tspec.SOH_RSOH_DCC_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0008,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_LOH_MSOH_DCC_transparency,
         { "LOH/MSOH DCC transparency", "rsvp.sender_tspec.LOH_MSOH_DCC_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0010,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_LOH_MSOH_extended_DCC_transparency,
         { "LOH/MSOH Extended DCC transparency", "rsvp.sender_tspec.LOH_MSOH_extended_DCC_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0020,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_K1_K2_transparency,
         { "K1/K2 transparency", "rsvp.sender_tspec.K1_K2_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0040,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_E1_transparency,
         { "E1 transparency", "rsvp.sender_tspec.E1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0080,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_F1_transparency,
         { "F1 transparency", "rsvp.sender_tspec.F1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0100,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_E2_transparency,
         { "E2 transparency", "rsvp.sender_tspec.E2_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0200,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_B1_transparency,
         { "B1 transparency", "rsvp.sender_tspec.B1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0400,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_B2_transparency,
         { "B2 transparency", "rsvp.sender_tspec.B2_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0800,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_M0_transparency,
         { "M0 transparency", "rsvp.sender_tspec.M0_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x1000,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_M1_transparency,
         { "M1 transparency", "rsvp.sender_tspec.M1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x2000,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_standard_contiguous_concatenation,
         { "Standard contiguous concatenation", "rsvp.flowspec.standard_contiguous_concatenation",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_arbitrary_contiguous_concatenation,
         { "Arbitrary contiguous concatenation", "rsvp.flowspec.arbitrary_contiguous_concatenation",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_regenerator_section,
         { "Section/Regenerator Section layer transparency", "rsvp.flowspec.regenerator_section",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0001,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_multiplex_section,
         { "Line/Multiplex Section layer transparency", "rsvp.flowspec.multiplex_section",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0002,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_J0_transparency,
         { "J0 transparency", "rsvp.flowspec.J0_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0004,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_SOH_RSOH_DCC_transparency,
         { "SOH/RSOH DCC transparency", "rsvp.flowspec.SOH_RSOH_DCC_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0008,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_LOH_MSOH_DCC_transparency,
         { "LOH/MSOH DCC transparency", "rsvp.flowspec.LOH_MSOH_DCC_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0010,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_LOH_MSOH_extended_DCC_transparency,
         { "LOH/MSOH Extended DCC transparency", "rsvp.flowspec.LOH_MSOH_extended_DCC_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0020,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_K1_K2_transparency,
         { "K1/K2 transparency", "rsvp.flowspec.K1_K2_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0040,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_E1_transparency,
         { "E1 transparency", "rsvp.flowspec.E1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0080,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_F1_transparency,
         { "F1 transparency", "rsvp.flowspec.F1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0100,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_E2_transparency,
         { "E2 transparency", "rsvp.flowspec.E2_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0200,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_B1_transparency,
         { "B1 transparency", "rsvp.flowspec.B1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0400,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_B2_transparency,
         { "B2 transparency", "rsvp.flowspec.B2_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0800,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_M0_transparency,
         { "M0 transparency", "rsvp.flowspec.M0_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x1000,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_M1_transparency,
         { "M1 transparency", "rsvp.flowspec.M1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x2000,
           NULL, HFILL }
        },

        {&hf_rsvp_integrity_flags_handshake,
         { "Handshake", "rsvp.integrity.flags.handshake",
           FT_BOOLEAN, 8, TFS(&tfs_capable_not_capable), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_sa_flags_local,
         { "Local protection", "rsvp.sa.flags.local",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_sa_flags_label,
         { "Label recording", "rsvp.sa.flags.label",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_sa_flags_se_style,
         { "SE style", "rsvp.sa.flags.se_style",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_sa_flags_bandwidth,
         { "Bandwidth protection", "rsvp.sa.flags.bandwidth",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_sa_flags_node,
         { "Node protection", "rsvp.sa.flags.node",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_local_avail,
         { "Local Protection", "rsvp.rro.flags.local_avail",
           FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_local_in_use,
         { "Local Protection", "rsvp.rro.flags.local_in_use",
           FT_BOOLEAN, 8, TFS(&tfs_used_notused), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_bandwidth,
         { "Bandwidth Protection", "rsvp.rro.flags.bandwidth",
           FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_node,
         { "Node Protection", "rsvp.rro.flags.node",
           FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_node_address,
         { "Address Specifies a Node-id Address", "rsvp.rro.flags.node_address",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_backup_tunnel_bandwidth,
         { "Backup Tunnel Has Bandwidth", "rsvp.rro.flags.backup_tunnel_bandwidth",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_backup_tunnel_hop,
         { "Backup Tunnel Goes To", "rsvp.rro.flags.backup_tunnel_hop",
           FT_BOOLEAN, 8, TFS(&tfs_next_next_hop_next_hop), 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_e2e,
         { "E2E re-routing", "rsvp.lsp_attr.e2e",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_boundary,
         { "Boundary re-routing", "rsvp.lsp_attr.boundary",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_segment,
         { "Segment-based re-routing", "rsvp.lsp_attr.segment",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_gen_uni_direction,
         { "Direction", "rsvp.gen_uni.direction",
           FT_BOOLEAN, 8, TFS(&tfs_gen_uni_direction), 0x80,
           NULL, HFILL }
        },

        {&hf_rsvp_protection_info_flags_secondary_lsp,
         { "Secondary LSP", "rsvp.pi.flags.secondary_lsp",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_extra_traffic,
         { "Extra Traffic", "rsvp.pi_link.flags.extra_traffic",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_unprotected,
         { "Unprotected", "rsvp.pi_link.flags.unprotected",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_shared,
         { "Shared", "rsvp.pi_link.flags.shared",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_dedicated1_1,
         { "Dedicated 1:1", "rsvp.pi_link.flags.dedicated1_1",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_dedicated1plus1,
         { "Dedicated 1+1", "rsvp.pi_link.flags.dedicated1plus1",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_enhanced,
         { "Enhanced", "rsvp.pi_link.flags.enhanced",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x20,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_extra,
         { "Extra Traffic", "rsvp.pi_link.flags.extra",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_dedicated_1_1,
         { "Dedicated 1:1", "rsvp.pi_link.flags.dedicated_1_1",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_dedicated_1plus1,
         { "Dedicated 1+1", "rsvp.pi_link.flags.dedicated_1plus1",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_rfc4872_secondary,
         { "Secondary LSP", "rsvp.rfc4872.secondary",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
           NULL, HFILL }
        },

        {&hf_rsvp_rfc4872_protecting,
         { "Protecting LSP", "rsvp.rfc4872.protecting",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
           NULL, HFILL }
        },

        {&hf_rsvp_rfc4872_notification_msg,
         { "Protecting LSP", "rsvp.rfc4872.notification_msg",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
           NULL, HFILL }
        },

        {&hf_rsvp_rfc4872_operational,
         { "Protecting LSP", "rsvp.rfc4872.operational",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_lsp_flags_full_rerouting,
         { "(Full) rerouting", "rsvp.pi_lsp.flags.full_rerouting",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_lsp_flags_rerouting_extra,
         { "Rerouting without extra-traffic", "rsvp.pi_lsp.flags.rerouting_extra",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_lsp_flags_1_n_protection,
         { "1:N protection with extra-traffic", "rsvp.pi_lsp.flags.1_n_protection",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_lsp_flags_1plus1_unidirectional,
         { "1+1 unidirectional protection", "rsvp.pi_lsp.flags.1plus1_unidirectional",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_lsp_flags_1plus1_bidirectional,
         { "1+1 bidirectional protection", "rsvp.pi_lsp.flags.1plus1_bidirectional",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_protection_info_in_place,
         { "In-Place", "rsvp.protection_info.in_place",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
           NULL, HFILL }
        },

        {&hf_rsvp_protection_info_required,
         { "Required", "rsvp.protection_info.required",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_seg_flags_full_rerouting,
         { "(Full) rerouting", "rsvp.pi_seg.flags.full_rerouting",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_seg_flags_rerouting_extra,
         { "Rerouting without extra-traffic", "rsvp.pi_seg.flags.rerouting_extra",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_seg_flags_1_n_protection,
         { "1:N protection with extra-traffic", "rsvp.pi_seg.flags.1_n_protection",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_seg_flags_1plus1_unidirectional,
         { "1+1 unidirectional protection", "rsvp.pi_seg.flags.1plus1_unidirectional",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_seg_flags_1plus1_bidirectional,
         { "1+1 bidirectional protection", "rsvp.pi_seg.flags.1plus1_bidirectional",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_frr_flags_one2one_backup,
         { "One-to-One Backup", "rsvp.frr.flags.one2one_backup",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_frr_flags_facility_backup,
         { "Facility Backup", "rsvp.frr.flags.facility_backup",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x02,
           NULL, HFILL }
        },

    };

    gint *ett_tree[TT_MAX];

    /* Build the tree array */
    for (i=0; i<TT_MAX; i++) {
        ett_treelist[i] = -1;
        ett_tree[i] = &(ett_treelist[i]);
    }
    proto_rsvp = proto_register_protocol("Resource ReserVation Protocol (RSVP)",
                                         "RSVP", "rsvp");
    proto_register_field_array(proto_rsvp, rsvpf_info, array_length(rsvpf_info));
    proto_register_subtree_array(ett_tree, array_length(ett_tree));
    register_rsvp_prefs();

    rsvp_dissector_table = register_dissector_table("rsvp.proto", "RSVP Protocol",
                                                    FT_UINT8, BASE_DEC);

    /* Initialization routine for RSVP conversations */
    register_init_routine(&rsvp_init_protocol);
}

void
proto_reg_handoff_rsvp(void)
{
    dissector_handle_t rsvp_handle;

    rsvp_handle = create_dissector_handle(dissect_rsvp, proto_rsvp);
    dissector_add_uint("ip.proto", IP_PROTO_RSVP, rsvp_handle);
    dissector_add_uint("ip.proto", IP_PROTO_RSVPE2EI, rsvp_handle);
    dissector_add_uint("udp.port", UDP_PORT_PRSVP, rsvp_handle);
    rsvp_tap = register_tap("rsvp");
}
