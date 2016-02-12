/* packet-idrp.c
 * ISO 10747 Inter Domain Routing Protocol
 * Routines for IDRP packet dissection.
 * Copyright 2013, Mathias Guettler <guettler@web.de>
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
/* Supports:
 * ISO 10747 Inter Domain Routing Protocol October 18, 1993
 * TODO:
 * Validation checksum calculation
 *
 */

#include "config.h"

#include <math.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/nlpid.h>

#define IDRP_PROTO "ISO/IEC 10747 (1993): Inter Domain Routing Protocol "

void proto_register_idrp(void);

static int proto_idrp = -1;
static gint ett_idrp = -1;
static gint ett_idrp_sub = -1;

/* static header */
static int hf_idrp_li = -1;
static int hf_idrp_type = -1;
static int hf_idrp_sequence = -1;
static int hf_idrp_ack = -1;
static int hf_idrp_credit_offered = -1;
static int hf_idrp_credit_avail = -1;
static int hf_idrp_validation_pattern = -1;
/* OPEN BISPDU */
static int hf_idrp_open_version = -1;
static int hf_idrp_open_hold_time = -1;
static int hf_idrp_open_max_pdu_size = -1;
static int hf_idrp_open_src_rdi = -1;
static int hf_idrp_open_rib_attr_locally_defined_qos_nsap = -1;
static int hf_idrp_open_rib_attr_locally_defined_qos_value = -1;
static int hf_idrp_open_rib_attr_locally_defined_qos_metric = -1;
static int hf_idrp_open_rib_attr_security_reg_id = -1;
static int hf_idrp_open_rib_attr_security_info = -1;
static int hf_idrp_open_number_of_confederations = -1;
static int hf_idrp_open_confederation = -1;
static int hf_idrp_open_authentication_code = -1;
static int hf_idrp_open_authentication_data = -1;
/* UPDATE BISPDU */
static int hf_idrp_update_number_of_unfeasible_routes = -1;
static int hf_idrp_update_withdrawn_route = -1;
static int hf_idrp_update_path_attr_flag = -1;
static int hf_idrp_update_path_attr_type = -1;
static int hf_idrp_update_path_attr_length = -1;
static int hf_idrp_update_path_attr_route_separator_id = -1;
static int hf_idrp_update_path_attr_route_separator_localpref = -1;
static int hf_idrp_update_path_attr_ext_info = -1;
static int hf_idrp_update_path_attr_rd_path_type = -1;
static int hf_idrp_update_path_attr_rd_path_segment_length = -1;
static int hf_idrp_update_path_attr_rd_path_rdi = -1;
static int hf_idrp_update_path_attr_next_hop_idrp_server = -1;
static int hf_idrp_update_path_attr_next_hop_proto_type = -1;
static int hf_idrp_update_path_attr_next_hop_proto = -1;
static int hf_idrp_update_path_attr_next_hop_rdi = -1;
static int hf_idrp_update_path_attr_next_hop_nb_snpa = -1;
static int hf_idrp_update_path_attr_next_hop_snpa = -1;
static int hf_idrp_update_path_attr_dist_list_incl_nb_rdi = -1;
static int hf_idrp_update_path_attr_dist_list_incl_rdi = -1;
static int hf_idrp_update_path_attr_dist_list_excl_nb_rdi = -1;
static int hf_idrp_update_path_attr_dist_list_excl_rdi = -1;
static int hf_idrp_update_path_attr_multi_exit_disc = -1;
static int hf_idrp_update_path_attr_transit_delay = -1;
static int hf_idrp_update_path_attr_residual_error = -1;
static int hf_idrp_update_path_attr_expense = -1;
static int hf_idrp_update_path_attr_locally_defined_qos_nsap = -1;
static int hf_idrp_update_path_attr_locally_defined_qos_value = -1;
static int hf_idrp_update_path_attr_locally_defined_qos_metric = -1;
static int hf_idrp_update_path_attr_hierarchicaldecoding = -1;
static int hf_idrp_update_path_attr_rd_hop_count = -1;
static int hf_idrp_update_path_attr_security_reg_id = -1;
static int hf_idrp_update_path_attr_security_info = -1;
static int hf_idrp_update_path_attr_capacity = -1;
static int hf_idrp_update_path_attr_priority = -1;
static int hf_idrp_update_nlri_proto_type = -1;
static int hf_idrp_update_nlri_proto_id = -1;
static int hf_idrp_update_nlri_addr_length = -1;
static int hf_idrp_update_nlri_addr_info_nb_bits = -1;
static int hf_idrp_update_nlri_addr_info = -1;
/* ERROR BISPDU */
static int hf_idrp_error_code = -1;
static int hf_idrp_error_open_subcode = -1;
static int hf_idrp_error_update_subcode = -1;
static int hf_idrp_error_hold_timer_subcode = -1;
static int hf_idrp_error_fsm_subcode = -1;
static int hf_idrp_error_rib_refresh_subcode = -1;
static int hf_idrp_error_data = -1;
/* RIB-REFRESH BISPDU */
static int hf_idrp_rib_refresh_opcode = -1;
static int hf_idrp_rib_refresh_rib_attr_locally_defined_qos_nsap = -1;
static int hf_idrp_rib_refresh_rib_attr_locally_defined_qos_value = -1;
static int hf_idrp_rib_refresh_rib_attr_locally_defined_qos_metric = -1;
static int hf_idrp_rib_refresh_rib_attr_security_reg_id = -1;
static int hf_idrp_rib_refresh_rib_attr_security_info = -1;

static expert_field ei_idrp_no_path_attributes = EI_INIT;

/* flags */
#define IDRP_UPDATE_PATH_FLAG_OPTIONAL                    0x80
#define IDRP_UPDATE_PATH_FLAG_OPTIONAL_TRANSITIVE         0xc0
#define IDRP_UPDATE_PATH_FLAG_OPTIONAL_TRANSITIVE_PARTIAL 0xe0
#define IDRP_UPDATE_PATH_FLAG_TRANSITIVE                  0x40
#define IDRP_UPDATE_PATH_FLAG_PARTIAL                     0x20
static const value_string idrp_path_attr_flags[] = {
    {IDRP_UPDATE_PATH_FLAG_OPTIONAL,
     "Optional"},
    {IDRP_UPDATE_PATH_FLAG_TRANSITIVE,
     "Transitive"},
    {IDRP_UPDATE_PATH_FLAG_PARTIAL,
     "Partial"},
    {IDRP_UPDATE_PATH_FLAG_OPTIONAL_TRANSITIVE,
     "Optional, Transitive"},
    {IDRP_UPDATE_PATH_FLAG_OPTIONAL_TRANSITIVE_PARTIAL,
     "Optional, Transitive, Partial"},
    {0, NULL}
};

  /* BISPDU Type Codes */
#define IDRP_TYPE_OPEN        1
#define IDRP_TYPE_UPDATE      2
#define IDRP_TYPE_ERROR       3
#define IDRP_TYPE_KEEPALIVE   4
#define IDRP_TYPE_CEASE       5
#define IDRP_TYPE_RIB_REFRESH 6
static const value_string idrp_pdu_types[] = {
    {IDRP_TYPE_OPEN,        "OPEN"},
    {IDRP_TYPE_UPDATE,      "UPDATE"},
    {IDRP_TYPE_ERROR,       "ERROR"},
    {IDRP_TYPE_KEEPALIVE,   "KEEPALIVE"},
    {IDRP_TYPE_CEASE,       "CEASE"},
    {IDRP_TYPE_RIB_REFRESH, "RIB REFRESH"},
    {0, NULL}
};

#define IDRP_OPEN_AUTHENTICATION_CODE_INTEGRITY_ONLY                0
#define IDRP_OPEN_AUTHENTICATION_CODE_INTEGRITY_PLUS_AUTHENTICATION 1
#define IDRP_OPEN_AUTHENTICATION_CODE_INTEGRITY_PLUS_SECRET_TEXT    2
static const value_string idrp_pdu_open_authentication_codes[] = {
    {IDRP_OPEN_AUTHENTICATION_CODE_INTEGRITY_ONLY,
        "Integrity Only"},
    {IDRP_OPEN_AUTHENTICATION_CODE_INTEGRITY_PLUS_AUTHENTICATION,
        "Integrity plus authentication"},
    {IDRP_OPEN_AUTHENTICATION_CODE_INTEGRITY_PLUS_SECRET_TEXT,
        "Integrity plus secret text"},
    {0, NULL}
};


#define IDRP_PATH_ATTR_TYPE_ROUTE_SEPARATOR        1
#define IDRP_PATH_ATTR_TYPE_EXT_INFO               2
#define IDRP_PATH_ATTR_TYPE_RD_PATH                3
#define IDRP_PATH_ATTR_TYPE_NEXT_HOP               4
#define IDRP_PATH_ATTR_TYPE_DIST_LIST_INCL         5
#define IDRP_PATH_ATTR_TYPE_DIST_LIST_EXCL         6
#define IDRP_PATH_ATTR_TYPE_MULTI_EXIT_DISC        7
#define IDRP_PATH_ATTR_TYPE_TRANSIT_DELAY          8
#define IDRP_PATH_ATTR_TYPE_RESIDUAL_ERROR         9
#define IDRP_PATH_ATTR_TYPE_EXPENSE               10
#define IDRP_PATH_ATTR_TYPE_LOCALLY_DEFINED_QOS   11
#define IDRP_PATH_ATTR_TYPE_HIERARCHICALRECORDING 12
#define IDRP_PATH_ATTR_TYPE_RD_HOP_COUNT          13
#define IDRP_PATH_ATTR_TYPE_SECURITY              14
#define IDRP_PATH_ATTR_TYPE_CAPACITY              15
#define IDRP_PATH_ATTR_TYPE_PRIORITY              16
static const value_string path_attr_types[] = {
    {IDRP_PATH_ATTR_TYPE_ROUTE_SEPARATOR,       "Route Separator"},
    {IDRP_PATH_ATTR_TYPE_EXT_INFO,              "Ext Info"},
    {IDRP_PATH_ATTR_TYPE_RD_PATH,               "RD Path"},
    {IDRP_PATH_ATTR_TYPE_NEXT_HOP,              "Next Hop"},
    {IDRP_PATH_ATTR_TYPE_DIST_LIST_INCL,        "Dist List Incl"},
    {IDRP_PATH_ATTR_TYPE_DIST_LIST_EXCL,        "Dist List Excl"},
    {IDRP_PATH_ATTR_TYPE_MULTI_EXIT_DISC,       "Multi Exit Disc"},
    {IDRP_PATH_ATTR_TYPE_TRANSIT_DELAY,         "Transit Delay"},
    {IDRP_PATH_ATTR_TYPE_RESIDUAL_ERROR,        "Residual Error"},
    {IDRP_PATH_ATTR_TYPE_EXPENSE,               "Expense"},
    {IDRP_PATH_ATTR_TYPE_LOCALLY_DEFINED_QOS,   "Locally Ddefined Qos"},
    {IDRP_PATH_ATTR_TYPE_HIERARCHICALRECORDING, "Hierarchical Recording"},
    {IDRP_PATH_ATTR_TYPE_RD_HOP_COUNT,          "RD Hop Count"},
    {IDRP_PATH_ATTR_TYPE_SECURITY,              "Security"},
    {IDRP_PATH_ATTR_TYPE_CAPACITY,              "Capacity"},
    {IDRP_PATH_ATTR_TYPE_PRIORITY,              "Priority"},
    {0, NULL}
};

#define IDRP_RD_PATH_RD_SET    1
#define IDRP_RD_PATH_RD_SEQ    2
#define IDRP_RD_PATH_ENTRY_SEQ 3
#define IDRP_RD_PATH_ENTRY_SET 4
static const value_string path_rd_segment_types[] = {
    {IDRP_RD_PATH_RD_SET,    "RD_SET"},
    {IDRP_RD_PATH_RD_SEQ,    "RD_SEQ"},
    {IDRP_RD_PATH_ENTRY_SEQ, "ENTRY_SEQ"},
    {IDRP_RD_PATH_ENTRY_SET, "ENTRY_SET"},
    {0, NULL}
};

#define IDRP_PROTO_TYPE_TR_9577 1
#define IDRP_PROTO_TYPE_8802 2
static const value_string idrp_proto_type[] = {
    {IDRP_PROTO_TYPE_TR_9577, "ISO TR 9577 IPI/SPI"},
    {IDRP_PROTO_TYPE_8802,    "ISO 8802 LSAP"},
    {0, NULL}
};


/* ERROR PDU error codes: */
#define IDRP_ERROR_OPEN        1
#define IDRP_ERROR_UPDATE      2
#define IDRP_ERROR_HOLD_TIMER  3
#define IDRP_ERROR_FSM         4
#define IDRP_ERROR_RIB_REFRESH 5
static const value_string idrp_error_codes[] = {
    {IDRP_ERROR_OPEN,        "OPEN PDU_Error"},
    {IDRP_ERROR_UPDATE,      "UPDATE PDU_Error"},
    {IDRP_ERROR_HOLD_TIMER,  "Hold Timer_Expired"},
    {IDRP_ERROR_FSM,         "FSM Error"},
    {IDRP_ERROR_RIB_REFRESH, "RIB REFRESH PDU Error"},
    {0, NULL}
};

/* ERROR PDU sub error codes: OPEN */
#define IDRP_ERROR_OPEN_UNSUPPORTED_VERSION_NUMBER      1
#define IDRP_ERROR_OPEN_BAD_MAXPDU_SIZE                 2
#define IDRP_ERROR_OPEN_BAD_PEER_RD                     3
#define IDRP_ERROR_OPEN_UNSUPPORTED_AUTHENTICATION_CODE 4
#define IDRP_ERROR_OPEN_AUTHENTICATION_FAILURE          5
#define IDRP_ERROR_OPEN_BAD_RIB_ATTRSSET                6
#define IDRP_ERROR_RDC_MISMATCH                         7
static const value_string idrp_error_open_subcodes[] = {
    {IDRP_ERROR_OPEN_UNSUPPORTED_VERSION_NUMBER,
     "Unsupported Version Number"},
    {IDRP_ERROR_OPEN_BAD_MAXPDU_SIZE,
     "Bad Maximum PDU Size"},
    {IDRP_ERROR_OPEN_BAD_PEER_RD,
     "Bad Peer RD"},
    {IDRP_ERROR_OPEN_UNSUPPORTED_AUTHENTICATION_CODE,
     "Unsupported Authentication Code"},
    {IDRP_ERROR_OPEN_AUTHENTICATION_FAILURE,
     "Authentication Failure"},
    {IDRP_ERROR_OPEN_BAD_RIB_ATTRSSET,
     "Bad RIB Attribute Set"},
    {IDRP_ERROR_RDC_MISMATCH,
     "RDC Mismatch"},
    {0, NULL}
};

/* ERROR PDU sub error codes: UPDATE */
#define IDRP_ERROR_UPDATE_MALFORMED_ATTRIBUTE_LIST           1
#define IDRP_ERROR_UPDATE_UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE  2
#define IDRP_ERROR_UPDATE_MISSING_WELL_KNOWN_ATTRIBUTE       3
#define IDRP_ERROR_UPDATE_ATTRIBUTE_FLAGS_ERROR              4
#define IDRP_ERROR_UPDATE_ATTRIBUTE_LENGTH_ERROR             5
#define IDRP_ERROR_UPDATE_RD_ROUTEING_LOOP                   6
#define IDRP_ERROR_UPDATE_INVALID_NEXT_HOP_ATTRIBUTE         7
#define IDRP_ERROR_UPDATE_OPTIONAL_ATTRIBUTE_ERROR           8
#define IDRP_ERROR_UPDATE_INVALID_REACHABILITY_INFORMATION   9
#define IDRP_ERROR_UPDATE_MISCONFIGURED_RDCS                10
#define IDRP_ERROR_UPDATE_MALFORMED_NLRI                    11
#define IDRP_ERROR_UPDATE_DUPLICATED_ATTRIBUTES             12
#define IDRP_ERROR_UPDATE_ILLEGAL_RD_PATH_SEGMENT           13
static const value_string idrp_error_update_subcodes[] = {
    {IDRP_ERROR_UPDATE_MALFORMED_ATTRIBUTE_LIST,
     "Malformed Attribute List"},
    {IDRP_ERROR_UPDATE_UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE,
     "Unrecognized Well-known Attribute"},
    {IDRP_ERROR_UPDATE_MISSING_WELL_KNOWN_ATTRIBUTE,
     "Missing Well-known Attribute"},
    {IDRP_ERROR_UPDATE_ATTRIBUTE_FLAGS_ERROR,
     "Attribute Flags Error"},
    {IDRP_ERROR_UPDATE_ATTRIBUTE_LENGTH_ERROR,
     "Attribute Length Error"},
    {IDRP_ERROR_UPDATE_RD_ROUTEING_LOOP,
     "RD Routing Loop"},
    {IDRP_ERROR_UPDATE_INVALID_NEXT_HOP_ATTRIBUTE,
     "Invalid NEXT HOP Attribute"},
    {IDRP_ERROR_UPDATE_OPTIONAL_ATTRIBUTE_ERROR,
     "Optional Attribute error"},
    {IDRP_ERROR_UPDATE_INVALID_REACHABILITY_INFORMATION,
     "Invalid Reachability Information"},
    {IDRP_ERROR_UPDATE_MISCONFIGURED_RDCS,
     "Misconfigured RDCs"},
    {IDRP_ERROR_UPDATE_MALFORMED_NLRI,
     "Malformed NLRI"},
    {IDRP_ERROR_UPDATE_DUPLICATED_ATTRIBUTES,
     "Duplicated_Attributes"},
    {IDRP_ERROR_UPDATE_ILLEGAL_RD_PATH_SEGMENT,
     "Illegal RD Path Segment"},
    {0, NULL}
};

#define IDRP_ERROR_HOLD_TIMER_NONE 0
static const value_string idrp_error_hold_timer_subcodes[] = {
    {IDRP_ERROR_HOLD_TIMER_NONE, "None"},
    {0, NULL}
};

/* ERROR PDU sub error codes: FSM */
#define IDRP_ERROR_FSM_CLOSED      1
#define IDRP_ERROR_FSM_OPEN_RCVD   2
#define IDRP_ERROR_FSM_OPEN_SENT   3
#define IDRP_ERROR_FSM_CLOSE_WAIT  4
#define IDRP_ERROR_FSM_ESTABLISHED 5
static const value_string idrp_error_fsm_subcodes[] = {
    {IDRP_ERROR_FSM_CLOSED,      "CLOSED"},
    {IDRP_ERROR_FSM_OPEN_RCVD,   "OPEN-RCVD"},
    {IDRP_ERROR_FSM_OPEN_SENT,   "OPEN-SENT"},
    {IDRP_ERROR_FSM_CLOSE_WAIT,  "CLOSE-WAIT"},
    {IDRP_ERROR_FSM_ESTABLISHED, "ESTABLISHED"},
    {0, NULL}
};


#define IDRP_ERROR_RIB_REFRESH_INVALID_OPCODE       1
#define IDRP_ERROR_RIB_REFRESH_UNSUPPORTED_RIB_ATTS 2
static const value_string idrp_error_rib_refresh_subcodes[] = {
    {IDRP_ERROR_RIB_REFRESH_INVALID_OPCODE, "Invalid OpCode"},
    {IDRP_ERROR_RIB_REFRESH_UNSUPPORTED_RIB_ATTS,
        "Unsupported RIB-Attributes"},
    {0, NULL}
};


#if 0
#define IDRP_RIB_REFRESH_REQUEST 1
#define IDRP_RIB_REFRESH_START 2
#define IDRP_RIB_REFRESH_END 3
static const value_string idrp_rib_refresh_opcodes[] = {
    {IDRP_RIB_REFRESH_REQUEST, "RIB Refresh Request"},
    {IDRP_RIB_REFRESH_START,   "RIB Refresh Start"},
    {IDRP_RIB_REFRESH_END,     "RIB Refresh End"},
    {0, NULL}
};
#endif


static int dissect_BISPDU_OPEN(tvbuff_t * tvb, int offset, proto_tree * tree)
{
    guint8 rdi_len;
    guint8 number_of_non_empty_rib_attributes;
    guint8 number_of_distinguishing_attributes;
    guint8 rib_attribute_type;
    guint8 number_of_rdcs;
    guint8 length_indicator_guint8;
    gint   i;
    gint   j;

    /* 1 octet idrp version */
    proto_tree_add_item(tree, hf_idrp_open_version, tvb, offset,1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Hold Time (2 octets) */
    proto_tree_add_item(tree, hf_idrp_open_hold_time, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Maximum PDU Size (2 octets) */
    proto_tree_add_item(tree, hf_idrp_open_max_pdu_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Source RDI Length Indicator (1 octet) */
    rdi_len = tvb_get_guint8(tvb, offset);
    offset += 1;

    /* Source RDI */
    proto_tree_add_item(tree, hf_idrp_open_src_rdi, tvb, offset, rdi_len, ENC_NA);
    offset += rdi_len;

    /* Number of Non-empty RIB-Atts */
    number_of_non_empty_rib_attributes = tvb_get_guint8(tvb, offset);
    offset += 1;

    /* process Nth non-empty RIB-Atts */
    for (i = number_of_non_empty_rib_attributes; i > 0; i--) {
        /* 1 octet number of distinguishing attributes that are contained in
           the Nth RIB-Att. */
        number_of_distinguishing_attributes = tvb_get_guint8(tvb, offset);
        offset += 1;

        /* process Nth RIB-Att */
        for (j = number_of_distinguishing_attributes; j > 0; j--) {
            /* 1 octet Type of RIB-Att */
            rib_attribute_type = tvb_get_guint8(tvb, offset);
            offset += 1;

            switch (rib_attribute_type) {
                case IDRP_PATH_ATTR_TYPE_ROUTE_SEPARATOR:
                case IDRP_PATH_ATTR_TYPE_EXT_INFO:
                case IDRP_PATH_ATTR_TYPE_RD_PATH:
                case IDRP_PATH_ATTR_TYPE_NEXT_HOP:
                case IDRP_PATH_ATTR_TYPE_DIST_LIST_EXCL:
                case IDRP_PATH_ATTR_TYPE_DIST_LIST_INCL:
                case IDRP_PATH_ATTR_TYPE_MULTI_EXIT_DISC:
                case IDRP_PATH_ATTR_TYPE_RESIDUAL_ERROR:
                case IDRP_PATH_ATTR_TYPE_EXPENSE:
                case IDRP_PATH_ATTR_TYPE_HIERARCHICALRECORDING:
                case IDRP_PATH_ATTR_TYPE_RD_HOP_COUNT:
                case IDRP_PATH_ATTR_TYPE_CAPACITY:
                case IDRP_PATH_ATTR_TYPE_PRIORITY:
                    break;
                case IDRP_PATH_ATTR_TYPE_LOCALLY_DEFINED_QOS:
                    /* 1 octet Nsap prefix length */
                    length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                    offset += 1;
                    /* process Nsap prefix */
                    proto_tree_add_item(
                            tree,
                            hf_idrp_open_rib_attr_locally_defined_qos_nsap,
                            tvb,
                            offset,
                            length_indicator_guint8,
                            ENC_NA);
                    offset += length_indicator_guint8;

                    /* 1 octet Qos length */
                    length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                    offset += 1;
                    /* process Qos */
                    proto_tree_add_item(
                            tree,
                            hf_idrp_open_rib_attr_locally_defined_qos_value,
                            tvb,
                            offset,
                            length_indicator_guint8,
                            ENC_NA);
                    offset += length_indicator_guint8;

                    /* 1 octet Metric length */
                    /* note: metric  always absent in OPEN BISPDU */
                    length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                    offset += 1;
                    /* process Metric */
                    proto_tree_add_item(
                            tree,
                            hf_idrp_open_rib_attr_locally_defined_qos_metric,
                            tvb,
                            offset,
                            length_indicator_guint8,
                            ENC_NA);
                    offset += length_indicator_guint8;
                    break;
                case IDRP_PATH_ATTR_TYPE_SECURITY:
                    /* length of Security Registration ID and Security Information */
                    offset += 2;

                    /* length of Security Registration ID */
                    length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                    offset += 1;
                    /* value of Security Registration ID */
                    proto_tree_add_item(
                            tree,
                            hf_idrp_open_rib_attr_security_reg_id,
                            tvb,
                            offset,
                            length_indicator_guint8,
                            ENC_NA);
                    offset += length_indicator_guint8;

                    /* length of Security Information */
                    /* note: always absent for OPEN BISPDU*/
                    length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                    offset += 1;
                    /* value of Security Information */
                    proto_tree_add_item(
                            tree,
                            hf_idrp_open_rib_attr_security_info,
                            tvb,
                            offset,
                            length_indicator_guint8,
                            ENC_NA);
                    offset += length_indicator_guint8;

                    break;
                default:
                    break;
            } /* switch (path_attr_type) */
        }
    } /* process Nth non-empty RIB-Atts */

    /* Confed-ID's */
    /* Number of RDCs */
    number_of_rdcs = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_idrp_open_number_of_confederations, tvb,
            offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* process Nth Confederation RDI */
    for (i = number_of_rdcs; i > 0; i--) {
        /* 1 octet of RDI length */
        length_indicator_guint8 = tvb_get_guint8(tvb, offset);
        offset += 1;

        /* process Nth RDI */
        proto_tree_add_item(tree, hf_idrp_open_confederation, tvb,
                offset, length_indicator_guint8, ENC_NA);
        offset += length_indicator_guint8;
    }

    /* Authentication Code */
    proto_tree_add_item(tree, hf_idrp_open_authentication_code, tvb, offset, 1,
            ENC_BIG_ENDIAN);
    offset += 1;

    /* Authentication Data */
    proto_tree_add_item(tree, hf_idrp_open_authentication_data, tvb, offset,
            tvb_reported_length_remaining(tvb, offset), ENC_NA);
    offset += tvb_reported_length_remaining(tvb, offset);

    return offset;
}

static int dissect_BISPDU_UPDATE(tvbuff_t * tvb, int offset, proto_tree * tree)
{
    guint16 nb_unfeasible_routes;
    guint16 path_attrs_len;
    int     path_attrs_start_offset;
    guint8  path_attr_type;
    guint16 path_attr_len;
    int     start_offset;
    guint16 rdi_len;
    guint8  proto_len;
    guint16 net_len;
    int     path_segment_rdi_offset;
    guint16 length_indicator_guint16;
    guint8  length_indicator_guint8;
    guint8  nb_of_snpa;
    guint8  dist_list_count;
    int     i;

    /* 2 octet withdrawn ("Unfeasible") Route Count */
    nb_unfeasible_routes = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_idrp_update_number_of_unfeasible_routes,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* process Nth unfeasible route ID */
    for (i = nb_unfeasible_routes; i > 0; i--) {
        proto_tree_add_item(tree, hf_idrp_update_withdrawn_route, tvb, offset,
                4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    /* 2 octets path attributes length */
    path_attrs_len = tvb_get_ntohs(tvb, offset);
    offset += 2;

    path_attrs_start_offset = offset;
    /* process Nth path attribute */
    while (offset < (path_attrs_start_offset + path_attrs_len)) {
        /* Path attribute flag */
        proto_tree_add_item(tree, hf_idrp_update_path_attr_flag, tvb,
                offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* Path attribute type */
        path_attr_type = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_idrp_update_path_attr_type, tvb,
                offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* Path attribute length */
        path_attr_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_idrp_update_path_attr_length, tvb,
                offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        /* Path attribute value */
        switch (path_attr_type) {
            case IDRP_PATH_ATTR_TYPE_ROUTE_SEPARATOR:
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_route_separator_id,
                        tvb,
                        offset,
                        4,
                        ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_route_separator_localpref,
                        tvb,
                        offset,
                        1,
                        ENC_BIG_ENDIAN);
                offset ++ ;
                break;
            case IDRP_PATH_ATTR_TYPE_EXT_INFO:
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_ext_info,
                        tvb,
                        offset,
                        0,
                        ENC_BIG_ENDIAN);
                break;
            case IDRP_PATH_ATTR_TYPE_RD_PATH:
                start_offset = offset;

                /* process Nth path segment */
                while (offset < (start_offset + path_attr_len)) {
                    /* print path segment type */
                    proto_tree_add_item(tree,
                            hf_idrp_update_path_attr_rd_path_type,
                            tvb,
                            offset,
                            1,
                            ENC_BIG_ENDIAN);
                    offset += 1;

                    /* 2 octets of path segment length */
                    length_indicator_guint16 = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(tree,
                            hf_idrp_update_path_attr_rd_path_segment_length,
                            tvb,
                            offset,
                            2,
                            ENC_BIG_ENDIAN);
                    offset += 2;

                    /* one path segment may contain one or more RDI */
                    path_segment_rdi_offset = offset;
                    while (offset < (path_segment_rdi_offset + length_indicator_guint16)) {
                        /* 1 octet rdi length */
                        length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                        offset += 1;
                        /* print N times path RDI */
                        proto_tree_add_item(tree,
                                hf_idrp_update_path_attr_rd_path_rdi,
                                tvb,
                                offset,
                                length_indicator_guint8,
                                ENC_NA);
                        offset += length_indicator_guint8;
                    }
                }
                break;
            case IDRP_PATH_ATTR_TYPE_NEXT_HOP:
                /* 1 octet idrp server flag */
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_next_hop_idrp_server,
                        tvb,
                        offset,
                        1,
                        ENC_BIG_ENDIAN);
                offset += 1;

                start_offset = offset;
                /* process Nth next hop */
                while (offset < (start_offset + path_attr_len)) {
                    /* 1 octet Proto type */
                    proto_tree_add_item(tree,
                            hf_idrp_update_path_attr_next_hop_proto_type,
                            tvb,
                            offset,
                            1,
                            ENC_BIG_ENDIAN);
                    offset += 1;
                    /* 1 octet Proto len */
                    length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                    offset += 1;
                    /* N octets Proto: in case of ISO 8473 one octet with the value 0x81 */
                    proto_tree_add_item(tree,
                            hf_idrp_update_path_attr_next_hop_proto,
                            tvb,
                            offset,
                            length_indicator_guint8,
                            ENC_ASCII | ENC_NA);
                    offset += length_indicator_guint8;

                    /* length of NET of Next HOP */
                    length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                    offset += 1;
                    /* NET of Next HOP */
                    proto_tree_add_item(tree,
                            hf_idrp_update_path_attr_next_hop_rdi,
                            tvb,
                            offset,
                            length_indicator_guint8,
                            ENC_NA);
                    offset +=  length_indicator_guint8;

                    /* number of SNPA */
                    nb_of_snpa = tvb_get_guint8(tvb, offset);
                    proto_tree_add_item(tree,
                            hf_idrp_update_path_attr_next_hop_nb_snpa,
                            tvb,
                            offset,
                            1,
                            ENC_BIG_ENDIAN);
                    offset += 1;
                    /* process Nth SNPA */
                    for (i = nb_of_snpa; i > 0; i--) {
                        /* SNPS length in multiples of 4 bit */
                        length_indicator_guint8 =
                            /* length = half the length in semi-octets rounded up */
                            (tvb_get_guint8(tvb, offset) + 1) / 2;
                        offset += 1;
                        proto_tree_add_item(tree,
                                hf_idrp_update_path_attr_next_hop_snpa,
                                tvb,
                                offset,
                                length_indicator_guint8 ,
                                ENC_NA);
                        offset += length_indicator_guint8;
                    }
                } /* while: process Nth next hop */
                break;
            case IDRP_PATH_ATTR_TYPE_DIST_LIST_EXCL:
                /* 1 octet number of RDI's/Confed's in DIST list */
                dist_list_count = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_dist_list_excl_nb_rdi,
                        tvb,
                        offset,
                        1 ,
                        ENC_BIG_ENDIAN);
                offset += 1;

                /* process RDI's/Confederations's in DIST list */
                for (i = dist_list_count; i > 0; i--) {
                    /* 1 octet RDI/Confed length indicator */
                    length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                    offset += 1;
                    /* variable size RDI/Conderation */
                    proto_tree_add_item(tree,
                            hf_idrp_update_path_attr_dist_list_excl_rdi ,
                            tvb,
                            offset,
                            length_indicator_guint8 ,
                            ENC_NA);
                    offset += length_indicator_guint8;
                }
                break;
            case IDRP_PATH_ATTR_TYPE_DIST_LIST_INCL:
                /* 1 octet number of RDI's/Confed's in DIST list */
                dist_list_count = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_dist_list_incl_nb_rdi,
                        tvb,
                        offset,
                        1 ,
                        ENC_BIG_ENDIAN);
                offset += 1;

                /* process RDI's/Confederations's in DIST list */
                for (i = dist_list_count; i > 0; i--) {
                    /* 1 octet RDI/Confed length indicator */
                    length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                    offset += 1;
                    /* variable size RDI/Conderation */
                    proto_tree_add_item(tree,
                            hf_idrp_update_path_attr_dist_list_incl_rdi ,
                            tvb,
                            offset,
                            length_indicator_guint8 ,
                            ENC_NA);
                    offset += length_indicator_guint8;
                }
                break;
            case IDRP_PATH_ATTR_TYPE_MULTI_EXIT_DISC:
                /* 1 octet Multi Exit Discriminator */
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_multi_exit_disc ,
                        tvb,
                        offset,
                        1 ,
                        ENC_BIG_ENDIAN);
                offset += 1;
                break;
            case IDRP_PATH_ATTR_TYPE_TRANSIT_DELAY:
                /* 2 octets of transit delay */
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_transit_delay ,
                        tvb,
                        offset,
                        2 ,
                        ENC_BIG_ENDIAN);
                offset += 2;
                break;
            case IDRP_PATH_ATTR_TYPE_RESIDUAL_ERROR:
                /* 4 octets of residual error */
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_residual_error ,
                        tvb,
                        offset,
                        4 ,
                        ENC_BIG_ENDIAN);
                offset += 4;
                break;
            case IDRP_PATH_ATTR_TYPE_EXPENSE:
                /* 2 octets of Expense */
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_expense ,
                        tvb,
                        offset,
                        2 ,
                        ENC_BIG_ENDIAN);
                offset += 2;
                break;
            case IDRP_PATH_ATTR_TYPE_LOCALLY_DEFINED_QOS:
                /* 1 octet Nsap prefix length */
                length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                offset += 1;
                /* process Nsap prefix */
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_locally_defined_qos_nsap ,
                        tvb,
                        offset,
                        length_indicator_guint8 ,
                        ENC_NA);
                offset += length_indicator_guint8;
                /* 1 octet Qoslength */
                length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                offset += 1;
                /* process Qos */
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_locally_defined_qos_value,
                        tvb,
                        offset,
                        length_indicator_guint8 ,
                        ENC_NA);
                offset += length_indicator_guint8;
                /* 1 octet Metric length */
                length_indicator_guint8  = tvb_get_guint8(tvb, offset);
                offset += 1;
                /* process Metric */
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_locally_defined_qos_metric,
                        tvb,
                        offset,
                        length_indicator_guint8 ,
                        ENC_NA);
                offset += length_indicator_guint8;
                break;
            case IDRP_PATH_ATTR_TYPE_HIERARCHICALRECORDING:
                /* 1 octet flag hierarchical recording */
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_hierarchicaldecoding,
                        tvb,
                        offset,
                        1 ,
                        ENC_BIG_ENDIAN);
                offset += 1;
                break;
            case IDRP_PATH_ATTR_TYPE_RD_HOP_COUNT:
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_rd_hop_count,
                        tvb,
                        offset,
                        1 ,
                        ENC_BIG_ENDIAN);
                offset += 1;
                break;
            case IDRP_PATH_ATTR_TYPE_SECURITY:
                /* length of Security Registration ID */
                length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                offset += 1;

                /* value of Security Registration ID */
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_security_reg_id,
                        tvb,
                        offset,
                        length_indicator_guint8 ,
                        ENC_NA);
                offset += length_indicator_guint8;

                /* length of Security Information */
                length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                offset += 1;
                /* value of Security Information */
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_security_info,
                        tvb,
                        offset,
                        length_indicator_guint8,
                        ENC_NA);
                offset += length_indicator_guint8;
                break;
            case IDRP_PATH_ATTR_TYPE_CAPACITY:
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_capacity,
                        tvb,
                        offset,
                        1 ,
                        ENC_BIG_ENDIAN);
                offset += 1;
                break;
            case IDRP_PATH_ATTR_TYPE_PRIORITY:
                proto_tree_add_item(tree,
                        hf_idrp_update_path_attr_priority,
                        tvb,
                        offset,
                        1 ,
                        ENC_BIG_ENDIAN);
                offset += 1;
                break;
            default:
                break;
        }
    }

    /* 1 octet Proto type */
    proto_tree_add_item(tree, hf_idrp_update_nlri_proto_type, tvb, offset,
            1, ENC_BIG_ENDIAN);
    offset += 1;

    /* 1 octet Proto len */
    proto_len = tvb_get_guint8(tvb, offset);
    offset += 1;

    /* N octets Proto identity: in case of ISO 8473 one octet with the value 0x81 */
    proto_tree_add_item(tree, hf_idrp_update_nlri_proto_id, tvb, offset,
            proto_len, ENC_NA);
    offset += proto_len;

    /* 2 octets length of address */
    net_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_idrp_update_nlri_addr_length, tvb, offset,
            2, ENC_BIG_ENDIAN);
    offset += 2;

    /* process N address info sets */
    start_offset = offset;
    while (offset < (start_offset + net_len)) {
        /* 1 octet address length in bits */
        rdi_len = tvb_get_guint8(tvb, offset) / 8;
        proto_tree_add_item(tree, hf_idrp_update_nlri_addr_info_nb_bits, tvb,
                offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_idrp_update_nlri_addr_info, tvb,
                offset, rdi_len, ENC_NA);
        offset += rdi_len;
    }
    return offset;
}

static int dissect_BISPDU_ERROR(tvbuff_t * tvb, int offset, proto_tree * tree)
{
    guint8 error_code = 0;
    gint   data_length;

    /* Error Code (1 octet) */
    error_code = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_idrp_error_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    switch (error_code) {
        case IDRP_ERROR_OPEN:
            proto_tree_add_item(tree, hf_idrp_error_open_subcode, tvb, offset, 1,
                    ENC_BIG_ENDIAN);
            break;
        case IDRP_ERROR_UPDATE:
            proto_tree_add_item(tree, hf_idrp_error_update_subcode, tvb, offset, 1,
                    ENC_BIG_ENDIAN);
            break;
        case IDRP_ERROR_HOLD_TIMER:
            proto_tree_add_item(tree, hf_idrp_error_hold_timer_subcode, tvb,
                    offset, 1, ENC_BIG_ENDIAN);
            break;
        case IDRP_ERROR_FSM:
            proto_tree_add_item(tree, hf_idrp_error_fsm_subcode, tvb, offset, 1,
                    ENC_BIG_ENDIAN);
            break;
        case IDRP_ERROR_RIB_REFRESH:
            proto_tree_add_item(tree, hf_idrp_error_rib_refresh_subcode, tvb,
                    offset, 1, ENC_BIG_ENDIAN);
            break;
        default:
            break;
    }
    offset += 1;

    /* data : zero or more octets of data to be used in diagnosing the reason
       for the IDRP ERROR PDU. The contents of the Data field depends upon the
       error code and error subcode. */
    data_length = tvb_reported_length_remaining(tvb, offset);
    if (data_length>0) {
        proto_tree_add_item(tree, hf_idrp_error_data, tvb, offset, data_length,
                ENC_NA);
        offset += data_length;
    }

    return offset;
}

static int dissect_BISPDU_RIB_REFRESH(tvbuff_t * tvb, packet_info *pinfo, int offset, proto_tree * tree)
{
    proto_tree *sub_tree;
    proto_item *sub_item;
    guint8      number_of_non_empty_rib_attributes;
    guint8      number_of_distinguishing_attributes;
    guint8      rib_attribute_type;
    guint8      length_indicator_guint8;
    int         i;
    int         j;

    /* 1 octet Opcode */
    proto_tree_add_item(tree, hf_idrp_rib_refresh_opcode, tvb, offset, 1,
            ENC_BIG_ENDIAN);
    offset += 1;

    /* Path Attributes subtree */
    sub_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_idrp_sub, &sub_item, "Path Attributes");

    /* Number of Non-empty RIB-Atts */
    number_of_non_empty_rib_attributes = tvb_get_guint8(tvb, offset);
    offset += 1;

    if (!number_of_non_empty_rib_attributes)
        expert_add_info(pinfo, sub_item, &ei_idrp_no_path_attributes);

    /* process Nth RIB-Atts */
    for (i = number_of_non_empty_rib_attributes; i > 0; i--) {

        /* 1 octet number of distinguishing attributes that are contained in
           the Nth RIB-Att. */
        number_of_distinguishing_attributes = tvb_get_guint8(tvb, offset);
        offset += 1;

        /* process Nth RIB-Att */
        for (j = number_of_distinguishing_attributes; j > 0; j--) {
            /* 1 octet Type of RIB-Att */
            rib_attribute_type = tvb_get_guint8(tvb, offset);
            offset += 1;

            switch (rib_attribute_type) {
                case IDRP_PATH_ATTR_TYPE_ROUTE_SEPARATOR:
                case IDRP_PATH_ATTR_TYPE_EXT_INFO:
                case IDRP_PATH_ATTR_TYPE_RD_PATH:
                case IDRP_PATH_ATTR_TYPE_NEXT_HOP:
                case IDRP_PATH_ATTR_TYPE_DIST_LIST_EXCL:
                case IDRP_PATH_ATTR_TYPE_DIST_LIST_INCL:
                case IDRP_PATH_ATTR_TYPE_MULTI_EXIT_DISC:
                case IDRP_PATH_ATTR_TYPE_RESIDUAL_ERROR:
                case IDRP_PATH_ATTR_TYPE_EXPENSE:
                case IDRP_PATH_ATTR_TYPE_HIERARCHICALRECORDING:
                case IDRP_PATH_ATTR_TYPE_RD_HOP_COUNT:
                case IDRP_PATH_ATTR_TYPE_CAPACITY:
                case IDRP_PATH_ATTR_TYPE_PRIORITY:
                    break;
                case IDRP_PATH_ATTR_TYPE_LOCALLY_DEFINED_QOS:
                    /* 1 octet Nsap prefix length */
                    length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                    offset += 1;
                    /* process Nsap prefix */
                    proto_tree_add_item(
                            sub_tree,
                            hf_idrp_rib_refresh_rib_attr_locally_defined_qos_nsap,
                            tvb,
                            offset,
                            length_indicator_guint8,
                            ENC_NA);
                    offset += length_indicator_guint8;

                    /* 1 octet Qos length */
                    length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                    offset += 1;
                    /* process Qos */
                    proto_tree_add_item(
                            sub_tree,
                            hf_idrp_rib_refresh_rib_attr_locally_defined_qos_value,
                            tvb,
                            offset,
                            length_indicator_guint8,
                            ENC_NA);
                    offset += length_indicator_guint8;

                    /* 1 octet Metric length */
                    /* note: metric  always absent in OPEN BISPDU */
                    length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                    offset += 1;
                    /* process Metric */
                    proto_tree_add_item(
                            sub_tree,
                            hf_idrp_rib_refresh_rib_attr_locally_defined_qos_metric,
                            tvb,
                            offset,
                            length_indicator_guint8,
                            ENC_NA);
                    offset += length_indicator_guint8;
                    break;
                case IDRP_PATH_ATTR_TYPE_SECURITY:
                    /* length of Security Registration ID and Security Information */
                    offset += 2;

                    /* length of Security Registration ID */
                    length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                    offset += 1;
                    /* value of Security Registration ID */
                    proto_tree_add_item(
                            sub_tree,
                            hf_idrp_rib_refresh_rib_attr_security_reg_id,
                            tvb,
                            offset,
                            length_indicator_guint8,
                            ENC_NA);
                    offset += length_indicator_guint8;

                    /* length of Security Information */
                    /* note: always absent for OPEN BISPDU*/
                    length_indicator_guint8 = tvb_get_guint8(tvb, offset);
                    offset += 1;
                    /* value of Security Information */
                    proto_tree_add_item(
                            sub_tree,
                            hf_idrp_rib_refresh_rib_attr_security_info,
                            tvb,
                            offset,
                            length_indicator_guint8,
                            ENC_NA);
                    offset += length_indicator_guint8;

                    break;
                default:
                    break;
            } /* switch (path_attr_type) */
        }
    }
    return offset;
}

static int
dissect_idrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *idrp_tree;
    guint8      pdu_type;
    gint        offset = 0;


    if (tvb_get_guint8(tvb, offset) != NLPID_ISO10747_IDRP)
        return 0;  /* no idrp packet */
    offset += 1;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IDRP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_idrp, tvb, 0, -1, ENC_NA);
    idrp_tree = proto_item_add_subtree(ti, ett_idrp);

    /* 2 octets BISPDU Length */
    proto_tree_add_item(idrp_tree, hf_idrp_li,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* 1 octet BISPDU Type */
    pdu_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(idrp_tree, hf_idrp_type,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* 4 octets Sequence */
    proto_tree_add_item(idrp_tree, hf_idrp_sequence,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* 4 octets Acknowledge */
    proto_tree_add_item(idrp_tree, hf_idrp_ack,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* 1 octets credits offered */
    proto_tree_add_item(idrp_tree, hf_idrp_credit_offered,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* 1 octets credits offered */
    proto_tree_add_item(idrp_tree, hf_idrp_credit_avail,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* 16 octets validation */
    proto_tree_add_item(idrp_tree, hf_idrp_validation_pattern,
            tvb, offset, 16, ENC_NA);
    offset += 16;

    switch (pdu_type) {
        case IDRP_TYPE_OPEN:
            offset = dissect_BISPDU_OPEN(tvb, offset, idrp_tree);
            break;
        case IDRP_TYPE_UPDATE:
            offset = dissect_BISPDU_UPDATE(tvb, offset, idrp_tree);
            break;
        case IDRP_TYPE_ERROR:
            offset = dissect_BISPDU_ERROR(tvb, offset, idrp_tree);
            break;
        case IDRP_TYPE_KEEPALIVE:
            /* KEEPALIVE PDU consists of only a PDU header and has a length of 30
               octets */
            offset += 30;
            break;
        case IDRP_TYPE_CEASE:
            /* CEASE is composed a PDU header and has length of 30 octets */
            offset += 30;
            break;
        case IDRP_TYPE_RIB_REFRESH:
            offset = dissect_BISPDU_RIB_REFRESH(tvb, pinfo, offset, idrp_tree);
            break;
        default:
            break;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
            val_to_str(pdu_type, idrp_pdu_types, "Unknown (%u)"));

    return offset;
}


void proto_register_idrp(void)
{
    static hf_register_info hf_idrp[] = {
        {&hf_idrp_li,
            {"BISPDU Length", "idrp.li", FT_UINT16, BASE_DEC, NULL, 0x0,
                "BISPDU Length Indicator, length of this PDU", HFILL}},
        {&hf_idrp_type,
            {"BISPDU Type", "idrp.type", FT_UINT8, BASE_DEC,
                VALS(idrp_pdu_types), 0xff, NULL, HFILL}},
        {&hf_idrp_sequence,
            {"Sequence Number", "idrp.seq", FT_UINT32, BASE_DEC, NULL, 0x0,
                "Sequence number, Sequence number of current BISPDU ", HFILL}},
        {&hf_idrp_ack,
            {"Acknowledgment number", "idrp.ack", FT_UINT32, BASE_DEC, NULL, 0x0,
                "Acknowledgment number, Sequence number of the PDU that the sender last received correctly and in sequence number order",
                HFILL}},
        {&hf_idrp_credit_offered,
            {"Credits Offered", "idrp.credits-offered", FT_UINT8, BASE_DEC,
                NULL, 0,
                "Number of additional BISPDUs that the sender is willing to accept from the remote BIS",
                HFILL}},
        {&hf_idrp_credit_avail,
            {"Credits Available", "idrp.credits-avail", FT_UINT8, BASE_DEC,
                NULL, 0,
                "Number of additional BISPDUs that the sender is able to send to the remote BIS",
                HFILL}},
        {&hf_idrp_validation_pattern,
            {"Validation", "idrp.validation", FT_BYTES, BASE_NONE,
                NULL, 0,
                "16-octet field which provides a validation function for the BISPDU",
                HFILL}},
        {&hf_idrp_open_version,
            {"Version", "idrp.open.version", FT_UINT8, BASE_DEC,
                NULL, 0, "Version number of the protocol.", HFILL}},
        {&hf_idrp_open_hold_time,
            {"Hold Time", "idrp.open.hold-time", FT_UINT16, BASE_DEC,
                NULL, 0, "Max number of seconds to remain in the ESTABLISHED state",
                HFILL}},
        {&hf_idrp_open_max_pdu_size,
            {"Max PDU Size", "idrp.open.max-pdu-size", FT_UINT16, BASE_DEC,
                NULL, 0,
                "Maximum number of octets that this BIS will accept in an incoming UPDATE PDU, IDRP ERROR PDU, or RIB REFRESH PDU",
                HFILL}},
        {&hf_idrp_open_src_rdi,
            {"Source RDI", "idrp.open.src-rdi", FT_BYTES, BASE_NONE,
                NULL, 0,
                "RDI of the routing domain in which the BIS that is sending this BISPDU is located",
                HFILL}},
        {&hf_idrp_open_rib_attr_locally_defined_qos_nsap,
            {"Rib Attribute Value Locally Defined Qos NSAP",
                "idrp.open.rib-attr.locally-defined-qos.nsap", FT_BYTES, BASE_NONE,
                NULL, 0, "Locally Defined Qos NSAP" ,
                HFILL}},
        {&hf_idrp_open_rib_attr_locally_defined_qos_value,
            {"Rib Attribute Value Locally Defined Qos",
                "idrp.open.rib-attr.locally-defined-qos.qos", FT_BYTES, BASE_NONE,
                NULL, 0, "Locally Defined Qos Value" ,
                HFILL}},
        {&hf_idrp_open_rib_attr_locally_defined_qos_metric,
            {"Rib Attribute Value Locally Defined Qos Metric",
                "idrp.open.rib-attr.locally-defined-qos.metric", FT_BYTES, BASE_NONE,
                NULL, 0, "Locally Defined Metric" ,
                HFILL}},
        {&hf_idrp_open_rib_attr_security_reg_id,
            {"Rib Attribute Value Security Registration ID",
                "idrp.open.rib-attr.security.reg-id", FT_BYTES, BASE_NONE,
                NULL, 0, "Identifies the Security Authority" ,
                HFILL}},
        {&hf_idrp_open_rib_attr_security_info,
            {"Rib Attribute Value Security Registration ID",
                "idrp.open.rib-attr.security.info", FT_BYTES, BASE_NONE,
                NULL, 0, "Additional security related information" ,
                HFILL}},
        {&hf_idrp_open_number_of_confederations,
            {"Number of Routing Confederations",
                "idrp.open.number-of-confederations", FT_UINT8, BASE_DEC,
                NULL, 0,
                "Number of Routing Domain Identifiers (Routing Domain Confederation) that this BIS is a member of",
                HFILL}},
        {&hf_idrp_open_confederation,
            {"Routing Confederation", "idrp.open.confederation", FT_BYTES,
                BASE_NONE,
                NULL, 0,
                "Routing Domain Identifier of Routing Domain Confederation that this BIS is a member of",
                HFILL}},
        {&hf_idrp_open_authentication_code,
            {"Authentication Code", "idrp.open.authentication-code", FT_UINT8,
                BASE_DEC,
                VALS(idrp_pdu_open_authentication_codes), 0,
                "Indicates the authentication mechanism being used",
                HFILL}},
        {&hf_idrp_open_authentication_data,
            {"Authentication Data", "idrp.open.authentication-data", FT_BYTES,
                BASE_NONE,
                NULL, 0, "Datat used for optional authentication of a peer BIS", HFILL}},
        {&hf_idrp_update_number_of_unfeasible_routes,
            {"Number of Unfeasible Routes",
                "idrp.update.number-of-unfeasible-routes", FT_UINT16, BASE_DEC,
                NULL, 0,
                "Number of RDIs that are included in the subsequent withdrawn routes field",
                HFILL}},
        {&hf_idrp_update_withdrawn_route,
            {"Unfeasible Route", "idrp.update.unfeasible-route", FT_UINT32,
                BASE_DEC,
                NULL, 0,
                "Route-ID for the route that id being withdrawn from service",
                HFILL}},
        {&hf_idrp_update_path_attr_flag,
            {"Path Attribute Flag", "idrp.update.path-attribute-flag", FT_UINT8,
                BASE_HEX,
                VALS(idrp_path_attr_flags), 0, NULL, HFILL}},
        {&hf_idrp_update_path_attr_type,
            {"Path Attribute Type", "idrp.update.path-attribute-type", FT_UINT8,
                BASE_DEC,
                VALS(path_attr_types), 0, NULL, HFILL}},
        {&hf_idrp_update_path_attr_length,
            {"Path Attribute Length", "idrp.update.path-attribute-length", FT_UINT16,
                BASE_DEC,
                NULL, 0, NULL, HFILL}},
        {&hf_idrp_update_path_attr_route_separator_id,
            {"Path Attribute Value Route Separator Id",
                "idrp.update.path-attr.route-separator.id", FT_UINT32, BASE_DEC,
                NULL, 0,",Route identifier for the advertised route",
                HFILL}},
        {&hf_idrp_update_path_attr_route_separator_localpref,
            {"Path Attribute Value Route Separator Local Pref",
                "idrp.update.path-attr.route-separator.local-pref", FT_UINT8, BASE_DEC,
                NULL, 0,"Contains the local preference value for route",
                HFILL}},
        {&hf_idrp_update_path_attr_ext_info,
            {"Path Attribute Value External Info",
                "idrp.update.path-attr.ext-info",  FT_BOOLEAN, 8,
                NULL, 0,"Flag indicates if routes have been discovered by means of IDRP",
                HFILL}},
        {&hf_idrp_update_path_attr_rd_path_type,
            {"Path Attribute Value RD Path Segment Type",
                "idrp.update.path-attr.rd-path.segment-type",  FT_UINT8, BASE_HEX,
                VALS(path_rd_segment_types), 0, NULL,
                HFILL}},
        {&hf_idrp_update_path_attr_rd_path_segment_length,
            {"Path Attribute Value RD Path Segment Length",
                "idrp.update.path-attr.rd-path.segment-length",  FT_UINT16, BASE_DEC,
                NULL, 0, NULL,
                HFILL}},
        {&hf_idrp_update_path_attr_rd_path_rdi,
            {"Path Attribute Value RD Path Segment RDI",
                "idrp.update.path-attr.rd-path.segment-rdi",  FT_BYTES, BASE_NONE,
                NULL, 0,"RD Path Segment Routing Identifier or Confederation" ,
                HFILL}},
        {&hf_idrp_update_path_attr_next_hop_idrp_server,
            {"Path Attribute Value Next Hop Idrp Server",
                "idrp.update.path-attr.next-hop.idrp-server", FT_UINT8, BASE_DEC,
                NULL, 0, "Permit a BIS to advertise a different or local BISs NET" ,
                HFILL}},
        {&hf_idrp_update_path_attr_next_hop_proto_type,
            {"Path Attribute Value Next Hop Segment Protocol Type",
                "idrp.update.path-attr.next-hop.segment-protp-type",  FT_UINT8, BASE_DEC,
                VALS(idrp_proto_type), 0, NULL ,
                HFILL}},
        {&hf_idrp_update_path_attr_next_hop_proto,
            {"Path Attribute Value Next Hop Segment Protocol",
                "idrp.update.path-attr.next-hop.segment-proto",  FT_UINT8, BASE_DEC,
                NULL, 0, NULL ,
                HFILL}},
        {&hf_idrp_update_path_attr_next_hop_rdi,
            {"Path Attribute Value Next Hop RDI",
                "idrp.update.path-attr.next-hop.rdi", FT_BYTES, BASE_NONE,
                NULL, 0, "NET to advertise as next hop segment" ,
                HFILL}},
        {&hf_idrp_update_path_attr_next_hop_nb_snpa,
            {"Path Attribute Value Next Hop Number of SNPA",
                "idrp.update.path-attr.next-hop.number-snpa", FT_UINT8, BASE_DEC,
                NULL, 0, "Number of SNPA's on next hop segment" ,
                HFILL}},
        {&hf_idrp_update_path_attr_next_hop_snpa,
            {"Path Attribute Value Next Hop SNPA",
                "idrp.update.path-attr.next-hop.snpa", FT_BYTES, BASE_NONE,
                NULL, 0, "SNPA on next hop segment" ,
                HFILL}},
        {&hf_idrp_update_path_attr_dist_list_incl_nb_rdi,
            {"Path Attribute Value Dist List Incl Number of RDIs",
                "idrp.update.path-attr.dist-list-incl.number-rdi", FT_UINT8, BASE_DEC,
                NULL, 0, "Number of RDIs which NLRI information may be distributed" ,
                HFILL}},
        {&hf_idrp_update_path_attr_dist_list_incl_rdi,
            {"Path Attribute Value Dist List Incl RDI",
                "idrp.update.path-attr.dist-list-incl.rdi", FT_BYTES, BASE_NONE,
                NULL, 0, "RDI which NLRI information may be distributed" ,
                HFILL}},
        {&hf_idrp_update_path_attr_dist_list_excl_nb_rdi,
            {"Path Attribute Value Dist List Excl Number of RDIs",
                "idrp.update.path-attr.dist-list-excl.number-rdi", FT_UINT8, BASE_DEC,
                NULL, 0, "Number of RDIs which NLRI information may not be distributed" ,
                HFILL}},
        {&hf_idrp_update_path_attr_dist_list_excl_rdi,
            {"Path Attribute Value Dist List Excl RDI",
                "idrp.update.path-attr.dist-list-excl.rdi", FT_BYTES, BASE_NONE,
                NULL, 0, "RDI which NLRI information may be distributed" ,
                HFILL}},
        {&hf_idrp_update_path_attr_multi_exit_disc,
            {"Path Attribute Value Multi Exit Disc",
                "idrp.update.path-attr.multi-exit-disc", FT_UINT8, BASE_DEC,
                NULL, 0, "Number of exit points to an adjacent domain" ,
                HFILL}},
        {&hf_idrp_update_path_attr_transit_delay,
            {"Path Attribute Value Transit Delay",
                "idrp.update.path-attr.transit-delay", FT_UINT16, BASE_DEC,
                NULL, 0, "Transit Delay" ,
                HFILL}},
        {&hf_idrp_update_path_attr_residual_error,
            {"Path Attribute Value Residual Error",
                "idrp.update.path-attr.residual-error", FT_UINT32, BASE_DEC,
                NULL, 0, "Residual error probability to destination" ,
                HFILL}},
        {&hf_idrp_update_path_attr_expense,
            {"Path Attribute Value Expense",
                "idrp.update.path-attr.expense", FT_UINT16, BASE_DEC,
                NULL, 0, "Expense to destination" ,
                HFILL}},
        {&hf_idrp_update_path_attr_locally_defined_qos_nsap,
            {"Path Attribute Value Locally Defined Qos NSAP",
                "idrp.update.path-attr.locally-defined-qos.nsap", FT_BYTES, BASE_NONE,
                NULL, 0, "Locally Defined Qos NSAP" ,
                HFILL}},
        {&hf_idrp_update_path_attr_locally_defined_qos_value,
            {"Path Attribute Value Locally Defined Qos",
                "idrp.update.path-attr.locally-defined-qos.qos", FT_BYTES, BASE_NONE,
                NULL, 0, "Locally Defined Qos Value" ,
                HFILL}},
        {&hf_idrp_update_path_attr_locally_defined_qos_metric,
            {"Path Attribute Value Locally Defined Qos Metric",
                "idrp.update.path-attr.locally-defined-qos.metric", FT_BYTES, BASE_NONE,
                NULL, 0, "Locally Defined Metric" ,
                HFILL}},
        {&hf_idrp_update_path_attr_hierarchicaldecoding,
            {"Path Attribute Value Hierarchical Decoding",
                "idrp.update.path-attr.hierarchical-decoding", FT_UINT8, BASE_HEX,
                NULL, 0, "Controls the transitivity of NPDUs through the confederation" ,
                HFILL}},
        {&hf_idrp_update_path_attr_rd_hop_count,
            {"Path Attribute Value RD Hop Count",
                "idrp.update.path-attr.rd-hop-count", FT_UINT8, BASE_DEC,
                NULL, 0, "Maximum Hop Count for this Routing Information to travel" ,
                HFILL}},
        {&hf_idrp_update_path_attr_security_reg_id,
            {"Path Attribute Value Security Registration ID",
                "idrp.update.path-attr.security.reg-id", FT_BYTES, BASE_NONE,
                NULL, 0, "Identifies the Security Authority" ,
                HFILL}},
        {&hf_idrp_update_path_attr_security_info,
            {"Path Attribute Value Security Registration ID",
                "idrp.update.path-attr.security.info", FT_BYTES, BASE_NONE,
                NULL, 0, "Additional security related information" ,
                HFILL}},
        {&hf_idrp_update_path_attr_capacity,
            {"Path Attribute Value Capacity",
                "idrp.update.path-attr.capacity", FT_UINT8, BASE_DEC,
                NULL, 0, "Capacity of the RD_PATH for handling traffic" ,
                HFILL}},
        {&hf_idrp_update_path_attr_priority,
            {"Path Attribute Value Capacity",
                "idrp.update.path-attr.capacity", FT_UINT8, BASE_DEC,
                NULL, 0, "Capacity of the RD_PATH for handling traffic" ,
                HFILL}},
        {&hf_idrp_update_nlri_proto_type,
            {"NLRI Protocol Type", "idrp.update.nlri.proto-type", FT_UINT8,
                BASE_DEC,
                VALS(idrp_proto_type), 0, NULL, HFILL}},
        {&hf_idrp_update_nlri_proto_id,
            {"NLRI Protocol Identity", "idrp.update.nlri.proto-id", FT_BYTES,
                BASE_NONE,
                NULL, 0,
                "Identity of the protocol associated with the NLRI address information",
                HFILL}},
        {&hf_idrp_update_nlri_addr_length,
            {"NLRI Address Length",
                "idrp.update.nlri.addr-length.", FT_UINT16, BASE_DEC,
                NULL, 0, NULL ,
                HFILL}},
        {&hf_idrp_update_nlri_addr_info_nb_bits,
            {"NLRI Address Info Bits",
                "idrp.update.nlri.addr-info-bits.", FT_UINT8, BASE_DEC,
                NULL, 0, NULL ,
                HFILL}},
        {&hf_idrp_update_nlri_addr_info,
            {"NLRI Address Info", "idrp.update.nlri.addr-info", FT_BYTES,
                BASE_NONE,
                NULL, 0, "Network Layer Reachability Information Protocol", HFILL}},
        {&hf_idrp_error_code,
            {"Error Code", "idrp.error.code", FT_UINT8, BASE_DEC,
                VALS(idrp_error_codes), 0,
                NULL, HFILL}},
        {&hf_idrp_error_open_subcode,
            {"Error Subcode (Open Message)", "idrp.error.subcode", FT_UINT8,
                BASE_DEC, VALS(idrp_error_open_subcodes),
                0, NULL, HFILL}},
        {&hf_idrp_error_update_subcode,
            {"Error Subcode (Update Message)", "idrp.error.subcode", FT_UINT8,
                BASE_DEC, VALS(idrp_error_update_subcodes),
                0, NULL, HFILL}},
        {&hf_idrp_error_hold_timer_subcode,
            {"Error Subcode (Hold Timer)", "idrp.error.subcode", FT_UINT8,
                BASE_DEC, VALS(idrp_error_hold_timer_subcodes),
                0, NULL, HFILL}},
        {&hf_idrp_error_fsm_subcode,
            {"Error Subcode (Fsm State)", "idrp.error.subcode", FT_UINT8,
                BASE_DEC, VALS(idrp_error_fsm_subcodes),
                0, NULL, HFILL}},
        {&hf_idrp_error_rib_refresh_subcode,
            {"Error Subcode (Rib-Refresh Message)", "idrp.error.subcode",
                FT_UINT8, BASE_DEC, VALS(idrp_error_rib_refresh_subcodes),
                0xff, NULL, HFILL}},
        {&hf_idrp_error_data,
            {"Error Data", "idrp.error.data", FT_BYTES, BASE_NONE, NULL, 0,
                "Diagnosis data that depends upon the error code and error subcode",
                HFILL}},
        {&hf_idrp_rib_refresh_opcode,
            {"Rib Refresh opcode", "idrp.rib-refresh.opcode", FT_UINT8, BASE_DEC,
                VALS(idrp_error_rib_refresh_subcodes),
                0xff, NULL, HFILL}},
        {&hf_idrp_rib_refresh_rib_attr_locally_defined_qos_nsap,
            {"Rib Attribute Value Locally Defined Qos NSAP",
                "idrp.rib-refresh.rib-attr.locally-defined-qos.nsap",
                FT_BYTES, BASE_NONE,
                NULL, 0, "Locally Defined Qos NSAP" ,
                HFILL}},
        {&hf_idrp_rib_refresh_rib_attr_locally_defined_qos_value,
            {"Rib Attribute Value Locally Defined Qos",
                "idrp.rib-refresh.rib-attr.locally-defined-qos.qos",
                FT_BYTES, BASE_NONE,
                NULL, 0, "Locally Defined Qos Value" ,
                HFILL}},
        {&hf_idrp_rib_refresh_rib_attr_locally_defined_qos_metric,
            {"Rib Attribute Value Locally Defined Qos Metric",
                "idrp.rib-refresh.rib-attr.locally-defined-qos.metric",
                FT_BYTES, BASE_NONE,
                NULL, 0, "Locally Defined Metric" ,
                HFILL}},
        {&hf_idrp_rib_refresh_rib_attr_security_reg_id,
            {"Rib Attribute Value Security Registration ID",
                "idrp.rib-refresh.rib-attr.security.reg-id", FT_BYTES, BASE_NONE,
                NULL, 0, "Identifies the Security Authority" ,
                HFILL}},
        {&hf_idrp_rib_refresh_rib_attr_security_info,
            {"Rib Attribute Value Security Registration ID",
                "idrp.rib-refresh.rib-attr.security.info", FT_BYTES, BASE_NONE,
                NULL, 0, "Additional security related information" ,
                HFILL}},
    };

    /* List of subtrees */
    static gint *ett[] = {
        &ett_idrp,
        &ett_idrp_sub
    };

    static ei_register_info ei[] = {
        { &ei_idrp_no_path_attributes, { "idrp.no_path_attributes", PI_PROTOCOL, PI_NOTE, "No path attributes", EXPFILL }},
    };

    expert_module_t* expert_idrp;

    proto_idrp = proto_register_protocol(IDRP_PROTO, "IDRP", "idrp");
    proto_register_field_array(proto_idrp, hf_idrp, array_length(hf_idrp));
    proto_register_subtree_array(ett, array_length(ett));
    expert_idrp = expert_register_protocol(proto_idrp);
    expert_register_field_array(expert_idrp, ei, array_length(ei));
    register_dissector("idrp", dissect_idrp, proto_idrp);

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
