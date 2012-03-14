/* packet-dccp.c
 * Routines for Datagram Congestion Control Protocol, "DCCP" dissection:
 * it should conform to RFC 4340
 *
 * Copyright 2005 _FF_
 *
 * Francesco Fondelli <francesco dot fondelli, gmail dot com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-udp.c
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* NOTES:
 *
 * Nov 13, 2006: makes checksum computation dependent
 * upon the header CsCov field (cf. RFC 4340, 5.1)
 * (Gerrit Renker)
 *
 * Nov 13, 2006: removes the case where checksums are zero
 * (unlike UDP/packet-udp, from which the code stems,
 * zero checksums are illegal in DCCP (as in TCP))
 * (Gerrit Renker)
 *
 * Jan 29, 2007: updates the offsets of the timestamps to be
 * compliant to (cf. RFC 4342, sec. 13).
 * (Gerrit Renker)
 *
 * Mar 11, 2012: add support for RFC 5596 (DCCP-Listen Packet)
 * (Francesco Fondelli)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include "packet-ip.h"
#include <epan/conversation.h>
#include <epan/tap.h>
#include "packet-dccp.h"

/*
 * Some definitions and the dissect_options() logic have been taken
 * from Arnaldo Carvalho de Melo's DCCP implementation, thanks!
 */
#define DCCP_HDR_LEN 16     /* base DCCP header length, with 48 bits seqnums */
#define DCCP_HDR_LEN_MIN 12 /* with 24 bits seqnum */
#define DCCP_HDR_PKT_TYPES_LEN_MAX 12 /* max per packet type extra
                                       * header length
                                       */
#define DCCP_OPT_LEN_MAX 1008
#define DCCP_HDR_LEN_MAX (DCCP_HDR_LEN + DCCP_HDR_PKT_TYPES_LEN_MAX + \
                          DCCP_OPT_LEN_MAX)

/*
 * FF: please keep this list in sync with
 * http://www.iana.org/assignments/dccp-parameters/dccp-parameters.xml
 * Registry Name: 'Packet Types'
 */
static const value_string dccp_packet_type_vals[] = {
    {0x0, "Request" },
    {0x1, "Response"},
    {0x2, "Data"    },
    {0x3, "Ack"     },
    {0x4, "DataAck" },
    {0x5, "CloseReq"},
    {0x6, "Close"   },
    {0x7, "Reset"   },
    {0x8, "Sync"    },
    {0x9, "SyncAck" },
    {0xA, "Listen"  },
    {0xB, "Reserved"},
    {0xC, "Reserved"},
    {0xD, "Reserved"},
    {0xE, "Reserved"},
    {0xF, "Reserved"},
    {0,   NULL      }
};

static const value_string dccp_reset_code_vals[] = {
    {0x00, "Unspecified"       },
    {0x01, "Closed"            },
    {0x02, "Aborted"           },
    {0x03, "No Connection"     },
    {0x04, "Packet Error"      },
    {0x05, "Option Error"      },
    {0x06, "Mandatory Error"   },
    {0x07, "Connection Refused"},
    {0x08, "Bad Service Code"  },
    {0x09, "Too Busy"          },
    {0x0A, "Bad Init Cookie"   },
    {0x0B, "Aggression Penalty"},
    {0x0C, "Reserved"          },
    {0,    NULL                }
};

static const value_string dccp_feature_options_vals[] = {
    {0x20, "Change L" },
    {0x21, "Confirm L"},
    {0x22, "Change R" },
    {0x23, "Confirm R"},
    {0,    NULL       }
};

static const value_string dccp_feature_numbers_vals[] = {
    {0x01, "CCID"                     },
    {0x02, "Allow Short Seqnums"      },
    {0x03, "Sequence Window"          },
    {0x04, "ECN Incapable"            },
    {0x05, "Ack Ratio"                },
    {0x06, "Send Ack Vector"          },
    {0x07, "Send NDP Count"           },
    {0x08, "Minimum Checksum Coverage"},
    {0x09, "Check Data Checksum"      },
    {0xC0, "Send Loss Event Rate"     }, /* CCID3, RFC 4342, 8.5 */
    {0,    NULL                       }
};

static int proto_dccp = -1;
static int dccp_tap = -1;

static int hf_dccp_srcport = -1;
static int hf_dccp_dstport = -1;
static int hf_dccp_port = -1;
static int hf_dccp_data_offset = -1;
static int hf_dccp_ccval = -1;
static int hf_dccp_cscov = -1;
static int hf_dccp_checksum = -1;
static int hf_dccp_checksum_bad = -1;
static int hf_dccp_res1 = -1;
static int hf_dccp_type = -1;
static int hf_dccp_x = -1;
static int hf_dccp_res2 = -1;
static int hf_dccp_seq = -1;

static int hf_dccp_ack_res = -1;
static int hf_dccp_ack = -1;

static int hf_dccp_service_code = -1;
static int hf_dccp_reset_code = -1;
static int hf_dccp_data1 = -1;
static int hf_dccp_data2 = -1;
static int hf_dccp_data3 = -1;

static int hf_dccp_options = -1;
static int hf_dccp_option_type = -1;
static int hf_dccp_feature_number = -1;
static int hf_dccp_ndp_count = -1;
static int hf_dccp_timestamp = -1;
static int hf_dccp_timestamp_echo = -1;
static int hf_dccp_elapsed_time = -1;
static int hf_dccp_data_checksum = -1;

static int hf_dccp_malformed = -1;

static gint ett_dccp = -1;
static gint ett_dccp_options = -1;

static dissector_table_t dccp_subdissector_table;
static heur_dissector_list_t heur_subdissector_list;
static dissector_handle_t data_handle;

/* preferences */
static gboolean dccp_summary_in_tree = TRUE;
static gboolean try_heuristic_first = FALSE;
static gboolean dccp_check_checksum = TRUE;

static void
decode_dccp_ports(tvbuff_t *tvb, int offset, packet_info *pinfo,
                  proto_tree *tree, int sport, int dport)
{
    tvbuff_t *next_tvb;
    int low_port, high_port;

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    /*
     * determine if this packet is part of a conversation and call dissector
     * for the conversation if available
     */
    if (try_conversation_dissector(&pinfo->src, &pinfo->dst, PT_DCCP, sport,
                                   dport, next_tvb, pinfo, tree)) {
        return;
    }

    if (try_heuristic_first) {
        /* do lookup with the heuristic subdissector table */
        if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo,
                                    tree)) {
            return;
        }
    }

    /*
     * Do lookups with the subdissector table.
     * We try the port number with the lower value first, followed by the
     * port number with the higher value.  This means that, for packets
     * where a dissector is registered for *both* port numbers:
     *
     * 1) we pick the same dissector for traffic going in both directions;
     *
     * 2) we prefer the port number that's more likely to be the right
     * one (as that prefers well-known ports to reserved ports);
     *
     * although there is, of course, no guarantee that any such strategy
     * will always pick the right port number.
     * XXX - we ignore port numbers of 0, as some dissectors use a port
     * number of 0 to disable the port.
     */
    if (sport > dport) {
        low_port = dport;
        high_port = sport;
    } else {
        low_port = sport;
        high_port = dport;
    }

    if (low_port != 0 &&
        dissector_try_uint(dccp_subdissector_table, low_port,
                           next_tvb, pinfo, tree)) {
        return;
    }

    if (high_port != 0 &&
        dissector_try_uint(dccp_subdissector_table, high_port,
                           next_tvb, pinfo, tree)) {
        return;
    }

    if (!try_heuristic_first) {
        /* do lookup with the heuristic subdissector table */
        if (dissector_try_heuristic(heur_subdissector_list, next_tvb,
                                    pinfo, tree)) {
            return;
        }
    }

    /* Oh, well, we don't know this; dissect it as data. */
    call_dissector(data_handle, next_tvb, pinfo, tree);
}

/*
 * decode a variable-length number of nbytes starting at offset.  Based on
 * a concept by Arnaldo de Melo
 */
static guint64
tvb_get_ntoh_var(tvbuff_t *tvb, gint offset, guint nbytes)
{
    const guint8 *ptr;
    guint64 value = 0;

    ptr = tvb_get_ptr(tvb, offset, nbytes);
    if (nbytes > 5)
        value += ((guint64) * ptr++) << 40;
    if (nbytes > 4)
        value += ((guint64) * ptr++) << 32;
    if (nbytes > 3)
        value += ((guint64) * ptr++) << 24;
    if (nbytes > 2)
        value += ((guint64) * ptr++) << 16;
    if (nbytes > 1)
        value += ((guint64) * ptr++) << 8;
    if (nbytes > 0)
        value += *ptr;

    return value;
}

static void
dissect_feature_options(proto_tree *dccp_options_tree, tvbuff_t *tvb,
                        int offset, guint8 option_len,
                        guint8 option_type)
{
    guint8 feature_number = tvb_get_guint8(tvb, offset + 2);
    proto_item *dccp_item, *hidden_item;
    int i;

    hidden_item =
        proto_tree_add_uint(dccp_options_tree, hf_dccp_feature_number, tvb,
                            offset + 2, 1, feature_number);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    dccp_item =
        proto_tree_add_text(dccp_options_tree, tvb, offset, option_len, "%s(",
                            val_to_str(option_type,
                                       dccp_feature_options_vals,
                                       "Unknown Type"));

    /*
     * decode the feature according to whether it is server-priority (list)
     * or NN (single number)
     */
    switch (feature_number) {

    /* Server Priority features (RFC 4340, 6.3.1) */

    case 1:       /* Congestion Control ID (CCID); fall through    */
    case 2:       /* Allow Short Seqnums; fall through             */
    case 4:       /* ECN Incapable; fall through                   */
    case 6:       /* Send Ack Vector; fall through                 */
    case 7:       /* Send NDP Count; fall through                  */
    case 8:       /* Minimum Checksum Coverage; fall through       */
    case 9:       /* Check Data Checksum; fall through             */
    case 192:     /* Send Loss Event Rate, RFC 4342, section 8.4   */
        proto_item_append_text(dccp_item, "%s",
                               val_to_str(feature_number,
                                          dccp_feature_numbers_vals,
                                          "Unknown Type"));
        for (i = 0; i < option_len - 3; i++)
            proto_item_append_text(dccp_item, "%s %d", i ? "," : "",
                                   tvb_get_guint8(tvb,
                                                  offset + 3 + i));
        break;

    /* Non-negotiable features (RFC 4340, 6.3.2) */

    case 3:       /* Sequence Window; fall through                 */
    case 5:       /* Ack Ratio                                     */
        proto_item_append_text(dccp_item, "%s",
                               val_to_str(feature_number,
                                          dccp_feature_numbers_vals,
                                          "Unknown Type"));

        if (option_len > 3) /* could be empty Confirm */
            proto_item_append_text(dccp_item, " %" G_GINT64_MODIFIER "u",
                                   tvb_get_ntoh_var(tvb, offset + 3,
                                                    option_len - 3));
        break;

    /* Reserved, specific, or unknown features */
    default:
        if (feature_number == 0 ||
            (feature_number >= 10 && feature_number <= 127))
            proto_item_append_text(dccp_item, "Reserved feature number %d",
                                   feature_number);
        else if (feature_number >= 193)
            proto_item_append_text(dccp_item, "CCID-specific feature number %d",
                                   feature_number);
        else
            proto_item_append_text(dccp_item, "Unknown feature number %d",
                                   feature_number);
        break;
    }
    proto_item_append_text(dccp_item, ")");
}

/*
 * This function dissects DCCP options
 */
static void
dissect_options(tvbuff_t *tvb, packet_info *pinfo _U_,
                proto_tree *dccp_options_tree, proto_tree *tree _U_,
                e_dccphdr *dccph _U_,
                int offset_start,
                int offset_end)
{
    /*
     * if here I'm sure there is at least offset_end - offset_start bytes
     * in tvb and it should be options
     */
    int offset = offset_start;
    guint8 option_type = 0;
    guint8 option_len = 0;
    int i;
    guint32 p;
    proto_item *dccp_item = NULL;
    proto_item *hidden_item;

    while (offset < offset_end) {
        /* first byte is the option type */
        option_type = tvb_get_guint8(tvb, offset);
        hidden_item =
            proto_tree_add_uint(dccp_options_tree, hf_dccp_option_type, tvb,
                                offset,
                                1,
                                option_type);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        if (option_type >= 32) { /* variable length options */
            if (!tvb_bytes_exist(tvb, offset, 1)) {
                hidden_item =
                    proto_tree_add_boolean(dccp_options_tree, hf_dccp_malformed,
                                           tvb, offset, 0, TRUE);
                PROTO_ITEM_SET_HIDDEN(hidden_item);
                THROW(ReportedBoundsError);
            }

            option_len = tvb_get_guint8(tvb, offset + 1);

            if (option_len < 2) {
                hidden_item =
                    proto_tree_add_boolean(dccp_options_tree, hf_dccp_malformed,
                                           tvb, offset, 0, TRUE);
                PROTO_ITEM_SET_HIDDEN(hidden_item);
                THROW(ReportedBoundsError);
            }

            if (!tvb_bytes_exist(tvb, offset, option_len)) {
                hidden_item =
                    proto_tree_add_boolean(dccp_options_tree, hf_dccp_malformed,
                                           tvb, offset, 0, TRUE);
                PROTO_ITEM_SET_HIDDEN(hidden_item);
                THROW(ReportedBoundsError);
            }
        } else { /* 1byte options */
            option_len = 1;
        }

        switch (option_type) {
        case 0:
            proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                "Padding");
            break;
        case 1:
            proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                "Mandatory");
            break;
        case 2:
            proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                "Slow Receiver");
            break;
        case 32:
        case 33:
        case 34:
        case 35:
            dissect_feature_options(dccp_options_tree, tvb, offset, option_len,
                                    option_type);
            break;
        case 36:
            dccp_item =
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "Init Cookie(");
            for (i = 0; i < option_len - 2; i++) {
                if (i == 0)
                    proto_item_append_text(dccp_item, "%02x",
                                           tvb_get_guint8(tvb, offset + 2 + i));
                else
                    proto_item_append_text(dccp_item, " %02x",
                                           tvb_get_guint8(tvb, offset + 2 + i));
            }
            proto_item_append_text(dccp_item, ")");
            break;
        case 37:
            if (option_len > 8)
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "NDP Count too long (max 6 bytes)");
            else
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "NDP Count: %" G_GINT64_MODIFIER "u",
                                    tvb_get_ntoh_var(tvb, offset + 2,
                                                     option_len - 2));
            break;
        case 38:
            dccp_item =
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "Ack Vector [Nonce 0]:");
            for (i = 0; i < option_len - 2; i++)
                proto_item_append_text(dccp_item, " %02x",
                                       tvb_get_guint8(tvb, offset + 2 + i));
            break;
        case 39:
            dccp_item =
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "Ack Vector [Nonce 1]:");
            for (i = 0; i < option_len - 2; i++)
                proto_item_append_text(dccp_item, " %02x",
                                       tvb_get_guint8(tvb, offset + 2 + i));
            proto_item_append_text(dccp_item, ")");
            break;
        case 40:
            dccp_item =
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "Data Dropped:");
            for (i = 0; i < option_len - 2; i++)
                proto_item_append_text(dccp_item, " %02x",
                                       tvb_get_guint8(tvb, offset + 2 + i));
            break;
        case 41:
            if (option_len == 6)
                proto_tree_add_uint(dccp_options_tree, hf_dccp_timestamp, tvb,
                                    offset + 2, 4,
                                    tvb_get_ntohl(tvb, offset + 2));
            else
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "Timestamp too long [%u != 6]", option_len);
            break;
        case 42:
            if (option_len == 6)
                proto_tree_add_uint(dccp_options_tree, hf_dccp_timestamp_echo,
                                    tvb, offset + 2, 4,
                                    tvb_get_ntohl(tvb, offset + 2));
            else if (option_len == 8) {
                proto_tree_add_uint(dccp_options_tree, hf_dccp_timestamp_echo,
                                    tvb, offset + 2, 4,
                                    tvb_get_ntohl(tvb, offset + 2));
                proto_tree_add_uint(dccp_options_tree, hf_dccp_elapsed_time,
                                    tvb, offset + 6, 2,
                                    tvb_get_ntohs(tvb, offset + 6));
            } else if (option_len == 10) {
                proto_tree_add_uint(dccp_options_tree, hf_dccp_timestamp_echo,
                                    tvb, offset + 2, 4,
                                    tvb_get_ntohl(tvb, offset + 2));
                proto_tree_add_uint(dccp_options_tree, hf_dccp_elapsed_time,
                                    tvb, offset + 6, 4,
                                    tvb_get_ntohl(tvb, offset + 6));
            } else
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "Wrong Timestamp Echo length");
            break;
        case 43:
            if (option_len == 4)
                proto_tree_add_uint(dccp_options_tree, hf_dccp_elapsed_time,
                                    tvb, offset + 2, 2,
                                    tvb_get_ntohs(tvb, offset + 2));
            else if (option_len == 6)
                proto_tree_add_uint(dccp_options_tree, hf_dccp_elapsed_time,
                                    tvb, offset + 2, 4,
                                    tvb_get_ntohl(tvb, offset + 2));
            else
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "Wrong Elapsed Time length");
            break;
        case 44:
            if (option_len == 6) {
                proto_tree_add_uint(dccp_options_tree, hf_dccp_data_checksum,
                                    tvb, offset + 2, 4,
                                    tvb_get_ntohl(tvb, offset + 2));
            } else
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "Wrong Data checksum length");
            break;
        case 192: /* RFC 4342, 8.5 */
            if (option_len == 6) {
                p = tvb_get_ntohl(tvb, offset + 2);
                /*
                 * According to the comment in section 8.5 of RFC 4342,
                 * 0xffffffff can mean zero
                 */
                if (p == 0xFFFFFFFF)
                    proto_tree_add_text(dccp_options_tree, tvb, offset,
                                        option_len,
                                        "CCID3 Loss Event Rate: 0 (or max)");
                else
                    proto_tree_add_text(dccp_options_tree, tvb, offset,
                                        option_len, "CCID3 Loss Event Rate: %u",
                                        p);
            } else
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "Wrong CCID3 Loss Event Rate length");
            break;
        case 193: /* RFC 4342, 8.6 */
            proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                "CCID3 Loss Intervals");
            /*
             * FIXME: not implemented and apparently not used by any
             * implementation so far
             */
            break;
        case 194: /* RFC 4342, 8.3 */
            if (option_len == 6)
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "CCID3 Receive Rate: %u bytes/sec",
                                    tvb_get_ntohl(tvb, offset + 2));
            else
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "Wrong CCID3 Receive Rate length");
            break;
        default:
            if (((option_type >= 45) && (option_type <= 127)) ||
                ((option_type >= 3) && (option_type <= 31))) {
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "Reserved");
                break;
            }

            if (option_type >= 128) {
                proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                    "CCID option %d",
                                    option_type);
                break;
            }

            /* if here we don't know this option */
            proto_tree_add_text(dccp_options_tree, tvb, offset, option_len,
                                "Unknown");
            break;
        } /* end switch() */
        offset += option_len; /* move offset past the dissected option */
    } /* end while() */
}

/*
 * compute DCCP checksum coverage according to RFC 4340, section 9
*/
static inline guint
dccp_csum_coverage(const e_dccphdr *dccph, guint len)
{
    guint cov;

    if (dccph->cscov == 0)
        return len;

    cov = (dccph->data_offset + dccph->cscov - 1) * sizeof (guint32);
    return (cov > len) ? len : cov;
}

static void
dissect_dccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *dccp_tree = NULL;
    proto_tree *dccp_options_tree = NULL;
    proto_item *dccp_item = NULL;
    proto_item *hidden_item;

    vec_t cksum_vec[4];
    guint32 phdr[2];
    guint16 computed_cksum;
    guint offset = 0;
    guint len = 0;
    guint reported_len = 0;
    guint advertised_dccp_header_len = 0;
    guint options_len = 0;
    e_dccphdr *dccph;

    /* get at least a full message header */
    if (tvb_length(tvb) < DCCP_HDR_LEN_MIN) {
        if (tree) {
            hidden_item =
                proto_tree_add_boolean(dccp_tree, hf_dccp_malformed, tvb,
                                       offset, 0, TRUE);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        }
        col_set_str(pinfo->cinfo, COL_INFO, "Packet too short");
        THROW(ReportedBoundsError);
    }

    dccph = ep_alloc0(sizeof (e_dccphdr));

    SET_ADDRESS(&dccph->ip_src, pinfo->src.type, pinfo->src.len,
                pinfo->src.data);
    SET_ADDRESS(&dccph->ip_dst, pinfo->dst.type, pinfo->dst.len,
                pinfo->dst.data);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DCCP");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Extract generic header */
    dccph->sport = tvb_get_ntohs(tvb, offset);
    dccph->dport = tvb_get_ntohs(tvb, offset + 2);

    /*
     * update pinfo structure. I guess I have to do it, because this
     * is a transport protocol dissector.
     */
    pinfo->ptype = PT_DCCP;
    pinfo->srcport = dccph->sport;
    pinfo->destport = dccph->dport;

    dccph->data_offset = tvb_get_guint8(tvb, offset + 4);
    dccph->cscov = tvb_get_guint8(tvb, offset + 5) & 0x0F;
    dccph->ccval = tvb_get_guint8(tvb, offset + 5) & 0xF0;
    dccph->ccval >>= 4;
    dccph->checksum = tvb_get_ntohs(tvb, offset + 6);
    dccph->reserved1 = tvb_get_guint8(tvb, offset + 8) & 0xE0;
    dccph->reserved1 >>= 5;
    dccph->type = tvb_get_guint8(tvb, offset + 8) & 0x1E;
    dccph->type >>= 1;
    dccph->x = tvb_get_guint8(tvb, offset + 8) & 0x01;

    if (dccph->x) {
        if (tvb_length(tvb) < DCCP_HDR_LEN) { /* at least 16 bytes */
            hidden_item =
                proto_tree_add_boolean(dccp_tree, hf_dccp_malformed, tvb,
                                       offset, 0, TRUE);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
            THROW(ReportedBoundsError);
        }
        dccph->reserved2 = tvb_get_guint8(tvb, offset + 9);

        dccph->seq = tvb_get_ntohs(tvb, offset + 10);
        dccph->seq <<= 32;
        dccph->seq += tvb_get_ntohl(tvb, offset + 12);
    } else {
        dccph->seq = tvb_get_guint8(tvb, offset + 9);
        dccph->seq <<= 16;
        dccph->seq += tvb_get_ntohs(tvb, offset + 10);
    }

    col_add_fstr(pinfo->cinfo, COL_INFO,
                 "%s > %s [%s] Seq=%" G_GINT64_MODIFIER "u",
                 get_dccp_port(dccph->sport),
                 get_dccp_port(dccph->dport),
                 val_to_str(dccph->type, dccp_packet_type_vals, "Unknown Type"),
                 dccph->seq);

    if (tree) {
        if (dccp_summary_in_tree) {
            dccp_item =
                proto_tree_add_protocol_format(
                    tree, proto_dccp, tvb, offset, dccph->data_offset * 4,
                    "Datagram Congestion Control Protocol, Src Port: %s (%u),"
                    " Dst Port: %s (%u)"
                    " [%s] Seq=%" G_GINT64_MODIFIER "u",
                    get_dccp_port(dccph->sport), dccph->sport,
                    get_dccp_port(dccph->dport), dccph->dport,
                    val_to_str(dccph->type, dccp_packet_type_vals,
                               "Unknown Type"),
                    dccph->seq);
        } else {
            dccp_item = proto_tree_add_item(tree, proto_dccp, tvb, offset, 8,
                                            ENC_NA);
        }

        dccp_tree = proto_item_add_subtree(dccp_item, ett_dccp);

        proto_tree_add_uint_format_value(dccp_tree, hf_dccp_srcport, tvb,
                                         offset, 2, dccph->sport,
                                         "%s (%u)",
                                         get_dccp_port(dccph->sport),
                                         dccph->sport);
        proto_tree_add_uint_format_value(dccp_tree, hf_dccp_dstport, tvb,
                                         offset + 2, 2, dccph->dport,
                                         "%s (%u)",
                                         get_dccp_port(dccph->dport),
                                         dccph->dport);
        hidden_item =
            proto_tree_add_uint(dccp_tree, hf_dccp_port, tvb, offset, 2,
                                dccph->sport);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        hidden_item =
            proto_tree_add_uint(dccp_tree, hf_dccp_port, tvb, offset + 2, 2,
                                dccph->dport);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        proto_tree_add_uint(dccp_tree, hf_dccp_data_offset, tvb, offset + 4, 1,
                            dccph->data_offset);
        proto_tree_add_uint(dccp_tree, hf_dccp_ccval, tvb, offset + 5, 1,
                            dccph->ccval);
        proto_tree_add_uint(dccp_tree, hf_dccp_cscov, tvb, offset + 5, 1,
                            dccph->cscov);

        /*
         * checksum analysis taken from packet-udp (difference: mandatory
         * checksums in DCCP)
         */
        reported_len = tvb_reported_length(tvb);
        len = tvb_length(tvb);

        if (!pinfo->fragmented && len >= reported_len) {
            /* The packet isn't part of a fragmented datagram and isn't
             * truncated, so we can checksum it.
             * XXX - make a bigger scatter-gather list once we do fragment
             * reassembly? */
            if (dccp_check_checksum) {
                /* Set up the fields of the pseudo-header. */
                cksum_vec[0].ptr = pinfo->src.data;
                cksum_vec[0].len = pinfo->src.len;
                cksum_vec[1].ptr = pinfo->dst.data;
                cksum_vec[1].len = pinfo->dst.len;
                cksum_vec[2].ptr = (const guint8 *) &phdr;
                switch (pinfo->src.type) {
                case AT_IPv4:
                    phdr[0] = g_htonl((IP_PROTO_DCCP << 16) + reported_len);
                    cksum_vec[2].len = 4;
                    break;
                case AT_IPv6:
                    phdr[0] = g_htonl(reported_len);
                    phdr[1] = g_htonl(IP_PROTO_DCCP);
                    cksum_vec[2].len = 8;
                    break;

                default:
                    /* DCCP runs only atop IPv4 and IPv6... */
                    break;
                }
                cksum_vec[3].ptr = tvb_get_ptr(tvb, offset, len);
                cksum_vec[3].len = dccp_csum_coverage(dccph, reported_len);
                computed_cksum = in_cksum(&cksum_vec[0], 4);
                if (computed_cksum == 0) {
                    proto_tree_add_uint_format_value(dccp_tree,
                                                     hf_dccp_checksum, tvb,
                                                     offset + 6, 2,
                                                     dccph->checksum,
                                                     "0x%04x [correct]",
                                                     dccph->checksum);
                } else {
                    hidden_item =
                        proto_tree_add_boolean(dccp_tree, hf_dccp_checksum_bad,
                                               tvb, offset + 6, 2, TRUE);;
                    PROTO_ITEM_SET_HIDDEN(hidden_item);
                    proto_tree_add_uint_format_value(
                        dccp_tree, hf_dccp_checksum, tvb, offset + 6, 2,
                        dccph->checksum,
                        "0x%04x [incorrect, should be 0x%04x]",
                        dccph->checksum,
                        in_cksum_shouldbe(dccph->checksum, computed_cksum));
                }
            } else {
                proto_tree_add_uint_format_value(dccp_tree, hf_dccp_checksum,
                                                 tvb,
                                                 offset + 6, 2, dccph->checksum,
                                                 "0x%04x", dccph->checksum);
            }
        } else {
            proto_tree_add_uint_format_value(dccp_tree, hf_dccp_checksum, tvb,
                                             offset + 6, 2, dccph->checksum,
                                             "0x%04x", dccph->checksum);
        }

        hidden_item =
            proto_tree_add_uint(dccp_tree, hf_dccp_res1, tvb, offset + 8, 1,
                                dccph->reserved1);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        proto_tree_add_uint(dccp_tree, hf_dccp_type, tvb, offset + 8, 1,
                            dccph->type);
        proto_tree_add_boolean(dccp_tree, hf_dccp_x, tvb, offset + 8, 1,
                               dccph->x);
        if (dccph->x) {
            hidden_item =
                proto_tree_add_uint(dccp_tree, hf_dccp_res2, tvb, offset + 9, 1,
                                    dccph->reserved2);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
            proto_tree_add_uint64(dccp_tree, hf_dccp_seq, tvb, offset + 10, 6,
                                  dccph->seq);
        } else {
            proto_tree_add_uint64(dccp_tree, hf_dccp_seq, tvb, offset + 9, 3,
                                  dccph->seq);
        }
    }

    if (dccph->x)
        offset += 16; /* move offset past the extended Generic header */
    else
        offset += 12; /* move offset past the not extended Generic header */

    /* dissecting type dependant additional fields */
    switch (dccph->type) {
    case 0x0: /* DCCP-Request */
    case 0xA: /* DCCP-Listen */
        if (!tvb_bytes_exist(tvb, offset, 4)) { /* at least 4 byte */
            if (tree)
                proto_tree_add_text(dccp_tree, tvb, offset, -1,
                                    "too short packet");
            return;
        }
        dccph->service_code = tvb_get_ntohl(tvb, offset);
        if (tree)
            proto_tree_add_uint(dccp_tree, hf_dccp_service_code, tvb, offset, 4,
                                dccph->service_code);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (service=%u)",
                        dccph->service_code);
        offset += 4; /* move offset past the service code */
        break;
    case 0x1: /* DCCP-Response */
        if (!tvb_bytes_exist(tvb, offset, 8)) { /* at least 8 byte */
            if (tree)
                proto_tree_add_text(dccp_tree, tvb, offset, -1,
                                    "too short packet");
            return;
        }
        dccph->ack_reserved = tvb_get_ntohs(tvb, offset);
        if (tree) {
            hidden_item =
                proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset, 2,
                                    dccph->ack_reserved);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        }
        dccph->ack = tvb_get_ntohs(tvb, offset + 2);
        dccph->ack <<= 32;
        dccph->ack += tvb_get_ntohl(tvb, offset + 4);

        if (tree)
            proto_tree_add_uint64(dccp_tree, hf_dccp_ack, tvb, offset + 2, 6,
                                  dccph->ack);
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        " (Ack=%" G_GINT64_MODIFIER "u)",
                        dccph->ack);
        offset += 8; /* move offset past the Acknowledgement Number Subheader */

        if (!tvb_bytes_exist(tvb, offset, 4)) { /* at least 4 byte */
            if (tree)
                proto_tree_add_text(dccp_tree, tvb, offset, -1,
                                    "too short packet");
            return;
        }
        dccph->service_code = tvb_get_ntohl(tvb, offset);
        if (tree)
            proto_tree_add_uint(dccp_tree, hf_dccp_service_code, tvb, offset, 4,
                                dccph->service_code);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (service=%u)",
                        dccph->service_code);

        offset += 4; /* move offset past the service code */
        break;
    case 0x2: /* DCCP-Data */
        /* nothing to dissect */
        break;
    case 0x3: /* DCCP-Ack */
    case 0x4: /* DCCP-DataAck */
        if (dccph->x) {
            if (!tvb_bytes_exist(tvb, offset, 8)) { /* at least 8 byte */
                if (tree)
                    proto_tree_add_text(dccp_tree, tvb, offset, -1,
                                        "too short packet");
                return;
            }
            dccph->ack_reserved = tvb_get_ntohs(tvb, offset);
            if (tree) {
                hidden_item =
                    proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset,
                                        2, dccph->ack_reserved);
                PROTO_ITEM_SET_HIDDEN(hidden_item);
            }
            dccph->ack = tvb_get_ntohs(tvb, offset + 2);
            dccph->ack <<= 32;
            dccph->ack += tvb_get_ntohl(tvb, offset + 4);
            if (tree)
                proto_tree_add_uint64(dccp_tree, hf_dccp_ack, tvb, offset + 2,
                                      6, dccph->ack);
            col_append_fstr(pinfo->cinfo, COL_INFO,
                            " (Ack=%" G_GINT64_MODIFIER "u)",
                            dccph->ack);
            offset += 8; /* move offset past the Ack Number Subheader */
        } else {
            if (!tvb_bytes_exist(tvb, offset, 4)) { /* at least 4 byte */
                if (tree)
                    proto_tree_add_text(dccp_tree, tvb, offset, -1,
                                        "too short packet");
                return;
            }
            dccph->ack_reserved = tvb_get_guint8(tvb, offset);
            if (tree) {
                hidden_item =
                    proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset,
                                        1, dccph->ack_reserved);
                PROTO_ITEM_SET_HIDDEN(hidden_item);
            }
            dccph->ack = tvb_get_guint8(tvb, offset + 1);
            dccph->ack <<= 16;
            dccph->ack += tvb_get_ntohs(tvb, offset + 2);
            if (tree)
                proto_tree_add_uint64(dccp_tree, hf_dccp_ack, tvb, offset + 1,
                                      3, dccph->ack);
            col_append_fstr(pinfo->cinfo, COL_INFO,
                            " (Ack=%" G_GINT64_MODIFIER "u)", dccph->ack);
            offset += 4; /* move offset past the Ack. Number Subheader */
        }
        break;
    case 0x7: /* DCCP-Reset */
        if (!tvb_bytes_exist(tvb, offset, 8)) { /* at least 8 byte */
            if (tree)
                proto_tree_add_text(dccp_tree, tvb, offset, -1,
                                    "too short packet");
            return;
        }

        dccph->ack_reserved = tvb_get_ntohs(tvb, offset);

        if (tree) {
            hidden_item =
                proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset, 2,
                                    dccph->ack_reserved);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        }

        dccph->ack = tvb_get_ntohs(tvb, offset + 2);
        dccph->ack <<= 32;
        dccph->ack += tvb_get_ntohl(tvb, offset + 4);

        if (tree)
            proto_tree_add_uint64(dccp_tree, hf_dccp_ack, tvb, offset + 2, 6,
                                  dccph->ack);
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        " (Ack=%" G_GINT64_MODIFIER "u)", dccph->ack);
        offset += 8; /* move offset past the Ack. Number Subheader */

        dccph->reset_code = tvb_get_guint8(tvb, offset);
        dccph->data1 = tvb_get_guint8(tvb, offset + 1);
        dccph->data2 = tvb_get_guint8(tvb, offset + 2);
        dccph->data3 = tvb_get_guint8(tvb, offset + 3);

        if (tree) {
            proto_tree_add_uint(dccp_tree, hf_dccp_reset_code, tvb, offset, 1,
                                dccph->reset_code);
            proto_tree_add_uint(dccp_tree, hf_dccp_data1, tvb, offset + 1, 1,
                                dccph->data1);
            proto_tree_add_uint(dccp_tree, hf_dccp_data2, tvb, offset + 2, 1,
                                dccph->data2);
            proto_tree_add_uint(dccp_tree, hf_dccp_data3, tvb, offset + 3, 1,
                                dccph->data3);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, " (code=%s)",
                        val_to_str(dccph->reset_code, dccp_reset_code_vals,
                                   "Unknown"));

        offset += 4; /* move offset past the Reset Code and data123 */
        break;
    case 0x5: /* DCCP-CloseReq */
    case 0x6: /* DCCP-Close */
    case 0x8: /* DCCP-Sync */
    case 0x9: /* DCCP-SyncAck */
        if (!tvb_bytes_exist(tvb, offset, 8)) { /* at least 8 byte */
            if (tree)
                proto_tree_add_text(dccp_tree, tvb, offset, -1,
                                    "too short packet");
            return;
        }
        dccph->ack_reserved = tvb_get_ntohs(tvb, offset);
        if (tree) {
            hidden_item =
                proto_tree_add_uint(dccp_tree, hf_dccp_ack_res, tvb, offset, 2,
                                    dccph->ack_reserved);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        }
        dccph->ack = tvb_get_ntohs(tvb, offset + 2);
        dccph->ack <<= 32;
        dccph->ack += tvb_get_ntohl(tvb, offset + 4);
        if (tree)
            proto_tree_add_uint64(dccp_tree, hf_dccp_ack, tvb, offset + 2, 6,
                                  dccph->ack);
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        " (Ack=%" G_GINT64_MODIFIER "u)", dccph->ack);
        offset += 8; /* move offset past the Ack. Number Subheader */
        break;
    default:
        if (tree)
            proto_tree_add_text(
                dccp_tree, tvb, offset, -1,
                "Reserved packet type: unable to dissect further");
        return;
    }

    /*
     * note: data_offset is the offset from the start of the packet's
     * DCCP header to the start of its application data area, in 32-bit words.
     */

    /* it's time to do some checks */
    advertised_dccp_header_len = dccph->data_offset * 4;
    options_len = advertised_dccp_header_len - offset;

    if (advertised_dccp_header_len > DCCP_HDR_LEN_MAX) {
        if (tree)
            proto_tree_add_text(
                dccp_tree, tvb, 4, 2,
                "bogus data offset, advertised header length (%d) is "
                "larger than max (%d)",
                advertised_dccp_header_len, DCCP_HDR_LEN_MAX);
        return;
    }

    if (tvb_length(tvb) < advertised_dccp_header_len) {
        if (tree)
            proto_tree_add_text(
                dccp_tree, tvb, offset, -1,
                "too short packet: missing %d bytes of DCCP header",
                advertised_dccp_header_len -
                tvb_reported_length_remaining(tvb, offset));
        return;
    }

    if (options_len > DCCP_OPT_LEN_MAX) {
        if (tree) {
            hidden_item =
                proto_tree_add_boolean(dccp_tree, hf_dccp_malformed, tvb,
                                       offset, 0, TRUE);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        }
        THROW(ReportedBoundsError);
    }

    /*
     * Dissecting Options (if here we have at least
     * (advertised_dccp_header_len - offset) bytes of options)
     */
    if (advertised_dccp_header_len == offset) {
        ; /* ok no options, no need to move the offset forward */
    } else if (advertised_dccp_header_len < offset) {
        if (tree) {
            proto_tree_add_text(
                dccp_tree, tvb, 4, 2,
                "bogus data offset, advertised header length (%d) is "
                "shorter than expected",
                advertised_dccp_header_len);
            hidden_item =
                proto_tree_add_boolean(dccp_tree, hf_dccp_malformed, tvb,
                                       offset, 0, TRUE);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        }
        THROW(ReportedBoundsError);
    } else {
        if (dccp_tree) {
            dccp_item =
                proto_tree_add_none_format(dccp_tree, hf_dccp_options, tvb,
                                           offset,
                                           options_len, "Options: (%u bytes)",
                                           options_len);
            dccp_options_tree = proto_item_add_subtree(dccp_item,
                                                       ett_dccp_options);
        }
        dissect_options(tvb, pinfo, dccp_options_tree, tree, dccph, offset,
                        offset + options_len);
    }

    offset += options_len; /* move offset past the Options */

    /* queuing tap data */
    tap_queue_packet(dccp_tap, pinfo, dccph);

    /* call sub-dissectors */
    if (!pinfo->flags.in_error_pkt || tvb_length_remaining(tvb, offset) > 0)
        decode_dccp_ports(tvb, offset, pinfo, tree, dccph->sport, dccph->dport);
}

void
proto_register_dccp(void)
{
    module_t *dccp_module;

    static hf_register_info hf[] = {
        {
            &hf_dccp_srcport,
            {
                "Source Port", "dccp.srcport",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_dstport,
            {
                "Destination Port", "dccp.dstport",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_port,
            {
                "Source or Destination Port", "dccp.port",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_data_offset,
            {
                "Data Offset", "dccp.data_offset",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_ccval,
            {
                "CCVal", "dccp.ccval",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_cscov,
            {
                "Checksum Coverage", "dccp.cscov",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_checksum_bad,
            {
                "Bad Checksum", "dccp.checksum_bad",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_checksum,
            {
                "Checksum", "dccp.checksum",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_res1,
            {
                "Reserved", "dccp.res1",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_res2,
            {
                "Reserved", "dccp.res2",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_type,
            {
                "Type", "dccp.type",
                FT_UINT8, BASE_DEC, VALS(dccp_packet_type_vals), 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_x,
            {
                "Extended Sequence Numbers", "dccp.x",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_seq,
            {
                "Sequence Number", "dccp.seq",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_ack_res,
            {
                "Reserved", "dccp.ack_res",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_ack,
            {
                "Acknowledgement Number", "dccp.ack",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_service_code,
            {
                "Service Code", "dccp.service_code",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_reset_code,
            {
                "Reset Code", "dccp.reset_code",
                FT_UINT8, BASE_DEC, VALS(dccp_reset_code_vals), 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_data1,
            {
                "Data 1", "dccp.data1",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_data2,
            {
                "Data 2", "dccp.data2",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_data3,
            {
                "Data 3", "dccp.data3",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_option_type,
            {
                "Option Type", "dccp.option_type",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_feature_number,
            {
                "Feature Number", "dccp.feature_number",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_ndp_count,
            {
                "NDP Count", "dccp.ndp_count",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_timestamp,
            {
                "Timestamp", "dccp.timestamp",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_timestamp_echo,
            {
                "Timestamp Echo", "dccp.timestamp_echo",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_elapsed_time,
            {
                "Elapsed Time", "dccp.elapsed_time",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_data_checksum,
            {
                "Data Checksum", "dccp.checksum_data",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_malformed,
            {
                "Malformed", "dccp.malformed",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_dccp_options,
            {
                "Options", "dccp.options",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "DCCP Options fields", HFILL
            }
        }
    };

    static gint *ett[] = {
        &ett_dccp,
        &ett_dccp_options
    };

    proto_dccp =
        proto_register_protocol("Datagram Congestion Control Protocol", "DCCP",
                                "dccp");
    proto_register_field_array(proto_dccp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* subdissectors */
    dccp_subdissector_table =
        register_dissector_table("dccp.port", "DCCP port", FT_UINT16,
                                 BASE_DEC);
    register_heur_dissector_list("dccp", &heur_subdissector_list);

    /* reg preferences */
    dccp_module = prefs_register_protocol(proto_dccp, NULL);
    prefs_register_bool_preference(
        dccp_module, "summary_in_tree",
        "Show DCCP summary in protocol tree",
        "Whether the DCCP summary line should be shown in the protocol tree",
        &dccp_summary_in_tree);

    prefs_register_bool_preference(
        dccp_module, "try_heuristic_first",
        "Try heuristic sub-dissectors first",
        "Try to decode a packet using an heuristic sub-dissector before "
        "using a sub-dissector "
        "registered to a specific port",
        &try_heuristic_first);

    prefs_register_bool_preference(
        dccp_module, "check_checksum",
        "Check the validity of the DCCP checksum when possible",
        "Whether to check the validity of the DCCP checksum",
        &dccp_check_checksum);
}

void
proto_reg_handoff_dccp(void)
{
    dissector_handle_t dccp_handle;

    dccp_handle = create_dissector_handle(dissect_dccp, proto_dccp);
    dissector_add_uint("ip.proto", IP_PROTO_DCCP, dccp_handle);
    data_handle = find_dissector("data");
    dccp_tap = register_tap("dccp");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
