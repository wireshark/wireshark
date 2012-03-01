/* packet-mpls-pm.c
 *
 * Routines for MPLS delay and loss measurement: it should conform
 * to RFC 6374.  'PM' stands for Performance Measurement.
 *
 * Copyright 2012 _FF_
 *
 * Francesco Fondelli <francesco dot fondelli, gmail dot com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <glib.h>

#include <epan/packet.h>
#include <packet-ip.h>

/* message control flags */
#define MPLS_PM_FLAGS_R    0x08
#define MPLS_PM_FLAGS_T    0x04
#define MPLS_PM_FLAGS_RES  0x03
#define MPLS_PM_FLAGS_MASK 0x0F

/* data format flags */
#define MPLS_PM_DFLAGS_X    0x80
#define MPLS_PM_DFLAGS_B    0x40
#define MPLS_PM_DFLAGS_RES  0x30
#define MPLS_PM_DFLAGS_MASK 0xF0

static gint proto_mpls_pm_dlm = -1;
static gint proto_mpls_pm_ilm = -1;
static gint proto_mpls_pm_dm = -1;
static gint proto_mpls_pm_dlm_dm = -1;
static gint proto_mpls_pm_ilm_dm = -1;

static gint ett_mpls_pm = -1;
static gint ett_mpls_pm_flags = -1;
static gint ett_mpls_pm_dflags = -1;

static int hf_mpls_pm_version = -1;
static int hf_mpls_pm_flags = -1;
static int hf_mpls_pm_flags_r = -1;
static int hf_mpls_pm_flags_t = -1;
static int hf_mpls_pm_flags_res = -1;
static int hf_mpls_pm_query_ctrl_code = -1;
static int hf_mpls_pm_response_ctrl_code = -1;
static int hf_mpls_pm_length = -1;
static int hf_mpls_pm_dflags = -1;
static int hf_mpls_pm_dflags_x = -1;
static int hf_mpls_pm_dflags_b = -1;
static int hf_mpls_pm_dflags_res = -1;
static int hf_mpls_pm_otf = -1;
static int hf_mpls_pm_session_id = -1;
static int hf_mpls_pm_ds = -1;
static int hf_mpls_pm_origin_timestamp_null = -1;
static int hf_mpls_pm_origin_timestamp_seq = -1;
static int hf_mpls_pm_origin_timestamp_ntp = -1;
static int hf_mpls_pm_origin_timestamp_ptp = -1;
static int hf_mpls_pm_origin_timestamp_unk = -1;
static int hf_mpls_pm_counter1 = -1;
static int hf_mpls_pm_counter2 = -1;
static int hf_mpls_pm_counter3 = -1;
static int hf_mpls_pm_counter4 = -1;
static int hf_mpls_pm_qtf = -1;
static int hf_mpls_pm_qtf_combined = -1;
static int hf_mpls_pm_rtf = -1;
static int hf_mpls_pm_rtf_combined = -1;
static int hf_mpls_pm_rptf = -1;
static int hf_mpls_pm_rptf_combined = -1;
static int hf_mpls_pm_timestamp1_q_null = -1;
static int hf_mpls_pm_timestamp1_r_null = -1;
static int hf_mpls_pm_timestamp1_q_seq = -1;
static int hf_mpls_pm_timestamp1_r_seq = -1;
static int hf_mpls_pm_timestamp1_q_ntp = -1;
static int hf_mpls_pm_timestamp1_r_ntp = -1;
static int hf_mpls_pm_timestamp1_q_ptp = -1;
static int hf_mpls_pm_timestamp1_r_ptp = -1;
static int hf_mpls_pm_timestamp1_unk = -1;
static int hf_mpls_pm_timestamp2_null = -1;
static int hf_mpls_pm_timestamp3_null = -1;
static int hf_mpls_pm_timestamp3_r_null = -1;
static int hf_mpls_pm_timestamp3_r_seq = -1;
static int hf_mpls_pm_timestamp3_r_ntp = -1;
static int hf_mpls_pm_timestamp3_r_ptp = -1;
static int hf_mpls_pm_timestamp3_unk = -1;
static int hf_mpls_pm_timestamp4_null = -1;
static int hf_mpls_pm_timestamp4_r_null = -1;
static int hf_mpls_pm_timestamp4_r_seq = -1;
static int hf_mpls_pm_timestamp4_r_ntp = -1;
static int hf_mpls_pm_timestamp4_r_ptp = -1;
static int hf_mpls_pm_timestamp4_unk = -1;

static dissector_handle_t mpls_pm_dlm_handle;
static dissector_handle_t mpls_pm_ilm_handle;
static dissector_handle_t mpls_pm_dm_handle;
static dissector_handle_t mpls_pm_dlm_dm_handle;
static dissector_handle_t mpls_pm_ilm_dm_handle;

/*
 * FF: please keep this list in sync with
 * http://www.iana.org/assignments/mpls-lsp-ping-parameters
 * Registry Name: 'Loss/Delay Measurement Control Code: Query Codes'
 */
const range_string mpls_pm_query_ctrl_code_rvals[] = {
    { 0x00, 0x00, "In-band Response Requested"     },
    { 0x01, 0x01, "Out-of-band Response Requested" },
    { 0x02, 0x02, "No Response Requested"          },
    { 0x03, 0xFF, "Unassigned"                     },
    { 0x00, 0x00, NULL                             }
};

/*
 * FF: please keep this list in sync with
 * http://www.iana.org/assignments/mpls-lsp-ping-parameters
 * Registry Name: 'Loss/Delay Measurement Control Code: Response Codes'
 */
const range_string mpls_pm_response_ctrl_code_rvals[] = {
    { 0x00, 0x00, "Reserved"                            },
    { 0x01, 0x01, "Success"                             },
    { 0x02, 0x02, "Data Format Invalid"                 },
    { 0x03, 0x03, "Initialization in Progress"          },
    { 0x04, 0x04, "Data Reset Occurred"                 },
    { 0x05, 0x05, "Resource Temporarily Unavailable"    },
    { 0x06, 0x0F, "Unassigned"                          },
    { 0x10, 0x10, "Unspecified Error"                   },
    { 0x11, 0x11, "Unsupported Version"                 },
    { 0x12, 0x12, "Unsupported Control Code"            },
    { 0x13, 0x13, "Unsupported Data Format"             },
    { 0x14, 0x14, "Authentication Failure"              },
    { 0x15, 0x15, "Invalid Destination Node Identifier" },
    { 0x16, 0x16, "Connection Mismatch"                 },
    { 0x17, 0x17, "Unsupported Mandatory TLV Object"    },
    { 0x18, 0x18, "Unsupported Query Interval"          },
    { 0x19, 0x19, "Administrative Block"                },
    { 0x1A, 0x1A, "Resource Unavailable"                },
    { 0x1B, 0x1B, "Resource Released"                   },
    { 0x1C, 0x1C, "Invalid Message"                     },
    { 0x1D, 0x1D, "Protocol Error"                      },
    { 0x1E, 0xFF, "Unassigned"                          },
    { 0x00, 0x00, NULL                                  }
};

#define DLM 1
#define ILM 2
#define DM 3
#define DLMDM 4
#define ILMDM 5
/* FF: internal */
static const value_string pmt_vals[] = {
    { DLM,   "DLM"    },
    { ILM,   "ILM"    },
    { DM,    "DM"     },
    { DLMDM, "DLM+DM" },
    { ILMDM, "ILM+DM" },
    {     0, NULL     }
};

/*
 * FF: please keep this list in sync with
 * http://www.iana.org/assignments/mpls-lsp-ping-parameters
 * Registry Name: 'Loss/Delay Measurement Control Code: Response Codes'
 */
#define MPLS_PM_TSF_NULL 0
#define MPLS_PM_TSF_SEQ 1
#define MPLS_PM_TSF_NTP 2
#define MPLS_PM_TSF_PTP 3
const range_string mpls_pm_time_stamp_format_rvals[] = {
    { MPLS_PM_TSF_NULL, MPLS_PM_TSF_NULL,  "Null Timestamp"                                 },
    { MPLS_PM_TSF_SEQ, MPLS_PM_TSF_SEQ,  "Sequence Number"                                  },
    { MPLS_PM_TSF_NTP, MPLS_PM_TSF_NTP,  "Network Time Protocol version 4 64-bit Timestamp" },
    { MPLS_PM_TSF_PTP, MPLS_PM_TSF_PTP,  "Truncated IEEE 1588v2 PTP Timestamp"              },
    { 4, 15, "Unassigned"                                                                   },
    { 0,  0,  NULL                                                                          }
};

static void
mpls_pm_dissect_counter(tvbuff_t *tvb, proto_tree *pm_tree,
                        guint32 offset, gboolean query, gboolean bflag,
                        guint8 i)
{
    proto_item *ti;
    gchar strunitp[] = "packets";
    gchar strunitb[] = "octets";
    /*
     *  FF: when bflag is true, indicates that the Counter 1-4 
     *  fields represent octet counts.  Otherwise Counter 1-4 fields
     *  represent packet counts
     */
    gchar *unit = bflag ? strunitb : strunitp;

    if (query) {
        switch (i) {
        case 1:
            ti = proto_tree_add_item(pm_tree, hf_mpls_pm_counter1, tvb,
                                         offset, 8, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, " %s (A_Tx)", unit);
            break;
        case 2:
            proto_tree_add_item(pm_tree, hf_mpls_pm_counter2, tvb,
                                offset, 8, ENC_BIG_ENDIAN);
            break;
        case 3:
            proto_tree_add_item(pm_tree, hf_mpls_pm_counter3, tvb,
                                offset, 8, ENC_BIG_ENDIAN);
            break;
        case 4:
            proto_tree_add_item(pm_tree, hf_mpls_pm_counter4, tvb,
                                offset, 8, ENC_BIG_ENDIAN);
            break;
        default:
            /* never here */
            break;
        }
    } else {
        /* response */
        switch (i) {
        case 1:
            ti = proto_tree_add_item(pm_tree, hf_mpls_pm_counter1, tvb,
                                         offset, 8, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, " %s (B_Tx)", unit);
            break;
        case 2:
            proto_tree_add_item(pm_tree, hf_mpls_pm_counter2, tvb,
                                offset, 8, ENC_BIG_ENDIAN);
            break;
        case 3:
            ti = proto_tree_add_item(pm_tree, hf_mpls_pm_counter3, tvb,
                                         offset, 8, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, " %s (A_Tx)", unit);
            break;
        case 4:
            ti = proto_tree_add_item(pm_tree, hf_mpls_pm_counter4, tvb,
                                         offset, 8, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, " %s (B_Rx)", unit);
            break;
        default:
            /* never here */
            break;
        }
    }
}

static void
mpls_pm_dissect_timestamp(tvbuff_t *tvb, proto_tree *pm_tree,
                          guint32 offset, guint8 qtf, guint8 rtf,
                          gboolean query, guint8 i)
{
    if (query) {
        /*
         * FF: when a query is sent from A, Timestamp 1 is set to T1 and the
         * other timestamp fields are set to 0.
         */
        switch (i) {
        case 1:
            switch (qtf) {
                /*
                 * FF: the actual formats of the timestamp fields written by A
                 * are indicated by the Querier Timestamp Format.
                 */
            case MPLS_PM_TSF_NULL:
                proto_tree_add_item(pm_tree,
                                    hf_mpls_pm_timestamp1_q_null, tvb,
                                    offset, 8, ENC_BIG_ENDIAN);
                break;
            case MPLS_PM_TSF_SEQ:
                proto_tree_add_item(pm_tree, hf_mpls_pm_timestamp1_q_seq, tvb,
                                    offset, 8, ENC_BIG_ENDIAN);
                break;
            case MPLS_PM_TSF_NTP:
                proto_tree_add_item(pm_tree, hf_mpls_pm_timestamp1_q_ntp, tvb,
                                    offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN);
                break;
            case MPLS_PM_TSF_PTP:
                {
                    nstime_t ts;
                    ts.secs = tvb_get_ntohl(tvb, offset);
                    ts.nsecs = tvb_get_ntohl(tvb, offset + 4);
                    proto_tree_add_time(pm_tree, hf_mpls_pm_timestamp1_q_ptp,
                                        tvb, offset, 8, &ts);
                }
                break;
            default:
                proto_tree_add_item(pm_tree, hf_mpls_pm_timestamp1_unk, tvb,
                                    offset, 8, ENC_BIG_ENDIAN);
                break;
            }
            break;
        case 2:
            proto_tree_add_item(pm_tree,
                                hf_mpls_pm_timestamp2_null, tvb,
                                offset, 8, ENC_BIG_ENDIAN);
            break;
        case 3:
            proto_tree_add_item(pm_tree,
                                hf_mpls_pm_timestamp3_null, tvb,
                                offset, 8, ENC_BIG_ENDIAN);
            break;
        case 4:
            proto_tree_add_item(pm_tree,
                                hf_mpls_pm_timestamp4_null, tvb,
                                offset, 8, ENC_BIG_ENDIAN);
            break;
        default:
            /* never here */
            break;
        } /* end of switch (i) */
    } else {
        /*
         * FF: when B transmits the response, Timestamp 1 is set to T3,
         * Timestamp 3 is set to T1 and Timestamp 4 is set to T2.  Timestamp 2
         * is set to 0.
         */
        switch (i) {
        case 1:
            switch (rtf) {
                /*
                 * FF: the actual formats of the timestamp fields written by B
                 * are indicated by the Responder Timestamp Format.
                 */
            case MPLS_PM_TSF_NULL:
                proto_tree_add_item(pm_tree,
                                    hf_mpls_pm_timestamp1_r_null, tvb,
                                    offset, 8, ENC_BIG_ENDIAN);
                break;
            case MPLS_PM_TSF_SEQ:
                proto_tree_add_item(pm_tree, hf_mpls_pm_timestamp1_r_seq, tvb,
                                    offset, 8, ENC_BIG_ENDIAN);
                break;
            case MPLS_PM_TSF_NTP:
                proto_tree_add_item(pm_tree, hf_mpls_pm_timestamp1_r_ntp, tvb,
                                    offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN);
                break;
            case MPLS_PM_TSF_PTP:
                {
                    nstime_t ts;
                    ts.secs = tvb_get_ntohl(tvb, offset);
                    ts.nsecs = tvb_get_ntohl(tvb, offset + 4);
                    proto_tree_add_time(pm_tree, hf_mpls_pm_timestamp1_r_ptp,
                                        tvb, offset, 8, &ts);
                }
                break;
            default:
                proto_tree_add_item(pm_tree, hf_mpls_pm_timestamp1_unk, tvb,
                                    offset, 8, ENC_BIG_ENDIAN);
                break;
            }
            break;
        case 2:
            proto_tree_add_item(pm_tree,
                                hf_mpls_pm_timestamp2_null, tvb,
                                offset, 8, ENC_BIG_ENDIAN);
            break;
        case 3:
            switch (rtf) {
            case MPLS_PM_TSF_NULL:
                proto_tree_add_item(pm_tree,
                                    hf_mpls_pm_timestamp3_r_null, tvb,
                                    offset, 8, ENC_BIG_ENDIAN);
                break;
            case MPLS_PM_TSF_SEQ:
                proto_tree_add_item(pm_tree, hf_mpls_pm_timestamp3_r_seq, tvb,
                                    offset, 8, ENC_BIG_ENDIAN);
                break;
            case MPLS_PM_TSF_NTP:
                proto_tree_add_item(pm_tree, hf_mpls_pm_timestamp3_r_ntp, tvb,
                                    offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN);
                break;
            case MPLS_PM_TSF_PTP:
                {
                    nstime_t ts;
                    ts.secs = tvb_get_ntohl(tvb, offset);
                    ts.nsecs = tvb_get_ntohl(tvb, offset + 4);
                    proto_tree_add_time(pm_tree, hf_mpls_pm_timestamp3_r_ptp,
                                        tvb, offset, 8, &ts);
                }
                break;
            default:
                proto_tree_add_item(pm_tree, hf_mpls_pm_timestamp3_unk, tvb,
                                    offset, 8, ENC_BIG_ENDIAN);
                break;
            }
            break;
        case 4:
            switch (rtf) {
            case MPLS_PM_TSF_NULL:
                proto_tree_add_item(pm_tree,
                                    hf_mpls_pm_timestamp4_r_null, tvb,
                                    offset, 8, ENC_BIG_ENDIAN);
                break;
            case MPLS_PM_TSF_SEQ:
                proto_tree_add_item(pm_tree, hf_mpls_pm_timestamp4_r_seq, tvb,
                                    offset, 8, ENC_BIG_ENDIAN);
                break;
            case MPLS_PM_TSF_NTP:
                proto_tree_add_item(pm_tree, hf_mpls_pm_timestamp4_r_ntp, tvb,
                                    offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN);
                break;
            case MPLS_PM_TSF_PTP:
                {
                    nstime_t ts;
                    ts.secs = tvb_get_ntohl(tvb, offset);
                    ts.nsecs = tvb_get_ntohl(tvb, offset + 4);
                    proto_tree_add_time(pm_tree, hf_mpls_pm_timestamp4_r_ptp,
                                        tvb, offset, 8, &ts);
                }
                break;
            default:
                proto_tree_add_item(pm_tree, hf_mpls_pm_timestamp4_unk, tvb,
                                    offset, 8, ENC_BIG_ENDIAN);
                break;
            }
            break;
        default:
            /* never here */
            break;
        } /* end of switch (i) */
    }
}

static void
mpls_pm_build_cinfo(tvbuff_t *tvb, packet_info *pinfo, const char *str_pmt,
                    gboolean *query, gboolean *response,
                    gboolean *class_specific,
                    guint32 *sid, guint8 *code)
{
    int offset = 0;
    guint8 sid3, sid2, sid1, sid0;

    *response = (tvb_get_guint8(tvb, offset) & 0x08) ? TRUE : FALSE;
    *class_specific = (tvb_get_guint8(tvb, offset) & 0x04) ? TRUE : FALSE;
    *query = !(*response);
    *code = tvb_get_guint8(tvb, offset + 1);

    if (!(*class_specific)) {
        /*
         * FF: when the T flag is set to 0 the DS field can be considered
         * part of the Session Identifier.
         */
        *sid = tvb_get_ntohl(tvb, offset + 8);
    } else {
        sid3 = tvb_get_guint8(tvb, offset + 8);
        sid2 = tvb_get_guint8(tvb, offset + 9);
        sid1 = tvb_get_guint8(tvb, offset + 10);
        sid0 = tvb_get_guint8(tvb, offset + 11) & 0xC0;
        *sid = ((guint32) sid0 >> 6) | ((guint32) sid1 >> 8) |
               ((guint32) sid2 >> 16) | ((guint32) sid3 >> 24);
    }

    col_clear(pinfo->cinfo, COL_PROTOCOL);
    col_clear(pinfo->cinfo, COL_INFO);

    col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "MPLS PM (%s)", str_pmt);

    if (*query) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "Query, sid: %u", *sid);
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "Response, sid: %u, code: %s (%u)",
                     *sid,
                     rval_to_str(*code,
                                 mpls_pm_response_ctrl_code_rvals,
                                 "Unknown"),
                     *code);
    }
}

/* FF: the message formats for direct and inferred LM are identical */
static void
dissect_mpls_pm_loss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     guint8 pmt)
{
    proto_item *ti = NULL;
    proto_tree *pm_tree = NULL;
    proto_tree *pm_tree_flags = NULL;
    proto_tree *pm_tree_dflags = NULL;
    guint32 offset = 0;
    gboolean query = 0;
    gboolean response = 0;
    gboolean class_specific = 0;
    guint32 sid = 0;
    guint8 code = 0;
    guint8 otf = 0;
    gboolean bflag = FALSE;
    guint8 i = 0;

    mpls_pm_build_cinfo(tvb, pinfo,
                        val_to_str(pmt, pmt_vals, ""),
                        &query, &response, &class_specific, &sid, &code);

    if (!tree) {
        return;
    }

    /* create display subtree for the protocol */
    if (pmt == DLM) {
        ti = proto_tree_add_item(tree, proto_mpls_pm_dlm, tvb, 0, -1, ENC_NA);
    } else {
        ti = proto_tree_add_item(tree, proto_mpls_pm_ilm, tvb, 0, -1, ENC_NA);
    }

    pm_tree = proto_item_add_subtree(ti, ett_mpls_pm);

    /* add version to the subtree */
    proto_tree_add_item(pm_tree, hf_mpls_pm_version, tvb, offset, 1, ENC_NA);

    /* ctrl flags subtree */

    ti = proto_tree_add_item(pm_tree, hf_mpls_pm_flags, tvb, offset, 1, ENC_NA);
    pm_tree_flags = proto_item_add_subtree(ti, ett_mpls_pm_flags);
    proto_tree_add_item(pm_tree_flags, hf_mpls_pm_flags_r, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(pm_tree_flags, hf_mpls_pm_flags_t, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(pm_tree_flags, hf_mpls_pm_flags_res, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (query) {
        proto_tree_add_item(pm_tree, hf_mpls_pm_query_ctrl_code,
                            tvb, offset, 1, ENC_NA);
    } else {
        proto_tree_add_item(pm_tree, hf_mpls_pm_response_ctrl_code,
                            tvb, offset, 1, ENC_NA);
    }
    offset += 1;

    proto_tree_add_item(pm_tree, hf_mpls_pm_length, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* data flags subtree */
    ti = proto_tree_add_item(pm_tree, hf_mpls_pm_dflags, tvb, offset, 1, ENC_NA);
    pm_tree_dflags = proto_item_add_subtree(ti, ett_mpls_pm_dflags);
    proto_tree_add_item(pm_tree_dflags, hf_mpls_pm_dflags_x, tvb, offset, 1, ENC_NA);
    bflag = (tvb_get_guint8(tvb, offset) & 0x40) ? TRUE : FALSE;
    proto_tree_add_item(pm_tree_dflags, hf_mpls_pm_dflags_b, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(pm_tree_dflags, hf_mpls_pm_dflags_res, tvb, offset, 1, ENC_NA);

    otf = tvb_get_guint8(tvb, offset) & 0x0F;
    proto_tree_add_item(pm_tree, hf_mpls_pm_otf, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* skip 3 reserved bytes */
    offset += 3;

    proto_tree_add_uint(pm_tree, hf_mpls_pm_session_id, tvb, offset, 4, sid);

    if (class_specific) {
        proto_tree_add_item(pm_tree, hf_mpls_pm_ds, tvb, offset + 3, 1, ENC_NA);
    }
    offset += 4;

    switch (otf) {
    case MPLS_PM_TSF_NULL:
        proto_tree_add_item(pm_tree, hf_mpls_pm_origin_timestamp_null, tvb,
                            offset, 8, ENC_BIG_ENDIAN);
        break;
    case MPLS_PM_TSF_SEQ:
        proto_tree_add_item(pm_tree, hf_mpls_pm_origin_timestamp_seq, tvb,
                            offset, 8, ENC_BIG_ENDIAN);
        break;
    case MPLS_PM_TSF_NTP:
        proto_tree_add_item(pm_tree, hf_mpls_pm_origin_timestamp_ntp, tvb,
                            offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN);
        break;
    case MPLS_PM_TSF_PTP:
        {
            nstime_t ts;
            ts.secs = tvb_get_ntohl(tvb, offset);
            ts.nsecs = tvb_get_ntohl(tvb, offset + 4);
            proto_tree_add_time(pm_tree, hf_mpls_pm_origin_timestamp_ptp, tvb,
                                offset, 8, &ts);
        }
        break;
    default:
        proto_tree_add_item(pm_tree, hf_mpls_pm_origin_timestamp_unk, tvb,
                            offset, 8, ENC_BIG_ENDIAN);
        break;
    }
    offset += 8;
    
    /* counters 1..4 */
    for (i = 1; i <= 4; i++) {
        mpls_pm_dissect_counter(tvb, pm_tree, offset, query, bflag, i);
        offset += 8;
    }
}

static void
dissect_mpls_pm_dlm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* the message formats for direct and inferred LM are identical */
    dissect_mpls_pm_loss(tvb, pinfo, tree, DLM);
}

static void
dissect_mpls_pm_ilm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* the message formats for direct and inferred LM are identical */
    dissect_mpls_pm_loss(tvb, pinfo, tree, ILM);
}

static void
dissect_mpls_pm_delay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *pm_tree = NULL;
    proto_tree *pm_tree_flags = NULL;
    guint32 offset = 0;
    gboolean query = 0;
    gboolean response = 0;
    gboolean class_specific = 0;
    guint32 sid = 0;
    guint8 code = 0;
    guint8 qtf = 0;
    guint8 rtf = 0;
    guint8 i = 0;

    mpls_pm_build_cinfo(tvb, pinfo,
                        "DM",
                        &query, &response, &class_specific, &sid, &code);

    if (!tree) {
        return;
    }

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_mpls_pm_dm, tvb, 0, -1, ENC_NA);
    pm_tree = proto_item_add_subtree(ti, ett_mpls_pm);

    /* add version to the subtree */
    proto_tree_add_item(pm_tree, hf_mpls_pm_version, tvb, offset, 1, ENC_NA);

    /* ctrl flags subtree */
    ti = proto_tree_add_item(pm_tree, hf_mpls_pm_flags, tvb, offset, 1, ENC_NA);
    pm_tree_flags = proto_item_add_subtree(ti, ett_mpls_pm_flags);
    proto_tree_add_item(pm_tree_flags, hf_mpls_pm_flags_r, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(pm_tree_flags, hf_mpls_pm_flags_t, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(pm_tree_flags, hf_mpls_pm_flags_res, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (query) {
        proto_tree_add_item(pm_tree, hf_mpls_pm_query_ctrl_code,
                            tvb, offset, 1, ENC_NA);
    } else {
        proto_tree_add_item(pm_tree, hf_mpls_pm_response_ctrl_code,
                            tvb, offset, 1, ENC_NA);
    }
    offset += 1;

    proto_tree_add_item(pm_tree, hf_mpls_pm_length, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* qtf, rtf */
    qtf = (tvb_get_guint8(tvb, offset) & 0xF0) >> 4;
    proto_tree_add_item(pm_tree, hf_mpls_pm_qtf, tvb,
                        offset, 1, ENC_BIG_ENDIAN);

    rtf = tvb_get_guint8(tvb, offset) & 0x0F;
    proto_tree_add_item(pm_tree, hf_mpls_pm_rtf, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* rptf */
    proto_tree_add_item(pm_tree, hf_mpls_pm_rptf, tvb,
                        offset, 1, ENC_BIG_ENDIAN);

    /* skip 20 reserved bits */
    offset += 3;

    proto_tree_add_uint(pm_tree, hf_mpls_pm_session_id, tvb, offset, 4, sid);

    if (class_specific) {
        proto_tree_add_item(pm_tree, hf_mpls_pm_ds, tvb, offset + 3, 1, ENC_NA);
    }
    offset += 4;

    /* timestamps 1..4 */
    for (i = 1; i <= 4; i++) {
        mpls_pm_dissect_timestamp(tvb, pm_tree, offset, qtf, rtf, query, i);
        offset += 8;
    }
}

static void
dissect_mpls_pm_combined(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         guint8 pmt)
{
    proto_item *ti = NULL;
    proto_tree *pm_tree = NULL;
    proto_tree *pm_tree_flags = NULL;
    proto_tree *pm_tree_dflags = NULL;
    guint32 offset = 0;
    gboolean query = 0;
    gboolean response = 0;
    gboolean class_specific = 0;
    guint32 sid = 0;
    guint8 code = 0;
    guint8 qtf = 0;
    guint8 rtf = 0;
    gboolean bflag = FALSE;
    guint8 i = 0;

    mpls_pm_build_cinfo(tvb, pinfo,
                        val_to_str(pmt, pmt_vals, ""),
                        &query, &response, &class_specific, &sid, &code);

    if (!tree) {
        return;
    }

    /* create display subtree for the protocol */
    if (pmt == DLMDM) {
        ti = proto_tree_add_item(tree, proto_mpls_pm_dlm_dm,
                                 tvb, 0, -1, ENC_NA);
    } else {
        ti = proto_tree_add_item(tree, proto_mpls_pm_ilm_dm,
                                 tvb, 0, -1, ENC_NA);
    }

    pm_tree = proto_item_add_subtree(ti, ett_mpls_pm);

    /* add version to the subtree */
    proto_tree_add_item(pm_tree, hf_mpls_pm_version, tvb, offset, 1, ENC_NA);

    /* ctrl flags subtree */
    ti = proto_tree_add_item(pm_tree, hf_mpls_pm_flags, tvb, offset, 1, ENC_NA);
    pm_tree_flags = proto_item_add_subtree(ti, ett_mpls_pm_flags);
    proto_tree_add_item(pm_tree_flags, hf_mpls_pm_flags_r, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(pm_tree_flags, hf_mpls_pm_flags_t, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(pm_tree_flags, hf_mpls_pm_flags_res, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (query) {
        proto_tree_add_item(pm_tree, hf_mpls_pm_query_ctrl_code,
                            tvb, offset, 1, ENC_NA);
    } else {
        proto_tree_add_item(pm_tree, hf_mpls_pm_response_ctrl_code,
                            tvb, offset, 1, ENC_NA);
    }
    offset += 1;

    proto_tree_add_item(pm_tree, hf_mpls_pm_length, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* data flags subtree */
    ti = proto_tree_add_item(pm_tree, hf_mpls_pm_dflags, tvb, offset, 1, ENC_NA);
    pm_tree_dflags = proto_item_add_subtree(ti, ett_mpls_pm_dflags);
    proto_tree_add_item(pm_tree_dflags, hf_mpls_pm_dflags_x, tvb, offset, 1, ENC_NA);
    bflag = (tvb_get_guint8(tvb, offset) & 0x40) ? TRUE : FALSE;
    proto_tree_add_item(pm_tree_dflags, hf_mpls_pm_dflags_b, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(pm_tree_dflags, hf_mpls_pm_dflags_res, tvb, offset, 1, ENC_NA);

    /*
     * FF: the roles of the OTF and Origin Timestamp fields for LM are
     * here played by the QTF and Timestamp 1 fields, respectively.
     */
    qtf = tvb_get_guint8(tvb, offset) & 0x0F;
    proto_tree_add_item(pm_tree, hf_mpls_pm_qtf_combined, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* rtf, rptf */
    rtf = tvb_get_guint8(tvb, offset) & 0xF0 >> 4;
    proto_tree_add_item(pm_tree, hf_mpls_pm_rtf_combined, tvb,
                        offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(pm_tree, hf_mpls_pm_rptf_combined, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* skip 2 reserved bytes */
    offset += 2;

    proto_tree_add_uint(pm_tree, hf_mpls_pm_session_id, tvb, offset, 4, sid);

    if (class_specific) {
        proto_tree_add_item(pm_tree, hf_mpls_pm_ds, tvb, offset + 3, 1, ENC_NA);
    }
    offset += 4;

    /* timestamps 1..4 */
    for (i = 1; i <= 4; i++) {
        mpls_pm_dissect_timestamp(tvb, pm_tree, offset, qtf, rtf, query, i);
        offset += 8;
    }

    /* counters 1..4 */
    for (i = 1; i <= 4; i++) {
        mpls_pm_dissect_counter(tvb, pm_tree, offset, query, bflag, i);
        offset += 8;
    }
}

static void
dissect_mpls_pm_dlm_dm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* the formats of the DLM+DM and ILM+DM messages are also identical */
    dissect_mpls_pm_combined(tvb, pinfo, tree, DLMDM);
}

static void
dissect_mpls_pm_ilm_dm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* the formats of the DLM+DM and ILM+DM messages are also identical */
    dissect_mpls_pm_combined(tvb, pinfo, tree, ILMDM);
}

void
proto_register_mpls_pm(void)
{
    static hf_register_info hf[] = {
        {
            &hf_mpls_pm_version,
            {
                "Version", "mpls.pm.version", FT_UINT8, BASE_DEC, NULL,
                0xF0, NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_flags,
            {
                "Flags", "mpls.pm.flags", FT_UINT8,
                BASE_HEX, NULL, MPLS_PM_FLAGS_MASK, NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_flags_r,
            {
                "Response indicator (R)", "mpls.pm.flags.r",
                FT_BOOLEAN, 4, TFS(&tfs_set_notset), MPLS_PM_FLAGS_R,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_flags_t,
            {
                "Traffic-class-specific measurement indicator (T)",
                "mpls.pm.flags.t",
                FT_BOOLEAN, 4, TFS(&tfs_set_notset), MPLS_PM_FLAGS_T,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_flags_res,
            {
                "Reserved",
                "mpls.pm.flags.res",
                FT_BOOLEAN, 4, TFS(&tfs_set_notset), MPLS_PM_FLAGS_RES,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_query_ctrl_code,
            {
                "Control Code",
                "mpls.pm.ctrl.code",
                FT_UINT8, BASE_RANGE_STRING | BASE_HEX,
                RVALS(&mpls_pm_query_ctrl_code_rvals), 0x0,
                "Code identifying the query type", HFILL
            }
        },
        {
            &hf_mpls_pm_response_ctrl_code,
            {
                "Control Code",
                "mpls.pm.ctrl.code",
                FT_UINT8, BASE_RANGE_STRING | BASE_HEX,
                RVALS(&mpls_pm_response_ctrl_code_rvals), 0x0,
                "Code identifying the response type", HFILL
            }
        },
        {
            &hf_mpls_pm_length,
            {
                "Message Length",
                "mpls.pm.length",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Total length of this message in bytes", HFILL
            }
        },
        {
            &hf_mpls_pm_dflags,
            {
                "DFlags", "mpls.pm.dflags", FT_UINT8,
                BASE_HEX, NULL, MPLS_PM_DFLAGS_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_dflags_x,
            {
                "Extended counter format indicator (X)", "mpls.pm.dflags.x",
                FT_BOOLEAN, 4, TFS(&tfs_set_notset), MPLS_PM_DFLAGS_X,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_dflags_b,
            {
                "Octet/Byte count indicator (B)", "mpls.pm.dflags.b",
                FT_BOOLEAN, 4, TFS(&tfs_set_notset), MPLS_PM_DFLAGS_B,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_dflags_res,
            {
                "Reserved",
                "mpls.pm.dflags.res",
                FT_BOOLEAN, 4, NULL, MPLS_PM_DFLAGS_RES,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_otf,
            {
                "Origin Timestamp Format (OTF)",
                "mpls.pm.otf",
                FT_UINT8, BASE_RANGE_STRING | BASE_DEC,
                RVALS(&mpls_pm_time_stamp_format_rvals), 0x0F,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_session_id,
            {
                "Session Identifier",
                "mpls.pm.session.id",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_ds,
            {
                "Differentiated Services Codepoint",
                "mpls.pm.ds",
                FT_UINT8, BASE_DEC,
                VALS(dscp_vals), 0x3F,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_origin_timestamp_null,
            {
                "Origin Timestamp",
                "mpls.pm.origin.timestamp.null",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_origin_timestamp_seq,
            {
                "Origin Timestamp",
                "mpls.pm.origin.timestamp.seq",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_origin_timestamp_ntp,
            {
                "Origin Timestamp",
                "mpls.pm.origin.timestamp.ntp",
                FT_RELATIVE_TIME, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_origin_timestamp_ptp,
            {
                "Origin Timestamp",
                "mpls.pm.origin.timestamp.ptp",
                FT_RELATIVE_TIME, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_origin_timestamp_unk,
            {
                "Origin Timestamp (Unknown Type)",
                "mpls.pm.origin.timestamp.unk",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_counter1,
            {
                "Counter 1",
                "mpls.pm.counter1",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_counter2,
            {
                "Counter 2",
                "mpls.pm.counter2",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_counter3,
            {
                "Counter 3",
                "mpls.pm.counter3",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_counter4,
            {
                "Counter 4",
                "mpls.pm.counter4",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_qtf,
            {
                "Querier timestamp format (QTF)",
                "mpls.pm.qtf",
                FT_UINT8, BASE_RANGE_STRING | BASE_DEC,
                RVALS(&mpls_pm_time_stamp_format_rvals), 0xF0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_qtf_combined,
            {
                "Querier timestamp format (QTF)",
                "mpls.pm.qtf",
                FT_UINT8, BASE_RANGE_STRING | BASE_DEC,
                RVALS(&mpls_pm_time_stamp_format_rvals), 0x0F,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_rtf,
            {
                "Responder timestamp format (RTF)",
                "mpls.pm.rtf",
                FT_UINT8, BASE_RANGE_STRING | BASE_DEC,
                RVALS(&mpls_pm_time_stamp_format_rvals), 0x0F,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_rtf_combined,
            {
                "Responder timestamp format (RTF)",
                "mpls.pm.rtf",
                FT_UINT8, BASE_RANGE_STRING | BASE_DEC,
                RVALS(&mpls_pm_time_stamp_format_rvals), 0xF0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_rptf,
            {
                "Responder's preferred timestamp format (RPTF)",
                "mpls.pm.rptf",
                FT_UINT8, BASE_RANGE_STRING | BASE_DEC,
                RVALS(&mpls_pm_time_stamp_format_rvals), 0xF0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_rptf_combined,
            {
                "Responder's preferred timestamp format (RPTF)",
                "mpls.pm.rptf",
                FT_UINT8, BASE_RANGE_STRING | BASE_DEC,
                RVALS(&mpls_pm_time_stamp_format_rvals), 0x0F,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp1_q_null,
            {
                "Timestamp 1 (T1)",
                "mpls.pm.timestamp1.null",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp1_r_null,
            {
                "Timestamp 1 (T3)",
                "mpls.pm.timestamp1.null",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp1_q_seq,
            {
                "Timestamp 1 (T1)",
                "mpls.pm.timestamp1.seq",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp1_r_seq,
            {
                "Timestamp 1 (T3)",
                "mpls.pm.timestamp1.seq",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp1_q_ntp,
            {
                "Timestamp 1 (T1)",
                "mpls.pm.timestamp1.ntp",
                FT_RELATIVE_TIME, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp1_r_ntp,
            {
                "Timestamp 1 (T3)",
                "mpls.pm.timestamp1.ntp",
                FT_RELATIVE_TIME, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp1_q_ptp,
            {
                "Timestamp 1 (T1)",
                "mpls.pm.timestamp1.ptp",
                FT_RELATIVE_TIME, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp1_r_ptp,
            {
                "Timestamp 1 (T3)",
                "mpls.pm.timestamp1.ptp",
                FT_RELATIVE_TIME, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp1_unk,
            {
                "Timestamp 1 (Unknown Type)",
                "mpls.pm.timestamp1.unk",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp2_null,
            {
                "Timestamp 2",
                "mpls.pm.timestamp2.null",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp3_null,
            {
                "Timestamp 3",
                "mpls.pm.timestamp3.null",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp3_r_null,
            {
                "Timestamp 3 (T1)",
                "mpls.pm.timestamp3.null",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp3_r_seq,
            {
                "Timestamp 3 (T1)",
                "mpls.pm.timestamp3.seq",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp3_r_ntp,
            {
                "Timestamp 3 (T1)",
                "mpls.pm.timestamp3.ntp",
                FT_RELATIVE_TIME, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp3_r_ptp,
            {
                "Timestamp 3 (T1)",
                "mpls.pm.timestamp3_ptp",
                FT_RELATIVE_TIME, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp3_unk,
            {
                "Timestamp 3 (Unknown Type)",
                "mpls.pm.timestamp3.unk",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp4_null,
            {
                "Timestamp 4",
                "mpls.pm.timestamp4.null",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp4_r_null,
            {
                "Timestamp 4 (T2)",
                "mpls.pm.timestamp4.null",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp4_r_seq,
            {
                "Timestamp 4 (T2)",
                "mpls.pm.timestamp4.seq",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp4_r_ntp,
            {
                "Timestamp 4 (T2)",
                "mpls.pm.timestamp4.ntp",
                FT_RELATIVE_TIME, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp4_r_ptp,
            {
                "Timestamp 4 (T2)",
                "mpls.pm.timestamp4.ptp",
                FT_RELATIVE_TIME, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_pm_timestamp4_unk,
            {
                "Timestamp 4 (Unknown Type)",
                "mpls.pm.timestamp4.unk",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
    };

    static gint *ett[] = {
        &ett_mpls_pm,
        &ett_mpls_pm_flags,
        &ett_mpls_pm_dflags
    };

    proto_mpls_pm_dlm =
        proto_register_protocol("MPLS Direct Loss Measurement (DLM)",
                                "MPLS Direct Loss Measurement (DLM)",
                                "mplspmdlm");

    proto_mpls_pm_ilm =
        proto_register_protocol("MPLS Inferred Loss Measurement (ILM)",
                                "MPLS Inferred Loss Measurement (ILM)",
                                "mplspmilm");

    proto_mpls_pm_dm =
        proto_register_protocol("MPLS Delay Measurement (DM)",
                                "MPLS Delay Measurement (DM)",
                                "mplspmdm");

    proto_mpls_pm_dlm_dm =
        proto_register_protocol("MPLS Direct Loss and Delay "
                                "Measurement (DLM+DM)",
                                "MPLS Direct Loss and Delay "
                                "Measurement (DLM+DM)",
                                "mplspmdlmdm");

    proto_mpls_pm_ilm_dm =
        proto_register_protocol("MPLS Inferred Loss and Delay "
                                "Measurement (ILM+DM)",
                                "MPLS Inferred Loss and Delay "
                                "Measurement (ILM+DM)",
                                "mplspmilmdm");

    proto_register_field_array(proto_mpls_pm_dlm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("mpls_pm_dlm", dissect_mpls_pm_dlm,
                       proto_mpls_pm_dlm);

    register_dissector("mpls_pm_ilm", dissect_mpls_pm_ilm,
                       proto_mpls_pm_ilm);

    register_dissector("mpls_pm_dm", dissect_mpls_pm_delay,
                       proto_mpls_pm_dm);

    register_dissector("mpls_pm_dlm_dm", dissect_mpls_pm_dlm_dm,
                       proto_mpls_pm_dlm_dm);

    register_dissector("mpls_pm_ilm_dm", dissect_mpls_pm_ilm_dm,
                       proto_mpls_pm_ilm_dm);
}

void
proto_reg_handoff_mpls_pm(void)
{
    mpls_pm_dlm_handle =
        create_dissector_handle(dissect_mpls_pm_dlm, proto_mpls_pm_dlm);

    mpls_pm_ilm_handle =
        create_dissector_handle(dissect_mpls_pm_ilm, proto_mpls_pm_ilm);

    mpls_pm_dm_handle =
        create_dissector_handle(dissect_mpls_pm_delay, proto_mpls_pm_dm);

    mpls_pm_dlm_dm_handle =
        create_dissector_handle(dissect_mpls_pm_dlm_dm, proto_mpls_pm_dlm_dm);

    mpls_pm_ilm_dm_handle =
        create_dissector_handle(dissect_mpls_pm_ilm_dm, proto_mpls_pm_ilm_dm);
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
