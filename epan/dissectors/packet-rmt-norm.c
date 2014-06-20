/* packet-rmt-norm.c
 * Reliable Multicast Transport (RMT)
 * NORM Protocol Instantiation dissector
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
 *
 * Extensive changes to decode more information Julian Onions
 *
 * Negative-acknowledgment (NACK)-Oriented Reliable Multicast (NORM):
 * ------------------------------------------------------------------
 *
 * This protocol is designed to provide end-to-end reliable transport of
 * bulk data objects or streams over generic IP multicast routing and
 * forwarding services.  NORM uses a selective, negative acknowledgment
 * mechanism for transport reliability and offers additional protocol
 * mechanisms to allow for operation with minimal "a priori"
 * coordination among senders and receivers.
 *
 * References:
 *     RFC 3940, Negative-acknowledgment (NACK)-Oriented Reliable Multicast (NORM) Protocol
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

#include "config.h"

#include <glib.h>
#include <math.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>

#include "packet-rmt-common.h"

void proto_register_norm(void);
void proto_reg_handoff_norm(void);

/* String tables */

#define NORM_INFO       1
#define NORM_DATA       2
#define NORM_CMD        3
#define NORM_NACK       4
#define NORM_ACK        5
#define NORM_REPORT     6

static const value_string string_norm_type[] =
{
    { NORM_INFO,   "INFO" },
    { NORM_DATA,   "DATA" },
    { NORM_CMD,    "CMD" },
    { NORM_NACK,   "NACK" },
    { NORM_ACK,    "ACK" },
    { NORM_REPORT, "REPORT" },
    { 0, NULL }
};

#define NORM_CMD_FLUSH          1
#define NORM_CMD_EOT            2
#define NORM_CMD_SQUELCH        3
#define NORM_CMD_CC             4
#define NORM_CMD_REPAIR_ADV     5
#define NORM_CMD_ACK_REQ        6
#define NORM_CMD_APPLICATION    7

static const value_string string_norm_cmd_type[] =
{
    { NORM_CMD_FLUSH,       "FLUSH" },
    { NORM_CMD_EOT,         "EOT" },
    { NORM_CMD_SQUELCH,     "SQUELCH" },
    { NORM_CMD_CC,          "CC" },
    { NORM_CMD_REPAIR_ADV,  "REPAIR_ADV" },
    { NORM_CMD_ACK_REQ,     "ACK_REQ" },
    { NORM_CMD_APPLICATION, "APPLICATION" },
    { 0, NULL }
};

#define NORM_ACK_CC         1
#define NORM_ACK_FLUSH      2

static const value_string string_norm_ack_type[] =
{
    { NORM_ACK_CC,    "ACK CC" },
    { NORM_ACK_FLUSH, "ACK FLUSH" },
    { 0, NULL }
};

#define NORM_NACK_ITEMS         1
#define NORM_NACK_RANGES        2
#define NORM_NACK_ERASURES      3

static const value_string string_norm_nack_form[] =
{
    { NORM_NACK_ITEMS,    "Items" },
    { NORM_NACK_RANGES,   "Ranges" },
    { NORM_NACK_ERASURES, "Erasures" },
    { 0, NULL }
};

#define NORM_FLAG_REPAIR        0x01
#define NORM_FLAG_EXPLICIT      0x02
#define NORM_FLAG_INFO          0x04
#define NORM_FLAG_UNRELIABLE    0x08
#define NORM_FLAG_FILE          0x10
#define NORM_FLAG_STREAM        0x20
#define NORM_FLAG_MSG_START     0x40

#define NORM_NACK_SEGMENT       0x01
#define NORM_NACK_BLOCK         0x02
#define NORM_NACK_INFO          0x04
#define NORM_NACK_OBJECT        0x08

#define NORM_FLAG_CC_CLR        0x01
#define NORM_FLAG_CC_PLR        0x02
#define NORM_FLAG_CC_RTT        0x04
#define NORM_FLAG_CC_START      0x08
#define NORM_FLAG_CC_LEAVE      0x10

#define hdrlen2bytes(x) ((x)*4U)

static gboolean global_norm_heur = FALSE;

typedef struct norm_packet_data
{
    guint8 encoding_id;
} norm_packet_data_t;

/* Initialize the protocol and registered fields */
/* ============================================= */
static dissector_handle_t rmt_fec_handle;

static int proto_rmt_norm = -1;

static int hf_version = -1;
static int hf_type = -1;
static int hf_hlen = -1;
static int hf_sequence = -1;
static int hf_source_id = -1;
static int hf_instance_id = -1;
static int hf_grtt = -1;
static int hf_backoff = -1;
static int hf_gsize = -1;
static int hf_flags = -1;
static int hf_flag_repair = -1;
static int hf_flag_norm_explicit = -1;
static int hf_flag_info = -1;
static int hf_flag_unreliable = -1;
static int hf_flag_file = -1;
static int hf_flag_stream = -1;
static int hf_flag_msgstart = -1;
static int hf_object_transport_id = -1;
static int hf_extension = -1;
static int hf_reserved = -1;
static int hf_payload_len = -1;
static int hf_payload_offset = -1;
static int hf_cmd_flavor = -1;
static int hf_cc_sequence = -1;
static int hf_cc_sts = -1;
static int hf_cc_stus = -1;
static int hf_cc_node_id = -1;
static int hf_cc_flags = -1;
static int hf_cc_flags_clr = -1;
static int hf_cc_flags_plr = -1;
static int hf_cc_flags_rtt = -1;
static int hf_cc_flags_start = -1;
static int hf_cc_flags_leave = -1;
static int hf_cc_rtt = -1;
static int hf_cc_rate = -1;
static int hf_cc_transport_id = -1;
static int hf_ack_source = -1;
static int hf_ack_type = -1;
static int hf_ack_id = -1;
static int hf_ack_grtt_sec = -1;
static int hf_ack_grtt_usec = -1;
static int hf_nack_server = -1;
static int hf_nack_grtt_sec = -1;
static int hf_nack_grtt_usec = -1;
static int hf_nack_form = -1;
static int hf_nack_flags = -1;
static int hf_nack_flags_segment = -1;
static int hf_nack_flags_block = -1;
static int hf_nack_flags_info = -1;
static int hf_nack_flags_object = -1;
static int hf_nack_length = -1;
static int hf_payload = -1;
static int hf_fec_encoding_id = -1;

static int ett_main = -1;
static int ett_hdrext = -1;
static int ett_flags = -1;
static int ett_streampayload = -1;
static int ett_congestioncontrol = -1;
static int ett_nackdata = -1;

static expert_field ei_version1_only = EI_INIT;

static const double RTT_MIN = 1.0e-06;
static const double RTT_MAX = 1000;

static double UnquantizeRtt(unsigned char qrtt)
{
    return ((qrtt <= 31) ? (((double)(qrtt+1))*(double)RTT_MIN) :
            (RTT_MAX/exp(((double)(255-qrtt))/(double)13.0)));
}

static double UnquantizeGSize(guint8 gsizex)
{
    guint mant = (gsizex & 0x8) ? 5 : 1;
    guint exponent = gsizex & 0x7;

    exponent += 1;
    return mant * pow(10, exponent);
}

/* code to dissect fairly common sequence in NORM packets */
static guint dissect_grrtetc(proto_tree *tree, tvbuff_t *tvb, guint offset)
{
    guint8 backoff;
    double gsizex;
    double grtt;

    proto_tree_add_item(tree, hf_instance_id, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
    grtt    = UnquantizeRtt(tvb_get_guint8(tvb, offset));
    proto_tree_add_double(tree, hf_grtt, tvb, offset, 1, grtt); offset += 1;
    backoff = hi_nibble(tvb_get_guint8(tvb, offset));
    gsizex  = UnquantizeGSize((guint8)lo_nibble(tvb_get_guint8(tvb, offset)));
    proto_tree_add_uint(tree, hf_backoff, tvb, offset, 1, backoff);
    proto_tree_add_double(tree, hf_gsize, tvb, offset, 1, gsizex);
    offset += 1;
    return offset;
}

/* split out some common FEC handling */
static guint dissect_feccode(proto_tree *tree, tvbuff_t *tvb, guint offset,
                             packet_info *pinfo, gint reserved)
{
    norm_packet_data_t *norm_data;
    guint8              encoding_id = tvb_get_guint8(tvb, offset);

    /* Save encoding ID */
    norm_data = wmem_new0(wmem_file_scope(), norm_packet_data_t);
    norm_data->encoding_id = encoding_id;

    p_add_proto_data(wmem_file_scope(), pinfo, proto_rmt_norm, 0, norm_data);

    proto_tree_add_item(tree, hf_fec_encoding_id, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
    if (reserved) {
        proto_tree_add_item(tree, hf_reserved, tvb, offset, 1, ENC_NA); offset += 1;
    }
    proto_tree_add_item(tree, hf_object_transport_id, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        fec_data_exchange_t  fec;
        tvbuff_t            *new_tvb;
        int                  len;

        new_tvb = tvb_new_subset_remaining(tvb, offset);

        fec.encoding_id = encoding_id;
        len = call_dissector_with_data(rmt_fec_handle, new_tvb, pinfo, tree, &fec);
        if (len > 0)
            offset += len;
    }

    return offset;
}

static guint dissect_norm_hdrext(proto_tree *tree, packet_info *pinfo,
                                 tvbuff_t *tvb, guint offset, guint8 hlen)
{
    lct_data_exchange_t  data_exchange;
    norm_packet_data_t  *packet_data = (norm_packet_data_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rmt_norm, 0);

    memset(&data_exchange, 0, sizeof(data_exchange));

    if (packet_data != NULL)
        data_exchange.codepoint = packet_data->encoding_id;

    offset += lct_ext_decode(tree, tvb, pinfo, offset, hdrlen2bytes(hlen), &data_exchange,
                             hf_extension, ett_hdrext);

    return offset;
}

static guint dissect_nack_data(proto_tree *tree, tvbuff_t *tvb, guint offset,
                               packet_info *pinfo)
{
    proto_item *ti, *tif;
    proto_tree *nack_tree, *flag_tree;
    guint16     len;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "NACK Data");
    nack_tree = proto_item_add_subtree(ti, ett_nackdata);
    proto_tree_add_item(nack_tree, hf_nack_form, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;

    tif = proto_tree_add_item(nack_tree, hf_nack_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    flag_tree = proto_item_add_subtree(tif, ett_flags);
    proto_tree_add_item(flag_tree, hf_nack_flags_segment, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_nack_flags_block,   tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_nack_flags_info,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_nack_flags_object,  tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(nack_tree, hf_nack_length, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
    proto_item_set_len(ti, 4+len);
    if (len > 4) {
        dissect_feccode(nack_tree, tvb, offset, pinfo, 1);
    }
    offset += len;
    return offset;
}

/* code to dissect NORM data packets */
static void dissect_norm_data(proto_tree *tree, packet_info *pinfo,
                              tvbuff_t *tvb, guint offset, guint8 hlen)
{
    guint8      flags;
    proto_item *ti;
    proto_tree *flag_tree;

    offset = dissect_grrtetc(tree, tvb, offset);

    ti = proto_tree_add_item(tree, hf_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset);
    flag_tree = proto_item_add_subtree(ti, ett_flags);
    proto_tree_add_item(flag_tree, hf_flag_repair,        tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_flag_norm_explicit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_flag_info,          tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_flag_unreliable,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_flag_file,          tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_flag_stream,        tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_flag_msgstart,      tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    offset = dissect_feccode(tree, tvb, offset, pinfo, 0);

    if (offset < hdrlen2bytes(hlen)) {
        offset = dissect_norm_hdrext(tree, pinfo, tvb, offset, hlen);
    }
    if (flags & NORM_FLAG_STREAM) {
        ti = proto_tree_add_text(tree, tvb, offset, 8, "Stream Data");
        flag_tree = proto_item_add_subtree(ti, ett_streampayload);
        proto_tree_add_item(flag_tree, hf_reserved,       tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
        proto_tree_add_item(flag_tree, hf_payload_len,    tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
        proto_tree_add_item(flag_tree, hf_payload_offset, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;

    }
    if (tvb_reported_length_remaining(tvb, offset) > 0)
        proto_tree_add_item(tree, hf_payload, tvb, offset, -1, ENC_NA);
}

/* code to dissect NORM info packets */
static void dissect_norm_info(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint8 hlen)
{
    proto_item         *ti;
    proto_tree         *flag_tree;
    norm_packet_data_t *norm_data;

    offset = dissect_grrtetc(tree, tvb, offset);

    ti = proto_tree_add_item(tree, hf_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    flag_tree = proto_item_add_subtree(ti, ett_flags);
    proto_tree_add_item(flag_tree, hf_flag_repair,        tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_flag_norm_explicit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_flag_info,          tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_flag_unreliable,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_flag_file,          tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_flag_stream,        tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_flag_msgstart,      tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Save encoding ID */
    norm_data = wmem_new0(wmem_file_scope(), norm_packet_data_t);
    norm_data->encoding_id = tvb_get_guint8(tvb, offset);

    p_add_proto_data(wmem_file_scope(), pinfo, proto_rmt_norm, 0, norm_data);

    proto_tree_add_item(tree, hf_fec_encoding_id,     tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
    proto_tree_add_item(tree, hf_object_transport_id, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;

    if (offset < hdrlen2bytes(hlen)) {
        offset = dissect_norm_hdrext(tree, pinfo, tvb, offset, hlen);
    }
    if (tvb_reported_length_remaining(tvb, offset) > 0)
        proto_tree_add_item(tree, hf_payload, tvb, offset, -1, ENC_NA);
}

/* code to dissect NORM cmd(flush) packets */
static guint dissect_norm_cmd_flush(proto_tree *tree, packet_info *pinfo,
                                    tvbuff_t *tvb, guint offset, guint8 hlen)
{
    offset = dissect_feccode(tree, tvb, offset, pinfo, 0);
    if (offset < hdrlen2bytes(hlen)) {
        offset = dissect_norm_hdrext(tree, pinfo, tvb, offset, hlen);
    }
    return offset;
}

/* code to dissect NORM cmd(flush) packets */
static guint dissect_norm_cmd_repairadv(proto_tree *tree, packet_info *pinfo,
                                        tvbuff_t *tvb, guint offset, guint8 hlen)
{
    proto_tree_add_item(tree, hf_flags,    tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
    proto_tree_add_item(tree, hf_reserved, tvb, offset, 2, ENC_BIG_ENDIAN); offset +=2;

    if (offset < hdrlen2bytes(hlen)) {
        offset = dissect_norm_hdrext(tree, pinfo, tvb, offset, hlen);
    }
    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset = dissect_nack_data(tree, tvb, offset, pinfo);
    }
    return offset;
}

/* code to dissect NORM cmd(cc) packets */
static guint dissect_norm_cmd_cc(proto_tree *tree, packet_info *pinfo,
                                 tvbuff_t *tvb, guint offset, guint8 hlen)
{
    proto_tree_add_item(tree, hf_reserved,    tvb, offset, 1, ENC_NA);         offset += 1;
    proto_tree_add_item(tree, hf_cc_sequence, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;

    proto_tree_add_item(tree, hf_cc_sts, tvb, offset, 4,  ENC_BIG_ENDIAN); offset += 4;
    proto_tree_add_item(tree, hf_cc_stus, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
    if (offset < hdrlen2bytes(hlen)) {
        offset = dissect_norm_hdrext(tree, pinfo, tvb, offset, hlen);
    }
    while (offset < hdrlen2bytes(hlen)) {
        proto_item *ti, *tif;
        proto_tree *cc_tree, *flag_tree;
        double grtt;
        ti = proto_tree_add_text(tree, tvb, offset, 8, "Congestion Control");
        cc_tree = proto_item_add_subtree(ti, ett_congestioncontrol);
        proto_tree_add_item(cc_tree, hf_cc_node_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        tif = proto_tree_add_item(cc_tree, hf_cc_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
        flag_tree = proto_item_add_subtree(tif, ett_flags);
        proto_tree_add_item(flag_tree, hf_cc_flags_clr,   tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_cc_flags_plr,   tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_cc_flags_rtt,   tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_cc_flags_start, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_cc_flags_leave, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        grtt = UnquantizeRtt(tvb_get_guint8(tvb, offset));
        proto_tree_add_double(cc_tree, hf_cc_rtt,  tvb, offset, 1, grtt); offset += 1;
        grtt = rmt_decode_send_rate(tvb_get_ntohs(tvb, offset));
        proto_tree_add_double(cc_tree, hf_cc_rate, tvb, offset, 2, grtt); offset += 2;
    }
    return offset;
}

/* code to dissect NORM cmd(squelch) packets */
static guint dissect_norm_cmd_squelch(proto_tree *tree, packet_info *pinfo,
                                      tvbuff_t *tvb, guint offset)
{
    offset = dissect_feccode(tree, tvb, offset, pinfo, 0);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(tree, hf_cc_transport_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 2;
    }
    return offset;
}

/* code to dissect NORM cmd(squelch) packets */
static guint dissect_norm_cmd_ackreq(proto_tree *tree, packet_info *pinfo _U_,
                                     tvbuff_t *tvb, guint offset)
{
    proto_tree_add_item(tree, hf_reserved, tvb, offset, 1, ENC_NA);         offset += 1;
    proto_tree_add_item(tree, hf_ack_type, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
    proto_tree_add_item(tree, hf_ack_id,   tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
    return offset;
}

/* code to dissect NORM cmd packets */
static void dissect_norm_cmd(proto_tree *tree, packet_info *pinfo,
                             tvbuff_t *tvb, guint offset, guint8 hlen)
{
    guint8 flavor;

    offset = dissect_grrtetc(tree, tvb, offset);
    flavor = tvb_get_guint8(tvb, offset);

    col_append_sep_str(pinfo->cinfo, COL_INFO, " ",
                       val_to_str(flavor, string_norm_cmd_type, "Unknown Cmd Type (0x%04x)"));
    proto_tree_add_item(tree, hf_cmd_flavor, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
    switch(flavor) {
    case NORM_CMD_CC:
        offset = dissect_norm_cmd_cc(tree, pinfo, tvb, offset, hlen);
        break;
    case NORM_CMD_FLUSH:
        offset = dissect_norm_cmd_flush(tree, pinfo, tvb, offset, hlen);
        break;
    case NORM_CMD_SQUELCH:
        offset = dissect_norm_cmd_squelch(tree, pinfo, tvb, offset);
        break;
    case NORM_CMD_REPAIR_ADV:
        offset = dissect_norm_cmd_repairadv(tree, pinfo, tvb, offset, hlen);
        break;
    case NORM_CMD_ACK_REQ:
        offset = dissect_norm_cmd_ackreq(tree, pinfo, tvb, offset);
        break;
    }
    if (tvb_reported_length_remaining(tvb, offset) > 0)
        proto_tree_add_item(tree, hf_payload, tvb, offset, -1, ENC_NA);
}

/* code to dissect NORM ack packets */
static void dissect_norm_ack(proto_tree *tree, packet_info *pinfo,
                             tvbuff_t *tvb, guint offset, guint8 hlen)
{
    guint8 acktype;

    proto_tree_add_item(tree, hf_ack_source,  tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
    proto_tree_add_item(tree, hf_instance_id, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
    acktype = tvb_get_guint8(tvb, offset);

    col_append_sep_str(pinfo->cinfo, COL_INFO, " ",
                       val_to_str(acktype, string_norm_ack_type, "Unknown Ack Type (0x%04x)"));
    proto_tree_add_item(tree, hf_ack_type,      tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
    proto_tree_add_item(tree, hf_ack_id,        tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
    proto_tree_add_item(tree, hf_ack_grtt_sec,  tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
    proto_tree_add_item(tree, hf_ack_grtt_usec, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
    if (offset < hdrlen2bytes(hlen)) {
        offset = dissect_norm_hdrext(tree, pinfo, tvb, offset, hlen);
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0)
        proto_tree_add_item(tree, hf_payload, tvb, offset, -1, ENC_NA);
}

/* code to dissect NORM nack packets */
static void dissect_norm_nack(proto_tree *tree, packet_info *pinfo,
                              tvbuff_t *tvb, guint offset, guint8 hlen)
{
    proto_tree_add_item(tree, hf_nack_server,    tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
    proto_tree_add_item(tree, hf_instance_id,    tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
    proto_tree_add_item(tree, hf_reserved,       tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
    proto_tree_add_item(tree, hf_nack_grtt_sec,  tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
    proto_tree_add_item(tree, hf_nack_grtt_usec, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
    if (offset < hdrlen2bytes(hlen)) {
        offset = dissect_norm_hdrext(tree, pinfo, tvb, offset, hlen);
    }

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset = dissect_nack_data(tree, tvb, offset, pinfo);
    }
    if (tvb_reported_length_remaining(tvb, offset) > 0)
        proto_tree_add_item(tree, hf_payload, tvb, offset, -1, ENC_NA);
}

/* Code to actually dissect the packets */
/* ==================================== */
static int
dissect_norm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Logical packet representation */
    guint8 version;
    guint8 type;
    guint8 hlen;

    /* Offset for subpacket dissection */
    guint offset = 0;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *norm_tree;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NORM");
    col_clear(pinfo->cinfo, COL_INFO);

    /* NORM header dissection, part 1 */
    /* ------------------------------ */

    version = hi_nibble(tvb_get_guint8(tvb, offset));

    /* Create subtree for the NORM protocol */
    ti = proto_tree_add_item(tree, proto_rmt_norm, tvb, offset, -1, ENC_NA);
    norm_tree = proto_item_add_subtree(ti, ett_main);

    /* Fill the NORM subtree */
    proto_tree_add_uint(norm_tree, hf_version, tvb, offset, 1, version);

    /* This dissector supports only NORMv1 packets.
     * If version > 1 print only version field and quit.
     */
    if (version != 1) {
        expert_add_info(pinfo, ti, &ei_version1_only);

        /* Complete entry in Info column on summary display */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Version: %u (not supported)", version);
        return 0;
    }

    /* NORM header dissection, part 2 */
    /* ------------------------------ */

    type = lo_nibble(tvb_get_guint8(tvb, offset));
    hlen = tvb_get_guint8(tvb, offset+1);

    if (tree) {
        proto_tree_add_uint(norm_tree, hf_type, tvb, offset, 1, type);
        proto_tree_add_item(norm_tree, hf_hlen, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(norm_tree, hf_sequence, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(norm_tree, hf_source_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);
    }

    offset += 8;


    /* Complete entry in Info column on summary display */
    /* ------------------------------------------------ */
    col_append_sep_str(pinfo->cinfo, COL_INFO, " ",
                       val_to_str(type, string_norm_type, "Unknown Type (0x%04x)"));


    switch(type) {
    case NORM_INFO:
        dissect_norm_info(norm_tree, pinfo, tvb, offset, hlen);
        break;
    case NORM_DATA:
        dissect_norm_data(norm_tree, pinfo, tvb, offset, hlen);
        break;
    case NORM_CMD:
        dissect_norm_cmd(norm_tree, pinfo, tvb, offset, hlen);
        break;
    case NORM_ACK:
        dissect_norm_ack(norm_tree, pinfo, tvb, offset, hlen);
        break;
    case NORM_NACK:
        dissect_norm_nack(norm_tree, pinfo, tvb, offset, hlen);
        break;
    default:
        /* Add the Payload item */
        if (tvb_reported_length_remaining(tvb, offset) > 0)
            proto_tree_add_item(norm_tree, hf_payload, tvb, offset, -1, ENC_NA);
        break;
    }

    return tvb_reported_length(tvb);
}

static gboolean
dissect_norm_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    guint8 byte1;

    if (!global_norm_heur)
        return FALSE;
    if (tvb_reported_length(tvb) < 12)
        return FALSE;  /* not enough to check */
    byte1 = tvb_get_guint8(tvb, 0);

    if (hi_nibble(byte1) != 1) return FALSE;
    if (lo_nibble(byte1) < 1 || lo_nibble(byte1) > 6) return FALSE;
    if (tvb_get_guint8(tvb, 1) > 20) return FALSE;

    dissect_norm(tvb, pinfo, tree, data);
    return TRUE; /* appears to be a NORM packet */
}

void proto_register_norm(void)
{
    /* Setup NORM header fields */
    static hf_register_info hf[] = {

        { &hf_version,
          { "Version", "norm.version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_type,
          { "Message Type", "norm.type",
            FT_UINT8, BASE_DEC, VALS(string_norm_type), 0x0,
            NULL, HFILL }
        },
        { &hf_hlen,
          { "Header length", "norm.hlen",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sequence,
          { "Sequence", "norm.sequence",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_source_id,
          { "Source ID", "norm.source_id",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_instance_id,
          { "Instance", "norm.instance_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_grtt,
          { "grtt", "norm.grtt",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_backoff,
          { "Backoff", "norm.backoff",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gsize,
          { "Group Size", "norm.gsize",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_flags,
          { "Flags", "norm.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_flag_repair,
          { "Repair Flag", "norm.flag.repair",
            FT_BOOLEAN, 8, NULL, NORM_FLAG_REPAIR,
            NULL, HFILL }
        },
        { &hf_flag_norm_explicit,
          { "Explicit Flag", "norm.flag.explicit",
            FT_BOOLEAN, 8, NULL, NORM_FLAG_EXPLICIT,
            NULL, HFILL }
        },
        { &hf_flag_info,
          { "Info Flag", "norm.flag.info",
            FT_BOOLEAN, 8, NULL, NORM_FLAG_INFO,
            NULL, HFILL }
        },
        { &hf_flag_unreliable,
          { "Unreliable Flag", "norm.flag.unreliable",
            FT_BOOLEAN, 8, NULL, NORM_FLAG_UNRELIABLE,
            NULL, HFILL }
        },
        { &hf_flag_file,
          { "File Flag", "norm.flag.file",
            FT_BOOLEAN, 8, NULL, NORM_FLAG_FILE,
            NULL, HFILL }
        },
        { &hf_flag_stream,
          { "Stream Flag", "norm.flag.stream",
            FT_BOOLEAN, 8, NULL, NORM_FLAG_STREAM,
            NULL, HFILL }
        },
        { &hf_flag_msgstart,
          { "Msg Start Flag", "norm.flag.msgstart",
            FT_BOOLEAN, 8, NULL, NORM_FLAG_MSG_START,
            NULL, HFILL }
        },
        { &hf_object_transport_id,
          { "Object Transport ID", "norm.object_transport_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_extension,
          { "Hdr Extension", "norm.hexext",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_reserved,
          { "Reserved", "norm.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_payload_len,
          { "Payload Len", "norm.payload.len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_payload_offset,
          { "Payload Offset", "norm.payload.offset",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },

        { &hf_cmd_flavor,
          { "Flavor", "norm.flavor",
            FT_UINT8, BASE_DEC, VALS(string_norm_cmd_type), 0x0,
            NULL, HFILL}
        },
        { &hf_cc_sequence,
          { "CC Sequence", "norm.ccsequence",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cc_sts,
          { "Send Time secs", "norm.cc_sts",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cc_stus,
          { "Send Time usecs", "norm.cc_stus",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cc_node_id,
          { "CC Node ID", "norm.cc_node_id",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cc_flags,
          { "CC Flags", "norm.cc_flags",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cc_flags_clr,
          { "CLR", "norm.cc_flags.clr",
            FT_BOOLEAN, 8, NULL, NORM_FLAG_CC_CLR,
            NULL, HFILL}
        },
        { &hf_cc_flags_plr,
          { "PLR", "norm.cc_flags.plr",
            FT_BOOLEAN, 8, NULL, NORM_FLAG_CC_PLR,
            NULL, HFILL}
        },
        { &hf_cc_flags_rtt,
          { "RTT", "norm.cc_flags.rtt",
            FT_BOOLEAN, 8, NULL, NORM_FLAG_CC_RTT,
            NULL, HFILL}
        },
        { &hf_cc_flags_start,
          { "Start", "norm.cc_flags.start",
            FT_BOOLEAN, 8, NULL, NORM_FLAG_CC_START,
            NULL, HFILL}
        },
        { &hf_cc_flags_leave,
          { "Leave", "norm.cc_flags.leave",
            FT_BOOLEAN, 8, NULL, NORM_FLAG_CC_LEAVE,
            NULL, HFILL}
        },
        { &hf_cc_rtt,
          { "CC RTT", "norm.cc_rtt",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cc_rate,
          { "CC Rate", "norm.cc_rate",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cc_transport_id,
          { "CC Transport ID", "norm.cc_transport_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },

        { &hf_ack_source,
          { "Ack Source", "norm.ack.source",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_ack_type,
          { "Ack Type", "norm.ack.type",
            FT_UINT8, BASE_DEC, VALS(string_norm_ack_type), 0x0,
            NULL, HFILL}
        },
        { &hf_ack_id,
          { "Ack ID", "norm.ack.id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_ack_grtt_sec,
          { "Ack GRTT Sec", "norm.ack.grtt_sec",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_ack_grtt_usec,
          { "Ack GRTT usec", "norm.ack.grtt_usec",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },

        { &hf_nack_server,
          { "NAck Server", "norm.nack.server",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_nack_grtt_sec,
          { "NAck GRTT Sec", "norm.nack.grtt_sec",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_nack_grtt_usec,
          { "NAck GRTT usec", "norm.nack.grtt_usec",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_nack_form,
          { "NAck FORM", "norm.nack.form",
            FT_UINT8, BASE_DEC, VALS(string_norm_nack_form), 0x0,
            NULL, HFILL}
        },
        { &hf_nack_flags,
          { "NAck Flags", "norm.nack.flags",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_nack_flags_segment,
          { "Segment", "norm.nack.flags.segment",
            FT_BOOLEAN, 8, NULL, NORM_NACK_SEGMENT,
            NULL, HFILL}
        },
        { &hf_nack_flags_block,
          { "Block", "norm.nack.flags.block",
            FT_BOOLEAN, 8, NULL, NORM_NACK_BLOCK,
            NULL, HFILL}
        },
        { &hf_nack_flags_info,
          { "Info", "norm.nack.flags.info",
            FT_BOOLEAN, 8, NULL, NORM_NACK_INFO,
            NULL, HFILL}
        },
        { &hf_nack_flags_object,
          { "Object", "norm.nack.flags.object",
            FT_BOOLEAN, 8, NULL, NORM_NACK_OBJECT,
            NULL, HFILL}
        },
        { &hf_nack_length,
          { "NAck Length", "norm.nack.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_payload,
          { "Payload", "norm.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fec_encoding_id,
          { "FEC Encoding ID", "norm.fec_encoding_id",
            FT_UINT8, BASE_DEC, VALS(string_fec_encoding_id), 0x0,
            NULL, HFILL}
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_main,
        &ett_hdrext,
        &ett_flags,
        &ett_streampayload,
        &ett_congestioncontrol,
        &ett_nackdata
    };

    static ei_register_info ei[] = {
        { &ei_version1_only, { "norm.version1_only", PI_PROTOCOL, PI_WARN, "Sorry, this dissector supports NORM version 1 only", EXPFILL }}
    };

    module_t *module;
    expert_module_t* expert_rmt_norm;

    /* Register the protocol name and description */
    proto_rmt_norm = proto_register_protocol("Negative-acknowledgment Oriented Reliable Multicast", "NORM", "norm");

    /* Register the header fields and subtrees used */
    proto_register_field_array(proto_rmt_norm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_rmt_norm = expert_register_protocol(proto_rmt_norm);
    expert_register_field_array(expert_rmt_norm, ei, array_length(ei));


    /* Register preferences */
    module = prefs_register_protocol(proto_rmt_norm, NULL);
    prefs_register_bool_preference(module, "heuristic_norm",
                                   "Try to decode UDP packets as NORM packets",
                                   "Check this to decode NORM traffic between clients",
                                   &global_norm_heur);
}

void proto_reg_handoff_norm(void)
{
    static dissector_handle_t handle;

    handle = new_create_dissector_handle(dissect_norm, proto_rmt_norm);
    dissector_add_for_decode_as("udp.port", handle);
    heur_dissector_add("udp", dissect_norm_heur, proto_rmt_norm);

    rmt_fec_handle = find_dissector("rmt-fec");
}

/*
 * Editor modelines - http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
