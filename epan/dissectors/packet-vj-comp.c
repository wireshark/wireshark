/* packet-vj-comp.c
 * Routines for decompression of PPP Van Jacobson compression
 * RFC 1144
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/* The routines in this file were created by reading the description of
 * RFC 1144 available here: ftp://ftp.rfc-editor.org/in-notes/rfc1144.pdf
 * ONLY the description of the protocol in section 3.2 was used.
 * Notably, the sample implementation in Appendix A was NOT read by this file's
 * author, due to the questionable legality of using it in Wireshark.
 * For details on this issue, see:
 * https://gitlab.com/wireshark/wireshark/-/issues/12138
 */
/* Currently hard-coded to assume TCP over IPv4.
 * Nothing in the standard explicitly prevents an IPv6 implementation...
 */

#include "config.h"

#include <glib.h>
#include <epan/tvbuff.h>
#include <epan/conversation.h>
#include <epan/in_cksum.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/ppptypes.h>
#include <wsutil/str_util.h>
#include "packet-ip.h"
#include "packet-ppp.h"

/* Shorthand macros for reading/writing 16/32 bit values from
 * possibly-unaligned indexes into a guint8[]
 */
#define GET_16(p,i) (guint16)(((p)[(i)] << 8) | ((p)[(i)+1]))
#define GET_32(p,i) (guint32)(((p)[(i)] << 24) | ((p)[(i)+1] << 16) | ((p)[(i)+2] << 8) | ((p)[(i)+3]))
#define PUT_16(p,i,v) G_STMT_START { \
    (p)[(i)]   = ((v) & 0xFF00) >> 8; \
    (p)[(i)+1] = ((v) & 0x00FF); \
} G_STMT_END
#define PUT_32(p,i,v) G_STMT_START { \
    (p)[(i)]   = ((v) & 0xFF000000) >> 24; \
    (p)[(i)+1] = ((v) & 0x00FF0000) >> 16; \
    (p)[(i)+2] = ((v) & 0x0000FF00) >> 8; \
    (p)[(i)+3] = ((v) & 0x000000FF); \
} G_STMT_END

/* Store the last connection number we've seen.
 * Only used on the first pass, in case the connection number itself
 * gets compressed out.
 */
#define CNUM_INVALID G_MAXUINT16
static guint16 last_cnum = CNUM_INVALID;

/* Location in an IPv4 packet of the IP Next Protocol field
 * (which VJC replaces with the connection ID in uncompressed packets)
 */
#define VJC_CONNID_OFFSET 9

/* Minimum TCP header length. We get compression data from the TCP header,
 * and also store it for future use.
 */
#define VJC_TCP_HDR_LEN 20

/* Structure for tracking the changeable parts of a packet header */
typedef struct vjc_hdr_s {
    guint16 tcp_chksum;
    guint16 urg;
    guint16 win;
    guint32 seq;
    guint32 ack;
    guint32 ip_id;
    gboolean psh;
} vjc_hdr_t;

/* The structure used in a wireshark "conversation" */
typedef struct vjc_conv_s {
    guint32     last_frame;     // On first pass, where to get the previous info
    guint32     last_frame_len; // On first pass, length of prev. frame (for SAWU/SWU)
    guint8     *frame_headers;  // Full copy of the IP header
    guint8      header_len;     // Length of the stored IP header
    wmem_map_t *vals;           // Hash of frame_number => vjc_hdr_t*
} vjc_conv_t;

static dissector_handle_t ip_handle;

void proto_register_vjc(void);
void proto_reg_handoff_vjc(void);

static int proto_vjc = -1;

static gint ett_vjc = -1;
static gint ett_vjc_change_mask = -1;

static expert_field ei_vjc_sawu = EI_INIT;
static expert_field ei_vjc_swu = EI_INIT;
static expert_field ei_vjc_no_cnum = EI_INIT;
static expert_field ei_vjc_no_conversation = EI_INIT;
static expert_field ei_vjc_no_direction = EI_INIT;
static expert_field ei_vjc_no_conv_data = EI_INIT;
static expert_field ei_vjc_undecoded = EI_INIT;
static expert_field ei_vjc_bad_data = EI_INIT;
static expert_field ei_vjc_error = EI_INIT;

#define VJC_FLAG_R 0x80
#define VJC_FLAG_C 0x40
#define VJC_FLAG_I 0x20
#define VJC_FLAG_P 0x10
#define VJC_FLAG_S 0x08
#define VJC_FLAG_A 0x04
#define VJC_FLAG_W 0x02
#define VJC_FLAG_U 0x01

#define VJC_FLAGS_SAWU 0x0F
#define VJC_FLAGS_SWU 0x0B

static int hf_vjc_comp = -1;
static int hf_vjc_cnum = -1;
static int hf_vjc_change_mask = -1;
static int hf_vjc_change_mask_r = -1;
static int hf_vjc_change_mask_c = -1;
static int hf_vjc_change_mask_i = -1;
static int hf_vjc_change_mask_p = -1;
static int hf_vjc_change_mask_s = -1;
static int hf_vjc_change_mask_a = -1;
static int hf_vjc_change_mask_w = -1;
static int hf_vjc_change_mask_u = -1;
static int hf_vjc_chksum = -1;
static int hf_vjc_urg = -1;
static int hf_vjc_d_win = -1;
static int hf_vjc_d_ack = -1;
static int hf_vjc_d_seq = -1;
static int hf_vjc_d_ipid = -1;
static int hf_vjc_tcpdata = -1;

static int * const vjc_change_mask_fields[] = {
    &hf_vjc_change_mask_r,
    &hf_vjc_change_mask_c,
    &hf_vjc_change_mask_i,
    &hf_vjc_change_mask_p,
    &hf_vjc_change_mask_s,
    &hf_vjc_change_mask_a,
    &hf_vjc_change_mask_w,
    &hf_vjc_change_mask_u,
    NULL
};

/* Initialization routine. Called at start of dissection.
 * Registered in proto_register_vjc() below.
 */
static void
vjc_init_protocol(void)
{
    last_cnum = CNUM_INVALID;
}

/* Cleanup routine. Called at close of file.
 * Registered in proto_register_vjc() below.
 */
static void
vjc_cleanup_protocol(void)
{
    last_cnum = CNUM_INVALID;
}

/* Find (or optionally create) a VJC conversation. */
static conversation_t *
vjc_find_conversation(packet_info *pinfo, guint32 vjc_cnum, gboolean create)
{
    /* PPP gives us almost nothing to hook a conversation on; just whether
     * the packet is considered to be P2P_DIR_RECV or P2P_DIR_SENT.
     * Ideally we should also be distinguishing conversations based on the
     * capture interface, VLAN ID, MPLS tags, etc., etc. but that's beyond
     * the scope of this dissector, and a perennial problem in Wireshark anyway.
     * See <https://gitlab.com/wireshark/wireshark/-/issues/4561>
     */
    conversation_t *conv = (conversation_t *)NULL;
    switch (pinfo->p2p_dir) {
        case P2P_DIR_RECV:
            vjc_cnum |= 0x0100;
            break;
        case P2P_DIR_SENT:
            vjc_cnum |= 0x0200;
            break;
        default:
            return conv;
    }

    conv = find_conversation_by_id(pinfo->num, CONVERSATION_NONE, vjc_cnum);
    if (!conv && create) {
        conv = conversation_new_by_id(pinfo->num, CONVERSATION_NONE, vjc_cnum);
    }

    return conv;
}

/* RFC 1144 section 3.2.2 says that "deltas" are sent for many values in the
 * header. If the initial byte is 0, that means the following 2 bytes are the
 * 16-bit value of the delta. Otherwise, the initial byte is the 8-bit value.
 */
static guint32
vjc_delta_uint(proto_tree *tree, int hf, tvbuff_t *tvb, guint *offset)
{
    guint32 ret_val;
    if (0 != tvb_get_guint8(tvb, *offset)) {
        proto_tree_add_item_ret_uint(tree, hf, tvb, *offset, 1,
                ENC_BIG_ENDIAN, &ret_val);
        (*offset)++;
    }
    else {
        (*offset)++;
        proto_tree_add_item_ret_uint(tree, hf, tvb, *offset, 2,
                ENC_BIG_ENDIAN, &ret_val);
        *offset += 2;
    }
    return ret_val;
}

/* Same thing but signed, since the TCP window delta can be negative */
static gint32
vjc_delta_int(proto_tree *tree, int hf, tvbuff_t *tvb, guint *offset)
{
    gint32 ret_val;
    if (0 != tvb_get_gint8(tvb, *offset)) {
        proto_tree_add_item_ret_int(tree, hf, tvb, *offset, 1,
                ENC_BIG_ENDIAN, &ret_val);
        (*offset)++;
    }
    else {
        (*offset)++;
        proto_tree_add_item_ret_int(tree, hf, tvb, *offset, 2,
                ENC_BIG_ENDIAN, &ret_val);
        *offset += 2;
    }
    return ret_val;
}

/* Main dissection routine for uncompressed VJC packets.
 * Registered in proto_reg_handoff_vjc() below.
 */
static int
dissect_vjc_uncomp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    /* A Van Jacobson uncompressed packet contains a standard TCP/IP header, with
     * the IP next protocol ID replaced with the connection number.
     * It's meant to signify a new TCP connection, or refresh an existing one,
     * which will have subsequent compressed packets.
     */
    proto_tree     *subtree     = NULL;
    proto_item     *ti          = NULL;
    guint8          ip_ver      = 0;
    guint8          ip_len      = 0;
    guint           tcp_len     = 0;
    guint32         vjc_cnum    = 0;
    tvbuff_t       *tcpip_tvb   = NULL;
    tvbuff_t       *sub_tvb     = NULL;
    conversation_t *conv        = NULL;
    vjc_hdr_t      *this_hdr    = NULL;
    vjc_conv_t     *pkt_data    = NULL;
    guint8         *pdata       = NULL;
    static guint8   real_proto  = IP_PROTO_TCP;

    ti = proto_tree_add_item(tree, proto_vjc, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_vjc);
    proto_item_set_text(subtree, "PPP Van Jacobson uncompressed TCP/IP");

    /* Start with some sanity checks */
    if (VJC_CONNID_OFFSET+1 > tvb_captured_length(tvb)) {
        proto_tree_add_expert_format(subtree, pinfo, &ei_vjc_bad_data, tvb, 0, -1,
                "Packet truncated before Connection ID field");
        return tvb_captured_length(tvb);
    }
    ip_ver = (tvb_get_guint8(tvb, 0) & 0xF0) >> 4;
    ip_len = (tvb_get_guint8(tvb, 0) & 0x0F) << 2;
    tcp_len = ip_len + VJC_TCP_HDR_LEN;
    if (4 != ip_ver) {
        proto_tree_add_expert_format(subtree, pinfo, &ei_vjc_bad_data, tvb, 0, 1,
                "IPv%d unsupported for VJC compression", ip_ver);
        return tvb_captured_length(tvb);
    }

    /* So far so good, continue the dissection */
    ti = proto_tree_add_boolean(subtree, hf_vjc_comp, tvb, 0, 0, FALSE);
    proto_item_set_generated(ti);

    proto_tree_add_item_ret_uint(subtree, hf_vjc_cnum, tvb, VJC_CONNID_OFFSET, 1,
            ENC_BIG_ENDIAN, &vjc_cnum);

    /* Build a composite TVB containing the original TCP/IP data.
     * This is easy for uncompressed VJC packets because only one byte
     * is different from the on-the-wire data.
     */
    sub_tvb = tvb_new_child_real_data(tvb, &real_proto, 1, 1);
    tvb_set_free_cb(sub_tvb, NULL);

    tcpip_tvb = tvb_new_composite();
    tvb_composite_append(tcpip_tvb, tvb_new_subset_length(tvb, 0, VJC_CONNID_OFFSET));
    tvb_composite_append(tcpip_tvb, sub_tvb);
    if (0 < tvb_captured_length_remaining(tvb, VJC_CONNID_OFFSET+1)) {
        tvb_composite_append(tcpip_tvb, tvb_new_subset_length(tvb, VJC_CONNID_OFFSET+1, -1));
    }
    tvb_composite_finalize(tcpip_tvb);

    add_new_data_source(pinfo, tcpip_tvb, "Original TCP/IP data");

    if (!(pinfo->p2p_dir == P2P_DIR_RECV || pinfo->p2p_dir == P2P_DIR_SENT)) {
        /* We can't make a proper conversation if we don't know the endpoints */
        proto_tree_add_expert(subtree, pinfo, &ei_vjc_no_direction, tvb, 0, 0);
    }
    else if (tcp_len > tvb_captured_length(tvb)) {
        /* Not enough data. We can still pass this packet onward (though probably
         * to no benefit), but can't base future decompression off of it.
         */
        proto_tree_add_expert_format(subtree, pinfo, &ei_vjc_bad_data, tvb, 0, -1,
                "Packet truncated before end of TCP/IP headers");
    }
    else if (!pinfo->fd->visited) {
        /* If this is our first time visiting this packet, set things up for
         * decompressing future packets.
         */
        last_cnum = vjc_cnum;
        conv = vjc_find_conversation(pinfo, vjc_cnum, TRUE);
        pkt_data = (vjc_conv_t *)conversation_get_proto_data(conv, proto_vjc);
        if (NULL == pkt_data) {
            pkt_data = wmem_new0(wmem_file_scope(), vjc_conv_t);
            pkt_data->vals = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
            conversation_add_proto_data(conv, proto_vjc, (void *)pkt_data);
        }
        pdata = // shorthand
            pkt_data->frame_headers =
            (guint8 *)tvb_memdup(wmem_file_scope(), tcpip_tvb, 0, tcp_len);

        pkt_data->last_frame = pinfo->num;
        pkt_data->header_len = tcp_len;

        // This value is used for re-calculating seq/ack numbers
        pkt_data->last_frame_len = tvb_reported_length(tvb) - ip_len;

        this_hdr = wmem_new0(wmem_file_scope(), vjc_hdr_t);
        this_hdr->ip_id = GET_16(pdata, 4);
        this_hdr->seq = GET_32(pdata, ip_len + 4);
        this_hdr->ack = GET_32(pdata, ip_len + 8);
        this_hdr->psh = (pdata[ip_len + 13] & 0x08) == 0x08;
        this_hdr->win = GET_16(pdata, ip_len + 14);
        this_hdr->tcp_chksum = GET_16(pdata, ip_len + 16);
        this_hdr->urg = GET_16(pdata, ip_len + 18);
        wmem_map_insert(pkt_data->vals, GUINT_TO_POINTER(pinfo->num), this_hdr);
    }
    else {
        /* We've already visited this packet, we should have all the info we need. */
    }

    return call_dissector_with_data(ip_handle, tcpip_tvb, pinfo, tree, data);
}

/* Main dissection routine for compressed VJC packets.
 * Registered in proto_reg_handoff_vjc() below.
 */
static int
dissect_vjc_comp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    /* A Van Jacobson compressed packet contains a change mask, which indicates
     * possible fields that may be present.
     */
    proto_tree     *subtree     = NULL;
    proto_item     *ti          = NULL;
    guint           hdr_len     = 3;    // See below
    gboolean        hdr_error   = FALSE;
    guint           ip_len      = 0;
    guint           pkt_len     = 0;
    guint           d_ipid      = 0;
    guint           d_seq       = 0;
    guint           d_ack       = 0;
    gint            d_win       = 0;
    guint8          flags       = 0;
    guint           offset      = 0;
    guint32         urg         = 0;
    guint32         ip_chksum   = 0;
    guint32         tcp_chksum  = 0;
    guint32         vjc_cnum    = 0;
    conversation_t *conv        = NULL;
    vjc_hdr_t      *this_hdr    = NULL;
    vjc_hdr_t      *last_hdr    = NULL;
    vjc_conv_t     *pkt_data    = NULL;
    guint8         *pdata       = NULL;
    tvbuff_t       *tcpip_tvb   = NULL;
    tvbuff_t       *sub_tvb     = NULL;

    /* Calculate the length of the VJC header,
     * accounting for extensions in the delta fields.
     * We start with a value of 3, because we'll always have
     * an 8-bit change mask and a 16-bit TCP checksum.
     */
#define TEST_HDR_LEN \
    if (hdr_len > tvb_captured_length(tvb)) { hdr_error = TRUE; goto done_header_len; }

    TEST_HDR_LEN;
    flags = tvb_get_guint8(tvb, offset);
    if (flags & VJC_FLAG_C) {
        // have connection number
        hdr_len++;
        TEST_HDR_LEN;
    }
    if ((flags & VJC_FLAGS_SAWU) == VJC_FLAGS_SAWU) {
        /* Special case for "unidirectional data transfer".
         * No change to header size; d_ack = 0, and
         * we're to calculate d_seq ourselves.
         */
    }
    else if ((flags & VJC_FLAGS_SAWU) == VJC_FLAGS_SWU) {
        /* Special case for "echoed interactive traffic".
         * No change to header size; we're to calculate d_seq and d_ack.
         */
    }
    else {
        /* Not a special case, determine the header size by
         * testing the SAWU flags individually.
         */
        if (flags & VJC_FLAG_U) {
            // have urgent pointer
            hdr_len += 2;
            TEST_HDR_LEN;
        }
        if (flags & VJC_FLAG_W) {
            // have d_win
            if (0 == tvb_get_gint8(tvb, offset + hdr_len))
                hdr_len += 3;
            else
                hdr_len++;
            TEST_HDR_LEN;
        }
        if (flags & VJC_FLAG_A) {
            // have d_ack
            if (0 == tvb_get_guint8(tvb, offset + hdr_len))
                hdr_len += 3;
            else
                hdr_len++;
            TEST_HDR_LEN;
        }
        if (flags & VJC_FLAG_S) {
            // have d_seq
            if (0 == tvb_get_guint8(tvb, offset + hdr_len))
                hdr_len += 3;
            else
                hdr_len++;
            TEST_HDR_LEN;
        }
    }
    if (flags & VJC_FLAG_I) {
        // have IP ID
        if (0 == tvb_get_guint8(tvb, offset + hdr_len))
            hdr_len += 3;
        else
            hdr_len++;
        TEST_HDR_LEN;
    }

    /* Now that we have the header length, use it when assigning the
     * protocol item.
     */
#undef TEST_HDR_LEN
done_header_len:
    ti = proto_tree_add_item(tree, proto_vjc, tvb, 0,
            MIN(hdr_len, tvb_captured_length(tvb)), ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_vjc);
    proto_item_set_text(subtree, "PPP Van Jacobson compressed TCP/IP");
    if (hdr_error) {
        proto_tree_add_expert_format(subtree, pinfo, &ei_vjc_bad_data, tvb, 0, -1,
                "Packet truncated, compression header incomplete");
        return tvb_captured_length(tvb);
    }

    ti = proto_tree_add_boolean(subtree, hf_vjc_comp, tvb, 0, 0, TRUE);
    proto_item_set_generated(ti);

   proto_tree_add_bitmask(subtree, tvb, 0, hf_vjc_change_mask,
            ett_vjc_change_mask, vjc_change_mask_fields, ENC_NA);
    if ((flags & VJC_FLAGS_SAWU) == VJC_FLAGS_SAWU) {
        proto_tree_add_expert(subtree, pinfo, &ei_vjc_sawu, tvb, 0, 1);
    }
    else if ((flags & VJC_FLAGS_SAWU) == VJC_FLAGS_SWU) {
        proto_tree_add_expert(subtree, pinfo, &ei_vjc_swu, tvb, 0, 1);
    }

    offset++;

    if (flags & VJC_FLAG_C) {
        proto_tree_add_item_ret_uint(subtree, hf_vjc_cnum, tvb, offset, 1,
                ENC_BIG_ENDIAN, &vjc_cnum);
        last_cnum = vjc_cnum;
        offset++;
    }
    else {
        vjc_cnum = last_cnum;
        if (vjc_cnum != CNUM_INVALID) {
            ti = proto_tree_add_uint(subtree, hf_vjc_cnum, tvb, offset, 0, vjc_cnum);
            proto_item_set_generated(ti);
        }
        else {
            proto_tree_add_expert(subtree, pinfo, &ei_vjc_no_cnum, tvb, 0, 0);
        }
    }
    conv = vjc_find_conversation(pinfo, vjc_cnum, FALSE);
    if (NULL != conv) {
        pkt_data = (vjc_conv_t *)conversation_get_proto_data(conv, proto_vjc);
        // Will be testing that pkt_data exists below
    }
    else {
        proto_tree_add_expert(subtree, pinfo, &ei_vjc_no_conversation,
                tvb, 1, (flags & VJC_FLAG_C) ? 1 : 0);
    }

    proto_tree_add_item_ret_uint(subtree, hf_vjc_chksum, tvb, offset, 2,
            ENC_BIG_ENDIAN, &tcp_chksum);
    offset += 2;

    if ((flags & VJC_FLAGS_SAWU) == VJC_FLAGS_SAWU) {
        /* Special case for "unidirectional data transfer".
         * d_ack is 0, and d_seq changed by the amount of data in the previous packet.
         */
        flags &= ~VJC_FLAGS_SAWU;
        d_ack = 0;
        if (NULL != pkt_data) {
            d_seq = pkt_data->last_frame_len;
        }
        ti = proto_tree_add_uint(subtree, hf_vjc_d_ack, tvb, offset, 0, d_ack);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(subtree, hf_vjc_d_seq, tvb, offset, 0, d_seq);
        proto_item_set_generated(ti);
    }
    else if ((flags & VJC_FLAGS_SAWU) == VJC_FLAGS_SWU) {
        /* Special case for "echoed interactive traffic".
         * d_seq and d_ack changed by the amount of user data in the
         * previous packet.
         */
        flags &= ~VJC_FLAGS_SAWU;
        if (NULL != pkt_data) {
            d_seq = d_ack = pkt_data->last_frame_len;
        }
        ti = proto_tree_add_uint(subtree, hf_vjc_d_ack, tvb, offset, 0, d_ack);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(subtree, hf_vjc_d_seq, tvb, offset, 0, d_seq);
        proto_item_set_generated(ti);
    }
    else {
        /* Not a special case, read the SAWU flags individually */

        if (flags & VJC_FLAG_U) {
            /* "The packet’s urgent pointer is sent if URG is set ..."
            * I assume that means the full 16-bit value here.
            */
            proto_tree_add_item_ret_uint(subtree, hf_vjc_urg, tvb, offset, 2,
                    ENC_BIG_ENDIAN, &urg);
            offset += 2;
        }
        else {
            urg = 0;
        }

        if (flags & VJC_FLAG_W) {
            /* "The number sent for the window is also the difference between the current
            * and previous values. However, either positive or negative changes are
            * allowed since the window is a 16-bit field."
            */
            d_win = vjc_delta_int(subtree, hf_vjc_d_win, tvb, &offset);
        }
        else {
            d_win = 0;
        }

        /* The rest of the deltas can only be positive. */
        if (flags & VJC_FLAG_A) {
            d_ack = vjc_delta_uint(subtree, hf_vjc_d_ack, tvb, &offset);
        }
        else {
            d_ack = 0;
        }

        if (flags & VJC_FLAG_S) {
            d_seq = vjc_delta_uint(subtree, hf_vjc_d_seq, tvb, &offset);
        }
        else {
            d_seq = 0;
        }
    }

    if (flags & VJC_FLAG_I) {
        d_ipid = vjc_delta_uint(subtree, hf_vjc_d_ipid, tvb, &offset);
    }
    else {
        /* "However, unlike the rest of the compressed fields, the assumed
         * change when I is clear is one, not zero." - section 3.2.2
         */
        d_ipid = 1;
        ti = proto_tree_add_uint(subtree, hf_vjc_d_ipid, tvb, offset, 0, d_ipid);
        proto_item_set_generated(ti);
    }

    if (!(pinfo->p2p_dir == P2P_DIR_RECV || pinfo->p2p_dir == P2P_DIR_SENT)) {
        /* We can't make a proper conversation if we don't know the endpoints */
        proto_tree_add_expert(subtree, pinfo, &ei_vjc_no_direction, tvb, offset,
                tvb_captured_length_remaining(tvb, offset));
        return tvb_captured_length(tvb);
    }
    if (NULL == conv) {
        proto_tree_add_expert(subtree, pinfo, &ei_vjc_undecoded, tvb, offset,
                tvb_captured_length_remaining(tvb, offset));
        return tvb_captured_length(tvb);
    }
    if (NULL == pkt_data) {
        proto_tree_add_expert(subtree, pinfo, &ei_vjc_no_conv_data, tvb, offset,
                tvb_captured_length_remaining(tvb, offset));
        return tvb_captured_length(tvb);
    }

    if (!pinfo->fd->visited) {
        /* We haven't visited this packet before.
         * Form its vjc_hdr_t from the deltas and the info from the previous frame.
         */
        last_hdr = (vjc_hdr_t *)wmem_map_lookup(pkt_data->vals,
                GUINT_TO_POINTER(pkt_data->last_frame));

        if (NULL != last_hdr) {
            this_hdr = wmem_new0(wmem_file_scope(), vjc_hdr_t);
            this_hdr->tcp_chksum = (guint16)tcp_chksum;
            this_hdr->urg = (guint16)urg;
            this_hdr->win = last_hdr->win + d_win;
            this_hdr->seq = last_hdr->seq + d_seq;
            this_hdr->ack = last_hdr->ack + d_ack;
            this_hdr->ip_id = last_hdr->ip_id + d_ipid;
            this_hdr->psh = (flags & VJC_FLAG_P) == VJC_FLAG_P;
            wmem_map_insert(pkt_data->vals, GUINT_TO_POINTER(pinfo->num), this_hdr);

            // This frame is the next frame's last frame
            pkt_data->last_frame = pinfo->num;
            pkt_data->last_frame_len = tvb_reported_length_remaining(tvb, offset);
        }
        else {
            proto_tree_add_expert_format(subtree, pinfo, &ei_vjc_error, tvb, 0, 0,
                    "Dissector error: unable to find headers for prior frame %d",
                    pkt_data->last_frame);
            return tvb_captured_length(tvb);
        }
        // if last_hdr is null, then this_hdr will stay null and be handled below
    }
    else {
        /* We have visited this packet before.
         * Get the values we saved the first time.
         */
        this_hdr = (vjc_hdr_t *)wmem_map_lookup(pkt_data->vals,
                GUINT_TO_POINTER(pinfo->num));
    }
    if (NULL != this_hdr) {
        /* pkt_data->frame_headers is our template packet header data.
         * Apply changes to it as needed.
         * The changes are intentionally done in the template before copying.
         */
        pkt_len = pkt_data->header_len + tvb_reported_length_remaining(tvb, offset);

        pdata = pkt_data->frame_headers; /* shorthand */
        ip_len = (pdata[0] & 0x0F) << 2;

        /* IP length */
        PUT_16(pdata, 2, pkt_len);

        /* IP ID */
        PUT_16(pdata, 4, this_hdr->ip_id);

        /* IP checksum */
        PUT_16(pdata, 10, 0x0000);
        ip_chksum = ip_checksum(pdata, ip_len);
        PUT_16(pdata, 10, g_htons(ip_chksum));

        /* TCP seq */
        PUT_32(pdata, ip_len + 4, this_hdr->seq);

        /* TCP ack */
        PUT_32(pdata, ip_len + 8, this_hdr->ack);

        /* TCP window */
        PUT_16(pdata, ip_len + 14, this_hdr->win);

        /* TCP push */
        if (this_hdr->psh) {
            pdata[ip_len + 13] |= 0x08;
        }
        else {
            pdata[ip_len + 13] &= ~0x08;
        }

        /* TCP checksum */
        PUT_16(pdata, ip_len + 16, this_hdr->tcp_chksum);

        /* TCP urg */
        if (this_hdr->urg) {
            pdata[ip_len + 13] |= 0x20;
            PUT_16(pdata, ip_len + 18, this_hdr->urg);
        }
        else {
            pdata[ip_len + 13] &= ~0x20;
            PUT_16(pdata, ip_len + 18, 0x0000);
        }

        /* Now that we're done manipulating the packet header, stick it into
         * a TVB for sub-dissectors to use.
         */
        sub_tvb = tvb_new_child_real_data(tvb, pdata,
                pkt_data->header_len, pkt_data->header_len);
        tvb_set_free_cb(sub_tvb, NULL);

        // Reuse pkt_len
        pkt_len = tvb_captured_length_remaining(tvb, offset);
        if (0 < pkt_len) {
            tcpip_tvb = tvb_new_composite();
            tvb_composite_append(tcpip_tvb, sub_tvb);
            tvb_composite_append(tcpip_tvb, tvb_new_subset_remaining(tvb, offset));
            tvb_composite_finalize(tcpip_tvb);

            ti = proto_tree_add_item(subtree, hf_vjc_tcpdata, tvb, offset, pkt_len, ENC_NA);
            proto_item_set_text(ti, "TCP data (%d byte%s)", pkt_len, plurality(pkt_len, "", "s"));
        }
        else
        {
            tcpip_tvb = sub_tvb;
        }

        add_new_data_source(pinfo, tcpip_tvb, "Decompressed TCP/IP data");
        return offset + call_dissector_with_data(ip_handle, tcpip_tvb, pinfo, tree, data);
    }
    else {
        proto_tree_add_expert_format(subtree, pinfo, &ei_vjc_error, tvb, 0, 0,
                "Dissector error: unable to find headers for current frame %d",
                pinfo->num);
    }
    return tvb_captured_length(tvb);
}

void
proto_register_vjc(void)
{
    static hf_register_info hf[] = {
        { &hf_vjc_comp,
            { "Is compressed", "vjc.compressed", FT_BOOLEAN, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_vjc_cnum,
            { "Connection number", "vjc.connection_number", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_vjc_change_mask,
            { "Change mask", "vjc.change_mask", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_vjc_change_mask_r,
            { "Reserved", "vjc.change_mask.reserved", FT_BOOLEAN, 8,
                TFS(&tfs_set_notset), VJC_FLAG_R, "Undefined bit", HFILL }},
        { &hf_vjc_change_mask_c,
            { "Connection number flag", "vjc.change_mask.connection_number", FT_BOOLEAN, 8,
                TFS(&tfs_set_notset), VJC_FLAG_C, "Whether connection number is present", HFILL }},
        { &hf_vjc_change_mask_i,
            { "IP ID flag", "vjc.change_mask.ip_id", FT_BOOLEAN, 8,
                TFS(&tfs_set_notset), VJC_FLAG_I, "Whether IP ID is present", HFILL }},
        { &hf_vjc_change_mask_p,
            { "TCP PSH flag", "vjc.change_mask.psh", FT_BOOLEAN, 8,
                TFS(&tfs_set_notset), VJC_FLAG_P, "Whether to set TCP PSH", HFILL }},
        { &hf_vjc_change_mask_s,
            { "TCP Sequence flag", "vjc.change_mask.seq", FT_BOOLEAN, 8,
                TFS(&tfs_set_notset), VJC_FLAG_S, "Whether TCP SEQ is present", HFILL }},
        { &hf_vjc_change_mask_a,
            { "TCP Acknowledgement flag", "vjc.change_mask.ack", FT_BOOLEAN, 8,
                TFS(&tfs_set_notset), VJC_FLAG_A, "Whether TCP ACK is present", HFILL }},
        { &hf_vjc_change_mask_w,
            { "TCP Window flag", "vjc.change_mask.win", FT_BOOLEAN, 8,
                TFS(&tfs_set_notset), VJC_FLAG_W, "Whether TCP Window is present", HFILL }},
        { &hf_vjc_change_mask_u,
            { "TCP Urgent flag", "vjc.change_mask.urg", FT_BOOLEAN, 8,
                TFS(&tfs_set_notset), VJC_FLAG_U, "Whether TCP URG pointer is present", HFILL }},
        { &hf_vjc_chksum,
            { "TCP Checksum", "vjc.checksum", FT_UINT16, BASE_HEX,
                NULL, 0x0, "TCP checksum of original packet", HFILL}},
        { &hf_vjc_urg,
            { "Urgent pointer", "vjc.urgent_pointer", FT_UINT16, BASE_DEC,
                NULL, 0x0, "TCP urgent pointer of original packet", HFILL}},
        { &hf_vjc_d_win,
            { "Delta window", "vjc.delta_window", FT_INT16, BASE_DEC,
                NULL, 0x0, "Change in TCP window size from previous packet", HFILL}},
        { &hf_vjc_d_ack,
            { "Delta ack", "vjc.delta_ack", FT_UINT16, BASE_DEC,
                NULL, 0x0, "Change in TCP acknowledgement number from previous packet", HFILL}},
        { &hf_vjc_d_seq,
            { "Delta seq", "vjc.delta_seq", FT_UINT16, BASE_DEC,
                NULL, 0x0, "Change in TCP sequence number from previous packet", HFILL}},
        { &hf_vjc_d_ipid,
            { "Delta IP ID", "vjc.delta_ipid", FT_UINT16, BASE_DEC,
                NULL, 0x0, "Change in IP Identification number from previous packet", HFILL}},
        { &hf_vjc_tcpdata,
            { "TCP data", "vjc.tcp_data", FT_BYTES, BASE_NONE,
                NULL, 0x0, "Original TCP payload", HFILL}},
    };

    static gint *ett[] = {
        &ett_vjc,
        &ett_vjc_change_mask,
    };

    expert_module_t* expert_vjc;
    static ei_register_info ei[] = {
        { &ei_vjc_sawu,
            { "vjc.special.sawu", PI_PROTOCOL, PI_CHAT,
                ".... 1111 = special case for \"unidirectional data transfer\"", EXPFILL }},
        { &ei_vjc_swu,
            { "vjc.special.swu", PI_PROTOCOL, PI_CHAT,
                ".... 1011 = special case for \"echoed interactive traffic\"", EXPFILL }},
        { &ei_vjc_no_cnum,
            { "vjc.no_connection_id", PI_PROTOCOL, PI_WARN,
                "No connection ID and no prior connection (common at capture start)", EXPFILL }},
        { &ei_vjc_no_conversation,
            { "vjc.no_connection", PI_PROTOCOL, PI_WARN,
                "No saved connection found (common at capture start)", EXPFILL }},
        { &ei_vjc_no_direction,
            { "vjc.no_direction", PI_UNDECODED, PI_WARN,
                "Connection has no direction info, cannot decompress", EXPFILL }},
        { &ei_vjc_no_conv_data,
            { "vjc.no_connection_data", PI_UNDECODED, PI_WARN,
                "Could not find saved connection data", EXPFILL }},
        { &ei_vjc_undecoded,
            { "vjc.no_decompress", PI_UNDECODED, PI_WARN,
                "Undecoded data (impossible due to missing information)", EXPFILL }},
        { &ei_vjc_bad_data,
            { "vjc.bad_data", PI_PROTOCOL, PI_ERROR,
                "Non-compliant packet data", EXPFILL }},
        { &ei_vjc_error,
            { "vjc.error", PI_MALFORMED, PI_ERROR,
                "Unrecoverable dissector error", EXPFILL }},
    };

    proto_vjc = proto_register_protocol("Van Jacobson PPP compression", "VJC", "vjc");
    proto_register_field_array(proto_vjc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_vjc = expert_register_protocol(proto_vjc);
    expert_register_field_array(expert_vjc, ei, array_length(ei));

    register_init_routine(&vjc_init_protocol);
    register_cleanup_routine(&vjc_cleanup_protocol);
}

void
proto_reg_handoff_vjc(void)
{
    dissector_handle_t vjcu_handle;
    dissector_handle_t vjcc_handle;

    ip_handle = find_dissector("ip");

    vjcc_handle = create_dissector_handle(dissect_vjc_comp, proto_vjc);
    dissector_add_uint("ppp.protocol", PPP_VJC_COMP, vjcc_handle);

    vjcu_handle = create_dissector_handle(dissect_vjc_uncomp, proto_vjc);
    dissector_add_uint("ppp.protocol", PPP_VJC_UNCOMP, vjcu_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
