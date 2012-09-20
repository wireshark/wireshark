/* packet-hdcp.c
 * Routines for HDCP dissection
 * Copyright 2011-2012, Martin Kaiser <martin@kaiser.cx>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * This dissector supports HDCP (version 1) over I2C. For now, only the
 * most common protocol messages are recognized.
 *
 * The specification of the version 1 protocol can be found at
 * http://www.digital-cp.com/files/static_page_files/5C3DC13B-9F6B-D82E-D77D8ACA08A448BF/HDCP Specification Rev1_4.pdf
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/ptvcursor.h>
#include <epan/expert.h>
#include "packet-hdcp.h"


static int proto_hdcp  = -1;

static emem_tree_t *transactions = NULL;

static gint ett_hdcp = -1;

static int hf_hdcp_addr = -1;
static int hf_hdcp_reg = -1;
static int hf_hdcp_resp_in = -1;
static int hf_hdcp_resp_to = -1;
static int hf_hdcp_a_ksv = -1;
static int hf_hdcp_b_ksv = -1;
static int hf_hdcp_an = -1;
static int hf_hdcp_hdmi_reserved = -1;
static int hf_hdcp_repeater = -1;
static int hf_hdcp_ksv_fifo = -1;
static int hf_hdcp_fast_trans = -1;
static int hf_hdcp_features = -1;
static int hf_hdcp_fast_reauth = -1;
static int hf_hdcp_hdmi_mode = -1;
static int hf_hdcp_max_casc_exc = -1;
static int hf_hdcp_depth = -1;
static int hf_hdcp_max_devs_exc = -1;
static int hf_hdcp_downstream = -1;
static int hf_hdcp_link_vfy = -1;

/* the addresses used by this dissector are 8bit, including the direction bit
   (to be in line with the HDCP specification) */
#define ADDR8_HDCP_WRITE 0x74  /* transmitter->receiver */
#define ADDR8_HDCP_READ  0x75  /* receiver->transmitter */

#define HDCP_ADDR8(x)   (x==ADDR8_HDCP_WRITE || x==ADDR8_HDCP_READ)

#define ADDR8_RCV "Receiver"
#define ADDR8_TRX "Transmitter"

#define REG_BKSV    0x0
#define REG_AKSV    0x10
#define REG_AN      0x18
#define REG_BCAPS   0x40
#define REG_BSTATUS 0x41

typedef struct _hdcp_transaction_t {
    guint32 rqst_frame;
    guint32 resp_frame;
    guint8 rqst_type;
} hdcp_transaction_t;

static const value_string hdcp_addr[] = {
    { ADDR8_HDCP_WRITE, "transmitter writes data for receiver" },
    { ADDR8_HDCP_READ, "transmitter reads data from receiver" },
    { 0, NULL }
};

static const value_string hdcp_reg[] = {
    { REG_BKSV, "B_ksv" },
    { REG_AKSV, "A_ksv" },
    { REG_AN, "An" },
    { REG_BCAPS, "B_caps"},
    { REG_BSTATUS, "B_status"},
    { 0, NULL }
};

gboolean
sub_check_hdcp(packet_info *pinfo _U_)
{
    /* by looking at the i2c_phdr only, we can't decide if this packet is HDCPv1
       this function is called when the user explicitly selected HDCPv1
       in the preferences
       therefore, we always return TRUE and hand the data to the (new
       style) dissector who will check if the packet is HDCPv1 */

   return TRUE;
}


static void
hdcp_init(void)
{
   /* se_...() allocations are automatically cleared when a new capture starts,
      so we should be safe to create the tree without any previous checks */
    transactions = se_tree_create_non_persistent(
            EMEM_TREE_TYPE_RED_BLACK, "hdcp_transactions");
}


static int
dissect_hdcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 addr, reg;
    proto_item *pi;
    ptvcursor_t *cursor;
    proto_tree *hdcp_tree = NULL;
    hdcp_transaction_t *hdcp_trans;
    proto_item *it;
    guint64 a_ksv, b_ksv;

    addr = tvb_get_guint8(tvb, 0);
    if (!HDCP_ADDR8(addr))
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HDCP");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        pi = proto_tree_add_protocol_format(tree, proto_hdcp,
                tvb, 0, tvb_reported_length(tvb), "HDCP");
        hdcp_tree = proto_item_add_subtree(pi, ett_hdcp);
    }

    cursor = ptvcursor_new(hdcp_tree, tvb, 0);
    /* all values in HDCP are little endian */
    ptvcursor_add(cursor, hf_hdcp_addr, 1, ENC_LITTLE_ENDIAN);

    if (addr==ADDR8_HDCP_WRITE) {
        /* transmitter sends data to the receiver */
        SET_ADDRESS(&pinfo->src, AT_STRINGZ, (int)strlen(ADDR8_TRX)+1, ADDR8_TRX);
        SET_ADDRESS(&pinfo->dst, AT_STRINGZ, (int)strlen(ADDR8_RCV)+1, ADDR8_RCV);

        reg = tvb_get_guint8(tvb, ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_hdcp_reg, 1, ENC_LITTLE_ENDIAN);

        if (tvb_reported_length_remaining(tvb,
                    ptvcursor_current_offset(cursor)) == 0) {
            /* transmitter requests the content of a register */
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "request %s",
                    val_to_str(reg, hdcp_reg, "unknown (0x%x)"));

            if (PINFO_FD_VISITED(pinfo)) {
                /* we've already dissected the receiver's response */
                hdcp_trans = (hdcp_transaction_t *)se_tree_lookup32(
                        transactions, PINFO_FD_NUM(pinfo));
                if (hdcp_trans && hdcp_trans->rqst_frame==PINFO_FD_NUM(pinfo) &&
                        hdcp_trans->resp_frame!=0) {

                   it = proto_tree_add_uint_format(hdcp_tree, hf_hdcp_resp_in,
                           NULL, 0, 0, hdcp_trans->resp_frame,
                           "Request to get the content of register %s, "
                           "response in frame %d",
                           val_to_str_const(hdcp_trans->rqst_type,
                               hdcp_reg, "unknown (0x%x)"),
                           hdcp_trans->resp_frame);
                    PROTO_ITEM_SET_GENERATED(it);
                }
            }
            else {
                /* we've not yet dissected the response */
                if (transactions) {
                    hdcp_trans = (hdcp_transaction_t *)se_alloc(
                            sizeof(hdcp_transaction_t));
                    hdcp_trans->rqst_frame = PINFO_FD_NUM(pinfo);
                    hdcp_trans->resp_frame = 0;
                    hdcp_trans->rqst_type = reg;
                    se_tree_insert32(transactions,
                            hdcp_trans->rqst_frame, (void *)hdcp_trans);
                }
            }
        }
        else {
            /* transmitter actually sends protocol data */
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "send %s",
                    val_to_str(reg, hdcp_reg, "unknown (0x%x)"));
            switch (reg) {
                case REG_AKSV:
                    a_ksv = tvb_get_letoh40(tvb,
                                ptvcursor_current_offset(cursor));
                    proto_tree_add_uint64_format(hdcp_tree, hf_hdcp_a_ksv,
                            tvb, ptvcursor_current_offset(cursor), 5,
                            a_ksv, "A_ksv 0x%010" G_GINT64_MODIFIER "x", a_ksv);
                    ptvcursor_advance(cursor, 5);
                    break;
                case REG_AN:
                    ptvcursor_add(cursor, hf_hdcp_an, 8, ENC_LITTLE_ENDIAN);
                    break;
                default:
                    break;
            }
        }
    }
    else {
        /* transmitter reads from receiver */
        SET_ADDRESS(&pinfo->src, AT_STRINGZ, (int)strlen(ADDR8_RCV)+1, ADDR8_RCV);
        SET_ADDRESS(&pinfo->dst, AT_STRINGZ, (int)strlen(ADDR8_TRX)+1, ADDR8_TRX);

       if (transactions) {
           hdcp_trans = (hdcp_transaction_t *)se_tree_lookup32_le(
                   transactions, PINFO_FD_NUM(pinfo));
           if (hdcp_trans) {
               if (hdcp_trans->resp_frame==0) {
                   /* there's a pending request, this packet is the response */
                   hdcp_trans->resp_frame = PINFO_FD_NUM(pinfo);
               }

               if (hdcp_trans->resp_frame== PINFO_FD_NUM(pinfo)) {
                   /* we found the request that corresponds to our response */
                   col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "send %s",
                           val_to_str_const(hdcp_trans->rqst_type,
                               hdcp_reg, "unknown (0x%x)"));
                   it = proto_tree_add_uint_format(hdcp_tree, hf_hdcp_resp_to,
                           NULL, 0, 0, hdcp_trans->rqst_frame,
                           "Response to frame %d (content of register %s)",
                           hdcp_trans->rqst_frame,
                           val_to_str_const(hdcp_trans->rqst_type,
                               hdcp_reg, "unknown (0x%x)"));
                   PROTO_ITEM_SET_GENERATED(it);
                   switch (hdcp_trans->rqst_type) {
                       case REG_BKSV:
                           b_ksv = tvb_get_letoh40(tvb,
                                   ptvcursor_current_offset(cursor));
                           proto_tree_add_uint64_format(hdcp_tree, hf_hdcp_b_ksv,
                                   tvb, ptvcursor_current_offset(cursor), 5,
                                   b_ksv, "B_ksv 0x%010" G_GINT64_MODIFIER "x",
                                   b_ksv);
                           ptvcursor_advance(cursor, 5);
                           break;
                       case REG_BCAPS:
                           ptvcursor_add_no_advance(cursor,
                                   hf_hdcp_hdmi_reserved, 1, ENC_LITTLE_ENDIAN);
                           ptvcursor_add_no_advance(cursor,
                                   hf_hdcp_repeater, 1, ENC_LITTLE_ENDIAN);
                           ptvcursor_add_no_advance(cursor,
                                   hf_hdcp_ksv_fifo, 1, ENC_LITTLE_ENDIAN);
                           ptvcursor_add_no_advance(cursor,
                                   hf_hdcp_fast_trans, 1, ENC_LITTLE_ENDIAN);
                           ptvcursor_add_no_advance(cursor,
                                   hf_hdcp_features, 1, ENC_LITTLE_ENDIAN);
                           ptvcursor_add_no_advance(cursor,
                                   hf_hdcp_fast_reauth, 1, ENC_LITTLE_ENDIAN);
                           break;
                       case REG_BSTATUS:
                           ptvcursor_add_no_advance(cursor,
                                   hf_hdcp_hdmi_mode, 2, ENC_LITTLE_ENDIAN);
                           ptvcursor_add_no_advance(cursor,
                                   hf_hdcp_max_casc_exc, 2, ENC_LITTLE_ENDIAN);
                           ptvcursor_add_no_advance(cursor,
                                   hf_hdcp_depth, 2, ENC_LITTLE_ENDIAN);
                           ptvcursor_add_no_advance(cursor,
                                   hf_hdcp_max_devs_exc, 2, ENC_LITTLE_ENDIAN);
                           ptvcursor_add_no_advance(cursor,
                                   hf_hdcp_downstream, 2, ENC_LITTLE_ENDIAN);
                           break;
                   }
               }
           }

           if (!hdcp_trans || hdcp_trans->resp_frame!=PINFO_FD_NUM(pinfo)) {
               /* the packet isn't a response to a request from the
                * transmitter; it must be a link verification */
               if (tvb_reported_length_remaining(
                           tvb, ptvcursor_current_offset(cursor)) == 2) {
                   col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                           "send link verification Ri'");
                   ptvcursor_add_no_advance(cursor,
                           hf_hdcp_link_vfy, 2, ENC_LITTLE_ENDIAN);
               }
           }
       }
    }

    ptvcursor_free(cursor);
    return tvb_reported_length(tvb);
}


void
proto_register_hdcp(void)
{
    static hf_register_info hf[] = {
        { &hf_hdcp_addr,
            { "8bit I2C address", "hdcp.addr", FT_UINT8, BASE_HEX,
                VALS(hdcp_addr), 0, NULL, HFILL } },
        { &hf_hdcp_reg,
            { "Register offset", "hdcp.reg", FT_UINT8, BASE_HEX,
                VALS(hdcp_reg), 0, NULL, HFILL } },
        { &hf_hdcp_resp_in,
            { "Response In", "hdcp.resp_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "The response to this request is in this frame", HFILL }},
        { &hf_hdcp_resp_to,
            { "Response To", "hdcp.resp_to", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "This is the response to the request in this frame", HFILL }},
        /* actually, the KSVs are only 40bits, but there's no FT_UINT40 type */
        { &hf_hdcp_a_ksv,
            { "Transmitter's key selection vector", "hdcp.a_ksv", FT_UINT64,
                BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_hdcp_b_ksv,
            { "Receiver's key selection vector", "hdcp.b_ksv", FT_UINT64,
                BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_hdcp_an,
            { "Random number for the session", "hdcp.an", FT_UINT64,
                BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_hdcp_hdmi_reserved,
            { "HDMI reserved", "hdcp.hdmi_reserved", FT_UINT8, BASE_DEC,
                NULL, 0x80, NULL, HFILL } },
        { &hf_hdcp_repeater,
            { "Repeater", "hdcp.repeater", FT_UINT8, BASE_DEC,
                NULL, 0x40, NULL, HFILL } },
        { &hf_hdcp_ksv_fifo,
            { "KSV fifo ready", "hdcp.ksv_fifo", FT_UINT8, BASE_DEC,
                NULL, 0x20, NULL, HFILL } },
        { &hf_hdcp_fast_trans,
            { "Support for 400KHz transfers", "hdcp.fast_trans",
                FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL } },
        { &hf_hdcp_features,
            { "Support for additional features", "hdcp.features",
                FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL } },
        { &hf_hdcp_fast_reauth,
            { "Support for fast re-authentication", "hdcp.fast_reauth",
                FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL } },
        { &hf_hdcp_hdmi_mode,
            { "HDMI mode", "hdcp.hdmi_mode",
                FT_UINT16, BASE_DEC, NULL, 0x1000, NULL, HFILL } },
        { &hf_hdcp_max_casc_exc,
            { "Maximum cascading depth exceeded", "hdcp.max_casc_exc",
                FT_UINT16, BASE_DEC, NULL, 0x0800, NULL, HFILL } },
        { &hf_hdcp_depth,
            { "Repeater cascade depth", "hdcp.depth",
                FT_UINT16, BASE_DEC, NULL, 0x0700, NULL, HFILL } },
        { &hf_hdcp_max_devs_exc,
            { "Maximum number of devices exceeded", "hdcp.max_devs_exc",
                FT_UINT16, BASE_DEC, NULL, 0x0080, NULL, HFILL } },
        { &hf_hdcp_downstream,
            { "Number of downstream receivers", "hdcp.downstream",
                FT_UINT16, BASE_DEC, NULL, 0x007F, NULL, HFILL } },
        { &hf_hdcp_link_vfy,
            { "Link verification response Ri'", "hdcp.link_vfy",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } }
    };

    static gint *ett[] = {
        &ett_hdcp
    };


    proto_hdcp = proto_register_protocol(
            "High bandwidth Digital Content Protection", "HDCP", "hdcp");

    proto_register_field_array(proto_hdcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    new_register_dissector("hdcp", dissect_hdcp, proto_hdcp);

    register_init_routine(hdcp_init);
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
