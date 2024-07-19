/* packet-trdp.c
 * Routines for TRDP dissection
 * Copyright 2020, EKE-Electronics Ltd, Kalle Pokki <kalle.pokki@eke.fi>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The Train Real-Time Data Protocol (TRDP) is defined in IEC 61375-2-3. The
 * protocol is used to exchange Train Communication Network (TCN) process data
 * and message data.
 *
 * NOTE: Message data support incomplete.
 */

#include <config.h>
#include <epan/packet.h>

void proto_reg_handoff_trdp(void);
void proto_register_trdp(void);

/* Initialize the protocol and registered fields */
static int proto_trdp;
static int hf_trdp_seq;
static int hf_trdp_ver;
static int hf_trdp_msgtype;
static int hf_trdp_comid;
static int hf_trdp_etb_topo;
static int hf_trdp_oper_topo;
static int hf_trdp_len;
static int hf_trdp_res;
static int hf_trdp_reply_comid;
static int hf_trdp_reply_ipaddr;
static int hf_trdp_header_fcs;
static int hf_trdp_padding;
static int hf_trdp_reply_status;
static int hf_trdp_session_id;
static int hf_trdp_reply_timeout;
static int hf_trdp_source_uri;
static int hf_trdp_dest_uri;

#define TRDP_PD_UDP_PORT 17224
#define TRDP_MD_TCP_UDP_PORT 17225
#define TRDP_PD_HEADER_LEN 40
#define TRDP_MD_HEADER_LEN 116

/* Initialize the subtree pointers */
static int ett_trdp;

/* Initialize dissector table */
static dissector_table_t trdp_dissector_table;
static dissector_handle_t data_handle;

/* Message type names */
static const value_string msgtype_names[] = {
    { 0x4d63, "Message Data Confirm" },
    { 0x4d65, "Message Data Error" },
    { 0x4d6e, "Message Data Notification (request without reply)" },
    { 0x4d70, "Message Data Reply without Confirmation" },
    { 0x4d71, "Message Data Reply with Confirmation" },
    { 0x4d72, "Message Data Request" },
    { 0x5064, "Process Data" },
    { 0x5065, "Process Data Error" },
    { 0x5070, "Process Data Reply" },
    { 0x5072, "Process Data Request" },
    { 0, NULL }
};
static const value_string msgtype_names_short[] = {
    { 0x4d63, "Mc" },
    { 0x4d65, "Me" },
    { 0x4d6e, "Mn" },
    { 0x4d70, "Mp" },
    { 0x4d71, "Mq" },
    { 0x4d72, "Mr" },
    { 0x5064, "Pd" },
    { 0x5065, "Pe" },
    { 0x5070, "Pp" },
    { 0x5072, "Pr" },
    { 0, NULL }
};


/* Communication identifier names */
static const value_string comid_names[] = {
    { 100, "Operational train directory status" },
    { 101, "Operational train directory notification" },
    { 106, "Train network directory information request" },
    { 107, "Train network directory information reply" },
    { 108, "Operational train directory information request" },
    { 109, "Operational train directory information reply" },
    { 120, "ECSP control telegram" },
    { 121, "ECSP status telegram" },
    { 132, "ETBN - Train network directory request" },
    { 133, "ETBN - Train network directory reply" },
    { 2204160, "EKE Modular I/O state" },
    { 2204161, "EKE Modular I/O control" },
    { 0, NULL }
};

/* Reply status indication names
 * Signed int: <0: NOK; 0: OK; >0: user reply status */
static const value_string reply_status_names[] = {
    { -1, "Reserved" },
    { -2, "Session abort" },
    { -3, "No replier instance (at replier side)" },
    { -4, "No memory (at replier side)" },
    { -5, "No memory (local)" },
    { -6, "No reply" },
    { -7, "Not all replies" },
    { -8, "No confirm" },
    { -9, "Reserved" },
    { -10, "Sending failed" },
    { 0, "Ok" },
    { 0, NULL }
};

static inline int is_pd(uint16_t msgtype)
{
    return (msgtype & 0xff00) == 0x5000; // 'P'
}

static int dissect_trdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *trdp_tree;
    uint16_t ver;
    uint32_t remaining, datalen, seq, comid, etb_topo, opr_topo, msgtype, header_len;
    tvbuff_t *next_tvb;

    if (tvb_reported_length(tvb) < TRDP_PD_HEADER_LEN)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TRDP");
    col_clear(pinfo->cinfo, COL_INFO);

    header_len = is_pd(tvb_get_uint16(tvb, 6, ENC_BIG_ENDIAN)) ? TRDP_PD_HEADER_LEN : TRDP_MD_HEADER_LEN;

    /* Create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_trdp, tvb, 0, header_len, ENC_NA);
    trdp_tree = proto_item_add_subtree(ti, ett_trdp);

    /* Add items to the subtree */
    proto_tree_add_item_ret_uint(trdp_tree, hf_trdp_seq, tvb, 0, 4, ENC_BIG_ENDIAN, &seq);
    ver = tvb_get_uint16(tvb, 4, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format_value(trdp_tree, hf_trdp_ver, tvb, 4, 2, 0, "%d.%d", ver >> 8, ver & 0xff);
    proto_tree_add_item_ret_uint(trdp_tree, hf_trdp_msgtype, tvb, 6, 2, ENC_BIG_ENDIAN, &msgtype);
    proto_tree_add_item_ret_uint(trdp_tree, hf_trdp_comid, tvb, 8, 4, ENC_BIG_ENDIAN, &comid);
    proto_tree_add_item_ret_uint(trdp_tree, hf_trdp_etb_topo, tvb, 12, 4, ENC_BIG_ENDIAN, &etb_topo);
    proto_tree_add_item_ret_uint(trdp_tree, hf_trdp_oper_topo, tvb, 16, 4, ENC_BIG_ENDIAN, &opr_topo);
    proto_tree_add_item_ret_uint(trdp_tree, hf_trdp_len, tvb, 20, 4, ENC_BIG_ENDIAN, &datalen);

    if ( is_pd(msgtype) ) {
        proto_tree_add_item(trdp_tree, hf_trdp_res, tvb, 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(trdp_tree, hf_trdp_reply_comid, tvb, 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(trdp_tree, hf_trdp_reply_ipaddr, tvb, 32, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(trdp_tree, hf_trdp_header_fcs, tvb, 36, 4, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(trdp_tree, hf_trdp_reply_status, tvb, 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(trdp_tree, hf_trdp_session_id, tvb, 28, 16, ENC_BIG_ENDIAN);
        uint32_t reply_timeout = tvb_get_uint32(tvb, 44, ENC_BIG_ENDIAN);
        proto_tree_add_uint_format_value(trdp_tree, hf_trdp_reply_timeout, tvb, 44, 4, 0, "%d usec", reply_timeout);
        proto_tree_add_item(trdp_tree, hf_trdp_source_uri, tvb, 48, 32, ENC_ASCII);
        proto_tree_add_item(trdp_tree, hf_trdp_dest_uri, tvb, 80, 32, ENC_ASCII);
        proto_tree_add_item(trdp_tree, hf_trdp_header_fcs, tvb, 112, 4, ENC_BIG_ENDIAN);
    }
    /* Append descriptions */
    proto_item_append_text(ti, ", Type: %s, Comid: %d, Seq: %d, ETB Topo: 0x%08x, Opr Topo: 0x%08x", val_to_str(msgtype, msgtype_names_short, "0x%x"), comid, seq, etb_topo, opr_topo);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type=%s Comid=%d Seq=%d", val_to_str(msgtype, msgtype_names_short, "0x%x"), comid, seq);

    /* Extract possible padding */
    remaining = tvb_captured_length_remaining(tvb, header_len);
    if (remaining - datalen > 0)
    {
        proto_tree_add_item(trdp_tree, hf_trdp_padding, tvb, header_len+datalen, -1, ENC_NA);
        proto_tree_set_appendix(trdp_tree, tvb, header_len+datalen, remaining-datalen);
    }

    /* If this protocol has a sub-dissector call it here, see section 1.8 of
     * README.dissector for more information. */

    next_tvb = tvb_new_subset_length(tvb, header_len, datalen);
    if (!dissector_try_uint(trdp_dissector_table, comid, next_tvb, pinfo, tree))
    {
        call_dissector(data_handle, next_tvb, pinfo, tree);
    }

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

void proto_register_trdp(void)
{
    static hf_register_info hf[] = {
        /* PD header */
        { &hf_trdp_seq,
          { "Sequence Counter", "trdp.seq", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_trdp_ver,
          { "Protocol Version", "trdp.ver", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_trdp_msgtype,
          { "Message Type", "trdp.msgtype", FT_UINT16, BASE_HEX, VALS(msgtype_names), 0, NULL, HFILL }
        },
        { &hf_trdp_comid,
          { "Communication Identifier", "trdp.comid", FT_UINT32, BASE_DEC, VALS(comid_names), 0, NULL, HFILL }
        },
        { &hf_trdp_etb_topo,
          { "ETB Topography Counter", "trdp.etb_topo", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_trdp_oper_topo,
          { "Operational Topography Counter", "trdp.oper_topo", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_trdp_len,
          { "Dataset Length", "trdp.len", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_trdp_res,
          { "Reserved", "trdp.res", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_trdp_reply_comid,
          { "Reply Communication Identifier", "trdp.reply_comid", FT_UINT32, BASE_DEC, VALS(comid_names), 0, NULL, HFILL }
        },
        { &hf_trdp_reply_ipaddr,
          { "Reply IP address", "trdp.reply_ipaddr", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_trdp_header_fcs,
          { "Header FCS", "trdp.fcs", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_trdp_padding,
          { "Padding", "trdp.padding", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },

        /* MD Header */
        { &hf_trdp_reply_status,
          { "Reply Status Indication", "trdp.reply_status", FT_INT32, BASE_DEC, VALS(reply_status_names), 0, NULL, HFILL }
        },
        { &hf_trdp_session_id,
          { "Session UUID", "trdp.session_id", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_trdp_reply_timeout,
          { "Reply Timeout", "trdp.reply_timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_trdp_source_uri,
          { "Source URI", "trdp.source_uri", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_trdp_dest_uri,
          { "Destination URI", "trdp.dest_uri", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_trdp
    };

    /* Register the protocol name and description */
    proto_trdp = proto_register_protocol("Train Realtime Data Protocol", "TRDP", "trdp");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_trdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register next dissector */
    trdp_dissector_table = register_dissector_table("trdp.comid", "comid", proto_trdp, FT_UINT32, BASE_DEC);
}

void proto_reg_handoff_trdp(void)
{
    static dissector_handle_t trdp_handle;

    trdp_handle = create_dissector_handle(dissect_trdp, proto_trdp);
    dissector_add_uint("udp.port", TRDP_PD_UDP_PORT, trdp_handle);
    dissector_add_uint("udp.port", TRDP_MD_TCP_UDP_PORT, trdp_handle);

    data_handle = find_dissector_add_dependency("data", proto_trdp);
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
