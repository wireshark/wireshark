/* packet-nxp_802154_sniffer.c
 * Routines for NXP JN51xx 802.15.4 Sniffer application packet dissection
 * Copyright 2017, Lee Mitchell <lee@indigopepper.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This dissector handles messages sent by either NXP's own sniffer server application,
 * or the open source one provided on GitHub here:
 * https://github.com/Codemonkey1973/JN51xx-802.15.4-Sniffer-Server
 *
 * When used with an NXP JN51xx wireless microcontroller running NXP's
 * Sniffer firmware, the sniffer server prefixes any received packets
 * with a short header and then sends them as a UDP datagrams. This dissector
 * decodes the short header and then passes the 802.15.4 frame on to the
 * IEEE 802.15.4 dissector for further dissection.
 *
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/dissectors/packet-ieee802154.h>

#define NXP_802154_SNIFFER_UDP_PORT             49999 /* Not IANA registered */
#define NXP_802154_SNIFFER_TIMESTAMP_LENGTH     5

void proto_reg_handoff_nxp_802154_sniffer(void);
void proto_register_nxp_802154_sniffer(void);

static int proto_nxp_802154_sniffer = -1;

static int hf_nxp_802154_sniffer_timestamp = -1;
static int hf_nxp_802154_sniffer_id = -1;
static int hf_nxp_802154_sniffer_channel = -1;
static int hf_nxp_802154_sniffer_lqi = -1;
static int hf_nxp_802154_sniffer_length = -1;

static gint ett_nxp_802154_sniffer = -1;

static dissector_handle_t ieee802154_handle;


static int
dissect_nxp_802154_sniffer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *nxp_802154_sniffer_tree;
    guint offset = 0;
    guint snifferidlen;

    tvbuff_t *ieee802154_tvb;

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < 9)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NXP 802.15.4 SNIFFER");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_nxp_802154_sniffer, tvb, offset, -1, ENC_NA);
    nxp_802154_sniffer_tree = proto_item_add_subtree(ti, ett_nxp_802154_sniffer);

    /* Time stamp */
    proto_tree_add_item(nxp_802154_sniffer_tree, hf_nxp_802154_sniffer_timestamp, tvb, offset, NXP_802154_SNIFFER_TIMESTAMP_LENGTH, ENC_BIG_ENDIAN);
    offset += NXP_802154_SNIFFER_TIMESTAMP_LENGTH;

    /* ID */
    proto_tree_add_item_ret_length(nxp_802154_sniffer_tree, hf_nxp_802154_sniffer_id, tvb, offset, -1, ENC_ASCII|ENC_NA, &snifferidlen);
    offset += snifferidlen;

    /* Channel */
    proto_tree_add_item(nxp_802154_sniffer_tree, hf_nxp_802154_sniffer_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* LQI */
    proto_tree_add_item(nxp_802154_sniffer_tree, hf_nxp_802154_sniffer_lqi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Length */
    proto_tree_add_item(nxp_802154_sniffer_tree, hf_nxp_802154_sniffer_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (offset >= (tvb_captured_length(tvb) - IEEE802154_FCS_LEN)) {
        return 0;
    }

    ieee802154_tvb = tvb_new_subset_length(tvb, offset, tvb_captured_length(tvb) - offset);
    call_dissector(ieee802154_handle, ieee802154_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}


void
proto_register_nxp_802154_sniffer(void)
{
    static hf_register_info hf[] = {
        { &hf_nxp_802154_sniffer_timestamp,
          { "Timestamp (16uS Symbol Periods)",  "nxp_802154_sniffer.timestamp", FT_UINT40,  BASE_DEC,   NULL, 0x0, NULL, HFILL } },
        { &hf_nxp_802154_sniffer_id,
          { "Sniffer ID",                       "nxp_802154_sniffer.id",        FT_STRINGZ, BASE_NONE,  NULL, 0x0, NULL, HFILL } },
        { &hf_nxp_802154_sniffer_channel,
          { "Channel",                          "nxp_802154_sniffer.channel",   FT_UINT8,   BASE_DEC,   NULL, 0x0, NULL, HFILL } },
        { &hf_nxp_802154_sniffer_lqi,
          { "LQI",                              "nxp_802154_sniffer.lqi",       FT_UINT8,   BASE_DEC,   NULL, 0x0, NULL, HFILL } },
        { &hf_nxp_802154_sniffer_length,
          { "Length",                           "nxp_802154_sniffer.length",    FT_UINT8,   BASE_DEC,   NULL, 0x0, NULL, HFILL } },
    };

    static gint *ett[] = {
       &ett_nxp_802154_sniffer,
    };

    proto_nxp_802154_sniffer = proto_register_protocol("NXP 802.15.4 Sniffer Protocol",
                                               "NXP 802154 Sniffer",
                                               "nxp_802154_sniffer");
    proto_register_field_array(proto_nxp_802154_sniffer, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nxp_802154_sniffer(void)
{
    dissector_handle_t nxp_802154_sniffer_handle;

    ieee802154_handle = find_dissector_add_dependency("wpan", proto_nxp_802154_sniffer);

    nxp_802154_sniffer_handle = create_dissector_handle(dissect_nxp_802154_sniffer, proto_nxp_802154_sniffer);
    dissector_add_uint_with_preference("udp.port", NXP_802154_SNIFFER_UDP_PORT, nxp_802154_sniffer_handle);
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
