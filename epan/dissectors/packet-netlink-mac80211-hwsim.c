/* packet-netlink-mac80211-hwsim.c
 * Dissector for mac80211_hwsim (over Netlink).
 *
 * Copyright (c) 2025, Alex Gavin <a_gavin@icloud.com>
 *
 * Credits: Authors of nl80211 dissector
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-netlink.h"

void proto_register_netlink_mac80211_hwsim(void);
void proto_reg_handoff_netlink_mac80211_hwsim(void);

typedef struct
{
    packet_info *pinfo;
} netlink_mac80211_hwsim_info_t;

enum ws_mac80211_hwsim_commands
{
    WS_HWSIM_CMD_UNSPEC,
    WS_HWSIM_CMD_REGISTER,
    WS_HWSIM_CMD_FRAME,
    WS_HWSIM_CMD_TX_INFO_FRAME,
    WS_HWSIM_CMD_NEW_RADIO,
    WS_HWSIM_CMD_DEL_RADIO,
    WS_HWSIM_CMD_GET_RADIO,
    WS_HWSIM_CMD_ADD_MAC_ADDR,
    WS_HWSIM_CMD_DEL_MAC_ADDR,
    WS_HWSIM_CMD_START_PMSR,
    WS_HWSIM_CMD_ABORT_PMSR,
    WS_HWSIM_CMD_REPORT_PMSR,
};

enum ws_mac80211_hwsim_attrs
{
    WS_MAC80211_HWSIM_ATTR_UNSPEC,
    WS_MAC80211_HWSIM_ATTR_ADDR_RECEIVER,
    WS_MAC80211_HWSIM_ATTR_ADDR_TRANSMITTER,
    WS_MAC80211_HWSIM_ATTR_FRAME,
    WS_MAC80211_HWSIM_ATTR_FLAGS,
    WS_MAC80211_HWSIM_ATTR_RX_RATE,
    WS_MAC80211_HWSIM_ATTR_SIGNAL,
    WS_MAC80211_HWSIM_ATTR_TX_INFO,
    WS_MAC80211_HWSIM_ATTR_COOKIE,
    WS_MAC80211_HWSIM_ATTR_CHANNELS,
    WS_MAC80211_HWSIM_ATTR_RADIO_ID,
    WS_MAC80211_HWSIM_ATTR_REG_HINT_ALPHA2,
    WS_MAC80211_HWSIM_ATTR_REG_CUSTOM_REG,
    WS_MAC80211_HWSIM_ATTR_REG_STRICT_REG,
    WS_MAC80211_HWSIM_ATTR_SUPPORT_P2P_DEVICE,
    WS_MAC80211_HWSIM_ATTR_USE_CHANCTX,
    WS_MAC80211_HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE,
    WS_MAC80211_HWSIM_ATTR_RADIO_NAME,
    WS_MAC80211_HWSIM_ATTR_NO_VIF,
    WS_MAC80211_HWSIM_ATTR_FREQ,
    WS_MAC80211_HWSIM_ATTR_PAD,
    WS_MAC80211_HWSIM_ATTR_TX_INFO_FLAGS,
    WS_MAC80211_HWSIM_ATTR_PERM_ADDR,
    WS_MAC80211_HWSIM_ATTR_IFTYPE_SUPPORT,
    WS_MAC80211_HWSIM_ATTR_CIPHER_SUPPORT,
    WS_MAC80211_HWSIM_ATTR_MLO_SUPPORT,
    WS_MAC80211_HWSIM_ATTR_PMSR_SUPPORT,
    WS_MAC80211_HWSIM_ATTR_PMSR_REQUEST,
    WS_MAC80211_HWSIM_ATTR_PMSR_RESULT,
    WS_MAC80211_HWSIM_ATTR_MULTI_RADIO,
};

static const value_string ws_mac80211_hwsim_commands_vals[] = {
    { WS_HWSIM_CMD_UNSPEC,        "HWSIM_CMD_UNSPEC" },
    { WS_HWSIM_CMD_REGISTER,      "HWSIM_CMD_REGISTER" },
    { WS_HWSIM_CMD_FRAME,         "HWSIM_CMD_FRAME" },
    { WS_HWSIM_CMD_TX_INFO_FRAME, "HWSIM_CMD_TX_INFO_FRAME" },
    { WS_HWSIM_CMD_NEW_RADIO,     "HWSIM_CMD_NEW_RADIO" },
    { WS_HWSIM_CMD_DEL_RADIO,     "HWSIM_CMD_DEL_RADIO" },
    { WS_HWSIM_CMD_GET_RADIO,     "HWSIM_CMD_GET_RADIO" },
    { WS_HWSIM_CMD_ADD_MAC_ADDR,  "HWSIM_CMD_ADD_MAC_ADDR" },
    { WS_HWSIM_CMD_DEL_MAC_ADDR,  "HWSIM_CMD_DEL_MAC_ADDR" },
    { WS_HWSIM_CMD_START_PMSR,    "HWSIM_CMD_START_PMSR" },
    { WS_HWSIM_CMD_ABORT_PMSR,    "HWSIM_CMD_ABORT_PMSR" },
    { WS_HWSIM_CMD_REPORT_PMSR,   "HWSIM_CMD_REPORT_PMSR" },
    {0, NULL}};
static value_string_ext ws_mac80211_hwsim_commands_vals_ext = VALUE_STRING_EXT_INIT(ws_mac80211_hwsim_commands_vals);

static const value_string ws_mac80211_hwsim_attrs_vals[] = {
    { WS_MAC80211_HWSIM_ATTR_UNSPEC,                 "HWSIM_ATTR_UNSPEC" },
    { WS_MAC80211_HWSIM_ATTR_ADDR_RECEIVER,          "HWSIM_ATTR_RECEIVER" },
    { WS_MAC80211_HWSIM_ATTR_ADDR_TRANSMITTER,       "HWSIM_ATTR_TRANSMITTER" },
    { WS_MAC80211_HWSIM_ATTR_FRAME,                  "HWSIM_ATTR_FRAME" },
    { WS_MAC80211_HWSIM_ATTR_FLAGS,                  "HWSIM_ATTR_FLAGS" },
    { WS_MAC80211_HWSIM_ATTR_RX_RATE,                "HWSIM_ATTR_RX_RATE" },
    { WS_MAC80211_HWSIM_ATTR_SIGNAL,                 "HWSIM_ATTR_SIGNAL" },
    { WS_MAC80211_HWSIM_ATTR_TX_INFO,                "HWSIM_ATTR_TX_INFO" },
    { WS_MAC80211_HWSIM_ATTR_COOKIE,                 "HWSIM_ATTR_COOKIE" },
    { WS_MAC80211_HWSIM_ATTR_CHANNELS,               "HWSIM_ATTR_ATTR_CHANNELS" },
    { WS_MAC80211_HWSIM_ATTR_RADIO_ID,               "HWSIM_ATTR_RADIO_ID" },
    { WS_MAC80211_HWSIM_ATTR_REG_HINT_ALPHA2,        "HWSIM_ATTR_REG_HINT_ALPHA2" },
    { WS_MAC80211_HWSIM_ATTR_REG_CUSTOM_REG,         "HWSIM_ATTR_REG_CUSTOM_REG" },
    { WS_MAC80211_HWSIM_ATTR_REG_STRICT_REG,         "HWSIM_ATTR_REG_STRICT_REG" },
    { WS_MAC80211_HWSIM_ATTR_SUPPORT_P2P_DEVICE,     "HWSIM_ATTR_SUPPORT_P2P_DEVICE" },
    { WS_MAC80211_HWSIM_ATTR_USE_CHANCTX,            "HWSIM_ATTR_USE_CHANCTX" },
    { WS_MAC80211_HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE, "HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE" },
    { WS_MAC80211_HWSIM_ATTR_RADIO_NAME,             "HWSIM_ATTR_RADIO_NAME" },
    { WS_MAC80211_HWSIM_ATTR_NO_VIF,                 "HWSIM_ATTR_NO_VIF" },
    { WS_MAC80211_HWSIM_ATTR_FREQ,                   "HWSIM_ATTR_FREQ" },
    { WS_MAC80211_HWSIM_ATTR_PAD,                    "HWSIM_ATTR_PAD" },
    { WS_MAC80211_HWSIM_ATTR_TX_INFO_FLAGS,          "HWSIM_ATTR_TX_INFO_FLAGS" },
    { WS_MAC80211_HWSIM_ATTR_PERM_ADDR,              "HWSIM_ATTR_PERM_ADDR" },
    { WS_MAC80211_HWSIM_ATTR_IFTYPE_SUPPORT,         "HWSIM_ATTR_IFTYPE_SUPPORT" },
    { WS_MAC80211_HWSIM_ATTR_CIPHER_SUPPORT,         "HWSIM_ATTR_CIPHER_SUPPORT" },
    { WS_MAC80211_HWSIM_ATTR_MLO_SUPPORT,            "HWSIM_ATTR_MLO_SUPPORT" },
    { WS_MAC80211_HWSIM_ATTR_PMSR_SUPPORT,           "HWSIM_ATTR_PMSR_SUPPORT" },
    { WS_MAC80211_HWSIM_ATTR_PMSR_REQUEST,           "HWSIM_ATTR_PMSR_REQUEST" },
    { WS_MAC80211_HWSIM_ATTR_PMSR_RESULT,            "HWSIM_ATTR_PMSR_RESULT" },
    { WS_MAC80211_HWSIM_ATTR_MULTI_RADIO,            "HWSIM_ATTR_MULTI_RADIO" },
    {0, NULL}};
static value_string_ext ws_mac80211_hwsim_attrs_vals_ext = VALUE_STRING_EXT_INIT(ws_mac80211_hwsim_attrs_vals);

static int hf_mac80211_hwsim_commands;
static int hf_mac80211_hwsim_attrs;

static int ett_mac80211_hwsim_commands;
static int ett_mac80211_hwsim_attrs;

static int proto_netlink_mac80211_hwsim;

static dissector_handle_t netlink_mac80211_hwsim_handle;

static int hf_mac80211_hwsim_attr_value;
static int hf_mac80211_hwsim_attr_value16;
static int hf_mac80211_hwsim_attr_value32;
static int hf_mac80211_hwsim_attr_value64;
static int hf_mac80211_hwsim_radio_name;

static int ett_mac80211_hwsim;
static int ett_mac80211_hwsim_frame;
static int ett_mac80211_hwsim_tag;

static int
dissect_mac80211_hwsim_generic(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type _U_, int offset, int len)
{
    /*
     * No specific dissection available, apply arbitrary heuristics to
     * determine whether we have an u16 or u32 field and treat others as
     * opaque bytes.
     */
    if (len)
    {
        if (len == 2)
        {
            proto_tree_add_item(tree, hf_mac80211_hwsim_attr_value16, tvb, offset, len, nl_data->encoding);
        }
        else if (len == 4)
        {
            proto_tree_add_item(tree, hf_mac80211_hwsim_attr_value32, tvb, offset, len, nl_data->encoding);
        }
        else if (len == 8)
        {
            proto_tree_add_item(tree, hf_mac80211_hwsim_attr_value64, tvb, offset, len, nl_data->encoding);
        }
        else
        {
            proto_tree_add_item(tree, hf_mac80211_hwsim_attr_value, tvb, offset, len, nl_data->encoding);
        }
        offset += len;
    }
    return offset;
}

struct attr_lookup
{
    unsigned int attr_type;
    int *hfptr;
    int *ett;
    int (*func)(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len);
};

static int
dissect_value(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len, const struct attr_lookup *values)
{
    for (int i = 0; values[i].attr_type != 0; i++)
    {
        if (values[i].attr_type != (nla_type & NLA_TYPE_MASK))
        {
            continue;
        }
        proto_tree_add_item(tree, *values[i].hfptr, tvb, offset, len, nl_data->encoding);
        return offset + len;
    }
    return offset;
}

static int
dissect_mac80211_hwsim_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
    static const struct attr_lookup values[] = {
        {WS_MAC80211_HWSIM_ATTR_RADIO_NAME, &hf_mac80211_hwsim_radio_name, NULL, NULL},
        {0, NULL, NULL, NULL}};
    int offset_end = offset + len;
    if (offset < offset_end)
    {
        offset = dissect_value(tvb, data, nl_data, tree, nla_type, offset, len, values);
    }
    if (offset < offset_end)
    {
        offset = dissect_mac80211_hwsim_generic(tvb, data, nl_data, tree, nla_type, offset, len);
    }
    return offset;
}

static int
dissect_netlink_mac80211_hwsim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    netlink_mac80211_hwsim_info_t info;
    genl_info_t *genl_info = (genl_info_t *)data;
    proto_tree *nlmsg_tree;
    proto_item *pi;
    int offset;

    DISSECTOR_ASSERT(genl_info);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "mac80211_hwsim");
    col_clear(pinfo->cinfo, COL_INFO);

    offset = dissect_genl_header(tvb, genl_info, genl_info->nl_data, hf_mac80211_hwsim_commands);

    /* Return if command has no payload */
    if (!tvb_reported_length_remaining(tvb, offset))
        /* XXX If you do not set the protocol item, you cannot filter on these messages */
        return offset;

    info.pinfo = pinfo;

    pi = proto_tree_add_item(tree, proto_netlink_mac80211_hwsim, tvb, offset, -1, ENC_NA);
    nlmsg_tree = proto_item_add_subtree(pi, ett_mac80211_hwsim);

    offset = dissect_netlink_attributes_to_end(tvb, hf_mac80211_hwsim_attrs, ett_mac80211_hwsim_attrs, &info, genl_info->nl_data, nlmsg_tree, offset, dissect_mac80211_hwsim_attrs);

    return offset;
}

void proto_register_netlink_mac80211_hwsim(void)
{
    static hf_register_info hf[] = {
        { &hf_mac80211_hwsim_attr_value,
            { "Attribute Value", "mac80211_hwsim.attr_value",
              FT_BYTES, BASE_NONE, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_mac80211_hwsim_attr_value16,
            { "Attribute Value", "mac80211_hwsim.attr_value16",
              FT_UINT16, BASE_HEX_DEC, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_mac80211_hwsim_attr_value32,
            { "Attribute Value", "mac80211_hwsim.attr_value32",
              FT_UINT32, BASE_HEX_DEC, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_mac80211_hwsim_attr_value64,
            { "Attribute Value", "mac80211_hwsim.attr_value64",
              FT_UINT64, BASE_HEX_DEC, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_mac80211_hwsim_radio_name,
            { "Radio Name", "mac80211_hwsim.radio_name",
              FT_STRINGZ, BASE_NONE, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_mac80211_hwsim_commands,
            {"Command", "mac80211_hwsim.cmd",
             FT_UINT8, BASE_DEC | BASE_EXT_STRING,
             VALS_EXT_PTR(&ws_mac80211_hwsim_commands_vals_ext), 0x00,
             "Generic Netlink Command", HFILL },
        },
        { &hf_mac80211_hwsim_attrs,
            {"Attribute Type", "mac80211_hwsim.attr_type",
             FT_UINT16, BASE_DEC | BASE_EXT_STRING,
             VALS_EXT_PTR(&ws_mac80211_hwsim_attrs_vals_ext), 0x00,
             NULL, HFILL },
        },
    };

    static int *ett[] = {
        &ett_mac80211_hwsim,
        &ett_mac80211_hwsim_frame,
        &ett_mac80211_hwsim_tag,
        &ett_mac80211_hwsim_commands,
        &ett_mac80211_hwsim_attrs,
    };

    proto_netlink_mac80211_hwsim = proto_register_protocol("Linux mac80211_hwsim Netlink", "mac80211_hwsim", "mac80211_hwsim");
    proto_register_field_array(proto_netlink_mac80211_hwsim, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    netlink_mac80211_hwsim_handle = register_dissector("mac80211_hwsim", dissect_netlink_mac80211_hwsim, proto_netlink_mac80211_hwsim);
}

void proto_reg_handoff_netlink_mac80211_hwsim(void)
{
    dissector_add_string("genl.family", "MAC80211_HWSIM", netlink_mac80211_hwsim_handle);
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
