/* packet-zbee-zcl-proto-iface.c
 * Dissector routines for the ZigBee ZCL Protoco Interfaces clusters
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*  Include Files */
#include "config.h"

#include <epan/packet.h>
#include <epan/tfs.h>
#include <wsutil/array.h>

#include "packet-zbee.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zcl.h"

/* ########################################################################## */
/* #### (0x0600) GENERIC TUNNEL CLUSTER ##################################### */
/* ########################################################################## */

/* Generic Tunnel Cluster Attributes */
#define ZBEE_ZCL_ATTR_ID_GENERIC_TUNNEL_MAX_IN_TRANSFER_SIZE  0x0001
#define ZBEE_ZCL_ATTR_ID_GENERIC_TUNNEL_MAX_OUT_TRANSFER_SIZE 0x0002
#define ZBEE_ZCL_ATTR_ID_GENERIC_TUNNEL_PROTOCOL_ADDR         0x0003

static const value_string zbee_zcl_generic_tunnel_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_GENERIC_TUNNEL_MAX_IN_TRANSFER_SIZE,  "MaximumIncomingTransferSize" },
    { ZBEE_ZCL_ATTR_ID_GENERIC_TUNNEL_MAX_OUT_TRANSFER_SIZE, "MaximumOutgoingTransferSize" },
    { ZBEE_ZCL_ATTR_ID_GENERIC_TUNNEL_PROTOCOL_ADDR,         "ProtocolAddress" },
    { 0, NULL }
};

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_GENERIC_TUNNEL_MATCH_PROTOCOL_ADDR 0x00
static const value_string zbee_zcl_generic_tunnel_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_GENERIC_TUNNEL_MATCH_PROTOCOL_ADDR, "Match Protocol Address" },
    { 0, NULL }
};

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_GENERIC_TUNNEL_MATCH_PROTOCOL_ADDR_RESP 0x00
#define ZBEE_ZCL_CMD_ID_GENERIC_TUNNEL_ADVERTISE_PROTOCOL_ADDR  0x01
static const value_string zbee_zcl_generic_tunnel_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_GENERIC_TUNNEL_MATCH_PROTOCOL_ADDR_RESP, "Match Protocol Address Response" },
    { ZBEE_ZCL_CMD_ID_GENERIC_TUNNEL_ADVERTISE_PROTOCOL_ADDR,  "Advertise Protocol Address" },
    { 0, NULL }
};

/* Minimal length of the Match Protocol Address Response: EUI64 plus empty octstr */
#define ZBEE_ZCL_GT_MATCH_PROTO_ADDR_RESP_MIN_LEN 9

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_generic_tunnel(void);
void proto_reg_handoff_zbee_zcl_generic_tunnel(void);

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_generic_tunnel;

static int hf_zbee_zcl_generic_tunnel_attr_id;
static int hf_zbee_zcl_generic_tunnel_max_in_transfer_size;
static int hf_zbee_zcl_generic_tunnel_max_out_transfer_size;
static int hf_zbee_zcl_generic_tunnel_proto_addr;
static int hf_zbee_zcl_generic_tunnel_srv_rx_cmd_id;
static int hf_zbee_zcl_generic_tunnel_srv_tx_cmd_id;
static int hf_zbee_zcl_generic_tunnel_device_eui64;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_generic_tunnel;

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Generic Tunnel cluster dissector for Wireshark.
 *
 *@param tvb pointer to buffer containing raw packet
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet
 *@param data pointer to ZCL packet structure
 *@return length of parsed data
*/
static int
dissect_zbee_zcl_generic_tunnel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;
    int               rem_len;

    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_generic_tunnel_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_generic_tunnel_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        switch (cmd_id) {
            case ZBEE_ZCL_CMD_ID_GENERIC_TUNNEL_MATCH_PROTOCOL_ADDR:
                rem_len = tvb_reported_length_remaining(tvb, offset);
                if (rem_len > 0) {
                    proto_tree_add_item(tree,
                            hf_zbee_zcl_generic_tunnel_proto_addr,
                            tvb, offset, 1, ENC_ZIGBEE);
                }
                break;

            default:
                break;
        }
    } else {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_generic_tunnel_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_generic_tunnel_srv_tx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        switch (cmd_id) {
            case ZBEE_ZCL_CMD_ID_GENERIC_TUNNEL_MATCH_PROTOCOL_ADDR_RESP:
                rem_len = tvb_reported_length_remaining(tvb, offset);
                if (rem_len >= ZBEE_ZCL_GT_MATCH_PROTO_ADDR_RESP_MIN_LEN) {
                    /* Device EUI64 Address */
                    proto_tree_add_item(tree,
                            hf_zbee_zcl_generic_tunnel_device_eui64,
                            tvb, offset, 8, ENC_LITTLE_ENDIAN);
                    offset += 8;
                    /* Protocol Address */
                    proto_tree_add_item(tree,
                            hf_zbee_zcl_generic_tunnel_proto_addr,
                            tvb, offset, 1, ENC_ZIGBEE);
                }
                break;

            case ZBEE_ZCL_CMD_ID_GENERIC_TUNNEL_ADVERTISE_PROTOCOL_ADDR:
                rem_len = tvb_reported_length_remaining(tvb, offset);
                if (rem_len > 0) {
                    /* Protocol Address */
                    proto_tree_add_item(tree,
                            hf_zbee_zcl_generic_tunnel_proto_addr,
                            tvb, offset, 1, ENC_ZIGBEE);
                }
                break;

            default:
                break;
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_generic_tunnel*/

/**
 *This function is called by ZCL foundation dissector in order to decode cluster specific
 *attributes data.
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
 *@param attr_id attribute identifier
 *@param data_type attribute data type
 *@param client_attr ZCL client
*/
static void
dissect_zcl_generic_tunnel_attr_data(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    int octstr_len;

    /* Dissect attribute data type and data */
    switch (attr_id) {
        case ZBEE_ZCL_ATTR_ID_GENERIC_TUNNEL_MAX_IN_TRANSFER_SIZE:
            proto_tree_add_item(tree, hf_zbee_zcl_generic_tunnel_max_in_transfer_size, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_GENERIC_TUNNEL_MAX_OUT_TRANSFER_SIZE:
            proto_tree_add_item(tree, hf_zbee_zcl_generic_tunnel_max_out_transfer_size, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_GENERIC_TUNNEL_PROTOCOL_ADDR:
            proto_tree_add_item_ret_length(tree, hf_zbee_zcl_generic_tunnel_proto_addr, tvb, *offset, 1, ENC_ZIGBEE, &octstr_len);
            *offset += octstr_len;
            break;

        default:
            dissect_zcl_attr_data(tvb, pinfo, tree, offset, data_type, client_attr);
            break;
    }
} /*dissect_zcl_generic_tunnel_attr_data*/

/**
 *ZigBee ZCL Generic Tunnel cluster protocol registration.
 *
*/
void
proto_register_zbee_zcl_generic_tunnel(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_generic_tunnel_attr_id,
            { "Attribute", "zbee_zcl_proto_iface.generic_tunnel.attr_id", FT_UINT16, BASE_HEX,
                VALS(zbee_zcl_generic_tunnel_attr_names), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_generic_tunnel_max_in_transfer_size,
            { "Maximum Incoming Transfer Size", "zbee_zcl_proto_iface.generic_tunnel.attr.max_in_transfer_size",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_generic_tunnel_max_out_transfer_size,
            { "Maximum Outgoing Transfer Size", "zbee_zcl_proto_iface.generic_tunnel.attr.max_out_transfer_size",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_generic_tunnel_proto_addr,
            { "Protocol Address", "zbee_zcl_proto_iface.generic_tunnel.attr.proto_addr",
                FT_UINT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL } },

        { &hf_zbee_zcl_generic_tunnel_device_eui64,
            { "Device IEEE Address", "zbee_zcl_proto_iface.generic_tunnel.responding_device_eui64",
                FT_EUI64, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        { &hf_zbee_zcl_generic_tunnel_srv_rx_cmd_id,
            { "Command", "zbee_zcl_proto_iface.generic_tunnel.cmd.srv_rx_id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_generic_tunnel_srv_rx_cmd_names), 0x0, NULL, HFILL } },

        { &hf_zbee_zcl_generic_tunnel_srv_tx_cmd_id,
            { "Command", "zbee_zcl_proto_iface.generic_tunnel.cmd.srv_tx_id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_generic_tunnel_srv_tx_cmd_names), 0x0, NULL, HFILL } },
    };

    /* ZCL Generic Tunnel subtrees */
    static int *ett[] = {
        &ett_zbee_zcl_generic_tunnel
    };

    /* Register the ZigBee ZCL Generic Tunnel cluster protocol name and description */
    proto_zbee_zcl_generic_tunnel = proto_register_protocol("ZigBee ZCL Generic Tunnel", "ZCL Generic Tunnel", ZBEE_PROTOABBREV_ZCL_GENERIC_TUNNEL);
    proto_register_field_array(proto_zbee_zcl_generic_tunnel, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Generic Tunnel dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_GENERIC_TUNNEL, dissect_zbee_zcl_generic_tunnel, proto_zbee_zcl_generic_tunnel);

} /*proto_register_zbee_zcl_generic_tunnel*/

/**
 *Hands off the ZCL Generic Tunnel cluster dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_generic_tunnel(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_GENERIC_TUNNEL,
                            proto_zbee_zcl_generic_tunnel,
                            ett_zbee_zcl_generic_tunnel,
                            ZBEE_ZCL_CID_GENERIC_TUNNEL,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_generic_tunnel_attr_id,
                            hf_zbee_zcl_generic_tunnel_attr_id,
                            hf_zbee_zcl_generic_tunnel_srv_rx_cmd_id,
                            hf_zbee_zcl_generic_tunnel_srv_tx_cmd_id,
                            dissect_zcl_generic_tunnel_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_generic_tunnel*/

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
