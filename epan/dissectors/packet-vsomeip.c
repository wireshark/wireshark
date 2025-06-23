/* packet-vsomeip.c
 * vSomeIP dissector.
 * By Dr. Lars Völker <lars.voelker@technica-engineering.de>
 * Copyright 2024-2025 Dr. Lars Völker
 *
 *
 * Dissector for the vSomeIP internally used protocol.
 *
 * Specification: https://github.com/COVESA/vsomeip/blob/master/documentation/vsomeipProtocol.md
 * lua dissector: https://github.com/COVESA/vsomeip/blob/master/tools/wireshark_plugin/vsomeip-dissector.lua
 *
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>

#include <wsutil/to_str.h>

#include "packet-tcp.h"
#include "packet-udp.h"
#include "packet-someip.h"

#define VSOMEIP_NAME                            "vSomeIP"
#define VSOMEIP_NAME_LONG                       "vSomeIP"
#define VSOMEIP_NAME_FILTER                     "vsomeip"

#define VSOMEIP_NOT_IMPLEMENTED_STRING          "Not implemented yet. Please consider creating a ticket and attaching an example trace."

#define VSOMEIP_MESSAGE_SIZE_WITH_OFFSET         13
#define VSOMEIP_SIZE_OFFSET                      9
#define VSOMEIP_MESSAGE_MIN_SIZE                 17
#define VSOMEIP_SIZE_OFFSET_SUSPEND              7
#define VSOMEIP_MESSAGE_MIN_SIZE_SUSPEND         15

 /* protocol registration and config */
static int proto_vsomeip;
static module_t *vsomeip_module;

static dissector_handle_t vsomeip_handle_udp;
static dissector_handle_t vsomeip_handle_tcp;
static dissector_handle_t someip_handle;

static bool vsomeip_hide_magic = true;
static bool vsomeip_auto_register_ports = true;
static bool vsomeip_suspend_without_client = false;

/* header fields */
static int hf_vsomeip_magic_start;
static int hf_vsomeip_magic_end;
static int hf_vsomeip_command;
static int hf_vsomeip_version;
static int hf_vsomeip_client;
static int hf_vsomeip_size;

static int hf_vsomeip_unparsed;

static int hf_vsomeip_name;

static int hf_vsomeip_new_client;

static int hf_vsomeip_ri_subcmd;
static int hf_vsomeip_ri_size;
static int hf_vsomeip_ri_client;
static int hf_vsomeip_ri_ipv4;
static int hf_vsomeip_ri_port;
static int hf_vsomeip_ri_ci_size;
static int hf_vsomeip_ri_srv_size;

static int hf_vsomeip_serviceid;
static int hf_vsomeip_instanceid;
static int hf_vsomeip_majorver;
static int hf_vsomeip_minorver;
static int hf_vsomeip_eventgroupid;
static int hf_vsomeip_eventid;
static int hf_vsomeip_pendingid;
static int hf_vsomeip_subscriberid;
static int hf_vsomeip_id;

static int hf_vsomeip_instance;
static int hf_vsomeip_reliable;
static int hf_vsomeip_crc;
static int hf_vsomeip_dest;
static int hf_vsomeip_payload;

static int hf_vsomeip_notifierid;
static int hf_vsomeip_event_type;
static int hf_vsomeip_provided;
static int hf_vsomeip_cyclic;
static int hf_vsomeip_num_entries;

static int hf_vsomeip_offer_type;

static int hf_vsomeip_osr_subcmd;
static int hf_vsomeip_osr_size;

static int hf_vsomeip_pend_offer;


static int hf_vsomeip_cfg_key_size;
static int hf_vsomeip_cfg_key;
static int hf_vsomeip_cfg_val_size;
static int hf_vsomeip_cfg_val;

/* protocol tree items */
static int ett_vsomeip;
static int ett_vsomeip_ri_cmds;
static int ett_vsomeip_ri_subcmd;
static int ett_vsomeip_ri_services;
static int ett_vsomeip_ri_service;
static int ett_vsomeip_ri_subscription;
static int ett_vsomeip_someip;
static int ett_vsomeip_event_entry;
static int ett_vsomeip_offered_services;
static int ett_vsomeip_offered_services_instances;
static int ett_vsomeip_config_entry;

/* expert info items */
static expert_field ei_vsomeip_unknown_version;

/* value strings */
#define VSOMEIP_ASSIGN_CLIENT                   0x00
#define VSOMEIP_ASSIGN_CLIENT_ACK               0x01
#define VSOMEIP_REGISTER_APPLICATION            0x02
#define VSOMEIP_DEREGISTER_APPLICATION          0x03
#define VSOMEIP_APPLICATION_LOST                0x04
#define VSOMEIP_ROUTING_INFO                    0x05
#define VSOMEIP_REGISTERED_ACK                  0x06
#define VSOMEIP_PING                            0x07
#define VSOMEIP_PONG                            0x08
#define VSOMEIP_OFFER_SERVICE                   0x10
#define VSOMEIP_STOP_OFFER_SERVICE              0x11
#define VSOMEIP_SUBSCRIBE                       0x12
#define VSOMEIP_UNSUBSCRIBE                     0x13
#define VSOMEIP_REQUEST_SERVICE                 0x14
#define VSOMEIP_RELEASE_SERVICE                 0x15
#define VSOMEIP_SUBSCRIBE_NACK                  0x16
#define VSOMEIP_SUBSCRIBE_ACK                   0x17
#define VSOMEIP_SEND                            0x18
#define VSOMEIP_NOTIFY                          0x19
#define VSOMEIP_NOTIFY_ONE                      0x1A
#define VSOMEIP_REGISTER_EVENT                  0x1B
#define VSOMEIP_UNREGISTER_EVENT                0x1C
#define VSOMEIP_ID_RESPONSE                     0x1D
#define VSOMEIP_ID_REQUEST                      0x1E
#define VSOMEIP_OFFERED_SERVICES_REQUEST        0x1F
#define VSOMEIP_OFFERED_SERVICES_RESPONSE       0x20
#define VSOMEIP_UNSUBSCRIBE_ACK                 0x21
#define VSOMEIP_RESEND_PROVIDED_EVENTS          0x22
#define VSOMEIP_UPDATE_SECURITY_POLICY          0x23
#define VSOMEIP_UPDATE_SECURITY_POLICY_RESPONSE 0x24
#define VSOMEIP_REMOVE_SECURITY_POLICY          0x25
#define VSOMEIP_REMOVE_SECURITY_POLICY_RESPONSE 0x26
#define VSOMEIP_UPDATE_SECURITY_CREDENTIALS     0x27
#define VSOMEIP_DISTRIBUTE_SECURITY_POLICIES    0x28
#define VSOMEIP_UPDATE_SECURITY_POLICY_INT      0x29
#define VSOMEIP_EXPIRE                          0x2A
#define VSOMEIP_SUSPEND                         0x30
#define VSOMEIP_CONFIG                          0x31

static const value_string vsomeip_command_type[] = {
    {VSOMEIP_ASSIGN_CLIENT,                     "VSOMEIP_ASSIGN_CLIENT"},
    {VSOMEIP_ASSIGN_CLIENT_ACK,                 "VSOMEIP_ASSIGN_CLIENT_ACK"},
    {VSOMEIP_REGISTER_APPLICATION,              "VSOMEIP_REGISTER_APPLICATION"},
    {VSOMEIP_DEREGISTER_APPLICATION,            "VSOMEIP_DEREGISTER_APPLICATION"},
    {VSOMEIP_APPLICATION_LOST,                  "VSOMEIP_APPLICATION_LOST (unused)"},
    {VSOMEIP_ROUTING_INFO,                      "VSOMEIP_ROUTING_INFO"},
    {VSOMEIP_REGISTERED_ACK,                    "VSOMEIP_REGISTERED_ACK"},
    {VSOMEIP_PING,                              "VSOMEIP_PING"},
    {VSOMEIP_PONG,                              "VSOMEIP_PONG"},
    {VSOMEIP_OFFER_SERVICE,                     "VSOMEIP_OFFER_SERVICE"},
    {VSOMEIP_STOP_OFFER_SERVICE,                "VSOMEIP_STOP_OFFER_SERVICE"},
    {VSOMEIP_SUBSCRIBE,                         "VSOMEIP_SUBSCRIBE"},
    {VSOMEIP_UNSUBSCRIBE,                       "VSOMEIP_UNSUBSCRIBE"},
    {VSOMEIP_REQUEST_SERVICE,                   "VSOMEIP_REQUEST_SERVICE"},
    {VSOMEIP_RELEASE_SERVICE,                   "VSOMEIP_RELEASE_SERVICE"},
    {VSOMEIP_SUBSCRIBE_NACK,                    "VSOMEIP_SUBSCRIBE_NACK"},
    {VSOMEIP_SUBSCRIBE_ACK,                     "VSOMEIP_SUBSCRIBE_ACK"},
    {VSOMEIP_SEND,                              "VSOMEIP_SEND"},
    {VSOMEIP_NOTIFY,                            "VSOMEIP_NOTIFY"},
    {VSOMEIP_NOTIFY_ONE,                        "VSOMEIP_NOTIFY_ONE"},
    {VSOMEIP_REGISTER_EVENT,                    "VSOMEIP_REGISTER_EVENT"},
    {VSOMEIP_UNREGISTER_EVENT,                  "VSOMEIP_UNREGISTER_EVENT"},
    {VSOMEIP_ID_RESPONSE,                       "VSOMEIP_ID_RESPONSE (unused)"},
    {VSOMEIP_ID_REQUEST,                        "VSOMEIP_ID_REQUEST (unused)"},
    {VSOMEIP_OFFERED_SERVICES_REQUEST,          "VSOMEIP_OFFERED_SERVICES_REQUEST"},
    {VSOMEIP_OFFERED_SERVICES_RESPONSE,         "VSOMEIP_OFFERED_SERVICES_RESPONSE"},
    {VSOMEIP_UNSUBSCRIBE_ACK,                   "VSOMEIP_UNSUBSCRIBE_ACK"},
    {VSOMEIP_RESEND_PROVIDED_EVENTS,            "VSOMEIP_RESEND_PROVIDED_EVENTS"},
    {VSOMEIP_UPDATE_SECURITY_POLICY,            "VSOMEIP_UPDATE_SECURITY_POLICY"},
    {VSOMEIP_UPDATE_SECURITY_POLICY_RESPONSE,   "VSOMEIP_UPDATE_SECURITY_POLICY_RESPONSE"},
    {VSOMEIP_REMOVE_SECURITY_POLICY,            "VSOMEIP_REMOVE_SECURITY_POLICY"},
    {VSOMEIP_REMOVE_SECURITY_POLICY_RESPONSE,   "VSOMEIP_REMOVE_SECURITY_POLICY_RESPONSE"},
    {VSOMEIP_UPDATE_SECURITY_CREDENTIALS,       "VSOMEIP_UPDATE_SECURITY_CREDENTIALS"},
    {VSOMEIP_DISTRIBUTE_SECURITY_POLICIES,      "VSOMEIP_DISTRIBUTE_SECURITY_POLICIES"},
    {VSOMEIP_UPDATE_SECURITY_POLICY_INT,        "VSOMEIP_UPDATE_SECURITY_POLICY_INT"},
    {VSOMEIP_EXPIRE,                            "VSOMEIP_EXPIRE"},
    {VSOMEIP_SUSPEND,                           "VSOMEIP_SUSPEND"},
    {VSOMEIP_CONFIG,                            "VSOMEIP_CONFIG"},
    {0, NULL}
};


#define VSOMEIP_RELIABLE_UDP                    0x00
#define VSOMEIP_RELIABLE_TCP                    0x01

static const value_string vsomeip_reliable_type[] = {
    {VSOMEIP_RELIABLE_UDP,                      "UDP"},
    {VSOMEIP_RELIABLE_TCP,                      "TCP"},
    {0, NULL}
};


#define VSOMEIP_SUBCMD_RIE_ADD_CLIENT           0x00
#define VSOMEIP_SUBCMD_RIE_DEL_CLIENT           0x01
#define VSOMEIP_SUBCMD_RIE_ADD_SERVICE_INSTANCE 0x02
#define VSOMEIP_SUBCMD_RIE_DEL_SERVICE_INSTANCE 0x04

static const value_string vsomeip_rie_subcmd_type[] = {
    {VSOMEIP_SUBCMD_RIE_ADD_CLIENT,             "RIE_ADD_CLIENT"},
    {VSOMEIP_SUBCMD_RIE_DEL_CLIENT,             "RIE_DEL_CLIENT"},
    {VSOMEIP_SUBCMD_RIE_ADD_SERVICE_INSTANCE,   "RIE_ADD_SERVICE_INSTANCE"},
    {VSOMEIP_SUBCMD_RIE_DEL_SERVICE_INSTANCE,   "RIE_DEL_SERVICE_INSTANCE"},
    {0, NULL}
};


#define VSOMEIP_ET_EVENT                        0x00
#define VSOMEIP_ET_SELECTIVE_EVENT              0x01
#define VSOMEIP_ET_FIELD                        0x02

static const value_string vsomeip_event_type[] = {
    {VSOMEIP_ET_EVENT,                          "ET_EVENT "},
    {VSOMEIP_ET_SELECTIVE_EVENT,                "ET_SELECTIVE_EVENT"},
    {VSOMEIP_ET_FIELD,                          "ET_FIELD"},
    {0, NULL}
};


#define VSOMEIP_FALSE                           0x00
#define VSOMEIP_TRUE                            0x01

static const value_string vsomeip_false_true_type[] = {
    {VSOMEIP_FALSE,                             "No"},
    {VSOMEIP_TRUE,                              "Yes"},
    {0, NULL}
};


#define VSOMEIP_LOCAL                           0x00
#define VSOMEIP_REMOTE                          0x01
#define VSOMEIP_ALL                             0x02

static const value_string vsomeip_offer_type[] = {
    {VSOMEIP_LOCAL,                             "Local"},
    {VSOMEIP_REMOTE,                            "Remote"},
    {VSOMEIP_ALL,                               "All"},
    {0, NULL}
};


/* yes, very similar to above but different IDs :-( */
#define VSOMEIP_SUBCMD_OSR_ADD_CLIENT           0x00
#define VSOMEIP_SUBCMD_OSR_ADD_SERVICE_INSTANCE 0x01
#define VSOMEIP_SUBCMD_OSR_DEL_SERVICE_INSTANCE 0x02
#define VSOMEIP_SUBCMD_OSR_DEL_CLIENT           0x03

static const value_string vsomeip_osr_subcmd_type[] = {
    {VSOMEIP_SUBCMD_OSR_ADD_CLIENT,             "ADD CLIENT"},
    {VSOMEIP_SUBCMD_OSR_ADD_SERVICE_INSTANCE,   "ADD SERVICE INSTANCE"},
    {VSOMEIP_SUBCMD_OSR_DEL_SERVICE_INSTANCE,   "DELETE SERVICE INSTANCE"},
    {VSOMEIP_SUBCMD_OSR_DEL_CLIENT,             "DELETE CLIENT"},
    {0, NULL}
};

void proto_register_vsomeip(void);
void proto_reg_handoff_vsomeip(void);

static int
dissect_vsomeip_service_instance(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset_orig, int entry_number, bool add_to_info_col) {
    int offset = offset_orig;
    proto_item *ti;

    proto_item *ti_service;
    proto_tree *tree_service = proto_tree_add_subtree_format(tree, tvb, offset, 9, ett_vsomeip_ri_service, &ti_service, "%d:", entry_number);

    uint32_t service_id;
    proto_tree_add_item_ret_uint(tree_service, hf_vsomeip_serviceid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &service_id);
    offset += 2;

    uint32_t instance_id;
    proto_tree_add_item_ret_uint(tree_service, hf_vsomeip_instanceid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &instance_id);
    offset += 2;

    proto_item_append_text(ti_service, " Service-ID: 0x%04x Instance-ID: 0x%04x Version ", service_id, instance_id);

    uint32_t major_version;
    ti = proto_tree_add_item_ret_uint(tree_service, hf_vsomeip_majorver, tvb, offset, 1, ENC_NA, &major_version);
    if (major_version == 0xff) {
        proto_item_append_text(ti, " (any)");
        proto_item_append_text(ti_service, "%s.", "any");
    } else {
        proto_item_append_text(ti_service, "%u.", major_version);
    }
    offset += 1;

    uint32_t minor_version;
    ti = proto_tree_add_item_ret_uint(tree_service, hf_vsomeip_minorver, tvb, offset, 4, ENC_LITTLE_ENDIAN, &minor_version);
    if (minor_version == 0xffffffff) {
        proto_item_append_text(ti, " (any)");
        proto_item_append_text(ti_service, "%s", "*");
    } else {
        proto_item_append_text(ti_service, "%u", minor_version);
    }
    offset += 4;

    if (add_to_info_col) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%04x.%04x]", service_id, instance_id);
    }

    return offset - offset_orig;
}

static int
dissect_vsomeip_service_instances(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset_orig, int size, bool add_to_info_col) {
    int offset = offset_orig;

    if (size > 0) {
        proto_tree *tree_services = proto_tree_add_subtree(tree, tvb, offset, size, ett_vsomeip_ri_services, NULL, "Services");

        int service_number = 0;
        int offset_srv_end = offset + size;
        while (offset + 9 <= offset_srv_end) {
            offset += dissect_vsomeip_service_instance(tvb, pinfo, tree_services, offset, service_number, add_to_info_col);
            service_number += 1;
        }
    }

    return offset - offset_orig;
}


static int
dissect_vsomeip_subscription(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset_orig, int entry_number, bool add_to_info_col) {
    int offset = offset_orig;
    proto_item *ti;

    proto_item *ti_subscription;
    proto_tree *tree_sub = proto_tree_add_subtree_format(tree, tvb, offset, 9, ett_vsomeip_ri_subscription, &ti_subscription, "%d:", entry_number);

    uint32_t service_id;
    proto_tree_add_item_ret_uint(tree_sub, hf_vsomeip_serviceid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &service_id);
    offset += 2;

    uint32_t instance_id;
    proto_tree_add_item_ret_uint(tree_sub, hf_vsomeip_instanceid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &instance_id);
    offset += 2;

    uint32_t eventgroup_id;
    proto_tree_add_item_ret_uint(tree_sub, hf_vsomeip_eventgroupid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &eventgroup_id);
    offset += 2;

    uint32_t major_version;
    ti = proto_tree_add_item_ret_uint(tree_sub, hf_vsomeip_majorver, tvb, offset, 1, ENC_NA, &major_version);
    if (major_version == 0xff) {
        proto_item_append_text(ti, " (any)");
    }
    offset += 1;

    uint32_t event_id;
    proto_tree_add_item_ret_uint(tree_sub, hf_vsomeip_eventid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &event_id);
    offset += 2;

    uint32_t pending_id;
    proto_tree_add_item_ret_uint(tree_sub, hf_vsomeip_pendingid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &pending_id);
    offset += 2;

    proto_item_append_text(ti_subscription, " Service-ID: 0x%04x Instance-ID: 0x%04x Eventgroup-ID: 0x%04x Event-ID: 0x%04x Version ", service_id, instance_id, eventgroup_id, event_id);

    if (major_version == 0xff) {
        proto_item_append_text(ti_subscription, "%s", "*");
    } else {
        proto_item_append_text(ti_subscription, "%u", major_version);
    }

    if (add_to_info_col) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%04x.%04x.%04x.%04x]", service_id, instance_id, eventgroup_id, event_id);
    }

    return offset - offset_orig;
}

static int
dissect_vsomeip_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_root, void *data _U_) {
    proto_item     *ti = NULL;
    proto_item     *ti_root;
    proto_tree     *tree;

    int             offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, VSOMEIP_NAME);
    ti_root = proto_tree_add_item(tree_root, proto_vsomeip, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(ti_root, ett_vsomeip);

    ti = proto_tree_add_item(tree, hf_vsomeip_magic_start, tvb, offset, 4, ENC_NA);
    /* TODO: should check that magic is 0x67 0x37 0x6d 0x07 */
    offset += 4;

    if (vsomeip_hide_magic) {
        proto_item_set_hidden(ti);
    }

    uint32_t cmd;
    proto_tree_add_item_ret_uint(tree, hf_vsomeip_command, tvb, offset, 1, ENC_NA, &cmd);
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str(cmd, vsomeip_command_type, "VSOMEIP CMD 0x%02x"));
    offset += 1;

    proto_tree_add_item(tree, hf_vsomeip_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    if (cmd != VSOMEIP_SUSPEND || !vsomeip_suspend_without_client) {
        uint32_t client;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_client, tvb, offset, 2, ENC_LITTLE_ENDIAN, &client);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%04x)", client);
        offset += 2;
    }

    uint32_t size;
    proto_tree_add_item_ret_uint(tree, hf_vsomeip_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &size);
    offset += 4;

    proto_item_append_text(ti_root, ": %s", val_to_str(cmd, vsomeip_command_type, "VSOMEIP CMD 0x%02x"));

    int offset_end = offset + size;

    switch (cmd) {
    case VSOMEIP_ASSIGN_CLIENT: {
        const uint8_t *name;
        proto_tree_add_item_ret_string(tree, hf_vsomeip_name, tvb, offset, size, ENC_UTF_8, pinfo->pool, &name);
        offset += size;

        col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);
    }
        break;

    case VSOMEIP_ASSIGN_CLIENT_ACK: {
        uint32_t newclient;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_new_client, tvb, offset, 2, ENC_LITTLE_ENDIAN, &newclient);
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, " --> (%04x)", newclient);
    }
        break;

    /* yes, fall through */
    case VSOMEIP_REGISTER_APPLICATION:
    case VSOMEIP_DEREGISTER_APPLICATION:
        /* Nothing to do */
        break;

    case VSOMEIP_APPLICATION_LOST:
        /* Unused */
        break;

    case VSOMEIP_ROUTING_INFO: {
        proto_tree *tree_ri = proto_tree_add_subtree_format(tree, tvb, offset, size, ett_vsomeip_ri_cmds, NULL, "Routing Info Commands");

        /* this can have multiple entries of different formats */
        while (offset + 5 < offset_end) {
            uint32_t subcmd_start = offset;
            uint32_t subcmd_size = tvb_get_uint32(tvb, offset + 1, ENC_LITTLE_ENDIAN);

            uint32_t subcmd = tvb_get_uint8(tvb, offset);
            const char *subcmd_text = val_to_str(subcmd, vsomeip_rie_subcmd_type, " Unknown Subcommand: %02x");

            proto_item *ti_subcmd;
            proto_tree *tree_subcmd = proto_tree_add_subtree_format(tree_ri, tvb, offset, 5 + subcmd_size, ett_vsomeip_ri_subcmd, &ti_subcmd, "%s", subcmd_text);

            proto_tree_add_item(tree_subcmd, hf_vsomeip_ri_subcmd, tvb, offset, 1, ENC_NA);
            col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", subcmd_text);
            offset += 1;

            proto_tree_add_item(tree_subcmd, hf_vsomeip_ri_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            if (subcmd == VSOMEIP_SUBCMD_RIE_ADD_CLIENT || subcmd == VSOMEIP_SUBCMD_RIE_DEL_CLIENT ||
                subcmd == VSOMEIP_SUBCMD_RIE_ADD_SERVICE_INSTANCE || subcmd == VSOMEIP_SUBCMD_RIE_DEL_SERVICE_INSTANCE) {

                uint32_t ci_size = subcmd_size;
                if (subcmd == VSOMEIP_SUBCMD_RIE_ADD_SERVICE_INSTANCE || subcmd == VSOMEIP_SUBCMD_RIE_DEL_SERVICE_INSTANCE) {
                    proto_tree_add_item_ret_uint(tree_subcmd, hf_vsomeip_ri_ci_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ci_size);
                    offset += 4;
                }

                if (ci_size >= 2) {
                    uint32_t ri_client;
                    proto_tree_add_item_ret_uint(tree_subcmd, hf_vsomeip_ri_client, tvb, offset, 2, ENC_LITTLE_ENDIAN, &ri_client);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Client=0x%04x", ri_client);
                    proto_item_append_text(ti_subcmd, " Client=0x%04x", ri_client);
                    offset += 2;
                }

                if (ci_size == 8) {
                    /* found IPv4 Address + Port Number*/
                    ws_in4_addr addr_ipv4;
                    proto_tree_add_item_ret_ipv4(tree_subcmd, hf_vsomeip_ri_ipv4, tvb, offset, 4, ENC_NA, &addr_ipv4);
                    offset += 4;

                    uint32_t portnumber;
                    proto_tree_add_item_ret_uint(tree_subcmd, hf_vsomeip_ri_port, tvb, offset, 2, ENC_LITTLE_ENDIAN, &portnumber);
                    offset += 2;

                    if (vsomeip_auto_register_ports) {
                        dissector_add_uint("tcp.port", portnumber, vsomeip_handle_tcp);
                    }

                    col_append_fstr(pinfo->cinfo, COL_INFO, " %s:%d", ip_addr_to_str(pinfo->pool, &addr_ipv4), portnumber);
                    proto_item_append_text(ti_subcmd, " %s:%d", ip_addr_to_str(pinfo->pool, &addr_ipv4), portnumber);
                } else {
                    /* TODO: add code to dissect IPv6? other?*/
                    offset += ci_size - 2;
                }

                if (subcmd == VSOMEIP_SUBCMD_RIE_ADD_SERVICE_INSTANCE || subcmd == VSOMEIP_SUBCMD_RIE_DEL_SERVICE_INSTANCE) {
                    uint32_t srv_size;
                    proto_tree_add_item_ret_uint(tree_subcmd, hf_vsomeip_ri_srv_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &srv_size);
                    offset += 4;

                    offset += dissect_vsomeip_service_instances(tvb, pinfo, tree_subcmd, offset, srv_size, false);
                }
            }

            if (offset < (int)(subcmd_start + subcmd_size)) {
                proto_tree_add_item(tree_subcmd, hf_vsomeip_unparsed, tvb, offset, subcmd_start + subcmd_size - offset, ENC_NA);
            }
        }
    }
        break;

    /* yes, fall through */
    case VSOMEIP_REGISTERED_ACK:
    case VSOMEIP_PING:
    case VSOMEIP_PONG:
        /* Nothing to do */
        break;

    /* yes, fall through */
    case VSOMEIP_OFFER_SERVICE:
    case VSOMEIP_STOP_OFFER_SERVICE:
        offset += dissect_vsomeip_service_instance(tvb, pinfo, tree, offset, 0, true);
        break;

    /* yes, fall through */
    case VSOMEIP_SUBSCRIBE:
    case VSOMEIP_UNSUBSCRIBE:
    case VSOMEIP_EXPIRE:
        offset += dissect_vsomeip_subscription(tvb, pinfo, tree, offset, 0, true);
        /* TODO: VSOMEIP_SUBSCRIBE: With size greater 11, there could be a filter here says the documentation. But we did not see it yet... */
        break;

    case VSOMEIP_REQUEST_SERVICE:
        offset += dissect_vsomeip_service_instances(tvb, pinfo, tree, offset, size, true);
        break;

    case VSOMEIP_RELEASE_SERVICE: {
        uint32_t service_id;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_serviceid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &service_id);
        offset += 2;

        uint32_t instance_id;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_instanceid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &instance_id);
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, " [%04x.%04x]", service_id, instance_id);
    }
        break;

    /* yes, fall through */
    case VSOMEIP_SUBSCRIBE_NACK:
    case VSOMEIP_SUBSCRIBE_ACK: {
        uint32_t service_id;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_serviceid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &service_id);
        offset += 2;

        uint32_t instance_id;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_instanceid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &instance_id);
        offset += 2;

        uint32_t eventgroup_id;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_eventgroupid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &eventgroup_id);
        offset += 2;

        uint32_t subscriber_id;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_subscriberid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &subscriber_id);
        offset += 2;

        uint32_t event_id;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_eventid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &event_id);
        offset += 2;

        uint32_t sub_id;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &sub_id);
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, " [%04x.%04x.%04x.%04x] (%04x)", service_id, instance_id, eventgroup_id, event_id, subscriber_id);
    }
        break;

    /* yes, fall through */
    case VSOMEIP_SEND:
    case VSOMEIP_NOTIFY:
    case VSOMEIP_NOTIFY_ONE: {
        proto_tree_add_item(tree, hf_vsomeip_instance, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        uint32_t reliable;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_reliable, tvb, offset, 1, ENC_NA, &reliable);
        offset += 1;

        proto_tree_add_item(tree, hf_vsomeip_crc, tvb, offset, 1, ENC_NA);
        offset += 1;

        uint32_t dest;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_dest, tvb, offset, 2, ENC_BIG_ENDIAN, &dest);
        offset += 2;

        /* A SOME/IP messages follows with the layout (all big endian!):
         * Service-ID [2]
         * Method-ID [2]
         * ...
         */
        uint32_t service_id = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
        uint32_t method_id = tvb_get_uint16(tvb, offset + 2, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, " --%s--> (%04x): ", val_to_str_const(reliable, vsomeip_reliable_type, "Unknown"), dest);

        proto_item_append_text(ti_root, " [Service: 0x%04x Method: 0x%04x]", service_id, method_id);


        /* hand off to SOME/IP dissector !*/
        col_set_fence(pinfo->cinfo, COL_INFO);
        uint32_t someip_message_length = size - 6;
        tvbuff_t *subtvb = tvb_new_subset_length(tvb, offset, someip_message_length);

        ti = proto_tree_add_item(tree, hf_vsomeip_payload, tvb, offset, someip_message_length, ENC_NA);
        call_dissector(someip_handle, subtvb, pinfo, proto_item_add_subtree(ti, ett_vsomeip_someip));
        offset += someip_message_length;

        col_clear_fence(pinfo->cinfo, COL_INFO);
    }
        break;

    case VSOMEIP_REGISTER_EVENT: {
        int offset_entries_end = offset + size;

        while (offset + 10 <= offset_entries_end) {
            proto_item *ti_entry;
            proto_tree *tree_entry = proto_tree_add_subtree(tree, tvb, offset, -1, ett_vsomeip_event_entry, &ti_entry, "Event: ");

            uint32_t service_id;
            proto_tree_add_item_ret_uint(tree_entry, hf_vsomeip_serviceid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &service_id);
            offset += 2;

            uint32_t instance_id;
            proto_tree_add_item_ret_uint(tree_entry, hf_vsomeip_instanceid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &instance_id);
            offset += 2;

            uint32_t notifier_id;
            proto_tree_add_item_ret_uint(tree_entry, hf_vsomeip_notifierid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &notifier_id);
            offset += 2;

            proto_tree_add_item(tree_entry, hf_vsomeip_event_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree_entry, hf_vsomeip_provided, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree_entry, hf_vsomeip_reliable, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree_entry, hf_vsomeip_cyclic, tvb, offset, 1, ENC_NA);
            offset += 1;

            uint32_t num_entries;
            proto_tree_add_item_ret_uint(tree_entry, hf_vsomeip_num_entries, tvb, offset, 2, ENC_LITTLE_ENDIAN, &num_entries);
            offset += 2;

            uint32_t i;
            for (i = 0; i < num_entries; i++) {
                proto_tree_add_item(tree_entry, hf_vsomeip_eventgroupid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }

            proto_item_append_text(ti_entry, "[%04x.%04x.%04x]", service_id, instance_id, notifier_id);
            col_append_fstr(pinfo->cinfo, COL_INFO, " [%04x.%04x.%04x]", service_id, instance_id, notifier_id);
        }
    }
        break;

    case VSOMEIP_UNREGISTER_EVENT: {
        uint32_t service_id;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_serviceid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &service_id);
        offset += 2;

        uint32_t instance_id;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_instanceid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &instance_id);
        offset += 2;

        uint32_t notifier_id;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_notifierid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &notifier_id);
        offset += 2;

        proto_tree_add_item(tree, hf_vsomeip_provided, tvb, offset, 1, ENC_NA);
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, " [%04x.%04x.%04x]", service_id, instance_id, notifier_id);
    }
        break;

    /* yes, fall through */
    case VSOMEIP_ID_RESPONSE:
    case VSOMEIP_ID_REQUEST:
        /* Unused */
        break;

    case VSOMEIP_OFFERED_SERVICES_REQUEST:
        proto_tree_add_item(tree, hf_vsomeip_offer_type, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;

    case VSOMEIP_OFFERED_SERVICES_RESPONSE: {
        int offset_services_end = offset + size;

        while (offset + 5 <= offset_services_end) {
            uint32_t instances_size = tvb_get_uint32(tvb, offset + 1, ENC_LITTLE_ENDIAN);

            proto_item *ti_services;
            proto_tree *tree_services = proto_tree_add_subtree(tree, tvb, offset, 5 + instances_size, ett_vsomeip_offered_services, &ti_services, "Offered Services: ");

            uint32_t subcmd;
            proto_tree_add_item_ret_uint(tree_services, hf_vsomeip_osr_subcmd, tvb, offset, 1, ENC_NA, &subcmd);
            offset += 1;

            proto_tree_add_item(tree_services, hf_vsomeip_osr_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_item *ti_instances;
            proto_tree *tree_instances = proto_tree_add_subtree(tree_services, tvb, offset, instances_size, ett_vsomeip_offered_services, &ti_instances, "Service Instances");

            /* XXX - Documentation for format seems to be wrong. Major and Minor Version are 2 bytes each. Before 1 and 4 as in SOME/IP! */
            /*       Until we find some traces and clarification, lets skip those bytes! */
            proto_tree_add_item(tree_instances, hf_vsomeip_unparsed, tvb, offset, instances_size, ENC_NA);
            offset += instances_size;

            /* TODO: add text to ti_services, ti_instances, and COL_INFO, if needed */
        }
    }
        break;

    case VSOMEIP_UNSUBSCRIBE_ACK: {
        uint32_t service_id;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_serviceid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &service_id);
        offset += 2;

        uint32_t instance_id;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_instanceid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &instance_id);
        offset += 2;

        uint32_t eventgroup_id;
        proto_tree_add_item_ret_uint(tree, hf_vsomeip_eventgroupid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &eventgroup_id);
        offset += 2;

        proto_tree_add_item(tree, hf_vsomeip_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, " [%04x.%04x.%04x]", service_id, instance_id, eventgroup_id);
    }
        break;

    case VSOMEIP_RESEND_PROVIDED_EVENTS:
        proto_tree_add_item(tree, hf_vsomeip_pend_offer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;

    /* yes, fall through */
    case VSOMEIP_UPDATE_SECURITY_POLICY:
    case VSOMEIP_UPDATE_SECURITY_POLICY_INT:
        /* TODO ! */

        proto_tree_add_text_internal(tree, tvb, offset, size, VSOMEIP_NOT_IMPLEMENTED_STRING);
        col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
        break;

    case VSOMEIP_UPDATE_SECURITY_POLICY_RESPONSE:
        /* TODO ! */

        proto_tree_add_text_internal(tree, tvb, offset, size, VSOMEIP_NOT_IMPLEMENTED_STRING);
        col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
        break;

    case VSOMEIP_REMOVE_SECURITY_POLICY:
        /* TODO ! */

        proto_tree_add_text_internal(tree, tvb, offset, size, VSOMEIP_NOT_IMPLEMENTED_STRING);
        col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
        break;

    case VSOMEIP_REMOVE_SECURITY_POLICY_RESPONSE:
        /* TODO ! */

        proto_tree_add_text_internal(tree, tvb, offset, size, VSOMEIP_NOT_IMPLEMENTED_STRING);
        col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
        break;

    case VSOMEIP_UPDATE_SECURITY_CREDENTIALS:
        /* TODO ! */

        proto_tree_add_text_internal(tree, tvb, offset, size, VSOMEIP_NOT_IMPLEMENTED_STRING);
        col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
        break;

    case VSOMEIP_DISTRIBUTE_SECURITY_POLICIES:
        /* TODO ! */

        proto_tree_add_text_internal(tree, tvb, offset, size, VSOMEIP_NOT_IMPLEMENTED_STRING);
        col_append_str(pinfo->cinfo, COL_INFO, "   *** NOT IMPLEMENTED YET ***");
        break;

    case VSOMEIP_SUSPEND:
        /* Nothing to do */
        break;

    case VSOMEIP_CONFIG: {
        int config_end = offset + size;

        while (config_end > offset) {
            uint32_t key_length = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
            uint32_t value_length = tvb_get_uint32(tvb, offset + 4 + key_length, ENC_LITTLE_ENDIAN);

            proto_item *ti_tree;
            proto_tree *tree_cfg = proto_tree_add_subtree(tree, tvb, offset, key_length + value_length + 8, ett_vsomeip_config_entry, &ti_tree, "Config: ");

            proto_tree_add_item(tree_cfg, hf_vsomeip_cfg_key_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            const uint8_t *key;
            proto_tree_add_item_ret_string(tree_cfg, hf_vsomeip_cfg_key, tvb, offset, key_length, ENC_UTF_8, pinfo->pool, &key);
            offset += key_length;

            proto_tree_add_item(tree_cfg, hf_vsomeip_cfg_val_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            const uint8_t *value;
            proto_tree_add_item_ret_string(tree_cfg, hf_vsomeip_cfg_val, tvb, offset, value_length, ENC_UTF_8, pinfo->pool, &value);
            offset += value_length;

            proto_item_append_text(ti_tree, "%s=%s", key, value);
            col_append_fstr(pinfo->cinfo, COL_INFO, "  %s=%s", key, value);
        }
    }
        break;

    }

    if (offset < offset_end) {
        proto_tree_add_item(tree, hf_vsomeip_unparsed, tvb, offset, offset_end - offset, ENC_NA);
        offset = offset_end;
    }

    ti = proto_tree_add_item(tree, hf_vsomeip_magic_end, tvb, offset, 4, ENC_NA);
    /* TODO: should check that magic is 0x07 0x6d 0x37 0x67 */
    offset += 4;

    if (vsomeip_hide_magic) {
        proto_item_set_hidden(ti);
    }

    proto_item_set_end(ti_root, tvb, offset);
    return offset;
}

static unsigned
get_vsomeip_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_) {
    /*
     * Regular Layout:
     *
     * Magic [4]
     * Header
     *   04: Command [1]
     *   05: Version [2]
     *   07: Client  [2]
     *   09: Size    [4]
     *   13: Payload [Size]
     * Magic [04]
     *
     * Unfortunately, for Command == VSOMEIP_SUSPEND, this changes:
     * - Client is removed; thus, positions after are 2 bytes earlier (says documentation)
     *
     * Even worse: In traces it seems that the documented layout might not be correct as two additional bytes are present
     * in traces and the lua dissector!
     * So we need a config item to adapt to it...
     */

    uint32_t cmd = tvb_get_uint8(tvb, 4);
    if (cmd == VSOMEIP_SUSPEND && vsomeip_suspend_without_client) {
        return VSOMEIP_MESSAGE_MIN_SIZE_SUSPEND + (unsigned)tvb_get_uint32(tvb, offset + VSOMEIP_SIZE_OFFSET_SUSPEND, ENC_LITTLE_ENDIAN);
    }

    return VSOMEIP_MESSAGE_MIN_SIZE + (unsigned)tvb_get_uint32(tvb, offset + VSOMEIP_SIZE_OFFSET, ENC_LITTLE_ENDIAN);
}

static int
dissect_vsomeip_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    tcp_dissect_pdus(tvb, pinfo, tree, true, VSOMEIP_MESSAGE_SIZE_WITH_OFFSET, get_vsomeip_message_len, dissect_vsomeip_message, data);
    return tvb_reported_length(tvb);
}

/* Currently binding using UDP not commonly used but created just in case */
static int
dissect_vsomeip_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return udp_dissect_pdus(tvb, pinfo, tree, VSOMEIP_MESSAGE_SIZE_WITH_OFFSET, NULL, get_vsomeip_message_len, dissect_vsomeip_message, data);
}

void
proto_register_vsomeip(void) {
    expert_module_t *expert_module_vsomeip;

    /* data fields */
    static hf_register_info hf[] = {
        { &hf_vsomeip_magic_start,  { "Magic", "vsomeip.magic_start", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_magic_end,    { "Magic", "vsomeip.magic_end", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_command,      { "Command", "vsomeip.command", FT_UINT8, BASE_HEX, VALS(vsomeip_command_type), 0x0, NULL, HFILL }},
        { &hf_vsomeip_version,      { "Version", "vsomeip.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_client,       { "Client", "vsomeip.client", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_size,         { "Size", "vsomeip.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_vsomeip_unparsed,     { "Unparsed", "vsomeip.unparsed", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_vsomeip_name,         { "Name", "vsomeip.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_vsomeip_new_client,   { "New Client", "vsomeip.newclient", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_vsomeip_ri_subcmd,    { "SubCommand", "vsomeip.routing_info.subcommand", FT_UINT8, BASE_HEX, VALS(vsomeip_rie_subcmd_type), 0x0, NULL, HFILL }},
        { &hf_vsomeip_ri_size,      { "Size", "vsomeip.routing_info.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_ri_client,    { "Client", "vsomeip.routing_info.client", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_ri_ipv4,      { "Address", "vsomeip.routing_info.address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_ri_port,      { "Port", "vsomeip.routing_info.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_ri_ci_size,   { "Client Info Size", "vsomeip.routing_info.size_client", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_ri_srv_size,  { "Service Info Size", "vsomeip.routing_info.size_services", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_vsomeip_serviceid,    { "Service ID", "vsomeip.service_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_instanceid,   { "Instance ID", "vsomeip.instance_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_majorver,     { "Major Version", "vsomeip.major_version", FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_minorver,     { "Minor Version", "vsomeip.minor_version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_eventgroupid, { "Eventgroup ID", "vsomeip.eventgroup_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_eventid,      { "Event ID", "vsomeip.event_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_pendingid,    { "Pending ID", "vsomeip.pending_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_subscriberid, { "Subscriber ID", "vsomeip.subscriber_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_id,           { "ID", "vsomeip.id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_vsomeip_instance,     { "Instance", "vsomeip.instance", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_reliable,     { "Reliable", "vsomeip.reliable", FT_UINT8, BASE_DEC, VALS(vsomeip_reliable_type), 0x0, NULL, HFILL }},
        { &hf_vsomeip_crc,          { "CRC", "vsomeip.crc", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_dest,         { "Destination Client", "vsomeip.dst_client", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_payload,      { "Payload", "vsomeip.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_vsomeip_notifierid,   { "Notifier ID", "vsomeip.notifier_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_event_type,   { "Type", "vsomeip.event_type", FT_UINT8, BASE_DEC, VALS(vsomeip_event_type), 0x0, NULL, HFILL }},
        { &hf_vsomeip_provided,     { "Provided", "vsomeip.provided", FT_UINT8, BASE_DEC, VALS(vsomeip_false_true_type), 0x0, NULL, HFILL }},
        { &hf_vsomeip_cyclic,       { "Is Cyclic", "vsomeip.cyclic", FT_UINT8, BASE_DEC, VALS(vsomeip_false_true_type), 0x0, NULL, HFILL }},
        { &hf_vsomeip_num_entries,  { "Number of Entries", "vsomeip.number_of_entries", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_vsomeip_offer_type,   { "Offer Type", "vsomeip.offer_type", FT_UINT8, BASE_DEC, VALS(vsomeip_offer_type), 0x0, NULL, HFILL }},

        { &hf_vsomeip_osr_subcmd,   { "SubCommand", "vsomeip.offered_services.subcommand", FT_UINT8, BASE_HEX, VALS(vsomeip_osr_subcmd_type), 0x0, NULL, HFILL }},
        { &hf_vsomeip_osr_size,     { "Size", "vsomeip.offered_services.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_vsomeip_pend_offer,   { "Pending Offer ID", "vsomeip.pending_offer_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_vsomeip_cfg_key_size, { "Key Size", "vsomeip.config.key_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_cfg_key,      { "Key", "vsomeip.config.key", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_cfg_val_size, { "Value Size", "vsomeip.config.value_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_vsomeip_cfg_val,      { "Value", "vsomeip.config.value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_vsomeip,
        &ett_vsomeip_ri_cmds,
        &ett_vsomeip_ri_subcmd,
        &ett_vsomeip_ri_services,
        &ett_vsomeip_ri_service,
        &ett_vsomeip_ri_subscription,
        &ett_vsomeip_someip,
        &ett_vsomeip_event_entry,
        &ett_vsomeip_offered_services,
        &ett_vsomeip_offered_services_instances,
        &ett_vsomeip_config_entry,
    };

    static ei_register_info ei[] = {
        { &ei_vsomeip_unknown_version,{ "vsomeip.unknown_protocol_version", PI_PROTOCOL, PI_WARN, "vSomeIP Unknown Protocol Version!", EXPFILL } },
    };

    /* Register Protocol, Handles, Fields, ETTs, Expert Info */
    proto_vsomeip = proto_register_protocol(VSOMEIP_NAME_LONG, VSOMEIP_NAME, VSOMEIP_NAME_FILTER);
    vsomeip_handle_udp = register_dissector("vsomeip_udp", dissect_vsomeip_udp, proto_vsomeip);
    vsomeip_handle_tcp = register_dissector("vsomeip_tcp", dissect_vsomeip_tcp, proto_vsomeip);
    register_dissector("vsomeip", dissect_vsomeip_message, proto_vsomeip);

    proto_register_field_array(proto_vsomeip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_vsomeip = expert_register_protocol(proto_vsomeip);
    expert_register_field_array(expert_module_vsomeip, ei, array_length(ei));

    /* Configuration Items */
    vsomeip_module = prefs_register_protocol(proto_vsomeip, &proto_reg_handoff_vsomeip);

    prefs_register_bool_preference(vsomeip_module, "hide_magic", "Hide Magic",
        "Should the dissector automatically hide the magic fields?", &vsomeip_hide_magic);

    prefs_register_bool_preference(vsomeip_module, "auto_register_port", "Automatically register port",
        "Should the dissector automatically register port numbers based on Routing Info?", &vsomeip_auto_register_ports);

    prefs_register_bool_preference(vsomeip_module, "suspend_without_client", "VSOMEIP_SUSPEND without Client",
        "Should we skip the Client in VSOMEIP_SUSPEND messages?", &vsomeip_suspend_without_client);
}

void
proto_reg_handoff_vsomeip(void) {
    static bool initialized = false;

    if (!initialized) {
        dissector_add_uint_range_with_preference("udp.port", "", vsomeip_handle_udp);
        dissector_add_uint_range_with_preference("tcp.port", "", vsomeip_handle_tcp);

        someip_handle = find_dissector("someip");

        initialized = true;
    }
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
