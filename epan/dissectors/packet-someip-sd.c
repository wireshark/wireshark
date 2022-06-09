/* packet-someip-sd.c
 * SOME/IP-SD dissector.
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de> / <lars.voelker@bmw.de>
 * Copyright 2012-2022 Dr. Lars Voelker
 * Copyright 2020      Ayoub Kaanich
 * Copyright 2019      Ana Pantar
 * Copyright 2019      Guenter Ebermann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/uat.h>
#include <epan/stats_tree.h>

#include <packet-udp.h>
#include <packet-someip.h>

 /*
  * Dissector for SOME/IP Service Discovery (SOME/IP-SD).
  *
  * See
  *     http://www.some-ip.com
  */

#define SOMEIP_SD_NAME                          "SOME/IP-SD"
#define SOMEIP_SD_NAME_LONG                     "SOME/IP Service Discovery Protocol"
#define SOMEIP_SD_NAME_FILTER                   "someipsd"

#define SOMEIP_SD_MESSAGEID                     0xffff8100

 /* Header */
#define SOMEIP_SD_REBOOT_FLAG                   0x80
#define SOMEIP_SD_UNICAST_FLAG                  0x40
#define SOMEIP_SD_EXPL_INIT_EVENT_REQ_FLAG      0x20
#define SOMEIP_SD_MIN_LENGTH                    12

/* Entries */
#define SD_ENTRY_LENGTH                         16

#define SD_ENTRY_UNKNOWN                        0x00
#define SD_ENTRY_SERVICE                        0x01
#define SD_ENTRY_EVENTGROUP                     0x02
/* TTL>0 */
#define SD_ENTRY_FIND_SERVICE                   0x00
#define SD_ENTRY_OFFER_SERVICE                  0x01
#define SD_ENTRY_SUBSCRIBE_EVENTGROUP           0x06
#define SD_ENTRY_SUBSCRIBE_EVENTGROUP_ACK       0x07
/* TTL=0 */
#define SD_ENTRY_STOP_OFFER_SERVICE             0x01
#define SD_ENTRY_STOP_SUBSCRIBE_EVENTGROUP      0x06
#define SD_ENTRY_SUBSCRIBE_EVENTGROUP_NACK      0x07

#define SD_EVENTGROUP_ENTRY_COUNTER_MASK        0x0f
#define SD_EVENTGROUP_ENTRY_RES2_MASK           0x70
#define SD_ENTRY_INIT_EVENT_REQ_MASK            0x80

/* Options */
#define SD_OPTION_MINLENGTH                     3
#define SD_OPTION_IPV4_LENGTH                   12
#define SD_OPTION_IPV6_LENGTH                   24

#define SD_OPTION_UNKNOWN                       0x00
#define SD_OPTION_CONFIGURATION                 0x01
#define SD_OPTION_LOADBALANCING                 0x02
#define SD_OPTION_IPV4_ENDPOINT                 0x04
#define SD_OPTION_IPV6_ENDPOINT                 0x06
#define SD_OPTION_IPV4_MULTICAST                0x14
#define SD_OPTION_IPV6_MULTICAST                0x16
#define SD_OPTION_IPV4_SD_ENDPOINT              0x24
#define SD_OPTION_IPV6_SD_ENDPOINT              0x26

#define SD_OPTION_L4PROTO_TCP                   6
#define SD_OPTION_L4PROTO_UDP                   17

/* ID wireshark identifies the dissector by */
static int proto_someip_sd = -1;

/* header field */
static int hf_someip_sd_flags = -1;
static int hf_someip_sd_rebootflag = -1;
static int hf_someip_sd_unicastflag = -1;
static int hf_someip_sd_explicitiniteventflag = -1;
static int hf_someip_sd_reserved = -1;

static int hf_someip_sd_length_entriesarray = -1;
static int hf_someip_sd_entries = -1;

static int hf_someip_sd_entry = -1;
static int hf_someip_sd_entry_type = -1;
static int hf_someip_sd_entry_type_offerservice = -1;
static int hf_someip_sd_entry_type_stopofferservice = -1;
static int hf_someip_sd_entry_type_findservice = -1;
static int hf_someip_sd_entry_type_subscribeeventgroup = -1;
static int hf_someip_sd_entry_type_stopsubscribeeventgroup = -1;
static int hf_someip_sd_entry_type_subscribeeventgroupack = -1;
static int hf_someip_sd_entry_type_subscribeeventgroupnack = -1;
static int hf_someip_sd_entry_index1 = -1;
static int hf_someip_sd_entry_index2 = -1;
static int hf_someip_sd_entry_numopt1 = -1;
static int hf_someip_sd_entry_numopt2 = -1;
static int hf_someip_sd_entry_opts_referenced = -1;
static int hf_someip_sd_entry_serviceid = -1;
static int hf_someip_sd_entry_servicename = -1;
static int hf_someip_sd_entry_instanceid = -1;
static int hf_someip_sd_entry_majorver = -1;
static int hf_someip_sd_entry_ttl = -1;
static int hf_someip_sd_entry_minorver = -1;
static int hf_someip_sd_entry_eventgroupid = -1;
static int hf_someip_sd_entry_eventgroupname = -1;
static int hf_someip_sd_entry_reserved = -1;
static int hf_someip_sd_entry_counter = -1;
static int hf_someip_sd_entry_intial_event_flag = -1;
static int hf_someip_sd_entry_reserved2 = -1;

static int hf_someip_sd_length_optionsarray = -1;
static int hf_someip_sd_options = -1;

static int hf_someip_sd_option_type = -1;
static int hf_someip_sd_option_length = -1;
static int hf_someip_sd_option_reserved = -1;
static int hf_someip_sd_option_ipv4 = -1;
static int hf_someip_sd_option_ipv6 = -1;
static int hf_someip_sd_option_port = -1;
static int hf_someip_sd_option_proto = -1;
static int hf_someip_sd_option_reserved2 = -1;
static int hf_someip_sd_option_data = -1;
static int hf_someip_sd_option_config_string = -1;
static int hf_someip_sd_option_config_string_element = -1;
static int hf_someip_sd_option_lb_priority = -1;
static int hf_someip_sd_option_lb_weight = -1;

/* protocol tree items */
static gint ett_someip_sd = -1;
static gint ett_someip_sd_flags = -1;
static gint ett_someip_sd_entries = -1;
static gint ett_someip_sd_entry = -1;
static gint ett_someip_sd_options = -1;
static gint ett_someip_sd_option = -1;
static gint ett_someip_sd_config_string = -1;


/*** Taps ***/
static int tap_someip_sd_entries = -1;

typedef struct _someip_sd_entries_tap {
    guint8  entry_type;
    guint16 service_id;
    guint8  major_version;
    guint32 minor_version;
    guint16 instance_id;
    guint16 eventgroup_id;
    guint32 ttl;
} someip_sd_entries_tap_t;


/*** Stats ***/
static const gchar *st_str_ip_src = "Source Addresses";
static const gchar *st_str_ip_dst = "Destination Addresses";

static int st_node_ip_src = -1;
static int st_node_ip_dst = -1;

/*** Preferences ***/
static range_t *someip_ignore_ports_udp = NULL;
static range_t *someip_ignore_ports_tcp = NULL;

/* SOME/IP-SD Entry Names for TTL>0 */
static const value_string sd_entry_type_positive[] = {
    {SD_ENTRY_FIND_SERVICE,                                             "Find Service"},
    {SD_ENTRY_OFFER_SERVICE,                                            "Offer Service"},
    {SD_ENTRY_SUBSCRIBE_EVENTGROUP,                                     "Subscribe Eventgroup"},
    {SD_ENTRY_SUBSCRIBE_EVENTGROUP_ACK,                                 "Subscribe Eventgroup Ack"},
    {0, NULL}
};

/* SOME/IP-SD Entry Names for TTL=0 */
static const value_string sd_entry_type_negative[] = {
    {SD_ENTRY_STOP_OFFER_SERVICE,                                       "Stop Offer Service"},
    {SD_ENTRY_STOP_SUBSCRIBE_EVENTGROUP,                                "Stop Subscribe Eventgroup"},
    {SD_ENTRY_SUBSCRIBE_EVENTGROUP_NACK,                                "Subscribe Eventgroup Negative Ack"},
    {0, NULL}
};

/* SOME/IP-SD Option Names */
static const value_string sd_option_type[] = {
    {SD_OPTION_UNKNOWN,                                                 "Unknown"},
    {SD_OPTION_CONFIGURATION,                                           "Configuration"},
    {SD_OPTION_LOADBALANCING,                                           "Load Balancing"},
    {SD_OPTION_IPV4_ENDPOINT,                                           "IPv4 Endpoint"},
    {SD_OPTION_IPV6_ENDPOINT,                                           "IPv6 Endpoint"},
    {SD_OPTION_IPV4_MULTICAST,                                          "IPv4 Multicast"},
    {SD_OPTION_IPV6_MULTICAST,                                          "IPv6 Multicast"},
    {SD_OPTION_IPV4_SD_ENDPOINT,                                        "IPv4 SD Endpoint"},
    {SD_OPTION_IPV6_SD_ENDPOINT,                                        "IPv6 SD Endpoint"},
    {0, NULL}
};

/* L4 Protocol Names for SOME/IP-SD Endpoints */
static const value_string sd_option_l4protos[] = {
    {SD_OPTION_L4PROTO_TCP,                                             "TCP"},
    {SD_OPTION_L4PROTO_UDP,                                             "UDP"},
    {0, NULL}
};

static const true_false_string sd_reboot_flag = {
    "Session ID did not roll over since last reboot",
    "Session ID rolled over since last reboot"
};

static const true_false_string sd_unicast_flag = {
    "Unicast messages support",
    "Unicast messages not supported (deprecated)"
};

static const true_false_string sd_eiec_flag = {
    "Explicit Initial Event control supported",
    "Explicit Initial Event control not supported"
};

/*** expert info items ***/
static expert_field ef_someipsd_message_truncated = EI_INIT;
static expert_field ef_someipsd_entry_array_malformed = EI_INIT;
static expert_field ef_someipsd_entry_array_empty = EI_INIT;
static expert_field ef_someipsd_entry_unknown = EI_INIT;
static expert_field ef_someipsd_option_array_truncated = EI_INIT;
static expert_field ef_someipsd_option_array_bytes_left = EI_INIT;
static expert_field ef_someipsd_option_unknown = EI_INIT;
static expert_field ef_someipsd_option_wrong_length = EI_INIT;
static expert_field ef_someipsd_L4_protocol_unsupported = EI_INIT;
static expert_field ef_someipsd_config_string_malformed = EI_INIT;

/*** prototypes ***/
void proto_register_someip_sd(void);
void proto_reg_handoff_someip_sd(void);

/**************************************
 ******** SOME/IP-SD Dissector ********
 *************************************/

static void
dissect_someip_sd_pdu_option_configuration(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint32 length, int optionnum) {
    guint32         offset_orig = offset;
    const guint8   *config_string;
    proto_item     *ti;
    proto_tree     *subtree;

    tree = proto_tree_add_subtree_format(tree, tvb, offset, length, ett_someip_sd_option, NULL, "%d: Configuration Option", optionnum);

    /* Add common fields */
    proto_tree_add_item(tree, hf_someip_sd_option_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_someip_sd_option_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_someip_sd_option_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    gint config_string_length = length - offset + offset_orig;
    ti = proto_tree_add_item_ret_string(tree, hf_someip_sd_option_config_string, tvb, offset, config_string_length, ENC_ASCII | ENC_NA, pinfo->pool, &config_string);
    subtree = proto_item_add_subtree(ti, ett_someip_sd_config_string);

    guint8 pos = 0;
    guint8 element_length;
    while (config_string != NULL && config_string_length - pos > 0) {
        element_length = config_string[pos];
        pos++;

        if (element_length == 0) {
            break;
        }

        if (element_length > config_string_length - pos) {
            expert_add_info(pinfo, ti, &ef_someipsd_config_string_malformed);
            break;
        }

        proto_tree_add_item(subtree, hf_someip_sd_option_config_string_element, tvb, offset + pos, element_length, ENC_ASCII | ENC_NA);
        pos += element_length;
    }
}

static void
dissect_someip_sd_pdu_option_loadbalancing(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset, guint32 length, int optionnum) {
    tree = proto_tree_add_subtree_format(tree, tvb, offset, length, ett_someip_sd_option, NULL, "%d: Load Balancing Option", optionnum);

    /* Add common fields */
    proto_tree_add_item(tree, hf_someip_sd_option_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_someip_sd_option_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_someip_sd_option_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_someip_sd_option_lb_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_someip_sd_option_lb_weight, tvb, offset, 2, ENC_BIG_ENDIAN);
}

static void
dissect_someip_sd_pdu_option_ipv4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint32 length, int optionnum) {
    guint8              type = 255;
    const gchar        *description = NULL;
    guint32             l4port = 0;
    guint32             l4proto = 0;
    const gchar        *l4protoname = NULL;
    const gchar        *ipstring = NULL;

    proto_item         *ti = NULL;
    proto_item         *ti_top = NULL;

    type = tvb_get_guint8(tvb, offset + 2);
    description = val_to_str(type, sd_option_type, "(Unknown Option: %d)");
    tree = proto_tree_add_subtree_format(tree, tvb, offset, length, ett_someip_sd_option, &ti_top, "%d: %s Option", optionnum, description);

    if (length != SD_OPTION_IPV4_LENGTH) {
        expert_add_info(pinfo, ti_top, &ef_someipsd_option_wrong_length);
        return;
    }

    /* Add common fields */
    proto_tree_add_item(tree, hf_someip_sd_option_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_someip_sd_option_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_someip_sd_option_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_someip_sd_option_ipv4, tvb, offset, 4, ENC_NA);
    ipstring = tvb_ip_to_str(pinfo->pool, tvb, offset);
    offset += 4;

    proto_tree_add_item(tree, hf_someip_sd_option_reserved2, tvb, offset, 1, ENC_NA);
    offset += 1;

    ti = proto_tree_add_item_ret_uint(tree, hf_someip_sd_option_proto, tvb, offset, 1, ENC_NA, &l4proto);
    l4protoname = val_to_str(l4proto, sd_option_l4protos, "Unknown Transport Protocol: %d");
    proto_item_append_text(ti, " (%s)", l4protoname);

    if (type != SD_OPTION_IPV4_ENDPOINT && l4proto == SD_OPTION_L4PROTO_TCP) {
        expert_add_info(pinfo, ti_top, &ef_someipsd_L4_protocol_unsupported);
    }
    offset += 1;

    proto_tree_add_item_ret_uint(tree, hf_someip_sd_option_port, tvb, offset, 2, ENC_BIG_ENDIAN, &l4port);

    proto_item_append_text(ti_top, " (%s:%d (%s))", ipstring, l4port, l4protoname);

    if (l4proto == SD_OPTION_L4PROTO_UDP && !value_is_in_range(someip_ignore_ports_udp, l4port)) {
        register_someip_port_udp(l4port);
    }
    if (l4proto == SD_OPTION_L4PROTO_TCP && !value_is_in_range(someip_ignore_ports_tcp, l4port)) {
        register_someip_port_tcp(l4port);
    }
}

static void
dissect_someip_sd_pdu_option_ipv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint32 length, int optionnum) {
    guint8              type = 255;
    const gchar        *description = NULL;
    guint32             l4port = 0;
    guint32             l4proto = 0;
    const gchar        *l4protoname = NULL;
    proto_item         *ti = NULL;
    proto_item         *ti_top = NULL;

    type = tvb_get_guint8(tvb, offset + 2);
    description = val_to_str(type, sd_option_type, "(Unknown Option: %d)");

    tree = proto_tree_add_subtree_format(tree, tvb, offset, length, ett_someip_sd_option, &ti_top, "%d: %s Option", optionnum, description);

    if (length != SD_OPTION_IPV6_LENGTH) {
        expert_add_info(pinfo, ti_top, &ef_someipsd_option_wrong_length);
        return;
    }

    proto_tree_add_item(tree, hf_someip_sd_option_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_someip_sd_option_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_someip_sd_option_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_someip_sd_option_ipv6, tvb, offset, 16, ENC_NA);
    offset += 16;

    proto_tree_add_item(tree, hf_someip_sd_option_reserved2, tvb, offset, 1, ENC_NA);
    offset += 1;

    ti = proto_tree_add_item_ret_uint(tree, hf_someip_sd_option_proto, tvb, offset, 1, ENC_NA, &l4proto);
    l4protoname = val_to_str(l4proto, sd_option_l4protos, "(Unknown Transport Protocol: %d)");
    proto_item_append_text(ti, " (%s)", l4protoname);

    if (type != SD_OPTION_IPV6_ENDPOINT && l4proto == SD_OPTION_L4PROTO_TCP) {
        expert_add_info(pinfo, ti_top, &ef_someipsd_L4_protocol_unsupported);
    }
    offset += 1;

    proto_tree_add_item_ret_uint(tree, hf_someip_sd_option_port, tvb, offset, 2, ENC_BIG_ENDIAN, &l4port);

    proto_item_append_text(ti_top, " (%s)", l4protoname);

    if (l4proto == SD_OPTION_L4PROTO_UDP && !value_is_in_range(someip_ignore_ports_udp, l4port)) {
        register_someip_port_udp(l4port);
    }
    if (l4proto == SD_OPTION_L4PROTO_TCP && !value_is_in_range(someip_ignore_ports_tcp, l4port)) {
        register_someip_port_tcp(l4port);
    }
}

static void
dissect_someip_sd_pdu_option_unknown(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint32 length, int optionnum) {
    guint32             len = 0;
    proto_item         *ti;

    tree = proto_tree_add_subtree_format(tree, tvb, offset, length, ett_someip_sd_option, &ti, "%d: %s Option", optionnum,
        val_to_str_const(tvb_get_guint8(tvb, offset + 2), sd_option_type, "Unknown"));

    expert_add_info(pinfo, ti, &ef_someipsd_option_unknown);

    proto_tree_add_item_ret_uint(tree, hf_someip_sd_option_length, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
    offset += 2;

    proto_tree_add_item(tree, hf_someip_sd_option_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (length > 3) {
        proto_tree_add_item(tree, hf_someip_sd_option_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        if (length > 4) {
            proto_tree_add_item(tree, hf_someip_sd_option_data, tvb, offset, length - 4, ENC_NA);
        }
    }
}

static int
dissect_someip_sd_pdu_options(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti, guint32 offset_orig, guint32 length) {
    guint16             real_length = 0;
    guint8              option_type = 0;
    int                 optionnum = 0;
    tvbuff_t           *subtvb = NULL;

    guint32             offset = offset_orig;

    if (!tvb_bytes_exist(tvb, offset, SD_OPTION_MINLENGTH) || !tvb_bytes_exist(tvb, offset, length)) {
        expert_add_info(pinfo, ti, &ef_someipsd_option_array_truncated);
        return offset;
    }

    while (tvb_bytes_exist(tvb, offset, SD_OPTION_MINLENGTH)) {
        real_length = tvb_get_ntohs(tvb, offset) + 3;
        option_type = tvb_get_guint8(tvb, offset + 2);

        if (!tvb_bytes_exist(tvb, offset, (gint)real_length) || offset - offset_orig + real_length > length) {
            expert_add_info(pinfo, ti, &ef_someipsd_option_array_truncated);
            return offset;
        }

        subtvb = tvb_new_subset_length(tvb, offset, (gint)real_length);

        switch (option_type) {
        case SD_OPTION_CONFIGURATION:
            dissect_someip_sd_pdu_option_configuration(subtvb, pinfo, tree, 0, real_length, optionnum);
            break;
        case SD_OPTION_LOADBALANCING:
            dissect_someip_sd_pdu_option_loadbalancing(subtvb, pinfo, tree, 0, real_length, optionnum);
            break;
        case SD_OPTION_IPV4_ENDPOINT:
        case SD_OPTION_IPV4_MULTICAST:
        case SD_OPTION_IPV4_SD_ENDPOINT:
            dissect_someip_sd_pdu_option_ipv4(subtvb, pinfo, tree, 0, real_length, optionnum);
            break;

        case SD_OPTION_IPV6_ENDPOINT:
        case SD_OPTION_IPV6_MULTICAST:
        case SD_OPTION_IPV6_SD_ENDPOINT:
            dissect_someip_sd_pdu_option_ipv6(subtvb, pinfo, tree, 0, real_length, optionnum);
            break;

        default:
            dissect_someip_sd_pdu_option_unknown(subtvb, pinfo, tree, 0, real_length, optionnum);
            break;
        }
        optionnum++;
        offset += real_length;
    }

    return offset;
}

static void
dissect_someip_sd_pdu_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset_orig, guint32 length, guint32 *entry_flags, guint32 *stop_entry_flags) {
    guint8              type = 255;
    guint32             serviceid = 0;
    guint32             instanceid = 0;
    guint32             eventgroupid = 0;
    guint32             majorver = 0;
    guint32             minorver = 0;
    guint32             ttl = 0;
    guint32             opt_index1;
    guint32             opt_index2;
    guint32             opt_num1;
    guint32             opt_num2;

    guint64             uniqueid = 0;
    guint8              category = SD_ENTRY_UNKNOWN;

    const gchar        *description = NULL;
    static gchar        buf_opt_ref[32];

    proto_item         *ti;
    proto_item         *ti_top;

    guint32             offset = offset_orig;

    if (length < SD_ENTRY_LENGTH || !tvb_bytes_exist(tvb, offset, length)) {
        return;
    }

    /* lets look ahead and find out the type and ttl */
    type = tvb_get_guint8(tvb, offset);
    ttl = tvb_get_ntoh24(tvb, offset + 9);

    if (type < 4) {
        category = SD_ENTRY_SERVICE;
    } else if (type >= 4 && type < 8) {
        category = SD_ENTRY_EVENTGROUP;
    } else {
        ti_top = proto_tree_add_none_format(tree, hf_someip_sd_entry, tvb, offset, SD_ENTRY_LENGTH, "Unknown Entry (Type: %d)", type);
        expert_add_info(pinfo, ti_top, &ef_someipsd_entry_unknown);
        return;
    }

    if (ttl == 0) {
        description = val_to_str(type, sd_entry_type_negative, "(Unknown Entry: %d)");
    } else {
        description = val_to_str(type, sd_entry_type_positive, "(Unknown Entry: %d)");
    }

    ti_top = proto_tree_add_none_format(tree, hf_someip_sd_entry, tvb, offset, SD_ENTRY_LENGTH, "%s Entry", description);
    tree = proto_item_add_subtree(ti_top, ett_someip_sd_entry);

    proto_tree_add_uint_format_value(tree, hf_someip_sd_entry_type, tvb, offset, 1, type, "0x%02x (%s)", type, description);
    offset += 1;

    proto_tree_add_item_ret_uint(tree, hf_someip_sd_entry_index1, tvb, offset, 1, ENC_BIG_ENDIAN, &opt_index1);
    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_someip_sd_entry_index2, tvb, offset, 1, ENC_BIG_ENDIAN, &opt_index2);
    offset += 1;

    proto_tree_add_item_ret_uint(tree, hf_someip_sd_entry_numopt1, tvb, offset, 1, ENC_NA, &opt_num1);
    proto_tree_add_item_ret_uint(tree, hf_someip_sd_entry_numopt2, tvb, offset, 1, ENC_NA, &opt_num2);
    offset += 1;

    if (opt_num1 != 0 && opt_num2 == 0) {
        snprintf(buf_opt_ref, 32, "%d-%d", opt_index1, opt_index1 + opt_num1 - 1);
    } else if (opt_num1 == 0 && opt_num2 != 0) {
        snprintf(buf_opt_ref, 32, "%d-%d", opt_index2, opt_index2 + opt_num2 - 1);
    } else if (opt_num1 != 0 && opt_num2 != 0) {
        snprintf(buf_opt_ref, 32, "%d-%d,%d-%d", opt_index1, opt_index1 + opt_num1 - 1, opt_index2, opt_index2 + opt_num2 - 1);
    } else {
        snprintf(buf_opt_ref, 32, "None");
    }

    ti = proto_tree_add_string(tree, hf_someip_sd_entry_opts_referenced, tvb, offset - 3, 3, buf_opt_ref);
    proto_item_set_generated(ti);

    ti = proto_tree_add_item_ret_uint(tree, hf_someip_sd_entry_serviceid, tvb, offset, 2, ENC_BIG_ENDIAN, &serviceid);
    description = someip_lookup_service_name((guint16)serviceid);
    if (description != NULL) {
        proto_item_append_text(ti, " (%s)", description);
        ti = proto_tree_add_string(tree, hf_someip_sd_entry_servicename, tvb, offset, 2, description);
        proto_item_set_generated(ti);
        proto_item_set_hidden(ti);
    }
    offset += 2;

    proto_tree_add_item_ret_uint(tree, hf_someip_sd_entry_instanceid, tvb, offset, 2, ENC_BIG_ENDIAN, &instanceid);
    offset += 2;

    proto_tree_add_item_ret_uint(tree, hf_someip_sd_entry_majorver, tvb, offset, 1, ENC_BIG_ENDIAN, &majorver);
    offset += 1;

    proto_tree_add_item(tree, hf_someip_sd_entry_ttl, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Add specific fields - i.e. the last line */
    if (category == SD_ENTRY_SERVICE) {
        proto_tree_add_item_ret_uint(tree, hf_someip_sd_entry_minorver, tvb, offset, 4, ENC_BIG_ENDIAN, &minorver);
        /* offset += 4; */

        proto_item_append_text(ti_top, " (Service ID 0x%04x, Instance ID 0x%04x, Version %u.%u)", serviceid, instanceid, majorver, minorver);
    } else if (category == SD_ENTRY_EVENTGROUP) {
        proto_tree_add_item(tree, hf_someip_sd_entry_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_someip_sd_entry_intial_event_flag, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_someip_sd_entry_reserved2, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_someip_sd_entry_counter, tvb, offset, 1, ENC_NA);
        offset += 1;

        ti = proto_tree_add_item_ret_uint(tree, hf_someip_sd_entry_eventgroupid, tvb, offset, 2, ENC_BIG_ENDIAN, &eventgroupid);
        description = someip_lookup_eventgroup_name((guint16)serviceid, (guint16)eventgroupid);
        if (description != NULL) {
            proto_item_append_text(ti, " (%s)", description);
            ti = proto_tree_add_string(tree, hf_someip_sd_entry_eventgroupname, tvb, offset, 2, description);
            proto_item_set_generated(ti);
            proto_item_set_hidden(ti);
        }

        proto_item_append_text(ti_top, " (Service ID 0x%04x, Instance ID 0x%04x, Eventgroup ID 0x%04x, Version %u)", serviceid, instanceid, eventgroupid, majorver);
    }

    /* mark for attaching to info column */
    if (type < 32) {
        if (ttl == 0) {
            *stop_entry_flags = *stop_entry_flags | (1 << type);
        } else {
            *entry_flags = *entry_flags | (1 << type);
        }
    }

    /* lets add some combined filtering term */
    uniqueid = (((guint64)serviceid) << 32) | (guint64)instanceid << 16 | (guint64)eventgroupid;

    ti = NULL;
    if (ttl > 0) {
        switch (type) {
        case SD_ENTRY_FIND_SERVICE:
            ti = proto_tree_add_uint64_format_value(tree, hf_someip_sd_entry_type_findservice, tvb, offset_orig, SD_ENTRY_LENGTH, uniqueid, "on 0x%012" PRIx64, uniqueid);
            break;
        case SD_ENTRY_OFFER_SERVICE:
            ti = proto_tree_add_uint64_format_value(tree, hf_someip_sd_entry_type_offerservice, tvb, offset_orig, SD_ENTRY_LENGTH, uniqueid, "on 0x%012" PRIx64, uniqueid);
            break;
        case SD_ENTRY_SUBSCRIBE_EVENTGROUP:
            ti = proto_tree_add_uint64_format_value(tree, hf_someip_sd_entry_type_subscribeeventgroup, tvb, offset_orig, SD_ENTRY_LENGTH, uniqueid, "on 0x%012" PRIx64, uniqueid);
            break;
        case SD_ENTRY_SUBSCRIBE_EVENTGROUP_ACK:
            ti = proto_tree_add_uint64_format_value(tree, hf_someip_sd_entry_type_subscribeeventgroupack, tvb, offset_orig, SD_ENTRY_LENGTH, uniqueid, "on 0x%012" PRIx64, uniqueid);
            break;
        }
    } else {
        switch (type) {
        case SD_ENTRY_STOP_OFFER_SERVICE:
            ti = proto_tree_add_uint64_format_value(tree, hf_someip_sd_entry_type_stopofferservice, tvb, offset_orig, SD_ENTRY_LENGTH, uniqueid, "on 0x%012" PRIx64, uniqueid);
            break;
        case SD_ENTRY_STOP_SUBSCRIBE_EVENTGROUP:
            ti = proto_tree_add_uint64_format_value(tree, hf_someip_sd_entry_type_stopsubscribeeventgroup, tvb, offset_orig, SD_ENTRY_LENGTH, uniqueid, "on 0x%012" PRIx64, uniqueid);
            break;
        case SD_ENTRY_SUBSCRIBE_EVENTGROUP_NACK:
            ti = proto_tree_add_uint64_format_value(tree, hf_someip_sd_entry_type_subscribeeventgroupnack, tvb, offset_orig, SD_ENTRY_LENGTH, uniqueid, "on 0x%012" PRIx64, uniqueid);
            break;
        }
    }

    if (ti != NULL) {
        PROTO_ITEM_SET_HIDDEN(ti);
    }

    /* TAP */
    if (have_tap_listener(tap_someip_sd_entries)) {
        someip_sd_entries_tap_t *data = wmem_alloc(pinfo->pool, sizeof(someip_sd_entries_tap_t));
        data->entry_type = type;
        data->service_id = (guint16)serviceid;
        data->major_version = (guint8)majorver;
        data->minor_version = minorver;
        data->instance_id = (guint16)instanceid;
        data->eventgroup_id = (guint16)eventgroupid;
        data->ttl = ttl;

        tap_queue_packet(tap_someip_sd_entries, pinfo, data);
    }
}

static int
dissect_someip_sd_pdu_entries(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti, guint32 offset, guint32 length) {
    guint32     entry_flags = 0;
    guint32     stop_entry_flags = 0;

    while (length >= SD_ENTRY_LENGTH) {
        dissect_someip_sd_pdu_entry(tvb, pinfo, tree, offset, SD_ENTRY_LENGTH, &entry_flags, &stop_entry_flags);
        offset += SD_ENTRY_LENGTH;
        length -= SD_ENTRY_LENGTH;
    }

    /* Add entry flags */
    if (stop_entry_flags != 0 || entry_flags != 0) {
        col_append_str(pinfo->cinfo, COL_INFO, " ");
    }

    if (entry_flags & (1 << SD_ENTRY_FIND_SERVICE)) {
        col_append_str(pinfo->cinfo, COL_INFO, "[Find]");
    }

    if (stop_entry_flags & (1 << SD_ENTRY_OFFER_SERVICE)) {
        col_append_str(pinfo->cinfo, COL_INFO, "[StopOffer]");
    }

    if (entry_flags & (1 << SD_ENTRY_OFFER_SERVICE)) {
        col_append_str(pinfo->cinfo, COL_INFO, "[Offer]");
    }

    if (stop_entry_flags & (1 << SD_ENTRY_SUBSCRIBE_EVENTGROUP)) {
        col_append_str(pinfo->cinfo, COL_INFO, "[StopSubscribe]");
    }

    if (entry_flags & (1 << SD_ENTRY_SUBSCRIBE_EVENTGROUP)) {
        col_append_str(pinfo->cinfo, COL_INFO, "[Subscribe]");
    }

    if (stop_entry_flags & (1 << SD_ENTRY_SUBSCRIBE_EVENTGROUP_ACK)) {
        col_append_str(pinfo->cinfo, COL_INFO, "[SubscribeNack]");
    }

    if (entry_flags & (1 << SD_ENTRY_SUBSCRIBE_EVENTGROUP_ACK)) {
        col_append_str(pinfo->cinfo, COL_INFO, "[SubscribeAck]");
    }

    if (length != 0) {
        expert_add_info(pinfo, ti, &ef_someipsd_entry_array_malformed);
    }

    return length;
}

static int
dissect_someip_sd_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    guint32         offset = 0;
    guint32         length_entriesarray = 0;
    guint32         length_optionsarray = 0;

    proto_item     *ti = NULL;
    proto_item     *ti_sd_entries = NULL;

    proto_tree     *someip_sd_entries_tree = NULL;
    proto_tree     *someip_sd_options_tree = NULL;
    gboolean        stop_parsing_after_entries = FALSE;
    guint32         offset_entriesarray;

    static int * const someipsd_flags[] = {
        &hf_someip_sd_rebootflag,
        &hf_someip_sd_unicastflag,
        &hf_someip_sd_explicitiniteventflag,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, SOMEIP_SD_NAME);
    col_set_str(pinfo->cinfo, COL_INFO, SOMEIP_SD_NAME_LONG);

    ti = proto_tree_add_item(tree, proto_someip_sd, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_someip_sd);

    if (!tvb_bytes_exist(tvb, offset, SOMEIP_SD_MIN_LENGTH)) {
        expert_add_info(pinfo, ti, &ef_someipsd_message_truncated);
        return tvb_reported_length(tvb);
    }

    /* add flags */
    proto_tree_add_bitmask(tree, tvb, offset, hf_someip_sd_flags, ett_someip_sd_flags, someipsd_flags, ENC_BIG_ENDIAN);
    offset += 1;

    /* add reserved */
    proto_tree_add_item(tree, hf_someip_sd_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* add length of entries */
    proto_tree_add_item_ret_uint(tree, hf_someip_sd_length_entriesarray, tvb, offset, 4, ENC_BIG_ENDIAN, &length_entriesarray);
    offset += 4;

    if (!tvb_bytes_exist(tvb, offset, length_entriesarray)) {
        expert_add_info(pinfo, ti   , &ef_someipsd_message_truncated);
        return tvb_reported_length(tvb);
    }

    if (!tvb_bytes_exist(tvb, offset, length_entriesarray)) {
        /* truncated SD message - need to shorten buffer */
        length_entriesarray = tvb_captured_length_remaining(tvb, offset);
        expert_add_info(pinfo, ti, &ef_someipsd_message_truncated);
        stop_parsing_after_entries = TRUE;
    }

    /* preparing entries array but not parsing it yet */
    ti_sd_entries = proto_tree_add_item(tree, hf_someip_sd_entries, tvb, offset, length_entriesarray, ENC_NA);
    someip_sd_entries_tree = proto_item_add_subtree(ti_sd_entries, ett_someip_sd_entries);
    /* save offset to parse entries later since we need to parse options first */
    offset_entriesarray = offset;
    offset += length_entriesarray;

    if (!stop_parsing_after_entries) {
        /* make sure we have a length field */
        if (tvb_bytes_exist(tvb, offset, 4)) {

            /* add options length */
            proto_tree_add_item_ret_uint(tree, hf_someip_sd_length_optionsarray, tvb, offset, 4, ENC_BIG_ENDIAN, &length_optionsarray);
            offset += 4;

            if (length_optionsarray > 0) {
                if (tvb_bytes_exist(tvb, offset, 1)) {
                    ti = proto_tree_add_item(tree, hf_someip_sd_options, tvb, offset, -1, ENC_NA);
                    someip_sd_options_tree = proto_item_add_subtree(ti, ett_someip_sd_options);

                    /* check, if enough bytes are left for optionsarray */
                    if (!tvb_bytes_exist(tvb, offset, length_optionsarray)) {
                        length_optionsarray = tvb_captured_length_remaining(tvb, offset);
                        expert_add_info(pinfo, ti, &ef_someipsd_message_truncated);
                        proto_item_append_text(ti, " (truncated!)");
                    }

                    /* updating to length we will work with */
                    if (length_optionsarray > 0) {
                        proto_item_set_len(ti, length_optionsarray);
                    }

                    dissect_someip_sd_pdu_options(tvb, pinfo, someip_sd_options_tree, ti, offset, length_optionsarray);
                    offset += length_optionsarray;
                } else {
                    expert_add_info(pinfo, ti, &ef_someipsd_message_truncated);
                }
            }
        }
    }

    /* Possible improvement: it would be nice, if entries referenced options. */
    if (length_entriesarray >= SD_ENTRY_LENGTH) {
        offset += dissect_someip_sd_pdu_entries(tvb, pinfo, someip_sd_entries_tree, ti_sd_entries, offset_entriesarray, length_entriesarray);
    } else {
        expert_add_info(pinfo, ti_sd_entries, &ef_someipsd_entry_array_empty);
    }
    return offset;
}

/*******************************************
 **************** Statistics ***************
 *******************************************/

static void
someipsd_entries_stats_tree_init(stats_tree *st) {
    st_node_ip_src = stats_tree_create_node(st, st_str_ip_src, 0, STAT_DT_INT, TRUE);
    stat_node_set_flags(st, st_str_ip_src, 0, FALSE, ST_FLG_SORT_TOP);
    st_node_ip_dst = stats_tree_create_node(st, st_str_ip_dst, 0, STAT_DT_INT, TRUE);
}

static void
stat_number_to_string_with_any(guint32 value, guint max, gchar *format_string, gchar *ret, size_t size_limit) {
    if (value == max) {
        snprintf(ret, size_limit, "%s", "MAX");
    } else {
        snprintf(ret, size_limit, format_string, value);
    }
}

static void
stat_create_entry_summary_string(const someip_sd_entries_tap_t *data, gchar *ret, size_t size_limit) {
    gchar service_str[128];
    gchar instance_str[128];
    gchar majorver_str[128];
    gchar minorver_str[128];
    gchar eventgrp_str[128];
    gchar tmp[128];

    char *service_name  = someip_lookup_service_name(data->service_id);
    char *eventgrp_name = someip_lookup_eventgroup_name(data->service_id, data->eventgroup_id);

    stat_number_to_string_with_any(data->service_id, UINT32_MAX, "0x%04x", service_str, sizeof(service_str) - 1);
    stat_number_to_string_with_any(data->instance_id, UINT32_MAX, "0x%04x", instance_str, sizeof(instance_str) - 1);
    stat_number_to_string_with_any(data->major_version, UINT8_MAX, "%d", majorver_str, sizeof(majorver_str) - 1);

    switch (data->entry_type) {
    case SD_ENTRY_FIND_SERVICE:
    case SD_ENTRY_OFFER_SERVICE:
        stat_number_to_string_with_any(data->minor_version, UINT32_MAX, "%d", minorver_str, sizeof(minorver_str) - 1);
        if (service_name != NULL) {
            snprintf(ret, size_limit, "Service %s (%s) Version %s.%s Instance %s", service_str, service_name, majorver_str, minorver_str, instance_str);
        } else {
            snprintf(ret, size_limit, "Service %s Version %s.%s Instance %s", service_str, majorver_str, minorver_str, instance_str);
        }
        break;

    case SD_ENTRY_SUBSCRIBE_EVENTGROUP:
    case SD_ENTRY_SUBSCRIBE_EVENTGROUP_ACK:
        stat_number_to_string_with_any(data->eventgroup_id, UINT32_MAX, "0x%04x", eventgrp_str, sizeof(eventgrp_str) - 1);
        if (service_name != NULL) {
            snprintf(tmp, sizeof(tmp) - 1, "Service %s (%s) Version %s Instance %s Eventgroup %s", service_str, service_name, majorver_str, instance_str, eventgrp_str);
        } else {
            snprintf(tmp, sizeof(tmp) - 1, "Service %s Version %s Instance %s Eventgroup %s", service_str, majorver_str, instance_str, eventgrp_str);
        }
        if (eventgrp_name != NULL) {
            snprintf(ret, size_limit, "%s (%s)", tmp, eventgrp_name);
        }
        break;
    }
}

static tap_packet_status
someipsd_entries_stats_tree_packet(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt _U_, const void *p, tap_flags_t flags _U_) {
    DISSECTOR_ASSERT(p);
    const someip_sd_entries_tap_t *data = (const someip_sd_entries_tap_t *)p;
    static gchar tmp_addr_str[256];

    snprintf(tmp_addr_str, sizeof(tmp_addr_str) - 1, "%s (%s)", address_to_str(pinfo->pool, &pinfo->net_src), address_to_name(&pinfo->net_src));
    tick_stat_node(st, st_str_ip_src, 0, FALSE);
    int src_id = tick_stat_node(st, tmp_addr_str, st_node_ip_src, TRUE);

    snprintf(tmp_addr_str, sizeof(tmp_addr_str) - 1, "%s (%s)", address_to_str(pinfo->pool, &pinfo->net_dst), address_to_name(&pinfo->net_dst));
    tick_stat_node(st, st_str_ip_dst, 0, FALSE);
    int dst_id = tick_stat_node(st, tmp_addr_str, st_node_ip_dst, TRUE);

    int tmp_id;
    static gchar tmp_str[128];

    if (data->ttl == 0) {
        switch (data->entry_type) {
        case SD_ENTRY_STOP_OFFER_SERVICE:
            stat_create_entry_summary_string(data, tmp_str, sizeof(tmp_str) - 1);
            tmp_id = tick_stat_node(st, "Stop Offer Service", src_id, TRUE);
            tick_stat_node(st, tmp_str, tmp_id, FALSE);
            tmp_id = tick_stat_node(st, "Stop Offer Service", dst_id, TRUE);
            tick_stat_node(st, tmp_str, tmp_id, FALSE);
            break;
        case SD_ENTRY_STOP_SUBSCRIBE_EVENTGROUP:
            stat_create_entry_summary_string(data, tmp_str, sizeof(tmp_str) - 1);
            tmp_id = tick_stat_node(st, "Stop Subscribe Eventgroup", src_id, TRUE);
            tick_stat_node(st, tmp_str, tmp_id, FALSE);
            tmp_id = tick_stat_node(st, "Stop Subscribe Eventgroup", dst_id, TRUE);
            tick_stat_node(st, tmp_str, tmp_id, FALSE);
            break;
        case SD_ENTRY_SUBSCRIBE_EVENTGROUP_NACK:
            stat_create_entry_summary_string(data, tmp_str, sizeof(tmp_str) - 1);
            tmp_id = tick_stat_node(st, "Subscribe Eventgroup Nack", src_id, TRUE);
            tick_stat_node(st, tmp_str, tmp_id, FALSE);
            tmp_id = tick_stat_node(st, "Subscribe Eventgroup Nack", dst_id, TRUE);
            tick_stat_node(st, tmp_str, tmp_id, FALSE);
            break;
        }
    } else {
        switch (data->entry_type) {
        case SD_ENTRY_FIND_SERVICE:
            stat_create_entry_summary_string(data, tmp_str, sizeof(tmp_str) - 1);
            tmp_id = tick_stat_node(st, "Find Service", src_id, TRUE);
            tick_stat_node(st, tmp_str, tmp_id, FALSE);
            tmp_id = tick_stat_node(st, "Find Service", dst_id, TRUE);
            tick_stat_node(st, tmp_str, tmp_id, FALSE);
            break;
        case SD_ENTRY_OFFER_SERVICE:
            stat_create_entry_summary_string(data, tmp_str, sizeof(tmp_str) - 1);
            tmp_id = tick_stat_node(st, "Offer Service", src_id, TRUE);
            tick_stat_node(st, tmp_str, tmp_id, FALSE);
            tmp_id = tick_stat_node(st, "Offer Service", dst_id, TRUE);
            tick_stat_node(st, tmp_str, tmp_id, FALSE);
            break;
        case SD_ENTRY_SUBSCRIBE_EVENTGROUP:
            stat_create_entry_summary_string(data, tmp_str, sizeof(tmp_str) - 1);
            tmp_id = tick_stat_node(st, "Subscribe Eventgroup", src_id, TRUE);
            tick_stat_node(st, tmp_str, tmp_id, FALSE);
            tmp_id = tick_stat_node(st, "Subscribe Eventgroup", dst_id, TRUE);
            tick_stat_node(st, tmp_str, tmp_id, FALSE);
            break;
        case SD_ENTRY_SUBSCRIBE_EVENTGROUP_ACK:
            stat_create_entry_summary_string(data, tmp_str, sizeof(tmp_str) - 1);
            tmp_id = tick_stat_node(st, "Subscribe Eventgroup Ack", src_id, TRUE);
            tick_stat_node(st, tmp_str, tmp_id, FALSE);
            tmp_id = tick_stat_node(st, "Subscribe Eventgroup Ack", dst_id, TRUE);
            tick_stat_node(st, tmp_str, tmp_id, FALSE);
            break;
        }
    }

    return TAP_PACKET_REDRAW;
}

void
proto_register_someip_sd(void) {
    module_t *someipsd_module;

    expert_module_t *expert_module_someip_sd;

    /* data fields */
    static hf_register_info hf_sd[] = {
        { &hf_someip_sd_flags,
            { "Flags", "someipsd.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_rebootflag,
            { "Reboot Flag", "someipsd.flags.reboot",
            FT_BOOLEAN, 8, TFS(&sd_reboot_flag), SOMEIP_SD_REBOOT_FLAG, NULL, HFILL }},
        { &hf_someip_sd_unicastflag,
            { "Unicast Flag", "someipsd.flags.unicast",
            FT_BOOLEAN, 8, TFS(&sd_unicast_flag), SOMEIP_SD_UNICAST_FLAG, NULL, HFILL }},
        { &hf_someip_sd_explicitiniteventflag,
            { "Explicit Initial Events Flag", "someipsd.flags.exp_init_events",
            FT_BOOLEAN, 8, TFS(&sd_eiec_flag), SOMEIP_SD_EXPL_INIT_EVENT_REQ_FLAG, NULL, HFILL }},
        { &hf_someip_sd_reserved,
            { "Reserved", "someipsd.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_someip_sd_length_entriesarray,
            { "Length of Entries Array", "someipsd.length_entriesarray",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entries,
            { "Entries Array", "someipsd.entries",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry,
            { "Entry", "someipsd.entry",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_type,
            { "Type", "someipsd.entry.type",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_index1,
            { "Index 1", "someipsd.entry.index1",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_index2,
            { "Index 2", "someipsd.entry.index2",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_numopt1,
            { "Number of Opts 1", "someipsd.entry.numopt1",
            FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL }},
        { &hf_someip_sd_entry_numopt2,
            { "Number of Opts 2", "someipsd.entry.numopt2",
            FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL }},
        { &hf_someip_sd_entry_opts_referenced,
            { "Options referenced", "someipsd.entry.optionsreferenced",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }},

        { &hf_someip_sd_entry_serviceid,
            { "Service ID", "someipsd.entry.serviceid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_servicename,
            { "Service Name", "someipsd.entry.servicename",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_instanceid,
            { "Instance ID", "someipsd.entry.instanceid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_majorver,
            { "Major Version", "someipsd.entry.majorver",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_ttl,
            { "TTL", "someipsd.entry.ttl",
            FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_minorver,
            { "Minor Version", "someipsd.entry.minorver",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_eventgroupid,
            { "Eventgroup ID", "someipsd.entry.eventgroupid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_eventgroupname,
            { "Eventgroup Name", "someipsd.entry.eventgroupname",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_reserved,
            { "Reserved", "someipsd.entry.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_someip_sd_entry_counter,
            { "Counter", "someipsd.entry.counter",
            FT_UINT8, BASE_HEX, NULL, SD_EVENTGROUP_ENTRY_COUNTER_MASK, NULL, HFILL } },
        { &hf_someip_sd_entry_reserved2,
            { "Reserved", "someipsd.entry.reserved2",
            FT_UINT8, BASE_HEX, NULL, SD_EVENTGROUP_ENTRY_RES2_MASK, NULL, HFILL } },
        { &hf_someip_sd_entry_intial_event_flag,
            { "Initial Event Request", "someipsd.entry.initialevents",
            FT_BOOLEAN, 8, NULL, SD_ENTRY_INIT_EVENT_REQ_MASK, NULL, HFILL } },

        { &hf_someip_sd_length_optionsarray,
            { "Length of Options Array", "someipsd.length_optionsarray",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_options,
            { "Options Array", "someipsd.options",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_someip_sd_option_type,
            { "Type", "someipsd.option.type",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_option_length,
            { "Length", "someipsd.option.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_option_reserved,
            { "Reserved", "someipsd.option.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_option_ipv4,
            { "IPv4 Address", "someipsd.option.ipv4address",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_option_ipv6,
            { "IPv6 Address", "someipsd.option.ipv6address",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_option_port,
            { "Port", "someipsd.option.port",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_option_proto,
            { "Protocol", "someipsd.option.proto",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_option_reserved2,
            { "Reserved 2", "someipsd.option.reserved2",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_someip_sd_option_data,
            { "Unknown Data", "someipsd.option.unknown_data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_someip_sd_option_config_string,
            { "Configuration String", "someipsd.option.config_string",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_someip_sd_option_config_string_element,
            { "Configuration String Element", "someipsd.option.config_string_element",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_someip_sd_option_lb_priority,
            { "Priority", "someipsd.option.priority",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_someip_sd_option_lb_weight,
            { "Weight", "someipsd.option.weight",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_someip_sd_entry_type_offerservice,
            { "Offer Service", "someipsd.entry.offerservice",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_type_stopofferservice,
            { "Stop Offer Service", "someipsd.entry.stopofferservice",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_type_findservice,
            { "Find Service", "someipsd.entry.findservice",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_someip_sd_entry_type_subscribeeventgroup,
            { "Subscribe Eventgroup", "someipsd.entry.subscribeeventgroup",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_type_stopsubscribeeventgroup,
            { "Stop Subscribe Eventgroup", "someipsd.entry.stopsubscribeeventgroup",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_someip_sd_entry_type_subscribeeventgroupack,
            { "Subscribe Eventgroup ACK", "someipsd.entry.subscribeeventgroupack",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sd_entry_type_subscribeeventgroupnack,
            { "Subscribe Eventgroup NACK", "someipsd.entry.subscribeeventgroupnack",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett_sd[] = {
        &ett_someip_sd,
        &ett_someip_sd_flags,
        &ett_someip_sd_entries,
        &ett_someip_sd_entry,
        &ett_someip_sd_options,
        &ett_someip_sd_option,
        &ett_someip_sd_config_string,
    };

    static ei_register_info ei_sd[] = {
        { &ef_someipsd_message_truncated,{ "someipsd.message_truncated", PI_MALFORMED, PI_ERROR, "SOME/IP-SD Truncated message!", EXPFILL } },
        { &ef_someipsd_entry_array_malformed,{ "someipsd.entry_array_malformed", PI_MALFORMED, PI_ERROR, "SOME/IP-SD Entry Array length not multiple of 16 bytes!", EXPFILL } },
        { &ef_someipsd_entry_array_empty,{ "someipsd.entry_array_empty", PI_MALFORMED, PI_ERROR, "SOME/IP-SD Empty Entry Array!", EXPFILL } },
        { &ef_someipsd_entry_unknown,{ "someipsd.entry_unknown", PI_MALFORMED, PI_WARN, "SOME/IP-SD Unknown Entry!", EXPFILL } },
        { &ef_someipsd_option_array_truncated,{ "someipsd.option_array_truncated", PI_MALFORMED, PI_ERROR, "SOME/IP-SD Option Array truncated!", EXPFILL } },
        { &ef_someipsd_option_array_bytes_left,{ "someipsd.option_array_bytes_left", PI_MALFORMED, PI_WARN, "SOME/IP-SD Option Array bytes left after parsing options!", EXPFILL } },
        { &ef_someipsd_option_unknown,{ "someipsd.option_unknown", PI_MALFORMED, PI_WARN, "SOME/IP-SD Unknown Option!", EXPFILL } },
        { &ef_someipsd_option_wrong_length,{ "someipsd.option_wrong_length", PI_MALFORMED, PI_ERROR, "SOME/IP-SD Option length is incorrect!", EXPFILL } },
        { &ef_someipsd_L4_protocol_unsupported,{ "someipsd.L4_protocol_unsupported", PI_MALFORMED, PI_ERROR, "SOME/IP-SD Unsupported Layer 4 Protocol!", EXPFILL } },
        { &ef_someipsd_config_string_malformed,{ "someipsd.config_string_malformed", PI_MALFORMED, PI_ERROR, "SOME/IP-SD Configuration String malformed!", EXPFILL } },
    };

    /* Register Protocol, Fields, ETTs, Expert Info, Taps */
    proto_someip_sd = proto_register_protocol(SOMEIP_SD_NAME_LONG, SOMEIP_SD_NAME, SOMEIP_SD_NAME_FILTER);
    proto_register_field_array(proto_someip_sd, hf_sd, array_length(hf_sd));
    proto_register_subtree_array(ett_sd, array_length(ett_sd));
    expert_module_someip_sd = expert_register_protocol(proto_someip_sd);
    expert_register_field_array(expert_module_someip_sd, ei_sd, array_length(ei_sd));
    tap_someip_sd_entries = register_tap("someipsd_entries");

    /* Register preferences */
    someipsd_module = prefs_register_protocol(proto_someip_sd, &proto_reg_handoff_someip_sd);

    range_convert_str(wmem_epan_scope(), &someip_ignore_ports_udp, "", 65535);
    prefs_register_range_preference(someipsd_module, "ports.udp.ignore", "UDP Ports ignored",
        "SOME/IP Ignore Port Ranges UDP. These ports are not automatically added by the SOME/IP-SD.",
        &someip_ignore_ports_udp, 65535);

    range_convert_str(wmem_epan_scope(), &someip_ignore_ports_tcp, "", 65535);
    prefs_register_range_preference(someipsd_module, "ports.tcp.ignore", "TCP Ports ignored",
        "SOME/IP Ignore Port Ranges TCP. These ports are not automatically added by the SOME/IP-SD.",
        &someip_ignore_ports_tcp, 65535);
 }

void
proto_reg_handoff_someip_sd(void) {
    static gboolean             initialized = FALSE;
    static dissector_handle_t   someip_sd_handle = NULL;

    if (!initialized) {
        someip_sd_handle = create_dissector_handle(dissect_someip_sd_pdu, proto_someip_sd);
        dissector_add_uint("someip.messageid", SOMEIP_SD_MESSAGEID, someip_sd_handle);

        stats_tree_register("someipsd_entries", "someipsd_entries", "SOME/IP-SD Entries", 0, someipsd_entries_stats_tree_packet, someipsd_entries_stats_tree_init, NULL);

        initialized = TRUE;
    }

    /* nothing to do here right now */
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
