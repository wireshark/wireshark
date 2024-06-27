/* packet-sparkplug.c
 * Routines for Sparkplug dissection
 * Copyright 2021 Graham Bloice <graham.bloice<at>trihedral.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>

/*
 * See
 *
 * https://cirrus-link.com/mqtt-sparkplug-tahu/
 *
 * and the specification is at
 *
 * https://www.eclipse.org/tahu/spec/Sparkplug%20Topic%20Namespace%20and%20State%20ManagementV2.2-with%20appendix%20B%20format%20-%20Eclipse.pdf
 *
 */

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_sparkplug(void);
void proto_register_sparkplug(void);

/* Initialize the protocol field */
static int proto_sparkplugb;

/* Initialize the subtree pointers */
static gint ett_sparkplugb;
static gint ett_sparkplugb_namespace;

/* The handle to the protobuf dissector */
dissector_handle_t protobuf_handle;

/* The hf items */
static int hf_sparkplugb_namespace;
static int hf_sparkplugb_groupid;
static int hf_sparkplugb_messagetype;
static int hf_sparkplugb_edgenodeid;
static int hf_sparkplugb_deviceid;

/* The expert info items */
static expert_field ei_sparkplugb_missing_groupid;
static expert_field ei_sparkplugb_missing_messagetype;
static expert_field ei_sparkplugb_missing_edgenodeid;

static gboolean
dissect_sparkplugb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti;
    proto_tree *sparkplugb_tree, *namespace_tree;
    gchar **topic_elements, **current_element;
    char *topic = (char *)data;

    /* Confirm the expected topic data is present */
    if (topic == NULL)
      return FALSE;

    /* Parse the topic into the elements */
    topic_elements = g_strsplit(topic, "/", 5);

    /* Heuristic check that the first element of the topic is the SparkplugB namespace */
    if (!topic_elements || (g_strcmp0("spBv1.0", topic_elements[0]) != 0)) {
        g_strfreev(topic_elements);
        return FALSE;
    }

    /* Make entries in Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SparkplugB");

    /* Adjust the info column */
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "SparkplugB");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_sparkplugb, tvb, 0, -1, ENC_NA);
    sparkplugb_tree = proto_item_add_subtree(ti, ett_sparkplugb);

    /* Add the elements parsed out from the topic string */
    namespace_tree = proto_tree_add_subtree(sparkplugb_tree, tvb, 0, 0, ett_sparkplugb_namespace, &ti, "Topic Namespace");
    proto_item_set_generated(ti);

    current_element = topic_elements;
    ti = proto_tree_add_string(namespace_tree, hf_sparkplugb_namespace, tvb, 0, 0, current_element[0]);
    proto_item_set_generated(ti);

    current_element += 1;
    if (current_element[0]) {
        ti = proto_tree_add_string(namespace_tree, hf_sparkplugb_groupid, tvb, 0, 0, current_element[0]);
        proto_item_set_generated(ti);
    }
    else {
        expert_add_info(pinfo, namespace_tree, &ei_sparkplugb_missing_groupid);
        return FALSE;
    }

    /* Adjust the info column text with the message type */
    current_element += 1;
    if (current_element[0]) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, current_element[0]);
        col_set_fence(pinfo->cinfo, COL_INFO);

        ti = proto_tree_add_string(namespace_tree, hf_sparkplugb_messagetype, tvb, 0, 0, current_element[0]);
        proto_item_set_generated(ti);
    }
    else {
        expert_add_info(pinfo, namespace_tree, &ei_sparkplugb_missing_messagetype);
        return FALSE;
    }

    current_element += 1;
    if (current_element[0]) {
        ti = proto_tree_add_string(namespace_tree, hf_sparkplugb_edgenodeid, tvb, 0, 0, current_element[0]);
        proto_item_set_generated(ti);
    }
    else {
        expert_add_info(pinfo, namespace_tree, &ei_sparkplugb_missing_edgenodeid);
        return FALSE;
    }

    /* Device ID is optional */
    current_element += 1;
    if (current_element[0]) {
        ti = proto_tree_add_string(namespace_tree, hf_sparkplugb_deviceid, tvb, 0, 0, current_element[0]);
        proto_item_set_generated(ti);
    }

    g_strfreev(topic_elements);

    /* Now handoff the Payload message to the protobuf dissector */
    call_dissector_with_data(protobuf_handle, tvb, pinfo, sparkplugb_tree, "message,com.cirruslink.sparkplug.protobuf.Payload");

    return TRUE;
}

static bool dissect_sparkplugb_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	return (bool)dissect_sparkplugb(tvb, pinfo, parent_tree, data);
}

void proto_register_sparkplug(void)
{
    expert_module_t* expert_sparkplugb;

    static gint *ett[] = {
        &ett_sparkplugb,
        &ett_sparkplugb_namespace
    };

    static hf_register_info hf[] = {
        {&hf_sparkplugb_namespace, {"Namespace", "sparkplugb.namespace", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_sparkplugb_groupid, {"Group ID", "sparkplugb.groupid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_sparkplugb_messagetype, {"Message Type", "sparkplugb.messagetype", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_sparkplugb_edgenodeid, {"Edge Node ID", "sparkplugb.edgenodeid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_sparkplugb_deviceid, {"Device ID", "sparkplugb.deviceid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    };

    static ei_register_info ei[] = {
        { &ei_sparkplugb_missing_groupid, { "sparkplugb.missing_groupid", PI_MALFORMED, PI_ERROR, "Missing Group ID", EXPFILL }},
        { &ei_sparkplugb_missing_messagetype, { "sparkplugb.missing_messagetype", PI_MALFORMED, PI_ERROR, "Missing Message Type", EXPFILL }},
        { &ei_sparkplugb_missing_edgenodeid, { "sparkplugb.missing_edgenodeid", PI_MALFORMED, PI_ERROR, "Missing Edge Node ID", EXPFILL }},
    };

    /* Register the protocol name and description, fields and trees */
    proto_sparkplugb = proto_register_protocol("SparkplugB", "SparkplugB", "sparkplugb");
    register_dissector("sparkplugb", dissect_sparkplugb, proto_sparkplugb);

    proto_register_field_array(proto_sparkplugb, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_sparkplugb = expert_register_protocol(proto_sparkplugb);
    expert_register_field_array(expert_sparkplugb, ei, array_length(ei));
}

void proto_reg_handoff_sparkplug(void)
{
    protobuf_handle = find_dissector_add_dependency("protobuf", proto_sparkplugb);

    /* register as heuristic dissector with MQTT */
    heur_dissector_add("mqtt.topic", dissect_sparkplugb_heur, "SparkplugB over MQTT",
                       "sparkplugb_mqtt", proto_sparkplugb, HEURISTIC_ENABLE);
}
