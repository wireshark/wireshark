/* packet-openflow.c
 * Routines for OpenFlow dissection
 * Copyright 2013, Anders Broman <anders.broman@ericsson.com>
 * Copyright 2013, Zoltan Lajos Kis <zoltan.lajos.kis@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref https://www.opennetworking.org/sdn-resources/onf-specifications/openflow
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include "packet-tcp.h"

void proto_register_openflow(void);
void proto_reg_handoff_openflow(void);

#define OFP_LEGACY_PORT 6633
#define OFP_LEGACY2_PORT 6634
#define OFP_IANA_PORT 6653
static range_t *g_openflow_ports = NULL;

static dissector_handle_t openflow_handle;
static dissector_handle_t openflow_v1_handle;
static dissector_handle_t openflow_v4_handle;
static dissector_handle_t openflow_v5_handle;
static dissector_handle_t openflow_v6_handle;

/* Initialize the protocol and registered fields */
static int proto_openflow = -1;
static int hf_openflow_version = -1;

static expert_field ei_openflow_version = EI_INIT;

static gboolean openflow_desegment = TRUE;

#define OFP_VERSION_1_0 1
#define OFP_VERSION_1_1 2
#define OFP_VERSION_1_2 3
#define OFP_VERSION_1_3 4
#define OFP_VERSION_1_4 5
#define OFP_VERSION_1_5 6

static const value_string openflow_version_values[] = {
    { OFP_VERSION_1_0, "1.0" },
    { OFP_VERSION_1_1, "1.1" },
    { OFP_VERSION_1_2, "1.2" },
    { OFP_VERSION_1_3, "1.3" },
    { OFP_VERSION_1_4, "1.4" },
    { OFP_VERSION_1_5, "1.5" },
    { 0, NULL }
};

static guint
get_openflow_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb,
                        int offset, void *data _U_)
{
    return tvb_get_ntohs(tvb, offset + 2);
}

static int
dissect_openflow_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint offset = 0;
    guint8 version;
    proto_item* ti;

    version = tvb_get_guint8(tvb, 0);
    /* Set the Protocol column to the constant string of openflow */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OpenFlow");
    col_clear(pinfo->cinfo,COL_INFO);

    switch(version){
    case OFP_VERSION_1_0:
        call_dissector(openflow_v1_handle, tvb, pinfo, tree);
        break;
    case OFP_VERSION_1_3:
        call_dissector(openflow_v4_handle, tvb, pinfo, tree);
        break;
    case OFP_VERSION_1_4:
        call_dissector(openflow_v5_handle, tvb, pinfo, tree);
        break;
    case OFP_VERSION_1_5:
        call_dissector(openflow_v6_handle, tvb, pinfo, tree);
        break;
    default:
        ti = proto_tree_add_item(tree, hf_openflow_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        expert_add_info(pinfo, ti, &ei_openflow_version);
        break;
    }
    return tvb_reported_length(tvb);
}

#define OFP_HEADER_LEN  8
static int
dissect_openflow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, openflow_desegment, OFP_HEADER_LEN,
                     get_openflow_pdu_length, dissect_openflow_tcp_pdu, data);
    return tvb_captured_length(tvb);
}

static gboolean
dissect_openflow_heur(tvbuff_t *tvb, packet_info *pinfo,
                     proto_tree *tree, void *data)
{
    conversation_t *conversation = NULL;

    if ((pinfo->destport != OFP_LEGACY_PORT) &&
        (pinfo->destport != OFP_LEGACY2_PORT) &&
        (pinfo->destport != OFP_IANA_PORT) &&
        (!value_is_in_range(g_openflow_ports, pinfo->destport))) {
        return FALSE;
    }

    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, openflow_handle);

    dissect_openflow(tvb, pinfo, tree, data);
    return TRUE;
}

static void
apply_openflow_prefs(void)
{
    /* Openflow uses the port preference for heuristics */
    g_openflow_ports = prefs_get_range_value("openflow", "tcp.port");
}

/*
 * Register the protocol with Wireshark.
 */
void
proto_register_openflow(void)
{
    static hf_register_info hf[] = {
        { &hf_openflow_version,
            { "Version", "openflow.version",
               FT_UINT8, BASE_HEX, VALS(openflow_version_values), 0x7f,
               NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_openflow_version, { "openflow.version.unknown", PI_UNDECODED, PI_WARN, "Unsupported version not dissected", EXPFILL }},
    };

    module_t *openflow_module;
    expert_module_t* expert_openflow;

    /* Register the protocol name and description */
    proto_openflow = proto_register_protocol("OpenFlow",
            "OpenFlow", "openflow");

    openflow_handle = register_dissector("openflow", dissect_openflow, proto_openflow);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_openflow, hf, array_length(hf));
    expert_openflow = expert_register_protocol(proto_openflow);
    expert_register_field_array(expert_openflow, ei, array_length(ei));

    openflow_module = prefs_register_protocol(proto_openflow, apply_openflow_prefs);

    /* Register heuristic preference */
    prefs_register_obsolete_preference(openflow_module, "heuristic");

    /* Register desegment preference */
    prefs_register_bool_preference(openflow_module, "desegment",
                                  "Reassemble OpenFlow messages spanning multiple TCP segments",
                                  "Whether the OpenFlow dissector should reassemble messages spanning multiple TCP segments."
                                  " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                  &openflow_desegment);
}

void
proto_reg_handoff_openflow(void)
{
    heur_dissector_add("tcp", dissect_openflow_heur, "OpenFlow over TCP", "openflow_tcp", proto_openflow, HEURISTIC_ENABLE);

    dissector_add_uint_with_preference("tcp.port", OFP_IANA_PORT, openflow_handle);

    openflow_v1_handle = find_dissector_add_dependency("openflow_v1", proto_openflow);
    openflow_v4_handle = find_dissector_add_dependency("openflow_v4", proto_openflow);
    openflow_v5_handle = find_dissector_add_dependency("openflow_v5", proto_openflow);
    openflow_v6_handle = find_dissector_add_dependency("openflow_v6", proto_openflow);
    apply_openflow_prefs();
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
