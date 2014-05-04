/* packet-openflow.c
 * Routines for OpenFlow dissection
 * Copyright 2013, Anders Broman <anders.broman@ericsson.com>
 * Copyright 2013, Zoltan Lajos Kis <zoltan.lajos.kis@ericsson.com>
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
 *
 * Ref https://www.opennetworking.org/sdn-resources/onf-specifications/openflow
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-tcp.h"

void proto_register_openflow(void);
void proto_reg_handoff_openflow(void);

#define OFP_LEGACY_PORT 6633
#define OFP_LEGACY2_PORT 6634
#define OFP_IANA_PORT 6653
static int g_openflow_port = OFP_IANA_PORT;
static gboolean openflow_heur_enabled = TRUE;

static dissector_handle_t openflow_handle;
static dissector_handle_t openflow_v1_handle;
static dissector_handle_t openflow_v4_handle;
static dissector_handle_t openflow_v5_handle;

/* Initialize the protocol and registered fields */
static int proto_openflow = -1;
static int hf_openflow_version = -1;

static gboolean openflow_desegment = TRUE;

#define OFP_VERSION_1_0 1
#define OFP_VERSION_1_1 2
#define OFP_VERSION_1_2 3
#define OFP_VERSION_1_3 4
#define OFP_VERSION_1_4 5

static const value_string openflow_version_values[] = {
    { 0x01, "1.0" },
    { 0x02, "1.1" },
    { 0x03, "1.2" },
    { 0x04, "1.3" },
    { 0x04, "1.4" },
    { 0, NULL }
};

static guint
get_openflow_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    return tvb_get_ntohs(tvb, offset + 2);
}

static int
dissect_openflow_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint offset = 0;
    guint8 version;

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
    default:
        proto_tree_add_item(tree, hf_openflow_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_text(tree, tvb, offset, -1, "Unsuported version not dissected");
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

    if (!openflow_heur_enabled) {
        return FALSE;
    }

    if ((pinfo->destport != OFP_LEGACY_PORT) &&
        (pinfo->destport != OFP_LEGACY2_PORT) &&
        (pinfo->destport != OFP_IANA_PORT) &&
        (pinfo->destport != (guint32)g_openflow_port)) {
        return FALSE;
    }

    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, openflow_handle);

    dissect_openflow(tvb, pinfo, tree, data);
    return TRUE;
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

    module_t *openflow_module;

    /* Register the protocol name and description */
    proto_openflow = proto_register_protocol("OpenFlow",
            "openflow", "openflow");

    new_register_dissector("openflow", dissect_openflow, proto_openflow);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_openflow, hf, array_length(hf));

    openflow_module = prefs_register_protocol(proto_openflow, proto_reg_handoff_openflow);

    /* Register port preference */
    prefs_register_uint_preference(openflow_module, "tcp.port", "OpenFlow TCP port",
                                   " OpenFlow TCP port (6653 is the IANA assigned port)",
                                   10, &g_openflow_port);

    /* Register heuristic preference */
    prefs_register_bool_preference(openflow_module, "heuristic",
                                   "Try to decode OpenFlow on other common ports",
                                   "Try to decode OpenFlow on several common "
                                   "ports in addition to the one supplied by "
                                   "user above (6653 is the IANA assigned port).",
                                   &openflow_heur_enabled);

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
    static gboolean initialized = FALSE;
    static int currentPort;

    if (!initialized) {
        openflow_handle = new_create_dissector_handle(dissect_openflow, proto_openflow);
        heur_dissector_add("tcp", dissect_openflow_heur, proto_openflow);
        initialized = TRUE;
    } else {
        dissector_delete_uint("tcp.port", currentPort, openflow_handle);
    }

    currentPort = g_openflow_port;

    dissector_add_uint("tcp.port", currentPort, openflow_handle);

    openflow_v1_handle = find_dissector("openflow_v1");
    openflow_v4_handle = find_dissector("openflow_v4");
    openflow_v5_handle = find_dissector("openflow_v5");
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
