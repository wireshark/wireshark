/* packet-rsync.c
 * Routines for rsync dissection
 * [ very rough, but mininally functional ]
 * Copyright 2003, Brad Hards <bradh@frogmouth.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define NEW_PROTO_TREE_API

#include "config.h"

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/wmem/wmem.h>
#include <epan/prefs.h>

void proto_register_rsync(void);

#define RSYNCD_MAGIC_HEADER "@RSYNCD:"
#define RSYNCD_MAGIC_HEADER_LEN 8

#define RSYNCD_AUTHREQD "@RSYNCD: AUTHREQD "
#define RSYNCD_AUTHREQD_LEN 18

#define RSYNCD_EXIT "@RSYNCD: EXIT"
#define RSYNCD_EXIT_LEN 13

#define RSYNC_MODULE_LIST_QUERY "\n"
#define RSYNC_MODULE_LIST_QUERY_LEN 1

/* what states make sense here ? */
typedef enum _rsync_state {
    RSYNC_INIT         = 0,
    RSYNC_SERV_INIT    = 1,
    RSYNC_CLIENT_QUERY = 2,
    RSYNC_MODULE_LIST  = 4,
    RSYNC_COMMAND      = 5,
    RSYNC_SERV_MOTD    = 6,
    RSYNC_DATA         = 7
} rsync_state_t;

enum rsync_who {
    CLIENT,
    SERVER
};

static gboolean rsync_desegment = TRUE;

/* this is a guide to the current conversation state */
struct rsync_conversation_data {
    rsync_state_t client_state;
    rsync_state_t server_state;
};

struct rsync_frame_data {
    rsync_state_t state;
};

static header_field_info *hfi_rsync = NULL;

#define RSYNC_HF_INIT HFI_INIT(proto_rsync)

static header_field_info hfi_rsync_hdr_magic RSYNC_HF_INIT = {
    "Magic Header", "rsync.hdr_magic",
    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_rsync_hdr_version RSYNC_HF_INIT = {
    "Header Version", "rsync.hdr_version",
    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_rsync_query_string RSYNC_HF_INIT = {
    "Client Query String", "rsync.query",
    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_rsync_motd_string RSYNC_HF_INIT = {
    "Server MOTD String", "rsync.motd",
    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_rsync_module_list_string RSYNC_HF_INIT = {
    "Server Module List", "rsync.module_list",
    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_rsync_rsyncdok_string RSYNC_HF_INIT = {
    "RSYNCD Response String", "rsync.response",
    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_rsync_command_string RSYNC_HF_INIT = {
    "Client Command String", "rsync.command",
    FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_rsync_data RSYNC_HF_INIT = {
    "rsync data", "rsync.data",
    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static gint ett_rsync = -1;

static dissector_handle_t rsync_handle;


#define TCP_PORT_RSYNC  873

static guint glb_rsync_tcp_port = TCP_PORT_RSYNC;

#define VERSION_LEN     4           /* 2 digits for main version; '.'; 1 digit for sub version */

static void
dissect_rsync_version_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *rsync_tree, enum rsync_who me)
{
    int   offset = 0;
    guint8 *version;

    proto_tree_add_item(rsync_tree, &hfi_rsync_hdr_magic, tvb, offset, RSYNCD_MAGIC_HEADER_LEN, ENC_ASCII|ENC_NA);
    offset += RSYNCD_MAGIC_HEADER_LEN;
    offset += 1; /* skip the space */
    proto_tree_add_item(rsync_tree, &hfi_rsync_hdr_version, tvb, offset, VERSION_LEN, ENC_ASCII|ENC_NA);
    version = tvb_get_string_enc(wmem_packet_scope(),tvb, offset, VERSION_LEN, ENC_ASCII|ENC_NA);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s Initialisation (Version %s)", (me == SERVER ? "Server" : "Client"), version);
}

/* Packet dissection routine called by tcp (& udp) when port 873 detected */
static int
dissect_rsync_encap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    gboolean desegment _U_)
{
    conversation_t                 *conversation;
    struct rsync_conversation_data *conversation_data;
    struct rsync_frame_data        *rsync_frame_data_p;
    proto_item                     *ti;
    proto_tree                     *rsync_tree;
    enum rsync_who                  me;
    int                             offset = 0;
    guint                           buff_length;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RSYNC");

    col_clear(pinfo->cinfo, COL_INFO);

    me = pinfo->srcport == glb_rsync_tcp_port ? SERVER : CLIENT;

    conversation = find_or_create_conversation(pinfo);

    conversation_data = (struct rsync_conversation_data *)conversation_get_proto_data(conversation, hfi_rsync->id);

    if (conversation_data == NULL) { /* new conversation */
    conversation_data = wmem_new(wmem_file_scope(), struct rsync_conversation_data);
    conversation_data->client_state = RSYNC_INIT;
    conversation_data->server_state = RSYNC_SERV_INIT;
    conversation_add_proto_data(conversation, hfi_rsync->id, conversation_data);
    }

    conversation_set_dissector(conversation, rsync_handle);

    ti = proto_tree_add_item(tree, hfi_rsync, tvb, 0, -1, ENC_NA);

    rsync_tree = proto_item_add_subtree(ti, ett_rsync);

    rsync_frame_data_p = (struct rsync_frame_data *)p_get_proto_data(wmem_file_scope(), pinfo, hfi_rsync->id, 0);
    if (!rsync_frame_data_p) {
    /* then we haven't seen this frame before */
    rsync_frame_data_p = wmem_new(wmem_file_scope(), struct rsync_frame_data);
    rsync_frame_data_p->state = (me == SERVER) ? conversation_data->server_state : conversation_data->client_state;
    p_add_proto_data(wmem_file_scope(), pinfo, hfi_rsync->id, 0, rsync_frame_data_p);
    }

    if (me == SERVER) {
    switch (rsync_frame_data_p->state) {
        case RSYNC_SERV_INIT:
            dissect_rsync_version_header(tvb, pinfo, rsync_tree, me);

            conversation_data->server_state = RSYNC_SERV_MOTD;

            break;

        case RSYNC_SERV_MOTD:
            proto_tree_add_item(rsync_tree, &hfi_rsync_motd_string, tvb, offset, -1, ENC_ASCII|ENC_NA);

            col_set_str(pinfo->cinfo, COL_INFO, "Server MOTD");

            conversation_data->server_state = RSYNC_SERV_MOTD;

            break;

        case RSYNC_MODULE_LIST:
            /* there are two cases - file list, or authentication */
            if (0 == tvb_strneql(tvb, offset, RSYNCD_AUTHREQD, RSYNCD_AUTHREQD_LEN)) {
                /* matches, so we assume its an authentication message */
                proto_tree_add_item(rsync_tree, &hfi_rsync_rsyncdok_string, tvb, offset, -1, ENC_ASCII|ENC_NA);

                col_set_str(pinfo->cinfo, COL_INFO, "Authentication");
                conversation_data->server_state = RSYNC_DATA;

            } else { /*  it didn't match, so it is probably a module list */

                proto_tree_add_item(rsync_tree, &hfi_rsync_module_list_string, tvb, offset, -1, ENC_ASCII|ENC_NA);

                /* we need to check the end of the buffer for magic string */
                buff_length = tvb_length_remaining(tvb, offset);
                if (buff_length > RSYNCD_EXIT_LEN &&
                    0 == tvb_strneql(tvb, buff_length-RSYNCD_EXIT_LEN-1, RSYNCD_EXIT, RSYNCD_EXIT_LEN)) {
            /* that's all, folks */
            col_set_str(pinfo->cinfo, COL_INFO, "Final module list");
            conversation_data->server_state = RSYNC_DATA;
                } else { /* there must be more data */
            col_set_str(pinfo->cinfo, COL_INFO, "Module list");
            conversation_data->server_state = RSYNC_MODULE_LIST;
                }
            }

            break;

        case RSYNC_DATA:
            proto_tree_add_item(rsync_tree, &hfi_rsync_data, tvb, offset, -1, ENC_NA);

            col_set_str(pinfo->cinfo, COL_INFO, "Data");

            conversation_data->server_state = RSYNC_DATA;

            break;

    default:
        /* Unknown state */
        break;
        }
    } else { /* me == CLIENT */
    switch (rsync_frame_data_p->state) {
        case RSYNC_INIT:
            dissect_rsync_version_header(tvb, pinfo, rsync_tree, me);

            conversation_data->client_state = RSYNC_CLIENT_QUERY;

            break;

        case RSYNC_CLIENT_QUERY:
            proto_tree_add_item(rsync_tree, &hfi_rsync_query_string, tvb, offset, -1, ENC_ASCII|ENC_NA);

            col_set_str(pinfo->cinfo, COL_INFO, "Client Query");

            conversation_data->client_state = RSYNC_COMMAND;

            if (tvb_length(tvb) == RSYNC_MODULE_LIST_QUERY_LEN &&
                0 == tvb_strneql(tvb, offset, RSYNC_MODULE_LIST_QUERY, RSYNC_MODULE_LIST_QUERY_LEN)) {
        conversation_data->server_state = RSYNC_MODULE_LIST;
            } else {
                conversation_data->server_state = RSYNC_DATA;
            }

            break;

        case RSYNC_COMMAND:
            /* then we are still sending commands */
            proto_tree_add_item(rsync_tree, &hfi_rsync_command_string, tvb, offset, -1, ENC_ASCII|ENC_NA);

            col_set_str(pinfo->cinfo, COL_INFO, "Client Command");

            conversation_data->client_state = RSYNC_COMMAND;

            break;

        case RSYNC_DATA:
            /* then we are still sending commands */
            proto_tree_add_item(rsync_tree, &hfi_rsync_data, tvb, offset, -1, ENC_NA);

            col_set_str(pinfo->cinfo, COL_INFO, "Data");

            conversation_data->client_state = RSYNC_DATA;

            break;

    default:
        /* Unknown state */
        break;
        }
    }
    return tvb_length(tvb);
}

/* Packet dissection routine called by tcp (& udp) when port 873 detected */
static int
dissect_rsync(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_rsync_encap(tvb, pinfo, tree, rsync_desegment);
}

/* Register protocol with Wireshark. */

void proto_reg_handoff_rsync(void);

void
proto_register_rsync(void)
{
#ifndef HAVE_HFI_SECTION_INIT
    static header_field_info *hfi[] = {
        &hfi_rsync_hdr_magic,
        &hfi_rsync_hdr_version,
        &hfi_rsync_query_string,
        &hfi_rsync_module_list_string,
        &hfi_rsync_motd_string,
        &hfi_rsync_rsyncdok_string,
        &hfi_rsync_command_string,
        &hfi_rsync_data,
    };
#endif

    static gint *ett[] = {
        &ett_rsync,
    };

    module_t *rsync_module;

    int proto_rsync;

    proto_rsync = proto_register_protocol("RSYNC File Synchroniser",
                                          "RSYNC", "rsync");
    hfi_rsync = proto_registrar_get_nth(proto_rsync);

    proto_register_fields(proto_rsync, hfi, array_length(hfi));
    proto_register_subtree_array(ett, array_length(ett));

    rsync_module = prefs_register_protocol(proto_rsync, proto_reg_handoff_rsync);
    prefs_register_uint_preference(rsync_module, "tcp_port",
                                   "rsync TCP Port",
                                   "Set the TCP port for RSYNC messages",
                                   10,
                                   &glb_rsync_tcp_port);
    prefs_register_bool_preference(rsync_module, "desegment",
                                   "Reassemble RSYNC messages spanning multiple TCP segments",
                                   "Whether the RSYNC dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable"
                                   " \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &rsync_desegment);

    rsync_handle = new_create_dissector_handle(dissect_rsync, proto_rsync);
}
void
proto_reg_handoff_rsync(void)
{
    static gboolean initialized = FALSE;
    static guint    saved_rsync_tcp_port;

    if (!initialized) {
        initialized = TRUE;
    } else {
        dissector_delete_uint("tcp.port", saved_rsync_tcp_port, rsync_handle);
    }

    dissector_add_uint("tcp.port", glb_rsync_tcp_port, rsync_handle);
    saved_rsync_tcp_port = glb_rsync_tcp_port;
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
