/* packet-rsync.c
 * Routines for rsync dissection
 * [ very rough, but mininally functional ]
 * Copyright 2003, Brad Hards <bradh@frogmouth.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"


#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

void proto_register_rsync(void);
void proto_reg_handoff_rsync(void);

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

static int proto_rsync = -1;

static int hf_rsync_command_string = -1;
static int hf_rsync_data = -1;
static int hf_rsync_hdr_magic = -1;
static int hf_rsync_hdr_version = -1;
static int hf_rsync_module_list_string = -1;
static int hf_rsync_motd_string = -1;
static int hf_rsync_query_string = -1;
static int hf_rsync_rsyncdok_string = -1;

static gint ett_rsync = -1;

static dissector_handle_t rsync_handle;


#define TCP_PORT_RSYNC  873

static range_t *glb_rsync_tcp_range = NULL;

#define VERSION_LEN     4           /* 2 digits for main version; '.'; 1 digit for sub version */

static void
dissect_rsync_version_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *rsync_tree, enum rsync_who me)
{
    int   offset = 0;
    guint8 *version;
    guint len;

    proto_tree_add_item(rsync_tree, hf_rsync_hdr_magic, tvb, offset, RSYNCD_MAGIC_HEADER_LEN, ENC_ASCII);
    offset += RSYNCD_MAGIC_HEADER_LEN;
    offset += 1; /* skip the space */
    proto_tree_add_item(rsync_tree, hf_rsync_hdr_version, tvb, offset, -1, ENC_ASCII);
    len = tvb_reported_length_remaining(tvb, offset);
    version = tvb_get_string_enc(pinfo->pool, tvb, offset, len, ENC_ASCII|ENC_NA);

    /* VERSION string can contain undesirable char (like \n) at the end. Trim it. */
    if (len > 0 && version[len - 1] == '\n')
        version[len - 1] = 0x0;

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

    me = value_is_in_range(glb_rsync_tcp_range, pinfo->srcport) ? SERVER : CLIENT;

    conversation = find_or_create_conversation(pinfo);

    conversation_data = (struct rsync_conversation_data *)conversation_get_proto_data(conversation, proto_rsync);

    if (conversation_data == NULL) { /* new conversation */
    conversation_data = wmem_new(wmem_file_scope(), struct rsync_conversation_data);
    conversation_data->client_state = RSYNC_INIT;
    conversation_data->server_state = RSYNC_SERV_INIT;
    conversation_add_proto_data(conversation, proto_rsync, conversation_data);
    }

    conversation_set_dissector(conversation, rsync_handle);

    ti = proto_tree_add_item(tree, proto_rsync, tvb, 0, -1, ENC_NA);

    rsync_tree = proto_item_add_subtree(ti, ett_rsync);

    rsync_frame_data_p = (struct rsync_frame_data *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rsync, 0);
    if (!rsync_frame_data_p) {
    /* then we haven't seen this frame before */
    rsync_frame_data_p = wmem_new(wmem_file_scope(), struct rsync_frame_data);
    rsync_frame_data_p->state = (me == SERVER) ? conversation_data->server_state : conversation_data->client_state;
    p_add_proto_data(wmem_file_scope(), pinfo, proto_rsync, 0, rsync_frame_data_p);
    }

    if (me == SERVER) {
    switch (rsync_frame_data_p->state) {
        case RSYNC_SERV_INIT:
            dissect_rsync_version_header(tvb, pinfo, rsync_tree, me);

            conversation_data->server_state = RSYNC_SERV_MOTD;

            break;

        case RSYNC_SERV_MOTD:
            proto_tree_add_item(rsync_tree, hf_rsync_motd_string, tvb, offset, -1, ENC_ASCII);

            col_set_str(pinfo->cinfo, COL_INFO, "Server MOTD");

            conversation_data->server_state = RSYNC_SERV_MOTD;

            break;

        case RSYNC_MODULE_LIST:
            /* there are two cases - file list, or authentication */
            if (0 == tvb_strneql(tvb, offset, RSYNCD_AUTHREQD, RSYNCD_AUTHREQD_LEN)) {
                /* matches, so we assume it's an authentication message */
                proto_tree_add_item(rsync_tree, hf_rsync_rsyncdok_string, tvb, offset, -1, ENC_ASCII);

                col_set_str(pinfo->cinfo, COL_INFO, "Authentication");
                conversation_data->server_state = RSYNC_DATA;

            } else { /*  it didn't match, so it is probably a module list */

                proto_tree_add_item(rsync_tree, hf_rsync_module_list_string, tvb, offset, -1, ENC_ASCII);

                /* we need to check the end of the buffer for magic string */
                buff_length = tvb_captured_length_remaining(tvb, offset);
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
            proto_tree_add_item(rsync_tree, hf_rsync_data, tvb, offset, -1, ENC_NA);

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
            proto_tree_add_item(rsync_tree, hf_rsync_query_string, tvb, offset, -1, ENC_ASCII);

            col_set_str(pinfo->cinfo, COL_INFO, "Client Query");

            conversation_data->client_state = RSYNC_COMMAND;

            if (tvb_captured_length(tvb) == RSYNC_MODULE_LIST_QUERY_LEN &&
                0 == tvb_strneql(tvb, offset, RSYNC_MODULE_LIST_QUERY, RSYNC_MODULE_LIST_QUERY_LEN)) {
                conversation_data->server_state = RSYNC_MODULE_LIST;
            } else {
                conversation_data->server_state = RSYNC_DATA;
            }

            break;

        case RSYNC_COMMAND:
            /* then we are still sending commands */
            proto_tree_add_item(rsync_tree, hf_rsync_command_string, tvb, offset, -1, ENC_ASCII);

            col_set_str(pinfo->cinfo, COL_INFO, "Client Command");

            conversation_data->client_state = RSYNC_COMMAND;

            break;

        case RSYNC_DATA:
            /* then we are still sending commands */
            proto_tree_add_item(rsync_tree, hf_rsync_data, tvb, offset, -1, ENC_NA);

            col_set_str(pinfo->cinfo, COL_INFO, "Data");

            conversation_data->client_state = RSYNC_DATA;

            break;

    default:
        /* Unknown state */
        break;
        }
    }
    return tvb_captured_length(tvb);
}

/* Packet dissection routine called by tcp (& udp) when port 873 detected */
static int
dissect_rsync(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_rsync_encap(tvb, pinfo, tree, rsync_desegment);
}

static void
apply_rsync_prefs(void)
{
    /* Rsync uses the port preference to determine client/server */
    glb_rsync_tcp_range = prefs_get_range_value("rsync", "tcp.port");
}

/* Register protocol with Wireshark. */
void
proto_register_rsync(void)
{
    static hf_register_info hf[] = {
        { &hf_rsync_hdr_magic,
            { "Magic Header", "rsync.hdr_magic",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_rsync_hdr_version,
            { "Header Version", "rsync.hdr_version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_rsync_query_string,
            { "Client Query String", "rsync.query",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_rsync_motd_string,
            { "Server MOTD String", "rsync.motd",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_rsync_module_list_string,
            { "Server Module List", "rsync.module_list",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_rsync_rsyncdok_string,
            { "RSYNCD Response String", "rsync.response",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_rsync_command_string,
            { "Client Command String", "rsync.command",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_rsync_data,
            { "rsync data", "rsync.data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_rsync,
    };

    module_t *rsync_module;

    proto_rsync = proto_register_protocol("RSYNC File Synchroniser", "RSYNC", "rsync");
    proto_register_field_array(proto_rsync, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    rsync_module = prefs_register_protocol(proto_rsync, apply_rsync_prefs);
    prefs_register_bool_preference(rsync_module, "desegment",
                                   "Reassemble RSYNC messages spanning multiple TCP segments",
                                   "Whether the RSYNC dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable"
                                   " \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &rsync_desegment);

    rsync_handle = create_dissector_handle(dissect_rsync, proto_rsync);
}
void
proto_reg_handoff_rsync(void)
{
    dissector_add_uint_with_preference("tcp.port", TCP_PORT_RSYNC, rsync_handle);
    apply_rsync_prefs();
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
