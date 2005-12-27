/* packet-rsync.c
 * Routines for rsync dissection
 * [ very rough, but mininally functional ]
 * Copyright 2003, Brad Hards <bradh@frogmouth.net>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <time.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/conversation.h>

#include <epan/prefs.h>


/* what states make sense here ? */
typedef enum _rsync_state {
  RSYNC_INIT = 0,
  RSYNC_SERV_INIT = 1,
  RSYNC_CLIENT_QUERY = 2,
  RSYNC_SERV_RESPONSE = 4,
  RSYNC_COMMAND = 5,
  RSYNC_SERV_MOTD = 6,
  RSYNC_DATA = 7
} rsync_state_t;

static gboolean rsync_desegment = TRUE;

/* this is a guide to the current conversation state */
struct rsync_conversation_data {
    rsync_state_t 	state;
};

struct rsync_frame_data {
    rsync_state_t 	state;
};

static int proto_rsync = -1;

static int hf_rsync_hdr_magic = -1;
static int hf_rsync_hdr_version = -1;
static int hf_rsync_query_string = -1;
static int hf_rsync_motd_string = -1;
static int hf_rsync_response_string = -1;
static int hf_rsync_rsyncdok_string = -1;
static int hf_rsync_command_string = -1;
static int hf_rsync_data = -1;

static gint ett_rsync = -1;

dissector_handle_t rsync_handle;


#define TCP_PORT_RSYNC	873

static unsigned int glb_rsync_tcp_port = TCP_PORT_RSYNC;

/* Packet dissection routine called by tcp (& udp) when port 873 detected */
static void
dissect_rsync_encap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		    gboolean desegment _U_)
{
    conversation_t			*conversation;
    struct rsync_conversation_data	*conversation_data;
    struct rsync_frame_data		*frame_data;
    proto_item				*ti;
    proto_tree				*rsync_tree;
    int					offset = 0;
    gchar				version[5];
    gchar				auth_string[10];
    guint				buff_length;
    gchar				magic_string[14];
    gchar				*version_out;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RSYNC");

    if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);

    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
				     pinfo->srcport, pinfo->destport, 0);
    if (conversation == NULL) {
	conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
					pinfo->ptype, pinfo->srcport,
					pinfo->destport, 0);
    }

    conversation_data = conversation_get_proto_data(conversation, proto_rsync);

    if (conversation_data == NULL) {
	conversation_data = g_malloc(sizeof(struct rsync_conversation_data));
	conversation_data->state = RSYNC_INIT;
	conversation_add_proto_data(conversation, proto_rsync, conversation_data);
    }

    conversation_set_dissector(conversation, rsync_handle);
   
    ti = proto_tree_add_item(tree, proto_rsync, tvb, 0, -1, FALSE);

    rsync_tree = proto_item_add_subtree(ti, ett_rsync);

    frame_data = p_get_proto_data(pinfo->fd, proto_rsync);
    if (!frame_data) {
	/* then we haven't seen this frame before */
	frame_data = g_malloc(sizeof(struct rsync_frame_data));
	frame_data->state = conversation_data->state;
	p_add_proto_data(pinfo->fd, proto_rsync, frame_data);
    }

    switch (frame_data->state) {
    case RSYNC_INIT:
	proto_tree_add_item(rsync_tree, hf_rsync_hdr_magic, tvb, offset, 8, TRUE);
	offset += 8;
	proto_tree_add_item(rsync_tree, hf_rsync_hdr_version, tvb, offset, 4, TRUE);
	tvb_get_nstringz0(tvb, offset, sizeof(version), version);
	offset += 4;

        if (check_col(pinfo->cinfo, COL_INFO)) {
            /* XXX - is this really a string? */
            version_out = format_text(version, 4);
            col_append_fstr(pinfo->cinfo, COL_INFO,
			    "Client Initialisation (Version %s)",
			    version_out);
	}

	conversation_data->state = RSYNC_SERV_INIT;
        conversation_add_proto_data(conversation, proto_rsync, conversation_data);

	break;
    case RSYNC_SERV_INIT:
	proto_tree_add_item(rsync_tree, hf_rsync_hdr_magic, tvb, offset, 8, TRUE);
	offset += 8;
	proto_tree_add_item(rsync_tree, hf_rsync_hdr_version, tvb, offset, 4, TRUE);
	tvb_get_nstringz0(tvb, offset, sizeof(version), version);
	offset += 4;

        if (check_col(pinfo->cinfo, COL_INFO)) {
            /* XXX - is this really a string? */
            version_out = format_text(version, 4);
            col_append_fstr(pinfo->cinfo, COL_INFO,
			    "Server Initialisation (Version %s)",
			    version_out);
	}

	conversation_data->state = RSYNC_CLIENT_QUERY;
        conversation_add_proto_data(conversation, proto_rsync, conversation_data);

	break;
    case RSYNC_CLIENT_QUERY:
	proto_tree_add_item(rsync_tree, hf_rsync_query_string, tvb, offset, -1, TRUE);

        if (check_col(pinfo->cinfo, COL_INFO)) {
	  col_append_str(pinfo->cinfo, COL_INFO, "Client Query");
	}

	conversation_data->state = RSYNC_SERV_MOTD;
        conversation_add_proto_data(conversation, proto_rsync, conversation_data);

	break;
    case RSYNC_SERV_MOTD:
	proto_tree_add_item(rsync_tree, hf_rsync_motd_string, tvb, offset, -1, TRUE);

        if (check_col(pinfo->cinfo, COL_INFO)) {
	  col_append_fstr(pinfo->cinfo, COL_INFO, "Server MOTD");
	}

	conversation_data->state = RSYNC_SERV_RESPONSE;
        conversation_add_proto_data(conversation, proto_rsync, conversation_data);

	break;
    case RSYNC_SERV_RESPONSE:
        /* there are two cases - file list, or authentication */
        tvb_get_nstringz0(tvb, offset, sizeof(auth_string), auth_string);
	if (0 == strncmp("@RSYNCD:", auth_string, 8)) {
	  /* matches, so we assume its an authentication message */
	  /* needs to handle the AUTHREQD case, but doesn't - FIXME */
	  proto_tree_add_item(rsync_tree, hf_rsync_rsyncdok_string, tvb, offset, -1, TRUE);

	  if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_append_str(pinfo->cinfo, COL_INFO, "Authentication");
	  }
	  conversation_data->state = RSYNC_COMMAND;

	} else { /*  it didn't match, so it is probably a module list */

	  proto_tree_add_item(rsync_tree, hf_rsync_response_string, tvb, offset, -1, TRUE);

	  if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_append_fstr(pinfo->cinfo, COL_INFO, "Module list");
	  }

	  /* we need to check the end of the buffer for magic string */
	  buff_length = tvb_length_remaining(tvb, offset);
	  tvb_get_nstringz0(tvb, buff_length-14, sizeof(magic_string), magic_string);
	  if (0 == strncmp("@RSYNCD: EXIT", magic_string, 14)) {
	    /* that's all, folks */
	    conversation_data->state = RSYNC_COMMAND;
	  } else { /* there must be more data */
	    conversation_data->state = RSYNC_SERV_RESPONSE;
	  }
	}

	conversation_add_proto_data(conversation, proto_rsync, conversation_data);

	break;

    case RSYNC_COMMAND:
        if (pinfo->destport == glb_rsync_tcp_port) {
	  /* then we are still sending commands */
	  proto_tree_add_item(rsync_tree, hf_rsync_command_string, tvb, offset, -1, TRUE);

	  if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_append_str(pinfo->cinfo, COL_INFO, "Command");
	  }

	  conversation_data->state = RSYNC_COMMAND;
	  conversation_add_proto_data(conversation, proto_rsync, conversation_data);

	  break;
	} /* else we fall through to the data phase */

    case RSYNC_DATA:
      /* then we are still sending commands */
      proto_tree_add_item(rsync_tree, hf_rsync_data, tvb, offset, -1, TRUE);

      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_append_str(pinfo->cinfo, COL_INFO, "Data");
      }

      conversation_data->state = RSYNC_DATA;
      conversation_add_proto_data(conversation, proto_rsync, conversation_data);

      break;

    }

}

/* Packet dissection routine called by tcp (& udp) when port 873 detected */
static void
dissect_rsync(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_rsync_encap(tvb, pinfo, tree, rsync_desegment);
}

/* Register protocol with Ethereal. */
void
proto_register_rsync(void)
{
    static hf_register_info hf[] = {
	{&hf_rsync_hdr_magic,
	 {"Magic Header", "rsync.hdr_magic",
	  FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
	},
	{&hf_rsync_hdr_version,
	 {"Header Version", "rsync.hdr_version",
	  FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
	},
	{&hf_rsync_query_string,
	 {"Client Query String", "rsync.query",
	  FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
	},
	{&hf_rsync_response_string,
	 {"Server Response String", "rsync.response",
	  FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
	},
	{&hf_rsync_motd_string,
	 {"Server MOTD String", "rsync.motd",
	  FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
	},
	{&hf_rsync_rsyncdok_string,
	 {"RSYNCD Response String", "rsync.response",
	  FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
	},
	{&hf_rsync_command_string,
	 {"Command String", "rsync.command",
	  FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
	},
	{&hf_rsync_data,
	 {"rsync data", "rsync.data",
	  FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
	},

    };

    static gint *ett[] = {
	&ett_rsync,
    };

    module_t *rsync_module;

    proto_rsync = proto_register_protocol("RSYNC File Synchroniser",
					   "RSYNC", "rsync");
    proto_register_field_array(proto_rsync, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    rsync_module = prefs_register_protocol(proto_rsync, NULL);
    prefs_register_uint_preference(rsync_module, "tcp_port",
				   "rsync TCP Port",
				   "Set the TCP port for RSYNC messages",
				   10,
				   &glb_rsync_tcp_port);
    prefs_register_bool_preference(rsync_module, "desegment",
	    "Reassemble RSYNC messages spanning multiple TCP segments",
	    "Whether the RSYNC dissector should reassemble messages spanning multiple TCP segments."
	    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	    &rsync_desegment);
}
void
proto_reg_handoff_rsync(void)
{
    rsync_handle = create_dissector_handle(dissect_rsync, proto_rsync);
    dissector_add("tcp.port", glb_rsync_tcp_port, rsync_handle);
}
