/* packet-gryphon.c
 * Routines for Gryphon protocol packet disassembly
 * By Steve Limkemann <stevelim@dgtech.com>
 * Copyright 1998 Steve Limkemann
 *
 * $Id: packet-gryphon.c,v 1.27 2002/01/21 07:37:48 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "plugins/plugin_api.h"

#include "moduleinfo.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>
#include <time.h>

#include <gmodule.h>
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#include <epan/packet.h>
#include "packet-gryphon.h"

#include "plugins/plugin_api_defs.h"

#ifndef __ETHEREAL_STATIC__
G_MODULE_EXPORT const gchar version[] = VERSION;
#endif

#ifndef G_HAVE_GINT64
#error "Sorry, this won't compile without 64-bit integer support"
#endif                                                                  

/*
 * See
 *
 *	http://www.dgtech.com/gryphon/docs/html/
 */

static int proto_gryphon = -1;

static int hf_gryph_src = -1;
static int hf_gryph_srcchan = -1;
static int hf_gryph_dest = -1;
static int hf_gryph_destchan= -1;
static int hf_gryph_type = -1;
static int hf_gryph_cmd = -1;

static gint ett_gryphon = -1;
static gint ett_gryphon_header = -1;
static gint ett_gryphon_body = -1;
static gint ett_gryphon_command_data = -1;
static gint ett_gryphon_response_data = -1;
static gint ett_gryphon_data_header = -1;
static gint ett_gryphon_flags = -1;
static gint ett_gryphon_data_body = -1;
static gint ett_gryphon_cmd_filter_block = -1;
static gint ett_gryphon_cmd_events_data = -1;
static gint ett_gryphon_cmd_config_device = -1;
static gint ett_gryphon_cmd_sched_data = -1;
static gint ett_gryphon_cmd_sched_cmd = -1;
static gint ett_gryphon_cmd_response_block = -1;
static gint ett_gryphon_pgm_list = -1;
static gint ett_gryphon_pgm_status = -1;
static gint ett_gryphon_pgm_options = -1;

static int dissect_gryphon_message(tvbuff_t *tvb, int offset,
    proto_tree *tree, gboolean is_msgresp_add);
static int decode_command(tvbuff_t*, int, int, int, proto_tree*);
static int decode_response(tvbuff_t*, int, int, int, proto_tree*);
static int decode_data(tvbuff_t*, int, int, int, proto_tree*);
static int decode_event(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_init(tvbuff_t*, int, int, int, proto_tree*);
static int resp_time(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_setfilt(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_ioctl(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_addfilt(tvbuff_t*, int, int, int, proto_tree*);
static int resp_addfilt(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_modfilt(tvbuff_t*, int, int, int, proto_tree*);
static int resp_filthan(tvbuff_t*, int, int, int, proto_tree*);
static int dfiltmode(tvbuff_t*, int, int, int, proto_tree*);
static int filtmode(tvbuff_t*, int, int, int, proto_tree*);
static int resp_events(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_register(tvbuff_t*, int, int, int, proto_tree*);
static int resp_register(tvbuff_t*, int, int, int, proto_tree*);
static int resp_getspeeds(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_sort(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_optimize(tvbuff_t*, int, int, int, proto_tree*);
static int resp_config(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_sched(tvbuff_t*, int, int, int, proto_tree*);
static int resp_blm_data(tvbuff_t*, int, int, int, proto_tree*);
static int resp_blm_stat(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_addresp(tvbuff_t*, int, int, int, proto_tree*);
static int resp_addresp(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_modresp(tvbuff_t*, int, int, int, proto_tree*);
static int resp_resphan(tvbuff_t*, int, int, int, proto_tree*);
static int resp_sched(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_desc(tvbuff_t*, int, int, int, proto_tree*);
static int resp_desc(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_upload(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_delete(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_list(tvbuff_t*, int, int, int, proto_tree*);
static int resp_list(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_start(tvbuff_t*, int, int, int, proto_tree*);
static int resp_start(tvbuff_t*, int, int, int, proto_tree*);
static int resp_status(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_options(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_files(tvbuff_t*, int, int, int, proto_tree*);
static int resp_files(tvbuff_t*, int, int, int, proto_tree*);
static int eventnum(tvbuff_t*, int, int, int, proto_tree*);
static int speed(tvbuff_t*, int, int, int, proto_tree*);
static int filter_block(tvbuff_t*, int, int, int, proto_tree*);
static int blm_mode(tvbuff_t*, int, int, int, proto_tree*);
static int cmd_usdt(tvbuff_t*, int, int, int, proto_tree*);

static char *frame_type[] = {
	"",
	"Command request",
	"Command response",
	"Network (vehicle) data",
	"Event",
	"Miscellaneous",
	"Text string"
};

static void
dissect_gryphon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset;
    proto_item *ti;
    proto_tree *gryphon_tree;
    guint8 frmtyp;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Gryphon");
    if (check_col(pinfo->cinfo, COL_INFO))
	col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_gryphon, tvb, 0,
	    	    tvb_length(tvb), FALSE);
    gryphon_tree = proto_item_add_subtree(ti, ett_gryphon);

    if (check_col(pinfo->cinfo, COL_INFO)) {
	/*
	 * Indicate what kind of message the first message is.
	 */
	frmtyp = tvb_get_guint8(tvb, 6) & ~RESPONSE_FLAGS;
	if (frmtyp >= SIZEOF (frame_type))
    	    col_set_str(pinfo->cinfo, COL_INFO, "- Invalid -");
	else
    	    col_set_str(pinfo->cinfo, COL_INFO, frame_type[frmtyp]);
    }

    if (tree) {
	offset = 0;
	while (tvb_reported_length_remaining(tvb, offset) > 0)
	    offset = dissect_gryphon_message(tvb, offset, gryphon_tree, FALSE);
    }
}

static int
dissect_gryphon_message(tvbuff_t *tvb, int offset, proto_tree *tree,
    gboolean is_msgresp_add)
{
    proto_tree	    *header_tree, *body_tree, *localTree;
    proto_item	    *header_item, *body_item, *localItem;
    int		    start_offset, msgend;
    int		    msglen, msgpad;
    unsigned int    src, dest, i, frmtyp;
    guint8	    flags;
    static const value_string src_dest[] = {
	    {SD_CARD,   	"Card"},
	    {SD_SERVER,     	"Server"},
	    {SD_CLIENT,		"Client"},
	    {SD_SCHED,		"Scheduler"},
	    {SD_SCRIPT,		"Script Processor"},
	    {SD_PGM,     	"Program Loader"},
	    {SD_USDT,     	"USDT Server"},
	    {SD_BLM,	    	"Bus Load Monitoring"},
	    {SD_FLIGHT,   	"Flight Recorder"},
	    {SD_RESP,     	"Message Responder"},
	    {-1,		"- unknown -"},
	    };

    src = tvb_get_guint8(tvb, offset + 0);
    dest = tvb_get_guint8(tvb, offset + 2);
    msglen = tvb_get_ntohs(tvb, offset + 4);
    flags = tvb_get_guint8(tvb, offset + 6);
    frmtyp = flags & ~RESPONSE_FLAGS;
    if (frmtyp >= SIZEOF (frame_type)) {
	/*
	 * Unknown message type.
	 */
	proto_tree_add_text(tree, tvb, offset, msglen, "Data");
	offset += msglen;
	return offset;
    }

    header_item = proto_tree_add_text(tree, tvb, offset, MSG_HDR_SZ, "Header");
    header_tree = proto_item_add_subtree(header_item, ett_gryphon_header);
    for (i = 0; i < SIZEOF(src_dest); i++) {
	if (src_dest[i].value == src)
	    break;
    }
    if (i >= SIZEOF(src_dest))
	i = SIZEOF(src_dest) - 1;
    proto_tree_add_text(header_tree, tvb, offset, 2,
	"Source: %s, channel %u", src_dest[i].strptr,
	tvb_get_guint8(tvb, offset + 1));
    proto_tree_add_uint_hidden(header_tree, hf_gryph_src, tvb,
	offset, 1, src);
    proto_tree_add_uint_hidden(header_tree, hf_gryph_srcchan, tvb,
	offset+1, 1, tvb_get_guint8(tvb, offset + 1));

    for (i = 0; i < SIZEOF(src_dest); i++) {
	if (src_dest[i].value == dest)
	    break;
    }
    if (i >= SIZEOF(src_dest))
	i = SIZEOF(src_dest) - 1;
    proto_tree_add_text(header_tree, tvb, offset+2, 2,
	"Destination: %s, channel %u", src_dest[i].strptr,
	tvb_get_guint8(tvb, offset + 3));
    proto_tree_add_uint_hidden(header_tree, hf_gryph_dest, tvb,
	offset+2, 1, dest);
    proto_tree_add_uint_hidden(header_tree, hf_gryph_destchan, tvb,
	offset+3, 1, tvb_get_guint8(tvb, offset + 3));

    proto_tree_add_text(header_tree, tvb, offset+4, 2,
	"Data length: %u bytes", msglen);
    proto_tree_add_text(header_tree, tvb, offset+6, 1,
	"Frame type: %s", frame_type[frmtyp]);
    if (is_msgresp_add) {
	localItem = proto_tree_add_text(header_tree, tvb, offset+6, 1, "Flags");
	localTree = proto_item_add_subtree (localItem, ett_gryphon_flags);
	if (flags & DONT_WAIT_FOR_RESP) {
	    proto_tree_add_text(localTree, tvb, offset+6, 1,
		    	    "1... .... = Don't wait for response");
	} else {
	    proto_tree_add_text(localTree, tvb, offset+6, 1,
		    	    "0... .... = Wait for response");
	}
	if (flags & WAIT_FOR_PREV_RESP) {
	    proto_tree_add_text(localTree, tvb, offset+6, 1,
		    	    ".1.. .... = Wait for previous responses");
	} else {
	    proto_tree_add_text(localTree, tvb, offset+6, 1,
		    	    ".0.. .... = Don't wait for previous responses");
	}
    }
    proto_tree_add_text(header_tree, tvb, offset+7, 1, "reserved");

    proto_tree_add_uint_hidden(header_tree, hf_gryph_type, tvb,
	offset+6, 1, frmtyp);
    msgpad = 3 - (msglen + 3) % 4;
    msgend = offset + msglen + msgpad + MSG_HDR_SZ;

    body_item = proto_tree_add_text(tree, tvb, offset + MSG_HDR_SZ,
	msglen + msgpad, "Body");
    body_tree = proto_item_add_subtree(body_item, ett_gryphon_body);

    start_offset = offset;
    offset += MSG_HDR_SZ;
    switch (frmtyp) {
    case GY_FT_CMD:
	offset = decode_command(tvb, offset, dest, msglen, body_tree);
	break;
    case GY_FT_RESP:
	offset = decode_response(tvb, offset, src, msglen, body_tree);
	break;
    case GY_FT_DATA:
	offset = decode_data(tvb, offset, src, msglen, body_tree);
	break;
    case GY_FT_EVENT:
	offset = decode_event(tvb, offset, src, msglen, body_tree);
	break;
    case GY_FT_MISC:
	break;
    case GY_FT_TEXT:
	break;
    default:
	break;
    }
    if (offset < msgend - msgpad) {
	i = msgend - msgpad - offset;
	proto_tree_add_text(tree, tvb, offset, i, "Data");
	offset += i;
    }
    if (offset < msgend) {
	i = msgend - offset;
	proto_tree_add_text(tree, tvb, offset, i, "padding");
	offset += i;
    }
    return offset;
}


static const val_str_dsp cmds[] = {
    	{CMD_INIT,	    	"Initialize", cmd_init, NULL},
        {CMD_GET_STAT,  	"Get status", NULL, NULL},
        {CMD_GET_CONFIG,	"Get configuration", NULL, resp_config},
        {CMD_EVENT_ENABLE,  	"Enable event", eventnum, NULL},
        {CMD_EVENT_DISABLE, 	"Disable event", eventnum, NULL},
	{CMD_GET_TIME,  	"Get time", NULL, resp_time},
	{CMD_GET_RXDROP,	"Get number of dropped RX messages", NULL, NULL},
	{CMD_RESET_RXDROP,  	"Clear number of dropped RX messages", NULL, NULL},
	{CMD_BCAST_ON,  	"Set broadcasts on", NULL, NULL},
	{CMD_BCAST_OFF, 	"Set broadcasts off", NULL, NULL},
	{CMD_CARD_SET_SPEED, 	"Set channel baud rate", speed, NULL},
	{CMD_CARD_GET_SPEED, 	"Get channel baud rate", NULL, speed},
	{CMD_CARD_SET_FILTER, 	"Set filter (deprecated)", cmd_setfilt, NULL},
	{CMD_CARD_GET_FILTER, 	"Get filter", resp_addfilt, cmd_addfilt},
	{CMD_CARD_TX,    	"Transmit message", decode_data, NULL},
	{CMD_CARD_TX_LOOP_ON, 	"Set transmit loopback on", NULL, NULL},
	{CMD_CARD_TX_LOOP_OFF,  "Set transmit loopback off", NULL, NULL},
	{CMD_CARD_IOCTL, 	"IOCTL pass-through", cmd_ioctl, NULL},
	{CMD_CARD_ADD_FILTER, 	"Add a filter", cmd_addfilt, resp_addfilt},
	{CMD_CARD_MODIFY_FILTER, "Modify a filter", cmd_modfilt, NULL},
	{CMD_CARD_GET_FILTER_HANDLES, "Get filter handles", NULL, resp_filthan},
	{CMD_CARD_SET_DEFAULT_FILTER, "Set default filter", dfiltmode, NULL},
	{CMD_CARD_GET_DEFAULT_FILTER, "Get default filter mode", NULL, dfiltmode},
	{CMD_CARD_SET_FILTER_MODE, "Set filter mode", filtmode, NULL},
	{CMD_CARD_GET_FILTER_MODE, "Get filter mode", NULL, filtmode},
	{CMD_CARD_GET_EVNAMES,	"Get event names", NULL, resp_events},
	{CMD_CARD_GET_SPEEDS,	"Get defined speeds", NULL, resp_getspeeds},
	{CMD_SERVER_REG, 	"Register with server", cmd_register, resp_register},
    	{CMD_SERVER_SET_SORT,	"Set the sorting behavior", cmd_sort, NULL},
    	{CMD_SERVER_SET_OPT,  	"Set the type of optimization", cmd_optimize, NULL},
	{CMD_BLM_SET_MODE,	"Set Bus Load Monitoring mode", blm_mode, NULL},
	{CMD_BLM_GET_MODE,	"Get Bus Load Monitoring mode", NULL, blm_mode},
	{CMD_BLM_GET_DATA,	"Get Bus Load data", NULL, resp_blm_data},
	{CMD_BLM_GET_STATS,	"Get Bus Load statistics", NULL, resp_blm_stat},
	{CMD_FLIGHT_GET_CONFIG, "Get flight recorder channel info", NULL, NULL},
	{CMD_FLIGHT_START_MON,  "Start flight recorder monitoring", NULL, NULL},
	{CMD_FLIGHT_STOP_MON, 	"Stop flight recorder monitoring", NULL, NULL},
	{CMD_MSGRESP_ADD,	"Add response message", cmd_addresp, resp_addresp},
	{CMD_MSGRESP_GET,	"Get response message", resp_addresp, cmd_addresp},
	{CMD_MSGRESP_MODIFY, 	"Modify response message state", cmd_modresp, NULL},
	{CMD_MSGRESP_GET_HANDLES, "Get response message handles", NULL, resp_resphan},
	{CMD_PGM_DESC,   	"Describe program to to uploaded", cmd_desc, resp_desc},
	{CMD_PGM_UPLOAD, 	"Upload a program to the Gryphon", cmd_upload, NULL},
	{CMD_PGM_DELETE, 	"Delete an uploaded program", cmd_delete, NULL},
	{CMD_PGM_LIST,   	"Get a list of uploaded programs", cmd_list, resp_list},
	{CMD_PGM_START,  	"Start an uploaded program", cmd_start, resp_start},
	{CMD_PGM_STOP,   	"Stop an uploaded program", resp_start, NULL},
	{CMD_PGM_STATUS, 	"Get status of an uploaded program", cmd_delete, resp_status},
	{CMD_PGM_OPTIONS, 	"Set program upload options", cmd_options, resp_status},
    	{CMD_PGM_FILES,     	"Get a list of files & directories", cmd_files, resp_files},
	{CMD_SCHED_TX,   	"Schedule transmission of messages", cmd_sched, resp_sched},
	{CMD_SCHED_KILL_TX,	"Stop and destroy a message transmission", NULL, NULL},
	{CMD_SCHED_STOP_TX,	"Kill a message transmission (deprecated)", NULL, NULL},
	{CMD_USDT_IOCTL,    	"Register/Unregister with USDT server", cmd_usdt, NULL},
	{-1,	    	    	"- unknown -", NULL, NULL},
        };

static const value_string responses[] = {
	{RESP_OK,		"OK - no error"},
	{RESP_UNKNOWN_ERR,	"Unknown error"},
	{RESP_UNKNOWN_CMD,	"Unrecognised command"},
	{RESP_UNSUPPORTED,	"Unsupported command"},
	{RESP_INVAL_CHAN,	"Invalid channel specified"},
	{RESP_INVAL_DST,	"Invalid destination"},
	{RESP_INVAL_PARAM,	"Invalid parameter(s)"},
	{RESP_INVAL_MSG,	"Invalid message"},
	{RESP_INVAL_LEN,	"Invalid length field"},
	{RESP_TX_FAIL,		"Transmit failed"},
	{RESP_RX_FAIL,		"Receive failed"},
	{RESP_AUTH_FAIL,	"Authorization failed"},
	{RESP_MEM_ALLOC_ERR,  	"Memory allocation error"},
	{RESP_TIMEOUT,	  	"Command timed out"},
	{RESP_UNAVAILABLE,	"Unavailable"},
	{RESP_BUF_FULL,		"Buffer full"},
	{RESP_NO_SUCH_JOB,	"No such job"},
	{-1,	    	    	"- unknown -"},
	};
	
static const value_string filter_data_types[] = {
	{FILTER_DATA_TYPE_HEADER_FRAME, "frame header"},
	{FILTER_DATA_TYPE_HEADER,   	"data message header"},
	{FILTER_DATA_TYPE_DATA,     	"data message data"},
	{FILTER_DATA_TYPE_EXTRA_DATA,	"data message extra data"},
	{FILTER_EVENT_TYPE_HEADER,  	"event message header"},
	{FILTER_EVENT_TYPE_DATA,    	"event message"},
	{-1,	    	    	    	"- unknown -"},
	};

static const value_string operators[] = {
	{BIT_FIELD_CHECK,    	"Bit field check"},
	{SVALUE_GT,  	    	"Greater than (signed)"},
	{SVALUE_GE,  	    	"Greater than or equal to (signed)"},
	{SVALUE_LT,  	    	"Less than (signed)"},
	{SVALUE_LE,  	    	"Less than or equal to (signed)"},
	{VALUE_EQ,   	    	"Equal to"},
	{VALUE_NE,   	    	"Not equal to"},
	{UVALUE_GT,  	    	"Greater than (unsigned)"},
	{UVALUE_GE,  	    	"Greater than or equal to (unsigned)"},
	{UVALUE_LT,  	    	"Less than (unsigned)"},
	{UVALUE_LE,  	    	"Less than or equal to (unsigned)"},
	{DIG_LOW_TO_HIGH,    	"Digital, low to high transistion"},
	{DIG_HIGH_TO_LOW,    	"Digital, high to low transistion"},
	{DIG_TRANSITION,     	"Digital, change of state"},
	{-1,	    	    	"- unknown -"},
	};

static const value_string modes[] = {
	{FILTER_OFF_PASS_ALL,	"Filter off, pass all messages"},
	{FILTER_OFF_BLOCK_ALL,	"Filter off, block all messages"},
	{FILTER_ON, 	    	"Filter on"},
	{-1,	    	    	"- unknown -"},
	};

static const value_string dmodes[] = {
	{DEFAULT_FILTER_BLOCK,	"Block"},
	{DEFAULT_FILTER_PASS,	"Pass"},
	{-1,	    	    	"- unknown -"},
	};

static const value_string filtacts[] = {
	{DELETE_FILTER,     	"Delete"},
	{ACTIVATE_FILTER,   	"Activate"},
	{DEACTIVATE_FILTER, 	"Deactivate"},
	{-1,	    	    	"- unknown -"},
	};

static const value_string ioctls[] = {
	{GINIT,     	    	"GINIT: Initialize"},
	{GLOOPON,   	    	"GLOOPON: Loop on"},
	{GLOOPOFF,  	    	"GLOOPOFF: Loop off"},
	{GGETHWTYPE,	    	"GGETHWTYPE: Get hardware type"},
	{GGETREG,   	    	"GGETREG: Get register"},
	{GSETREG,   	    	"GSETREG: Set register"},
	{GGETRXCOUNT,	    	"GGETRXCOUNT: Get the receive message counter"},
	{GSETRXCOUNT,	    	"GSETRXCOUNT: Set the receive message counter"},
	{GGETTXCOUNT,	    	"GGETTXCOUNT: Get the transmit message counter"},
	{GSETTXCOUNT,	    	"GSETTXCOUNT: Set the transmit message counter"},
	{GGETRXDROP, 	    	"GGETRXDROP: Get the number of dropped receive messages"},
	{GSETRXDROP,	    	"GSETRXDROP: Set the number of dropped receive messages"},
	{GGETTXDROP,	    	"GGETTXDROP: Get the number of dropped transmit messages"},
	{GSETTXDROP,	    	"GSETTXDROP: Set the number of dropped transmit messages"},
	{GGETRXBAD, 	    	"GGETRXBAD: Get the number of bad receive messages"},
	{GGETTXBAD, 	    	"GGETTXBAD: Get the number of bad transmit messages"},
	{GGETCOUNTS,	    	"GGETCOUNTS: Get total message counter"},
	{GGETBLMON, 	    	"GGETBLMON: Get bus load monitoring status"},
	{GSETBLMON, 	    	"GSETBLMON: Set bus load monitoring status (turn on/off)"},
	{GGETERRLEV,	    	"GGETERRLEV: Get error level"},
	{GSETERRLEV,	    	"GSETERRLEV: Set error level"},
	{GGETBITRATE,	    	"GGETBITRATE: Get bit rate"},
	{GGETRAM,   	    	"GGETRAM: Read value from RAM"},
	{GSETRAM,   	    	"GSETRAM: Write value to RAM"},
	{GCANGETBTRS,	    	"GCANGETBTRS: Read CAN bit timing registers"},
	{GCANSETBTRS,	    	"GCANSETBTRS: Write CAN bit timing registers"},
	{GCANGETBC, 	    	"GCANGETBC: Read CAN byte count"},
	{GCANSETBC, 	    	"GCANSETBC: Write CAN byte count"},
	{GCANGETMODE,	    	"GCANGETMODE"},
	{GCANSETMODE,	    	"GCANSETMODE"},
	{GCANGETTRANS,	    	"GCANGETTRANS"},
	{GCANSETTRANS,	    	"GCANSETTRANS"},
	{GCANSENDERR,	    	"GCANSENDERR"},
	{GCANRGETOBJ,	    	"GCANRGETOBJ"},
	{GCANRSETSTDID,     	"GCANRSETSTDID"},
	{GCANRSETEXTID,     	"GCANRSETEXTID"},
	{GCANRSETDATA,	    	"GCANRSETDATA"},
	{GCANRENABLE,	    	"GCANRENABLE"},
	{GCANRDISABLE,	    	"GCANRDISABLE"},
	{GCANRGETMASKS,     	"GCANRGETMASKS"},
	{GCANRSETMASKS,     	"GCANRSETMASKS"},
	{GCANSWGETMODE,     	"GCANSWGETMODE"},
	{GCANSWSETMODE,     	"GCANSWSETMODE"},
	{GDLCGETFOURX,	    	"GDLCGETFOURX"},
	{GDLCSETFOURX,	    	"GDLCSETFOURX"},
	{GDLCGETLOAD,	    	"GDLCGETLOAD"},
	{GDLCSETLOAD,	    	"GDLCSETLOAD"},
	{GDLCSENDBREAK,     	"GDLCSENDBREAK"},
	{GDLCABORTTX,	    	"GDLCABORTTX"},
	{GDLCGETHDRMODE,     	"DLCGETHDRMODE"},
	{GDLCSETHDRMODE,    	"GDLCSETHDRMODE"},
	{GHONSLEEP, 	    	"GHONSLEEP"},
	{GHONSILENCE,	    	"GHONSILENCE"},
	{GKWPSETPTIMES,     	"GKWPSETPTIMES"},
	{GKWPSETWTIMES,     	"GKWPSETWTIMES"},
	{GKWPDOWAKEUP,	    	"GKWPDOWAKEUP"},
	{GKWPGETBITTIME,    	"GKWPGETBITTIME"},
	{GKWPSETBITTIME,    	"GKWPSETBITTIME"},
	{GKWPSETNODEADDR,   	"GKWPSETNODEADDR"},
	{GKWPGETNODETYPE,   	"GKWPGETNODETYPE"},
	{GKWPSETNODETYPE,   	"GKWPSETNODETYPE"},
	{GKWPSETWAKETYPE,   	"GKWPSETWAKETYPE"},
	{GKWPSETTARGADDR,   	"GKWPSETTARGADDR"},
	{GKWPSETKEYBYTES,   	"GKWPSETKEYBYTES"},
	{GKWPSETSTARTREQ,   	"GKWPSETSTARTREQ"},
	{GKWPSETSTARTRESP,  	"GKWPSETSTARTRESP"},
	{GKWPSETPROTOCOL,   	"GKWPSETPROTOCOL"},
	{GKWPGETLASTKEYBYTES,	"GKWPGETLASTKEYBYTES"},
	{GKWPSETLASTKEYBYTES,	"GKWPSETLASTKEYBYTES"},
	{GSCPGETBBR,	    	"GSCPGETBBR"},
	{GSCPSETBBR, 	    	"GSCPSETBBR"},
	{GSCPGETID, 	    	"GSCPGETID"},
	{GSCPSETID, 	    	"GSCPSETID"},
	{GSCPADDFUNCID,     	"GSCPADDFUNCID"},
	{GSCPCLRFUNCID,     	"GSCPCLRFUNCID"},
	{GUBPGETBITRATE,    	"GUBPGETBITRATE"},
	{GUBPSETBITRATE,    	"GUBPSETBITRATE"},
	{GUBPGETINTERBYTE,  	"GUBPGETINTERBYTE"},
	{GUBPSETINTERBYTE,  	"GUBPSETINTERBYTE"},
	{GUBPGETNACKMODE,   	"GUBPGETNACKMODE"},
	{GUBPSETNACKMODE,   	"GUBPSETNACKMODE"},
	{-1, 	    	    	"- unknown -"},
	};


static int
decode_command(tvbuff_t *tvb, int offset, int dst, int msglen, proto_tree *pt)
{
    int     	    cmd, padding;
    unsigned int    i;
    proto_tree	    *ft;
    proto_item	    *ti;

    cmd = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint_hidden(pt, hf_gryph_cmd, tvb, offset, 1, cmd);
    if (cmd > 0x3F)
    	cmd += dst * 256;

    for (i = 0; i < SIZEOF(cmds); i++) {
    	if (cmds[i].value == cmd)
	    break;
    }
    if (i >= SIZEOF(cmds) && dst >= SD_KNOWN) {
    	cmd = (cmd & 0xFF) + SD_CARD * 256;
	for (i = 0; i < SIZEOF(cmds); i++) {
    	    if (cmds[i].value == cmd)
		break;
	}
    }
    if (i >= SIZEOF(cmds))
    	i = SIZEOF(cmds) - 1;

    proto_tree_add_text (pt, tvb, offset, 4, "Command: %s", cmds[i].strptr);
    offset += 4;
    msglen -= 4;

    if (cmds[i].cmd_fnct && msglen > 0) {
    	padding = 3 - (msglen + 3) % 4;
 	ti = proto_tree_add_text(pt, tvb, offset, msglen, "Data: (%d bytes)", msglen);
	ft = proto_item_add_subtree(ti, ett_gryphon_command_data);
	offset = (*(cmds[i].cmd_fnct)) (tvb, offset, dst, msglen, ft);
    }
    return offset;
}

static int
decode_response(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    int     	    cmd;
    unsigned int    i, j, resp;
    proto_tree	    *ft;
    proto_item	    *ti;

    cmd = tvb_get_guint8(tvb, offset);
    if (cmd > 0x3F)
    	cmd += src * 256;

    for (i = 0; i < SIZEOF(cmds); i++) {
    	if (cmds[i].value == cmd)
	    break;
    }
    if (i >= SIZEOF(cmds) && src >= SD_KNOWN) {
    	cmd = (cmd & 0xFF) + SD_CARD * 256;
	for (i = 0; i < SIZEOF(cmds); i++) {
    	    if (cmds[i].value == cmd)
		break;
	}
    }
    if (i >= SIZEOF(cmds))
    	i = SIZEOF(cmds) - 1;
    proto_tree_add_text (pt, tvb, offset, 4, "Command: %s", cmds[i].strptr);
    offset += 4;
    msglen -= 4;
    
    resp = tvb_get_ntohl (tvb, offset);
    for (j = 0; j < SIZEOF(responses); j++) {
    	if (responses[j].value == resp)
	    break;
    }
    if (j >= SIZEOF(responses))
    	j = SIZEOF(responses) - 1;
    proto_tree_add_text (pt, tvb, offset, 4, "Status: %s", responses[j].strptr);
    offset += 4;
    msglen -= 4;

    if (cmds[i].rsp_fnct && msglen > 0) {
	ti = proto_tree_add_text(pt, tvb, offset, msglen, "Data: (%d bytes)", msglen);
	ft = proto_item_add_subtree(ti, ett_gryphon_response_data);
	offset = (*(cmds[i].rsp_fnct)) (tvb, offset, src, msglen, ft);
    }
    return offset;
}

static int
decode_data(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_item	*item, *item1;
    proto_tree	*tree, *tree1;
    int     hdrsize, datasize, extrasize, hdrbits, msgsize, padding, mode;
    int     hours, minutes, seconds, fraction;
    unsigned long   timestamp;

    hdrsize = tvb_get_guint8(tvb, offset+0);
    hdrbits = tvb_get_guint8(tvb, offset+1);
    datasize = tvb_get_ntohs(tvb, offset+2);
    extrasize = tvb_get_guint8(tvb, offset+4);
    padding = 3 - (hdrsize + datasize + extrasize + 3) % 4;
    msgsize = hdrsize + datasize + extrasize + padding + 16;

    item = proto_tree_add_text(pt, tvb, offset, 16, "Message header");
    tree = proto_item_add_subtree (item, ett_gryphon_data_header);
    proto_tree_add_text(tree, tvb, offset, 2, "Header length: %d bytes, %d bits", hdrsize, hdrbits);
    proto_tree_add_text(tree, tvb, offset+2, 2, "Data length: %d bytes", datasize);
    proto_tree_add_text(tree, tvb, offset+4, 1, "Extra data length: %d bytes", extrasize);
    mode = tvb_get_guint8(tvb, offset+5);
    item1 = proto_tree_add_text(tree, tvb, offset+5, 1, "Mode: %d", mode);
    if (mode) {
	tree1 = proto_item_add_subtree (item1, ett_gryphon_flags);
	if (mode & 0x80)
	    proto_tree_add_text(tree1, tvb, offset+5, 1, "1... .... = Transmitted message");
	if (mode & 0x40)
	    proto_tree_add_text(tree1, tvb, offset+5, 1, ".1.. .... = Received message");
	if (mode & 0x20)
	    proto_tree_add_text(tree1, tvb, offset+5, 1, "..1. .... = Local message");
	if (mode & 0x10)
	    proto_tree_add_text(tree1, tvb, offset+5, 1, "...1 .... = Remote message");
	if (mode & 0x01)
	    proto_tree_add_text(tree1, tvb, offset+5, 1, ".... ...1 = Internal message");
    }
    proto_tree_add_text(tree, tvb, offset+6, 1, "Priority: %u",
	tvb_get_guint8(tvb, offset+6));
    proto_tree_add_text(tree, tvb, offset+7, 1, "Error status: %u",
	tvb_get_guint8(tvb, offset+7));
    timestamp = tvb_get_ntohl(tvb, offset+8);
    hours = timestamp /(100000 * 60 *60);
    minutes = (timestamp / (100000 * 60)) % 60;
    seconds = (timestamp / 100000) % 60;
    fraction = timestamp % 100000;
    proto_tree_add_text(tree, tvb, offset+8, 4, "Timestamp: %d:%02d:%02d.%05d", hours, minutes, seconds, fraction);
    proto_tree_add_text(tree, tvb, offset+12, 1, "Context: %u",
	tvb_get_guint8(tvb, offset+12));
    proto_tree_add_text(tree, tvb, offset+13, 3, "reserved:");
    offset += 16;
    item = proto_tree_add_text(pt, tvb, offset, msgsize-16-padding, "Message Body");
    tree = proto_item_add_subtree (item, ett_gryphon_data_body);
    if (hdrsize) {
	proto_tree_add_text(tree, tvb, offset, hdrsize, "Header");
	offset += hdrsize;
    }
    if (datasize) {
	proto_tree_add_text(tree, tvb, offset, datasize, "Data");
	offset += datasize;
    }
    if (extrasize) {
	proto_tree_add_text(tree, tvb, offset, extrasize, "Extra data");
	offset += extrasize;
    }
    if (padding) {
    	proto_tree_add_text(pt, tvb, offset, padding, "padding");
	offset += padding;
    }
    return offset;
}

static int
decode_event(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    int     	    hours, minutes, seconds, fraction, padding, length;
    unsigned long   timestamp;
    int		    msgend;

    padding = 3 - (msglen + 3) % 4;
    msgend = offset + msglen;
    proto_tree_add_text(pt, tvb, offset, 1, "Event ID: %u",
	tvb_get_guint8(tvb, offset));
    proto_tree_add_text(pt, tvb, offset+1, 1, "Event context: %u",
	tvb_get_guint8(tvb, offset+1));
    proto_tree_add_text(pt, tvb, offset+2, 2, "reserved");
    offset += 4;
    timestamp = tvb_get_ntohl(tvb, offset);
    hours = timestamp /(100000 * 60 *60);
    minutes = (timestamp / (100000 * 60)) % 60;
    seconds = (timestamp / 100000) % 60;
    fraction = timestamp % 100000;
    proto_tree_add_text(pt, tvb, offset, 4, "Timestamp: %d:%02d:%02d.%05d", hours, minutes, seconds, fraction);
    offset += 4;
    if (offset < msgend) {
    	length = msgend - offset;
    	proto_tree_add_text (pt, tvb, offset, length, "Data (%d bytes)", length);
	offset += length;
    }
    if (padding) {
    	proto_tree_add_text(pt, tvb, offset, padding, "padding");
	offset += padding;
    }
    return offset;
}

static int
cmd_init(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    char    	*ptr;
    
    if (tvb_get_guint8(tvb, offset) == 0)
    	ptr = "Always initialize";
    else
    	ptr = "Initialize if not previously initialized";
    proto_tree_add_text(pt, tvb, offset, 1, "Mode: %s", ptr);
    proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    return offset;
}

static int
eventnum(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    guint8	event = tvb_get_guint8(tvb, offset);
    
    if (event)
    	proto_tree_add_text(pt, tvb, offset, 1, "Event number: %u", event);
    else
    	proto_tree_add_text(pt, tvb, offset, 1, "Event numbers: All");
    proto_tree_add_text(pt, tvb, offset+1, 3, "padding");
    offset += 4;
    return offset;
}

static int
resp_time(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    int     hours, minutes, seconds, fraction;
    union {
    	unsigned int		lng[2];
	guint64			lnglng;
    } ts;
    unsigned int    timestamp;
    unsigned char   date[45];
   
    ts.lng[1] = tvb_get_ntohl(tvb, offset);
    ts.lng[0] = tvb_get_ntohl(tvb, offset + 4);
    timestamp = ts.lnglng / 100000L;
    strncpy (date, ctime((time_t*)&timestamp), sizeof(date));
    date[strlen(date)-1] = 0x00;
    proto_tree_add_text(pt, tvb, offset, 8, "Date/Time: %s", date);
    timestamp = ts.lng[0];
    hours = timestamp /(100000 * 60 *60);
    minutes = (timestamp / (100000 * 60)) % 60;
    seconds = (timestamp / 100000) % 60;
    fraction = timestamp % 100000;
    proto_tree_add_text(pt, tvb, offset+4, 4, "Timestamp: %d:%02d:%02d.%05d", hours, minutes, seconds, fraction);
    offset += 8;
    return offset;
}

static int
cmd_setfilt(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    int     	    flag = tvb_get_ntohl(tvb, offset);
    int     	    length, padding;
    unsigned char   mode[30];
    
    length =  tvb_get_guint8(tvb, offset+4) + tvb_get_guint8(tvb, offset+5)
	+ tvb_get_ntohs(tvb, offset+6);
    if (flag)
    	strcpy (mode, "Pass");
    else
    	strcpy (mode, "Block");
    if (length == 0)
    	strcat (mode, " all");
    proto_tree_add_text(pt, tvb, offset, 4, "Pass/Block flag: %s", mode);
    proto_tree_add_text(pt, tvb, offset+4, 4, "Length of Pattern & Mask: %d", length);
    offset += 8;
    if (length) {
	proto_tree_add_text(pt, tvb, offset, length * 2, "discarded data");
	offset += length * 2;
    }
    padding = 3 - (length * 2 + 3) % 4;
    if (padding) {
	proto_tree_add_text(pt, tvb, offset+1, 3, "padding");
	offset += padding;
    }
    return offset;
}

static int
cmd_ioctl(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    unsigned int    ioctl, i;

    ioctl = tvb_get_ntohl(tvb, offset);
    for (i = 0; i < SIZEOF(ioctls); i++) {
	if (ioctls[i].value == ioctl)
	    break;
    }
    if (i >= SIZEOF(ioctls))
	i = SIZEOF(ioctls) - 1;
    proto_tree_add_text(pt, tvb, offset, 4, "IOCTL: %s", ioctls[i].strptr);
    offset += 4;
    msglen -= 4;
    if (msglen > 0) {
	proto_tree_add_text(pt, tvb, offset, msglen, "Data");
	offset += msglen;
    }
    return offset;
}

static int
cmd_addfilt(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    guint8	flags;
    int     	blocks, i, length;
    char    	*ptr;
    char    	pass[] = ".... ...1 = Conforming messages are passed";
    char    	block[] = ".... ...0 = Conforming messages are blocked";
    char    	active[] = ".... ..1. = The filter is active";
    char    	inactive[] = ".... ..0. = The filter is inactive";

    item = proto_tree_add_text(pt, tvb, offset, 1, "Flags");
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    flags = tvb_get_guint8(tvb, offset);
    if (flags & FILTER_PASS_FLAG)
	ptr = pass;
    else
	ptr = block;
    proto_tree_add_text(tree, tvb, offset, 1, ptr);
    if (flags & FILTER_ACTIVE_FLAG)
	ptr = active;
    else
	ptr = inactive;
    proto_tree_add_text(tree, tvb, offset, 1, ptr);
    offset += 1;
    msglen -= 1;
    blocks = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(pt, tvb, offset, 1, "Number of filter blocks = %d", blocks);
    proto_tree_add_text(pt, tvb, offset+1, 6, "reserved");
    offset += 7;
    msglen -= 7;
    for (i = 1; i <= blocks; i++) {
	length = tvb_get_ntohs(tvb, offset+2) * 2 + 8;
	length += 3 - (length + 3) % 4;
	item = proto_tree_add_text(pt, tvb, offset, length, "Filter block %d", i);
	tree = proto_item_add_subtree (item, ett_gryphon_cmd_filter_block);
	offset = filter_block(tvb, offset, src, msglen, tree);
    }
    return offset;
}

static int
resp_addfilt(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 1, "Filter handle: %u",
	tvb_get_guint8(tvb, offset));
    proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    return offset;
}

static int
cmd_modfilt(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    guint8	    filter_handle;
    unsigned char   action, i;

    filter_handle = tvb_get_guint8(tvb, offset);
    if (filter_handle)
    	proto_tree_add_text(pt, tvb, offset, 1, "Filter handle: %u",
	    filter_handle);
    else
    	proto_tree_add_text(pt, tvb, offset, 1, "Filter handles: all");
    action = tvb_get_guint8(tvb, offset + 1);
    for (i = 0; i < SIZEOF(filtacts); i++) {
	if (filtacts[i].value == action)
	    break;
    }
    if (i >= SIZEOF(filtacts))
	i = SIZEOF(filtacts) - 1;
    proto_tree_add_text(pt, tvb, offset+1, 1, "Action: %s filter", filtacts[i].strptr);
    proto_tree_add_text(pt, tvb, offset+2, 2, "reserved");
    offset += 4;
    return offset;
}

static int
resp_filthan(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    int     	handles = tvb_get_guint8(tvb, offset);
    int     	i, padding;
    
    proto_tree_add_text(pt, tvb, offset, 1, "Number of filter handles: %d", handles);
    for (i = 1; i <= handles; i++){
	proto_tree_add_text(pt, tvb, offset+i, 1, "Handle %d: %u", i,
	    tvb_get_guint8(tvb, offset+i));
    }
    padding = 3 - (handles + 1 + 3) % 4;
    if (padding)
	proto_tree_add_text(pt, tvb, offset+1+handles, padding, "padding");
    offset += 1+handles+padding;
    return offset;
}

static int
dfiltmode(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    unsigned int    i;
    unsigned char   mode;
    
    mode = tvb_get_guint8(tvb, offset);
    for (i = 0; i < SIZEOF(modes); i++) {
	if (dmodes[i].value == mode)
	    break;
    }
    if (i >= SIZEOF(dmodes))
	i = SIZEOF(dmodes) - 1;
    proto_tree_add_text(pt, tvb, offset, 1, "Filter mode: %s", dmodes[i].strptr);
    proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    return offset;
}

static int
filtmode(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    unsigned int    i;
    unsigned char   mode;
    
    mode = tvb_get_guint8(tvb, offset);
    for (i = 0; i < SIZEOF(modes); i++) {
	if (modes[i].value == mode)
	    break;
    }
    if (i >= SIZEOF(modes))
	i = SIZEOF(modes) - 1;
    proto_tree_add_text(pt, tvb, offset, 1, "Filter mode: %s", modes[i].strptr);
    proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    return offset;
}

static int
resp_events(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    unsigned int    i;
    proto_tree	    *tree;
    proto_item	    *item;
    
    i = 1;
    while (msglen != 0) {
	item = proto_tree_add_text(pt, tvb, offset, 20, "Event %d:", i);
	tree = proto_item_add_subtree (item, ett_gryphon_cmd_events_data);
	proto_tree_add_text(tree, tvb, offset, 1, "Event ID: %u",
	    tvb_get_guint8(tvb, offset));
	proto_tree_add_text(tree, tvb, offset+1, 19, "Event name: %.19s",
		tvb_get_ptr(tvb, offset+1, 19));
	offset += 20;
	msglen -= 20;
	i++;
    }
    return offset;
}

static int
cmd_register(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 16, "Username: %.16s",
	tvb_get_ptr(tvb, offset, 16));
    offset += 16;
    proto_tree_add_text(pt, tvb, offset, 32, "Password: %.32s",
	tvb_get_ptr(tvb, offset, 32));
    offset += 32;
    return offset;
}

static int
resp_register(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 1, "Client ID: %u",
	tvb_get_guint8(tvb, offset));
    proto_tree_add_text(pt, tvb, offset+1, 1, "Privileges: %u",
	tvb_get_guint8(tvb, offset+1));
    proto_tree_add_text(pt, tvb, offset+2, 2, "reserved");
    offset += 4;
    return offset;
}


static int
resp_getspeeds(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    int size;
    int number;
    int index;
    
    proto_tree_add_text(pt, tvb, offset, 4, "Set Speed IOCTL");
    proto_tree_add_text(pt, tvb, offset+4, 4, "Get Speed IOCTL");
    size = tvb_get_guint8(tvb, offset+8);
    proto_tree_add_text(pt, tvb, offset+8, 1, "Speed data size is %d bytes", size);
    number = tvb_get_guint8(tvb, offset+9);
    proto_tree_add_text(pt, tvb, offset+9, 1, "There are %d preset speeds", number);
    offset += 10;
    for (index = 0; index < number; index++) {
	proto_tree_add_text(pt, tvb, offset, size, "Data for preset %d",
	    index+1);
	offset += size;
    }
    return offset;
}

static int
cmd_sort(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    char    	*which;
    
    which = tvb_get_guint8(tvb, offset) ?
	    "Sort into blocks of up to 16 messages" :
	    "Do not sort messages";
    proto_tree_add_text(pt, tvb, offset, 1, "Set sorting: %s", which);
    offset += 1;
    return offset;
}

static int
cmd_optimize(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    char    	*which;
    
    which = tvb_get_guint8(tvb, offset) ? 
	    "Optimize for latency (Nagle algorithm disabled)" :
	    "Optimize for throughput (Nagle algorithm enabled)";
    proto_tree_add_text(pt, tvb, offset, 1, "Set optimization: %s", which);
    offset += 1;
    return offset;
}

static int
resp_config(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_item	*ti;
    proto_tree	*ft;
    int     	devices;
    int     	i;
    unsigned int j, x;
    
    static const value_string protocol_types[] = {
	{GDUMMY * 256 + GDGDMARKONE,	"Dummy device driver"},
	{GCAN * 256 + G82527,	    	"CAN, 82527 subtype"},
	{GCAN * 256 + GSJA1000,     	"CAN, SJA1000 subtype"},
	{GCAN * 256 + G82527SW,     	"CAN, 82527 single wire subtype"},
	{GJ1850 * 256 + GHBCCPAIR,  	"J1850, HBCC subtype"},
	{GJ1850 * 256 + GDLC,	    	"J1850, GM DLC subtype"},
	{GJ1850 * 256 + GCHRYSLER,  	"J1850, Chrysler subtype"},
	{GJ1850 * 256 + GDEHC12,    	"J1850, DE HC12 KWP/BDLC subtype"},
	{GKWP2000 * 256 + GDEHC12KWP,  	"Keyword protocol 2000"},
	{GHONDA * 256 + GDGHC08,    	"Honda UART, DG HC08 subtype"},
	{GFORDUBP * 256 + GDGUBP08, 	"Ford UBP, DG HC08 subtype"},
	{-1,	    	    	    	"- unknown -"},
    };

    proto_tree_add_text(pt, tvb, offset, 20, "Device name: %.20s",
	tvb_get_ptr(tvb, offset, 20));
    offset += 20;

    proto_tree_add_text(pt, tvb, offset, 8, "Device version: %.8s",
	tvb_get_ptr(tvb, offset, 8));
    offset += 8;

    proto_tree_add_text(pt, tvb, offset, 20, "Device serial number: %.20s",
	tvb_get_ptr(tvb, offset, 20));
    offset += 20;

    devices = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(pt, tvb, offset, 1, "Number of channels: %d", devices);
    proto_tree_add_text(pt, tvb, offset+1, 15, "reserved");
    offset += 16;
    for (i = 1; i <= devices; i++) {
	ti = proto_tree_add_text(pt, tvb, offset, 80, "Channel %d:", i);
	ft = proto_item_add_subtree(ti, ett_gryphon_cmd_config_device);
	proto_tree_add_text(ft, tvb, offset, 20, "Driver name: %.20s",
	    tvb_get_ptr(tvb, offset, 20));
	offset += 20;

	proto_tree_add_text(ft, tvb, offset, 8, "Driver version: %.8s",
	    tvb_get_ptr(tvb, offset, 8));
	offset += 8;

	proto_tree_add_text(ft, tvb, offset, 24, "Device security string: %.24s",
	    tvb_get_ptr(tvb, offset, 24));
	offset += 24;

	proto_tree_add_text(ft, tvb, offset, 20, "Hardware serial number: %.20s",
	    tvb_get_ptr(tvb, offset, 20));
	offset += 20;

    	x = tvb_get_ntohs(tvb, offset);
	for (j = 0; j < SIZEOF(protocol_types); j++) {
	    if (protocol_types[j].value == x)
	    	break;
	}
	if (j >= SIZEOF(protocol_types))
	    j = SIZEOF(protocol_types) -1;
	proto_tree_add_text(ft, tvb, offset, 2, "Protocol type & subtype: %s", protocol_types[j].strptr);
	offset += 2;

	proto_tree_add_text(ft, tvb, offset, 1, "Channel ID: %u",
	    tvb_get_guint8(tvb, offset));
	proto_tree_add_text(ft, tvb, offset+1, 5, "reserved");
	offset += 6;
    }
    return offset;
}

static int
cmd_sched(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_item	    *item, *item1;
    proto_tree	    *tree, *tree1;
    int		    save_offset;
    unsigned int    i, x, length;
    unsigned char   def_chan = tvb_get_guint8(tvb, offset-9);
    char    	    *ptr;
    char    	    crit[] = ".... ...1 = Critical scheduler";
    char    	    norm[] = ".... ...0 = Normal scheduler";
    
    x = tvb_get_ntohl(tvb, offset);
    if (x == 0xFFFFFFFF)
    	proto_tree_add_text(pt, tvb, offset, 4, "Number of iterations: infinite");
    else
    	proto_tree_add_text(pt, tvb, offset, 4, "Number of iterations: %d", x);
    offset += 4;
    msglen -= 4;
    x = tvb_get_ntohl(tvb, offset);
    item = proto_tree_add_text(pt, tvb, offset, 4, "Flags");
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    ptr = x & 1 ? crit : norm;
    proto_tree_add_text(tree, tvb, offset, 4, ptr, NULL);
    offset += 4;
    msglen -= 4;
    i = 1;
    while (msglen > 0) {
    	length = 16 + tvb_get_guint8(tvb, offset+16) +
    	    tvb_get_ntohs(tvb, offset+18) + tvb_get_guint8(tvb, offset+20) + 16;
	length += 3 - (length + 3) % 4;
	item = proto_tree_add_text(pt, tvb, offset, length, "Message %d", i);
	tree = proto_item_add_subtree (item, ett_gryphon_cmd_sched_data);
	x = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Sleep: %d milliseconds", x);
	offset += 4;
	msglen -= 4;
	x = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Transmit count: %d", x);
	offset += 4;
	msglen -= 4;
	x = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Transmit period: %d milliseconds", x);
	offset += 4;
	msglen -= 4;
	proto_tree_add_text(tree, tvb, offset, 2, "reserved flags");
	x = tvb_get_guint8(tvb, offset+2);
	if (x == 0)
	    x = def_chan;
	proto_tree_add_text(tree, tvb, offset+2, 1, "Channel: %d", x);
	proto_tree_add_text(tree, tvb, offset+3, 1, "reserved");
	offset += 4;
	msglen -= 4;
	item1 = proto_tree_add_text(tree, tvb, offset, length, "Message");
	tree1 = proto_item_add_subtree (item1, ett_gryphon_cmd_sched_cmd);
	save_offset = offset;
	offset = decode_data(tvb, offset, msglen, src, tree1);
	msglen -= offset - save_offset;
	i++;
    }
    return offset;
}

static int
resp_blm_data(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    unsigned int    i;
    int             hours, minutes, seconds, fraction, x, fract;
    unsigned long   timestamp;
    char    *fields[] = {
    	"Bus load average: %d.%02d%%",
    	"Current bus load: %d.%02d%%",
    	"Peak bus load: %d.%02d%%",
    	"Historic peak bus load: %d.%02d%%"
    };

    timestamp = tvb_get_ntohl(tvb, offset);
    hours = timestamp /(100000 * 60 *60);
    minutes = (timestamp / (100000 * 60)) % 60;
    seconds = (timestamp / 100000) % 60;
    fraction = timestamp % 100000;
    proto_tree_add_text(pt, tvb, offset, 4, "Timestamp: %d:%02d:%02d.%05d", hours, minutes, seconds, fraction);
    offset += 4;
    for (i = 0; i < SIZEOF(fields); i++){
    	x = tvb_get_ntohs(tvb, offset);
	fract = x % 100;
	x /= 100;
	proto_tree_add_text(pt, tvb, offset, 2, fields[i], x, fract);
	offset += 2;
    }
    return offset;
}

static int
resp_blm_stat(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    unsigned int    x, i;
    char    	    *fields[] = {
    	"Receive frame count: %d",
    	"Transmit frame count: %d",
    	"Receive dropped frame count: %d",
    	"Transmit dropped frame count: %d",
    	"Receive error count: %d",
    	"Transmit error count: %d",
    };

    offset = resp_blm_data(tvb, offset, src, msglen, pt);
    for (i = 0; i < SIZEOF(fields); i++){
	x = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(pt, tvb, offset, 4, fields[i], x);
	offset += 4;
    }
    return offset;
}

static int
cmd_addresp(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    int     	blocks, responses, old_handle, i, length;
    int     	action, actionType, actionValue;
    char    	*ptr;
    char    	active[] = ".... ..1. = The response is active";
    char    	inactive[] = ".... ..0. = The response is inactive";

    actionType = 0;
    item = proto_tree_add_text(pt, tvb, offset, 1, "Flags");
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    if (tvb_get_guint8(tvb, offset) & FILTER_ACTIVE_FLAG)
    	ptr = active;
    else
    	ptr = inactive;
    proto_tree_add_text(tree, tvb, offset, 1, ptr, NULL);
    offset += 1;
    blocks = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(pt, tvb, offset, 1, "Number of filter blocks = %d", blocks);
    offset += 1;
    responses = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(pt, tvb, offset, 1, "Number of response blocks = %d", responses);
    offset += 1;
    old_handle = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(pt, tvb, offset, 1, "Old handle = %d", old_handle);
    offset += 1;
    action = tvb_get_guint8(tvb, offset);
    switch (action & 7) {
    case FR_RESP_AFTER_EVENT:
    	ptr = "Send response(s) for each conforming message";
    	break;
    case FR_RESP_AFTER_PERIOD:
    	ptr = "Send response(s) after the specified period expires following a conforming message";
    	break;
    case FR_IGNORE_DURING_PER:
    	ptr = "Send response(s) for a conforming message and ignore\nfurther messages until the specified period expires";
    	break;
    default:
    	ptr = "- unknown -";
    }
    item = proto_tree_add_text(pt, tvb, offset, 1, "Action = %s", ptr);
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    if (action & FR_DEACT_AFTER_PER && !(action & FR_DELETE)){
    	proto_tree_add_text(tree, tvb, offset, 1,
	    	"1.0. .... Deactivate this response after the specified period following a conforming message");
    }
    if (action & FR_DEACT_ON_EVENT && !(action & FR_DELETE)){
    	proto_tree_add_text(tree, tvb, offset, 1,
	    	".10. .... Deactivate this response for a conforming message");
    }
    if (action & FR_DEACT_AFTER_PER && action & FR_DELETE){
    	proto_tree_add_text(tree, tvb, offset, 1,
	    	"1.1. .... Delete this response after the specified period following a conforming message");
    }
    if (action & FR_DEACT_ON_EVENT && action & FR_DELETE){
    	proto_tree_add_text(tree, tvb, offset, 1,
	    	".11. .... Delete this response for a conforming message");
    }
    actionValue = tvb_get_ntohs(tvb, offset+2);
    if (actionValue) {
	if (action & FR_PERIOD_MSGS){
    	    ptr = "...1 .... The period is in frames";
	    actionType = 1;
	} else {
    	    ptr = "...0 .... The period is in 0.01 seconds";
	    actionType = 0;
	}
    	proto_tree_add_text(tree, tvb, offset, 1, ptr, NULL);
    }
    offset += 1;
    proto_tree_add_text(pt, tvb, offset, 1, "reserved");
    offset += 1;
    if (actionValue) {
    	if (actionType == 1) {
	    proto_tree_add_text(tree, tvb, offset, 2, "Period: %d messages", actionValue);
	} else {
	    proto_tree_add_text(tree, tvb, offset, 2, "Period: %d.%02d seconds", actionValue/100, actionValue%100);
	}
    }
    offset += 2;
    for (i = 1; i <= blocks; i++) {
	length = tvb_get_ntohs(tvb, offset+2) * 2 + 8;
	length += 3 - (length + 3) % 4;
	item = proto_tree_add_text(pt, tvb, offset, length, "Filter block %d", i);
	tree = proto_item_add_subtree (item, ett_gryphon_cmd_filter_block);
	offset = filter_block(tvb, offset, src, msglen, tree);
    }
    for (i = 1; i <= responses; i++) {
	length = tvb_get_ntohs(tvb, offset+4) + 8;
	length += 3 - (length + 3) % 4;
	item = proto_tree_add_text(pt, tvb, offset, length, "Response block %d", i);
	tree = proto_item_add_subtree (item, ett_gryphon_cmd_response_block);
	dissect_gryphon_message(tvb, offset, tree, TRUE);
	offset += length;
    }
    return offset;
}

static int
resp_addresp(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 1, "Response handle: %u",
	tvb_get_guint8(tvb, offset));
    proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    return offset;
}

static int
cmd_modresp(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    unsigned char   action;
    unsigned char   dest = tvb_get_guint8(tvb, offset-5);
    guint8	    resp_handle;
    unsigned int    i;

    resp_handle = tvb_get_guint8(tvb, offset);
    if (resp_handle)
	proto_tree_add_text(pt, tvb, offset, 1, "Response handle: %u",
	    resp_handle);
    else if (dest)
	proto_tree_add_text(pt, tvb, offset, 1, "Response handles: all on channel %hd", dest);
    else
    	proto_tree_add_text(pt, tvb, offset, 1, "Response handles: all");
    action = tvb_get_guint8(tvb, offset+1);
    for (i = 0; i < SIZEOF(filtacts); i++) {
	if (filtacts[i].value == action)
	    break;
    }
    if (i >= SIZEOF(filtacts))
	i = SIZEOF(filtacts) - 1;
    proto_tree_add_text(pt, tvb, offset+1, 1, "Action: %s response", filtacts[i].strptr);
    proto_tree_add_text(pt, tvb, offset+2, 2, "reserved");
    offset += 4;
    return offset;
}

static int
resp_resphan(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    int     	handles = tvb_get_guint8(tvb, offset);
    int     	i, padding;
    
    proto_tree_add_text(pt, tvb, offset, 1, "Number of response handles: %d", handles);
    for (i = 1; i <= handles; i++){
	proto_tree_add_text(pt, tvb, offset+i, 1, "Handle %d: %u", i,
	    tvb_get_guint8(tvb, offset+i));
    }
    padding = 3 - (handles + 1 + 3) % 4;
    if (padding)
	proto_tree_add_text(pt, tvb, offset+1+handles, padding, "padding");
    offset += 1+handles+padding;
    return offset;
}

static int
resp_sched(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    unsigned int    id = tvb_get_ntohl(tvb, offset);

    proto_tree_add_text(pt, tvb, offset, 4, "Transmit schedule ID: %u", id);
    offset += 4;
    return offset;
}

static int
cmd_desc(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 4, "Program size: %u bytes",
	tvb_get_ntohl(tvb, offset));
    offset += 4;
    proto_tree_add_text(pt, tvb, offset, 32, "Program name: %.32s",
	tvb_get_ptr(tvb, offset, 32));
    offset += 32;
    proto_tree_add_text(pt, tvb, offset, 80, "Program description: %.80s",
	tvb_get_ptr(tvb, offset, 80));
    offset += 80;
    return offset;
}

static int
resp_desc(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    char    	*ptr;
    char    	missing[] = ".... ...0 = The program is not present";
    char    	present[] = ".... ...1 = The program is already present";
    
    item = proto_tree_add_text(pt, tvb, offset, 1, "Flags");
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    if (tvb_get_guint8(tvb, offset) & 1)
    	ptr = present;
    else
    	ptr = missing;
    proto_tree_add_text(tree, tvb, offset, 1, ptr);
    proto_tree_add_text(pt, tvb, offset+1, 1, "Handle: %u",
	tvb_get_guint8(tvb, offset+1));
    proto_tree_add_text(pt, tvb, offset+2, 2, "reserved");
    offset += 4;
    return offset;
}

static int
cmd_upload(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    unsigned int    length;
    
    proto_tree_add_text(pt, tvb, offset, 2, "Block number: %u",
	tvb_get_ntohs(tvb, offset));
    offset += 4;
    msglen -= 4;
    proto_tree_add_text(pt, tvb, offset+2, 1, "Handle: %u",
	tvb_get_guint8(tvb, offset+2));
    offset += 3;
    msglen -= 3;
    length = msglen;
    proto_tree_add_text(pt, tvb, offset, length, "Data (%d bytes)", length);
    offset += length;
    length = 3 - (length + 3) % 4;
    if (length) {
	proto_tree_add_text(pt, tvb, offset, length, "padding");
	offset += length;
    }
    return offset;
}

static int
cmd_delete(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 32, "Program name: %.32s",
	tvb_get_ptr(tvb, offset, 32));
    offset += 32;
    return offset;
}

static int
cmd_list(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 1, "Block number: %u",
	tvb_get_guint8(tvb, offset));
    proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    return offset;
}

static int
resp_list(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    unsigned int    i, count;
    
    count = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(pt, tvb, offset, 1, "Number of programs in this response: %d", count);
    proto_tree_add_text(pt, tvb, offset+1, 1, "reserved");
    offset += 2;
    proto_tree_add_text(pt, tvb, offset, 2, "Number of remaining programs: %u",
	tvb_get_ntohs(tvb, offset));
    offset += 2;
    for (i = 1; i <= count; i++) {
	item = proto_tree_add_text(pt, tvb, offset, 112, "Program %d", i);
	tree = proto_item_add_subtree (item, ett_gryphon_pgm_list);
	proto_tree_add_text(tree, tvb, offset, 32, "Name: %.32s",
	    tvb_get_ptr(tvb, offset, 32));
	offset += 32;
	proto_tree_add_text(tree, tvb, offset, 80, "Description: %.80s",
	    tvb_get_ptr(tvb, offset, 80));
	offset += 80;
    }
    return offset;
}

static int
cmd_start(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    char	    string[120];
    gint	    length;
    
    offset = cmd_delete(tvb, offset, src, msglen, pt);
    length = tvb_get_nstringz0(tvb, offset, 120, string) + 1;
    proto_tree_add_text(pt, tvb, offset, length, "Arguments: %s", string);
    offset += length;
    length = 3 - (length + 3) % 4;
    if (length) {
	proto_tree_add_text(pt, tvb, offset, length, "padding");
	offset += length;
    }
    return offset;
}

static int
resp_start(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 1, "Channel (Client) number: %u",
	tvb_get_guint8(tvb, offset));
    proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    return offset;
}

static int
resp_status(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    unsigned int    i, copies, length;
    
    copies = tvb_get_guint8(tvb, offset);
    item = proto_tree_add_text(pt, tvb, offset, 1, "Number of running copies: %d", copies);
    tree = proto_item_add_subtree (item, ett_gryphon_pgm_status);
    offset += 1;
    if (copies) {
	for (i = 1; i <= copies; i++) {
	    proto_tree_add_text(tree, tvb, offset, 1, "Program %d channel (client) number %u",
		i, tvb_get_guint8(tvb, offset));
	    offset += 1;
	}
    }
    length = 3 - (copies + 1 + 3) % 4;
    if (length) {
	proto_tree_add_text(pt, tvb, offset, length, "padding");
	offset += length;
    }
    return offset;
}

static int
cmd_options(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    unsigned int    i, size, padding, option, option_length, option_value;
    unsigned char   *string, *string1;
    
    item = proto_tree_add_text(pt, tvb, offset, 1, "Handle: %u",
	tvb_get_guint8(tvb, offset));
    item = proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    msglen -= 4;
    for (i = 1; msglen > 0; i++) {
	option_length = tvb_get_guint8(tvb, offset+1);
    	size = option_length + 2;
	padding = 3 - ((size + 3) %4);
	item = proto_tree_add_text(pt, tvb, offset, size + padding, "Option number %d", i);
    	tree = proto_item_add_subtree (item, ett_gryphon_pgm_options);
	option = tvb_get_guint8(tvb, offset);
	switch (option_length) {
	case 1:
	    option_value = tvb_get_guint8(tvb, offset+2);
	    break;
	case 2:
	    option_value = tvb_get_ntohs(tvb, offset+2);
	    break;
	case 4:
	    option_value = tvb_get_ntohl(tvb, offset+2);
	    break;
	default:
	    option_value = 0;
	}
	string = "unknown option";
	string1 = "unknown option data";
	switch (option) {
	case PGM_CONV:
	    string = "Type of data in the file";
	    switch (option_value) {
	    case PGM_BIN:
	    	string1 = "Binary - Don't modify";
	    	break;
	    case PGM_ASCII:
	    	string1 = "ASCII - Remove CR's";
	    	break;
	    }
	    break;
	case PGM_TYPE:
	    string = "Type of file";
	    switch (option_value) {
	    case PGM_PGM:
	    	string1 = "Executable";
	    	break;
	    case PGM_DATA:
	    	string1 = "Data";
	    	break;
	    }
	    break;
	}
	proto_tree_add_text(tree, tvb, offset, 1, "%s", string);
	proto_tree_add_text(tree, tvb, offset+2, option_length, "%s", string1);
	if (padding)
	    proto_tree_add_text(tree, tvb, offset+option_length+2, padding, "padding");
	offset += size + padding;
	msglen -= size + padding;
    }
    return offset;
}

static int
cmd_files(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    u_char  *which;
    
    if (tvb_get_guint8(tvb, offset) == 0)
	which = "First group of names";
    else
	which = "Subsequent group of names";
    
    proto_tree_add_text(pt, tvb, offset, 1, "%s", which);
    proto_tree_add_text(pt, tvb, offset+1, msglen-1, "Directory: %.*s",
	msglen-1, tvb_get_ptr(tvb, offset+1, msglen-1));
    offset += msglen;
    return offset;
}

static int
resp_files(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    u_char  	*flag;
    
    flag = tvb_get_guint8(tvb, offset) ? "Yes": "No";
    proto_tree_add_text(pt, tvb, offset, 1, "More filenames to return: %s", flag);
    proto_tree_add_text(pt, tvb, offset+1, msglen-1, "File and directory names");
    offset += msglen;
    return offset;
}

static int
cmd_usdt(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    u_char  *desc;
    guint8  assemble_flag;
    
    if (tvb_get_guint8(tvb, offset))
	desc = "Register with gusdt";
    else
	desc = "Unregister with gusdt";
    proto_tree_add_text(pt, tvb, offset, 1, "%s", desc);
    
    if (tvb_get_guint8(tvb, offset+1))
	desc = "Echo long transmit messages back to the client";
    else
	desc = "Do not echo long transmit messages back to the client";
    proto_tree_add_text(pt, tvb, offset+1, 1, "%s", desc);
    
    assemble_flag = tvb_get_guint8(tvb, offset+2);
    if (assemble_flag == 2)
    	desc = "Assemble long received messages but do not send them to the client";
    else if (assemble_flag)
    	desc = "Assemble long received messages and send them to the client";
    else
    	desc = "Do not assemble long received messages on behalf of the client";
    proto_tree_add_text(pt, tvb, offset+2, 1, "%s", desc);
    
    offset += 4;
    return offset;
}

static int
speed(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 1, "Baud rate index: %u",
	tvb_get_guint8(tvb, offset));
    proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    return offset;
}

static int
filter_block(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    unsigned int    type, operator, i;
    int     length, padding;
    
    proto_tree_add_text(pt, tvb, offset, 2, "Filter field starts at byte %d",
	tvb_get_ntohs(tvb, offset));
    length = tvb_get_ntohs(tvb, offset+2);
    proto_tree_add_text(pt, tvb, offset+2, 2, "Filter field is %d bytes long", length);
    type = tvb_get_guint8(tvb, offset+4);
    for (i = 0; i < SIZEOF(filter_data_types); i++) {
	if (filter_data_types[i].value == type)
	    break;
    }
    if (i >= SIZEOF(filter_data_types))
	i = SIZEOF(filter_data_types) - 1;
    proto_tree_add_text(pt, tvb, offset+4, 1, "Filtering on %s", filter_data_types[i].strptr);

    operator = tvb_get_guint8(tvb, offset+5);
    for (i = 0; i < SIZEOF(operators); i++) {
	if (operators[i].value == operator)
	    break;
    }
    if (i >= SIZEOF(operators))
	i = SIZEOF(operators) - 1;
    proto_tree_add_text(pt, tvb, offset+5, 1, "Type of comparison: %s", operators[i].strptr);
    proto_tree_add_text(pt, tvb, offset+6, 2, "reserved");
    offset += 8;
    
    if (operator == BIT_FIELD_CHECK) {
	proto_tree_add_text(pt, tvb, offset, length, "Pattern");
	proto_tree_add_text(pt, tvb, offset+length, length, "Mask");
    } else {
	switch (length) {
	case 1:
	    proto_tree_add_text(pt, tvb, offset, 1, "Value: %u",
		tvb_get_guint8(tvb, offset));
	    break;
	case 2:
	    proto_tree_add_text(pt, tvb, offset, 2, "Value: %u",
		tvb_get_ntohs(tvb, offset));
	    break;
	case 4:
	    proto_tree_add_text(pt, tvb, offset, 4, "Value: %u",
		tvb_get_ntohl(tvb, offset));
	    break;
	default:
	    proto_tree_add_text(pt, tvb, offset, length, "Value");
	}
    }
    offset += length * 2;
    padding = 3 - (length * 2 + 3) % 4;
    if (padding) {
	proto_tree_add_text(pt, tvb, offset, padding, "padding");
	offset += padding;
    }
    return offset;
}

static int
blm_mode(tvbuff_t *tvb, int offset, int src, int msglen, proto_tree *pt)
{
    char    *mode, line[50];
    int     x, y, seconds;
    
    x = tvb_get_ntohl(tvb, offset);
    y = tvb_get_ntohl(tvb, offset+4);
    switch (x) {
    case 0:
    	mode = "Off";
	sprintf (line, "reserved");
    	break;
    case 1:
    	mode = "Average over time";
	seconds = y / 1000;
	y = y % 1000;
	sprintf (line, "Averaging period: %d.%03d seconds", seconds, y);
    	break;
    case 2:
    	mode = "Average over frame count";
	sprintf (line, "Averaging period: %d frames", y);
    	break;
    default:
    	mode = "- unknown -";
	sprintf (line, "reserved");
    }
    proto_tree_add_text(pt, tvb, offset, 4, "Mode: %s", mode);
    offset += 4;
    proto_tree_add_text(pt, tvb, offset, 4, line, NULL);
    offset += 4;
    return offset;
}

void
proto_register_gryphon(void)
{
    static hf_register_info hf[] = {
	{ &hf_gryph_src,
	{ "Source",           "gryph.src", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	"", HFILL }},
	{ &hf_gryph_srcchan,
	{ "Source channel",   "gryph.srcchan", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	"", HFILL }},
	{ &hf_gryph_dest,
	{ "Destination",      "gryph.dest", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	"", HFILL }},
	{ &hf_gryph_destchan,
	{ "Destination channel", "gryph.dstchan", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	"", HFILL }},
	{ &hf_gryph_type,
	{ "Frame type",       "gryph.type", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	"", HFILL }},
	{ &hf_gryph_cmd,
	{ "Command",          "gryph.cmd.cmd", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	"", HFILL }},
    };

    static gint *ett[] = {
	&ett_gryphon,
	&ett_gryphon_header,
	&ett_gryphon_body,
	&ett_gryphon_command_data,
	&ett_gryphon_response_data,
	&ett_gryphon_data_header,
	&ett_gryphon_flags,
	&ett_gryphon_data_body,
	&ett_gryphon_cmd_filter_block,
	&ett_gryphon_cmd_events_data,
	&ett_gryphon_cmd_config_device,
	&ett_gryphon_cmd_sched_data,
	&ett_gryphon_cmd_sched_cmd,
	&ett_gryphon_cmd_response_block,
	&ett_gryphon_pgm_list,
	&ett_gryphon_pgm_status,
	&ett_gryphon_pgm_options,
    };
    proto_gryphon = proto_register_protocol("DG Gryphon Protocol",
					    "Gryphon",
					    "gryphon");
    proto_register_field_array(proto_gryphon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_gryphon(void)
{
    dissector_handle_t gryphon_handle;

    gryphon_handle = create_dissector_handle(dissect_gryphon, proto_gryphon);
    dissector_add("tcp.port", 7000, gryphon_handle);
}

/* Start the functions we need for the plugin stuff */
G_MODULE_EXPORT void
plugin_reg_handoff(void){
  proto_reg_handoff_gryphon();
}

G_MODULE_EXPORT void
plugin_init(plugin_address_table_t *pat){
  /* initialise the table of pointers needed in Win32 DLLs */
  plugin_address_table_init(pat);
  /* register the new protocol, protocol fields, and subtrees */
  if (proto_gryphon == -1) { /* execute protocol initialization only once */
    proto_register_gryphon();
  }
}
/* End the functions we need for plugin stuff */
