/* packet-gryphon.c
 * Routines for Gryphon protocol packet disassembly
 * By Steve Limkemann <stevelim@dgtech.com>
 * Copyright 1998 Steve Limkemann
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-gryphon.h"
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>

/*
 * See
 *
 *	http://www.dgtech.com/gryphon/sys/www/docs/html/
 */

static int proto_gryphon = -1;

static int hf_gryphon_src = -1;
static int hf_gryphon_srcchan = -1;
static int hf_gryphon_dest = -1;
static int hf_gryphon_destchan= -1;
static int hf_gryphon_type = -1;
static int hf_gryphon_cmd = -1;

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
static gint ett_gryphon_valid_headers = -1;
static gint ett_gryphon_usdt_data = -1;
static gint ett_gryphon_digital_data = -1;

/* desegmentation of Gryphon */
static gboolean gryphon_desegment = TRUE;

static void dissect_gryphon_message(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, gboolean is_msgresp_add);
static int decode_command(tvbuff_t*, int, int, proto_tree*);
static int decode_response(tvbuff_t*, int, int, proto_tree*);
static int decode_data(tvbuff_t*, int, proto_tree*);
static int decode_event(tvbuff_t*, int, proto_tree*);
static int decode_misc(tvbuff_t*, int, proto_tree*);
static int cmd_init(tvbuff_t*, int, proto_tree*);
static int resp_time(tvbuff_t*, int, proto_tree*);
static int cmd_setfilt(tvbuff_t*, int, proto_tree*);
static int cmd_ioctl(tvbuff_t*, int, proto_tree*);
static int cmd_addfilt(tvbuff_t*, int, proto_tree*);
static int resp_addfilt(tvbuff_t*, int, proto_tree*);
static int cmd_modfilt(tvbuff_t*, int, proto_tree*);
static int resp_filthan(tvbuff_t*, int, proto_tree*);
static int dfiltmode(tvbuff_t*, int, proto_tree*);
static int filtmode(tvbuff_t*, int, proto_tree*);
static int resp_events(tvbuff_t*, int, proto_tree*);
static int cmd_register(tvbuff_t*, int, proto_tree*);
static int resp_register(tvbuff_t*, int, proto_tree*);
static int resp_getspeeds(tvbuff_t*, int, proto_tree*);
static int cmd_sort(tvbuff_t*, int, proto_tree*);
static int cmd_optimize(tvbuff_t*, int, proto_tree*);
static int resp_config(tvbuff_t*, int, proto_tree*);
static int cmd_sched(tvbuff_t*, int, proto_tree*);
static int cmd_sched_rep(tvbuff_t*, int, proto_tree*);
static int resp_blm_data(tvbuff_t*, int, proto_tree*);
static int resp_blm_stat(tvbuff_t*, int, proto_tree*);
static int cmd_addresp(tvbuff_t*, int, proto_tree*);
static int resp_addresp(tvbuff_t*, int, proto_tree*);
static int cmd_modresp(tvbuff_t*, int, proto_tree*);
static int resp_resphan(tvbuff_t*, int, proto_tree*);
static int resp_sched(tvbuff_t*, int, proto_tree*);
static int cmd_desc(tvbuff_t*, int, proto_tree*);
static int resp_desc(tvbuff_t*, int, proto_tree*);
static int cmd_upload(tvbuff_t*, int, proto_tree*);
static int cmd_delete(tvbuff_t*, int, proto_tree*);
static int cmd_list(tvbuff_t*, int, proto_tree*);
static int resp_list(tvbuff_t*, int, proto_tree*);
static int cmd_start(tvbuff_t*, int, proto_tree*);
static int resp_start(tvbuff_t*, int, proto_tree*);
static int resp_status(tvbuff_t*, int, proto_tree*);
static int cmd_options(tvbuff_t*, int, proto_tree*);
static int cmd_files(tvbuff_t*, int, proto_tree*);
static int resp_files(tvbuff_t*, int, proto_tree*);
static int eventnum(tvbuff_t*, int, proto_tree*);
static int speed(tvbuff_t*, int, proto_tree*);
static int filter_block(tvbuff_t*, int, proto_tree*);
static int blm_mode(tvbuff_t*, int, proto_tree*);
static int cmd_usdt(tvbuff_t*, int, proto_tree*);
static int cmd_bits_in(tvbuff_t*, int, proto_tree*);
static int cmd_bits_out(tvbuff_t*, int, proto_tree*);
static int cmd_init_strat(tvbuff_t*, int, proto_tree*);

static const char *frame_type[] = {
	"",
	"Command request",
	"Command response",
	"Network (vehicle) data",
	"Event",
	"Miscellaneous",
	"Text string"
};

/*
 * Length of the frame header.
 */
#define FRAME_HEADER_LEN	8

static guint
get_gryphon_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    guint16 plen;
    int padded_len;

    /*
     * Get the length of the Gryphon packet, and then get the length as
     * padded to a 4-byte boundary.
     */
    plen = tvb_get_ntohs(tvb, offset + 4);
    padded_len = plen + 3 - (plen + 3) % 4;

    /*
     * That length doesn't include the fixed-length part of the header;
     * add that in.
     */
    return padded_len + FRAME_HEADER_LEN;
}

static void
dissect_gryphon_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_gryphon_message(tvb, pinfo, tree, FALSE);
}

static void
dissect_gryphon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tcp_dissect_pdus(tvb, pinfo, tree, gryphon_desegment, FRAME_HEADER_LEN,
	get_gryphon_pdu_len, dissect_gryphon_pdu);
}

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
    {SD_IOPWR,          "I/O and power"},
    {SD_UTIL,           "Utility/Miscellaneous"},
    {0,			NULL}
};

static void
dissect_gryphon_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean is_msgresp_add)
{
    int		    offset = 0;
    proto_tree	    *gryphon_tree;
    proto_item	    *ti;
    proto_tree	    *header_tree, *body_tree, *localTree;
    proto_item	    *header_item, *body_item, *localItem, *hiddenItem;
    int		    start_offset, msgend;
    int		    msglen, msgpad;
    unsigned int    src, dest, i, frmtyp;
    guint8	    flags;

    if (!is_msgresp_add) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Gryphon");
	col_clear(pinfo->cinfo, COL_INFO);
    }

    if (!is_msgresp_add) {
	ti = proto_tree_add_item(tree, proto_gryphon, tvb, 0, -1, FALSE);
	gryphon_tree = proto_item_add_subtree(ti, ett_gryphon);
    } else
    	gryphon_tree = tree;

    src = tvb_get_guint8(tvb, offset + 0);
    dest = tvb_get_guint8(tvb, offset + 2);
    msglen = tvb_get_ntohs(tvb, offset + 4);
    flags = tvb_get_guint8(tvb, offset + 6);
    frmtyp = flags & ~RESPONSE_FLAGS;

    if (!is_msgresp_add) {
		/*
		 * This tvbuff includes padding to make its length a multiple
		 * of 4 bytes; set it to the actual length.
		 */
		set_actual_length(tvb, msglen + FRAME_HEADER_LEN);

	    /*
	     * Indicate what kind of message this is.
	     */
	    if (frmtyp >= SIZEOF (frame_type))
			col_set_str(pinfo->cinfo, COL_INFO, "- Invalid -");
	    else
			col_set_str(pinfo->cinfo, COL_INFO, frame_type[frmtyp]);
    }

    if (tree == NULL)
	return;

    if (frmtyp >= SIZEOF (frame_type)) {
	/*
	 * Unknown message type.
	 */
	proto_tree_add_text(gryphon_tree, tvb, offset, msglen, "Data");
	return;
    }

    header_item = proto_tree_add_text(gryphon_tree, tvb, offset, MSG_HDR_SZ, "Header");
    header_tree = proto_item_add_subtree(header_item, ett_gryphon_header);
    proto_tree_add_text(header_tree, tvb, offset, 2,
	"Source: %s, channel %u",
	val_to_str(src, src_dest, "Unknown (0x%02x)"),
	tvb_get_guint8(tvb, offset + 1));

	hiddenItem = proto_tree_add_uint(header_tree, hf_gryphon_src, tvb,
	offset, 1, src);
	PROTO_ITEM_SET_HIDDEN(hiddenItem);

	hiddenItem = proto_tree_add_uint(header_tree, hf_gryphon_srcchan, tvb,
	offset+1, 1, tvb_get_guint8(tvb, offset + 1));
	PROTO_ITEM_SET_HIDDEN(hiddenItem);

    proto_tree_add_text(header_tree, tvb, offset+2, 2,
	"Destination: %s, channel %u",
	val_to_str(dest, src_dest, "Unknown (0x%02x)"),
	tvb_get_guint8(tvb, offset + 3));

	hiddenItem = proto_tree_add_uint(header_tree, hf_gryphon_dest, tvb,
	offset+2, 1, dest);
	PROTO_ITEM_SET_HIDDEN(hiddenItem);

    hiddenItem = proto_tree_add_uint(header_tree, hf_gryphon_destchan, tvb,
	offset+3, 1, tvb_get_guint8(tvb, offset + 3));
	PROTO_ITEM_SET_HIDDEN(hiddenItem);

    proto_tree_add_text(header_tree, tvb, offset+4, 2,
	"Data length: %u byte%s", msglen, msglen == 1 ? "" : "s");
    proto_tree_add_text(header_tree, tvb, offset+6, 1,
	"Frame type: %s", frame_type[frmtyp]);

	if (is_msgresp_add) {
	localItem = proto_tree_add_text(header_tree, tvb, offset+6, 1, "Flags");
	localTree = proto_item_add_subtree (localItem, ett_gryphon_flags);
	proto_tree_add_text(localTree, tvb, offset+6, 1, "%s",
	    decode_boolean_bitfield(flags, DONT_WAIT_FOR_RESP, 8,
		"Don't wait for response",
		"Wait for response"));
	proto_tree_add_text(localTree, tvb, offset+6, 1, "%s",
	    decode_boolean_bitfield(flags, WAIT_FOR_PREV_RESP, 8,
		"Wait for previous responses",
		"Don't wait for previous responses"));
    }
    proto_tree_add_text(header_tree, tvb, offset+7, 1, "reserved");

    hiddenItem = proto_tree_add_uint(header_tree, hf_gryphon_type, tvb,
	offset+6, 1, frmtyp);
	PROTO_ITEM_SET_HIDDEN(hiddenItem);

    msgpad = 3 - (msglen + 3) % 4;
    msgend = offset + msglen + msgpad + MSG_HDR_SZ;

    body_item = proto_tree_add_text(gryphon_tree, tvb, offset + MSG_HDR_SZ,
	msglen + msgpad, "Body");
    body_tree = proto_item_add_subtree(body_item, ett_gryphon_body);

    start_offset = offset;
    offset += MSG_HDR_SZ;
    switch (frmtyp) {
    case GY_FT_CMD:
	offset = decode_command(tvb, offset, dest, body_tree);
	break;
    case GY_FT_RESP:
	offset = decode_response(tvb, offset, src, body_tree);
	break;
    case GY_FT_DATA:
	offset = decode_data(tvb, offset, body_tree);
	break;
    case GY_FT_EVENT:
	offset = decode_event(tvb, offset, body_tree);
	break;
    case GY_FT_MISC:
	offset = decode_misc (tvb, offset, body_tree);
	break;
    case GY_FT_TEXT:
	break;
    default:
	break;
    }
    if (offset < msgend - msgpad) {
	i = msgend - msgpad - offset;
	proto_tree_add_text(gryphon_tree, tvb, offset, i, "Data");
	offset += i;
    }
    if (offset < msgend) {
	i = msgend - offset;
	proto_tree_add_text(gryphon_tree, tvb, offset, i, "padding");
	offset += i;
    }
}


static const val_str_dsp cmds[] = {
	{CMD_INIT,	    	"Initialize", cmd_init, NULL},
	{CMD_GET_STAT,  	"Get status", NULL, NULL},
	{CMD_GET_CONFIG,	"Get configuration", NULL, resp_config},
	{CMD_EVENT_ENABLE,  	"Enable event", eventnum, NULL},
	{CMD_EVENT_DISABLE, 	"Disable event", eventnum, NULL},
	{CMD_GET_TIME,  	"Get time", NULL, resp_time},
	{CMD_SET_TIME,  	"Set time", resp_time, NULL},
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
	{CMD_PGM_START2,	"Start an uploaded program", NULL, resp_start},
	{CMD_PGM_STOP,   	"Stop an uploaded program", resp_start, NULL},
	{CMD_PGM_STATUS, 	"Get status of an uploaded program", cmd_delete, resp_status},
	{CMD_PGM_OPTIONS, 	"Set program upload options", cmd_options, resp_status},
	{CMD_PGM_FILES,     	"Get a list of files & directories", cmd_files, resp_files},
	{CMD_SCHED_TX,   	"Schedule transmission of messages", cmd_sched, resp_sched},
	{CMD_SCHED_KILL_TX,	"Stop and destroy a message transmission", resp_sched, NULL},
	{CMD_SCHED_STOP_TX,	"Kill a message transmission (deprecated)", resp_sched, NULL},
        {CMD_SCHED_MSG_REPLACE, "Replace a scheduled message", cmd_sched_rep, NULL},
	{CMD_USDT_IOCTL,    	"Register/Unregister with USDT server", cmd_usdt, NULL},
	{CMD_USDT_REGISTER,    	"Register/Unregister with USDT server", cmd_usdt, NULL},
        {CMD_USDT_SET_FUNCTIONAL, "Set IDs to use extended addressing", cmd_usdt, NULL},
        {CMD_IOPWR_GETINP,      "Read current digital inputs", NULL, cmd_bits_in},
        {CMD_IOPWR_GETLATCH,    "Read latched digital inputs", NULL, cmd_bits_in},
        {CMD_IOPWR_CLRLATCH,    "Read & clear latched digital inputs", cmd_bits_in, cmd_bits_in},
        {CMD_IOPWR_GETOUT,      "Read digital outputs", NULL, cmd_bits_out},
        {CMD_IOPWR_SETOUT,      "Write digital outputs", cmd_bits_out, NULL},
        {CMD_IOPWR_SETBIT,      "Set indicated output bits", cmd_bits_out, NULL},
        {CMD_IOPWR_CLRBIT,      "Clear indicated output bits", cmd_bits_out, NULL},
        {CMD_IOPWR_GETPOWER,    "Read digital inputs at power on time", NULL, cmd_bits_in},
        {CMD_UTIL_SET_INIT_STRATEGY, "Set initialization strategy", cmd_init_strat, NULL},
        {CMD_UTIL_GET_INIT_STRATEGY, "Get initialization strategy", NULL, cmd_init_strat},
	{-1,	    	    	"- unknown -", NULL, NULL},
	};

static const value_string responses_vs[] = {
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
	{0,	    	    	NULL},
	};

static const value_string filter_data_types[] = {
	{FILTER_DATA_TYPE_HEADER_FRAME, "frame header"},
	{FILTER_DATA_TYPE_HEADER,   	"data message header"},
	{FILTER_DATA_TYPE_DATA,     	"data message data"},
	{FILTER_DATA_TYPE_EXTRA_DATA,	"data message extra data"},
	{FILTER_EVENT_TYPE_HEADER,  	"event message header"},
	{FILTER_EVENT_TYPE_DATA,    	"event message"},
	{0,	    	    	    	NULL},
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
	{0,	    	    	NULL},
	};

static const value_string modes[] = {
	{FILTER_OFF_PASS_ALL,	"Filter off, pass all messages"},
	{FILTER_OFF_BLOCK_ALL,	"Filter off, block all messages"},
	{FILTER_ON, 	    	"Filter on"},
	{0,	    	    	NULL},
	};

static const value_string dmodes[] = {
	{DEFAULT_FILTER_BLOCK,	"Block"},
	{DEFAULT_FILTER_PASS,	"Pass"},
	{0,	    	    	NULL},
	};

static const value_string filtacts[] = {
	{DELETE_FILTER,     	"Delete"},
	{ACTIVATE_FILTER,   	"Activate"},
	{DEACTIVATE_FILTER, 	"Deactivate"},
	{0,	    	    	NULL},
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
	{GCANGETBC, 	    	"GCANGETBC: Read CAN bus configuration register"},
	{GCANSETBC, 	    	"GCANSETBC: Write CAN bus configuration register"},
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
        {GUBPGETRETRYDELAY,	"GUBPGETRETRYDELAY"},
        {GUBPSETRETRYDELAY,	"GUBPSETRETRYDELAY"},
        {GRESETHC08,            "GRESETHC08: Reset the HC08 processor"},
        {GTESTHC08COP,          "GTESTHC08COP: Stop updating the HC08 watchdog timer"},
        {GSJAGETLISTEN,         "GSJAGETLISTEN"},
        {GSJASETLISTEN,         "GSJASETLISTEN"},
        {GSJAGETSELFTEST,       "GSJAGETSELFTEST"},
        {GSJASETSELFTEST,       "GSJASETSELFTEST"},
        {GSJAGETXMITONCE,       "GSJAGETXMITONCE"},
        {GSJASETXMITONCE,       "GSJASETXMITONCE"},
        {GSJAGETTRIGSTATE,      "GSJAGETTRIGSTATE"},
        {GSJASETTRIGCTRL,       "GSJASETTRIGCTRL"},
        {GSJAGETTRIGCTRL,       "GSJAGETTRIGCTRL"},
        {GSJAGETOUTSTATE,       "GSJAGETOUTSTATE"},
        {GSJASETOUTSTATE,       "GSJASETOUTSTATE"},
        {GSJAGETFILTER,         "GSJAGETFILTER"},
        {GSJASETFILTER,         "GSJASETFILTER"},
        {GSJAGETMASK,           "GSJAGETMASK"},
        {GSJASETMASK,           "GSJASETMASK"},
        {GSJAGETINTTERM,        "GSJAGETINTTERM"},
        {GSJASETINTTERM,        "GSJASETINTTERM"},
        {GSJAGETFTTRANS,        "GSJAGETFTTRANS"},
        {GSJASETFTTRANS,        "GSJASETFTTRANS"},
        {GSJAGETFTERROR,        "GSJAGETFTERROR"},
        {GLINGETBITRATE,        "GLINGETBITRATE: Get the current bit rate"},
        {GLINSETBITRATE,        "GLINSETBITRATE: Set the bit rate"},
        {GLINGETBRKSPACE,       "GLINGETBRKSPACE"},
        {GLINSETBRKSPACE,       "GLINSETBRKSPACE"},
        {GLINGETBRKMARK,        "GLINGETBRKMARK"},
        {GLINSETBRKMARK,        "GLINSETBRKMARK"},
        {GLINGETIDDELAY,        "GLINGETIDDELAY"},
        {GLINSETIDDELAY,        "GLINSETIDDELAY"},
        {GLINGETRESPDELAY,      "GLINGETRESPDELAY"},
        {GLINSETRESPDELAY,      "GLINSETRESPDELAY"},
        {GLINGETINTERBYTE,      "GLINGETINTERBYTE"},
        {GLINSETINTERBYTE,      "GLINSETINTERBYTE"},
        {GLINGETWAKEUPDELAY,    "GLINGETWAKEUPDELAY"},
        {GLINSETWAKEUPDELAY,    "GLINSETWAKEUPDELAY"},
        {GLINGETWAKEUPTIMEOUT,  "GLINGETWAKEUPTIMEOUT"},
        {GLINSETWAKEUPTIMEOUT,  "GLINSETWAKEUPTIMEOUT"},
        {GLINGETWUTIMOUT3BR,    "GLINGETWUTIMOUT3BR"},
        {GLINSETWUTIMOUT3BR,    "GLINSETWUTIMOUT3BR"},
        {GLINSENDWAKEUP,        "GLINSENDWAKEUP"},
        {GLINGETMODE,           "GLINGETMODE"},
        {GLINSETMODE,           "GLINSETMODE"},
        {GINPGETINP,            "GINPGETINP: Read current digital inputs"},
        {GINPGETLATCH,          "GINPGETLATCH: Read latched digital inputs"},
        {GINPCLRLATCH,          "GINPCLRLATCH: Read and clear latched digital inputs"},
        {GOUTGET,               "GOUTGET: Read digital outputs"},
        {GOUTSET,               "GOUTSET: Write digital outputs"},
        {GOUTSETBIT,            "GOUTSETBIT: Set digital output bits"},
        {GOUTCLEARBIT,          "GOUTCLEARBIT"},
        {GPWRGETWHICH,          "GPWRGETWHICH"},
        {GPWROFF,               "GPWROFF"},
        {GPWROFFRESET,          "GPWROFFRESET"},
        {GPWRRESET,             "GPWRRESET"},



	{0, 	    	    	NULL},
	};


static int
decode_command(tvbuff_t *tvb, int offset, int dst, proto_tree *pt)
{
    int     	    cmd, padding, msglen;
    unsigned int    i;
    proto_tree	    *ft;
    proto_item	    *ti;
    proto_item	    *hi;

    msglen = tvb_reported_length_remaining(tvb, offset);
    cmd = tvb_get_guint8(tvb, offset);
    hi = proto_tree_add_uint(pt, hf_gryphon_cmd, tvb, offset, 1, cmd);
	PROTO_ITEM_SET_HIDDEN(hi);
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
 	ti = proto_tree_add_text(pt, tvb, offset, -1, "Data: (%d byte%s)",
                msglen, msglen == 1 ? "" : "s");
	ft = proto_item_add_subtree(ti, ett_gryphon_command_data);
	offset = (*(cmds[i].cmd_fnct)) (tvb, offset, ft);
    }
    return offset;
}

static int
decode_response(tvbuff_t *tvb, int offset, int src, proto_tree *pt)
{
    int     	    cmd, msglen;
    unsigned int    i, resp;
    proto_tree	    *ft;
    proto_item	    *ti;

    msglen = tvb_reported_length_remaining(tvb, offset);
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
    proto_tree_add_text (pt, tvb, offset, 4, "Status: %s",
	val_to_str(resp, responses_vs, "Unknown (0x%08x)"));
    offset += 4;
    msglen -= 4;

    if (cmds[i].rsp_fnct && msglen > 0) {
	ti = proto_tree_add_text(pt, tvb, offset, msglen, "Data: (%d byte%s)",
                msglen, msglen == 1 ? "" : "s");
	ft = proto_item_add_subtree(ti, ett_gryphon_response_data);
	offset = (*(cmds[i].rsp_fnct)) (tvb, offset, ft);
    }
    return offset;
}

static int
decode_data(tvbuff_t *tvb, int offset, proto_tree *pt)
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
    proto_tree_add_text(tree, tvb, offset, 2, "Header length: %d byte%s, %d bits",
            hdrsize, plurality(hdrsize, "", "s"), hdrbits);
    proto_tree_add_text(tree, tvb, offset+2, 2, "Data length: %d byte%s",
            datasize, plurality(datasize, "", "s"));
    proto_tree_add_text(tree, tvb, offset+4, 1, "Extra data length: %d byte%s",
            extrasize, plurality(extrasize, "", "s"));
    mode = tvb_get_guint8(tvb, offset+5);
    item1 = proto_tree_add_text(tree, tvb, offset+5, 1, "Mode: %d", mode);
    if (mode) {
	tree1 = proto_item_add_subtree (item1, ett_gryphon_flags);
	if (mode & 0x80) {
	    proto_tree_add_text(tree1, tvb, offset+5, 1, "%s",
		decode_boolean_bitfield(mode, 0x80, 8,
		    "Transmitted message", NULL));
	}
	if (mode & 0x40) {
	    proto_tree_add_text(tree1, tvb, offset+5, 1, "%s",
		decode_boolean_bitfield(mode, 0x40, 8,
		    "Received message", NULL));
	}
	if (mode & 0x20) {
	    proto_tree_add_text(tree1, tvb, offset+5, 1, "%s",
		decode_boolean_bitfield(mode, 0x20, 8,
		    "Local message", NULL));
	}
	if (mode & 0x10) {
	    proto_tree_add_text(tree1, tvb, offset+5, 1, "%s",
		decode_boolean_bitfield(mode, 0x10, 8,
		    "Remote message", NULL));
	}
	if (mode & 0x01) {
	    proto_tree_add_text(tree1, tvb, offset+5, 1, "%s",
		decode_boolean_bitfield(mode, 0x01, 8,
		    "Internal message", NULL));
	}
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
decode_event(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int		    msglen;
    int     	    hours, minutes, seconds, fraction, padding, length;
    unsigned long   timestamp;
    int		    msgend;

    msglen = tvb_reported_length_remaining(tvb, offset);
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
    	proto_tree_add_text (pt, tvb, offset, length, "Data (%d byte%s)",
                length, length == 1 ? "" : "s");
	offset += length;
    }
    if (padding) {
    	proto_tree_add_text(pt, tvb, offset, padding, "padding");
	offset += padding;
    }
    return offset;
}

static int
decode_misc (tvbuff_t *tvb, int offset, proto_tree *pt)
{
    #define         LENGTH 120
    int     	    padding, msglen;
    gint            length;
    unsigned char   local_data[LENGTH+1];

    msglen = tvb_reported_length_remaining(tvb, offset);
    padding = 3 - (msglen + 3) % 4;
    length = tvb_get_nstringz0(tvb, offset, LENGTH, local_data);
    proto_tree_add_text(pt, tvb, offset, msglen, "Data: %s", local_data);
    offset += msglen;
    if (padding) {
    	proto_tree_add_text (pt, tvb, offset, padding, "padding");
	offset += padding;
    }
    return offset;
}

static int
cmd_init(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    const char    	*ptr;

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
eventnum(tvbuff_t *tvb, int offset, proto_tree *pt)
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
resp_time(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint64 ts;
    time_t  timestamp;
    struct tm *tmp;
    static const char *mon_names[12] = {
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec"
    };

    ts = tvb_get_ntoh64(tvb, offset);
    timestamp = (time_t) (ts / 100000);
    tmp = localtime(&timestamp);

    if (tmp) {
        proto_tree_add_text(pt, tvb, offset, 8,
                            "Date/Time: %s %d, %d %02d:%02d:%02d.%05u",
                            mon_names[tmp->tm_mon],
                            tmp->tm_mday,
                            tmp->tm_year + 1900,
                            tmp->tm_hour,
                            tmp->tm_min,
                            tmp->tm_sec,
                            (guint) (ts % 100000));
    } else {
        proto_tree_add_text(pt, tvb, offset, 8,
                            "Date/Time: [Invalid]");
    }
    offset += 8;
    return offset;
}

static int
cmd_setfilt(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int     	    flag = tvb_get_ntohl(tvb, offset);
    int     	    length, padding;
    char   mode[30];

    length =  tvb_get_guint8(tvb, offset+4) + tvb_get_guint8(tvb, offset+5)
	+ tvb_get_ntohs(tvb, offset+6);
    if (flag)
       g_strlcpy (mode, "Pass", 30);
    else
       g_strlcpy (mode, "Block", 30);
    if (length == 0)
       g_strlcat (mode, " all", 30);
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
cmd_ioctl(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int		    msglen;
    unsigned int    ioctl;

    msglen = tvb_reported_length_remaining(tvb, offset);
    ioctl = tvb_get_ntohl(tvb, offset);
    proto_tree_add_text(pt, tvb, offset, 4, "IOCTL: %s",
	val_to_str(ioctl, ioctls, "Unknown (0x%08x)"));
    offset += 4;
    msglen -= 4;
    if (msglen > 0) {
	proto_tree_add_text(pt, tvb, offset, msglen, "Data");
	offset += msglen;
    }
    return offset;
}

static int
cmd_addfilt(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    guint8	flags;
    int     	blocks, i, length;

    item = proto_tree_add_text(pt, tvb, offset, 1, "Flags");
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "%s",
	decode_boolean_bitfield(flags, FILTER_PASS_FLAG, 8,
	    "Conforming messages are passed",
	    "Conforming messages are blocked"));
    proto_tree_add_text(tree, tvb, offset, 1, "%s",
	decode_boolean_bitfield(flags, FILTER_ACTIVE_FLAG, 8,
	    "The filter is active", "The filter is inactive"));
    offset += 1;
    blocks = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(pt, tvb, offset, 1, "Number of filter blocks = %d", blocks);
    proto_tree_add_text(pt, tvb, offset+1, 6, "reserved");
    offset += 7;
    for (i = 1; i <= blocks; i++) {
	length = tvb_get_ntohs(tvb, offset+2) * 2 + 8;
	length += 3 - (length + 3) % 4;
	item = proto_tree_add_text(pt, tvb, offset, length, "Filter block %d", i);
	tree = proto_item_add_subtree (item, ett_gryphon_cmd_filter_block);
	offset = filter_block(tvb, offset, tree);
    }
    return offset;
}

static int
resp_addfilt(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 1, "Filter handle: %u",
	tvb_get_guint8(tvb, offset));
    proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    return offset;
}

static int
cmd_modfilt(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint8	    filter_handle;
    unsigned char   action;

    filter_handle = tvb_get_guint8(tvb, offset);
    if (filter_handle)
    	proto_tree_add_text(pt, tvb, offset, 1, "Filter handle: %u",
	    filter_handle);
    else
    	proto_tree_add_text(pt, tvb, offset, 1, "Filter handles: all");
    action = tvb_get_guint8(tvb, offset + 1);
    proto_tree_add_text(pt, tvb, offset+1, 1, "Action: %s filter",
	val_to_str(action, filtacts, "Unknown (%u)"));
    proto_tree_add_text(pt, tvb, offset+2, 2, "reserved");
    offset += 4;
    return offset;
}

static int
resp_filthan(tvbuff_t *tvb, int offset, proto_tree *pt)
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
dfiltmode(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    unsigned char   mode;

    mode = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(pt, tvb, offset, 1, "Filter mode: %s",
	val_to_str(mode, dmodes, "Unknown (%u)"));
    proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    return offset;
}

static int
filtmode(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    unsigned char   mode;

    mode = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(pt, tvb, offset, 1, "Filter mode: %s",
	val_to_str(mode, modes, "Unknown (%u)"));
    proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    return offset;
}

static int
resp_events(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int		    msglen;
    unsigned int    i;
    proto_tree	    *tree;
    proto_item	    *item;

    msglen = tvb_reported_length_remaining(tvb, offset);
    i = 1;
    while (msglen != 0) {
	item = proto_tree_add_text(pt, tvb, offset, 20, "Event %d:", i);
	tree = proto_item_add_subtree (item, ett_gryphon_cmd_events_data);
	proto_tree_add_text(tree, tvb, offset, 1, "Event ID: %u",
	    tvb_get_guint8(tvb, offset));
	proto_tree_add_text(tree, tvb, offset+1, 19, "Event name: %.19s",
		tvb_get_ephemeral_string(tvb, offset+1, 19));
	offset += 20;
	msglen -= 20;
	i++;
    }
    return offset;
}

static int
cmd_register(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 16, "Username: %.16s",
	tvb_get_ephemeral_string(tvb, offset, 16));
    offset += 16;
    proto_tree_add_text(pt, tvb, offset, 32, "Password: %.32s",
	tvb_get_ephemeral_string(tvb, offset, 32));
    offset += 32;
    return offset;
}

static int
resp_register(tvbuff_t *tvb, int offset, proto_tree *pt)
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
resp_getspeeds(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int size;
    int number;
    int index;

    proto_tree_add_text(pt, tvb, offset, 4, "Set Speed IOCTL");
    proto_tree_add_text(pt, tvb, offset+4, 4, "Get Speed IOCTL");
    size = tvb_get_guint8(tvb, offset+8);
    proto_tree_add_text(pt, tvb, offset+8, 1, "Speed data size is %d byte%s",
            size, size == 1 ? "" : "s");
    number = tvb_get_guint8(tvb, offset+9);
    proto_tree_add_text(pt, tvb, offset+9, 1, "There %s %d preset speed%s",
        number == 1 ? "is" : "are", number, number == 1 ? "" : "s");
    offset += 10;
    for (index = 0; index < number; index++) {
	proto_tree_add_text(pt, tvb, offset, size, "Data for preset %d",
	    index+1);
	offset += size;
    }
    return offset;
}

static int
cmd_sort(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    const char	*which;

    which = tvb_get_guint8(tvb, offset) ?
	    "Sort into blocks of up to 16 messages" :
	    "Do not sort messages";
    proto_tree_add_text(pt, tvb, offset, 1, "Set sorting: %s", which);
    offset += 1;
    return offset;
}

static int
cmd_optimize(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    const char	*which;

    which = tvb_get_guint8(tvb, offset) ?
	    "Optimize for latency (Nagle algorithm disabled)" :
	    "Optimize for throughput (Nagle algorithm enabled)";
    proto_tree_add_text(pt, tvb, offset, 1, "Set optimization: %s", which);
    offset += 1;
    return offset;
}

static int
resp_config(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_item	*ti, *item;
    proto_tree	*ft, *tree;
    int     	devices;
    int     	i;
    unsigned int j, x;

    static const value_string protocol_types[] = {
	{GDUMMY * 256 + GDGDMARKONE,	"Dummy device driver"},
	{GCAN * 256 + G82527,	    	"CAN, 82527 subtype"},
	{GCAN * 256 + GSJA1000,     	"CAN, SJA1000 subtype"},
	{GCAN * 256 + G82527SW,     	"CAN, 82527 single wire subtype"},
	{GCAN * 256 + G82527ISO11992,   "CAN, 82527 ISO11992 subtype"},
	{GCAN * 256 + G82527_SINGLECHAN, "CAN, Fiber Optic 82527 subtype"},
	{GCAN * 256 + G82527SW_SINGLECHAN, "CAN, Fiber Optic 82527 single wire subtype"},
	{GCAN * 256 + G82527ISO11992_SINGLECHAN,	"CAN, Fiber Optic ISO11992 subtype"},
	{GCAN * 256 + GSJA1000FT,	"CAN, SJA1000 Fault Tolerant subtype"},
	{GCAN * 256 + GSJA1000C,    	"CAN, SJA1000 onboard subtype"},
	{GCAN * 256 + GSJA1000FT_FO,    "CAN, SJA1000 Fiber Optic Fault Tolerant subtype"},
	{GJ1850 * 256 + GHBCCPAIR,  	"J1850, HBCC subtype"},
	{GJ1850 * 256 + GDLC,	    	"J1850, GM DLC subtype"},
	{GJ1850 * 256 + GCHRYSLER,  	"J1850, Chrysler subtype"},
	{GJ1850 * 256 + GDEHC12,    	"J1850, DE HC12 KWP/BDLC subtype"},
	{GKWP2000 * 256 + GDEHC12KWP,  	"Keyword protocol 2000/ISO 9141"},
	{GHONDA * 256 + GDGHC08,    	"Honda UART, DG HC08 subtype"},
	{GFORDUBP * 256 + GDGUBP08, 	"Ford UBP, DG HC08 subtype"},
        {GSCI * 256 + G16550SCI,        "Chrysler SCI, UART subtype"},
        {GCCD * 256 + G16550CDP68HC68,  "Chrysler C2D, UART / CDP68HC68S1 subtype"},
        {GLIN * 256 + GDGLIN08,         "LIN, DG HC08 subtype"},
	{0,	    	    	    	NULL},
    };

    proto_tree_add_text(pt, tvb, offset, 20, "Device name: %.20s",
	tvb_get_ephemeral_string(tvb, offset, 20));
    offset += 20;

    proto_tree_add_text(pt, tvb, offset, 8, "Device version: %.8s",
	tvb_get_ephemeral_string(tvb, offset, 8));
    offset += 8;

    proto_tree_add_text(pt, tvb, offset, 20, "Device serial number: %.20s",
	tvb_get_ephemeral_string(tvb, offset, 20));
    offset += 20;

    devices = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(pt, tvb, offset, 1, "Number of channels: %d", devices);
    proto_tree_add_text(pt, tvb, offset+1, 11, "Name & version extension: %.11s",
	tvb_get_ephemeral_string(tvb, offset+1, 11));
    proto_tree_add_text(pt, tvb, offset+12, 4, "reserved");
    offset += 16;
    for (i = 1; i <= devices; i++) {
	ti = proto_tree_add_text(pt, tvb, offset, 80, "Channel %d:", i);
	ft = proto_item_add_subtree(ti, ett_gryphon_cmd_config_device);
	proto_tree_add_text(ft, tvb, offset, 20, "Driver name: %.20s",
	    tvb_get_ephemeral_string(tvb, offset, 20));
	offset += 20;

	proto_tree_add_text(ft, tvb, offset, 8, "Driver version: %.8s",
	    tvb_get_ephemeral_string(tvb, offset, 8));
	offset += 8;

	proto_tree_add_text(ft, tvb, offset, 16, "Device security string: %.16s",
	    tvb_get_ephemeral_string(tvb, offset, 16));
	offset += 16;

        x = tvb_get_ntohl (tvb, offset);
        if (x) {
            item = proto_tree_add_text(ft, tvb, offset, 4, "Valid Header lengths");
            tree = proto_item_add_subtree (item, ett_gryphon_valid_headers);
            for (j = 0; ; j++) {
                if (x & 1) {
	            proto_tree_add_text(tree, tvb, offset, 4, "%d byte%s", j,
                    j == 1 ? "" : "s");
                }
                if ((x >>= 1) == 0)
                    break;
            }
        }
	offset += 4;

        x = tvb_get_ntohs (tvb, offset);
	proto_tree_add_text(ft, tvb, offset, 2, "Maximum data length = %d byte%s",
                x, x == 1 ? "" : "s");
	offset += 2;

        x = tvb_get_ntohs (tvb, offset);
	proto_tree_add_text(ft, tvb, offset, 2, "Minimum data length = %d byte%s",
                x, x == 1 ? "" : "s");
	offset += 2;

	proto_tree_add_text(ft, tvb, offset, 20, "Hardware serial number: %.20s",
	    tvb_get_ephemeral_string(tvb, offset, 20));
	offset += 20;

    	x = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(ft, tvb, offset, 2, "Protocol type & subtype: %s",
	    val_to_str(x, protocol_types, "Unknown (0x%04x)"));
	offset += 2;

	proto_tree_add_text(ft, tvb, offset, 1, "Channel ID: %u",
	    tvb_get_guint8(tvb, offset));
        offset++;

	proto_tree_add_text(ft, tvb, offset, 1, "Card slot number: %u",
	    tvb_get_guint8(tvb, offset));
        offset ++;

        x = tvb_get_ntohs (tvb, offset);
	proto_tree_add_text(ft, tvb, offset, 2, "Maximum extra data = %d byte%s",
                x, x == 1 ? "" : "s");
        offset += 2;

        x = tvb_get_ntohs (tvb, offset);
	proto_tree_add_text(ft, tvb, offset, 2, "Minimum extra data = %d byte%s",
                x, x == 1 ? "" : "s");
        offset += 2;

    }
    return offset;
}

static int
cmd_sched(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int		    msglen;
    proto_item	    *item, *item1;
    proto_tree	    *tree, *tree1;
    int		    save_offset;
    unsigned int    i, x, length;
    unsigned char   def_chan = tvb_get_guint8(tvb, offset-9);

    msglen = tvb_reported_length_remaining(tvb, offset);
    x = tvb_get_ntohl(tvb, offset);
    if (x == 0xFFFFFFFF)
    	proto_tree_add_text(pt, tvb, offset, 4, "Number of iterations: \"infinite\"");
    else
    	proto_tree_add_text(pt, tvb, offset, 4, "Number of iterations: %u", x);
    offset += 4;
    msglen -= 4;
    x = tvb_get_ntohl(tvb, offset);
    item = proto_tree_add_text(pt, tvb, offset, 4, "Flags: 0x%08x", x);
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    proto_tree_add_text(tree, tvb, offset, 4, "%s",
	decode_boolean_bitfield(x, 0x01, 32,
	    "Critical scheduler", "Normal scheduler"));
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
	proto_tree_add_text(tree, tvb, offset, 4, "Sleep: %u milliseconds", x);
	offset += 4;
	msglen -= 4;
	x = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Transmit count: %u", x);
	offset += 4;
	msglen -= 4;
	x = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Transmit period: %u milliseconds", x);
	offset += 4;
	msglen -= 4;
        x = tvb_get_ntohs(tvb, offset);
	item1 = proto_tree_add_text(tree, tvb, offset, 2, "Flags");
        tree1 = proto_item_add_subtree (item1, ett_gryphon_flags);
        proto_tree_add_text(tree1, tvb, offset, 2, "%s%s",
	        decode_boolean_bitfield(x, 1, 16, "S", "Do not s"),
                "kip the last \"Transmit period\"");
        if (i == 1) {
            proto_tree_add_text(tree1, tvb, offset, 2, "%s%s",
	            decode_boolean_bitfield(x, 2, 16, "S", "Do not s"),
                    "kip the first \"Sleep\" value");
        }
	x = tvb_get_guint8(tvb, offset+2);
	if (x == 0)
	    x = def_chan;
	proto_tree_add_text(tree, tvb, offset+2, 1, "Channel: %u", x);
	proto_tree_add_text(tree, tvb, offset+3, 1, "reserved");
	offset += 4;
	msglen -= 4;
	item1 = proto_tree_add_text(tree, tvb, offset, length, "Message");
	tree1 = proto_item_add_subtree (item1, ett_gryphon_cmd_sched_cmd);
	save_offset = offset;
	offset = decode_data(tvb, offset, tree1);
	msglen -= offset - save_offset;
	i++;
    }
    return offset;
}

static int
cmd_sched_rep(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int		    msglen;
    proto_item	    *item;
    int		    save_offset;
    unsigned int    x;
    const char      *type;

    msglen = tvb_reported_length_remaining(tvb, offset);
    x = tvb_get_ntohl(tvb, offset);
    if (x & 0x80000000)
        type = "Critical";
    else
        type = "Normal";
    proto_tree_add_text(pt, tvb, offset, 4, "%s schedule ID: %u", type, x);
    offset += 4;
    msglen -= 4;
    x= tvb_get_guint8(tvb, offset);
    item = proto_tree_add_text(pt, tvb, offset, 1, "Message index: %d", x);
    item = proto_tree_add_text(pt, tvb, offset + 1, 3, "reserved");
    offset += 4;
    msglen -= 4;
    save_offset = offset;
    offset = decode_data(tvb, offset, pt);
    msglen -= offset - save_offset;
    return offset;
}

static int
resp_blm_data(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    unsigned int      i;
    int               hours, minutes, seconds, fraction, x, fract;
    unsigned long     timestamp;
    static const char *fields[] = {
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
resp_blm_stat(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    unsigned int    x, i;
    const char 	    *fields[] = {
    	"Receive frame count: %u",
    	"Transmit frame count: %u",
    	"Receive dropped frame count: %u",
    	"Transmit dropped frame count: %u",
    	"Receive error count: %u",
    	"Transmit error count: %u",
    };

    offset = resp_blm_data(tvb, offset, pt);
    for (i = 0; i < SIZEOF(fields); i++){
	x = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(pt, tvb, offset, 4, fields[i], x);
	offset += 4;
    }
    return offset;
}

static const value_string action_vals[] = {
    { FR_RESP_AFTER_EVENT,  "Send response(s) for each conforming message" },
    { FR_RESP_AFTER_PERIOD, "Send response(s) after the specified period expires following a conforming message" },
    { FR_IGNORE_DURING_PER, "Send response(s) for a conforming message and ignore\nfurther messages until the specified period expires" },
    { 0,                    NULL }
};

static const value_string deact_on_event_vals[] = {
    { FR_DEACT_ON_EVENT,
	"Deactivate this response for a conforming message" },
    { FR_DELETE|FR_DEACT_ON_EVENT,
	"Delete this response for a conforming message" },
    { 0,
	NULL }
};

static const value_string deact_after_per_vals[] = {
    { FR_DEACT_AFTER_PER,
	"Deactivate this response after the specified period following a conforming message" },
    { FR_DELETE|FR_DEACT_AFTER_PER,
	"Delete this response after the specified period following a conforming message" },
    { 0,
	NULL }
};

static int
cmd_addresp(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    guint8	flags;
    int     	blocks, responses, old_handle, i, msglen, length;
    int     	action, actionType, actionValue;
    tvbuff_t	*next_tvb;

    actionType = 0;
    flags = tvb_get_guint8(tvb, offset);
    item = proto_tree_add_text(pt, tvb, offset, 1, "Flags: 0x%02x", flags);
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    proto_tree_add_text(tree, tvb, offset, 1, "%s",
	decode_boolean_bitfield(flags, FILTER_ACTIVE_FLAG, 8,
		"The response is active", "The response is inactive"));
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
    item = proto_tree_add_text(pt, tvb, offset, 1, "Action: %s",
	val_to_str(action & 0x07, action_vals, "Unknown (%u)"));
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    proto_tree_add_text(tree, tvb, offset, 1, "%s",
	decode_enumerated_bitfield(action, 0x07, 8, action_vals, "%s"));
    actionValue = tvb_get_ntohs(tvb, offset+2);
    if (actionValue) {
	if (action & FR_PERIOD_MSGS) {
	    actionType = 1;
	} else {
	    actionType = 0;
	}
    	proto_tree_add_text(tree, tvb, offset, 1, "%s",
	    decode_boolean_bitfield(action, FR_PERIOD_MSGS, 8,
		"The period is in frames", "The period is in 0.01 seconds"));
    }
    if (action & FR_DEACT_ON_EVENT) {
	proto_tree_add_text(tree, tvb, offset, 1, "%s",
	    decode_enumerated_bitfield(action, FR_DELETE|FR_DEACT_ON_EVENT, 8,
		deact_on_event_vals, "%s"));
    }
    if (action & FR_DEACT_AFTER_PER) {
	proto_tree_add_text(tree, tvb, offset, 1, "%s",
	    decode_enumerated_bitfield(action, FR_DELETE|FR_DEACT_AFTER_PER, 8,
		deact_after_per_vals, "%s"));
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
	offset = filter_block(tvb, offset, tree);
    }
    for (i = 1; i <= responses; i++) {
	msglen = tvb_get_ntohs(tvb, offset+4) + 8;
	length = msglen + 3 - (msglen + 3) % 4;
	item = proto_tree_add_text(pt, tvb, offset, length, "Response block %d", i);
	tree = proto_item_add_subtree (item, ett_gryphon_cmd_response_block);
	next_tvb = tvb_new_subset(tvb, offset, msglen, msglen);
	dissect_gryphon_message(next_tvb, NULL, tree, TRUE);
	offset += length;
    }
    return offset;
}

static int
resp_addresp(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 1, "Response handle: %u",
	tvb_get_guint8(tvb, offset));
    proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    return offset;
}

static int
cmd_modresp(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    unsigned char   action;
    unsigned char   dest = tvb_get_guint8(tvb, offset-5);
    guint8	    resp_handle;

    resp_handle = tvb_get_guint8(tvb, offset);
    if (resp_handle)
	proto_tree_add_text(pt, tvb, offset, 1, "Response handle: %u",
	    resp_handle);
    else if (dest)
	proto_tree_add_text(pt, tvb, offset, 1, "Response handles: all on channel %c", dest);
    else
    	proto_tree_add_text(pt, tvb, offset, 1, "Response handles: all");
    action = tvb_get_guint8(tvb, offset+1);
    proto_tree_add_text(pt, tvb, offset+1, 1, "Action: %s response",
	val_to_str(action, filtacts, "Unknown (%u)"));
    proto_tree_add_text(pt, tvb, offset+2, 2, "reserved");
    offset += 4;
    return offset;
}

static int
resp_resphan(tvbuff_t *tvb, int offset, proto_tree *pt)
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
resp_sched(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    unsigned int    id = tvb_get_ntohl(tvb, offset);

    proto_tree_add_text(pt, tvb, offset, 4, "Transmit schedule ID: %u", id);
    offset += 4;
    return offset;
}

static int
cmd_desc(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 4, "Program size: %u bytes",
	tvb_get_ntohl(tvb, offset));
    offset += 4;
    proto_tree_add_text(pt, tvb, offset, 32, "Program name: %.32s",
	tvb_get_ephemeral_string(tvb, offset, 32));
    offset += 32;
    proto_tree_add_text(pt, tvb, offset, 80, "Program description: %.80s",
	tvb_get_ephemeral_string(tvb, offset, 80));
    offset += 80;
    return offset;
}

static int
resp_desc(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    guint8	flags;

    flags = tvb_get_guint8(tvb, offset);
    item = proto_tree_add_text(pt, tvb, offset, 1, "Flags: 0x%02x", flags);
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    proto_tree_add_text(tree, tvb, offset, 1, "%s",
	decode_boolean_bitfield(flags, 0x01, 8,
		"The program is already present",
		"The program is not present"));
    proto_tree_add_text(pt, tvb, offset+1, 1, "Handle: %u",
	tvb_get_guint8(tvb, offset+1));
    proto_tree_add_text(pt, tvb, offset+2, 2, "reserved");
    offset += 4;
    return offset;
}

static int
cmd_upload(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int		    msglen;
    unsigned int    length;

    msglen = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_text(pt, tvb, offset, 2, "Block number: %u",
	tvb_get_ntohs(tvb, offset));
    proto_tree_add_text(pt, tvb, offset+2, 1, "Handle: %u",
	tvb_get_guint8(tvb, offset+2));
    offset += 3;
    msglen -= 3;
    length = msglen;
    proto_tree_add_text(pt, tvb, offset, length, "Data (%u byte%s)",
            length, length == 1 ? "" : "s");
    offset += length;
    length = 3 - (length + 3) % 4;
    if (length) {
	proto_tree_add_text(pt, tvb, offset, length, "padding");
	offset += length;
    }
    return offset;
}

static int
cmd_delete(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 32, "Program name: %.32s",
	tvb_get_ephemeral_string(tvb, offset, 32));
    offset += 32;
    return offset;
}

static int
cmd_list(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 1, "Block number: %u",
	tvb_get_guint8(tvb, offset));
    proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    return offset;
}

static int
resp_list(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    unsigned int    i, count;

    count = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(pt, tvb, offset, 1, "Number of programs in this response: %u", count);
    proto_tree_add_text(pt, tvb, offset+1, 1, "reserved");
    offset += 2;
    proto_tree_add_text(pt, tvb, offset, 2, "Number of remaining programs: %u",
	tvb_get_ntohs(tvb, offset));
    offset += 2;
    for (i = 1; i <= count; i++) {
	item = proto_tree_add_text(pt, tvb, offset, 112, "Program %u", i);
	tree = proto_item_add_subtree (item, ett_gryphon_pgm_list);
	proto_tree_add_text(tree, tvb, offset, 32, "Name: %.32s",
	    tvb_get_ephemeral_string(tvb, offset, 32));
	offset += 32;
	proto_tree_add_text(tree, tvb, offset, 80, "Description: %.80s",
	    tvb_get_ephemeral_string(tvb, offset, 80));
	offset += 80;
    }
    return offset;
}

static int
cmd_start(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint8	    *string;
    gint	    length;
    int             msglen;
    int             hdr_stuff = offset;

    msglen = tvb_reported_length_remaining(tvb, offset);
    offset = cmd_delete(tvb, offset, pt);	/* decode the name */
    if (offset < msglen + hdr_stuff) {
        string = tvb_get_ephemeral_stringz(tvb, offset, &length);
        if (length > 1) {
            proto_tree_add_text(pt, tvb, offset, length, "Arguments: %s", string);
            offset += length;
            length = 3 - (length + 3) % 4;
            if (length) {
	        proto_tree_add_text(pt, tvb, offset, length, "padding");
	        offset += length;
            }
        }
    }
    return offset;
}

static int
resp_start(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int             msglen;

    msglen = tvb_reported_length_remaining(tvb, offset);
    if (msglen > 0) {
        proto_tree_add_text(pt, tvb, offset, 1, "Channel (Client) number: %u",
	    tvb_get_guint8(tvb, offset));
        proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
        offset += 4;
    }
    return offset;
}

static int
resp_status(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    unsigned int    i, copies, length;

    copies = tvb_get_guint8(tvb, offset);
    item = proto_tree_add_text(pt, tvb, offset, 1, "Number of running copies: %u", copies);
    tree = proto_item_add_subtree (item, ett_gryphon_pgm_status);
    offset += 1;
    if (copies) {
	for (i = 1; i <= copies; i++) {
	    proto_tree_add_text(tree, tvb, offset, 1, "Program %u channel (client) number %u",
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
cmd_options(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int		    msglen;
    proto_item	    *item;
    proto_tree	    *tree;
    unsigned int    i, size, padding, option, option_length, option_value;
    const char	    *string, *string1;

    msglen = tvb_reported_length_remaining(tvb, offset);
    item = proto_tree_add_text(pt, tvb, offset, 1, "Handle: %u",
	tvb_get_guint8(tvb, offset));
    item = proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    msglen -= 4;
    for (i = 1; msglen > 0; i++) {
	option_length = tvb_get_guint8(tvb, offset+1);
    	size = option_length + 2;
	padding = 3 - ((size + 3) %4);
	item = proto_tree_add_text(pt, tvb, offset, size + padding, "Option number %u", i);
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
cmd_files(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int	         msglen;
    const gchar  *which;

    msglen = tvb_reported_length_remaining(tvb, offset);
    if (tvb_get_guint8(tvb, offset) == 0)
	which = "First group of names";
    else
	which = "Subsequent group of names";

    proto_tree_add_text(pt, tvb, offset, 1, "%s", which);
    proto_tree_add_text(pt, tvb, offset+1, msglen-1, "Directory: %.*s",
	msglen-1, tvb_get_ephemeral_string(tvb, offset+1, msglen-1));
    offset += msglen;
    return offset;
}

static int
resp_files(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int			msglen;
    const gchar  	*flag;

    msglen = tvb_reported_length_remaining(tvb, offset);
    flag = tvb_get_guint8(tvb, offset) ? "Yes": "No";
    proto_tree_add_text(pt, tvb, offset, 1, "More filenames to return: %s", flag);
    proto_tree_add_text(pt, tvb, offset+1, msglen-1, "File and directory names");
    offset += msglen;
    return offset;
}

static int
cmd_usdt(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int		ids, id, remain, size, i, j, bytes;
    const gchar	*desc;
    guint8	flags;
    proto_tree	*localTree;
    proto_item	*localItem;
    const gchar	*actions[] = {
	"Use 11 bit headers only",
	"Use 29 bit headers only",
	"Use both 11 & 29 bit headers",
	"undefined"
    };
    const gchar *xmit_opts[] = {
	"Pad messages with less than 8 data bytes with 0x00's",
	"Pad messages with less than 8 data bytes with 0xFF's",
	"Do not pad messages with less than 8 data bytes",
	"undefined"
    };
    const gchar *recv_opts[] = {
	"Do not verify the integrity of long received messages and do not send them to the client",
	"Verify the integrity of long received messages and send them to the client",
	"Verify the integrity of long received messages but do not send them to the client",
	"undefined"
    };
    const gchar *block_desc[] = {"USDT request", "USDT response", "UUDT response"};

    flags = tvb_get_guint8(tvb, offset);
    if (flags & 1)
	desc = "R";
    else
	desc = "Unr";
    proto_tree_add_text(pt, tvb, offset, 1, "%segister with gusdt", desc);

    if (flags & 1) {
        localItem = proto_tree_add_text(pt, tvb, offset, 1, "Action flags");
        localTree = proto_item_add_subtree (localItem, ett_gryphon_flags);
	proto_tree_add_text(localTree, tvb, offset, 1, "%s%s",
	    decode_boolean_bitfield (flags, 1, 8,
		"R", "Unr"), "egister with gusdt");
	proto_tree_add_text(localTree, tvb, offset, 1, "%s = %s",
            decode_numeric_bitfield (flags, 6, 8, "%d"),
            actions[(flags >> 1) & 3]);

        flags = tvb_get_guint8(tvb, offset+1);
        localItem = proto_tree_add_text(pt, tvb, offset+1, 1, "Transmit options");
        localTree = proto_item_add_subtree (localItem, ett_gryphon_flags);
	proto_tree_add_text(localTree, tvb, offset+1, 1, "%s%s",
	    decode_boolean_bitfield (flags, 1, 8,
		"E", "Do not e"),
                "cho long transmit messages back to the client");
	proto_tree_add_text(localTree, tvb, offset+1, 1, "%s = %s",
            decode_numeric_bitfield (flags, 6, 8, "%d"),
            xmit_opts[(flags >> 1) & 3]);
	proto_tree_add_text(localTree, tvb, offset+1, 1, "%s%s",
	    decode_boolean_bitfield (flags, 8, 8,
		"S", "Do not s"),
                "end a USDT_DONE event when the last frame of a multi-frame USDT message is transmitted");

        flags = tvb_get_guint8(tvb, offset+2);
        localItem = proto_tree_add_text(pt, tvb, offset+2, 1, "Receive options");
        localTree = proto_item_add_subtree (localItem, ett_gryphon_flags);
	proto_tree_add_text(localTree, tvb, offset+2, 1, "%s = %s",
            decode_numeric_bitfield (flags, 3, 8, "%d"),
            recv_opts[flags & 3]);
	proto_tree_add_text(localTree, tvb, offset+2, 1, "%s%s",
	    decode_boolean_bitfield (flags, 4, 8,
		"S", "Do not s"),
                "end a USDT_FIRSTFRAME event when the first frame of a multi-frame USDT message is received");
	proto_tree_add_text(localTree, tvb, offset+2, 1, "%s%s",
	    decode_boolean_bitfield (flags, 8, 8,
		"S", "Do not s"),
                "end a USDT_LASTFRAME event when the last frame of a multi-frame USDT message is received");

        if ((ids = tvb_get_guint8(tvb, offset+3))) {
            localItem = proto_tree_add_text(pt, tvb, offset+3, 1, "Using extended addressing for %d ID%s",
                    ids, ids == 1?"":"s");
            offset += 4;
            localTree = proto_item_add_subtree (localItem, ett_gryphon_usdt_data);
            while (ids) {
                id = tvb_get_ntohl (tvb, offset);
                proto_tree_add_text (localTree, tvb, offset, 4, "%04X", id);
                offset += 4;
                ids--;
            }
        } else {
            proto_tree_add_text(pt, tvb, offset+3, 1, "Using extended addressing for the single, internally defined, ID");
            offset += 4;
        }
        for (i = 0; i < 2; i++) {
            bytes = tvb_reported_length_remaining (tvb, offset);
            if (bytes <= 0)
                break;
            localItem = proto_tree_add_text(pt, tvb, offset, 16, "%s block of USDT/UUDT IDs", i==0?"First":"Second");
            localTree = proto_item_add_subtree (localItem, ett_gryphon_usdt_data);
            size = tvb_get_ntohl (tvb, offset);
            if (size == 0) {
                proto_tree_add_text (localTree, tvb, offset, 16, "No IDs in the block");
                offset += 16;
            } else if (size == 1) {
                proto_tree_add_text (localTree, tvb, offset, 4, "1 ID in the block");
                offset += 4;
                for (j = 0; j < 3; j++){
                    id = tvb_get_ntohl (tvb, offset);
                    proto_tree_add_text (localTree, tvb, offset, 4,
                            "%s ID: %04X", block_desc[j], id);
                    offset += 4;
                }
            } else {
                proto_tree_add_text (localTree, tvb, offset, 4, "%d IDs in the block", size);
                offset += 4;
                for (j = 0; j < 3; j++){
                    id = tvb_get_ntohl (tvb, offset);
                    proto_tree_add_text (localTree, tvb, offset, 4,
                            "%s IDs from %04X through %04X", block_desc[j], id, id+size-1);
                    offset += 4;
                }
            }
        }
    } else {
        proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
        offset += 4;
    }

    if ((remain = tvb_reported_length_remaining(tvb, offset))) {
        proto_tree_add_text(pt, tvb, offset, remain, "%d ignored byte%s",
                remain, remain == 1 ? "" : "s");
        offset += remain;
    }

    return offset;
}

static int
cmd_bits_in (tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    unsigned int i;
    int	        msglen, mask, value;
    const char  *decode[] = {"Input 1", "Input 2", "Input 3", "Pushbutton"};

    msglen = tvb_reported_length_remaining(tvb, offset);
    value = tvb_get_guint8(tvb, offset);
    if (value) {
        item = proto_tree_add_text(pt, tvb, offset, 1, "Digital values set");
        tree = proto_item_add_subtree (item, ett_gryphon_digital_data);
        for (i = 0, mask = 1; i < SIZEOF (decode); mask <<= 1, i++) {
            if (value & mask) {
                proto_tree_add_text(tree, tvb, offset, 1, "%s is set",
                        decode[i]);
            }
        }
    } else {
        proto_tree_add_text(pt, tvb, offset, 1, "No digital values are set");
    }

    offset++;
    msglen--;
    return offset;
}

static int
cmd_bits_out (tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    unsigned int i;
    int	        msglen, mask, value;
    const char  *decode[] = {"Output 1", "Output 2"};

    msglen = tvb_reported_length_remaining(tvb, offset);
    value = tvb_get_guint8(tvb, offset);
    if (value) {
        item = proto_tree_add_text(pt, tvb, offset, 1, "Digital values set");
        tree = proto_item_add_subtree (item, ett_gryphon_digital_data);
        for (i = 0, mask = 1; i < SIZEOF (decode); mask <<= 1, i++) {
            if (value & mask) {
                proto_tree_add_text(tree, tvb, offset, 1, "%s is set",
                        decode[i]);
            }
        }
    } else {
        proto_tree_add_text(pt, tvb, offset, 1, "No digital values are set");
    }

    offset++;
    msglen--;
    return offset;
}

static int
cmd_init_strat (tvbuff_t *tvb, int offset, proto_tree *pt)
{
    int	    msglen, index;
    float   value;

    msglen = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_text(pt, tvb, offset, 4, "Reset Limit = %u messages",
	tvb_get_ntohl(tvb, offset));
    offset += 4;
    msglen -= 4;
    for (index = 1; msglen; index++, offset++, msglen--) {
        value = tvb_get_guint8(tvb, offset);
        if (value) {
            value /= 4;
            proto_tree_add_text(pt, tvb, offset, 1, "Delay %d = %.2f seconds",
	        index, value);
        } else {
            proto_tree_add_text(pt, tvb, offset, 1, "Delay %d = infinite",
	        index);
        }
    }
    return offset;
}

static int
speed(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree_add_text(pt, tvb, offset, 1, "Baud rate index: %u",
	tvb_get_guint8(tvb, offset));
    proto_tree_add_text(pt, tvb, offset+1, 3, "reserved");
    offset += 4;
    return offset;
}

static int
filter_block(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    unsigned int    type, operator;
    int     length, padding;

    proto_tree_add_text(pt, tvb, offset, 2, "Filter field starts at byte %u",
	tvb_get_ntohs(tvb, offset));
    length = tvb_get_ntohs(tvb, offset+2);
    proto_tree_add_text(pt, tvb, offset+2, 2, "Filter field is %d byte%s long",
            length, length == 1 ? "" : "s");
    type = tvb_get_guint8(tvb, offset+4);
    proto_tree_add_text(pt, tvb, offset+4, 1, "Filtering on %s",
	val_to_str(type, filter_data_types, "Unknown (0x%02x)"));

    operator = tvb_get_guint8(tvb, offset+5);
    proto_tree_add_text(pt, tvb, offset+5, 1, "Type of comparison: %s",
	val_to_str(operator, operators, "Unknown (%u)"));
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
blm_mode(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    const char    *mode;
    char line[50];
    int     x, y, seconds;

    x = tvb_get_ntohl(tvb, offset);
    y = tvb_get_ntohl(tvb, offset+4);
    switch (x) {
    case 0:
    	mode = "Off";
	g_snprintf (line, 50, "reserved");
    	break;
    case 1:
    	mode = "Average over time";
	seconds = y / 1000;
	y = y % 1000;
	g_snprintf (line, 50, "Averaging period: %d.%03d seconds", seconds, y);
    	break;
    case 2:
    	mode = "Average over frame count";
	g_snprintf (line, 50, "Averaging period: %d frames", y);
    	break;
    default:
    	mode = "- unknown -";
	g_snprintf (line, 50, "reserved");
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
	{ &hf_gryphon_src,
	{ "Source",           "gryphon.src", FT_UINT8, BASE_HEX, VALS(src_dest), 0x0,
	    	NULL, HFILL }},
	{ &hf_gryphon_srcchan,
	{ "Source channel",   "gryphon.srcchan", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	NULL, HFILL }},
	{ &hf_gryphon_dest,
	{ "Destination",      "gryphon.dest", FT_UINT8, BASE_HEX, VALS(src_dest), 0x0,
	    	NULL, HFILL }},
	{ &hf_gryphon_destchan,
	{ "Destination channel", "gryphon.destchan", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	NULL, HFILL }},
	{ &hf_gryphon_type,
	{ "Frame type",       "gryphon.type", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	NULL, HFILL }},
	{ &hf_gryphon_cmd,
	{ "Command",          "gryphon.cmd", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	NULL, HFILL }},
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
        &ett_gryphon_valid_headers,
        &ett_gryphon_usdt_data,
        &ett_gryphon_digital_data,
    };
    module_t *gryphon_module;

    proto_gryphon = proto_register_protocol("DG Gryphon Protocol",
					    "Gryphon",
					    "gryphon");
    proto_register_field_array(proto_gryphon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    gryphon_module = prefs_register_protocol(proto_gryphon, NULL);
    prefs_register_bool_preference(gryphon_module, "desegment",
	"Desegment all Gryphon messages spanning multiple TCP segments",
	"Whether the Gryphon dissector should desegment all messages spanning multiple TCP segments",
	&gryphon_desegment);
}

void
proto_reg_handoff_gryphon(void)
{
    dissector_handle_t gryphon_handle;

    gryphon_handle = create_dissector_handle(dissect_gryphon, proto_gryphon);
    dissector_add_uint("tcp.port", 7000, gryphon_handle);
}
