/* packet-gryphon.c
 * Routines for Gryphon protocol packet disassembly
 *
 * $Id: packet-gryphon.c,v 1.10 2000/05/31 05:09:07 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Steve Limkemann <stevelim@dgtech.com>
 * Copyright 1998 Steve Limkemann
 *
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
 *
 *
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

#include <glib.h>
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#include "packet.h"
#include "dfilter.h"
#include "packet-gryphon.h"

DLLEXPORT const gchar version[] = VERSION;
DLLEXPORT const gchar desc[] = "DG Gryphon Protocol";
DLLEXPORT const gchar protocol[] = "tcp";
DLLEXPORT const gchar filter_string[] = "tcp.port == 7000";

#ifndef G_HAVE_GINT64
#error "Sorry, this won't compile without 64-bit integer support"
#endif                                                                  

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



DLLEXPORT void
dissector(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{

    proto_tree	    *gryphon_tree, *header_tree, *body_tree;
    proto_item	    *ti, *header_item, *body_item;
    const u_char    *data, *dataend, *msgend;
    int		    src, msglen, msgpad, dest, frmtyp, i, end_of_frame;
    static const u_char *frame_type[] = {"",
    	    	    	                 "Command request",
			                 "Command response",
			                 "Network (vehicle) data",
			                 "Event",
			                 "Miscelaneous",
			                 "Text string"};
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

    data = &pd[offset];
    if (fd) {
        end_of_frame = END_OF_FRAME;
    }
    else {
	end_of_frame = pntohs (data + 4) + 8;
	end_of_frame += 3 - (end_of_frame + 3 ) % 4;
    }
    dataend = data + end_of_frame;

    if (fd && check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "Gryphon");

    if (END_OF_FRAME < 8)
	return;

    if (fd && check_col(fd, COL_INFO)) {
	/*
	 * Indicate what kind of message this is.
	 */
    	col_add_str (fd, COL_INFO, frame_type[data[6]]);
    }
    if (tree) {
    	if (fd) {
	    ti = proto_tree_add_item(tree, proto_gryphon, NullTVB, offset,
	    	    end_of_frame, FALSE);
	    gryphon_tree = proto_item_add_subtree(ti, ett_gryphon);
	} else
	    gryphon_tree = tree;

    	while (data < dataend) {
	    src = data[0];
	    dest = data[2];
	    frmtyp = data[6];
	    msglen = pntohs ((unsigned short *)&data[4]);

    	    header_item = proto_tree_add_text(gryphon_tree, NullTVB, offset,
	    	    MSG_HDR_SZ, "Header");
	    header_tree = proto_item_add_subtree(header_item,
	    	    ett_gryphon_header);
	    for (i = 0; i < SIZEOF(src_dest); i++) {
    		if (src_dest[i].value == src)
		    break;
	    }
	    if (i >= SIZEOF(src_dest))
    		i = SIZEOF(src_dest) - 1;
 	    proto_tree_add_text(header_tree, NullTVB, offset, 2,
	    	    "Source: %s, channel %hd", src_dest[i].strptr, data[1]);
    	    proto_tree_add_uint_hidden(header_tree, hf_gryph_src, NullTVB, offset, 1, src);
    	    proto_tree_add_uint_hidden(header_tree, hf_gryph_srcchan, NullTVB, offset+1, 1, data[1]);

	    for (i = 0; i < SIZEOF(src_dest); i++) {
    		if (src_dest[i].value == dest)
		    break;
	    }
	    if (i >= SIZEOF(src_dest))
    		i = SIZEOF(src_dest) - 1;
  	    proto_tree_add_text(header_tree, NullTVB, offset+2, 2,
	    	    "Destination: %s, channel %hd", src_dest[i].strptr, data[3]);
    	    proto_tree_add_uint_hidden(header_tree, hf_gryph_dest, NullTVB, offset+2, 1, dest);
    	    proto_tree_add_uint_hidden(header_tree, hf_gryph_destchan, NullTVB, offset+3, 1, data[3]);

	    proto_tree_add_text(header_tree, NullTVB, offset+4, 2,
	    	    "Data length: %d bytes", msglen);
	    proto_tree_add_text(header_tree, NullTVB, offset+6, 1,
	    	    "Frame type: %s", frame_type[frmtyp]);
	    proto_tree_add_text(header_tree, NullTVB, offset+7, 1, "reserved");

    	    proto_tree_add_uint_hidden(header_tree, hf_gryph_type, NullTVB, offset+6, 1, frmtyp);
	    msgpad = 3 - (msglen + 3) % 4;
	    msgend = data + msglen + msgpad + MSG_HDR_SZ;

    	    body_item = proto_tree_add_text(gryphon_tree, NullTVB, offset + MSG_HDR_SZ,
	    	    msglen + msgpad, "Body");
    	    body_tree = proto_item_add_subtree(body_item, ett_gryphon_body);

	    offset += MSG_HDR_SZ;
	    data += MSG_HDR_SZ;
	    switch (frmtyp) {
	    case GY_FT_CMD:
	    	decode_command (dest, &data, dataend, &offset, msglen, body_tree);
	    	break;
	    case GY_FT_RESP:
	    	decode_response (src, &data, dataend, &offset, msglen, body_tree);
	    	break;
	    case GY_FT_DATA:
	    	decode_data (src, &data, dataend, &offset, msglen, body_tree);
	    	break;
	    case GY_FT_EVENT:
	    	decode_event (src, &data, dataend, &offset, msglen, body_tree);
	    	break;
	    case GY_FT_MISC:
	    	break;
	    case GY_FT_TEXT:
	    	break;
	    default:
	    	break;
	    }
	    if (data < msgend - msgpad) {
	    	i = msgend - msgpad - data;
		proto_tree_add_text(gryphon_tree, NullTVB, offset, i, "Data");
		BUMP (offset, data, i);
	    }
	    if (data < msgend) {
	    	i = msgend - data;
		proto_tree_add_text(gryphon_tree, NullTVB, offset, i, "padding");
		BUMP (offset, data, i);
	    }
/*	    data = dataend;*/
	}

   }
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
	{CMD_CARD_GET_SPEEDS,	"Get defined speeds", NULL, NULL},
	{CMD_SERVER_REG, 	"Register with server", cmd_register, resp_register},
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
	{CMD_SCHED_TX,   	"Schedule transmission of messages", cmd_sched, resp_sched},
	{CMD_SCHED_KILL_TX,	"Stop and destroy a message transmission", NULL, NULL},
	{CMD_SCHED_STOP_TX,	"Kill a message transmission (deprecated)", NULL, NULL},
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


void
decode_command (int dst, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    int     	    cmd, i;
    proto_tree	    *ft;
    proto_item	    *ti;

    cmd = (*data)[0];
    proto_tree_add_uint_hidden(pt, hf_gryph_cmd, NullTVB, *offset, 1, cmd);
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

    proto_tree_add_text (pt, NullTVB, *offset, 4, "Command: %s", cmds[i].strptr);
    BUMP (*offset, *data, 4);

    if (cmds[i].cmd_fnct && dataend - *data) {
	ti = proto_tree_add_text(pt, NullTVB, *offset, dataend - *data, "Data: (%d bytes)", dataend - *data);
	ft = proto_item_add_subtree(ti, ett_gryphon_command_data);
	(*(cmds[i].cmd_fnct)) (dst, data, dataend, offset, msglen, ft);
    }
}

void
decode_response (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    int     	    cmd, i, j, resp;
    proto_tree	    *ft;
    proto_item	    *ti;

    cmd = (*data)[0];
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
    proto_tree_add_text (pt, NullTVB, *offset, 4, "Command: %s", cmds[i].strptr);
    BUMP (*offset, *data, 4);
    
    resp = pntohl ((unsigned long *)data[0]);
    for (j = 0; j < SIZEOF(responses); j++) {
    	if (responses[j].value == resp)
	    break;
    }
    if (j >= SIZEOF(responses))
    	j = SIZEOF(responses) - 1;
    proto_tree_add_text (pt, NullTVB, *offset, 4, "Status: %s", responses[j].strptr);
    BUMP (*offset, *data, 4);

    if (cmds[i].rsp_fnct) {
    ti = proto_tree_add_text(pt, NullTVB, *offset, dataend - *data, "Data: (%d bytes)", dataend - *data);
    ft = proto_item_add_subtree(ti, ett_gryphon_response_data);
	(*(cmds[i].rsp_fnct)) (src, data, dataend, offset, msglen, ft);
    }
}

void
decode_data (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    proto_item	*item, *item1;
    proto_tree	*tree, *tree1;
    int     hdrsize, datasize, extrasize, hdrbits, msgsize, padding, mode;
    int     hours, minutes, seconds, fraction;
    unsigned long   timestamp;

	hdrsize = (*data)[0];
	hdrbits = (*data)[1];
	datasize = pntohs ((unsigned short *)((*data)+2));
	extrasize = (*data)[4];
	padding = 3 - (hdrsize + datasize + extrasize + 3) % 4;
	msgsize = hdrsize + datasize + extrasize + padding + 16;

    	item = proto_tree_add_text(pt, NullTVB, *offset, 16, "Message header");
	tree = proto_item_add_subtree (item, ett_gryphon_data_header);
    	proto_tree_add_text(tree, NullTVB, *offset, 2, "Header length: %d bytes, %d bits", hdrsize, hdrbits);
    	proto_tree_add_text(tree, NullTVB, *offset+2, 2, "Data length: %d bytes", datasize);
    	proto_tree_add_text(tree, NullTVB, *offset+4, 1, "Extra data length: %d bytes", extrasize);
	mode = (*data)[5];
    	item1 = proto_tree_add_text(tree, NullTVB, *offset+5, 1, "Mode: %hd", mode);
	if (mode) {
	    tree1 = proto_item_add_subtree (item1, ett_gryphon_flags);
	    if (mode & 0x80)
	    	proto_tree_add_text(tree1, NullTVB, *offset+5, 1, "1... .... = Transmitted message");
	    if (mode & 0x40)
	    	proto_tree_add_text(tree1, NullTVB, *offset+5, 1, ".1.. .... = Received message");
	    if (mode & 0x20)
	    	proto_tree_add_text(tree1, NullTVB, *offset+5, 1, "..1. .... = Local message");
	    if (mode & 0x10)
	    	proto_tree_add_text(tree1, NullTVB, *offset+5, 1, "...1 .... = Remote message");
	    if (mode & 0x01)
	    	proto_tree_add_text(tree1, NullTVB, *offset+5, 1, ".... ...1 = Internal message");
	}
    	proto_tree_add_text(tree, NullTVB, *offset+6, 1, "Priority: %d", (*data)[6]);
    	proto_tree_add_text(tree, NullTVB, *offset+7, 1, "Error status: %hd", (*data)[7]);
	timestamp = pntohl ((unsigned long *)((*data)+8));
	hours = timestamp /(100000 * 60 *60);
	minutes = (timestamp / (100000 * 60)) % 60;
	seconds = (timestamp / 100000) % 60;
	fraction = timestamp % 100000;
    	proto_tree_add_text(tree, NullTVB, *offset+8, 4, "Timestamp: %d:%02d:%02d.%05d", hours, minutes, seconds, fraction);
    	proto_tree_add_text(tree, NullTVB, *offset+12, 1, "Context: %hd", (*data)[12]);
    	proto_tree_add_text(tree, NullTVB, *offset+13, 3, "reserved:");
	BUMP (*offset, *data, 16);
    	item = proto_tree_add_text(pt, NullTVB, *offset, msgsize-16-padding, "Message Body");
	tree = proto_item_add_subtree (item, ett_gryphon_data_body);
	if (hdrsize) {
	    proto_tree_add_text(tree, NullTVB, *offset, hdrsize, "Header");
	    BUMP (*offset, *data, hdrsize);
	}
	if (datasize) {
	    proto_tree_add_text(tree, NullTVB, *offset, datasize, "Data");
	    BUMP (*offset, *data, datasize);
	}
	if (extrasize) {
	    proto_tree_add_text(tree, NullTVB, *offset, extrasize, "Extra data");
	    BUMP (*offset, *data, extrasize);
	}
	if (padding) {
    	    proto_tree_add_text(pt, NullTVB, *offset, padding, "padding");
	    BUMP (*offset, *data, padding);
	}
}

void
decode_event (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    int     	    hours, minutes, seconds, fraction, padding, length;
    unsigned long   timestamp;
    const u_char    *msgend;

    padding = 3 - (msglen + 3) % 4;
    msgend = *data + msglen;
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Event ID: %hd", **data);
    proto_tree_add_text(pt, NullTVB, *offset+1, 1, "Event context: %hd", *((*data)+1));
    proto_tree_add_text(pt, NullTVB, *offset+2, 2, "reserved");
    BUMP (*offset, *data, 4);
    timestamp = pntohl ((unsigned long *)(*data));
    hours = timestamp /(100000 * 60 *60);
    minutes = (timestamp / (100000 * 60)) % 60;
    seconds = (timestamp / 100000) % 60;
    fraction = timestamp % 100000;
    proto_tree_add_text(pt, NullTVB, *offset, 4, "Timestamp: %d:%02d:%02d.%05d", hours, minutes, seconds, fraction);
    BUMP (*offset, *data, 4);
    if (*data < msgend) {
    	length = msgend - *data;
    	proto_tree_add_text (pt, NullTVB, *offset, length, "Data (%d bytes)", length);
	BUMP (*offset, *data, length);
    }
    if (padding) {
    	proto_tree_add_text (pt, NullTVB, *offset, padding, "padding");
	BUMP (*offset, *data, padding);
    }
}

void
cmd_init (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    char    	*ptr;
    
    if (*data >= dataend)
    	return;
    if (**data == 0)
    	ptr = "Always initialize";
    else
    	ptr = "Initialize if not previously initialized";
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Mode: %s", ptr);
    proto_tree_add_text(pt, NullTVB, *offset+1, 3, "reserved");
    BUMP (*offset, *data, 4);
}

void
eventnum (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    unsigned char   event = **data;
    
    if (event)
    	proto_tree_add_text(pt, NullTVB, *offset, 1, "Event number: %hd", event);
    else
    	proto_tree_add_text(pt, NullTVB, *offset, 1, "Event numbers: All");
    proto_tree_add_text(pt, NullTVB, *offset+1, 3, "padding");
    BUMP (*offset, *data, 4);
}

void
resp_time (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    int     hours, minutes, seconds, fraction;
    union {
    	unsigned int		lng[2];
	guint64			lnglng;
    } ts;
    unsigned int    timestamp;
    unsigned char   date[45];
   
    ts.lng[1] = pntohl ((unsigned int *)(*data));
    ts.lng[0] = pntohl ((unsigned int *)((*data)+4));
    timestamp = ts.lnglng / 100000L;
    strncpy (date, ctime((time_t*)&timestamp), sizeof(date));
    date[strlen(date)-1] = 0x00;
    proto_tree_add_text(pt, NullTVB, *offset, 8, "Date/Time: %s", date);
    timestamp = ts.lng[0];
    hours = timestamp /(100000 * 60 *60);
    minutes = (timestamp / (100000 * 60)) % 60;
    seconds = (timestamp / 100000) % 60;
    fraction = timestamp % 100000;
    proto_tree_add_text(pt, NullTVB, *offset+4, 4, "Timestamp: %d:%02d:%02d.%05d", hours, minutes, seconds, fraction);
    BUMP (*offset, *data, 8);
}

void
cmd_setfilt (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    int     	    flag = pntohl ((unsigned int *)((*data)+4));
    int     	    length, padding;
    unsigned char   mode[30];
    
    length =  *((*data)+4) + *((*data)+5) + pntohs ((unsigned short *)((*data)+6));
    if (flag)
    	strcpy (mode, "Pass");
    else
    	strcpy (mode, "Block");
    if (length == 0)
    	strcat (mode, " all");
    proto_tree_add_text(pt, NullTVB, *offset, 4, "Pass/Block flag: %s", mode);
    proto_tree_add_text(pt, NullTVB, *offset+4, 4, "Length of Pattern & Mask: %d", length);
    BUMP (*offset, *data, 8);
    if (length) {
    	proto_tree_add_text(pt, NullTVB, *offset, length * 2, "discarded data");
    	BUMP (*offset, *data, length * 2);
    }
    padding = 3 - (length * 2 + 3) % 4;
    if (padding) {
	proto_tree_add_text(pt, NullTVB, *offset+1, 3, "padding");
	BUMP (*offset, *data, padding);
    }
}

void
cmd_ioctl (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    unsigned int    ioctl;
    int     	    i;

    ioctl = pntohl ((unsigned int *)(*data));
    for (i = 0; i < SIZEOF(ioctls); i++) {
    	if (ioctls[i].value == ioctl)
	    break;
    }
    if (i >= SIZEOF(ioctls))
    	i = SIZEOF(ioctls) - 1;
    proto_tree_add_text(pt, NullTVB, *offset, 4, "IOCTL: %s", ioctls[i].strptr);
    BUMP (*offset, *data, 4);
    proto_tree_add_text(pt, NullTVB, *offset, dataend - *data, "Data");
    BUMP (*offset, *data, dataend - *data);
}

void
cmd_addfilt (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    int     	blocks, i, length;
    char    	*ptr;
    char    	pass[] = ".... ...1 = Conforming messages are passed";
    char    	block[] = ".... ...0 = Conforming messages are blocked";
    char    	active[] = ".... ..1. = The filter is active";
    char    	inactive[] = ".... ..0. = The filter is inactive";

    item = proto_tree_add_text(pt, NullTVB, *offset, 1, "Flags");
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    if (**data & FILTER_PASS_FLAG)
    	ptr = pass;
    else
    	ptr = block;
    proto_tree_add_text(tree, NullTVB, *offset, 1, ptr);
    if (**data & FILTER_ACTIVE_FLAG)
    	ptr = active;
    else
    	ptr = inactive;
    proto_tree_add_text(tree, NullTVB, *offset, 1, ptr);
    BUMP (*offset, *data, 1);
    blocks = **data;
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Number of filter blocks = %d", blocks);
    proto_tree_add_text(pt, NullTVB, *offset+1, 6, "reserved");
    BUMP (*offset, *data, 7);
    for (i = 1; i <= blocks; i++) {
	length = pntohs ((unsigned short *)((*data)+2)) * 2 + 8;
	length += 3 - (length + 3) % 4;
	item = proto_tree_add_text(pt, NullTVB, *offset, length, "Filter block %d", i);
	tree = proto_item_add_subtree (item, ett_gryphon_cmd_filter_block);
	filter_block (src, data, dataend, offset, msglen, tree);
    }
}

void
resp_addfilt (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Filter handle: %hd", **data);
    proto_tree_add_text(pt, NullTVB, *offset+1, 3, "reserved");
    BUMP (*offset, *data, 4);
}

void
cmd_modfilt (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    unsigned char   action;
    int     	    i;

    if (**data)
    	proto_tree_add_text(pt, NullTVB, *offset, 1, "Filter handle: %hd", **data);
    else
    	proto_tree_add_text(pt, NullTVB, *offset, 1, "Filter handles: all");
    action = *((*data) + 1);
    for (i = 0; i < SIZEOF(filtacts); i++) {
    	if (filtacts[i].value == action)
	    break;
    }
    if (i >= SIZEOF(filtacts))
    	i = SIZEOF(filtacts) - 1;
    proto_tree_add_text(pt, NullTVB, *offset+1, 1, "Action: %s filter", filtacts[i].strptr);
    proto_tree_add_text(pt, NullTVB, *offset+2, 2, "reserved");
    BUMP (*offset, *data, 4);
}

void
resp_filthan (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    int     	handles = **data;
    int     	i, padding;
    
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Number of filter handles: %d", handles);
    for (i = 1; i <= handles; i++){
    	proto_tree_add_text(pt, NullTVB, *offset+i, 1, "Handle %d: %hd", i, *(*data+i));
    }
    padding = 3 - (handles + 1 + 3) % 4;
    if (padding)
    	proto_tree_add_text(pt, NullTVB, *offset+1+handles, padding, "padding");
    BUMP (*offset, *data, 1+handles+padding);
}

void
dfiltmode (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    int     	    i;
    unsigned char   mode;
    
    mode = **data;
    for (i = 0; i < SIZEOF(modes); i++) {
    	if (dmodes[i].value == mode)
	    break;
    }
    if (i >= SIZEOF(dmodes))
    	i = SIZEOF(dmodes) - 1;
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Filter mode: %s", dmodes[i].strptr);
    proto_tree_add_text(pt, NullTVB, *offset+1, 3, "reserved");
    BUMP (*offset, *data, 4);
}

void
filtmode (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    int     	    i;
    unsigned char   mode;
    
    mode = **data;
    for (i = 0; i < SIZEOF(modes); i++) {
    	if (modes[i].value == mode)
	    break;
    }
    if (i >= SIZEOF(modes))
    	i = SIZEOF(modes) - 1;
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Filter mode: %s", modes[i].strptr);
    proto_tree_add_text(pt, NullTVB, *offset+1, 3, "reserved");
    BUMP (*offset, *data, 4);
}

void
resp_events (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    int     	    i;
    proto_tree	    *tree;
    proto_item	    *item;
    
    i = 1;
    while (*data < dataend) {
    	item = proto_tree_add_text(pt, NullTVB, *offset, 20, "Event %d:", i);
	tree = proto_item_add_subtree (item, ett_gryphon_cmd_events_data);
	proto_tree_add_text(tree, NullTVB, *offset, 1, "Event ID: %hd", **data);
	proto_tree_add_text(tree, NullTVB, *offset+1, 19, "Event name: %s", (*data)+1);
	BUMP (*offset, *data, 20);
	i++;
    }
}

void
cmd_register (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    char    	string[33];
    
    MEMCPY (string, *data, 16);
    proto_tree_add_text(pt, NullTVB, *offset, 16, "Username: %s", string);
    BUMP (*offset, *data, 16);
    MEMCPY (string, *data, 32);
    proto_tree_add_text(pt, NullTVB, *offset, 32, "Password: %s", string);
    BUMP (*offset, *data, 32);
}

void
resp_register (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Client ID: %hd", (*data)[0]);
    proto_tree_add_text(pt, NullTVB, *offset+1, 1, "Privileges: %hd", (*data)[1]);
    proto_tree_add_text(pt, NullTVB, *offset+2, 2, "reserved");
    BUMP (*offset, *data, 4);
}

void
resp_config (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    proto_item	*ti;
    proto_tree	*ft;
    char    	string[33];
    int     	devices;
    int     	i, j, x;
    
    static const value_string protocol_types[] = {
	{GDUMMY * 256 + GDGDMARKONE,	"Dummy device driver"},
	{GCAN * 256 + G82527,	    	"CAN, 82527 subtype"},
	{GCAN * 256 + GSJA1000,     	"CAN, SJA1000 subtype"},
	{GCAN * 256 + G82527SW,     	"CAN, 82527 single wire subtype"},
	{GJ1850 * 256 + GHBCCPAIR,  	"J1850, HBCC subtype"},
	{GJ1850 * 256 + GDLC,	    	"J1850, GM DLC subtype"},
	{GJ1850 * 256 + GCHRYSLER,  	"J1850, Chrysler subtype"},
	{GJ1850 * 256 + GDEHC12,    	"J1850, DE HC12 KWP/BDLC subtype"},
	{GKWP2000,  	    	    	"Keyword protocol 2000"},
	{GHONDA * 256 + GDGHC08,    	"Honda UART, DG HC08 subtype"},
	{GFORDUBP * 256 + GDGUBP08, 	"Ford UBP, DG HC08 subtype"},
	{-1,	    	    	    	"- unknown -"},
    };




   MEMCPY (string, *data, 20);
    proto_tree_add_text(pt, NullTVB, *offset, 20, "Device name: %s", string);
    BUMP (*offset, *data, 20);

    MEMCPY (string, *data, 8);
    proto_tree_add_text(pt, NullTVB, *offset, 8, "Device version: %s", string);
    BUMP (*offset, *data, 8);

    MEMCPY (string, *data, 20);
    proto_tree_add_text(pt, NullTVB, *offset, 20, "Device serial number: %s", string);
    BUMP (*offset, *data, 20);

    devices = **data;
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Number of channels: %d", devices);
    proto_tree_add_text(pt, NullTVB, *offset+1, 15, "reserved");
    BUMP (*offset, *data, 16);
    for (i = 1; i <= devices; i++) {
	ti = proto_tree_add_text(pt, NullTVB, *offset, 80, "Channel %d:", i);
	ft = proto_item_add_subtree(ti, ett_gryphon_cmd_config_device);
	MEMCPY (string, *data, 20);
	proto_tree_add_text(ft, NullTVB, *offset, 20, "Driver name: %s", string);
	BUMP (*offset, *data, 20);

	MEMCPY (string, *data, 8);
	proto_tree_add_text(ft, NullTVB, *offset, 8, "Driver version: %s", string);
	BUMP (*offset, *data, 8);

	MEMCPY (string, *data, 24);
	proto_tree_add_text(ft, NullTVB, *offset, 24, "device security string: %s", string);
	BUMP (*offset, *data, 24);

	MEMCPY (string, *data, 20);
	proto_tree_add_text(ft, NullTVB, *offset, 20, "Hardware serial number: %s", string);
	BUMP (*offset, *data, 20);

    	x = pntohs ((unsigned short *)*data);
	for (j = 0; j < SIZEOF(protocol_types); j++) {
	    if (protocol_types[j].value == x)
	    	break;
	}
	if (j >= SIZEOF(protocol_types))
	    j = SIZEOF(protocol_types) -1;
	proto_tree_add_text(ft, NullTVB, *offset, 2, "Protocol type & subtype: %s", protocol_types[j].strptr);
	BUMP (*offset, *data, 2);

	proto_tree_add_text(ft, NullTVB, *offset, 1, "Channel ID: %hd", **data);
	proto_tree_add_text(ft, NullTVB, *offset+1, 5, "reserved");
	BUMP (*offset, *data, 6);
    }
}

void
cmd_sched (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    proto_item	    *item, *item1;
    proto_tree	    *tree, *tree1;
    unsigned int    i, x, length;
    unsigned char   def_chan = *((*data)-9);
    char    	    *ptr;
    char    	    crit[] = ".... ...1 = Critical scheduler";
    char    	    norm[] = ".... ...0 = Normal scheduler";
    
    x = pntohl ((unsigned int *)*data);
    if (x == 0xFFFFFFFF)
    	proto_tree_add_text(pt, NullTVB, *offset, 4, "Number of iterations: infinite");
    else
    	proto_tree_add_text(pt, NullTVB, *offset, 4, "Number of iterations: %d", x);
    BUMP (*offset, *data, 4);
    x = pntohl ((unsigned int *)*data);
    item = proto_tree_add_text(pt, NullTVB, *offset, 4, "Flags");
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    ptr = x & 1 ? crit : norm;
    proto_tree_add_text(tree, NullTVB, *offset, 4, ptr, NULL);
    BUMP (*offset, *data, 4);
    i = 1;
    while (*data < dataend) {
    	length = 16 + (*data)[16] + pntohs ((unsigned short *)((*data)+18)) + (*data)[20] + 16;
	length += 3 - (length + 3) % 4;
	item = proto_tree_add_text(pt, NullTVB, *offset, length, "Message %d", i);
	tree = proto_item_add_subtree (item, ett_gryphon_cmd_sched_data);
	x = pntohl ((unsigned int *)*data);
	proto_tree_add_text(tree, NullTVB, *offset, 4, "Sleep: %d milliseconds", x);
	BUMP (*offset, *data, 4);
	x = pntohl ((unsigned int *)*data);
	proto_tree_add_text(tree, NullTVB, *offset, 4, "Transmit count: %d", x);
	BUMP (*offset, *data, 4);
	x = pntohl ((unsigned int *)*data);
	proto_tree_add_text(tree, NullTVB, *offset, 4, "Transmit period: %d milliseconds", x);
	BUMP (*offset, *data, 4);
	proto_tree_add_text(tree, NullTVB, *offset, 2, "reserved flags");
	x = *((*data)+2);
	if (x == 0)
	    x = def_chan;
	proto_tree_add_text(tree, NullTVB, *offset+2, 1, "Channel: %d", x);
	proto_tree_add_text(tree, NullTVB, *offset+3, 1, "reserved");
	BUMP (*offset, *data, 4);
	item1 = proto_tree_add_text(tree, NullTVB, *offset, length, "Message");
	tree1 = proto_item_add_subtree (item1, ett_gryphon_cmd_sched_cmd);
   	decode_data (src, data, dataend, offset, msglen, tree1);
	i++;
    }
}

void
resp_blm_data (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    int     hours, minutes, seconds, fraction, i, x, fract;
    unsigned long   timestamp;
    char    *fields[] = {
    	"Bus load average: %d.%02d%%",
    	"Current bus load: %d.%02d%%",
    	"Peak bus load: %d.%02d%%",
    	"Historic peak bus load: %d.%02d%%"
    };

    timestamp = pntohl ((unsigned long *)(*data));
    hours = timestamp /(100000 * 60 *60);
    minutes = (timestamp / (100000 * 60)) % 60;
    seconds = (timestamp / 100000) % 60;
    fraction = timestamp % 100000;
    proto_tree_add_text(pt, NullTVB, *offset, 4, "Timestamp: %d:%02d:%02d.%05d", hours, minutes, seconds, fraction);
    BUMP (*offset, *data, 4);
    for (i = 0; i < SIZEOF(fields); i++){
    	x = pntohs ((unsigned short *)(*data));
	fract = x % 100;
	x /= 100;
	proto_tree_add_text(pt, NullTVB, *offset, 2, fields[i], x, fract);
	BUMP (*offset, *data, 2);
    }
}

void
resp_blm_stat (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
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

    resp_blm_data (src, data, dataend, offset, msglen, pt);
    for (i = 0; i < SIZEOF(fields); i++){
    	x = pntohl ((unsigned int *)(*data));
	proto_tree_add_text(pt, NullTVB, *offset, 4, fields[i], x);
	BUMP (*offset, *data, 4);
    }
}

void
cmd_addresp (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    int     	blocks, responses, old_handle, i, length;
    int     	action, actionType, actionValue;
    char    	*ptr;
    char    	active[] = ".... ..1. = The response is active";
    char    	inactive[] = ".... ..0. = The response is inactive";

    actionType = 0;
    item = proto_tree_add_text(pt, NullTVB, *offset, 1, "Flags");
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    if (**data & FILTER_ACTIVE_FLAG)
    	ptr = active;
    else
    	ptr = inactive;
    proto_tree_add_text(tree, NullTVB, *offset, 1, ptr, NULL);
    BUMP (*offset, *data, 1);
    blocks = **data;
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Number of filter blocks = %d", blocks);
    BUMP (*offset, *data, 1);
    responses = **data;
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Number of response blocks = %d", responses);
    BUMP (*offset, *data, 1);
    old_handle = **data;
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Old handle = %d", old_handle);
    BUMP (*offset, *data, 1);
    action = **data;
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
    item = proto_tree_add_text(pt, NullTVB, *offset, 1, "Action = %s", ptr);
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    if (action & FR_DEACT_AFTER_PER && !(action & FR_DELETE)){
    	proto_tree_add_text(tree, NullTVB, *offset, 1,
	    	"1.0. .... Deactivate this response after the specified period following a conforming message");
    }
    if (action & FR_DEACT_ON_EVENT && !(action & FR_DELETE)){
    	proto_tree_add_text(tree, NullTVB, *offset, 1,
	    	".10. .... Deactivate this response for a conforming message");
    }
    if (action & FR_DEACT_AFTER_PER && action & FR_DELETE){
    	proto_tree_add_text(tree, NullTVB, *offset, 1,
	    	"1.1. .... Delete this response after the specified period following a conforming message");
    }
    if (action & FR_DEACT_ON_EVENT && action & FR_DELETE){
    	proto_tree_add_text(tree, NullTVB, *offset, 1,
	    	".11. .... Delete this response for a conforming message");
    }
    actionValue = pntohs ((unsigned short *)((*data)+2));
    if (actionValue) {
	if (action & FR_PERIOD_MSGS){
    	    ptr = "...1 .... The period is in frames";
	    actionType = 1;
	} else {
    	    ptr = "...0 .... The period is in 0.01 seconds";
	    actionType = 0;
	}
    	proto_tree_add_text(tree, NullTVB, *offset, 1, ptr, NULL);
    }
    BUMP (*offset, *data, 1);
    proto_tree_add_text(pt, NullTVB, *offset, 1, "reserved");
    BUMP (*offset, *data, 1);
    if (actionValue) {
    	if (actionType == 1) {
	    proto_tree_add_text(tree, NullTVB, *offset, 2, "Period: %d messages", actionValue);
	} else {
	    proto_tree_add_text(tree, NullTVB, *offset, 2, "Period: %d.%02d seconds", actionValue/100, actionValue%100);
	}
    }
    BUMP (*offset, *data, 2);
    for (i = 1; i <= blocks; i++) {
	length = pntohs ((unsigned short *)((*data)+2)) * 2 + 8;
	length += 3 - (length + 3) % 4;
	item = proto_tree_add_text(pt, NullTVB, *offset, length, "Filter block %d", i);
	tree = proto_item_add_subtree (item, ett_gryphon_cmd_filter_block);
	filter_block (src, data, dataend, offset, msglen, tree);
    }
    for (i = 1; i <= responses; i++) {
	length = pntohs ((unsigned short *)((*data)+4)) + 8;
	length += 3 - (length + 3) % 4;
	item = proto_tree_add_text(pt, NullTVB, *offset, length, "Response block %d", i);
	tree = proto_item_add_subtree (item, ett_gryphon_cmd_response_block);
    	dissector((*data)-*offset, *offset, NULL, tree);
    	BUMP (*offset, *data, length);
    }
}

void
resp_addresp (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    if (*data < dataend) {
	proto_tree_add_text(pt, NullTVB, *offset, 1, "Response handle: %hd", **data);
	proto_tree_add_text(pt, NullTVB, *offset+1, 3, "reserved");
	BUMP (*offset, *data, 4);
    }
}

void
cmd_modresp (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    unsigned char   action;
    unsigned char   dest = *((*data)-5);
    int     	    i;

    if (**data)
    	proto_tree_add_text(pt, NullTVB, *offset, 1, "Response handle: %hd", **data);
    else if (dest)
    	proto_tree_add_text(pt, NullTVB, *offset, 1, "Response handles: all on channel %hd", dest);
    else
    	proto_tree_add_text(pt, NullTVB, *offset, 1, "Response handles: all");
    action = *((*data) + 1);
    for (i = 0; i < SIZEOF(filtacts); i++) {
    	if (filtacts[i].value == action)
	    break;
    }
    if (i >= SIZEOF(filtacts))
    	i = SIZEOF(filtacts) - 1;
    proto_tree_add_text(pt, NullTVB, *offset+1, 1, "Action: %s response", filtacts[i].strptr);
    proto_tree_add_text(pt, NullTVB, *offset+2, 2, "reserved");
    BUMP (*offset, *data, 4);
}

void
resp_resphan (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    int     	handles = **data;
    int     	i, padding;
    
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Number of response handles: %d", handles);
    for (i = 1; i <= handles; i++){
    	proto_tree_add_text(pt, NullTVB, *offset+i, 1, "Handle %d: %hd", i, *(*data+i));
    }
    padding = 3 - (handles + 1 + 3) % 4;
    if (padding)
    	proto_tree_add_text(pt, NullTVB, *offset+1+handles, padding, "padding");
    BUMP (*offset, *data, 1+handles+padding);
}

void
resp_sched (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    unsigned int    id = pntohl ((unsigned int *)(*data));
    proto_tree_add_text(pt, NullTVB, *offset, 4, "Transmit schedule ID: %d", id);
    BUMP (*offset, *data, 4);
}

void
cmd_desc (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    u_char  string[81];
    
    proto_tree_add_text(pt, NullTVB, *offset, 4, "Program size: %d bytes", pntohl ((unsigned int *)(*data)));
    BUMP (*offset, *data, 4);
    strncpy (string, *data, 32);
    string[32] = 0;
    proto_tree_add_text(pt, NullTVB, *offset, 32, "Program name: %s", string);
    BUMP (*offset, *data, 32);
    strncpy (string, *data, 80);
    string[80] = 0;
    proto_tree_add_text(pt, NullTVB, *offset, 80, "Program description: %s", string);
    BUMP (*offset, *data, 80);
}

void
resp_desc (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt)
{
    proto_item	*item;
    proto_tree	*tree;
    char    	*ptr;
    char    	missing[] = ".... ...0 = The program is not present";
    char    	present[] = ".... ...1 = The program is already present";
    
    item = proto_tree_add_text(pt, NullTVB, *offset, 1, "Flags");
    tree = proto_item_add_subtree (item, ett_gryphon_flags);
    if (**data & 1)
    	ptr = present;
    else
    	ptr = missing;
    proto_tree_add_text(tree, NullTVB, *offset, 1, ptr);
    proto_tree_add_text(pt, NullTVB, *offset+1, 1, "Handle: %hd", (*data)[1]);
    proto_tree_add_text(pt, NullTVB, *offset+2, 2, "reserved");
    BUMP (*offset, *data, 4);
}

void
cmd_upload (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    unsigned int    length;
    
    proto_tree_add_text(pt, NullTVB, *offset, 2, "Block number: %d", pntohs ((unsigned short *)(*data)));
    BUMP (*offset, *data, 4);
    proto_tree_add_text(pt, NullTVB, *offset+2, 1, "Handle: %hd", (*data)[2]);
    BUMP (*offset, *data, 3);
    length = *data - dataend;
    proto_tree_add_text(pt, NullTVB, *offset, length, "Data (%d bytes)", length);
    BUMP (*offset, *data, length);
    length = 3 - (length + 3) % 4;
    if (length) {
	proto_tree_add_text(pt, NullTVB, *offset, length, "padding");
	BUMP (*offset, *data, length);
    }
}

void
cmd_delete (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    u_char  string[33];
    
    strncpy (string, *data, 32);
    string[32] = 0;
    proto_tree_add_text(pt, NullTVB, *offset, 32, "Program name: %s", string);
    BUMP (*offset, *data, 32);
}

void
cmd_list (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Block number: %hd", (*data)[0]);
    proto_tree_add_text(pt, NullTVB, *offset+1, 3, "reserved");
    BUMP (*offset, *data, 4);
}

void
resp_list (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    proto_item	*item;
    proto_tree	*tree;
    u_char  string[81];
    unsigned int    i, count;
    
    count = (*data)[0];
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Number of programs in this response: %d", count);
    proto_tree_add_text(pt, NullTVB, *offset+1, 1, "reserved");
    BUMP (*offset, *data, 2);
    proto_tree_add_text(pt, NullTVB, *offset, 2, "Number of remaining programs: %d", pntohs ((unsigned short *)(*data)));
    BUMP (*offset, *data, 2);
    for (i = 1; i <= count; i++) {
	item = proto_tree_add_text(pt, NullTVB, *offset, 112, "Program %d", i);
	tree = proto_item_add_subtree (item, ett_gryphon_pgm_list);
	strncpy (string, *data, 32);
	string[32] = 0;
	proto_tree_add_text(tree, NullTVB, *offset, 32, "Name: %s", string);
	BUMP (*offset, *data, 32);
	strncpy (string, *data, 80);
	string[80] = 0;
	proto_tree_add_text(tree, NullTVB, *offset, 80, "Description: %s", string);
	BUMP (*offset, *data, 80);
    }
}

void
cmd_start (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    u_char  	    string[120];
    unsigned int    length;
    
    cmd_delete (src, data, dataend, offset, msglen, pt);
    strncpy (string, *data, 119);
    string[119] = 0;
    length = strlen (string) + 1;
    proto_tree_add_text(pt, NullTVB, *offset, length, "Arguments: %s", string);
    BUMP (*offset, *data, length);
    length = 3 - (length + 3) % 4;
    if (length) {
	proto_tree_add_text(pt, NullTVB, *offset, length, "padding");
	BUMP (*offset, *data, length);
    }
}

void
resp_start (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Channel (Client) number: %hd", (*data)[0]);
    proto_tree_add_text(pt, NullTVB, *offset+1, 3, "reserved");
    BUMP (*offset, *data, 4);
}

void
resp_status (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    proto_item	*item;
    proto_tree	*tree;
    unsigned int    i, copies, length;
    
    copies = (*data)[0];
    item = proto_tree_add_text(pt, NullTVB, *offset, 1, "Number of running copies: %d", copies);
    tree = proto_item_add_subtree (item, ett_gryphon_pgm_status);
    BUMP (*offset, *data, 1);
    if (copies) {
	for (i = 1; i <= copies; i++) {
	    proto_tree_add_text(tree, NullTVB, *offset, 1, "Program %d channel (client) number %hd", i, (*data)[0]);
    	    BUMP (*offset, *data, 1);
	}
    }
    length = 3 - (copies + 1 + 3) % 4;
    if (length) {
	proto_tree_add_text(pt, NullTVB, *offset, length, "padding");
	BUMP (*offset, *data, length);
    }
}

void
cmd_options (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    proto_item	*item;
    proto_tree	*tree;
    unsigned int    i, size, padding, option, option_length, option_value;
    unsigned char   *string, *string1;
    
    item = proto_tree_add_text(pt, NullTVB, *offset, 1, "Handle: %hd", **data);
    item = proto_tree_add_text(pt, NullTVB, *offset+1, 3, "reserved");
    BUMP (*offset, *data, 4);
    for (i = 1; *data <= dataend; i++) {
    	size = (*data)[1] + 2;
	padding = 3 - ((size + 3) %4);
	item = proto_tree_add_text(pt, NullTVB, *offset, size + padding, "Option number %d", i);
    	tree = proto_item_add_subtree (item, ett_gryphon_pgm_options);
	option = **data;
	option_length = (*data)[1];
	switch (option_length) {
	case 1:
	    option_value = (*data)[2];
	    break;
	case 2:
	    option_value = pntohs ((unsigned short *)((*data)+2));
	    break;
	case 4:
	    option_value = pntohl ((unsigned int *)((*data)+2));
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
	proto_tree_add_text(tree, NullTVB, *offset, 1, "%s", string);
	proto_tree_add_text(tree, NullTVB, *offset+2, option_length, "%s", string1);
	if (padding)
	    proto_tree_add_text(tree, NullTVB, *offset+option_length+2, padding, "padding");
    	BUMP (*offset, *data, size + padding);
    }
}

void
speed (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    
    proto_tree_add_text(pt, NullTVB, *offset, 1, "Baud rate index: %hd", (*data)[0]);
    proto_tree_add_text(pt, NullTVB, *offset+1, 3, "reserved");
    BUMP (*offset, *data, 4);
}

void
filter_block (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    int     length, type, i, operator, padding;
    
    proto_tree_add_text(pt, NullTVB, *offset, 2, "Filter field starts at byte %d", pntohs ((unsigned short *)(*data)));
    length = pntohs ((unsigned short *)((*data)+2));
    proto_tree_add_text(pt, NullTVB, *offset+2, 2, "Filter field is %d bytes long", length);
    type = *((*data)+4);
    for (i = 0; i < SIZEOF(filter_data_types); i++) {
    	if (filter_data_types[i].value == type)
	    break;
    }
    if (i >= SIZEOF(filter_data_types))
    	i = SIZEOF(filter_data_types) - 1;
    proto_tree_add_text(pt, NullTVB, *offset+4, 1, "Filtering on %s", filter_data_types[i].strptr);

    operator = *((*data)+5);
    for (i = 0; i < SIZEOF(operators); i++) {
    	if (operators[i].value == operator)
	    break;
    }
    if (i >= SIZEOF(operators))
    	i = SIZEOF(operators) - 1;
    proto_tree_add_text(pt, NullTVB, *offset+5, 1, "Type of comparison: %s", operators[i].strptr);
    proto_tree_add_text(pt, NullTVB, *offset+6, 2, "reserved");
    BUMP (*offset, *data, 8);
    
    if (operator == BIT_FIELD_CHECK) {
    	proto_tree_add_text(pt, NullTVB, *offset, length, "Pattern");
    	proto_tree_add_text(pt, NullTVB, *offset+length, length, "Mask");
    } else {
    	switch (length) {
	case 1:
    	    proto_tree_add_text(pt, NullTVB, *offset, 1, "Value: %hd", **data);
	    break;
	case 2:
   	    proto_tree_add_text(pt, NullTVB, *offset, 2, "Value: %d", pntohs ((unsigned short *)(*data)));
	    break;
	case 4:
   	    proto_tree_add_text(pt, NullTVB, *offset, 4, "Value: %dl", pntohl ((unsigned long *)(*data)));
	    break;
	default:
   	    proto_tree_add_text(pt, NullTVB, *offset, length, "Value");
	}
    }
    BUMP (*offset, *data, length * 2);
    padding = 3 - (length * 2 + 3) % 4;
    if (padding) {
    	proto_tree_add_text(pt, NullTVB, *offset, padding, "padding");
	BUMP (*offset, *data, padding);
    }
}

void
blm_mode (int src, const u_char **data, const u_char *dataend, int *offset, int msglen, proto_tree *pt) {
    
    char    *mode, line[50];
    int     x, y, seconds;
    
    x = pntohl ((unsigned long *)(*data));
    y = pntohl ((unsigned long *)((*data)+4));
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
    proto_tree_add_text(pt, NullTVB, *offset, 4, "Mode: %s", mode);
    BUMP (*offset, *data, 4);
    proto_tree_add_text(pt, NullTVB, *offset, 4, line, NULL);
    BUMP (*offset, *data, 4);
}

DLLEXPORT void
plugin_init(plugin_address_table_t *pat)
{
    static hf_register_info hf[] = {
	{ &hf_gryph_src,
	{ "Source",           "gryph.src", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	"" }},
	{ &hf_gryph_srcchan,
	{ "Source channel",   "gryph.srcchan", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	"" }},
	{ &hf_gryph_dest,
	{ "Destination",      "gryph.dest", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	"" }},
	{ &hf_gryph_destchan,
	{ "Destination channel", "gryph.dstchan", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	"" }},
	{ &hf_gryph_type,
	{ "Frame type",       "gryph.type", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	"" }},
	{ &hf_gryph_cmd,
	{ "Command",          "gryph.cmd.cmd", FT_UINT8, BASE_DEC, NULL, 0x0,
	    	"" }},
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
    plugin_address_table_init(pat);
    dfilter_cleanup();
    proto_gryphon = proto_register_protocol("DG Gryphon Protocol", "gryphon");
    proto_register_field_array(proto_gryphon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    dfilter_init();
}
