/* packet-csm-encaps.c
 * Routines for CSM_ENCAPS dissection
 * Copyright 2005, Angelo Bannack <angelo.bannack@siemens.com>
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2003 Gerald Combs
 *
 * Copied from packet-ans.c
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
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif



#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/tap.h>

#include <epan/proto.h>
#include <etypes.h>





#define OPCODE_NOOP	             0x0000
#define OPCODE_CONTROL_PACKET    0x0001
#define OPCODE_RELIABLE_DATA     0x0002


#define CSM_ENCAPS_CTRL_ACK		         0x80
#define CSM_ENCAPS_CTRL_ACK_SUPRESS		 0x40
#define CSM_ENCAPS_CTRL_ACK_TO_HOST	     0x20
#define CSM_ENCAPS_CTRL_ENDIAN		     0x01



#define CSM_ENCAPS_TYPE_CHANGE			     0x00
#define CSM_ENCAPS_TYPE_QUERY			     0x01
#define CSM_ENCAPS_TYPE_RESPONSE		     0x02
#define CSM_ENCAPS_TYPE_INDICATION		     0x03
#define CSM_ENCAPS_TYPE_QUERY_RESPONSE	     0x04
#define CSM_ENCAPS_TYPE_INDICATION_RESPONSE  0x05


const value_string opcode_vals[] = {
	{ OPCODE_NOOP,           "No Operation" },
	{ OPCODE_CONTROL_PACKET, "Control Packet" },
	{ OPCODE_RELIABLE_DATA,  "Reliable Data Transfer" },
	{ 0,       NULL }
};

const value_string function_code_vals[] = {
	{0x0000, " "},
	{ 0,       NULL }
};


const value_string class_type_vals[] = {
	{ 0,      NULL }
};



const value_string exclusive_to_host_vals[] = {
	{ 0,      NULL }
};

const value_string exclusive_to_host_ct_vals[] = {
	{ 0,      NULL }
};


const value_string error_vals[] = {
	{ 0,      NULL }
};



/* Initialize the protocol and registered fields */
static int proto_csm_encaps            = -1;

static int hf_csm_encaps_opcode	          = -1;
static int hf_csm_encaps_seq              = -1;
static int hf_csm_encaps_ctrl             = -1;
static int hf_csm_encaps_ctrl_endian      = -1;
static int hf_csm_encaps_ctrl_ack         = -1;
static int hf_csm_encaps_ctrl_ack_supress = -1;
static int hf_csm_encaps_channel          = -1;
static int hf_csm_encaps_index            = -1;
static int hf_csm_encaps_length           = -1;
static int hf_csm_encaps_class            = -1;
static int hf_csm_encaps_type             = -1;
static int hf_csm_encaps_function_code    = -1;
static int hf_csm_encaps_reserved         = -1;
static int hf_csm_encaps_param_error      = -1;
static int hf_csm_encaps_param1           = -1;
static int hf_csm_encaps_param2           = -1;
static int hf_csm_encaps_param3           = -1;
static int hf_csm_encaps_param4           = -1;
static int hf_csm_encaps_param5           = -1;
static int hf_csm_encaps_param6           = -1;
static int hf_csm_encaps_param7           = -1;
static int hf_csm_encaps_param8           = -1;
static int hf_csm_encaps_param9           = -1;
static int hf_csm_encaps_param10          = -1;
static int hf_csm_encaps_param11          = -1;
static int hf_csm_encaps_param12          = -1;
static int hf_csm_encaps_param13          = -1;
static int hf_csm_encaps_param14          = -1;
static int hf_csm_encaps_param15          = -1;
static int hf_csm_encaps_param16          = -1;
static int hf_csm_encaps_param17          = -1;
static int hf_csm_encaps_param18          = -1;
static int hf_csm_encaps_param19          = -1;
static int hf_csm_encaps_param20          = -1;
static int hf_csm_encaps_param21          = -1;
static int hf_csm_encaps_param22          = -1;
static int hf_csm_encaps_param23          = -1;
static int hf_csm_encaps_param24          = -1;
static int hf_csm_encaps_param25          = -1;
static int hf_csm_encaps_param26          = -1;
static int hf_csm_encaps_param27          = -1;
static int hf_csm_encaps_param28          = -1;
static int hf_csm_encaps_param29          = -1;
static int hf_csm_encaps_param30          = -1;
static int hf_csm_encaps_param31          = -1;
static int hf_csm_encaps_param32          = -1;
static int hf_csm_encaps_param33          = -1;
static int hf_csm_encaps_param34          = -1;
static int hf_csm_encaps_param35          = -1;
static int hf_csm_encaps_param36          = -1;
static int hf_csm_encaps_param37          = -1;
static int hf_csm_encaps_param38          = -1;
static int hf_csm_encaps_param39          = -1;
static int hf_csm_encaps_param40          = -1;
static int hf_csm_encaps_param            = -1;


/* Initialize the subtree pointers */
static gint ett_csm_encaps         = -1;
static gint ett_csm_encaps_control = -1;

gchar *csm_fc(guint16 fc, guint16 ct);
gboolean csm_to_host(guint16 fc, guint16 ct);


/* returns the command name */
gchar *csm_fc(guint16 fc, guint16 ct)
{
    if (fc == 0x0000) {
        return g_strdup(val_to_str(ct, class_type_vals,
            "0x%04x"));
    } else {
        return g_strdup(val_to_str(fc, function_code_vals,
            "0x%04x"));
    }
}



/* check to see if the message is an exclusive message send to host */
gboolean csm_to_host(guint16 fc, guint16 ct)
{
	guint16 i=0;

	if (fc == 0x0000)
	{
		while (1)
		{
			if (exclusive_to_host_ct_vals[i].strptr == NULL)
				return FALSE;
			else if (exclusive_to_host_ct_vals[i].value == ct)
				return TRUE;
			i++;
		}
	}

	else
	{
		while (1)
		{
			if (exclusive_to_host_vals[i].strptr == NULL)
				return FALSE;
			else if (exclusive_to_host_vals[i].value == fc)
				return TRUE;
			i++;
		}
	}
	return FALSE;
}



/* Code to actually dissect the packets */
static void
dissect_csm_encaps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item  *ti, *subitem;
	proto_tree  *csm_encaps_tree = NULL;
	proto_tree  *csm_encaps_control_tree = NULL;
	guint16      function_code, channel, class_type;
	guint        control, type, sequence, length;
	guint        i;
	gboolean	show_error_param= FALSE;
	gchar       *str_function_name;


	function_code = tvb_get_letohs(tvb, 10);
	control = tvb_get_guint8(tvb, 3);

	class_type= tvb_get_guint8(tvb, 9);
	class_type= class_type<<8;
	class_type|= tvb_get_guint8(tvb, 8);

	type = tvb_get_guint8(tvb, 8);
	sequence = tvb_get_guint8(tvb, 2);
	length = tvb_get_guint8(tvb, 6);
	channel = tvb_get_ntohs(tvb, 4);


	if (CSM_ENCAPS_CTRL_ACK&control)
		show_error_param= FALSE;
	else
	{
		if (csm_to_host(function_code, class_type)) /* exclusive messages to host */
			show_error_param= FALSE;
		else
		{
			if (type == CSM_ENCAPS_TYPE_RESPONSE)
				show_error_param= TRUE;
			else
				show_error_param= FALSE;
		}
	}


	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CSM_ENCAPS");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);


		if (CSM_ENCAPS_CTRL_ACK&control)
		{
			if (CSM_ENCAPS_CTRL_ACK_TO_HOST&control)
				col_append_fstr(pinfo->cinfo, COL_INFO, "<-- ACK                                 Ch: 0x%04X, Seq: %2d (To Host)", channel, sequence);
			else
				col_append_fstr(pinfo->cinfo, COL_INFO, "--> ACK                                 Ch: 0x%04X, Seq: %2d (From Host)", channel, sequence);
		}
		else
		{
			str_function_name= csm_fc(function_code, class_type);
			if ((type == CSM_ENCAPS_TYPE_RESPONSE) || (csm_to_host(function_code, class_type)))
				col_append_fstr(pinfo->cinfo, COL_INFO, "<-- %-35s Ch: 0x%04X, Seq: %2d (To Host)", str_function_name, channel, sequence);
			else
				col_append_fstr(pinfo->cinfo, COL_INFO, "--> %-35s Ch: 0x%04X, Seq: %2d (From Host)", str_function_name, channel, sequence);
			g_free(str_function_name);
		}
	}


	if (tree) {
		ti = proto_tree_add_item(tree, proto_csm_encaps, tvb, 0, -1, FALSE);
		csm_encaps_tree = proto_item_add_subtree(ti, ett_csm_encaps);




		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_opcode, tvb, 0, 2, FALSE);
		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_seq, tvb, 2, 1, FALSE);

		subitem = proto_tree_add_uint(csm_encaps_tree, hf_csm_encaps_ctrl, tvb, 3, 1, control);
		csm_encaps_control_tree = proto_item_add_subtree(subitem, ett_csm_encaps_control);

		    proto_tree_add_boolean(csm_encaps_control_tree, hf_csm_encaps_ctrl_ack, tvb, 3, 1, control);
    		proto_tree_add_boolean(csm_encaps_control_tree, hf_csm_encaps_ctrl_ack_supress, tvb, 3, 1, control);
		    proto_tree_add_boolean(csm_encaps_control_tree, hf_csm_encaps_ctrl_endian, tvb, 3, 1, control);

		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_channel, tvb, 4, 2, FALSE);
		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_length, tvb, 6, 1, FALSE);
		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_index, tvb, 7, 1, FALSE);
		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_class, tvb, 9, 1, FALSE);
		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_type, tvb, 8, 1, FALSE);
		proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_function_code, tvb, 10, 2, TRUE);

		i=6;

		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_reserved, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length)
		{
			if (show_error_param)
				proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param_error, tvb, 12 + i-6, 2, TRUE);
			else
				proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param1, tvb, 12 + i-6, 2, TRUE);
			i+=2;
		}
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param2, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param3, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param4, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param5, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param6, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param7, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param8, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param9, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param10, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param11, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param12, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param13, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param14, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param15, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param16, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param17, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param18, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param19, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param20, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param21, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param22, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param23, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param24, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param25, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param26, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param27, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param28, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param29, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param30, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param31, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param32, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param33, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param34, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param35, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param36, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param37, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param38, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param39, tvb, 12 + i-6, 2, TRUE); i+=2;
		if (i<length) proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param40, tvb, 12 + i-6, 2, TRUE); i+=2;

		for (; i<length; i+=2)
			proto_tree_add_item(csm_encaps_tree, hf_csm_encaps_param, tvb, 12 + i-6, 2, TRUE);
	}
}


void
proto_register_csm_encaps(void)
{
	static struct true_false_string control_endian_bit      = {"Little Endian","Big Endian"};
	static struct true_false_string control_ack_bit         = {"ACK Packet", "Message Packet"};
	static struct true_false_string control_ack_supress_bit = {"ACK Supressed", "ACK Required"};


	static hf_register_info hf[] = {
		{ &hf_csm_encaps_opcode,
			{ "Opcode", "csm_encaps.opcode",
				FT_UINT16, BASE_HEX, VALS(opcode_vals), 0,
				"CSM_ENCAPS Opcode", HFILL }
		},
		{ &hf_csm_encaps_seq,
			{ "Sequence Number", "csm_encaps.seq_num",
				FT_UINT8, BASE_DEC, NULL, 0,
				"CSM_ENCAPS Sequence Number", HFILL }
		},

		{ &hf_csm_encaps_ctrl,
			{ "Control", "csm_encaps.ctrl",
				FT_UINT8, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Control", HFILL }
		},

		{ &hf_csm_encaps_ctrl_ack,
		   { "Packet Bit",	"csm_encaps.ctrl.ack",
		        FT_BOOLEAN, 8, TFS(&control_ack_bit), CSM_ENCAPS_CTRL_ACK,
		        "Message Packet/ACK Packet", HFILL }
		},
		{ &hf_csm_encaps_ctrl_ack_supress,
		   { "ACK Supress Bit",	"csm_encaps.ctrl.ack_supress",
		        FT_BOOLEAN, 8, TFS(&control_ack_supress_bit), CSM_ENCAPS_CTRL_ACK_SUPRESS,
		        "ACK Required/ACK Supressed", HFILL }
		},
		{ &hf_csm_encaps_ctrl_endian,
		   { "Endian Bit",	"csm_encaps.ctrl.endian",
		        FT_BOOLEAN, 8, TFS(&control_endian_bit), CSM_ENCAPS_CTRL_ENDIAN,
		        "Little Endian/Big Endian", HFILL }
		},


		{ &hf_csm_encaps_channel,
			{ "Channel Number", "csm_encaps.channel",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Channel Number", HFILL }
		},
		{ &hf_csm_encaps_index,
			{ "Index", "csm_encaps.index",
				FT_UINT8, BASE_DEC, NULL, 0,
				"CSM_ENCAPS Index", HFILL }
		},
		{ &hf_csm_encaps_length,
			{ "Length", "csm_encaps.length",
				FT_UINT8, BASE_DEC, NULL, 0,
				"CSM_ENCAPS Length", HFILL }
		},
		{ &hf_csm_encaps_class,
			{ "Class", "csm_encaps.class",
				FT_UINT8, BASE_DEC, NULL, 0,
				"CSM_ENCAPS Class", HFILL }
		},
		{ &hf_csm_encaps_type,
			{ "Type", "csm_encaps.type",
				FT_UINT8, BASE_DEC, NULL, 0,
				"CSM_ENCAPS Type", HFILL }
		},
		{ &hf_csm_encaps_function_code,
			{ "Function Code", "csm_encaps.function_code",
				FT_UINT16, BASE_HEX, VALS(function_code_vals), 0,
				"CSM_ENCAPS Function Code", HFILL }
		},
		{ &hf_csm_encaps_reserved,
			{ "Reserved", "csm_encaps.reserved",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Reserved", HFILL }
		},
		{ &hf_csm_encaps_param_error,
			{ "Parameter 1", "csm_encaps.param1",
				FT_UINT16, BASE_HEX, VALS(error_vals), 0,
				"CSM_ENCAPS Parameter 1", HFILL }
		},
		{ &hf_csm_encaps_param1,
			{ "Parameter 1", "csm_encaps.param1",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 1", HFILL }
		},
		{ &hf_csm_encaps_param2,
			{ "Parameter 2", "csm_encaps.param2",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 2", HFILL }
		},
		{ &hf_csm_encaps_param3,
			{ "Parameter 3", "csm_encaps.param3",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 3", HFILL }
		},
		{ &hf_csm_encaps_param4,
			{ "Parameter 4", "csm_encaps.param4",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 4", HFILL }
		},
		{ &hf_csm_encaps_param5,
			{ "Parameter 5", "csm_encaps.param5",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 5", HFILL }
		},
		{ &hf_csm_encaps_param6,
			{ "Parameter 6", "csm_encaps.param6",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 6", HFILL }
		},
		{ &hf_csm_encaps_param7,
			{ "Parameter 7", "csm_encaps.param7",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 7", HFILL }
		},
		{ &hf_csm_encaps_param8,
			{ "Parameter 8", "csm_encaps.param8",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 8", HFILL }
		},
		{ &hf_csm_encaps_param9,
			{ "Parameter 9", "csm_encaps.param9",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 9", HFILL }
		},
		{ &hf_csm_encaps_param10,
			{ "Parameter 10", "csm_encaps.param10",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 10", HFILL }
		},
		{ &hf_csm_encaps_param11,
			{ "Parameter 11", "csm_encaps.param11",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 11", HFILL }
		},
		{ &hf_csm_encaps_param12,
			{ "Parameter 12", "csm_encaps.param12",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 12", HFILL }
		},
		{ &hf_csm_encaps_param13,
			{ "Parameter 13", "csm_encaps.param13",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 13", HFILL }
		},
		{ &hf_csm_encaps_param14,
			{ "Parameter 14", "csm_encaps.param14",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 14", HFILL }
		},
		{ &hf_csm_encaps_param15,
			{ "Parameter 15", "csm_encaps.param15",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 15", HFILL }
		},
		{ &hf_csm_encaps_param16,
			{ "Parameter 16", "csm_encaps.param16",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 16", HFILL }
		},
		{ &hf_csm_encaps_param17,
			{ "Parameter 17", "csm_encaps.param17",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 17", HFILL }
		},
		{ &hf_csm_encaps_param18,
			{ "Parameter 18", "csm_encaps.param18",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 18", HFILL }
		},
		{ &hf_csm_encaps_param19,
			{ "Parameter 19", "csm_encaps.param19",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 19", HFILL }
		},
		{ &hf_csm_encaps_param20,
			{ "Parameter 20", "csm_encaps.param20",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 20", HFILL }
		},
		{ &hf_csm_encaps_param21,
			{ "Parameter 21", "csm_encaps.param21",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 21", HFILL }
		},
		{ &hf_csm_encaps_param22,
			{ "Parameter 22", "csm_encaps.param22",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 22", HFILL }
		},
		{ &hf_csm_encaps_param23,
			{ "Parameter 23", "csm_encaps.param23",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 23", HFILL }
		},
		{ &hf_csm_encaps_param24,
			{ "Parameter 24", "csm_encaps.param24",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 24", HFILL }
		},
		{ &hf_csm_encaps_param25,
			{ "Parameter 25", "csm_encaps.param25",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 25", HFILL }
		},
		{ &hf_csm_encaps_param26,
			{ "Parameter 26", "csm_encaps.param26",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 26", HFILL }
		},
		{ &hf_csm_encaps_param27,
			{ "Parameter 27", "csm_encaps.param27",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 27", HFILL }
		},
		{ &hf_csm_encaps_param28,
			{ "Parameter 28", "csm_encaps.param28",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 28", HFILL }
		},
		{ &hf_csm_encaps_param29,
			{ "Parameter 29", "csm_encaps.param29",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 29", HFILL }
		},
		{ &hf_csm_encaps_param30,
			{ "Parameter 30", "csm_encaps.param30",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 30", HFILL }
		},
		{ &hf_csm_encaps_param31,
			{ "Parameter 31", "csm_encaps.param31",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 31", HFILL }
		},
		{ &hf_csm_encaps_param32,
			{ "Parameter 32", "csm_encaps.param32",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 32", HFILL }
		},
		{ &hf_csm_encaps_param33,
			{ "Parameter 33", "csm_encaps.param33",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 33", HFILL }
		},
		{ &hf_csm_encaps_param34,
			{ "Parameter 34", "csm_encaps.param34",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 34", HFILL }
		},
		{ &hf_csm_encaps_param35,
			{ "Parameter 35", "csm_encaps.param35",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 35", HFILL }
		},
		{ &hf_csm_encaps_param36,
			{ "Parameter 36", "csm_encaps.param36",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 36", HFILL }
		},
		{ &hf_csm_encaps_param37,
			{ "Parameter 37", "csm_encaps.param37",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 37", HFILL }
		},
		{ &hf_csm_encaps_param38,
			{ "Parameter 38", "csm_encaps.param38",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 38", HFILL }
		},
		{ &hf_csm_encaps_param39,
			{ "Parameter 39", "csm_encaps.param39",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 39", HFILL }
		},
		{ &hf_csm_encaps_param40,
			{ "Parameter 40", "csm_encaps.param40",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter 40", HFILL }
		},
		{ &hf_csm_encaps_param,
			{ "Parameter", "csm_encaps.param",
				FT_UINT16, BASE_HEX, NULL, 0,
				"CSM_ENCAPS Parameter", HFILL }
		},
	};

	static gint *ett[] = {
		&ett_csm_encaps,
		&ett_csm_encaps_control
	};

	proto_csm_encaps = proto_register_protocol("CSM_ENCAPS", "CSM_ENCAPS", "csm_encaps");
	proto_register_field_array(proto_csm_encaps, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_csm_encaps(void)
{
	dissector_handle_t csm_encaps_handle;

	csm_encaps_handle = create_dissector_handle(dissect_csm_encaps, proto_csm_encaps);
	dissector_add("ethertype", ETHERTYPE_CSM_ENCAPS, csm_encaps_handle);
}
