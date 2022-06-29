/* packet-tplink-smarthome.c
 *
 * Routines for TP-Link Smart Home Protocol dissection
 *
 * Copyright 2020-2021, Fulko Hew <fulko.hew@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * TP-Link Smart Home Protocol (Port 9999) Wireshark Dissector
 * For decrypting local network traffic between TP-Link Smart Home Devices (such as a KP400)
 * and the Kasa Smart Home App (or equivalent)
 *
 * Protocol	Message
 *
 *		+--+--+--+--+--+--+--+--+--+--+
 *  UDP		| Autokey XOR'ed message ...  |
 *		+--+--+--+--+--+--+--+--+--+--+
 *
 *		+-------+-------+-------+-------+--+--+--+--+--+--+--+--+--+--+
 *  TCP		| Big-endian 32-bit byte count  + Autokey XOR'ed message ...  |
 *		+-------+-------+-------+-------+--+--+--+--+--+--+--+--+--+--+
 *
 * I.e. They are both the same except TCP is prefixed with a byte count.
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/address.h>
#include <epan/wmem_scopes.h>
#include "packet-tcp.h"

#define TPLINK_SMARTHOME_PORT	9999 /* Not IANA registered */
/* TP-Link Smart Home devices use this port on both TCP and UDP */
#define FRAME_HEADER_LEN	4			/* 4 bytes of TCP frame length header info */

	/* Prototypes */
	/* (Required to prevent [-Wmissing-prototypes] warnings */

void proto_reg_handoff_tplink_smarthome(void);
void proto_register_tplink_smarthome(void);

		/* Initialize the protocol and registered fields */

static int	proto_tplink_smarthome	= -1;
static gint	ett_tplink_smarthome	= -1;		/* Initialize the subtree pointers */

static int	hf_tplink_smarthome_Len	= -1;
static int	hf_tplink_smarthome_Msg	= -1;

static int
dissect_tplink_smarthome_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		void *data _U_)
{
	proto_item	*ti;
	proto_tree	*tplink_smarthome_tree;
	gint8		start;
	guint8		c, d;
	guint8		key = 171;
	gint32		len = tvb_captured_length(tvb);

	switch (pinfo->ptype) {									/* look at the IP port type */
		case PT_UDP:									/* UDP */
			if (len < 2) return 0;							/* don't dissect unless it contains enough to hold minimum valid JSON i.e. '{}' */
			start = 0;								/* and the JSON message starts immediately */
			break;
		case PT_TCP:									/* TCP */
			if (len < (4 + 2)) return 0;						/* don't dissect unless it has the msg length plus minimal JSON */
			start = 4;								/* and the JSON message starts after that */
			break;
		default:
			return 0;
	}
	/* The message is always JSON, so test the first two characters.
         * They must be {" or {}, as the protocol doesn't appear to
         * have whitespace.). */
	c = tvb_get_guint8(tvb, start);
	d = c ^ key;
	if (d != '{') {
		return 0;
	}
	d = c ^ tvb_get_guint8(tvb, start+1);
	if (d != '"' && d != '}') {
		return 0;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TPLINK-SMARTHOME");				/* show the protocol name of what we're dissecting */
	col_clear(pinfo->cinfo, COL_INFO);							/* and clear anything that might be in the Info field on the UI */

	ti = proto_tree_add_item(tree, proto_tplink_smarthome, tvb, 0, -1, ENC_NA);		/* create display subtree for this protocol */
	tplink_smarthome_tree = proto_item_add_subtree(ti, ett_tplink_smarthome);		/* and add it to the display tree */

	if (pinfo->ptype == PT_TCP) {
		proto_tree_add_item(tplink_smarthome_tree, hf_tplink_smarthome_Len,
					tvb, 0, FRAME_HEADER_LEN, ENC_BIG_ENDIAN);		/* decode the 4 byte message length field pre-pended in a TCP message, */
	}
	gint	i_offset	= start;
	gint	o_offset	= 0;
	gint	decode_len	= len - start;
	char	*ascii_buffer	= (char *)wmem_alloc(pinfo->pool, 1 + len - start);		/* create a buffer for the decoded (JSON) message */

	for (; o_offset < decode_len; i_offset++, o_offset++) {					/* decrypt 'Autokey XOR' message (into ASCII) */
		c	= tvb_get_guint8(tvb, i_offset);
		d	= c ^ key;								/* XOR the byte with the key to get the decoded byte */
		key	= c;									/* then use that decoded byte as the value for the next key */
		*(ascii_buffer + o_offset) = g_ascii_isprint(d) ? d : '.';			/* buffer a printable version (for display and JSON decoding) */
	}
	*(ascii_buffer + o_offset) = '\0';

	char *mtype;										/* categorize the message's intent: */
	if	(pinfo->destport == TPLINK_SMARTHOME_PORT)	{ mtype = "Cmd"; }		/*	'Cmd' - if it's  TO  the TP_Link port */
	else if	(pinfo->srcport  == TPLINK_SMARTHOME_PORT)	{ mtype = "Rsp"; }		/*	'Rsp' - if it's FROM the TP_Link port */
	else							{ mtype = "Msg"; }		/* impossible... because we're registered on this port so src or dest must have matched */

	proto_tree_add_string_format(tplink_smarthome_tree, hf_tplink_smarthome_Msg, tvb,
					start, -1, ascii_buffer, "%s: %s", mtype, ascii_buffer);	    /* add the decrypted data to the subtree so you can 'expand' on it */

	tvbuff_t *next_tvb = tvb_new_child_real_data(tvb, (guint8 *)ascii_buffer, decode_len, decode_len);	/* create a new TVB and insert the decrypted ASCII string, and */
	add_new_data_source(pinfo, next_tvb, "JSON Message");					    	/* add it so you can click on this JSON entry and see the decoded buffer */
	call_dissector(find_dissector("json"), next_tvb, pinfo, ti);			    		/* and decode/dissect it as JSON so you can drill down into it as well */

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s: %s",
		(pinfo->ptype == PT_UDP) ? "UDP" : "TCP",
		mtype, ascii_buffer);									/* add the decoded string to the INFO column for a quick and easy read */

	return tvb_captured_length(tvb);								/* finally return the amount of data this dissector was able to dissect */
}

static guint
get_tplink_smarthome_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{													/* the PDU size is... the value in the length field */
    return (guint)tvb_get_ntohl(tvb, offset) + FRAME_HEADER_LEN;					/* plus the 'size of' the length field itself */
}

static int
dissect_tplink_smarthome(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	if (pinfo->ptype == PT_UDP) {
		dissect_tplink_smarthome_message(tvb, pinfo, tree, data);
	} else {
		tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
			get_tplink_smarthome_message_len, dissect_tplink_smarthome_message, data);
	}
	return tvb_captured_length(tvb);
}

	/* Register the protocol with Wireshark. */

void
proto_register_tplink_smarthome(void)
{
	static hf_register_info hf[] = {								/* setup list of header fields */
		{ &hf_tplink_smarthome_Len,
			{ "Len", "tplink_smarthome.len",
				FT_UINT32, BASE_DEC, NULL, 0,
				"Message Length", HFILL }
		},
		{ &hf_tplink_smarthome_Msg,
			{ "Msg", "tplink_smarthome.msg",
				FT_STRING, BASE_NONE, NULL, 0,
				"Message", HFILL }
		}
	};

	static gint *ett[] = {										/* setup protocol subtree array */
		&ett_tplink_smarthome
	};

	proto_tplink_smarthome = proto_register_protocol("TP-Link Smart Home Protocol",			/* register the protocol name and description */
			"TPLINK-SMARTHOME", "tplink-smarthome");

	proto_register_field_array(proto_tplink_smarthome, hf, array_length(hf));			/* register the header fields */
	proto_register_subtree_array(ett, array_length(ett));						/* and subtrees */
}

void
proto_reg_handoff_tplink_smarthome(void)
{
	dissector_handle_t tplink_smarthome_handle;

	tplink_smarthome_handle = create_dissector_handle(dissect_tplink_smarthome, proto_tplink_smarthome);
	dissector_add_uint_with_preference("tcp.port", TPLINK_SMARTHOME_PORT, tplink_smarthome_handle);
	dissector_add_uint_with_preference("udp.port", TPLINK_SMARTHOME_PORT, tplink_smarthome_handle);
}

/*
 * Editor modelines - https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 noexpandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
