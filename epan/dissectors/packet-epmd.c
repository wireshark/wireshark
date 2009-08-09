/* packet-epmd.c
 * dissector for EPMD (Erlang Port Mapper Daemon) messages;
 * this are the messages sent between Erlang nodes and
 * the empd process.
 * The message formats are derived from the
 * lib/kernel/src/erl_epmd.* files as part of the Erlang
 * distribution available from http://www.erlang.org/
 *
 * (c) 2007 Joost Yervante Damad <joost[AT]teluna.org>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-time.c
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
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/ptvcursor.h>

static int proto_epmd = -1;
static int hf_epmd_len = -1;
static int hf_epmd_type = -1;
static int hf_epmd_tcp_port = -1;
static int hf_epmd_dist_high = -1;
static int hf_epmd_dist_low = -1;
static int hf_epmd_name_len = -1;
static int hf_epmd_name = -1;
static int hf_epmd_elen = -1;
static int hf_epmd_edata = -1;
static int hf_epmd_names = -1;
static int hf_epmd_result = -1;
static int hf_epmd_creation = -1;

static gint ett_epmd = -1;

#define EPMD_PORT 4369

/* requests */
#define EPMD_ALIVE2 'x'
#define EPMD_PORT_PLEASE 'p'
#define EPMD_PORT_PLEASE2 'z'
#define EPMD_NAMES 'n'
#define EPMD_ALIVE 'a'

/* responses */
#define EPMD_ALIVE_OK 'Y'
#define EPMD_ALIVE2_OK 'y'
#define EPMD_PORT_PLEASE2_OK 'w'

/* unknown; currently not implemented */
#define EPMD_DUMP 'd'
#define EPMD_KILL 'k'
#define EPMD_STOP 's'

static const value_string message_types[] =
{
	{  EPMD_ALIVE,		"Alive" },
	{  EPMD_PORT_PLEASE,	"Port Please" },
	{  EPMD_NAMES,		"Names" },
	{  EPMD_DUMP,		"Dump" },
	{  EPMD_KILL,		"Kill" },
	{  EPMD_STOP,		"Stop" },
	{  EPMD_ALIVE_OK,	"Alive Ok" },
	{  EPMD_ALIVE2,		"Alive 2" },
	{  EPMD_PORT_PLEASE2,	"Port Please 2" },
	{  EPMD_ALIVE2_OK,	"Alive 2 Ok" },
	{  EPMD_PORT_PLEASE2_OK, "Port Please 2 Ok" },
	{  0, NULL }
};

static void
dissect_epmd_request(ptvcursor_t *cursor)
{
    tvbuff_t *tvb;
    guint8 type;

    tvb = ptvcursor_tvbuff(cursor);
    ptvcursor_add(cursor, hf_epmd_len, 2, FALSE);

    type = tvb_get_guint8(tvb, ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_epmd_type, 1, FALSE);
    switch (type) {
	case EPMD_ALIVE2: {
	    guint16 name_length, elen;
	    ptvcursor_add(cursor, hf_epmd_tcp_port, 2, FALSE);
	    ptvcursor_advance(cursor,2); /* 'M', 0 */
	    ptvcursor_add(cursor, hf_epmd_dist_high, 2, FALSE);
	    ptvcursor_add(cursor, hf_epmd_dist_low, 2, FALSE);
	    name_length = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
	    ptvcursor_add(cursor, hf_epmd_name_len, 2, FALSE);
	    ptvcursor_add(cursor, hf_epmd_name, name_length, FALSE);
	    elen = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
	    ptvcursor_add(cursor, hf_epmd_elen, 2, FALSE);
	    if (elen > 0)
		ptvcursor_add(cursor, hf_epmd_edata, elen, FALSE);
	    break;
	}
	case EPMD_PORT_PLEASE:
	case EPMD_PORT_PLEASE2:
	    /*ptvcursor_add(cursor, hf_epmd_name, tvb_length(tvb)-3, FALSE);*/
	    ptvcursor_add(cursor, hf_epmd_name, -1, FALSE);
	    break;
	case EPMD_ALIVE: {
	    ptvcursor_add(cursor, hf_epmd_tcp_port, 2, FALSE);
	    /*ptvcursor_add(cursor, hf_epmd_name, tvb_length(tvb)-3, FALSE);*/
	    ptvcursor_add(cursor, hf_epmd_name, -1, FALSE);
	    break;
	}
	case EPMD_NAMES:
	default:
	    break;
    }
}

static void
dissect_epmd_response_names(ptvcursor_t *cursor)
{
    ptvcursor_add(cursor, hf_epmd_tcp_port, 2, FALSE);
    ptvcursor_add(cursor, hf_epmd_names, -1, FALSE);
    /* TODO: parse names */
}

static void
dissect_epmd_response(ptvcursor_t *cursor)
{
    tvbuff_t *tvb;
    guint32 port;
    guint8 type;

    tvb = ptvcursor_tvbuff(cursor);
    port = tvb_get_ntohl(tvb, 0);
    if (port == EPMD_PORT) {
	dissect_epmd_response_names(cursor);
	return;
    }

    type = tvb_get_guint8(tvb, 0);
    ptvcursor_add(cursor, hf_epmd_type, 1, FALSE);
    switch (type) {
	case EPMD_PORT_PLEASE2_OK: {
	    ptvcursor_advance(cursor, 1);
/* 'w', 0, Port(16), Type(8), Proto(8), High(16), Low(16), NLen(16), Name(x) */
	    ptvcursor_add(cursor, hf_epmd_tcp_port, 2, FALSE);
	    ptvcursor_advance(cursor, 2); /* 'M', 0 */
	    ptvcursor_add(cursor, hf_epmd_dist_high, 2, FALSE);
	    ptvcursor_add(cursor, hf_epmd_dist_low, 2, FALSE);
	    ptvcursor_add(cursor, hf_epmd_name_len, 2, FALSE);
	    ptvcursor_add(cursor, hf_epmd_name, -1, FALSE);
	}
	case EPMD_ALIVE_OK:
	case EPMD_ALIVE2_OK: {
	    ptvcursor_add(cursor, hf_epmd_result, 1, FALSE);
	    ptvcursor_add(cursor, hf_epmd_creation, 2, FALSE);
	}
	default:
	    break;
    }
}

static gboolean
check_epmd(tvbuff_t *tvb)
{
    guint8 type;

    /* simple heuristic:
     *
     * just check if the type is one of the EPMD
     * command types
     *
     * It's possible to start checking lengths but imho that
     * doesn't bring very much.
     */
    if (tvb_length(tvb) < 3)
	return(FALSE);

    type = tvb_get_guint8(tvb, 0);
    switch (type) {
	case EPMD_ALIVE_OK:
	case EPMD_ALIVE2_OK:
	case EPMD_PORT_PLEASE2_OK:
	    return(TRUE);
	default:
	    break;
    }

    type = tvb_get_guint8(tvb, 2);
    switch (type) {
	case EPMD_ALIVE2:
	case EPMD_PORT_PLEASE:
	case EPMD_PORT_PLEASE2:
	case EPMD_NAMES:
	case EPMD_ALIVE:
	    return( TRUE);
	default:
	    break;
    }

    return(FALSE);
}

static int
dissect_epmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *epmd_tree;
    proto_item *ti;
    ptvcursor_t *cursor;

    if (!check_epmd(tvb))
	return(0);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EPMD");

    if (tree) {
	ti = proto_tree_add_item(tree, proto_epmd, tvb, 0, -1, FALSE);
	epmd_tree = proto_item_add_subtree(ti, ett_epmd);
	cursor = ptvcursor_new(epmd_tree, tvb, 0);

	if (pinfo->srcport==EPMD_PORT) {
	    dissect_epmd_response(cursor);
	} else {
	    dissect_epmd_request(cursor);
	}

	ptvcursor_free(cursor);
    }

    return(tvb_length(tvb));
}

void
proto_register_epmd(void)
{
    static hf_register_info hf[] = {
	{ &hf_epmd_len,
	    {   "Length", "epmd.len",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"Message Length", HFILL }},
	{ &hf_epmd_type,
	    { "Type", "epmd.type",
		FT_UINT8, BASE_DEC, VALS(message_types), 0x0,
		"Message Type", HFILL }},
	{ &hf_epmd_result,
	    { "Result", "epmd.result",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},
	{ &hf_epmd_tcp_port,
	    { "TCP Port", "epmd.tcp_port",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},
	{ &hf_epmd_creation,
	    { "Creation", "epmd.creation",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},
	{ &hf_epmd_dist_high,
	    { "Dist High", "epmd.dist_high",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},
	{ &hf_epmd_dist_low,
	    { "Dist Low", "epmd.dist_low",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},
	{ &hf_epmd_name_len,
	    { "Name Length", "epmd.name_len",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},
	{ &hf_epmd_name,
	    { "Name", "epmd.name",
		FT_STRING, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	{ &hf_epmd_elen,
	    { "Elen", "epmd.elen",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"Extra Length", HFILL }},
	{ &hf_epmd_edata,
	    { "Edata", "epmd.edata",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		"Extra Data", HFILL }},
	{ &hf_epmd_names,
	    { "Names", "epmd.names",
		FT_BYTES, BASE_NONE, NULL, 0x0,
		"List of names", HFILL }}
    };
    static gint *ett[] = {
	&ett_epmd,
    };

    proto_epmd = proto_register_protocol("EPMD Protocol", "EPMD", "epmd");
    proto_register_field_array(proto_epmd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    new_register_dissector("epmd", dissect_epmd, proto_epmd);
}

void
proto_reg_handoff_epmd(void)
{
    dissector_handle_t epmd_handle;
    epmd_handle = find_dissector("epmd");
    dissector_add("tcp.port", EPMD_PORT, epmd_handle);
}
