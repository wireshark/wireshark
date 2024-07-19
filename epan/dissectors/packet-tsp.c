/* packet-tsp.c
 * Routines for Time Synchronization Protocol (TSP) packet dissection
 *
 * Uwe Girlich <Uwe.Girlich@philosys.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-quake.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

/*
 * For a full documentation of the Time Synchronization Protocol (TSP) see:
 * http://docs.freebsd.org/44doc/smm/12.timed/paper.pdf
 */
void proto_register_tsp(void);
void proto_reg_handoff_tsp(void);

static dissector_handle_t tsp_handle;

static int proto_tsp;
static int hf_tsp_type;
static int hf_tsp_vers;
static int hf_tsp_seq;
static int hf_tsp_hopcnt;
static int hf_tsp_time_sec;
static int hf_tsp_time_usec;
static int hf_tsp_name;

static int ett_tsp;

/* timed port from /etc/services */
#define UDP_PORT_TIMED	525


static const value_string names_tsp_type[] = {
#define TSP_ANY                 0       /* match any types */
	{	TSP_ANY, "any" },
#define TSP_ADJTIME             1       /* send adjtime */
	{	TSP_ADJTIME, "adjtime" },
#define TSP_ACK                 2       /* generic acknowledgement */
	{	TSP_ACK, "ack" },
#define TSP_MASTERREQ           3       /* ask for master's name */
	{	TSP_MASTERREQ, "masterreq" },
#define TSP_MASTERACK           4       /* acknowledge master request */
	{	TSP_MASTERACK, "masterack" },
#define TSP_SETTIME             5       /* send network time */
	{	TSP_SETTIME, "settime" },
#define TSP_MASTERUP            6       /* inform slaves that master is up */
	{	TSP_MASTERUP, "masterup" },
#define TSP_SLAVEUP             7       /* slave is up but not polled */
	{	TSP_SLAVEUP, "slaveup" },
#define TSP_ELECTION            8       /* advance candidature for master */
	{	TSP_ELECTION, "election" },
#define TSP_ACCEPT              9       /* support candidature of master */
	{	TSP_ACCEPT, "accept" },
#define TSP_REFUSE              10      /* reject candidature of master */
	{	TSP_REFUSE, "refuse" },
#define TSP_CONFLICT            11      /* two or more masters present */
	{	TSP_CONFLICT, "conflict" },
#define TSP_RESOLVE             12      /* masters' conflict resolution */
	{	TSP_RESOLVE, "resolve" },
#define TSP_QUIT                13      /* reject candidature if master is up */
	{	TSP_QUIT, "quit" },
#define TSP_DATE                14      /* reset the time (date command) */
	{	TSP_DATE, "date" },
#define TSP_DATEREQ             15      /* remote request to reset the time */
	{	TSP_DATEREQ, "datereq" },
#define TSP_DATEACK             16      /* acknowledge time setting  */
	{	TSP_DATEACK, "dateack" },
#define TSP_TRACEON             17      /* turn tracing on */
	{	TSP_TRACEON, "traceon" },
#define TSP_TRACEOFF            18      /* turn tracing off */
	{	TSP_TRACEOFF, "traceoff" },
#define TSP_MSITE               19      /* find out master's site */
	{	TSP_MSITE, "msite" },
#define TSP_MSITEREQ            20      /* remote master's site request */
	{	TSP_MSITEREQ, "msitereq" },
#define TSP_TEST                21      /* for testing election algo */
	{	TSP_TEST, "test" },
#define TSP_SETDATE             22      /* New from date command */
	{	TSP_SETDATE, "setdate" },
#define TSP_SETDATEREQ          23      /* New remote for above */
	{	TSP_SETDATEREQ, "setdatereq" },
#define TSP_LOOP                24      /* loop detection packet */
	{	TSP_LOOP, "loop" },
	{ 0, NULL }
};


static int
dissect_tsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree	*tsp_tree;
	proto_item	*tsp_item;

	uint8_t		tsp_type;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TSP");
	col_clear(pinfo->cinfo, COL_INFO);

	tsp_type = tvb_get_uint8(tvb, 0);
	col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(tsp_type, names_tsp_type, "Unknown message type (%u)"));

	tsp_item = proto_tree_add_item(tree, proto_tsp,
				tvb, 0, -1, ENC_NA);
	tsp_tree = proto_item_add_subtree(tsp_item, ett_tsp);

	if (tsp_tree) {
		proto_tree_add_uint(tsp_tree, hf_tsp_type,
			tvb, 0, 1, tsp_type);
		proto_tree_add_item(tsp_tree, hf_tsp_vers,
			tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tsp_tree, hf_tsp_seq,
			tvb, 2, 2, ENC_BIG_ENDIAN);
	}

	switch (tsp_type) {

	case TSP_LOOP:
		if (tsp_tree)
			proto_tree_add_item(tsp_tree, hf_tsp_hopcnt,
				tvb, 4, 1, ENC_BIG_ENDIAN);
		break;

	case TSP_SETTIME:
	case TSP_ADJTIME:
	case TSP_SETDATE:
	case TSP_SETDATEREQ:
		if (tsp_tree) {
			proto_tree_add_item(tsp_tree, hf_tsp_time_sec,
				tvb, 4, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(tsp_tree, hf_tsp_time_usec,
				tvb, 8, 4, ENC_BIG_ENDIAN);
		}
		break;
	}

	if (tsp_tree) {
		proto_tree_add_item(tsp_tree, hf_tsp_name, tvb, 12,
			-1, ENC_ASCII);
	}
	return tvb_captured_length(tvb);
}


void
proto_reg_handoff_tsp(void)
{
	dissector_add_uint_with_preference("udp.port", UDP_PORT_TIMED, tsp_handle);
}


void
proto_register_tsp(void)
{
	static hf_register_info hf[] = {
		{ &hf_tsp_type,
		  { "Type", "tsp.type",
		    FT_UINT8, BASE_DEC, VALS(names_tsp_type), 0x0,
		    "Packet Type", HFILL }},
		{ &hf_tsp_vers,
		  { "Version", "tsp.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Protocol Version Number", HFILL }},
		{ &hf_tsp_seq,
		  { "Sequence", "tsp.sequence",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Sequence Number", HFILL }},
		{ &hf_tsp_hopcnt,
		  { "Hop Count", "tsp.hopcnt",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_tsp_time_sec,
		  { "Seconds", "tsp.sec",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_tsp_time_usec,
		  { "Microseconds", "tsp.usec",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_tsp_name,
		  { "Machine Name", "tsp.name",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Sender Machine Name", HFILL }}
	};
	static int *ett[] = {
		&ett_tsp
	};

	proto_tsp = proto_register_protocol("Time Synchronization Protocol",
					    "TSP", "tsp");
	proto_register_field_array(proto_tsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	tsp_handle = register_dissector("tsp", dissect_tsp, proto_tsp);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
