/* packet-slowprotocols.c
 * Routines for EtherType (0x8809) Slow Protocols disassembly.
 *
 * $Id: packet-slowprotocols.c,v 1.4 2002/08/28 21:00:31 jmayer Exp $
 *
 * Copyright 2002 Steve Housley <steve_housley@3com.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

 /* *** WARNING!! *** Only a dissector for LACPDU (Link Aggregation Control
  * Protocol Data Unit) disassembly has currently been implemented.
  */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include "etypes.h"
#include "llcsaps.h"
#include "ppptypes.h"
#include <epan/resolv.h>

/* Offsets of fields within a LACPDU */

#define LACPDU_SUBTYPE				0
#define LACPDU_VERSION_NUMBER			1

#define LACPDU_ACTOR_TYPE			2
#define LACPDU_ACTOR_INFO_LEN			3
#define LACPDU_ACTOR_SYS_PRIORITY		4
#define LACPDU_ACTOR_SYSTEM			6
#define LACPDU_ACTOR_KEY			12
#define LACPDU_ACTOR_PORT_PRIORITY		14
#define LACPDU_ACTOR_PORT			16
#define LACPDU_ACTOR_STATE			18
#define LACPDU_ACTOR_RESERVED			19

#define LACPDU_PARTNER_TYPE			22
#define LACPDU_PARTNER_INFO_LEN			23
#define LACPDU_PARTNER_SYS_PRIORITY		24
#define LACPDU_PARTNER_SYSTEM			26
#define LACPDU_PARTNER_KEY			32
#define LACPDU_PARTNER_PORT_PRIORITY		34
#define LACPDU_PARTNER_PORT			36
#define LACPDU_PARTNER_STATE			38
#define LACPDU_PARTNER_RESERVED			39

#define LACPDU_COLL_TYPE			42
#define LACPDU_COLL_INFO_LEN			43
#define LACPDU_COLL_MAX_DELAY			44
#define LACPDU_COLL_RESERVED			46

#define LACPDU_TERM_TYPE			58
#define LACPDU_TERM_LEN				59
#define LACPDU_TERM_RESERVED			60

/* Actor and Partner Flag bits */

#define LACPDU_FLAGS_ACTIVITY		0x01
#define LACPDU_FLAGS_TIMEOUT		0x02
#define LACPDU_FLAGS_AGGREGATION	0x04
#define LACPDU_FLAGS_SYNC		0x08
#define LACPDU_FLAGS_COLLECTING		0x10
#define LACPDU_FLAGS_DISTRIB		0x20
#define LACPDU_FLAGS_DEFAULTED		0x40
#define LACPDU_FLAGS_EXPIRED		0x80

/* Initialise the protocol and registered fields */

static int proto_lacpdu = -1;

static int hf_lacpdu_subtype = -1;
static int hf_lacpdu_version_number = -1;

static int hf_lacpdu_actor_type = -1;
static int hf_lacpdu_actor_info_len = -1;
static int hf_lacpdu_actor_sys_priority = -1;
static int hf_lacpdu_actor_sys = -1;
static int hf_lacpdu_actor_key = -1;
static int hf_lacpdu_actor_port_priority = -1;
static int hf_lacpdu_actor_port = -1;
static int hf_lacpdu_actor_state = -1;
static int hf_lacpdu_flags_a_activity = -1;
static int hf_lacpdu_flags_a_timeout = -1;
static int hf_lacpdu_flags_a_aggregation = -1;
static int hf_lacpdu_flags_a_sync = -1;
static int hf_lacpdu_flags_a_collecting = -1;
static int hf_lacpdu_flags_a_distrib = -1;
static int hf_lacpdu_flags_a_defaulted = -1;
static int hf_lacpdu_flags_a_expired = -1;
static int hf_lacpdu_actor_reserved = -1;

static int hf_lacpdu_partner_type = -1;
static int hf_lacpdu_partner_info_len = -1;
static int hf_lacpdu_partner_sys_priority = -1;
static int hf_lacpdu_partner_sys = -1;
static int hf_lacpdu_partner_key = -1;
static int hf_lacpdu_partner_port_priority = -1;
static int hf_lacpdu_partner_port = -1;
static int hf_lacpdu_partner_state = -1;
static int hf_lacpdu_flags_p_activity = -1;
static int hf_lacpdu_flags_p_timeout = -1;
static int hf_lacpdu_flags_p_aggregation = -1;
static int hf_lacpdu_flags_p_sync = -1;
static int hf_lacpdu_flags_p_collecting = -1;
static int hf_lacpdu_flags_p_distrib = -1;
static int hf_lacpdu_flags_p_defaulted = -1;
static int hf_lacpdu_flags_p_expired = -1;
static int hf_lacpdu_partner_reserved = -1;

static int hf_lacpdu_coll_type = -1;
static int hf_lacpdu_coll_info_len = -1;
static int hf_lacpdu_coll_max_delay = -1;
static int hf_lacpdu_coll_reserved = -1;

static int hf_lacpdu_term_type = -1;
static int hf_lacpdu_term_len = -1;
static int hf_lacpdu_term_reserved = -1;

/* Initialise the subtree pointers */

static gint ett_lacpdu = -1;
static gint ett_lacpdu_a_flags = -1;
static gint ett_lacpdu_p_flags = -1;

/* General declarations and macros */

#define LACP_SUBTYPE 0x1

static const char initial_sep[] = " (";
static const char cont_sep[] = ", ";

#define APPEND_BOOLEAN_FLAG(flag, item, string) \
	if(flag){							\
		if(item)						\
			proto_item_append_text(item, string, sep);	\
		sep = cont_sep;						\
	}

/* Code to actually dissect the LACPDU packets */
static void
dissect_lacpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
      guint16 raw_word;
      guint8  raw_octet;

      guint8  flags;

      const guint8 *a_sys;
      const guint8 *p_sys;
      const guint8 *resv_bytes;

      proto_tree *lacpdu_tree;
      proto_item *lacpdu_item;
      proto_tree *actor_flags_tree;
      proto_item *actor_flags_item;
      proto_tree *partner_flags_tree;
      proto_item *partner_flags_item;


      const char *sep;


      if (check_col(pinfo->cinfo, COL_PROTOCOL))
      {
	    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LACP"); /* LACP Protocol */
      }

      if (check_col(pinfo->cinfo, COL_INFO))
      {
	    col_clear(pinfo->cinfo, COL_INFO);
      }

      if (tree)
	  {
	    /* Add LACP Heading */
	    lacpdu_item = proto_tree_add_protocol_format(tree, proto_lacpdu, tvb,
				0, -1, "Link Aggregation Control Protocol");
	    lacpdu_tree = proto_item_add_subtree(lacpdu_item, ett_lacpdu);

	    /* Version Number */
	    raw_octet = tvb_get_guint8(tvb, LACPDU_VERSION_NUMBER);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_version_number, tvb,
				LACPDU_VERSION_NUMBER, 1, raw_octet);

	    if (check_col(pinfo->cinfo, COL_INFO))
	    {
		col_append_fstr(pinfo->cinfo, COL_INFO, "Version %d.  ", raw_octet);
	    }

	    /* Actor Type */
	    raw_octet = tvb_get_guint8(tvb, LACPDU_ACTOR_TYPE);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_actor_type, tvb,
				LACPDU_ACTOR_TYPE, 1, raw_octet);

	    /* Actor Info Length */
	    raw_octet = tvb_get_guint8(tvb, LACPDU_ACTOR_INFO_LEN);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_actor_info_len, tvb,
				LACPDU_ACTOR_INFO_LEN, 1, raw_octet);

	    /* Actor System Priority */

	    raw_word = tvb_get_ntohs(tvb, LACPDU_ACTOR_SYS_PRIORITY);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_actor_sys_priority, tvb,
				LACPDU_ACTOR_SYS_PRIORITY, 2, raw_word);
	    /* Actor System */

	    a_sys = tvb_get_ptr(tvb, LACPDU_ACTOR_SYSTEM , 6);
	    proto_tree_add_ether(lacpdu_tree, hf_lacpdu_actor_sys, tvb,
				LACPDU_ACTOR_SYSTEM, 6, a_sys);

	    /* Actor Key */

	    raw_word = tvb_get_ntohs(tvb, LACPDU_ACTOR_KEY);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_actor_key, tvb,
				LACPDU_ACTOR_KEY, 2, raw_word);

	    /* Actor Port Priority */

	    raw_word = tvb_get_ntohs(tvb, LACPDU_ACTOR_PORT_PRIORITY);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_actor_port_priority, tvb,
				LACPDU_ACTOR_PORT_PRIORITY, 2, raw_word);

	    /* Actor Port */

	    raw_word = tvb_get_ntohs(tvb, LACPDU_ACTOR_PORT);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_actor_port, tvb,
				LACPDU_ACTOR_PORT, 2, raw_word);

	    if (check_col(pinfo->cinfo, COL_INFO))
	    {
		col_append_fstr(pinfo->cinfo, COL_INFO, "Actor Port = %d ", raw_word);
	    }

	    /* Actor State */

	    flags = tvb_get_guint8(tvb, LACPDU_ACTOR_STATE);
	    actor_flags_item = proto_tree_add_uint(lacpdu_tree, hf_lacpdu_actor_state, tvb,
				LACPDU_ACTOR_STATE, 1, flags);
	    actor_flags_tree = proto_item_add_subtree(actor_flags_item, ett_lacpdu_a_flags);

	    sep = initial_sep;

	    /* Activity Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_ACTIVITY, actor_flags_item,
				"%sActivity");
	    proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_activity, tvb,
				LACPDU_ACTOR_STATE, 1, flags);

	    /* Timeout Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_TIMEOUT, actor_flags_item,
				"%sTimeout");
	    proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_timeout, tvb,
				LACPDU_ACTOR_STATE, 1, flags);

	    /* Aggregation Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_AGGREGATION, actor_flags_item,
				"%sAggregation");
	    proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_aggregation, tvb,
				LACPDU_ACTOR_STATE, 1, flags);

	    /* Synchronization Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_SYNC, actor_flags_item,
				"%sSynchronization");
	    proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_sync, tvb,
				LACPDU_ACTOR_STATE, 1, flags);

	    /* Collecting Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_COLLECTING, actor_flags_item,
				"%sCollecting");
	    proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_collecting, tvb,
				LACPDU_ACTOR_STATE, 1, flags);


	    /* Distributing Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_DISTRIB, actor_flags_item,
				"%sDistributing");
	    proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_distrib, tvb,
				LACPDU_ACTOR_STATE, 1, flags);

	    /* Defaulted Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_DEFAULTED, actor_flags_item,
				"%sDefaulted");
	    proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_defaulted, tvb,
				LACPDU_ACTOR_STATE, 1, flags);

	    /* Expired Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_EXPIRED, actor_flags_item,
				"%sExpired");
	    proto_tree_add_boolean(actor_flags_tree, hf_lacpdu_flags_a_expired, tvb,
				LACPDU_ACTOR_STATE, 1, flags);

	    sep = cont_sep;
	    if (sep != initial_sep)
	    {
		/* We put something in; put in the terminating ")" */
		proto_item_append_text(actor_flags_item, ")");
	    }

	    /* Actor Reserved */

	    resv_bytes = tvb_get_ptr(tvb, LACPDU_ACTOR_RESERVED, 3);
	    proto_tree_add_bytes(lacpdu_tree, hf_lacpdu_actor_reserved, tvb,
				LACPDU_ACTOR_RESERVED, 3, resv_bytes);


	    /* Partner Type */
	    raw_octet = tvb_get_guint8(tvb, LACPDU_PARTNER_TYPE);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_partner_type, tvb,
				LACPDU_PARTNER_TYPE, 1, raw_octet);

	    /* Partner Info Length */
	    raw_octet = tvb_get_guint8(tvb, LACPDU_PARTNER_INFO_LEN);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_partner_info_len, tvb,
				LACPDU_PARTNER_INFO_LEN, 1, raw_octet);

	    /* Partner System Priority */

	    raw_word = tvb_get_ntohs(tvb, LACPDU_PARTNER_SYS_PRIORITY);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_partner_sys_priority, tvb,
				LACPDU_PARTNER_SYS_PRIORITY, 2, raw_word);

	    /* Partner System */

	    p_sys = tvb_get_ptr(tvb, LACPDU_PARTNER_SYSTEM, 6);
	    proto_tree_add_ether(lacpdu_tree, hf_lacpdu_partner_sys, tvb,
				LACPDU_PARTNER_SYSTEM, 6, p_sys);

	    /* Partner Key */

	    raw_word = tvb_get_ntohs(tvb, LACPDU_PARTNER_KEY);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_partner_key, tvb,
				LACPDU_PARTNER_KEY, 2, raw_word);

	    /* Partner Port Priority */

	    raw_word = tvb_get_ntohs(tvb, LACPDU_PARTNER_PORT_PRIORITY);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_partner_port_priority, tvb,
				LACPDU_PARTNER_PORT_PRIORITY, 2, raw_word);

	    /* Partner Port */

	    raw_word = tvb_get_ntohs(tvb, LACPDU_PARTNER_PORT);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_partner_port, tvb,
				LACPDU_PARTNER_PORT, 2, raw_word);

	    if (check_col(pinfo->cinfo, COL_INFO))
	    {
		col_append_fstr(pinfo->cinfo, COL_INFO, "Partner Port = %d ", raw_word);
	    }

	    /* Partner State */

	    flags = tvb_get_guint8(tvb, LACPDU_PARTNER_STATE);
	    partner_flags_item = proto_tree_add_uint(lacpdu_tree, hf_lacpdu_partner_state, tvb,
				LACPDU_PARTNER_STATE, 1, flags);
	    partner_flags_tree = proto_item_add_subtree(partner_flags_item, ett_lacpdu_p_flags);

	    sep = initial_sep;

	    /* Activity Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_ACTIVITY, partner_flags_item,
				"%sActivity");
	    proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_activity, tvb,
				LACPDU_PARTNER_STATE, 1, flags);

	    /* Timeout Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_TIMEOUT, partner_flags_item,
				"%sTimeout");
	    proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_timeout, tvb,
				LACPDU_PARTNER_STATE, 1, flags);

	    /* Aggregation Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_AGGREGATION, partner_flags_item,
				"%sAggregation");
	    proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_aggregation, tvb,
				LACPDU_PARTNER_STATE, 1, flags);

	    /* Synchronization Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_SYNC, partner_flags_item,
				"%sSynchronization");
	    proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_sync, tvb,
				LACPDU_PARTNER_STATE, 1, flags);

	    /* Collecting Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_COLLECTING, partner_flags_item,
				"%sCollecting");
	    proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_collecting, tvb,
				LACPDU_PARTNER_STATE, 1, flags);


	    /* Distributing Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_DISTRIB, partner_flags_item,
				"%sDistributing");
	    proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_distrib, tvb,
				LACPDU_PARTNER_STATE, 1, flags);

	    /* Defaulted Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_DEFAULTED, partner_flags_item,
				"%sDefaulted");
	    proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_defaulted, tvb,
				LACPDU_PARTNER_STATE, 1, flags);

	    /* Expired Flag */

	    APPEND_BOOLEAN_FLAG(flags & LACPDU_FLAGS_EXPIRED, partner_flags_item,
				"%sExpired");
	    proto_tree_add_boolean(partner_flags_tree, hf_lacpdu_flags_p_expired, tvb,
				LACPDU_PARTNER_STATE, 1, flags);

	    sep = cont_sep;
	    if (sep != initial_sep)
	    {
		/* We put something in; put in the terminating ")" */
		proto_item_append_text(partner_flags_item, ")");
	    }

	    /* Partner Reserved */

	    resv_bytes = tvb_get_ptr(tvb, LACPDU_PARTNER_RESERVED, 3);
	    proto_tree_add_bytes(lacpdu_tree, hf_lacpdu_partner_reserved, tvb,
				LACPDU_PARTNER_RESERVED, 3, resv_bytes);


	    /* Collector Type */
	    raw_octet = tvb_get_guint8(tvb, LACPDU_COLL_TYPE);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_coll_type, tvb,
				LACPDU_COLL_TYPE, 1, raw_octet);

	    /* Collector Info Length */
	    raw_octet = tvb_get_guint8(tvb, LACPDU_COLL_INFO_LEN);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_coll_info_len, tvb,
				LACPDU_COLL_INFO_LEN, 1, raw_octet);

	    /* Collector Max Delay */

	    raw_word = tvb_get_ntohs(tvb, LACPDU_COLL_MAX_DELAY);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_coll_max_delay, tvb,
				LACPDU_COLL_MAX_DELAY, 2, raw_word);

		/* Collector Reserved */

	    resv_bytes = tvb_get_ptr(tvb, LACPDU_COLL_RESERVED, 12);
	    proto_tree_add_bytes(lacpdu_tree, hf_lacpdu_coll_reserved, tvb,
				LACPDU_COLL_RESERVED, 12, resv_bytes);

	    /* Terminator Type */
	    raw_octet = tvb_get_guint8(tvb, LACPDU_TERM_TYPE);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_term_type, tvb,
				LACPDU_TERM_TYPE, 1, raw_octet);

	    /* Terminator Info Length */
	    raw_octet = tvb_get_guint8(tvb, LACPDU_TERM_LEN);
	    proto_tree_add_uint(lacpdu_tree, hf_lacpdu_term_len, tvb,
				LACPDU_TERM_LEN, 1, raw_octet);

	    /* Terminator Reserved */

	    resv_bytes = tvb_get_ptr(tvb, LACPDU_TERM_RESERVED, 50);
	    proto_tree_add_bytes(lacpdu_tree, hf_lacpdu_term_reserved, tvb,
				LACPDU_TERM_RESERVED, 50, resv_bytes);
      }
}


/* Code to dissect the Slow Protocol packets */
static void
dissect_slow_protocols(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
      guint8 raw_octet;

      if (tree)
      {

		/* Get the Slow Protocol Subtype value */
		raw_octet = tvb_get_guint8(tvb, LACPDU_SUBTYPE);

		if (raw_octet != LACP_SUBTYPE)
		{
			/* This is not a LACPDU. Do not disassemble. */
			/* Requires implementation at a later date. */
			if (check_col(pinfo->cinfo, COL_PROTOCOL))
			{
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "Slow Protocols"); /* Slow Protocols */
			}

			/* Display the subtype value to aid the user. */
			if (check_col(pinfo->cinfo, COL_INFO))
			{
				col_add_fstr(pinfo->cinfo, COL_INFO, "Subtype = %u.", raw_octet);
			}
			return;
		}
      }

      /* This is a LACPDU so decode it! */
      dissect_lacpdu(tvb, pinfo, tree);
}



/* Register the protocol with Ethereal */

static const value_string subtype_vals[] = {
	{ 1, "LACP" },
	{ 2, "Marker Protocol" },
	{ 0, NULL }
};

static const true_false_string yesno = {
	"Yes",
	"No"
};

void
proto_register_lacpdu(void)
{
/* Setup list of header fields */

  static hf_register_info hf[] = {

    { &hf_lacpdu_subtype,
      { "Subtype",	"lacp.subtype",
	FT_UINT8,	BASE_HEX,	VALS(subtype_vals),	0x0,
      	"The specific Slow Protocol being used", HFILL }},

    { &hf_lacpdu_version_number,
      { "LACP Version Number",	"lacp.version",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"Identifies the LACP version", HFILL }},

    { &hf_lacpdu_actor_type,
      { "Actor Information",	"lacp.actorInfo",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"TLV type = Actor", HFILL }},

    { &hf_lacpdu_actor_info_len,
      { "Actor Information Length",			"lacp.actorInfoLen",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"The length of the Actor TLV", HFILL }},

    { &hf_lacpdu_actor_sys_priority,
      { "Actor System Priority",  "lacp.actorSysPriority",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	"The priority assigned to this System by management or admin", HFILL }},

    { &hf_lacpdu_actor_sys,
      { "Actor System",			"lacp.actorSystem",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	"The Actor's System ID encoded as a MAC address", HFILL }},

    { &hf_lacpdu_actor_key,
      { "Actor Key",			"lacp.actorKey",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	"The operational Key value assigned to the port by the Actor", HFILL }},

    { &hf_lacpdu_actor_port_priority,
      { "Actor Port Priority",			"lacp.actorPortPriority",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	"The priority assigned to the port by the Actor (via Management or Admin)", HFILL }},

    { &hf_lacpdu_actor_port,
      { "Actor Port",			"lacp.actorPort",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	"The port number assigned to the port by the Actor (via Management or Admin)", HFILL }},

    { &hf_lacpdu_actor_state,
      { "Actor State",			"lacp.actorState",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"The Actor's state variables for the port, encoded as bits within a single octet", HFILL }},

    { &hf_lacpdu_flags_a_activity,
      { "LACP Activity",		"lacp.actorState.activity",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_ACTIVITY,
      	"Activity control value for this link. Active = 1, Passive = 0", HFILL }},

    { &hf_lacpdu_flags_a_timeout,
      { "LACP Timeout",		"lacp.actorState.timeout",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_TIMEOUT,
      	"Timeout control value for this link. Short Timeout = 1, Long Timeout = 0", HFILL }},


    { &hf_lacpdu_flags_a_aggregation,
      { "Aggregation",		"lacp.actorState.aggregation",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_AGGREGATION,
      	"Aggregatable = 1, Individual = 0", HFILL }},


    { &hf_lacpdu_flags_a_sync,
      { "Synchronization",		"lacp.actorState.synchronization",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_SYNC,
      	"In Sync = 1, Out of Sync = 0", HFILL }},


    { &hf_lacpdu_flags_a_collecting,
      { "Collecting",		"lacp.actorState.collecting",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_COLLECTING,
      	"Collection of incoming frames is: Enabled = 1, Disabled = 0", HFILL }},


    { &hf_lacpdu_flags_a_distrib,
      { "Distributing",		"lacp.actorState.distributing",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_DISTRIB,
      	"Distribution of outgoing frames is: Enabled = 1, Disabled = 0", HFILL }},



    { &hf_lacpdu_flags_a_defaulted,
      { "Defaulted",		"lacp.actorState.defaulted",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_DEFAULTED,
      	"1 = Actor Rx machine is using DEFAULT Partner info, 0 = using info in Rx'd LACPDU", HFILL }},


    { &hf_lacpdu_flags_a_expired,
      { "Expired",		"lacp.actorState.expired",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_EXPIRED,
      	"1 = Actor Rx machine is EXPIRED, 0 = is NOT EXPIRED", HFILL }},


    { &hf_lacpdu_actor_reserved,
      { "Reserved",		"lacp.reserved",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},

    { &hf_lacpdu_partner_type,
      { "Partner Information",	"lacp.partnerInfo",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"TLV type = Partner", HFILL }},

    { &hf_lacpdu_partner_info_len,
      { "Partner Information Length",			"lacp.partnerInfoLen",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"The length of the Partner TLV", HFILL }},

    { &hf_lacpdu_partner_sys_priority,
      { "Partner System Priority",  "lacp.partnerSysPriority",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	"The priority assigned to the Partner System by management or admin", HFILL }},

    { &hf_lacpdu_partner_sys,
      { "Partner System",			"lacp.partnerSystem",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	"The Partner's System ID encoded as a MAC address", HFILL }},

    { &hf_lacpdu_partner_key,
      { "Partner Key",			"lacp.partnerKey",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	"The operational Key value assigned to the port associated with this link by the Partner", HFILL }},

    { &hf_lacpdu_partner_port_priority,
      { "Partner Port Priority",			"lacp.partnerPortPriority",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	"The priority assigned to the port by the Partner (via Management or Admin)", HFILL }},

    { &hf_lacpdu_partner_port,
      { "Partner Port",			"lacp.partnerPort",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	"The port number associated with this link assigned to the port by the Partner (via Management or Admin)", HFILL }},

    { &hf_lacpdu_partner_state,
      { "Partner State",			"lacp.partnerState",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"The Partner's state variables for the port, encoded as bits within a single octet", HFILL }},

    { &hf_lacpdu_flags_p_activity,
      { "LACP Activity",		"lacp.partnerState.activity",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_ACTIVITY,
      	"Activity control value for this link. Active = 1, Passive = 0", HFILL }},

    { &hf_lacpdu_flags_p_timeout,
      { "LACP Timeout",		"lacp.partnerState.timeout",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_TIMEOUT,
      	"Timeout control value for this link. Short Timeout = 1, Long Timeout = 0", HFILL }},


    { &hf_lacpdu_flags_p_aggregation,
      { "Aggregation",		"lacp.partnerState.aggregation",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_AGGREGATION,
      	"Aggregatable = 1, Individual = 0", HFILL }},


    { &hf_lacpdu_flags_p_sync,
      { "Synchronization",		"lacp.partnerState.synchronization",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_SYNC,
      	"In Sync = 1, Out of Sync = 0", HFILL }},


    { &hf_lacpdu_flags_p_collecting,
      { "Collecting",		"lacp.partnerState.collecting",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_COLLECTING,
      	"Collection of incoming frames is: Enabled = 1, Disabled = 0", HFILL }},


    { &hf_lacpdu_flags_p_distrib,
      { "Distributing",		"lacp.partnerState.distributing",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_DISTRIB,
      	"Distribution of outgoing frames is: Enabled = 1, Disabled = 0", HFILL }},



    { &hf_lacpdu_flags_p_defaulted,
      { "Defaulted",		"lacp.partnerState.defaulted",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_DEFAULTED,
      	"1 = Actor Rx machine is using DEFAULT Partner info, 0 = using info in Rx'd LACPDU", HFILL }},


    { &hf_lacpdu_flags_p_expired,
      { "Expired",		"lacp.partnerState.expired",
	FT_BOOLEAN,	8,		TFS(&yesno),	LACPDU_FLAGS_EXPIRED,
      	"1 = Actor Rx machine is EXPIRED, 0 = is NOT EXPIRED", HFILL }},


    { &hf_lacpdu_partner_reserved,
      { "Reserved",		"lacp.reserved",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},

    { &hf_lacpdu_coll_type,
      { "Collector Information",	"lacp.collectorInfo",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"TLV type = Collector", HFILL }},

    { &hf_lacpdu_coll_info_len,
      { "Collector Information Length",			"lacp.collectorInfoLen",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"The length of the Collector TLV", HFILL }},

    { &hf_lacpdu_coll_max_delay,
      { "Collector Max Delay",  "lacp.collectorMaxDelay",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	"The max delay of the station tx'ing the LACPDU (in tens of usecs)", HFILL }},

    { &hf_lacpdu_coll_reserved,
      { "Reserved",		"lacp.reserved",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},


    { &hf_lacpdu_term_type,
      { "Terminator Information",	"lacp.termInfo",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"TLV type = Terminator", HFILL }},

    { &hf_lacpdu_term_len,
      { "Terminator Length",			"lacp.termLen",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"The length of the Terminator TLV", HFILL }},

    { &hf_lacpdu_term_reserved,
      { "Reserved",		"lacp.reserved",
	FT_BYTES,	BASE_NONE,	NULL,	0x0,
      	"", HFILL }},

  };

  /* Setup protocol subtree array */

  static gint *ett[] = {
    &ett_lacpdu,
    &ett_lacpdu_a_flags,
    &ett_lacpdu_p_flags,
  };

  /* Register the protocol name and description */

  proto_lacpdu = proto_register_protocol("Link Aggregation Control Protocol", "LACP", "lacp");

  /* Required function calls to register the header fields and subtrees used */

  proto_register_field_array(proto_lacpdu, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_lacpdu(void)
{
  dissector_handle_t slow_protocols_handle;

  slow_protocols_handle = create_dissector_handle(dissect_slow_protocols, proto_lacpdu);
  dissector_add("ethertype", ETHERTYPE_SLOW_PROTOCOLS, slow_protocols_handle);
}
