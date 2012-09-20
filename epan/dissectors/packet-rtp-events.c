/* packet-rtp-events.c
 *
 * Routines for RFC 2833 RTP Events dissection
 * Copyright 2003, Kevin A. Noll <knoll[AT]poss.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * Ref http://www.ietf.org/rfc/rfc4733.txt?number=4733
 */

/*
 * This dissector tries to dissect RTP Events.
 *
 * Cisco NSE is now supported, additions by
 *                Gonzalo Salgueiro <gsalguei@cisco.com>
 *          Chidambaram Arunachalam <carunach@cisco.com>
 * Copyright 2008, Cisco Systems, Inc.
 */


#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-rtp-events.h"
#include "packet-rtp.h"
#include <epan/tap.h>

/*  rtp_event_payload_type_value is the value used globally
	to set the appropriate payload type
*/
static guint rtp_event_payload_type_value = 101;

/*  cisco_nse_pt_value is used globally
	to set the appropriate Cisco NSE payload type value
 */
static guint cisco_nse_pt_value = 100;


/* RTP Event Fields */

static int proto_rtp_events          = -1;
static int rtp_event_tap = -1;

static int hf_rtp_events_event = -1; /* one byte */
static int hf_rtp_events_end = -1; /* one bit */
static int hf_rtp_events_reserved = -1; /* one bit */
static int hf_rtp_events_volume = -1; /* six bits */
static int hf_rtp_events_duration = -1; /* sixteen bits */


/* RTP Events fields defining a subtree */

static gint ett_rtp_events           = -1;

void
proto_reg_handoff_rtp_events(void);

static struct _rtp_event_info rtp_event_info;

static void
dissect_rtp_events( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	proto_item *ti            = NULL;
	proto_tree *rtp_events_tree     = NULL;
	unsigned int offset       = 0;
	struct _rtp_conversation_info *p_conv_data = NULL;

	guint8      rtp_evt;
	guint8      octet;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP EVENT");
	col_clear(pinfo->cinfo, COL_INFO);


	/* Get event fields */

	rtp_evt = tvb_get_guint8(tvb, offset );

	/* get tap info */
	rtp_event_info.info_rtp_evt = rtp_evt;

	p_conv_data = p_get_proto_data(pinfo->fd, proto_get_id_by_filter_name("rtp"));
	if (p_conv_data)
		rtp_event_info.info_setup_frame_num = p_conv_data->frame_number;
	else
		rtp_event_info.info_setup_frame_num = 0;


	if ( check_col( pinfo->cinfo, COL_INFO) )
	{
		col_add_fstr( pinfo->cinfo, COL_INFO,
		    "Payload type=RTP Event, %s",
		    val_to_str( rtp_evt, rtp_event_type_values, "Unknown (%u)" ));
	}

	ti = proto_tree_add_item( tree, proto_rtp_events, tvb, offset, -1, ENC_NA );
	rtp_events_tree = proto_item_add_subtree( ti, ett_rtp_events );

	proto_tree_add_uint ( rtp_events_tree, hf_rtp_events_event, tvb, offset, 1, rtp_evt);
	offset++;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_boolean (rtp_events_tree, hf_rtp_events_end, tvb, offset, 1, octet);
	proto_tree_add_boolean (rtp_events_tree, hf_rtp_events_reserved, tvb, offset, 1, octet);
	proto_tree_add_uint ( rtp_events_tree, hf_rtp_events_volume, tvb, offset, 1, octet);
	offset++;

	/* The duration field indicates the duration of the event or segment
	 * being reported, in timestamp units.
	 */
	rtp_event_info.info_duration = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item ( rtp_events_tree, hf_rtp_events_duration, tvb, offset, 2, ENC_BIG_ENDIAN);

	/* set the end info for the tap */
	if (octet & 0x80)
	{
		rtp_event_info.info_end = TRUE;
	} else
	{
		rtp_event_info.info_end = FALSE;
	}

	/* Make end-of-event packets obvious in the info column */
	if ((octet & 0x80))
	{
		col_append_str(pinfo->cinfo, COL_INFO, " (end)");
	}

	tap_queue_packet(rtp_event_tap, pinfo, &rtp_event_info);
}


void
proto_register_rtp_events(void)
{

	module_t *rtp_events_module;

	static hf_register_info hf[] =
	{
		{
			&hf_rtp_events_event,
			{
				"Event ID",
				"rtpevent.event_id",
				FT_UINT8,
				BASE_DEC,
				VALS(rtp_event_type_values),
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_events_end,
			{
				"End of Event",
				"rtpevent.end_of_event",
				FT_BOOLEAN,
				8,
				NULL,
				0x80,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_events_reserved,
			{
				"Reserved",
				"rtpevent.reserved",
				FT_BOOLEAN,
				8,
				NULL,
				0x40,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_events_volume,
			{
				"Volume",
				"rtpevent.volume",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x3F,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_events_duration,
			{
				"Event Duration",
				"rtpevent.duration",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

	};

	static gint *ett[] =
	{
		&ett_rtp_events,
	};


	proto_rtp_events = proto_register_protocol("RFC 2833 RTP Event", "RTP Event", "rtpevent");
	proto_register_field_array(proto_rtp_events, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));


	/* Register preferences */
	rtp_events_module = prefs_register_protocol (proto_rtp_events, proto_reg_handoff_rtp_events);
	prefs_register_uint_preference (rtp_events_module,
                                    "event_payload_type_value", "Payload Type for RFC2833 RTP Events",
                                    "This is the value of the Payload Type field"
                                    " that specifies RTP Events", 10,
                                    &rtp_event_payload_type_value);


	prefs_register_uint_preference (rtp_events_module,
                                    "cisco_nse_payload_type_value", "Payload Type for Cisco Named Signaling Events",
                                    "This is the value of the Payload Type field"
                                    " that specifies Cisco Named Signaling Events", 10,
                                    &cisco_nse_pt_value);

	register_dissector("rtpevent", dissect_rtp_events, proto_rtp_events);
	rtp_event_tap = register_tap("rtpevent");
}



void
proto_reg_handoff_rtp_events(void)
{
	static dissector_handle_t rtp_events_handle;
	/* saved_payload_type_value is a temporary place to save */
	/* the value so we can properly reinitialize when the    */
	/* settings get changed.                                 */
	static guint saved_payload_type_value;
	static guint saved_cisco_nse_pt_value;
	static gboolean rtp_events_prefs_initialized = FALSE;

	if (!rtp_events_prefs_initialized) {
		rtp_events_handle = find_dissector("rtpevent");
		dissector_add_string("rtp_dyn_payload_type", "telephone-event", rtp_events_handle);
		dissector_add_string("rtp_dyn_payload_type", "X-NSE", rtp_events_handle);
		rtp_events_prefs_initialized = TRUE;
	}
	else {
		dissector_delete_uint("rtp.pt", saved_payload_type_value, rtp_events_handle);
		dissector_delete_uint("rtp.pt", saved_cisco_nse_pt_value, rtp_events_handle);
	}

	saved_payload_type_value = rtp_event_payload_type_value;
	/* rtp_event_payload_type_value is set from preferences */
	saved_cisco_nse_pt_value = cisco_nse_pt_value;
	/* cisco_nse_pt_value is set from preferences */

	dissector_add_uint("rtp.pt", saved_payload_type_value, rtp_events_handle);
	dissector_add_uint("rtp.pt", saved_cisco_nse_pt_value, rtp_events_handle);
}
