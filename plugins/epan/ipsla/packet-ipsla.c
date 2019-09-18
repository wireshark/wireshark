/* packet-ipsla.c
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

#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/to_str.h>



#include <string.h>

#define PROTO_TAG_IPSLA	"IPSLA"

#define CONTROL_PACKET_V1 0
#define CONTROL_PACKET_V2 1
#define MEASUREMENT_PACKET_V1 2
#define MEASUREMENT_PACKET_V2 3
#define MEASUREMENT_PACKET_V3 10

/* Wireshark ID of the IPSLA protocol */
static int proto_ipsla = -1;

/* These are the handles of our subdissectors */
static dissector_handle_t data_handle=NULL;

static dissector_handle_t ipsla_handle;
gint dissect_ipsla(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

static int global_ipsla_port = 5000;

static const value_string packettypenames[] = {
	{ CONTROL_PACKET_V1, "CONTROL_PACKET_V1" },
	{ CONTROL_PACKET_V2, "CONTROL_PACKET_V2" },
        { MEASUREMENT_PACKET_V1, "MEASUREMENT_PACKET_V1" },
        { MEASUREMENT_PACKET_V2, "MEASUREMENT_PACKET_V2" },
        { MEASUREMENT_PACKET_V3, "MEASUREMENT_PACKET_V3" },
	{ 0, NULL }
};	


/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_ipsla()
*/
//static int hf_ipsla_pdu = -1;
/** Kts attempt at defining the protocol */

static gint hf_ipsla_probe_type = -1;
static gint hf_ipsla_delta_time = -1;

static gint hf_ipsla_send_time = -1;
static gint hf_ipsla_recv_time = -1;

static gint hf_ipsla_sender_send_time = -1;
static gint hf_ipsla_responder_recv_time = -1;
static gint hf_ipsla_responder_send_time = -1;
static gint hf_ipsla_sender_recv_time = -1;
static gint hf_ipsla_sender_offset = -1;
static gint hf_ipsla_responder_offset = -1;

static gint hf_ipsla_sender_sequence_number = -1;
static gint hf_ipsla_responder_sequence_number = -1;
static gint hf_ipsla_data = -1;


/* These are the ids of the subtrees that we may be creating */
static gint ett_ipsla_probe = -1;

void proto_reg_handoff_ipsla(void)
{
	static gboolean initialized=FALSE;

	if (!initialized) {
		data_handle = find_dissector("data");
		ipsla_handle = create_dissector_handle(dissect_ipsla, proto_ipsla);
                dissector_add_uint("udp.port", global_ipsla_port, ipsla_handle);
	}

}

void proto_register_ipsla (void)
{
	/* A header field is something you can search/filter on.
	* 
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/
    static hf_register_info hf[] = {
        { &hf_ipsla_probe_type,
            { "Probe Type", "ipsla.probe_type",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Probe Type", HFILL }
        },
        { &hf_ipsla_delta_time,
            { "Delta Time", "ipsla.delta_time",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Delta Time", HFILL }
        },
        { &hf_ipsla_send_time,
            { "Send Time", "ipsla.send_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Send Time", HFILL }
        },
        { &hf_ipsla_recv_time,
            { "Recv Time", "ipsla.recv_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Recv Time", HFILL }
        },
        { &hf_ipsla_sender_send_time,
            { "Sender Send Time", "ipsla.sender_send_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            "Sender Send Time", HFILL }
        },
        { &hf_ipsla_responder_recv_time,
            { "Responder Recv Time", "ipsla.responder_recieve_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            "Responder Recv Time", HFILL }
        },
        { &hf_ipsla_responder_send_time,
            { "Responder Send Time", "ipsla.responder_send_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            "Responder Send Time", HFILL }
        },
        { &hf_ipsla_sender_recv_time,
            { "Sender Recv Time", "ipsla.sender_recv_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            "Sender Recv Time", HFILL }
        },
        { &hf_ipsla_sender_offset,
            { "Sender Offset", "ipsla.sender_recv_time",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            "Sender Offset", HFILL }
        },
        { &hf_ipsla_responder_offset,
            { "Recv Offset", "ipsla.sender_recv_time",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            "Recv Offset", HFILL }
        },
        { &hf_ipsla_sender_sequence_number,
            { "Sender Sequence Number", "ipsla.sender_sequence_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Sender Sequence Number", HFILL }
        },
        { &hf_ipsla_responder_sequence_number,
            { "Responder Sequence Number", "ipsla.responder_sequence_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Responder Sequence Number", HFILL }
        },
        { &hf_ipsla_data,
            { "Data", "ipsla.data",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Data", HFILL }
        }
    };

    static gint *ett[] = {
		&ett_ipsla_probe
	};
	//if (proto_ipsla == -1) { /* execute protocol initialization only once */
	proto_ipsla = proto_register_protocol ("IPSLA Protocol", "IPSLA", "ipsla");

	proto_register_field_array (proto_ipsla, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
	register_dissector("ipsla", dissect_ipsla, proto_ipsla);
	//}
}

#define MSPERDAY            86400000

/* ======================================================================= */
static guint32
get_best_guess_mstimeofday(tvbuff_t * tvb, gint offset, guint32 comp_ts)
{
    guint32 be_ts, le_ts;

    /* Account for the special case from RFC 792 as best we can by clearing
     * the msb.  Ref: [Page 16] of http://tools.ietf.org/html/rfc792:

     If the time is not available in milliseconds or cannot be provided
     with respect to midnight UT then any time can be inserted in a
     timestamp provided the high order bit of the timestamp is also set
     to indicate this non-standard value.
     */
    be_ts = tvb_get_ntohl(tvb, offset) & 0x7fffffff;
    le_ts = tvb_get_letohl(tvb, offset) & 0x7fffffff;

    if (be_ts < MSPERDAY && le_ts >= MSPERDAY) {
        return be_ts;
    }

    if (le_ts < MSPERDAY && be_ts >= MSPERDAY) {
        return le_ts;
    }

    if (be_ts < MSPERDAY && le_ts < MSPERDAY) {
        guint32 saved_be_ts = be_ts;
        guint32 saved_le_ts = le_ts;

        /* Is this a rollover to a new day, clocks not synchronized, different
         * timezones between originate and receive/transmit, .. what??? */
        if (be_ts < comp_ts && be_ts <= (MSPERDAY / 4)
            && comp_ts >= (MSPERDAY - (MSPERDAY / 4)))
            be_ts += MSPERDAY;	/* Assume a rollover to a new day */
        if (le_ts < comp_ts && le_ts <= (MSPERDAY / 4)
            && comp_ts >= (MSPERDAY - (MSPERDAY / 4)))
            le_ts += MSPERDAY;	/* Assume a rollover to a new day */
        if ((be_ts - comp_ts) < (le_ts - comp_ts))
            return saved_be_ts;
        return saved_le_ts;
    }

    /* Both are bigger than MSPERDAY, but neither one's msb's are set.  This
     * is clearly invalid, but now what TODO?  For now, take the one closest to
     * the comparative timestamp, which is another way of saying, "let's
     * return a deterministic wild guess. */
    if ((be_ts - comp_ts) < (le_ts - comp_ts)) {
        return be_ts;
    }
    return le_ts;
}				/* get_best_guess_mstimeofday() */

static gint
dissect_ipsla(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{

	proto_item *ipsla_item = NULL;
	proto_tree *ipsla_tree = NULL;
        proto_item *ti = NULL;

	guint16 type = 0;
        guint32 offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_IPSLA);
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	// This is not a good way of dissecting packets.  The tvb length should
	// be sanity checked so we aren't going past the actual size of the buffer.
        type = tvb_get_guint16(tvb, 0, BASE_DEC);


	col_add_fstr(pinfo->cinfo, COL_INFO, "%d -> %d Info Type:[%s]",
	pinfo->srcport, pinfo->destport, 
	val_to_str(type, packettypenames, "Unknown Type:0x%02x"));

	if (tree) { /* we are being asked for details */

		ipsla_item = proto_tree_add_item(tree, proto_ipsla, tvb, 0, -1, FALSE);
		ipsla_tree = proto_item_add_subtree(ipsla_item, ett_ipsla_probe);

                guint32 frame_ts;

                frame_ts = (guint32)(((pinfo->abs_ts.secs * 1000) +
                    (pinfo->abs_ts.nsecs / 1000000)) %
                    86400000);

                type = tvb_get_guint16(tvb, 0, BASE_DEC);

                if (MEASUREMENT_PACKET_V1 == type)
                {
                    proto_tree_add_item(ipsla_tree, hf_ipsla_probe_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    proto_tree_add_item(ipsla_tree, hf_ipsla_delta_time, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    ti = proto_tree_add_item(ipsla_tree, hf_ipsla_send_time, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti, " (%s after midnight UTC)", signed_time_msecs_to_str(wmem_packet_scope(), get_best_guess_mstimeofday(tvb, offset, frame_ts)));
                    offset += 4;

                    ti = proto_tree_add_item(ipsla_tree, hf_ipsla_recv_time, tvb, offset, 4, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti, " (%s after midnight UTC)", signed_time_msecs_to_str(wmem_packet_scope(), get_best_guess_mstimeofday(tvb, offset, frame_ts)));
                    offset += 4;

                    proto_tree_add_item(ipsla_tree, hf_ipsla_sender_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    proto_tree_add_item(ipsla_tree, hf_ipsla_responder_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                }
                else if (MEASUREMENT_PACKET_V2 == type)
                {
                    proto_tree_add_item(ipsla_tree, hf_ipsla_probe_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    /*Priority (Reserved in RFC6812) - which is 2 bytes, so incrementing the offset by additional 2 bytes*/
                    offset += 2;

                    proto_tree_add_item(ipsla_tree, hf_ipsla_sender_send_time, tvb, offset, 8, ENC_TIME_NTP);
                    offset += 8;

                    proto_tree_add_item(ipsla_tree, hf_ipsla_responder_recv_time, tvb, offset, 8, ENC_TIME_NTP);
                    offset += 8;

                    proto_tree_add_item(ipsla_tree, hf_ipsla_responder_send_time, tvb, offset, 8, ENC_TIME_NTP);
                    offset += 8;

                    proto_tree_add_item(ipsla_tree, hf_ipsla_sender_recv_time, tvb, offset, 8, ENC_TIME_NTP);
                    offset += 8;

                    proto_tree_add_item(ipsla_tree, hf_ipsla_sender_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
                    offset += 8;

                    proto_tree_add_item(ipsla_tree, hf_ipsla_responder_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
                    offset += 8;

                    proto_tree_add_item(ipsla_tree, hf_ipsla_sender_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    proto_tree_add_item(ipsla_tree, hf_ipsla_responder_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                }
	}
        return offset;
}	
