/* packet-ccsds.c
 * Routines for CCSDS dissection
 * Copyright 2000, Scott Hovis scott.hovis@ums.msfc.nasa.gov
 * Enhanced 2008, Matt Dunkle Matthew.L.Dunkle@nasa.gov
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>


/*
 * See
 *
 *  http://public.ccsds.org/publications/archive/133x0b1c1.pdf section 4.1  -- CCSDS 133.0-B-1 replaces CCSDS 701.0-B-2
 *  http://www.everyspec.com/NASA/NASA+-+JSC/NASA+-+SSP+PUBS/download.php?spec=SSP_52050E.003096.pdf section 3.1.3
 *
 * for some information.
 */


/* Initialize the protocol and registered fields */
static int proto_ccsds = -1;

/* primary ccsds header */
static int hf_ccsds_apid = -1;
static int hf_ccsds_version = -1;
static int hf_ccsds_secheader = -1;
static int hf_ccsds_type = -1;
static int hf_ccsds_seqnum = -1;
static int hf_ccsds_seqflag = -1;
static int hf_ccsds_length = -1;

/* common ccsds secondary header */
static int hf_ccsds_coarse_time = -1;
static int hf_ccsds_fine_time = -1;
static int hf_ccsds_timeid = -1;
static int hf_ccsds_checkword_flag = -1;

/* payload specific ccsds secondary header */
static int hf_ccsds_zoe = -1;
static int hf_ccsds_packet_type_unused = -1;
static int hf_ccsds_vid = -1;
static int hf_ccsds_dcc = -1;

/* core specific ccsds secondary header */
static int hf_ccsds_spare1 = -1;
static int hf_ccsds_packet_type = -1;
static int hf_ccsds_spare2 = -1;
static int hf_ccsds_element_id = -1;
static int hf_ccsds_cmd_data_packet = -1;
static int hf_ccsds_format_version_id = -1;
static int hf_ccsds_extended_format_id = -1;
static int hf_ccsds_spare3 = -1;
static int hf_ccsds_frame_id = -1;

/* ccsds checkword (checksum) */
static int hf_ccsds_checkword = -1;
static int hf_ccsds_checkword_good = -1;
static int hf_ccsds_checkword_bad = -1;

/* Initialize the subtree pointers */
static gint ett_ccsds = -1;
static gint ett_ccsds_primary_header = -1;
static gint ett_ccsds_secondary_header = -1;
static gint ett_ccsds_checkword = -1;

/* Generic data handle */
static dissector_handle_t data_handle;

/* Forward declaration we need below */
void proto_reg_handoff_ccsds(void);

static enum_val_t dissect_checkword[] = {
  { "hdr", "Use header flag", 2 },
  { "no", "Override header flag to be false", 0 },
  { "yes", "Override header flag to be true", 1 },
  { NULL, NULL, 0 }
};

/* Global preferences */
/* As defined above, default is to use header flag */
static gint global_dissect_checkword = 2;

/*
 * Bits in the first 16-bit header word
 */
#define HDR_VERSION	0xe000
#define HDR_TYPE	0x1000
#define HDR_SECHDR	0x0800
#define HDR_APID	0x07ff

/* some basic sizing parameters */
enum
{
  IP_HEADER_LENGTH = 48,
  VCDU_HEADER_LENGTH = 6,
  CCSDS_PRIMARY_HEADER_LENGTH = 6,
  CCSDS_SECONDARY_HEADER_LENGTH = 10
};

/* leap year macro */
#ifndef Leap
#  define Leap(yr) ( ( 0 == (yr)%4  &&  0 != (yr)%100 )  ||  ( 0 == (yr)%400 ) )
#endif


static const value_string ccsds_primary_header_sequence_flags[] = {
  { 0, "Continuation segment" },
  { 1, "First segment" },
  { 2, "Last segment" },
  { 3, "Unsegmented data" },
  { 0, NULL }
};

static const value_string ccsds_secondary_header_type[] = {
  { 0, "Core" },
  { 1, "Payload" },
  { 0, NULL }
};

static const value_string ccsds_secondary_header_packet_type[] = {
  { 0,  "UNDEFINED" },
  { 1,  "Data Dump" },
  { 2,  "UNDEFINED" },
  { 3,  "UNDEFINED" },
  { 4,  "TLM/Status" },
  { 5,  "UNDEFINED" },
  { 6,  "Payload Private/Science" },
  { 7,  "Ancillary Data" },
  { 8,  "Essential Cmd" },
  { 9,  "System Cmd" },
  { 10, "Payload Cmd" },
  { 11, "Data Load/File Transfer" },
  { 12, "UNDEFINED" },
  { 13, "UNDEFINED" },
  { 14, "UNDEFINED" },
  { 15, "UNDEFINED" },
  { 0, NULL }
};

static const value_string ccsds_secondary_header_element_id[] = {
  { 0,  "NASA (Ground Test Only)" },
  { 1,  "NASA" },
  { 2,  "ESA/APM" },
  { 3,  "NASDA" },
  { 4,  "RSA" },
  { 5,  "CSA" },
  { 6,  "ESA/ATV" },
  { 7,  "ASI" },
  { 8,  "ESA/ERA" },
  { 9,  "Reserved" },
  { 10, "RSA SPP" },
  { 11, "NASDA HTV" },
  { 12, "Reserved" },
  { 13, "Reserved" },
  { 14, "Reserved" },
  { 15, "Reserved" },
  { 0, NULL }
};

static const value_string ccsds_secondary_header_cmd_data_packet[] = {
  { 0, "Command Packet" },
  { 1, "Data Packet" },
  { 0, NULL }
};

static const value_string ccsds_secondary_header_format_id[] = {
  { 0,  "Reserved" },
  { 1,  "Essential Telemetry" },
  { 2,  "Housekeeping Tlm - 1" },
  { 3,  "Housekeeping Tlm - 2" },
  { 4,  "PCS DDT" },
  { 5,  "CCS S-Band Command Response" },
  { 6,  "Contingency Telemetry via the SMCC" },
  { 7,  "Normal Data Dump" },
  { 8,  "Extended Data Dump" },
  { 9,  "Reserved" },
  { 10, "Reserved" },
  { 11, "Broadcast Ancillary Data" },
  { 12, "Reserved" },
  { 13, "NCS to OIU Telemetry and ECOMM Telemetry" },
  { 14, "CCS to OIU Telemetry - Direct" },
  { 15, "Reserved" },
  { 16, "Normal File Dump" },
  { 17, "Extended File Dump" },
  { 18, "NCS to FGB Telemetry" },
  { 19, "Reserved" },
  { 20, "ZOE Normal Dump (S-Band)" },
  { 21, "ZOE Extended Dump (S-Band)" },
  { 22, "EMU S-Band TLM Packet" },
  { 23, "Reserved" },
  { 24, "Reserved" },
  { 25, "Reserved" },
  { 26, "CCS to OIU Telemetry via UHF" },
  { 27, "OSTP Telemetry (After Flight 1E, CCS R5)" },
  { 28, "Reserved" },
  { 29, "Reserved" },
  { 30, "Reserved" },
  { 31, "Reserved" },
  { 32, "Reserved" },
  { 33, "Reserved" },
  { 34, "Reserved" },
  { 35, "Reserved" },
  { 36, "Reserved" },
  { 37, "Reserved" },
  { 38, "Reserved" },
  { 39, "Reserved" },
  { 40, "Reserved" },
  { 41, "Reserved" },
  { 42, "Reserved" },
  { 43, "Reserved" },
  { 44, "Reserved" },
  { 45, "Reserved" },
  { 46, "Reserved" },
  { 47, "Reserved" },
  { 48, "Reserved" },
  { 49, "Reserved" },
  { 50, "Reserved" },
  { 51, "Reserved" },
  { 52, "Reserved" },
  { 53, "Reserved" },
  { 54, "Reserved" },
  { 55, "Reserved" },
  { 56, "Reserved" },
  { 57, "Reserved" },
  { 58, "Reserved" },
  { 59, "Reserved" },
  { 60, "Reserved" },
  { 61, "Reserved" },
  { 62, "Reserved" },
  { 63, "Reserved" },
  { 0, NULL }
};




/* convert ccsds embedded time to a human readable string - NOT THREAD SAFE */
static const char* embedded_time_to_string ( int coarse_time, int fine_time )
{
        static int utcdiff = 0;
        nstime_t t;
        int yr;
        int fraction;
        int multiplier = 1000;

        /* compute the static constant difference in seconds
         * between midnight 5-6 January 1980 (GPS time) and
         * seconds since 1/1/1970 (UTC time) just this once
         */
        if ( 0 == utcdiff )
        {
                for ( yr=1970; yr < 1980; ++yr )
                {
                        utcdiff += ( Leap(yr)  ?  366 : 365 ) * 24 * 60 * 60;
                }

                utcdiff += 5 * 24 * 60 * 60;  /* five days of January 1980 */
        }

        t.secs = coarse_time + utcdiff;
        fraction = ( multiplier * ( (int)fine_time & 0xff ) ) / 256;
        t.nsecs = fraction*1000000;	/* msecs to nsecs */

	return abs_time_to_str(&t, ABSOLUTE_TIME_DOY_UTC, TRUE);
}


/* Code to actually dissect the packets */
static void
dissect_ccsds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_item *ccsds_packet;
	proto_tree *ccsds_tree;
	proto_item *primary_header;
	proto_tree *primary_header_tree;
	guint16 first_word;
	guint32 coarse_time;
	guint8 fine_time;
	proto_item *secondary_header;
	proto_tree *secondary_header_tree;
        const char* time_string;
	gint ccsds_length = 0;
	gint length;
	gint reported_length;
	guint8 checkword_flag = 0;
	gint counter = 0;
	proto_item *item = NULL;
	proto_tree *checkword_tree;
	guint16 checkword_field = 0;
	guint16 checkword_sum = 0;


	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CCSDS");
	col_set_str(pinfo->cinfo, COL_INFO, "CCSDS Packet");
	first_word=tvb_get_ntohs(tvb, 0);
	col_add_fstr(pinfo->cinfo, COL_INFO, "APID %1$4d (0x%1$03X)", first_word&HDR_APID);

	if (tree) {
		reported_length = tvb_reported_length_remaining(tvb, 0);
		ccsds_length = tvb_get_ntohs(tvb, 4) + CCSDS_PRIMARY_HEADER_LENGTH + 1;
		/* Min length is size of headers, whereas max length is reported length.
		 * If the length field in the CCSDS header is outside of these bounds,
		 * use the value it violates.  Otherwise, use the length field value.
		 */
		if (ccsds_length > reported_length)
			length = reported_length;
		else if (ccsds_length < CCSDS_PRIMARY_HEADER_LENGTH + CCSDS_SECONDARY_HEADER_LENGTH)
			length = CCSDS_PRIMARY_HEADER_LENGTH + CCSDS_SECONDARY_HEADER_LENGTH;
		else
			length = ccsds_length;

		ccsds_packet = proto_tree_add_item(tree, proto_ccsds, tvb, 0, length, FALSE);
		ccsds_tree = proto_item_add_subtree(ccsds_packet, ett_ccsds);

                /* build the ccsds primary header tree */
		primary_header=proto_tree_add_text(ccsds_tree, tvb, offset, CCSDS_PRIMARY_HEADER_LENGTH, "Primary CCSDS Header");
		primary_header_tree=proto_item_add_subtree(primary_header, ett_ccsds_primary_header);

		proto_tree_add_uint(primary_header_tree, hf_ccsds_version, tvb, offset, 2, first_word);
		proto_tree_add_uint(primary_header_tree, hf_ccsds_type, tvb, offset, 2, first_word);
		proto_tree_add_boolean(primary_header_tree, hf_ccsds_secheader, tvb, offset, 2, first_word);
		proto_tree_add_uint(primary_header_tree, hf_ccsds_apid, tvb, offset, 2, first_word);
		offset += 2;

		proto_tree_add_item(primary_header_tree, hf_ccsds_seqflag, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(primary_header_tree, hf_ccsds_seqnum, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		item = proto_tree_add_item(primary_header_tree, hf_ccsds_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		if (ccsds_length > reported_length) {
			expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
					"Length field value is greater than the packet seen on the wire");
		}
		offset += 2;
		proto_item_set_end(primary_header, tvb, offset);

                /* build the ccsds secondary header tree */
		if ( first_word & HDR_SECHDR )
		{
			secondary_header=proto_tree_add_text(ccsds_tree, tvb, offset, CCSDS_SECONDARY_HEADER_LENGTH, "Secondary CCSDS Header");
			secondary_header_tree=proto_item_add_subtree(secondary_header, ett_ccsds_secondary_header);

                        /* command ccsds secondary header flags */
		        coarse_time=tvb_get_ntohl(tvb, offset);
			proto_tree_add_item(secondary_header_tree, hf_ccsds_coarse_time, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

		        fine_time=tvb_get_guint8(tvb, offset);
			proto_tree_add_item(secondary_header_tree, hf_ccsds_fine_time, tvb, offset, 1, ENC_BIG_ENDIAN);
			++offset;

                        time_string = embedded_time_to_string ( coarse_time, fine_time );
                        proto_tree_add_text(secondary_header_tree, tvb, offset-5, 5, "%s = Embedded Time", time_string);

			proto_tree_add_item(secondary_header_tree, hf_ccsds_timeid, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(secondary_header_tree, hf_ccsds_checkword_flag, tvb, offset, 1, FALSE);

			/* Global Preference: how to handle checkword flag */
			switch (global_dissect_checkword) {
			   case 0:
			      /* force checkword presence flag to be false */
			      checkword_flag = 0;
			      break;
			   case 1:
			      /* force checkword presence flag to be true */
			      checkword_flag = 1;
			      break;
			   default:
			      /* use value of checkword presence flag from header */
			      checkword_flag = (tvb_get_guint8(tvb, offset)&0x20) >> 5;
			      break;
			}

                        /* payload specific ccsds secondary header flags */
                        if ( first_word & HDR_TYPE )
                        {
		        	proto_tree_add_item(secondary_header_tree, hf_ccsds_zoe, tvb, offset, 1, ENC_BIG_ENDIAN);
			        proto_tree_add_item(secondary_header_tree, hf_ccsds_packet_type_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
			        ++offset;

			        proto_tree_add_item(secondary_header_tree, hf_ccsds_vid, tvb, offset, 2, ENC_BIG_ENDIAN);
			        offset += 2;

			        proto_tree_add_item(secondary_header_tree, hf_ccsds_dcc, tvb, offset, 2, ENC_BIG_ENDIAN);
			        offset += 2;
                        }

                        /* core specific ccsds secondary header flags */
                        else
                        {
		        	/* proto_tree_add_item(secondary_header_tree, hf_ccsds_spare1, tvb, offset, 1, ENC_BIG_ENDIAN); */
			        proto_tree_add_item(secondary_header_tree, hf_ccsds_packet_type, tvb, offset, 1, ENC_BIG_ENDIAN);
			        ++offset;

			        /* proto_tree_add_item(secondary_header_tree, hf_ccsds_spare2, tvb, offset, 2, ENC_BIG_ENDIAN); */
			        proto_tree_add_item(secondary_header_tree, hf_ccsds_element_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			        proto_tree_add_item(secondary_header_tree, hf_ccsds_cmd_data_packet, tvb, offset, 2, ENC_BIG_ENDIAN);
			        proto_tree_add_item(secondary_header_tree, hf_ccsds_format_version_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			        proto_tree_add_item(secondary_header_tree, hf_ccsds_extended_format_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			        offset += 2;

			        /* proto_tree_add_item(secondary_header_tree, hf_ccsds_spare3, tvb, offset, 1, ENC_BIG_ENDIAN); */
                                ++offset;

			        proto_tree_add_item(secondary_header_tree, hf_ccsds_frame_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			        ++offset;
                        }

                        /* finish the ccsds secondary header */
			proto_item_set_end(secondary_header, tvb, offset);
		}

		/* If there wasn't a full packet, then don't allow a tree item for checkword. */
		if (reported_length < ccsds_length || ccsds_length < CCSDS_PRIMARY_HEADER_LENGTH + CCSDS_SECONDARY_HEADER_LENGTH) {
			/* Label CCSDS payload 'User Data' */
			if (length > offset)
				proto_tree_add_text(ccsds_tree, tvb, offset, length-offset, "User Data");
			offset += length-offset;
			if (checkword_flag == 1)
				proto_tree_add_text(ccsds_tree, tvb, offset, 0, "Packet does not contain a Checkword");
		}
		/*  Handle checkword according to CCSDS preference setting. */
		else {
			/* Label CCSDS payload 'User Data' */
			proto_tree_add_text(ccsds_tree, tvb, offset, length-offset-2*checkword_flag, "User Data");
			offset += length-offset-2*checkword_flag;

			/* If checkword is present, calculate packet checksum (16-bit running sum) for comparison */
			if (checkword_flag == 1) {
				/* don't count the checkword as part of the checksum */
				while (counter < ccsds_length-2) {
					checkword_sum += tvb_get_ntohs(tvb, counter);
					counter += 2;
				}
				checkword_field = tvb_get_ntohs(tvb, offset);

				/* Report checkword status */
				if (checkword_sum == checkword_field) {
					item = proto_tree_add_uint_format(ccsds_tree, hf_ccsds_checkword, tvb, offset, 2, checkword_field,
							"CCSDS checkword: 0x%04x [correct]", checkword_field);
					checkword_tree = proto_item_add_subtree(item, ett_ccsds_checkword);
					item = proto_tree_add_boolean(checkword_tree, hf_ccsds_checkword_good, tvb, offset, 2, TRUE);
					PROTO_ITEM_SET_GENERATED(item);
					item = proto_tree_add_boolean(checkword_tree, hf_ccsds_checkword_bad, tvb, offset, 2, FALSE);
					PROTO_ITEM_SET_GENERATED(item);
				} else {
					item = proto_tree_add_uint_format(ccsds_tree, hf_ccsds_checkword, tvb, offset, 2, checkword_field,
							"CCSDS checkword: 0x%04x [incorrect, should be 0x%04x]", checkword_field, checkword_sum);
					checkword_tree = proto_item_add_subtree(item, ett_ccsds_checkword);
					item = proto_tree_add_boolean(checkword_tree, hf_ccsds_checkword_good, tvb, offset, 2, FALSE);
					PROTO_ITEM_SET_GENERATED(item);
					item = proto_tree_add_boolean(checkword_tree, hf_ccsds_checkword_bad, tvb, offset, 2, TRUE);
					PROTO_ITEM_SET_GENERATED(item);
				}
				offset += 2;
			}
		}

		/* Give the data dissector any bytes past the CCSDS packet length */
		call_dissector(data_handle, tvb_new_subset(tvb, offset, tvb_length(tvb) - length, 0),
				pinfo, tree);
	}
}


/* Register the protocol with Wireshark
 * this format is required because a script is used to build the C function
 * that calls all the protocol registration.
 */
void
proto_register_ccsds(void)
{
	static hf_register_info hf[] = {

                /* primary ccsds header flags */
		{ &hf_ccsds_version,
			{ "Version",           "ccsds.version",
			FT_UINT16, BASE_DEC, NULL, HDR_VERSION,
			NULL, HFILL }
		},
		{ &hf_ccsds_type,
			{ "Type",           "ccsds.type",
			FT_UINT16, BASE_DEC, VALS(ccsds_secondary_header_type), HDR_TYPE,
			NULL, HFILL }
		},
		{ &hf_ccsds_secheader,
			{ "Secondary Header",           "ccsds.secheader",
			FT_BOOLEAN, 16, NULL, HDR_SECHDR,
			"Secondary Header Present", HFILL }
		},
		{ &hf_ccsds_apid,
			{ "APID",           "ccsds.apid",
			FT_UINT16, BASE_DEC, NULL, HDR_APID,
			NULL, HFILL }
		},
		{ &hf_ccsds_seqflag,
			{ "Sequence Flags",           "ccsds.seqflag",
			FT_UINT16, BASE_DEC, VALS(ccsds_primary_header_sequence_flags), 0xc000,
			NULL, HFILL }
		},
		{ &hf_ccsds_seqnum,
			{ "Sequence Number",           "ccsds.seqnum",
			FT_UINT16, BASE_DEC, NULL, 0x3fff,
			NULL, HFILL }
		},
		{ &hf_ccsds_length,
			{ "Packet Length",           "ccsds.length",
			FT_UINT16, BASE_DEC, NULL, 0xffff,
			NULL, HFILL }
		},


                /* common ccsds secondary header flags */
		{ &hf_ccsds_coarse_time,
			{ "Coarse Time",           "ccsds.coarse_time",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ccsds_fine_time,
			{ "Fine Time",           "ccsds.fine_time",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
		{ &hf_ccsds_timeid,
			{ "Time Identifier",           "ccsds.timeid",
			FT_UINT8, BASE_DEC, NULL, 0xc0,
			NULL, HFILL }
		},
		{ &hf_ccsds_checkword_flag,
			{ "Checkword Indicator",           "ccsds.checkword_flag",
			FT_BOOLEAN, 8, NULL, 0x20,
			"Checkword present", HFILL }
		},


                /* payload specific ccsds secondary header flags */
		{ &hf_ccsds_zoe,
			{ "ZOE TLM",           "ccsds.zoe",
			FT_UINT8, BASE_DEC, NULL, 0x10,
			"Contains S-band ZOE Packets", HFILL }
		},
		{ &hf_ccsds_packet_type_unused,
			{ "Packet Type (unused for Ku-band)",  "ccsds.packet_type",
			FT_UINT8, BASE_DEC, NULL, 0x0f,
			NULL, HFILL }
		},
		{ &hf_ccsds_vid,
			{ "Version Identifier",           "ccsds.vid",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ccsds_dcc,
			{ "Data Cycle Counter",           "ccsds.dcc",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},


                /* core specific ccsds secondary header flags */
		{ &hf_ccsds_spare1,
			{ "Spare Bit 1",           "ccsds.spare1",
			FT_UINT8, BASE_DEC, NULL, 0x10,
			"unused spare bit 1", HFILL }
		},
		{ &hf_ccsds_packet_type,
			{ "Packet Type",       "ccsds.packet_type",
			FT_UINT8, BASE_DEC, VALS(ccsds_secondary_header_packet_type), 0x0f,
			NULL, HFILL }
		},
		{ &hf_ccsds_spare2,
			{ "Spare Bit 2",           "ccsds.spare2",
			FT_UINT16, BASE_DEC, NULL, 0x8000,
			NULL, HFILL }
		},
		{ &hf_ccsds_element_id,
			{ "Element ID",           "ccsds.element_id",
			FT_UINT16, BASE_DEC, VALS(ccsds_secondary_header_element_id), 0x7800,
			NULL, HFILL }
		},
		{ &hf_ccsds_cmd_data_packet,
			{ "Cmd/Data Packet Indicator",  "ccsds.cmd_data_packet",
			FT_UINT16, BASE_DEC, VALS(ccsds_secondary_header_cmd_data_packet), 0x0400,
			NULL, HFILL }
		},
		{ &hf_ccsds_format_version_id,
			{ "Format Version ID",    "ccsds.format_version_id",
			FT_UINT16, BASE_DEC, NULL, 0x03c0,
			NULL, HFILL }
		},
		{ &hf_ccsds_extended_format_id,
			{ "Extended Format ID",   "ccsds.extended_format_id",
			FT_UINT16, BASE_DEC, VALS(ccsds_secondary_header_format_id), 0x003f,
			NULL, HFILL }
		},
		{ &hf_ccsds_spare3,
			{ "Spare Bits 3",         "ccsds.spare3",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
		{ &hf_ccsds_frame_id,
			{ "Frame ID",             "ccsds.frame_id",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL, HFILL }
		},
		{ &hf_ccsds_checkword,
			{ "CCSDS checkword",   "ccsds.checkword",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"CCSDS checkword: 16-bit running sum of all bytes excluding the checkword", HFILL }
		},
		{ &hf_ccsds_checkword_good,
			{ "Good",              "ccsds.checkword_good",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"True: checkword matches packet content; False: doesn't match content", HFILL }
		},
		{ &hf_ccsds_checkword_bad,
			{ "Bad",               "ccsds.checkword_bad",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"True: checkword doesn't match packet content; False: matches content", HFILL }
		}
	};

        /* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ccsds,
		&ett_ccsds_primary_header,
		&ett_ccsds_secondary_header,
		&ett_ccsds_checkword
	};

	/* Define the CCSDS preferences module */
	module_t *ccsds_module;

	/* Register the protocol name and description */
	proto_ccsds = proto_register_protocol("CCSDS", "CCSDS", "ccsds");

        /* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_ccsds, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector ( "ccsds", dissect_ccsds, proto_ccsds );

	/* Register preferences module */
	ccsds_module = prefs_register_protocol(proto_ccsds, proto_reg_handoff_ccsds);

	prefs_register_enum_preference(ccsds_module, "global_pref_checkword",
		"How to handle the CCSDS checkword",
		"Specify how the dissector should handle the CCSDS checkword",
		&global_dissect_checkword, dissect_checkword, FALSE);
}


/* If this dissector uses sub-dissector registration add a registration routine.
 * This format is required because a script is used to find these routines and
 * create the code that calls these routines.
 */
void
proto_reg_handoff_ccsds(void)
{
	dissector_add_handle ( "udp.port", find_dissector("ccsds") ); /* for 'decode as' */
	data_handle = find_dissector("data");
}

