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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>


/*
 * See
 *
 *	http://stationpayloads.jsc.nasa.gov/J-reference/documents/ssp57002B.pdf
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
static int hf_ccsds_checkword = -1;

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

/* Initialize the subtree pointers */
static gint ett_ccsds = -1;
static gint ett_ccsds_primary_header = -1;
static gint ett_ccsds_secondary_header = -1;

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




/* convert time from utc to julian values */
void utc_to_julian ( int utc, int* year, int* julianday, int* hour, int* minute, int* second )
{
        static int Days[2][13] =
        {
                { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
                { 0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
        };

        int j, days_yr[2], left, secs;

        /* oops... */
        if ( ! year  ||  ! julianday  ||  ! hour  ||  ! minute  ||  ! second ) return;

        *year = 1970;
        *julianday = 0;
        *hour = 0;
        *minute = 0;
        *second = 0;

        days_yr[0] = days_yr[1] = 0;

        for ( j=1; j < 13; ++j )
        {
                days_yr[0] += Days[0][j];
                days_yr[1] += Days[1][j];
        }

        left = utc;
        secs = days_yr[Leap(*year)] * 24 * 60 * 60;

        while (left > secs)
        {
                ++(*year);
                left -= secs;
                secs = days_yr[Leap(*year)] * 24 * 60 * 60;
        }

        *julianday = (left / (24 * 60 * 60)) + 1;
        left = left % (24 * 60 * 60);

        *hour = left / (60 * 60);
        left = left % (60 * 60);

        *minute = left / 60;

        *second = left % 60;

}



/* convert ccsds embedded time to a human readable string - NOT THREAD SAFE */
static const char* embedded_time_to_string ( int coarse_time, int fine_time )
{
        static const char* fmt = "%04d/%03d:%02d:%02d:%02d.%03d";
        static char juliantime[40];
        static int utcdiff = 0;

        int utc, yr, year, julianday, hour, minute, second, fraction;
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

        utc = coarse_time + utcdiff;
        utc_to_julian ( utc, &year, &julianday, &hour, &minute, &second );

        fraction = ( multiplier * ( (int)fine_time & 0xff ) ) / 256;

        g_snprintf ( juliantime, sizeof(juliantime), fmt, year, julianday, hour, minute, second, fraction );

        return juliantime;

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

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CCSDS");
	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_set_str(pinfo->cinfo, COL_INFO, "CCSDS Packet");

	if (tree) {
		ccsds_packet = proto_tree_add_item(tree, proto_ccsds, tvb, 0, -1, FALSE);
		ccsds_tree = proto_item_add_subtree(ccsds_packet, ett_ccsds);

                /* build the ccsds primary header tree */
		primary_header=proto_tree_add_text(ccsds_tree, tvb, offset, CCSDS_PRIMARY_HEADER_LENGTH, "Primary CCSDS Header");
		primary_header_tree=proto_item_add_subtree(primary_header, ett_ccsds_primary_header);

		first_word=tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(primary_header_tree, hf_ccsds_version, tvb, offset, 2, first_word);
		proto_tree_add_uint(primary_header_tree, hf_ccsds_type, tvb, offset, 2, first_word);
		proto_tree_add_boolean(primary_header_tree, hf_ccsds_secheader, tvb, offset, 2, first_word);
		proto_tree_add_uint(primary_header_tree, hf_ccsds_apid, tvb, offset, 2, first_word);
		offset += 2;

		proto_tree_add_item(primary_header_tree, hf_ccsds_seqflag, tvb, offset, 2, FALSE);
		proto_tree_add_item(primary_header_tree, hf_ccsds_seqnum, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(primary_header_tree, hf_ccsds_length, tvb, offset, 2, FALSE);
		offset += 2;
		proto_item_set_end(primary_header, tvb, offset);

                /* build the ccsds secondary header tree */
		if ( first_word & HDR_SECHDR )
		{
			secondary_header=proto_tree_add_text(ccsds_tree, tvb, offset, CCSDS_SECONDARY_HEADER_LENGTH, "Secondary CCSDS Header");
			secondary_header_tree=proto_item_add_subtree(secondary_header, ett_ccsds_secondary_header);

                        /* command ccsds secondary header flags */
		        coarse_time=tvb_get_ntohl(tvb, offset);
			proto_tree_add_item(secondary_header_tree, hf_ccsds_coarse_time, tvb, offset, 4, FALSE);
			offset += 4;

		        fine_time=tvb_get_guint8(tvb, offset);
			proto_tree_add_item(secondary_header_tree, hf_ccsds_fine_time, tvb, offset, 1, FALSE);
			++offset;

                        time_string = embedded_time_to_string ( coarse_time, fine_time );
                        proto_tree_add_text(secondary_header_tree, tvb, offset-5, 5, "%s = Embedded Time", time_string);

			proto_tree_add_item(secondary_header_tree, hf_ccsds_timeid, tvb, offset, 1, FALSE);
			proto_tree_add_item(secondary_header_tree, hf_ccsds_checkword, tvb, offset, 1, FALSE);

                        /* payload specific ccsds secondary header flags */
                        if ( first_word & HDR_TYPE )
                        {
		        	proto_tree_add_item(secondary_header_tree, hf_ccsds_zoe, tvb, offset, 1, FALSE);
			        proto_tree_add_item(secondary_header_tree, hf_ccsds_packet_type_unused, tvb, offset, 1, FALSE);
			        ++offset;

			        proto_tree_add_item(secondary_header_tree, hf_ccsds_vid, tvb, offset, 2, FALSE);
			        offset += 2;

			        proto_tree_add_item(secondary_header_tree, hf_ccsds_dcc, tvb, offset, 2, FALSE);
			        offset += 2;
                        }

                        /* core specific ccsds secondary header flags */
                        else
                        {
		        	/* proto_tree_add_item(secondary_header_tree, hf_ccsds_spare1, tvb, offset, 1, FALSE); */
			        proto_tree_add_item(secondary_header_tree, hf_ccsds_packet_type, tvb, offset, 1, FALSE);
			        ++offset;

			        /* proto_tree_add_item(secondary_header_tree, hf_ccsds_spare2, tvb, offset, 2, FALSE); */
			        proto_tree_add_item(secondary_header_tree, hf_ccsds_element_id, tvb, offset, 2, FALSE);
			        proto_tree_add_item(secondary_header_tree, hf_ccsds_cmd_data_packet, tvb, offset, 2, FALSE);
			        proto_tree_add_item(secondary_header_tree, hf_ccsds_format_version_id, tvb, offset, 2, FALSE);
			        proto_tree_add_item(secondary_header_tree, hf_ccsds_extended_format_id, tvb, offset, 2, FALSE);
			        offset += 2;

			        /* proto_tree_add_item(secondary_header_tree, hf_ccsds_spare3, tvb, offset, 1, FALSE); */
                                ++offset;

			        proto_tree_add_item(secondary_header_tree, hf_ccsds_frame_id, tvb, offset, 1, FALSE);
			        ++offset;
                        }

                        /* finish the ccsds secondary header */
			proto_item_set_end(secondary_header, tvb, offset);
		}

                /* everything that's left is the remainder of the packet data zone */
		proto_tree_add_text(ccsds_tree, tvb, offset, -1, "Data");
	}
}


/* Register the protocol with Wireshark
 * this format is require because a script is used to build the C function
 * that calls all the protocol registration.
 */
void
proto_register_ccsds(void)
{                 
        /* Setup list of header fields  See Section 1.6.1 for details*/
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
		{ &hf_ccsds_checkword,
			{ "Checkword Indicator",           "ccsds.checkword",
			FT_UINT8, BASE_DEC, NULL, 0x20,          
			NULL, HFILL }
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

	};

        /* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ccsds,
		&ett_ccsds_primary_header,
		&ett_ccsds_secondary_header
	};

        /* Register the protocol name and description */
	proto_ccsds = proto_register_protocol("CCSDS", "CCSDS", "ccsds");

        /* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_ccsds, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


/* If this dissector uses sub-dissector registration add a registration routine.
 * This format is required because a script is used to find these routines and
 * create the code that calls these routines.
 */
void
proto_reg_handoff_ccsds(void)
{
	register_dissector ( "ccsds", dissect_ccsds, proto_ccsds );
	dissector_add ( "udp.port", 0, find_dissector("ccsds") );
}

