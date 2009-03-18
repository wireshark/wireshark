/* packet-vcdu.c
 * Routines for VCDU dissection
 * Copyright 2000, Scott Hovis scott.hovis@ums.msfc.nasa.gov
 * Enhanced 2008, Matt Dunkle Matthew.L.Dunkle@nasa.gov
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.com>
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
#include <epan/filesystem.h>
#include <wsutil/file_util.h>


/* Initialize the protocol and registered fields */
static int proto_vcdu = -1;

static int hf_smex_gsc = -1;
static int hf_smex_unused = -1;
static int hf_smex_version = -1;
static int hf_smex_framelen = -1;
static int hf_smex_rs_error = -1;
static int hf_smex_rs_enable = -1;
static int hf_smex_crc_enable = -1;
static int hf_smex_crc_error = -1;
static int hf_smex_mcs_enable = -1;
static int hf_smex_mcs_num_error = -1;
static int hf_smex_data_inv = -1;
static int hf_smex_frame_sync = -1;
static int hf_smex_data_dir = -1;
static int hf_smex_data_class = -1;
static int hf_smex_pb5 = -1;
static int hf_smex_jday = -1;
static int hf_smex_seconds = -1;
static int hf_smex_msec = -1;
static int hf_smex_spare = -1;

static int hf_vcdu_version = -1;
static int hf_vcdu_sp_id = -1;
static int hf_vcdu_vc_id = -1;
static int hf_vcdu_seq = -1;
static int hf_vcdu_replay = -1;

/* although technically not part of the vcdu header, the
 * first header pointer (for ccsds), and the last bit
 * pointer (for bitstream), are more easily processed by
 * simply adding them to the tail end of the vcdu header
 * branch rather than creating a distinct branch for them
 */
static int hf_vcdu_fhp = -1;
static int hf_vcdu_lbp = -1;

static dissector_handle_t ccsds_handle = (dissector_handle_t)-1;

/* Initialize the subtree pointers */
static gint ett_vcdu = -1;
static gint ett_smex = -1;
static gint ett_vcduh = -1;

/*
 * Bits in the first 16-bit header word
 */
#define SMEX_VERSION	0xc000
#define SMEX_FRAMELEN	0x3fff

/* some basic sizing parameters */
#define IP_HEADER_LENGTH 48
#define SMEX_HEADER_LENGTH 20
#define VCDU_HEADER_LENGTH 6
#define CCSDS_PRIMARY_HEADER_LENGTH 6
#define CCSDS_SECONDARY_HEADER_LENGTH 10

#define PB5_JULIAN_DAY_MASK 0x7ffe
#define PB5_SECONDS_MASK 0x01ffff
#define PB5_MILLISECONDS_MASK 0xffc0

#define LBP_ALL_DATA 0x3fff
#define LBP_ALL_DATA_ANOMALY 0x7ff
#define LBP_ALL_FILL 0x3ffe

#define FHP_ALL_FILL 0x7fe
#define FHP_CONTINUATION 0x7ff

#define LBP_MASK 0x3fff
#define FHP_MASK 0x7ff

/* leap year macro */
#ifndef Leap
#  define Leap(yr) ( ( 0 == (yr)%4  &&  0 != (yr)%100 )  ||  ( 0 == (yr)%400 ) )
#endif


static const value_string smex_data_inversion_type[] = {
  { 0, "Data True (not inverted)" },
  { 1, "Data Inverted (not corrected)" },
  { 2, "Data Inversion State UNDEFINED" },
  { 3, "Data Inverted (and corrected)" },
  { 0, NULL }
};

static const value_string smex_frame_sync_mode[] = {
  { 0, "Search" },
  { 1, "Check" },
  { 2, "Lock" },
  { 3, "Flywheel" },
  { 0, NULL }
};

static const value_string smex_data_direction[] = {
  { 0, "Forward" },
  { 1, "Reverse" },
  { 0, NULL }
};

static const value_string smex_data_class[] = {
  { 0, "Data Class UNDEFINED" },
  { 1, "CCSDS Frame" },
  { 2, "CCSDS Packet" },
  { 3, "TDM Frame" },
  { 4, "Stopped TDM Frame" },
  { 0, NULL }
};




/* prototype of utc to julian time conversion function - see packet-ccsds.c for the full source code */
extern void utc_to_julian ( int utc, int* year, int* julianday, int* hour, int* minute, int* second );


/* convert smex PB5 header time to a human readable string - NOT THREAD SAFE
 *
 * note:  this is not true PB5 time either, but a tsi specific version, although it is similar
 */
static const char* smex_time_to_string ( int pb5_days_since_midnight_9_10_oct_1995, int pb5_seconds, int pb5_milliseconds )
{
        static const char* fmt = "%04d/%03d:%02d:%02d:%02d.%03d";
        static char juliantime[40];
        static int utcdiff = 0;

        static int Days[2][13] =
        {
          { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
          { 0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
        };

        int utc, yr, year, julianday, hour, minute, second;
        int ix, days, month;

        /* compute the static constant difference in seconds
         * between midnight 9-10 October 1995 (PB5 time) and
         * seconds since 1/1/1970 (UTC time) just this once
         */
        if ( 0 == utcdiff )
        {
          for ( yr=1970; yr < 1995; ++yr )
          {
            utcdiff += ( Leap(yr)  ?  366 : 365 ) * 24 * 60 * 60;
          }

          days = 0;
          ix = ( Leap(1995)  ?  1 : 0 );

          for ( month=1; month < 10; ++month )
          {
            days += Days[ix][month];
          }

          days += 9;  /* this gets us up to midnight october 9-10 */

          utcdiff += days * 24 * 60 * 60;  /* add days in 1995 prior to October 10 */
        }

        utc = ( pb5_days_since_midnight_9_10_oct_1995 * 86400 ) + pb5_seconds + utcdiff;
        utc_to_julian ( utc, &year, &julianday, &hour, &minute, &second );

        g_snprintf ( juliantime, sizeof(juliantime), fmt, year, julianday, hour, minute, second, pb5_milliseconds );

        return juliantime;

}


/* Code to actually dissect the packets */
static void
dissect_vcdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        static int bitstream_channels_file_read = 0;

        /* default bitstream channel assignments:
         * the audio channels 4-6 are designated as bitstream channels
         * the standard bitstream channels are 12 through 19
         * the video channels 28-30 are designated as bitstream channels
         * the fill channel 63 is designated as bitstream
         */
        static int bitstream_channels[] =
        {
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* channels 0-9 */
          0, 0, 1, 1, 1, 1, 1, 1, 1, 1,  /* channels 10-19 */
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* channels 20-29 */
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* channels 30-39 */
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* channels 40-49 */
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* channels 50-59 */
          0, 0, 0, 1                     /* channels 60-63 */
        };

        int packet_boundary = 0;
	int offset = 0;
	int new_offset=0;
        int ccsds_tree_added = 0;

	int apid = 0;
	int ccsds_len = 0;

	proto_item *smex_header = NULL;
	proto_tree *smex_tree = NULL;

	proto_item *vcdu_header = NULL;
	proto_tree *vcdu_tree = NULL;

	guint16 first_word = 0;
        guint32 long_word = 0;
	guint16 new_ptr = 0;

	tvbuff_t *new_tvb = NULL;

        int channel = 0, vcid = 0;
        char *filename = NULL;
        char *endptr = NULL, *cptr = NULL;
        FILE* fp = NULL;
        char readbuf[1024];

        int pb5_days = 0, pb5_seconds = 0, pb5_milliseconds = 0;
        const char* time_string = NULL;


        /* if the bitstream channels file has not been read attempt to do so now.
         * this file potentially contains a modified list of the channels that
         * should be processed as bitstream instead of ccsds.
         */
        if ( ! bitstream_channels_file_read )
        {
                bitstream_channels_file_read = 1;
                filename = get_persconffile_path ( ".bitstream_channels", FALSE, FALSE );
                fp = ws_fopen ( filename, "r" );

                if ( NULL != fp )
                {
                  if ( fgets ( readbuf, sizeof(readbuf), fp ) == readbuf )
                  {
                    memset ( bitstream_channels, 0, sizeof(bitstream_channels) );
                    cptr = readbuf;

                    while ( TRUE )
                    {
                      channel = strtoul ( cptr, &endptr, 0 );
                      if ( cptr == endptr ) break;

                      if ( channel >= 0  &&  channel < 64 )
                      {
                        bitstream_channels[channel] = 1;
                      }

                      cptr = endptr;
                    }
                  }

                  fclose(fp);
                  g_free(filename);
                }
        }
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "VCDU");
	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_set_str(pinfo->cinfo, COL_INFO, "Virtual Channel Data Unit");

	if (tree) {
                /* build the smex header tree */
		smex_header=proto_tree_add_text(tree, tvb, offset, SMEX_HEADER_LENGTH, "SMEX Header");
		smex_tree=proto_item_add_subtree(smex_header, ett_smex);

		proto_tree_add_item(smex_tree, hf_smex_gsc, tvb, offset, 8, FALSE);
		offset += 8;
		/* proto_tree_add_uint(smex_tree, hf_smex_unused, tvb, offset, 2, FALSE); */
		offset += 2;

		first_word=tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(smex_tree, hf_smex_version, tvb, offset, 2, first_word);
		proto_tree_add_uint(smex_tree, hf_smex_framelen, tvb, offset, 2, first_word);
		offset += 2;

		proto_tree_add_item(smex_tree, hf_smex_rs_enable, tvb, offset, 1, FALSE);
		proto_tree_add_item(smex_tree, hf_smex_rs_error, tvb, offset, 1, FALSE);
		proto_tree_add_item(smex_tree, hf_smex_crc_enable, tvb, offset, 1, FALSE);
		proto_tree_add_item(smex_tree, hf_smex_crc_error, tvb, offset, 1, FALSE);
		proto_tree_add_item(smex_tree, hf_smex_mcs_enable, tvb, offset, 1, FALSE);
		proto_tree_add_item(smex_tree, hf_smex_mcs_num_error, tvb, offset, 1, FALSE);
		proto_tree_add_item(smex_tree, hf_smex_data_inv, tvb, offset, 1, FALSE);
		++offset;

		proto_tree_add_item(smex_tree, hf_smex_frame_sync, tvb, offset, 1, FALSE);
		proto_tree_add_item(smex_tree, hf_smex_data_dir, tvb, offset, 1, FALSE);
		proto_tree_add_item(smex_tree, hf_smex_data_class, tvb, offset, 1, FALSE);
		++offset;

                /* extract smex ground receipt time tag */
                long_word = tvb_get_ntohl ( tvb, offset );
                pb5_days = ( long_word >> 17 ) & PB5_JULIAN_DAY_MASK;
                pb5_seconds = ( long_word & PB5_SECONDS_MASK );

                first_word = tvb_get_ntohs ( tvb, offset+4 );
                pb5_milliseconds = ( first_word & PB5_MILLISECONDS_MASK ) >> 6;

		proto_tree_add_item(smex_tree, hf_smex_pb5, tvb, offset, 2, FALSE);
		proto_tree_add_item(smex_tree, hf_smex_jday, tvb, offset, 2, FALSE);
		++offset;
		proto_tree_add_item(smex_tree, hf_smex_seconds, tvb, offset, 3, FALSE);
		offset += 3;

		proto_tree_add_item(smex_tree, hf_smex_msec, tvb, offset, 2, FALSE);
		/* proto_tree_add_item(smex_tree, hf_smex_spare, tvb, offset, 2, FALSE); */
		offset += 2;

                /* format ground receipt time into human readable time format for display */
                time_string = smex_time_to_string ( pb5_days, pb5_seconds, pb5_milliseconds );
                proto_tree_add_text (smex_tree, tvb, offset-6, 6, "%s = Ground Receipt Time", time_string );

		proto_item_set_end(smex_header, tvb, offset);


                /* build the vcdu header tree */
		vcdu_header=proto_tree_add_text(tree, tvb, offset, VCDU_HEADER_LENGTH, "VCDU Header");
		vcdu_tree = proto_item_add_subtree(vcdu_header, ett_vcdu);

                /* extract the virtual channel for use later on */
		first_word=tvb_get_ntohs(tvb, offset);
                vcid = first_word & 0x3f;

		proto_tree_add_item(vcdu_tree, hf_vcdu_version, tvb, offset, 2, FALSE);
		proto_tree_add_item(vcdu_tree, hf_vcdu_sp_id, tvb, offset, 2, FALSE);
		proto_tree_add_item(vcdu_tree, hf_vcdu_vc_id, tvb, offset, 2, FALSE);
		offset += 2;
		proto_tree_add_item(vcdu_tree, hf_vcdu_seq, tvb, offset, 3, FALSE);
		offset += 3;
		proto_tree_add_item(vcdu_tree, hf_vcdu_replay, tvb, offset, 1, FALSE);
		++offset;

                /* extract mpdu/bpdu header word */
		first_word=tvb_get_ntohs(tvb, offset);

                /* do bitstream channel processing */
                if ( bitstream_channels[vcid] )
                {
                  /* extract last bit pointer for bitstream channels */
		  new_ptr=first_word & LBP_MASK;

                  /* add last bit pointer to display tree */
		  proto_tree_add_item(vcdu_tree, hf_vcdu_lbp, tvb, offset, 2, FALSE);

                  switch ( new_ptr )
                  {
                  case LBP_ALL_DATA:
		    proto_tree_add_text(vcdu_tree, tvb, 0, -1, "Bitream ALL Data");
                    break;

                  case LBP_ALL_DATA_ANOMALY:
		    proto_tree_add_text(vcdu_tree, tvb, 0, -1, "Bitream ALL Data (Anomaly)");
                    break;

                  case LBP_ALL_FILL:
		    proto_tree_add_text(vcdu_tree, tvb, 0, -1, "Bitream ALL Fill");
                    break;

                  default:
                    break;
                  }
                }  /* end of bitstream channel processing */

                /* do ccsds channel processing */
                else
                {
                  /* extract first header pointer for ccsds channels */
		  new_ptr=first_word & FHP_MASK;

                  /* add first header pointer to display tree */
		  proto_tree_add_item(vcdu_tree, hf_vcdu_fhp, tvb, offset, 2, FALSE);

                  /* process special cases of first header pointer */
                  if ( FHP_ALL_FILL == new_ptr )
                  {
		    proto_tree_add_text(vcdu_tree, tvb, 0, -1, "Ccsds ALL Fill");
                  }

                  else if ( FHP_CONTINUATION == new_ptr )
                  {
		    proto_tree_add_text(vcdu_tree, tvb, 0, -1, "Ccsds Continuation Packet");
                  }

                  /* process as many ccsds packet headers as we can using the ccsds packet dissector */
                  else
                  {
                    /* compute offset and packet boundary lengths for ccsds dissector loop */
		    new_offset=offset+2+new_ptr;

                    packet_boundary = pinfo->iplen - IP_HEADER_LENGTH - VCDU_HEADER_LENGTH - CCSDS_PRIMARY_HEADER_LENGTH - CCSDS_SECONDARY_HEADER_LENGTH;

		    while ( (new_offset-offset+2) < packet_boundary  &&  (new_offset-offset+2) >= 4 )
		    {
                           ccsds_tree_added = 1;
                           ccsds_len=tvb_get_ntohs(tvb, new_offset+4);

			   apid=tvb_get_ntohs(tvb, new_offset);
			   apid=apid & 0x07ff;
			   /* printf ( "new_ptr=%d new_offset=%d apid=%d ccsds_len=%d\n", new_ptr, new_offset, apid, ccsds_len );  fflush(stdout); */

			   new_tvb = tvb_new_subset(tvb, new_offset, -1, -1);
			   call_dissector(ccsds_handle, new_tvb, pinfo, vcdu_tree);
		
			   new_offset=new_offset+ccsds_len+7;
		    }

                    if ( ! ccsds_tree_added )
                    {
		      proto_tree_add_text(vcdu_tree, tvb, 0, -1, "FHP too close to end of VCDU.  Incomplete Hdr Info Available - Unable to format CCSDS Hdr(s)." );
                    }
		  }

                }  /* end of ccsds channel processing */

                /* don't include the mpdu/bpdu header in the vcdu header highlighting.
                 * by skipping the offset bump the vcdu header highlighting will show
                 * just 6 bytes as it really should, and the fhp/lbp will be included
                 * in the data zone, which is technically more correct.
                 */
                /* offset += 2; */
		proto_item_set_end(vcdu_tree, tvb, offset);

                if ( ! ccsds_tree_added )
                {
                        /* add "Data" section if ccsds parsing did not do so already */
		        proto_tree_add_text(vcdu_tree, tvb, offset, -1, "Data");
                }
	}
}


/* Register the protocol with Wireshark
 * this format is require because a script is used to build the C function
 * that calls all the protocol registration.
 */
void
proto_register_vcdu(void)
{                 
        /* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_smex_gsc,
			{ "Ground Sequence Counter",  "smex.gsc",
			FT_UINT64, BASE_DEC, NULL, 0x0,          
			"SMEX Ground Sequence Counter", HFILL }
		},
		{ &hf_smex_unused,
			{ "Unused",  "smex.unused",
			FT_UINT16, BASE_DEC, NULL, 0x0,          
			"SMEX Unused", HFILL }
		},
		{ &hf_smex_version,
			{ "Version",           "smex.version",
			FT_UINT16, BASE_DEC, NULL, SMEX_VERSION,
			"SMEX Version", HFILL }
		},
		{ &hf_smex_framelen,
			{ "Frame Length",           "smex.frame_len",
			FT_UINT16, BASE_DEC, NULL, SMEX_FRAMELEN,          
			"SMEX Frame Length", HFILL }
		},
		{ &hf_smex_rs_enable,
			{ "RS Enable",           "smex.rs_enable",
			FT_BOOLEAN, 8, NULL, 0x80,
			"SMEX RS Enable", HFILL }
		},
		{ &hf_smex_rs_error,
			{ "RS Error",           "smex.rs_error",
			FT_BOOLEAN, 8, NULL, 0x40,
			"SMEX RS Error", HFILL }
		},
		{ &hf_smex_crc_enable,
			{ "CRC Enable",           "smex.crc_enable",
			FT_BOOLEAN, 8, NULL, 0x20,
			"SMEX CRC Enable", HFILL }
		},
		{ &hf_smex_crc_error,
			{ "CRC Error",           "smex.crc_error",
			FT_BOOLEAN, 8, NULL, 0x10,
			"SMEX CRC Error", HFILL }
		},
		{ &hf_smex_mcs_enable,
			{ "MCS Enable",           "smex.mcs_enable",
			FT_BOOLEAN, 8, NULL, 0x08,
			"SMEX MCS Enable", HFILL }
		},
		{ &hf_smex_mcs_num_error,
			{ "MCS Number Error",           "smex.mcs_numerr",
			FT_BOOLEAN, 8, NULL, 0x04,
			"SMEX MCS Number Error", HFILL }
		},
		{ &hf_smex_data_inv,
			{ "Data Inversion",           "smex.data_inv",
			FT_UINT16, BASE_DEC, VALS(smex_data_inversion_type), 0x03,
			"SMEX Data Inversion", HFILL }
		},
		{ &hf_smex_frame_sync,
			{ "Frame Sync",           "smex.frame_sync",
			FT_UINT16, BASE_DEC, VALS(smex_frame_sync_mode), 0xc0,
			"SMEX Frame Sync Flag", HFILL }
		},
		{ &hf_smex_data_dir,
			{ "Data Direction",           "smex.data_dir",
			FT_UINT16, BASE_DEC, VALS(smex_data_direction), 0x20,
			"SMEX Data Direction flag", HFILL }
		},
		{ &hf_smex_data_class,
			{ "Data Class",           "smex.data_class",
			FT_UINT16, BASE_DEC, VALS(smex_data_class), 0x1f,
			"SMEX Data Class", HFILL }
		},
		{ &hf_smex_pb5,
			{ "PB5 Flag",           "smex.pb5",
			FT_UINT16, BASE_DEC, NULL, 0x8000,
			"SMEX PB5 Flag", HFILL }
		}, 
		{ &hf_smex_jday,
			{ "Julian Day",           "smex.jday",
			FT_UINT16, BASE_DEC, NULL, PB5_JULIAN_DAY_MASK,
			"SMEX Julian Day", HFILL }
		}, 
		{ &hf_smex_seconds,
			{ "Seconds",           "smex.seconds",
			FT_UINT24, BASE_DEC, NULL, PB5_SECONDS_MASK,
			"SMEX Seconds", HFILL }
		}, 
		{ &hf_smex_msec,
			{ "Milliseconds",           "smex.msec",
			FT_UINT16, BASE_DEC, NULL, PB5_MILLISECONDS_MASK,
			"SMEX Milliseconds", HFILL }
		}, 
		{ &hf_smex_spare,
			{ "Spare",           "smex.spare",
			FT_UINT16, BASE_DEC, NULL, 0x03f,
			"SMEX Spare", HFILL }
		}, 



		{ &hf_vcdu_version,
			{ "Version",           "vcdu.version",
			FT_UINT16, BASE_DEC, NULL, 0xc0,
			"VCDU Version", HFILL }
		},
		{ &hf_vcdu_sp_id,
			{ "Space Craft ID",           "vcdu.spid",
			FT_UINT16, BASE_DEC, NULL, 0x3fc0,
			"VCDU Space Craft ID", HFILL }
		},
		{ &hf_vcdu_vc_id,
			{ "Virtual Channel ID",           "vcdu.vcid",
			FT_UINT16, BASE_DEC, NULL, 0x3f,
			"VCDU Virtual Channel ID", HFILL }
		},
		{ &hf_vcdu_seq,
			{ "Sequence Count",           "vcdu.seq",
			FT_UINT16, BASE_DEC, NULL, 0xffffff,
			"VCDU Sequence Count", HFILL }
		},
		{ &hf_vcdu_replay,
			{ "Replay Flag",           "vcdu.replay",
			FT_BOOLEAN, 8, NULL, 0x80,
			"VCDU Replay Flag", HFILL }
		},

                /* not really part of the vcdu header, but it's easier this way */
		{ &hf_vcdu_fhp,
			{ "First Header Pointer",  "vcdu.fhp",
			FT_UINT16, BASE_DEC, NULL, FHP_MASK,
			"VCDU/MPDU First Header Pointer", HFILL }
		},
		{ &hf_vcdu_lbp,
			{ "Last Bit Pointer",  "vcdu.lbp",
			FT_UINT16, BASE_DEC, NULL, LBP_MASK,
			"VCDU/BPDU Last Bit Pointer", HFILL }
		}
	};

        /* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_vcdu,
		&ett_smex,
		&ett_vcduh,
	};

        /* Register the protocol name and description */
	proto_vcdu = proto_register_protocol("VCDU", "VCDU", "vcdu");

        /* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_vcdu, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


/* If this dissector uses sub-dissector registration add a registration routine.
 * This format is required because a script is used to find these routines and
 * create the code that calls these routines.
 */
void
proto_reg_handoff_vcdu(void)
{
	register_dissector ( "vcdu", dissect_vcdu, proto_vcdu );
	dissector_add ( "udp.port", 0, find_dissector("vcdu") );
	ccsds_handle = find_dissector ( "ccsds" );
}

