/* packet-synphasor.c
 * Dissector for IEEE C37.118 synchrophasor frames.
 *
 * Copyright 2008, Jens Steinhauser <jens.steinhauser@omicron.at>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <math.h>

#include <epan/packet.h>
#include <epan/crc16-tvb.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include "packet-tcp.h"

#include <wsutil/utf8_entities.h>

#define PROTOCOL_NAME	    "IEEE C37.118 Synchrophasor Protocol"
#define PROTOCOL_SHORT_NAME "SYNCHROPHASOR"
#define PROTOCOL_ABBREV	    "synphasor"

/* forward references */
void proto_register_synphasor(void);
void proto_reg_handoff_synphasor(void);

/* global variables */

static int proto_synphasor	 = -1;

/* user preferences */
static guint global_pref_tcp_port = 4712;
static guint global_pref_udp_port = 4713;

/* the ett... variables hold the state (open/close) of the treeview in the GUI */
static gint ett_synphasor	   = -1; /* root element for this protocol */
  /* used in the common header */
  static gint ett_frtype	   = -1;
  static gint ett_timequal	   = -1;
  /* used for config frames */
  static gint ett_conf		   = -1;
    static gint ett_conf_station   = -1;
      static gint ett_conf_format  = -1;
      static gint ett_conf_phnam   = -1;
      static gint ett_conf_annam   = -1;
      static gint ett_conf_dgnam   = -1;
      static gint ett_conf_phconv  = -1;
      static gint ett_conf_anconv  = -1;
      static gint ett_conf_dgmask  = -1;
  /* used for data frames */
  static gint ett_data		   = -1;
    static gint ett_data_block	   = -1;
      static gint ett_data_stat	   = -1;
      static gint ett_data_phasors = -1;
      static gint ett_data_analog  = -1;
      static gint ett_data_digital = -1;
  /* used for command frames */
  static gint ett_command	   = -1;
  static gint ett_status_word_mask = -1;

/* handles to the header fields hf[] in proto_register_synphasor() */
static int hf_sync		    = -1;
static int hf_sync_frtype	    = -1;
static int hf_sync_version	    = -1;
static int hf_idcode		    = -1;
static int hf_frsize		    = -1;
static int hf_soc		    = -1;
static int hf_timeqal_lsdir	    = -1;
static int hf_timeqal_lsocc	    = -1;
static int hf_timeqal_lspend	    = -1;
static int hf_timeqal_timequalindic = -1;
static int hf_fracsec		    = -1;
static int hf_conf_timebase	    = -1;
static int hf_conf_numpmu	    = -1;
static int hf_conf_formatb3	    = -1;
static int hf_conf_formatb2	    = -1;
static int hf_conf_formatb1	    = -1;
static int hf_conf_formatb0	    = -1;
static int hf_conf_fnom		    = -1;
static int hf_conf_cfgcnt	    = -1;
static int hf_data_statb15	    = -1;
static int hf_data_statb14	    = -1;
static int hf_data_statb13	    = -1;
static int hf_data_statb12	    = -1;
static int hf_data_statb11	    = -1;
static int hf_data_statb10	    = -1;
static int hf_data_statb05to04	    = -1;
static int hf_data_statb03to00	    = -1;
static int hf_command		    = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_synphasor_data = -1;
static int hf_synphasor_checksum = -1;
static int hf_synphasor_num_phasors = -1;
static int hf_synphasor_num_analog_values = -1;
static int hf_synphasor_num_digital_status_words = -1;
static int hf_synphasor_rate_of_transmission = -1;
static int hf_synphasor_phasor = -1;
static int hf_synphasor_actual_frequency_value = -1;
static int hf_synphasor_rate_change_frequency = -1;
static int hf_synphasor_frequency_deviation_from_nominal = -1;
static int hf_synphasor_analog_value = -1;
static int hf_synphasor_digital_status_word = -1;
static int hf_synphasor_conversion_factor = -1;
static int hf_synphasor_factor_for_analog_value = -1;
static int hf_synphasor_channel_name = -1;
static int hf_synphasor_extended_frame_data = -1;
static int hf_synphasor_unknown_data = -1;
static int hf_synphasor_status_word_mask_normal_state = -1;
static int hf_synphasor_status_word_mask_valid_bits = -1;

static expert_field ei_synphasor_extended_frame_data = EI_INIT;

static dissector_handle_t synphasor_udp_handle;

/* the five different frame types for this protocol */
enum FrameType {
	DATA = 0,
	HEADER,
	CFG1,
	CFG2,
	CMD
};

/* the channel names in the protocol are all 16 bytes
 * long (and don't have to be NULL terminated) */
#define CHNAM_LEN 16

/* Structures to save CFG frame content. */

/* type to indicate the format for (D)FREQ/PHASORS/ANALOG in data frame	 */
typedef enum { integer,		/* 16 bit signed integer */
	       floating_point	/* single precision floating point */
} data_format;

typedef enum { rect, polar } phasor_notation_e;

typedef enum { V, A } unit_e;

/* holds the information required to dissect a single phasor */
typedef struct {
	char	      name[CHNAM_LEN + 1];
	unit_e        unit;
	guint32	      conv; /* conversation factor in 10^-5 scale */
} phasor_info;

/* holds the information for an analog value */
typedef struct {
	char	name[CHNAM_LEN + 1];
	guint32 conv; /* conversation factor, user defined scaling (so it's pretty useless) */
} analog_info;

/* holds information required to dissect a single PMU block in a data frame */
typedef struct {
	guint16		   id;			/* identifies source of block     */
	char		   name[CHNAM_LEN + 1];	/* holds STN			  */
	data_format	   format_fr;		/* data format of FREQ and DFREQ  */
	data_format	   format_ph;		/* data format of PHASORS	  */
	data_format	   format_an;		/* data format of ANALOG	  */
	phasor_notation_e  phasor_notation;	/* format of the phasors	  */
	guint		   fnom;		/* nominal line frequency	  */
	guint		   num_dg;		/* number of digital status words */
	wmem_array_t	  *phasors;		/* array of phasor_infos	  */
	wmem_array_t	  *analogs;		/* array of analog_infos	  */
} config_block;

/* holds the id the configuration comes from an and
 * an array of config_block members */
typedef struct {
	guint32	 fnum;		/* frame number */

	guint16	 id;
	wmem_array_t	*config_blocks; /* Contains a config_block struct for
				 * every PMU included in the config frame */
} config_frame;

/* strings for type bits in SYNC */
static const value_string typenames[] = {
	{ 0, "Data Frame"	     },
	{ 1, "Header Frame"	     },
	{ 2, "Configuration Frame 1" },
	{ 3, "Configuration Frame 2" },
	{ 4, "Command Frame"	     },
	{ 0, NULL		     }
};

/* strings for version bits in SYNC */
static const value_string versionnames[] = {
	{ 1, "IEEE C37.118-2005 initial publication" },
	{ 0, NULL				     }
};

/* strings for the time quality flags in FRACSEC */
static const value_string timequalcodes[] = {
	{ 0xF, "Clock failure, time not reliable"    },
	{ 0xB, "Clock unlocked, time within 10 s"    },
	{ 0xA, "Clock unlocked, time within 1 s"     },
	{ 0x9, "Clock unlocked, time within 10^-1 s" },
	{ 0x8, "Clock unlocked, time within 10^-2 s" },
	{ 0x7, "Clock unlocked, time within 10^-3 s" },
	{ 0x6, "Clock unlocked, time within 10^-4 s" },
	{ 0x5, "Clock unlocked, time within 10^-5 s" },
	{ 0x4, "Clock unlocked, time within 10^-6 s" },
	{ 0x3, "Clock unlocked, time within 10^-7 s" },
	{ 0x2, "Clock unlocked, time within 10^-8 s" },
	{ 0x1, "Clock unlocked, time within 10^-9 s" },
	{ 0x0, "Normal operation, clock locked"	     },
	{  0 , NULL				     }
};

/* strings for flags in the FORMAT word of a configuration frame */
static const true_false_string conf_formatb123names = {
	"floating point",
	"16-bit integer"
};
static const true_false_string conf_formatb0names = {
	"polar",
	"rectangular"
};

/* strings to decode ANUNIT in configuration frame */
static const range_string conf_anconvnames[] = {
	{  0,	0, "single point-on-wave" },
	{  1,	1, "rms of analog input"  },
	{  2,	2, "peak of input"	  },
	{  3,	4, "undefined"		  },
	{  5,  64, "reserved"		  },
	{ 65, 255, "user defined"	  },
	{  0,	0, NULL			  }
};

/* strings for the FNOM field */
static const true_false_string conf_fnomnames = {
	"50Hz",
	"60Hz"
};

/* strings for flags in the STAT word of a data frame */
static const true_false_string data_statb15names = {
	"Data is invalid",
	"Data is valid"
};
static const true_false_string data_statb14names = {
	"Error",
	"No error"
};
static const true_false_string data_statb13names = {
	"Synchronization lost",
	"Clock is synchronized"
};
static const true_false_string data_statb12names = {
	"By arrival",
	"By timestamp"
};
static const true_false_string data_statb11names = {
	"Trigger detected",
	"No trigger"
};
static const true_false_string data_statb10names = {
	"Within 1 minute",
	"No"
};
static const value_string      data_statb05to04names[] = {
	{ 0, "Time locked, best quality" },
	{ 1, "Unlocked for 10s"		 },
	{ 2, "Unlocked for 100s"	 },
	{ 3, "Unlocked for over 1000s"	 },
	{ 0, NULL			 }
};
static const value_string      data_statb03to00names[] = {
	{ 0x0, "Manual"		    },
	{ 0x1, "Magnitude low"	    },
	{ 0x2, "Magnitude high"	    },
	{ 0x3, "Phase-angel diff"   },
	{ 0x4, "Frequency high/low" },
	{ 0x5, "df/dt high"	    },
	{ 0x6, "Reserved"	    },
	{ 0x7, "Digital"	    },
	{ 0x8, "User defined"	    },
	{ 0x9, "User defined"	    },
	{ 0xA, "User defined"	    },
	{ 0xB, "User defined"	    },
	{ 0xC, "User defined"	    },
	{ 0xD, "User defined"	    },
	{ 0xE, "User defined"	    },
	{ 0xF, "User defined"	    },
	{  0 , NULL		    }
};

/* strings to decode the commands */
static const value_string command_names[] = {
	{  0, "unknown command"	      },
	{  1, "data transmission off" },
	{  2, "data transmission on"  },
	{  3, "send HDR frame"	      },
	{  4, "send CFG-1 frame"      },
	{  5, "send CFG-2 frame"      },
	{  6, "unknown command"	      },
	{  7, "unknown command"	      },
	{  8, "extended frame"	      },
	{  9, "unknown command"	      },
	{ 10, "unknown command"	      },
	{ 11, "unknown command"	      },
	{ 12, "unknown command"	      },
	{ 13, "unknown command"	      },
	{ 14, "unknown command"	      },
	{ 15, "unknown command"	      },
	{  0, NULL		      }
};

/* Dissects a configuration frame (only the most important stuff, tries
 * to be fast, does no GUI stuff) and returns a pointer to a config_frame
 * struct that contains all the information from the frame needed to
 * dissect a DATA frame.
 *
 * use 'config_frame_free()' to free the config_frame again
 */
static config_frame *config_frame_fast(tvbuff_t *tvb)
{
	guint16	      idcode, num_pmu;
	gint	      offset;
	config_frame *frame;

	/* get a new frame and initialize it */
	frame = wmem_new(wmem_file_scope(), config_frame);

	frame->config_blocks = wmem_array_new(wmem_file_scope(), sizeof(config_block));

	idcode = tvb_get_ntohs(tvb, 4);
	frame->id	= idcode;

	num_pmu = tvb_get_ntohs(tvb, 18);
	offset = 20; /* start of repeating blocks */

	while (num_pmu) {
		guint16	     format_flags;
		gint	     num_ph,
			     num_an,
			     num_dg;
		gint	     i,
			     phunit,
			     anunit,
			     fnom;
		config_block block;

		/* initialize the block */
		block.phasors = wmem_array_new(wmem_file_scope(), sizeof(phasor_info));
		block.analogs = wmem_array_new(wmem_file_scope(), sizeof(analog_info));
		/* copy the station name from the tvb to block, and add NULL byte */
		tvb_memcpy(tvb, block.name, offset, CHNAM_LEN); offset += CHNAM_LEN;
		block.name[CHNAM_LEN] = '\0';

		block.id = tvb_get_ntohs(tvb, offset); offset += 2;

		format_flags	      = tvb_get_ntohs(tvb, offset); offset += 2;
		block.format_fr	      = (format_flags & 0x0008) ? floating_point : integer;
		block.format_an	      = (format_flags & 0x0004) ? floating_point : integer;
		block.format_ph	      = (format_flags & 0x0002) ? floating_point : integer;
		block.phasor_notation = (format_flags & 0x0001) ? polar		 : rect;

		num_ph = tvb_get_ntohs(tvb, offset); offset += 2;
		num_an = tvb_get_ntohs(tvb, offset); offset += 2;
		num_dg = tvb_get_ntohs(tvb, offset); offset += 2;
		block.num_dg = num_dg;

		/* the offset of the PHUNIT, ANUNIT, and FNOM blocks */
		phunit = offset + (num_ph + num_an + num_dg * CHNAM_LEN) * CHNAM_LEN;
		anunit = phunit + num_ph * 4;
		fnom   = anunit + num_an * 4 + num_dg * 4;

		/* read num_ph phasor names and conversation factors */
		for (i = 0; i != num_ph; i++) {
			phasor_info  pi;
			guint32	     conv;

			/* copy the phasor name from the tvb, and add NULL byte */
			tvb_memcpy(tvb, pi.name, offset, CHNAM_LEN); offset += CHNAM_LEN;
			pi.name[CHNAM_LEN] = '\0';

			conv = tvb_get_ntohl(tvb, phunit + 4 * i);
			pi.unit = conv & 0xFF000000 ? A : V;
			pi.conv = conv & 0x00FFFFFF;

			wmem_array_append_one(block.phasors, pi);
		}

		/* read num_an analog value names and conversation factors */
		for (i = 0; i != num_an; i++) {
			analog_info ai;
			guint32	    conv;

			/* copy the phasor name from the tvb, and add NULL byte */
			tvb_memcpy(tvb, ai.name, offset, CHNAM_LEN); offset += CHNAM_LEN;
			ai.name[CHNAM_LEN] = '\0';

			conv = tvb_get_ntohl(tvb, anunit + 4 * i);
			ai.conv = conv;

			wmem_array_append_one(block.analogs, ai);
		}

		/* the names for the bits in the digital status words aren't saved,
		   there is no space to display them in the GUI anyway */

		/* save FNOM */
		block.fnom = tvb_get_ntohs(tvb, fnom) & 0x0001 ? 50 : 60;
		offset = fnom + 2;

		/* skip CFGCNT */
		offset += 2;

		wmem_array_append_one(frame->config_blocks, block);
		num_pmu--;
	}

	return frame;
}

/* Checks the CRC of a synchrophasor frame, 'tvb' has to include the whole
 * frame, including CRC, the calculated CRC is returned in '*computedcrc'.
 */
static gboolean check_crc(tvbuff_t *tvb, guint16 *computedcrc)
{
	guint16 crc;
	guint	len = tvb_get_ntohs(tvb, 2);

	crc = tvb_get_ntohs(tvb, len - 2);
	*computedcrc = crc16_x25_ccitt_tvb(tvb, len - 2);

	if (crc == *computedcrc)
		return TRUE;

	return FALSE;
}

/* forward declarations of the subdissectors for the data
 * in the frame that is not common to all types of frames
 */
static int dissect_config_frame (tvbuff_t *, proto_item *);
static int dissect_data_frame	(tvbuff_t *, proto_item *, packet_info *);
static int dissect_command_frame(tvbuff_t *, proto_item *, packet_info *);
/* to keep 'dissect_common()' shorter */
static gint dissect_header(tvbuff_t *, proto_tree *);

/* Dissects the header (common to all types of frames) and then calls
 * one of the subdissectors (declared above) for the rest of the frame.
 */
static int dissect_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint8	frame_type;
	guint16 crc;
	guint	tvbsize = tvb_reported_length(tvb);

	/* some heuristics */
	if (tvbsize < 17		    /* 17 bytes = header frame with only a
					       NULL character, useless but valid */
	 || tvb_get_guint8(tvb, 0) != 0xAA) /* every synchrophasor frame starts with 0xAA */
		return 0;

	/* write the protocol name to the info column */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTOCOL_SHORT_NAME);

	frame_type = tvb_get_guint8(tvb, 1) >> 4;

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_const(frame_type, typenames, "invalid packet type"));

	/* CFG-2 and DATA frames need special treatment during the first run:
	 * For CFG-2 frames, a 'config_frame' struct is created to hold the
	 * information necessary to decode DATA frames. A pointer to this
	 * struct is saved in the conversation and is copied to the
	 * per-packet information if a DATA frame is dissected.
	 */
	if (!pinfo->fd->flags.visited) {
		if (CFG2 == frame_type &&
		    check_crc(tvb, &crc)) {
			conversation_t *conversation;

			/* fill the config_frame */
			config_frame *frame = config_frame_fast(tvb);
			frame->fnum = pinfo->num;

			/* find a conversation, create a new one if none exists */
			conversation = find_or_create_conversation(pinfo);

			/* remove data from a previous CFG-2 frame, only
			 * the most recent configuration frame is relevant */
			if (conversation_get_proto_data(conversation, proto_synphasor))
				conversation_delete_proto_data(conversation, proto_synphasor);

			conversation_add_proto_data(conversation, proto_synphasor, frame);
		}
		else if (DATA == frame_type) {
			conversation_t *conversation = find_conversation(pinfo->num,
									 &pinfo->src, &pinfo->dst,
									 pinfo->ptype,
									 pinfo->srcport, pinfo->destport,
									 0);

			if (conversation) {
				config_frame *conf = (config_frame *)conversation_get_proto_data(conversation, proto_synphasor);
				/* no problem if 'conf' is NULL, the DATA frame dissector checks this again */
			p_add_proto_data(wmem_file_scope(), pinfo, proto_synphasor, 0, conf);
			}
		}
	} /* if (!visited) */

	{
		proto_tree *synphasor_tree;
		proto_item *temp_item;
		proto_item *sub_item;

		gint	    offset;
		guint16	    framesize;
		tvbuff_t   *sub_tvb;
		gboolean   crc_good;

		temp_item = proto_tree_add_item(tree, proto_synphasor, tvb, 0, -1, ENC_NA);
		proto_item_append_text(temp_item, ", %s", val_to_str_const(frame_type, typenames,
									   ", invalid packet type"));

		/* synphasor_tree is where from now on all new elements for this protocol get added */
		synphasor_tree = proto_item_add_subtree(temp_item, ett_synphasor);

		framesize = dissect_header(tvb, synphasor_tree);
		offset = 14; /* header is 14 bytes long */

		/* check CRC, call appropriate subdissector for the rest of the frame if CRC is correct*/
		sub_item  = proto_tree_add_item(synphasor_tree, hf_synphasor_data, tvb, offset, tvbsize - 16, ENC_NA);
		crc_good = check_crc(tvb, &crc);
		proto_tree_add_checksum(synphasor_tree, tvb, tvbsize - 2, hf_synphasor_checksum, -1, NULL, pinfo, crc16_x25_ccitt_tvb(tvb, tvb_get_ntohs(tvb, 2) - 2),
							ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
		if (!crc_good) {
			proto_item_append_text(sub_item,  ", not dissected because of wrong checksum");
		}
		else {
			/* create a new tvb to pass to the subdissector
			   '-16': length of header + 2 CRC bytes */
			sub_tvb = tvb_new_subset(tvb, offset, tvbsize - 16, framesize - 16);

			/* call subdissector */
			switch (frame_type) {
				case DATA:
					dissect_data_frame(sub_tvb, sub_item, pinfo);
					break;
				case HEADER: /* no further dissection is done/needed */
					proto_item_append_text(sub_item, "Header Frame");
					break;
				case CFG1:
				case CFG2:
					dissect_config_frame(sub_tvb, sub_item);
					break;
				case CMD:
					dissect_command_frame(sub_tvb, sub_item, pinfo);
					break;

				default:
					proto_item_append_text(sub_item, " of unknown type");
			}
			proto_item_append_text(temp_item, " [correct]");
		}

		/*offset += 2;*/ /* CRC */
	}

	return tvb_reported_length(tvb);
} /* dissect_synphasor() */

/* called for synchrophasors over UDP */
static int dissect_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	return dissect_common(tvb, pinfo, tree, data);
}

/* callback for 'tcp_dissect_pdus()' to give it the length of the frame */
static guint get_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb,
                            int offset, void *data _U_)
{
	return tvb_get_ntohs(tvb, offset + 2);
}

static int dissect_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, get_pdu_length, dissect_common, data);

	return tvb_reported_length(tvb);
}


/* Dissects the common header of frames.
 *
 * Returns the framesize, in contrast to most
 * other helper functions that return the offset.
 */
static gint dissect_header(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree *temp_tree;
	proto_item *temp_item;

	gint	offset = 0;
	guint16 framesize;

	/* SYNC and flags */
	temp_item = proto_tree_add_item(tree, hf_sync, tvb, offset, 2, ENC_BIG_ENDIAN);
	temp_tree = proto_item_add_subtree(temp_item, ett_frtype);
	proto_tree_add_item(temp_tree, hf_sync_frtype,	tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(temp_tree, hf_sync_version, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* FRAMESIZE */
	proto_tree_add_item(tree, hf_frsize, tvb, offset, 2, ENC_BIG_ENDIAN);
	framesize = tvb_get_ntohs(tvb, offset); offset += 2;

	/* IDCODE */
	proto_tree_add_item(tree, hf_idcode, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* SOC */
	proto_tree_add_item(tree, hf_soc, tvb, offset, 4, ENC_TIME_TIMESPEC | ENC_BIG_ENDIAN);
	offset += 4;

	/* FRACSEC */
	/* time quality flags */
	temp_tree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_timequal, NULL, "Time quality flags");
	proto_tree_add_item(temp_tree, hf_timeqal_lsdir,	 tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(temp_tree, hf_timeqal_lsocc,	 tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(temp_tree, hf_timeqal_lspend,	 tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(temp_tree, hf_timeqal_timequalindic, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_fracsec,  tvb, offset, 3, ENC_BIG_ENDIAN);
	/*offset += 3;*/

	return framesize;
}

/* forward declarations of helper functions for 'dissect_config_frame()' */
static gint dissect_CHNAM  (tvbuff_t *tvb, proto_tree *tree, gint offset, gint cnt, const char *prefix);
static gint dissect_PHUNIT (tvbuff_t *tvb, proto_tree *tree, gint offset, gint cnt);
static gint dissect_ANUNIT (tvbuff_t *tvb, proto_tree *tree, gint offset, gint cnt);
static gint dissect_DIGUNIT(tvbuff_t *tvb, proto_tree *tree, gint offset, gint cnt);

/* dissects a configuration frame (type 1 and 2) and adds fields to 'config_item' */
static int dissect_config_frame(tvbuff_t *tvb, proto_item *config_item)
{
	proto_tree *config_tree;
	gint	    offset = 0, j;
	guint16	    num_pmu;

	proto_item_set_text   (config_item, "Configuration data");
	config_tree = proto_item_add_subtree(config_item, ett_conf);

	/* TIME_BASE and NUM_PMU */
	offset += 1; /* skip the reserved byte */
	proto_tree_add_item(config_tree, hf_conf_timebase, tvb, offset, 3, ENC_BIG_ENDIAN); offset += 3;
	proto_tree_add_item(config_tree, hf_conf_numpmu,   tvb, offset, 2, ENC_BIG_ENDIAN);
	/* add number of included PMUs to the text in the list view  */
	num_pmu = tvb_get_ntohs(tvb, offset); offset += 2;
	proto_item_append_text(config_item, ", %"G_GUINT16_FORMAT" PMU(s) included", num_pmu);

	/* dissect the repeating PMU blocks */
	for (j = 0; j < num_pmu; j++) {
		guint16	    num_ph, num_an, num_dg;
		proto_item *station_item;
		proto_tree *station_tree;
		proto_tree *temp_tree;
		char	   *str;

		gint oldoffset = offset; /* to calculate the length of the whole PMU block later */

		/* STN with new tree to add the rest of the PMU block */
		str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, CHNAM_LEN, ENC_ASCII);
		station_tree = proto_tree_add_subtree_format(config_tree, tvb, offset, CHNAM_LEN,
							     ett_conf_station, &station_item,
							     "Station #%i: \"%s\"", j + 1, str);
		offset += CHNAM_LEN;

		/* IDCODE */
		proto_tree_add_item(station_tree, hf_idcode, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;

		/* FORMAT */
		temp_tree = proto_tree_add_subtree(station_tree, tvb, offset, 2, ett_conf_format, NULL,
						   "Data format in data frame");
		proto_tree_add_item(temp_tree, hf_conf_formatb3, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(temp_tree, hf_conf_formatb2, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(temp_tree, hf_conf_formatb1, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(temp_tree, hf_conf_formatb0, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* PHNMR, ANNMR, DGNMR */
		num_ph = tvb_get_ntohs(tvb, offset    );
		num_an = tvb_get_ntohs(tvb, offset + 2);
		num_dg = tvb_get_ntohs(tvb, offset + 4);
		proto_tree_add_uint(station_tree, hf_synphasor_num_phasors, tvb, offset, 2, num_ph);
		proto_tree_add_uint(station_tree, hf_synphasor_num_analog_values, tvb, offset + 2, 2, num_an);
		proto_tree_add_uint(station_tree, hf_synphasor_num_digital_status_words, tvb, offset + 4, 2, num_dg);
		offset += 6;

		/* CHNAM, the channel names */
		offset = dissect_CHNAM(tvb, station_tree, offset, num_ph     , "Phasor name"	     );
		offset = dissect_CHNAM(tvb, station_tree, offset, num_an     , "Analog value"	     );
		offset = dissect_CHNAM(tvb, station_tree, offset, num_dg * 16, "Digital status label");

		/* PHUNIT, ANUINT and DIGUNIT */
		offset = dissect_PHUNIT (tvb, station_tree, offset, num_ph);
		offset = dissect_ANUNIT (tvb, station_tree, offset, num_an);
		offset = dissect_DIGUNIT(tvb, station_tree, offset, num_dg);

		/* FNOM and CFGCNT */
		proto_tree_add_item(station_tree, hf_conf_fnom,	  tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
		proto_tree_add_item(station_tree, hf_conf_cfgcnt, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;

		/* set the correct length for the "Station :" item */
		proto_item_set_len(station_item, offset - oldoffset);
	} /* for() PMU blocks */

	/* DATA_RATE */
	{
		gint16 tmp = tvb_get_ntohs(tvb, offset);
		if (tmp > 0)
			proto_tree_add_int_format_value(config_tree, hf_synphasor_rate_of_transmission, tvb, offset, 2, tmp,
                        "%d frame(s) per second", tmp);
		else
			proto_tree_add_int_format_value(config_tree, hf_synphasor_rate_of_transmission, tvb, offset, 2, tmp,
                        "1 frame per %d second(s)", (gint16)-tmp);
		offset += 2;
	}

	return offset;
} /* dissect_config_frame() */

/* forward declarations of helper functions for 'dissect_data_frame()' */
static gint dissect_PHASORS(tvbuff_t *tvb, proto_tree *tree, config_block *block, gint offset);
static gint dissect_DFREQ  (tvbuff_t *tvb, proto_tree *tree, config_block *block, gint offset);
static gint dissect_ANALOG (tvbuff_t *tvb, proto_tree *tree, config_block *block, gint offset);
static gint dissect_DIGITAL(tvbuff_t *tvb, proto_tree *tree, config_block *block, gint offset);

/* calculates the size (in bytes) of a data frame that the config_block describes */
#define SYNP_BLOCKSIZE(x) (2							   /* STAT    */ \
		   + wmem_array_get_count((x).phasors) * (integer == (x).format_ph ? 4 : 8) /* PHASORS */ \
		   +			                 (integer == (x).format_fr ? 4 : 8) /* (D)FREQ */ \
		   + wmem_array_get_count((x).analogs) * (integer == (x).format_an ? 2 : 4) /* ANALOG  */ \
		   + (x).num_dg * 2)					   /* DIGITAL */

/* Dissects a data frame */
static int dissect_data_frame(tvbuff_t	  *tvb,
			      proto_item  *data_item, /* all items are placed beneath this item	  */
			      packet_info *pinfo)     /* used to find the data from a CFG-2 frame */
{
	proto_tree   *data_tree;
	gint	      offset	 = 0;
	guint	      i;
	config_frame *conf;

	proto_item_set_text(data_item, "Measurement data");
	data_tree = proto_item_add_subtree(data_item, ett_data);

	/* search for configuration information to dissect the frame */
	{
		gboolean config_found = FALSE;
		conf = (config_frame *)p_get_proto_data(wmem_file_scope(), pinfo, proto_synphasor, 0);

		if (conf) {
			/* check if the size of the current frame is the
			   size of the frame the config_frame describes */
			size_t reported_size = 0;
			for (i = 0; i < wmem_array_get_count(conf->config_blocks); i++) {
				config_block *block = (config_block*)wmem_array_index(conf->config_blocks, i);
				reported_size += SYNP_BLOCKSIZE(*block);
			}

			if (tvb_reported_length(tvb) == reported_size) {
				proto_item_append_text(data_item, ", using frame number %"G_GUINT32_FORMAT" as configuration frame",
						       conf->fnum);
				config_found = TRUE;
			}
		}

		if (!config_found) {
			proto_item_append_text(data_item, ", no configuration frame found");
			return 0;
		}
	}

	/* dissect a PMU block for every config_block in the frame */
	for (i = 0; i < wmem_array_get_count(conf->config_blocks); i++) {
		config_block *block = (config_block*)wmem_array_index(conf->config_blocks, i);

		proto_tree *block_tree = proto_tree_add_subtree_format(data_tree, tvb, offset, SYNP_BLOCKSIZE(*block),
								       ett_data_block, NULL,
								       "Station: \"%s\"", block->name);

		/* STAT */
		proto_tree *temp_tree = proto_tree_add_subtree(block_tree, tvb, offset, 2, ett_data_stat, NULL, "Flags");

		proto_tree_add_item(temp_tree, hf_data_statb15,	    tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(temp_tree, hf_data_statb14,	    tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(temp_tree, hf_data_statb13,	    tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(temp_tree, hf_data_statb12,	    tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(temp_tree, hf_data_statb11,	    tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(temp_tree, hf_data_statb10,	    tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(temp_tree, hf_data_statb05to04, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(temp_tree, hf_data_statb03to00, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* PHASORS, (D)FREQ, ANALOG, and DIGITAL */
		offset = dissect_PHASORS(tvb, block_tree, block, offset);
		offset = dissect_DFREQ	(tvb, block_tree, block, offset);
		offset = dissect_ANALOG (tvb, block_tree, block, offset);
		offset = dissect_DIGITAL(tvb, block_tree, block, offset);
	}
	return offset;
} /* dissect_data_frame() */

/* Dissects a command frame and adds fields to config_item.
 *
 * 'pinfo' is used to add the type of command
 * to the INFO column in the packet list.
 */
static int dissect_command_frame(tvbuff_t    *tvb,
				 proto_item  *command_item,
				 packet_info *pinfo)
{
	proto_tree *command_tree;
	guint	    tvbsize	  = tvb_reported_length(tvb);
	const char *s;

	proto_item_set_text(command_item, "Command data");
	command_tree = proto_item_add_subtree(command_item, ett_command);

	/* CMD */
	proto_tree_add_item(command_tree, hf_command, tvb, 0, 2, ENC_BIG_ENDIAN);

	s = val_to_str_const(tvb_get_ntohs(tvb, 0), command_names, "invalid command");
	col_append_str(pinfo->cinfo, COL_INFO, ", ");
	col_append_str(pinfo->cinfo, COL_INFO, s);

	if (tvbsize > 2) {
		if (tvb_get_ntohs(tvb, 0) == 0x0008) {
			/* Command: Extended Frame, the extra data is ok */
			proto_item *ti = proto_tree_add_item(command_tree, hf_synphasor_extended_frame_data, tvb, 2, tvbsize - 2, ENC_NA);
			if (tvbsize % 2)
				expert_add_info(pinfo, ti, &ei_synphasor_extended_frame_data);
		}
		else
			proto_tree_add_item(command_tree, hf_synphasor_unknown_data, tvb, 2, tvbsize - 2, ENC_NA);
	}

	return tvbsize;
} /* dissect_command_frame() */

/****************************************************************/
/* after this line: helper functions for 'dissect_data_frame()' */
/****************************************************************/

/* Dissects a single phasor for 'dissect_PHASORS()' */
static int dissect_single_phasor(tvbuff_t *tvb, int offset,
					double *mag, double *phase, /* returns the resulting values here */
					data_format	format,	    /* information needed to... */
					phasor_notation_e notation) /*  ...dissect the phasor	*/
{
	if (floating_point == format) {
		if (polar == notation) {
			/* float, polar */
			*mag   = tvb_get_ntohieee_float(tvb, offset    );
			*phase = tvb_get_ntohieee_float(tvb, offset + 4);
		}
		else {
			/* float, rect */
			gfloat real, imag;
			real = tvb_get_ntohieee_float(tvb, offset    );
			imag = tvb_get_ntohieee_float(tvb, offset + 4);

			*mag   = sqrt(pow(real, 2) + pow(imag, 2));
			*phase = atan2(imag, real);
		}
	}
	else {
		if (polar == notation) {
			/* int, polar */
			*mag	= (guint16)tvb_get_ntohs(tvb, offset	);
			*phase	= (gint16) tvb_get_ntohs(tvb, offset + 2);
			*phase /= 10000.0; /* angle is in radians*10^4 */
		}
		else {
			/* int, rect */
			gint16 real, imag;
			real = tvb_get_ntohs(tvb, offset    );
			imag = tvb_get_ntohs(tvb, offset + 2);

			*mag   = sqrt(pow(real, 2) + pow(imag, 2));
			*phase = atan2(imag, real);
		}
	}

	return floating_point == format ? 8 : 4;
}

/* used by 'dissect_data_frame()' to dissect the PHASORS field */
static gint dissect_PHASORS(tvbuff_t *tvb, proto_tree *tree, config_block *block, gint offset)
{
	proto_tree *phasor_tree;
	guint	    length;
	gint	    j;
	gint	    cnt = wmem_array_get_count(block->phasors); /* number of phasors to dissect */

	if (0 == cnt)
		return offset;

	length	    = wmem_array_get_count(block->phasors) * (floating_point == block->format_ph ? 8 : 4);
	phasor_tree = proto_tree_add_subtree_format(tree, tvb, offset, length, ett_data_phasors, NULL,
						    "Phasors (%u)", cnt);

	/* dissect a phasor for every phasor_info saved in the config_block */
	for (j = 0; j < cnt; j++) {
		proto_item  *temp_item;
		double	     mag, phase;
		phasor_info *pi;

		pi = (phasor_info *)wmem_array_index(block->phasors, j);
		temp_item = proto_tree_add_string_format(phasor_tree, hf_synphasor_phasor, tvb, offset,
						floating_point == block->format_ph ? 8 : 4, pi->name,
						"Phasor #%u: \"%s\"", j + 1, pi->name);

		offset += dissect_single_phasor(tvb, offset,
						&mag, &phase,
						block->format_ph,
						block->phasor_notation);

		/* for values in integer format, apply conversation factor */
		if (integer == block->format_ph)
			mag = (mag * pi->conv) * 0.00001;

		#define SYNP_ANGLE  "/_"

		proto_item_append_text(temp_item, ", %10.2f%c" SYNP_ANGLE "%7.2f" UTF8_DEGREE_SIGN,
						  mag,
						  V == pi->unit ? 'V' : 'A',
						  phase *180.0/G_PI);
		#undef SYNP_ANGLE
	}
	return offset;
}

/* used by 'dissect_data_frame()' to dissect the FREQ and DFREQ fields */
static gint dissect_DFREQ(tvbuff_t *tvb, proto_tree *tree, config_block *block, gint offset)
{
	if (floating_point == block->format_fr) {
		gfloat tmp;

		tmp = tvb_get_ntohieee_float(tvb, offset);
		proto_tree_add_float_format_value(tree, hf_synphasor_actual_frequency_value, tvb, offset, 4, tmp, "%fHz", tmp); offset += 4;

		/* The standard doesn't clearly say how to interpret this value, but
		 * http://www.pes-psrc.org/h/C37_118_H11_FAQ_Jan2008.pdf provides further information.
		 * --> no scaling factor is applied to DFREQ
		 */
		tmp = tvb_get_ntohieee_float(tvb, offset);
		proto_tree_add_float_format_value(tree, hf_synphasor_rate_change_frequency, tvb, offset, 4, tmp, "%fHz/s", tmp); offset += 4;
	}
	else {
		gint16 tmp;

		tmp = tvb_get_ntohs(tvb, offset);
		proto_tree_add_int_format_value(tree, hf_synphasor_frequency_deviation_from_nominal, tvb, offset, 2, tmp,
				    "%dmHz (actual frequency: %.3fHz)", tmp, block->fnom + (tmp / 1000.0));
		offset += 2;

		tmp = tvb_get_ntohs(tvb, offset);
		proto_tree_add_float_format_value(tree, hf_synphasor_rate_change_frequency, tvb, offset, 2, (gfloat)(tmp / 100.0), "%.3fHz/s", tmp / 100.0); offset += 2;
	}
	return offset;
}

/* used by 'dissect_data_frame()' to dissect the ANALOG field */
static gint dissect_ANALOG(tvbuff_t *tvb, proto_tree *tree, config_block *block, gint offset)
{
	proto_tree *analog_tree;
	guint	    length;
	gint	    j;
	gint	    cnt = wmem_array_get_count(block->analogs); /* number of analog values to dissect */

	if (0 == cnt)
		return offset;

	length	    = wmem_array_get_count(block->analogs) * (floating_point == block->format_an ? 4 : 2);
	analog_tree = proto_tree_add_subtree_format(tree, tvb, offset, length, ett_data_analog, NULL,
						    "Analog values (%u)", cnt);

	for (j = 0; j < cnt; j++) {
		proto_item *temp_item;
		analog_info *ai = (analog_info *)wmem_array_index(block->analogs, j);

		temp_item = proto_tree_add_string_format(analog_tree, hf_synphasor_analog_value, tvb, offset,
						floating_point == block->format_an ? 4 : 2, ai->name,
						"Analog value #%u: \"%s\"", j + 1, ai->name);

		if (floating_point == block->format_an) {
			gfloat tmp = tvb_get_ntohieee_float(tvb, offset); offset += 4;
			proto_item_append_text(temp_item, ", %.3f", tmp);
		}
		else {
			/* the "standard" doesn't say if this is signed or unsigned,
			 * so I just use gint16; the scaling of the conversation factor
			 * is also "user defined", so I just write it after the analog value */
			gint16 tmp = tvb_get_ntohs(tvb, offset); offset += 2;
			proto_item_append_text(temp_item, ", %" G_GINT16_FORMAT " (conversation factor: %#06x)",
					       tmp, ai->conv);
		}
	}
	return offset;
}

/* used by 'dissect_data_frame()' to dissect the DIGITAL field */
static gint dissect_DIGITAL(tvbuff_t *tvb, proto_tree *tree, config_block *block, gint offset)
{
	gint	    j;
	gint	    cnt = block->num_dg; /* number of digital status words to dissect */

	if (0 == cnt)
		return offset;

	tree = proto_tree_add_subtree_format(tree, tvb, offset, cnt * 2, ett_data_digital, NULL,
					     "Digital status words (%u)", cnt);

	for (j = 0; j < cnt; j++) {
		guint16 tmp = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint_format(tree, hf_synphasor_digital_status_word, tvb, offset, 2, tmp, "Digital status word #%u: 0x%04x", j + 1, tmp);
		offset += 2;
	}
	return offset;
}

/*******************************************************************/
/* after this line:  helper functions for 'dissect_config_frame()' */
/*******************************************************************/

/* used by 'dissect_config_frame()' to dissect the PHUNIT field */
static gint dissect_PHUNIT(tvbuff_t *tvb, proto_tree *tree, gint offset, gint cnt)
{
	proto_tree *temp_tree;
	int i;

	if (0 == cnt)
		return offset;

	temp_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4 * cnt, ett_conf_phconv, NULL,
						  "Phasor conversation factors (%u)", cnt);

	/* Conversion factor for phasor channels. Four bytes for each phasor.
	 * MSB:		  0 = voltage, 1 = current
	 * Lower 3 Bytes: unsigned 24-bit word in 10^-5 V or A per bit to scale the phasor value
	 */
	for (i = 0; i < cnt; i++) {
		guint32 tmp = tvb_get_ntohl(tvb, offset);
		proto_tree_add_uint_format(temp_tree, hf_synphasor_conversion_factor, tvb, offset, 4,
				    tmp, "#%u factor: %u * 10^-5, unit: %s",
				    i + 1,
				    tmp & 0x00FFFFFF,
				    tmp & 0xFF000000 ? "Ampere" : "Volt");
		offset += 4;
	}

	return offset;
}

/* used by 'dissect_config_frame()' to dissect the ANUNIT field */
static gint dissect_ANUNIT(tvbuff_t *tvb, proto_tree *tree, gint offset, gint cnt)
{
	proto_item *temp_item;
	proto_tree *temp_tree;
	int i;

	if (0 == cnt)
		return offset;

	temp_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4 * cnt, ett_conf_anconv, NULL,
						  "Analog values conversation factors (%u)", cnt);

	/* Conversation factor for analog channels. Four bytes for each analog value.
	 * MSB: see 'synphasor_conf_anconvnames' in 'synphasor_strings.c'
	 * Lower 3 Bytes: signed 24-bit word, user-defined scaling
	 */
	for (i = 0; i < cnt; i++) {
		gint32 tmp = tvb_get_ntohl(tvb, offset);
		temp_item = proto_tree_add_uint_format(temp_tree, hf_synphasor_factor_for_analog_value, tvb, offset, 4,
						tmp, "Factor for analog value #%i: %s",
						i + 1,
						try_rval_to_str((tmp >> 24) & 0x000000FF, conf_anconvnames));

		tmp &= 0x00FFFFFF;
		if (	tmp &  0x00800000) /* sign bit set */
			tmp |= 0xFF000000;

		proto_item_append_text(temp_item, ", value: %" G_GINT32_FORMAT, tmp);

		offset += 4;
	}

	return offset;
}

/* used by 'dissect_config_frame()' to dissect the DIGUNIT field */
static gint dissect_DIGUNIT(tvbuff_t *tvb, proto_tree *tree, gint offset, gint cnt)
{
	proto_tree *temp_tree, *mask_tree;
	int i;

	if (0 == cnt)
		return offset;

	temp_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4 * cnt, ett_conf_dgmask, NULL,
						  "Masks for digital status words (%u)", cnt);

	/* Mask words for digital status words. Two 16-bit words for each digital word. The first
	 * indicates the normal status of the inputs, the second indicated the valid bits in
	 * the status word
	 */
	for (i = 0; i < cnt; i++) {

		mask_tree = proto_tree_add_subtree_format(temp_tree, tvb, offset, 4, ett_status_word_mask, NULL, "Mask for status word #%u: ", i + 1);
		proto_tree_add_item(mask_tree, hf_synphasor_status_word_mask_normal_state, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(mask_tree, hf_synphasor_status_word_mask_valid_bits, tvb, offset, 4, ENC_BIG_ENDIAN);

		offset += 4;
	}

	return offset;
}

/* used by 'dissect_config_frame()' to dissect the "channel name"-fields */
static gint dissect_CHNAM(tvbuff_t *tvb, proto_tree *tree, gint offset, gint cnt, const char *prefix)
{
	proto_tree *temp_tree;
	int i;

	if (0 == cnt)
		return offset;

	temp_tree = proto_tree_add_subtree_format(tree, tvb, offset, CHNAM_LEN * cnt, ett_conf_phnam, NULL,
						  "%ss (%u)", prefix, cnt);

	/* dissect the 'cnt' channel names */
	for (i = 0; i < cnt; i++) {
		char *str;
		str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, CHNAM_LEN, ENC_ASCII);
		proto_tree_add_string_format(temp_tree, hf_synphasor_channel_name, tvb, offset, CHNAM_LEN,
				    str, "%s #%i: \"%s\"", prefix, i+1, str);
		offset += CHNAM_LEN;
	}

	return offset;
}

void proto_register_synphasor(void)
{
	static hf_register_info hf[] = {
		/* Sync word */
		{ &hf_sync,
		{ "Synchronization word", "synphasor.sync", FT_UINT16, BASE_HEX,
		  NULL, 0x0, NULL, HFILL }},

		/* Flags in the Sync word */
			{ &hf_sync_frtype,
			{ "Frame Type", "synphasor.frtype", FT_UINT16, BASE_HEX,
			  VALS(typenames), 0x0070, NULL, HFILL }},

			{ &hf_sync_version,
			{ "Version",	"synphasor.version", FT_UINT16, BASE_DEC,
			  VALS(versionnames), 0x000F, NULL, HFILL }},

		{ &hf_frsize,
		{ "Framesize", "synphasor.frsize", FT_UINT16, BASE_DEC,
		  NULL, 0x0, NULL, HFILL }},

		{ &hf_idcode,
		{ "PMU/DC ID number", "synphasor.idcode", FT_UINT16, BASE_DEC,
		  NULL, 0x0, NULL, HFILL }},

		{ &hf_soc,
		{ "SOC time stamp", "synphasor.soc", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
		  NULL, 0x0, NULL, HFILL }},

		/* Time quality flags in fracsec */
		{ &hf_timeqal_lsdir,
		{ "Leap second direction", "synphasor.timeqal.lsdir", FT_BOOLEAN, 8,
		  NULL, 0x40, NULL, HFILL }},

		{ &hf_timeqal_lsocc,
		{ "Leap second occurred", "synphasor.timeqal.lsocc", FT_BOOLEAN, 8,
		  NULL, 0x20, NULL, HFILL }},

		{ &hf_timeqal_lspend,
		{ "Leap second pending", "synphasor.timeqal.lspend", FT_BOOLEAN, 8,
		  NULL, 0x10, NULL, HFILL }},

		{ &hf_timeqal_timequalindic,
		{ "Time Quality indicator code", "synphasor.timeqal.timequalindic", FT_UINT8, BASE_HEX,
		  VALS(timequalcodes), 0x0F, NULL, HFILL }},

		/* Fraction of second */
		{ &hf_fracsec,
		{ "Fraction of second (raw)", "synphasor.fracsec", FT_UINT24, BASE_DEC,
		  NULL, 0x0, NULL, HFILL }},

	/* Data types for configuration frames */
		{ &hf_conf_timebase,
		{ "Resolution of fractional second time stamp", "synphasor.conf.timebase", FT_UINT24, BASE_DEC,
		  NULL, 0x0, NULL, HFILL }},

		{ &hf_conf_numpmu,
		{ "Number of PMU blocks included in the frame", "synphasor.conf.numpmu", FT_UINT16, BASE_DEC,
		  NULL, 0x0, NULL, HFILL }},

		/* Bits in the FORMAT word */
		{ &hf_conf_formatb3,
		{ "FREQ/DFREQ format", "synphasor.conf.dfreq_format", FT_BOOLEAN, 16,
		  TFS(&conf_formatb123names), 0x8, NULL, HFILL }},

		{ &hf_conf_formatb2,
		{ "Analog values format", "synphasor.conf.analog_format", FT_BOOLEAN, 16,
		  TFS(&conf_formatb123names), 0x4, NULL, HFILL }},

		{ &hf_conf_formatb1,
		{ "Phasor format", "synphasor.conf.phasor_format", FT_BOOLEAN, 16,
		  TFS(&conf_formatb123names), 0x2, NULL, HFILL }},

		{ &hf_conf_formatb0,
		{ "Phasor notation", "synphasor.conf.phasor_notation", FT_BOOLEAN, 16,
		  TFS(&conf_formatb0names), 0x1, NULL, HFILL }},

		{ &hf_conf_fnom,
		{ "Nominal line freqency", "synphasor.conf.fnom", FT_BOOLEAN, 16,
		  TFS(&conf_fnomnames), 0x0001, NULL, HFILL }},

		{ &hf_conf_cfgcnt,
		{ "Configuration change count", "synphasor.conf.cfgcnt", FT_UINT16, BASE_DEC,
		  NULL, 0, NULL, HFILL }},

	/* Data types for data frames */
		/* Flags in the STAT word */
		{ &hf_data_statb15,
		{ "Data valid", "synphasor.data.valid", FT_BOOLEAN, 16,
		  TFS(&data_statb15names), 0x8000, NULL, HFILL }},

		{ &hf_data_statb14,
		{ "PMU error", "synphasor.data.PMUerror", FT_BOOLEAN, 16,
		  TFS(&data_statb14names), 0x4000, NULL, HFILL }},

		{ &hf_data_statb13,
		{ "Time synchronized", "synphasor.data.sync", FT_BOOLEAN, 16,
		  TFS(&data_statb13names), 0x2000, NULL, HFILL }},

		{ &hf_data_statb12,
		{ "Data sorting", "synphasor.data.sorting", FT_BOOLEAN, 16,
		  TFS(&data_statb12names), 0x1000, NULL, HFILL }},

		{ &hf_data_statb11,
		{ "Trigger detected", "synphasor.data.trigger", FT_BOOLEAN, 16,
		  TFS(&data_statb11names), 0x0800, NULL, HFILL }},

		{ &hf_data_statb10,
		{ "Configuration changed", "synphasor.data.CFGchange", FT_BOOLEAN, 16,
		  TFS(&data_statb10names), 0x0400, NULL, HFILL }},

		{ &hf_data_statb05to04,
		{ "Unlocked time", "synphasor.data.t_unlock", FT_UINT16, BASE_HEX,
		  VALS(data_statb05to04names), 0x0030, NULL, HFILL }},

		{ &hf_data_statb03to00,
		{ "Trigger reason", "synphasor.data.trigger_reason", FT_UINT16, BASE_HEX,
		  VALS(data_statb03to00names), 0x000F, NULL, HFILL }},

	/* Data type for command frame */
		{ &hf_command,
		{ "Command", "synphasor.command", FT_UINT16, BASE_HEX,
		  VALS(command_names), 0x000F, NULL, HFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_synphasor_data, { "Data", "synphasor.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_checksum, { "Checksum", "synphasor.checksum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_num_phasors, { "Number of phasors", "synphasor.num_phasors", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_num_analog_values, { "Number of analog values", "synphasor.num_analog_values", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_num_digital_status_words, { "Number of digital status words", "synphasor.num_digital_status_words", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_rate_of_transmission, { "Rate of transmission", "synphasor.rate_of_transmission", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_phasor, { "Phasor", "synphasor.phasor", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_actual_frequency_value, { "Actual frequency value", "synphasor.actual_frequency_value", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_rate_change_frequency, { "Rate of change of frequency", "synphasor.rate_change_frequency", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_frequency_deviation_from_nominal, { "Frequency deviation from nominal", "synphasor.frequency_deviation_from_nominal", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_analog_value, { "Analog value", "synphasor.analog_value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_digital_status_word, { "Digital status word", "synphasor.digital_status_word", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_conversion_factor, { "conversion factor", "synphasor.conversion_factor", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_factor_for_analog_value, { "Factor for analog value", "synphasor.factor_for_analog_value", FT_UINT32, BASE_DEC, NULL, 0x000000FF, NULL, HFILL }},
      { &hf_synphasor_channel_name, { "Channel name", "synphasor.channel_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_extended_frame_data, { "Extended frame data", "synphasor.extended_frame_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_unknown_data, { "Unknown data", "synphasor.data.unknown", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_synphasor_status_word_mask_normal_state, { "Normal state", "synphasor.status_word_mask.normal_state", FT_UINT32, BASE_HEX, NULL, 0xFFFF0000, NULL, HFILL }},
      { &hf_synphasor_status_word_mask_valid_bits, { "Valid bits", "synphasor.status_word_mask.valid_bits", FT_UINT32, BASE_HEX, NULL, 0x0000FFFF, NULL, HFILL }},
	};

	/* protocol subtree array */
	static gint *ett[] = {
		&ett_synphasor,
		&ett_frtype,
		&ett_timequal,
		&ett_conf,
		&ett_conf_station,
		&ett_conf_format,
		&ett_conf_phnam,
		&ett_conf_annam,
		&ett_conf_dgnam,
		&ett_conf_phconv,
		&ett_conf_anconv,
		&ett_conf_dgmask,
		&ett_data,
		&ett_data_block,
		&ett_data_stat,
		&ett_data_phasors,
		&ett_data_analog,
		&ett_data_digital,
		&ett_command,
		&ett_status_word_mask
	};

	static ei_register_info ei[] = {
		{ &ei_synphasor_extended_frame_data, { "synphasor.extended_frame_data.unaligned", PI_PROTOCOL, PI_WARN, "Size not multiple of 16-bit word", EXPFILL }},
	};

	module_t *synphasor_module;
	expert_module_t* expert_synphasor;

	/* register protocol */
	proto_synphasor = proto_register_protocol(PROTOCOL_NAME,
						  PROTOCOL_SHORT_NAME,
						  PROTOCOL_ABBREV);

	/* Registering protocol to be called by another dissector */
	synphasor_udp_handle = register_dissector("synphasor", dissect_udp, proto_synphasor);

	proto_register_field_array(proto_synphasor, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_synphasor = expert_register_protocol(proto_synphasor);
	expert_register_field_array(expert_synphasor, ei, array_length(ei));

	/* register preferences */
	synphasor_module = prefs_register_protocol(proto_synphasor, proto_reg_handoff_synphasor);

	/* the port numbers of the lower level protocols */
	prefs_register_uint_preference(synphasor_module, "udp_port", "Synchrophasor UDP port",
				       "Set the port number for synchrophasor frames over UDP" \
				       "(if other than the default of 4713)",
				       10, &global_pref_udp_port);
	prefs_register_uint_preference(synphasor_module, "tcp_port", "Synchrophasor TCP port",
				       "Set the port number for synchrophasor frames over TCP" \
				       "(if other than the default of 4712)",
				       10, &global_pref_tcp_port);

} /* proto_register_synphasor() */

/* called at startup and when the preferences change */
void proto_reg_handoff_synphasor(void)
{
	static gboolean		  initialized = FALSE;
	static dissector_handle_t synphasor_tcp_handle;
	static guint		  current_udp_port;
	static guint		  current_tcp_port;

	if (!initialized) {
		synphasor_tcp_handle = create_dissector_handle(dissect_tcp, proto_synphasor);
		dissector_add_for_decode_as("rtacser.data", synphasor_udp_handle);
		initialized = TRUE;
	}
	else {
		/* update preferences */
		dissector_delete_uint("udp.port", current_udp_port, synphasor_udp_handle);
		dissector_delete_uint("tcp.port", current_tcp_port, synphasor_tcp_handle);
	}

	current_udp_port = global_pref_udp_port;
	current_tcp_port = global_pref_tcp_port;

	dissector_add_uint("udp.port", current_udp_port, synphasor_udp_handle);
	dissector_add_uint("tcp.port", current_tcp_port, synphasor_tcp_handle);
} /* proto_reg_handoff_synphasor() */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
