/* packet-rfc2190.c
 *
 * Routines for RFC2190-encapsulated H.263 dissection
 *
 * Copyright 2003 Niklas Ogren <niklas.ogren@7l.se>
 * Seven Levels Consultants AB
 *
 * Copyright 2008 Richard van der Hoff, MX Telecom
 * <richardv@mxtelecom.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * This dissector tries to dissect the H.263 protocol according to
 * RFC 2190, http://www.ietf.org/rfc/rfc2190.txt
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <epan/rtp_pt.h>
#include <epan/iax2_codec_type.h>

#include "packet-h263.h"

/* H.263 header fields             */
static int proto_rfc2190		= -1;

/* Mode A header */
static int hf_rfc2190_ftype = -1;
static int hf_rfc2190_pbframes = -1;
static int hf_rfc2190_sbit = -1;
static int hf_rfc2190_ebit = -1;
static int hf_rfc2190_srcformat = -1;
static int hf_rfc2190_picture_coding_type = -1;
static int hf_rfc2190_unrestricted_motion_vector = -1;
static int hf_rfc2190_syntax_based_arithmetic = -1;
static int hf_rfc2190_advanced_prediction = -1;
static int hf_rfc2190_r = -1;
static int hf_rfc2190_rr = -1;
static int hf_rfc2190_dbq = -1;
static int hf_rfc2190_trb = -1;
static int hf_rfc2190_tr = -1;
/* Additional fields for Mode B or C header */
static int hf_rfc2190_quant = -1;
static int hf_rfc2190_gobn = -1;
static int hf_rfc2190_mba = -1;
static int hf_rfc2190_hmv1 = -1;
static int hf_rfc2190_vmv1 = -1;
static int hf_rfc2190_hmv2 = -1;
static int hf_rfc2190_vmv2 = -1;

static gint ett_rfc2190			= -1;
static dissector_handle_t h263_handle;


static void
dissect_rfc2190( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
    proto_item *ti					= NULL;
    proto_tree *rfc2190_tree			= NULL;
    unsigned int offset				= 0;
    unsigned int rfc2190_version		= 0;
    tvbuff_t *next_tvb;

    rfc2190_version = (tvb_get_guint8( tvb, offset ) & 0xc0 ) >> 6;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "H.263 ");

    if( rfc2190_version == 0x00) {
        col_append_str( pinfo->cinfo, COL_INFO, "MODE A ");
    }
    else if( rfc2190_version == 0x02) {
        col_append_str( pinfo->cinfo, COL_INFO, "MODE B ");
    }
    else if( rfc2190_version == 0x03) {
        col_append_str( pinfo->cinfo, COL_INFO, "MODE C ");
    }

    if ( tree ) {
        ti = proto_tree_add_item( tree, proto_rfc2190, tvb, offset, -1, ENC_NA );
        rfc2190_tree = proto_item_add_subtree( ti, ett_rfc2190 );

        /* FBIT 1st octet, 1 bit */
        proto_tree_add_boolean( rfc2190_tree, hf_rfc2190_ftype, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x80 );
        /* PBIT 1st octet, 1 bit */
        proto_tree_add_boolean( rfc2190_tree, hf_rfc2190_pbframes, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x40 );
        /* SBIT 1st octet, 3 bits */
        proto_tree_add_uint( rfc2190_tree, hf_rfc2190_sbit, tvb, offset, 1, ( tvb_get_guint8( tvb, offset ) & 0x38 ) >> 3 );
        /* EBIT 1st octet, 3 bits */
        proto_tree_add_uint( rfc2190_tree, hf_rfc2190_ebit, tvb, offset, 1, tvb_get_guint8( tvb, offset )  & 0x7 );

        offset++;

        /* SRC 2nd octet, 3 bits */
        proto_tree_add_uint( rfc2190_tree, hf_rfc2190_srcformat, tvb, offset, 1, tvb_get_guint8( tvb, offset ) >> 5 );

        if(rfc2190_version == 0x00) { /* MODE A */
            /* I flag, 1 bit */
            proto_tree_add_boolean( rfc2190_tree, hf_rfc2190_picture_coding_type, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x10 );
            /* U flag, 1 bit */
            proto_tree_add_boolean( rfc2190_tree, hf_rfc2190_unrestricted_motion_vector, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x08 );
            /* S flag, 1 bit */
            proto_tree_add_boolean( rfc2190_tree, hf_rfc2190_syntax_based_arithmetic, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x04 );
            /* A flag, 1 bit */
            proto_tree_add_boolean( rfc2190_tree, hf_rfc2190_advanced_prediction, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x02 );

            /* Reserved 2nd octect, 1 bit + 3rd octect 3 bits */
            proto_tree_add_uint( rfc2190_tree, hf_rfc2190_r, tvb, offset, 2, ( ( tvb_get_guint8( tvb, offset ) & 0x1 ) << 3 ) + ( ( tvb_get_guint8( tvb, offset + 1 ) & 0xe0 ) >> 5 ) );

            offset++;

            /* DBQ 3 octect, 2 bits */
            proto_tree_add_uint( rfc2190_tree, hf_rfc2190_dbq, tvb, offset, 1, ( tvb_get_guint8( tvb, offset ) & 0x18 ) >> 3 );
            /* TRB 3 octect, 3 bits */
            proto_tree_add_uint( rfc2190_tree, hf_rfc2190_trb, tvb, offset, 1, ( tvb_get_guint8( tvb, offset ) & 0x07 ) );

            offset++;

            /* TR 4 octect, 8 bits */
            proto_tree_add_uint( rfc2190_tree, hf_rfc2190_tr, tvb, offset, 1, tvb_get_guint8( tvb, offset ) );

            offset++;

        } else { /* MODE B or MODE C */
            /* QUANT 2 octect, 5 bits */
            proto_tree_add_uint( rfc2190_tree, hf_rfc2190_quant, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x1f );

            offset++;

            /* GOBN 3 octect, 5 bits */
            proto_tree_add_uint( rfc2190_tree, hf_rfc2190_gobn, tvb, offset, 1, ( tvb_get_guint8( tvb, offset ) & 0xf8 ) >> 3);
            /* MBA 3 octect, 3 bits + 4 octect 6 bits */
            proto_tree_add_uint( rfc2190_tree, hf_rfc2190_mba, tvb, offset, 2, ( ( tvb_get_guint8( tvb, offset ) & 0x7 ) << 6 ) + ( ( tvb_get_guint8( tvb, offset + 1 ) & 0xfc ) >> 2 ) );

            offset++;

            /* Reserved 4th octect, 2 bits */
            proto_tree_add_uint( rfc2190_tree, hf_rfc2190_r, tvb, offset, 1, ( tvb_get_guint8( tvb, offset ) & 0x3 ) );

            offset++;

            /* I flag, 1 bit */
            proto_tree_add_boolean( rfc2190_tree, hf_rfc2190_picture_coding_type, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x80 );
            /* U flag, 1 bit */
            proto_tree_add_boolean( rfc2190_tree, hf_rfc2190_unrestricted_motion_vector, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x40 );
            /* S flag, 1 bit */
            proto_tree_add_boolean( rfc2190_tree, hf_rfc2190_syntax_based_arithmetic, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x20 );
            /* A flag, 1 bit */
            proto_tree_add_boolean( rfc2190_tree, hf_rfc2190_advanced_prediction, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x10 );

            /* HMV1 5th octect, 4 bits + 6th octect 3 bits*/
            proto_tree_add_uint( rfc2190_tree, hf_rfc2190_hmv1, tvb, offset, 2,( ( tvb_get_guint8( tvb, offset ) & 0xf ) << 3 ) + ( ( tvb_get_guint8( tvb, offset+1 ) & 0xe0 ) >> 5) );

            offset++;

            /* VMV1 6th octect, 5 bits + 7th octect 2 bits*/
            proto_tree_add_uint( rfc2190_tree, hf_rfc2190_vmv1, tvb, offset, 2,( ( tvb_get_guint8( tvb, offset ) & 0x1f ) << 2 ) + ( ( tvb_get_guint8( tvb, offset+1 ) & 0xc0 ) >> 6) );

            offset++;

            /* HMV2 7th octect, 6 bits + 8th octect 1 bit*/
            proto_tree_add_uint( rfc2190_tree, hf_rfc2190_hmv2, tvb, offset, 2,( ( tvb_get_guint8( tvb, offset ) & 0x3f ) << 1 ) + ( ( tvb_get_guint8( tvb, offset+1 ) & 0xf0 ) >> 7) );

            offset++;

            /* VMV2 8th octect, 7 bits*/
            proto_tree_add_uint( rfc2190_tree, hf_rfc2190_vmv2, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x7f );

            offset++;

            if(rfc2190_version == 0x03) { /* MODE C */
                /* Reserved 9th to 11th octect, 8 + 8 + 3 bits */
                proto_tree_add_uint( rfc2190_tree, hf_rfc2190_rr, tvb, offset, 3, ( tvb_get_guint8( tvb, offset ) << 11 ) + ( tvb_get_guint8( tvb, offset + 1 ) << 3 ) + ( ( tvb_get_guint8( tvb, offset + 2 ) & 0xe0 ) >> 5 ) );

                offset+=2;

                /* DBQ 11th octect, 2 bits */
                proto_tree_add_uint( rfc2190_tree, hf_rfc2190_dbq, tvb, offset, 1, ( tvb_get_guint8( tvb, offset ) & 0x18 ) >>3 );
                /* TRB 11th octect, 3 bits */
                proto_tree_add_uint( rfc2190_tree, hf_rfc2190_trb, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x07 );

                offset++;

                /* TR 12th octect, 8 bits */
                proto_tree_add_uint( rfc2190_tree, hf_rfc2190_tr, tvb, offset, 1, tvb_get_guint8( tvb, offset ) );

                offset++;
            } /* end mode c */
        } /* end not mode a */
    } else {
        switch(rfc2190_version) {
            case 0x00: /* MODE A */
                offset += 4;
                break;
            case 0x01: /* MODE B */
                offset += 8;
                break;
            case 0x02: /* MODE C */
                offset += 12;
                break;
        }
    }


    /* The rest of the packet is the H.263 stream */
    next_tvb = tvb_new_subset( tvb, offset, tvb_length(tvb) - offset, tvb_reported_length(tvb) - offset);
    call_dissector(h263_handle,next_tvb,pinfo,tree);
}

void
proto_reg_handoff_rfc2190(void)
{
	dissector_handle_t rfc2190_handle;

	rfc2190_handle = find_dissector("rfc2190");
	dissector_add_uint("rtp.pt", PT_H263, rfc2190_handle);
	dissector_add_uint("iax2.codec", AST_FORMAT_H263, rfc2190_handle);

	h263_handle = find_dissector("h263data");
}


void
proto_register_rfc2190(void)
{
	static hf_register_info hf[] =
	{
		{
			&hf_rfc2190_ftype,
			{
				"F",
				"rfc2190.ftype",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				"Indicates the mode of the payload header (MODE A or B/C)", HFILL
			}
		},
		{
			&hf_rfc2190_pbframes,
			{
				"p/b frame",
				"rfc2190.pbframes",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				"Optional PB-frames mode as defined by H.263 (MODE C)", HFILL
			}
		},
		{
			&hf_rfc2190_sbit,
			{
				"Start bit position",
				"rfc2190.sbit",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Start bit position specifies number of most significant bits that shall be ignored in the first data byte.", HFILL
			}
		},
		{
			&hf_rfc2190_ebit,
			{
				"End bit position",
				"rfc2190.ebit",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"End bit position specifies number of least significant bits that shall be ignored in the last data byte.", HFILL
			}
		},
		{
			&hf_rfc2190_srcformat,
			{
				"SRC format",
				"rfc2190.srcformat",
				FT_UINT8,
				BASE_DEC,
				VALS(h263_srcformat_vals),
				0x0,
				"Source format specifies the resolution of the current picture.", HFILL
			}
		},
		{
			&hf_rfc2190_picture_coding_type,
			{
				"Inter-coded frame",
				"rfc2190.picture_coding_type",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				"Picture coding type, intra-coded (false) or inter-coded (true)", HFILL
			}
		},
		{
			&hf_rfc2190_unrestricted_motion_vector,
			{
				"Motion vector",
				"rfc2190.unrestricted_motion_vector",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				"Unrestricted Motion Vector option for current picture", HFILL
			}
		},
		{
			&hf_rfc2190_syntax_based_arithmetic,
			{
				"Syntax-based arithmetic coding",
				"rfc2190.syntax_based_arithmetic",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				"Syntax-based Arithmetic Coding option for current picture", HFILL
			}
		},
		{
			&hf_rfc2190_advanced_prediction,
			{
				"Advanced prediction option",
				"rfc2190.advanced_prediction",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				"Advanced Prediction option for current picture", HFILL
			}
		},
		{
			&hf_rfc2190_dbq,
			{
				"Differential quantization parameter",
				"rfc2190.dbq",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Differential quantization parameter used to calculate quantizer for the B frame based on quantizer for the P frame, when PB-frames option is used.", HFILL
			}
		},
		{
			&hf_rfc2190_trb,
			{
				"Temporal Reference for B frames",
				"rfc2190.trb",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Temporal Reference for the B frame as defined by H.263", HFILL
			}
		},
		{
			&hf_rfc2190_tr,
			{
				"Temporal Reference for P frames",
				"rfc2190.tr",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Temporal Reference for the P frame as defined by H.263", HFILL
			}
		},
		{
			&hf_rfc2190_quant,
			{
				"Quantizer",
				"rfc2190.quant",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Quantization value for the first MB coded at the starting of the packet.", HFILL
			}
		},
		{
			&hf_rfc2190_gobn,
			{
				"GOB Number",
				"rfc2190.gobn",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"GOB number in effect at the start of the packet.", HFILL
			}
		},
		{
			&hf_rfc2190_mba,
			{
				"Macroblock address",
				"rfc2190.mba",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"The address within the GOB of the first MB in the packet, counting from zero in scan order.", HFILL
			}
		},
		{
			&hf_rfc2190_hmv1,
			{
				"Horizontal motion vector 1",
				"rfc2190.hmv1",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Horizontal motion vector predictor for the first MB in this packet", HFILL
			}
		},
		{
			&hf_rfc2190_vmv1,
			{
				"Vertical motion vector 1",
				"rfc2190.vmv1",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Vertical motion vector predictor for the first MB in this packet", HFILL
			}
		},
		{
			&hf_rfc2190_hmv2,
			{
				"Horizontal motion vector 2",
				"rfc2190.hmv2",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Horizontal motion vector predictor for block number 3 in the first MB in this packet when four motion vectors are used with the advanced prediction option.", HFILL
			}
		},
		{
			&hf_rfc2190_vmv2,
			{
				"Vertical motion vector 2",
				"rfc2190.vmv2",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Vertical motion vector predictor for block number 3 in the first MB in this packet when four motion vectors are used with the advanced prediction option.", HFILL
			}
		},
		{
			&hf_rfc2190_r,
			{
				"Reserved field",
				"rfc2190.r",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Reserved field that should contain zeroes", HFILL
			}
		},
		{
			&hf_rfc2190_rr,
			{
				"Reserved field 2",
				"rfc2190.rr",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"Reserved field that should contain zeroes", HFILL
			}
		},
        };

        static gint *ett[] =
	{
            &ett_rfc2190,
        };

        proto_register_subtree_array(ett, array_length(ett));

	proto_rfc2190 = proto_register_protocol("H.263 RTP Payload header (RFC2190)",
	    "RFC2190", "rfc2190");

	proto_register_field_array(proto_rfc2190, hf, array_length(hf));
	register_dissector("rfc2190", dissect_rfc2190, proto_rfc2190);
}

