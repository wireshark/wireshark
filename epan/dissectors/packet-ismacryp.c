/* packet-ismacryp.c
 * ISMACryp 1.1 & 2.0 protocol as defined in ISMA Encryption and Authentication see http://www.isma.tv
 *
 * David Castleford, Orange Labs / France Telecom R&D
 * March 2009
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* 	TODO: get ISMACryp parameters automatically from SDP info,
 *             if present (typically sent via SAP/SDP),
 *             rather than having manual insertion via preferences
 *	TODO: perhaps better check coherence of certain information?
*/
#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_ismacryp(void);
void proto_reg_handoff_ismacryp(void);

/* keeps track of current position in buffer in terms of bit and byte offset */
typedef struct Toffset_struct
{
	gint offset_bytes;
	guint8 offset_bits;

} offset_struct;

static void dissect_ismacryp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint ismacryp_version);
static offset_struct* dissect_auheader( tvbuff_t *tvb, offset_struct *poffset, packet_info *pinfo, proto_tree *tree, guint set_version );
static void add_bits(offset_struct* poffset, gint len_bits);

#define PROTO_TAG_ISMACRYP	"ISMACRYP"
#define PROTO_TAG_ISMACRYP_11	"ISMACryp_11"
#define PROTO_TAG_ISMACRYP_20	"ISMACryp_20"
#define V11					11
#define V20					20
#define AAC_HBR_MODE				0
#define MPEG4_VIDEO_MODE			1
#define AVC_VIDEO_MODE				2
/* #define USERMODE				3 */
#define DEFAULT_SELECTIVE_ENCRYPTION		TRUE
#define DEFAULT_SLICE_INDICATION		FALSE
#define DEFAULT_PADDING_INDICATION		FALSE
#define DEFAULT_IV_LENGTH			4
#define DEFAULT_DELTA_IV_LENGTH			0
#define DEFAULT_KEY_INDICATOR_LENGTH		0
#define DEFAULT_KEY_INDICATOR_PER_AU		FALSE
#define AU_HEADERS_LENGTH_SIZE			2 /* size in bytes */
#define DEFAULT_AU_SIZE_LENGTH			0
#define DEFAULT_AU_INDEX_LENGTH			0
#define DEFAULT_AU_INDEX_DELTA_LENGTH		0
#define DEFAULT_CTS_DELTA_LENGTH		0
#define DEFAULT_DTS_DELTA_LENGTH		0
#define DEFAULT_RANDOM_ACCESS_INDICATION	FALSE
#define DEFAULT_STREAM_STATE_INDICATION		0

/* Wireshark ID of the ISMACRYP protocol */
static int proto_ismacryp = -1;
static int proto_ismacryp_v11 = -1;
static int proto_ismacryp_v20 = -1;

/* parameters set in preferences */
static guint    pref_au_size_length           = DEFAULT_AU_SIZE_LENGTH;            /* default Au size length */
static guint    pref_au_index_length          = DEFAULT_AU_INDEX_LENGTH;           /* default Au index length */
static guint    pref_au_index_delta_length    = DEFAULT_AU_INDEX_DELTA_LENGTH;     /* default Au index delta length */
static guint    pref_cts_delta_length         = DEFAULT_CTS_DELTA_LENGTH;          /* default CTS delta  length */
static guint    pref_dts_delta_length         = DEFAULT_DTS_DELTA_LENGTH;          /* default DTS delta  length */
static gboolean pref_random_access_indication = DEFAULT_RANDOM_ACCESS_INDICATION;  /* default random access indication */
static guint    pref_stream_state_indication  = DEFAULT_STREAM_STATE_INDICATION;   /* default stream state indication */
static guint    version_type                  = V11;                               /* default to ISMACryp 1.1 */
static guint    mode                          = AVC_VIDEO_MODE;                    /* default codec mode */
static gboolean selective_encryption          = DEFAULT_SELECTIVE_ENCRYPTION;      /* default selective encryption flag */
static gboolean slice_indication              = DEFAULT_SLICE_INDICATION;          /* default slice indication */
static gboolean padding_indication            = DEFAULT_PADDING_INDICATION;        /* default padding indication */
static guint    key_indicator_length          = DEFAULT_KEY_INDICATOR_LENGTH;      /* default key indicator length */
static gboolean key_indicator_per_au_flag     = DEFAULT_KEY_INDICATOR_PER_AU;      /* default key indicator per au */
static guint    iv_length                     = DEFAULT_IV_LENGTH;                 /* default IV length */
static guint    delta_iv_length               = DEFAULT_DELTA_IV_LENGTH;           /* default delta IV length */
static gboolean pref_user_mode                = FALSE; /* preference user mode instead of RFC3640 mode? */
static gboolean override_flag                 = FALSE; /* override use of RTP payload type to deduce ISMACryp version */

/* */

static guint    au_size_length                = DEFAULT_AU_SIZE_LENGTH;            /* default Au size length */
static guint    au_index_length               = DEFAULT_AU_INDEX_LENGTH;           /* default Au index length */
static guint    au_index_delta_length         = DEFAULT_AU_INDEX_DELTA_LENGTH;     /* default Au index delta length */
static guint    cts_delta_length              = DEFAULT_CTS_DELTA_LENGTH;          /* default CTS delta  length */
static guint    dts_delta_length              = DEFAULT_DTS_DELTA_LENGTH;          /* default DTS delta  length */
static gboolean random_access_indication      = DEFAULT_RANDOM_ACCESS_INDICATION;  /* default random access indication */
static guint    stream_state_indication       = DEFAULT_STREAM_STATE_INDICATION;   /* default stream state indication */
static gboolean user_mode                     = FALSE; /* selected user mode instead of RFC3640 mode? */

/*static const value_string messagetypenames[] = {};	*/

/* ismacryp Parameter Types */
/*static const value_string parametertypenames[] = {}; */
static const value_string modetypenames[] = {
	{ AAC_HBR_MODE,     "aac-hbr" },
	{ MPEG4_VIDEO_MODE, "mpeg4-video" },
	{ AVC_VIDEO_MODE,   "avc-video" },
	{ 0, NULL}
};
/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_ismacryp()
*/
/** Kts attempt at defining the protocol */
/* static gint hf_ismacryp = -1; */
static gint hf_ismacryp_header = -1;
static gint hf_ismacryp_au_headers_length = -1;
/* static gint hf_ismacryp_header_length = -1; */
static gint hf_ismacryp_header_byte = -1;
/* static gint hf_ismacryp_version = -1; */
/* static gint hf_ismacryp_length = -1; */
/* static gint hf_ismacryp_message_type = -1; */
/* static gint hf_ismacryp_message_length = -1; */
static gint hf_ismacryp_message = -1;
/* static gint hf_ismacryp_parameter = -1; */
/* static gint hf_ismacryp_parameter_type = -1; */
/* static gint hf_ismacryp_parameter_length = -1; */
/* static gint hf_ismacryp_parameter_value = -1; */
static gint hf_ismacryp_iv = -1;
static gint hf_ismacryp_delta_iv = -1;
static gint hf_ismacryp_key_indicator = -1;
/* static gint hf_ismacryp_delta_iv_length = -1; */
static gint hf_ismacryp_au_size = -1;
static gint hf_ismacryp_au_index = -1;
static gint hf_ismacryp_au_index_delta = -1;
static gint hf_ismacryp_cts_delta = -1;
static gint hf_ismacryp_cts_flag = -1;
static gint hf_ismacryp_dts_flag = -1;
static gint hf_ismacryp_dts_delta = -1;
static gint hf_ismacryp_rap_flag = -1;
static gint hf_ismacryp_au_is_encrypted = -1;
static gint hf_ismacryp_slice_start = -1;
static gint hf_ismacryp_slice_end = -1;
static gint hf_ismacryp_padding_bitcount = -1;
static gint hf_ismacryp_padding = -1;
static gint hf_ismacryp_reserved_bits = -1;
static gint hf_ismacryp_unused_bits = -1;
static gint hf_ismacryp_stream_state = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_ismacryp = -1;
static gint ett_ismacryp_header = -1;
static gint ett_ismacryp_header_byte = -1;
static gint ett_ismacryp_message = -1;

/* Informative tree structure is shown here:
* TREE 	-
*	AU Headers Length (2 bytes) - total length of AU header(s)
*	- HEADER1
*		HEADER BYTE (if present - 1 byte)
*			-AU_is_encrypted (1 bit)
*			-Slice_start (1 bit)
*			-Slice_end (1 bit)
*			-Padding_bitcount (3 bits)
*			-Reserved (2 bits)
*		IV (variable length)
*		Key Indicator (variable length)
*		AU size (if present - variable length)
*		AU index (if present - variable length)
*		CTS delta (if present - variable length)
*		DTS delta (if present - variable length)
*		RAP flag (if present - 1 bit)
*		Stream State Indication (if present - variable length)
*	- HEADER2 if 2nd header present (depends on AU headers length)
*		Header Byte (if present - 1 byte)
*			-AU_is_encrypted (1 bit)
*			-Slice_start (1 bit)
*			-Slice_end (1 bit)
*			-Padding_bitcount (3 bits)
*			-Reserved (2 bits)
*		IV (variable length)
*		Key Indicator (variable length)
*		AU size (if present - variable length)
*		AU index delta(if present - variable length)
*		CTS delta (if present - variable length)
*		DTS delta (if present - variable length)
*		RAP flag (if present - 1 bit)
*		Stream State Indication (if present - variable length)
*	- more HEADERS if present
*	- MESSAGE
*		encrypted AU
* End informative tree structure
*/

/* Note that check coherence of total AU headers length and that calculated from size of parameters defined by default or preferences.
* These are found in SDP and vary e.g. between audio and video and depend on ISMACryp encoding parameters
* hence if these values are incorrect displayed values will be strange and can see errors
* this could be improved of course
*/

/* dissect_ismacryp_v11 gets called if rtp_dyn_payload_type = "enc-mpeg4-generic" i.e. is set via SDP */
static int dissect_ismacryp_v11(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	/* display ISMACryp version */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_ISMACRYP_11);

	/* display RTP payload type */
	col_set_str(pinfo->cinfo, COL_INFO, "(PT=enc-mpeg4-generic)");

	dissect_ismacryp_common( tvb, pinfo, tree, V11);
	return tvb_captured_length(tvb);
}

/* dissect_ismacryp_v20 gets called if rtp_dyn_payload_type = "enc-isoff-generic" i.e. is set via SDP */
static int dissect_ismacryp_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	/* display ISMACryp version */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_ISMACRYP_20);

	/* display RTP payload type */
	col_set_str(pinfo->cinfo, COL_INFO, "(PT=enc-isoff-generic)");

	dissect_ismacryp_common( tvb, pinfo, tree, V20);
	return tvb_captured_length(tvb);
}

static int dissect_ismacryp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_INFO, "Manual version");
	dissect_ismacryp_common( tvb, pinfo, tree, version_type);   /* Unknown version type: Use preference */
	return tvb_captured_length(tvb);
}

static void dissect_ismacryp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint ismacryp_version)
{
	guint set_version;           /* ISMACryp version used during dissection */
	proto_item *ismacryp_item;
	proto_tree *ismacryp_tree;
	proto_tree *ismacryp_message_tree;

	/* select and display ISMACryp version */
	if ((ismacryp_version != version_type) && override_flag) {
		/* override -> use manual preference setting */
		col_append_str(pinfo->cinfo, COL_INFO, " Manual version");
		set_version = version_type; /* set to preference value */
	}
	else {
		set_version = ismacryp_version;
	}

	if (set_version == V11) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_ISMACRYP_11);
		/* display mode */
		if (pref_user_mode == FALSE) {
			col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(mode, modetypenames, "user mode"));
		} else {
			col_append_str(pinfo->cinfo, COL_INFO, ", user mode");
		}
		user_mode = pref_user_mode;
	}
	if (set_version == V20) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_ISMACRYP_20);
		user_mode = TRUE;
		/* display mode */
		col_append_str(pinfo->cinfo, COL_INFO, ", user mode");
	}
	/* select correct AU values depending on version & selected mode in preferences menu if not in user_mode */
	if (user_mode == TRUE) { /* use values set in preference menu */
		au_size_length = pref_au_size_length;
		au_index_length = pref_au_index_length;
		au_index_delta_length = pref_au_index_delta_length;
		cts_delta_length = pref_cts_delta_length;
		dts_delta_length = pref_dts_delta_length;
		random_access_indication = pref_random_access_indication;
		stream_state_indication = pref_stream_state_indication;
	} /* end if user_mode == TRUE */
	if (user_mode == FALSE) {
		switch (mode) {
			case AAC_HBR_MODE:
				au_size_length = 13;
				au_index_length = 3;
				au_index_delta_length = 3;
				cts_delta_length = 0;
				dts_delta_length = 0;
				random_access_indication = FALSE;
				stream_state_indication = 0;
				break;
			case MPEG4_VIDEO_MODE:
				au_size_length = 0;
				au_index_length = 0;
				au_index_delta_length = 0;
				cts_delta_length = 0;
				dts_delta_length = 22;
				random_access_indication = TRUE;
				stream_state_indication = 0;
				break;
			case AVC_VIDEO_MODE:
				au_size_length = 0;
				au_index_length = 0;
				au_index_delta_length = 0;
				cts_delta_length = 0;
				dts_delta_length = 22;
				random_access_indication = TRUE;
				stream_state_indication = 0;
				break;
			default:
				DISSECTOR_ASSERT_NOT_REACHED();
				break;
		} /* end switch */
	} /* end if user_mode == FALSE */

	/* navigate through buffer */
	{
		guint16 au_headers_length;     /* total length of AU headers */
		guint16 totalbits;             /* keeps track of total number of AU header bits treated (used to determine end of AU headers) */
		int deltabits;                 /* keeps track of extra bits per AU header treated (used to determine end of AU headers ) */
		offset_struct s_offset;
		offset_struct* poffset;
		guint16 nbmessage_bytes;       /*nb of message data bytes */
		s_offset.offset_bytes = 0;     /* initialise byte offset */
		s_offset.offset_bits  = 0;     /* initialise bit offset */
		poffset = &s_offset;

		ismacryp_item = proto_tree_add_item(tree, proto_ismacryp, tvb, 0, -1, ENC_NA);
		ismacryp_tree = proto_item_add_subtree(ismacryp_item, ett_ismacryp);
		proto_item_append_text(tree, ", %s", "ismacryp packet"); /* add text to tree */

		/* ismacryp_tree analysis */
		/* get total length of AU headers (first 2 bytes) */
		proto_tree_add_item(ismacryp_tree, hf_ismacryp_au_headers_length,
						    tvb, poffset->offset_bytes, AU_HEADERS_LENGTH_SIZE, ENC_BIG_ENDIAN );
		au_headers_length = tvb_get_ntohs(tvb, poffset->offset_bytes); /* 2 byte au headers length */
		poffset->offset_bytes += AU_HEADERS_LENGTH_SIZE;
		/* ADD HEADER(S) BRANCH  */

		/* AU Header loop */
		totalbits = (poffset->offset_bytes*8) + poffset->offset_bits;
		deltabits = 1;
		while( ((totalbits - 8*AU_HEADERS_LENGTH_SIZE)<au_headers_length) && deltabits != 0 ) /* subtract AU headers length bits*/
		{
			poffset = dissect_auheader( tvb, poffset, pinfo, ismacryp_tree, set_version);
			deltabits = (poffset->offset_bytes*8) + poffset->offset_bits - totalbits; /* if zero this means no actual AU header so exit while loop */
			totalbits += deltabits;
		}
		/* reached end of AU Header(s) */
		/* sanity check if actual total AU headers length in bits i.e. totalbits is */
		/*  the same as expected AU headers length from 2 bytes at start of buffer */
		if ( (totalbits - 8*AU_HEADERS_LENGTH_SIZE) != au_headers_length) /* something wrong */
		{
			proto_item_append_text(ismacryp_item,
					       " Error - expected total AU headers size (%d bits) "
					       "does not match calculated size (%d bits) - check parameters!",
					       au_headers_length, (totalbits - 8*AU_HEADERS_LENGTH_SIZE));
		}
		/* add padding if need to byte align */
		if (poffset->offset_bits != 0)
		{
			guint16 totalbit_offset;   /* total offset in bits*/
			int nbpadding_bits;        /* number of padding bits*/
			totalbit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
			nbpadding_bits = (8 - poffset->offset_bits); /* number of padding bits for byte alignment */
			ismacryp_item = proto_tree_add_bits_item(ismacryp_tree, hf_ismacryp_padding,
								 tvb, totalbit_offset, nbpadding_bits , ENC_BIG_ENDIAN); /* padding bits */
			proto_item_append_text(ismacryp_item, ": Length=%d bits", nbpadding_bits); /* add padding info */
			add_bits(poffset, nbpadding_bits);
		}
		/* ADD MESSAGE BRANCH  */
		ismacryp_item = proto_tree_add_item( ismacryp_tree, hf_ismacryp_message,
						     tvb, poffset->offset_bytes, -1, ENC_NA );
		ismacryp_message_tree = proto_item_add_subtree(ismacryp_item, ett_ismacryp_message);
		proto_item_append_text(ismacryp_item, ", %s", "Encrypted data"); /* add text to Message tree */
		nbmessage_bytes = tvb_reported_length_remaining(tvb, poffset->offset_bytes);
		proto_item_append_text(ismacryp_item, ", Length= %d bytes", nbmessage_bytes ); /* add length of message */

		/* ismacryp message tree analysis (encrypted AUs) */
		if (ismacryp_message_tree)
		{
			poffset->offset_bytes +=  nbmessage_bytes;	/* */
		}
	}
}
/* AU Header dissection */
static offset_struct* dissect_auheader( tvbuff_t *tvb, offset_struct *poffset, packet_info *pinfo, proto_tree *ismacryp_tree, guint set_version )
{
	proto_item *ismacryp_item;
	proto_tree *ismacryp_header_tree;
	proto_tree *ismacryp_header_byte_tree;

	guint16 header_len_bytes = 0; /* total length of non-first AU header in bytes (rounded up) */
	gint header_len = 0; /* length of AU headers in bits */
	gint cts_flag =0;
	gint dts_flag =0;
	gboolean first_au_flag = FALSE;
	gint bit_offset = 0;

	/*first determine total AU header length */
	/* calculate each AU header length in bits first */
	switch (set_version) {
		case V11:
			if (selective_encryption)
				header_len += 8; /* add one byte to header length */
			break;
		case V20:
			if (selective_encryption || slice_indication || padding_indication)
				header_len += 8; /* add one byte to header length */
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			break;
	}	/* end switch */
	header_len += au_size_length; /* add au size length */

	if (poffset->offset_bytes == AU_HEADERS_LENGTH_SIZE) {	/*first AU */
		header_len += 8*(iv_length);                      /* add IV length */
		header_len += 8*key_indicator_length;             /* add key indicator length */
		header_len += au_index_length;                    /* add AU index length */
		first_au_flag = TRUE;
	}
	else { /* not the first AU */
		if (key_indicator_per_au_flag == TRUE)
			header_len += 8*key_indicator_length; /* add key indicator length */
		header_len += 8*(delta_iv_length);                /* add delta IV length */
		header_len += au_index_delta_length;              /* add AU delta index length */
	}
	/* CTS flag is present? */
	if (cts_delta_length != 0) {    /* need to test whether cts_delta_flag is TRUE or FALSE */
		cts_flag = tvb_get_bits8(tvb, AU_HEADERS_LENGTH_SIZE*8 + header_len, 1); /*fetch 1 bit CTS flag  */
		header_len += 1;         /* add CTS flag bit */
		if (cts_flag == 1)
			header_len += cts_delta_length; /* add CTS delta length bits if CTS flag SET */
	}
	/* DTS flag is present? */
	if (dts_delta_length != 0) { /* need to test whether dts_delta_flag is TRUE or FALSE */
		dts_flag = tvb_get_bits8(tvb, AU_HEADERS_LENGTH_SIZE*8 + header_len, 1); /*fetch 1 bit DTS flag */
		header_len += 1;      /* add DTS flag bit */
		if (dts_flag == 1)
			header_len += dts_delta_length; /* add DTS delta length bits if DTS flag SET */
	}
	/* RAP flag present? */
	if (random_access_indication != FALSE)
		header_len += 1;      /* add 1 bit RAP flag */

	/* stream state indication present */
	if (stream_state_indication !=0)
		header_len += stream_state_indication; /* add stream state indication bits */

	/* convert header_len to bytes (rounded up) */
	if (header_len% 8 != 0)
	{
		header_len_bytes = ((header_len)/8) + 1; /*add 1 */
	}
	else
		header_len_bytes = ((header_len)/8);

	/* add AU header tree  */
	ismacryp_item = proto_tree_add_item(ismacryp_tree, hf_ismacryp_header, tvb, poffset->offset_bytes, header_len_bytes, ENC_NA );
	proto_item_append_text(ismacryp_item, ": Length=%d bits", header_len); /* add text to Header tree indicating length */
	/* sanity check if actual AU header length is zero bits, which indicates an error */
	if ( header_len == 0) /* something wrong */
	{
		proto_item_append_text(ismacryp_item, " Error - zero bit AU header size - check parameters!");
	}
	ismacryp_header_tree = proto_item_add_subtree(ismacryp_item, ett_ismacryp_header);

	/* ismacryp header analysis */

	/* Extra 1 Byte Header? */

	if ((set_version == V20 && (selective_encryption || slice_indication || padding_indication))
		|| (set_version == V11 && selective_encryption)) {

		/* add  header byte tree	*/
		ismacryp_item = proto_tree_add_item(ismacryp_header_tree, hf_ismacryp_header_byte,
						    tvb, poffset->offset_bytes, 1, ENC_NA );
		proto_item_append_text(ismacryp_item, ": Length=8 bits"); /* add text to Header byte tree indicating length */
		ismacryp_header_byte_tree = proto_item_add_subtree(ismacryp_item, ett_ismacryp_header_byte);

		/*ismacryp_header_byte_tree */
		/* tvb is network order, so get MSB bits first, so shift 8 bits and work "backwards" */
		add_bits(poffset, 7);   /*shift 7 bits to get correct bit */
		/* AU_is_encrypted bit */
		bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
		if (selective_encryption) { /* bit used */
			proto_tree_add_bits_item(ismacryp_header_byte_tree, hf_ismacryp_au_is_encrypted,
						 tvb, bit_offset, 1, ENC_BIG_ENDIAN); /*fetch 1 bit AU_is_encrypted */
		}
		else { /* bit unused */
			proto_tree_add_bits_item(ismacryp_header_byte_tree, hf_ismacryp_unused_bits,
						 tvb, bit_offset, 1, ENC_BIG_ENDIAN); /*fetch 1 bit unused */
		}
		switch (set_version) { /* ISMACryp version? */
			case V11:
				/* Reserved bits */
				add_bits(poffset, -7); /* move back 7 bits for reserved bits */
				bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
				proto_tree_add_bits_item(ismacryp_header_byte_tree, hf_ismacryp_reserved_bits,
							 tvb, bit_offset, 7, ENC_BIG_ENDIAN); /*fetch 7 bits reserved */
				add_bits(poffset, 8);   /* offset to next byte */
				break;
			case V20:
				/* Slice_start bit */
				add_bits(poffset, -1); /* move back 1 bit for slice_start */
				bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
				if (slice_indication) {
					proto_tree_add_bits_item(ismacryp_header_byte_tree, hf_ismacryp_slice_start,
								 tvb, bit_offset, 1, ENC_BIG_ENDIAN); /*fetch 1 bit slice_start */
				}
				else { /* bit unused */
					proto_tree_add_bits_item(ismacryp_header_byte_tree, hf_ismacryp_unused_bits,
								 tvb, bit_offset, 1, ENC_BIG_ENDIAN); /*fetch 1 bit unused */
				}
				add_bits(poffset, -1); /* move back 1 bit for slice_end */

				/* Slice_end bit */
				bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
				if (slice_indication) {
					proto_tree_add_bits_item(ismacryp_header_byte_tree, hf_ismacryp_slice_end,
								 tvb, bit_offset, 1, ENC_BIG_ENDIAN); /*fetch 1 bit Slice_end */
				}
				else { /* bit unused */
					proto_tree_add_bits_item(ismacryp_header_byte_tree, hf_ismacryp_unused_bits,
								 tvb, bit_offset, 1, ENC_BIG_ENDIAN); /*fetch 1 bit unused */
				}
				add_bits(poffset, -3); /* move back 3 bits for padding_bitcount */

				/* Padding_bitcount bits */
				bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
				if (padding_indication) {
					proto_tree_add_bits_item(ismacryp_header_byte_tree, hf_ismacryp_padding_bitcount,
								 tvb, bit_offset, 3, ENC_BIG_ENDIAN); /*fetch 3 bits padding_bitcount */
				}
				else { /* bits unused */
					proto_tree_add_bits_item(ismacryp_header_byte_tree, hf_ismacryp_unused_bits,
								 tvb, bit_offset, 3, ENC_BIG_ENDIAN); /*fetch 3 bits unused */
				}
				add_bits(poffset, -2); /* move back 2 bits for reserved bits */

				/* Reserved bits */
				bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
				proto_tree_add_bits_item(ismacryp_header_byte_tree, hf_ismacryp_reserved_bits,
							 tvb, bit_offset, 2, ENC_BIG_ENDIAN); /*fetch 2 bits reserved */
				add_bits(poffset, 8); /* offset to next byte */
				break;
			default:
				DISSECTOR_ASSERT_NOT_REACHED();
				break;
		} /* end switch set_version */
	} /* end selective encryption */
	/* IV */
	if (first_au_flag == TRUE && iv_length != 0)
	{
		ismacryp_item = proto_tree_add_item(ismacryp_header_tree, hf_ismacryp_iv, tvb, poffset->offset_bytes, iv_length, ENC_NA);
		proto_item_append_text(ismacryp_item, ": Length=%d bytes", iv_length); /* add IV info */
		col_append_fstr( pinfo->cinfo, COL_INFO,
			", IV=0x%s", tvb_bytes_to_str_punct(pinfo->pool, tvb, poffset->offset_bytes, iv_length, ' '));

		poffset->offset_bytes += iv_length; /* add IV length to offset_bytes */
	}
	/*Delta  IV */
	if (first_au_flag == FALSE && delta_iv_length != 0)
	{
		ismacryp_item = proto_tree_add_item(ismacryp_header_tree, hf_ismacryp_delta_iv,
						    tvb, poffset->offset_bytes, delta_iv_length, ENC_NA);
		proto_item_append_text(ismacryp_item, ": Length=%d bytes", delta_iv_length); /* add delta IV info */
		col_append_fstr( pinfo->cinfo, COL_INFO,
			", Delta IV=0x%s", tvb_bytes_to_str_punct(pinfo->pool, tvb, poffset->offset_bytes, delta_iv_length, ' '));
		poffset->offset_bytes += delta_iv_length; /* add IV length to offset_bytes */
	}
	/* Key Indicator */
	if ( key_indicator_length != 0 && ( first_au_flag == TRUE || key_indicator_per_au_flag == TRUE) )
	{
		/* (first AU or KI for each AU) and non-zero KeyIndicator size */
		ismacryp_item = proto_tree_add_item(ismacryp_header_tree, hf_ismacryp_key_indicator,
						    tvb, poffset->offset_bytes, key_indicator_length, ENC_NA);
		proto_item_append_text(ismacryp_item, ": Length=%d bytes", key_indicator_length); /* add KI info */
		col_append_fstr( pinfo->cinfo, COL_INFO,
					 ", KI=0x%s", tvb_bytes_to_str_punct(pinfo->pool, tvb, poffset->offset_bytes, key_indicator_length, ' '));
		poffset->offset_bytes += key_indicator_length; /* add KI length to offset_bytes */
	}
	/* AU size */
	if (au_size_length != 0) /* in bits */
	{
		bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
		ismacryp_item = proto_tree_add_bits_item(ismacryp_header_tree, hf_ismacryp_au_size,
							 tvb, bit_offset, au_size_length, ENC_BIG_ENDIAN);
		proto_item_append_text(ismacryp_item, " bytes: Length=%d bits", au_size_length); /* add AU size info */
		/*bit_offset += au_size_length;*/
		add_bits(poffset, au_size_length);
	}
	/* AU Index */
	if (first_au_flag == TRUE && au_index_length != 0) /* first AU and non-zero AU size */
	{
		bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
		ismacryp_item = proto_tree_add_bits_item(ismacryp_header_tree, hf_ismacryp_au_index,
							 tvb, bit_offset, au_index_length, ENC_BIG_ENDIAN);
		proto_item_append_text(ismacryp_item, " bits: Length=%d bits", au_index_length); /* add AU index info */
		/*bit_offset += au_index_length;*/
		add_bits(poffset, au_index_length);
	}
	/* AU index delta */
	if (first_au_flag == FALSE && au_index_delta_length != 0) /* not first AU and non-zero AU delta size */
	{
		bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
		ismacryp_item = proto_tree_add_bits_item(ismacryp_header_tree, hf_ismacryp_au_index_delta,
							 tvb, bit_offset, au_index_delta_length, ENC_BIG_ENDIAN);
		proto_item_append_text(ismacryp_item, ": Length=%d bits", au_index_delta_length); /* add AU index info */
		/*bit_offset += au_index_delta_length;*/
		add_bits(poffset, au_index_delta_length);
	}
	/* CTS delta value */
	if (cts_delta_length != 0)
	{
		bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
		proto_tree_add_bits_item(ismacryp_header_tree, hf_ismacryp_cts_flag,
					 tvb, bit_offset, 1, ENC_BIG_ENDIAN); /* read CTS flag */
		add_bits(poffset, 1);
		if (cts_flag == 1)
		{
			/* now fetch CTS delta value (remember offset 1 bit due to CTS flag) */
			bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
			ismacryp_item = proto_tree_add_bits_item(ismacryp_header_tree, hf_ismacryp_cts_delta,
								 tvb, bit_offset, cts_delta_length, ENC_BIG_ENDIAN); /* read CTS delta value */
			proto_item_append_text(ismacryp_item, ": Length=%d bits", cts_delta_length); /* add CTS delta info */
			add_bits(poffset, cts_delta_length);
		}
	}
	/* DTS delta value */
	if (dts_delta_length != 0)
	{
		bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
		proto_tree_add_bits_item(ismacryp_header_tree, hf_ismacryp_dts_flag,
					 tvb, bit_offset, 1, ENC_BIG_ENDIAN); /* read DTS flag */
		add_bits(poffset, 1);

		/* now fetch DTS delta value (remember offset x bits due to DTS flag) */
		if (dts_flag ==1)
		{
			bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
			ismacryp_item = proto_tree_add_bits_item(ismacryp_header_tree, hf_ismacryp_dts_delta,
								 tvb, bit_offset, dts_delta_length, ENC_BIG_ENDIAN); /* read DTS delta value */
			proto_item_append_text(ismacryp_item, ": Length=%d bits", dts_delta_length); /* add DTS delta info */
			add_bits(poffset, dts_delta_length);
		}
	}
	/* RAP */
	if (random_access_indication != FALSE)
	{
		bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
		proto_tree_add_bits_item(ismacryp_header_tree, hf_ismacryp_rap_flag,
					 tvb, bit_offset, 1, ENC_BIG_ENDIAN); /* read RAP flag */
		add_bits(poffset, 1);
	}
	/*STREAM STATE */
	if (stream_state_indication != 0)
	{
		bit_offset = (poffset->offset_bytes)*8 + poffset->offset_bits; /* offset in bits */
		proto_tree_add_bits_item(ismacryp_header_tree, hf_ismacryp_stream_state,
					 tvb, bit_offset, stream_state_indication, ENC_BIG_ENDIAN); /* read stream state */
		add_bits(poffset, stream_state_indication);
	}
return poffset;
}

/* add len_bits to offset bits and  bytes, handling bits overflow */
static void add_bits(offset_struct* poffset, gint len_bits)
{
	gint nbbitstotal;
	nbbitstotal = poffset->offset_bytes*8 + (poffset->offset_bits) + len_bits; /* total offset in bits */
	/* now calculate bytes and bit offsets */
	poffset->offset_bytes = (nbbitstotal / 8); /* add integer no. of bytes */
	poffset->offset_bits  = (nbbitstotal % 8); /* add remaining bits */
}

void proto_register_ismacryp (void)
{
	/* A header field is something you can search/filter on.
	*
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/
	static hf_register_info hf[] = {
#if 0
		{ &hf_ismacryp,
		  { "Data", "ismacryp.data", FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
#endif

#if 0
		{ &hf_ismacryp_length,
		  { "Total Length", "ismacryp.len", FT_UINT16, BASE_DEC, NULL, 0x0,	/* length 2 bytes, print as decimal value */
		    NULL, HFILL }},
#endif

		{ &hf_ismacryp_header,
		  { "AU Header", "ismacryp.header", FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

#if 0
		{ &hf_ismacryp_header_length,
		  { "Header Length", "ismacryp.header.length", FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
#endif

		{ &hf_ismacryp_au_headers_length,
		  { "AU Headers Length", "ismacryp.au_headers.length", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_bit_bits, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_header_byte,
		  { "Header Byte", "ismacryp.header.byte", FT_NONE, BASE_NONE, NULL, 0x0, /* 1 byte */
		    NULL, HFILL }},

#if 0
		{ &hf_ismacryp_version,
		  { "Version", "ismacryp.version", FT_UINT8, BASE_HEX, NULL, 0x0, 	/* version 1 byte */
		    NULL, HFILL }},
#endif

		{ &hf_ismacryp_message,
		  { "Message", "ismacryp.message", FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

#if 0
		{ &hf_ismacryp_message_length,
		  { "Message Length", "ismacryp.message.len", FT_UINT16, BASE_DEC, NULL, 0x0,	/* length 2 bytes, print as decimal value */
		    NULL, HFILL }},
#endif

#if 0
		{ &hf_ismacryp_parameter,
		  { "Parameter", "ismacryp.parameter", FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
#endif

#if 0
		{ &hf_ismacryp_parameter_length,
		  { "Parameter Length", "ismacryp.parameter.len", FT_UINT16, BASE_DEC, NULL, 0x0, /* length 2 bytes, print as decimal value */
		    NULL, HFILL }},
#endif

		{ &hf_ismacryp_iv,
		  { "IV", "ismacryp.iv", FT_BYTES, BASE_NONE, NULL, 0x0, /* variable length */
		    NULL, HFILL }},

		{ &hf_ismacryp_delta_iv,
		  { "Delta IV", "ismacryp.delta_iv", FT_BYTES, BASE_NONE, NULL, 0x0, /* variable length */
		    NULL, HFILL }},

		{ &hf_ismacryp_key_indicator,
		  { "Key Indicator", "ismacryp.key_indicator", FT_BYTES, BASE_NONE, NULL, 0x0, /* variable length */
		    NULL, HFILL }},

#if 0
		{ &hf_ismacryp_parameter_value,
		  { "Parameter Value", "ismacryp.parameter.value", FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
#endif

		{ &hf_ismacryp_au_size,
		  { "AU size", "ismacryp.au.size", FT_UINT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_au_index,
		  { "AU index", "ismacryp.au.index", FT_UINT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_au_index_delta,
		  { "AU index delta", "ismacryp.au.index_delta", FT_UINT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_cts_delta,
		  { "CTS delta", "ismacryp.cts_delta", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_cts_flag,
		  { "CTS flag", "ismacryp.cts_flag", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_dts_delta,
		  { "DTS delta", "ismacryp.dts_delta", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_dts_flag,
		  { "DTS flag", "ismacryp.dts_flag", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_rap_flag,
		  { "RAP flag", "ismacryp.rap_flag", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_stream_state,
		  { "Stream state", "ismacryp.stream_state", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_au_is_encrypted,
		  { "AU_is_encrypted flag", "ismacryp.au_is_encrypted", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_slice_start,
		  { "Slice_start flag", "ismacryp.slice_start", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_slice_end,
		  { "Slice_end flag", "ismacryp.slice_end", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_padding_bitcount,
		  { "Padding_bitcount bits", "ismacryp.padding_bitcount", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_padding,
		  { "Padding bits", "ismacryp.padding", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_reserved_bits,
		  { "Reserved bits", "ismacryp.reserved", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_ismacryp_unused_bits,
		  { "Unused bits", "ismacryp.unused", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }}
	};

	static gint *ett[] =
	{
		&ett_ismacryp,
		&ett_ismacryp_header,
		&ett_ismacryp_header_byte,
		&ett_ismacryp_message
	};

	static const enum_val_t version_types[] = {
		{PROTO_TAG_ISMACRYP_11, "ISMACryp v1.1", V11},
		{PROTO_TAG_ISMACRYP_20, "ISMACryp v2.0", V20},
		{NULL, NULL, -1}
	};

	static const enum_val_t mode_types[] = {
		{"aac-hbr", "aac-hbr", AAC_HBR_MODE},
		{"mpeg4-video", "mpeg4-video", MPEG4_VIDEO_MODE},
		{"avc-video", "avc-video", AVC_VIDEO_MODE},
		{NULL, NULL, -1}
	};

	module_t *ismacryp_module;

	proto_ismacryp = proto_register_protocol ("ISMACryp Protocol", "ISMACRYP", "ismacryp");
	proto_ismacryp_v11 = proto_register_protocol_in_name_only ("ISMACryp Protocol v1.1",
			"ISMACRYP 1.1", "ismacryp_v11", proto_ismacryp, FT_PROTOCOL);
	proto_ismacryp_v20 = proto_register_protocol_in_name_only ("ISMACryp Protocol v2.0",
			"ISMACRYP 2.0", "ismacryp_v20", proto_ismacryp, FT_PROTOCOL);
	proto_register_field_array (proto_ismacryp, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));

	/* Register our configuration options for ismacryp */
	ismacryp_module = prefs_register_protocol(proto_ismacryp, NULL);

	prefs_register_obsolete_preference(ismacryp_module, "dynamic.payload.type");

	prefs_register_enum_preference(ismacryp_module, "version",
					       "ISMACryp version",
					       "ISMACryp version",
					       &version_type, version_types, TRUE);

	prefs_register_static_text_preference(ismacryp_module, "text_override",
					      "The following option allows the version to be set manually"
					      " and to override the version if detected from RTP payload type:",
					      "The following option allows the version to be set manually"
					      " and to override the version if detected from RTP payload type:");

	prefs_register_bool_preference(ismacryp_module,
				       "override_rtp_pt", "Override RTP payload type for version",
				       "Indicates whether or not the ISMACryp version deduced"
				       " from RTP payload type, if present, is used or whether the"
				       " version above is used",
				       &override_flag);

	/* ISMACryp v11 parameters */
	prefs_register_static_text_preference(ismacryp_module,
					      "v11_parameters",
					      "ISMACryp v1.1 parameters:",
					      "ISMACryp v1.1 parameters declared in SDP");

	prefs_register_uint_preference(ismacryp_module,
				       "iv_length", "ISMACrypIVLength (bytes)",
				       "Set the length of the IV in the ISMACryp AU Header in bytes",
				       10, &iv_length);

	prefs_register_uint_preference(ismacryp_module,
				       "delta_iv_length", "ISMACrypDeltaIVLength (bytes)",
				       "Set the length of the Delta IV in the ISMACryp AU Header in bytes",
				       10, &delta_iv_length);

	prefs_register_uint_preference(ismacryp_module,
				       "key_indicator_length", "ISMACrypKeyIndicatorLength (bytes)",
				       "Set the length of the Key Indicator in the ISMACryp AU Header in bytes",
				       10, &key_indicator_length);

	prefs_register_bool_preference(ismacryp_module,
				       "key_indicator_per_au_flag", "ISMACrypKeyIndicatorPerAU (T/F)",
				       "Indicates whether or not the Key Indicator is present in all AU Headers (T/F)",
				       &key_indicator_per_au_flag);

	prefs_register_bool_preference(ismacryp_module,
				       "selective_encryption", "ISMACrypSelectiveEncryption (T/F)",
				       "Indicates whether or not selective encryption is enabled (T/F)",
				       &selective_encryption);

	/* ISMACryp v20 parameters */
	prefs_register_static_text_preference(ismacryp_module,
					      "v20_parameters",
					      "ISMACryp v2.0 parameters:",
					      "ISMACryp v2.0 parameters declared in SDP");

	prefs_register_bool_preference(ismacryp_module,
				       "slice_indication", "ISMACrypSliceIndication (T/F)",
				       "Indicates whether or not slice start / end is present (T/F)",
				       &slice_indication);

	prefs_register_bool_preference(ismacryp_module,
				       "padding_indication", "ISMACrypPaddingIndication (T/F)",
				       "Indicates whether or not padding information is present (T/F)",
				       &padding_indication);

	/* RFC3640 mode - ISMACryp v11 */
	prefs_register_static_text_preference(ismacryp_module,
					      "codec_modes",
					      "Codec mode selection (RFC3640 for ISMACryp v1.1 only):",
					      "AU parameters set according to RFC3640 mode or user defined");

	prefs_register_enum_preference(ismacryp_module,
				       "rfc3640_mode",
				       "RFC3640 mode",
				       "RFC3640 mode",
				       &mode, mode_types, TRUE);

	/* User defined mode */
	prefs_register_bool_preference(ismacryp_module,
				       "user_mode", "User mode (T/F)",
				       "Indicates use of user mode instead of RFC3640 modes (T/F)",
				       &pref_user_mode);

	/* following preference values only used if user mode is selected above */
	prefs_register_static_text_preference(ismacryp_module,
					      "user_defined_modes",
					      "Following parameters only valid and used for user mode:",
					      "AU parameters defined by the user");

	/* ideally would grey this out or disable this if in user mode */
	prefs_register_uint_preference(ismacryp_module,
				       "au_size_length", "User mode: SizeLength (bits)",
				       "Set the length of the AU size in the AU Header in bits",
				       10, &pref_au_size_length);

	prefs_register_uint_preference(ismacryp_module,
				       "au_index_length", "User mode: IndexLength (bits)",
				       "Set the length of the AU index in the AU Header in bits",
				       10, &pref_au_index_length);

	prefs_register_uint_preference(ismacryp_module,
				       "au_index_delta_length", "User mode: IndexDeltaLength (bits)",
				       "Set the length of the AU delta index in the AU Header in bits",
				       10, &pref_au_index_delta_length);

	prefs_register_uint_preference(ismacryp_module,
				       "cts_delta_length", "User mode: CTSDeltaLength (bits)",
				       "Set the length of the CTS delta field in the AU Header in bits",
				       10, &pref_cts_delta_length);

	prefs_register_uint_preference(ismacryp_module,
				       "dts_delta_length", "User mode: DTSDeltaLength (bits)",
				       "Set the length of the DTS delta field in the AU Header in bits",
				       10, &pref_dts_delta_length);

	prefs_register_bool_preference(ismacryp_module,
				       "random_access_indication", "User mode: RandomAccessIndication (T/F)",
				       "Indicates whether or not the RAP field is present in the AU Header (T/F)",
				       &pref_random_access_indication);

	prefs_register_uint_preference(ismacryp_module,
				       "stream_state_indication", "User mode: StreamStateIndication (number of bits)",
				       "Indicates the number of bits on which the stream state field is encoded"
				       " in the AU Header (bits)",
				       10, &pref_stream_state_indication);

}

void proto_reg_handoff_ismacryp(void)
{
	dissector_handle_t ismacryp_handle;
	dissector_handle_t ismacryp_v11_handle;
	dissector_handle_t ismacryp_v20_handle;

	ismacryp_handle = create_dissector_handle(dissect_ismacryp, proto_ismacryp);
	ismacryp_v11_handle = create_dissector_handle(dissect_ismacryp_v11, proto_ismacryp_v11);
	ismacryp_v20_handle = create_dissector_handle(dissect_ismacryp_v20, proto_ismacryp_v20);
	dissector_add_string("rtp_dyn_payload_type", "ISMACRYP", ismacryp_handle);
	dissector_add_string("rtp_dyn_payload_type", "enc-mpeg4-generic", ismacryp_v11_handle);
	dissector_add_string("rtp_dyn_payload_type", "enc-isoff-generic", ismacryp_v20_handle);
	dissector_add_uint_range_with_preference("rtp.pt", "", ismacryp_handle);

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
