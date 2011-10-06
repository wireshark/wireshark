/* packet-icep.c
 * Routines for "The ICE Protocol" dissection
 * Copyright 2004 _FF_
 * Francesco Fondelli <fondelli dot francesco, tiscali dot it>
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

/*
  TODO:
  1) Dissect encoded data (do sth like idl2wrs for CORBA).
  2) Add conversations.
  3) Register a dissector as one that can be selected by a UDP/TCP port number.
  4) Put in Preferences/Protocols/ICEP Option menu:
      - ICEP_MAX_ICE_STRING_LEN
      - ICEP_MAX_BATCH_REQUESTS
      - ICEP_MAX_ICE_CONTEXT_PAIRS
*/

/*
  NOTES:
  1) p. 586 Chapter 23.2 of "The ICE Protocol"
     "Data is always encoded using little-endian byte order for numeric types."
  2) Informations about Ice can be found here: http://www.zeroc.com
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include "packet-tcp.h"

#if 0
#define DBG(str, args...)       do {\
                                        fprintf(stdout, \
                                        "[%s][%s][%d]: ",\
                                        __FILE__, \
                                        __FUNCTION__, \
                                        __LINE__); \
                                        fflush(stdout); \
                                        fprintf(stdout, str, ## args); \
                                } while (0)
#else
#define DBG0(format)
#define DBG1(format, arg1)
#define DBG2(format, arg1, arg2)
#endif /* 0/1 */

/* fixed values taken from the standard */
static const guint8 icep_magic[] = { 'I', 'c', 'e', 'P' };
#define ICEP_HEADER_SIZE			14
#define ICEP_MIN_REPLY_SIZE			5
#define ICEP_MIN_PARAMS_SIZE			6
#define ICEP_MIN_COMMON_REQ_HEADER_SIZE		13

/* values derived from common sense */
#define ICEP_MAX_BATCH_REQUESTS			64
#define ICEP_MAX_ICE_STRING_LEN			512
#define ICEP_MAX_ICE_CONTEXT_PAIRS		64


/* Initialize the protocol and registered fields */
static int proto_icep = -1;

/* Message Header */
static int hf_icep_protocol_major = -1;
static int hf_icep_protocol_minor = -1;
static int hf_icep_encoding_major = -1;
static int hf_icep_encoding_minor = -1;
static int hf_icep_message_type = -1;
static int hf_icep_compression_status = -1;
static int hf_icep_message_size = -1;

/* [Batch] Request Message Body */
static int hf_icep_request_id = -1;
static int hf_icep_id_name = -1;
static int hf_icep_id_category = -1;
static int hf_icep_facet = -1;
static int hf_icep_operation = -1;
static int hf_icep_mode = -1;
static int hf_icep_context = -1;
static int hf_icep_params_size = -1;
static int hf_icep_params_major = -1;
static int hf_icep_params_minor = -1;

/* Reply Message Body */
static int hf_icep_reply_status = -1;

/* Initialize the subtree pointers */
static gint ett_icep = -1;
static gint ett_icep_msg = -1;

static const value_string icep_msgtype_vals[] = {
	{0x0, "Request"},
	{0x1, "Batch request"},
	{0x2, "Reply"},
	{0x3, "Validate connection"},
	{0x4, "Close connection"},
	{0, NULL}
};

static const value_string icep_zipstatus_vals[] = {
	{0x0, "Uncompressed, sender cannot accept a compressed reply"},
	{0x1, "Uncompressed, sender can accept a compressed reply"},
	{0x2, "Compressed, sender can accept a compressed reply"},
	{0, NULL}
};

static const value_string icep_replystatus_vals[] = {
	{0x0, "Success"},
	{0x1, "User exception"},
	{0x2, "Object does not exist"},
	{0x3, "Facet does not exist"},
	{0x4, "Operation does not exist"},
	{0x5, "Unknown Ice local exception"},
	{0x6, "Unknown Ice user exception"},
	{0x7, "Unknown exception"},
	{0, NULL}
};

static const value_string icep_mode_vals[] = {
	{0x0, "normal"},
	{0x1, "nonmutating"},
	{0x2, "idempotent"},
	{0, NULL}
};

static packet_info *mypinfo;



/*
 * This function dissects an "Ice string", adds hf to "tree" and returns consumed
 * bytes in "*consumed", if errors "*consumed" is -1.
 *
 * "*dest" is a null terminated version of the dissected Ice string.
 */
static void dissect_ice_string(proto_tree *tree, int hf_icep,
			       tvbuff_t *tvb, guint32 offset, gint32 *consumed,
			       char **dest, gboolean add_hf)
{
	/* p. 586 chapter 23.2.1 and p. 588 chapter 23.2.5
	 * string == Size + content
	 * string = 1byte (0..254) + string not null terminated
	 * or
	 * string = 1byte (255) + 1int (255..2^32-1) + string not null terminated
	 */

	guint32 Size = 0;
	char *s = NULL;

	(*consumed) = 0;

	/* check for first byte */
	if ( !tvb_bytes_exist(tvb, offset, 1) ) {

		if (tree)
			proto_tree_add_text(tree, tvb, offset, -1,
					    "1st byte of Size missing");

		col_append_str(mypinfo->cinfo, COL_INFO,
				       " (1st byte of Size missing)");

		(*consumed) = -1;
		return;
	}

	/* get the Size */
	Size = tvb_get_guint8(tvb, offset);
	offset++;
	(*consumed)++;

	if ( Size == 255 ) {

		/* check for next 4 bytes */
		if ( !tvb_bytes_exist(tvb, offset, 4) ) {

			if (tree)
				proto_tree_add_text(tree, tvb, offset, -1,
						    "second field of Size missing");

			col_append_str(mypinfo->cinfo, COL_INFO,
					       " (second field of Size missing)");

			(*consumed) = -1;
			return;
		}

		/* get second field of Size */
		Size = tvb_get_letohl(tvb, offset);
		offset += 4;
		(*consumed) += 4;
	}

	DBG1("string.Size --> %d\n", Size);

	/* check if the string exists */
	if ( !tvb_bytes_exist(tvb, offset, Size) ) {

		if (tree)
			proto_tree_add_text(tree, tvb, offset, -1,
					    "missing or truncated string");

		col_append_str(mypinfo->cinfo, COL_INFO,
				       " (missing or truncated string)");

		(*consumed) = -1;
		return;
	}

	if ( Size > ICEP_MAX_ICE_STRING_LEN ) {

		if (tree)
			proto_tree_add_text(tree, tvb, offset, -1, "string too long");

		col_append_str(mypinfo->cinfo, COL_INFO,
				       " (string too long)");

		(*consumed) = -1;
		return;
	}



	if ( Size != 0 ) {
		s = tvb_get_ephemeral_string(tvb, offset, Size);
		if (tree && add_hf)
			proto_tree_add_string(tree, hf_icep, tvb, offset, Size, s);
	} else {
		s = g_strdup("(empty)");
		/* display the 0x00 Size byte when click on a empty ice_string */
		if (tree && add_hf)
			proto_tree_add_string(tree, hf_icep, tvb, offset - 1, 1, s);
	}

	if ( dest != NULL )
		*dest = s;

	offset += Size;
	(*consumed) += Size;
	return;
}

/*
 * This function dissects an "Ice facet", adds hf(s) to "tree" and returns consumed
 * bytes in "*consumed", if errors "*consumed" is -1.
 */
static void dissect_ice_facet(proto_tree *tree, int hf_icep,
			      tvbuff_t *tvb, guint32 offset, gint32 *consumed)
{
	/*  p. 588, chapter 23.2.6:
	 *  "facet" is a StringSeq, a StringSeq is a:
	 *  sequence<string>
	 *
	 *
	 * sequence == Size + SizeElements
	 * sequence = 1byte (0..254) + SizeElements
	 * or
	 * sequence = 1byte (255) + 1int (255..2^32-1) + SizeElements
	 *
	 *
	 * p.613. chapter 23.3.2
	 * "facet has either zero elements (empty) or one element"
	 *
	 *
	 */

	guint32 Size = 0; /* number of elements in the sequence */
	char *s = NULL;

	(*consumed) = 0;

	/* check first byte */
	if ( !tvb_bytes_exist(tvb, offset, 1) ) {

		if (tree)
			proto_tree_add_text(tree, tvb, offset, -1, "facet field missing");

		col_append_str(mypinfo->cinfo, COL_INFO,
				       " (facet field missing)");

		(*consumed) = -1;
		return;
	}

	/* get first byte of Size */
	Size = tvb_get_guint8(tvb, offset);
	offset++;
	(*consumed)++;

	if ( Size == 0 ) {

		if (tree) {
			s = ep_strdup( "(empty)" );
			/* display the 0x00 Size byte when click on a empty ice_string */
			proto_tree_add_string(tree, hf_icep, tvb, offset - 1, 1, s);
		}
		return;
	}

	if ( Size == 1 ) {

		gint32 consumed_facet = 0;

		dissect_ice_string(tree, hf_icep, tvb, offset, &consumed_facet, NULL, TRUE);

		if ( consumed_facet == -1 ) {
			(*consumed) = -1;
			return;
		}

		offset += consumed_facet;
		(*consumed) += consumed_facet;
		return;
	}

	/* if here => Size > 1 => not possible */

	if (tree)
		/* display the XX Size byte when click here */
		proto_tree_add_text(tree, tvb, offset - 1, 1,
				    "facet can be max one element");

	col_append_str(mypinfo->cinfo, COL_INFO,
			       " (facet can be max one element)");

	(*consumed) = -1;
	return;
}

/*
 * This function dissects an "Ice context", adds hf(s) to "tree" and returns consumed
 * bytes in "*consumed", if errors "*consumed" is -1.
 */
static void dissect_ice_context(proto_tree *tree, tvbuff_t *tvb, guint32 offset,
				gint32 *consumed)
{
	/*  p. 588, chapter 23.2.7 and p. 613, 23.3.2:
	 *  "context" is a dictionary<string, string>
	 *
	 * dictionary<string, string> == Size + SizeKeyValuePairs
	 * dictionary<string, string> = 1byte (0..254) + SizeKeyValuePairs
	 * or
	 * dictionary<string, string>= 1byte (255) + 1int (255..2^32-1)+SizeKeyValuePairs
	 *
	 */

	guint32 Size = 0; /* number of key-value in the dictionary */
	guint32 i = 0;
	const char *s = NULL;

	(*consumed) = 0;

	/* check first byte */
	if ( !tvb_bytes_exist(tvb, offset, 1) ) {

		if (tree)
			proto_tree_add_text(tree, tvb, offset, -1, "context missing");

		col_append_str(mypinfo->cinfo, COL_INFO,
				       " (context missing)");

		(*consumed) = -1;
		return;
	}

	/* get first byte of Size */
	Size = tvb_get_guint8(tvb, offset);
	offset++;
	(*consumed)++;

	if ( Size == 255 ) {

		/* check for next 4 bytes */
		if ( !tvb_bytes_exist(tvb, offset, 4) ) {

			if (tree)
				proto_tree_add_text(tree, tvb, offset, -1,
						    "second field of Size missing");

			col_append_str(mypinfo->cinfo, COL_INFO,
					       " (second field of Size missing)");

			(*consumed) = -1;
			return;
		}

		/* get second field of Size */
		Size = tvb_get_letohl(tvb, offset);
		offset += 4;
		(*consumed) += 4;
	}

	DBG1("context.Size --> %d\n", Size);

	if ( Size > ICEP_MAX_ICE_CONTEXT_PAIRS ) {

		if (tree)
			/* display the XX Size byte when click here */
			proto_tree_add_text(tree, tvb, offset - 1, 1, "too long context");

		col_append_str(mypinfo->cinfo, COL_INFO,
				       " (too long context)");

		(*consumed) = -1;
		return;
	}

	if (Size == 0) {
		s = "(empty)";
		/* display the 0x00 Size byte when click on a empty context */
		if (tree)
			proto_tree_add_string(tree, hf_icep_context, tvb, offset - 1, 1, s);
		return;
	}

	/* looping through the dictionary */
	for ( i = 0; i < Size; i++ ) {
		/* key */
		gint32 consumed_key = 0;
		char *str_key = NULL;
		/* value */
		gint32 consumed_value = 0;
		char *str_value = NULL;


		DBG1("looping through context dictionary, loop #%d\n", i);

		dissect_ice_string(tree, -1, tvb, offset, &consumed_key,
				   &str_key, FALSE);

		if ( consumed_key == -1 ) {
			(*consumed) = -1;
			return;
		}

		offset += consumed_key;
		(*consumed) += consumed_key;

		dissect_ice_string(tree, -1, tvb, offset, &consumed_value,
				   &str_value, FALSE);

		if ( consumed_value == -1 ) {
			(*consumed) = -1;
			return;
		}

		offset += consumed_value;
		(*consumed) += consumed_value;

		if (tree && str_value && str_key) {

			proto_tree_add_text(tree, tvb,
					    offset - (consumed_key + consumed_value) - 1,
					    (consumed_key + consumed_value) + 1,
					    "Invocation Context: %s/%s",
					    str_key, str_value);
		}

	}
}

/*
 * This function dissects an "Ice params", adds hf(s) to "tree" and returns consumed
 * bytes in "*consumed", if errors "*consumed" is -1.
 */
static void dissect_ice_params(proto_tree *tree, tvbuff_t *tvb,
			       guint32 offset, gint32 *consumed)
{
	/*  p. 612, chapter 23.3.2 and p. 587, 23.2.2:
	 *  "params" is an Encapsulation
	 *
	 *  struct Encapsulation {
	 *  	int size;
	 *  	byte major;
	 *      byte minor;
	 *      //(size - 6) bytes of data
	 *  }
	 *
	 */

	gint32 size = 0;
	gint tvb_data_remained = 0;

	(*consumed) = 0;

	/* check first 6 bytes */
	if ( !tvb_bytes_exist(tvb, offset, ICEP_MIN_PARAMS_SIZE) ) {

		if (tree)
			proto_tree_add_text(tree, tvb, offset, -1, "params missing");

		col_append_str(mypinfo->cinfo, COL_INFO,
				       " (params missing)");

		(*consumed) = -1;
		return;
	}

	/* get the size */
	size = tvb_get_letohl(tvb, offset);

	DBG1("params.size --> %d\n", size);

	if ( size < ICEP_MIN_PARAMS_SIZE ) {

		if (tree)
			proto_tree_add_text(tree, tvb, offset, 4,
					    "params size too small");

		col_append_str(mypinfo->cinfo, COL_INFO,
				       " (params size too small)");

		(*consumed) = -1;
		return;
	}

	if ( tree ) {

		proto_tree_add_item(tree, hf_icep_params_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		(*consumed) += 4;

		proto_tree_add_item(tree, hf_icep_params_major, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		(*consumed)++;

		proto_tree_add_item(tree, hf_icep_params_minor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		(*consumed)++;

	} else {
		/* skipp size, major, minor */
		offset += 6;
		(*consumed) += 6;
	}

	if( size == ICEP_MIN_PARAMS_SIZE ) /* no encapsulatd data present, it's normal */
		return;

	/* check if I got all encapsulated data */
	tvb_data_remained = tvb_reported_length_remaining(tvb, offset);

	if ( tvb_data_remained < ( size - ICEP_MIN_PARAMS_SIZE ) ) {

		if (tree)
			proto_tree_add_text(tree, tvb, offset, -1,
					    "missing encapsulated data (%d bytes)",
					    size
					    - ICEP_MIN_PARAMS_SIZE
					    - tvb_data_remained);

		if ( check_col(mypinfo->cinfo, COL_INFO) ) {
			col_append_fstr(mypinfo->cinfo, COL_INFO,
					" (missing encapsulated data (%d bytes))",
					size
					- ICEP_MIN_PARAMS_SIZE
					- tvb_data_remained);
		}

		(*consumed) = -1;
		return;
	}

	/* encapsulated params */

	if (tree) {
		proto_tree_add_text(tree, tvb, offset, (size - ICEP_MIN_PARAMS_SIZE),
				    "Encapsulated parameters (%d bytes)",
				    (size - ICEP_MIN_PARAMS_SIZE));
	}

	(*consumed) += (size - ICEP_MIN_PARAMS_SIZE);
}

static void dissect_icep_request_common(tvbuff_t *tvb, guint32 offset,
					proto_tree *icep_sub_tree, gint32 *total_consumed)
{
	/*  p. 613, chapter 23.3.3 and p. 612 chapter 23.3.2:
	 *  Request and BatchRequest differ only in the first 4 bytes (requestID)
	 *  so them share this part
	 *
	 *	 Ice::Identity id;
	 *	 Ice::StringSeq facet;
	 *	 string operation;
	 *	 byte mode;
	 *	 Ice::Context context;
	 *	 Encapsulation params;
	 *  }
	 */

	gint32 consumed = 0;
	char *namestr = NULL;
	char *opstr = NULL;

	(*total_consumed) = 0;

	/* check common header (i.e. the batch request one)*/
	if ( !tvb_bytes_exist(tvb, offset, ICEP_MIN_COMMON_REQ_HEADER_SIZE) ) {

		if (icep_sub_tree)
			proto_tree_add_text(icep_sub_tree, tvb, offset, -1,
					    "too short header");

		col_append_str(mypinfo->cinfo, COL_INFO,
				       " (too short header)");

		goto error;
	}

	/* got at least 15 bytes */

	/*  "id" is a:
	 *  struct Identity {
	 *      string name;
	 *	string category;
	 *  }
	 */

	dissect_ice_string(icep_sub_tree, hf_icep_id_name, tvb, offset,
			   &consumed, &namestr, TRUE);

	if ( consumed == -1 )
		goto error;

	offset += consumed; DBG1("consumed --> %d\n", consumed);
	(*total_consumed) += consumed;


	dissect_ice_string(icep_sub_tree, hf_icep_id_category, tvb, offset,
			   &consumed, NULL, TRUE);

	if ( consumed == -1 )
		goto error;

	offset += consumed; DBG1("consumed --> %d\n", consumed);
	(*total_consumed) += consumed;


	/*  "facet" is a:
	 *  sequence<string> StringSeq
	 *
	 */

	dissect_ice_facet(icep_sub_tree, hf_icep_facet, tvb, offset, &consumed);

	if ( consumed == -1 )
		goto error;

	offset += consumed; DBG1("consumed --> %d\n", consumed);
	(*total_consumed) += consumed;

	/*  "operation" is an ice_string
	 *
	 */

	dissect_ice_string(icep_sub_tree, hf_icep_operation, tvb, offset,
			   &consumed, &opstr, TRUE);

	if ( consumed == -1 )
		goto error;
	else {
		offset += consumed; DBG1("consumed --> %d\n", consumed);
		(*total_consumed) += consumed;

		if ( opstr && namestr ) {
			DBG2("operation --> %s.%s()\n", namestr, opstr);
			if ( check_col(mypinfo->cinfo, COL_INFO) ) {
				col_append_fstr(mypinfo->cinfo, COL_INFO, " %s.%s()",
						namestr, opstr);
			}
			opstr = NULL;
			namestr = NULL;
		}
	}

	/* check and get mode byte */
	if ( !tvb_bytes_exist(tvb, offset, 1) ) {

		if (icep_sub_tree)
			proto_tree_add_text(icep_sub_tree, tvb, offset, -1,
					    "mode field missing");

		col_append_str(mypinfo->cinfo, COL_INFO,
				       " (mode field missing)");

		goto error;
	}

	if (icep_sub_tree)
		proto_tree_add_item(icep_sub_tree, hf_icep_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);

	offset++; DBG0("consumed --> 1\n");
	(*total_consumed)++;


	/*  "context" is a dictionary<string, string>
	 *
	 */

	dissect_ice_context(icep_sub_tree, tvb, offset, &consumed);

	if ( consumed == -1 )
		goto error;

	offset += consumed; DBG1("consumed --> %d\n", consumed);
	(*total_consumed) += consumed;

	/*  "params" is a Encapsulation
	 *
	 */

	dissect_ice_params(icep_sub_tree, tvb, offset, &consumed);

	if ( consumed == -1 )
		goto error;

	offset += consumed; DBG1("consumed --> %d\n", consumed);
	(*total_consumed) += consumed;

	return;

error:
	(*total_consumed) = -1;
}


static void dissect_icep_request(tvbuff_t *tvb, guint32 offset, proto_tree *icep_tree)
{
	/*  p. 612, chapter 23.3.2:
	 *
	 *  struct RequestData {
	 * 	 int requestID;
	 *	 Ice::Identity id;
	 *	 Ice::StringSeq facet;
	 *	 string operation;
	 *	 byte mode;
	 *	 Ice::Context context;
	 *	 Encapsulation params;
	 *  }
	 */

	proto_item *ti = NULL;
	proto_tree *icep_sub_tree = NULL;
	gint32 consumed = 0;
	guint32 reqid = 0;

	DBG0("dissect request\n");

	/* check for req id */
	if ( !tvb_bytes_exist(tvb, offset, 4) ) {

		if (icep_tree)
			proto_tree_add_text(icep_tree, tvb, offset, -1,
					    "too short header");

		col_append_str(mypinfo->cinfo, COL_INFO,
				       " (too short header)");

		return;
	}

	/* got at least 4 bytes */

	/* create display subtree for this message type */

	reqid = tvb_get_letohl(tvb, offset);

	if (icep_tree) {

		ti = proto_tree_add_text(icep_tree, tvb, offset, -1,
					 "Request Message Body");

		icep_sub_tree = proto_item_add_subtree(ti, ett_icep_msg);

		proto_tree_add_item(icep_sub_tree, hf_icep_request_id, tvb, offset, 4,
				    ENC_LITTLE_ENDIAN);

	}

	if ( reqid != 0 ) {
		if ( check_col(mypinfo->cinfo, COL_INFO) ) {
			col_append_fstr(mypinfo->cinfo, COL_INFO, "(%d):",
					tvb_get_letohl(tvb, offset));
		}
	} else
		col_append_str(mypinfo->cinfo, COL_INFO, "(oneway):");


	offset += 4;
	DBG0("consumed --> 4\n");

	dissect_icep_request_common(tvb, offset, icep_sub_tree, &consumed);

	if ( consumed == -1 )
		return;

	offset += consumed;
	DBG1("consumed --> %d\n", consumed);
}



static void dissect_icep_batch_request(tvbuff_t *tvb, guint32 offset,
				       proto_tree *icep_tree)
{
	/*  p. 613, chapter 23.3.3
	 *  A batch request msg is a "sequence" of batch request
	 *  Sequence is Size + elements
	 *
	 *  struct BatchRequestData {
	 *	 Ice::Identity id;
	 *	 Ice::StringSeq facet;
	 *	 string operation;
	 *	 byte mode;
	 *	 Ice::Context context;
	 *	 Encapsulation params;
	 *  }
	 *
	 * NOTE!!!:
	 * The only real implementation of the Ice protocol puts a 32bit count in front
	 * of a Batch Request, *not* an Ice::Sequence (as the standard says). Basically the
	 * same people wrote both code and standard so I'll follow the code.
	 */

	proto_item *ti = NULL;
	proto_tree *icep_sub_tree = NULL;
	guint32 num_reqs = 0;
	guint32 i = 0;
	gint32 consumed = 0;

	DBG0("dissect batch request\n");

	/* check for first 4 byte */
	if ( !tvb_bytes_exist(tvb, offset, 4) ) {

		if (icep_tree)
			proto_tree_add_text(icep_tree, tvb, offset, -1,
					    "counter of batch requests missing");

		col_append_str(mypinfo->cinfo, COL_INFO,
				       " (counter of batch requests missing)");

		return;
	}

	num_reqs = tvb_get_letohl(tvb, offset);
	offset += 4;

	DBG1("batch_requests.count --> %d\n", num_reqs);

	if ( num_reqs > ICEP_MAX_BATCH_REQUESTS ) {

		if (icep_tree)
			proto_tree_add_text(icep_tree, tvb, offset, -1,
					    "too many batch requests (%d)", num_reqs);

		if ( check_col(mypinfo->cinfo, COL_INFO) ) {
			col_append_fstr(mypinfo->cinfo, COL_INFO,
					" (too many batch requests, %d)",
					num_reqs);
		}

		return;
	}

	if ( num_reqs == 0 ) {

		if (icep_tree)
			proto_tree_add_text(icep_tree, tvb, offset, -1,
					    "empty batch requests sequence");
		col_append_str(mypinfo->cinfo, COL_INFO,
					" (empty batch requests sequence)");

		return;
	}


	col_append_str(mypinfo->cinfo, COL_INFO,
				":");

	/*
	 * process requests
	 */

	for ( i = 0; i < num_reqs; i++ ) {

		DBG1("looping through sequence of batch requests, loop #%d\n", i);

		/* create display subtree for this message type */

		if (icep_tree) {

			ti = proto_tree_add_text(icep_tree, tvb, offset, -1,
						 "Batch Request Message Body: #%d", i);

			icep_sub_tree = proto_item_add_subtree(ti, ett_icep_msg);

		}

		if ( check_col(mypinfo->cinfo, COL_INFO) && (i != 0) ) {
			col_append_str(mypinfo->cinfo, COL_INFO,
					",");
		}

		dissect_icep_request_common(tvb, offset, icep_sub_tree, &consumed);

		if ( consumed == -1 )
			return;

		if ( icep_tree && ti )
			proto_item_set_len(ti, consumed);

		offset += consumed;
		DBG1("consumed --> %d\n", consumed);
	}
}

static void dissect_icep_reply(tvbuff_t *tvb, guint32 offset, proto_tree *icep_tree)
{
	/*  p. 614, chapter 23.3.4:
	 *
	 *  struct ReplyData {
	 * 	 int requestId;
	 *	 byte replyStatus;
	 *	 [... messageSize - 19 bytes ...  ]
	 *  }
	 */

	gint32 messageSize = 0;
	guint32 tvb_data_remained = 0;
	guint32 reported_reply_data = 0;
	proto_item *ti = NULL;
	proto_tree *icep_sub_tree = NULL;

	DBG0("dissect reply\n");

	/* get at least a full reply message header */

	if ( !tvb_bytes_exist(tvb, offset, ICEP_MIN_REPLY_SIZE) ) {

		if (icep_tree)
			proto_tree_add_text(icep_tree, tvb, offset, -1,
					    "too short header");

		col_append_str(mypinfo->cinfo, COL_INFO,
				       " (too short header)");

		return;
	}

	/* got 5 bytes, then data */

	/* create display subtree for this message type */

	if (icep_tree) {

		ti = proto_tree_add_text(icep_tree, tvb, offset, -1,
					 "Reply Message Body");

		icep_sub_tree = proto_item_add_subtree(ti, ett_icep_msg);

		proto_tree_add_item(icep_sub_tree, hf_icep_request_id, tvb, offset, 4,
				    ENC_LITTLE_ENDIAN);
	}

	if ( check_col(mypinfo->cinfo, COL_INFO) ) {
		col_append_fstr(mypinfo->cinfo, COL_INFO, "(%d):",
				tvb_get_letohl(tvb, offset));
	}

	offset += 4;

	if (icep_tree)
		proto_tree_add_item(icep_sub_tree, hf_icep_reply_status, tvb, offset, 1,
				    ENC_LITTLE_ENDIAN);

	if ( check_col(mypinfo->cinfo, COL_INFO) ) {
		col_append_fstr(mypinfo->cinfo, COL_INFO, " %s",
				val_to_str(tvb_get_guint8(tvb, offset),
					   icep_replystatus_vals,
					   "unknown reply status"));
	}

	offset++;

	DBG1("consumed --> %d\n", 5);

	/* check if I got all reply data */
	tvb_data_remained = tvb_length_remaining(tvb, offset);
	messageSize = tvb_get_letohl(tvb, 10);
	reported_reply_data = messageSize - (ICEP_HEADER_SIZE + ICEP_MIN_REPLY_SIZE);

	/* no */
	if ( tvb_data_remained < reported_reply_data ) {

		if (icep_sub_tree)
			proto_tree_add_text(icep_sub_tree, tvb, offset, -1,
					    "Reply Data (missing %d bytes out of %d)",
					    reported_reply_data - tvb_data_remained,
					    reported_reply_data);

		if ( check_col(mypinfo->cinfo, COL_INFO) ) {
			col_append_fstr(mypinfo->cinfo, COL_INFO,
					" (missing reply data, %d bytes)",
					reported_reply_data - tvb_data_remained);
		}

		offset += tvb_data_remained;
		DBG1("consumed --> %d\n", tvb_data_remained);
		return;
	}

	/* yes (reported_reply_data can be 0) */

	if (icep_sub_tree) {

		if ( reported_reply_data !=0 )
			proto_tree_add_text(icep_sub_tree, tvb, offset,
					    reported_reply_data,
					    "Reply data (%d bytes)",
					    reported_reply_data);
		else
			proto_tree_add_text(icep_sub_tree, tvb, offset,
					    reported_reply_data,
					    "Reply data (empty)");
	}

	offset += reported_reply_data;
	DBG1("consumed --> %d\n", reported_reply_data);
}

static guint get_icep_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	return tvb_get_letohl(tvb, offset + 10);
}

static void dissect_icep_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/*  p. 611, chapter 23.3.1:
	 *
	 *  struct HeaderData {
	 * 	 int magic;
	 *	 byte protocolMajor;
	 *	 byte protocolMinor;
	 *	 byte encodingMajor;
	 *	 byte encodingMinor;
	 *	 byte messageType;
	 *	 byte compressionStatus;
	 *	 int messageSize;
	 *  }
	 */

	proto_item *ti = NULL;
	proto_tree *icep_tree = NULL;
	guint32 offset = 0;

	/* Make entries in Protocol column and Info column on summary display */

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ICEP");

	if ( check_col(pinfo->cinfo, COL_INFO) ) {
		col_add_str(pinfo->cinfo, COL_INFO,
			     val_to_str(tvb_get_guint8(tvb, 8),
					icep_msgtype_vals,
					"Unknown Message Type: 0x%02x"));
	}

	mypinfo = pinfo;

	if (tree) {

		DBG0("got an icep msg, start analysis\n");

		/* create display subtree for the protocol */

		ti = proto_tree_add_item(tree, proto_icep, tvb, 0, -1, FALSE);

		icep_tree = proto_item_add_subtree(ti, ett_icep);

		/* add items to the subtree */

		/* message header */

		proto_tree_add_text(icep_tree, tvb, offset, 4,
				    "Magic Number: 'I','c','e','P'");
		offset += 4;

		proto_tree_add_item(icep_tree, hf_icep_protocol_major,
				    tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;

		proto_tree_add_item(icep_tree, hf_icep_protocol_minor,
				    tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;

		proto_tree_add_item(icep_tree, hf_icep_encoding_major,
				    tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;

		proto_tree_add_item(icep_tree, hf_icep_encoding_minor,
				    tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;

		proto_tree_add_item(icep_tree, hf_icep_message_type,
				    tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;

		proto_tree_add_item(icep_tree, hf_icep_compression_status,
				    tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;

		proto_tree_add_item(icep_tree, hf_icep_message_size,
				    tvb, offset, 4, TRUE);
		offset += 4;
	} else {
		offset += ICEP_HEADER_SIZE;
	}

	switch(tvb_get_guint8(tvb, 8)) {
	case 0x0:
		DBG1("request message body: parsing %d bytes\n",
		    tvb_length_remaining(tvb, offset));
		dissect_icep_request(tvb, offset, icep_tree);
		break;
	case 0x1:
		DBG1("batch request message body: parsing %d bytes\n",
		    tvb_length_remaining(tvb, offset));
		dissect_icep_batch_request(tvb, offset, icep_tree);
		break;
	case 0x2:
		DBG1("reply message body: parsing %d bytes\n",
		    tvb_length_remaining(tvb, offset));
		dissect_icep_reply(tvb, offset, icep_tree);
		break;
	case 0x3:
	case 0x4:
	        /* messages already dissected */
		break;
	default:
		if (tree)
			proto_tree_add_text(tree, tvb, 8, 1, /* display msg type byte */
					    "Unknown Message Type: 0x%02x",
					    tvb_get_guint8(tvb, 8));
		break;
	}
}

/* entry point */
static gboolean dissect_icep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	DBG0("triggered\n");

	/* get at least a full message header (taken from packet-yhoo.c) */

	/* check for magic string (taken from packet-giop.c) */

	if ( tvb_memeql(tvb, 0, icep_magic, 4) == -1 ) {
		/* Not a ICEP packet. */
		return FALSE;
	}

	/* start dissecting */

	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, ICEP_HEADER_SIZE,
	    get_icep_pdu_len, dissect_icep_pdu);

	return TRUE;
}


/* Register the protocol with Wireshark */

void proto_register_icep(void)
{

	/* Setup list of header fields */

	static hf_register_info hf[] = {

		{ &hf_icep_protocol_major,
		  {
			  "Protocol Major", "icep.protocol_major",
			  FT_INT8, BASE_DEC, NULL, 0x0,
			  "The protocol major version number", HFILL
		  }
		},

		{ &hf_icep_protocol_minor,
		  {
			  "Protocol Minor", "icep.protocol_minor",
			  FT_INT8, BASE_DEC, NULL, 0x0,
			  "The protocol minor version number", HFILL
		  }
		},

		{ &hf_icep_encoding_major,
		  {
			  "Encoding Major", "icep.encoding_major",
			  FT_INT8, BASE_DEC, NULL, 0x0,
			  "The encoding major version number", HFILL
		  }
		},

		{ &hf_icep_encoding_minor,
		  {
			  "Encoding Minor", "icep.encoding_minor",
			  FT_INT8, BASE_DEC, NULL, 0x0,
			  "The encoding minor version number", HFILL
		  }
		},

		{ &hf_icep_message_type,
		  {
			  "Message Type", "icep.message_type",
			  FT_INT8, BASE_DEC, VALS(icep_msgtype_vals), 0x0,
			  "The message type", HFILL
		  }
		},

		{ &hf_icep_compression_status,
		  {
			  "Compression Status", "icep.compression_status",
			  FT_INT8, BASE_DEC, VALS(icep_zipstatus_vals), 0x0,
			  "The compression status of the message", HFILL
		  }
		},

		{ &hf_icep_message_size,
		  {
			  "Message Size", "icep.message_status",
			  FT_INT32, BASE_DEC, NULL, 0x0,
			  "The size of the message in bytes, including the header",
			  HFILL
		  }
		},

		{ &hf_icep_request_id,
		  {
			  "Request Identifier", "icep.request_id",
			  FT_INT32, BASE_DEC, NULL, 0x0,
			  "The request identifier",
			  HFILL
		  }
		},

		{ &hf_icep_reply_status,
		  {
			  "Reply Status", "icep.protocol_major",
			  FT_INT8, BASE_DEC, VALS(icep_replystatus_vals), 0x0,
			  "The reply status", HFILL
		  }
		},

		{ &hf_icep_id_name,
		  {
			  "Object Identity Name", "icep.id.name",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  "The object identity name", HFILL
		  }
		},

		{ &hf_icep_id_category,
		  {
			  "Object Identity Content", "icep.id.content",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  "The object identity content", HFILL
		  }
		},

		{ &hf_icep_facet,
		  {
			  "Facet Name", "icep.facet",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  "The facet name", HFILL
		  }
		},

		{ &hf_icep_operation,
		  {
			  "Operation Name", "icep.operation",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  "The operation name", HFILL
		  }
		},

		{ &hf_icep_mode,
		  {
			  "Ice::OperationMode", "icep.operation_mode",
			  FT_INT8, BASE_DEC, VALS(icep_mode_vals), 0x0,
			  "A byte representing Ice::OperationMode", HFILL
		  }
		},

		{ &hf_icep_context,
		  {
			  "Invocation Context", "icep.context",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  "The invocation context", HFILL
		  }
		},

		{ &hf_icep_params_size,
		  {
			  "Input Parameters Size", "icep.params.size",
			  FT_INT32, BASE_DEC, NULL, 0x0,
			  "The encapsulated input parameters size",
			  HFILL
		  }
		},

		{ &hf_icep_params_major,
		  {
			  "Input Parameters Encoding Major",
			  "icep.params.major",
			  FT_INT8, BASE_DEC, NULL, 0x0,
			  "The major encoding version of encapsulated parameters",
			  HFILL
		  }
		},

		{ &hf_icep_params_minor,
		  {
			  "Input Parameters Encoding Minor",
			  "icep.params.minor",
			  FT_INT8, BASE_DEC, NULL, 0x0,
			  "The minor encoding version of encapsulated parameters",
			  HFILL
		  }
		},

	};

	/* Setup protocol subtree array */

	static gint *ett[] = {
		&ett_icep,
		&ett_icep_msg,
	};

	/* Register the protocol name and description */

	proto_icep =
		proto_register_protocol("Internet Communications Engine Protocol",
					"ICEP", "icep");

	/* Required function calls to register the header fields and subtrees used */

	proto_register_field_array(proto_icep, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


void proto_reg_handoff_icep(void)
{
	/* Register as a heuristic TCP/UDP dissector */

	heur_dissector_add("tcp", dissect_icep, proto_icep);
	heur_dissector_add("udp", dissect_icep, proto_icep);
}
