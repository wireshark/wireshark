/*
 * packet-iax2.c
 *
 * Routines for IAX2 packet disassembly
 * By Alastair Maw <asterisk@almaw.com>
 * Copyright 2003 Alastair Maw
 *
 * IAX2 is a VoIP protocol for the open source PBX Asterisk. Please see
 * http://www.asterisk.org for more information.
 *
 * $Id: packet-iax2.c,v 1.2 2004/01/27 01:43:41 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version. This program is distributed in the hope
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details. You
 * should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>

#include "packet-iax2.h"

#define IAX2_PORT		4569
#define PROTO_TAG_IAX2	"IAX2"

static int proto_iax2 = -1;

static int hf_iax2_retransmission = -1;
static int hf_iax2_scallno = -1;
static int hf_iax2_dcallno = -1;
static int hf_iax2_ts = -1;
static int hf_iax2_minits = -1;
static int hf_iax2_voicedata = -1;
static int hf_iax2_oseqno = -1;
static int hf_iax2_iseqno = -1;
static int hf_iax2_type = -1;
static int hf_iax2_csub = -1;
static int hf_iax2_dtmf_csub = -1;
static int hf_iax2_cmd_csub = -1;
static int hf_iax2_iax_csub = -1;
static int hf_iax2_voice_csub = -1;
static int hf_iax2_ies = -1;
static int hf_IAX_IE_CALLED_NUMBER = -1;
static int hf_IAX_IE_CALLING_NUMBER = -1;
static int hf_IAX_IE_CALLING_ANI = -1;
static int hf_IAX_IE_CALLING_NAME = -1;
static int hf_IAX_IE_CALLED_CONTEXT = -1;
static int hf_IAX_IE_USERNAME = -1;
static int hf_IAX_IE_PASSWORD = -1;
static int hf_IAX_IE_CAPABILITY = -1;
static int hf_IAX_IE_FORMAT = -1;
static int hf_IAX_IE_LANGUAGE = -1;
static int hf_IAX_IE_VERSION = -1;
static int hf_IAX_IE_ADSICPE = -1;
static int hf_IAX_IE_DNID = -1;
static int hf_IAX_IE_AUTHMETHODS = -1;
static int hf_IAX_IE_CHALLENGE = -1;
static int hf_IAX_IE_MD5_RESULT = -1;
static int hf_IAX_IE_RSA_RESULT = -1;
static int hf_IAX_IE_APPARENT_ADDR = -1;
static int hf_IAX_IE_REFRESH = -1;
static int hf_IAX_IE_DPSTATUS = -1;
static int hf_IAX_IE_CALLNO = -1;
static int hf_IAX_IE_CAUSE = -1;
static int hf_IAX_IE_IAX_UNKNOWN = -1;
static int hf_IAX_IE_MSGCOUNT = -1;
static int hf_IAX_IE_AUTOANSWER = -1;
static int hf_IAX_IE_MUSICONHOLD = -1;
static int hf_IAX_IE_TRANSFERID = -1;
static int hf_IAX_IE_RDNIS = -1;



static gint ett_iax2 = -1;
static gint ett_iax2_ies = -1;
static gint ett_iax2_codecs = -1;

static const value_string iax_frame_types[] = {
  {0, "(0?)"},
  {1, "DTMF"},
  {2, "Voice"},
  {3, "Video"},
  {4, "Control"},
  {5, "NULL"},
  {6, "IAX"},
  {7, "Text"},
  {8, "Image"}
};
static const value_string iax_iax_subclasses[] = {
  {0, "(0?)"},
  {1, "NEW"},
  {2, "PING"},
  {3, "PONG"},
  {4, "ACK"},
  {5, "HANGUP"},
  {6, "REJECT"},
  {7, "ACCEPT"},
  {8, "AUTHREQ"},
  {9, "AUTHREP"},
  {10, "INVAL"},
  {11, "LAGRQ"},
  {12, "LAGRP"},
  {13, "REGREQ"},
  {14, "REGAUTH"},
  {15, "REGACK"},
  {16, "REGREJ"},
  {17, "REGREL"},
  {18, "VNAK"},
  {19, "DPREQ"},
  {20, "DPREP"},
  {21, "DIAL"},
  {22, "TXREQ"},
  {23, "TXCNT"},
  {24, "TXACC"},
  {25, "TXREADY"},
  {26, "TXREL"},
  {27, "TXREJ"},
  {28, "QUELCH"},
  {29, "UNQULCH"},
  {30, "POKE"},
  {31, "PAGE"},
  {32, "MWI"},
  {33, "UNSUPPORTED"},
  {34, "TRANSFER"}
};
static const value_string iax_cmd_subclasses[] = {
  {0, "(0?)"},
  {1, "HANGUP"},
  {2, "RING"},
  {3, "RINGING"},
  {4, "ANSWER"},
  {5, "BUSY"},
  {6, "TKOFFHK"},
  {7, "OFFHOOK"}
};

static const value_string iax_ies_type[] = {
  {IAX_IE_CALLED_NUMBER, "Number/extension being called"},
  {IAX_IE_CALLING_NUMBER, "Calling number"},
  {IAX_IE_CALLING_ANI, "Calling number ANI for billing"},
  {IAX_IE_CALLING_NAME, "Name of caller"},
  {IAX_IE_CALLED_CONTEXT, "Context for number"},
  {IAX_IE_USERNAME, "Username (peer or user) for authentication"},
  {IAX_IE_PASSWORD, "Password for authentication"},
  {IAX_IE_CAPABILITY, "Actual codec capability"},
  {IAX_IE_FORMAT, "Desired codec format"},
  {IAX_IE_LANGUAGE, "Desired language"},
  {IAX_IE_VERSION, "Protocol version"},
  {IAX_IE_ADSICPE, "CPE ADSI capability"},
  {IAX_IE_DNID, "Originally dialed DNID"},
  {IAX_IE_AUTHMETHODS, "Authentication method(s)"},
  {IAX_IE_CHALLENGE, "Challenge data for MD5/RSA"},
  {IAX_IE_MD5_RESULT, "MD5 challenge result"},
  {IAX_IE_RSA_RESULT, "RSA challenge result"},
  {IAX_IE_APPARENT_ADDR, "Apparent address of peer"},
  {IAX_IE_REFRESH, "When to refresh registration"},
  {IAX_IE_DPSTATUS, "Dialplan status"},
  {IAX_IE_CALLNO, "Call number of peer"},
  {IAX_IE_CAUSE, "Cause"},
  {IAX_IE_IAX_UNKNOWN, "Unknown IAX command"},
  {IAX_IE_MSGCOUNT, "How many messages waiting"},
  {IAX_IE_AUTOANSWER, "Request auto-answering"},
  {IAX_IE_MUSICONHOLD, "Request musiconhold with QUELCH"},
  {IAX_IE_TRANSFERID, "Transfer Request Identifier"},
  {IAX_IE_RDNIS, "Referring DNIS"}
};

static const value_string codec_types[] = {
  {AST_FORMAT_G723_1, "G.723.1 compression"},
  {AST_FORMAT_GSM, "GSM compression"},
  {AST_FORMAT_ULAW, "Raw mu-law data (G.711)"},
  {AST_FORMAT_ALAW, "Raw A-law data (G.711)"},
  {AST_FORMAT_MP3, "MPEG-2 layer 3"},
  {AST_FORMAT_ADPCM, "ADPCM (whose?)"},
  {AST_FORMAT_SLINEAR, "Raw 16-bit Signed Linear (8000 Hz) PCM"},
  {AST_FORMAT_LPC10, "LPC10, 180 samples/frame"},
  {AST_FORMAT_G729A, "G.729a Audio"}
};

static void
dissect_iax2 (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_tree *iax2_tree = NULL, *ies_tree = NULL, *codec_tree = NULL;
  proto_item *ti = 0, *ies_base = 0, *codec_base = 0;
  guint32 offset = 0, codecs = 0, i = 0, mask = 0, retransmission = 0;
  long addr;
  guint16 scallno;
  guint16 dcallno;
  guint32 ts;
  guint8 type;
  guint8 csub;

  if (check_col (pinfo->cinfo, COL_PROTOCOL))
    {
      col_set_str (pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_IAX2);
    }
  if (check_col (pinfo->cinfo, COL_INFO))
    {
      col_clear (pinfo->cinfo, COL_INFO);
    }

  if (tree)
    {
      ti = proto_tree_add_item (tree, proto_iax2, tvb, offset, -1, FALSE);
      iax2_tree = proto_item_add_subtree (ti, ett_iax2);
    }

  scallno = tvb_get_ntohs(tvb, offset);
  if (scallno & 0x8000)
    {
      /*
       * remove the top bit for header type detection 
       */
      scallno = scallno & 0x7FFF;
      proto_tree_add_uint (iax2_tree, hf_iax2_scallno, tvb, offset, 2,
			   scallno);

      /*
       * remove the top bit for retransmission detection 
       */
      dcallno = tvb_get_ntohs(tvb, offset + 2);
      retransmission = dcallno & 0x8000;
      proto_tree_add_uint (iax2_tree, hf_iax2_dcallno, tvb, offset + 2, 2,
			   dcallno);
      proto_tree_add_boolean (iax2_tree, hf_iax2_retransmission, tvb,
			      offset + 2, 2, retransmission);

      ts = tvb_get_ntohl(tvb, offset + 4);
      proto_tree_add_uint (iax2_tree, hf_iax2_ts, tvb, offset + 4, 4, ts);
      proto_tree_add_item (iax2_tree, hf_iax2_oseqno, tvb, offset + 8, 1,
			   FALSE);
      proto_tree_add_item (iax2_tree, hf_iax2_iseqno, tvb, offset + 9, 1,
			   FALSE);
      type = tvb_get_guint8(tvb, offset + 10);
      proto_tree_add_uint (iax2_tree, hf_iax2_type, tvb, offset + 10, 1,
			   type);

      csub = tvb_get_guint8(tvb, offset + 11);
      if (type == AST_FRAME_IAX)
	{
	  proto_tree_add_uint (iax2_tree, hf_iax2_iax_csub, tvb,
			       offset + 11, 1, csub);
	  if (check_col (pinfo->cinfo, COL_INFO))
	    {
	      col_add_fstr (pinfo->cinfo, COL_INFO,
			    "%s %s, source call# %d, timestamp %ums",
			    val_to_str (type, iax_frame_types,
					"Unknown (0x%02x)"),
			    val_to_str (csub, iax_iax_subclasses,
					"unknown (0x%02x)"), scallno,
			    ts);
	    }

	}
      else if (type == AST_FRAME_DTMF)
	{
	  proto_tree_add_uint (iax2_tree, hf_iax2_dtmf_csub, tvb,
			       offset + 11, 1, csub);
	  if (check_col (pinfo->cinfo, COL_INFO))
	    {
	      col_add_fstr (pinfo->cinfo, COL_INFO,
			    "%s digit %c, source call# %d, timestamp %ums",
			    val_to_str (type, iax_frame_types,
					"Unknown (0x%02x)"), csub,
			    scallno, ts);
	    }

	}
      else if (type == AST_FRAME_CONTROL)
	{
	  proto_tree_add_uint (iax2_tree, hf_iax2_cmd_csub, tvb,
			       offset + 11, 1, csub);
	  if (check_col (pinfo->cinfo, COL_INFO))
	    {
	      col_add_fstr (pinfo->cinfo, COL_INFO,
			    "%s %s, source call# %d, timestamp %ums",
			    val_to_str (type, iax_frame_types,
					"Unknown (0x%02x)"),
			    val_to_str (csub, iax_cmd_subclasses,
					"unknown (0x%02x)"), scallno,
			    ts);
	    }

	}
      else if (type == AST_FRAME_VOICE)
	{
	  proto_tree_add_uint (iax2_tree, hf_iax2_voice_csub, tvb,
			       offset + 11, 1, csub);
	  if (check_col (pinfo->cinfo, COL_INFO))
	    {
	      col_add_fstr (pinfo->cinfo, COL_INFO,
			    "%s codec %s, source call# %d, timestamp %ums",
			    val_to_str (type, iax_frame_types,
					"Unknown (0x%02x)"),
			    val_to_str (csub, codec_types,
					"unknown (0x%02x)"), scallno,
			    ts);
	    }
	}
      else
	{
	  proto_tree_add_uint (iax2_tree, hf_iax2_csub, tvb, offset + 11,
			       1, csub);
	  if (check_col (pinfo->cinfo, COL_INFO))
	    {
	      col_add_fstr (pinfo->cinfo, COL_INFO,
			    "%s subclass %d, source call# %d, timestamp %ums",
			    val_to_str (type, iax_frame_types,
					"Unknown (0x%02x)"), csub,
			    scallno, ts);
	    }
	}
      offset += 12;

      if (type == AST_FRAME_IAX && (offset < tvb_reported_length (tvb)))
	{
	  ies_base =
	    proto_tree_add_item (iax2_tree, hf_iax2_ies, tvb, offset,
				 -1, FALSE);
	  ies_tree = proto_item_add_subtree (ies_base, ett_iax2_ies);
	}

      while (type == AST_FRAME_IAX && offset < tvb_reported_length (tvb))
	{
	  int ies_type = tvb_get_guint8(tvb, offset);
	  int ies_len = tvb_get_guint8(tvb, offset + 1);
	  switch (ies_type)
	    {
	    case IAX_IE_CALLED_NUMBER:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_CALLED_NUMBER, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_CALLING_NUMBER:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_CALLING_NUMBER,
				   tvb, offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_CALLING_ANI:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_CALLING_ANI, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_CALLING_NAME:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_CALLING_NAME, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_CALLED_CONTEXT:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_CALLED_CONTEXT,
				   tvb, offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_USERNAME:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_USERNAME, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_PASSWORD:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_PASSWORD, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_LANGUAGE:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_LANGUAGE, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_DNID:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_DNID, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_CHALLENGE:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_CHALLENGE, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_MD5_RESULT:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_MD5_RESULT, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_RSA_RESULT:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_RSA_RESULT, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_RDNIS:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_RDNIS, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_CAPABILITY:
	      codec_base =
		proto_tree_add_item (ies_tree, hf_IAX_IE_CAPABILITY,
				     tvb, offset + 2, ies_len, FALSE);
	      codec_tree =
		proto_item_add_subtree (codec_base, ett_iax2_codecs);

	      codecs = tvb_get_ntohl (tvb, offset + 2);
	      for (i = 0; i < 8; i++)
		{
		  mask = (1 << i);
		  if (codecs & mask)
		    proto_tree_add_text (codec_tree, tvb, offset + 2, 4,
					 "Supported: %s",
					 val_to_str (mask, codec_types,
						     "unknown"));
		}
	      for (i = 0; i < 8; i++)
		{
		  mask = (1 << i);
		  if (!(codecs & mask))
		    proto_tree_add_text (codec_tree, tvb, offset + 2, 4,
					 "Unsupported: %s",
					 val_to_str (mask, codec_types,
						     "unknown"));
		}

	      break;
	    case IAX_IE_FORMAT:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_FORMAT, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_VERSION:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_VERSION, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_ADSICPE:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_ADSICPE, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_AUTHMETHODS:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_AUTHMETHODS, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_APPARENT_ADDR:
	      addr = tvb_get_ntohl (tvb, offset + 6);
	      ti = proto_tree_add_ipv4 (ies_tree, hf_IAX_IE_APPARENT_ADDR, tvb, offset + 6, 4, addr);
	      proto_item_append_text( ti, ", Port: %d", tvb_get_ntohs(tvb, offset + 2));
	      break;
	    case IAX_IE_REFRESH:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_REFRESH, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_DPSTATUS:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_DPSTATUS, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_CALLNO:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_CALLNO, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_CAUSE:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_CAUSE, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_IAX_UNKNOWN:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_IAX_UNKNOWN, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_MSGCOUNT:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_MSGCOUNT, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_AUTOANSWER:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_AUTOANSWER, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_MUSICONHOLD:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_MUSICONHOLD, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    case IAX_IE_TRANSFERID:
	      proto_tree_add_item (ies_tree, hf_IAX_IE_TRANSFERID, tvb,
				   offset + 2, ies_len, FALSE);
	      break;
	    }
	  offset += ies_len + 2;
	}

    }
  else
    {
      proto_tree_add_uint (iax2_tree, hf_iax2_scallno, tvb, offset, 2,
			   scallno);
      ts = tvb_get_ntohs(tvb, offset + 2);
      proto_tree_add_uint (iax2_tree, hf_iax2_minits, tvb, offset + 2, 2,
			   ts);
      if (check_col (pinfo->cinfo, COL_INFO))
	{
	  col_add_fstr (pinfo->cinfo, COL_INFO,
			"Voice frame (mini header), source call# %d, timestamp %ums",
			scallno, ts);
	}
      proto_tree_add_item (iax2_tree, hf_iax2_voicedata, tvb, offset + 4,
			   -1, FALSE);
    }

}				/* dissect_iax2 */

void
proto_register_iax2 (void)
{
  static hf_register_info hf[] = {
    {&hf_iax2_scallno,
     {"Source call", "iax2.src_call", FT_UINT16, BASE_DEC, NULL, 0x0,
      "",
      HFILL}},
    {&hf_iax2_dcallno,
     {"Destination call", "iax2.dst_call", FT_UINT16, BASE_DEC, NULL,
      0x0, "",
      HFILL}},
    {&hf_iax2_retransmission,
     {"Retransmission", "iax2.retransmission", FT_BOOLEAN, BASE_NONE,
      NULL,
      0x0, "", HFILL}},
    {&hf_iax2_ts,
     {"Timestamp", "iax2.timestamp", FT_UINT32, BASE_DEC, NULL, 0x0,
      "",
      HFILL}},
    {&hf_iax2_minits,
     {"Timestamp", "iax2.timestamp", FT_UINT16, BASE_DEC, NULL, 0x0,
      "",
      HFILL}},
    {&hf_iax2_voicedata,
     {"Voice data", "iax2.voicedata", FT_BYTES, BASE_NONE, NULL, 0x0,
      "",
      HFILL}},
    {&hf_iax2_oseqno,
     {"Outbound seq.no.", "iax2.oseqno", FT_UINT16, BASE_DEC, NULL,
      0x0, "",
      HFILL}},
    {&hf_iax2_iseqno,
     {"Inbound seq.no.", "iax2.iseqno", FT_UINT16, BASE_DEC, NULL, 0x0,
      "",
      HFILL}},
    {&hf_iax2_type,
     {"Type", "iax2.type", FT_INT8, BASE_DEC, VALS (iax_frame_types),
      0x0, "",
      HFILL}},
    {&hf_iax2_csub,
     {"Sub-class", "iax2.subclass", FT_UINT8, BASE_DEC, NULL, 0x0, "",
      HFILL}},
    {&hf_iax2_dtmf_csub,
     {"DTMF digit", "iax2.dtmf.digit", FT_UINT8, BASE_DEC, NULL, 0x0,
      "",
      HFILL}},
    {&hf_iax2_cmd_csub,
     {"Control type", "iax2.control", FT_UINT8, BASE_DEC,
      VALS (iax_cmd_subclasses), 0x0, "", HFILL}},
    {&hf_iax2_voice_csub,
     {"CODEC", "iax2.voice", FT_UINT8, BASE_DEC, VALS (codec_types),
      0x0, "",
      HFILL}},
    {&hf_iax2_iax_csub,
     {"IAX type", "iax2.iax", FT_UINT8, BASE_DEC,
      VALS (iax_iax_subclasses),
      0x0, "", HFILL}},
    {&hf_iax2_ies,
     {"Information elements", "iax2.ies", FT_BYTES, BASE_NONE, NULL,
      0x0, "",
      HFILL}},
    {&hf_IAX_IE_CALLED_NUMBER,
     {"Number/extension being called", "iax2.ies.called_number",
      FT_STRING,
      BASE_NONE, NULL, 0x0, "", HFILL}},
    {&hf_IAX_IE_CALLING_NUMBER,
     {"Calling number", "iax2.ies.calling_number", FT_STRING,
      BASE_NONE, NULL,
      0x0, "", HFILL}},
    {&hf_IAX_IE_CALLING_ANI,
     {"Calling number ANI for billing", "iax2.ies.calling_ani",
      FT_STRING,
      BASE_NONE, NULL, 0x0, "", HFILL}},
    {&hf_IAX_IE_CALLING_NAME,
     {"Name of caller", "iax2.ies.calling_name", FT_STRING, BASE_NONE,
      NULL,
      0x0, "", HFILL}},
    {&hf_IAX_IE_CALLED_CONTEXT,
     {"Context for number", "iax2.ies.called_context", FT_STRING,
      BASE_NONE,
      NULL, 0x0, "", HFILL}},
    {&hf_IAX_IE_USERNAME,
     {"Username (peer or user) for authentication",
      "iax2.ies.username",
      FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL}},
    {&hf_IAX_IE_PASSWORD,
     {"Password for authentication", "iax2.ies.password", FT_STRING,
      BASE_NONE, NULL, 0x0, "", HFILL}},
    {&hf_IAX_IE_CAPABILITY,
     {"Actual codec capability", "iax2.ies.capability", FT_UINT32,
      BASE_HEX,
      NULL, 0x0, "", HFILL}},
    {&hf_IAX_IE_FORMAT,
     {"Desired codec format", "iax2.ies.format", FT_UINT32, BASE_HEX,
      VALS (codec_types), 0x0, "", HFILL}},
    {&hf_IAX_IE_LANGUAGE,
     {"Desired language", "iax2.ies.language", FT_STRING, BASE_NONE,
      NULL,
      0x0, "", HFILL}},
    {&hf_IAX_IE_VERSION,
     {"Protocol version", "iax2.ies.version", FT_INT16, BASE_HEX, NULL,
      0x0,
      "", HFILL}},
    {&hf_IAX_IE_ADSICPE,
     {"CPE ADSI capability", "iax2.ies.cpe_adsi", FT_INT16, BASE_HEX,
      NULL,
      0x0, "", HFILL}},
    {&hf_IAX_IE_DNID,
     {"Originally dialed DNID", "iax2.ies.dnid", FT_STRING, BASE_NONE,
      NULL,
      0x0, "", HFILL}},
    {&hf_IAX_IE_AUTHMETHODS,
     {"Authentication method(s)", "iax2.ies.auth.methods", FT_INT16,
      BASE_HEX,
      NULL, 0x0, "", HFILL}},
    {&hf_IAX_IE_CHALLENGE,
     {"Challenge data for MD5/RSA", "iax2.ies.auth.challenge",
      FT_STRING,
      BASE_NONE, NULL, 0x0, "", HFILL}},
    {&hf_IAX_IE_MD5_RESULT,
     {"MD5 challenge result", "iax2.ies.auth.md5", FT_STRING,
      BASE_NONE, NULL,
      0x0, "", HFILL}},
    {&hf_IAX_IE_RSA_RESULT,
     {"RSA challenge result", "iax2.ies.auth.rsa", FT_STRING,
      BASE_NONE, NULL,
      0x0, "", HFILL}},
    {&hf_IAX_IE_APPARENT_ADDR,
     {"Apparent address of peer", "iax2.ies.address", FT_STRING,
      BASE_NONE,
      NULL, 0x0, "", HFILL}},
    {&hf_IAX_IE_REFRESH,
     {"When to refresh registration", "iax2.ies.refresh", FT_INT16,
      BASE_DEC,
      NULL, 0x0, "", HFILL}},
    {&hf_IAX_IE_DPSTATUS,
     {"Dialplan status", "iax2.ies.dialplan_status", FT_INT16,
      BASE_HEX, NULL,
      0x0, "", HFILL}},
    {&hf_IAX_IE_CALLNO,
     {"Call number of peer", "iax2.ies.call_no", FT_INT16, BASE_DEC,
      NULL,
      0x0, "", HFILL}},
    {&hf_IAX_IE_CAUSE,
     {"Cause", "iax2.ies.cause", FT_STRING, BASE_NONE, NULL, 0x0, "",
      HFILL}},
    {&hf_IAX_IE_IAX_UNKNOWN,
     {"Unknown IAX command", "iax2.ies.iax_unknown", FT_BYTES,
      BASE_HEX, NULL,
      0x0, "", HFILL}},
    {&hf_IAX_IE_MSGCOUNT,
     {"How many messages waiting", "iax2.ies.msg_count", FT_INT16,
      BASE_DEC,
      NULL, 0x0, "", HFILL}},
    {&hf_IAX_IE_AUTOANSWER,
     {"Request auto-answering", "iax2.ies.autoanswer", FT_NONE,
      BASE_NONE,
      NULL, 0x0, "", HFILL}},
    {&hf_IAX_IE_MUSICONHOLD,
     {"Request musiconhold with QUELCH", "iax2.ies.moh", FT_NONE,
      BASE_NONE,
      NULL, 0x0, "", HFILL}},
    {&hf_IAX_IE_TRANSFERID,
     {"Transfer Request Identifier", "iax2.ies.transferid", FT_INT32,
      BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_IAX_IE_RDNIS,
     {"Referring DNIS", "iax2.ies.rdnis", FT_STRING, BASE_NONE, NULL,
      0x0, "",
      HFILL}}
  };

  static gint *ett[] = {
    &ett_iax2,
    &ett_iax2_ies,
    &ett_iax2_codecs
  };

  proto_iax2 =
    proto_register_protocol ("IAX2", "Inter-Asterisk eXchange v2", "iax2");
  proto_register_field_array (proto_iax2, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

}

void
proto_reg_handoff_iax2 (void)
{

  dissector_handle_t iax2_handle = NULL;

  iax2_handle = create_dissector_handle (dissect_iax2, proto_iax2);

  dissector_add ("udp.port", IAX2_PORT, iax2_handle);
}
