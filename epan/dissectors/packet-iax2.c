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
 * $Id$
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

#include <epan/circuit.h>
#include <epan/packet.h>
#include <epan/to_str.h>

#include "packet-iax2.h"
#include "iax2_codec_type.h"

#define IAX2_PORT		4569
#define PROTO_TAG_IAX2	"IAX2"

/* #define DEBUG_HASHING */

/* Ethereal ID of the IAX2 protocol */
static int proto_iax2 = -1;

/* The following hf_* variables are used to hold the ethereal IDs of
 * our header fields; they are filled out when we call
 * proto_register_field_array() in proto_register_iax2()
 */
static int hf_iax2_packet_type = -1;
static int hf_iax2_retransmission = -1;
static int hf_iax2_scallno = -1;
static int hf_iax2_dcallno = -1;
static int hf_iax2_ts = -1;
static int hf_iax2_minits = -1;
static int hf_iax2_minividts = -1;
static int hf_iax2_minividmarker = -1;
static int hf_iax2_oseqno = -1;
static int hf_iax2_iseqno = -1;
static int hf_iax2_type = -1;
static int hf_iax2_csub = -1;
static int hf_iax2_cmd_csub = -1;
static int hf_iax2_iax_csub = -1;
static int hf_iax2_voice_csub = -1;
static int hf_iax2_voice_codec = -1;
static int hf_iax2_video_csub = -1;
static int hf_iax2_video_codec = -1;
static int hf_iax2_marker = -1;

static int hf_iax2_cap_g723_1 = -1;
static int hf_iax2_cap_gsm = -1;
static int hf_iax2_cap_ulaw = -1;
static int hf_iax2_cap_alaw = -1;
static int hf_iax2_cap_g726 = -1;
static int hf_iax2_cap_adpcm = -1;
static int hf_iax2_cap_slinear = -1;
static int hf_iax2_cap_lpc10 = -1;
static int hf_iax2_cap_g729a = -1;
static int hf_iax2_cap_speex = -1;
static int hf_iax2_cap_ilbc = -1;
static int hf_iax2_cap_jpeg = -1;
static int hf_iax2_cap_png = -1;
static int hf_iax2_cap_h261 = -1;
static int hf_iax2_cap_h263 = -1;

static int hf_IAX_IE_APPARENTADDR_SINFAMILY = -1;
static int hf_IAX_IE_APPARENTADDR_SINPORT = -1;
static int hf_IAX_IE_APPARENTADDR_SINADDR = -1;
static int hf_IAX_IE_APPARENTADDR_SINZERO = -1;		  
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
static int hf_IAX_IE_DATAFORMAT = -1;
static int hf_IAX_IE_UNKNOWN_BYTE = -1;
static int hf_IAX_IE_UNKNOWN_I16 = -1;
static int hf_IAX_IE_UNKNOWN_I32 = -1;
static int hf_IAX_IE_UNKNOWN_BYTES = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_iax2 = -1;
static gint ett_iax2_full_mini_subtree = -1;
static gint ett_iax2_type = -1;     	/* Frame-type specific subtree */
static gint ett_iax2_ie = -1;  		/* single IE */
static gint ett_iax2_codecs = -1;       /* capabilities IE */
static gint ett_iax2_ies_apparent_addr = -1; /* apparent address IE */

static dissector_handle_t data_handle;

/* data-call subdissectors, AST_DATAFORMAT_* */
static dissector_table_t iax2_dataformat_dissector_table;
/* voice/video call subdissectors, AST_FORMAT_* */
static dissector_table_t iax2_codec_dissector_table;

/* IAX2 Full-frame types */
static const value_string iax_frame_types[] = {
  {0, "(0?)"},
  {1, "DTMF"},
  {2, "Voice"},
  {3, "Video"},
  {4, "Control"},
  {5, "NULL"},
  {6, "IAX"},
  {7, "Text"},
  {8, "Image"},
  {0,NULL}
};

/* Subclasses for IAX packets */
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
  {34, "TRANSFER"},
  {0,NULL}
};

/* Subclassess for Control packets */
static const value_string iax_cmd_subclasses[] = {
  {0, "(0?)"},
  {1, "HANGUP"},
  {2, "RING"},
  {3, "RINGING"},
  {4, "ANSWER"},
  {5, "BUSY"},
  {6, "TKOFFHK"},
  {7, "OFFHOOK"},
  {0xFF, "stop sounds"}, /* sent by app_dial, and not much else */
  {0,NULL}
};

/* Information elements */
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
  {IAX_IE_RDNIS, "Referring DNIS"},
  {IAX_IE_PROVISIONING, "Provisioning info"},
  {IAX_IE_AESPROVISIONING, "AES Provisioning info"},
  {IAX_IE_DATETIME,"Date/Time"},
  {IAX_IE_DATAFORMAT, "Data call format"},
  {0,NULL}
};

static const value_string codec_types[] = {
  {AST_FORMAT_G723_1, "G.723.1 compression"},
  {AST_FORMAT_GSM, "GSM compression"},
  {AST_FORMAT_ULAW, "Raw mu-law data (G.711)"},
  {AST_FORMAT_ALAW, "Raw A-law data (G.711)"},
  {AST_FORMAT_G726, "ADPCM (G.726, 32kbps)"},
  {AST_FORMAT_ADPCM, "ADPCM (IMA)"},
  {AST_FORMAT_SLINEAR, "Raw 16-bit Signed Linear (8000 Hz) PCM"},
  {AST_FORMAT_LPC10, "LPC10, 180 samples/frame"},
  {AST_FORMAT_G729A, "G.729a Audio"},
  {AST_FORMAT_SPEEX, "SpeeX Free Compression"},
  {AST_FORMAT_ILBC, "iLBC Free Compression"},
  {AST_FORMAT_JPEG, "JPEG Images"},
  {AST_FORMAT_PNG, "PNG Images"},
  {AST_FORMAT_H261, "H.261 Video"},
  {AST_FORMAT_H263, "H.263 Video"},
  {0,NULL}
};

static const value_string iax_dataformats[] = {
  {AST_DATAFORMAT_NULL, "N/A (analogue call?)"},
  {AST_DATAFORMAT_V110,	"ITU-T V.110 rate adaption"},
  {AST_DATAFORMAT_H223_H245,"ITU-T H.223/H.245"},
  {0,NULL}
};

typedef enum {
  IAX2_MINI_VOICE_PACKET,
  IAX2_FULL_PACKET,
  IAX2_MINI_VIDEO_PACKET,
  IAX2_META_PACKET
} packet_type;

static const value_string iax_packet_types[] = {
  {IAX2_FULL_PACKET, "Full packet"},
  {IAX2_MINI_VOICE_PACKET, "Mini voice packet"},
  {IAX2_MINI_VIDEO_PACKET, "Mini video packet"},
  {IAX2_META_PACKET, "Meta packet"},
  {0,NULL}
};
  

/* ************************************************************************* */

/* In order to track IAX calls, we have a hash table which maps
 * {addr,port type,port,call} to a unique circuit id.
 *
 * Each call has two such circuits associated with it (a forward and a
 * reverse circuit, where 'forward' is defined as the direction the NEW
 * packet went in), and we maintain an iax_call_data structure for each
 * call, attached to both circuits with circuit_add_proto_data.
 *
 * Because {addr,port type,port,call} quadruplets can be reused
 * (Asterisk reuses call numbers), circuit ids aren't unique to
 * individual calls and we treat NEW packets somewhat specially. When we
 * get such a packet, we see if there are any calls with a matching
 * circuit id, and make sure that its circuits are marked as ended
 * before that packet.
 *
 * A second complication is that we only know one quadruplet at the time
 * the NEW packet is processed: there is therefore cunningness in
 * iax_lookup_circuit_details() to look for replies to NEW packets and
 * create the reverse circuit.
 */


/* start with a hash of {addr,port type,port,call}->{id} */

typedef struct {
  address addr;
  port_type ptype;
  guint32 port;
  guint32 callno;
} iax_circuit_key;

/* tables */
static GHashTable *iax_circuit_hashtab = NULL;
static GMemChunk *iax_circuit_keys = NULL;
static GMemChunk *iax_circuit_vals = NULL;
static guint circuitcount = 0;

/* the number of keys and values to reserve space for in each memory chunk.
   We assume we won't be tracking many calls at once so this is quite low.
*/
#define IAX_INIT_PACKET_COUNT 10

#ifdef DEBUG_HASHING
static gchar *key_to_str( const iax_circuit_key *key )
{
  static int i=0;
  static gchar *strp, str[3][80];

  i++;
  if(i>=3){
    i=0;
  }
  strp=str[i];

  /* why doesn't address_to_str take a const pointer?
     cast the warnings into oblivion. */

  sprintf(strp,"{%s:%i,%i}",
	  address_to_str((address *)&key->addr),
	  key->port,
	  key->callno);
  return strp;
}
#endif

/* Hash Functions */
static gint iax_circuit_equal(gconstpointer v, gconstpointer w)
{
  const iax_circuit_key *v1 = (const iax_circuit_key *)v;
  const iax_circuit_key *v2 = (const iax_circuit_key *)w;
  gint result;

  result = ( ADDRESSES_EQUAL(&(v1->addr), &(v2->addr)) &&
	     v1->ptype == v2->ptype &&
	     v1->port  == v2->port &&
	     v1->callno== v2->callno);
#ifdef DEBUG_HASHING
  g_message( "+++ Comparing for equality: %s, %s: %u",key_to_str(v1), key_to_str(v2), result);
#endif

  return result;;
}

static guint iax_circuit_hash (gconstpointer v)
{
  const iax_circuit_key *key = (const iax_circuit_key *)v;
  guint hash_val;
  int i;

  hash_val = 0;
  for (i = 0; i < key->addr.len; i++)
    hash_val += (guint)(key->addr.data[i]);

  hash_val += (guint)(key->ptype);
  hash_val += (guint)(key->port);
  hash_val += (guint)(key->callno);

#ifdef DEBUG_HASHING
  g_message( "+++ Hashing key: %s, result %#x", key_to_str(key), hash_val );
#endif
  
  return (guint) hash_val;
}

static guint iax_circuit_lookup(const address *address,
				port_type ptype,
				guint32 port,
				guint32 callno)
{
  iax_circuit_key key;
  guint32 *circuit_id_p;

  key.addr = *address;
  key.ptype = ptype;
  key.port = port;
  key.callno = callno;

#ifdef DEBUG_HASHING
  g_message( "+++ looking up key: %s", key_to_str(&key));
#endif
  
  circuit_id_p = g_hash_table_lookup( iax_circuit_hashtab, &key);
  if( ! circuit_id_p ) {
    iax_circuit_key *new_key;

    new_key = g_mem_chunk_alloc(iax_circuit_keys);
    COPY_ADDRESS(&new_key->addr, address);
    new_key->ptype = ptype;
    new_key->port = port;
    new_key->callno = callno;

    circuit_id_p = g_mem_chunk_alloc(iax_circuit_vals);
    *circuit_id_p = ++circuitcount;

    g_hash_table_insert(iax_circuit_hashtab, new_key, circuit_id_p);
  }

#ifdef DEBUG_HASHING
    g_message( "+++ Id: %u", *circuit_id_p );
#endif

  return *circuit_id_p;
}


/* ************************************************************************* */


/* This is our per-call data structure, which is attached to both the
 * forward and reverse circuits.
 */
typedef struct iax_call_data {
  /* For this data, src and dst are relative to the original direction under
     which this call is stored. Obviously if the reversed flag is set true by
     iax_find_call, src and dst are reversed relative to the direction the
     actual source and destination of the data.

     if the codec changes mid-call, we update it here; because we store a codec
     number with each packet too, we handle going back to earlier packets
     without problem.
  */

  iax_dataformat_t dataformat;
  guint32 src_codec, dst_codec;
  guint32 src_vformat, dst_vformat;

  guint forward_circuit_id;
  guint reverse_circuit_id;

  guint callno;
} iax_call_data;

static guint callcount = 0;

static GMemChunk *iax_call_datas = NULL;

static void iax_init_hash( void )
{
  if (iax_circuit_hashtab)
    g_hash_table_destroy(iax_circuit_hashtab);

  if (iax_circuit_keys)
    g_mem_chunk_destroy(iax_circuit_keys);
  if (iax_circuit_vals)
    g_mem_chunk_destroy(iax_circuit_vals);
  if (iax_call_datas)
    g_mem_chunk_destroy(iax_call_datas);

  iax_circuit_hashtab = g_hash_table_new(iax_circuit_hash, iax_circuit_equal);

  iax_circuit_keys = g_mem_chunk_create(iax_circuit_key,
					2*IAX_INIT_PACKET_COUNT,
					G_ALLOC_ONLY);
  iax_circuit_vals = g_mem_chunk_create(iax_circuit_key,
					2*IAX_INIT_PACKET_COUNT,
					G_ALLOC_ONLY);

  iax_call_datas = g_mem_chunk_create(iax_call_data,
				      IAX_INIT_PACKET_COUNT,
				      G_ALLOC_ONLY);
  circuitcount = 0;
  callcount = 0;
}


static iax_call_data *iax_lookup_circuit_details_from_dest( guint src_circuit_id,
							    guint dst_circuit_id,
							    guint framenum,
							    gboolean *reversed_p,
							    circuit_t **circuit_p)
{
  circuit_t *dst_circuit;
  iax_call_data * iax_call;
  gboolean reversed = FALSE;
  
  dst_circuit = find_circuit( CT_IAX2,
			      dst_circuit_id,
			      framenum );

  if( !dst_circuit ) {
#ifdef DEBUG_HASHING
    g_message( "++ destination circuit not found, must have missed NEW packet" );
#endif
    return NULL;
  }

#ifdef DEBUG_HASHING
  g_message( "++ found destination circuit" );
#endif
      
  iax_call = (iax_call_data *)circuit_get_proto_data(dst_circuit,proto_iax2);

  /* there's no way we can create a CT_IAX2 circuit without adding
     iax call data to it; assert this */
  g_assert(iax_call);
  
  if( dst_circuit_id == iax_call -> forward_circuit_id ) {
#ifdef DEBUG_HASHING
    g_message( "++ destination circuit matches forward_circuit_id of call, "
	       "therefore packet is reversed" );
#endif

    reversed = TRUE;

    if( iax_call -> reverse_circuit_id == 0 ) {
      circuit_t *rev_circuit;
      
      /* we are going in the reverse direction, and this call
	 doesn't have a reverse circuit associated with it.
	 create one now. */
#ifdef DEBUG_HASHING
      g_message( "++ reverse_circuit_id of call is zero, need to create a "
		 "new reverse circuit for this call" );
#endif

      iax_call -> reverse_circuit_id = src_circuit_id;
      rev_circuit = circuit_new(CT_IAX2,
				src_circuit_id,
				framenum );
      circuit_add_proto_data(rev_circuit, proto_iax2, iax_call);
	
      /* we should have already set up a subdissector for the forward
       * circuit. we'll need to copy it to the reverse circuit. */
      circuit_set_dissector(rev_circuit, circuit_get_dissector(dst_circuit));
#ifdef DEBUG_HASHING
      g_message( "++ done" );
#endif
    } else if( iax_call -> reverse_circuit_id != src_circuit_id ) {
      g_warning( "IAX Packet %u from circuit ids %u->%u"
		 "conflicts with earlier call with circuit ids %u->%u",
		 framenum,
		 src_circuit_id,dst_circuit_id,
		 iax_call->forward_circuit_id,
		 iax_call->reverse_circuit_id);
      return NULL;
    }
  } else if ( dst_circuit_id == iax_call -> reverse_circuit_id ) {
#ifdef DEBUG_HASHING
    g_message( "++ destination circuit matches reverse_circuit_id of call, "
	       "therefore packet is forward" );
#endif

    reversed = FALSE;
    if( iax_call -> forward_circuit_id != src_circuit_id ) {
      g_warning( "IAX Packet %u from circuit ids %u->%u"
		 "conflicts with earlier call with circuit ids %u->%u",
		 framenum,
		 src_circuit_id,dst_circuit_id,
		 iax_call->forward_circuit_id,
		 iax_call->reverse_circuit_id);
      return NULL;
    }
  } else {
    g_assert_not_reached();
  }


  if( circuit_p ) {
    /* by now we've created a new circuit if one was necessary, or
       bailed out if it looks like a conflict, and we should be able
       to look up the source circuit without issue */
    *circuit_p = find_circuit( CT_IAX2, 
			       src_circuit_id,
			       framenum );
    g_assert(*circuit_p);
  }

  if( reversed_p )
    *reversed_p = reversed;

  return iax_call;
}

  
  /* looks up a circuit_t and an iax_call for this packet */
static iax_call_data *iax_lookup_circuit_details( packet_info *pinfo, 
						 guint32 scallno,
						 guint32 dcallno,
						 gboolean *reversed_p,
						 circuit_t **circuit_p)
{
  gboolean reversed = FALSE;
  iax_call_data *iax_call = NULL;
  guint src_circuit_id;
  circuit_t *src_circuit = NULL;

#ifdef DEBUG_HASHING
  g_message( "++ iax_lookup_circuit_details: Looking up circuit for frame %u, "
	     "from {%s:%u:%u} to {%s:%u:%u}", pinfo->fd->num,
	     address_to_str(&pinfo->src),pinfo->srcport,scallno,
	     address_to_str(&pinfo->dst),pinfo->destport,dcallno);
#endif


  src_circuit_id = iax_circuit_lookup(&pinfo->src,pinfo->ptype,
				      pinfo->srcport,scallno);


  /* the most reliable indicator of call is the destination callno, if
     we have one */
  if( dcallno != 0 ) {
    guint dst_circuit_id;
#ifdef DEBUG_HASHING
    g_message( "++ dcallno non-zero, looking up destination circuit" );
#endif

    dst_circuit_id = iax_circuit_lookup(&pinfo->dst,pinfo->ptype,
					pinfo->destport,dcallno);

    iax_call = iax_lookup_circuit_details_from_dest(src_circuit_id, dst_circuit_id, pinfo->fd->num, &reversed, &src_circuit);
  } else {

    /* in all other circumstances, the source circuit should already
     * exist: its absense indicates that we missed the all-important NEW
     * packet.
     */

    src_circuit = find_circuit( CT_IAX2,
			    src_circuit_id,
			    pinfo->fd->num );

    if( src_circuit ) {
      iax_call = (iax_call_data *)circuit_get_proto_data(src_circuit,proto_iax2);

      /* there's no way we can create a CT_IAX2 circuit without adding
	 iax call data to it; assert this */
      g_assert(iax_call);

      if( src_circuit_id == iax_call -> forward_circuit_id )
	reversed = FALSE;
      else if ( src_circuit_id == iax_call -> reverse_circuit_id )
	reversed = TRUE;
      else {
	/* there's also no way we can attach an iax_call_data to a circuit
	   without the circuit being either the forward or reverse circuit
	   for that call; assert this too.
	*/
	g_assert_not_reached();
      }
    }
  }

  if(src_circuit && iax_call) {
    /* info for subdissectors. We always pass on the forward circuit,
     * and steal the p2p_dir flag to indicate the direction */
    pinfo -> ctype = CT_IAX2;
    pinfo -> circuit_id = (guint32)iax_call->forward_circuit_id;
    pinfo -> p2p_dir = reversed?P2P_DIR_RECV:P2P_DIR_SENT;
  }

  if(reversed_p)
    *reversed_p = reversed;

  if(circuit_p)
    *circuit_p = src_circuit;

#ifdef DEBUG_HASHING
  if( iax_call ) {
    g_message( "++ Found call for packet: id %u, reversed=%c", iax_call->callno, reversed?'1':'0' );
  } else {
    g_message( "++ Call not found. Must have missed the NEW packet?" );
  }
#endif
  
  return iax_call;
}


/* handles a NEW packet by creating a new iax call and forward circuit.
   the reverse circuit is not created until the ACK is received and
   is created by iax_lookup_circuit_details. */
static iax_call_data *iax_new_circuit_details( packet_info *pinfo, 
					      guint32 scallno,
					      circuit_t **circuit_p)
{
  circuit_t *circuit;
  iax_call_data *call;
  guint circuit_id;
    
#ifdef DEBUG_HASHING
  g_message( "+ new_circuit: Handling NEW packet, frame %u", pinfo->fd->num );
#endif
  
    circuit_id = iax_circuit_lookup(&pinfo->src,pinfo->ptype,
				    pinfo->srcport,scallno);
    
    circuit = circuit_new(CT_IAX2,
			  circuit_id,
			  pinfo->fd->num );

    

    call = g_mem_chunk_alloc(iax_call_datas);
    call -> dataformat = 0;
    call -> src_codec = 0;
    call -> dst_codec = 0;
    call -> forward_circuit_id = circuit_id;
    call -> reverse_circuit_id = 0;
    call -> callno = ++callcount;

#ifdef DEBUG_HASHING
    g_message( "+ new_circuit: Added new circuit for new call %u", call -> callno );
#endif

    circuit_add_proto_data( circuit, proto_iax2, call );

  if( circuit_p )
    *circuit_p = circuit;

  return call;
}
    

/* ************************************************************************* */

/* per-packet data */
typedef struct iax_packet_data {
  iax_call_data *call_data;
  guint32 codec;
} iax_packet_data;

static GMemChunk *iax_packets = NULL;

static iax_packet_data *iax_new_packet_data(iax_call_data *call)
{
  iax_packet_data *p = g_mem_chunk_alloc(iax_packets);
  p->call_data=call;
  p->codec=0;
  return p;
}


/* ************************************************************************* */

static guint32 dissect_fullpacket (tvbuff_t * tvb, guint32 offset,
				guint16 scallno,
				packet_info * pinfo,
				proto_tree * iax2_tree,
				proto_tree * main_tree);


static guint32 dissect_minipacket (tvbuff_t * tvb, guint32 offset, 
				guint16 scallno,
				packet_info * pinfo,
				proto_tree * iax2_tree,
				proto_tree * main_tree);

static guint32 dissect_minivideopacket (tvbuff_t * tvb, guint32 offset, 
					guint16 scallno,
					packet_info * pinfo,
					proto_tree * iax2_tree,
					proto_tree * main_tree);

static void dissect_payload(tvbuff_t *tvb, guint32 offset,
			    packet_info *pinfo, proto_tree *tree,
			    guint32 ts, gboolean video,
			    iax_packet_data *iax_packet);



static void
dissect_iax2 (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *iax2_item = NULL;
  proto_tree *iax2_tree = NULL;
  proto_tree *full_mini_subtree = NULL;
  guint32 offset = 0, len;
  guint16 scallno = 0;
  guint16 stmp;
  packet_type type;

  /* set up the protocol and info fields in the summary pane */
  if (check_col (pinfo->cinfo, COL_PROTOCOL))
    {
      col_set_str (pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_IAX2);
    }
  if (check_col (pinfo->cinfo, COL_INFO))
    {
      col_clear (pinfo->cinfo, COL_INFO);
    }

  /* add the 'iax2' tree to the main tree */
  if (tree)
    {
      iax2_item = proto_tree_add_item (tree, proto_iax2, tvb, offset, -1, FALSE);
      iax2_tree = proto_item_add_subtree (iax2_item, ett_iax2);
    }

  stmp = tvb_get_ntohs(tvb, offset);
  if( stmp == 0 ) {
    /* starting with 0x0000 indicates either a mini video packet or a 'meta'
     * packet, whatever that means */
    offset+=2;
    stmp = tvb_get_ntohs(tvb, offset);
    if( stmp & 0x8000 ) {
      /* mini video packet */
      type = IAX2_MINI_VIDEO_PACKET;
      scallno = stmp & 0x7FFF;
      offset += 2;
    }
    else {
      type = IAX2_META_PACKET;
    }
  } else {
    /* The source call/fullpacket flag is common to both mini and full packets */
    scallno = tvb_get_ntohs(tvb, offset);
    offset += 2;
    if( scallno & 0x8000 )
      type = IAX2_FULL_PACKET;
    else {
      type = IAX2_MINI_VOICE_PACKET;
    }
    scallno &= 0x7FFF;
  }

  if( tree ) {
    proto_item *full_mini_base;

    full_mini_base = proto_tree_add_uint(iax2_tree, hf_iax2_packet_type, tvb, 0, offset, type);
    full_mini_subtree = proto_item_add_subtree(full_mini_base, ett_iax2_full_mini_subtree);

    if( scallno != 0 )
      proto_tree_add_item (full_mini_subtree, hf_iax2_scallno, tvb, offset-2, 2, FALSE);
  }

  switch( type ) {
    case IAX2_FULL_PACKET:
      len = dissect_fullpacket( tvb, offset, scallno, pinfo, full_mini_subtree, tree );
      break;
    case IAX2_MINI_VOICE_PACKET:
      len = dissect_minipacket( tvb, offset, scallno, pinfo, full_mini_subtree, tree );
      break;
    case IAX2_MINI_VIDEO_PACKET:
      len = dissect_minivideopacket( tvb, offset, scallno, pinfo, full_mini_subtree, tree );
      break;
    case IAX2_META_PACKET:
      /* not implemented yet */
      len = 0;
      break;
    default:
      len = 0;
  }

  /* update the 'length' of the main IAX2 header field so that it covers just the headers,
     not the audio data. */
  proto_item_set_len(iax2_item, len);
}


/* dissect the information elements in an IAX frame. Returns the updated offset */
static guint32 dissect_ies (tvbuff_t * tvb, guint32 offset,
			    proto_tree * iax_tree,
			    iax_call_data *iax_call_data )
{
  proto_tree *sockaddr_tree = NULL;
  proto_item *sockaddr_item = 0;


  while (offset < tvb_reported_length (tvb)) {

    int ies_type = tvb_get_guint8(tvb, offset);
    int ies_len = tvb_get_guint8(tvb, offset + 1);

    if( iax_tree ) {
      proto_item *ti;
      proto_tree *ies_tree;

      ti = proto_tree_add_text(iax_tree, tvb, offset, ies_len+2,
			       "Information Element: %s (0x%02X)",
			       val_to_str(ies_type, iax_ies_type, 
					  "Unknown information element"),
			       ies_type);


      ies_tree = proto_item_add_subtree(ti, ett_iax2_ie);
      
      proto_tree_add_text(ies_tree, tvb, offset, 1, "IE id: %s (0x%02X)",
			  val_to_str(ies_type, iax_ies_type, "Unknown"),
			  ies_type);

      proto_tree_add_text(ies_tree, tvb, offset+1, 1, "Length: %u",ies_len);


      switch (ies_type) {
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
	    {
	      proto_tree *codec_tree;
	      proto_item *codec_base;

	      codec_base =
		proto_tree_add_item (ies_tree, hf_IAX_IE_CAPABILITY,
				     tvb, offset + 2, ies_len, FALSE);
	      codec_tree =
		proto_item_add_subtree (codec_base, ett_iax2_codecs);
	      
	      proto_tree_add_item(codec_tree, hf_iax2_cap_g723_1, tvb, offset + 2, ies_len, FALSE );
	      proto_tree_add_item(codec_tree, hf_iax2_cap_gsm, tvb, offset + 2, ies_len, FALSE );
	      proto_tree_add_item(codec_tree, hf_iax2_cap_ulaw, tvb, offset + 2, ies_len, FALSE );
	      proto_tree_add_item(codec_tree, hf_iax2_cap_alaw, tvb, offset + 2, ies_len, FALSE );
	      proto_tree_add_item(codec_tree, hf_iax2_cap_g726, tvb, offset + 2, ies_len, FALSE );
	      proto_tree_add_item(codec_tree, hf_iax2_cap_adpcm, tvb, offset + 2, ies_len, FALSE );
	      proto_tree_add_item(codec_tree, hf_iax2_cap_slinear, tvb, offset + 2, ies_len, FALSE );
	      proto_tree_add_item(codec_tree, hf_iax2_cap_lpc10, tvb, offset + 2, ies_len, FALSE );
	      proto_tree_add_item(codec_tree, hf_iax2_cap_g729a, tvb, offset + 2, ies_len, FALSE );
	      proto_tree_add_item(codec_tree, hf_iax2_cap_speex, tvb, offset + 2, ies_len, FALSE );
	      proto_tree_add_item(codec_tree, hf_iax2_cap_ilbc, tvb, offset + 2, ies_len, FALSE );
	      proto_tree_add_item(codec_tree, hf_iax2_cap_jpeg, tvb, offset + 2, ies_len, FALSE );
	      proto_tree_add_item(codec_tree, hf_iax2_cap_png, tvb, offset + 2, ies_len, FALSE );
	      proto_tree_add_item(codec_tree, hf_iax2_cap_h261, tvb, offset + 2, ies_len, FALSE );
	      proto_tree_add_item(codec_tree, hf_iax2_cap_h263, tvb, offset + 2, ies_len, FALSE );
	      break;
	    }
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
	      sockaddr_item = proto_tree_add_text(ies_tree, tvb, offset + 2, 16, "Apparent Address");
	      sockaddr_tree = proto_item_add_subtree(sockaddr_item, ett_iax2_ies_apparent_addr);
	      proto_tree_add_item(sockaddr_tree, hf_IAX_IE_APPARENTADDR_SINADDR, tvb, offset + 6, 4, FALSE);
	      proto_tree_add_item(sockaddr_tree, hf_IAX_IE_APPARENTADDR_SINPORT, tvb, offset + 4, 2, FALSE);
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
	      
      case IAX_IE_DATAFORMAT:
	proto_tree_add_item (ies_tree, hf_IAX_IE_DATAFORMAT, tvb,
			     offset + 2, ies_len, FALSE);

	if( iax_call_data )
	  iax_call_data -> dataformat = tvb_get_ntohl(tvb, offset+2);
	    
	break;

      default:
      {
	switch(ies_len) {
	case 1:
	  proto_tree_add_item( ies_tree, hf_IAX_IE_UNKNOWN_BYTE, tvb, offset+2, ies_len, FALSE );
	  break;
	  
	case 2:
	  proto_tree_add_item( ies_tree, hf_IAX_IE_UNKNOWN_I16, tvb, offset+2, ies_len, FALSE );
	  break;
	
	case 4:
	  proto_tree_add_item( ies_tree, hf_IAX_IE_UNKNOWN_I32, tvb, offset+2, ies_len, FALSE );
	  break;

	default:
	  proto_tree_add_item( ies_tree, hf_IAX_IE_UNKNOWN_BYTES, tvb, offset+2, ies_len, FALSE );
	}
      }
      }
    }
    offset += ies_len + 2;
  }
  return offset;
}

static guint32 uncompress_subclass(guint8 csub)
{
  /* If the SC_LOG flag is set, return 2^csub otherwise csub */
  if (csub & 0x80) {
    /* special case for 'compressed' -1 */
    if (csub == 0xff)
      return (guint32)-1;
    else
      return 1 << (csub & 0x1F);
  }
  else
    return (guint32)csub;
}


static guint32
dissect_fullpacket (tvbuff_t * tvb, guint32 offset, 
		    guint16 scallno,
		    packet_info * pinfo, proto_tree * iax2_tree,
		    proto_tree * main_tree)
{
  guint32 retransmission = 0;
  guint16 dcallno;
  guint32 ts;
  guint8 type;
  guint8 csub;
  guint32 codec;

  proto_tree *packet_type_tree = NULL;
  iax_call_data *iax_call;
  iax_packet_data *iax_packet;
  gboolean reversed;
  gboolean rtp_marker;

  circuit_t *circuit;

      /*
       * remove the top bit for retransmission detection 
       */
      dcallno = tvb_get_ntohs(tvb, offset);
      retransmission = dcallno & 0x8000;
      dcallno = dcallno & 0x7FFF;
      ts = tvb_get_ntohl(tvb, offset+2);
      type = tvb_get_guint8(tvb, offset + 8);
      csub = tvb_get_guint8(tvb, offset + 9);

  /* see if we've seen this packet before */
  iax_packet = (iax_packet_data *)p_get_proto_data(pinfo->fd,proto_iax2);
  if( !iax_packet ) {
    /* if not, find or create an iax_call info structure for this IAX session. */

    if( type == AST_FRAME_IAX && csub == IAX_COMMAND_NEW ) {
      /* NEW packets start a new call */
      iax_call = iax_new_circuit_details(pinfo,scallno,&circuit);
      reversed = FALSE;
    } else {
      iax_call = iax_lookup_circuit_details(pinfo, scallno, dcallno,
				       &reversed, &circuit);
    }

    iax_packet = iax_new_packet_data(iax_call);
    p_add_proto_data(pinfo->fd,proto_iax2,iax_packet);
  } else {
    iax_call = iax_packet->call_data;
  }
   
  if( iax2_tree ) {
      proto_item *packet_type_base;

      proto_tree_add_item (iax2_tree, hf_iax2_dcallno, tvb, offset, 2, FALSE );
      proto_tree_add_boolean(iax2_tree, hf_iax2_retransmission, tvb, offset, 2, FALSE );

      proto_tree_add_uint (iax2_tree, hf_iax2_ts, tvb, offset+2, 4, ts);

      proto_tree_add_item (iax2_tree, hf_iax2_oseqno, tvb, offset+6, 1,
			   FALSE);

      proto_tree_add_item (iax2_tree, hf_iax2_iseqno, tvb, offset+7, 1,
			   FALSE);
      packet_type_base = proto_tree_add_uint (iax2_tree, hf_iax2_type, tvb,
					      offset+8, 1, type);

      /* add the type-specific subtree */
      packet_type_tree = proto_item_add_subtree (packet_type_base, ett_iax2_type);
  }

  /* add frame type to info line */
  if (check_col (pinfo->cinfo, COL_INFO)) {
    col_add_fstr (pinfo->cinfo, COL_INFO, "%s, source call# %d, timestamp %ums",
		  val_to_str (type, iax_frame_types, "Unknown (0x%02x)"),
		  scallno, ts);
  }

  switch( type ) {
  case AST_FRAME_IAX:
    /* add the subclass */
    proto_tree_add_uint (packet_type_tree, hf_iax2_iax_csub, tvb,
			   offset+9, 1, csub);
    offset += 10;

    if (check_col (pinfo->cinfo, COL_INFO))
      col_append_fstr (pinfo->cinfo, COL_INFO, " %s", 
		    val_to_str (csub, iax_iax_subclasses, "unknown (0x%02x)"));

    if (offset < tvb_reported_length (tvb)) {
      offset += dissect_ies(tvb, offset, packet_type_tree, iax_call);
    }

    if( csub == IAX_COMMAND_NEW && circuit && iax_call ) {
      /* if this is a data call, set up a subdissector for the circuit */
      dissector_handle_t s;
      s = dissector_get_port_handle(iax2_dataformat_dissector_table, iax_call -> dataformat );
      circuit_set_dissector( circuit, s );
    }
    break;

  case AST_FRAME_DTMF:
    proto_tree_add_text (packet_type_tree, tvb, offset+9, 1, "DTMF digit: %c", csub);
    offset += 10;

    if (check_col (pinfo->cinfo, COL_INFO))
      col_append_fstr (pinfo->cinfo, COL_INFO, " digit %c", csub );
    break;

  case AST_FRAME_CONTROL:
    /* add the subclass */
    proto_tree_add_uint (packet_type_tree, hf_iax2_cmd_csub, tvb,
			 offset+9, 1, csub);
    offset += 10;

    if (check_col (pinfo->cinfo, COL_INFO))
      col_append_fstr (pinfo->cinfo, COL_INFO, " %s",
		    val_to_str (csub, iax_cmd_subclasses, "unknown (0x%02x)"));
    break;

  case AST_FRAME_VOICE:
    /* add the codec */
    iax_packet -> codec = codec = uncompress_subclass(csub);

    if( packet_type_tree ) {
      proto_tree_add_item (packet_type_tree, hf_iax2_voice_csub, tvb, offset+9, 1, FALSE);
      proto_tree_add_uint (packet_type_tree, hf_iax2_voice_codec, tvb, offset+9, 1, codec);
    }

    offset += 10;

    if( iax_call ) {
      if( reversed ) {
	iax_call->dst_codec = codec;
      } else {
	iax_call->src_codec = codec;
      }
    }

    dissect_payload(tvb, offset, pinfo, main_tree, ts, FALSE,iax_packet);
    break;

  case AST_FRAME_VIDEO:
    /* bit 6 of the csub is used to represent the rtp 'marker' bit */
    rtp_marker = csub & 0x40 ? TRUE:FALSE;
    iax_packet -> codec = codec = uncompress_subclass((guint8) (csub & ~40));

    if( packet_type_tree ) {
      proto_tree_add_item (packet_type_tree, hf_iax2_video_csub, tvb, offset+9, 1, FALSE);
      proto_tree_add_item (packet_type_tree, hf_iax2_marker, tvb, offset+9, 1, FALSE);
      proto_tree_add_uint (packet_type_tree, hf_iax2_video_codec, tvb, offset+9, 1, codec);
    }

    offset += 10;

    if( iax_call ) {
      if( reversed ) {
	iax_call->dst_vformat = codec;
      } else {
	iax_call->src_vformat = codec;
      }
    }

    if( rtp_marker && check_col (pinfo->cinfo, COL_INFO))
      col_append_fstr (pinfo->cinfo, COL_INFO, ", Mark" );


    dissect_payload(tvb, offset, pinfo, main_tree, ts, TRUE, iax_packet);
    break;


  default:
    proto_tree_add_uint (packet_type_tree, hf_iax2_csub, tvb, offset+9,
			 1, csub);
    offset += 10;

    if (check_col (pinfo->cinfo, COL_INFO))
      col_append_fstr (pinfo->cinfo, COL_INFO, " subclass %d", csub );
    break;
  }

  return offset;
}

static iax_packet_data *iax2_get_packet_data_for_minipacket(packet_info * pinfo,
							    guint16 scallno,
							    gboolean video)
{
  /* see if we've seen this packet before */
  iax_packet_data *p = (iax_packet_data *)p_get_proto_data(pinfo->fd,proto_iax2);

  if( !p ) {
    /* if not, find or create an iax_call info structure for this IAX session. */
    gboolean reversed;
    circuit_t *circuit;
    iax_call_data *iax_call;

    iax_call = iax_lookup_circuit_details(pinfo, scallno, 0, &reversed, &circuit);

    p = iax_new_packet_data(iax_call);
    p_add_proto_data(pinfo->fd,proto_iax2,p);

    /* set the codec for this frame to be whatever the last full frame used */
    if( iax_call ) {
     if( video ) 
        p->codec = reversed ? iax_call -> dst_vformat : iax_call -> src_vformat;
      else 
        p->codec = reversed ? iax_call -> dst_codec : iax_call -> src_codec;
    }
  }
  return p;
}


static guint32 dissect_minivideopacket (tvbuff_t * tvb, guint32 offset,
					guint16 scallno, packet_info * pinfo,
					proto_tree * iax2_tree, proto_tree *main_tree)
{
  guint32 ts;
  iax_packet_data *iax_packet;
  gboolean rtp_marker;

  ts = tvb_get_ntohs(tvb, offset);

  /* bit 15 of the ts is used to represent the rtp 'marker' bit */
  rtp_marker = ts & 0x8000 ? TRUE:FALSE;
  ts &= ~0x8000;


  if( iax2_tree ) {
    proto_tree_add_item (iax2_tree, hf_iax2_minividts, tvb, offset, 2, FALSE);
    proto_tree_add_item (iax2_tree, hf_iax2_minividmarker, tvb, offset, 2, FALSE);
  }

  offset += 2;
  
  iax_packet = iax2_get_packet_data_for_minipacket(pinfo, scallno, TRUE);
  
  if (check_col (pinfo->cinfo, COL_INFO))
      col_add_fstr (pinfo->cinfo, COL_INFO, 
		    "Mini video packet, source call# %d, timestamp %ums%s",
		    scallno, ts, rtp_marker?", Mark":"");


  dissect_payload(tvb, offset, pinfo, main_tree, ts, TRUE, iax_packet);

  return offset;
}

static guint32
dissect_minipacket (tvbuff_t * tvb, guint32 offset, guint16 scallno, packet_info * pinfo, proto_tree * iax2_tree,
		    proto_tree *main_tree)
{
  guint32 ts;
  iax_packet_data *iax_packet;

  ts = tvb_get_ntohs(tvb, offset);

  iax_packet = iax2_get_packet_data_for_minipacket(pinfo, scallno, FALSE);
  
  proto_tree_add_uint (iax2_tree, hf_iax2_minits, tvb, offset, 2,
		       ts);
  offset += 2;
  
  if (check_col (pinfo->cinfo, COL_INFO))
      col_add_fstr (pinfo->cinfo, COL_INFO, 
		    "Mini packet, source call# %d, timestamp %ums",
		    scallno, ts);


  /* XXX fix the timestamp logic */
  dissect_payload(tvb, offset, pinfo, main_tree, ts, FALSE, iax_packet);


  return offset;
}

static void dissect_payload(tvbuff_t *tvb, guint32 offset,
			    packet_info *pinfo, proto_tree *tree,
			    guint32 ts, gboolean video,
			    iax_packet_data *iax_packet)
{
  gboolean out_of_order = FALSE;
  tvbuff_t *sub_tvb;
  guint32 codec = iax_packet -> codec;
  iax_call_data *iax_call = iax_packet -> call_data;

  /* keep compiler quiet */
  ts = ts;

  if( offset >= tvb_reported_length (tvb)) {
    if (check_col (pinfo->cinfo, COL_INFO))
      col_append_fstr (pinfo->cinfo, COL_INFO, ", empty frame" );
    return;
  }

  sub_tvb = tvb_new_subset(tvb, offset, -1, -1 );

  /* XXX shouldn't pass through out-of-order packets. */

  if (check_col (pinfo->cinfo, COL_INFO)) {
    if( !video && iax_call && iax_call -> dataformat != 0 ) {
      col_append_fstr (pinfo->cinfo, COL_INFO, ", data, format %s",
		       val_to_str (iax_call -> dataformat, 
				   iax_dataformats, "unknown (0x%02x)"));

      if( out_of_order )
	col_append_fstr (pinfo->cinfo, COL_INFO, " (out-of-order packet)");
    } else {
      col_append_fstr (pinfo->cinfo, COL_INFO, ", %s",
		       val_to_str (codec, codec_types, "unknown (0x%02x)"));
    }
  }

  /* pass the rest of the block to a subdissector */
  if( !video && try_circuit_dissector(pinfo->ctype, pinfo->circuit_id, pinfo->fd->num,
			    sub_tvb, pinfo, tree))
    return;

  if( codec != 0 && dissector_try_port(iax2_codec_dissector_table, codec, sub_tvb, pinfo, tree ))
    return;
  
  /* we don't know how to dissect our data: dissect it as data */
  call_dissector(data_handle,sub_tvb, pinfo, tree);
}

/*
 * Init routines
 */

/* called at the start of a capture. We should clear out our static, per-capture
 * data.
 */

static void
iax_init_protocol(void)
{
  iax_init_hash();

  if (iax_packets)
    g_mem_chunk_destroy(iax_packets);
  iax_packets = g_mem_chunk_create(iax_packet_data,128,G_ALLOC_ONLY);
}


void
proto_register_iax2 (void)
{
  /* we use this for displaying which codecs are supported */
  static const true_false_string supported_strings = {
    "Supported",
    "Not supported"
  };

  /* A header field is something you can search/filter on.
   * 
   * We create a structure to register our fields. It consists of an
   * array of hf_register_info structures, each of which are of the format
   * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
   */
   
  static hf_register_info hf[] = {

    {&hf_iax2_packet_type,
     {"Packet type", "iax2.type", FT_UINT8, BASE_DEC, VALS(iax_packet_types), 0,
      "Full/minivoice/minivideo/meta packet",
      HFILL}},


    {&hf_iax2_scallno,
     {"Source call", "iax2.src_call", FT_UINT16, BASE_DEC, NULL, 0x7FFF,
      "src_call holds the number of this call at the packet source pbx",
      HFILL}},

    /* FIXME could this be turned into a FRAMENUM field? */
    {&hf_iax2_dcallno,
     {"Destination call", "iax2.dst_call", FT_UINT16, BASE_DEC, NULL, 0x7FFF,
      "dst_call holds the number of this call at the packet destination",
      HFILL}},

    {&hf_iax2_retransmission,
     {"Retransmission", "iax2.retransmission", FT_BOOLEAN, 16,
      NULL, 0x8000,
      "retransmission is set if this packet is a retransmission of an earlier "
      "failed packet", HFILL}},

    {&hf_iax2_ts,
     {"Timestamp", "iax2.timestamp", FT_UINT32, BASE_DEC, NULL, 0x0,
      "timestamp is the time, in ms after the start of this call, at which "
      "this packet was transmitted",
      HFILL}},

    {&hf_iax2_minits,
     {"Timestamp", "iax2.timestamp", FT_UINT16, BASE_DEC, NULL, 0x0,
      "timestamp is the time, in ms after the start of this call, at which "
      "this packet was transmitted",
      HFILL}},

    {&hf_iax2_minividts,
     {"Timestamp", "iax2.timestamp", FT_UINT16, BASE_DEC, NULL, 0x7FFF,
      "timestamp is the time, in ms after the start of this call, at which "
      "this packet was transmitted",
      HFILL}},

    {&hf_iax2_minividmarker,
     {"Marker", "iax2.video.marker", FT_UINT16, BASE_DEC, NULL, 0x8000,
      "RTP end-of-frame marker",
      HFILL}},

    {&hf_iax2_oseqno,
     {"Outbound seq.no.", "iax2.oseqno", FT_UINT16, BASE_DEC, NULL,
      0x0, 
      "oseqno is the sequence no of this packet. The first packet has "
      "oseqno==0, and subsequent packets increment the oseqno by 1",
      HFILL}},

    {&hf_iax2_iseqno,
     {"Inbound seq.no.", "iax2.iseqno", FT_UINT16, BASE_DEC, NULL, 0x0,
      "iseqno is the sequence no of the last successfully recieved packet",
      HFILL}},

    {&hf_iax2_type,
     {"Type", "iax2.type", FT_UINT8, BASE_DEC, VALS (iax_frame_types),
      0x0,
      "For full IAX2 frames, type is the type of frame",
      HFILL}},

    {&hf_iax2_csub,
     {"Sub-class", "iax2.subclass", FT_UINT8, BASE_DEC, NULL, 0x0, 
      "subclass",
      HFILL}},

    {&hf_iax2_cmd_csub,
     {"Control subclass", "iax2.control.subclass", FT_UINT8, BASE_DEC,
      VALS (iax_cmd_subclasses), 0x0, 
      "This gives the command number for a Control packet.", HFILL}},

    {&hf_iax2_iax_csub,
     {"IAX type", "iax2.iax.subclass", FT_UINT8, BASE_DEC,
      VALS (iax_iax_subclasses),
      0x0, 
      "IAX type gives the command number for IAX signalling packets", HFILL}},

    {&hf_iax2_voice_csub,
     {"Sub-class", "iax2.voice.subclass", FT_UINT8, BASE_DEC, NULL, 0x0, 
      "subclass",
      HFILL}},

    {&hf_iax2_voice_codec,
     {"CODEC", "iax2.voice.codec", FT_UINT32, BASE_HEX, VALS (codec_types),
      0x0, 
      "CODEC gives the codec used to encode audio data", HFILL}},

    {&hf_iax2_video_csub,
     {"Subclass (compressed codec no)", "iax2.video.subclass", FT_UINT8, BASE_DEC, NULL, 0xBF, 
      "Subclass (compressed codec no)",
      HFILL}},
    
    {&hf_iax2_marker,
     {"Marker", "iax2.video.marker", FT_BOOLEAN, 8, NULL, 0x40,
      "RTP end-of-frame marker",
      HFILL}},

    {&hf_iax2_video_codec,
     {"CODEC", "iax2.video.codec", FT_UINT32, BASE_HEX, VALS (codec_types), 0, 
      "The codec used to encode video data", HFILL}},
    
    /*
     * Decoding for the ies
     */

    {&hf_IAX_IE_APPARENTADDR_SINFAMILY,
     {"Family", "iax2.iax.app_addr.sinfamily", FT_UINT16, BASE_DEC, NULL, 0, "Family", HFILL }},
    {&hf_IAX_IE_APPARENTADDR_SINPORT,
     {"Port", "iax2.iax.app_addr.sinport", FT_UINT16, BASE_DEC, NULL, 0, "Port", HFILL }},
    {&hf_IAX_IE_APPARENTADDR_SINADDR,
     {"Address", "iax2.iax.app_addr.sinaddr", FT_IPv4, BASE_HEX, NULL, 0, "Address", HFILL }},
    {&hf_IAX_IE_APPARENTADDR_SINZERO,
     {"Zero", "iax2.iax.app_addr.sinzero", FT_BYTES, BASE_HEX, NULL, 0, "Zero", HFILL }},

    {&hf_IAX_IE_CALLED_NUMBER,
     {"Number/extension being called", "iax2.iax.called_number",
      FT_STRING,
      BASE_NONE, NULL, 0x0, "", HFILL}},

    {&hf_IAX_IE_CALLING_NUMBER,
     {"Calling number", "iax2.iax.calling_number", FT_STRING,
      BASE_NONE, NULL,
      0x0, "", HFILL}},

    {&hf_IAX_IE_CALLING_ANI,
     {"Calling number ANI for billing", "iax2.iax.calling_ani",
      FT_STRING,
      BASE_NONE, NULL, 0x0, "", HFILL}},

    {&hf_IAX_IE_CALLING_NAME,
     {"Name of caller", "iax2.iax.calling_name", FT_STRING, BASE_NONE,
      NULL,
      0x0, "", HFILL}},

    {&hf_IAX_IE_CALLED_CONTEXT,
     {"Context for number", "iax2.iax.called_context", FT_STRING,
      BASE_NONE,
      NULL, 0x0, "", HFILL}},

    {&hf_IAX_IE_USERNAME,
     {"Username (peer or user) for authentication",
      "iax2.iax.username",
      FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL}},

    {&hf_IAX_IE_PASSWORD,
     {"Password for authentication", "iax2.iax.password", FT_STRING,
      BASE_NONE, NULL, 0x0, "", HFILL}},

    {&hf_IAX_IE_CAPABILITY,
     {"Actual codec capability", "iax2.iax.capability", FT_UINT32,
      BASE_HEX,
      NULL, 0x0, "", HFILL}},

    {&hf_IAX_IE_FORMAT,
     {"Desired codec format", "iax2.iax.format", FT_UINT32, BASE_HEX,
      VALS (codec_types), 0x0, "", HFILL}},

    {&hf_IAX_IE_LANGUAGE,
     {"Desired language", "iax2.iax.language", FT_STRING, BASE_NONE,
      NULL,
      0x0, "", HFILL}},

    {&hf_IAX_IE_VERSION,
     {"Protocol version", "iax2.iax.version", FT_UINT16, BASE_HEX, NULL,
      0x0,
      "", HFILL}},

    {&hf_IAX_IE_ADSICPE,
     {"CPE ADSI capability", "iax2.iax.cpe_adsi", FT_UINT16, BASE_HEX,
      NULL,
      0x0, "", HFILL}},

    {&hf_IAX_IE_DNID,
     {"Originally dialed DNID", "iax2.iax.dnid", FT_STRING, BASE_NONE,
      NULL,
      0x0, "", HFILL}},

    {&hf_IAX_IE_AUTHMETHODS,
     {"Authentication method(s)", "iax2.iax.auth.methods", FT_UINT16,
      BASE_HEX,
      NULL, 0x0, "", HFILL}},

    {&hf_IAX_IE_CHALLENGE,
     {"Challenge data for MD5/RSA", "iax2.iax.auth.challenge",
      FT_STRING,
      BASE_NONE, NULL, 0x0, "", HFILL}},

    {&hf_IAX_IE_MD5_RESULT,
     {"MD5 challenge result", "iax2.iax.auth.md5", FT_STRING,
      BASE_NONE, NULL,
      0x0, "", HFILL}},

    {&hf_IAX_IE_RSA_RESULT,
     {"RSA challenge result", "iax2.iax.auth.rsa", FT_STRING,
      BASE_NONE, NULL,
      0x0, "", HFILL}},

    {&hf_IAX_IE_REFRESH,
     {"When to refresh registration", "iax2.iax.refresh", FT_INT16,
      BASE_DEC,
      NULL, 0x0, "", HFILL}},

    {&hf_IAX_IE_DPSTATUS,
     {"Dialplan status", "iax2.iax.dialplan_status", FT_UINT16,
      BASE_HEX, NULL,
      0x0, "", HFILL}},

    {&hf_IAX_IE_CALLNO,
     {"Call number of peer", "iax2.iax.call_no", FT_INT16, BASE_DEC,
      NULL,
      0x0, "", HFILL}},

    {&hf_IAX_IE_CAUSE,
     {"Cause", "iax2.iax.cause", FT_STRING, BASE_NONE, NULL, 0x0, "",
      HFILL}},

    {&hf_IAX_IE_IAX_UNKNOWN,
     {"Unknown IAX command", "iax2.iax.iax_unknown", FT_BYTES,
      BASE_HEX, NULL,
      0x0, "", HFILL}},

    {&hf_IAX_IE_MSGCOUNT,
     {"How many messages waiting", "iax2.iax.msg_count", FT_INT16,
      BASE_DEC,
      NULL, 0x0, "", HFILL}},

    {&hf_IAX_IE_AUTOANSWER,
     {"Request auto-answering", "iax2.iax.autoanswer", FT_NONE,
      BASE_NONE,
      NULL, 0x0, "", HFILL}},

    {&hf_IAX_IE_MUSICONHOLD,
     {"Request musiconhold with QUELCH", "iax2.iax.moh", FT_NONE,
      BASE_NONE,
      NULL, 0x0, "", HFILL}},

    {&hf_IAX_IE_TRANSFERID,
     {"Transfer Request Identifier", "iax2.iax.transferid", FT_UINT32,
      BASE_HEX, NULL, 0x0, "", HFILL}},

    {&hf_IAX_IE_RDNIS,
     {"Referring DNIS", "iax2.iax.rdnis", FT_STRING, BASE_NONE, NULL,
      0x0, "",
      HFILL}},

    {&hf_IAX_IE_DATAFORMAT,
     {"Data call format", "iax2.iax.dataformat", FT_UINT32, BASE_HEX,
      VALS(iax_dataformats), 0x0, "", HFILL}},

    {&hf_IAX_IE_UNKNOWN_BYTE,
     {"data", "iax2.iax.unknowndata", FT_UINT8, BASE_HEX, NULL,
      0x0, "Raw data for unknown IEs",
      HFILL}},
    {&hf_IAX_IE_UNKNOWN_I16,
     {"data", "iax2.iax.unknowndata", FT_UINT16, BASE_HEX, NULL,
      0x0, "Raw data for unknown IEs",
      HFILL}},
    {&hf_IAX_IE_UNKNOWN_I32,
     {"data", "iax2.iax.unknowndata", FT_UINT32, BASE_HEX, NULL,
      0x0, "Raw data for unknown IEs",
      HFILL}},
    {&hf_IAX_IE_UNKNOWN_BYTES,
     {"data", "iax2.iax.unknowndata", FT_BYTES, BASE_NONE, NULL,
      0x0, "Raw data for unknown IEs",
      HFILL}},

    /* capablilites */
    {&hf_iax2_cap_g723_1,
     {"G.723.1 compression", "iax2.cap.g723_1", FT_BOOLEAN, 32,
      TFS(&supported_strings), AST_FORMAT_G723_1,
      "G.723.1 compression", HFILL }},

    {&hf_iax2_cap_gsm,
     {"GSM compression", "iax2.cap.gsm", FT_BOOLEAN, 32,
       TFS(&supported_strings), AST_FORMAT_GSM, 
      "GSM compression", HFILL }},

    {&hf_iax2_cap_ulaw,
     {"Raw mu-law data (G.711)", "iax2.cap.ulaw",FT_BOOLEAN, 32,
      TFS(&supported_strings), AST_FORMAT_ULAW,
      "Raw mu-law data (G.711)", HFILL }},

     {&hf_iax2_cap_alaw,
      {"Raw A-law data (G.711)", "iax2.cap.alaw",FT_BOOLEAN, 32,
       TFS(&supported_strings), AST_FORMAT_ALAW,
       "Raw A-law data (G.711)", HFILL }},

    {&hf_iax2_cap_g726,
     {"G.726 compression", "iax2.cap.g726",FT_BOOLEAN, 32,
      TFS(&supported_strings), AST_FORMAT_G726,
      "G.726 compression", HFILL }},

    {&hf_iax2_cap_adpcm,
     {"ADPCM", "iax2.cap.adpcm", FT_BOOLEAN, 32,
      TFS(&supported_strings), AST_FORMAT_ADPCM,
      "ADPCM", HFILL }},
    
    {&hf_iax2_cap_slinear,
     {"Raw 16-bit Signed Linear (8000 Hz) PCM", "iax2.cap.slinear", 
      FT_BOOLEAN, 32, TFS(&supported_strings), AST_FORMAT_SLINEAR, 
      "Raw 16-bit Signed Linear (8000 Hz) PCM", HFILL }},

    {&hf_iax2_cap_lpc10,
     {"LPC10, 180 samples/frame", "iax2.cap.lpc10", FT_BOOLEAN, 32,
      TFS(&supported_strings), AST_FORMAT_LPC10,
      "LPC10, 180 samples/frame", HFILL }},

    {&hf_iax2_cap_g729a,
     {"G.729a Audio", "iax2.cap.g729a", FT_BOOLEAN, 32,
      TFS(&supported_strings), AST_FORMAT_G729A,
      "G.729a Audio", HFILL }},

    {&hf_iax2_cap_speex,
     {"SPEEX Audio", "iax2.cap.speex", FT_BOOLEAN, 32,
      TFS(&supported_strings), AST_FORMAT_SPEEX,
      "SPEEX Audio", HFILL }},

    {&hf_iax2_cap_ilbc,
     {"iLBC Free compressed Audio", "iax2.cap.ilbc", FT_BOOLEAN, 32,
      TFS(&supported_strings), AST_FORMAT_ILBC,
      "iLBC Free compressed Audio", HFILL }},

    {&hf_iax2_cap_jpeg,
     {"JPEG images", "iax2.cap.jpeg", FT_BOOLEAN, 32,
      TFS(&supported_strings), AST_FORMAT_JPEG,
      "JPEG images", HFILL }},

    {&hf_iax2_cap_png,
     {"PNG images", "iax2.cap.png", FT_BOOLEAN, 32,
      TFS(&supported_strings), AST_FORMAT_PNG,
      "PNG images", HFILL }},

    {&hf_iax2_cap_h261,
     {"H.261 video", "iax2.cap.h261", FT_BOOLEAN, 32,
      TFS(&supported_strings), AST_FORMAT_H261,
      "H.261 video", HFILL }},

    {&hf_iax2_cap_h263,
     {"H.263 video", "iax2.cap.h263", FT_BOOLEAN, 32,
      TFS(&supported_strings), AST_FORMAT_H263,
      "H.263 video", HFILL }}
  };

  static gint *ett[] = {
    &ett_iax2,
    &ett_iax2_full_mini_subtree,
    &ett_iax2_type,
    &ett_iax2_ie,
    &ett_iax2_codecs,
    &ett_iax2_ies_apparent_addr
  };

  proto_iax2 =
    proto_register_protocol ("Inter-Asterisk eXchange v2", "IAX2", "iax2");
  proto_register_field_array (proto_iax2, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector("iax2", dissect_iax2, proto_iax2);

  iax2_codec_dissector_table = register_dissector_table(
    "iax2.codec","IAX codec number", FT_UINT32, BASE_HEX);
  iax2_dataformat_dissector_table = register_dissector_table(
    "iax2.dataformat","IAX dataformat number", FT_UINT32, BASE_HEX);
  
  /* register our init routine to be called at the start of a capture,
     to clear out our hash tables etc */
  register_init_routine(&iax_init_protocol);
}

void
proto_reg_handoff_iax2 (void)
{
  dissector_add("udp.port", IAX2_PORT, find_dissector("iax2"));
  dissector_add("iax2.dataformat", AST_DATAFORMAT_V110, find_dissector("v110"));
  data_handle = find_dissector("data");
}


/* 
 * This sets up the indentation style for this file in emacs.
 *
 * Local Variables:
 * c-basic-offset: 2
 * End:
 */
