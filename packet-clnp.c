/* packet-clnp.c
 * Routines for ISO/OSI network and transport protocol packet disassembly
 *
 * $Id: packet-clnp.c,v 1.14 2000/11/18 10:38:24 guy Exp $
 * Laurent Deniel <deniel@worldnet.fr>
 * Ralf Schneider <Ralf.Schneider@t-online.de>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include "prefs.h"
#include "packet.h"
#include "packet-osi.h"
#include "packet-osi-options.h"
#include "packet-clnp.h"
#include "packet-isis.h"
#include "packet-esis.h"
#include "nlpid.h"

/* protocols and fields */

static int  proto_clnp         = -1;
static gint ett_clnp           = -1;
static int  proto_cotp         = -1;
static gint ett_cotp           = -1;
static int  proto_cltp         = -1;
static gint ett_cltp           = -1;

static int hf_clnp_id          = -1;
static int hf_clnp_length      = -1;
static int hf_clnp_version     = -1;
static int hf_clnp_ttl         = -1;
static int hf_clnp_type        = -1;
static int hf_clnp_pdu_length  = -1;
static int hf_clnp_checksum    = -1;
static int hf_clnp_dest_length = -1;
static int hf_clnp_dest        = -1;
static int hf_clnp_src_length  = -1;
static int hf_clnp_src         = -1;

/*
 * ISO 8473 OSI CLNP definition (see RFC994)
 *
 *            _________________________________
 *           |           Fixed Part            |
 *           |_________________________________|
 *           |          Address Part           |
 *           |_________________________________|
 *           |   Segmentation Part (optional)  |
 *           |_________________________________|
 *           |     Options Part (optional)     |
 *           |_________________________________|
 *           |         Data (optional)         |
 *           |_________________________________|
 */

#define	ISO8473_V1  0x01    /* CLNP version 1 */

/* Fixed part */

#define CNF_TYPE		0x1f
#define CNF_ERR_OK		0x20
#define CNF_MORE_SEGS		0x40
#define CNF_SEG_OK		0x80

#define DT_NPDU			0x1C
#define MD_NPDU			0x1D
#define ER_NPDU			0x01
#define ERQ_NPDU		0x1E
#define ERP_NPDU		0x1F

static const value_string npdu_type_vals[] = {
  { DT_NPDU,	"DT" },
  { MD_NPDU,	"MD" },
  { ER_NPDU,	"ER" },
  { ERQ_NPDU,	"ERQ" },
  { ERP_NPDU,	"ERP" },
  { 0,		NULL }
};

/* field position */

#define P_CLNP_PROTO_ID		0
#define P_CLNP_HDR_LEN		1
#define P_CLNP_VERS		2
#define P_CLNP_TTL		3
#define P_CLNP_TYPE		4
#define P_CLNP_SEGLEN		5
#define P_CLNP_CKSUM		7
#define P_CLNP_ADDRESS_PART	9

/* Segmentation part */

struct clnp_segment {
  u_short	cng_id;		/* data unit identifier */
  u_short	cng_off;	/* segment offset */
  u_short	cng_tot_len;	/* total length */
};

/* NSAP selector */

#define NSEL_NET 		0x00
#define NSEL_NP  		0x20
#define NSEL_TP  		0x21

/*
 * ISO8073 OSI COTP definition (see RFC905)
 */

/* don't use specific TPDU types to avoid alignment problems & copy overhead */

/* TPDU definition */

#define ED_TPDU        		0x1	/* COTP */
#define EA_TPDU        		0x2	/* COTP */
#define UD_TPDU        		0x4	/* CLTP */
#define RJ_TPDU        		0x5	/* COTP */
#define AK_TPDU        		0x6	/* COTP */
#define ER_TPDU        		0x7	/* COTP */
#define DR_TPDU        		0x8	/* COTP */
#define DC_TPDU        		0xC	/* COTP */
#define CC_TPDU        		0xD	/* COTP */
#define CR_TPDU        		0xE	/* COTP */
#define DT_TPDU        		0xF	/* COTP */

/* field position */

#define P_LI           		0
#define P_TPDU         		1
#define P_CDT          		1
#define P_DST_REF      		2
#define P_SRC_REF      		4
#define P_TPDU_NR_0_1  		2
#define P_TPDU_NR_234  		4
#define P_VAR_PART_NDT 		5
#define P_VAR_PART_EDT 		8
#define P_VAR_PART_DC           6
#define P_CDT_IN_AK    		8
#define P_CDT_IN_RJ    		8
#define P_REJECT_ER    		4
#define P_REASON_IN_DR 		6
#define P_CLASS_OPTION 		6

/* TPDU length indicator */

#define LI_NORMAL_DT_CLASS_01		 2
#define LI_NORMAL_DT_WITH_CHECKSUM       8
#define LI_NORMAL_DT_WITHOUT_CHECKSUM    4
#define LI_EXTENDED_DT_WITH_CHECKSUM     11
#define LI_EXTENDED_DT_WITHOUT_CHECKSUM  7
#define LI_NORMAL_EA_WITH_CHECKSUM       8
#define LI_NORMAL_EA_WITHOUT_CHECKSUM    4
#define LI_EXTENDED_EA_WITH_CHECKSUM     11
#define LI_EXTENDED_EA_WITHOUT_CHECKSUM  7
#define LI_NORMAL_RJ                     4
#define LI_EXTENDED_RJ                   9
#define LI_MIN_DR                        6
#define LI_MAX_DC                        9
#define LI_MAX_AK                        27
#define LI_MAX_EA                        11
#define LI_MAX_ER			 8
/* XXX - can we always decide this based on whether the length
   indicator is odd or not?  What if the variable part has an odd
   number of octets? */
#define is_LI_NORMAL_AK(p)               ( ( p & 0x01 ) == 0 )

/* variant part */

#define VP_ACK_TIME     	0x85
#define VP_RES_ERROR    	0x86
#define VP_PRIORITY     	0x87
#define VP_TRANSIT_DEL  	0x88
#define VP_THROUGHPUT   	0x89
#define VP_SEQ_NR       	0x8A         /* in AK */
#define VP_REASSIGNMENT 	0x8B
#define VP_FLOW_CNTL    	0x8C         /* in AK */
#define VP_TPDU_SIZE    	0xC0
#define VP_SRC_TSAP     	0xC1         /* in CR/CC */
#define VP_DST_TSAP     	0xC2
#define VP_CHECKSUM     	0xC3
#define VP_VERSION_NR   	0xC4
#define VP_PROTECTION   	0xC5
#define VP_OPT_SEL      	0xC6
#define VP_PROTO_CLASS  	0xC7
#define VP_PREF_MAX_TPDU_SIZE  	0xF0
#define VP_INACTIVITY_TIMER  	0xF2

static const value_string tp_vpart_type_vals[] = {
  { VP_ACK_TIME,		"ack time" },
  { VP_RES_ERROR,		"res error" },
  { VP_PRIORITY,		"priority" },
  { VP_TRANSIT_DEL,		"transit delay" },
  { VP_THROUGHPUT,		"throughput" },
  { VP_SEQ_NR,			"seq number" },
  { VP_REASSIGNMENT,		"reassignment" },
  { VP_FLOW_CNTL,		"flow control" },
  { VP_TPDU_SIZE,		"tpdu-size" },
  { VP_SRC_TSAP,		"src-tsap" },
  { VP_DST_TSAP,		"dst-tsap" },
  { VP_CHECKSUM,		"checksum" },
  { VP_VERSION_NR,		"version" },
  { VP_PROTECTION,		"protection" },
  { VP_OPT_SEL,			"options" },
  { VP_PROTO_CLASS,		"proto class" },
  { VP_PREF_MAX_TPDU_SIZE,	"preferred max TPDU size" },
  { 0,				NULL }
};

/* misc */

#define EXTRACT_SHORT(p) 	pntohs(p)
#define EXTRACT_LONG(p) 	pntohl(p)

/* global variables */

static u_char  li, tpdu, cdt; 	/* common fields */
static u_short dst_ref;

/* List of dissectors to call for COTP packets put atop the Inactive
   Subset of CLNP. */
static heur_dissector_list_t cotp_is_heur_subdissector_list;

/* options */
static guint tp_nsap_selector = NSEL_TP;
static gboolean always_decode_transport = FALSE;

/* function definitions */

#define MAX_TSAP_LEN	32
static gchar *print_tsap(const u_char *tsap, int length)
{

  static gchar  str[3][MAX_TSAP_LEN * 2 + 1];
  static gchar *cur;
  gchar tmp[3];
  gboolean allprintable;
  int i;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }


  cur[0] = '\0';
  if (length <= 0 || length > MAX_TSAP_LEN) 
    sprintf(cur, "<unsupported TSAP length>");
  else {    
    allprintable=TRUE;
    for (i=0;i<length;i++) {
	/* If any byte is not printable ASCII, display the TSAP as a
	   series of hex byte values rather than as a string; this
	   means that, for example, accented letters will cause it
	   to be displayed as hex, but it also means that byte values
	   such as 0xff and 0xfe, which *are* printable ISO 8859/x
	   characters, won't be treated as printable - 0xfffffffe
	   is probably binary, not text. */
	if (!(isascii(tsap[i]) && isprint(tsap[i]))) {
	  allprintable=FALSE;
	  break;
	  }	 
	}
    if (!allprintable){
      strcat(cur,"0x");
      }
    while (length != 0) {
      if (allprintable)
	sprintf(tmp, "%c", *tsap ++);
      else
	sprintf(tmp, "%02x", *tsap ++);
      strcat(cur, tmp);
      length --;
    }
  }
  return cur;

} /* print_tsap */

static gboolean osi_decode_tp_var_part(tvbuff_t *tvb, int offset,
				      int vp_length, int class_option,
				      proto_tree *tree)
{
  guint8  code, length;
  guint8  c1;
  guint16 s, s1,s2,s3,s4;
  guint32 t1, t2, t3, t4;
  guint32 pref_max_tpdu_size;

  while (vp_length != 0) {
    code = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1,
		"Parameter code:   0x%02x (%s)",
			    code,
			    val_to_str(code, tp_vpart_type_vals, "Unknown"));
    offset += 1;
    vp_length -= 1;

    if (vp_length == 0)
      break;
    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1,
		"Parameter length: %u", length);
    offset += 1;
    vp_length -= 1;

    switch (code) {

    case VP_ACK_TIME:
      s = tvb_get_ntohs(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, length, 
			      "Ack time (ms): %u", s);
      offset += length;
      vp_length -= length;
      break;

    case VP_RES_ERROR:
      proto_tree_add_text(tree, tvb, offset, 1,
		"Residual error rate, target value: 10^%u",
		tvb_get_guint8(tvb, offset));
      offset += 1;
      length -= 1;
      vp_length -= 1;

      proto_tree_add_text(tree, tvb, offset, 1,
		"Residual error rate, minimum acceptable: 10^%u",
		tvb_get_guint8(tvb, offset));
      offset += 1;
      length -= 1;
      vp_length -= 1;


      proto_tree_add_text(tree, tvb, offset, 1,
		"Residual error rate, TSDU size of interest: %u",
		1<<tvb_get_guint8(tvb, offset));
      offset += 1;
      length -= 1;
      vp_length -= 1;

      break;

    case VP_PRIORITY:
      s = tvb_get_ntohs(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, length,
		"Priority: %u", s);
      offset += length;
      vp_length -= length;
      break;
	
    case VP_TRANSIT_DEL:
      s1 = tvb_get_ntohs(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, 2,
		"Transit delay, target value, calling-called: %u ms", s1);
      offset += 2;
      length -= 2;
      vp_length -= 2;

      s2 = tvb_get_ntohs(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, 2,
		"Transit delay, maximum acceptable, calling-called: %u ms", s2);
      offset += 2;
      length -= 2;
      vp_length -= 2;

      s3 = tvb_get_ntohs(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, 2,
		"Transit delay, target value, called-calling: %u ms", s3);
      offset += 2;
      length -= 2;
      vp_length -= 2;

      s4 = tvb_get_ntohs(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, 2,
		"Transit delay, maximum acceptable, called-calling: %u ms", s4);
      offset += 2;
      length -= 2;
      vp_length -= 2;
      break;

    case VP_THROUGHPUT:
      t1 = tvb_get_ntoh24(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, 3,
		"Maximum throughput, target value, calling-called:       %u o/s", t1);
      offset += 3;
      length -= 3;
      vp_length -= 3;

      t2 = tvb_get_ntoh24(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, 3,
		"Maximum throughput, minimum acceptable, calling-called: %u o/s", t2);
      offset += 3;
      length -= 3;
      vp_length -= 3;

      t3 = tvb_get_ntoh24(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, 3,
		"Maximum throughput, target value, called-calling:       %u o/s", t3);
      offset += 3;
      length -= 3;
      vp_length -= 3;

      t4 = tvb_get_ntoh24(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, 3,
		"Maximum throughput, minimum acceptable, called-calling: %u o/s", t4);
      offset += 3;
      length -= 3;
      vp_length -= 3;

      if (length != 0) {	/* XXX - should be 0 or 12 */
	t1 = tvb_get_ntoh24(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 3,
		"Average throughput, target value, calling-called:       %u o/s", t1);
	offset += 3;
	length -= 3;
	vp_length -= 3;

	t2 = tvb_get_ntoh24(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 3,
		"Average throughput, minimum acceptable, calling-called: %u o/s", t2);
	offset += 3;
	length -= 3;
	vp_length -= 3;

	t3 = tvb_get_ntoh24(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 3,
		"Average throughput, target value, called-calling:       %u o/s", t3);
	offset += 3;
	length -= 3;
	vp_length -= 3;

	t4 = tvb_get_ntoh24(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 3,
		"Average throughput, minimum acceptable, called-calling: %u o/s", t4);
	offset += 3;
	length -= 3;
	vp_length -= 3;
      }
      break;

    case VP_SEQ_NR:
      proto_tree_add_text(tree, tvb, offset, 2,
		"Sequence number: 0x%04x", tvb_get_ntohs(tvb, offset));
      offset += length;
      vp_length -= length;
      break;

    case VP_REASSIGNMENT: 
      proto_tree_add_text(tree, tvb, offset, 2,
		"Reassignment time: %u secs", tvb_get_ntohs(tvb, offset));
      offset += length;
      vp_length -= length;
      break;

    case VP_FLOW_CNTL:
      proto_tree_add_text(tree, tvb, offset, 4,
		"Lower window edge: 0x%08x", tvb_get_ntohl(tvb, offset));
      offset += 4;
      length -= 4;
      vp_length -= 4;

      proto_tree_add_text(tree, tvb, offset, 2,
		"Sequence number: 0x%04x", tvb_get_ntohs(tvb, offset));
      offset += 2;
      length -= 2;
      vp_length -= 2;

      proto_tree_add_text(tree, tvb, offset, 2,
		"Credit: 0x%04x", tvb_get_ntohs(tvb, offset));
      offset += 2;
      length -= 2;
      vp_length -= 2;

      break;

    case VP_TPDU_SIZE:
      c1 = tvb_get_guint8(tvb, offset) & 0x0F;
      proto_tree_add_text(tree, tvb, offset, length, 
		"TPDU size: %u", 2 << c1);
      offset += length;
      vp_length -= length;
      break;

    case VP_SRC_TSAP:
      proto_tree_add_text(tree, tvb, offset, length,
		"Calling TSAP: %s",
		print_tsap(tvb_get_ptr(tvb, offset, length), length));
      offset += length;
      vp_length -= length;
      break;

    case VP_DST_TSAP:
      proto_tree_add_text(tree, tvb, offset, length,
		"Called TSAP: %s",
		print_tsap(tvb_get_ptr(tvb, offset, length), length));
      offset += length;
      vp_length -= length;
      break;

    case VP_CHECKSUM:
      proto_tree_add_text(tree, tvb, offset, length,
		"Checksum: 0x%04x", tvb_get_ntohs(tvb, offset));
      offset += length;
      vp_length -= length;
      break;

    case VP_VERSION_NR:
      c1 = tvb_get_guint8(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, length,
		"Version: %u", c1);
      offset += length;
      vp_length -= length;
      break;

    case VP_OPT_SEL:
      c1 = tvb_get_guint8(tvb, offset) & 0x0F;
      switch (class_option) {

      case 1:
	if (c1 & 0x8)
	  proto_tree_add_text(tree, tvb, offset, 1,
				  "Use of network expedited data");
	else
	  proto_tree_add_text(tree, tvb, offset, 1,
				  "Non use of network expedited data");
	if (c1 & 0x4)
	  proto_tree_add_text(tree, tvb, offset, 1,
				  "Use of Receipt confirmation");
	else
	  proto_tree_add_text(tree, tvb, offset, 1,
				  "Use of explicit AK variant");
	break;

      case 4:
	if (c1 & 0x2)
	  proto_tree_add_text(tree, tvb, offset, 1,
				  "Non-use 16 bit checksum in class 4");
	else
	  proto_tree_add_text(tree, tvb, offset, 1,
				  "Use 16 bit checksum ");
	break;
      }
      if (c1 & 0x1)
	proto_tree_add_text(tree, tvb, offset, 1,
				"Use of transport expedited data transfer\n");
      else
	proto_tree_add_text(tree, tvb, offset, 1,
				"Non-use of transport expedited data transfer");
      offset += length;
      vp_length -= length;
      break;

    case VP_PREF_MAX_TPDU_SIZE:
      switch (length) {

      case 1:
        pref_max_tpdu_size = tvb_get_guint8(tvb, offset);
        break;

      case 2:
        pref_max_tpdu_size = tvb_get_ntohs(tvb, offset);
        break;

      case 3:
	pref_max_tpdu_size = tvb_get_ntoh24(tvb, offset);
	break;

      case 4:
        pref_max_tpdu_size = tvb_get_ntohl(tvb, offset);
        break;

      default:
        proto_tree_add_text(tree, tvb, offset, length,
		"Preferred maximum TPDU size: bogus length %u (not 1, 2, 3, or 4)",
		length);
	return FALSE;
      }
      proto_tree_add_text(tree, tvb, offset, length,
		"Preferred maximum TPDU size: %u", pref_max_tpdu_size*128);
      offset += length;
      vp_length -= length;
      break; 

    case VP_INACTIVITY_TIMER:
      proto_tree_add_text(tree, tvb, offset, length,
		"Inactivity timer: %u ms", tvb_get_ntohl(tvb, offset));
      offset += length;
      vp_length -= length;
      break;
	
    case VP_PROTECTION:           /* user-defined */
    case VP_PROTO_CLASS:          /* todo */
    default:			  /* unknown, no decoding */
      proto_tree_add_text(tree, tvb, offset, length,
			      "Parameter value: <not shown>");
      offset += length;
      vp_length -= length;
      break; 
    }
  } /* while */

  return TRUE;
}

static int osi_decode_DR(tvbuff_t *tvb, int offset, 
			 packet_info *pinfo, proto_tree *tree) 
{
  proto_tree *cotp_tree;
  proto_item *ti;
  u_short src_ref;
  u_char  reason;
  char *str;
  
  if (li < LI_MIN_DR) 
    return -1;
  
  src_ref = tvb_get_ntohs(tvb, offset + P_SRC_REF);
  reason  = tvb_get_guint8(tvb, offset + P_REASON_IN_DR);

  switch(reason) {
    case (128+0): str = "Normal Disconnect"; break;
    case (128+1): str = "Remote transport entity congestion"; break;
    case (128+2): str = "Connection negotiation failed"; break;
    case (128+3): str = "Duplicate source reference"; break;
    case (128+4): str = "Mismatched references"; break;
    case (128+5): str = "Protocol error"; break;
    case (128+7): str = "Reference overflow"; break;
    case (128+8): str = "Connection requestion refused"; break;
    case (128+10):str = "Header or parameter length invalid"; break;
    case (0):     str = "Reason not specified"; break;
    case (1):     str = "Congestion at TSAP"; break;
    case (2):     str = "Session entity not attached to TSAP"; break;
    case (3):     str = "Address unknown"; break;
    default:      return -1;
      /*NOTREACHED*/
      break;
  }

  if (check_col(pinfo->fd, COL_INFO))
    col_append_fstr(pinfo->fd, COL_INFO,
		"DR TPDU src-ref: 0x%04x dst-ref: 0x%04x",
		 src_ref, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, tvb, offset,      1,
			"Length indicator: %u", li);
    proto_tree_add_text(cotp_tree, tvb, offset +  1, 1, 
			"TPDU code: 0x%x (DR)", tpdu); 
    proto_tree_add_text(cotp_tree, tvb, offset +  2, 2, 
			"Destination reference: 0x%04x", dst_ref);
    proto_tree_add_text(cotp_tree, tvb, offset +  4, 2, 
			"Source reference: 0x%04x", src_ref);
    proto_tree_add_text(cotp_tree, tvb, offset +  6, 1, 
			"Cause: %s", str);
  }

  offset += li + 1;

  /* User data */
  dissect_data(tvb, offset, pinfo, tree);
  offset += tvb_length_remaining(tvb, offset);
     /* we dissected all of the containing PDU */

  return offset;

} /* osi_decode_DR */

static int osi_decode_DT(tvbuff_t *tvb, int offset, 
			 packet_info *pinfo, proto_tree *tree,
			 gboolean uses_inactive_subset,
			 gboolean *subdissector_found)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  gboolean is_extended;
  gboolean is_class_234;
  u_int    tpdu_nr ;
  u_int    fragment = 0;
  tvbuff_t *next_tvb;
    
  /* VP_CHECKSUM is the only parameter allowed in the variable part.
     (This means we may misdissect this if the packet is bad and
     contains other parameters.) */
  switch (li) {

    case LI_NORMAL_DT_WITH_CHECKSUM      :
      if (tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_CHECKSUM)
	return -1;
      /* FALLTHROUGH */

    case LI_NORMAL_DT_WITHOUT_CHECKSUM   :
      tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
      if ( tpdu_nr & 0x80 )
	tpdu_nr = tpdu_nr & 0x7F;
      else
	fragment = 1;
      is_extended = FALSE;
      is_class_234 = TRUE;
      break;

    case LI_EXTENDED_DT_WITH_CHECKSUM    :
      if (tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_CHECKSUM)
	return -1;
      /* FALLTHROUGH */

    case LI_EXTENDED_DT_WITHOUT_CHECKSUM :
      tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
      if ( tpdu_nr & 0x80000000 )
	tpdu_nr = tpdu_nr & 0x7FFFFFFF;
      else
	fragment = 1;
      is_extended = TRUE;
      is_class_234 = TRUE;
      break;

    case LI_NORMAL_DT_CLASS_01           :
      tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_0_1);
      if ( tpdu_nr & 0x80 )
	tpdu_nr = tpdu_nr & 0x7F;
      else
	fragment = 1;      
      is_extended = FALSE;
      is_class_234 = FALSE;
      break;

    default : /* bad TPDU */
      return -1;
      /*NOTREACHED*/
      break;
  }

  if (check_col(pinfo->fd, COL_INFO))
    col_append_fstr(pinfo->fd, COL_INFO, "DT TPDU (%u) dst-ref: 0x%04x %s", 
		 tpdu_nr,
		 dst_ref,
		 (fragment)? "(fragment)" : "");

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, tvb, offset, 1,
			"Length indicator: %u", li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_text(cotp_tree, tvb, offset, 1,
			"TPDU code: 0x%x (DT)", tpdu); 

  }
  offset += 1;
  li -= 1;

  if (is_class_234) {
    if (tree) {
      proto_tree_add_text(cotp_tree, tvb, offset, 2,
			  "Destination reference: 0x%04x", dst_ref);
    }
    offset += 2;
    li -= 2;
  }

  if (is_extended) {
    if (tree) {
      proto_tree_add_text(cotp_tree, tvb, offset, 4, 
			    "TPDU number: 0x%08x (%s)", 
			    tpdu_nr,
			    (fragment)? "fragment":"complete");
    }
    offset += 4;
    li -= 4;
  } else {
    if (tree) {
      proto_tree_add_text(cotp_tree, tvb, offset, 1,
			    "TPDU number: 0x%02x (%s)", 
			    tpdu_nr,
			    (fragment)? "fragment":"complete");
    }
    offset += 1;
    li -= 1;
  }

  if (tree)
    osi_decode_tp_var_part(tvb, offset, li, 4, cotp_tree);
  offset += li;

  next_tvb = tvb_new_subset(tvb, offset, -1, -1);
  if (uses_inactive_subset){
	if (dissector_try_heuristic(cotp_is_heur_subdissector_list, next_tvb,
					pinfo, tree)) {
		*subdissector_found = TRUE;
	} else {
	  /* Fill in other Dissectors using inactive subset here */
	  dissect_data(next_tvb, 0, pinfo, tree);
	}
  } else
	dissect_data(next_tvb, 0, pinfo, tree);
  offset += tvb_length_remaining(tvb, offset);
     /* we dissected all of the containing PDU */

  return offset;

} /* osi_decode_DT */

static int osi_decode_ED(tvbuff_t *tvb, int offset, 
			 packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  gboolean is_extended;
  u_int    tpdu_nr ;
  tvbuff_t *next_tvb;

  /* ED TPDUs are never fragmented */

  /* VP_CHECKSUM is the only parameter allowed in the variable part.
     (This means we may misdissect this if the packet is bad and
     contains other parameters.) */
  switch (li) {

    case LI_NORMAL_DT_WITH_CHECKSUM      :
      if (tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_CHECKSUM)
	return -1;
      /* FALLTHROUGH */

    case LI_NORMAL_DT_WITHOUT_CHECKSUM   :
      tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
      if ( tpdu_nr & 0x80 )
	tpdu_nr = tpdu_nr & 0x7F;
      else
	return -1;
      is_extended = FALSE;
      break;

    case LI_EXTENDED_DT_WITH_CHECKSUM    :
      if (tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_CHECKSUM)
	return -1;
      /* FALLTHROUGH */

    case LI_EXTENDED_DT_WITHOUT_CHECKSUM :
      tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
      if ( tpdu_nr & 0x80000000 )
	tpdu_nr = tpdu_nr & 0x7FFFFFFF;
      else
	return -1;
      is_extended = TRUE;
      break;

    default : /* bad TPDU */
      return -1;
      /*NOTREACHED*/
      break;
  } /* li */

  if (check_col(pinfo->fd, COL_INFO))
    col_append_fstr(pinfo->fd, COL_INFO, "ED TPDU (%u) dst-ref: 0x%04x", 
		 tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, tvb, offset, 1,
			"Length indicator: %u", li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_text(cotp_tree, tvb, offset, 1, 
			"TPDU code: 0x%x (ED)", tpdu);
  }
  offset += 1;
  li -= 1;

  if (tree) {
    proto_tree_add_text(cotp_tree, tvb, offset, 2,
			"Destination reference: 0x%04x", dst_ref);
  }
  offset += 2;
  li -= 2;

  if (is_extended) {
    if (tree) {
      proto_tree_add_text(cotp_tree, tvb, offset, 4,
			    "TPDU number: 0x%02x", tpdu_nr);
    }
    offset += 4;
    li -= 4;
  } else {
    if (tree) {
      proto_tree_add_text(cotp_tree, tvb, offset, 1,
			    "TPDU number: 0x%02x", tpdu_nr);	
    }
    offset += 1;
    li -= 1;
  }

  if (tree)
    osi_decode_tp_var_part(tvb, offset, li, 4, cotp_tree);
  offset += li;

  next_tvb = tvb_new_subset(tvb, offset, -1, -1);
  dissect_data(next_tvb, 0, pinfo, tree);

  offset += tvb_length_remaining(tvb, offset);
     /* we dissected all of the containing PDU */

  return offset;

} /* osi_decode_ED */

static int osi_decode_RJ(tvbuff_t *tvb, int offset, 
			 packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree;
  proto_item *ti;
  u_int    tpdu_nr ;
  u_short  credit = 0;

  switch(li) {
    case LI_NORMAL_RJ   :
      tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
      break;
    case LI_EXTENDED_RJ :
      tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
      credit = tvb_get_ntohs(tvb, offset + P_CDT_IN_RJ);
      break;
    default :
      return -1;
      /*NOTREACHED*/
      break;
  }

  if (check_col(pinfo->fd, COL_INFO))
    col_append_fstr(pinfo->fd, COL_INFO, "RJ TPDU (%u) dst-ref: 0x%04x", 
		 tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, tvb, offset,      1,
			"Length indicator: %u", li);
    proto_tree_add_text(cotp_tree, tvb, offset +  1, 1, 
			"TPDU code: 0x%x (RJ)", tpdu); 
    if (li == LI_NORMAL_RJ)
      proto_tree_add_text(cotp_tree, tvb, offset +  1, 1, 
			  "Credit: %u", cdt);
    proto_tree_add_text(cotp_tree, tvb, offset +  2, 2, 
			"Destination reference: 0x%04x", dst_ref);
    if (li == LI_NORMAL_RJ)
      proto_tree_add_text(cotp_tree, tvb, offset +  4, 1, 
			  "Your TPDU number: 0x%02x", tpdu_nr);
    else {
      proto_tree_add_text(cotp_tree, tvb, offset +  4, 4, 
			  "Your TPDU number: 0x%02x", tpdu_nr);
      proto_tree_add_text(cotp_tree, tvb, offset +  8, 2, 
			  "Credit: 0x%02x", credit);
    }
  }

  offset += li + 1;

  return offset;

} /* osi_decode_RJ */

static int osi_decode_CC(tvbuff_t *tvb, int offset, 
			 packet_info *pinfo, proto_tree *tree)
{

  /* CC & CR decoding in the same function */

  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  u_short src_ref;
  u_char  class_option;

  src_ref = tvb_get_ntohs(tvb, offset + P_SRC_REF);
  class_option = (tvb_get_guint8(tvb, offset + P_CLASS_OPTION) >> 4 ) & 0x0F;
  if (class_option > 4)
    return -1;

  if (check_col(pinfo->fd, COL_INFO))
    col_append_fstr(pinfo->fd, COL_INFO,
		 "%s TPDU src-ref: 0x%04x dst-ref: 0x%04x",
		 (tpdu == CR_TPDU) ? "CR" : "CC",
		 src_ref,
		 dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, tvb, offset, 1,
			"Length indicator: %u", li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_text(cotp_tree, tvb, offset, 1,
			"TPDU code: 0x%x (%s)", tpdu,
			(tpdu == CR_TPDU) ? "CR" : "CC");
  }
  offset += 1;
  li -= 1;

  if (tree) {
    proto_tree_add_text(cotp_tree, tvb, offset, 2,
			"Destination reference: 0x%04x", dst_ref);
  }
  offset += 2;
  li -= 2;

  if (tree) {
    proto_tree_add_text(cotp_tree, tvb, offset, 2,
			"Source reference: 0x%04x", src_ref);
  }
  offset += 2;
  li -= 2;

  if (tree) {
    proto_tree_add_text(cotp_tree, tvb, offset, 1,
			"Class option: 0x%02x", class_option);
  }
  offset += 1;
  li -= 1;

  if (tree)
    osi_decode_tp_var_part(tvb, offset, li, class_option, cotp_tree);
  offset += li;

  /* User data */
  dissect_data(tvb, offset, pinfo, tree);
  offset += tvb_length_remaining(tvb, offset);
     /* we dissected all of the containing PDU */

  return offset;

} /* osi_decode_CC */

static int osi_decode_DC(tvbuff_t *tvb, int offset, 
			 packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  u_short src_ref;

  if (li > LI_MAX_DC) 
    return -1;

  src_ref = tvb_get_ntohs(tvb, offset + P_SRC_REF);

  if (check_col(pinfo->fd, COL_INFO))
    col_append_fstr(pinfo->fd, COL_INFO,
		 "DC TPDU src-ref: 0x%04x dst-ref: 0x%04x", 
		 src_ref,
		 dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, tvb, offset, 1,
			"Length indicator: %u", li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_text(cotp_tree, tvb, offset, 1,
			"TPDU code: 0x%x (DC)", tpdu);
  }
  offset += 1;
  li -= 1;

  if (tree) {
    proto_tree_add_text(cotp_tree, tvb, offset, 2,
			"Destination reference: 0x%04x", dst_ref);
  }
  offset += 2;
  li -= 2;

  if (tree) {
    proto_tree_add_text(cotp_tree, tvb, offset, 2,
			"Source reference: 0x%04x", src_ref);
  }
  offset += 2;
  li -= 2;

  if (tree)
    osi_decode_tp_var_part(tvb, offset, li, 4, cotp_tree);
  offset += li;

  return offset;

} /* osi_decode_DC */

static int osi_decode_AK(tvbuff_t *tvb, int offset, 
			 packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  u_int      tpdu_nr;
  u_short    cdt_in_ak;

  if (li > LI_MAX_AK) 
    return -1;

  if (is_LI_NORMAL_AK(li)) {

    tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);

    if (check_col(pinfo->fd, COL_INFO))
      col_append_fstr(pinfo->fd, COL_INFO, "AK TPDU (%u) dst-ref: 0x%04x", 
		   tpdu_nr, dst_ref);

    if (tree) {
      ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
      cotp_tree = proto_item_add_subtree(ti, ett_cotp);
      proto_tree_add_text(cotp_tree, tvb, offset, 1,
			  "Length indicator: %u", li);
    }
    offset += 1;

    if (tree) {
      proto_tree_add_text(cotp_tree, tvb, offset, 1,
			  "TPDU code: 0x%x (AK)", tpdu);
      proto_tree_add_text(cotp_tree, tvb, offset, 1,
			  "Credit: %u", cdt);
    }
    offset += 1;
    li -= 1;

    if (tree) {
      proto_tree_add_text(cotp_tree, tvb, offset, 2,
			  "Destination reference: 0x%04x", dst_ref);
    }
    offset += 2;
    li -= 2;

    if (tree) {
      proto_tree_add_text(cotp_tree, tvb, offset, 1,
			  "Your TPDU number: 0x%02x", tpdu_nr);
    }
    offset += 1;
    li -= 1;

    if (tree)
      osi_decode_tp_var_part(tvb, offset, li, 4, cotp_tree);
    offset += li;

  } else { /* extended format */
    
    tpdu_nr   = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
    cdt_in_ak = tvb_get_ntohs(tvb, offset + P_CDT_IN_AK);

    if (check_col(pinfo->fd, COL_INFO))
      col_append_fstr(pinfo->fd, COL_INFO, "AK TPDU (%u) dst-ref: 0x%04x", 
		   tpdu_nr, dst_ref);
    
    if (tree) {
      ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
      cotp_tree = proto_item_add_subtree(ti, ett_cotp);
      proto_tree_add_text(cotp_tree, tvb, offset, 1,
			  "Length indicator: %u", li);
    }
    offset += 1;

    if (tree) {
      proto_tree_add_text(cotp_tree, tvb, offset, 1,
			  "TPDU code: 0x%x (AK)", tpdu);
    }
    offset += 1;
    li -= 1;

    if (tree) {
      proto_tree_add_text(cotp_tree, tvb, offset, 2,
			  "Destination reference: 0x%04x", dst_ref);
    }
    offset += 2;
    li -= 2;

    if (tree) {
      proto_tree_add_text(cotp_tree, tvb, offset, 4,
			  "Your TPDU number: 0x%08x", tpdu_nr);
    }
    offset += 4;
    li -= 4;

    if (tree) {
      proto_tree_add_text(cotp_tree, tvb, offset, 2,
			  "Credit: 0x%04x", cdt_in_ak);
    }
    offset += 2;
    li -= 2;
    
    if (tree)
      osi_decode_tp_var_part(tvb, offset, li, 4, cotp_tree);
    offset += li;

  } /* is_LI_NORMAL_AK */

  return offset;

} /* osi_decode_AK */

static int osi_decode_EA(tvbuff_t *tvb, int offset, 
			 packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  gboolean is_extended;
  u_int    tpdu_nr ;

  if (li > LI_MAX_EA) 
    return -1;

  /* VP_CHECKSUM is the only parameter allowed in the variable part.
     (This means we may misdissect this if the packet is bad and
     contains other parameters.) */
  switch (li) {

    case LI_NORMAL_EA_WITH_CHECKSUM      :
      if (tvb_get_guint8(tvb, offset + P_VAR_PART_NDT) != VP_CHECKSUM ||
		tvb_get_guint8(tvb, offset + P_VAR_PART_NDT + 1) != 2)
	return -1;
      /* FALLTHROUGH */

    case LI_NORMAL_EA_WITHOUT_CHECKSUM   :
      tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);
      is_extended = FALSE;
      break;

    case LI_EXTENDED_EA_WITH_CHECKSUM    :
      if (tvb_get_guint8(tvb, offset + P_VAR_PART_EDT) != VP_CHECKSUM ||
		tvb_get_guint8(tvb, offset + P_VAR_PART_EDT + 1) != 2)
	return -1;
      /* FALLTHROUGH */

    case LI_EXTENDED_EA_WITHOUT_CHECKSUM :
      tpdu_nr = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
      is_extended = TRUE;
      break;

    default : /* bad TPDU */
      return -1;
      /*NOTREACHED*/
      break;
  } /* li */

  if (check_col(pinfo->fd, COL_INFO))
    col_append_fstr(pinfo->fd, COL_INFO, 
		 "EA TPDU (%u) dst-ref: 0x%04x", tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, tvb, offset, 1,
			"Length indicator: %u", li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_text(cotp_tree, tvb, offset, 1,
			"TPDU code: 0x%x (EA)", tpdu);
  }
  offset += 1;
  li -= 1;

  if (tree) {
    proto_tree_add_text(cotp_tree, tvb, offset, 2,
			"Destination reference: 0x%04x", dst_ref);
  }
  offset += 2;
  li -= 2;

  if (is_extended) {
    if (tree) {
      proto_tree_add_text(cotp_tree, tvb, offset, 4,
			    "Your TPDU number: 0x%08x", tpdu_nr);
    }
    offset += 4;
    li -= 4;
  } else {
    if (tree) {
      proto_tree_add_text(cotp_tree, tvb, offset, 1,
			    "Your TPDU number: 0x%02x", tpdu_nr);
    }
    offset += 1;
    li -= 1;
  }

  if (tree)
    osi_decode_tp_var_part(tvb, offset, li, 4, cotp_tree);
  offset += li;

  return offset;

} /* osi_decode_EA */

static int osi_decode_ER(tvbuff_t *tvb, int offset, 
			 packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree;
  proto_item *ti;
  u_char *str;

  if (li > LI_MAX_ER) 
    return -1;

  switch(tvb_get_guint8(tvb, offset + P_REJECT_ER)) {
    case 0 :
      str = "Reason not specified";
      break;
    case 1 :
      str = "Invalid parameter code";
      break;
    case 2 :
      str = "Invalid TPDU type";
      break;
    case 3 :
      str = "Invalid parameter value";
      break;
    default:
      return -1;
      /*NOTREACHED*/
      break;
  }

  if (check_col(pinfo->fd, COL_INFO))
    col_append_fstr(pinfo->fd, COL_INFO, "ER TPDU dst-ref: 0x%04x", dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, tvb, offset,      1,
			"Length indicator: %u", li);
    proto_tree_add_text(cotp_tree, tvb, offset +  1, 1, 
			"TPDU code: 0x%x (ER)", tpdu); 
    proto_tree_add_text(cotp_tree, tvb, offset +  2, 2, 
			"Destination reference: 0x%04x", dst_ref);
    proto_tree_add_text(cotp_tree, tvb, offset +  4, 1, 
			"Reject cause: %s", str);
  }

  offset += li + 1;

  return offset;

} /* osi_decode_ER */

static int osi_decode_UD(tvbuff_t *tvb, int offset, 
			 packet_info *pinfo, proto_tree *tree,
			 gboolean *subdissector_found)
{
  proto_item *ti;
  proto_tree *cltp_tree = NULL;
  tvbuff_t   *next_tvb;

  if (check_col(pinfo->fd, COL_INFO))
    col_append_str(pinfo->fd, COL_INFO, "UD TPDU");

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cltp, tvb, offset, li + 1, FALSE);
    cltp_tree = proto_item_add_subtree(ti, ett_cltp);
    proto_tree_add_text(cltp_tree, tvb, offset, 1,
			"Length indicator: %u", li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_text(cltp_tree, tvb, offset, 1, 
			"TPDU code: 0x%x (UD)", tpdu);
  }
  offset += 1;
  li -= 1;

  if (tree)
    osi_decode_tp_var_part(tvb, offset, li, 0, cltp_tree);
  offset += li;

  next_tvb = tvb_new_subset(tvb, offset, -1, -1);
  dissect_data(next_tvb, 0, pinfo, tree);
  offset += tvb_length_remaining(tvb, offset);
     /* we dissected all of the containing PDU */

  return offset;

} /* osi_decode_UD */

/* Returns TRUE if we found at least one valid COTP or CLTP PDU, FALSE
   otherwise.

   There doesn't seem to be any way in which the OSI network layer protocol
   distinguishes between COTP and CLTP, but the first two octets of both
   protocols' headers mean the same thing - length and PDU type - and the
   only valid CLTP PDU type is not a valid COTP PDU type, so we'll handle
   both of them here. */
static gboolean dissect_ositp_internal(tvbuff_t *tvb, packet_info *pinfo,
		  proto_tree *tree, gboolean uses_inactive_subset) 
{
  int offset = 0;
  gboolean first_tpdu = TRUE;
  int new_offset;
  gboolean found_ositp = FALSE;
  gboolean is_cltp = FALSE;
  gboolean subdissector_found = FALSE;

  if (!proto_is_protocol_enabled(proto_cotp))
    return FALSE;	/* COTP has been disabled */
  /* XXX - what about CLTP? */

  pinfo->current_proto = "COTP";

  /* Initialize the COL_INFO field; each of the TPDUs will have its
     information appended. */
  if (check_col(pinfo->fd, COL_INFO))
    col_add_str(pinfo->fd, COL_INFO, "");

  while (tvb_offset_exists(tvb, offset)) {
    if (!first_tpdu) {
      if (check_col(pinfo->fd, COL_INFO))
        col_append_str(pinfo->fd, COL_INFO, ", ");
    }
    if ((li = tvb_get_guint8(tvb, offset + P_LI)) == 0) {
      if (check_col(pinfo->fd, COL_INFO))
        col_append_str(pinfo->fd, COL_INFO, "Length indicator is zero");
      if (!first_tpdu)
        dissect_data(tvb, offset, pinfo, tree);
      return found_ositp;
    }

    tpdu    = (tvb_get_guint8(tvb, offset + P_TPDU) >> 4) & 0x0F;
    if (tpdu == UD_TPDU)
      pinfo->current_proto = "CLTP";	/* connectionless transport */
    cdt     = tvb_get_guint8(tvb, offset + P_CDT) & 0x0F;
    dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);

    switch (tpdu) {
      case CC_TPDU :
      case CR_TPDU :
        new_offset = osi_decode_CC(tvb, offset, pinfo, tree);
        break;
      case DR_TPDU :
        new_offset = osi_decode_DR(tvb, offset, pinfo, tree);
        break;
      case DT_TPDU :
        new_offset = osi_decode_DT(tvb, offset, pinfo, tree,
				   uses_inactive_subset, &subdissector_found);
        break;
      case ED_TPDU :
        new_offset = osi_decode_ED(tvb, offset, pinfo, tree);
        break;
      case RJ_TPDU :
        new_offset = osi_decode_RJ(tvb, offset, pinfo, tree);
        break;
      case DC_TPDU :
        new_offset = osi_decode_DC(tvb, offset, pinfo, tree);
        break;
      case AK_TPDU :
        new_offset = osi_decode_AK(tvb, offset, pinfo, tree);
        break;
      case EA_TPDU :
        new_offset = osi_decode_EA(tvb, offset, pinfo, tree);
        break;
      case ER_TPDU :
        new_offset = osi_decode_ER(tvb, offset, pinfo, tree);
        break;
      case UD_TPDU :
        new_offset = osi_decode_UD(tvb, offset, pinfo, tree,
				   &subdissector_found);
        is_cltp = TRUE;
        break;
      default      :
        if (first_tpdu && check_col(pinfo->fd, COL_INFO))
          col_append_fstr(pinfo->fd, COL_INFO, "Unknown TPDU type (0x%x)", tpdu);
        new_offset = -1;	/* bad PDU type */
        break;
    }

    if (new_offset == -1) { /* incorrect TPDU */
      if (!first_tpdu)
        dissect_data(tvb, offset, pinfo, tree);
      break;
    }

    if (first_tpdu) {
      /* Well, we found at least one valid COTP or CLTP PDU, so I guess this
         is either COTP or CLTP. */
      if (!subdissector_found && check_col(pinfo->fd, COL_PROTOCOL))
        col_add_str(pinfo->fd, COL_PROTOCOL, is_cltp ? "CLTP" : "COTP");
      found_ositp = TRUE;
    }

    offset = new_offset;
    first_tpdu = FALSE;
  }
  return found_ositp;
} /* dissect_ositp_internal */

void dissect_ositp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) 
{
  if (!dissect_ositp_internal(tvb, pinfo, tree, FALSE))
    dissect_data(tvb, 0, pinfo, tree);
}


/*
 *  CLNP part / main entry point 
*/

static void dissect_clnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *clnp_tree = NULL;
  proto_item *ti;
  guint8      cnf_proto_id;
  guint8      cnf_hdr_len;
  guint8      cnf_vers;
  guint8      cnf_ttl;
  guint8      cnf_type;
  char        flag_string[6+1];
  char       *pdu_type_string;
  guint16     segment_length;
  guint16     segment_offset = 0;
  guint16     cnf_cksum;
  int         offset;
  u_char      src_len, dst_len, nsel, opt_len = 0;
  guint8     *dst_addr, *src_addr;
  guint       len;
  tvbuff_t   *next_tvb;

  CHECK_DISPLAY_AS_DATA(proto_clnp, tvb, pinfo, tree);

  pinfo->current_proto = "CLNP";

  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_add_str(pinfo->fd, COL_PROTOCOL, "CLNP");

  cnf_proto_id = tvb_get_guint8(tvb, P_CLNP_PROTO_ID);
  if (cnf_proto_id == NLPID_NULL) {
    if (check_col(pinfo->fd, COL_INFO))
      col_add_str(pinfo->fd, COL_INFO, "Inactive subset");
    if (tree) {
      ti = proto_tree_add_item(tree, proto_clnp, tvb, P_CLNP_PROTO_ID, 1, FALSE);
      clnp_tree = proto_item_add_subtree(ti, ett_clnp);
      proto_tree_add_uint_format(clnp_tree, hf_clnp_id, tvb, P_CLNP_PROTO_ID, 1, 
				 cnf_proto_id,
				 "Inactive subset");
    } 
    next_tvb = tvb_new_subset(tvb, 1, -1, -1);
    dissect_ositp_internal(next_tvb, pinfo, tree, TRUE);
    return;
  } 
 
  /* return if version not known */
  cnf_vers = tvb_get_guint8(tvb, P_CLNP_VERS);
  if (cnf_vers != ISO8473_V1) {
    dissect_data(tvb, 0, pinfo, tree);
    return;
  }

  /* fixed part decoding */
  cnf_hdr_len = tvb_get_guint8(tvb, P_CLNP_HDR_LEN);
  opt_len = cnf_hdr_len;

  if (tree) {
    ti = proto_tree_add_item(tree, proto_clnp, tvb, 0, cnf_hdr_len, FALSE);
    clnp_tree = proto_item_add_subtree(ti, ett_clnp);
    proto_tree_add_uint(clnp_tree, hf_clnp_id, tvb, P_CLNP_PROTO_ID, 1, 
			       cnf_proto_id);
    proto_tree_add_uint(clnp_tree, hf_clnp_length, tvb, P_CLNP_HDR_LEN, 1, 
			cnf_hdr_len); 
    proto_tree_add_uint(clnp_tree, hf_clnp_version, tvb, P_CLNP_VERS, 1, 
			cnf_vers);
    cnf_ttl = tvb_get_guint8(tvb, P_CLNP_TTL);
    proto_tree_add_uint_format(clnp_tree, hf_clnp_ttl, tvb, P_CLNP_TTL, 1, 
			       cnf_ttl,
			       "Holding Time : %u (%u secs)", 
			       cnf_ttl, cnf_ttl / 2);
  }

  cnf_type = tvb_get_guint8(tvb, P_CLNP_TYPE);
  pdu_type_string = val_to_str(cnf_type & CNF_TYPE, npdu_type_vals,
				"Unknown (0x%02x)");
  flag_string[0] = '\0';
  if (cnf_type & CNF_SEG_OK)
    strcat(flag_string, "S ");
  if (cnf_type & CNF_MORE_SEGS)
    strcat(flag_string, "M ");
  if (cnf_type & CNF_ERR_OK)
    strcat(flag_string, "E ");
  if (tree) {
    proto_tree_add_uint_format(clnp_tree, hf_clnp_type, tvb, P_CLNP_TYPE, 1,
			       cnf_type,
			       "PDU Type     : 0x%02x (%s%s)",
			       cnf_type,
			       flag_string,
			       pdu_type_string);
  }

  /* If we don't have the full header - i.e., not enough to see the
     segmentation part and determine whether this datagram is segmented
     or not - set the Info column now; we'll get an exception before
     we set it otherwise. */

  if (!tvb_bytes_exist(tvb, 0, cnf_hdr_len)) {
    if (check_col(pinfo->fd, COL_INFO))
      col_add_fstr(pinfo->fd, COL_INFO, "%s NPDU %s", pdu_type_string, flag_string);
  }

  segment_length = tvb_get_ntohs(tvb, P_CLNP_SEGLEN);
  if (tree) {
    proto_tree_add_uint(clnp_tree, hf_clnp_pdu_length, tvb, P_CLNP_SEGLEN, 2,
			segment_length);
    cnf_cksum = tvb_get_ntohs(tvb, P_CLNP_CKSUM);
    proto_tree_add_uint_format(clnp_tree, hf_clnp_checksum, tvb, P_CLNP_CKSUM, 2,
			       cnf_cksum,
			       "Checksum     : 0x%04x",
			       cnf_cksum);
    opt_len -= 9; /* Fixed part of Hesder */
  } /* tree */

  /* address part */
  
  offset = P_CLNP_ADDRESS_PART;
  dst_len  = tvb_get_guint8(tvb, offset);
  dst_addr = tvb_get_ptr(tvb, offset + 1, dst_len);
  nsel     = tvb_get_guint8(tvb, offset + dst_len);
  src_len  = tvb_get_guint8(tvb, offset + dst_len + 1);
  src_addr = tvb_get_ptr(tvb, offset + dst_len + 2, src_len);

  if (tree) {
    proto_tree_add_uint(clnp_tree, hf_clnp_dest_length, tvb, offset, 1, 
			dst_len);
    proto_tree_add_bytes_format(clnp_tree, hf_clnp_dest, tvb, offset + 1 , dst_len, 
			       dst_addr,
			       " DA : %s", 
			       print_nsap_net(dst_addr, dst_len));
    proto_tree_add_uint(clnp_tree, hf_clnp_src_length, tvb, 
			offset + 1 + dst_len, 1, src_len);
    proto_tree_add_bytes_format(clnp_tree, hf_clnp_src, tvb, 
			       offset + dst_len + 2, src_len,
			       src_addr,
			       " SA : %s", 
			       print_nsap_net(src_addr, src_len));

    opt_len -= dst_len + src_len +2;
  }

  if (check_col(pinfo->fd, COL_RES_NET_SRC))
    col_add_fstr(pinfo->fd, COL_RES_NET_SRC, "%s", print_nsap_net(src_addr, src_len));
  if (check_col(pinfo->fd, COL_RES_NET_DST))
    col_add_fstr(pinfo->fd, COL_RES_NET_DST, "%s", print_nsap_net(dst_addr, dst_len));

  /* Segmentation Part */

  offset += dst_len + src_len + 2;

  if (cnf_type & CNF_SEG_OK) {
    struct clnp_segment seg;			/* XXX - not used */
    tvb_memcpy(tvb, (guint8 *)&seg, offset, sizeof(seg));	/* XXX - not used */
    
    segment_offset = tvb_get_ntohs(tvb, offset + 2);
    if (tree) {
      proto_tree_add_text(clnp_tree, tvb, offset, 2, 
			"Data unit identifier: %06u",
			tvb_get_ntohs(tvb, offset));
      proto_tree_add_text(clnp_tree, tvb, offset + 2 , 2,
			"Segment offset      : %6u", 
			segment_offset);
      proto_tree_add_text(clnp_tree, tvb, offset + 4 , 2,
			"Total length        : %6u", 
			tvb_get_ntohs(tvb, offset + 4));
    }
    
    offset  += 6;
    opt_len -= 6;
  }

  if (tree) {
    /* To do : decode options  */
/*
    proto_tree_add_text(clnp_tree, tvb, offset, 
			cnf_hdr_len - offset,
			"Options/Data: <not shown>");
*/
/* QUICK HACK Option Len:= PDU_Hd_length-( FixedPart+AddresPart+SegmentPart )*/

    dissect_osi_options( 0xff, 
                         opt_len,
                         tvb, offset, pinfo, clnp_tree ); 
  }

  /* Length of CLNP datagram plus headers above it. */
  len = segment_length;

  /* Set the payload and captured-payload lengths to the minima of (the
     datagram length plus the length of the headers above it) and the
     frame lengths. */
  if (pinfo->len > len)
    pinfo->len = len;
  if (pinfo->captured_len > len)
    pinfo->captured_len = len;

  offset = cnf_hdr_len;

  /* For now, dissect the payload of segments other than the initial
     segment as data, rather than handing them off to the transport
     protocol, just as we do with fragments other than the first
     fragment in a fragmented IP datagram; in the future, we will
     probably reassemble fragments for IP, and may reassemble segments
     for CLNP. */
  if ((cnf_type & CNF_SEG_OK) && segment_offset != 0) {
    if (check_col(pinfo->fd, COL_INFO))
      col_add_fstr(pinfo->fd, COL_INFO, "Fragmented %s NPDU %s(off=%u)",
		pdu_type_string, flag_string, segment_offset);
    dissect_data(tvb, offset, pinfo, tree);
    return;
  }

  if (tvb_offset_exists(tvb, offset)) {
    switch (cnf_type & CNF_TYPE) {

    case DT_NPDU:
    case MD_NPDU:
      /* Continue with COTP if any data.
         XXX - if this isn't the first Derived PDU of a segmented Initial
         PDU, skip that? */

      if (nsel == (char)tp_nsap_selector || always_decode_transport) { 
        next_tvb = tvb_new_subset(tvb, offset, -1, -1);
        if (dissect_ositp_internal(next_tvb, pinfo, tree, FALSE))
          return;	/* yes, it appears to be COTP or CLTP */
      }
      break;

    case ER_NPDU:
      /* The payload is the header and "none, some, or all of the data
         part of the discarded PDU", i.e. it's like an ICMP error;
	 just as we don't yet trust ourselves to be able to dissect
	 the payload of an ICMP error packet, we don't yet trust
	 ourselves to dissect the payload of a CLNP ER packet. */
      break;

    case ERQ_NPDU:
    case ERP_NPDU:
      /* XXX - dissect this */
      break;
    }
  }
  if (check_col(pinfo->fd, COL_INFO))
    col_add_fstr(pinfo->fd, COL_INFO, "%s NPDU %s", pdu_type_string, flag_string);
  next_tvb = tvb_new_subset(tvb, offset, -1, -1);
  dissect_data(next_tvb, 0, pinfo, tree);

} /* dissect_clnp */


void proto_register_clnp(void)
{
  static hf_register_info hf[] = {
    { &hf_clnp_id,
      { "Network Layer Protocol Identifier", "clnp.nlpi", FT_UINT8, BASE_HEX, 
        VALS(nlpid_vals), 0x0, "" }},

    { &hf_clnp_length,
      { "HDR Length   ", "clnp.len",	   FT_UINT8, BASE_DEC, NULL, 0x0, "" }},

    { &hf_clnp_version,
      { "Version      ", "clnp.version",  FT_UINT8, BASE_DEC, NULL, 0x0, "" }},

    { &hf_clnp_ttl,
      { "Holding Time ", "clnp.ttl",	   FT_UINT8, BASE_DEC, NULL, 0x0, "" }},

    { &hf_clnp_type,
      { "PDU Type     ", "clnp.type",     FT_UINT8, BASE_DEC, NULL, 0x0, "" }},

    { &hf_clnp_pdu_length,
      { "PDU length   ", "clnp.pdu.len",  FT_UINT16, BASE_DEC, NULL, 0x0, "" }},

    { &hf_clnp_checksum,
      { "Checksum     ", "clnp.checksum", FT_UINT16, BASE_DEC, NULL, 0x0, "" }},

    { &hf_clnp_dest_length,
      { "DAL ", "clnp.dsap.len", FT_UINT8, BASE_DEC, NULL, 0x0, "" }},

    { &hf_clnp_dest,
      { " DA ", "clnp.dsap",     FT_BYTES, BASE_NONE, NULL, 0x0, "" }},

    { &hf_clnp_src_length,
      { "SAL ", "clnp.ssap.len", FT_UINT8, BASE_DEC, NULL, 0x0, "" }},

    { &hf_clnp_src,
      { " SA ", "clnp.ssap",     FT_BYTES, BASE_NONE, NULL, 0x0, "" }},
  };
  static gint *ett[] = {
    &ett_clnp,
  };

  module_t *clnp_module;

  proto_clnp = proto_register_protocol(PROTO_STRING_CLNP, "clnp");
  proto_register_field_array(proto_clnp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  clnp_module = prefs_register_module("clnp", "CLNP", NULL);
  prefs_register_uint_preference(clnp_module, "tp_nsap_selector",
	"NSAP selector for Transport Protocol (last byte in hexa)",
	"NSAP selector for Transport Protocol (last byte in hexa)",
       	16, &tp_nsap_selector);
  prefs_register_bool_preference(clnp_module, "always_decode_transport",
	"Always try to decode NSDU as transport PDUs",
	"Always try to decode NSDU as transport PDUs",
       	&always_decode_transport);

}

void proto_register_cotp(void)
{
  /*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "cotp.abbreviation", TYPE, VALS_POINTER }},
        };*/
	static gint *ett[] = {
		&ett_cotp,
	};

        proto_cotp = proto_register_protocol(PROTO_STRING_COTP, "cotp");
 /*       proto_register_field_array(proto_cotp, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));

/* subdissector code */
	register_heur_dissector_list("cotp_is", &cotp_is_heur_subdissector_list);
}

void proto_register_cltp(void)
{
  /*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "cltp.abbreviation", TYPE, VALS_POINTER }},
        };*/
	static gint *ett[] = {
		&ett_cltp,
	};

        proto_cltp = proto_register_protocol(PROTO_STRING_CLTP, "cltp");
 /*       proto_register_field_array(proto_cotp, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_clnp(void)
{
	dissector_add("osinl", NLPID_ISO8473_CLNP, dissect_clnp);
	dissector_add("osinl", NLPID_NULL, dissect_clnp);	/* Inactive subset */
}
