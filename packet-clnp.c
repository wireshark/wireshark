/* packet-clnp.c
 * Routines for ISO/OSI network and transport protocol packet disassembly
 *
 * $Id: packet-clnp.c,v 1.4 2000/04/18 18:01:50 deniel Exp $
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
#include "packet.h"
#include "packet-osi.h"
#include "packet-osi-options.h"
#include "packet-clnp.h"
#include "packet-isis.h"
#include "packet-esis.h"
#include "packet-h1.h"
#include "nlpid.h"

/* protocols and fields */

static int  proto_clnp         = -1;
static int  proto_cotp         = -1;
static gint ett_clnp           = -1;
static gint ett_cotp           = -1;

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

struct clnp_header {
  u_char	cnf_proto_id;	/* network layer protocol identifier */
  u_char	cnf_hdr_len;	/* length indicator (octets) */
  u_char	cnf_vers;	/* version/protocol identifier extension */
  u_char	cnf_ttl;      	/* lifetime (500 milliseconds) */
  u_char	cnf_type;      	/* type code */
  u_char	cnf_seglen_msb;	/* pdu segment length (octets) high byte */
  u_char	cnf_seglen_lsb;	/* pdu segment length (octets) low byte */
  u_char	cnf_cksum_msb;	/* checksum high byte */
  u_char	cnf_cksum_lsb;	/* checksum low byte */
};

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

#define P_ADDRESS_PART		9

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

#define ED_TPDU        		0x1
#define EA_TPDU        		0x2
#define RJ_TPDU        		0x5
#define AK_TPDU        		0x6
#define ER_TPDU        		0x7
#define DR_TPDU        		0x8
#define DC_TPDU        		0xC
#define CC_TPDU        		0xD
#define CR_TPDU        		0xE
#define DT_TPDU        		0xF

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
#define P_VAR_PART_NAK 		5
#define P_VAR_PART_CC  		7
#define P_VAR_PART_EAK 		10
#define P_VAR_PART_DC           6
#define P_VAR_PART_DR		7
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
#define LI_DC_WITH_CHECKSUM		 9
#define LI_DC_WITHOUT_CHECKSUM           5
#define is_LI_NORMAL_AK(p)               ( p & 0x01 )

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

/* misc */

#define EXTRACT_SHORT(p) 	pntohs(p)
#define EXTRACT_LONG(p) 	pntohl(p)

/* global variables */

static u_char  li, tpdu, cdt; 	/* common fields */
static u_short dst_ref;

/* function definitions */

static int osi_decode_DR(const u_char *pd, int offset, 
			 frame_data *fd, proto_tree *tree) 
{
  proto_tree *cotp_tree;
  proto_item *ti;
  u_short src_ref;
  u_char  reason;
  char *str;
  
  if (li < LI_MIN_DR) 
    return -1;
  
  src_ref = EXTRACT_SHORT(&pd[offset + P_SRC_REF]);
  reason  = pd[offset + P_REASON_IN_DR];

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

  if (check_col(fd, COL_INFO))
    col_append_fstr(fd, COL_INFO, "DR TPDU src-ref: 0x%04x dst-ref: 0x%04x",
		 src_ref, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, offset, li + 1, NULL);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, offset,      1,
			"Length indicator: %u", li);
    proto_tree_add_text(cotp_tree, offset +  1, 1, 
			"TPDU code: 0x%x (DR)", tpdu); 
    proto_tree_add_text(cotp_tree, offset +  2, 2, 
			"Destination reference: 0x%04x", dst_ref);
    proto_tree_add_text(cotp_tree, offset +  4, 2, 
			"Source reference: 0x%04x", src_ref);
    proto_tree_add_text(cotp_tree, offset +  6, 1, 
			"Cause: %s", str);
  }

  offset += li + 1;
  dissect_data(pd, offset, fd, tree);

  return pi.captured_len;	/* we dissected all of the containing PDU */

} /* osi_decode_DR */

/* Returns TRUE if we called a sub-dissector, FALSE if not. */
static gboolean osi_decode_DT(const u_char *pd, int offset, 
			 frame_data *fd, proto_tree *tree,
			 gboolean uses_inactive_subset)
{
  proto_tree *cotp_tree;
  proto_item *ti;
  u_int    tpdu_nr ;
  u_short  checksum = 0;
  u_char   code = 0, length = 0;
  u_int    fragment = 0;
    
  switch (li) {
    case LI_NORMAL_DT_WITH_CHECKSUM      :
      tpdu_nr = pd[offset + P_TPDU_NR_234];
      if ( tpdu_nr & 0x80 )
	tpdu_nr = tpdu_nr & 0x7F;
      else
	fragment = 1;
      code = pd[offset + P_VAR_PART_NDT];
      if (code == VP_CHECKSUM)
	checksum = EXTRACT_SHORT(&pd[offset + P_VAR_PART_NDT + 2]);
      else
	return -1;
      break;
    case LI_NORMAL_DT_WITHOUT_CHECKSUM   :
      tpdu_nr = pd[offset + P_TPDU_NR_234];
      if ( tpdu_nr & 0x80 )
	tpdu_nr = tpdu_nr & 0x7F;
      else
	fragment = 1;
      break;
    case LI_EXTENDED_DT_WITH_CHECKSUM    :
      tpdu_nr = EXTRACT_LONG(&pd[offset + P_TPDU_NR_234]);
      if ( tpdu_nr & 0x80000000 )
	tpdu_nr = tpdu_nr & 0x7FFFFFFF;
      else
	fragment = 1;
      code = pd[offset + P_VAR_PART_EDT];
      if (code == VP_CHECKSUM)
	checksum = EXTRACT_SHORT(&pd[offset + P_VAR_PART_EDT + 2]);
      else
	return -1;
      break;
    case LI_EXTENDED_DT_WITHOUT_CHECKSUM :
      tpdu_nr = EXTRACT_LONG(&pd[offset + P_TPDU_NR_234]);
      if ( tpdu_nr & 0x80000000 )
	tpdu_nr = tpdu_nr & 0x7FFFFFFF;
      else
	fragment = 1;
      break;
    case LI_NORMAL_DT_CLASS_01           :
      tpdu_nr = pd[offset + P_TPDU_NR_0_1];
      if ( tpdu_nr & 0x80 )
	tpdu_nr = tpdu_nr & 0x7F;
      else
	fragment = 1;      
      break;
    default : /* bad TPDU */
      return -1;
      /*NOTREACHED*/
      break;
  }

  if (check_col(fd, COL_INFO))
    col_append_fstr(fd, COL_INFO, "DT TPDU (%u) dst-ref: 0x%04x %s", 
		 tpdu_nr,
		 dst_ref,
		 (fragment)? "(fragment)" : "");

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, offset, li + 1, NULL);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, offset,      1,
			"Length indicator: %u", li);
    proto_tree_add_text(cotp_tree, offset +  1, 1, 
			"TPDU code: 0x%x (DT)", tpdu); 

    if (li != LI_NORMAL_DT_CLASS_01)
      proto_tree_add_text(cotp_tree, offset +  2, 2, 
			  "Destination reference: 0x%04x", dst_ref);

    switch (li) {
      case LI_NORMAL_DT_WITH_CHECKSUM      :
	proto_tree_add_text(cotp_tree, offset +  4, 1, 
			    "TPDU number: 0x%02x (%s)", 
			    tpdu_nr,
			    (fragment)? "fragment":"complete");
	proto_tree_add_text(cotp_tree, 
			    offset +  P_VAR_PART_NDT, 1, 
			    "Parameter code: 0x%02x (checksum)", code);
	proto_tree_add_text(cotp_tree, 
			    offset +  P_VAR_PART_NDT + 1, 1, 
			    "Parameter length: %u", length);
	proto_tree_add_text(cotp_tree, 
			    offset +  P_VAR_PART_NDT + 2, length, 
			    "Checksum: 0x%04x", checksum);
	break;
      case LI_NORMAL_DT_WITHOUT_CHECKSUM   :
	proto_tree_add_text(cotp_tree, offset +  4, 1, 
			    "TPDU number: 0x%02x (%s)", 
			    tpdu_nr,
			    (fragment)? "fragment":"complete");
	break;
      case LI_EXTENDED_DT_WITH_CHECKSUM    :
	proto_tree_add_text(cotp_tree, offset +  4, 4, 
			    "TPDU number: 0x%08x (%s)", 
			    tpdu_nr,
			    (fragment)? "fragment":"complete");
	proto_tree_add_text(cotp_tree, 
			    offset +  P_VAR_PART_EDT, 1, 
			    "Parameter code: 0x%02x (checksum)", code);
	proto_tree_add_text(cotp_tree, 
			    offset +  P_VAR_PART_EDT + 1, 1, 
			    "Parameter length: %u", length);
	proto_tree_add_text(cotp_tree, 
			    offset +  P_VAR_PART_EDT + 2, length, 
			    "Checksum: 0x%04x", checksum);
	break;
      case LI_EXTENDED_DT_WITHOUT_CHECKSUM :
	proto_tree_add_text(cotp_tree, offset +  4, 4, 
			    "TPDU number: 0x%08x (%s)", 
			    tpdu_nr,
			    (fragment)? "fragment":"complete");
	break;
      case LI_NORMAL_DT_CLASS_01           :
	proto_tree_add_text(cotp_tree, offset +  2, 1, 
			    "TPDU number: 0x%02x (%s)", 
			    tpdu_nr,
			    (fragment)? "fragment":"complete");
	break;
    }
  } /* tree */

  offset += li + 1;
  if (uses_inactive_subset){
	dissect_h1(pd, offset, fd, tree);
	return TRUE;
	}
  else {
	dissect_data(pd, offset, fd, tree);
	return FALSE;
	}
} /* osi_decode_DT */

static int osi_decode_ED(const u_char *pd, int offset, 
			 frame_data *fd, proto_tree *tree)
{
  proto_tree *cotp_tree;
  proto_item *ti;
  u_int    tpdu_nr ;
  u_short  checksum = 0;
  u_char   code = 0, length = 0;

  /* ED TPDUs are never fragmented */

  switch (li) {
    case LI_NORMAL_DT_WITH_CHECKSUM      :
      tpdu_nr = pd[offset + P_TPDU_NR_234];
      if ( tpdu_nr & 0x80 )
	tpdu_nr = tpdu_nr & 0x7F;
      else
	return -1;
      code = pd[offset + P_VAR_PART_NDT];
      length = pd[offset + P_VAR_PART_NDT + 1];
      if (code == VP_CHECKSUM)
	checksum = EXTRACT_SHORT(&pd[offset + P_VAR_PART_NDT + 2]);
      else
	return -1;
      break;
    case LI_NORMAL_DT_WITHOUT_CHECKSUM   :
      tpdu_nr = pd[offset + P_TPDU_NR_234];
      if ( tpdu_nr & 0x80 )
	tpdu_nr = tpdu_nr & 0x7F;
      else
	return -1;
      break;
    case LI_EXTENDED_DT_WITH_CHECKSUM    :
      tpdu_nr = EXTRACT_LONG(&pd[offset + P_TPDU_NR_234]);
      if ( tpdu_nr & 0x80000000 )
	tpdu_nr = tpdu_nr & 0x7FFFFFFF;
      else
	return -1;
      code = pd[offset + P_VAR_PART_EDT];
      length = pd[offset + P_VAR_PART_EDT + 1];
      if (code == VP_CHECKSUM)
	checksum = EXTRACT_SHORT(&pd[offset + P_VAR_PART_EDT + 2]);
      else
	return -1;
      break;
    case LI_EXTENDED_DT_WITHOUT_CHECKSUM :
      tpdu_nr = EXTRACT_LONG(&pd[offset + P_TPDU_NR_234]);
      if ( tpdu_nr & 0x80000000 )
	tpdu_nr = tpdu_nr & 0x7FFFFFFF;
      else
	return -1;
      break;
    default : /* bad TPDU */
      return -1;
      /*NOTREACHED*/
      break;
  } /* li */

  if (check_col(fd, COL_INFO))
    col_append_fstr(fd, COL_INFO, "ED TPDU (%u) dst-ref: 0x%04x", 
		 tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, offset, li + 1, NULL);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, offset,      1,
			"Length indicator: %u", li);
    proto_tree_add_text(cotp_tree, offset +  1, 1, 
			"TPDU code: 0x%x (ED)", tpdu); 
    proto_tree_add_text(cotp_tree, offset +  2, 2, 
			"Destination reference: 0x%04x", dst_ref);

    switch (li) {
      case LI_NORMAL_DT_WITH_CHECKSUM      :
	proto_tree_add_text(cotp_tree, offset +  4, 1, 
			    "TPDU number: 0x%02x", tpdu_nr);	
	proto_tree_add_text(cotp_tree, 
			    offset +  P_VAR_PART_NDT, 1, 
			    "Parameter code: 0x%02x (checksum)", code);
	proto_tree_add_text(cotp_tree, 
			    offset +  P_VAR_PART_NDT + 1, 1, 
			    "Parameter length: %u", length);
	proto_tree_add_text(cotp_tree, 
			    offset +  P_VAR_PART_NDT + 2, length, 
			    "Checksum: 0x%04x", checksum);
	break;
      case LI_NORMAL_DT_WITHOUT_CHECKSUM   :
	proto_tree_add_text(cotp_tree, offset +  4, 1, 
			    "TPDU number: 0x%02x", tpdu_nr);
	break;
      case LI_EXTENDED_DT_WITH_CHECKSUM    :
	proto_tree_add_text(cotp_tree, offset +  4, 4, 
			    "TPDU number: 0x%02x", tpdu_nr);	
	proto_tree_add_text(cotp_tree, 
			    offset +  P_VAR_PART_EDT, 1, 
			    "Parameter code: 0x%02x (checksum)", code);
	proto_tree_add_text(cotp_tree, 
			    offset +  P_VAR_PART_EDT + 1, 1, 
			    "Parameter length: %u", length);
	proto_tree_add_text(cotp_tree, 
			    offset +  P_VAR_PART_EDT + 2, length, 
			    "Checksum: 0x%04x", checksum);
	break;
      case LI_EXTENDED_DT_WITHOUT_CHECKSUM :
	proto_tree_add_text(cotp_tree, offset +  4, 4, 
			    "TPDU number: 0x%02x", tpdu_nr);
	break;
    }
  } /* tree */

  offset += li + 1;
  dissect_data(pd, offset, fd, tree);

  return pi.captured_len;	/* we dissected all of the containing PDU */

} /* osi_decode_ED */

static int osi_decode_RJ(const u_char *pd, int offset, 
			 frame_data *fd, proto_tree *tree)
{
  proto_tree *cotp_tree;
  proto_item *ti;
  u_int    tpdu_nr ;
  u_short  credit = 0;

  switch(li) {
    case LI_NORMAL_RJ   :
      tpdu_nr = pd[offset + P_TPDU_NR_234];
      break;
    case LI_EXTENDED_RJ :
      tpdu_nr = EXTRACT_LONG(&pd[offset + P_TPDU_NR_234]);
      credit = EXTRACT_SHORT(&pd[offset + P_CDT_IN_RJ]);
      break;
    default :
      return -1;
      /*NOTREACHED*/
      break;
  }

  if (check_col(fd, COL_INFO))
    col_append_fstr(fd, COL_INFO, "RJ TPDU (%u) dst-ref: 0x%04x", 
		 tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, offset, li + 1, NULL);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, offset,      1,
			"Length indicator: %u", li);
    proto_tree_add_text(cotp_tree, offset +  1, 1, 
			"TPDU code: 0x%x (RJ)", tpdu); 
    if (li == LI_NORMAL_RJ)
      proto_tree_add_text(cotp_tree, offset +  1, 1, 
			  "Credit: %u", cdt);
    proto_tree_add_text(cotp_tree, offset +  2, 2, 
			"Destination reference: 0x%04x", dst_ref);
    if (li == LI_NORMAL_RJ)
      proto_tree_add_text(cotp_tree, offset +  4, 1, 
			  "Your TPDU number: 0x%02x", tpdu_nr);
    else {
      proto_tree_add_text(cotp_tree, offset +  4, 4, 
			  "Your TPDU number: 0x%02x", tpdu_nr);
      proto_tree_add_text(cotp_tree, offset +  8, 2, 
			  "Credit: 0x%02x", credit);
    }
  }

  offset += li + 1;

  return offset;

} /* osi_decode_RJ */

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
	if (!isprint(tsap[i])) { /* if any byte is not printable */
	  allprintable=FALSE;    /* switch to hexdump */
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

static int osi_decode_CC(const u_char *pd, int offset, 
			 frame_data *fd, proto_tree *tree)
{

  /* CC & CR decoding in the same function */

  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  u_short src_ref, checksum;
  u_char  class_option, code, length;
  u_int   i = 0;

  src_ref = EXTRACT_SHORT(&pd[offset + P_SRC_REF]);
  class_option = (pd[offset + P_CLASS_OPTION] >> 4 ) & 0x0F;
  if (class_option > 4)
    return -1;

  if (check_col(fd, COL_INFO))
    col_append_fstr(fd, COL_INFO, "%s TPDU src-ref: 0x%04x dst-ref: 0x%04x",
		 (tpdu == CR_TPDU) ? "CR" : "CC",
		 src_ref,
		 dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, offset, li + 1, NULL);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, offset,      1,
			"Length indicator: %u", li);
    proto_tree_add_text(cotp_tree, offset +  1, 1, 
			"TPDU code: 0x%x (%s)", tpdu,
			(tpdu == CR_TPDU) ? "CR" : "CC"); 
    proto_tree_add_text(cotp_tree, offset +  2, 2, 
			"Destination reference: 0x%04x", dst_ref);
    proto_tree_add_text(cotp_tree, offset +  4, 2, 
			"Source reference: 0x%04x", src_ref);
    proto_tree_add_text(cotp_tree, offset +  6, 1, 
			"Class option: 0x%02x", class_option);
  }

  if (tree)
    while(li > P_VAR_PART_CC + i - 1) {
      
      u_char  c1;
      u_short s, s1,s2,s3,s4;
      u_int   t1,t2,t3,t4;
      
      switch( (code = pd[offset + P_VAR_PART_CC + i]) )	{
	case VP_CHECKSUM :
	  length   = pd[offset + P_VAR_PART_CC + i + 1];
	  checksum = EXTRACT_SHORT(&pd[offset + P_VAR_PART_CC + i + 2]);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i, 1, 
			      "Parameter code:   0x%02x (checksum)", code);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 1, 1, 
			      "Parameter length: %u", length);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 2, length, 
			      "Checksum:         0x%04x", checksum);
	  i += length + 2;
	  break;
	case VP_SRC_TSAP    :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i, 1, 
			      "Parameter code:   0x%02x (src-tsap)", code);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 1, 1, 
			      "Parameter length: %u", length);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 2, length, 
			      "Calling TSAP:     %s", 
			      print_tsap(&pd[offset + P_VAR_PART_CC + i + 2],
					 length));
	  i += length + 2;
	  break;
	case VP_DST_TSAP    :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i, 1, 
			      "Parameter code:   0x%02x (dst-tsap)", code);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 1, 1, 
			      "Parameter length: %u", length);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 2, length, 
			      "Called TSAP:      %s", 
			      print_tsap(&pd[offset + P_VAR_PART_CC + i + 2],
					 length));
	  i += length + 2;
	  break;
	case VP_TPDU_SIZE   :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  c1 = pd[offset + P_VAR_PART_CC + i + 2] & 0x0F;
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i, 1, 
			      "Parameter code:   0x%02x (tpdu-size)", code);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 1, 1, 
			      "Parameter length: %u", length);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 2, length, 
			      "TPDU size:        %u", 2 << c1);
	  i += length + 2;
	  break;
	case VP_OPT_SEL     :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  c1 = pd[offset + P_VAR_PART_CC + i + 2] & 0x0F;
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i, 1, 
			      "Parameter code:   0x%02x (options)", code);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 1, 1, 
			      "Parameter length: %u", length);
	  if (class_option == 1) {
	    if (c1 & 0x8)
	      proto_tree_add_text(cotp_tree, 
				  offset +  P_VAR_PART_CC + i + 2, 1,
				  "Use of network expedited data");
	    else
	      proto_tree_add_text(cotp_tree, 
				  offset +  P_VAR_PART_CC + i + 2, 1,
				  "Non use of network expedited data");
	    if (c1 & 0x4)
	      proto_tree_add_text(cotp_tree, 
				  offset +  P_VAR_PART_CC + i + 2, 1,
				  "Use of Receipt confirmation");
	    else
	      proto_tree_add_text(cotp_tree, 
				  offset +  P_VAR_PART_CC + i + 2, 1,
				  "Use of explicit AK variant");
	  } else if (class_option == 4) {
	    if (c1 & 0x2)
	      proto_tree_add_text(cotp_tree, 
				  offset +  P_VAR_PART_CC + i + 2, 1,
				  "Non-use 16 bit checksum in class 4");
	    else
	      proto_tree_add_text(cotp_tree, 
				  offset +  P_VAR_PART_CC + i + 2, 1,
				  "Use 16 bit checksum ");
	  }
	  if (c1 & 0x1)
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_CC + i + 2, 1,
				"Use of transport expedited data transfer\n");
	  else
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_CC + i + 2, 1,
				"Non-use of transport expedited data transfer");
	  i += length + 2;
	  break;
	case VP_ACK_TIME    :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  s = EXTRACT_SHORT(&pd[offset + P_VAR_PART_CC + i + 2]);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i, 1, 
			      "Parameter code: 0x%02x (ack time)", code);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 1, 1, 
			      "Parameter length: %u", length);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 2, length, 
			      "Ack time (ms): %u", s);
	  i += length + 2;
	  break;
	case VP_THROUGHPUT  :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  t1 = EXTRACT_LONG(&pd[offset + P_VAR_PART_CC + i + 1]);
	  t2 = EXTRACT_LONG(&pd[offset + P_VAR_PART_CC + i + 4]);
	  t3 = EXTRACT_LONG(&pd[offset + P_VAR_PART_CC + i + 7]);
	  t4 = EXTRACT_LONG(&pd[offset + P_VAR_PART_CC + i + 10]);
	  proto_tree_add_text(cotp_tree, 
                              offset +  P_VAR_PART_CC + i, 1, 
			      "Parameter code:  0x%02x (throughput)", code);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 1, 1, 
			      "Parameter length:              %u", length);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 2, 4, 
			      "Target value / calling-called: %u o/s", t1);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 6, 4, 
			      "Minimum / calling-called:      %u o/s", t2);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 10, 4, 
			      "Target value / called-calling: %u o/s", t3);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 14, 4, 
			      "Minimum / called-calling: %u o/s", t4);
	  i += length + 2;
	  break;
        case VP_TRANSIT_DEL :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  s1 = EXTRACT_SHORT(&pd[offset + P_VAR_PART_CC + i + 2]);
	  s2 = EXTRACT_SHORT(&pd[offset + P_VAR_PART_CC + i + 4]);
	  s3 = EXTRACT_SHORT(&pd[offset + P_VAR_PART_CC + i + 6]);
	  s4 = EXTRACT_SHORT(&pd[offset + P_VAR_PART_CC + i + 8]);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i, 1, 
			      "Parameter code: 0x%02x (transit delay)", code);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 1, 1, 
			      "Parameter length: %u", length);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 2, 2, 
			      "Target value / calling-called: %u ms", s1);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 4, 2, 
			      "Minimum / calling-called: %u ms", s2);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 6, 2, 
			      "Target value / called-calling: %u ms", s3);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 8, 2, 
			      "Minimum / called-calling: %u ms", s4);
	  i += length + 2;
	  break;
	case VP_PRIORITY    :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  s = EXTRACT_SHORT(&pd[offset + P_VAR_PART_CC + i + 2]);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i, 1, 
			      "Parameter code: 0x%02x (priority)", code);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 1, 1, 
			      "Parameter length: %u", length);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 2, length,
			      "Priority: %u", s);
	  i += length + 2;
	  break;
	
	case VP_VERSION_NR  :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  c1 = pd[offset + P_VAR_PART_CC + i + 2];
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i, 1, 
			      "Parameter code: 0x%02x (version)", code);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 1, 1, 
			      "Parameter length: %u", length);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 2, length,
			      "Version: %u", c1);
	  i += length + 2;
	  break;

	case VP_REASSIGNMENT: 	  /* todo */
	case VP_RES_ERROR   :
	case VP_PROTECTION  :
	case VP_PROTO_CLASS :
	default             :	  /* no decoding */
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 0, 1, 
			      "Parameter code: 0x%02x", code);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 1, 1, 
			      "Parameter length: %u", length);
	  proto_tree_add_text(cotp_tree, 
			      offset +  P_VAR_PART_CC + i + 2, length, 
			      "Parameter value: <not shown>");
	  i += length + 2;
	  break; 
      }
    } /* while */

  offset += li + 1;
  dissect_data(pd, offset, fd, tree);

  return pi.captured_len;	/* we dissected all of the containing PDU */

} /* osi_decode_CC */

static int osi_decode_DC(const u_char *pd, int offset, 
			 frame_data *fd, proto_tree *tree)
{
  proto_tree *cotp_tree;
  proto_item *ti;
  u_short src_ref, checksum = 0;
  u_char  length = 0, code = 0;

  if (li > LI_MAX_DC) 
    return -1;

  src_ref = EXTRACT_SHORT(&pd[offset + P_SRC_REF]);

  switch(li) {
    case LI_DC_WITHOUT_CHECKSUM :
      break;
    case LI_DC_WITH_CHECKSUM :
      if ((code = pd[offset + P_VAR_PART_DC]) != VP_CHECKSUM) 
	return -1;
      length   = pd[offset + P_VAR_PART_DC + 1];
      checksum = EXTRACT_SHORT(&pd[offset + P_VAR_PART_DC + 2]);
      break;
    default :
      return -1;
      /*NOTREACHED*/
      break;
  } /* li */

  if (check_col(fd, COL_INFO))
    col_append_fstr(fd, COL_INFO, "DC TPDU src-ref: 0x%04x dst-ref: 0x%04x", 
		 src_ref,
		 dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, offset, li + 1, NULL);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, offset,      1,
			"Length indicator: %u", li);
    proto_tree_add_text(cotp_tree, offset +  1, 1, 
			"TPDU code: 0x%x (DC)", tpdu); 
    proto_tree_add_text(cotp_tree, offset +  2, 2, 
			"Destination reference: 0x%04x", dst_ref);
    proto_tree_add_text(cotp_tree, offset +  4, 2, 
			"Source reference: 0x%04x", src_ref);
    if (code) {
      proto_tree_add_text(cotp_tree, 
			  offset +  P_VAR_PART_DC + 0, 1, 
			  "Parameter code: 0x%02x (checksum)", code);
      proto_tree_add_text(cotp_tree, 
			  offset +  P_VAR_PART_DC + 1, 1, 
			  "Parameter length: %u", length);
      proto_tree_add_text(cotp_tree, 
			  offset +  P_VAR_PART_DC + 2, 2, 
			  "Checksum: 0x%04x", checksum);
    }
  }

  offset += li + 1;

  return offset;

} /* osi_decode_DC */

static int osi_decode_AK(const u_char *pd, int offset, 
			 frame_data *fd, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  u_int      tpdu_nr,i =0, r_lower_window_edge ;
  u_short    cdt_in_ak;
  u_short    checksum, seq_nr, r_seq_nr, r_cdt;
  u_char     code, length;

  if (li > LI_MAX_AK) 
    return -1;

  if (!is_LI_NORMAL_AK(li)) {
    tpdu_nr = pd[offset + P_TPDU_NR_234];

    if (check_col(fd, COL_INFO))
      col_append_fstr(fd, COL_INFO, "AK TPDU (%u) dst-ref: 0x%04x", 
		   tpdu_nr, dst_ref);
    
    if (tree) {
      ti = proto_tree_add_item(tree, proto_cotp, offset, li + 1, NULL);
      cotp_tree = proto_item_add_subtree(ti, ett_cotp);
      proto_tree_add_text(cotp_tree, offset,      1,
			  "Length indicator: %u", li);
      proto_tree_add_text(cotp_tree, offset +  1, 1, 
			  "TPDU code: 0x%x (AK)", tpdu); 
      proto_tree_add_text(cotp_tree, offset +  1, 1, 
			  "Credit: %u", cdt);
      proto_tree_add_text(cotp_tree, offset +  2, 2, 
			  "Destination reference: 0x%04x", dst_ref);
      proto_tree_add_text(cotp_tree, offset +  4, 1, 
			  "Your TPDU number: 0x%02x", tpdu_nr);
    }

    while(li > P_VAR_PART_NAK + i - 1) {
      switch( (code = pd[offset + P_VAR_PART_NAK + i]) ) {
        case VP_CHECKSUM :
	  length   = pd[offset + P_VAR_PART_NAK + i + 1];
	  checksum = EXTRACT_SHORT(&pd[offset + P_VAR_PART_NAK + i + 2]);
	  if (tree) {
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_NAK + i + 0, 1, 
				"Parameter code: 0x%02x (checksum)", code);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_NAK + i + 1, 1, 
				"Parameter length: %u", length);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_NAK + i + 2, 2, 
				"Checksum: 0x%04x", checksum);
	  }
	  i += length + 2;
	  break;
        case VP_FLOW_CNTL :
	  length = pd[offset + P_VAR_PART_NAK + i + 1];
	  r_lower_window_edge = 
	    EXTRACT_LONG(&pd[offset + P_VAR_PART_NAK + i + 2]);
	  r_seq_nr = EXTRACT_SHORT(&pd[offset + P_VAR_PART_NAK + i + 6]);
	  r_cdt = EXTRACT_SHORT(&pd[offset + P_VAR_PART_NAK + i + 8]);
	  if (tree) {
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_NAK + i + 0, 1, 
				"Parameter code: 0x%02x (flow control)", 
				code);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_NAK + i + 1, 1, 
				"Parameter length: %u", length);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_NAK + i + 2, 4, 
				"Lower window edge: 0x%08x", 
				r_lower_window_edge);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_NAK + i + 6, 2, 
				"Sequence number: 0x%04x", 
				r_seq_nr);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_NAK + i + 8, 2, 
				"Credit: 0x%04x", 
				r_cdt);
	  }
	  i += length + 2;
	  break;
        case VP_SEQ_NR :
	  length = pd[offset + P_VAR_PART_NAK + i + 1];
	  seq_nr = EXTRACT_SHORT(&pd[offset + P_VAR_PART_NAK + i + 2]);
	  if (tree) {
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_NAK + i + 0, 1, 
				"Parameter code: 0x%02x (seq number)", code);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_NAK + i + 1, 1, 
				"Parameter length: %u", length);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_NAK + i + 2, 2, 
				"Sequence number: 0x%04x", seq_nr);
	  }
	  i += length + 2;
	  break;
        default :
	  length = pd[offset + P_VAR_PART_NAK + i + 1];
	  if (tree) {
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_NAK + i + 0, 1, 
				"Parameter code: 0x%02x (unknown)", code);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_NAK + i + 1, 1, 
				"Parameter length: %u", length);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_NAK + i + 2, length, 
				"Parameter value: <not shown>");
	  }
	  i += length + 2;
	  break;
      } /* code */
    }
  } else { /* extended format */
    
    tpdu_nr   = EXTRACT_LONG(&pd[offset + P_TPDU_NR_234]);
    cdt_in_ak = EXTRACT_SHORT(&pd[offset + P_CDT_IN_AK]);

    if (check_col(fd, COL_INFO))
      col_append_fstr(fd, COL_INFO, "AK TPDU (%u) dst-ref: 0x%04x", 
		   tpdu_nr, dst_ref);
    
    if (tree) {
      ti = proto_tree_add_item(tree, proto_cotp, offset, li + 1, NULL);
      cotp_tree = proto_item_add_subtree(ti, ett_cotp);
      proto_tree_add_text(cotp_tree, offset,      1,
			  "Length indicator: %u", li);
      proto_tree_add_text(cotp_tree, offset +  1, 1, 
			  "TPDU code: 0x%x (AK)", tpdu); 
      proto_tree_add_text(cotp_tree, offset +  2, 2, 
			  "Destination reference: 0x%04x", dst_ref);
      proto_tree_add_text(cotp_tree, offset +  4, 4, 
			  "Your TPDU number: 0x%08x", tpdu_nr);
      proto_tree_add_text(cotp_tree, offset +  8, 2, 
			  "Credit: 0x%04x", cdt_in_ak);
    }
    
    while(li > P_VAR_PART_EAK + i - 1) {
      switch( (code = pd[offset + P_VAR_PART_EAK + i]) ) {
        case VP_CHECKSUM :
	  length   = pd[offset + P_VAR_PART_EAK + i + 1];
	  checksum = EXTRACT_SHORT(&pd[offset + P_VAR_PART_EAK + i + 2]);
	  if (tree) {
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_EAK + i + 0, 1, 
				"Parameter code: 0x%02x (checksum)", code);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_EAK + i + 1, 1, 
				"Parameter length: %u", length);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_EAK + i + 2, 2, 
				"Checksum: 0x%04x", checksum);
	  }
	  i += length + 2;
	  break;
        case VP_FLOW_CNTL :
	  length   = pd[offset + P_VAR_PART_EAK + i + 1];
	  r_lower_window_edge = 
	    EXTRACT_LONG(&pd[offset + P_VAR_PART_EAK + i + 2]);
	  r_seq_nr = EXTRACT_SHORT(&pd[offset + P_VAR_PART_EAK + i + 6]);
	  r_cdt = EXTRACT_SHORT(&pd[offset + P_VAR_PART_EAK + i + 8]);
	  if (tree) {
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_EAK + i + 0, 1, 
				"Parameter code: 0x%02x (flow control)",
				code);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_EAK + i + 1, 1, 
				"Parameter length: %u", length);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_EAK + i + 2, 4, 
				"Lower window edge: 0x%08x", 
				r_lower_window_edge);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_EAK + i + 6, 2, 
				"Sequence number: 0x%04x", 
				r_seq_nr);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_EAK + i + 8, 2, 
				"Credit: 0x%04x", 
				r_cdt);
	  }
	  i += length + 2;
	  break;
        case VP_SEQ_NR :
	  length   = pd[offset + P_VAR_PART_EAK + i + 1];
	  seq_nr = EXTRACT_SHORT(&pd[offset + P_VAR_PART_EAK + i + 2]);
	  if (tree) {
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_EAK + i + 0, 1, 
				"Parameter code: 0x%02x (seq number)", code);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_EAK + i + 1, 1, 
				"Parameter length: %u", length);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_EAK + i + 2, 2, 
				"Sequence number: 0x%04x", seq_nr);
	  }
	  i += length + 2;
	  break;
        default :
	  length   = pd[offset + P_VAR_PART_EAK + i + 1];
	  if (tree) {
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_EAK + i + 0, 1, 
				"Parameter code: 0x%02x (unknown)", code);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_EAK + i + 1, 1, 
				"Parameter length: %u", length);
	    proto_tree_add_text(cotp_tree, 
				offset +  P_VAR_PART_EAK + i + 2, length, 
				"Parameter value: <not shown>");
	  }
	  i += length + 2;
	  break;
      } /* code */
    }
    
  } /* is_LI_NORMAL_AK */

  offset += li + 1;

  return offset;

} /* osi_decode_AK */

static int osi_decode_EA(const u_char *pd, int offset, 
			 frame_data *fd, proto_tree *tree)
{
  proto_tree *cotp_tree;
  proto_item *ti;
  u_int    tpdu_nr ;
  u_short  checksum = 0;
  u_char   code = 0;
  u_char   length = 0;

  if (li > LI_MAX_EA) 
    return -1;

  switch (li) {
    case LI_NORMAL_EA_WITH_CHECKSUM      :
      tpdu_nr = pd[offset + P_TPDU_NR_234];
      code    = pd[offset + P_VAR_PART_NDT];
      length  = pd[offset + P_VAR_PART_NDT + 1];
      if (code != VP_CHECKSUM || length != 1)
	return -1;
      checksum = EXTRACT_SHORT(&pd[offset + P_VAR_PART_NDT + 2]);
      break;
    case LI_NORMAL_EA_WITHOUT_CHECKSUM   :
      tpdu_nr = pd[offset + P_TPDU_NR_234];
      break;
    case LI_EXTENDED_EA_WITH_CHECKSUM    :
      tpdu_nr = EXTRACT_LONG(&pd[offset + P_TPDU_NR_234]);
      code    = pd[offset + P_VAR_PART_EDT];
      length  = pd[offset + P_VAR_PART_EDT + 1];
      if (code != VP_CHECKSUM || length != 1)
	return -1;
      checksum = EXTRACT_SHORT(&pd[offset + P_VAR_PART_EDT + 2]);
      break;
    case LI_EXTENDED_EA_WITHOUT_CHECKSUM :
      tpdu_nr = EXTRACT_LONG(&pd[offset + P_TPDU_NR_234]);
      break;
    default : /* bad TPDU */
      return -1;
      /*NOTREACHED*/
      break;
  } /* li */

  if (check_col(fd, COL_INFO))
    col_append_fstr(fd, COL_INFO, 
		 "EA TPDU (%u) dst-ref: 0x%04x", tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, offset, li + 1, NULL);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, offset,      1,
			"Length indicator: %u", li);
    proto_tree_add_text(cotp_tree, offset +  1, 1, 
			"TPDU code: 0x%x (EA)", tpdu); 
    proto_tree_add_text(cotp_tree, offset +  2, 2, 
			"Destination reference: 0x%04x", dst_ref);

    switch (li) {
      case LI_NORMAL_EA_WITH_CHECKSUM      :
	proto_tree_add_text(cotp_tree, offset +  4, 1, 
			    "Your TPDU number: 0x%02x", tpdu_nr);
	proto_tree_add_text(cotp_tree, offset +  5, 1, 
			    "Parameter code: 0x%02x (checksum)", code);
	proto_tree_add_text(cotp_tree, offset +  6, 1, 
			    "Parameter length: %u", length);
	proto_tree_add_text(cotp_tree, offset +  7, 2, 
			    "Checksum: 0x%04x", checksum);
	break;
      case LI_NORMAL_EA_WITHOUT_CHECKSUM   :
	proto_tree_add_text(cotp_tree, offset +  4, 1, 
			    "Your TPDU number: 0x%02x", tpdu_nr);
	break;
      case LI_EXTENDED_EA_WITH_CHECKSUM    :
	proto_tree_add_text(cotp_tree, offset +  4, 4, 
			    "Your TPDU number: 0x%08x", tpdu_nr);
	proto_tree_add_text(cotp_tree, offset +  8, 1, 
			    "Parameter code: 0x%02x (checksum)", code);
	proto_tree_add_text(cotp_tree, offset +  9, 1, 
			    "Parameter length: %u", length);
	proto_tree_add_text(cotp_tree, offset +  10, 2, 
			    "Checksum: 0x%04x", checksum);
	break;
      case LI_EXTENDED_EA_WITHOUT_CHECKSUM :
	proto_tree_add_text(cotp_tree, offset +  4, 4, 
			    "Your TPDU number: 0x%08x", tpdu_nr);
	break;
      default :
	break;
    } /* li */
  } /* tree */

  offset += li + 1;

  return offset;

} /* osi_decode_EA */

static int osi_decode_ER(const u_char *pd, int offset, 
			 frame_data *fd, proto_tree *tree)
{
  proto_tree *cotp_tree;
  proto_item *ti;
  u_char *str;

  if (li > LI_MAX_ER) 
    return -1;

  switch(pd[offset + P_REJECT_ER]) {
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

  if (check_col(fd, COL_INFO))
    col_append_fstr(fd, COL_INFO, "ER TPDU dst-ref: 0x%04x", dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, offset, li + 1, NULL);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_text(cotp_tree, offset,      1,
			"Length indicator: %u", li);
    proto_tree_add_text(cotp_tree, offset +  1, 1, 
			"TPDU code: 0x%x (ER)", tpdu); 
    proto_tree_add_text(cotp_tree, offset +  2, 2, 
			"Destination reference: 0x%04x", dst_ref);
    proto_tree_add_text(cotp_tree, offset +  4, 1, 
			"Reject cause: %s", str);
  }

  offset += li + 1;

  return offset;

} /* osi_decode_ER */

/* Returns TRUE if we found at least one valid COTP PDU, FALSE
   otherwise. */
static gboolean dissect_cotp_internal(const u_char *pd, int offset,
		  frame_data *fd, proto_tree *tree,
		  gboolean uses_inactive_subset) 
{
  gboolean first_tpdu = TRUE;
  int new_offset;
  gboolean found_cotp = FALSE;
  gboolean subdissector_found = FALSE;

  /* Initialize the COL_INFO field; each of the TPDUs will have its
     information appended. */
  if (check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO, "");

  while (IS_DATA_IN_FRAME(offset)) {
    if (!first_tpdu) {
      if (check_col(fd, COL_INFO))
        col_append_str(fd, COL_INFO, ", ");
    }
    if ((li = pd[offset + P_LI]) == 0) {
      if (check_col(fd, COL_INFO))
        col_append_str(fd, COL_INFO, "Length indicator is zero");
      if (!first_tpdu)
        dissect_data(pd, offset, fd, tree);
      return found_cotp;
    }
    if (!BYTES_ARE_IN_FRAME(offset, P_LI + li + 1)) {
      if (check_col(fd, COL_INFO))
        col_append_str(fd, COL_INFO, "Captured data in frame doesn't include entire frame");
      if (!first_tpdu)
        dissect_data(pd, offset, fd, tree);
      return found_cotp;
    }

    tpdu    = (pd[offset + P_TPDU] >> 4) & 0x0F;
    cdt     = pd[offset + P_CDT] & 0x0F;
    dst_ref = EXTRACT_SHORT(&pd[offset + P_DST_REF]);

    switch (tpdu) {
      case CC_TPDU :
      case CR_TPDU :
        new_offset = osi_decode_CC(pd, offset, fd, tree);
        break;
      case DR_TPDU :
        new_offset = osi_decode_DR(pd, offset, fd, tree);
        break;
      case DT_TPDU :
        if (osi_decode_DT(pd, offset, fd, tree, uses_inactive_subset))
          subdissector_found = TRUE;
        new_offset = pi.captured_len;	/* DT PDUs run to the end of the packet */
        break;
      case ED_TPDU :
        new_offset = osi_decode_ED(pd, offset, fd, tree);
        break;
      case RJ_TPDU :
        new_offset = osi_decode_RJ(pd, offset, fd, tree);
        break;
      case DC_TPDU :
        new_offset = osi_decode_DC(pd, offset, fd, tree);
        break;
      case AK_TPDU :
        new_offset = osi_decode_AK(pd, offset, fd, tree);
        break;
      case EA_TPDU :
        new_offset = osi_decode_EA(pd, offset, fd, tree);
        break;
      case ER_TPDU :
        new_offset = osi_decode_ER(pd, offset, fd, tree);
        break;
      default      :
        if (first_tpdu && check_col(fd, COL_INFO))
          col_append_fstr(fd, COL_INFO, "Unknown TPDU type (0x%x)", tpdu);
        new_offset = -1;	/* bad PDU type */
        break;
    }

    if (new_offset == -1) { /* incorrect TPDU */
      if (!first_tpdu)
        dissect_data(pd, offset, fd, tree);
      break;
    }

    if (first_tpdu) {
      /* Well, we found at least one valid COTP PDU, so I guess this
         is COTP. */
      if (!subdissector_found && check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, "COTP");
      found_cotp = TRUE;
    }

    offset = new_offset;
    first_tpdu = FALSE;
  }
  return found_cotp;
} /* dissect_cotp_internal */

void dissect_cotp(const u_char *pd, int offset, frame_data *fd,
		  proto_tree *tree) 
{
  if (!dissect_cotp_internal(pd, offset, fd, tree, FALSE))
    dissect_data(pd, offset, fd, tree);
}


/*
 *  CLNP part / main entry point 
*/

static void dissect_clnp(const u_char *pd, int offset, frame_data *fd,
		  proto_tree *tree) 
{

  struct clnp_header clnp;
  proto_tree *clnp_tree = NULL;
  proto_item *ti;
  u_char      src_len, dst_len, nsel, opt_len = 0;
  u_int       first_offset = offset;
  char flag_string[6+1];
  char *pdu_type_string;
  guint16 segment_length;
  guint16 segment_offset = 0;
  guint len;

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "CLNP");

  /* avoid alignment problem */
  memcpy(&clnp, &pd[offset], sizeof(clnp));

  if (clnp.cnf_proto_id == NLPID_NULL) {
    if (check_col(fd, COL_INFO))
      col_add_str(fd, COL_INFO, "Inactive subset");
    if (tree) {
      ti = proto_tree_add_item(tree, proto_clnp, offset, 1, NULL);
      clnp_tree = proto_item_add_subtree(ti, ett_clnp);
      proto_tree_add_uint_format(clnp_tree, hf_clnp_id, offset, 1, 
				 clnp.cnf_proto_id,
				 "Inactive subset");
    } 
    dissect_cotp_internal(pd, offset+1, fd, tree, TRUE);
    return;
  } 
 
  if (!BYTES_ARE_IN_FRAME(offset, sizeof(clnp))) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  /* return if version not known */
  if (clnp.cnf_vers != ISO8473_V1) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  /* fixed part decoding */
  opt_len = clnp.cnf_hdr_len;

  segment_length = EXTRACT_SHORT(&clnp.cnf_seglen_msb);
  flag_string[0] = '\0';
  if (clnp.cnf_type & CNF_SEG_OK)
    strcat(flag_string, "S ");
  if (clnp.cnf_type & CNF_MORE_SEGS)
    strcat(flag_string, "M ");
  if (clnp.cnf_type & CNF_ERR_OK)
    strcat(flag_string, "E ");
  pdu_type_string = val_to_str(clnp.cnf_type & CNF_TYPE, npdu_type_vals,
				"Unknown (0x%02x)");
  if (tree) {
    ti = proto_tree_add_item(tree, proto_clnp, offset, clnp.cnf_hdr_len, NULL);
    clnp_tree = proto_item_add_subtree(ti, ett_clnp);
    proto_tree_add_item(clnp_tree, hf_clnp_id, offset, 1, 
			       clnp.cnf_proto_id);
    proto_tree_add_item(clnp_tree, hf_clnp_length, offset +  1, 1, 
			clnp.cnf_hdr_len); 
    proto_tree_add_item(clnp_tree, hf_clnp_version, offset +  2, 1, 
			clnp.cnf_vers);
    proto_tree_add_uint_format(clnp_tree, hf_clnp_ttl, offset +  3, 1, 
			       clnp.cnf_ttl,
			       "Holding Time : %u (%u secs)", 
			       clnp.cnf_ttl, clnp.cnf_ttl / 2);
    proto_tree_add_uint_format(clnp_tree, hf_clnp_type, offset +  4, 1, 
			       clnp.cnf_type,
			       "PDU Type     : 0x%02x (%s%s)",
			       clnp.cnf_type,
			       flag_string,
			       pdu_type_string);
    proto_tree_add_item(clnp_tree, hf_clnp_pdu_length, offset +  5, 2, 
			segment_length);
    proto_tree_add_uint_format(clnp_tree, hf_clnp_checksum, offset +  7, 2,
			       EXTRACT_SHORT(&clnp.cnf_cksum_msb),
			       "Checksum     : 0x%04x",
			       EXTRACT_SHORT(&clnp.cnf_cksum_msb));
    opt_len -= 9; /* Fixed part of Hesder */
  } /* tree */

  /* stop here if header is not complete */

  if (!BYTES_ARE_IN_FRAME(offset, clnp.cnf_hdr_len)) {
    if (check_col(fd, COL_INFO))
      col_add_fstr(fd, COL_INFO, "%s NPDU %s", pdu_type_string, flag_string);
    dissect_data(pd, offset, fd, tree);
    return;
  }

  /* address part */
  
  offset += P_ADDRESS_PART;
  dst_len = pd[offset];
  nsel    = pd[offset + dst_len];
  src_len = pd[offset + dst_len + 1];

  if (tree) {
    proto_tree_add_item(clnp_tree, hf_clnp_dest_length, offset, 1, 
			dst_len);
    proto_tree_add_bytes_format(clnp_tree, hf_clnp_dest, offset + 1 , dst_len, 
			       &pd[offset + 1],
			       " DA : %s", 
			       print_nsap_net(&pd[offset + 1], dst_len));
    proto_tree_add_item(clnp_tree, hf_clnp_src_length, 
			offset + 1 + dst_len, 1, src_len);
    proto_tree_add_bytes_format(clnp_tree, hf_clnp_src, 
			       offset + dst_len + 2, src_len,
			       &pd[offset + dst_len + 2],
			       " SA : %s", 
			       print_nsap_net(&pd[offset + dst_len + 2], src_len));

    opt_len -= dst_len + src_len +2;
  }

  if (check_col(fd, COL_RES_NET_SRC))
    col_add_fstr(fd, COL_RES_NET_SRC, "%s", 
		 print_nsap_net(&pd[offset + dst_len + 2], src_len));
  if (check_col(fd, COL_RES_NET_DST))
    col_add_fstr(fd, COL_RES_NET_DST, "%s", 
		 print_nsap_net(&pd[offset + 1], dst_len));

  /* Segmentation Part */

  offset += dst_len + src_len + 2;

  if (clnp.cnf_type & CNF_SEG_OK) {
    struct clnp_segment seg;			/* XXX - not used */
    memcpy(&seg, &pd[offset], sizeof(seg));	/* XXX - not used */
    
    segment_offset = EXTRACT_SHORT(&pd[offset + 2]);
    if (tree) {
      proto_tree_add_text(clnp_tree, offset, 2, 
			"Data unit identifier: %06u",
			EXTRACT_SHORT(&pd[offset]));
      proto_tree_add_text(clnp_tree, offset + 2 , 2,
			"Segment offset      : %6u", 
			segment_offset);
      proto_tree_add_text(clnp_tree, offset + 4 , 2,
			"Total length        : %6u", 
			EXTRACT_SHORT(&pd[offset + 4]));
    }
    
    offset  += 6;
    opt_len -= 6;
  }

  if (tree) {
    /* To do : decode options  */
/*
    proto_tree_add_text(clnp_tree, offset, 
			clnp.cnf_hdr_len + first_offset - offset,
			"Options/Data: <not shown>");
*/
/* QUICK HACK Option Len:= PDU_Hd_length-( FixedPart+AddresPart+SegmentPart )*/

    dissect_osi_options( 0xff, 
                         opt_len,
                         pd, offset, fd, clnp_tree ); 
  }

  /* Length of CLNP datagram plus headers above it. */
  len = segment_length + first_offset;

  /* Set the payload and captured-payload lengths to the minima of (the
     datagram length plus the length of the headers above it) and the
     frame lengths. */
  if (pi.len > len)
    pi.len = len;
  if (pi.captured_len > len)
    pi.captured_len = len;

  offset = first_offset + clnp.cnf_hdr_len;

  /* For now, dissect the payload of segments other than the initial
     segment as data, rather than handing them off to the transport
     protocol, just as we do with fragments other than the first
     fragment in a fragmented IP datagram; in the future, we will
     probably reassemble fragments for IP, and may reassemble segments
     for CLNP. */
  if ((clnp.cnf_type & CNF_SEG_OK) && segment_offset != 0) {
    if (check_col(fd, COL_INFO))
      col_add_fstr(fd, COL_INFO, "Fragmented %s NPDU %s(off=%u)",
		pdu_type_string, flag_string, segment_offset);
    dissect_data(pd, offset, fd, tree);
    return;
  }

  if (IS_DATA_IN_FRAME(offset)) {
    switch (clnp.cnf_type & CNF_TYPE) {

    case DT_NPDU:
    case MD_NPDU:
      /* Continue with COTP if any data.
         XXX - if this isn't the first Derived PDU of a segmented Initial
         PDU, skip that? */

      if (nsel == NSEL_TP) { 	/* just guessing here - valid for DECNet-OSI */
        if (dissect_cotp_internal(pd, offset, fd, tree, FALSE))
          return;	/* yes, it appears to be COTP */
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
  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "%s NPDU %s", pdu_type_string, flag_string);
  dissect_data(pd, offset, fd, tree);

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

  proto_clnp = proto_register_protocol(PROTO_STRING_CLNP, "clnp");
  proto_register_field_array(proto_clnp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
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
}

void
proto_reg_handoff_clnp(void)
{
	dissector_add("osinl", NLPID_ISO8473_CLNP, dissect_clnp);
	dissector_add("osinl", NLPID_NULL, dissect_clnp);	/* Inactive subset */
}
