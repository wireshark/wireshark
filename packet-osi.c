/* packet-osi.c
 * Routines for ISO/OSI network and transport protocol packet disassembly
 *
 * $Id: packet-osi.c,v 1.6 1999/03/23 03:14:41 gram Exp $
 * Laurent Deniel <deniel@worldnet.fr>
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
 *
 * To do:
 *
 * - add other network protocols (ES,IS-IS)
 * - add NSAP decoding & resolution
 * - complete CLNP decoding (options)
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
#include <glib.h>
#include "packet.h"

/* Network layer protocol identifiers */

#define ISO8473_CLNP		0x81
#define	ISO9542_ESIS		0x82
#define ISO10589_ISIS		0x83
#define ISO9542X25_ESIS		0x8a

/*
 * ISO8473 OSI CLNP definition (see RFC994)
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

#define	ISO8473_V1		0x01	/* CLNP version 1 */

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

#define ER_NPDU			0x01
#define DT_NPDU			0x1C

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
    case (128+1): str = "Remote transport enity congestion"; break;
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

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "COTP");
  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "DR TPDU src-ref: 0x%04x dst-ref: 0x%04x",
	    src_ref, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, offset, li + 1, "ISO COTP");
    cotp_tree = proto_tree_new();
    proto_item_add_subtree(ti, cotp_tree, ETT_COTP);
    proto_tree_add_item(cotp_tree, offset,      1,
		     "Length indicator: %d", li);
    proto_tree_add_item(cotp_tree, offset +  1, 1, 
		     "TPDU code: Ox%x (DR)", tpdu); 
    proto_tree_add_item(cotp_tree, offset +  2, 2, 
		     "Destination reference: 0x%04x", dst_ref);
    proto_tree_add_item(cotp_tree, offset +  4, 2, 
		     "Source reference: 0x%04x", src_ref);
    proto_tree_add_item(cotp_tree, offset +  6, 1, 
		     "Cause: %s", str);
  }

  offset += li + 1;
  dissect_data(pd, offset, fd, tree);

  return 0;

} /* osi_decode_DR */

static int osi_decode_DT(const u_char *pd, int offset, 
			 frame_data *fd, proto_tree *tree) 
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

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "COTP");
  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "DT TPDU (%d) dst-ref: 0x%04x %s", 
	    tpdu_nr,
	    dst_ref,
	    (fragment)? "(fragment)" : "");

  if (tree) {
    ti = proto_tree_add_item(tree, offset, li + 1, "ISO COTP");
    cotp_tree = proto_tree_new();
    proto_item_add_subtree(ti, cotp_tree, ETT_COTP);
    proto_tree_add_item(cotp_tree, offset,      1,
		     "Length indicator: %d", li);
    proto_tree_add_item(cotp_tree, offset +  1, 1, 
		     "TPDU code: Ox%x (DT)", tpdu); 

    if (li != LI_NORMAL_DT_CLASS_01)
      proto_tree_add_item(cotp_tree, offset +  2, 2, 
		       "Destination reference: 0x%04x", dst_ref);

    switch (li) {
      case LI_NORMAL_DT_WITH_CHECKSUM      :
	proto_tree_add_item(cotp_tree, offset +  4, 1, 
			 "TPDU number: 0x%02x (%s)", 
			 tpdu_nr,
			 (fragment)? "fragment":"complete");
	proto_tree_add_item(cotp_tree, 
			 offset +  P_VAR_PART_NDT, 1, 
			 "Parameter code: 0x%02x (checksum)", code);
	proto_tree_add_item(cotp_tree, 
			 offset +  P_VAR_PART_NDT + 1, 1, 
			 "Parameter length: 0x%02x", length);
	proto_tree_add_item(cotp_tree, 
			 offset +  P_VAR_PART_NDT + 2, length, 
			 "Checksum: 0x%04x", checksum);
	break;
      case LI_NORMAL_DT_WITHOUT_CHECKSUM   :
	proto_tree_add_item(cotp_tree, offset +  4, 1, 
			 "TPDU number: 0x%02x (%s)", 
			 tpdu_nr,
			 (fragment)? "fragment":"complete");
	break;
      case LI_EXTENDED_DT_WITH_CHECKSUM    :
	proto_tree_add_item(cotp_tree, offset +  4, 4, 
			 "TPDU number: 0x%08x (%s)", 
			 tpdu_nr,
			 (fragment)? "fragment":"complete");
	proto_tree_add_item(cotp_tree, 
			 offset +  P_VAR_PART_EDT, 1, 
			 "Parameter code: 0x%02x (checksum)", code);
	proto_tree_add_item(cotp_tree, 
			 offset +  P_VAR_PART_EDT + 1, 1, 
			 "Parameter length: 0x%02x", length);
	proto_tree_add_item(cotp_tree, 
			 offset +  P_VAR_PART_EDT + 2, length, 
			 "Checksum: 0x%04x", checksum);
	break;
      case LI_EXTENDED_DT_WITHOUT_CHECKSUM :
	proto_tree_add_item(cotp_tree, offset +  4, 4, 
			 "TPDU number: 0x%08x (%s)", 
			 tpdu_nr,
			 (fragment)? "fragment":"complete");
	break;
      case LI_NORMAL_DT_CLASS_01           :
	proto_tree_add_item(cotp_tree, offset +  2, 1, 
			 "TPDU number: 0x%02x (%s)", 
			 tpdu_nr,
			 (fragment)? "fragment":"complete");
	break;
    }
  } /* tree */

  offset += li + 1;
  dissect_data(pd, offset, fd, tree);

  return 0;

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

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "COTP");
  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "ED TPDU (%d) dst-ref: 0x%04x", tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, offset, li + 1, "ISO COTP");
    cotp_tree = proto_tree_new();
    proto_item_add_subtree(ti, cotp_tree, ETT_COTP);
    proto_tree_add_item(cotp_tree, offset,      1,
		     "Length indicator: %d", li);
    proto_tree_add_item(cotp_tree, offset +  1, 1, 
		     "TPDU code: Ox%x (ED)", tpdu); 
    proto_tree_add_item(cotp_tree, offset +  2, 2, 
		     "Destination reference: 0x%04x", dst_ref);

    switch (li) {
      case LI_NORMAL_DT_WITH_CHECKSUM      :
	proto_tree_add_item(cotp_tree, offset +  4, 1, 
			 "TPDU number: 0x%02x", tpdu_nr);	
	proto_tree_add_item(cotp_tree, 
			 offset +  P_VAR_PART_NDT, 1, 
			 "Parameter code: 0x%02x (checksum)", code);
	proto_tree_add_item(cotp_tree, 
			 offset +  P_VAR_PART_NDT + 1, 1, 
			 "Parameter length: 0x%02x", length);
	proto_tree_add_item(cotp_tree, 
			 offset +  P_VAR_PART_NDT + 2, length, 
			 "Checksum: 0x%04x", checksum);
	break;
      case LI_NORMAL_DT_WITHOUT_CHECKSUM   :
	proto_tree_add_item(cotp_tree, offset +  4, 1, 
			 "TPDU number: 0x%02x", tpdu_nr);
	break;
      case LI_EXTENDED_DT_WITH_CHECKSUM    :
	proto_tree_add_item(cotp_tree, offset +  4, 4, 
			 "TPDU number: 0x%02x", tpdu_nr);	
	proto_tree_add_item(cotp_tree, 
			 offset +  P_VAR_PART_EDT, 1, 
			 "Parameter code: 0x%02x (checksum)", code);
	proto_tree_add_item(cotp_tree, 
			 offset +  P_VAR_PART_EDT + 1, 1, 
			 "Parameter length: 0x%02x", length);
	proto_tree_add_item(cotp_tree, 
			 offset +  P_VAR_PART_EDT + 2, length, 
			 "Checksum: 0x%04x", checksum);
	break;
      case LI_EXTENDED_DT_WITHOUT_CHECKSUM :
	proto_tree_add_item(cotp_tree, offset +  4, 4, 
			 "TPDU number: 0x%02x", tpdu_nr);
	break;
    }
  } /* tree */

  offset += li + 1;
  dissect_data(pd, offset, fd, tree);

  return 0;

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

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "COTP");
  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "RJ TPDU (%d) dst-ref: 0x%04x", tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, offset, li + 1, "ISO COTP");
    cotp_tree = proto_tree_new();
    proto_item_add_subtree(ti, cotp_tree, ETT_COTP);
    proto_tree_add_item(cotp_tree, offset,      1,
		     "Length indicator: %d", li);
    proto_tree_add_item(cotp_tree, offset +  1, 1, 
		     "TPDU code: Ox%x (RJ)", tpdu); 
    if (li == LI_NORMAL_RJ)
      proto_tree_add_item(cotp_tree, offset +  1, 1, 
		       "Credit: %d", cdt);
    proto_tree_add_item(cotp_tree, offset +  2, 2, 
		     "Destination reference: 0x%04x", dst_ref);
    if (li == LI_NORMAL_RJ)
      proto_tree_add_item(cotp_tree, offset +  4, 1, 
		       "Your TPDU number: 0x%02x", tpdu_nr);
    else {
      proto_tree_add_item(cotp_tree, offset +  4, 4, 
		       "Your TPDU number: 0x%02x", tpdu_nr);
      proto_tree_add_item(cotp_tree, offset +  8, 2, 
		       "Credit: 0x%02x", credit);
    }
  }

  offset += li + 1;
  dissect_data(pd, offset, fd, tree);

  return 0;

} /* osi_decode_RJ */

#define MAX_TSAP_LEN	32

static gchar *print_tsap(const u_char *tsap, int length)
{

  static gchar  str[3][MAX_TSAP_LEN * 2 + 1];
  static gchar *cur;
  gchar tmp[3];

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }

  /* to do: test if all bytes are printable */

  cur[0] = '\0';
  if (length <= 0 || length > MAX_TSAP_LEN) 
    sprintf(cur, "<unsupported TSAP length>");
  else {    
    while (length != 0) {
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

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "COTP");
  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "%s TPDU src-ref: 0x%04x dst-ref: 0x%04x",
	    (tpdu == CR_TPDU) ? "CR" : "CC",
	    src_ref,
	    dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, offset, li + 1, "ISO COTP");
    cotp_tree = proto_tree_new();
    proto_item_add_subtree(ti, cotp_tree, ETT_COTP);
    proto_tree_add_item(cotp_tree, offset,      1,
		     "Length indicator: %d", li);
    proto_tree_add_item(cotp_tree, offset +  1, 1, 
		     "TPDU code: Ox%x (%s)", tpdu,
		     (tpdu == CR_TPDU) ? "CR" : "CC"); 
    proto_tree_add_item(cotp_tree, offset +  2, 2, 
		     "Destination reference: 0x%04x", dst_ref);
    proto_tree_add_item(cotp_tree, offset +  4, 2, 
		     "Source reference: 0x%04x", src_ref);
    proto_tree_add_item(cotp_tree, offset +  6, 1, 
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
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i, 1, 
			   "Parameter code: 0x%02x (checksum)", code);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 1, 1, 
			   "Parameter length: 0x%02x", length);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 2, length, 
			   "Checksum: 0x%04x", checksum);
	  i += length + 2;
	  break;
	case VP_SRC_TSAP    :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i, 1, 
			   "Parameter code: 0x%02x (src-tsap)", code);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 1, 1, 
			   "Parameter length: 0x%02x", length);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 2, length, 
			   "Calling TSAP: 0x%s", 
			   print_tsap(&pd[offset + P_VAR_PART_CC + i + 2],
				      length));
	  i += length + 2;
	  break;
	case VP_DST_TSAP    :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i, 1, 
			   "Parameter code: 0x%02x (dst-tsap)", code);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 1, 1, 
			   "Parameter length: 0x%02x", length);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 2, length, 
			   "Called TSAP: 0x%s", 
			   print_tsap(&pd[offset + P_VAR_PART_CC + i + 2],
				      length));
	  i += length + 2;
	  break;
	case VP_TPDU_SIZE   :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  c1 = pd[offset + P_VAR_PART_CC + i + 2] & 0x0F;
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i, 1, 
			   "Parameter code: 0x%02x (tpdu-size)", code);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 1, 1, 
			   "Parameter length: 0x%02x", length);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 2, length, 
			   "TPDU size: %d", 2 << c1);
	  i += length + 2;
	  break;
	case VP_OPT_SEL     :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  c1 = pd[offset + P_VAR_PART_CC + i + 2] & 0x0F;
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i, 1, 
			   "Parameter code: 0x%02x (options)", code);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 1, 1, 
			   "Parameter length: 0x%02x", length);
	  if (class_option == 1) {
	    if (c1 & 0x8)
	      proto_tree_add_item(cotp_tree, 
			       offset +  P_VAR_PART_CC + i + 2, 1,
			       "Use of network expedited data");
	    else
	      proto_tree_add_item(cotp_tree, 
			       offset +  P_VAR_PART_CC + i + 2, 1,
			       "Non use of network expedited data");
	    if (c1 & 0x4)
	      proto_tree_add_item(cotp_tree, 
			       offset +  P_VAR_PART_CC + i + 2, 1,
			       "Use of Receipt confirmation");
	    else
	      proto_tree_add_item(cotp_tree, 
			       offset +  P_VAR_PART_CC + i + 2, 1,
			       "Use of explicit AK variant");
	  } else if (class_option == 4) {
	    if (c1 & 0x2)
	      proto_tree_add_item(cotp_tree, 
			       offset +  P_VAR_PART_CC + i + 2, 1,
			       "Use 16 bit checksum ");
	    else
	      proto_tree_add_item(cotp_tree, 
			       offset +  P_VAR_PART_CC + i + 2, 1,
			       "Non-use 16 bit checksum in class 4");
	  }
	  if (c1 & 0x1)
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_CC + i + 2, 1,
			     "Use of transport expedited data transfer\n");
	  else
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_CC + i + 2, 1,
			     "Non-use of transport expedited data transfer");
	  i += length + 2;
	  break;
	case VP_ACK_TIME    :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  s = EXTRACT_SHORT(&pd[offset + P_VAR_PART_CC + i + 2]);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i, 1, 
			   "Parameter code: 0x%02x (ack time)", code);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 1, 1, 
			   "Parameter length: 0x%02x", length);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 2, length, 
			   "Ack time (ms): %d", s);
	  i += length + 2;
	  break;
	case VP_THROUGHPUT  :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  t1 = EXTRACT_LONG(&pd[offset + P_VAR_PART_CC + i + 1]);
	  t2 = EXTRACT_LONG(&pd[offset + P_VAR_PART_CC + i + 4]);
	  t3 = EXTRACT_LONG(&pd[offset + P_VAR_PART_CC + i + 7]);
	  t4 = EXTRACT_LONG(&pd[offset + P_VAR_PART_CC + i + 10]);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i, 1, 
			   "Parameter code: 0x%02x (throughput)", code);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 1, 1, 
			   "Parameter length: 0x%02x", length);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 2, 4, 
			   "Target value / calling-called: %d o/s", t1);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 6, 4, 
			   "Minimum / calling-called: %d o/s", t2);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 10, 4, 
			   "Target value / called-calling: %d o/s", t3);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 14, 4, 
			   "Minimum / called-calling: %d o/s", t4);
	  i += length + 2;
	  break;
	case VP_TRANSIT_DEL :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  s1 = EXTRACT_SHORT(&pd[offset + P_VAR_PART_CC + i + 2]);
	  s2 = EXTRACT_SHORT(&pd[offset + P_VAR_PART_CC + i + 4]);
	  s3 = EXTRACT_SHORT(&pd[offset + P_VAR_PART_CC + i + 6]);
	  s4 = EXTRACT_SHORT(&pd[offset + P_VAR_PART_CC + i + 8]);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i, 1, 
			   "Parameter code: 0x%02x (transit delay)", code);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 1, 1, 
			   "Parameter length: 0x%02x", length);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 2, 2, 
			   "Target value / calling-called: %d ms", s1);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 4, 2, 
			   "Minimum / calling-called: %d ms", s2);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 6, 2, 
			   "Target value / called-calling: %d ms", s3);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 8, 2, 
			   "Minimum / called-calling: %d ms", s4);
	  i += length + 2;
	  break;
	case VP_PRIORITY    :
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  s = EXTRACT_SHORT(&pd[offset + P_VAR_PART_CC + i + 2]);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i, 1, 
			   "Parameter code: 0x%02x (priority)", code);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 1, 1, 
			   "Parameter length: 0x%02x", length);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 2, length,
			   "Priority: %d", s);
	  i += length + 2;
	  break;

	case VP_REASSIGNMENT: 	  /* todo */
	case VP_RES_ERROR   :
	case VP_VERSION_NR  :
	case VP_PROTECTION  :
	case VP_PROTO_CLASS :
	default             :	  /* no decoding */
	  length = pd[offset + P_VAR_PART_CC + i + 1];
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 0, 1, 
			   "Parameter code: 0x%02x", code);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 1, 1, 
			   "Parameter length: 0x%02x", length);
	  proto_tree_add_item(cotp_tree, 
			   offset +  P_VAR_PART_CC + i + 2, length, 
			   "Parameter value: <not shown>");
	  i += length + 2;
	  break; 
      }
    } /* while */

  offset += li + 1;
  dissect_data(pd, offset, fd, tree);

  return 0;

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

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "COTP");
  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "DC TPDU src-ref: 0x%04x dst-ref: 0x%04x", 
	    src_ref,
	    dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, offset, li + 1, "ISO COTP");
    cotp_tree = proto_tree_new();
    proto_item_add_subtree(ti, cotp_tree, ETT_COTP);
    proto_tree_add_item(cotp_tree, offset,      1,
		     "Length indicator: %d", li);
    proto_tree_add_item(cotp_tree, offset +  1, 1, 
		     "TPDU code: Ox%x (DC)", tpdu); 
    proto_tree_add_item(cotp_tree, offset +  2, 2, 
		     "Destination reference: 0x%04x", dst_ref);
    proto_tree_add_item(cotp_tree, offset +  4, 2, 
		     "Source reference: 0x%04x", src_ref);
    if (code) {
      proto_tree_add_item(cotp_tree, 
		       offset +  P_VAR_PART_DC + 0, 1, 
		       "Parameter code: 0x%02x (checksum)", code);
      proto_tree_add_item(cotp_tree, 
		       offset +  P_VAR_PART_DC + 1, 1, 
		       "Parameter length: 0x%02x", length);
      proto_tree_add_item(cotp_tree, 
		       offset +  P_VAR_PART_DC + 2, 2, 
		       "Checksum: 0x%04x", checksum);
    }
  }

  offset += li + 1;
  dissect_data(pd, offset, fd, tree);

  return 0;

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

    if (check_col(fd, COL_PROTOCOL))
      col_add_str(fd, COL_PROTOCOL, "COTP");
    if (check_col(fd, COL_INFO))
      col_add_fstr(fd, COL_INFO, "AK TPDU (%d) dst-ref: 0x%04x", 
	      tpdu_nr, dst_ref);
    
    if (tree) {
      ti = proto_tree_add_item(tree, offset, li + 1, "ISO COTP");
      cotp_tree = proto_tree_new();
      proto_item_add_subtree(ti, cotp_tree, ETT_COTP);
      proto_tree_add_item(cotp_tree, offset,      1,
		       "Length indicator: %d", li);
      proto_tree_add_item(cotp_tree, offset +  1, 1, 
		       "TPDU code: Ox%x (AK)", tpdu); 
      proto_tree_add_item(cotp_tree, offset +  1, 1, 
		       "Credit: %d", cdt);
      proto_tree_add_item(cotp_tree, offset +  2, 2, 
		       "Destination reference: 0x%04x", dst_ref);
      proto_tree_add_item(cotp_tree, offset +  4, 1, 
		       "Your TPDU number: 0x%02x", tpdu_nr);
    }

    while(li > P_VAR_PART_NAK + i - 1) {
      switch( (code = pd[offset + P_VAR_PART_NAK + i]) ) {
        case VP_CHECKSUM :
	  length   = pd[offset + P_VAR_PART_NAK + i + 1];
	  checksum = EXTRACT_SHORT(&pd[offset + P_VAR_PART_NAK + i + 2]);
	  if (tree) {
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_NAK + i + 0, 1, 
			     "Parameter code: 0x%02x (checksum)", code);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_NAK + i + 1, 1, 
			     "Parameter length: 0x%02x", length);
	    proto_tree_add_item(cotp_tree, 
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
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_NAK + i + 0, 1, 
			     "Parameter code: 0x%02x (flow control)", 
			     code);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_NAK + i + 1, 1, 
			     "Parameter length: 0x%02x", length);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_NAK + i + 2, 4, 
			     "Lower window edge: 0x%08x", 
			     r_lower_window_edge);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_NAK + i + 6, 2, 
			     "Sequence number: 0x%04x", 
			     r_seq_nr);
	    proto_tree_add_item(cotp_tree, 
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
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_NAK + i + 0, 1, 
			     "Parameter code: 0x%02x (seq number)", code);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_NAK + i + 1, 1, 
			     "Parameter length: 0x%02x", length);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_NAK + i + 2, 2, 
			     "Sequence number: 0x%04x", seq_nr);
	  }
	  i += length + 2;
	  break;
        default :
	  length = pd[offset + P_VAR_PART_NAK + i + 1];
	  if (tree) {
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_NAK + i + 0, 1, 
			     "Parameter code: 0x%02x (unknown)", code);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_NAK + i + 1, 1, 
			     "Parameter length: 0x%02x", length);
	    proto_tree_add_item(cotp_tree, 
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

    if (check_col(fd, COL_PROTOCOL))
      col_add_str(fd, COL_PROTOCOL, "COTP");
    if (check_col(fd, COL_INFO))
      col_add_fstr(fd, COL_INFO, "AK TPDU (%d) dst-ref: 0x%04x", 
	      tpdu_nr, dst_ref);
    
    if (tree) {
      ti = proto_tree_add_item(tree, offset, li + 1, "ISO COTP");
      cotp_tree = proto_tree_new();
      proto_item_add_subtree(ti, cotp_tree, ETT_COTP);
      proto_tree_add_item(cotp_tree, offset,      1,
		       "Length indicator: %d", li);
      proto_tree_add_item(cotp_tree, offset +  1, 1, 
		       "TPDU code: Ox%x (AK)", tpdu); 
      proto_tree_add_item(cotp_tree, offset +  2, 2, 
		       "Destination reference: 0x%04x", dst_ref);
      proto_tree_add_item(cotp_tree, offset +  4, 4, 
		       "Your TPDU number: 0x%08x", tpdu_nr);
      proto_tree_add_item(cotp_tree, offset +  8, 2, 
		       "Credit: 0x%04x", cdt_in_ak);
    }
    
    while(li > P_VAR_PART_EAK + i - 1) {
      switch( (code = pd[offset + P_VAR_PART_EAK + i]) ) {
        case VP_CHECKSUM :
	  length   = pd[offset + P_VAR_PART_EAK + i + 1];
	  checksum = EXTRACT_SHORT(&pd[offset + P_VAR_PART_EAK + i + 2]);
	  if (tree) {
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_EAK + i + 0, 1, 
			     "Parameter code: 0x%02x (checksum)", code);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_EAK + i + 1, 1, 
			     "Parameter length: 0x%02x", length);
	    proto_tree_add_item(cotp_tree, 
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
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_EAK + i + 0, 1, 
			     "Parameter code: 0x%02x (flow control)",
			     code);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_EAK + i + 1, 1, 
			     "Parameter length: 0x%02x", length);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_EAK + i + 2, 4, 
			     "Lower window edge: 0x%08x", 
			     r_lower_window_edge);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_EAK + i + 6, 2, 
			     "Sequence number: 0x%04x", 
			     r_seq_nr);
	    proto_tree_add_item(cotp_tree, 
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
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_EAK + i + 0, 1, 
			     "Parameter code: 0x%02x (seq number)", code);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_EAK + i + 1, 1, 
			     "Parameter length: 0x%02x", length);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_EAK + i + 2, 2, 
			     "Sequence number: 0x%04x", seq_nr);
	  }
	  i += length + 2;
	  break;
        default :
	  length   = pd[offset + P_VAR_PART_EAK + i + 1];
	  if (tree) {
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_EAK + i + 0, 1, 
			     "Parameter code: 0x%02x (unknown)", code);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_EAK + i + 1, 1, 
			     "Parameter length: 0x%02x", length);
	    proto_tree_add_item(cotp_tree, 
			     offset +  P_VAR_PART_EAK + i + 2, length, 
			     "Parameter value: <not shown>");
	  }
	  i += length + 2;
	  break;
      } /* code */
    }
    
  } /* is_LI_NORMAL_AK */

  offset += li + 1;
  dissect_data(pd, offset, fd, tree);

  return 0;

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

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "COTP");
  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "EA TPDU (%d) dst-ref: 0x%04x", tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, offset, li + 1, "ISO COTP");
    cotp_tree = proto_tree_new();
    proto_item_add_subtree(ti, cotp_tree, ETT_COTP);
    proto_tree_add_item(cotp_tree, offset,      1,
		     "Length indicator: %d", li);
    proto_tree_add_item(cotp_tree, offset +  1, 1, 
		     "TPDU code: Ox%x (EA)", tpdu); 
    proto_tree_add_item(cotp_tree, offset +  2, 2, 
		     "Destination reference: 0x%04x", dst_ref);

    switch (li) {
      case LI_NORMAL_EA_WITH_CHECKSUM      :
	proto_tree_add_item(cotp_tree, offset +  4, 1, 
			 "Your TPDU number: 0x%02x", tpdu_nr);
	proto_tree_add_item(cotp_tree, offset +  5, 1, 
			 "Parameter code: 0x%02x (checksum)", code);
	proto_tree_add_item(cotp_tree, offset +  6, 1, 
			 "Parameter length: 0x%02x", length);
	proto_tree_add_item(cotp_tree, offset +  7, 2, 
			 "Checksum: 0x%04x", checksum);
	break;
      case LI_NORMAL_EA_WITHOUT_CHECKSUM   :
	proto_tree_add_item(cotp_tree, offset +  4, 1, 
			 "Your TPDU number: 0x%02x", tpdu_nr);
	break;
      case LI_EXTENDED_EA_WITH_CHECKSUM    :
	proto_tree_add_item(cotp_tree, offset +  4, 4, 
			 "Your TPDU number: 0x%08x", tpdu_nr);
	proto_tree_add_item(cotp_tree, offset +  8, 1, 
			 "Parameter code: 0x%02x (checksum)", code);
	proto_tree_add_item(cotp_tree, offset +  9, 1, 
			 "Parameter length: 0x%02x", length);
	proto_tree_add_item(cotp_tree, offset +  10, 2, 
			 "Checksum: 0x%04x", checksum);
	break;
      case LI_EXTENDED_EA_WITHOUT_CHECKSUM :
	proto_tree_add_item(cotp_tree, offset +  4, 4, 
			 "Your TPDU number: 0x%08x", tpdu_nr);
	break;
      default :
	break;
    } /* li */
  } /* tree */

  offset += li + 1;
  dissect_data(pd, offset, fd, tree);

  return 0;

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

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "COTP");
  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "ER TPDU dst-ref: 0x%04x", dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, offset, li + 1, "ISO COTP");
    cotp_tree = proto_tree_new();
    proto_item_add_subtree(ti, cotp_tree, ETT_COTP);
    proto_tree_add_item(cotp_tree, offset,      1,
		     "Length indicator: %d", li);
    proto_tree_add_item(cotp_tree, offset +  1, 1, 
		     "TPDU code: Ox%x (ER)", tpdu); 
    proto_tree_add_item(cotp_tree, offset +  2, 2, 
		     "Destination reference: 0x%04x", dst_ref);
    proto_tree_add_item(cotp_tree, offset +  4, 1, 
		     "Reject cause: %s", str);
  }

  offset += li + 1;
  dissect_data(pd, offset, fd, tree);

  return 0;

} /* osi_decode_ER */

void dissect_cotp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{

  int status = -1;

  if (((li = pd[offset + P_LI]) == 0) ||
      (offset + P_LI + li + 1 > fd->cap_len)) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  tpdu    = (pd[offset + P_TPDU] >> 4) & 0x0F;
  cdt     = pd[offset + P_CDT] & 0x0F;
  dst_ref = EXTRACT_SHORT(&pd[offset + P_DST_REF]);

  switch (tpdu) {
    case CC_TPDU :
    case CR_TPDU :
      status = osi_decode_CC(pd, offset, fd, tree);
      break;
    case DR_TPDU :
      status = osi_decode_DR(pd, offset, fd, tree);
      break;
    case DT_TPDU :
      status = osi_decode_DT(pd, offset, fd, tree);
      break;
    case ED_TPDU :
      status = osi_decode_ED(pd, offset, fd, tree);
      break;
    case RJ_TPDU :
      status = osi_decode_RJ(pd, offset, fd, tree);
      break;
    case DC_TPDU :
      status = osi_decode_DC(pd, offset, fd, tree);
      break;
    case AK_TPDU :
      status = osi_decode_AK(pd, offset, fd, tree);
      break;
    case EA_TPDU :
      status = osi_decode_EA(pd, offset, fd, tree);
      break;
    case ER_TPDU :
      status = osi_decode_ER(pd, offset, fd, tree);
      break;
    default      :
      break;
  }

  if (status == -1) /* incorrect TPDU */
    dissect_data(pd, offset, fd, tree);

} /* dissect_cotp */


/*
 *  CLNP part 
 */

#define MAX_NSAP_LEN	20

static gchar *print_nsap(const u_char *nsap, int length)
{

  /* to do : real NSAP decoding */

  static gchar  str[3][MAX_NSAP_LEN * 3 + 1];
  static gchar *cur;
  gchar tmp[5];

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }

  cur[0] = '\0';
  if (length <= 0 || length > MAX_NSAP_LEN) 
    sprintf(cur, "<invalid NSAP>");
  else
    while (length != 1) {
      sprintf(tmp, "%02x:", *nsap ++);
      strcat(cur, tmp);
      length --;
    }
  sprintf(tmp, "%02x", *nsap);
  strcat(cur, tmp);
  return cur;

} /* print_nsap */

void dissect_clnp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{

  struct clnp_header clnp;
  proto_tree *clnp_tree = NULL;
  proto_item *ti;
  u_char src_len, dst_len, nsel;
  u_int first_offset = offset;

  if (fd->cap_len < offset + sizeof(clnp)) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  /* avoid alignment problem */
  memcpy(&clnp, &pd[offset], sizeof(clnp));
  
  /* return if version not known */
  if (clnp.cnf_vers != ISO8473_V1) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  /* fixed part decoding */

  if (tree) {
    ti = proto_tree_add_item(tree, offset, clnp.cnf_hdr_len, "ISO CLNP");
    clnp_tree = proto_tree_new();
    proto_item_add_subtree(ti, clnp_tree, ETT_CLNP);
    proto_tree_add_item(clnp_tree, offset,      1,
		     "Protocol identifier: 0x%02x", clnp.cnf_proto_id);
    proto_tree_add_item(clnp_tree, offset +  1, 1, 
		     "Length: %d", clnp.cnf_hdr_len); 
    proto_tree_add_item(clnp_tree, offset +  2, 1, 
		     "Version: %d", clnp.cnf_vers);
    proto_tree_add_item(clnp_tree, offset +  3, 1, 
		     "TTL: %d (%d secs)", 
		     clnp.cnf_ttl, clnp.cnf_ttl / 2);
    proto_tree_add_item(clnp_tree, offset +  4, 1, 
		     "Type code: 0x%02x (%s%s%s%s)", 
		     clnp.cnf_type,
		     (clnp.cnf_type & CNF_SEG_OK) ? "S " : "",
		     (clnp.cnf_type & CNF_MORE_SEGS) ? "M " : "",
		     (clnp.cnf_type & CNF_ERR_OK) ? "E " : "",
		     (clnp.cnf_type & CNF_TYPE) == DT_NPDU ? "DT" : "ER");
    proto_tree_add_item(clnp_tree, offset +  5, 2, 
		     "PDU segment length: %d",
		     EXTRACT_SHORT(&clnp.cnf_seglen_msb));
    proto_tree_add_item(clnp_tree, offset +  7, 2, 
		     "Checksum: 0x%04x",
		     EXTRACT_SHORT(&clnp.cnf_cksum_msb));
  } /* tree */

  /* stop here if header is not complete */

  if (fd->cap_len < offset + clnp.cnf_hdr_len) {
    dissect_data(pd, offset, fd, tree);
    return;
  }

  /* address part */
  
  offset += P_ADDRESS_PART;
  dst_len = pd[offset];
  nsel    = pd[offset + dst_len];
  src_len = pd[offset + dst_len + 1];

  if (tree) {
    proto_tree_add_item(clnp_tree, offset, 1, 
		     "Destination address length: 0x%02x", dst_len);
    proto_tree_add_item(clnp_tree, offset + 1 , dst_len, 
		     "Destination address: %s", 
		     print_nsap(&pd[offset + 1], dst_len));
    proto_tree_add_item(clnp_tree, offset + 1 + dst_len, 1, 
		     "Source address length: 0x%02x", src_len);
    proto_tree_add_item(clnp_tree, offset + dst_len + 2, src_len, 
		     "Source address: %s", 
		     print_nsap(&pd[offset + dst_len + 2], src_len));
  }

  if (check_col(fd, COL_RES_NET_SRC))
    col_add_fstr(fd, COL_RES_NET_SRC, "%s", 
	    print_nsap(&pd[offset + dst_len + 2], src_len));
  if (check_col(fd, COL_RES_NET_DST))
    col_add_fstr(fd, COL_RES_NET_DST, "%s", 
	    print_nsap(&pd[offset + 1], dst_len));

  /* Segmentation Part */

  offset += dst_len + src_len + 2;

  if (tree && (clnp.cnf_type & CNF_SEG_OK)) {
    struct clnp_segment seg;
    memcpy(&seg, &pd[offset], sizeof(seg));
    
    proto_tree_add_item(clnp_tree, offset, 2, 
		     "Data unit identifier: 0x%04x",
		     EXTRACT_SHORT(&pd[offset]));
    proto_tree_add_item(clnp_tree, offset + 2 , 2,
		     "Segment offset: 0x%04x", 
		     EXTRACT_SHORT(&pd[offset + 2]));
    proto_tree_add_item(clnp_tree, offset + 4 , 2,
		     "Total length: 0x%04x", 
		     EXTRACT_SHORT(&pd[offset + 4]));
    
    offset += 6;
  }

  if (tree) {
    /* To do : decode options  */

    proto_tree_add_item(clnp_tree, offset, 
		     clnp.cnf_hdr_len + first_offset - offset,
		     "Options/Data: <not shown>");
  }


  offset = first_offset + clnp.cnf_hdr_len;

  if (offset == fd->cap_len)
    return;

  /* continue with COTP if any */

  if (nsel == NSEL_TP) 	/* just guessing here - valid for DECNet-OSI */
    dissect_cotp(pd, offset, fd, tree);
  else
    dissect_data(pd, offset, fd, tree);

} /* dissect_clnp */


/* main entry point */

void dissect_osi(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{

  switch (pd[offset]) {

      /* only CLNP is currently decoded */

    case ISO8473_CLNP:
      if (check_col(fd, COL_PROTOCOL)) 
	{
	  col_add_str(fd, COL_PROTOCOL, "CLNP");
	}      
      dissect_clnp(pd, offset, fd, tree);
      break;
    case ISO9542_ESIS:
      if (check_col(fd, COL_PROTOCOL)) 
	{
	  col_add_str(fd, COL_PROTOCOL, "ESIS");
	}
      dissect_data(pd, offset, fd, tree);
      break;
    case ISO9542X25_ESIS:
      if (check_col(fd, COL_PROTOCOL)) 
	{
	  col_add_str(fd, COL_PROTOCOL, "ESIS(X25)");
	}
      dissect_data(pd, offset, fd, tree);
      break;
    case ISO10589_ISIS:
      if (check_col(fd, COL_PROTOCOL)) 
	{
	  col_add_str(fd, COL_PROTOCOL, "ISIS");
	}
      dissect_data(pd, offset, fd, tree);
      break;
    default:
      if (check_col(fd, COL_PROTOCOL)) 
	{
	  col_add_str(fd, COL_PROTOCOL, "ISO");
	}
      if (check_col(fd, COL_INFO)) 
	{
	  col_add_fstr(fd, COL_INFO, "Unknown ISO protocol (%02x)", pd[offset]);
	}
      dissect_data(pd, offset, fd, tree);
      break;
  }
  
} /* dissect_osi */

