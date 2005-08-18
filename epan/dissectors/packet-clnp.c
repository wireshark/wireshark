/* packet-clnp.c
 * Routines for ISO/OSI network and transport protocol packet disassembly
 *
 * $Id$
 * Laurent Deniel <laurent.deniel@free.fr>
 * Ralf Schneider <Ralf.Schneider@t-online.de>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/emem.h>
#include "packet-osi.h"
#include "packet-osi-options.h"
#include "packet-isis.h"
#include "packet-esis.h"
#include "nlpid.h"
#include <epan/ipproto.h>

/* protocols and fields */

static int  proto_clnp         = -1;
static gint ett_clnp           = -1;
static gint ett_clnp_type      = -1;
static gint ett_clnp_segments  = -1;
static gint ett_clnp_segment   = -1;
static gint ett_clnp_disc_pdu  = -1;

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
static int hf_clnp_segments    = -1;
static int hf_clnp_segment     = -1;
static int hf_clnp_segment_overlap = -1;
static int hf_clnp_segment_overlap_conflict = -1;
static int hf_clnp_segment_multiple_tails = -1;
static int hf_clnp_segment_too_long_segment = -1;
static int hf_clnp_segment_error = -1;
static int hf_clnp_reassembled_in = -1;

static int  proto_cotp         = -1;
static gint ett_cotp           = -1;
static gint ett_cotp_segments  = -1;
static gint ett_cotp_segment   = -1;

static int hf_cotp_srcref      = -1;
static int hf_cotp_destref     = -1;
static int hf_cotp_tpdu_number = -1;
static int hf_cotp_tpdu_number_extended = -1;
static int hf_cotp_next_tpdu_number = -1;
static int hf_cotp_next_tpdu_number_extended = -1;
static int hf_cotp_eot			= -1;
static int hf_cotp_eot_extended	= -1;

static int hf_cotp_li          = -1;
static int hf_cotp_type        = -1;
static int hf_cotp_segments    = -1;
static int hf_cotp_segment     = -1;
static int hf_cotp_segment_overlap = -1;
static int hf_cotp_segment_overlap_conflict = -1;
static int hf_cotp_segment_multiple_tails = -1;
static int hf_cotp_segment_too_long_segment = -1;
static int hf_cotp_segment_error = -1;
static int hf_cotp_reassembled_in = -1;

static const true_false_string fragment_descriptions = {
	"Yes",
	"No"
};

static int  proto_cltp         = -1;
static gint ett_cltp           = -1;

static int hf_cltp_li = -1;
static int hf_cltp_type = -1;

static const fragment_items clnp_frag_items = {
	&ett_clnp_segment,
	&ett_clnp_segments,
	&hf_clnp_segments,
	&hf_clnp_segment,
	&hf_clnp_segment_overlap,
	&hf_clnp_segment_overlap_conflict,
	&hf_clnp_segment_multiple_tails,
	&hf_clnp_segment_too_long_segment,
	&hf_clnp_segment_error,
	&hf_clnp_reassembled_in,
	"segments"
};

static const fragment_items cotp_frag_items = {
	&ett_cotp_segment,
	&ett_cotp_segments,
	&hf_cotp_segments,
	&hf_cotp_segment,
	&hf_cotp_segment_overlap,
	&hf_cotp_segment_overlap_conflict,
	&hf_cotp_segment_multiple_tails,
	&hf_cotp_segment_too_long_segment,
	&hf_cotp_segment_error,
	&hf_cotp_reassembled_in,
	"segments"
};

static dissector_handle_t clnp_handle;
static dissector_handle_t data_handle;

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

static const value_string npdu_type_abbrev_vals[] = {
  { DT_NPDU,	"DT" },
  { MD_NPDU,	"MD" },
  { ER_NPDU,	"ER" },
  { ERQ_NPDU,	"ERQ" },
  { ERP_NPDU,	"ERP" },
  { 0,		NULL }
};

static const value_string npdu_type_vals[] = {
  { DT_NPDU,	"Data" },
  { MD_NPDU,	"Multicast Data" },
  { ER_NPDU,	"Error Report" },
  { ERQ_NPDU,	"Echo Request" },
  { ERP_NPDU,	"Echo Response" },
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
  gushort	cng_id;		/* data unit identifier */
  gushort	cng_off;	/* segment offset */
  gushort	cng_tot_len;	/* total length */
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

static const value_string cotp_tpdu_type_abbrev_vals[] = {
  { ED_TPDU,	"ED Expedited Data" },
  { EA_TPDU,	"EA Expedited Data Acknowledgement" },
  { RJ_TPDU,	"RJ Reject" },
  { AK_TPDU,	"AK Data Acknowledgement" },
  { ER_TPDU,	"ER TPDU Error" },
  { DR_TPDU,	"DR Disconnect Request" },
  { DC_TPDU,	"DC Disconnect Confirm" },
  { CC_TPDU,	"CC Connect Confirm" },
  { CR_TPDU,	"CR Connect Request" },
  { DT_TPDU,	"DT Data" },
  { 0,		NULL }
};

static const value_string cltp_tpdu_type_abbrev_vals[] = {
  { UD_TPDU,	"UD" },
  { 0,		NULL }
};

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

static int hf_cotp_vp_src_tsap = -1; 
static int hf_cotp_vp_dst_tsap = -1;
static int hf_cotp_vp_src_tsap_bytes = -1; 
static int hf_cotp_vp_dst_tsap_bytes = -1;


/* misc */

#define EXTRACT_SHORT(p) 	pntohs(p)
#define EXTRACT_LONG(p) 	pntohl(p)

/* global variables */

/* List of dissectors to call for COTP packets put atop the Inactive
   Subset of CLNP. */
static heur_dissector_list_t cotp_is_heur_subdissector_list;
/* List of dissectors to call for COTP packets put atop CLNP */
static heur_dissector_list_t cotp_heur_subdissector_list;
/* List of dissectors to call for CLNP packets */
static heur_dissector_list_t clnp_heur_subdissector_list;

/*
 * Reassembly of CLNP.
 */
static GHashTable *clnp_segment_table = NULL;
static GHashTable *clnp_reassembled_table = NULL;

/*
 * Reassembly of COTP.
 */
static GHashTable *cotp_segment_table = NULL;
static GHashTable *cotp_reassembled_table = NULL;

#define TSAP_DISPLAY_AUTO	0
#define TSAP_DISPLAY_STRING	1
#define TSAP_DISPLAY_BYTES	2


/* options */
static guint tp_nsap_selector = NSEL_TP;
static gboolean always_decode_transport = FALSE;
static gboolean clnp_reassemble = FALSE;
static gboolean cotp_reassemble = FALSE;
static gint32   tsap_display = TSAP_DISPLAY_AUTO;

const enum_val_t tsap_display_options[] = {
  {"auto", "As strings if printable", TSAP_DISPLAY_AUTO},
  {"string", "As strings", TSAP_DISPLAY_STRING},
  {"bytes", "As bytes", TSAP_DISPLAY_BYTES},
  {NULL, NULL, -1}
};


/* function definitions */

#define MAX_TSAP_LEN	32
static gboolean is_all_printable(const guchar *stringtocheck, int length)
{
  gboolean allprintable;
  int i;

  allprintable=TRUE;
  for (i=0;i<length;i++) {
    if (!(isascii(stringtocheck[i]) && isprint(stringtocheck[i]))) {
      allprintable=FALSE;
      break;
    }
  }
  return allprintable; 
} /* is_all_printable */


static gchar *print_tsap(const guchar *tsap, int length)
{

  gchar *cur;
  gchar tmp[3];
  gboolean allprintable;

  cur=ep_alloc(MAX_TSAP_LEN * 2 + 3);
  cur[0] = '\0';
  if (length <= 0 || length > MAX_TSAP_LEN)
    g_snprintf(cur, MAX_TSAP_LEN * 2 + 3, "<unsupported TSAP length>");
  else {
    allprintable = is_all_printable(tsap,length);
    if (!allprintable)
      strcat(cur,"0x");
    while (length != 0) {
      if (allprintable)
	g_snprintf(tmp, sizeof(tmp), "%c", *tsap ++);
      else
	g_snprintf(tmp, sizeof(tmp), "%02x", *tsap ++);
      strcat(cur, tmp);
      length --;
    }
  }
  return cur;

} /* print_tsap */

static gboolean ositp_decode_var_part(tvbuff_t *tvb, int offset,
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
		"TPDU size: %u", 1 << c1);
      offset += length;
      vp_length -= length;
      break;

    case VP_SRC_TSAP:
      /* if our preference is set to STRING or the  
	 TSAP is not printable, add as bytes and hidden as string;
         otherwise vice-versa */
      if (tsap_display==TSAP_DISPLAY_STRING ||
	 (tsap_display==TSAP_DISPLAY_AUTO && is_all_printable(tvb_get_ptr(tvb,offset,length),length))) {
     	proto_tree_add_string(tree, hf_cotp_vp_src_tsap, tvb, offset, length, 
		print_tsap(tvb_get_ptr(tvb, offset, length),length));
        proto_tree_add_item_hidden(tree, hf_cotp_vp_src_tsap_bytes, tvb, offset, length, TRUE);
      } else {
     	proto_tree_add_string_hidden(tree, hf_cotp_vp_src_tsap, tvb, offset, length, 
		print_tsap(tvb_get_ptr(tvb, offset, length),length));
        proto_tree_add_item(tree, hf_cotp_vp_src_tsap_bytes, tvb, offset, length, TRUE);
      }
      offset += length;
      vp_length -= length;
      break;

    case VP_DST_TSAP:
      /* if our preference is set to STRING or the  
	 TSAP is not printable, add as bytes and hidden as string;
         otherwise vice-versa */      
      if (tsap_display==TSAP_DISPLAY_STRING ||
	 (tsap_display==TSAP_DISPLAY_AUTO && is_all_printable(tvb_get_ptr(tvb,offset,length),length))) {
     	proto_tree_add_string(tree, hf_cotp_vp_dst_tsap, tvb, offset, length, 
		print_tsap(tvb_get_ptr(tvb, offset, length),length));
        proto_tree_add_item_hidden(tree, hf_cotp_vp_dst_tsap_bytes, tvb, offset, length, TRUE);
      } else {
     	proto_tree_add_string_hidden(tree, hf_cotp_vp_dst_tsap, tvb, offset, length, 
		print_tsap(tvb_get_ptr(tvb, offset, length),length));
        proto_tree_add_item(tree, hf_cotp_vp_dst_tsap_bytes, tvb, offset, length, TRUE);
      }
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
				"Use of transport expedited data transfer");
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

static int ositp_decode_DR(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
			 packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree;
  proto_item *ti;
  guint16 dst_ref, src_ref;
  guchar  reason;
  const char *str;

  if (li < LI_MIN_DR)
    return -1;

  dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);

  src_ref = tvb_get_ntohs(tvb, offset + P_SRC_REF);

  reason  = tvb_get_guint8(tvb, offset + P_REASON_IN_DR);

  /* the settings of the TCP srcport and destport are currently disables,
   * for the following reasons:
   * a) only used for ISO conversation handling (which currently doesn't work)
   * b) will prevent "ISO on TCP" (RFC1006) packets from using "follow TCP stream" correctly
   *
   * A future conversation handling might be able to handle different kinds of conversations
   * (TCP, ISO, TCP on TCP, ...), but in that case this has to be fixed in any case.
   */
  /*pinfo->srcport = src_ref;*/
  /*pinfo->destport = dst_ref;*/
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

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO,
		"DR TPDU src-ref: 0x%04x dst-ref: 0x%04x",
		 src_ref, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
    proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset +  1, 1, tpdu);
    proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset +  2, 2, dst_ref);
    proto_tree_add_uint(cotp_tree, hf_cotp_srcref, tvb, offset +  4, 2, src_ref);
    proto_tree_add_text(cotp_tree, tvb, offset +  6, 1,
			"Cause: %s", str);
  }

  offset += li + 1;

  /* User data */
  call_dissector(data_handle, tvb_new_subset(tvb, offset, -1, -1), pinfo, tree);
  offset += tvb_length_remaining(tvb, offset);
     /* we dissected all of the containing PDU */

  return offset;

} /* ositp_decode_DR */

static int ositp_decode_DT(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
			 packet_info *pinfo, proto_tree *tree,
			 gboolean uses_inactive_subset,
			 gboolean *subdissector_found)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  gboolean is_extended;
  gboolean is_class_234;
  guint16  dst_ref;
  guint    tpdu_nr;
  gboolean fragment = FALSE;
  guint32  fragment_length = 0;
  tvbuff_t *next_tvb;
  tvbuff_t *reassembled_tvb = NULL;
  fragment_data *fd_head;

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
	fragment = TRUE;
      is_extended = FALSE;
      is_class_234 = TRUE;
      dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
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
	fragment = TRUE;
      is_extended = TRUE;
      is_class_234 = TRUE;
      dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
      break;

    case LI_NORMAL_DT_CLASS_01           :
      tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_0_1);
      if ( tpdu_nr & 0x80 )
	tpdu_nr = tpdu_nr & 0x7F;
      else
	fragment = TRUE;
      is_extended = FALSE;
      is_class_234 = FALSE;
      dst_ref = 0;
      break;

    default : /* bad TPDU */
      return -1;
      /*NOTREACHED*/
      break;
  }

  /* pinfo->destport = dst_ref; */
  /* pinfo->srcport = 0; */
  pinfo->fragmented = fragment;
  if (check_col(pinfo->cinfo, COL_INFO)) {
    if (is_class_234) {
      col_append_fstr(pinfo->cinfo, COL_INFO, "DT TPDU (%u) dst-ref: 0x%04x %s",
		 tpdu_nr,
		 dst_ref,
		 (fragment)? "(fragment)" : "EOT");
    } else {
      col_append_fstr(pinfo->cinfo, COL_INFO, "DT TPDU (%u) %s",
		 tpdu_nr,
		 (fragment)? "(fragment)" : "EOT");
    }
  }

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset, 1, tpdu);
  }
  offset += 1;
  li -= 1;

  if (is_class_234) {
    if (tree)
      proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset, 2, dst_ref);
    offset += 2;
    li -= 2;
  }

  if (is_extended) {
    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_tpdu_number_extended, tvb, offset, 4,
			  tpdu_nr);
      proto_tree_add_item(cotp_tree, hf_cotp_eot_extended, tvb, offset, 4,
      			  FALSE);
    }
    offset += 4;
    li -= 4;
  } else {
    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_tpdu_number, tvb, offset, 1,
			  tpdu_nr);
      proto_tree_add_item(cotp_tree, hf_cotp_eot, tvb, offset, 1, FALSE);
    }
    offset += 1;
    li -= 1;
  }

  if (tree)
    ositp_decode_var_part(tvb, offset, li, 4, cotp_tree);
  offset += li;

  next_tvb = tvb_new_subset(tvb, offset, -1, -1);
  if (cotp_reassemble) {
    fragment_length = tvb_length(next_tvb);
    /*
     * XXX - these sequence numbers are connection sequence number,
     * not segment sequence numbers - the first segment of a
     * segmented packet doesn't have a specific sequence number (e.g., 0
     * or 1), it has whatever the appropriate sequence number is for
     * it in the connection.
     *
     * For now, we assume segments arrive in order, and just supply
     * the negation of the EOT flag as the "more flags" argument.
     * We should probably handle out-of-order packets separately,
     * so that we can deliver them in order even when *not*
     * reassembling.
     *
     * Note also that TP0 has no sequence number, and relies on
     * the protocol atop which it runs to guarantee in-order delivery.
     */
    fd_head = fragment_add_seq_next(next_tvb, 0, pinfo, dst_ref,
				     cotp_segment_table,
				     cotp_reassembled_table,
				     fragment_length, fragment);
    if (fd_head) {
      if (fd_head->next) {
	/* This is the last packet */
	reassembled_tvb = tvb_new_real_data(fd_head->data,
					    fd_head->len,
					    fd_head->len);
	tvb_set_child_real_data_tvbuff(next_tvb, reassembled_tvb);
	add_new_data_source(pinfo, reassembled_tvb, "Reassembled COTP");
	
	show_fragment_seq_tree(fd_head,
			       &cotp_frag_items,
			       cotp_tree,
			       pinfo, reassembled_tvb, &ti);
	pinfo->fragmented = fragment;
	next_tvb = reassembled_tvb;
      }
    }
    if (fragment && reassembled_tvb == NULL) {
      proto_tree_add_text(cotp_tree, tvb, offset, -1,
			  "User data (%u byte%s)", fragment_length,
			  plurality(fragment_length, "", "s"));
    } 

  } 

  if (uses_inactive_subset) {
    if (dissector_try_heuristic(cotp_is_heur_subdissector_list, next_tvb,
				pinfo, tree)) {
      *subdissector_found = TRUE;
    } else {
      /* Fill in other Dissectors using inactive subset here */
      call_dissector(data_handle,next_tvb, pinfo, tree);
    }
  } else {
    /*
     * We dissect payload if one of the following is TRUE: 
     *
     * - Reassembly option for COTP in preferences is unchecked 
     * - Reassembly option is checked and this packet is the last fragment
     */
    if ( (!cotp_reassemble) ||
	 ((cotp_reassemble) && (!fragment))) {
      if (dissector_try_heuristic(cotp_heur_subdissector_list, next_tvb,
				  pinfo, tree)) {
        *subdissector_found = TRUE;
      } else {
        call_dissector(data_handle,next_tvb, pinfo, tree);
      }
    }
  }   

  offset += tvb_length_remaining(tvb, offset);
     /* we dissected all of the containing PDU */

  return offset;

} /* ositp_decode_DT */

static int ositp_decode_ED(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
			 packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  gboolean is_extended;
  guint16  dst_ref;
  guint    tpdu_nr;
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

  dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);

  /* pinfo->destport = dst_ref; */
  /* pinfo->srcport = 0; */
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "ED TPDU (%u) dst-ref: 0x%04x",
		 tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset, 1, tpdu);
  }
  offset += 1;
  li -= 1;

  if (tree)
    proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset, 2, dst_ref);
  offset += 2;
  li -= 2;

  if (is_extended) {
    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_tpdu_number_extended, tvb,
			  offset, 4, tpdu_nr);
    }
    offset += 4;
    li -= 4;
  } else {
    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_tpdu_number, tvb, offset, 1,
			  tpdu_nr);
    }
    offset += 1;
    li -= 1;
  }

  if (tree)
    ositp_decode_var_part(tvb, offset, li, 4, cotp_tree);
  offset += li;

  next_tvb = tvb_new_subset(tvb, offset, -1, -1);
  call_dissector(data_handle,next_tvb, pinfo, tree);

  offset += tvb_length_remaining(tvb, offset);
     /* we dissected all of the containing PDU */

  return offset;

} /* ositp_decode_ED */

static int ositp_decode_RJ(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
			 guint8 cdt, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree;
  proto_item *ti;
  guint16  dst_ref;
  guint    tpdu_nr;
  gushort  credit = 0;

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

  dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);

  /* pinfo->destport = dst_ref; */
  /* pinfo->srcport = 0; */
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "RJ TPDU (%u) dst-ref: 0x%04x",
		 tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
    proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset +  1, 1, tpdu);
    if (li == LI_NORMAL_RJ)
      proto_tree_add_text(cotp_tree, tvb, offset +  1, 1,
			  "Credit: %u", cdt);
    proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset +  2, 2, dst_ref);
    if (li == LI_NORMAL_RJ)
      proto_tree_add_uint(cotp_tree, hf_cotp_next_tpdu_number, tvb, offset + 4,
			  1, tpdu_nr);
    else {
      proto_tree_add_uint(cotp_tree, hf_cotp_next_tpdu_number_extended, tvb,
			  offset + 4, 4, tpdu_nr);
      proto_tree_add_text(cotp_tree, tvb, offset +  8, 2,
			  "Credit: 0x%02x", credit);
    }
  }

  offset += li + 1;

  return offset;

} /* ositp_decode_RJ */

static int ositp_decode_CC(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
			 packet_info *pinfo, proto_tree *tree,
			 gboolean uses_inactive_subset,
			 gboolean *subdissector_found)
{

  /* CC & CR decoding in the same function */

  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  guint16 dst_ref, src_ref;
  guchar  class_option;
  tvbuff_t *next_tvb;

  src_ref = tvb_get_ntohs(tvb, offset + P_SRC_REF);
  
  class_option = (tvb_get_guint8(tvb, offset + P_CLASS_OPTION) >> 4 ) & 0x0F;
  if (class_option > 4)
    return -1;

  dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
  /* pinfo->srcport = src_ref; */
  /* pinfo->destport = dst_ref; */
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO,
		 "%s TPDU src-ref: 0x%04x dst-ref: 0x%04x",
		 (tpdu == CR_TPDU) ? "CR" : "CC",
		 src_ref,
		 dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset, 1, tpdu);
  }
  offset += 1;
  li -= 1;

  if (tree)
    proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset, 2, dst_ref);
  offset += 2;
  li -= 2;

  if (tree)
    proto_tree_add_uint(cotp_tree, hf_cotp_srcref, tvb, offset, 2, src_ref);
  offset += 2;
  li -= 2;

  if (tree) {
    proto_tree_add_text(cotp_tree, tvb, offset, 1,
			"Class option: 0x%02x", class_option);
  }
  offset += 1;
  li -= 1;

  if (tree)
    ositp_decode_var_part(tvb, offset, li, class_option, cotp_tree);
  offset += li;

  next_tvb = tvb_new_subset(tvb, offset, -1, -1);
  if (!uses_inactive_subset){
    if (dissector_try_heuristic(cotp_heur_subdissector_list, next_tvb,
				pinfo, tree)) {
      *subdissector_found = TRUE;
    } else {
      call_dissector(data_handle,next_tvb, pinfo, tree);
    }
  }
  else
    call_dissector(data_handle, next_tvb, pinfo, tree);
  offset += tvb_length_remaining(tvb, offset);
     /* we dissected all of the containing PDU */

  return offset;

} /* ositp_decode_CC */

static int ositp_decode_DC(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
			 packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  guint16 dst_ref, src_ref;

  if (li > LI_MAX_DC)
    return -1;

  dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
  src_ref = tvb_get_ntohs(tvb, offset + P_SRC_REF);

  /* pinfo->srcport = src_ref; */
  /* pinfo->destport = dst_ref; */
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO,
		 "DC TPDU src-ref: 0x%04x dst-ref: 0x%04x",
		 src_ref,
		 dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset, 1, tpdu);
  }
  offset += 1;
  li -= 1;

  if (tree)
    proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset, 2, dst_ref);
  offset += 2;
  li -= 2;

  if (tree)
    proto_tree_add_uint(cotp_tree, hf_cotp_srcref, tvb, offset, 2, src_ref);
  offset += 2;
  li -= 2;

  if (tree)
    ositp_decode_var_part(tvb, offset, li, 4, cotp_tree);
  offset += li;

  return offset;

} /* ositp_decode_DC */

static int ositp_decode_AK(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
			 guint8 cdt, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  guint16    dst_ref;
  guint      tpdu_nr;
  gushort    cdt_in_ak;

  if (li > LI_MAX_AK)
    return -1;

  if (is_LI_NORMAL_AK(li)) {

    dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
    tpdu_nr = tvb_get_guint8(tvb, offset + P_TPDU_NR_234);

    /* pinfo->srcport = 0; */
    /* pinfo->destport = dst_ref; */
    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, "AK TPDU (%u) dst-ref: 0x%04x",
		   tpdu_nr, dst_ref);

    if (tree) {
      ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
      cotp_tree = proto_item_add_subtree(ti, ett_cotp);
      proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
    }
    offset += 1;

    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset, 1, tpdu);
      proto_tree_add_text(cotp_tree, tvb, offset, 1,
			  "Credit: %u", cdt);
    }
    offset += 1;
    li -= 1;

    if (tree)
      proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset, 2, dst_ref);
    offset += 2;
    li -= 2;

    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_next_tpdu_number, tvb, offset, 1,
			  tpdu_nr);
    }
    offset += 1;
    li -= 1;

    if (tree)
      ositp_decode_var_part(tvb, offset, li, 4, cotp_tree);
    offset += li;

  } else { /* extended format */

    dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
    tpdu_nr   = tvb_get_ntohl(tvb, offset + P_TPDU_NR_234);
    cdt_in_ak = tvb_get_ntohs(tvb, offset + P_CDT_IN_AK);

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, "AK TPDU (%u) dst-ref: 0x%04x Credit: %u",
		   tpdu_nr, dst_ref, cdt_in_ak);

    if (tree) {
      ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
      cotp_tree = proto_item_add_subtree(ti, ett_cotp);
      proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
    }
    offset += 1;

    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset, 1, tpdu);
    }
    offset += 1;
    li -= 1;

    if (tree)
      proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset, 2, dst_ref);
    offset += 2;
    li -= 2;

    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_next_tpdu_number_extended, tvb,
			  offset, 4, tpdu_nr);
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
      ositp_decode_var_part(tvb, offset, li, 4, cotp_tree);
    offset += li;

  } /* is_LI_NORMAL_AK */

  return offset;

} /* ositp_decode_AK */

static int ositp_decode_EA(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
			 packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree = NULL;
  proto_item *ti;
  gboolean is_extended;
  guint16  dst_ref;
  guint    tpdu_nr;

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

  dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
  /* pinfo->srcport = 0; */
  /* pinfo->destport = dst_ref; */
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO,
		 "EA TPDU (%u) dst-ref: 0x%04x", tpdu_nr, dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset, 1, tpdu);
  }
  offset += 1;
  li -= 1;

  if (tree)
    proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset, 2, dst_ref);
  offset += 2;
  li -= 2;

  if (is_extended) {
    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_next_tpdu_number_extended, tvb,
			  offset, 4, tpdu_nr);
    }
    offset += 4;
    li -= 4;
  } else {
    if (tree) {
      proto_tree_add_uint(cotp_tree, hf_cotp_next_tpdu_number, tvb, offset, 1,
			  tpdu_nr);
    }
    offset += 1;
    li -= 1;
  }

  if (tree)
    ositp_decode_var_part(tvb, offset, li, 4, cotp_tree);
  offset += li;

  return offset;

} /* ositp_decode_EA */

static int ositp_decode_ER(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
			 packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cotp_tree;
  proto_item *ti;
  const char *str;
  guint16 dst_ref;

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

  dst_ref = tvb_get_ntohs(tvb, offset + P_DST_REF);
  /* pinfo->srcport = 0; */
  /* pinfo->destport = dst_ref; */
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "ER TPDU dst-ref: 0x%04x", dst_ref);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cotp, tvb, offset, li + 1, FALSE);
    cotp_tree = proto_item_add_subtree(ti, ett_cotp);
    proto_tree_add_uint(cotp_tree, hf_cotp_li, tvb, offset, 1,li);
    proto_tree_add_uint(cotp_tree, hf_cotp_type, tvb, offset +  1, 1, tpdu);
    proto_tree_add_uint(cotp_tree, hf_cotp_destref, tvb, offset +  2, 2, dst_ref);
    proto_tree_add_text(cotp_tree, tvb, offset +  4, 1,
			"Reject cause: %s", str);
  }

  offset += li + 1;

  return offset;

} /* ositp_decode_ER */

static int ositp_decode_UD(tvbuff_t *tvb, int offset, guint8 li, guint8 tpdu,
			 packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *cltp_tree = NULL;
  tvbuff_t   *next_tvb;

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "UD TPDU");

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cltp, tvb, offset, li + 1, FALSE);
    cltp_tree = proto_item_add_subtree(ti, ett_cltp);
    proto_tree_add_uint(cltp_tree, hf_cltp_li, tvb, offset, 1,li);
  }
  offset += 1;

  if (tree) {
    proto_tree_add_uint(cltp_tree, hf_cltp_type, tvb, offset, 1, tpdu);
  }
  offset += 1;
  li -= 1;

  if (tree)
    ositp_decode_var_part(tvb, offset, li, 0, cltp_tree);
  offset += li;

  next_tvb = tvb_new_subset(tvb, offset, -1, -1);
  call_dissector(data_handle,next_tvb, pinfo, tree);
  offset += tvb_length_remaining(tvb, offset);
     /* we dissected all of the containing PDU */

  return offset;

} /* ositp_decode_UD */

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
  guint8 li, tpdu, cdt;
  gboolean first_tpdu = TRUE;
  int new_offset;
  gboolean found_ositp = FALSE;
  gboolean is_cltp = FALSE;
  gboolean subdissector_found = FALSE;

  if (!proto_is_protocol_enabled(find_protocol_by_id(proto_cotp)))
    return FALSE;	/* COTP has been disabled */
  /* XXX - what about CLTP? */

  pinfo->current_proto = "COTP";

  /* Initialize the COL_INFO field; each of the TPDUs will have its
     information appended. */
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO, "");

  while (tvb_offset_exists(tvb, offset)) {
    if (!first_tpdu) {
      if (check_col(pinfo->cinfo, COL_INFO))
        col_append_str(pinfo->cinfo, COL_INFO, ", ");
    }
    if ((li = tvb_get_guint8(tvb, offset + P_LI)) == 0) {
      if (check_col(pinfo->cinfo, COL_INFO))
        col_append_str(pinfo->cinfo, COL_INFO, "Length indicator is zero");
      if (!first_tpdu)
        call_dissector(data_handle, tvb_new_subset(tvb, offset, -1, -1),
                       pinfo, tree);
      return found_ositp;
    }

    tpdu    = (tvb_get_guint8(tvb, offset + P_TPDU) >> 4) & 0x0F;
    if (tpdu == UD_TPDU)
      pinfo->current_proto = "CLTP";	/* connectionless transport */
    cdt     = tvb_get_guint8(tvb, offset + P_CDT) & 0x0F;

    switch (tpdu) {
      case CC_TPDU :
      case CR_TPDU :
        new_offset = ositp_decode_CC(tvb, offset, li, tpdu, pinfo, tree,
				     uses_inactive_subset, &subdissector_found);
        break;
      case DR_TPDU :
        new_offset = ositp_decode_DR(tvb, offset, li, tpdu, pinfo, tree);
        break;
      case DT_TPDU :
        new_offset = ositp_decode_DT(tvb, offset, li, tpdu, pinfo, tree,
				   uses_inactive_subset, &subdissector_found);
        break;
      case ED_TPDU :
        new_offset = ositp_decode_ED(tvb, offset, li, tpdu, pinfo, tree);
        break;
      case RJ_TPDU :
        new_offset = ositp_decode_RJ(tvb, offset, li, tpdu, cdt, pinfo, tree);
        break;
      case DC_TPDU :
        new_offset = ositp_decode_DC(tvb, offset, li, tpdu, pinfo, tree);
        break;
      case AK_TPDU :
        new_offset = ositp_decode_AK(tvb, offset, li, tpdu, cdt, pinfo, tree);
        break;
      case EA_TPDU :
        new_offset = ositp_decode_EA(tvb, offset, li, tpdu, pinfo, tree);
        break;
      case ER_TPDU :
        new_offset = ositp_decode_ER(tvb, offset, li, tpdu, pinfo, tree);
        break;
      case UD_TPDU :
        new_offset = ositp_decode_UD(tvb, offset, li, tpdu, pinfo, tree);
        is_cltp = TRUE;
        break;
      default      :
        if (first_tpdu && check_col(pinfo->cinfo, COL_INFO))
          col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown TPDU type (0x%x)", tpdu);
        new_offset = -1;	/* bad PDU type */
        break;
    }

    if (new_offset == -1) { /* incorrect TPDU */
      if (!first_tpdu)
        call_dissector(data_handle, tvb_new_subset(tvb, offset, -1, -1),
                       pinfo, tree);
      break;
    }

    if (first_tpdu) {
      /* Well, we found at least one valid COTP or CLTP PDU, so I guess this
         is either COTP or CLTP. */
      if (!subdissector_found && check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, is_cltp ? "CLTP" : "COTP");
      found_ositp = TRUE;
    }

    offset = new_offset;
    first_tpdu = FALSE;
  }
  return found_ositp;
} /* dissect_ositp_internal */

static void dissect_ositp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!dissect_ositp_internal(tvb, pinfo, tree, FALSE))
    call_dissector(data_handle,tvb, pinfo, tree);
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
  const char *pdu_type_string;
  proto_tree *type_tree;
  guint16     segment_length;
  guint16     du_id = 0;
  guint16     segment_offset = 0;
  guint16     cnf_cksum;
  cksum_status_t cksum_status;
  int         offset;
  guchar      src_len, dst_len, nsel, opt_len = 0;
  const guint8     *dst_addr, *src_addr;
  gint        len;
  guint       next_length;
  proto_tree *discpdu_tree;
  gboolean    save_in_error_pkt;
  fragment_data *fd_head;
  tvbuff_t   *next_tvb;
  gboolean    update_col_info = TRUE;
  gboolean    save_fragmented;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CLNP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  cnf_proto_id = tvb_get_guint8(tvb, P_CLNP_PROTO_ID);
  if (cnf_proto_id == NLPID_NULL) {
    if (check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "Inactive subset");
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
    call_dissector(data_handle,tvb, pinfo, tree);
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
			       "Holding Time : %u (%u.%u secs)",
			       cnf_ttl, cnf_ttl / 2, (cnf_ttl % 2) * 5);
  }

  cnf_type = tvb_get_guint8(tvb, P_CLNP_TYPE);
  pdu_type_string = val_to_str(cnf_type & CNF_TYPE, npdu_type_abbrev_vals,
				"Unknown (0x%02x)");
  flag_string[0] = '\0';
  if (cnf_type & CNF_SEG_OK)
    strcat(flag_string, "S ");
  if (cnf_type & CNF_MORE_SEGS)
    strcat(flag_string, "M ");
  if (cnf_type & CNF_ERR_OK)
    strcat(flag_string, "E ");
  if (tree) {
    ti = proto_tree_add_uint_format(clnp_tree, hf_clnp_type, tvb, P_CLNP_TYPE, 1,
			       cnf_type,
			       "PDU Type     : 0x%02x (%s%s)",
			       cnf_type,
			       flag_string,
			       pdu_type_string);
    type_tree = proto_item_add_subtree(ti, ett_clnp_type);
    proto_tree_add_text(type_tree, tvb, P_CLNP_TYPE, 1, "%s",
			decode_boolean_bitfield(cnf_type, CNF_SEG_OK, 8,
				      "Segmentation permitted",
				      "Segmentation not permitted"));
    proto_tree_add_text(type_tree, tvb, P_CLNP_TYPE, 1, "%s",
			decode_boolean_bitfield(cnf_type, CNF_MORE_SEGS, 8,
				      "More segments",
				      "Last segment"));
    proto_tree_add_text(type_tree, tvb, P_CLNP_TYPE, 1, "%s",
			decode_boolean_bitfield(cnf_type, CNF_ERR_OK, 8,
				      "Report error if PDU discarded",
				      "Don't report error if PDU discarded"));
    proto_tree_add_text(type_tree, tvb, P_CLNP_TYPE, 1, "%s",
			decode_enumerated_bitfield(cnf_type, CNF_TYPE, 8,
				      npdu_type_vals, "%s"));
  }

  /* If we don't have the full header - i.e., not enough to see the
     segmentation part and determine whether this datagram is segmented
     or not - set the Info column now; we'll get an exception before
     we set it otherwise. */

  if (!tvb_bytes_exist(tvb, 0, cnf_hdr_len)) {
    if (check_col(pinfo->cinfo, COL_INFO))
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s NPDU %s", pdu_type_string, flag_string);
  }

  segment_length = tvb_get_ntohs(tvb, P_CLNP_SEGLEN);
  cnf_cksum = tvb_get_ntohs(tvb, P_CLNP_CKSUM);
  cksum_status = calc_checksum(tvb, 0, cnf_hdr_len, cnf_cksum);
  if (tree) {
    proto_tree_add_uint(clnp_tree, hf_clnp_pdu_length, tvb, P_CLNP_SEGLEN, 2,
			segment_length);
    switch (cksum_status) {

    default:
	/*
	 * No checksum present, or not enough of the header present to
	 * checksum it.
	 */
	proto_tree_add_uint_format(clnp_tree, hf_clnp_checksum, tvb,
			       P_CLNP_CKSUM, 2,
			       cnf_cksum,
			       "Checksum     : 0x%04x",
			       cnf_cksum);
	break;

    case CKSUM_OK:
	/*
	 * Checksum is correct.
	 */
	proto_tree_add_uint_format(clnp_tree, hf_clnp_checksum, tvb,
			       P_CLNP_CKSUM, 2,
			       cnf_cksum,
			       "Checksum     : 0x%04x (correct)",
			       cnf_cksum);
	break;

    case CKSUM_NOT_OK:
	/*
	 * Checksum is not correct.
	 */
	proto_tree_add_uint_format(clnp_tree, hf_clnp_checksum, tvb,
			       P_CLNP_CKSUM, 2,
			       cnf_cksum,
			       "Checksum     : 0x%04x (incorrect)",
			       cnf_cksum);
	break;
    }
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

  SET_ADDRESS(&pinfo->net_src, AT_OSI, src_len, src_addr);
  SET_ADDRESS(&pinfo->src, AT_OSI, src_len, src_addr);
  SET_ADDRESS(&pinfo->net_dst, AT_OSI, dst_len, dst_addr);
  SET_ADDRESS(&pinfo->dst, AT_OSI, dst_len, dst_addr);

  /* Segmentation Part */

  offset += dst_len + src_len + 2;

  if (cnf_type & CNF_SEG_OK) {
    struct clnp_segment seg;			/* XXX - not used */
    tvb_memcpy(tvb, (guint8 *)&seg, offset, sizeof(seg));	/* XXX - not used */

    segment_offset = tvb_get_ntohs(tvb, offset + 2);
    du_id = tvb_get_ntohs(tvb, offset);
    if (tree) {
      proto_tree_add_text(clnp_tree, tvb, offset, 2,
			"Data unit identifier: %06u",
			du_id);
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

    dissect_osi_options( opt_len,
                         tvb, offset, clnp_tree );
  }

  /* Length of CLNP datagram plus headers above it. */
  len = segment_length;

  offset = cnf_hdr_len;

  /* If clnp_reassemble is on, this is a segment, we have all the
   * data in the segment, and the checksum is valid, then just add the
   * segment to the hashtable.
   */
  save_fragmented = pinfo->fragmented;
  if (clnp_reassemble && (cnf_type & CNF_SEG_OK) &&
	((cnf_type & CNF_MORE_SEGS) || segment_offset != 0) &&
	tvb_bytes_exist(tvb, offset, segment_length - cnf_hdr_len) &&
	cksum_status != CKSUM_NOT_OK) {
    fd_head = fragment_add_check(tvb, offset, pinfo, du_id, clnp_segment_table,
			   clnp_reassembled_table, segment_offset,
			   segment_length - cnf_hdr_len,
			   cnf_type & CNF_MORE_SEGS);

    next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled CLNP",
        fd_head, &clnp_frag_items, &update_col_info, clnp_tree);
  } else {
    /* If this is the first segment, dissect its contents, otherwise
       just show it as a segment.

       XXX - if we eventually don't save the reassembled contents of all
       segmented datagrams, we may want to always reassemble. */
    if ((cnf_type & CNF_SEG_OK) && segment_offset != 0) {
      /* Not the first segment - don't dissect it. */
      next_tvb = NULL;
    } else {
      /* First segment, or not segmented.  Dissect what we have here. */

      /* Get a tvbuff for the payload. */
      next_tvb = tvb_new_subset(tvb, offset, -1, -1);

      /*
       * If this is the first segment, but not the only segment,
       * tell the next protocol that.
       */
      if ((cnf_type & (CNF_SEG_OK|CNF_MORE_SEGS)) == (CNF_SEG_OK|CNF_MORE_SEGS))
        pinfo->fragmented = TRUE;
      else
        pinfo->fragmented = FALSE;
    }
  }

  if (next_tvb == NULL) {
    /* Just show this as a segment. */
    if (check_col(pinfo->cinfo, COL_INFO))
      col_add_fstr(pinfo->cinfo, COL_INFO, "Fragmented %s NPDU %s(off=%u)",
		pdu_type_string, flag_string, segment_offset);

    /* As we haven't reassembled anything, we haven't changed "pi", so
       we don't have to restore it. */
    call_dissector(data_handle, tvb_new_subset(tvb, offset, -1, -1), pinfo,
                   tree);
    pinfo->fragmented = save_fragmented;
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
        if (dissect_ositp_internal(next_tvb, pinfo, tree, FALSE)) {
          pinfo->fragmented = save_fragmented;
          return;	/* yes, it appears to be COTP or CLTP */
        }
      }
      if (dissector_try_heuristic(clnp_heur_subdissector_list, next_tvb,
				  pinfo, tree))	{
          pinfo->fragmented = save_fragmented;
          return;	/* yes, it appears to be COTP or CLTP */
      }
	
      break;

    case ER_NPDU:
      /* The payload is the header and "none, some, or all of the data
         part of the discarded PDU", i.e. it's like an ICMP error;
	 dissect it as a CLNP PDU. */
      if (check_col(pinfo->cinfo, COL_INFO))
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s NPDU %s", pdu_type_string, flag_string);
      if (tree) {
        next_length = tvb_length_remaining(tvb, offset);
        if (next_length != 0) {
          /* We have payload; dissect it. */
          ti = proto_tree_add_text(clnp_tree, tvb, offset, next_length,
            "Discarded PDU");
          discpdu_tree = proto_item_add_subtree(ti, ett_clnp_disc_pdu);

          /* Save the current value of the "we're inside an error packet"
             flag, and set that flag; subdissectors may treat packets
             that are the payload of error packets differently from
             "real" packets. */
          save_in_error_pkt = pinfo->in_error_pkt;
          pinfo->in_error_pkt = TRUE;

          call_dissector(clnp_handle, next_tvb, pinfo, discpdu_tree);

          /* Restore the "we're inside an error packet" flag. */
          pinfo->in_error_pkt = save_in_error_pkt;
        }
      }
      pinfo->fragmented = save_fragmented;
      return;	/* we're done with this PDU */

    case ERQ_NPDU:
    case ERP_NPDU:
      /* XXX - dissect this */
      break;
    }
  }
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s NPDU %s", pdu_type_string, flag_string);
  call_dissector(data_handle,next_tvb, pinfo, tree);
  pinfo->fragmented = save_fragmented;
} /* dissect_clnp */

static void
clnp_reassemble_init(void)
{
  fragment_table_init(&clnp_segment_table);
  reassembled_table_init(&clnp_reassembled_table);
}

static void
cotp_reassemble_init(void)
{
  fragment_table_init(&cotp_segment_table);
  reassembled_table_init(&cotp_reassembled_table);
}

void proto_register_clnp(void)
{
  static hf_register_info hf[] = {
    { &hf_clnp_id,
      { "Network Layer Protocol Identifier", "clnp.nlpi", FT_UINT8, BASE_HEX,
        VALS(nlpid_vals), 0x0, "", HFILL }},

    { &hf_clnp_length,
      { "HDR Length   ", "clnp.len",	   FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_clnp_version,
      { "Version      ", "clnp.version",  FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_clnp_ttl,
      { "Holding Time ", "clnp.ttl",	   FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_clnp_type,
      { "PDU Type     ", "clnp.type",     FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_clnp_pdu_length,
      { "PDU length   ", "clnp.pdu.len",  FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_clnp_checksum,
      { "Checksum     ", "clnp.checksum", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_clnp_dest_length,
      { "DAL ", "clnp.dsap.len", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_clnp_dest,
      { " DA ", "clnp.dsap",     FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_clnp_src_length,
      { "SAL ", "clnp.ssap.len", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_clnp_src,
      { " SA ", "clnp.ssap",     FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_clnp_segment_overlap,
      { "Segment overlap", "clnp.segment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"Segment overlaps with other segments", HFILL }},

    { &hf_clnp_segment_overlap_conflict,
      { "Conflicting data in segment overlap", "clnp.segment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"Overlapping segments contained conflicting data", HFILL }},

    { &hf_clnp_segment_multiple_tails,
      { "Multiple tail segments found", "clnp.segment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"Several tails were found when reassembling the packet", HFILL }},

    { &hf_clnp_segment_too_long_segment,
      { "Segment too long", "clnp.segment.toolongsegment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"Segment contained data past end of packet", HFILL }},

    { &hf_clnp_segment_error,
      { "Reassembly error", "clnp.segment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	"Reassembly error due to illegal segments", HFILL }},

    { &hf_clnp_segment,
      { "CLNP Segment", "clnp.segment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	"CLNP Segment", HFILL }},

    { &hf_clnp_segments,
      { "CLNP Segments", "clnp.segments", FT_NONE, BASE_DEC, NULL, 0x0,
	"CLNP Segments", HFILL }},

    { &hf_clnp_reassembled_in,
      { "Reassembled CLNP in frame", "clnp.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	"This CLNP packet is reassembled in this frame", HFILL }}
  };
  static gint *ett[] = {
    &ett_clnp,
    &ett_clnp_type,
    &ett_clnp_segments,
    &ett_clnp_segment,
    &ett_clnp_disc_pdu,
  };

  module_t *clnp_module;

  proto_clnp = proto_register_protocol(PROTO_STRING_CLNP, "CLNP", "clnp");
  proto_register_field_array(proto_clnp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("clnp", dissect_clnp, proto_clnp);
  register_heur_dissector_list("clnp", &clnp_heur_subdissector_list);  
  register_init_routine(clnp_reassemble_init);
  register_init_routine(cotp_reassemble_init);

  clnp_module = prefs_register_protocol(proto_clnp, NULL);
  prefs_register_uint_preference(clnp_module, "tp_nsap_selector",
	"NSAP selector for Transport Protocol (last byte in hex)",
	"NSAP selector for Transport Protocol (last byte in hex)",
       	16, &tp_nsap_selector);
  prefs_register_bool_preference(clnp_module, "always_decode_transport",
	"Always try to decode NSDU as transport PDUs",
	"Always try to decode NSDU as transport PDUs",
       	&always_decode_transport);
  prefs_register_bool_preference(clnp_module, "reassemble",
	"Reassemble segmented CLNP datagrams",
	"Whether segmented CLNP datagrams should be reassembled",
	&clnp_reassemble);
}

void
proto_reg_handoff_clnp(void)
{
  data_handle = find_dissector("data");

  clnp_handle = create_dissector_handle(dissect_clnp, proto_clnp);
  dissector_add("osinl", NLPID_ISO8473_CLNP, clnp_handle);
  dissector_add("osinl", NLPID_NULL, clnp_handle); /* Inactive subset */
  dissector_add("x.25.spi", NLPID_ISO8473_CLNP, clnp_handle);
}

void proto_register_cotp(void)
{
  static hf_register_info hf[] = {
    { &hf_cotp_srcref,
      { "Source reference", "cotp.srcref", FT_UINT16, BASE_HEX, NULL, 0x0,
        "Source address reference", HFILL}},
    { &hf_cotp_destref,
      { "Destination reference", "cotp.destref", FT_UINT16, BASE_HEX, NULL, 0x0,
        "Destination address reference", HFILL}}, 
    { &hf_cotp_li,
      { "Length", "cotp.li", FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length Indicator, length of this header", HFILL}},
    { &hf_cotp_type,
      { "PDU Type", "cotp.type", FT_UINT8, BASE_HEX, VALS(cotp_tpdu_type_abbrev_vals), 0x0,
        "PDU Type - upper nibble of byte", HFILL}},
    { &hf_cotp_tpdu_number,
      { "TPDU number", "cotp.tpdu-number", FT_UINT8, BASE_HEX, NULL, 0x7f,
        "TPDU number", HFILL}},
    { &hf_cotp_tpdu_number_extended,
      { "TPDU number", "cotp.tpdu-number", FT_UINT32, BASE_HEX, NULL, 0x0 /* XXX - 0x7fff? */,
        "TPDU number", HFILL}},
    { &hf_cotp_next_tpdu_number,
      { "Your TPDU number", "cotp.next-tpdu-number", FT_UINT8, BASE_HEX, NULL, 0x0,
        "Your TPDU number", HFILL}},
    { &hf_cotp_next_tpdu_number_extended,
      { "Your TPDU number", "cotp.next-tpdu-number", FT_UINT32, BASE_HEX, NULL, 0x0,
        "Your TPDU number", HFILL}},
    { &hf_cotp_eot,
      { "Last data unit", "cotp.eot", FT_BOOLEAN, 8, TFS(&fragment_descriptions),  0x80,
        "Is current TPDU the last data unit of a complete DT TPDU sequence (End of TSDU)?", HFILL}},
    { &hf_cotp_eot_extended,
      { "Last data unit", "cotp.eot", FT_BOOLEAN, 32, TFS(&fragment_descriptions),  0x80000000,
        "Is current TPDU the last data unit of a complete DT TPDU sequence (End of TSDU)?", HFILL}},
    { &hf_cotp_segment_overlap,
      { "Segment overlap", "cotp.segment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"Segment overlaps with other segments", HFILL }},
    { &hf_cotp_segment_overlap_conflict,
      { "Conflicting data in segment overlap", "cotp.segment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"Overlapping segments contained conflicting data", HFILL }},
    { &hf_cotp_segment_multiple_tails,
      { "Multiple tail segments found", "cotp.segment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"Several tails were found when reassembling the packet", HFILL }},
    { &hf_cotp_segment_too_long_segment,
      { "Segment too long", "cotp.segment.toolongsegment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"Segment contained data past end of packet", HFILL }},
    { &hf_cotp_segment_error,
      { "Reassembly error", "cotp.segment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	"Reassembly error due to illegal segments", HFILL }},
    { &hf_cotp_segment,
      { "COTP Segment", "cotp.segment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	"COTP Segment", HFILL }},
    { &hf_cotp_segments,
      { "COTP Segments", "cotp.segments", FT_NONE, BASE_DEC, NULL, 0x0,
	"COTP Segments", HFILL }},
    { &hf_cotp_reassembled_in,
      { "Reassembled COTP in frame", "cotp.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	"This COTP packet is reassembled in this frame", HFILL }},
/* ISO DP 8073 i13.3.4(a) Source and destination TSAPs are defined as
   identifiers of unspecified type and length.
   Some implementations of COTP use printable strings, others use raw bytes.
   We always add both representations to the tree; one will always be hidden
   depending on the tsap display preference */
    { &hf_cotp_vp_src_tsap,
      { "Source TSAP", "cotp.src-tsap", FT_STRING, BASE_NONE, NULL, 0x0,
        "Calling TSAP", HFILL }},
    { &hf_cotp_vp_src_tsap_bytes,
      { "Source TSAP", "cotp.src-tsap-bytes", FT_BYTES, BASE_NONE, NULL, 0x0,
        "Calling TSAP (bytes representation)", HFILL }},
    { &hf_cotp_vp_dst_tsap,
      { "Destination TSAP", "cotp.dst-tsap", FT_STRING, BASE_NONE, NULL, 0x0,
	"Called TSAP", HFILL }},
    { &hf_cotp_vp_dst_tsap_bytes,
      { "Destination TSAP", "cotp.dst-tsap-bytes", FT_BYTES, BASE_NONE, NULL, 0x0,
	"Called TSAP (bytes representation)", HFILL }},

  };
  static gint *ett[] = {
	&ett_cotp,
	&ett_cotp_segment,
	&ett_cotp_segments,
  };

  module_t *cotp_module;

  proto_cotp = proto_register_protocol(PROTO_STRING_COTP, "COTP", "cotp");
  proto_register_field_array(proto_cotp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  cotp_module = prefs_register_protocol(proto_cotp, NULL);

  prefs_register_bool_preference(cotp_module, "reassemble",
	 "Reassemble segmented COTP datagrams",
	 "Whether segmented COTP datagrams should be reassembled."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	&cotp_reassemble);

  prefs_register_enum_preference(cotp_module, "tsap_display",
	 "Display TSAPs as strings or bytes",
	 "How TSAPs should be displayed",
	&tsap_display,
	tsap_display_options,
	FALSE);

  /* subdissector code in inactive subset */
  register_heur_dissector_list("cotp_is", &cotp_is_heur_subdissector_list);

  /* other COTP/ISO 8473 subdissectors */
  register_heur_dissector_list("cotp", &cotp_heur_subdissector_list);

  /* XXX - what about CLTP and proto_cltp? */
  register_dissector("ositp", dissect_ositp, proto_cotp);
}

void
proto_reg_handoff_cotp(void)
{
  dissector_handle_t ositp_handle;

  ositp_handle = find_dissector("ositp");
  dissector_add("ip.proto", IP_PROTO_TP, ositp_handle);
}

void proto_register_cltp(void)
{
  static hf_register_info hf[] = {
    { &hf_cltp_li,
      { "Length", "cltp.li", FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length Indicator, length of this header", HFILL}},
    { &hf_cltp_type,
      { "PDU Type", "cltp.type", FT_UINT8, BASE_HEX, VALS(cltp_tpdu_type_abbrev_vals), 0x0,
        "PDU Type", HFILL}},
  };
  static gint *ett[] = {
	&ett_cltp,
  };

  proto_cltp = proto_register_protocol(PROTO_STRING_CLTP, "CLTP", "cltp");
  proto_register_field_array(proto_cltp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}
