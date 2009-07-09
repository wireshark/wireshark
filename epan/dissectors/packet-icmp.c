/* packet-icmp.c
 * Routines for ICMP - Internet Control Message Protocol
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Monday, June 27, 2005
 * Support for the ICMP extensions for MPLS
 * (http://www.ietf.org/proceedings/01aug/I-D/draft-ietf-mpls-icmp-02.txt)
 * by   Maria-Luiza Crivat <luizacri@gmail.com>
 * &    Brice Augustin <bricecotte@gmail.com>
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
#include <glib.h>

#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/prefs.h>
#include <epan/in_cksum.h>

#include "packet-ip.h"


/* Decode the end of the ICMP payload as ICMP MPLS extensions
if the packet in the payload has more than 128 bytes */
static gboolean favor_icmp_mpls_ext = FALSE;

static int proto_icmp = -1;
static int hf_icmp_type = -1;
static int hf_icmp_code = -1;
static int hf_icmp_checksum = -1;
static int hf_icmp_checksum_bad = -1;
static int hf_icmp_ident = -1;
static int hf_icmp_seq_num = -1;
static int hf_icmp_mtu = -1;
static int hf_icmp_redir_gw = -1;


/* Mobile ip */
static int hf_icmp_mip_type = -1;
static int hf_icmp_mip_length = -1;
static int hf_icmp_mip_prefix_length = -1;
static int hf_icmp_mip_seq = -1;
static int hf_icmp_mip_life = -1;
static int hf_icmp_mip_flags = -1;
static int hf_icmp_mip_r = -1;
static int hf_icmp_mip_b = -1;
static int hf_icmp_mip_h = -1;
static int hf_icmp_mip_f = -1;
static int hf_icmp_mip_m = -1;
static int hf_icmp_mip_g = -1;
static int hf_icmp_mip_v = -1;
static int hf_icmp_mip_rt = -1;
static int hf_icmp_mip_u = -1;
static int hf_icmp_mip_x = -1;
static int hf_icmp_mip_reserved = -1;
static int hf_icmp_mip_coa = -1;
static int hf_icmp_mip_challenge = -1;

/* MPLS extensions */
static int hf_icmp_mpls = -1;
static int hf_icmp_mpls_version = -1;
static int hf_icmp_mpls_reserved = -1;
static int hf_icmp_mpls_checksum = -1;
static int hf_icmp_mpls_checksum_bad = -1;
static int hf_icmp_mpls_length = -1;
static int hf_icmp_mpls_class = -1;
static int hf_icmp_mpls_c_type = -1;
static int hf_icmp_mpls_label = -1;
static int hf_icmp_mpls_exp = -1;
static int hf_icmp_mpls_s = -1;
static int hf_icmp_mpls_ttl = -1;

static gint ett_icmp = -1;
static gint ett_icmp_mip = -1;
static gint ett_icmp_mip_flags = -1;

/* MPLS extensions */
static gint ett_icmp_mpls = -1;
static gint ett_icmp_mpls_object = -1;
static gint ett_icmp_mpls_stack_object = -1;

/* ICMP definitions */

#define ICMP_ECHOREPLY     0
#define ICMP_UNREACH       3
#define ICMP_SOURCEQUENCH  4
#define ICMP_REDIRECT      5
#define ICMP_ECHO          8
#define ICMP_RTRADVERT     9
#define ICMP_RTRSOLICIT   10
#define ICMP_TIMXCEED     11
#define ICMP_PARAMPROB    12
#define ICMP_TSTAMP       13
#define ICMP_TSTAMPREPLY  14
#define ICMP_IREQ         15
#define ICMP_IREQREPLY    16
#define ICMP_MASKREQ      17
#define ICMP_MASKREPLY    18

/* ICMP UNREACHABLE */

#define ICMP_NET_UNREACH        0       /* Network Unreachable */
#define ICMP_HOST_UNREACH       1       /* Host Unreachable */
#define ICMP_PROT_UNREACH       2       /* Protocol Unreachable */
#define ICMP_PORT_UNREACH       3       /* Port Unreachable */
#define ICMP_FRAG_NEEDED        4       /* Fragmentation Needed/DF set */
#define ICMP_SR_FAILED          5       /* Source Route failed */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_NET_ANO            9
#define ICMP_HOST_ANO           10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13      /* Packet filtered */
#define ICMP_PREC_VIOLATION     14      /* Precedence violation */
#define ICMP_PREC_CUTOFF        15      /* Precedence cut off */

#define ICMP_MIP_EXTENSION_PAD	0
#define ICMP_MIP_MOB_AGENT_ADV	16
#define ICMP_MIP_PREFIX_LENGTHS	19
#define ICMP_MIP_CHALLENGE	24

static dissector_handle_t ip_handle;
static dissector_handle_t data_handle;

static const value_string mip_extensions[] = {
  { ICMP_MIP_EXTENSION_PAD, "One byte padding extension"},  /* RFC 2002 */
  { ICMP_MIP_MOB_AGENT_ADV, "Mobility Agent Advertisement Extension"},
							    /* RFC 2002 */
  { ICMP_MIP_PREFIX_LENGTHS, "Prefix Lengths Extension"},   /* RFC 2002 */
  { ICMP_MIP_CHALLENGE, "Challenge Extension"},             /* RFC 3012 */
  { 0, NULL}
};

/*
 * Dissect the mobile ip advertisement extensions.
 */
static void
dissect_mip_extensions(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  guint8       type;
  guint8       length;
  guint16      flags;
  proto_item   *ti;
  proto_tree   *mip_tree=NULL;
  proto_tree   *flags_tree=NULL;
  gint         numCOAs;
  gint         i;

  /* Not much to do if we're not parsing everything */
  if (!tree) return;

  while (tvb_reported_length_remaining(tvb, offset) > 0) {

	type = tvb_get_guint8(tvb, offset + 0);
	if (type)
	  length = tvb_get_guint8(tvb, offset + 1);
	else
	  length=0;

	ti = proto_tree_add_text(tree, tvb, offset,
							 type?(length + 2):1,
							 "Ext: %s",
							 val_to_str(type, mip_extensions,
										"Unknown ext %u"));
	mip_tree = proto_item_add_subtree(ti, ett_icmp_mip);


	switch (type) {
	case ICMP_MIP_EXTENSION_PAD:
	  /* One byte padding extension */
	  /* Add our fields */
	  /* type */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_type, tvb, offset,
						  1, FALSE);
	  offset++;
	  break;
	case ICMP_MIP_MOB_AGENT_ADV:
	  /* Mobility Agent Advertisement Extension (RFC 2002)*/
	  /* Add our fields */
	  /* type */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_type, tvb, offset,
						  1, FALSE);
	  offset++;
	  /* length */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_length, tvb, offset,
						  1, FALSE);
	  offset++;
	  /* sequence number */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_seq, tvb, offset,
						  2, FALSE);
	  offset+=2;
	  /* Registration Lifetime */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_life, tvb, offset,
						  2, FALSE);
	  offset+=2;
	  /* flags */
	  flags = tvb_get_ntohs(tvb, offset);
	  ti = proto_tree_add_uint(mip_tree, hf_icmp_mip_flags, tvb, offset, 2, flags);
	  flags_tree = proto_item_add_subtree(ti, ett_icmp_mip_flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_r, tvb, offset, 2, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_b, tvb, offset, 2, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_h, tvb, offset, 2, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_f, tvb, offset, 2, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_m, tvb, offset, 2, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_g, tvb, offset, 2, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_v, tvb, offset, 2, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_rt, tvb, offset, 2, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_u, tvb, offset, 2, flags);
	  proto_tree_add_boolean(flags_tree, hf_icmp_mip_x, tvb, offset, 2, flags);

	  /* Reserved */
	  proto_tree_add_uint(flags_tree, hf_icmp_mip_reserved, tvb, offset, 2, flags);
	  offset+=2;

	  /* COAs */
	  numCOAs = (length - 6) / 4;
	  for (i=0; i<numCOAs; i++) {
		proto_tree_add_item(mip_tree, hf_icmp_mip_coa, tvb, offset,
							4, FALSE);
		offset+=4;
	  }
	  break;
	case ICMP_MIP_PREFIX_LENGTHS:
	  /* Prefix-Lengths Extension  (RFC 2002)*/
	  /* Add our fields */
	  /* type */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_type, tvb, offset,
						  1, FALSE);
	  offset++;
	  /* length */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_length, tvb, offset,
						  1, FALSE);
	  offset++;

	  /* prefix lengths */
	  for(i=0; i<length; i++) {
		proto_tree_add_item(mip_tree, hf_icmp_mip_prefix_length, tvb, offset,
							1, FALSE);
		offset++;
	  }
	  break;
	case ICMP_MIP_CHALLENGE:
	  /* Challenge Extension  (RFC 3012)*/
	  /* type */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_type, tvb, offset,
						  1, FALSE);
	  offset++;
	  /* length */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_length, tvb, offset,
						  1, FALSE);
	  offset++;
	  /* challenge */
	  proto_tree_add_item(mip_tree, hf_icmp_mip_challenge, tvb, offset,
						  length, FALSE);
	  offset+=length;

	  break;
	default:
	  g_warning("Unknown type(%u)!  I hope the length is right (%u)",
				type, length);
	  offset += length + 2;
	  break;
	} /* switch type */
  } /* end while */

} /* dissect_mip_extensions */

#define MPLS_STACK_ENTRY_OBJECT_CLASS           1
#define MPLS_EXTENDED_PAYLOAD_OBJECT_CLASS      2

#define MPLS_STACK_ENTRY_C_TYPE                 1
#define MPLS_EXTENDED_PAYLOAD_C_TYPE            1

/* XXX no header defines these macros ??? */
#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif

/*
 * Dissect the MPLS extensions
 */
static void
dissect_mpls_extensions(tvbuff_t *tvb, gint offset, proto_tree *tree)
{
    guint8          version;
    guint8          class_num;
    guint8          c_type;
    guint8          ttl;
    guint8          tmp;
    guint16         reserved;
    guint16         cksum, computed_cksum;
    guint16         obj_length, obj_trunc_length;
    proto_item      *ti, *tf_object, *tf_entry, *hidden_item;
    proto_tree      *mpls_tree=NULL, *mpls_object_tree, *mpls_stack_object_tree;
    gint            obj_end_offset;
    guint           reported_length;
    guint           label;
    gboolean        unknown_object;

    if (!tree)
        return;

    reported_length = tvb_reported_length_remaining(tvb, offset);

    if (reported_length < 4 /* Common header */)
    {
        proto_tree_add_text(tree, tvb, offset,
                            reported_length,
                            "MPLS Extensions (truncated)");
        return;
    }

    /* Add a tree for the MPLS extensions */
    ti = proto_tree_add_none_format(tree, hf_icmp_mpls, tvb,
                                            offset, reported_length, "MPLS Extensions");

    mpls_tree = proto_item_add_subtree(ti, ett_icmp_mpls);

    /* Version */
    version = hi_nibble(tvb_get_guint8(tvb, offset));
    proto_tree_add_uint(mpls_tree, hf_icmp_mpls_version, tvb, offset, 1, version);

    /* Reserved */
    reserved = tvb_get_ntohs(tvb, offset) & 0x0fff;
    proto_tree_add_uint_format(mpls_tree, hf_icmp_mpls_reserved,
                                tvb, offset, 2, reserved,
                                "Reserved: 0x%03x", reserved);

    /* Checksum */
    cksum = tvb_get_ntohs(tvb, offset + 2);

    computed_cksum = ip_checksum(tvb_get_ptr(tvb, offset, reported_length),
                                    reported_length);

    if (computed_cksum == 0)
    {
        proto_tree_add_uint_format(mpls_tree, hf_icmp_mpls_checksum, tvb, offset + 2, 2,
                                    cksum, "Checksum: 0x%04x [correct]", cksum);
    }
    else
    {
        hidden_item = proto_tree_add_boolean(mpls_tree, hf_icmp_mpls_checksum_bad, tvb,
                                            offset + 2, 2, TRUE);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        proto_tree_add_uint_format(mpls_tree, hf_icmp_mpls_checksum, tvb, offset + 2, 2,
                                    cksum,
                                    "Checksum: 0x%04x [incorrect, should be 0x%04x]",
                                    cksum, in_cksum_shouldbe(cksum, computed_cksum));
    }

    if (version != 1 && version != 2)
    {
        /* Unsupported version */
        proto_item_append_text(ti, " (unsupported version)");
        return;
    }

    /* Skip the common header */
    offset += 4;

    /* While there is enough room to read an object */
    while (tvb_reported_length_remaining(tvb, offset) >= 4 /* Object header */)
    {
        /* Object length */
        obj_length = tvb_get_ntohs(tvb, offset);

        obj_trunc_length =  min(obj_length, tvb_reported_length_remaining(tvb, offset));

        obj_end_offset = offset + obj_trunc_length;

        /* Add a subtree for this object (the text will be reset later) */
        tf_object = proto_tree_add_text(mpls_tree, tvb, offset,
                                        max(obj_trunc_length, 4),
                                        "Unknown object");

        mpls_object_tree = proto_item_add_subtree(tf_object, ett_icmp_mpls_object);

        proto_tree_add_uint(mpls_object_tree, hf_icmp_mpls_length, tvb, offset, 2, obj_length);

        /* Class */
        class_num = tvb_get_guint8(tvb, offset + 2);
        proto_tree_add_uint(mpls_object_tree, hf_icmp_mpls_class, tvb, offset + 2, 1, class_num);

        /* C-Type */
        c_type = tvb_get_guint8(tvb, offset + 3);
        proto_tree_add_uint(mpls_object_tree, hf_icmp_mpls_c_type, tvb, offset + 3, 1, c_type);

        if (obj_length < 4 /* Object header */)
        {
            /* Thanks doc/README.developer :)) */
            proto_item_set_text(tf_object, "Object with bad length");
            break;
        }

        /* Skip the object header */
        offset += 4;

        /* Default cases will set this flag to TRUE */
        unknown_object = FALSE;

        switch (class_num)
        {
            case MPLS_STACK_ENTRY_OBJECT_CLASS:
                switch (c_type)
                {
                    case MPLS_STACK_ENTRY_C_TYPE:

                        proto_item_set_text(tf_object, "MPLS Stack Entry");

                        /* For each entry */
                        while (offset + 4 <= obj_end_offset)
                        {
                            if (tvb_reported_length_remaining(tvb, offset) < 4)
                            {
                                /* Not enough room in the packet ! */
                                break;
                            }

                            /* Create a subtree for each entry (the text will be set later) */
                            tf_entry = proto_tree_add_text(mpls_object_tree,
                                                            tvb, offset, 4, " ");
                            mpls_stack_object_tree = proto_item_add_subtree(tf_entry,
                                                                            ett_icmp_mpls_stack_object);

                            /* Label */
                            label =  (guint)tvb_get_ntohs(tvb, offset);
                            tmp = tvb_get_guint8(tvb, offset + 2);
                            label = (label << 4) + (tmp >> 4);

                            proto_tree_add_uint(mpls_stack_object_tree,
                                                    hf_icmp_mpls_label,
                                                    tvb,
                                                    offset,
                                                    3,
                                                    label << 4);

                            proto_item_set_text(tf_entry, "Label: %u", label);

                            /* Experimental field (also called "CoS") */
                            proto_tree_add_uint(mpls_stack_object_tree,
                                                    hf_icmp_mpls_exp,
                                                    tvb,
                                                    offset + 2,
                                                    1,
                                                    tmp);

                            proto_item_append_text(tf_entry, ", Exp: %u", (tmp >> 1) & 0x07);

                            /* Stack bit */
                            proto_tree_add_boolean(mpls_stack_object_tree,
                                                    hf_icmp_mpls_s,
                                                    tvb,
                                                    offset + 2,
                                                    1,
                                                    tmp);

                            proto_item_append_text(tf_entry, ", S: %u", tmp  & 0x01);

                            /* TTL */
                            ttl = tvb_get_guint8(tvb, offset + 3);

                            proto_tree_add_item(mpls_stack_object_tree,
                                                hf_icmp_mpls_ttl,
                                                tvb,
                                                offset + 3,
                                                1,
                                                FALSE);

                            proto_item_append_text(tf_entry, ", TTL: %u", ttl);

                            /* Skip the entry */
                            offset += 4;

                        } /* end while */

                        if (offset < obj_end_offset)
                            proto_tree_add_text(mpls_object_tree, tvb,
                                                offset,
                                                obj_end_offset - offset,
                                                "%d junk bytes",
                                                obj_end_offset - offset);

                        break;
                    default:

                        unknown_object = TRUE;

                        break;
                } /* end switch c_type */
                break;
            case MPLS_EXTENDED_PAYLOAD_OBJECT_CLASS:
                switch (c_type)
                {
                    case MPLS_EXTENDED_PAYLOAD_C_TYPE:
                        proto_item_set_text(tf_object, "Extended Payload");

                        /* This object contains some portion of the original packet
                        that could not fit in the 128 bytes of the ICMP payload */
                        if (obj_trunc_length > 4)
                            proto_tree_add_text(mpls_object_tree, tvb,
                                                offset, obj_trunc_length - 4,
                                                "Data (%d bytes)", obj_trunc_length - 4);

                        break;
                    default:

                        unknown_object = TRUE;

                        break;
                } /* end switch c_type */
                break;
            default:

                unknown_object = TRUE;

                break;
        } /* end switch class_num */

        /* The switches couldn't decode the object */
        if (unknown_object == TRUE)
        {
            proto_item_set_text(tf_object, "Unknown object (%d/%d)", class_num, c_type);

            if (obj_trunc_length > 4)
                proto_tree_add_text(mpls_object_tree, tvb,
                                    offset, obj_trunc_length - 4,
                                    "Data (%d bytes)", obj_trunc_length - 4);
        }

        /* */
        if (obj_trunc_length < obj_length)
            proto_item_append_text(tf_object, " (truncated)");

        /* Go to the end of the object */
        offset = obj_end_offset;

    } /* end while */
} /* end dissect_mpls_extensions */

static const gchar *unreach_str[] = {"Network unreachable",
                                     "Host unreachable",
                                     "Protocol unreachable",
                                     "Port unreachable",
                                     "Fragmentation needed",
                                     "Source route failed",
                                     "Destination network unknown",
                                     "Destination host unknown",
                                     "Source host isolated",
                                     "Network administratively prohibited",
                                     "Host administratively prohibited",
                                     "Network unreachable for TOS",
                                     "Host unreachable for TOS",
                                     "Communication administratively filtered",
                                     "Host precedence violation",
                                     "Precedence cutoff in effect"};

#define	N_UNREACH	(sizeof unreach_str / sizeof unreach_str[0])

static const gchar *redir_str[] = {"Redirect for network",
                                   "Redirect for host",
                                   "Redirect for TOS and network",
                                   "Redirect for TOS and host"};

#define	N_REDIRECT	(sizeof redir_str / sizeof redir_str[0])

static const gchar *ttl_str[] = {"Time to live exceeded in transit",
                                 "Fragment reassembly time exceeded"};

#define	N_TIMXCEED	(sizeof ttl_str / sizeof ttl_str[0])

static const gchar *par_str[] = {"IP header bad", "Required option missing"};

#define	N_PARAMPROB	(sizeof par_str / sizeof par_str[0])

/*
 * RFC 792 for basic ICMP.
 * RFC 1191 for ICMP_FRAG_NEEDED (with MTU of next hop).
 * RFC 1256 for router discovery messages.
 * RFC 2002 and 3012 for Mobile IP stuff.
 */
static void
dissect_icmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *icmp_tree = NULL;
  guint8     icmp_type;
  guint8     icmp_code;
  guint      length, reported_length;
  guint16    cksum, computed_cksum;
  const gchar *type_str, *code_str;
  guint8     num_addrs = 0;
  guint8     addr_entry_size = 0;
  int        i;
  gboolean   save_in_error_pkt;
  tvbuff_t   *next_tvb;
  proto_item *item;

  type_str="";
  code_str="";


  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ICMP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  /* To do: check for runts, errs, etc. */
  icmp_type = tvb_get_guint8(tvb, 0);
  icmp_code = tvb_get_guint8(tvb, 1);
  cksum = tvb_get_ntohs(tvb, 2);

  switch (icmp_type) {
    case ICMP_ECHOREPLY:
      type_str="Echo (ping) reply";
      break;
    case ICMP_UNREACH:
      type_str="Destination unreachable";
      if (icmp_code < N_UNREACH) {
        code_str = unreach_str[icmp_code];
      } else {
        code_str = "Unknown - error?";
      }
      break;
    case ICMP_SOURCEQUENCH:
      type_str="Source quench (flow control)";
      break;
    case ICMP_REDIRECT:
      type_str="Redirect";
      if (icmp_code < N_REDIRECT) {
        code_str = redir_str[icmp_code];
      } else {
        code_str = "Unknown - error?";
      }
      break;
    case ICMP_ECHO:
      type_str="Echo (ping) request";
      break;
    case ICMP_RTRADVERT:
      switch (icmp_code) {
      case 0: /* Mobile-Ip */
      case 16: /* Mobile-Ip */
        type_str="Mobile IP Advertisement";
        break;
      default:
        type_str="Router advertisement";
        break;
      } /* switch icmp_code */
      break;
    case ICMP_RTRSOLICIT:
      type_str="Router solicitation";
      break;
    case ICMP_TIMXCEED:
      type_str="Time-to-live exceeded";
      if (icmp_code < N_TIMXCEED) {
        code_str = ttl_str[icmp_code];
      } else {
        code_str = "Unknown - error?";
      }
      break;
    case ICMP_PARAMPROB:
      type_str="Parameter problem";
      if (icmp_code < N_PARAMPROB) {
        code_str = par_str[icmp_code];
      } else {
        code_str = "Unknown - error?";
      }
      break;
    case ICMP_TSTAMP:
      type_str="Timestamp request";
      break;
    case ICMP_TSTAMPREPLY:
      type_str="Timestamp reply";
      break;
    case ICMP_IREQ:
      type_str="Information request";
      break;
    case ICMP_IREQREPLY:
      type_str="Information reply";
      break;
    case ICMP_MASKREQ:
      type_str="Address mask request";
      break;
    case ICMP_MASKREPLY:
      type_str="Address mask reply";
      break;
    default:
      type_str="Unknown ICMP (obsolete or malformed?)";
      break;
  }

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_set_str(pinfo->cinfo, COL_INFO, type_str);
    if (code_str[0] != '\0')
      col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", code_str);
  }

  length = tvb_length(tvb);
  reported_length = tvb_reported_length(tvb);

  if (tree) {
    proto_item *ti;

    ti = proto_tree_add_item(tree, proto_icmp, tvb, 0, length, FALSE);
    icmp_tree = proto_item_add_subtree(ti, ett_icmp);
    proto_tree_add_uint_format(icmp_tree, hf_icmp_type, tvb, 0, 1,
			       icmp_type,
			       "Type: %u (%s)",
			       icmp_type, type_str);
    proto_tree_add_uint_format(icmp_tree, hf_icmp_code, tvb, 1, 1,
			       icmp_code,
			       "Code: %u (%s)",
			       icmp_code, code_str);
    if (!pinfo->fragmented && length >= reported_length) {
      /* The packet isn't part of a fragmented datagram and isn't
         truncated, so we can checksum it. */

      computed_cksum = ip_checksum(tvb_get_ptr(tvb, 0, reported_length),
	  			     reported_length);
      if (computed_cksum == 0) {
        proto_tree_add_uint_format(icmp_tree, hf_icmp_checksum, tvb, 2, 2,
 			  cksum,
			  "Checksum: 0x%04x [correct]", cksum);
      } else {
        item = proto_tree_add_boolean(icmp_tree, hf_icmp_checksum_bad,
			  tvb, 2, 2, TRUE);
        PROTO_ITEM_SET_HIDDEN(item);
        proto_tree_add_uint_format(icmp_tree, hf_icmp_checksum, tvb, 2, 2,
		  cksum,
		  "Checksum: 0x%04x [incorrect, should be 0x%04x]",
		  cksum, in_cksum_shouldbe(cksum, computed_cksum));
      }
    } else {
      proto_tree_add_uint(icmp_tree, hf_icmp_checksum, tvb, 2, 2, cksum);
    }
  }

  /* Decode the second 4 bytes of the packet. */
  switch (icmp_type) {
      case ICMP_ECHOREPLY:
      case ICMP_ECHO:
      case ICMP_TSTAMP:
      case ICMP_TSTAMPREPLY:
      case ICMP_IREQ:
      case ICMP_IREQREPLY:
      case ICMP_MASKREQ:
      case ICMP_MASKREPLY:
        proto_tree_add_item(icmp_tree, hf_icmp_ident, tvb, 4, 2, FALSE);
        proto_tree_add_item(icmp_tree, hf_icmp_seq_num, tvb, 6, 2, FALSE);
	break;

      case ICMP_UNREACH:
        switch (icmp_code) {
          case ICMP_FRAG_NEEDED:
            proto_tree_add_item(icmp_tree, hf_icmp_mtu, tvb, 6, 2, FALSE);
            break;
	}
        break;

      case ICMP_RTRADVERT:
        num_addrs = tvb_get_guint8(tvb, 4);
	proto_tree_add_text(icmp_tree, tvb, 4, 1, "Number of addresses: %u",
	  num_addrs);
	addr_entry_size = tvb_get_guint8(tvb, 5);
	proto_tree_add_text(icmp_tree, tvb, 5, 1, "Address entry size: %u",
	  addr_entry_size);
	proto_tree_add_text(icmp_tree, tvb, 6, 2, "Lifetime: %s",
	  time_secs_to_str(tvb_get_ntohs(tvb, 6)));
	break;

      case ICMP_PARAMPROB:
	proto_tree_add_text(icmp_tree, tvb, 4, 1, "Pointer: %u",
	  tvb_get_guint8(tvb, 4));
	break;

      case ICMP_REDIRECT:
        proto_tree_add_item(icmp_tree, hf_icmp_redir_gw, tvb, 4, 4, FALSE);
	break;
  }

  /* Decode the additional information in the packet.  */
  switch (icmp_type) {
      case ICMP_UNREACH:
      case ICMP_TIMXCEED:
      case ICMP_PARAMPROB:
      case ICMP_SOURCEQUENCH:
      case ICMP_REDIRECT:
	/* Save the current value of the "we're inside an error packet"
	   flag, and set that flag; subdissectors may treat packets
	   that are the payload of error packets differently from
	   "real" packets. */
	save_in_error_pkt = pinfo->in_error_pkt;
	pinfo->in_error_pkt = TRUE;

	/* Decode the IP header and first 64 bits of data from the
	   original datagram. */
	next_tvb = tvb_new_subset(tvb, 8, -1, -1);

	/* There is a collision between RFC 1812 and draft-ietf-mpls-icmp-02.
	We don't know how to decode the 128th and following bytes of the ICMP payload.
	According to draft-ietf-mpls-icmp-02, these bytes should be decoded as MPLS extensions
	whereas RFC 1812 tells us to decode them as a portion of the original packet.
	Let the user decide.

	Here the user decided to favor MPLS extensions.
	Force the IP dissector to decode only the first 128 bytes. */
	if ((tvb_reported_length(tvb) > 8 + 128) &&
			favor_icmp_mpls_ext && (tvb_get_ntohs(tvb, 8 + 2) > 128))
		set_actual_length(next_tvb, 128);

	call_dissector(ip_handle, next_tvb, pinfo, icmp_tree);

	/* Restore the "we're inside an error packet" flag. */
	pinfo->in_error_pkt = save_in_error_pkt;

	/* Decode MPLS extensions if the payload has at least 128 bytes, and
		- the original packet in the ICMP payload has less than 128 bytes, or
		- the user favors the MPLS extensions analysis */
	if ((tvb_reported_length(tvb) > 8 + 128)
			&& (tvb_get_ntohs(tvb, 8 + 2) <= 128 || favor_icmp_mpls_ext))
		dissect_mpls_extensions(tvb, 8 + 128, icmp_tree);

	break;

      case ICMP_ECHOREPLY:
      case ICMP_ECHO:
	call_dissector(data_handle, tvb_new_subset(tvb, 8, -1, -1), pinfo,
	               icmp_tree);
	break;

      case ICMP_RTRADVERT:
        if (addr_entry_size == 2) {
	  for (i = 0; i < num_addrs; i++) {
	    proto_tree_add_text(icmp_tree, tvb, 8 + (i*8), 4,
	      "Router address: %s",
	      ip_to_str(tvb_get_ptr(tvb, 8 + (i*8), 4)));
	    proto_tree_add_text(icmp_tree, tvb, 12 + (i*8), 4,
	      "Preference level: %d", tvb_get_ntohl(tvb, 12 + (i*8)));
	  }
	  if ((icmp_code == 0) || (icmp_code == 16)) {
		/* Mobile-Ip */
		dissect_mip_extensions(tvb, 8 + i*8, icmp_tree);
	  }
	} else
	  call_dissector(data_handle, tvb_new_subset(tvb, 8, -1, -1), pinfo,
	                 icmp_tree);
	break;

      case ICMP_TSTAMP:
      case ICMP_TSTAMPREPLY:
	proto_tree_add_text(icmp_tree, tvb, 8, 4, "Originate timestamp: %s after midnight UTC",
	  time_msecs_to_str(tvb_get_ntohl(tvb, 8)));
	proto_tree_add_text(icmp_tree, tvb, 12, 4, "Receive timestamp: %s after midnight UTC",
	  time_msecs_to_str(tvb_get_ntohl(tvb, 12)));
	proto_tree_add_text(icmp_tree, tvb, 16, 4, "Transmit timestamp: %s after midnight UTC",
	  time_msecs_to_str(tvb_get_ntohl(tvb, 16)));
	break;

    case ICMP_MASKREQ:
    case ICMP_MASKREPLY:
	proto_tree_add_text(icmp_tree, tvb, 8, 4, "Address mask: %s (0x%08x)",
	  ip_to_str(tvb_get_ptr(tvb, 8, 4)), tvb_get_ntohl(tvb, 8));
	break;
  }
}

void
proto_register_icmp(void)
{
  static hf_register_info hf[] = {

    { &hf_icmp_type,
      { "Type",		"icmp.type",		FT_UINT8, BASE_DEC,	NULL, 0x0,
      	NULL, HFILL }},

    { &hf_icmp_code,
      { "Code",		"icmp.code",		FT_UINT8, BASE_HEX,	NULL, 0x0,
      	NULL, HFILL }},

    { &hf_icmp_checksum,
      { "Checksum",	"icmp.checksum",	FT_UINT16, BASE_HEX,	NULL, 0x0,
      	NULL, HFILL }},

    { &hf_icmp_checksum_bad,
      { "Bad Checksum",	"icmp.checksum_bad",	FT_BOOLEAN, BASE_NONE,	NULL, 0x0,
	NULL, HFILL }},

    { &hf_icmp_ident,
      {"Identifier", "icmp.ident",              FT_UINT16, BASE_HEX,    NULL, 0x0,
       NULL, HFILL }},

    { &hf_icmp_seq_num,
      {"Sequence number", "icmp.seq",           FT_UINT16, BASE_DEC_HEX,    NULL, 0x0,
       NULL, HFILL }},

    { &hf_icmp_mtu,
      {"MTU of next hop", "icmp.mtu",           FT_UINT16, BASE_DEC,    NULL, 0x0,
       NULL, HFILL}},

    { &hf_icmp_redir_gw,
      {"Gateway address", "icmp.redir_gw",      FT_IPv4, BASE_NONE,     NULL, 0x0,
       NULL, HFILL }},

    { &hf_icmp_mip_type,
      { "Extension Type", "icmp.mip.type",	FT_UINT8, BASE_DEC,
	VALS(mip_extensions), 0x0,NULL, HFILL}},

    { &hf_icmp_mip_length,
      { "Length", "icmp.mip.length",		FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},

    { &hf_icmp_mip_prefix_length,
      { "Prefix Length", "icmp.mip.prefixlength",  FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},

    { &hf_icmp_mip_seq,
      { "Sequence Number", "icmp.mip.seq",	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},

    { &hf_icmp_mip_life,
      { "Registration Lifetime", "icmp.mip.life",  FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},

    { &hf_icmp_mip_flags,
      { "Flags", "icmp.mip.flags",            FT_UINT16, BASE_HEX, NULL, 0x0,
	NULL, HFILL}},

    { &hf_icmp_mip_r,
      { "Registration Required", "icmp.mip.r", FT_BOOLEAN, 16, NULL, 32768,
	"Registration with this FA is required", HFILL }},

    { &hf_icmp_mip_b,
      { "Busy", "icmp.mip.b", FT_BOOLEAN, 16, NULL, 16384,
	"This FA will not accept requests at this time", HFILL }},

    { &hf_icmp_mip_h,
      { "Home Agent", "icmp.mip.h", FT_BOOLEAN, 16, NULL, 8192,
	"Home Agent Services Offered", HFILL }},

    { &hf_icmp_mip_f,
      { "Foreign Agent", "icmp.mip.f", FT_BOOLEAN, 16, NULL, 4096,
	"Foreign Agent Services Offered", HFILL }},

    { &hf_icmp_mip_m,
      { "Minimal Encapsulation", "icmp.mip.m", FT_BOOLEAN, 16, NULL, 2048,
	"Minimal encapsulation tunneled datagram support", HFILL }},

    { &hf_icmp_mip_g,
      { "GRE", "icmp.mip.g", FT_BOOLEAN, 16, NULL, 1024,
	"GRE encapsulated tunneled datagram support", HFILL }},

    { &hf_icmp_mip_v,
      { "VJ Comp", "icmp.mip.v", FT_BOOLEAN, 16, NULL, 512,
	"Van Jacobson Header Compression Support", HFILL }},

    { &hf_icmp_mip_rt,
      { "Reverse tunneling", "icmp.mip.rt", FT_BOOLEAN, 16, NULL, 256,
       "Reverse tunneling support", HFILL }},

    { &hf_icmp_mip_u,
      { "UDP tunneling", "icmp.mip.u", FT_BOOLEAN, 16, NULL, 128,
       "UDP tunneling support", HFILL }},

    { &hf_icmp_mip_x,
      { "Revocation support", "icmp.mip.x", FT_BOOLEAN, 16, NULL, 64,
       "Registration revocation support", HFILL }},


    { &hf_icmp_mip_reserved,
      { "Reserved", "icmp.mip.reserved",     FT_UINT16, BASE_HEX, NULL, 0x003f,
	NULL, HFILL}},

    { &hf_icmp_mip_coa,
      { "Care-Of-Address", "icmp.mip.coa",    FT_IPv4, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},

    { &hf_icmp_mip_challenge,
      { "Challenge", "icmp.mip.challenge",    FT_BYTES, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},

    { &hf_icmp_mpls,
      { "ICMP Extensions for MPLS",	"icmp.mpls",	FT_NONE, BASE_NONE,	NULL, 0x0,
	NULL, HFILL }},

	{ &hf_icmp_mpls_version,
		{ "Version",		"icmp.mpls.version", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

    { &hf_icmp_mpls_reserved,
      { "Reserved",	"icmp.mpls.res",	FT_UINT16, BASE_HEX,	NULL, 0x0,
      	NULL, HFILL }},

	{ &hf_icmp_mpls_checksum,
      { "Checksum",	"icmp.mpls.checksum",	FT_UINT16, BASE_HEX,	NULL, 0x0,
      	NULL, HFILL }},

	{ &hf_icmp_mpls_checksum_bad,
      { "Bad Checksum",	"icmp.mpls.checksum_bad",	FT_BOOLEAN, BASE_NONE,	NULL, 0x0,
	NULL, HFILL }},

	{ &hf_icmp_mpls_length,
      { "Length",	"icmp.mpls.length",	FT_UINT16, BASE_HEX,	NULL, 0x0,
      	NULL, HFILL }},

	{ &hf_icmp_mpls_class,
		{ "Class",	"icmp.mpls.class", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

	{ &hf_icmp_mpls_c_type,
		{ "C-Type",	"icmp.mpls.ctype", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

	{ &hf_icmp_mpls_label,
		{ "Label",	"icmp.mpls.label", FT_UINT24, BASE_DEC, NULL, 0x00fffff0,
			NULL, HFILL }},

	{ &hf_icmp_mpls_exp,
		{ "Experimental",	"icmp.mpls.exp", FT_UINT24, BASE_DEC,
			NULL, 0x0e,
			NULL, HFILL }},

	{ &hf_icmp_mpls_s,
		{ "Stack bit",	"icmp.mpls.s", FT_BOOLEAN, 24, TFS(&tfs_set_notset), 0x01,
			NULL, HFILL }},

	{ &hf_icmp_mpls_ttl,
		{ "Time to live",	"icmp.mpls.ttl", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }}

  };
  static gint *ett[] = {
    &ett_icmp,
	&ett_icmp_mip,
	&ett_icmp_mip_flags,
	/* MPLS extensions */
	&ett_icmp_mpls,
	&ett_icmp_mpls_object,
	&ett_icmp_mpls_stack_object
  };

  module_t *icmp_module;

  proto_icmp = proto_register_protocol("Internet Control Message Protocol",
				       "ICMP", "icmp");
  proto_register_field_array(proto_icmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  icmp_module = prefs_register_protocol(proto_icmp, NULL);

  prefs_register_bool_preference(icmp_module, "favor_icmp_mpls",
	    "Favor ICMP extensions for MPLS",
	    "Whether the 128th and following bytes of the ICMP payload should be decoded as MPLS extensions or as a portion of the original packet",
	    &favor_icmp_mpls_ext);

  register_dissector("icmp", dissect_icmp, proto_icmp);
}

void
proto_reg_handoff_icmp(void)
{
  dissector_handle_t icmp_handle;

  /*
   * Get handle for the IP dissector.
   */
  ip_handle = find_dissector("ip");
  icmp_handle = find_dissector("icmp");
  data_handle = find_dissector("data");

  dissector_add("ip.proto", IP_PROTO_ICMP, icmp_handle);
}
