/* packet-udp.c
 * Routines for UDP/UDPLite packet disassembly
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Richard Sharpe, 13-Feb-1999, added dispatch table support and
 *                              support for tftp.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-udp.h"

#include "packet-ip.h"
#include <epan/conversation.h>
#include <epan/tap.h>

static int udp_tap = -1;
static int udp_follow_tap = -1;

static int proto_udp = -1;
static int proto_udplite = -1;
static int hf_udp_srcport = -1;
static int hf_udp_dstport = -1;
static int hf_udp_port = -1;
static int hf_udp_length = -1;
static int hf_udplite_checksum_coverage = -1;
static int hf_udplite_checksum_coverage_bad = -1;
static int hf_udp_checksum = -1;
static int hf_udp_checksum_good = -1;
static int hf_udp_checksum_bad = -1;
static int hf_udp_proc_src_uid = -1;
static int hf_udp_proc_src_pid = -1;
static int hf_udp_proc_src_uname = -1;
static int hf_udp_proc_src_cmd = -1;
static int hf_udp_proc_dst_uid = -1;
static int hf_udp_proc_dst_pid = -1;
static int hf_udp_proc_dst_uname = -1;
static int hf_udp_proc_dst_cmd = -1;

static gint ett_udp = -1;
static gint ett_udp_checksum = -1;
static gint ett_udp_process_info = -1;

/* Preferences */

/* Place UDP summary in proto tree */
static gboolean udp_summary_in_tree = TRUE;

/* Check UDP checksums */
static gboolean udp_check_checksum = FALSE;

/* Collect IPFIX process flow information */
static gboolean udp_process_info = FALSE;

/* Ignore an invalid checksum coverage field for UDPLite */
static gboolean udplite_ignore_checksum_coverage = TRUE;

/* Check UDPLite checksums */
static gboolean udplite_check_checksum = FALSE;

static dissector_table_t udp_dissector_table;
static heur_dissector_list_t heur_subdissector_list;
static dissector_handle_t data_handle;

/* Determine if there is a sub-dissector and call it.  This has been */
/* separated into a stand alone routine so other protocol dissectors */
/* can call to it, ie. socks	*/

static gboolean try_heuristic_first = FALSE;


/* Conversation and process code originally copied from packet-tcp.c */
static struct udp_analysis *
init_udp_conversation_data(void)
{
  struct udp_analysis *udpd;

  /* Initialize the udp protocol data structure to add to the udp conversation */
  udpd = se_alloc0(sizeof(struct udp_analysis));
  /*
  udpd->flow1.username = NULL;
  udpd->flow1.command = NULL;
  udpd->flow2.username = NULL;
  udpd->flow2.command = NULL;
  */

  return udpd;
}

static struct udp_analysis *
get_udp_conversation_data(conversation_t *conv, packet_info *pinfo)
{
  int direction;
  struct udp_analysis *udpd=NULL;

  /* Did the caller supply the conversation pointer? */
  if( conv==NULL )
	  conv = find_or_create_conversation(pinfo);

  /* Get the data for this conversation */
  udpd=conversation_get_proto_data(conv, proto_udp);

  /* If the conversation was just created or it matched a
   * conversation with template options, udpd will not
   * have been initialized. So, initialize
   * a new udpd structure for the conversation.
   */
  if (!udpd) {
    udpd = init_udp_conversation_data();
    conversation_add_proto_data(conv, proto_udp, udpd);
  }

  if (!udpd) {
    return NULL;
  }

  /* check direction and get ua lists */
  direction=CMP_ADDRESS(&pinfo->src, &pinfo->dst);
  /* if the addresses are equal, match the ports instead */
  if(direction==0) {
	  direction= (pinfo->srcport > pinfo->destport) ? 1 : -1;
  }
  if(direction>=0){
	  udpd->fwd=&(udpd->flow1);
	  udpd->rev=&(udpd->flow2);
  } else {
	  udpd->fwd=&(udpd->flow2);
	  udpd->rev=&(udpd->flow1);
  }

  return udpd;
}

/* Attach process info to a flow */
/* XXX - We depend on the UDP dissector finding the conversation first */
void
add_udp_process_info(guint32 frame_num, address *local_addr, address *remote_addr, guint16 local_port, guint16 remote_port, guint32 uid, guint32 pid, gchar *username, gchar *command) {
  conversation_t *conv;
  struct udp_analysis *udpd;
  udp_flow_t *flow = NULL;

  if (!udp_process_info) {
    return;
  }

  conv = find_conversation(frame_num, local_addr, remote_addr, PT_UDP, local_port, remote_port, 0);
  if (!conv) {
    return;
  }

  udpd = conversation_get_proto_data(conv, proto_udp);
  if (!udpd) {
    return;
  }

  if (CMP_ADDRESS(local_addr, &conv->key_ptr->addr1) == 0 && local_port == conv->key_ptr->port1) {
    flow = &udpd->flow1;
  } else if (CMP_ADDRESS(remote_addr, &conv->key_ptr->addr1) == 0 && remote_port == conv->key_ptr->port1) {
    flow = &udpd->flow2;
  }
  if (!flow || flow->command) {
    return;
  }

  flow->process_uid = uid;
  flow->process_pid = pid;
  flow->username = se_strdup(username);
  flow->command = se_strdup(command);
}



void
decode_udp_ports(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, int uh_sport, int uh_dport, int uh_ulen)
{
  tvbuff_t *next_tvb;
  int low_port, high_port;
  gint len, reported_len;

  len = tvb_length_remaining(tvb, offset);
  reported_len = tvb_reported_length_remaining(tvb, offset);
  if (uh_ulen != -1) {
    /* This is the length from the UDP header; the payload should be cut
       off at that length.  (If our caller passed a value here, they
       are assumed to have checked that it's >= 8, and hence >= offset.)

       XXX - what if it's *greater* than the reported length? */
    if (uh_ulen - offset < reported_len)
      reported_len = uh_ulen - offset;
    if (len > reported_len)
      len = reported_len;
  }

  next_tvb = tvb_new_subset(tvb, offset, len, reported_len);

  /* If the user has a "Follow UDP Stream" window loading, pass a pointer
   * to the payload tvb through the tap system. */
  if(have_tap_listener(udp_follow_tap))
	  tap_queue_packet(udp_follow_tap, pinfo, next_tvb);

/* determine if this packet is part of a conversation and call dissector */
/* for the conversation if available */

  if (try_conversation_dissector(&pinfo->dst, &pinfo->src, PT_UDP,
		uh_dport, uh_sport, next_tvb, pinfo, tree)){
    return;
  }

  if (try_heuristic_first) {
    /* do lookup with the heuristic subdissector table */
    if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree))
      return;
  }

  /* Do lookups with the subdissector table.
     We try the port number with the lower value first, followed by the
     port number with the higher value.  This means that, for packets
     where a dissector is registered for *both* port numbers:

	1) we pick the same dissector for traffic going in both directions;

	2) we prefer the port number that's more likely to be the right
	   one (as that prefers well-known ports to reserved ports);

     although there is, of course, no guarantee that any such strategy
     will always pick the right port number.

     XXX - we ignore port numbers of 0, as some dissectors use a port
     number of 0 to disable the port, and as RFC 768 says that the source
     port in UDP datagrams is optional and is 0 if not used. */
  if (uh_sport > uh_dport) {
    low_port = uh_dport;
    high_port = uh_sport;
  } else {
    low_port = uh_sport;
    high_port = uh_dport;
  }
  if (low_port != 0 &&
      dissector_try_uint(udp_dissector_table, low_port, next_tvb, pinfo, tree))
    return;
  if (high_port != 0 &&
      dissector_try_uint(udp_dissector_table, high_port, next_tvb, pinfo, tree))
    return;

  if (!try_heuristic_first) {
    /* do lookup with the heuristic subdissector table */
    if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree))
      return;
  }

  call_dissector(data_handle,next_tvb, pinfo, tree);
}


static void
dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 ip_proto)
{
  proto_tree *udp_tree = NULL;
  proto_item *ti, *hidden_item, *port_item;
  guint      len;
  guint      reported_len;
  vec_t      cksum_vec[4];
  guint32    phdr[2];
  guint16    computed_cksum;
  int        offset = 0;
  e_udphdr *udph;
  proto_tree *checksum_tree;
  proto_item *item;
  conversation_t *conv = NULL;
  struct udp_analysis *udpd = NULL;
  proto_tree *process_tree;

  udph=ep_alloc(sizeof(e_udphdr));
  SET_ADDRESS(&udph->ip_src, pinfo->src.type, pinfo->src.len, pinfo->src.data);
  SET_ADDRESS(&udph->ip_dst, pinfo->dst.type, pinfo->dst.len, pinfo->dst.data);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, (ip_proto == IP_PROTO_UDP) ? "UDP" : "UDPlite");
  col_clear(pinfo->cinfo, COL_INFO);

  udph->uh_sport=tvb_get_ntohs(tvb, offset);
  udph->uh_dport=tvb_get_ntohs(tvb, offset+2);

  col_add_fstr(pinfo->cinfo, COL_INFO, "Source port: %s  Destination port: %s",
    get_udp_port(udph->uh_sport), get_udp_port(udph->uh_dport));

  if (tree) {
    if (udp_summary_in_tree) {
      if (ip_proto == IP_PROTO_UDP) {
        ti = proto_tree_add_protocol_format(tree, proto_udp, tvb, offset, 8,
        "User Datagram Protocol, Src Port: %s (%u), Dst Port: %s (%u)",
        get_udp_port(udph->uh_sport), udph->uh_sport, get_udp_port(udph->uh_dport), udph->uh_dport);
      } else {
        ti = proto_tree_add_protocol_format(tree, proto_udplite, tvb, offset, 8,
        "Lightweight User Datagram Protocol, Src Port: %s (%u), Dst Port: %s (%u)",
        get_udp_port(udph->uh_sport), udph->uh_sport, get_udp_port(udph->uh_dport), udph->uh_dport);
      }
    } else {
      ti = proto_tree_add_item(tree, (ip_proto == IP_PROTO_UDP) ? proto_udp : proto_udplite, tvb, offset, 8, ENC_NA);
    }
    udp_tree = proto_item_add_subtree(ti, ett_udp);

    port_item = proto_tree_add_uint_format(udp_tree, hf_udp_srcport, tvb, offset, 2, udph->uh_sport,
	"Source port: %s (%u)", get_udp_port(udph->uh_sport), udph->uh_sport);
    /* The beginning port number, 32768 + 666 (33434), is from LBL's traceroute.c source code and this code
     * further assumes that 3 attempts are made per hop */
    if(udph->uh_sport > 32768 + 666 && udph->uh_sport <= 32768 + 666 + 30)
	    expert_add_info_format(pinfo, port_item, PI_SEQUENCE, PI_CHAT, "Possible traceroute: hop #%u, attempt #%u",
				   ((udph->uh_sport - 32768 - 666 - 1) / 3) + 1,
				   ((udph->uh_sport - 32768 - 666 - 1) % 3) + 1
				   );

    port_item = proto_tree_add_uint_format(udp_tree, hf_udp_dstport, tvb, offset + 2, 2, udph->uh_dport,
	"Destination port: %s (%u)", get_udp_port(udph->uh_dport), udph->uh_dport);
    if(udph->uh_dport > 32768 + 666 && udph->uh_dport <= 32768 + 666 + 30)
	    expert_add_info_format(pinfo, port_item, PI_SEQUENCE, PI_CHAT, "Possible traceroute: hop #%u, attempt #%u",
				   ((udph->uh_dport - 32768 - 666 - 1) / 3) + 1,
				   ((udph->uh_dport - 32768 - 666 - 1) % 3) + 1
				   );

    hidden_item = proto_tree_add_uint(udp_tree, hf_udp_port, tvb, offset, 2, udph->uh_sport);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    hidden_item = proto_tree_add_uint(udp_tree, hf_udp_port, tvb, offset+2, 2, udph->uh_dport);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
  }

  if (ip_proto == IP_PROTO_UDP) {
    udph->uh_ulen = udph->uh_sum_cov = tvb_get_ntohs(tvb, offset+4);
    if (udph->uh_ulen < 8) {
      /* Bogus length - it includes the header, so it must be >= 8. */
      /* XXX - should handle IPv6 UDP jumbograms (RFC 2675), where the length is zero */
      item = proto_tree_add_uint_format(udp_tree, hf_udp_length, tvb, offset + 4, 2,
          udph->uh_ulen, "Length: %u (bogus, must be >= 8)", udph->uh_ulen);
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Bad length value %u < 8", udph->uh_ulen);
      col_append_fstr(pinfo->cinfo, COL_INFO, " [BAD UDP LENGTH %u < 8]", udph->uh_ulen);
      return;
    }
    if ((udph->uh_ulen > tvb_reported_length(tvb)) && ! pinfo->fragmented && ! pinfo->flags.in_error_pkt) {
      /* Bogus length - it goes past the end of the IP payload */
      item = proto_tree_add_uint_format(udp_tree, hf_udp_length, tvb, offset + 4, 2,
          udph->uh_ulen, "Length: %u (bogus, payload length %u)", udph->uh_ulen, tvb_reported_length(tvb));
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Bad length value %u > IP payload length", udph->uh_ulen);
      col_append_fstr(pinfo->cinfo, COL_INFO, " [BAD UDP LENGTH %u > IP PAYLOAD LENGTH]", udph->uh_ulen);
    } else {
      if (tree) {
        proto_tree_add_uint(udp_tree, hf_udp_length, tvb, offset + 4, 2, udph->uh_ulen);
        /* XXX - why is this here, given that this is UDP, not Lightweight UDP? */
        hidden_item = proto_tree_add_uint(udp_tree, hf_udplite_checksum_coverage, tvb, offset + 4,
                                          0, udph->uh_sum_cov);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
      }
    }
  } else {
    udph->uh_ulen = pinfo->iplen - pinfo->iphdrlen;
    udph->uh_sum_cov = tvb_get_ntohs(tvb, offset+4);
    if (((udph->uh_sum_cov > 0) && (udph->uh_sum_cov < 8)) || (udph->uh_sum_cov > udph->uh_ulen)) {
      /* Bogus length - it includes the header, so it must be >= 8, and no larger then the IP payload size. */
      if (tree) {
        hidden_item = proto_tree_add_boolean(udp_tree, hf_udplite_checksum_coverage_bad, tvb, offset + 4, 2, TRUE);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        hidden_item = proto_tree_add_uint(udp_tree, hf_udp_length, tvb, offset + 4, 0, udph->uh_ulen);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
      }
      item = proto_tree_add_uint_format(udp_tree, hf_udplite_checksum_coverage, tvb, offset + 4, 2,
          udph->uh_sum_cov, "Checksum coverage: %u (bogus, must be >= 8 and <= %u (ip.len-ip.hdr_len))",
          udph->uh_sum_cov, udph->uh_ulen);
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Bad checksum coverage length value %u < 8 or > %u",
                             udph->uh_sum_cov, udph->uh_ulen);
      col_append_fstr(pinfo->cinfo, COL_INFO, " [BAD LIGHTWEIGHT UDP CHECKSUM COVERAGE LENGTH %u < 8 or > %u]",
                        udph->uh_sum_cov, udph->uh_ulen);
      if (!udplite_ignore_checksum_coverage)
        return;
    } else {
      if (tree) {
        hidden_item = proto_tree_add_uint(udp_tree, hf_udp_length, tvb, offset + 4, 0, udph->uh_ulen);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        proto_tree_add_uint(udp_tree, hf_udplite_checksum_coverage, tvb, offset + 4, 2, udph->uh_sum_cov);
      }
    }
  }

  udph->uh_sum_cov = (udph->uh_sum_cov) ? udph->uh_sum_cov : udph->uh_ulen;
  udph->uh_sum = tvb_get_ntohs(tvb, offset+6);
  reported_len = tvb_reported_length(tvb);
  len = tvb_length(tvb);
  if (udph->uh_sum == 0) {
    /* No checksum supplied in the packet. */
    if (ip_proto == IP_PROTO_UDP) {
      item = proto_tree_add_uint_format(udp_tree, hf_udp_checksum, tvb, offset + 6, 2, 0,
        "Checksum: 0x%04x (none)", 0);

      checksum_tree = proto_item_add_subtree(item, ett_udp_checksum);
      item = proto_tree_add_boolean(checksum_tree, hf_udp_checksum_good, tvb,
                             offset + 6, 2, FALSE);
      PROTO_ITEM_SET_GENERATED(item);
      item = proto_tree_add_boolean(checksum_tree, hf_udp_checksum_bad, tvb,
                             offset + 6, 2, FALSE);
      PROTO_ITEM_SET_GENERATED(item);
    } else {
      item = proto_tree_add_uint_format(udp_tree, hf_udp_checksum, tvb, offset + 6, 2, 0,
        "Checksum: 0x%04x (Illegal)", 0);
      expert_add_info_format(pinfo, item, PI_CHECKSUM, PI_ERROR, "Illegal Checksum value (0)");
      col_append_fstr(pinfo->cinfo, COL_INFO, " [ILLEGAL CHECKSUM (0)]");

      checksum_tree = proto_item_add_subtree(item, ett_udp_checksum);
      item = proto_tree_add_boolean(checksum_tree, hf_udp_checksum_good, tvb,
                             offset + 6, 2, FALSE);
      PROTO_ITEM_SET_GENERATED(item);
      item = proto_tree_add_boolean(checksum_tree, hf_udp_checksum_bad, tvb,
                             offset + 6, 2, TRUE);
      PROTO_ITEM_SET_GENERATED(item);
    }
  } else if (!pinfo->fragmented && len >= reported_len &&
             len >= udph->uh_sum_cov && reported_len >= udph->uh_sum_cov &&
             udph->uh_sum_cov >=8) {
    /* The packet isn't part of a fragmented datagram and isn't
       truncated, so we can checksum it.
       XXX - make a bigger scatter-gather list once we do fragment
       reassembly? */

    if (((ip_proto == IP_PROTO_UDP) && (udp_check_checksum)) ||
        ((ip_proto == IP_PROTO_UDPLITE) && (udplite_check_checksum))) {
      /* Set up the fields of the pseudo-header. */
      cksum_vec[0].ptr = pinfo->src.data;
      cksum_vec[0].len = pinfo->src.len;
      cksum_vec[1].ptr = pinfo->dst.data;
      cksum_vec[1].len = pinfo->dst.len;
      cksum_vec[2].ptr = (const guint8 *)&phdr;
      switch (pinfo->src.type) {

      case AT_IPv4:
        phdr[0] = g_htonl((ip_proto<<16) + reported_len);
        cksum_vec[2].len = 4;
        break;

      case AT_IPv6:
        phdr[0] = g_htonl(reported_len);
        phdr[1] = g_htonl(ip_proto);
        cksum_vec[2].len = 8;
        break;

      default:
        /* UDP runs only atop IPv4 and IPv6.... */
        DISSECTOR_ASSERT_NOT_REACHED();
        break;
      }
      cksum_vec[3].ptr = tvb_get_ptr(tvb, offset, udph->uh_sum_cov);
      cksum_vec[3].len = udph->uh_sum_cov;
      computed_cksum = in_cksum(&cksum_vec[0], 4);
      if (computed_cksum == 0) {
        item = proto_tree_add_uint_format(udp_tree, hf_udp_checksum, tvb,
          offset + 6, 2, udph->uh_sum, "Checksum: 0x%04x [correct]", udph->uh_sum);

        checksum_tree = proto_item_add_subtree(item, ett_udp_checksum);
        item = proto_tree_add_boolean(checksum_tree, hf_udp_checksum_good, tvb,
                                      offset + 6, 2, TRUE);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_boolean(checksum_tree, hf_udp_checksum_bad, tvb,
                                      offset + 6, 2, FALSE);
        PROTO_ITEM_SET_GENERATED(item);
      } else {
        item = proto_tree_add_uint_format(udp_tree, hf_udp_checksum, tvb,
                                          offset + 6, 2, udph->uh_sum,
          "Checksum: 0x%04x [incorrect, should be 0x%04x (maybe caused by \"UDP checksum offload\"?)]", udph->uh_sum,
          in_cksum_shouldbe(udph->uh_sum, computed_cksum));

        checksum_tree = proto_item_add_subtree(item, ett_udp_checksum);
        item = proto_tree_add_boolean(checksum_tree, hf_udp_checksum_good, tvb,
                                      offset + 6, 2, FALSE);
        PROTO_ITEM_SET_GENERATED(item);
        item = proto_tree_add_boolean(checksum_tree, hf_udp_checksum_bad, tvb,
                                      offset + 6, 2, TRUE);
        PROTO_ITEM_SET_GENERATED(item);
        expert_add_info_format(pinfo, item, PI_CHECKSUM, PI_ERROR, "Bad checksum");

        col_append_fstr(pinfo->cinfo, COL_INFO, " [UDP CHECKSUM INCORRECT]");
      }
    } else {
      item = proto_tree_add_uint_format(udp_tree, hf_udp_checksum, tvb,
        offset + 6, 2, udph->uh_sum, "Checksum: 0x%04x [validation disabled]", udph->uh_sum);
      checksum_tree = proto_item_add_subtree(item, ett_udp_checksum);
      item = proto_tree_add_boolean(checksum_tree, hf_udp_checksum_good, tvb,
                             offset + 6, 2, FALSE);
      PROTO_ITEM_SET_GENERATED(item);
      item = proto_tree_add_boolean(checksum_tree, hf_udp_checksum_bad, tvb,
                             offset + 6, 2, FALSE);
      PROTO_ITEM_SET_GENERATED(item);
    }
  } else {
    item = proto_tree_add_uint_format(udp_tree, hf_udp_checksum, tvb,
      offset + 6, 2, udph->uh_sum, "Checksum: 0x%04x [unchecked, not all data available]", udph->uh_sum);

    checksum_tree = proto_item_add_subtree(item, ett_udp_checksum);
    item = proto_tree_add_boolean(checksum_tree, hf_udp_checksum_good, tvb,
                             offset + 6, 2, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
    item = proto_tree_add_boolean(checksum_tree, hf_udp_checksum_bad, tvb,
                             offset + 6, 2, FALSE);
    PROTO_ITEM_SET_GENERATED(item);
  }

  /* Skip over header */
  offset += 8;

  pinfo->ptype = PT_UDP;
  pinfo->srcport = udph->uh_sport;
  pinfo->destport = udph->uh_dport;

  tap_queue_packet(udp_tap, pinfo, udph);

  /* find(or create if needed) the conversation for this udp session */
  if (udp_process_info) {
    conv=find_or_create_conversation(pinfo);
    udpd=get_udp_conversation_data(conv,pinfo);
  }

  if (udpd && ((udpd->fwd && udpd->fwd->command) || (udpd->rev && udpd->rev->command))) {
    ti = proto_tree_add_text(udp_tree, tvb, offset, 0, "Process Information");
	PROTO_ITEM_SET_GENERATED(ti);
    process_tree = proto_item_add_subtree(ti, ett_udp_process_info);
	if (udpd->fwd && udpd->fwd->command) {
      proto_tree_add_uint_format_value(process_tree, hf_udp_proc_dst_uid, tvb, 0, 0,
              udpd->fwd->process_uid, "%u", udpd->fwd->process_uid);
      proto_tree_add_uint_format_value(process_tree, hf_udp_proc_dst_pid, tvb, 0, 0,
              udpd->fwd->process_pid, "%u", udpd->fwd->process_pid);
      proto_tree_add_string_format_value(process_tree, hf_udp_proc_dst_uname, tvb, 0, 0,
              udpd->fwd->username, "%s", udpd->fwd->username);
      proto_tree_add_string_format_value(process_tree, hf_udp_proc_dst_cmd, tvb, 0, 0,
              udpd->fwd->command, "%s", udpd->fwd->command);
    }
    if (udpd->rev->command) {
      proto_tree_add_uint_format_value(process_tree, hf_udp_proc_src_uid, tvb, 0, 0,
              udpd->rev->process_uid, "%u", udpd->rev->process_uid);
      proto_tree_add_uint_format_value(process_tree, hf_udp_proc_src_pid, tvb, 0, 0,
              udpd->rev->process_pid, "%u", udpd->rev->process_pid);
      proto_tree_add_string_format_value(process_tree, hf_udp_proc_src_uname, tvb, 0, 0,
              udpd->rev->username, "%s", udpd->rev->username);
      proto_tree_add_string_format_value(process_tree, hf_udp_proc_src_cmd, tvb, 0, 0,
              udpd->rev->command, "%s", udpd->rev->command);
    }
  }

  /*
   * Call sub-dissectors.
   *
   * XXX - should we do this if this is included in an error packet?
   * It might be nice to see the details of the packet that caused the
   * ICMP error, but it might not be nice to have the dissector update
   * state based on it.
   * Also, we probably don't want to run UDP taps on those packets.
   *
   * We definitely don't want to do it for an error packet if there's
   * nothing left in the packet.
   */
  if (!pinfo->flags.in_error_pkt || tvb_length_remaining(tvb, offset) > 0)
    decode_udp_ports(tvb, offset, pinfo, tree, udph->uh_sport, udph->uh_dport,
                     udph->uh_ulen);
}

static void
dissect_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect(tvb, pinfo, tree, IP_PROTO_UDP);
}

static void
dissect_udplite(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect(tvb, pinfo, tree, IP_PROTO_UDPLITE);
}

void
proto_register_udp(void)
{
	module_t *udp_module;
	module_t *udplite_module;

	static hf_register_info hf[] = {
		{ &hf_udp_srcport,
		{ "Source Port",	"udp.srcport", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_udp_dstport,
		{ "Destination Port",	"udp.dstport", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_udp_port,
		{ "Source or Destination Port",	"udp.port", FT_UINT16, BASE_DEC,  NULL, 0x0,
			NULL, HFILL }},

		{ &hf_udp_length,
		{ "Length",		"udp.length", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_udp_checksum,
		{ "Checksum",		"udp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
			"Details at: http://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html", HFILL }},

		{ &hf_udp_checksum_good,
		{ "Good Checksum",	"udp.checksum_good", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"True: checksum matches packet content; False: doesn't match content or not checked", HFILL }},

		{ &hf_udp_checksum_bad,
		{ "Bad Checksum",	"udp.checksum_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"True: checksum doesn't match packet content; False: matches content or not checked", HFILL }},

		{ &hf_udp_proc_src_uid,
		  { "Source process user ID", "udp.proc.srcuid", FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}},

		{ &hf_udp_proc_src_pid,
		  { "Source process ID", "udp.proc.srcpid", FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}},

		{ &hf_udp_proc_src_uname,
		  { "Source process user name", "udp.proc.srcuname", FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}},

		{ &hf_udp_proc_src_cmd,
		  { "Source process name", "udp.proc.srccmd", FT_STRING, BASE_NONE, NULL, 0x0,
		    "Source process command name", HFILL}},

		{ &hf_udp_proc_dst_uid,
		  { "Destination process user ID", "udp.proc.dstuid", FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}},

		{ &hf_udp_proc_dst_pid,
		  { "Destination process ID", "udp.proc.dstpid", FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}},

		{ &hf_udp_proc_dst_uname,
		  { "Destination process user name", "udp.proc.dstuname", FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}},

		{ &hf_udp_proc_dst_cmd,
		  { "Destination process name", "udp.proc.dstcmd", FT_STRING, BASE_NONE, NULL, 0x0,
		    "Destination process command name", HFILL}}
	};

	static hf_register_info hf_lite[] = {
		{ &hf_udplite_checksum_coverage_bad,
		{ "Bad Checksum coverage",	"udp.checksum_coverage_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_udplite_checksum_coverage,
		{ "Checksum coverage",	"udp.checksum_coverage", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_udp,
		&ett_udp_checksum,
		&ett_udp_process_info
	};

	proto_udp = proto_register_protocol("User Datagram Protocol",
	    "UDP", "udp");
	register_dissector("udp", dissect_udp, proto_udp);
	proto_udplite = proto_register_protocol("Lightweight User Datagram Protocol",
	    "UDPlite", "udplite");
	proto_register_field_array(proto_udp, hf, array_length(hf));
	proto_register_field_array(proto_udplite, hf_lite, array_length(hf_lite));
	proto_register_subtree_array(ett, array_length(ett));

/* subdissector code */
	udp_dissector_table = register_dissector_table("udp.port",
	    "UDP port", FT_UINT16, BASE_DEC);
	register_heur_dissector_list("udp", &heur_subdissector_list);
	register_heur_dissector_list("udplite", &heur_subdissector_list);

	/* Register configuration preferences */
	udp_module = prefs_register_protocol(proto_udp, NULL);
	prefs_register_bool_preference(udp_module, "summary_in_tree",
	    "Show UDP summary in protocol tree",
	    "Whether the UDP summary line should be shown in the protocol tree",
	    &udp_summary_in_tree);
	prefs_register_bool_preference(udp_module, "try_heuristic_first",
	    "Try heuristic sub-dissectors first",
	    "Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port",
	    &try_heuristic_first);
	prefs_register_bool_preference(udp_module, "check_checksum",
	    "Validate the UDP checksum if possible",
	    "Whether to validate the UDP checksum",
	    &udp_check_checksum);
	prefs_register_bool_preference(udp_module, "process_info",
	    "Collect process flow information",
	    "Collect process flow information from IPFIX",
	    &udp_process_info);

	udplite_module = prefs_register_protocol(proto_udplite, NULL);
	prefs_register_bool_preference(udplite_module, "ignore_checksum_coverage",
	    "Ignore UDPlite checksum coverage",
	    "Ignore an invalid checksum coverage field and continue dissection",
	    &udplite_ignore_checksum_coverage);
	prefs_register_bool_preference(udplite_module, "check_checksum",
	    "Validate the UDPlite checksum if possible",
	    "Whether to validate the UDPlite checksum",
	    &udplite_check_checksum);
}

void
proto_reg_handoff_udp(void)
{
	dissector_handle_t udp_handle;
	dissector_handle_t udplite_handle;

	udp_handle = find_dissector("udp");
	dissector_add_uint("ip.proto", IP_PROTO_UDP, udp_handle);
	udplite_handle = create_dissector_handle(dissect_udplite, proto_udplite);
	dissector_add_uint("ip.proto", IP_PROTO_UDPLITE, udplite_handle);
	data_handle = find_dissector("data");
	udp_tap = register_tap("udp");
	udp_follow_tap = register_tap("udp_follow");
}
