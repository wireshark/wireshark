/* packet-udp.c
 * Routines for UDP/UDP-Lite packet disassembly
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

#define NEW_PROTO_TREE_API

#include "config.h"


#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>
#include <epan/prefs.h>
#include <epan/follow.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/proto_data.h>

#include <wsutil/utf8_entities.h>
#include <wsutil/pint.h>

#include "packet-udp.h"

#include <epan/conversation.h>
#include <epan/conversation_table.h>
#include <epan/dissector_filters.h>
#include <epan/decode_as.h>

void proto_register_udp(void);
void proto_reg_handoff_udp(void);

static dissector_handle_t udp_handle;
static dissector_handle_t udplite_handle;

static int udp_tap = -1;
static int udp_follow_tap = -1;

static header_field_info *hfi_udp = NULL;
static header_field_info *hfi_udplite = NULL;

#define UDP_HFI_INIT HFI_INIT(proto_udp)
#define UDPLITE_HFI_INIT HFI_INIT(proto_udplite)

static header_field_info hfi_udp_srcport UDP_HFI_INIT =
{ "Source Port", "udp.srcport", FT_UINT16, BASE_PT_UDP, NULL, 0x0,
  NULL, HFILL };

static header_field_info hfi_udp_dstport UDP_HFI_INIT =
{ "Destination Port", "udp.dstport", FT_UINT16, BASE_PT_UDP, NULL, 0x0,
  NULL, HFILL };

static header_field_info hfi_udp_port UDP_HFI_INIT =
{ "Source or Destination Port", "udp.port", FT_UINT16, BASE_PT_UDP, NULL, 0x0,
  NULL, HFILL };

static header_field_info hfi_udp_stream UDP_HFI_INIT =
 { "Stream index", "udp.stream", FT_UINT32, BASE_DEC, NULL, 0x0,
  NULL, HFILL };

static header_field_info hfi_udp_length UDP_HFI_INIT =
{ "Length", "udp.length", FT_UINT16, BASE_DEC, NULL, 0x0,
  NULL, HFILL };

static header_field_info hfi_udp_checksum UDP_HFI_INIT =
{ "Checksum", "udp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
  "Details at: http://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html", HFILL };

static header_field_info hfi_udp_checksum_calculated UDP_HFI_INIT =
{ "Calculated Checksum", "udp.checksum_calculated", FT_UINT16, BASE_HEX, NULL, 0x0,
  "The expected UDP checksum field as calculated from the UDP packet", HFILL };

static header_field_info hfi_udp_checksum_status UDP_HFI_INIT =
{ "Checksum Status", "udp.checksum.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
  NULL, HFILL };

static header_field_info hfi_udp_proc_src_uid UDP_HFI_INIT =
{ "Source process user ID", "udp.proc.srcuid", FT_UINT32, BASE_DEC, NULL, 0x0,
  NULL, HFILL};

static header_field_info hfi_udp_proc_src_pid UDP_HFI_INIT =
{ "Source process ID", "udp.proc.srcpid", FT_UINT32, BASE_DEC, NULL, 0x0,
  NULL, HFILL};

static header_field_info hfi_udp_proc_src_uname UDP_HFI_INIT =
{ "Source process user name", "udp.proc.srcuname", FT_STRING, BASE_NONE, NULL, 0x0,
  NULL, HFILL};

static header_field_info hfi_udp_proc_src_cmd UDP_HFI_INIT =
{ "Source process name", "udp.proc.srccmd", FT_STRING, BASE_NONE, NULL, 0x0,
  "Source process command name", HFILL};

static header_field_info hfi_udp_proc_dst_uid UDP_HFI_INIT =
{ "Destination process user ID", "udp.proc.dstuid", FT_UINT32, BASE_DEC, NULL, 0x0,
  NULL, HFILL};

static header_field_info hfi_udp_proc_dst_pid UDP_HFI_INIT =
{ "Destination process ID", "udp.proc.dstpid", FT_UINT32, BASE_DEC, NULL, 0x0,
  NULL, HFILL};

static header_field_info hfi_udp_proc_dst_uname UDP_HFI_INIT =
{ "Destination process user name", "udp.proc.dstuname", FT_STRING, BASE_NONE, NULL, 0x0,
  NULL, HFILL};

static header_field_info hfi_udp_proc_dst_cmd UDP_HFI_INIT =
{ "Destination process name", "udp.proc.dstcmd", FT_STRING, BASE_NONE, NULL, 0x0,
  "Destination process command name", HFILL};

static header_field_info hfi_udp_pdu_size UDP_HFI_INIT =
{ "PDU Size", "udp.pdu.size", FT_UINT32, BASE_DEC, NULL, 0x0,
  "The size of this PDU", HFILL };

static header_field_info hfi_udplite_checksum_coverage UDPLITE_HFI_INIT =
{ "Checksum coverage", "udp.checksum_coverage", FT_UINT16, BASE_DEC, NULL, 0x0,
  NULL, HFILL };

static gint ett_udp = -1;
static gint ett_udp_checksum = -1;
static gint ett_udp_process_info = -1;

static expert_field ei_udp_possible_traceroute = EI_INIT;
static expert_field ei_udp_length_bad = EI_INIT;
static expert_field ei_udplite_checksum_coverage_bad = EI_INIT;
static expert_field ei_udp_checksum_zero = EI_INIT;
static expert_field ei_udp_checksum_bad = EI_INIT;
static expert_field ei_udp_length_bad_zero = EI_INIT;

/* Preferences */

/* Place UDP summary in proto tree */
static gboolean udp_summary_in_tree = TRUE;

/* Check UDP checksums */
static gboolean udp_check_checksum = FALSE;

/* Collect IPFIX process flow information */
static gboolean udp_process_info = FALSE;

/* Ignore an invalid checksum coverage field for UDP-Lite */
static gboolean udplite_ignore_checksum_coverage = TRUE;

/* Check UDP-Lite checksums */
static gboolean udplite_check_checksum = FALSE;

static dissector_table_t udp_dissector_table;
static heur_dissector_list_t heur_subdissector_list;
static guint32 udp_stream_count;

/* Determine if there is a sub-dissector and call it.  This has been */
/* separated into a stand alone routine so other protocol dissectors */
/* can call to it, ie. socks */

static gboolean try_heuristic_first = FALSE;

/* Per-packet-info for UDP */
typedef struct
{
    heur_dtbl_entry_t *heur_dtbl_entry;
}   udp_p_info_t;

static void
udp_src_prompt(packet_info *pinfo, gchar *result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "source (%u%s)", pinfo->srcport, UTF8_RIGHTWARDS_ARROW);
}

static gpointer
udp_src_value(packet_info *pinfo)
{
    return GUINT_TO_POINTER(pinfo->srcport);
}

static void
udp_dst_prompt(packet_info *pinfo, gchar *result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "destination (%s%u)", UTF8_RIGHTWARDS_ARROW, pinfo->destport);
}

static gpointer
udp_dst_value(packet_info *pinfo)
{
    return GUINT_TO_POINTER(pinfo->destport);
}

static void
udp_both_prompt(packet_info *pinfo, gchar *result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Both (%u%s%u)", pinfo->srcport, UTF8_LEFT_RIGHT_ARROW, pinfo->destport);
}

/* Conversation and process code originally copied from packet-tcp.c */
static struct udp_analysis *
init_udp_conversation_data(void)
{
  struct udp_analysis *udpd;

  /* Initialize the udp protocol data structure to add to the udp conversation */
  udpd = wmem_new0(wmem_file_scope(), struct udp_analysis);
  /*
  udpd->flow1.username = NULL;
  udpd->flow1.command = NULL;
  udpd->flow2.username = NULL;
  udpd->flow2.command = NULL;
  */

  udpd->stream = udp_stream_count++;

  return udpd;
}

struct udp_analysis *
get_udp_conversation_data(conversation_t *conv, packet_info *pinfo)
{
  int direction;
  struct udp_analysis *udpd=NULL;

  /* Did the caller supply the conversation pointer? */
  if (conv == NULL)
    conv = find_or_create_conversation(pinfo);

  /* Get the data for this conversation */
  udpd=(struct udp_analysis *)conversation_get_proto_data(conv, hfi_udp->id);

  /* If the conversation was just created or it matched a
   * conversation with template options, udpd will not
   * have been initialized. So, initialize
   * a new udpd structure for the conversation.
   */
  if (!udpd) {
    udpd = init_udp_conversation_data();
    conversation_add_proto_data(conv, hfi_udp->id, udpd);
  }

  if (!udpd) {
    return NULL;
  }

  /* check direction and get ua lists */
  direction=cmp_address(&pinfo->src, &pinfo->dst);
  /* if the addresses are equal, match the ports instead */
  if (direction == 0) {
    direction= (pinfo->srcport > pinfo->destport) ? 1 : -1;
  }
  if (direction >= 0) {
    udpd->fwd=&(udpd->flow1);
    udpd->rev=&(udpd->flow2);
  } else {
    udpd->fwd=&(udpd->flow2);
    udpd->rev=&(udpd->flow1);
  }

  return udpd;
}

static const char* udp_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
    if (filter == CONV_FT_SRC_PORT)
        return "udp.srcport";

    if (filter == CONV_FT_DST_PORT)
        return "udp.dstport";

    if (filter == CONV_FT_ANY_PORT)
        return "udp.port";

    if(!conv) {
        return CONV_FILTER_INVALID;
    }

    if (filter == CONV_FT_SRC_ADDRESS) {
        if (conv->src_address.type == AT_IPv4)
            return "ip.src";
        if (conv->src_address.type == AT_IPv6)
            return "ipv6.src";
    }

    if (filter == CONV_FT_DST_ADDRESS) {
        if (conv->dst_address.type == AT_IPv4)
            return "ip.dst";
        if (conv->dst_address.type == AT_IPv6)
            return "ipv6.dst";
    }

    if (filter == CONV_FT_ANY_ADDRESS) {
        if (conv->src_address.type == AT_IPv4)
            return "ip.addr";
        if (conv->src_address.type == AT_IPv6)
            return "ipv6.addr";
    }

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t udp_ct_dissector_info = {&udp_conv_get_filter_type};

static int
udpip_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    const e_udphdr *udphdr=(const e_udphdr *)vip;

    add_conversation_table_data_with_conv_id(hash, &udphdr->ip_src, &udphdr->ip_dst, udphdr->uh_sport, udphdr->uh_dport, (conv_id_t) udphdr->uh_stream, 1, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts, &udp_ct_dissector_info, PT_UDP);

    return 1;
}

static const char* udp_host_get_filter_type(hostlist_talker_t* host, conv_filter_type_e filter)
{

    if (filter == CONV_FT_SRC_PORT)
        return "udp.srcport";

    if (filter == CONV_FT_DST_PORT)
        return "udp.dstport";

    if (filter == CONV_FT_ANY_PORT)
        return "udp.port";

    if(!host) {
        return CONV_FILTER_INVALID;
    }

    if (filter == CONV_FT_SRC_ADDRESS || filter == CONV_FT_DST_ADDRESS || filter == CONV_FT_ANY_ADDRESS) {
        if (host->myaddress.type == AT_IPv4)
            return "ip.src";
        if (host->myaddress.type == AT_IPv6)
            return "ipv6.src";
    }

    return CONV_FILTER_INVALID;
}

static hostlist_dissector_info_t udp_host_dissector_info = {&udp_host_get_filter_type};

static int
udpip_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
    conv_hash_t *hash = (conv_hash_t*) pit;
    const e_udphdr *udphdr=(const e_udphdr *)vip;

    /* Take two "add" passes per packet, adding for each direction, ensures that all
    packets are counted properly (even if address is sending to itself)
    XXX - this could probably be done more efficiently inside hostlist_table */
    add_hostlist_table_data(hash, &udphdr->ip_src, udphdr->uh_sport, TRUE, 1, pinfo->fd->pkt_len, &udp_host_dissector_info, PT_UDP);
    add_hostlist_table_data(hash, &udphdr->ip_dst, udphdr->uh_dport, FALSE, 1, pinfo->fd->pkt_len, &udp_host_dissector_info, PT_UDP);

    return 1;
}

static gboolean
udp_filter_valid(packet_info *pinfo)
{
    return proto_is_frame_protocol(pinfo->layers, "udp");
}

static gchar*
udp_build_filter(packet_info *pinfo)
{
    if( pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4 ) {
        /* UDP over IPv4 */
        return g_strdup_printf("(ip.addr eq %s and ip.addr eq %s) and (udp.port eq %d and udp.port eq %d)",
            address_to_str(pinfo->pool, &pinfo->net_src),
            address_to_str(pinfo->pool, &pinfo->net_dst),
            pinfo->srcport, pinfo->destport );
    }

    if( pinfo->net_src.type == AT_IPv6 && pinfo->net_dst.type == AT_IPv6 ) {
        /* UDP over IPv6 */
        return g_strdup_printf("(ipv6.addr eq %s and ipv6.addr eq %s) and (udp.port eq %d and udp.port eq %d)",
            address_to_str(pinfo->pool, &pinfo->net_src),
            address_to_str(pinfo->pool, &pinfo->net_dst),
            pinfo->srcport, pinfo->destport );
    }

    return NULL;
}

static gchar* udp_follow_conv_filter(packet_info *pinfo, int* stream)
{
    conversation_t *conv;
    struct udp_analysis *udpd;

    if( ((pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4) ||
            (pinfo->net_src.type == AT_IPv6 && pinfo->net_dst.type == AT_IPv6))
          && (conv=find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
              pinfo->srcport, pinfo->destport, 0)) != NULL )
    {
        /* UDP over IPv4/6 */
        udpd=get_udp_conversation_data(conv, pinfo);
        if (udpd == NULL)
            return NULL;

        *stream = udpd->stream;
        return g_strdup_printf("udp.stream eq %d", udpd->stream);
    }

    return NULL;
}

static gchar* udp_follow_index_filter(int stream)
{
    return g_strdup_printf("udp.stream eq %d", stream);
}

static gchar* udp_follow_address_filter(address* src_addr, address* dst_addr, int src_port, int dst_port)
{
    const gchar  *ip_version = src_addr->type == AT_IPv6 ? "v6" : "";
    gchar         src_addr_str[MAX_IP6_STR_LEN];
    gchar         dst_addr_str[MAX_IP6_STR_LEN];

    address_to_str_buf(src_addr, src_addr_str, sizeof(src_addr_str));
    address_to_str_buf(dst_addr, dst_addr_str, sizeof(dst_addr_str));

    return g_strdup_printf("((ip%s.src eq %s and udp.srcport eq %d) and "
                     "(ip%s.dst eq %s and udp.dstport eq %d))"
                     " or "
                     "((ip%s.src eq %s and udp.srcport eq %d) and "
                     "(ip%s.dst eq %s and udp.dstport eq %d))",
                     ip_version, src_addr_str, src_port,
                     ip_version, dst_addr_str, dst_port,
                     ip_version, dst_addr_str, dst_port,
                     ip_version, src_addr_str, src_port);
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

  udpd = (struct udp_analysis *)conversation_get_proto_data(conv, hfi_udp->id);
  if (!udpd) {
    return;
  }

  if ((cmp_address(local_addr, &conv->key_ptr->addr1) == 0) && (local_port == conv->key_ptr->port1)) {
    flow = &udpd->flow1;
  } else if ((cmp_address(remote_addr, &conv->key_ptr->addr1) == 0) && (remote_port == conv->key_ptr->port1)) {
    flow = &udpd->flow2;
  }
  if (!flow || flow->command) {
    return;
  }

  flow->process_uid = uid;
  flow->process_pid = pid;
  flow->username = wmem_strdup(wmem_file_scope(), username);
  flow->command = wmem_strdup(wmem_file_scope(), command);
}


/* Return the current stream count */
guint32 get_udp_stream_count(void)
{
    return udp_stream_count;
}

void
decode_udp_ports(tvbuff_t *tvb, int offset, packet_info *pinfo,
                 proto_tree *tree, int uh_sport, int uh_dport, int uh_ulen)
{
  tvbuff_t *next_tvb;
  int low_port, high_port;
  gint len, reported_len;
  udp_p_info_t *udp_p_info = NULL;
  /* Save curr_layer_num as it might be changed by subdissector */
  guint8 curr_layer_num = pinfo->curr_layer_num;
  heur_dtbl_entry_t *hdtbl_entry;

  len = tvb_captured_length_remaining(tvb, offset);
  reported_len = tvb_reported_length_remaining(tvb, offset);
  if (uh_ulen != -1) {
    /* This is the length from the UDP header; the payload should be cut
       off at that length.  (If our caller passed a value here, they
       are assumed to have checked that it's >= 8, and hence >= offset.)

       XXX - what if it's *greater* than the reported length? */
    if ((uh_ulen - offset) < reported_len)
      reported_len = uh_ulen - offset;
    if (len > reported_len)
      len = reported_len;
  }

  next_tvb = tvb_new_subset(tvb, offset, len, reported_len);

  /* If the user has a "Follow UDP Stream" window loading, pass a pointer
   * to the payload tvb through the tap system. */
  if (have_tap_listener(udp_follow_tap))
    tap_queue_packet(udp_follow_tap, pinfo, next_tvb);

  if (pinfo->fd->flags.visited) {
    udp_p_info = (udp_p_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, hfi_udp->id, pinfo->curr_layer_num);
    if (udp_p_info) {
      call_heur_dissector_direct(udp_p_info->heur_dtbl_entry, next_tvb, pinfo, tree, NULL);
      return;
    }
  }

  /* determine if this packet is part of a conversation and call dissector */
/* for the conversation if available */

  if (try_conversation_dissector(&pinfo->dst, &pinfo->src, PT_UDP,
                                 uh_dport, uh_sport, next_tvb, pinfo, tree, NULL)) {
    return;
  }

  if (try_heuristic_first) {
    /* Do lookup with the heuristic subdissector table */
    if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, NULL)) {
      if (!udp_p_info) {
        udp_p_info = wmem_new0(wmem_file_scope(), udp_p_info_t);
        udp_p_info->heur_dtbl_entry = hdtbl_entry;
        p_add_proto_data(wmem_file_scope(), pinfo, hfi_udp->id, curr_layer_num, udp_p_info);
      }
      return;
    }
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
    low_port  = uh_dport;
    high_port = uh_sport;
  } else {
    low_port  = uh_sport;
    high_port = uh_dport;
  }
  if ((low_port != 0) &&
      dissector_try_uint(udp_dissector_table, low_port, next_tvb, pinfo, tree))
    return;
  if ((high_port != 0) &&
      dissector_try_uint(udp_dissector_table, high_port, next_tvb, pinfo, tree))
    return;

  if (!try_heuristic_first) {
    /* Do lookup with the heuristic subdissector table */
    if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, NULL)) {
      if (!udp_p_info) {
        udp_p_info = wmem_new0(wmem_file_scope(), udp_p_info_t);
        udp_p_info->heur_dtbl_entry = hdtbl_entry;
        p_add_proto_data(wmem_file_scope(), pinfo, hfi_udp->id, curr_layer_num, udp_p_info);
      }
      return;
    }
  }

  call_data_dissector(next_tvb, pinfo, tree);
}

int
udp_dissect_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 guint fixed_len,  gboolean (*heuristic_check)(packet_info *, tvbuff_t *, int, void*),
                 guint (*get_pdu_len)(packet_info *, tvbuff_t *, int, void*),
                 dissector_t dissect_pdu, void* dissector_data)
{
  volatile int offset = 0;
  int offset_before;
  guint captured_length_remaining;
  volatile guint plen;
  guint length;
  tvbuff_t *next_tvb;
  proto_item *item=NULL;
  const char *saved_proto;
  guint8 curr_layer_num;
  wmem_list_frame_t *frame;

  while (tvb_reported_length_remaining(tvb, offset) > 0) {
     /*
      * We use "tvb_ensure_captured_length_remaining()" to make
      * sure there actually *is* data remaining.  The protocol
      * we're handling could conceivably consists of a sequence of
      * fixed-length PDUs, and therefore the "get_pdu_len" routine
      * might not actually fetch anything from the tvbuff, and thus
      * might not cause an exception to be thrown if we've run past
      * the end of the tvbuff.
      *
      * This means we're guaranteed that "captured_length_remaining" is positive.
      */
     captured_length_remaining = tvb_ensure_captured_length_remaining(tvb, offset);

     /*
      * If there is a heuristic function, check it
      */
     if ((heuristic_check != NULL) &&
         ((*heuristic_check)(pinfo, tvb, offset, dissector_data) == FALSE)) {
        return offset;
     }

     /*
      * Get the length of the PDU.
      */
     plen = (*get_pdu_len)(pinfo, tvb, offset, dissector_data);
     if (plen == 0) {
        /*
         * Either protocol has variable length (which isn't supposed by UDP)
         * or packet doesn't belong to protocol
         */
        return offset;
     }

     if (plen < fixed_len) {
       /*
        * Either:
        *
        *  1) the length value extracted from the fixed-length portion
        *     doesn't include the fixed-length portion's length, and
        *     was so large that, when the fixed-length portion's
        *     length was added to it, the total length overflowed;
        *
        *  2) the length value extracted from the fixed-length portion
        *     includes the fixed-length portion's length, and the value
        *     was less than the fixed-length portion's length, i.e. it
        *     was bogus.
        *
        * Report this as a bounds error.
        */
        show_reported_bounds_error(tvb, pinfo, tree);
        return offset;
     }

     curr_layer_num = pinfo->curr_layer_num-1;
     frame = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
     while (frame && (hfi_udp->id != (gint) GPOINTER_TO_UINT(wmem_list_frame_data(frame)))) {
       frame = wmem_list_frame_prev(frame);
       curr_layer_num--;
     }

     /*
      * Display the PDU length as a field
      */
     item=proto_tree_add_uint((proto_tree *)p_get_proto_data(pinfo->pool, pinfo, hfi_udp->id, curr_layer_num),
                                    &hfi_udp_pdu_size,
                                    tvb, offset, plen, plen);
     PROTO_ITEM_SET_GENERATED(item);

     /*
      * Construct a tvbuff containing the amount of the payload we have
      * available.  Make its reported length the amount of data in the PDU.
      */
     length = captured_length_remaining;
     if (length > plen)
       length = plen;
     next_tvb = tvb_new_subset(tvb, offset, length, plen);

     /*
      * Dissect the PDU.
      *
      * If it gets an error that means there's no point in
      * dissecting any more PDUs, rethrow the exception in
      * question.
      *
      * If it gets any other error, report it and continue, as that
      * means that PDU got an error, but that doesn't mean we should
      * stop dissecting PDUs within this frame or chunk of reassembled
      * data.
      */
     saved_proto = pinfo->current_proto;
     TRY {
       (*dissect_pdu)(next_tvb, pinfo, tree, dissector_data);
     }
     CATCH_NONFATAL_ERRORS {
        /*  Restore the private_data structure in case one of the
         *  called dissectors modified it (and, due to the exception,
         *  was unable to restore it).
         */
       show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);

        /*
         * Restore the saved protocol as well; we do this after
         * show_exception(), so that the "Malformed packet" indication
         * shows the protocol for which dissection failed.
         */
       pinfo->current_proto = saved_proto;
     }
     ENDTRY;

    /*
     * Step to the next PDU.
     * Make sure we don't overflow.
     */
    offset_before = offset;
    offset += plen;
    if (offset <= offset_before)
      break;
  }

  return offset;
}

static gboolean
capture_udp(const guchar *pd _U_, int offset _U_, int len _U_, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
  guint16 src_port, dst_port, low_port, high_port;

  if (!BYTES_ARE_IN_FRAME(offset, len, 4))
    return FALSE;

  capture_dissector_increment_count(cpinfo, hfi_udp->id);

  src_port = pntoh16(&pd[offset]);
  dst_port = pntoh16(&pd[offset+2]);

  if (src_port > dst_port) {
    low_port = dst_port;
    high_port = src_port;
  } else {
    low_port = src_port;
    high_port = dst_port;
  }

  if (low_port != 0 &&
      try_capture_dissector("udp.port", low_port, pd, offset+20, len, cpinfo, pseudo_header))
      return TRUE;

  if (high_port != 0 &&
      try_capture_dissector("udp.port", high_port, pd, offset+20, len, cpinfo, pseudo_header))
      return TRUE;

  /* We've at least identified one type of packet, so this shouldn't be "other" */
  return TRUE;
}

static void
dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 ip_proto)
{
  proto_tree *udp_tree = NULL;
  proto_item *ti, *item, *hidden_item, *calc_item;
  proto_item *src_port_item, *dst_port_item, *len_cov_item;
  guint       len;
  guint       reported_len;
  vec_t       cksum_vec[4];
  guint32     phdr[2];
  guint16     computed_cksum;
  int         offset = 0;
  e_udphdr   *udph;
  proto_tree *checksum_tree;
  conversation_t *conv = NULL;
  struct udp_analysis *udpd = NULL;
  proto_tree *process_tree;
  gboolean    udp_jumbogram = FALSE;

  udph = wmem_new0(wmem_packet_scope(), e_udphdr);
  udph->uh_sport = tvb_get_ntohs(tvb, offset);
  udph->uh_dport = tvb_get_ntohs(tvb, offset + 2);
  copy_address_shallow(&udph->ip_src, &pinfo->src);
  copy_address_shallow(&udph->ip_dst, &pinfo->dst);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, (ip_proto == IP_PROTO_UDP) ? "UDP" : "UDP-Lite");
  col_clear(pinfo->cinfo, COL_INFO);
  col_append_ports(pinfo->cinfo, COL_INFO, PT_UDP, udph->uh_sport, udph->uh_dport);

  reported_len = tvb_reported_length(tvb);
  len = tvb_captured_length(tvb);

  ti = proto_tree_add_item(tree, (ip_proto == IP_PROTO_UDP) ? hfi_udp : hfi_udplite, tvb, offset, 8, ENC_NA);
  if (udp_summary_in_tree) {
    proto_item_append_text(ti, ", Src Port: %s, Dst Port: %s",
                           port_with_resolution_to_str(wmem_packet_scope(), PT_UDP, udph->uh_sport),
                           port_with_resolution_to_str(wmem_packet_scope(), PT_UDP, udph->uh_dport));
  }
  udp_tree = proto_item_add_subtree(ti, ett_udp);
  p_add_proto_data(pinfo->pool, pinfo, hfi_udp->id, pinfo->curr_layer_num, udp_tree);

  src_port_item = proto_tree_add_item(udp_tree, &hfi_udp_srcport, tvb, offset, 2, ENC_BIG_ENDIAN);
  dst_port_item = proto_tree_add_item(udp_tree, &hfi_udp_dstport, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

  hidden_item = proto_tree_add_item(udp_tree, &hfi_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
  PROTO_ITEM_SET_HIDDEN(hidden_item);
  hidden_item = proto_tree_add_item(udp_tree, &hfi_udp_port, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
  PROTO_ITEM_SET_HIDDEN(hidden_item);

  /* The beginning port number, 32768 + 666 (33434), is from LBL's traceroute.c source code and this code
   * further assumes that 3 attempts are made per hop */
  if ((udph->uh_sport > (32768 + 666)) && (udph->uh_sport <= (32768 + 666 + 30))) {
    expert_add_info_format(pinfo, src_port_item, &ei_udp_possible_traceroute, "Possible traceroute: hop #%u, attempt #%u",
                                 ((udph->uh_sport - 32768 - 666 - 1) / 3) + 1,
                                 ((udph->uh_sport - 32768 - 666 - 1) % 3) + 1);
  }
  if ((udph->uh_dport > (32768 + 666)) && (udph->uh_dport <= (32768 + 666 + 30))) {
    expert_add_info_format(pinfo, dst_port_item, &ei_udp_possible_traceroute, "Possible traceroute: hop #%u, attempt #%u",
                                 ((udph->uh_dport - 32768 - 666 - 1) / 3) + 1,
                                 ((udph->uh_dport - 32768 - 666 - 1) % 3) + 1);
  }

  udph->uh_ulen = udph->uh_sum_cov = tvb_get_ntohs(tvb, offset + 4);
  if (ip_proto == IP_PROTO_UDP) {
    len_cov_item = proto_tree_add_item(udp_tree, &hfi_udp_length, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
    if (udph->uh_ulen == 0 && pinfo->src.type == AT_IPv6) {
      /* RFC 2675 (section 4) - UDP Jumbograms */
      udph->uh_ulen = udph->uh_sum_cov = reported_len;
      udp_jumbogram = TRUE;
    }
    if (udph->uh_ulen < 8) {
      /* Bogus length - it includes the header, so it must be >= 8. */
      proto_item_append_text(len_cov_item, " (bogus, must be >= 8)");
      expert_add_info_format(pinfo, len_cov_item, &ei_udp_length_bad, "Bad length value %u < 8", udph->uh_ulen);
      col_append_fstr(pinfo->cinfo, COL_INFO, " [BAD UDP LENGTH %u < 8]", udph->uh_ulen);
      return;
    }
    if ((udph->uh_ulen > reported_len) && (!pinfo->fragmented) && (!pinfo->flags.in_error_pkt)) {
      /* Bogus length - it goes past the end of the IP payload */
      proto_item_append_text(len_cov_item, " (bogus, payload length %u)", reported_len);
      expert_add_info_format(pinfo, len_cov_item, &ei_udp_length_bad, "Bad length value %u > IP payload length", udph->uh_ulen);
      col_append_fstr(pinfo->cinfo, COL_INFO, " [BAD UDP LENGTH %u > IP PAYLOAD LENGTH]", udph->uh_ulen);
      /*return;*/
    }
    if (udp_jumbogram && (udph->uh_ulen < 65536)) {
      expert_add_info(pinfo, len_cov_item, &ei_udp_length_bad_zero);
    }
  } else {
    len_cov_item = proto_tree_add_item(udp_tree, &hfi_udplite_checksum_coverage, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
    udph->uh_ulen = reported_len;
    if (udph->uh_sum_cov == 0) {
      udph->uh_sum_cov = reported_len;
    }
    item = proto_tree_add_uint(udp_tree, &hfi_udp_length, tvb, offset + 4, 0, udph->uh_ulen);
    PROTO_ITEM_SET_GENERATED(item);
    if ((udph->uh_sum_cov < 8) || (udph->uh_sum_cov > udph->uh_ulen)) {
      /* Bogus coverage - it includes the header, so it must be >= 8, and no larger then the IP payload size. */
      proto_item_append_text(len_cov_item, " (bogus, must be >= 8 and <= %u)", udph->uh_ulen);
      expert_add_info_format(pinfo, len_cov_item, &ei_udplite_checksum_coverage_bad, "Bad checksum coverage length value %u < 8 or > %u",
                             udph->uh_sum_cov, udph->uh_ulen);
      col_append_fstr(pinfo->cinfo, COL_INFO, " [BAD LIGHTWEIGHT UDP CHECKSUM COVERAGE LENGTH %u < 8 or > %u]",
                      udph->uh_sum_cov, udph->uh_ulen);
      if (!udplite_ignore_checksum_coverage) {
        return;
      }
    }
  }

  col_append_str_uint(pinfo->cinfo, COL_INFO, "Len", udph->uh_ulen - 8, " "); /* Payload length */
  if (udp_jumbogram)
    col_append_str(pinfo->cinfo, COL_INFO, " [Jumbogram]");

  udph->uh_sum = tvb_get_ntohs(tvb, offset + 6);
  if (udph->uh_sum == 0) {
    /* No checksum supplied in the packet. */
    if (((ip_proto == IP_PROTO_UDP) && (pinfo->src.type == AT_IPv4)) || pinfo->flags.in_error_pkt) {
      proto_tree_add_checksum(udp_tree, tvb, offset + 6, hfi_udp_checksum.id, hfi_udp_checksum_status.id, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NOT_PRESENT);
    } else {
      item = proto_tree_add_uint_format_value(udp_tree, hfi_udp_checksum.id, tvb, offset + 6, 2, 0, "0 (Illegal)");
      checksum_tree = proto_item_add_subtree(item, ett_udp_checksum);

      expert_add_info(pinfo, item, &ei_udp_checksum_zero);
      col_append_str(pinfo->cinfo, COL_INFO, " [ILLEGAL CHECKSUM (0)]");

      /* XXX - What should this special status be? */
      item = proto_tree_add_uint(checksum_tree, &hfi_udp_checksum_status, tvb,
                                        offset + 6, 0, 4);
      PROTO_ITEM_SET_GENERATED(item);
    }
  } else if (!pinfo->fragmented && (len >= reported_len) &&
             (len >= udph->uh_sum_cov) && (reported_len >= udph->uh_sum_cov) &&
             (udph->uh_sum_cov >= 8)) {
    /* The packet isn't part of a fragmented datagram and isn't
       truncated, so we can checksum it.
       XXX - make a bigger scatter-gather list once we do fragment
       reassembly? */

    if (((ip_proto == IP_PROTO_UDP) && udp_check_checksum) ||
        ((ip_proto == IP_PROTO_UDPLITE) && udplite_check_checksum)) {
      /* Set up the fields of the pseudo-header. */
      SET_CKSUM_VEC_PTR(cksum_vec[0], (const guint8 *)pinfo->src.data, pinfo->src.len);
      SET_CKSUM_VEC_PTR(cksum_vec[1], (const guint8 *)pinfo->dst.data, pinfo->dst.len);
      switch (pinfo->src.type) {

      case AT_IPv4:
        if (ip_proto == IP_PROTO_UDP)
          phdr[0] = g_htonl((ip_proto<<16) | udph->uh_ulen);
        else
          phdr[0] = g_htonl((ip_proto<<16) | reported_len);
        SET_CKSUM_VEC_PTR(cksum_vec[2], (const guint8 *)&phdr, 4);
        break;

      case AT_IPv6:
        if (ip_proto == IP_PROTO_UDP)
          phdr[0] = g_htonl(udph->uh_ulen);
        else
          phdr[0] = g_htonl(reported_len);
        phdr[1] = g_htonl(ip_proto);
        SET_CKSUM_VEC_PTR(cksum_vec[2], (const guint8 *)&phdr, 8);
        break;

      default:
        /* UDP runs only atop IPv4 and IPv6.... */
        DISSECTOR_ASSERT_NOT_REACHED();
        break;
      }
      SET_CKSUM_VEC_TVB(cksum_vec[3], tvb, offset, udph->uh_sum_cov);
      computed_cksum = in_cksum(&cksum_vec[0], 4);

      item = proto_tree_add_checksum(udp_tree, tvb, offset+6, hfi_udp_checksum.id, hfi_udp_checksum_status.id, &ei_udp_checksum_bad, pinfo, computed_cksum,
                                      ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
      checksum_tree = proto_item_add_subtree(item, ett_udp_checksum);

      if (computed_cksum != 0) {
         proto_item_append_text(item, "(maybe caused by \"UDP checksum offload\"?)");
         col_append_str(pinfo->cinfo, COL_INFO, " [UDP CHECKSUM INCORRECT]");
         calc_item = proto_tree_add_uint(checksum_tree, &hfi_udp_checksum_calculated,
                                   tvb, offset + 6, 2, in_cksum_shouldbe(udph->uh_sum, computed_cksum));
      } else {
         calc_item = proto_tree_add_uint(checksum_tree, &hfi_udp_checksum_calculated,
                                   tvb, offset + 6, 2, udph->uh_sum);
      }
      PROTO_ITEM_SET_GENERATED(calc_item);

    } else {
      proto_tree_add_checksum(udp_tree, tvb, offset + 6, hfi_udp_checksum.id, hfi_udp_checksum_status.id, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    }
  } else {
    proto_tree_add_checksum(udp_tree, tvb, offset + 6, hfi_udp_checksum.id, hfi_udp_checksum_status.id, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
  }

  /* Skip over header */
  offset += 8;

  pinfo->ptype = PT_UDP;
  pinfo->srcport = udph->uh_sport;
  pinfo->destport = udph->uh_dport;

  /* find(or create if needed) the conversation for this udp session */
  conv = find_or_create_conversation(pinfo);
  udpd = get_udp_conversation_data(conv, pinfo);
  if (udpd) {
    item = proto_tree_add_uint(udp_tree, &hfi_udp_stream, tvb, offset, 0, udpd->stream);
    PROTO_ITEM_SET_GENERATED(item);

    /* Copy the stream index into the header as well to make it available
    * to tap listeners.
    */
    udph->uh_stream = udpd->stream;
  }

  tap_queue_packet(udp_tap, pinfo, udph);

  if (udpd && ((udpd->fwd && udpd->fwd->command) || (udpd->rev && udpd->rev->command))) {
    process_tree = proto_tree_add_subtree(udp_tree, tvb, offset, 0, ett_udp_process_info, &ti, "Process Information");
    PROTO_ITEM_SET_GENERATED(ti);
    if (udpd->fwd && udpd->fwd->command) {
      proto_tree_add_uint_format_value(process_tree, hfi_udp_proc_dst_uid.id, tvb, 0, 0,
              udpd->fwd->process_uid, "%u", udpd->fwd->process_uid);
      proto_tree_add_uint_format_value(process_tree, hfi_udp_proc_dst_pid.id, tvb, 0, 0,
              udpd->fwd->process_pid, "%u", udpd->fwd->process_pid);
      proto_tree_add_string_format_value(process_tree, hfi_udp_proc_dst_uname.id, tvb, 0, 0,
              udpd->fwd->username, "%s", udpd->fwd->username);
      proto_tree_add_string_format_value(process_tree, hfi_udp_proc_dst_cmd.id, tvb, 0, 0,
              udpd->fwd->command, "%s", udpd->fwd->command);
    }
    if (udpd->rev->command) {
      proto_tree_add_uint_format_value(process_tree, hfi_udp_proc_src_uid.id, tvb, 0, 0,
              udpd->rev->process_uid, "%u", udpd->rev->process_uid);
      proto_tree_add_uint_format_value(process_tree, hfi_udp_proc_src_pid.id, tvb, 0, 0,
              udpd->rev->process_pid, "%u", udpd->rev->process_pid);
      proto_tree_add_string_format_value(process_tree, hfi_udp_proc_src_uname.id, tvb, 0, 0,
              udpd->rev->username, "%s", udpd->rev->username);
      proto_tree_add_string_format_value(process_tree, hfi_udp_proc_src_cmd.id, tvb, 0, 0,
              udpd->rev->command, "%s", udpd->rev->command);
    }
  }

  if (udph->uh_ulen == 8) {
    /* Empty UDP payload, nothing left to do. */
    return;
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
  if (!pinfo->flags.in_error_pkt || (tvb_captured_length_remaining(tvb, offset) > 0))
    decode_udp_ports(tvb, offset, pinfo, tree, udph->uh_sport, udph->uh_dport, udph->uh_ulen);
}

static int
dissect_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect(tvb, pinfo, tree, IP_PROTO_UDP);
  return tvb_captured_length(tvb);
}

static int
dissect_udplite(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect(tvb, pinfo, tree, IP_PROTO_UDPLITE);
  return tvb_captured_length(tvb);
}

static void
udp_init(void)
{
  udp_stream_count = 0;
}

void
proto_register_udp(void)
{
  module_t *udp_module;
  module_t *udplite_module;
  expert_module_t* expert_udp;

#ifndef HAVE_HFI_SECTION_INIT
  static header_field_info *hfi[] = {
    &hfi_udp_srcport,
    &hfi_udp_dstport,
    &hfi_udp_port,
    &hfi_udp_stream,
    &hfi_udp_length,
    &hfi_udp_checksum,
    &hfi_udp_checksum_calculated,
    &hfi_udp_checksum_status,
    &hfi_udp_proc_src_uid,
    &hfi_udp_proc_src_pid,
    &hfi_udp_proc_src_uname,
    &hfi_udp_proc_src_cmd,
    &hfi_udp_proc_dst_uid,
    &hfi_udp_proc_dst_pid,
    &hfi_udp_proc_dst_uname,
    &hfi_udp_proc_dst_cmd,
    &hfi_udp_pdu_size,
  };

  static header_field_info *hfi_lite[] = {
    &hfi_udplite_checksum_coverage,
  };
#endif

  static gint *ett[] = {
    &ett_udp,
    &ett_udp_checksum,
    &ett_udp_process_info
  };

  static ei_register_info ei[] = {
    { &ei_udp_possible_traceroute, { "udp.possible_traceroute", PI_SEQUENCE, PI_CHAT, "Possible traceroute", EXPFILL }},
    { &ei_udp_length_bad, { "udp.length.bad", PI_MALFORMED, PI_ERROR, "Bad length value", EXPFILL }},
    { &ei_udplite_checksum_coverage_bad, { "udplite.checksum_coverage.bad", PI_MALFORMED, PI_ERROR, "Bad checksum coverage length value", EXPFILL }},
    { &ei_udp_checksum_zero, { "udp.checksum.zero", PI_CHECKSUM, PI_ERROR, "Illegal Checksum value (0)", EXPFILL }},
    { &ei_udp_checksum_bad, { "udp.checksum.bad", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
    { &ei_udp_length_bad_zero, { "udp.length.bad_zero", PI_PROTOCOL, PI_WARN, "Length is zero but payload < 65536", EXPFILL }},
  };

  static build_valid_func udp_da_src_values[1] = {udp_src_value};
  static build_valid_func udp_da_dst_values[1] = {udp_dst_value};
  static build_valid_func udp_da_both_values[2] = {udp_src_value, udp_dst_value};
  static decode_as_value_t udp_da_values[3] = {{udp_src_prompt, 1, udp_da_src_values}, {udp_dst_prompt, 1, udp_da_dst_values}, {udp_both_prompt, 2, udp_da_both_values}};
  static decode_as_t udp_da = {"udp", "Transport", "udp.port", 3, 2, udp_da_values, "UDP", "port(s) as",
                               decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

  int proto_udp, proto_udplite;

  proto_udp = proto_register_protocol("User Datagram Protocol",
                                      "UDP", "udp");
  hfi_udp = proto_registrar_get_nth(proto_udp);
  udp_handle = register_dissector("udp", dissect_udp, proto_udp);
  expert_udp = expert_register_protocol(proto_udp);
  proto_register_fields(proto_udp, hfi, array_length(hfi));

  proto_udplite = proto_register_protocol("Lightweight User Datagram Protocol",
                                          "UDP-Lite", "udplite");
  udplite_handle = create_dissector_handle(dissect_udplite, proto_udplite);
  hfi_udplite = proto_registrar_get_nth(proto_udplite);
  proto_register_fields(proto_udplite, hfi_lite, array_length(hfi_lite));

  proto_register_subtree_array(ett, array_length(ett));
  expert_register_field_array(expert_udp, ei, array_length(ei));

/* subdissector code */
  udp_dissector_table = register_dissector_table("udp.port",
                                                 "UDP port", proto_udp, FT_UINT16, BASE_DEC);
  heur_subdissector_list = register_heur_dissector_list("udp", proto_udp);

  register_capture_dissector_table("udp.port", "UDP");

  /* Register configuration preferences */
  udp_module = prefs_register_protocol(proto_udp, NULL);
  prefs_register_bool_preference(udp_module, "summary_in_tree",
                                 "Show UDP summary in protocol tree",
                                 "Whether the UDP summary line should be shown in the protocol tree",
                                 &udp_summary_in_tree);
  prefs_register_bool_preference(udp_module, "try_heuristic_first",
                                 "Try heuristic sub-dissectors first",
                                 "Try to decode a packet using an heuristic sub-dissector"
                                  " before using a sub-dissector registered to a specific port",
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
                                 "Ignore UDP-Lite checksum coverage",
                                 "Ignore an invalid checksum coverage field and continue dissection",
                                 &udplite_ignore_checksum_coverage);
  prefs_register_bool_preference(udplite_module, "check_checksum",
                                 "Validate the UDP-Lite checksum if possible",
                                 "Whether to validate the UDP-Lite checksum",
                                 &udplite_check_checksum);

  register_decode_as(&udp_da);
  register_conversation_table(proto_udp, FALSE, udpip_conversation_packet, udpip_hostlist_packet);
  register_conversation_filter("udp", "UDP", udp_filter_valid, udp_build_filter);
  register_follow_stream(proto_udp, "udp_follow", udp_follow_conv_filter, udp_follow_index_filter, udp_follow_address_filter,
                         udp_port_to_display, follow_tvb_tap_listener);

  register_init_routine(udp_init);

}

void
proto_reg_handoff_udp(void)
{
  dissector_add_uint("ip.proto", IP_PROTO_UDP, udp_handle);
  dissector_add_uint("ip.proto", IP_PROTO_UDPLITE, udplite_handle);

  register_capture_dissector("ip.proto", IP_PROTO_UDP, capture_udp, hfi_udp->id);
  register_capture_dissector("ip.proto", IP_PROTO_UDPLITE, capture_udp, hfi_udplite->id);
  register_capture_dissector("ipv6.nxt", IP_PROTO_UDP, capture_udp, hfi_udp->id);
  register_capture_dissector("ipv6.nxt", IP_PROTO_UDPLITE, capture_udp, hfi_udplite->id);

  udp_tap = register_tap("udp");
  udp_follow_tap = register_tap("udp_follow");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
