/* packet-pflog.c
 * Routines for pflog (OpenBSD Firewall Logging) packet disassembly
 *
 * $Id: packet-pflog.c,v 1.2 2002/01/30 23:08:26 guy Exp $
 *
 * Copyright 2001 Mike Frantzen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *      with the distribution.
 *          
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include "etypes.h"
#include <epan/resolv.h>
#include "packet-ip.h"
#include "packet-ipv6.h"
#include "packet-pflog.h"

#ifndef offsetof
/* Can't trust stddef.h to be there for us */
# define offsetof(type, member) ((size_t)(&((type *)0)->member))
#endif

static dissector_handle_t  data_handle, ip_handle, ipv6_handle, pflog_handle;

/* header fields */
static int proto_pflog = -1;
static int hf_pflog_af = -1;
static int hf_pflog_ifname = -1;
static int hf_pflog_rnr = -1;
static int hf_pflog_reason = -1;
static int hf_pflog_action = -1;
static int hf_pflog_dir = -1;

static gint ett_pflog = -1;

static char *pf_reasons[PFRES_MAX+2] = PFRES_NAMES;


void
capture_pflog(const u_char *pd, int offset, int len, packet_counts *ld)
{
  struct pfloghdr pflogh;

  if (!BYTES_ARE_IN_FRAME(offset, len, (int)PFLOG_HDRLEN)) {
    ld->other++;
    return;
  }

  offset += PFLOG_HDRLEN;
  
  /* Copy out the pflog header to insure alignment */
  memcpy(&pflogh, pd, sizeof(pflogh));
  NTOHL(pflogh.af);

  if (pflogh.af == BSD_PF_INET)
    capture_ip(pd, offset, len, ld);
#ifdef notyet
  else if (pflogh.af == BSD_PF_INET6)
    capture_ipv6(pd, offset, len, ld);
#endif
  else
    ld->other++;
}

static void
dissect_pflog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct pfloghdr pflogh;
  tvbuff_t *next_tvb;
  proto_tree *pflog_tree;
  proto_item *ti, *tf;
  char *why;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "pflog");

  /* Copy out the pflog header to insure alignment */
  tvb_memcpy(tvb, (guint8 *)&pflogh, 0, sizeof(pflogh));

  /* Byteswap the header now */
  NTOHL(pflogh.af);
  NTOHS(pflogh.rnr);
  NTOHS(pflogh.reason);
  NTOHS(pflogh.action);
  NTOHS(pflogh.dir);

  why = (pflogh.reason < PFRES_MAX) ? pf_reasons[pflogh.reason] : "unkn";

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_pflog, tvb, 0,
             PFLOG_HDRLEN,
             "PF Log %s %s on %s by rule %d", pflogh.af == BSD_PF_INET ? "IPv4" :
             pflogh.af == BSD_PF_INET6 ? "IPv6" : "unkn",
             pflogh.action == PF_PASS  ? "passed" :
             pflogh.action == PF_DROP  ? "dropped" :
             pflogh.action == PF_SCRUB ? "scrubbed" : "unkn",
             pflogh.ifname,
             pflogh.rnr);
    pflog_tree = proto_item_add_subtree(ti, ett_pflog);

    tf = proto_tree_add_uint_format(pflog_tree, hf_pflog_rnr, tvb,
             offsetof(struct pfloghdr, rnr), sizeof(pflogh.rnr),
             pflogh.rnr, "Rule Number: %d", pflogh.rnr);
    tf = proto_tree_add_string(pflog_tree, hf_pflog_ifname, tvb,
             offsetof(struct pfloghdr, reason), sizeof(pflogh.reason),
             pflogh.ifname);
    tf = proto_tree_add_string(pflog_tree, hf_pflog_reason, tvb,
             offsetof(struct pfloghdr, reason), sizeof(pflogh.reason),
             why);
    tf = proto_tree_add_string(pflog_tree, hf_pflog_action, tvb,
             offsetof(struct pfloghdr, action), sizeof(pflogh.action),
             pflogh.action == PF_PASS  ? "pass" :
             pflogh.action == PF_DROP  ? "drop" :
             pflogh.action == PF_SCRUB ? "scrub" : "unkn");
    tf = proto_tree_add_string(pflog_tree, hf_pflog_dir, tvb,
             offsetof(struct pfloghdr, dir), sizeof(pflogh.dir),
             pflogh.dir == PF_IN ? "in" : "out");
  }

  /* Set the tvbuff for the payload after the header */
  next_tvb = tvb_new_subset(tvb, PFLOG_HDRLEN, -1, -1);

  pinfo->ethertype = (hf_pflog_af == BSD_PF_INET) ? ETHERTYPE_IP : ETHERTYPE_IPv6;
  if (pflogh.af == BSD_PF_INET)
    call_dissector(ip_handle, next_tvb, pinfo, tree);
  else if (pflogh.af == BSD_PF_INET6)
    call_dissector(ipv6_handle, next_tvb, pinfo, tree);
  else
    call_dissector(data_handle, next_tvb, pinfo, tree);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "[%s %s/#%d] ",
        pflogh.action == PF_PASS  ? "passed" :
        pflogh.action == PF_DROP  ? "dropped" :
        pflogh.action == PF_SCRUB ? "scrubbed" : "unkn",
        pflogh.ifname,
        pflogh.rnr);
  }
}

void
proto_register_pflog(void)
{
  static hf_register_info hf[] = {
    { &hf_pflog_af,
      { "Address Family", "pflog.af", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Protocol (IPv4 vs IPv6)", HFILL }},
    { &hf_pflog_ifname,
      { "Interface", "pflog.ifname", FT_STRING, BASE_NONE, NULL, 0x0,
        "Interface", HFILL }},
    { &hf_pflog_rnr,
      { "Rule Number", "pflog.rnr", FT_UINT16, BASE_DEC, NULL, 0x0,
        "Last matched firewall rule number", HFILL }},
    { &hf_pflog_reason,
      { "Reason", "pflog.reason", FT_STRING, BASE_NONE, NULL, 0x0,
        "Reason for logging the packet", HFILL }},
    { &hf_pflog_action,
      { "Action", "pflog.action", FT_STRING, BASE_NONE, NULL, 0x0,
        "Action taken by PF on the packet", HFILL }},
    { &hf_pflog_dir,
      { "Direction", "pflog.dir", FT_STRING, BASE_NONE, NULL, 0x0,
        "Direction of packet in stack (inbound versus outbound)", HFILL }},
  };
  static gint *ett[] = { &ett_pflog };

  proto_pflog = proto_register_protocol("pflog", "pflog", "pflog");
  proto_register_field_array(proto_pflog, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("pflog", dissect_pflog, proto_pflog);
}

void
proto_reg_handoff_pflog(void)
{
  dissector_handle_t pflog_handle;

  pflog_handle = find_dissector("pflog");
  ip_handle = find_dissector("ip");
  ipv6_handle = find_dissector("ipv6");
  data_handle = find_dissector("data");
  dissector_add("wtap_encap", WTAP_ENCAP_PFLOG, pflog_handle);
}
