/* packet-pflog.c
 * Routines for pflog (OpenBSD Firewall Logging) packet disassembly
 *
 * $Id: packet-pflog.c,v 1.3 2002/02/05 00:43:59 guy Exp $
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

  switch (pflogh.af) {

  case BSD_PF_INET:
    capture_ip(pd, offset, len, ld);
    break;

#ifdef notyet
  case BSD_PF_INET6:
    capture_ipv6(pd, offset, len, ld);
    break;
#endif

  default:
    ld->other++;
    break;
  }
}

static const value_string af_vals[] = {
  { BSD_PF_INET,  "IPv4" },
  { BSD_PF_INET6, "IPv6" },
  { 0,            NULL }
};

static const value_string reason_vals[] = {
  { 0, "match" },
  { 1, "bad-offset" },
  { 2, "fragment" },
  { 3, "short" },
  { 4, "normalize" },
  { 5, "memory" },
  { 0, NULL }
};

static const value_string action_vals[] = {
  { PF_PASS,  "passed" },
  { PF_DROP,  "dropped" },
  { PF_SCRUB, "scrubbed" },
  { 0,        NULL }
};

static const value_string dir_vals[] = {
  { PF_IN,  "in" },
  { PF_OUT, "out" },
  { 0,      NULL }
};

static void
dissect_pflog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct pfloghdr pflogh;
  tvbuff_t *next_tvb;
  proto_tree *pflog_tree;
  proto_item *ti;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PFLOG");

  /* Copy out the pflog header to insure alignment */
  tvb_memcpy(tvb, (guint8 *)&pflogh, 0, sizeof(pflogh));

  /* Byteswap the header now */
  NTOHL(pflogh.af);
  NTOHS(pflogh.rnr);
  NTOHS(pflogh.reason);
  NTOHS(pflogh.action);
  NTOHS(pflogh.dir);

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_pflog, tvb, 0,
             PFLOG_HDRLEN,
             "PF Log %s %s on %s by rule %d",
             val_to_str(pflogh.af, af_vals, "unknown (%u)"),
             val_to_str(pflogh.action, action_vals, "unknown (%u)"),
             pflogh.ifname,
             pflogh.rnr);
    pflog_tree = proto_item_add_subtree(ti, ett_pflog);

    proto_tree_add_uint(pflog_tree, hf_pflog_af, tvb,
             offsetof(struct pfloghdr, af), sizeof(pflogh.af),
             pflogh.af);
    proto_tree_add_int(pflog_tree, hf_pflog_rnr, tvb,
             offsetof(struct pfloghdr, rnr), sizeof(pflogh.rnr),
             pflogh.rnr);
    proto_tree_add_string(pflog_tree, hf_pflog_ifname, tvb,
             offsetof(struct pfloghdr, ifname), sizeof(pflogh.ifname),
             pflogh.ifname);
    proto_tree_add_uint(pflog_tree, hf_pflog_reason, tvb,
             offsetof(struct pfloghdr, reason), sizeof(pflogh.reason),
             pflogh.reason);
    proto_tree_add_uint(pflog_tree, hf_pflog_action, tvb,
             offsetof(struct pfloghdr, action), sizeof(pflogh.action),
             pflogh.action);
    proto_tree_add_uint(pflog_tree, hf_pflog_dir, tvb,
             offsetof(struct pfloghdr, dir), sizeof(pflogh.dir),
             pflogh.dir);
  }

  /* Set the tvbuff for the payload after the header */
  next_tvb = tvb_new_subset(tvb, PFLOG_HDRLEN, -1, -1);

  switch (pflogh.af) {

  case BSD_PF_INET:
    call_dissector(ip_handle, next_tvb, pinfo, tree);
    break;

  case BSD_PF_INET6:
    call_dissector(ipv6_handle, next_tvb, pinfo, tree);
    break;

  default:
    call_dissector(data_handle, next_tvb, pinfo, tree);
    break;
  }

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "[%s %s/#%d] ",
        val_to_str(pflogh.action, action_vals, "unknown (%u)"),
        pflogh.ifname,
        pflogh.rnr);
  }
}

void
proto_register_pflog(void)
{
  static hf_register_info hf[] = {
    { &hf_pflog_af,
      { "Address Family", "pflog.af", FT_UINT32, BASE_DEC, VALS(af_vals), 0x0,
        "Protocol (IPv4 vs IPv6)", HFILL }},
    { &hf_pflog_ifname,
      { "Interface", "pflog.ifname", FT_STRING, BASE_NONE, NULL, 0x0,
        "Interface", HFILL }},
    { &hf_pflog_rnr,
      { "Rule Number", "pflog.rnr", FT_INT16, BASE_DEC, NULL, 0x0,
        "Last matched firewall rule number", HFILL }},
    { &hf_pflog_reason,
      { "Reason", "pflog.reason", FT_UINT16, BASE_DEC, VALS(reason_vals), 0x0,
        "Reason for logging the packet", HFILL }},
    { &hf_pflog_action,
      { "Action", "pflog.action", FT_UINT16, BASE_DEC, VALS(action_vals), 0x0,
        "Action taken by PF on the packet", HFILL }},
    { &hf_pflog_dir,
      { "Direction", "pflog.dir", FT_UINT16, BASE_DEC, VALS(dir_vals), 0x0,
        "Direction of packet in stack (inbound versus outbound)", HFILL }},
  };
  static gint *ett[] = { &ett_pflog };

  proto_pflog = proto_register_protocol("OpenBSD Packet Filter log file",
					"PFLOG", "pflog");
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
