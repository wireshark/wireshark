/* packet-pflog.c
 * Routines for pflog (OpenBSD Firewall Logging) packet disassembly
 *
 * $Id$
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

#include <epan/packet.h>

#include <epan/aftypes.h>
#include <epan/etypes.h>
#include <epan/addr_resolv.h>
#include "packet-ip.h"
#include "packet-pflog.h"

#ifndef offsetof
/* Can't trust stddef.h to be there for us */
# define offsetof(type, member) ((size_t)(&((type *)0)->member))
#endif

#ifndef BPF_WORDALIGN
#define BPF_ALIGNMENT sizeof(long)
#define BPF_WORDALIGN(x) (((x) + (BPF_ALIGNMENT - 1)) & ~(BPF_ALIGNMENT - 1))
#endif

static dissector_handle_t  data_handle, ip_handle, ipv6_handle;

/* header fields */
static int proto_pflog = -1;
static int hf_pflog_length = -1;
static int hf_pflog_af = -1;
static int hf_pflog_action = -1;
static int hf_pflog_reason = -1;
static int hf_pflog_ifname = -1;
static int hf_pflog_ruleset = -1;
static int hf_pflog_rulenr = -1;
static int hf_pflog_subrulenr = -1;
static int hf_pflog_dir = -1;

static gint ett_pflog = -1;

/* old header */
static int proto_old_pflog = -1;
static int hf_old_pflog_af = -1;
static int hf_old_pflog_ifname = -1;
static int hf_old_pflog_rnr = -1;
static int hf_old_pflog_reason = -1;
static int hf_old_pflog_action = -1;
static int hf_old_pflog_dir = -1;

static gint ett_old_pflog = -1;

static const value_string af_vals[] = {
  { BSD_AF_INET,  "IPv4" },
  { BSD_AF_INET6_BSD, "IPv6" },
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

static const value_string old_dir_vals[] = {
  { PF_OLD_IN,  "in" },
  { PF_OLD_OUT, "out" },
  { 0,          NULL }
};

static const value_string dir_vals[] = {
  { PF_INOUT, "inout" },
  { PF_IN,    "in" },
  { PF_OUT,   "out" },
  { 0,        NULL }
};

static void
dissect_pflog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
#define MAX_RULE_STR 128
  struct pfloghdr pflogh;
  static char rulestr[MAX_RULE_STR];
  tvbuff_t *next_tvb;
  proto_tree *pflog_tree;
  proto_item *ti;
  int hdrlen;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PFLOG");

  /* Copy out the pflog header to insure alignment */
  tvb_memcpy(tvb, (guint8 *)&pflogh, 0, sizeof(pflogh));

  /* Byteswap the header now */
  pflogh.rulenr = g_ntohl(pflogh.rulenr);
  pflogh.subrulenr = g_ntohl(pflogh.subrulenr);

  hdrlen = BPF_WORDALIGN(pflogh.length);

  if (pflogh.subrulenr == (guint32) -1)
    g_snprintf(rulestr, sizeof(rulestr), "%u",
             pflogh.rulenr);
  else
    g_snprintf(rulestr, sizeof(rulestr), "%u.%s.%u",
             pflogh.rulenr, pflogh.ruleset, pflogh.subrulenr);

  if (hdrlen < MIN_PFLOG_HDRLEN) {
    if (tree) {
      proto_tree_add_protocol_format(tree, proto_pflog, tvb, 0,
          hdrlen, "PF Log invalid header length (%u)", hdrlen);
    }
    if (check_col(pinfo->cinfo, COL_INFO)) {
      col_prepend_fstr(pinfo->cinfo, COL_INFO, "Invalid header length %u",
          hdrlen);
    }
    return;
  }

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_pflog, tvb, 0,
             hdrlen,
             "PF Log %s %s on %s by rule %s",
             val_to_str(pflogh.af, af_vals, "unknown (%u)"),
             val_to_str(pflogh.action, action_vals, "unknown (%u)"),
             pflogh.ifname,
             rulestr);
    pflog_tree = proto_item_add_subtree(ti, ett_pflog);

    proto_tree_add_uint(pflog_tree, hf_pflog_length, tvb,
             offsetof(struct pfloghdr, length), sizeof(pflogh.length),
             pflogh.length);
    proto_tree_add_uint(pflog_tree, hf_pflog_af, tvb,
             offsetof(struct pfloghdr, af), sizeof(pflogh.af),
             pflogh.af);
    proto_tree_add_uint(pflog_tree, hf_pflog_action, tvb,
             offsetof(struct pfloghdr, action), sizeof(pflogh.action),
             pflogh.action);
    proto_tree_add_uint(pflog_tree, hf_pflog_reason, tvb,
             offsetof(struct pfloghdr, reason), sizeof(pflogh.reason),
             pflogh.reason);
    proto_tree_add_string(pflog_tree, hf_pflog_ifname, tvb,
             offsetof(struct pfloghdr, ifname), sizeof(pflogh.ifname),
             pflogh.ifname);
    proto_tree_add_string(pflog_tree, hf_pflog_ruleset, tvb,
             offsetof(struct pfloghdr, ruleset), sizeof(pflogh.ruleset),
             pflogh.ruleset);
    proto_tree_add_int(pflog_tree, hf_pflog_rulenr, tvb,
             offsetof(struct pfloghdr, rulenr), sizeof(pflogh.rulenr),
             pflogh.rulenr);
    proto_tree_add_int(pflog_tree, hf_pflog_subrulenr, tvb,
             offsetof(struct pfloghdr, subrulenr), sizeof(pflogh.subrulenr),
             pflogh.subrulenr);
    proto_tree_add_uint(pflog_tree, hf_pflog_dir, tvb,
             offsetof(struct pfloghdr, dir), sizeof(pflogh.dir),
             pflogh.dir);
  }

  /* Set the tvbuff for the payload after the header */
  next_tvb = tvb_new_subset_remaining(tvb, hdrlen);

  switch (pflogh.af) {

  case BSD_AF_INET:
    call_dissector(ip_handle, next_tvb, pinfo, tree);
    break;

  case BSD_AF_INET6_BSD:
    call_dissector(ipv6_handle, next_tvb, pinfo, tree);
    break;

  default:
    call_dissector(data_handle, next_tvb, pinfo, tree);
    break;
  }

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "[%s %s/%s] ",
        val_to_str(pflogh.action, action_vals, "unknown (%u)"),
        pflogh.ifname,
        rulestr);
  }
}

void
proto_register_pflog(void)
{
  static hf_register_info hf[] = {
    { &hf_pflog_length,
      { "Header Length", "pflog.length", FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length of Header", HFILL }},
    { &hf_pflog_af,
      { "Address Family", "pflog.af", FT_UINT32, BASE_DEC, VALS(af_vals), 0x0,
        "Protocol (IPv4 vs IPv6)", HFILL }},
    { &hf_pflog_action,
      { "Action", "pflog.action", FT_UINT8, BASE_DEC, VALS(action_vals), 0x0,
        "Action taken by PF on the packet", HFILL }},
    { &hf_pflog_reason,
      { "Reason", "pflog.reason", FT_UINT8, BASE_DEC, VALS(reason_vals), 0x0,
        "Reason for logging the packet", HFILL }},
    { &hf_pflog_ifname,
      { "Interface", "pflog.ifname", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_ruleset,
      { "Ruleset", "pflog.ruleset", FT_STRING, BASE_NONE, NULL, 0x0,
        "Ruleset name in anchor", HFILL }},
    { &hf_pflog_rulenr,
      { "Rule Number", "pflog.rulenr", FT_INT32, BASE_DEC, NULL, 0x0,
        "Last matched firewall main ruleset rule number", HFILL }},
    { &hf_pflog_subrulenr,
      { "Sub Rule Number", "pflog.subrulenr", FT_INT32, BASE_DEC, NULL, 0x0,
        "Last matched firewall anchored ruleset rule number", HFILL }},
    { &hf_pflog_dir,
      { "Direction", "pflog.dir", FT_UINT8, BASE_DEC, VALS(dir_vals), 0x0,
        "Direction of packet in stack (inbound versus outbound)", HFILL }},
  };
  static gint *ett[] = { &ett_pflog };

  proto_pflog = proto_register_protocol("OpenBSD Packet Filter log file",
                                        "PFLOG", "pflog");
  proto_register_field_array(proto_pflog, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pflog(void)
{
  dissector_handle_t pflog_handle;

  ip_handle = find_dissector("ip");
  ipv6_handle = find_dissector("ipv6");
  data_handle = find_dissector("data");

  pflog_handle = create_dissector_handle(dissect_pflog, proto_pflog);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_PFLOG, pflog_handle);
}

static void
dissect_old_pflog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct old_pfloghdr pflogh;
  tvbuff_t *next_tvb;
  proto_tree *pflog_tree;
  proto_item *ti;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PFLOG-OLD");

  /* Copy out the pflog header to insure alignment */
  tvb_memcpy(tvb, (guint8 *)&pflogh, 0, sizeof(pflogh));

  /* Byteswap the header now */
  pflogh.af = g_ntohl(pflogh.af);
  pflogh.rnr = g_ntohs(pflogh.rnr);
  pflogh.reason = g_ntohs(pflogh.reason);
  pflogh.action = g_ntohs(pflogh.action);
  pflogh.dir = g_ntohs(pflogh.dir);

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_old_pflog, tvb, 0,
             OLD_PFLOG_HDRLEN,
             "PF Log (pre 3.4) %s %s on %s by rule %d",
             val_to_str(pflogh.af, af_vals, "unknown (%u)"),
             val_to_str(pflogh.action, action_vals, "unknown (%u)"),
             pflogh.ifname,
             pflogh.rnr);
    pflog_tree = proto_item_add_subtree(ti, ett_pflog);

    proto_tree_add_uint(pflog_tree, hf_old_pflog_af, tvb,
             offsetof(struct old_pfloghdr, af), sizeof(pflogh.af),
             pflogh.af);
    proto_tree_add_int(pflog_tree, hf_old_pflog_rnr, tvb,
             offsetof(struct old_pfloghdr, rnr), sizeof(pflogh.rnr),
             pflogh.rnr);
    proto_tree_add_string(pflog_tree, hf_old_pflog_ifname, tvb,
             offsetof(struct old_pfloghdr, ifname), sizeof(pflogh.ifname),
             pflogh.ifname);
    proto_tree_add_uint(pflog_tree, hf_old_pflog_reason, tvb,
             offsetof(struct old_pfloghdr, reason), sizeof(pflogh.reason),
             pflogh.reason);
    proto_tree_add_uint(pflog_tree, hf_old_pflog_action, tvb,
             offsetof(struct old_pfloghdr, action), sizeof(pflogh.action),
             pflogh.action);
    proto_tree_add_uint(pflog_tree, hf_old_pflog_dir, tvb,
             offsetof(struct old_pfloghdr, dir), sizeof(pflogh.dir),
             pflogh.dir);
  }

  /* Set the tvbuff for the payload after the header */
  next_tvb = tvb_new_subset_remaining(tvb, OLD_PFLOG_HDRLEN);

  switch (pflogh.af) {

  case BSD_AF_INET:
    call_dissector(ip_handle, next_tvb, pinfo, tree);
    break;

  case BSD_AF_INET6_BSD:
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
proto_register_old_pflog(void)
{
  static hf_register_info hf[] = {
    { &hf_old_pflog_af,
      { "Address Family", "pflog.af", FT_UINT32, BASE_DEC, VALS(af_vals), 0x0,
        "Protocol (IPv4 vs IPv6)", HFILL }},
    { &hf_old_pflog_ifname,
      { "Interface", "pflog.ifname", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_old_pflog_rnr,
      { "Rule Number", "pflog.rnr", FT_INT16, BASE_DEC, NULL, 0x0,
        "Last matched firewall rule number", HFILL }},
    { &hf_old_pflog_reason,
      { "Reason", "pflog.reason", FT_UINT16, BASE_DEC, VALS(reason_vals), 0x0,
        "Reason for logging the packet", HFILL }},
    { &hf_old_pflog_action,
      { "Action", "pflog.action", FT_UINT16, BASE_DEC, VALS(action_vals), 0x0,
        "Action taken by PF on the packet", HFILL }},
    { &hf_old_pflog_dir,
      { "Direction", "pflog.dir", FT_UINT16, BASE_DEC, VALS(old_dir_vals), 0x0,
        "Direction of packet in stack (inbound versus outbound)", HFILL }},
  };
  static gint *ett[] = { &ett_old_pflog };

  proto_old_pflog = proto_register_protocol(
          "OpenBSD Packet Filter log file, pre 3.4",
          "PFLOG-OLD", "pflog-old");
  proto_register_field_array(proto_old_pflog, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_old_pflog(void)
{
  dissector_handle_t pflog_handle;

  ip_handle = find_dissector("ip");
  ipv6_handle = find_dissector("ipv6");
  data_handle = find_dissector("data");

  pflog_handle = create_dissector_handle(dissect_old_pflog, proto_old_pflog);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_OLD_PFLOG, pflog_handle);
}

