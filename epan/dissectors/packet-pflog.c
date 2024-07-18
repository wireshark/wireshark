/* packet-pflog.c
 * Routines for pflog (Firewall Logging) packet disassembly
 *
 * Copyright 2001 Mike Frantzen
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-1-Clause
 */

/*
 * Specifications:
 *
 * OpenBSD PF log:
 *
 *	https://cvsweb.openbsd.org/src/sys/net/if_pflog.c
 *	https://cvsweb.openbsd.org/src/sys/net/if_pflog.h
 *	https://cvsweb.openbsd.org/src/sys/net/pfvar.h
 *
 * FreeBSD PF log:
 *
 *	https://cgit.freebsd.org/src/tree/sys/net/if_pflog.h
 *	https://cgit.freebsd.org/src/tree/sys/netpfil/pf/if_pflog.c
 *	https://cgit.freebsd.org/src/tree/sys/netpfil/pf/pf.h
 *
 * NetBSD PF log:
 *
 *	http://cvsweb.netbsd.org/bsdweb.cgi/src/sys/dist/pf/net/if_pflog.c
 *	http://cvsweb.netbsd.org/bsdweb.cgi/src/sys/dist/pf/net/if_pflog.h
 *	http://cvsweb.netbsd.org/bsdweb.cgi/src/sys/dist/pf/net/pfvar.h
 *
 * DragonFly BSD PF log:
 *
 *	https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/net/pf/if_pflog.c
 *	https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/net/pf/if_pflog.h
 *	https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/net/pf/pfvar.h
 *
 * macOS/Darwin PF log:
 *
 *	https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_pflog.c
 *	https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_pflog.h
 *	https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pfvar.h
 */
#include "config.h"

#include <epan/packet.h>

#include <epan/aftypes.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include <wsutil/ws_roundup.h>

void proto_register_pflog(void);
void proto_reg_handoff_pflog(void);
void proto_register_old_pflog(void);
void proto_reg_handoff_old_pflog(void);

static dissector_handle_t old_pflog_handle;
static dissector_handle_t pflog_handle;
static dissector_handle_t  ip_handle, ipv6_handle;

/* header fields */
static int proto_pflog;
static int hf_pflog_length;
static int hf_pflog_af;
static int hf_pflog_action;
static int hf_pflog_reason;
static int hf_pflog_ifname;
static int hf_pflog_ruleset;
static int hf_pflog_rulenr;
static int hf_pflog_subrulenr;
static int hf_pflog_uid;
static int hf_pflog_pid;
static int hf_pflog_rule_uid;
static int hf_pflog_rule_pid;
static int hf_pflog_dir;
static int hf_pflog_rewritten;
static int hf_pflog_pad;
static int hf_pflog_saddr_ipv4;
static int hf_pflog_daddr_ipv4;
static int hf_pflog_saddr_ipv6;
static int hf_pflog_daddr_ipv6;
static int hf_pflog_saddr;
static int hf_pflog_daddr;
static int hf_pflog_sport;
static int hf_pflog_dport;
static int ett_pflog;

static expert_field ei_pflog_invalid_header_length;

/* old header */
static int proto_old_pflog;
static int hf_old_pflog_af;
static int hf_old_pflog_ifname;
static int hf_old_pflog_rnr;
static int hf_old_pflog_reason;
static int hf_old_pflog_action;
static int hf_old_pflog_dir;

static int ett_old_pflog;

/*
 * Because ENC_HOST_ENDIAN is either equal to ENC_BIG_ENDIAN or
 * ENC_LITTLE_ENDIAN, it will be confusing if we use ENC_ values
 * directly, as, if the current setting is "Host-endian", it'll
 * look like "Big-endian" on big-endian machines and like
 * "Little-endian" on little-endian machines, and will display
 * as such if you open up the preferences.
 */
#define ID_HOST_ENDIAN   0
#define ID_BIG_ENDIAN    1
#define ID_LITTLE_ENDIAN 2

static int id_endian = ID_HOST_ENDIAN;
static const enum_val_t id_endian_vals[] = {
	{ "host", "Host-endian", ID_HOST_ENDIAN },
	{ "big", "Big-endian", ID_BIG_ENDIAN },
	{ "little", "Little-endian", ID_LITTLE_ENDIAN },
	{ NULL, NULL, 0 }
};

/*
 * Length as of OpenBSD 3.4, not including padding.
 */
#define LEN_PFLOG_OPENBSD_3_4 45

/*
 * Length as of OpenBSD 3.8, not including padding.
 *
 * Also the current length on DragonFly BSD, NetBSD, and Darwin;
 * those all have the same log message header.
 */
#define LEN_PFLOG_OPENBSD_3_8 61

/*
 * Length as of OpenBSD 4.9; there are 2 internal pad bytes, but no
 * padding at the end.
 */
#define LEN_PFLOG_OPENBSD_4_9 100

static const value_string pflog_af_vals[] = {
  { BSD_AF_INET, "IPv4" },
  { BSD_AF_INET6_BSD, "IPv6" },
  { BSD_AF_INET6_FREEBSD, "IPv6" },
  { BSD_AF_INET6_DARWIN, "IPv6" },
  { 0, NULL }
};

/*
 * Reason values.
 *
 * Past 14, these differ for different OSes.
 */
static const value_string pflog_reason_vals[] = {
  { 0, "match" },
  { 1, "bad-offset" },
  { 2, "fragment" },
  { 3, "short" },
  { 4, "normalize" },
  { 5, "memory" },
  { 6, "timestamp" },
  { 7, "congestion" },
  { 8, "ip-option" },
  { 9, "proto-cksum" },
  { 10, "state-mismatch" },
  { 11, "state-ins-fail" },
  { 12, "max-states" },
  { 13, "srcnode-limit" },
  { 14, "syn-proxy" },
#if defined(__FreeBSD__)
  { 15, "map-failed" },
#elif defined(__NetBSD__)
  { 15, "state-locked" },
#elif defined(__OpenBSD__)
  { 15, "translate" },
  { 16, "no-route" },
#elif defined(__APPLE__)
  { 15, "dummynet" },
#endif
  { 0, NULL }
};

/*
 * Action values.
 *
 * Past 10, these differ for different OSes.
 */
#define PF_PASS          0
#define PF_DROP          1
#define PF_SCRUB         2
#define PF_NOSCRUB       3
#define PF_NAT           4
#define PF_NONAT         5
#define PF_BINAT         6
#define PF_NOBINAT       7
#define PF_RDR           8
#define PF_NORDR         9
#define PF_SYNPROXY_DROP 10
#if defined(__FreeBSD__)
#define PF_DEFER         11
#elif defined(__OpenBSD__)
#define PF_DEFER         11
#define PF_MATCH         12
#define PF_DIVERT        13
#define PF_RT            14
#define PF_AFRT          15
#elif defined(__APPLE__)
#define PF_DUMMYNET      11
#define PF_NODUMMYNET    12
#define PF_NAT64         13
#define PF_NONAT64       14
#endif

static const value_string pflog_action_vals[] = {
  { PF_PASS,          "pass" },
  { PF_DROP,          "block" },
  { PF_SCRUB,         "scrub" },
  { PF_NAT,           "nat" },
  { PF_NONAT,         "nonat" },
  { PF_BINAT,         "binat" },
  { PF_NOBINAT,       "nobinat" },
  { PF_RDR,           "rdr" },
  { PF_NORDR,         "nordr" },
  { PF_SYNPROXY_DROP, "synproxy-drop" },
#if defined(__FreeBSD__)
  { PF_DEFER,         "defer" },
#elif defined(__OpenBSD__)
  { PF_DEFER,         "defer" },
  { PF_MATCH,         "match" },
  { PF_DIVERT,        "divert" },
  { PF_RT,            "rt" },
  { PF_AFRT,          "afrt" },
#elif defined(__APPLE__)
  { PF_DUMMYNET,      "dummynet" },
  { PF_NODUMMYNET,    "nodummynet" },
  { PF_NAT64,         "nat64" },
  { PF_NONAT64,       "nonat64" },
#endif
  { 0,                NULL }
};

/* Directions */
#define PF_OLD_IN  0
#define PF_OLD_OUT 1

#define PF_INOUT 0
#define PF_IN    1
#define PF_OUT   2
#define PF_FWD   3  /* for now, 3 is only used by OpenBSD */

static const value_string pflog_old_dir_vals[] = {
  { PF_OLD_IN,  "in" },
  { PF_OLD_OUT, "out" },
  { 0,          NULL }
};

static const value_string pflog_dir_vals[] = {
  { PF_INOUT, "inout" },
  { PF_IN,    "in" },
  { PF_OUT,   "out" },
  { PF_FWD,   "fwd" },
  { 0,        NULL }
};

static int
dissect_pflog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  tvbuff_t *next_tvb;
  proto_tree *pflog_tree;
  proto_item *ti = NULL, *ti_len;
  uint32_t length, padded_length;
  uint32_t af, action;
  const uint8_t *ifname;
  int32_t rulenr;
  int offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PFLOG");

  ti = proto_tree_add_item(tree, proto_pflog, tvb, offset, -1, ENC_NA);
  pflog_tree = proto_item_add_subtree(ti, ett_pflog);

  ti_len = proto_tree_add_item_ret_uint(pflog_tree, hf_pflog_length, tvb, offset, 1, ENC_BIG_ENDIAN, &length);
  if(length < LEN_PFLOG_OPENBSD_3_4)
  {
    expert_add_info_format(pinfo, ti_len, &ei_pflog_invalid_header_length, "Invalid header length %u", length);
  }

  padded_length = WS_ROUNDUP_4(length);

  offset += 1;

  proto_tree_add_item_ret_uint(pflog_tree, hf_pflog_af, tvb, offset, 1, ENC_BIG_ENDIAN, &af);
  offset += 1;

  proto_tree_add_item_ret_uint(pflog_tree, hf_pflog_action, tvb, offset, 1, ENC_BIG_ENDIAN, &action);
  offset += 1;

  proto_tree_add_item(pflog_tree, hf_pflog_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item_ret_string(pflog_tree, hf_pflog_ifname, tvb, offset, 16, ENC_ASCII|ENC_NA, pinfo->pool, &ifname);
  offset += 16;

  proto_tree_add_item(pflog_tree, hf_pflog_ruleset, tvb, offset, 16, ENC_ASCII);
  offset += 16;

  proto_tree_add_item_ret_int(pflog_tree, hf_pflog_rulenr, tvb, offset, 4, ENC_BIG_ENDIAN, &rulenr);
  offset += 4;

  proto_tree_add_item(pflog_tree, hf_pflog_subrulenr, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  if(length >= LEN_PFLOG_OPENBSD_3_8)
  {
    int endian;

    switch (id_endian) {

    case ID_HOST_ENDIAN:
      endian = ENC_HOST_ENDIAN;
      break;

    case ID_BIG_ENDIAN:
      endian = ENC_BIG_ENDIAN;
      break;

    case ID_LITTLE_ENDIAN:
      endian = ENC_LITTLE_ENDIAN;
      break;

    default:
      DISSECTOR_ASSERT_NOT_REACHED();
    }

    proto_tree_add_item(pflog_tree, hf_pflog_uid, tvb, offset, 4, endian);
    offset += 4;

    proto_tree_add_item(pflog_tree, hf_pflog_pid, tvb, offset, 4, endian);
    offset += 4;

    proto_tree_add_item(pflog_tree, hf_pflog_rule_uid, tvb, offset, 4, endian);
    offset += 4;

    proto_tree_add_item(pflog_tree, hf_pflog_rule_pid, tvb, offset, 4, endian);
    offset += 4;
  }
  proto_tree_add_item(pflog_tree, hf_pflog_dir, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  if(length >= LEN_PFLOG_OPENBSD_4_9)
  {
    proto_tree_add_item(pflog_tree, hf_pflog_rewritten, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Internal padding */
    proto_tree_add_item(pflog_tree, hf_pflog_pad, tvb, offset, 2, ENC_NA);
    offset += 2;

    switch (af) {

    case BSD_AF_INET:
      proto_tree_add_item(pflog_tree, hf_pflog_saddr_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 16;

      proto_tree_add_item(pflog_tree, hf_pflog_daddr_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 16;
      break;

    case BSD_AF_INET6_BSD:
      proto_tree_add_item(pflog_tree, hf_pflog_saddr_ipv6, tvb, offset, 16, ENC_NA);
      offset += 16;

      proto_tree_add_item(pflog_tree, hf_pflog_daddr_ipv6, tvb, offset, 16, ENC_NA);
      offset += 16;
      break;

    default:
      proto_tree_add_item(pflog_tree, hf_pflog_saddr, tvb, offset, 16, ENC_NA);
      offset += 16;

      proto_tree_add_item(pflog_tree, hf_pflog_daddr, tvb, offset, 16, ENC_NA);
      offset += 16;
      break;
    }

    proto_tree_add_item(pflog_tree, hf_pflog_sport, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(pflog_tree, hf_pflog_dport, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
  } else {
    /* End-of-header padding */
    proto_tree_add_item(pflog_tree, hf_pflog_pad, tvb, offset, 3, ENC_NA);
    offset += 3;
  }

  proto_item_set_text(ti, "PF Log %s %s on %s by rule %d",
    val_to_str(af, pflog_af_vals, "unknown (%u)"),
    val_to_str(action, pflog_action_vals, "unknown (%u)"),
    ifname,
    rulenr);
  proto_item_set_len(ti, offset);

  /* Set the tvbuff for the payload after the header */
  next_tvb = tvb_new_subset_remaining(tvb, padded_length);

  switch (af) {

  case BSD_AF_INET:
    call_dissector(ip_handle, next_tvb, pinfo, tree);
    break;

  case BSD_AF_INET6_BSD:
  case BSD_AF_INET6_FREEBSD:
  case BSD_AF_INET6_DARWIN:
    call_dissector(ipv6_handle, next_tvb, pinfo, tree);
    break;

  default:
    call_data_dissector(next_tvb, pinfo, tree);
    break;
  }

  col_prepend_fstr(pinfo->cinfo, COL_INFO, "[%s %s/%d] ",
        val_to_str(action, pflog_action_vals, "unknown (%u)"),
        ifname,
        rulenr);
  return tvb_captured_length(tvb);
}

void
proto_register_pflog(void)
{
  static hf_register_info hf[] = {
    { &hf_pflog_length,
      { "Header Length", "pflog.length", FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length of Header", HFILL }},
    { &hf_pflog_af,
      { "Address Family", "pflog.af", FT_UINT32, BASE_DEC, VALS(pflog_af_vals), 0x0,
        "Protocol (IPv4 vs IPv6)", HFILL }},
    { &hf_pflog_action,
      { "Action", "pflog.action", FT_UINT8, BASE_DEC, VALS(pflog_action_vals), 0x0,
        "Action taken by PF on the packet", HFILL }},
    { &hf_pflog_reason,
      { "Reason", "pflog.reason", FT_UINT8, BASE_DEC, VALS(pflog_reason_vals), 0x0,
        "Reason for logging the packet", HFILL }},
    { &hf_pflog_ifname,
      { "Interface", "pflog.ifname", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_ruleset,
      { "Ruleset", "pflog.ruleset", FT_STRING, BASE_NONE, NULL, 0x0,
        "Ruleset name in anchor", HFILL }},
    /*
     * XXX - these are u_int32_t/uint32_t in struct pfloghdr, but are
     * FT_INT32 here, and at least one capture, from issue #6115, has
     * 0xFFFFFFFF as a sub rule number; that looks suspiciously as
     * if it's -1.
     *
     * At least in OpenBSD, the rule and subrule are unsigned in the
     * kernel, and -1 - which really means 0xFFFFFFFFU - is used if
     * there is no subrule.  Perhaps we should treat that value
     * specially and report it as "None" or something such as that.
     */
    { &hf_pflog_rulenr,
      { "Rule Number", "pflog.rulenr", FT_INT32, BASE_DEC, NULL, 0x0,
        "Last matched firewall main ruleset rule number", HFILL }},
    { &hf_pflog_subrulenr,
      { "Sub Rule Number", "pflog.subrulenr", FT_INT32, BASE_DEC, NULL, 0x0,
        "Last matched firewall anchored ruleset rule number", HFILL }},
    { &hf_pflog_uid,
      { "UID", "pflog.uid", FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_pid,
      { "PID", "pflog.pid", FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_rule_uid,
      { "Rule UID", "pflog.rule_uid", FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_rule_pid,
      { "Rule PID", "pflog.rule_pid", FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_rewritten,
      { "Rewritten", "pflog.rewritten", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_pad,
      { "Padding", "pflog.pad", FT_BYTES, BASE_NONE, NULL, 0x0,
        "Must be Zero", HFILL }},
    { &hf_pflog_saddr_ipv4,
      { "Source Address", "pflog.saddr.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_daddr_ipv4,
      { "Destination Address", "pflog.daddr.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_saddr_ipv6,
      { "Source Address", "pflog.saddr.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_daddr_ipv6,
      { "Destination Address", "pflog.daddr.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_saddr,
      { "Source Address", "pflog.saddr.bytes", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_daddr,
      { "Destination Address", "pflog.daddr.bytes", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_sport,
      { "Source Port", "pflog.sport", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_dport,
      { "Destination Port", "pflog.dport", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_pflog_dir,
      { "Direction", "pflog.dir", FT_UINT8, BASE_DEC, VALS(pflog_dir_vals), 0x0,
        "Direction of packet in stack (inbound versus outbound)", HFILL }},
  };
  static int *ett[] = { &ett_pflog };

  static ei_register_info ei[] = {
     { &ei_pflog_invalid_header_length, { "pflog.invalid_header_length", PI_MALFORMED, PI_ERROR, "Invalid header length ", EXPFILL }},
  };

  expert_module_t* expert_pflog;
  module_t *pflog_module;

  proto_pflog = proto_register_protocol("OpenBSD Packet Filter log file", "PFLOG", "pflog");
  proto_register_field_array(proto_pflog, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_pflog = expert_register_protocol(proto_pflog);
  expert_register_field_array(expert_pflog, ei, array_length(ei));

  pflog_handle = register_dissector("pflog", dissect_pflog, proto_pflog);

  pflog_module = prefs_register_protocol(proto_pflog, NULL);

  prefs_register_enum_preference(pflog_module, "id_endian",
        "Byte order for UID and PID fields",
        "Whether or not UID and PID fields are dissected in host, big, or little endian byte order",
        &id_endian, id_endian_vals, false);
  prefs_register_obsolete_preference(pflog_module, "uid_endian");
}

void
proto_reg_handoff_pflog(void)
{
  ip_handle = find_dissector_add_dependency("ip", proto_pflog);
  ipv6_handle = find_dissector_add_dependency("ipv6", proto_pflog);

  dissector_add_uint("wtap_encap", WTAP_ENCAP_PFLOG, pflog_handle);
}

static int
dissect_old_pflog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  tvbuff_t *next_tvb;
  proto_tree *pflog_tree;
  proto_item *ti;
  uint32_t af;
  const uint8_t *ifname;
  uint16_t rnr, action;
  int offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PFLOG-OLD");

  ti = proto_tree_add_item(tree, proto_old_pflog, tvb, 0, -1, ENC_NA);
  pflog_tree = proto_item_add_subtree(ti, ett_pflog);

  proto_tree_add_item(pflog_tree, hf_old_pflog_af, tvb, offset, 4, ENC_BIG_ENDIAN);

  af = tvb_get_ntohl(tvb, offset);
  offset +=4;

  proto_tree_add_item_ret_string(pflog_tree, hf_old_pflog_ifname, tvb, offset, 16, ENC_ASCII|ENC_NA, pinfo->pool, &ifname);
  offset +=16;

  proto_tree_add_item(pflog_tree, hf_old_pflog_rnr, tvb, offset, 2, ENC_BIG_ENDIAN);
  rnr = tvb_get_ntohs(tvb, offset);
  offset +=2;

  proto_tree_add_item(pflog_tree, hf_old_pflog_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset +=2;

  proto_tree_add_item(pflog_tree, hf_old_pflog_action, tvb, offset, 2, ENC_BIG_ENDIAN);
  action = tvb_get_ntohs(tvb, offset);
  offset +=2;

  proto_tree_add_item(pflog_tree, hf_old_pflog_dir, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset +=2;

  proto_item_set_text(ti, "PF Log (pre 3.4) %s %s on %s by rule %d",
      val_to_str(af, pflog_af_vals, "unknown (%u)"),
      val_to_str(action, pflog_action_vals, "unknown (%u)"),
      ifname,
      rnr);
  proto_item_set_len(ti, offset);

  /* Set the tvbuff for the payload after the header */
  next_tvb = tvb_new_subset_remaining(tvb, offset);

  switch (af) {

  case BSD_AF_INET:
    offset += call_dissector(ip_handle, next_tvb, pinfo, tree);
    break;

  case BSD_AF_INET6_BSD:
    offset += call_dissector(ipv6_handle, next_tvb, pinfo, tree);
    break;

  default:
    offset += call_data_dissector(next_tvb, pinfo, tree);
    break;
  }

  col_prepend_fstr(pinfo->cinfo, COL_INFO, "[%s %s/#%d] ",
        val_to_str(action, pflog_action_vals, "unknown (%u)"),
        ifname,
        rnr);

  return offset;
}

void
proto_register_old_pflog(void)
{
  static hf_register_info hf[] = {
    { &hf_old_pflog_af,
      { "Address Family", "pflog.af", FT_UINT32, BASE_DEC, VALS(pflog_af_vals), 0x0,
        "Protocol (IPv4 vs IPv6)", HFILL }},
    { &hf_old_pflog_ifname,
      { "Interface", "pflog.ifname", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_old_pflog_rnr,
      { "Rule Number", "pflog.rnr", FT_INT16, BASE_DEC, NULL, 0x0,
        "Last matched firewall rule number", HFILL }},
    { &hf_old_pflog_reason,
      { "Reason", "pflog.reason", FT_UINT16, BASE_DEC, VALS(pflog_reason_vals), 0x0,
        "Reason for logging the packet", HFILL }},
    { &hf_old_pflog_action,
      { "Action", "pflog.action", FT_UINT16, BASE_DEC, VALS(pflog_action_vals), 0x0,
        "Action taken by PF on the packet", HFILL }},
    { &hf_old_pflog_dir,
      { "Direction", "pflog.dir", FT_UINT16, BASE_DEC, VALS(pflog_old_dir_vals), 0x0,
        "Direction of packet in stack (inbound versus outbound)", HFILL }},
  };
  static int *ett[] = { &ett_old_pflog };

  proto_old_pflog = proto_register_protocol("OpenBSD Packet Filter log file, pre 3.4", "PFLOG-OLD", "pflog-old");
  proto_register_field_array(proto_old_pflog, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  old_pflog_handle = register_dissector("pflog-old", dissect_old_pflog, proto_old_pflog);
}

void
proto_reg_handoff_old_pflog(void)
{
  dissector_add_uint("wtap_encap", WTAP_ENCAP_OLD_PFLOG, old_pflog_handle);
}
/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
