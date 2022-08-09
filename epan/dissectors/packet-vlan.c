/* packet-vlan.c
 * Routines for VLAN 802.1Q ethernet header disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <wsutil/pint.h>
#include <epan/expert.h>
#include "packet-ieee8023.h"
#include "packet-ipx.h"
#include "packet-llc.h"
#include <epan/etypes.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include <epan/addr_resolv.h>
#include <epan/proto_data.h>

void proto_register_vlan(void);
void proto_reg_handoff_vlan(void);

static unsigned int q_in_q_ethertype = ETHERTYPE_QINQ_OLD;

static gboolean vlan_summary_in_tree = TRUE;

enum version_value {
  IEEE_8021Q_1998,
  IEEE_8021Q_2005,
  IEEE_8021Q_2011
};

static gint vlan_version = (gint)IEEE_8021Q_2011;

enum priority_drop_value {
  Priority_Drop_8P0D,
  Priority_Drop_7P1D,
  Priority_Drop_6P2D,
  Priority_Drop_5P3D,
};

static gint vlan_priority_drop = (gint)Priority_Drop_8P0D;

static dissector_handle_t vlan_handle;
static dissector_handle_t ethertype_handle;

static capture_dissector_handle_t llc_cap_handle;
static capture_dissector_handle_t ipx_cap_handle;

static int proto_vlan;

static int hf_vlan_cfi = -1;
static int hf_vlan_dei = -1;
static int hf_vlan_etype = -1;
static int hf_vlan_id = -1;
static int hf_vlan_id_name = -1;
static int hf_vlan_len = -1;
static int hf_vlan_priority = -1;
static int hf_vlan_priority_5 = -1;
static int hf_vlan_priority_6 = -1;
static int hf_vlan_priority_7 = -1;
static int hf_vlan_priority_old = -1;
static int hf_vlan_trailer = -1;

static gint ett_vlan = -1;

static expert_field ei_vlan_len = EI_INIT;
static expert_field ei_vlan_too_many_tags = EI_INIT;

/* From Table G-2 of IEEE standard 802.1D-2004 */
/* Note that 0 is the default priority, but is above 1 and 2.
 * Priority order from lowest to highest is 1,2,0,3,4,5,6,7 */
static const value_string pri_vals_old[] = {
  { 0, "Best Effort (default)"             },
  { 1, "Background"                        },
  { 2, "Spare"                             },
  { 3, "Excellent Effort"                  },
  { 4, "Controlled Load"                   },
  { 5, "Video, < 100ms latency and jitter" },
  { 6, "Voice, < 10ms latency and jitter"  },
  { 7, "Network Control"                   },
  { 0, NULL                                }
};

/* From Table G-2 of IEEE standard 802.1Q-2005 (and I-2 of 2011 and 2014 revisions) */
/* Note that 0 is still the default, but priority 2 was moved from below 0 to
 * above it. The new order from lowest to highest is 1,0,2,3,4,5,6,7 */
static const value_string pri_vals[] = {
  { 0, "Best Effort (default)"             },
  { 1, "Background"                        },
  { 2, "Excellent Effort"                  },
  { 3, "Critical Applications"             },
  { 4, "Video, < 100ms latency and jitter" },
  { 5, "Voice, < 10ms latency and jitter"  },
  { 6, "Internetwork Control"              },
  { 7, "Network Control"                   },
  { 0, NULL                                }
};

/* From Tables G-2,3 of IEEE standard 802.1Q-2005 (and I-2,3,7 of 2011 and 2014 revisions) */
static const value_string pri_vals_7[] = {
  { 0, "Best Effort (default)"                           },
  { 1, "Background"                                      },
  { 2, "Excellent Effort"                                },
  { 3, "Critical Applications"                           },
  { 4, "Voice, < 10ms latency and jitter, Drop Eligible" },
  { 5, "Voice, < 10ms latency and jitter"                },
  { 6, "Internetwork Control"                            },
  { 7, "Network Control"                                 },
  { 0, NULL                                              }
};

/* From Tables G-2,3 of IEEE standard 802.1Q-2005 (and I-2,3,7 of 2011 and 2015 revisions) */
static const value_string pri_vals_6[] = {
  { 0, "Best Effort (default)"                            },
  { 1, "Background"                                       },
  { 2, "Critical Applications, Drop Eligible"             },
  { 3, "Critical Applications"                            },
  { 4, "Voice, < 10ms latency and jitter, Drop Eligible"  },
  { 5, "Voice, < 10ms latency and jitter"                 },
  { 6, "Internetwork Control"                             },
  { 7, "Network Control"                                  },
  { 0, NULL                                               }
};

/* From Tables G-2,3 of IEEE standard 802.1Q-2005 (and I-2,3,7 of 2011 and 2015 revisions) */
static const value_string pri_vals_5[] = {
  { 0, "Best Effort (default), Drop Eligible"            },
  { 1, "Best Effort (default)"                           },
  { 2, "Critical Applications, Drop Eligible"            },
  { 3, "Critical Applications"                           },
  { 4, "Voice, < 10ms latency and jitter, Drop Eligible" },
  { 5, "Voice, < 10ms latency and jitter"                },
  { 6, "Internetwork Control"                            },
  { 7, "Network Control"                                 },
  { 0, NULL                                              }
};

/* True is non-canonical (i.e., bit-reversed MACs like Token Ring) since usually 0 and canonical. */
static const true_false_string tfs_noncanonical_canonical = { "Non-canonical", "Canonical" };

static const true_false_string tfs_eligible_ineligible = { "Eligible", "Ineligible" };

#define VLAN_MAX_NESTED_TAGS 20

static gboolean
capture_vlan(const guchar *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_ ) {
  guint16 encap_proto;
  if ( !BYTES_ARE_IN_FRAME(offset,len,5) )
    return FALSE;

  encap_proto = pntoh16( &pd[offset+2] );
  if ( encap_proto <= IEEE_802_3_MAX_LEN) {
    if ( pd[offset+4] == 0xff && pd[offset+5] == 0xff ) {
      return call_capture_dissector(ipx_cap_handle, pd,offset+4,len, cpinfo, pseudo_header);
    } else {
      return call_capture_dissector(llc_cap_handle, pd,offset+4,len, cpinfo, pseudo_header);
    }
  }

  return try_capture_dissector("ethertype", encap_proto, pd, offset+4, len, cpinfo, pseudo_header);
}

static void
columns_set_vlan(column_info *cinfo, guint16 tci)
{
  char id_str[16];

  guint32_to_str_buf(tci & 0xFFF, id_str, sizeof(id_str));

  if (vlan_version < IEEE_8021Q_2011) {
    col_add_fstr(cinfo, COL_INFO,
                 "PRI: %d  CFI: %d  ID: %s",
                 (tci >> 13), ((tci >> 12) & 1), id_str);
  } else {
    col_add_fstr(cinfo, COL_INFO,
                 "PRI: %d  DEI: %d  ID: %s",
                 (tci >> 13), ((tci >> 12) & 1), id_str);
  }
  col_add_str(cinfo, COL_8021Q_VLAN_ID, id_str);
}

static int
dissect_vlan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti;
  guint16 tci, vlan_id;
  guint16 encap_proto;
  gboolean is_802_2;
  proto_tree *vlan_tree;
  proto_item *item;
  guint vlan_nested_count;
  int hf1, hf2;

  int * const flags[] = {
      &hf1,
      &hf2,
      &hf_vlan_id,
      NULL
  };

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "VLAN");
  col_clear(pinfo->cinfo, COL_INFO);

  tci = tvb_get_ntohs( tvb, 0 );
  vlan_id = tci & 0xFFF;
  /* Add the VLAN Id if it's the first one*/
  if (pinfo->vlan_id == 0) {
      pinfo->vlan_id = vlan_id;
  }

  columns_set_vlan(pinfo->cinfo, tci);

  vlan_tree = NULL;

  ti = proto_tree_add_item(tree, proto_vlan, tvb, 0, 4, ENC_NA);
  vlan_nested_count = p_get_proto_depth(pinfo, proto_vlan);
  if (++vlan_nested_count > VLAN_MAX_NESTED_TAGS) {
    expert_add_info(pinfo, ti, &ei_vlan_too_many_tags);
    return tvb_captured_length(tvb);
  }
  p_set_proto_depth(pinfo, proto_vlan, vlan_nested_count);

  if (tree) {

    if (vlan_summary_in_tree) {
      if (vlan_version < IEEE_8021Q_2011) {
        proto_item_append_text(ti, ", PRI: %u, CFI: %u, ID: %u",
                (tci >> 13), ((tci >> 12) & 1), vlan_id);
      } else {
        proto_item_append_text(ti, ", PRI: %u, DEI: %u, ID: %u",
                (tci >> 13), ((tci >> 12) & 1), vlan_id);
      }
    }

    vlan_tree = proto_item_add_subtree(ti, ett_vlan);

    if (vlan_version == IEEE_8021Q_1998) {
      hf1 = hf_vlan_priority_old;
      hf2 = hf_vlan_cfi;
    } else {
      switch (vlan_priority_drop) {

        case Priority_Drop_8P0D:
          hf1 = hf_vlan_priority;
          break;

        case Priority_Drop_7P1D:
          hf1 = hf_vlan_priority_7;
          break;

        case Priority_Drop_6P2D:
          hf1 = hf_vlan_priority_6;
          break;

        case Priority_Drop_5P3D:
          hf1 = hf_vlan_priority_5;
          break;
      }
      if (vlan_version == IEEE_8021Q_2005) {
        hf2 = hf_vlan_cfi;
      } else {
        hf2 = hf_vlan_dei;
      }
    }

    proto_tree_add_bitmask_list(vlan_tree, tvb, 0, 2, flags, ENC_BIG_ENDIAN);

    if (gbl_resolv_flags.vlan_name) {
      item = proto_tree_add_string(vlan_tree, hf_vlan_id_name, tvb, 0, 2,
                                   get_vlan_name(pinfo->pool, vlan_id));
      proto_item_set_generated(item);

    }

    /* TODO: If the CFI is set on Ethernet (or FDDI MAC and not source routed,
     * i.e. the RII bit in the source MAC address is 0, then a E-RIF follows.
     * Only true before version 2011 since the CFI was replaced with DEI
     * (Since who needs VLANs that bridge Token Ring and FDDI these days?)  */
  }

  encap_proto = tvb_get_ntohs(tvb, 2);
  if (encap_proto <= IEEE_802_3_MAX_LEN) {
    /* Is there an 802.2 layer? I can tell by looking at the first 2
       bytes after the VLAN header. If they are 0xffff, then what
       follows the VLAN header is an IPX payload, meaning no 802.2.
       (IPX/SPX is they only thing that can be contained inside a
       straight 802.3 packet, so presumably the same applies for
       Ethernet VLAN packets). A non-0xffff value means that there's an
       802.2 layer inside the VLAN layer */
    is_802_2 = TRUE;

    /* Don't throw an exception for this check (even a BoundsError) */
    if (tvb_captured_length_remaining(tvb, 4) >= 2) {
      if (tvb_get_ntohs(tvb, 4) == 0xffff) {
        is_802_2 = FALSE;
      }
    }

    dissect_802_3(encap_proto, is_802_2, tvb, 4, pinfo, tree, vlan_tree,
                  hf_vlan_len, hf_vlan_trailer, &ei_vlan_len, 0);
  } else {
    ethertype_data_t ethertype_data;

    proto_tree_add_uint(vlan_tree, hf_vlan_etype, tvb, 2, 2, encap_proto);

    ethertype_data.etype = encap_proto;
    ethertype_data.payload_offset = 4;
    ethertype_data.fh_tree = vlan_tree;
    ethertype_data.trailer_id = hf_vlan_trailer;
    ethertype_data.fcs_len = 0;

    call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
  }
  return tvb_captured_length(tvb);
}

void
proto_register_vlan(void)
{
  static hf_register_info hf[] = {
    { &hf_vlan_priority_old,
      { "Priority", "vlan.priority",
        FT_UINT16, BASE_DEC, VALS(pri_vals_old), 0xE000,
        "Descriptions are recommendations from IEEE standard 802.1D-2004", HFILL }
    },
    { &hf_vlan_priority,
      { "Priority", "vlan.priority",
        FT_UINT16, BASE_DEC, VALS(pri_vals), 0xE000,
        "Descriptions are recommendations from IEEE standard 802.1Q-2014", HFILL }
    },
    { &hf_vlan_priority_7,
      { "Priority", "vlan.priority",
        FT_UINT16, BASE_DEC, VALS(pri_vals_7), 0xE000,
        "Descriptions are recommendations from IEEE standard 802.1Q-2014", HFILL }
    },
    { &hf_vlan_priority_6,
      { "Priority", "vlan.priority",
        FT_UINT16, BASE_DEC, VALS(pri_vals_6), 0xE000,
        "Descriptions are recommendations from IEEE standard 802.1Q-2014", HFILL }
    },
    { &hf_vlan_priority_5,
      { "Priority", "vlan.priority",
        FT_UINT16, BASE_DEC, VALS(pri_vals_5), 0xE000,
        "Descriptions are recommendations from IEEE standard 802.1Q-2014", HFILL }
      },
    { &hf_vlan_cfi,
      { "CFI", "vlan.cfi",
        FT_BOOLEAN, 16, TFS(&tfs_noncanonical_canonical), 0x1000,
        "Canonical Format Identifier", HFILL }
    },
    { &hf_vlan_dei,
      { "DEI", "vlan.dei",
        FT_BOOLEAN, 16, TFS(&tfs_eligible_ineligible), 0x1000,
        "Drop Eligible Indicator", HFILL }
    },
    { &hf_vlan_id,
      { "ID", "vlan.id",
        FT_UINT16, BASE_DEC, NULL, 0x0FFF,
        "VLAN ID", HFILL }
    },
    { &hf_vlan_id_name,
      { "Name", "vlan.id_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "VLAN ID Name", HFILL }
    },
    { &hf_vlan_etype,
      { "Type", "vlan.etype",
        FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
        "Ethertype", HFILL }
    },
    { &hf_vlan_len,
      { "Length", "vlan.len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_vlan_trailer,
      { "Trailer", "vlan.trailer",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "VLAN Trailer", HFILL }
    },
  };

  static gint *ett[] = {
    &ett_vlan
  };

  static ei_register_info ei[] = {
     { &ei_vlan_len, { "vlan.len.past_end", PI_MALFORMED, PI_ERROR, "Length field value goes past the end of the payload", EXPFILL }},
     { &ei_vlan_too_many_tags, { "vlan.too_many_tags", PI_UNDECODED, PI_WARN, "Too many nested VLAN tags", EXPFILL }},
  };

  static const enum_val_t version_vals[] = {
    {"1998", "IEEE 802.1Q-1998", IEEE_8021Q_1998},
    {"2005", "IEEE 802.1Q-2005", IEEE_8021Q_2005},
    {"2011", "IEEE 802.1Q-2011", IEEE_8021Q_2011},
    {NULL, NULL, -1}
  };

  static const enum_val_t priority_drop_vals[] = {
    {"8p0d", "8 Priorities, 0 Drop Eligible", Priority_Drop_8P0D},
    {"7p1d", "7 Priorities, 1 Drop Eligible", Priority_Drop_7P1D},
    {"6p2d", "6 Priorities, 2 Drop Eligible", Priority_Drop_6P2D},
    {"5p3d", "5 Priorities, 3 Drop Eligible", Priority_Drop_5P3D},
    {NULL, NULL, -1}
  };

  module_t *vlan_module;
  expert_module_t* expert_vlan;

  proto_vlan = proto_register_protocol("802.1Q Virtual LAN", "VLAN", "vlan");
  proto_register_field_array(proto_vlan, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_vlan = expert_register_protocol(proto_vlan);
  expert_register_field_array(expert_vlan, ei, array_length(ei));

  vlan_module = prefs_register_protocol(proto_vlan, proto_reg_handoff_vlan);
  prefs_register_bool_preference(vlan_module, "summary_in_tree",
        "Show vlan summary in protocol tree",
        "Whether the vlan summary line should be shown in the protocol tree",
        &vlan_summary_in_tree);
  prefs_register_uint_preference(vlan_module, "qinq_ethertype",
        "802.1QinQ Ethertype (in hex)",
        "The (hexadecimal) Ethertype used to indicate 802.1QinQ VLAN in VLAN tunneling.",
        16, &q_in_q_ethertype);
  prefs_register_enum_preference(vlan_module, "version",
        "IEEE 802.1Q version",
        "IEEE 802.1Q specification version used (802.1Q-1998 uses 802.1D-2004 for PRI values)",
        &vlan_version, version_vals, TRUE);
  prefs_register_enum_preference(vlan_module, "priority_drop",
        "Priorities and drop eligibility",
        "Number of priorities supported, and number of those drop eligible (not used for 802.1Q-1998)",
        &vlan_priority_drop, priority_drop_vals, FALSE);
  vlan_handle = register_dissector("vlan", dissect_vlan, proto_vlan);
}

void
proto_reg_handoff_vlan(void)
{
  static gboolean prefs_initialized = FALSE;
  static unsigned int old_q_in_q_ethertype;
  capture_dissector_handle_t vlan_cap_handle;

  if (!prefs_initialized)
  {
    dissector_add_uint("ethertype", ETHERTYPE_VLAN, vlan_handle);
    vlan_cap_handle = create_capture_dissector_handle(capture_vlan, proto_vlan);
    capture_dissector_add_uint("ethertype", ETHERTYPE_VLAN, vlan_cap_handle);

    prefs_initialized = TRUE;
  }
  else
  {
    dissector_delete_uint("ethertype", old_q_in_q_ethertype, vlan_handle);
  }

  old_q_in_q_ethertype = q_in_q_ethertype;
  ethertype_handle = find_dissector_add_dependency("ethertype", proto_vlan);

  dissector_add_uint("ethertype", q_in_q_ethertype, vlan_handle);

  llc_cap_handle = find_capture_dissector("llc");
  ipx_cap_handle = find_capture_dissector("ipx");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
