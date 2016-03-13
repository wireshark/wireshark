/* packet-corosync-totemsrp.c
 * Dissectors for totem single ring protocol implemented in corosync cluster engine
 * Copyright 2007 2009 2010 2014 Masatake YAMATO <yamato@redhat.com>
 * Copyright (c) 2010 2014 Red Hat, Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/* Fields description are taken from

   Y.AMIR, L.E.MOSER, P.M.MELLIAR-SMITH, D.A.AGARWAL, P.CIARFELLA.
   "The Totem Single-Ring Ordering and Membership Protocol"*/

/*
 * NOTE: the source code at www.corosync.org looks as if it will not
 * work with multiple OSes in a cluster if it uses IPv6, as it appears
 * to use the OS's AF_ values in packets, and the value of AF_INET6
 * is ***NOT*** the same in all OSes.
 *
 * (It'll work with IPv4, because AF_INET came out of 4.2BSD and
 * most if not all OSes just picked up BSD's value of 2.)
 *
 * So we just check for all the AF_INET6 values we know about.
 *
 * We get the AF_ values from epan/aftypes.h, *not* from the OS
 * we happen to be built for.
 */

# include "config.h"

#include <epan/packet.h>
#include <epan/aftypes.h>

/*
 * Utilities for subdissectors of corosync_totemsrp.
 */
struct corosync_totemsrp_info {
  guint encoding;
  guint nodeid;
};

/* Forward declaration we need below */
void proto_register_corosync_totemsrp(void);
void proto_reg_handoff_corosync_totemsrp(void);

/* Initialize the protocol and registered fields */
static int proto_corosync_totemsrp = -1;

static heur_dissector_list_t heur_subdissector_list;

/* fields for struct message_header */
static int hf_corosync_totemsrp_message_header_type            = -1;
static int hf_corosync_totemsrp_message_header_encapsulated    = -1;
static int hf_corosync_totemsrp_message_header_endian_detector = -1;
static int hf_corosync_totemsrp_message_header_nodeid          = -1;

/* fields for struct orf_token */
static int hf_corosync_totemsrp_orf_token                      = -1;
static int hf_corosync_totemsrp_orf_token_seq                  = -1;
static int hf_corosync_totemsrp_orf_token_token_seq            = -1;
static int hf_corosync_totemsrp_orf_token_aru                  = -1;
static int hf_corosync_totemsrp_orf_token_aru_addr             = -1;
static int hf_corosync_totemsrp_orf_token_backlog              = -1;
static int hf_corosync_totemsrp_orf_token_fcc                  = -1;
static int hf_corosync_totemsrp_orf_token_retrnas_flg          = -1;
static int hf_corosync_totemsrp_orf_token_rtr_list_entries     = -1;

/* field for struct memb_ring_id */
static int hf_corosync_totemsrp_memb_ring_id                   = -1;
static int hf_corosync_totemsrp_memb_ring_id_seq               = -1;

/* field for struct totem_ip_address */
static int hf_corosync_totemsrp_ip_address                     = -1;
static int hf_corosync_totemsrp_ip_address_nodeid              = -1;
static int hf_corosync_totemsrp_ip_address_family              = -1;
static int hf_corosync_totemsrp_ip_address_addr                = -1;
static int hf_corosync_totemsrp_ip_address_addr4               = -1;
static int hf_corosync_totemsrp_ip_address_addr4_padding       = -1;
static int hf_corosync_totemsrp_ip_address_addr6               = -1;

/* field of struct mcast */
static int hf_corosync_totemsrp_mcast                          = -1;
static int hf_corosync_totemsrp_mcast_seq                      = -1;
static int hf_corosync_totemsrp_mcast_this_seqno               = -1;
static int hf_corosync_totemsrp_mcast_node_id                  = -1;
static int hf_corosync_totemsrp_mcast_system_from              = -1;
static int hf_corosync_totemsrp_mcast_guarantee                = -1;

/* field of struct memb_merge_detect */
static int hf_corosync_totemsrp_memb_merge_detect              = -1;

/* field of struct struct srp_addr */
static int hf_corosync_totemsrp_srp_addr                       = -1;

/* field of struct rtr_item */
static int hf_corosync_totemsrp_rtr_item                       = -1;
static int hf_corosync_totemsrp_rtr_item_seq                   = -1;

/* field of struct memb_join */
static int hf_corosync_totemsrp_memb_join                      = -1;
static int hf_corosync_totemsrp_memb_join_proc_list_entries    = -1;
static int hf_corosync_totemsrp_memb_join_failed_list_entries  = -1;
static int hf_corosync_totemsrp_memb_join_ring_seq             = -1;

/* field of struct memb_commit_token  */
static int hf_corosync_totemsrp_memb_commit_token              = -1;
static int hf_corosync_totemsrp_memb_commit_token_token_seq    = -1;
static int hf_corosync_totemsrp_memb_commit_token_retrans_flg  = -1;
static int hf_corosync_totemsrp_memb_commit_token_memb_index   = -1;
static int hf_corosync_totemsrp_memb_commit_token_addr_entries = -1;

/* field of struct memb_commit_token_memb_entry  */
static int hf_corosync_totemsrp_memb_commit_token_memb_entry                = -1;
static int hf_corosync_totemsrp_memb_commit_token_memb_entry_aru            = -1;
static int hf_corosync_totemsrp_memb_commit_token_memb_entry_high_delivered = -1;
static int hf_corosync_totemsrp_memb_commit_token_memb_entry_received_flg   = -1;

/* field of struct token_hold_cancel */
static int hf_corosync_totemsrp_token_hold_cancel              = -1;

/* Initialize the subtree pointers */
static gint ett_corosync_totemsrp                              = -1;
static gint ett_corosync_totemsrp_orf_token                    = -1;
static gint ett_corosync_totemsrp_memb_ring_id                 = -1;
static gint ett_corosync_totemsrp_ip_address                   = -1;
static gint ett_corosync_totemsrp_mcast                        = -1;
static gint ett_corosync_totemsrp_memb_merge_detect            = -1;
static gint ett_corosync_totemsrp_srp_addr                     = -1;
static gint ett_corosync_totemsrp_rtr_item                     = -1;
static gint ett_corosync_totemsrp_memb_join                    = -1;
static gint ett_corosync_totemsrp_memb_commit_token            = -1;
static gint ett_corosync_totemsrp_memb_commit_token_memb_entry = -1;
static gint ett_corosync_totemsrp_token_hold_cancel            = -1;
static gint ett_corosync_totemsrp_memb_join_proc_list          = -1;
static gint ett_corosync_totemsrp_memb_join_failed_list        = -1;


/*
 * Value strings
 */
#define COROSYNC_TOTEMSRP_MESSAGE_TYPE_ORF_TOKEN         0
#define COROSYNC_TOTEMSRP_MESSAGE_TYPE_MCAST             1
#define COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_MERGE_DETECT 2
#define COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_JOIN         3
#define COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_COMMIT_TOKEN 4
#define COROSYNC_TOTEMSRP_MESSAGE_TYPE_TOKEN_HOLD_CANCEL 5

static const value_string corosync_totemsrp_message_header_type[] = {
  { COROSYNC_TOTEMSRP_MESSAGE_TYPE_ORF_TOKEN,         "orf"               },
  { COROSYNC_TOTEMSRP_MESSAGE_TYPE_MCAST,             "mcast"             },
  { COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_MERGE_DETECT, "merge rings"       },
  { COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_JOIN,         "join message"      },
  { COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_COMMIT_TOKEN, "commit token"      },
  { COROSYNC_TOTEMSRP_MESSAGE_TYPE_TOKEN_HOLD_CANCEL, "cancel"            },
  { 0, NULL                                                               }
};

#define COROSYNC_TOTEMSRP_MESSAGE_ENCAPSULATED     1
#define COROSYNC_TOTEMSRP_MESSAGE_NOT_ENCAPSULATED 2

static const value_string corosync_totemsrp_message_header_encapsulated[] = {
  { 0,                                              "not mcast message" },
  { COROSYNC_TOTEMSRP_MESSAGE_ENCAPSULATED,         "encapsulated"      },
  { COROSYNC_TOTEMSRP_MESSAGE_NOT_ENCAPSULATED,     "not encapsulated"  },
  { 0, NULL                                                             }
};


static const value_string corosync_totemsrp_ip_address_family[] = {
  { COMMON_AF_INET,       "AF_INET"  },
  { BSD_AF_INET6_BSD,     "AF_INET6 (most BSD)" },
  { BSD_AF_INET6_FREEBSD, "AF_INET6 (FreeBSD)" },
  { BSD_AF_INET6_DARWIN,  "AF_INET6 (OS X and iOS)" },
  { LINUX_AF_INET6,       "AF_INET6 (Linux)" },
  { SOLARIS_AF_INET6,     "AF_INET6 (Solaris)" },
  { WINSOCK_AF_INET6,     "AF_INET6 (Windows)" },
  { 0, NULL              }
};

static guint16
corosync_totemsrp_get_guint16(tvbuff_t* tvb, gint offset, const guint encoding)
{
  if (encoding == ENC_LITTLE_ENDIAN)
    return tvb_get_letohs(tvb, offset);

  return tvb_get_ntohs(tvb, offset);
}


static guint32
corosync_totemsrp_get_guint32(tvbuff_t* tvb, gint offset, const guint encoding)
{
  if (encoding == ENC_LITTLE_ENDIAN)
    return tvb_get_letohl(tvb, offset);

  return tvb_get_ntohl(tvb, offset);
}

static guint64
corosync_totemsrp_get_guint64(tvbuff_t* tvb, gint offset, const guint encoding)
{
  if (encoding == ENC_LITTLE_ENDIAN)
    return tvb_get_letoh64(tvb, offset);

  return tvb_get_ntoh64(tvb, offset);
}


#define COROSYNC_TOTEMSRP_SRP_ADDR_INTERFACE_MAX 2

static int dissect_corosync_totemsrp0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
                                      gboolean encapsulated);


static int
dissect_corosync_totemsrp_ip_address(tvbuff_t *tvb,
                                     packet_info *pinfo _U_,
                                     proto_tree *parent_tree,
                                     guint length _U_, int offset,
                                     const guint encoding,
                                     gboolean print_interface,
                                     guint    interface,
                                     guint   *nodeid)
{
  guint16 family;
  guint nid;
  int original_offset = offset;
  proto_tree *tree;
  proto_item *item;
  gint len;

  nid = corosync_totemsrp_get_guint32(tvb, offset, encoding);
  if (nodeid)
    *nodeid = nid;
  family = corosync_totemsrp_get_guint16(tvb, offset + 4, encoding);

  item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_ip_address, tvb, offset,
                             -1, ENC_NA);
  tree = proto_item_add_subtree(item, ett_corosync_totemsrp_ip_address);

  proto_item_append_text(item, " (");
  if (print_interface)
    proto_item_append_text(item, "interface: %u; ", interface);

  proto_tree_add_item(tree, hf_corosync_totemsrp_ip_address_nodeid,
                        tvb, offset, 4, encoding);
  proto_item_append_text(item, "node: %u)", nid);
  offset += 4;

  proto_tree_add_item(tree, hf_corosync_totemsrp_ip_address_family,
                        tvb, offset, 2, encoding);
  offset += 2;

  switch (family)
  {
  case COMMON_AF_INET:
    len = 4;
    proto_tree_add_item(tree, hf_corosync_totemsrp_ip_address_addr4, tvb, offset, len, ENC_BIG_ENDIAN);
    break;
  case BSD_AF_INET6_BSD:
  case BSD_AF_INET6_FREEBSD:
  case BSD_AF_INET6_DARWIN:
  case LINUX_AF_INET6:
  case SOLARIS_AF_INET6:
  case WINSOCK_AF_INET6:
    len = sizeof(struct e_in6_addr);
    proto_tree_add_item(tree, hf_corosync_totemsrp_ip_address_addr6, tvb, offset, len, ENC_NA);
    break;
  default:
    len = sizeof(struct e_in6_addr);
    proto_tree_add_item(tree, hf_corosync_totemsrp_ip_address_addr, tvb, offset, len, ENC_NA);
    break;
  }

  offset += len;

  if (len != sizeof(struct e_in6_addr)) {
    gint padding_len;

    padding_len = (gint)(sizeof(struct e_in6_addr) - len);
    proto_tree_add_item (tree, hf_corosync_totemsrp_ip_address_addr4_padding,
                           tvb, offset, padding_len, ENC_NA);
    offset += padding_len;
  }

  proto_item_set_len(item, offset - original_offset);
  return offset - original_offset;
}

static int
dissect_corosync_totemsrp_memb_ring_id(tvbuff_t *tvb,
                                       packet_info *pinfo, proto_tree *parent_tree,
                                       guint length, int offset,
                                       const guint encoding,
                                       guint *node_id,
                                       guint64 *ring_id)
{
  int original_offset = offset;
  proto_tree *tree;
  proto_item *item;
  guint64 rid;
  guint nid;

  item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_memb_ring_id, tvb, offset,
                               -1, encoding);
  tree = proto_item_add_subtree(item, ett_corosync_totemsrp_memb_ring_id);

  offset += dissect_corosync_totemsrp_ip_address(tvb, pinfo, tree,
                                                    length, offset,
                                                    encoding,
                                                    FALSE, -1,
                                                    &nid);

  proto_tree_add_item(tree, hf_corosync_totemsrp_memb_ring_id_seq,
                        tvb, offset, 8, encoding);
  rid = corosync_totemsrp_get_guint64(tvb, offset, encoding);
  offset += 8;

  proto_item_append_text(item, " (ring: %" G_GINT64_MODIFIER "u)", rid);

  if (node_id)
    *node_id = nid;
  if (ring_id)
    *ring_id = rid;

  proto_item_set_len(item, offset - original_offset);
  return offset - original_offset;
}

static int
dissect_corosync_totemsrp_rtr_list(tvbuff_t *tvb,
                                   packet_info *pinfo, proto_tree *parent_tree,
                                   guint length, int offset,
                                   const guint encoding)
{
  int original_offset = offset;
  proto_tree *tree;
  proto_item *item;

  guint node_id;
  guint64 ring_id;
  guint32 seq;

  item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_rtr_item, tvb, offset,
                               -1, ENC_NA);
  tree = proto_item_add_subtree(item, ett_corosync_totemsrp_rtr_item);

  offset += dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, tree,
                                                        length, offset,
                                                        encoding,
                                                        &node_id,
                                                        &ring_id);

  proto_tree_add_item(tree, hf_corosync_totemsrp_rtr_item_seq,
                        tvb, offset, 4, encoding);

  seq = corosync_totemsrp_get_guint32(tvb, offset, encoding);
  proto_item_append_text(item, " (ring: %" G_GINT64_MODIFIER "u node: %u seq: %u)",
                           ring_id, node_id, seq);
  offset += 4;

  proto_item_set_len(item, offset - original_offset);
  return (offset - original_offset);
}

static int
dissect_corosync_totemsrp_orf_token(tvbuff_t *tvb,
                                    packet_info *pinfo, proto_tree *parent_tree,
                                    guint length, int offset,
                                    const guint encoding)
{
  int original_offset = offset;
  guint32 rtr_list_entries = 0, seq, aru, i;
  proto_tree *tree;
  proto_item *item;
  guint   node_id;
  guint64 ring_id;

  item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_orf_token,
                             tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(item, ett_corosync_totemsrp_orf_token);

  proto_tree_add_item(tree, hf_corosync_totemsrp_orf_token_seq,
                        tvb, offset, 4, encoding);
  offset += 4;

  proto_tree_add_item(tree, hf_corosync_totemsrp_orf_token_token_seq,
                        tvb, offset, 4, encoding);
  seq = corosync_totemsrp_get_guint32(tvb, offset, encoding);
  offset += 4;

  proto_tree_add_item(tree, hf_corosync_totemsrp_orf_token_aru,
                        tvb, offset, 4, encoding);
  aru = corosync_totemsrp_get_guint32(tvb, offset, encoding);
  offset += 4;

  proto_tree_add_item(tree, hf_corosync_totemsrp_orf_token_aru_addr,
                        tvb, offset, 4, encoding);
  offset += 4;

  offset += dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, tree,
                                                        length, offset,
                                                        encoding,
                                                        &node_id,
                                                        &ring_id);

  proto_tree_add_item(tree, hf_corosync_totemsrp_orf_token_backlog,
                        tvb, offset, 4, encoding);
  offset += 4;

  proto_tree_add_item(tree, hf_corosync_totemsrp_orf_token_fcc,
                        tvb, offset, 4, encoding);
  offset += 4;

  proto_tree_add_item(tree, hf_corosync_totemsrp_orf_token_retrnas_flg,
                        tvb, offset, 4, encoding);
  offset += 4;

  proto_tree_add_item(tree, hf_corosync_totemsrp_orf_token_rtr_list_entries,
                        tvb, offset, 4, encoding);
  rtr_list_entries = corosync_totemsrp_get_guint32(tvb, offset, encoding);
  offset += 4;

  for (i = 0; i < rtr_list_entries; i++) {
    offset += dissect_corosync_totemsrp_rtr_list(tvb, pinfo,
                                                    tree,
                                                    length, offset,
                                                    encoding);
  }

  proto_item_append_text(item, " (ring: %" G_GINT64_MODIFIER "u node: %u nrtr: %d seq: %d au: %u)",
                           ring_id, node_id, rtr_list_entries, seq, aru);

  proto_item_set_len(item, offset - original_offset);
  return offset - original_offset;
}

static int
dissect_corosync_totemsrp_srp_addr(tvbuff_t *tvb,
                                   packet_info *pinfo, proto_tree *parent_tree,
                                   guint length, int offset,
                                   int   hf,
                                   const guint encoding)
{
  int original_offset = offset;
  proto_tree *tree;
  proto_item *item;
  guint nodeid;

  item = proto_tree_add_item(parent_tree, hf? hf: hf_corosync_totemsrp_srp_addr, tvb, offset,
                               -1, encoding);
  tree = proto_item_add_subtree(item, ett_corosync_totemsrp_srp_addr);

  offset += dissect_corosync_totemsrp_ip_address(tvb, pinfo, tree,
                                                      length, offset,
                                                      encoding,
                                                      TRUE, 0,
                                                      &nodeid);
  proto_item_append_text(item, " (node: %u)", nodeid);

  offset += dissect_corosync_totemsrp_ip_address(tvb, pinfo, tree,
                                                      length, offset,
                                                      encoding,
                                                      TRUE, 1,
                                                      NULL);

  proto_item_set_len(item, offset - original_offset);
  return (offset - original_offset);
}

static int
dissect_corosync_totemsrp_mcast(tvbuff_t *tvb,
                                  packet_info *pinfo, proto_tree *tree,
                                  guint length, int offset,
                                  guint8 message_header__encapsulated,
                                  const guint encoding, proto_tree *parent_tree,
                                  struct corosync_totemsrp_info *totemsrp_info)
{
  int original_offset = offset;
  proto_tree *mcast_tree;

  proto_item *item;
  guint node_id;
  guint64 ring_id;
  tvbuff_t *next_tvb;

  heur_dtbl_entry_t *hdtbl_entry = NULL;

  item = proto_tree_add_item(tree, hf_corosync_totemsrp_mcast, tvb, offset,
                               -1, encoding);
  mcast_tree = proto_item_add_subtree(item, ett_corosync_totemsrp_mcast);

  offset += dissect_corosync_totemsrp_srp_addr(tvb, pinfo, mcast_tree,
                                                    length, offset,
                                                    hf_corosync_totemsrp_mcast_system_from,
                                                    encoding);

  proto_tree_add_item(mcast_tree, hf_corosync_totemsrp_mcast_seq,
                        tvb, offset, 4, encoding);
  offset += 4;

  proto_tree_add_item(mcast_tree, hf_corosync_totemsrp_mcast_this_seqno,
                        tvb, offset, 4, encoding);
  offset += 4;

  offset += dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, mcast_tree,
                                                        length, offset,
                                                        encoding,
                                                        &node_id,
                                                        &ring_id);

  proto_item_append_text(item, " (ring: %" G_GINT64_MODIFIER "u node: %u)",
                           ring_id, node_id);

  proto_tree_add_item(tree, hf_corosync_totemsrp_mcast_node_id,
                        tvb, offset, 4, encoding);
  offset += 4;

  proto_tree_add_item(tree, hf_corosync_totemsrp_mcast_guarantee,
                        tvb, offset, 4, encoding);
  offset += 4;

  next_tvb = tvb_new_subset_remaining(tvb, offset);

  if (message_header__encapsulated == COROSYNC_TOTEMSRP_MESSAGE_ENCAPSULATED)
  {
    offset += dissect_corosync_totemsrp0(next_tvb, pinfo, tree, TRUE);
  }
  else
  {
    if (dissector_try_heuristic(heur_subdissector_list,
                                next_tvb,
                                pinfo,
                                parent_tree,
                                &hdtbl_entry,
                                totemsrp_info))
       offset = length;
  }

  proto_item_set_len(item, offset - original_offset);
  return (offset - original_offset);
}


static int
dissect_corosync_totemsrp_memb_merge_detect(tvbuff_t *tvb,
                                            packet_info *pinfo, proto_tree *parent_tree,
                                            guint length, int offset,
                                            const guint encoding)
{
  int original_offset = offset;
  proto_tree *tree;
  proto_item *item;
  guint node_id;
  guint64 ring_id;

  item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_memb_merge_detect, tvb, offset,
                               -1, ENC_NA);
  tree = proto_item_add_subtree(item, ett_corosync_totemsrp_memb_merge_detect);

  offset += dissect_corosync_totemsrp_srp_addr(tvb, pinfo, tree,
                                                    length, offset,
                                                    0,
                                                    encoding);

  offset += dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, tree,
                                                        length, offset,
                                                        encoding,
                                                        &node_id,
                                                        &ring_id);

  proto_item_append_text(item, " (ring: %" G_GINT64_MODIFIER "u node: %u)",
                           ring_id, node_id);

  proto_item_set_len(item, offset - original_offset);
  return (offset - original_offset);
}

static int
dissect_corosync_totemsrp_memb_join(tvbuff_t *tvb,
                                    packet_info *pinfo, proto_tree *parent_tree,
                                    guint length, int offset,
                                    const guint encoding)
{
  int original_offset = offset;
  proto_tree *tree;
  proto_item *item;

  guint32 proc_list_entries;
  proto_tree *proc_tree;

  guint32 failed_list_entries;
  proto_tree *failed_tree;
  proto_item *failed_item;

  guint i;

  proto_item *proc_item;

  item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_memb_join, tvb, offset,
                               -1, encoding);
  tree = proto_item_add_subtree(item, ett_corosync_totemsrp_memb_join);


  offset += dissect_corosync_totemsrp_srp_addr(tvb, pinfo, tree,
                                                    length, offset,
                                                    0,
                                                    encoding);

  proc_item = proto_tree_add_item(tree, hf_corosync_totemsrp_memb_join_proc_list_entries,
                                    tvb, offset, 4, encoding);
  proc_list_entries = corosync_totemsrp_get_guint32(tvb, offset, encoding);
  offset += 4;

  failed_item = proto_tree_add_item(tree, hf_corosync_totemsrp_memb_join_failed_list_entries,
                                      tvb, offset, 4, encoding);
  failed_list_entries = corosync_totemsrp_get_guint32(tvb, offset, encoding);
  offset += 4;

  proto_tree_add_item(tree, hf_corosync_totemsrp_memb_join_ring_seq,
                        tvb, offset, 8, encoding);
  offset += 8;

  proc_tree = proto_item_add_subtree(proc_item, ett_corosync_totemsrp_memb_join_proc_list);

  proto_item_append_text(item, " (nprocs: %u nfailed: %u)",
                           proc_list_entries, failed_list_entries);

  for (i = 0; i < proc_list_entries; i++) {
    offset += dissect_corosync_totemsrp_srp_addr(tvb, pinfo, proc_tree,
                                                    length, offset,
                                                    0,
                                                    encoding);
  }

  failed_tree = proto_item_add_subtree(failed_item,
                                         ett_corosync_totemsrp_memb_join_failed_list);

  for (i = 0; i < failed_list_entries; i++) {
    offset += dissect_corosync_totemsrp_srp_addr(tvb, pinfo, failed_tree,
                                                    length, offset,
                                                    0,
                                                    encoding);
  }

  proto_item_set_len(item, offset - original_offset);
  return (offset - original_offset);
}

static int
dissect_corosync_totemsrp_memb_commit_token_memb_entry(tvbuff_t *tvb,
                                                       packet_info *pinfo,
                                                       proto_tree *parent_tree,
                                                       guint length, int offset,
                                                       const guint encoding,
                                                       guint *node_id,
                                                       guint64 *ring_id)
{
  int original_offset = offset;

  proto_tree *tree;
  proto_item *item;

  item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_memb_commit_token_memb_entry,
                               tvb, offset, -1, encoding);
  tree = proto_item_add_subtree(item, ett_corosync_totemsrp_memb_commit_token_memb_entry);


  offset += dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, tree,
                                                        length, offset,
                                                        encoding,
                                                        node_id,
                                                        ring_id);

  proto_tree_add_item(tree, hf_corosync_totemsrp_memb_commit_token_memb_entry_aru,
                        tvb, offset, 4, encoding);
  offset += 4;

  proto_tree_add_item(tree, hf_corosync_totemsrp_memb_commit_token_memb_entry_high_delivered,
                        tvb, offset, 4, encoding);
  offset += 4;

  proto_tree_add_item(tree, hf_corosync_totemsrp_memb_commit_token_memb_entry_received_flg,
                        tvb, offset, 4, encoding);
  offset += 4;

  proto_item_set_len(item, offset - original_offset);
  return (offset - original_offset);
}

static int
dissect_corosync_totemsrp_memb_commit_token(tvbuff_t *tvb,
                                            packet_info *pinfo, proto_tree *parent_tree,
                                            guint length, int offset,
                                            const guint encoding)
{
  int original_offset = offset;
  proto_tree *tree;
  proto_item *item;

  guint32 i, addr_entries;

  guint32 seq;
  guint node_id;
  guint64 ring_id;

  item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_memb_commit_token,
                               tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(item, ett_corosync_totemsrp_memb_commit_token);

  proto_tree_add_item(tree, hf_corosync_totemsrp_memb_commit_token_token_seq,
                        tvb, offset, 4, encoding);
  seq = corosync_totemsrp_get_guint32(tvb, offset, encoding);
  offset += 4;

  offset += dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, tree,
                                                        length, offset,
                                                        encoding,
                                                        &node_id,
                                                        &ring_id);

  proto_tree_add_item(tree, hf_corosync_totemsrp_memb_commit_token_retrans_flg,
                        tvb, offset, 4, encoding);
  offset += 4;

  proto_tree_add_item(tree, hf_corosync_totemsrp_memb_commit_token_memb_index,
                        tvb, offset, 4, encoding);
  offset += 4;

  proto_tree_add_item(tree, hf_corosync_totemsrp_memb_commit_token_addr_entries,
                        tvb, offset, 4, encoding);
  addr_entries = corosync_totemsrp_get_guint32(tvb, offset, encoding);
  offset += 4;

  for (i = 0; i < addr_entries; i++) {
    offset += dissect_corosync_totemsrp_srp_addr(tvb, pinfo, tree,
                                                    length, offset,
                                                    0,
                                                    encoding);
  }

  for (i = 0; i < addr_entries; i++) {
    offset += dissect_corosync_totemsrp_memb_commit_token_memb_entry(tvb, pinfo, tree,
                                                                        length, offset,
                                                                        encoding,
                                                                        NULL,
                                                                        NULL);
  }

  proto_item_append_text(item, " (ring: %" G_GINT64_MODIFIER "u node: %u seq: %u entries: %u)",
                           ring_id, node_id, seq, addr_entries);

  proto_item_set_len(item, offset - original_offset);
  return (offset - original_offset);
}

static int
dissect_corosync_totemsrp_token_hold_cancel(tvbuff_t *tvb,
                                            packet_info *pinfo, proto_tree *parent_tree,
                                            guint length, int offset,
                                            const guint encoding)
{
  int original_offset = offset;
  proto_tree *tree;
  proto_item *item;
  guint node_id;
  guint64 ring_id;

  item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_token_hold_cancel, tvb, offset,
                               -1, ENC_NA);
  tree = proto_item_add_subtree(item, ett_corosync_totemsrp_token_hold_cancel);

  offset += dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, tree,
                                                        length, offset,
                                                        encoding,
                                                        &node_id,
                                                        &ring_id);

  proto_item_append_text(item, " (ring: %" G_GINT64_MODIFIER "u node: %u)",
                             ring_id, node_id);

  proto_item_set_len(item, offset - original_offset);
  return (offset - original_offset);
}

static int
dissect_corosync_totemsrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
  return dissect_corosync_totemsrp0(tvb, pinfo, parent_tree, FALSE);
}

#define COROSYNC_TOTEMSRP_TEST_LITTLE_ENDIAN    0x22FF
#define COROSYNC_TOTEMSRP_TEST_BIG_ENDIAN       0xFF22

static int
dissect_corosync_totemsrp0(tvbuff_t *tvb,
                           packet_info *pinfo, proto_tree *tree,
                           gboolean encapsulated)
{
  proto_item *item;
  guint       length;
  int         offset = 0;
  guint16     endian_test;
  proto_tree *corosync_tree;

  guint8      message_header__type;
  guint8      message_header__encapsulated;

  guint encoding;
  struct corosync_totemsrp_info info;

  /* Check that there's enough data */
  length = tvb_reported_length(tvb);
  if (length < 1 + 1 + 2 + 4)
    return 0;

  /* message header */
  message_header__type = tvb_get_guint8(tvb, 0);
  if (message_header__type > 5)
    return 0;

  message_header__encapsulated = tvb_get_guint8(tvb, 1);

  /* message_header -- byte order checking */
  endian_test = tvb_get_ntohs(tvb, 2);
  if (endian_test == COROSYNC_TOTEMSRP_TEST_LITTLE_ENDIAN)
    encoding = ENC_LITTLE_ENDIAN;
  else if (endian_test == COROSYNC_TOTEMSRP_TEST_BIG_ENDIAN)
    encoding = ENC_BIG_ENDIAN;
  else
    return 0;

  if (encapsulated == FALSE)
  {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "COROSYNC/TOTEMSRP");
    col_set_str(pinfo->cinfo, COL_INFO,
              ((message_header__type == COROSYNC_TOTEMSRP_MESSAGE_TYPE_MCAST)
               && (message_header__encapsulated == COROSYNC_TOTEMSRP_MESSAGE_ENCAPSULATED))?
              "ENCAPSULATED":
              val_to_str_const(message_header__type,
                               corosync_totemsrp_message_header_type,
                               "Unknown"));
  }

  item = proto_tree_add_item(tree, proto_corosync_totemsrp, tvb, offset, -1, ENC_NA);
  corosync_tree = proto_item_add_subtree(item, ett_corosync_totemsrp);

  proto_tree_add_item(corosync_tree, hf_corosync_totemsrp_message_header_type,
                        tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(corosync_tree, hf_corosync_totemsrp_message_header_encapsulated,
                        tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(corosync_tree, hf_corosync_totemsrp_message_header_endian_detector,
                        tvb, offset, 2, encoding);
  offset += 2;

  proto_tree_add_item(corosync_tree,
                        hf_corosync_totemsrp_message_header_nodeid,
                        tvb, offset, 4, encoding);
  info.encoding = encoding;
  info.nodeid = corosync_totemsrp_get_guint32(tvb, offset, encoding);
  offset += 4;

  switch (message_header__type) {
  case COROSYNC_TOTEMSRP_MESSAGE_TYPE_ORF_TOKEN:
    dissect_corosync_totemsrp_orf_token(tvb, pinfo, corosync_tree, length, offset, encoding);
    break;
  case COROSYNC_TOTEMSRP_MESSAGE_TYPE_MCAST:
    dissect_corosync_totemsrp_mcast(tvb, pinfo, corosync_tree, length, offset,
                                    message_header__encapsulated,
                                    encoding, tree, &info);
    break;
  case COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_MERGE_DETECT:
    dissect_corosync_totemsrp_memb_merge_detect(tvb, pinfo, corosync_tree, length, offset,
                                                encoding);
    break;
  case COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_JOIN:
    dissect_corosync_totemsrp_memb_join(tvb, pinfo, corosync_tree, length, offset,
                                        encoding);
    break;
  case COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_COMMIT_TOKEN:
    dissect_corosync_totemsrp_memb_commit_token(tvb, pinfo, corosync_tree, length, offset,
                                                encoding);
    break;
  case COROSYNC_TOTEMSRP_MESSAGE_TYPE_TOKEN_HOLD_CANCEL:
    dissect_corosync_totemsrp_token_hold_cancel(tvb, pinfo, corosync_tree, length, offset,
                                                encoding);
    break;
  default:
    break;
  }

  return length;
}

void
proto_register_corosync_totemsrp(void)
{
  static hf_register_info hf[] = {
    /* message_header */
    { &hf_corosync_totemsrp_message_header_type,
      { "Type", "corosync_totemsrp.message_header.type",
        FT_INT8, BASE_DEC, VALS(corosync_totemsrp_message_header_type), 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_message_header_encapsulated,
      { "Encapsulated", "corosync_totemsrp.message_header.encapsulated",
        FT_INT8, BASE_DEC, VALS(corosync_totemsrp_message_header_encapsulated), 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_message_header_endian_detector,
      { "Endian detector", "corosync_totemsrp.message_header.endian_detector",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_message_header_nodeid,
      { "Node ID", "corosync_totemsrp.message_header.nodeid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    /* orf_token */
    { &hf_corosync_totemsrp_orf_token,
      { "Ordering, Reliability, Flow (ORF) control Token", "corosync_totemsrp.orf_token",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_orf_token_seq,
      { "Sequence number allowing recognition of redundant copies of the token", "corosync_totemsrp.orf_token.seq",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_orf_token_token_seq,
      { "The largest sequence number", "corosync_totemsrp.orf_token.seq",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "The largest sequence number of any message "
        "that has been broadcast on the ring"
        "[1]" ,
        HFILL }},
    { &hf_corosync_totemsrp_orf_token_aru,
      { "Sequence number all received up to", "corosync_totemsrp.orf_token.aru",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_orf_token_aru_addr,
      { "ID of node setting ARU", "corosync_totemsrp.orf_token.aru_addr",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_orf_token_backlog,
      { "Backlog", "corosync_totemsrp.orf_token.backlog",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "The sum of the number of new message waiting to be transmitted by each processor on the ring "
        "at the time at which that processor forwarded the token during the previous rotation"
        "[1]",
        HFILL }},
    { &hf_corosync_totemsrp_orf_token_fcc,
      { "FCC",
        "corosync_totemsrp.orf_token.fcc",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "A count of the number of messages broadcast by all processors "
        "during the previous rotation of the token"
        "[1]",
        HFILL }},
    { &hf_corosync_totemsrp_orf_token_retrnas_flg,
      { "Retransmission flag", "corosync_totemsrp.orf_token.retrans_flg",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_orf_token_rtr_list_entries,
      { "The number of retransmission list entries", "corosync_totemsrp.orf_token.rtr_list_entries",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    /* memb_ring_id */
    { &hf_corosync_totemsrp_memb_ring_id,
      { "Member ring id", "corosync_totemsrp.memb_ring_id",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_memb_ring_id_seq,
      { "Sequence in member ring id", "corosync_totemsrp.memb_ring_id.seq",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    /* totem_ip_address */
    { &hf_corosync_totemsrp_ip_address,
      { "Node IP address", "corosync_totemsrp.ip_address",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_ip_address_nodeid,
      { "Node ID", "corosync_totemsrp.ip_address.nodeid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_ip_address_family,
      { "Address family", "corosync_totemsrp.ip_address.family",
        FT_UINT16, BASE_DEC, VALS(corosync_totemsrp_ip_address_family), 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_ip_address_addr,
      { "Address", "corosync_totemsrp.ip_address.addr",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_ip_address_addr4,
      { "Address", "corosync_totemsrp.ip_address.addr4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_ip_address_addr4_padding,
      { "Address padding", "corosync_totemsrp.ip_address.addr4_padding",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_ip_address_addr6,
      { "Address", "corosync_totemsrp.ip_address.addr6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* mcast */
    { &hf_corosync_totemsrp_mcast,
      { "ring ordered multicast message", "corosync_totemsrp.mcast",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemsrp_mcast_seq,
      {"Multicast sequence number", "corosync_totemsrp.mcast.seq",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL }},
    { &hf_corosync_totemsrp_mcast_this_seqno,
      {"This Sequence number", "corosync_totemsrp.mcast.this_seqno",
       FT_INT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL }},
    { &hf_corosync_totemsrp_mcast_node_id,
      {"Node id(unused?)", "corosync_totemsrp.mcast.node_id",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL }},
    { &hf_corosync_totemsrp_mcast_system_from,
      {"System from address", "corosync_totemsrp.mcast.system_from",
       FT_NONE, BASE_NONE, NULL, 0x0,
       NULL, HFILL }},

    { &hf_corosync_totemsrp_mcast_guarantee,
      {"Guarantee", "corosync_totemsrp.mcast.guarantee",
       FT_INT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL }},

    /* memb_merge_detect */
    { &hf_corosync_totemsrp_memb_merge_detect,
      { "Merge rings if there are available rings", "corosync_totemsrp.memb_merge_detect",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* srp_addr */
    { &hf_corosync_totemsrp_srp_addr,
      {"Single Ring Protocol Address", "corosync_totemsrp.srp_addr",
       FT_NONE, BASE_NONE, NULL, 0x0,
       NULL, HFILL }},

    /* rtr_item */
    { &hf_corosync_totemsrp_rtr_item,
      {"Retransmission Item", "corosync_totemsrp.rtr_item",
       FT_NONE, BASE_NONE, NULL, 0x0,
       NULL, HFILL }},
    { &hf_corosync_totemsrp_rtr_item_seq,
      {"Sequence of Retransmission Item", "corosync_totemsrp.rtr_item.seq",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL }},

    /* memb_join */
    { &hf_corosync_totemsrp_memb_join,
      {"Membership join message", "corosync_totemsrp.memb_join",
       FT_NONE, BASE_NONE, NULL, 0x0,
       NULL, HFILL}},
    { &hf_corosync_totemsrp_memb_join_proc_list_entries,
      {"The number of processor list entries", "corosync_totemsrp.memb_join.proc_list_entries",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL}},
    { &hf_corosync_totemsrp_memb_join_failed_list_entries,
      {"The number of failed list entries", "corosync_totemsrp.memb_join.failed_list_entries",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL}},
    { &hf_corosync_totemsrp_memb_join_ring_seq,
      {"Ring sequence number", "corosync_totemsrp.memb_join.ring_seq",
       FT_UINT64, BASE_DEC, NULL, 0x0,
       NULL, HFILL}},

    /* memb_commit_token */
    { &hf_corosync_totemsrp_memb_commit_token,
      {"Membership commit token", "corosync_totemsrp.memb_commit_token",
       FT_NONE, BASE_NONE, NULL, 0x0,
       NULL, HFILL}},
    { &hf_corosync_totemsrp_memb_commit_token_token_seq,
      {"Token sequence", "corosync_totemsrp.memb_commit_token.token_seq",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL}},
    { &hf_corosync_totemsrp_memb_commit_token_retrans_flg,
      {"Retransmission flag", "corosync_totemsrp.memb_commit_token.retrans_flg",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL}},
    { &hf_corosync_totemsrp_memb_commit_token_memb_index,
      {"Member index", "corosync_totemsrp.memb_commit_token.memb_index",
       FT_INT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL}},
    { &hf_corosync_totemsrp_memb_commit_token_addr_entries,
      {"The number of address entries", "corosync_totemsrp.memb_commit_token.addr_entries",
       FT_INT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL}},

    /* memb_commit_token_memb_entry */
    { &hf_corosync_totemsrp_memb_commit_token_memb_entry,
      { "Membership entry", "corosync_totemsrp.memb_commit_token_memb_entry",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
    { &hf_corosync_totemsrp_memb_commit_token_memb_entry_aru,
      {"Sequence number all received up to", "corosync_totemsrp.memb_commit_token_memb_entry.aru",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL}},
    { &hf_corosync_totemsrp_memb_commit_token_memb_entry_high_delivered,
      {"High delivered", "corosync_totemsrp.memb_commit_token_memb_entry.high_delivered",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL}},
    { &hf_corosync_totemsrp_memb_commit_token_memb_entry_received_flg,
      {"Received flag", "corosync_totemsrp.memb_commit_token_memb_entry.received_flg",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL}},

    /* token_hold_cancel */
    { &hf_corosync_totemsrp_token_hold_cancel,
      {"Hold cancel token", "corosync_totemsrp.token_hold_cancel",
       FT_NONE, BASE_NONE, NULL, 0x0,
       NULL, HFILL}},
  };

  static gint *ett[] = {
    &ett_corosync_totemsrp,
    &ett_corosync_totemsrp_orf_token,
    &ett_corosync_totemsrp_memb_ring_id,
    &ett_corosync_totemsrp_ip_address,
    &ett_corosync_totemsrp_mcast,
    &ett_corosync_totemsrp_memb_merge_detect,
    &ett_corosync_totemsrp_srp_addr,
    &ett_corosync_totemsrp_rtr_item,
    &ett_corosync_totemsrp_memb_join,
    &ett_corosync_totemsrp_memb_commit_token,
    &ett_corosync_totemsrp_memb_commit_token_memb_entry,
    &ett_corosync_totemsrp_token_hold_cancel,
    &ett_corosync_totemsrp_memb_join_proc_list,
    &ett_corosync_totemsrp_memb_join_failed_list

  };

  proto_corosync_totemsrp = proto_register_protocol("Totem Single Ring Protocol implemented in Corosync Cluster Engine",
                                                    "COROSYNC/TOTEMSRP", "corosync_totemsrp");
  proto_register_field_array(proto_corosync_totemsrp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  heur_subdissector_list = register_heur_dissector_list("corosync_totemsrp.mcast", proto_corosync_totemsrp);

  register_dissector( "corosync_totemsrp", dissect_corosync_totemsrp, proto_corosync_totemsrp);
}

void
proto_reg_handoff_corosync_totemsrp(void)
{
  /* Nothing to be done.
     dissect_corosync_totemsrp is directly called from corosync_totemnet dissector. */
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
