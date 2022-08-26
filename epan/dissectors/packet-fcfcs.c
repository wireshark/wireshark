/* packet-fcfcs.c
 * Routines for FC Fabric Configuration Server
 * Copyright 2001, Dinesh G Dutt <ddutt@andiamo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/expert.h>
#include "packet-fc.h"
#include "packet-fcct.h"
#include "packet-fcfcs.h"

void proto_register_fcfcs(void);
void proto_reg_handoff_fcfcs(void);

/*
 * See the FC-GS3 specification.
 */

/* Initialize the protocol and registered fields */
static int proto_fcfcs          = -1;
static int hf_fcs_opcode        = -1;
static int hf_fcs_iename        = -1;
static int hf_fcs_ietype        = -1;
static int hf_fcs_iedomainid    = -1;
static int hf_fcs_mgmtid        = -1;
static int hf_fcs_fabricname    = -1;
static int hf_fcs_mgmtaddr      = -1;
static int hf_fcs_lname         = -1;
static int hf_fcs_vendorname    = -1;
static int hf_fcs_modelname     = -1;
static int hf_fcs_portname      = -1;
static int hf_fcs_portmodtype   = -1;
static int hf_fcs_porttxtype    = -1;
static int hf_fcs_porttype      = -1;
static int hf_fcs_physportnum   = -1;
static int hf_fcs_portflags     = -1;
static int hf_fcs_portstate     = -1;
static int hf_fcs_platformname_len  = -1;
static int hf_fcs_platformname  = -1;
static int hf_fcs_platformnname = -1;
static int hf_fcs_platformtype  = -1;
static int hf_fcs_platformaddr  = -1;
static int hf_fcs_reason        = -1;
static int hf_fcs_rjtdetail     = -1;
static int hf_fcs_vendor        = -1;
static int hf_fcs_numcap        = -1;
static int hf_fcs_mgmt_subtype  = -1;
static int hf_fcs_unsmask       = -1;
static int hf_fcs_vnd_capmask   = -1;
static int hf_fcs_fcsmask       = -1;
static int hf_fcs_maxres_size   = -1;
static int hf_fcs_releasecode   = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_fcfcs_num_ie_entries = -1;
static int hf_fcfcs_num_mgmt_addresses = -1;
static int hf_fcfcs_list_length = -1;
static int hf_fcfcs_vendor_specific_information = -1;
static int hf_fcfcs_num_port_entries = -1;
static int hf_fcfcs_num_attached_port_entries = -1;
static int hf_fcfcs_num_platform_node_name_entries = -1;
static int hf_fcfcs_num_mgmt_address_entries = -1;
static int hf_fcfcs_num_platform_name_entries = -1;

/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_fcfcs_no_record_of_exchange = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_fcfcs = -1;

typedef struct _fcfcs_conv_key {
    guint32 conv_idx;
} fcfcs_conv_key_t;

typedef struct _fcfcs_conv_data {
    guint32 opcode;
} fcfcs_conv_data_t;

static wmem_map_t *fcfcs_req_hash = NULL;

/*
 * Hash Functions
 */
static gint
fcfcs_equal(gconstpointer v, gconstpointer w)
{
  const fcfcs_conv_key_t *v1 = (const fcfcs_conv_key_t *)v;
  const fcfcs_conv_key_t *v2 = (const fcfcs_conv_key_t *)w;

  return (v1->conv_idx == v2->conv_idx);
}

static guint
fcfcs_hash (gconstpointer v)
{
    const fcfcs_conv_key_t *key = (const fcfcs_conv_key_t *)v;
    guint val;

    val = key->conv_idx;

    return val;
}

/* Code to actually dissect the packets */
static void
dissect_fcfcs_giel (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the ct header */
    guint32 numelem, i;

    if (!isreq && tree) {
        proto_tree_add_item_ret_uint(tree, hf_fcfcs_num_ie_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &numelem);
        offset += 4;
        for (i = 0; i < numelem; i++) {
            proto_tree_add_item (tree, hf_fcs_iename, tvb, offset, 8, ENC_NA);
            proto_tree_add_item (tree, hf_fcs_ietype, tvb, offset+11, 1, ENC_BIG_ENDIAN);
            offset += 12;
        }
    }
}

static void
dissect_fcfcs_giet (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */

    if (tree) {
        if (isreq) {
            proto_tree_add_item (tree, hf_fcs_iename, tvb, offset, 8, ENC_NA);
        }
        else {
            proto_tree_add_item (tree, hf_fcs_ietype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        }
    }
}

static void
dissect_fcfcs_gdid (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */

    if (tree) {
        if (isreq) {
            proto_tree_add_item (tree, hf_fcs_iename, tvb, offset, 8, ENC_NA);
        }
        else {
            proto_tree_add_item (tree, hf_fcs_iedomainid, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        }
    }
}

static void
dissect_fcfcs_gmid (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */

    if (tree) {
        if (isreq) {
            proto_tree_add_item (tree, hf_fcs_iename, tvb, offset, 8, ENC_NA);
        }
        else {
            proto_tree_add_item (tree, hf_fcs_mgmtid, tvb, offset+1, 3, ENC_NA);
        }
    }
}

static void
dissect_fcfcs_gfn (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */

    if (tree) {
        if (isreq) {
            proto_tree_add_item (tree, hf_fcs_iename, tvb, offset, 8, ENC_NA);
        }
        else {
            proto_tree_add_item (tree, hf_fcs_fabricname, tvb, offset, 8, ENC_NA);
        }
    }
}

static void
dissect_fcfcs_gieln (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */

    if (tree) {
        if (isreq) {
            proto_tree_add_item (tree, hf_fcs_iename, tvb, offset, 8, ENC_NA);
        }
        else {
            proto_tree_add_item (tree, hf_fcs_lname, tvb, offset,
                                 1, ENC_ASCII|ENC_BIG_ENDIAN);
        }
    }
}

static void
dissect_fcfcs_gmal (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */
    guint32 numelem, i;

    if (tree) {
        if (isreq) {
            proto_tree_add_item (tree, hf_fcs_iename, tvb, offset, 8, ENC_NA);
        }
        else {
            proto_tree_add_item_ret_uint(tree, hf_fcfcs_num_mgmt_addresses, tvb, offset, 4, ENC_BIG_ENDIAN, &numelem);

            offset += 4;
            for (i = 0; i < numelem; i++) {
                proto_tree_add_item (tree, hf_fcs_mgmtaddr, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
                offset += 256;
            }
        }
    }
}

static void
dissect_fcfcs_gieil (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */
    guint len;
    guint32 tot_len, prevlen;

    if (isreq) {
        proto_tree_add_item (tree, hf_fcs_iename, tvb, offset, 8, ENC_NA);
    }
    else {
        proto_tree_add_item_ret_uint(tree, hf_fcfcs_list_length, tvb, offset+3, 1, ENC_NA, &tot_len);

        prevlen = 0;
        len = tvb_strsize(tvb, offset+4);
        proto_tree_add_item (tree, hf_fcs_vendorname, tvb, offset+4,
                len, ENC_ASCII);
        prevlen += len;

        len = tvb_strsize(tvb, offset+4+prevlen);
        proto_tree_add_item (tree, hf_fcs_modelname, tvb, offset+4+prevlen,
                len, ENC_ASCII);
        prevlen += len;

        len = tvb_strsize(tvb, offset+4+prevlen);
        proto_tree_add_item (tree, hf_fcs_releasecode, tvb,
                offset+4+prevlen, len, ENC_ASCII);
        prevlen += len;
        offset += (4+prevlen);
        while (tot_len > prevlen) {
            len = tvb_strsize(tvb, offset);
            proto_tree_add_item(tree, hf_fcfcs_vendor_specific_information, tvb, offset, len, ENC_NA|ENC_ASCII);
            prevlen += len;
            offset += len;
        }
    }
}

static void
dissect_fcfcs_gpl (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */
    guint32 numelem, i;

    if (tree) {
        if (isreq) {
            proto_tree_add_item (tree, hf_fcs_iename, tvb, offset, 8, ENC_NA);
        }
        else {
            proto_tree_add_item_ret_uint(tree, hf_fcfcs_num_port_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &numelem);
            offset += 4;

            for (i = 0; i < numelem; i++) {
                proto_tree_add_item (tree, hf_fcs_portname, tvb, offset, 8, ENC_NA);
                proto_tree_add_item (tree, hf_fcs_portmodtype, tvb, offset+9,
                                     1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_fcs_porttxtype, tvb, offset+10,
                                     1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_fcs_porttype, tvb, offset+11,
                                     1, ENC_BIG_ENDIAN);
                offset += 12;
            }
        }
    }
}

static void
dissect_fcfcs_gpt (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */

    if (tree) {
        if (isreq) {
            proto_tree_add_item (tree, hf_fcs_portname, tvb, offset, 8, ENC_NA);
        }
        else {
            proto_tree_add_item (tree, hf_fcs_porttype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        }
    }
}

static void
dissect_fcfcs_gppn (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */

    if (tree) {
        if (isreq) {
            proto_tree_add_item (tree, hf_fcs_portname, tvb, offset, 8, ENC_NA);
        }
        else {
            proto_tree_add_item (tree, hf_fcs_physportnum, tvb, offset, 4, ENC_NA);
        }
    }
}

static void
dissect_fcfcs_gapnl (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */
    guint32 numelem, i;

    if (tree) {
        if (isreq) {
            proto_tree_add_item (tree, hf_fcs_portname, tvb, offset, 8, ENC_NA);
        }
        else {
            proto_tree_add_item_ret_uint(tree, hf_fcfcs_num_attached_port_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &numelem);
            offset += 4;
            for (i = 0; i < numelem; i++) {
                proto_tree_add_item (tree, hf_fcs_portname, tvb, offset, 8, ENC_NA);
                proto_tree_add_item (tree, hf_fcs_portflags, tvb, offset+10,
                                     1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_fcs_porttype, tvb, offset+11,
                                     1, ENC_BIG_ENDIAN);
                offset += 12;
            }
        }
    }
}

static void
dissect_fcfcs_gps (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */

    if (tree) {
        if (isreq) {
            proto_tree_add_item (tree, hf_fcs_portname, tvb, offset, 8, ENC_NA);
        }
        else {
            proto_tree_add_item (tree, hf_fcs_porttype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_fcs_portstate, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        }
    }
}

static void
dissect_fcfcs_gplnl (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */
    guint32 numelem, i, len;

    if (tree) {
        if (isreq) {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_uint(tree, hf_fcs_platformname_len, tvb, offset, 1, len);
            proto_tree_add_item (tree, hf_fcs_platformname, tvb, offset+1,
                                 len, ENC_NA);
        }
        else {
            proto_tree_add_item_ret_uint(tree, hf_fcfcs_num_platform_node_name_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &numelem);
            offset += 4;
            for (i = 0; i < numelem; i++) {
                proto_tree_add_item (tree, hf_fcs_platformnname, tvb, offset,
                                       8, ENC_NA);
                offset += 8;
            }
        }
    }
}

static void
dissect_fcfcs_gplt (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */
    int len;

    if (tree) {
        if (isreq) {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_uint(tree, hf_fcs_platformname_len, tvb, offset, 1, len);
            proto_tree_add_item (tree, hf_fcs_platformname, tvb, offset+1,
                                 len, ENC_NA);
        }
        else {
            proto_tree_add_item (tree, hf_fcs_platformtype, tvb, offset+3,
                                 1, ENC_BIG_ENDIAN);
        }
    }
}

static void
dissect_fcfcs_gplml (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */
    guint32 numelem, i, len;

    if (tree) {
        if (isreq) {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_uint(tree, hf_fcs_platformname_len, tvb, offset, 1, len);
            proto_tree_add_item (tree, hf_fcs_platformname, tvb, offset+1,
                                 len, ENC_NA);
        }
        else {
            proto_tree_add_item_ret_uint(tree, hf_fcfcs_num_mgmt_address_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &numelem);
            offset += 4;
            for (i = 0; i < numelem; i++) {
                proto_tree_add_item (tree, hf_fcs_platformaddr, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
                offset += 256;
            }
        }
    }
}

static void
dissect_fcfcs_gnpl (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */
    int len;

    if (tree) {
        if (isreq) {
            proto_tree_add_item (tree, hf_fcs_platformnname, tvb, offset, 8, ENC_NA);
        }
        else {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_uint (tree, hf_fcs_platformname_len, tvb, offset, 1, len);
            proto_tree_add_item (tree, hf_fcs_platformname, tvb, offset+1,
                                 len, ENC_NA);
        }
    }
}

static void
dissect_fcfcs_gpnl (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16; /* past the fcct header */
    guint32 numelem, i, len;

    if (tree) {
        if (!isreq) {
            proto_tree_add_item_ret_uint(tree, hf_fcfcs_num_platform_name_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &numelem);
            offset += 4;
            for (i = 0; i < numelem; i++) {
                len = tvb_get_guint8 (tvb, offset);
                proto_tree_add_uint (tree, hf_fcs_platformname_len, tvb, offset, 1, len);
                proto_tree_add_item (tree, hf_fcs_platformname, tvb, offset+1,
                                     len, ENC_NA);
                offset += 256;
            }
        }
    }
}

static void
dissect_fcfcs_rieln (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (tree) {
        if (isreq) {
            proto_tree_add_item (tree, hf_fcs_iename, tvb, offset, 8, ENC_NA);
            proto_tree_add_item (tree, hf_fcs_lname, tvb, offset+8, 1, ENC_ASCII|ENC_BIG_ENDIAN);
        }
    }
}

static void
dissect_fcfcs_rpl (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint32 numelem, i, len;

    if (tree) {
        if (isreq) {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_uint (tree, hf_fcs_platformname_len, tvb, offset, 1, len);
            proto_tree_add_item (tree, hf_fcs_platformname, tvb, offset+1,
                                 len, ENC_NA);
            proto_tree_add_item (tree, hf_fcs_platformtype, tvb, offset+256, 4,
                                 ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_uint(tree, hf_fcfcs_num_mgmt_address_entries, tvb, offset+260, 4, ENC_BIG_ENDIAN, &numelem);
            offset += 264;
            for (i = 0; i < numelem; i++) {
                proto_tree_add_item (tree, hf_fcs_mgmtaddr, tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
                offset += 256;
            }

            proto_tree_add_item_ret_uint(tree, hf_fcfcs_num_platform_node_name_entries, tvb, offset, 4, ENC_BIG_ENDIAN, &numelem);
            offset += 4;
            for (i = 0; i < numelem; i++) {
                proto_tree_add_item (tree, hf_fcs_platformnname, tvb, offset, 8, ENC_NA);
                offset += 8;
            }
        }
    }
}

static void
dissect_fcfcs_rpln (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int len;

    if (tree) {
        if (isreq) {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_uint (tree, hf_fcs_platformname_len, tvb, offset, 1, len);
            proto_tree_add_item (tree, hf_fcs_platformname, tvb, offset+1,
                                 len, ENC_NA);
            proto_tree_add_item (tree, hf_fcs_platformnname, tvb, offset+256,
                                   8, ENC_NA);
        }
    }
}

static void
dissect_fcfcs_rplt (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int len;

    if (tree) {
        if (isreq) {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_uint (tree, hf_fcs_platformname_len, tvb, offset, 1, len);
            proto_tree_add_item (tree, hf_fcs_platformname, tvb, offset+1,
                                 len, ENC_NA);
            proto_tree_add_item (tree, hf_fcs_platformtype, tvb, offset+256,
                                 4, ENC_BIG_ENDIAN);
        }
    }
}

static void
dissect_fcfcs_rplm (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int len;

    if (tree) {
        if (isreq) {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_uint (tree, hf_fcs_platformname_len, tvb, offset, 1, len);
            proto_tree_add_item (tree, hf_fcs_platformname, tvb, offset+1,
                                 len, ENC_NA);
            proto_tree_add_item (tree, hf_fcs_platformaddr, tvb, offset+256,
                                 1, ENC_ASCII|ENC_BIG_ENDIAN);
        }
    }
}

static void
dissect_fcfcs_dpl (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int len;

    if (tree) {
        if (isreq) {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_uint (tree, hf_fcs_platformname_len, tvb, offset, 1, len);
            proto_tree_add_item (tree, hf_fcs_platformname, tvb, offset+1,
                                 len, ENC_NA);
        }
    }
}

static void
dissect_fcfcs_dpln (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (tree) {
        if (isreq) {
            proto_tree_add_item(tree, hf_fcs_platformnname, tvb, offset, 8, ENC_NA);
        }
    }
}

static void
dissect_fcfcs_dplml (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int len;

    if (tree) {
        if (isreq) {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_uint (tree, hf_fcs_platformname_len, tvb, offset, 1, len);
            proto_tree_add_item (tree, hf_fcs_platformname, tvb, offset+1,
                                 len, ENC_NA);
        }
    }
}

static void
dissect_fcfcs_gcap (tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int numrec, i;
    guint8 subtype;

    if (tree) {
        if (!isreq) {
            numrec = tvb_get_ntohl (tvb, offset);
            proto_tree_add_item (tree, hf_fcs_numcap, tvb, offset, 4, ENC_BIG_ENDIAN);

            offset += 4;
            for (i = 0; i < numrec; i++) {
                subtype = tvb_get_guint8 (tvb, offset);
                proto_tree_add_uint (tree, hf_fcs_mgmt_subtype, tvb, offset,
                                     1, subtype);

                proto_tree_add_item (tree, hf_fcs_vnd_capmask, tvb, offset+1,
                                     3, ENC_BIG_ENDIAN);
                if (subtype == FCCT_GSSUBTYPE_FCS) {
                    proto_tree_add_item (tree, hf_fcs_fcsmask, tvb, offset+4,
                                         4, ENC_BIG_ENDIAN);
                }
                else if (subtype == FCCT_GSSUBTYPE_UNS) {
                    proto_tree_add_item (tree, hf_fcs_unsmask, tvb, offset+4,
                                         4, ENC_BIG_ENDIAN);
                }
                offset += 8;
            }
        }
    }
}

static void
dissect_fcfcs_rjt (tvbuff_t *tvb, proto_tree *tree)
{
    int offset = 0;

    if (tree) {
        proto_tree_add_item (tree, hf_fcs_reason, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_fcs_rjtdetail, tvb, offset+14, 1,
                             ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_fcs_vendor, tvb, offset+15, 1, ENC_BIG_ENDIAN);
    }

}

static int
dissect_fcfcs (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{

/* Set up structures needed to add the protocol subtree and manage it */
    int offset = 0;
    proto_item *ti;
    proto_tree *fcfcs_tree = NULL;
    fc_ct_preamble cthdr;
    gboolean isreq = 1;
    conversation_t *conversation;
    fcfcs_conv_data_t *cdata;
    fcfcs_conv_key_t ckey, *req_key;
    int opcode,
        failed_opcode = 0;
    fc_hdr *fchdr;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    fchdr = (fc_hdr *)data;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FC-FCS");

    ti = proto_tree_add_protocol_format (tree, proto_fcfcs, tvb, 0,
                                            tvb_reported_length (tvb),
                                            "FCS");
    fcfcs_tree = proto_item_add_subtree (ti, ett_fcfcs);

    tvb_memcpy (tvb, (guint8 *)&cthdr, offset, FCCT_PRMBL_SIZE);
    cthdr.revision = tvb_get_guint8 (tvb, offset);
    cthdr.in_id = tvb_get_ntoh24 (tvb, offset+1);
    cthdr.opcode = g_ntohs (cthdr.opcode);
    opcode = tvb_get_ntohs (tvb, offset+8);
    cthdr.maxres_size = g_ntohs (cthdr.maxres_size);

    if ((opcode != FCCT_MSG_ACC) && (opcode != FCCT_MSG_RJT)) {
        conversation = find_conversation (pinfo->num, &pinfo->src, &pinfo->dst,
                                          conversation_pt_to_conversation_type(pinfo->ptype), fchdr->oxid,
                                          fchdr->rxid, NO_PORT_B);
        if (!conversation) {
            conversation = conversation_new (pinfo->num, &pinfo->src, &pinfo->dst,
                                             conversation_pt_to_conversation_type(pinfo->ptype), fchdr->oxid,
                                             fchdr->rxid, NO_PORT2);
        }

        ckey.conv_idx = conversation->conv_index;

        cdata = (fcfcs_conv_data_t *)wmem_map_lookup (fcfcs_req_hash,
                                                            &ckey);
        if (cdata) {
            /* Since we never free the memory used by an exchange, this maybe a
             * case of another request using the same exchange as a previous
             * req.
             */
            cdata->opcode = opcode;
        }
        else {
            req_key = wmem_new(wmem_file_scope(), fcfcs_conv_key_t);
            req_key->conv_idx = conversation->conv_index;

            cdata = wmem_new(wmem_file_scope(), fcfcs_conv_data_t);
            cdata->opcode = opcode;

            wmem_map_insert (fcfcs_req_hash, req_key, cdata);
        }
        col_add_str (pinfo->cinfo, COL_INFO,
                         val_to_str (opcode, fc_fcs_opcode_abbrev_val, "0x%x"));
    }
    else {
        /* Opcode is ACC or RJT */
        conversation = find_conversation (pinfo->num, &pinfo->src, &pinfo->dst,
                                          conversation_pt_to_conversation_type(pinfo->ptype), fchdr->oxid,
                                          fchdr->rxid, NO_PORT_B);
        isreq = 0;
        if (!conversation) {
            if (opcode == FCCT_MSG_ACC) {
                col_add_str (pinfo->cinfo, COL_INFO,
                                 val_to_str (opcode, fc_fcs_opcode_abbrev_val,
                                             "0x%x"));
                /* No record of what this accept is for. Can't decode */
                proto_tree_add_expert(fcfcs_tree, pinfo, &ei_fcfcs_no_record_of_exchange, tvb, 0, -1);
                return 0;
            }
        }
        else {
            ckey.conv_idx = conversation->conv_index;

            cdata = (fcfcs_conv_data_t *)wmem_map_lookup (fcfcs_req_hash,
                                                              &ckey);

            if (cdata != NULL) {
                if (opcode == FCCT_MSG_ACC)
                    opcode = cdata->opcode;
                else
                    failed_opcode = cdata->opcode;
            }

            if (opcode != FCCT_MSG_RJT) {
                col_add_fstr (pinfo->cinfo, COL_INFO, "MSG_ACC (%s)",
                                val_to_str (opcode, fc_fcs_opcode_abbrev_val,
                                            "0x%x"));
            }
            else {
                col_add_fstr (pinfo->cinfo, COL_INFO, "MSG_RJT (%s)",
                                val_to_str (failed_opcode,
                                            fc_fcs_opcode_abbrev_val,
                                            "0x%x"));
            }

            if ((cdata == NULL) && (opcode != FCCT_MSG_RJT)) {
                /* No record of what this accept is for. Can't decode */
                proto_tree_add_expert(fcfcs_tree, pinfo, &ei_fcfcs_no_record_of_exchange, tvb, 0, -1);
                return 0;
            }
        }
    }


    if (tree) {
        proto_tree_add_item (fcfcs_tree, hf_fcs_opcode, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (fcfcs_tree, hf_fcs_maxres_size, tvb, offset+10,
                             2, ENC_BIG_ENDIAN);
    }

    switch (opcode) {
    case FCCT_MSG_RJT:
        dissect_fcfcs_rjt (tvb, fcfcs_tree);
        break;
    case FCFCS_GIEL:
        dissect_fcfcs_giel (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GIET:
        dissect_fcfcs_giet (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GDID:
        dissect_fcfcs_gdid (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GMID:
        dissect_fcfcs_gmid (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GFN:
        dissect_fcfcs_gfn (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GIELN:
        dissect_fcfcs_gieln (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GMAL:
        dissect_fcfcs_gmal (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GIEIL:
        dissect_fcfcs_gieil (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GPL:
        dissect_fcfcs_gpl (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GPT:
        dissect_fcfcs_gpt (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GPPN:
        dissect_fcfcs_gppn (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GAPNL:
        dissect_fcfcs_gapnl (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GPS:
        dissect_fcfcs_gps (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GPLNL:
        dissect_fcfcs_gplnl (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GPLT:
        dissect_fcfcs_gplt (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GPLML:
        dissect_fcfcs_gplml (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GNPL:
        dissect_fcfcs_gnpl (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GPNL:
        dissect_fcfcs_gpnl (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_RIELN:
        dissect_fcfcs_rieln (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_RPL:
        dissect_fcfcs_rpl (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_RPLN:
        dissect_fcfcs_rpln (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_RPLT:
        dissect_fcfcs_rplt (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_RPLM:
        dissect_fcfcs_rplm (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_DPL:
        dissect_fcfcs_dpl (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_DPLN:
        dissect_fcfcs_dpln (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_DPLML:
        dissect_fcfcs_dplml (tvb, fcfcs_tree, isreq);
        break;
    case FCFCS_GCAP:
        dissect_fcfcs_gcap (tvb, fcfcs_tree, isreq);
        break;
    default:
        call_data_dissector(tvb, pinfo, fcfcs_tree);
        break;
    }

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */

void
proto_register_fcfcs (void)
{

    static hf_register_info hf[] = {
        { &hf_fcs_opcode,
          {"Opcode", "fcs.opcode", FT_UINT16, BASE_HEX,
           VALS (fc_fcs_opcode_val), 0x0, NULL, HFILL}},
        { &hf_fcs_iename,
          {"Interconnect Element Name", "fcs.ie.name", FT_FCWWN, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcs_ietype,
          {"Interconnect Element Type", "fcs.ie.type", FT_UINT8, BASE_HEX,
           VALS (fc_fcs_ietype_val), 0x0, NULL, HFILL}},
        { &hf_fcs_iedomainid,
          {"Interconnect Element Domain ID", "fcs.ie.domainid", FT_UINT8,
           BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_fcs_mgmtid,
          {"Interconnect Element Mgmt. ID", "fcs.ie.mgmtid", FT_BYTES,
           SEP_DOT, NULL, 0x0, NULL, HFILL}},
        { &hf_fcs_fabricname,
          {"Interconnect Element Fabric Name", "fcs.ie.fname", FT_FCWWN,
           BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_fcs_mgmtaddr,
          {"Interconnect Element Mgmt. Address", "fcs.ie.mgmtaddr", FT_UINT_STRING,
           BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_fcs_lname,
          {"Interconnect Element Logical Name", "fcs.ie.logname", FT_UINT_STRING,
           BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_fcs_vendorname,
          {"Vendor Name", "fcs.vendorname", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcs_modelname,
          {"Model Name/Number", "fcs.modelname", FT_STRING, BASE_NONE, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcs_portname,
          {"Port Name", "fcs.port.name", FT_FCWWN, BASE_NONE, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fcs_portmodtype,
          {"Port Module Type", "fcs.port.moduletype", FT_UINT8, BASE_HEX,
           VALS (fc_fcs_port_modtype_val), 0x0, NULL, HFILL}},
        { &hf_fcs_porttxtype,
          {"Port TX Type", "fcs.port.txtype", FT_UINT8, BASE_HEX,
           VALS (fc_fcs_port_txtype_val), 0x0, NULL, HFILL}},
        { &hf_fcs_porttype,
          {"Port Type", "fcs.port.type", FT_UINT8, BASE_HEX,
           VALS (fc_fcs_port_type_val), 0x0, NULL, HFILL}},
        { &hf_fcs_physportnum,
          {"Physical Port Number", "fcs.port.physportnum", FT_BYTES, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcs_portflags,
          {"Port Flags", "fcs.port.flags", FT_BOOLEAN, BASE_NONE,
           TFS (&fc_fcs_portflags_tfs), 0x0, NULL, HFILL}},
        { &hf_fcs_portstate,
          {"Port State", "fcs.port.state", FT_UINT8, BASE_HEX,
           VALS (fc_fcs_port_state_val), 0x0, NULL, HFILL}},
        { &hf_fcs_platformname_len,
          {"Platform Name Length", "fcs.platform.len", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcs_platformname,
          {"Platform Name", "fcs.platform.name", FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
        { &hf_fcs_platformnname,
          {"Platform Node Name", "fcs.platform.nodename", FT_FCWWN, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcs_platformtype,
          {"Platform Type", "fcs.platform.type", FT_UINT8, BASE_HEX,
           VALS (fc_fcs_plat_type_val), 0x0, NULL, HFILL}},
        { &hf_fcs_platformaddr,
          {"Management Address", "fcs.platform.mgmtaddr", FT_UINT_STRING, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcs_reason,
          {"Reason Code", "fcs.reason", FT_UINT8, BASE_HEX,
           VALS (fc_ct_rjt_code_vals), 0x0, NULL, HFILL}},
        { &hf_fcs_rjtdetail,
          {"Reason Code Explanation", "fcs.reasondet", FT_UINT8, BASE_HEX,
           VALS (fc_fcs_rjt_code_val), 0x0, NULL, HFILL}},
        { &hf_fcs_vendor,
          {"Vendor Unique Reject Code", "fcs.err.vendor", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcs_numcap,
          {"Number of Capabilities", "fcs.numcap", FT_UINT32, BASE_DEC, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcs_mgmt_subtype,
          {"Management GS Subtype", "fcs.gssubtype", FT_UINT8, BASE_HEX, NULL,
           0x0, NULL, HFILL}},
        { &hf_fcs_vnd_capmask,
          {"Vendor Unique Capability Bitmask", "fcs.vbitmask", FT_UINT24,
           BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_fcs_fcsmask,
          {"Subtype Capability Bitmask", "fcs.fcsmask", FT_UINT32, BASE_HEX,
           VALS (fc_fcs_fcsmask_val), 0x0, NULL, HFILL}},
        { &hf_fcs_unsmask,
          {"Subtype Capability Bitmask", "fcs.unsmask", FT_UINT32, BASE_HEX,
           VALS (fc_fcs_unsmask_val), 0x0, NULL, HFILL}},
        { &hf_fcs_maxres_size,
          {"Maximum/Residual Size", "fcs.maxres_size", FT_UINT16, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcs_releasecode,
          {"Release Code", "fcs.releasecode", FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
        /* Generated from convert_proto_tree_add_text.pl */
        { &hf_fcfcs_num_ie_entries, { "Number of IE entries", "fcfcs.num_ie_entries", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_fcfcs_num_mgmt_addresses, { "Number of Mgmt. Addresses", "fcfcs.num_mgmt_addresses", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_fcfcs_list_length, { "List Length", "fcfcs.list_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_fcfcs_vendor_specific_information, { "Vendor-specific Information", "fcfcs.vendor_specific_information", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_fcfcs_num_port_entries, { "Number of Port Entries", "fcfcs.num_port_entries", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_fcfcs_num_attached_port_entries, { "Number of Attached Port Entries", "fcfcs.num_attached_port_entries", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_fcfcs_num_platform_node_name_entries, { "Number of Platform Node Name Entries", "fcfcs.num_platform_node_name_entries", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_fcfcs_num_mgmt_address_entries, { "Number of Mgmt. Address Entries", "fcfcs.num_mgmt_address_entries", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_fcfcs_num_platform_name_entries, { "Number of Platform Name Entries", "fcfcs.num_platform_name_entries", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_fcfcs,
    };

    static ei_register_info ei[] = {
        /* Generated from convert_proto_tree_add_text.pl */
        { &ei_fcfcs_no_record_of_exchange, { "fcfcs.no_record_of_exchange", PI_UNDECODED, PI_WARN, "No record of Exchg. Unable to decode MSG_ACC/RJT", EXPFILL }},
    };

    expert_module_t* expert_fcfcs;

    proto_fcfcs = proto_register_protocol("FC Fabric Configuration Server",
                                          "FC-FCS", "fcs");

    proto_register_field_array(proto_fcfcs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_fcfcs = expert_register_protocol(proto_fcfcs);
    expert_register_field_array(expert_fcfcs, ei, array_length(ei));

    fcfcs_req_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), fcfcs_hash, fcfcs_equal);
}

void
proto_reg_handoff_fcfcs (void)
{
    dissector_handle_t fcs_handle;

    fcs_handle = create_dissector_handle (dissect_fcfcs, proto_fcfcs);

    dissector_add_uint("fcct.server", FCCT_GSRVR_FCS, fcs_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
