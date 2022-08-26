/* packet-fcfzs.c
 * Routines for FC Fabric Zone Server
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
#include "packet-fcfzs.h"

void proto_register_fcfzs(void);
void proto_reg_handoff_fcfzs(void);

/* Initialize the protocol and registered fields */
static int proto_fcfzs                     = -1;
static int hf_fcfzs_opcode                 = -1;
static int hf_fcfzs_gzc_vendor             = -1;
static int hf_fcfzs_gest_vendor            = -1;
static int hf_fcfzs_numzoneattrs           = -1;
static int hf_fcfzs_zonesetnmlen           = -1;
static int hf_fcfzs_zonesetname            = -1;
static int hf_fcfzs_numzones               = -1;
static int hf_fcfzs_numzonesetattrs        = -1;
static int hf_fcfzs_zonenmlen              = -1;
static int hf_fcfzs_zonename               = -1;
static int hf_fcfzs_nummbrs                = -1;
static int hf_fcfzs_nummbrentries          = -1;
static int hf_fcfzs_mbrid_fcwwn            = -1;
static int hf_fcfzs_mbrid_fc               = -1;
static int hf_fcfzs_mbrid_uint             = -1;
/* static int hf_fcfzs_mbridlen               = -1; */
static int hf_fcfzs_mbrtype                = -1;
static int hf_fcfzs_reason                 = -1;
static int hf_fcfzs_rjtdetail              = -1;
static int hf_fcfzs_rjtvendor              = -1;
static int hf_fcfzs_maxres_size            = -1;
static int hf_fcfzs_mbrid_lun              = -1;
static int hf_fcfzs_gzc_flags              = -1;
static int hf_fcfzs_gzc_flags_hard_zones   = -1;
static int hf_fcfzs_gzc_flags_soft_zones   = -1;
static int hf_fcfzs_gzc_flags_zoneset_db   = -1;
static int hf_fcfzs_zone_state             = -1;
static int hf_fcfzs_soft_zone_set_enforced = -1;
static int hf_fcfzs_hard_zone_set_enforced = -1;

/* Initialize the subtree pointers */
static gint ett_fcfzs = -1;
static gint ett_fcfzs_gzc_flags = -1;
static gint ett_fcfzs_zone_state = -1;

static expert_field ei_fcfzs_no_exchange = EI_INIT;
static expert_field ei_fcfzs_mbrid = EI_INIT;

typedef struct _fcfzs_conv_key {
    guint32 conv_idx;
} fcfzs_conv_key_t;

typedef struct _fcfzs_conv_data {
    guint32 opcode;
} fcfzs_conv_data_t;

static wmem_map_t *fcfzs_req_hash = NULL;

/*
 * Hash Functions
 */
static gint
fcfzs_equal(gconstpointer v, gconstpointer w)
{
    const fcfzs_conv_key_t *v1 = (const fcfzs_conv_key_t *)v;
    const fcfzs_conv_key_t *v2 = (const fcfzs_conv_key_t *)w;

    return (v1->conv_idx == v2->conv_idx);
}

static guint
fcfzs_hash(gconstpointer v)
{
    const fcfzs_conv_key_t *key = (const fcfzs_conv_key_t *)v;
    guint val;

    val = key->conv_idx;

    return val;
}

/* Code to actually dissect the packets */
static void
dissect_fcfzs_zoneset(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset)
{
    int numzones, nummbrs, i, j, len;
    proto_item* ti;

    /* The zoneset structure has the following format */
    /* zoneset name (len[not including pad], name, pad),
     * number of zones,
     * for each zone,
     *     Zone name (len[not including pad], name, pad), num zone mbrs
     *     for each zone mbr,
     *         zone mbr id type, zone mbr id (len, name, pad)
     */

        /* Zoneset Name */
        len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_fcfzs_zonesetnmlen, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fcfzs_zonesetname, tvb, offset+4,
                            len, ENC_ASCII);
        offset += 4 + len + (4-(len % 4));


        /* Number of zones */
        numzones = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(tree, hf_fcfzs_numzones, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        /* For each zone... */
        for (i = 0; i < numzones; i++) {
            len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_fcfzs_zonenmlen, tvb, offset,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_fcfzs_zonename, tvb, offset+4,
                                len, ENC_ASCII);
            offset += 4 + len + (4-(len % 4));

            nummbrs = tvb_get_ntohl(tvb, offset);
            proto_tree_add_item(tree, hf_fcfzs_nummbrentries, tvb, offset,
                                4, ENC_BIG_ENDIAN);

            offset += 4;
            for (j = 0; j < nummbrs; j++) {
                ti = proto_tree_add_item(tree, hf_fcfzs_mbrtype, tvb, offset, 1, ENC_BIG_ENDIAN);

                switch (tvb_get_guint8(tvb, offset)) {
                case FC_FZS_ZONEMBR_PWWN:
                case FC_FZS_ZONEMBR_NWWN:
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_fcwwn, tvb,
                                          offset+4, 8, ENC_NA);
                    break;
                case FC_FZS_ZONEMBR_DP:
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_uint,
                                                 tvb, offset+4, 3, ENC_BIG_ENDIAN);
                    break;
                case FC_FZS_ZONEMBR_FCID:
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_fc, tvb,
                                          offset+4, 3, ENC_NA);
                    break;
                case FC_FZS_ZONEMBR_PWWN_LUN:
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_fcwwn, tvb,
                                          offset+4, 8, ENC_NA);
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_lun, tvb,
                                        offset+8, 8, ENC_NA);
                    break;
                case FC_FZS_ZONEMBR_DP_LUN:
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_uint,
                                                 tvb, offset+4, 3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_lun, tvb,
                                        offset+4, 8, ENC_NA);
                    break;
                case FC_FZS_ZONEMBR_FCID_LUN:
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_fc, tvb,
                                          offset+4, 3, ENC_NA);
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_lun, tvb,
                                        offset+4, 8, ENC_NA);
                    break;
                default:
                    expert_add_info(pinfo, ti, &ei_fcfzs_mbrid);
                }
                offset += 12;
            }
        }
}


static void
dissect_fcfzs_gzc(tvbuff_t *tvb, int offset, proto_tree *parent_tree, gboolean isreq)
{
    static int * const flags[] = {
        &hf_fcfzs_gzc_flags_hard_zones,
        &hf_fcfzs_gzc_flags_soft_zones,
        &hf_fcfzs_gzc_flags_zoneset_db,
        NULL
    };

    if (!isreq) {
        proto_tree_add_bitmask_with_flags(parent_tree, tvb, offset, hf_fcfzs_gzc_flags,
                                   ett_fcfzs_gzc_flags, flags, ENC_NA, BMT_NO_FALSE|BMT_NO_TFS);

        proto_tree_add_item(parent_tree, hf_fcfzs_gzc_vendor, tvb, offset+4, 4, ENC_BIG_ENDIAN);
    }
}

static void
dissect_fcfzs_gest(tvbuff_t *tvb, proto_tree *parent_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    static int * const flags[] = {
        &hf_fcfzs_soft_zone_set_enforced,
        &hf_fcfzs_hard_zone_set_enforced,
        NULL
    };

    if (!isreq) {
        proto_tree_add_bitmask_with_flags(parent_tree, tvb, offset, hf_fcfzs_zone_state,
                                   ett_fcfzs_zone_state, flags, ENC_NA, BMT_NO_FALSE|BMT_NO_TFS);

        proto_tree_add_item(parent_tree, hf_fcfzs_gest_vendor, tvb, offset+4, 4, ENC_BIG_ENDIAN);
    }
}

static void
dissect_fcfzs_gzsn(tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int numrec, i, len;
    int offset = 16;            /* past the fc_ct header */

    if (tree) {
        if (!isreq) {
            numrec = tvb_get_ntohl(tvb, offset);

            proto_tree_add_item(tree, hf_fcfzs_numzonesetattrs, tvb, offset,
                                4, ENC_BIG_ENDIAN);

            offset += 4;
            for (i = 0; i < numrec; i++) {
                len = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree, hf_fcfzs_zonesetnmlen, tvb, offset,
                                    1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_fcfzs_zonesetname, tvb, offset+1,
                                    len, ENC_ASCII);
                offset += len + 1 + (len % 4);
                proto_tree_add_item(tree, hf_fcfzs_numzones, tvb, offset,
                                    4, ENC_BIG_ENDIAN);
                offset += 4;
            }
        }
    }
}

static void
dissect_fcfzs_gzd(tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int numrec, i, len;
    int offset = 16;            /* past the fc_ct header */

    if (tree) {
        if (isreq) {
            len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_fcfzs_zonesetnmlen, tvb, offset,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_fcfzs_zonesetname, tvb, offset+1,
                                len, ENC_ASCII);
        }
        else {
            numrec = tvb_get_ntohl(tvb, offset);

            proto_tree_add_item(tree, hf_fcfzs_numzoneattrs, tvb, offset,
                                4, ENC_BIG_ENDIAN);

            offset += 4;
            for (i = 0; i < numrec; i++) {
                len = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree, hf_fcfzs_zonenmlen, tvb, offset,
                                    1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_fcfzs_zonename, tvb, offset+1,
                                    len, ENC_ASCII);
                offset += len + 1 + (len % 4);
                proto_tree_add_item(tree, hf_fcfzs_nummbrs, tvb, offset,
                                    4, ENC_BIG_ENDIAN);
                offset += 4;
            }
        }
    }
}

static void
dissect_fcfzs_gzm(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, gboolean isreq)
{
    int numrec, i, len;
    int offset = 16;            /* past the fc_ct header */
    proto_item* ti;

        if (isreq) {
            len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_fcfzs_zonenmlen, tvb, offset,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_fcfzs_zonename, tvb, offset+1,
                                len, ENC_ASCII);
        }
        else {
            numrec = tvb_get_ntohl(tvb, offset);

            proto_tree_add_item(tree, hf_fcfzs_nummbrentries, tvb, offset,
                                4, ENC_BIG_ENDIAN);
            offset += 4;
            for (i = 0; i < numrec; i++) {
                ti = proto_tree_add_item(tree, hf_fcfzs_mbrtype, tvb, offset, 1, ENC_BIG_ENDIAN);
                switch (tvb_get_guint8(tvb, offset)) {
                case FC_FZS_ZONEMBR_PWWN:
                case FC_FZS_ZONEMBR_NWWN:
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_fcwwn, tvb,
                                          offset+4, 8, ENC_NA);
                    break;
                case FC_FZS_ZONEMBR_DP:
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_uint,
                                                 tvb, offset+4, 3, ENC_BIG_ENDIAN);
                    break;
                case FC_FZS_ZONEMBR_FCID:
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_fc, tvb,
                                          offset+4, 3, ENC_NA);
                    break;
                default:
                    expert_add_info(pinfo, ti, &ei_fcfzs_mbrid);
                }
                offset += 12;
            }
        }
}

static void
dissect_fcfzs_gazs(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (!isreq) {
        dissect_fcfzs_zoneset(tvb, pinfo, tree, offset);
    }
}

static void
dissect_fcfzs_gzs(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int len;

    if (isreq) {
        len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_fcfzs_zonesetnmlen, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fcfzs_zonesetname, tvb, offset+4,
                            len, ENC_ASCII);
    }
    else {
        dissect_fcfzs_zoneset(tvb, pinfo, tree, offset);
    }
}

static void
dissect_fcfzs_adzs(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        dissect_fcfzs_zoneset(tvb, pinfo, tree, offset);
    }
}

static void
dissect_fcfzs_azsd(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        dissect_fcfzs_zoneset(tvb, pinfo, tree, offset);
    }
}

static void
dissect_fcfzs_arzs(tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int len;

    if (tree) {
        if (isreq) {
            len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_fcfzs_zonesetnmlen, tvb, offset,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_fcfzs_zonesetname, tvb, offset+4,
                                len, ENC_ASCII);
        }
    }
}

static void
dissect_fcfzs_dzs(tvbuff_t *tvb _U_, proto_tree *tree _U_, gboolean isreq _U_)
{
    /* Both req & successful response contain just the FC_CT header */
    return;
}

static void
dissect_fcfzs_arzm(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, gboolean isreq)
{
    int numrec, i, len, plen;
    int offset = 16;            /* past the fc_ct header */
    proto_item* ti;

        if (isreq) {
            len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_fcfzs_zonenmlen, tvb, offset,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_fcfzs_zonename, tvb, offset+1,
                                len, ENC_ASCII);

            len += (len % 4);
            plen = tvb_reported_length(tvb) - offset - len;

            numrec = plen/12;   /* each mbr rec is 12 bytes long */

            offset += len;
            for (i = 0; i < numrec; i++) {
                ti = proto_tree_add_item(tree, hf_fcfzs_mbrtype, tvb, offset, 1, ENC_BIG_ENDIAN);
                switch (tvb_get_guint8(tvb, offset)) {
                case FC_FZS_ZONEMBR_PWWN:
                case FC_FZS_ZONEMBR_NWWN:
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_fcwwn, tvb,
                                          offset+4, 8, ENC_NA);
                    break;
                case FC_FZS_ZONEMBR_DP:
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_uint,
                                                 tvb, offset+4, 3, ENC_BIG_ENDIAN);
                    break;
                case FC_FZS_ZONEMBR_FCID:
                    proto_tree_add_item(tree, hf_fcfzs_mbrid_fc, tvb,
                                          offset+4, 3, ENC_NA);
                    break;
                default:
                    expert_add_info(pinfo, ti, &ei_fcfzs_mbrid);
                }
                offset += 12;
            }
        }
}

static void
dissect_fcfzs_arzd(tvbuff_t *tvb, proto_tree *tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int len;

    if (tree) {
        if (isreq) {
            len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_fcfzs_zonesetnmlen, tvb, offset,
                                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_fcfzs_zonesetname, tvb, offset+4,
                                len, ENC_ASCII);
            len += (len % 4);
            offset += len;

            len = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_fcfzs_zonenmlen, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_fcfzs_zonename, tvb, offset+4,
                                len, ENC_ASCII);
        }
    }
}

static void
dissect_fcfzs_rjt(tvbuff_t *tvb, proto_tree *tree)
{
    int offset = 0;

    if (tree) {
        proto_tree_add_item(tree, hf_fcfzs_reason, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fcfzs_rjtdetail, tvb, offset+14, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fcfzs_rjtvendor, tvb, offset+15, 1, ENC_BIG_ENDIAN);
    }
}

static int
dissect_fcfzs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item        *ti;
    proto_tree        *fcfzs_tree    = NULL;
    int                offset        = 0;
    fc_ct_preamble     cthdr;
    int                opcode;
    int                failed_opcode = 0;
    conversation_t    *conversation;
    fcfzs_conv_data_t *cdata;
    fcfzs_conv_key_t   ckey, *req_key;
    gboolean           isreq         = TRUE;
    fc_hdr *fchdr;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    fchdr = (fc_hdr *)data;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Zone Server");


    tvb_memcpy(tvb, (guint8 *)&cthdr, offset, FCCT_PRMBL_SIZE);
    cthdr.revision = tvb_get_guint8(tvb, offset+1);
    cthdr.in_id = tvb_get_ntoh24(tvb, offset);
    cthdr.opcode = g_ntohs(cthdr.opcode);
    opcode = cthdr.opcode;
    cthdr.maxres_size = g_ntohs(cthdr.maxres_size);

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_fcfzs, tvb, 0,
                                            tvb_captured_length(tvb),
                                            "Zone Server");
        fcfzs_tree = proto_item_add_subtree(ti, ett_fcfzs);
        proto_tree_add_item(fcfzs_tree, hf_fcfzs_opcode, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(fcfzs_tree, hf_fcfzs_maxres_size, tvb, offset+10,
                            2, ENC_BIG_ENDIAN);
    }

    if ((opcode != FCCT_MSG_ACC) && (opcode != FCCT_MSG_RJT)) {
        conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                         conversation_pt_to_conversation_type(pinfo->ptype), fchdr->oxid,
                                         fchdr->rxid, NO_PORT_B);
        if (!conversation) {
            conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst,
                                            conversation_pt_to_conversation_type(pinfo->ptype), fchdr->oxid,
                                            fchdr->rxid, NO_PORT2);
        }

        ckey.conv_idx = conversation->conv_index;

        cdata = (fcfzs_conv_data_t *)wmem_map_lookup(fcfzs_req_hash,
                                                         &ckey);
        if (cdata) {
            /* Since we never free the memory used by an exchange, this maybe a
             * case of another request using the same exchange as a previous
             * req.
             */
            cdata->opcode = opcode;
        }
        else {
            req_key = wmem_new(wmem_file_scope(), fcfzs_conv_key_t);
            req_key->conv_idx = conversation->conv_index;

            cdata = wmem_new(wmem_file_scope(), fcfzs_conv_data_t);
            cdata->opcode = opcode;

            wmem_map_insert(fcfzs_req_hash, req_key, cdata);
        }

        col_add_str(pinfo->cinfo, COL_INFO, val_to_str(opcode, fc_fzs_opcode_val,
                                                           "0x%x"));
    }
    else {
        /* Opcode is ACC or RJT */
        conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                         conversation_pt_to_conversation_type(pinfo->ptype), fchdr->oxid,
                                         fchdr->rxid, NO_PORT_B);
        isreq = FALSE;
        if (!conversation) {
            if (opcode == FCCT_MSG_ACC) {
                col_add_str(pinfo->cinfo, COL_INFO,
                                val_to_str(opcode, fc_fzs_opcode_val,
                                           "0x%x"));
                /* No record of what this accept is for. Can't decode */
                proto_tree_add_expert_format(fcfzs_tree, pinfo, &ei_fcfzs_no_exchange, tvb, 0, -1,
                                    "No record of Exchg. Unable to decode MSG_ACC");
                return 0;
            }
        }
        else {
            ckey.conv_idx = conversation->conv_index;

            cdata = (fcfzs_conv_data_t *)wmem_map_lookup(fcfzs_req_hash, &ckey);

            if (cdata != NULL) {
                if (opcode == FCCT_MSG_ACC)
                    opcode = cdata->opcode;
                else
                    failed_opcode = cdata->opcode;
            }

            if (opcode != FCCT_MSG_RJT) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "MSG_ACC (%s)",
                                val_to_str(opcode,
                                        fc_fzs_opcode_val, "0x%x"));
            }
            else {
                col_add_fstr(pinfo->cinfo, COL_INFO, "MSG_RJT (%s)",
                                val_to_str(failed_opcode,
                                        fc_fzs_opcode_val, "0x%x"));
            }

            if ((cdata == NULL) && (opcode != FCCT_MSG_RJT)) {
                /* No record of what this accept is for. Can't decode */
                proto_tree_add_expert_format(fcfzs_tree, pinfo, &ei_fcfzs_no_exchange, tvb, 0, -1,
                                    "No record of Exchg. Unable to decode MSG_ACC/RJT");
                return 0;
            }
        }
    }

    switch (opcode) {
    case FCCT_MSG_RJT:
        dissect_fcfzs_rjt(tvb, fcfzs_tree);
        break;
    case FC_FZS_GZC:
        dissect_fcfzs_gzc(tvb, 16, fcfzs_tree, isreq);
        break;
    case FC_FZS_GEST:
        dissect_fcfzs_gest(tvb, fcfzs_tree, isreq);
        break;
    case FC_FZS_GZSN:
        dissect_fcfzs_gzsn(tvb, fcfzs_tree, isreq);
        break;
    case FC_FZS_GZD:
        dissect_fcfzs_gzd(tvb, fcfzs_tree, isreq);
        break;
    case FC_FZS_GZM:
        dissect_fcfzs_gzm(tvb, pinfo, fcfzs_tree, isreq);
        break;
    case FC_FZS_GAZS:
        dissect_fcfzs_gazs(tvb, pinfo, fcfzs_tree, isreq);
        break;
    case FC_FZS_GZS:
        dissect_fcfzs_gzs(tvb, pinfo, fcfzs_tree, isreq);
        break;
    case FC_FZS_ADZS:
        dissect_fcfzs_adzs(tvb, pinfo, fcfzs_tree, isreq);
        break;
    case FC_FZS_AZSD:
        dissect_fcfzs_azsd(tvb, pinfo, fcfzs_tree, isreq);
        break;
    case FC_FZS_AZS:
        dissect_fcfzs_arzs(tvb, fcfzs_tree, isreq);
        break;
    case FC_FZS_DZS:
        dissect_fcfzs_dzs(tvb, fcfzs_tree, isreq);
        break;
    case FC_FZS_AZM:
        dissect_fcfzs_arzm(tvb, pinfo, fcfzs_tree, isreq);
        break;
    case FC_FZS_AZD:
        dissect_fcfzs_arzd(tvb, fcfzs_tree, isreq);
        break;
    case FC_FZS_RZM:
        dissect_fcfzs_arzm(tvb, pinfo, fcfzs_tree, isreq);
        break;
    case FC_FZS_RZD:
        dissect_fcfzs_arzd(tvb, fcfzs_tree, isreq);
        break;
    case FC_FZS_RZS:
        dissect_fcfzs_arzs(tvb, fcfzs_tree, isreq);
        break;
    default:
        call_data_dissector(tvb, pinfo, tree);
        break;
    }

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */

void
proto_register_fcfzs(void)
{

    static hf_register_info hf[] = {
        { &hf_fcfzs_opcode,
          {"Opcode", "fcfzs.opcode",
           FT_UINT16, BASE_HEX, VALS(fc_fzs_opcode_val), 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_gzc_vendor,
          {"Vendor Specific Flags", "fcfzs.gzc.vendor",
           FT_UINT32, BASE_HEX, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_gest_vendor,
          {"Vendor Specific State", "fcfzs.gest.vendor",
           FT_UINT32, BASE_HEX, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_numzoneattrs,
          {"Number of Zone Attribute Entries", "fcfzs.zone.numattrs",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_zonesetnmlen,
          {"Zone Set Name Length", "fcfzs.zoneset.namelen",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_zonesetname,
          {"Zone Set Name", "fcfzs.zoneset.name",
           FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_numzones,
          {"Number of Zones", "fcfzs.zoneset.numzones",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_numzonesetattrs,
          {"Number of Zone Set Attribute Entries", "fcfzs.zoneset.numattrs",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_zonenmlen,
          {"Zone Name Length", "fcfzs.zone.namelen",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_zonename,
          {"Zone Name", "fcfzs.zone.name",
           FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_nummbrs,
          {"Number of Zone Members", "fcfzs.zone.nummbrs",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_nummbrentries,
          {"Number of Zone Member Attribute Entries", "fcfzs.zonembr.numattrs",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_mbrtype,
          {"Zone Member Identifier Type", "fcfzs.zonembr.idtype",
           FT_UINT8, BASE_HEX, VALS(fc_fzs_zonembr_type_val), 0x0,
           NULL, HFILL}},

#if 0
        { &hf_fcfzs_mbridlen,
          {"Zone Member Identifier Length", "fcfzs.zonembr.idlen",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},
#endif

        { &hf_fcfzs_mbrid_fcwwn,
          {"Zone Member Identifier", "fcfzs.zone.mbrid.fcwwn",
           FT_FCWWN, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_mbrid_fc,
          {"Zone Member Identifier", "fcfzs.zone.mbrid.fc",
           FT_BYTES, SEP_DOT, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_mbrid_uint,
          {"Zone Member Identifier", "fcfzs.zone.mbrid.uint",
           FT_UINT24, BASE_HEX, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_reason,
          {"Reason Code", "fcfzs.reason",
           FT_UINT8, BASE_HEX, VALS(fc_ct_rjt_code_vals), 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_rjtdetail,
          {"Reason Code Explanation", "fcfzs.rjtdetail",
           FT_UINT8, BASE_HEX, VALS(fc_fzs_rjt_code_val), 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_rjtvendor,
          {"Vendor Specific Reason", "fcfzs.rjtvendor",
           FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_maxres_size,
          {"Maximum/Residual Size", "fcfzs.maxres_size",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_mbrid_lun,
          {"LUN", "fcfzs.zone.lun",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_gzc_flags,
          {"Capabilities", "fcfzs.gzc.flags",
           FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_gzc_flags_hard_zones,
          {"Hard Zones", "fcfzs.gzc.flags.hard_zones",
           FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
           NULL, HFILL}},

        { &hf_fcfzs_gzc_flags_soft_zones,
          {"Soft Zones", "fcfzs.gzc.flags.soft_zones",
           FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
           NULL, HFILL}},

        { &hf_fcfzs_gzc_flags_zoneset_db,
          {"ZoneSet Database", "fcfzs.gzc.flags.zoneset_db",
           FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x01,
           NULL, HFILL}},

        { &hf_fcfzs_zone_state,
          {"Zone State", "fcfzs.zone.state",
           FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL}},

        { &hf_fcfzs_soft_zone_set_enforced,
          {"Soft Zone Set", "fcfzs.soft_zone_set.enforced",
           FT_BOOLEAN, 8, TFS(&tfs_enforced_not_enforced), 0x80,
           NULL, HFILL}},

        { &hf_fcfzs_hard_zone_set_enforced,
          {"Hard Zone Set", "fcfzs.hard_zone_set.enforced",
           FT_BOOLEAN, 8, TFS(&tfs_enforced_not_enforced), 0x40,
           NULL, HFILL}},

    };

    static gint *ett[] = {
        &ett_fcfzs,
        &ett_fcfzs_gzc_flags,
        &ett_fcfzs_zone_state,
    };

    static ei_register_info ei[] = {
        { &ei_fcfzs_no_exchange, { "fcfzs.no_exchange", PI_UNDECODED, PI_WARN, "No record of Exchg. Unable to decode", EXPFILL }},
        { &ei_fcfzs_mbrid, { "fcfzs.mbrid.unknown_type", PI_PROTOCOL, PI_WARN, "Unknown member type format", EXPFILL }},
    };

    expert_module_t* expert_fcfzs;

    proto_fcfzs = proto_register_protocol("Fibre Channel Fabric Zone Server", "FC FZS", "fcfzs");

    proto_register_field_array(proto_fcfzs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_fcfzs = expert_register_protocol(proto_fcfzs);
    expert_register_field_array(expert_fcfzs, ei, array_length(ei));

    fcfzs_req_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), fcfzs_hash, fcfzs_equal);
}

void
proto_reg_handoff_fcfzs(void)
{
    dissector_handle_t fzs_handle;

    fzs_handle = create_dissector_handle(dissect_fcfzs, proto_fcfzs);
    dissector_add_uint("fcct.server", FCCT_GSRVR_FZS, fzs_handle);
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
