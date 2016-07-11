/* packet-shim6.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * SHIM6 support added by Matthijs Mekking <matthijs@NLnetLabs.nl>
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/in_cksum.h>
#include <epan/ipproto.h>

#include "packet-ipv6.h"

void proto_register_shim6(void);
void proto_reg_handoff_shim6(void);

/* SHIM6 header */
struct ip6_shim {
    guint8  ip6s_nxt; /* next header */
    guint8  ip6s_len; /* header extension length */
    guint8  ip6s_p;   /* P field and first 7 bits of remainder */
    /* followed by shim6 specific data*/
};

/* SHIM6 control message types */
#define SHIM6_TYPE_I1           0x01    /* 0 000 0001 */
#define SHIM6_TYPE_R1           0x02    /* 0 000 0010 */
#define SHIM6_TYPE_I2           0x03    /* 0 000 0011 */
#define SHIM6_TYPE_R2           0x04    /* 0 000 0100 */
#define SHIM6_TYPE_R1BIS        0x05    /* 0 000 0101 */
#define SHIM6_TYPE_I2BIS        0x06    /* 0 000 0110 */
#define SHIM6_TYPE_UPD_REQ      0x40    /* 0 100 0000 = 64 */
#define SHIM6_TYPE_UPD_ACK      0x41    /* 0 100 0001 = 65 */
#define SHIM6_TYPE_KEEPALIVE    0x42    /* 0 100 0010 = 66 */
#define SHIM6_TYPE_PROBE        0x43    /* 0 100 0011 = 67 */

/* SHIM6 Options */
#define SHIM6_OPT_RESPVAL       0x01    /* 0 000 0001 */
#define SHIM6_OPT_LOCLIST       0x02    /* 0 000 0010 */
#define SHIM6_OPT_LOCPREF       0x03    /* 0 000 0011 */
#define SHIM6_OPT_CGAPDM        0x04    /* 0 000 0100 */
#define SHIM6_OPT_CGASIG        0x05    /* 0 000 0101 */
#define SHIM6_OPT_ULIDPAIR      0x06    /* 0 000 0110 */
#define SHIM6_OPT_FII           0x07    /* 0 000 0111 */

/* SHIM6 Bitmasks */
#define SHIM6_BITMASK_P         0x80    /* 1 000 0000 */
#define SHIM6_BITMASK_TYPE      0x7F    /* 0 111 1111 */
#define SHIM6_BITMASK_PROTOCOL  0x01    /* 0 000 0001 */
#define SHIM6_BITMASK_SPECIFIC  0xFE    /* 1 111 1110 */
#define SHIM6_BITMASK_R         0x80    /* 1 000 0000 */
#define SHIM6_BITMASK_CT        0x7F    /* 0 111 1111 */
#define SHIM6_BITMASK_OPT_TYPE  0xFFFE  /* 1 111 1111    1 111 1110 */
#define SHIM6_BITMASK_CRITICAL  0x01    /* 0 000 0001 */
#define SHIM6_BITMASK_PRECVD    0xF0    /* 1 111 0000 */
#define SHIM6_BITMASK_PSENT     0x0F    /* 0 000 1111 */
#define SHIM6_BITMASK_STA       0xC0    /* 1 100 0000 */

/* SHIM6 Verification Methods */
#define SHIM6_VERIF_HBA         0x01    /* 0 000 0001 */
#define SHIM6_VERIF_CGA         0x02    /* 0 000 0010 */

/* SHIM6 Flags */
#define SHIM6_FLAG_BROKEN       0x01    /* 0 000 0001 */
#define SHIM6_FLAG_TEMPORARY    0x02    /* 0 000 0010 */

/* SHIM6 REAP States */
#define SHIM6_REAP_OPERATIONAL  0x00    /* 0 000 0000 */
#define SHIM6_REAP_EXPLORING    0x01    /* 0 000 0001 */
#define SHIM6_REAP_INBOUNDOK    0x02    /* 0 000 0010 */

static int proto_shim6                     = -1;

static int hf_shim6_nxt            = -1;
static int hf_shim6_len            = -1;
static int hf_shim6_len_oct        = -1;
static int hf_shim6_p              = -1;
/* context tag is 49 bits, cannot be used for filter yet */
static int hf_shim6_ct             = -1;
static int hf_shim6_type           = -1;
static int hf_shim6_proto          = -1;
static int hf_shim6_checksum       = -1;
static int hf_shim6_checksum_status= -1;
static int hf_shim6_inonce         = -1; /* also for request nonce */
static int hf_shim6_rnonce         = -1;
static int hf_shim6_reserved       = -1;
static int hf_shim6_reserved2      = -1;
static int hf_shim6_precvd         = -1;
static int hf_shim6_psent          = -1;
static int hf_shim6_psrc           = -1;
static int hf_shim6_pdst           = -1;
static int hf_shim6_pnonce         = -1;
static int hf_shim6_pdata          = -1;
static int hf_shim6_sulid          = -1;
static int hf_shim6_rulid          = -1;
static int hf_shim6_reap           = -1;
static int hf_shim6_opt_type       = -1;
static int hf_shim6_opt_len        = -1;
static int hf_shim6_opt_total_len  = -1;
static int hf_shim6_opt_loc_verif_methods = -1;
static int hf_shim6_opt_critical   = -1;
static int hf_shim6_opt_loclist    = -1;
static int hf_shim6_locator        = -1;
static int hf_shim6_loc_flag       = -1;
static int hf_shim6_loc_prio       = -1;
static int hf_shim6_loc_weight     = -1;
static int hf_shim6_opt_locnum     = -1;
static int hf_shim6_opt_elemlen    = -1;
static int hf_shim6_opt_fii        = -1;
static int hf_shim6_validator      = -1;
static int hf_shim6_cga_parameter_data_structure = -1;
static int hf_shim6_cga_signature  = -1;
static int hf_shim6_padding        = -1;

static gint ett_shim6_proto        = -1;
static gint ett_shim6_option       = -1;
static gint ett_shim6_locators     = -1;
static gint ett_shim6_verif_methods = -1;
static gint ett_shim6_loc_pref     = -1;
static gint ett_shim6_probes_sent  = -1;
static gint ett_shim6_probe_sent   = -1;
static gint ett_shim6_probes_rcvd  = -1;
static gint ett_shim6_probe_rcvd   = -1;
static gint ett_shim6_cksum        = -1;

static expert_field ei_shim6_opt_elemlen_invalid = EI_INIT;
static expert_field ei_shim6_checksum_bad = EI_INIT;



static guint16
shim6_checksum(tvbuff_t *tvb, int offset, int len)
{
    vec_t cksum_vec[1];

    SET_CKSUM_VEC_TVB(cksum_vec[0], tvb, offset, len);
    return in_cksum(&cksum_vec[0], 1);
}

static const value_string shimoptvals[] = {
    { SHIM6_OPT_RESPVAL,  "Responder Validator Option" },
    { SHIM6_OPT_LOCLIST,  "Locator List Option" },
    { SHIM6_OPT_LOCPREF,  "Locator Preferences Option" },
    { SHIM6_OPT_CGAPDM,   "CGA Parameter Data Structure Option" },
    { SHIM6_OPT_CGASIG,   "CGA Signature Option" },
    { SHIM6_OPT_ULIDPAIR, "ULID Pair Option" },
    { SHIM6_OPT_FII,      "Forked Instance Identifier Option" },
    { 0, NULL }
};

static const value_string shimverifmethods[] = {
    { SHIM6_VERIF_HBA, "HBA" },
    { SHIM6_VERIF_CGA, "CGA" },
    { 0, NULL }
};

static const value_string shimflags[] _U_ = {
    { SHIM6_FLAG_BROKEN,    "BROKEN" },
    { SHIM6_FLAG_TEMPORARY, "TEMPORARY" },
    { 0, NULL }
};

static const value_string shimreapstates[] = {
    { SHIM6_REAP_OPERATIONAL, "Operational" },
    { SHIM6_REAP_EXPLORING,   "Exploring" },
    { SHIM6_REAP_INBOUNDOK,   "InboundOK" },
    { 0, NULL }
};

static const value_string shim6_protocol[] = {
    { 0, "SHIM6" },
    { 1, "HIP" },
    { 0, NULL }
};


static void
dissect_shim6_opt_loclist(proto_tree * opt_tree, tvbuff_t * tvb, gint *offset)
{
    proto_tree *subtree;
    guint       count;
    guint       optlen;
    int         p = *offset;

    proto_tree_add_item(opt_tree, hf_shim6_opt_loclist, tvb, p, 4, ENC_BIG_ENDIAN);
    p += 4;

    optlen = tvb_get_guint8(tvb, p);
    proto_tree_add_item(opt_tree, hf_shim6_opt_locnum, tvb, p, 1, ENC_BIG_ENDIAN);
    p++;

    /* Verification Methods */
    subtree = proto_tree_add_subtree(opt_tree, tvb, p, optlen,
                             ett_shim6_verif_methods, NULL, "Locator Verification Methods");

    for (count=0; count < optlen; count++)
        proto_tree_add_item(subtree, hf_shim6_opt_loc_verif_methods, tvb,
                            p+count, 1, ENC_BIG_ENDIAN);
    p += optlen;

    /* Padding, included in length field */
    if ((7 - optlen % 8) > 0) {
        proto_tree_add_item(opt_tree, hf_shim6_padding, tvb, p, (7 - optlen % 8), ENC_NA);
        p += (7 - optlen % 8);
    }

    /* Locators */
    subtree = proto_tree_add_subtree(opt_tree, tvb, p, 16 * optlen, ett_shim6_locators, NULL, "Locators");

    for (count=0; count < optlen; count++) {
        proto_tree_add_item(subtree, hf_shim6_locator, tvb, p, 16, ENC_NA);
        p += 16;
    }
    *offset = p;
}

static void
dissect_shim6_opt_loc_pref(proto_tree * opt_tree, tvbuff_t * tvb, gint *offset, gint len, packet_info *pinfo)
{
    proto_tree *subtree;

    gint        p;
    gint        optlen;
    gint        count;

    p = *offset;

    proto_tree_add_item(opt_tree, hf_shim6_opt_loclist, tvb, p, 4, ENC_BIG_ENDIAN);
    p += 4;

    optlen = tvb_get_guint8(tvb, p);
    proto_tree_add_item(opt_tree, hf_shim6_opt_elemlen, tvb, p, 1, ENC_BIG_ENDIAN);

    if (optlen < 1 || optlen > 3) {
        proto_tree_add_expert_format(opt_tree, pinfo, &ei_shim6_opt_elemlen_invalid, tvb, p, 1,
                                     "Invalid element length: %u", optlen);
        return;
    }

    p++;

    /* Locator Preferences */
    count = 1;
    while (p < len) {
        subtree = proto_tree_add_subtree_format(opt_tree, tvb, p, optlen, ett_shim6_loc_pref, NULL,
                                                "Locator Preferences %u", count);

        /* Flags */
        if (optlen >= 1)
            proto_tree_add_item(subtree, hf_shim6_loc_flag, tvb, p, 1, ENC_BIG_ENDIAN);
        /* Priority */
        if (optlen >= 2)
            proto_tree_add_item(subtree, hf_shim6_loc_prio, tvb, p+1, 1, ENC_BIG_ENDIAN);
        /* Weight */
        if (optlen >= 3)
            proto_tree_add_item(subtree, hf_shim6_loc_weight, tvb, p+2, 1, ENC_BIG_ENDIAN);
        /*
         * Shim6 Draft 08 doesn't specify the format when the Element length is
         * more than three, except that any such formats MUST be defined so that
         * the first three octets are the same as in the above case, that is, a
         * of a 1 octet flags field followed by a 1 octet priority field, and a
         * 1 octet weight field.
         */
        p += optlen;
        count++;
    }
    *offset = p;
}


static int
dissect_shimopts(tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo)
{
    int          len, total_len;
    gint         p;
    gint         padding;
    proto_tree  *opt_tree;
    proto_item  *ti;


    p = offset;

    p += 4;

    len = tvb_get_ntohs(tvb, offset+2);
    padding = 7 - ((len + 3) % 8);
    total_len = 4 + len + padding;

    if (tree)
    {
        /* Option Type */
        opt_tree = proto_tree_add_subtree(tree, tvb, offset, total_len, ett_shim6_option, NULL,
                            val_to_str_const( (tvb_get_ntohs(tvb, offset) & SHIM6_BITMASK_OPT_TYPE) >> 1, shimoptvals, "Unknown Option Type"));

        proto_tree_add_item(opt_tree, hf_shim6_opt_type, tvb, offset, 2, ENC_BIG_ENDIAN);

        /* Critical */
        proto_tree_add_item(opt_tree, hf_shim6_opt_critical, tvb, offset+1, 1, ENC_BIG_ENDIAN);

        /* Content Length */
        proto_tree_add_item(opt_tree, hf_shim6_opt_len, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        ti = proto_tree_add_uint(opt_tree, hf_shim6_opt_total_len, tvb, offset+2, 2, total_len);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Option Type Specific */
        switch (tvb_get_ntohs(tvb, offset) >> 1)
        {
        case SHIM6_OPT_RESPVAL:
            proto_tree_add_item(opt_tree, hf_shim6_validator, tvb, p, len, ENC_NA);
            p += len;
            if (total_len-(len+4) > 0)
                proto_tree_add_item(opt_tree, hf_shim6_padding, tvb, p, total_len-(len+4), ENC_NA);
            break;
        case SHIM6_OPT_LOCLIST:
            dissect_shim6_opt_loclist(opt_tree, tvb, &p);
            break;
        case SHIM6_OPT_LOCPREF:
            dissect_shim6_opt_loc_pref(opt_tree, tvb, &p, offset+len+4, pinfo);
            if (total_len-(len+4) > 0)
                proto_tree_add_item(opt_tree, hf_shim6_padding, tvb, p, total_len-(len+4), ENC_NA);
            break;
        case SHIM6_OPT_CGAPDM:
            proto_tree_add_item(opt_tree, hf_shim6_cga_parameter_data_structure, tvb, p, len, ENC_NA);
            p += len;
            if (total_len-(len+4) > 0)
                proto_tree_add_item(opt_tree, hf_shim6_padding, tvb, p, total_len-(len+4), ENC_NA);
            break;
        case SHIM6_OPT_CGASIG:
            proto_tree_add_item(opt_tree, hf_shim6_cga_signature, tvb, p, len, ENC_NA);
            p += len;
            if (total_len-(len+4) > 0)
                proto_tree_add_item(opt_tree, hf_shim6_padding, tvb, p, total_len-(len+4), ENC_NA);
            break;
        case SHIM6_OPT_ULIDPAIR:
            proto_tree_add_item(opt_tree, hf_shim6_reserved, tvb, p, 4, ENC_NA);
            p += 4;
            proto_tree_add_item(opt_tree, hf_shim6_sulid, tvb, p, 16, ENC_NA);
            p += 16;
            proto_tree_add_item(opt_tree, hf_shim6_rulid, tvb, p, 16, ENC_NA);
            p += 16;
            break;
        case SHIM6_OPT_FII:
            proto_tree_add_item(opt_tree, hf_shim6_opt_fii, tvb, p, 4, ENC_BIG_ENDIAN);
            p += 4;
            break;
        default:
            break;
        }
    }
    return total_len;
}

static void
dissect_shim6_ct(proto_tree * shim_tree, gint hf_item, tvbuff_t * tvb, gint offset, const guchar * label)
{
    guint8  tmp[6];
    guchar *ct_str;

    tmp[0] = tvb_get_guint8(tvb, offset++);
    tmp[1] = tvb_get_guint8(tvb, offset++);
    tmp[2] = tvb_get_guint8(tvb, offset++);
    tmp[3] = tvb_get_guint8(tvb, offset++);
    tmp[4] = tvb_get_guint8(tvb, offset++);
    tmp[5] = tvb_get_guint8(tvb, offset++);

    ct_str = wmem_strdup_printf(wmem_packet_scope(),
                                "%s: %02X %02X %02X %02X %02X %02X", label,
                                tmp[0] & SHIM6_BITMASK_CT, tmp[1], tmp[2],
                                tmp[3], tmp[4], tmp[5]
        );
    proto_tree_add_none_format(shim_tree, hf_item, tvb, offset - 6, 6, "%s", ct_str);
}

static void
dissect_shim6_probes(proto_tree * shim_tree, tvbuff_t * tvb, gint offset,
                     const guchar * label, guint nbr_probe,
                     gboolean probes_rcvd)
{
    proto_tree *probes_tree;
    proto_tree *probe_tree;
    gint        ett_probes;
    gint        ett_probe;
    guint       count;

    if (probes_rcvd) {
        ett_probes = ett_shim6_probes_rcvd;
        ett_probe = ett_shim6_probe_rcvd;
    } else {
        ett_probes = ett_shim6_probes_sent;
        ett_probe = ett_shim6_probe_sent;
    }
    probes_tree = proto_tree_add_subtree(shim_tree, tvb, offset, 40 * nbr_probe, ett_probes, NULL, label);

    for (count=0; count < nbr_probe; count++) {
        probe_tree = proto_tree_add_subtree_format(probes_tree, tvb, offset, 40,
                                            ett_probe, NULL, "Probe %u", count+1);

        proto_tree_add_item(probe_tree, hf_shim6_psrc, tvb, offset, 16, ENC_NA);
        offset += 16;
        proto_tree_add_item(probe_tree, hf_shim6_pdst, tvb, offset, 16, ENC_NA);
        offset += 16;

        proto_tree_add_item(probe_tree, hf_shim6_pnonce, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(probe_tree, hf_shim6_pdata, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

/* Dissect SHIM6 data: control messages */
static int
dissect_shimctrl(tvbuff_t *tvb, gint offset, guint type, proto_tree *shim_tree)
{
    gint         p;
    guint8       tmp;
    const gchar *sta;
    guint        probes_sent;
    guint        probes_rcvd;

    p = offset;

    switch (type)
    {
    case SHIM6_TYPE_I1:
        dissect_shim6_ct(shim_tree, hf_shim6_ct, tvb, p, "Initiator Context Tag");
        p += 6;
        proto_tree_add_item(shim_tree, hf_shim6_inonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        break;
    case SHIM6_TYPE_R1:
        proto_tree_add_item(shim_tree, hf_shim6_reserved2, tvb, p, 2, ENC_NA);
        p += 2;
        proto_tree_add_item(shim_tree, hf_shim6_inonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        proto_tree_add_item(shim_tree, hf_shim6_rnonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        break;
    case SHIM6_TYPE_I2:
        dissect_shim6_ct(shim_tree, hf_shim6_ct, tvb, p, "Initiator Context Tag");
        p += 6;
        proto_tree_add_item(shim_tree, hf_shim6_inonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        proto_tree_add_item(shim_tree, hf_shim6_rnonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        proto_tree_add_item(shim_tree, hf_shim6_reserved2, tvb, p, 4, ENC_NA);
        p += 4;
        break;
    case SHIM6_TYPE_R2:
        dissect_shim6_ct(shim_tree, hf_shim6_ct, tvb, p, "Responder Context Tag");
        p += 6;
        proto_tree_add_item(shim_tree, hf_shim6_inonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        break;
    case SHIM6_TYPE_R1BIS:
        dissect_shim6_ct(shim_tree, hf_shim6_ct, tvb, p, "Packet Context Tag");
        p += 6;
        proto_tree_add_item(shim_tree, hf_shim6_rnonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        break;
    case SHIM6_TYPE_I2BIS:
        dissect_shim6_ct(shim_tree, hf_shim6_ct, tvb, p, "Initiator Context Tag");
        p += 6;
        proto_tree_add_item(shim_tree, hf_shim6_inonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        proto_tree_add_item(shim_tree, hf_shim6_rnonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        proto_tree_add_item(shim_tree, hf_shim6_reserved2, tvb, p, 6, ENC_NA);
        p += 6;
        dissect_shim6_ct(shim_tree, hf_shim6_ct, tvb, p, "Initiator Context Tag");
        p += 6;
        break;
    case SHIM6_TYPE_UPD_REQ:
    case SHIM6_TYPE_UPD_ACK:
        dissect_shim6_ct(shim_tree, hf_shim6_ct, tvb, p, "Receiver Context Tag");
        p += 6;
        proto_tree_add_item(shim_tree, hf_shim6_rnonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        break;
    case SHIM6_TYPE_KEEPALIVE:
        dissect_shim6_ct(shim_tree, hf_shim6_ct, tvb, p, "Receiver Context Tag");
        p += 6;
        proto_tree_add_item(shim_tree, hf_shim6_reserved2, tvb, p, 4, ENC_NA);
        p += 4;
        break;
    case SHIM6_TYPE_PROBE:
        dissect_shim6_ct(shim_tree, hf_shim6_ct, tvb, p, "Receiver Context Tag");
        p += 6;

        tmp = tvb_get_guint8(tvb, p);
        probes_sent = tmp & SHIM6_BITMASK_PSENT;
        probes_rcvd = (tmp & SHIM6_BITMASK_PRECVD) >> 4;
        proto_tree_add_item(shim_tree, hf_shim6_psent, tvb,
                            p, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(shim_tree, hf_shim6_precvd, tvb,
                            p, 1, ENC_BIG_ENDIAN);
        p++;

        sta = val_to_str_const((tvb_get_guint8(tvb, p) & SHIM6_BITMASK_STA) >> 6,
                               shimreapstates, "Unknown REAP State");
        proto_tree_add_uint_format_value(shim_tree, hf_shim6_reap, tvb,
                                         p, 1, (tvb_get_guint8(tvb, p) & SHIM6_BITMASK_STA) >> 6,
                                         "%s", sta);

        proto_tree_add_item(shim_tree, hf_shim6_reserved2, tvb, p, 3, ENC_NA);
        p += 3;

        /* Probes Sent */
        if (probes_sent) {
            dissect_shim6_probes(shim_tree, tvb, p, "Probes Sent",
                                 probes_sent, FALSE);
            p += 40 * probes_sent;
        }

        /* Probes Received */
        if (probes_rcvd) {
            dissect_shim6_probes(shim_tree, tvb, p, "Probes Received",
                                 probes_rcvd, TRUE);
            p += 40 * probes_rcvd;
        }
        break;
    default:
        break;
    }
    return p-offset;
}

/* Dissect SHIM6 data: payload, common part, options */
static const value_string shimctrlvals[] = {
    { SHIM6_TYPE_I1,        "I1" },
    { SHIM6_TYPE_R1,        "R1" },
    { SHIM6_TYPE_I2,        "I2" },
    { SHIM6_TYPE_R2,        "R2" },
    { SHIM6_TYPE_R1BIS,     "R1bis" },
    { SHIM6_TYPE_I2BIS,     "I2bis" },
    { SHIM6_TYPE_UPD_REQ,   "Update Request" },
    { SHIM6_TYPE_UPD_ACK,   "Update Acknowledgment" },
    { SHIM6_TYPE_KEEPALIVE, "Keepalive" },
    { SHIM6_TYPE_PROBE,     "Probe" },
    { 0, NULL }
};

static int
dissect_shim6(tvbuff_t *tvb, packet_info * pinfo, proto_tree *tree, void* data _U_)
{
    struct ip6_shim  shim;
    int              offset = 0, len;
    gint             p;
    proto_tree      *shim_tree;
    proto_item      *ti, *ti_len;
    guint8           tmp[5];

    tvb_memcpy(tvb, (guint8 *)&shim, offset, sizeof(shim));
    len = (shim.ip6s_len + 1) << 3;

    if (shim.ip6s_p & SHIM6_BITMASK_P) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, " , ", "Shim6 (Payload)");
    }
    else {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " , ", "Shim6 (%s)",
                        val_to_str_const(shim.ip6s_p & SHIM6_BITMASK_TYPE, shimctrlvals, "Unknown"));
    }

    ti = proto_tree_add_item(tree, proto_shim6, tvb, offset, len, ENC_NA);
    shim_tree = proto_item_add_subtree(ti, ett_shim6_proto);

    /* Next Header */
    proto_tree_add_uint_format_value(shim_tree, hf_shim6_nxt, tvb,
                                     offset + (int)offsetof(struct ip6_shim, ip6s_nxt), 1, shim.ip6s_nxt,
                                     "%s (%u)", ipprotostr(shim.ip6s_nxt), shim.ip6s_nxt);

    /* Header Extension Length */
    ti_len = proto_tree_add_item(shim_tree, hf_shim6_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_uint(shim_tree, hf_shim6_len_oct, tvb, offset, 1, len);
    proto_item_append_text(ti, " bytes");
    PROTO_ITEM_SET_GENERATED(ti);
    PROTO_ITEM_SET_HIDDEN(ti);
    proto_item_append_text(ti_len, " (%d bytes)", len);

    /* P Field */
    proto_tree_add_item(shim_tree, hf_shim6_p, tvb,
                        offset + (int)offsetof(struct ip6_shim, ip6s_p), 1, ENC_BIG_ENDIAN);

    /* skip the first 2 bytes (nxt hdr, hdr ext len, p+7bits) */
    p = offset + 3;

    if (shim.ip6s_p & SHIM6_BITMASK_P) {
        tmp[0] = tvb_get_guint8(tvb, p++);
        tmp[1] = tvb_get_guint8(tvb, p++);
        tmp[2] = tvb_get_guint8(tvb, p++);
        tmp[3] = tvb_get_guint8(tvb, p++);
        tmp[4] = tvb_get_guint8(tvb, p++);

        /* Payload Extension Header */
        proto_tree_add_none_format(shim_tree, hf_shim6_ct, tvb,
                                   offset + (int)offsetof(struct ip6_shim, ip6s_p), 6,
                                   "Receiver Context Tag: %02x %02x %02x %02x %02x %02x",
                                   shim.ip6s_p & SHIM6_BITMASK_CT, tmp[0], tmp[1], tmp[2], tmp[3], tmp[4]);
    } else {
        /* Control Message */
        guint16 csum;
        int advance;

        /* Message Type */
        proto_tree_add_item(shim_tree, hf_shim6_type, tvb,
                            offset + (int)offsetof(struct ip6_shim, ip6s_p), 1,
                            ENC_BIG_ENDIAN
            );

        /* Protocol bit (Must be zero for SHIM6) */
        proto_tree_add_item(shim_tree, hf_shim6_proto, tvb, p, 1, ENC_BIG_ENDIAN);
        p++;

        /* Checksum */
        csum = shim6_checksum(tvb, offset, len);
        proto_tree_add_checksum(shim_tree, tvb, p, hf_shim6_checksum, hf_shim6_checksum_status, &ei_shim6_checksum_bad, pinfo, csum,
                                ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
        if (csum != 0)
            col_append_str(pinfo->cinfo, COL_INFO, " [Shim6 CHECKSUM INCORRECT]");
        p += 2;

        /* Type specific data */
        advance = dissect_shimctrl(tvb, p, shim.ip6s_p & SHIM6_BITMASK_TYPE, shim_tree);
        p += advance;

        /* Options */
        while (p < offset+len) {
            p += dissect_shimopts(tvb, p, shim_tree, pinfo);
        }
    }

    return len;
}

void
proto_register_shim6(void)
{
    static hf_register_info hf_shim6[] = {
        { &hf_shim6_nxt,
            { "Next Header", "shim6.nxt",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_shim6_len,
            { "Length", "shim6.len",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Extension header length in 8-octet words (minus 1)", HFILL }
        },
        { &hf_shim6_len_oct,
            { "Length", "shim6.len_oct",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Extension header length in octets", HFILL }
        },
        { &hf_shim6_p,
            { "P Bit", "shim6.p",
                FT_BOOLEAN, 8, NULL, SHIM6_BITMASK_P,
                NULL, HFILL }
        },
        { &hf_shim6_ct,
            { "Context Tag", "shim6.ct",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_shim6_type,
            { "Message Type", "shim6.type",
                FT_UINT8, BASE_DEC, VALS(shimctrlvals), SHIM6_BITMASK_TYPE,
                NULL, HFILL }
        },
        { &hf_shim6_proto,
            { "Protocol", "shim6.proto",
                FT_UINT8, BASE_DEC, VALS(shim6_protocol), SHIM6_BITMASK_PROTOCOL,
                NULL, HFILL }
        },
        { &hf_shim6_checksum,
            { "Checksum", "shim6.checksum",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "Shim6 Checksum", HFILL }
        },
        { &hf_shim6_checksum_status,
            { "Checksum Status", "shim6.checksum.status",
                FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_shim6_inonce,
            { "Initiator Nonce", "shim6.inonce",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_shim6_rnonce,
            { "Responder Nonce", "shim6.rnonce",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_shim6_reserved,
            { "Reserved", "shim6.reserved",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_shim6_reserved2,
            { "Reserved2", "shim6.reserved2",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_shim6_precvd,
            { "Probes Received", "shim6.precvd",
                FT_UINT8, BASE_DEC, NULL, SHIM6_BITMASK_PRECVD,
                NULL, HFILL }
        },
        { &hf_shim6_psent,
            { "Probes Sent", "shim6.psent",
                FT_UINT8, BASE_DEC, NULL, SHIM6_BITMASK_PSENT,
                NULL, HFILL }
        },
        { &hf_shim6_psrc,
            { "Source Address", "shim6.psrc",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Shim6 Probe Source Address", HFILL }
        },
        { &hf_shim6_pdst,
            { "Destination Address", "shim6.pdst",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Shim6 Probe Destination Address", HFILL }
        },
        { &hf_shim6_pnonce,
            { "Nonce", "shim6.pnonce",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
                "Shim6 Probe Nonce", HFILL }
        },
        { &hf_shim6_pdata,
            { "Data", "shim6.pdata",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                "Shim6 Probe Data", HFILL }
        },
        { &hf_shim6_sulid,
            { "Sender ULID", "shim6.sulid",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Shim6 Sender ULID", HFILL }
        },
        { &hf_shim6_rulid,
            { "Receiver ULID", "shim6.rulid",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Shim6 Receiver ULID", HFILL }
        },
        { &hf_shim6_reap,
            { "REAP State", "shim6.reap",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_shim6_opt_type,
            { "Option Type", "shim6.opt.type",
                FT_UINT16, BASE_DEC, VALS(shimoptvals), SHIM6_BITMASK_OPT_TYPE,
                "Shim6 Option Type", HFILL }
        },
        { &hf_shim6_opt_critical,
            { "Option Critical Bit", "shim6.opt.critical",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), SHIM6_BITMASK_CRITICAL,
                "TRUE: option is critical, FALSE: option is not critical", HFILL }
        },
        { &hf_shim6_opt_len,
            { "Content Length", "shim6.opt.len",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Content Length Option", HFILL }
        },
        { &hf_shim6_opt_total_len,
            { "Total Length", "shim6.opt.total_len",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Total Option Length", HFILL }
        },
        { &hf_shim6_opt_loc_verif_methods,
            { "Verification Method", "shim6.opt.verif_method",
                FT_UINT8, BASE_DEC, VALS(shimverifmethods), 0x0,
                "Locator Verification Method", HFILL }
        },
        { &hf_shim6_opt_loclist,
            { "Locator List Generation", "shim6.opt.loclist",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_shim6_locator,
            { "Locator", "shim6.locator",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Shim6 Locator", HFILL }
        },
        { &hf_shim6_opt_locnum,
            { "Num Locators", "shim6.opt.locnum",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Number of locators in Locator List", HFILL }
        },
        { &hf_shim6_opt_elemlen,
            { "Element Length", "shim6.opt.elemlen",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Length of Elements in Locator Preferences Option", HFILL }
        },
        { &hf_shim6_loc_flag,
            { "Flags", "shim6.loc.flags",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Locator Preferences Flags", HFILL }
        },
        { &hf_shim6_loc_prio,
            { "Priority", "shim6.loc.prio",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Locator Preferences Priority", HFILL }
        },
        { &hf_shim6_loc_weight,
            { "Weight", "shim6.loc.weight",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Locator Preferences Weight", HFILL }
        },
        { &hf_shim6_opt_fii,
            { "Forked Instance Identifier", "shim6.opt.fii",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_shim6_validator,
            { "Validator", "shim6.validator",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_shim6_cga_parameter_data_structure,
            { "CGA Parameter Data Structure", "shim6.cga_parameter_data_structure",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_shim6_cga_signature,
            { "CGA Signature", "shim6.cga_signature",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_shim6_padding,
            { "Padding", "shim6.padding",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        }
    };

    static gint *ett_shim6[] = {
        &ett_shim6_proto,
        &ett_shim6_option,
        &ett_shim6_locators,
        &ett_shim6_verif_methods,
        &ett_shim6_loc_pref,
        &ett_shim6_probes_sent,
        &ett_shim6_probes_rcvd,
        &ett_shim6_probe_sent,
        &ett_shim6_probe_rcvd,
        &ett_shim6_cksum
    };

    static ei_register_info ei_shim6[] = {
        { &ei_shim6_opt_elemlen_invalid,
            { "shim6.opt.elemlen.invalid", PI_MALFORMED, PI_ERROR,
                "Invalid element length", EXPFILL }
        },
        { &ei_shim6_checksum_bad,
            { "shim6.checksum_bad.expert", PI_CHECKSUM, PI_ERROR,
                "Bad checksum", EXPFILL }
        }
    };

    expert_module_t* expert_shim6;

    proto_shim6 = proto_register_protocol("Shim6 Protocol", "Shim6", "shim6");
    proto_register_field_array(proto_shim6, hf_shim6, array_length(hf_shim6));
    proto_register_subtree_array(ett_shim6, array_length(ett_shim6));
    expert_shim6 = expert_register_protocol(proto_shim6);
    expert_register_field_array(expert_shim6, ei_shim6, array_length(ei_shim6));
}

void
proto_reg_handoff_shim6(void)
{
    dissector_handle_t shim6_handle;

    shim6_handle = create_dissector_handle(dissect_shim6, proto_shim6);
    dissector_add_uint("ipv6.nxt", IP_PROTO_SHIM6, shim6_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
