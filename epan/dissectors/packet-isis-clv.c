/* packet-isis-clv.c
 * Common CLV decode routines.
 *
 * Stuart Stanley <stuarts@mxmail.net>
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
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-isis-clv.h"
#include <epan/nlpid.h>

/*
 * Name: isis_dissect_area_address_clv()
 *
 * Description:
 *    Take an area address CLV and display it pieces.  An area address
 *    CLV is n, x byte hex strings.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of clv we are decoding
 *
 * Output:
 *    void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_area_address_clv(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb,
        expert_field* expert, int hf_area, int offset, int length)
{
    int        arealen,area_idx;

    while ( length > 0 ) {
        arealen = tvb_get_guint8(tvb, offset);
        length--;
        if (length<=0) {
            proto_tree_add_expert_format(tree, pinfo, expert, tvb, offset, -1,
                "short address (no length for payload)");
            return;
        }
        if ( arealen > length) {
            proto_tree_add_expert_format(tree, pinfo, expert, tvb, offset, -1,
                "short address, packet says %d, we have %d left",
                arealen, length );
            return;
        }

        if ( tree ) {
            proto_item *ti;

            ti = proto_tree_add_bytes_format( tree, hf_area, tvb, offset, arealen + 1,
                NULL, "Area address (%d): ", arealen );

            /*
             * Lets turn the area address into "standard"
             * xx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx format string.
             * this is a private routine as the print_nsap_net in
             * epan/osi_utils.c is incomplete and we need only
             * a subset - actually some nice placing of dots ....
             */
            for (area_idx = 0; area_idx < arealen; area_idx++) {
                proto_item_append_text(ti, "%02x",
                    tvb_get_guint8(tvb, offset+area_idx+1));
                if (((area_idx & 1) == 0) &&
                    (area_idx + 1 < arealen)) {
                    proto_item_append_text(ti, ".");
                }
            }
        }
        offset += arealen + 1;
        length -= arealen;    /* length already adjusted for len fld*/
    }
}

/*
 * Name: isis_dissect_instance_identifier_clv()
 *
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of clv we are decoding
 *
 * Output:
 *    void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_instance_identifier_clv(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb,
        expert_field* expert, int hf_iid, int hf_supported_itid, int offset, int length)
{

    length--;
    if (length<=0) {
        proto_tree_add_expert_format(tree, pinfo, expert, tvb, offset, -1,
            "short address (no length for payload)");
        return;
    }

    proto_tree_add_item(tree, hf_iid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    length -= 2;

    while ( length > 0 ) {

        proto_tree_add_item(tree, hf_supported_itid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        length -= 2;

    }
}

/*
 * Name: isis_dissect_authentication_clv()
 *
 * Description:
 *    Take apart the CLV that hold authentication information.  This
 *    is currently 1 octet auth type.
 *      the two defined authentication types
 *      are 1 for a clear text password and
 *           54 for a HMAC-MD5 digest
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of clv we are decoding
 *
 * Output:
 *    void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_authentication_clv(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb,
        int hf_auth_bytes, expert_field* auth_expert, int offset, int length)
{
    guchar pw_type;
    int auth_unsupported;

    if ( length <= 0 ) {
        return;
    }

    pw_type = tvb_get_guint8(tvb, offset);
    offset += 1;
    length--;
    auth_unsupported = FALSE;

    switch (pw_type) {
    case 1:
        if ( length > 0 ) {
            proto_tree_add_bytes_format( tree, hf_auth_bytes, tvb, offset, length,
                NULL, "clear text (1), password (length %d) = %s", length, tvb_format_text(tvb, offset, length));
        } else {
            proto_tree_add_bytes_format( tree, hf_auth_bytes, tvb, offset, length,
                NULL, "clear text (1), no clear-text password found!!!");
        }
        break;
    case 54:
        if ( length == 16 ) {
            proto_tree_add_bytes_format( tree, hf_auth_bytes, tvb, offset, length,
                NULL, "hmac-md5 (54), password (length %d) = %s", length, tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, length));
        } else {
            proto_tree_add_bytes_format( tree, hf_auth_bytes, tvb, offset, length,
                NULL, "hmac-md5 (54), illegal hmac-md5 digest format (must be 16 bytes)");
        }
        break;
    default:
        proto_tree_add_bytes_format( tree, hf_auth_bytes, tvb, offset, length,
                NULL, "type 0x%02x (0x%02x)", pw_type, length);
        auth_unsupported=TRUE;
        break;
    }

    if ( auth_unsupported ) {
        proto_tree_add_expert(tree, pinfo, auth_expert, tvb, offset, -1);
    }
}

/*
 * Name: isis_dissect_hostname_clv()
 *
 * Description:
 *      dump the hostname information found in TLV 137
 *      pls note that the hostname is not null terminated
 *
 * Input:
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : protocol display tree to fill out.  May be NULL
 *      int : offset into packet data where we are.
 *      int : length of clv we are decoding
 *      int : tree id to use for proto tree.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */


void
isis_dissect_hostname_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
    int length, int tree_id)
{
    proto_item* ti = proto_tree_add_item( tree, tree_id, tvb, offset, length, ENC_ASCII|ENC_NA);
    if ( length == 0 ) {
        proto_item_append_text(ti, "--none--" );
    }
}




void
isis_dissect_mt_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset, int length,
    int tree_id, expert_field* mtid_expert)
{
    guint16 mt_block;
    const char *mt_desc;

    while (length>0) {
        /* length can only be a multiple of 2, otherwise there is
           something broken -> so decode down until length is 1 */
        if (length!=1) {
        /* fetch two bytes */
        mt_block=tvb_get_ntohs(tvb, offset);

        /* mask out the lower 12 bits */
        switch(mt_block&0x0fff) {
        case 0:
            mt_desc="IPv4 unicast";
            break;
        case 1:
            mt_desc="In-Band Management";
            break;
        case 2:
            mt_desc="IPv6 unicast";
            break;
        case 3:
            mt_desc="Multicast";
            break;
        case 4095:
            mt_desc="Development, Experimental or Proprietary";
            break;
        default:
            mt_desc="Reserved for IETF Consensus";
            break;
        }
        proto_tree_add_uint_format ( tree, tree_id, tvb, offset, 2,
            mt_block,
            "%s Topology (0x%03x), %ssubTLVs present%s",
                      mt_desc,
                      mt_block&0xfff,
                      (mt_block&0x8000) ? "" : "no ",
                      (mt_block&0x4000) ? ", ATT bit set" : "" );
        } else {
        proto_tree_add_expert( tree, pinfo, mtid_expert, tvb, offset, 1);
        break;
        }
        length -= 2;
        offset += 2;
    }
}


/*
 * Name: isis_dissect_ip_int_clv()
 *
 * Description:
 *    Take apart the CLV that lists all the IP interfaces.  The
 *    meaning of which is slightly different for the different base packet
 *    types, but the display is not different.  What we have is n ip
 *    addresses, plain and simple.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of clv we are decoding
 *    int : tree id to use for proto tree.
 *
 * Output:
 *    void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_ip_int_clv(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb, expert_field* expert,
    int offset, int length, int tree_id)
{
    if ( length <= 0 ) {
        return;
    }

    while ( length > 0 ) {
        if ( length < 4 ) {
            proto_tree_add_expert_format(tree, pinfo, expert, tvb, offset, -1,
                "Short IP interface address (%d vs 4)",length );
            return;
        }

        if ( tree ) {
            proto_tree_add_item(tree, tree_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
        offset += 4;
        length -= 4;
    }
}

/*
 * Name: isis_dissect_ipv6_int_clv()
 *
 * Description:
 *    Take apart the CLV that lists all the IPv6 interfaces.  The
 *    meaning of which is slightly different for the different base packet
 *    types, but the display is not different.  What we have is n ip
 *    addresses, plain and simple.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of clv we are decoding
 *    int : tree id to use for proto tree.
 *
 * Output:
 *    void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_ipv6_int_clv(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb, expert_field* expert,
    int offset, int length, int tree_id)
{
    struct e_in6_addr addr;

    if ( length <= 0 ) {
        return;
    }

    while ( length > 0 ) {
        if ( length < 16 ) {
            proto_tree_add_expert_format(tree, pinfo, expert, tvb, offset, -1,
                "Short IPv6 interface address (%d vs 16)",length );
            return;
        }
        tvb_get_ipv6(tvb, offset, &addr);
        if ( tree ) {
            proto_tree_add_ipv6(tree, tree_id, tvb, offset, 16, &addr);
        }
        offset += 16;
        length -= 16;
    }
}


/*
 * Name: isis_dissect_te_router_id_clv()
 *
 * Description:
 *      Display the Traffic Engineering Router ID TLV #134.
 *      This TLV is like the IP Interface TLV, except that
 *      only _one_ IP address is present
 *
 * Input:
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : protocol display tree to fill out.  May be NULL
 *      int : offset into packet data where we are.
 *      int : length of clv we are decoding
 *      int : tree id to use for proto tree.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_te_router_id_clv(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb, expert_field* expert,
    int offset, int length, int tree_id)
{
    if ( length <= 0 ) {
        return;
    }

    if ( length != 4 ) {
        proto_tree_add_expert_format(tree, pinfo, expert, tvb, offset, -1,
            "malformed Traffic Engineering Router ID (%d vs 4)",length );
        return;
    }

    proto_tree_add_item(tree, tree_id, tvb, offset, 4, ENC_BIG_ENDIAN);
}

/*
 * Name: isis_dissect_nlpid_clv()
 *
 * Description:
 *    Take apart a NLPID packet and display it.  The NLPID (for intergrated
 *    ISIS, contains n network layer protocol IDs that the box supports.
 *    We max out at 256 entries.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of clv we are decoding
 *
 * Output:
 *    void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_nlpid_clv(tvbuff_t *tvb, proto_tree *tree, int hf_nlpid, int offset, int length)
{
    gboolean first;
    proto_item *ti;

    if ( !tree ) return;        /* nothing to do! */

    if (length <= 0) {
        proto_tree_add_item(tree, hf_nlpid, tvb, offset, length, ENC_NA);
    } else {
        first = TRUE;
        ti = proto_tree_add_bytes_format(tree, hf_nlpid, tvb, offset, length, NULL, "NLPID(s): ");
        while (length-- > 0 ) {
            if (!first) {
                proto_item_append_text(ti, ", ");
            }
            proto_item_append_text(ti, "%s (0x%02x)",
                           /* NLPID_IEEE_8021AQ conflicts with NLPID_SNDCF.
                        * In this context, we want the former.
                        */
                           (tvb_get_guint8(tvb, offset) == NLPID_IEEE_8021AQ
                        ? "IEEE 802.1aq (SPB)"
                        : val_to_str_const(tvb_get_guint8(tvb, offset), nlpid_vals, "Unknown")),
                           tvb_get_guint8(tvb, offset));
            offset++;
            first = FALSE;
        }
    }
}

/*
 * Name: isis_dissect_clvs()
 *
 * Description:
 *    Dispatch routine to shred all the CLVs in a packet.  We just
 *    walk through the clv entries in the packet.  For each one, we
 *    search the passed in valid clv's for this protocol (opts) for
 *    a matching code.  If found, we add to the display tree and
 *    then call the dissector.  If it is not, we just post an
 *    "unknown" clv entry using the passed in unknown clv tree id.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    isis_clv_handle_t * : NULL dissector terminated array of codes
 *        and handlers (along with tree text and tree id's).
 *    int : length of CLV area.
 *    int : length of IDs in packet.
 *    int : unknown clv tree id
 *
 * Output:
 *    void, but we will add to proto tree if !NULL.
 */
void
isis_dissect_clvs(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    const isis_clv_handle_t *opts, expert_field* expert_short_len, int len, int id_length,
    int unknown_tree_id _U_, int tree_type, int tree_length, expert_field ei_unknown)
{
    guint8 code;
    guint8 length;
    int q;
    proto_tree    *clv_tree;

    while ( len > 0 ) {
        code = tvb_get_guint8(tvb, offset);
        offset += 1;
        len -= 1;
        if (len == 0)
            break;

        length = tvb_get_guint8(tvb, offset);
        offset += 1;
        len -= 1;
        if (len == 0)
            break;

        if ( len < length ) {
            proto_tree_add_expert_format(tree, pinfo, expert_short_len, tvb, offset, -1,
                "Short CLV header (%d vs %d)",
                length, len );
            return;
        }
        q = 0;
        while ((opts[q].dissect != NULL )&&( opts[q].optcode != code )){
            q++;
        }
        if ( opts[q].dissect ) {
            /* adjust by 2 for code/len octets */
            clv_tree = proto_tree_add_subtree_format(tree, tvb, offset - 2,
                    length + 2, *opts[q].tree_id, NULL, "%s (t=%u, l=%u)",
                    opts[q].tree_text, opts[q].optcode, length);

            proto_tree_add_item(clv_tree, tree_type, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(clv_tree, tree_length, tvb, offset - 1, 1, ENC_BIG_ENDIAN);
            opts[q].dissect(tvb, pinfo, clv_tree, offset,
                id_length, length);
        } else {
            clv_tree = proto_tree_add_subtree_format(tree, tvb, offset - 2,
                    length + 2, unknown_tree_id, NULL, "Unknown code (t=%u, l=%u)",
                    code, length);
            proto_tree_add_item(clv_tree, tree_type, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(clv_tree, tree_length, tvb, offset - 1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_expert_format(clv_tree, pinfo, &ei_unknown, tvb, offset, length -2, "Dissector for IS-IS CLV (%d)"
              " code not implemented, Contact Wireshark developers if you want this supported", code);
        }
        offset += length;
        len -= length;
    }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
