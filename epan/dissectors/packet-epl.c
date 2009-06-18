/* packet-epl.c
 * Routines for "Ethernet POWERLINK 2.0" dissection
 * (Ethernet POWERLINK V2.0 Communication Profile Specification Draft Standard Version 1.0.0)
 *
 * Copyright (c) 2006: Zurich University of Applied Sciences Winterthur (ZHW)
 *                     Institute of Embedded Systems (InES)
 *                     http://ines.zhwin.ch
 *
 *                     - Dominic Bechaz <bdo[AT]zhwin.ch>
 *                     - Damir Bursic <bum[AT]zhwin.ch>
 *                     - David Buechi <bhd[AT]zhwin.ch>
 *
 * Copyright (c) 2007: SYS TEC electronic GmbH
 *                     http://www.systec-electronic.com
 *                     - Daniel Krueger <daniel.krueger[AT]systec-electronic.com>
 *
 * $Id$
 *
 * A plugin for:
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <gmodule.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/prefs.h>

#include "packet-epl.h"



/* Initialize the protocol and registered fields */
static gint proto_epl            = -1;
static gint hf_epl_mtyp          = -1;
static gint hf_epl_dest          = -1;
static gint hf_epl_src           = -1;

static gint hf_epl_soc_mc        = -1;
static gint hf_epl_soc_ps        = -1;
static gint hf_epl_soc_nettime   = -1;
static gint hf_epl_soc_relativetime = -1;

static gint hf_epl_preq_ms       = -1;
static gint hf_epl_preq_ea       = -1;
static gint hf_epl_preq_rd       = -1;
static gint hf_epl_preq_pdov     = -1;
static gint hf_epl_preq_size     = -1;
static gint hf_epl_preq_pl       = -1;

static gint hf_epl_pres_stat_ms  = -1;
static gint hf_epl_pres_stat_cs  = -1;
static gint hf_epl_pres_ms       = -1;
static gint hf_epl_pres_en       = -1;
static gint hf_epl_pres_rd       = -1;
static gint hf_epl_pres_pr       = -1;
static gint hf_epl_pres_rs       = -1;
static gint hf_epl_pres_pdov     = -1;
static gint hf_epl_pres_size     = -1;
static gint hf_epl_pres_pl       = -1;

static gint hf_epl_soa_stat_ms   = -1;
static gint hf_epl_soa_stat_cs   = -1;
static gint hf_epl_soa_ea        = -1;
static gint hf_epl_soa_er        = -1;
static gint hf_epl_soa_svid      = -1;
static gint hf_epl_soa_svtg      = -1;
static gint hf_epl_soa_eplv      = -1;

static gint hf_epl_asnd_svid     = -1;
static gint hf_epl_asnd_data     = -1;

/*IdentResponse*/
static gint hf_epl_asnd_identresponse_en             = -1;
static gint hf_epl_asnd_identresponse_ec             = -1;
static gint hf_epl_asnd_identresponse_pr             = -1;
static gint hf_epl_asnd_identresponse_rs             = -1;
static gint hf_epl_asnd_identresponse_stat_ms        = -1;
static gint hf_epl_asnd_identresponse_stat_cs        = -1;
static gint hf_epl_asnd_identresponse_ever           = -1;
static gint hf_epl_asnd_identresponse_feat           = -1;
static gint hf_epl_asnd_identresponse_feat_bit0      = -1;
static gint hf_epl_asnd_identresponse_feat_bit1      = -1;
static gint hf_epl_asnd_identresponse_feat_bit2      = -1;
static gint hf_epl_asnd_identresponse_feat_bit3      = -1;
static gint hf_epl_asnd_identresponse_feat_bit4      = -1;
static gint hf_epl_asnd_identresponse_feat_bit5      = -1;
static gint hf_epl_asnd_identresponse_feat_bit6      = -1;
static gint hf_epl_asnd_identresponse_feat_bit7      = -1;
static gint hf_epl_asnd_identresponse_feat_bit8      = -1;
static gint hf_epl_asnd_identresponse_feat_bit9      = -1;
static gint hf_epl_asnd_identresponse_feat_bitA      = -1;
static gint hf_epl_asnd_identresponse_feat_bitB      = -1;
static gint hf_epl_asnd_identresponse_feat_bitC      = -1;
static gint hf_epl_asnd_identresponse_feat_bitD      = -1;
static gint hf_epl_asnd_identresponse_mtu            = -1;
static gint hf_epl_asnd_identresponse_pis            = -1;
static gint hf_epl_asnd_identresponse_pos            = -1;
static gint hf_epl_asnd_identresponse_rst            = -1;
static gint hf_epl_asnd_identresponse_dt             = -1;
static gint hf_epl_asnd_identresponse_profile        = -1;
static gint hf_epl_asnd_identresponse_vid            = -1;
static gint hf_epl_asnd_identresponse_productcode    = -1;
static gint hf_epl_asnd_identresponse_rno            = -1;
static gint hf_epl_asnd_identresponse_sno            = -1;
static gint hf_epl_asnd_identresponse_vex1           = -1;
static gint hf_epl_asnd_identresponse_vcd            = -1;
static gint hf_epl_asnd_identresponse_vct            = -1;
static gint hf_epl_asnd_identresponse_ad             = -1;
static gint hf_epl_asnd_identresponse_at             = -1;
static gint hf_epl_asnd_identresponse_ipa            = -1;
static gint hf_epl_asnd_identresponse_snm            = -1;
static gint hf_epl_asnd_identresponse_gtw            = -1;
static gint hf_epl_asnd_identresponse_hn             = -1;
static gint hf_epl_asnd_identresponse_vex2           = -1;

/*StatusResponse*/
static gint hf_epl_asnd_statusresponse_en            = -1;
static gint hf_epl_asnd_statusresponse_ec            = -1;
static gint hf_epl_asnd_statusresponse_pr            = -1;
static gint hf_epl_asnd_statusresponse_rs            = -1;
static gint hf_epl_asnd_statusresponse_stat_ms       = -1;
static gint hf_epl_asnd_statusresponse_stat_cs       = -1;
static gint hf_epl_asnd_statusresponse_seb           = -1;

/*StaticErrorBitField */
static gint hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit0 = -1;
static gint hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit1 = -1;
static gint hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit2 = -1;
static gint hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit3 = -1;
static gint hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit4 = -1;
static gint hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit5 = -1;
static gint hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit7 = -1;
static gint hf_epl_asnd_statusresponse_seb_devicespecific_err        = -1;

/*List of Errors/Events*/
static gint hf_epl_asnd_statusresponse_el                    = -1;
static gint hf_epl_asnd_statusresponse_el_entry              = -1;
static gint hf_epl_asnd_statusresponse_el_entry_type         = -1;
static gint hf_epl_asnd_statusresponse_el_entry_type_profile = -1;
static gint hf_epl_asnd_statusresponse_el_entry_type_mode    = -1;
static gint hf_epl_asnd_statusresponse_el_entry_type_bit14   = -1;
static gint hf_epl_asnd_statusresponse_el_entry_type_bit15   = -1;
static gint hf_epl_asnd_statusresponse_el_entry_code         = -1;
static gint hf_epl_asnd_statusresponse_el_entry_time         = -1;
static gint hf_epl_asnd_statusresponse_el_entry_add          = -1;

/*NMTRequest*/
static gint hf_epl_asnd_nmtrequest_rcid                      = -1;
static gint hf_epl_asnd_nmtrequest_rct                       = -1;
static gint hf_epl_asnd_nmtrequest_rcd                       = -1;

/*NMTCommand*/
static gint hf_epl_asnd_nmtcommand_cid                       = -1;
static gint hf_epl_asnd_nmtcommand_cdat                      = -1;
/*static gint hf_epl_asnd_nmtcommand_nmtnetparameterset_mtu    = -1;*/
static gint hf_epl_asnd_nmtcommand_nmtnethostnameset_hn      = -1;
static gint hf_epl_asnd_nmtcommand_nmtflusharpentry_nid      = -1;
static gint hf_epl_asnd_nmtcommand_nmtpublishtime_dt         = -1;

/*Asynchronuous SDO Sequence Layer*/
static gint hf_epl_asnd_sdo_seq_receive_sequence_number      = -1;
static gint hf_epl_asnd_sdo_seq_receive_con                  = -1;
static gint hf_epl_asnd_sdo_seq_send_sequence_number         = -1;
static gint hf_epl_asnd_sdo_seq_send_con                     = -1;

/*Asynchronuous SDO Command Layer*/
static gint hf_epl_asnd_sdo_cmd_transaction_id               = -1;
static gint hf_epl_asnd_sdo_cmd_response                     = -1;
static gint hf_epl_asnd_sdo_cmd_abort                        = -1;

static gint hf_epl_asnd_sdo_cmd_segmentation                 = -1;
static gint hf_epl_asnd_sdo_cmd_command_id                   = -1;
static gint hf_epl_asnd_sdo_cmd_segment_size                 = -1;
static gint hf_epl_asnd_sdo_cmd_data_size                    = -1;

static gint hf_epl_asnd_sdo_cmd_abort_code                   = -1;
/*static gint hf_epl_asnd_sdo_cmd_abort_flag                   = -1;*/
/*static gint hf_epl_asnd_sdo_cmd_segmentation_flag            = -1;*/
/*static gint hf_epl_asnd_sdo_cmd_cmd_valid_test               = -1;*/

/*static gint hf_epl_asnd_sdo_actual_command_id                = -1;*/

static gint hf_epl_asnd_sdo_cmd_write_by_index_index         = -1;
static gint hf_epl_asnd_sdo_cmd_write_by_index_subindex      = -1;
static gint hf_epl_asnd_sdo_cmd_write_by_index_data          = -1;
/*static gint hf_epl_asnd_sdo_cmd_write_by_index_response      = -1;*/

static gint hf_epl_asnd_sdo_cmd_read_by_index_index          = -1;
static gint hf_epl_asnd_sdo_cmd_read_by_index_subindex       = -1;
static gint hf_epl_asnd_sdo_cmd_read_by_index_data           = -1;
/*static gint hf_epl_asnd_sdo_cmd_read_by_index_response       = -1;*/

/*static gint hf_epl_asnd_sdo_actual_segment_size              = -1;*/
/*static gint hf_epl_asnd_sdo_actual_payload_size_read         = -1;*/

/* Initialize the subtree pointers */
static gint ett_epl                 = -1;
static gint ett_epl_feat            = -1;
static gint ett_epl_seb             = -1;
static gint ett_epl_el              = -1;
static gint ett_epl_el_entry        = -1;
static gint ett_epl_el_entry_type   = -1;
static gint ett_epl_sdo_entry_type  = -1;

/* preference whether or not display the SoC flags in info column */
gboolean show_soc_flags = FALSE;


/* Define the tap for epl */
/*static gint epl_tap = -1;*/


/* Code to actually dissect the packets */
static gboolean
dissect_epl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 epl_mtyp, epl_src, epl_dest;
    const  gchar *src_str, *dest_str;
    gboolean udpencap = FALSE;
    /* static epl_info_t mi; */
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *epl_tree = NULL, *epl_src_item, *epl_dest_item;
    gint offset = 0;

    if (tvb_length(tvb) < 3)
    {
        /* Not enough data for an EPL header; don't try to interpret it */
        return FALSE;
    }

    /* Make entries in Protocol column and Info column on summary display */
    if (pinfo->ethertype == ETHERTYPE_EPL_V2)
    {
        if (check_col(pinfo->cinfo, COL_PROTOCOL))
        {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "EPL");
        }
        udpencap = FALSE;
    }
    else
    {   /* guess that this is an EPL frame encapsulated into an UDP datagram */
        if (check_col(pinfo->cinfo, COL_PROTOCOL))
        {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "EPL/UDP");
        }
        udpencap = TRUE;
    }

    /* Get message type */
    epl_mtyp = tvb_get_guint8(tvb, EPL_MTYP_OFFSET) & 0x7F;

    /* tap */
    /*  mi.epl_mtyp = epl_mtyp;
    tap_queue_packet(epl_tap, pinfo, &mi);
    */

    /* Get Destination */
    epl_dest = tvb_get_guint8(tvb, EPL_DEST_OFFSET);
    dest_str = decode_epl_address(epl_dest);

    /* Get Source */
    epl_src = tvb_get_guint8(tvb, EPL_SRC_OFFSET);
    src_str = decode_epl_address(epl_src);

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_clear(pinfo->cinfo, COL_INFO);

        /* Choose the right string for "Info" column (message type) */
        switch (epl_mtyp)
        {
            case EPL_SOC:
                /* source and destination NodeID are fixed according to the spec */
                col_set_str(pinfo->cinfo, COL_INFO, "SoC    ");
                break;

            case EPL_PREQ:
                /* show only destination NodeID, because source is always 240 (MN) */
                col_add_fstr(pinfo->cinfo, COL_INFO, "PReq   dst = %3d   ", epl_dest);
                break;

            case EPL_PRES:
                /* show only source NodeID, because destination is always 255 (broadcast) */
                col_add_fstr(pinfo->cinfo, COL_INFO, "PRes   src = %3d   ", epl_src);
                break;

            case EPL_SOA:
                /* source and destination NodeID are fixed according to the spec */
                col_set_str(pinfo->cinfo, COL_INFO, "SoA    ");
                break;

            case EPL_ASND:
                if (udpencap)
                {
                    col_set_str(pinfo->cinfo, COL_INFO, "ASnd   ");
                }
                else
                {
                    col_add_fstr(pinfo->cinfo, COL_INFO, "ASnd   src = %3d   dst = %3d   ", epl_src, epl_dest);
                }
                break;

            default:    /* no valid EPL packet */
                return FALSE;

        }

    }

    if (tree)
    {
        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_epl, tvb, 0, -1, TRUE);
        epl_tree = proto_item_add_subtree(ti, ett_epl);

        proto_tree_add_item(epl_tree,
            hf_epl_mtyp, tvb, offset, 1, TRUE);
    }
    offset += 1;

    if (tree && !udpencap)
    {
        epl_dest_item = proto_tree_add_item(epl_tree, hf_epl_dest, tvb, offset, 1, TRUE);
        proto_item_append_text (epl_dest_item, "%s", dest_str);
        offset += 1;

        epl_src_item = proto_tree_add_item(epl_tree, hf_epl_src, tvb, offset, 1, TRUE);
        proto_item_append_text (epl_src_item, "%s", src_str);
        offset += 1;
    }
    else
    {
        offset += 2;
    }

    /* The rest of the EPL dissector depends on the message type  */
    switch (epl_mtyp)
    {
        case EPL_SOC:
            offset = dissect_epl_soc(epl_tree, tvb, pinfo, offset);
            break;

        case EPL_PREQ:
            offset = dissect_epl_preq(epl_tree, tvb, pinfo, offset);
            break;

        case EPL_PRES:
            offset = dissect_epl_pres(epl_tree, tvb, pinfo, epl_src, offset);
            break;

        case EPL_SOA:
            offset = dissect_epl_soa(epl_tree, tvb, pinfo, epl_src, offset);
            break;

        case EPL_ASND:
            offset = dissect_epl_asnd(epl_tree, tvb, pinfo, epl_src, offset);
            break;

        default:    /* no valid EPL packet */
            return FALSE;
    }

    return TRUE;
}



const gchar*
decode_epl_address (guchar adr)
{
    const gchar *addr_str;

    addr_str = match_strval(adr, addr_str_vals);

    if (addr_str != NULL)
    {
        return addr_str;
    }
    else
    {
        if (( adr < EPL_MN_NODEID) && (adr > EPL_INVALID_NODEID))
        {
            return addr_str_cn;
        }
        else
        {
            return addr_str_res;
        }
    }
}



/* Get the abbreviation for an EPL NodeID */
/*const gchar*
decode_epl_address_abbrev (guchar adr)
{
    const gchar *addr_str;

    addr_str = match_strval(adr, addr_str_abbr_vals);

    if (addr_str != NULL)
    {
        return addr_str;
    }
    else
    {
        if (( adr < EPL_MN_NODEID) && (adr > EPL_INVALID_NODEID))
        {
            return addr_str_abbr_cn;
        }
        else
        {
            return addr_str_abbr_res;
        }
    }
}
*/


gint
dissect_epl_soc(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
    nstime_t nettime;
    guint8  flags;

    offset += 1;

    flags = tvb_get_guint8(tvb, offset);
    if (epl_tree)
    {
        proto_tree_add_boolean(epl_tree, hf_epl_soc_mc, tvb, offset, 1, flags);
        proto_tree_add_boolean(epl_tree, hf_epl_soc_ps, tvb, offset, 1, flags);
    }
    offset += 2;

    if (show_soc_flags && check_col(pinfo->cinfo, COL_INFO))
    {
	col_append_fstr(pinfo->cinfo, COL_INFO, "MC = %d   PS = %d",
			((EPL_SOC_MC_MASK & flags) >> 7), ((EPL_SOC_PS_MASK & flags) >> 6));
    }

    if (epl_tree)
    {
        nettime.secs  = tvb_get_letohl(tvb, offset);
        nettime.nsecs = tvb_get_letohl(tvb, offset+4);
        proto_tree_add_time_format_value(epl_tree, hf_epl_soc_nettime,
            tvb, offset, 8, &nettime, "%s", abs_time_to_str(&nettime));
        offset += 8;

        proto_tree_add_item(epl_tree, hf_epl_soc_relativetime, tvb, offset, 8, TRUE);
        offset += 8;
    }

    return offset;
}



gint
dissect_epl_preq(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
    guint16 len;
    guint8  pdoversion;
    guint8  flags;

    offset += 1;

    flags = tvb_get_guint8(tvb, offset);
    if (epl_tree)
    {
        proto_tree_add_boolean(epl_tree, hf_epl_preq_ms, tvb, offset, 1, flags);
        proto_tree_add_boolean(epl_tree, hf_epl_preq_ea, tvb, offset, 1, flags);
        proto_tree_add_boolean(epl_tree, hf_epl_preq_rd, tvb, offset, 1, flags);
    }
    offset += 2;

    pdoversion = tvb_get_guint8(tvb, offset);
    if (epl_tree)
    {
        proto_tree_add_string_format(epl_tree, hf_epl_preq_pdov, tvb, offset,
        1, "", "PDOVersion %d.%d",  hi_nibble(pdoversion), lo_nibble(pdoversion));
    }
    offset += 2;

    /* get size of payload */
    len = tvb_get_letohs(tvb, offset);
    if (epl_tree)
    {
        proto_tree_add_uint(epl_tree, hf_epl_preq_size, tvb, offset, 2, len);
    }

    offset += 2;

    if (epl_tree && (len > 0))
    {
        proto_tree_add_item(epl_tree, hf_epl_preq_pl, tvb, offset, len, TRUE);
    }
    offset += len;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "RD = %d   size = %d   ver = %d.%d",
                        (EPL_PDO_RD_MASK & flags), len, hi_nibble(pdoversion), lo_nibble(pdoversion));
    }

    return offset;
}



gint
dissect_epl_pres(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset)
{
    guint16  len;
    guint8  pdoversion;
    guint8  flags;

    if (epl_tree)
    {
        if (epl_src != EPL_MN_NODEID)   /* check if the sender is CN or MN */
        {
            proto_tree_add_item(epl_tree, hf_epl_pres_stat_cs, tvb, offset, 1, TRUE);
        }
        else /* MN */
        {
            proto_tree_add_item(epl_tree, hf_epl_pres_stat_ms, tvb, offset, 1, TRUE);
        }
    }
    offset += 1;

    flags = tvb_get_guint8(tvb, offset);
    if (epl_tree)
    {
        proto_tree_add_boolean(epl_tree, hf_epl_pres_ms, tvb, offset, 1, flags);
        proto_tree_add_boolean(epl_tree, hf_epl_pres_en, tvb, offset, 1, flags);
        proto_tree_add_boolean(epl_tree, hf_epl_pres_rd, tvb, offset, 1, flags);
    }
    offset += 1;

    if (epl_tree)
    {
        proto_tree_add_item(epl_tree, hf_epl_pres_pr, tvb, offset, 1, TRUE);
        proto_tree_add_item(epl_tree, hf_epl_pres_rs, tvb, offset, 1, TRUE);
    }
    offset += 1;

    pdoversion = tvb_get_guint8(tvb, offset);
    if (epl_tree)
    {
        proto_tree_add_string_format(epl_tree, hf_epl_pres_pdov, tvb, offset,
        1, "", "PDOVersion %d.%d",  hi_nibble(pdoversion), lo_nibble(pdoversion));
    }
    offset += 2;

    /* get size of payload */
    len = tvb_get_letohs(tvb, offset);
    if (epl_tree)
    {
        proto_tree_add_uint(epl_tree, hf_epl_pres_size, tvb, offset, 2, len);
    }

    offset += 2;
    if (epl_tree && (len > 0))
    {
        proto_tree_add_item(epl_tree, hf_epl_pres_pl, tvb, offset, len, TRUE);
    }
    offset += len;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "RD = %d   size = %d   ver = %d.%d",
                        (EPL_PDO_RD_MASK & flags), len, hi_nibble(pdoversion), lo_nibble(pdoversion));
    }

    return offset;
}



gint
dissect_epl_soa(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset)
{
    guint8 eplversion;
    guint8 svid, target;

    if (epl_tree)
    {
        if (epl_src != EPL_MN_NODEID)   /* check if CN or MN */
        {
            proto_tree_add_item(epl_tree, hf_epl_soa_stat_cs, tvb, offset, 1, TRUE);
        }
        else /* MN */
        {
            proto_tree_add_item(epl_tree, hf_epl_soa_stat_ms, tvb, offset, 1, TRUE);
        }
    }
    offset += 1;

    if (epl_tree)
    {
        proto_tree_add_item(epl_tree, hf_epl_soa_ea, tvb, offset, 1, TRUE);
        proto_tree_add_item(epl_tree, hf_epl_soa_er, tvb, offset, 1, TRUE);
    }
    offset += 2;

    svid = tvb_get_guint8(tvb, offset);
    if (epl_tree)
    {
        proto_tree_add_uint(epl_tree, hf_epl_soa_svid, tvb, offset, 1, svid);
    }
    offset += 1;

    target = tvb_get_guint8(tvb, offset);
    if (epl_tree)
    {
        proto_tree_add_uint(epl_tree, hf_epl_soa_svtg, tvb, offset, 1, target);
    }
    offset += 1;

    if (svid != EPL_SOA_NOSERVICE && check_col(pinfo->cinfo, COL_INFO))
    {
	col_append_fstr(pinfo->cinfo, COL_INFO, "tgt = %3d   %s",
			target, val_to_str(svid, soa_svid_vals, "Unknown (%d)"));
    }

    if (epl_tree)
    {
        eplversion = tvb_get_guint8(tvb, offset);
        proto_tree_add_string_format(epl_tree, hf_epl_soa_eplv, tvb, offset,
            1, "", "EPLVersion %d.%d",  hi_nibble(eplversion), lo_nibble(eplversion));
    }
    offset += 1;

    return offset;
}



gint
dissect_epl_asnd(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset)
{
    guint8  svid;

    /* get ServiceID of payload */
    svid = tvb_get_guint8(tvb, offset);
    if (epl_tree)
    {
        proto_tree_add_uint(epl_tree, hf_epl_asnd_svid, tvb, offset, 1, svid);
    }

    offset += 1;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s   ",
                        val_to_str(svid, asnd_svid_vals, "Unknown (%d)"));
    }

    switch (svid)
    {
        case EPL_ASND_IDENTRESPONSE:
            offset = dissect_epl_asnd_ires(epl_tree, tvb, pinfo, epl_src, offset);
            break;

        case EPL_ASND_STATUSRESPONSE:
            offset = dissect_epl_asnd_sres(epl_tree, tvb, pinfo, epl_src, offset);
            break;

        case EPL_ASND_NMTREQUEST:
            offset = dissect_epl_asnd_nmtreq(epl_tree, tvb, pinfo, offset);
            break;

        case EPL_ASND_NMTCOMMAND:
            offset = dissect_epl_asnd_nmtcmd(epl_tree, tvb, pinfo, offset);
            break;

        case EPL_ASND_SDO:
            offset = dissect_epl_asnd_sdo(epl_tree, tvb, pinfo, offset);
            break;
    }

    return offset;
}



gint
dissect_epl_asnd_nmtreq(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
    guint8 rcid;

    rcid = tvb_get_guint8(tvb, offset);

    if (epl_tree)
    {
        proto_tree_add_uint(epl_tree, hf_epl_asnd_nmtrequest_rcid, tvb, offset, 1, rcid);
        offset += 1;

        proto_tree_add_item(epl_tree, hf_epl_asnd_nmtrequest_rct, tvb, offset, 1, TRUE);
        offset += 1;

        proto_tree_add_item(epl_tree, hf_epl_asnd_nmtrequest_rcd, tvb, offset, -1, TRUE);
    }

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_str(pinfo->cinfo, COL_INFO,
                        val_to_str(rcid, asnd_cid_vals, "Unknown (%d)"));
    }

    return offset;
}



gint
dissect_epl_asnd_nmtcmd(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
    guint8 epl_asnd_nmtcommand_cid;

    epl_asnd_nmtcommand_cid = tvb_get_guint8(tvb, offset);
    if (epl_tree)
    {
        proto_tree_add_uint(epl_tree, hf_epl_asnd_nmtcommand_cid, tvb, offset, 1, epl_asnd_nmtcommand_cid);
        offset += 2;

        switch (epl_asnd_nmtcommand_cid)
        {
            case EPL_ASND_NMTCOMMAND_NMTNETHOSTNAMESET:
                proto_tree_add_item(epl_tree, hf_epl_asnd_nmtcommand_nmtnethostnameset_hn, tvb, offset, 32, TRUE);
                offset += 32;
                break;

            case EPL_ASND_NMTCOMMAND_NMTFLUSHARPENTRY:
                proto_tree_add_item(epl_tree, hf_epl_asnd_nmtcommand_nmtflusharpentry_nid, tvb, offset, 1, TRUE);
                offset += 1;
                break;

            case EPL_ASND_NMTCOMMAND_NMTPUBLISHTIME:
                proto_tree_add_item(epl_tree, hf_epl_asnd_nmtcommand_nmtpublishtime_dt, tvb, offset, 6, TRUE);
                offset += 6;
                break;

            default:
                proto_tree_add_item(epl_tree, hf_epl_asnd_nmtcommand_cdat, tvb, offset, -1, TRUE);
        }
    }

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_str(pinfo->cinfo, COL_INFO,
                        val_to_str(epl_asnd_nmtcommand_cid, asnd_cid_vals, "Unknown (%d)"));
    }

    return offset;
}



gint
dissect_epl_asnd_ires(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset)
{
    guint8  eplversion;
    guint16 profile,additional;
    guint32 epl_asnd_identresponse_ipa, epl_asnd_identresponse_snm, epl_asnd_identresponse_gtw;
    guint32 epl_asnd_ires_feat, device_type;
    proto_item  *ti_feat;
    proto_tree  *epl_feat_tree;

    device_type = tvb_get_letohl(tvb, offset + 22);
	profile    = tvb_get_letohs(tvb, offset + 22);

    if (epl_tree)
    {
        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_en, tvb, offset, 1, TRUE);
        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_ec, tvb, offset, 1, TRUE);
        offset += 1;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_pr, tvb, offset, 1, TRUE);
        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_rs, tvb, offset, 1, TRUE);
        offset += 1;

        if (epl_src != EPL_MN_NODEID)   /* check if CN or MN */
        {
            proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_stat_cs, tvb, offset, 1, TRUE);
        }
        else /* MN */
        {
            proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_stat_ms, tvb, offset, 1, TRUE);
        }
        offset += 2;

        eplversion = tvb_get_guint8(tvb, offset);
        proto_tree_add_string_format(epl_tree, hf_epl_asnd_identresponse_ever, tvb, offset,
            1, "", "EPLVersion %d.%d",  hi_nibble(eplversion), lo_nibble(eplversion));
        offset += 2;

        /* decode FeatureFlags */
        epl_asnd_ires_feat = tvb_get_letohl(tvb, offset);
        ti_feat = proto_tree_add_uint(epl_tree, hf_epl_asnd_identresponse_feat, tvb, offset, 4, epl_asnd_ires_feat);
        epl_feat_tree = proto_item_add_subtree(ti_feat, ett_epl_feat);
        proto_tree_add_boolean(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit0, tvb, offset, 4, epl_asnd_ires_feat);
        proto_tree_add_boolean(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit1, tvb, offset, 4, epl_asnd_ires_feat);
        proto_tree_add_boolean(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit2, tvb, offset, 4, epl_asnd_ires_feat);
        proto_tree_add_boolean(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit3, tvb, offset, 4, epl_asnd_ires_feat);
        proto_tree_add_boolean(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit4, tvb, offset, 4, epl_asnd_ires_feat);
        proto_tree_add_boolean(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit5, tvb, offset, 4, epl_asnd_ires_feat);
        proto_tree_add_boolean(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit6, tvb, offset, 4, epl_asnd_ires_feat);
        proto_tree_add_boolean(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit7, tvb, offset, 4, epl_asnd_ires_feat);
        proto_tree_add_boolean(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit8, tvb, offset, 4, epl_asnd_ires_feat);
        proto_tree_add_boolean(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit9, tvb, offset, 4, epl_asnd_ires_feat);
        proto_tree_add_boolean(epl_feat_tree, hf_epl_asnd_identresponse_feat_bitA, tvb, offset, 4, epl_asnd_ires_feat);
        proto_tree_add_boolean(epl_feat_tree, hf_epl_asnd_identresponse_feat_bitB, tvb, offset, 4, epl_asnd_ires_feat);
        proto_tree_add_boolean(epl_feat_tree, hf_epl_asnd_identresponse_feat_bitC, tvb, offset, 4, epl_asnd_ires_feat);
        proto_tree_add_boolean(epl_feat_tree, hf_epl_asnd_identresponse_feat_bitD, tvb, offset, 4, epl_asnd_ires_feat);
        offset += 4;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_mtu, tvb, offset, 2, TRUE);
        offset += 2;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_pis, tvb, offset, 2, TRUE);
        offset += 2;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_pos, tvb, offset, 2, TRUE);
        offset += 2;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_rst, tvb, offset, 4, TRUE);
        offset += 6;

        additional = tvb_get_letohs(tvb, offset+2);
        proto_tree_add_string_format(epl_tree, hf_epl_asnd_identresponse_dt, tvb, offset,
            4, "", "Device Type: Profil %d (%s), Additional Information: 0x%4.4X",
            profile, val_to_str(profile, epl_device_profiles, "Unknown Profile"), additional);

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_profile, tvb, offset, 2, TRUE);
        offset += 4;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_vid, tvb, offset, 4, TRUE);
        offset += 4;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_productcode, tvb, offset, 4, TRUE);
        offset += 4;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_rno, tvb, offset, 4, TRUE);
        offset += 4;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_sno, tvb, offset, 4, TRUE);
        offset += 4;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_vex1, tvb, offset, 8, TRUE);
        offset += 8;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_vcd, tvb, offset, 4, TRUE);
        offset += 4;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_vct, tvb, offset, 4, TRUE);
        offset += 4;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_ad, tvb, offset, 4, TRUE);
        offset += 4;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_at, tvb, offset, 4, TRUE);
        offset += 4;

        epl_asnd_identresponse_ipa = tvb_get_ntohl(tvb, offset);
        proto_tree_add_ipv4(epl_tree , hf_epl_asnd_identresponse_ipa, tvb, offset, 4, epl_asnd_identresponse_ipa);
        offset += 4;

        epl_asnd_identresponse_snm = tvb_get_ntohl(tvb, offset);
        proto_tree_add_ipv4(epl_tree , hf_epl_asnd_identresponse_snm, tvb, offset, 4, epl_asnd_identresponse_snm);
        offset += 4;

        epl_asnd_identresponse_gtw = tvb_get_ntohl(tvb, offset);
        proto_tree_add_ipv4(epl_tree , hf_epl_asnd_identresponse_gtw, tvb, offset, 4, epl_asnd_identresponse_gtw);
        offset += 4;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_hn, tvb, offset, 32, TRUE);
        offset += 32;

        proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_vex2, tvb, offset, 48, TRUE);
        offset += 48;
    }

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str(profile, epl_device_profiles, "Device Profile %d"));
    }

    return offset;
}



gint
dissect_epl_asnd_sres(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset)
{
    proto_item  *ti_seb, *ti_el, *ti_el_entry, *ti_el_entry_type;
    proto_tree  *epl_seb_tree, *epl_el_tree, *epl_el_entry_tree, *epl_el_entry_type_tree;
    guint       number_of_entries, cnt;    /* used for dissection of ErrorCodeList */
    guint8      nmt_state;

    if (epl_tree)
    {
        proto_tree_add_item(epl_tree, hf_epl_asnd_statusresponse_en, tvb, offset, 1, TRUE);
        proto_tree_add_item(epl_tree, hf_epl_asnd_statusresponse_ec, tvb, offset, 1, TRUE);
        offset += 1;

        proto_tree_add_item(epl_tree, hf_epl_asnd_statusresponse_pr, tvb, offset, 1, TRUE);
        proto_tree_add_item(epl_tree, hf_epl_asnd_statusresponse_rs, tvb, offset, 1, TRUE);
        offset += 1;
    }
    else
    {
        offset += 2;
    }

    nmt_state = tvb_get_guint8(tvb, offset);
    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s   ", val_to_str(nmt_state, epl_nmt_cs_vals, "Unknown (%d)"));
    }

    if (epl_tree)
    {
        if (epl_src != EPL_MN_NODEID)   /* check if CN or MN */
        {
            proto_tree_add_uint(epl_tree, hf_epl_asnd_statusresponse_stat_cs, tvb, offset, 1, nmt_state);
        }
        else /* MN */
        {
            proto_tree_add_uint(epl_tree, hf_epl_asnd_statusresponse_stat_ms, tvb, offset, 1, nmt_state);
        }
        offset += 4;

        /* Subtree for the static error bitfield */
        ti_seb = proto_tree_add_text(epl_tree, tvb, offset, 8, "StaticErrorBitfield");

        epl_seb_tree = proto_item_add_subtree(ti_seb, ett_epl_seb);

        proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit0, tvb, offset, 1, TRUE);
        proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit1, tvb, offset, 1, TRUE);
        proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit2, tvb, offset, 1, TRUE);
        proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit3, tvb, offset, 1, TRUE);
        proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit4, tvb, offset, 1, TRUE);
        proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit5, tvb, offset, 1, TRUE);
        proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit7, tvb, offset, 1, TRUE);
        offset += 2;

        proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_devicespecific_err, tvb,offset, 6, TRUE);
        offset += 6;

        /* List of errors / events */
        /* get the number of entries in the error code list*/
        number_of_entries = (tvb_length(tvb)-offset)/20;

        ti_el = proto_tree_add_text(epl_tree, tvb, offset, -1, "ErrorCodeList: %d entries", number_of_entries);

        epl_el_tree = proto_item_add_subtree(ti_el, ett_epl_el);

        /*Dissect the whole Error List (display each entry)*/
        for (cnt = 0; cnt<number_of_entries; cnt++)
        {
            ti_el_entry = proto_tree_add_text(ti_el, tvb, offset, 20, "Entry %d", cnt+1);

            epl_el_entry_tree = proto_item_add_subtree(ti_el_entry, ett_epl_el_entry);

            /*Entry Type*/
            ti_el_entry_type = proto_tree_add_item(ti_el_entry,
            hf_epl_asnd_statusresponse_el_entry_type, tvb, offset, 2, TRUE);

            epl_el_entry_type_tree = proto_item_add_subtree(ti_el_entry_type,
                ett_epl_el_entry_type);

            proto_tree_add_item(epl_el_entry_type_tree,
                hf_epl_asnd_statusresponse_el_entry_type_profile, tvb, offset, 2, TRUE);

            proto_tree_add_item(epl_el_entry_type_tree,
                hf_epl_asnd_statusresponse_el_entry_type_mode, tvb, offset, 2, TRUE);

            proto_tree_add_item(epl_el_entry_type_tree,
                hf_epl_asnd_statusresponse_el_entry_type_bit14, tvb, offset, 2, TRUE);

            proto_tree_add_item(epl_el_entry_type_tree,
                hf_epl_asnd_statusresponse_el_entry_type_bit15, tvb, offset, 2, TRUE);
            offset += 2;

            proto_tree_add_item(epl_el_entry_tree, hf_epl_asnd_statusresponse_el_entry_code, tvb, offset, 2, TRUE);
            offset += 2;

            proto_tree_add_item(epl_el_entry_tree, hf_epl_asnd_statusresponse_el_entry_time, tvb, offset, 8, TRUE);
            offset += 8;

            proto_tree_add_item(epl_el_entry_tree, hf_epl_asnd_statusresponse_el_entry_add, tvb, offset, 8, TRUE);
            offset += 8;
        }
    }

    return offset;
}



gint
dissect_epl_asnd_sdo(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
    offset = dissect_epl_sdo_sequence(epl_tree, tvb, pinfo, offset);

    if (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        offset = dissect_epl_sdo_command(epl_tree, tvb, pinfo, offset);
    }
    else if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "Empty CommandLayer");
    }

    return offset;
}


gint
dissect_epl_sdo_sequence(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
    guint8 seq_recv, seq_send;

    /* Asynchronuous SDO Sequence Layer */
    seq_recv = tvb_get_guint8(tvb, offset);

    if (epl_tree)
    {
        proto_tree_add_uint(epl_tree, hf_epl_asnd_sdo_seq_receive_sequence_number, tvb, offset, 1, seq_recv);
        proto_tree_add_uint(epl_tree, hf_epl_asnd_sdo_seq_receive_con,             tvb, offset, 1, seq_recv);
    }
    offset += 1;

    seq_send = tvb_get_guint8(tvb, offset);

    if (epl_tree)
    {
        proto_tree_add_uint(epl_tree, hf_epl_asnd_sdo_seq_send_sequence_number, tvb, offset, 1, seq_send);
        proto_tree_add_uint(epl_tree, hf_epl_asnd_sdo_seq_send_con, tvb, offset, 1, seq_send);
    }
    offset += 3;

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        seq_recv &= EPL_ASND_SDO_SEQ_CON_MASK;
        seq_send &= EPL_ASND_SDO_SEQ_CON_MASK;
        if ((seq_recv == 0x00) && (seq_send == 0x00))
        {   /* Sequence layer will be closed */
            col_append_str(pinfo->cinfo, COL_INFO, "Close  ");
        }
        else if ((seq_recv < 0x02) || (seq_send < 0x02))
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Init=%d%d  ",
                            seq_recv, seq_send);
        }
    }

    return offset;
}



gint
dissect_epl_sdo_command(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
    guint8  segmented, command_id;
    gboolean response, abort_flag;
    guint32 abort_code;
    guint16 segment_size;

    offset += 1;
    segmented = FALSE;

    command_id = tvb_get_guint8(tvb, offset + 2);

    abort_flag      = tvb_get_guint8(tvb, offset + 1) & EPL_ASND_SDO_CMD_ABORT_FILTER;

    /* test if CommandField == empty */
    if (command_id != 0 || abort_flag)
    {
        segmented  = (tvb_get_guint8(tvb, offset + 1) & EPL_ASND_SDO_CMD_SEGMENTATION_FILTER) >> 4;
        response   = tvb_get_guint8(tvb, offset + 1) & EPL_ASND_SDO_CMD_RESPONSE_FILTER;
        segment_size = tvb_get_letohs(tvb, offset + 3);

        if (epl_tree)
        {
            proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_transaction_id, tvb, offset, 1, TRUE);
            offset += 1;

            proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_response, tvb, offset, 1, TRUE);
            proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_abort,    tvb, offset, 1, TRUE);

            proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_segmentation, tvb, offset, 1, TRUE);
            offset += 1;

            proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_command_id, tvb, offset, 1, TRUE);
            offset += 1;

            proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_segment_size, tvb, offset, 2, TRUE);
            offset += 4;
        }
        else
        {
            offset += 7;
        }

        /* adjust size of packet */
        tvb_set_reported_length(tvb, offset + segment_size);

        if (segmented == EPL_ASND_SDO_CMD_SEGMENTATION_INITIATE_TRANSFER)
        {
            /* if Segmentation = Initiate then print DataSize */
            if (epl_tree)
            {
                proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_data_size, tvb, offset, 4, TRUE);
            }
            segmented = TRUE;
            offset += 4;
        }

        if (abort_flag)
        {
            abort_code = tvb_get_letohl(tvb, offset);
            /* if AbortBit is set then print AbortMessage */
            if (epl_tree)
            {
                proto_tree_add_uint(epl_tree, hf_epl_asnd_sdo_cmd_abort_code, tvb, offset, 4, abort_code);
            }
            if (check_col(pinfo->cinfo, COL_INFO))
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Abort = 0x%08X", abort_code);
            }
        }
        else
        {
            switch (command_id)
            {
                case EPL_ASND_SDO_COMMAND_WRITE_BY_INDEX:
                    offset = dissect_epl_sdo_command_write_by_index(epl_tree, tvb, pinfo, offset, segmented, response);
                    break;

                case EPL_ASND_SDO_COMMAND_READ_BY_INDEX:
                    offset = dissect_epl_sdo_command_read_by_index(epl_tree, tvb, pinfo, offset, segmented, response);
                    break;

                default:
                    return FALSE;
            }
        }
    }
    return offset;
}



gint
dissect_epl_sdo_command_write_by_index(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 segmented, gboolean response)
{
    gint size;
    guint16 index;
    guint8 subindex;
    guint32 val;
    proto_item* item;

    if (!response)
    {   /* request */
        if (segmented <= EPL_ASND_SDO_CMD_SEGMENTATION_INITIATE_TRANSFER)
        {
            index = tvb_get_letohs(tvb, offset);
            if (epl_tree)
            {
                proto_tree_add_uint(epl_tree, hf_epl_asnd_sdo_cmd_write_by_index_index, tvb, offset, 2, index);
            }
            offset += 2;

            subindex = tvb_get_guint8(tvb, offset);
            if (epl_tree)
            {
                proto_tree_add_uint(epl_tree, hf_epl_asnd_sdo_cmd_write_by_index_subindex, tvb, offset, 1, subindex);
            }
            offset += 2;

            if (check_col(pinfo->cinfo, COL_INFO))
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Write 0x%04X/%d", index, subindex);
            }
        }
        else if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Requ. %s",
                            val_to_str(segmented, epl_sdo_asnd_cmd_segmentation, "Unknown (%d)"));
        }

        if (epl_tree)
        {
            size = tvb_reported_length_remaining(tvb, offset);
            item = proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_write_by_index_data, tvb, offset, size, TRUE);

            if (size == 4)
            {
                val = tvb_get_letohl(tvb, offset);
                proto_item_append_text(item, " (%d)", val);
            }
            else if (size == 2)
            {
                val = tvb_get_letohs(tvb, offset);
                proto_item_append_text(item, " (%d)", val);
            }
            else if (size == 1)
            {
                val = tvb_get_guint8(tvb, offset);
                proto_item_append_text(item, " (%d)", val);
            }

            offset += size;
        }
    }
    else
    {
        /* response, no payload */
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_append_str(pinfo->cinfo, COL_INFO, "Response");
        }
    }
    return offset;
}



gint
dissect_epl_sdo_command_read_by_index(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 segmented, gboolean response)
{
    gint size;
    guint16 index;
    guint8 subindex;
    guint32 val;
    proto_item* item;

    if (!response)
    {   /* request */
        index = tvb_get_letohs(tvb, offset);
        if (epl_tree)
        {
            proto_tree_add_uint(epl_tree, hf_epl_asnd_sdo_cmd_read_by_index_index, tvb, offset, 2, index);
        }
        offset += 2;

        subindex = tvb_get_guint8(tvb, offset);
        if (epl_tree)
        {
            proto_tree_add_uint(epl_tree, hf_epl_asnd_sdo_cmd_read_by_index_subindex, tvb, offset, 1, subindex);
        }
        offset += 1;

        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Read 0x%04X/%d", index, subindex);
        }

    }
    else
    {   /* response */
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Resp. %s",
                            val_to_str(segmented, epl_sdo_asnd_cmd_segmentation, "Unknown (%d)"));
        }

        if (epl_tree)
        {
            size = tvb_reported_length_remaining(tvb, offset);
            item = proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_read_by_index_data, tvb, offset, size, TRUE);

            if (size == 4)
            {
                val = tvb_get_letohl(tvb, offset);
                proto_item_append_text(item, " (%d)", val);
            }
            else if (size == 2)
            {
                val = tvb_get_letohs(tvb, offset);
                proto_item_append_text(item, " (%d)", val);
            }
            else if (size == 1)
            {
                val = tvb_get_guint8(tvb, offset);
                proto_item_append_text(item, " (%d)", val);
            }

            offset += size;
        }
    }

    return offset;
}



/* Register the protocol with Wireshark */
void
proto_register_epl(void)
{
static hf_register_info hf[] = {

/* Common data fields (same for all message types) */
{ &hf_epl_mtyp,         { "MessageType",                        "epl.mtyp",             FT_UINT8,   BASE_DEC, VALS(mtyp_vals),      0x7F, NULL, HFILL }},
{ &hf_epl_dest,         { "Destination",                        "epl.dest",             FT_UINT8,   BASE_DEC_HEX, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_src,          { "Source",                             "epl.src",              FT_UINT8,   BASE_DEC_HEX, NULL,                 0x00, NULL, HFILL }},

/* SoC data fields*/
{ &hf_epl_soc_mc,       { "MC (Multiplexed Cycle Completed)",   "epl.soc.mc",           FT_BOOLEAN,   8, NULL,                 EPL_SOC_MC_MASK, NULL, HFILL }},
{ &hf_epl_soc_ps,       { "PS (Prescaled Slot)",                "epl.soc.ps",           FT_BOOLEAN,   8, NULL,                 EPL_SOC_PS_MASK, NULL, HFILL }},
{ &hf_epl_soc_nettime,  { "NetTime",                            "epl.soc.nettime",      FT_ABSOLUTE_TIME,   BASE_NONE, NULL,                 0x0,  NULL, HFILL }},
{ &hf_epl_soc_relativetime,{ "RelativeTime",                    "epl.soc.relativetime", FT_UINT64,  BASE_DEC, NULL,                 0x0,  NULL, HFILL }},

/* PReq data fields*/
{ &hf_epl_preq_ms,      { "MS (Multiplexed Slot)",              "epl.preq.ms",          FT_BOOLEAN,   8, NULL,                 0x20, NULL, HFILL }},
{ &hf_epl_preq_ea,      { "EA (Exception Acknowledge)",         "epl.preq.ea",          FT_BOOLEAN,   8, NULL,                 0x04, NULL, HFILL }},
{ &hf_epl_preq_rd,      { "RD (Ready)",                         "epl.preq.rd",          FT_BOOLEAN,   8, NULL,                 EPL_PDO_RD_MASK, NULL, HFILL }},
{ &hf_epl_preq_pdov,    { "PDOVersion",                         "epl.preq.pdov",        FT_STRING,  BASE_NONE, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_preq_size,    { "Size",                               "epl.preq.size",        FT_UINT16,  BASE_DEC, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_preq_pl,      { "Payload",                            "epl.preq.pl",          FT_BYTES,   BASE_NONE, NULL,                 0x00, NULL, HFILL }},

/* PRes data fields*/
{ &hf_epl_pres_stat_ms, { "NMTStatus",                          "epl.pres.stat",        FT_UINT8,   BASE_HEX, VALS(epl_nmt_ms_vals),0x00, NULL, HFILL }},
{ &hf_epl_pres_stat_cs, { "NMTStatus",                          "epl.pres.stat",        FT_UINT8,   BASE_HEX, VALS(epl_nmt_cs_vals),0x00, NULL, HFILL }},
{ &hf_epl_pres_ms,      { "MS (Multiplexed Slot)",              "epl.pres.ms",          FT_BOOLEAN,   8, NULL,                 0x20, NULL, HFILL }},
{ &hf_epl_pres_en,      { "EN (Exception New)",                 "epl.pres.en",          FT_BOOLEAN,   8, NULL,                 0x10, NULL, HFILL }},
{ &hf_epl_pres_rd,      { "RD (Ready)",                         "epl.pres.rd",          FT_BOOLEAN,   8, NULL,                 EPL_PDO_RD_MASK, NULL, HFILL }},
{ &hf_epl_pres_pr,      { "PR (Priority)",                      "epl.pres.pr",          FT_UINT8,   BASE_DEC, VALS(epl_pr_vals),    0x38, NULL, HFILL }},
{ &hf_epl_pres_rs,      { "RS (RequestToSend)",                 "epl.pres.rs",          FT_UINT8,   BASE_DEC, NULL,                 0x07, NULL, HFILL }},
{ &hf_epl_pres_pdov,    { "PDOVersion",                         "epl.pres.pdov",        FT_STRING,  BASE_NONE, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_pres_size,    { "Size",                               "epl.pres.size",        FT_UINT16,  BASE_DEC, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_pres_pl,      { "Payload",                            "epl.pres.pl",          FT_BYTES,   BASE_NONE, NULL,                 0x00, NULL, HFILL }},

/* SoA data fields*/
{ &hf_epl_soa_stat_ms,  { "NMTStatus",                          "epl.soa.stat",         FT_UINT8,   BASE_HEX, VALS(epl_nmt_ms_vals),0x00, NULL, HFILL }},
{ &hf_epl_soa_stat_cs,  { "NMTStatus",                          "epl.soa.stat",         FT_UINT8,   BASE_HEX, VALS(epl_nmt_cs_vals),0x00, NULL, HFILL }},
{ &hf_epl_soa_ea,       { "EA (Exception Acknowledge)",         "epl.soa.ea",           FT_BOOLEAN,        8, NULL,                 0x04, NULL, HFILL }},
{ &hf_epl_soa_er,       { "ER (Exception Reset)",               "epl.soa.er",           FT_BOOLEAN,        8, NULL,                 0x02, NULL, HFILL }},
{ &hf_epl_soa_svid,     { "RequestedServiceID",                 "epl.soa.svid",         FT_UINT8,   BASE_DEC, VALS(soa_svid_vals),  0x00, NULL, HFILL }},
{ &hf_epl_soa_svtg,     { "RequestedServiceTarget",             "epl.soa.svtg",         FT_UINT8,   BASE_DEC, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_soa_eplv,     { "EPLVersion",                         "epl.soa.eplv",         FT_STRING,  BASE_NONE, NULL,                 0x00, NULL, HFILL }},

/* ASnd header */
{ &hf_epl_asnd_svid,    { "ServiceID",                          "epl.asnd.svid",    FT_UINT8, BASE_DEC, VALS(asnd_svid_vals),   0x00,NULL, HFILL }},
{ &hf_epl_asnd_data,    { "Data",                               "epl.asnd.data",    FT_BYTES, BASE_NONE, NULL,                   0x00,NULL, HFILL }},

/* ASnd-->IdentResponse */
{ &hf_epl_asnd_identresponse_en,      { "EN (Exception New)",       "epl.asnd.ires.en",             FT_BOOLEAN,        8, NULL,                 0x10, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_ec,      { "EC (Exception Clear)",     "epl.asnd.ires.ec",             FT_BOOLEAN,        8, NULL,                 0x08, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_pr,      { "PR (Priority)",            "epl.asnd.ires.pr",             FT_UINT8,   BASE_DEC, VALS(epl_pr_vals),    0x38, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_rs,      { "RS (RequestToSend)",       "epl.asnd.ires.rs",             FT_UINT8,   BASE_DEC, NULL,                 0x07, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_stat_ms, { "NMTStatus",                "epl.asnd.ires.state",          FT_UINT8,   BASE_HEX, VALS(epl_nmt_ms_vals),0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_stat_cs, { "NMTStatus",                "epl.asnd.ires.state",          FT_UINT8,   BASE_HEX, VALS(epl_nmt_cs_vals),0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_ever,    { "EPLVersion",               "epl.asnd.ires.eplver",         FT_STRING,  BASE_NONE, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat,    { "FeatureFlags",             "epl.asnd.ires.features",       FT_UINT32,  BASE_HEX, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat_bit0,   { "Isochronous",              "epl.asnd.ires.features.bit0",  FT_BOOLEAN,  32, NULL,           0x0001, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat_bit1,   { "SDO by UDP/IP",            "epl.asnd.ires.features.bit1",  FT_BOOLEAN,  32, NULL,           0x0002, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat_bit2,   { "SDO by ASnd",              "epl.asnd.ires.features.bit2",  FT_BOOLEAN,  32, NULL,           0x0004, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat_bit3,   { "SDO by PDO",               "epl.asnd.ires.features.bit3",  FT_BOOLEAN,  32, NULL,           0x0008, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat_bit4,   { "NMT Info Services",        "epl.asnd.ires.features.bit4",  FT_BOOLEAN,  32, NULL,           0x0010, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat_bit5,   { "Ext. NMT State Commands",  "epl.asnd.ires.features.bit5",  FT_BOOLEAN,  32, NULL,           0x0020, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat_bit6,   { "Dynamic PDO Mapping",      "epl.asnd.ires.features.bit6",  FT_BOOLEAN,  32, NULL,           0x0040, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat_bit7,   { "NMT Service by UDP/IP",    "epl.asnd.ires.features.bit7",  FT_BOOLEAN,  32, NULL,           0x0080, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat_bit8,   { "Configuration Manager",    "epl.asnd.ires.features.bit8",  FT_BOOLEAN,  32, NULL,           0x0100, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat_bit9,   { "Multiplexed Access",       "epl.asnd.ires.features.bit9",  FT_BOOLEAN,  32, NULL,           0x0200, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat_bitA,   { "NodeID setup by SW",       "epl.asnd.ires.features.bitA",  FT_BOOLEAN,  32, NULL,           0x0400, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat_bitB,   { "MN Basic Ethernet Mode",   "epl.asnd.ires.features.bitB",  FT_BOOLEAN,  32, NULL,           0x0800, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat_bitC,   { "Routing Type 1 Support",   "epl.asnd.ires.features.bitC",  FT_BOOLEAN,  32, NULL,           0x1000, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_feat_bitD,   { "Routing Type 2 Support",   "epl.asnd.ires.features.bitD",  FT_BOOLEAN,  32, NULL,           0x2000, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_mtu,     { "MTU",                      "epl.asnd.ires.mtu",            FT_UINT16,  BASE_DEC, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_pis,     { "PollInSize",               "epl.asnd.ires.pollinsize",     FT_UINT16,  BASE_DEC, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_pos,     { "PollOutSize",              "epl.asnd.ires.polloutsizes",   FT_UINT16,  BASE_DEC, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_rst,     { "ResponseTime",             "epl.asnd.ires.resptime",       FT_UINT32,  BASE_DEC, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_dt,      { "DeviceType",               "epl.asnd.ires.devicetype",     FT_STRING,  BASE_NONE, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_profile, { "Profile",                  "epl.asnd.ires.profile",        FT_UINT16,  BASE_DEC, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_vid,     { "VendorId",                 "epl.asnd.ires.vendorid",       FT_UINT32,  BASE_DEC_HEX, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_productcode,{ "ProductCode",           "epl.asnd.ires.productcode",    FT_UINT32,  BASE_DEC_HEX, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_rno,     { "RevisionNumber",           "epl.asnd.ires.revisionno",     FT_UINT32,  BASE_DEC_HEX, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_sno,     { "SerialNumber",             "epl.asnd.ires.serialno",       FT_UINT32,  BASE_DEC_HEX, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_vex1,    { "VendorSpecificExtension1", "epl.asnd.ires.vendorext1",     FT_UINT64,  BASE_DEC_HEX, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_vcd,     { "VerifyConfigurationDate",  "epl.asnd.ires.confdate",       FT_UINT32,  BASE_DEC_HEX, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_vct,     { "VerifyConfigurationTime",  "epl.asnd.ires.conftime",       FT_UINT32,  BASE_DEC_HEX, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_ad,      { "applicationSwDate",        "epl.asnd.ires.appswdate",      FT_UINT32,  BASE_DEC_HEX, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_at,      { "applicationSwTime",        "epl.asnd.ires.appswtime",      FT_UINT32,  BASE_DEC_HEX, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_ipa,     { "IPAddress",                "epl.asnd.ires.ip",             FT_IPv4,    BASE_NONE, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_snm,     { "SubnetMask",               "epl.asnd.ires.subnet",         FT_IPv4,    BASE_NONE, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_gtw,     { "DefaultGateway",           "epl.asnd.ires.gateway",        FT_IPv4,    BASE_NONE, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_hn,      { "HostName",                 "epl.asnd.ires.hostname",       FT_STRING,  BASE_NONE, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_identresponse_vex2,    { "VendorSpecificExtension2", "epl.asnd.ires.vendorext2",     FT_BYTES,   BASE_NONE, NULL,                 0x00, NULL, HFILL }},


/* ASnd-->StatusResponse */
{ &hf_epl_asnd_statusresponse_en,                               { "EN (Exception New)",         "epl.asnd.sres.en",                     FT_BOOLEAN,      8, NULL,                   0x10, NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_ec,                               { "EC (Exception Clear)",       "epl.asnd.sres.ec",                     FT_BOOLEAN,      8, NULL,                   0x08, NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_pr,                               { "PR (Priority)",              "epl.asnd.sres.pr",                     FT_UINT8, BASE_DEC, VALS(epl_pr_vals),      0x38, NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_rs,                               { "RS (RequestToSend)",         "epl.asnd.sres.rs",                     FT_UINT8, BASE_DEC, NULL,                   0x07, NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_stat_ms,                          { "NMTStatus",                  "epl.asnd.sres.stat",                   FT_UINT8, BASE_HEX, VALS(epl_nmt_ms_vals),  0x00, NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_stat_cs,                          { "NMTStatus",                  "epl.asnd.sres.stat",                   FT_UINT8, BASE_HEX, VALS(epl_nmt_cs_vals),  0x00, NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_seb,                              { "StaticErrorBitField",        "epl.asnd.sres.seb",                    FT_BYTES, BASE_NONE, NULL,                   0x00, NULL, HFILL }},

/*StaticErrorBitField */
{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit0,    { "Generic error",              "epl.asnd.res.seb.bit0",                FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit1,    { "Current",                    "epl.asnd.res.seb.bit1",                FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit2,    { "Voltage",                    "epl.asnd.res.seb.bit2",                FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit3,    { "Temperature",                "epl.asnd.res.seb.bit3",                FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit4,    { "Communication error",        "epl.asnd.res.seb.bit4",                FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit5,    { "Device profile specific",    "epl.asnd.res.seb.bit5",                FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit7,    { "Manufacturer specific",      "epl.asnd.res.seb.bit7",                FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_seb_devicespecific_err,           { "Device profile specific",    "epl.asnd.res.seb.devicespecific_err",FT_BYTES, BASE_NONE,NULL, 0x00, NULL, HFILL }},

{ &hf_epl_asnd_statusresponse_el,                               { "ErrorCodesList",             "epl.asnd.sres.el",                     FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry,                         { "Entry",                      "epl.asnd.sres.el.entry",               FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }},

/*List of Errors/Events*/
{ &hf_epl_asnd_statusresponse_el_entry_type,                    { "Entry Type",                 "epl.asnd.sres.el.entry.type",          FT_UINT16, BASE_HEX, NULL, 0x00,    NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry_type_profile,            { "Profile",                    "epl.asnd.sres.el.entry.type.profile",  FT_UINT16, BASE_DEC, NULL, 0x0FFF,  NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry_type_mode,               { "Mode",                       "epl.asnd.sres.el.entry.type.mode",     FT_UINT16, BASE_DEC, NULL, 0x3000,  NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry_type_bit14,              { "Bit14",                      "epl.asnd.sres.el.entry.type.bit14",    FT_UINT16, BASE_DEC, NULL, 0x4000,  NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry_type_bit15,              { "Bit15",                      "epl.asnd.sres.el.entry.type.bit15",    FT_UINT16, BASE_DEC, NULL, 0x8000,  NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry_code,                    { "Error Code",                 "epl.asnd.sres.el.entry.code",          FT_UINT16, BASE_DEC, NULL, 0x00,    NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry_time,                    { "Time Stamp",                 "epl.asnd.sres.el.entry.time",          FT_UINT64, BASE_DEC, NULL, 0x00,    NULL, HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry_add,                     { "Additional Information",     "epl.asnd.sres.el.entry.add",           FT_UINT64, BASE_DEC, NULL, 0x00,    NULL, HFILL }},


/* ASnd-->NMTRequest */
{ &hf_epl_asnd_nmtrequest_rcid,                     { "NMTRequestedCommandID",      "epl.asnd.nmtrequest.rcid",                     FT_UINT8,   BASE_HEX_DEC, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_nmtrequest_rct,                      { "NMTRequestedCommandTarget",  "epl.asnd.nmtrequest.rct",                      FT_UINT8,   BASE_DEC_HEX, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_nmtrequest_rcd,                      { "NMTRequestedCommandData",    "epl.asnd.nmtrequest.rcd",                      FT_BYTES,   BASE_NONE, NULL,                 0x00, NULL, HFILL }},

/* ASnd-->NMTCommand */
{ &hf_epl_asnd_nmtcommand_cid,                      { "NMTCommandId",               "epl.asnd.nmtcommand.cid",                      FT_UINT8,   BASE_HEX_DEC, VALS(asnd_cid_vals),  0x00, NULL, HFILL }},
{ &hf_epl_asnd_nmtcommand_cdat,                     { "NMTCommandData",             "epl.asnd.nmtcommand.cdat",                     FT_BYTES,   BASE_NONE, NULL,                 0x00, NULL, HFILL }},

{ &hf_epl_asnd_nmtcommand_nmtnethostnameset_hn,     { "HostName",                   "epl.asnd.nmtcommand.nmtnethostnameset.hn",     FT_BYTES,   BASE_NONE, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_nmtcommand_nmtflusharpentry_nid,     { "NodeID",                     "epl.asnd.nmtcommand.nmtflusharpentry.nid",     FT_UINT8,   BASE_DEC_HEX, NULL,                 0x00, NULL, HFILL }},
{ &hf_epl_asnd_nmtcommand_nmtpublishtime_dt,        { "DateTime",                   "epl.asnd.nmtcommand.nmtpublishtime.dt",        FT_BYTES,   BASE_NONE, NULL,                 0x00, NULL, HFILL }},

/* ASnd-->SDO */
{ &hf_epl_asnd_sdo_seq_receive_sequence_number, { "ReceiveSequenceNumber",          "epl.asnd.sdo.seq.receive.sequence.number", FT_UINT8,   BASE_DEC, NULL,                             0xfc, NULL, HFILL }},
{ &hf_epl_asnd_sdo_seq_receive_con,             { "ReceiveCon",                     "epl.asnd.sdo.seq.receive.con",             FT_UINT8,   BASE_DEC, VALS(epl_sdo_receive_con_vals),   0x03, NULL, HFILL }},
{ &hf_epl_asnd_sdo_seq_send_sequence_number,    { "SendSequenceNumber",             "epl.asnd.sdo.seq.send.sequence.number",    FT_UINT8,   BASE_DEC, NULL,                             0xfc, NULL, HFILL }},
{ &hf_epl_asnd_sdo_seq_send_con,                { "SendCon",                        "epl.asnd.sdo.seq.send.con",                FT_UINT8,   BASE_DEC, VALS(epl_sdo_send_con_vals),      0x03, NULL, HFILL }},

{ &hf_epl_asnd_sdo_cmd_transaction_id,          { "SDO Transaction ID",             "epl.asnd.sdo.cmd.transaction.id",          FT_UINT8,   BASE_DEC, NULL,                             0x00, NULL, HFILL }},
{ &hf_epl_asnd_sdo_cmd_response,                { "SDO Response",                   "epl.asnd.sdo.cmd.response",                FT_UINT8,   BASE_DEC, VALS(epl_sdo_asnd_cmd_response),  0x80, NULL, HFILL }},
{ &hf_epl_asnd_sdo_cmd_abort,                   { "SDO Abort",                      "epl.asnd.sdo.cmd.abort",                   FT_UINT8,   BASE_DEC, VALS(epl_sdo_asnd_cmd_abort),     0x40, NULL, HFILL }},
{ &hf_epl_asnd_sdo_cmd_segmentation,            { "SDO Segmentation",               "epl.asnd.sdo.cmd.segmentation",            FT_UINT8,   BASE_DEC, VALS(epl_sdo_asnd_cmd_segmentation), 0x30, NULL, HFILL }},
{ &hf_epl_asnd_sdo_cmd_command_id,              { "SDO Command ID",                 "epl.asnd.sdo.cmd.command.id",              FT_UINT8,   BASE_DEC, VALS(epl_sdo_asnd_commands),      0x00, NULL, HFILL }},
{ &hf_epl_asnd_sdo_cmd_segment_size,            { "SDO Segment size",               "epl.asnd.sdo.cmd.segment.size",            FT_UINT8,   BASE_DEC, NULL,                             0x00, NULL, HFILL }},
{ &hf_epl_asnd_sdo_cmd_data_size,               { "SDO Data size",                  "epl.asnd.sdo.cmd.data.size",               FT_UINT8,   BASE_DEC, NULL,                             0x00, NULL, HFILL } },
{ &hf_epl_asnd_sdo_cmd_abort_code,              { "SDO Transfer Abort",             "epl.asnd.sdo.cmd.abort.code",              FT_UINT8,   BASE_HEX, VALS(sdo_cmd_abort_code),         0x00, NULL, HFILL }},
{ &hf_epl_asnd_sdo_cmd_write_by_index_index,    { "SDO Write by Index, Index",      "epl.asnd.sdo.cmd.write.by.index.index",    FT_UINT16,  BASE_HEX, NULL,                             0x00, NULL, HFILL }},
{ &hf_epl_asnd_sdo_cmd_write_by_index_subindex, { "SDO Write by Index, SubIndex",   "epl.asnd.sdo.cmd.write.by.index.subindex", FT_UINT8,   BASE_HEX, NULL,                             0x00, NULL, HFILL }},
{ &hf_epl_asnd_sdo_cmd_read_by_index_index,     { "SDO Read by Index, Index",       "epl.asnd.sdo.cmd.read.by.index.index",     FT_UINT16,  BASE_HEX, NULL,                             0x00, NULL, HFILL }},
{ &hf_epl_asnd_sdo_cmd_read_by_index_subindex,  { "SDO Read by Index, SubIndex",    "epl.asnd.sdo.cmd.read.by.index.subindex",  FT_UINT8,   BASE_HEX, NULL,                             0x00, NULL, HFILL }},
{ &hf_epl_asnd_sdo_cmd_write_by_index_data,     { "Payload",                        "epl.asnd.sdo.cmd.write.by.index.data",     FT_BYTES,   BASE_NONE, NULL,                             0x00, NULL, HFILL }},
{ &hf_epl_asnd_sdo_cmd_read_by_index_data,      { "Payload",                        "epl.asnd.sdo.cmd.read.by.index.data",      FT_BYTES,   BASE_NONE, NULL,                             0x00, NULL, HFILL }},
};


    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_epl,
        &ett_epl_feat,
        &ett_epl_seb,
        &ett_epl_el,
        &ett_epl_el_entry,
        &ett_epl_el_entry_type,
        &ett_epl_sdo_entry_type,
    };

    module_t *epl_module;

    /* Register the protocol name and description */
    proto_epl = proto_register_protocol("Ethernet POWERLINK V2", "EPL", "epl");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_epl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* register preferences */
    epl_module = prefs_register_protocol(proto_epl, NULL);

    prefs_register_bool_preference(epl_module, "show_soc_flags", "Show flags of SoC frame in Info column",
        "If you are capturing in networks with multiplexed or slow nodes, this can be useful", &show_soc_flags);

    /* tap-registration */
    /*  epl_tap = register_tap("epl");*/
}



void
proto_reg_handoff_epl(void)
{
    dissector_handle_t epl_handle;

    epl_handle = new_create_dissector_handle(dissect_epl, proto_epl);
    dissector_add("ethertype", ETHERTYPE_EPL_V2, epl_handle);
    dissector_add("udp.port", UDP_PORT_EPL, epl_handle);
}

