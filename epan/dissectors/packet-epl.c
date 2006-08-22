/* packet-epl.c
 * Routines for "Ethernet Powerlink 2.0" dissection 
 * (ETHERNET Powerlink V2.0 Communication Profile Specification Draft Standard Version 1.0.0)
 *
 * Copyright (c) 2006: Zurich University of Applied Sciences Winterthur (ZHW)
 *                     Institute of Embedded Systems (InES)
 *                     http://ines.zhwin.ch
 *                     
 *                     - Dominic BÇchaz <bdo@zhwin.ch>
 *                     - Damir Bursic <bum@zhwin.ch>
 *                     - David BÅchi <bhd@zhwin.ch>
 *
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
#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/etypes.h>

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
static gint hf_epl_asnd_identresponse_mtu            = -1;
static gint hf_epl_asnd_identresponse_pis            = -1;
static gint hf_epl_asnd_identresponse_pos            = -1;
static gint hf_epl_asnd_identresponse_rst            = -1;
static gint hf_epl_asnd_identresponse_dt             = -1;
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
static gint hf_epl_asnd_nmtcommand_nmtnetparameterset_mtu    = -1;
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
static gint hf_epl_asnd_sdo_cmd_abort_flag                   = -1;
static gint hf_epl_asnd_sdo_cmd_segmentation_flag            = -1;
static gint hf_epl_asnd_sdo_cmd_cmd_valid_test               = -1;

static gint hf_epl_asnd_sdo_actual_command_id                = -1;

static gint hf_epl_asnd_sdo_cmd_write_by_index_index         = -1;
static gint hf_epl_asnd_sdo_cmd_write_by_index_subindex      = -1;
static gint hf_epl_asnd_sdo_cmd_write_by_index_data          = -1;
static gint hf_epl_asnd_sdo_cmd_write_by_index_response      = -1;

static gint hf_epl_asnd_sdo_cmd_read_by_index_index          = -1;
static gint hf_epl_asnd_sdo_cmd_read_by_index_subindex       = -1;
static gint hf_epl_asnd_sdo_cmd_read_by_index_data           = -1;
static gint hf_epl_asnd_sdo_cmd_read_by_index_response       = -1;

static gint hf_epl_asnd_sdo_actual_segment_size              = -1;
static gint hf_epl_asnd_sdo_actual_payload_size_read         = -1;

/* Initialize the subtree pointers */
static gint ett_epl                 = -1;
static gint ett_epl_seb             = -1;
static gint ett_epl_el              = -1;
static gint ett_epl_el_entry        = -1;
static gint ett_epl_el_entry_type   = -1;
static gint ett_epl_sdo_entry_type  = -1;

/* Define the tap for epl */
/*static gint epl_tap = -1;*/

    
    
/* Code to actually dissect the packets */
static gboolean
dissect_epl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 epl_mtyp, epl_src, epl_dest, epl_soa_svid, epl_asnd_svid;
    const  gchar *src_str, *dest_str, *src_str_abbr, *dest_str_abbr;
    gchar  *info_str;
    /* static epl_info_t mi; */
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *epl_tree, *epl_src_item, *epl_dest_item;
    gint offset = 0;

    info_str = ep_alloc(200);
    info_str[0] = 0;

    if (tvb_length_remaining(tvb, offset) < 3)
    {
        /* Not enough data for an EPL header; don't try to interpret it */
        return FALSE;
    }

    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "EPL");
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
    dest_str_abbr = decode_epl_address_abbrev(epl_dest);

    /* Get Source */
    epl_src = tvb_get_guint8(tvb, EPL_SRC_OFFSET);
    src_str = decode_epl_address(epl_src);
    src_str_abbr = decode_epl_address_abbrev(epl_src);

    /* Choose the right string for "Info" column (message type) */
    switch (epl_mtyp)
    {
        case EPL_SOC:
            g_snprintf(info_str, 200, "SoC    dest = %3d%s   src = %3d%s   ", epl_dest, dest_str_abbr, epl_src, src_str_abbr);
            break;

        case EPL_PREQ:
            g_snprintf(info_str, 200, "PReq   dest = %3d%s   src = %3d%s   ", epl_dest, dest_str_abbr, epl_src, src_str_abbr);
            break;

        case EPL_PRES:
            g_snprintf(info_str, 200, "PRes   dest = %3d%s   src = %3d%s   ", epl_dest, dest_str_abbr, epl_src, src_str_abbr);
            break;

        case EPL_SOA:
            epl_soa_svid = tvb_get_guint8(tvb, EPL_SOA_SVID_OFFSET);    /* Get RequestedServiceID */
            g_snprintf(info_str, 200, "SoA    dest = %3d%s   src = %3d%s   %s   ",
                epl_dest, dest_str_abbr, epl_src, src_str_abbr, match_strval(epl_soa_svid, soa_svid_vals));
            break;

        case EPL_ASND:
            epl_asnd_svid = tvb_get_guint8(tvb, EPL_ASND_SVID_OFFSET);  /* Get ServiceID */
            g_snprintf(info_str, 200, "ASnd   dest = %3d%s   src = %3d%s   %s   ",
                epl_dest, dest_str_abbr, epl_src, src_str_abbr, match_strval(epl_asnd_svid, asnd_svid_vals));
            break;

        default:    /* no valid EPL packet */
            return FALSE;

    }

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_clear(pinfo->cinfo, COL_INFO);
    }

    if (check_col(pinfo->cinfo, COL_INFO))
    {   
        col_add_str(pinfo->cinfo, COL_INFO, info_str);
    }

    if (tree)
    {
        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_epl, tvb, 0, -1, TRUE);
        epl_tree = proto_item_add_subtree(ti, ett_epl);

        proto_tree_add_item(epl_tree,
            hf_epl_mtyp, tvb, offset, 1, TRUE);
        offset += 1;

        epl_dest_item = proto_tree_add_item(epl_tree, hf_epl_dest, tvb, offset, 1, TRUE);
        proto_item_append_text (epl_dest_item, dest_str);
        offset += 1;

        epl_src_item = proto_tree_add_item(epl_tree, hf_epl_src, tvb, offset, 1, TRUE);
        proto_item_append_text (epl_src_item, src_str);
        offset += 1;

        /* The rest of the epl-dissector depends on the message type  */
        switch (epl_mtyp)
        {
            case EPL_SOC:
                offset = dissect_epl_soc(epl_tree, tvb, offset);
                break;

            case EPL_PREQ:
                offset = dissect_epl_preq(epl_tree, tvb, offset);
                break;

            case EPL_PRES:
                offset = dissect_epl_pres(epl_tree, tvb, epl_src, offset);
                break;

            case EPL_SOA:
                offset = dissect_epl_soa(epl_tree, tvb, epl_src, offset);
                break;

            case EPL_ASND:
                offset = dissect_epl_asnd(tree, epl_tree, tvb, epl_src, offset);
                break;   

            default:    /* no valid EPL packet */
                return FALSE;
        }
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
const gchar*
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



gint
dissect_epl_soc(proto_tree *epl_tree, tvbuff_t *tvb, gint offset)
{
    nstime_t nettime;

    offset += 1;

    proto_tree_add_item(epl_tree, hf_epl_soc_mc, tvb, offset, 1, TRUE);
    proto_tree_add_item(epl_tree, hf_epl_soc_ps, tvb, offset, 1, TRUE);
    offset += 2;

    nettime.secs  = tvb_get_letohl(tvb, offset);
    nettime.nsecs = tvb_get_letohl(tvb, offset+4);
    proto_tree_add_time_format_value(epl_tree, hf_epl_soc_nettime, 
        tvb, offset, 8, &nettime, "%s", abs_time_to_str(&nettime));
    offset += 8;

    proto_tree_add_item(epl_tree, hf_epl_soc_relativetime, tvb, offset, 8, TRUE);
    offset += 8;

    return offset;
}



gint
dissect_epl_preq(proto_tree *epl_tree, tvbuff_t *tvb, gint offset)
{
    guint16 len;
    guint8  pdoversion;

    offset += 1;

    proto_tree_add_item(epl_tree, hf_epl_preq_ms, tvb, offset, 1, TRUE);
    proto_tree_add_item(epl_tree, hf_epl_preq_ea, tvb, offset, 1, TRUE);
    proto_tree_add_item(epl_tree, hf_epl_preq_rd, tvb, offset, 1, TRUE);
    offset += 2;
    
    pdoversion = tvb_get_guint8(tvb, offset);
    proto_tree_add_string_format(epl_tree, hf_epl_preq_pdov, tvb, offset,
        1, "", "PDOVersion %d.%d",  hi_nibble(pdoversion), lo_nibble(pdoversion));
    offset += 2;

    proto_tree_add_item(epl_tree, hf_epl_preq_size, tvb, offset, 2, TRUE);

    /* get size of payload */
    len = tvb_get_letohs(tvb, offset);
    offset += 2;

    if (len > 0)
    {
        proto_tree_add_item(epl_tree, hf_epl_preq_pl, tvb, offset, len, TRUE);
    }
    offset += len;

    return offset;
}



gint
dissect_epl_pres(proto_tree *epl_tree, tvbuff_t *tvb, guint8 epl_src, gint offset)
{
    guint16  len;
    guint8  pdoversion;

    if (epl_src != EPL_MN_NODEID)   /* check if the sender is CN or MN */
    {
        proto_tree_add_item(epl_tree, hf_epl_pres_stat_cs, tvb, offset, 1, TRUE);
    }
    else /* MN */
    {
        proto_tree_add_item(epl_tree, hf_epl_pres_stat_ms, tvb, offset, 1, TRUE);
    }
    offset += 1;

    proto_tree_add_item(epl_tree, hf_epl_pres_ms, tvb, offset, 1, TRUE);
    proto_tree_add_item(epl_tree, hf_epl_pres_en, tvb, offset, 1, TRUE);
    proto_tree_add_item(epl_tree, hf_epl_pres_rd, tvb, offset, 1, TRUE);
    offset += 1;

    proto_tree_add_item(epl_tree, hf_epl_pres_pr, tvb, offset, 1, TRUE);
    proto_tree_add_item(epl_tree, hf_epl_pres_rs, tvb, offset, 1, TRUE);
    offset += 1;

    pdoversion = tvb_get_guint8(tvb, offset);
    proto_tree_add_string_format(epl_tree, hf_epl_pres_pdov, tvb, offset,
        1, "", "PDOVersion %d.%d",  hi_nibble(pdoversion), lo_nibble(pdoversion));
    offset += 2;

    proto_tree_add_item(epl_tree, hf_epl_pres_size, tvb, offset, 2, TRUE);

    /* get size of payload */
    len = tvb_get_letohs(tvb, offset);
    offset += 2;
    if (len > 0)
    {
        proto_tree_add_item(epl_tree, hf_epl_pres_pl, tvb, offset, len, TRUE);
    }
    offset += len;

    return offset;
}



gint
dissect_epl_soa(proto_tree *epl_tree, tvbuff_t *tvb, guint8 epl_src, gint offset)
{
    guint8 eplversion;

    if (epl_src != EPL_MN_NODEID)   /* check if CN or MN */
    {
        proto_tree_add_item(epl_tree, hf_epl_soa_stat_cs, tvb, offset, 1, TRUE);
    }
    else /* MN */
    {
        proto_tree_add_item(epl_tree, hf_epl_soa_stat_ms, tvb, offset, 1, TRUE);
    }
    offset += 1;

    proto_tree_add_item(epl_tree, hf_epl_soa_ea, tvb, offset, 1, TRUE);
    proto_tree_add_item(epl_tree, hf_epl_soa_er, tvb, offset, 1, TRUE);
    offset += 2;

    proto_tree_add_item(epl_tree, hf_epl_soa_svid, tvb, offset, 1, TRUE);
    offset += 1;

    proto_tree_add_item(epl_tree, hf_epl_soa_svtg, tvb, offset, 1, TRUE);
    offset += 1;

    eplversion = tvb_get_guint8(tvb, offset);
    proto_tree_add_string_format(epl_tree, hf_epl_soa_eplv, tvb, offset,
        1, "", "EPLVersion %d.%d",  hi_nibble(eplversion), lo_nibble(eplversion));
    offset += 1;

    return offset;
}



gint
dissect_epl_asnd(proto_tree *tree, proto_tree *epl_tree, tvbuff_t *tvb, guint8 epl_src, gint offset)
{
    guint16  svid;

    proto_tree_add_item(epl_tree, hf_epl_asnd_svid, tvb, offset, 1, TRUE);

    /* get ServiceID of payload */
    svid = tvb_get_guint8(tvb, offset);
    offset += 1;

    switch (svid)
    {
        case EPL_ASND_IDENTRESPONSE: 
            offset = dissect_epl_asnd_ires(epl_tree, tvb, epl_src, offset);
            break;

        case EPL_ASND_STATUSRESPONSE:
            offset = dissect_epl_asnd_sres(tree, epl_tree, tvb, epl_src, offset);
            break;

        case EPL_ASND_NMTREQUEST:
            offset = dissect_epl_asnd_nmtreq(epl_tree, tvb, offset);
            break;

        case EPL_ASND_NMTCOMMAND:
            offset = dissect_epl_asnd_nmtcmd(epl_tree, tvb, offset);
            break;

        case EPL_ASND_SDO: 
            offset = dissect_epl_asnd_sdo(epl_tree, tvb, offset);
            break;
    }

    return offset;
}



gint
dissect_epl_asnd_nmtreq(proto_tree *epl_tree, tvbuff_t *tvb, gint offset)
{
    proto_tree_add_item(epl_tree, hf_epl_asnd_nmtrequest_rcid, tvb, offset, 1, TRUE);
    offset += 1;

    proto_tree_add_item(epl_tree, hf_epl_asnd_nmtrequest_rct, tvb, offset, 1, TRUE);
    offset += 1;

    proto_tree_add_item(epl_tree, hf_epl_asnd_nmtrequest_rcd, tvb, offset, -1, TRUE);

    return offset;
}



gint
dissect_epl_asnd_nmtcmd(proto_tree *epl_tree, tvbuff_t *tvb, gint offset)
{
    guint8 epl_asnd_nmtcommand_cid;

    proto_tree_add_item(epl_tree, hf_epl_asnd_nmtcommand_cid, tvb, offset, 1, TRUE);
    epl_asnd_nmtcommand_cid = tvb_get_guint8(tvb, offset);
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
    return offset;
}



gint
dissect_epl_asnd_ires(proto_tree *epl_tree, tvbuff_t *tvb, guint8 epl_src, gint offset)
{
    guint8  eplversion;
    guint32 epl_asnd_identresponse_ipa, epl_asnd_identresponse_snm, epl_asnd_identresponse_gtw;

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

    proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_feat, tvb, offset, 4, TRUE);
    offset += 4;

    proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_mtu, tvb, offset, 2, TRUE);
    offset += 2;

    proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_pis, tvb, offset, 2, TRUE);
    offset += 2;

    proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_pos, tvb, offset, 2, TRUE);
    offset += 2;

    proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_rst, tvb, offset, 4, TRUE);
    offset += 6;

    proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_dt, tvb, offset, 4, TRUE);
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

    return offset;
}



gint
dissect_epl_asnd_sres(proto_tree *tree, proto_tree *epl_tree, tvbuff_t *tvb, guint8 epl_src, gint offset)
{
    proto_item  *ti_seb, *ti_el, *ti_el_entry, *ti_el_entry_type;
    proto_tree  *epl_seb_tree, *epl_el_tree, *epl_el_entry_tree, *epl_el_entry_type_tree;
    guint       number_of_entries, cnt;    /* used for dissection of ErrorCodeList */

    proto_tree_add_item(epl_tree, hf_epl_asnd_statusresponse_en, tvb, offset, 1, TRUE);
    proto_tree_add_item(epl_tree, hf_epl_asnd_statusresponse_ec, tvb, offset, 1, TRUE);
    offset += 1;

    proto_tree_add_item(epl_tree, hf_epl_asnd_statusresponse_pr, tvb, offset, 1, TRUE);
    proto_tree_add_item(epl_tree, hf_epl_asnd_statusresponse_rs, tvb, offset, 1, TRUE);
    offset += 1;

    if (epl_src != EPL_MN_NODEID)   /* check if CN or MN */
    {
        proto_tree_add_item(epl_tree, hf_epl_asnd_statusresponse_stat_cs, tvb, offset, 1, TRUE);
    }
    else /* MN */
    { 
        proto_tree_add_item(epl_tree, hf_epl_asnd_statusresponse_stat_ms, tvb, offset, 1, TRUE);
    }
    offset += 4;

    /* Subtree for the static errorr bitfield */
    if (tree)
    {
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

        proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_devicespecific_err, tvb,offset, 8, TRUE);
        offset += 8;
    }

    /* List of errors / events */
    if (tree)
    {
        /* get the number of entries in the error code list*/
        number_of_entries = (tvb_length(tvb)-offset)/20;

        ti_el = proto_tree_add_text(epl_tree, tvb, offset, -1, "ErrorCodeList: %d entries", number_of_entries);

        epl_el_tree = proto_item_add_subtree(ti_el, ett_epl_el);

        /*Dissect the whole Error List (display each entry)*/
        for (cnt = 0; cnt<number_of_entries; cnt++)
        {
            if (tree)
            {
                ti_el_entry = proto_tree_add_text(ti_el, tvb, offset, 20, "Entry %d", cnt+1);

                epl_el_entry_tree = proto_item_add_subtree(ti_el_entry, ett_epl_el_entry);

                /*Entry Type*/
                if (tree)
                {
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
                }
                offset += 2;

                proto_tree_add_item(epl_el_entry_tree, hf_epl_asnd_statusresponse_el_entry_code, tvb, offset, 2, TRUE);
                offset += 2;

                proto_tree_add_item(epl_el_entry_tree, hf_epl_asnd_statusresponse_el_entry_time, tvb, offset, 8, TRUE);
                offset += 8;

                proto_tree_add_item(epl_el_entry_tree, hf_epl_asnd_statusresponse_el_entry_add, tvb, offset, 8, TRUE);
                offset += 8;
            }
        }
    }
    return offset;
}



gint
dissect_epl_asnd_sdo(proto_tree *epl_tree, tvbuff_t *tvb, gint offset)
{
    offset = dissect_epl_sdo_sequence(epl_tree, tvb, offset);

    offset = dissect_epl_sdo_command(epl_tree, tvb, offset);

    return offset;
}


gint
dissect_epl_sdo_sequence(proto_tree *epl_tree, tvbuff_t *tvb, gint offset)
{

    /* Asynchronuous SDO Sequence Layer */
    proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_seq_receive_sequence_number, tvb, offset, 1, TRUE);
    proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_seq_receive_con,             tvb, offset, 1, TRUE); 
    offset += 1;

    proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_seq_send_sequence_number, tvb, offset, 1, TRUE);
    proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_seq_send_con, tvb, offset, 1, TRUE);
    offset += 3;

    return offset;
}



gint
dissect_epl_sdo_command(proto_tree *epl_tree, tvbuff_t *tvb, gint offset)
{
    guint8  command_id;
    gboolean segmented, response, abort;

    offset += 1;
    segmented = FALSE;

    segmented  = tvb_get_guint8(tvb, offset + 1) & EPL_ASND_SDO_CMD_SEGMENTATION_FILTER;
    response   = tvb_get_guint8(tvb, offset + 1) & EPL_ASND_SDO_CMD_RESPONSE_FILTER;
    abort      = tvb_get_guint8(tvb, offset + 1) & EPL_ASND_SDO_CMD_ABORT_FILTER;
    command_id = tvb_get_guint8(tvb, offset + 2);

    /* test if CommandField == empty */
    if (command_id != 0)
    {
        proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_transaction_id, tvb, offset, 1, TRUE);
        offset += 1;

        proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_response, tvb, offset, 1, TRUE);
        proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_abort,    tvb, offset, 1, TRUE);

        if (abort)
        {
            /* if AbortBit is set then print AbortMessage */
            proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_abort_code, tvb, offset, 4, TRUE);
        }

        proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_segmentation, tvb, offset, 1, TRUE);
        offset += 1;

        proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_command_id, tvb, offset, 1, TRUE);
        offset += 1;

        proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_segment_size, tvb, offset, 2, TRUE);
        offset += 4;

        if (segmented)
        {  
            /* if SegemenationBit is set then print DataSize */
            proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_data_size, tvb, offset, 4, TRUE); 
            segmented = TRUE;
            offset += 4;
        }

        switch (command_id)
        {
            case EPL_ASND_SDO_COMMAND_WRITE_BY_INDEX:
                offset = dissect_epl_sdo_command_write_by_index(epl_tree, tvb, offset, segmented, response);
                break;

            case EPL_ASND_SDO_COMMAND_READ_BY_INDEX:
                offset = dissect_epl_sdo_command_read_by_index(epl_tree, tvb, offset, response);
                break;

            default:
                return FALSE;
        }
    }
    return offset;
}



gint
dissect_epl_sdo_command_write_by_index(proto_tree *epl_tree, tvbuff_t *tvb, gint offset, gboolean segmented, gboolean response)
{
    gint size;

    if (segmented)
    {
        /* TODO: print payload size... */
        offset += 4;
    }

    if (!response)
    {   /* request */
        proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_write_by_index_index, tvb, offset, 2, TRUE);
        offset += 2;

        proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_write_by_index_subindex, tvb, offset, 1, TRUE);
        offset += 2;

        size = tvb_length_remaining(tvb, offset);
        proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_write_by_index_data, tvb, offset, size, TRUE);

        offset += size;
    }
    else
    {
        /* response, no payload */
    }
    return offset;
}



gint
dissect_epl_sdo_command_read_by_index(proto_tree *epl_tree, tvbuff_t *tvb, gint offset, gboolean response)
{
    gint size;

    if (!response)
    {   /* request */
        proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_read_by_index_index, tvb, offset, 2, TRUE); 
        offset += 2;

        proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_read_by_index_subindex, tvb, offset, 1, TRUE);
        offset += 1;
    }
    else
    {   /* response */
        size = tvb_length_remaining(tvb, offset);
        proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_read_by_index_data, tvb, offset, size, TRUE);
        offset += size;
    }

    return offset;
}



/* Register the protocol with Wireshark */
void
proto_register_epl(void)
{
static hf_register_info hf[] = {

/* Common data fields (same for all message types) */
{ &hf_epl_mtyp,         { "MessageType",                        "epl.mtyp",             FT_UINT8,   BASE_DEC, VALS(mtyp_vals),      0x7F, "", HFILL }},
{ &hf_epl_dest,         { "Destination",                        "epl.dest",             FT_UINT8,   BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_src,          { "Source",                             "epl.src",              FT_UINT8,   BASE_DEC, NULL,                 0x00, "", HFILL }},

/* SoC data fields*/
{ &hf_epl_soc_mc,       { "MC (Multiplexed Cycle Completed)",   "epl.soc.mc",           FT_UINT8,   BASE_DEC, NULL,                 0x80, "", HFILL }},
{ &hf_epl_soc_ps,       { "PS (Prescaled Slot)",                "epl.soc.ps",           FT_UINT8,   BASE_DEC, NULL,                 0x40, "", HFILL }},
{ &hf_epl_soc_nettime,  { "NetTime",                            "epl.soc.nettime",      FT_ABSOLUTE_TIME,   BASE_DEC, NULL,                 0x0,  "", HFILL }},
{ &hf_epl_soc_relativetime,{ "RelativeTime",                    "epl.soc.relativetime", FT_UINT64,  BASE_DEC, NULL,                 0x0,  "", HFILL }},

/* PReq data fields*/
{ &hf_epl_preq_ms,      { "MS (Multiplexed Slot)",              "epl.preq.ms",          FT_UINT8,   BASE_DEC, NULL,                 0x20, "", HFILL }},
{ &hf_epl_preq_ea,      { "EA (Exception Acknowledge)",         "epl.preq.ea",          FT_UINT8,   BASE_DEC, NULL,                 0x04, "", HFILL }},
{ &hf_epl_preq_rd,      { "RD (Ready)",                         "epl.preq.rd",          FT_UINT8,   BASE_DEC, NULL,                 0x01, "", HFILL }},
{ &hf_epl_preq_pdov,    { "PDOVersion",                         "epl.preq.pdov",        FT_STRING,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_preq_size,    { "Size",                               "epl.preq.size",        FT_UINT16,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_preq_pl,      { "Payload",                            "epl.preq.pl",          FT_BYTES,   BASE_HEX, NULL,                 0x00, "", HFILL }},

/* PRes data fields*/
{ &hf_epl_pres_stat_ms, { "NMTStatus",                          "epl.pres.stat",        FT_UINT8,   BASE_DEC, VALS(epl_nmt_cs_vals),0x00, "", HFILL }},
{ &hf_epl_pres_stat_cs, { "NMTStatus",                          "epl.pres.stat",        FT_UINT8,   BASE_DEC, VALS(epl_nmt_ms_vals),0x00, "", HFILL }},
{ &hf_epl_pres_ms,      { "MS (Multiplexed Slot)",              "epl.pres.ms",          FT_UINT8,   BASE_DEC, NULL,                 0x20, "", HFILL }},
{ &hf_epl_pres_en,      { "EN (Exception New)",                 "epl.pres.en",          FT_UINT8,   BASE_DEC, NULL,                 0x10, "", HFILL }},
{ &hf_epl_pres_rd,      { "RD (Ready)",                         "epl.pres.rd",          FT_UINT8,   BASE_DEC, NULL,                 0x01, "", HFILL }},
{ &hf_epl_pres_pr,      { "PR (Priority)",                      "epl.pres.pr",          FT_UINT8,   BASE_DEC, VALS(epl_pr_vals),    0x38, "", HFILL }},
{ &hf_epl_pres_rs,      { "RS (RequestToSend)",                 "epl.pres.rs",          FT_UINT8,   BASE_DEC, NULL,                 0x07, "", HFILL }},
{ &hf_epl_pres_pdov,    { "PDOVersion",                         "epl.pres.pdov",        FT_STRING,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_pres_size,    { "Size",                               "epl.pres.size",        FT_UINT16,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_pres_pl,      { "Payload",                            "epl.pres.pl",          FT_BYTES,   BASE_HEX, NULL,                 0x00, "", HFILL }},

/* SoA data fields*/
{ &hf_epl_soa_stat_ms,  { "NMTStatus",                          "epl.soa.stat",         FT_UINT8,   BASE_DEC, VALS(epl_nmt_ms_vals),0x00, "", HFILL }},
{ &hf_epl_soa_stat_cs,  { "NMTStatus",                          "epl.soa.stat",         FT_UINT8,   BASE_DEC, VALS(epl_nmt_cs_vals),0x00, "", HFILL }},
{ &hf_epl_soa_ea,       { "EA (Exception Acknowledge)",         "epl.soa.ea",           FT_UINT8,   BASE_DEC, NULL,                 0x04, "", HFILL }},
{ &hf_epl_soa_er,       { "ER (Exception Reset)",               "epl.soa.er",           FT_UINT8,   BASE_DEC, NULL,                 0x02, "", HFILL }},
{ &hf_epl_soa_svid,     { "RequestedServiceID",                 "epl.soa.svid",         FT_UINT8,   BASE_DEC, VALS(soa_svid_vals),  0x00, "", HFILL }},
{ &hf_epl_soa_svtg,     { "RequestedServiceTarget",             "epl.soa.svtg",         FT_UINT8,   BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_soa_eplv,     { "EPLVersion",                         "epl.soa.eplv",         FT_STRING,  BASE_DEC, NULL,                 0x00, "", HFILL }},

/* ASnd header */
{ &hf_epl_asnd_svid,    { "ServiceID",                          "epl.asnd.svid",    FT_UINT8, BASE_DEC, VALS(asnd_svid_vals),   0x00,"", HFILL }},
{ &hf_epl_asnd_data,    { "Data",                               "epl.asnd.data",    FT_BYTES, BASE_HEX, NULL,                   0x00,"", HFILL }},

/* ASnd-->IdentResponse */
{ &hf_epl_asnd_identresponse_en,      { "EN (Exception New)",       "epl.asnd.ires.en",             FT_UINT8,   BASE_DEC, NULL,                 0x10, "", HFILL }},
{ &hf_epl_asnd_identresponse_ec,      { "EC (Exception Clear)",     "epl.asnd.ires.ec",             FT_UINT8,   BASE_DEC, NULL,                 0x08, "", HFILL }},
{ &hf_epl_asnd_identresponse_pr,      { "PR (Priority)",            "epl.asnd.ires.pr",             FT_UINT8,   BASE_DEC, VALS(epl_pr_vals),    0x38, "", HFILL }},
{ &hf_epl_asnd_identresponse_rs,      { "RS (RequestToSend)",       "epl.asnd.ires.rs",             FT_UINT8,   BASE_DEC, NULL,                 0x07, "", HFILL }},
{ &hf_epl_asnd_identresponse_stat_ms, { "NMTStatus",                "epl.asnd.ires.state",          FT_UINT8,   BASE_DEC, VALS(epl_nmt_ms_vals),0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_stat_cs, { "NMTStatus",                "epl.asnd.ires.state",          FT_UINT8,   BASE_DEC, VALS(epl_nmt_cs_vals),0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_ever,    { "EPLVersion",               "epl.asnd.ires.eplver",         FT_STRING,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_feat,    { "FeatureFlags",             "epl.asnd.ires.features",       FT_UINT32,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_mtu,     { "MTU",                      "epl.asnd.ires.mtu",            FT_UINT16,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_pis,     { "PollInSize",               "epl.asnd.ires.pollinsize",     FT_UINT16,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_pos,     { "PollOutSize",              "epl.asnd.ires.polloutsizes",   FT_UINT16,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_rst,     { "ResponseTime",             "epl.asnd.ires.resptime",       FT_UINT32,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_dt,      { "DeviceType",               "epl.asnd.ires.devicetype",     FT_UINT32,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_vid,     { "VendorId",                 "epl.asnd.ires.vendorid",       FT_UINT32,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_productcode,{ "ProductCode",           "epl.asnd.ires.productcode",    FT_UINT32,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_rno,     { "RevisionNumber",           "epl.asnd.ires.revisionno",     FT_UINT32,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_sno,     { "SerialNumber",             "epl.asnd.ires.serialno",       FT_UINT32,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_vex1,    { "VendorSpecificExtension1", "epl.asnd.ires.vendorext1",     FT_UINT64,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_vcd,     { "VerifyConfigurationDate",  "epl.asnd.ires.confdate",       FT_UINT32,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_vct,     { "VerifyConfigurationTime",  "epl.asnd.ires.conftime",       FT_UINT32,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_ad,      { "applicationSwDate",        "epl.asnd.ires.appswdate",      FT_UINT32,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_at,      { "applicationSwTime",        "epl.asnd.ires.appswtime",      FT_UINT32,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_ipa,     { "IPAddress",                "epl.asnd.ires.ip",             FT_IPv4,    BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_snm,     { "SubnetMask",               "epl.asnd.ires.subnet",         FT_IPv4,    BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_gtw,     { "DefaultGateway",           "epl.asnd.ires.gateway",        FT_IPv4,    BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_hn,      { "HostName",                 "epl.asnd.ires.hostname",       FT_STRING,  BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_identresponse_vex2,    { "VendorSpecificExtension2", "epl.asnd.ires.vendorext2",     FT_BYTES,   BASE_DEC, NULL,                 0x00, "", HFILL }},


/* ASnd-->StatusResponse */
{ &hf_epl_asnd_statusresponse_en,                               { "EN (Exception New)",         "epl.asnd.sres.en",                     FT_UINT8, BASE_DEC, NULL,                   0x10, "", HFILL }},
{ &hf_epl_asnd_statusresponse_ec,                               { "EC (Exception Clear)",       "epl.asnd.sres.ec",                     FT_UINT8, BASE_DEC, NULL,                   0x08, "", HFILL }},
{ &hf_epl_asnd_statusresponse_pr,                               { "PR (Priority)",              "epl.asnd.sres.pr",                     FT_UINT8, BASE_DEC, VALS(epl_pr_vals),      0x38, "", HFILL }},
{ &hf_epl_asnd_statusresponse_rs,                               { "RS (RequestToSend)",         "epl.asnd.sres.rs",                     FT_UINT8, BASE_DEC, NULL,                   0x07, "", HFILL }},
{ &hf_epl_asnd_statusresponse_stat_ms,                          { "NMTStatus",                  "epl.asnd.sres.stat",                   FT_UINT8, BASE_DEC, VALS(epl_nmt_ms_vals),  0x00, "", HFILL }},
{ &hf_epl_asnd_statusresponse_stat_cs,                          { "NMTStatus",                  "epl.asnd.sres.stat",                   FT_UINT8, BASE_DEC, VALS(epl_nmt_cs_vals),  0x00, "", HFILL }},
{ &hf_epl_asnd_statusresponse_seb,                              { "StaticErrorBitField",        "epl.asnd.sres.seb",                    FT_BYTES, BASE_HEX, NULL,                   0x00, "", HFILL }},

/*StaticErrorBitField */
{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit0,    { "Generic error",              "epl.asnd.res.seb.bit0",                FT_UINT8, BASE_DEC, NULL, 0x01, "", HFILL }},
{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit1,    { "Current",                    "epl.asnd.res.seb.bit1",                FT_UINT8, BASE_DEC, NULL, 0x02, "", HFILL }},
{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit2,    { "Voltage",                    "epl.asnd.res.seb.bit2",                FT_UINT8, BASE_DEC, NULL, 0x04, "", HFILL }},
{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit3,    { "Temperature",                "epl.asnd.res.seb.bit3",                FT_UINT8, BASE_DEC, NULL, 0x08, "", HFILL }},
{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit4,    { "Communication error",        "epl.asnd.res.seb.bit4",                FT_UINT8, BASE_DEC, NULL, 0x10, "", HFILL }},
{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit5,    { "Device profile specific",    "epl.asnd.res.seb.bit5",                FT_UINT8, BASE_DEC, NULL, 0x20, "", HFILL }},
{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit7,    { "Manufacturer specific",      "epl.asnd.res.seb.bit7",                FT_UINT8, BASE_DEC, NULL, 0x80, "", HFILL }},
{ &hf_epl_asnd_statusresponse_seb_devicespecific_err,           { "Device profile specific",    "epl.asnd.res.seb.devicespecific_err",FT_BYTES, BASE_DEC,NULL, 0x00, "", HFILL }},

{ &hf_epl_asnd_statusresponse_el,                               { "ErrorsCodeList",             "epl.asnd.sres.el",                     FT_BYTES, BASE_DEC, NULL, 0x00, "", HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry,                         { "Entry",                      "epl.asnd.sres.el.entry",               FT_BYTES, BASE_DEC, NULL, 0x00, "", HFILL }},

/*List of Errors/Events*/
{ &hf_epl_asnd_statusresponse_el_entry_type,                    { "Entry Type",                 "epl.asnd.sres.el.entry.type",          FT_UINT16, BASE_HEX, NULL, 0x00,    "", HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry_type_profile,            { "Profile",                    "epl.asnd.sres.el.entry.type.profile",  FT_UINT16, BASE_DEC, NULL, 0x0FFF,  "", HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry_type_mode,               { "Mode",                       "epl.asnd.sres.el.entry.type.mode",     FT_UINT16, BASE_DEC, NULL, 0x3000,  "", HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry_type_bit14,              { "Bit14",                      "epl.asnd.sres.el.entry.type.bit14",    FT_UINT16, BASE_DEC, NULL, 0x4000,  "", HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry_type_bit15,              { "Bit15",                      "epl.asnd.sres.el.entry.type.bit15",    FT_UINT16, BASE_DEC, NULL, 0x8000,  "", HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry_code,                    { "Error Code",                 "epl.asnd.sres.el.entry.code",          FT_UINT16, BASE_DEC, NULL, 0x00,    "", HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry_time,                    { "Time Stamp",                 "epl.asnd.sres.el.entry.time",          FT_UINT64, BASE_DEC, NULL, 0x00,    "", HFILL }},
{ &hf_epl_asnd_statusresponse_el_entry_add,                     { "Additional Information",     "epl.asnd.sres.el.entry.add",           FT_UINT64, BASE_DEC, NULL, 0x00,    "", HFILL }},


/* ASnd-->NMTRequest */
{ &hf_epl_asnd_nmtrequest_rcid,                     { "NMTRequestedCommandID",      "epl.asnd.nmtrequest.rcid",                     FT_UINT8,   BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_nmtrequest_rct,                      { "NMTRequestedCommandTarget",  "epl.asnd.nmtrequest.rct",                      FT_UINT8,   BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_nmtrequest_rcd,                      { "NMTRequestedCommandData",    "epl.asnd.nmtrequest.rcd",                      FT_BYTES,   BASE_DEC, NULL,                 0x00, "", HFILL }},

/* ASnd-->NMTCommand */                             
{ &hf_epl_asnd_nmtcommand_cid,                      { "NMTCommandId",               "epl.asnd.nmtcommand.cid",                      FT_UINT8,   BASE_DEC, VALS(asnd_cid_vals),  0x00, "", HFILL }},
{ &hf_epl_asnd_nmtcommand_cdat,                     { "NMTCommandData",             "epl.asnd.nmtcommand.cdat",                     FT_BYTES,   BASE_DEC, NULL,                 0x00, "", HFILL }},

{ &hf_epl_asnd_nmtcommand_nmtnethostnameset_hn,     { "HostName",                   "epl.asnd.nmtcommand.nmtnethostnameset.hn",     FT_BYTES,   BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_nmtcommand_nmtflusharpentry_nid,     { "NodeID",                     "epl.asnd.nmtcommand.nmtflusharpentry.nid",     FT_UINT8,   BASE_DEC, NULL,                 0x00, "", HFILL }},
{ &hf_epl_asnd_nmtcommand_nmtpublishtime_dt,        { "DateTime",                   "epl.asnd.nmtcommand.nmtpublishtime.dt",        FT_BYTES,   BASE_DEC, NULL,                 0x00, "", HFILL }},

/* ASnd-->SDO */ 
{ &hf_epl_asnd_sdo_seq_receive_sequence_number, { "ReceiveSequenceNumber",          "epl.asnd.sdo.seq.receive.sequence.number", FT_UINT8,   BASE_DEC, NULL,                             0xfc, "", HFILL }},     
{ &hf_epl_asnd_sdo_seq_receive_con,             { "ReceiveCon",                     "epl.asnd.sdo.seq.receive.con",             FT_UINT8,   BASE_DEC, VALS(epl_sdo_receive_con_vals),   0x03, "", HFILL }},         
{ &hf_epl_asnd_sdo_seq_send_sequence_number,    { "SendSequenceNumber",             "epl.asnd.sdo.seq.send.sequence.number",    FT_UINT8,   BASE_DEC, NULL,                             0xfc, "", HFILL }},  
{ &hf_epl_asnd_sdo_seq_send_con,                { "SendCon",                        "epl.asnd.sdo.seq.send.con",                FT_UINT8,   BASE_DEC, VALS(epl_sdo_send_con_vals),      0x03, "", HFILL }},

{ &hf_epl_asnd_sdo_cmd_transaction_id,          { "SDO Transaction ID",             "epl.asnd.sdo.cmd.transaction.id",          FT_UINT8,   BASE_DEC, NULL,                             0x00, "", HFILL }},      
{ &hf_epl_asnd_sdo_cmd_response,                { "SDO Response",                   "epl.asnd.sdo.cmd.response",                FT_UINT8,   BASE_DEC, VALS(epl_sdo_asnd_cmd_response),  0x80, "", HFILL }},       
{ &hf_epl_asnd_sdo_cmd_abort,                   { "SDO Abort",                      "epl.asnd.sdo.cmd.abort",                   FT_UINT8,   BASE_DEC, VALS(epl_sdo_asnd_cmd_abort),     0x40, "", HFILL }},    
{ &hf_epl_asnd_sdo_cmd_segmentation,            { "SDO Segmentation",               "epl.asnd.sdo.cmd.segmentation",            FT_UINT8,   BASE_DEC, VALS(epl_sdo_asnd_cmd_segmentation), 0x30, "", HFILL }},   
{ &hf_epl_asnd_sdo_cmd_command_id,              { "SDO Command ID",                 "epl.asnd.sdo.cmd.command.id",              FT_UINT8,   BASE_DEC, VALS(epl_sdo_asnd_commands),      0x00, "", HFILL }}, 
{ &hf_epl_asnd_sdo_cmd_segment_size,            { "SDO Segment size",               "epl.asnd.sdo.cmd.segment.size",            FT_UINT8,   BASE_DEC, NULL,                             0x00, "", HFILL }}, 
{ &hf_epl_asnd_sdo_cmd_data_size,               { "SDO Data size",                  "epl.asnd.sdo.cmd.data.size",               FT_UINT8,   BASE_DEC, NULL,                             0x00, "", HFILL } }, 
{ &hf_epl_asnd_sdo_cmd_abort_code,              { "SDO Transfer Abort",             "epl.asnd.sdo.cmd.abort.code",              FT_UINT8,   BASE_HEX, VALS(sdo_cmd_abort_code),         0x00, "", HFILL }},
{ &hf_epl_asnd_sdo_cmd_write_by_index_index,    { "SDO Write by Index, Index",      "epl.asnd.sdo.cmd.write.by.index.index",    FT_UINT16,  BASE_HEX, NULL,                             0x00, "", HFILL }},      
{ &hf_epl_asnd_sdo_cmd_write_by_index_subindex, { "SDO Write by Index, SubIndex",   "epl.asnd.sdo.cmd.write.by.index.subindex", FT_UINT8,   BASE_HEX, NULL,                             0x00, "", HFILL }},      
{ &hf_epl_asnd_sdo_cmd_read_by_index_index,     { "SDO Read by Index, Index",       "epl.asnd.sdo.cmd.read.by.index.index",     FT_UINT16,  BASE_HEX, NULL,                             0x00, "", HFILL }},      
{ &hf_epl_asnd_sdo_cmd_read_by_index_subindex,  { "SDO Read by Index, SubIndex",    "epl.asnd.sdo.cmd.read.by.index.subindex",  FT_UINT8,   BASE_HEX, NULL,                             0x00, "", HFILL }},               
{ &hf_epl_asnd_sdo_cmd_write_by_index_data,     { "Payload",                        "epl.asnd.sdo.cmd.write.by.index.data",     FT_BYTES,   BASE_HEX, NULL,                             0x00, "", HFILL }},
{ &hf_epl_asnd_sdo_cmd_read_by_index_data,      { "Payload",                        "epl.asnd.sdo.cmd.read.by.index.data",      FT_BYTES,   BASE_HEX, NULL,                             0x00, "", HFILL }},
};


    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_epl,
        &ett_epl_seb,
        &ett_epl_el,
        &ett_epl_el_entry,
        &ett_epl_el_entry_type,
        &ett_epl_sdo_entry_type,
    };
        
    /* Register the protocol name and description */
    proto_epl = proto_register_protocol("ETHERNET Powerlink v2", "EPL", "epl");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_epl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    
    /* tap-registration */
    /*  epl_tap = register_tap("epl");*/
}



void
proto_reg_handoff_epl(void)
{
    dissector_handle_t epl_handle;
    
    epl_handle = create_dissector_handle(dissect_epl, proto_epl);
    dissector_add("ethertype", ETHERTYPE_EPL_V2, epl_handle);
}
