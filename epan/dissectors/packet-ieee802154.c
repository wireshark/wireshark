/* packet-ieee802154.c
 *
 * $Id$
 *
 * IEEE 802.15.4 Dissectors for Wireshark
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2007 Exegin Technologies Limited
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *------------------------------------------------------------
 *
 *  In IEEE 802.15.4 packets, all fields are little endian. And
 *  Each byte is transmitted least significan bit first (reflected
 *  bit ordering).
 *------------------------------------------------------------
 *
 *  IEEE 802.15.4 Packets have the following format:
 *  |  FCF  |Seq No|  Addressing |         Data          |  FCS  |
 *  |2 bytes|1 byte|0 to 20 bytes|Length-(Overhead) bytes|2 Bytes|
 *------------------------------------------------------------
 *
 *  CRC16 is calculated using the x^16 + x^12 + x^5 + 1 polynomial
 *  as specified by ITU-T, and is calculated over the IEEE 802.15.4
 *  packet (excluding the FCS) as transmitted over the air. Note,
 *  that because the least significan bits are transmitted first, this
 *  will require reversing the bit-order in each byte. Also, unlike
 *  most CRC algorithms, IEEE 802.15.4 uses an initial and final value
 *  of 0x0000, instead of 0xffff (which is used by the CCITT).
 *------------------------------------------------------------
 *
 *  This dissector supports both link-layer IEEE 802.15.4 captures
 *  and IEEE 802.15.4 packets encapsulated within other layers.
 *  Additionally, support has been provided for various formats
 *  of the frame check sequence:
 *      - IEEE 802.15.4 compliant FCS.
 *      - ChipCon/Texas Instruments CC24xx style FCS.
 *      - No FCS at all.
 *------------------------------------------------------------
 *
 *  No support has been provided for decryption. Maybe a TODO
 *  item, but this is unlikely as the decryption process requires
 *  the extended source address (to build the nonce/initial value)
 *  which will be absent most of the time.
 *------------------------------------------------------------
 */

/*  Include files */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVEHCONFIG_H */

#include <string.h>
#include <stdlib.h>
#include <gmodule.h>
#include <glib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/crc16.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>

#include "packet-ieee802154.h"
#include "packet-frame.h"   /* For Exception Handling */

/* Dissection Options for dissect_ieee802154_common */
#define DISSECT_IEEE802154_OPTION_CC24xx    0x00000001  /* FCS field contains a TI CC24xx style FCS. */
#define DISSECT_IEEE802154_OPTION_LINUX     0x00000002  /* Addressing fields are padded DLT_IEEE802_15_4_LINUX, not implemented. */

/*  Function declarations */
/* Register Functions. Loads the dissector into Wireshark. */
void proto_reg_handoff_ieee802154   (void);
void proto_register_ieee802154      (void);

/* Dissection Routines. */
static void dissect_ieee802154              (tvbuff_t *, packet_info *, proto_tree *);
static void dissect_ieee802154_nofcs        (tvbuff_t *, packet_info *, proto_tree *);
static void dissect_ieee802154_cc24xx       (tvbuff_t *, packet_info *, proto_tree *);
/*static void dissect_ieee802154_linux        (tvbuff_t *, packet_info *, proto_tree *);  TODO: Implement Me. */
static void dissect_ieee802154_common       (tvbuff_t *, packet_info *, proto_tree *, guint);
static void dissect_ieee802154_beacon       (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *);
static void dissect_ieee802154_cmd          (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *);
/* Sub-dissector helpers. */
static void dissect_ieee802154_fcf          (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *, guint *);
static void dissect_ieee802154_cmd_asreq    (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *, guint *);
static void dissect_ieee802154_cmd_asrsp    (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *, guint *);
static void dissect_ieee802154_cmd_disas    (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *, guint *);
static void dissect_ieee802154_cmd_realign  (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *, guint *);
static void dissect_ieee802154_cmd_gtsrq    (tvbuff_t *, packet_info *, proto_tree *, ieee802154_packet *, guint *);

/*  Initialize Protocol and Registered fields */
static int proto_ieee802154 = -1;
static int hf_ieee802154_frame_type = -1;
static int hf_ieee802154_security = -1;
static int hf_ieee802154_pending = -1;
static int hf_ieee802154_ack_request = -1;
static int hf_ieee802154_intra_pan = -1;
static int hf_ieee802154_seqno = -1;
static int hf_ieee802154_src_addr_mode = -1;
static int hf_ieee802154_dst_addr_mode = -1;
static int hf_ieee802154_version = -1;
static int hf_ieee802154_dst_pan = -1;
static int hf_ieee802154_dst_addr16 = -1;
static int hf_ieee802154_dst_addr64 = -1;
static int hf_ieee802154_src_panID = -1;
static int hf_ieee802154_src_addr16 = -1;
static int hf_ieee802154_src_addr64 = -1;
static int hf_ieee802154_fcs = -1;
static int hf_ieee802154_rssi = -1;
static int hf_ieee802154_fcs_ok = -1;
static int hf_ieee802154_correlation;

/*  Registered fields for Command Packets */
static int hf_ieee802154_cmd_id = -1;
static int hf_ieee802154_cmd_cinfo_alt_coord = -1;
static int hf_ieee802154_cmd_cinfo_device_type = -1;
static int hf_ieee802154_cmd_cinfo_power_src = -1;
static int hf_ieee802154_cmd_cinfo_idle_rx = -1;
static int hf_ieee802154_cmd_cinfo_sec_capable = -1;
static int hf_ieee802154_cmd_cinfo_alloc_addr = -1;
static int hf_ieee802154_cmd_asrsp_addr = -1;
static int hf_ieee802154_cmd_asrsp_status = -1;
static int hf_ieee802154_cmd_disas_reason = -1;
static int hf_ieee802154_cmd_coord_pan = -1;
static int hf_ieee802154_cmd_coord_caddr = -1;
static int hf_ieee802154_cmd_coord_channel = -1;
static int hf_ieee802154_cmd_coord_addr = -1;
static int hf_ieee802154_cmd_coord_channel_page = -1;
static int hf_ieee802154_cmd_gts_req_len = -1;
static int hf_ieee802154_cmd_gts_req_dir = -1;
static int hf_ieee802154_cmd_gts_req_type = -1;

/*  Registered fields for Beacon Packets */
static int hf_ieee802154_bcn_beacon_order = -1;
static int hf_ieee802154_bcn_superframe_order = -1;
static int hf_ieee802154_bcn_cap = -1;
static int hf_ieee802154_bcn_battery_ext = -1;
static int hf_ieee802154_bcn_coord = -1;
static int hf_ieee802154_bcn_assoc_permit = -1;
static int hf_ieee802154_bcn_gts_count = -1;
static int hf_ieee802154_bcn_gts_permit = -1;
static int hf_ieee802154_bcn_gts_direction = -1;
static int hf_ieee802154_bcn_pending16 = -1;
static int hf_ieee802154_bcn_pending64 = -1;

/*  Initialize Subtree Pointers */
static gint ett_ieee802154 = -1;
static gint ett_ieee802154_fcf = -1;
static gint ett_ieee802154_fcs = -1;
static gint ett_ieee802154_cmd = -1;
static gint ett_ieee802154_cmd_cinfo = -1;
static gint ett_ieee802154_bcn = -1;
static gint ett_ieee802154_bcn_superframe_spec = -1;
static gint ett_ieee802154_bcn_gts_spec = -1;
static gint ett_ieee802154_bcn_gts_direction = -1;
static gint ett_ieee802154_bcn_gts_descriptors = -1;
static gint ett_ieee802154_bcn_pending = -1;

/*  Dissector handles */
static dissector_handle_t       data_handle;
static heur_dissector_list_t    ieee802154_heur_subdissector_list;

/* Name Strings */
static const value_string ieee802154_frame_types[] = {
    { IEEE802154_FCF_BEACON,    "Beacon" },
    { IEEE802154_FCF_DATA,      "Data" },
    { IEEE802154_FCF_ACK,       "Ack" },
    { IEEE802154_FCF_CMD,       "Command" },
    { 0, NULL }
};

static const value_string ieee802154_addr_modes[] = {
    { IEEE802154_FCF_ADDR_NONE,     "None" },
    { IEEE802154_FCF_ADDR_SHORT,    "Short/16-bit" },
    { IEEE802154_FCF_ADDR_EXT,      "Long/64-bit" },
    { 0, NULL }
};

static const value_string ieee802154_cmd_names[] = {
    { IEEE802154_CMD_ASRQ,      "Association Request" },
    { IEEE802154_CMD_ASRSP,     "Association Response" },
    { IEEE802154_CMD_DISAS,     "Disassociation Notification" },
    { IEEE802154_CMD_DATA_RQ,   "Data Request" },
    { IEEE802154_CMD_PANID_ERR, "PAN ID Conflict" },
    { IEEE802154_CMD_ORPH_NOTIF,"Orphan Notification" },
    { IEEE802154_CMD_BCN_RQ,    "Beacon Request" },
    { IEEE802154_CMD_COORD_REAL,"Coordinator Realignment" },
    { IEEE802154_CMD_GTS_REQ,   "GTS Request" },
    { 0, NULL }
};

/* CRC definitions. IEEE 802.15.4 CRCs vary from CCITT by using an initial value of
 * 0x0000, and no XOR out. IEEE802154_CRC_XOR is defined as 0xFFFF in order to un-XOR
 * the output from the CCITT CRC routines in Wireshark.
 */
#define IEEE802154_CRC_SEED     0x0000
#define IEEE802154_CRC_XOROUT   0xFFFF
#define ieee802154_crc_tvb(tvb, offset)   (crc16_ccitt_tvb_seed(tvb, offset, IEEE802154_CRC_SEED) ^ IEEE802154_CRC_XOROUT)

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      get_by_mask
 *  DESCRIPTION
 *      Extracts an integer sub-field from an int with a given mask
 *      if the mask is 0, this will return 0, if the mask is non-
 *      continuos the output is undefined.
 *  PARAMETERS
 *      guint       input
 *      guint       mask
 *  RETURNS
 *      guint
 *---------------------------------------------------------------
 */
guint
get_by_mask(guint input, guint mask)
{
    /* Sanity Check, don't want infinite loops. */
    if (mask == 0) return 0;
    /* Shift input and mask together. */
    while (!(mask & 0x1)) {
        input >>= 1;
        mask >>=1;
    } /* while */
    return (input & mask);
} /* get_by_mask */

#define EUI64_STRLEN    (3*(sizeof(guint64)+1))
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      print_eui64
 *  DESCRIPTION
 *      Prints an EUI-64 address in a string. Does not attempt to
 *      resolve the OUI value.
 *
 *  PARAMETERS
 *      guint64 addr
 *  RETURNS
 *      gchar*
 *---------------------------------------------------------------
 */
gchar *
print_eui64(guint64 addr)
{
    address         eui64addr;

    /* Endian-swap the address to put it into network order. */
    addr = pntoh64(&addr);
    /* Fill in the address struct. */
    eui64addr.type = AT_EUI64;
    eui64addr.len = sizeof(guint64);
    eui64addr.data = &addr;
    /* Print the address. */
    return address_to_str(&eui64addr);
} /* print_eui64 */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      print_eui64_oui
 *  DESCRIPTION
 *      Prints an EUI-64 address in a string. Attempts to lookup
 *      the vendor name from the OUI,
 *
 *  PARAMETERS
 *      guint64 addr
 *  RETURNS
 *      gchar*
 *---------------------------------------------------------------
 */
gchar *
print_eui64_oui(guint64 addr)
{
    const gchar     *manuf_name;
    address         eui64addr;

    /* Endian-swap the address to put it into network order. */
    addr = pntoh64(&addr);
    /* Fill in the address struct. */
    eui64addr.type = AT_EUI64;
    eui64addr.len = sizeof(guint64);
    eui64addr.data = &addr;
    /* Attempt an OUI lookup. */
    manuf_name = get_manuf_name_if_known(eui64addr.data);
    if (manuf_name == NULL) {
        /* Could not find an OUI. */
        return address_to_str(&eui64addr);
    }
    else {
        /* Found an address string. */
        gchar       *output_str = ep_alloc(64);
        g_snprintf(output_str, 64, "%s_%02x:%02x:%02x:%02x:%02x", manuf_name,
            ((guint8 *)(eui64addr.data))[3], ((guint8 *)(eui64addr.data))[4],
            ((guint8 *)(eui64addr.data))[5], ((guint8 *)(eui64addr.data))[6],
            ((guint8 *)(eui64addr.data))[7]);
        return output_str;
    }
} /* print_eui64_oui */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_ieee802154_fcf
 *  DESCRIPTION
 *      Dissector helper, parses and displays the frame control
 *      field.
 *
 *  PARAMETERS
 *      ieee802154_packet   *packet - Packet info structure.
 *      tvbuff_t    *tvb    - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree  *tree   - pointer to data tree ethereal uses to display packet.
 *      ieee802154_packet *packet   - IEEE 802.15.4 packet information.
 *      guint       offset  - offset into the tvb to find the FCF.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_ieee802154_fcf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ieee802154_packet *packet, guint *offset)
{
    guint16         fcf;
    proto_tree      *field_tree;
    proto_item      *ti;

    /* Get the FCF field. */
    fcf = tvb_get_letohs(tvb, *offset);

     /* Parse FCF Flags. */
    packet->frame_type      = get_by_mask(fcf, IEEE802154_FCF_TYPE_MASK);
    packet->security_enable = get_by_mask(fcf, IEEE802154_FCF_SEC_EN);
    packet->frame_pending   = get_by_mask(fcf, IEEE802154_FCF_FRAME_PND);
    packet->ack_request     = get_by_mask(fcf, IEEE802154_FCF_ACK_REQ);
    packet->intra_pan       = get_by_mask(fcf, IEEE802154_FCF_INTRA_PAN);
    packet->version         = get_by_mask(fcf, IEEE802154_FCF_VERSION);
    packet->dst_addr_mode   = get_by_mask(fcf, IEEE802154_FCF_DADDR_MASK);
    packet->src_addr_mode   = get_by_mask(fcf, IEEE802154_FCF_SADDR_MASK);

    /* Display the frame type. */
    if (tree) proto_item_append_text(tree, " %s", val_to_str(packet->frame_type, ieee802154_frame_types, "Reserved"));
    if (check_col(pinfo->cinfo, COL_INFO)) col_set_str(pinfo->cinfo, COL_INFO, val_to_str(packet->frame_type, ieee802154_frame_types, "Reserved"));

    /* Add the FCF to the protocol tree. */
    if (tree) {
        /*  Create the FCF subtree. */
        ti = proto_tree_add_text(tree, tvb, *offset, sizeof(guint16), "Frame Control Field: %s (0x%04x)",
                val_to_str(packet->frame_type, ieee802154_frame_types, "Unknown"), fcf);
        field_tree = proto_item_add_subtree(ti, ett_ieee802154_fcf);

        /* FCF Fields. */
        proto_tree_add_uint(field_tree, hf_ieee802154_frame_type, tvb, *offset, sizeof(guint8), fcf & IEEE802154_FCF_TYPE_MASK);
        proto_tree_add_boolean(field_tree, hf_ieee802154_security, tvb, *offset, sizeof(guint8), fcf & IEEE802154_FCF_SEC_EN);
        proto_tree_add_boolean(field_tree, hf_ieee802154_pending, tvb, *offset, sizeof(guint8), fcf & IEEE802154_FCF_FRAME_PND);
        proto_tree_add_boolean(field_tree, hf_ieee802154_ack_request, tvb, *offset, sizeof(guint8), fcf & IEEE802154_FCF_ACK_REQ);
        proto_tree_add_boolean(field_tree, hf_ieee802154_intra_pan, tvb, *offset, sizeof(guint8), fcf & IEEE802154_FCF_INTRA_PAN);
        proto_tree_add_uint(field_tree, hf_ieee802154_dst_addr_mode, tvb, (*offset)+sizeof(guint8), sizeof(guint8), fcf & IEEE802154_FCF_DADDR_MASK);
        proto_tree_add_uint(field_tree, hf_ieee802154_version, tvb, (*offset)+sizeof(guint8), sizeof(guint8), fcf & IEEE802154_FCF_VERSION);
        proto_tree_add_uint(field_tree, hf_ieee802154_src_addr_mode, tvb, (*offset)+sizeof(guint8), sizeof(guint8), fcf & IEEE802154_FCF_SADDR_MASK);
    }

    *offset += sizeof(guint16);
} /* dissect_ieee802154_fcf */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_ieee802154
 *  DESCRIPTION
 *      Dissector for IEEE 802.15.4 packet with an FCS containing
 *      a 16-bit CRC value.
 *
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_ieee802154(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Call the common dissector. */
    dissect_ieee802154_common(tvb, pinfo, tree, 0);
} /* dissect_ieee802154 */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_ieee802154_nofcs
 *  DESCRIPTION
 *      Dissector for IEEE 802.15.4 packet with no FCS present.
 *
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_ieee802154_nofcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t    *new_tvb;
    /* If there is no FCS present in the reported packet, then the length of
     * the true IEEE 802.15.4 packet is actually 2 bytes longer. Re-create
     * the buffer with an extended reported length so that the packet will
     * be handled as though the FCS were truncated.
     *
     * Note, we can't just call tvb_set_reported_length(), because it includes
     * checks to ensure that the new reported length is not longer than the old
     * reported length (why?), and will throw an exception.
     */
    new_tvb = tvb_new_subset(tvb, 0, -1, tvb_reported_length(tvb)+IEEE802154_FCS_LEN);
    /* Call the common dissector. */
    dissect_ieee802154_common(new_tvb, pinfo, tree, 0);
} /* dissect_ieee802154_nofcs */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_ieee802154_cc24xx
 *  DESCRIPTION
 *      Dissector for IEEE 802.15.4 packet with a ChipCon/Texas
 *      Instruments compatible FCS. This is typically called by
 *      layers encapsulating an IEEE 802.15.4 packet.
 *
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_ieee802154_cc24xx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Call the common dissector. */
    dissect_ieee802154_common(tvb, pinfo, tree, DISSECT_IEEE802154_OPTION_CC24xx);
} /* dissect_ieee802154_cc24xx */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_ieee802154_common
 *  DESCRIPTION
 *      IEEE 802.15.4 packet dissection routine for Ethereal.
 *      This function extracts all the information first before displaying.
 *      If payload exists, that portion will be passed into another dissector
 *      for further processing.
 *
 *      This is called after the individual dissect_ieee802154* functions
 *      have been called to determine what sort of FCS is present.
 *      The dissect_ieee802154* functions will set the parameters
 *      in the ieee802154_packet structure, and pass it to this one
 *      through the pinfo->private_data pointer.
 *
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      guint options       - bitwise or of dissector options (see DISSECT_IEEE802154_OPTION_xxx).
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_ieee802154_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint options)
{
    tvbuff_t            *payload_tvb;
    proto_tree          *volatile ieee802154_tree = NULL;
    proto_item          *volatile proto_root = NULL;
    proto_item          *ti;

    guint               offset = 0;
    gboolean            fcs_ok = TRUE;
    const char          *saved_proto;
    ieee802154_packet   *packet = ep_alloc(sizeof(ieee802154_packet));

    /* Link our packet info structure into the private data field for the
     * Network-Layer heuristic subdissectors. */
    pinfo->private_data = packet;

    /* Create the protocol tree. */
    if (tree) {
        proto_root = proto_tree_add_protocol_format(tree, proto_ieee802154, tvb, 0, tvb_length(tvb), "IEEE 802.15.4");
        ieee802154_tree = proto_item_add_subtree(proto_root, ett_ieee802154);
    }
    /* Add the protocol name. */
    if(check_col(pinfo->cinfo, COL_PROTOCOL)){
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEEE 802.15.4");
    }
    /* Add the packet length. */
    if(check_col(pinfo->cinfo, COL_PACKET_LENGTH)){
        col_clear(pinfo->cinfo, COL_PACKET_LENGTH);
        col_add_fstr(pinfo->cinfo, COL_PACKET_LENGTH, "%i", tvb_length(tvb));
    }

    /*=====================================================
     * FRAME CONTROL FIELD
     *=====================================================
     */
    dissect_ieee802154_fcf(tvb, pinfo, ieee802154_tree, packet, &offset);

    /*=====================================================
     * SEQUENCE NUMBER
     *=====================================================
     */
    packet->seqno = tvb_get_guint8(tvb, offset);
    if (tree) {
        proto_tree_add_uint(ieee802154_tree, hf_ieee802154_seqno, tvb, offset, 1, packet->seqno);
        /* For Ack packets display this in the root. */
        if (packet->frame_type == IEEE802154_FCF_ACK) {
            proto_item_append_text(proto_root, ", Sequence Number: %u", packet->seqno);
        }
    }
    offset += sizeof(guint8);

    /*=====================================================
     * ADDRESSING FIELDS
     *=====================================================
     */
    /* Clear out the addressing strings. */
    SET_ADDRESS(&pinfo->dst, AT_NONE, 0, NULL);
    SET_ADDRESS(&pinfo->src, AT_NONE, 0, NULL);
    SET_ADDRESS(&pinfo->dl_dst, AT_NONE, 0, NULL);
    SET_ADDRESS(&pinfo->dl_src, AT_NONE, 0, NULL);
    SET_ADDRESS(&pinfo->net_dst, AT_NONE, 0, NULL);
    SET_ADDRESS(&pinfo->net_src, AT_NONE, 0, NULL);

    /* Get and display the destination PAN, if present. */
    if ( (packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) ||
         (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT) ) {
        packet->dst_pan = tvb_get_letohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(ieee802154_tree, hf_ieee802154_dst_pan, tvb, offset, sizeof(guint16), packet->dst_pan);
        }
        offset += sizeof(guint16);
    }

    /* Get destination address. */
    if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
        /* Dynamic (not stack) memory required for address column. */
        gchar   *dst_addr = ep_alloc(32);

        /* Get the address. */
        packet->dst.addr16 = tvb_get_letohs(tvb, offset);

        /* Display the destination address. */
        if(packet->dst.addr16==IEEE802154_BCAST_ADDR) g_snprintf(dst_addr, 32, "Broadcast");
        else g_snprintf(dst_addr, 32, "0x%04x", packet->dst.addr16);
        SET_ADDRESS(&pinfo->dl_dst, AT_STRINGZ, strlen(dst_addr)+1, dst_addr);
        SET_ADDRESS(&pinfo->dst, AT_STRINGZ, strlen(dst_addr)+1, dst_addr);
        if (tree) {
            proto_tree_add_uint(ieee802154_tree, hf_ieee802154_dst_addr16, tvb, offset, sizeof(guint16), packet->dst.addr16);
            proto_item_append_text(proto_root, ", Dst: %s", dst_addr);
        }
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Dst: %s", dst_addr);
        }
        offset += sizeof(guint16);
    }
    else if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT) {
        /* Dynamic (not stack) memory required for address column. */
        gchar    *addr = ep_alloc(sizeof(guint64));
        gchar    *dst, *dst_oui;

        /* Get the address */
        packet->dst.addr64 = tvb_get_letoh64(tvb, offset);

        /* print the address strings. */
        dst = print_eui64(packet->dst.addr64);
        dst_oui = print_eui64_oui(packet->dst.addr64);

        /* Copy and convert the address to network byte order. */
        *(guint64 *)(addr) = pntoh64(&(packet->dst.addr64));

        /* Display the destination address. */
        /* NOTE: OUI resolution doesn't happen when displaying EUI64 addresses
         *          might want to switch to AT_STRINZ type to display the OUI in
         *          the address columns.
         */
        SET_ADDRESS(&pinfo->dl_dst, AT_EUI64, sizeof(guint64), addr);
        SET_ADDRESS(&pinfo->dst, AT_EUI64, sizeof(guint64), addr);
        if (tree) {
            proto_tree_add_uint64_format_value(ieee802154_tree, hf_ieee802154_dst_addr64, tvb, offset, sizeof(guint64), packet->dst.addr64, "%s (%s)", dst_oui, dst);
            proto_item_append_text(proto_root, ", Dst: %s", dst_oui);
        }
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Dst: %s", dst_oui);
        }
        offset += sizeof(guint64);
    }
    else if (packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE) {
        /* Invalid Destination Address Mode. Abort Dissection. */
        expert_add_info_format(pinfo, proto_root, PI_MALFORMED, PI_ERROR, "Invalid Destination Address Mode");
        return;
    }

    /* Get the source PAN if it exists. The source address will be present if:
     *  - The Source addressing exists and
     *  - The Destination addressing doesn't exist, or the Intra-PAN bit is unset.
     */
    if ( ((packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) || (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT)) &&
         ((packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE) || (!packet->intra_pan)) ) {
        /* Source PAN is present, extract it and add it to the tree. */
        packet->src_pan = tvb_get_letohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(ieee802154_tree, hf_ieee802154_src_panID, tvb, offset, sizeof(guint16), packet->src_pan);
        }
        offset += sizeof(guint16);
    }
    else {
        /* Set the panID field in case the intra-pan condition was met. */
        packet->src_pan = packet->dst_pan;
    }

    /* Get source address if present. */
    if (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
        /* Dynamic (not stack) memory required for address column. */
        gchar   *src_addr = ep_alloc(32);

        /* Get the address. */
        packet->src.addr16 = tvb_get_letohs(tvb, offset);

        /* Update the Address fields. */
        if(packet->src.addr16==IEEE802154_BCAST_ADDR) g_snprintf(src_addr, 32, "Broadcast");
        else g_snprintf(src_addr, 32, "0x%04x", packet->src.addr16);
        SET_ADDRESS(&pinfo->dl_src, AT_STRINGZ, strlen(src_addr)+1, src_addr);
        SET_ADDRESS(&pinfo->src, AT_STRINGZ, strlen(src_addr)+1, src_addr);

        /* Add the addressing info to the tree. */
        if (tree) {
            proto_tree_add_uint(ieee802154_tree, hf_ieee802154_src_addr16, tvb, offset, sizeof(guint16), packet->src.addr16);
            proto_item_append_text(proto_root, ", Src: %s", src_addr);
        }
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Src: %s", src_addr);
        }
        offset += sizeof(guint16);
    }
    else if (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) {
        /* Dynamic (not stack) memory required for address column. */
        gchar   *addr = ep_alloc(sizeof(guint64));
        gchar   *src, *src_oui;

        /* Get the address. */
        packet->src.addr64 = tvb_get_letoh64(tvb, offset);

        /* Print the address strings. */
        src = print_eui64(packet->src.addr64);
        src_oui = print_eui64_oui(packet->src.addr64);

        /* Copy and convert the address to network byte order. */
        *(guint64 *)(addr) = pntoh64(&(packet->src.addr64));

        /* Display the source address. */
        /* NOTE: OUI resolution doesn't happen when displaying EUI64 addresses
         *          might want to switch to AT_STRINZ type to display the OUI in
         *          the address columns.
         */
        SET_ADDRESS(&pinfo->dl_src, AT_EUI64, sizeof(guint64), addr);
        SET_ADDRESS(&pinfo->src, AT_EUI64, sizeof(guint64), addr);
        if (tree) {
            proto_tree_add_uint64_format_value(ieee802154_tree, hf_ieee802154_src_addr64, tvb, offset, sizeof(guint64), packet->src.addr64, "%s (%s)", src_oui, src);
            proto_item_append_text(proto_root, ", Src: %s", src_oui);
        }
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Src: %s", src_oui);
        }
        offset += sizeof(guint64);
    }
    else if (packet->src_addr_mode != IEEE802154_FCF_ADDR_NONE) {
        /* Invalid Destination Address Mode. Abort Dissection. */
        expert_add_info_format(pinfo, proto_root, PI_MALFORMED, PI_ERROR, "Invalid Source Address Mode");
        return;
    }

    /*=====================================================
     * FRAME CHECK SEQUENCE VERIFICATION
     *=====================================================
     */
    /* Check, but don't display the FCS yet, otherwise the payload dissection
     * may be out of place in the tree. But we want to know if the FCS is OK in
     * case the CRC is bad (don't want to continue dissection to the NWK layer).
     */
    if (tvb_bytes_exist(tvb, tvb_reported_length(tvb)-IEEE802154_FCS_LEN, IEEE802154_FCS_LEN)) {
        /* The FCS is in the last two bytes of the packet. */
        guint16     fcs = tvb_get_letohs(tvb, tvb_reported_length(tvb)-IEEE802154_FCS_LEN);
        gboolean    fcs_ok;
        /* Check if we are expecting a CC2420-style FCS*/
        if (options & DISSECT_IEEE802154_OPTION_CC24xx) {
            fcs_ok = (fcs & IEEE802154_CC24xx_CRC_OK);
        }
        else {
            fcs_ok = (fcs == ieee802154_crc_tvb(tvb, tvb_reported_length(tvb)-IEEE802154_FCS_LEN));
        }
    }

    /*=====================================================
     * PAYLOAD DISSECTION
     *=====================================================
     */
    /* Create the payload buffer. */
    payload_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb)-offset-IEEE802154_FCS_LEN);
    /* Just being safe to ensure that real_length <= reported_length. The tvbuff
     * code should ensure this condition when creating the subset, but I don't
     * think it does. */
    tvb_set_reported_length(payload_tvb, tvb_reported_length(tvb)-offset-IEEE802154_FCS_LEN);
    /* We can't handle encryption, so if the packet is encrypted, give up. */
    if (packet->security_enable) {
        /* Payload is encrypted. We can't handle this. Maybe a future feature? */
        expert_add_info_format(pinfo, proto_root, PI_UNDECODED, PI_WARN, "Encrypted Payload");
        call_dissector(data_handle, payload_tvb, pinfo, tree);
        goto dissect_ieee802154_fcs;
    }
    /*
     * Wrap the sub-dissection in a try/catch block in case the payload is
     * broken. First we store the current protocol so we can fix it if an
     * exception is thrown by the subdissectors.
     */
    saved_proto = pinfo->current_proto;
    /* Try to dissect the payload. */
    TRY {
        switch (packet->frame_type) {
            case IEEE802154_FCF_BEACON:
                dissect_ieee802154_beacon(payload_tvb, pinfo, ieee802154_tree, packet);
                break;
            case IEEE802154_FCF_CMD:
                dissect_ieee802154_cmd(payload_tvb, pinfo, ieee802154_tree, packet);
                break;
            case IEEE802154_FCF_DATA:
                if (fcs_ok && (tvb_reported_length(payload_tvb)>0)) {
                    /* Attempt heuristic subdissection. */
                    if (dissector_try_heuristic(ieee802154_heur_subdissector_list, payload_tvb, pinfo, tree)) {
                        /* found a sub-dissector! */
                        break;
                    }
                }
                /* If no sub-dissector was called, call the data dissector. */
                call_dissector(data_handle, payload_tvb, pinfo, tree);
                break;
            case IEEE802154_FCF_ACK:
                /* Ack should not contain a payload. */
                if (tvb_reported_length(payload_tvb) > 0) {
                    expert_add_info_format(pinfo, proto_root, PI_MALFORMED, PI_WARN, "Unexpected Payload in Acknowledgement");
                }
                call_dissector(data_handle, payload_tvb, pinfo, tree);
                break;
            default:
                /* Unknown frame type! */
                call_dissector(data_handle, payload_tvb, pinfo, tree);
                break;
        } /* switch */
    }
    CATCH_ALL {
        /*
         * Someone encountered an error while dissecting the payload. But
         * we haven't yet finished processing all of our layer. Catch and
         * display the exception, then fall-through to finish displaying
         * the FCS (which we display last so the frame is ordered correctly
         * in the tree).
         */
        show_exception(payload_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
        pinfo->current_proto = saved_proto;
    }
    ENDTRY;

    /*=====================================================
     * FRAME CHECK SEQUENCE
     *=====================================================
     */
dissect_ieee802154_fcs:
    /* The FCS should be the last bytes of the reported packet. */
    offset = tvb_reported_length(tvb)-IEEE802154_FCS_LEN;
    /* Dissect the FCS only if it exists (captures which don't or can't get the
     * FCS will simply truncate the packet to omit it, but should still set the
     * reported length to cover the original packet length), so if the snapshot
     * is too short for an FCS don't make a fuss.
     */
    if (tvb_bytes_exist(tvb, offset, IEEE802154_FCS_LEN) && (tree)) {
        proto_tree  *field_tree;
        guint16     fcs = tvb_get_letohs(tvb, offset);

        /* Display the FCS depending on expected FCS format */
        if ((options & DISSECT_IEEE802154_OPTION_CC24xx)) {
            /* Create a subtree for the FCS. */
            ti = proto_tree_add_text(ieee802154_tree, tvb, offset, sizeof(guint16), "Frame Check Sequence: FCS %s", (fcs_ok) ? "OK" : "Bad");
            field_tree = proto_item_add_subtree(ti, ett_ieee802154_fcs);
            /* Display FCS contents.  */
            ti = proto_tree_add_int(field_tree, hf_ieee802154_rssi, tvb, offset, sizeof(guint16), get_by_mask(fcs, IEEE802154_CC24xx_RSSI));
            proto_item_append_text(ti, " dBm"); /*  Displaying Units */
            proto_tree_add_boolean(field_tree, hf_ieee802154_fcs_ok, tvb, offset, sizeof(guint16), get_by_mask(fcs, IEEE802154_CC24xx_CRC_OK));
            proto_tree_add_uint(field_tree, hf_ieee802154_correlation, tvb, offset, sizeof(guint16), get_by_mask(fcs, IEEE802154_CC24xx_CORRELATION));
        }
        else {
            ti = proto_tree_add_uint(ieee802154_tree, hf_ieee802154_fcs, tvb, offset, sizeof(guint16), fcs);
            if (fcs_ok) {
                proto_item_append_text(ti, " (Correct)");
            }
            else {
                proto_item_append_text(ti, " (Incorrect, expected FCS=0x%04x", ieee802154_crc_tvb(tvb, offset));
            }
            /* To Help with filtering, add the fcs_ok field to the tree.  */
            ti = proto_tree_add_boolean(ieee802154_tree, hf_ieee802154_fcs_ok, tvb, offset, sizeof(guint16), fcs_ok);
            PROTO_ITEM_SET_HIDDEN(ti);
        }
    }
    else if (tree) {
        /* Even if the FCS isn't present, add the fcs_ok field to the tree to
         * help with filter. Be sure not to make it visible though.
         */
        ti = proto_tree_add_boolean(ieee802154_tree, hf_ieee802154_fcs_ok, tvb, offset, sizeof(guint16), fcs_ok);
        PROTO_ITEM_SET_HIDDEN(ti);
    }

    /* If the CRC is invalid, make a note of it in the info column. */
    if (!fcs_ok) {
        if (check_col(pinfo->cinfo, COL_INFO)) col_append_fstr(pinfo->cinfo, COL_INFO, ", Bad FCS");
        if (tree) proto_item_append_text(proto_root, ", Bad FCS");

        /* Flag packet as having a bad crc. */
        expert_add_info_format(pinfo, proto_root, PI_CHECKSUM, PI_WARN, "Bad FCS");
    }
} /* dissect_ieee802154_common */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_ieee802154_beacon
 *  DESCRIPTION
 *      ZigBee packet dissection routine for beacon packets.Please refer
 *      to section 7.2.2.1 in the IEEE 802.15.4 document on Beacon frame format
 *  PARAMETERS
 *      tvbuff_t *tvb               - pointer to buffer containing raw packet.
 *      packet_info *pinfo          - pointer to packet information fields
 *      proto_tree *tree            - pointer to data tree ethereal uses to display packet.
 *      ieee802154_packet *packet   - IEEE 802.15.4 packet information.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_ieee802154_beacon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ieee802154_packet *packet)
{
    proto_tree          *field_tree = NULL;
    proto_tree          *bcn_tree = NULL;
    proto_item          *ti;

    guint8      superframe_spec_hi;
    guint8      superframe_spec_lo;
    guint8      gts_spec;
    guint8      gts_desc_count;
    guint8      paddr_spec;
    guint8      paddr_num16;
    guint8      paddr_num64;
    guint8      bcn_payload_len;

    gint        i;
    gint        offset = 0;

    /* Parse the superframe spec. */
    superframe_spec_hi = tvb_get_guint8(tvb, offset);
    superframe_spec_lo = tvb_get_guint8(tvb, offset+1);
    if(tree){
        guint8  bo = superframe_spec_hi & IEEE802154_BCN_BO_MASK;
        guint8  sfo = (superframe_spec_hi & IEEE802154_BCN_SFO_MASK)>>IEEE802154_BCN_SFO_SHIFT;

        /*  Add Subtree for beacon frame */
        ti = proto_tree_add_text(tree, tvb, 0, tvb_length(tvb), "Beacon Frame");
        bcn_tree = proto_item_add_subtree(ti, ett_ieee802154_bcn);

        /* 'Light' Assert to check for valid addressing. */
        if (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_WARN, "Missing Source Address in Beacon" );
        }

        /*  Add Subtree for superframe specification */
        ti = proto_tree_add_text(bcn_tree, tvb, offset, 2, "Superframe Specification");
        field_tree = proto_item_add_subtree(ti, ett_ieee802154_bcn_superframe_spec);

        /*  Add Beacon Order to the superframe spec. */
        ti = proto_tree_add_uint_format(field_tree, hf_ieee802154_bcn_beacon_order, tvb, offset, 1, bo, "Beacon Order: ");
        if(bo == 0xf) proto_item_append_text(ti, "Beacons Disabled");
        else proto_item_append_text(ti, "%i", IEEE802154_BCN_SFRM_DURATION*(1<<bo));

        /* Add superframe order to superframe spec. */
        ti = proto_tree_add_uint_format(field_tree, hf_ieee802154_bcn_superframe_order, tvb, offset, 1, sfo, "Superframe Order: ");
        if(bo == 0xf) proto_item_append_text(ti, "Inactive");
        else proto_item_append_text(ti, "%i", IEEE802154_BCN_SFRM_DURATION*(1<<sfo));

        /* Add the CAP and Flags. */
        proto_tree_add_uint(field_tree, hf_ieee802154_bcn_cap, tvb, offset+1, 1, superframe_spec_lo & IEEE802154_BCN_CAP_MASK);
        proto_tree_add_boolean(field_tree, hf_ieee802154_bcn_battery_ext, tvb, offset+1, 1, superframe_spec_lo & IEEE802154_BCN_BATT_EXTN_MASK);
        proto_tree_add_boolean(field_tree, hf_ieee802154_bcn_coord, tvb, offset+1, 1, superframe_spec_lo & IEEE802154_BCN_COORD_MASK);
        proto_tree_add_boolean(field_tree, hf_ieee802154_bcn_assoc_permit, tvb, offset+1, 1, superframe_spec_lo & IEEE802154_BCN_ASSOC_PERM_MASK);
    }
    offset += sizeof(guint16);

    /*  Get and display the GTS specification field */
    gts_spec = tvb_get_guint8(tvb, offset);
    gts_desc_count = gts_spec & IEEE802154_BCN_GTS_COUNT_MASK;
    if(tree){
        proto_tree_add_uint(bcn_tree, hf_ieee802154_bcn_gts_count, tvb, offset, 1, gts_desc_count);
        proto_tree_add_boolean(bcn_tree, hf_ieee802154_bcn_gts_permit, tvb, offset, 1, gts_spec & IEEE802154_BCN_GTS_PERMIT_MASK);
    }
    offset += sizeof(guint8);

    /* If the GTS descriptor count is nonzero, then the GTS directions mask and descriptor list are present. */
    if(gts_desc_count){
        guint8  gts_directions = tvb_get_guint8(tvb, offset + 1);
        guint   gts_numRx = 0;

        /* Display the directions mask. */
        if (tree) {
            /* Create a subtree. */
            ti = proto_tree_add_text(bcn_tree, tvb, offset, sizeof(guint8), "GTS Directions");
            field_tree = proto_item_add_subtree(ti, ett_ieee802154_bcn_gts_direction);

            /* Add the directions to the subtree. */
            for (i=0; i<gts_desc_count; i++) {
                gboolean    dir = gts_directions & IEEE802154_BCN_GTS_DIRECTION_SLOT(i);

                proto_tree_add_boolean_format(field_tree, hf_ieee802154_bcn_gts_direction, tvb, offset, sizeof(guint8), dir, "GTS Slot %i: %s", i+1, dir?"Receive Only":"Transmit Only");
                if (dir) gts_numRx++;
            } /* for */
            proto_item_append_text(ti, ": %i Receive & %i Transmit", gts_numRx, gts_desc_count-gts_numRx);
        }
        offset += sizeof(guint8);

        /* Create a subtree for the GTS descriptors. */
        if (tree) {
            ti = proto_tree_add_text(bcn_tree, tvb, offset, (sizeof(guint16)+sizeof(guint8))*gts_desc_count, "GTS Descriptors");
            field_tree = proto_item_add_subtree(ti, ett_ieee802154_bcn_gts_descriptors);
        }

        /* Get and display the GTS descriptors. */
        for (i=0; i<gts_desc_count; i++) {
            guint16 gts_addr        = tvb_get_letohs(tvb, offset);
            guint8  gts_slot        = tvb_get_guint8(tvb, offset+2);
            guint8  gts_slot_len    = (gts_slot & IEEE802154_BCN_GTS_LENGTH_MASK) >> IEEE802154_BCN_GTS_LENGTH_SHIFT;

            if (tree) {
                /* Add address, slot, and time length fields. */
                ti = proto_tree_add_text(field_tree, tvb, offset, 2, "{Address: 0x%04x", gts_addr);
                proto_item_append_text(ti, ", Slot: %i", gts_slot);
                proto_item_append_text(ti, ", Length: %i}", gts_slot_len);
            }
            offset += sizeof(guint16)+sizeof(guint8);
        } /* for */
    }

    /*  Get the Pending Addresses specification fields */
    paddr_spec = tvb_get_guint8(tvb, offset);
    paddr_num16 = paddr_spec & IEEE802154_BCN_PADDR_SHORT_MASK;
    paddr_num64 = (paddr_spec & IEEE802154_BCN_PADDR_LONG_MASK) >> IEEE802154_BCN_PADDR_LONG_SHIFT;
    if(tree){
        /*  Add Subtree for the addresses */
        ti = proto_tree_add_text(bcn_tree, tvb, offset, 1 + 2*paddr_num16 + 8*paddr_num64, "Pending Addresses: %i Short and %i Long", paddr_num16, paddr_num64);
        field_tree = proto_item_add_subtree(ti, ett_ieee802154_bcn_pending);
    }
    offset += sizeof(guint8);

    for (i=0; i<paddr_num16; i++) {
        guint16 addr = tvb_get_letohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(field_tree, hf_ieee802154_bcn_pending16, tvb, offset, sizeof(guint16), addr);
        }
        offset += sizeof(guint16);
    }
    for (i=0; i<paddr_num64; i++) {
        guint64 addr = tvb_get_letoh64(tvb, offset);
        if (tree) {
            proto_tree_add_uint64_format_value(field_tree, hf_ieee802154_bcn_pending64, tvb, offset, sizeof(guint64), addr, "%s (%s)", print_eui64_oui(addr), print_eui64(addr));
        }
        offset += sizeof(guint64);
    }

    /* Get the beacon payload (if it exists) */
    bcn_payload_len = tvb_length(tvb) - offset;
    if(bcn_payload_len){
        proto_tree  *root_tree      = proto_tree_get_root(tree);
        tvbuff_t    *payload_tvb    = tvb_new_subset(tvb, offset, bcn_payload_len, bcn_payload_len);
        /* Attempt subdissection. */
        if(!dissector_try_heuristic(ieee802154_heur_subdissector_list, payload_tvb, pinfo, root_tree)) {
            /* heuristic subdissector was not called. use data subdissector instead. */
            call_dissector(data_handle, payload_tvb, pinfo, root_tree);
        }
    }
} /* dissect_ieee802154_beacon */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_ieee802154_cmd
 *  DESCRIPTION
 *      IEEE 802.15.4 packet dissection routine for command packets
 *  PARAMETERS
 *      tvbuff_t *tvb               - pointer to buffer containing raw packet.
 *      packet_info *pinfo          - pointer to packet information fields
 *      proto_tree *tree            - pointer to data tree Ethereal uses to display packet.
 *      ieee802154_packet *packet   - IEEE 802.15.4 packet information.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 *  MAC Command Frames have a MAC Payload organized as follows:
 *  |Command Frame Identifier|   Command Payload    |
 *  |       1 Byte           |dependant upon command|
 *---------------------------------------------------------------
 */
static void
dissect_ieee802154_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ieee802154_packet   *packet)
{
    guint8              cmd_id;
    guint               offset = 0;
    proto_tree          *cmd_tree = NULL;
    proto_item          *ti;
    proto_item          *cmd_root = NULL;

#define CMD_ADDR_CHECK(x)    if (!(x)) expert_add_info_format(pinfo, cmd_root, PI_MALFORMED, PI_WARN, "Invalid Addressing for %s", val_to_str(cmd_id, ieee802154_cmd_names, "Unknown Command"))

    /* Get and display the command frame identifier. */
    cmd_id = tvb_get_guint8(tvb, offset);
    if(check_col(pinfo->cinfo, COL_INFO)) {
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str(cmd_id, ieee802154_cmd_names, "Unknown Command"));
    }
    if (tree) {
        /* Create a subtree for this command frame. */
        cmd_root = proto_tree_add_text(tree, tvb, 0, tvb_length(tvb), "Command Frame, %s", val_to_str(cmd_id, ieee802154_cmd_names, "Unknown Command"));
        cmd_tree = proto_item_add_subtree(cmd_root, ett_ieee802154_cmd);

        /* Add the command ID to the subtree. */
        ti = proto_tree_add_uint(cmd_tree, hf_ieee802154_cmd_id, tvb, offset, sizeof(guint8), cmd_id);
    }

    /* Increment the offset field. */
    offset += sizeof(guint8);

    /* Parse the Command Payloads. */
    switch(cmd_id){
        case IEEE802154_CMD_ASRQ:
            /* Check that the addressing is correct for this command type. */
            CMD_ADDR_CHECK((packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT)
                        && (packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE));

            dissect_ieee802154_cmd_asreq(tvb, pinfo, cmd_tree, packet, &offset);
            break;

        case IEEE802154_CMD_ASRSP:
            /* Check that the addressing is correct for this command type. */
            CMD_ADDR_CHECK((packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT)
                        && (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT));

            dissect_ieee802154_cmd_asrsp(tvb, pinfo, cmd_tree, packet, &offset);
            break;

        case IEEE802154_CMD_DISAS:
            /* Check that the addressing is correct for this command type. */
            CMD_ADDR_CHECK((packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT)
                        && (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT));

            dissect_ieee802154_cmd_disas(tvb, pinfo, cmd_tree, packet, &offset);
            break;

        case IEEE802154_CMD_DATA_RQ:
            /* Check that the addressing is correct for this command type. */
            CMD_ADDR_CHECK(packet->src_addr_mode != IEEE802154_FCF_ADDR_NONE);

            /* Data Req contains no payload. */
            break;

        case IEEE802154_CMD_PANID_ERR:
            /* Check that the addressing is correct for this command type. */
            CMD_ADDR_CHECK((packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT)
                        && (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT));

            /* PANID Err contains no payload. */
            break;

        case IEEE802154_CMD_ORPH_NOTIF:
            /* Check that the addressing is correct for this command type. */
            CMD_ADDR_CHECK((packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT)
                        && (packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT)
                        && (packet->dst.addr16 == IEEE802154_BCAST_ADDR)
                        && (packet->src_pan == IEEE802154_BCAST_PAN)
                        && (packet->dst_pan == IEEE802154_BCAST_PAN));

            /* Orphan Notification contains no payload. */
            break;

        case IEEE802154_CMD_BCN_RQ:
            /* Check that the addressing is correct for this command type. */
            CMD_ADDR_CHECK((packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT)
                        && (packet->src_addr_mode == IEEE802154_FCF_ADDR_NONE)
                        && (packet->dst.addr16 == IEEE802154_BCAST_ADDR)
                        && (packet->dst_pan == IEEE802154_BCAST_PAN));

            /* Beacon Request contains no payload. */
            break;

        case IEEE802154_CMD_COORD_REAL:
            /* Check that the addressing is correct for this command type. */
            CMD_ADDR_CHECK((packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT)
                        && (packet->dst_pan == IEEE802154_BCAST_PAN)
                        && (packet->dst_addr_mode != IEEE802154_FCF_ADDR_NONE));

            if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT) {
                /* If directed to a 16-bit address, check that it is being broadcast. */
                CMD_ADDR_CHECK(packet->dst.addr16 == IEEE802154_BCAST_ADDR);
            }

            dissect_ieee802154_cmd_realign(tvb, pinfo, cmd_tree, packet, &offset);
            break;

        case IEEE802154_CMD_GTS_REQ:
            /* Check that the addressing is correct for this command type. */
            CMD_ADDR_CHECK((packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT)
                        && (packet->dst_addr_mode == IEEE802154_FCF_ADDR_NONE)
                        && (packet->src.addr16 != IEEE802154_BCAST_ADDR)
                        && (packet->src.addr16 != IEEE802154_NO_ADDR16));

            dissect_ieee802154_cmd_gtsrq(tvb, pinfo, cmd_tree, packet, &offset);
            break;

        default:
            break;
    } /* switch */

#undef CMD_ADDR_CHECK

    /* If there are bytes leftover, call the data dissector to handle them. */
    if (offset < tvb_length(tvb)) {
        guint       leftover_len    = tvb_length(tvb) - offset;
        proto_tree  *root           = proto_tree_get_root(tree);
        tvbuff_t    *leftover_tvb   = tvb_new_subset(tvb, offset, leftover_len, leftover_len);

        /* Call the data dissector. */
        if (leftover_tvb) call_dissector(data_handle, leftover_tvb, pinfo, root);
    }
} /* dissect_ieee802154_cmd */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_ieee802154_cmd_asreq
 *  DESCRIPTION
 *      Command subdissector routine for the Association request
 *      command.
 *
 *      Assumes that COL_INFO will be set to the command name,
 *      command name will already be appended to the command subtree
 *      and protocol root. In addition, assumes that the command ID
 *      has already been parsed.
 *  PARAMETERS
 *      tvbuff_t    *tvb            - pointer to buffer containing raw packet.
 *      packet_info *pinfo          - pointer to packet information fields (unused).
 *      proto_tree  *tree           - pointer to command subtree.
 *      ieee802154_packet *packet   - IEEE 802.15.4 packet information (unused).
 *      guint       *offset         - offset into the tvbuff to begin dissection.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_ieee802154_cmd_asreq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, ieee802154_packet *packet _U_, guint *offset)
{
    proto_item          *ti;
    proto_tree          *field_tree;
    guint8              capability_info;

    /* Get the capability info. */
    capability_info = tvb_get_guint8(tvb, *offset);

    /* Display capability info. */
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, *offset, sizeof(guint8), "Capability Information");
        field_tree = proto_item_add_subtree(ti, ett_ieee802154_cmd_cinfo);

        /* Enter the capability bits. */
        proto_tree_add_boolean(field_tree, hf_ieee802154_cmd_cinfo_alt_coord, tvb, *offset, sizeof(guint8), capability_info & IEEE802154_CMD_CINFO_ALT_PAN_COORD);
        ti = proto_tree_add_boolean(field_tree, hf_ieee802154_cmd_cinfo_device_type, tvb, *offset, sizeof(guint8), capability_info & IEEE802154_CMD_CINFO_DEVICE_TYPE);
        if (capability_info & IEEE802154_CMD_CINFO_DEVICE_TYPE) proto_item_append_text(ti, " (FFD)");
        else proto_item_append_text(ti, " (RFD)");
        ti = proto_tree_add_boolean(field_tree, hf_ieee802154_cmd_cinfo_power_src, tvb, *offset, sizeof(guint8), capability_info & IEEE802154_CMD_CINFO_POWER_SRC);
        if (capability_info & IEEE802154_CMD_CINFO_POWER_SRC) proto_item_append_text(ti, " (AC/Mains Power)");
        else proto_item_append_text(ti, " (Battery)");
        proto_tree_add_boolean(field_tree, hf_ieee802154_cmd_cinfo_idle_rx, tvb, *offset, sizeof(guint8), capability_info & IEEE802154_CMD_CINFO_IDLE_RX);
        proto_tree_add_boolean(field_tree, hf_ieee802154_cmd_cinfo_sec_capable, tvb, *offset, sizeof(guint8), capability_info & IEEE802154_CMD_CINFO_SEC_CAPABLE);
        proto_tree_add_boolean(field_tree, hf_ieee802154_cmd_cinfo_alloc_addr, tvb, *offset, sizeof(guint8), capability_info & IEEE802154_CMD_CINFO_ALLOC_ADDR);
    }

    /* Increase the offset. */
    (*offset) += sizeof(guint8);
} /* dissect_ieee802154_cmd_asreq */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_ieee802154_cmd_asrsp
 *  DESCRIPTION
 *      Command subdissector routine for the Association response
 *      command.
 *
 *      Assumes that COL_INFO will be set to the command name,
 *      command name will already be appended to the command subtree
 *      and protocol root. In addition, assumes that the command ID
 *      has already been parsed.
 *  PARAMETERS
 *      tvbuff_t    *tvb            - pointer to buffer containing raw packet.
 *      packet_info *pinfo          - pointer to packet information fields
 *      proto_tree  *tree           - pointer to command subtree.
 *      ieee802154_packet *packet   - IEEE 802.15.4 packet information (unused).
 *      guint       *offset         - offset into the tvbuff to begin dissection.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_ieee802154_cmd_asrsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ieee802154_packet *packet _U_, guint *offset)
{
    proto_item          *ti;
    guint16             short_addr;
    guint8              status;

    /* Get and display the short address. */
    short_addr = tvb_get_letohs(tvb, *offset);
    if (tree) {
        proto_tree_add_uint(tree, hf_ieee802154_cmd_asrsp_addr, tvb, *offset, sizeof(guint16), short_addr);
    }
    (*offset) += sizeof(guint16);

    /* Get and display the status. */
    status = tvb_get_guint8(tvb, *offset);
    if (tree) {
        ti = proto_tree_add_uint(tree, hf_ieee802154_cmd_asrsp_status, tvb, *offset, sizeof(guint8), status);
        if (status == IEEE802154_CMD_ASRSP_AS_SUCCESS) proto_item_append_text(ti, " (Association Successful)");
        else if (status == IEEE802154_CMD_ASRSP_PAN_FULL) proto_item_append_text(ti, " (PAN Full)");
        else if (status == IEEE802154_CMD_ASRSP_PAN_DENIED) proto_item_append_text(ti, " (Association Denied)");
        else proto_item_append_text(ti, " (Reserved)");
    }
    (*offset) += sizeof(guint8);

    /* Update the info column. */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        if (status == IEEE802154_CMD_ASRSP_AS_SUCCESS) {
            /* Association was successful. */
            if (packet->src_addr_mode != IEEE802154_FCF_ADDR_SHORT) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", PAN: 0x%04x", packet->dst_pan);
            }
            if (short_addr != IEEE802154_NO_ADDR16) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " Addr: 0x%04x", short_addr);
            }
        }
        else {
            /* Association was unsuccessful. */
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Unsuccessful");
        }
    }
} /* dissect_ieee802154_cmd_asrsp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_ieee802154_cmd_disas
 *  DESCRIPTION
 *      Command subdissector routine for the Disassociate command.
 *
 *      Assumes that COL_INFO will be set to the command name,
 *      command name will already be appended to the command subtree
 *      and protocol root. In addition, assumes that the command ID
 *      has already been parsed.
 *  PARAMETERS
 *      tvbuff_t    *tvb            - pointer to buffer containing raw packet.
 *      packet_info *pinfo          - pointer to packet information fields (unused).
 *      proto_tree  *tree           - pointer to command subtree.
 *      ieee802154_packet *packet   - IEEE 802.15.4 packet information (unused).
 *      guint       *offset         - offset into the tvbuff to begin dissection.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_ieee802154_cmd_disas(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, ieee802154_packet *packet _U_, guint *offset)
{
    proto_item          *ti;
    guint8              reason;

    /* Get and display the dissasociation reason. */
    reason = tvb_get_guint8(tvb, *offset);
    if (tree) {
        ti = proto_tree_add_uint(tree, hf_ieee802154_cmd_disas_reason, tvb, *offset, sizeof(guint8), reason);
        switch(reason) {
            case 0x01:
                proto_item_append_text(ti, " (Coordinator requests device to leave)");
                break;

            case 0x02:
                proto_item_append_text(ti, " (Device wishes to leave)");
                break;

            default:
                proto_item_append_text(ti, " (Reserved)");
                break;
        } /* switch */
    }

    /* Adjust offset */
    (*offset) += sizeof(guint8);
} /* dissect_ieee802154_cmd_disas */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_ieee802154_cmd_gtsrq
 *  DESCRIPTION
 *      Command subdissector routine for the Coordinator Realignment
 *      command.
 *
 *      Assumes that COL_INFO will be set to the command name,
 *      command name will already be appended to the command subtree
 *      and protocol root. In addition, assumes that the command ID
 *      has already been parsed.
 *  PARAMETERS
 *      tvbuff_t    *tvb            - pointer to buffer containing raw packet.
 *      packet_info *pinfo          - pointer to packet information fields
 *      proto_tree  *tree           - pointer to command subtree.
 *      ieee802154_packet *packet   - IEEE 802.15.4 packet information.
 *      guint       *offset         - offset into the tvbuff to begin dissection.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_ieee802154_cmd_realign(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ieee802154_packet *packet, guint *offset)
{
    guint16 pan_id;
    guint16 coord_addr;
    guint8  channel;
    guint16 short_addr;

    /* Get and display the command PAN ID. */
    pan_id = tvb_get_letohs(tvb, *offset);
    if (tree) proto_tree_add_uint(tree, hf_ieee802154_cmd_coord_pan, tvb, *offset, sizeof(guint16), pan_id);
    if (check_col(pinfo->cinfo, COL_INFO)) col_append_fstr(pinfo->cinfo, COL_INFO, ", PAN: 0x%04x", pan_id);
    (*offset) += sizeof(guint16);

    /* Get and display the coordinator address. */
    coord_addr = tvb_get_letohs(tvb, *offset);
    if (tree) proto_tree_add_uint(tree, hf_ieee802154_cmd_coord_caddr, tvb, *offset, sizeof(guint16), coord_addr);
    if (check_col(pinfo->cinfo, COL_INFO)) col_append_fstr(pinfo->cinfo, COL_INFO, ", Coordinator: 0x%04x", coord_addr);
    (*offset) += sizeof(guint16);

    /* Get and display the channel. */
    channel = tvb_get_guint8(tvb, *offset);
    if (tree) proto_tree_add_uint(tree, hf_ieee802154_cmd_coord_channel, tvb, *offset, sizeof(guint8), channel);
    if (check_col(pinfo->cinfo, COL_INFO)) col_append_fstr(pinfo->cinfo, COL_INFO, ", Channel: %u", channel);
    (*offset) += sizeof(guint8);

    /* Get and display the short address. */
    short_addr = tvb_get_letohs(tvb, *offset);
    if (tree) proto_tree_add_uint(tree, hf_ieee802154_cmd_coord_addr, tvb, *offset, sizeof(guint16), short_addr);
    if (   (check_col(pinfo->cinfo, COL_INFO))
        && (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT)
        && (short_addr != IEEE802154_NO_ADDR16)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Addr: 0x%04x", short_addr);
    }
    (*offset) += sizeof(guint16);

    /* Get and display the channel page, if it exists. Added in IEEE802.15.4-2006 */
    if (tvb_bytes_exist(tvb, *offset, sizeof(guint8))) {
        guint8  channel_page = tvb_get_guint8(tvb, *offset);

        if (tree) proto_tree_add_uint(tree, hf_ieee802154_cmd_coord_channel_page, tvb, *offset, sizeof(guint8), channel_page);
        (*offset) += sizeof(guint8);
    }
} /* dissect_ieee802154_cmd_realign */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_ieee802154_cmd_gtsrq
 *  DESCRIPTION
 *      Command subdissector routine for the GTS request command.
 *
 *      Assumes that COL_INFO will be set to the command name,
 *      command name will already be appended to the command subtree
 *      and protocol root. In addition, assumes that the command ID
 *      has already been parsed.
 *  PARAMETERS
 *      tvbuff_t    *tvb            - pointer to buffer containing raw packet.
 *      packet_info *pinfo          - pointer to packet information fields (unused).
 *      proto_tree  *tree           - pointer to command subtree.
 *      ieee802154_packet *packet   - IEEE 802.15.4 packet information (unused).
 *      guint       *offset         - offset into the tvbuff to begin dissection.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_ieee802154_cmd_gtsrq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, ieee802154_packet *packet _U_, guint *offset)
{
    proto_item  *ti;

    guint8  characteristics;
    guint8  length;
    guint8  direction;
    guint8  type;

    /* Get the characteristics field. */
    characteristics = tvb_get_guint8(tvb, *offset);
    length = characteristics & IEEE802154_CMD_GTS_REQ_LEN;
    direction = characteristics & IEEE802154_CMD_GTS_REQ_DIR;
    type = characteristics & IEEE802154_CMD_GTS_REQ_TYPE;

    /* Display the characteristics field. */
    if (tree) {
        proto_tree_add_uint(tree, hf_ieee802154_cmd_gts_req_len, tvb, *offset, sizeof(guint8), length);
        ti = proto_tree_add_boolean(tree, hf_ieee802154_cmd_gts_req_dir, tvb, *offset, sizeof(guint8), direction);
        if (direction) proto_item_append_text(ti, " (Receive)");
        else proto_item_append_text(ti, " (Transmit)");
        ti = proto_tree_add_boolean(tree, hf_ieee802154_cmd_gts_req_type, tvb, *offset, sizeof(guint8), type);
        if (type) proto_item_append_text(ti, " (Allocate GTS)");
        else proto_item_append_text(ti, " (Deallocate GTS)");
    }

    /* Adjust offset */
    (*offset) += sizeof(guint8);
} /* dissect_ieee802154_cmd_gtsrq */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_ieee802154
 *  DESCRIPTION
 *      IEEE 802.15.4 protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_register_ieee802154(void)
{
    static hf_register_info hf[] = {
        { &hf_ieee802154_frame_type,
        { "Frame Type",                     "wpan.frame_type", FT_UINT16, BASE_HEX, VALS(ieee802154_frame_types), IEEE802154_FCF_TYPE_MASK,
            "", HFILL }},

        { &hf_ieee802154_security,
        { "Security Enabled",               "wpan.security", FT_BOOLEAN, 16, NULL, IEEE802154_FCF_SEC_EN,
            "Whether security operations are performed at the MAC layer or not.", HFILL }},

        { &hf_ieee802154_pending,
        { "Frame Pending",                  "wpan.pending", FT_BOOLEAN, 16, NULL, IEEE802154_FCF_FRAME_PND,
            "Indication of additional packets waiting to be transferred from the source device.", HFILL }},

        { &hf_ieee802154_ack_request,
        { "Acknowledge Request",            "wpan.ack_request", FT_BOOLEAN, 16, NULL, IEEE802154_FCF_ACK_REQ,
            "Whether the sender of this packet requests acknowledgement or not.", HFILL }},

        { &hf_ieee802154_intra_pan,
        { "Intra-PAN",                      "wpan.intra_pan", FT_BOOLEAN, 16, NULL, IEEE802154_FCF_INTRA_PAN,
            "Whether this packet originated and terminated within the same PAN or not.", HFILL }},

        { &hf_ieee802154_seqno,
        { "Sequence Number",                "wpan.seq_no", FT_UINT8, BASE_DEC, NULL, 0x0,
            "", HFILL }},

        { &hf_ieee802154_dst_addr_mode,
        { "Destination Addressing Mode",    "wpan.dst_addr_mode", FT_UINT16, BASE_HEX, VALS(ieee802154_addr_modes), IEEE802154_FCF_DADDR_MASK,
            "", HFILL }},

        { &hf_ieee802154_src_addr_mode,
        { "Source Addressing Mode",         "wpan.src_addr_mode", FT_UINT16, BASE_HEX, VALS(ieee802154_addr_modes), IEEE802154_FCF_SADDR_MASK,
            "", HFILL }},

        { &hf_ieee802154_version,
        { "Frame Version",                  "wpan.version", FT_UINT16, BASE_DEC, NULL, IEEE802154_FCF_VERSION,
            "", HFILL }},

        { &hf_ieee802154_dst_pan,
        { "Destination PAN",                "wpan.dst_pan", FT_UINT16, BASE_HEX, NULL, 0x0,
            "", HFILL }},

        { &hf_ieee802154_dst_addr16,
        { "Destination",                    "wpan.dst_addr16", FT_UINT16, BASE_HEX, NULL, 0x0,
            "", HFILL }},

        { &hf_ieee802154_dst_addr64,
        { "Destination",                    "wpan.dst_addr64", FT_UINT64, BASE_HEX, NULL, 0x0,
            "", HFILL }},

        { &hf_ieee802154_src_panID,
        { "Source PAN",                     "wpan.src_pan", FT_UINT16, BASE_HEX, NULL, 0x0,
            "", HFILL }},

        { &hf_ieee802154_src_addr16,
        { "Source",                         "wpan.src_addr16", FT_UINT16, BASE_HEX, NULL, 0x0,
            "", HFILL }},

        { &hf_ieee802154_src_addr64,
        { "Source",                         "wpan.src_addr64", FT_UINT64, BASE_HEX, NULL, 0x0,
            "", HFILL }},

        { &hf_ieee802154_fcs,
        { "FCS",                            "wpan.fcs", FT_UINT16, BASE_HEX, NULL, 0x0,
            "", HFILL }},

        { &hf_ieee802154_rssi,
        { "RSSI",                           "wpan.rssi", FT_INT8, BASE_DEC, NULL, 0x0,
            "Received Signal Strength", HFILL }},

        { &hf_ieee802154_fcs_ok,
        { "FCS Valid",                      "wpan.fcs_ok", FT_BOOLEAN, 8, NULL, 0x0,
            "", HFILL }},

        { &hf_ieee802154_correlation,
        { "LQI Correlation Value",          "wpan.correlation", FT_UINT8, BASE_DEC, NULL, 0x0,
            "", HFILL }},

            /*  Command Frame Specific Fields */
            /*--------------------------------*/

        { &hf_ieee802154_cmd_id,
        { "Command Identifier",         "wpan.cmd.id", FT_UINT8, BASE_HEX, VALS(ieee802154_cmd_names), 0x0,
            "", HFILL }},

            /*  Capability Information Fields */
        { &hf_ieee802154_cmd_cinfo_alt_coord,
        { "Alternate PAN Coordinator",  "wpan.cmd.cinfo.alt_coord", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_ALT_PAN_COORD,
            "Whether this device can act as a PAN coordinator or not.", HFILL }},

        { &hf_ieee802154_cmd_cinfo_device_type,
        { "Device Type",                "wpan.cmd.cinfo.device_type", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_DEVICE_TYPE,
            "Whether this device is RFD (reduced-function device) or FFD (full-function device).", HFILL }},

        { &hf_ieee802154_cmd_cinfo_power_src,
        { "Power Source",               "wpan.cmd.cinfo.power_src", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_POWER_SRC,
            "Whether this device is operating on AC/mains or battery power.", HFILL }},

        { &hf_ieee802154_cmd_cinfo_idle_rx,
        { "Receive On When Idle",       "wpan.cmd.cinfo.idle_rx", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_IDLE_RX,
            "Whether this device can receive packets while idle or not.", HFILL }},

        { &hf_ieee802154_cmd_cinfo_sec_capable,
        { "Security Capability",        "wpan.cmd.cinfo.sec_capable", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_SEC_CAPABLE,
            "Whether this device is capable of receiving encrypted packets.", HFILL }},

        { &hf_ieee802154_cmd_cinfo_alloc_addr,
        { "Allocate Address",           "wpan.cmd.cinfo.alloc_addr", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_ALLOC_ADDR,
            "Whether this device wishes to use a 16-bit short address instead of its IEEE 802.15.4 64-bit long address.", HFILL }},

            /*  Association response fields */
        { &hf_ieee802154_cmd_asrsp_addr,
        { "Short Address",              "wpan.cmd.asrsp.addr", FT_UINT16, BASE_HEX, NULL, 0x0,
            "The short address that the device should assume. An address of 0xfffe indicates that the device should use its IEEE 64-bit long address.", HFILL }},

        { &hf_ieee802154_cmd_asrsp_status,
        { "Association Status",         "wpan.cmd.asrsp.status", FT_UINT8, BASE_HEX, NULL, 0x0,
            "", HFILL }},

        { &hf_ieee802154_cmd_disas_reason,
        { "Disassociation Reason",      "wpan.cmd.disas.reason", FT_UINT8, BASE_HEX, NULL, 0x0,
            "", HFILL }},

            /*  Coordinator Realignment fields */
        { &hf_ieee802154_cmd_coord_pan,
        { "PAN ID",                     "wpan.cmd.coord.pan", FT_UINT16, BASE_HEX, NULL, 0x0,
            "The PAN identifier the coordinator wishes to use for future communication.", HFILL }},

        { &hf_ieee802154_cmd_coord_caddr,
        { "Coordinator Short Address",  "wpan.cmd.coord.addr", FT_UINT16, BASE_HEX, NULL, 0x0,
            "The 16-bit address the coordinator wishes to use for future communication.", HFILL }},

        { &hf_ieee802154_cmd_coord_channel,
        { "Logical Channel",            "wpan.cmd.coord.channel", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The logical channel the coordinator wishes to use for future communication.", HFILL }},

        { &hf_ieee802154_cmd_coord_addr,
        { "Short Address",              "wpan.cmd.coord.addr", FT_UINT16, BASE_HEX, NULL, 0x0,
            "A short-address that the orphaned device shall assume if applicable.", HFILL }},

        { &hf_ieee802154_cmd_coord_channel_page,
        { "Channel Page",               "wpan.cmd.coord.channel_page", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The logical channel page the coordinator wishes to use for future communication.", HFILL }},

        { &hf_ieee802154_cmd_gts_req_len,
        { "GTS Length",                 "wpan.cmd.gts.length", FT_UINT8, BASE_DEC, NULL, IEEE802154_CMD_GTS_REQ_LEN,
            "Number of superframe slots the device is requesting.", HFILL }},

        { &hf_ieee802154_cmd_gts_req_dir,
        { "GTS Direction",              "wpan.cmd.gts.direction", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_GTS_REQ_DIR,
            "The direction of traffic in the guaranteed timeslot.", HFILL }},

        { &hf_ieee802154_cmd_gts_req_type,
        { "Characteristic Type",        "wpan.cmd.gts.type", FT_BOOLEAN, 8, NULL, IEEE802154_CMD_GTS_REQ_TYPE,
            "Whether this request is to allocate or deallocate a timeslot.", HFILL }},

            /*  Beacon Frame Specific Fields */
            /*-------------------------------*/
        { &hf_ieee802154_bcn_beacon_order,
        { "Beacon Interval",            "wpan.bcn.beacon_order", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Specifies the transmission interval of the beacons.", HFILL }},

        { &hf_ieee802154_bcn_superframe_order,
        { "Superframe Interval",        "wpan.bcn.superframe_order", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Specifies the length of time the coordinator will interact with the PAN.", HFILL }},

        { &hf_ieee802154_bcn_cap,
        { "Final CAP Slot",             "wpan.bcn.cap", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Specifies the final superframe slot used by the CAP.", HFILL }},

        { &hf_ieee802154_bcn_battery_ext,
        { "Battery Extension",          "wpan.bcn.battery_ext", FT_BOOLEAN, 8, NULL, IEEE802154_BCN_BATT_EXTN_MASK,
            "Whether transmissions may not extend past the length of the beacon frame.", HFILL }},

        { &hf_ieee802154_bcn_coord,
        { "PAN Coordinator",            "wpan.bcn.coord", FT_BOOLEAN, 8, NULL, IEEE802154_BCN_COORD_MASK,
            "Whether this beacon frame is being transmitted by the PAN coordinator or not.", HFILL }},

        { &hf_ieee802154_bcn_assoc_permit,
        { "Association Permit",         "wpan.bcn.assoc_permit", FT_BOOLEAN, 8, NULL, IEEE802154_BCN_ASSOC_PERM_MASK,
            "Whether this PAN is accepting association requests or not.", HFILL }},

        { &hf_ieee802154_bcn_gts_count,
        { "GTS Descriptor Count",       "wpan.bcn.gts.count", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The number of GTS descriptors present in this beacon frame.", HFILL }},

        { &hf_ieee802154_bcn_gts_permit,
        { "GTS Permit",                 "wpan.bcn.gts.permit", FT_BOOLEAN, 8, NULL, 0x0,
            "Whether the PAN coordinator is accepting GTS requests or not.", HFILL }},

        { &hf_ieee802154_bcn_gts_direction,
        { "Direction",                  "wpan.bcn.gts.direction", FT_BOOLEAN, 8, NULL, 0x0,
            "A flag defining the direction of the GTS Slot.", HFILL }},

        { &hf_ieee802154_bcn_pending16,
        { "Address",                    "wpan.bcn.pending16", FT_UINT16, BASE_HEX, NULL, 0x0,
            "Device with pending data to receive.", HFILL }},

        { &hf_ieee802154_bcn_pending64,
        { "Address",                    "wpan.bcn.pending64", FT_UINT64, BASE_HEX, NULL, 0x0,
            "Device with pending data to receive.", HFILL }}
    };

    static gint *ett[] = {
        &ett_ieee802154,
        &ett_ieee802154_fcf,
        &ett_ieee802154_fcs,
        &ett_ieee802154_cmd,
        &ett_ieee802154_cmd_cinfo,
        &ett_ieee802154_bcn,
        &ett_ieee802154_bcn_superframe_spec,
        &ett_ieee802154_bcn_gts_spec,
        &ett_ieee802154_bcn_gts_direction,
        &ett_ieee802154_bcn_gts_descriptors,
        &ett_ieee802154_bcn_pending
    };

    /*  Register Protocol name and description. */
    proto_ieee802154 = proto_register_protocol("IEEE 802.15.4 Low-Rate Wireless PAN", "IEEE 802.15.4", "wpan");

    /*  Register header fields and subtrees. */
    proto_register_field_array(proto_ieee802154, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the subdissector list */
    register_heur_dissector_list("wpan", &ieee802154_heur_subdissector_list);

    /*  Register dissectors with Ethereal. */
    register_dissector("wpan", dissect_ieee802154, proto_ieee802154);
    register_dissector("wpan_nofcs", dissect_ieee802154_nofcs, proto_ieee802154);
    register_dissector("wpan_cc24xx", dissect_ieee802154_cc24xx, proto_ieee802154);
} /* proto_register_ieee802154 */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_ieee802154
 *  DESCRIPTION
 *      Registers the zigbee dissector with Wireshark.
 *      Will be called every time 'apply' is pressed in the preferences menu.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_reg_handoff_ieee802154(void)
{
    dissector_handle_t  ieee802154_handle;

    /* Get the dissector handles. */
    ieee802154_handle   = find_dissector("wpan");
    data_handle         = find_dissector("data");

    /* Register dissector handles. */
    dissector_add("wtap_encap", WTAP_ENCAP_IEEE802_15_4, ieee802154_handle);
} /* proto_reg_handoff_ieee802154 */

