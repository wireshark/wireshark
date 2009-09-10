/* packet-ieee802154.h
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
 */
#ifndef PACKET_IEEE802154_H
#define PACKET_IEEE802154_H

/*  Packet Overhead from MAC header + footer (excluding addressing) */
#define IEEE802154_MAX_FRAME_LEN            127
#define IEEE802154_FCS_LEN                  2

/*  Command Frame Identifier Types Definions */
#define IEEE802154_CMD_ASRQ                 0x01
#define IEEE802154_CMD_ASRSP                0x02
#define IEEE802154_CMD_DISAS                0x03
#define IEEE802154_CMD_DATA_RQ              0x04
#define IEEE802154_CMD_PANID_ERR            0x05
#define IEEE802154_CMD_ORPH_NOTIF           0x06
#define IEEE802154_CMD_BCN_RQ               0x07
#define IEEE802154_CMD_COORD_REAL           0x08
#define IEEE802154_CMD_GTS_REQ              0x09
#define IEEE802145_CMD_MAX_ID               0x09

/*  Definitions for Association Response Command */
#define IEEE802154_CMD_ASRSP_AS_SUCCESS     0x00
#define IEEE802154_CMD_ASRSP_PAN_FULL       0x01
#define IEEE802154_CMD_ASRSP_PAN_DENIED     0x02

/*  Bit Masks for Capability Information Feild
    Included in Association Req. command    */
#define IEEE802154_CMD_CINFO_ALT_PAN_COORD  0x01
#define IEEE802154_CMD_CINFO_DEVICE_TYPE    0x02
#define IEEE802154_CMD_CINFO_POWER_SRC      0x04
#define IEEE802154_CMD_CINFO_IDLE_RX        0x08
#define IEEE802154_CMD_CINFO_SEC_CAPABLE    0x40
#define IEEE802154_CMD_CINFO_ALLOC_ADDR     0x80

#define IEEE802154_CMD_GTS_REQ_LEN          0x0F
#define IEEE802154_CMD_GTS_REQ_DIR          0x10
#define IEEE802154_CMD_GTS_REQ_TYPE         0x20

/*  Bit masks & shifts for various beacon fields */
#define IEEE802154_BCN_BO_MASK              0x0F
#define IEEE802154_BCN_SFO_MASK             0xF0
#define IEEE802154_BCN_CAP_MASK             0x0F
#define IEEE802154_BCN_BATT_EXTN_MASK       0x10
#define IEEE802154_BCN_COORD_MASK           0x40
#define IEEE802154_BCN_ASSOC_PERM_MASK      0x80
#define IEEE802154_BCN_SFO_SHIFT            4

#define IEEE802154_BCN_GTS_COUNT_MASK           0x03
#define IEEE802154_BCN_GTS_PERMIT_MASK          0x80
#define IEEE802154_BCN_GTS_DIRECTION_SLOT(i)    (0x01<<(i))
#define IEEE802154_BCN_GTS_MAX_SLOTS            7
#define IEEE802154_BCN_GTS_DIRECTION_SLOT1      0x01
#define IEEE802154_BCN_GTS_DIRECTION_SLOT2      0x02
#define IEEE802154_BCN_GTS_DIRECTION_SLOT3      0x04
#define IEEE802154_BCN_GTS_DIRECTION_SLOT4      0x08
#define IEEE802154_BCN_GTS_DIRECTION_SLOT5      0x10
#define IEEE802154_BCN_GTS_DIRECTION_SLOT6      0x20
#define IEEE802154_BCN_GTS_DIRECTION_SLOT7      0x40
#define IEEE802154_BCN_GTS_SLOT_MASK            0x0F
#define IEEE802154_BCN_GTS_LENGTH_MASK          0xF0
#define IEEE802154_BCN_GTS_LENGTH_SHIFT         4

#define IEEE802154_BCN_PADDR_SHORT_MASK     0x07
#define IEEE802154_BCN_PADDR_LONG_MASK      0x70
#define IEEE802154_BCN_PADDR_LONG_SHIFT     4

#define IEEE802154_BCN_SFRM_DURATION        (IEEE802154_BCN_SLOT_DURATION * IEEE802154_BCN_NUM_SLOTS)
#define IEEE802154_BCN_SLOT_DURATION        60
#define IEEE802154_BCN_NUM_SLOTS            16

/*  Bit-masks for the FCF */
#define IEEE802154_FCF_TYPE_MASK            0x0007  /* Frame Type Mask */
#define IEEE802154_FCF_SEC_EN               0x0008
#define IEEE802154_FCF_FRAME_PND            0x0010
#define IEEE802154_FCF_ACK_REQ              0x0020
#define IEEE802154_FCF_INTRA_PAN            0x0040
#define IEEE802154_FCF_DADDR_MASK           0x0C00  /* destination addressing mask */
#define IEEE802154_FCF_VERSION              0x3000
#define IEEE802154_FCF_SADDR_MASK           0xC000  /* source addressing mask */

/* Frame Type Definitions */
#define IEEE802154_FCF_BEACON               0x0000  /* Beacon Frame */
#define IEEE802154_FCF_DATA                 0x0001  /* Data Frame */
#define IEEE802154_FCF_ACK                  0x0002  /* Acknowlegement Frame */
#define IEEE802154_FCF_CMD                  0x0003  /* Command Frame */

/* Address Mode Definitions */
#define IEEE802154_FCF_ADDR_NONE            0x0000
#define IEEE802154_FCF_ADDR_SHORT           0x0002
#define IEEE802154_FCF_ADDR_EXT             0x0003

/*  Bit-masks for CC24xx style FCS */
#define IEEE802154_CC24xx_CORRELATION       0x7F00
#define IEEE802154_CC24xx_CRC_OK            0x8000
#define IEEE802154_CC24xx_RSSI              0x00FF

/*  Special IEEE802.15.4 Addresses */
#define IEEE802154_NO_ADDR16                0xFFFE
#define IEEE802154_BCAST_ADDR               0xFFFF
#define IEEE802154_BCAST_PAN                0xFFFF

/*  Bit mask for PHY length field */
#define IEEE802154_PHY_LENGTH_MASK          0x7f

/*  Structure containing information regarding all necessary packet feilds. */
typedef struct {
    /* Frame control field. */
    gint32      version;
    gint32      frame_type;
    gint32      dst_addr_mode;
    gint32      src_addr_mode;
    gboolean    security_enable;
    gboolean    frame_pending;
    gboolean    ack_request;
    gboolean    intra_pan;

    guint8      seqno;

    /* Addressing Info. */
    guint16     dst_pan;
    union {
        guint16 addr16;
        guint64 addr64;
    } dst;
    guint16     src_pan;
    union {
        guint16 addr16;
        guint64 addr64;
    } src;
} ieee802154_packet;


/* Some Helper Function Definitions. */
extern guint    get_by_mask(guint, guint);
extern gchar    *print_eui64(guint64);
extern gchar    *print_eui64_oui(guint64);

#endif /* PACKET_IEEE802154_H */
