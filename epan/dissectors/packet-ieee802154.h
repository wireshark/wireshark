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

/* Protocol Abbreviation */
#define IEEE802154_PROTOABBREV_WPAN     "wpan"

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

/*  Bit Masks for Capability Information Field
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
#define IEEE802154_BEACON_ORDER_MASK        0x000F
#define IEEE802154_SUPERFRAME_ORDER_MASK    0x00F0
#define IEEE802154_SUPERFRAME_CAP_MASK      0x0F00
#define IEEE802154_BATT_EXTENSION_MASK      0x1000
#define IEEE802154_SUPERFRAME_COORD_MASK    0x4000
#define IEEE802154_ASSOC_PERMIT_MASK        0x8000
#define IEEE802154_SUPERFRAME_ORDER_SHIFT   4
#define IEEE802154_SUPERFRAME_CAP_SHIFT     8

#define IEEE802154_GTS_COUNT_MASK           0x03
#define IEEE802154_GTS_PERMIT_MASK          0x80
#define IEEE802154_GTS_DIRECTION_SLOT(i)    (0x01<<(i))
#define IEEE802154_GTS_MAX_SLOTS            7
#define IEEE802154_GTS_DIRECTION_SLOT1      0x01
#define IEEE802154_GTS_DIRECTION_SLOT2      0x02
#define IEEE802154_GTS_DIRECTION_SLOT3      0x04
#define IEEE802154_GTS_DIRECTION_SLOT4      0x08
#define IEEE802154_GTS_DIRECTION_SLOT5      0x10
#define IEEE802154_GTS_DIRECTION_SLOT6      0x20
#define IEEE802154_GTS_DIRECTION_SLOT7      0x40
#define IEEE802154_GTS_SLOT_MASK            0x0F
#define IEEE802154_GTS_LENGTH_MASK          0xF0
#define IEEE802154_GTS_LENGTH_SHIFT         4

#define IEEE802154_PENDADDR_SHORT_MASK      0x07
#define IEEE802154_PENDADDR_LONG_MASK       0x70
#define IEEE802154_PENDADDR_LONG_SHIFT      4

#define IEEE802154_SUPERFRAME_DURATION      (IEEE802154_BASE_SLOT_DURATION * IEEE802154_SUPERFRAME_SLOTS)
#define IEEE802154_BASE_SLOT_DURATION       60
#define IEEE802154_SUPERFRAME_SLOTS         16

/*  Bit-masks for the FCF */
#define IEEE802154_FCF_TYPE_MASK            0x0007  /* Frame Type Mask */
#define IEEE802154_FCF_SEC_EN               0x0008
#define IEEE802154_FCF_FRAME_PND            0x0010
#define IEEE802154_FCF_ACK_REQ              0x0020
#define IEEE802154_FCF_INTRA_PAN            0x0040  /* known as PAN ID Compression in IEEE 802.15.4-2006 */
#define IEEE802154_FCF_DADDR_MASK           0x0C00  /* destination addressing mask */
#define IEEE802154_FCF_VERSION              0x3000
#define IEEE802154_FCF_SADDR_MASK           0xC000  /* source addressing mask */

/* Frame Type Definitions */
#define IEEE802154_FCF_BEACON               0x0000  /* Beacon Frame */
#define IEEE802154_FCF_DATA                 0x0001  /* Data Frame */
#define IEEE802154_FCF_ACK                  0x0002  /* Acknowlegement Frame */
#define IEEE802154_FCF_CMD                  0x0003  /* Command Frame */

/* Frame version definitions. */
#define IEEE802154_VERSION_2003             0x0
#define IEEE802154_VERSION_2006             0x1

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

/* Auxiliary Security Header */
#define IEEE802154_AUX_SEC_LEVEL_MASK       0x07  /* Security Level */
#define IEEE802154_AUX_KEY_ID_MODE_MASK     0x18  /* Key Identifier Mode */
#define IEEE802154_AUX_KEY_ID_MODE_SHIFT    3
#define IEEE802154_AUX_KEY_RESERVED_MASK    0xE0  /* Reserved */

typedef enum {
    SECURITY_LEVEL_NONE = 0x00,
    SECURITY_LEVEL_MIC_32 = 0x01,
    SECURITY_LEVEL_MIC_64 = 0x02,
    SECURITY_LEVEL_MIC_128 = 0x03,
    SECURITY_LEVEL_ENC = 0x04,
    SECURITY_LEVEL_ENC_MIC_32 = 0x05,
    SECURITY_LEVEL_ENC_MIC_64 = 0x06,
    SECURITY_LEVEL_ENC_MIC_128 = 0x07
} ieee802154_security_level;

typedef enum {
    KEY_ID_MODE_IMPLICIT = 0x00,
    KEY_ID_MODE_KEY_INDEX = 0x01,
    KEY_ID_MODE_KEY_EXPLICIT_4 = 0x02,
    KEY_ID_MODE_KEY_EXPLICIT_8 = 0x03
} ieee802154_key_id_mode;

/* IEEE 802.15.4 cipher block size. */
#define IEEE802154_CIPHER_SIZE              16

/* Macro to compute the MIC length. */
#define IEEE802154_MIC_LENGTH(_level_) ((0x2 << ((_level_) & 0x3)) & ~0x3)
/* Macro to check for payload encryption. */
#define IEEE802154_IS_ENCRYPTED(_level_) ((_level_) & 0x4)

/*  Structure containing information regarding all necessary packet fields. */
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
    guint16     src_pan;
    guint16     dst16;
    guint64     dst64;
    guint16     src16;
    guint64     src64;

    /* Security Info. */
    ieee802154_security_level   security_level;
    ieee802154_key_id_mode      key_id_mode;
    guint32     frame_counter;
    union {
        guint32 addr32;
        guint64 addr64;
    } key_source;
    guint8      key_index;

    /* Command ID (only if frame_type == 0x3) */
    guint8      command_id;
    GHashTable *short_table;
} ieee802154_packet;

/* Structure for two-way mapping table */
typedef struct {
    GHashTable *long_table;
    GHashTable *short_table;
} ieee802154_map_tab_t;

/* Key used by the short address hash table. */
typedef struct {
    guint16     pan;
    guint16     addr;
} ieee802154_short_addr;

/* Key used by the long address hash table. */
typedef struct {
    guint64     addr;
} ieee802154_long_addr;

/* A mapping record for a frame, pointed to by hash table */
typedef struct {
    const char *proto; /* name of protocol that created this record */
    guint       start_fnum;
    guint       end_fnum;
    guint64     addr64;
    /*guint32   frame_counter;   TODO for frame counter sequence checks. */
} ieee802154_map_rec;

#define IEEE802154_USER_MAPPING 0

typedef struct {
    guint16             src_pan;
    guint16             src16;
    ieee802154_map_rec *map_rec;
} ieee802154_hints_t;

/* Short to Extended Address Prototypes */
extern ieee802154_map_rec *ieee802154_addr_update(ieee802154_map_tab_t *, guint16, guint16, guint64,
        const char *, guint);
extern guint    ieee802154_short_addr_hash(gconstpointer);
extern guint    ieee802154_long_addr_hash(gconstpointer key);
extern gboolean ieee802154_short_addr_equal(gconstpointer, gconstpointer);
extern gboolean ieee802154_long_addr_equal(gconstpointer a, gconstpointer b);

extern gboolean ieee802154_short_addr_invalidate(guint16, guint16, guint);
extern gboolean ieee802154_long_addr_invalidate(guint64, guint);

#endif /* PACKET_IEEE802154_H */
