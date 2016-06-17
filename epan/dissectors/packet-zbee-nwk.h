/* packet-zbee-nwk.h
 * Dissector routines for the ZigBee Network Layer (NWK)
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
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
#ifndef PACKET_ZBEE_NWK_H
#define PACKET_ZBEE_NWK_H

/*  ZigBee NWK FCF fields */
#define ZBEE_NWK_FCF_FRAME_TYPE             0x0003
#define ZBEE_NWK_FCF_VERSION                0x003C
#define ZBEE_NWK_FCF_DISCOVER_ROUTE         0x00C0
#define ZBEE_NWK_FCF_MULTICAST              0x0100  /* ZigBee 2006 and Later */
#define ZBEE_NWK_FCF_SECURITY               0x0200
#define ZBEE_NWK_FCF_SOURCE_ROUTE           0x0400  /* ZigBee 2006 and Later */
#define ZBEE_NWK_FCF_EXT_DEST               0x0800  /* ZigBee 2006 and Later */
#define ZBEE_NWK_FCF_EXT_SOURCE             0x1000  /* ZigBee 2006 and Later */
#define ZBEE_NWK_FCF_END_DEVICE_INITIATOR   0x2000  /* ZigBee PRO r21 */

/*  ZigBee NWK FCF Frame Types */
#define ZBEE_NWK_FCF_DATA                   0x0000
#define ZBEE_NWK_FCF_CMD                    0x0001
#define ZBEE_NWK_FCF_INTERPAN               0x0003

/* ZigBee NWK Discovery Modes. */
#define ZBEE_NWK_FCF_DISCOVERY_SUPPRESS     0x0000
#define ZBEE_NWK_FCF_DISCOVERY_ENABLE       0x0001
#define ZBEE_NWK_FCF_DISCOVERY_FORCE        0x0003

/* Multicast Control */
#define ZBEE_NWK_MCAST_MODE                 0x03    /* ZigBee 2006 and later */
#define ZBEE_NWK_MCAST_RADIUS               0x1c    /* ZigBee 2006 and later */
#define ZBEE_NWK_MCAST_MAX_RADIUS           0xe0    /* ZigBee 2006 and later */
#define ZBEE_NWK_MCAST_MODE_NONMEMBER       0x00    /* ZigBee 2006 and later */
#define ZBEE_NWK_MCAST_MODE_MEMBER          0x01    /* ZigBee 2006 and later */

/*  ZigBee NWK Command Types */
#define ZBEE_NWK_CMD_ROUTE_REQ                  0x01
#define ZBEE_NWK_CMD_ROUTE_REPLY                0x02
#define ZBEE_NWK_CMD_NWK_STATUS                 0x03
#define ZBEE_NWK_CMD_LEAVE                      0x04    /* ZigBee 2006 and Later */
#define ZBEE_NWK_CMD_ROUTE_RECORD               0x05    /* ZigBee 2006 and later */
#define ZBEE_NWK_CMD_REJOIN_REQ                 0x06    /* ZigBee 2006 and later */
#define ZBEE_NWK_CMD_REJOIN_RESP                0x07    /* ZigBee 2006 and later */
#define ZBEE_NWK_CMD_LINK_STATUS                0x08    /* ZigBee 2007 and later */
#define ZBEE_NWK_CMD_NWK_REPORT                 0x09    /* ZigBee 2007 and later */
#define ZBEE_NWK_CMD_NWK_UPDATE                 0x0a    /* ZigBee 2007 and later */
#define ZBEE_NWK_CMD_ED_TIMEOUT_REQUEST         0x0b    /* r21 */
#define ZBEE_NWK_CMD_ED_TIMEOUT_RESPONSE        0x0c    /* r21 */
#define ZBEE_NWK_CMD_LINK_PWR_DELTA             0x0d    /* r22 */

/*  ZigBee NWK Route Options Flags */
#define ZBEE_NWK_CMD_ROUTE_OPTION_REPAIR        0x80    /* ZigBee 2004 only. */
#define ZBEE_NWK_CMD_ROUTE_OPTION_MCAST         0x40    /* ZigBee 2006 and later */
#define ZBEE_NWK_CMD_ROUTE_OPTION_DEST_EXT      0x20    /* ZigBee 2007 and later (route request only). */
#define ZBEE_NWK_CMD_ROUTE_OPTION_MANY_MASK     0x18    /* ZigBee 2007 and later (route request only). */
#define ZBEE_NWK_CMD_ROUTE_OPTION_RESP_EXT      0x20    /* ZigBee 2007 and layer (route reply only). */
#define ZBEE_NWK_CMD_ROUTE_OPTION_ORIG_EXT      0x10    /* ZigBee 2007 and later (route reply only). */

/* Many-to-One modes, ZigBee 2007 and later (route request only). */
#define ZBEE_NWK_CMD_ROUTE_OPTION_MANY_NONE     0x00
#define ZBEE_NWK_CMD_ROUTE_OPTION_MANY_REC      0x01
#define ZBEE_NWK_CMD_ROUTE_OPTION_MANY_NOREC    0x02

/*  ZigBee NWK Leave Options Flags */
#define ZBEE_NWK_CMD_LEAVE_OPTION_CHILDREN      0x80
#define ZBEE_NWK_CMD_LEAVE_OPTION_REQUEST       0x40
#define ZBEE_NWK_CMD_LEAVE_OPTION_REJOIN        0x20

/* ZigBee NWK Link Status Options. */
#define ZBEE_NWK_CMD_LINK_OPTION_LAST_FRAME     0x40
#define ZBEE_NWK_CMD_LINK_OPTION_FIRST_FRAME    0x20
#define ZBEE_NWK_CMD_LINK_OPTION_COUNT_MASK     0x1f

/* ZigBee NWK Link Status cost fields. */
#define ZBEE_NWK_CMD_LINK_INCOMMING_COST_MASK   0x07
#define ZBEE_NWK_CMD_LINK_OUTGOING_COST_MASK    0x70

/* ZigBee NWK Report Options. */
#define ZBEE_NWK_CMD_NWK_REPORT_COUNT_MASK      0x1f
#define ZBEE_NWK_CMD_NWK_REPORT_ID_MASK         0xe0
#define ZBEE_NWK_CMD_NWK_REPORT_ID_PAN_CONFLICT 0x00

/* ZigBee NWK Update Options. */
#define ZBEE_NWK_CMD_NWK_UPDATE_COUNT_MASK      0x1f
#define ZBEE_NWK_CMD_NWK_UPDATE_ID_MASK         0xe0
#define ZBEE_NWK_CMD_NWK_UPDATE_ID_PAN_UPDATE   0x00

/* ZigBee NWK Values of the Parent Information Bitmask (Table 3.47) */
#define ZBEE_NWK_CMD_ED_TIMEO_RSP_PRNT_INFO_MAC_DATA_POLL_KEEPAL_SUPP  0x01
#define ZBEE_NWK_CMD_ED_TIMEO_RSP_PRNT_INFO_ED_TIMOU_REQ_KEEPAL_SUPP   0x02
#define ZBEE_NWK_CMD_ED_TIMEO_RSP_PRNT_INFO_PWR_NEG_SUPP               0x04

/* ZigBee NWK Link Power Delta Options */
#define ZBEE_NWK_CMD_NWK_LINK_PWR_DELTA_TYPE_MASK   0x03

/* Network Status Code Definitions. */
#define ZBEE_NWK_STATUS_NO_ROUTE_AVAIL      0x00
#define ZBEE_NWK_STATUS_TREE_LINK_FAIL      0x01
#define ZBEE_NWK_STATUS_NON_TREE_LINK_FAIL  0x02
#define ZBEE_NWK_STATUS_LOW_BATTERY         0x03
#define ZBEE_NWK_STATUS_NO_ROUTING          0x04
#define ZBEE_NWK_STATUS_NO_INDIRECT         0x05
#define ZBEE_NWK_STATUS_INDIRECT_EXPIRE     0x06
#define ZBEE_NWK_STATUS_DEVICE_UNAVAIL      0x07
#define ZBEE_NWK_STATUS_ADDR_UNAVAIL        0x08
#define ZBEE_NWK_STATUS_PARENT_LINK_FAIL    0x09
#define ZBEE_NWK_STATUS_VALIDATE_ROUTE      0x0a
#define ZBEE_NWK_STATUS_SOURCE_ROUTE_FAIL   0x0b
#define ZBEE_NWK_STATUS_MANY_TO_ONE_FAIL    0x0c
#define ZBEE_NWK_STATUS_ADDRESS_CONFLICT    0x0d
#define ZBEE_NWK_STATUS_VERIFY_ADDRESS      0x0e
#define ZBEE_NWK_STATUS_PANID_UPDATE        0x0f
#define ZBEE_NWK_STATUS_ADDRESS_UPDATE      0x10
#define ZBEE_NWK_STATUS_BAD_FRAME_COUNTER   0x11
#define ZBEE_NWK_STATUS_BAD_KEY_SEQNO       0x12
#define ZBEE_NWK_STATUS_UNKNOWN_COMMAND     0x13

#define ZBEE_SEC_CONST_KEYSIZE              16

typedef struct{
    gboolean    security;
    gboolean    discovery;
    gboolean    multicast;          /* ZigBee 2006 and Later */
    gboolean    route;              /* ZigBee 2006 and Later */
    gboolean    ext_dst;            /* ZigBee 2006 and Later */
    gboolean    ext_src;            /* ZigBee 2006 and Later */
    guint16     type;
    guint8      version;

    guint16     dst;
    guint16     src;
    guint64     dst64;              /* ZigBee 2006 and Later */
    guint64     src64;              /* ZigBee 2006 and Later */
    guint8      radius;
    guint8      seqno;

    guint8      mcast_mode;         /* ZigBee 2006 and Later */
    guint8      mcast_radius;       /* ZigBee 2006 and Later */
    guint8      mcast_max_radius;   /* ZigBee 2006 and Later */

    guint8      payload_offset;
    guint8      payload_len;

    guint16     cluster_id;     /* an application-specific message identifier that
                                 * happens to be included in the transport (APS) layer header.
                                 */

    void        *private_data;  /* For ZigBee (sub)dissector specific data */
} zbee_nwk_packet;

/* Key used for link key hash table. */
typedef struct {
    guint64     lt_addr64; /* lesser than address */
    guint64     gt_addr64; /* greater than address */
} table_link_key_t;

/* Values in the key rings. */
typedef struct {
    guint       frame_num;
    gchar      *label;
    guint8      key[ZBEE_SEC_CONST_KEYSIZE];
} key_record_t;

typedef struct {
    gint                    src_pan;    /* source pan */
    gint                    src;        /* short source address from nwk */
#if 0
    gint                    ieee_src;   /* short source address from mac */
#endif
    ieee802154_map_rec     *map_rec;    /* extended src from nwk */
    key_record_t           *nwk;        /* Network key found for this packet */
    key_record_t           *link;       /* Link key found for this packet */
} zbee_nwk_hints_t;

extern ieee802154_map_tab_t zbee_nwk_map;
extern GHashTable *zbee_table_nwk_keyring;
extern GHashTable *zbee_table_link_keyring;

/* Key Types */
#define ZBEE_USER_KEY 0x01

/* ZigBee PRO beacons */
#define ZBEE_NWK_BEACON_PROTOCOL_ID            0x00
#define ZBEE_NWK_BEACON_STACK_PROFILE        0x000f
#define ZBEE_NWK_BEACON_PROTOCOL_VERSION     0x00f0
#define ZBEE_NWK_BEACON_ROUTER_CAPACITY      0x0400
#define ZBEE_NWK_BEACON_NETWORK_DEPTH        0x7800
#define ZBEE_NWK_BEACON_END_DEVICE_CAPACITY  0x8000
#define ZBEE_NWK_BEACON_LENGTH                   15

/* ZigBee IP beacons */
#define ZBEE_IP_BEACON_PROTOCOL_ID             0x02
#define ZBEE_IP_BEACON_ALLOW_JOIN              0x01
#define ZBEE_IP_BEACON_ROUTER_CAPACITY         0x02
#define ZBEE_IP_BEACON_HOST_CAPACITY           0x04
#define ZBEE_IP_BEACON_UNSECURE                0x80 /* Undocumented bit for test networks. */

#define ZBEE_IP_BEACON_TLV_LENGTH_MASK         0x0f
#define ZBEE_IP_BEACON_TLV_TYPE_MASK           0xf0
#define ZBEE_IP_BEACON_TLV_TYPE_LFDI           0x0

#endif /* PACKET_ZBEE_NWK_H */

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
