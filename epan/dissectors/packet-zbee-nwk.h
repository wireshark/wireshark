/* packet-zbee-nwk.h
 * Dissector routines for the ZigBee Network Layer (NWK)
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
 *
 * $Id$
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

/*  ZigBee NWK FCF Frame Types */
#define ZBEE_NWK_FCF_DATA                   0x0000
#define ZBEE_NWK_FCF_CMD                    0x0001

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

typedef struct{
    gboolean    security;
    gboolean    discovery;
    gboolean    is_bcast;
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
} zbee_nwk_packet;

/* Beacon Definitions. */
#define ZBEE_NWK_BEACON_PROCOL_ID              0x00
#define ZBEE_NWK_BEACON_STACK_PROFILE          0x0f
#define ZBEE_NWK_BEACON_PROTOCOL_VERSION       0xf0
#define ZBEE_NWK_BEACON_ROUTER_CAPACITY        0x04
#define ZBEE_NWK_BEACON_NETWORK_DEPTH          0x78
#define ZBEE_NWK_BEACON_END_DEVICE_CAPACITY    0x80

#endif /* PACKET_ZBEE_NWK_H */
