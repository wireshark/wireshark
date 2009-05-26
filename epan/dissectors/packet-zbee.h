/* packet-zbee.h
 * Dissector routines for the ZigBee protocol stack.
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
#ifndef PACKET_ZBEE_H
#define PACKET_ZBEE_H

/* IEEE 802.15.4 definitions. */
#include <epan/dissectors/packet-ieee802154.h>

/* The ZigBee Broadcast Address */
#define ZBEE_BCAST_ALL                  0xffff
#define ZBEE_BCAST_ACTIVE               0xfffd
#define ZBEE_BCAST_ROUTERS              0xfffc
#define ZBEE_BCAST_LOW_POWER_ROUTERS    0xfffb

/* Capability Information fields. */
#define ZBEE_CINFO_ALT_COORD            IEEE802154_CMD_CINFO_ALT_PAN_COORD
#define ZBEE_CINFO_FFD                  IEEE802154_CMD_CINFO_DEVICE_TYPE
#define ZBEE_CINFO_POWER                IEEE802154_CMD_CINFO_POWER_SRC
#define ZBEE_CINFO_IDLE_RX              IEEE802154_CMD_CINFO_IDLE_RX
#define ZBEE_CINFO_SECURITY             IEEE802154_CMD_CINFO_SEC_CAPABLE
#define ZBEE_CINFO_ALLOC                IEEE802154_CMD_CINFO_ALLOC_ADDR

/* ZigBee version numbers. */
#define ZBEE_VERSION_PROTOTYPE  0   /* Does this even exist? */
#define ZBEE_VERSION_2004       1   /* Re: 053474r06ZB_TSC-ZigBeeSpecification.pdf */
#define ZBEE_VERSION_2007       2   /* Re: 053474r17ZB_TSC-ZigBeeSpecification.pdf */

/* ZigBee version macro. */
#define ZBEE_HAS_2003(x)        ((x) >= ZBEE_VERSION_2003)
#define ZBEE_HAS_2006(x)        ((x) >= ZBEE_VERSION_2007)
#define ZBEE_HAS_2007(x)        ((x) >= ZBEE_VERSION_2007)

/* Helper Functions */
extern proto_item  *proto_tree_add_eui64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint64 value);
extern guint zbee_get_bit_field(guint input, guint mask);

#endif /* PACKET_ZBEE_H */

