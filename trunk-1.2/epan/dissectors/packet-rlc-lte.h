/* packet-rlc-lte.h
 *
 * Martin Mathieson
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

/* rlcMode */
#define RLC_TM_MODE 1
#define RLC_UM_MODE 2
#define RLC_AM_MODE 4
#define RLC_PREDEF  8

/* direction */
#define DIRECTION_UPLINK 0
#define DIRECTION_DOWNLINK 1

/* priority ? */

/* channelType */
#define CHANNEL_TYPE_CCCH 1
#define CHANNEL_TYPE_BCCH 2
#define CHANNEL_TYPE_PCCH 3
#define CHANNEL_TYPE_SRB 4
#define CHANNEL_TYPE_DRB 5

/* UMSequenceNumberLength */
#define UM_SN_LENGTH_5_BITS 5
#define UM_SN_LENGTH_10_BITS 10

/* Info attached to each LTE RLC frame */
typedef struct rlc_lte_info
{
    guint8          rlcMode;
    guint8          direction;
    guint8          priority;
    guint16         ueid;
    guint16         channelType;
    guint16         channelId;
    guint16         pduLength;
    guint8          UMSequenceNumberLength;
} rlc_lte_info;

