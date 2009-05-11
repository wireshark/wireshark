/* packet-pdcp-lte.h
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


/* Direction */
#define DIRECTION_UPLINK   0
#define DIRECTION_DOWNLINK 1

enum pdcp_plane
{
  SIGNALING_PLANE = 1,
  USER_PLANE = 2
};

enum rohc_mode
{
  UNIDIRECTIONAL = 1,
  OPTIMISTIC_BIDIRECTIONAL = 2,
  RELIABLE_BIDIRECTIONAL = 3
};

typedef enum LogicalChannelType
{
    Channel_DCCH=1,
    Channel_BCCH=2,
    Channel_CCCH=3,
    Channel_PCCH=4
} LogicalChannelType;

typedef enum
{
    BCH_TRANSPORT=1,
    DLSCH_TRANSPORT=2
} BCCHTransportType;


#define CID_IN_PDCP_HEADER 0
#define CID_IN_ROHC_PACKET 1

#define PDCP_SN_LENGTH_7_BITS 7
#define PDCP_SN_LENGTH_12_BITS 12



/* Info attached to each LTE PDCP/RoHC packet */
typedef struct pdcp_lte_info
{
    /* Channel info is needed for RRC parsing */
    guint8             Direction;
    LogicalChannelType channelType;
    BCCHTransportType  BCCHTransport;

    /* Details of PDCP header */
    gboolean           no_header_pdu;
    enum pdcp_plane    plane;
    guint8             seqnum_length;

    /* RoHC settings */
    gboolean           rohc_compression;
    unsigned short     rohc_ip_version;
    gboolean           cid_inclusion_info;
    gboolean           large_cid_present;
    enum rohc_mode     mode;
    gboolean           rnd;
    gboolean           udp_checkum_present;
    unsigned short     profile;
} pdcp_lte_info;

