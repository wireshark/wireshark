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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include "packet-rohc.h"

/* Direction */
#define DIRECTION_UPLINK   0
#define DIRECTION_DOWNLINK 1

enum pdcp_plane
{
  SIGNALING_PLANE = 1,
  USER_PLANE = 2
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

#define PDCP_SN_LENGTH_5_BITS  5
#define PDCP_SN_LENGTH_7_BITS  7
#define PDCP_SN_LENGTH_12_BITS 12
#define PDCP_SN_LENGTH_15_BITS 15



/* Info attached to each LTE PDCP/RoHC packet */
typedef struct pdcp_lte_info
{
    /* Channel info is needed for RRC parsing */
    guint8             direction;
    guint16            ueid;
    LogicalChannelType channelType;
    guint16            channelId;
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

    guint8             is_retx;
} pdcp_lte_info;



/*****************************************************************/
/* UDP framing format                                            */
/* -----------------------                                       */
/* Several people have asked about dissecting PDCP by framing    */
/* PDUs over IP.  A suggested format over UDP has been defined   */
/* and implemented by this dissector, using the definitions      */
/* below. A link to an example program showing you how to encode */
/* these headers and send LTE PDCP PDUs on a UDP socket is       */
/* provided at http://wiki.wireshark.org/PDCP-LTE                */
/*                                                               */
/* A heuristic dissecter (enabled by a preference) will          */
/* recognise a signature at the beginning of these frames.       */
/* Until someone is using this format, suggestions for changes   */
/* are welcome.                                                  */
/*****************************************************************/


/* Signature.  Rather than try to define a port for this, or make the
   port number a preference, frames will start with this string (with no
   terminating NULL */
#define PDCP_LTE_START_STRING "pdcp-lte"

/* Fixed fields.  This is followed by the following 3 mandatory fields:
   - no_header_pdu (1 byte)
   - plane (1 byte)
   - rohc_compression ( byte)
   (where the allowed values are defined above) */

/* Conditional field. This field is mandatory in case of User Plane PDCP PDU.
   The format is to have the tag, followed by the value (there is no length field,
   its implicit from the tag). The allowed values are defined above. */

#define PDCP_LTE_SEQNUM_LENGTH_TAG          0x02
/* 1 byte */

/* Optional fields. Attaching this info to frames will allow you
   to show you display/filter/plot/add-custom-columns on these fields, so should
   be added if available.
   The format is to have the tag, followed by the value (there is no length field,
   its implicit from the tag) */

#define PDCP_LTE_DIRECTION_TAG              0x03
/* 1 byte */

#define PDCP_LTE_LOG_CHAN_TYPE_TAG          0x04
/* 1 byte */

#define PDCP_LTE_BCCH_TRANSPORT_TYPE_TAG    0x05
/* 1 byte */

#define PDCP_LTE_ROHC_IP_VERSION_TAG        0x06
/* 2 bytes, network order */

#define PDCP_LTE_ROHC_CID_INC_INFO_TAG      0x07
/* 1 byte */

#define PDCP_LTE_ROHC_LARGE_CID_PRES_TAG    0x08
/* 1 byte */

#define PDCP_LTE_ROHC_MODE_TAG              0x09
/* 1 byte */

#define PDCP_LTE_ROHC_RND_TAG               0x0A
/* 1 byte */

#define PDCP_LTE_ROHC_UDP_CHECKSUM_PRES_TAG 0x0B
/* 1 byte */

#define PDCP_LTE_ROHC_PROFILE_TAG           0x0C
/* 2 bytes, network order */


/* PDCP PDU. Following this tag comes the actual PDCP PDU (there is no length, the PDU
   continues until the end of the frame) */
#define PDCP_LTE_PAYLOAD_TAG                0x01
