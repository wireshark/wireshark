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
#define CHANNEL_TYPE_BCCH_BCH 2
#define CHANNEL_TYPE_PCCH 3
#define CHANNEL_TYPE_SRB 4
#define CHANNEL_TYPE_DRB 5
#define CHANNEL_TYPE_BCCH_DL_SCH 6

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


typedef struct rlc_lte_tap_info {
    /* Info from context */
    guint8          rlcMode;
    guint8          direction;
    guint8          priority;
    guint16         ueid;
    guint16         channelType;
    guint16         channelId;
    guint16         pduLength;
    guint8          UMSequenceNumberLength;

    nstime_t        time;
    guint8          loggedInMACFrame;
    guint16         sequenceNumber;
    guint8          isResegmented;
    guint8          isControlPDU;
    guint16         ACKNo;
    #define MAX_NACKs 128
    guint16         noOfNACKs;
    guint16         NACKs[MAX_NACKs];

    guint16         missingSNs;
} rlc_lte_tap_info;


/* Configure number of PDCP SN bits to use for DRB channels. */
void set_rlc_lte_drb_pdcp_seqnum_length(guint16 ueid, guint8 drbid, guint8 userplane_seqnum_length);


/*****************************************************************/
/* UDP framing format                                            */
/* -----------------------                                       */
/* Several people have asked about dissecting RLC by framing     */
/* PDUs over IP.  A suggested format over UDP has been defined   */
/* and implemented by this dissector, using the definitions      */
/* below. A link to an example program showing you how to encode */
/* these headers and send LTE RLC PDUs on a UDP socket is        */
/* provided at http://wiki.wireshark.org/RLC-LTE                 */
/*                                                               */
/* A heuristic dissecter (enabled by a preference) will          */
/* recognise a signature at the beginning of these frames.       */
/* Until someone is using this format, suggestions for changes   */
/* are welcome.                                                  */
/*****************************************************************/


/* Signature.  Rather than try to define a port for this, or make the
   port number a preference, frames will start with this string (with no
   terminating NULL */
#define RLC_LTE_START_STRING "rlc-lte"

/* Fixed field.  This is followed by the following 1 mandatory field:
   - rlcMode (1 byte)
   (where the allowed values are defined above */

/* Conditional field. This field is mandatory in case of RLC Unacknowledged mode.
   The format is to have the tag, followed by the value (there is no length field,
   its implicit from the tag). The allowed values are defined above. */

#define RLC_LTE_UM_SN_LENGTH_TAG    0x02
/* 1 byte */

/* Optional fields. Attaching this info to frames will allow you
   to show you display/filter/plot/add-custom-columns on these fields, so should
   be added if available.
   The format is to have the tag, followed by the value (there is no length field,
   its implicit from the tag) */

#define RLC_LTE_DIRECTION_TAG       0x03
/* 1 byte */

#define RLC_LTE_PRIORITY_TAG        0x04
/* 1 byte */

#define RLC_LTE_UEID_TAG            0x05
/* 2 bytes, network order */

#define RLC_LTE_CHANNEL_TYPE_TAG    0x06
/* 2 bytes, network order */

#define RLC_LTE_CHANNEL_ID_TAG      0x07
/* 2 bytes, network order */


/* RLC PDU. Following this tag comes the actual RLC PDU (there is no length, the PDU
   continues until the end of the frame) */
#define RLC_LTE_PAYLOAD_TAG         0x01


/* Accessor function to check if a frame was considered to be ReTx */
int is_rlc_lte_frame_retx(packet_info *pinfo, guint8 direction);

