/* packet-pdcp.h
 *
 * Martin Mathieson
 * $Id: packet-umts_fp.h 21726 2007-05-08 17:13:14Z martinm $
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


#define LTE_DCH_TAG    0x00
#define LTE_BCCH_TAG   0x01
#define LTE_CCCH_TAG   0x02
#define LTE_PCCH_TAG   0x03
#define LTE_MCCH_TAG   0x04
#define LTE_MTCH_TAG   0x05
#define LTE_DCCH_TAG   0x06
#define LTE_DTCH_TAG   0x07

#define LTE_SRB_TAG    0x00
#define LTE_DRB_TAG    0x01

enum pdcp_plane
{
    Signalling_Plane=1,
    User_Plane=2
};

enum rohc_mode
{
    Unidirectional=1,
    OptimisticBidirectional=2,
    ReliableBidirectional=3
};

#define CID_IN_PDCP_HEADER 0
#define CID_IN_ROHC_PACKET 1


/* Info attached to each PDCP/RoHC packet */
typedef struct pdcp_info
{
    /* Thread info not really needed for decode */
    guint16         ueid;
    guint8          rbid_type;
    guint8          rbid_value;

    guint8          channel_type;
    guint8          channel_id;
    
    /* Details of PDCP header */
    gboolean        no_header_pdu;
    enum pdcp_plane plane;
    guint8          seqnum_length;

    /* RoHC settings */
    gboolean        rohc_compression;
    unsigned short  rohc_ip_version;
    gboolean        cid_inclusion_info;
    gboolean        large_cid_present;
    enum rohc_mode  mode;
    gboolean        rnd;
    gboolean        udp_checkum_present;
    unsigned short  profile;
} pdcp_info;

