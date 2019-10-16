/* packet-pdcp-nr.h
 *
 * Martin Mathieson
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "packet-rohc.h"

/* Direction */
#define PDCP_NR_DIRECTION_UPLINK   0
#define PDCP_NR_DIRECTION_DOWNLINK 1

enum pdcp_nr_plane
{
    NR_SIGNALING_PLANE = 1,
    NR_USER_PLANE = 2
};

typedef enum NRBearerType
{
    Bearer_DCCH=1,
    Bearer_BCCH_BCH=2,
    Bearer_BCCH_DL_SCH=3,
    Bearer_CCCH=4,
    Bearer_PCCH=5,
} NRBearerType;


#define PDCP_NR_SN_LENGTH_12_BITS 12
#define PDCP_NR_SN_LENGTH_18_BITS 18

#define PDCP_NR_UL_SDAP_HEADER_PRESENT 0x01
#define PDCP_NR_DL_SDAP_HEADER_PRESENT 0x02

/* Info attached to each nr PDCP/RoHC packet */
typedef struct pdcp_nr_info
{
    /* Bearer info is needed for RRC parsing */
    guint8             direction;
    guint16            ueid;
    NRBearerType       bearerType;
    guint8             bearerId;

    /* Details of PDCP header */
    enum pdcp_nr_plane plane;
    guint8             seqnum_length;
    gboolean           maci_present;
    /* PDCP_NR_(U|D)L_SDAP_HEADER_PRESENT bitmask */
    guint8             sdap_header;

    /* RoHC settings */
    rohc_info          rohc;

    guint8             is_retx;

    /* Used by heuristic dissector only */
    guint16            pdu_length;
} pdcp_nr_info;

/* Functions to be called from outside this module (e.g. in a plugin, where pdcp_nr_info
   isn't available) to get/set per-packet data */
WS_DLL_PUBLIC
pdcp_nr_info *get_pdcp_nr_proto_data(packet_info *pinfo);
WS_DLL_PUBLIC
void set_pdcp_nr_proto_data(packet_info *pinfo, pdcp_nr_info *p_pdcp_nr_info);


/*****************************************************************/
/* UDP framing format                                            */
/* -----------------------                                       */
/* Several people have asked about dissecting PDCP by framing    */
/* PDUs over IP.  A suggested format over UDP has been defined   */
/* and implemented by this dissector, using the definitions      */
/* below.                                                        */
/*                                                               */
/* A heuristic dissecter (enabled by a preference) will          */
/* recognise a signature at the beginning of these frames.       */
/* Until someone is using this format, suggestions for changes   */
/* are welcome.                                                  */
/*****************************************************************/


/* Signature.  Rather than try to define a port for this, or make the
   port number a preference, frames will start with this string (with no
   terminating NULL */
#define PDCP_NR_START_STRING "pdcp-nr"

/* Fixed fields:
   - plane (1 byte) */

/* Conditional field. This field is mandatory in case of User Plane PDCP PDU.
   The format is to have the tag, followed by the value (there is no length field,
   it's implicit from the tag). The allowed values are defined above. */

#define PDCP_NR_SEQNUM_LENGTH_TAG          0x02
/* 1 byte */

/* Optional fields. Attaching this info should be added if available.
   The format is to have the tag, followed by the value (there is no length field,
   it's implicit from the tag) */

#define PDCP_NR_DIRECTION_TAG              0x03
/* 1 byte */

#define PDCP_NR_BEARER_TYPE_TAG            0x04
/* 1 byte */

#define PDCP_NR_BEARER_ID_TAG              0x05
/* 1 byte */

#define PDCP_NR_UEID_TAG                   0x06
/* 2 bytes, network order */

#define PDCP_NR_ROHC_COMPRESSION_TAG       0x07
/* 0 byte */

/* N.B. The following ROHC values only have significance if rohc_compression
   is in use for the current channel */

#define PDCP_NR_ROHC_IP_VERSION_TAG        0x08
/* 1 byte */

#define PDCP_NR_ROHC_CID_INC_INFO_TAG      0x09
/* 0 byte */

#define PDCP_NR_ROHC_LARGE_CID_PRES_TAG    0x0A
/* 0 byte */

#define PDCP_NR_ROHC_MODE_TAG              0x0B
/* 1 byte */

#define PDCP_NR_ROHC_RND_TAG               0x0C
/* 0 byte */

#define PDCP_NR_ROHC_UDP_CHECKSUM_PRES_TAG 0x0D
/* 0 byte */

#define PDCP_NR_ROHC_PROFILE_TAG           0x0E
/* 2 bytes, network order */

#define PDCP_NR_MACI_PRES_TAG              0x0F
/* 0 byte */

#define PDCP_NR_SDAP_HEADER_TAG            0x10
/* 1 byte, bitmask with PDCP_NR_UL_SDAP_HEADER_PRESENT and/or PDCP_NR_DL_SDAP_HEADER_PRESENT */

/* PDCP PDU. Following this tag comes the actual PDCP PDU (there is no length, the PDU
   continues until the end of the frame) */
#define PDCP_NR_PAYLOAD_TAG                0x01


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
