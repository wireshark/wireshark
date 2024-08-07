/* packet-pdcp-lte.h
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
    Channel_PCCH=4,
    Channel_DCCH_NB=5,
    Channel_BCCH_NB=6,
    Channel_CCCH_NB=7,
    Channel_PCCH_NB=8
} LogicalChannelType;

typedef enum
{
    BCH_TRANSPORT=1,
    DLSCH_TRANSPORT=2
} BCCHTransportType;

#define PDCP_SN_LENGTH_5_BITS  5
#define PDCP_SN_LENGTH_7_BITS  7
#define PDCP_SN_LENGTH_12_BITS 12
#define PDCP_SN_LENGTH_15_BITS 15
#define PDCP_SN_LENGTH_18_BITS 18

enum lte_security_integrity_algorithm_e { eia0, eia1, eia2, eia3 };
enum lte_security_ciphering_algorithm_e { eea0, eea1, eea2, eea3 };

typedef struct pdcp_lte_security_info_t
{
    uint32_t                                configuration_frame;
    bool                                    seen_next_ul_pdu;  /* i.e. have we seen SecurityModeResponse */
    enum lte_security_integrity_algorithm_e integrity;
    enum lte_security_ciphering_algorithm_e ciphering;

    /* Store previous settings so can revert if get SecurityModeFailure */
    uint32_t                                previous_configuration_frame;
    enum lte_security_integrity_algorithm_e previous_integrity;
    enum lte_security_ciphering_algorithm_e previous_ciphering;
} pdcp_lte_security_info_t;


/* Info attached to each LTE PDCP/RoHC packet */
typedef struct pdcp_lte_info
{
    /* Channel info is needed for RRC parsing */
    uint8_t            direction;
    uint16_t           ueid;
    LogicalChannelType channelType;
    uint16_t           channelId;
    BCCHTransportType  BCCHTransport;

    /* Details of PDCP header */
    bool               no_header_pdu;
    enum pdcp_plane    plane;
    uint8_t            seqnum_length;

    /* RoHC settings */
    rohc_info          rohc;

    uint8_t            is_retx;

    /* Used by heuristic dissector only */
    uint16_t           pdu_length;
} pdcp_lte_info;



/***********************************************************************/
/* UDP framing format                                                  */
/* -----------------------                                             */
/* Several people have asked about dissecting PDCP by framing          */
/* PDUs over IP.  A suggested format over UDP has been defined         */
/* and implemented by this dissector, using the definitions            */
/* below. A link to an example program showing you how to encode       */
/* these headers and send LTE PDCP PDUs on a UDP socket is             */
/* provided at https://gitlab.com/wireshark/wireshark/-/wikis/PDCP-LTE */
/*                                                                     */
/* A heuristic dissector (enabled by a preference) will                */
/* recognise a signature at the beginning of these frames.             */
/* Until someone is using this format, suggestions for changes         */
/* are welcome.                                                        */
/***********************************************************************/


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
   it's implicit from the tag). The allowed values are defined above. */

#define PDCP_LTE_SEQNUM_LENGTH_TAG          0x02
/* 1 byte */

/* Optional fields. Attaching this info to frames will allow you
   to show you display/filter/plot/add-custom-columns on these fields, so should
   be added if available.
   The format is to have the tag, followed by the value (there is no length field,
   it's implicit from the tag) */

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

#define PDCP_LTE_CHANNEL_ID_TAG             0x0D
/* 2 bytes, network order */

#define PDCP_LTE_UEID_TAG                   0x0E
/* 2 bytes, network order */

/* PDCP PDU. Following this tag comes the actual PDCP PDU (there is no length, the PDU
   continues until the end of the frame) */
#define PDCP_LTE_PAYLOAD_TAG                0x01



/* Called by RRC, or other configuration protocols */

/* Function to configure ciphering & integrity algorithms */
void set_pdcp_lte_security_algorithms(uint16_t ueid, pdcp_lte_security_info_t *security_info);

/* Function to indicate securityModeCommand did not complete */
void set_pdcp_lte_security_algorithms_failed(uint16_t ueid);


/* Called by external dissectors */
void set_pdcp_lte_rrc_ciphering_key(uint16_t ueid, const char *key, uint32_t frame_num);
void set_pdcp_lte_rrc_integrity_key(uint16_t ueid, const char *key, uint32_t frame_num);
void set_pdcp_lte_up_ciphering_key(uint16_t ueid, const char *key, uint32_t frame_num);

/* Reset UE's bearers */
void pdcp_lte_reset_ue_bearers(packet_info *pinfo, uint16_t ueid, bool including_drb_am);

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
