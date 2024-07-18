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

enum nr_security_integrity_algorithm_e { nia0, nia1, nia2, nia3 };
enum nr_security_ciphering_algorithm_e { nea0, nea1, nea2, nea3, nea_disabled=999};

typedef struct pdcp_nr_security_info_t
{
    uint32_t                               algorithm_configuration_frame;
    bool                                   seen_next_ul_pdu;       /* i.e. have we seen SecurityModeComplete */
    bool                                   dl_after_reest_request; /* i.e. waiting for DL after rrcReestablishmentRequest */
    enum nr_security_integrity_algorithm_e integrity;
    enum nr_security_ciphering_algorithm_e ciphering;

    /* Store previous settings so can revert if get SecurityModeFailure */
    uint32_t                               previous_algorithm_configuration_frame;
    enum nr_security_integrity_algorithm_e previous_integrity;
    enum nr_security_ciphering_algorithm_e previous_ciphering;
} pdcp_nr_security_info_t;


/* Info attached to each nr PDCP/RoHC packet */
typedef struct pdcp_nr_info
{
    /* Bearer info is needed for RRC parsing */
    uint8_t            direction;
    uint16_t           ueid;
    NRBearerType       bearerType;
    uint8_t            bearerId;

    /* Details of PDCP header */
    enum pdcp_nr_plane plane;
    uint8_t            seqnum_length;
    bool               maci_present;
    bool               ciphering_disabled;
    /* PDCP_NR_(U|D)L_SDAP_HEADER_PRESENT bitmask */
    uint8_t            sdap_header;

    /* RoHC settings */
    rohc_info          rohc;

    uint8_t            is_retx;

    /* Used by heuristic dissector only */
    uint16_t           pdu_length;
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
/* A heuristic dissector (enabled by a preference) will          */
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

#define PDCP_NR_CIPHER_DISABLED_TAG        0x11
/* 0 byte */

/* PDCP PDU. Following this tag comes the actual PDCP PDU (there is no length, the PDU
   continues until the end of the frame) */
#define PDCP_NR_PAYLOAD_TAG                0x01


/* Called by RRC, or other configuration protocols */

/* Function to configure ciphering & integrity algorithms */
void set_pdcp_nr_security_algorithms(uint16_t ueid, pdcp_nr_security_info_t *security_info);

/* Function to indicate securityModeCommand did not complete */
void set_pdcp_nr_security_algorithms_failed(uint16_t ueid);

/* Function to indicate rrcReestablishmentRequest.
 * This results in the next DL SRB1 PDU not being decrypted */
void set_pdcp_nr_rrc_reestablishment_request(uint16_t ueid);

/* Called by external dissectors */
void set_pdcp_nr_rrc_ciphering_key(uint16_t ueid, const char *key, uint32_t frame_num);
void set_pdcp_nr_rrc_integrity_key(uint16_t ueid, const char *key, uint32_t frame_num);
void set_pdcp_nr_up_ciphering_key(uint16_t ueid, const char *key, uint32_t frame_num);
void set_pdcp_nr_up_integrity_key(uint16_t ueid, const char *key, uint32_t frame_num);

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
