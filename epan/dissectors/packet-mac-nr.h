/* packet-mac-nr.h
 *
 * Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* radioType */
#define FDD_RADIO 1
#define TDD_RADIO 2

/* Direction */
#define DIRECTION_UPLINK   0
#define DIRECTION_DOWNLINK 1

/* rntiType */
#define NO_RNTI     0
#define P_RNTI      1
#define RA_RNTI     2
#define C_RNTI      3
#define SI_RNTI     4
#define CS_RNTI     5

/* Context info attached to each NR MAC frame */
typedef struct mac_nr_info
{
    /* Needed for decode */
    guint8          radioType;
    guint8          direction;
    guint8          rntiType;

    /* Extra info to display */
    guint16         rnti;
    guint16         ueid;
    guint8          harqid;

    /* Will these be included in the ME PHR report? */
    guint8          phr_type2_othercell;

    /* Timing info */
    guint16         sysframeNumber;
    guint8          subframeNumber;

    /* Length of DL PDU or UL grant size in bytes */
    guint16         length;

} mac_nr_info;


/* Functions to be called from outside this module (e.g. in a plugin, where mac_lte_info
   isn't available) to get/set per-packet data */
WS_DLL_PUBLIC
mac_nr_info *get_mac_nr_proto_data(packet_info *pinfo);
WS_DLL_PUBLIC
void set_mac_nr_proto_data(packet_info *pinfo, mac_nr_info *p_mac_nr_info);

/*****************************************************************/
/* UDP framing format                                            */
/* -----------------------                                       */
/* Several people have asked about dissecting MAC by framing     */
/* PDUs over IP.  A suggested format over UDP has been created   */
/* and implemented by this dissector, using the definitions      */
/* below.                                                        */
/*                                                               */
/* A heuristic dissector (enabled by a preference) will          */
/* recognise a signature at the beginning of these frames.       */
/*****************************************************************/


/* Signature.  Rather than try to define a port for this, or make the
   port number a preference, frames will start with this string (with no
   terminating NULL */
#define MAC_NR_START_STRING "mac-nr"

/* Fixed fields.  This is followed by the following 3 mandatory fields:
   - radioType (1 byte)
   - direction (1 byte)
   - rntiType (1 byte)
   (where the allowed values are defined above */

/* Optional fields. Attaching this info to frames will allow you
   to show you display/filter/plot/add-custom-columns on these fields, so should
   be added if available.
   The format is to have the tag, followed by the value (there is no length field,
   it's implicit from the tag) */

#define MAC_NR_RNTI_TAG                0x02
/* 2 bytes, network order */

#define MAC_NR_UEID_TAG                0x03
/* 2 bytes, network order */

#define MAC_NR_FRAME_SUBFRAME_TAG      0x04
/* 2 bytes, network order, SFN is stored in 12 MSB and SF in 4 LSB */

#define MAC_NR_PHR_TYPE2_OTHERCELL_TAG 0x05
/* 1 byte, TRUE/FALSE */

#define MAC_NR_HARQID                  0x06
/* 1 byte */


/* MAC PDU. Following this tag comes the actual MAC PDU (there is no length, the PDU
   continues until the end of the frame) */
#define MAC_NR_PAYLOAD_TAG         0x01

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
