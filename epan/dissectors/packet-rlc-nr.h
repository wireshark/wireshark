/* packet-rlc-nr.h
 *
 * Pascal Quantin
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_RLC_NR_H
#define PACKET_RLC_NR_H

/* rlcMode */
#define RLC_TM_MODE 1
#define RLC_UM_MODE 2
#define RLC_AM_MODE 4

/* direction */
#define DIRECTION_UPLINK 0
#define DIRECTION_DOWNLINK 1

/* bearerType */
#define BEARER_TYPE_CCCH 1
#define BEARER_TYPE_BCCH_BCH 2
#define BEARER_TYPE_PCCH 3
#define BEARER_TYPE_SRB 4
#define BEARER_TYPE_DRB 5
#define BEARER_TYPE_BCCH_DL_SCH 6

/* sequenceNumberLength */
#define TM_SN_LENGTH_0_BITS  0
#define UM_SN_LENGTH_6_BITS  6
#define UM_SN_LENGTH_12_BITS 12
#define AM_SN_LENGTH_12_BITS 12
#define AM_SN_LENGTH_18_BITS 18

/* Info attached to each NR RLC frame */
typedef struct rlc_nr_info
{
    guint8          rlcMode;
    guint8          direction;
    guint8          sequenceNumberLength;
    guint8          bearerType;
    guint8          bearerId;
    guint16         ueid;
    guint16         pduLength;
} rlc_nr_info;

/* Configure number of PDCP SN bits to use for DRB channels. */
void set_rlc_nr_drb_pdcp_seqnum_length(packet_info *pinfo, guint16 ueid, guint8 drbid,
                                       guint8 userplane_seqnum_length_ul,
                                       guint8 userplane_seqnum_length_dl);

/*****************************************************************/
/* UDP framing format                                            */
/* -----------------------                                       */
/* Several people have asked about dissecting RLC by framing     */
/* PDUs over IP. A suggested format over UDP has been defined    */
/* and implemented by this dissector, using the definitions      */
/* below.                                                        */
/*                                                               */
/* A heuristic dissector (enabled by a preference) will          */
/* recognise a signature at the beginning of these frames.       */
/*****************************************************************/


/* Signature.  Rather than try to define a port for this, or make the
   port number a preference, frames will start with this string (with no
   terminating NULL */
#define RLC_NR_START_STRING "rlc-nr"

/* Fixed field. This is followed by the following 2 mandatory field:
   - rlcMode (1 byte)
   - sequenceNumberLength (1 byte)
   (where the allowed values are defined above) */

/* Optional fields. Attaching this info to frames will allow you
   to show you display/filter/plot/add-custom-columns on these fields, so should
   be added if available.
   The format is to have the tag, followed by the value (there is no length field,
   it's implicit from the tag) */

#define RLC_NR_DIRECTION_TAG       0x02
/* 1 byte */

#define RLC_NR_UEID_TAG            0x03
/* 2 bytes, network order */

#define RLC_NR_BEARER_TYPE_TAG     0x04
/* 1 byte */

#define RLC_NR_BEARER_ID_TAG       0x05
/* 1 byte */

/* RLC PDU. Following this tag comes the actual RLC PDU (there is no length, the PDU
   continues until the end of the frame) */
#define RLC_NR_PAYLOAD_TAG         0x01

#endif

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
