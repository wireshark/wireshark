/* packet-mac-lte.h
 *
 * Martin Mathieson
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
 *
 * This header file may also be distributed under
 * the terms of the BSD Licence as follows:
 *
 * Copyright (C) 2009 Martin Mathieson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE
 */

#include "ws_symbol_export.h"

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
#define SPS_RNTI    5
#define M_RNTI      6
#define SL_BCH_RNTI 7
#define SL_RNTI     8
#define SC_RNTI     9
#define G_RNTI      10

typedef enum mac_lte_oob_event {
    ltemac_send_preamble,
    ltemac_send_sr,
    ltemac_sr_failure
} mac_lte_oob_event;

typedef enum mac_lte_dl_retx {
    dl_retx_no,
    dl_retx_yes,
    dl_retx_unknown
} mac_lte_dl_retx;

typedef enum mac_lte_crc_status {
    crc_fail = 0,
    crc_success = 1,
    crc_high_code_rate = 2,
    crc_pdsch_lost = 3,
    crc_duplicate_nonzero_rv = 4,
    crc_false_dci = 5
} mac_lte_crc_status;

typedef enum mac_lte_carrier_id {
    carrier_id_primary,
    carrier_id_secondary_1,
    carrier_id_secondary_2,
    carrier_id_secondary_3,
    carrier_id_secondary_4
} mac_lte_carrier_id;

typedef enum mac_lte_ce_mode {
    no_ce_mode = 0,
    ce_mode_a = 1,
    ce_mode_b = 2
} mac_lte_ce_mode;

typedef enum mac_lte_nb_mode {
    no_nb_mode = 0,
    nb_mode = 1
} mac_lte_nb_mode;

/* Context info attached to each LTE MAC frame */
typedef struct mac_lte_info
{
    /* Needed for decode */
    guint8          radioType;
    guint8          direction;
    guint8          rntiType;

    /* Extra info to display */
    guint16         rnti;
    guint16         ueid;

    /* Timing info */
    guint16         sysframeNumber;
    guint16         subframeNumber;

    /* Optional field. More interesting for TDD (FDD is always -4 subframeNumber) */
    gboolean        subframeNumberOfGrantPresent;
    guint16         subframeNumberOfGrant;

    /* Flag set only if doing PHY-level data test - i.e. there may not be a
       well-formed MAC PDU so just show as raw data */
    gboolean        isPredefinedData;

    /* Length of DL PDU or UL grant size in bytes */
    guint16         length;

    /* 0=newTx, 1=first-retx, etc */
    guint8          reTxCount;
    guint8          isPHICHNACK; /* FALSE=PDCCH retx grant, TRUE=PHICH NACK */

    /* UL only.  Indicates if the R10 extendedBSR-Sizes parameter is set */
    gboolean        isExtendedBSRSizes;

    /* UL only.  Indicates if the R10 simultaneousPUCCH-PUSCH parameter is set for PCell */
    gboolean        isSimultPUCCHPUSCHPCell;

    /* UL only.  Indicates if the R10 extendedBSR-Sizes parameter is set for PSCell */
    gboolean        isSimultPUCCHPUSCHPSCell;

    /* Status of CRC check. For UE it is DL only. For eNodeB it is UL
       only. For an analyzer, it is present for both DL and UL. */
    gboolean        crcStatusValid;
    mac_lte_crc_status crcStatus;

    /* Carrier ID */
    mac_lte_carrier_id   carrierId;

    /* DL only.  Is this known to be a retransmission? */
    mac_lte_dl_retx dl_retx;

    /* DL only. CE mode to be used for RAR decoding */
    mac_lte_ce_mode ceMode;

    /* DL and UL. NB-IoT mode of the UE */
    mac_lte_nb_mode nbMode;

    /* UL only, for now used for CE mode A RAR decoding */
    guint8          nUlRb;

    /* More Physical layer info (see direction above for which side of union to use) */
    union {
        struct mac_lte_ul_phy_info
        {
            guint8 present;  /* Remaining UL fields are present and should be displayed */
            guint8 modulation_type;
            guint8 tbs_index;
            guint8 resource_block_length;
            guint8 resource_block_start;
            guint8 harq_id;
            gboolean ndi;
        } ul_info;
        struct mac_lte_dl_phy_info
        {
            guint8 present; /* Remaining DL fields are present and should be displayed */
            guint8 dci_format;
            guint8 resource_allocation_type;
            guint8 aggregation_level;
            guint8 mcs_index;
            guint8 redundancy_version_index;
            guint8 resource_block_length;
            guint8 harq_id;
            gboolean ndi;
            guint8   transport_block;  /* 0..1 */
        } dl_info;
    } detailed_phy_info;

    /* Relating to out-of-band events */
    /* N.B. dissector will only look to these fields if length is 0... */
    mac_lte_oob_event  oob_event;
    guint8             rapid;
    guint8             rach_attempt_number;
    #define MAX_SRs 20
    guint16            number_of_srs;
    guint16            oob_ueid[MAX_SRs];
    guint16            oob_rnti[MAX_SRs];
} mac_lte_info;


typedef struct mac_lte_tap_info {
    /* Info from context */
    guint16  rnti;
    guint16  ueid;
    guint8   rntiType;
    guint8   isPredefinedData;
    gboolean crcStatusValid;
    mac_lte_crc_status   crcStatus;
    guint8   direction;

    guint8   isPHYRetx;
    guint16  ueInTTI;

    nstime_t mac_lte_time;

    /* Number of bytes (which part is used depends upon context settings) */
    guint32  single_number_of_bytes;
    guint32  bytes_for_lcid[11];
    guint32  sdus_for_lcid[11];
    guint8   number_of_rars;
    guint8   number_of_paging_ids;

    /* Number of padding bytes includes padding subheaders and trailing padding */
    guint16  padding_bytes;
    guint16  raw_length;
} mac_lte_tap_info;


/* Accessor function to check if a frame was considered to be ReTx */
int is_mac_lte_frame_retx(packet_info *pinfo, guint8 direction);

/*****************************************************************/
/* UDP framing format                                            */
/* -----------------------                                       */
/* Several people have asked about dissecting MAC by framing     */
/* PDUs over IP.  A suggested format over UDP has been created   */
/* and implemented by this dissector, using the definitions      */
/* below. A link to an example program showing you how to encode */
/* these headers and send LTE MAC PDUs on a UDP socket is        */
/* provided at https://wiki.wireshark.org/MAC-LTE                 */
/*                                                               */
/* A heuristic dissecter (enabled by a preference) will          */
/* recognise a signature at the beginning of these frames.       */
/*****************************************************************/


/* Signature.  Rather than try to define a port for this, or make the
   port number a preference, frames will start with this string (with no
   terminating NULL */
#define MAC_LTE_START_STRING "mac-lte"

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

#define MAC_LTE_RNTI_TAG            0x02
/* 2 bytes, network order */

#define MAC_LTE_UEID_TAG            0x03
/* 2 bytes, network order */

#define MAC_LTE_FRAME_SUBFRAME_TAG  0x04
/* 2 bytes, network order, SFN is stored in 12 MSB and SF in 4 LSB */

#define MAC_LTE_PREDEFINED_DATA_TAG 0x05
/* 1 byte */

#define MAC_LTE_RETX_TAG            0x06
/* 1 byte */

#define MAC_LTE_CRC_STATUS_TAG      0x07
/* 1 byte */

#define MAC_LTE_EXT_BSR_SIZES_TAG   0x08
/* 0 byte */

#define MAC_LTE_SEND_PREAMBLE_TAG   0x09
/* 2 bytes, RAPID value (1 byte) followed by RACH attempt number (1 byte) */

#define MAC_LTE_CARRIER_ID_TAG      0x0A
/* 1 byte */

#define MAC_LTE_PHY_TAG             0x0B
/* variable length, length (1 byte) then depending on direction
   in UL: modulation type (1 byte), TBS index (1 byte), RB length (1 byte),
          RB start (1 byte), HARQ id (1 byte), NDI (1 byte)
   in DL: DCI format (1 byte), resource allocation type (1 byte), aggregation level (1 byte),
          MCS index (1 byte), redundancy version (1 byte), resource block length (1 byte),
          HARQ id (1 byte), NDI (1 byte), TB (1 byte), DL reTx (1 byte) */

#define MAC_LTE_SIMULT_PUCCH_PUSCH_PCELL_TAG  0x0C
/* 0 byte */

#define MAC_LTE_SIMULT_PUCCH_PUSCH_PSCELL_TAG 0x0D
/* 0 byte */

#define MAC_LTE_CE_MODE_TAG         0x0E
/* 1 byte containing mac_lte_ce_mode enum value */

#define MAC_LTE_NB_MODE_TAG         0x0F
/* 1 byte containing mac_lte_nb_mode enum value */

#define MAC_LTE_N_UL_RB_TAG         0x10
/* 1 byte containing the number of UL resource blocks: 6, 15, 25, 50, 75 or 100 */

/* MAC PDU. Following this tag comes the actual MAC PDU (there is no length, the PDU
   continues until the end of the frame) */
#define MAC_LTE_PAYLOAD_TAG 0x01


/* Type to store parameters for configuring LCID->RLC channel settings for DRB */
/* Some are optional, and may not be seen (e.g. on reestablishment) */
typedef struct drb_mapping_t
{
    guint16    ueid;                /* Mandatory */
    guint8     drbid;               /* Mandatory */
    gboolean   lcid_present;
    guint8     lcid;                /* Part of LogicalChannelConfig - optional */
    gboolean   rlcMode_present;
    guint8     rlcMode;             /* Part of RLC config - optional */
    gboolean   rlc_ul_ext_li_field; /* Part of RLC config - optional */
    gboolean   rlc_dl_ext_li_field; /* Part of RLC config - optional */
    gboolean   rlc_ul_ext_am_sn;    /* Part of RLC config - optional */
    gboolean   rlc_dl_ext_am_sn;    /* Part of RLC config - optional */
    gboolean   um_sn_length_present;
    guint8     um_sn_length;        /* Part of RLC config - optional */
    gboolean   ul_priority_present;
    guint8     ul_priority;         /* Part of LogicalChannelConfig - optional */
    gboolean   pdcp_sn_size_present;
    guint8     pdcp_sn_size;        /* Part of pdcp-Config - optional */
} drb_mapping_t;


/* Set details of an LCID -> drb channel mapping.  To be called from
   configuration protocol (e.g. RRC) */
void set_mac_lte_channel_mapping(drb_mapping_t *drb_mapping);


/* Dedicated DRX config. Used to verify that a sensible config is given.
   Also, beginning to configure MAC with this config and (optionally) show
   DRX config and state (cycles/timers) attached to each UL/DL PDU! */
typedef struct drx_config_t {
    gboolean    configured;
    guint32     frameNum;
    guint32     previousFrameNum;

    guint32     onDurationTimer;
    guint32     inactivityTimer;
    guint32     retransmissionTimer;
    guint32     longCycle;
    guint32     cycleOffset;
    /* Optional Short cycle */
    gboolean    shortCycleConfigured;
    guint32     shortCycle;
    guint32     shortCycleTimer;
} drx_config_t;

/* Functions to set/release up dedicated DRX config */
void set_mac_lte_drx_config(guint16 ueid, drx_config_t *drx_config, packet_info *pinfo);
void set_mac_lte_drx_config_release(guint16 ueid,  packet_info *pinfo);

/* RRC can tell this dissector which RAPIDs are Group A, Group A&B */
void set_mac_lte_rapid_ranges(guint groupA, guint all_RA);

/* RRC can indicate whether extended BSR sizes are used */
void set_mac_lte_extended_bsr_sizes(guint16 ueid, gboolean use_ext_bsr_sizes, packet_info *pinfo);

/* RRC can indicate whether simultaneous PUCCH/PUSCH is used */
typedef enum {
    SIMULT_PUCCH_PUSCH_PCELL = 0,
    SIMULT_PUCCH_PUSCH_PSCELL
} simult_pucch_pusch_cell_type;
void set_mac_lte_simult_pucch_pusch(guint16 ueid, simult_pucch_pusch_cell_type cell_type, gboolean use_simult_pucch_pusch, packet_info *pinfo);

/* Functions to be called from outside this module (e.g. in a plugin, where mac_lte_info
   isn't available) to get/set per-packet data */
WS_DLL_PUBLIC
mac_lte_info *get_mac_lte_proto_data(packet_info *pinfo);
WS_DLL_PUBLIC
void set_mac_lte_proto_data(packet_info *pinfo, mac_lte_info *p_mac_lte_info);

/* Function to attempt to populate p_mac_lte_info using framing definition above */
gboolean dissect_mac_lte_context_fields(struct mac_lte_info  *p_mac_lte_info, tvbuff_t *tvb,
                                        gint *p_offset);

