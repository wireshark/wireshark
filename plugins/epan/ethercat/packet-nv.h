/* packet-nv.h
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_NV_H_
#define _PACKET_NV_H_

/**
 * @brief Platform-independent header describing a single EtherType 0x88A4 non-volatile data entry; layout is fixed across all platforms.
 */
typedef struct _ETYPE_88A4_NV_DATA_HEADER
{
    uint16_t Id;      /**< Identifier of the NV data entry, used to distinguish the type or source of the payload. */
    uint16_t Hash;    /**< Hash of the NV data payload, used to detect corruption or unintended modification. */
    uint16_t Length;  /**< Length in bytes of the NV data payload that follows this header. */
    uint16_t Quality; /**< Quality indicator for the NV data entry, reflecting validity or signal confidence. */
} ETYPE_88A4_NV_DATA_HEADER;
#define ETYPE_88A4_NV_DATA_HEADER_Len (int)sizeof(ETYPE_88A4_NV_DATA_HEADER) /**< Wire size in bytes of ETYPE_88A4_NV_DATA_HEADER. */

/**
 * @brief Parser header for an EtherType 0x88A4 NV (non-volatile) data frame, preceding one or more ETYPE_88A4_NV_DATA_HEADER entries.
 */
typedef struct _NvParserHDR
{
    uint8_t  Publisher[6]; /**< MAC address of the device that published this NV data frame. */
    uint16_t CountNV;      /**< Number of NV data entries contained within this frame. */
    uint16_t CycleIndex;   /**< Cyclic counter incremented by the publisher each transmission cycle, used for continuity checks. */
    uint16_t Reserved;     /**< Reserved for future use; must be set to zero. */
} NvParserHDR;
#define NvParserHDR_Len (int)sizeof(NvParserHDR) /**< Wire size in bytes of NvParserHDR. */

#endif /* _PACKET_NV_H_*/
