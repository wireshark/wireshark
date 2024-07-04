/* packet-sv.h
 * Routines for IEC 61850 Sampled Vales packet dissection
 * Michael Bernhard 2008
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SV_H__
#define __PACKET_SV_H__

#define IEC61850_SV_MAX_PHSMEAS_ENTRIES 20

typedef struct _sv_phs_meas {
	int32_t value;
	uint32_t qual;
} sv_phs_meas;

typedef struct _sv_frame_data {
	uint16_t smpCnt;
	uint8_t smpSynch;
	uint8_t num_phsMeas;
	sv_phs_meas phsMeas[IEC61850_SV_MAX_PHSMEAS_ENTRIES];
	uint16_t smpMod;
} sv_frame_data;

#endif /*__PACKET_SV_H__*/
