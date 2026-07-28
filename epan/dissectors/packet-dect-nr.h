/* packet-dect-nr.h
 *
 * Copyright 2025, Stig Bjørlykke <stig@bjorlykke.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_DECT_NR_H__
#define __PACKET_DECT_NR_H__

typedef enum {
	DECT_NR_PHF_TYPE_AUTO,
	DECT_NR_PHF_TYPE_1,
	DECT_NR_PHF_TYPE_2,
} dect_nr_phf_type_t;

typedef struct _dect_nr_info_t {
	dect_nr_phf_type_t phf_type;
} dect_nr_info_t;

#endif /* __PACKET_DECT_NR_H__ */
