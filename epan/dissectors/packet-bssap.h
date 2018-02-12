/* packet-bssap.h
 * Routines for Base Station Subsystem Application Part (BSSAP/BSAP) dissection
 * Specifications from 3GPP2 (www.3gpp2.org) and 3GPP (www.3gpp.org)
 *	IOS 4.0.1 (BSAP)
 *	GSM 08.06 (BSSAP)
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define BSSAP_PDU_TYPE_BSSMAP	0x00
#define BSSAP_PDU_TYPE_DTAP	0x01

#define BSSAP_PDU_TYPE_BSMAP	BSSAP_PDU_TYPE_BSSMAP
