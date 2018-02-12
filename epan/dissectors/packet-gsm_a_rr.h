/* packet-gsm_a_rr.h
 * Definitions for GSM A Interface (actually A-bis really) RR dissection - A.K.A. GSM layer 3 Radio Resource Protocol
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Added Dissection of Radio Resource Management Information Elements
 * and other enhancements and fixes.
 * Copyright 2005 - 2006, Anders Broman [AT] ericsson.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_GSM_A_RR_H__
#define __PACKET_GSM_A_RR_H__

extern gint f_k(gint k, gint *w, gint range);

#endif /* __PACKET_GSM_A_RR_H__ */
