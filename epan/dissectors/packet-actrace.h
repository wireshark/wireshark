/* packet-actrace.h
 * Routines for AudioCodes Trunk traces packet disassembly
 *
 * Copyright (c) 2005 by Alejandro Vaquero <alejandro.vaquero@verso.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Container for tapping relevant data */
typedef struct _actrace_info_t
{
    int          type;          /* ACTRACE_CAS=1   ACTRACE_ISDN=2 */
    int          direction;     /* direction BLADE_TO_PSTN=0 PSTN_TO_BLADE=1 */
    int          trunk;
    gint32       cas_bchannel;
    const gchar *cas_frame_label;
} actrace_info_t;

