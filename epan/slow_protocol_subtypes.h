/* slow_protocol_subtypes.h
 * Defines subtypes for 802.3 "slow protocols"
 *
 * Copyright 2002 Steve Housley <steve_housley@3com.com>
 * Copyright 2005 Dominique Bastien <dbastien@accedian.com>
 * Copyright 2009 Artem Tamazov <artem.tamazov@telllabs.com>
 * Copyright 2010 Roberto Morro <roberto.morro[AT]tilab.com>
 * Copyright 2014 Philip Rosenberg-Watt <p.rosenberg-watt[at]cablelabs.com.>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SLOW_PROTOCOL_SUBTYPES_H__
#define __SLOW_PROTOCOL_SUBTYPES_H__

#define LACP_SUBTYPE                    0x1
#define MARKER_SUBTYPE                  0x2
#define OAM_SUBTYPE                     0x3
#define OSSP_SUBTYPE                    0xa /* IEEE 802.3 Annex 57A*/

#endif /* __SLOW_PROTOCOL_SUBTYPES_H__ */
