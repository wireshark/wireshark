/* packet-mstp.h
 * Routines for BACnet MS/TP datalink dissection
 * Copyright 2008 Steve Karg <skarg@users.sourceforge.net> Alabama
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __MSTP_H__
#define __MSTP_H__

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif

/**
 * Returns a value string for the BACnet MS/TP Frame Type.
 * @param val
 * @return constant C String with MS/TP Frame Type
 */
const gchar *
mstp_frame_type_text(guint32 val);

/**
 * Dissects the BACnet MS/TP packet after the preamble,
 * starting with the MS/TP Frame type octet.  Passes
 * the PDU, if there is one, to the BACnet dissector.
 * @param tvb
 * @param pinfo
 * @param tree
 * @param subtree
 * @param offset
 * @return none
 */
void
dissect_mstp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *subtree, gint offset);

#endif /* __MSTP_H__ */


