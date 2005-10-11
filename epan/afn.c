/* afn.c
 * RFC 1700 address family numbers
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/afn.h>

const value_string afn_vals[] = {
    { 0, "Reserved" },
    { AFNUM_INET, "IPv4" },
    { AFNUM_INET6, "IPv6" },
    { AFNUM_NSAP, "NSAP" },
    { AFNUM_HDLC, "HDLC (8-bit multidrop)" },
    { AFNUM_BBN1822, "BBN 1822" },
    { AFNUM_802, "802" },
    { AFNUM_E163, "E.163" },
    { AFNUM_E164, "E.164" },
    { AFNUM_F69, "F.69" },
    { AFNUM_X121, "X.121" },
    { AFNUM_IPX, "IPX" },
    { AFNUM_ATALK, "Appletalk" },
    { AFNUM_DECNET, "Decnet IV" },
    { AFNUM_BANYAN, "Banyan Vines" },
    { AFNUM_E164NSAP, "E.164 with NSAP subaddress" },
    { AFNUM_L2VPN_OLD, "Layer-2 VPN (old)" },
    { AFNUM_L2VPN, "Layer-2 VPN" },
    { 65535, "Reserved" },
    { 0, NULL },
};
