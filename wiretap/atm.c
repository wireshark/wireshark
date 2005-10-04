/* atm.c
 *
 * $Id$
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
#include "config.h"
#endif
#include "wtap-int.h"
#include "atm.h"

/*
 * Routines to use with ATM capture file types that don't include information
 * about the *type* of ATM traffic (or, at least, where we haven't found
 * that information).
 *
 * We assume the traffic is AAL5, unless it's VPI 0/VCI 5, in which case
 * we assume it's the signalling AAL.
 */

void
atm_guess_traffic_type(const guint8 *pd, guint32 len,
    union wtap_pseudo_header *pseudo_header)
{
	/*
	 * Start out assuming nothing other than that it's AAL5.
	 */
	pseudo_header->atm.aal = AAL_5;
	pseudo_header->atm.type = TRAF_UNKNOWN;
	pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;

	if (pseudo_header->atm.vpi == 0) {
		/*
		 * Traffic on some PVCs with a VPI of 0 and certain
		 * VCIs is of particular types.
		 */
		switch (pseudo_header->atm.vci) {

		case 5:
			/*
			 * Signalling AAL.
			 */
			pseudo_header->atm.aal = AAL_SIGNALLING;
			return;

		case 16:
			/*
			 * ILMI.
			 */
			pseudo_header->atm.type = TRAF_ILMI;
			return;
		}
	}

	/*
	 * OK, we can't tell what it is based on the VPI/VCI; try
	 * guessing based on the contents, if we have enough data
	 * to guess.
	 */
	if (len >= 3) {
		if (pd[0] == 0xaa && pd[1] == 0xaa && pd[2] == 0x03) {
			/*
			 * Looks like a SNAP header; assume it's LLC
			 * multiplexed RFC 1483 traffic.
			 */
			pseudo_header->atm.type = TRAF_LLCMX;
		} else {
			/*
			 * Assume it's LANE.
			 */
			pseudo_header->atm.type = TRAF_LANE;
			atm_guess_lane_type(pd, len, pseudo_header);
		}
		return;
	}
       else
               /*
                * Not only VCI 5 is used for signaling. It might be
                * one of these VCIs
                */
               pseudo_header->atm.aal = AAL_SIGNALLING;
}

void
atm_guess_lane_type(const guint8 *pd, guint32 len,
    union wtap_pseudo_header *pseudo_header)
{
	if (len >= 2) {
		if (pd[0] == 0xff && pd[1] == 0x00) {
			/*
			 * Looks like LE Control traffic.
			 */
			pseudo_header->atm.subtype = TRAF_ST_LANE_LE_CTRL;
		} else {
                       guint32 len_802_3;
                       len_802_3 = pd[10];
                       len_802_3 <<= 8;
                       len_802_3 |= pd[11];
			/*
			 * XXX - Ethernet, or Token Ring?
			 * Assume Ethernet for now; if we see earlier
			 * LANE traffic, we may be able to figure out
			 * the traffic type from that, but there may
			 * still be situations where the user has to
			 * tell us.
			 */
                       if (( len_802_3 + 5 + 5 + 2 ) == len )
                               pseudo_header->atm.subtype = TRAF_ST_LANE_802_3;
                       else
                       /*
                        * When it is not a 802.3 frame it might be a signalling one.
                        */
                       {
                               pseudo_header->atm.aal = AAL_SIGNALLING;
                               pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
                       }
		}
	}
}
