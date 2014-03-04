/* atm.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
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
atm_guess_traffic_type(struct wtap_pkthdr *phdr, const guint8 *pd)
{
	/*
	 * Start out assuming nothing other than that it's AAL5.
	 */
	phdr->pseudo_header.atm.aal = AAL_5;
	phdr->pseudo_header.atm.type = TRAF_UNKNOWN;
	phdr->pseudo_header.atm.subtype = TRAF_ST_UNKNOWN;

	if (phdr->pseudo_header.atm.vpi == 0) {
		/*
		 * Traffic on some PVCs with a VPI of 0 and certain
		 * VCIs is of particular types.
		 */
		switch (phdr->pseudo_header.atm.vci) {

		case 5:
			/*
			 * Signalling AAL.
			 */
			phdr->pseudo_header.atm.aal = AAL_SIGNALLING;
			return;

		case 16:
			/*
			 * ILMI.
			 */
			phdr->pseudo_header.atm.type = TRAF_ILMI;
			return;
		}
	}

	/*
	 * OK, we can't tell what it is based on the VPI/VCI; try
	 * guessing based on the contents, if we have enough data
	 * to guess.
	 */

	if (phdr->caplen >= 3) {
		if (pd[0] == 0xaa && pd[1] == 0xaa && pd[2] == 0x03) {
			/*
			 * Looks like a SNAP header; assume it's LLC
			 * multiplexed RFC 1483 traffic.
			 */
			phdr->pseudo_header.atm.type = TRAF_LLCMX;
		} else if ((phdr->pseudo_header.atm.aal5t_len && phdr->pseudo_header.atm.aal5t_len < 16) ||
		    phdr->caplen < 16) {
			/*
			 * As this cannot be a LANE Ethernet frame (less
			 * than 2 bytes of LANE header + 14 bytes of
			 * Ethernet header) we can try it as a SSCOP frame.
			 */
			phdr->pseudo_header.atm.aal = AAL_SIGNALLING;
		} else if (pd[0] == 0x83 || pd[0] == 0x81) {
			/*
			 * MTP3b headers often encapsulate
			 * a SCCP or MTN in the 3G network.
			 * This should cause 0x83 or 0x81
			 * in the first byte.
			 */
			phdr->pseudo_header.atm.aal = AAL_SIGNALLING;
		} else {
			/*
			 * Assume it's LANE.
			 */
			phdr->pseudo_header.atm.type = TRAF_LANE;
			atm_guess_lane_type(phdr, pd);
		}
	} else {
	       /*
		* Not only VCI 5 is used for signaling. It might be
		* one of these VCIs.
		*/
	       phdr->pseudo_header.atm.aal = AAL_SIGNALLING;
	}
}

void
atm_guess_lane_type(struct wtap_pkthdr *phdr, const guint8 *pd)
{
	if (phdr->caplen >= 2) {
		if (pd[0] == 0xff && pd[1] == 0x00) {
			/*
			 * Looks like LE Control traffic.
			 */
			phdr->pseudo_header.atm.subtype = TRAF_ST_LANE_LE_CTRL;
		} else {
			/*
			 * XXX - Ethernet, or Token Ring?
			 * Assume Ethernet for now; if we see earlier
			 * LANE traffic, we may be able to figure out
			 * the traffic type from that, but there may
			 * still be situations where the user has to
			 * tell us.
			 */
			phdr->pseudo_header.atm.subtype = TRAF_ST_LANE_802_3;
		}
	}
}
