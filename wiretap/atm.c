/* atm.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "atm.h"
#include "wtap-int.h"

/*
 * Routines to use with ATM capture file types that don't include information
 * about the *type* of ATM traffic (or, at least, where we haven't found
 * that information).
 *
 * We assume the traffic is AAL5, unless it's VPI 0/VCI 5, in which case
 * we assume it's the signalling AAL.
 */

void
atm_guess_traffic_type(wtap_rec *rec, const uint8_t *pd)
{
	/*
	 * Start out assuming nothing other than that it's AAL5.
	 */
	rec->rec_header.packet_header.pseudo_header.atm.aal = AAL_5;
	rec->rec_header.packet_header.pseudo_header.atm.type = TRAF_UNKNOWN;
	rec->rec_header.packet_header.pseudo_header.atm.subtype = TRAF_ST_UNKNOWN;

	if (rec->rec_header.packet_header.pseudo_header.atm.vpi == 0) {
		/*
		 * Traffic on some PVCs with a VPI of 0 and certain
		 * VCIs is of particular types.
		 */
		switch (rec->rec_header.packet_header.pseudo_header.atm.vci) {

		case 5:
			/*
			 * Signalling AAL.
			 */
			rec->rec_header.packet_header.pseudo_header.atm.aal = AAL_SIGNALLING;
			return;

		case 16:
			/*
			 * ILMI.
			 */
			rec->rec_header.packet_header.pseudo_header.atm.type = TRAF_ILMI;
			return;
		}
	}

	/*
	 * OK, we can't tell what it is based on the VPI/VCI; try
	 * guessing based on the contents, if we have enough data
	 * to guess.
	 */

	if (rec->rec_header.packet_header.caplen >= 3) {
		if (pd[0] == 0xaa && pd[1] == 0xaa && pd[2] == 0x03) {
			/*
			 * Looks like a SNAP header; assume it's LLC
			 * multiplexed RFC 1483 traffic.
			 */
			rec->rec_header.packet_header.pseudo_header.atm.type = TRAF_LLCMX;
		} else if ((rec->rec_header.packet_header.pseudo_header.atm.aal5t_len && rec->rec_header.packet_header.pseudo_header.atm.aal5t_len < 16) ||
		    rec->rec_header.packet_header.caplen < 16) {
			/*
			 * As this cannot be a LANE Ethernet frame (less
			 * than 2 bytes of LANE header + 14 bytes of
			 * Ethernet header) we can try it as a SSCOP frame.
			 */
			rec->rec_header.packet_header.pseudo_header.atm.aal = AAL_SIGNALLING;
		} else if (pd[0] == 0x83 || pd[0] == 0x81) {
			/*
			 * MTP3b headers often encapsulate
			 * a SCCP or MTN in the 3G network.
			 * This should cause 0x83 or 0x81
			 * in the first byte.
			 */
			rec->rec_header.packet_header.pseudo_header.atm.aal = AAL_SIGNALLING;
		} else {
			/*
			 * Assume it's LANE.
			 */
			rec->rec_header.packet_header.pseudo_header.atm.type = TRAF_LANE;
			atm_guess_lane_type(rec, pd);
		}
	} else {
	       /*
		* Not only VCI 5 is used for signaling. It might be
		* one of these VCIs.
		*/
	       rec->rec_header.packet_header.pseudo_header.atm.aal = AAL_SIGNALLING;
	}
}

void
atm_guess_lane_type(wtap_rec *rec, const uint8_t *pd)
{
	if (rec->rec_header.packet_header.caplen >= 2) {
		if (pd[0] == 0xff && pd[1] == 0x00) {
			/*
			 * Looks like LE Control traffic.
			 */
			rec->rec_header.packet_header.pseudo_header.atm.subtype = TRAF_ST_LANE_LE_CTRL;
		} else {
			/*
			 * XXX - Ethernet, or Token Ring?
			 * Assume Ethernet for now; if we see earlier
			 * LANE traffic, we may be able to figure out
			 * the traffic type from that, but there may
			 * still be situations where the user has to
			 * tell us.
			 */
			rec->rec_header.packet_header.pseudo_header.atm.subtype = TRAF_ST_LANE_802_3;
		}
	}
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
