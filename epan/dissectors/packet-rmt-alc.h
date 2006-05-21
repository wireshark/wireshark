/* packet-rmt-alc.h
 * Reliable Multicast Transport (RMT)
 * ALC Protocol Instantiation function definitions
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
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
 
#ifndef __PACKET_RMT_ALC__
#define __PACKET_RMT_ALC__

#include "packet-rmt-common.h"
#include "packet-rmt-lct.h"
#include "packet-rmt-fec.h"

/* Type definitions */
/* ================ */

/* Logical ALC packet representation */
struct _alc
{
	guint8 version;
	struct _lct lct;
	struct _fec fec;
};

/* Wireshark stuff */
/* ============== */

/* ALC header field definitions*/
struct _alc_hf
{
	int version;
	
	struct _lct_hf lct;
	struct _fec_hf fec;
	
	int payload;
};

/* ALC subtrees */
struct _alc_ett
{
	gint main;
	
	struct _lct_ett lct;
	struct _fec_ett fec;
};

/* ALC preferences */
struct _alc_prefs
{
	gboolean use_default_udp_port;
	guint default_udp_port;

	struct _lct_prefs lct;
	struct _fec_prefs fec;
};

/* Function declarations */
/* ===================== */

#endif
