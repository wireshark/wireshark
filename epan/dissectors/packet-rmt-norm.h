/* packet-rmt-norm.h
 * Reliable Multicast Transport (RMT)
 * NORM Protocol Instantiation function definitions
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
 
#ifndef __PACKET_RMT_NORM__
#define __PACKET_RMT_NORM__

#include "packet-rmt-common.h"
#include "packet-rmt-fec.h"

/* Type definitions */
/* ================ */

/* Logical NORM packet representation */
struct _norm
{
	guint8 version;
	guint8 type;
	guint8 hlen;
	guint16 sequence;
	guint32 source_id;
	
	struct _fec fec;
};

/* Ethereal stuff */
/* ============== */

/* NORM header field definitions*/
struct _norm_hf
{
	int version;
	int type;
	int hlen;
	int sequence;
	int source_id;
	
	struct _fec_hf fec;
	
	int payload;
};

/* NORM subtrees */
struct _norm_ett
{
	gint main;
	
	struct _fec_ett fec;
};

/* NORM preferences */
struct _norm_prefs
{
	struct _fec_prefs fec;
};

/* Function declarations */
/* ===================== */

#endif
