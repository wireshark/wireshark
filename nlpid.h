/* nlpid.h
 * Definitions of OSI NLPIDs (Network Layer Protocol IDs)
 * Laurent Deniel <deniel@worldnet.fr>
 *
 * $Id: nlpid.h,v 1.1 2000/01/13 00:41:11 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

/* Some of these come from RFC 1490. */

#define	NLPID_NULL		0x00
#define	NLPID_SNAP		0x80
#define NLPID_ISO8473_CLNP	0x81
#define	NLPID_ISO9542_ESIS	0x82
#define NLPID_ISO10589_ISIS	0x83
#define NLPID_ISO9542X25_ESIS	0x8a
#define	NLPID_IP		0xcc

extern const value_string nlpid_vals[];

