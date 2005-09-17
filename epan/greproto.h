/* greproto.h
 * Protocol type values for for the Generic Routing Encapsulation (GRE)
 * protocol
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
 *
 * The protocol type in GRE is supposed to be an Ethernet type value;
 * this file lists protocol type values for which nobody's found an
 * official Ethernet type definition and put that in "etypes.h".
 * Move these to "etypes.h" if you find an official Ethernet type
 * definition for them; when this file is empty, get rid of all includes
 * of it, and get rid of it.
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

#define GRE_WCCP	0x883E
