/* packet-dcerpc-initshutdown.h
 * Routines for SMB \PIPE\initshutdown packet disassembly
 * Based on packet-dcerpc-winreg.h
 * Copyright 2001-2003 Tim Potter <tpot@samba.org>
 * as per a suggestion by Jim McDonough
 *
 * $Id: packet-dcerpc-initshutdown.h,v 1.1 2003/10/27 23:31:54 guy Exp $
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

#ifndef __PACKET_DCERPC_INITSHUTDOWN_H
#define __PACKET_DCERPC_INITSHUTDOWN_H

/* Functions available on the INITSHUTDOWN pipe. */

#define INITSHUTDOWN_INITIATE_SYSTEM_SHUTDOWN 	0x00
#define INITSHUTDOWN_ABORT_SYSTEM_SHUTDOWN	0x01
#define INITSHUTDOWN_INITIATE_SYSTEM_SHUTDOWN_EX 0x02

#endif /* packet-dcerpc-initshutdown.h */
