/* packet-dhis.h
 * Routines for DHIS (Dynamic Host Information Services) packet disassembly
 * see http://dhis.sourceforge.net/
 * Olivier Abad <abad@daba.dhis.net>
 *
 * $Id: packet-dhis.h,v 1.3 2000/04/08 07:07:13 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2000
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
 *
 *
 */

#define DHIS_VERSION_ERROR	0
#define DHIS_VERSION_4		1
#define DHIS_VERSION_5		2

#define DHIS_ENCRYPT_ERROR	0
#define DHIS_ENCRYPT_PLAINTEXT	1
#define DHIS_ENCRYPT_BLOWFISH	2

#define DHIS_MESSAGE_ERROR	0
#define DHIS_UPDATE_QUERY	1
#define DHIS_UPDATE_REPLY	2
#define DHIS_ALIVE_QUERY	3
#define DHIS_ALIVE_REPLY	4

#define DHIS_MARK_ONLINE	0
#define DHIS_MARK_OFFLINE	1

#define DHIS_UPDATE_SUCCEEDED	0
#define DHIS_UPDATE_FAILED	1
#define DHIS_INVALID_PASSWORD	2
#define DHIS_INVALID_ACCOUNT	3
#define DHIS_INVALID_OPCODE	4
