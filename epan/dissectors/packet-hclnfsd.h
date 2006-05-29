/* packet-hclnfsd.h
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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

#ifndef PACKET_HCLNFSD_H
#define PACKET_HCLNFSD_H

#define HCLNFSD_PROGRAM  0x2f00dbad

#define HCLNFSDPROC_NULL					0
#define HCLNFSDPROC_SPOOL_INQUIRE		1
#define HCLNFSDPROC_SPOOL_FILE			2
#define HCLNFSDPROC_AUTHORIZE				3
#define HCLNFSDPROC_GRP_NAME_TO_NUMB	4
#define HCLNFSDPROC_GRP_TO_NUMBER		5
#define HCLNFSDPROC_RETURN_HOST			6
#define HCLNFSDPROC_UID_TO_NAME			7
#define HCLNFSDPROC_NAME_TO_UID			8
#define HCLNFSDPROC_SHARE					20
#define HCLNFSDPROC_UNSHARE				21
#define HCLNFSDPROC_LOCK					22
#define HCLNFSDPROC_REMOVE					23
#define HCLNFSDPROC_UNLOCK					24
#define HCLNFSDPROC_GET_PRINTERS			30
#define HCLNFSDPROC_GET_PRINTQ			31
#define HCLNFSDPROC_CANCEL_PRJOB			32
#define HCLNFSDPROC_ZAP_LOCKS				105

#endif
