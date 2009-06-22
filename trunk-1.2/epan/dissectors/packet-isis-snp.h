/* packet-isis-snp.h
 * Defines and such for CSNP, PSNP, and their payloads
 *
 * $Id$
 * Stuart Stanley <stuarts@mxmail.net>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _PACKET_ISIS_SNP_H
#define _PACKET_ISIS_SNP_H

/*
 * Published API functions.  NOTE, this are "local" API functions and
 * are only valid from with isis decodes.
 */
extern void isis_dissect_isis_csnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	int offset, int type, int header_length, int id_length);
extern void isis_register_csnp(int proto_isis);
extern void isis_dissect_isis_psnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	int offset, int type, int header_length, int id_length);
extern void isis_register_psnp(int proto_isis);

#endif /* _PACKET_ISIS_CSNP_H */
