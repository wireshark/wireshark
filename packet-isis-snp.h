/* packet-isis-snp.h
 * Defines and such for CSNP, PSNP, and their payloads
 *
 * $Id: packet-isis-snp.h,v 1.3 2001/07/02 00:19:34 guy Exp $
 * Stuart Stanley <stuarts@mxmail.net>
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
 *
 *
 */

#ifndef _PACKET_ISIS_SNP_H
#define _PACKET_ISIS_SNP_H

/*
 * Note, the spec say 133 for authentication, but everyone seems to use 10. 
 * Any clue on why this is would be appreciated!
 */

/*
 * detail cvls information for L1 CSNP packets
 */
#define ISIS_CLV_L1_CSNP_LSP_ENTRIES		9
#define ISIS_CLV_L1_CSNP_AUTHENTICATION_NS	10
#define ISIS_CLV_L1_CSNP_AUTHENTICATION		133

/*
 * detail cvls information for L2 CSNP packets
 */
#define ISIS_CLV_L2_CSNP_LSP_ENTRIES		9
#define ISIS_CLV_L2_CSNP_AUTHENTICATION_NS	10
#define ISIS_CLV_L2_CSNP_AUTHENTICATION		133

/*
 * detail cvls information for L1 PSNP packets
 */
#define ISIS_CLV_L1_PSNP_LSP_ENTRIES		9
#define ISIS_CLV_L1_PSNP_AUTHENTICATION_NS	10
#define ISIS_CLV_L1_PSNP_AUTHENTICATION		133

/*
 * detail cvls information for L2 PSNP packets
 */
#define ISIS_CLV_L2_PSNP_LSP_ENTRIES		9
#define ISIS_CLV_L2_PSNP_AUTHENTICATION_NS	10
#define ISIS_CLV_L2_PSNP_AUTHENTICATION		133

/*
 * Published API functions.  NOTE, this are "local" API functions and
 * are only valid from with isis decodes.
 */
extern void isis_dissect_isis_csnp(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset,
	int type, int header_length, int id_length);
extern void isis_dissect_isis_psnp(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset,
	int type, int header_length, int id_length);

#endif /* _PACKET_ISIS_CSNP_H */
