/* packet-isis-snp.h
 * Defines and such for CSNP, PSNP, and their payloads
 *
 * $Id: packet-isis-snp.h,v 1.1 1999/12/15 04:34:19 guy Exp $
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
 * Declare L1/L2 CSNP header
 */
typedef struct {
	guint8	isis_csnp_pdu_length[2];	/* pdu length including hdr */
	guint8	isis_csnp_source_id[7];		/* source sysid */
	isis_lsp_id_t isis_csnp_start_lsp_id;		/* start LSP id */
	isis_lsp_id_t isis_csnp_end_lsp_id;		/* end LSP id */
} isis_csnp_t;

/*
 * Declare L1/L2 PSNP header
 */
typedef struct {
	guint8	isis_psnp_pdu_length[2];	/* pdu length including hdr */
	guint8	isis_psnp_source_id[7];		/* source sysid */
} isis_psnp_t;

/*
 * Declare SNP payload element
 */
typedef struct {
	guint8	isis_snp_remaining_lifetime[2];	/* lifetime of LSP */
	isis_lsp_id_t isis_snp_lsp_id;		/* target LSP id */
	guint8	isis_snp_sequence_number[4];	/* sequence number of LSP */
	guint8	isis_snp_checksum[2];		/* checksum of LSP */
} isis_snp_t;

/*
 * Published API functions.  NOTE, this are "local" API functions and
 * are only valid from with isis decodes.
 */
extern void isis_dissect_isis_csnp(int type, int header_length,
        const u_char *pd, int offset, frame_data *fd, proto_tree *tree);
extern void isis_dissect_isis_psnp(int type, int header_length,
        const u_char *pd, int offset, frame_data *fd, proto_tree *tree);

#endif /* _PACKET_ISIS_CSNP_H */
