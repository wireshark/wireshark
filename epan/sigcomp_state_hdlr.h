/* sigcomp_state_hdlr.c
 * Routines making up the State handler of the Univerasl Decompressor Virtual Machine (UDVM) 
 * used for Signaling Compression (SigComp) dissection.
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
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
 * References:
 * http://www.ietf.org/rfc/rfc3320.txt?number=3320
 * http://www.ietf.org/rfc/rfc3321.txt?number=3321
 * Useful links :
 * http://www.ietf.org/internet-drafts/draft-ietf-rohc-sigcomp-impl-guide-03.txt
 * http://www.ietf.org/internet-drafts/draft-ietf-rohc-sigcomp-sip-01.txt
 */

#ifndef SIGCOMP_STATE_HDLR_H
#define SIGCOMP_STATE_HDLR_H

extern const value_string result_code_vals[];
extern int udvm_state_access(tvbuff_t *tvb, proto_tree *tree,guint8 *buff,guint16 p_id_start, guint16 p_id_length, guint16 state_begin, guint16 *state_length, 
								guint16 *state_address, guint16 *state_instruction, gint hf_id);

extern void udvm_state_create(guint8 *state_buff,guint8 *state_identifier_buff,guint16 p_id_length);
extern void udvm_state_free(guint8 buff[],guint16 p_id_start,guint16 p_id_length);

extern void sigcomp_init_udvm(void);

#define STATE_BUFFER_SIZE 20

#endif 
/* SIGCOMP_STATE_HDLR_H */
