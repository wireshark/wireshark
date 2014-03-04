/* packet-pw-atm.h
 * Interface of pw-atm module
 * Copyright 2009, Artem Tamazov <artem.tamazov@tellabs.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PACKET_PW_ATM_H
#define PACKET_PW_ATM_H

#include "packet-pw-common.h"

typedef enum {
	PWATM_MODE_UNKNOWN = 0
	,PWATM_MODE_N1_NOCW
	,PWATM_MODE_N1_CW
	,PWATM_MODE_11_VCC
	,PWATM_MODE_11_VPC
	,PWATM_MODE_AAL5_SDU
	,PWATM_MODE_AAL5_PDU
} pwatm_mode_t;

typedef enum {
	PWATM_SUBMODE_DEFAULT = 0
	,PWATM_SUBMODE_ADMIN_CELL /*used in aal5_sdu dissector only*/
} pwatm_submode_t;

typedef struct {
	int pw_cell_number;
	int props;
	gint packet_size;
	pwatm_mode_t mode;
	pwatm_submode_t submode;
	struct {
		/*
		 * ATM-specific attributes which remain the same
		 * across all the cells in the pw packet. Values are filled
		 * by sub-dissectors and read by upper-level dissector.
		 * Meanings of values:
		 *   (-1) 	- value is unknown
		 *   (-2) 	- value is different among cells
		 *   positive	- value is the same in all cells
		 * Machinery is implemented in the UPDATE_CUMULATIVE_VALUE macro.
		 */
		gint32 vpi;
		gint32 vci;
		gint32 clp;
		gint32 pti;
	} cumulative;
	gint32 vpi; /*-1 if unknown*/
	gint32 vci; /*-1 if unknown*/
	gint32 pti; /*-1 if unknown*/
	struct {
		/*
		 * Some fields from 3rd byte of CW. Filled by cell_header dissector.
		 * In in AAL5 PDU mode, this allows control_word dissector to print
		 * these values in the CW heading line in the tree.
		 * Meanings of values:
		 *   (-1) 	- value is unknown
		 */
		gint32 m;
		gint32 v;
		gint32 rsv;
		gint32 u;
		gint32 e;
		gint32 clp;
	} cwb3;
	gboolean aal5_sdu_frame_relay_cr_bit; /*see rfc4717 10.1*/
	gboolean cell_mode_oam; /*atm admin cell*/
	gboolean enable_fill_columns_by_atm_dissector;
} pwatm_private_data_t;


#define PWATM_PRIVATE_DATA_T_INITIALIZER {		\
	0, PWC_PACKET_PROPERTIES_T_INITIALIZER, 0	\
	,PWATM_MODE_UNKNOWN, PWATM_SUBMODE_DEFAULT	\
	,{-1, -1, -1, -1 } 				\
	,-1, -1, -1 					\
	,{-1, -1, -1, -1, -1, -1 }			\
	,FALSE, FALSE, TRUE				\
	}

#endif /*PACKET_PW_ATM_H*/
