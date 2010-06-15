/* mtp3_stat.h
 *
 * $Id$
 *
 * Copyright 2004, Michael Lum <mlum [AT] telostech.com>,
 * In association with Telos Technology Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __MTP3_STAT_H__
#define __MTP3_STAT_H__

/** @file
 *  Statistics for MTP3.
 *  @todo Could someone with more knowledge of this comment it for doxygen?
 */

typedef struct _mtp3_stat_si_code_t {
    int			num_msus;
    int			size;
} mtp3_stat_si_code_t;

typedef struct _mtp3_stat_t {
    mtp3_addr_pc_t		addr_opc;
    mtp3_addr_pc_t		addr_dpc;
    mtp3_stat_si_code_t		si_code[MTP3_NUM_SI_CODE];
} mtp3_stat_t;

/*
 * I don't like it but I don't have time to create
 * the code for a dynamic size solution
 */
#define	MTP3_MAX_NUM_OPC_DPC	50

extern mtp3_stat_t		mtp3_stat[];
extern guint8			mtp3_num_used;

#endif /* __MTP3_STAT_H__ */
