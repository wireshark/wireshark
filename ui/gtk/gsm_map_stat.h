/* gsm_map_stat.h
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

#ifndef __GSM_MAP_STAT_H__
#define __GSM_MAP_STAT_H__

/** @file
 *  Statistics for GSM MAP Operations.
 */

/** Gsm map statistic data */
typedef struct _gsm_map_stat_t {
    int			opr_code[GSM_MAP_MAX_NUM_OPR_CODES];
    int			size[GSM_MAP_MAX_NUM_OPR_CODES];

    int			opr_code_rr[GSM_MAP_MAX_NUM_OPR_CODES];
    int			size_rr[GSM_MAP_MAX_NUM_OPR_CODES];
} gsm_map_stat_t;

/** Global gsm map statistic data */
extern gsm_map_stat_t		gsm_map_stat;

#endif /* __GSM_MAP_STAT_H__ */
