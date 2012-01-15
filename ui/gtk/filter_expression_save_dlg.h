/* filter_expression_save_dlg.h
 * Submitted by Edwin Groothuis <wireshark@mavetju.org>
 *
 * $Id$
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

#ifndef __FILTER_EXPRESSIONS_SAVE_DLG_H__
#define __FILTER_EXPRESSIONS_SAVE_DLG_H__

#include "globals.h"
#include "epan/filter_expressions.h"

enum {
	FILTER_EXPRESSION_REINIT_DESTROY = 1,
	FILTER_EXPRESSION_REINIT_CREATE = 2
};

/** User requested to shift the time of the trace
 *
 * @param widget parent widget (unused)
 * @param data unused
 * @param action the function to use
 */

extern void filter_expression_save_dlg(gpointer data);
void filter_expression_save_dlg_init(gpointer filter_tb, gpointer filter_te);
void filter_expression_reinit(int what);

#endif /* __FILTER_EXPRESSIONS_SAVE_DLG_H__ */
