/* prefs_dlg.h
 * Definitions for preference handling routines
 *
 * $Id: prefs_dlg.h,v 1.2 2000/02/12 06:46:54 guy Exp $
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
 */

#ifndef __PREFS_DLG_H__
#define __PREFS_DLG_H__

#ifndef __PREFS_H__
#include "prefs.h"
#endif


#define E_PR_PG_NONE     -1
#define E_PR_PG_PRINTING  0
#define E_PR_PG_FILTER    1
#define E_PR_PG_COLUMN    2

void     prefs_cb(GtkWidget *, gpointer);

#endif
