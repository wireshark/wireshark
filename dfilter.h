/* dfilter.h
 * Definitions for display filters
 *
 * $Id: dfilter.h,v 1.6 1999/08/12 21:16:32 guy Exp $
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

#ifndef __DFILTER_H__
#define __DFILTER_H__

void dfilter_init(void);
int dfilter_compile(char* dfilter_text, GNode** p_dfcode);
gboolean dfilter_apply(GNode *dfcode, proto_tree *ptree, const guint8* pd);

#ifdef WIN32
#define boolean truth_value
#endif

#endif /* ! __DFILTER_H__ */
