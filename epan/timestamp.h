/* timestamp.h
 * Defines for packet timestamps
 *
 * $Id: timestamp.h,v 1.1 2001/04/01 06:11:25 hagbard Exp $
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

#ifndef __TIMESTAMP_H__
#define __TIMESTAMP_H__

/* MS VC has these macros */
#ifdef RELATIVE
#undef RELATIVE
#endif

#ifdef ABSOLUTE
#undef ABSOLUTE
#endif

/*
 * Type of time-stamp shown in the summary display.
 */
typedef enum {
	RELATIVE,
	ABSOLUTE,
	ABSOLUTE_WITH_DATE,
	DELTA
} ts_type;

extern ts_type timestamp_type;

#endif /* timestamp.h */
