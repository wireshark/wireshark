/* params.h
 * Definitions for parameter handling routines
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PARAMS_H__
#define __PARAMS_H__

/*
 * Definition of a value for an enumerated type.
 *
 * "name" is the the name one would use on the command line for the value.
 * "description" is the description of the value, used in combo boxes/
 * option menus.
 * "value" is the value.
 */
typedef struct {
	const char	*name;
	const char	*description;
	gint		value;
} enum_val_t;

#endif /* params.h */

