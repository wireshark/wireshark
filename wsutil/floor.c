/* floor.c
 * 
 * Provides floor functions for systems that do not provide them
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

#include "config.h"

#include <glib.h>

#ifndef HAVE_FLOORL
long double
floorl(long double x)
{
#ifdef (__GNUC__)
  __builtin_floorl(x);
#else
#error "The floorl() function is not present on this system and the GNU C"
#error "compiler (gcc) isn't in use, which can provide one."
#endif

#endif /* !HAVE_FLOORL */
