/*
 * $Id: ftypes-int.h,v 1.12 2003/12/10 21:12:02 gerald Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2001 Gerald Combs
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

#ifndef FTYPES_INT_H
#define FTYPES_INT_H

#include <epan/packet.h>
#include "ftypes.h"

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif /* HAVE_LIBPCRE */


#ifdef HAVE_LIBPCRE
struct _pcre_tuple_t {
    char *string;
    pcre *re;
    pcre_extra *ex;
    char *error;
};
#endif /* HAVE_LIBPCRE */

void
ftype_register(enum ftenum ftype, ftype_t *ft);

#endif
