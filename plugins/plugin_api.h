/* plugin_api.h
 * Routines for Ethereal plugins.
 *
 * $Id: plugin_api.h,v 1.56 2003/09/24 18:35:08 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * Copyright 2000 by Gilbert Ramirez <gram@alumni.rice.edu>
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

#ifndef PLUGIN_API_H
#define PLUGIN_API_H

#ifdef PLUGINS_NEED_ADDRESS_TABLE

/* Some OSes (Win32) have DLLs that cannot reference symbols in the parent
   executable, so the executable needs to provide a collection of pointers
   to global variables and functions for the DLL plugin to use. */

/* #defines for those functions that are called through pointers,
   and global variables that are referred to through pointers.

   #defined in this fashion so that the declaration of the functions
   and variables, from the system header files, turn into declarations
   of pointers to functions and variables, and the references to them in
   plugins, in the plugins, turn into references through the pointers. */

/* file generted by plugin_gen.py */
#include "Xplugin_api.h"

#define tvb_get_string			(*p_tvb_get_string)
#define tvb_get_stringz			(*p_tvb_get_stringz)

#endif

#include <epan/packet.h>
#include <epan/conversation.h>
#include "prefs.h"
#include "reassemble.h"
#include "packet-giop.h"
#include "packet-tpkt.h"
#include "packet-tcp.h"
#include "tap.h"
#include "asn1.h"
#include "packet-per.h"
#include "epan/except.h"

#include "plugin_table.h"

#ifdef PLUGINS_NEED_ADDRESS_TABLE
/* The parent executable will send us the pointer to a filled in
   plugin_address_table_t struct, and we copy the pointers from
   that table so that we can use functions from the parent executable. */
void plugin_address_table_init(plugin_address_table_t*);
#else
#define plugin_address_table_init(x)    ;
#endif

#endif /* PLUGIN_API_H */
