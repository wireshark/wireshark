/* packet-netbios.c
 * Declarations of public routines for NetBIOS protocol packet disassembly
 * Jeff Foster <foste@woodward.com>            
 * Copyright 1999 Jeffrey C. Foster
 * 
 * derived from the packet-nbns.c
 *
 * $Id: packet-netbios.h,v 1.4 1999/11/30 07:45:42 guy Exp $
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

/* Length of NetBIOS names */
#define NETBIOS_NAME_LEN	16

extern int process_netbios_name(const u_char *name_ptr, char *name_ret);
extern int get_netbios_name(const u_char *data_ptr, int offset,
    char *name_ret);
extern char *netbios_name_type_descr(int name_type);
extern gboolean netbios_add_name( char* label, const u_char *pd, int offset,
    proto_tree *tree);
