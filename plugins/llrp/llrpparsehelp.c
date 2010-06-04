/* EPCglobal Low-Level Reader Protocol Packet Dissector
 *
 * Copyright 2008, Intermec Technologies Corp. <matt.poduska@intermec.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#include <stdio.h>
#include "llrpparsetypes.h"
#include "llrpparsehelp.h"

char *llrp_field_type_to_name(unsigned char type)
{
    if(LLRP_FIELDTYPE_IS_VARIABLE(type))
        return llrp_variable_field_name[type-LLRP_FIELDTYPE_u1v];
    else if(type == LLRP_FIELDTYPE_bytesToEnd)
        return "bytesToEnd";
    else
        return llrp_fixed_field_name[type];
}

char *llrp_enumeration_to_name(t_llrp_enumeration *enumeration, unsigned short value)
{
    unsigned short usIndex;
    t_llrp_enumeration_item *item;

    for(usIndex= 0; usIndex< enumeration->count; usIndex++)
    {
        item= &enumeration->list[usIndex];
        if(item->value== value)
            return item->name;

        /* Since the enumeration list is ordered by value (ascending), short circuit is possible */
        if(item->value> value)
            return NULL;
    }

    return NULL;
}

