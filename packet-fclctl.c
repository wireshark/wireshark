/* packet-fclctl.c
 * Routines for FC Link Control Frames 
 * Copyright 2001, Dinesh G Dutt <ddutt@cisco.com>
 *
 * $Id: packet-fclctl.c,v 1.1 2002/12/08 02:32:17 gerald Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include "etypes.h"
#include "packet-fc.h"
#include "packet-fclctl.h"

static gchar errstr[64];

gchar *
fclctl_get_typestr (guint8 linkctl_type, guint8 type)
{
    if ((linkctl_type == FC_LCTL_FBSYB) ||
        (linkctl_type == FC_LCTL_FBSYL)) {
        return (val_to_str ((type & 0xF0), fc_lctl_fbsy_val, "0x%x")); 
    }
    else return ("\0");
}

gchar *
fclctl_get_paramstr (guint32 linkctl_type, guint32 param)
{
    int len;
    
    errstr[0] = '\0';
    
    if (linkctl_type == FC_LCTL_PBSY) {
        strcpy (errstr, val_to_str (((param & 0xFF000000) >> 24),
                                    fc_lctl_pbsy_acode_val, "0x%x"));
        len = strlen (errstr);
        strcpy (&errstr[len], ", ");
        len = strlen (errstr);
        strcpy (&errstr[len],
                val_to_str (((param & 0x00FF0000) >> 16),
                            fc_lctl_pbsy_rjt_val, "0x%x"));
    }
    else if ((linkctl_type == FC_LCTL_FRJT) ||
             (linkctl_type == FC_LCTL_PRJT)) {
        strcpy (errstr,
                val_to_str (((param & 0xFF000000) >> 24),
                            fc_lctl_rjt_acode_val, "0x%x"));
        len = strlen (errstr);
        strcpy (&errstr[len], ", ");
        len = strlen (errstr);
        strcpy (&errstr[len],
                val_to_str (((param & 0x00FF0000) >> 16), fc_lctl_rjt_val,
                            "%x"));
    }

    return (errstr);
}
