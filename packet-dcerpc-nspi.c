/* packet-dcerpc-nspi.c
 * Routines for dcerpc nspi dissection
 * Copyright 2001, Todd Sabin <tsabin@optonline.net>
 *
 * $Id: packet-dcerpc-nspi.c,v 1.1 2002/05/23 23:45:22 guy Exp $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"

static int proto_nspi = -1;

static gint ett_nspi = -1;

static e_uuid_t uuid_nspi = { 0xf5cc5a18, 0x4264, 0x101a, { 0x8c, 0x59, 0x08, 0x00, 0x2b, 0x2f, 0x84, 0x26 } };
static guint16  ver_nspi = 56;

static dcerpc_sub_dissector nspi_dissectors[] = {
    { 0, "NspiBind", NULL, NULL },
    { 1, "NspiUnbind", NULL, NULL },
    { 2, "NspiUpdateStat", NULL, NULL },
    { 3, "NspiQueryRows", NULL, NULL },
    { 4, "NspiSeekEntries", NULL, NULL },
    { 5, "NspiGetMatches", NULL, NULL },
    { 6, "NspiResortRestriction", NULL, NULL },
    { 7, "NspiDNToEph", NULL, NULL },
    { 8, "NspiGetPropList", NULL, NULL },
    { 9, "NspiGetProps", NULL, NULL },
    { 10, "NspiCompareDNTs", NULL, NULL },
    { 11, "NspiModProps", NULL, NULL },
    { 12, "NspiGetHierarchyInfo", NULL, NULL },
    { 13, "NspiGetTemplateInfo", NULL, NULL },
    { 14, "NspiModLinkAttr", NULL, NULL },
    { 15, "NspiDeleteEntries", NULL, NULL },
    { 16, "NspiQueryColumns", NULL, NULL },
    { 17, "NspiGetNamesFromIDs", NULL, NULL },
    { 18, "NspiGetIDsFromNames", NULL, NULL },
    { 19, "NspiResolveNames", NULL, NULL },
    { 0, NULL, NULL, NULL },
};


void
proto_register_nspi (void)
{
   static gint *ett[] = {
       &ett_nspi,
   };
   proto_nspi = proto_register_protocol ("NSPI", "NSPI", "nspi");
   proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_nspi (void)
{
   /* Register the protocol as dcerpc */
   dcerpc_init_uuid (proto_nspi, ett_nspi, &uuid_nspi, ver_nspi, nspi_dissectors);
}
