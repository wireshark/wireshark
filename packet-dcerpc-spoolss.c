/* packet-dcerpc-spoolss.c
 * Routines for SMB \\PIPE\\spoolss packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-spoolss.c,v 1.1 2001/11/21 02:08:57 guy Exp $
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

#include <glib.h>
#include "packet.h"
#include "packet-dcerpc.h"
#include "packet-dcerpc-spoolss.h"

static int proto_dcerpc_spoolss = -1;
static gint ett_dcerpc_spoolss = -1;

static e_uuid_t uuid_dcerpc_spoolss = {
        0x12345678, 0x1234, 0xabcd,
        { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab }
};

static guint16 ver_dcerpc_spoolss = 1;

static dcerpc_sub_dissector dcerpc_spoolss_dissectors[] = {
        { SPOOLSS_ENUMPRINTERS, "SPOOLSS_ENUMPRINTERS", NULL, NULL },
        { SPOOLSS_SETJOB, "SPOOLSS_SETJOB", NULL, NULL },
        { SPOOLSS_GETJOB, "SPOOLSS_GETJOB", NULL, NULL },
        { SPOOLSS_ENUMJOBS, "SPOOLSS_ENUMJOBS", NULL, NULL },
        { SPOOLSS_ADDPRINTER, "SPOOLSS_ADDPRINTER", NULL, NULL },
        { SPOOLSS_DELETEPRINTER, "SPOOLSS_DELETEPRINTER", NULL, NULL },
        { SPOOLSS_SETPRINTER, "SPOOLSS_SETPRINTER", NULL, NULL },
        { SPOOLSS_GETPRINTER, "SPOOLSS_GETPRINTER", NULL, NULL },
        { SPOOLSS_ADDPRINTERDRIVER, "SPOOLSS_ADDPRINTERDRIVER", NULL, NULL },
        { SPOOLSS_ENUMPRINTERDRIVERS, "SPOOLSS_ENUMPRINTERDRIVERS", NULL, NULL },
        { SPOOLSS_GETPRINTERDRIVERDIRECTORY, "SPOOLSS_GETPRINTERDRIVERDIRECTORY", NULL, NULL },
        { SPOOLSS_DELETEPRINTERDRIVER, "SPOOLSS_DELETEPRINTERDRIVER", NULL, NULL },
        { SPOOLSS_ADDPRINTPROCESSOR, "SPOOLSS_ADDPRINTPROCESSOR", NULL, NULL },
        { SPOOLSS_ENUMPRINTPROCESSORS, "SPOOLSS_ENUMPRINTPROCESSORS", NULL, NULL },
        { SPOOLSS_STARTDOCPRINTER, "SPOOLSS_STARTDOCPRINTER", NULL, NULL },
        { SPOOLSS_STARTPAGEPRINTER, "SPOOLSS_STARTPAGEPRINTER", NULL, NULL },
        { SPOOLSS_WRITEPRINTER, "SPOOLSS_WRITEPRINTER", NULL, NULL },
        { SPOOLSS_ENDPAGEPRINTER, "SPOOLSS_ENDPAGEPRINTER", NULL, NULL },
        { SPOOLSS_ABORTPRINTER, "SPOOLSS_ABORTPRINTER", NULL, NULL },
        { SPOOLSS_ENDDOCPRINTER, "SPOOLSS_ENDDOCPRINTER", NULL, NULL },
        { SPOOLSS_ADDJOB, "SPOOLSS_ADDJOB", NULL, NULL },
        { SPOOLSS_SCHEDULEJOB, "SPOOLSS_SCHEDULEJOB", NULL, NULL },
        { SPOOLSS_GETPRINTERDATA, "SPOOLSS_GETPRINTERDATA", NULL, NULL },
        { SPOOLSS_SETPRINTERDATA, "SPOOLSS_SETPRINTERDATA", NULL, NULL },
        { SPOOLSS_CLOSEPRINTER, "SPOOLSS_CLOSEPRINTER", NULL, NULL },
        { SPOOLSS_ADDFORM, "SPOOLSS_ADDFORM", NULL, NULL },
        { SPOOLSS_DELETEFORM, "SPOOLSS_DELETEFORM", NULL, NULL },
        { SPOOLSS_GETFORM, "SPOOLSS_GETFORM", NULL, NULL },
        { SPOOLSS_SETFORM, "SPOOLSS_SETFORM", NULL, NULL },
        { SPOOLSS_ENUMFORMS, "SPOOLSS_ENUMFORMS", NULL, NULL },
        { SPOOLSS_ENUMPORTS, "SPOOLSS_ENUMPORTS", NULL, NULL },
        { SPOOLSS_ENUMMONITORS, "SPOOLSS_ENUMMONITORS", NULL, NULL },
        { SPOOLSS_ENUMPRINTPROCDATATYPES, "SPOOLSS_ENUMPRINTPROCDATATYPES", NULL, NULL },
        { SPOOLSS_GETPRINTERDRIVER2, "SPOOLSS_GETPRINTERDRIVER2", NULL, NULL },
        { SPOOLSS_FCPN, "SPOOLSS_FCPN", NULL, NULL },
        { SPOOLSS_REPLYOPENPRINTER, "SPOOLSS_REPLYOPENPRINTER", NULL, NULL },
        { SPOOLSS_REPLYCLOSEPRINTER, "SPOOLSS_REPLYCLOSEPRINTER", NULL, NULL },
        { SPOOLSS_RFFPCNEX, "SPOOLSS_RFFPCNEX", NULL, NULL },
        { SPOOLSS_RRPCN, "SPOOLSS_RRPCN", NULL, NULL },
        { SPOOLSS_RFNPCNEX, "SPOOLSS_RFNPCNEX", NULL, NULL },
        { SPOOLSS_OPENPRINTEREX, "SPOOLSS_OPENPRINTEREX", NULL, NULL },
        { SPOOLSS_ADDPRINTEREX, "SPOOLSS_ADDPRINTEREX", NULL, NULL },
        { SPOOLSS_ENUMPRINTERDATA, "SPOOLSS_ENUMPRINTERDATA", NULL, NULL },
        { SPOOLSS_DELETEPRINTERDATA, "SPOOLSS_DELETEPRINTERDATA", NULL, NULL },
        { SPOOLSS_GETPRINTERDATAEX, "SPOOLSS_GETPRINTERDATAEX", NULL, NULL },
        { SPOOLSS_SETPRINTERDATAEX, "SPOOLSS_SETPRINTERDATAEX", NULL, NULL },

        {0, NULL, NULL,  NULL },
};

void 
proto_register_dcerpc_spoolss(void)
{
        static gint *ett[] = {
                &ett_dcerpc_spoolss,
        };

        proto_dcerpc_spoolss = proto_register_protocol(
                "Microsoft Spool Subsystem", "SPOOLSS", "spoolss");

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_spoolss(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_spoolss, ett_dcerpc_spoolss, 
                         &uuid_dcerpc_spoolss, ver_dcerpc_spoolss, 
                         dcerpc_spoolss_dissectors);
}
