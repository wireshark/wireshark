/* packet-ypserv.c
 * Routines for ypserv dissection
 *
 * $Id: packet-ypserv.c,v 1.1 1999/11/10 17:23:54 nneul Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-smb.c
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


#include "packet-rpc.h"
#include "packet-ypserv.h"

static int proto_ypserv = -1;

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */
const vsff ypserv1_proc[] = {
	{ 0,	"NULL",		NULL,				NULL },
	{ YPPROC_ALL,	"ALL",		NULL,				NULL },
	{ YPPROC_CLEAR,	"CLEAR",		NULL,				NULL },
	{ YPPROC_DOMAIN,	"DOMAIN",		NULL,				NULL },
	{ YPPROC_DOMAIN_NONACK,	"DOMAIN_NONACK",		NULL,				NULL },
	{ YPPROC_FIRST,	"FIRST",		NULL,				NULL },
	{ YPPROC_MAPLIST,	"MAPLIST",		NULL,				NULL },
	{ YPPROC_MASTER,	"MASTER",		NULL,				NULL },
	{ YPPROC_MATCH,	"MATCH",		NULL,				NULL },
	{ YPPROC_NEXT,	"NEXT",		NULL,				NULL },
	{ YPPROC_ORDER,	"ORDER",		NULL,				NULL },
	{ YPPROC_XFR,	"XFR",		NULL,				NULL },
	{ 0,	NULL,		NULL,				NULL }
};
/* end of YPServ version 1 */

const vsff ypserv2_proc[] = {
    { 0,    "NULL",     NULL,               NULL },
    { YPPROC_ALL,   "ALL",      NULL,               NULL },
    { YPPROC_CLEAR, "CLEAR",        NULL,               NULL },
    { YPPROC_DOMAIN,    "DOMAIN",       NULL,               NULL },
    { YPPROC_DOMAIN_NONACK, "DOMAIN_NONACK",        NULL,               NULL },
    { YPPROC_FIRST, "FIRST",        NULL,               NULL },
    { YPPROC_MAPLIST,   "MAPLIST",      NULL,               NULL },
    { YPPROC_MASTER,    "MASTER",       NULL,               NULL },
    { YPPROC_MATCH, "MATCH",        NULL,               NULL },
    { YPPROC_NEXT,  "NEXT",     NULL,               NULL },
    { YPPROC_ORDER, "ORDER",        NULL,               NULL },
    { YPPROC_XFR,   "XFR",      NULL,               NULL },
    { 0,    NULL,       NULL,               NULL }
};
/* end of YPServ version 2 */


void
proto_register_ypserv(void)
{
	proto_ypserv = proto_register_protocol("Yellow Pages Service", "YPSERV");

	/* Register the protocol as RPC */
	rpc_init_prog(proto_ypserv, YPSERV_PROGRAM, ETT_YPSERV);
	/* Register the procedure tables */
	rpc_init_proc_table(YPSERV_PROGRAM, 1, ypserv1_proc);
	rpc_init_proc_table(YPSERV_PROGRAM, 2, ypserv2_proc);
}

