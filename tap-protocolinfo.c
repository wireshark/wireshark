/* tap-protocolinfo.c
 * protohierstat   2002 Ronnie Sahlberg
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* This module provides Protocol Column Info tap for tethereal */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include "epan/epan_dissect.h"
#include "epan/column-utils.h"
#include "epan/proto.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include "register.h"

typedef struct _pci_t {
	char *filter;
	int hf_index;
} pci_t;


static int
protocolinfo_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_)
{
	pci_t *rs=prs;
	GPtrArray *gp;
	guint i;
	char *str;

	/*
	 * XXX - there needs to be a way for "protocolinfo_init()" to
	 * find out whether the columns are being generated and, if not,
	 * to report an error and exit, as the whole point of this tap
	 * is to modify the columns, and if the columns aren't being
	 * displayed, that makes this tap somewhat pointless.
	 *
	 * To prevent a crash, we check whether pinfo->cinfo is null
	 * and, if so, we report that error and exit.
	 */
	if (pinfo->cinfo == NULL) {
		fprintf(stderr, "tethereal: the proto,colinfo tap doesn't work if the columns aren't being printed.\n");
		exit(1);
	}
	gp=proto_get_finfo_ptr_array(edt->tree, rs->hf_index);
	if(!gp){
		return 0;
	}

	for(i=0;i<gp->len;i++){
		str=proto_construct_dfilter_string(gp->pdata[i], NULL);
		if(str){
			col_append_fstr(pinfo->cinfo, COL_INFO, "  %s",str);
		}
	}
	return 0;
}



static void
protocolinfo_init(const char *optarg, void* userdata _U_)
{
	pci_t *rs;
	const char *field=NULL;
	const char *filter=NULL;
	header_field_info *hfi;
	GString *error_string;

	if(!strncmp("proto,colinfo,",optarg,14)){
		filter=optarg+14;
		field=strchr(filter,',');
		if(field){
			field+=1;  /* skip the ',' */
		}
	}
	if(!field){
		fprintf(stderr, "tethereal: invalid \"-z proto,colinfo,<filter>,<field>\" argument\n");
		exit(1);
	}

	hfi=proto_registrar_get_byname(field);
	if(!hfi){
		fprintf(stderr, "tethereal: Field \"%s\" doesn't exist.\n", field);
		exit(1);
	}

	rs=g_malloc(sizeof(pci_t));
	rs->hf_index=hfi->id;
	if((field-filter)>1){
		rs->filter=g_malloc(field-filter);
		strncpy(rs->filter,filter,(field-filter)-1);
		rs->filter[(field-filter)-1]=0;
	} else {
		rs->filter=NULL;
	}

	error_string=register_tap_listener("frame", rs, rs->filter, NULL, protocolinfo_packet, NULL);
	if(error_string){
		/* error, we failed to attach to the tap. complain and clean up */
		fprintf(stderr, "tethereal: Couldn't register proto,colinfo tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		if(rs->filter){
			g_free(rs->filter);
		}
		g_free(rs);

		exit(1);
	}
}


void
register_tap_listener_protocolinfo(void)
{
	register_stat_cmd_arg("proto,colinfo,", protocolinfo_init,NULL);
}

