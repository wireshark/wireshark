/* tap-protohierstat.c
 * protohierstat   2002 Ronnie Sahlberg
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

/* This module provides ProtocolHierarchyStatistics for tshark */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "epan/packet_info.h"
#include "epan/epan_dissect.h"
#include "epan/proto.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>

void register_tap_listener_protohierstat(void);

typedef struct _phs_t {
	struct _phs_t *sibling;
	struct _phs_t *child;
	struct _phs_t *parent;
	char *filter;
	int protocol;
	const char *proto_name;
	guint32 frames;
	guint64 bytes;
} phs_t;


static phs_t *
new_phs_t(phs_t *parent)
{
	phs_t *rs;
	rs=g_new(phs_t,1);
	rs->sibling=NULL;
	rs->child=NULL;
	rs->parent=parent;
	rs->filter=NULL;
	rs->protocol=-1;
	rs->proto_name=NULL;
	rs->frames=0;
	rs->bytes=0;
	return rs;
}


static int
protohierstat_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_)
{
	phs_t *rs=(phs_t *)prs;
	phs_t *tmprs;
	proto_node *node;
	field_info *fi;

	if(!edt){
		return 0;
	}
	if(!edt->tree){
		return 0;
	}
	if(!edt->tree->first_child){
		return 0;
	}

	for(node=edt->tree->first_child;node;node=node->next){
		fi=PNODE_FINFO(node);

		/* first time we saw a protocol at this leaf */
		if(rs->protocol==-1){
			rs->protocol=fi->hfinfo->id;
			rs->proto_name=fi->hfinfo->abbrev;
			rs->frames=1;
			rs->bytes=pinfo->fd->pkt_len;
			rs->child=new_phs_t(rs);
			rs=rs->child;
			continue;
		}

		/* find this protocol in the list of siblings */
		for(tmprs=rs;tmprs;tmprs=tmprs->sibling){
			if(tmprs->protocol==fi->hfinfo->id){
				break;
			}
		}

		/* not found, then we must add it to the end of the list */
		if(!tmprs){
			for(tmprs=rs;tmprs->sibling;tmprs=tmprs->sibling)
				;
			tmprs->sibling=new_phs_t(rs->parent);
			rs=tmprs->sibling;
			rs->protocol=fi->hfinfo->id;
			rs->proto_name=fi->hfinfo->abbrev;
		} else {
			rs=tmprs;
		}

		rs->frames++;
		rs->bytes+=pinfo->fd->pkt_len;

		if(!rs->child){
			rs->child=new_phs_t(rs);
		}
		rs=rs->child;
	}
	return 1;
}

static void
phs_draw(phs_t *rs, int indentation)
{
	int i, stroff;
#define MAXPHSLINE 80
	char str[MAXPHSLINE];
	for(;rs;rs=rs->sibling){
		if(rs->protocol==-1){
			return;
		}
		str[0]=0;
		stroff=0;
		for(i=0;i<indentation;i++){
			if(i>15){
				stroff+=g_snprintf(str+stroff, MAXPHSLINE-stroff, "...");
				break;
			}
			stroff+=g_snprintf(str+stroff, MAXPHSLINE-stroff, "  ");
		}
		g_snprintf(str+stroff, MAXPHSLINE-stroff, "%s", rs->proto_name);
		printf("%-40s frames:%d bytes:%" G_GINT64_MODIFIER "d\n",str, rs->frames, rs->bytes);
		phs_draw(rs->child, indentation+1);
	}
}

static void
protohierstat_draw(void *prs)
{
	phs_t *rs=(phs_t *)prs;

	printf("\n");
	printf("===================================================================\n");
	printf("Protocol Hierarchy Statistics\n");
	printf("Filter: %s\n\n",rs->filter?rs->filter:"");
	phs_draw(rs,0);
	printf("===================================================================\n");
}


static void
protohierstat_init(const char *opt_arg, void* userdata _U_)
{
	phs_t *rs;
	int pos=0;
	const char *filter=NULL;
	GString *error_string;

	if(strcmp("io,phs",opt_arg)==0){
		/* No arguments */
	} else if(sscanf(opt_arg,"io,phs,%n",&pos)==0){
		if(pos){
			filter=opt_arg+pos;
		}
	} else {
		fprintf(stderr, "tshark: invalid \"-z io,phs[,<filter>]\" argument\n");
		exit(1);
	}

	rs=new_phs_t(NULL);

	if(filter){
		rs->filter=g_strdup(filter);
	} else {
		rs->filter=NULL;
	}

	error_string=register_tap_listener("frame", rs, filter, TL_REQUIRES_PROTO_TREE, NULL, protohierstat_packet, protohierstat_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(rs->filter);
		g_free(rs);

		fprintf(stderr, "tshark: Couldn't register io,phs tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}


void
register_tap_listener_protohierstat(void)
{
	register_stat_cmd_arg("io,phs", protohierstat_init, NULL);
}

