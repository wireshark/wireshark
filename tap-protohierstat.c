/* tap-protohierstat.c
 * protohierstat   2002 Ronnie Sahlberg
 *
 * $Id$
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

/* This module provides ProtocolHierarchyStatistics for tethereal */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include "epan/packet_info.h"
#include "epan/epan_dissect.h"
#include "epan/proto.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include "register.h"

typedef struct _phs_t {
	struct _phs_t *sibling;
	struct _phs_t *child;
	struct _phs_t *parent;
	char *filter;
	int protocol;
	const char *proto_name;
	guint32 frames;
	guint32 bytes;
} phs_t;


static phs_t *
new_phs_t(phs_t *parent)
{
	phs_t *rs;
	rs=g_malloc(sizeof(phs_t));
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
	phs_t *rs=prs;
	phs_t *tmprs;
	proto_tree *tree;
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

	for(tree=edt->tree->first_child;tree;tree=tree->next){
		fi=PITEM_FINFO(tree);

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
		stroff+=g_snprintf(str+stroff, MAXPHSLINE-stroff, rs->proto_name);
		printf("%-40s frames:%d bytes:%d\n",str, rs->frames, rs->bytes);
		phs_draw(rs->child, indentation+1);
	}
}

static void
protohierstat_draw(void *prs)
{
	phs_t *rs=prs;

	printf("\n");
	printf("===================================================================\n");
	printf("Protocol Hierarchy Statistics\n");
	printf("Filter: %s\n\n",rs->filter?rs->filter:"");
	phs_draw(rs,0);
	printf("===================================================================\n");
}


static void
protohierstat_init(const char *optarg, void* userdata _U_)
{
	phs_t *rs;
	int pos=0;
	const char *filter=NULL;
	GString *error_string;

	if(!strcmp("io,phs",optarg)){
		filter="frame";
	} else if(sscanf(optarg,"io,phs,%n",&pos)==0){
		if(pos){
			filter=optarg+pos;
		} else {
			/* We must use a filter to guarantee that edt->tree
			   will be populated. "frame" matches everything so
			   that one is used instead of no filter.
			*/
			filter="frame"; 
		}
	} else {
		fprintf(stderr, "tethereal: invalid \"-z io,phs[,<filter>]\" argument\n");
		exit(1);
	}

	rs=new_phs_t(NULL);

	if(filter){
		rs->filter=g_malloc(strlen(filter)+1);
		strcpy(rs->filter, filter);
	} else {
		rs->filter=NULL;
	}

	error_string=register_tap_listener("frame", rs, filter, NULL, protohierstat_packet, protohierstat_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(rs->filter);
		g_free(rs);

		fprintf(stderr, "tethereal: Couldn't register io,phs tap: %s\n",
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

