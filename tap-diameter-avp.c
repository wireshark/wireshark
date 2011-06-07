/* tap-diameter-avp.c
 * Copyright 2010 Andrej Kuehnal <andrejk@freenet.de>
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

/*
 * This TAP enables extraction of most important diameter fields in text format.
 * - much more performance than -T text and -T pdml
 * - more powerfull than -T field and -z proto,colinfo
 * - exacltly one text line per diameter message
 * - multiple diameter messages in one frame supported
 *   E.g. one device watchdog answer and two credit control answers
 *        in one TCP packet produces 3 text lines.
 * - several fields with same name within one diameter message supported
 *   E.g. Multiple AVP(444) Subscription-Id-Data once with IMSI once with MSISDN
 * - several grouped AVPs supported
 *   E.g. Zero or more Multiple-Services-Credit-Control AVPs(456)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include "epan/packet_info.h"
#include <epan/tap.h>
#include <epan/epan_dissect.h>
#include <epan/stat_cmd_args.h>
#include "epan/value_string.h"
#include "epan/nstime.h"
#include "epan/ftypes/ftypes.h"
#include "epan/to_str.h"
#include "epan/dissectors/packet-diameter.h"


/* used to keep track of the statistics for an entire program interface */
typedef struct _diameteravp_t {
	guint32 frame;
	guint32 diammsg_toprocess;
	guint32 cmd_code;
	guint32 req_count;
	guint32 ans_count;
	guint32 paired_ans_count;
	gchar* filter;
} diameteravp_t;

/* Copied from proto.c */
static gboolean
tree_traverse_pre_order(proto_tree *tree, proto_tree_traverse_func func, gpointer data)
{
	proto_node *pnode = tree;
	proto_node *child;
	proto_node *current;

	if (func(pnode, data))
		return TRUE;

	child = pnode->first_child;
	while (child != NULL) {
		current = child;
		child = current->next;
		if (tree_traverse_pre_order((proto_tree *)current, func, data))
			return TRUE;
	}
	return FALSE;
}

static gboolean
diam_tree_to_csv(proto_node* node, gpointer data)
{
	char* val_str=NULL;
	char* val_tmp=NULL;
	ftenum_t ftype;
	field_info* fi;
	header_field_info	*hfi;
	if(!node) {
		fprintf(stderr,"traverse end: empty node. node='%p' data='%p'\n",node,data);
		return FALSE;
	}
	fi=node->finfo;
	hfi=fi ? fi->hfinfo : NULL;
	if(!hfi) {
		fprintf(stderr,"traverse end: hfi not found. node='%p'\n",node);
		return FALSE;
	}
	ftype=fi->value.ftype->ftype;
	if (ftype!=FT_NONE&&ftype!=FT_PROTOCOL) {
		/* convert value to string */
		if(fi->value.ftype->val_to_string_repr)
		{
			val_tmp=fvalue_to_string_repr(&fi->value,FTREPR_DISPLAY,NULL);
			if(val_tmp)
			{
				val_str=ep_strdup(val_tmp);
				g_free(val_tmp);
			}
		}
		if(!val_str)
			val_str=ep_strdup_printf("unsupported type: %s",ftype_name(ftype));

		/*printf("traverse: name='%s', abbrev='%s',desc='%s', val='%s'\n",hfi->name,hfi->abbrev,ftype_name(hfi->type),val_str);*/
		printf("%s='%s' ",hfi->name,val_str);
	}
	return FALSE;
}

static int
diameteravp_packet(void *pds, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pdi)
{
	int ret = 0;
	double resp_time=0.;
	gboolean is_request=TRUE;
	guint32 cmd_code=0;
	guint32 req_frame=0;
	guint32 ans_frame=0;
	guint32 diam_child_node=0;
	proto_node* current=NULL;
	proto_node* node = NULL;
	header_field_info* hfi=NULL;
	field_info* finfo=NULL;
	const diameter_req_ans_pair_t* dp=pdi;
	diameteravp_t *ds=NULL;

	/* Validate paramerers. */
	if(!dp || !edt || !edt->tree)
		return ret;

	/* Several diameter messages within one frame are possible.                    *
	 * Check if we processing the message in same frame like befor or in new frame.*/
	ds=(diameteravp_t *)pds;
	if(pinfo->fd->num > ds->frame) {
		ds->frame=pinfo->fd->num;
		ds->diammsg_toprocess=0;
	} else {
			ds->diammsg_toprocess+=1;
	}

	/* Extract data from request/answer pair provided by diameter dissector.*/
	is_request=dp->processing_request;
	cmd_code=dp->cmd_code;
	req_frame=dp->req_frame;
	ans_frame=dp->ans_frame;
	if(!is_request) {
		nstime_t ns;
		nstime_delta(&ns, &pinfo->fd->abs_ts, &dp->req_time);
		resp_time=nstime_to_sec(&ns);
		resp_time=resp_time<0?0.:resp_time;
	}

	/* Check command code provided by command line option.*/
	if (ds->cmd_code && ds->cmd_code!=cmd_code)
		return ret;

	/* Loop over top level nodes */
	node = edt->tree->first_child;
	while (node != NULL) {
		current = node;
		node = current->next;
		finfo=current->finfo;
		hfi=finfo ? finfo->hfinfo : NULL;
		/*fprintf(stderr,"DEBUG: diameteravp_packet %d %p %p node=%p abbrev=%s\n",cmd_code,edt,edt->tree,current,hfi->abbrev);*/
		/* process current diameter subtree in the current frame. */
		if(hfi && hfi->abbrev && strcmp(hfi->abbrev,"diameter")==0) {
			/* Process current diameter message in the frame */
			if (ds->diammsg_toprocess==diam_child_node) {
				if(is_request) {
					ds->req_count++;
				} else {
					ds->ans_count++;
					if (req_frame>0)
						ds->paired_ans_count++;
				}
				/* Output frame data.*/
				printf("frame='%d' time='%f' src='%s' srcport='%d' dst='%s' dstport='%d' proto='diameter' msgnr='%d' is_request='%d' cmd='%d' req_frame='%d' ans_frame='%d' resp_time='%f' ",
								pinfo->fd->num,nstime_to_sec(&pinfo->fd->abs_ts),ep_address_to_str(&pinfo->src),pinfo->srcport,ep_address_to_str(&pinfo->dst), pinfo->destport,ds->diammsg_toprocess,is_request,cmd_code,req_frame,ans_frame,resp_time);
				/* Visit selected nodes of one diameter message.*/
				tree_traverse_pre_order(current, diam_tree_to_csv, &ds);
				/* End of message.*/
				printf("\n");
				/*printf("hfi: name='%s', msg_curr='%d' abbrev='%s',type='%s'\n",hfi->name,diam_child_node,hfi->abbrev,ftype_name(hfi->type));*/
			}
			diam_child_node++;
		}
	}
	return ret;
}

static void
diameteravp_draw(void* pds)
{
	diameteravp_t *ds=(diameteravp_t *)pds;
	/* printing results */
	printf("=== Diameter Summary ===\nrequset count:\t%d\nanswer count:\t%d\nreq/ans pairs:\t%d\n",ds->req_count,ds->ans_count,ds->paired_ans_count);
}


static void
diameteravp_init(const char *optarg, void* userdata _U_)
{
	diameteravp_t *ds;
	gchar* field=NULL;
	gchar** tokens;
	guint opt_count=0;
	guint opt_idx=0;
	GString* filter=NULL;
	GString* error_string=NULL;

	ds=g_malloc(sizeof(diameteravp_t));
	ds->frame=0;
	ds->diammsg_toprocess=0;
	ds->cmd_code=0;
	ds->req_count=0;
	ds->ans_count=0;
	ds->paired_ans_count=0;
	ds->filter=NULL;

	filter=g_string_new("diameter");

	/* Split command line options. */
	tokens = g_strsplit(optarg,",", 1024);
	opt_count=0;
	while (tokens[opt_count])
		opt_count++;
	if (opt_count>2)
		ds->cmd_code=(guint32)atoi(tokens[2]);

	/* Loop over diameter field names. */
	for(opt_idx=3;opt_idx<opt_count;opt_idx++)
	{
		/* Current field from command line arguments. */
		field=tokens[opt_idx];
		/* Connect all requested fields with logical OR. */
		g_string_append(filter,"||");
		/* Prefix field name with "diameter." by default. */
		if(!strchr(field,'.'))
			g_string_append(filter, "diameter.");
		/* Append field name to the filter. */
		g_string_append(filter, field);
	}
	g_strfreev(tokens);
	ds->filter=g_string_free(filter,FALSE);

	error_string=register_tap_listener("diameter", ds, ds->filter, 0, NULL, diameteravp_packet, diameteravp_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(ds);

		fprintf(stderr, "tshark: Couldn't register diam,csv tap: %s\n",
				error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}


void
register_tap_listener_diameteravp(void)
{
	register_stat_cmd_arg("diameter,avp", diameteravp_init, NULL);
}

