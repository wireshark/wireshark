/* packet-smb-sidsnooping.c
 * Routines for snooping SID to name mappings
 * Copyright 2003, Ronnie Sahlberg
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include "epan/packet_info.h"
#include "epan/epan_dissect.h"
#include "epan/proto.h"
#include <epan/tap.h>
#include <epan/emem.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "register.h"
#include <epan/dissectors/packet-smb.h>
#include "packet-smb-sidsnooping.h"

static int hf_lsa = -1;
static int hf_lsa_info_level = -1;
static int hf_lsa_opnum = -1;
static int hf_lsa_domain = -1;
static int hf_nt_domain_sid = -1;
static int hf_samr_hnd = -1;
static int hf_samr_rid = -1;
static int hf_samr_acct_name = -1;
static int hf_samr_level = -1;



GHashTable *sid_name_table = NULL;


static GHashTable *ctx_handle_table = NULL;


static gboolean lsa_policy_information_tap_installed = FALSE;
static gboolean samr_query_dispinfo_tap_installed = FALSE;


char *
find_sid_name(char *sid)
{
	sid_name *sn;
	sid_name old_sn;

	old_sn.sid=sid;
	sn=g_hash_table_lookup(sid_name_table, &old_sn);
	if(!sn){
		return NULL;
	}
	return sn->name;
}

static void
add_sid_name_mapping(char *sid, char *name)
{
	sid_name *sn;
	sid_name old_sn;

	old_sn.sid=sid;
	sn=g_hash_table_lookup(sid_name_table, &old_sn);
	if(sn){
		return;
	}

	sn=se_alloc(sizeof(sid_name));
	sn->sid=g_strdup(sid);
	sn->name=g_strdup(name);
	g_hash_table_insert(sid_name_table, sn, sn);
}



/*
 * QueryDispInfo :
 * level  1 : user displayinfo 1
 */
static int
samr_query_dispinfo(void *dummy _U_, packet_info *pinfo, epan_dissect_t *edt, const void *pri)
{
	const dcerpc_info *ri=pri;
	void *old_ctx=NULL;
	char *pol_name;
	char *sid;
	int sid_len;
	int num_rids;
	int num_names;
	GPtrArray *gp;
	GPtrArray *gp_rids;
	GPtrArray *gp_names;
	field_info *fi;
	field_info *fi_rid;
	field_info *fi_name;
	char sid_name[256];
	int info_level;

	gp=proto_get_finfo_ptr_array(edt->tree, hf_samr_level);
	if(!gp || gp->len!=1){
		return 0;
	}
	fi=gp->pdata[0];
	info_level=fi->value.value.integer;

	if(info_level!=1){
		return 0;
	}

	if(!ri){
		return 0;
	}
	if(!ri->call_data){
		return 0;
	}
	if(ri->ptype == PDU_REQ){
		gp=proto_get_finfo_ptr_array(edt->tree, hf_samr_hnd);
		if(!gp || gp->len!=1){
			return 0;
		}
		fi=gp->pdata[0];

		old_ctx=g_hash_table_lookup(ctx_handle_table, GINT_TO_POINTER(pinfo->fd->num));
		if(old_ctx){
			g_hash_table_remove(ctx_handle_table, GINT_TO_POINTER(pinfo->fd->num));
		}
		if(!old_ctx){
			old_ctx=se_alloc(20);
			memcpy(old_ctx, fi->value.value.bytes->data, 20);
		}
		g_hash_table_insert(ctx_handle_table, GINT_TO_POINTER(pinfo->fd->num), old_ctx);

		return 0;
	}

	if(!ri->call_data->req_frame){
		return 0;
	}

	old_ctx=g_hash_table_lookup(ctx_handle_table, GINT_TO_POINTER(ri->call_data->req_frame));
	if(!old_ctx){
		return 0;
	}

	if (!dcerpc_smb_fetch_pol(old_ctx, &pol_name, NULL, NULL, ri->call_data->req_frame)) {
		return 0;
	}

	if (!pol_name)
		return 0;

	sid=strstr(pol_name,"S-1-5");
	if(!sid){
		return 0;
	}

	for(sid_len=4;1;sid_len++){
		if((sid[sid_len]>='0') && (sid[sid_len]<='9')){
			continue;
		}
		if(sid[sid_len]=='-'){
			continue;
		}
		break;
	}

	gp_rids=proto_get_finfo_ptr_array(edt->tree, hf_samr_rid);
	if(!gp_rids || gp_rids->len<1){
		return 0;
	}
	num_rids=gp_rids->len;
	gp_names=proto_get_finfo_ptr_array(edt->tree, hf_samr_acct_name);
	if(!gp_names || gp_names->len<1){
		return 0;
	}
	num_names=gp_names->len;

	if(num_rids>num_names){
		num_rids=num_names;
	}

	for(;num_rids;num_rids--){
		int len=sid_len;

		fi_rid=gp_rids->pdata[num_rids-1];
		fi_name=gp_names->pdata[num_rids-1];
		strncpy(sid_name, sid, len);
		sid_name[len++]='-';
		len+=g_snprintf(sid_name+len, 256-len, "%d",fi_rid->value.value.integer);
		sid_name[len]=0;
		add_sid_name_mapping(sid_name, fi_name->value.value.string);
	}
	return 1;
}

/*
 * PolicyInformation :
 * level  3 : PRIMARY_DOMAIN_INFO lsa.domain_sid -> lsa.domain
 * level  5 : ACCOUNT_DOMAIN_INFO lsa.domain_sid -> lsa.domain
 * level 12 : DNS_DOMAIN_INFO     lsa.domain_sid -> lsa.domain
 */
static int
lsa_policy_information(void *dummy _U_, packet_info *pinfo _U_, epan_dissect_t *edt, const void *pri _U_)
{
	GPtrArray *gp;
	field_info *fi;
	char *domain;
	char *sid;
	int info_level;

	gp=proto_get_finfo_ptr_array(edt->tree, hf_lsa_info_level);
	if(!gp || gp->len!=1){
		return 0;
	}
	fi=gp->pdata[0];
	info_level=fi->value.value.integer;

	switch(info_level){
	case 3:
	case 5:
	case 12:
		gp=proto_get_finfo_ptr_array(edt->tree, hf_lsa_domain);
		if(!gp || gp->len!=1){
			return 0;
		}
		fi=gp->pdata[0];
		domain=fi->value.value.string;

		gp=proto_get_finfo_ptr_array(edt->tree, hf_nt_domain_sid);
		if(!gp || gp->len!=1){
			return 0;
		}
		fi=gp->pdata[0];
		sid=fi->value.value.string;

		add_sid_name_mapping(sid, domain);
		break;
	}
	return 0;
}

static gboolean
free_all_sid_names(gpointer key_arg, gpointer value _U_, gpointer user_data _U_)
{
	sid_name *sn = (sid_name *)key_arg;

	if(sn->sid){
		g_free((gpointer)sn->sid);
		sn->sid=NULL;
	}
	if(sn->name){
		g_free((gpointer)sn->name);
		sn->name=NULL;
	}
	return TRUE;
}

static gint
sid_name_equal(gconstpointer k1, gconstpointer k2)
{
	const sid_name *sn1 = (const sid_name *)k1;
	const sid_name *sn2 = (const sid_name *)k2;
	
	return !strcmp(sn1->sid, sn2->sid);
}

static guint
sid_name_hash(gconstpointer k)
{
	const sid_name *sn = (const sid_name *)k;
	int i, sum;

	for(sum=0,i=strlen(sn->sid)-1;i>=0;i--){
		sum+=sn->sid[i];
	}

	return sum;
}


static gboolean
free_all_ctx_handle(gpointer key_arg _U_, gpointer value _U_, gpointer user_data _U_)
{
	return TRUE;
}
static gint
ctx_handle_equal(gconstpointer k1, gconstpointer k2)
{
	int sn1 = GPOINTER_TO_INT(k1);
	int sn2 = GPOINTER_TO_INT(k2);
	
	return sn1==sn2;
}

static guint
ctx_handle_hash(gconstpointer k)
{
	int sn = GPOINTER_TO_INT(k);

	return sn;
}


static void
sid_snooping_init(void)
{
	header_field_info *hfi;
	GString *error_string;

	if(lsa_policy_information_tap_installed){
		remove_tap_listener(&lsa_policy_information_tap_installed);
		lsa_policy_information_tap_installed=FALSE;
	}
	if(samr_query_dispinfo_tap_installed){
		remove_tap_listener(&samr_query_dispinfo_tap_installed);
		samr_query_dispinfo_tap_installed=FALSE;
	}

	if(sid_name_table){
		g_hash_table_foreach_remove(sid_name_table, free_all_sid_names, NULL);
		sid_name_table=NULL;
	}
	if(ctx_handle_table){
		g_hash_table_foreach_remove(ctx_handle_table, free_all_ctx_handle, NULL);
		ctx_handle_table=NULL;
	}


	if(!sid_name_snooping){
		return;
	}


	sid_name_table=g_hash_table_new(sid_name_hash, sid_name_equal);


	ctx_handle_table=g_hash_table_new(ctx_handle_hash, ctx_handle_equal);


	hf_lsa=proto_get_id_by_filter_name("lsa");

	hfi=proto_registrar_get_byname("lsa.opnum");
	if(hfi){
		hf_lsa_opnum=hfi->id;
	}

	hfi=proto_registrar_get_byname("nt.domain_sid");
	if(hfi){
		hf_nt_domain_sid=hfi->id;
	}

	hfi=proto_registrar_get_byname("lsa.domain");
	if(hfi){
		hf_lsa_domain=hfi->id;
	}

	hfi=proto_registrar_get_byname("lsa.info.level");
	if(hfi){
		hf_lsa_info_level=hfi->id;
	}

	hfi=proto_registrar_get_byname("samr.hnd");
	if(hfi){
		hf_samr_hnd=hfi->id;
	}
	hfi=proto_registrar_get_byname("samr.rid");
	if(hfi){
		hf_samr_rid=hfi->id;
	}
	hfi=proto_registrar_get_byname("samr.acct_name");
	if(hfi){
		hf_samr_acct_name=hfi->id;
	}
	hfi=proto_registrar_get_byname("samr.level");
	if(hfi){
		hf_samr_level=hfi->id;
	}



	error_string=register_tap_listener("dcerpc", &lsa_policy_information_tap_installed, "lsa.policy_information and ( lsa.info.level or lsa.domain or nt.domain_sid )", NULL, lsa_policy_information, NULL);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */

		fprintf(stderr, "tethereal: Couldn't register proto_reg_handoff_smb_sidsnooping()/lsa_policy_information tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
	lsa_policy_information_tap_installed=TRUE;

	error_string=register_tap_listener("dcerpc", &samr_query_dispinfo_tap_installed, "samr and samr.opnum==40 and ( samr.hnd or samr.rid or samr.acct_name or samr.level )", NULL, samr_query_dispinfo, NULL);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */

		fprintf(stderr, "tethereal: Couldn't register proto_reg_handoff_smb_sidsnooping()/samr_query_dispinfo tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
	samr_query_dispinfo_tap_installed=TRUE;
}

void
proto_register_smb_sidsnooping(void)
{
	register_init_routine(sid_snooping_init);
}

void
proto_reg_handoff_smb_sidsnooping(void)
{
}
