/* 
 * Copyright 2004, Irene Ruengeler <i.ruengeler [AT] fh-muenster.de>
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
#include <gtk/gtk.h>
#include "simple_dialog.h"      /* Both is used for error handling */
#include "globals.h"
#include "epan/packet_info.h"   /* Needed for packet_info */
#include <epan/tap.h>                /* Needed for register_tap_listener */
#include "tap_menu.h"
#include "dlg_utils.h"
#include "compat_macros.h"
#include "register.h"
#include <string.h>
#include "sctp_stat.h"
#include <math.h>


#define SCTP_HEARTBEAT_CHUNK_ID          4
#define SCTP_HEARTBEAT_ACK_CHUNK_ID      5
#define SCTP_ABORT_CHUNK_ID              6
#define SCTP_SHUTDOWN_CHUNK_ID           7
#define SCTP_SHUTDOWN_ACK_CHUNK_ID       8
#define SCTP_ERROR_CHUNK_ID              9
#define SCTP_COOKIE_ECHO_CHUNK_ID       10
#define SCTP_COOKIE_ACK_CHUNK_ID        11
#define SCTP_ECNE_CHUNK_ID              12
#define SCTP_CWR_CHUNK_ID               13
#define SCTP_SHUTDOWN_COMPLETE_CHUNK_ID 14
#define SCTP_FORWARD_TSN_CHUNK_ID      192
#define SCTP_ASCONF_ACK_CHUNK_ID      0x80
#define SCTP_PKTDROP_CHUNK_ID         0X81
#define SCTP_ASCONF_CHUNK_ID          0XC1
#define SCTP_IETF_EXT                  255

#define SCTP_ABORT_CHUNK_T_BIT	0x01


#define PARAMETER_TYPE_LENGTH            2
#define PARAMETER_LENGTH_LENGTH          2
#define PARAMETER_HEADER_LENGTH          (PARAMETER_TYPE_LENGTH + PARAMETER_LENGTH_LENGTH)

#define PARAMETER_HEADER_OFFSET          0
#define PARAMETER_TYPE_OFFSET            PARAMETER_HEADER_OFFSET
#define PARAMETER_LENGTH_OFFSET          (PARAMETER_TYPE_OFFSET + PARAMETER_TYPE_LENGTH)
#define PARAMETER_VALUE_OFFSET           (PARAMETER_LENGTH_OFFSET + PARAMETER_LENGTH_LENGTH)

#define IPV6_ADDRESS_LENGTH 16
#define IPV6_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET
#define IPV4_ADDRESS_LENGTH 4
#define IPV4_ADDRESS_OFFSET PARAMETER_VALUE_OFFSET
#define IPV4ADDRESS_PARAMETER_ID             0x0005
#define IPV6ADDRESS_PARAMETER_ID             0x0006

#define SACK_CHUNK_CUMULATIVE_TSN_ACK_LENGTH    4
#define SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET (CHUNK_VALUE_OFFSET + 0)
#define SACK_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH 4
#define SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET (SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET + \
                                                 SACK_CHUNK_CUMULATIVE_TSN_ACK_LENGTH)



static const value_string chunk_type_values[] = {
  { SCTP_DATA_CHUNK_ID,              "DATA" },
  { SCTP_INIT_CHUNK_ID,              "INIT" },
  { SCTP_INIT_ACK_CHUNK_ID,          "INIT_ACK" },
  { SCTP_SACK_CHUNK_ID,              "SACK" },
  { SCTP_HEARTBEAT_CHUNK_ID,         "HEARTBEAT" },
  { SCTP_HEARTBEAT_ACK_CHUNK_ID,     "HEARTBEAT_ACK" },
  { SCTP_ABORT_CHUNK_ID,             "ABORT" },
  { SCTP_SHUTDOWN_CHUNK_ID,          "SHUTDOWN" },
  { SCTP_SHUTDOWN_ACK_CHUNK_ID,      "SHUTDOWN_ACK" },
  { SCTP_ERROR_CHUNK_ID,             "ERROR" },
  { SCTP_COOKIE_ECHO_CHUNK_ID,       "COOKIE_ECHO" },
  { SCTP_COOKIE_ACK_CHUNK_ID,        "COOKIE_ACK" },
  { SCTP_ECNE_CHUNK_ID,              "ECNE" },
  { SCTP_CWR_CHUNK_ID,               "CWR" },
  { SCTP_SHUTDOWN_COMPLETE_CHUNK_ID, "SHUTDOWN_COMPLETE" },
  { SCTP_FORWARD_TSN_CHUNK_ID,       "FORWARD TSN" },
  { SCTP_ASCONF_ACK_CHUNK_ID,        "ASCONF_ACK" },
  { SCTP_PKTDROP_CHUNK_ID,           "PKTDROP" },
  { SCTP_ASCONF_CHUNK_ID,            "ASCONF" },
  { SCTP_IETF_EXT,                   "IETF_EXTENSION" },
  { 0,                               NULL } };


  #define FORWARD_STREAM						0
  #define BACKWARD_STREAM						1
  #define FORWARD_ADD_FORWARD_VTAG				2
  #define BACKWARD_ADD_FORWARD_VTAG				3
  #define BACKWARD_ADD_BACKWARD_VTAG			4
  #define ADDRESS_FORWARD_STREAM				5
  #define ADDRESS_BACKWARD_STREAM				6
  #define ADDRESS_FORWARD_ADD_FORWARD_VTAG		7
  #define ADDRESS_BACKWARD_ADD_FORWARD_VTAG		8
  #define ADDRESS_BACKWARD_ADD_BACKWARD_VTAG	9
  #define ASSOC_NOT_FOUND						10


static sctp_allassocs_info_t sctp_tapinfo_struct =	{0, NULL, FALSE, NULL};


static
void free_first(gpointer data, gpointer user_data _U_)
{
	fflush(stdout);
	g_free(data);
}

void tsn_free(gpointer data, gpointer user_data _U_)
{
tsn_t *tsn;
	tsn = (tsn_t *) data;
	if (tsn->tsns!=NULL)
	{
		g_list_foreach(tsn->tsns, free_first, NULL);
		g_list_free(tsn->tsns);
		tsn->tsns=NULL;
	}
}

void
reset(sctp_allassocs_info_t *tapdata )
{
GList* list;
sctp_assoc_info_t * info;

	list = g_list_first(tapdata->assoc_info_list);
		while (list)
		{
			info = (sctp_assoc_info_t *)  (list->data);

			if (info->addr1!=NULL)
			{
				g_list_foreach(info->addr1, free_first, NULL);
				g_list_free(info->addr1);
				info->addr1 = NULL;
			}

			if (info->addr2!=NULL)
			{
				g_list_foreach(info->addr2,free_first, NULL);
				g_list_free(info->addr2);
				info->addr2 = NULL;
			}

			if (info->error_info_list!=NULL)
			{
				g_list_foreach(info->error_info_list, free_first, NULL);
				g_list_free(info->error_info_list);
				info->error_info_list = NULL;
			}

			if (info->frame_numbers!=NULL)
			{
				g_list_free(info->frame_numbers);
				info->frame_numbers = NULL;
			}

			if (info->tsn1!=NULL)
			{
				g_list_foreach(info->tsn1,tsn_free, NULL);
				g_list_free(info->tsn1);
				info->tsn1 = NULL;
			}

			if (info->tsn2!=NULL)
			{
				g_list_foreach(info->tsn2,tsn_free, NULL);
				g_list_free(info->tsn2);
				info->tsn2 = NULL;
			}

			if (info->sack1!=NULL)
			{
				g_list_foreach(info->sack1,tsn_free, NULL);
				g_list_free(info->sack1);
				info->sack1 = NULL;
			}

			if (info->sack2!=NULL)
			{
				g_list_foreach(info->sack2,tsn_free, NULL);
				g_list_free(info->sack2);
				info->sack2 = NULL;
			}

			if (info->sort_tsn1!=NULL)
				g_array_free(info->sort_tsn1, TRUE);

			if (info->sort_tsn2!=NULL)
				g_array_free(info->sort_tsn2, TRUE);

			if (info->sort_sack1!=NULL)
				g_array_free(info->sort_sack1, TRUE);

			if (info->sort_sack2!=NULL)
				g_array_free(info->sort_sack2, TRUE);

			if (info->min_max!=NULL)
			{
				g_slist_foreach(info->min_max,free_first, NULL);
				info->min_max = NULL;
			}

			g_free(list->data);
			list = g_list_next(list);
		}
		g_list_free(tapdata->assoc_info_list);
	tapdata->sum_tvbs=0;
	tapdata->assoc_info_list=NULL;
}


static sctp_assoc_info_t * calc_checksum(struct _sctp_info * check_data, sctp_assoc_info_t * data)
{
guint8 ok=0;

if (check_data->adler32_calculated)
{
	data->n_adler32_calculated++;
	if (check_data->adler32_correct)
		data->n_adler32_correct++;
}
if (check_data->crc32c_calculated)
{
	data->n_crc32c_calculated++;
	if (check_data->crc32c_correct)
		data->n_crc32c_correct++;
}
if (data->n_adler32_calculated>0)
{
	if ((float)(data->n_adler32_correct*1.0/data->n_adler32_calculated)>0.5)
	{
		strcpy(data->checksum_type,"ADLER32");
		data->n_checksum_errors=(data->n_adler32_calculated-data->n_adler32_correct);
		ok=1;
	}
}

if (data->n_crc32c_calculated>0)
{
	if ((float)(data->n_crc32c_correct*1.0/data->n_crc32c_calculated)>0.5)
	{
		strcpy(data->checksum_type,"CRC32C");
		data->n_checksum_errors=data->n_crc32c_calculated-data->n_crc32c_correct;
		ok=1;
	}
}

if (ok==0)
{
	strcpy(data->checksum_type,"UNKNOWN");
	data->n_checksum_errors=0;
}

	return data;

}


gint sctp_assoc_vtag_cmp(gconstpointer aa, gconstpointer bb)
{

	const struct _sctp_assoc_info* a = aa;
	const struct _sctp_assoc_info* b = bb;

	if (a==b)
		return 0;

	if (a==NULL || b==NULL)
		return 1;

	/* assoc known*/
	if ((a->port1 == b->port1)
		&& (a->port2 == b->port2)
		&& (a->verification_tag1 == b->verification_tag1)
		&& ((a->verification_tag1!=0 || b->verification_tag2 !=0)))
		return FORWARD_STREAM;

	if ((a->port1 == b->port2)
		&& (a->port2 == b->port1)
		&& (a->verification_tag1 == b->verification_tag2))
		return BACKWARD_STREAM;

	/*forward stream verifivation tag can be added*/
	if ((a->port1 == b->port1)
		&& (a->port2 == b->port2)
		&& (a->verification_tag1 !=0)
		&& (b->verification_tag1 == 0)
		&& (b->verification_tag2 !=0))
		return FORWARD_ADD_FORWARD_VTAG;
	if ((a->port1 == b->port2)
		&& (a->port2 == b->port1)
		&& (a->verification_tag1 ==b->verification_tag2)
		&& (b->verification_tag1 == 0))
		return BACKWARD_ADD_FORWARD_VTAG;
	/*backward stream verification tag can be added */
	if ((a->port1 == b->port2)
		&& (a->port2 == b->port1)
		&& (a->verification_tag1 !=0)
		&& (b->verification_tag1 != 0)
		&& (b->verification_tag2 == 0))
		return BACKWARD_ADD_BACKWARD_VTAG;

	return ASSOC_NOT_FOUND;
}


gint sctp_assoc_address_cmp(gconstpointer aa, gconstpointer bb)
{
GList *srclist, *dstlist;
const struct _sctp_tmp_info* a = aa; //tmp_info
const struct _sctp_assoc_info* b = bb; //info
struct sockaddr_storage *store=NULL;
struct sockaddr_storage *srcstore=NULL;
struct sockaddr_storage *dststore=NULL;
struct sockaddr_in *src=NULL;
struct sockaddr_in6 *src6=NULL;
struct sockaddr_in *infosrc=NULL;
struct sockaddr_in *infodst=NULL;
struct sockaddr_in6 *infosrc6=NULL;
struct sockaddr_in *dst=NULL;
struct sockaddr_in6 *dst6=NULL;
struct sockaddr_in6 *infodst6=NULL;
gboolean src_v4=FALSE;
gboolean src_v6=FALSE;
gboolean dst_v4=FALSE;
gboolean dst_v6=FALSE;

	store = g_malloc(sizeof(struct sockaddr_storage));
	g_memmove(store, &(a->src),sizeof(struct sockaddr_storage));
	if (store->ss_family==AF_INET)
	{
		src = g_malloc(sizeof(struct sockaddr_in));
		g_memmove(src, &(a->src),sizeof(struct sockaddr_in));
		src_v4=TRUE;
	}
	else if (store->ss_family==AF_INET6)
	{
		src6 = g_malloc(sizeof(struct sockaddr_in6));
		g_memmove(src6, &(a->src),sizeof(struct sockaddr_in6));
		src_v6=TRUE;
	}

	g_memmove(store, &(a->dst),sizeof(struct sockaddr_storage));
	if (store->ss_family==AF_INET)
	{
		dst = g_malloc(sizeof(struct sockaddr_in));
		g_memmove(dst, &(a->dst),sizeof(struct sockaddr_in));
		dst_v4=TRUE;
	}
	else if (store->ss_family==AF_INET6)
	{
		dst6 = g_malloc(sizeof(struct sockaddr_in6));
		g_memmove(dst6, &(a->dst),sizeof(struct sockaddr_in6));
		dst_v6=TRUE;
	}

	srclist = g_list_first(b->addr1);
	while (srclist)
	{
		srcstore = (struct sockaddr_storage *) (srclist->data);
		if (srcstore->ss_family==AF_INET && src_v4==TRUE)
		{
			infosrc=(struct sockaddr_in *) (srclist->data);
			if (src->sin_addr.s_addr==infosrc->sin_addr.s_addr && a->port1 == b->port1)
			{
				dstlist = g_list_first(b->addr2);
				while (dstlist)
				{
						dststore = (struct sockaddr_storage *) (dstlist->data);
						if (dststore->ss_family==AF_INET && dst_v4==TRUE)
						{
							infodst=(struct sockaddr_in *) (dstlist->data);
							if (dst->sin_addr.s_addr==infodst->sin_addr.s_addr && a->port2 == b->port2)
							{
								if ((a->verification_tag1 !=0)&& (b->verification_tag1 == 0)&& (b->verification_tag2 !=0))
									return ADDRESS_FORWARD_ADD_FORWARD_VTAG;
								else
									return ADDRESS_FORWARD_STREAM;
							}
							else
								dstlist=g_list_next(dstlist);
						}
						else if (dststore->ss_family==AF_INET6 && dst_v6==TRUE)
						{
							infodst6=(struct sockaddr_in6 *) (dstlist->data);
							if (dst6->sin6_addr.s6_addr==infodst6->sin6_addr.s6_addr && a->port2 == b->port2)
							{
								if ((a->verification_tag1 !=0)&& (b->verification_tag1 == 0)&& (b->verification_tag2 !=0))
									return ADDRESS_FORWARD_ADD_FORWARD_VTAG;
								else
									return ADDRESS_FORWARD_STREAM;
							}
							else
								dstlist=g_list_next(dstlist);
						}
						else
							dstlist=g_list_next(dstlist);
				}
				srclist=g_list_next(srclist);
			}
			else
				srclist=g_list_next(srclist);
		}
		else if (srcstore->ss_family==AF_INET6 && src_v6==TRUE)
		{
			infosrc6=(struct sockaddr_in6 *) (srclist->data);
			if (src6->sin6_addr.s6_addr==infosrc6->sin6_addr.s6_addr && a->port1 == b->port1)
			{
				dstlist = g_list_first(b->addr2);
				while (dstlist)
				{
					dststore = (struct sockaddr_storage *) (dstlist->data);
					if (dststore->ss_family==AF_INET && dst_v4==TRUE)
					{
						infodst=(struct sockaddr_in *) (dstlist->data);
						if (dst->sin_addr.s_addr==infodst->sin_addr.s_addr && a->port2 == b->port2)
						{
							if ((a->verification_tag1 !=0)&& (b->verification_tag1 == 0)&& (b->verification_tag2 !=0))
								return ADDRESS_FORWARD_ADD_FORWARD_VTAG;
							else
								return ADDRESS_FORWARD_STREAM;
						}
						else
							dstlist=g_list_next(dstlist);
					}
					else if (dststore->ss_family==AF_INET6 && dst_v6==TRUE)
					{
						infodst6=(struct sockaddr_in6 *) (dstlist->data);
						if (dst6->sin6_addr.s6_addr==infodst6->sin6_addr.s6_addr && a->port2 == b->port2)
						{
							if ((a->verification_tag1 !=0)&& (b->verification_tag1 == 0)&& (b->verification_tag2 !=0))
								return ADDRESS_FORWARD_ADD_FORWARD_VTAG;
							else
								return ADDRESS_FORWARD_STREAM;
						}
						else
							dstlist=g_list_next(dstlist);
					}
					else
						dstlist=g_list_next(dstlist);
				}
				srclist=g_list_next(srclist);
			}
			else
				srclist=g_list_next(srclist);
		}
		else
			srclist=g_list_next(srclist);
	}

	g_free(src);
	g_free(dst);
	g_free(src6);
	g_free(dst6);
	g_free(store);

	store = g_malloc(sizeof(struct sockaddr_storage));
	g_memmove(store, &(a->dst),sizeof(struct sockaddr_storage));
	if (store->ss_family==AF_INET)
	{
		src = g_malloc(sizeof(struct sockaddr_in));
		g_memmove(src, &(a->dst),sizeof(struct sockaddr_in));
		src_v4=TRUE;
	}
	else if (store->ss_family==AF_INET6)
	{
		src6 = g_malloc(sizeof(struct sockaddr_in6));
		g_memmove(src6, &(a->dst),sizeof(struct sockaddr_in6));
		src_v6=TRUE;
	}

	g_memmove(store, &(a->src),sizeof(struct sockaddr_storage));
	if (store->ss_family==AF_INET)
	{
		dst = g_malloc(sizeof(struct sockaddr_in));
		g_memmove(dst, &(a->src),sizeof(struct sockaddr_in));
		dst_v4=TRUE;
	}
	else if (store->ss_family==AF_INET6)
	{
		dst6 = g_malloc(sizeof(struct sockaddr_in6));
		g_memmove(dst6, &(a->src),sizeof(struct sockaddr_in6));
		dst_v6=TRUE;
	}

	srclist = g_list_first(b->addr1);
	while (srclist)
	{
		srcstore = (struct sockaddr_storage *) (srclist->data);
		if (srcstore->ss_family==AF_INET && src_v4==TRUE)
		{
			infosrc=(struct sockaddr_in *) (srclist->data);
			if (src->sin_addr.s_addr==infosrc->sin_addr.s_addr && a->port2 == b->port1)
			{
				dstlist = g_list_first(b->addr2);
				while (dstlist)
				{
						dststore = (struct sockaddr_storage *) (dstlist->data);
						if (dststore->ss_family==AF_INET && src_v4==TRUE)
						{
							infodst=(struct sockaddr_in *) (dstlist->data);
							if (dst->sin_addr.s_addr==infodst->sin_addr.s_addr && a->port1 == b->port2)
							{
								if ((a->verification_tag1 ==b->verification_tag2)&& (b->verification_tag1 == 0))
									return ADDRESS_BACKWARD_ADD_FORWARD_VTAG;
								else if ((a->verification_tag1 !=0)	&& (b->verification_tag1 != 0)&& (b->verification_tag2 == 0))
									return ADDRESS_BACKWARD_ADD_BACKWARD_VTAG;
								else
									return ADDRESS_BACKWARD_STREAM;
							}
							else
								dstlist=g_list_next(dstlist);
						}
						else if (dststore->ss_family==AF_INET6 && src_v6==TRUE)
						{
							infodst6=(struct sockaddr_in6 *) (dstlist->data);
							if (dst6->sin6_addr.s6_addr==infodst6->sin6_addr.s6_addr && a->port1 == b->port2)
							{

								if ((a->verification_tag1 ==b->verification_tag2)&& (b->verification_tag1 == 0))
									return ADDRESS_BACKWARD_ADD_FORWARD_VTAG;
								else if ((a->verification_tag1 !=0)	&& (b->verification_tag1 != 0)&& (b->verification_tag2 == 0))
									return ADDRESS_BACKWARD_ADD_BACKWARD_VTAG;
								else
									return ADDRESS_BACKWARD_STREAM;
							}
							else
								dstlist=g_list_next(dstlist);
						}
						else
							dstlist=g_list_next(dstlist);
				}
				srclist=g_list_next(srclist);
			}
			else
				srclist=g_list_next(srclist);
		}
		else if (srcstore->ss_family==AF_INET6 && src_v6==TRUE)
		{
			infosrc6=(struct sockaddr_in6 *) (srclist->data);
			if (src6->sin6_addr.s6_addr==infosrc6->sin6_addr.s6_addr && a->port2 == b->port1)
			{
				dstlist = g_list_first(b->addr2);
				while (dstlist)
				{
					dststore = (struct sockaddr_storage *) (dstlist->data);
					if (dststore->ss_family==AF_INET && src_v4==TRUE)
					{
						infodst=(struct sockaddr_in *) (dstlist->data);
						if (dst->sin_addr.s_addr==infodst->sin_addr.s_addr && a->port1 == b->port2)
						{
								if ((a->verification_tag1 ==b->verification_tag2)&& (b->verification_tag1 == 0))
									return ADDRESS_BACKWARD_ADD_FORWARD_VTAG;
								else if ((a->verification_tag1 !=0)	&& (b->verification_tag1 != 0)&& (b->verification_tag2 == 0))
									return ADDRESS_BACKWARD_ADD_BACKWARD_VTAG;
								else
									return ADDRESS_BACKWARD_STREAM;
						}
						else
							dstlist=g_list_next(dstlist);
					}
					else if (dststore->ss_family==AF_INET6 && src_v6==TRUE)
					{
						infodst6=(struct sockaddr_in6 *) (dstlist->data);
						if (dst6->sin6_addr.s6_addr==infodst6->sin6_addr.s6_addr && a->port1 == b->port2)
						{
								if ((a->verification_tag1 ==b->verification_tag2)&& (b->verification_tag1 == 0))
									return ADDRESS_BACKWARD_ADD_FORWARD_VTAG;
								else if ((a->verification_tag1 !=0)	&& (b->verification_tag1 != 0)&& (b->verification_tag2 == 0))
									return ADDRESS_BACKWARD_ADD_BACKWARD_VTAG;
								else
									return ADDRESS_BACKWARD_STREAM;
						}
						else
							dstlist=g_list_next(dstlist);
					}
					else
						dstlist=g_list_next(dstlist);
				}
				srclist=g_list_next(srclist);
			}
			else
				srclist=g_list_next(srclist);
		}
		else
			srclist=g_list_next(srclist);
	}


	g_free(src);
	g_free(dst);
	g_free(src6);
	g_free(dst6);
	g_free(store);
	return ASSOC_NOT_FOUND;
}






sctp_assoc_info_t * find_assoc(sctp_tmp_info_t * needle)
{
sctp_allassocs_info_t *assoc_info;
sctp_assoc_info_t *info = NULL;
GList* list;
guint8 cmp;

	assoc_info = &sctp_tapinfo_struct;
	if ((list = g_list_first(assoc_info->assoc_info_list))!=NULL)
	{
		while (list)
		{
			cmp=sctp_assoc_vtag_cmp(needle, (sctp_assoc_info_t*)(list->data));
			if (cmp==ASSOC_NOT_FOUND)
			{
				cmp=sctp_assoc_address_cmp(needle, (sctp_assoc_info_t*)(list->data));
			}
			switch (cmp)
			{
			case FORWARD_STREAM:
				info = (sctp_assoc_info_t*)(list->data);
				info->direction = 1;
				return info;
			case BACKWARD_STREAM:
				info = (sctp_assoc_info_t*)(list->data);
				info->direction = 2;
				return info;
			case FORWARD_ADD_FORWARD_VTAG:
				info = (sctp_assoc_info_t*)(list->data);
				info->verification_tag1=needle->verification_tag1;
				info->direction = 1;
				return info;
			case BACKWARD_ADD_FORWARD_VTAG:
				info = (sctp_assoc_info_t*)(list->data);
				info->verification_tag1=needle->verification_tag1;
				info->direction = 2;
				return info;
			case BACKWARD_ADD_BACKWARD_VTAG:
				info = (sctp_assoc_info_t*)(list->data);
				info->verification_tag2=needle->verification_tag1;
				info->direction = 2;
				return info;
			case ADDRESS_FORWARD_STREAM:
				info = (sctp_assoc_info_t*)(list->data);
				info->direction = 1;
				info->check_address=TRUE;
				return info;
			case ADDRESS_BACKWARD_STREAM:
				info = (sctp_assoc_info_t*)(list->data);
				info->direction = 2;
				info->check_address=TRUE;
				return info;
			case ADDRESS_FORWARD_ADD_FORWARD_VTAG:
				info = (sctp_assoc_info_t*)(list->data);
				info->verification_tag1=needle->verification_tag1;
				info->direction = 1;
				info->check_address=TRUE;
				return info;
			case ADDRESS_BACKWARD_ADD_FORWARD_VTAG:
				info = (sctp_assoc_info_t*)(list->data);
				info->verification_tag1=needle->verification_tag1;
				info->direction = 2;
				info->check_address=TRUE;
				return info;
			case ADDRESS_BACKWARD_ADD_BACKWARD_VTAG:
				info = (sctp_assoc_info_t*)(list->data);
				info->verification_tag2=needle->verification_tag1;
				info->direction = 2;
				info->check_address=TRUE;
				return info;
			}

			list = g_list_next(list);
		}
	}
	return NULL;
}

sctp_assoc_info_t * add_address(struct sockaddr_storage * vadd, sctp_assoc_info_t *info, guint8 direction)
{
GList *list;
struct sockaddr_in  *v4, *v4add=NULL;
struct sockaddr_in6	*v6, *v6add=NULL;
struct sockaddr_storage *v;

	if (direction == 1)
		list = g_list_first(info->addr1);
	else
		list = g_list_first(info->addr2);

	while (list)
	{
		v = (struct sockaddr_storage *) (list->data);
		if (v->ss_family == AF_INET && vadd->ss_family == AF_INET)
		{
			v4 = (struct sockaddr_in *)(list->data);
			v4add = (struct sockaddr_in *) vadd;
			if (v4add->sin_addr.s_addr!=v4->sin_addr.s_addr)
				list = g_list_next(list);
			else
			{
				g_free(v4add);
				return info;
			}
		}
		else if (v->ss_family == AF_INET6 && vadd->ss_family == AF_INET6)
		{
			v6 = (struct sockaddr_in6 *)(list->data);
			v6add = (struct sockaddr_in6 *) vadd;
			if (v6add->sin6_addr.s6_addr!=v6->sin6_addr.s6_addr)
				list = g_list_next(list);
			else
			{
				g_free(v6add);
				return info;
			}
		}
		else
			list= g_list_next(list);
	}

	if (direction == 1)
		info->addr1 = g_list_append(info->addr1, vadd);
	else if (direction==2)
		info->addr2 = g_list_append(info->addr2, vadd);

	return info;
}

static int
packet(void *tapdata _U_, packet_info *pinfo , epan_dissect_t *edt _U_ , void *data _U_)
{
struct _sctp_info *sctp_info;
guint32 chunk_number=0, ip, tsnumber;
sctp_tmp_info_t tmp_info;
sctp_assoc_info_t *info = NULL;
sctp_error_info_t *error = NULL;
char str[200];
guint16	type, length;
struct sockaddr_in v4n;
struct sockaddr_in6 v6n;
struct sockaddr_storage *store=NULL;
tsn_t	*tsn=NULL;
tsn_t	*sack=NULL;
guint8 *t_s_n=NULL;
gboolean sackchunk=FALSE;
gboolean datachunk=FALSE;
guint32 max;
struct tsn_sort tsn_s;

	sctp_allassocs_info_t *assoc_info=NULL;
	assoc_info = &sctp_tapinfo_struct;

    sctp_info = (struct _sctp_info *) data;
	max =0xFFFFFFFF;

	type = pinfo->src.type;
	if (type == AT_IPv4)
	{
		v4n.sin_family = AF_INET;
		v4n.sin_port = 0;
		g_memmove(&(v4n.sin_addr.s_addr), pinfo->src.data, 4);
		g_memmove(&(tmp_info.src), &v4n, sizeof(struct sockaddr_in));
	}
	else if (type == AT_IPv6)
	{
		v6n.sin6_family=AF_INET6;
		v6n.sin6_port = 0;
		g_memmove(&(v6n.sin6_addr.s6_addr), pinfo->src.data, 16);
		g_memmove(&(tmp_info.src), &v6n, sizeof(struct sockaddr_in6));
	}
	type = pinfo->dst.type;

	if (type == AT_IPv4)
	{
		v4n.sin_family=AF_INET;
		v4n.sin_port = 0;
		g_memmove(&(v4n.sin_addr.s_addr), pinfo->dst.data, 4);
		g_memmove(&(tmp_info.dst), &v4n, sizeof(struct sockaddr_in));
	}
	else if (type == AT_IPv6)
	{
		v6n.sin6_family=AF_INET6;
		v6n.sin6_port = 0;
		g_memmove(&(v6n.sin6_addr.s6_addr), pinfo->dst.data, 16);
		g_memmove(&(tmp_info.dst), &v6n, sizeof(struct sockaddr_in6));
	}

	tmp_info.port1 = pinfo->srcport;
	tmp_info.port2 = pinfo->destport;
	tmp_info.verification_tag1=sctp_info->verification_tag;
	tmp_info.verification_tag2=0;
	tmp_info.n_tvbs=0;


	info=find_assoc(&tmp_info);
	if (!info)
	{
		tmp_info.n_tvbs = sctp_info->number_of_tvbs;
		sctp_tapinfo_struct.sum_tvbs+=sctp_info->number_of_tvbs;


		if (sctp_info->number_of_tvbs>0)
		{
			info = g_malloc(sizeof(sctp_assoc_info_t));
			memset(info, 0, sizeof(sctp_assoc_info_t));
			g_memmove(info, &tmp_info, sizeof(sctp_tmp_info_t));

			info->init=FALSE;
			info->initack=FALSE;
			info->direction=0;
			info=calc_checksum(sctp_info, info);
			info->n_packets=1;
			info->error_info_list=NULL;
			info->min_secs=0xffffffff;
			info->min_usecs=0xffffffff;
			info->max_secs=0;
			info->max_usecs=0;
			info->min_tsn2=0xFFFFFFFF;
			info->min_tsn1=0xffffffff;
			info->max_tsn1=0;
			info->max_tsn2=0;
			info->max_bytes1=0;
			info->max_bytes2=0;
			info->n_data_chunks=0;
			info->n_data_bytes=0;
			info->n_data_chunks_ep1=0;
			info->n_data_bytes_ep1=0;
			info->n_data_chunks_ep2=0;
			info->n_data_bytes_ep2=0;
			info->n_sack_chunks_ep1=0;
			info->n_sack_chunks_ep2=0;
			info->n_array_tsn1=0;
			info->n_array_tsn2=0;
			info->max_window1=0;
			info->max_window2=0;
			info->min_max=NULL;
			info->sort_tsn1=g_array_new(FALSE, FALSE, sizeof(struct tsn_sort));
			info->sort_tsn2=g_array_new(FALSE, FALSE, sizeof(struct tsn_sort));
			info->sort_sack1=g_array_new(FALSE, FALSE, sizeof(struct tsn_sort));
			info->sort_sack2=g_array_new(FALSE, FALSE, sizeof(struct tsn_sort));

			if (((tvb_get_guint8(sctp_info->tvb[0],0))==SCTP_INIT_CHUNK_ID) ||
				((tvb_get_guint8(sctp_info->tvb[0],0))==SCTP_INIT_ACK_CHUNK_ID) ||
				((tvb_get_guint8(sctp_info->tvb[0],0))==SCTP_DATA_CHUNK_ID) ||
				((tvb_get_guint8(sctp_info->tvb[0],0))==SCTP_SACK_CHUNK_ID))
			{
				tsn = g_malloc(sizeof(tsn_t));
				sack = g_malloc(sizeof(tsn_t));
				tsn->tsns = NULL;
				tsn->src = tmp_info.src;
				tsn->dst = tmp_info.dst;
				tsn->secs = (guint32)pinfo->fd->rel_secs;
				tsn->usecs = (guint32)pinfo->fd->rel_usecs;
				if (((tvb_get_guint8(sctp_info->tvb[0],0))==SCTP_DATA_CHUNK_ID) ||
					((tvb_get_guint8(sctp_info->tvb[0],0))==SCTP_SACK_CHUNK_ID))
				{
					if (tsn->secs<info->min_secs)
					{
						info->min_secs=tsn->secs;
						info->min_usecs=tsn->usecs;
					}
					else if (tsn->secs==info->min_secs && tsn->usecs < info->min_usecs)
						info->min_usecs=tsn->usecs;

					if (tsn->secs>info->max_secs)
					{
						info->max_secs=tsn->secs;
						info->max_usecs=tsn->usecs;
					}
					else if (tsn->secs==info->max_secs && tsn->usecs > info->max_usecs)
						info->max_usecs=tsn->usecs;
				}

				tsn->frame_number = pinfo->fd->num;
				g_memmove(sack, tsn, sizeof(tsn_t));

			}
			if ((tvb_get_guint8(sctp_info->tvb[0],0)==SCTP_INIT_CHUNK_ID) || (tvb_get_guint8(sctp_info->tvb[0],0)==SCTP_INIT_ACK_CHUNK_ID))
			{
				info->min_tsn1 = tvb_get_ntohl(sctp_info->tvb[0],INIT_CHUNK_INITIAL_TSN_OFFSET);
				info->verification_tag2=tvb_get_ntohl(sctp_info->tvb[0], INIT_CHUNK_INITIATE_TAG_OFFSET);
				info->instream1=tvb_get_ntohs(sctp_info->tvb[0],INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET);
				info->outstream1=tvb_get_ntohs(sctp_info->tvb[0],INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET);
				for (chunk_number = 1; chunk_number < sctp_info->number_of_tvbs; chunk_number++)
				{
					type = tvb_get_ntohs(sctp_info->tvb[chunk_number],0);
					if (type == IPV4ADDRESS_PARAMETER_ID)
					{
						v4n.sin_family=AF_INET;
						v4n.sin_port = 0;
						ip=tvb_get_ntohl(sctp_info->tvb[chunk_number],4);
						ip=htonl(ip);
						v4n.sin_addr.s_addr=ip;
						store = g_malloc(sizeof(struct sockaddr_storage));
						g_memmove(store,&v4n, sizeof(struct sockaddr_in));
						info = add_address(store, info, 1);
					}
					else if (type == IPV6ADDRESS_PARAMETER_ID)
					{
						v6n.sin6_family=AF_INET6;
						v6n.sin6_port = 0;
						tvb_memcpy(sctp_info->tvb[chunk_number], (guint8 *)&(v6n.sin6_addr.s6_addr),IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH);
						store = g_malloc(sizeof(struct sockaddr_storage));
						g_memmove(store, &v6n, sizeof(struct sockaddr_in6));
						info = add_address(store, info, 1);
					}
				}
				if (tvb_get_guint8(sctp_info->tvb[0],0)==SCTP_INIT_CHUNK_ID)
				{
					info->init=TRUE;
				}
				else
				{
					info->initack_dir=1;
					info->initack=TRUE;
				}
			}
			else
				for (chunk_number = 0; chunk_number < sctp_info->number_of_tvbs; chunk_number++)
				{
					if (tvb_get_guint8(sctp_info->tvb[chunk_number],0)==SCTP_DATA_CHUNK_ID)
					{
						length=tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET);
						info->n_data_chunks++;
						info->n_data_bytes+=length;
						info->outstream1=tvb_get_ntohs((sctp_info->tvb)[chunk_number], DATA_CHUNK_STREAM_ID_OFFSET)+1;
						tsnumber = tvb_get_ntohl((sctp_info->tvb)[chunk_number], DATA_CHUNK_TSN_OFFSET);
						if (tsnumber<info->min_tsn1)
							info->min_tsn1=tsnumber;
						if (tsnumber>info->max_tsn1)
						{
							length=tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET);
							info->n_data_chunks_ep1++;
							info->n_data_bytes_ep1+=length;
							info->max_tsn1=tsnumber;
						}

						t_s_n = g_malloc(16);
						tvb_memcpy(sctp_info->tvb[chunk_number], (guint8 *)(t_s_n),0, 16);
						tsn->tsns = g_list_append(tsn->tsns, t_s_n);
						datachunk = TRUE;
						tsn_s.tsnumber=tsnumber;
						tsn_s.secs=tsn->secs;
						tsn_s.usecs=tsn->usecs;
						tsn_s.offset=0;
						tsn_s.length=length-16;
						info->sort_tsn1=g_array_append_val(info->sort_tsn1, tsn_s);
						info->n_array_tsn1++;
					}
					if (tvb_get_guint8(sctp_info->tvb[chunk_number],0)==SCTP_SACK_CHUNK_ID)
					{
						tsnumber = tvb_get_ntohl((sctp_info->tvb)[chunk_number], SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET);
						if (tsnumber<info->min_tsn2)
							info->min_tsn2=tsnumber;
						if (tsnumber>info->max_tsn2)
							info->max_tsn2=tsnumber;
						info->n_sack_chunks_ep2++;
						length = tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET);
						t_s_n = g_malloc(length);
						tvb_memcpy(sctp_info->tvb[chunk_number], (guint8 *)(t_s_n),0, length);
						sack->tsns = g_list_append(sack->tsns, t_s_n);
						sackchunk=TRUE;
						tsn_s.tsnumber=tsnumber;
						tsn_s.secs=tsn->secs;
						tsn_s.usecs=tsn->usecs;
						tsn_s.offset=0;
						tsn_s.length= tvb_get_ntohl(sctp_info->tvb[chunk_number], SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET);
						if (tsn_s.length>info->max_window1)
							info->max_window1=tsn_s.length;
						info->sort_sack2=g_array_append_val(info->sort_sack2, tsn_s);
						info->n_sack_chunks_ep2++;						
					}

				}
			if (info->verification_tag1!=0 || info->verification_tag2!=0)
			{
				store = g_malloc(sizeof (struct sockaddr_storage));
				g_memmove(store,&(tmp_info.src),sizeof(struct sockaddr_storage));
				info = add_address(store, info, 1);
				store = g_malloc(sizeof (struct sockaddr_storage));
				g_memmove(store,&(tmp_info.dst),sizeof(struct sockaddr_storage));
				info = add_address(store, info, 2);
				info->frame_numbers=g_list_prepend(info->frame_numbers,&(pinfo->fd->num));
				if (datachunk==TRUE)
					info->tsn1 = g_list_prepend(info->tsn1, tsn);
				if (sackchunk == TRUE)
					info->sack2 = g_list_prepend(info->sack2, sack);
				sctp_tapinfo_struct.assoc_info_list = g_list_append(sctp_tapinfo_struct.assoc_info_list, info);
			}
			else
			{
				error = g_malloc(sizeof(sctp_error_info_t));
				error->frame_number = pinfo->fd->num;
				strcpy(str,"");
				strcpy(error->chunk_info,"");
				if ((tvb_get_guint8(sctp_info->tvb[0],0))==SCTP_INIT_CHUNK_ID)
					strcpy(error->chunk_info, val_to_str(tvb_get_guint8(sctp_info->tvb[0],0),chunk_type_values,"Reserved"));
				else
					for (chunk_number = 0; chunk_number < sctp_info->number_of_tvbs; chunk_number++)
						strcat(error->chunk_info, val_to_str(tvb_get_guint8(sctp_info->tvb[chunk_number],0),chunk_type_values,"Reserved"));
				error->info_text="INFOS";
				info->error_info_list = g_list_append(info->error_info_list, error);
			}
		}
	}
	else
	{
		if (((tvb_get_guint8(sctp_info->tvb[0],0))==SCTP_INIT_ACK_CHUNK_ID) ||
			((tvb_get_guint8(sctp_info->tvb[0],0))==SCTP_DATA_CHUNK_ID) ||
			((tvb_get_guint8(sctp_info->tvb[0],0))==SCTP_SACK_CHUNK_ID))
		{

			tsn = g_malloc(sizeof(tsn_t));
			sack = g_malloc(sizeof(tsn_t));
			tsn->tsns = NULL;
			tsn->src = tmp_info.src;
			tsn->dst = tmp_info.dst;
			tsn->secs = (guint32)pinfo->fd->rel_secs;
			tsn->usecs = (guint32)pinfo->fd->rel_usecs;
			if (((tvb_get_guint8(sctp_info->tvb[0],0))==SCTP_DATA_CHUNK_ID) ||
			((tvb_get_guint8(sctp_info->tvb[0],0))==SCTP_SACK_CHUNK_ID))
			{
				if (tsn->secs<info->min_secs)
				{
					info->min_secs=tsn->secs;
					info->min_usecs=tsn->usecs;
				}
				else if (tsn->secs==info->min_secs && tsn->usecs<info->min_usecs)
					info->min_usecs=tsn->usecs;

				if (tsn->secs>info->max_secs)
					{
						info->max_secs=tsn->secs;
						info->max_usecs=tsn->usecs;
					}
					else if (tsn->secs==info->max_secs && tsn->usecs > info->max_usecs)
						info->max_usecs=tsn->usecs;
			}
			tsn->frame_number = pinfo->fd->num;
			g_memmove(sack, tsn, sizeof(tsn_t));
		}
		info->frame_numbers=g_list_prepend(info->frame_numbers,&(pinfo->fd->num));

		if (info->direction==1)
		{
			store = g_malloc(sizeof (struct sockaddr_storage));
			g_memmove(store,&(tmp_info.src),sizeof(struct sockaddr_storage));
			info = add_address(store, info, 1);
			store = g_malloc(sizeof (struct sockaddr_storage));
			g_memmove(store,&(tmp_info.dst),sizeof(struct sockaddr_storage));
			info = add_address(store, info, 2);
		}
		else if (info->direction==2)
		{
			store = g_malloc(sizeof (struct sockaddr_storage));
			g_memmove(store,&(tmp_info.src),sizeof(struct sockaddr_storage));
			info = add_address(store, info, 2);
			store = g_malloc(sizeof (struct sockaddr_storage));
			g_memmove(store,&(tmp_info.dst),sizeof(struct sockaddr_storage));
			info = add_address(store, info, 1);
		}
		if ((tvb_get_guint8(sctp_info->tvb[0],0))==SCTP_INIT_ACK_CHUNK_ID)
		{
			tsnumber = tvb_get_ntohl((sctp_info->tvb)[chunk_number], INIT_CHUNK_INITIAL_TSN_OFFSET);

			if (info->direction==2)
			{
				if (tsnumber<info->min_tsn2)
					info->min_tsn2 = tsnumber;
				if (tsnumber > info->max_tsn2)
					info->max_tsn2 = tsnumber;
				info->instream2=tvb_get_ntohs(sctp_info->tvb[0],INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET);
				info->outstream2=tvb_get_ntohs(sctp_info->tvb[0],INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET);
				info->initack_dir=2;
				info->tsn2 = g_list_prepend(info->tsn2, tsn);
			}
			else if (info->direction==1)
			{
				if (tsnumber<info->min_tsn1)
					info->min_tsn1 = tsnumber;
				if (tsnumber > info->max_tsn1)
					info->max_tsn1 = tsnumber;
				info->instream1=tvb_get_ntohs(sctp_info->tvb[0],INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET);
				info->outstream1=tvb_get_ntohs(sctp_info->tvb[0],INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET);
				info->initack_dir=1;
				info->tsn1 = g_list_prepend(info->tsn1, tsn);
			}
			for (chunk_number = 1; chunk_number < sctp_info->number_of_tvbs; chunk_number++)
			{
				type = tvb_get_ntohs(sctp_info->tvb[chunk_number],0);
				if (type == IPV4ADDRESS_PARAMETER_ID)
					{
						v4n.sin_family=AF_INET;
						v4n.sin_port = 0;
						ip=tvb_get_ntohl(sctp_info->tvb[chunk_number],4);
						ip=htonl(ip);
						v4n.sin_addr.s_addr=ip;
						store = g_malloc(sizeof(struct sockaddr_storage));
						g_memmove(store, &v4n, sizeof(struct sockaddr_in));
						info = add_address(store, info, info->direction);
					}
					else if (type == IPV6ADDRESS_PARAMETER_ID)
					{
						v6n.sin6_family=AF_INET6;
						v6n.sin6_port = 0;
						tvb_memcpy(sctp_info->tvb[chunk_number], (guint8 *)&(v6n.sin6_addr.s6_addr),IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH);
						store = g_malloc(sizeof(struct sockaddr_storage));
						g_memmove(store, &v6n, sizeof(struct sockaddr_in6));
						info = add_address(store, info, info->direction);
					}

			}
			info->initack=TRUE;
		}
		else
		{
		for (chunk_number = 0; chunk_number < sctp_info->number_of_tvbs; chunk_number++)
		{
			if ((tvb_get_guint8(sctp_info->tvb[0],0))==SCTP_DATA_CHUNK_ID)
			{
				tsnumber = tvb_get_ntohl((sctp_info->tvb)[chunk_number], DATA_CHUNK_TSN_OFFSET);
				t_s_n = g_malloc(16);
				tvb_memcpy(sctp_info->tvb[chunk_number], (guint8 *)(t_s_n),0, 16);
				tsn->tsns = g_list_append(tsn->tsns, t_s_n);
				datachunk = TRUE;
				length=tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET);
				info->n_data_chunks++;
				info->n_data_bytes+=length;
				tsn_s.tsnumber=tsnumber;
				tsn_s.secs=tsn->secs;
				tsn_s.usecs=tsn->usecs;
				tsn_s.offset=0;
				tsn_s.length=length-16;

				if (info->direction == 1)
				{
					if(tsnumber<info->min_tsn1)
						info->min_tsn1 = tsnumber;
					if ((info->init==TRUE || (info->initack==TRUE && info->initack_dir==1))&& tsnumber==info->min_tsn1 && tsnumber<=info->max_tsn1)
					{
						length=tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET);
						info->n_data_chunks_ep1++;
						info->n_data_bytes_ep1+=length;
					}
					if(tsnumber>info->max_tsn1)
					{
						info->max_tsn1 = tsnumber;
						length=tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET);
						info->n_data_chunks_ep1++;
						info->n_data_bytes_ep1+=length;
					}
					if (info->init==FALSE)
						info->outstream1=tvb_get_ntohs((sctp_info->tvb)[chunk_number], DATA_CHUNK_STREAM_ID_OFFSET)+1;
					if (info->initack==FALSE)
						info->instream2=tvb_get_ntohs((sctp_info->tvb)[chunk_number], DATA_CHUNK_STREAM_ID_OFFSET)+1;

					info->sort_tsn1=g_array_append_val(info->sort_tsn1, tsn_s);
					info->n_array_tsn1++;
				}
				else if (info->direction == 2)
				{

					if(tsnumber<info->min_tsn2)
						info->min_tsn2 = tsnumber;

					if ((info->initack==TRUE && info->initack_dir==2)&& tsnumber==info->min_tsn2 && tsnumber<=info->max_tsn2)
					{
						length=tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET);
						info->n_data_chunks_ep2++;
						info->n_data_bytes_ep2+=length;
					}
					if(tsnumber>info->max_tsn2)
					{
						info->max_tsn2 = tsnumber;
						length=tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET);
						info->n_data_chunks_ep2++;
						info->n_data_bytes_ep2+=length;
					}
					if (info->init==FALSE)
						info->instream1=tvb_get_ntohs((sctp_info->tvb)[chunk_number], DATA_CHUNK_STREAM_ID_OFFSET)+1;
					if (info->initack==FALSE)
						info->outstream2=tvb_get_ntohs((sctp_info->tvb)[chunk_number], DATA_CHUNK_STREAM_ID_OFFSET)+1;

					info->sort_tsn2=g_array_append_val(info->sort_tsn2, tsn_s);
					info->n_array_tsn2++;
				}
			}
			else if (tvb_get_guint8(sctp_info->tvb[chunk_number],0)==SCTP_SACK_CHUNK_ID)
			{
				tsnumber = tvb_get_ntohl((sctp_info->tvb)[chunk_number], SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET);
				length = tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET);
				t_s_n = g_malloc(length);
				tvb_memcpy(sctp_info->tvb[chunk_number], (guint8 *)(t_s_n),0, length);
				sack->tsns = g_list_append(sack->tsns, t_s_n);
				sackchunk=TRUE;
				tsn_s.tsnumber=tsnumber;
				tsn_s.secs=tsn->secs;
				tsn_s.usecs=tsn->usecs;
				tsn_s.offset=0;
				tsn_s.length= tvb_get_ntohl(sctp_info->tvb[chunk_number], SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET);


				if (info->direction == 2)
				{
					if(tsnumber<info->min_tsn1)
						info->min_tsn1 = tsnumber;
					if(tsnumber>info->max_tsn1)
						info->max_tsn1 = tsnumber;
					if (tsn_s.length>info->max_window1)
							info->max_window1=tsn_s.length;
					info->sort_sack1=g_array_append_val(info->sort_sack1, tsn_s);
					info->n_sack_chunks_ep1++;
				}
				else if (info->direction == 1)
				{

					if(tsnumber<info->min_tsn2)
						info->min_tsn2 = tsnumber;
					if(tsnumber>info->max_tsn2)
						info->max_tsn2 = tsnumber;
					if (tsn_s.length>info->max_window2)
							info->max_window2=tsn_s.length;
					info->sort_sack2=g_array_append_val(info->sort_sack2, tsn_s);
					info->n_sack_chunks_ep2++;
				}

			}

		}

		}
		if (datachunk==TRUE)
		{
			if (info->direction == 1)
				info->tsn1 = g_list_prepend(info->tsn1, tsn);
			else if (info->direction == 2)
				info->tsn2 = g_list_prepend(info->tsn2, tsn);
		}
		if (sackchunk==TRUE)
		{
			if (info->direction == 1)
					info->sack2 = g_list_prepend(info->sack2, sack);
				else if(info->direction == 2)
					info->sack1 = g_list_prepend(info->sack1, sack);
		}

		info->n_tvbs+=sctp_info->number_of_tvbs;
		sctp_tapinfo_struct.sum_tvbs+=sctp_info->number_of_tvbs;
		info = calc_checksum(sctp_info, info);
		info->n_packets++;

	}

	return(1);
}


/* XXX just copied from gtk/rpc_stat.c */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);

/****************************************************************************/
void
remove_tap_listener_sctp_stat(void)
{
	if (sctp_tapinfo_struct.is_registered) {
		protect_thread_critical_region();
		remove_tap_listener(&sctp_tapinfo_struct);
		unprotect_thread_critical_region();
		sctp_tapinfo_struct.is_registered = FALSE;
	}
}


void sctp_stat_scan(void)
{
	if (!sctp_tapinfo_struct.is_registered)
		register_tap_listener_sctp_stat();
}

const sctp_allassocs_info_t* sctp_stat_get_info(void)
{
	return &sctp_tapinfo_struct;
}


static void
gtk_sctpstat_init(char *dummy _U_)
{

}

static void sctp_update(void)
{
	if (get_stat_dlg()!=NULL)
		sctp_stat_dlg_update();
}

void
register_tap_listener_sctp_stat(void)
{
GString *error_string;

if (!sctp_tapinfo_struct.is_registered)
{
register_ethereal_tap("sctp",gtk_sctpstat_init);
	if ((error_string = register_tap_listener("sctp", &sctp_tapinfo_struct, NULL, (void *)reset, packet, (void *)sctp_update))) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
		g_string_free(error_string, TRUE);
		return;
	}
	sctp_tapinfo_struct.is_registered=TRUE;
	}


}
