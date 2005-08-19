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
#include <epan/tap.h>           /* Needed for register_tap_listener */
#include <epan/stat.h>
#include "stat_menu.h"
#include "dlg_utils.h"
#include "compat_macros.h"
#include "register.h"
#include <string.h>
#include "sctp_stat.h"
#include <math.h>
#include "epan/address.h"

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

#define SCTP_ABORT_CHUNK_T_BIT        0x01

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

#define INIT_CHUNK_INITIAL_TSN_LENGTH                4
#define INIT_CHUNK_FIXED_PARAMTERS_LENGTH            (INIT_CHUNK_INITIATE_TAG_LENGTH + \
                                                      INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH + \
                                                      INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH + \
                                                      INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH + \
                                                      INIT_CHUNK_INITIAL_TSN_LENGTH)	
#define CHUNK_HEADER_LENGTH           (CHUNK_TYPE_LENGTH + \
                                       CHUNK_FLAGS_LENGTH + \
                                       CHUNK_LENGTH_LENGTH)
#define INIT_CHUNK_VARIABLE_LENGTH_PARAMETER_OFFSET  (INIT_CHUNK_INITIAL_TSN_OFFSET + \
                                                      INIT_CHUNK_INITIAL_TSN_LENGTH ) 

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


#define FORWARD_STREAM                     0
#define BACKWARD_STREAM                    1
#define FORWARD_ADD_FORWARD_VTAG           2
#define BACKWARD_ADD_FORWARD_VTAG          3
#define BACKWARD_ADD_BACKWARD_VTAG         4
#define ADDRESS_FORWARD_STREAM             5
#define ADDRESS_BACKWARD_STREAM            6
#define ADDRESS_FORWARD_ADD_FORWARD_VTAG   7
#define ADDRESS_BACKWARD_ADD_FORWARD_VTAG  8
#define ADDRESS_BACKWARD_ADD_BACKWARD_VTAG 9
#define ASSOC_NOT_FOUND                    10

static sctp_allassocs_info_t sctp_tapinfo_struct = {0, NULL, FALSE, NULL};

static
void free_first(gpointer data, gpointer user_data _U_)
{
	g_free(data);
}

void tsn_free(gpointer data, gpointer user_data _U_)
{
	tsn_t *tsn;

	tsn = (tsn_t *) data;
	if (tsn->tsns != NULL)
	{
		g_list_foreach(tsn->tsns, free_first, NULL);
		g_list_free(tsn->tsns);
		tsn->tsns=NULL;
	}
}

static void
reset(void *arg)
{
	sctp_allassocs_info_t *tapdata = arg;
	GList* list;
	sctp_assoc_info_t * info;

	list = g_list_first(tapdata->assoc_info_list);
	while (list)
	{
		info = (sctp_assoc_info_t *) (list->data);

		if (info->addr1 != NULL)
		{
			g_list_foreach(info->addr1, free_first, NULL);
			g_list_free(info->addr1);
			info->addr1 = NULL;
		}

		if (info->addr2 != NULL)
		{
			g_list_foreach(info->addr2,free_first, NULL);
			g_list_free(info->addr2);
			info->addr2 = NULL;
		}

		if (info->error_info_list != NULL)
		{
			g_list_foreach(info->error_info_list, free_first, NULL);
			g_list_free(info->error_info_list);
			info->error_info_list = NULL;
		}

		if (info->frame_numbers != NULL)
		{
			g_list_free(info->frame_numbers);
			info->frame_numbers = NULL;
		}

		if (info->tsn1 != NULL)
		{
			g_list_foreach(info->tsn1, tsn_free, NULL);
			g_list_free(info->tsn1);
			info->tsn1 = NULL;
		}

		if (info->tsn2 != NULL)
		{
			g_list_foreach(info->tsn2, tsn_free, NULL);
			g_list_free(info->tsn2);
			info->tsn2 = NULL;
		}

		if (info->sack1 != NULL)
		{
			g_list_foreach(info->sack1, tsn_free, NULL);
			g_list_free(info->sack1);
			info->sack1 = NULL;
		}

		if (info->sack2 != NULL)
		{
			g_list_foreach(info->sack2, tsn_free, NULL);
			g_list_free(info->sack2);
			info->sack2 = NULL;
		}

		if (info->sort_tsn1 != NULL)
			g_ptr_array_free(info->sort_tsn1, TRUE);

		if (info->sort_tsn2 != NULL)
			g_ptr_array_free(info->sort_tsn2, TRUE);

		if (info->sort_sack1 != NULL)
			g_ptr_array_free(info->sort_sack1, TRUE);

		if (info->sort_sack2 != NULL)
			g_ptr_array_free(info->sort_sack2, TRUE);

		if (info->min_max != NULL)
		{
			g_slist_foreach(info->min_max, free_first, NULL);
			info->min_max = NULL;
		}

		g_free(list->data);
		list = g_list_next(list);
	}
	g_list_free(tapdata->assoc_info_list);
	tapdata->sum_tvbs = 0;
	tapdata->assoc_info_list = NULL;
}


static sctp_assoc_info_t *calc_checksum(struct _sctp_info *check_data, sctp_assoc_info_t *data)
{
	gboolean ok = FALSE;

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
	if (data->n_adler32_calculated > 0)
	{
		if ((float)(data->n_adler32_correct*1.0/data->n_adler32_calculated) > 0.5)
		{
			strcpy(data->checksum_type,"ADLER32");
			data->n_checksum_errors=(data->n_adler32_calculated-data->n_adler32_correct);
			ok = TRUE;
		}
	}

	if (data->n_crc32c_calculated>0)
	{
		if ((float)(data->n_crc32c_correct*1.0/data->n_crc32c_calculated) > 0.5)
		{
			strcpy(data->checksum_type,"CRC32C");
			data->n_checksum_errors=data->n_crc32c_calculated-data->n_crc32c_correct;
			ok = TRUE;
		}
	}

	if (!ok)
	{
		strcpy(data->checksum_type,"UNKNOWN");
		data->n_checksum_errors=0;
	}

	return(data);

}


gint sctp_assoc_vtag_cmp(gconstpointer aa, gconstpointer bb)
{

	const struct _sctp_assoc_info* a = aa;
	const struct _sctp_assoc_info* b = bb;

	if (a == b)
		return(0);

	if (a == NULL || b == NULL)
		return(1);

	/* assoc known*/
	if ((a->port1 == b->port1) &&
	    (a->port2 == b->port2) &&
	    (a->verification_tag1 == b->verification_tag1) &&
	    ((a->verification_tag1 != 0 || 
	     (b->verification_tag2 != 0))))
		return(FORWARD_STREAM);

	if ((a->port1 == b->port2) &&
	    (a->port2 == b->port1) &&
	    (a->verification_tag1 == b->verification_tag2))
		return(BACKWARD_STREAM);
		
	if ((a->port1 == b->port2) &&
	    (a->port2 == b->port1) &&
	    (a->verification_tag2 == b->verification_tag1))
		return(BACKWARD_STREAM);

	/*forward stream verifivation tag can be added*/
	if ((a->port1 == b->port1) &&
	    (a->port2 == b->port2) &&
	    (a->verification_tag1 != 0) &&
	    (b->verification_tag1 == 0) &&
	    (b->verification_tag2 !=0))
		return (FORWARD_ADD_FORWARD_VTAG);
		
	if ((a->port1 == b->port2) &&
	    (a->port2 == b->port1) &&
	    (a->verification_tag1 == b->verification_tag2) &&
	    (b->verification_tag1 == 0))
		return (BACKWARD_ADD_FORWARD_VTAG);
		
	/*backward stream verification tag can be added */
	if ((a->port1 == b->port2) &&
	    (a->port2 == b->port1) &&
	    (a->verification_tag1 !=0) &&
	    (b->verification_tag1 != 0) &&
	    (b->verification_tag2 == 0))
		return(BACKWARD_ADD_BACKWARD_VTAG);

	return(ASSOC_NOT_FOUND);
}


gint sctp_assoc_address_cmp(gconstpointer aa, gconstpointer bb)
{
	GList *srclist, *dstlist;
	const struct _sctp_tmp_info* a = aa;
	const struct _sctp_assoc_info* b = bb;
	address *srcstore=NULL;
	address *dststore=NULL;
	address *src=NULL;
	address *dst=NULL;
	gboolean src_v4=FALSE;
	gboolean src_v6=FALSE;
	gboolean dst_v4=FALSE;
	gboolean dst_v6=FALSE;
	guint8* addr;

	src = g_malloc(sizeof(address));
	if (a->src.type == AT_IPv4)
	{
		src->type = AT_IPv4;
		src->len  = 4;
		src_v4    = TRUE;
	}
	else if (a->src.type==AT_IPv6)
	{
		src->type = AT_IPv6;
		src->len  = 16;
		src_v6    = TRUE;
	}
	addr = g_malloc(src->len);
	memcpy(addr, a->src.data, src->len);
	src->data = addr;

	dst = g_malloc(sizeof(address));
	if (a->dst.type == AT_IPv4)
	{
		dst->type = AT_IPv4;
		dst->len  = 4;
		dst_v4    = TRUE;
	}
	else if (a->dst.type==AT_IPv6)
	{
		dst->type = AT_IPv6;
		dst->len  = 16;
		dst_v6    = TRUE;
	}
	addr = g_malloc(dst->len);
	memcpy(addr, a->dst.data, dst->len);
	dst->data = addr;

	srclist = g_list_first(b->addr1);
	while (srclist)
	{
		srcstore = (address *) (srclist->data);
		if (srcstore->type==AT_IPv4 && src_v4==TRUE)
		{
			if (*src->data==*srcstore->data && a->port1 == b->port1)
			{
				dstlist = g_list_first(b->addr2);
				while (dstlist)
				{
						dststore = (address *) (dstlist->data);
						if ((dststore->type==AT_IPv4 && dst_v4==TRUE) ||(dststore->type==AT_IPv6 && dst_v6==TRUE) )
						{
							if (*dst->data==*dststore->data && a->port2 == b->port2)
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
		else if (srcstore->type==AT_IPv6 && src_v6==TRUE)
		{
			if (*src->data == *srcstore->data  && a->port1 == b->port1)
			{
				dstlist = g_list_first(b->addr2);
				while (dstlist)
				{
					dststore = (address *) (dstlist->data);
					if ((dststore->type==AT_IPv4 && dst_v4==TRUE) || (dststore->type==AT_IPv6 && dst_v6==TRUE))
					{
						if (*dst->data==*dststore->data && a->port2 == b->port2)
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

	src = g_malloc(sizeof(address));
	if (a->dst.type == AT_IPv4)
	{
		src->type = AT_IPv4;
		src->len  = 4;
		src_v4    = TRUE;
	}
	else if (a->dst.type==AT_IPv6)
	{
		src->type = AT_IPv6;
		src->len  = 16;
		src_v6    = TRUE;
	}
	addr = g_malloc(src->len);
	memcpy(addr, a->dst.data, src->len);
	src->data = addr;
	
	dst = g_malloc(sizeof(address));
	if (a->src.type == AT_IPv4)
	{
		dst->type = AT_IPv4;
		dst->len  = 4;
		dst_v4    = TRUE;
	}
	else if (a->src.type==AT_IPv6)
	{
		dst->type = AT_IPv6;
		dst->len  = 16;
		dst_v6    = TRUE;
	}
	addr = g_malloc(dst->len);
	memcpy(addr, a->src.data, dst->len);
	dst->data = addr;
	
	srclist = g_list_first(b->addr1);
	while (srclist)
	{
		srcstore = (address *) (srclist->data);
		if (srcstore->type==AT_IPv4 && src_v4==TRUE)
		{
			if (*src->data==*srcstore->data && a->port2 == b->port1)
			{
				dstlist = g_list_first(b->addr2);
				while (dstlist)
				{
						dststore = (address *) (dstlist->data);
						if ((dststore->type==AT_IPv4 && src_v4==TRUE) || (dststore->type==AT_IPv6 && src_v6==TRUE))
						{
							if (*dst->data==*dststore->data && a->port1 == b->port2)
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
		else if (srcstore->type==AT_IPv6 && src_v6==TRUE)
		{
			if (*src->data == *srcstore->data && a->port2 == b->port1)
			{
				dstlist = g_list_first(b->addr2);
				while (dstlist)
				{
					dststore = (address *) (dstlist->data);
					if ((dststore->type==AT_IPv4 && src_v4==TRUE) || (dststore->type==AT_IPv6 && src_v6==TRUE))
					{
						if (*dst->data==*dststore->data && a->port1 == b->port2)
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
			/*if (cmp==ASSOC_NOT_FOUND)
			{
				cmp=sctp_assoc_address_cmp(needle, (sctp_assoc_info_t*)(list->data));
			}*/
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

sctp_assoc_info_t * add_chunk_count(address * vadd, sctp_assoc_info_t * info, guint32 direction, guint32 type)
{
	GList *list;
	address *v=NULL;
	sctp_addr_chunk *ch=NULL;
	guint8 * dat;
	int i;

		list = g_list_first(info->addr_chunk_count);
		
	while (list)
	{
		ch = (sctp_addr_chunk *)(list->data);
		if (ch->direction == direction)
		{
			v = (address *) (ch->addr);
			if (*(vadd->data)==*(v->data))
			{
				ch->addr_count[type]++;
				return info;
			}
			else
			{
				list = g_list_next(list);
			}
		}
		else
			list = g_list_next(list);
	}
	ch = g_malloc(sizeof(sctp_addr_chunk));
	ch->direction = direction;
	ch->addr = g_malloc(sizeof(address)); 
	ch->addr->type = vadd->type;
	ch->addr->len = vadd->len;
	dat = g_malloc(vadd->len);
	memcpy(dat, vadd->data, vadd->len);
	ch->addr->data = dat;
	for (i=0; i<13; i++)
		ch->addr_count[i] = 0;
	ch->addr_count[type]++;
	info->addr_chunk_count = g_list_append(info->addr_chunk_count, ch);
	
	return info;
}

sctp_assoc_info_t * add_address(address * vadd, sctp_assoc_info_t *info, guint8 direction)
{
	GList *list;
	address *v=NULL;
	
	if (direction == 1)
		list = g_list_first(info->addr1);
	else
		list = g_list_first(info->addr2);
		
	while (list)
	{
		v = (address *) (list->data);
		if (v->type == AT_IPv4 && vadd->type == AT_IPv4)
		{
			if (*vadd->data!=*v->data)
			{
				list = g_list_next(list);
			}
			else
			{
				g_free(vadd);
				return info;
			}
		}
		else if (v->type == AT_IPv6 && vadd->type == AT_IPv6)
		{
			if (strcmp(ip6_to_str((const struct e_in6_addr *)(vadd->data)), ip6_to_str((const struct e_in6_addr *)v->data)))
			{
				list = g_list_next(list);
			}
			else
			{
				g_free(vadd);
				return info;
			}
		}
		else
		{
			list = g_list_next(list);
		}
	}

	if (direction == 1)
		info->addr1 = g_list_append(info->addr1, vadd);
	else if (direction==2)
		info->addr2 = g_list_append(info->addr2, vadd);
	
	return info;
}

static int
packet(void *tapdata _U_, packet_info *pinfo , epan_dissect_t *edt _U_ , const void *data)
{
	struct _sctp_info *sctp_info;
	guint32 chunk_number = 0, tsnumber;
	sctp_tmp_info_t tmp_info;
	sctp_assoc_info_t *info = NULL;
	sctp_error_info_t *error = NULL;
	char str[200];
	guint16	type, length;
	address *store = NULL;
	tsn_t	*tsn = NULL;
	tsn_t	*sack = NULL;
	guint8  *t_s_n = NULL;
	gboolean sackchunk = FALSE;
	gboolean datachunk = FALSE;
	guint32 max;
	struct tsn_sort *tsn_s;
	guint8* addr = NULL;
	int i;

	sctp_allassocs_info_t *assoc_info=NULL;
	assoc_info = &sctp_tapinfo_struct;

	sctp_info = (struct _sctp_info *) data;
	max =0xFFFFFFFF;

	type = sctp_info->ip_src.type;

	if (type == AT_IPv4)
	{
		tmp_info.src.type = AT_IPv4;
		tmp_info.src.len  = 4;
	}
	else if (type == AT_IPv6)
	{
		tmp_info.src.type = AT_IPv6;
		tmp_info.src.len  = 16;
	}
	
	addr = g_malloc(tmp_info.src.len);
	memcpy(addr, sctp_info->ip_src.data, tmp_info.src.len);
	tmp_info.src.data = addr;

	type = sctp_info->ip_dst.type;

	if (type == AT_IPv4)
	{
		tmp_info.dst.type = AT_IPv4;
		tmp_info.dst.len  = 4;
	}
	else if (type == AT_IPv6)
	{
		tmp_info.dst.type = AT_IPv6;
		tmp_info.dst.len  = 16;
	}
	
	addr = g_malloc(tmp_info.dst.len);
	memcpy(addr, sctp_info->ip_dst.data, tmp_info.dst.len);
	tmp_info.dst.data = addr;

	tmp_info.port1 = sctp_info->sport;
	tmp_info.port2 = sctp_info->dport;

	if (sctp_info->vtag_reflected)
	{
		tmp_info.verification_tag2 = sctp_info->verification_tag;
		tmp_info.verification_tag1 = 0;
	}
	else
	{
		tmp_info.verification_tag1 = sctp_info->verification_tag;
		tmp_info.verification_tag2 = 0;
	}
	tmp_info.n_tvbs = 0;

	info = find_assoc(&tmp_info);
	if (!info)
	{
		tmp_info.n_tvbs = sctp_info->number_of_tvbs;
		sctp_tapinfo_struct.sum_tvbs+=sctp_info->number_of_tvbs;

		if (sctp_info->number_of_tvbs > 0)
		{
			info = g_malloc(sizeof(sctp_assoc_info_t));
			memset(info, 0, sizeof(sctp_assoc_info_t));
			info->src.type = tmp_info.src.type;
			info->src.len  = tmp_info.src.len;
			addr = g_malloc(tmp_info.dst.len);
			memcpy(addr,(tmp_info.src.data), tmp_info.src.len);
			info->src.data = addr;
			info->dst.type = tmp_info.dst.type;
			info->dst.len  = tmp_info.dst.len;
			addr = g_malloc(tmp_info.dst.len);
			memcpy(addr, (tmp_info.dst.data), tmp_info.dst.len);
			info->dst.data = addr;
			info->port1 = tmp_info.port1;
			info->port2 = tmp_info.port2;
			info->verification_tag1 = tmp_info.verification_tag1;
			info->verification_tag2 = tmp_info.verification_tag2;
			info->n_tvbs            = tmp_info.n_tvbs;
			info->init              = FALSE;
			info->initack           = FALSE;
			info->direction         = 0;
			info = calc_checksum(sctp_info, info);
			info->n_packets         = 1;
			info->error_info_list   = NULL;
			info->min_secs          = 0xffffffff;
			info->min_usecs         = 0xffffffff;
			info->max_secs          = 0;
			info->max_usecs         = 0;
			info->min_tsn2          = 0xFFFFFFFF;
			info->min_tsn1          = 0xffffffff;
			info->max_tsn1          = 0;
			info->max_tsn2          = 0;
			info->max_bytes1        = 0;
			info->max_bytes2        = 0;
			info->n_data_chunks     = 0;
			info->n_data_bytes      = 0;
			info->n_data_chunks_ep1 = 0;
			info->n_data_bytes_ep1  = 0;
			info->n_data_chunks_ep2 = 0;
			info->n_data_bytes_ep2  = 0;
			info->n_sack_chunks_ep1 = 0;
			info->n_sack_chunks_ep2 = 0;
			info->n_array_tsn1      = 0;
			info->n_array_tsn2      = 0;
			info->max_window1       = 0;
			info->max_window2       = 0;
			info->min_max           = NULL;
			info->sort_tsn1         = g_ptr_array_new();
			info->sort_tsn2         = g_ptr_array_new();
			info->sort_sack1        = g_ptr_array_new();
			info->sort_sack2        = g_ptr_array_new();
			for (i=0; i < NUM_CHUNKS; i++)
			{
				info->chunk_count[i] = 0;
				info->ep1_chunk_count[i] = 0;
				info->ep2_chunk_count[i] = 0;
			}
			info->addr_chunk_count = NULL;
			
			if (((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_INIT_CHUNK_ID) ||
			    ((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_INIT_ACK_CHUNK_ID) ||
			    ((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_DATA_CHUNK_ID) ||
			    ((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_SACK_CHUNK_ID))
			{
				tsn  = g_malloc(sizeof(tsn_t));
				sack = g_malloc(sizeof(tsn_t));
				tsn->tsns  = NULL;
				sack->tsns = NULL;
				sack->src.type=tsn->src.type = tmp_info.src.type;
				sack->src.len=tsn->src.len   = tmp_info.src.len;
				addr = g_malloc(tmp_info.src.len);
				memcpy(addr, tmp_info.src.data, tmp_info.src.len);
				tsn->src.data = addr;
				addr = g_malloc(tmp_info.src.len);
				memcpy(addr, tmp_info.src.data, tmp_info.src.len);
				sack->src.data = addr;
				sack->dst.type = tsn->dst.type = tmp_info.dst.type;
				sack->dst.len  =tsn->dst.len   = tmp_info.dst.len;
				addr = g_malloc(tmp_info.dst.len);
				memcpy(addr, tmp_info.dst.data, tmp_info.dst.len);
				tsn->dst.data = addr;
				addr = g_malloc(tmp_info.dst.len);
				memcpy(addr, tmp_info.dst.data, tmp_info.dst.len);
				sack->dst.data = addr;
				sack->secs=tsn->secs   = (guint32)pinfo->fd->rel_secs;
				sack->usecs=tsn->usecs = (guint32)pinfo->fd->rel_usecs;
				if (((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_DATA_CHUNK_ID) ||
					((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_SACK_CHUNK_ID))
				{
					if (tsn->secs < info->min_secs)
					{
						info->min_secs  = tsn->secs;
						info->min_usecs = tsn->usecs;
					}
					else if (tsn->secs == info->min_secs && tsn->usecs < info->min_usecs)
						info->min_usecs = tsn->usecs;

					if (tsn->secs > info->max_secs)
					{
						info->max_secs  = tsn->secs;
						info->max_usecs = tsn->usecs;
					}
					else if (tsn->secs == info->max_secs && tsn->usecs > info->max_usecs)
						info->max_usecs = tsn->usecs;
				}

				sack->frame_number = tsn->frame_number = pinfo->fd->num;
			}
			if ((tvb_get_guint8(sctp_info->tvb[0],0) == SCTP_INIT_CHUNK_ID) || (tvb_get_guint8(sctp_info->tvb[0],0) == SCTP_INIT_ACK_CHUNK_ID))
			{
				info->min_tsn1 = tvb_get_ntohl(sctp_info->tvb[0],INIT_CHUNK_INITIAL_TSN_OFFSET);
				info->verification_tag2 = tvb_get_ntohl(sctp_info->tvb[0], INIT_CHUNK_INITIATE_TAG_OFFSET);
				info->instream1 = tvb_get_ntohs(sctp_info->tvb[0],INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET);
				info->outstream1 = tvb_get_ntohs(sctp_info->tvb[0],INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET);
				for (chunk_number = 1; chunk_number < sctp_info->number_of_tvbs; chunk_number++)
				{
				type = tvb_get_ntohs(sctp_info->tvb[chunk_number],0);
					if (type == IPV4ADDRESS_PARAMETER_ID)
					{
						store = g_malloc(sizeof (address));
						store->type = AT_IPv4;;
						store->len  = 4;
						store->data = g_malloc(4);
						tvb_memcpy(sctp_info->tvb[chunk_number], (guint8 *)(store->data),IPV4_ADDRESS_OFFSET, 4);
						info = add_address(store, info, 1);
					}
					else if (type == IPV6ADDRESS_PARAMETER_ID)
					{
						store = g_malloc(sizeof (address));
						store->type = AT_IPv6;;
						store->len  = 16;
						store->data = g_malloc(16);
						tvb_memcpy(sctp_info->tvb[chunk_number], (guint8 *)(store->data),IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH);	
						info = add_address(store, info, 1);
					}
				}
				
				if (tvb_get_guint8(sctp_info->tvb[0],0) == SCTP_INIT_CHUNK_ID)
				{
					info->init = TRUE;
				}
				else
				{
					info->initack_dir = 1;
					info->initack     = TRUE;
				}
				info->chunk_count[tvb_get_guint8(sctp_info->tvb[0],0)]++;
				info->ep1_chunk_count[tvb_get_guint8(sctp_info->tvb[0],0)]++;
				info = add_chunk_count(&tmp_info.src, info, 1, tvb_get_guint8(sctp_info->tvb[0],0));
			}
			else
			{
				if (((tvb_get_guint8(sctp_info->tvb[0],0)) != SCTP_INIT_CHUNK_ID) &&
				    ((tvb_get_guint8(sctp_info->tvb[0],0)) != SCTP_INIT_ACK_CHUNK_ID) &&
				    ((tvb_get_guint8(sctp_info->tvb[0],0)) != SCTP_DATA_CHUNK_ID) &&
				    ((tvb_get_guint8(sctp_info->tvb[0],0)) != SCTP_SACK_CHUNK_ID))
				{
					tsn  = g_malloc(sizeof(tsn_t));
					sack = g_malloc(sizeof(tsn_t));
					tsn->tsns  = NULL;
					sack->tsns = NULL;
				}
				for (chunk_number = 0; chunk_number < sctp_info->number_of_tvbs; chunk_number++)
				{
					if ((tvb_get_guint8(sctp_info->tvb[chunk_number],0)) < 12)
					{
						info->chunk_count[tvb_get_guint8(sctp_info->tvb[0],0)]++;
						info->ep1_chunk_count[tvb_get_guint8(sctp_info->tvb[0],0)]++;
						info = add_chunk_count(&tmp_info.src, info, 1, tvb_get_guint8(sctp_info->tvb[0],0));
					}
					else
					{
						info->chunk_count[12]++;
						info->ep1_chunk_count[12]++;
						info = add_chunk_count(&tmp_info.src, info, 1, 12);
					}
					if (tvb_get_guint8(sctp_info->tvb[chunk_number],0) == SCTP_DATA_CHUNK_ID)
					{
						length = tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET)-DATA_CHUNK_HEADER_LENGTH;
						info->n_data_chunks++;
						info->n_data_bytes+=length;
						info->outstream1 = tvb_get_ntohs((sctp_info->tvb)[chunk_number], DATA_CHUNK_STREAM_ID_OFFSET)+1;
						tsnumber = tvb_get_ntohl((sctp_info->tvb)[chunk_number], DATA_CHUNK_TSN_OFFSET);
						if (tsnumber < info->min_tsn1)
							info->min_tsn1 = tsnumber;
						if (tsnumber > info->max_tsn1)
						{
							length=tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET)-DATA_CHUNK_HEADER_LENGTH;
							info->n_data_chunks_ep1++;
							info->n_data_bytes_ep1+=length;
							info->max_tsn1 = tsnumber;
						}
						t_s_n = g_malloc(16);
						tvb_memcpy(sctp_info->tvb[chunk_number], (guint8 *)(t_s_n),0, 16);
						tsn->tsns = g_list_append(tsn->tsns, t_s_n);
						datachunk = TRUE;
						tsn_s = g_malloc(sizeof(struct tsn_sort));
						tsn_s->tsnumber = tsnumber;
						tsn_s->secs     = tsn->secs;
						tsn_s->usecs    = tsn->usecs;
						tsn_s->offset   = 0;
						tsn_s->length   = length-DATA_CHUNK_HEADER_LENGTH;
						g_ptr_array_add(info->sort_tsn1, tsn_s);
						info->n_array_tsn1++;
					}
					if (tvb_get_guint8(sctp_info->tvb[chunk_number],0) == SCTP_SACK_CHUNK_ID)
					{
						tsnumber = tvb_get_ntohl((sctp_info->tvb)[chunk_number], SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET);
						if (tsnumber < info->min_tsn2)
							info->min_tsn2 = tsnumber;
						if (tsnumber > info->max_tsn2)
							info->max_tsn2 = tsnumber;
						info->n_sack_chunks_ep2++;
						length = tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET);
						t_s_n = g_malloc(length);
						tvb_memcpy(sctp_info->tvb[chunk_number], (guint8 *)(t_s_n),0, length);
						sack->tsns = g_list_append(sack->tsns, t_s_n);
						sackchunk = TRUE;
						tsn_s = g_malloc(sizeof(struct tsn_sort));
						tsn_s->tsnumber = tsnumber;
						tsn_s->secs     = tsn->secs;
						tsn_s->usecs    = tsn->usecs;
						tsn_s->offset   = 0;
						tsn_s->length   =  tvb_get_ntohl(sctp_info->tvb[chunk_number], SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET);
						if (tsn_s->length > info->max_window1)
							info->max_window1 = tsn_s->length;
						g_ptr_array_add(info->sort_sack2, tsn_s);
						info->n_sack_chunks_ep2++;
					}
				}
			}
			if (info->verification_tag1 != 0 || info->verification_tag2 != 0)
			{
				store = g_malloc(sizeof (address));
				store->type = tmp_info.src.type;
				store->len  = tmp_info.src.len;
				addr = g_malloc(tmp_info.src.len);
				memcpy(addr,(tmp_info.src.data),tmp_info.src.len);
				store->data = addr;
				info  = add_address(store, info, 1);
				store = g_malloc(sizeof (address));
				store->type = tmp_info.dst.type;
				store->len  = tmp_info.dst.len;
				addr = g_malloc(tmp_info.dst.len);
				memcpy(addr,(tmp_info.dst.data),tmp_info.dst.len);
				store->data = addr;
				info = add_address(store, info, 2);
				info->frame_numbers=g_list_prepend(info->frame_numbers,&(pinfo->fd->num));
				if (datachunk == TRUE)
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
				if ((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_INIT_CHUNK_ID)
					strcpy(error->chunk_info, val_to_str(tvb_get_guint8(sctp_info->tvb[0],0),chunk_type_values,"Reserved"));
				else
					for (chunk_number = 0; chunk_number < sctp_info->number_of_tvbs; chunk_number++)
						strcat(error->chunk_info, val_to_str(tvb_get_guint8(sctp_info->tvb[chunk_number],0),chunk_type_values,"Reserved"));
				error->info_text = "INFOS";
				info->error_info_list = g_list_append(info->error_info_list, error);
			}
		}
	} /* endif (!info) */
	else
	{
		if (((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_INIT_CHUNK_ID) ||
		    ((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_INIT_ACK_CHUNK_ID) ||
		    ((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_DATA_CHUNK_ID) ||
		    ((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_SACK_CHUNK_ID))
		{

			tsn  = g_malloc(sizeof(tsn_t));
			sack = g_malloc(sizeof(tsn_t));
			tsn->tsns  = NULL;
			sack->tsns = NULL;
			sack->src.type = tsn->src.type = tmp_info.src.type;
			sack->src.len  = tsn->src.len = tmp_info.src.len;
			addr = g_malloc(tmp_info.src.len);
			memcpy(addr, tmp_info.src.data, tmp_info.src.len);
			tsn->src.data = addr;
			addr = g_malloc(tmp_info.src.len);
			memcpy(addr, tmp_info.src.data, tmp_info.src.len);
			sack->src.data = addr;
			sack->dst.type = tsn->dst.type = tmp_info.dst.type;
			sack->dst.len  = tsn->dst.len = tmp_info.dst.len;
			addr = g_malloc(tmp_info.dst.len);
			memcpy(addr, tmp_info.dst.data, tmp_info.dst.len);
			tsn->dst.data = addr;			
			addr = g_malloc(tmp_info.dst.len);
			memcpy(addr, tmp_info.dst.data, tmp_info.dst.len);
			sack->dst.data = addr;
			sack->secs=tsn->secs = (guint32)pinfo->fd->rel_secs;
			sack->usecs=tsn->usecs = (guint32)pinfo->fd->rel_usecs;
			if (((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_DATA_CHUNK_ID) ||
			((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_SACK_CHUNK_ID))
			{
				if (tsn->secs < info->min_secs)
				{
					info->min_secs  = tsn->secs;
					info->min_usecs = tsn->usecs;
				}
				else if (tsn->secs == info->min_secs && tsn->usecs < info->min_usecs)
					info->min_usecs = tsn->usecs;

				if (tsn->secs > info->max_secs)
					{
						info->max_secs  = tsn->secs;
						info->max_usecs = tsn->usecs;
					}
					else if (tsn->secs == info->max_secs && tsn->usecs > info->max_usecs)
						info->max_usecs = tsn->usecs;
			}
			sack->frame_number = tsn->frame_number = pinfo->fd->num;
		}
		info->frame_numbers = g_list_prepend(info->frame_numbers,&(pinfo->fd->num));

		store = g_malloc(sizeof (address));
		store->type = tmp_info.src.type;
		store->len  = tmp_info.src.len;
		addr = g_malloc(tmp_info.src.len);
		memcpy(addr,(tmp_info.src.data),tmp_info.src.len);
		store->data = addr;
			
		if (info->direction == 1)
			info = add_address(store, info, 1);
		else if (info->direction == 2)
			info = add_address(store, info, 2);
			
		store = g_malloc(sizeof (address));
		store->type = tmp_info.dst.type;
		store->len  = tmp_info.dst.len;
		addr = g_malloc(tmp_info.dst.len);
		memcpy(addr,(tmp_info.dst.data),tmp_info.dst.len);
		store->data = addr;
		
		if (info->direction == 1)
			info = add_address(store, info, 2);
		else if (info->direction == 2)
			info = add_address(store, info, 1);

		if (((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_INIT_ACK_CHUNK_ID) ||
		    ((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_INIT_CHUNK_ID))
		{
			tsnumber = tvb_get_ntohl((sctp_info->tvb)[chunk_number], INIT_CHUNK_INITIAL_TSN_OFFSET);

			if (info->direction == 2)
			{
				if (tsnumber < info->min_tsn2)
					info->min_tsn2 = tsnumber;
				if (tsnumber > info->max_tsn2)
					info->max_tsn2 = tsnumber;
				info->instream2 = tvb_get_ntohs(sctp_info->tvb[0],INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET);
				info->outstream2 = tvb_get_ntohs(sctp_info->tvb[0],INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET);
				/*info->initack_dir=2;*/
				info->tsn2 = g_list_prepend(info->tsn2, tsn);
			}
			else if (info->direction == 1)
			{
				if (tsnumber < info->min_tsn1)
					info->min_tsn1 = tsnumber;
				if (tsnumber > info->max_tsn1)
					info->max_tsn1 = tsnumber;
				info->instream1 = tvb_get_ntohs(sctp_info->tvb[0],INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET);
				info->outstream1 = tvb_get_ntohs(sctp_info->tvb[0],INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET);
				/*info->initack_dir=1;*/
				info->tsn1 = g_list_prepend(info->tsn1, tsn);
			}
			info->chunk_count[tvb_get_guint8(sctp_info->tvb[0],0)]++;
			if (info->direction == 1)
				info->ep1_chunk_count[tvb_get_guint8(sctp_info->tvb[0],0)]++;
			else
				info->ep2_chunk_count[tvb_get_guint8(sctp_info->tvb[0],0)]++;
			info = add_chunk_count(&tmp_info.src, info, info->direction, tvb_get_guint8(sctp_info->tvb[0],0));
			for (chunk_number = 1; chunk_number < sctp_info->number_of_tvbs; chunk_number++)
			{
				type = tvb_get_ntohs(sctp_info->tvb[chunk_number],0);
					if (type == IPV4ADDRESS_PARAMETER_ID)
					{
						store = g_malloc(sizeof (address));
						store->type = AT_IPv4;;
						store->len  = 4;
						store->data = g_malloc(4);
						tvb_memcpy(sctp_info->tvb[chunk_number], (guint8 *)(store->data),IPV4_ADDRESS_OFFSET, 4);
						info = add_address(store, info, info->direction);
					}
					else if (type == IPV6ADDRESS_PARAMETER_ID)
					{
						store = g_malloc(sizeof (address));
						store->type = AT_IPv6;;
						store->len  = 16;
						store->data = g_malloc(16);
						tvb_memcpy(sctp_info->tvb[chunk_number], (guint8 *)(store->data),IPV6_ADDRESS_OFFSET, IPV6_ADDRESS_LENGTH);
						info = add_address(store, info, info->direction);
					}
					}
			if ((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_INIT_ACK_CHUNK_ID)
			{
				info->initack = TRUE;
				info->initack_dir = info->direction;
			}
			else
			if ((tvb_get_guint8(sctp_info->tvb[0],0)) == SCTP_INIT_CHUNK_ID)
			{
				info->init = TRUE;
			}
		}
		else
		{
			if (((tvb_get_guint8(sctp_info->tvb[0],0)) != SCTP_INIT_ACK_CHUNK_ID) &&
			    ((tvb_get_guint8(sctp_info->tvb[0],0)) != SCTP_DATA_CHUNK_ID) &&
			    ((tvb_get_guint8(sctp_info->tvb[0],0)) != SCTP_SACK_CHUNK_ID))
			{
				sack = g_malloc(sizeof(tsn_t));
				sack->tsns = NULL;
				tsn = g_malloc(sizeof(tsn_t));
				tsn->tsns = NULL;
			}
			for (chunk_number = 0; chunk_number < sctp_info->number_of_tvbs; chunk_number++)
			{
				if ((tvb_get_guint8(sctp_info->tvb[chunk_number],0)) < 12)
				{
					info->chunk_count[tvb_get_guint8(sctp_info->tvb[chunk_number],0)]++;
					if (info->direction == 1)
						info->ep1_chunk_count[tvb_get_guint8(sctp_info->tvb[chunk_number],0)]++;
					else
						info->ep2_chunk_count[tvb_get_guint8(sctp_info->tvb[chunk_number],0)]++;
					info = add_chunk_count(&tmp_info.src, info,info->direction, tvb_get_guint8(sctp_info->tvb[chunk_number],0));
				}
				else
				{
					info->chunk_count[12]++;
					if (info->direction == 1)
						info->ep1_chunk_count[12]++;
					else
						info->ep2_chunk_count[12]++;
					info = add_chunk_count(&tmp_info.src, info, info->direction,12);
				}
				if ((tvb_get_guint8(sctp_info->tvb[chunk_number],0)) == SCTP_DATA_CHUNK_ID)
				{
					tsnumber = tvb_get_ntohl((sctp_info->tvb)[chunk_number], DATA_CHUNK_TSN_OFFSET);
					t_s_n = g_malloc(16);
					tvb_memcpy(sctp_info->tvb[chunk_number], (guint8 *)(t_s_n),0, 16);
					tsn->tsns = g_list_append(tsn->tsns, t_s_n);
					datachunk = TRUE;
					length=tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET)-DATA_CHUNK_HEADER_LENGTH;
					info->n_data_chunks++;
					info->n_data_bytes+=length;
					tsn_s = g_malloc(sizeof(struct tsn_sort));
					tsn_s->tsnumber = tsnumber;
					tsn_s->secs  = tsn->secs;
					tsn_s->usecs = tsn->usecs;
					tsn_s->offset = 0;
					tsn_s->length = length;
	
					if (info->direction == 1)
					{
						if(tsnumber < info->min_tsn1)
							info->min_tsn1 = tsnumber;
						if ((info->init == TRUE || (info->initack == TRUE && info->initack_dir == 1))&& tsnumber >= info->min_tsn1 && tsnumber <= info->max_tsn1)
						{
							length = tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET)-DATA_CHUNK_HEADER_LENGTH;
							info->n_data_chunks_ep1++;
							info->n_data_bytes_ep1 += length;
						}
						if(tsnumber > info->max_tsn1)
						{
							info->max_tsn1 = tsnumber;
							length = tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET)-DATA_CHUNK_HEADER_LENGTH;
							info->n_data_chunks_ep1++;
							info->n_data_bytes_ep1 += length;
						}
						if (info->init == FALSE)
							info->outstream1 = tvb_get_ntohs((sctp_info->tvb)[chunk_number], DATA_CHUNK_STREAM_ID_OFFSET)+1;
						if (info->initack == FALSE)
							info->instream2 = tvb_get_ntohs((sctp_info->tvb)[chunk_number], DATA_CHUNK_STREAM_ID_OFFSET)+1;
	
						g_ptr_array_add(info->sort_tsn1, tsn_s);
						info->n_array_tsn1++;
					}
					else if (info->direction == 2)
					{
	
						if(tsnumber < info->min_tsn2)
							info->min_tsn2 = tsnumber;
	
						if ((info->initack == TRUE && info->initack_dir == 2)&& tsnumber >= info->min_tsn2 && tsnumber <= info->max_tsn2)
						{
							length = tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET)-DATA_CHUNK_HEADER_LENGTH;
							info->n_data_chunks_ep2++;
							info->n_data_bytes_ep2+=length;
						}
						if(tsnumber > info->max_tsn2)
						{
							info->max_tsn2 = tsnumber;
							length = tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET)-DATA_CHUNK_HEADER_LENGTH;
							info->n_data_chunks_ep2++;
							info->n_data_bytes_ep2+=length;
						}
						if (info->init == FALSE)
							info->instream1 = tvb_get_ntohs((sctp_info->tvb)[chunk_number], DATA_CHUNK_STREAM_ID_OFFSET)+1;
						if (info->initack == FALSE)
							info->outstream2 = tvb_get_ntohs((sctp_info->tvb)[chunk_number], DATA_CHUNK_STREAM_ID_OFFSET)+1;
	
						g_ptr_array_add(info->sort_tsn2, tsn_s);
						info->n_array_tsn2++;
					}
				}
				else if (tvb_get_guint8(sctp_info->tvb[chunk_number],0) == SCTP_SACK_CHUNK_ID)
				{
					tsnumber = tvb_get_ntohl((sctp_info->tvb)[chunk_number], SACK_CHUNK_CUMULATIVE_TSN_ACK_OFFSET);
					length = tvb_get_ntohs(sctp_info->tvb[chunk_number], CHUNK_LENGTH_OFFSET);
					t_s_n = g_malloc(length);
					tvb_memcpy(sctp_info->tvb[chunk_number], (guint8 *)(t_s_n),0, length);
					sack->tsns = g_list_append(sack->tsns, t_s_n);
					sackchunk = TRUE;
					tsn_s = g_malloc(sizeof(struct tsn_sort));
					tsn_s->tsnumber = tsnumber;
					tsn_s->secs   = tsn->secs;
					tsn_s->usecs  = tsn->usecs;
					tsn_s->offset = 0;
					tsn_s->length = tvb_get_ntohl(sctp_info->tvb[chunk_number], SACK_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET);
	
	
					if (info->direction == 2)
					{
						if(tsnumber < info->min_tsn1)
							info->min_tsn1 = tsnumber;
						if(tsnumber > info->max_tsn1)
							info->max_tsn1 = tsnumber;
						if (tsn_s->length > info->max_window1)
								info->max_window1 = tsn_s->length;
						g_ptr_array_add(info->sort_sack1, tsn_s);
						info->n_sack_chunks_ep1++;
					}
					else if (info->direction == 1)
					{
	
						if(tsnumber < info->min_tsn2)
							info->min_tsn2 = tsnumber;
						if(tsnumber > info->max_tsn2)
							info->max_tsn2 = tsnumber;
						if (tsn_s->length > info->max_window2)
								info->max_window2 = tsn_s->length;
						g_ptr_array_add(info->sort_sack2, tsn_s);
						info->n_sack_chunks_ep2++;
					}
					
				}
			}

		}
		if (datachunk == TRUE)
		{
			if (info->direction == 1)
				info->tsn1 = g_list_prepend(info->tsn1, tsn);
			else if (info->direction == 2)
				info->tsn2 = g_list_prepend(info->tsn2, tsn);
		}
		if (sackchunk == TRUE)
		{
			if (info->direction == 1)
					info->sack2 = g_list_prepend(info->sack2, sack);
				else if(info->direction == 2)
					info->sack1 = g_list_prepend(info->sack1, sack);
		}
		info->n_tvbs += sctp_info->number_of_tvbs;
		sctp_tapinfo_struct.sum_tvbs += sctp_info->number_of_tvbs;
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
gtk_sctpstat_init(const char *dummy _U_)
{

}

static void sctp_update(void *dummy _U_)
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
		register_stat_cmd_arg("sctp",gtk_sctpstat_init);
		if ((error_string = register_tap_listener("sctp", &sctp_tapinfo_struct, NULL, reset, packet, sctp_update))) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
			g_string_free(error_string, TRUE);
			return;
		}
		sctp_tapinfo_struct.is_registered=TRUE;
	}
}
