/* tap-iostat.c
 * iostat   2002 Ronnie Sahlberg
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include "epan/epan_dissect.h"
#include "epan/packet_info.h"
#include <epan/tap.h>
#include "stat.h"
#include "register.h"


typedef struct _io_stat_t {
	gint32 interval;	/* unit is ms */
	guint32 num_items;
	struct _io_stat_item_t *items;
	const char **filters;
} io_stat_t;	

#define CALC_TYPE_BYTES	0
#define CALC_TYPE_COUNT	1
#define CALC_TYPE_SUM	2
#define CALC_TYPE_MIN	3
#define CALC_TYPE_MAX	4
#define CALC_TYPE_AVG	5

typedef struct _io_stat_item_t {
	io_stat_t *parent;
	struct _io_stat_item_t *next;
	struct _io_stat_item_t *prev;
	gint32 time;		/* unit is ms since start of capture */
	int calc_type;
	int hf_index;
	guint32 frames;
	guint32 num;
	guint32 counter;
} io_stat_item_t;


static int
iostat_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *dummy _U_)
{
	io_stat_item_t *mit = arg;
	io_stat_item_t *it;
	gint32 current_time;
	GPtrArray *gp;
	guint i;

	current_time=((pinfo->fd->rel_secs*1000)+(pinfo->fd->rel_usecs/1000));

	/* the prev item before the main one is always the last interval we saw packets for */
	it=mit->prev;

	/* XXX for the time being, just ignore all frames that are in the past.
	   should be fixed in the future but hopefully it is uncommon */
	if(current_time<it->time){
		return FALSE;
	}

	/* we have moved into a new interval, we need to create a new struct */
	if(current_time>=(it->time+mit->parent->interval)){
		it->next=g_malloc(sizeof(io_stat_item_t));
		it->next->prev=it;
		it->next->next=NULL;
		it=it->next;
		mit->prev=it;

		it->time=(current_time / mit->parent->interval) * mit->parent->interval;
		it->frames=0;
		it->counter=0;
		it->num=0;
		it->calc_type=it->prev->calc_type;
		it->hf_index=it->prev->hf_index;
	}

	/* it will now give us the current structure to use to store the data in */
	it->frames++;

	switch(it->calc_type){
	case CALC_TYPE_BYTES:
		it->counter+=pinfo->fd->pkt_len;
		break;
	case CALC_TYPE_COUNT:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			it->counter+=gp->len;
		}
		break;
	case CALC_TYPE_SUM:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			for(i=0;i<gp->len;i++){
				it->counter+=fvalue_get_integer(&((field_info *)gp->pdata[i])->value);
			}
		}
		break;
	case CALC_TYPE_MIN:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			int type;
			guint32 val;
			nstime_t *new_time;

			type=proto_registrar_get_ftype(it->hf_index);
			for(i=0;i<gp->len;i++){
				switch(type){
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
					val=fvalue_get_integer(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if(val<it->counter){
						it->counter=val;
					}				
					break;
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
					val=fvalue_get_integer(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if((gint32)val<(gint32)(it->counter)){
						it->counter=val;
					}				
					break;
				case FT_RELATIVE_TIME:
					new_time=fvalue_get(&((field_info *)gp->pdata[i])->value);
					val=new_time->secs*1000+new_time->nsecs/1000000;
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if(val<it->counter){
						it->counter=val;
					}				
					break;
				}
			}
		}
		break;
	case CALC_TYPE_MAX:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			int type;
			guint32 val;
			nstime_t *new_time;

			type=proto_registrar_get_ftype(it->hf_index);
			for(i=0;i<gp->len;i++){
				switch(type){
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
					val=fvalue_get_integer(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if(val>it->counter){
						it->counter=val;
					}				
					break;
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
					val=fvalue_get_integer(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if((gint32)val>(gint32)(it->counter)){
						it->counter=val;
					}				
					break;
				case FT_RELATIVE_TIME:
					new_time=fvalue_get(&((field_info *)gp->pdata[i])->value);
					val=new_time->secs*1000+new_time->nsecs/1000000;
					if((it->frames==1)&&(i==0)){
						it->counter=val;
					} else if(val>it->counter){
						it->counter=val;
					}				
					break;
				}
			}
		}
		break;
	case CALC_TYPE_AVG:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			int type;
			guint32 val;
			nstime_t *new_time;

			type=proto_registrar_get_ftype(it->hf_index);
			for(i=0;i<gp->len;i++){
				it->num++;
				switch(type){
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
					val=fvalue_get_integer(&((field_info *)gp->pdata[i])->value);
					it->counter+=val;
					break;
				case FT_RELATIVE_TIME:
					new_time=fvalue_get(&((field_info *)gp->pdata[i])->value);
					val=new_time->secs*1000+new_time->nsecs/1000000;
					it->counter+=val;
					break;
				}
			}
		}
		break;
	}

	return TRUE;
}

static void
iostat_draw(void *arg)
{
	io_stat_item_t *mit = arg;
	io_stat_t *iot;
	io_stat_item_t **items;
	guint32 *frames;
	guint32 *counters;
	guint32 *num;
	guint32 i,more_items;
	gint t;

	iot=mit->parent;

	printf("\n");
	printf("===================================================================\n");
	printf("IO Statistics\n");
	printf("Interval: %d.%03d secs\n", iot->interval/1000, iot->interval%1000);
	for(i=0;i<iot->num_items;i++){
		printf("Column #%d: %s\n",i,iot->filters[i]?iot->filters[i]:"");
	}
	printf("                ");
	for(i=0;i<iot->num_items;i++){
		printf("|   Column #%-2d   ",i);
	}
	printf("\n");
	printf("Time            ");
	for(i=0;i<iot->num_items;i++){
		switch(iot->items[i].calc_type){
		case CALC_TYPE_BYTES:
			printf("|frames|  bytes  ");
			break;
		case CALC_TYPE_COUNT:
			printf("|          COUNT ");
			break;
		case CALC_TYPE_SUM:
			printf("|            SUM ");
			break;
		case CALC_TYPE_MIN:
			printf("|            MIN ");
			break;
		case CALC_TYPE_MAX:
			printf("|            MAX ");
			break;
		case CALC_TYPE_AVG:
			printf("|            AVG ");
			break;
		}
	}
	printf("\n");

	items=g_malloc(sizeof(io_stat_item_t *)*iot->num_items);
	frames=g_malloc(sizeof(guint32)*iot->num_items);
	counters=g_malloc(sizeof(guint32)*iot->num_items);
	num=g_malloc(sizeof(guint32)*iot->num_items);
	/* preset all items at the first interval */
	for(i=0;i<iot->num_items;i++){
		items[i]=&iot->items[i];
	}

	/* loop the items until we run out of them all */
	t=0;
	do {
		more_items=0;
		for(i=0;i<iot->num_items;i++){
			frames[i]=0;
			counters[i]=0;
			num[i]=0;
		}
		for(i=0;i<iot->num_items;i++){
			if(items[i] && (t>=(items[i]->time+iot->interval))){
				items[i]=items[i]->next;
			}

			if(items[i] && (t<(items[i]->time+iot->interval)) && (t>=items[i]->time) ){
				frames[i]=items[i]->frames;
				counters[i]=items[i]->counter;
				num[i]=items[i]->num;
			}

			if(items[i]){
				more_items=1;
			}
		}

		if(more_items){
			printf("%03d.%03d-%03d.%03d  ",
				t/1000,t%1000,
				(t+iot->interval)/1000,(t+iot->interval)%1000);
			for(i=0;i<iot->num_items;i++){
				switch(iot->items[i].calc_type){
				case CALC_TYPE_BYTES:
					printf("%6d %9d ",frames[i],counters[i]);
					break;
				case CALC_TYPE_COUNT:
					printf("        %8d ", counters[i]);
					break;
				case CALC_TYPE_SUM:
					printf("        %8d ", counters[i]);
					break;
				case CALC_TYPE_MIN:
					switch(proto_registrar_get_ftype(iot->items[i].hf_index)){
					case FT_UINT8:
					case FT_UINT16:
					case FT_UINT24:
					case FT_UINT32:
						printf("        %8u ", counters[i]);
						break;
					case FT_INT8:
					case FT_INT16:
					case FT_INT24:
					case FT_INT32:
						printf("        %8d ", counters[i]);
						break;
					case FT_RELATIVE_TIME:
						printf("      %6d.%03d ", counters[i]/1000, counters[i]%1000);
						break;
					}
					break;
				case CALC_TYPE_MAX:
					switch(proto_registrar_get_ftype(iot->items[i].hf_index)){
					case FT_UINT8:
					case FT_UINT16:
					case FT_UINT24:
					case FT_UINT32:
						printf("        %8u ", counters[i]);
						break;
					case FT_INT8:
					case FT_INT16:
					case FT_INT24:
					case FT_INT32:
						printf("        %8d ", counters[i]);
						break;
					case FT_RELATIVE_TIME:
						printf("      %6d.%03d ", counters[i]/1000, counters[i]%1000);
						break;
					}
					break;
				case CALC_TYPE_AVG:
					if(num[i]==0){
						num[i]=1;
					}
					switch(proto_registrar_get_ftype(iot->items[i].hf_index)){
					case FT_UINT8:
					case FT_UINT16:
					case FT_UINT24:
					case FT_UINT32:
						printf("        %8u ", counters[i]/num[i]);
						break;
					case FT_INT8:
					case FT_INT16:
					case FT_INT24:
					case FT_INT32:
						printf("        %8d ", counters[i]/num[i]);
						break;
					case FT_RELATIVE_TIME:
						counters[i]/=num[i];
						printf("      %6d.%03d ", counters[i]/1000, counters[i]%1000);
						break;
					}
					break;

				}
			}
			printf("\n");
		}

		t+=iot->interval;
	} while(more_items);

	printf("===================================================================\n");

	g_free(items);
	g_free(frames);
	g_free(counters);
	g_free(num);
}


static int
get_calc_field(const char *filter, const char **flt)
{
	char field[256];
	int i;
	header_field_info *hfi;

	*flt="";
	for(i=0;filter[i];i++){
		if(i>=255){
			fprintf(stderr,"get_calc_field(): Too long field name: %s\n", filter);
			exit(10);
		}
		if(filter[i]==')'){
			break;
		}
		field[i]=filter[i];
		field[i+1]=0;
	}
	if(filter[i]==')'){
		*flt=&filter[i+1];
	}

	hfi=proto_registrar_get_byname(field);
	if(!hfi){
		fprintf(stderr, "get_calc_field(): No such field %s\n", field);
		exit(10);
	}
	
	return hfi->id;
}

static void
register_io_tap(io_stat_t *io, int i, const char *filter)
{
	GString *error_string;
	const char *flt;

	io->items[i].prev=&io->items[i];
	io->items[i].next=NULL;
	io->items[i].parent=io;
	io->items[i].time=0;
	io->items[i].calc_type=CALC_TYPE_BYTES;
	io->items[i].frames=0;
	io->items[i].counter=0;
	io->items[i].num=0;
	io->filters[i]=filter;
	flt=filter;

	if(!filter){
		filter="";
	}
	if(!strncmp("COUNT(", filter, 6)){
		io->items[i].calc_type=CALC_TYPE_COUNT;
		io->items[i].hf_index=get_calc_field(filter+6, &flt);
	} else if (!strncmp("SUM(", filter, 4)){
		io->items[i].calc_type=CALC_TYPE_SUM;
		io->items[i].hf_index=get_calc_field(filter+4, &flt);
		switch(proto_registrar_get_nth(io->items[i].hf_index)->type){
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			break;
		default:
			fprintf(stderr, "register_io_tap(): Invalid field type. SUM(x) only supports 8,16,24 and 32 byte integer fields\n");
			exit(10);
		}
	} else if (!strncmp("MIN(", filter, 4)){
		io->items[i].calc_type=CALC_TYPE_MIN;
		io->items[i].hf_index=get_calc_field(filter+4, &flt);
		switch(proto_registrar_get_nth(io->items[i].hf_index)->type){
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_RELATIVE_TIME:
			break;
		default:
			fprintf(stderr, "register_io_tap(): Invalid field type. MIN(x) only supports 8,16,24 and 32 byte integer fields and relative time fields\n");
			exit(10);
		}
	} else if (!strncmp("MAX(", filter, 4)){
		io->items[i].calc_type=CALC_TYPE_MAX;
		io->items[i].hf_index=get_calc_field(filter+4, &flt);
		switch(proto_registrar_get_nth(io->items[i].hf_index)->type){
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_RELATIVE_TIME:
			break;
		default:
			fprintf(stderr, "register_io_tap(): Invalid field type. MAX(x) only supports 8,16,24 and 32 byte integer fields and relative time fields\n");
			exit(10);
		}
	} else if (!strncmp("AVG(", filter, 4)){
		io->items[i].calc_type=CALC_TYPE_AVG;
		io->items[i].hf_index=get_calc_field(filter+4, &flt);
		switch(proto_registrar_get_nth(io->items[i].hf_index)->type){
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_RELATIVE_TIME:
			break;
		default:
			fprintf(stderr, "register_io_tap(): Invalid field type. AVG(x) only supports 8,16,24 and 32 byte integer fields and relative time fields\n");
			exit(10);
		}
	}

/*
CALC_TYPE_SUM	2
CALC_TYPE_MIN	3
CALC_TYPE_MAX	4
CALC_TYPE_AVG	5
*/

	error_string=register_tap_listener("frame", &io->items[i], flt, NULL, iostat_packet, i?NULL:iostat_draw);
	if(error_string){
		g_free(io->items);
		g_free(io);
		fprintf(stderr, "tethereal: Couldn't register io,stat tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

void
iostat_init(const char *optarg)
{
	float interval_float;
	gint32 interval; 
	int pos=0;
	io_stat_t *io;
	const char *filter=NULL;

	if(sscanf(optarg,"io,stat,%f,%n",&interval_float,&pos)==1){
		if(pos){
			filter=optarg+pos;
		} else {
			filter=NULL;
		}
	} else {
		fprintf(stderr, "tethereal: invalid \"-z io,stat,<interval>[,<filter>]\" argument\n");
		exit(1);
	}


	/* make interval be number of ms */
	interval=(gint32)(interval_float*1000.0+0.9);	
	if(interval<1){
		fprintf(stderr, "tethereal:iostat_init()  interval must be >=0.001 seconds\n");
		exit(10);
	}
	
	io=g_malloc(sizeof(io_stat_t));
	io->interval=interval;
	if((!filter)||(filter[0]==0)){
		io->num_items=1;
		io->items=g_malloc(sizeof(io_stat_item_t)*io->num_items);
		io->filters=g_malloc(sizeof(char *)*io->num_items);

		register_io_tap(io, 0, NULL);
	} else {
		const char *str,*pos;
		char *tmp;
		int i;
		/* find how many ',' separated filters we have */
		str=filter;
		io->num_items=1;
		while((str=strchr(str,','))){
			io->num_items++;
			str++;
		}

		io->items=g_malloc(sizeof(io_stat_item_t)*io->num_items);
		io->filters=g_malloc(sizeof(char *)*io->num_items);

		/* for each filter, register a tap listener */		
		i=0;
		str=filter;
		do{
			pos=strchr(str,',');
			if(pos==str){
				register_io_tap(io, i, NULL);
			} else if(pos==NULL) {
				tmp=g_malloc(strlen(str)+1);
				strcpy(tmp,str);
				register_io_tap(io, i, tmp);
			} else {
				tmp=g_malloc((pos-str)+1);
				strncpy(tmp,str,(pos-str));
				tmp[pos-str]=0;
				register_io_tap(io, i, tmp);
			}
			str=pos+1;
			i++;			
		} while(pos);
	}			
}

void
register_tap_listener_iostat(void)
{
	register_stat_cmd_arg("io,stat,", iostat_init);
}
