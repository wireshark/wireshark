/* tap-iostat.c
 * iostat   2002 Ronnie Sahlberg
 *
 * $Id: tap-iostat.c,v 1.1 2002/11/01 01:49:38 sahlberg Exp $
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

/* This module provides rpc call/reply RTT statistics to tethereal.
 * It is only used by tethereal and not ethereal
 *
 * It serves as an example on how to use the tap api.
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
#include "tap.h"
#include "register.h"


typedef struct _io_stat_t {
	gint32 interval;
	guint32 num_items;
	struct _io_stat_item_t *items;
	char **filters;
} io_stat_t;	

typedef struct _io_stat_item_t {
	io_stat_t *parent;
	struct _io_stat_item_t *next;
	struct _io_stat_item_t *prev;
	gint32 time;
	guint32 frames;
	guint32 bytes;
} io_stat_item_t;

#ifdef REMOVED
/* Tethereal does not use the reset callback.
   But if someone ports this feature to Gtk with a nice gui, this is what
   reset should look like.
*/
static void
iostat_reset(io_stat_item_t *mit)
{
	io_stat_item_t *it;

	mit->prev=mit;
	mit->time=0;
	mit->frames=0;
	mit->bytes=0;
	while(mit->next){
		it=mit->next;
		mit=mit->next->next;
		g_free(it);
	}
}

/* function to remove and clean up an io stat. would be used by Gtk/Gtk2 version
   io iostat when the iostat window is closed.
*/
static void 
iostat_cleanup(io_stat_t *io)
{
	int i;

	for(i=0;i<io->num_items;i++){
		if(filters[i]){
			g_free(filters[i]);
			filters[i]=NULL;
		}
		iostat_reset(&io->items[i]);
		remove_tap_listener(&io->items[i]);
	}
	g_free(io->items);
	g_free(io->filters);
	g_free(io);
}

#endif

static int
iostat_packet(io_stat_item_t *mit, packet_info *pinfo, epan_dissect_t *edt _U_, void *dummy _U_)
{
	io_stat_item_t *it;

	/* the prev item before the main one is always the last interval we saw packets for */
	it=mit->prev;

	/* XXX for the time being, just ignore all frames that are in the past.
	   should be fixed in the future but hopefully it is uncommon */
	if(pinfo->fd->rel_secs<it->time){
		return FALSE;
	}

	/* we have moved into a new interval, we need to create a new struct */
	if(pinfo->fd->rel_secs>=(it->time+mit->parent->interval)){
		it->next=g_malloc(sizeof(io_stat_item_t));
		it->next->prev=it;
		it->next->next=NULL;
		it=it->next;
		mit->prev=it;

		it->time=(pinfo->fd->rel_secs / mit->parent->interval) * mit->parent->interval;
		it->frames=0;
		it->bytes=0;
	}

	/* it will now give us the current structure to use to store the data in */
	it->frames++;
	it->bytes+=pinfo->fd->pkt_len;
	
	return TRUE;
}

static void
iostat_draw(io_stat_item_t *mit)
{
	io_stat_t *iot;
	io_stat_item_t **items;
	guint32 *frames;
	guint32 *bytes;
	guint32 i,more_items;
	gint t;

	iot=mit->parent;

	printf("\n");
	printf("===================================================================\n");
	printf("IO Statistics\n");
	printf("Interval: %d secs\n", iot->interval);
	for(i=0;i<iot->num_items;i++){
		printf("Column #%d: %s\n",i,iot->filters[i]?iot->filters[i]:"");
	}
	printf("            ");
	for(i=0;i<iot->num_items;i++){
		printf("|   Column #%-2d   ",i);
	}
	printf("\n");
	printf("Time        ");
	for(i=0;i<iot->num_items;i++){
		printf("|frames|  bytes  ");
	}
	printf("\n");

	items=g_malloc(sizeof(io_stat_item_t *)*iot->num_items);
	frames=g_malloc(sizeof(guint32)*iot->num_items);
	bytes=g_malloc(sizeof(guint32)*iot->num_items);
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
			bytes[i]=0;
		}
		for(i=0;i<iot->num_items;i++){
			if(items[i] && (t>=(items[i]->time+iot->interval))){
				items[i]=items[i]->next;
			}

			if(items[i] && (t<(items[i]->time+iot->interval)) && (t>=items[i]->time) ){
				frames[i]=items[i]->frames;
				bytes[i]=items[i]->bytes;
			}

			if(items[i]){
				more_items=1;
			}
		}

		if(more_items){
			printf("%5d-%5d  ",t,t+iot->interval);
			for(i=0;i<iot->num_items;i++){
				printf("%6d %9d ",frames[i],bytes[i]);
			}
			printf("\n");
		}

		t+=iot->interval;
	} while(more_items);

	printf("===================================================================\n");

	g_free(items);
	g_free(frames);
	g_free(bytes);
}


static void
register_io_tap(io_stat_t *io, int i, char *filter)
{
	io->items[i].prev=&io->items[i];
	io->items[i].next=NULL;
	io->items[i].parent=io;
	io->items[i].time=0;
	io->items[i].frames=0;
	io->items[i].bytes=0;
	io->filters[i]=filter;

	if(register_tap_listener("frame", &io->items[i], filter, NULL, (void*)iostat_packet, i?NULL:(void*)iostat_draw)){
		g_free(io->items);
		g_free(io);
		fprintf(stderr,"tethereal: iostat_init() failed to attach tap\n");
		exit(1);
	}
}

void
iostat_init(char *optarg)
{
	int interval, pos=0;
	io_stat_t *io;
	char *filter=NULL;

	if(sscanf(optarg,"io,stat,%d,%n",&interval,&pos)==1){
		if(pos){
			filter=optarg+pos;
		} else {
			filter=NULL;
		}
	} else {
		fprintf(stderr, "tethereal: invalid \"-z io,stat,<interval>[,<filter>]\" argument\n");
		exit(1);
	}

	if(interval<1){
		fprintf(stderr, "tethereal:iostat_init()  interval must be >0 seconds\n");
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
		char *str,*pos,*tmp;
		int i;
		/* find how many ',' separated filters we have */
		str=filter;
		io->num_items=1;
		while((str=index(str,','))){
			io->num_items++;
			str++;
		}

		io->items=g_malloc(sizeof(io_stat_item_t)*io->num_items);
		io->filters=g_malloc(sizeof(char *)*io->num_items);

		/* for each filter, register a tap listener */		
		i=0;
		str=filter;
		do{
			pos=index(str,',');
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
	register_ethereal_tap("io,stat,", iostat_init, NULL, NULL);
}

