/* emem.c
 * Ethereal memory management and garbage collection functions
 * Ronnie Sahlberg 2005
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
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef _WIN32
#include <process.h>    /* getpid */
#endif

#include <glib.h>
#include <proto.h>
#include "emem.h"
#include <wiretap/file_util.h>

/* When required, allocate more memory from the OS in this size chunks */
#define EMEM_PACKET_CHUNK_SIZE 10485760

/* The maximum number of allocations per chunk */
#define EMEM_ALLOCS_PER_CHUNK (EMEM_PACKET_CHUNK_SIZE / 512)

/*
 * Tools like Valgrind and ElectricFence don't work well with memchunks.
 * Uncomment the defines below to make {ep|se}_alloc() allocate each
 * object individually.
 */
/* #define EP_DEBUG_FREE 1 */
/* #define SE_DEBUG_FREE 1 */

#if GLIB_MAJOR_VERSION >= 2
GRand   *rand_state = NULL;
#endif

#define EMEM_CANARY_SIZE 8
#define EMEM_CANARY_DATA_SIZE (EMEM_CANARY_SIZE * 2 - 1)
guint8  ep_canary[EMEM_CANARY_DATA_SIZE], se_canary[EMEM_CANARY_DATA_SIZE];

typedef struct _emem_chunk_t {
	struct _emem_chunk_t *next;
	unsigned int	amount_free;
	unsigned int	free_offset;
	char *buf;
#if ! defined(EP_DEBUG_FREE) && ! defined(SE_DEBUG_FREE)
	unsigned int	c_count;
	void		*canary[EMEM_ALLOCS_PER_CHUNK];
	guint8		cmp_len[EMEM_ALLOCS_PER_CHUNK];
#endif
} emem_chunk_t;

typedef struct _emem_header_t {
  emem_chunk_t *free_list;
  emem_chunk_t *used_list;
} emem_header_t;

static emem_header_t ep_packet_mem;
static emem_header_t se_packet_mem;

/*
 * Set a canary value to be placed between memchunks.
 */

void
emem_canary(guint8 *canary) {
	int i;

	/* First, use GLib's random function if we have it */
#if GLIB_MAJOR_VERSION >= 2
	if (rand_state == NULL) {
		rand_state = g_rand_new();
	}
	for (i = 0; i < EMEM_CANARY_DATA_SIZE; i ++) {
		canary[i] = (guint8) g_rand_int(rand_state);
	}
	return;
#else
	FILE *fp;
	size_t sz;
	/* Try /dev/urandom */
	if ((fp = eth_fopen("/dev/urandom", "r")) != NULL) {
		sz = fread(canary, EMEM_CANARY_DATA_SIZE, 1, fp);
		fclose(fp);
		if (sz == EMEM_CANARY_SIZE) {
			return;
		}
	}

	/* Our last resort */
	srandom(time(NULL) | getpid());
	for (i = 0; i < EMEM_CANARY_DATA_SIZE; i ++) {
		canary[i] = (guint8) random();
	}
	return;
#endif /* GLIB_MAJOR_VERSION >= 2 */
}

/*
 * Given an allocation size, return the amount of padding needed for
 * the canary value.
 */
static guint8
emem_canary_pad (size_t allocation) {
	guint8 pad;

	pad = EMEM_CANARY_SIZE - (allocation % EMEM_CANARY_SIZE);
	if (pad < EMEM_CANARY_SIZE)
		pad += EMEM_CANARY_SIZE;

	return pad;
}

/* Initialize the packet-lifetime memory allocation pool.
 * This function should be called only once when Ethereal or Tethereal starts
 * up.
 */
void
ep_init_chunk(void)
{
	ep_packet_mem.free_list=NULL;
	ep_packet_mem.used_list=NULL;

	emem_canary(ep_canary);
}
/* Initialize the capture-lifetime memory allocation pool.
 * This function should be called only once when Ethereal or Tethereal starts
 * up.
 */
void
se_init_chunk(void)
{
	se_packet_mem.free_list=NULL;
	se_packet_mem.used_list=NULL;

	emem_canary(se_canary);
}

#define EMEM_CREATE_CHUNK(FREE_LIST) \
	/* we dont have any free data, so we must allocate a new one */ \
	if(!FREE_LIST){ \
		emem_chunk_t *npc; \
		npc=g_malloc(sizeof(emem_chunk_t)); \
		npc->next=NULL; \
		npc->amount_free=EMEM_PACKET_CHUNK_SIZE; \
		npc->free_offset=0; \
		npc->buf=g_malloc(EMEM_PACKET_CHUNK_SIZE); \
		npc->c_count = 0; \
		FREE_LIST=npc; \
	}

/* allocate 'size' amount of memory with an allocation lifetime until the
 * next packet.
 */
void *
ep_alloc(size_t size)
{
	void *buf, *cptr;
	guint8 pad = emem_canary_pad(size);
	emem_chunk_t *free_list;

#ifndef EP_DEBUG_FREE
	/* Round up to an 8 byte boundary.  Make sure we have at least
	 * 8 pad bytes for our canary.
	 */
	size += pad;

	/* make sure we dont try to allocate too much (arbitrary limit) */
	DISSECTOR_ASSERT(size<(EMEM_PACKET_CHUNK_SIZE>>2));

	EMEM_CREATE_CHUNK(ep_packet_mem.free_list);

	/* oops, we need to allocate more memory to serve this request
         * than we have free. move this node to the used list and try again
	 */
	if(size>ep_packet_mem.free_list->amount_free || ep_packet_mem.free_list->c_count >= EMEM_ALLOCS_PER_CHUNK){
		emem_chunk_t *npc;
		npc=ep_packet_mem.free_list;
		ep_packet_mem.free_list=ep_packet_mem.free_list->next;
		npc->next=ep_packet_mem.used_list;
		ep_packet_mem.used_list=npc;
	}

	EMEM_CREATE_CHUNK(ep_packet_mem.free_list);

	free_list = ep_packet_mem.free_list;

	buf = free_list->buf + free_list->free_offset;

	free_list->amount_free -= size;
	free_list->free_offset += size;

	cptr = (char *)buf + size - pad;
	memcpy(cptr, &ep_canary, pad);
	free_list->canary[free_list->c_count] = cptr;
	free_list->cmp_len[free_list->c_count] = pad;
	free_list->c_count++;

#else /* EP_DEBUG_FREE */
	emem_chunk_t *npc;

	npc=g_malloc(sizeof(emem_chunk_t));
	npc->next=ep_packet_mem.used_list;
	npc->amount_free=size;
	npc->free_offset=0;
	npc->buf=g_malloc(size);
	buf = npc->buf;
	ep_packet_mem.used_list=npc;
#endif /* EP_DEBUG_FREE */

	return buf;
}
/* allocate 'size' amount of memory with an allocation lifetime until the
 * next capture.
 */
void *
se_alloc(size_t size)
{
	void *buf, *cptr;
	guint8 pad = emem_canary_pad(size);
	emem_chunk_t *free_list;

#ifndef SE_DEBUG_FREE
	/* Round up to an 8 byte boundary.  Make sure we have at least
	 * 8 pad bytes for our canary.
	 */
	size += pad;

	/* make sure we dont try to allocate too much (arbitrary limit) */
	DISSECTOR_ASSERT(size<(EMEM_PACKET_CHUNK_SIZE>>2));

	EMEM_CREATE_CHUNK(se_packet_mem.free_list);

	/* oops, we need to allocate more memory to serve this request
         * than we have free. move this node to the used list and try again
	 */
	if(size>se_packet_mem.free_list->amount_free || se_packet_mem.free_list->c_count >= EMEM_ALLOCS_PER_CHUNK){
		emem_chunk_t *npc;
		npc=se_packet_mem.free_list;
		se_packet_mem.free_list=se_packet_mem.free_list->next;
		npc->next=se_packet_mem.used_list;
		se_packet_mem.used_list=npc;
	}

	EMEM_CREATE_CHUNK(se_packet_mem.free_list);

	free_list = se_packet_mem.free_list;

	buf = free_list->buf + free_list->free_offset;

	free_list->amount_free -= size;
	free_list->free_offset += size;

	cptr = (char *)buf + size - pad;
	memcpy(cptr, &se_canary, pad);
	free_list->canary[free_list->c_count] = cptr;
	free_list->cmp_len[free_list->c_count] = pad;
	free_list->c_count++;

#else /* SE_DEBUG_FREE */
	emem_chunk_t *npc;

	npc=g_malloc(sizeof(emem_chunk_t));
	npc->next=se_packet_mem.used_list;
	npc->amount_free=size;
	npc->free_offset=0;
	npc->buf=g_malloc(size);
	buf = npc->buf;
	se_packet_mem.used_list=npc;
#endif /* SE_DEBUG_FREE */

	return buf;
}


void* ep_alloc0(size_t size) {
	return memset(ep_alloc(size),'\0',size);
}

gchar* ep_strdup(const gchar* src) {
	guint len = strlen(src);
	gchar* dst;

	dst = strncpy(ep_alloc(len+1), src, len);

	dst[len] = '\0';

	return dst;
}

gchar* ep_strndup(const gchar* src, size_t len) {
	gchar* dst = ep_alloc(len+1);
	guint i;

	for (i = 0; src[i] && i < len; i++)
		dst[i] = src[i];

	dst[i] = '\0';

	return dst;
}

void* ep_memdup(const void* src, size_t len) {
	return memcpy(ep_alloc(len), src, len);
}

gchar* ep_strdup_vprintf(const gchar* fmt, va_list ap) {
	va_list ap2;
	guint len;
	gchar* dst;

	G_VA_COPY(ap2, ap);

	len = g_printf_string_upper_bound(fmt, ap);

	dst = ep_alloc(len+1);
	g_vsnprintf (dst, len, fmt, ap2);
	va_end(ap2);

	return dst;
}

gchar* ep_strdup_printf(const gchar* fmt, ...) {
	va_list ap;
	gchar* dst;

	va_start(ap,fmt);
	dst = ep_strdup_vprintf(fmt, ap);
	va_end(ap);
	return dst;
}

gchar** ep_strsplit(const gchar* string, const gchar* sep, int max_tokens) {
	gchar* splitted;
	gchar* s;
	guint tokens;
	guint str_len;
	guint sep_len;
	guint i;
	gchar** vec;
	enum { AT_START, IN_PAD, IN_TOKEN } state;
	guint curr_tok = 0;

	if ( ! string
		 || ! sep
		 || ! sep[0])
		return NULL;

	s = splitted = ep_strdup(string);
	str_len = strlen(splitted);
	sep_len = strlen(sep);

	if (max_tokens < 1) max_tokens = INT_MAX;

	tokens = 1;


	while (tokens <= (guint)max_tokens && ( s = strstr(s,sep) )) {
		tokens++;

		for(i=0; i < sep_len; i++ )
			s[i] = '\0';

		s += sep_len;

	}

	vec = ep_alloc_array(gchar*,tokens+1);
	state = AT_START;

	for (i=0; i< str_len; i++) {
		switch(state) {
			case AT_START:
				switch(splitted[i]) {
					case '\0':
						state  = IN_PAD;
						continue;
					default:
						vec[curr_tok] = &(splitted[i]);
						curr_tok++;
						state = IN_TOKEN;
						continue;
				}
			case IN_TOKEN:
				switch(splitted[i]) {
					case '\0':
						state = IN_PAD;
					default:
						continue;
				}
			case IN_PAD:
				switch(splitted[i]) {
					default:
						vec[curr_tok] = &(splitted[i]);
						curr_tok++;
						state = IN_TOKEN;
					case '\0':
						continue;
				}
		}
	}

	vec[curr_tok] = NULL;

	return vec;
}



void* se_alloc0(size_t size) {
	return memset(se_alloc(size),'\0',size);
}

/* If str is NULL, just return the string "<NULL>" so that the callers dont
 * have to bother checking it.
 */
gchar* se_strdup(const gchar* src) {
	guint len;
	gchar* dst;

	if(!src){
		return "<NULL>";
	}

	len = strlen(src);
	dst = strncpy(se_alloc(len+1), src, len);

	dst[len] = '\0';

	return dst;
}

gchar* se_strndup(const gchar* src, size_t len) {
	gchar* dst = se_alloc(len+1);
	guint i;

	for (i = 0; src[i] && i < len; i++)
		dst[i] = src[i];

	dst[i] = '\0';

	return dst;
}

void* se_memdup(const void* src, size_t len) {
	return memcpy(se_alloc(len), src, len);
}

gchar* se_strdup_vprintf(const gchar* fmt, va_list ap) {
	va_list ap2;
	guint len;
	gchar* dst;

	G_VA_COPY(ap2, ap);

	len = g_printf_string_upper_bound(fmt, ap);

	dst = se_alloc(len+1);
	g_vsnprintf (dst, len, fmt, ap2);
	va_end(ap2);

	return dst;
}

gchar* se_strdup_printf(const gchar* fmt, ...) {
	va_list ap;
	gchar* dst;

	va_start(ap,fmt);
	dst = se_strdup_vprintf(fmt, ap);
	va_end(ap);
	return dst;
}

/* release all allocated memory back to the pool.
 */
void
ep_free_all(void)
{
	emem_chunk_t *npc;
	guint i;

	/* move all used chunks over to the free list */
	while(ep_packet_mem.used_list){
		npc=ep_packet_mem.used_list;
		ep_packet_mem.used_list=ep_packet_mem.used_list->next;
		npc->next=ep_packet_mem.free_list;
		ep_packet_mem.free_list=npc;
	}

	/* clear them all out */
	npc = ep_packet_mem.free_list;
	while (npc != NULL) {
#ifndef EP_DEBUG_FREE
		for (i = 0; i < npc->c_count; i++) {
			if (memcmp(npc->canary[i], &ep_canary, npc->cmp_len[i]) != 0)
				g_error("Per-packet memory corrupted.");
		}
		npc->c_count = 0;
		npc->amount_free=EMEM_PACKET_CHUNK_SIZE;
		npc->free_offset=0;
		npc = npc->next;
#else /* EP_DEBUG_FREE */
		emem_chunk_t *next = npc->next;

		g_free(npc->buf);
		g_free(npc);
		npc = next;
#endif /* EP_DEBUG_FREE */
	}

#ifdef EP_DEBUG_FREE
	ep_init_chunk();
#endif
}
/* release all allocated memory back to the pool.
 */
void
se_free_all(void)
{
	emem_chunk_t *npc;
	guint i;

	/* move all used chunks over to the free list */
	while(se_packet_mem.used_list){
		npc=se_packet_mem.used_list;
		se_packet_mem.used_list=se_packet_mem.used_list->next;
		npc->next=se_packet_mem.free_list;
		se_packet_mem.free_list=npc;
	}

	/* clear them all out */
	npc = se_packet_mem.free_list;
	while (npc != NULL) {
#ifndef SE_DEBUG_FREE
		for (i = 0; i < npc->c_count; i++) {
			if (memcmp(npc->canary[i], &se_canary, npc->cmp_len[i]) != 0)
				g_error("Per-session memory corrupted.");
		}
		npc->c_count = 0;
		npc->amount_free=EMEM_PACKET_CHUNK_SIZE;
		npc->free_offset=0;
		npc = npc->next;
#else /* SE_DEBUG_FREE */
		emem_chunk_t *next = npc->next;

		g_free(npc->buf);
		g_free(npc);
		npc = next;
#endif /* SE_DEBUG_FREE */
	}

#ifdef SE_DEBUG_FREE
		se_init_chunk();
#endif
}


ep_stack_t ep_stack_new(void) {
    ep_stack_t s = ep_new(struct _ep_stack_frame_t*);
    *s = ep_new0(struct _ep_stack_frame_t);
    return s;
}

/*  for ep_stack_t we'll keep the popped frames so we reuse them instead
of allocating new ones.
*/


void* ep_stack_push(ep_stack_t stack, void* data) {
    struct _ep_stack_frame_t* frame;
    struct _ep_stack_frame_t* head = (*stack);

    if (head->above) {
        frame = head->above;
    } else {
       frame = ep_new(struct _ep_stack_frame_t);
       head->above = frame;
       frame->below = head;
       frame->above = NULL;
    }

    frame->payload = data;
    (*stack) = frame;

    return data;
}

void* ep_stack_pop(ep_stack_t stack) {

    if ((*stack)->below) {
        (*stack) = (*stack)->below;
        return (*stack)->above->payload;
    } else {
        return NULL;
    }
}

