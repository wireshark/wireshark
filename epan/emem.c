/* emem.c
 * Wireshark memory management and garbage collection functions
 * Ronnie Sahlberg 2005
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <glib.h>

#include "proto.h"
#include "emem.h"

#ifdef _WIN32
#include <windows.h>	/* VirtualAlloc, VirtualProtect */
#include <process.h>    /* getpid */
#endif

/*
 * Tools like Valgrind and ElectricFence don't work well with memchunks.
 * Export the following environment variables to make {ep|se}_alloc() allocate each
 * object individually.
 *
 * WIRESHARK_DEBUG_EP_NO_CHUNKS
 * WIRESHARK_DEBUG_SE_NO_CHUNKS
 */
static gboolean ep_debug_use_chunks;
static gboolean se_debug_use_chunks;

/* Do we want to use canaries?
 * Export the following environment variables to disable/enable canaries
 *
 * WIRESHARK_DEBUG_EP_NO_CANARY
 * For SE memory use of canary is default off as the memory overhead
 * is considerable.
 * WIRESHARK_DEBUG_SE_USE_CANARY
 */
static gboolean ep_debug_use_canary;
static gboolean se_debug_use_canary;

/* Print out statistics about our memory allocations? */
/*#define SHOW_EMEM_STATS*/

/* Do we want to use guardpages? if available */
#define WANT_GUARD_PAGES 1

#ifdef WANT_GUARD_PAGES
/* Add guard pages at each end of our allocated memory */
#if defined(HAVE_SYSCONF) && defined(HAVE_MMAP) && defined(HAVE_MPROTECT) && defined(HAVE_STDINT_H)
#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>
#if defined(MAP_ANONYMOUS)
#define ANON_PAGE_MODE	(MAP_ANONYMOUS|MAP_PRIVATE)
#elif defined(MAP_ANON)
#define ANON_PAGE_MODE	(MAP_ANON|MAP_PRIVATE)
#else
#define ANON_PAGE_MODE	(MAP_PRIVATE)	/* have to map /dev/zero */
#define NEED_DEV_ZERO
#endif
#ifdef NEED_DEV_ZERO
#include <fcntl.h>
static int dev_zero_fd;
#define ANON_FD	dev_zero_fd
#else
#define ANON_FD	-1
#endif
#define USE_GUARD_PAGES 1
#endif
#endif

/* When required, allocate more memory from the OS in this size chunks */
#define EMEM_PACKET_CHUNK_SIZE 10485760

/* The maximum number of allocations per chunk */
#define EMEM_ALLOCS_PER_CHUNK (EMEM_PACKET_CHUNK_SIZE / 64)

#define EMEM_CANARY_SIZE 8
#define EMEM_CANARY_DATA_SIZE (EMEM_CANARY_SIZE * 2 - 1)

/* this should be static, but if it were gdb would had problems finding it */
guint8 ep_canary[EMEM_CANARY_DATA_SIZE];
guint8 se_canary[EMEM_CANARY_DATA_SIZE];

typedef struct _emem_no_chunk_t {
	unsigned int	c_count;
	void		*canary[EMEM_ALLOCS_PER_CHUNK];
	guint8		cmp_len[EMEM_ALLOCS_PER_CHUNK];
} emem_canary_t;

typedef struct _emem_chunk_t {
	struct _emem_chunk_t *next;
	char			*buf;
	unsigned int	amount_free_init;
	unsigned int	amount_free;
	unsigned int	free_offset_init;
	unsigned int	free_offset;
	emem_canary_t	*canary_info;
} emem_chunk_t;

typedef struct _emem_header_t {
	emem_chunk_t *free_list;
	emem_chunk_t *used_list;
} emem_header_t;

static emem_header_t ep_packet_mem;
static emem_header_t se_packet_mem;

#if defined (_WIN32)
static SYSTEM_INFO sysinfo;
static OSVERSIONINFO versinfo;
static int pagesize;
#elif defined(USE_GUARD_PAGES)
static intptr_t pagesize;
#endif /* _WIN32 / USE_GUARD_PAGES */

/*
 * Set a canary value to be placed between memchunks.
 */
static void
emem_canary(guint8 *canary) {
	int i;
	static GRand   *rand_state = NULL;

	if (rand_state == NULL) {
		rand_state = g_rand_new();
	}
	for (i = 0; i < EMEM_CANARY_DATA_SIZE; i ++) {
		canary[i] = (guint8) g_rand_int(rand_state);
	}
	return;
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

/* used for debugging canaries, will block */
#ifdef DEBUG_INTENSE_CANARY_CHECKS
gboolean intense_canary_checking = FALSE;

/*  used to intensivelly check ep canaries
 */
void ep_check_canary_integrity(const char* fmt, ...) {
	va_list ap;
	static gchar there[128] = {
		'L','a','u','n','c','h',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	gchar here[128];
	emem_chunk_t* npc = NULL;

	if (! intense_canary_checking ) return;

	here[126] = '\0';
	here[127] = '\0';

	va_start(ap,fmt);
	g_vsnprintf(here, 126,fmt, ap);
	va_end(ap);

	for (npc = ep_packet_mem.free_list; npc != NULL; npc = npc->next) {
		static unsigned i_ctr;

		if (npc->canary_info->c_count > 0x00ffffff) {
			g_error("ep_packet_mem.free_list was corrupted\nbetween: %s\nand: %s",there, here);
		}

		for (i_ctr = 0; i_ctr < npc->canary_info->c_count; i_ctr++) {
			if (memcmp(npc->canary_info->canary[i_ctr], &ep_canary, npc->canary_info->cmp_len[i_ctr]) != 0) {
				g_error("Per-packet memory corrupted\nbetween: %s\nand: %s",there, here);
			}
		}
	}

	strncpy(there,here,126);

}
#endif


/* Initialize the packet-lifetime memory allocation pool.
 * This function should be called only once when Wireshark or TShark starts
 * up.
 */
void
ep_init_chunk(void)
{
	ep_packet_mem.free_list=NULL;
	ep_packet_mem.used_list=NULL;

	ep_debug_use_chunks = (gboolean) (!getenv("WIRESHARK_DEBUG_EP_NO_CHUNKS"));
	ep_debug_use_canary = (gboolean) (!getenv("WIRESHARK_DEBUG_EP_NO_CANARY"));

#ifdef DEBUG_INTENSE_CANARY_CHECKS
	intense_canary_checking = (gboolean)getenv("WIRESHARK_DEBUG_EP_INTENSE_CANARY");
#endif

	if (ep_debug_use_canary)
		emem_canary(ep_canary);

#if defined (_WIN32)
	/* Set up our guard page info for Win32 */
	GetSystemInfo(&sysinfo);
	pagesize = sysinfo.dwPageSize;

	/* calling GetVersionEx using the OSVERSIONINFO structure.
	 * OSVERSIONINFOEX requires Win NT4 with SP6 or newer NT Versions.
	 * OSVERSIONINFOEX will fail on Win9x and older NT Versions.
	 * See also:
	 * http://msdn.microsoft.com/library/en-us/sysinfo/base/getversionex.asp
	 * http://msdn.microsoft.com/library/en-us/sysinfo/base/osversioninfo_str.asp
	 * http://msdn.microsoft.com/library/en-us/sysinfo/base/osversioninfoex_str.asp
	 */
	versinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&versinfo);

#elif defined(USE_GUARD_PAGES)
	pagesize = sysconf(_SC_PAGESIZE);
#ifdef NEED_DEV_ZERO
	dev_zero_fd = ws_open("/dev/zero", O_RDWR);
	g_assert(dev_zero_fd != -1);
#endif
#endif /* _WIN32 / USE_GUARD_PAGES */
}

/* Initialize the capture-lifetime memory allocation pool.
 * This function should be called only once when Wireshark or TShark starts
 * up.
 */
void
se_init_chunk(void)
{
	se_packet_mem.free_list = NULL;
	se_packet_mem.used_list = NULL;

	se_debug_use_chunks = (gboolean) (!getenv("WIRESHARK_DEBUG_SE_NO_CHUNKS"));

	if (getenv("WIRESHARK_DEBUG_SE_USE_CANARY")) {
		se_debug_use_canary = TRUE;
		emem_canary(se_canary);
	} else
		se_debug_use_canary = FALSE;
}

#ifdef SHOW_EMEM_STATS
static guint allocations[10] = { 0 };
static guint total_no_chunks = 0;

static void
print_alloc_stats()
{
	guint num_chunks = 0;
	guint num_allocs = 0;
	guint total_used = 0;
	guint total_allocation = 0;
	guint total_free = 0;
	guint used_for_canaries = 0;
	guint i_ctr, i;
	emem_chunk_t *chunk;
	guint total_space_allocated_from_os, total_space_wasted;
	gboolean ep_stat=TRUE;

	printf("\n-------- EP allocator statistics --------\n");
	printf("%s chunks, %s canaries\n",
	       ep_debug_use_chunks ? "Using" : "Not using",
	       ep_debug_use_canary ? "using" : "not using");

	if (! (ep_packet_mem.free_list || !ep_packet_mem.used_list)) {
		printf("No memory allocated\n");
		ep_stat = FALSE;
	}
	if ((ep_debug_use_chunks)&&(ep_stat)){
		/* Nothing interesting without chunks */
		/*  Only look at the used_list since those chunks are fully used.
		 *  Looking at the free list would skew our view.
		 */
		for (chunk = ep_packet_mem.used_list; chunk; chunk = chunk->next) {
			num_chunks++;
			total_used += (chunk->amount_free_init - chunk->amount_free);
			total_allocation += chunk->amount_free_init;
			total_free += chunk->amount_free;
		}
		if (num_chunks > 0) {
			printf ("\n");
			printf ("\n---- Buffer space ----\n");
			printf ("\tChunk allocation size: %10u\n", EMEM_PACKET_CHUNK_SIZE);
			printf ("\t*    Number of chunks: %10u\n", num_chunks);
			printf ("\t-------------------------------------------\n");
			printf ("\t= %u (%u including guard pages) total space used for buffers\n",
			total_allocation, EMEM_PACKET_CHUNK_SIZE * num_chunks);
			printf ("\t-------------------------------------------\n");
			total_space_allocated_from_os = total_allocation
				+ (sizeof(emem_chunk_t) + sizeof(emem_canary_t)) * num_chunks;
			printf ("Total allocated from OS: %u\n\n",
				total_space_allocated_from_os);
		}else{
			printf ("No fully used chunks, nothing to do\n");
		}
		/* Reset stats */
		num_chunks = 0;
		num_allocs = 0;
		total_used = 0;
		total_allocation = 0;
		total_free = 0;
		used_for_canaries = 0;
	}


	printf("\n-------- SE allocator statistics --------\n");
	printf("Total number of chunk allocations %u\n",
		total_no_chunks);
	printf("%s chunks, %s canaries\n",
	       se_debug_use_chunks ? "Using" : "Not using",
	       se_debug_use_canary ? "using" : "not using");

	if (! (se_packet_mem.free_list || !se_packet_mem.used_list)) {
		printf("No memory allocated\n");
		return;
	}

	if (!se_debug_use_chunks )
		return; /* Nothing interesting without chunks & canaries?? */

	/*  Only look at the used_list since those chunks are fully used.
	 *  Looking at the free list would skew our view.
	 */
	for (chunk = se_packet_mem.used_list; chunk; chunk = chunk->next) {
		num_chunks++;
		total_used += (chunk->amount_free_init - chunk->amount_free);
		total_allocation += chunk->amount_free_init;
		total_free += chunk->amount_free;

		if (se_debug_use_canary){
			num_allocs += chunk->canary_info->c_count;
			for (i_ctr = 0; i_ctr < chunk->canary_info->c_count; i_ctr++) {
				used_for_canaries += chunk->canary_info->cmp_len[i_ctr];
			}
		}
	}

	if (num_chunks == 0) {

		printf ("No fully used chunks, nothing to do\n");
		return;
	}
	if (!se_debug_use_canary){
		printf ("\n");
		printf ("\n---- Buffer space ----\n");
		printf ("\tChunk allocation size: %10u\n", EMEM_PACKET_CHUNK_SIZE);
		printf ("\t*    Number of chunks: %10u\n", num_chunks);
		printf ("\t-------------------------------------------\n");
		printf ("\t= %u (%u including guard pages) total space used for buffers\n",
		total_allocation, EMEM_PACKET_CHUNK_SIZE * num_chunks);
		printf ("\t-------------------------------------------\n");
		total_space_allocated_from_os = total_allocation
			+ (sizeof(emem_chunk_t) + sizeof(emem_canary_t)) * num_chunks;
		printf ("Total allocated from OS: %u\n\n",
			total_space_allocated_from_os);
		printf ("---------- Allocations from the SE pool ----------\n");
		printf ("   Number of SE allocations: %10u\n", num_allocs);
		printf ("Bytes used (incl. canaries): %10u\n", total_used);
		printf ("    Bytes used for canaries: %10u\n", used_for_canaries);
		printf ("      Bytes unused (wasted): %10u\n\n",
			total_allocation - total_used);
		printf ("---------- Statistics ----------\n");
		printf ("\nAllocation distribution (sizes include canaries):\n");
		for (i = 0; i < 9; i++)
			printf ("size < %5d: %8u\n", 32<<i, allocations[i]);
		printf ("size > %5d: %8u\n", 32<<i, allocations[i]);
		return;
	}

	printf ("\n");
	printf ("---------- Allocations from the OS ----------\n");
	printf ("---- Headers ----\n");
	printf ("\t(    Chunk header size: %10lu\n", sizeof(emem_chunk_t));
	printf ("\t  + Canary header size: %10lu)\n", sizeof(emem_canary_t));
	printf ("\t*     Number of chunks: %10u\n", num_chunks);
	printf ("\t-------------------------------------------\n");
	printf ("\t= %lu total space used for headers\n",
		(sizeof(emem_chunk_t) + sizeof(emem_canary_t)) * num_chunks);
	printf ("\n---- Buffer space ----\n");
	printf ("\tChunk allocation size: %10u\n", EMEM_PACKET_CHUNK_SIZE);
	printf ("\t*    Number of chunks: %10u\n", num_chunks);
	printf ("\t-------------------------------------------\n");
	printf ("\t= %u (%u including guard pages) total space used for buffers\n",
		total_allocation, EMEM_PACKET_CHUNK_SIZE * num_chunks);
	printf ("\t-------------------------------------------\n");
	total_space_allocated_from_os = total_allocation
		+ (sizeof(emem_chunk_t) + sizeof(emem_canary_t)) * num_chunks;
	printf ("Total allocated from OS: %u\n\n",
		total_space_allocated_from_os);

	printf ("---------- Allocations from the SE pool ----------\n");
	printf ("   Number of SE allocations: %10u\n", num_allocs);
	printf ("Bytes used (incl. canaries): %10u\n", total_used);
	printf ("    Bytes used for canaries: %10u\n", used_for_canaries);
	printf ("      Bytes unused (wasted): %10u\n\n",
		total_allocation - total_used);

	printf ("---------- Statistics ----------\n");
	printf ("Average SE allocation size (incl. canaries): %6.2f\n",
		(float)total_used/(float)num_allocs);
	printf ("Average SE allocation size (excl. canaries): %6.2f\n",
		(float)(total_used - used_for_canaries)/(float)num_allocs);
	printf ("        Average wasted bytes per allocation: %6.2f\n",
		(total_allocation - total_used)/(float)num_allocs);
	total_space_wasted = (total_allocation - total_used)
		+ (sizeof(emem_chunk_t) + sizeof(emem_canary_t));
	printf (" Space used for headers + unused allocation: %8u\n",
		total_space_wasted);
	printf ("--> %% overhead/waste: %4.2f\n",
		100 * (float)total_space_wasted/(float)total_space_allocated_from_os);

	printf ("\nAllocation distribution (sizes include canaries):\n");
	for (i = 0; i < 9; i++)
		printf ("size < %5d: %8u\n", 32<<i, allocations[i]);
	printf ("size > %5d: %8u\n", 32<<i, allocations[i]);
}
#endif

static gboolean
emem_verify_pointer(emem_header_t *hdr, const void *ptr)
{
	const gchar *cptr = ptr;
	emem_chunk_t *used_list[2];
	guint8 used_list_idx;
	emem_chunk_t *chunk;

	used_list[0] = hdr->free_list;
	used_list[1] = hdr->used_list;

	for (used_list_idx=0; used_list_idx < G_N_ELEMENTS(used_list); ++used_list_idx) {
		chunk = used_list[used_list_idx];
		for ( ; chunk ; chunk = chunk->next) {
			if (cptr >= (chunk->buf + chunk->free_offset_init) &&
				cptr < (chunk->buf + chunk->free_offset))
				return TRUE;
		}
	}

	return FALSE;
}

gboolean
ep_verify_pointer(const void *ptr)
{
	return emem_verify_pointer(&ep_packet_mem, ptr);
}

gboolean
se_verify_pointer(const void *ptr)
{
	return emem_verify_pointer(&se_packet_mem, ptr);
}

static void
emem_create_chunk(emem_chunk_t **free_list, gboolean use_canary) {
#if defined (_WIN32)
	BOOL ret;
	char *buf_end, *prot1, *prot2;
	DWORD oldprot;
#elif defined(USE_GUARD_PAGES)
	int ret;
	char *buf_end, *prot1, *prot2;
#endif /* _WIN32 / USE_GUARD_PAGES */
	emem_chunk_t *npc;

	/* we dont have any free data, so we must allocate a new one */
    DISSECTOR_ASSERT(!*free_list);

	npc = g_new(emem_chunk_t, 1);
	npc->next = NULL;
	if (use_canary) {
		npc->canary_info = g_new(emem_canary_t, 1);
		npc->canary_info->c_count = 0;
	}
	else
		npc->canary_info = NULL;

	*free_list = npc;
#if defined (_WIN32)
	/*
	 * MSDN documents VirtualAlloc/VirtualProtect at
	 * http://msdn.microsoft.com/library/en-us/memory/base/creating_guard_pages.asp
	 */

	/* XXX - is MEM_COMMIT|MEM_RESERVE correct? */
	npc->buf = VirtualAlloc(NULL, EMEM_PACKET_CHUNK_SIZE,
		MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if(npc->buf == NULL) {
		THROW(OutOfMemoryError);
	}
#ifdef SHOW_EMEM_STATS
	total_no_chunks++;
#endif
	buf_end = npc->buf + EMEM_PACKET_CHUNK_SIZE;

	/* Align our guard pages on page-sized boundaries */
	prot1 = (char *) ((((int) npc->buf + pagesize - 1) / pagesize) * pagesize);
	prot2 = (char *) ((((int) buf_end - (1 * pagesize)) / pagesize) * pagesize);

	ret = VirtualProtect(prot1, pagesize, PAGE_NOACCESS, &oldprot);
	g_assert(ret != 0 || versinfo.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS);
	ret = VirtualProtect(prot2, pagesize, PAGE_NOACCESS, &oldprot);
	g_assert(ret != 0 || versinfo.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS);

	npc->amount_free_init = (unsigned int) (prot2 - prot1 - pagesize);
	npc->amount_free = npc->amount_free_init;
	npc->free_offset_init = (unsigned int) (prot1 - npc->buf) + pagesize;
	npc->free_offset = npc->free_offset_init;

#elif defined(USE_GUARD_PAGES)
	npc->buf = mmap(NULL, EMEM_PACKET_CHUNK_SIZE,
		PROT_READ|PROT_WRITE, ANON_PAGE_MODE, ANON_FD, 0);
	if(npc->buf == MAP_FAILED) {
		/* XXX - what do we have to cleanup here? */
		THROW(OutOfMemoryError);
	}
	buf_end = npc->buf + EMEM_PACKET_CHUNK_SIZE;
#ifdef SHOW_EMEM_STATS
	total_no_chunks++;
#endif
	/* Align our guard pages on page-sized boundaries */
	prot1 = (char *) ((((intptr_t) npc->buf + pagesize - 1) / pagesize) * pagesize);
	prot2 = (char *) ((((intptr_t) buf_end - (1 * pagesize)) / pagesize) * pagesize);
	ret = mprotect(prot1, pagesize, PROT_NONE);
	g_assert(ret != -1);
	ret = mprotect(prot2, pagesize, PROT_NONE);
	g_assert(ret != -1);

	npc->amount_free_init = prot2 - prot1 - pagesize;
	npc->amount_free = npc->amount_free_init;
	npc->free_offset_init = (prot1 - npc->buf) + pagesize;
	npc->free_offset = npc->free_offset_init;

#else /* Is there a draft in here? */
	npc->buf = g_malloc(EMEM_PACKET_CHUNK_SIZE);
	if(npc->buf == NULL) {
		THROW(OutOfMemoryError);
	}
#ifdef SHOW_EMEM_STATS
	total_no_chunks++;
#endif
	npc->amount_free_init = EMEM_PACKET_CHUNK_SIZE;
	npc->amount_free = npc->amount_free_init;
	npc->free_offset_init = 0;
	npc->free_offset = npc->free_offset_init;
#endif /* USE_GUARD_PAGES */
}

/* allocate 'size' amount of memory. */
static void *
emem_alloc(size_t size, emem_header_t *mem, gboolean use_chunks, guint8 *canary)
{
	void *buf;
	void *cptr;
	guint8 pad;
	emem_chunk_t *free_list;

	if (use_chunks) {
		gboolean use_canary = canary != NULL;
		/* Round up to an 8 byte boundary. Make sure we have at least
		 * 8 pad bytes for our canary.
		 */
		 if (use_canary)
			pad = emem_canary_pad(size);
		 else
			pad = ((8 - (size & 0x7)) & 0x7);

		size += pad;

#ifdef SHOW_EMEM_STATS
		/* Do this check here so we can include the canary size */
		if (mem == &se_packet_mem) {
			if (size < 32)
				allocations[0]++;
			else if (size < 64)
				allocations[1]++;
			else if (size < 128)
				allocations[2]++;
			else if (size < 256)
				allocations[3]++;
			else if (size < 512)
				allocations[4]++;
			else if (size < 1024)
				allocations[5]++;
			else if (size < 2048)
				allocations[6]++;
			else if (size < 4096)
				allocations[7]++;
			else if (size < 8192)
				allocations[8]++;
			else if (size < 16384)
				allocations[8]++;
			else
				allocations[9]++;
		}
#endif

		/* make sure we dont try to allocate too much (arbitrary limit) */
		DISSECTOR_ASSERT(size<(EMEM_PACKET_CHUNK_SIZE>>2));

		if (!mem->free_list)
			emem_create_chunk(&mem->free_list, use_canary);

		/* oops, we need to allocate more memory to serve this request
		 * than we have free. move this node to the used list and try again
		 */
		if(size > mem->free_list->amount_free ||
		   (use_canary &&
			mem->free_list->canary_info->c_count >= EMEM_ALLOCS_PER_CHUNK)) {
			emem_chunk_t *npc;
			npc=mem->free_list;
			mem->free_list=mem->free_list->next;
			npc->next=mem->used_list;
			mem->used_list=npc;
		}

		if (!mem->free_list)
			emem_create_chunk(&mem->free_list, use_canary);

		free_list = mem->free_list;

		buf = free_list->buf + free_list->free_offset;

		free_list->amount_free -= (unsigned int) size;
		free_list->free_offset += (unsigned int) size;

		if (use_canary) {
			cptr = (char *)buf + size - pad;
			memcpy(cptr, canary, pad);
			free_list->canary_info->canary[free_list->canary_info->c_count] = cptr;
			free_list->canary_info->cmp_len[free_list->canary_info->c_count] = pad;
			free_list->canary_info->c_count++;
		}
	} else {
		emem_chunk_t *npc;

		npc=g_new(emem_chunk_t, 1);
		npc->next=mem->used_list;
		npc->buf=g_malloc(size);
		npc->canary_info = NULL;
		buf = npc->buf;
		mem->used_list=npc;
		/* There's no padding/alignment involved (from our point of view) when
		 * we fetch the memory directly from the system pool, so WYSIWYG */
		npc->free_offset = npc->free_offset_init = 0;
		npc->amount_free = npc->amount_free_init = (unsigned int) size;
	}

	return buf;
}

/* allocate 'size' amount of memory with an allocation lifetime until the
 * next packet.
 */
void *
ep_alloc(size_t size)
{
	if (ep_debug_use_chunks)
		if (ep_debug_use_canary)
			return emem_alloc(size, &ep_packet_mem, TRUE, ep_canary);
		else
			return emem_alloc(size, &ep_packet_mem, TRUE, NULL);
	else
		return emem_alloc(size, &ep_packet_mem, FALSE, NULL);
}

/* allocate 'size' amount of memory with an allocation lifetime until the
 * next capture.
 */
void *
se_alloc(size_t size)
{
	if (se_debug_use_chunks)
		if (se_debug_use_canary)
			return emem_alloc(size, &se_packet_mem, TRUE, se_canary);
		else
			return emem_alloc(size, &se_packet_mem, TRUE, NULL);
	else
		return emem_alloc(size, &se_packet_mem, FALSE, NULL);
}

void* ep_alloc0(size_t size) {
	return memset(ep_alloc(size),'\0',size);
}

gchar* ep_strdup(const gchar* src) {
	guint len = (guint) strlen(src);
	gchar* dst;

	dst = strncpy(ep_alloc(len+1), src, len);

	dst[len] = '\0';

	return dst;
}

gchar* ep_strndup(const gchar* src, size_t len) {
	gchar* dst = ep_alloc(len+1);
	guint i;

	for (i = 0; (i < len) && src[i]; i++)
		dst[i] = src[i];

	dst[i] = '\0';

	return dst;
}

void* ep_memdup(const void* src, size_t len) {
	return memcpy(ep_alloc(len), src, len);
}

gchar* ep_strdup_vprintf(const gchar* fmt, va_list ap) {
	va_list ap2;
	gsize len;
	gchar* dst;

	G_VA_COPY(ap2, ap);

	len = g_printf_string_upper_bound(fmt, ap);

	dst = ep_alloc(len+1);
	g_vsnprintf (dst, (gulong) len, fmt, ap2);
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

	if (    ! string
	     || ! sep
	     || ! sep[0])
		return NULL;

	s = splitted = ep_strdup(string);
	str_len = (guint) strlen(splitted);
	sep_len = (guint) strlen(sep);

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

	len = (guint) strlen(src);
	dst = strncpy(se_alloc(len+1), src, len);

	dst[len] = '\0';

	return dst;
}

gchar* se_strndup(const gchar* src, size_t len) {
	gchar* dst = se_alloc(len+1);
	guint i;

	for (i = 0; (i < len) && src[i]; i++)
		dst[i] = src[i];

	dst[i] = '\0';

	return dst;
}

void* se_memdup(const void* src, size_t len) {
	return memcpy(se_alloc(len), src, len);
}

gchar* se_strdup_vprintf(const gchar* fmt, va_list ap) {
	va_list ap2;
	gsize len;
	gchar* dst;

	G_VA_COPY(ap2, ap);

	len = g_printf_string_upper_bound(fmt, ap);

	dst = se_alloc(len+1);
	g_vsnprintf (dst, (gulong) len, fmt, ap2);
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

/* release all allocated memory back to the pool. */
static void
emem_free_all(emem_header_t *mem, gboolean use_chunks, guint8 *canary, emem_tree_t *trees)
{
	emem_chunk_t *npc;
	emem_tree_t *tree_list;
	guint i;

	/* move all used chunks over to the free list */
	while(mem->used_list){
		npc=mem->used_list;
		mem->used_list=mem->used_list->next;
		npc->next=mem->free_list;
		mem->free_list=npc;
	}

	/* clear them all out */
	npc = mem->free_list;
	while (npc != NULL) {
		if (use_chunks) {
			if (canary) {
				for (i = 0; i < npc->canary_info->c_count; i++) {
					if (memcmp(npc->canary_info->canary[i], canary, npc->canary_info->cmp_len[i]) != 0)
						g_error("Memory corrupted");
				}
				npc->canary_info->c_count = 0;
			}
			npc->amount_free = npc->amount_free_init;
			npc->free_offset = npc->free_offset_init;
			npc = npc->next;
		} else {
			emem_chunk_t *next = npc->next;

			g_free(npc->buf);
			g_free(npc);
			npc = next;
		}
	}

	/* release/reset all allocated trees */
	for(tree_list=trees;tree_list;tree_list=tree_list->next){
		tree_list->tree=NULL;
	}
}

/* release all allocated memory back to the pool. */
void
ep_free_all(void)
{
	if (ep_debug_use_chunks)
		if (ep_debug_use_canary)
			emem_free_all(&ep_packet_mem, TRUE, ep_canary, NULL /* trees */);
		else
			emem_free_all(&ep_packet_mem, TRUE, NULL, NULL /* trees */);
	else
		emem_free_all(&ep_packet_mem, FALSE, NULL, NULL /* trees */);

	if (!ep_debug_use_chunks)
		ep_init_chunk();
}

/* routines to manage se allocated red-black trees */
static emem_tree_t *se_trees=NULL;

/* release all allocated memory back to the pool. */
void
se_free_all(void)
{

#ifdef SHOW_EMEM_STATS
	print_alloc_stats();
#endif

	if (se_debug_use_chunks)
		if (se_debug_use_canary)
			emem_free_all(&se_packet_mem, TRUE, se_canary, se_trees);
		else
			emem_free_all(&se_packet_mem, TRUE, NULL, se_trees);
	else
		emem_free_all(&se_packet_mem, FALSE, NULL, se_trees);

	if (!se_debug_use_chunks)
		se_init_chunk();
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

emem_tree_t *
se_tree_create(int type, const char *name)
{
	emem_tree_t *tree_list;

	tree_list=g_malloc(sizeof(emem_tree_t));
	tree_list->next=se_trees;
	tree_list->type=type;
	tree_list->tree=NULL;
	tree_list->name=name;
	tree_list->malloc=se_alloc;
	se_trees=tree_list;

	return tree_list;
}

void *
emem_tree_lookup32(emem_tree_t *se_tree, guint32 key)
{
	emem_tree_node_t *node;

	node=se_tree->tree;

	while(node){
		if(key==node->key32){
			return node->data;
		}
		if(key<node->key32){
			node=node->left;
			continue;
		}
		if(key>node->key32){
			node=node->right;
			continue;
		}
	}
	return NULL;
}

void *
emem_tree_lookup32_le(emem_tree_t *se_tree, guint32 key)
{
	emem_tree_node_t *node;

	node=se_tree->tree;

	if(!node){
		return NULL;
	}


	while(node){
		if(key==node->key32){
			return node->data;
		}
		if(key<node->key32){
			if(node->left){
				node=node->left;
				continue;
			} else {
				break;
			}
		}
		if(key>node->key32){
			if(node->right){
				node=node->right;
				continue;
			} else {
				break;
			}
		}
	}


	if(!node){
		return NULL;
	}

	/* If we are still at the root of the tree this means that this node
	 * is either smaller than the search key and then we return this
	 * node or else there is no smaller key available and then
	 * we return NULL.
	 */
	if(!node->parent){
		if(key>node->key32){
			return node->data;
		} else {
			return NULL;
		}
	}

	if(node->parent->left==node){
		/* left child */

		if(key>node->key32){
			/* if this is a left child and its key is smaller than
			 * the search key, then this is the node we want.
			 */
			return node->data;
		} else {
			/* if this is a left child and its key is bigger than
			 * the search key, we have to check if any
			 * of our ancestors are smaller than the search key.
			 */
			while(node){
				if(key>node->key32){
					return node->data;
				}
				node=node->parent;
			}
			return NULL;
		}
	} else {
		/* right child */

		if(node->key32<key){
			/* if this is the right child and its key is smaller
			 * than the search key then this is the one we want.
			 */
			return node->data;
		} else {
			/* if this is the right child and its key is larger
			 * than the search key then our parent is the one we
			 * want.
			 */
			return node->parent->data;
		}
	}

}


static inline emem_tree_node_t *
emem_tree_parent(emem_tree_node_t *node)
{
	return node->parent;
}

static inline emem_tree_node_t *
emem_tree_grandparent(emem_tree_node_t *node)
{
	emem_tree_node_t *parent;

	parent=emem_tree_parent(node);
	if(parent){
		return parent->parent;
	}
	return NULL;
}
static inline emem_tree_node_t *
emem_tree_uncle(emem_tree_node_t *node)
{
	emem_tree_node_t *parent, *grandparent;

	parent=emem_tree_parent(node);
	if(!parent){
		return NULL;
	}
	grandparent=emem_tree_parent(parent);
	if(!grandparent){
		return NULL;
	}
	if(parent==grandparent->left){
		return grandparent->right;
	}
	return grandparent->left;
}

static inline void rb_insert_case1(emem_tree_t *se_tree, emem_tree_node_t *node);
static inline void rb_insert_case2(emem_tree_t *se_tree, emem_tree_node_t *node);

static inline void
rotate_left(emem_tree_t *se_tree, emem_tree_node_t *node)
{
	if(node->parent){
		if(node->parent->left==node){
			node->parent->left=node->right;
		} else {
			node->parent->right=node->right;
		}
	} else {
		se_tree->tree=node->right;
	}
	node->right->parent=node->parent;
	node->parent=node->right;
	node->right=node->right->left;
	if(node->right){
		node->right->parent=node;
	}
	node->parent->left=node;
}

static inline void
rotate_right(emem_tree_t *se_tree, emem_tree_node_t *node)
{
	if(node->parent){
		if(node->parent->left==node){
			node->parent->left=node->left;
		} else {
			node->parent->right=node->left;
		}
	} else {
		se_tree->tree=node->left;
	}
	node->left->parent=node->parent;
	node->parent=node->left;
	node->left=node->left->right;
	if(node->left){
		node->left->parent=node;
	}
	node->parent->right=node;
}

static inline void
rb_insert_case5(emem_tree_t *se_tree, emem_tree_node_t *node)
{
	emem_tree_node_t *grandparent;
	emem_tree_node_t *parent;

	parent=emem_tree_parent(node);
	grandparent=emem_tree_parent(parent);
	parent->u.rb_color=EMEM_TREE_RB_COLOR_BLACK;
	grandparent->u.rb_color=EMEM_TREE_RB_COLOR_RED;
	if( (node==parent->left) && (parent==grandparent->left) ){
		rotate_right(se_tree, grandparent);
	} else {
		rotate_left(se_tree, grandparent);
	}
}

static inline void
rb_insert_case4(emem_tree_t *se_tree, emem_tree_node_t *node)
{
	emem_tree_node_t *grandparent;
	emem_tree_node_t *parent;

	parent=emem_tree_parent(node);
	grandparent=emem_tree_parent(parent);
	if(!grandparent){
		return;
	}
	if( (node==parent->right) && (parent==grandparent->left) ){
		rotate_left(se_tree, parent);
		node=node->left;
	} else if( (node==parent->left) && (parent==grandparent->right) ){
		rotate_right(se_tree, parent);
		node=node->right;
	}
	rb_insert_case5(se_tree, node);
}

static inline void
rb_insert_case3(emem_tree_t *se_tree, emem_tree_node_t *node)
{
	emem_tree_node_t *grandparent;
	emem_tree_node_t *parent;
	emem_tree_node_t *uncle;

	uncle=emem_tree_uncle(node);
	if(uncle && (uncle->u.rb_color==EMEM_TREE_RB_COLOR_RED)){
		parent=emem_tree_parent(node);
		parent->u.rb_color=EMEM_TREE_RB_COLOR_BLACK;
		uncle->u.rb_color=EMEM_TREE_RB_COLOR_BLACK;
		grandparent=emem_tree_grandparent(node);
		grandparent->u.rb_color=EMEM_TREE_RB_COLOR_RED;
		rb_insert_case1(se_tree, grandparent);
	} else {
		rb_insert_case4(se_tree, node);
	}
}

static inline void
rb_insert_case2(emem_tree_t *se_tree, emem_tree_node_t *node)
{
	emem_tree_node_t *parent;

	parent=emem_tree_parent(node);
	/* parent is always non-NULL here */
	if(parent->u.rb_color==EMEM_TREE_RB_COLOR_BLACK){
		return;
	}
	rb_insert_case3(se_tree, node);
}

static inline void
rb_insert_case1(emem_tree_t *se_tree, emem_tree_node_t *node)
{
	emem_tree_node_t *parent;

	parent=emem_tree_parent(node);
	if(!parent){
		node->u.rb_color=EMEM_TREE_RB_COLOR_BLACK;
		return;
	}
	rb_insert_case2(se_tree, node);
}

/* insert a new node in the tree. if this node matches an already existing node
 * then just replace the data for that node */
void
emem_tree_insert32(emem_tree_t *se_tree, guint32 key, void *data)
{
	emem_tree_node_t *node;

	node=se_tree->tree;

	/* is this the first node ?*/
	if(!node){
		node=se_tree->malloc(sizeof(emem_tree_node_t));
		switch(se_tree->type){
		case EMEM_TREE_TYPE_RED_BLACK:
			node->u.rb_color=EMEM_TREE_RB_COLOR_BLACK;
			break;
		}
		node->parent=NULL;
		node->left=NULL;
		node->right=NULL;
		node->key32=key;
		node->data=data;
		node->u.is_subtree = EMEM_TREE_NODE_IS_DATA;
		se_tree->tree=node;
		return;
	}

	/* it was not the new root so walk the tree until we find where to
	 * insert this new leaf.
	 */
	while(1){
		/* this node already exists, so just replace the data pointer*/
		if(key==node->key32){
			node->data=data;
			return;
		}
		if(key<node->key32) {
			if(!node->left){
				/* new node to the left */
				emem_tree_node_t *new_node;
				new_node=se_tree->malloc(sizeof(emem_tree_node_t));
				node->left=new_node;
				new_node->parent=node;
				new_node->left=NULL;
				new_node->right=NULL;
				new_node->key32=key;
				new_node->data=data;
				new_node->u.is_subtree=EMEM_TREE_NODE_IS_DATA;
				node=new_node;
				break;
			}
			node=node->left;
			continue;
		}
		if(key>node->key32) {
			if(!node->right){
				/* new node to the right */
				emem_tree_node_t *new_node;
				new_node=se_tree->malloc(sizeof(emem_tree_node_t));
				node->right=new_node;
				new_node->parent=node;
				new_node->left=NULL;
				new_node->right=NULL;
				new_node->key32=key;
				new_node->data=data;
				new_node->u.is_subtree=EMEM_TREE_NODE_IS_DATA;
				node=new_node;
				break;
			}
			node=node->right;
			continue;
		}
	}

	/* node will now point to the newly created node */
	switch(se_tree->type){
	case EMEM_TREE_TYPE_RED_BLACK:
		node->u.rb_color=EMEM_TREE_RB_COLOR_RED;
		rb_insert_case1(se_tree, node);
		break;
	}
}

static void* lookup_or_insert32(emem_tree_t *se_tree, guint32 key, void*(*func)(void*),void* ud, int is_subtree) {
	emem_tree_node_t *node;

	node=se_tree->tree;

	/* is this the first node ?*/
	if(!node){
		node=se_tree->malloc(sizeof(emem_tree_node_t));
		switch(se_tree->type){
			case EMEM_TREE_TYPE_RED_BLACK:
				node->u.rb_color=EMEM_TREE_RB_COLOR_BLACK;
				break;
		}
		node->parent=NULL;
		node->left=NULL;
		node->right=NULL;
		node->key32=key;
		node->data= func(ud);
		node->u.is_subtree = is_subtree;
		se_tree->tree=node;
		return node->data;
	}

	/* it was not the new root so walk the tree until we find where to
		* insert this new leaf.
		*/
	while(1){
		/* this node already exists, so just return the data pointer*/
		if(key==node->key32){
			return node->data;
		}
		if(key<node->key32) {
			if(!node->left){
				/* new node to the left */
				emem_tree_node_t *new_node;
				new_node=se_tree->malloc(sizeof(emem_tree_node_t));
				node->left=new_node;
				new_node->parent=node;
				new_node->left=NULL;
				new_node->right=NULL;
				new_node->key32=key;
				new_node->data= func(ud);
				new_node->u.is_subtree = is_subtree;
				node=new_node;
				break;
			}
			node=node->left;
			continue;
		}
		if(key>node->key32) {
			if(!node->right){
				/* new node to the right */
				emem_tree_node_t *new_node;
				new_node=se_tree->malloc(sizeof(emem_tree_node_t));
				node->right=new_node;
				new_node->parent=node;
				new_node->left=NULL;
				new_node->right=NULL;
				new_node->key32=key;
				new_node->data= func(ud);
				new_node->u.is_subtree = is_subtree;
				node=new_node;
				break;
			}
			node=node->right;
			continue;
		}
	}

	/* node will now point to the newly created node */
	switch(se_tree->type){
		case EMEM_TREE_TYPE_RED_BLACK:
			node->u.rb_color=EMEM_TREE_RB_COLOR_RED;
			rb_insert_case1(se_tree, node);
			break;
	}

	return node->data;
}

/* When the se data is released, this entire tree will dissapear as if it
 * never existed including all metadata associated with the tree.
 */
emem_tree_t *
se_tree_create_non_persistent(int type, const char *name)
{
	emem_tree_t *tree_list;

	tree_list=se_alloc(sizeof(emem_tree_t));
	tree_list->next=NULL;
	tree_list->type=type;
	tree_list->tree=NULL;
	tree_list->name=name;
	tree_list->malloc=se_alloc;

	return tree_list;
}

/* This tree is PErmanent and will never be released
 */
emem_tree_t *
pe_tree_create(int type, const char *name)
{
	emem_tree_t *tree_list;

	tree_list=g_new(emem_tree_t, 1);
	tree_list->next=NULL;
	tree_list->type=type;
	tree_list->tree=NULL;
	tree_list->name=name;
	tree_list->malloc=(void *(*)(size_t)) g_malloc;

	return tree_list;
}

/* create another (sub)tree using the same memory allocation scope
 * as the parent tree.
 */
static emem_tree_t *
emem_tree_create_subtree(emem_tree_t *parent_tree, const char *name)
{
	emem_tree_t *tree_list;

	tree_list=parent_tree->malloc(sizeof(emem_tree_t));
	tree_list->next=NULL;
	tree_list->type=parent_tree->type;
	tree_list->tree=NULL;
	tree_list->name=name;
	tree_list->malloc=parent_tree->malloc;

	return tree_list;
}

static void* create_sub_tree(void* d) {
	emem_tree_t *se_tree = d;
	return emem_tree_create_subtree(se_tree, "subtree");
}

/* insert a new node in the tree. if this node matches an already existing node
 * then just replace the data for that node */

void
emem_tree_insert32_array(emem_tree_t *se_tree, emem_tree_key_t *key, void *data)
{
	emem_tree_t *next_tree;

	if((key[0].length<1)||(key[0].length>100)){
		DISSECTOR_ASSERT_NOT_REACHED();
	}
	if((key[0].length==1)&&(key[1].length==0)){
		emem_tree_insert32(se_tree, *key[0].key, data);
		return;
	}

	next_tree=lookup_or_insert32(se_tree, *key[0].key, create_sub_tree, se_tree, EMEM_TREE_NODE_IS_SUBTREE);

	if(key[0].length==1){
		key++;
	} else {
		key[0].length--;
		key[0].key++;
	}
	emem_tree_insert32_array(next_tree, key, data);
}

void *
emem_tree_lookup32_array(emem_tree_t *se_tree, emem_tree_key_t *key)
{
	emem_tree_t *next_tree;

	if((key[0].length<1)||(key[0].length>100)){
		DISSECTOR_ASSERT_NOT_REACHED();
	}
	if((key[0].length==1)&&(key[1].length==0)){
		return emem_tree_lookup32(se_tree, *key[0].key);
	}
	next_tree=emem_tree_lookup32(se_tree, *key[0].key);
	if(!next_tree){
		return NULL;
	}
	if(key[0].length==1){
		key++;
	} else {
		key[0].length--;
		key[0].key++;
	}
	return emem_tree_lookup32_array(next_tree, key);
}


/* Strings are stored as an array of uint32 containing the string characters
   with 4 characters in each uint32.
   The first byte of the string is stored as the most significant byte.
   If the string is not a multiple of 4 characters in length the last
   uint32 containing the string bytes are padded with 0 bytes.
   After the uint32's containing the string, there is one final terminator
   uint32 with the value 0x00000001
*/
void
emem_tree_insert_string(emem_tree_t* se_tree, const gchar* k, void* v, guint32 flags)
{
	emem_tree_key_t key[2];
	guint32 *aligned=NULL;
	guint32 len = (guint32) strlen(k);
	guint32 div = (len+3)/4+1;
	guint32 i;
	guint32 tmp;

	aligned = g_malloc(div * sizeof (guint32));

	/* pack the bytes one one by one into guint32s */
	tmp = 0;
	for (i = 0;i < len;i++) {
		unsigned char ch;

		ch = (unsigned char)k[i];
		if (flags & EMEM_TREE_STRING_NOCASE) {
			if(isupper(ch)) {
				ch = tolower(ch);
			}
		}
		tmp <<= 8;
		tmp |= ch;
		if (i%4 == 3) {
			aligned[i/4] = tmp;
			tmp = 0;
		}
	}
	/* add required padding to the last uint32 */
	if (i%4 != 0) {
		while (i%4 != 0) {
			i++;
			tmp <<= 8;
		}
		aligned[i/4-1] = tmp;
	}

	/* add the terminator */
	aligned[div-1] = 0x00000001;

	key[0].length = div;
	key[0].key = aligned;
	key[1].length = 0;
	key[1].key = NULL;


	emem_tree_insert32_array(se_tree, key, v);
	g_free(aligned);
}

void *
emem_tree_lookup_string(emem_tree_t* se_tree, const gchar* k, guint32 flags)
{
	emem_tree_key_t key[2];
	guint32 *aligned=NULL;
	guint32 len = (guint) strlen(k);
	guint32 div = (len+3)/4+1;
	guint32 i;
	guint32 tmp;
	void *ret;

	aligned = g_malloc(div * sizeof (guint32));

	/* pack the bytes one one by one into guint32s */
	tmp = 0;
	for (i = 0;i < len;i++) {
		unsigned char ch;

		ch = (unsigned char)k[i];
		if (flags & EMEM_TREE_STRING_NOCASE) {
			if(isupper(ch)) {
				ch = tolower(ch);
			}
		}
		tmp <<= 8;
		tmp |= ch;
		if (i%4 == 3) {
			aligned[i/4] = tmp;
			tmp = 0;
		}
	}
	/* add required padding to the last uint32 */
	if (i%4 != 0) {
		while (i%4 != 0) {
			i++;
			tmp <<= 8;
		}
		aligned[i/4-1] = tmp;
	}

	/* add the terminator */
	aligned[div-1] = 0x00000001;

	key[0].length = div;
	key[0].key = aligned;
	key[1].length = 0;
	key[1].key = NULL;


	ret = emem_tree_lookup32_array(se_tree, key);
	g_free(aligned);
	return ret;
}

static gboolean
emem_tree_foreach_nodes(emem_tree_node_t* node, tree_foreach_func callback, void *user_data)
{
	gboolean stop_traverse = FALSE;

	if (!node)
		return FALSE;

	if(node->left) {
		stop_traverse = emem_tree_foreach_nodes(node->left, callback, user_data);
		if (stop_traverse) {
			return TRUE;
		}
	}

	if (node->u.is_subtree == EMEM_TREE_NODE_IS_SUBTREE) {
		stop_traverse = emem_tree_foreach(node->data, callback, user_data);
	} else {
		stop_traverse = callback(node->data, user_data);
	}

	if (stop_traverse) {
		return TRUE;
	}

	if(node->right) {
		stop_traverse = emem_tree_foreach_nodes(node->right, callback, user_data);
		if (stop_traverse) {
			return TRUE;
		}
	}

	return FALSE;
}

gboolean
emem_tree_foreach(emem_tree_t* emem_tree, tree_foreach_func callback, void *user_data)
{
	if (!emem_tree)
		return FALSE;

	if(!emem_tree->tree)
		return FALSE;

	return emem_tree_foreach_nodes(emem_tree->tree, callback, user_data);
}


static void
emem_tree_print_nodes(emem_tree_node_t* node, int level)
{
	int i;

	if (!node)
		return;

	for(i=0;i<level;i++){
		printf("    ");
	}

	printf("NODE:%p parent:%p left:0x%p right:%px key:%d data:%p\n",
		(void *)node,(void *)(node->parent),(void *)(node->left),(void *)(node->right),
		(node->key32),node->data);
	if(node->left)
		emem_tree_print_nodes(node->left, level+1);
	if(node->right)
		emem_tree_print_nodes(node->right, level+1);
}
void
emem_print_tree(emem_tree_t* emem_tree)
{
	if (!emem_tree)
		return;

	printf("EMEM tree type:%d name:%s tree:%p\n",emem_tree->type,emem_tree->name,(void *)(emem_tree->tree));
	if(emem_tree->tree)
		emem_tree_print_nodes(emem_tree->tree, 0);
}

/*
 * String buffers
 */

/*
 * Presumably we're using these routines for building strings for the tree.
 * Use ITEM_LABEL_LENGTH as the basis for our default lengths.
 */

#define DEFAULT_STRBUF_LEN (ITEM_LABEL_LENGTH / 10)
#define MAX_STRBUF_LEN 65536

static gsize
next_size(gsize cur_alloc_len, gsize wanted_alloc_len, gsize max_alloc_len) {
	if (max_alloc_len < 1 || max_alloc_len > MAX_STRBUF_LEN) {
		max_alloc_len = MAX_STRBUF_LEN;
	}

	if (cur_alloc_len < 1) {
		cur_alloc_len = DEFAULT_STRBUF_LEN;
	}

	while (cur_alloc_len < wanted_alloc_len) {
		cur_alloc_len *= 2;
	}

	return cur_alloc_len < max_alloc_len ? cur_alloc_len : max_alloc_len;
}

static void
ep_strbuf_grow(emem_strbuf_t *strbuf, gsize wanted_alloc_len) {
	gsize new_alloc_len;
	gchar *new_str;

	if (!strbuf || (wanted_alloc_len <= strbuf->alloc_len) || (strbuf->alloc_len >= strbuf->max_alloc_len)) {
		return;
	}

	new_alloc_len = next_size(strbuf->alloc_len, wanted_alloc_len, strbuf->max_alloc_len);
	new_str = ep_alloc(new_alloc_len);
	g_strlcpy(new_str, strbuf->str, new_alloc_len);

	strbuf->alloc_len = new_alloc_len;
	strbuf->str = new_str;
}

emem_strbuf_t *
ep_strbuf_sized_new(gsize alloc_len, gsize max_alloc_len) {
	emem_strbuf_t *strbuf;

	strbuf = ep_alloc(sizeof(emem_strbuf_t));

	if ((max_alloc_len == 0) || (max_alloc_len > MAX_STRBUF_LEN))
		max_alloc_len = MAX_STRBUF_LEN;
	if (alloc_len == 0)
		alloc_len = 1;
	else if (alloc_len > max_alloc_len)
		alloc_len = max_alloc_len;

	strbuf->str = ep_alloc(alloc_len);
	strbuf->str[0] = '\0';

	strbuf->len = 0;
	strbuf->alloc_len = alloc_len;
	strbuf->max_alloc_len = max_alloc_len;

	return strbuf;
}

emem_strbuf_t *
ep_strbuf_new(const gchar *init) {
	emem_strbuf_t *strbuf;

	strbuf = ep_strbuf_sized_new(next_size(0, init?strlen(init):0, 0), 0);
	if (init) {
		gsize full_len;
		full_len = g_strlcpy(strbuf->str, init, strbuf->alloc_len);
		strbuf->len = MIN(full_len, strbuf->alloc_len-1);
	}

	return strbuf;
}

emem_strbuf_t *
ep_strbuf_new_label(const gchar *init) {
	emem_strbuf_t *strbuf;
	gsize full_len;

	/* Be optimistic: Allocate default size strbuf string and only      */
        /*  request an increase if needed.                                  */
        /* XXX: Is it reasonable to assume that much of the usage of        */
        /*  ep_strbuf_new_label will have  init==NULL or                    */
        /*   strlen(init) < DEFAULT_STRBUF_LEN) ???                         */
	strbuf = ep_strbuf_sized_new(DEFAULT_STRBUF_LEN, ITEM_LABEL_LENGTH);

	if (!init)
		return strbuf;

	/* full_len does not count the trailing '\0'.                       */
	full_len = g_strlcpy(strbuf->str, init, strbuf->alloc_len);
	if (full_len < strbuf->alloc_len) {
		strbuf->len += full_len;
	} else {
		strbuf = ep_strbuf_sized_new(full_len+1, ITEM_LABEL_LENGTH);
		full_len = g_strlcpy(strbuf->str, init, strbuf->alloc_len);
		strbuf->len = MIN(full_len, strbuf->alloc_len-1);
	}

	return strbuf;
}

emem_strbuf_t *
ep_strbuf_append(emem_strbuf_t *strbuf, const gchar *str) {
	gsize add_len, full_len;

	if (!strbuf || !str || str[0] == '\0') {
		return strbuf;
	}

	/* Be optimistic; try the g_strlcpy first & see if enough room.                 */
	/* Note: full_len doesn't count the trailing '\0'; add_len does allow for same  */
	add_len = strbuf->alloc_len - strbuf->len;
	full_len = g_strlcpy(&strbuf->str[strbuf->len], str, add_len);
	if (full_len < add_len) {
		strbuf->len += full_len;
	} else {
		strbuf->str[strbuf->len] = '\0'; /* end string at original length again */
		ep_strbuf_grow(strbuf, strbuf->len + full_len + 1);
		add_len = strbuf->alloc_len - strbuf->len;
		full_len = g_strlcpy(&strbuf->str[strbuf->len], str, add_len);
		strbuf->len += MIN(add_len-1, full_len);
	}

	return strbuf;
}

void
ep_strbuf_append_vprintf(emem_strbuf_t *strbuf, const gchar *format, va_list ap) {
	va_list ap2;
	gsize add_len, full_len;

	G_VA_COPY(ap2, ap);

	/* Be optimistic; try the g_vsnprintf first & see if enough room.               */
	/* Note: full_len doesn't count the trailing '\0'; add_len does allow for same. */
	add_len = strbuf->alloc_len - strbuf->len;
	full_len = g_vsnprintf(&strbuf->str[strbuf->len], (gulong) add_len, format, ap);
	if (full_len < add_len) {
		strbuf->len += full_len;
	} else {
		strbuf->str[strbuf->len] = '\0'; /* end string at original length again */
		ep_strbuf_grow(strbuf, strbuf->len + full_len + 1);
		add_len = strbuf->alloc_len - strbuf->len;
		full_len = g_vsnprintf(&strbuf->str[strbuf->len], (gulong) add_len, format, ap2);
		strbuf->len += MIN(add_len-1, full_len);
	}

	va_end(ap2);
}

void
ep_strbuf_append_printf(emem_strbuf_t *strbuf, const gchar *format, ...) {
	va_list ap;

	va_start(ap, format);
	ep_strbuf_append_vprintf(strbuf, format, ap);
	va_end(ap);
}

void
ep_strbuf_printf(emem_strbuf_t *strbuf, const gchar *format, ...) {
	va_list ap;
	if (!strbuf) {
		return;
	}

	strbuf->len = 0;

	va_start(ap, format);
	ep_strbuf_append_vprintf(strbuf, format, ap);
	va_end(ap);
}

emem_strbuf_t *
ep_strbuf_append_c(emem_strbuf_t *strbuf, const gchar c) {
	if (!strbuf) {
		return strbuf;
	}

	/* +1 for the new character & +1 for the trailing '\0'. */
	if (strbuf->alloc_len < strbuf->len + 1 + 1) {
		ep_strbuf_grow(strbuf, strbuf->len + 1 + 1);
	}
	if (strbuf->alloc_len >= strbuf->len + 1 + 1) {
		strbuf->str[strbuf->len] = c;
		strbuf->len++;
		strbuf->str[strbuf->len] = '\0';
	}

	return strbuf;
}

emem_strbuf_t *
ep_strbuf_truncate(emem_strbuf_t *strbuf, gsize len) {
	if (!strbuf || len >= strbuf->len) {
		return strbuf;
	}

	strbuf->str[len] = '\0';
	strbuf->len = len;

	return strbuf;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * ex: set shiftwidth=8 tabstop=8 noexpandtab
 * :indentSize=8:tabSize=8:noTabs=false:
 */
