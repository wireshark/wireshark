/* emem.c
 * Wireshark memory management and garbage collection functions
 * Ronnie Sahlberg 2005
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
#include "config.h"

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

#include <glib.h>

#include "app_mem_usage.h"
#include "proto.h"
#include "exceptions.h"
#include "emem.h"
#include "wmem/wmem.h"

#ifdef _WIN32
#include <windows.h>	/* VirtualAlloc, VirtualProtect */
#include <process.h>    /* getpid */
#endif

/* Print out statistics about our memory allocations? */
/*#define SHOW_EMEM_STATS*/

/* Do we want to use guardpages? if available */
#define WANT_GUARD_PAGES 1

#ifdef WANT_GUARD_PAGES
/* Add guard pages at each end of our allocated memory */

#if defined(HAVE_SYSCONF) && defined(HAVE_MMAP) && defined(HAVE_MPROTECT) && defined(HAVE_STDINT_H)
#include <stdint.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#include <sys/mman.h>

#if defined(MAP_ANONYMOUS)
#define ANON_PAGE_MODE	(MAP_ANONYMOUS|MAP_PRIVATE)
#elif defined(MAP_ANON)
#define ANON_PAGE_MODE	(MAP_ANON|MAP_PRIVATE)
#else
#define ANON_PAGE_MODE	(MAP_PRIVATE)	/* have to map /dev/zero */
#define NEED_DEV_ZERO
#endif /* defined(MAP_ANONYMOUS) */

#ifdef NEED_DEV_ZERO
#include <fcntl.h>
static int dev_zero_fd;
#define ANON_FD	dev_zero_fd
#else
#define ANON_FD	-1
#endif /* NEED_DEV_ZERO */

#define USE_GUARD_PAGES 1
#endif /* defined(HAVE_SYSCONF) && defined(HAVE_MMAP) && defined(HAVE_MPROTECT) && defined(HAVE_STDINT_H) */
#endif /* WANT_GUARD_PAGES */

/* When required, allocate more memory from the OS in this size chunks */
#define EMEM_PACKET_CHUNK_SIZE (10 * 1024 * 1024)

/* The canary between allocations is at least 8 bytes and up to 16 bytes to
 * allow future allocations to be 4- or 8-byte aligned.
 * All but the last byte of the canary are randomly generated; the last byte is
 * NULL to separate the canary and the pointer to the next canary.
 *
 * For example, if the allocation is a multiple of 8 bytes, the canary and
 * pointer would look like:
 *   |0|1|2|3|4|5|6|7||0|1|2|3|4|5|6|7|
 *   |c|c|c|c|c|c|c|0||p|p|p|p|p|p|p|p| (64-bit), or:
 *   |c|c|c|c|c|c|c|0||p|p|p|p|         (32-bit)
 *
 * If the allocation was, for example, 12 bytes, the canary would look like:
 *        |0|1|2|3|4|5|6|7||0|1|2|3|4|5|6|7|
 *   [...]|a|a|a|a|c|c|c|c||c|c|c|c|c|c|c|0| (followed by the pointer)
 */
#define EMEM_CANARY_SIZE 8
#define EMEM_CANARY_DATA_SIZE (EMEM_CANARY_SIZE * 2 - 1)

typedef struct _emem_chunk_t {
	struct _emem_chunk_t *next;
	char		*buf;
	size_t           size;
	unsigned int	amount_free_init;
	unsigned int	amount_free;
	unsigned int	free_offset_init;
	unsigned int	free_offset;
	void		*canary_last;
} emem_chunk_t;

typedef struct _emem_pool_t {
	emem_chunk_t *free_list;
	emem_chunk_t *used_list;

	guint8 canary[EMEM_CANARY_DATA_SIZE];
	void *(*memory_alloc)(size_t size, struct _emem_pool_t *);

	/*
	 * Tools like Valgrind and ElectricFence don't work well with memchunks.
	 * Export the following environment variables to make {ep|se}_alloc() allocate each
	 * object individually.
	 *
	 * WIRESHARK_DEBUG_EP_NO_CHUNKS
	 */
	gboolean debug_use_chunks;

	/* Do we want to use canaries?
	 * Export the following environment variables to disable/enable canaries
	 *
	 * WIRESHARK_DEBUG_EP_NO_CANARY
	 */
	gboolean debug_use_canary;

	/*  Do we want to verify no one is using a pointer to an ep_
	 *  allocated thing where they shouldn't be?
	 *
	 * Export WIRESHARK_EP_VERIFY_POINTERS to turn this on.
	 */
	gboolean debug_verify_pointers;

} emem_pool_t;

static emem_pool_t ep_packet_mem;

/*
 *  Memory scrubbing is expensive but can be useful to ensure we don't:
 *    - use memory before initializing it
 *    - use memory after freeing it
 *  Export WIRESHARK_DEBUG_SCRUB_MEMORY to turn it on.
 */
static gboolean debug_use_memory_scrubber = FALSE;

#if defined (_WIN32)
static SYSTEM_INFO sysinfo;
static gboolean iswindowsplatform;
static int pagesize;
#elif defined(USE_GUARD_PAGES)
static intptr_t pagesize;
#endif /* _WIN32 / USE_GUARD_PAGES */

static void *emem_alloc_chunk(size_t size, emem_pool_t *mem);
static void *emem_alloc_glib(size_t size, emem_pool_t *mem);

/*
 * Set a canary value to be placed between memchunks.
 */
static void
emem_canary_init(guint8 *canary)
{
	int i;
	static GRand *rand_state = NULL;

	if (rand_state == NULL) {
		rand_state = g_rand_new();
	}
	for (i = 0; i < EMEM_CANARY_DATA_SIZE; i ++) {
		canary[i] = (guint8) g_rand_int_range(rand_state, 1, 0x100);
	}
	return;
}

static void *
emem_canary_next(guint8 *mem_canary, guint8 *canary, int *len)
{
	void *ptr;
	int i;

	for (i = 0; i < EMEM_CANARY_SIZE-1; i++)
		if (mem_canary[i] != canary[i])
			return (void *) -1;

	for (; i < EMEM_CANARY_DATA_SIZE; i++) {
		if (canary[i] == '\0') {
			memcpy(&ptr, &canary[i+1], sizeof(void *));

			if (len)
				*len = i + 1 + (int)sizeof(void *);
			return ptr;
		}

		if (mem_canary[i] != canary[i])
			return (void *) -1;
	}

	return (void *) -1;
}

/*
 * Given an allocation size, return the amount of room needed for the canary
 * (with a minimum of 8 bytes) while using the canary to pad to an 8-byte
 * boundary.
 */
static guint8
emem_canary_pad (size_t allocation)
{
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
void
ep_check_canary_integrity(const char* fmt, ...)
{
	va_list ap;
	static gchar there[128] = {
		'L','a','u','n','c','h',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	gchar here[128];
	emem_chunk_t* npc = NULL;

	if (! intense_canary_checking ) return;

	va_start(ap,fmt);
	g_vsnprintf(here, sizeof(here), fmt, ap);
	va_end(ap);

	for (npc = ep_packet_mem.free_list; npc != NULL; npc = npc->next) {
		void *canary_next = npc->canary_last;

		while (canary_next != NULL) {
			canary_next = emem_canary_next(ep_packet_mem.canary, canary_next, NULL);
			/* XXX, check if canary_next is inside allocated memory? */

			if (canary_next == (void *) -1)
				g_error("Per-packet memory corrupted\nbetween: %s\nand: %s", there, here);
		}
	}

	g_strlcpy(there, here, sizeof(there));
}
#endif

static void
emem_init_chunk(emem_pool_t *mem)
{
	if (mem->debug_use_canary)
		emem_canary_init(mem->canary);

	if (mem->debug_use_chunks)
		mem->memory_alloc = emem_alloc_chunk;
	else
		mem->memory_alloc = emem_alloc_glib;
}

static gsize
emem_memory_usage(const emem_pool_t *pool)
{
	gsize total_used = 0;
	emem_chunk_t *chunk;

	for (chunk = pool->used_list; chunk; chunk = chunk->next)
		total_used += (chunk->amount_free_init - chunk->amount_free);

	for (chunk = pool->free_list; chunk; chunk = chunk->next)
		total_used += (chunk->amount_free_init - chunk->amount_free);

	return total_used;
}

static gsize
ep_memory_usage(void)
{
	return emem_memory_usage(&ep_packet_mem);
}

/* Initialize the packet-lifetime memory allocation pool.
 * This function should be called only once when Wireshark or TShark starts
 * up.
 */
static void
ep_init_chunk(void)
{
	static const ws_mem_usage_t ep_stats = { "EP", ep_memory_usage, NULL };

	ep_packet_mem.free_list=NULL;
	ep_packet_mem.used_list=NULL;

	ep_packet_mem.debug_use_chunks = (getenv("WIRESHARK_DEBUG_EP_NO_CHUNKS") == NULL);
	ep_packet_mem.debug_use_canary = ep_packet_mem.debug_use_chunks && (getenv("WIRESHARK_DEBUG_EP_NO_CANARY") == NULL);
	ep_packet_mem.debug_verify_pointers = (getenv("WIRESHARK_EP_VERIFY_POINTERS") != NULL);

#ifdef DEBUG_INTENSE_CANARY_CHECKS
	intense_canary_checking = (getenv("WIRESHARK_DEBUG_EP_INTENSE_CANARY") != NULL);
#endif

	emem_init_chunk(&ep_packet_mem);

	memory_usage_component_register(&ep_stats);
}

/*  Initialize all the allocators here.
 *  This function should be called only once when Wireshark or TShark starts
 *  up.
 */
void
emem_init(void)
{
	ep_init_chunk();

	if (getenv("WIRESHARK_DEBUG_SCRUB_MEMORY"))
		debug_use_memory_scrubber  = TRUE;

#if defined (_WIN32)
	/* Set up our guard page info for Win32 */
	GetSystemInfo(&sysinfo);
	pagesize = sysinfo.dwPageSize;

#if (_MSC_VER >= 1800)
	/*
	 * On VS2103, GetVersionEx is deprecated. Microsoft recommend to
	 * use VerifyVersionInfo instead
	 */
	{
		OSVERSIONINFOEX osvi;
		DWORDLONG dwlConditionMask = 0;
		int op = VER_EQUAL;

		SecureZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
		osvi.dwPlatformId = VER_PLATFORM_WIN32_WINDOWS;
		VER_SET_CONDITION(dwlConditionMask, VER_PLATFORMID, op);
		iswindowsplatform = VerifyVersionInfo(&osvi, VER_PLATFORMID, dwlConditionMask);
	}
#else
	/* calling GetVersionEx using the OSVERSIONINFO structure.
	 * OSVERSIONINFOEX requires Win NT4 with SP6 or newer NT Versions.
	 * OSVERSIONINFOEX will fail on Win9x and older NT Versions.
	 * See also:
	 * http://msdn.microsoft.com/library/en-us/sysinfo/base/getversionex.asp
	 * http://msdn.microsoft.com/library/en-us/sysinfo/base/osversioninfo_str.asp
	 * http://msdn.microsoft.com/library/en-us/sysinfo/base/osversioninfoex_str.asp
	 */
	{
		OSVERSIONINFO versinfo;

		SecureZeroMemory(&versinfo, sizeof(OSVERSIONINFO));
		versinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		GetVersionEx(&versinfo);
		iswindowsplatform = (versinfo.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS);
	}
#endif

#elif defined(USE_GUARD_PAGES)
	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize == -1)
		fprintf(stderr, "Warning: call to sysconf() for _SC_PAGESIZE has failed...\n");
#ifdef NEED_DEV_ZERO
	dev_zero_fd = ws_open("/dev/zero", O_RDWR);
	g_assert(dev_zero_fd != -1);
#endif
#endif /* _WIN32 / USE_GUARD_PAGES */
}

static gboolean
emem_verify_pointer_list(const emem_chunk_t *chunk_list, const void *ptr)
{
	const gchar *cptr = (const gchar *)ptr;
	const emem_chunk_t *chunk;

	for (chunk = chunk_list; chunk; chunk = chunk->next) {
		if (cptr >= (chunk->buf + chunk->free_offset_init) && cptr < (chunk->buf + chunk->free_offset))
			return TRUE;
	}
	return FALSE;
}

static gboolean
emem_verify_pointer(const emem_pool_t *hdr, const void *ptr)
{
	return emem_verify_pointer_list(hdr->free_list, ptr) || emem_verify_pointer_list(hdr->used_list, ptr);
}

gboolean
ep_verify_pointer(const void *ptr)
{
	if (ep_packet_mem.debug_verify_pointers)
		return emem_verify_pointer(&ep_packet_mem, ptr);
	else
		return FALSE;
}

static void
emem_scrub_memory(char *buf, size_t size, gboolean alloc)
{
	guint scrubbed_value;
	size_t offset;

	if (!debug_use_memory_scrubber)
		return;

	if (alloc) /* this memory is being allocated */
		scrubbed_value = 0xBADDCAFE;
	else /* this memory is being freed */
		scrubbed_value = 0xDEADBEEF;

	/*  We shouldn't need to check the alignment of the starting address
	 *  since this is malloc'd memory (or 'pagesize' bytes into malloc'd
	 *  memory).
	 */

	/* XXX - if the above is *NOT* true, we should use memcpy here,
	 * in order to avoid problems on alignment-sensitive platforms, e.g.
	 * http://stackoverflow.com/questions/108866/is-there-memset-that-accepts-integers-larger-than-char
	 */

	for (offset = 0; offset + sizeof(guint) <= size; offset += sizeof(guint))
		*(guint*)(void*)(buf+offset) = scrubbed_value;

	/* Initialize the last bytes, if any */
	if (offset < size) {
		*(guint8*)(buf+offset) = scrubbed_value >> 24;
		offset++;
		if (offset < size) {
			*(guint8*)(buf+offset) = (scrubbed_value >> 16) & 0xFF;
			offset++;
			if (offset < size) {
				*(guint8*)(buf+offset) = (scrubbed_value >> 8) & 0xFF;
			}
		}
	}


}

static emem_chunk_t *
emem_create_chunk(size_t size)
{
	emem_chunk_t *npc;

	npc = g_new(emem_chunk_t, 1);
	npc->next = NULL;
	npc->canary_last = NULL;

#if defined (_WIN32)
	/*
	 * MSDN documents VirtualAlloc/VirtualProtect at
	 * http://msdn.microsoft.com/library/en-us/memory/base/creating_guard_pages.asp
	 */

	/* XXX - is MEM_COMMIT|MEM_RESERVE correct? */
	npc->buf = (char *)VirtualAlloc(NULL, size,
		MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

	if (npc->buf == NULL) {
		g_free(npc);
		if (getenv("WIRESHARK_ABORT_ON_OUT_OF_MEMORY"))
			abort();
		else
			THROW(OutOfMemoryError);
	}

#elif defined(USE_GUARD_PAGES)
	npc->buf = (char *)mmap(NULL, size,
		PROT_READ|PROT_WRITE, ANON_PAGE_MODE, ANON_FD, 0);

	if (npc->buf == MAP_FAILED) {
		g_free(npc);
		if (getenv("WIRESHARK_ABORT_ON_OUT_OF_MEMORY"))
			abort();
		else
			THROW(OutOfMemoryError);
	}

#else /* Is there a draft in here? */
	npc->buf = g_malloc(size);
	/* g_malloc() can't fail */
#endif

	npc->amount_free = npc->amount_free_init = (unsigned int) size;
	npc->free_offset = npc->free_offset_init = 0;
	return npc;
}

static emem_chunk_t *
emem_create_chunk_gp(size_t size)
{
#if defined (_WIN32)
	BOOL ret;
	char *buf_end, *prot1, *prot2;
	DWORD oldprot;
#elif defined(USE_GUARD_PAGES)
	int ret;
	char *buf_end, *prot1, *prot2;
#endif /* _WIN32 / USE_GUARD_PAGES */
	emem_chunk_t *npc;

	npc = emem_create_chunk(size);

#if defined (_WIN32)
	buf_end = npc->buf + size;

	/* Align our guard pages on page-sized boundaries */
	prot1 = (char *) ((((intptr_t) npc->buf + pagesize - 1) / pagesize) * pagesize);
	prot2 = (char *) ((((intptr_t) buf_end - (1 * pagesize)) / pagesize) * pagesize);

	ret = VirtualProtect(prot1, pagesize, PAGE_NOACCESS, &oldprot);
	g_assert(ret != 0 || iswindowsplatform);
	ret = VirtualProtect(prot2, pagesize, PAGE_NOACCESS, &oldprot);
	g_assert(ret != 0 || iswindowsplatform);

	npc->amount_free_init = (unsigned int) (prot2 - prot1 - pagesize);
	npc->free_offset_init = (unsigned int) (prot1 - npc->buf) + pagesize;
#elif defined(USE_GUARD_PAGES)
	buf_end = npc->buf + size;

	/* Align our guard pages on page-sized boundaries */
	prot1 = (char *) ((((intptr_t) npc->buf + pagesize - 1) / pagesize) * pagesize);
	prot2 = (char *) ((((intptr_t) buf_end - (1 * pagesize)) / pagesize) * pagesize);

	ret = mprotect(prot1, pagesize, PROT_NONE);
	g_assert(ret != -1);
	ret = mprotect(prot2, pagesize, PROT_NONE);
	g_assert(ret != -1);

	npc->amount_free_init = (unsigned int)(prot2 - prot1 - pagesize);
	npc->free_offset_init = (unsigned int)((prot1 - npc->buf) + pagesize);
#else
	npc->amount_free_init = size;
	npc->free_offset_init = 0;
#endif /* USE_GUARD_PAGES */

	npc->amount_free = npc->amount_free_init;
	npc->free_offset = npc->free_offset_init;
	return npc;
}

static void *
emem_alloc_chunk(size_t size, emem_pool_t *mem)
{
	void *buf;

	size_t asize = size;
	gboolean use_canary = mem->debug_use_canary;
	guint8 pad;
	emem_chunk_t *free_list;

	/* Allocate room for at least 8 bytes of canary plus some padding
	 * so the canary ends on an 8-byte boundary.
	 * But first add the room needed for the pointer to the next canary
	 * (so the entire allocation will end on an 8-byte boundary).
	 */
	 if (use_canary) {
		asize += sizeof(void *);
		pad = emem_canary_pad(asize);
	} else
		pad = (WS_MEM_ALIGN - (asize & (WS_MEM_ALIGN-1))) & (WS_MEM_ALIGN-1);

	asize += pad;

	/* make sure we don't try to allocate too much (arbitrary limit) */
	DISSECTOR_ASSERT(size<(EMEM_PACKET_CHUNK_SIZE>>2));

	if (!mem->free_list)
		mem->free_list = emem_create_chunk_gp(EMEM_PACKET_CHUNK_SIZE);

	/* oops, we need to allocate more memory to serve this request
	 * than we have free. move this node to the used list and try again
	 */
	if(asize > mem->free_list->amount_free) {
		emem_chunk_t *npc;
		npc=mem->free_list;
		mem->free_list=mem->free_list->next;
		npc->next=mem->used_list;
		mem->used_list=npc;

		if (!mem->free_list)
			mem->free_list = emem_create_chunk_gp(EMEM_PACKET_CHUNK_SIZE);
	}

	free_list = mem->free_list;

	buf = free_list->buf + free_list->free_offset;

	free_list->amount_free -= (unsigned int) asize;
	free_list->free_offset += (unsigned int) asize;

	if (use_canary) {
		char *cptr = (char *)buf + size;

		memcpy(cptr, mem->canary, pad-1);
		cptr[pad-1] = '\0';
		memcpy(cptr + pad, &free_list->canary_last, sizeof(void *));

		free_list->canary_last = cptr;
	}

	return buf;
}

static void *
emem_alloc_glib(size_t size, emem_pool_t *mem)
{
	emem_chunk_t *npc;

	npc=g_new(emem_chunk_t, 1);
	npc->next=mem->used_list;
	npc->buf=(char *)g_malloc(size);
	npc->canary_last = NULL;
	mem->used_list=npc;
	/* There's no padding/alignment involved (from our point of view) when
	 * we fetch the memory directly from the system pool, so WYSIWYG */
	npc->amount_free = npc->free_offset_init = 0;
	npc->free_offset = npc->amount_free_init = (unsigned int) size;

	return npc->buf;
}

/* allocate 'size' amount of memory. */
static void *
emem_alloc(size_t size, emem_pool_t *mem)
{
	void *buf;

#if 0
	/* For testing wmem, effectively redirects most emem memory to wmem.
	 * You will also have to comment out several assertions in wmem_core.c,
	 * specifically anything g_assert(allocator->in_scope), since it is much
	 * stricter about when it is permitted to be called. */
	if (mem == &ep_packet_mem) {
		return wmem_alloc(wmem_packet_scope(), size);
	}
#endif

	buf = mem->memory_alloc(size, mem);

	/*  XXX - this is a waste of time if the allocator function is going to
	 *  memset this straight back to 0.
	 */
	emem_scrub_memory((char *)buf, size, TRUE);

	return buf;
}

/* allocate 'size' amount of memory with an allocation lifetime until the
 * next packet.
 */
void *
ep_alloc(size_t size)
{
	return emem_alloc(size, &ep_packet_mem);
}

void *
ep_alloc0(size_t size)
{
	return memset(ep_alloc(size),'\0',size);
}

static gchar *
emem_strdup_vprintf(const gchar *fmt, va_list ap, void *allocator(size_t))
{
	va_list ap2;
	gsize len;
	gchar* dst;

	G_VA_COPY(ap2, ap);

	len = g_printf_string_upper_bound(fmt, ap);

	dst = (gchar *)allocator(len+1);
	g_vsnprintf (dst, (gulong) len, fmt, ap2);
	va_end(ap2);

	return dst;
}

static gchar *
ep_strdup_vprintf(const gchar *fmt, va_list ap)
{
	return emem_strdup_vprintf(fmt, ap, ep_alloc);
}

gchar *
ep_strdup_printf(const gchar *fmt, ...)
{
	va_list ap;
	gchar *dst;

	va_start(ap, fmt);
	dst = ep_strdup_vprintf(fmt, ap);
	va_end(ap);
	return dst;
}


/* release all allocated memory back to the pool. */
static void
emem_free_all(emem_pool_t *mem)
{
	gboolean use_chunks = mem->debug_use_chunks;

	emem_chunk_t *npc;

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
			while (npc->canary_last != NULL) {
				npc->canary_last = emem_canary_next(mem->canary, (guint8 *)npc->canary_last, NULL);
				/* XXX, check if canary_last is inside allocated memory? */

				if (npc->canary_last == (void *) -1)
					g_error("Memory corrupted");
			}

			emem_scrub_memory((npc->buf + npc->free_offset_init),
					  (npc->free_offset - npc->free_offset_init),
					  FALSE);

			npc->amount_free = npc->amount_free_init;
			npc->free_offset = npc->free_offset_init;
			npc = npc->next;
		} else {
			emem_chunk_t *next = npc->next;

			emem_scrub_memory(npc->buf, npc->amount_free_init, FALSE);

			g_free(npc->buf);
			g_free(npc);
			npc = next;
		}
	}

	if (!use_chunks) {
		/* We've freed all this memory already */
		mem->free_list = NULL;
	}
}

/* release all allocated memory back to the pool. */
void
ep_free_all(void)
{
	emem_free_all(&ep_packet_mem);
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
 * ex: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
