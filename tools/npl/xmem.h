/*
 * Copyright 2012-2013, Jakub Zawadzki <darkjames-ws@darkjames.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _X_MEM_H
#define _X_MEM_H

#include <stdlib.h>

static void oom_killer(void) {
	fprintf(stderr, "\n\n !!! Out of memory !!!\n\n");
	abort();
}

static inline void *xmalloc(size_t s) { void *ptr = malloc(s); if (!ptr) oom_killer(); return memset(ptr, 0x00, s); }
static inline void *xrealloc(void *p, size_t s) { void *ptr = realloc(p, s); if (!ptr) oom_killer(); return ptr; }

static inline void *xmemdup(void *p, size_t s) { void *ptr = malloc(s); if (!ptr) oom_killer(); return memcpy(ptr, p, s); }
static inline char *xstrdup(const char *s) { void *ptr = strdup(s); if (!ptr) oom_killer(); return ptr; }

#define xnew(x) (x *) xmalloc(sizeof(x))
#define xdup(x, y) (x *) xmemdup(y, sizeof(x))

#endif
