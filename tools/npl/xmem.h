/*
 * Copyright 2012-2013, Jakub Zawadzki <darkjames-ws@darkjames.pl>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
