/*
 * Coverity Scan modeling file for Wireshark.
 *
 * See https://scan.coverity.com/models for the modeling language. To
 * use this file, upload it under "Modeling File" in the Coverity Scan
 * project settings (Settings -> Modeling File) or compile it locally
 * with:
 *
 *   cov-make-library --output-file wireshark-model.xmldb tools/coverity/model.c
 *
 * This file is not part of the Wireshark build.
 *
 * SPDX-License-Identifier: MIT
 */

/*
 * Memory from wmem allocators is owned by the allocator ("scope") and
 * released when the scope is freed or destroyed. Most wmem functions are
 * declared with G_GNUC_MALLOC (__attribute__((malloc))), which makes
 * Coverity treat their return values as storage that the caller must
 * free, and so it reports RESOURCE_LEAK for every use of such a string
 * that isn't released, e.g. col_add_str(cinfo, id, val_to_str(pool, ...)).
 *
 * Model the wmem functions and the helpers that return wmem-allocated
 * strings as returning memory that is not owned by the caller. The
 * models deliberately don't call __coverity_alloc__() or friends.
 */

typedef unsigned long size_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned char uint8_t;
/* The model compiler has no __builtin_va_list; the layout doesn't matter here. */
typedef void *va_list;

typedef struct _wmem_allocator_t wmem_allocator_t;
typedef struct _value_string value_string;
typedef struct _value_string_ext value_string_ext;
typedef struct _val64_string val64_string;
typedef struct _val64_string_ext val64_string_ext;
typedef struct _string_string string_string;
typedef struct _range_string range_string;
typedef struct _bytes_string bytes_string;

/* wsutil/wmem/wmem_core.h */

void *wmem_alloc(wmem_allocator_t *allocator, const size_t size)
{
    void *p;
    return p;
}

void *wmem_alloc0(wmem_allocator_t *allocator, const size_t size)
{
    void *p;
    return p;
}

void *wmem_realloc(wmem_allocator_t *allocator, void *ptr, const size_t size)
{
    void *p;
    return p;
}

/* wsutil/wmem/wmem_miscutl.h */

void *wmem_memdup(wmem_allocator_t *allocator, const void *source, const size_t size)
{
    void *p;
    return p;
}

/* wsutil/wmem/wmem_strutl.h */

char *wmem_strdup(wmem_allocator_t *allocator, const char *src)
{
    char *s;
    return s;
}

char *wmem_strndup(wmem_allocator_t *allocator, const char *src, const size_t len)
{
    char *s;
    return s;
}

char *wmem_strdup_printf(wmem_allocator_t *allocator, const char *fmt, ...)
{
    char *s;
    return s;
}

char *wmem_strdup_vprintf(wmem_allocator_t *allocator, const char *fmt, va_list ap)
{
    char *s;
    return s;
}

/* wsutil/value_string.h */

char *val_to_str(wmem_allocator_t *scope, const uint32_t val, const value_string *vs, const char *fmt)
{
    char *s;
    return s;
}

char *val_to_str_ext(wmem_allocator_t *scope, const uint32_t val, value_string_ext *vse, const char *fmt)
{
    char *s;
    return s;
}

const char *val64_to_str_wmem(wmem_allocator_t *scope, const uint64_t val, const val64_string *vs, const char *fmt)
{
    char *s;
    return s;
}

char *val64_to_str_ext_wmem(wmem_allocator_t *scope, const uint64_t val, val64_string_ext *vse, const char *fmt)
{
    char *s;
    return s;
}

const char *str_to_str_wmem(wmem_allocator_t *scope, const char *val, const string_string *vs, const char *fmt)
{
    char *s;
    return s;
}

const char *rval_to_str_wmem(wmem_allocator_t *scope, const uint32_t val, const range_string *rs, const char *fmt)
{
    char *s;
    return s;
}

const char *bytesval_to_str_wmem(wmem_allocator_t *scope, const uint8_t *val, const size_t val_len, const bytes_string *bs, const char *fmt)
{
    char *s;
    return s;
}

const char *bytesprefix_to_str(wmem_allocator_t *scope, const uint8_t *haystack, const size_t haystack_len, const bytes_string *bs, const char *fmt)
{
    char *s;
    return s;
}
