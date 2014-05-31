/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef NGHTTP2_HD_H
#define NGHTTP2_HD_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <wsutil/nghttp2/nghttp2/nghttp2.h>

#include "nghttp2_hd_huffman.h"
#include "nghttp2_buf.h"

#define NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE NGHTTP2_DEFAULT_HEADER_TABLE_SIZE
#define NGHTTP2_HD_ENTRY_OVERHEAD 32

/* The maximum length of one name/value pair.  This is the sum of the
   length of name and value.  This is not specified by the spec. We
   just chose the arbitrary size */
#define NGHTTP2_HD_MAX_NV 8192

/* Default size of maximum table buffer size for encoder. Even if
   remote decoder notifies larger buffer size for its decoding,
   encoder only uses the memory up to this value. */
#define NGHTTP2_HD_DEFAULT_MAX_DEFLATE_BUFFER_SIZE (1 << 12)

typedef enum {
  NGHTTP2_HD_ROLE_DEFLATE,
  NGHTTP2_HD_ROLE_INFLATE
} nghttp2_hd_role;

typedef enum {
  NGHTTP2_HD_FLAG_NONE = 0,
  /* Indicates name was dynamically allocated and must be freed */
  NGHTTP2_HD_FLAG_NAME_ALLOC = 1,
  /* Indicates value was dynamically allocated and must be freed */
  NGHTTP2_HD_FLAG_VALUE_ALLOC = 1 << 1,
  /* Indicates that the entry is in the reference set */
  NGHTTP2_HD_FLAG_REFSET = 1 << 2,
  /* Indicates that the entry is emitted in the current header
     processing. */
  NGHTTP2_HD_FLAG_EMIT = 1 << 3,
  NGHTTP2_HD_FLAG_IMPLICIT_EMIT = 1 << 4,
  /* Indicates that the name was gifted to the entry and no copying
     necessary. */
  NGHTTP2_HD_FLAG_NAME_GIFT = 1 << 5,
  /* Indicates that the value was gifted to the entry and no copying
     necessary. */
  NGHTTP2_HD_FLAG_VALUE_GIFT = 1 << 6
} nghttp2_hd_flags;

typedef struct {
  nghttp2_nv nv;
  uint32_t name_hash;
  uint32_t value_hash;
  /* Reference count */
  uint8_t ref;
  uint8_t flags;
} nghttp2_hd_entry;

typedef struct {
  nghttp2_hd_entry ent;
  size_t index;
} nghttp2_hd_static_entry;

typedef struct {
  nghttp2_hd_entry **buffer;
  size_t mask;
  size_t first;
  size_t len;
} nghttp2_hd_ringbuf;

typedef enum {
  NGHTTP2_HD_OPCODE_NONE,
  NGHTTP2_HD_OPCODE_INDEXED,
  NGHTTP2_HD_OPCODE_NEWNAME,
  NGHTTP2_HD_OPCODE_INDNAME
} nghttp2_hd_opcode;

typedef enum {
  NGHTTP2_HD_STATE_OPCODE,
  NGHTTP2_HD_STATE_CLEAR_REFSET,
  NGHTTP2_HD_STATE_READ_TABLE_SIZE,
  NGHTTP2_HD_STATE_READ_INDEX,
  NGHTTP2_HD_STATE_NEWNAME_CHECK_NAMELEN,
  NGHTTP2_HD_STATE_NEWNAME_READ_NAMELEN,
  NGHTTP2_HD_STATE_NEWNAME_READ_NAMEHUFF,
  NGHTTP2_HD_STATE_NEWNAME_READ_NAME,
  NGHTTP2_HD_STATE_CHECK_VALUELEN,
  NGHTTP2_HD_STATE_READ_VALUELEN,
  NGHTTP2_HD_STATE_READ_VALUEHUFF,
  NGHTTP2_HD_STATE_READ_VALUE
} nghttp2_hd_inflate_state;

typedef struct {
  /* dynamic header table */
  nghttp2_hd_ringbuf hd_table;
  /* Abstract buffer size of hd_table as described in the spec. This
     is the sum of length of name/value in hd_table +
     NGHTTP2_HD_ENTRY_OVERHEAD bytes overhead per each entry. */
  size_t hd_table_bufsize;
  /* The effective header table size. */
  size_t hd_table_bufsize_max;
  /* Role of this context; deflate or infalte */
  nghttp2_hd_role role;
  /* If inflate/deflate error occurred, this value is set to 1 and
     further invocation of inflate/deflate will fail with
     NGHTTP2_ERR_HEADER_COMP. */
  uint8_t bad;
} nghttp2_hd_context;

struct nghttp2_hd_deflater {
  nghttp2_hd_context ctx;
  /* The upper limit of the header table size the deflater accepts. */
  size_t deflate_hd_table_bufsize_max;
  /* Set to this nonzero to clear reference set on each deflation each
     time. */
  uint8_t no_refset;
  /* If nonzero, send header table size using encoding context update
     in the next deflate process */
  uint8_t notify_table_size_change;
};

struct nghttp2_hd_inflater {
  nghttp2_hd_context ctx;
  /* header buffer */
  nghttp2_bufs nvbufs;
  /* Stores current state of huffman decoding */
  nghttp2_hd_huff_decode_context huff_decode_ctx;
  /* Pointer to the nghttp2_hd_entry which is used current header
     emission. This is required because in some cases the
     ent_keep->ref == 0 and we have to keep track of it. */
  nghttp2_hd_entry *ent_keep;
  /* Pointer to the name/value pair buffer which is used in the
     current header emission. */
  uint8_t *nv_keep;
  /* Pointers to the name/value pair which is referred as indexed
     name. This entry must be in header table. */
  nghttp2_hd_entry *ent_name;
  /* The number of bytes to read */
  ssize_t left;
  /* The index in indexed repr or indexed name */
  size_t index;
  /* The index of header table to toggle off the entry from reference
     set at the end of decompression. */
  size_t end_headers_index;
  /* The length of new name encoded in literal.  For huffman encoded
     string, this is the length after it is decoded. */
  size_t newnamelen;
  /* The maximum header table size the inflater supports. This is the
     same value transmitted in SETTINGS_HEADER_TABLE_SIZE */
  size_t settings_hd_table_bufsize_max;
  nghttp2_hd_opcode opcode;
  nghttp2_hd_inflate_state state;
  /* nonzero if string is huffman encoded */
  uint8_t huffman_encoded;
  /* nonzero if deflater requires that current entry is indexed */
  uint8_t index_required;
  /* nonzero if deflater requires that current entry must not be
     indexed */
  uint8_t no_index;
};

/*
 * Initializes the |ent| members. If NGHTTP2_HD_FLAG_NAME_ALLOC bit
 * set in the |flags|, the content pointed by the |name| with length
 * |namelen| is copied. Likewise, if NGHTTP2_HD_FLAG_VALUE_ALLOC bit
 * set in the |flags|, the content pointed by the |value| with length
 * |valuelen| is copied.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_hd_entry_init(nghttp2_hd_entry *ent, uint8_t flags,
                          uint8_t *name, size_t namelen,
                          uint8_t *value, size_t valuelen);

void nghttp2_hd_entry_free(nghttp2_hd_entry *ent);

/*
 * Initializes |deflater| for deflating name/values pairs.
 *
 * The encoder only uses up to
 * NGHTTP2_HD_DEFAULT_MAX_DEFLATE_BUFFER_SIZE bytes for header table
 * even if the larger value is specified later in
 * nghttp2_hd_change_table_size().
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_hd_deflate_init(nghttp2_hd_deflater *deflater);

/*
 * Initializes |deflater| for deflating name/values pairs.
 *
 * The encoder only uses up to |deflate_hd_table_bufsize_max| bytes
 * for header table even if the larger value is specified later in
 * nghttp2_hd_change_table_size().
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_hd_deflate_init2(nghttp2_hd_deflater *deflater,
                             size_t deflate_hd_table_bufsize_max);

/*
 * Deallocates any resources allocated for |deflater|.
 */
void nghttp2_hd_deflate_free(nghttp2_hd_deflater *deflater);

/*
 * Deflates the |nva|, which has the |nvlen| name/value pairs, into
 * the |bufs|.
 *
 * This function expands |bufs| as necessary to store the result. If
 * buffers is full and the process still requires more space, this
 * funtion fails and returns NGHTTP2_ERR_HEADER_COMP.
 *
 * After this function returns, it is safe to delete the |nva|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_HEADER_COMP
 *     Deflation process has failed.
 * NGHTTP2_ERR_BUFFER_ERROR
 *     Out of buffer space.
 */
int nghttp2_hd_deflate_hd_bufs(nghttp2_hd_deflater *deflater,
                               nghttp2_bufs *bufs,
                               nghttp2_nv *nva, size_t nvlen);

/*
 * Initializes |inflater| for inflating name/values pairs.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_hd_inflate_init(nghttp2_hd_inflater *inflater);

/*
 * Deallocates any resources allocated for |inflater|.
 */
void nghttp2_hd_inflate_free(nghttp2_hd_inflater *inflater);

/* For unittesting purpose */
int nghttp2_hd_emit_indname_block(nghttp2_bufs *bufs, size_t index,
                                  nghttp2_nv *nv, int inc_indexing);

/* For unittesting purpose */
int nghttp2_hd_emit_newname_block(nghttp2_bufs *bufs, nghttp2_nv *nv,
                                  int inc_indexing);

/* For unittesting purpose */
int nghttp2_hd_emit_table_size(nghttp2_bufs *bufs, size_t table_size);

/* For unittesting purpose */
nghttp2_hd_entry* nghttp2_hd_table_get(nghttp2_hd_context *context,
                                       size_t index);

/* Huffman encoding/decoding functions */

/*
 * Counts the required bytes to encode |src| with length |len|.
 *
 * This function returns the number of required bytes to encode given
 * data, including padding of prefix of terminal symbol code. This
 * function always succeeds.
 */
size_t nghttp2_hd_huff_encode_count(const uint8_t *src, size_t len);

/*
 * Encodes the given data |src| with length |srclen| to the |bufs|.
 * This function expands extra buffers in |bufs| if necessary.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_BUFFER_ERROR
 *     Out of buffer space.
 */
int nghttp2_hd_huff_encode(nghttp2_bufs *bufs,
                           const uint8_t *src, size_t srclen);

void nghttp2_hd_huff_decode_context_init(nghttp2_hd_huff_decode_context *ctx);

/*
 * Decodes the given data |src| with length |srclen|. The |ctx| must
 * be initialized by nghttp2_hd_huff_decode_context_init(). The result
 * will be added to |dest|. This function may expand |dest| as
 * needed. The caller is responsible to release the memory of |dest|
 * by calling nghttp2_bufs_free() or export its content using
 * nghttp2_bufs_remove().
 *
 * The caller must set the |final| to nonzero if the given input is
 * the final block.
 *
 * This function returns the number of read bytes from the |in|.
 *
 * If this function fails, it returns one of the following negative
 * return codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_BUFFER_ERROR
 *     Maximum buffer capacity size exceeded.
 * NGHTTP2_ERR_HEADER_COMP
 *     Decoding process has failed.
 */
ssize_t nghttp2_hd_huff_decode(nghttp2_hd_huff_decode_context *ctx,
                               nghttp2_bufs *bufs,
                               const uint8_t *src, size_t srclen, int final);

#endif /* NGHTTP2_HD_H */
