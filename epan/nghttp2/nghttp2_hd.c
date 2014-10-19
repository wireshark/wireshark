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
#include "nghttp2_hd.h"

#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "nghttp2_helper.h"
#include "nghttp2_int.h"

#define STATIC_TABLE_LENGTH 61

/* Make scalar initialization form of nghttp2_nv */
#define MAKE_STATIC_ENT(I, N, V, NH, VH)                                \
  { { { (uint8_t*)N, (uint8_t*)V, sizeof(N) - 1, sizeof(V) - 1, 0 },    \
        NH, VH, 1, NGHTTP2_HD_FLAG_NONE }, I }

/* Sorted by hash(name) and its table index */
static nghttp2_hd_static_entry static_table[] = {
  MAKE_STATIC_ENT(20, "age", "", 96511u, 0u),
  MAKE_STATIC_ENT(59, "via", "", 116750u, 0u),
  MAKE_STATIC_ENT(32, "date", "", 3076014u, 0u),
  MAKE_STATIC_ENT(33, "etag", "", 3123477u, 0u),
  MAKE_STATIC_ENT(36, "from", "", 3151786u, 0u),
  MAKE_STATIC_ENT(37, "host", "", 3208616u, 0u),
  MAKE_STATIC_ENT(44, "link", "", 3321850u, 0u),
  MAKE_STATIC_ENT(58, "vary", "", 3612210u, 0u),
  MAKE_STATIC_ENT(38, "if-match", "", 34533653u, 0u),
  MAKE_STATIC_ENT(41, "if-range", "", 39145613u, 0u),
  MAKE_STATIC_ENT(3, ":path", "/", 56997727u, 47u),
  MAKE_STATIC_ENT(4, ":path", "/index.html", 56997727u, 2144181430u),
  MAKE_STATIC_ENT(21, "allow", "", 92906313u, 0u),
  MAKE_STATIC_ENT(49, "range", "", 108280125u, 0u),
  MAKE_STATIC_ENT(14, "accept-charset", "", 124285319u, 0u),
  MAKE_STATIC_ENT(43, "last-modified", "", 150043680u, 0u),
  MAKE_STATIC_ENT(48, "proxy-authorization", "", 329532250u, 0u),
  MAKE_STATIC_ENT(57, "user-agent", "", 486342275u, 0u),
  MAKE_STATIC_ENT(40, "if-none-match", "", 646073760u, 0u),
  MAKE_STATIC_ENT(30, "content-type", "", 785670158u, 0u),
  MAKE_STATIC_ENT(16, "accept-language", "", 802785917u, 0u),
  MAKE_STATIC_ENT(50, "referer", "", 1085069613u, 0u),
  MAKE_STATIC_ENT(51, "refresh", "", 1085444827u, 0u),
  MAKE_STATIC_ENT(55, "strict-transport-security", "", 1153852136u, 0u),
  MAKE_STATIC_ENT(54, "set-cookie", "", 1237214767u, 0u),
  MAKE_STATIC_ENT(56, "transfer-encoding", "", 1274458357u, 0u),
  MAKE_STATIC_ENT(17, "accept-ranges", "", 1397189435u, 0u),
  MAKE_STATIC_ENT(42, "if-unmodified-since", "", 1454068927u, 0u),
  MAKE_STATIC_ENT(46, "max-forwards", "", 1619948695u, 0u),
  MAKE_STATIC_ENT(45, "location", "", 1901043637u, 0u),
  MAKE_STATIC_ENT(52, "retry-after", "", 1933352567u, 0u),
  MAKE_STATIC_ENT(25, "content-encoding", "", 2095084583u, 0u),
  MAKE_STATIC_ENT(28, "content-location", "", 2284906121u, 0u),
  MAKE_STATIC_ENT(39, "if-modified-since", "", 2302095846u, 0u),
  MAKE_STATIC_ENT(18, "accept", "", 2871506184u, 0u),
  MAKE_STATIC_ENT(29, "content-range", "", 2878374633u, 0u),
  MAKE_STATIC_ENT(22, "authorization", "", 2909397113u, 0u),
  MAKE_STATIC_ENT(31, "cookie", "", 2940209764u, 0u),
  MAKE_STATIC_ENT(0, ":authority", "", 2962729033u, 0u),
  MAKE_STATIC_ENT(35, "expires", "", 2985731892u, 0u),
  MAKE_STATIC_ENT(34, "expect", "", 3005803609u, 0u),
  MAKE_STATIC_ENT(24, "content-disposition", "", 3027699811u, 0u),
  MAKE_STATIC_ENT(26, "content-language", "", 3065240108u, 0u),
  MAKE_STATIC_ENT(1, ":method", "GET", 3153018267u, 70454u),
  MAKE_STATIC_ENT(2, ":method", "POST", 3153018267u, 2461856u),
  MAKE_STATIC_ENT(27, "content-length", "", 3162187450u, 0u),
  MAKE_STATIC_ENT(19, "access-control-allow-origin", "", 3297999203u, 0u),
  MAKE_STATIC_ENT(5, ":scheme", "http", 3322585695u, 3213448u),
  MAKE_STATIC_ENT(6, ":scheme", "https", 3322585695u, 99617003u),
  MAKE_STATIC_ENT(7, ":status", "200", 3338091692u, 49586u),
  MAKE_STATIC_ENT(8, ":status", "204", 3338091692u, 49590u),
  MAKE_STATIC_ENT(9, ":status", "206", 3338091692u, 49592u),
  MAKE_STATIC_ENT(10, ":status", "304", 3338091692u, 50551u),
  MAKE_STATIC_ENT(11, ":status", "400", 3338091692u, 51508u),
  MAKE_STATIC_ENT(12, ":status", "404", 3338091692u, 51512u),
  MAKE_STATIC_ENT(13, ":status", "500", 3338091692u, 52469u),
  MAKE_STATIC_ENT(53, "server", "", 3389140803u, 0u),
  MAKE_STATIC_ENT(47, "proxy-authenticate", "", 3993199572u, 0u),
  MAKE_STATIC_ENT(60, "www-authenticate", "", 4051929931u, 0u),
  MAKE_STATIC_ENT(23, "cache-control", "", 4086191634u, 0u),
  MAKE_STATIC_ENT(15, "accept-encoding", "gzip, deflate", 4127597688u, 1733326877u),
};

/* Index to the position in static_table */
const size_t static_table_index[] = {
  38, 43, 44, 10, 11, 47, 48, 49, 50, 51, 52, 53, 54, 55, 14, 60,
  20, 26, 34, 46, 0 , 12, 36, 59, 41, 31, 42, 45, 32, 35, 19, 37,
  2 , 3 , 40, 39, 4 , 5 , 8 , 33, 18, 9 , 27, 15, 6 , 29, 28, 57,
  16, 13, 21, 22, 30, 56, 24, 23, 25, 17, 7 , 1 , 58
};

const size_t NGHTTP2_STATIC_TABLE_LENGTH =
  sizeof(static_table)/sizeof(static_table[0]);

static int memeq(const void *s1, const void *s2, size_t n)
{
  const uint8_t *a = (const uint8_t*)s1, *b = (const uint8_t*)s2;
  uint8_t c = 0;
  while(n > 0) {
    c |= (*a++) ^ (*b++);
    --n;
  }
  return c == 0;
}

static uint32_t hash(const uint8_t *s, size_t n)
{
  uint32_t h = 0;
  while(n > 0) {
    h = h * 31 + *s++;
    --n;
  }
  return h;
}

int nghttp2_hd_entry_init(nghttp2_hd_entry *ent, uint8_t flags,
                          uint8_t *name, size_t namelen,
                          uint8_t *value, size_t valuelen,
                          uint32_t name_hash, uint32_t value_hash)
{
  int rv = 0;

  /* Since nghttp2_hd_entry is used for indexing, ent->nv.flags always
     NGHTTP2_NV_FLAG_NONE */
  ent->nv.flags = NGHTTP2_NV_FLAG_NONE;

  if((flags & NGHTTP2_HD_FLAG_NAME_ALLOC) &&
     (flags & NGHTTP2_HD_FLAG_NAME_GIFT) == 0) {
    if(namelen == 0) {
      /* We should not allow empty header field name */
      ent->nv.name = NULL;
    } else {
      ent->nv.name = (uint8_t *)nghttp2_memdup(name, namelen);
      if(ent->nv.name == NULL) {
        rv = NGHTTP2_ERR_NOMEM;
        goto fail;
      }
    }
  } else {
    ent->nv.name = name;
  }
  if((flags & NGHTTP2_HD_FLAG_VALUE_ALLOC) &&
     (flags & NGHTTP2_HD_FLAG_VALUE_GIFT) == 0) {
    if(valuelen == 0) {
      ent->nv.value = NULL;
    } else {
      ent->nv.value = (uint8_t *)nghttp2_memdup(value, valuelen);
      if(ent->nv.value == NULL) {
        rv = NGHTTP2_ERR_NOMEM;
        goto fail2;
      }
    }
  } else {
    ent->nv.value = value;
  }
  ent->nv.namelen = namelen;
  ent->nv.valuelen = valuelen;
  ent->ref = 1;
  ent->flags = flags;

  ent->name_hash = name_hash;
  ent->value_hash = value_hash;

  return 0;

 fail2:
  if(flags & NGHTTP2_HD_FLAG_NAME_ALLOC) {
    free(ent->nv.name);
  }
 fail:
  return rv;
}

void nghttp2_hd_entry_free(nghttp2_hd_entry *ent)
{
  assert(ent->ref == 0);
  if(ent->flags & NGHTTP2_HD_FLAG_NAME_ALLOC) {
    free(ent->nv.name);
  }
  if(ent->flags & NGHTTP2_HD_FLAG_VALUE_ALLOC) {
    free(ent->nv.value);
  }
}

static int hd_ringbuf_init(nghttp2_hd_ringbuf *ringbuf, size_t bufsize)
{
  size_t size;
  for(size = 1; size < bufsize; size <<= 1);
  ringbuf->buffer = (nghttp2_hd_entry**)malloc(sizeof(nghttp2_hd_entry*) * size);
  if(ringbuf->buffer == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  ringbuf->mask = size - 1;
  ringbuf->first = 0;
  ringbuf->len = 0;
  return 0;
}

static nghttp2_hd_entry* hd_ringbuf_get(nghttp2_hd_ringbuf *ringbuf,
                                        size_t idx)
{
  assert(idx < ringbuf->len);
  return ringbuf->buffer[(ringbuf->first + idx) & ringbuf->mask];
}

static int hd_ringbuf_reserve(nghttp2_hd_ringbuf *ringbuf, size_t bufsize)
{
  size_t i;
  size_t size;
  nghttp2_hd_entry **buffer;

  if(ringbuf->mask + 1 >= bufsize) {
    return 0;
  }
  for(size = 1; size < bufsize; size <<= 1);
  buffer = (nghttp2_hd_entry **)malloc(sizeof(nghttp2_hd_entry*) * size);
  if(buffer == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }
  for(i = 0; i < ringbuf->len; ++i) {
    buffer[i] = hd_ringbuf_get(ringbuf, i);
  }
  free(ringbuf->buffer);
  ringbuf->buffer = buffer;
  ringbuf->mask = size - 1;
  ringbuf->first = 0;
  return 0;
}

static void hd_ringbuf_free(nghttp2_hd_ringbuf *ringbuf)
{
  size_t i;
  if(ringbuf == NULL) {
    return;
  }
  for(i = 0; i < ringbuf->len; ++i) {
    nghttp2_hd_entry *ent = hd_ringbuf_get(ringbuf, i);
    --ent->ref;
    nghttp2_hd_entry_free(ent);
    free(ent);
  }
  free(ringbuf->buffer);
}

static int hd_ringbuf_push_front(nghttp2_hd_ringbuf *ringbuf,
                                 nghttp2_hd_entry *ent)
{
  int rv;

  rv = hd_ringbuf_reserve(ringbuf, ringbuf->len + 1);

  if(rv != 0) {
    return rv;
  }

  ringbuf->buffer[--ringbuf->first & ringbuf->mask] = ent;
  ++ringbuf->len;

  return 0;
}

static void hd_ringbuf_pop_back(nghttp2_hd_ringbuf *ringbuf)
{
  assert(ringbuf->len > 0);
  --ringbuf->len;
}

static int hd_context_init(nghttp2_hd_context *context)
{
  int rv;
  context->bad = 0;
  context->hd_table_bufsize_max = NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE;
  rv = hd_ringbuf_init
    (&context->hd_table,
     context->hd_table_bufsize_max/NGHTTP2_HD_ENTRY_OVERHEAD);
  if(rv != 0) {
    return rv;
  }

  context->hd_table_bufsize = 0;
  return 0;
}

static void hd_context_free(nghttp2_hd_context *context)
{
  hd_ringbuf_free(&context->hd_table);
}

int nghttp2_hd_deflate_init(nghttp2_hd_deflater *deflater)
{
  return nghttp2_hd_deflate_init2(deflater,
                                  NGHTTP2_HD_DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
}

int nghttp2_hd_deflate_init2(nghttp2_hd_deflater *deflater,
                             size_t deflate_hd_table_bufsize_max)
{
  int rv;
  rv =  hd_context_init(&deflater->ctx);
  if(rv != 0) {
    return rv;
  }

  if(deflate_hd_table_bufsize_max < NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE) {
    deflater->notify_table_size_change = 1;
    deflater->ctx.hd_table_bufsize_max = deflate_hd_table_bufsize_max;
  } else {
    deflater->notify_table_size_change = 0;
  }

  deflater->deflate_hd_table_bufsize_max = deflate_hd_table_bufsize_max;
  deflater->min_hd_table_bufsize_max = UINT32_MAX;

  return 0;
}

int nghttp2_hd_inflate_init(nghttp2_hd_inflater *inflater)
{
  int rv;

  rv = hd_context_init(&inflater->ctx);
  if(rv != 0) {
    goto fail;
  }

  inflater->settings_hd_table_bufsize_max =
    NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE;

  inflater->ent_keep = NULL;
  inflater->nv_keep = NULL;

  inflater->opcode = NGHTTP2_HD_OPCODE_NONE;
  inflater->state = NGHTTP2_HD_STATE_OPCODE;

  rv = nghttp2_bufs_init3(&inflater->nvbufs, NGHTTP2_HD_MAX_NV / 8, 8, 1, 0);

  if(rv != 0) {
    goto nvbufs_fail;
  }

  inflater->huffman_encoded = 0;
  inflater->index = 0;
  inflater->left = 0;
  inflater->shift = 0;
  inflater->newnamelen = 0;
  inflater->index_required = 0;
  inflater->no_index = 0;

  return 0;

 nvbufs_fail:
  hd_context_free(&inflater->ctx);
 fail:
  return rv;
}

static void hd_inflate_keep_free(nghttp2_hd_inflater *inflater)
{
  if(inflater->ent_keep) {
    if(inflater->ent_keep->ref == 0) {
      nghttp2_hd_entry_free(inflater->ent_keep);
      free(inflater->ent_keep);
    }
    inflater->ent_keep = NULL;
  }

  free(inflater->nv_keep);
  inflater->nv_keep = NULL;
}

void nghttp2_hd_deflate_free(nghttp2_hd_deflater *deflater)
{
  hd_context_free(&deflater->ctx);
}

void nghttp2_hd_inflate_free(nghttp2_hd_inflater *inflater)
{
  hd_inflate_keep_free(inflater);
  nghttp2_bufs_free(&inflater->nvbufs);
  hd_context_free(&inflater->ctx);
}

static size_t entry_room(size_t namelen, size_t valuelen)
{
  return NGHTTP2_HD_ENTRY_OVERHEAD + namelen + valuelen;
}

static int emit_indexed_header(nghttp2_nv *nv_out, nghttp2_hd_entry *ent)
{
  DEBUGF(fprintf(stderr, "inflatehd: header emission: "));
  DEBUGF(fwrite(ent->nv.name, ent->nv.namelen, 1, stderr));
  DEBUGF(fprintf(stderr, ": "));
  DEBUGF(fwrite(ent->nv.value, ent->nv.valuelen, 1, stderr));
  DEBUGF(fprintf(stderr, "\n"));
  /* ent->ref may be 0. This happens if the encoder emits literal
     block larger than header table capacity with indexing. */
  *nv_out = ent->nv;
  return 0;
}

static int emit_literal_header(nghttp2_nv *nv_out, nghttp2_nv *nv)
{
  DEBUGF(fprintf(stderr, "inflatehd: header emission: "));
  DEBUGF(fwrite(nv->name, nv->namelen, 1, stderr));
  DEBUGF(fprintf(stderr, ": "));
  DEBUGF(fwrite(nv->value, nv->valuelen, 1, stderr));
  DEBUGF(fprintf(stderr, "\n"));
  *nv_out = *nv;
  return 0;
}

static size_t count_encoded_length(size_t n, size_t prefix)
{
  size_t k = (1 << prefix) - 1;
  size_t len = 0;
  if(n >= k) {
    n -= k;
    ++len;
  } else {
    return 1;
  }
  do {
    ++len;
    if(n >= 128) {
      n >>= 7;
    } else {
      break;
    }
  } while(n);
  return len;
}

static size_t encode_length(uint8_t *buf, size_t n, size_t prefix)
{
  size_t k = (1 << prefix) - 1;
  size_t len = 0;

  *buf &= ~k;

  if(n < k) {
    *buf++ |= n;

    return 1;
  }

  *buf++ |= k;
  n -= k;
  ++len;

  do {
    ++len;
    if(n >= 128) {
      *buf++ = (1 << 7) | (n & 0x7f);
      n >>= 7;
    } else {
      *buf++ = (uint8_t)n;
      break;
    }
  } while(n);
  return len;
}

/*
 * Decodes |prefix| prefixed integer stored from |in|.  The |last|
 * represents the 1 beyond the last of the valid contiguous memory
 * region from |in|.  The decoded integer must be less than or equal
 * to UINT32_MAX.
 *
 * If the |initial| is nonzero, it is used as a initial value, this
 * function assumes the |in| starts with intermediate data.
 *
 * An entire integer is decoded successfully, decoded, the |*final| is
 * set to nonzero.
 *
 * This function stores the decoded integer in |*res| if it succeed,
 * including partial decoding (in this case, number of shift to make
 * in the next call will be stored in |*shift_ptr|) and returns number
 * of bytes processed, or returns -1, indicating decoding error.
 */
static ssize_t decode_length(uint32_t *res, size_t *shift_ptr, int *final,
                             uint32_t initial, size_t shift,
                             uint8_t *in, uint8_t *last, size_t prefix)
{
  uint32_t k = (1 << prefix) - 1;
  uint32_t n = initial;
  uint8_t *start = in;

  *shift_ptr = 0;
  *final = 0;

  if(n == 0) {
    if((*in & k) != k) {
      *res = (*in) & k;
      *final = 1;
      return 1;
    }

    n = k;

    if(++in == last) {
      *res = n;
      return (ssize_t)(in - start);
    }
  }

  for(; in != last; ++in, shift += 7) {
    uint32_t add = *in & 0x7f;

    if((UINT32_MAX >> shift) < add) {
      DEBUGF(fprintf(stderr, "inflate: integer overflow on shift\n"));
      return -1;
    }

    add <<= shift;

    if(UINT32_MAX - add < n) {
      DEBUGF(fprintf(stderr, "inflate: integer overflow on addition\n"));
      return -1;
    }

    n += add;

    if((*in & (1 << 7)) == 0) {
      break;
    }
  }

  *shift_ptr = shift;

  if(in == last) {
    *res = n;
    return (ssize_t)(in - start);
  }

  *res = n;
  *final = 1;
  return (ssize_t)(in + 1 - start);
}

static int emit_table_size(nghttp2_bufs *bufs, size_t table_size)
{
  int rv;
  uint8_t *bufp;
  size_t blocklen;
  uint8_t sb[16];

  DEBUGF(fprintf(stderr, "deflatehd: emit table_size=%zu\n", table_size));

  blocklen = count_encoded_length(table_size, 5);

  if(sizeof(sb) < blocklen) {
    return NGHTTP2_ERR_HEADER_COMP;
  }

  bufp = sb;

  *bufp = 0x20u;

  encode_length(bufp, table_size, 5);

  rv = nghttp2_bufs_add(bufs, sb, blocklen);
  if(rv != 0) {
    return rv;
  }

  return 0;
}

static int emit_indexed_block(nghttp2_bufs *bufs, size_t idx)
{
  int rv;
  size_t blocklen;
  uint8_t sb[16];
  uint8_t *bufp;

  blocklen = count_encoded_length(idx + 1, 7);

  DEBUGF(fprintf(stderr, "deflatehd: emit indexed index=%zu, %zu bytes\n",
                 idx, blocklen));

  if(sizeof(sb) < blocklen) {
    return NGHTTP2_ERR_HEADER_COMP;
  }

  bufp = sb;
  *bufp = 0x80u;
  encode_length(bufp, idx + 1, 7);

  rv = nghttp2_bufs_add(bufs, sb, blocklen);
  if(rv != 0) {
    return rv;
  }

  return 0;
}

static int emit_string(nghttp2_bufs *bufs, const uint8_t *str, size_t len)
{
  int rv;
  uint8_t sb[16];
  uint8_t *bufp;
  size_t blocklen;
  size_t enclen;
  int huffman = 0;

  enclen = nghttp2_hd_huff_encode_count(str, len);

  if(enclen < len) {
    huffman = 1;
  } else {
    enclen = len;
  }

  blocklen = count_encoded_length(enclen, 7);

  DEBUGF(fprintf(stderr,
                 "deflatehd: emit string str="));
  DEBUGF(fwrite(str, len, 1, stderr));
  DEBUGF(fprintf(stderr, ", length=%zu, huffman=%d, encoded_length=%zu\n",
                 len, huffman, enclen));

  if(sizeof(sb) < blocklen) {
    return NGHTTP2_ERR_HEADER_COMP;
  }

  bufp = sb;
  *bufp = huffman ? 1 << 7 : 0;
  encode_length(bufp, enclen, 7);

  rv = nghttp2_bufs_add(bufs, sb, blocklen);
  if(rv != 0) {
    return rv;
  }

  if(huffman) {
    rv = nghttp2_hd_huff_encode(bufs, str, len);
  } else {
    assert(enclen == len);
    rv = nghttp2_bufs_add(bufs, str, len);
  }

  return rv;
}

static uint8_t pack_first_byte(int inc_indexing, int no_index)
{
  if(inc_indexing) {
    return 0x40u;
  }

  if(no_index) {
    return 0x10u;
  }

  return 0;
}

static int emit_indname_block(nghttp2_bufs *bufs, size_t idx,
                              const nghttp2_nv *nv,
                              int inc_indexing)
{
  int rv;
  uint8_t *bufp;
  size_t blocklen;
  uint8_t sb[16];
  size_t prefixlen;
  int no_index;

  no_index = (nv->flags & NGHTTP2_NV_FLAG_NO_INDEX) != 0;

  if(inc_indexing) {
    prefixlen = 6;
  } else {
    prefixlen = 4;
  }

  DEBUGF(fprintf(stderr,
                 "deflatehd: emit indname index=%zu, valuelen=%zu, "
                 "indexing=%d, no_index=%d\n",
                 idx, nv->valuelen, inc_indexing, no_index));

  blocklen = count_encoded_length(idx + 1, prefixlen);

  if(sizeof(sb) < blocklen) {
    return NGHTTP2_ERR_HEADER_COMP;
  }

  bufp = sb;

  *bufp = pack_first_byte(inc_indexing, no_index);

  encode_length(bufp, idx + 1, prefixlen);

  rv = nghttp2_bufs_add(bufs, sb, blocklen);
  if(rv != 0) {
    return rv;
  }

  rv = emit_string(bufs, nv->value, nv->valuelen);
  if(rv != 0) {
    return rv;
  }

  return 0;
}

static int emit_newname_block(nghttp2_bufs *bufs, const nghttp2_nv *nv,
                              int inc_indexing)
{
  int rv;
  int no_index;

  no_index = (nv->flags & NGHTTP2_NV_FLAG_NO_INDEX) != 0;

  DEBUGF(fprintf(stderr,
                 "deflatehd: emit newname namelen=%zu, valuelen=%zu, "
                 "indexing=%d, no_index=%d\n",
                 nv->namelen, nv->valuelen, inc_indexing, no_index));

  rv = nghttp2_bufs_addb(bufs, pack_first_byte(inc_indexing, no_index));
  if(rv != 0) {
    return rv;
  }

  rv = emit_string(bufs, nv->name, nv->namelen);
  if(rv != 0) {
    return rv;
  }

  rv = emit_string(bufs, nv->value, nv->valuelen);
  if(rv != 0) {
    return rv;
  }

  return 0;
}

static nghttp2_hd_entry* add_hd_table_incremental(nghttp2_hd_context *context,
                                                  const nghttp2_nv *nv,
                                                  uint32_t name_hash,
                                                  uint32_t value_hash,
                                                  uint8_t entry_flags)
{
  int rv;
  nghttp2_hd_entry *new_ent;
  size_t room;

  room = entry_room(nv->namelen, nv->valuelen);

  while(context->hd_table_bufsize + room > context->hd_table_bufsize_max &&
        context->hd_table.len > 0) {

    size_t idx = context->hd_table.len - 1;
    nghttp2_hd_entry* ent = hd_ringbuf_get(&context->hd_table, idx);

    context->hd_table_bufsize -= entry_room(ent->nv.namelen, ent->nv.valuelen);

    DEBUGF(fprintf(stderr, "hpack: remove item from header table: "));
    DEBUGF(fwrite(ent->nv.name, ent->nv.namelen, 1, stderr));
    DEBUGF(fprintf(stderr, ": "));
    DEBUGF(fwrite(ent->nv.value, ent->nv.valuelen, 1, stderr));
    DEBUGF(fprintf(stderr, "\n"));
    hd_ringbuf_pop_back(&context->hd_table);
    if(--ent->ref == 0) {
      nghttp2_hd_entry_free(ent);
      free(ent);
    }
  }

  new_ent = (nghttp2_hd_entry *)malloc(sizeof(nghttp2_hd_entry));
  if(new_ent == NULL) {
    return NULL;
  }

  rv = nghttp2_hd_entry_init(new_ent, entry_flags,
                             nv->name, nv->namelen, nv->value, nv->valuelen,
                             name_hash, value_hash);
  if(rv != 0) {
    free(new_ent);
    return NULL;
  }

  if(room > context->hd_table_bufsize_max) {
    /* The entry taking more than NGHTTP2_HD_MAX_BUFFER_SIZE is
       immediately evicted. */
    --new_ent->ref;
  } else {
    rv = hd_ringbuf_push_front(&context->hd_table, new_ent);

    if(rv != 0) {
      --new_ent->ref;

      /* nv->name and nv->value are managed by caller. */
      new_ent->nv.name = NULL;
      new_ent->nv.namelen = 0;
      new_ent->nv.value = NULL;
      new_ent->nv.valuelen = 0;

      nghttp2_hd_entry_free(new_ent);
      free(new_ent);

      return NULL;
    }

    context->hd_table_bufsize += room;
  }
  return new_ent;
}

static int name_eq(const nghttp2_nv *a, const nghttp2_nv *b)
{
  return a->namelen == b->namelen && memeq(a->name, b->name, a->namelen);
}

static int value_eq(const nghttp2_nv *a, const nghttp2_nv *b)
{
  return a->valuelen == b->valuelen && memeq(a->value, b->value, a->valuelen);
}

typedef struct {
  ssize_t index;
  /* Nonzero if both name and value are matched. */
  uint8_t name_value_match;
} search_result;

static search_result search_hd_table(nghttp2_hd_context *context,
                                     const nghttp2_nv *nv,
                                     uint32_t name_hash, uint32_t value_hash)
{
  ssize_t left = -1, right = (ssize_t)STATIC_TABLE_LENGTH;
  search_result res = { -1, 0 };
  size_t i;
  int use_index = (nv->flags & NGHTTP2_NV_FLAG_NO_INDEX) == 0;

  /* Search dynamic table first, so that we can find recently used
     entry first */
  if(use_index) {
    for(i = 0; i < context->hd_table.len; ++i) {
      nghttp2_hd_entry *ent = hd_ringbuf_get(&context->hd_table, i);
      if(ent->name_hash != name_hash || !name_eq(&ent->nv, nv)) {
        continue;
      }

      if(res.index == -1) {
        res.index = (ssize_t)(i + NGHTTP2_STATIC_TABLE_LENGTH);
      }

      if(ent->value_hash == value_hash && value_eq(&ent->nv, nv)) {
        res.index = (ssize_t)(i + NGHTTP2_STATIC_TABLE_LENGTH);
        res.name_value_match = 1;
        return res;
      }
    }
  }

  while(right - left > 1) {
    ssize_t mid = (left + right) / 2;
    nghttp2_hd_entry *ent = &static_table[mid].ent;
    if(ent->name_hash < name_hash) {
      left = mid;
    } else {
      right = mid;
    }
  }

  for(i = right; i < STATIC_TABLE_LENGTH; ++i) {
    nghttp2_hd_entry *ent = &static_table[i].ent;
    if(ent->name_hash != name_hash) {
      break;
    }

    if(name_eq(&ent->nv, nv)) {
      if(res.index == -1) {
        res.index = (ssize_t)(static_table[i].index);
      }
      if(use_index &&
         ent->value_hash == value_hash && value_eq(&ent->nv, nv)) {
        res.index = (ssize_t)(static_table[i].index);
        res.name_value_match = 1;
        return res;
      }
    }
  }

  return res;
}

static void hd_context_shrink_table_size(nghttp2_hd_context *context)
{
  while(context->hd_table_bufsize > context->hd_table_bufsize_max &&
        context->hd_table.len > 0) {
    size_t idx = context->hd_table.len - 1;
    nghttp2_hd_entry* ent = hd_ringbuf_get(&context->hd_table, idx);
    context->hd_table_bufsize -= entry_room(ent->nv.namelen, ent->nv.valuelen);
    hd_ringbuf_pop_back(&context->hd_table);
    if(--ent->ref == 0) {
      nghttp2_hd_entry_free(ent);
      free(ent);
    }
  }
}

int nghttp2_hd_deflate_change_table_size(nghttp2_hd_deflater *deflater,
                                         size_t settings_hd_table_bufsize_max)
{
  size_t next_bufsize = nghttp2_min(settings_hd_table_bufsize_max,
                                    deflater->deflate_hd_table_bufsize_max);

  deflater->ctx.hd_table_bufsize_max = next_bufsize;

  deflater->min_hd_table_bufsize_max =
    nghttp2_min(deflater->min_hd_table_bufsize_max, next_bufsize);

  deflater->notify_table_size_change = 1;

  hd_context_shrink_table_size(&deflater->ctx);
  return 0;
}

int nghttp2_hd_inflate_change_table_size(nghttp2_hd_inflater *inflater,
                                         size_t settings_hd_table_bufsize_max)
{
  inflater->settings_hd_table_bufsize_max = settings_hd_table_bufsize_max;
  inflater->ctx.hd_table_bufsize_max = settings_hd_table_bufsize_max;
  hd_context_shrink_table_size(&inflater->ctx);
  return 0;
}

#define INDEX_RANGE_VALID(context, idx) \
  ((idx) < (context)->hd_table.len + NGHTTP2_STATIC_TABLE_LENGTH)

static size_t get_max_index(nghttp2_hd_context *context)
{
  return context->hd_table.len + NGHTTP2_STATIC_TABLE_LENGTH - 1;
}

nghttp2_hd_entry* nghttp2_hd_table_get(nghttp2_hd_context *context,
                                       size_t idx)
{
  assert(INDEX_RANGE_VALID(context, idx));
  if(idx >= NGHTTP2_STATIC_TABLE_LENGTH) {
    return hd_ringbuf_get(&context->hd_table, idx - NGHTTP2_STATIC_TABLE_LENGTH);
  } else {
    return &static_table[static_table_index[idx]].ent;
  }
}

#define name_match(NV, NAME)                                            \
  (nv->namelen == sizeof(NAME) - 1 && memeq(nv->name, NAME, sizeof(NAME) - 1))

static int hd_deflate_should_indexing(nghttp2_hd_deflater *deflater,
                                      const nghttp2_nv *nv)
{
  if((nv->flags & NGHTTP2_NV_FLAG_NO_INDEX) ||
     entry_room(nv->namelen, nv->valuelen) >
     deflater->ctx.hd_table_bufsize_max * 3 / 4) {
    return 0;
  }
#ifdef NGHTTP2_XHD
  return !name_match(nv, NGHTTP2_XHD);
#else /* !NGHTTP2_XHD */
  return
    !name_match(nv, ":path") &&
    !name_match(nv, "content-length") &&
    !name_match(nv, "set-cookie") &&
    !name_match(nv, "etag") &&
    !name_match(nv, "if-modified-since") &&
    !name_match(nv, "if-none-match") &&
    !name_match(nv, "location") &&
    !name_match(nv, "age");
#endif /* !NGHTTP2_XHD */
}

static int deflate_nv(nghttp2_hd_deflater *deflater,
                      nghttp2_bufs *bufs, const nghttp2_nv *nv)
{
  int rv;
  search_result res;
  ssize_t idx = -1;
  int incidx = 0;
  uint32_t name_hash = hash(nv->name, nv->namelen);
  uint32_t value_hash = hash(nv->value, nv->valuelen);

  DEBUGF(fprintf(stderr, "deflatehd: deflating "));
  DEBUGF(fwrite(nv->name, nv->namelen, 1, stderr));
  DEBUGF(fprintf(stderr, ": "));
  DEBUGF(fwrite(nv->value, nv->valuelen, 1, stderr));
  DEBUGF(fprintf(stderr, "\n"));


  res = search_hd_table(&deflater->ctx, nv, name_hash, value_hash);

  idx = res.index;

  if(res.name_value_match) {

    DEBUGF(fprintf(stderr, "deflatehd: name/value match index=%zd\n", idx));

    rv = emit_indexed_block(bufs, idx);
    if(rv != 0) {
      return rv;
    }

    return 0;
  }

  if(res.index != -1) {
    DEBUGF(fprintf(stderr, "deflatehd: name match index=%zd\n",
                   res.index));
  }

  if(hd_deflate_should_indexing(deflater, nv)) {
    nghttp2_hd_entry *new_ent;
    if(idx != -1 && idx < (ssize_t)NGHTTP2_STATIC_TABLE_LENGTH) {
      nghttp2_nv nv_indname;
      nv_indname = *nv;
      nv_indname.name = nghttp2_hd_table_get(&deflater->ctx, idx)->nv.name;
      new_ent = add_hd_table_incremental(&deflater->ctx, &nv_indname,
                                         name_hash, value_hash,
                                         NGHTTP2_HD_FLAG_VALUE_ALLOC);
    } else {
      new_ent = add_hd_table_incremental(&deflater->ctx, nv,
                                         name_hash, value_hash,
                                         NGHTTP2_HD_FLAG_NAME_ALLOC |
                                         NGHTTP2_HD_FLAG_VALUE_ALLOC);
    }
    if(!new_ent) {
      return NGHTTP2_ERR_HEADER_COMP;
    }
    if(new_ent->ref == 0) {
      nghttp2_hd_entry_free(new_ent);
      free(new_ent);
    }
    incidx = 1;
  }
  if(idx == -1) {
    rv = emit_newname_block(bufs, nv, incidx);
  } else {
    rv = emit_indname_block(bufs, idx, nv, incidx);
  }
  if(rv != 0) {
    return rv;
  }

  return 0;
}

int nghttp2_hd_deflate_hd_bufs(nghttp2_hd_deflater *deflater,
                               nghttp2_bufs *bufs,
                               const nghttp2_nv *nv, size_t nvlen)
{
  size_t i;
  int rv = 0;

  if(deflater->ctx.bad) {
    return NGHTTP2_ERR_HEADER_COMP;
  }

  if(deflater->notify_table_size_change) {
    size_t min_hd_table_bufsize_max;

    min_hd_table_bufsize_max = deflater->min_hd_table_bufsize_max;

    deflater->notify_table_size_change = 0;
    deflater->min_hd_table_bufsize_max = UINT32_MAX;

    if(deflater->ctx.hd_table_bufsize_max > min_hd_table_bufsize_max) {

      rv = emit_table_size(bufs, min_hd_table_bufsize_max);

      if(rv != 0) {
        goto fail;
      }
    }

    rv = emit_table_size(bufs, deflater->ctx.hd_table_bufsize_max);

    if(rv != 0) {
      goto fail;
    }
  }

  for(i = 0; i < nvlen; ++i) {
    rv = deflate_nv(deflater, bufs, &nv[i]);
    if(rv != 0) {
      goto fail;
    }
  }

  DEBUGF(fprintf(stderr,
                 "deflatehd: all input name/value pairs were deflated\n"));

  return 0;
 fail:
  DEBUGF(fprintf(stderr, "deflatehd: error return %d\n", rv));

  deflater->ctx.bad = 1;
  return rv;
}

ssize_t nghttp2_hd_deflate_hd(nghttp2_hd_deflater *deflater,
                              uint8_t *buf, size_t buflen,
                              const nghttp2_nv *nv, size_t nvlen)
{
  nghttp2_bufs bufs;
  int rv;

  rv = nghttp2_bufs_wrap_init(&bufs, buf, buflen);

  if(rv != 0) {
    return rv;
  }

  rv = nghttp2_hd_deflate_hd_bufs(deflater, &bufs, nv, nvlen);

  buflen = nghttp2_bufs_len(&bufs);

  nghttp2_bufs_wrap_free(&bufs);

  if(rv == NGHTTP2_ERR_BUFFER_ERROR) {
    return NGHTTP2_ERR_INSUFF_BUFSIZE;
  }

  if(rv != 0) {
    return rv;
  }

  return (ssize_t)buflen;
}

size_t nghttp2_hd_deflate_bound(nghttp2_hd_deflater *deflater _U_,
                                const nghttp2_nv *nva, size_t nvlen)
{
  size_t n = 0;
  size_t i;

  /* Possible Maximum Header Table Size Change.  Encoding (1u << 31) -
     1 using 4 bit prefix requires 6 bytes.  We may emit this at most
     twice. */
  n += 12;

  /* Use Literal Header Field without indexing - New Name, since it is
     most space consuming format.  Also we choose the less one between
     non-huffman and huffman, so using literal byte count is
     sufficient for upper bound.

     Encoding (1u << 31) - 1 using 7 bit prefix requires 6 bytes.  We
     need 2 of this for |nvlen| header fields. */
  n += 6 * 2 * nvlen;

  for(i = 0; i < nvlen; ++i) {
    n += nva[i].namelen + nva[i].valuelen;
  }

  return n;
}

int nghttp2_hd_deflate_new(nghttp2_hd_deflater **deflater_ptr,
                           size_t deflate_hd_table_bufsize_max)
{
  int rv;
  nghttp2_hd_deflater *deflater;

  deflater = (nghttp2_hd_deflater *)malloc(sizeof(nghttp2_hd_deflater));

  if(deflater == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  rv =  nghttp2_hd_deflate_init2(deflater, deflate_hd_table_bufsize_max);

  if(rv != 0) {
    free(deflater);

    return rv;
  }

  *deflater_ptr = deflater;

  return 0;
}

void nghttp2_hd_deflate_del(nghttp2_hd_deflater *deflater)
{
  nghttp2_hd_deflate_free(deflater);

  free(deflater);
}

static void hd_inflate_set_huffman_encoded(nghttp2_hd_inflater *inflater,
                                           const uint8_t *in)
{
  inflater->huffman_encoded = (*in & (1 << 7)) != 0;
}

/*
 * Decodes the integer from the range [in, last).  The result is
 * assigned to |inflater->left|.  If the |inflater->left| is 0, then
 * it performs variable integer decoding from scratch. Otherwise, it
 * uses the |inflater->left| as the initial value and continues to
 * decode assuming that [in, last) begins with intermediary sequence.
 *
 * This function returns the number of bytes read if it succeeds, or
 * one of the following negative error codes:
 *
 * NGHTTP2_ERR_HEADER_COMP
 *   Integer decoding failed
 */
static ssize_t hd_inflate_read_len(nghttp2_hd_inflater *inflater,
                                   int *rfin,
                                   uint8_t *in, uint8_t *last,
                                   size_t prefix, size_t maxlen)
{
  ssize_t rv;
  uint32_t out;

  *rfin = 0;

  rv = decode_length(&out, &inflater->shift, rfin, (uint32_t)inflater->left,
                     inflater->shift, in, last, prefix);

  if(rv == -1) {
    DEBUGF(fprintf(stderr, "inflatehd: integer decoding failed\n"));
    return NGHTTP2_ERR_HEADER_COMP;
  }

  if(out > maxlen) {
    DEBUGF(fprintf(stderr,
                   "inflatehd: integer exceeded the maximum value %zu\n",
                   maxlen));
    return NGHTTP2_ERR_HEADER_COMP;
  }

  inflater->left = out;

  DEBUGF(fprintf(stderr, "inflatehd: decoded integer is %u\n", out));

  return rv;
}

/*
 * Reads |inflater->left| bytes from the range [in, last) and performs
 * huffman decoding against them and pushes the result into the
 * |buffer|.
 *
 * This function returns the number of bytes read if it succeeds, or
 * one of the following negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *   Out of memory
 * NGHTTP2_ERR_HEADER_COMP
 *   Huffman decoding failed
 * NGHTTP2_ERR_BUFFER_ERROR
 *     Out of buffer space.
 */
static ssize_t hd_inflate_read_huff(nghttp2_hd_inflater *inflater,
                                    nghttp2_bufs *bufs,
                                    uint8_t *in, uint8_t *last)
{
  ssize_t readlen;
  int final = 0;
  if((size_t)(last - in) >= inflater->left) {
    last = in + inflater->left;
    final = 1;
  }
  readlen = nghttp2_hd_huff_decode(&inflater->huff_decode_ctx, bufs,
                                   in, last - in, final);

  if(readlen < 0) {
    DEBUGF(fprintf(stderr, "inflatehd: huffman decoding failed\n"));
    return readlen;
  }
  inflater->left -= (size_t)readlen;
  return readlen;
}

/*
 * Reads |inflater->left| bytes from the range [in, last) and copies
 * them into the |buffer|.
 *
 * This function returns the number of bytes read if it succeeds, or
 * one of the following negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *   Out of memory
 * NGHTTP2_ERR_HEADER_COMP
 *   Header decompression failed
 * NGHTTP2_ERR_BUFFER_ERROR
 *     Out of buffer space.
 */
static ssize_t hd_inflate_read(nghttp2_hd_inflater *inflater,
                               nghttp2_bufs *bufs,
                               uint8_t *in, uint8_t *last)
{
  int rv;
  size_t len = nghttp2_min((size_t)(last - in), inflater->left);
  rv = nghttp2_bufs_add(bufs, in, len);
  if(rv != 0) {
    return rv;
  }
  inflater->left -= len;
  return (ssize_t)len;
}

/*
 * Finalize indexed header representation reception. If header is
 * emitted, |*nv_out| is filled with that value and 0 is returned. If
 * no header is emitted, 1 is returned.
 *
 * This function returns either 0 or 1 if it succeeds, or one of the
 * following negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *   Out of memory
 */
static int hd_inflate_commit_indexed(nghttp2_hd_inflater *inflater,
                                     nghttp2_nv *nv_out)
{
  nghttp2_hd_entry *ent = nghttp2_hd_table_get(&inflater->ctx, inflater->index);

  emit_indexed_header(nv_out, ent);

  return 0;
}

static int hd_inflate_remove_bufs(nghttp2_hd_inflater *inflater,
                                  nghttp2_nv *nv, int value_only)
{
  ssize_t rv;
  size_t buflen;
  uint8_t *buf;
  nghttp2_buf *pbuf;

  if(inflater->index_required ||
     inflater->nvbufs.head != inflater->nvbufs.cur) {

    rv = nghttp2_bufs_remove(&inflater->nvbufs, &buf);

    if(rv < 0) {
      return NGHTTP2_ERR_NOMEM;
    }

    buflen = rv;

    if(value_only) {
      nv->name = NULL;
      nv->namelen = 0;
    } else {
      nv->name = buf;
      nv->namelen = inflater->newnamelen;
    }

    nv->value = buf + nv->namelen;
    nv->valuelen = buflen - nv->namelen;

    return 0;
  }

  /* If we are not going to store header in header table and
     name/value are in first chunk, we just refer them from nv,
     instead of mallocing another memory. */

  pbuf = &inflater->nvbufs.head->buf;

  if(value_only) {
    nv->name = NULL;
    nv->namelen = 0;
  } else {
    nv->name = pbuf->pos;
    nv->namelen = inflater->newnamelen;
  }

  nv->value = pbuf->pos + nv->namelen;
  nv->valuelen = nghttp2_buf_len(pbuf) - nv->namelen;

  /* Resetting does not change the content of first buffer */
  nghttp2_bufs_reset(&inflater->nvbufs);

  return 0;
}

/*
 * Finalize literal header representation - new name- reception. If
 * header is emitted, |*nv_out| is filled with that value and 0 is
 * returned.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *   Out of memory
 */
static int hd_inflate_commit_newname(nghttp2_hd_inflater *inflater,
                                     nghttp2_nv *nv_out)
{
  int rv;
  nghttp2_nv nv;

  rv = hd_inflate_remove_bufs(inflater, &nv, 0 /* name and value */);
  if(rv != 0) {
    return NGHTTP2_ERR_NOMEM;
  }

  if(inflater->no_index) {
    nv.flags = NGHTTP2_NV_FLAG_NO_INDEX;
  } else {
    nv.flags = NGHTTP2_NV_FLAG_NONE;
  }

  if(inflater->index_required) {
    nghttp2_hd_entry *new_ent;
    uint8_t ent_flags;

    /* nv->value points to the middle of the buffer pointed by
       nv->name.  So we just need to keep track of nv->name for memory
       management. */
    ent_flags = NGHTTP2_HD_FLAG_NAME_ALLOC | NGHTTP2_HD_FLAG_NAME_GIFT;

    new_ent = add_hd_table_incremental(&inflater->ctx, &nv,
                                       hash(nv.name, nv.namelen),
                                       hash(nv.value, nv.valuelen),
                                       ent_flags);

    if(new_ent) {
      emit_indexed_header(nv_out, new_ent);
      inflater->ent_keep = new_ent;

      return 0;
    }

    free(nv.name);

    return NGHTTP2_ERR_NOMEM;
  }

  emit_literal_header(nv_out, &nv);

  if(nv.name != inflater->nvbufs.head->buf.pos) {
    inflater->nv_keep = nv.name;
  }

  return 0;
}

/*
 * Finalize literal header representation - indexed name-
 * reception. If header is emitted, |*nv_out| is filled with that
 * value and 0 is returned.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *   Out of memory
 */
static int hd_inflate_commit_indname(nghttp2_hd_inflater *inflater,
                                     nghttp2_nv *nv_out)
{
  int rv;
  nghttp2_nv nv;
  nghttp2_hd_entry *ent_name;

  rv = hd_inflate_remove_bufs(inflater, &nv, 1 /* value only */);
  if(rv != 0) {
    return NGHTTP2_ERR_NOMEM;
  }

  if(inflater->no_index) {
    nv.flags = NGHTTP2_NV_FLAG_NO_INDEX;
  } else {
    nv.flags = NGHTTP2_NV_FLAG_NONE;
  }

  ent_name = nghttp2_hd_table_get(&inflater->ctx, inflater->index);

  nv.name = ent_name->nv.name;
  nv.namelen = ent_name->nv.namelen;

  if(inflater->index_required) {
    nghttp2_hd_entry *new_ent;
    uint8_t ent_flags;
    int static_name;

    ent_flags = NGHTTP2_HD_FLAG_VALUE_ALLOC | NGHTTP2_HD_FLAG_VALUE_GIFT;
    static_name = inflater->index < NGHTTP2_STATIC_TABLE_LENGTH;

    if(!static_name) {
      ent_flags |= NGHTTP2_HD_FLAG_NAME_ALLOC;
      /* For entry in static table, we must not touch ref, because it
         is shared by threads */
      ++ent_name->ref;
    }

    new_ent = add_hd_table_incremental(&inflater->ctx, &nv,
                                       ent_name->name_hash,
                                       hash(nv.value, nv.valuelen),
                                       ent_flags);

    if(!static_name && --ent_name->ref == 0) {
      nghttp2_hd_entry_free(ent_name);
      free(ent_name);
    }

    if(new_ent) {
      emit_indexed_header(nv_out, new_ent);

      inflater->ent_keep = new_ent;

      return 0;
    }

    free(nv.value);

    return NGHTTP2_ERR_NOMEM;
  }

  emit_literal_header(nv_out, &nv);

  if(nv.value != inflater->nvbufs.head->buf.pos) {
    inflater->nv_keep = nv.value;
  }

  return 0;
}

ssize_t nghttp2_hd_inflate_hd(nghttp2_hd_inflater *inflater,
                              nghttp2_nv *nv_out, int *inflate_flags,
                              uint8_t *in, size_t inlen, int in_final)
{
  ssize_t rv = 0;
  uint8_t *first = in;
  uint8_t *last = in + inlen;
  int rfin = 0;

  if(inflater->ctx.bad) {
    return NGHTTP2_ERR_HEADER_COMP;
  }

  DEBUGF(fprintf(stderr, "inflatehd: start state=%d\n",
                 inflater->state));
  hd_inflate_keep_free(inflater);
  *inflate_flags = NGHTTP2_HD_INFLATE_NONE;
  for(; in != last;) {
    switch(inflater->state) {
    case NGHTTP2_HD_STATE_OPCODE:
      if((*in & 0xe0u) == 0x20u) {
        DEBUGF(fprintf(stderr, "inflatehd: header table size change\n"));
        inflater->opcode = NGHTTP2_HD_OPCODE_INDEXED;
        inflater->state = NGHTTP2_HD_STATE_READ_TABLE_SIZE;
      } else if(*in & 0x80u) {
        DEBUGF(fprintf(stderr, "inflatehd: indexed repr\n"));
        inflater->opcode = NGHTTP2_HD_OPCODE_INDEXED;
        inflater->state = NGHTTP2_HD_STATE_READ_INDEX;
      } else {
        if(*in == 0x40u || *in == 0 || *in == 0x10u) {
          DEBUGF(fprintf(stderr,
                         "inflatehd: literal header repr - new name\n"));
          inflater->opcode = NGHTTP2_HD_OPCODE_NEWNAME;
          inflater->state = NGHTTP2_HD_STATE_NEWNAME_CHECK_NAMELEN;
        } else {
          DEBUGF(fprintf(stderr,
                         "inflatehd: literal header repr - indexed name\n"));
          inflater->opcode = NGHTTP2_HD_OPCODE_INDNAME;
          inflater->state = NGHTTP2_HD_STATE_READ_INDEX;
        }
        inflater->index_required = (*in & 0x40) != 0;
        inflater->no_index = (*in & 0xf0u) == 0x10u;
        DEBUGF(fprintf(stderr,
                       "inflatehd: indexing required=%d, no_index=%d\n",
                       inflater->index_required,
                       inflater->no_index));
        if(inflater->opcode == NGHTTP2_HD_OPCODE_NEWNAME) {
          ++in;
        }
      }
      inflater->left = 0;
      inflater->shift = 0;
      break;
    case NGHTTP2_HD_STATE_READ_TABLE_SIZE:
      rfin = 0;
      rv = hd_inflate_read_len(inflater, &rfin, in, last, 5,
                               inflater->settings_hd_table_bufsize_max);
      if(rv < 0) {
        goto fail;
      }
      in += rv;
      if(!rfin) {
        goto almost_ok;
      }
      DEBUGF(fprintf(stderr, "inflatehd: table_size=%zu\n", inflater->left));
      inflater->ctx.hd_table_bufsize_max = inflater->left;
      hd_context_shrink_table_size(&inflater->ctx);
      inflater->state = NGHTTP2_HD_STATE_OPCODE;
      break;
    case NGHTTP2_HD_STATE_READ_INDEX: {
      size_t prefixlen;

      if(inflater->opcode == NGHTTP2_HD_OPCODE_INDEXED) {
        prefixlen = 7;
      } else if(inflater->index_required) {
        prefixlen = 6;
      } else {
        prefixlen = 4;
      }

      rfin = 0;
      rv = hd_inflate_read_len(inflater, &rfin, in, last, prefixlen,
                               get_max_index(&inflater->ctx) + 1);
      if(rv < 0) {
        goto fail;
      }

      in += rv;

      if(!rfin) {
        goto almost_ok;
      }

      if(inflater->left == 0) {
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }

      DEBUGF(fprintf(stderr, "inflatehd: index=%zu\n", inflater->left));
      if(inflater->opcode == NGHTTP2_HD_OPCODE_INDEXED) {
        inflater->index = inflater->left;
        --inflater->index;

        rv = hd_inflate_commit_indexed(inflater, nv_out);
        if(rv < 0) {
          goto fail;
        }
        inflater->state = NGHTTP2_HD_STATE_OPCODE;
        /* If rv == 1, no header was emitted */
        if(rv == 0) {
          *inflate_flags |= NGHTTP2_HD_INFLATE_EMIT;
          return (ssize_t)(in - first);
        }
      } else {
        inflater->index = inflater->left;
        --inflater->index;

        inflater->state = NGHTTP2_HD_STATE_CHECK_VALUELEN;
      }
      break;
    }
    case NGHTTP2_HD_STATE_NEWNAME_CHECK_NAMELEN:
      hd_inflate_set_huffman_encoded(inflater, in);
      inflater->state = NGHTTP2_HD_STATE_NEWNAME_READ_NAMELEN;
      inflater->left = 0;
      inflater->shift = 0;
      DEBUGF(fprintf(stderr, "inflatehd: huffman encoded=%d\n",
                     inflater->huffman_encoded != 0));
      /* Fall through */
    case NGHTTP2_HD_STATE_NEWNAME_READ_NAMELEN:
      rfin = 0;
      rv = hd_inflate_read_len(inflater, &rfin, in, last, 7,
                               NGHTTP2_HD_MAX_NV);
      if(rv < 0) {
        goto fail;
      }
      in += rv;
      if(!rfin) {
        DEBUGF(fprintf(stderr,
                       "inflatehd: integer not fully decoded. current=%zu\n",
                       inflater->left));

        goto almost_ok;
      }

      if(inflater->huffman_encoded) {
        nghttp2_hd_huff_decode_context_init(&inflater->huff_decode_ctx);

        inflater->state = NGHTTP2_HD_STATE_NEWNAME_READ_NAMEHUFF;
      } else {
        inflater->state = NGHTTP2_HD_STATE_NEWNAME_READ_NAME;
      }
      break;
    case NGHTTP2_HD_STATE_NEWNAME_READ_NAMEHUFF:
      rv = hd_inflate_read_huff(inflater, &inflater->nvbufs, in, last);
      if(rv < 0) {
        goto fail;
      }

      in += rv;

      DEBUGF(fprintf(stderr, "inflatehd: %zd bytes read\n", rv));

      if(inflater->left) {
        DEBUGF(fprintf(stderr,
                       "inflatehd: still %zu bytes to go\n", inflater->left));

        goto almost_ok;
      }

      inflater->newnamelen = nghttp2_bufs_len(&inflater->nvbufs);

      inflater->state = NGHTTP2_HD_STATE_CHECK_VALUELEN;

      break;
    case NGHTTP2_HD_STATE_NEWNAME_READ_NAME:
      rv = hd_inflate_read(inflater, &inflater->nvbufs, in, last);
      if(rv < 0) {
        goto fail;
      }

      in += rv;

      DEBUGF(fprintf(stderr, "inflatehd: %zd bytes read\n", rv));
      if(inflater->left) {
        DEBUGF(fprintf(stderr,
                       "inflatehd: still %zu bytes to go\n", inflater->left));

        goto almost_ok;
      }

      inflater->newnamelen = nghttp2_bufs_len(&inflater->nvbufs);

      inflater->state = NGHTTP2_HD_STATE_CHECK_VALUELEN;

      break;
    case NGHTTP2_HD_STATE_CHECK_VALUELEN:
      hd_inflate_set_huffman_encoded(inflater, in);
      inflater->state = NGHTTP2_HD_STATE_READ_VALUELEN;
      inflater->left = 0;
      inflater->shift = 0;
      DEBUGF(fprintf(stderr, "inflatehd: huffman encoded=%d\n",
                     inflater->huffman_encoded != 0));
      /* Fall through */
    case NGHTTP2_HD_STATE_READ_VALUELEN:
      rfin = 0;
      rv = hd_inflate_read_len(inflater, &rfin, in, last, 7,
                               NGHTTP2_HD_MAX_NV);
      if(rv < 0) {
        goto fail;
      }

      in += rv;

      if(!rfin) {
        goto almost_ok;
      }

      DEBUGF(fprintf(stderr, "inflatehd: valuelen=%zu\n", inflater->left));
      if(inflater->left == 0) {
        if(inflater->opcode == NGHTTP2_HD_OPCODE_NEWNAME) {
          rv = hd_inflate_commit_newname(inflater, nv_out);
        } else {
          rv = hd_inflate_commit_indname(inflater, nv_out);
        }
        if(rv != 0) {
          goto fail;
        }
        inflater->state = NGHTTP2_HD_STATE_OPCODE;
        *inflate_flags |= NGHTTP2_HD_INFLATE_EMIT;
        return (ssize_t)(in - first);
      }

      if(inflater->huffman_encoded) {
        nghttp2_hd_huff_decode_context_init(&inflater->huff_decode_ctx);

        inflater->state = NGHTTP2_HD_STATE_READ_VALUEHUFF;
      } else {
        inflater->state = NGHTTP2_HD_STATE_READ_VALUE;
      }
      break;
    case NGHTTP2_HD_STATE_READ_VALUEHUFF:
      rv = hd_inflate_read_huff(inflater, &inflater->nvbufs, in, last);
      if(rv < 0) {
        goto fail;
      }

      in += rv;

      DEBUGF(fprintf(stderr, "inflatehd: %zd bytes read\n", rv));

      if(inflater->left) {
        DEBUGF(fprintf(stderr,
                       "inflatehd: still %zu bytes to go\n", inflater->left));

        goto almost_ok;
      }

      if(inflater->opcode == NGHTTP2_HD_OPCODE_NEWNAME) {
        rv = hd_inflate_commit_newname(inflater, nv_out);
      } else {
        rv = hd_inflate_commit_indname(inflater, nv_out);
      }

      if(rv != 0) {
        goto fail;
      }

      inflater->state = NGHTTP2_HD_STATE_OPCODE;
      *inflate_flags |= NGHTTP2_HD_INFLATE_EMIT;

      return (ssize_t)(in - first);
    case NGHTTP2_HD_STATE_READ_VALUE:
      rv = hd_inflate_read(inflater, &inflater->nvbufs, in, last);
      if(rv < 0) {
        DEBUGF(fprintf(stderr, "inflatehd: value read failure %zd: %s\n",
                       rv, nghttp2_strerror((int)rv)));
        goto fail;
      }

      in += rv;

      DEBUGF(fprintf(stderr, "inflatehd: %zd bytes read\n", rv));

      if(inflater->left) {
        DEBUGF(fprintf(stderr,
                       "inflatehd: still %zu bytes to go\n", inflater->left));
        goto almost_ok;
      }

      if(inflater->opcode == NGHTTP2_HD_OPCODE_NEWNAME) {
        rv = hd_inflate_commit_newname(inflater, nv_out);
      } else {
        rv = hd_inflate_commit_indname(inflater, nv_out);
      }

      if(rv != 0) {
        goto fail;
      }

      inflater->state = NGHTTP2_HD_STATE_OPCODE;
      *inflate_flags |= NGHTTP2_HD_INFLATE_EMIT;

      return (ssize_t)(in - first);
    }
  }

  assert(in == last);

  DEBUGF(fprintf(stderr, "inflatehd: all input bytes were processed\n"));

  if(in_final) {
    DEBUGF(fprintf(stderr, "inflatehd: in_final set\n"));

    if(inflater->state != NGHTTP2_HD_STATE_OPCODE) {
      DEBUGF(fprintf(stderr, "inflatehd: unacceptable state=%d\n",
                     inflater->state));
      rv = NGHTTP2_ERR_HEADER_COMP;

      goto fail;
    }
    *inflate_flags |= NGHTTP2_HD_INFLATE_FINAL;
  }
  return (ssize_t)(in - first);

 almost_ok:
  if(in_final && inflater->state != NGHTTP2_HD_STATE_OPCODE) {
    DEBUGF(fprintf(stderr, "inflatehd: input ended prematurely\n"));

    rv = NGHTTP2_ERR_HEADER_COMP;

    goto fail;
  }
  return (ssize_t)(in - first);

 fail:
  DEBUGF(fprintf(stderr, "inflatehd: error return %zd\n", rv));

  inflater->ctx.bad = 1;
  return rv;
}

int nghttp2_hd_inflate_end_headers(nghttp2_hd_inflater *inflater)
{
  hd_inflate_keep_free(inflater);
  return 0;
}

int nghttp2_hd_inflate_new(nghttp2_hd_inflater **inflater_ptr)
{
  int rv;
  nghttp2_hd_inflater *inflater;

  inflater = (nghttp2_hd_inflater *)malloc(sizeof(nghttp2_hd_inflater));

  if(inflater == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  rv = nghttp2_hd_inflate_init(inflater);

  if(rv != 0) {
    free(inflater);

    return rv;
  }

  *inflater_ptr = inflater;

  return 0;
}

void nghttp2_hd_inflate_del(nghttp2_hd_inflater *inflater)
{
  nghttp2_hd_inflate_free(inflater);

  free(inflater);
}

int nghttp2_hd_emit_indname_block(nghttp2_bufs *bufs, size_t idx,
                                  nghttp2_nv *nv, int inc_indexing)
{

  return emit_indname_block(bufs, idx, nv, inc_indexing);
}

int nghttp2_hd_emit_newname_block(nghttp2_bufs *bufs, nghttp2_nv *nv,
                                  int inc_indexing)
{
  return emit_newname_block(bufs, nv, inc_indexing);
}

int nghttp2_hd_emit_table_size(nghttp2_bufs *bufs, size_t table_size)
{
  return emit_table_size(bufs, table_size);
}

ssize_t nghttp2_hd_decode_length(uint32_t *res, size_t *shift_ptr, int *final,
                                 uint32_t initial, size_t shift,
                                 uint8_t *in, uint8_t *last, size_t prefix)
{
  return decode_length(res, shift_ptr, final, initial, shift, in, last,
                       prefix);
}
