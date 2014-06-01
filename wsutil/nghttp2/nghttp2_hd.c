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
  MAKE_STATIC_ENT(15, "accept-encoding", "", 4127597688u, 0u),
};

/* Index to the position in static_table */
const size_t static_table_index[] = {
  38, 43, 44, 10, 11, 47, 48, 49, 50, 51, 52, 53, 54, 55, 14, 60,
  20, 26, 34, 46, 0 , 12, 36, 59, 41, 31, 42, 45, 32, 35, 19, 37,
  2 , 3 , 40, 39, 4 , 5 , 8 , 33, 18, 9 , 27, 15, 6 , 29, 28, 57,
  16, 13, 21, 22, 30, 56, 24, 23, 25, 17, 7 , 1 , 58
};

static const size_t STATIC_TABLE_LENGTH =
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

typedef struct {
  nghttp2_nv *nva;
  size_t nvacap;
  size_t nvlen;
} nghttp2_nva_out;

int nghttp2_hd_entry_init(nghttp2_hd_entry *ent, uint8_t flags,
                          uint8_t *name, size_t namelen,
                          uint8_t *value, size_t valuelen)
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
  if(ent->nv.name) {
    ent->name_hash = hash(ent->nv.name, ent->nv.namelen);
  } else {
    ent->name_hash = 0;
  }
  if(ent->nv.value) {
    ent->value_hash = hash(ent->nv.value, ent->nv.valuelen);
  } else {
    ent->value_hash = 0;
  }
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
  ringbuf->buffer = (nghttp2_hd_entry **)malloc(sizeof(nghttp2_hd_entry*)*size);
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

static size_t hd_ringbuf_push_front(nghttp2_hd_ringbuf *ringbuf,
                                    nghttp2_hd_entry *ent)
{
  assert(ringbuf->len <= ringbuf->mask);
  ringbuf->buffer[--ringbuf->first & ringbuf->mask] = ent;
  ++ringbuf->len;
  return 0;
}

static void hd_ringbuf_pop_back(nghttp2_hd_ringbuf *ringbuf)
{
  assert(ringbuf->len > 0);
  --ringbuf->len;
}

static int hd_context_init(nghttp2_hd_context *context,
                           nghttp2_hd_role role)
{
  int rv;
  context->role = role;
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
  rv =  hd_context_init(&deflater->ctx, NGHTTP2_HD_ROLE_DEFLATE);
  if(rv != 0) {
    return rv;
  }
  deflater->no_refset = 0;

  if(deflate_hd_table_bufsize_max < NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE) {
    deflater->notify_table_size_change = 1;
    deflater->ctx.hd_table_bufsize_max = deflate_hd_table_bufsize_max;
  } else {
    deflater->notify_table_size_change = 0;
  }

  deflater->deflate_hd_table_bufsize_max = deflate_hd_table_bufsize_max;

  return 0;
}

int nghttp2_hd_inflate_init(nghttp2_hd_inflater *inflater)
{
  int rv;

  rv = hd_context_init(&inflater->ctx, NGHTTP2_HD_ROLE_INFLATE);
  if(rv != 0) {
    goto fail;
  }

  inflater->settings_hd_table_bufsize_max =
    NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE;

  inflater->ent_keep = NULL;
  inflater->nv_keep = NULL;
  inflater->end_headers_index = 0;

  inflater->opcode = NGHTTP2_HD_OPCODE_NONE;
  inflater->state = NGHTTP2_HD_STATE_OPCODE;

  rv = nghttp2_bufs_init(&inflater->nvbufs, NGHTTP2_HD_MAX_NV / 2, 2);

  if(rv != 0) {
    goto nvbufs_fail;
  }

  inflater->huffman_encoded = 0;
  inflater->index = 0;
  inflater->left = 0;
  inflater->newnamelen = 0;
  inflater->index_required = 0;
  inflater->no_index = 0;
  inflater->ent_name = NULL;

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

void nghttp2_hd_deflate_set_no_refset(nghttp2_hd_deflater *deflater,
                                      uint8_t no_refset)
{
  deflater->no_refset = no_refset;
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
  /* ent->ref may be 0. This happens if the careless stupid encoder
     emits literal block larger than header table capacity with
     indexing. */
  ent->flags |= NGHTTP2_HD_FLAG_EMIT;
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

static size_t count_encoded_length(size_t n, int prefix)
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

static size_t encode_length(uint8_t *buf, size_t n, int prefix)
{
  size_t k = (1 << prefix) - 1;
  size_t len = 0;
  *buf &= ~k;
  if(n >= k) {
    *buf++ |= k;
    n -= k;
    ++len;
  } else {
    *buf++ |= n;
    return 1;
  }
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
 * Decodes |prefx| prefixed integer stored from |in|. The |last|
 * represents the 1 beyond the last of the valid contiguous memory
 * region from |in|. The decoded integer must be strictly less than 1
 * << 16.
 *
 * If the |initial| is nonzero, it is used as a initial value, this
 * function assumes the |in| starts with intermediate data.
 *
 * An entire integer is decoded successfully, decoded, the |*final| is
 * set to nonzero.
 *
 * This function returns the next byte of read byte. This function
 * stores the decoded integer in |*res| if it succeed, including
 * partial decoding, or stores -1 in |*res|, indicating decoding
 * error.
 */
static  uint8_t* decode_length(ssize_t *res, int *final, ssize_t initial,
                               uint8_t *in, uint8_t *last, int prefix)
{
  int k = (1 << prefix) - 1, r;
  ssize_t n = initial;
  *final = 0;
  if(n == 0) {
    if((*in & k) == k) {
      n = k;
    } else {
      *res = (*in) & k;
      *final = 1;
      return in + 1;
    }
    if(++in == last) {
      *res = n;
      return in;
    }
  }
  for(r = 0; in != last; ++in, r += 7) {
    n += (*in & 0x7f) << r;
    if(n >= (1 << 16)) {
      *res = -1;
      return in + 1;
    }
    if((*in & (1 << 7)) == 0) {
      break;
    }
  }
  if(in == last) {
    *res = n;
    return in;
  }
  if(*in & (1 << 7)) {
    *res = -1;
    return in + 1;
  }
  *res = n;
  *final = 1;
  return in + 1;
}

static int emit_clear_refset(nghttp2_bufs *bufs)
{
  int rv;

  DEBUGF(fprintf(stderr, "deflatehd: emit clear refset\n"));

  rv = nghttp2_bufs_addb(bufs, 0x30u);
  if(rv != 0) {
    return rv;
  }

  return 0;
}

static int emit_table_size(nghttp2_bufs *bufs, size_t table_size)
{
  int rv;
  uint8_t *bufp;
  size_t blocklen;
  uint8_t sb[16];

  DEBUGF(fprintf(stderr, "deflatehd: emit table_size=%zu\n", table_size));

  blocklen = count_encoded_length(table_size, 4);

  if(sizeof(sb) < blocklen) {
    return NGHTTP2_ERR_HEADER_COMP;
  }

  bufp = sb;

  *bufp = 0x20u;

  encode_length(bufp, table_size, 4);

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

static int emit_string(nghttp2_bufs *bufs,
                       size_t enclen, int huffman,
                       const uint8_t *str, size_t len)
{
  size_t rv;
  uint8_t sb[16];
  uint8_t *bufp;
  size_t blocklen;

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
    return (int)rv;
  }

  if(huffman) {
    rv = nghttp2_hd_huff_encode(bufs, str, len);
  } else {
    assert(enclen == len);
    rv = nghttp2_bufs_add(bufs, str, len);
  }

  return (int)rv;
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
                              nghttp2_nv *nv,
                              int inc_indexing)
{
  int rv;
  uint8_t *bufp;
  size_t encvallen;
  size_t blocklen;
  int huffman;
  uint8_t sb[16];
  int prefixlen;
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

  encvallen = nghttp2_hd_huff_encode_count(nv->value, nv->valuelen);
  blocklen = count_encoded_length(idx + 1, prefixlen);
  huffman = encvallen < nv->valuelen;

  if(!huffman) {
    encvallen = nv->valuelen;
  }

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

  rv = emit_string(bufs, encvallen, huffman, nv->value, nv->valuelen);
  if(rv != 0) {
    return rv;
  }

  return 0;
}

static int emit_newname_block(nghttp2_bufs *bufs, nghttp2_nv *nv,
                              int inc_indexing)
{
  int rv;
  size_t encnamelen;
  size_t encvallen;
  int name_huffman;
  int value_huffman;
  int no_index;

  no_index = (nv->flags & NGHTTP2_NV_FLAG_NO_INDEX) != 0;

  DEBUGF(fprintf(stderr,
                 "deflatehd: emit newname namelen=%zu, valuelen=%zu, "
                 "indexing=%d, no_index=%d\n",
                 nv->namelen, nv->valuelen, inc_indexing, no_index));

  encnamelen = nghttp2_hd_huff_encode_count(nv->name, nv->namelen);
  encvallen = nghttp2_hd_huff_encode_count(nv->value, nv->valuelen);
  name_huffman = encnamelen < nv->namelen;
  value_huffman = encvallen < nv->valuelen;

  if(!name_huffman) {
    encnamelen = nv->namelen;
  }
  if(!value_huffman) {
    encvallen = nv->valuelen;
  }

  rv = nghttp2_bufs_addb(bufs, pack_first_byte(inc_indexing, no_index));
  if(rv != 0) {
    return rv;
  }

  rv = emit_string(bufs, encnamelen, name_huffman, nv->name, nv->namelen);
  if(rv != 0) {
    return rv;
  }

  rv = emit_string(bufs, encvallen, value_huffman, nv->value, nv->valuelen);
  if(rv != 0) {
    return rv;
  }

  return 0;
}

/*
 * Emit common header with |index| by toggle off and on (thus 2
 * indexed representation emissions).
 */
static int emit_implicit(nghttp2_bufs *bufs, size_t idx)
{
  int i, rv;

  for(i = 0; i < 2; ++i) {
    rv = emit_indexed_block(bufs, idx);
    if(rv != 0) {
      return rv;
    }
  }
  return 0;
}

static nghttp2_hd_entry* add_hd_table_incremental(nghttp2_hd_context *context,
                                                  nghttp2_bufs *bufs,
                                                  nghttp2_nv *nv,
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
    if(context->role == NGHTTP2_HD_ROLE_DEFLATE) {
      if(ent->flags & NGHTTP2_HD_FLAG_IMPLICIT_EMIT) {
        /* Emit common header just before it slips away from the
           table. If we don't do this, we have to emit it in literal
           representation which hurts compression. */
        rv = emit_implicit(bufs, idx);
        if(rv != 0) {
          return NULL;
        }
      }
    }
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
                             nv->name, nv->namelen, nv->value, nv->valuelen);
  if(rv != 0) {
    free(new_ent);
    return NULL;
  }

  if(room > context->hd_table_bufsize_max) {
    /* The entry taking more than NGHTTP2_HD_MAX_BUFFER_SIZE is
       immediately evicted. */
    --new_ent->ref;
  } else {
    context->hd_table_bufsize += room;
    hd_ringbuf_push_front(&context->hd_table, new_ent);

    new_ent->flags |= NGHTTP2_HD_FLAG_REFSET;
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
                                     nghttp2_nv *nv)
{
  search_result res = { -1, 0 };
  size_t i;
  uint32_t name_hash = hash(nv->name, nv->namelen);
  uint32_t value_hash = hash(nv->value, nv->valuelen);
  ssize_t left = -1, right = (ssize_t)STATIC_TABLE_LENGTH;
  int use_index = (nv->flags & NGHTTP2_NV_FLAG_NO_INDEX) == 0;

  if(use_index) {
    for(i = 0; i < context->hd_table.len; ++i) {
      nghttp2_hd_entry *ent = hd_ringbuf_get(&context->hd_table, i);
      if(ent->name_hash == name_hash && name_eq(&ent->nv, nv)) {
        if(res.index == -1) {
          res.index = (ssize_t)i;
        }
        if(ent->value_hash == value_hash && value_eq(&ent->nv, nv)) {
          res.index = (ssize_t)i;
          res.name_value_match = 1;
          return res;
        }
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
        res.index = (ssize_t)(context->hd_table.len + static_table[i].index);
      }
      if(use_index &&
         ent->value_hash == value_hash && value_eq(&ent->nv, nv)) {
        res.index = (ssize_t)(context->hd_table.len + static_table[i].index);
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
  int rv;
  size_t next_bufsize = nghttp2_min(settings_hd_table_bufsize_max,
                                    deflater->deflate_hd_table_bufsize_max);
  rv = hd_ringbuf_reserve
    (&deflater->ctx.hd_table, next_bufsize / NGHTTP2_HD_ENTRY_OVERHEAD);
  if(rv != 0) {
    return rv;
  }

  deflater->ctx.hd_table_bufsize_max = next_bufsize;

  deflater->notify_table_size_change = 1;

  hd_context_shrink_table_size(&deflater->ctx);
  return 0;
}

int nghttp2_hd_inflate_change_table_size(nghttp2_hd_inflater *inflater,
                                         size_t settings_hd_table_bufsize_max)
{
  int rv;

  rv = hd_ringbuf_reserve
    (&inflater->ctx.hd_table,
     settings_hd_table_bufsize_max / NGHTTP2_HD_ENTRY_OVERHEAD);
  if(rv != 0) {
    return rv;
  }
  inflater->settings_hd_table_bufsize_max = settings_hd_table_bufsize_max;
  inflater->ctx.hd_table_bufsize_max = settings_hd_table_bufsize_max;
  hd_context_shrink_table_size(&inflater->ctx);
  return 0;
}

static void clear_refset(nghttp2_hd_context *context)
{
  size_t i;
  for(i = 0; i < context->hd_table.len; ++i) {
    nghttp2_hd_entry *ent = hd_ringbuf_get(&context->hd_table, i);
    ent->flags &= ~NGHTTP2_HD_FLAG_REFSET;
  }
}

#define INDEX_RANGE_VALID(context, idx) \
  ((idx) < (context)->hd_table.len + STATIC_TABLE_LENGTH)

static int get_max_index(nghttp2_hd_context *context)
{
  return (int)(context->hd_table.len + STATIC_TABLE_LENGTH - 1);
}

nghttp2_hd_entry* nghttp2_hd_table_get(nghttp2_hd_context *context,
                                       size_t idx)
{
  assert(INDEX_RANGE_VALID(context, idx));
  if(idx < context->hd_table.len) {
    return hd_ringbuf_get(&context->hd_table, idx);
  } else {
    return
      &static_table[static_table_index[idx - context->hd_table.len]].ent;
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
    !name_match(nv, "set-cookie") &&
    !name_match(nv, "content-length") &&
    !name_match(nv, "location") &&
    !name_match(nv, "etag") &&
    !name_match(nv, ":path");
#endif /* !NGHTTP2_XHD */
}

static int deflate_nv(nghttp2_hd_deflater *deflater,
                      nghttp2_bufs *bufs, nghttp2_nv *nv)
{
  int rv;
  nghttp2_hd_entry *ent;
  search_result res;

  DEBUGF(fprintf(stderr, "deflatehd: deflating "));
  DEBUGF(fwrite(nv->name, nv->namelen, 1, stderr));
  DEBUGF(fprintf(stderr, ": "));
  DEBUGF(fwrite(nv->value, nv->valuelen, 1, stderr));
  DEBUGF(fprintf(stderr, "\n"));

  res = search_hd_table(&deflater->ctx, nv);

  if(res.index != -1 && res.name_value_match) {
    size_t idx = res.index;

    DEBUGF(fprintf(stderr, "deflatehd: name/value match index=%zd\n",
                   res.index));

    ent = nghttp2_hd_table_get(&deflater->ctx, idx);
    if(idx >= deflater->ctx.hd_table.len) {
      nghttp2_hd_entry *new_ent;

      /* It is important to first add entry to the header table and
         let eviction go. If NGHTTP2_HD_FLAG_IMPLICIT_EMIT entry is
         evicted, it must be emitted before the |nv|. */
      new_ent = add_hd_table_incremental(&deflater->ctx, bufs, &ent->nv,
                                         NGHTTP2_HD_FLAG_NONE);
      if(!new_ent) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      if(new_ent->ref == 0) {
        nghttp2_hd_entry_free(new_ent);
        free(new_ent);
        new_ent = NULL;
      } else {
        /* new_ent->ref > 0 means that new_ent is in the reference
           set */
        new_ent->flags |= NGHTTP2_HD_FLAG_EMIT;
      }
      rv = emit_indexed_block(bufs, idx);
      if(rv != 0) {
        return rv;
      }
    } else if((ent->flags & NGHTTP2_HD_FLAG_REFSET) == 0) {
      ent->flags |= NGHTTP2_HD_FLAG_REFSET | NGHTTP2_HD_FLAG_EMIT;
      rv = emit_indexed_block(bufs, idx);
      if(rv != 0) {
        return rv;
      }
    } else {
      int num_emits = 0;
      if(ent->flags & NGHTTP2_HD_FLAG_EMIT) {
        /* occurrences of the same indexed representation. Emit index
           twice. */
        num_emits = 2;
      } else if(ent->flags & NGHTTP2_HD_FLAG_IMPLICIT_EMIT) {
        /* ent was implicitly emitted because it is the common
           header field. To support occurrences of the same indexed
           representation, we have to emit 4 times. This is because
           "implicitly emitted" means actually not emitted at
           all. So first 2 emits performs 1st header appears in the
           reference set. And another 2 emits are done for 2nd
           (current) header. */
        ent->flags ^= NGHTTP2_HD_FLAG_IMPLICIT_EMIT;
        ent->flags |= NGHTTP2_HD_FLAG_EMIT;
        num_emits = 4;
      } else {
        /* This is common header and not emitted in the current
           run. Just mark IMPLICIT_EMIT, in the hope that we are not
           required to emit anything for this. We will emit toggle
           off/on for this entry if it is removed from the header
           table. */
        ent->flags |= NGHTTP2_HD_FLAG_IMPLICIT_EMIT;
      }
      for(; num_emits > 0; --num_emits) {
        rv = emit_indexed_block(bufs, idx);
        if(rv != 0) {
          return rv;
        }
      }
    }
  } else {
    ssize_t idx = -1;
    int incidx = 0;
    if(res.index != -1) {
      DEBUGF(fprintf(stderr, "deflatehd: name match index=%zd\n",
                     res.index));

      idx = res.index;
    }
    if(hd_deflate_should_indexing(deflater, nv)) {
      nghttp2_hd_entry *new_ent;
      if(idx >= (ssize_t)deflater->ctx.hd_table.len) {
        nghttp2_nv nv_indname;
        nv_indname = *nv;
        nv_indname.name = nghttp2_hd_table_get(&deflater->ctx, idx)->nv.name;
        new_ent = add_hd_table_incremental(&deflater->ctx, bufs, &nv_indname,
                                           NGHTTP2_HD_FLAG_VALUE_ALLOC);
      } else {
        new_ent = add_hd_table_incremental(&deflater->ctx, bufs, nv,
                                           NGHTTP2_HD_FLAG_NAME_ALLOC |
                                           NGHTTP2_HD_FLAG_VALUE_ALLOC);
      }
      if(!new_ent) {
        return NGHTTP2_ERR_HEADER_COMP;
      }
      if(new_ent->ref == 0) {
        nghttp2_hd_entry_free(new_ent);
        free(new_ent);
      } else {
        /* new_ent->ref > 0 means that new_ent is in the reference
           set. */
        new_ent->flags |= NGHTTP2_HD_FLAG_EMIT;
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
  }
  return 0;
}

static int deflate_post_process_hd_entry(nghttp2_hd_entry *ent,
                                         size_t idx,
                                         nghttp2_bufs *bufs)
{
  int rv;

  if((ent->flags & NGHTTP2_HD_FLAG_REFSET) &&
     (ent->flags & NGHTTP2_HD_FLAG_IMPLICIT_EMIT) == 0 &&
     (ent->flags & NGHTTP2_HD_FLAG_EMIT) == 0) {
    /* This entry is not present in the current header set and must
       be removed. */
    ent->flags ^= NGHTTP2_HD_FLAG_REFSET;

    rv = emit_indexed_block(bufs, idx);
    if(rv != 0) {
      return rv;
    }
  }

  ent->flags &= ~(NGHTTP2_HD_FLAG_EMIT | NGHTTP2_HD_FLAG_IMPLICIT_EMIT);

  return 0;
}

int nghttp2_hd_deflate_hd_bufs(nghttp2_hd_deflater *deflater,
                               nghttp2_bufs *bufs,
                               nghttp2_nv *nv, size_t nvlen)
{
  size_t i;
  int rv = 0;

  if(deflater->ctx.bad) {
    return NGHTTP2_ERR_HEADER_COMP;
  }

  if(deflater->notify_table_size_change) {

    deflater->notify_table_size_change = 0;

    rv = emit_table_size(bufs, deflater->ctx.hd_table_bufsize_max);

    if(rv != 0) {
      goto fail;
    }
  }

  if(deflater->no_refset) {
    rv = emit_clear_refset(bufs);
    if(rv != 0) {
      goto fail;
    }
    clear_refset(&deflater->ctx);
  }
  for(i = 0; i < nvlen; ++i) {
    rv = deflate_nv(deflater, bufs, &nv[i]);
    if(rv != 0) {
      goto fail;
    }
  }

  DEBUGF(fprintf(stderr,
                 "deflatehd: all input name/value pairs were deflated\n"));

  for(i = 0; i < deflater->ctx.hd_table.len; ++i) {
    nghttp2_hd_entry *ent = hd_ringbuf_get(&deflater->ctx.hd_table, i);

    rv = deflate_post_process_hd_entry(ent, i, bufs);
    if(rv != 0) {
      goto fail;
    }
  }

  return 0;
 fail:
  DEBUGF(fprintf(stderr, "deflatehd: error return %d\n", rv));

  deflater->ctx.bad = 1;
  return rv;
}

ssize_t nghttp2_hd_deflate_hd(nghttp2_hd_deflater *deflater,
                              uint8_t *buf, size_t buflen,
                              nghttp2_nv *nv, size_t nvlen)
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

size_t nghttp2_hd_deflate_bound(nghttp2_hd_deflater *deflater,
                                const nghttp2_nv *nva, size_t nvlen)
{
  size_t n;
  size_t i;

  /* Possible Reference Set Emptying */
  n = 1;

  /* Possible Maximum Header Table Size Change.  Encoding (1u << 31) -
     1 using 4 bit prefix requires 6 bytes. */
  n += 6;

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

  /* Add possible reference set toggle off */
  n += deflater->ctx.hd_table.len;

  return n;
}

int nghttp2_hd_deflate_new(nghttp2_hd_deflater **deflater_ptr,
                           size_t deflate_hd_table_bufsize_max)
{
  *deflater_ptr = (nghttp2_hd_deflater *)malloc(sizeof(nghttp2_hd_deflater));

  if(*deflater_ptr == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  return nghttp2_hd_deflate_init2(*deflater_ptr, deflate_hd_table_bufsize_max);
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
                                   int prefix, size_t maxlen)
{
  uint8_t *nin;
  *rfin = 0;
  nin = decode_length(&inflater->left, rfin, inflater->left, in, last, prefix);
  if(inflater->left == -1) {
    DEBUGF(fprintf(stderr, "inflatehd: invalid integer\n"));
    return NGHTTP2_ERR_HEADER_COMP;
  }
  if((size_t)inflater->left > maxlen) {
    DEBUGF(fprintf(stderr,
                   "inflatehd: integer exceeded the maximum value %zu\n",
                   maxlen));
    return NGHTTP2_ERR_HEADER_COMP;
  }
  return(ssize_t) (nin - in);
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
  int rv;
  int final = 0;
  if(last - in >= inflater->left) {
    last = in + inflater->left;
    final = 1;
  }
  rv = (int)nghttp2_hd_huff_decode(&inflater->huff_decode_ctx, bufs,
                              in, last - in, final);

  if(rv < 0) {
    DEBUGF(fprintf(stderr, "inflatehd: huffman decoding failed\n"));
    return rv;
  }
  inflater->left -= rv;
  return rv;
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
  ssize_t len = (ssize_t)nghttp2_min(last - in, inflater->left);
  rv = nghttp2_bufs_add(bufs, in, len);
  if(rv != 0) {
    return rv;
  }
  inflater->left -= len;
  return len;
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
  if(inflater->index >= inflater->ctx.hd_table.len) {
    nghttp2_hd_entry *new_ent;
    new_ent = add_hd_table_incremental(&inflater->ctx, NULL, &ent->nv,
                                       NGHTTP2_HD_FLAG_NONE);
    if(!new_ent) {
      return NGHTTP2_ERR_NOMEM;
    }
    /* new_ent->ref == 0 may be hold */
    emit_indexed_header(nv_out, new_ent);
    inflater->ent_keep = new_ent;
    return 0;
  }
  ent->flags ^= NGHTTP2_HD_FLAG_REFSET;
  if(ent->flags & NGHTTP2_HD_FLAG_REFSET) {
    emit_indexed_header(nv_out, ent);
    return 0;
  }
  DEBUGF(fprintf(stderr, "inflatehd: toggle off item: "));
  DEBUGF(fwrite(ent->nv.name, ent->nv.namelen, 1, stderr));
  DEBUGF(fprintf(stderr, ": "));
  DEBUGF(fwrite(ent->nv.value, ent->nv.valuelen, 1, stderr));
  DEBUGF(fprintf(stderr, "\n"));
  return 1;
}

static int hd_inflate_remove_bufs(nghttp2_hd_inflater *inflater,
                                  nghttp2_nv *nv, int value_only)
{
  ssize_t rv;
  size_t buflen;
  uint8_t *buf;

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

    new_ent = add_hd_table_incremental(&inflater->ctx, NULL, &nv, ent_flags);

    if(new_ent) {
      emit_indexed_header(nv_out, new_ent);
      inflater->ent_keep = new_ent;

      return 0;
    }

    free(nv.name);

    return NGHTTP2_ERR_NOMEM;
  }

  emit_literal_header(nv_out, &nv);

  inflater->nv_keep = nv.name;

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

  rv = hd_inflate_remove_bufs(inflater, &nv, 1 /* value only */);
  if(rv != 0) {
    return NGHTTP2_ERR_NOMEM;
  }

  if(inflater->no_index) {
    nv.flags = NGHTTP2_NV_FLAG_NO_INDEX;
  } else {
    nv.flags = NGHTTP2_NV_FLAG_NONE;
  }

  nv.name = inflater->ent_name->nv.name;
  nv.namelen = inflater->ent_name->nv.namelen;

  if(inflater->index_required) {
    nghttp2_hd_entry *new_ent;
    uint8_t ent_flags;
    int static_name;

    ent_flags = NGHTTP2_HD_FLAG_VALUE_ALLOC | NGHTTP2_HD_FLAG_VALUE_GIFT;
    static_name = inflater->index >= inflater->ctx.hd_table.len;

    if(!static_name) {
      ent_flags |= NGHTTP2_HD_FLAG_NAME_ALLOC;
      /* For entry in static table, we must not touch ref, because it
         is shared by threads */
      ++inflater->ent_name->ref;
    }

    new_ent = add_hd_table_incremental(&inflater->ctx, NULL, &nv, ent_flags);

    if(!static_name && --inflater->ent_name->ref == 0) {
      nghttp2_hd_entry_free(inflater->ent_name);
      free(inflater->ent_name);
    }

    inflater->ent_name = NULL;

    if(new_ent) {
      emit_indexed_header(nv_out, new_ent);

      inflater->ent_keep = new_ent;

      return 0;
    }

    free(nv.value);

    return NGHTTP2_ERR_NOMEM;
  }

  emit_literal_header(nv_out, &nv);

  inflater->nv_keep = nv.value;

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
      if((*in & 0xf0u) == 0x20u) {
        DEBUGF(fprintf(stderr, "inflatehd: header table size change\n"));
        inflater->opcode = NGHTTP2_HD_OPCODE_INDEXED;
        inflater->state = NGHTTP2_HD_STATE_READ_TABLE_SIZE;
      } else if((*in & 0xf0u) == 0x30u) {
        if(*in != 0x30u) {
          rv = NGHTTP2_ERR_HEADER_COMP;
          goto fail;
        }

        DEBUGF(fprintf(stderr, "inflatehd: clearing reference set\n"));
        inflater->opcode = NGHTTP2_HD_OPCODE_INDEXED;
        inflater->state = NGHTTP2_HD_STATE_CLEAR_REFSET;
        ++in;
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
        inflater->no_index = (*in & 0x10u) != 0;
        DEBUGF(fprintf(stderr,
                       "inflatehd: indexing required=%d, no_index=%d\n",
                       inflater->index_required,
                       inflater->no_index));
        if(inflater->opcode == NGHTTP2_HD_OPCODE_NEWNAME) {
          ++in;
        }
      }
      inflater->left = 0;
      break;
    case NGHTTP2_HD_STATE_CLEAR_REFSET:
      clear_refset(&inflater->ctx);
      inflater->state = NGHTTP2_HD_STATE_OPCODE;

      break;
    case NGHTTP2_HD_STATE_READ_TABLE_SIZE:
      rfin = 0;
      rv = hd_inflate_read_len(inflater, &rfin, in, last, 4,
                               inflater->settings_hd_table_bufsize_max);
      if(rv < 0) {
        goto fail;
      }
      in += rv;
      if(!rfin) {
        goto almost_ok;
      }
      DEBUGF(fprintf(stderr, "inflatehd: table_size=%zd\n", inflater->left));
      inflater->ctx.hd_table_bufsize_max = inflater->left;
      hd_context_shrink_table_size(&inflater->ctx);
      inflater->state = NGHTTP2_HD_STATE_OPCODE;
      break;
    case NGHTTP2_HD_STATE_READ_INDEX: {
      int prefixlen;

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

      if(inflater->left == 0) {
        rv = NGHTTP2_ERR_HEADER_COMP;
        goto fail;
      }

      if(!rfin) {
        goto almost_ok;
      }
      DEBUGF(fprintf(stderr, "inflatehd: index=%zd\n", inflater->left));
      if(inflater->opcode == NGHTTP2_HD_OPCODE_INDEXED) {
        inflater->index = inflater->left;
        assert(inflater->index > 0);
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
        assert(inflater->index > 0);
        --inflater->index;
        inflater->ent_name = nghttp2_hd_table_get(&inflater->ctx,
                                                  inflater->index);
        inflater->state = NGHTTP2_HD_STATE_CHECK_VALUELEN;
      }
      break;
    }
    case NGHTTP2_HD_STATE_NEWNAME_CHECK_NAMELEN:
      hd_inflate_set_huffman_encoded(inflater, in);
      inflater->state = NGHTTP2_HD_STATE_NEWNAME_READ_NAMELEN;
      inflater->left = 0;
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
                       "inflatehd: integer not fully decoded. current=%zd\n",
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
                       "inflatehd: still %zd bytes to go\n", inflater->left));

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
                       "inflatehd: still %zd bytes to go\n", inflater->left));

        goto almost_ok;
      }

      inflater->newnamelen = nghttp2_bufs_len(&inflater->nvbufs);

      inflater->state = NGHTTP2_HD_STATE_CHECK_VALUELEN;

      break;
    case NGHTTP2_HD_STATE_CHECK_VALUELEN:
      hd_inflate_set_huffman_encoded(inflater, in);
      inflater->state = NGHTTP2_HD_STATE_READ_VALUELEN;
      inflater->left = 0;
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

      DEBUGF(fprintf(stderr, "inflatehd: valuelen=%zd\n", inflater->left));
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
                       "inflatehd: still %zd bytes to go\n", inflater->left));

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
                       rv, nghttp2_strerror(rv)));
        goto fail;
      }

      in += rv;

      DEBUGF(fprintf(stderr, "inflatehd: %zd bytes read\n", rv));

      if(inflater->left) {
        DEBUGF(fprintf(stderr,
                       "inflatehd: still %zd bytes to go\n", inflater->left));
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
    for(; inflater->end_headers_index < inflater->ctx.hd_table.len;
        ++inflater->end_headers_index) {
      nghttp2_hd_entry *ent;
      ent = hd_ringbuf_get(&inflater->ctx.hd_table,
                           inflater->end_headers_index);

      if((ent->flags & NGHTTP2_HD_FLAG_REFSET) &&
         (ent->flags & NGHTTP2_HD_FLAG_EMIT) == 0) {
        emit_indexed_header(nv_out, ent);
        *inflate_flags |= NGHTTP2_HD_INFLATE_EMIT;
        return (ssize_t)(in - first);
      }
      ent->flags &= ~NGHTTP2_HD_FLAG_EMIT;
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
  inflater->end_headers_index = 0;
  return 0;
}

int nghttp2_hd_inflate_new(nghttp2_hd_inflater **inflater_ptr)
{
  *inflater_ptr = (nghttp2_hd_inflater *)malloc(sizeof(nghttp2_hd_inflater));

  if(*inflater_ptr == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  return nghttp2_hd_inflate_init(*inflater_ptr);
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
