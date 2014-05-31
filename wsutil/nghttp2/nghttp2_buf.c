/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
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
#include "nghttp2_buf.h"

#include <stdio.h>

#include "nghttp2_helper.h"

void nghttp2_buf_init(nghttp2_buf *buf)
{
  buf->begin = NULL;
  buf->end = NULL;
  buf->pos = NULL;
  buf->last = NULL;
  buf->mark = NULL;
}

int nghttp2_buf_init2(nghttp2_buf *buf, size_t initial)
{
  nghttp2_buf_init(buf);
  return nghttp2_buf_reserve(buf, initial);
}

void nghttp2_buf_free(nghttp2_buf *buf)
{
  free(buf->begin);
}

int nghttp2_buf_reserve(nghttp2_buf *buf, size_t new_cap)
{
  uint8_t *ptr;
  size_t cap;

  cap = nghttp2_buf_cap(buf);

  if(cap >= new_cap) {
    return 0;
  }

  new_cap = nghttp2_max(new_cap, cap * 2);

  ptr = (uint8_t *)realloc(buf->begin, new_cap);
  if(ptr == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  buf->pos = ptr + (buf->pos - buf->begin);
  buf->last = ptr + (buf->last - buf->begin);
  buf->mark = ptr + (buf->mark - buf->begin);
  buf->begin = ptr;
  buf->end = ptr + new_cap;

  return 0;
}

int nghttp2_buf_pos_reserve(nghttp2_buf *buf, size_t new_rel_cap)
{
  return nghttp2_buf_reserve(buf, nghttp2_buf_pos_offset(buf) + new_rel_cap);
}

int nghttp2_buf_last_reserve(nghttp2_buf *buf, size_t new_rel_cap)
{
  return nghttp2_buf_reserve(buf, nghttp2_buf_last_offset(buf) + new_rel_cap);
}

void nghttp2_buf_reset(nghttp2_buf *buf)
{
  buf->pos = buf->last = buf->mark = buf->begin;
}

void nghttp2_buf_wrap_init(nghttp2_buf *buf, uint8_t *begin, size_t len)
{
  buf->begin = buf->pos = buf->last = buf->mark = begin;
  buf->end = begin + len;
}

static int buf_chain_new(nghttp2_buf_chain **chain, size_t chunk_length)
{
  int rv;

  *chain = (nghttp2_buf_chain *)malloc(sizeof(nghttp2_buf_chain));
  if(*chain == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  (*chain)->next = NULL;

  rv = nghttp2_buf_init2(&(*chain)->buf, chunk_length);
  if(rv != 0) {
    free(*chain);
    return NGHTTP2_ERR_NOMEM;
  }

  return 0;
}

static void buf_chain_del(nghttp2_buf_chain *chain)
{
  nghttp2_buf_free(&chain->buf);
  free(chain);
}

int nghttp2_bufs_init(nghttp2_bufs *bufs, size_t chunk_length,
                      size_t max_chunk)
{
  return nghttp2_bufs_init2(bufs, chunk_length, max_chunk, 0);
}

int nghttp2_bufs_init2(nghttp2_bufs *bufs, size_t chunk_length,
                       size_t max_chunk, size_t offset)
{
  return nghttp2_bufs_init3(bufs, chunk_length, max_chunk, max_chunk, offset);
}

int nghttp2_bufs_init3(nghttp2_bufs *bufs, size_t chunk_length,
                       size_t max_chunk, size_t chunk_keep, size_t offset)
{
  int rv;
  nghttp2_buf_chain *chain;

  if(chunk_keep == 0 || max_chunk < chunk_keep || chunk_length < offset) {
    return NGHTTP2_ERR_INVALID_ARGUMENT;
  }

  rv = buf_chain_new(&chain, chunk_length);
  if(rv != 0) {
    return rv;
  }

  bufs->offset = offset;

  bufs->head = chain;
  bufs->cur = bufs->head;

  nghttp2_buf_shift_right(&bufs->cur->buf, offset);

  bufs->chunk_length = chunk_length;
  bufs->chunk_used = 1;
  bufs->max_chunk = max_chunk;
  bufs->chunk_keep = chunk_keep;

  return 0;
}

void nghttp2_bufs_free(nghttp2_bufs *bufs)
{
  nghttp2_buf_chain *chain, *next_chain;

  for(chain = bufs->head; chain;) {
    next_chain = chain->next;

    buf_chain_del(chain);

    chain = next_chain;
  }
}

int nghttp2_bufs_wrap_init(nghttp2_bufs *bufs, uint8_t *begin, size_t len)
{
  nghttp2_buf_chain *chain;

  chain = (nghttp2_buf_chain *)malloc(sizeof(nghttp2_buf_chain));
  if(chain == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  chain->next = NULL;

  nghttp2_buf_wrap_init(&chain->buf, begin, len);

  bufs->offset = 0;

  bufs->head = chain;
  bufs->cur = bufs->head;

  bufs->chunk_length = len;
  bufs->chunk_used = 1;
  bufs->max_chunk = 1;
  bufs->chunk_keep = 1;

  return 0;
}

void nghttp2_bufs_wrap_free(nghttp2_bufs *bufs)
{
  free(bufs->head);
}

void nghttp2_bufs_seek_last_present(nghttp2_bufs *bufs)
{
  nghttp2_buf_chain *ci;

  for(ci = bufs->cur; ci; ci = ci->next) {
    if(nghttp2_buf_len(&ci->buf) == 0) {
      return;
    } else {
      bufs->cur = ci;
    }
  }
}

ssize_t nghttp2_bufs_len(nghttp2_bufs *bufs)
{
  nghttp2_buf_chain *ci;
  ssize_t len;

  len = 0;
  for(ci = bufs->head; ci; ci = ci->next) {
    len += nghttp2_buf_len(&ci->buf);
  }

  return len;
}

static int bufs_avail(nghttp2_bufs *bufs)
{
  return (int)(nghttp2_buf_avail(&bufs->cur->buf) +
    (bufs->chunk_length - bufs->offset) * (bufs->max_chunk - bufs->chunk_used));
}

static int bufs_alloc_chain(nghttp2_bufs *bufs)
{
  int rv;
  nghttp2_buf_chain *chain;

  if(bufs->cur->next) {
    bufs->cur = bufs->cur->next;

    return 0;
  }

  if(bufs->max_chunk == bufs->chunk_used) {
    return NGHTTP2_ERR_BUFFER_ERROR;
  }

  rv = buf_chain_new(&chain, bufs->chunk_length);
  if(rv != 0) {
    return rv;
  }

  DEBUGF(fprintf(stderr,
                 "new buffer %zu bytes allocated for bufs %p, used %zu\n",
                 bufs->chunk_length, bufs, bufs->chunk_used));

  ++bufs->chunk_used;

  bufs->cur->next = chain;
  bufs->cur = chain;

  nghttp2_buf_shift_right(&bufs->cur->buf, bufs->offset);

  return 0;
}

int nghttp2_bufs_add(nghttp2_bufs *bufs, const void *data, size_t len)
{
  int rv;
  size_t nwrite;
  nghttp2_buf *buf;
  const uint8_t *p;

  if(bufs_avail(bufs) < (ssize_t)len) {
    return NGHTTP2_ERR_BUFFER_ERROR;
  }

  p = (const uint8_t *)data;

  while(len) {
    buf = &bufs->cur->buf;

    nwrite = nghttp2_min((size_t)nghttp2_buf_avail(buf), len);
    if(nwrite == 0) {
      rv = bufs_alloc_chain(bufs);
      if(rv != 0) {
        return rv;
      }
      continue;
    }

    buf->last = nghttp2_cpymem(buf->last, p, nwrite);
    p += len;
    len -= nwrite;
  }

  return 0;
}

static int bufs_ensure_addb(nghttp2_bufs *bufs)
{
  int rv;
  nghttp2_buf *buf;

  buf = &bufs->cur->buf;

  if(nghttp2_buf_avail(buf) > 0) {
    return 0;
  }

  rv = bufs_alloc_chain(bufs);
  if(rv != 0) {
    return rv;
  }

  return 0;
}

int nghttp2_bufs_addb(nghttp2_bufs *bufs, uint8_t b)
{
  int rv;

  rv = bufs_ensure_addb(bufs);
  if(rv != 0) {
    return rv;
  }

  *bufs->cur->buf.last++ = b;

  return 0;
}

int nghttp2_bufs_addb_hold(nghttp2_bufs *bufs, uint8_t b)
{
  int rv;

  rv = bufs_ensure_addb(bufs);
  if(rv != 0) {
    return rv;
  }

  *bufs->cur->buf.last = b;

  return 0;
}

int nghttp2_bufs_orb(nghttp2_bufs *bufs, uint8_t b)
{
  int rv;

  rv = bufs_ensure_addb(bufs);
  if(rv != 0) {
    return rv;
  }

  *bufs->cur->buf.last++ |= b;

  return 0;
}

int nghttp2_bufs_orb_hold(nghttp2_bufs *bufs, uint8_t b)
{
  int rv;

  rv = bufs_ensure_addb(bufs);
  if(rv != 0) {
    return rv;
  }

  *bufs->cur->buf.last |= b;

  return 0;
}

ssize_t nghttp2_bufs_remove(nghttp2_bufs *bufs, uint8_t **out)
{
  size_t len;
  nghttp2_buf_chain *chain;
  nghttp2_buf *buf;
  uint8_t *res;
  nghttp2_buf resbuf;

  len = 0;

  for(chain = bufs->head; chain; chain = chain->next) {
    len += nghttp2_buf_len(&chain->buf);
  }

  if(!len) {
    res = NULL;
  } else {
    res = (uint8_t *)malloc(len);

    if(res == NULL) {
      return NGHTTP2_ERR_NOMEM;
    }
  }

  nghttp2_buf_wrap_init(&resbuf, res, len);

  for(chain = bufs->head; chain; chain = chain->next) {
    buf = &chain->buf;

    if(resbuf.last) {
      resbuf.last = nghttp2_cpymem(resbuf.last,
                                   buf->pos, nghttp2_buf_len(buf));
    }

    nghttp2_buf_reset(buf);
    nghttp2_buf_shift_right(&chain->buf, bufs->offset);
  }

  bufs->cur = bufs->head;

  *out = res;

  return (ssize_t)len;
}

void nghttp2_bufs_reset(nghttp2_bufs *bufs)
{
  nghttp2_buf_chain *chain, *ci;
  size_t k;

  k = bufs->chunk_keep;

  for(ci = bufs->head; ci; ci = ci->next) {
    nghttp2_buf_reset(&ci->buf);
    nghttp2_buf_shift_right(&ci->buf, bufs->offset);

    if(--k == 0) {
      break;
    }
  }

  if(ci) {
    chain = ci->next;
    ci->next = NULL;

    for(ci = chain; ci;) {
      chain = ci->next;

      buf_chain_del(ci);

      ci = chain;
    }

    bufs->chunk_used = bufs->chunk_keep;
  }

  bufs->cur = bufs->head;
}

int nghttp2_bufs_advance(nghttp2_bufs *bufs)
{
  return bufs_alloc_chain(bufs);
}

int nghttp2_bufs_next_present(nghttp2_bufs *bufs)
{
  nghttp2_buf_chain *chain;

  chain = bufs->cur->next;

  return chain && nghttp2_buf_len(&chain->buf);
}

