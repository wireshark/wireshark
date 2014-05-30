/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
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
#ifndef NGHTTP2_HELPER_H
#define NGHTTP2_HELPER_H


#  include <config.h>

#include <wsutil/nghttp2/nghttp2/nghttp2.h>

#define nghttp2_min(A, B) ((A) < (B) ? (A) : (B))
#define nghttp2_max(A, B) ((A) > (B) ? (A) : (B))

/*
 * Copies 2 byte unsigned integer |n| in host byte order to |buf| in
 * network byte order.
 */
void nghttp2_put_uint16be(uint8_t *buf, uint16_t n);

/*
 * Copies 4 byte unsigned integer |n| in host byte order to |buf| in
 * network byte order.
 */
void nghttp2_put_uint32be(uint8_t *buf, uint32_t n);

/*
 * Retrieves 2 byte unsigned integer stored in |data| in network byte
 * order and returns it in host byte order.
 */
uint16_t nghttp2_get_uint16(const uint8_t *data);

/*
 * Retrieves 4 byte unsigned integer stored in |data| in network byte
 * order and returns it in host byte order.
 */
uint32_t nghttp2_get_uint32(const uint8_t *data);

/*
 * Ensures that buffer |*buf_ptr| with |*buflen_ptr| length has at
 * least |min_length| bytes. If |min_length| > |*buflen_ptr|,
 * allocates new buffer having at least |min_length| bytes and assigns
 * its pointer to |*buf_ptr| and allocated number of bytes to
 * |*buflen_ptr|. The memory pointed by |*buf_ptr| previously may
 * change. No memory copy is done between old and new buffer.
 * |*buf_ptr| and |*buflen_ptr| are only updated iff this function
 * succeeds.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_reserve_buffer(uint8_t **buf_ptr, size_t *buflen_ptr,
                           size_t min_length);

/*
 * Allocates |n| bytes of memory and copy the memory region pointed by
 * |src| with the length |n| bytes into it. Returns the allocated memory.
 *
 * This function returns pointer to allocated memory, or one of the
 * following negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
void* nghttp2_memdup(const void* src, size_t n);

void nghttp2_downcase(uint8_t *s, size_t len);

/*
 * Adjusts |*local_window_size_ptr|, |*recv_window_size_ptr|,
 * |*recv_reduction_ptr| with |*delta_ptr| which is the
 * WINDOW_UPDATE's window_size_increment sent from local side. If
 * |delta| is strictly larger than |*recv_window_size_ptr|,
 * |*local_window_size_ptr| is increased by delta -
 * *recv_window_size_ptr. If |delta| is negative,
 * |*local_window_size_ptr| is decreased by delta.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_FLOW_CONTROL
 *     local_window_size overflow or gets negative.
 */
int nghttp2_adjust_local_window_size(int32_t *local_window_size_ptr,
                                     int32_t *recv_window_size_ptr,
                                     int32_t *recv_reduction_ptr,
                                     int32_t *delta_ptr);

/*
 * Returns non-zero if the function decided that WINDOW_UPDATE should
 * be sent.
 */
int nghttp2_should_send_window_update(int32_t local_window_size,
                                      int32_t recv_window_size);

/*
 * Deallocates memory space pointed by |ptr|. This function exists for
 * the application to free the memory space allocated by the library
 * functions. Currently this function is hidden from the public API,
 * but may be exposed as public API.
 */
void nghttp2_free(void *ptr);

/*
 * Copies the buffer |src| of length |len| to the destination pointed
 * by the |dest|, assuming that the |dest| is at lest |len| bytes long
 * . Returns dest + len.
 */
uint8_t* nghttp2_cpymem(uint8_t *dest, const void *src, size_t len);

#endif /* NGHTTP2_HELPER_H */
