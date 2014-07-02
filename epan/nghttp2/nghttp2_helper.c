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
#include "nghttp2_helper.h"

#include <assert.h>
#include <string.h>

#include "nghttp2_net.h"

void nghttp2_put_uint16be(uint8_t *buf, uint16_t n)
{
  uint16_t x = htons(n);
  memcpy(buf, &x, sizeof(uint16_t));
}

void nghttp2_put_uint32be(uint8_t *buf, uint32_t n)
{
  uint32_t x = htonl(n);
  memcpy(buf, &x, sizeof(uint32_t));
}

uint16_t nghttp2_get_uint16(const uint8_t *data)
{
  uint16_t n;
  memcpy(&n, data, sizeof(uint16_t));
  return ntohs(n);
}

uint32_t nghttp2_get_uint32(const uint8_t *data)
{
  uint32_t n;
  memcpy(&n, data, sizeof(uint32_t));
  return ntohl(n);
}

int nghttp2_reserve_buffer(uint8_t **buf_ptr, size_t *buflen_ptr,
                           size_t min_length)
{
  if(min_length > *buflen_ptr) {
    uint8_t *temp;
    min_length = (min_length+4095)/4096*4096;
    temp = (uint8_t *)realloc(*buf_ptr, min_length);
    if(temp == NULL) {
      return NGHTTP2_ERR_NOMEM;
    } else {
      *buf_ptr = temp;
      *buflen_ptr = min_length;
    }
  }
  return 0;
}

void* nghttp2_memdup(const void* src, size_t n)
{
  void* dest;

  if(n == 0) {
    return NULL;
  }

  dest = malloc(n);
  if(dest == NULL) {
    return NULL;
  }
  memcpy(dest, src, n);
  return dest;
}

void nghttp2_downcase(uint8_t *s, size_t len)
{
  size_t i;
  for(i = 0; i < len; ++i) {
    if('A' <= s[i] && s[i] <= 'Z') {
      s[i] += 'a'-'A';
    }
  }
}

int nghttp2_adjust_local_window_size(int32_t *local_window_size_ptr,
                                     int32_t *recv_window_size_ptr,
                                     int32_t *recv_reduction_ptr,
                                     int32_t *delta_ptr)
{
  if(*delta_ptr > 0) {
    int32_t new_recv_window_size =
      nghttp2_max(0, *recv_window_size_ptr) - *delta_ptr;
    if(new_recv_window_size < 0) {
      /* The delta size is strictly more than received bytes. Increase
         local_window_size by that difference. */
      int32_t recv_reduction_diff;
      if(*local_window_size_ptr >
         NGHTTP2_MAX_WINDOW_SIZE + new_recv_window_size) {
        return NGHTTP2_ERR_FLOW_CONTROL;
      }
      *local_window_size_ptr -= new_recv_window_size;
      /* If there is recv_reduction due to earlier window_size
         reduction, we have to adjust it too. */
      recv_reduction_diff = nghttp2_min(*recv_reduction_ptr,
                                        -new_recv_window_size);
      *recv_reduction_ptr -= recv_reduction_diff;
      if(*recv_window_size_ptr < 0) {
        *recv_window_size_ptr += recv_reduction_diff;
      } else {
        /* If *recv_window_size_ptr > 0, then those bytes are
           considered to be backed to the remote peer (by
           WINDOW_UPDATE with the adjusted *delta_ptr), so it is
           effectively 0 now. */
        *recv_window_size_ptr = recv_reduction_diff;
      }
      /* recv_reduction_diff must be paied from *delta_ptr, since it
         was added in window size reduction (see below). */
      *delta_ptr -= recv_reduction_diff;
    } else {
      *recv_window_size_ptr = new_recv_window_size;
    }
    return 0;
  } else {
    if(*local_window_size_ptr + *delta_ptr < 0 ||
       *recv_window_size_ptr < INT32_MIN - *delta_ptr ||
       *recv_reduction_ptr > INT32_MAX + *delta_ptr) {
      return NGHTTP2_ERR_FLOW_CONTROL;
    }
    /* Decreasing local window size. Note that we achieve this without
       noticing to the remote peer. To do this, we cut
       recv_window_size by -delta. This means that we don't send
       WINDOW_UPDATE for -delta bytes. */
    *local_window_size_ptr += *delta_ptr;
    *recv_window_size_ptr += *delta_ptr;
    *recv_reduction_ptr -= *delta_ptr;
    *delta_ptr = 0;
  }
  return 0;
}

int nghttp2_should_send_window_update(int32_t local_window_size,
                                      int32_t recv_window_size)
{
  return recv_window_size >= local_window_size / 2;
}

const char* nghttp2_strerror(int error_code)
{
  switch(error_code) {
  case 0:
    return "Success";
  case NGHTTP2_ERR_INVALID_ARGUMENT:
    return "Invalid argument";
  case NGHTTP2_ERR_BUFFER_ERROR:
    return "Out of buffer space";
  case NGHTTP2_ERR_UNSUPPORTED_VERSION:
    return "Unsupported SPDY version";
  case NGHTTP2_ERR_WOULDBLOCK:
    return "Operation would block";
  case NGHTTP2_ERR_PROTO:
    return "Protocol error";
  case NGHTTP2_ERR_INVALID_FRAME:
    return "Invalid frame octets";
  case NGHTTP2_ERR_EOF:
    return "EOF";
  case NGHTTP2_ERR_DEFERRED:
    return "Data transfer deferred";
  case NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE:
    return "No more Stream ID available";
  case NGHTTP2_ERR_STREAM_CLOSED:
    return "Stream was already closed or invalid";
  case NGHTTP2_ERR_STREAM_CLOSING:
    return "Stream is closing";
  case NGHTTP2_ERR_STREAM_SHUT_WR:
    return "The transmission is not allowed for this stream";
  case NGHTTP2_ERR_INVALID_STREAM_ID:
    return "Stream ID is invalid";
  case NGHTTP2_ERR_INVALID_STREAM_STATE:
    return "Invalid stream state";
  case NGHTTP2_ERR_DEFERRED_DATA_EXIST:
    return "Another DATA frame has already been deferred";
  case NGHTTP2_ERR_START_STREAM_NOT_ALLOWED:
    return "request HEADERS is not allowed";
  case NGHTTP2_ERR_GOAWAY_ALREADY_SENT:
    return "GOAWAY has already been sent";
  case NGHTTP2_ERR_INVALID_HEADER_BLOCK:
    return "Invalid header block";
  case NGHTTP2_ERR_INVALID_STATE:
    return "Invalid state";
  case NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE:
    return "The user callback function failed due to the temporal error";
  case NGHTTP2_ERR_FRAME_SIZE_ERROR:
    return "The length of the frame is invalid";
  case NGHTTP2_ERR_HEADER_COMP:
    return "Header compression/decompression error";
  case NGHTTP2_ERR_FLOW_CONTROL:
    return "Flow control error";
  case NGHTTP2_ERR_INSUFF_BUFSIZE:
    return "Insufficient buffer size given to function";
  case NGHTTP2_ERR_PAUSE:
    return "Callback was paused by the application";
  case NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS:
    return "Too many inflight SETTINGS";
  case NGHTTP2_ERR_PUSH_DISABLED:
    return "Server push is disabled by peer";
  case NGHTTP2_ERR_DATA_EXIST:
    return "DATA frame already exists";
  case NGHTTP2_ERR_NOMEM:
    return "Out of memory";
  case NGHTTP2_ERR_CALLBACK_FAILURE:
    return "The user callback function failed";
  default:
    return "Unknown error code";
  }
}

void nghttp2_free(void *ptr)
{
  free(ptr);
}

static int VALID_HD_NAME_CHARS[] = {
  0 /* NUL  */, 0 /* SOH  */, 0 /* STX  */, 0 /* ETX  */,
  0 /* EOT  */, 0 /* ENQ  */, 0 /* ACK  */, 0 /* BEL  */,
  0 /* BS   */, 0 /* HT   */, 0 /* LF   */, 0 /* VT   */,
  0 /* FF   */, 0 /* CR   */, 0 /* SO   */, 0 /* SI   */,
  0 /* DLE  */, 0 /* DC1  */, 0 /* DC2  */, 0 /* DC3  */,
  0 /* DC4  */, 0 /* NAK  */, 0 /* SYN  */, 0 /* ETB  */,
  0 /* CAN  */, 0 /* EM   */, 0 /* SUB  */, 0 /* ESC  */,
  0 /* FS   */, 0 /* GS   */, 0 /* RS   */, 0 /* US   */,
  0 /* SPC  */, 1 /* !    */, 0 /* "    */, 1 /* #    */,
  1 /* $    */, 1 /* %    */, 1 /* &    */, 1 /* '    */,
  0 /* (    */, 0 /* )    */, 1 /* *    */, 1 /* +    */,
  0 /* ,    */, 1 /* -    */, 1 /* .    */, 0 /* /    */,
  1 /* 0    */, 1 /* 1    */, 1 /* 2    */, 1 /* 3    */,
  1 /* 4    */, 1 /* 5    */, 1 /* 6    */, 1 /* 7    */,
  1 /* 8    */, 1 /* 9    */, 0 /* :    */, 0 /* ;    */,
  0 /* <    */, 0 /* =    */, 0 /* >    */, 0 /* ?    */,
  0 /* @    */, 0 /* A    */, 0 /* B    */, 0 /* C    */,
  0 /* D    */, 0 /* E    */, 0 /* F    */, 0 /* G    */,
  0 /* H    */, 0 /* I    */, 0 /* J    */, 0 /* K    */,
  0 /* L    */, 0 /* M    */, 0 /* N    */, 0 /* O    */,
  0 /* P    */, 0 /* Q    */, 0 /* R    */, 0 /* S    */,
  0 /* T    */, 0 /* U    */, 0 /* V    */, 0 /* W    */,
  0 /* X    */, 0 /* Y    */, 0 /* Z    */, 0 /* [    */,
  0 /* \    */, 0 /* ]    */, 1 /* ^    */, 1 /* _    */,
  1 /* `    */, 1 /* a    */, 1 /* b    */, 1 /* c    */,
  1 /* d    */, 1 /* e    */, 1 /* f    */, 1 /* g    */,
  1 /* h    */, 1 /* i    */, 1 /* j    */, 1 /* k    */,
  1 /* l    */, 1 /* m    */, 1 /* n    */, 1 /* o    */,
  1 /* p    */, 1 /* q    */, 1 /* r    */, 1 /* s    */,
  1 /* t    */, 1 /* u    */, 1 /* v    */, 1 /* w    */,
  1 /* x    */, 1 /* y    */, 1 /* z    */, 0 /* {    */,
  1 /* |    */, 0 /* }    */, 1 /* ~    */, 0 /* DEL  */,
  0 /* 0x80 */, 0 /* 0x81 */, 0 /* 0x82 */, 0 /* 0x83 */,
  0 /* 0x84 */, 0 /* 0x85 */, 0 /* 0x86 */, 0 /* 0x87 */,
  0 /* 0x88 */, 0 /* 0x89 */, 0 /* 0x8a */, 0 /* 0x8b */,
  0 /* 0x8c */, 0 /* 0x8d */, 0 /* 0x8e */, 0 /* 0x8f */,
  0 /* 0x90 */, 0 /* 0x91 */, 0 /* 0x92 */, 0 /* 0x93 */,
  0 /* 0x94 */, 0 /* 0x95 */, 0 /* 0x96 */, 0 /* 0x97 */,
  0 /* 0x98 */, 0 /* 0x99 */, 0 /* 0x9a */, 0 /* 0x9b */,
  0 /* 0x9c */, 0 /* 0x9d */, 0 /* 0x9e */, 0 /* 0x9f */,
  0 /* 0xa0 */, 0 /* 0xa1 */, 0 /* 0xa2 */, 0 /* 0xa3 */,
  0 /* 0xa4 */, 0 /* 0xa5 */, 0 /* 0xa6 */, 0 /* 0xa7 */,
  0 /* 0xa8 */, 0 /* 0xa9 */, 0 /* 0xaa */, 0 /* 0xab */,
  0 /* 0xac */, 0 /* 0xad */, 0 /* 0xae */, 0 /* 0xaf */,
  0 /* 0xb0 */, 0 /* 0xb1 */, 0 /* 0xb2 */, 0 /* 0xb3 */,
  0 /* 0xb4 */, 0 /* 0xb5 */, 0 /* 0xb6 */, 0 /* 0xb7 */,
  0 /* 0xb8 */, 0 /* 0xb9 */, 0 /* 0xba */, 0 /* 0xbb */,
  0 /* 0xbc */, 0 /* 0xbd */, 0 /* 0xbe */, 0 /* 0xbf */,
  0 /* 0xc0 */, 0 /* 0xc1 */, 0 /* 0xc2 */, 0 /* 0xc3 */,
  0 /* 0xc4 */, 0 /* 0xc5 */, 0 /* 0xc6 */, 0 /* 0xc7 */,
  0 /* 0xc8 */, 0 /* 0xc9 */, 0 /* 0xca */, 0 /* 0xcb */,
  0 /* 0xcc */, 0 /* 0xcd */, 0 /* 0xce */, 0 /* 0xcf */,
  0 /* 0xd0 */, 0 /* 0xd1 */, 0 /* 0xd2 */, 0 /* 0xd3 */,
  0 /* 0xd4 */, 0 /* 0xd5 */, 0 /* 0xd6 */, 0 /* 0xd7 */,
  0 /* 0xd8 */, 0 /* 0xd9 */, 0 /* 0xda */, 0 /* 0xdb */,
  0 /* 0xdc */, 0 /* 0xdd */, 0 /* 0xde */, 0 /* 0xdf */,
  0 /* 0xe0 */, 0 /* 0xe1 */, 0 /* 0xe2 */, 0 /* 0xe3 */,
  0 /* 0xe4 */, 0 /* 0xe5 */, 0 /* 0xe6 */, 0 /* 0xe7 */,
  0 /* 0xe8 */, 0 /* 0xe9 */, 0 /* 0xea */, 0 /* 0xeb */,
  0 /* 0xec */, 0 /* 0xed */, 0 /* 0xee */, 0 /* 0xef */,
  0 /* 0xf0 */, 0 /* 0xf1 */, 0 /* 0xf2 */, 0 /* 0xf3 */,
  0 /* 0xf4 */, 0 /* 0xf5 */, 0 /* 0xf6 */, 0 /* 0xf7 */,
  0 /* 0xf8 */, 0 /* 0xf9 */, 0 /* 0xfa */, 0 /* 0xfb */,
  0 /* 0xfc */, 0 /* 0xfd */, 0 /* 0xfe */, 0 /* 0xff */
};

int nghttp2_check_header_name(const uint8_t *name, size_t len)
{
  const uint8_t *last;
  if(len == 0) {
    return 0;
  }
  if(*name == ':') {
    if(len == 1) {
      return 0;
    }
    ++name;
    --len;
  }
  for(last = name + len; name != last; ++name) {
    if(!VALID_HD_NAME_CHARS[*name]) {
      return 0;
    }
  }
  return 1;
}

static int VALID_HD_VALUE_CHARS[] = {
  1 /* NUL  */, 0 /* SOH  */, 0 /* STX  */, 0 /* ETX  */,
  0 /* EOT  */, 0 /* ENQ  */, 0 /* ACK  */, 0 /* BEL  */,
  0 /* BS   */, 1 /* HT   */, 0 /* LF   */, 0 /* VT   */,
  0 /* FF   */, 0 /* CR   */, 0 /* SO   */, 0 /* SI   */,
  0 /* DLE  */, 0 /* DC1  */, 0 /* DC2  */, 0 /* DC3  */,
  0 /* DC4  */, 0 /* NAK  */, 0 /* SYN  */, 0 /* ETB  */,
  0 /* CAN  */, 0 /* EM   */, 0 /* SUB  */, 0 /* ESC  */,
  0 /* FS   */, 0 /* GS   */, 0 /* RS   */, 0 /* US   */,
  1 /* SPC  */, 1 /* !    */, 1 /* "    */, 1 /* #    */,
  1 /* $    */, 1 /* %    */, 1 /* &    */, 1 /* '    */,
  1 /* (    */, 1 /* )    */, 1 /* *    */, 1 /* +    */,
  1 /* ,    */, 1 /* -    */, 1 /* .    */, 1 /* /    */,
  1 /* 0    */, 1 /* 1    */, 1 /* 2    */, 1 /* 3    */,
  1 /* 4    */, 1 /* 5    */, 1 /* 6    */, 1 /* 7    */,
  1 /* 8    */, 1 /* 9    */, 1 /* :    */, 1 /* ;    */,
  1 /* <    */, 1 /* =    */, 1 /* >    */, 1 /* ?    */,
  1 /* @    */, 1 /* A    */, 1 /* B    */, 1 /* C    */,
  1 /* D    */, 1 /* E    */, 1 /* F    */, 1 /* G    */,
  1 /* H    */, 1 /* I    */, 1 /* J    */, 1 /* K    */,
  1 /* L    */, 1 /* M    */, 1 /* N    */, 1 /* O    */,
  1 /* P    */, 1 /* Q    */, 1 /* R    */, 1 /* S    */,
  1 /* T    */, 1 /* U    */, 1 /* V    */, 1 /* W    */,
  1 /* X    */, 1 /* Y    */, 1 /* Z    */, 1 /* [    */,
  1 /* \    */, 1 /* ]    */, 1 /* ^    */, 1 /* _    */,
  1 /* `    */, 1 /* a    */, 1 /* b    */, 1 /* c    */,
  1 /* d    */, 1 /* e    */, 1 /* f    */, 1 /* g    */,
  1 /* h    */, 1 /* i    */, 1 /* j    */, 1 /* k    */,
  1 /* l    */, 1 /* m    */, 1 /* n    */, 1 /* o    */,
  1 /* p    */, 1 /* q    */, 1 /* r    */, 1 /* s    */,
  1 /* t    */, 1 /* u    */, 1 /* v    */, 1 /* w    */,
  1 /* x    */, 1 /* y    */, 1 /* z    */, 1 /* {    */,
  1 /* |    */, 1 /* }    */, 1 /* ~    */, 0 /* DEL  */,
  1 /* 0x80 */, 1 /* 0x81 */, 1 /* 0x82 */, 1 /* 0x83 */,
  1 /* 0x84 */, 1 /* 0x85 */, 1 /* 0x86 */, 1 /* 0x87 */,
  1 /* 0x88 */, 1 /* 0x89 */, 1 /* 0x8a */, 1 /* 0x8b */,
  1 /* 0x8c */, 1 /* 0x8d */, 1 /* 0x8e */, 1 /* 0x8f */,
  1 /* 0x90 */, 1 /* 0x91 */, 1 /* 0x92 */, 1 /* 0x93 */,
  1 /* 0x94 */, 1 /* 0x95 */, 1 /* 0x96 */, 1 /* 0x97 */,
  1 /* 0x98 */, 1 /* 0x99 */, 1 /* 0x9a */, 1 /* 0x9b */,
  1 /* 0x9c */, 1 /* 0x9d */, 1 /* 0x9e */, 1 /* 0x9f */,
  1 /* 0xa0 */, 1 /* 0xa1 */, 1 /* 0xa2 */, 1 /* 0xa3 */,
  1 /* 0xa4 */, 1 /* 0xa5 */, 1 /* 0xa6 */, 1 /* 0xa7 */,
  1 /* 0xa8 */, 1 /* 0xa9 */, 1 /* 0xaa */, 1 /* 0xab */,
  1 /* 0xac */, 1 /* 0xad */, 1 /* 0xae */, 1 /* 0xaf */,
  1 /* 0xb0 */, 1 /* 0xb1 */, 1 /* 0xb2 */, 1 /* 0xb3 */,
  1 /* 0xb4 */, 1 /* 0xb5 */, 1 /* 0xb6 */, 1 /* 0xb7 */,
  1 /* 0xb8 */, 1 /* 0xb9 */, 1 /* 0xba */, 1 /* 0xbb */,
  1 /* 0xbc */, 1 /* 0xbd */, 1 /* 0xbe */, 1 /* 0xbf */,
  1 /* 0xc0 */, 1 /* 0xc1 */, 1 /* 0xc2 */, 1 /* 0xc3 */,
  1 /* 0xc4 */, 1 /* 0xc5 */, 1 /* 0xc6 */, 1 /* 0xc7 */,
  1 /* 0xc8 */, 1 /* 0xc9 */, 1 /* 0xca */, 1 /* 0xcb */,
  1 /* 0xcc */, 1 /* 0xcd */, 1 /* 0xce */, 1 /* 0xcf */,
  1 /* 0xd0 */, 1 /* 0xd1 */, 1 /* 0xd2 */, 1 /* 0xd3 */,
  1 /* 0xd4 */, 1 /* 0xd5 */, 1 /* 0xd6 */, 1 /* 0xd7 */,
  1 /* 0xd8 */, 1 /* 0xd9 */, 1 /* 0xda */, 1 /* 0xdb */,
  1 /* 0xdc */, 1 /* 0xdd */, 1 /* 0xde */, 1 /* 0xdf */,
  1 /* 0xe0 */, 1 /* 0xe1 */, 1 /* 0xe2 */, 1 /* 0xe3 */,
  1 /* 0xe4 */, 1 /* 0xe5 */, 1 /* 0xe6 */, 1 /* 0xe7 */,
  1 /* 0xe8 */, 1 /* 0xe9 */, 1 /* 0xea */, 1 /* 0xeb */,
  1 /* 0xec */, 1 /* 0xed */, 1 /* 0xee */, 1 /* 0xef */,
  1 /* 0xf0 */, 1 /* 0xf1 */, 1 /* 0xf2 */, 1 /* 0xf3 */,
  1 /* 0xf4 */, 1 /* 0xf5 */, 1 /* 0xf6 */, 1 /* 0xf7 */,
  1 /* 0xf8 */, 1 /* 0xf9 */, 1 /* 0xfa */, 1 /* 0xfb */,
  1 /* 0xfc */, 1 /* 0xfd */, 1 /* 0xfe */, 1 /* 0xff */
};

int nghttp2_check_header_value(const uint8_t *value, size_t len)
{
  const uint8_t *last;
  for(last = value + len; value != last; ++value) {
    if(!VALID_HD_VALUE_CHARS[*value]) {
      return 0;
    }
  }
  return 1;
}

uint8_t* nghttp2_cpymem(uint8_t *dest, const void *src, size_t len)
{
  memcpy(dest, src, len);

  return dest + len;
}
