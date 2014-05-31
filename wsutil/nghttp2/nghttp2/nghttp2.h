/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013, 2014 Tatsuhiro Tsujikawa
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
#ifndef NGHTTP2_H
#define NGHTTP2_H

#include "ws_symbol_export.h"
#include "config.h"

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#ifdef _MSC_VER

typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;

/* Limits of integral types. */
#ifndef INT8_MIN
#define INT8_MIN               (-128)
#endif
#ifndef INT16_MIN
#define INT16_MIN              (-32767-1)
#endif
#ifndef INT32_MIN
#define INT32_MIN              (-2147483647-1)
#endif
#ifndef INT8_MAX
#define INT8_MAX               (127)
#endif
#ifndef INT16_MAX
#define INT16_MAX              (32767)
#endif
#ifndef INT32_MAX
#define INT32_MAX              (2147483647)
#endif
#ifndef UINT8_MAX
#define UINT8_MAX              (255U)
#endif
#ifndef UINT16_MAX
#define UINT16_MAX             (65535U)
#endif
#ifndef UINT32_MAX
#define UINT32_MAX             (4294967295U)
#endif

#else
#include <stdint.h>
#endif
#include <sys/types.h>

#include <wsutil/nghttp2/nghttp2/nghttp2ver.h>

/**
 * @macro
 *
 * The protocol version identification string of this library
 * supports.  This identifier is used if HTTP/2 is used over TLS.
 */
#define NGHTTP2_PROTO_VERSION_ID "h2-12"
/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_PROTO_VERSION_ID`.
 */
#define NGHTTP2_PROTO_VERSION_ID_LEN 5

/**
 * @macro
 *
 * The protocol version identification string of this library
 * supports.  This identifier is used if HTTP/2 is used over cleartext
 * TCP.
 */
#define NGHTTP2_CLEARTEXT_PROTO_VERSION_ID "h2c-12"

/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_CLEARTEXT_PROTO_VERSION_ID`.
 */
#define NGHTTP2_CLEARTEXT_PROTO_VERSION_ID_LEN 6

struct nghttp2_session;
/**
 * @struct
 *
 * The primary structure to hold the resources needed for a HTTP/2
 * session.  The details of this structure are intentionally hidden
 * from the public API.
 */
typedef struct nghttp2_session nghttp2_session;

/**
 * @macro
 *
 * The age of :type:`nghttp2_info`
 */
#define NGHTTP2_VERSION_AGE 1

/**
 * @struct
 *
 * This struct is what `nghttp2_version()` returns.  It holds
 * information about the particular nghttp2 version.
 */
typedef struct {
  /**
   * Age of this struct.  This instance of nghttp2 sets it to
   * :macro:`NGHTTP2_VERSION_AGE` but a future version may bump it and
   * add more struct fields at the bottom
   */
  int age;
  /**
   * the :macro:`NGHTTP2_VERSION_NUM` number (since age ==1)
   */
  int version_num;
  /**
   * points to the :macro:`NGHTTP2_VERSION` string (since age ==1)
   */
  const char *version_str;
  /**
   * points to the :macro:`NGHTTP2_PROTO_VERSION_ID` string this
   * instance implements (since age ==1)
   */
  const char *proto_str;
  /* -------- the above fields all exist when age == 1 */
} nghttp2_info;

/**
 * @macro
 *
 * The default weight of stream dependency.
 */
#define NGHTTP2_DEFAULT_WEIGHT 16

/**
 * @macro
 *
 * The maximum weight of stream dependency.
 */
#define NGHTTP2_MAX_WEIGHT 256

/**
 * @macro
 *
 * The minimum weight of stream dependency.
 */
#define NGHTTP2_MIN_WEIGHT 1

/**
 * @macro
 *
 * The maximum window size
 */
#define NGHTTP2_MAX_WINDOW_SIZE ((int32_t)((1U << 31) - 1))

/**
 * @macro
 *
 * The initial window size for stream level flow control.
 */
#define NGHTTP2_INITIAL_WINDOW_SIZE ((1 << 16) - 1)
/**
 * @macro
 *
 * The initial window size for connection level flow control.
 */
#define NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE ((1 << 16) - 1)

/**
 * @macro
 *
 * The default header table size.
 */
#define NGHTTP2_DEFAULT_HEADER_TABLE_SIZE (1 << 12)

/**
 * @macro
 *
 * The client connection preface.
 */
#define NGHTTP2_CLIENT_CONNECTION_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_CLIENT_CONNECTION_PREFACE`.
 */
#define NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN 24

/**
 * @macro
 *
 * The client connection header.  This macro is obsoleted by
 * NGHTTP2_CLIENT_CONNECTION_PREFACE.
 */
#define NGHTTP2_CLIENT_CONNECTION_HEADER NGHTTP2_CLIENT_CONNECTION_PREFACE

/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_CLIENT_CONNECTION_HEADER`.
 */
#define NGHTTP2_CLIENT_CONNECTION_HEADER_LEN    \
  NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN

/**
 * @enum
 *
 * Error codes used in this library.  The code range is [-999, -500],
 * inclusive. The following values are defined:
 */
typedef enum {
  /**
   * Invalid argument passed.
   */
  NGHTTP2_ERR_INVALID_ARGUMENT = -501,
  /**
   * Ouf of buffer space.
   */
  NGHTTP2_ERR_BUFFER_ERROR = -502,
  /**
   * The specified protocol version is not supported.
   */
  NGHTTP2_ERR_UNSUPPORTED_VERSION = -503,
  /**
   * Used as a return value from :type:`nghttp2_send_callback` and
   * :type:`nghttp2_recv_callback` to indicate that the operation
   * would block.
   */
  NGHTTP2_ERR_WOULDBLOCK = -504,
  /**
   * General protocol error
   */
  NGHTTP2_ERR_PROTO = -505,
  /**
   * The frame is invalid.
   */
  NGHTTP2_ERR_INVALID_FRAME = -506,
  /**
   * The peer performed a shutdown on the connection.
   */
  NGHTTP2_ERR_EOF = -507,
  /**
   * Used as a return value from
   * :func:`nghttp2_data_source_read_callback` to indicate that data
   * transfer is postponed.  See
   * :func:`nghttp2_data_source_read_callback` for details.
   */
  NGHTTP2_ERR_DEFERRED = -508,
  /**
   * Stream ID has reached the maximum value.  Therefore no stream ID
   * is available.
   */
  NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE = -509,
  /**
   * The stream is already closed; or the stream ID is invalid.
   */
  NGHTTP2_ERR_STREAM_CLOSED = -510,
  /**
   * RST_STREAM has been added to the outbound queue.  The stream is
   * in closing state.
   */
  NGHTTP2_ERR_STREAM_CLOSING = -511,
  /**
   * The transmission is not allowed for this stream (e.g., a frame
   * with END_STREAM flag set has already sent).
   */
  NGHTTP2_ERR_STREAM_SHUT_WR = -512,
  /**
   * The stream ID is invalid.
   */
  NGHTTP2_ERR_INVALID_STREAM_ID = -513,
  /**
   * The state of the stream is not valid (e.g., DATA cannot be sent
   * to the stream if response HEADERS has not been sent).
   */
  NGHTTP2_ERR_INVALID_STREAM_STATE = -514,
  /**
   * Another DATA frame has already been deferred.
   */
  NGHTTP2_ERR_DEFERRED_DATA_EXIST = -515,
  /**
   * Starting new stream is not allowed (e.g., GOAWAY has been sent
   * and/or received).
   */
  NGHTTP2_ERR_START_STREAM_NOT_ALLOWED = -516,
  /**
   * GOAWAY has already been sent.
   */
  NGHTTP2_ERR_GOAWAY_ALREADY_SENT = -517,
  /**
   * The received frame contains the invalid header block (e.g., There
   * are duplicate header names; or the header names are not encoded
   * in US-ASCII character set and not lower cased; or the header name
   * is zero-length string; or the header value contains multiple
   * in-sequence NUL bytes).
   */
  NGHTTP2_ERR_INVALID_HEADER_BLOCK = -518,
  /**
   * Indicates that the context is not suitable to perform the
   * requested operation.
   */
  NGHTTP2_ERR_INVALID_STATE = -519,
  /**
   * The user callback function failed due to the temporal error.
   */
  NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE = -521,
  /**
   * The length of the frame is invalid, either too large or too small.
   */
  NGHTTP2_ERR_FRAME_SIZE_ERROR = -522,
  /**
   * Header block inflate/deflate error.
   */
  NGHTTP2_ERR_HEADER_COMP = -523,
  /**
   * Flow control error
   */
  NGHTTP2_ERR_FLOW_CONTROL = -524,
  /**
   * Insufficient buffer size given to function.
   */
  NGHTTP2_ERR_INSUFF_BUFSIZE = -525,
  /**
   * Callback was paused by the application
   */
  NGHTTP2_ERR_PAUSE = -526,
  /**
   * There are too many in-flight SETTING frame and no more
   * transmission of SETTINGS is allowed.
   */
  NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS = -527,
  /**
   * The server push is disabled.
   */
  NGHTTP2_ERR_PUSH_DISABLED = -528,
  /**
   * DATA frame for a given stream has been already submitted and has
   * not been fully processed yet.
   */
  NGHTTP2_ERR_DATA_EXIST = -529,
  /**
   * The errors < :enum:`NGHTTP2_ERR_FATAL` mean that the library is
   * under unexpected condition and processing was terminated (e.g.,
   * out of memory).  If application receives this error code, it must
   * stop using that :type:`nghttp2_session` object and only allowed
   * operation for that object is deallocate it using
   * `nghttp2_session_del()`.
   */
  NGHTTP2_ERR_FATAL = -900,
  /**
   * Out of memory.  This is a fatal error.
   */
  NGHTTP2_ERR_NOMEM = -901,
  /**
   * The user callback function failed.  This is a fatal error.
   */
  NGHTTP2_ERR_CALLBACK_FAILURE = -902
} nghttp2_error;

typedef enum {
  NGHTTP2_MSG_MORE
} nghttp2_io_flag;

/**
 * @enum
 *
 * The flags for header field name/value pair.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_NV_FLAG_NONE = 0,
  /**
   * Indicates that this name/value pair must not be indexed.
   */
  NGHTTP2_NV_FLAG_NO_INDEX = 0x01
} nghttp2_nv_flag;

/**
 * @struct
 *
 * The name/value pair, which mainly used to represent header fields.
 */
typedef struct {
  /**
   * The |name| byte string, which is not necessarily ``NULL``
   * terminated.
   */
  uint8_t *name;
  /**
   * The |value| byte string, which is not necessarily ``NULL``
   * terminated.
   */
  uint8_t *value;
  /**
   * The length of the |name|.
   */
  size_t namelen;
  /**
   * The length of the |value|.
   */
  size_t valuelen;
  /**
   * Bitwise OR of one or more of :type:`nghttp2_nv_flag`.
   */
  uint8_t flags;
} nghttp2_nv;

/**
 * @enum
 * The control frame types in HTTP/2.
 */
typedef enum {
  /**
   * The DATA frame.
   */
  NGHTTP2_DATA = 0,
  /**
   * The HEADERS frame.
   */
  NGHTTP2_HEADERS = 0x01,
  /**
   * The PRIORITY frame.
   */
  NGHTTP2_PRIORITY = 0x02,
  /**
   * The RST_STREAM frame.
   */
  NGHTTP2_RST_STREAM = 0x03,
  /**
   * The SETTINGS frame.
   */
  NGHTTP2_SETTINGS = 0x04,
  /**
   * The PUSH_PROMISE frame.
   */
  NGHTTP2_PUSH_PROMISE = 0x05,
  /**
   * The PING frame.
   */
  NGHTTP2_PING = 0x06,
  /**
   * The GOAWAY frame.
   */
  NGHTTP2_GOAWAY = 0x07,
  /**
   * The WINDOW_UPDATE frame.
   */
  NGHTTP2_WINDOW_UPDATE = 0x08,
  /**
   * The CONTINUATION frame.
   */
  NGHTTP2_CONTINUATION = 0x09,
  /**
   * The ALTSVC frame.
   */
  NGHTTP2_ALTSVC = 0x0a,
  /**
   * The BLOCKED frame.
   */
  NGHTTP2_BLOCKED = 0x0b
} nghttp2_frame_type;

/**
 * @enum
 *
 * The flags for HTTP/2 frames.  This enum defines all flags for all
 * frames.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_FLAG_NONE = 0,
  /**
   * The END_STREAM flag.
   */
  NGHTTP2_FLAG_END_STREAM = 0x01,
  /**
   * The END_HEADERS flag.
   */
  NGHTTP2_FLAG_END_HEADERS = 0x04,
  /**
   * The ACK flag.
   */
  NGHTTP2_FLAG_ACK = 0x01,
  /**
   * The END_SEGMENT flag.
   */
  NGHTTP2_FLAG_END_SEGMENT = 0x02,
  /**
   * The PAD_LOW flag.
   */
  NGHTTP2_FLAG_PAD_LOW = 0x08,
  /**
   * The PAD_HIGH flag.
   */
  NGHTTP2_FLAG_PAD_HIGH = 0x10,
  /**
   * The PRIORITY flag.
   */
  NGHTTP2_FLAG_PRIORITY = 0x20,
  /**
   * THE COMPRESSED flag.
   */
  NGHTTP2_FLAG_COMPRESSED = 0x20
} nghttp2_flag;

/**
 * @enum
 * The SETTINGS ID.
 */
typedef enum {
  /**
   * SETTINGS_HEADER_TABLE_SIZE
   */
  NGHTTP2_SETTINGS_HEADER_TABLE_SIZE = 1,
  /**
   * SETTINGS_ENABLE_PUSH
   */
  NGHTTP2_SETTINGS_ENABLE_PUSH = 2,
  /**
   * SETTINGS_MAX_CONCURRENT_STREAMS
   */
  NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 3,
  /**
   * SETTINGS_INITIAL_WINDOW_SIZE
   */
  NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 4,
  /**
   * SETTINGS_COMPRESS_DATA
   */
  NGHTTP2_SETTINGS_COMPRESS_DATA = 5,
  /**
   * Maximum ID of :type:`nghttp2_settings_id`.
   */
  NGHTTP2_SETTINGS_MAX = 5
} nghttp2_settings_id;

/**
 * @macro
 * Default maximum concurrent streams.
 */
#define NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS ((1U << 31) - 1)

/**
 * @enum
 * The status codes for the RST_STREAM and GOAWAY frames.
 */
typedef enum {
  /**
   * No errors.
   */
  NGHTTP2_NO_ERROR = 0,
  /**
   * PROTOCOL_ERROR
   */
  NGHTTP2_PROTOCOL_ERROR = 1,
  /**
   * INTERNAL_ERROR
   */
  NGHTTP2_INTERNAL_ERROR = 2,
  /**
   * FLOW_CONTROL_ERROR
   */
  NGHTTP2_FLOW_CONTROL_ERROR = 3,
  /**
   * SETTINGS_TIMEOUT
   */
  NGHTTP2_SETTINGS_TIMEOUT = 4,
  /**
   * STREAM_CLOSED
   */
  NGHTTP2_STREAM_CLOSED = 5,
  /**
   * FRAME_SIZE_ERROR
   */
  NGHTTP2_FRAME_SIZE_ERROR = 6,
  /**
   * REFUSED_STREAM
   */
  NGHTTP2_REFUSED_STREAM = 7,
  /**
   * CANCEL
   */
  NGHTTP2_CANCEL = 8,
  /**
   * COMPRESSION_ERROR
   */
  NGHTTP2_COMPRESSION_ERROR = 9,
  /**
   * CONNECT_ERROR
   */
  NGHTTP2_CONNECT_ERROR = 10,
  /**
   * ENHANCE_YOUR_CALM
   */
  NGHTTP2_ENHANCE_YOUR_CALM = 11,
  /**
   * INADEQUATE_SECURITY
   */
  NGHTTP2_INADEQUATE_SECURITY = 12
} nghttp2_error_code;

/**
 * @struct
 * The frame header.
 */
typedef struct {
  /**
   * The length field of this frame, excluding frame header.
   */
  size_t length;
  /**
   * The stream identifier (aka, stream ID)
   */
  int32_t stream_id;
  /**
   * The type of this frame.  See `nghttp2_frame`.
   */
  uint8_t type;
  /**
   * The flags.
   */
  uint8_t flags;
} nghttp2_frame_hd;


/**
 * @union
 *
 * This union represents the some kind of data source passed to
 * :type:`nghttp2_data_source_read_callback`.
 */
typedef union {
  /**
   * The integer field, suitable for a file descriptor.
   */
  int fd;
  /**
   * The pointer to an arbitrary object.
   */
  void *ptr;
} nghttp2_data_source;

/**
 * @enum
 *
 * The flags used to set in |data_flags| output parameter in
 * :type:`nghttp2_data_source_read_callback`.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_DATA_FLAG_NONE = 0,
  /**
   * Indicates EOF was sensed.
   */
  NGHTTP2_DATA_FLAG_EOF = 0x01,
  /**
   * Indicates data was compressed by application.
   */
  NGHTTP2_DATA_FLAG_COMPRESSED = 0x02
} nghttp2_data_flag;

/**
 * @functypedef
 *
 * Callback function invoked when the library wants to read data from
 * the |source|.  The read data is sent in the stream |stream_id|.
 * The implementation of this function must read at most |length|
 * bytes of data from |source| (or possibly other places) and store
 * them in |buf| and return number of data stored in |buf|.  If EOF is
 * reached, set :enum:`NGHTTP2_DATA_FLAG_EOF` flag in |*data_flags|.
 *
 * To send compressed data payload without affecting content-length,
 * set :enum:`NGHTTP2_DATA_FLAG_COMPRESSED` flag in |*data_flags|.
 * Compression must be done by application prior to fill data in
 * |buf|.
 *
 * If the application wants to postpone DATA frames (e.g.,
 * asynchronous I/O, or reading data blocks for long time), it is
 * achieved by returning :enum:`NGHTTP2_ERR_DEFERRED` without reading
 * any data in this invocation.  The library removes DATA frame from
 * the outgoing queue temporarily.  To move back deferred DATA frame
 * to outgoing queue, call `nghttp2_session_resume_data()`.  In case
 * of error, there are 2 choices. Returning
 * :enum:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE` will close the stream
 * by issuing RST_STREAM with :enum:`NGHTTP2_INTERNAL_ERROR`.
 * Returning :enum:`NGHTTP2_ERR_CALLBACK_FAILURE` will signal the
 * entire session failure.
 */
typedef ssize_t (*nghttp2_data_source_read_callback)
(nghttp2_session *session, int32_t stream_id,
 uint8_t *buf, size_t length, uint32_t *data_flags,
 nghttp2_data_source *source, void *user_data);

/**
 * @struct
 *
 * This struct represents the data source and the way to read a chunk
 * of data from it.
 */
typedef struct {
  /**
   * The data source.
   */
  nghttp2_data_source source;
  /**
   * The callback function to read a chunk of data from the |source|.
   */
  nghttp2_data_source_read_callback read_callback;
} nghttp2_data_provider;

/**
 * @struct
 *
 * The DATA frame.  The received data is delivered via
 * :type:`nghttp2_on_data_chunk_recv_callback`.
 */
typedef struct {
  nghttp2_frame_hd hd;
  /**
   * The length of the padding in this frame.  This includes PAD_HIGH
   * and PAD_LOW.
   */
  size_t padlen;
} nghttp2_data;

/**
 * @enum
 *
 * The category of HEADERS, which indicates the role of the frame.  In
 * HTTP/2 spec, request, response, push response and other arbitrary
 * headers (e.g., trailers) are all called just HEADERS.  To give the
 * application the role of incoming HEADERS frame, we define several
 * categories.
 */
typedef enum {
  /**
   * The HEADERS frame is opening new stream, which is analogous to
   * SYN_STREAM in SPDY.
   */
  NGHTTP2_HCAT_REQUEST = 0,
  /**
   * The HEADERS frame is the first response headers, which is
   * analogous to SYN_REPLY in SPDY.
   */
  NGHTTP2_HCAT_RESPONSE = 1,
  /**
   * The HEADERS frame is the first headers sent against reserved
   * stream.
   */
  NGHTTP2_HCAT_PUSH_RESPONSE = 2,
  /**
   * The HEADERS frame which does not apply for the above categories,
   * which is analogous to HEADERS in SPDY.
   */
  NGHTTP2_HCAT_HEADERS = 3
} nghttp2_headers_category;

/**
 * @struct
 *
 * The structure to specify stream dependency.
 */
typedef struct {
  /**
   * The stream ID of the stream to depend on.  Specifying 0 makes
   * stream not depend any other stream.
   */
  int32_t stream_id;
  /**
   * The weight of this dependency.
   */
  int32_t weight;
  /**
   * nonzero means exclusive dependency
   */
  uint8_t exclusive;
} nghttp2_priority_spec;

/**
 * @struct
 *
 * The HEADERS frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The length of the padding in this frame.  This includes PAD_HIGH
   * and PAD_LOW.
   */
  size_t padlen;
  /**
   * The priority specification
   */
  nghttp2_priority_spec pri_spec;
  /**
   * The name/value pairs.
   */
  nghttp2_nv *nva;
  /**
   * The number of name/value pairs in |nva|.
   */
  size_t nvlen;
  /**
   * The category of this HEADERS frame.
   */
  nghttp2_headers_category cat;
} nghttp2_headers;

/**
 * @struct
 *
 * The PRIORITY frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The priority specification.
   */
  nghttp2_priority_spec pri_spec;
} nghttp2_priority;

/**
 * @struct
 *
 * The RST_STREAM frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The error code.  See :type:`nghttp2_error_code`.
   */
  nghttp2_error_code error_code;
} nghttp2_rst_stream;

/**
 * @struct
 *
 * The SETTINGS ID/Value pair.  It has the following members:
 */
typedef struct {
  /**
   * The SETTINGS ID.  See :type:`nghttp2_settings_id`.
   */
  int32_t settings_id;
  /**
   * The value of this entry.
   */
  uint32_t value;
} nghttp2_settings_entry;

/**
 * @struct
 *
 * The SETTINGS frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The number of SETTINGS ID/Value pairs in |iv|.
   */
  size_t niv;
  /**
   * The pointer to the array of SETTINGS ID/Value pair.
   */
  nghttp2_settings_entry *iv;
} nghttp2_settings;

/**
 * @struct
 *
 * The PUSH_PROMISE frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The length of the padding in this frame.  This includes PAD_HIGH
   * and PAD_LOW.
   */
  size_t padlen;
  /**
   * The name/value pairs.
   */
  nghttp2_nv *nva;
  /**
   * The number of name/value pairs in |nva|.
   */
  size_t nvlen;
  /**
   * The promised stream ID
   */
  int32_t promised_stream_id;
} nghttp2_push_promise;

/**
 * @struct
 *
 * The PING frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The opaque data
   */
  uint8_t opaque_data[8];
} nghttp2_ping;

/**
 * @struct
 *
 * The GOAWAY frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The last stream stream ID.
   */
  int32_t last_stream_id;
  /**
   * The error code.  See :type:`nghttp2_error_code`.
   */
  nghttp2_error_code error_code;
  /**
   * The additional debug data
   */
  uint8_t *opaque_data;
  /**
   * The length of |opaque_data| member.
   */
  size_t opaque_data_len;
} nghttp2_goaway;

/**
 * @struct
 *
 * The WINDOW_UPDATE frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The window size increment.
   */
  int32_t window_size_increment;
} nghttp2_window_update;

/**
 * @struct
 *
 * The ALTSVC frame.  It has following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * Protocol ID
   */
  uint8_t *protocol_id;
  /**
   * Host
   */
  uint8_t *host;
  /**
   * Origin
   */
  uint8_t *origin;
  /**
   * The length of |protocol_id|
   */
  size_t protocol_id_len;
  /**
   * The length of |host|
   */
  size_t host_len;
  /**
   * The length of |origin|
   */
  size_t origin_len;
  /**
   * Max-Age
   */
  uint32_t max_age;
  /**
   * Port
   */
  uint16_t port;
} nghttp2_altsvc;

/**
 * @struct
 *
 * The BLOCKED frame.  It has following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
} nghttp2_blocked;

/**
 * @union
 *
 * This union includes all frames to pass them to various function
 * calls as nghttp2_frame type.  The CONTINUATION frame is omitted
 * from here because the library deals with it internally.
 */
typedef union {
  /**
   * The frame header, which is convenient to inspect frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The DATA frame.
   */
  nghttp2_data data;
  /**
   * The HEADERS frame.
   */
  nghttp2_headers headers;
  /**
   * The PRIORITY frame.
   */
  nghttp2_priority priority;
  /**
   * The RST_STREAM frame.
   */
  nghttp2_rst_stream rst_stream;
  /**
   * The SETTINGS frame.
   */
  nghttp2_settings settings;
  /**
   * The PUSH_PROMISE frame.
   */
  nghttp2_push_promise push_promise;
  /**
   * The PING frame.
   */
  nghttp2_ping ping;
  /**
   * The GOAWAY frame.
   */
  nghttp2_goaway goaway;
  /**
   * The WINDOW_UPDATE frame.
   */
  nghttp2_window_update window_update;
  /**
   * The ALTSVC frame.
   */
  nghttp2_altsvc altsvc;
  /**
   * The BLOCKED frame.
   */
  nghttp2_blocked blocked;
} nghttp2_frame;

/**
 * @functypedef
 *
 * Callback function invoked when |session| wants to send data to the
 * remote peer.  The implementation of this function must send at most
 * |length| bytes of data stored in |data|.  The |flags| is currently
 * not used and always 0. It must return the number of bytes sent if
 * it succeeds.  If it cannot send any single byte without blocking,
 * it must return :enum:`NGHTTP2_ERR_WOULDBLOCK`.  For other errors,
 * it must return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.  The
 * |user_data| pointer is the third argument passed in to the call to
 * `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
 *
 * This callback is required if the application uses
 * `nghttp2_session_send()` to send data to the remote endpoint.  If
 * the application uses solely `nghttp2_session_mem_send()` instead,
 * this callback function is unnecessary.
 */
typedef ssize_t (*nghttp2_send_callback)
(nghttp2_session *session,
 const uint8_t *data, size_t length, int flags, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when |session| wants to receive data from
 * the remote peer.  The implementation of this function must read at
 * most |length| bytes of data and store it in |buf|.  The |flags| is
 * currently not used and always 0.  It must return the number of
 * bytes written in |buf| if it succeeds.  If it cannot read any
 * single byte without blocking, it must return
 * :enum:`NGHTTP2_ERR_WOULDBLOCK`.  If it gets EOF before it reads any
 * single byte, it must return :enum:`NGHTTP2_ERR_EOF`.  For other
 * errors, it must return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 * Returning 0 is treated as :enum:`NGHTTP2_ERR_WOULDBLOCK`.  The
 * |user_data| pointer is the third argument passed in to the call to
 * `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
 *
 * This callback is required if the application uses
 * `nghttp2_session_recv()` to receive data from the remote endpoint.
 * If the application uses solely `nghttp2_session_mem_recv()`
 * instead, this callback function is unnecessary.
 */
typedef ssize_t (*nghttp2_recv_callback)
(nghttp2_session *session,
 uint8_t *buf, size_t length, int flags, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked by `nghttp2_session_recv()` when a frame
 * is received.  The |user_data| pointer is the third argument passed
 * in to the call to `nghttp2_session_client_new()` or
 * `nghttp2_session_server_new()`.
 *
 * If frame is HEADERS or PUSH_PROMISE, the ``nva`` and ``nvlen``
 * member of their data structure are always ``NULL`` and 0
 * respectively.  The header name/value pairs are emitted via
 * :type:`nghttp2_on_header_callback`.
 *
 * For HEADERS, PUSH_PROMISE and DATA frames, this callback may be
 * called after stream is closed (see
 * :type:`nghttp2_on_stream_close_callback`).  The application should
 * check that stream is still alive using its own stream management or
 * :func:`nghttp2_session_get_stream_user_data()`.
 *
 * Only HEADERS and DATA frame can signal the end of incoming data.
 * If ``frame->hd.flags & NGHTTP2_FLAG_END_STREAM`` is nonzero, the
 * |frame| is the last frame from the remote peer in this stream.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero value is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_mem_recv()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_frame_recv_callback)
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked by `nghttp2_session_recv()` when an
 * invalid non-DATA frame is received.  The |error_code| is one of the
 * :enum:`nghttp2_error_code` and indicates the error.  When this
 * callback function is invoked, the library automatically submits
 * either RST_STREAM or GOAWAY frame.  The |user_data| pointer is the
 * third argument passed in to the call to
 * `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
 *
 * If frame is HEADERS or PUSH_PROMISE, the ``nva`` and ``nvlen``
 * member of their data structure are always ``NULL`` and 0
 * respectively.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_invalid_frame_recv_callback)
(nghttp2_session *session, const nghttp2_frame *frame,
 nghttp2_error_code error_code, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when a chunk of data in DATA frame is
 * received.  The |stream_id| is the stream ID this DATA frame belongs
 * to.  The |flags| is the flags of DATA frame which this data chunk
 * is contained.  ``(flags & NGHTTP2_FLAG_END_STREAM) != 0`` does not
 * necessarily mean this chunk of data is the last one in the stream.
 * You should use :type:`nghttp2_on_frame_recv_callback` to know all
 * data frames are received.  The |user_data| pointer is the third
 * argument passed in to the call to `nghttp2_session_client_new()` or
 * `nghttp2_session_server_new()`.
 *
 * If the application uses `nghttp2_session_mem_recv()`, it can return
 * :enum:`NGHTTP2_ERR_PAUSE` to make `nghttp2_session_mem_recv()`
 * return without processing further input bytes.  The memory by
 * pointed by the |data| is retained until
 * `nghttp2_session_mem_recv()` or `nghttp2_session_recv()` is called.
 * The application must retain the input bytes which was used to
 * produce the |data| parameter, because it may refer to the memory
 * region included in the input bytes.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_mem_recv()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_data_chunk_recv_callback)
(nghttp2_session *session, uint8_t flags, int32_t stream_id,
 const uint8_t *data, size_t len, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked just before the non-DATA frame |frame| is
 * sent.  The |user_data| pointer is the third argument passed in to
 * the call to `nghttp2_session_client_new()` or
 * `nghttp2_session_server_new()`.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_before_frame_send_callback)
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked after the frame |frame| is sent.  The
 * |user_data| pointer is the third argument passed in to the call to
 * `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_frame_send_callback)
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked after the non-DATA frame |frame| is not
 * sent because of the error.  The error is indicated by the
 * |lib_error_code|, which is one of the values defined in
 * :type:`nghttp2_error`.  The |user_data| pointer is the third
 * argument passed in to the call to `nghttp2_session_client_new()` or
 * `nghttp2_session_server_new()`.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_frame_not_send_callback)
(nghttp2_session *session, const nghttp2_frame *frame, int lib_error_code,
 void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when the stream |stream_id| is closed.
 * The reason of closure is indicated by the |error_code|.  The
 * stream_user_data, which was specified in `nghttp2_submit_request()`
 * or `nghttp2_submit_headers()`, is still available in this function.
 * The |user_data| pointer is the third argument passed in to the call
 * to `nghttp2_session_client_new()` or
 * `nghttp2_session_server_new()`.
 *
 * This function is also called for a stream in reserved state.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_stream_close_callback)
(nghttp2_session *session, int32_t stream_id, nghttp2_error_code error_code,
 void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when the received frame type is unknown.
 * The |head| is the pointer to the header of the received frame.  The
 * |headlen| is the length of the |head|.  According to the spec, the
 * |headlen| is always 8.  In other words, the |head| is the first 8
 * bytes of the received frame.  The |payload| is the pointer to the
 * data portion of the received frame.  The |payloadlen| is the length
 * of the |payload|.  This is the data after the length field.  The
 * |user_data| pointer is the third argument passed in to the call to
 * `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
 *
 * The implementation of this function must return 0 if it succeeds.
 * If nonzero is returned, it is treated as fatal error and
 * `nghttp2_session_recv()` and `nghttp2_session_send()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_unknown_frame_recv_callback)
(nghttp2_session *session,
 const uint8_t *head, size_t headlen,
 const uint8_t *payload, size_t payloadlen,
 void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when the reception of header block in
 * HEADERS or PUSH_PROMISE is started.  Each header name/value pair
 * will be emitted by :type:`nghttp2_on_header_callback`.
 *
 * The ``frame->hd.flags`` may not have
 * :enum:`NGHTTP2_FLAG_END_HEADERS` flag set, which indicates that one
 * or more CONTINUATION frames are involved.  But the application does
 * not need to care about that because the header name/value pairs are
 * emitted transparently regardless of CONTINUATION frames.
 *
 * The implementation of this function must return 0 if it succeeds or
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.  If nonzero value other than
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE` is returned, it is treated as
 * if :enum:`NGHTTP2_ERR_CALLBACK_FAILURE` is returned.  If
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE` is returned,
 * `nghttp2_session_mem_recv()` function will immediately return
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_begin_headers_callback)
(nghttp2_session *session, const nghttp2_frame *frame, void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when a header name/value pair is received
 * for the |frame|.  The |name| of length |namelen| is header name.
 * The |value| of length |valuelen| is header value.  The |flags| is
 * bitwise OR of one or more of :type:`nghttp2_nv_flag`.
 *
 * If :enum:`NGHTTP2_NV_FLAG_NO_INDEX` is set in |flags|, the receiver
 * must not index this name/value pair when forwarding it to the next
 * hop.
 *
 * When this callback is invoked, ``frame->hd.type`` is either
 * :enum:`NGHTTP2_HEADERS` or :enum:`NGHTTP2_PUSH_PROMISE`.  After all
 * header name/value pairs are processed with this callback, and no
 * error has been detected, :type:`nghttp2_on_frame_recv_callback`
 * will be invoked.  If there is an error in decompression,
 * :type:`nghttp2_on_frame_recv_callback` for the |frame| will not be
 * invoked.
 *
 * The |name| may be ``NULL`` if the |namelen| is 0.  The same thing
 * can be said about the |value|.
 *
 * Please note that nghttp2 library does not perform any validity
 * check against the |name| and the |value|.  For example, the
 * |namelen| could be 0, and/or the |value| contains ``0x0a`` or
 * ``0x0d``.  The application must check them if it matters.  The
 * helper function `nghttp2_check_header_name()` and
 * `nghttp2_check_header_value()` provide simple validation against
 * HTTP2 header field construction rule.
 *
 * One more thing to note is that the |value| may contain ``NULL``
 * (``0x00``) characters.  It is used to concatenate header values
 * which share the same header field name.  The application should
 * split these values if it wants to get individual value.  This
 * concatenation is used in order to keep the ordering of headers.
 *
 * If the application uses `nghttp2_session_mem_recv()`, it can return
 * :enum:`NGHTTP2_ERR_PAUSE` to make `nghttp2_session_mem_recv()`
 * return without processing further input bytes.  The memory pointed
 * by |frame|, |name| and |value| parameters are retained until
 * `nghttp2_session_mem_recv()` or `nghttp2_session_recv()` is called.
 * The application must retain the input bytes which was used to
 * produce these parameters, because it may refer to the memory region
 * included in the input bytes.
 *
 * Returning :enum:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE` will close
 * the stream by issuing RST_STREAM with
 * :enum:`NGHTTP2_INTERNAL_ERROR`.  In this case,
 * :type:`nghttp2_on_frame_recv_callback` will not be invoked.
 *
 * The implementation of this function must return 0 if it succeeds.
 * It may return :enum:`NGHTTP2_ERR_PAUSE` or
 * :enum:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.  For other critical
 * failures, it must return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.  If
 * the other nonzero value is returned, it is treated as
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.  If
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE` is returned,
 * `nghttp2_session_recv()` and `nghttp2_session_mem_recv()` functions
 * immediately return :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef int (*nghttp2_on_header_callback)
(nghttp2_session *session,
 const nghttp2_frame *frame,
 const uint8_t *name, size_t namelen,
 const uint8_t *value, size_t valuelen,
 uint8_t flags,
 void *user_data);

/**
 * @functypedef
 *
 * Callback function invoked when the library asks application how
 * many padding bytes are required for the transmission of the
 * |frame|.  The application must choose the total length of payload
 * including padded bytes in range [frame->hd.length, max_payloadlen],
 * inclusive.  Choosing number not in this range will be treated as
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.  Returning
 * ``frame->hd.length`` means no padding is added.  Returning
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE` will make
 * `nghttp2_session_send()` function immediately return
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`.
 */
typedef ssize_t (*nghttp2_select_padding_callback)
(nghttp2_session *session,
 const nghttp2_frame *frame,
 size_t max_payloadlen,
 void *user_data);

/**
 * @struct
 *
 * Callback functions.
 */
typedef struct {
  /**
   * Callback function invoked when the |session| wants to send data
   * to the remote peer.  This callback is not necessary if the
   * application uses solely `nghttp2_session_mem_send()` to serialize
   * data to transmit.
   */
  nghttp2_send_callback send_callback;
  /**
   * Callback function invoked when the |session| wants to receive
   * data from the remote peer.  This callback is not necessary if the
   * application uses solely `nghttp2_session_mem_recv()` to process
   * received data.
   */
  nghttp2_recv_callback recv_callback;
  /**
   * Callback function invoked by `nghttp2_session_recv()` when a
   * frame is received.
   */
  nghttp2_on_frame_recv_callback on_frame_recv_callback;
  /**
   * Callback function invoked by `nghttp2_session_recv()` when an
   * invalid non-DATA frame is received.
   */
  nghttp2_on_invalid_frame_recv_callback on_invalid_frame_recv_callback;
  /**
   * Callback function invoked when a chunk of data in DATA frame is
   * received.
   */
  nghttp2_on_data_chunk_recv_callback on_data_chunk_recv_callback;
  /**
   * Callback function invoked before a non-DATA frame is sent.
   */
  nghttp2_before_frame_send_callback before_frame_send_callback;
  /**
   * Callback function invoked after a frame is sent.
   */
  nghttp2_on_frame_send_callback on_frame_send_callback;
  /**
   * The callback function invoked when a non-DATA frame is not sent
   * because of an error.
   */
  nghttp2_on_frame_not_send_callback on_frame_not_send_callback;
  /**
   * Callback function invoked when the stream is closed.
   */
  nghttp2_on_stream_close_callback on_stream_close_callback;
  /**
   * Callback function invoked when the received frame type is
   * unknown.
   */
  nghttp2_on_unknown_frame_recv_callback on_unknown_frame_recv_callback;
  /**
   * Callback function invoked when the reception of header block in
   * HEADERS or PUSH_PROMISE is started.
   */
  nghttp2_on_begin_headers_callback on_begin_headers_callback;
  /**
   * Callback function invoked when a header name/value pair is
   * received.
   */
  nghttp2_on_header_callback on_header_callback;
  /**
   * Callback function invoked when the library asks application how
   * many padding bytes are required for the transmission of the given
   * frame.
   */
  nghttp2_select_padding_callback select_padding_callback;
} nghttp2_session_callbacks;

struct nghttp2_option;

/**
 * @struct
 *
 * Configuration options for :type:`nghttp2_session`.  The details of
 * this structure are intentionally hidden from the public API.
 */
typedef struct nghttp2_option nghttp2_option;

/**
 * @function
 *
 * Initializes |*option_ptr| with default values.
 *
 * When the application finished using this object, it can use
 * `nghttp2_option_del()` to free its memory.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_option_new(nghttp2_option **option_ptr);

/**
 * @function
 *
 * Frees any resources allocated for |option|.  If |option| is
 * ``NULL``, this function does nothing.
 */
void nghttp2_option_del(nghttp2_option *option);

/**
 * @function
 *
 * This option prevents the library from sending WINDOW_UPDATE for a
 * stream automatically.  If this option is set to nonzero, the
 * library won't send WINDOW_UPDATE for a stream and the application
 * is responsible for sending WINDOW_UPDATE using
 * `nghttp2_submit_window_update`.  By default, this option is set to
 * zero.
 */
void nghttp2_option_set_no_auto_stream_window_update(nghttp2_option *option,
                                                     int val);

/**
 * @function
 *
 * This option prevents the library from sending WINDOW_UPDATE for a
 * connection automatically.  If this option is set to nonzero, the
 * library won't send WINDOW_UPDATE for a connection and the
 * application is responsible for sending WINDOW_UPDATE with stream ID
 * 0 using `nghttp2_submit_window_update`.  By default, this option is
 * set to zero.
 */
void nghttp2_option_set_no_auto_connection_window_update
(nghttp2_option *option, int val);

/**
 * @function
 *
 * This option sets the SETTINGS_MAX_CONCURRENT_STREAMS value of
 * remote endpoint as if it is received in SETTINGS frame.  Without
 * specifying this option, before the local endpoint receives
 * SETTINGS_MAX_CONCURRENT_STREAMS in SETTINGS frame from remote
 * endpoint, SETTINGS_MAX_CONCURRENT_STREAMS is unlimited.  This may
 * cause problem if local endpoint submits lots of requests initially
 * and sending them at once to the remote peer may lead to the
 * rejection of some requests.  Specifying this option to the sensible
 * value, say 100, may avoid this kind of issue. This value will be
 * overwritten if the local endpoint receives
 * SETTINGS_MAX_CONCURRENT_STREAMS from the remote endpoint.
 */
void nghttp2_option_set_peer_max_concurrent_streams(nghttp2_option *option,
                                                    uint32_t val);

/**
 * @function
 *
 * Initializes |*session_ptr| for client use.  The all members of
 * |callbacks| are copied to |*session_ptr|.  Therefore |*session_ptr|
 * does not store |callbacks|.  The |user_data| is an arbitrary user
 * supplied data, which will be passed to the callback functions.
 *
 * The :member:`nghttp2_session_callbacks.send_callback` must be
 * specified.  If the application code uses `nghttp2_session_recv()`,
 * the :member:`nghttp2_session_callbacks.recv_callback` must be
 * specified.  The other members of |callbacks| can be ``NULL``.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_session_client_new(nghttp2_session **session_ptr,
                               const nghttp2_session_callbacks *callbacks,
                               void *user_data);

/**
 * @function
 *
 * Initializes |*session_ptr| for server use.  The all members of
 * |callbacks| are copied to |*session_ptr|. Therefore |*session_ptr|
 * does not store |callbacks|.  The |user_data| is an arbitrary user
 * supplied data, which will be passed to the callback functions.
 *
 * The :member:`nghttp2_session_callbacks.send_callback` must be
 * specified.  If the application code uses `nghttp2_session_recv()`,
 * the :member:`nghttp2_session_callbacks.recv_callback` must be
 * specified.  The other members of |callbacks| can be ``NULL``.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_session_server_new(nghttp2_session **session_ptr,
                               const nghttp2_session_callbacks *callbacks,
                               void *user_data);

/**
 * @function
 *
 * Like `nghttp2_session_client_new()`, but with additional options
 * specified in the |option|.
 *
 * The |option| can be ``NULL`` and the call is equivalent to
 * `nghttp2_session_client_new()`.
 *
 * This function does not take ownership |option|.  The application is
 * responsible for freeing |option| if it finishes using the object.
 *
 * The library code does not refer to |option| after this function
 * returns.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_session_client_new2(nghttp2_session **session_ptr,
                                const nghttp2_session_callbacks *callbacks,
                                void *user_data,
                                const nghttp2_option *option);

/**
 * @function
 *
 * Like `nghttp2_session_server_new()`, but with additional options
 * specified in the |option|.
 *
 * The |option| can be ``NULL`` and the call is equivalent to
 * `nghttp2_session_server_new()`.
 *
 * This function does not take ownership |option|.  The application is
 * responsible for freeing |option| if it finishes using the object.
 *
 * The library code does not refer to |option| after this function
 * returns.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_session_server_new2(nghttp2_session **session_ptr,
                                const nghttp2_session_callbacks *callbacks,
                                void *user_data,
                                const nghttp2_option *option);

/**
 * @function
 *
 * Frees any resources allocated for |session|.  If |session| is
 * ``NULL``, this function does nothing.
 */
void nghttp2_session_del(nghttp2_session *session);

/**
 * @function
 *
 * Sends pending frames to the remote peer.
 *
 * This function retrieves the highest prioritized frame from the
 * outbound queue and sends it to the remote peer.  It does this as
 * many as possible until the user callback
 * :member:`nghttp2_session_callbacks.send_callback` returns
 * :enum:`NGHTTP2_ERR_WOULDBLOCK` or the outbound queue becomes empty.
 * This function calls several callback functions which are passed
 * when initializing the |session|.  Here is the simple time chart
 * which tells when each callback is invoked:
 *
 * 1. Get the next frame to send from outbound queue.
 * 2. Prepare transmission of the frame.
 * 3. If the control frame cannot be sent because some preconditions
 *    are not met (e.g., request HEADERS cannot be sent after GOAWAY),
 *    :member:`nghttp2_session_callbacks.on_frame_not_send_callback`
 *    is invoked.  Abort the following steps.
 * 4. If the frame is HEADERS, PUSH_PROMISE or DATA,
 *    :member:`nghttp2_session_callbacks.select_padding_callback` is
 *    invoked.
 * 5. If the frame is request HEADERS, the stream is opened here.
 * 6. :member:`nghttp2_session_callbacks.before_frame_send_callback` is
 *    invoked.
 * 7. :member:`nghttp2_session_callbacks.send_callback` is invoked one
 *    or more times to send the frame.
 * 8. :member:`nghttp2_session_callbacks.on_frame_send_callback` is
 *    invoked.
 * 9. If the transmission of the frame triggers closure of the stream,
 *    the stream is closed and
 *    :member:`nghttp2_session_callbacks.on_stream_close_callback` is
 *    invoked.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`
 *     The callback function failed.
 */
int nghttp2_session_send(nghttp2_session *session);

/**
 * @function
 *
 * Returns the serialized data to send.
 *
 * This function behaves like `nghttp2_session_send()` except that it
 * does not use :member:`nghttp2_session_callbacks.send_callback` to
 * transmit data.  Instead, it assigns the pointer to the serialized
 * data to the |*data_ptr| and returns its length.  The other
 * callbacks are called in the same way as they are in
 * `nghttp2_session_send()`.
 *
 * If no data is available to send, this function returns 0.
 *
 * This function may not return all serialized data in one invocation.
 * To get all data, call this function repeatedly until it returns 0
 * or one of negative error codes.
 *
 * The assigned |*data_ptr| is valid until the next call of
 * `nghttp2_session_mem_send()` or `nghttp2_session_send()`.
 *
 * The caller must send all data before sending the next chunk of
 * data.
 *
 * This function returns the length of the data pointed by the
 * |*data_ptr| if it succeeds, or one of the following negative error
 * codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
ssize_t nghttp2_session_mem_send(nghttp2_session *session,
                                 const uint8_t **data_ptr);

/**
 * @function
 *
 * Receives frames from the remote peer.
 *
 * This function receives as many frames as possible until the user
 * callback :member:`nghttp2_session_callbacks.recv_callback` returns
 * :enum:`NGHTTP2_ERR_WOULDBLOCK`.  This function calls several
 * callback functions which are passed when initializing the
 * |session|.  Here is the simple time chart which tells when each
 * callback is invoked:
 *
 * 1. :member:`nghttp2_session_callbacks.recv_callback` is invoked one
 *    or more times to receive frame header.
 * 2. If the frame is DATA frame:
 *
 *    1. :member:`nghttp2_session_callbacks.recv_callback` is invoked
 *       to receive DATA payload. For each chunk of data,
 *       :member:`nghttp2_session_callbacks.on_data_chunk_recv_callback`
 *       is invoked.
 *    2. If one DATA frame is completely received,
 *       :member:`nghttp2_session_callbacks.on_frame_recv_callback` is
 *       invoked.  If the reception of the frame triggers the
 *       closure of the stream,
 *       :member:`nghttp2_session_callbacks.on_stream_close_callback`
 *       is invoked.
 *
 * 3. If the frame is the control frame:
 *
 *    1. :member:`nghttp2_session_callbacks.recv_callback` is invoked
 *       one or more times to receive whole frame.
 *
 *    2. If the received frame is valid, then following actions are
 *       taken.  If the frame is either HEADERS or PUSH_PROMISE,
 *       :member:`nghttp2_session_callbacks.on_begin_headers_callback`
 *       is invoked.  Then
 *       :member:`nghttp2_session_callbacks.on_header_callback` is
 *       invoked for each header name/value pair.  After all name/value
 *       pairs are emitted successfully,
 *       :member:`nghttp2_session_callbacks.on_frame_recv_callback` is
 *       invoked.  For other frames,
 *       :member:`nghttp2_session_callbacks.on_frame_recv_callback` is
 *       invoked.
 *       If the reception of the frame triggers the closure of the
 *       stream,
 *       :member:`nghttp2_session_callbacks.on_stream_close_callback`
 *       is invoked.
 *    3. If the received frame is unpacked but is interpreted as
 *       invalid,
 *       :member:`nghttp2_session_callbacks.on_invalid_frame_recv_callback`
 *       is invoked.
 *    4. If the received frame type is unknown,
 *       :member:`nghttp2_session_callbacks.on_unknown_frame_recv_callback`
 *       is invoked.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_EOF`
 *     The remote peer did shutdown on the connection.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`
 *     The callback function failed.
 */
int nghttp2_session_recv(nghttp2_session *session);

/**
 * @function
 *
 * Processes data |in| as an input from the remote endpoint.  The
 * |inlen| indicates the number of bytes in the |in|.
 *
 * This function behaves like `nghttp2_session_recv()` except that it
 * does not use :member:`nghttp2_session_callbacks.recv_callback` to
 * receive data; the |in| is the only data for the invocation of this
 * function.  If all bytes are processed, this function returns.  The
 * other callbacks are called in the same way as they are in
 * `nghttp2_session_recv()`.
 *
 * In the current implementation, this function always tries to
 * processes all input data unless either an error occurs or
 * :enum:`NGHTTP2_ERR_PAUSE` is returned from
 * :member:`nghttp2_session_callbacks.on_header_callback` or
 * :member:`nghttp2_session_callbacks.on_data_chunk_recv_callback`.
 * If :enum:`NGHTTP2_ERR_PAUSE` is used, the return value includes the
 * number of bytes which was used to produce the data or frame for the
 * callback.
 *
 * This function returns the number of processed bytes, or one of the
 * following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_CALLBACK_FAILURE`
 *     The callback function failed.
 */
ssize_t nghttp2_session_mem_recv(nghttp2_session *session,
                                 const uint8_t *in, size_t inlen);

/**
 * @function
 *
 * Puts back previously deferred DATA frame in the stream |stream_id|
 * to the outbound queue.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The stream does not exist; or no deferred data exist; or data
 *     was deferred by flow control.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_session_resume_data(nghttp2_session *session, int32_t stream_id);

/**
 * @function
 *
 * Returns nonzero value if |session| wants to receive data from the
 * remote peer.
 *
 * If both `nghttp2_session_want_read()` and
 * `nghttp2_session_want_write()` return 0, the application should
 * drop the connection.
 */
int nghttp2_session_want_read(nghttp2_session *session);

/**
 * @function
 *
 * Returns nonzero value if |session| wants to send data to the remote
 * peer.
 *
 * If both `nghttp2_session_want_read()` and
 * `nghttp2_session_want_write()` return 0, the application should
 * drop the connection.
 */
int nghttp2_session_want_write(nghttp2_session *session);

/**
 * @function
 *
 * Returns stream_user_data for the stream |stream_id|.  The
 * stream_user_data is provided by `nghttp2_submit_request()`,
 * `nghttp2_submit_headers()` or
 * `nghttp2_session_set_stream_user_data()`.  Unless it is set using
 * `nghttp2_session_set_stream_user_data()`, if the stream is
 * initiated by the remote endpoint, stream_user_data is always
 * ``NULL``.  If the stream does not exist, this function returns
 * ``NULL``.
 */
void* nghttp2_session_get_stream_user_data(nghttp2_session *session,
                                           int32_t stream_id);

/**
 * @function
 *
 * Sets the |stream_user_data| to the stream denoted by the
 * |stream_id|.  If a stream user data is already set to the stream,
 * it is replaced with the |stream_user_data|.  It is valid to specify
 * ``NULL`` in the |stream_user_data|, which nullifies the associated
 * data pointer.
 *
 * It is valid to set the |stream_user_data| to the stream reserved by
 * PUSH_PROMISE frame.
 *
 * This function returns 0 if it succeeds, or one of following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The stream does not exist
 */
int nghttp2_session_set_stream_user_data(nghttp2_session *session,
                                         int32_t stream_id,
                                         void *stream_user_data);

/**
 * @function
 *
 * Returns the number of frames in the outbound queue.  This does not
 * include the deferred DATA frames.
 */
size_t nghttp2_session_get_outbound_queue_size(nghttp2_session *session);

/**
 * @function
 *
 * Returns the number of DATA payload in bytes received without
 * WINDOW_UPDATE transmission for the stream |stream_id|.  The local
 * (receive) window size can be adjusted by
 * `nghttp2_submit_window_update()`.  This function takes into account
 * that and returns effective data length.  In particular, if the
 * local window size is reduced by submitting negative
 * window_size_increment with `nghttp2_submit_window_update()`, this
 * function returns the number of bytes less than actually received.
 *
 * This function returns -1 if it fails.
 */
int32_t nghttp2_session_get_stream_effective_recv_data_length
(nghttp2_session *session, int32_t stream_id);

/**
 * @function
 *
 * Returns the local (receive) window size for the stream |stream_id|.
 * The local window size can be adjusted by
 * `nghttp2_submit_window_update()`.  This function takes into account
 * that and returns effective window size.
 *
 * This function returns -1 if it fails.
 */
int32_t nghttp2_session_get_stream_effective_local_window_size
(nghttp2_session *session, int32_t stream_id);

/**
 * @function
 *
 * Returns the number of DATA payload in bytes received without
 * WINDOW_UPDATE transmission for a connection.  The local (receive)
 * window size can be adjusted by `nghttp2_submit_window_update()`.
 * This function takes into account that and returns effective data
 * length.  In particular, if the local window size is reduced by
 * submitting negative window_size_increment with
 * `nghttp2_submit_window_update()`, this function returns the number
 * of bytes less than actually received.
 *
 * This function returns -1 if it fails.
 */
int32_t nghttp2_session_get_effective_recv_data_length
(nghttp2_session *session);

/**
 * @function
 *
 * Returns the local (receive) window size for a connection.  The
 * local window size can be adjusted by
 * `nghttp2_submit_window_update()`.  This function takes into account
 * that and returns effective window size.
 *
 * This function returns -1 if it fails.
 */
int32_t nghttp2_session_get_effective_local_window_size
(nghttp2_session *session);

/**
 * @function
 *
 * Returns the remote window size for a given stream |stream_id|.
 * This is the amount of flow-controlled payload (e.g., DATA) that the
 * local endpoint can send without WINDOW_UPDATE.
 *
 * This function returns -1 if it fails.
 */
int32_t nghttp2_session_get_stream_remote_window_size(nghttp2_session* session,
                                                      int32_t stream_id);

/**
 * @function
 *
 * Signals the session so that the connection should be terminated.
 *
 * GOAWAY frame with the given |error_code| will be submitted if it
 * has not been transmitted.  After the transmission, both
 * `nghttp2_session_want_read()` and `nghttp2_session_want_write()`
 * return 0.  If GOAWAY frame has already transmitted at the time when
 * this function is invoked, `nghttp2_session_want_read()` and
 * `nghttp2_session_want_write()` returns 0 immediately after this
 * function succeeds.
 *
 * This function should be called when the connection should be
 * terminated after sending GOAWAY.  If the remaining streams should
 * be processed after GOAWAY, use `nghttp2_submit_goaway()` instead.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_session_terminate_session(nghttp2_session *session,
                                      nghttp2_error_code error_code);

/**
 * @function
 *
 * Returns the value of SETTINGS |id| notified by a remote endpoint.
 */
uint32_t nghttp2_session_get_remote_settings(nghttp2_session *session,
                                             nghttp2_settings_id id);

/**
 * @function
 *
 * Performs post-process of HTTP Upgrade request.  This function can
 * be called from both client and server, but the behavior is very
 * different in each other.
 *
 * If called from client side, the |settings_payload| must be the
 * value sent in ``HTTP2-Settings`` header field and must be decoded
 * by base64url decoder.  The |settings_payloadlen| is the length of
 * |settings_payload|.  The |settings_payload| is unpacked and its
 * setting values will be submitted using `nghttp2_submit_settings()`.
 * This means that the client application code does not need to submit
 * SETTINGS by itself.  The stream with stream ID=1 is opened and the
 * |stream_user_data| is used for its stream_user_data.  The opened
 * stream becomes half-closed (local) state.
 *
 * If called from server side, the |settings_payload| must be the
 * value received in ``HTTP2-Settings`` header field and must be
 * decoded by base64url decoder.  The |settings_payloadlen| is the
 * length of |settings_payload|.  It is treated as if the SETTINGS
 * frame with that payload is received.  Thus, callback functions for
 * the reception of SETTINGS frame will be invoked.  The stream with
 * stream ID=1 is opened.  The |stream_user_data| is ignored.  The
 * opened stream becomes half-closed (remote).
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |settings_payload| is badly formed.
 * :enum:`NGHTTP2_ERR_PROTO`
 *     The stream ID 1 is already used or closed; or is not available.
 */
int nghttp2_session_upgrade(nghttp2_session *session,
                            const uint8_t *settings_payload,
                            size_t settings_payloadlen,
                            void *stream_user_data);

/**
 * @function
 *
 * Serializes the SETTINGS values |iv| in the |buf|.  The size of the
 * |buf| is specified by |buflen|.  The number of entries in the |iv|
 * array is given by |niv|.  The required space in |buf| for the |niv|
 * entries is ``8*niv`` bytes and if the given buffer is too small, an
 * error is returned.  This function is used mainly for creating a
 * SETTINGS payload to be sent with the ``HTTP2-Settings`` header
 * field in an HTTP Upgrade request.  The data written in |buf| is NOT
 * base64url encoded and the application is responsible for encoding.
 *
 * This function returns the number of bytes written in |buf|, or one
 * of the following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |iv| contains duplicate settings ID or invalid value.
 *
 * :enum:`NGHTTP2_ERR_INSUFF_BUFSIZE`
 *     The provided |buflen| size is too small to hold the output.
 */
ssize_t nghttp2_pack_settings_payload(uint8_t *buf,
                                      size_t buflen,
                                      const nghttp2_settings_entry *iv,
                                      size_t niv);

/**
 * @function
 *
 * Returns string describing the |lib_error_code|.  The
 * |lib_error_code| must be one of the :enum:`nghttp2_error`.
 */
const char* nghttp2_strerror(int lib_error_code);

/**
 * @function
 *
 * Initializes |pri_spec| with the |stream_id| of the stream to depend
 * on with |weight| and its exclusive flag.  If |exclusive| is
 * nonzero, exclusive flag is set.
 *
 * The |weight| must be in [:enum:`NGHTTP2_MIN_WEIGHT`,
 * :enum:`NGHTTP2_MAX_WEIGHT`], inclusive.
 */
void nghttp2_priority_spec_init(nghttp2_priority_spec *pri_spec,
                                int32_t stream_id, int32_t weight,
                                int exclusive);

/**
 * @function
 *
 * Initializes |pri_spec| with the default values.  The default values
 * are: stream_id = 0, weight = :macro:`NGHTTP2_DEFAULT_WEIGHT` and
 * exclusive = 0.
 */
void nghttp2_priority_spec_default_init(nghttp2_priority_spec *pri_spec);

/**
 * @function
 *
 * Returns nonzero if the |pri_spec| is filled with default values.
 */
int nghttp2_priority_spec_check_default(const nghttp2_priority_spec *pri_spec);

/**
 * @function
 *
 * Submits HEADERS frame and optionally one or more DATA frames.
 *
 * The |pri_spec| is priority specification of this request.  ``NULL``
 * means the default priority (see
 * `nghttp2_priority_spec_default_init()`).  To specify the priority,
 * use `nghttp2_priority_spec_init()`.  If |pri_spec| is not ``NULL``,
 * this function will copy its data members.
 *
 * The `pri_spec->weight` must be in [:enum:`NGHTTP2_MIN_WEIGHT`,
 * :enum:`NGHTTP2_MAX_WEIGHT`], inclusive.  If `pri_spec->weight` is
 * strictly less than :enum:`NGHTTP2_MIN_WEIGHT`, it becomes
 * :enum:`NGHTTP2_MIN_WEIGHT`.  If it is strictly greater than
 * :enum:`NGHTTP2_MAX_WEIGHT`, it becomes :enum:`NGHTTP2_MAX_WEIGHT`.
 *
 * The |nva| is an array of name/value pair :type:`nghttp2_nv` with
 * |nvlen| elements.  The value is opaque sequence of bytes and
 * therefore can contain NULL byte (0x0).  If the application requires
 * that the ordering of values for a single header field name
 * appearing in different header fields, it has to concatenate them
 * using NULL byte (0x0) before passing them to this function.
 *
 * HTTP/2 specification has requirement about header fields in the
 * request HEADERS.  See the specification for more details.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.
 *
 * If |data_prd| is not ``NULL``, it provides data which will be sent
 * in subsequent DATA frames.  In this case, a method that allows
 * request message bodies
 * (http://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9) must
 * be specified with ``:method`` key in |nva| (e.g. ``POST``).  This
 * function does not take ownership of the |data_prd|.  The function
 * copies the members of the |data_prd|.  If |data_prd| is ``NULL``,
 * HEADERS have END_STREAM set.  The |stream_user_data| is data
 * associated to the stream opened by this request and can be an
 * arbitrary pointer, which can be retrieved later by
 * `nghttp2_session_get_stream_user_data()`.
 *
 * This function returns assigned stream ID if it succeeds.  But that
 * stream is not opened yet.  The application must not submit frame to
 * that stream ID before
 * :member:`nghttp2_session_callbacks.before_frame_send_callback` is
 * called for this frame.
 *
 * This function returns assigned stream ID if it succeeds, or one of
 * the following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE`
 *     No stream ID is available because maximum stream ID was
 *     reached.
 */
int32_t nghttp2_submit_request(nghttp2_session *session,
                               const nghttp2_priority_spec *pri_spec,
                               const nghttp2_nv *nva, size_t nvlen,
                               const nghttp2_data_provider *data_prd,
                               void *stream_user_data);

/**
 * @function
 *
 * Submits response HEADERS frame and optionally one or more DATA
 * frames against the stream |stream_id|.
 *
 * The |nva| is an array of name/value pair :type:`nghttp2_nv` with
 * |nvlen| elements.  The value is opaque sequence of bytes and
 * therefore can contain NULL byte (0x0).  If the application requires
 * that the ordering of values for a single header field name
 * appearing in different header fields, it has to concatenate them
 * using NULL byte (0x0) before passing them to this function.
 *
 * HTTP/2 specification has requirement about header fields in the
 * response HEADERS.  See the specification for more details.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.
 *
 * If |data_prd| is not ``NULL``, it provides data which will be sent
 * in subsequent DATA frames.  This function does not take ownership
 * of the |data_prd|.  The function copies the members of the
 * |data_prd|.  If |data_prd| is ``NULL``, HEADERS will have
 * END_STREAM flag set.
 *
 * This method can be used as normal HTTP response and push response.
 * When pushing a resource using this function, the |session| must be
 * configured using `nghttp2_session_server_new()` or its variants and
 * the target stream denoted by the |stream_id| must be reserved using
 * `nghttp2_submit_push_promise()`.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_submit_response(nghttp2_session *session,
                            int32_t stream_id,
                            const nghttp2_nv *nva, size_t nvlen,
                            const nghttp2_data_provider *data_prd);

/**
 * @function
 *
 * Submits HEADERS frame. The |flags| is bitwise OR of the
 * following values:
 *
 * * :enum:`NGHTTP2_FLAG_END_STREAM`
 *
 * If |flags| includes :enum:`NGHTTP2_FLAG_END_STREAM`, this frame has
 * END_STREAM flag set.
 *
 * The library handles the CONTINUATION frame internally and it
 * correctly sets END_HEADERS to the last sequence of the PUSH_PROMISE
 * or CONTINUATION frame.
 *
 * If the |stream_id| is -1, this frame is assumed as request (i.e.,
 * request HEADERS frame which opens new stream).  In this case, the
 * assigned stream ID will be returned.  Otherwise, specify stream ID
 * in |stream_id|.
 *
 * The |pri_spec| is priority specification of this request.  ``NULL``
 * means the default priority (see
 * `nghttp2_priority_spec_default_init()`).  To specify the priority,
 * use `nghttp2_priority_spec_init()`.  If |pri_spec| is not ``NULL``,
 * this function will copy its data members.
 *
 * The `pri_spec->weight` must be in [:enum:`NGHTTP2_MIN_WEIGHT`,
 * :enum:`NGHTTP2_MAX_WEIGHT`], inclusive.  If `pri_spec->weight` is
 * strictly less than :enum:`NGHTTP2_MIN_WEIGHT`, it becomes
 * :enum:`NGHTTP2_MIN_WEIGHT`.  If it is strictly greater than
 * :enum:`NGHTTP2_MAX_WEIGHT`, it becomes :enum:`NGHTTP2_MAX_WEIGHT`.
 *
 * The |nva| is an array of name/value pair :type:`nghttp2_nv` with
 * |nvlen| elements.  The value is opaque sequence of bytes and
 * therefore can contain NULL byte (0x0).  If the application requires
 * that the ordering of values for a single header field name
 * appearing in different header fields, it has to concatenate them
 * using NULL byte (0x0) before passing them to this function.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.
 *
 * The |stream_user_data| is a pointer to an arbitrary data which is
 * associated to the stream this frame will open.  Therefore it is
 * only used if this frame opens streams, in other words, it changes
 * stream state from idle or reserved to open.
 *
 * This function is low-level in a sense that the application code can
 * specify flags directly.  For usual HTTP request,
 * `nghttp2_submit_request()` is useful.
 *
 * This function returns assigned stream ID if it succeeds and
 * |stream_id| is -1.  But that stream is not opened yet.  The
 * application must not submit frame to that stream ID before
 * :member:`nghttp2_session_callbacks.before_frame_send_callback` is
 * called for this frame.
 *
 * This function returns newly assigned stream ID if it succeeds and
 * |stream_id| is -1.  Otherwise, this function returns 0 if it
 * succeeds, or one of the following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE`
 *     No stream ID is available because maximum stream ID was
 *     reached.
 */
int32_t nghttp2_submit_headers(nghttp2_session *session, uint8_t flags,
                               int32_t stream_id,
                               const nghttp2_priority_spec *pri_spec,
                               const nghttp2_nv *nva, size_t nvlen,
                               void *stream_user_data);

/**
 * @function
 *
 * Submits one or more DATA frames to the stream |stream_id|.  The
 * data to be sent are provided by |data_prd|.  If |flags| contains
 * :enum:`NGHTTP2_FLAG_END_STREAM`, the last DATA frame has END_STREAM
 * flag set.  If |flags| contains :enum:`NGHTTP2_FLAG_END_SEGMENT`,
 * the last DATA frame has END_SEGMENT flag set.
 *
 * This function does not take ownership of the |data_prd|.  The
 * function copies the members of the |data_prd|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_DATA_EXIST`
 *     DATA has been already submitted and not fully processed yet.
 */
int nghttp2_submit_data(nghttp2_session *session, uint8_t flags,
                        int32_t stream_id,
                        const nghttp2_data_provider *data_prd);

/**
 * @function
 *
 * Submits PRIORITY frame to change the priority of stream |stream_id|
 * to the priority specification |pri_spec|.
 *
 * The |flags| is currently ignored and should be
 * :enum:`NGHTTP2_FLAG_NONE`.
 *
 * The |pri_spec| is priority specification of this request.  ``NULL``
 * is not allowed for this function. To specify the priority, use
 * `nghttp2_priority_spec_init()`.  This function will copy its data
 * members.
 *
 * The `pri_spec->weight` must be in [:enum:`NGHTTP2_MIN_WEIGHT`,
 * :enum:`NGHTTP2_MAX_WEIGHT`], inclusive.  If `pri_spec->weight` is
 * strictly less than :enum:`NGHTTP2_MIN_WEIGHT`, it becomes
 * :enum:`NGHTTP2_MIN_WEIGHT`.  If it is strictly greater than
 * :enum:`NGHTTP2_MAX_WEIGHT`, it becomes :enum:`NGHTTP2_MAX_WEIGHT`.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |pri_spec| is NULL; or trying to depend on itself.
 */
int nghttp2_submit_priority(nghttp2_session *session, uint8_t flags,
                            int32_t stream_id,
                            const nghttp2_priority_spec *pri_spec);

/**
 * @function
 *
 * Submits RST_STREAM frame to cancel/reject the stream |stream_id|
 * with the error code |error_code|.
 *
 * The |flags| is currently ignored and should be
 * :enum:`NGHTTP2_FLAG_NONE`.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_submit_rst_stream(nghttp2_session *session, uint8_t flags,
                              int32_t stream_id,
                              nghttp2_error_code error_code);

/**
 * @function
 *
 * Stores local settings and submits SETTINGS frame.  The |iv| is the
 * pointer to the array of :type:`nghttp2_settings_entry`.  The |niv|
 * indicates the number of :type:`nghttp2_settings_entry`.
 *
 * The |flags| is currently ignored and should be
 * :enum:`NGHTTP2_FLAG_NONE`.
 *
 * This function does not take ownership of the |iv|.  This function
 * copies all the elements in the |iv|.
 *
 * While updating individual stream's local window size, if the window
 * size becomes strictly larger than NGHTTP2_MAX_WINDOW_SIZE,
 * RST_STREAM is issued against such a stream.
 *
 * SETTINGS with :enum:`NGHTTP2_FLAG_ACK` is automatically submitted
 * by the library and application could not send it at its will.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The |iv| contains invalid value (e.g., initial window size
 *     strictly greater than (1 << 31) - 1.
 * :enum:`NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS`
 *     There is already another in-flight SETTINGS.  Note that the
 *     current implementation only allows 1 in-flight SETTINGS frame
 *     without ACK flag set.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_submit_settings(nghttp2_session *session, uint8_t flags,
                            const nghttp2_settings_entry *iv, size_t niv);


/**
 * @function
 *
 * Submits PUSH_PROMISE frame.
 *
 * The |flags| is currently ignored.  The library handles the
 * CONTINUATION frame internally and it correctly sets END_HEADERS to
 * the last sequence of the PUSH_PROMISE or CONTINUATION frame.
 *
 * The |stream_id| must be client initiated stream ID.
 *
 * The |nva| is an array of name/value pair :type:`nghttp2_nv` with
 * |nvlen| elements.  The value is opaque sequence of bytes and
 * therefore can contain NULL byte (0x0).  If the application requires
 * that the ordering of values for a single header field name
 * appearing in different header fields, it has to concatenate them
 * using NULL byte (0x0) before passing them to this function.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.
 *
 * The |promised_stream_user_data| is a pointer to an arbitrary data
 * which is associated to the promised stream this frame will open and
 * make it in reserved state.  It is available using
 * `nghttp2_session_get_stream_user_data()`.  The application can
 * access it in :type:`nghttp2_before_frame_send_callback` and
 * :type:`nghttp2_on_frame_send_callback` of this frame.
 *
 * This function returns assigned promised stream ID if it succeeds.
 * But that stream is not opened yet.  The application must not submit
 * frame to that stream ID before
 * :member:`nghttp2_session_callbacks.before_frame_send_callback` is
 * called for this frame.
 *
 * The client side is not allowed to use this function.
 *
 * This function returns assigned promised stream ID if it succeeds,
 * or one of the following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_PROTO`
 *     This function was invoked when |session| is initialized as
 *     client.
 * :enum:`NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE`
 *     No stream ID is available because maximum stream ID was
 *     reached.
 */
int32_t nghttp2_submit_push_promise(nghttp2_session *session, uint8_t flags,
                                    int32_t stream_id,
                                    const nghttp2_nv *nva, size_t nvlen,
                                    void *promised_stream_user_data);

/**
 * @function
 *
 * Submits PING frame.  You don't have to send PING back when you
 * received PING frame.  The library automatically submits PING frame
 * in this case.
 *
 * The |flags| is currently ignored and should be
 * :enum:`NGHTTP2_FLAG_NONE`.
 *
 * If the |opaque_data| is non ``NULL``, then it should point to the 8
 * bytes array of memory to specify opaque data to send with PING
 * frame.  If the |opaque_data| is ``NULL``, zero-cleared 8 bytes will
 * be sent as opaque data.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_submit_ping(nghttp2_session *session, uint8_t flags,
                        uint8_t *opaque_data);

/**
 * @function
 *
 * Submits GOAWAY frame with the error code |error_code|.
 *
 * The |flags| is currently ignored and should be
 * :enum:`NGHTTP2_FLAG_NONE`.
 *
 * If the |opaque_data| is not ``NULL`` and |opaque_data_len| is not
 * zero, those data will be sent as additional debug data.  The
 * library makes a copy of the memory region pointed by |opaque_data|
 * with the length |opaque_data_len|, so the caller does not need to
 * keep this memory after the return of this function.  If the
 * |opaque_data_len| is 0, the |opaque_data| could be ``NULL``.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * NGHTTP2_ERR_INVALID_ARGUMENT
 *     The |opaque_data_len| is too large.
 */
int nghttp2_submit_goaway(nghttp2_session *session, uint8_t flags,
                          nghttp2_error_code error_code,
                          const uint8_t *opaque_data, size_t opaque_data_len);

/**
 * @function
 *
 * Submits WINDOW_UPDATE frame.
 *
 * The |flags| is currently ignored and should be
 * :enum:`NGHTTP2_FLAG_NONE`.
 *
 * If the |window_size_increment| is positive, the WINDOW_UPDATE with
 * that value as window_size_increment is queued.  If the
 * |window_size_increment| is larger than the received bytes from the
 * remote endpoint, the local window size is increased by that
 * difference.
 *
 * If the |window_size_increment| is negative, the local window size
 * is decreased by -|window_size_increment|.  If
 * :enum:`NGHTTP2_OPT_NO_AUTO_STREAM_WINDOW_UPDATE` (or
 * :enum:`NGHTTP2_OPT_NO_AUTO_CONNECTION_WINDOW_UPDATE` if |stream_id|
 * is 0) is not set and the library decided that the WINDOW_UPDATE
 * should be submitted, then WINDOW_UPDATE is queued with the current
 * received bytes count.
 *
 * If the |window_size_increment| is 0, the function does nothing and
 * returns 0.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_FLOW_CONTROL`
 *     The local window size overflow or gets negative.
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_submit_window_update(nghttp2_session *session, uint8_t flags,
                                 int32_t stream_id,
                                 int32_t window_size_increment);

/**
 * @function
 *
 * Submits ALTSVC frame with given parameters.
 *
 * The |flags| is currently ignored and should be
 * :enum:`NGHTTP2_FLAG_NONE`.
 *
 * Only the server can send the ALTSVC frame.  If |session| is
 * initialized as client, this function fails and returns
 * :enum:`NGHTTP2_ERR_INVALID_STATE`.
 *
 * If the |protocol_id_len| is 0, the |protocol_id| could be ``NULL``.
 *
 * If the |host_len| is 0, the |host| could be ``NULL``.
 *
 * If the |origin_len| is 0, the |origin| could be ``NULL``.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_PROTO`
 *     The function is invoked with |session| which was initialized as
 *     client.
 * :enum:`NGHTTP2_ERR_INVALID_ARGUMENT`
 *     The combined length of |protocol_id_len|, |host_len| and
 *     |origin_len| is is too large.
 */
int nghttp2_submit_altsvc(nghttp2_session *session, uint8_t flags,
                          int32_t stream_id,
                          uint32_t max_age, uint16_t port,
                          const uint8_t *protocol_id, size_t protocol_id_len,
                          const uint8_t *host, size_t host_len,
                          const uint8_t *origin, size_t origin_len);

/**
 * @function
 *
 * Compares ``lhs->name`` of length ``lhs->namelen`` bytes and
 * ``rhs->name`` of length ``rhs->namelen`` bytes.  Returns negative
 * integer if ``lhs->name`` is found to be less than ``rhs->name``; or
 * returns positive integer if ``lhs->name`` is found to be greater
 * than ``rhs->name``; or returns 0 otherwise.
 */
int nghttp2_nv_compare_name(const nghttp2_nv *lhs, const nghttp2_nv *rhs);

/**
 * @function
 *
 * A helper function for dealing with NPN in client side or ALPN in
 * server side.  The |in| contains peer's protocol list in preferable
 * order.  The format of |in| is length-prefixed and not
 * null-terminated.  For example, ``HTTP-draft-04/2.0`` and
 * ``http/1.1`` stored in |in| like this::
 *
 *     in[0] = 17
 *     in[1..17] = "HTTP-draft-04/2.0"
 *     in[18] = 8
 *     in[19..26] = "http/1.1"
 *     inlen = 27
 *
 * The selection algorithm is as follows:
 *
 * 1. If peer's list contains HTTP/2 protocol the library supports,
 *    it is selected and returns 1. The following step is not taken.
 *
 * 2. If peer's list contains ``http/1.1``, this function selects
 *    ``http/1.1`` and returns 0.  The following step is not taken.
 *
 * 3. This function selects nothing and returns -1 (So called
 *    non-overlap case).  In this case, |out| and |outlen| are left
 *    untouched.
 *
 * Selecting ``HTTP-draft-04/2.0`` means that ``HTTP-draft-04/2.0`` is
 * written into |*out| and its length (which is 17) is assigned to
 * |*outlen|.
 *
 * For ALPN, refer to
 * https://tools.ietf.org/html/draft-ietf-tls-applayerprotoneg-05
 *
 * See http://technotes.googlecode.com/git/nextprotoneg.html for more
 * details about NPN.
 *
 * For NPN, to use this method you should do something like::
 *
 *     static int select_next_proto_cb(SSL* ssl,
 *                                     unsigned char **out,
 *                                     unsigned char *outlen,
 *                                     const unsigned char *in,
 *                                     unsigned int inlen,
 *                                     void *arg)
 *     {
 *         int rv;
 *         rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
 *         if(rv == 1) {
 *             ((MyType*)arg)->http2_selected = 1;
 *         }
 *         return SSL_TLSEXT_ERR_OK;
 *     }
 *     ...
 *     SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, my_obj);
 *
 */
int nghttp2_select_next_protocol(unsigned char **out, unsigned char *outlen,
                                 const unsigned char *in, unsigned int inlen);

/**
 * @function
 *
 * Returns a pointer to a nghttp2_info struct with version information
 * about the run-time library in use.  The |least_version| argument
 * can be set to a 24 bit numerical value for the least accepted
 * version number and if the condition is not met, this function will
 * return a ``NULL``.  Pass in 0 to skip the version checking.
 */
nghttp2_info *nghttp2_version(int least_version);

/**
 * @function
 *
 * Returns nonzero if the :type:`nghttp2_error` library error code
 * |lib_error| is fatal.
 */
int nghttp2_is_fatal(int lib_error);

/**
 * @function
 *
 * Returns nonzero if HTTP header field name |name| of length |len| is
 * valid according to
 * http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-25#section-3.2
 *
 * Because this is a header field name in HTTP2, the upper cased alphabet
 * is treated as error.
 */
int nghttp2_check_header_name(const uint8_t *name, size_t len);

/**
 * @function
 *
 * Returns nonzero if HTTP header field value |value| of length |len|
 * is valid according to
 * http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-25#section-3.2
 *
 * Because this is HTTP2 header field value, it can contain NULL
 * character (0x00).
 */
int nghttp2_check_header_value(const uint8_t *value, size_t len);

/* HPACK API */

struct nghttp2_hd_deflater;

/**
 * @struct
 *
 * HPACK deflater object.
 */
typedef struct nghttp2_hd_deflater nghttp2_hd_deflater;

/**
 * @function
 *
 * Initializes |*deflater_ptr| for deflating name/values pairs.
 *
 * The |deflate_hd_table_bufsize_max| is the upper bound of header
 * table size the deflater will use.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_hd_deflate_new(nghttp2_hd_deflater **deflater_ptr,
                           size_t deflate_hd_table_bufsize_max);

/**
 * @function
 *
 * Deallocates any resources allocated for |deflater|.
 */
void nghttp2_hd_deflate_del(nghttp2_hd_deflater *deflater);

/**
 * @function
 *
 * Sets the availability of reference set in the |deflater|.  If
 * |no_refset| is nonzero, the deflater will first emit "Reference Set
 * Emptying" in the each subsequent invocation of
 * `nghttp2_hd_deflate_hd()` to clear up reference set.  By default,
 * the deflater uses reference set.
 */
void nghttp2_hd_deflate_set_no_refset(nghttp2_hd_deflater *deflater,
                                      uint8_t no_refset);

/**
 * @function
 *
 * Changes header table size of the |deflater| to
 * |settings_hd_table_bufsize_max| bytes.  This may trigger eviction
 * in the dynamic table.
 *
 * The |settings_hd_table_bufsize_max| should be the value received in
 * SETTINGS_HEADER_TABLE_SIZE.
 *
 * The deflater never uses more memory than
 * ``deflate_hd_table_bufsize_max`` bytes specified in
 * `nghttp2_hd_deflate_new()`.  Therefore, if
 * |settings_hd_table_bufsize_max| > ``deflate_hd_table_bufsize_max``,
 * resulting maximum table size becomes
 * ``deflate_hd_table_bufsize_max``.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_hd_deflate_change_table_size(nghttp2_hd_deflater *deflater,
                                         size_t settings_hd_table_bufsize_max);

/**
 * @function
 *
 * Deflates the |nva|, which has the |nvlen| name/value pairs, into
 * the |buf| of length |buflen|.
 *
 * If |buf| is not large enough to store the deflated header block,
 * this function fails with :enum:`NGHTTP2_ERR_INSUFF_BUFSIZE`.  The
 * caller should use `nghttp2_hd_deflate_bound()` to know the upper
 * bound of buffer size required to deflate given header name/value
 * pairs.
 *
 * Once this function fails, subsequent call of this function always
 * returns :enum:`NGHTTP2_ERR_HEADER_COMP`.
 *
 * After this function returns, it is safe to delete the |nva|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_HEADER_COMP`
 *     Deflation process has failed.
 * :enum:`NGHTTP2_ERR_INSUFF_BUFSIZE`
 *     The provided |buflen| size is too small to hold the output.
 */
ssize_t nghttp2_hd_deflate_hd(nghttp2_hd_deflater *deflater,
                              uint8_t *buf, size_t buflen,
                              nghttp2_nv *nva, size_t nvlen);

/**
 * @function
 *
 * Returns an upper bound on the compressed size after deflation of
 * |nva| of length |nvlen|.
 */
size_t nghttp2_hd_deflate_bound(nghttp2_hd_deflater *deflater,
                                const nghttp2_nv *nva, size_t nvlen);

struct nghttp2_hd_inflater;

/**
 * @struct
 *
 * HPACK inflater object.
 */
typedef struct nghttp2_hd_inflater nghttp2_hd_inflater;

/**
 * @function
 *
 * Initializes |*inflater_ptr| for inflating name/values pairs.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
WS_DLL_PUBLIC int nghttp2_hd_inflate_new(nghttp2_hd_inflater **inflater_ptr);

/**
 * @function
 *
 * Deallocates any resources allocated for |inflater|.
 */
void nghttp2_hd_inflate_del(nghttp2_hd_inflater *inflater);

/**
 * @function
 *
 * Changes header table size in the |inflater|.  This may trigger
 * eviction in the dynamic table.
 *
 * The |settings_hd_table_bufsize_max| should be the value transmitted
 * in SETTINGS_HEADER_TABLE_SIZE.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_hd_inflate_change_table_size(nghttp2_hd_inflater *inflater,
                                         size_t settings_hd_table_bufsize_max);

/**
 * @enum
 *
 * The flags for header inflation.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_HD_INFLATE_NONE = 0,
  /**
   * Indicates all headers were inflated.
   */
  NGHTTP2_HD_INFLATE_FINAL = 0x01,
  /**
   * Indicates a header was emitted.
   */
  NGHTTP2_HD_INFLATE_EMIT = 0x02
} nghttp2_hd_inflate_flag;

/**
 * @function
 *
 * Inflates name/value block stored in |in| with length |inlen|.  This
 * function performs decompression.  For each successful emission of
 * header name/value pair, :enum:`NGHTTP2_HD_INFLATE_EMIT` is set in
 * |*inflate_flags| and name/value pair is assigned to the |nv_out|
 * and the function returns.  The caller must not free the members of
 * |nv_out|.
 *
 * The |nv_out| may include pointers to the memory region in the |in|.
 * The caller must retain the |in| while the |nv_out| is used.
 *
 * The application should call this function repeatedly until the
 * ``(*inflate_flags) & NGHTTP2_HD_INFLATE_FINAL`` is nonzero and
 * return value is non-negative.  This means the all input values are
 * processed successfully.  Then the application must call
 * `nghttp2_hd_inflate_end_headers()` to prepare for the next header
 * block input.
 *
 * The caller can feed complete compressed header block.  It also can
 * feed it in several chunks.  The caller must set |in_final| to
 * nonzero if the given input is the last block of the compressed
 * header.
 *
 * This function returns the number of bytes processed if it succeeds,
 * or one of the following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_HEADER_COMP`
 *     Inflation process has failed.
 * :enum:`NGHTTP2_ERR_BUFFER_ERROR`
 *     The heder field name or value is too large.
 *
 * Example follows::
 *
 *     int inflate_header_block(nghttp2_hd_inflater *hd_inflater,
 *                              uint8_t *in, size_t inlen, int final)
 *     {
 *         int rv;
 *
 *         for(;;) {
 *             nghttp2_nv nv;
 *             int inflate_flags = 0;
 *
 *             rv = nghttp2_hd_inflate_hd(hd_inflater, &nv, &inflate_flags,
 *                                        in, inlen, final);
 *
 *             if(rv < 0) {
 *                 fprintf(stderr, "inflate failed with error code %d", rv);
 *                 return -1;
 *             }
 *
 *             in += rv;
 *             inlen -= rv;
 *
 *             if(inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
 *                 fwrite(nv.name, nv.namelen, 1, stderr);
 *                 fprintf(stderr, ": ");
 *                 fwrite(nv.value, nv.valuelen, 1, stderr);
 *                 fprintf(stderr, "\n");
 *             }
 *             if(inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
 *                 nghttp2_hd_inflate_end_headers(hd_inflater);
 *                 break;
 *             }
 *             if((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 &&
 *                inlen == 0) {
 *                break;
 *             }
 *         }
 *
 *         return 0;
 *     }
 *
 */
WS_DLL_PUBLIC ssize_t nghttp2_hd_inflate_hd(nghttp2_hd_inflater *inflater,
                              nghttp2_nv *nv_out, int *inflate_flags,
                              uint8_t *in, size_t inlen, int in_final);

/**
 * @function
 *
 * Signals the end of decompression for one header block.
 *
 * This function returns 0 if it succeeds. Currently this function
 * always succeeds.
 */
WS_DLL_PUBLIC int nghttp2_hd_inflate_end_headers(nghttp2_hd_inflater *inflater);

#ifdef __cplusplus
}
#endif

#endif /* NGHTTP2_H */
