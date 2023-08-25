
# Supported features
The HTTP3 dissector is a work in progress.

At the moment, the following aspects of HTTP3 are supported:
- Diseciton of different HTTP3 stream types
- Dissection of different HTTP3 frame types
- Dissection of HTTP header fields
- Dissection of QPACK instructions

In addition, the dissector suports decoding of the HTTP3
header fields. This ability requires `nghttp3` third-party library.

## High-level overview
The HTTP3 dissector is invoked by the QUIC dissector.

The essential call tree:
-  `dissect_http3`
   Main entry point. Depending on the stream type, invokes one of the following:
   -  `dissect_http3_uni_stream`
      Processes unidirectional streams, including the control streams,
      the QPACK encoder/decoder streams, and the HTTP3 server push streams.
      NOTE: the HTTP3 server push streams support is rudimental.
      -  `dissect_http3_qpack_enc`
         Dissects the QPACK encoder stream.
         If Wireshark was built with the optional `nghttp3` library,
         this function is also responsible on updating the state
         of the QPACK decoder.
   -  `dissect_http3_frame`
      Processed HTTP3 frames from the client-initiated bidirectional stream.
      Determines the frame type, and dispatches the call to one of the
      sub-dissectors:
      -  `dissect_http3_data`
         Dissects the `HTTP3_DATA` frames.
      -  `dissect_http3_headers`
         Dissects the `HTTP3_HEADER` frames.
         If Wireshark was built with the optional `nghttp3` library,
         this function attempts to decode the header fields, using
         the QPACK decoder.
      -  `dissect_http3_settings`
         Dissects the `HTTP3_SETTINGS` frames.

### Overview of the HTTP3 header dissection
The QPACK implementation from `nghttp3` requires a separate QPACK decoder instance
for every HTTP3 connection. The different HTTP3 streams that constitute a single
HTTP3 conneciton are sharing the same QPACK decoder instance.

The HTTP3 dissector interacts with the QPACK decoder in 2 ways:
-  On the reception of QPACK encoder data (which is delivered on a dedicated unidirectional stream),
   the dissector updates the connection's decoder instance.
-  On the reception of compressed HTTP3 headers, the dissector uses the connection's decoder
   to uncompress the HTTP headers.

If decompression succeeds, the dissector adds tree items to the packet tree. Otherwise,
the dissector adds expert info items.

The decompression can fail due to several reasons:
-  If the instruction count required by the compressed HTTP3 headers
   exceeds the maximal instruction count that the QPACK decoder is aware of,
   the decoding becomes "blocked". This situation can occure when the QUIC packets
   that carry the QPACK encoder instructions are dropped/reordered.
-  If the state of the decoder becomes invalid, which may happen when a "garbage"
   data is received on the QUIC stream.
-  Lastly, the decoding can fail if the underlying QUIC desegmentation is
   not working correctly.

### Overview of HTTP3 data frames dissection
The higher-level dissectors that could use HTTP3 (e.g. WebTransport) need to be able
to access the contents of a single HTTP3 stream as a contiguous span of data.

For that purpose, the HTTP3 dissector is defining a custom conversation finder.
See functions `http3_find_inner_conversation` and `http3_reset_inner_conversation`.

## Essential data structures
### File-level state
#### `HTTP3_CONN_INFO_MAP`
The `HTTP3_CONN_INFO_MAP` contains session-level information for every HTTP3 connection
in a PCAP file. This map is lazily allocated, and is cleared upon exiting the file scope.

### HTTP3 header caches
The dissector attempts to conserve memory, by avoding allocating memory for
duplicate header names/values. Instead, the dissector keeps the decoded names/values
in two caches: `HTTP3_HEADER_CACHE` and `HTTP3_HEADER_DEF_CACHE`. The former stores
the decoded HTTP3 header values, and the latter stores the decoded HTTP3 header names.

### Connection-level state
#### `http3_session_info_t`
The `http3_session_info_t` keeps the state of the QPACK decoder. Every HTTP3 connection
corresponds to a single session. In the future, the session may be shared between multiple
connections, to support connection migration or multipath HTTP3.
At the moment, there are no shared sessions.

### Stream-level state
#### `http3_stream_info_t`
The `http3_stream_info_t` keeps the information about the individual HTTP3 streams,
as well as mapping to the underlying QUIC streams.

### Frame-level state
#### `http3_header_field_t`
The `http3_header_field_t` keeps the information about a single HTTP header.
It contains both the encoded and the decoded representation of the header.
The actual decoded strings are stored in `HTTP3_HEADER_CACHE`/`HTTP3_HEADER_DEF_CACHE`;
the individual `http3_header_field_t` instances contain pointers to the strings.