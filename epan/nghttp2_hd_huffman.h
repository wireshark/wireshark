/* @file
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef NGHTTP2_HD_HUFFMAN_H
#define NGHTTP2_HD_HUFFMAN_H

#include <config.h>

#include <stdlib.h>
#include <stdint.h>

typedef enum {
  /* FSA accepts this state as the end of huffman encoding
     sequence. */
  NGHTTP2_HUFF_ACCEPTED = 1 << 14,
  /* This state emits symbol */
  NGHTTP2_HUFF_SYM = 1 << 15,
} nghttp2_huff_decode_flag;

typedef struct {
  /* fstate is the current huffman decoding state, which is actually
     the node ID of internal huffman tree with
     nghttp2_huff_decode_flag OR-ed.  We have 257 leaf nodes, but they
     are identical to root node other than emitting a symbol, so we
     have 256 internal nodes [1..255], inclusive.  The node ID 256 is
     a special node and it is a terminal state that means decoding
     failed. */
  uint16_t fstate;
  /* symbol if NGHTTP2_HUFF_SYM flag set */
  uint8_t sym;
} nghttp2_huff_decode;

typedef nghttp2_huff_decode huff_decode_table_type[16];

typedef struct {
  /* fstate is the current huffman decoding state. */
  uint16_t fstate;
} nghttp2_hd_huff_decode_context;

typedef struct {
  /* The number of bits in this code */
  uint32_t nbits;
  /* Huffman code aligned to LSB */
  uint32_t code;
} nghttp2_huff_sym;

extern const nghttp2_huff_sym huff_sym_table[];
extern const nghttp2_huff_decode huff_decode_table[][16];

#endif /* NGHTTP2_HD_HUFFMAN_H */
