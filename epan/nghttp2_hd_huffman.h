/* @file
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once
#include <stdlib.h>
#include <stdint.h>

/**
 * @brief Flag bits OR-ed into a Huffman FSA state to signal decode events.
 */
typedef enum {
    NGHTTP2_HUFF_ACCEPTED = 1 << 14, /**< FSA accepts this state as a valid terminal (end of Huffman-encoded sequence) */
    NGHTTP2_HUFF_SYM      = 1 << 15, /**< This state emits a decoded symbol; see nghttp2_huff_decode::sym */
} nghttp2_huff_decode_flag;

/**
 * @brief Represents the current state of an incremental HPACK Huffman decoder.
 *
 * The FSA has 256 internal nodes [1..255] inclusive. Node 256 is a special
 * terminal error state indicating decoding failure. Leaf nodes are identical
 * to their corresponding internal nodes except that they emit a symbol via
 * the NGHTTP2_HUFF_SYM flag. @ref fstate encodes both the node ID and any
 * active nghttp2_huff_decode_flag bits via bitwise OR.
 */
typedef struct {
    uint16_t fstate; /**< Current FSA node ID OR-ed with nghttp2_huff_decode_flag bits;
                      *   node 256 indicates a decoding failure */
    uint8_t  sym;    /**< Decoded symbol byte; valid only when fstate has NGHTTP2_HUFF_SYM set */
} nghttp2_huff_decode;

typedef nghttp2_huff_decode huff_decode_table_type[16];

/**
 * @brief Persistent context for incremental HPACK Huffman decoding across input chunks.
 */
typedef struct {
    uint16_t fstate; /**< Current Huffman FSA node ID, OR-ed with nghttp2_huff_decode_flag bits from the previous decode step */
} nghttp2_hd_huff_decode_context;

/**
 * @brief Huffman code entry for a single symbol in the HPACK static Huffman table.
 */
typedef struct {
    uint32_t nbits; /**< Number of bits in the Huffman code for this symbol */
    uint32_t code;  /**< Huffman code for this symbol, right-aligned (LSB-aligned) */
} nghttp2_huff_sym;

extern const nghttp2_huff_sym huff_sym_table[];
extern const nghttp2_huff_decode huff_decode_table[][16];
