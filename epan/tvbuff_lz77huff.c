/*
 * Decompression code for LZ77+Huffman. This encoding is used by
 * Microsoft in various file formats and protocols including SMB3.
 *
 * See MS-XCA.
 *
 * Initial code from Samba re-licensed with Samuel's permission.
 * Copyright (C) Samuel Cabrero 2017
 *
 * Glib-ification, extra error-checking and WS integration
 * Copyright (C) Aurélien Aptel 2019
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <stdlib.h> /* qsort */
#include <epan/exceptions.h>
#include <epan/tvbuff.h>
#include <epan/wmem_scopes.h>

#define MAX_INPUT_SIZE (16*1024*1024) /* 16MB */

#define TREE_SIZE 1024
#define ENCODED_TREE_SIZE 256
#define SYMBOL_INFO_SIZE (2*ENCODED_TREE_SIZE)

struct input {
	tvbuff_t *tvb;
	int offset;
	size_t size;
};

/**
 * Represents a node in a Huffman prefix code tree
 */
struct prefix_code_node {
	/* Stores the symbol encoded by this node in the prefix code tree */
	uint16_t symbol;

	/* Indicates whether this node is a leaf in the tree */
	uint8_t leaf;

	/*
	 * Points to the node's two children. Values are indexes in
	 * the tree node array. The value -1 is used to indicate that
	 * a particular child does not exist
	 */
	int16_t child[2];
};

/**
 * Represent information about a Huffman-encoded symbol
 */
struct prefix_code_symbol {
	/* Stores the symbol */
	uint16_t symbol;

	/* Stores the symbol’s Huffman prefix code length */
	uint16_t length;
};

/**
 * Represent a byte array as a bit string from which individual bits can
 * be read
 */
struct bitstring {
	/* The byte array */
	const struct input *input;

	/* The index in source from which the next set of bits will be pulled
         * when the bits in mask have been consumed */
	uint32_t bitstring_index;

	/* Stores the next bits to be consumed in the bit string */
	uint32_t mask;

	/* Stores the number of bits in mask that remain to be consumed */
	int32_t bits;
};

struct hf_tree {
	struct prefix_code_node *root;
	struct prefix_code_node nodes[TREE_SIZE];
};

static bool is_node_valid(struct hf_tree *tree, struct prefix_code_node *node)
{
        return (node && node >= tree->nodes && node < tree->nodes + TREE_SIZE);
}

/**
 * Links a symbol's prefix_code_node into its correct position in a Huffman
 * prefix code tree
 */
static int prefix_code_tree_add_leaf(struct hf_tree *tree,
				     uint32_t leaf_index,
				     uint32_t mask,
				     uint32_t bits,
				     uint32_t *out_index)
{
	struct prefix_code_node *node = &tree->nodes[0];
	uint32_t i = leaf_index + 1;
	uint32_t child_index;

	if (leaf_index >= TREE_SIZE)
		return -1;

	while (bits > 1) {
		bits = bits - 1;
		child_index = (mask >> bits) & 1;
		if (node->child[child_index] < 0) {
			if (i >= TREE_SIZE)
				return -1;
			node->child[child_index] = i;
			tree->nodes[i].leaf = false;
			i = i + 1;
		}
		node = tree->nodes + node->child[child_index];
		if (!is_node_valid(tree, node))
			return -1;
	}

	node->child[mask & 1] = leaf_index;

	*out_index = i;
	return 0;
}

/**
 * Determines the sort order of one prefix_code_symbol relative to another
 */
static int compare_symbols(const void *ve1, const void *ve2)
{
	const struct prefix_code_symbol *e1 = (const struct prefix_code_symbol *)ve1;
	const struct prefix_code_symbol *e2 = (const struct prefix_code_symbol *)ve2;

	if (e1->length < e2->length)
		return -1;
	else if (e1->length > e2->length)
		return 1;
	else if (e1->symbol < e2->symbol)
		return -1;
	else if (e1->symbol > e2->symbol)
		return 1;
	else
		return 0;
}

/**
 * Rebuilds the Huffman prefix code tree that will be used to decode symbols
 * during decompression
 */
static int PrefixCodeTreeRebuild( struct hf_tree *tree,
				 const struct input *input)
{
	struct prefix_code_symbol symbolInfo[SYMBOL_INFO_SIZE];
	uint32_t i, j, mask, bits;
	int rc;

	for (i = 0; i < TREE_SIZE; i++) {
		tree->nodes[i].symbol = 0;
		tree->nodes[i].leaf = false;
		tree->nodes[i].child[0] = -1;
		tree->nodes[i].child[1] = -1;
	}

	if (input->size < ENCODED_TREE_SIZE)
		return -1;

	for (i = 0; i < ENCODED_TREE_SIZE; i++) {
		symbolInfo[2*i].symbol = 2*i;
		symbolInfo[2*i].length = tvb_get_guint8(input->tvb, input->offset+i) & 15;
		symbolInfo[2*i+1].symbol = 2*i+1;
		symbolInfo[2*i+1].length = tvb_get_guint8(input->tvb, input->offset+i) >> 4;
	}

	qsort(symbolInfo, SYMBOL_INFO_SIZE, sizeof(symbolInfo[0]), compare_symbols);

	i = 0;
	while (i < SYMBOL_INFO_SIZE && symbolInfo[i].length == 0) {
		i = i + 1;
	}

	mask = 0;
	bits = 1;

	tree->root = &tree->nodes[0];
	tree->root->leaf = false;

	j = 1;
	for (; i < 512; i++) {
		//ws_assert(j < TREE_SIZE);
		if (j >= TREE_SIZE) {
			return -1;
		}
		tree->nodes[j].symbol = symbolInfo[i].symbol;
		tree->nodes[j].leaf = true;
		mask <<= symbolInfo[i].length - bits;
		bits = symbolInfo[i].length;
		rc = prefix_code_tree_add_leaf(tree, j, mask, bits, &j);
		if (rc)
			return rc;
		mask += 1;
	}

	return 0;
}

/**
 * Initializes a bitstream data structure
 */
static void bitstring_init(struct bitstring *bstr,
			   const struct input *input,
			   uint32_t bitstring_index)
{
	bstr->mask = tvb_get_letohs(input->tvb, input->offset+bitstring_index);
	bstr->mask <<= sizeof(bstr->mask) * 8 - 16;
	bitstring_index += 2;

	bstr->mask += tvb_get_letohs(input->tvb, input->offset+bitstring_index);
	bitstring_index += 2;

	bstr->bits = 32;
	bstr->input = input;
	bstr->bitstring_index = bitstring_index;
}

/**
 * Returns the next n bits from the front of a bit string.
 */
static uint32_t bitstring_lookup(struct bitstring *bstr, uint32_t n)
{
	if (n == 0 || bstr->bits < 0 || n > (uint32_t)bstr->bits) {
		return 0;
	}
	return bstr->mask >> (sizeof(bstr->mask) * 8 - n);
}

/**
 * Advances the bit string's cursor by n bits.
 */
static void bitstring_skip(struct bitstring *bstr, uint32_t n)
{
	bstr->mask = bstr->mask << n;
	bstr->bits = bstr->bits - n;

	if (bstr->bits < 16) {
		bstr->mask += tvb_get_letohs(bstr->input->tvb,
					     bstr->input->offset + bstr->bitstring_index)
			<< (16 - bstr->bits);
		bstr->bitstring_index = bstr->bitstring_index + 2;
		bstr->bits = bstr->bits + 16;
	}
}

/**
 * Returns the symbol encoded by the next prefix code in a bit string.
 */
static int prefix_code_tree_decode_symbol(struct hf_tree *tree,
					  struct bitstring *bstr,
					  uint32_t *out_symbol)
{
	uint32_t bit;
	struct prefix_code_node *node = tree->root;

	do {
		bit = bitstring_lookup(bstr, 1);
		bitstring_skip(bstr, 1);
		node = tree->nodes + node->child[bit];
		if (!is_node_valid(tree, node))
			return -1;
	} while (node->leaf == false);

	*out_symbol = node->symbol;
	return 0;
}

static bool do_uncompress(struct input *input,
			      wmem_array_t *obuf)
{
	uint32_t symbol;
	uint32_t length;
	int32_t match_offset;
	int rc;
	struct hf_tree tree = {0};
	struct bitstring bstr = {0};

	if (!input->tvb)
		return false;

	if (!input->size || input->size > MAX_INPUT_SIZE)
		return false;

	rc = PrefixCodeTreeRebuild(&tree, input);
	if (rc)
		return false;

	bitstring_init(&bstr, input, ENCODED_TREE_SIZE);

	while (1) {
		rc = prefix_code_tree_decode_symbol(&tree, &bstr, &symbol);
		if (rc < 0)
			return false;

		if (symbol < 256) {
			uint8_t v = symbol & 0xFF;
			wmem_array_append_one(obuf, v);
		} else {
			if (symbol == 256) {
				/* EOF symbol */
				return bstr.bitstring_index == bstr.input->size;
			}
			symbol = symbol - 256;
			length = symbol & 0xF;
			symbol = symbol >> 4;

			match_offset = (1U << symbol) + bitstring_lookup(&bstr, symbol);
			match_offset *= -1;

			if (length == 15) {
				if (bstr.bitstring_index >= bstr.input->size)
					return false;
				length = tvb_get_guint8(bstr.input->tvb,
							bstr.input->offset+bstr.bitstring_index) + 15;
				bstr.bitstring_index += 1;

				if (length == 270) {
					if (bstr.bitstring_index+1 >= bstr.input->size)
						return false;
					length = tvb_get_letohs(bstr.input->tvb, bstr.input->offset+bstr.bitstring_index);
					bstr.bitstring_index += 2;
				}
			}

			bitstring_skip(&bstr, symbol);

			length += 3;
			do {
				uint8_t byte;
				unsigned elem_count = wmem_array_get_count(obuf)+match_offset;

				if (wmem_array_try_index(obuf, elem_count, &byte))
					return false;
				wmem_array_append_one(obuf, byte);
				length--;
			} while (length != 0);
		}
	}
	return true;
}

tvbuff_t *
tvb_uncompress_lz77huff(tvbuff_t *tvb,
			const int offset,
			int input_size)
{
	volatile bool ok;
	wmem_allocator_t *pool;
	wmem_array_t *obuf;
	tvbuff_t *out;
	struct input input = {
			      .tvb = tvb,
			      .offset = offset,
			      .size = input_size
	};

	pool = wmem_allocator_new(WMEM_ALLOCATOR_SIMPLE);
	obuf = wmem_array_sized_new(pool, 1, input_size*2);

	TRY {
		ok = do_uncompress(&input, obuf);
	} CATCH_ALL {
		ok = false;
	}
	ENDTRY;

	if (ok) {
		/*
		 * Cannot pass a tvb free callback that frees the wmem
		 * pool, so we make an extra copy that uses bare
		 * pointers. This could be optimized if tvb API had a
		 * free pool callback of some sort.
		 */
		unsigned size = wmem_array_get_count(obuf);
		uint8_t *p = (uint8_t *)g_malloc(size);
		memcpy(p, wmem_array_get_raw(obuf), size);
		out = tvb_new_real_data(p, size, size);
		tvb_set_free_cb(out, g_free);
	} else {
		out = NULL;
	}

	wmem_destroy_allocator(pool);

	return out;
}

tvbuff_t *
tvb_child_uncompress_lz77huff(tvbuff_t *parent, tvbuff_t *tvb, const int offset, int in_size)
{
	tvbuff_t *new_tvb = tvb_uncompress_lz77huff(tvb, offset, in_size);
	if (new_tvb)
		tvb_set_child_real_data_tvbuff(parent, new_tvb);
	return new_tvb;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
