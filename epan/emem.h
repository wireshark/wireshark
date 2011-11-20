/* emem.h
 * Definitions for Wireshark memory management and garbage collection
 * Ronnie Sahlberg 2005
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __EMEM_H__
#define __EMEM_H__

/** @file
 */
/**  Initialize all the memory allocation pools described below.
 *  This function must be called once when *shark initialize to set up the
 *  required structures.
 */
void emem_init(void);

/* Functions for handling memory allocation and garbage collection with
 * a packet lifetime scope.
 * These functions are used to allocate memory that will only remain persistent
 * until Wireshark starts dissecting the next packet in the list.
 * Everytime Wireshark starts decoding the next packet all memory allocated
 * through these functions will be released back to the free pool.
 *
 * These functions are very fast and offer automatic garbage collection:
 * Everytime a new packet is dissected, all memory allocations done in
 * the previous packet is freed.
 */

/** Allocate memory with a packet lifetime scope */
void *ep_alloc(size_t size) G_GNUC_MALLOC;
#define ep_new(type) ((type*)ep_alloc(sizeof(type)))

/** Allocate memory with a packet lifetime scope and fill it with zeros*/
void* ep_alloc0(size_t size) G_GNUC_MALLOC;
#define ep_new0(type) ((type*)ep_alloc0(sizeof(type)))

/** Duplicate a string with a packet lifetime scope */
gchar* ep_strdup(const gchar* src) G_GNUC_MALLOC;

/** Duplicate at most n characters of a string with a packet lifetime scope */
gchar* ep_strndup(const gchar* src, size_t len) G_GNUC_MALLOC;

/** Duplicate a buffer with a packet lifetime scope */
void* ep_memdup(const void* src, size_t len) G_GNUC_MALLOC;

/** Create a formatted string with a packet lifetime scope */
gchar* ep_strdup_vprintf(const gchar* fmt, va_list ap) G_GNUC_MALLOC;
gchar* ep_strdup_printf(const gchar* fmt, ...)
     G_GNUC_MALLOC G_GNUC_PRINTF(1, 2);

gchar *ep_strconcat(const gchar *string, ...) G_GNUC_MALLOC G_GNUC_NULL_TERMINATED;

/** allocates with a packet lifetime scope an array of type made of num elements */
#define ep_alloc_array(type,num) (type*)ep_alloc(sizeof(type)*(num))

/** allocates with a packet lifetime scope an array of type made of num elements,
 * initialised to zero.
 */
#define ep_alloc_array0(type,num) (type*)ep_alloc0(sizeof(type)*(num))

/**
 * Splits a string into a maximum of max_tokens pieces, using the given
 * delimiter. If max_tokens is reached, the remainder of string is appended
 * to the last token. Consecutive delimiters are treated as a single delimiter.
 *
 * The vector and all the strings are allocated with packet lifetime scope
 */
gchar** ep_strsplit(const gchar* string, const gchar* delimiter, int max_tokens);

/** release all memory allocated in the previous packet dissection */
void ep_free_all(void);


/** a stack implemented using ephemeral allocators */

typedef struct _ep_stack_frame_t** ep_stack_t;

struct _ep_stack_frame_t {
    void* payload;
    struct _ep_stack_frame_t* below;
    struct _ep_stack_frame_t* above;
};

/**
 * creates an empty stack with a packet lifetime scope
 */
ep_stack_t ep_stack_new(void) G_GNUC_MALLOC;

/**
 * pushes item into stack, returns item
 */
void* ep_stack_push(ep_stack_t stack, void* item);

/**
 * pops an item from the stack
 */
void* ep_stack_pop(ep_stack_t stack);

/**
 * returns the item on top of the stack without popping it
 */
#define ep_stack_peek(stack) ((*(stack))->payload)


/* Functions for handling memory allocation and garbage collection with
 * a capture lifetime scope.
 * These functions are used to allocate memory that will only remain persistent
 * until Wireshark opens a new capture or capture file.
 * Everytime Wireshark starts a new capture or opens a new capture file
 * all the data allocated through these functions will be released back
 * to the free pool.
 *
 * These functions are very fast and offer automatic garbage collection.
 */

/** Allocate memory with a capture lifetime scope */
void *se_alloc(size_t size) G_GNUC_MALLOC;
#define se_new(type) ((type*)se_alloc(sizeof(type)))

/** Allocate memory with a capture lifetime scope and fill it with zeros*/
void* se_alloc0(size_t size) G_GNUC_MALLOC;
#define se_new0(type) ((type*)se_alloc0(sizeof(type)))

/** Duplicate a string with a capture lifetime scope */
gchar* se_strdup(const gchar* src) G_GNUC_MALLOC;

/** Duplicate at most n characters of a string with a capture lifetime scope */
gchar* se_strndup(const gchar* src, size_t len) G_GNUC_MALLOC;

/** Duplicate a buffer with a capture lifetime scope */
void* se_memdup(const void* src, size_t len) G_GNUC_MALLOC;

/* Create a formatted string with a capture lifetime scope */
gchar* se_strdup_vprintf(const gchar* fmt, va_list ap) G_GNUC_MALLOC;
gchar* se_strdup_printf(const gchar* fmt, ...)
     G_GNUC_MALLOC G_GNUC_PRINTF(1, 2);

/** allocates with a capture lifetime scope an array of type made of num elements */
#define se_alloc_array(type,num) (type*)se_alloc(sizeof(type)*(num))

/** release all memory allocated */
void se_free_all(void);

/**************************************************************
 * slab allocator
 **************************************************************/
struct _emem_chunk_t;

/* Macros to initialize ws_memory_slab */
/* XXX, is G_MEM_ALIGN enough? http://mail.gnome.org/archives/gtk-devel-list/2004-December/msg00091.html */
#define WS_MEMORY_SLAB_INIT(type, count) { ((sizeof(type) + (G_MEM_ALIGN - 1)) & ~(G_MEM_ALIGN - 1)), count, NULL, NULL }
#define WS_MEMORY_SLAB_INIT_UNALIGNED(size, count) { size, count, NULL, NULL }

struct ws_memory_slab {
	const gint item_size;
	const gint count;

	struct _emem_chunk_t *chunk_list;
	void *freed;
};

void *sl_alloc(struct ws_memory_slab *mem_chunk);
void *sl_alloc0(struct ws_memory_slab *mem_chunk);
void sl_free(struct ws_memory_slab *mem_chunk, gpointer ptr);

/** release all memory allocated */
void sl_free_all(struct ws_memory_slab *mem_chunk);

/**************************************************************
 * binary trees
 **************************************************************/
typedef struct _emem_tree_node_t {
	struct _emem_tree_node_t *parent;
	struct _emem_tree_node_t *left;
	struct _emem_tree_node_t *right;
	struct {
#define EMEM_TREE_RB_COLOR_RED		0
#define EMEM_TREE_RB_COLOR_BLACK	1
		guint32 rb_color:1;
#define EMEM_TREE_NODE_IS_DATA		0
#define EMEM_TREE_NODE_IS_SUBTREE	1
		guint32 is_subtree:1;
	} u;
	guint32 key32;
	void *data;
} emem_tree_node_t;

/** Right now we only do basic red/black trees   but in the future we might want
 * to try something different, such as a tree where each node keeps track
 * of how many times it has been looked up, and letting often looked up
 * nodes bubble upwards in the tree using rotate_right/left.
 * That would probably be good for things like nfs filehandles
 */
#define EMEM_TREE_TYPE_RED_BLACK	1
typedef struct _emem_tree_t {
	struct _emem_tree_t *next;
	int type;
	const char *name;    /**< just a string to make debugging easier */
	emem_tree_node_t *tree;
	void *(*malloc)(size_t);
} emem_tree_t;

/* *******************************************************************
 * Tree functions for SE memory allocation scope
 * ******************************************************************* */
/** This function is used to create a se based tree with monitoring.
 * When the SE heap is released back to the system the pointer to the
 * tree is automatically reset to NULL.
 *
 * type is : EMEM_TREE_TYPE_RED_BLACK for a standard red/black tree.
 */
emem_tree_t *se_tree_create(int type, const char *name) G_GNUC_MALLOC;

/** This function is similar to the se_tree_create() call but with the
 * difference that when the se memory is released everything including the
 * pointer to the tree itself will be released.
 * This tree will not be just reset to zero, it will be completely forgotten
 * by the allocator.
 * Use this function for when you want to store the pointer to a tree inside
 * another structure that is also se allocated so that when the structure is
 * released, the tree will be completely released as well.
 */
emem_tree_t *se_tree_create_non_persistent(int type, const char *name) G_GNUC_MALLOC;

/** se_tree_insert32
 * Insert data into the tree and key it by a 32bit integer value
 */
#define se_tree_insert32 emem_tree_insert32

/** se_tree_lookup32
 * Retrieve the data at the search key. The search key is a 32bit integer value
 */
#define se_tree_lookup32 emem_tree_lookup32

/** se_tree_lookup32_le
 * Retrieve the data for the largest key that is less than or equal
 * to the search key.
 */
#define se_tree_lookup32_le emem_tree_lookup32_le

/** se_tree_insert32_array
 * Insert data into the tree and key it by a 32bit integer value
 */
#define se_tree_insert32_array emem_tree_insert32_array

/** se_tree_lookup32_array
 * Lookup data from the tree that is index by an array
 */
#define se_tree_lookup32_array emem_tree_lookup32_array

/** se_tree_lookup32_array_le
 * Retrieve the data for the largest key that is less than or equal
 * to the search key.
 */
#define se_tree_lookup32_array_le emem_tree_lookup32_array_le

/** Create a new string based hash table */
#define se_tree_create_string() se_tree_create(SE_TREE_TYPE_RED_BLACK)

/** Insert a new value under a string key */
#define se_tree_insert_string emem_tree_insert_string

/** Lookup the value under a string key */
#define se_tree_lookup_string emem_tree_lookup_string

/** Traverse a tree */
#define se_tree_foreach emem_tree_foreach


/* *******************************************************************
 * Tree functions for PE memory allocation scope
 * ******************************************************************* */
/* These trees have PErmanent allocation scope and will never be released
 */
emem_tree_t *pe_tree_create(int type, const char *name) G_GNUC_MALLOC;
#define pe_tree_insert32 emem_tree_insert32
#define pe_tree_lookup32 emem_tree_lookup32
#define pe_tree_lookup32_le emem_tree_lookup32_le
#define pe_tree_insert32_array emem_tree_insert32_array
#define pe_tree_lookup32_array emem_tree_lookup32_array
#define pe_tree_insert_string emem_tree_insert_string
#define pe_tree_lookup_string emem_tree_lookup_string
#define pe_tree_foreach emem_tree_foreach



/* ******************************************************************
 * Real tree functions
 * ****************************************************************** */

/** This function is used to insert a node indexed by a guint32 key value.
 * The data pointer should be allocated by the appropriate storage scope
 * so that it will be released at the same time as the tree itself is
 * destroyed.
 */
void emem_tree_insert32(emem_tree_t *se_tree, guint32 key, void *data);

/** This function will look up a node in the tree indexed by a guint32 integer
 * value.
 */
void *emem_tree_lookup32(emem_tree_t *se_tree, guint32 key);

/** This function will look up a node in the tree indexed by a guint32 integer
 * value.
 * The function will return the node that has the largest key that is
 * equal to or smaller than the search key, or NULL if no such key was
 * found.
 */
void *emem_tree_lookup32_le(emem_tree_t *se_tree, guint32 key);

typedef struct _emem_tree_key_t {
	guint32 length;			/**< length in guint32 words */
	guint32 *key;
} emem_tree_key_t;

/** This function is used to insert a node indexed by a sequence of guint32
 * key values.
 * The data pointer should be allocated by SE allocators so that the
 * data will be released at the same time as the tree itself is destroyed.
 *
 * Note: all the "key" members of the "key" argument MUST be aligned on
 * 32-bit boundaries; otherwise, this code will crash on platforms such
 * as SPARC that require aligned pointers.
 *
 * If you use ...32_array() calls you MUST make sure that every single node
 * you add to a specific tree always has a key of exactly the same number of
 * keylen words or things will most likely crash. Or at least that every single
 * item that sits behind the same top level node always have exactly the same
 * number of words.
 *
 * One way to guarantee this is the way that NFS does this for the
 * nfs_name_snoop_known tree which holds filehandles for both v2 and v3.
 * v2 filehandles are always 32 bytes (8 words) while v3 filehandles can have
 * any length (though 32 bytes are most common).
 * The NFS dissector handles this by providing a guint32 containing the length
 * as the very first item in this vector :
 *
 *			emem_tree_key_t fhkey[3];
 *
 *			fhlen=nns->fh_length;
 *			fhkey[0].length=1;
 *			fhkey[0].key=&fhlen;
 *			fhkey[1].length=fhlen/4;
 *			fhkey[1].key=nns->fh;
 *			fhkey[2].length=0;
 */
void emem_tree_insert32_array(emem_tree_t *se_tree, emem_tree_key_t *key, void *data);

/** This function will look up a node in the tree indexed by a sequence of
 * guint32 integer values.
 */
void *emem_tree_lookup32_array(emem_tree_t *se_tree, emem_tree_key_t *key);

/** This function will look up a node in the tree indexed by a
 * multi-part tree value.
 * The function will return the node that has the largest key that is
 * equal to or smaller than the search key, or NULL if no such key was
 * found.
 * Note:  The key returned will be "less" in key order.  The usefullness
 * of the returned node must be verified prior to use.
 */
void *emem_tree_lookup32_array_le(emem_tree_t *se_tree, emem_tree_key_t *key);

/** case insensitive strings as keys */
#define EMEM_TREE_STRING_NOCASE			0x00000001
/** Insert a new value under a string key */
void emem_tree_insert_string(emem_tree_t* h, const gchar* k, void* v, guint32 flags);

/** Lookup the value under a string key */
void* emem_tree_lookup_string(emem_tree_t* h, const gchar* k, guint32 flags);


/** traverse a tree. if the callback returns TRUE the traversal will end */
typedef gboolean (*tree_foreach_func)(void *value, void *userdata);

gboolean emem_tree_foreach(emem_tree_t* emem_tree, tree_foreach_func callback, void *user_data);


/* ******************************************************************
 * String buffers - Growable strings similar to GStrings
 * ****************************************************************** */

typedef struct _emem_strbuf_t {
    gchar *str;             /**< Points to the character data. It may move as text is       */
                            /*  added. The str field is null-terminated and so can        */
                            /*  be used as an ordinary C string.                          */
    gsize len;              /**< strlen: ie: length of str not including trailing '\0'      */
    gsize alloc_len;        /**< num bytes curently allocated for str: 1 .. MAX_STRBUF_LEN  */
    gsize max_alloc_len;    /**< max num bytes to allocate for str: 1 .. MAX_STRBUF_LEN     */
} emem_strbuf_t;

/*
 * The maximum length is limited to 64K. If you need something bigger, you
 * should probably use an actual GString or GByteArray.
 */

/**
 * Allocate an ephemeral string buffer with "unlimited" size.
 *
 * @param init The initial string for the buffer, or NULL to allocate an initial zero-length string.
 *
 * @return A newly-allocated string buffer.
 */
emem_strbuf_t *ep_strbuf_new(const gchar *init) G_GNUC_MALLOC;

/**
 * Allocate an ephemeral string buffer suitable for the protocol tree.
 * The string will never grow beyond the maximum tree item length.
 *
 * @param init The initial string for the buffer, or NULL to allocate an initial zero-length string.
 *
 * @return A newly-allocated string buffer.
 */
emem_strbuf_t *ep_strbuf_new_label(const gchar *init) G_GNUC_MALLOC;

/**
 * Allocate an ephemeral string buffer with enough initial space for alloc_len bytes
 * and a maximum of max_alloc_len bytes.
 *
 * @param alloc_len The initial size of the buffer. This value can be 0, but a nonzero
 * value is recommended.
 * @param max_alloc_len The maximum size of the buffer. 0 means "unlimited" (within
 * reason).
 *
 * @return A newly-allocated string buffer. str will be empty.
 */
emem_strbuf_t *ep_strbuf_sized_new(gsize alloc_len, gsize max_alloc_len) G_GNUC_MALLOC;

/**
 * Append vprintf-style formatted text to a string buffer.
 *
 * @param strbuf The ep_strbuf-allocated string buffer to append to.
 * @param format A printf-style string format.
 * @param ap The list of arguments to append.
 */
void ep_strbuf_append_vprintf(emem_strbuf_t *strbuf, const gchar *format, va_list ap);

/**
 * Apply printf-style formatted text to a string buffer.
 *
 * @param strbuf The ep_strbuf-allocated string buffer to set to.
 * @param format A printf-style string format.
 */
void ep_strbuf_printf(emem_strbuf_t *strbuf, const gchar *format, ...)
     G_GNUC_PRINTF(2, 3);

/**
 * Append printf-style formatted text to a string buffer.
 *
 * @param strbuf The ep_strbuf-allocated string buffer to append to.
 * @param format A printf-style string format.
 */
void ep_strbuf_append_printf(emem_strbuf_t *strbuf, const gchar *format, ...)
    G_GNUC_PRINTF(2, 3);

/**
 * Append a string to a string buffer.
 *
 * @param strbuf The ep_strbuf-allocated string buffer to append to.
 * @param str A null-terminated string.
 *
 * @return strbuf
 */
emem_strbuf_t *ep_strbuf_append(emem_strbuf_t *strbuf, const gchar *str);

/**
 * Append a character to a string buffer.
 *
 * @param strbuf The ep_strbuf-allocated string buffer to append to.
 * @param c The character to append.
 *
 * @return strbuf
 */
emem_strbuf_t *ep_strbuf_append_c(emem_strbuf_t *strbuf, const gchar c);

/**
 * Chop off the end of a string buffer.
 *
 * @param strbuf The ep_strbuf-allocated string buffer to append to.
 * @param len The new string length.
 *
 * @return strbuf
 */
emem_strbuf_t *ep_strbuf_truncate(emem_strbuf_t *strbuf, gsize len);

void emem_print_tree(emem_tree_t* emem_tree);

/* #define DEBUG_INTENSE_CANARY_CHECKS */

/** Helper to troubleshoot ep memory corruption.
 * If compiled and the environment variable WIRESHARK_DEBUG_EP_INTENSE_CANARY exists
 * it will check the canaries and when found corrupt stop there in the hope
 * the corruptor is still there in the stack.
 * Some checkpoints are already set in packet.c in strategic points
 * before and after dissection of a frame or a dissector call.
 */

#ifdef DEBUG_INTENSE_CANARY_CHECKS
void ep_check_canary_integrity(const char* fmt, ...)
    G_GNUC_PRINTF(1, 2);
#define EP_CHECK_CANARY(args) ep_check_canary_integrity args
#else
#define EP_CHECK_CANARY(args)
#endif

/**
 * Verify that the given pointer is of ephemeral type.
 *
 * @param ptr The pointer to verify
 *
 * @return TRUE if the pointer belongs to the ephemeral pool.
 */
gboolean ep_verify_pointer(const void *ptr);
/**
 * Verify that the given pointer is of seasonal type.
 *
 * @param ptr The pointer to verify
 *
 * @return TRUE if the pointer belongs to the seasonal pool.
 */
gboolean se_verify_pointer(const void *ptr);

#endif /* emem.h */
