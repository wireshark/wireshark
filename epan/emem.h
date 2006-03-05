/* emem.h
 * Definitions for ethereal memory management and garbage collection
 * Ronnie Sahlberg 2005
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include "gnuc_format_check.h"

/* Functions for handling memory allocation and garbage collection with 
 * a packet lifetime scope.
 * These functions are used to allocate memory that will only remain persistent
 * until ethereal starts dissecting the next packet in the list.
 * Everytime ethereal starts decoding the next packet all memory allocated
 * through these functions will be released back to the free pool.
 *
 * These functions are very fast and offer automatic garbage collection:
 * Everytime a new packet is dissected, all memory allocations done in
 * the previous packet is freed.
 */
/* Initialize packet-lifetime memory allocation pool. This function is called 
 * once when [t]ethereal is initialized to set up the required structures.
 */
void ep_init_chunk(void);

/* Allocate memory with a packet lifetime scope */
void *ep_alloc(size_t size);
#define ep_new(type) ((type*)ep_alloc(sizeof(type)))

/* Allocate memory with a packet lifetime scope and fill it with zeros*/
void* ep_alloc0(size_t size);
#define ep_new0(type) ((type*)ep_alloc0(sizeof(type)))

/* Duplicate a string with a packet lifetime scope */
gchar* ep_strdup(const gchar* src);

/* Duplicate at most n characters of a string with a packet lifetime scope */
gchar* ep_strndup(const gchar* src, size_t len);

/* Duplicate a buffer with a packet lifetime scope */
void* ep_memdup(const void* src, size_t len);

/* Create a formatted string with a packet lifetime scope */
gchar* ep_strdup_vprintf(const gchar* fmt, va_list ap);
gchar* ep_strdup_printf(const gchar* fmt, ...)
    GNUC_FORMAT_CHECK(printf, 1, 2);

/* allocates with a packet lifetime scope an array of type made of num elements */
#define ep_alloc_array(type,num) (type*)ep_alloc(sizeof(type)*(num))

/* 
 * Splits a string into a maximum of max_tokens pieces, using the given
 * delimiter. If max_tokens is reached, the remainder of string is appended
 * to the last token. Consecutive delimiters are treated as a single delimiter.
 *
 * the vector and all the strings are allocated with packet lifetime scope
 */
gchar** ep_strsplit(const gchar* string, const gchar* delimiter, int max_tokens);

/* release all memory allocated in the previous packet dissector */
void ep_free_all(void);


/* a stack implemented using ephemeral allocators */

typedef struct _ep_stack_frame_t** ep_stack_t;

struct _ep_stack_frame_t {
    void* payload;
    struct _ep_stack_frame_t* below;
    struct _ep_stack_frame_t* above;
};

/*
 * creates an empty stack with a packet lifetime scope
 */
ep_stack_t ep_stack_new(void);

/*
 * pushes item into stack, returns item
 */
void* ep_stack_push(ep_stack_t stack, void* item);

/*
 * pops an item from the stack
 */
void* ep_stack_pop(ep_stack_t stack);

/*
 * returns the item on top of the stack without popping it
 */
#define ep_stack_peek(stack) ((*(stack))->payload)


/* Functions for handling memory allocation and garbage collection with 
 * a capture lifetime scope.
 * These functions are used to allocate memory that will only remain persistent
 * until ethereal opens a new capture or capture file.
 * Everytime ethereal starts a new capture or opens a new capture file
 * all the data allocated through these functions will be released back 
 * to the free pool.
 *
 * These functions are very fast and offer automatic garbage collection.
 */
/* Initialize capture-lifetime memory allocation pool. This function is called 
 * once when [t]ethereal is initialized to set up the required structures.
 */
void se_init_chunk(void);

/* Allocate memory with a capture lifetime scope */
void *se_alloc(size_t size);

/* Allocate memory with a capture lifetime scope and fill it with zeros*/
void* se_alloc0(size_t size);

/* Duplicate a string with a capture lifetime scope */
gchar* se_strdup(const gchar* src);

/* Duplicate at most n characters of a string with a capture lifetime scope */
gchar* se_strndup(const gchar* src, size_t len);

/* Duplicate a buffer with a capture lifetime scope */
void* se_memdup(const void* src, size_t len);

/* Create a formatted string with a capture lifetime scope */
gchar* se_strdup_vprintf(const gchar* fmt, va_list ap);
gchar* se_strdup_printf(const gchar* fmt, ...)
    GNUC_FORMAT_CHECK(printf, 1, 2);

/* allocates with a capture lifetime scope an array of type made of num elements */
#define se_alloc_array(type,num) (type*)se_alloc(sizeof(type)*(num))

/* release all memory allocated */
void se_free_all(void);




/**************************************************************
 * binary trees with SE allocation 
 **************************************************************/
#define SE_TREE_RB_COLOR_RED	0x00
#define SE_TREE_RB_COLOR_BLACK	0x01
typedef struct _se_tree_node_t {
	struct _se_tree_node_t *parent;
	struct _se_tree_node_t *left;
	struct _se_tree_node_t *right;
	union {
		guint32 rb_color;
	};
	guint32 key32;
	void *data;
} se_tree_node_t;

/* list of all se trees so they can all be reset automatically when
 * we free all se memory
 */
/* Right now we only do basic red/black trees   but in the future we might want
 * to try something different, such as a tree where each node keeps track
 * of how many times it has been looked up, and letting often looked up
 * nodes bubble upwards in the tree using rotate_right/left.
 * That would probably be good for things like nfs filehandles 
 */
#define SE_TREE_TYPE_RED_BLACK	1
typedef struct _se_tree_t {
	struct _se_tree_t *next;
	int type;
	se_tree_node_t *tree;
} se_tree_t;
extern se_tree_t *se_trees;

se_tree_t *se_tree_create(int type);
void se_tree_insert32(se_tree_t *se_tree, guint32 key, void *data);
void *se_tree_lookup32(se_tree_t *se_tree, guint32 key);

#endif /* emem.h */
