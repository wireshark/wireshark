/* syntax-tree.h
 *
 * $Id: syntax-tree.h,v 1.1 2001/02/01 20:21:18 gram Exp $
 *
 */
#ifndef SYNTAX_TREE_H
#define SYNTAX_TREE_H

#include <glib.h>
#include "cppmagic.h"

typedef enum {
	STTYPE_UNINITIALIZED,
	STTYPE_TEST,
	STTYPE_STRING,
	STTYPE_FIELD,
	STTYPE_FVALUE,
	STTYPE_RANGE,
	STTYPE_NUM_TYPES
} sttype_id_t;

typedef gpointer        (*STTypeNewFunc)(gpointer);
typedef void            (*STTypeFreeFunc)(gpointer);


/* Type information */
typedef struct {
	sttype_id_t		id;
	const char		*name;
	STTypeNewFunc		func_new;
	STTypeFreeFunc		func_free;
} sttype_t;

/* Node (type instance) information */
typedef struct {
	guint32		magic;
	sttype_t	*type;
	gpointer	data;

} stnode_t;

void
sttype_init(void);

void
sttype_cleanup(void);

void
sttype_register(sttype_t *type);

stnode_t*
stnode_new(sttype_id_t type_id, gpointer data);

void
stnode_init(stnode_t *node, sttype_id_t type_id, gpointer data);

void
stnode_free(stnode_t *node);

const char*
stnode_type_name(stnode_t *node);

sttype_id_t
stnode_type_id(stnode_t *node);

gpointer
stnode_data(stnode_t *node);

#define assert_magic(obj, mnum) \
        g_assert((obj)); \
        if ((obj)->magic != (mnum)) { \
                g_print("\nMagic num is 0x%08x, but should be 0x%08x", \
                                (obj)->magic, (mnum)); \
                g_assert((obj)->magic == (mnum)); \
        }




#define STTYPE_ACCESSOR(ret,type,attr,magicnum) \
	ret \
	CONCAT(CONCAT(CONCAT(sttype_,type),_),attr) (stnode_t *node) \
{\
	CONCAT(type,_t)	*value; \
	value = stnode_data(node);\
	assert_magic(value, magicnum); \
	return value->attr; \
}
	
#define STTYPE_ACCESSOR_PROTOTYPE(ret,type,attr) \
	ret \
	CONCAT(CONCAT(CONCAT(sttype_,type),_),attr) (stnode_t *node);


#endif
