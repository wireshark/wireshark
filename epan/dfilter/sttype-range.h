#ifndef STTYPE_RANGE_H
#define STTYPE_RANGE_H

#include "syntax-tree.h"

STTYPE_ACCESSOR_PROTOTYPE(header_field_info*, range, hfinfo)
STTYPE_ACCESSOR_PROTOTYPE(gint, range, start)
STTYPE_ACCESSOR_PROTOTYPE(gint, range, end)
STTYPE_ACCESSOR_PROTOTYPE(char*, range, start_error)
STTYPE_ACCESSOR_PROTOTYPE(char*, range, end_error)

/* Set a range, [x:y], [:y], [x:] */
void
sttype_range_set(stnode_t *node, stnode_t *field, stnode_t *start, stnode_t *end);

/* Set a single-byte lookup, [x] */
void
sttype_range_set1(stnode_t *node, stnode_t *field, stnode_t *offset);

#endif
