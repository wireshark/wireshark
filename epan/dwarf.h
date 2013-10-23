#ifndef __DWARF_H__
#define __DWARF_H__

#include <glib.h>

gint dissect_uleb128(tvbuff_t *tvb, gint offset, guint64 *value);
gint dissect_leb128(tvbuff_t *tvb, gint offset, gint64 *value);

#endif /* __DWARF_H__ */