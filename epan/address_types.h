/* address_types.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __ADDRESS_TYPES_H__
#define __ADDRESS_TYPES_H__

#include "address.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef gboolean (*AddrValueToString)(const address* addr, gchar *buf, int buf_len);
typedef int (*AddrValueToStringLen)(const address* addr);

struct _address_type_t;
typedef struct _address_type_t address_type_t;

void address_type_register(int address_type, address_type_t *at);

int address_type_dissector_register(const char* name, const char* pretty_name,
                                    AddrValueToString to_str_func, AddrValueToStringLen str_len_func);

void address_types_initialize(void);

/* XXX - Temporary?  Here at least until all of the address type handling is finalized
 * Otherwise should be folded into address_types.c or just be handled with function pointers
 */
int address_type_get_length(const address* addr);
void address_type_to_string(const address* addr, gchar *buf, int buf_len);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __ADDRESS_TYPES_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
