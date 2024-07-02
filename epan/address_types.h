/** @file
 * Definitions for address types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __ADDRESS_TYPES_H__
#define __ADDRESS_TYPES_H__

#include "address.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef int (*AddrValueToString)(const address* addr, char *buf, int buf_len);
typedef int (*AddrValueToStringLen)(const address* addr);
typedef unsigned (*AddrValueToByte)(const address* addr, uint8_t *buf, unsigned buf_len);
typedef int (*AddrFixedLen)(void);
typedef const char* (*AddrColFilterString)(const address* addr, bool src);
typedef int (*AddrNameResolutionLen)(void);
typedef const char* (*AddrNameResolutionToString)(const address* addr);

struct _address_type_t;
typedef struct _address_type_t address_type_t;

WS_DLL_PUBLIC int address_type_dissector_register(const char* name, const char* pretty_name,
                                    AddrValueToString to_str_func, AddrValueToStringLen str_len_func,
                                    AddrValueToByte to_bytes_func, AddrColFilterString col_filter_str_func, AddrFixedLen fixed_len_func,
                                    AddrNameResolutionToString name_res_str_func, AddrNameResolutionLen name_res_len_func);

WS_DLL_PUBLIC int address_type_get_by_name(const char* name);

int ipv4_to_str(const address* addr, char *buf, int buf_len);

void address_types_initialize(void);

/* Address type functions used by multiple (dissector) address types */
int none_addr_to_str(const address* addr, char *buf, int buf_len);
int none_addr_str_len(const address* addr);
int none_addr_len(void);

int ether_to_str(const address* addr, char *buf, int buf_len);
int ether_str_len(const address* addr);
int ether_len(void);
const char* ether_name_resolution_str(const address* addr);
int ether_name_resolution_len(void);



/* XXX - Temporary?  Here at least until all of the address type handling is finalized
 * Otherwise should be folded into address_types.c or just be handled with function pointers
 */
const char* address_type_column_filter_string(const address* addr, bool src);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __ADDRESS_TYPES_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
