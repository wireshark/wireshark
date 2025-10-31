/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WTAP_INT_H__
#define __WTAP_INT_H__

#include "wtap.h"
#include <time.h>

/**
 * @brief Initialize file type subtypes for wiretap.
 */
void wtap_init_file_type_subtypes(void);

/**
 * @struct backwards_compatibiliity_lua_name
 * @brief Mapping between a Lua name and a file type.
 *
 * Used to support backwards compatibility for Lua scripts referencing legacy file type names.
 */
struct backwards_compatibiliity_lua_name {
    const char *name; /**< Legacy Lua name. */
    int ft;           /**< File type identifier. */
};

/**
 * @brief Retrieve the table of backwards compatibility Lua names.
 *
 * Returns a GArray of backwards_compatibiliity_lua_name entries.
 *
 * @return Pointer to GArray of compatibility mappings.
 */
WS_DLL_PUBLIC
const GArray *get_backwards_compatibility_lua_table(void);

/**
 * @brief Gets new section header block for new file, based on existing info.
 * @details Creates a new wtap_block_t section header block and only
 *          copies appropriate members of the SHB for a new file. In
 *          particular, the comment string is copied, and any custom options
 *          which should be copied are copied. The os, hardware, and
 *          application strings are *not* copied.
 *
 * @note Use wtap_free_shb() to free the returned section header.
 *
 * @param wth The wiretap session.
 * @return The new section header, which must be wtap_free_shb'd.
 */
GArray* wtap_file_get_shb_for_new_file(wtap *wth);

/**
 * @brief Generate an IDB, given a set of dump parameters, using the
 *      parameters' encapsulation type, snapshot length, and time stamp
 *      resolution. For use when a dump file has a given encapsulation type,
 *      and the source is not passing IDBs.
 * @note This requires that the encapsulation type and time stamp
 *      resolution not be per-packet; it will terminate the process
 *      if either of them are.
 *
 * @param params The wtap dump parameters.
 * @return A newly allocated IDB block.
 */
wtap_block_t wtap_dump_params_generate_idb(const wtap_dump_params *params);

/**
 * @brief Gets new name resolution info for new file, based on existing info.
 * @details Creates a new wtap_block_t of name resolution info and only
 *          copies appropriate members for a new file.
 *
 * @note Use wtap_free_nrb() to free the returned pointer.
 *
 * @param wth The wiretap session.
 * @return The new name resolution info, which must be freed.
 */
GArray* wtap_file_get_nrb_for_new_file(wtap *wth);

#endif /* __WTAP_INT_H__ */

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
