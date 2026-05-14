/**
 * Support for Apple Legacy and Custom pcapng blocks and options
 * Copyright 2025, Omer Shapira <oesh@apple.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WTAP_PCAPNG_DARWIN_CUSTOM_H__
#define __WTAP_PCAPNG_DARWIN_CUSTOM_H__

#include "wtap.h"
#include "pcapng.h"
#include "pcapng_module.h"
#include "wtap_opttypes.h"
#include <stdbool.h>

/**
 * @brief Writes a legacy Darwin process event block to the dump file.
 *
 * @param wdh The wtap_dumper structure for the output file.
 * @param sdata The wtap_block_t containing the data for the block.
 * @param err Pointer to an integer that will be set to an error code if an error occurs.
 * @return true if successful, false otherwise.
 */
extern bool
pcapng_write_legacy_darwin_process_event_block(wtap_dumper *wdh, wtap_block_t sdata, int *err);

/**
 * @brief Computes the size of an EPB legacy Darwin option based on its ID and value.
 *
 * @param option_id The ID of the option to compute the size for.
 * @param optval Pointer to the option value structure containing the data.
 * @return The size of the option in bytes, or 0 if the option is invalid or too large.
 */
extern uint32_t
pcapng_compute_epb_legacy_darwin_size(unsigned option_id, wtap_optval_t *optval);

/**
 * @brief Writes an EPB legacy Darwin option to a pcapng file.
 *
 * @param wdh Pointer to the wtap_dumper structure for writing the option.
 * @param sdata The block data associated with the option, if applicable.
 * @param option_id The ID of the option to write.
 * @param option_type The type of the option value.
 * @param optval Pointer to the option value structure containing the data to write.
 * @param err Pointer to an integer where any error code will be stored on failure.
 * @param err_info Pointer to a string where error information will be stored on failure.
 * @return true if the option was successfully written, false otherwise.
 */
extern bool
pcapng_write_epb_legacy_darwin_option(wtap_dumper *wdh, wtap_block_t sdata,
        unsigned option_id, wtap_opttype_e option_type, wtap_optval_t *optval, int *err, char **err_info);

#endif /* __WTAP_PCAPNG_DARWIN_CUSTOM_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
