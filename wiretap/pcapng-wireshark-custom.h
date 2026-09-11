/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WTAP_PCAPNG_WIRESHARK_CUSTOM_H__
#define __WTAP_PCAPNG_WIRESHARK_CUSTOM_H__

#include "wtap.h"
#include "wtap_opttypes.h"
#include <stdbool.h>

/**
 * @brief Writes a process information block as a Wireshark custom block.
 *
 * @param wdh The wtap_dumper structure for the output file.
 * @param pib The WTAP_BLOCK_PROCESS_INFORMATION block to write.
 * @param err Pointer to an integer that will be set to an error code if an error occurs.
 * @param err_info Pointer to a string where error information will be stored on failure.
 * @return true if successful, false otherwise.
 */
extern bool
pcapng_write_wireshark_process_info_block(wtap_dumper *wdh, wtap_block_t pib,
                                          int *err, char **err_info);

#endif /* __WTAP_PCAPNG_WIRESHARK_CUSTOM_H__ */

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
