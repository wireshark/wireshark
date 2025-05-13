/** @file
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __WTAP_PCAPNG_SYSDIG_INT_H__
#define __WTAP_PCAPNG_SYSDIG_INT_H__

#include "wtap.h"
#include "pcapng.h"
#include "pcapng_module.h"

extern bool
pcapng_read_sysdig_event_block(wtap* wth, FILE_T fh, pcapng_block_header_t* bh,
    section_info_t* section_info,
    wtapng_block_t* wblock,
    int* err, char** err_info);

extern bool
pcapng_write_sysdig_event_block(wtap_dumper* wdh, const wtap_rec* rec,
    int* err, char** err_info);

/* Process a Sysdig meta event block that we have just read. */
extern void
pcapng_process_meta_event(wtap* wth, wtapng_block_t* wblock);

extern bool
pcapng_read_meta_event_block(FILE_T fh, pcapng_block_header_t* bh,
    wtapng_block_t* wblock,
    int* err, char** err_info);

#endif

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
