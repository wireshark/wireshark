/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WTAP_PCAPNG_NETFLIX_CUSTOM_H
#define WTAP_PCAPNG_NETFLIX_CUSTOM_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Netflix custom options.
 */
extern bool
pcapng_read_nflx_custom_block(FILE_T fh, uint32_t block_payload_length,
                              section_info_t *section_info,
                              wtapng_block_t *wblock,
                              int *err, char **err_info);

extern bool
pcapng_process_nflx_custom_option(wtapng_block_t *wblock,
                                  section_info_t *section_info,
                                  const uint8_t *value, uint16_t length);
                                  
extern bool
pcapng_write_nflx_custom_block(wtap_dumper *wdh, const wtap_rec *rec, int *err,
                               char **err_info _U_);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* WTAP_PCAPNG_NETFLIX_CUSTOM_H */
