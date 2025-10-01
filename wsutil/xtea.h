/** @file
 *
 * Implementation of XTEA cipher
 * By Ahmad Fatoum <ahmad[AT]a3f.at>
 * Copyright 2017 Ahmad Fatoum
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __XTEA_H__
#define __XTEA_H__

/* Actual XTEA is big-endian, nevertheless there exist protocols that treat every block
 * as little endian, so we provide both
 */
#include "wireshark.h"

/**
 * @brief Decrypt a single 64-bit block using XTEA in ECB mode.
 *
 * @param plaintext     Output buffer for the decrypted 8-byte block.
 * @param ciphertext    Input buffer containing the encrypted 8-byte block.
 * @param key           128-bit key as four 32-bit words.
 * @param num_rounds    Number of XTEA rounds to perform.
 */
WS_DLL_PUBLIC void decrypt_xtea_ecb(uint8_t plaintext[8], const uint8_t ciphertext[8], const uint32_t key[4], unsigned num_rounds);

/**
 * @brief Decrypt a single 64-bit block using XTEA in little-endian ECB mode.
 *
 * @param plaintext     Output buffer for the decrypted 8-byte block.
 * @param ciphertext    Input buffer containing the encrypted 8-byte block.
 * @param key           128-bit key as four 32-bit words.
 * @param num_rounds    Number of XTEA rounds to perform.
 */
WS_DLL_PUBLIC void decrypt_xtea_le_ecb(uint8_t plaintext[8], const uint8_t ciphertext[8], const uint32_t key[4], unsigned num_rounds);

#endif /* __XTEA_H__ */

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
