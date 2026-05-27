/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __W_EYESDN_H__
#define __W_EYESDN_H__

#include "wtap.h"

/**
 * @brief Open an EyeSDN capture file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error message if an error occurs.
 * @return wtap_open_return_val The result of opening the file.
 */
wtap_open_return_val eyesdn_open(wtap *wth, int *err, char **err_info);

/**
 * @brief Identifies the encapsulated protocol type of a record in an EyeSDN log file.
 */
enum EyeSDN_TYPES {
    EYESDN_ENCAP_ISDN   = 0, /**< ISDN D-channel (Q.931/LAPD) signalling record */
    EYESDN_ENCAP_MSG,        /**< EyeSDN internal status or diagnostic message record */
    EYESDN_ENCAP_LAPB,       /**< LAPB (X.25 layer 2) data record */
    EYESDN_ENCAP_ATM,        /**< ATM cell record */
    EYESDN_ENCAP_MTP2,       /**< SS7 MTP2 signalling data record */
    EYESDN_ENCAP_DPNSS,      /**< DPNSS (Digital Private Network Signalling System) record */
    EYESDN_ENCAP_DASS2,      /**< DASS2 (Digital Access Signalling System No. 2) record */
    EYESDN_ENCAP_BACNET,     /**< BACnet (Building Automation and Control network) record */
    EYESDN_ENCAP_V5_EF       /**< V5 Envelope Function (V5.1/V5.2 access network) record */
};

#endif
