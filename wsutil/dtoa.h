/** @file
 * David M. Gay dtoa (double to ASCII string) implementation header file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: dtoa
 */

#pragma once

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Stores the closest decimal approximation to value in buf;
 * it suffices to declare buf
 *      char buf[32];
 *
 * Specifically, this finds the shortest possible string that when converted
 * back to a double will be equal to the original value. There is no single
 * value that can be passed to snprintf("%.*g") that will work for all cases.
 *
 * E.g., for the IEEE 754 double closest to 1/7th (0x1.2492492492492p-3) 17
 * (DBL_DECIMAL_DIG) digits are required; neither "0.1428571428571428" nor
 * "0.1428571428571429" suffice, converting to 0x1.249249249249p-3 and
 * 0x1.2492492492494p-3, respectively. However, for the double closest to
 * 0.2 (0x1.999999999999ap-3), the closest string with 17 significant digits
 * is "0.20000000000000001", not "0.2", even though both convert *to* the
 * same double and would test as equal. So DBL_DECIMAL_DIG is *sufficient*
 * for serialization but not necessary in all cases and can look particularly
 * worse in formats where trailing zeros are removed.
 *
 * Note C++17 provides std::to_chars to provide the same result, though the
 * difficulty in implementation caused this to be one of the last widely
 * supported features across C++ standard libraries. It is not part of the
 * C standard library functions.
 */
WS_DLL_PUBLIC char *dtoa_g_fmt(char *buf, double value);

#ifdef __cplusplus
}
#endif /* __cplusplus */
