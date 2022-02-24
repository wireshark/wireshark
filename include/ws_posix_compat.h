/* ws_posix_compat.h
 * Definitions for POSIX compatibility.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __POSIX_COMPAT_H__
#define __POSIX_COMPAT_H__

#include <stdint.h>
#include <limits.h>

#if !defined(SSIZE_MAX) && !defined(HAVE_SSIZE_T)
#if defined(_WIN64)

typedef int64_t ssize_t;

#define SSIZE_MAX INT64_MAX

#else /* !_WIN64 */

typedef signed long int ssize_t;

#define SSIZE_MAX LONG_MAX

#endif /* _WIN64 */
#endif /* !SSIZE_MAX && !HAVE_SSIZE_T */

#endif /* __POSIX_COMPAT_H__ */
