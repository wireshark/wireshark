/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_ASSERT_H__
#define __WS_ASSERT_H__

#include <ws_symbol_export.h>
#include <ws_attributes.h>
#include <stdbool.h>
#include <string.h>

#ifdef WS_LOG_DOMAIN
#define _ASSERT_DOMAIN WS_LOG_DOMAIN
#else
#define _ASSERT_DOMAIN ""
#endif

#ifdef WS_DISABLE_ASSERT
#define _ASSERT_ENABLED false
#else
#define _ASSERT_ENABLED true
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

WS_DLL_PUBLIC
WS_NORETURN
void ws_assert_failed(const char *file, long line, const char *function,
                        const char *domain, const char *assertion,
                        bool unreachable);

/*
 * We don't want to execute the expression with WS_DISABLE_ASSERT because
 * it might be time and space costly and the goal here is to optimize for
 * WS_DISABLE_ASSERT. However removing it completely is not good enough
 * because it might generate many unused variable warnings. So we use
 * if (false) and let the compiler optimize away the dead execution branch.
 */
#define _ASSERT_IF_ACTIVE(active, expr) \
        do {                                                        \
            if ((active) && !(expr)) {                              \
                ws_assert_failed(__FILE__, __LINE__, __func__,      \
                                    _ASSERT_DOMAIN, #expr, false);  \
            }                                                       \
        } while (0)

/*
 * ws_abort_if_fail() is not conditional on WS_DISABLE_ASSERT.
 * Usually used to appease a static analyzer.
 */
#define ws_abort_if_fail(expr) \
        _ASSERT_IF_ACTIVE(true, expr)

/*
 * ws_assert() cannot produce side effects, otherwise code will
 * behave differently because of WS_DISABLE_ASSERT, and probably introduce
 * some difficult to track bugs.
 */
#define ws_assert(expr) \
        _ASSERT_IF_ACTIVE(_ASSERT_ENABLED, expr)


#define ws_assert_streq(s1, s2) \
        ws_assert((s1) && (s2) && strcmp((s1), (s2)) == 0)

/*
 * We don't want to disable ws_assert_not_reached() with WS_DISABLE_ASSERT.
 * That would blast compiler warnings everywhere for no benefit, not
 * even a miniscule performance gain. Reaching this function is always
 * a programming error and will unconditionally abort execution.
 *
 * Note: With g_assert_not_reached() if the compiler supports unreachable
 * built-ins (which recent versions of GCC and MSVC do) there is no warning
 * blast with g_assert_not_reached() and G_DISABLE_ASSERT. However if that
 * is not the case then g_assert_not_reached() is simply (void)0 and that
 * causes the spurious warnings, because the compiler can't tell anymore
 * that a certain code path is not used. We avoid that with
 * ws_assert_not_reached(). There is no reason to ever use a no-op here.
 */
#define ws_assert_not_reached() \
        ws_assert_failed(__FILE__, __LINE__, __func__, \
                            _ASSERT_DOMAIN, NULL, true)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WS_ASSERT_H__ */
