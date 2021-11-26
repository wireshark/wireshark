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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

WS_DLL_PUBLIC
WS_NORETURN
void ws_assert_failed(const char *file, int line, const char *function,
                        const char *domain, const char *assertion,
                        bool unreachable);

#define _ASSERT_FAIL(expr) \
        ws_assert_failed(__FILE__, __LINE__, __func__, \
                            _ASSERT_DOMAIN, #expr, false)

/*
 * ws_abort_if_fail() is not conditional on WS_DISABLE_ASSERT.
 * Usually used to appease a static analyzer.
 */
#define ws_abort_if_fail(expr) \
        do { if (!(expr)) _ASSERT_FAIL(expr); } while (0)

#ifdef WS_DISABLE_ASSERT
/*
 * ws_assert() cannot produce side effects, otherwise code will
 * behave differently because of WS_DISABLE_ASSERT, and probably introduce
 * some difficult to track bugs.
 *
 * We don't want to execute the expression with WS_DISABLE_ASSERT because
 * it might be time and space costly and the goal here is to optimize for
 * WS_DISABLE_ASSERT. However removing it completely is not good enough
 * because it might generate many unused variable warnings. So we use
 * if (false) and let the compiler optimize away the dead execution branch.
 */
#define ws_assert(expr) do { if (false) ws_abort_if_fail(expr); } while (0)
#else
#define ws_assert(expr) ws_abort_if_fail(expr)
#endif

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
