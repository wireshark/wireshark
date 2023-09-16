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
#include <wsutil/wslog.h>
#include <wsutil/wmem/wmem.h>

#if defined(ENABLE_ASSERT)
#define WS_ASSERT_ENABLED       1
#elif defined(NDEBUG)
#define WS_ASSERT_ENABLED       0
#else
#define WS_ASSERT_ENABLED       1
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * We don't want to execute the expression without assertions because
 * it might be time and space costly and the goal here is to optimize for
 * that case. However removing it completely is not good enough
 * because it might generate many unused variable warnings. So we use
 * if (false) and let the compiler optimize away the dead execution branch.
 */
#define ws_assert_if_active(active, expr) \
        do {                                                \
            if ((active) && !(expr))                        \
                ws_error("assertion failed: %s", #expr);    \
        } while (0)

/*
 * ws_abort_if_fail() is not conditional on having assertions enabled.
 * Usually used to appease a static analyzer.
 */
#define ws_abort_if_fail(expr) \
        ws_assert_if_active(true, expr)

/*
 * ws_assert() cannot produce side effects, otherwise code will
 * behave differently because of having assertions enabled/disabled, and
 * probably introduce some difficult to track bugs.
 */
#define ws_assert(expr) \
        ws_assert_if_active(WS_ASSERT_ENABLED, expr)


#define ws_assert_streq(s1, s2) \
        ws_assert((s1) && (s2) && strcmp((s1), (s2)) == 0)

#define ws_assert_utf8(str, len) \
        do {                                                            \
            const char *__assert_endptr;                                \
            if (WS_ASSERT_ENABLED &&                                    \
                        !g_utf8_validate(str, len, &__assert_endptr)) { \
                ws_log_utf8_full(LOG_DOMAIN_UTF_8, LOG_LEVEL_ERROR,     \
                                    __FILE__, __LINE__, __func__,       \
                                    str, len, __assert_endptr);         \
            }                                                           \
        } while (0)

/*
 * We don't want to disable ws_assert_not_reached() with (optional) assertions
 * disabled.
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
        ws_error("assertion \"not reached\" failed")

/*
 * These macros can be used as an alternative to ws_assert() to
 * assert some condition on function arguments. This must only be used
 * to catch programming errors, in situations where an assertion is
 * appropriate. And it should only be used if failing the condition
 * doesn't necessarily lead to an inconsistent state for the program.
 *
 * It is possible to set the fatal log domain to "InvalidArg" to abort
 * execution for debugging purposes, if one of these checks fail.
 */

#define ws_warn_badarg(str) \
    ws_log_full(LOG_DOMAIN_EINVAL, LOG_LEVEL_WARNING, \
                    __FILE__, __LINE__, __func__, \
                    "invalid argument: %s", str)

#define ws_return_str_if(expr, scope) \
        do { \
            if (WS_ASSERT_ENABLED && (expr)) { \
                ws_warn_badarg(#expr); \
                return wmem_strdup_printf(scope, "(invalid argument: %s)", #expr); \
            } \
        } while (0)

#define ws_return_val_if(expr, val) \
        do { \
            if (WS_ASSERT_ENABLED && (expr)) { \
                ws_warn_badarg(#expr); \
                return (val); \
            } \
        } while (0)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WS_ASSERT_H__ */
