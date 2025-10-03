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

/*
 * XXX - WS_ASSERT_ENABLED is tested in various if statements
 * below, so that we don't test various assertions unless
 * assertions are enabled. Compilers will often partially
 * evaluate (CONSTANT && (expression)) at compile time, so
 * that if CONSTANT is 0 the rest of the test isn't evaluated
 * and assumed to result in a false result, with the code in
 * the if branch being removed, and if CONSTANT is 1, the
 * code is treated as an if that tests the expression.
 *
 * This could mean that, if "defined but not used" tests are
 * being done, any variable tested in the expression may be warned
 * as "defined but not used" if WS_ASSERT_ENABLED is 0, causing
 * a pile of warnings if the variable isn't marked as unused
 * (especially true of parametre variables).
 *
 * However, some compilers - Clang, in my tests, and probably GCC,
 * due to tests in builds not failing - treat "if (0 && (expression))"
 * specially, pretending hat all variables in the expression are used,
 * even if they aren't used in the generated code. (At least in
 * Apple clang version 15.0.0 (clang-1500.1.0.2.5), it must be
 * exactly 0 - (0) doesn't have the same effect.)
 *
 * That's all very well, but, unfortunately Microsoft Visual Studio's
 * C compiler doesn't do that, so the variables have to be marked as
 * unused, which may cause warnings "used, but marked as unused"
 * warnings if the code is compiled with assertions enabled.
 */
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

/**
 * @def ws_assert_if_active
 * @brief Conditionally assert an expression.
 *
 * Evaluates the expression `expr` when `active` is true. If the expression
 * evaluates to false, triggers an error with a descriptive message via `ws_error()`.
 * When `active` is false, the expression is wrapped in a dead branch to
 * avoid execution while suppressing unused variable warnings, allowing the compiler
 * to optimize it away.
 *
 * @param active  Flag indicating whether assertions are enabled.
 * @param expr    Expression to be asserted.
 */
#define ws_assert_if_active(active, expr) \
        do {                                                \
            if ((active) && !(expr))                        \
                ws_error("assertion failed: %s", #expr);    \
        } while (0)

/**
 * @def ws_abort_if_fail
 * @brief Unconditionally assert an expression, typically for static analysis.
 *
 * Always evaluates `expr` and triggers an error via `ws_error()` if it fails.
 * Intended to satisfy static analyzers by ensuring the expression is checked,
 * regardless of runtime assertion settings.
 *
 * @param expr  Expression to assert.
 */
#define ws_abort_if_fail(expr) \
        ws_assert_if_active(true, expr)

/**
 * @def ws_assert
 * @brief Unconditionally assert an expression when assertions are enabled.
 *
 * Evaluates `expr` only if `WS_ASSERT_ENABLED` is true. The expression must not
 * produce side effects, as assertion state should not alter program behavior.
 * If the assertion fails, triggers an error via `ws_error()`.
 *
 * @param expr  Expression to assert.
 */
#define ws_assert(expr) \
        ws_assert_if_active(WS_ASSERT_ENABLED, expr)


/**
 * @def ws_assert_streq
 * @brief Assert that two strings are non-NULL and equal.
 *
 * Checks that both `s1` and `s2` are non-NULL and that their contents match.
 * If the assertion fails, triggers an error via `ws_error()`.
 *
 * @param s1  First string to compare.
 * @param s2  Second string to compare.
 */
#define ws_assert_streq(s1, s2) \
        ws_assert((s1) && (s2) && strcmp((s1), (s2)) == 0)

/**
 * @def ws_assert_utf8
 * @brief Assert that a string is valid UTF-8 when assertions are enabled.
 *
 * Validates that the given string `str` of length `len` is well-formed UTF-8.
 * If validation fails and assertions are enabled, logs an error with full context
 * including the location of the failure.
 *
 * @param str   Pointer to the string to validate.
 * @param len   Length of the string in bytes.
 */
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

 /**
 * @def ws_assert_not_reached
 * @brief Unconditionally abort execution if reached; always indicates a programming error.
 *
 * This macro is used to mark code paths that should never be executed.
 * Unlike conditional assertions, it is always active—even when assertions are disabled—
 * to prevent compiler warnings and ensure that unreachable code is clearly flagged.
 * Invoking this macro will trigger an error via `ws_error()` and terminate execution.
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

/**
 * @def ws_warn_badarg
 * @brief Log a warning for an invalid function argument.
 *
 * Emits a warning message indicating that the argument `str` is invalid.
 * Intended for use in macros that assert argument correctness without
 * causing inconsistent program state. Can be paired with a fatal log domain
 * for debugging purposes.
 *
 * @param str  String representation of the invalid argument expression.
 */
#define ws_warn_badarg(str) \
    ws_log_full(LOG_DOMAIN_EINVAL, LOG_LEVEL_WARNING, \
                    __FILE__, __LINE__, __func__, \
                    "invalid argument: %s", str)

/**
 * @def ws_return_str_if
 * @brief Return a formatted error string if an expression is true and assertions are enabled.
 *
 * Checks `expr` when `WS_ASSERT_ENABLED` is true. If the expression evaluates to true,
 * logs a warning with the expression string and returns a formatted error string
 * allocated in the given `scope`.
 *
 * @param expr   Expression to evaluate.
 * @param scope  Memory scope for allocating the returned error string.
 */
#define ws_return_str_if(expr, scope) \
        do { \
            if (WS_ASSERT_ENABLED && (expr)) { \
                ws_warn_badarg(#expr); \
                return wmem_strdup_printf(scope, "(invalid argument: %s)", #expr); \
            } \
        } while (0)

/**
 * @def ws_return_val_if
 * @brief Return a value if an expression is true and assertions are enabled.
 *
 * Checks `expr` when `WS_ASSERT_ENABLED` is true. If the expression evaluates to true,
 * logs a warning with the expression string and returns the specified value `val`.
 *
 * @param expr  Expression to evaluate.
 * @param val   Value to return if the expression is true.
 */
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
