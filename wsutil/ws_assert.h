/* ws_assert.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_ASSERT_H__
#define __WS_ASSERT_H__

#include <ws_attributes.h>
#include <stdlib.h>

/*
 * ws_assert() cannot produce side effects, otherwise code will
 * behave differently because of WS_DISABLE_ASSERT, and probably introduce
 * some nasty bugs.
 */
#ifndef WS_DISABLE_ASSERT
#define ws_assert(expr) g_assert(expr)
#else
#define ws_assert(expr) (void)0
#endif

/*
 * We don't want to disable ws_assert_not_reached() with WS_DISABLE_ASSERT.
 * That would blast compiler warnings everywhere for no benefit, not
 * even a miniscule performance gain.
 *
 * Note: If the compiler supports unreachable built-ins (which recent
 * versions of GCC and MSVC do) there is no warning blast with
 * g_assert_not_reached() and G_DISABLE_ASSERT. However if that is not
 * the case then g_assert_not_reached() is simply (void)0 and that
 * causes the spurious warnings, because the compiler can't tell anymore
 * that a certain code path is not used. We add the call to abort() so
 * that the function never returns, even with G_DISABLE_ASSERT.
 */
static inline
WS_NORETURN void ws_assert_not_reached(void) {
    g_assert_not_reached();
    abort();
};

/* ws_assert_bounds() is always enabled. For bounds check where the array
 * size is known sometimes it's just not worth disabling assertions.
 */
#define ws_assert_bounds(expr) g_assert_true(expr)

#endif /* __WS_ASSERT_H__ */
