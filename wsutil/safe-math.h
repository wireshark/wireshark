/* Overflow-safe math helper macros
 *
 *   To the extent possible under law, the authors have waived all
 *   copyright and related or neighboring rights to this code.  For
 *   details, see the Creative Commons Zero 1.0 Universal license at
 *   https://creativecommons.org/publicdomain/zero/1.0/
 */

#pragma once

#include <setjmp.h>

#define ws_safe_op_jmp(op, res, a, b, env) \
    do { \
        if(ckd_##op(res, a, b)) { \
            longjmp(env, 1); \
        } \
    } while (0)

#define ws_safe_add_jmp(res, a, b, env) ws_safe_op_jmp(add, res, a, b, env)
#define ws_safe_sub_jmp(res, a, b, env) ws_safe_op_jmp(sub, res, a, b, env)
#define ws_safe_mul_jmp(res, a, b, env) ws_safe_op_jmp(mul, res, a, b, env)
