/* json_dumper.c
 * Routines for serializing data as JSON.
 *
 * Copyright 2018, Peter Wu <peter@lekensteyn.nl>
 * Copyright (C) 2016 Jakub Zawadzki
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WSUTIL

#include <glib.h>
#include <string.h>

#include "json_dumper.h"
#include <wsutil/to_str.h>
#include <math.h>

#include <wsutil/array.h>
#include <wsutil/wslog.h>

/*
 * json_dumper.state[current_depth] describes a nested element:
 * - type: none/object/array/non-base64 value/base64 value
 * - has_name: Whether the object member name was set.
 *
 * (A base64 value isn't really a nested element, but that's a
 * convenient way of handling them, with a begin call that opens
 * the string with a double-quote, one or more calls to convert
 * raw bytes to base64 and add them to the value, and an end call
 * that finishes the base64 encoding, adds any remaining raw bytes
 * in base64 encoding, and closes the string with a double-quote.)
 */
enum json_dumper_element_type {
    JSON_DUMPER_TYPE_NONE = 0,
    JSON_DUMPER_TYPE_VALUE = 1,
    JSON_DUMPER_TYPE_OBJECT = 2,
    JSON_DUMPER_TYPE_ARRAY = 3,
    JSON_DUMPER_TYPE_BASE64 = 4,
};
#define JSON_DUMPER_TYPE(state)         ((enum json_dumper_element_type)((state) & 7))
#define JSON_DUMPER_HAS_NAME            (1 << 3)

static const char * const json_dumper_element_type_names[] = {
    [JSON_DUMPER_TYPE_NONE] = "none",
    [JSON_DUMPER_TYPE_VALUE] = "value",
    [JSON_DUMPER_TYPE_OBJECT] = "object",
    [JSON_DUMPER_TYPE_ARRAY] = "array",
    [JSON_DUMPER_TYPE_BASE64] = "base64"
};
#define NUM_JSON_DUMPER_ELEMENT_TYPE_NAMES array_length(json_dumper_element_type_names)

#define JSON_DUMPER_FLAGS_ERROR     (1 << 16)   /* Output flag: an error occurred. */

enum json_dumper_change {
    JSON_DUMPER_BEGIN,
    JSON_DUMPER_END,
    JSON_DUMPER_SET_NAME,
    JSON_DUMPER_SET_VALUE,
    JSON_DUMPER_WRITE_BASE64,
    JSON_DUMPER_FINISH,
};

/* Internal write buffer to reduce per-character stdio call overhead. */

static inline void
jd_flush(json_dumper *dumper)
{
    if (dumper->buf_pos > 0) {
        if (dumper->output_file) {
            fwrite(dumper->buf, 1, dumper->buf_pos, dumper->output_file);
        }
        if (dumper->output_string) {
            g_string_append_len(dumper->output_string, dumper->buf, dumper->buf_pos);
        }
        dumper->buf_pos = 0;
    }
}

static inline void
jd_buf_append(json_dumper *dumper, const char *s, size_t len)
{
    while (len > 0) {
        size_t avail = JD_BUF_SIZE - dumper->buf_pos;
        if (len <= avail) {
            memcpy(dumper->buf + dumper->buf_pos, s, len);
            dumper->buf_pos += len;
            return;
        }
        memcpy(dumper->buf + dumper->buf_pos, s, avail);
        dumper->buf_pos = JD_BUF_SIZE;
        jd_flush(dumper);
        s += avail;
        len -= avail;
    }
}

/* JSON Dumper putc */
static inline void
jd_putc(json_dumper *dumper, char c)
{
    if (dumper->buf_pos >= JD_BUF_SIZE) {
        jd_flush(dumper);
    }
    dumper->buf[dumper->buf_pos++] = c;
}

/* JSON Dumper puts */
static inline void
jd_puts(json_dumper *dumper, const char *s)
{
    jd_buf_append(dumper, s, strlen(s));
}

static inline void
jd_puts_len(json_dumper *dumper, const char *s, size_t len)
{
    jd_buf_append(dumper, s, len);
}

static void
jd_vprintf(json_dumper *dumper, const char *format, va_list args)
{
    /* Try to format directly into the remaining buffer space */
    size_t saved_pos = dumper->buf_pos;
    size_t avail = JD_BUF_SIZE - saved_pos;
    va_list args_copy;
    va_copy(args_copy, args);
    int n = vsnprintf(dumper->buf + saved_pos, avail, format, args);
    if (n >= 0 && (size_t)n < avail) {
        dumper->buf_pos = saved_pos + n;
        va_end(args_copy);
        return;
    }
    /* Didn't fit - restore position (discard truncated write), flush, retry */
    dumper->buf_pos = saved_pos;
    jd_flush(dumper);
    n = vsnprintf(dumper->buf, JD_BUF_SIZE, format, args_copy);
    if (n >= 0 && (size_t)n < JD_BUF_SIZE) {
        dumper->buf_pos = n;
    } else {
        /* Very large format - write directly */
        if (dumper->output_file) {
            vfprintf(dumper->output_file, format, args_copy);
        }
        if (dumper->output_string) {
            g_string_append_vprintf(dumper->output_string, format, args_copy);
        }
    }
    va_end(args_copy);
}

static void
json_puts_string(json_dumper *dumper, const char *str, bool dot_to_underscore)
{
    if (!str) {
        jd_puts(dumper, "null");
        return;
    }

    static const char json_cntrl[0x20][6] = {
        "u0000", "u0001", "u0002", "u0003", "u0004", "u0005", "u0006", "u0007", "b",     "t",     "n",     "u000b", "f",     "r",     "u000e", "u000f",
        "u0010", "u0011", "u0012", "u0013", "u0014", "u0015", "u0016", "u0017", "u0018", "u0019", "u001a", "u001b", "u001c", "u001d", "u001e", "u001f"
    };

    jd_putc(dumper, '"');
    if (!dot_to_underscore) {
        /* Fast path: scan for runs of characters that need no escaping */
        const char *p = str;
        while (*p) {
            const char *run_start = p;
            while ((unsigned char)*p >= 0x20 && *p != '\\' && *p != '"' &&
                   !(*p == '/' && p > str && *(p - 1) == '<')) {
                p++;
            }
            if (p > run_start) {
                jd_puts_len(dumper, run_start, p - run_start);
            }
            if (!*p) break;
            if ((unsigned char)*p < 0x20) {
                jd_putc(dumper, '\\');
                jd_puts(dumper, json_cntrl[(unsigned char)*p]);
            } else if (*p == '/' && p > str && *(p - 1) == '<') {
                jd_puts_len(dumper, "\\/", 2);
            } else {
                /* '\\' or '"' */
                jd_putc(dumper, '\\');
                jd_putc(dumper, *p);
            }
            p++;
        }
    } else {
        /* Dot-to-underscore path: scan for runs of plain chars (not dot/backslash/quote/control/</) */
        const char *p = str;
        while (*p) {
            const char *run_start = p;
            while ((unsigned char)*p >= 0x20 && *p != '\\' && *p != '"' && *p != '.' &&
                   !(*p == '/' && p > str && *(p - 1) == '<')) {
                p++;
            }
            if (p > run_start) {
                jd_puts_len(dumper, run_start, p - run_start);
            }
            if (!*p) break;
            if ((unsigned char)*p < 0x20) {
                jd_putc(dumper, '\\');
                jd_puts(dumper, json_cntrl[(unsigned char)*p]);
            } else if (*p == '/' && p > str && *(p - 1) == '<') {
                jd_puts_len(dumper, "\\/", 2);
            } else if (*p == '\\' || *p == '"') {
                jd_putc(dumper, '\\');
                jd_putc(dumper, *p);
            } else {
                /* dot -> underscore */
                jd_putc(dumper, '_');
            }
            p++;
        }
    }
    jd_putc(dumper, '"');
}

static inline uint8_t
json_dumper_get_prev_state(json_dumper *dumper)
{
    unsigned depth = dumper->current_depth;
    return depth != 0 ? dumper->state[depth - 1] : 0;
}

static inline uint8_t
json_dumper_get_curr_state(json_dumper *dumper)
{
    unsigned depth = dumper->current_depth;
    return dumper->state[depth];
}

/**
 * Called when a programming error is encountered where the JSON manipulation
 * state got corrupted. This could happen when pairing the wrong begin/end
 * calls, when writing multiple values for the same object, etc.
 */
static void
json_dumper_bad(json_dumper *dumper, const char *what)
{
    dumper->flags |= JSON_DUMPER_FLAGS_ERROR;
    if ((dumper->flags & JSON_DUMPER_FLAGS_NO_DEBUG)) {
        /* Console output can be slow, disable log calls to speed up fuzzing. */
        /*
         * XXX - should this call abort()?  If that flag isn't set,
         * ws_error() wou;d call it; is there any point in continuing
         * to do anything if we get here when fuzzing?
         */
        return;
    }

    if (dumper->output_file) {
        jd_flush(dumper);
        fflush(dumper->output_file);
    }
    char unknown_curr_type_name[10+1];
    char unknown_prev_type_name[10+1];
    const char *curr_type_name, *prev_type_name;
    uint8_t curr_state = json_dumper_get_curr_state(dumper);
    uint8_t curr_type = JSON_DUMPER_TYPE(curr_state);
    if (curr_type < NUM_JSON_DUMPER_ELEMENT_TYPE_NAMES) {
        curr_type_name = json_dumper_element_type_names[curr_type];
    } else {
        snprintf(unknown_curr_type_name, sizeof unknown_curr_type_name, "%u", curr_type);
        curr_type_name = unknown_curr_type_name;
    }
    if (dumper->current_depth != 0) {
        uint8_t prev_state = json_dumper_get_prev_state(dumper);
        uint8_t prev_type = JSON_DUMPER_TYPE(prev_state);
        if (prev_type < NUM_JSON_DUMPER_ELEMENT_TYPE_NAMES) {
            prev_type_name = json_dumper_element_type_names[prev_type];
        } else {
            snprintf(unknown_prev_type_name, sizeof unknown_prev_type_name, "%u", prev_type);
            prev_type_name = unknown_prev_type_name;
        }
    } else {
        prev_type_name = "(none)";
    }
    ws_error("json_dumper error: %s: current stack depth %u, current type %s, previous_type %s",
             what, dumper->current_depth, curr_type_name, prev_type_name);
    /* NOTREACHED */
}

static inline bool
json_dumper_stack_would_overflow(json_dumper *dumper)
{
    if (dumper->current_depth + 1 >= JSON_DUMPER_MAX_DEPTH) {
        json_dumper_bad(dumper, "JSON dumper stack overflow");
        return true;
    }
    return false;
}

static inline bool
json_dumper_stack_would_underflow(json_dumper *dumper)
{
    if (dumper->current_depth == 0) {
        json_dumper_bad(dumper, "JSON dumper stack underflow");
        return true;
    }
    return false;
}

/**
 * Checks that the dumper has not already had an error.  Fail, and
 * return false, to tell our caller not to do any more work, if it
 * has.
 */
static bool
json_dumper_check_previous_error(json_dumper *dumper)
{
    if ((dumper->flags & JSON_DUMPER_FLAGS_ERROR)) {
        json_dumper_bad(dumper, "previous corruption detected");
        return false;
    }
    return true;
}

static void
print_newline_indent(json_dumper *dumper, unsigned depth)
{
    if ((dumper->flags & JSON_DUMPER_FLAGS_PRETTY_PRINT)) {
        /* Pre-built indent: newline + up to 128 levels of 2-space indent */
        static const char indent_buf[1 + 256 + 1] =
            "\n                                                                "
            "                                                                "
            "                                                                "
            "                                                                ";
        size_t indent_len = depth * 2;
        if (indent_len <= 256) {
            jd_puts_len(dumper, indent_buf, 1 + indent_len);
        } else {
            jd_putc(dumper, '\n');
            for (unsigned i = 0; i < depth; i++) {
                jd_puts_len(dumper, "  ", 2);
            }
        }
    }
}

/**
 * Prints commas, newlines and indentation (if necessary). Used for array
 * values, object names and normal values (strings, etc.).
 */
static void
prepare_token(json_dumper *dumper)
{
    if (dumper->current_depth == 0) {
        // not part of an array or object.
        return;
    }
    uint8_t prev_state = dumper->state[dumper->current_depth - 1];

    // While processing the object value, reset the key state as it is consumed.
    dumper->state[dumper->current_depth - 1] &= ~JSON_DUMPER_HAS_NAME;

    switch (JSON_DUMPER_TYPE(prev_state)) {
        case JSON_DUMPER_TYPE_OBJECT:
            if ((prev_state & JSON_DUMPER_HAS_NAME)) {
                // Object key already set, value follows. No indentation needed.
                return;
            }
            break;
        case JSON_DUMPER_TYPE_ARRAY:
            break;
        default:
            // Initial values do not need indentation.
            return;
    }

    uint8_t curr_state = json_dumper_get_curr_state(dumper);
    if (curr_state != JSON_DUMPER_TYPE_NONE) {
        jd_putc(dumper, ',');
    }
    print_newline_indent(dumper, dumper->current_depth);
}

/**
 * Common code to open an object/array/base64 value, printing
 * an opening character.
 *
 * It also makes various correctness checks.
 */
static bool
json_dumper_begin_nested_element(json_dumper *dumper, enum json_dumper_element_type type)
{
    if (!json_dumper_check_previous_error(dumper)) {
        return false;
    }

    /* Make sure we won't overflow the dumper stack */
    if (json_dumper_stack_would_overflow(dumper)) {
        return false;
    }

    prepare_token(dumper);
    switch (type) {
        case JSON_DUMPER_TYPE_OBJECT:
            jd_putc(dumper, '{');
            break;
        case JSON_DUMPER_TYPE_ARRAY:
            jd_putc(dumper, '[');
            break;
        case JSON_DUMPER_TYPE_BASE64:
            dumper->base64_state = 0;
            dumper->base64_save = 0;

            jd_putc(dumper, '"');
            break;
        default:
            json_dumper_bad(dumper, "beginning unknown nested element type");
            return false;
    }

    dumper->state[dumper->current_depth] = type;
    /*
     * Guaranteed not to overflow, as json_dumper_stack_would_overflow()
     * returned false.
     */
    ++dumper->current_depth;
    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_NONE;
    return true;
}

/**
 * Common code to close an object/array/base64 value, printing a
 * closing character (and if necessary, it is preceded by newline
 * and indentation).
 *
 * It also makes various correctness checks.
 */
static bool
json_dumper_end_nested_element(json_dumper *dumper, enum json_dumper_element_type type)
{
    if (!json_dumper_check_previous_error(dumper)) {
        return false;
    }

    uint8_t prev_state = json_dumper_get_prev_state(dumper);

    switch (type) {
        case JSON_DUMPER_TYPE_OBJECT:
            if (JSON_DUMPER_TYPE(prev_state) != JSON_DUMPER_TYPE_OBJECT) {
                json_dumper_bad(dumper, "ending non-object nested item type as object");
                return false;
            }
            break;
        case JSON_DUMPER_TYPE_ARRAY:
            if (JSON_DUMPER_TYPE(prev_state) != JSON_DUMPER_TYPE_ARRAY) {
                json_dumper_bad(dumper, "ending non-array nested item type as array");
                return false;
            }
            break;
        case JSON_DUMPER_TYPE_BASE64:
            if (JSON_DUMPER_TYPE(prev_state) != JSON_DUMPER_TYPE_BASE64) {
                json_dumper_bad(dumper, "ending non-base64 nested item type as base64");
                return false;
            }
            break;
        default:
            json_dumper_bad(dumper, "ending unknown nested element type");
            return false;
    }

    if (prev_state & JSON_DUMPER_HAS_NAME) {
        json_dumper_bad(dumper, "finishing object with last item having name but no value");
        return false;
    }

    /* Make sure we won't underflow the dumper stack */
    if (json_dumper_stack_would_underflow(dumper)) {
        return false;
    }

    // if the object/array was non-empty, add a newline and indentation.
    if (dumper->state[dumper->current_depth]) {
        print_newline_indent(dumper, dumper->current_depth - 1);
    }

    switch (type) {
        case JSON_DUMPER_TYPE_OBJECT:
            jd_putc(dumper, '}');
            break;
        case JSON_DUMPER_TYPE_ARRAY:
            jd_putc(dumper, ']');
            break;
        case JSON_DUMPER_TYPE_BASE64:
        {
            char buf[4];
            size_t wrote;

            wrote = g_base64_encode_close(false, buf, &dumper->base64_state, &dumper->base64_save);
            jd_puts_len(dumper, buf, wrote);

            jd_putc(dumper, '"');
            break;
        }
        default:
            json_dumper_bad(dumper, "ending unknown nested element type");
            return false;
    }

    /*
     * Guaranteed not to underflow, as json_dumper_stack_would_underflow()
     * returned false.
     */
    --dumper->current_depth;
    return true;
}

void
json_dumper_begin_object(json_dumper *dumper)
{
    json_dumper_begin_nested_element(dumper, JSON_DUMPER_TYPE_OBJECT);
}

void
json_dumper_set_member_name(json_dumper *dumper, const char *name)
{
    if (!json_dumper_check_previous_error(dumper)) {
        return;
    }

    uint8_t prev_state = json_dumper_get_prev_state(dumper);

    /* Only object members, not array members, have names. */
    if (JSON_DUMPER_TYPE(prev_state) != JSON_DUMPER_TYPE_OBJECT) {
        json_dumper_bad(dumper, "setting name on non-object nested item type");
        return;
    }
    /* An object member name can only be set once before its value is set. */
    if (prev_state & JSON_DUMPER_HAS_NAME) {
        json_dumper_bad(dumper, "setting name twice on an object member");
        return;
    }

    prepare_token(dumper);
    json_puts_string(dumper, name, dumper->flags & JSON_DUMPER_DOT_TO_UNDERSCORE);
    jd_putc(dumper, ':');
    if ((dumper->flags & JSON_DUMPER_FLAGS_PRETTY_PRINT)) {
        jd_putc(dumper, ' ');
    }

    dumper->state[dumper->current_depth - 1] |= JSON_DUMPER_HAS_NAME;
}

void
json_dumper_set_member_name_noesc(json_dumper *dumper, const char *name, size_t len)
{
    if (!json_dumper_check_previous_error(dumper)) {
        return;
    }

    uint8_t prev_state = json_dumper_get_prev_state(dumper);

    if (JSON_DUMPER_TYPE(prev_state) != JSON_DUMPER_TYPE_OBJECT) {
        json_dumper_bad(dumper, "setting name on non-object nested item type");
        return;
    }
    if (prev_state & JSON_DUMPER_HAS_NAME) {
        json_dumper_bad(dumper, "setting name twice on an object member");
        return;
    }

    prepare_token(dumper);
    jd_putc(dumper, '"');
    jd_puts_len(dumper, name, len);
    jd_putc(dumper, '"');
    jd_putc(dumper, ':');
    if ((dumper->flags & JSON_DUMPER_FLAGS_PRETTY_PRINT)) {
        jd_putc(dumper, ' ');
    }

    dumper->state[dumper->current_depth - 1] |= JSON_DUMPER_HAS_NAME;
}

void
json_dumper_end_object(json_dumper *dumper)
{
    json_dumper_end_nested_element(dumper, JSON_DUMPER_TYPE_OBJECT);
}

void
json_dumper_begin_array(json_dumper *dumper)
{
    json_dumper_begin_nested_element(dumper, JSON_DUMPER_TYPE_ARRAY);
}

void
json_dumper_end_array(json_dumper *dumper)
{
    json_dumper_end_nested_element(dumper, JSON_DUMPER_TYPE_ARRAY);
}

static bool
json_dumper_setting_value_ok(json_dumper *dumper)
{
    uint8_t prev_state = json_dumper_get_prev_state(dumper);

    switch (JSON_DUMPER_TYPE(prev_state)) {
        case JSON_DUMPER_TYPE_OBJECT:
            /*
             * This value is part of an object.  As such, it must
             * have a name.
             */
            if (!(prev_state & JSON_DUMPER_HAS_NAME)) {
                json_dumper_bad(dumper, "setting value of object member without a name");
                return false;
            }
            break;
        case JSON_DUMPER_TYPE_ARRAY:
            /*
             * This value is part of an array.  As such, it's not
             * required to have a name (and shouldn't have a name;
             * that's already been checked in json_dumper_set_member_name()).
             */
            break;
        case JSON_DUMPER_TYPE_BASE64:
            /*
             * We're in the middle of constructing a base64-encoded
             * value.  Only json_dumper_write_base64() can be used
             * for that; we can't add individual values to it.
             */
            json_dumper_bad(dumper, "attempt to set value of base64 item to something not base64-encoded");
            return false;
        case JSON_DUMPER_TYPE_NONE:
        case JSON_DUMPER_TYPE_VALUE:
        {
            uint8_t curr_state = json_dumper_get_curr_state(dumper);
            switch (JSON_DUMPER_TYPE(curr_state)) {
                case JSON_DUMPER_TYPE_NONE:
                    /*
                     * We haven't put a value yet, so we can put one now.
                     */
                    break;
                case JSON_DUMPER_TYPE_VALUE:
                    /*
                     * This value isn't part of an object or array,
                     * and we've already put one value.
                     */
                    json_dumper_bad(dumper, "value not in object or array immediately follows another value");
                    return false;
                case JSON_DUMPER_TYPE_OBJECT:
                case JSON_DUMPER_TYPE_ARRAY:
                case JSON_DUMPER_TYPE_BASE64:
                    /*
                     * This should never be the case, no matter what
                     * our callers do:
                     *
                     *    JSON_DUMPER_TYPE_OBJECT can be the previous
                     *    type, meaning we're in the process of adding
                     *    elements to an object, but it should never be
                     *    the current type;
                     *
                     *    JSON_DUMPER_TYPE_ARRAY can be the previous
                     *    type, meaning we're in the process of adding
                     *    elements to an array, but it should never be
                     *    the current type;
                     *
                     *    JSON_DUMPER_TYPE_BASE64 should only be the
                     *    current type if we're in the middle of
                     *    building a base64 value, in which case the
                     *    previous type should also be JSON_DUMPER_TYPE_BASE64,
                     *    but that's not the previous type.
                     */
                    json_dumper_bad(dumper, "internal error setting value - should not happen");
                    return false;
                default:
                    json_dumper_bad(dumper, "internal error setting value, bad current state - should not happen");
                    return false;
            }
            break;
        }
        default:
            json_dumper_bad(dumper, "internal error setting value, bad previous state - should not happen");
            return false;
    }
    return true;
}

void
json_dumper_value_string(json_dumper *dumper, const char *value)
{
    if (!json_dumper_check_previous_error(dumper)) {
        return;
    }
    if (!json_dumper_setting_value_ok(dumper)) {
        return;
    }

    prepare_token(dumper);
    json_puts_string(dumper, value, false);

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_VALUE;
}

void
json_dumper_value_string_noesc(json_dumper *dumper, const char *value, size_t len)
{
    if (!json_dumper_check_previous_error(dumper)) {
        return;
    }
    if (!json_dumper_setting_value_ok(dumper)) {
        return;
    }

    prepare_token(dumper);
    jd_putc(dumper, '"');
    jd_puts_len(dumper, value, len);
    jd_putc(dumper, '"');

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_VALUE;
}

void
json_dumper_value_double(json_dumper *dumper, double value)
{
    if (!json_dumper_check_previous_error(dumper)) {
        return;
    }

    if (!json_dumper_setting_value_ok(dumper)) {
        return;
    }

    prepare_token(dumper);
    char buffer[G_ASCII_DTOSTR_BUF_SIZE] = { 0 };
    if (isfinite(value) && g_ascii_dtostr(buffer, G_ASCII_DTOSTR_BUF_SIZE, value) && buffer[0]) {
        jd_puts(dumper, buffer);
    } else {
        jd_puts(dumper, "null");
    }

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_VALUE;
}

void
json_dumper_value_va_list(json_dumper *dumper, const char *format, va_list ap)
{
    if (!json_dumper_check_previous_error(dumper)) {
        return;
    }

    if (!json_dumper_setting_value_ok(dumper)) {
        return;
    }

    prepare_token(dumper);
    jd_vprintf(dumper, format, ap);

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_VALUE;
}

void
json_dumper_value_anyf(json_dumper *dumper, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    json_dumper_value_va_list(dumper, format, ap);
    va_end(ap);
}

void
json_dumper_value_int(json_dumper *dumper, int64_t value)
{
    if (!json_dumper_check_previous_error(dumper)) {
        return;
    }
    if (!json_dumper_setting_value_ok(dumper)) {
        return;
    }
    prepare_token(dumper);

    char buf[22]; /* -9223372036854775808\0 = 21 chars + extra */
    char *end = buf + sizeof(buf);
    char *p = int64_to_str_back(end, value);
    jd_puts_len(dumper, p, end - p);

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_VALUE;
}

void
json_dumper_value_uint(json_dumper *dumper, uint64_t value)
{
    if (!json_dumper_check_previous_error(dumper)) {
        return;
    }
    if (!json_dumper_setting_value_ok(dumper)) {
        return;
    }
    prepare_token(dumper);

    char buf[21];
    char *end = buf + sizeof(buf);
    char *p = uint64_to_str_back(end, value);
    jd_puts_len(dumper, p, end - p);

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_VALUE;
}

bool
json_dumper_finish(json_dumper *dumper)
{
    if (!json_dumper_check_previous_error(dumper)) {
        return false;
    }

    if (dumper->current_depth != 0) {
        json_dumper_bad(dumper, "JSON dumper stack not empty at finish");
        return false;
    }

    jd_putc(dumper, '\n');
    jd_flush(dumper);
    dumper->state[0] = JSON_DUMPER_TYPE_NONE;
    return true;
}

void
json_dumper_begin_base64(json_dumper *dumper)
{
    json_dumper_begin_nested_element(dumper, JSON_DUMPER_TYPE_BASE64);
}

void
json_dumper_write_base64(json_dumper* dumper, const unsigned char *data, size_t len)
{
    if (!json_dumper_check_previous_error(dumper)) {
        return;
    }

    uint8_t prev_state = json_dumper_get_prev_state(dumper);

    if (JSON_DUMPER_TYPE(prev_state) != JSON_DUMPER_TYPE_BASE64) {
        json_dumper_bad(dumper, "writing base64 data to a non-base64 value");
        return;
    }

    #define CHUNK_SIZE 1024
    char buf[(CHUNK_SIZE / 3 + 1) * 4 + 4];

    while (len > 0) {
        size_t chunk_size = len < CHUNK_SIZE ? len : CHUNK_SIZE;
        size_t output_size = g_base64_encode_step(data, chunk_size, false, buf, &dumper->base64_state, &dumper->base64_save);
        jd_puts_len(dumper, buf, output_size);
        data += chunk_size;
        len -= chunk_size;
    }

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_BASE64;
}

void
json_dumper_end_base64(json_dumper *dumper)
{
    json_dumper_end_nested_element(dumper, JSON_DUMPER_TYPE_BASE64);
}
