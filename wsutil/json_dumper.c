/* wsjson.h
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

#include "json_dumper.h"

#include <math.h>

/*
 * json_dumper.state[current_depth] describes a nested element:
 * - type: none/object/array/value
 * - has_name: Whether the object member name was set.
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

#define JSON_DUMPER_FLAGS_ERROR     (1 << 16)   /* Output flag: an error occurred. */
#define JSON_DUMPER_FLAGS_NO_DEBUG  (1 << 17)   /* Input flag: disable debug prints (intended for speeding up fuzzing). */

enum json_dumper_change {
    JSON_DUMPER_BEGIN,
    JSON_DUMPER_END,
    JSON_DUMPER_SET_NAME,
    JSON_DUMPER_SET_VALUE,
    JSON_DUMPER_WRITE_BASE64,
    JSON_DUMPER_FINISH,
};

static void
json_puts_string(FILE *fp, const char *str, gboolean dot_to_underscore)
{
    if (!str) {
        fputs("null", fp);
        return;
    }

    static const char json_cntrl[0x20][6] = {
        "u0000", "u0001", "u0002", "u0003", "u0004", "u0005", "u0006", "u0007", "b",     "t",     "n",     "u000b", "f",     "r",     "u000e", "u000f",
        "u0010", "u0011", "u0012", "u0013", "u0014", "u0015", "u0016", "u0017", "u0018", "u0019", "u001a", "u001b", "u001c", "u001d", "u001e", "u001f"
    };

    fputc('"', fp);
    for (int i = 0; str[i]; i++) {
        if ((guint)str[i] < 0x20) {
            fputc('\\', fp);
            fputs(json_cntrl[(guint)str[i]], fp);
        } else if (i > 0 && str[i - 1] == '<' && str[i] == '/') {
            // Convert </script> to <\/script> to avoid breaking web pages.
            fputs("\\/", fp);
        } else {
            if (str[i] == '\\' || str[i] == '"') {
                fputc('\\', fp);
            }
            if (dot_to_underscore && str[i] == '.')
                fputc('_', fp);
            else
                fputc(str[i], fp);
        }
    }
    fputc('"', fp);
}

/**
 * Called when a programming error is encountered where the JSON manipulation
 * state got corrupted. This could happen when pairing the wrong begin/end
 * calls, when writing multiple values for the same object, etc.
 */
static void
json_dumper_bad(json_dumper *dumper, enum json_dumper_change change,
        enum json_dumper_element_type type, const char *what)
{
    unsigned states[3];
    int depth = dumper->current_depth;
    /* Do not use add/subtract from depth to avoid signed overflow. */
    int adj = -1;
    for (int i = 0; i < 3; i++, adj++) {
        if (depth >= -adj && depth < JSON_DUMPER_MAX_DEPTH - adj) {
            states[i] = dumper->state[depth + adj];
        } else {
            states[i] = 0xbad;
        }
    }
    if ((dumper->flags & JSON_DUMPER_FLAGS_NO_DEBUG)) {
        /* Console output can be slow, disable log calls to speed up fuzzing. */
        return;
    }
    fflush(dumper->output_file);
    g_error("Bad json_dumper state: %s; change=%d type=%d depth=%d prev/curr/next state=%02x %02x %02x",
            what, change, type, dumper->current_depth, states[0], states[1], states[2]);
}

/**
 * Checks that the dumper state is valid for a new change. Any error will be
 * sticky and prevent further dumps from succeeding.
 */
static gboolean
json_dumper_check_state(json_dumper *dumper, enum json_dumper_change change, enum json_dumper_element_type type)
{
    if ((dumper->flags & JSON_DUMPER_FLAGS_ERROR)) {
        json_dumper_bad(dumper, change, type, "previous corruption detected");
        return FALSE;
    }

    int depth = dumper->current_depth;
    if (depth < 0 || depth >= JSON_DUMPER_MAX_DEPTH) {
        /* Corrupted state, no point in continuing. */
        dumper->flags |= JSON_DUMPER_FLAGS_ERROR;
        json_dumper_bad(dumper, change, type, "depth corruption");
        return FALSE;
    }

    guint8 prev_state = depth > 0 ? dumper->state[depth - 1] : 0;
    enum json_dumper_element_type prev_type = JSON_DUMPER_TYPE(prev_state);

    gboolean ok = FALSE;
    switch (change) {
        case JSON_DUMPER_BEGIN:
            ok = depth + 1 < JSON_DUMPER_MAX_DEPTH;
            break;
        case JSON_DUMPER_END:
            ok = prev_type == type && !(prev_state & JSON_DUMPER_HAS_NAME);
            break;
        case JSON_DUMPER_SET_NAME:
            /* An object name can only be set once before a value is set. */
            ok = prev_type == JSON_DUMPER_TYPE_OBJECT && !(prev_state & JSON_DUMPER_HAS_NAME);
            break;
        case JSON_DUMPER_SET_VALUE:
            if (prev_type == JSON_DUMPER_TYPE_OBJECT) {
                ok = (prev_state & JSON_DUMPER_HAS_NAME);
            } else if (prev_type == JSON_DUMPER_TYPE_ARRAY) {
                ok = TRUE;
            } else if (prev_type == JSON_DUMPER_TYPE_BASE64) {
                ok = FALSE;
            } else {
                ok = JSON_DUMPER_TYPE(dumper->state[depth]) == JSON_DUMPER_TYPE_NONE;
            }
            break;
        case JSON_DUMPER_WRITE_BASE64:
            ok = (prev_type == JSON_DUMPER_TYPE_BASE64) &&
                (type == JSON_DUMPER_TYPE_NONE || type == JSON_DUMPER_TYPE_BASE64);
            break;
        case JSON_DUMPER_FINISH:
            ok = depth == 0;
            break;
    }
    if (!ok) {
        dumper->flags |= JSON_DUMPER_FLAGS_ERROR;
        json_dumper_bad(dumper, change, type, "illegal transition");
    }
    return ok;
}

static void
print_newline_indent(const json_dumper *dumper, int depth)
{
    if ((dumper->flags & JSON_DUMPER_FLAGS_PRETTY_PRINT)) {
        fputc('\n', dumper->output_file);
        for (int i = 0; i < depth; i++) {
            fputs("  ", dumper->output_file);
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
    guint8 prev_state = dumper->state[dumper->current_depth - 1];

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

    if (dumper->state[dumper->current_depth]) {
        fputc(',', dumper->output_file);
    }
    print_newline_indent(dumper, dumper->current_depth);
}

/**
 * Common code to close an object/array, printing a closing character (and if
 * necessary, it is preceded by newline and indentation).
 */
static void
finish_token(const json_dumper *dumper, char close_char)
{
    // if the object/array was non-empty, add a newline and indentation.
    if (dumper->state[dumper->current_depth]) {
        print_newline_indent(dumper, dumper->current_depth - 1);
    }
    fputc(close_char, dumper->output_file);
}

void
json_dumper_begin_object(json_dumper *dumper)
{
    if (!json_dumper_check_state(dumper, JSON_DUMPER_BEGIN, JSON_DUMPER_TYPE_OBJECT)) {
        return;
    }

    prepare_token(dumper);
    fputc('{', dumper->output_file);

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_OBJECT;
    ++dumper->current_depth;
    dumper->state[dumper->current_depth] = 0;
}

void
json_dumper_set_member_name(json_dumper *dumper, const char *name)
{
    if (!json_dumper_check_state(dumper, JSON_DUMPER_SET_NAME, JSON_DUMPER_TYPE_NONE)) {
        return;
    }

    prepare_token(dumper);
    json_puts_string(dumper->output_file, name, dumper->flags & JSON_DUMPER_DOT_TO_UNDERSCORE);
    fputc(':', dumper->output_file);
    if ((dumper->flags & JSON_DUMPER_FLAGS_PRETTY_PRINT)) {
        fputc(' ', dumper->output_file);
    }

    dumper->state[dumper->current_depth - 1] |= JSON_DUMPER_HAS_NAME;
}

void
json_dumper_end_object(json_dumper *dumper)
{
    if (!json_dumper_check_state(dumper, JSON_DUMPER_END, JSON_DUMPER_TYPE_OBJECT)) {
        return;
    }

    finish_token(dumper, '}');

    --dumper->current_depth;
}

void
json_dumper_begin_array(json_dumper *dumper)
{
    if (!json_dumper_check_state(dumper, JSON_DUMPER_BEGIN, JSON_DUMPER_TYPE_ARRAY)) {
        return;
    }

    prepare_token(dumper);
    fputc('[', dumper->output_file);

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_ARRAY;
    ++dumper->current_depth;
    dumper->state[dumper->current_depth] = 0;
}

void
json_dumper_end_array(json_dumper *dumper)
{
    if (!json_dumper_check_state(dumper, JSON_DUMPER_END, JSON_DUMPER_TYPE_ARRAY)) {
        return;
    }

    finish_token(dumper, ']');

    --dumper->current_depth;
}

void
json_dumper_value_string(json_dumper *dumper, const char *value)
{
    if (!json_dumper_check_state(dumper, JSON_DUMPER_SET_VALUE, JSON_DUMPER_TYPE_VALUE)) {
        return;
    }

    prepare_token(dumper);
    json_puts_string(dumper->output_file, value, FALSE);

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_VALUE;
}

void
json_dumper_value_double(json_dumper *dumper, double value)
{
    if (!json_dumper_check_state(dumper, JSON_DUMPER_SET_VALUE, JSON_DUMPER_TYPE_VALUE)) {
        return;
    }

    prepare_token(dumper);
    gchar buffer[G_ASCII_DTOSTR_BUF_SIZE] = { 0 };
    if (isfinite(value) && g_ascii_dtostr(buffer, G_ASCII_DTOSTR_BUF_SIZE, value) && buffer[0]) {
        fputs(buffer, dumper->output_file);
    } else {
        fputs("null", dumper->output_file);
    }

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_VALUE;
}

void
json_dumper_value_va_list(json_dumper *dumper, const char *format, va_list ap)
{
    if (!json_dumper_check_state(dumper, JSON_DUMPER_SET_VALUE, JSON_DUMPER_TYPE_VALUE)) {
        return;
    }

    prepare_token(dumper);
    vfprintf(dumper->output_file, format, ap);

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

gboolean
json_dumper_finish(json_dumper *dumper)
{
    if (!json_dumper_check_state(dumper, JSON_DUMPER_FINISH, JSON_DUMPER_TYPE_NONE)) {
        return FALSE;
    }

    fputc('\n', dumper->output_file);
    dumper->state[0] = 0;
    return TRUE;
}

void
json_dumper_begin_base64(json_dumper *dumper)
{
    if (!json_dumper_check_state(dumper, JSON_DUMPER_BEGIN, JSON_DUMPER_TYPE_BASE64)) {
        return;
    }

    dumper->base64_state = 0;
    dumper->base64_save = 0;

    prepare_token(dumper);

    fputc('"', dumper->output_file);

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_BASE64;
    ++dumper->current_depth;
    dumper->state[dumper->current_depth] = 0;
}

void
json_dumper_write_base64(json_dumper* dumper, const guchar *data, size_t len)
{
    if (!json_dumper_check_state(dumper, JSON_DUMPER_WRITE_BASE64, JSON_DUMPER_TYPE_BASE64)) {
        return;
    }

    #define CHUNK_SIZE 1024
    gchar buf[(CHUNK_SIZE / 3 + 1) * 4 + 4];

    while (len > 0) {
        gsize chunk_size = len < CHUNK_SIZE ? len : CHUNK_SIZE;
        gsize output_size = g_base64_encode_step(data, chunk_size, FALSE, buf, &dumper->base64_state, &dumper->base64_save);
        fwrite(buf, 1, output_size, dumper->output_file);
        data += chunk_size;
        len -= chunk_size;
    }

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_BASE64;
}

void
json_dumper_end_base64(json_dumper *dumper)
{
    if (!json_dumper_check_state(dumper, JSON_DUMPER_END, JSON_DUMPER_TYPE_BASE64)) {
        return;
    }

    gchar buf[4];
    gsize wrote;

    wrote = g_base64_encode_close(FALSE, buf, &dumper->base64_state, &dumper->base64_save);
    fwrite(buf, 1, wrote, dumper->output_file);

    fputc('"', dumper->output_file);

    --dumper->current_depth;
}
