/* wsjson.h
 * Routines for serializing data as JSON.
 *
 * Copyright 2018, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "json_dumper.h"

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
};
#define JSON_DUMPER_TYPE(state)         ((enum json_dumper_element_type)((state) & 3))
#define JSON_DUMPER_HAS_NAME            (1 << 2)

#define JSON_DUMPER_FLAGS_ERROR     (1 << 16)   /* Output flag: an error occurred. */

enum json_dumper_change {
    JSON_DUMPER_BEGIN,
    JSON_DUMPER_END,
    JSON_DUMPER_SET_NAME,
    JSON_DUMPER_SET_VALUE,
    JSON_DUMPER_FINISH,
};

static void
json_puts_string(FILE *fp, const char *str)
{
    static const char json_cntrl[0x20][6] = {
        "u0000", "u0001", "u0002", "u0003", "u0004", "u0005", "u0006", "u0007", "b",     "t",     "n",     "u000b", "f",     "r",     "u000e", "u000f",
        "u0010", "u0011", "u0012", "u0013", "u0014", "u0015", "u0016", "u0017", "u0018", "u0019", "u001a", "u001b", "u001c", "u001d", "u001e", "u001f"
    };

    fputc('"', fp);
    for (int i = 0; str[i]; i++) {
        if ((guint)str[i] < 0x20) {
            fputc('\\', fp);
            fputs(json_cntrl[(guint)str[i]], fp);
        } else {
            if (str[i] == '\\' || str[i] == '"') {
                fputc('\\', fp);
            }
            fputc(str[i], fp);
        }
    }
    fputc('"', fp);
}

/**
 * Checks that the dumper state is valid for a new change. Any error will be
 * sticky and prevent further dumps from succeeding.
 */
static gboolean
json_dumper_check_state(json_dumper *dumper, enum json_dumper_change change, enum json_dumper_element_type type)
{
    if ((dumper->flags & JSON_DUMPER_FLAGS_ERROR)) {
        return FALSE;
    }

    int depth = dumper->current_depth;
    if (depth < 0 || depth >= JSON_DUMPER_MAX_DEPTH) {
        /* Corrupted state, no point in continuing. */
        dumper->flags |= JSON_DUMPER_FLAGS_ERROR;
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
            } else {
                ok = JSON_DUMPER_TYPE(dumper->state[depth]) == JSON_DUMPER_TYPE_NONE;
            }
            break;
        case JSON_DUMPER_FINISH:
            ok = depth == 0;
            break;
    }
    if (!ok) {
        dumper->flags |= JSON_DUMPER_FLAGS_ERROR;
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
    json_puts_string(dumper->output_file, name);
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
    json_puts_string(dumper->output_file, value);

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_VALUE;
}

void
json_dumper_value_anyf(json_dumper *dumper, const char *format, ...)
{
    va_list ap;
    if (!json_dumper_check_state(dumper, JSON_DUMPER_SET_VALUE, JSON_DUMPER_TYPE_VALUE)) {
        return;
    }

    prepare_token(dumper);
    va_start(ap, format);
    vfprintf(dumper->output_file, format, ap);
    va_end(ap);

    dumper->state[dumper->current_depth] = JSON_DUMPER_TYPE_VALUE;
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
