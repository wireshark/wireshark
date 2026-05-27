/** @file
 * Definitions for print streams.
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "ws_symbol_export.h"

#include <wsutil/color.h>
#include <wsutil/str_util.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Print stream code; this provides a "print stream" class with subclasses
 * of various sorts.  Additional subclasses might be implemented elsewhere.
 */
struct print_stream;

/**
 * @brief Vtable of operations implementing a print stream backend for rendering dissection output.
 */
typedef struct print_stream_ops {
    /**
     * @brief Outputs any preamble required by the print format before the first line of content.
     * @param self           The print stream instance.
     * @param filename       Name of the capture file being printed.
     * @param version_string Wireshark version string to include in the preamble.
     * @return True on success, false on write failure.
     */
    bool (*print_preamble)(struct print_stream *self, char *filename, const char *version_string);

    /**
     * @brief Prints a single line of text at the specified indentation level.
     * @param self   The print stream instance.
     * @param indent Number of indentation levels to apply before the line.
     * @param line   The text content to print.
     * @return True on success, false on write failure.
     */
    bool (*print_line)(struct print_stream *self, int indent, const char *line);

    /**
     * @brief Prints a single line of text with explicit foreground and background colors.
     * @param self   The print stream instance.
     * @param indent Number of indentation levels to apply before the line.
     * @param line   The text content to print.
     * @param fg     Foreground color to apply to the line, or NULL for default.
     * @param bg     Background color to apply to the line, or NULL for default.
     * @return True on success, false on write failure.
     */
    bool (*print_line_color)(struct print_stream *self, int indent, const char *line, const color_t *fg, const color_t *bg);

    /**
     * @brief Inserts a named bookmark anchor at the current position in the output.
     * @param self  The print stream instance.
     * @param name  Internal identifier for the bookmark.
     * @param title Human-readable title associated with the bookmark.
     * @return True on success, false on write failure.
     */
    bool (*print_bookmark)(struct print_stream *self, const char *name, const char *title);

    /**
     * @brief Advances the output to a new page, if supported by the print format.
     * @param self The print stream instance.
     * @return True on success, false on write failure.
     */
    bool (*new_page)(struct print_stream *self);

    /**
     * @brief Outputs any finale or closing content required by the print format after all lines.
     * @param self The print stream instance.
     * @return True on success, false on write failure.
     */
    bool (*print_finale)(struct print_stream *self);

    /**
     * @brief Destroys the print stream and releases all associated resources.
     * @param self The print stream instance to destroy.
     * @return True on success, false if cleanup encountered an error.
     */
    bool (*destroy)(struct print_stream *self);
} print_stream_ops_t;

/**
 * @brief Represents an abstract print stream, pairing a backend operations vtable with instance-specific state.
 */
typedef struct print_stream {
    const print_stream_ops_t* ops;  /**< Pointer to the vtable of backend operations implementing this print stream. */
    void*                     data; /**< Opaque pointer to backend-specific state for this print stream instance. */
} print_stream_t;

/*
 * These return a print_stream_t * on success and NULL on failure.
 */

/**
 * @brief Create a new print stream for text output.
 *
 * @param to_file If true, output will be written to a file; otherwise, it will be written to standard output.
 * @param dest The destination file name.
 * @return Pointer to the newly created print stream, or NULL on failure.
 */
WS_DLL_PUBLIC print_stream_t *print_stream_text_new(bool to_file, const char *dest);

/**
 * @brief Create a new print stream for text output using standard I/O.
 *
 * @param fh File handle to write to.
 * @return Pointer to the newly created print stream, or NULL on failure.
 */
WS_DLL_PUBLIC print_stream_t *print_stream_text_stdio_new(FILE *fh);

/**
 * @brief Create a new print stream for PostScript output.
 *
 * @param to_file If true, output will be written to a file; otherwise, it will be written to standard output.
 * @param dest The destination file name.
 * @return Pointer to the newly created print stream, or NULL on failure.
 */
WS_DLL_PUBLIC print_stream_t *print_stream_ps_new(bool to_file, const char *dest);

/**
 * @brief Create a new print stream for PostScript output using standard I/O.
 *
 * @param fh File handle to write to.
 * @return Pointer to the newly created print stream, or NULL on failure.
 */
WS_DLL_PUBLIC print_stream_t *print_stream_ps_stdio_new(FILE *fh);

/**
 * @brief Print the preamble to a print stream.
 *
 * @param self           The print stream.
 * @param filename       The name of the capture file being printed.
 * @param version_string The Wireshark version string.
 * @return true if the print was successful, false otherwise.
 */
WS_DLL_PUBLIC bool print_preamble(print_stream_t *self, char *filename, const char *version_string);

/**
 * @brief Prints a line to the print stream.
 *
 * @param self Pointer to the print stream object.
 * @param indent Number of spaces for indentation.
 * @param line The line to be printed.
 * @return true if the line was successfully printed, false otherwise.
 */
WS_DLL_PUBLIC bool print_line(print_stream_t *self, int indent, const char *line);

/**
 * @brief Print a colored line to a print stream.
 *
 * Equivalent to print_line(), but if the stream supports text coloring then
 * the output text will also be colored with the given foreground and
 * background.
 *
 * @param self The print stream.
 * @param indent The indentation level.
 * @param line The line of text to print.
 * @param fg The foreground color.
 * @param bg The background color.
 * @return true if the print was successful, false otherwise.
 */
WS_DLL_PUBLIC bool print_line_color(print_stream_t *self, int indent, const char *line, const color_t *fg, const color_t *bg);

/**
 * @brief Print a bookmark in the print stream.
 *
 * @param self Pointer to the print_stream_t object.
 * @param name The name of the bookmark.
 * @param title The title of the bookmark.
 * @return true if successful, false otherwise.
 */
WS_DLL_PUBLIC bool print_bookmark(print_stream_t *self, const char *name,
    const char *title);

/**
 * @brief Create a new page in the print stream.
 *
 * @param self Pointer to the print_stream_t object.
 * @return true if successful, false otherwise.
 */
WS_DLL_PUBLIC bool new_page(print_stream_t *self);

/**
 * @brief Print the finale of the print stream.
 *
 * @param self Pointer to the print_stream_t object.
 * @return true if successful, false otherwise.
 */
WS_DLL_PUBLIC bool print_finale(print_stream_t *self);

/**
 * @brief Destroys a print stream.
 *
 * @param self Pointer to the print_stream_t structure to be destroyed.
 * @return true if successful, false otherwise.
 */
WS_DLL_PUBLIC bool destroy_print_stream(print_stream_t *self);

#ifdef __cplusplus
}
#endif /* __cplusplus */
