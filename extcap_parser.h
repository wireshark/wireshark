/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __EXTCAP_PARSER_H__
#define __EXTCAP_PARSER_H__

#include <stdio.h>
#include <glib.h>
#include <string.h>

#include "ui/iface_toolbar.h"

/**
 * @brief Identifies the type of a parsed extcap output sentence.
 */
typedef enum {
    EXTCAP_SENTENCE_UNKNOWN,   /**< Unrecognized or malformed sentence */
    EXTCAP_SENTENCE_ARG,       /**< Argument definition sentence */
    EXTCAP_SENTENCE_VALUE,     /**< Value option sentence for a preceding argument */
    EXTCAP_SENTENCE_EXTCAP,    /**< Top-level extcap metadata sentence (version, help) */
    EXTCAP_SENTENCE_INTERFACE, /**< Interface advertisement sentence */
    EXTCAP_SENTENCE_DLT,       /**< Data link type (DLT) advertisement sentence */
    EXTCAP_SENTENCE_CONTROL    /**< Toolbar control definition sentence */
} extcap_sentence_type;

/**
 * @brief Data type of an extcap argument, controlling its GUI widget and value parsing.
 */
typedef enum {
    /* Simple types */
    EXTCAP_ARG_UNKNOWN,       /**< Unrecognized argument type */
    EXTCAP_ARG_INTEGER,       /**< Signed integer value */
    EXTCAP_ARG_UNSIGNED,      /**< Unsigned integer value */
    EXTCAP_ARG_LONG,          /**< Long signed integer value */
    EXTCAP_ARG_DOUBLE,        /**< Double-precision floating-point value */
    EXTCAP_ARG_BOOLEAN,       /**< Boolean value rendered as a checkbox with an explicit true/false argument */
    EXTCAP_ARG_BOOLFLAG,      /**< Boolean flag; the argument is omitted entirely when false */
    EXTCAP_ARG_STRING,        /**< Free-form string value */
    EXTCAP_ARG_PASSWORD,      /**< Sensitive string value; masked in the GUI and never saved to disk */
    /* Complex GUI types which are populated with value sentences */
    EXTCAP_ARG_SELECTOR,      /**< Drop-down selector populated from accompanying value sentences */
    EXTCAP_ARG_EDIT_SELECTOR, /**< Editable drop-down selector populated from accompanying value sentences */
    EXTCAP_ARG_RADIO,         /**< Radio-button group populated from accompanying value sentences */
    EXTCAP_ARG_MULTICHECK,    /**< Multi-select checkbox group populated from accompanying value sentences */
    EXTCAP_ARG_TABLE,         /**< Tabular multi-row input populated from accompanying value sentences */
    EXTCAP_ARG_FILESELECT,    /**< File path selector with an optional extension filter and existence check */
    EXTCAP_ARG_TIMESTAMP      /**< Date/time timestamp picker */
} extcap_arg_type;

/**
 * @brief Token keys for key/value pairs within a parsed extcap sentence.
 */
typedef enum {
    EXTCAP_PARAM_UNKNOWN,         /**< Unrecognized parameter key */
    EXTCAP_PARAM_ARGNUM,          /**< Argument number linking a value sentence to its parent arg sentence */
    EXTCAP_PARAM_CALL,            /**< CLI flag name passed to the extcap binary */
    EXTCAP_PARAM_DISPLAY,         /**< Human-readable label shown in the GUI */
    EXTCAP_PARAM_TYPE,            /**< Argument type token (maps to extcap_arg_type) */
    EXTCAP_PARAM_ARG,             /**< Argument number reference within a value or control sentence */
    EXTCAP_PARAM_DEFAULT,         /**< Default value for the argument */
    EXTCAP_PARAM_VALUE,           /**< Value payload for a value sentence */
    EXTCAP_PARAM_RANGE,           /**< Valid numeric range for the argument (min,max) */
    EXTCAP_PARAM_TOOLTIP,         /**< Tooltip text shown on hover in the GUI */
    EXTCAP_PARAM_PLACEHOLDER,     /**< Placeholder text shown in an empty input widget */
    EXTCAP_PARAM_NAME,            /**< Name of the extcap or interface */
    EXTCAP_PARAM_ENABLED,         /**< Whether a value option is selectable in the GUI */
    EXTCAP_PARAM_FILE_MUSTEXIST,  /**< If set, the selected file must already exist on disk */
    EXTCAP_PARAM_FILE_EXTENSION,  /**< Comma-separated list of accepted file extensions for file selectors */
    EXTCAP_PARAM_GROUP,           /**< GUI grouping label used to visually cluster related arguments */
    EXTCAP_PARAM_PARENT,          /**< Parent argument call name for hierarchical value relationships */
    EXTCAP_PARAM_REQUIRED,        /**< Whether the argument must be provided before capture can start */
    EXTCAP_PARAM_RELOAD,          /**< If set, changing this argument triggers a reload of dependent arguments */
    EXTCAP_PARAM_CONFIGURABLE,    /**< Whether the argument can be reconfigured during an active capture */
    EXTCAP_PARAM_PREFIX,          /**< Optional prefix string prepended to the argument value on the CLI */
    EXTCAP_PARAM_SAVE,            /**< Whether the argument value is persisted across capture sessions */
    EXTCAP_PARAM_VALIDATION,      /**< Regular expression used to validate the argument's string value */
    EXTCAP_PARAM_VERSION,         /**< Version string of the extcap binary */
    EXTCAP_PARAM_HELP,            /**< URL or text pointing to help documentation for the extcap */
    EXTCAP_PARAM_CONTROL,         /**< Control number linking a control sentence to toolbar actions */
    EXTCAP_PARAM_ROLE             /**< Role of a toolbar control (e.g., logger, message) */
} extcap_param_type;

/** @brief Casts an extcap_sentence_type or extcap_param_type to a GHashTable-compatible pointer key. */
#define ENUM_KEY(s) GUINT_TO_POINTER((unsigned)s)

/**
 * @brief A single selectable value option associated with a selector, radio, or multicheck argument.
 */
typedef struct _extcap_value {
    int   arg_num;    /**< Argument number of the parent arg sentence this value belongs to */
    char *call;       /**< CLI value string passed to the extcap when this option is selected */
    char *display;    /**< Human-readable label shown for this option in the GUI */
    bool  enabled;    /**< True if this option is currently selectable in the GUI */
    bool  is_default; /**< True if this option is the pre-selected default */
    char *parent;     /**< Call name of the parent value for hierarchical selectors; NULL if top-level */
} extcap_value;

/**
 * @brief A typed scalar value used to represent argument defaults and range bounds.
 */
typedef struct _extcap_complex {
    extcap_arg_type  complex_type; /**< Type of the stored value, determining how @ref _val is parsed */
    char            *_val;         /**< Raw string representation of the value */
} extcap_complex;

/** @brief Special string for the required= parameter indicating the argument is sufficient (not strictly required). */
#define EXTCAP_PARAM_REQUIRED_SUFFICIENT "sufficient"

/**
 * @brief A fully parsed extcap argument sentence with all its associated options.
 */
typedef struct _extcap_arg {
    int   arg_num;      /**< Unique argument number used to associate value sentences with this argument */
    char *call;         /**< CLI flag name passed to the extcap for this argument (e.g., "--port") */
    char *display;      /**< Human-readable label shown in the capture options GUI */
    char *tooltip;      /**< Tooltip text shown when hovering over the argument's widget */
    char *placeholder;  /**< Placeholder text shown inside an empty string input widget */

    char *fileextension; /**< Accepted file extension(s) for EXTCAP_ARG_FILESELECT arguments */
    bool  fileexists;    /**< If true, the selected file must already exist on disk */

    bool  is_required;  /**< If true, this argument must be set before capture can start */
    bool  is_sufficient; /**< If true, providing this argument alone is sufficient to start capture */
    bool  save;         /**< If true, the argument value is persisted between capture sessions */
    bool  reload;       /**< If true, changing this argument triggers a reload of dependent argument values */
    bool  configurable; /**< If true, this argument may be reconfigured during an active capture */
    char *prefix;       /**< Optional string prepended to the value on the CLI */
    char *regexp;       /**< Regular expression pattern used to validate the argument's string value */
    char *group;        /**< GUI group label used to visually cluster related arguments together */

    extcap_arg_type  arg_type;        /**< Data type and GUI widget type for this argument */
    extcap_complex  *range_start;     /**< Minimum allowed value for numeric arguments; NULL if unbounded */
    extcap_complex  *range_end;       /**< Maximum allowed value for numeric arguments; NULL if unbounded */
    extcap_complex  *default_complex; /**< Default value; NULL if no default is specified */

    char **pref_valptr;  /**< Pointer to the preference storage location holding the current value */
    char  *device_name;  /**< Name of the capture device this argument is associated with */
    GList *values;       /**< List of extcap_value entries for selector, radio, and multicheck arguments */
} extcap_arg;

/**
 * @brief Describes a single capture interface advertised by an extcap binary.
 */
typedef struct _extcap_interface {
    char *call;        /**< Interface identifier string passed to the extcap via --extcap-interface */
    char *display;     /**< Human-readable interface name shown in the capture interfaces dialog */
    char *version;     /**< Version string reported by the extcap for this interface */
    char *help;        /**< URL or text pointing to help documentation for this interface */
    char *extcap_path; /**< Absolute path to the extcap binary that provides this interface */

    extcap_sentence_type if_type; /**< Sentence type discriminator (EXTCAP_SENTENCE_INTERFACE or EXTCAP_SENTENCE_DLT) */
} extcap_interface;

/**
 * @brief Describes a data link type (DLT) supported by an extcap interface.
 */
typedef struct _extcap_dlt {
    int   number;  /**< Numeric DLT value (e.g., 1 for DLT_EN10MB) */
    char *name;    /**< Short canonical name of the DLT (e.g., "EN10MB") */
    char *display; /**< Human-readable description of the DLT shown in the GUI */
} extcap_dlt;

/**
 * @brief A single tokenized extcap output sentence with its key/value parameter map.
 */
typedef struct _extcap_token_sentence {
    char       *sentence;    /**< The sentence type keyword (e.g., "arg", "value", "interface") */
    GHashTable *param_list;  /**< Hash table of parameter key/value pairs parsed from the sentence */
} extcap_token_sentence;

#ifdef __cplusplus
extern "C" {
#endif

/* Parse a string into a complex type */

/**
 * @brief Parse a complex value from a string.
 *
 * @param complex_type The type of the complex value.
 * @param data The string representation of the complex value.
 * @return extcap_complex* A pointer to the newly created complex value, or NULL on failure.
 */
extcap_complex *extcap_parse_complex(extcap_arg_type complex_type,
        const char *data);

/**
 * @brief Free a complex value.
 *
 * @param comp Pointer to the extcap_complex structure to be freed.
 */
/* Free a complex */
void extcap_free_complex(extcap_complex *comp);

/* Print a complex value out for debug */

/**
 * @brief Prints a complex type using its string representation.
 *
 * @param comp Pointer to the extcap_complex structure to be printed.
 */
void extcap_printf_complex(extcap_complex *comp);

/**
 * @brief Get a string representation of a complex type.
 * @return a string representation of a complex type
 * @note Caller is responsible for calling g_free on the returned string
 */
char *extcap_get_complex_as_string(extcap_complex *comp);

/**
 * @brief Retrieves an integer value from an extcap complex structure.
 *
 * @param comp Pointer to the extcap_complex structure.
 * @return The integer value, or 0 if the input is invalid.
 */
int extcap_complex_get_int(extcap_complex *comp);

/**
 * @brief Retrieves an unsigned integer value from an extcap complex structure.
 *
 * @param comp Pointer to the extcap_complex structure.
 * @return The unsigned integer value, or 0 if the input is invalid.
 */
unsigned extcap_complex_get_uint(extcap_complex *comp);

/**
 * @brief Retrieves a long value from an extcap complex structure.
 *
 * @param comp Pointer to the extcap_complex structure.
 * @return The long value, or 0 if the input is invalid.
 */
int64_t extcap_complex_get_long(extcap_complex *comp);

/**
 * @brief Retrieves the double value from an extcap_complex structure.
 *
 * @param comp Pointer to the extcap_complex structure.
 * @return The double value, or 0 if the input is invalid.
 */
double extcap_complex_get_double(extcap_complex *comp);

/**
 * @brief Retrieves the boolean value from an extcap complex structure.
 *
 * @param comp Pointer to the extcap_complex structure.
 * @return true if the value is valid andmatches a boolean regex, false otherwise.
 */
bool extcap_complex_get_bool(extcap_complex *comp);

/**
 * @brief Get the string value from an extcap complex structure.
 *
 * @param comp Pointer to the extcap_complex structure.
 * @return char* The string value, or NULL if the input is NULL.
 */
char *extcap_complex_get_string(extcap_complex *comp);

/* compares the default value of an element with a given parameter */

/**
 * @brief Compares an argument's default complex value with a test complex value.
 *
 * @param element The extcap_arg structure containing the default complex value.
 * @param test The extcap_complex structure to compare against the default.
 * @return true if the default complex value matches the test value, false otherwise.
 */
bool extcap_compare_is_default(extcap_arg *element, extcap_complex *test);

/**
 * @brief Free a single argument.
 *
 * This function releases all resources associated with an extcap_arg structure, including
 * freeing memory for its various fields and nested structures.
 *
 * @param a Pointer to the extcap_arg structure to be freed.
 */
void extcap_free_arg(extcap_arg *a);

/**
 * @brief Free entire toolbar control structure.
 *
 * @param control Pointer to the toolbar control structure to be freed.
 */
void extcap_free_toolbar_control(iface_toolbar_control *control);

/**
 * @brief Free an entire arg list.
 *
 * This function frees a GList containing extcap_arg structures, calling extcap_free_arg on each element.
 *
 * @param a The GList to be freed.
 */
void extcap_free_arg_list(GList *a);


/** Parser for extcap data */

/* Parse all sentences for args and values */

/**
 * @brief Parses arguments from extcap output.
 *
 * @param output The output string to parse.
 * @return A GList of parsed extcap_args.
 */
GList * extcap_parse_args(char *output);

/**
 * @brief Parse all sentences for values.
 *
 * @param output The output string containing sentences to parse.
 * @return GList* A list of parsed extcap_value structures.
 */
GList * extcap_parse_values(char *output);

/**
 * @brief Parse all sentences for interfaces
 *
 * This function parses the interfaces section of extcap output and returns a list of interface objects.
 *
 * @param output The extcap output string to parse.
 * @param control_items Pointer to a GList containing control items for parsing.
 * @return A GList of parsed extcap_interface objects, or NULL if parsing fails.
 */
GList * extcap_parse_interfaces(char *output, GList **control_items);

/**
 * @brief Parse all sentences for DLT (Data Link Type) information.
 *
 * This function tokenizes the input output into sentences and then parses each sentence to extract DLT information.
 * It returns a GList containing parsed extcap_dlt structures.
 *
 * @param output The input string containing DLT information.
 * @return A GList of extcap_dlt structures representing the parsed DLTs, or NULL if parsing fails.
 */
GList * extcap_parse_dlts(char *output);

#ifdef __cplusplus
}
#endif

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
