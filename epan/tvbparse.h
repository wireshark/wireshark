/** @file
 *
 * an API for text tvb parsers
 *
 * Copyright 2005, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 The intention behind this is to ease the writing of dissectors that have to
 parse text without the need of writing into buffers.

 It was originally written to avoid using lex and yacc for the xml dissector.

 the parser is able to look for wanted elements these can be:

 simple tokens:
 - a char out of a string of needles
 - a char not belonging to a string of needles
 - a sequence of chars that belong to a set of chars
 - a sequence of chars that do not belong to a set of chars
 - a string
 - a caseless string
 - all the characters up to a certain wanted element (included or excluded)

 composed elements:
 - one of a given group of wanted elements
 - a sequence of wanted elements
 - some (at least one) instances of a wanted element

 Once a wanted element is successfully extracted, by either tvbparse_get or
 tvbparse_find, the parser will invoke a given callback
 before and another one after every of its component's subelement's callbacks
 are being called.

 If tvbparse_get or tvbparse_find fail to extract the wanted element the
 subelements callbacks are not going to be invoked.

 The wanted elements are instantiated once by the proto_register_xxx function.

 The parser is instantiated for every packet and it maintains its state.

 The element's data is destroyed before the next packet is dissected.
 */
#pragma once
#include <epan/tvbuff.h>
#include "ws_symbol_export.h"

typedef struct _tvbparse_elem_t tvbparse_elem_t;
typedef struct _tvbparse_wanted_t tvbparse_wanted_t;
typedef struct _tvbparse_t tvbparse_t;


/*
 * a callback function to be called before or after an element has been
 * successfully extracted.
 *
 * Note that if the token belongs to a composed token the callbacks of the
 * components won't be called unless the composed token is successfully
 * extracted.
 *
 * tvbparse_data: the private data of the parser
 * wanted_data: the private data of the wanted element
 * elem: the extracted element
 */
typedef void (*tvbparse_action_t)(void* tvbparse_data, const void* wanted_data, struct _tvbparse_elem_t* elem);

typedef int (*tvbparse_condition_t)
(tvbparse_t*, const int,
 const tvbparse_wanted_t*,
 tvbparse_elem_t**);


/**
 * @brief Controls how a parser consumes the terminal element when scanning up to the last token.
 */
typedef enum {
    TP_UNTIL_INCLUDE, /**< The last element is included in the result and its span is consumed by the parser */
    TP_UNTIL_SPEND,   /**< The last element is excluded from the result but its span is still consumed by the parser */
    TP_UNTIL_LEAVE    /**< The last element is excluded from the result and its span is left unconsumed for the next parse step */
} until_mode_t;


/**
 * @brief Describes a parsing rule or expectation for a tvbuff parser.
 *
 * This structure defines a unit of parsing logic used by the tvbparse engine.
 * It specifies conditions, control parameters, length constraints, and optional
 * pre/post actions to guide how data is extracted from a tvbuff.
 */
struct _tvbparse_wanted_t {
    int id; /**< Unique identifier for the parsing rule. */

    tvbparse_condition_t condition; /**< Condition that determines when this rule applies. */

    /**
     * @brief Control parameters for the parsing rule.
     *
     * The active member depends on the parsing strategy. This union supports
     * string matching, numeric values, nested rules, hash-based dispatch,
     * and other advanced parsing constructs.
     */
    union {
        const char* str; /**< String to match. */
        struct _tvbparse_wanted_t** handle; /**< Pointer to a rule handle array. */
        struct {
            union {
                int64_t i;     /**< Signed integer value. */
                uint64_t u;    /**< Unsigned integer value. */
                double f;      /**< Floating-point value. */
            } value;
        } number; /**< Numeric value to match. */
        enum ftenum ftenum; /**< Field type enum for typed parsing. */
        struct {
            until_mode_t mode; /**< Mode for "until" parsing (e.g., until match or delimiter). */
            const tvbparse_wanted_t* subelem; /**< Sub-element to parse until. */
        } until;
        struct {
            wmem_map_t* table; /**< Lookup table for dispatching based on key. */
            struct _tvbparse_wanted_t* key; /**< Key to use for lookup. */
            struct _tvbparse_wanted_t* other; /**< Fallback rule if key not found. */
        } hash;
        GPtrArray* elems; /**< Array of sub-elements to parse. */
        const tvbparse_wanted_t* subelem; /**< Single sub-element reference. */
        void* p; /**< Generic pointer for custom control data. */
    } control;

    int len; /**< Expected length of the parsed element (if fixed). */

    unsigned min; /**< Minimum length constraint. */
    unsigned max; /**< Maximum length constraint. */

    const void* data; /**< Optional user-defined data associated with the rule. */

    tvbparse_action_t before; /**< Action to perform before parsing this element. */
    tvbparse_action_t after;  /**< Action to perform after parsing this element. */
};

/**
 * @brief Represents an instance of a per-packet parser for tvbuff data.
 *
 * This structure encapsulates the state and context for parsing a single packet buffer
 * using tvbparse rules. It tracks memory scope, parsing boundaries, recursion depth,
 * and optional control data.
 */
struct _tvbparse_t {
    wmem_allocator_t* scope;              /**< Memory allocator used for parser allocations. */
    tvbuff_t* tvb;                        /**< Pointer to the tvbuff being parsed. */
    int offset;                           /**< Current offset within the tvbuff. */
    int end_offset;                       /**< Parsing boundary (exclusive end offset). */
    void* data;                           /**< Optional user-defined parser context data. */
    const tvbparse_wanted_t* ignore;      /**< Optional rule to ignore during parsing. */
    int recursion_depth;                  /**< Current recursion depth for nested parsing. */
};


/**
 * @brief Represents a single token matched by the tvbuff parser, forming part of a linked tree of parse results.
 */
struct _tvbparse_elem_t {
    int                       id;     /**< Identifier corresponding to the matched tvbparse_wanted_t rule that produced this token. */

    tvbparse_t*               parser; /**< The parser instance that produced this token. */
    tvbuff_t*                 tvb;    /**< The tvbuff in which this token was matched. */
    int                       offset; /**< Byte offset within the tvbuff at which this token begins. */
    int                       len;    /**< Length in bytes of the matched token within the tvbuff. */

    void*                     data;   /**< Opaque user-defined data associated with this token by a callback. */

    struct _tvbparse_elem_t*  sub;    /**< Pointer to the first child token for composite matches, or NULL if this is a leaf token. */

    struct _tvbparse_elem_t*  next;   /**< Pointer to the next sibling token at the same level, or NULL if this is the last sibling. */
    struct _tvbparse_elem_t*  last;   /**< Pointer to the last sibling token in the sibling chain for efficient appending. */

    const tvbparse_wanted_t*  wanted; /**< Pointer to the parse rule (wanted definition) that this token was matched against. */
};


/*
 * definition of wanted token types
 *
 * the following functions define the tokens we will be able to look for in a tvb
 * common parameters are:
 *
 * id: an arbitrary id that will be copied to the eventual token (don't use 0)
 * private_data: persistent data to be passed to the callback action (wanted_data)
 * before_cb: an callback function to be called before those of the subelements
 * after_cb: an callback function to be called after those of the subelements
 */


/**
 * @brief Create a single-character match element.
 *
 * Matches exactly one byte at the current parser offset if that byte is
 * present in @p needles. On success returns a simple element one byte long.
 *
 * @param id           Caller-assigned identifier stored in the returned element.
 * @param needles      A string whose characters form the set of accepted bytes.
 * @param private_data Opaque caller data passed to the callbacks.
 * @param before_cb    Callback invoked before the match is consumed, or NULL.
 * @param after_cb     Callback invoked after the match is consumed, or NULL.
 * @return A newly allocated @c tvbparse_wanted_t describing this element.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t *tvbparse_char(const int id,
                                 const char *needles,
                                 const void *private_data,
                                 tvbparse_action_t before_cb,
                                 tvbparse_action_t after_cb);


/**
 * @brief Create a single-character exclusion match element.
 *
 * When looked for it returns a simple element one character long if the char
 * at the current offset does not match one of the needles.
 *
 * @param id           Caller-assigned identifier stored in the returned element.
 * @param needle       A string whose characters form the set of rejected bytes.
 * @param private_data Opaque caller data passed to the callbacks.
 * @param before_cb    Callback invoked before the match is consumed, or NULL.
 * @param after_cb     Callback invoked after the match is consumed, or NULL.
 * @return A newly allocated @c tvbparse_wanted_t describing this element.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t *tvbparse_not_char(const int id,
                                     const char *needle,
                                     const void *private_data,
                                     tvbparse_action_t before_cb,
                                     tvbparse_action_t after_cb);

/**
 * @brief Create a multi-character span match element.
 *
 * When looked for it returns a simple element one or more characters long if
 * one or more char(s) starting from the current offset match one of the needles.
 * An element will be returned if at least min_len chars are given (1 if it's 0)
 * It will get at most max_len chars or as much as it can if max_len is 0.
 *
 * @param id           Caller-assigned identifier stored in the returned element.
 * @param min_len      Minimum number of matching bytes required for success;
 *                     treated as 1 if 0.
 * @param max_len      Maximum number of bytes to consume; 0 means unlimited.
 * @param needles      A string whose characters form the set of accepted bytes.
 * @param private_data Opaque caller data passed to the callbacks.
 * @param before_cb    Callback invoked before the match is consumed, or NULL.
 * @param after_cb     Callback invoked after the match is consumed, or NULL.
 * @return A newly allocated @c tvbparse_wanted_t describing this element.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t *tvbparse_chars(const int id,
                                  const unsigned min_len,
                                  const unsigned max_len,
                                  const char *needles,
                                  const void *private_data,
                                  tvbparse_action_t before_cb,
                                  tvbparse_action_t after_cb);

/**
 * @brief Create a multi-character exclusion span match element.
 *
 * When looked for it returns a simple element one or more characters long if
 * one or more char(s) starting from the current offset do not match one of the
 * needles.
 * An element will be returned if at least min_len chars are given (1 if it's 0)
 * It will get at most max_len chars or as much as it can if max_len is 0.
 *
 * @param id           Caller-assigned identifier stored in the returned element.
 * @param min_len      Minimum number of non-matching bytes required for success;
 *                     treated as 1 if 0.
 * @param max_len      Maximum number of bytes to consume; 0 means unlimited.
 * @param needles      A string whose characters form the set of rejected bytes.
 * @param private_data Opaque caller data passed to the callbacks.
 * @param before_cb    Callback invoked before the match is consumed, or NULL.
 * @param after_cb     Callback invoked after the match is consumed, or NULL.
 * @return A newly allocated @c tvbparse_wanted_t describing this element.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t *tvbparse_not_chars(const int id,
                                      const unsigned min_len,
                                      const unsigned max_len,
                                      const char *needles,
                                      const void *private_data,
                                      tvbparse_action_t before_cb,
                                      tvbparse_action_t after_cb);

/**
 * @brief Create a case-sensitive literal string match element.
 *
 * When looked for it returns a simple element if we have the given string at
 * the current offset
 *
 * @param id           Caller-assigned identifier stored in the returned element.
 * @param string       The literal byte sequence to match.
 * @param private_data Opaque caller data passed to the callbacks.
 * @param before_cb    Callback invoked before the match is consumed, or NULL.
 * @param after_cb     Callback invoked after the match is consumed, or NULL.
 * @return A newly allocated @c tvbparse_wanted_t describing this element.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t *tvbparse_string(const int id,
                                   const char *string,
                                   const void *private_data,
                                   tvbparse_action_t before_cb,
                                   tvbparse_action_t after_cb);

/**
 * @brief Create a case-insensitive literal string match element.
 *
 * When looked for it returns a simple element if we have a matching string at
 * the current offset
 *
 * @param id        Caller-assigned identifier stored in the returned element.
 * @param str       The literal string to match case-insensitively.
 * @param data      Opaque caller data passed to the callbacks.
 * @param before_cb Callback invoked before the match is consumed, or NULL.
 * @param after_cb  Callback invoked after the match is consumed, or NULL.
 * @return A newly allocated @c tvbparse_wanted_t describing this element.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t *tvbparse_casestring(const int id,
                                       const char *str,
                                       const void *data,
                                       tvbparse_action_t before_cb,
                                       tvbparse_action_t after_cb);

/**
 * @brief Create an "until" match element that consumes bytes up to a terminator.
 *
* When looked for it returns a simple element containing all the characters
 * found until the first match of the ending element if the ending element is
 *
 * When looking for until elements it calls tvbparse_find so it can be very slow.
 *
 * It won't have a subelement, the ending's callbacks won't get called.
 * op_mode values determine how the terminating element and the current offset
 * of the parser are handled
 *
 * @param id           Caller-assigned identifier stored in the returned element.
 * @param private_data Opaque caller data passed to the callbacks.
 * @param before_cb    Callback invoked before the match is consumed, or NULL.
 * @param after_cb     Callback invoked after the match is consumed, or NULL.
 * @param ending       The terminating element to search for.
 * @param until_mode   Controls how the terminator affects the returned element
 *                     and parser offset.
 * @return A newly allocated @c tvbparse_wanted_t describing this element.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t *tvbparse_until(const int id,
                                  const void *private_data,
                                  tvbparse_action_t before_cb,
                                  tvbparse_action_t after_cb,
                                  const tvbparse_wanted_t *ending,
                                  until_mode_t until_mode);

/**
 * @brief Create a one-of alternation element.
 *
 * When looked for it will try to match to the given candidates and return a
 * composed element whose subelement is the first match.
 *
 * The list of candidates is terminated with a NULL
 *
 * @param id           Caller-assigned identifier stored in the returned element.
 * @param private_data Opaque caller data passed to the callbacks.
 * @param before_cb    Callback invoked before the match is consumed, or NULL.
 * @param after_cb     Callback invoked after the match is consumed, or NULL.
 * @param ...          NULL-terminated list of @c tvbparse_wanted_t* candidates
 *                     to try in order.
 * @return A newly allocated @c tvbparse_wanted_t describing this alternation.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t *tvbparse_set_oneof(const int id,
                                      const void *private_data,
                                      tvbparse_action_t before_cb,
                                      tvbparse_action_t after_cb,
                                      ...);

/**
 * @brief Create a hash-dispatch element that selects a sub-element by key.
 *
 * @param id        Caller-assigned identifier stored in the returned element.
 * @param data      Opaque caller data passed to the callbacks.
 * @param before_cb Callback invoked before the match is consumed, or NULL.
 * @param after_cb  Callback invoked after the match is consumed, or NULL.
 * @param key       The element used to extract the dispatch key string.
 * @param other     Fallback element used when the key has no hash entry;
 *                  NULL to fail the match when no entry is found.
 * @param ...       Optional additional NULL-terminated alternating pairs of
 *                  @c char* key name and @c tvbparse_wanted_t* element.
 * @return A newly allocated @c tvbparse_wanted_t describing this element.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t *tvbparse_hashed(const int id,
                                   const void *data,
                                   tvbparse_action_t before_cb,
                                   tvbparse_action_t after_cb,
                                   tvbparse_wanted_t *key,
                                   tvbparse_wanted_t *other,
                                   ...);

/**
 * @brief Adds a hashed element to the wanted list.
 *
 * @param w Pointer to the tvbparse_wanted_t structure.
 * @param ... Variable arguments, alternating between name (char*) and element (tvbparse_wanted_t*).
 */
WS_DLL_PUBLIC
void tvbparse_hashed_add(tvbparse_wanted_t *w, ...);

/**
 * @brief Create a sequential composition element.
 *
 * When looked for it will try to match in order all the given candidates. If
 * every candidate is found in the given order it will return a composed
 * element whose subelements are the matched elements.
 *
 * The list of candidates is terminated with a NULL.
 *
 * @param id           Caller-assigned identifier stored in the returned element.
 * @param private_data Opaque caller data passed to the callbacks.
 * @param before_cb    Callback invoked before the sequence is consumed, or NULL.
 * @param after_cb     Callback invoked after the sequence is consumed, or NULL.
 * @param ...          NULL-terminated list of @c tvbparse_wanted_t* candidates
 *                     to match in order.
 * @return A newly allocated @c tvbparse_wanted_t describing this sequence.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t *tvbparse_set_seq(const int id,
                                    const void *private_data,
                                    tvbparse_action_t before_cb,
                                    tvbparse_action_t after_cb,
                                    ...);

/**
 * @brief Creates a parsing element that matches a given candidate a specified number of times.
 *
 * When looked for it will try to match the given candidate at least min times
 * and at most max times. If the given candidate is matched at least min times
 * a composed element is returned.
 *
 * @param id Identifier for the parsing element.
 * @param min Minimum number of times the candidate should be matched.
 * @param max Maximum number of times the candidate should be matched.
 * @param data User-defined data to be associated with the parsing element.
 * @param before_cb Callback function to be called before parsing the element.
 * @param after_cb Callback function to be called after parsing the element.
 * @param wanted The candidate element to be matched repeatedly.
 * @return A pointer to a tvbparse_wanted_t structure representing the parsing element.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_some(const int id,
                                 const unsigned min,
                                 const unsigned max,
                                 const void* data,
                                 tvbparse_action_t before_cb,
                                 tvbparse_action_t after_cb,
                                 const tvbparse_wanted_t* wanted);

#define tvbparse_one_or_more(id, private_data, before_cb, after_cb, wanted)\
    tvbparse_some(id, 1, INT_MAX, private_data, before_cb, after_cb, wanted)


/**
 * @brief Create an indirect reference element for recursive grammars.
 *
 * this is a pointer to a pointer to a wanted element (that might have not
 * been initialized yet) so that recursive structures
 * @param handle Pointer to the @c tvbparse_wanted_t* that will be resolved
 *               at match time. The pointed-to value must be non-NULL before
 *               the first call to @c tvbparse_get() or @c tvbparse_find()
 *               that may reach this element.
 * @return A newly allocated @c tvbparse_wanted_t that indirects through
 *         @p handle when matched.
 *
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_handle(tvbparse_wanted_t** handle);

/**
 * @brief Parses quoted strings in a given data buffer.
 *
 * this is a composed candidate, that will try to match a quoted string
 * (included the quotes) including into it every escaped quote.
 *
 *  C strings are matched with tvbparse_quoted(-1,NULL,NULL,NULL,"\"","\\")
 *
 * @param id Identifier for the parsed token.
 * @param data Pointer to the data buffer containing the quoted strings.
 * @param before_cb Callback function to be invoked before parsing.
 * @param after_cb Callback function to be invoked after parsing.
 * @param quote Character used as the quote delimiter.
 * @param escape Character used for escaping special characters within quotes.
 * @return A tvbparse_wanted_t structure representing the parsed quoted strings.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_quoted(const int id,
                                   const void* data,
                                   tvbparse_action_t before_cb,
                                   tvbparse_action_t after_cb,
                                   const char quote,
                                   const char escape);

/*
 * a helper callback for quoted strings that will shrink the token to contain
 * only the string and not the quotes
 */
/**
 * @brief Callback function to shrink token length and offset.
 *
 * This callback is invoked before or after an element has been processed.
 * It adjusts the token's offset and length by incrementing the offset and decrementing the length by 2.
 *
 * @param tvbparse_data User data passed to the callback (not used).
 * @param wanted_data Wanted data for the element (not used).
 * @param tok Pointer to the current token being processed.
 */
WS_DLL_PUBLIC
void tvbparse_shrink_token_cb(void* tvbparse_data,
                              const void* wanted_data,
                              tvbparse_elem_t* tok);




/**
 * @brief Initialize a new TVB parser.
 *
 * initialize the parser (at every packet)
 * scope: memory scope/pool
 * tvb: what are we parsing?
 * offset: from where
 * len: for how many bytes
 * private_data: will be passed to the action callbacks
 * ignore: a wanted token type to be ignored (the associated cb WILL be called when it matches)
 *
 * @param scope Memory allocation scope for the parser.
 * @param tvb The input tvbuff to parse.
 * @param offset Starting offset within the tvbuff.
 * @param len Length of data to parse, or -1 to use the entire captured length.
 * @param private_data Private data to associate with the parser.
 * @param ignore Configuration for ignored elements during parsing.
 * @return Pointer to the initialized tvbparse_t structure.
 */
WS_DLL_PUBLIC
tvbparse_t* tvbparse_init(wmem_allocator_t *scope,
                          tvbuff_t* tvb,
                          const int offset,
                          int len,
                          void* private_data,
                          const tvbparse_wanted_t* ignore);

/**
 * @brief Resets the token buffer parser to a new offset and length.
 *
 * @param tt Pointer to the tvbparse_t structure.
 * @param offset The new starting offset for parsing.
 * @param len The new length of data to parse.
 * @return true if the reset is successful, false otherwise.
 */
WS_DLL_PUBLIC
bool tvbparse_reset(tvbparse_t* tt, const unsigned offset, unsigned len);

/**
 * @brief Get the current offset in the TVB parse structure.
 *
 * @param tt Pointer to the TVB parse structure.
 * @return The current offset.
 */
WS_DLL_PUBLIC
unsigned tvbparse_curr_offset(tvbparse_t* tt);

/**
 * @brief Get the number of bytes left to parse in the TVB parse structure.
 *
 * @param tt Pointer to the TVB parse structure.
 * @return The number of bytes left to parse.
 */
unsigned tvbparse_len_left(tvbparse_t* tt);

/**
 * @brief Peeks at the next token in the buffer without advancing the parser.
 *
 * This will look for the wanted token at the current offset or after any given
 * number of ignored tokens returning false if there's no match or true if there
 * is a match.
 * The parser will be left in its original state and no callbacks will be called.
 *
 * @param tt Pointer to the tvbparse_t structure representing the parser state.
 * @param wanted Pointer to the tvbparse_wanted_t structure describing the token to look for.
 * @return True if a match is found, false otherwise.
 */
WS_DLL_PUBLIC
bool tvbparse_peek(tvbparse_t* tt,
                       const tvbparse_wanted_t* wanted);

/**
 * @brief Retrieves a token based on the specified conditions.
 *
 * This will look for the wanted token at the current offset or after any given
 * number of ignored tokens returning NULL if there's no match.
 * if there is a match it will set the offset of the current parser after
 * the end of the token
 *
 * @param tt Pointer to the TVB parse context.
 * @param wanted Pointer to the structure containing the conditions for the desired token.
 * @return Pointer to the retrieved token if successful, NULL otherwise.
 */
WS_DLL_PUBLIC
tvbparse_elem_t* tvbparse_get(tvbparse_t* tt,
                              const tvbparse_wanted_t* wanted);

/**
 * @brief Finds an element in a TVB parse structure based on a given condition.
 *
 * Like tvbparse_get but this will look for a wanted token even beyond the
 * current offset.
 * This function is slow.
 *
 * @param tt Pointer to the TVB parse structure.
 * @param wanted Pointer to the wanted element description, including the condition function.
 * @return Pointer to the found element if successful, NULL otherwise.
 */
WS_DLL_PUBLIC
tvbparse_elem_t* tvbparse_find(tvbparse_t* tt,
                               const tvbparse_wanted_t* wanted);

/**
 * @brief Adds an element to a protocol tree.
 *
 * @param tree The protocol tree to which the element will be added.
 * @param curr The current element being processed.
 */
WS_DLL_PUBLIC
void tvbparse_tree_add_elem(proto_tree* tree, tvbparse_elem_t* curr);
