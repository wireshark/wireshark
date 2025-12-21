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

#ifndef _TVB_PARSE_H_
#define _TVB_PARSE_H_

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


typedef enum  {
    TP_UNTIL_INCLUDE, /* last elem is included, its span is spent by the parser */
    TP_UNTIL_SPEND, /* last elem is not included, but its span is spent by the parser */
    TP_UNTIL_LEAVE /* last elem is not included, neither its span is spent by the parser */
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


/* a matching token returned by either tvbparser_get or tvb_parser_find */
struct _tvbparse_elem_t {
    int id;

    tvbparse_t* parser;
    tvbuff_t* tvb;
    int offset;
    int len;

    void* data;

    struct _tvbparse_elem_t* sub;

    struct _tvbparse_elem_t* next;
    struct _tvbparse_elem_t* last;

    const tvbparse_wanted_t* wanted;
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


/*
 * a char element.
 *
 * When looked for it returns a simple element one character long if the char
 * at the current offset matches one of the needles.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_char(const int id,
                                 const char* needles,
                                 const void* private_data,
                                 tvbparse_action_t before_cb,
                                 tvbparse_action_t after_cb);

/*
 * a not_char element.
 *
 * When looked for it returns a simple element one character long if the char
 * at the current offset does not match one of the needles.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_not_char(const int id,
                                     const char* needle,
                                     const void* private_data,
                                     tvbparse_action_t before_cb,
                                     tvbparse_action_t after_cb);

/*
 * a chars element
 *
 * When looked for it returns a simple element one or more characters long if
 * one or more char(s) starting from the current offset match one of the needles.
 * An element will be returned if at least min_len chars are given (1 if it's 0)
 * It will get at most max_len chars or as much as it can if max_len is 0.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_chars(const int id,
                                  const unsigned min_len,
                                  const unsigned max_len,
                                  const char* needles,
                                  const void* private_data,
                                  tvbparse_action_t before_cb,
                                  tvbparse_action_t after_cb);

/*
 * a not_chars element
 *
 * When looked for it returns a simple element one or more characters long if
 * one or more char(s) starting from the current offset do not match one of the
 * needles.
 * An element will be returned if at least min_len chars are given (1 if it's 0)
 * It will get at most max_len chars or as much as it can if max_len is 0.
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_not_chars(const int id,
                                      const unsigned min_len,
                                      const unsigned max_len,
                                      const char* needles,
                                      const void* private_data,
                                      tvbparse_action_t before_cb,
                                      tvbparse_action_t after_cb);

/*
 * a string element
 *
 * When looked for it returns a simple element if we have the given string at
 * the current offset
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_string(const int id,
                                   const char* string,
                                   const void* private_data,
                                   tvbparse_action_t before_cb,
                                   tvbparse_action_t after_cb);

/*
 * casestring
 *
 * When looked for it returns a simple element if we have a matching string at
 * the current offset
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_casestring(const int id,
                                       const char* str,
                                       const void* data,
                                       tvbparse_action_t before_cb,
                                       tvbparse_action_t after_cb);

/*
 * until
 *
 * When looked for it returns a simple element containing all the characters
 * found until the first match of the ending element if the ending element is
 * found.
 *
 * When looking for until elements it calls tvbparse_find so it can be very slow.
 *
 * It won't have a subelement, the ending's callbacks won't get called.
 */

/*
 * op_mode values determine how the terminating element and the current offset
 * of the parser are handled
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_until(const int id,
                                  const void* private_data,
                                  tvbparse_action_t before_cb,
                                  tvbparse_action_t after_cb,
                                  const tvbparse_wanted_t* ending,
                                  until_mode_t until_mode);

/*
 * one_of
 *
 * When looked for it will try to match to the given candidates and return a
 * composed element whose subelement is the first match.
 *
 * The list of candidates is terminated with a NULL
 *
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_set_oneof(const int id,
                                      const void* private_data,
                                      tvbparse_action_t before_cb,
                                      tvbparse_action_t after_cb,
                                      ...);

/*
 * hashed
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_hashed(const int id,
                                   const void* data,
                                   tvbparse_action_t before_cb,
                                   tvbparse_action_t after_cb,
                                   tvbparse_wanted_t* key,
                                   tvbparse_wanted_t* other,
                                   ...);

WS_DLL_PUBLIC
void tvbparse_hashed_add(tvbparse_wanted_t* w, ...);

/*
 * sequence
 *
 * When looked for it will try to match in order all the given candidates. If
 * every candidate is found in the given order it will return a composed
 * element whose subelements are the matched elements.
 *
 * The list of candidates is terminated with a NULL.
 *
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_set_seq(const int id,
                                    const void* private_data,
                                    tvbparse_action_t before_cb,
                                    tvbparse_action_t after_cb,
                                    ...);

/*
 * some
 *
 * When looked for it will try to match the given candidate at least min times
 * and at most max times. If the given candidate is matched at least min times
 * a composed element is returned.
 *
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_some(const int id,
                                 const unsigned min,
                                 const unsigned max,
                                 const void* private_data,
                                 tvbparse_action_t before_cb,
                                 tvbparse_action_t after_cb,
                                 const tvbparse_wanted_t* wanted);

#define tvbparse_one_or_more(id, private_data, before_cb, after_cb, wanted)\
    tvbparse_some(id, 1, INT_MAX, private_data, before_cb, after_cb, wanted)


/*
 * handle
 *
 * this is a pointer to a pointer to a wanted element (that might have not
 * been initialized yet) so that recursive structures
 */
WS_DLL_PUBLIC
tvbparse_wanted_t* tvbparse_handle(tvbparse_wanted_t** handle);

/*  quoted
 *  this is a composed candidate, that will try to match a quoted string
 *  (included the quotes) including into it every escaped quote.
 *
 *  C strings are matched with tvbparse_quoted(-1,NULL,NULL,NULL,"\"","\\")
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
WS_DLL_PUBLIC
void tvbparse_shrink_token_cb(void* tvbparse_data,
                              const void* wanted_data,
                              tvbparse_elem_t* tok);




/* initialize the parser (at every packet)
 * scope: memory scope/pool
 * tvb: what are we parsing?
 * offset: from where
 * len: for how many bytes
 * private_data: will be passed to the action callbacks
 * ignore: a wanted token type to be ignored (the associated cb WILL be called when it matches)
 */
WS_DLL_PUBLIC
tvbparse_t* tvbparse_init(wmem_allocator_t *scope,
                          tvbuff_t* tvb,
                          const int offset,
                          int len,
                          void* private_data,
                          const tvbparse_wanted_t* ignore);

/* reset the parser */
WS_DLL_PUBLIC
bool tvbparse_reset(tvbparse_t* tt, const unsigned offset, unsigned len);

WS_DLL_PUBLIC
unsigned tvbparse_curr_offset(tvbparse_t* tt);
unsigned tvbparse_len_left(tvbparse_t* tt);



/*
 * This will look for the wanted token at the current offset or after any given
 * number of ignored tokens returning false if there's no match or true if there
 * is a match.
 * The parser will be left in its original state and no callbacks will be called.
 */
WS_DLL_PUBLIC
bool tvbparse_peek(tvbparse_t* tt,
                       const tvbparse_wanted_t* wanted);

/*
 * This will look for the wanted token at the current offset or after any given
 * number of ignored tokens returning NULL if there's no match.
 * if there is a match it will set the offset of the current parser after
 * the end of the token
 */
WS_DLL_PUBLIC
tvbparse_elem_t* tvbparse_get(tvbparse_t* tt,
                              const tvbparse_wanted_t* wanted);

/*
 * Like tvbparse_get but this will look for a wanted token even beyond the
 * current offset.
 * This function is slow.
 */
WS_DLL_PUBLIC
tvbparse_elem_t* tvbparse_find(tvbparse_t* tt,
                               const tvbparse_wanted_t* wanted);


WS_DLL_PUBLIC
void tvbparse_tree_add_elem(proto_tree* tree, tvbparse_elem_t* curr);

#endif
