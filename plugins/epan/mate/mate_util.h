/* mate_util.h
 *
 * Copyright 2004, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __AVP_H_
#define __AVP_H_
#include "epan/proto.h"
#include <sys/types.h>

/* #define _AVP_DEBUGGING */


/******* dbg_print *********/
#define DEBUG_BUFFER_SIZE 4096

/**
 * @brief Prints debug information to a specified output.
 *
 * @param which Pointer to an integer indicating the verbosity level.
 * @param how The minimum verbosity level required for printing.
 * @param where File stream to print to, or NULL to use ws_message().
 * @param fmt Format string for the message.
 */
extern void dbg_print(const int* which, int how, FILE* where,
	const char* fmt, ... ) G_GNUC_PRINTF(4, 5);


/******* single copy strings *********/
typedef struct _scs_collection SCS_collection;

#define SCS_HUGE_SIZE 65535

/**
 * @brief Subscribe to a collection with a given string.
 *
 * @param collection Pointer to the SCS_collection structure.
 * @param s The string to subscribe to.
 * @return A pointer to the original string or NULL on failure.
 */
extern char* scs_subscribe(SCS_collection* collection, const char* s);
/**
 * @brief Unsubscribe a string from an SCS collection, releasing it if
 * no other subscribers remain.
 *
 * @param collection The SCS collection to unsubscribe from.
 * @param s          The string to unsubscribe.
 */
extern void scs_unsubscribe(SCS_collection* collection, char* s);

/**
 * @brief Format a string and subscribe it to an SCS collection.
 *
 * @param collection The SCS collection to subscribe to.
 * @param fmt        A printf-style format string.
 * @param ...        Arguments for the format string.
 * @return The subscribed string, or NULL on failure.
 */
extern char* scs_subscribe_printf(SCS_collection* collection, char* fmt, ...)
	G_GNUC_PRINTF(2, 3);

/******* AVPs & Co. *********/

/* these are the defined operators of avps */
#define AVP_OP_EQUAL		'='
#define AVP_OP_NOTEQUAL		'!'
#define AVP_OP_STARTS		'^'
#define AVP_OP_ENDS		'$'
#define AVP_OP_CONTAINS		'~'
#define AVP_OP_LOWER		'<'
#define AVP_OP_HIGHER		'>'
#define AVP_OP_EXISTS		'?'
#define AVP_OP_ONEOFF		'|'
#define AVP_OP_TRANSF		'&'


/* an avp is an object made of a name a value and an operator */
typedef struct _avp {
	char* n;
	char* v;
	char o;
} AVP;

/* avp nodes are used in avp lists */
typedef struct _avp_node {
	AVP* avp;
	struct _avp_node* next;
	struct _avp_node* prev;
} AVPN;

/* an avp list is a sorted set of avps */
typedef struct _avp_list {
	char* name;
	uint32_t len;
	AVPN null;
} AVPL;



/* an avpl transformation operation */
typedef enum _avpl_match_mode {
	AVPL_NO_MATCH,
	AVPL_STRICT,
	AVPL_LOOSE,
	AVPL_EVERY
} avpl_match_mode;

typedef enum _avpl_replace_mode {
	AVPL_NO_REPLACE,
	AVPL_INSERT,
	AVPL_REPLACE
} avpl_replace_mode;

typedef struct _avpl_transf AVPL_Transf;

struct _avpl_transf {
	char* name;

	AVPL* match;
	AVPL* replace;

	avpl_match_mode match_mode;
	avpl_replace_mode replace_mode;

	GHashTable* map;
	AVPL_Transf* next;
};

/* loalnodes are used in LoALs */
typedef struct _loal_node {
	AVPL* avpl;
	struct _loal_node *next;
	struct _loal_node *prev;
} LoALnode;


/* a loal is a list of avp lists */
typedef struct _loal {
	char* name;
	unsigned len;
	LoALnode null;
} LoAL;


/* avp library (re)initialization */

/**
 * @brief Initializes the AVP strings collection.
 *
 * This function initializes the AVP strings collection by destroying any existing
 * collection and creating a new one.
 */
extern void avp_init(void);

/* If enabled set's up the debug facilities for the avp library */
#ifdef _AVP_DEBUGGING
extern void setup_avp_debug(FILE* fp, int* general, int* avp, int* avp_op, int* avpl, int* avpl_op);
#endif /* _AVP_DEBUGGING */

/*
 * avp constructors
 */

/* creates a new avp */

/**
 * @brief Creates a new AVP with the given name, value, and operator.
 *
 * @param name The name of the AVP.
 * @param value The value of the AVP.
 * @param op The operator for the AVP.
 * @return A pointer to the newly created AVP.
 */
extern AVP* new_avp(const char* name, const char* value, char op);

/**
 * @brief Copies an AVP structure.
 *
 * Creates a new AVP structure and copies the values from the source AVP.
 *
 * @param from The source AVP to copy.
 * @return A pointer to the newly created AVP, or NULL if memory allocation fails.
 */
extern AVP* avp_copy(AVP* from);

/**
 * @brief Creates an AVP from field information.
 *
 * creates an avp from a field_info record
 *
 * @param name The name of the AVP.
 * @param finfo The field information containing the value to be converted.
 * @return A new AVP with the value set based on the field information.
 */
extern AVP* new_avp_from_finfo(const char* name, field_info* finfo);

/**
 * @brief Destroys an AVP and frees its memory.
 *
 * @param avp The AVP to destroy.
 */
extern void delete_avp(AVP* avp);

/*
 * avp methods
 */
/**
 * @brief Converts an AVP to a string representation.
 *
 * @param avp The AVP to convert.
 * @return A pointer to the newly allocated string containing the representation of the AVP.
 */
#define avp_to_str(avp) (ws_strdup_printf("%s%c%s",avp->n,avp->o,avp->v))

/**
 * @brief Matches an AVP against another AVP.
 *
 * Compares two AVPs (Attribute-Value Pairs) and returns a pointer to the matching AVP if they match, or NULL otherwise.
 *
 * @param src The source AVP to be compared.
 * @param op The operation AVP containing the criteria for comparison.
 * @return A pointer to the matching AVP if found; otherwise, NULL.
 */
extern AVP* match_avp(AVP* src, AVP* op);


/*
 * avplist constructors
 */

/**
 * @brief Creates a new AVPL (Attribute-Value-Pair List) object.
 *
 * @param name The name of the AVPL.
 * @return A pointer to the newly created AVPL object.
 */
extern AVPL* new_avpl(const char* name);


/**
 * @brief Creates a new AVPL from an existing one.
 *
 * @param name The name of the new AVPL.
 * @param avpl The existing AVPL to copy.
 * @param copy_avps Whether to copy the AVPs or not.
 * @return A pointer to the newly created AVPL.
 */
extern AVPL* new_avpl_from_avpl(const char* name, AVPL* avpl, bool copy_avps);

/**
 * @brief Create a new AVPL by loosely matching a source AVPL against an
 * operand AVPL.
 *
 * @param name      The name to assign to the new AVPL.
 * @param src       The source AVPL to match against.
 * @param op        The operand AVPL containing the match criteria.
 * @param copy_avps Whether to copy the AVPs into the new AVPL rather than
 *                  referencing them.
 * @return A new AVPL containing the matched AVPs, or NULL if no match.
 */
extern AVPL* new_avpl_loose_match(const char* name, AVPL* src, AVPL* op, bool copy_avps);


/**
 * @brief Create a new AVPL by matching pairs of AVPs from a source AVPL
 * against an operand AVPL.
 *
 * @param name      The name to assign to the new AVPL.
 * @param src       The source AVPL to match against.
 * @param op        The operand AVPL containing the match criteria.
 * @param strict    Whether to require all AVPs in @p op to match.
 * @param copy_avps Whether to copy the AVPs into the new AVPL rather than
 *                  referencing them.
 * @return A new AVPL containing the matched AVPs, or NULL if no match.
 */
extern AVPL* new_avpl_pairs_match(const char* name, AVPL* src, AVPL* op, bool strict, bool copy_avps);

/* uses mode to call one of the former matches. NO_MATCH = merge(merge(copy(src),op)) */

/**
 * @brief Creates a new AVPL based on the given match mode.
 *
 * Uses the provided mode to call one of the former matches. NO_MATCH = merge(merge(copy(src),op))
 *
 * @param mode The match mode to use for creating the AVPL.
 * @param name The name to assign to the new AVPL.
 * @param src The source AVPL.
 * @param op The operation AVPL.
 * @param copy_avps Whether to copy the AVPs.
 * @return A pointer to the newly created AVPL, or NULL if an error occurs.
 */
extern AVPL* new_avpl_from_match(avpl_match_mode mode, const char* name,AVPL* src, AVPL* op, bool copy_avps);


/*
 * functions on avpls
 */

/**
 * @brief Inserts an AVP into an AVPL.
 *
 * @param avpl The AVPL to insert the AVP into.
 * @param avp The AVP to insert.
 * @return true if the AVP was inserted, false otherwise.
 */
extern bool insert_avp(AVPL* avpl, AVP* avp);

/**
 * @brief Renames an AVPL (Attribute Value Pair List) to a new name.
 *
 * @param avpl Pointer to the AVPL to be renamed.
 * @param name The new name for the AVPL.
 */
extern void rename_avpl(AVPL* avpl, char* name);

/**
 * @brief Merges two AVPL structures.
 *
 * Merges the source AVPL into the destination AVPL. If copy_avps is true, copies the AVP values; otherwise, moves them.
 * It will add all the avps in src which don't match(*) any attribute in dest
 *
 * @param dest Destination AVPL to merge into.
 * @param src Source AVPL to merge from.
 * @param copy Flag indicating whether to copy or move AVP values.
 */
extern void merge_avpl(AVPL* dest, AVPL* src, bool copy);

/**
 * @brief Retrieves an AVP by name from an AVPL.
 *
 * it will return the first avp in an avpl whose name matches the given name.
 * will return NULL if there is not anyone matching
 *
 * @param avpl The AVPL to search within.
 * @param name The name of the AVP to retrieve.
 * @param cookie A pointer to a void pointer that can be used for resuming the search. If NULL, the search starts from the beginning.
 * @return The found AVP if successful; otherwise, NULL.
 */
extern AVP* get_avp_by_name(AVPL* avpl, char* name, void** cookie);

/**
 * @brief Retrieves the next AVP from an AVPL list.
 *
 * Get the next avp from an avpl, using cookie to keep state
 *
 * @param avpl The AVPL list to retrieve the AVP from.
 * @param cookie A pointer to a void pointer that acts as a cursor for iteration.
 * @return The next AVP in the list, or NULL if there are no more AVPs.
 */
extern AVP* get_next_avp(AVPL* avpl, void** cookie);

/**
 * @brief Extracts the first AVP from an AVPL list.
 *
 * @param avpl Pointer to the AVPL list.
 * @return Pointer to the extracted AVP, or NULL if no AVP is available.
 */
extern AVP* extract_first_avp(AVPL* avpl);

/**
 * @brief Extracts and returns the last AVP from an AVPL list.
 *
 * @param avpl Pointer to the AVPL list.
 * @return Pointer to the extracted AVP, or NULL if the list is empty.
 */
extern AVP* extract_last_avp(AVPL* avpl);

/**
 * @brief Extracts an AVP by name from an AVPL.
 *
 * it will extract the first avp in an avpl whose name matches the given name.
 * it will not extract any and  return NULL if there is not anyone matching
 *
 * @param avpl The AVPL to search within.
 * @param name The name of the AVP to extract.
 * @return The extracted AVP if found, NULL otherwise.
 */
extern AVP* extract_avp_by_name(AVPL* avpl, char* name);

/**
 * @brief Convert an AVPL to a string representation.
 *
 * Returns a newly allocated string containing a representation of the avp list
 *
 * @param avpl The AVPL to convert.
 * @return A string representing the AVPL.
 */
extern char* avpl_to_str(AVPL* avpl);

/**
 * @brief Converts an AVPL to a DOT string representation.
 *
 * This function takes an AVPL (Attribute-Value Pair List) and converts it into a string in DOT format, which is commonly used for graph visualization.
 *
 * @param avpl The AVPL to convert.
 * @return A dynamically allocated string representing the AVPL in DOT format. The caller is responsible for freeing this memory.
 */
extern char* avpl_to_dotstr(AVPL* avpl);

/* deletes an avp list  and eventually its contents */

/**
 * @brief Deletes an AVPL and optionally its contained AVPs.
 *
 * @param avpl Pointer to the AVPL to be deleted.
 * @param avps_too If true, also deletes all contained AVPs.
 */
extern void delete_avpl(AVPL* avpl, bool avps_too);

/*
 *  AVPL transformations
 */
/**
 * @brief Free an AVPL transformation and all its resources.
 *
 * @param it The AVPL transformation to delete.
 */
extern void delete_avpl_transform(AVPL_Transf* it);

/**
 * @brief Apply an AVPL transformation to a source AVPL in place.
 *
 * @param src The source AVPL to transform.
 * @param op  The transformation to apply.
 */
extern void avpl_transform(AVPL* src, AVPL_Transf* op);


/*
 * Lists of AVP lists
 */

/**
 * @brief Creates a new LoAL object with the given name.
 *
 * creates an empty list of avp lists
 *
 * @param name The name of the LoAL object.
 * @return A pointer to the newly created LoAL object.
 */
extern LoAL* new_loal(const char* name);

/**
 * @brief Creates a new LoAL object from a file.
 *
 * given a file loads all the avpls contained in it
 * every line is formatted as it is the output of avplist_to_string
 *
 * @param filename The name of the file to read.
 * @return A pointer to the newly created LoAL object, or NULL if an error occurred.
 */
extern LoAL* loal_from_file(char* filename);

/**
 * @brief Appends an AVPL to a LoAL.
 *
 * @param loal The LoAL to which the AVPL will be appended.
 * @param avpl The AVPL to append to the LoAL.
 */
extern void loal_append(LoAL* loal, AVPL* avpl);

/**
 * @brief Extracts the first AVPL from a LoAL.
 *
 * @param loal The LoAL from which to extract the first AVPL.
 * @return The extracted AVPL, or NULL if no AVPL is available.
 */
extern AVPL* extract_first_avpl(LoAL* loal);

/**
 * @brief Extracts and returns the last AVPL from a LoAL.
 *
 * @param loal The LoAL from which to extract the last AVPL.
 * @return The extracted AVPL, or NULL if the LoAL is empty.
 */
extern AVPL* extract_last_avpl(LoAL* loal);

/**
 * @brief Retrieves the next AVPL node from a LoAL structure.
 *
 * Get the next avp list from a LoAL, using cookie to keep state
 *
 * @param loal Pointer to the LoAL structure.
 * @param cookie Pointer to a void pointer that acts as an iterator for the LoAL nodes.
 * @return Pointer to the next AVPL node, or NULL if no more nodes are available.
 */
extern AVPL* get_next_avpl(LoAL* loal,void** cookie);

/**
 * @brief Deletes a LoAL and optionally its AVPLs and AVPs.
 *
 * @param loal The LoAL to delete.
 * @param avpls_too If true, deletes all AVPLs in the LoAL.
 * @param avps_too If true, deletes all AVPs in the AVPLs.
 */
extern void delete_loal(LoAL* loal, bool avpls_too, bool avps_too);


#endif
