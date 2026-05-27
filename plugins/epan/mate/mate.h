/* mate.h
 * MATE -- Meta Analysis and Tracing Engine
 *
 * Copyright 2004, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __MATE_H_
#define __MATE_H_

#define WS_LOG_DOMAIN "MATE"
#include <wireshark.h>

#include <gmodule.h>

#include <stdio.h>
#include <string.h>

#include <wsutil/report_message.h>
#include <wsutil/wslog.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/epan_dissect.h>
#include <wsutil/filesystem.h>

#include "mate_util.h"

/* defaults */

#define DEFAULT_GOG_EXPIRATION 2.0

#ifdef _WIN32
#define DIR_SEP '\\'
#else
#define DIR_SEP '/'
#endif

#define DEFAULT_MATE_LIB_PATH "matelib"

#define MATE_ITEM_ID_SIZE 24

#define VALUE_TOO ((void*)1)

#define MateConfigError 65535

/**
 * @brief Controls how much detail a GOP (Group of PDUs) subtree exposes in the protocol tree.
 */
typedef enum _gop_tree_mode_t {
    GOP_NULL_TREE,  /**< No GOP subtree is shown */
    GOP_BASIC_TREE, /**< Show a minimal GOP subtree with key attributes only */
    GOP_FULL_TREE   /**< Show the complete GOP subtree with all attributes */
} gop_tree_mode_t;


/**
 * @brief Controls how PDUs are displayed within a GOP node in the protocol tree.
 */
typedef enum _gop_pdu_tree {
    GOP_NO_TREE,       /**< Do not show PDU children under the GOP node */
    GOP_PDU_TREE,      /**< Show PDU items as children of the GOP node */
    GOP_FRAME_TREE,    /**< Show frame references as children of the GOP node */
    GOP_BASIC_PDU_TREE /**< Show a minimal PDU subtree with essential fields only */
} gop_pdu_tree_t;


/**
 * @brief Controls whether a criterium match causes a PDU to be accepted or rejected.
 */
typedef enum _accept_mode_t {
    ACCEPT_MODE, /**< A matching PDU is accepted and assigned to the GOP */
    REJECT_MODE  /**< A matching PDU is rejected and excluded from the GOP */
} accept_mode_t;


/**
 * @brief Configuration for a MATE PDU type, defining extraction rules and assignment criteria.
 */
typedef struct _mate_cfg_pdu {
    char      *name;          /**< Unique name identifying this PDU configuration */
    GPtrArray *transforms;    /**< Ordered list of AVPL transformations applied after attribute extraction */

    int hfid;                 /**< Header field ID for the MATE PDU item added to the protocol tree */
    int hfid_proto;           /**< Header field ID of the protocol that triggers this PDU configuration */
    int hfid_pdu_rel_time;    /**< Header field ID for the PDU's relative time since capture start */
    int hfid_pdu_time_in_gop; /**< Header field ID for the PDU's time offset since its GOP start */

    GHashTable *my_hfids;     /**< Hash table of hfid→field_name mappings used during field registration */

    int ett;                  /**< ett index for the PDU subtree */
    int ett_attr;             /**< ett index for the PDU attributes subtree */

    GHashTable *hfids_attr;   /**< Hash table mapping hfid → AVP attribute name for extracted fields */

    bool discard;             /**< If true, discard the PDU's AVPL after GOP assignment */
    bool last_extracted;      /**< If true, stop extraction after the first matching transport/payload range */
    bool drop_unassigned;     /**< If true, do not display PDUs that are not assigned to any GOP */

    GPtrArray *transport_ranges; /**< Array of hfid ranges from which to extract transport-layer attributes */
    GPtrArray *payload_ranges;   /**< Array of hfid ranges from which to extract payload-layer attributes */

    avpl_match_mode  criterium_match_mode;  /**< Match mode (any/all) applied to the criterium AVPL */
    accept_mode_t    criterium_accept_mode; /**< Whether a criterium match accepts or rejects the PDU */
    AVPL            *criterium;             /**< AVPL used to filter which PDUs are eligible for GOP assignment */
} mate_cfg_pdu;


/**
 * @brief Configuration for a MATE GOP (Group of PDUs) type, defining grouping and lifecycle rules.
 */
typedef struct _mate_cfg_gop {
    char      *name;       /**< Unique name identifying this GOP configuration */
    GPtrArray *transforms; /**< Ordered list of AVPL transformations applied to the GOP's AVPL */
    const char *on_pdu;    /**< Name of the mate_cfg_pdu type that feeds into this GOP */

    AVPL *key;   /**< AVPL defining the attributes that form the GOP's correlation key */
    AVPL *start; /**< AVPL whose match marks the first PDU as the GOP's start PDU */
    AVPL *stop;  /**< AVPL whose match marks a PDU as the GOP's stop PDU */
    AVPL *extra; /**< AVPL of additional attributes unconditionally merged into the GOP */

    double expiration;    /**< Seconds after release before the GOP expires and is discarded */
    double idle_timeout;  /**< Seconds of inactivity before an unreleased GOP is timed out */
    double lifetime;      /**< Maximum lifetime in seconds for a GOP regardless of release */

    bool           drop_unassigned; /**< If true, do not display GOPs not assigned to any GOG */
    gop_pdu_tree_t pdu_tree_mode;   /**< Controls how PDU children are shown under the GOP tree node */
    bool           show_times;      /**< If true, display GOP timing fields in the protocol tree */

    GHashTable *my_hfids;       /**< Hash table of hfid→field_name mappings for field registration */
    int hfid;                   /**< Header field ID for the GOP item in the protocol tree */
    int hfid_start_time;        /**< Header field ID for the GOP start timestamp */
    int hfid_stop_time;         /**< Header field ID for the GOP stop/release timestamp */
    int hfid_last_time;         /**< Header field ID for the timestamp of the last PDU in the GOP */
    int hfid_gop_pdu;           /**< Header field ID for PDU reference items under the GOP */
    int hfid_gop_num_pdus;      /**< Header field ID for the total PDU count of the GOP */

    int ett;           /**< ett index for the GOP subtree */
    int ett_attr;      /**< ett index for the GOP attributes subtree */
    int ett_times;     /**< ett index for the GOP timing subtree */
    int ett_children;  /**< ett index for the GOP children (PDUs) subtree */
} mate_cfg_gop;


/**
 * @brief Configuration for a MATE GOG (Group of GOPs) type, defining session-level grouping rules.
 */
typedef struct _mate_cfg_gog {
    char      *name;       /**< Unique name identifying this GOG configuration */
    GPtrArray *transforms; /**< Ordered list of AVPL transformations applied to the GOG's AVPL */

    LoAL *keys;   /**< List of AVPLs used as candidate correlation keys to match GOPs into this GOG */
    AVPL *extra;  /**< AVPL of additional attributes unconditionally merged into the GOG */

    double          expiration;    /**< Seconds after all GOPs release before the GOG expires */
    gop_tree_mode_t gop_tree_mode; /**< Controls how GOP children are shown under the GOG tree node */
    bool            show_times;    /**< If true, display GOG timing fields in the protocol tree */

    GHashTable *my_hfids;          /**< Hash table of hfid→field_name mappings for field registration */
    int hfid;                      /**< Header field ID for the GOG item in the protocol tree */
    int hfid_gog_num_of_gops;      /**< Header field ID for the total number of GOPs in the GOG */
    int hfid_gog_gop;              /**< Header field ID for GOP reference items under the GOG */
    int hfid_gog_gopstart;         /**< Header field ID for the GOP start marker under the GOG */
    int hfid_gog_gopstop;          /**< Header field ID for the GOP stop marker under the GOG */
    int hfid_start_time;           /**< Header field ID for the GOG start timestamp */
    int hfid_stop_time;            /**< Header field ID for the GOG stop/release timestamp */
    int hfid_last_time;            /**< Header field ID for the timestamp of the last activity in the GOG */

    int ett;          /**< ett index for the GOG subtree */
    int ett_attr;     /**< ett index for the GOG attributes subtree */
    int ett_times;    /**< ett index for the GOG timing subtree */
    int ett_children; /**< ett index for the GOG children (GOPs) subtree */
    int ett_gog_gop;  /**< ett index for the per-GOP subtree within the GOG */
} mate_cfg_gog;


/**
 * @brief Master MATE configuration, aggregating all PDU, GOP, and GOG type definitions.
 */
typedef struct _mate_config {
    int hfid_mate; /**< Root header field ID for the MATE dissector */

    GArray  *wanted_hfids;       /**< Array of hfids for all protocols and fields MATE monitors */
    unsigned num_fields_wanted;  /**< Number of entries in @ref wanted_hfids */

    FILE *dbg_facility;    /**< Output stream for debug messages; falls back to ws_message() if NULL */
    char *mate_lib_path;   /**< Primary search path for MATE "Include" configuration files */

    GHashTable *pducfgs; /**< Hash table of PDU configurations, keyed by mate_cfg_pdu::name */
    GHashTable *gopcfgs; /**< Hash table of GOP configurations, keyed by mate_cfg_gop::name */
    GHashTable *gogcfgs; /**< Hash table of GOG configurations, keyed by mate_cfg_gog::name */
    GHashTable *transfs; /**< Hash table of named AVPL transformations, keyed by transform name */

    GPtrArray  *pducfglist;       /**< Ordered list of PDU configurations in dissection execution order */
    GHashTable *gops_by_pduname;  /**< Maps PDU config name → GOP config for direct GOP lookup */
    GHashTable *gogs_by_gopname;  /**< Maps GOP name → LoAL of key AVPLs for GOG matching */

    GArray *hfrs;    /**< Array of hf_register_info entries for all dynamically registered fields */
    int     ett_root; /**< ett index for the MATE root subtree */
    GArray *ett;      /**< Array of ett index pointers for all MATE subtrees */

    /** @brief Default values applied to newly created PDU, GOP, and GOG configurations. */
    struct _mate_cfg_defaults {

        /** @brief Default settings for PDU configurations. */
        struct _pdu_defaults {
            avpl_match_mode   match_mode;      /**< Default AVPL match mode for PDU criteria */
            avpl_replace_mode replace_mode;    /**< Default AVPL replace mode for PDU transforms */
            bool              last_extracted;  /**< Default value for mate_cfg_pdu::last_extracted */
            bool              drop_unassigned; /**< Default value for mate_cfg_pdu::drop_unassigned */
            bool              discard;         /**< Default value for mate_cfg_pdu::discard */
        } pdu;

        /** @brief Default settings for GOP configurations. */
        struct _gop_defaults {
            double         expiration;    /**< Default GOP expiration time in seconds */
            double         idle_timeout;  /**< Default GOP idle timeout in seconds */
            double         lifetime;      /**< Default GOP maximum lifetime in seconds */
            gop_pdu_tree_t pdu_tree_mode; /**< Default PDU tree display mode for GOPs */
            bool           show_times;    /**< Default value for mate_cfg_gop::show_times */
            bool           drop_unassigned; /**< Default value for mate_cfg_gop::drop_unassigned */
        } gop;

        /** @brief Default settings for GOG configurations. */
        struct _gog_defaults {
            double          expiration;    /**< Default GOG expiration time in seconds */
            bool            show_times;    /**< Default value for mate_cfg_gog::show_times */
            gop_tree_mode_t gop_tree_mode; /**< Default GOP tree display mode for GOGs */
        } gog;

    } defaults;

    /* Debug verbosity levels */
    int dbg_lvl;     /**< Global MATE debug verbosity level */
    int dbg_pdu_lvl; /**< Debug verbosity level for PDU processing */
    int dbg_gop_lvl; /**< Debug verbosity level for GOP processing */
    int dbg_gog_lvl; /**< Debug verbosity level for GOG processing */

    GPtrArray *config_stack; /**< Stack of mate_config_frame entries tracking nested Include files */
    GString   *config_error; /**< Accumulated configuration parse error messages; NULL if no errors */
} mate_config;


/**
 * @brief Tracks the source location of the currently executing MATE configuration statement.
 */
typedef struct _mate_config_frame {
    char    *filename; /**< Path to the MATE configuration file being parsed */
    unsigned linenum;  /**< Current line number within @ref filename */
} mate_config_frame;


/**
 * @brief Per-GOP-configuration runtime state maintained during a live dissection pass.
 */
typedef struct _gopcfg_runtime_data {
    unsigned    last_id;   /**< Monotonically increasing counter used to assign unique IDs to new GOPs */
    GHashTable *gop_index; /**< Hash table mapping GOP key strings → active mate_gop instances */
    GHashTable *gog_index; /**< Hash table mapping GOG key strings → active mate_gog instances */
} gopcfg_runtime_data;


/**
 * @brief Global MATE runtime state for a single dissection pass over a capture file.
 */
typedef struct _mate_runtime_data {
    unsigned current_items;          /**< Total number of live MATE items (PDUs + GOPs + GOGs) */
    double   now;                    /**< Relative timestamp of the packet currently being dissected */
    unsigned highest_analyzed_frame; /**< Frame number of the highest-numbered frame analyzed so far */

    GHashTable *frames; /**< Maps frame number → linked list of mate_pdu instances for that frame */
    GHashTable *gops;   /**< Set of all allocated mate_gop instances; used for memory management */
    GHashTable *gogs;   /**< Set of all allocated mate_gog instances; used for memory management */

    GHashTable *pdu_last_ids; /**< Maps mate_cfg_pdu* → last ID assigned to a PDU of that config */
    GHashTable *gopcfg_rd;    /**< Maps mate_cfg_gop* → gopcfg_runtime_data for that config */
    GHashTable *gog_last_ids; /**< Maps mate_cfg_gog* → last ID assigned to a GOG of that config */
} mate_runtime_data;


/** @brief Forward declaration of the MATE PDU instance type. */
typedef struct _mate_pdu mate_pdu;
/** @brief Forward declaration of the MATE GOP instance type. */
typedef struct _mate_gop mate_gop;
/** @brief Forward declaration of the MATE GOG instance type. */
typedef struct _mate_gog mate_gog;


/**
 * @brief A single MATE PDU instance created from a dissected packet.
 */
struct _mate_pdu {
    uint32_t               id;           /**< Unique PDU identifier within its configuration type */
    const mate_cfg_pdu    *cfg;          /**< PDU configuration type that created this instance */

    AVPL    *avpl;                        /**< Attribute-Value Pair List extracted from the packet */

    uint32_t frame;                       /**< Frame number of the packet this PDU was extracted from */
    double   rel_time;                    /**< Relative time in seconds since the start of the capture */

    mate_gop *gop;                        /**< GOP this PDU has been assigned to; NULL if unassigned */
    mate_pdu *next;                       /**< Next PDU in the owning GOP's PDU linked list */
    double    time_in_gop;               /**< Time offset in seconds from the GOP's start PDU */

    bool first;         /**< True if this is the first PDU extracted from its frame */
    bool is_start;      /**< True if this PDU matched the GOP's start AVPL */
    bool is_stop;       /**< True if this PDU matched the GOP's stop AVPL */
    bool after_release; /**< True if this PDU arrived after the GOP's stop PDU */
};


/**
 * @brief A MATE GOP (Group of PDUs) instance tracking a correlated sequence of PDUs.
 */
struct _mate_gop {
    uint32_t            id;      /**< Unique GOP identifier within its configuration type */
    const mate_cfg_gop *cfg;     /**< GOP configuration type that created this instance */

    char *gop_key; /**< String representation of the key AVPL used to correlate PDUs into this GOP */
    AVPL *avpl;    /**< Accumulated Attribute-Value Pair List for this GOP */
    unsigned last_n; /**< Number of attributes in @ref avpl as of the last GOG attribute check */

    mate_gog *gog;  /**< GOG this GOP has been assigned to; NULL if unassigned */
    mate_gop *next; /**< Next GOP in the owning GOG's GOP linked list */

    double expiration;       /**< Absolute relative-time at which this GOP expires after release */
    double idle_expiration;  /**< Absolute relative-time at which this GOP times out due to inactivity */
    double time_to_die;      /**< Absolute relative-time at which this GOP exceeds its maximum lifetime */
    double time_to_timeout;  /**< Absolute relative-time at which the next applicable timeout fires */

    double start_time;    /**< Relative time of the GOP's start PDU */
    double release_time;  /**< Relative time at which the GOP was released (stop PDU received) */
    double last_time;     /**< Relative time of the most recently assigned PDU */

    int num_of_pdus;                /**< Total number of PDUs assigned to this GOP */
    int num_of_after_release_pdus;  /**< Number of PDUs received after the GOP's stop PDU */
    mate_pdu *pdus;                 /**< Head of the linked list of PDUs assigned to this GOP */
    mate_pdu *last_pdu;             /**< Tail of the PDU linked list for O(1) append */

    bool released; /**< True if this GOP has received its stop PDU and been released */
};


/**
 * @brief A MATE GOG (Group of GOPs) instance tracking a correlated session of GOPs.
 */
struct _mate_gog {
    uint32_t            id;  /**< Unique GOG identifier within its configuration type */
    const mate_cfg_gog *cfg; /**< GOG configuration type that created this instance */

    AVPL    *avpl;   /**< Accumulated Attribute-Value Pair List for this GOG */
    unsigned last_n; /**< Number of attributes in @ref avpl as of the last update check */

    bool released; /**< True if all member GOPs have been released */

    double expiration;      /**< Absolute relative-time at which this GOG expires after full release */
    double idle_expiration; /**< Absolute relative-time at which this GOG times out due to inactivity */

    double start_time;   /**< Relative time of the first GOP assigned to this GOG */
    double release_time; /**< Relative time at which all member GOPs were released */
    double last_time;    /**< Relative time of the most recent activity in any member GOP */

    mate_gop *gops;     /**< Head of the linked list of GOPs assigned to this GOG */
    mate_gop *last_gop; /**< Tail of the GOP linked list for O(1) append */

    int num_of_gops;              /**< Total number of GOPs assigned to this GOG */
    int num_of_counting_gops;     /**< Number of GOPs that count toward triggering GOG release */
    int num_of_released_gops;     /**< Number of member GOPs that have been released so far */
    GPtrArray *gog_keys;          /**< Array of key strings under which this GOG is indexed in the GOG hash */
};

/**
 * @brief Union sized to the largest of the three MATE item types, used for
 *        generic allocation and type-punning across PDU, GOP, and GOG objects.
 */
typedef union _mate_max_size {
    mate_pdu pdu; /**< PDU (Protocol Data Unit) item; determines size if largest. */
    mate_gop gop; /**< GOP (Group of PDUs) item; determines size if largest. */
    mate_gog gog; /**< GOG (Group of GOPs) item; determines size if largest. */
} mate_max_size;

/* from mate_runtime.c */

/**
 * @brief Initializes the MATE runtime.
 *
 * @param mc The MATE configuration.
 */
extern void initialize_mate_runtime(mate_config* mc);

/**
 * @brief Retrieves PDUs for a given frame number.
 *
 * @param framenum The frame number to retrieve PDUs for.
 * @return A GPtrArray containing the PDUs, or NULL if not found.
 */
extern GPtrArray* mate_get_pdus(uint32_t framenum);

/**
 * @brief Analyzes a frame for MATE.
 *
 * @param mc The MATE configuration.
 * @param pinfo The packet information.
 * @param tree The protocol tree.
 */
extern void mate_analyze_frame(mate_config *mc, packet_info *pinfo, proto_tree* tree);

/* from mate_setup.c */
/**
 * @brief Create a configuration for MATE.
 *
 * @param filename The name of the file containing the MATE module's configuration.
 * @param mate_hfid The header field identifier for MATE.
 * @return A pointer to the newly created mate_config structure, or NULL on failure.
 */
extern mate_config* mate_make_config(const char* filename, int mate_hfid);

/**
 * @brief Create and register a new PDU configuration in the MATE config.
 *
 * @param mc   The MATE configuration.
 * @param name The name of the new PDU configuration.
 * @return Pointer to the new @c mate_cfg_pdu, or NULL on failure.
 */
extern mate_cfg_pdu* new_pducfg(mate_config* mc, char* name);

/**
 * @brief Create and register a new GoP configuration in the MATE config.
 *
 * @param mc   The MATE configuration.
 * @param name The name of the new GoP configuration.
 * @return Pointer to the new @c mate_cfg_gop, or NULL on failure.
 */
extern mate_cfg_gop* new_gopcfg(mate_config* mc, char* name);

/**
 * @brief Create and register a new GoG configuration in the MATE config.
 *
 * @param mc   The MATE configuration.
 * @param name The name of the new GoG configuration.
 * @return Pointer to the new @c mate_cfg_gog, or NULL on failure.
 */
extern mate_cfg_gog* new_gogcfg(mate_config* mc, char* name);

/**
 * @brief Add a header field mapping to a MATE configuration hash table.
 *
 * @param mc    The MATE configuration.
 * @param hfi   The header field info to add.
 * @param as    The name to map the field to.
 * @param where The hash table to insert the mapping into.
 * @return true on success, false if the field is already mapped.
 */
extern bool add_hfid(mate_config* mc, header_field_info* hfi, char* as, GHashTable* where);

/**
 * @brief Append a range string to a range pointer array.
 *
 * @param range        The range string to add.
 * @param range_ptr_arr The array to append the range to.
 * @return The range string, or NULL on failure.
 */
extern char* add_ranges(char* range, GPtrArray* range_ptr_arr);

/* from mate_parser.l */

/**
 * @brief Load and parse a MATE configuration file.
 *
 * @param filename The path to the MATE configuration file.
 * @param mc       The MATE configuration to populate.
 * @return true on success, false on failure.
 */
extern bool mate_load_config(const char* filename, mate_config* mc);

/** @brief The argument type for the Lemon parser allocator function. */
#define YYMALLOCARGTYPE size_t

/**
 * @brief Allocate and initialize a new MateParser instance.
 */
void *MateParserAlloc(void* (*)(YYMALLOCARGTYPE));

/**
 * @brief Free a MateParser instance and all its resources.
 */
void MateParserFree(void*, void (*)(void *));


/**
 * @brief Pass a token to the MateParser for processing.
 */
void MateParser(void*, int, char*, mate_config*);

#endif
