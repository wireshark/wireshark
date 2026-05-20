/** @file
 *
 * Common data for ASN.1
 * 2007  Anders Broman
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <epan/packet.h>
#include "ws_symbol_export.h"

/**
 * @brief Identifies the ASN.1 transfer syntax encoding used for a PDU.
 */
typedef enum {
    ASN1_ENC_BER, /**< X.690 Basic/Canonical/Distinguished Encoding Rules (BER, CER, DER). */
    ASN1_ENC_PER, /**< X.691 Packed Encoding Rules (PER) — aligned or unaligned. */
    ASN1_ENC_ECN, /**< X.692 Encoding Control Notation (ECN). */
    ASN1_ENC_XER, /**< X.693 XML Encoding Rules (XER). */
    ASN1_ENC_OER  /**< X.696 Octet Encoding Rules (OER). */
} asn1_enc_e;


/**
 * @brief Identifies the variant of an ASN.1 callback registered for a type.
 */
typedef enum {
    CB_ASN1_ENC,         /**< Callback operates on the ASN.1 encoding directly. */
    CB_NEW_DISSECTOR,    /**< Callback invokes a new protocol dissector. */
    CB_DISSECTOR_HANDLE  /**< Callback uses a registered dissector handle. */
} asn1_cb_variant;


/**
 * @brief Identifies the kind of an ASN.1 parameterized type argument.
 */
typedef enum {
    ASN1_PAR_IRR,     /**< Irrelevant (unused) parameter slot. */
    ASN1_PAR_BOOLEAN, /**< Value parameter of boolean type. */
    ASN1_PAR_INTEGER, /**< Value parameter of integer type. */
    ASN1_PAR_TYPE     /**< Governor parameter specifying a type. */
} asn1_par_type;


/**
 * @brief Static definition of a single ASN.1 parameterized type parameter (name + kind).
 */
typedef struct _asn1_par_def_t {
    const char    *name;  /**< Name of the parameter as it appears in the ASN.1 module. */
    asn1_par_type  ptype; /**< Kind of the parameter; see #asn1_par_type. */
} asn1_par_def_t;


/**
 * @brief Runtime instance of a resolved ASN.1 parameterized type argument.
 */
typedef struct _asn1_par_t {
    const char    *name;  /**< Name of the parameter. */
    asn1_par_type  ptype; /**< Kind of the argument; selects the active @c value member. */
    union {
        bool     v_boolean; /**< Boolean value (when @c ptype == #ASN1_PAR_BOOLEAN). */
        int32_t  v_integer; /**< Integer value (when @c ptype == #ASN1_PAR_INTEGER). */
        void    *v_type;    /**< Opaque type reference (when @c ptype == #ASN1_PAR_TYPE). */
    } value;                /**< Resolved argument value. */
    struct _asn1_par_t *next; /**< Next parameter in the singly-linked argument list, or NULL. */
} asn1_par_t;


/**
 * @brief Single frame on the ASN.1 parameterized type resolution stack.
 */
typedef struct _asn1_stack_frame_t {
    const char                 *name; /**< Name of the ASN.1 type being resolved at this frame. */
    struct _asn1_par_t         *par;  /**< Linked list of resolved parameter arguments for this frame. */
    struct _asn1_stack_frame_t *next; /**< Next (outer) frame on the stack, or NULL if this is the bottom. */
} asn1_stack_frame_t;


/** @brief Magic signature value used to validate an #asn1_ctx_t pointer ("ACTX"). */
#define ASN1_CTX_SIGNATURE 0x41435458


/**
 * @brief Central context object threaded through all ASN.1 dissection calls.
 *
 * Carries encoding parameters, packet metadata, the type-resolution stack,
 * and per-PDU working state for EXTERNAL and EMBEDDED PDV types.
 */
typedef struct _asn1_ctx_t {
    uint32_t                    signature;    /**< Must equal #ASN1_CTX_SIGNATURE; guards against stale pointers. */
    asn1_enc_e                  encoding;     /**< Transfer syntax in use for this PDU. */
    bool                        aligned;      /**< True if PER encoding is byte-aligned (relevant when @c encoding == #ASN1_ENC_PER). */
    packet_info                *pinfo;        /**< Wireshark packet metadata for the current frame. */
    proto_item                 *created_item; /**< The most recently created protocol tree item, available for post-hoc annotation. */
    struct _asn1_stack_frame_t *stack;        /**< Top of the parameterized type resolution stack. */
    void                       *value_ptr;    /**< Generic pointer to the most recently decoded value; type depends on context. */
    void                       *private_data; /**< Opaque pointer reserved for per-dissector private state. */

    /**
     * @brief Decoding state for ASN.1 EXTERNAL type values.
     */
    struct {
        int     hf_index;                 /**< Protocol-tree field index for the EXTERNAL value. */
        bool    data_value_descr_present; /**< True if the data-value-descriptor field is present. */
        bool    direct_ref_present;       /**< True if the direct-reference OID is present. */
        bool    indirect_ref_present;     /**< True if the indirect-reference integer is present. */
        tvbuff_t   *data_value_descriptor; /**< Buffer containing the data-value-descriptor string, or NULL. */
        const char *direct_reference;     /**< Direct-reference OID string, or NULL. */
        int32_t     indirect_reference;   /**< Indirect-reference presentation-context ID. */
        int         encoding;             /**< Encoding of the contained value:
                                           *   0 = single-ASN1-type, 1 = octet-aligned, 2 = arbitrary. */
        tvbuff_t   *single_asn1_type;    /**< Buffer for single-ASN1-type encoding, or NULL. */
        tvbuff_t   *octet_aligned;       /**< Buffer for octet-aligned encoding, or NULL. */
        tvbuff_t   *arbitrary;           /**< Buffer for arbitrary (bit-string) encoding, or NULL. */
        union {
            struct {
                /** @brief BER callback to dissect the contained EXTERNAL value.
                 *  @param imp_tag  True if the tag is implicitly encoded.
                 *  @param tvb      Buffer containing the value.
                 *  @param offset   Byte offset into @p tvb.
                 *  @param actx     The enclosing ASN.1 context.
                 *  @param tree     Protocol tree to populate.
                 *  @param hf_index Field index for the value item.
                 *  @return         Number of bytes consumed.
                 */
                unsigned (*ber_callback)(bool imp_tag, tvbuff_t *tvb, unsigned offset,
                                         struct _asn1_ctx_t *actx, proto_tree *tree, int hf_index);
            } ber; /**< BER-specific dissection callback. */
            struct {
                /** @brief PER callback to dissect the contained EXTERNAL value.
                 *  @param tvb      Buffer containing the value.
                 *  @param offset   Bit offset into @p tvb.
                 *  @param actx     The enclosing ASN.1 context.
                 *  @param tree     Protocol tree to populate.
                 *  @param hf_index Field index for the value item.
                 *  @return         Number of bits consumed.
                 */
                unsigned (*type_cb)(tvbuff_t *tvb, uint32_t offset,
                                    struct _asn1_ctx_t *actx, proto_tree *tree, int hf_index);
            } per; /**< PER-specific dissection callback. */
        } u; /**< Encoding-specific dissection callback. */
    } external; /**< State for the currently decoded EXTERNAL type instance. */

    /**
     * @brief Protocol subtree pointers for building nested dissection trees.
     */
    struct {
        proto_tree *tree;      /**< Current working subtree for item insertion. */
        proto_tree *top_tree;  /**< Root protocol tree for the current PDU. */
        void       *tree_ctx;  /**< Opaque per-tree context pointer. */
    } subtree;

    /**
     * @brief Decoding state for ASN.1 EMBEDDED PDV type values.
     */
    struct {
        int     hf_index;                 /**< Protocol-tree field index for the EMBEDDED PDV value. */
        bool    data_value_descr_present; /**< True if the data-value-descriptor field is present. */
        tvbuff_t   *data_value_descriptor; /**< Buffer containing the data-value-descriptor string, or NULL. */
        int         identification;       /**< Identification choice in use:
                                           *   0 = syntaxes, 1 = syntax, 2 = presentation-context-id,
                                           *   3 = context-negotiation, 4 = transfer-syntax, 5 = fixed. */
        int32_t     presentation_context_id; /**< Presentation context ID (when @c identification == 2 or 3). */
        const char *abstract_syntax;     /**< Abstract syntax OID string (when @c identification == 0 or 1), or NULL. */
        const char *transfer_syntax;     /**< Transfer syntax OID string (when @c identification == 0, 4), or NULL. */
        tvbuff_t   *data_value;          /**< Buffer containing the embedded PDV data value. */
        union {
            struct {
                /** @brief BER callback to dissect the contained EMBEDDED PDV value.
                 *  @param imp_tag  True if the tag is implicitly encoded.
                 *  @param tvb      Buffer containing the value.
                 *  @param offset   Byte offset into @p tvb.
                 *  @param actx     The enclosing ASN.1 context.
                 *  @param tree     Protocol tree to populate.
                 *  @param hf_index Field index for the value item.
                 *  @return         Number of bytes consumed.
                 */
                int (*ber_callback)(bool imp_tag, tvbuff_t *tvb, int offset,
                                    struct _asn1_ctx_t *actx, proto_tree *tree, int hf_index);
            } ber; /**< BER-specific dissection callback. */
            struct {
                /** @brief PER callback to dissect the contained EMBEDDED PDV value.
                 *  @param tvb      Buffer containing the value.
                 *  @param offset   Bit offset into @p tvb.
                 *  @param actx     The enclosing ASN.1 context.
                 *  @param tree     Protocol tree to populate.
                 *  @param hf_index Field index for the value item.
                 *  @return         Number of bits consumed.
                 */
                int (*type_cb)(tvbuff_t *tvb, int offset,
                               struct _asn1_ctx_t *actx, proto_tree *tree, int hf_index);
            } per; /**< PER-specific dissection callback. */
        } u; /**< Encoding-specific dissection callback. */
    } embedded_pdv; /**< State for the currently decoded EMBEDDED PDV type instance. */

    struct _rose_ctx_t *rose_ctx; /**< Optional ROSE (Remote Operations Service Element) context, or NULL. */
} asn1_ctx_t;


/** @brief Magic signature value used to validate a #rose_ctx_t pointer ("ROSE"). */
#define ROSE_CTX_SIGNATURE 0x524F5345


/**
 * @brief Context object carrying per-association state for ROSE (Remote Operations Service Element) dissection.
 *
 * Holds per-direction dissector tables for argument, result, and error PDUs,
 * plus transient per-APDU working state accumulated as each ROSE operation is decoded.
 */
typedef struct _rose_ctx_t {
    uint32_t            signature;                  /**< Must equal #ROSE_CTX_SIGNATURE; guards against stale pointers. */
    dissector_table_t   arg_global_dissector_table; /**< Global dissector table for ROSE operation argument PDUs. */
    dissector_table_t   arg_local_dissector_table;  /**< Local dissector table for ROSE operation argument PDUs. */
    dissector_table_t   res_global_dissector_table; /**< Global dissector table for ROSE result PDUs. */
    dissector_table_t   res_local_dissector_table;  /**< Local dissector table for ROSE result PDUs. */
    dissector_table_t   err_global_dissector_table; /**< Global dissector table for ROSE error PDUs. */
    dissector_table_t   err_local_dissector_table;  /**< Local dissector table for ROSE error PDUs. */
    int                 apdu_depth;                 /**< Current nesting depth of ROSE APDUs being decoded. */
    bool                fillin_info;                /**< True if descriptive text should be written into the Info column or a buffer. */
    char               *fillin_ptr;                 /**< Pointer into @c fillin_buf at the next write position. */
    size_t              fillin_buf_size;            /**< Remaining capacity in bytes at @c fillin_ptr. */

    /**
     * @brief Transient per-APDU state, refreshed for each ROSE PDU decoded.
     */
    struct {
        int pdu;         /**< ROSE PDU type: 1 = invoke, 2 = returnResult, 3 = returnError, 4 = reject. */
        int code;        /**< Operation/error code form: -1 = none (optional in ReturnResult), 0 = local, 1 = global. */
        int32_t     code_local;  /**< Local (integer) operation or error code (when @c code == 0). */
        const char *code_global; /**< Global (OID string) operation or error code (when @c code == 1), or NULL. */
        proto_item *code_item;   /**< Protocol tree item representing the operation/error code field, for post-hoc annotation. */
    } d;

    void *private_data; /**< Opaque pointer reserved for per-dissector private state. */
} rose_ctx_t;

/**
 * @brief Initialize an ASN.1 context.
 *
 * @param actx     The ASN.1 context to initialize.
 * @param encoding The ASN.1 encoding type.
 * @param aligned  Whether the encoding is aligned.
 * @param pinfo    The packet info.
 */
WS_DLL_PUBLIC void asn1_ctx_init(asn1_ctx_t *actx, asn1_enc_e encoding, bool aligned, packet_info *pinfo);

/**
 * @brief Check the signature of an ASN.1 context.
 *
 * @param actx The ASN.1 context.
 * @return true if the signature is valid, false otherwise.
 */
WS_DLL_PUBLIC bool asn1_ctx_check_signature(asn1_ctx_t *actx);

/**
 * @brief Clean the external data of an ASN.1 context.
 *
 * @param actx The ASN.1 context.
 */
WS_DLL_PUBLIC void asn1_ctx_clean_external(asn1_ctx_t *actx);

/**
 * @brief Clean the EPDV data of an ASN.1 context.
 *
 * @param actx The ASN.1 context.
 */
extern void asn1_ctx_clean_epdv(asn1_ctx_t *actx);


/**
 * @brief Push a stack frame onto the ASN.1 context.
 *
 * @param actx The ASN.1 context.
 * @param name The name of the stack frame.
 */
WS_DLL_PUBLIC void asn1_stack_frame_push(asn1_ctx_t *actx, const char *name);

/**
 * @brief Pop a stack frame from the ASN.1 context.
 *
 * @param actx The ASN.1 context.
 * @param name The name of the stack frame.
 */
WS_DLL_PUBLIC void asn1_stack_frame_pop(asn1_ctx_t *actx, const char *name);

/**
 * @brief Check that the current stack frame matches the expected name and
 * parameter definitions.
 *
 * @param actx    The ASN.1 context.
 * @param name    The expected name of the stack frame.
 * @param par_def The expected parameter definitions.
 */
WS_DLL_PUBLIC void asn1_stack_frame_check(asn1_ctx_t *actx, const char *name, const asn1_par_def_t *par_def);


/**
 * @brief Push a boolean parameter onto the ASN.1 context parameter stack.
 *
 * @param actx  The ASN.1 context.
 * @param value The boolean value to push.
 */
WS_DLL_PUBLIC void asn1_param_push_boolean(asn1_ctx_t *actx, bool value);

/**
 * @brief Push an integer parameter onto the ASN.1 context parameter stack.
 *
 * @param actx  The ASN.1 context.
 * @param value The integer value to push.
 */
WS_DLL_PUBLIC void asn1_param_push_integer(asn1_ctx_t *actx, int32_t value);

/**
 * @brief Get a named boolean parameter from the ASN.1 context.
 *
 * @param actx The ASN.1 context.
 * @param name The name of the parameter.
 * @return The boolean value of the parameter.
 */
extern bool asn1_param_get_boolean(asn1_ctx_t *actx, const char *name);

/**
 * @brief Get a named integer parameter from the ASN.1 context.
 *
 * @param actx The ASN.1 context.
 * @param name The name of the parameter.
 * @return The integer value of the parameter.
 */
WS_DLL_PUBLIC int32_t asn1_param_get_integer(asn1_ctx_t *actx, const char *name);

/**
 * @brief Initialize a ROSE context.
 *
 * @param rctx The ROSE context to initialize.
 */
WS_DLL_PUBLIC void rose_ctx_init(rose_ctx_t *rctx);

/**
 * @brief Check the signature of a ROSE context.
 *
 * @param rctx The ROSE context.
 * @return true if the signature is valid, false otherwise.
 */
extern bool rose_ctx_check_signature(rose_ctx_t *rctx);

/**
 * @brief Clean the data of a ROSE context.
 *
 * @param rctx The ROSE context.
 */
WS_DLL_PUBLIC void rose_ctx_clean_data(rose_ctx_t *rctx);

/**
 * @brief Retrieve the ASN.1 context from an opaque pointer.
 *
 * @param ptr Opaque pointer to a structure containing an ASN.1 context.
 * @return The ASN.1 context.
 */
WS_DLL_PUBLIC asn1_ctx_t *get_asn1_ctx(void *ptr);

/**
 * @brief Retrieve the ROSE context from an opaque pointer.
 *
 * @param ptr Opaque pointer to a structure containing a ROSE context.
 * @return The ROSE context.
 */
WS_DLL_PUBLIC rose_ctx_t *get_rose_ctx(void *ptr);

/**
 * @brief Convert an ASN.1 encoded real value to a double.
 *
 * Sets err to EINVAL for an invalid encoding (returning 0) to ERANGE if
 * overflow or underflow occurs (rounding, possibly to +/-HUGE_VAL, +/-0.0),
 * and 0 if conversion is successful.
 *
 * @param real_ptr Pointer to the encoded real value.
 * @param len The length of the encoded buffer.
 * @param err Output error code.
 * @return The decoded double value.
 */
WS_DLL_PUBLIC double asn1_get_real(const uint8_t *real_ptr, int len, int *err);

/* flags */
#define ASN1_EXT_ROOT 0x01
#define ASN1_EXT_EXT  0x02
#define ASN1_OPT      0x04
#define ASN1_DFLT     0x08

#define ASN1_HAS_EXT(f) ((f)&(ASN1_EXT_ROOT|ASN1_EXT_EXT))
