/* packet-trdp-dict.h
 * Routines for trdp packet dissection, parser for IEC 61375-3-2 XML description
 *
 * Copyright Bombardier Transportation Inc. or its subsidiaries and others, 2013. Florian Weispfenning
 * Copyright Universität Rostock, 2019 (substantial changes leading to GLib-only version). Thorsten Schulz
 * Copyright Stadler Deutschland GmbH, 2024-2025. Thorsten Schulz
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TRDP_CONFIG_HANDLER
#define TRDP_CONFIG_HANDLER

/*******************************************************************************
 * INCLUDES
 */
#include <epan/packet.h>

 /* packet-trdp-env.h */
#define TRDP_BITSET8 1     /**< =UINT8, n:[1..8] bits relevant, see subtype  */
#define TRDP_CHAR8 2       /**< char, can be used also as UTF8 */
#define TRDP_UTF16 3       /**< Unicode UTF-16 character */
#define TRDP_INT8 4        /**< Signed integer, 8 bit */
#define TRDP_INT16 5       /**< Signed integer, 16 bit */
#define TRDP_INT32 6       /**< Signed integer, 32 bit */
#define TRDP_INT64 7       /**< Signed integer, 64 bit */
#define TRDP_UINT8 8       /**< Unsigned integer, 8 bit */
#define TRDP_UINT16 9      /**< Unsigned integer, 16 bit */
#define TRDP_UINT32 10     /**< Unsigned integer, 32 bit */
#define TRDP_UINT64 11     /**< Unsigned integer, 64 bit */
#define TRDP_REAL32 12     /**< Floating point real, 32 bit */
#define TRDP_REAL64 13     /**< Floating point real, 64 bit */
#define TRDP_TIMEDATE32 14 /**< 32 bit UNIX time */
#define TRDP_TIMEDATE48                                                        \
  15 /**< 48 bit TCN time (32 bit seconds and 16 bit ticks) */
#define TRDP_TIMEDATE64 16 /**< 32 bit seconds and 32 bit microseconds */
#define TRDP_SC32 17       /**< SC-32 to be checked, 32 bit */
#define TRDP_UUID 18       /**< UINT8*16 == UUID, not official type though */

#define TRDP_BITSUBTYPE_BITS 8
#define TRDP_BITSUBTYPE_BITSET8 0 /**< =UINT8, all 8bits displayed */
#define TRDP_BITSUBTYPE_BOOL8                                                  \
  1 /**< =UINT8, 1 bit relevant (equal to zero -> false, not equal to zero ->  \
       true) */
#define TRDP_BITSUBTYPE_ANTIVALENT8                                            \
  2 /**< =UINT8, 2 bit relevant ('01'B -> false, '10'B -> true) */

#define TRDP_ENDSUBTYPE_BIG 0 /**< Big Endian */
#define TRDP_ENDSUBTYPE_LIT 1 /**< Little Endian */

#define TRDP_STANDARDTYPE_MAX TRDP_UUID /**< The last standard data type */

#define TRDP_DEFAULT_UDPTCP_MD_PORT                                            \
  17225 /**< Default port address for Message data (MD) communication */
#define TRDP_DEFAULT_UDP_PD_PORT                                               \
  17224 /**< Default port address for Process data (PD) communication */
#define TRDP_DEFAULT_STR_PD_PORT "17224"
#define TRDP_DEFAULT_STR_MD_PORT "17225"

#define TRDP_DEFAULT_SC32_SID 0xFFFFFFFF
#define TRDP_DEFAULT_STR_SC32_SID "0xFFFFFFFF"

#define TRDP_MAX_DATASET_RECURSION \
  15 /**< limit the hierarchy of datasets, this is an arbitrary value  */

#define PROTO_TAG_TRDP "TRDP"
#define PROTO_NAME_TRDP "Train Real Time Data Protocol"
#define PROTO_DISSECTORNAME_TRDP "TRDP"
#define PROTO_DISSECTORNAME_TRDPTCP "TRDP.tcp"
#define PROTO_FILTERNAME_TRDP "trdp"
#define PROTO_FILTERNAME_TRDP_PDU PROTO_FILTERNAME_TRDP ".pdu"

#define WS_LOG_DOMAIN PROTO_TAG_TRDP

#define TRDP_HEADER_OFFSET_SEQCNT 0
#define TRDP_HEADER_OFFSET_PROTOVER 4
#define TRDP_HEADER_OFFSET_TYPE 6
#define TRDP_HEADER_OFFSET_COMID 8
#define TRDP_HEADER_OFFSET_ETB_TOPOCNT 12
#define TRDP_HEADER_OFFSET_OP_TRN_TOPOCNT 16
#define TRDP_HEADER_OFFSET_DATASETLENGTH 20

#define TRDP_HEADER_PD_OFFSET_RESERVED 24
#define TRDP_HEADER_PD_OFFSET_REPLY_COMID 28
#define TRDP_HEADER_PD_OFFSET_REPLY_IPADDR 32
#define TRDP_HEADER_PD_OFFSET_FCSHEAD 36
#define TRDP_HEADER_PD_OFFSET_DATA 40

#define TRDP_HEADER_MD_OFFSET_REPLY_STATUS 24
#define TRDP_HEADER_MD_SESSIONID0 28
#define TRDP_HEADER_MD_SESSIONID1 32
#define TRDP_HEADER_MD_SESSIONID2 36
#define TRDP_HEADER_MD_SESSIONID3 40
#define TRDP_HEADER_MD_REPLY_TIMEOUT 44
#define TRDP_HEADER_MD_SRC_URI 48
#define TRDP_HEADER_MD_DEST_URI 80
#define TRDP_HEADER_MD_OFFSET_FCSHEAD 112
#define TRDP_HEADER_MD_OFFSET_DATA 116

#define TRDP_MD_HEADERLENGTH                                                   \
  TRDP_HEADER_MD_OFFSET_DATA /**< Length of the TRDP header of an MD message   \
                              */

#define TRDP_FCS_LENGTH                                                        \
  4 /**< The CRC calculation results in a 32bit result so 4 bytes are          \
       necessary */

#define TRDP_SC32_LENGTH                                                       \
  4 /**< The CRC calculation results in a 32bit result so 4 bytes are necessary */

int32_t trdp_dissect_width(uint32_t type);

/* end packet-trdp-env.h */
/*******************************************************************************
 * CLASS Definition
 */

/** @class Element
 *  @brief description of one element
 *
 * All persisted information can be seen in this diagram:
 * @dot
 * digraph ERdetails {
 *      node [shape=record ];
 *      c [ label="ComId" fontsize=18 ];
 *      cdDatasetId [ label="datasetId" shape=diamond ];
 *      cComID [ label="ComId" shape=ellipse ];
 *      d [ label="Dataset" fontsize=18 ];
 *      deList [ label="listOfElements" shape=diamond ];
 *      dName [ label="name" shape=ellipse ];
 *      e [ label="Element" fontsize=18 ];
 *      eName [ label="name" shape=ellipse ];
 *      eType [ label="type" shape=ellipse ];
 *      eTypeName [ label="typeName" shape=ellipse ];
 *      eArray [ label="array_size" shape=ellipse ];
 *      eUnit [ label="unit" shape=ellipse ];
 *      eScale [ label="scale" shape=ellipse ];
 *      eOffset [ label="offset" shape=ellipse ];
 *
 *      c -> cComID [ arrowhead=none ];
 *      c -> cdDatasetId [ arrowhead=none label="1" ];
 *      cdDatasetId -> d [ arrowhead=none label="1" ];
 *      d -> deList [ arrowhead=none label="1" ];
 *      d -> dName [ arrowhead=none ];
 *      deList -> e [ arrowhead=none label="N" ];
 *      e -> eName  [ arrowhead=none ];
 *      e -> eType [ arrowhead=none ];
 *      e -> eTypeName [ arrowhead=none ];
 *      e -> eArray [ arrowhead=none ];
 *      e -> eUnit [ arrowhead=none ];
 *      e -> eScale [ arrowhead=none ];
 *      e -> eOffset [ arrowhead=none ];
 * }
 * @enddot
 */


/* Assistant type to cater the type duality of a BITSET8 */
typedef struct ElementType {
	char name[32];
	uint32_t id;
	uint32_t subtype;
} ElementType;

typedef struct Bit {
	char name[32];  /**< Name of the element, maybe a stringified index within the dataset, never NULL */
	int        hf_id;
	int        ett_id;
//      int        position;
//      struct Element *parent;
} Bit;

typedef struct Element {
/* R/O */
	char *name;  /**< Name of the element, maybe a stringified index within the dataset, never NULL */
	char *unit;  /**< Unit to display, may point to an empty string */

/*public:*/

	ElementType type; /**< Numeric type of the variable (see Usermanual, chapter 4.2) or defined at ::TRDP_BOOL8, ::TRDP_UINT8, ::TRDP_UINT16 and so on, and its typeName[1..30]*/

	int32_t     array_size; /**< Amount this value occurred. 1 is default; 0 indicates a dynamic list (the dynamic list is preceeded by an integer revealing the actual size.) */
	double      scale;      /**< A factor the given value is scaled */
	int32_t     offset;     /**< Offset that is added to the values. displayed value = scale * raw value + offset */

	Bit*        bits;       /**< Array of bit-name definitions. Only allocated for bitsets */
	int32_t     bitindex;   /**< target for next to write bit, if it has no explicit position */
	int **      bitfields;  /**< Array of bit-hf refs. Only allocated for bitsets */
	int         bits_ett_id;

	int32_t     width; /**< Contains the Element's size as returned by trdp_dissect_width(this->type) */
	struct Dataset *linkedDS; /**< points to DS for non-standard types */
	int         hf_id;
	int         ett_id;
	struct Element *next;

} Element;

/** @class Dataset
 *  @brief Description of one dataset.
 */
typedef struct Dataset {
/* private */
	int32_t  size;            /**< Cached size of Dataset, including subsets. negative, if size cannot be calculated due to a missing/broken sub-dataset definition, 0, if contains var-array and must be recalculated */
	char     *name;           /**< Description of the dataset, maybe stringified datasetId, never NULL */

/* public */
	uint32_t datasetId;       /**< Unique identification of one dataset */
	int      ett_id;          /**< GUI-id for packet subtree */
	int      duplicates;      /**< incremented on multiple instances */
	char     *source;         /**< file name of first appearance for debugging */

	struct Element *listOfElements; /**< All elements, this dataset consists of. */
	struct Element *lastOfElements; /**< other end of the Bratwurst */
	struct Dataset *next;    /**< next dataset in linked list */
} Dataset;


/** @class ComId
 *
 *  @brief This struct makes a mapping between one comId and one dataset.
 *
 * The following overview visualizes the relation between one comId and an element of a dataset:
 * @dot
 * digraph Reference {
 *      rankdir=LR;
 *      node [shape=record];
 *      c [ label="ComId" ];
 *      d [ label="Dataset" ];
 *      e [ label="Element" ];
 *      c -> d [ label="1..1" ];
 *      d -> d [ label="0..*" ];
 *      d -> e [ label="1..*" ];
 * }
 * @enddot
 * There is a separate structure for datasets necessary, because the dataset itself can be packed recursively into each other.
 */
typedef struct ComId {
	char    *name;       /**< name given in XML, may be an empty string, never NULL */

/* public: */
	uint32_t comId;      /**< Communication Id, used as key*/
	uint32_t dataset;    /**< Id for a dataset ( @link #Dataset see Dataset structure @endlink) */
	int32_t  size;       /**< cached size derived from linked dataset */
	int      ett_id;     /**< GUI-id for root-subtree */
	int      duplicates; /**< incremented on multiple instances */
	char     *source;    /**< file name of first appearance for debugging */

	struct Dataset *linkedDS; /**< cached dataset for id in #dataset */
	struct ComId   *next;     /**< next comId item in linked list */
} ComId;

/** @struct TrdpDict
 *
 *  @brief This struct is the root container for the XML type dictionary.
 *
 *  The old QtXML-based application used hash-tables instead of lists.
 *  GLib offers GHashTable as an alternative.
 *  However, once the structure is built, there are not that many look-ups, since Datasets and Elemnts are directly linked.
 *  Only in case of large ComId databases, this would become relevant again. Mañana, mañana ...
 */
typedef struct TrdpDict {

/* pub */
	struct Dataset *mTableDataset; /**< first item of linked list of Dataset items. Use it to iterate if necessary or use TrdpDict_get_Dataset for a pointer. */

/* pub-R/O */
        struct Dataset *mCyclicDataset;/**< on dict creation, this is set, if a Dataset causes cyclic recursion. It is an internal error flag.  */
        size_t maxDatasetDepth;      /**< stats, maximum depth. if >TRDP_MAX_DATASET_RECURSION, this is an error indication */
	unsigned int   knowledge;    /**< number of found ComIds */
	unsigned int   datasets;     /**< number of Datasets */
	struct ComId  *mTableComId;  /**< first item of linked list of ComId items. Use it to iterate if necessary or use TrdpDict_lookup_ComId for a pointer. */
	const char    *currentFile;  /**< name of currently parsed file */
	bool           isShippedXml; /**< mark datasets when shipped to be displayed accordingly */
	uint32_t def_bitset_subtype; /**< default subtype value for numeric bitset types */
	uint32_t def_endian_subtype; /**< default subtype value for numeric types [0,1] */
} TrdpDict;

/** @fn  TrdpDict *TrdpDict_new    (const char *xmlconfigFile, gint parent_id, GError **error)
 *
 *  @brief Create a new TrdpDict container
 *
 *  @param baseXmlConfig      path to included xml files, can be file or folder (all files are read)
 *  @param customXmlConfig    path to user-provided xml files, can be file or folder (all files are read)
 *  @param bitset_subtype     sets the bitmap subtype, if XML contains numeric values
 *  @param endian_subtype     sets the endian subtype, if XML contains numeric values
 *  @param error              Will be set to non-null on any error.
 *
 *  @return pointer to the container or NULL on problems. See error then for the cause.
 */
extern TrdpDict* TrdpDict_new(const char* baseXmlConfig, const char* customXmlConfig, uint32_t bitset_subtype, uint32_t endian_subtype, GError** error);

/** @fn  TrdpDict *TrdpDict_delete(TrdpDict *self)
 *
 *  @brief Delete the TrdpDict container
 *
 *  This will also clear all associated ComId, Dataset and Element items.
 *
 *  @param self           TrdpDict instance
 *  @param parent_id      The parent protocol handle (from proto_register_protocol() ).
 */
extern void         TrdpDict_delete (      TrdpDict *self, gint parent_id);

/** @fn  const ComId   *TrdpDict_lookup_ComId(const TrdpDict *self, uint32_t comId)
 *
 *  @brief Lookup a given comId in the dictionary self
 *
 *  You may only read on the returned item.
 *
 *  @param self  TrdpDict instance
 *  @param comId The number referencing the ComId item
 *
 *  @return  pointer to the ComId item in the dictionary or NULL if not found
 */
extern const ComId* TrdpDict_lookup_ComId(const TrdpDict *self, uint32_t comId);

/** @fn  const ComId   *TrdpDict_lookup_ComId(const TrdpDict *self, uint32_t comId)
 *
 *  @brief Lookup a given comId in the dictionary self
 *
 *  You may only read on the returned item.
 *
 *  @param self  TrdpDict instance
 *  @param comId The number referencing the ComId item
 *
 *  @return  pointer to the found name of the ComId or NULL if not found
 */
extern const char* TrdpDict_lookup_ComId_Name(const TrdpDict *self, uint32_t comId);

/** @fn  Dataset *TrdpDict_get_Dataset (const TrdpDict *self, uint32_t datasetId)
 *
 *  @brief Lookup a given datasetId in the dictionary self
 *
 *  You may read and change information on the returned item, but do not free it
 *
 *  @param self      TrdpDict instance
 *  @param datasetId The number referencing the Dataset item
 *
 *  @return  pointer to the Dataset item in the dictionary or NULL if not found
 */
extern       Dataset* TrdpDict_get_Dataset (const TrdpDict *self, uint32_t datasetId);

/* @fn     int32_t TrdpDict_element_size(const Element *element, uint32_t array_size);
 *
 * @brief  Calculate the size of an element and its subtree if there is one.
 *
 * @param  self       The element to calculate
 * @param  array_size Hand in the dynamic size of the array (kept from the previous element) or set to 1 to use the predefined size from the dictionary.
 * @return -1 on error, or the type-size multiplied by the array-size. */
extern       int32_t   TrdpDict_element_size(const Element  *self, uint32_t array_size /* = 1*/);

extern const ElementType ElBasics[];

#endif
