/* packet-trdp.c
 * Routines for trdp packet dissection
 *
 * The Train Real-Time Data Protocol (TRDP) is defined in IEC 61375-2-3. The
 * protocol is used to exchange Train Communication Network (TCN) process data
 * and message data.
 *
 * Copyright Bombardier Transportation Inc. or its subsidiaries and others, 2013. Florian Weispfenning
 * Copyright Universität Rostock, 2019 (substantial changes leading to GLib-only version). Thorsten Schulz
 * Copyright Stadler Deutschland GmbH, 2022-2026. Thorsten Schulz
 *
 * The new display-filter approach contains aspects and code
 * snippets from the wimaxasncp dissector by Stephen Croll.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include <epan/addr_resolv.h>
#include <epan/strutil.h>
#include <epan/tvbuff.h>
#include <wsutil/crc32.h>
#include <epan/crc32-tvb.h>
#include <epan/column-utils.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/expert.h>
#include <wsutil/report_message.h>
#include <wsutil/filesystem.h>
#include <libxml/xmlreader.h>
#include <libxml/tree.h>


/*******************************************************************************
 * DEFINES
 */

enum TrdpTypeId {
    TRDP_BITSET8=1,     /**< =UINT8, n:[1..8] bits relevant, see subtype  */
    TRDP_CHAR8,       /**< char, can be used also as UTF8 */
    TRDP_UTF16,       /**< Unicode UTF-16 character */
    TRDP_INT8,        /**< Signed integer, 8 bit */
    TRDP_INT16,       /**< Signed integer, 16 bit */
    TRDP_INT32,       /**< Signed integer, 32 bit */
    TRDP_INT64,       /**< Signed integer, 64 bit */
    TRDP_UINT8,       /**< Unsigned integer, 8 bit */
    TRDP_UINT16,      /**< Unsigned integer, 16 bit */
    TRDP_UINT32,      /**< Unsigned integer, 32 bit */
    TRDP_UINT64,      /**< Unsigned integer, 64 bit */
    TRDP_REAL32,      /**< Floating point real, 32 bit */
    TRDP_REAL64,      /**< Floating point real, 64 bit */
    TRDP_TIMEDATE32,  /**< 32 bit UNIX time */
    TRDP_TIMEDATE48,  /**< 48 bit TCN time (32 bit seconds and 16 bit ticks) */
    TRDP_TIMEDATE64,  /**< 32 bit seconds and 32 bit microseconds */
    TRDP_UUID,        /**< UINT8*16 == UUID, not official type though */
};

#define TRDP_BITSUBTYPE_BITS    8

enum TrdpBitSubtypeId {
    TRDP_BITSUBTYPE_BITSET8,    /**< =UINT8, all 8bits displayed */
    TRDP_BITSUBTYPE_BOOL8,      /**< =UINT8, 1 bit relevant (equal to zero -> false, not equal to zero -> true) */
    TRDP_BITSUBTYPE_ANTIVALENT8 /**< =UINT8, 2 bit relevant ('01'B -> false, '10'B -> true) */
};

enum TrdpEndianSubtypeId {
    TRDP_ENDSUBTYPE_BIG, /**< Big Endian */
    TRDP_ENDSUBTYPE_LIT  /**< Little Endian */
};

enum TrdpFoldSetting {
    TRDP_FOLD_NEVER,
    TRDP_FOLD_CONFIG,
    TRDP_FOLD_ALWAYS
};

#define TRDP_STANDARDTYPE_MAX TRDP_UUID /**< The last standard data type */

#define TRDP_DEFAULT_UDPTCP_MD_PORT 17225 /**< Default port address for Message data (MD) communication */
#define TRDP_DEFAULT_UDP_PD_PORT    17224 /**< Default port address for Process data (PD) communication */
#define TRDP_DEFAULT_STR_PD_PORT   "17224"
#define TRDP_DEFAULT_STR_MD_PORT   "17225"

#define TRDP_DEFAULT_SC32_SID      0xFFFFFFFF
#define TRDP_DEFAULT_STR_SC32_SID "0xFFFFFFFF"
#define TRDP_SDTPROT_VERSION       0x0002

#define TRDP_MAX_DATASET_RECURSION 15 /**< limit the hierarchy of datasets. This is an arbitrary value  */

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
#define TRDP_HEADER_MD_SESSIONID 28
#define TRDP_HEADER_MD_REPLY_TIMEOUT 44
#define TRDP_HEADER_MD_SRC_URI 48
#define TRDP_HEADER_MD_DEST_URI 80
#define TRDP_HEADER_MD_OFFSET_FCSHEAD 112
#define TRDP_HEADER_MD_OFFSET_DATA 116

#define TRDP_MD_HEADERLENGTH TRDP_HEADER_MD_OFFSET_DATA

#define TRDP_FCS_LENGTH 4
#define TRDP_SC32_LENGTH 4

typedef enum {
/* basically copied from GMarkup */
    XML_BAD_UTF8,
    XML_EMPTY,
    XML_PARSE,
    XML_UNKNOWN_ELEMENT,
    XML_UNKNOWN_ATTRIBUTE,
    XML_INVALID_CONTENT,
    XML_INTERNAL
} XmlErrorCode;
/*******************************************************************************
 * CLASS Definition
 */

typedef struct collectedParameter{
    const char* ifName; /* info, interface name from bus-def */
    const char* hostIp; /* as defined in xml, should be identical to captured packet */
    const char* leadIp; /* leader ip, if this is the follower declaration */
/* time-monitoring not yet implemented */
    const char* pdComTo;
    const char* mdComConfirmTo;
    const char* mdComReplyTo;
    const char* pdTo;   /* pd timeout in µs */
    const char* cycle;  /* pd transmission cycle */
    const char* mdConfirmTo; /* md confirmation timeout in µs */
    const char* mdReplyTo; /* md reply timeout in µs */
/* */
    const char* uri;    /* dst: destination uri, !dst: if set filter for source uri */
    const char* smi;    /* SMI of telegram */
    const char* udv;    /* userdata version 0<udv<256, in the packet udv=1 -> 0x0100 --BE-> 00 01 */
    const char* uri2;   /* !dst-only, filter for redundancy device */
    const char* smi2;   /* !dst-only, SMI for message from follower */
} XMLCollectedPar;

/* Assistant type to cater the type duality of a BITSET8 */
typedef struct ElementType {
    char name[64];
    uint32_t id;
    uint32_t subtype;
} ElementType;

typedef struct Bit {
    char name[32];  /**< Name of the element, maybe a stringified index within the dataset, never NULL */
    int  hf_id;
    int  ett_id;
} Bit;

typedef struct Element {
    /* R/O */
    char *name;  /**< Name of the element, maybe a stringified index within the dataset, never NULL */
    char *unit;  /**< Unit to display, may point to an empty string */
    struct knownUnit {
        bool fold0, hide0, sc32, version, ssc;
    } isUnit;

    /*public:*/

    ElementType type; /**< Numeric type of the variable (see Usermanual, chapter 4.2) or defined at ::TRDP_BOOL8, ::TRDP_UINT8, ::TRDP_UINT16 and so on, and its typeName[1..30]*/

    int32_t     array_size; /**< Amount this value occurred. 1 is default; 0 indicates a dynamic list (the dynamic list is preceded by an integer revealing the actual size.) */
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
    ElementType type;         /**< Description of the dataset, maybe stringified datasetId, never NULL */
                              /**< Unique identification of one dataset */

    /* public */
    int      ett_id;          /**< GUI-id for packet subtree */
    int      duplicates;      /**< incremented on multiple instances */
    char     *source;         /**< file name of first appearance for debugging */

    struct Element *listOfElements; /**< All elements, this dataset consists of. */
    struct Element *lastOfElements; /**< other end of the Bratwurst */
    struct Dataset *next;    /**< next dataset in linked list */
} Dataset;

typedef struct Connection {
    char*    name;       /**< name given in XML, may be an empty string, never NULL */
    address src, dst;
    uint32_t src_raw, dst_raw; /**< IPv4 only, referenced in address structs */

    uint16_t udv;      /**< userDataVersion, should match what's in the VDP_TRAILER */
    uint32_t smi;      /**< safeMessageIdentifier, sourced from the xml-config */
    uint32_t sequence; /**< this would have to be reset per dissection */
    //char uuid[16];   /**< not used here, it's either zeros or something application specific. set in prefs */

    struct Connection* next;
} Connection;

/** @class ComId
 *
 *  @brief This struct makes a mapping between one comId and one dataset.
 *
 */
typedef struct ComId {
    char*    name;       /**< name given in XML, may be an empty string, never NULL */

    /* public: */
    uint32_t comId;      /**< Communication Id, used as key*/
    ElementType dataset; /**< Id for a dataset ( @link #Dataset see Dataset structure @endlink) */
    int32_t  size;       /**< cached size derived from linked dataset */
    int      ett_id;     /**< GUI-id for root-subtree */
    int      duplicates; /**< incremented on multiple instances */
    char*    source;     /**< file name of first appearance for debugging */

    struct Connection* con;   /**< */
    struct Dataset* linkedDS; /**< cached dataset for id in #dataset */
    struct ComId*   next;     /**< next comId item in linked list */
} ComId;

typedef struct TrdpXmlContext {
    const char* currentFile;  /**< name of currently parsed file */
    bool        isShippedXml; /**< mark datasets when shipped to be displayed accordingly */
    GError**    error;

    xmlTextReader* reader;    /**< will be acquired on first call and reused */
} TrdpXmlContext;

/** @struct TrdpDict
 *
 *  @brief This struct is the root container for the type dictionary read from XML
 *
 *  The old QtXML-based application used hash-tables instead of lists.
 *  GLib offers GHashTable as an alternative.
 *  However, once the structure is built, there are not that many look-ups, since Datasets and Elements are directly linked.
 *  Only in case of large ComId databases, this would become relevant again. Mañana, mañana ...
 */
typedef struct TrdpDict {
    TrdpXmlContext parseCtx;

    /* pub */
    struct Dataset *mTableDataset; /**< first item of linked list of Dataset items. Use it to iterate if necessary or use TrdpDict_get_Dataset for a pointer. */

    /* pub-R/O */
    struct Dataset *mCyclicDataset;/**< on dict creation, this is set, if a Dataset causes cyclic recursion. It is an internal error flag.  */
    size_t maxDatasetDepth;      /**< stats, maximum depth. if >TRDP_MAX_DATASET_RECURSION, this is an error indication */
    unsigned int   knowledge;    /**< number of found ComIds */
    unsigned int   datasets;     /**< number of Datasets */
    struct ComId  *mTableComId;  /**< first item of linked list of ComId items. Use it to iterate if necessary or use TrdpDict_lookup_ComId for a pointer. */
} TrdpDict;


/* this is a construct, to point empty strings (name, unit, ...) to this const
 * instead of NULL, so readers don't have to catch for NULL - though w/o
 * wasting needless heap allocations.
 */
static const char* const SEMPTY = "";
static uint8_t cstUUID[16] = {0};
static bool    have_cstUUID = false;
static bool invalid_cstUUID = false;
static GQuark q_xml;
static wmem_allocator_t *wmem_dic;

/* these settings are also used on dictionary parsing */
static int g_uuid_subtype = TRDP_ENDSUBTYPE_BIG;
static int g_bitset_subtype = TRDP_BITSUBTYPE_BOOL8;
static int g_endian_subtype = TRDP_ENDSUBTYPE_BIG;
static int g_wchar_subtype = TRDP_ENDSUBTYPE_BIG;

/*******************************************************************************
 * XML-DEFINES
 */

#define FALLBACK(a,b) ((a)?(a):(b))

#define FILE_SUFFIX_LOWCASE ".xml"
#define FILE_SUFFIX_UPCASE ".XML"


/*******************************************************************************
 * some Definitions for "early" use internal functions
 * actually, this triple calls each other after XML parsing to check and build
 * the whole dict-tree
 */

static Dataset* TrdpDict_get_Dataset(const TrdpDict* self, ElementType *dataset);
static ComId* TrdpDict_lookup_ComId(const TrdpDict* self, uint32_t comId);
static int32_t ComId_preCalculate(ComId* self, TrdpDict* dict);
static void ComId_connection_parse(ComId* com, const char* name, bool dst, XMLCollectedPar* par, GError** error);
static int32_t Dataset_preCalculate(Dataset* self, TrdpDict* dict, Dataset** hierarchyStack, size_t depth);
static bool Element_checkConsistency(Element* self, TrdpDict* dict, Dataset** hierarchyStack, size_t depth);
static void Element_add_bit(Element* self, const char* name, const char* _position, int32_t position, GError** err);

static Element* Element_new(const char* _type, const char* _name, const char* _unit, const char* _array_size,
                            const char* _scale, const char* _offset, const char* _bitnames,
                            unsigned int cnt, GError** error);
static Dataset* Dataset_new(const char* dsId, const char* aname, const char* filename, GError** error);
static ComId* ComId_new(const char* id, const char* aname, const char* dsId, const char* filename, GError** error);

static bool Element_equals(const Element* self, const Element* other, GError** error);
static bool Dataset_equals(const Dataset* self, const Dataset* other, GError** error);
static bool ComId_equals(const ComId* self, const ComId* other, GError** error);

static void TrdpDict_delete(TrdpDict* self, int parent_id);
static void Element_delete(Element* self);
static void Dataset_delete(Dataset* self, int parent_id);
static void ComId_delete(ComId* self);

/*******************************************************************************
 * type lookup handler
 *
 * there may be better library structures to do string to ID and vice versa.
 * Though, this will also work
 */

const ElementType ElBasics[] = {
    { "", 0, 0 },
    { "BITSET8", TRDP_BITSET8, TRDP_BITSUBTYPE_BITSET8 },
    { "BOOL8", TRDP_BITSET8, TRDP_BITSUBTYPE_BOOL8 },
    { "ANTIVALENT8", TRDP_BITSET8, TRDP_BITSUBTYPE_ANTIVALENT8 },
    { "CHAR8", TRDP_CHAR8, 0 },
    { "UTF16", TRDP_UTF16, TRDP_ENDSUBTYPE_BIG },
    { "UTF16_LE", TRDP_UTF16, TRDP_ENDSUBTYPE_LIT },
    { "INT8", TRDP_INT8, 0 },
    { "INT16", TRDP_INT16, TRDP_ENDSUBTYPE_BIG },
    { "INT16_LE", TRDP_INT16, TRDP_ENDSUBTYPE_LIT },
    { "INT32", TRDP_INT32, TRDP_ENDSUBTYPE_BIG },
    { "INT32_LE", TRDP_INT32, TRDP_ENDSUBTYPE_LIT },
    { "INT64", TRDP_INT64, TRDP_ENDSUBTYPE_BIG },
    { "INT64_LE", TRDP_INT64, TRDP_ENDSUBTYPE_LIT },
    { "UINT8", TRDP_UINT8, 0 },
    { "UINT16", TRDP_UINT16, TRDP_ENDSUBTYPE_BIG },
    { "UINT16_LE", TRDP_UINT16, TRDP_ENDSUBTYPE_LIT },
    { "UINT32", TRDP_UINT32, TRDP_ENDSUBTYPE_BIG },
    { "UINT32_LE", TRDP_UINT32, TRDP_ENDSUBTYPE_LIT },
    { "UINT64", TRDP_UINT64, TRDP_ENDSUBTYPE_BIG },
    { "UINT64_LE", TRDP_UINT64, TRDP_ENDSUBTYPE_LIT },
    { "REAL32", TRDP_REAL32, TRDP_ENDSUBTYPE_BIG },
    { "REAL32_LE", TRDP_REAL32, TRDP_ENDSUBTYPE_LIT },
    { "REAL64", TRDP_REAL64, TRDP_ENDSUBTYPE_BIG },
    { "REAL64_LE", TRDP_REAL64, TRDP_ENDSUBTYPE_LIT },
    { "TIMEDATE32", TRDP_TIMEDATE32, 0 },
    { "TIMEDATE48", TRDP_TIMEDATE48, 0 },
    { "TIMEDATE64", TRDP_TIMEDATE64, 0 },
    { "UUID", TRDP_UUID, TRDP_ENDSUBTYPE_BIG },
    { "UUID_LE", TRDP_UUID, TRDP_ENDSUBTYPE_LIT },
};


/* this parse part tries to allow quite a lot of input slob in terms of id and name */

static bool TrdpDict_parseType(const char* _id, const char* _name, ElementType* type, GError** error) {
    uint32_t id = 0;
    char *endptr=NULL;
    if (!type) return FALSE;

    /* try to parse a type based on a number */
    if (_id && *_id) {
        id = (uint32_t)g_ascii_strtoull(_id, &endptr, 10);
        if (*endptr!='\0') id=0; /* reset half-way numbers */
    }
    /* fail in case of an invalid number */
    if (!((_id && *_id) || (_name && *_name)) || (!id && (endptr != _id))) { /* fail if not a complete number */
        g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                    "id=\"%s\" What is this? ID definition was unparsable (%s).", _id, g_strerror(61));
        return FALSE;
    }
    /* check, whether it's a known type in an element definition */
    if (!id && !_name) {
        for (size_t i = 0; i < array_length(ElBasics); i++) {
            if (0 == g_ascii_strcasecmp(_id, ElBasics[i].name)) {
                *type = ElBasics[i];
                return TRUE;
            }
        }
    }

    type->id = id;
    /* _name is only set in dataset calls and in that case only _name or _id can be used */
    snprintf(type->name, sizeof(type->name), "%s", (_name && *_name)?_name:_id);
    //if (!memccpy(type->name, (_name && *_name)?_name:_id, 0, sizeof(type->name))) type->name[sizeof(type->name)-1] = '\0';

    bool isNumber = (id >= TRDP_INT8) && (id <= TRDP_REAL64);
    bool isUUID   = (id == TRDP_UUID);
    bool isBit    = (id == TRDP_BITSET8);
    bool isWChar  = (id == TRDP_UTF16);
    type->subtype = isBit ? g_bitset_subtype : (isNumber ? g_endian_subtype : (isUUID ? g_uuid_subtype : (isWChar ? g_wchar_subtype : 0)));
    if (id>0 && id<=TRDP_STANDARDTYPE_MAX) {
        for (unsigned int i = 1; type && i < array_length(ElBasics); i++) {
            if (type->id == ElBasics[i].id && type->subtype == ElBasics[i].subtype) {
                *type = ElBasics[i];
                break;
            }
        }
    }
    return TRUE;
}

static void XML_translate_element(TrdpDict* self, xmlNode* node, unsigned int* cnt, GError** error) {
    GError* err=NULL;

    if (node) {

        Element* el = Element_new(
            (const char*)xmlGetProp(node, (const xmlChar *)"type"),
            (const char*)xmlGetProp(node, (const xmlChar *)"name"),
            (const char*)xmlGetProp(node, (const xmlChar *)"unit"),
            (const char*)xmlGetProp(node, (const xmlChar *)"array-size"),
            (const char*)xmlGetProp(node, (const xmlChar *)"scale"),
            (const char*)xmlGetProp(node, (const xmlChar *)"offset"),
            (const char*)xmlGetProp(node, (const xmlChar *)"bits"),
            ++(*cnt),
            &err);

        if (el) {
            /* update the element in the list */
            if (!self->mTableDataset->listOfElements)
                self->mTableDataset->listOfElements = el;
            else
                self->mTableDataset->lastOfElements->next = el;
            self->mTableDataset->lastOfElements = el;

            /* read additional bit-elements, do it inline here */
            xmlNode* bit = xmlFirstElementChild(node);
            while (bit && !err) {
                Element_add_bit(
                    el,
                    (const char*)xmlGetProp(bit, (const xmlChar *)"name"),
                    (const char*)xmlGetProp(bit, (const xmlChar *)"position"),
                    -1, &err);

                bit = xmlNextElementSibling(bit);
            }
        }
        if (err) g_propagate_error(error, err);
    }
}

static void XML_translate_dataset(TrdpDict* self, xmlNode* node, GError** error) {
    GError* err=NULL;
    unsigned int element_cnt = 0;

    if (node) {
        Dataset* ds = Dataset_new(
            (const char*)xmlGetProp(node, (const xmlChar *)"id"),
            (const char*)xmlGetProp(node, (const xmlChar *)"name"),
            self->parseCtx.isShippedXml ? NULL : self->parseCtx.currentFile,
            &err);

        if (ds) {
            ds->next = self->mTableDataset;
            self->mTableDataset = ds;
            self->datasets++;
            element_cnt = 0;
            /* we need to duplicate-check at the end */

            xmlNode* element = xmlFirstElementChild(node);
            while (element && !err) {
                XML_translate_element(self, element, &element_cnt, &err);
                element = xmlNextElementSibling(element);
            }
            if (!err) {
                Dataset* newest = self->mTableDataset;
                self->mTableDataset = newest->next; /* unqueue the newest Dataset for a sec */
                Dataset* preExists = TrdpDict_get_Dataset(self, &newest->type);
                if (preExists) {
                    if (!Dataset_equals(preExists, newest, &err))
                        g_propagate_error(error, err);
                    preExists->duplicates++;
                    Dataset_delete(newest, -1);
                    self->datasets--;
                } else {
                    self->mTableDataset = newest;
                }
            }
        }
        if (err) g_propagate_error(error, err);
    }
}

static void XML_translate_com_connection(TrdpDict* self, ComId* com, xmlNode* node, XMLCollectedPar* par, GError** error) {
    bool dst;

    if (!self || !com || !node || !par) return;

           if (0==xmlStrcmp(node->name, (const xmlChar *)"source")) {
        dst = false;
    } else if (0==xmlStrcmp(node->name, (const xmlChar *)"destination")) {
        dst = true;
    } else {
        /*skip*/
        return;
    }

    par->uri  = (const char*)xmlGetProp(node, (const xmlChar *)(dst?"uri":"uri1"));
    par->uri2 = (const char*)(dst ? xmlGetProp(node, (const xmlChar *)"uri2") : NULL);

    xmlNode* sdt_par = xmlFirstElementChild(node);
    if (sdt_par && (0==xmlStrcmp(sdt_par->name, (const xmlChar *)"sdt-parameter"))) {
        par->smi  = (const char*)xmlGetProp(sdt_par, (const xmlChar *)"smi1");
        par->smi2 = (const char*)xmlGetProp(sdt_par, (const xmlChar *)"smi2");
        par->udv  = (const char*)xmlGetProp(sdt_par, (const xmlChar *)"udv");
    } else {
        par->smi=NULL;
        par->smi2=NULL;
        par->udv=NULL;
    }
    if (xmlNextElementSibling(sdt_par)) {
        g_set_error(error, q_xml, XML_INVALID_CONTENT, "Extra SDT-Parameter elements in XML.");
        return;
    }

    ComId_connection_parse(com, (const char*)xmlGetProp(node, (const xmlChar *)"name"), dst, par, error);
}

static void XML_translate_com(TrdpDict* self, xmlNode* node, XMLCollectedPar* par, GError** error) {
    GError* err=NULL;

    if (node) {
        ComId* com = ComId_new(
            (const char*)xmlGetProp(node, (const xmlChar *)"com-id"),
            (const char*)xmlGetProp(node, (const xmlChar *)"name"),
            (const char*)xmlGetProp(node, (const xmlChar *)"data-set-id"),
            self->parseCtx.currentFile,
            &err);

        if (com && !err) {

            /* check for an existing duplicate in terms of com-ID */
            ComId* com2 = TrdpDict_lookup_ComId(self, com->comId);
            if (!com2 && !err) {
                com->next = self->mTableComId;
                self->mTableComId = com;
                self->knowledge++;
            } else {
                if (!err) ComId_equals(com2, com, &err);

                com2->duplicates++;
                ComId_delete(com);
                com = !err ? com2 : NULL;
            }

            xmlNode* compar = xmlFirstElementChild(node);
            while (compar && !err) {
                const char* s;
                if (0==xmlStrcmp(compar->name, (const xmlChar *)"pd-parameter")) {
                    if ((s = (const char*)xmlGetProp(compar, (const xmlChar *)"timeout"))) {
                        if (!par->pdTo       ) par->pdTo        = s; else g_set_error(&err, q_xml, XML_INVALID_CONTENT, "Extra pd-parameter element.");
                    }
                    if ((s = (const char*)xmlGetProp(compar, (const xmlChar *)"cycle"))) {
                        if (!par->cycle      ) par->cycle       = s; else g_set_error(&err, q_xml, XML_INVALID_CONTENT, "Extra pd-parameter element.");
                    }
                }
                if (0==xmlStrcmp(compar->name, (const xmlChar *)"md-parameter")) {
                    if ((s = (const char*)xmlGetProp(compar, (const xmlChar *)"confirm-timeout"))) {
                        if (!par->mdConfirmTo) par->mdConfirmTo = s; else g_set_error(&err, q_xml, XML_INVALID_CONTENT, "Extra md-parameter element.");
                    }
                    if ((s = (const char*)xmlGetProp(compar, (const xmlChar *)"reply-timeout"))) {
                        if (!par->mdReplyTo  ) par->mdReplyTo   = s; else g_set_error(&err, q_xml, XML_INVALID_CONTENT, "Extra md-parameter element.");
                    }
                }
                compar = xmlNextElementSibling(compar);
            }
            /* only take the common params, if there are no specific */
            if (!par->pdTo       ) par->pdTo =        par->pdComTo;
            if (!par->mdConfirmTo) par->mdConfirmTo = par->mdComConfirmTo;
            if (!par->mdReplyTo  ) par->mdReplyTo =   par->mdComReplyTo;

            xmlNode* srcdst = xmlFirstElementChild(node);
            while (srcdst && !err) {
                XML_translate_com_connection(self, com, srcdst, par, error);
                srcdst = xmlNextElementSibling(srcdst);
            }

            par->pdTo = NULL;
            par->cycle = NULL;
            par->mdConfirmTo = NULL;
            par->mdReplyTo = NULL;
        }
        if (err) g_propagate_error(error, err);
    }
}

static void XML_translate(TrdpDict* self, xmlDoc* doc, GError** error) {

    xmlNode* device = doc->children; /* can be only be the device element by known XPath-Expr. */
    xmlNode* node = xmlFirstElementChild(device);
    while (node && !*error) {
        if (0==xmlStrcmp(node->name, (const xmlChar *)"bus-interface-list")) {
            xmlNode* busInterface = xmlFirstElementChild(node);
            while (busInterface && !*error) {
                XMLCollectedPar par = {
                    .ifName = (const char*)xmlGetProp(busInterface, (const xmlChar *)"name"),
                    .hostIp = (const char*)xmlGetProp(busInterface, (const xmlChar *)"host-ip"),
                    .leadIp = (const char*)xmlGetProp(busInterface, (const xmlChar *)"leader-ip"),
                    NULL,};

                xmlNode* comParam = xmlFirstElementChild(busInterface);
                while (comParam && !*error) {
                    const char* s;
                    if (0==xmlStrcmp(comParam->name, (const xmlChar *)"pd-com-parameter")) {
                        if ((s = (const char*)xmlGetProp(comParam, (const xmlChar *)"timeout-value"))) {
                            if (!par.pdComTo       ) par.pdComTo        = s; else g_set_error(error, q_xml, XML_INVALID_CONTENT, "Extra pd-com-parameter element.");
                        }
                    }
                    if (0==xmlStrcmp(comParam->name, (const xmlChar *)"md-com-parameter")) {
                        if ((s = (const char*)xmlGetProp(comParam, (const xmlChar *)"confirm-timeout"))) {
                            if (!par.mdComConfirmTo) par.mdComConfirmTo = s; else g_set_error(error, q_xml, XML_INVALID_CONTENT, "Extra md-com-parameter element.");
                        }
                        if ((s = (const char*)xmlGetProp(comParam, (const xmlChar *)"reply-timeout"))) {
                            if (!par.mdComReplyTo  ) par.mdComReplyTo   = s; else g_set_error(error, q_xml, XML_INVALID_CONTENT, "Extra md-com-parameter element.");
                        }
                    }
                    comParam = xmlNextElementSibling(comParam);
                }

                xmlNode* telegram = xmlFirstElementChild(busInterface);
                while (telegram && !*error) {
                    if (0==xmlStrcmp(telegram->name, (const xmlChar *)"telegram")) {
                        XML_translate_com(self, telegram, &par, error);
                    }
                    telegram = xmlNextElementSibling(telegram);
                }

                busInterface = xmlNextElementSibling(busInterface);
            }
        } else if (0==xmlStrcmp(node->name, (const xmlChar *)"data-set-list")) {
            xmlNode* dataSet = xmlFirstElementChild(node);
            while (dataSet && !*error) {
                XML_translate_dataset(self, dataSet, error);
                dataSet = xmlNextElementSibling(dataSet);
            }
        }
        node = xmlNextElementSibling(node);
    }
}

#if LIBXML_VERSION < 21200
static void XML_errorHook(void *user_data, xmlError *xmlerror) {
#else
static void XML_errorHook(void *user_data, const xmlError *xmlerror) {
#endif
    g_set_error_literal((GError **)user_data, q_xml, xmlerror ? xmlerror->code : 0, xmlerror ? xmlerror->message : "[NULL]");
}

/*******************************************************************************
 * TrdpDict functions
 * holds both lists (telegrams and datasets) and takes care of parsing and
 * cleanup.
 */

#define TRDP_XML_PATHS (xmlChar*)\
    "/device/bus-interface-list/bus-interface/pd-com-parameter|"\
    "/device/bus-interface-list/bus-interface/md-com-parameter|"\
    "/device/bus-interface-list/bus-interface/telegram|"\
    "/device/bus-interface-list/bus-interface/telegram/pd-parameter|"\
    "/device/bus-interface-list/bus-interface/telegram/md-parameter|"\
    "/device/bus-interface-list/bus-interface/telegram/destination/sdt-parameter|"\
    "/device/bus-interface-list/bus-interface/telegram/source/sdt-parameter|"\
    "/device/data-set-list/data-set/element|"\
    "/device/data-set-list/data-set/element/bit"

static void TrdpDict_parseXML(TrdpDict* self, const char* filename, bool isShipped, GError** error )
{
    xmlDoc *doc;
    int options = XML_PARSE_NOENT | XML_PARSE_COMPACT;
    self->parseCtx.currentFile = filename;
    self->parseCtx.isShippedXml = isShipped;
    self->parseCtx.error = error;
    if (!self->parseCtx.reader) {
        if (!(self->parseCtx.reader = xmlReaderForFile(filename, NULL, options))) {
            g_set_error(error, q_xml, XML_INTERNAL, "Failed to create XML reader.");
            return;
        }
        xmlTextReaderSetStructuredErrorHandler(self->parseCtx.reader, XML_errorHook, self);
    } else {
        if (xmlReaderNewFile(self->parseCtx.reader, filename, NULL, options) < 0) {
            g_set_error(error, q_xml, XML_INTERNAL, "Failed to switch file in XML reader.");
            return;
        }
    }
    xmlTextReaderPreservePattern(self->parseCtx.reader, TRDP_XML_PATHS, NULL);

    int ret = xmlTextReaderRead(self->parseCtx.reader);
    while (ret == 1 && !*error) {
        //xmlTextReaderDepth(self->parseCtx.reader);
        //xmlNode* node = xmlTextReaderExpand(self->parseCtx.reader);
        ret = xmlTextReaderRead(self->parseCtx.reader);
    }
    if (ret < 0 || !(doc = xmlTextReaderCurrentDoc(self->parseCtx.reader)) ) {
        g_set_error(error, q_xml, XML_PARSE, "Failed to parse the file, but I don't know what happened.");
    } else {
        XML_translate(self, doc, error);
    }
    /* do not xmlFreeDoc(doc), it's weirdly implemented. The xmlreader does not notice and will double free later */
}

static bool TrdpDict_check(TrdpDict* self, const char* baseXmlConfig, const char* customXmlConfig, GError** error)
{
    ComId* com;

    if (!self->knowledge) {
        /* wrap up and summarize after all XMLs did not provide anything */
        if (baseXmlConfig && customXmlConfig && *customXmlConfig)
            g_set_error(error, q_xml, XML_INVALID_CONTENT,
                        "%s parsed ok, but did not provide any ComId.", customXmlConfig);
    } else {

        /* try to construct the com-id -- datasets - tree */
        for( com = self->mTableComId; com; com=com->next) {
            if (ComId_preCalculate(com, self) < 0) break; /* oops, logical inconsistency */
        }

        /* catch some parse faults and turn them into error messages */
        if (self->mCyclicDataset) {
            g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                        "Checks detected a cyclic recursion of datasets. Check references of %d (%s)", self->mCyclicDataset->type.id, self->mCyclicDataset->type.name);
            self->knowledge = 0;
        } else if (self->maxDatasetDepth > TRDP_MAX_DATASET_RECURSION) {
            g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                        "Final dictionary violates the max level (%d) of dataset hierarchies.", TRDP_MAX_DATASET_RECURSION);
            self->knowledge = 0;
        } else if (com) {
            g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                        "Lastly \"%s\" parsed ok and found %d ComIDs. However, com-ID %d FAILED to compute.", customXmlConfig, self->knowledge, com->comId);
            self->knowledge = 0;
        }
    }

    return !!self->knowledge;
}

/** @fn  TrdpDict *TrdpDict_new    (const char *xmlconfigFile, gint parent_id, GError **error)
 *
 *  @brief Create a new TrdpDict container
 *
 *  @param baseXmlConfig      path to included xml files, can be file or folder (all files are read)
 *  @param customXmlConfig    path to user-provided xml files, can be file or folder (all files are read)
 *  @param error              Will be set to non-null on any error.
 *
 *  @return pointer to the container or NULL on problems. See error then for the cause.
 */
static TrdpDict* TrdpDict_new(const char* baseXmlConfig, const char* customXmlConfig, GError** error)
{
    GError* err2 = NULL;
    bool isShippedXml = !!baseXmlConfig;
    const char* xmlConfig = isShippedXml ? baseXmlConfig : customXmlConfig;
    TrdpDict* self = wmem_new0(wmem_dic, TrdpDict);
    q_xml = g_quark_from_static_string("XML error");

    while (xmlConfig && *xmlConfig && !*error) {
        GError* err = NULL;
        GDir* dir = NULL;
        char* dirname = NULL;
        char* currentPath = NULL;
        const char* potentialNextFile = NULL;

        /* check, if path is a file or folder, check permissions */

        if (!g_file_test(xmlConfig, G_FILE_TEST_EXISTS)) {
            g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_NOENT, // error code
                        "The configured XML-file \"%s\" could not be accessed. Check the Wireshark settings -> Protocols -> TRDP.", xmlConfig);
        } else {

            if (g_file_test(xmlConfig, G_FILE_TEST_IS_DIR)) {
                dirname = g_strdup(xmlConfig);
            } else {
                dirname = g_path_get_dirname(xmlConfig);
                potentialNextFile = xmlConfig + strlen(dirname) + 1;
            }
            if (!potentialNextFile || !*potentialNextFile) {
                dir = g_dir_open(dirname, 0, &err);
                if (dir) {
                    potentialNextFile = g_dir_read_name(dir);
                } else {
                    g_propagate_prefixed_error(error, err, "Entering XML source location (%s) failed.\n", dirname);
                }
            }
        }

        while (potentialNextFile && !*error) {
            if (!dir || g_str_has_suffix(potentialNextFile, FILE_SUFFIX_LOWCASE) || g_str_has_suffix(potentialNextFile, FILE_SUFFIX_UPCASE)) {
                currentPath = wmem_strdup_printf(wmem_dic, "%s"G_DIR_SEPARATOR_S"%s", dirname, potentialNextFile);

                TrdpDict_parseXML(self, currentPath, isShippedXml, &err);
                if (err)
                    g_propagate_prefixed_error(error, err, "XML Source %s:\n", isShippedXml ? currentPath : potentialNextFile);

                wmem_free(wmem_dic, currentPath);
            }
            potentialNextFile = dir ? g_dir_read_name(dir) : NULL;

        }

        g_free(dirname); /* dirname may come from g_path_get_dirname */
        if (dir) g_dir_close(dir);
        xmlConfig = isShippedXml ? customXmlConfig : NULL;
        isShippedXml = FALSE; /* switch the flag to signal using the custom xml */
    }

    xmlFreeDoc(xmlTextReaderCurrentDoc(self->parseCtx.reader));
    xmlFreeTextReader(self->parseCtx.reader);
    self->parseCtx.reader = NULL;

    /* If init was unsuccessful, clean up the whole thing */
    if (!TrdpDict_check(self, baseXmlConfig, customXmlConfig, &err2)) {
        if (err2 && !*error) g_propagate_error(error, err2);
        TrdpDict_delete(self, -1);
        self = NULL;
    }

    return self;
}

/** @fn  TrdpDict *TrdpDict_delete(TrdpDict *self)
 *
 *  @brief Delete the TrdpDict container
 *
 *  This will also clear all associated ComId, Dataset and Element items.
 *
 *  @param self           TrdpDict instance
 *  @param parent_id      The parent protocol handle (from proto_register_protocol() ).
 */
static void TrdpDict_delete(TrdpDict* self, int parent_id)
{
    if (self) {
        while (self->mTableComId) {
            ComId* com = self->mTableComId;
            self->mTableComId = self->mTableComId->next;
            ComId_delete(com); /* only removes itself, no linkedDS */
        }
        while (self->mTableDataset) {
            Dataset* ds = self->mTableDataset;
            self->mTableDataset = self->mTableDataset->next;
            Dataset_delete(ds, parent_id);
            self->datasets--;
        }
        wmem_free(wmem_dic, self);
    }
}

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
static ComId* TrdpDict_lookup_ComId(const TrdpDict* self, uint32_t comId)
{
    if (self)
        for (ComId* com = self->mTableComId; com; com = com->next)
            if (com->comId == comId)
                return com;

    return NULL;
}

/** @fn  Dataset *TrdpDict_get_Dataset (const TrdpDict* self, ElementType* type)
 *
 *  @brief Lookup a given datasetId in the dictionary self
 *
 *  You may read and change information on the returned item, but do not free it
 *
 *  @param self      TrdpDict instance
 *  @param type      The type-ref containing the number referencing the Dataset item
 *
 *  @return  pointer to the Dataset item in the dictionary or NULL if not found
 */
static Dataset* TrdpDict_get_Dataset(const TrdpDict* self, ElementType* type)
{
    if (self && type) {
        for (Dataset* ds = self->mTableDataset; ds; ds = ds->next) {
            if (type->id && (ds->type.id == type->id)) return ds;
            if (*type->name && (0 == g_ascii_strcasecmp(ds->type.name, type->name))) return ds;
        }
    }
    return NULL;
}

/************************************************************************************
 *                          ELEMENT
 ************************************************************************************/

static int32_t Element_width(Element* self) {
    switch (self->type.id) {
        case TRDP_BITSET8: // BITSET8     1
        case TRDP_CHAR8:   // CHAR8		2	char, can be used also as UTF8
        case TRDP_INT8:    // INT8		4	Signed integer, 8 bit
        case TRDP_UINT8:   // UINT8		8	Unsigned integer, 8 bit
            return 1;
        case TRDP_UTF16:  // UTF16		3	Unicode UTF-16 character
        case TRDP_INT16:  // INT16		5	Signed integer, 16 bit
        case TRDP_UINT16: // UINT16		9	Unsigned integer, 16 bit
            return 2;
        case TRDP_INT32:      // INT32		6	Signed integer, 32 bit
        case TRDP_UINT32:     // UINT32		10	Unsigned integer, 32 bit
        case TRDP_REAL32:     // REAL32		12	Floating point real, 32 bit
        case TRDP_TIMEDATE32: // TIMEDATE32	14	32 bit UNIX time
            return 4;
        case TRDP_INT64:      // INT64		7	Signed integer, 64 bit
        case TRDP_UINT64:     // UINT64		11	Unsigned integer, 64 bit
        case TRDP_REAL64:     // REAL64		13	Floating point real, 64 bit
        case TRDP_TIMEDATE64: // TIMEDATE64	16	32 bit seconds and 32 bit
            // microseconds
            return 8;
        case TRDP_TIMEDATE48: // TIMEDATE48	15	48 bit TCN time (32 bit seconds
            // and 16 bit ticks)
            return 6;
        case TRDP_UUID:       // UUID		18	UUID, not official but improves handling in WS
            return 16;
        default:
            return -1;
    }
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursion depth guard in place
static bool Element_checkConsistency(Element* self, TrdpDict* dict, Dataset** hierarchyStack, size_t depth)
{
    if (!self || !dict || !hierarchyStack || depth > TRDP_MAX_DATASET_RECURSION)
        return FALSE;

    if (self->type.id > TRDP_STANDARDTYPE_MAX || !self->type.id) {

        if (!self->linkedDS) {
            self->linkedDS = TrdpDict_get_Dataset(dict, &self->type);
            if (self->linkedDS && !*self->type.name) {
                if (*self->linkedDS->type.name)
                    memcpy(self->type.name, self->linkedDS->type.name, sizeof(self->type.name));
                else
                    uint32_to_str_buf(self->linkedDS->type.id, self->type.name, sizeof(self->type.name));
            }
        }

        /* check, if the referenced dataset already occurs in the call chain, if so, stop and whack the user later. */
        for(size_t i=0; i<depth; i++) {
            if (hierarchyStack[i] && (hierarchyStack[i] == self->linkedDS)) {
                dict->mCyclicDataset = hierarchyStack[i];
                return FALSE;
            }
        }
        /* the above check should prevent infinite / cyclic recursion, so tell clang, we care */

        // NOLINTNEXTLINE(misc-no-recursion)
        self->width = Dataset_preCalculate(self->linkedDS, dict, hierarchyStack, depth);
        return self->width >= 0;

    } else
        return TRUE;
}

static Element* Element_new(const char* _type, const char* _name, const char* _unit, const char* _array_size,
                            const char* _scale, const char* _offset, const char* _bitnames,
                            unsigned int cnt, GError** error)
{

    gdouble scale;
    int32_t offset;
    int32_t array_size;
    ElementType type;
    char* endptr = NULL;
    errno = 0;
    array_size = _array_size ? (int32_t)g_ascii_strtoull(_array_size, &endptr, 10) : 1;
    if (errno) {
        g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                    "array-size=\"%s\" What is this? <element>'s attribute was unparsable. (%s)", endptr, g_strerror(errno));
        return NULL;
    }
    offset = _offset ? (int32_t)g_ascii_strtoll(_offset, &endptr, 10) : 0;
    if (errno) {
        g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                    "offset=\"%s\" What is this? <element>'s attribute was unparsable. (%s)", endptr, g_strerror(errno));
        return NULL;
    }
    scale = _scale ? g_ascii_strtod(_scale, &endptr) : 0;
    if (errno) {
        g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                    "scale=\"%s\" What is this? <element>'s attribute was unparsable. (%s)", endptr, g_strerror(errno));
        return NULL;
    }
    GError* err=NULL;
    if (!TrdpDict_parseType(_type, NULL, &type, &err)) {
        g_propagate_prefixed_error(error, err, "While looking at element \"%s\", ", _name);
        return NULL;
    }

    Element* self = wmem_new0(wmem_dic, Element);
    self->ett_id = -1;
    self->bits_ett_id = -1;
    self->array_size = array_size;
    self->name = _name && *_name ? wmem_strdup(wmem_dic, _name) : wmem_strdup_printf(wmem_dic, "%u", cnt); /* in case the name is empty, take a running number */
    self->scale = scale;
    self->offset = offset;
    self->type = type;
    self->unit = _unit ? wmem_strdup(wmem_dic, _unit) : (char*)SEMPTY;
    self->isUnit.fold0 = (0 == g_ascii_strcasecmp(self->unit, "fold0"));
    self->isUnit.hide0 = (0 == g_ascii_strcasecmp(self->unit, "hide0"));
    self->isUnit.sc32  = (0 == g_ascii_strcasecmp(self->unit, "sc32"));
    self->isUnit.version = (0 == g_ascii_strcasecmp(self->unit, "version"));
    self->isUnit.ssc   = (0 == g_ascii_strcasecmp(self->unit, "ssc"));

    if (_bitnames && *_bitnames) {
        char**  bitnametoks = wmem_strsplit(wmem_dic, _bitnames, ",", TRDP_BITSUBTYPE_BITS);
        for (int b=0; bitnametoks[b]; b++) Element_add_bit(self, bitnametoks[b], NULL, b, error);
        wmem_free(wmem_dic, bitnametoks[0]); /* free the actual character mem */
        wmem_free(wmem_dic, bitnametoks   ); /* free the token-pointers into it */
    }

    self->width = Element_width(self);
    return self;
}

static void Element_add_bit(Element* self, const char* name, const char* _position, int32_t position, GError** error)
{
    char* endptr = NULL;
    if (self && self->type.id == TRDP_BITSET8 && self->type.subtype == TRDP_BITSUBTYPE_BITSET8 && name && *name) {
        if (_position) {
            position = (int32_t)g_ascii_strtoll(_position, &endptr, 10);
            if (errno) {
                g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                            "position=\"%s\" What is this? <bit>'s attribute was unparsable. (%s)", endptr, g_strerror(errno));
                return;
            }
        }

        if (position == -1) {
            position = self->bitindex;
        }

        if ((position >= TRDP_BITSUBTYPE_BITS) || (position < 0)) {
            g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                        "position=\"%d\" is out of range - <bit>'s attribute was unparsable.", position);
            return;
        }

        if (!self->bits) {
            self->bits = wmem_alloc0_array(wmem_dic, Bit, TRDP_BITSUBTYPE_BITS);
            self->bitfields = wmem_alloc0_array(wmem_dic, int*, TRDP_BITSUBTYPE_BITS + 1);
            for (unsigned b = 0; b < TRDP_BITSUBTYPE_BITS; b++) {
                self->bits[b].hf_id = -1;
                self->bits[b].ett_id = -1;
            }
        }

        g_strlcpy(self->bits[position].name, name, sizeof(self->bits[position].name));

        self->bitindex = position + 1;
    }
}

static bool Element_equals(const Element* self, const Element* other, GError** error)
{
    bool eq = ((self == other)
    || ((self->type.id == other->type.id)
    && (self->type.subtype == other->type.subtype)
    && !g_ascii_strcasecmp(self->name, other->name)
    && ((!self->unit && !other->unit) || (self->unit && other->unit && !g_ascii_strcasecmp(self->unit, other->unit)))
    && (self->array_size == other->array_size)
    && (self->scale == other->scale)
    && (self->offset == other->offset)
    && ((!self->bits && !other->bits) || (self->bits && other->bits && !(memcmp(self->bits, other->bits, sizeof(other->bits[0])))))));

    if (!eq && error) {
        g_set_error(error, q_xml, XML_INVALID_CONTENT,
                    "Type: %s / %s, Name: %s / %s, Unit: %s / %s, Array: %d / %d, Scale: %f / %f, Offset: %d / %d, Bits: %d / %d\n ",
                    self->type.name, other->type.name,
                    self->name, other->name,
                    FALLBACK(self->unit,"nil"), FALLBACK(other->unit,"nil"),
                    self->array_size, other->array_size,
                    self->scale, other->scale,
                    self->offset, other->offset,
                    !!self->bits, !!other->bits);
    }
    return eq;
}

static void Element_delete(Element* self)
{
    if (self) {
        wmem_free(wmem_dic, self->bits);
        wmem_free(wmem_dic, self->bitfields);
        if (self->name) wmem_free(wmem_dic, self->name);
        if (self->unit && self->unit != SEMPTY)
            wmem_free(wmem_dic, self->unit);
        wmem_free(wmem_dic, self);
    }
}

/** @fn     int32_t TrdpDict_element_size(const Element *element, uint32_t array_size);
 *
 *  @brief  Calculate the size of an element and its subtree if there is one.
 *
 *  @param  self       The element to calculate
 *  @param  array_size Hand in the dynamic size of the array (kept from the previous element) or set to 1 to use the predefined size from the dictionary.
 *  @return -1 on error, or the type-size multiplied by the array-size.
 */

static int32_t TrdpDict_element_size(const Element* self, uint32_t array_size /* = 1*/)
{
    return self ? (self->width * FALLBACK(self->array_size,(int32_t)array_size)) : -1;
}


/************************************************************************************
 *                          DATASET
 ************************************************************************************/

static Dataset* Dataset_new(const char* _id, const char* _name, const char* filename, GError** error)
{
    ElementType type;
    GError* err=NULL;
    if (!TrdpDict_parseType(_id, _name, &type, error)) {
        g_propagate_prefixed_error(error, err,
                                   "While looking at \"%s\", around dataset %s:%s, ",
                                   FALLBACK(filename,"baked-in XML"), _id, _name);
        return NULL;
    }

    Dataset* self = wmem_new0(wmem_dic, Dataset);
    self->type = type;
    self->ett_id = -1;
    self->duplicates = 0;
    self->source = wmem_strdup(wmem_dic, filename);
    return self;
}

static bool Dataset_equals(const Dataset* self, const Dataset* other, GError** error)
{
    if (self == other)
        return TRUE;

    if (self->type.id != other->type.id)
        return FALSE;

    GError* err = NULL;
    if (0 == g_ascii_strcasecmp(self->type.name, other->type.name)) {
        Element* elSelf  = self->listOfElements;
        Element* elOther = other->listOfElements;
        while (elSelf && elOther && Element_equals(elSelf, elOther, error ? &err : NULL)) {
            elSelf = elSelf->next;
            elOther = elOther->next;
        }
        if (error && err) {
            g_propagate_prefixed_error(error, err,
                                       "Dataset %d:%s differs between \"%s\" and \"%s\" error-causing element: ",
                                       self->type.id, self->type.name, FALLBACK(self->source,"baked-in XML"), FALLBACK(other->source,"baked-in XML"));
        }
        return (!elSelf && !elOther);
    } else if (!self->type.id && !other->type.id) {
        g_set_error(error, q_xml, XML_INVALID_CONTENT,
                    "Dataset %d differ between \"%s\" and \"%s\" in name: %s / %s",
                    self->type.id, FALLBACK(self->source,"baked-in XML"), FALLBACK(other->source,"baked-in XML"), self->type.name, other->type.name);
    }
    return FALSE;
}

/* this must be called for all DS *after* config reading */
/** Calculate the size of the elements and its contents
 * @brief calculateSize
 * @return size (==getSize()), or -1 on error, 0 on variable elements
 */
// NOLINTNEXTLINE(misc-no-recursion) -- recursion depth guard in place
static int32_t Dataset_preCalculate(Dataset* self, TrdpDict* dict, Dataset** hierarchyStack, size_t depth)
{
    /* If data is missing, we cannot calculate at all. This is an error. */
    if (!self || !dict || depth > TRDP_MAX_DATASET_RECURSION)
        return -1;

    /* remember about the maximum depth and break if we pass the limit */
    if (dict->maxDatasetDepth < depth+1) dict->maxDatasetDepth = depth+1;
    if (dict->maxDatasetDepth > TRDP_MAX_DATASET_RECURSION) {
        return -1;
    }

    if (!self->size) {
        int32_t size = 0;
        bool var_array = FALSE;
        hierarchyStack[depth++] = self;

        for (Element* el = self->listOfElements; el; el = el->next) {

            if (!Element_checkConsistency(el, dict, hierarchyStack, depth)) {
                size = -1;
                break;
            }
            /* if a DS contains at least one variable array, we cannot pre-calc this datasets size */
            if (!el->array_size || !el->width) {
                size = 0;
                var_array = TRUE;
                /* instead of breaking here, we need to continue through more elements to check them all, but sticking
                 * size at zero */
            }

            /* add simple size to datasets size */
            if (!var_array) {
                size += TrdpDict_element_size(el, 1);
            }
        }
        self->size = size;
    }
    return self->size;
}

static void Dataset_delete(Dataset* self, int parent_id)
{
    if (self) {
        while (self->listOfElements) {
            Element* el = self->listOfElements;
            self->listOfElements = self->listOfElements->next;
            if (parent_id > -1 && el->hf_id > -1) {
                proto_deregister_field(parent_id, el->hf_id);
            }
            /* no idea how to clean up subtree handler el->ett_id */
            Element_delete(el);
        }
        wmem_free(wmem_dic, self->source);
        wmem_free(wmem_dic, self);
    }
}

/************************************************************************************
 *                          COMID
 ************************************************************************************/

static void ComId_delete(ComId* self)
{
    for (Connection* con = self->con; con; con = self->con) {
        self->con = con->next;
        if (con->name && con->name != SEMPTY) wmem_free(wmem_dic, con->name);
        wmem_free(wmem_dic, con);
    }
    if (self->name && self->name != SEMPTY)
        wmem_free(wmem_dic, self->name);
    wmem_free(wmem_dic, self->source);
    wmem_free(wmem_dic, self);
}

static ComId* ComId_new(const char* _id, const char* aname, const char* _dsId, const char* file, GError** error)
{
    /* check params */
    char* endptr=NULL;
    errno = (_id && *_id) ? 0 : 61 /*ENODATA*/;
    uint32_t id = errno ? 0 : (uint32_t)g_ascii_strtoull(_id, &endptr, 10);
    if (errno) {
        g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                    "com-id=\"%s\" What is this? <telegram>'s attribute was unparsable. (%s)", endptr, g_strerror(errno));
        return NULL;
    }
    ElementType type = ElBasics[0];
    if (_dsId && *_dsId) { /* dataset id is optional in telegram-def, ie, empty or opaque payload */
        GError* err=NULL;
        if (!TrdpDict_parseType(_dsId, NULL, &type, &err)) {
            g_propagate_prefixed_error(error, err,
                                       "While looking at \"%s\", around telegram %d:%s, ",
                                       FALLBACK(file,"baked-in XML"), id, aname);

            return NULL;
        }
    }

    if (!(aname && *aname) && !(type.id || *type.name)) {
        g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                    "com-id=\"%s\" provides no definition. Neither name nor data-set is given. Please check.", _id);
        return NULL;
    }

    ComId* self = wmem_new0(wmem_dic, ComId);
    self->comId = id;
    self->dataset = type;
    self->ett_id = -1;
    self->name = aname ? wmem_strdup(wmem_dic, aname) : (char*)SEMPTY;
    self->source = wmem_strdup(wmem_dic, file);
    return self;
}

/* compare two connection structures for equality. They are expected to belong to the same com-id parent
 */
static bool ComId_connection_equals(const Connection* self, const Connection* other, GError** error) {
    if (self == other) return TRUE;
    if (!self || !other) return FALSE;
    bool eq = (self->src_raw == other->src_raw) && (self->dst_raw == other->dst_raw);
    if (eq) {
        char src_buf[16], dst_buf[16];
        address_to_str_buf(&self->src, src_buf, sizeof(src_buf));
        address_to_str_buf(&self->dst, dst_buf, sizeof(dst_buf));
        if (self->udv != other->udv) {
            g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                        "Incompatible instances of source and/or destination were defined. Mismatch in \"udv\"=%hu/%hu for %s -> %s", self->udv, other->udv, src_buf, dst_buf);
            return FALSE;
        }
        if (self->smi != other->smi) {
            g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                        "Incompatible instances of source and/or destination were defined. Mismatch in \"smi\"=%u/%u for %s -> %s", self->smi, other->smi, src_buf, dst_buf);
            return FALSE;
        }
    }
    return eq;
}

/*
 * char*    name;
 * address src, dst;
 * uint32_t src_raw, dst_raw;
 *
 * uint16_t udv;
 * uint32_t smi;
 * uint32_t sequence;
 *
 */
static void ComId_connection_add(ComId* com, const char* name, uint32_t src, uint32_t dst, uint16_t udv, uint32_t smi, GError** error) {
    Connection* con = wmem_new0(wmem_dic, Connection);
    con->name = name ? wmem_strdup(wmem_dic, name) : (char*)SEMPTY;
    con->src_raw = src;
    con->dst_raw = dst;
    set_address(&con->src, AT_IPv4, sizeof(con->src_raw), &con->src_raw);
    set_address(&con->dst, AT_IPv4, sizeof(con->dst_raw), &con->dst_raw);
    con->udv = udv;
    con->smi = smi;

    if (com->con) {
        Connection* comcon = com->con;
        /* check, for duplicates */
        while (comcon) {
            if (ComId_connection_equals(comcon, con, error)) {
                if (con->name && con->name != SEMPTY) wmem_free(wmem_dic, con->name);
                wmem_free(wmem_dic, con);
                comcon = NULL;
                break;
            } else if (*error) return;
            comcon = comcon->next;
        }
        if (comcon) comcon->next = con;
    } else {
        com->con = con;
    }
}

/* add aparameters for a specific instance of a telegram-path ("connection") between devices. This is sort of a template
 * for an actual data connection. However, Wireshark connection tracking is not yet implemented in the current iteration.
 */
static void ComId_connection_parse(ComId* com, const char* name, bool dst, XMLCollectedPar* par, GError** error) {
    /* name   - info, connection name
     * dst    - true if defined in xml as destination, ie., host is source, uri is sink
     */
    /* strategy aspects,
     * The Wireshark capture is not necessarily done on a device defined in the xml, so may neither be a source or a sink
     * The TRDP traffic been watched may not be covered by the XML config, or only partially. So there is quite some
     * guessing / tolerant evaluation necessary.
     * (1) Timing is not supervised at all.
     * (2) How can I differentiate between being on consist-level or on etb-level?
     * (3) How can I resolve uri to ip and vice versa?
     * (4) sequence numbers are monitored per IP-source
     */
    if (com && par) {
        char* endptr = NULL;
        uint64_t udv = 0;
        uint64_t smi = 0;
        uint32_t host = 0;
        uint32_t uri = 0;

        errno = 0;
        udv = par->udv ? g_ascii_strtoull(par->udv, &endptr, 0) : 0;
        if (errno || udv > 0xffff || !udv) {
            g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                        "udv=\"%s\" What is this? <sdt-parameter>'s attribute was unparsable. (%s)", par->udv, g_strerror(errno));
            return;
        }
        udv = (udv <= 0xff && strnlen(par->udv, 4) <= 3) ? udv<<8 : udv;

        smi = par->smi ? g_ascii_strtoull(par->smi, &endptr, 10) : 0;
        if (errno || (par->smi && par->smi[0] == '0') || smi > 0xffffffff) {
            g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                        "smi1=\"%s\" What is this? <%s><sdt-parameter>'s attribute was unparsable. (%s)", par->smi, dst?"destination":"source", g_strerror(errno));
            return;
        }

        if (par->hostIp) {
            if (!str_to_ip(par->hostIp, &host)) {
                g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                                "host-ip=\"%s\" What is this? <%s>'s attribute was unparsable.", par->hostIp, "bus-interface");
                return;
            }
        }

        if (par->uri) {
            if (!str_to_ip(par->uri, &uri)) {
                /* don't bark if it may be a host name, which we cannot resolve right here */
                if (g_ascii_isdigit(par->uri[0])) {
                    g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                        "uri=\"%s\" What is this? <%s>'s attribute was unparsable.", par->uri, dst?"destination":"source");
                    return;
                }
            }
        }

        if (!dst) {
            ComId_connection_add(com, name, uri, host, (uint16_t)udv, (uint32_t)smi, error);
            if (*error) return;
            if (par->uri2) {
                uint32_t uri2 = 0;
                if (str_to_ip(par->uri2, &uri2)) {

                    uint64_t smi2 = par->smi2 ? g_ascii_strtoull(par->smi2, &endptr, 10) : 0;
                    if (errno || smi2 > 0xffffffff) {
                        g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                                    "smi2=\"%s\" What is this? <%s><sdt-parameter>'s attribute was unparsable. (%s)", par->smi2, dst?"destination":"source", g_strerror(errno));
                        return;
                    }

                    if (smi && !smi2) {
                        g_set_error(error, q_xml, XML_INVALID_CONTENT,
                                    "uri2=\"%s\" but smi2 is undefined, while smi is. That is broken, please fix.", par->smi2);
                        return;
                    }
                } else {
                    /* don't bark if it may be a host name, which we cannot resolve right here */
                    if (g_ascii_isdigit(par->uri2[0])) {
                        g_set_error(error, q_xml, XML_INVALID_CONTENT, // error code
                                    "uri2=\"%s\" What is this? <%s>'s attribute was unparsable.", par->uri2, "source");
                        return;
                    }
                }
                ComId_connection_add(com, name, uri2, host, (uint16_t)udv, (uint32_t)smi, error);
            }
        } else {
            ComId_connection_add(com, name, host, uri, (uint16_t)udv, (uint32_t)smi, error);
        }
    }
}

static bool ComId_equals(const ComId* self, const ComId* other, GError** error)
{
    /* the good thing is, we don't really care about sub-tag such as source/sink/com-parameters. */
    /* Name should be ignored */
    bool eq = (self == other || (self->comId == other->comId && ((self->dataset.id && (self->dataset.id == other->dataset.id)) || (0==g_ascii_strcasecmp(self->dataset.name,other->dataset.name)))));
    if (!eq) {
        g_set_error(error, q_xml, XML_INVALID_CONTENT,
                    "ComId %d differ in Dataset-ID %d:%s / %d:%s. Check \"%s\" against \"%s\".",
                    self->comId, self->dataset.id, self->dataset.name, other->dataset.id, other->dataset.name, self->source, other->source);
    }
    return eq;
}

/* Tries to get the size for the comId-related DS. Will only work, if all DS are non-variable. */
/**< must only be called after full config initialization */
static int32_t ComId_preCalculate(ComId* self, TrdpDict* dict)
{
    if (!dict) {
        self->size = -1;
    } else {
        if (!self->linkedDS)
            self->linkedDS = TrdpDict_get_Dataset(dict, &self->dataset);

        /* setup the dataset-call-stack to detect cyclic dependencies */
        Dataset* hierarchyStack[TRDP_MAX_DATASET_RECURSION] = {NULL, };
        /* this is ok to use, because the root dataset is not an element, thus cannot be an array */
        self->size = self->linkedDS ? Dataset_preCalculate(self->linkedDS, dict, hierarchyStack, 0) : 0;
    }
    return self->size;
}

/* look up the specific telegram src/dst parameters, if provided. Will typically not work for the predefined telegrams
 * from the standard, as they require special name resolution and have no source defined
 */
static Connection* ComId_connection_lookup(ComId* self, const packet_info* pinfo) {
    if (!self || !pinfo || !self->con) return NULL;

    Connection* comcon = self->con;
    while (comcon) {
        if (addresses_equal(&pinfo->src, &comcon->src) && addresses_equal(&pinfo->dst, &comcon->dst)) break;
        comcon = comcon->next;
    }
    return comcon;
}

/*
    uint32_t safeTopoCnt; //> STC: unique identification of the actual train composition (opTrnTopoCnt) for train wide communication over ETB. 0 for consist network internal communication. see 5.3.3.2.13
*/

static bool ComId_make_SID(ComId* self, const packet_info* pinfo, uint32_t stc, uint32_t* sid) {

    if (!self || !sid) return FALSE;

    Connection* con = ComId_connection_lookup(self, pinfo);
    if (!con) return FALSE;

    uint32_t smi = con->smi; /* get from config */

    if (!smi /*|| (!stc != !have_cstUUID)*/) return FALSE;

    uint16_t input16[16] = {0,};
    uint32_t* input32 = (uint32_t*)&input16;
    input32[0] = g_htonl(smi);
    input16[3] = g_htons(TRDP_SDTPROT_VERSION);
    if (have_cstUUID) memcpy(input32+2, cstUUID, 16);
    input32[6] = g_htonl(stc);

    *sid = crc32_sc32_seed((const uint8_t*)input16, sizeof(input16), TRDP_DEFAULT_SC32_SID);
    return TRUE;
}

static bool ComId_assert_SSC(ComId* self, const packet_info* pinfo, uint32_t ssc, int* result) {
    if (!self || !result) return FALSE;

    if (pinfo->fd->visited) return FALSE;
    pinfo->fd->visited = TRUE;

    Connection* con = ComId_connection_lookup(self, pinfo);
    if (!con) return FALSE;

    *result = (con->sequence < ssc) ? 1 : 0;
    if (con->sequence > 0xfffffff7 && ssc < 8) *result = 1; /* silently tolerate an overflow */
    con->sequence = ssc;

    return TRUE;
}

/*****************************************************************************
 * Actual dissector code
 *****************************************************************************/


#define API_TRACE  ws_noisy("%s:%d : %s\n", __FILE__, __LINE__, __FUNCTION__)

/* Reply status indication names
 * Signed int: <0: NOK; 0: OK; >0: user reply status
 * (taken from TRDP-EKE) */

static const value_string reply_status_names[] = {
    {-1, "Reserved"},
    {-2, "Session abort"},
    {-3, "No replier instance (at replier side)"},
    {-4, "No memory (at replier side)"},
    {-5, "No memory (local)"},
    {-6, "No reply"},
    {-7, "Not all replies"},
    {-8, "No confirm"},
    {-9, "Reserved"},
    {-10, "Sending failed"},
    {0, "Ok"},
    {0, NULL}};

/* TRDP-packet-type map */
static const char *trdp_types[] = {
    "Pr", "PD Request",
    "Pp", "PD Reply  ",
    "Pe", "PD Error  ",
    "Pd", "PD Data   ",
    "Mn", "MD Notification (Req. w/o reply)",
    "Mr", "MD Request with reply",
    "Mp", "MD Reply ( w/o confrm)",
    "Mq", "MD Reply (with confrm)",
    "Mc", "MD Confirm",
    "Me", "MD error  ",
    NULL, "Unknown TRDP Type"
};

/* Initialize the protocol and registered fields */
static int proto_trdp = -1;
static dissector_handle_t trdp_handle;
static dissector_handle_t trdp_TCP_handle;

void proto_reg_handoff_trdp(void);
void proto_register_trdp(void);

/*For All*/
static int hf_trdp_sequencecounter;  /*uint32*/
static int hf_trdp_protocolversion;  /*uint16*/
static int hf_trdp_type;             /*uint16*/
static int hf_trdp_etb_topocount;    /*uint32*/
static int hf_trdp_op_trn_topocount; /*uint32*/
static int hf_trdp_comid;            /*uint32*/
static int hf_trdp_datasetlength;    /*uint16*/
static int hf_trdp_padding;          /*bytes */

/*For All (user data)*/
static int hf_trdp_fcs_head;      /*uint32*/
static int hf_trdp_fcs_head_status;
static int hf_trdp_sc32_status;
static int hf_trdp_userdata;      /* userdata */

/*needed only for PD messages*/
static int hf_trdp_reserved;               /*uint32*/
static int hf_trdp_reply_comid; /*uint32*/ /*for MD-family only*/
static int hf_trdp_reply_ipaddress;        /*uint32*/

/* needed only for MD messages*/
static int hf_trdp_replystatus;    /*uint32*/
static int hf_trdp_sessionid;      /*uuid*/
static int hf_trdp_replytimeout;   /*uint32*/
static int hf_trdp_sourceURI;      /*string*/
static int hf_trdp_destinationURI; /*string*/

static bool g_basexml = TRUE;
static const char *g_customTrdpDictionary;
static const char *g_customTrdpDictionaryFolder;
static unsigned int g_pd_port = TRDP_DEFAULT_UDP_PD_PORT;
static unsigned int g_md_port = TRDP_DEFAULT_UDPTCP_MD_PORT;
static bool g_scaled = TRUE;
static bool g_char8_is_utf8 = TRUE;
static bool g_0strings;
static bool g_time_local = TRUE;
static bool g_time_raw;
static const char* g_cstUUID = NULL;
static int g_fold0_mode = TRDP_FOLD_CONFIG;

/* Initialize the subtree pointers */
static int ett_trdp = -1;

/* Expert fields */
static expert_field ei_trdp_type_unknown;
static expert_field ei_trdp_packet_small;
static expert_field ei_trdp_userdata_empty;
static expert_field ei_trdp_userdata_wrong;
static expert_field ei_trdp_config_notparsed;
static expert_field ei_trdp_padding_not_zero;
static expert_field ei_trdp_array_wrong;
static expert_field ei_trdp_faulty_antivalent;
static expert_field ei_trdp_reserved_not_zero;
static expert_field ei_trdp_header_checksum;
static expert_field ei_trdp_sdtv2_safetycode;
static expert_field ei_trdp_sdtv2_sequence;
static expert_field ei_trdp_proc_comid_zero;

/* static container for dynamic fields and subtree handles */
static struct {
    wmem_array_t *hf;
    wmem_array_t *ett;
} trdp_build_dict;

static TrdpDict *pTrdpParser;

/* @fn *static void checkPaddingAndOffset(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset)
 *
 * @brief Check for correct padding
 *
 * @param[in]   tvb     Buffer with the captured data
 * @param[in]   pinfo   Necessary to mark status of this packet
 * @param[in]   tree    The information is appended
 * @param[in]   offset  Actual offset where the padding starts
 *
 * @return position in the buffer
 */
static int checkPaddingAndOffset(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset) {
    int remainingBytes;
    bool isPaddingZero = TRUE;
    int maxpadding= ((offset + 3) & (~3))-offset; /* round up to add padding */

    remainingBytes = tvb_reported_length_remaining(tvb, offset);
    ws_noisy("The remaining bytes are %d (padding=%d)(maxpadding=%d)", remainingBytes, remainingBytes%4, maxpadding);

    if (remainingBytes < 0) { /* There is no space for user data */
        return offset;
    } else {
        if (remainingBytes < maxpadding) maxpadding = remainingBytes;
        if (maxpadding > 0) {
            for (int i = 0; i < maxpadding; i++) {
                if (tvb_get_uint8(tvb, offset + i) != 0) {
                    isPaddingZero = FALSE;
                    break;
                }
            }
            proto_tree_add_bytes_format_value(tree, hf_trdp_padding, tvb, offset, maxpadding, NULL, "%s", (isPaddingZero ? "[ok]" : "not zero"));

            /* Mark this packet in the statistics also as "not perfect" */
            if (!isPaddingZero) expert_add_info_format(pinfo, tree, &ei_trdp_padding_not_zero, "Padding not zero");
        }
    }
    return offset+maxpadding;
}

/** @fn uint32_t dissect_trdp_generic_body(tvbuff_t* tvb, packet_info* pinfo,
 * proto_tree* trdp_tree, ComId* com, Dataset* ds, uint32_t
 * offset, unsigned int clength, uint8_t dataset_level, const char* title, const int32_t
 * arr_idx )
 *
 * @brief Extract all information from the userdata (uses the parsebody module for unmarshalling)
 *
 * @param tvb               buffer
 * @param pinfo             info for the packet
 * @param trdp_tree         to which the information are added
 * @param com               com data from dictionary
 * @param ds                dataset data from dictionary
 * @param offset            where the userdata starts in the TRDP packet
 * @param clength           Amount of bytes, that are given in the PDU
 * @param dataset_level     is set to 0 for the beginning
 * @param title             presents the instance-name of the dataset for the sub-tree
 * @param arr_idx           index for presentation when a dataset occurs in an array element
 * @param zeroScanMode      if set, look for zeros and don't work on the tree
 * @param isAllZeros        return value of zeroCheck
 *
 * @return the actual offset in the packet
 */
// NOLINTNEXTLINE(misc-no-recursion) -- increment_dissection_depth() is used as guard
static int dissect_trdp_dataset(tvbuff_t* tvb, packet_info *pinfo, proto_tree* trdp_tree, ComId* com, Dataset* ds,
                                     int offset, int clength,
                                     uint8_t dataset_level, const char* title, const int32_t arr_idx,
                                     bool zeroScanMode, bool *isAllZeros)
{

    if (!com || !ds || !isAllZeros) return offset+clength;


    int start_offset = offset; /* mark beginning of the dataset */
    proto_tree* trdp_userdata = NULL;
    proto_tree* userdata_element = NULL;
    proto_item* pi = NULL;
    int array_index = 0;
    int element_count = 0; /* the expected number of array-elements in the current element */
    int potential_array_size = -1; /* hold on to the value, for the next element, as it may be its element_count */
    bool zero_here = TRUE;

    /* start with the dataset "header", and make it foldable */
    ws_debug("%d:%s ([%d] octets)", ds->type.id, ds->type.name, ds->size);
    if (!zeroScanMode) {
        trdp_userdata = (arr_idx >= 0)
                      ? proto_tree_add_subtree_format(trdp_tree, tvb, offset, FALLBACK(ds->size,-1), ds->ett_id, &pi, "%s.%d", title, arr_idx)
                      : (ds->type.id /*if available, show its dataset-id*/
                          ? proto_tree_add_subtree_format(trdp_tree, tvb, offset, FALLBACK(ds->size,-1), ds->ett_id, &pi, "%s: %s (%d)", title, ds->type.name, ds->type.id)
                          : proto_tree_add_subtree_format(trdp_tree, tvb, offset, FALLBACK(ds->size,-1), ds->ett_id, &pi, "%s: %s", title, ds->type.name));
    }

    for (Element *el = ds->listOfElements; el; el = el->next) {

        int foldableDatasetMode = (((g_fold0_mode == TRDP_FOLD_ALWAYS) || ((g_fold0_mode == TRDP_FOLD_CONFIG) && el->isUnit.fold0)) && (!el->type.id || (el->type.id > TRDP_STANDARDTYPE_MAX)));

        ws_debug("[%d] Offset %5u ----> Element: type=%2d %s\tname=%s\tarray-size=%d\tunit=%s\tscale=%f\toffset=%d",
                 dataset_level, offset, el->type.id, el->type.name, el->name, el->array_size, el->unit, el->scale, el->offset);

        // at startup of a new item, check if it is an array or not
        int remainder = 0;
        element_count = el->array_size;

        if (!element_count) { // handle variable element count
            if (g_0strings && (el->type.id == TRDP_CHAR8 || el->type.id == TRDP_UTF16)) {
                /* handle the special elements CHAR8 and UTF16: */
                if (potential_array_size && (el != ds->listOfElements)) zero_here = FALSE; /* then, the previous element cannot be ignored */
            } else {
                element_count = potential_array_size;
                if (element_count < 1) { /* the previous element's data is special */
                    if (element_count == 0) {
                        potential_array_size = -1;
                        continue; /* if, at the end of the day, the array is intentionally 0, skip the element */
                    } else {
                        expert_add_info_format(pinfo, trdp_tree, &ei_trdp_array_wrong, "%s : was introduced by an unsupported length field. (%d)", el->name, potential_array_size);
                        return 0; /* in this case, the whole packet is garbled */
                    }
                } else {
                    ws_debug("[%d] Offset %5u Dynamic array, with %d elements found", dataset_level, offset, element_count);
                }

                // check if the specified amount is available in the package
                remainder = (int)tvb_reported_length_remaining(tvb, offset);
                if (remainder < TrdpDict_element_size(el, element_count)) {
                    expert_add_info_format(pinfo, trdp_tree, &ei_trdp_userdata_wrong, "%s : has %d elements [%d byte each], but only %d left", el->name, element_count, TrdpDict_element_size(el, 1), remainder);
                    return 0;
                }
            }
        } else {
            if (potential_array_size && (el != ds->listOfElements)) zero_here = FALSE; /* then, the previous element cannot be ignored */
        }
        if (element_count > 1) {
            ws_debug("[%d] Offset %5u -- Array found, expecting %d elements using %d bytes", dataset_level, offset, element_count, TrdpDict_element_size(el, element_count));
        }

        if (!zeroScanMode) {
            /* For an array, inject a new node in the graphical dissector, tree (also the extracted dynamic information, see above are added) */
            userdata_element = ((element_count == 1) || (el->type.id == TRDP_CHAR8) || (el->type.id == TRDP_UTF16)) /* for single line */
                             ? trdp_userdata           /* take existing branch */
                             : proto_tree_add_subtree_format( trdp_userdata, tvb, offset, TrdpDict_element_size(el, element_count), el->ett_id, &pi,
                                                              "%s (%d): %s[%d]", el->type.name, el->type.id, el->name, element_count);
        }

        do {
            int64_t vals = 0;
            uint64_t valu = 0;
            const char *text = NULL;
            int slen = 0;
            int bytelen = el->width;
            double real64 = 0;
            nstime_t nstime = {0, 0};
            char bits[TRDP_BITSUBTYPE_BITS+1];
            uint32_t valuOrig = 0;
            uint32_t calced_crc = 0;
            e_guid_t guid;
            bool zero_there = TRUE;

            /* first do some value preprocessing depending on the element type */
            switch (el->type.id) {
            case TRDP_BITSET8:
                valu = tvb_get_uint8(tvb, offset);
                if (valu) zero_here = FALSE;
                break;

            case TRDP_CHAR8:
                bytelen = (element_count || !g_0strings) ? (unsigned int)element_count : tvb_strsize(tvb, offset);
                slen = (element_count || !g_0strings) ? bytelen : (bytelen - 1);
                if (tvb_skip_uint8(tvb, offset, bytelen, 0) != (unsigned)(offset+bytelen)) zero_here = FALSE;
                break;

            case TRDP_UTF16:
                bytelen = (element_count || !g_0strings) ? (unsigned int)(2 * element_count) : tvb_unicode_strsize(tvb, offset);
                slen = (element_count || !g_0strings) ? bytelen : (bytelen - 2);
                if (tvb_skip_uint8(tvb, offset, bytelen, 0) != (unsigned)(offset+bytelen)) zero_here = FALSE;
                break;

            case TRDP_INT8:
                vals = tvb_get_int8(tvb, offset);
                break;

            case TRDP_INT16:
                vals = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letohis(tvb, offset) : tvb_get_ntohis(tvb, offset);
                break;

            case TRDP_INT32:
                vals = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letohil(tvb, offset) : tvb_get_ntohil(tvb, offset);
                break;

            case TRDP_INT64:
                vals = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letohi64(tvb, offset) : tvb_get_ntohi64(tvb, offset);
                break;

            case TRDP_UINT8:
                valu = tvb_get_uint8(tvb, offset);
                break;

            case TRDP_UINT16:
                valuOrig = tvb_get_ntohs(tvb, offset);
                valu = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letohs(tvb, offset) : valuOrig;
                break;

            case TRDP_UINT32:
                valuOrig = tvb_get_ntohl(tvb, offset);
                /* valuOrig always interpreted as BE for SC32 & SSC */
                valu = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letohl(tvb, offset) : valuOrig;
                break;

            case TRDP_UINT64:
                valu = tvb_get_ntoh64(tvb, offset);
                valuOrig = (uint32_t)valu; /* should not be used with U64 */
                valu = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letoh64(tvb, offset) : valu;
                break;

            case TRDP_REAL32:
                real64 = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letohieee_float(tvb, offset) : tvb_get_ntohieee_float(tvb, offset);
                break;

            case TRDP_REAL64:
                real64 = el->type.subtype == TRDP_ENDSUBTYPE_LIT ? tvb_get_letohieee_double(tvb, offset) : tvb_get_ntohieee_double(tvb, offset);
                break;

            case TRDP_TIMEDATE32:
                /* This should be time_t from general understanding, which is UNIX time,
                 * seconds since 1970 time_t is a signed long in modern POSIX ABIs, ie.
                 * often s64! However, vos_types.h defines this as u32, which may
                 * introduce some odd complications -- later. IEC61375-2-1 says for
                 * UNIX-time: SIGNED32 - ok, will respect!
                 */
                vals = tvb_get_ntohil(tvb, offset);
                nstime.secs = (long int)vals;
                break;

            case TRDP_TIMEDATE48:
                vals = tvb_get_ntohil(tvb, offset);
                nstime.secs = (time_t)vals;
                valu = tvb_get_ntohs(tvb, offset + 4);
                nstime.nsecs = (int)(valu * (1000000000ULL / 256ULL)) / 256;
                break;

            case TRDP_TIMEDATE64:
                vals = tvb_get_ntohil(tvb, offset);
                nstime.secs = (time_t)vals;
                vals = tvb_get_ntohil(tvb, offset + 4);
                nstime.nsecs = (int)vals * 1000;
                break;

            case TRDP_UUID:
                tvb_get_guid(tvb, offset, &guid, ((el->type.subtype == TRDP_ENDSUBTYPE_LIT) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN));
                if (tvb_skip_uint8(tvb, offset, bytelen, 0) != (unsigned)(offset+bytelen)) zero_here = FALSE;
                break;

            default:
                ws_debug("Unique type %d for %s", el->type.id, el->name);
                /* safe guard against excessive recursion of datasets by using dissection-depth().
                 * Problems should have been caught at dictionary reading. If it breaks here, it is some weird bug.
                 */
                /* use Wireshark's own protection. However, in the current dev-build of WS this value's (gui.max_tree_depth) default was much higher. */
                /* be aware that each array introduces an extra level, as well as other protocol layers */

                bytelen = clength - (offset - start_offset);
                if (zeroScanMode || foldableDatasetMode) {
                    int offs = -1;
                    increment_dissection_depth(pinfo);
                    // NOLINTNEXTLINE(misc-no-recursion)
                    offs = dissect_trdp_dataset( tvb, pinfo, userdata_element, com, el->linkedDS,
                                                 offset, bytelen, dataset_level + 1,
                                                 el->name, (element_count != 1) ? array_index : -1,
                                                 zeroScanMode || foldableDatasetMode, &zero_there);
                    decrement_dissection_depth(pinfo);
                    bytelen = offs-offset;
                    /* TODO The result of a sub-dataset being zero or not should be stored/cached, because this is run way too repeatedly */
                    if (!zero_there) {
                        zero_here = FALSE;
                        *isAllZeros = FALSE;
                    }
                    if (!offs) return 0;
                }
                break;
            }

            /* do the actual tree insertions */
            if (!zeroScanMode) switch (el->type.id) {
            case TRDP_BITSET8:
                switch (el->type.subtype) {
                    case TRDP_BITSUBTYPE_BOOL8:
                        proto_tree_add_boolean(userdata_element, el->hf_id, tvb, offset, el->width, (uint32_t)valu);
                        break;
                    case TRDP_BITSUBTYPE_BITSET8:
                        if (!el->bitfields) {
                            bits[sizeof(bits) - 1] = 0;
                            uint64_t v = valu;
                            for (int i = sizeof(bits) - 1; i--; v >>= 1) bits[i] = v & 1 ? '1' : '.';
                            proto_tree_add_uint_format_value(userdata_element, el->hf_id, tvb, offset, el->width, (uint32_t)valu,
                                                             "0x%#02x ( %s )", (uint32_t)valu, bits);
                        } else {
                            proto_tree_add_bitmask(userdata_element, tvb, offset, el->hf_id, el->bits_ett_id, el->bitfields, ENC_BIG_ENDIAN);
                        }
                        break;
                    case TRDP_BITSUBTYPE_ANTIVALENT8:
                        switch (valu) {
                            case 1:
                            case 2:
                                proto_tree_add_boolean(userdata_element, el->hf_id, tvb, offset, el->width, (uint32_t)(valu==2));
                                break;

                            default:
                                proto_tree_add_expert_format(userdata_element, pinfo, &ei_trdp_faulty_antivalent, tvb, offset, el->width,
                                                             "%#2x is an invalid ANTIVALENT8 value.", (uint32_t)valu);
                                break;
                        }
                        break;
                }
                break;

            case TRDP_CHAR8:
                text = (g_char8_is_utf8 && element_count > 1)
                    ? (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, slen, ENC_UTF_8)
                    : tvb_format_text(pinfo->pool, tvb, offset, slen);

                if (element_count == 1) {
                    proto_tree_add_string(userdata_element, el->hf_id, tvb, offset, bytelen, text);
                } else {
                    proto_tree_add_string_format_value(userdata_element, el->hf_id, tvb, offset, bytelen, text, "[%d] \"%s\"", slen, text);
                }
                break;

            case TRDP_UTF16:
                text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, slen, ENC_UTF_16 | ((el->type.subtype == TRDP_ENDSUBTYPE_LIT) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN));
                proto_tree_add_string_format_value(userdata_element, el->hf_id, tvb, offset, bytelen, text, "[%d] \"%s\"", slen / 2, text);
                break;

            /* case TRDP_INT8 ... TRDP_INT64: */
            case TRDP_INT8:
            case TRDP_INT16:
            case TRDP_INT32:
            case TRDP_INT64:

                if (el->isUnit.hide0) {
                    if (vals != 0) {
                        if (array_index)
                            proto_tree_add_expert_format(userdata_element, pinfo, &ei_trdp_reserved_not_zero,
                                                         tvb, offset, el->width, "Element [%d/%d] is not zero (%" G_GINT64_FORMAT ").", array_index, element_count, vals);
                        else
                            proto_tree_add_expert_format(userdata_element, pinfo, &ei_trdp_reserved_not_zero,
                                                         tvb, offset, el->width, "Element is not zero (%" G_GINT64_FORMAT ").", vals);
                    }
                } else if (el->scale && g_scaled) {
                    double formated_value = vals * el->scale + el->offset;
                    proto_tree_add_double_format_value(userdata_element, el->hf_id, tvb, offset, el->width, formated_value,
                                                       "%lg %s (raw=%" G_GINT64_FORMAT ")", formated_value, el->unit, vals);
                } else {
                    if (g_scaled) vals += el->offset;
                    proto_tree_add_int64(userdata_element, el->hf_id, tvb, offset, el->width, vals);
                }
                break;

            /* case TRDP_UINT8 ... TRDP_UINT64: */
            case TRDP_UINT8:
            case TRDP_UINT16:
            case TRDP_UINT32:
            case TRDP_UINT64:
                if (el->isUnit.sc32) {
                    uint32_t sid;
                    int flags = PROTO_CHECKSUM_NO_FLAGS;
                    bool trailerZero = tvb_skip_uint8(tvb, offset-12, 12+el->width, 0) == (unsigned)(offset+el->width);
                    if (trailerZero) {
                        flags |= PROTO_CHECKSUM_NOT_PRESENT;
                    } else {
                        uint32_t opTrnTopoCnt = tvb_get_ntohl(tvb, TRDP_HEADER_OFFSET_OP_TRN_TOPOCNT);
                        if (ComId_make_SID(com, pinfo, opTrnTopoCnt, &sid)) {
                            calced_crc = crc32_sc32_tvb_offset_seed(tvb, TRDP_HEADER_PD_OFFSET_DATA, offset-TRDP_HEADER_PD_OFFSET_DATA, sid);
                            if (calced_crc == 0) calced_crc = 0xffffffff;
                            flags |= PROTO_CHECKSUM_VERIFY;
                        }
                    }

                    proto_tree_add_checksum(userdata_element, tvb, offset, el->hf_id, hf_trdp_sc32_status, &ei_trdp_sdtv2_safetycode,
                                            pinfo, calced_crc, ENC_BIG_ENDIAN, flags);

                    if (!trailerZero && invalid_cstUUID)
                        proto_tree_add_expert_format(userdata_element, pinfo, &ei_trdp_sdtv2_safetycode, tvb, offset, el->width,
                                                     "Preferences for TRDP protocol contain invalid consist UUID. Ignored. Please check format.");

                } else if (el->isUnit.ssc) { /* safeSequenceCount */
                    int isOk = -1;
                    /* approach conversation / pinfo->fd->visited */
                    if (ComId_assert_SSC(com, pinfo, valuOrig, &isOk) && !isOk) {
                        proto_tree_add_expert_format(userdata_element, pinfo, &ei_trdp_sdtv2_sequence, tvb, offset, el->width, "%d is not sequential.", valuOrig);
                    }
                    proto_tree_add_uint_format_value(userdata_element, el->hf_id, tvb, offset, el->width, valuOrig, "%u [%s]", valuOrig, isOk<0?"cannot verify":(isOk?"ok":"bad"));
                } else if (el->isUnit.hide0) {
                    if (valu != 0) {
                        if (array_index)
                            proto_tree_add_expert_format(userdata_element, pinfo, &ei_trdp_reserved_not_zero,
                                                         tvb, offset, el->width, "Element [%d/%d] is not zero (%" G_GUINT64_FORMAT ").", array_index, element_count, valu);
                        else
                            proto_tree_add_expert_format(userdata_element, pinfo, &ei_trdp_reserved_not_zero,
                                                         tvb, offset, el->width, "Element is not zero (%" G_GUINT64_FORMAT ").", valu);
                    }
                } else if (el->isUnit.version) {
                    proto_tree_add_uint_format_value(userdata_element, el->hf_id, tvb, offset, el->width, valuOrig, "%02u.%02u", (valuOrig>>8)&0xff, (valuOrig>>0)&0xff);
                } else if (el->scale && g_scaled) {
                    double formated_value = valu * el->scale + el->offset;
                    proto_tree_add_double_format_value(userdata_element, el->hf_id, tvb, offset, el->width, formated_value, "%lg %s (raw=%" G_GUINT64_FORMAT ")", formated_value, el->unit, valu);
                } else {
                    if (g_scaled) valu += el->offset;
                    proto_tree_add_uint64(userdata_element, el->hf_id, tvb, offset, el->width, valu);
                }
                break;

            case TRDP_REAL32:
            case TRDP_REAL64:
                if (el->scale && g_scaled) {
                    double formated_value = real64 * el->scale + el->offset;
                    proto_tree_add_double_format_value(userdata_element, el->hf_id, tvb, offset, el->width, formated_value,
                                                       "%lg %s (raw=%lf)", formated_value, el->unit, real64);
                } else {
                    if (g_scaled) real64 += el->offset;
                    proto_tree_add_double(userdata_element, el->hf_id, tvb, offset, el->width, real64);
                }
                bytelen = el->width;
                break;

            /* case TRDP_TIMEDATE32 ... TRDP_TIMEDATE64: */
            case TRDP_TIMEDATE32:
            case TRDP_TIMEDATE48:
            case TRDP_TIMEDATE64:
                /* Is it allowed to have offset / scale?? I am not going to scale
                 * seconds, but there could be use for an offset, esp. when misused as
                 * relative time. */
                if (g_scaled) nstime.secs += el->offset;
                if (g_time_raw) {
                    switch (el->type.id) {
                    case TRDP_TIMEDATE32:
                        proto_tree_add_time_format_value(userdata_element, el->hf_id, tvb, offset, el->width, &nstime,
                                                         "%ji seconds", nstime.secs);
                    break;
                    case TRDP_TIMEDATE48:
                        proto_tree_add_time_format_value(userdata_element, el->hf_id, tvb, offset, el->width, &nstime,
                                                         "%ji.%05ld seconds (=%" G_GUINT64_FORMAT " ticks)", nstime.secs, (nstime.nsecs + 5000L) / 10000L, valu);
                    break;
                    case TRDP_TIMEDATE64:
                        proto_tree_add_time_format_value(userdata_element, el->hf_id, tvb, offset, el->width, &nstime,
                                                         "%ji.%06ld seconds", nstime.secs, nstime.nsecs / 1000L);
                    break;

                    }
                } else
                    proto_tree_add_time(userdata_element, el->hf_id, tvb, offset, el->width, &nstime);

                break;

            case TRDP_UUID:
                proto_tree_add_guid(userdata_element, el->hf_id, tvb, offset, el->width, &guid);
                break;

            default:
                if (zero_there && (foldableDatasetMode || (g_fold0_mode == TRDP_FOLD_ALWAYS))) {
                    //proto_tree_add_none_format(userdata_element, el->hf_id, tvb, offset, bytelen, "%s [zero, not used]", title);
                    proto_tree_add_bytes_format_value(userdata_element, el->hf_id, tvb, offset, bytelen, NULL, "%s [zero, not used]", el->linkedDS->type.name);
                } else {
                    increment_dissection_depth(pinfo);
                    // NOLINTNEXTLINE(misc-no-recursion)
                    int offs = dissect_trdp_dataset( tvb, pinfo, userdata_element, com, el->linkedDS,
                                                        offset, bytelen, dataset_level + 1,
                                                        el->name, (element_count != 1) ? array_index : -1,
                                                        FALSE, &zero_there);
                    decrement_dissection_depth(pinfo);
                    if (!offs) return 0; /* break dissecting, if things went sideways */
                    bytelen = offs-offset;
                }
                break;
            }

            if (nstime.secs || nstime.nsecs || real64) zero_here = FALSE;
            if (el->type.id == TRDP_CHAR8 || el->type.id == TRDP_UTF16) element_count = 1; /* needs reset in that case, these are never branched in the tree */
            offset += bytelen;

            if (array_index || element_count != 1) {
                /* handle arrays */
                ws_debug( "[%d / %d]", array_index, element_count);
                if (++array_index >= element_count) {
                    array_index = 0;
                    userdata_element = trdp_userdata; /* restore the array-sub-tree when done */
                }
                potential_array_size = -1;
                if (valu || vals) zero_here = FALSE;
            } else {
                ws_debug("[%d / %d], (type=%d) val-u=%" G_GUINT64_FORMAT " val-s=%" G_GINT64_FORMAT ".", array_index, element_count, el->type.id, valu, vals);

                potential_array_size = (el->type.id < TRDP_INT8 || el->type.id > TRDP_UINT64) ? -1 : (el->type.id >= TRDP_UINT8 ? (int)valu : (int)vals);
            }

        } while (array_index);
        if (!zero_here) *isAllZeros = false;
    }

    return offset;
}

/**
 * @internal
 * Build the special header for PD and MD datasets (and calls the function to extract the userdata)
 *
 * @param tvb               buffer
 * @param pinfo             info for tht packet
 * @param tree              to which the information are added
 * @param trdp_comid        the already extracted comId
 * @param offset            where the userdata starts in the TRDP package
 *
 * @return size of the user data
 */
static uint32_t build_trdp_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item **ti_type, ComId* com, char *trdp_string) {
    proto_item *ti = NULL;
    proto_tree *trdp_tree = NULL;
    proto_item *_ti_type_tmp = NULL;
    proto_item **pti_type = FALLBACK(ti_type,&_ti_type_tmp);

    uint32_t datasetlength = 0;
    uint32_t offset = 0;

    API_TRACE;

    /* when the package is big enough extract some data. */
    if (tvb_reported_length_remaining(tvb, 0) > TRDP_HEADER_PD_OFFSET_RESERVED) {
        ti = proto_tree_add_item(tree, proto_trdp, tvb, 0, -1, ENC_NA);
        trdp_tree = proto_item_add_subtree(ti, ett_trdp);

        proto_tree_add_item(trdp_tree, hf_trdp_sequencecounter, tvb, TRDP_HEADER_OFFSET_SEQCNT, 4, ENC_BIG_ENDIAN);
        int verMain = tvb_get_uint8(tvb, TRDP_HEADER_OFFSET_PROTOVER);
        int verSub = tvb_get_uint8(tvb, (TRDP_HEADER_OFFSET_PROTOVER + 1));
        proto_tree_add_bytes_format_value(trdp_tree, hf_trdp_protocolversion, tvb, 4, 2, NULL, "%d.%d", verMain, verSub);

        *pti_type = proto_tree_add_item(trdp_tree, hf_trdp_type, tvb, TRDP_HEADER_OFFSET_TYPE, 2, ENC_ASCII);
        proto_tree_add_item(trdp_tree, hf_trdp_comid,            tvb, TRDP_HEADER_OFFSET_COMID, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(trdp_tree, hf_trdp_etb_topocount,    tvb, TRDP_HEADER_OFFSET_ETB_TOPOCNT, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(trdp_tree, hf_trdp_op_trn_topocount, tvb, TRDP_HEADER_OFFSET_OP_TRN_TOPOCNT, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(trdp_tree, hf_trdp_datasetlength,    tvb, TRDP_HEADER_OFFSET_DATASETLENGTH, 4, ENC_BIG_ENDIAN);
        datasetlength = tvb_get_ntohl(tvb, TRDP_HEADER_OFFSET_DATASETLENGTH);
    } else {
        expert_add_info_format(pinfo, tree, &ei_trdp_packet_small, "Packet too small for header information");
    }

    if (trdp_string) {
        switch (trdp_string[0]) {
        case 'P':
            /* PD specific stuff */
            proto_tree_add_item(trdp_tree, hf_trdp_reserved,        tvb, TRDP_HEADER_PD_OFFSET_RESERVED, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(trdp_tree, hf_trdp_reply_comid,     tvb, TRDP_HEADER_PD_OFFSET_REPLY_COMID, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(trdp_tree, hf_trdp_reply_ipaddress, tvb, TRDP_HEADER_PD_OFFSET_REPLY_IPADDR, 4, ENC_BIG_ENDIAN);
            offset = TRDP_HEADER_PD_OFFSET_FCSHEAD;
            break;
        case 'M':
            /* MD specific stuff */
            proto_tree_add_item(trdp_tree, hf_trdp_replystatus,     tvb, TRDP_HEADER_MD_OFFSET_REPLY_STATUS, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(trdp_tree, hf_trdp_sessionid,       tvb, TRDP_HEADER_MD_SESSIONID, 16, ENC_BIG_ENDIAN);
            proto_tree_add_item(trdp_tree, hf_trdp_replytimeout,    tvb, TRDP_HEADER_MD_REPLY_TIMEOUT, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(trdp_tree, hf_trdp_sourceURI,       tvb, TRDP_HEADER_MD_SRC_URI, 32, ENC_ASCII);
            proto_tree_add_item(trdp_tree, hf_trdp_destinationURI,  tvb, TRDP_HEADER_MD_DEST_URI, 32, ENC_ASCII);
            offset = TRDP_HEADER_MD_OFFSET_FCSHEAD;
            break;
        default:
            break;
        }
    }
    if (offset) {
        proto_tree_add_checksum(trdp_tree, tvb, offset, hf_trdp_fcs_head, hf_trdp_fcs_head_status, &ei_trdp_header_checksum,
                                pinfo, crc32_802_tvb(tvb, offset), ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
        offset += 4;

        if (datasetlength) {
            bool isAllZeros = (g_fold0_mode == TRDP_FOLD_ALWAYS);
            proto_tree_add_item(trdp_tree, hf_trdp_userdata, tvb, offset, datasetlength, ENC_NA);
            if (isAllZeros) {
                /* do a first run through the packet to assure the PDU is all zeros (or not). The actual tree is not modified. */
                dissect_trdp_dataset(tvb, pinfo, trdp_tree, com, com?com->linkedDS:NULL, offset, datasetlength, 0, "dataset", -1,  TRUE, &isAllZeros);
            }
            if (!isAllZeros || g_fold0_mode == TRDP_FOLD_NEVER) {
                /* grow the tree, either because the PDU is non-zero, or it is forced by fold-mode  */
                dissect_trdp_dataset(tvb, pinfo, trdp_tree, com, com?com->linkedDS:NULL, offset, datasetlength, 0, "dataset", -1, FALSE, &isAllZeros);
            }
            offset = checkPaddingAndOffset(tvb, pinfo, trdp_tree, offset);
        }
    }
    return offset;
}

static int dissect_trdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint32_t    trdp_comid;
    char*       trdp_string;
    uint32_t    parsed_size;
    proto_item* ti_type = NULL;
    ComId*      com = NULL;

    /* Load header fields and dictionary if not already done */
    if (hf_trdp_type <= 0) {
        proto_registrar_get_byname("trdp.type");
    }

    /* Make entries in Protocol column ... */
    if (col_get_writable(pinfo->cinfo, COL_PROTOCOL)) col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_TRDP);

    /* and "info" column on summary display */
    if (col_get_writable(pinfo->cinfo, COL_INFO))     col_clear(pinfo->cinfo, COL_INFO);

    /* Read required values from the package: */
    trdp_string = (char *)tvb_format_text(pinfo->pool, tvb, TRDP_HEADER_OFFSET_TYPE, 2);
    trdp_comid  = tvb_get_ntohl(tvb, TRDP_HEADER_OFFSET_COMID);
    if (!trdp_comid && (trdp_string[0] == 'P'))
        expert_add_info(pinfo, tree, &ei_trdp_proc_comid_zero);
    else
        com = TrdpDict_lookup_ComId(pTrdpParser, trdp_comid);

    /* Telegram that fits into one packet, or the header of huge telegram, that was reassembled */
    parsed_size = build_trdp_tree(tvb, pinfo, tree, &ti_type, com, trdp_string);
    if (tree == NULL) ws_debug("Dissector did not get a tree passed (type=%s, comid=%u, parsed=%u).", trdp_string, trdp_comid, parsed_size);

    /* Append the packet type into the information description */
    if (col_get_writable(pinfo->cinfo, COL_INFO)) {
        /* Display a info line */
        col_append_fstr(pinfo->cinfo, COL_INFO, "comId: %5u ", trdp_comid);

        /* look-up the packet-type name */
        const char **tt = trdp_types;
        while (*tt && strcmp(trdp_string, *tt)) tt+=2;
        col_append_str(pinfo->cinfo, COL_INFO, *(tt+1));
        if (!*tt) expert_add_info_format(pinfo, ti_type, &ei_trdp_type_unknown, "Unknown TRDP Type: %s", trdp_string);

        /* Help with high-level name of ComId / Dataset */
        if (com) {
            if (com->name && *com->name) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", com->name);
            } else if (com->linkedDS) {
                if (*com->linkedDS->type.name) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%s]", com->linkedDS->type.name);
                } else {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " -> [%u]", com->linkedDS->type.id);
                }
            }
        }
    }
    ws_debug("Returning a parsed_size=%d", parsed_size); // tvb_captured_length(tvb)
    return parsed_size;
}

/** @fn static unsigned int get_trdp_tcp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
 *  @internal
 *  @brief retrieve the expected size of the transmitted packet.
 */
static unsigned int get_trdp_tcp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_) {
    unsigned int datasetlength   = (unsigned int)tvb_get_ntohl(tvb, offset + TRDP_HEADER_OFFSET_DATASETLENGTH);
    unsigned int without_padding = datasetlength + TRDP_MD_HEADERLENGTH/* + TRDP_FCS_LENGTH*/;
    ws_debug("get_trdp_tcp_message_len (datasetlength=%d w/ padding=%d tvb_reported_length=%d / captured=%d)", datasetlength, (without_padding + 3) & (~3), tvb_reported_length(tvb), tvb_captured_length(tvb));
    return (without_padding + 3) & (~3); /* round up to add padding */
}

/**
 * Code to analyze the actual TRDP packet, transmitted via TCP
 *
 * @param tvb       buffer
 * @param pinfo     info for the packet
 * @param tree      to which the information are added
 * @param data      Collected information
 *
 * @return length
 */
static int dissect_trdp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    API_TRACE;
    if (!tvb_bytes_exist(tvb, 0, TRDP_MD_HEADERLENGTH)) {
        ws_debug("Missing enough bytes %d/%d", tvb_captured_length(tvb), TRDP_MD_HEADERLENGTH);
        return 0;
    }

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, TRDP_MD_HEADERLENGTH, get_trdp_tcp_message_len, dissect_trdp, data);

    return tvb_reported_length(tvb);
}

/* ========================================================================= */
/* Register the protocol fields and subtrees with Wireshark
 * (strongly inspired by the wimaxasncp plugin)
 */

/* ========================================================================= */
/* Modify the given string to make a suitable display filter                 */
/*                                             copied from wimaxasncp plugin */
static char *alnumerize(char *name) {
    char *r = name; /* read pointer */
    char *w = name; /* write pointer */
    char c;

    for (; (c = *r); ++r) {
        if (g_ascii_isalnum(c) || c == '_' || c == '.') { /* These characters are fine - copy them */
            *(w++) = c;
        } else if (c == ' ' || c == '-' || c == '/') {
            if (w == name)       continue; /* Skip these others if haven't written any characters out yet */
            if (*(w - 1) == '_') continue; /* Skip if we would produce multiple adjacent '_'s */

            *(w++) = '_'; /* OK, replace with underscore */
        }
        /* Other undesirable characters are just skipped */
    }
    *w = '\0'; /* Terminate and return modified string */
    return name;
}

/* ========================================================================= */

static void add_reg_info(int *hf_ptr, const char *name, const char *abbrev, enum ftenum type, int display, int bitmask, const char *blurb) {

    hf_register_info hf = {hf_ptr, {name, abbrev, type, display, NULL, bitmask, blurb, HFILL}};

    wmem_array_append_one(trdp_build_dict.hf, hf);
}

/* ========================================================================= */

static void Element_add_reg_info(Element* el, const char* parentName) {
    char *name;
    char *abbrev;
    const char *blurb;
    int *pett_id = &el->ett_id;

    name = wmem_strdup(NULL, el->name);
    abbrev = alnumerize(wmem_strdup_printf(NULL, PROTO_FILTERNAME_TRDP_PDU ".%s.%s", parentName, el->name));

    if (el->scale || el->offset) {
        blurb = wmem_strdup_printf(NULL, "An element of type=%s(%u) scaling *%4g plus offset %+0d in unit %s",
                                el->type.name, el->type.id, FALLBACK(el->scale,1.0), el->offset, el->unit);
    } else {
        blurb = wmem_strdup_printf(NULL, "An element of type=%s(%u) with unit %s",
                                el->type.name, el->type.id, el->unit);
    }

    if (!((el->array_size == 1) || (el->type.id == TRDP_CHAR8) || (el->type.id == TRDP_UTF16))) {
        wmem_array_append_one(trdp_build_dict.ett, pett_id);
    }

    switch (el->type.id) {
        case TRDP_BITSET8:
            if (el->type.subtype == TRDP_BITSUBTYPE_BITSET8) {
                /* TODO an Array of bitsets is currently not supported */
                if (el->bits /*&& el->array_size == 1*/) {
                    int **bitfields = el->bitfields;
                    int *pb_ett_id = &el->bits_ett_id;
                    wmem_array_append_one(trdp_build_dict.ett, pb_ett_id);
                    for (int i=0;i<TRDP_BITSUBTYPE_BITS;i++) {
                        if (*el->bits[i].name) {
                            char* abbrev2 = alnumerize(wmem_strdup_printf(NULL, PROTO_FILTERNAME_TRDP_PDU ".%s.%s.%s", parentName, el->name, el->bits[i].name));
                            add_reg_info( &el->bits[i].hf_id, el->bits[i].name, abbrev2, FT_BOOLEAN, 8, 1<<i, NULL);
                            *bitfields = &el->bits[i].hf_id;
                            bitfields++;
                        }
                    }
                }
                add_reg_info(&el->hf_id, name, abbrev, FT_UINT8, BASE_HEX, 0, NULL);
            } else {
                add_reg_info(&el->hf_id, name, abbrev, FT_BOOLEAN, 8, 0, blurb);
            }
            break;
        case TRDP_CHAR8:
        case TRDP_UTF16:
            add_reg_info(&el->hf_id, name, abbrev, el->array_size ? FT_STRING : FT_STRINGZ, BASE_NONE, 0, blurb);
            break;

        /*    case TRDP_INT8 ... TRDP_INT64: not supported in MSVC :( */
        case TRDP_INT8:
        case TRDP_INT16:
        case TRDP_INT32:
        case TRDP_INT64:
            if (el->scale && g_scaled) {
                add_reg_info(&el->hf_id, name, abbrev, FT_DOUBLE, BASE_NONE, 0, blurb);
            } else
                add_reg_info(&el->hf_id, name, abbrev, FT_INT64, BASE_DEC, 0, blurb);
            break;

        /*    case TRDP_UINT8 ... TRDP_UINT64: */
        case TRDP_UINT8:
        case TRDP_UINT16:
        case TRDP_UINT32:
        case TRDP_UINT64:
            if (el->isUnit.sc32) {
                add_reg_info(&el->hf_id, name, abbrev, FT_UINT32, BASE_HEX, 0, blurb);
            } else if (el->isUnit.ssc) {
                add_reg_info(&el->hf_id, name, abbrev, FT_UINT32, BASE_DEC, 0, blurb);
            } else if (el->isUnit.version) {
                add_reg_info(&el->hf_id, name, abbrev, FT_UINT16, BASE_DEC, 0, blurb);
            } else if (el->scale && g_scaled) {
                add_reg_info(&el->hf_id, name, abbrev, FT_DOUBLE, BASE_NONE,0, blurb);
            } else
                add_reg_info(&el->hf_id, name, abbrev, FT_UINT64, BASE_DEC, 0, blurb);
            break;

        case TRDP_REAL32:
        case TRDP_REAL64:
            add_reg_info(&el->hf_id, name, abbrev, FT_DOUBLE, BASE_NONE, 0, blurb);
            break;

        /*    case TRDP_TIMEDATE32 ... TRDP_TIMEDATE64:*/
        case TRDP_TIMEDATE32:
        case TRDP_TIMEDATE48:
        case TRDP_TIMEDATE64:
            add_reg_info(&el->hf_id, name, abbrev, g_time_raw ? FT_RELATIVE_TIME : FT_ABSOLUTE_TIME,
                                                   g_time_raw ? 0 : (g_time_local ? ABSOLUTE_TIME_LOCAL : ABSOLUTE_TIME_UTC), 0, blurb);
            break;

        case TRDP_UUID:
            add_reg_info(&el->hf_id, name, abbrev, FT_GUID, BASE_NONE, 0, blurb);
            break;

        default:
            add_reg_info(&el->hf_id, name, abbrev, FT_BYTES, BASE_NONE, 0, blurb);

        /* as long as I do not track the hierarchy, do not recurse */
        /* add_dataset_reg_info(el->linkedDS); */
    }
}

static void Dataset_add_reg_info(Dataset *ds) {
    int *pett_id = &ds->ett_id;

    for (Element *el = ds->listOfElements; el; el = el->next) Element_add_reg_info(el, ds->type.name);

    if (ds->listOfElements)  wmem_array_append_one(trdp_build_dict.ett, pett_id);
}

static void register_trdp_fields(const char *prefix _U_) {
    API_TRACE;

    /* List of header fields. */
    static hf_register_info hf_base[] = {
        /* All the general fields for the header */
        // clang-format off
        {&hf_trdp_sequencecounter, {"sequenceCounter", "trdp.sequencecounter", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_protocolversion, {"protocolVersion", "trdp.protocolversion", FT_BYTES,  BASE_NONE, NULL, 0x0, "", HFILL}},
        {&hf_trdp_type,            {"msgtype", "trdp.type", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL}},
        {&hf_trdp_comid,           {"comId", "trdp.comid", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_etb_topocount,   {"etbTopoCnt", "trdp.etbtopocnt", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_op_trn_topocount,{"opTrnTopoCnt", "trdp.optrntopocnt", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_datasetlength,   {"datasetLength", "trdp.datasetlength", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_padding,         {"padding", "trdp.padding", FT_BYTES,  BASE_NONE, NULL, 0x0, "", HFILL}},

        /* PD specific stuff */
        {&hf_trdp_reserved,        {"reserved", "trdp.reserved", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_reply_comid,     {"replyComId", "trdp.replycomid", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}}, /* only in PD request */
        {&hf_trdp_reply_ipaddress, {"replyIpAddress", "trdp.replyip", FT_IPv4,   BASE_NONE, NULL, 0x0, "", HFILL}},

        /* MD specific stuff */
        {&hf_trdp_replystatus,     {"replyStatus", "trdp.replystatus", FT_INT32,  BASE_DEC,  VALS(reply_status_names), 0x0, "", HFILL}},
        {&hf_trdp_sessionid,       {"sessionUUID", "trdp.sessionid", FT_GUID,   BASE_NONE, NULL, 0x0, "", HFILL}},
        {&hf_trdp_replytimeout,    {"replyTimeout", "trdp.replytimeout", FT_UINT32, BASE_DEC,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_sourceURI,       {"sourceUri", "trdp.sourceUri", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL}},
        {&hf_trdp_destinationURI,  {"destinationURI", "trdp.destinationUri", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL}},
        {&hf_trdp_userdata,        {"dataset", "trdp.rawdata", FT_BYTES,  BASE_NONE, NULL, 0x0, "", HFILL}},

        {&hf_trdp_fcs_head,        {"headerFcs", "trdp.fcshead", FT_UINT32, BASE_HEX,  NULL, 0x0, "", HFILL}},
        {&hf_trdp_fcs_head_status, {"headerFcsStatus", "trdp.fcshead.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0, NULL, HFILL}},
        {&hf_trdp_sc32_status,     {"safetyCodeStatus", "trdp.safetycode.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0, NULL, HFILL}},

        // clang-format on
    };

    /* Setup protocol subtree array */
    static int *ett_base[] = {
        &ett_trdp,
    };

    /* ------------------------------------------------------------------------
     * load the XML dictionary
     * ------------------------------------------------------------------------
     */

    TrdpDict_delete(pTrdpParser, proto_trdp);

    if (trdp_build_dict.hf)  wmem_free(wmem_dic, trdp_build_dict.hf);
    if (trdp_build_dict.ett) wmem_free(wmem_dic, trdp_build_dict.ett);

    //g_customTrdpDictionaryFolder
    ws_info("TRDP custom dictionary is '%s' (proto=%d).", g_customTrdpDictionary, proto_trdp);
    API_TRACE;

    GError *err = NULL;
    char *basepath = g_basexml ? get_datafile_path("trdp", epan_get_environment_prefix()) : NULL;
    const char* ld = (g_customTrdpDictionary && *g_customTrdpDictionary) ? g_customTrdpDictionary : g_customTrdpDictionaryFolder;
    pTrdpParser = TrdpDict_new(basepath, ld, &err);

    API_TRACE;
    if (err) {
        report_failure("TRDP | XML input failed [%d]:\n%s", err->code, err->message);
        g_error_free(err);
    }

    g_free(basepath); /* is a g_malloc'ed string */

    /* ------------------------------------------------------------------------
     * build the hf and ett dictionary entries
     * ------------------------------------------------------------------------
     */

    trdp_build_dict.hf =  wmem_array_new(wmem_dic, sizeof(hf_register_info));
    trdp_build_dict.ett = wmem_array_new(wmem_dic, sizeof(int *));

    if (hf_trdp_type <= 0) {
        proto_register_field_array(proto_trdp, hf_base, array_length(hf_base));
        proto_register_subtree_array(ett_base, array_length(ett_base));
    }

    if (pTrdpParser) {
        /* arrays use the same hf */
        /* don't care about comID linkage, as I really want to index all datasets,
         * regardless of their hierarchy */
        for (Dataset *ds = pTrdpParser->mTableDataset; ds; ds = ds->next) Dataset_add_reg_info(ds);
    }

    /* Required function calls to register the header fields and subtrees used */

    proto_register_field_array(proto_trdp, (hf_register_info *)wmem_array_get_raw(trdp_build_dict.hf), wmem_array_get_count(trdp_build_dict.hf));

    proto_register_subtree_array((int **)wmem_array_get_raw(trdp_build_dict.ett), wmem_array_get_count(trdp_build_dict.ett));
}

void proto_reg_handoff_trdp(void) {
    static bool initialized = FALSE;
    static unsigned int pd_port=0;
    static unsigned int md_port=0;
    API_TRACE;

    if (initialized == FALSE) {
        initialized = TRUE;
    } else {
        if (pd_port != g_pd_port) {
            dissector_delete_uint("udp.port", pd_port, trdp_handle);
        }
        if (md_port != g_md_port) {
            dissector_delete_uint("udp.port", md_port, trdp_handle);
            dissector_delete_uint("tcp.port", md_port, trdp_TCP_handle);
        }
    }
    if (pd_port != g_pd_port) {
        pd_port = g_pd_port;
        dissector_add_uint_with_preference("udp.port", pd_port, trdp_handle);
    }
    if (md_port != g_md_port) {
        md_port = g_md_port;
        dissector_add_uint_with_preference("udp.port", md_port, trdp_handle);
        dissector_add_uint_with_preference("tcp.port", md_port, trdp_TCP_handle);
    }

    /* Reload header fields and dictionary but only, if it's been in use before */
    if (hf_trdp_type > 0) register_trdp_fields(NULL);

    if (g_cstUUID) {
        uint8_t x[16];
        int i=0;
        const char* s = g_cstUUID;
        while(*s && i < 16) {
            if (*s == '-') {
                s++;
            } else {
                int8_t a = ws_xton(*s++);
                if (a < 0) break;
                int8_t b = ws_xton(*s++);
                if (b < 0) break;
                x[i++] = (uint8_t)a << 4 | b;
            }
        }

        if (i == 16) {
            memcpy(cstUUID, x, sizeof(cstUUID));
            invalid_cstUUID = false;
            have_cstUUID = true;
        } else {
            invalid_cstUUID = !!g_cstUUID[0]; /* invalid, if the string is not empty */
            have_cstUUID = false;
        }
    } else {
        invalid_cstUUID = false;
        have_cstUUID = false;
    }
}

void proto_register_trdp(void) {
    module_t *trdp_module;

    enum_val_t *bitsetenumvals;
    gsize bitset_offset = 0;
    gsize bitset_types = 0;

    wmem_dic = wmem_allocator_new(WMEM_ALLOCATOR_SIMPLE);

    while (ElBasics[bitset_offset].id              != TRDP_BITSET8) bitset_offset++;
    while (ElBasics[bitset_offset+bitset_types].id == TRDP_BITSET8) bitset_types++;

    bitsetenumvals = wmem_alloc0_array(wmem_epan_scope(), enum_val_t, bitset_types + 1);
    for (gsize i = 0; i < bitset_types; i++) {
        bitsetenumvals[i].description = ElBasics[bitset_offset+i].name;
        bitsetenumvals[i].name = wmem_ascii_strdown(wmem_epan_scope(), ElBasics[bitset_offset+i].name, -1);
        bitsetenumvals[i].value = (int)ElBasics[bitset_offset+i].subtype;
    }

    enum_val_t *endianenumvals = wmem_alloc0_array(wmem_epan_scope(), enum_val_t, 2 + 1);
    endianenumvals[0].description = "BE";
    endianenumvals[0].name = "be";
    endianenumvals[0].value = TRDP_ENDSUBTYPE_BIG;
    endianenumvals[1].description = "LE (non-standard)";
    endianenumvals[1].name = "le";
    endianenumvals[1].value = TRDP_ENDSUBTYPE_LIT;

    enum_val_t *foldenumvals = wmem_alloc0_array(wmem_epan_scope(), enum_val_t, 3 + 1);
    foldenumvals[0].description = "never";
    foldenumvals[0].name = "never";
    foldenumvals[0].value = TRDP_FOLD_NEVER;
    foldenumvals[1].description = "XML config unit";
    foldenumvals[1].name = "config";
    foldenumvals[1].value = TRDP_FOLD_CONFIG;
    foldenumvals[2].description = "always";
    foldenumvals[2].name = "always";
    foldenumvals[2].value = TRDP_FOLD_ALWAYS;

    API_TRACE;

    /* Register the protocol name and description */
    proto_trdp      = proto_register_protocol(PROTO_NAME_TRDP, PROTO_TAG_TRDP, PROTO_FILTERNAME_TRDP);
    trdp_handle     = register_dissector(PROTO_DISSECTORNAME_TRDP,    (dissector_t)dissect_trdp,     proto_trdp);
    trdp_TCP_handle = register_dissector(PROTO_DISSECTORNAME_TRDPTCP, (dissector_t)dissect_trdp_tcp, proto_trdp);
    /* Delay registration of com-id and dataset-id definitions */
    proto_register_prefix("trdp", register_trdp_fields);

    trdp_module     = prefs_register_protocol(proto_trdp, proto_reg_handoff_trdp);

    /* Register the preference */
    prefs_register_static_text_preference( trdp_module, "dissector_summary",
        "Version 20260314",
        NULL);

    prefs_register_bool_preference( trdp_module, "basexml",
        "Load basic set of comIDs and dataset definitions from IEC 61375-2-3",
        "When ticked, basic definitions of IEC 61375-2-3 are loaded. If that conflicts with your use or your definitions "
        "- untick. If there's a bug or data missing, please file an issue.",
        &g_basexml);

    prefs_set_preference_effect_fields(trdp_module, "basexml");

    prefs_register_filename_preference( trdp_module, "configfile",
        "Custom TRDP configuration file",
        "Custom TRDP configuration file",
        &g_customTrdpDictionary, FALSE);

    prefs_set_preference_effect_fields(trdp_module, "configfile");

    prefs_register_directory_preference( trdp_module, "configfolder",
        "Custom TRDP configuration file folder",
        "Custom TRDP configuration file folder",
        &g_customTrdpDictionaryFolder);

    prefs_set_preference_effect_fields(trdp_module, "configfolder");

    prefs_register_static_text_preference( trdp_module, "xml_summary",
        "Please chose only either a file or a folder and leave the other field empty. Be sure, not to have conflicting versions of datasets or com-ids in that target folder - the file parser will be pesky.",
        NULL);

    prefs_register_enum_preference( trdp_module, "bitset.subtype",
        "Select default sub-type for TRDP-Element type 1",
        "Type 1 can be interpreted differently, as BOOL, ANTIVALENT or BITSET. Select the fallback, if the element type is not given literally.",
        &g_bitset_subtype, bitsetenumvals, FALSE);

    prefs_set_preference_effect_fields( trdp_module, "bitset.subtype");

    prefs_register_enum_preference( trdp_module, "numeric.subtype",
        "Select default byte-order for TRDP-Element types (5-7,9-13)",
        "Number types can be interpreted differently, as BE or LE (non-standard). Select the fallback, if the element type is not given literally (e.g., UINT16 vs UINT16_LE).",
        &g_endian_subtype, endianenumvals, FALSE);

    prefs_set_preference_effect_fields( trdp_module, "numeric.subtype");

    prefs_register_enum_preference( trdp_module, "strings.le",
        "Select default byte-order for TRDP-Element type 3 (UTF-16 strings).",
        "Wide-character strings can be interpreted differently, as BE or LE (non-standard). Select the fallback, if the element type is not given literally (e.g., UTF16 vs UTF16_LE).",
        &g_wchar_subtype, endianenumvals, FALSE);

    prefs_set_preference_effect_fields( trdp_module, "strings.le");

    prefs_register_enum_preference( trdp_module, "uuid.subtype",
        "Select default byte-order for UUID fields.",
        "UUID can be interpreted differently, as BE or LE (non-standard). Select the fallback, if the element type is not given literally (e.g., UUID vs UUID_LE). This does not affect the VDP-Trailer check.",
        &g_uuid_subtype, endianenumvals, FALSE);

    prefs_set_preference_effect_fields( trdp_module, "uuid.subtype");

    prefs_register_enum_preference( trdp_module, "fold0",
        "Hide a dataset if it is all zeros",
        "If a dataset is all zeros (except array length values) it is hidden. For individual hiding, set the dataset referencing element's unit to \"fold0\".",
        &g_fold0_mode, foldenumvals, FALSE);

    prefs_set_preference_effect_fields( trdp_module, "fold0");

    prefs_register_bool_preference( trdp_module, "time.local",
        "Display time-types as local time, untick for UTC / no offsets.",
        "Time types should be based on UTC. When ticked, Wireshark adds on local timezone offset. Untick if you like UTC to be displayed, or the source is not UTC.",
        &g_time_local);

    prefs_register_bool_preference( trdp_module, "time.raw",
        "Display time-types as raw seconds, not absolute time.",
        "Time types should be absolute time since the UNIX-Epoch. When ticked, they are shown as seconds.",
        &g_time_raw);

    prefs_register_bool_preference( trdp_module, "0strings",
        "Variable-length CHAR8 and UTF16 arrays are 0-terminated. (non-standard)",
        "When ticked, the length of a variable-length string (array-size=0) is calculated from searching for a terminator instead of using a previous length element.",
        &g_0strings);

    prefs_register_bool_preference( trdp_module, "char8utf8",
        "Interpret CHAR8 arrays as UTF-8.",
        "When ticked, CHAR8 arrays are interpreted as UTF-8 string. If it fails, an exception is thrown. Untick if you need to see weird ASCII as C-escapes.",
        &g_char8_is_utf8);

    prefs_register_bool_preference( trdp_module, "scaled",
        "Use scaled value for filter.",
        "When ticked, uses scaled values for filtering and display, otherwise the raw value.",
        &g_scaled);

    prefs_register_string_preference( trdp_module, "sdtv2.consist_uuid",
        "cstUUID used for VDP_TRAILER check",
        "consist UUID for Safety Trailer calculation. Leave empty for consist-local. Insert only valid UUIDs-strings copied, "
        "e.g., from some UUID-field in the format 00112233-4455-6677-8899-aabbccddeeff. Invalid values will be ignored w/o warning.",
        &g_cstUUID);
    prefs_set_preference_effect_fields( trdp_module, "sdtv2.consist_uuid");

    prefs_register_uint_preference( trdp_module, "pd.udp.port",
        "PD message Port",
        "UDP port for PD messages (Default port is " TRDP_DEFAULT_STR_PD_PORT ")",
        10 /*base */, &g_pd_port);

    prefs_register_uint_preference( trdp_module, "md.udptcp.port",
        "MD message Port",
        "UDP and TCP port for MD messages (Default port is " TRDP_DEFAULT_STR_MD_PORT ")",
        10 /*base */, &g_md_port);

    /* abandon legacy prefs */
    prefs_register_obsolete_preference( trdp_module, "udp.port");
    prefs_register_obsolete_preference( trdp_module, "tcp.port");
    prefs_register_obsolete_preference( trdp_module, "sdtv2.sid");

    /* Register expert information */
    expert_module_t *expert_trdp;
    static ei_register_info ei[] = {
        {&ei_trdp_type_unknown,     {"trdp.type_unknown",      PI_UNDECODED, PI_WARN, "TRDP type unknown", EXPFILL}},
        {&ei_trdp_packet_small,     {"trdp.packet_size",       PI_UNDECODED, PI_WARN, "TRDP packet too small", EXPFILL}},
        {&ei_trdp_userdata_empty,   {"trdp.userdata_empty",    PI_UNDECODED, PI_WARN, "TRDP user data is empty", EXPFILL}},
        {&ei_trdp_proc_comid_zero,  {"trdp.process_comid_zero",PI_MALFORMED, PI_WARN, "Process packets must have com-id > 0", EXPFILL}},
        {&ei_trdp_userdata_wrong,   {"trdp.userdata_wrong",    PI_UNDECODED, PI_WARN, "TRDP user data has wrong format", EXPFILL}},
        {&ei_trdp_config_notparsed, {"trdp.config_unparsable", PI_UNDECODED, PI_WARN, "TRDP XML configuration cannot be parsed", EXPFILL}},
        {&ei_trdp_padding_not_zero, {"trdp.padding_non_zero",  PI_MALFORMED, PI_WARN, "TRDP Padding not filled with zero", EXPFILL}},
        {&ei_trdp_array_wrong,      {"trdp.array",             PI_PROTOCOL,  PI_WARN, "Dynamic array has unsupported datatype for length", EXPFILL}},
        {&ei_trdp_faulty_antivalent,{"trdp.faulty_antivalent", PI_MALFORMED, PI_WARN, "Data contains faulty antivalent value.", EXPFILL}},
        {&ei_trdp_reserved_not_zero,{"trdp.reserved_non_zero", PI_MALFORMED, PI_WARN, "Reserved attribute is not zero", EXPFILL}},
        {&ei_trdp_header_checksum,  {"trdp.checksum_hrd.bad",  PI_CHECKSUM,  PI_WARN, "Header checksum error.", EXPFILL}},
        {&ei_trdp_sdtv2_safetycode, {"trdp.sdtv2_safetycode.bad",PI_CHECKSUM,PI_WARN, "SDTv2 SafetyCode check error.", EXPFILL}},
        {&ei_trdp_sdtv2_sequence,   {"trdp.sdtv2_sequence",    PI_SEQUENCE,  PI_WARN, "SDTv2 SafetySequenceCounter check error.", EXPFILL}},
    };

    expert_trdp = expert_register_protocol(proto_trdp);
    expert_register_field_array(expert_trdp, ei, array_length(ei));
}
