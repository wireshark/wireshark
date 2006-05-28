/*
 *  This is part of tree.h from the libxml2 distribution.  It is used
 *  for structure reference when dynamically linking to libxml.
 *
 *  The GPL agreement for this file and for libxml2 can be found at
 *  http://www.xmlsoft.org
 */

#include "config.h"

/****************** specific to wireshark ********************************/
/*
 * Uncomment the following line to restore XML_DO_VALIDITY_CHECKING
 * behavior which is causing issues on WIN32 platforms. See:
 * http://www.ethereal.com/lists/ethereal-dev/200410/msg00194.html
 */
/* #define WIRESHARK_XML_DO_VALIDITY_CHECKING */
/****************** From xml headers ************************************/

/*
 * use those to be sure nothing nasty will happen if
 * your library and includes mismatch
 */
#ifndef LIBXML2_COMPILING_MSCCDEF
extern void xmlCheckVersion(int version);
#endif /* LIBXML2_COMPILING_MSCCDEF */
#define LIBXML_DOTTED_VERSION "2.3.8"
#define LIBXML_VERSION 20308
#define LIBXML_VERSION_STRING "20308"
#define LIBXML_TEST_VERSION xmlCheckVersion(20308);

/*
 * Whether the trio support need to be configured in
 */
#if 0
#define WITH_TRIO
#else
#define WITHOUT_TRIO
#endif

/*
 * Whether the FTP support is configured in
 */
#if 1
#define LIBXML_FTP_ENABLED
#else
#define LIBXML_FTP_DISABLED
#endif

/*
 * Whether the HTTP support is configured in
 */
#if 1
#define LIBXML_HTTP_ENABLED
#else
#define LIBXML_HTTP_DISABLED
#endif

/*
 * Whether the HTML support is configured in
 */
#if 1
#define LIBXML_HTML_ENABLED
#else
#define LIBXML_HTML_DISABLED
#endif

/*
 * Whether the SGML Docbook support is configured in
 */
#if 1
#define LIBXML_DOCB_ENABLED
#else
#define LIBXML_DOCB_DISABLED
#endif

/*
 * Whether XPath is configured in
 */
#if 1
#define LIBXML_XPATH_ENABLED
#else
#define LIBXML_XPATH_DISABLED
#endif

/*
 * Whether XPointer is configured in
 */
#if 1
#define LIBXML_XPTR_ENABLED
#else
#define LIBXML_XPTR_DISABLED
#endif

/*
 * Whether XInclude is configured in
 */
#if 1
#define LIBXML_XINCLUDE_ENABLED
#else
#define LIBXML_XINCLUDE_DISABLED
#endif

/*
 * Whether iconv support is available
 */
#ifdef HAVE_ICONV_H
#define LIBXML_ICONV_ENABLED
#include <iconv.h>
#else
#define LIBXML_ICONV_DISABLED
#endif

/*
 * Whether Debugging module is configured in
 */
#if 1
#define LIBXML_DEBUG_ENABLED
#else
#define LIBXML_DEBUG_DISABLED
#endif

/*
 * Whether the memory debugging is configured in
 */
#if 0
#define DEBUG_MEMORY_LOCATION
#endif

#ifndef LIBXML_DLL_IMPORT
#if defined(_WIN32) && !defined(STATIC)
#define LIBXML_DLL_IMPORT __declspec(dllimport)
#else
#define LIBXML_DLL_IMPORT
#endif
#endif

#ifdef __GNUC__
#ifdef HAVE_ANSIDECL_H
#include <ansidecl.h>
#endif
#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED
#endif
#else
#define ATTRIBUTE_UNUSED
#endif


#define XML_XML_NAMESPACE \
    (const xmlChar *) "http://www.w3.org/XML/1998/namespace"

/*
 * The different element types carried by an XML tree
 *
 * NOTE: This is synchronized with DOM Level1 values
 *       See http://www.w3.org/TR/REC-DOM-Level-1/
 *
 * Actually this had diverged a bit, and now XML_DOCUMENT_TYPE_NODE should
 * be deprecated to use an XML_DTD_NODE.
 */
typedef enum {
    XML_ELEMENT_NODE=           1,
    XML_ATTRIBUTE_NODE=         2,
    XML_TEXT_NODE=              3,
    XML_CDATA_SECTION_NODE=     4,
    XML_ENTITY_REF_NODE=        5,
    XML_ENTITY_NODE=            6,
    XML_PI_NODE=                7,
    XML_COMMENT_NODE=           8,
    XML_DOCUMENT_NODE=          9,
    XML_DOCUMENT_TYPE_NODE=     10,
    XML_DOCUMENT_FRAG_NODE=     11,
    XML_NOTATION_NODE=          12,
    XML_HTML_DOCUMENT_NODE=     13,
    XML_DTD_NODE=               14,
    XML_ELEMENT_DECL=           15,
    XML_ATTRIBUTE_DECL=         16,
    XML_ENTITY_DECL=            17,
    XML_NAMESPACE_DECL=         18,
    XML_XINCLUDE_START=         19,
    XML_XINCLUDE_END=           20
#ifdef LIBXML_DOCB_ENABLED
   ,XML_DOCB_DOCUMENT_NODE=     21
#endif
} xmlElementType;

/*
 * Size of an internal character representation.
 *
 * We use 8bit chars internal representation for memory efficiency,
 * Note that with 8 bits wide xmlChars one can still use UTF-8 to handle
 * correctly non ISO-Latin input.
 */

typedef unsigned char xmlChar;

#ifndef _WIN32
#ifndef CHAR
#define CHAR xmlChar
#endif
#endif

#define BAD_CAST (xmlChar *)

/*
 * a DTD Notation definition
 */

typedef struct _xmlNotation xmlNotation;
typedef xmlNotation *xmlNotationPtr;
struct _xmlNotation {
    const xmlChar               *name;          /* Notation name */
    const xmlChar               *PublicID;      /* Public identifier, if any */
    const xmlChar               *SystemID;      /* System identifier, if any */
};

/*
 * a DTD Attribute definition
 */

typedef enum {
    XML_ATTRIBUTE_CDATA = 1,
    XML_ATTRIBUTE_ID,
    XML_ATTRIBUTE_IDREF ,
    XML_ATTRIBUTE_IDREFS,
    XML_ATTRIBUTE_ENTITY,
    XML_ATTRIBUTE_ENTITIES,
    XML_ATTRIBUTE_NMTOKEN,
    XML_ATTRIBUTE_NMTOKENS,
    XML_ATTRIBUTE_ENUMERATION,
    XML_ATTRIBUTE_NOTATION
} xmlAttributeType;

typedef enum {
    XML_ATTRIBUTE_NONE = 1,
    XML_ATTRIBUTE_REQUIRED,
    XML_ATTRIBUTE_IMPLIED,
    XML_ATTRIBUTE_FIXED
} xmlAttributeDefault;

typedef struct _xmlEnumeration xmlEnumeration;
typedef xmlEnumeration *xmlEnumerationPtr;
struct _xmlEnumeration {
    struct _xmlEnumeration    *next;    /* next one */
    const xmlChar            *name;     /* Enumeration name */
};

typedef struct _xmlAttribute xmlAttribute;
typedef xmlAttribute *xmlAttributePtr;
struct _xmlAttribute {
#ifndef XML_WITHOUT_CORBA
    void           *_private;           /* for Corba, must be first ! */
#endif
    xmlElementType          type;       /* XML_ATTRIBUTE_DECL, must be second ! */
    const xmlChar          *name;       /* Attribute name */
    struct _xmlNode    *children;       /* NULL */
    struct _xmlNode        *last;       /* NULL */
    struct _xmlDtd       *parent;       /* -> DTD */
    struct _xmlNode        *next;       /* next sibling link  */
    struct _xmlNode        *prev;       /* previous sibling link  */
    struct _xmlDoc          *doc;       /* the containing document */

    struct _xmlAttribute  *nexth;       /* next in hash table */
    xmlAttributeType       atype;       /* The attribute type */
    xmlAttributeDefault      def;       /* the default */
    const xmlChar  *defaultValue;       /* or the default value */
    xmlEnumerationPtr       tree;       /* or the enumeration tree if any */
    const xmlChar        *prefix;       /* the namespace prefix if any */
    const xmlChar          *elem;       /* Element holding the attribute */
};

/*
 * a DTD Element definition.
 */
typedef enum {
    XML_ELEMENT_CONTENT_PCDATA = 1,
    XML_ELEMENT_CONTENT_ELEMENT,
    XML_ELEMENT_CONTENT_SEQ,
    XML_ELEMENT_CONTENT_OR
} xmlElementContentType;

typedef enum {
    XML_ELEMENT_CONTENT_ONCE = 1,
    XML_ELEMENT_CONTENT_OPT,
    XML_ELEMENT_CONTENT_MULT,
    XML_ELEMENT_CONTENT_PLUS
} xmlElementContentOccur;

typedef struct _xmlElementContent xmlElementContent;
typedef xmlElementContent *xmlElementContentPtr;
struct _xmlElementContent {
    xmlElementContentType     type;     /* PCDATA, ELEMENT, SEQ or OR */
    xmlElementContentOccur    ocur;     /* ONCE, OPT, MULT or PLUS */
    const xmlChar            *name;     /* Element name */
    struct _xmlElementContent *c1;      /* first child */
    struct _xmlElementContent *c2;      /* second child */
    struct _xmlElementContent *parent;  /* parent */
};

typedef enum {
    XML_ELEMENT_TYPE_UNDEFINED = 0,
    XML_ELEMENT_TYPE_EMPTY = 1,
    XML_ELEMENT_TYPE_ANY,
    XML_ELEMENT_TYPE_MIXED,
    XML_ELEMENT_TYPE_ELEMENT
} xmlElementTypeVal;

typedef struct _xmlElement xmlElement;
typedef xmlElement *xmlElementPtr;
struct _xmlElement {
#ifndef XML_WITHOUT_CORBA
    void           *_private;           /* for Corba, must be first ! */
#endif
    xmlElementType          type;       /* XML_ELEMENT_DECL, must be second ! */
    const xmlChar          *name;       /* Element name */
    struct _xmlNode    *children;       /* NULL */
    struct _xmlNode        *last;       /* NULL */
    struct _xmlDtd       *parent;       /* -> DTD */
    struct _xmlNode        *next;       /* next sibling link  */
    struct _xmlNode        *prev;       /* previous sibling link  */
    struct _xmlDoc          *doc;       /* the containing document */

    xmlElementTypeVal      etype;       /* The type */
    xmlElementContentPtr content;       /* the allowed element content */
    xmlAttributePtr   attributes;       /* List of the declared attributes */
    const xmlChar        *prefix;       /* the namespace prefix if any */
};

/*
 * An XML namespace.
 * Note that prefix == NULL is valid, it defines the default namespace
 * within the subtree (until overriden).
 *
 * XML_GLOBAL_NAMESPACE is now deprecated for good
 * xmlNsType is unified with xmlElementType
 */

#define XML_LOCAL_NAMESPACE XML_NAMESPACE_DECL
typedef xmlElementType xmlNsType;

typedef struct _xmlNs xmlNs;
typedef xmlNs *xmlNsPtr;
struct _xmlNs {
    struct _xmlNs  *next;       /* next Ns link for this node  */
    xmlNsType      type;        /* global or local */
    const xmlChar *href;        /* URL for the namespace */
    const xmlChar *prefix;      /* prefix for the namespace */
};

/*
 * An XML DtD, as defined by <!DOCTYPE.
 */
typedef struct _xmlDtd xmlDtd;
typedef xmlDtd *xmlDtdPtr;
struct _xmlDtd {
#ifndef XML_WITHOUT_CORBA
    void           *_private;   /* for Corba, must be first ! */
#endif
    xmlElementType  type;       /* XML_DTD_NODE, must be second ! */
    const xmlChar *name;        /* Name of the DTD */
    struct _xmlNode *children;  /* the value of the property link */
    struct _xmlNode *last;      /* last child link */
    struct _xmlDoc  *parent;    /* child->parent link */
    struct _xmlNode *next;      /* next sibling link  */
    struct _xmlNode *prev;      /* previous sibling link  */
    struct _xmlDoc  *doc;       /* the containing document */

    /* End of common part */
    void          *notations;   /* Hash table for notations if any */
    void          *elements;    /* Hash table for elements if any */
    void          *attributes;  /* Hash table for attributes if any */
    void          *entities;    /* Hash table for entities if any */
    const xmlChar *ExternalID;  /* External identifier for PUBLIC DTD */
    const xmlChar *SystemID;    /* URI for a SYSTEM or PUBLIC DTD */
    void          *pentities;   /* Hash table for param entities if any */
};

/*
 * A attribute of an XML node.
 */
typedef struct _xmlAttr xmlAttr;
typedef xmlAttr *xmlAttrPtr;
struct _xmlAttr {
#ifndef XML_WITHOUT_CORBA
    void           *_private;   /* for Corba, must be first ! */
#endif
    xmlElementType   type;      /* XML_ATTRIBUTE_NODE, must be second ! */
    const xmlChar   *name;      /* the name of the property */
    struct _xmlNode *children;  /* the value of the property */
    struct _xmlNode *last;      /* NULL */
    struct _xmlNode *parent;    /* child->parent link */
    struct _xmlAttr *next;      /* next sibling link  */
    struct _xmlAttr *prev;      /* previous sibling link  */
    struct _xmlDoc  *doc;       /* the containing document */
    xmlNs           *ns;        /* pointer to the associated namespace */
    xmlAttributeType atype;     /* the attribute type if validating */
};

/*
 * An XML ID instance.
 */

typedef struct _xmlID xmlID;
typedef xmlID *xmlIDPtr;
struct _xmlID {
    struct _xmlID    *next;     /* next ID */
    const xmlChar    *value;    /* The ID name */
    xmlAttrPtr        attr;     /* The attribut holding it */
};

/*
 * An XML IDREF instance.
 */

typedef struct _xmlRef xmlRef;
typedef xmlRef *xmlRefPtr;
struct _xmlRef {
    struct _xmlRef    *next;    /* next Ref */
    const xmlChar     *value;   /* The Ref name */
    xmlAttrPtr        attr;     /* The attribut holding it */
};

/*
 * A buffer structure
 */

typedef enum {
    XML_BUFFER_ALLOC_DOUBLEIT,
    XML_BUFFER_ALLOC_EXACT
} xmlBufferAllocationScheme;

typedef struct _xmlBuffer xmlBuffer;
typedef xmlBuffer *xmlBufferPtr;
struct _xmlBuffer {
    xmlChar *content;           /* The buffer content UTF8 */
    unsigned int use;           /* The buffer size used */
    unsigned int size;          /* The buffer size */
    xmlBufferAllocationScheme alloc; /* The realloc method */
};

/*
 * A node in an XML tree.
 */
typedef struct _xmlNode xmlNode;
typedef xmlNode *xmlNodePtr;
struct _xmlNode {
#ifndef XML_WITHOUT_CORBA
    void           *_private;   /* for Corba, must be first ! */
#endif
    xmlElementType   type;      /* type number, must be second ! */
    const xmlChar   *name;      /* the name of the node, or the entity */
    struct _xmlNode *children;  /* parent->childs link */
    struct _xmlNode *last;      /* last child link */
    struct _xmlNode *parent;    /* child->parent link */
    struct _xmlNode *next;      /* next sibling link  */
    struct _xmlNode *prev;      /* previous sibling link  */
    struct _xmlDoc  *doc;       /* the containing document */
    xmlNs           *ns;        /* pointer to the associated namespace */
#ifndef XML_USE_BUFFER_CONTENT
    xmlChar         *content;   /* the content */
#else
    xmlBufferPtr     content;   /* the content in a buffer */
#endif

    /* End of common part */
    struct _xmlAttr *properties;/* properties list */
    xmlNs           *nsDef;     /* namespace definitions on this node */
};

/*
 * An XML document.
 */
typedef struct _xmlDoc xmlDoc;
typedef xmlDoc *xmlDocPtr;
struct _xmlDoc {
#ifndef XML_WITHOUT_CORBA
    void           *_private;   /* for Corba, must be first ! */
#endif
    xmlElementType  type;       /* XML_DOCUMENT_NODE, must be second ! */
    char           *name;       /* name/filename/URI of the document */
    struct _xmlNode *children;  /* the document tree */
    struct _xmlNode *last;      /* last child link */
    struct _xmlNode *parent;    /* child->parent link */
    struct _xmlNode *next;      /* next sibling link  */
    struct _xmlNode *prev;      /* previous sibling link  */
    struct _xmlDoc  *doc;       /* autoreference to itself */

    /* End of common part */
    int             compression;/* level of zlib compression */
    int             standalone; /* standalone document (no external refs) */
    struct _xmlDtd  *intSubset; /* the document internal subset */
    struct _xmlDtd  *extSubset; /* the document external subset */
    struct _xmlNs   *oldNs;     /* Global namespace, the old way */
    const xmlChar  *version;    /* the XML version string */
    const xmlChar  *encoding;   /* external initial encoding, if any */
    void           *ids;        /* Hash table for ID attributes if any */
    void           *refs;       /* Hash table for IDREFs attributes if any */
    const xmlChar  *URL;        /* The URI for that document */
    int             charset;    /* encoding of the in-memory content
                                   actually an xmlCharEncoding */
};

/**
 * Predefined values for some standard encodings
 * Libxml don't do beforehand translation on UTF8, ISOLatinX
 * It also support UTF16 (LE and BE) by default.
 *
 * Anything else would have to be translated to UTF8 before being
 * given to the parser itself. The BOM for UTF16 and the encoding
 * declaration are looked at and a converter is looked for at that
 * point. If not found the parser stops here as asked by the XML REC
 * Converter can be registered by the user using xmlRegisterCharEncodingHandler
 * but the currentl form doesn't allow stateful transcoding (a serious
 * problem agreed !). If iconv has been found it will be used
 * automatically and allow stateful transcoding, the simplest is then
 * to be sure to enable icon and to provide iconv libs for the encoding
 * support needed.
 */
typedef enum {
    XML_CHAR_ENCODING_ERROR=   -1, /* No char encoding detected */
    XML_CHAR_ENCODING_NONE=     0, /* No char encoding detected */
    XML_CHAR_ENCODING_UTF8=     1, /* UTF-8 */
    XML_CHAR_ENCODING_UTF16LE=  2, /* UTF-16 little endian */
    XML_CHAR_ENCODING_UTF16BE=  3, /* UTF-16 big endian */
    XML_CHAR_ENCODING_UCS4LE=   4, /* UCS-4 little endian */
    XML_CHAR_ENCODING_UCS4BE=   5, /* UCS-4 big endian */
    XML_CHAR_ENCODING_EBCDIC=   6, /* EBCDIC uh! */
    XML_CHAR_ENCODING_UCS4_2143=7, /* UCS-4 unusual ordering */
    XML_CHAR_ENCODING_UCS4_3412=8, /* UCS-4 unusual ordering */
    XML_CHAR_ENCODING_UCS2=     9, /* UCS-2 */
    XML_CHAR_ENCODING_8859_1=   10,/* ISO-8859-1 ISO Latin 1 */
    XML_CHAR_ENCODING_8859_2=   11,/* ISO-8859-2 ISO Latin 2 */
    XML_CHAR_ENCODING_8859_3=   12,/* ISO-8859-3 */
    XML_CHAR_ENCODING_8859_4=   13,/* ISO-8859-4 */
    XML_CHAR_ENCODING_8859_5=   14,/* ISO-8859-5 */
    XML_CHAR_ENCODING_8859_6=   15,/* ISO-8859-6 */
    XML_CHAR_ENCODING_8859_7=   16,/* ISO-8859-7 */
    XML_CHAR_ENCODING_8859_8=   17,/* ISO-8859-8 */
    XML_CHAR_ENCODING_8859_9=   18,/* ISO-8859-9 */
    XML_CHAR_ENCODING_2022_JP=  19,/* ISO-2022-JP */
    XML_CHAR_ENCODING_SHIFT_JIS=20,/* Shift_JIS */
    XML_CHAR_ENCODING_EUC_JP=   21,/* EUC-JP */
    XML_CHAR_ENCODING_ASCII=    22 /* pure ASCII */
} xmlCharEncoding;

/**
 * xmlCharEncodingInputFunc:
 * @param out  a pointer ot an array of bytes to store the UTF-8 result
 * @param outlen  the length of out
 * @param in  a pointer ot an array of chars in the original encoding
 * @param inlen  the length of in
 *
 * Take a block of chars in the original encoding and try to convert
 * it to an UTF-8 block of chars out.
 *
 * Returns the number of byte written, or -1 by lack of space, or -2
 *     if the transcoding failed.
 * The value of inlen after return is the number of octets consumed
 *     as the return value is positive, else unpredictiable.
 * The value of outlen after return is the number of ocetes consumed.
 */
typedef int (* xmlCharEncodingInputFunc)(unsigned char* out, int *outlen,
                                         const unsigned char* in, int *inlen);


/**
 * xmlCharEncodingOutputFunc:
 * @param out  a pointer ot an array of bytes to store the result
 * @param outlen  the length of out
 * @param in  a pointer ot an array of UTF-8 chars
 * @param inlen  the length of in
 *
 * Take a block of UTF-8 chars in and try to convert it to an other
 * encoding.
 * Note: a first call designed to produce heading info is called with
 * in = NULL. If stateful this should also initialize the encoder state
 *
 * Returns the number of byte written, or -1 by lack of space, or -2
 *     if the transcoding failed.
 * The value of inlen after return is the number of octets consumed
 *     as the return value is positive, else unpredictiable.
 * The value of outlen after return is the number of ocetes consumed.
 */
typedef int (* xmlCharEncodingOutputFunc)(unsigned char* out, int *outlen,
                                          const unsigned char* in, int *inlen);


/*
 * Block defining the handlers for non UTF-8 encodings.
 * If iconv is supported, there is two extra fields
 */

typedef struct _xmlCharEncodingHandler xmlCharEncodingHandler;
typedef xmlCharEncodingHandler *xmlCharEncodingHandlerPtr;
struct _xmlCharEncodingHandler {
    char                       *name;
    xmlCharEncodingInputFunc   input;
    xmlCharEncodingOutputFunc  output;
#ifdef LIBXML_ICONV_ENABLED
    iconv_t                    iconv_in;
    iconv_t                    iconv_out;
#endif /* LIBXML_ICONV_ENABLED */
};

typedef int (*xmlInputMatchCallback) (char const *filename);
typedef void * (*xmlInputOpenCallback) (char const *filename);
typedef int (*xmlInputReadCallback) (void * context, char * buffer, int len);
typedef void (*xmlInputCloseCallback) (void * context);

typedef struct _xmlParserInputBuffer xmlParserInputBuffer;
typedef xmlParserInputBuffer *xmlParserInputBufferPtr;
struct _xmlParserInputBuffer {
    void*                  context;
    xmlInputReadCallback   readcallback;
    xmlInputCloseCallback  closecallback;

    xmlCharEncodingHandlerPtr encoder; /* I18N conversions to UTF-8 */

    xmlBufferPtr buffer;    /* Local buffer encoded in UTF-8 */
    xmlBufferPtr raw;       /* if encoder != NULL buffer for raw input */
};


/*
 * Those are the functions and datatypes for the library output
 * I/O structures.
 */

typedef int (*xmlOutputMatchCallback) (char const *filename);
typedef void * (*xmlOutputOpenCallback) (char const *filename);
typedef int (*xmlOutputWriteCallback) (void * context, const char * buffer,
                                       int len);
typedef void (*xmlOutputCloseCallback) (void * context);

typedef struct _xmlOutputBuffer xmlOutputBuffer;
typedef xmlOutputBuffer *xmlOutputBufferPtr;
struct _xmlOutputBuffer {
    void*                   context;
    xmlOutputWriteCallback  writecallback;
    xmlOutputCloseCallback  closecallback;

    xmlCharEncodingHandlerPtr encoder; /* I18N conversions to UTF-8 */

    xmlBufferPtr buffer;    /* Local buffer encoded in UTF-8 or ISOLatin */
    xmlBufferPtr conv;      /* if encoder != NULL buffer for output */
    int written;            /* total number of byte written */
};

#define XML_DEFAULT_VERSION     "1.0"

/**
 * an xmlParserInput is an input flow for the XML processor.
 * Each entity parsed is associated an xmlParserInput (except the
 * few predefined ones). This is the case both for internal entities
 * - in which case the flow is already completely in memory - or
 * external entities - in which case we use the buf structure for
 * progressive reading and I18N conversions to the internal UTF-8 format.
 */

typedef void (* xmlParserInputDeallocate)(xmlChar *);
typedef struct _xmlParserInput xmlParserInput;
typedef xmlParserInput *xmlParserInputPtr;
struct _xmlParserInput {
    /* Input buffer */
    xmlParserInputBufferPtr buf;      /* UTF-8 encoded buffer */

    const char *filename;             /* The file analyzed, if any */
    const char *directory;            /* the directory/base of teh file */
    const xmlChar *base;              /* Base of the array to parse */
    const xmlChar *cur;               /* Current char being parsed */
    const xmlChar *end;               /* end of the arry to parse */
    int length;                       /* length if known */
    int line;                         /* Current line */
    int col;                          /* Current column */
    int consumed;                     /* How many xmlChars already consumed */
    xmlParserInputDeallocate free;    /* function to deallocate the base */
    const xmlChar *encoding;          /* the encoding string for entity */
    const xmlChar *version;           /* the version string for entity */
    int standalone;                   /* Was that entity marked standalone */
};

/**
 * the parser can be asked to collect Node informations, i.e. at what
 * place in the file they were detected.
 * NOTE: This is off by default and not very well tested.
 */
typedef struct _xmlParserNodeInfo xmlParserNodeInfo;
typedef xmlParserNodeInfo *xmlParserNodeInfoPtr;

struct _xmlParserNodeInfo {
  const struct _xmlNode* node;
  /* Position & line # that text that created the node begins & ends on */
  unsigned long begin_pos;
  unsigned long begin_line;
  unsigned long end_pos;
  unsigned long end_line;
};

typedef struct _xmlParserNodeInfoSeq xmlParserNodeInfoSeq;
typedef xmlParserNodeInfoSeq *xmlParserNodeInfoSeqPtr;
struct _xmlParserNodeInfoSeq {
  unsigned long maximum;
  unsigned long length;
  xmlParserNodeInfo* buffer;
};

/*
 * Validation state added for non-determinist content model
 */
typedef struct _xmlValidState xmlValidState;
typedef xmlValidState *xmlValidStatePtr;

/**
 * an xmlValidCtxt is used for error reporting when validating
 */

typedef void (*xmlValidityErrorFunc) (void *ctx, const char *msg, ...);
typedef void (*xmlValidityWarningFunc) (void *ctx, const char *msg, ...);

typedef struct _xmlValidCtxt xmlValidCtxt;
typedef xmlValidCtxt *xmlValidCtxtPtr;
struct _xmlValidCtxt {
    void *userData;                     /* user specific data block */
    xmlValidityErrorFunc error;         /* the callback in case of errors */
    xmlValidityWarningFunc warning;     /* the callback in case of warning */

    /* Node analysis stack used when validating within entities */
    xmlNodePtr         node;          /* Current parsed Node */
    int                nodeNr;        /* Depth of the parsing stack */
    int                nodeMax;       /* Max depth of the parsing stack */
    xmlNodePtr        *nodeTab;       /* array of nodes */

    int              finishDtd;       /* finished validating the Dtd ? */
    xmlDocPtr              doc;       /* the document */
    int                  valid;       /* temporary validity check result */

    /* state state used for non-determinist content validation */
    xmlValidState     *vstate;        /* current state */
    int                vstateNr;      /* Depth of the validation stack */
    int                vstateMax;     /* Max depth of the validation stack */
    xmlValidState     *vstateTab;     /* array of validation states */
};

typedef struct _xmlLink xmlLink;
typedef xmlLink *xmlLinkPtr;

typedef struct _xmlList xmlList;
typedef xmlList *xmlListPtr;

typedef void (*xmlListDeallocator) (xmlLinkPtr lk);
typedef int  (*xmlListDataCompare) (const void *data0, const void *data1);
typedef int (*xmlListWalker) (const void *data, const void *user);

/*
 * ALl notation declarations are stored in a table
 * there is one table per DTD
 */

typedef struct _xmlHashTable xmlNotationTable;
typedef xmlNotationTable *xmlNotationTablePtr;

/*
 * ALl element declarations are stored in a table
 * there is one table per DTD
 */

typedef struct _xmlHashTable xmlElementTable;
typedef xmlElementTable *xmlElementTablePtr;

/*
 * ALl attribute declarations are stored in a table
 * there is one table per DTD
 */

typedef struct _xmlHashTable xmlAttributeTable;
typedef xmlAttributeTable *xmlAttributeTablePtr;

/*
 * ALl IDs attributes are stored in a table
 * there is one table per document
 */

typedef struct _xmlHashTable xmlIDTable;
typedef xmlIDTable *xmlIDTablePtr;

/*
 * ALl Refs attributes are stored in a table
 * there is one table per document
 */

typedef struct _xmlHashTable xmlRefTable;
typedef xmlRefTable *xmlRefTablePtr;

/* helper */
xmlChar *           xmlSplitQName2      (const xmlChar *name,
                                         xmlChar **prefix);

/**
 * The parser is now working also as a state based parser
 * The recursive one use the stagte info for entities processing
 */
typedef enum {
    XML_PARSER_EOF = -1,        /* nothing is to be parsed */
    XML_PARSER_START = 0,       /* nothing has been parsed */
    XML_PARSER_MISC,            /* Misc* before int subset */
    XML_PARSER_PI,              /* Whithin a processing instruction */
    XML_PARSER_DTD,             /* within some DTD content */
    XML_PARSER_PROLOG,          /* Misc* after internal subset */
    XML_PARSER_COMMENT,         /* within a comment */
    XML_PARSER_START_TAG,       /* within a start tag */
    XML_PARSER_CONTENT,         /* within the content */
    XML_PARSER_CDATA_SECTION,   /* within a CDATA section */
    XML_PARSER_END_TAG,         /* within a closing tag */
    XML_PARSER_ENTITY_DECL,     /* within an entity declaration */
    XML_PARSER_ENTITY_VALUE,    /* within an entity value in a decl */
    XML_PARSER_ATTRIBUTE_VALUE, /* within an attribute value */
    XML_PARSER_SYSTEM_LITERAL,  /* within a SYSTEM value */
    XML_PARSER_EPILOG,          /* the Misc* after the last end tag */
    XML_PARSER_IGNORE           /* within an IGNORED section */
} xmlParserInputState;

/**
 * The parser context.
 * NOTE This doesn't completely defines the parser state, the (current ?)
 *      design of the parser uses recursive function calls since this allow
 *      and easy mapping from the production rules of the specification
 *      to the actual code. The drawback is that the actual function call
 *      also reflect the parser state. However most of the parsing routines
 *      takes as the only argument the parser context pointer, so migrating
 *      to a state based parser for progressive parsing shouldn't be too hard.
 */
typedef struct _xmlParserCtxt xmlParserCtxt;
typedef xmlParserCtxt *xmlParserCtxtPtr;
struct _xmlParserCtxt {
    struct _xmlSAXHandler *sax;       /* The SAX handler */
    void            *userData;        /* For SAX interface only, used by DOM build */
    xmlDocPtr           myDoc;        /* the document being built */
    int            wellFormed;        /* is the document well formed */
    int       replaceEntities;        /* shall we replace entities ? */
    const xmlChar    *version;        /* the XML version string */
    const xmlChar   *encoding;        /* the declared encoding, if any */
    int            standalone;        /* standalone document */
    int                  html;        /* an HTML(1)/Docbook(2) document */

    /* Input stream stack */
    xmlParserInputPtr  input;         /* Current input stream */
    int                inputNr;       /* Number of current input streams */
    int                inputMax;      /* Max number of input streams */
    xmlParserInputPtr *inputTab;      /* stack of inputs */

    /* Node analysis stack only used for DOM building */
    xmlNodePtr         node;          /* Current parsed Node */
    int                nodeNr;        /* Depth of the parsing stack */
    int                nodeMax;       /* Max depth of the parsing stack */
    xmlNodePtr        *nodeTab;       /* array of nodes */

    int record_info;                  /* Whether node info should be kept */
    xmlParserNodeInfoSeq node_seq;    /* info about each node parsed */

    int errNo;                        /* error code */

    int     hasExternalSubset;        /* reference and external subset */
    int             hasPErefs;        /* the internal subset has PE refs */
    int              external;        /* are we parsing an external entity */

    int                 valid;        /* is the document valid */
    int              validate;        /* shall we try to validate ? */
    xmlValidCtxt        vctxt;        /* The validity context */

    xmlParserInputState instate;      /* current type of input */
    int                 token;        /* next char look-ahead */

    char           *directory;        /* the data directory */

    /* Node name stack */
    xmlChar           *name;          /* Current parsed Node */
    int                nameNr;        /* Depth of the parsing stack */
    int                nameMax;       /* Max depth of the parsing stack */
    xmlChar *         *nameTab;       /* array of nodes */

    long               nbChars;       /* number of xmlChar processed */
    long            checkIndex;       /* used by progressive parsing lookup */
    int             keepBlanks;       /* ugly but ... */
    int             disableSAX;       /* SAX callbacks are disabled */
    int               inSubset;       /* Parsing is in int 1/ext 2 subset */
    xmlChar *          intSubName;    /* name of subset */
    xmlChar *          extSubURI;     /* URI of external subset */
    xmlChar *          extSubSystem;  /* SYSTEM ID of external subset */

    /* xml:space values */
    int *              space;         /* Should the parser preserve spaces */
    int                spaceNr;       /* Depth of the parsing stack */
    int                spaceMax;      /* Max depth of the parsing stack */
    int *              spaceTab;      /* array of space infos */

    int                depth;         /* to prevent entity substitution loops */
    xmlParserInputPtr  entity;        /* used to check entities boundaries */
    int                charset;       /* encoding of the in-memory content
                                         actually an xmlCharEncoding */
    int                nodelen;       /* Those two fields are there to */
    int                nodemem;       /* Speed up large node parsing */
    int                pedantic;      /* signal pedantic warnings */
    void              *_private;      /* For user data, libxml won't touch it */

    int                loadsubset;    /* should the external subset be loaded */
};

/**
 * a SAX Locator.
 */
typedef struct _xmlSAXLocator xmlSAXLocator;
typedef xmlSAXLocator *xmlSAXLocatorPtr;
struct _xmlSAXLocator {
    const xmlChar *(*getPublicId)(void *ctx);
    const xmlChar *(*getSystemId)(void *ctx);
    int (*getLineNumber)(void *ctx);
    int (*getColumnNumber)(void *ctx);
};

/*
 * The different valid entity types
 */
typedef enum {
    XML_INTERNAL_GENERAL_ENTITY = 1,
    XML_EXTERNAL_GENERAL_PARSED_ENTITY = 2,
    XML_EXTERNAL_GENERAL_UNPARSED_ENTITY = 3,
    XML_INTERNAL_PARAMETER_ENTITY = 4,
    XML_EXTERNAL_PARAMETER_ENTITY = 5,
    XML_INTERNAL_PREDEFINED_ENTITY = 6
} xmlEntityType;

/*
 * An unit of storage for an entity, contains the string, the value
 * and the linkind data needed for the linking in the hash table.
 */

typedef struct _xmlEntity xmlEntity;
typedef xmlEntity *xmlEntityPtr;
struct _xmlEntity {
#ifndef XML_WITHOUT_CORBA
    void           *_private;           /* for Corba, must be first ! */
#endif
    xmlElementType          type;       /* XML_ENTITY_DECL, must be second ! */
    const xmlChar          *name;       /* Attribute name */
    struct _xmlNode    *children;       /* NULL */
    struct _xmlNode        *last;       /* NULL */
    struct _xmlDtd       *parent;       /* -> DTD */
    struct _xmlNode        *next;       /* next sibling link  */
    struct _xmlNode        *prev;       /* previous sibling link  */
    struct _xmlDoc          *doc;       /* the containing document */

    xmlChar                *orig;       /* content without ref substitution */
    xmlChar             *content;       /* content or ndata if unparsed */
    int                   length;       /* the content length */
    xmlEntityType          etype;       /* The entity type */
    const xmlChar    *ExternalID;       /* External identifier for PUBLIC */
    const xmlChar      *SystemID;       /* URI for a SYSTEM or PUBLIC Entity */

    struct _xmlEntity     *nexte;       /* unused */
    const xmlChar           *URI;       /* the full URI as computed */
};

/*
 * ALl entities are stored in an hash table
 * there is 2 separate hash tables for global and parmeter entities
 */

typedef struct _xmlHashTable xmlEntitiesTable;
typedef xmlEntitiesTable *xmlEntitiesTablePtr;

/*
 * External functions :
 */

/**
 * a SAX handler is bunch of callbacks called by the parser when processing
 * of the input generate data or structure informations.
 */

typedef xmlParserInputPtr (*resolveEntitySAXFunc) (void *ctx,
                            const xmlChar *publicId, const xmlChar *systemId);
typedef void (*internalSubsetSAXFunc) (void *ctx, const xmlChar *name,
                            const xmlChar *ExternalID, const xmlChar *SystemID);
typedef void (*externalSubsetSAXFunc) (void *ctx, const xmlChar *name,
                            const xmlChar *ExternalID, const xmlChar *SystemID);
typedef xmlEntityPtr (*getEntitySAXFunc) (void *ctx,
                            const xmlChar *name);
typedef xmlEntityPtr (*getParameterEntitySAXFunc) (void *ctx,
                            const xmlChar *name);
typedef void (*entityDeclSAXFunc) (void *ctx,
                            const xmlChar *name, int type, const xmlChar *publicId,
                            const xmlChar *systemId, xmlChar *content);
typedef void (*notationDeclSAXFunc)(void *ctx, const xmlChar *name,
                            const xmlChar *publicId, const xmlChar *systemId);
typedef void (*attributeDeclSAXFunc)(void *ctx, const xmlChar *elem,
                            const xmlChar *name, int type, int def,
                            const xmlChar *defaultValue, xmlEnumerationPtr tree);
typedef void (*elementDeclSAXFunc)(void *ctx, const xmlChar *name,
                            int type, xmlElementContentPtr content);
typedef void (*unparsedEntityDeclSAXFunc)(void *ctx,
                            const xmlChar *name, const xmlChar *publicId,
                            const xmlChar *systemId, const xmlChar *notationName);
typedef void (*setDocumentLocatorSAXFunc) (void *ctx,
                            xmlSAXLocatorPtr loc);
typedef void (*startDocumentSAXFunc) (void *ctx);
typedef void (*endDocumentSAXFunc) (void *ctx);
typedef void (*startElementSAXFunc) (void *ctx, const xmlChar *name,
                            const xmlChar **atts);
typedef void (*endElementSAXFunc) (void *ctx, const xmlChar *name);
typedef void (*attributeSAXFunc) (void *ctx, const xmlChar *name,
                                  const xmlChar *value);
typedef void (*referenceSAXFunc) (void *ctx, const xmlChar *name);
typedef void (*charactersSAXFunc) (void *ctx, const xmlChar *ch,
                            int len);
typedef void (*ignorableWhitespaceSAXFunc) (void *ctx,
                            const xmlChar *ch, int len);
typedef void (*processingInstructionSAXFunc) (void *ctx,
                            const xmlChar *target, const xmlChar *data);
typedef void (*commentSAXFunc) (void *ctx, const xmlChar *value);
typedef void (*cdataBlockSAXFunc) (void *ctx, const xmlChar *value, int len);
typedef void (*warningSAXFunc) (void *ctx, const char *msg, ...);
typedef void (*errorSAXFunc) (void *ctx, const char *msg, ...);
typedef void (*fatalErrorSAXFunc) (void *ctx, const char *msg, ...);
typedef int (*isStandaloneSAXFunc) (void *ctx);
typedef int (*hasInternalSubsetSAXFunc) (void *ctx);
typedef int (*hasExternalSubsetSAXFunc) (void *ctx);

typedef struct _xmlSAXHandler xmlSAXHandler;
typedef xmlSAXHandler *xmlSAXHandlerPtr;
struct _xmlSAXHandler {
    internalSubsetSAXFunc internalSubset;
    isStandaloneSAXFunc isStandalone;
    hasInternalSubsetSAXFunc hasInternalSubset;
    hasExternalSubsetSAXFunc hasExternalSubset;
    resolveEntitySAXFunc resolveEntity;
    getEntitySAXFunc getEntity;
    entityDeclSAXFunc entityDecl;
    notationDeclSAXFunc notationDecl;
    attributeDeclSAXFunc attributeDecl;
    elementDeclSAXFunc elementDecl;
    unparsedEntityDeclSAXFunc unparsedEntityDecl;
    setDocumentLocatorSAXFunc setDocumentLocator;
    startDocumentSAXFunc startDocument;
    endDocumentSAXFunc endDocument;
    startElementSAXFunc startElement;
    endElementSAXFunc endElement;
    referenceSAXFunc reference;
    charactersSAXFunc characters;
    ignorableWhitespaceSAXFunc ignorableWhitespace;
    processingInstructionSAXFunc processingInstruction;
    commentSAXFunc comment;
    warningSAXFunc warning;
    errorSAXFunc error;
    fatalErrorSAXFunc fatalError;
    getParameterEntitySAXFunc getParameterEntity;
    cdataBlockSAXFunc cdataBlock;
    externalSubsetSAXFunc externalSubset;
};

/**
 * External entity loaders types
 */
typedef xmlParserInputPtr (*xmlExternalEntityLoader)(const char *URL,
                                                     const char *ID,
                                                     xmlParserCtxtPtr context);

/*
 * Compatibility naming layer with libxml1
 */
#ifndef xmlChildrenNode
#define xmlChildrenNode children
#define xmlRootNode children
#endif


/*********************Xml routines and function pointers */
#ifdef IN_XMLSTUB
#define XML_EXTERN
#else
#define XML_EXTERN extern
#endif

typedef struct {
	/* Functions */
	xmlDocPtr         (*xmlParseFile)(const char *filename);
	int              (*xmlStrcmp)(const xmlChar *str1, const xmlChar *str2);
	xmlParserCtxtPtr  (*xmlCreatePushParserCtxt)(xmlSAXHandlerPtr, void *, const char *,
												 int, const char *);
	int              (*xmlParseChunk)(xmlParserCtxtPtr, const char *, int, int);
	void             (*xmlFreeParserCtxt)(xmlParserCtxtPtr);
	xmlNodePtr         (*xmlDocGetRootElement)(xmlDocPtr);
	void             (*xmlFreeDoc)(xmlDocPtr);
	char            *(*xmlNodeListGetString)(xmlDocPtr, xmlNodePtr, int);
	char            *(*xmlGetProp)(xmlNodePtr, char *);
	int              (*xmlKeepBlanksDefault)(int);
	int              (*xmlSubstituteEntitiesDefault)(int);
#ifdef WIRESHARK_XML_DO_VALIDITY_CHECKING
  int              *xmlDoValidityCheckingDefaultValue;
#endif
} XML_STUB;

XML_EXTERN XML_STUB XmlStub;
XML_EXTERN int XmlStubInitialized;

#ifdef _WIN32
/* We're in windows, use the windows filename */
#define XML_LIBRARY "libxml2.dll"
#else
#define XML_LIBRARY "libxml2.so"
#endif

/*
 * This needs to be called before the library is used.  It
 * returns zero on success.  Any non-zero return means that
 * either dynamic libraries are not supported, or that libxml
 * is not installed on the current system.  (Or it's not in
 * the LD path)
 */
int loadLibXML(void);



