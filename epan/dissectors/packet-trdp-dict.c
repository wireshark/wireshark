/* packet-trdp-dict.c
 * Routines for trdp packet dissection, parser for IEC 61375-3-2 XML description
 *
 * Copyright Bombardier Transportation Inc. or its subsidiaries and others, 2013. Florian Weispfenning
 * Copyright Universität Rostock, 2019 (substantial changes leading to GLib-only version). Thorsten Schulz
 * Copyright Stadler Deutschland GmbH, 2022-2025. Thorsten Schulz
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*******************************************************************************
 * INCLUDES
 */
#include <string.h>
#include "packet-trdp-dict.h"
//#include <errno.h>

/* Taken from glibc 2.6.1 */
static char* ws_strsep(char** stringp, const char* delim)
{
    char* begin, * end;

    begin = *stringp;
    if (begin == NULL)
        return NULL;

    /* A frequent case is when the delimiter string contains only one
       character.  Here we don't need to call the expensive `strpbrk'
       function and instead work using `strchr'.  */
    if (delim[0] == '\0' || delim[1] == '\0')
    {
        char ch = delim[0];

        if (ch == '\0')
            end = NULL;
        else
        {
            if (*begin == ch)
                end = begin;
            else if (*begin == '\0')
                end = NULL;
            else
                end = strchr(begin + 1, ch);
        }
    } else
        /* Find the end of the token.  */
        end = strpbrk(begin, delim);

    if (end)
    {
        /* Terminate the token and set *STRINGP past NUL character.  */
        *end++ = '\0';
        *stringp = end;
    } else
        /* No more delimiters; this is the last token.  */
        *stringp = NULL;

    return begin;
}

/* this is a construct, to point empty strings (name, unit, ...) to this const
 * instead of NULL, so readers don't have to catch for NULL - though w/o
 * wasting needless heap allocations.
 */
const char* const SEMPTY = "";

#define FALLBACK(a,b) ((a)?(a):(b))

/*******************************************************************************
 * DEFINES
 */

#define TAG_BIT "bit"
#define TAG_ELEMENT "element"
#define TAG_DATA_SET "data-set"
#define TAG_TELEGRAM "telegram"

#define ATTR_DATA_SET_ID "data-set-id"
#define ATTR_COM_ID "com-id"
#define ATTR_NAME "name"
#define ATTR_TYPE "type"
#define ATTR_ARRAYSIZE "array-size"

#define ATTR_DATASET_ID "id"
#define ATTR_DATASET_NAME "name"
#define ATTR_UNIT "unit"
#define ATTR_SCALE "scale"
#define ATTR_OFFSET "offset"
#define ATTR_BITS "bits"
#define ATTR_POSITION "position"

#define ATTR_COMPAR "com-parameter-id"
#define ATTR_CREATE "create"

#define FILE_SUFFIX_LOWCASE ".xml"
#define FILE_SUFFIX_UPCASE ".XML"


/*******************************************************************************
 * some Definitions for "early" use internal functions
 * actually, this triple calls each other after XML parsing to check and build
 * the whole dict-tree
 */

static int32_t ComId_preCalculate(ComId* self, TrdpDict* dict);
static int32_t Dataset_preCalculate(Dataset* self, TrdpDict* dict, Dataset** hierarchyStack, size_t depth);
static bool Element_checkConsistency(Element* self, TrdpDict* dict, Dataset** hierarchyStack, size_t depth);
static void Element_add_bit(Element* self, const char* name, const char* _position, int32_t position, GError** err);

static Element* Element_new(const char* _type, const char* _name, const char* _unit, const char* _array_size,
                            const char* _scale, const char* _offset, const char* _bitnames,
                            unsigned int cnt, uint32_t def_bitset_subtype, uint32_t def_endian_subtype, GError** error);
static Dataset* Dataset_new(const char* dsId, const char* aname, const char* filename, GError** error);
static ComId* ComId_new(const char* id, const char* aname, const char* dsId, const char* filename, GError** error);

static bool Element_equals(const Element* self, const Element* other, GError** error);
static bool Dataset_equals(const Dataset* self, const Dataset* other, GError** error);
static bool ComId_equals(const ComId* self, const ComId* other, GError** error);

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
    { "BITSET8", TRDP_BITSET8, TRDP_BITSUBTYPE_BITSET8 },
    { "BOOL8", TRDP_BITSET8, TRDP_BITSUBTYPE_BOOL8 },
    { "ANTIVALENT8", TRDP_BITSET8, TRDP_BITSUBTYPE_ANTIVALENT8 },
    { "CHAR8", TRDP_CHAR8, 0 },
    { "UTF16", TRDP_UTF16, 0 },
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
    { "SC32", TRDP_SC32, 0 },
    { "UUID", TRDP_UUID, 0 },
};

static ElementType decodeType(const char* type, uint32_t bitmap_subtype, uint32_t endian_subtype)
{
    ElementType numeric;
    numeric.id = (uint32_t)g_ascii_strtoull(type, NULL, 10);
    if (!numeric.id) {
        for (gsize i = 0; i < array_length(ElBasics); i++)
            if (strcmp(type, ElBasics[i].name) == 0) {
                return ElBasics[i];
            }
    }
    bool isNumber = (numeric.id >= TRDP_INT8) && (numeric.id <= TRDP_REAL64);
    numeric.subtype = (numeric.id == TRDP_BITSET8) ? bitmap_subtype : (isNumber ? endian_subtype : 0);
    memccpy(numeric.name, type, 0, sizeof(numeric.name));
    return numeric;
}

static void encodeBasicType(ElementType* elt)
{
    for (unsigned int i = 0; elt && i < array_length(ElBasics); i++) {
        if (elt->id == ElBasics[i].id && elt->subtype == ElBasics[i].subtype) {
            memccpy(elt->name, ElBasics[i].name, 0, sizeof(elt->name)); /* there are only NULL-terminated strings in ElBasics */
            break;
        }
    }
}

/*******************************************************************************
 * GMarkupParser Implementation
 */

/* checkHierarchy
 * Assert the required XML hierarchy in a hard-coded way.
 * See trdp-config.xsd for more information.
 */

static int Markup_checkHierarchy(GMarkupParseContext* context, const char* element_name,
    GError** error)
{

    int tagtype = -1;
    /* check tree */
    const GSList* tagtree = g_markup_parse_context_get_element_stack(context);
    if (0 == g_ascii_strcasecmp((const char*)tagtree->data, TAG_TELEGRAM)) {
        tagtree = tagtree->next;
        if (tagtree && tagtree->next && tagtree->next->next && 0 == g_ascii_strcasecmp((const char*)tagtree->data, "bus-interface") && 0 == g_ascii_strcasecmp((const char*)tagtree->next->data, "bus-interface-list") && 0 == g_ascii_strcasecmp((const char*)tagtree->next->next->data, "device"))
            tagtype = 1;

    } else if (0 == g_ascii_strcasecmp((const char*)tagtree->data, TAG_DATA_SET)) {
        tagtree = tagtree->next;
        if (tagtree && tagtree->next && 0 == g_ascii_strcasecmp((const char*)tagtree->data, "data-set-list") && 0 == g_ascii_strcasecmp((const char*)tagtree->next->data, "device"))
            tagtype = 2;

    } else if (0 == g_ascii_strcasecmp((const char*)tagtree->data, TAG_ELEMENT)) {
        tagtree = tagtree->next;
        if (tagtree && tagtree->next && tagtree->next->next && 0 == g_ascii_strcasecmp((const char*)tagtree->data, TAG_DATA_SET) && 0 == g_ascii_strcasecmp((const char*)tagtree->next->data, "data-set-list") && 0 == g_ascii_strcasecmp((const char*)tagtree->next->next->data, "device"))
            tagtype = 3;

    } else if (0 == g_ascii_strcasecmp((const char*)tagtree->data, "device")) {
        if (!tagtree->next)
            tagtype = 4;

    } else if (0 == g_ascii_strcasecmp((const char*)tagtree->data, TAG_BIT)) {
        tagtree = tagtree->next;
        if (tagtree && tagtree->next && tagtree->next->next && tagtree->next->next->next && 0 == g_ascii_strcasecmp((const char*)tagtree->data, TAG_ELEMENT) && 0 == g_ascii_strcasecmp((const char*)tagtree->next->data, TAG_DATA_SET) && 0 == g_ascii_strcasecmp((const char*)tagtree->next->next->data, "data-set-list") && 0 == g_ascii_strcasecmp((const char*)tagtree->next->next->next->data, "device"))
            tagtype = 5;

    } else
        tagtype = 0; /* ignore other */

    if (tagtype == -1)
        g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_UNKNOWN_ELEMENT, // error code
            "Broken XML hierarchy tree for tag: <%s>.", element_name);

    return tagtype;
}

static void Markup_start_element(GMarkupParseContext* context, const char* element_name,
    const char** attribute_names, const char** attribute_values,
    gpointer user_data, GError** error)
{

    static unsigned int element_cnt = 0;
    GError* err = NULL;
    TrdpDict* self = (TrdpDict*)user_data;

    /* check tree */
    int tagtype = Markup_checkHierarchy(context, element_name, &err);
    if (err) {
        g_propagate_error(error, err); /* only if one happened */
        return;
    }

    /* Found a new comId, add that to the hash map */
    if (tagtype == 1) {
        const char *name, *id, *ds_id;

        g_markup_collect_attributes(element_name, attribute_names, attribute_values, &err,
            G_MARKUP_COLLECT_STRING, ATTR_COM_ID, &id, /* u32 */
            G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, ATTR_DATA_SET_ID, &ds_id, /* u32 */
            G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, ATTR_NAME, &name, /* may-len=30 */
            G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, ATTR_COMPAR, NULL, /* u32 */
            G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, ATTR_TYPE, NULL, /* "sink", "source", "source-sink" */
            G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, ATTR_CREATE, NULL, /* "on" / "off" */
            G_MARKUP_COLLECT_INVALID);

        if (!err) {
            ComId* com = ComId_new(id, name, ds_id, self->currentFile, &err);
            if (com) {
                ComId* com2 = (ComId*)TrdpDict_lookup_ComId(self, com->comId);
                if (!com2) {
                    com->next = self->mTableComId;
                    self->mTableComId = com;
                    self->knowledge++;
                } else {
                    if (!ComId_equals(com2, com, &err)) {
                        g_propagate_error(error, err);
                    }
                    com2->duplicates++;
                    ComId_delete(com);
                }
            } else
                g_propagate_error(error, err);

        } else
            g_propagate_error(error, err);

    } else if (tagtype == 2) {
        const char *name, *id;

        g_markup_collect_attributes(element_name, attribute_names, attribute_values, &err,
            G_MARKUP_COLLECT_STRING, ATTR_DATASET_ID, &id, /* u32 */
            G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, ATTR_NAME, &name, /* may-len=30 */
            G_MARKUP_COLLECT_INVALID);
        if (!err) {
            Dataset* ds = Dataset_new(id, name, self->isShippedXml ? NULL : self->currentFile, &err);
            if (ds) {
                ds->next = self->mTableDataset;
                self->mTableDataset = ds;
                self->datasets++;
                element_cnt = 0;
                /* we need to duplicate-check at the end */
            } else
                g_propagate_error(error, err);

        } else
            g_propagate_error(error, err);
    } else if (tagtype == 3) {
        if (self->mTableDataset) {
            const char *name, *type, *array_size, *unit, *scale, *offset, *bitnames;

            g_markup_collect_attributes(element_name, attribute_names, attribute_values, &err,
                G_MARKUP_COLLECT_STRING, ATTR_TYPE, &type, /* name30, u32 */
                G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, ATTR_NAME, &name, /* may-len=30 */
                G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, ATTR_ARRAYSIZE, &array_size, /* u32 */
                G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, ATTR_UNIT, &unit, /* string */
                G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, ATTR_SCALE, &scale, /* float */
                G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, ATTR_OFFSET, &offset, /* i32 */
                G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, ATTR_BITS, &bitnames, /* string */
                G_MARKUP_COLLECT_INVALID);

            if (!err) {
                Element* el = Element_new(type, name, unit, array_size, scale, offset, bitnames, ++element_cnt, self->def_bitset_subtype, self->def_endian_subtype, &err);
                if (el) {
                    /* update the element in the list */
                    if (!self->mTableDataset->listOfElements)
                        self->mTableDataset->listOfElements = el;
                    else
                        self->mTableDataset->lastOfElements->next = el;
                    self->mTableDataset->lastOfElements = el;
                } else
                    g_propagate_error(error, err);

            } else
                g_propagate_error(error, err);
        }
    } else if (tagtype == 5) {
        if (self->mTableDataset) {
            const char *name, *position;

            g_markup_collect_attributes(element_name, attribute_names, attribute_values, &err,
                G_MARKUP_COLLECT_STRING, ATTR_NAME, &name, /* may-len=30 */
                G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, ATTR_POSITION, &position, /* u32 */
                G_MARKUP_COLLECT_INVALID);

            if (!err)
                Element_add_bit(self->mTableDataset->lastOfElements, name, position, -1, &err);
            if (err)
                g_propagate_error(error, err);
        }
    }
}

static void Markup_end_element(GMarkupParseContext* context, const char* element_name,
    gpointer user_data, GError** error)
{

    GError* err = NULL;
    TrdpDict* self = (TrdpDict*)user_data;
    /* identify structure issues. Maybe already handled by GMarkup itself */
    int tagtype = Markup_checkHierarchy(context, element_name, error);

    if (tagtype == 2) {
        Dataset* newest = self->mTableDataset;
        self->mTableDataset = newest->next; /* unqueue the newest Dataset for a sec */
        Dataset* preExists = TrdpDict_get_Dataset(self, newest->datasetId);
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

GMarkupParser parser = {
    .start_element = Markup_start_element,
    .end_element = Markup_end_element,
};

/*******************************************************************************
 * TrdpDict functions
 * holds boths lists (telegrams and datasets) and takes care of parsing and
 * cleanup.
 */

static void TrdpDict_parseXML(TrdpDict* self, const char* contents, gsize len, GError** error )
{
    GError* err = NULL;
    GMarkupParseContext* xml = g_markup_parse_context_new(&parser, G_MARKUP_PREFIX_ERROR_POSITION, self, NULL);

    if (!g_markup_parse_context_parse(xml, contents, len, &err)) {
        g_propagate_prefixed_error(error, err, "Parsing failed.\n");
        self->knowledge = 0; /* it's dubious knowledge, better get rid of it it */
    } else if (!g_markup_parse_context_end_parse(xml, &err)) {
        g_propagate_prefixed_error(error, err, "Configuration was incomplete.\n");
        self->knowledge = 0;
    }
    g_markup_parse_context_free(xml);
}

static bool TrdpDict_check(TrdpDict* self, const char* baseXmlConfig, const char* customXmlConfig, GError** error)
{
    ComId* com;

    if (!self->knowledge) {
        if (baseXmlConfig && customXmlConfig && *customXmlConfig)
            g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_MISSING_ATTRIBUTE,
                    "%s parsed ok, but did not provide any ComId.", customXmlConfig);
    } else {

        for( com = self->mTableComId; com; com=com->next) {
            if (ComId_preCalculate(com, self) < 0) break; /* oops, logical inconsistency */
        }

        /* catch some parse faults and turn them into error messages */
        if (self->mCyclicDataset) {
            g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, // error code
                        "Checks detected a cyclic recursion of datasets. Check references of %d (%s)", self->mCyclicDataset->datasetId, self->mCyclicDataset->name);
            self->knowledge = 0;
        } else if (self->maxDatasetDepth > TRDP_MAX_DATASET_RECURSION) {
            g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, // error code
                        "Final dictionary violates the max level (%d) of dataset hierarchies.", TRDP_MAX_DATASET_RECURSION);
            self->knowledge = 0;
        } else if (com) {
            g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, // error code
                        "Lastly \"%s\" parsed ok and found %d ComIDs. However, dataset-ID %d FAILED to compute.", customXmlConfig, self->knowledge, com->comId);
            self->knowledge = 0;
        }
    }

    return !!self->knowledge;
}

TrdpDict* TrdpDict_new(const char* baseXmlConfig, const char* customXmlConfig, uint32_t bitset_subtype, uint32_t endian_subtype, GError** error)
{
    GError* err = NULL;
    bool isShippedXml = !!baseXmlConfig;
    const char* xmlConfig = isShippedXml ? baseXmlConfig : customXmlConfig;
    TrdpDict* self = g_new0(TrdpDict, 1);
    self->def_bitset_subtype = bitset_subtype;
    self->def_endian_subtype = endian_subtype;

    while (xmlConfig && *xmlConfig) {
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
            currentPath = g_strdup_printf("%s"G_DIR_SEPARATOR_S"%s", dirname, potentialNextFile);
            self->currentFile = currentPath;
            self->isShippedXml = isShippedXml;

            if (dir && (!g_str_has_suffix(currentPath, FILE_SUFFIX_LOWCASE) && !g_str_has_suffix(currentPath, FILE_SUFFIX_UPCASE))) {

            } else {
                GMappedFile* gmf = g_mapped_file_new(currentPath, FALSE, &err);
                if (err) {
                    g_propagate_prefixed_error(error, err, "XML reading failed.\n");

                } else {
                    TrdpDict_parseXML(self,
                                      g_mapped_file_get_contents(gmf),
                                      g_mapped_file_get_length(gmf),
                                      &err);
                    if (err)
                        g_propagate_prefixed_error(error, err, "XML Source %s:\n", isShippedXml ? currentPath : potentialNextFile);

                    g_mapped_file_unref(gmf);
                }
            }
            g_free(currentPath);
            potentialNextFile = dir ? g_dir_read_name(dir) : NULL;
        }
        g_free(dirname);
        if (dir) g_dir_close(dir);
        xmlConfig = isShippedXml ? customXmlConfig : NULL;
        isShippedXml = FALSE; /* switch the flag to signal using the custom xml */
    }

    /* If init was unsuccessful, clean up the whole thing */
    if (!TrdpDict_check(self, baseXmlConfig, customXmlConfig, &err)) {
        if (err) g_propagate_error(error, err);
        TrdpDict_delete(self, -1);
        self = NULL;
    }
    return self;
}

void TrdpDict_delete(TrdpDict* self, int parent_id)
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
        g_free(self);
    }
}

const ComId* TrdpDict_lookup_ComId(const TrdpDict* self, uint32_t comId)
{
    if (self)
        for (ComId* com = self->mTableComId; com; com = com->next)
            if (com->comId == comId)
                return com;

    return NULL;
}

const char* TrdpDict_lookup_ComId_Name(const TrdpDict* self, uint32_t comId)
{
    const ComId* com = TrdpDict_lookup_ComId(self, comId);
    return com ? com->name : NULL;
}

Dataset* TrdpDict_get_Dataset(const TrdpDict* self, uint32_t datasetId)
{
    if (self)
        for (Dataset* ds = self->mTableDataset; ds; ds = ds->next)
            if (ds->datasetId == datasetId)
                return ds;
    return NULL;
}

/************************************************************************************
 *                          ELEMENT
 ************************************************************************************/

static void Element_stringifyType(Element* self, const char* _typeName)
{
    if (!self)
        return;
    if (self->type.id <= TRDP_STANDARDTYPE_MAX) {
        encodeBasicType(&self->type);
    } else if (self->linkedDS) {
        if (*self->linkedDS->name)
            memccpy(self->type.name, self->linkedDS->name, 0, sizeof(self->type.name));
        else
            snprintf(self->type.name, sizeof(self->type.name), "%d", self->linkedDS->datasetId);
    } else {
        if (_typeName)
            memccpy(self->type.name, _typeName, 0, sizeof(self->type.name));
    }
}

// NOLINTNEXTLINE(misc-no-recursion) -- recursion depth guard in place
static bool Element_checkConsistency(Element* self, TrdpDict* dict, Dataset** hierarchyStack, size_t depth)
{
    if (!self || !dict || !hierarchyStack || depth > TRDP_MAX_DATASET_RECURSION)
        return FALSE;

    if (self->type.id > TRDP_STANDARDTYPE_MAX) {

        if (!self->linkedDS) {
            self->linkedDS = TrdpDict_get_Dataset(dict, self->type.id);
            Element_stringifyType(self, NULL);
        }

        /* check, if the referenced dataset already occurs in the call chain, if so, stop and whack the user later. */
        for(size_t i=0; i<depth; i++) {
            if (hierarchyStack[i] && self->type.id == hierarchyStack[i]->datasetId) {
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
    unsigned int cnt, uint32_t def_bitset_subtype, uint32_t def_endian_subtype, GError** error)
{

    gdouble scale;
    int32_t offset;
    int32_t array_size;
    ElementType type;
    char* endptr = NULL;
    errno = 0;
    array_size = _array_size ? (int32_t)g_ascii_strtoull(_array_size, &endptr, 10) : 1;
    if (errno) {
        g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, // error code
            ATTR_ARRAYSIZE "=\"%s\" What is this? <" TAG_ELEMENT ">'s attribute was unparsible. (%s)", endptr, g_strerror(errno));
        return NULL;
    }
    offset = _offset ? (int32_t)g_ascii_strtoll(_offset, &endptr, 10) : 0;
    if (errno) {
        g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, // error code
            ATTR_OFFSET "=\"%s\" What is this? <" TAG_ELEMENT ">'s attribute was unparsible. (%s)", endptr, g_strerror(errno));
        return NULL;
    }
    scale = _scale ? g_ascii_strtod(_scale, &endptr) : 0;
    if (errno) {
        g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, // error code
            ATTR_SCALE "=\"%s\" What is this? <" TAG_ELEMENT ">'s attribute was unparsible. (%s)", endptr, g_strerror(errno));
        return NULL;
    }
    type = decodeType(_type, def_bitset_subtype, def_endian_subtype);
    if (!type.id) {
        g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, // error code
            ATTR_TYPE "=\"%s\" What is this? <" TAG_ELEMENT ">'s attribute was unparsible.", _type);
        return NULL;
    }

    Element* self = g_new0(Element, 1);
    self->hf_id = -1;
    self->ett_id = -1;
    self->bits_ett_id = -1;
    self->array_size = array_size;
    self->name = _name && *_name ? g_strdup(_name) : g_strdup_printf("%u", cnt); /* in case the name is empty, take a running number */
    self->unit = _unit ? g_strdup(_unit) : (char*)SEMPTY;
    self->scale = scale;
    self->offset = offset;
    self->type = type;

    if (_bitnames) {
        char* orig = g_strdup(_bitnames);
        char* lead = orig;
        char* bitname;
        for (unsigned b = 0; b < TRDP_BITSUBTYPE_BITS && (bitname = ws_strsep(&lead, ",:;")); b++) {
            Element_add_bit(self, bitname, NULL, b, error);
        }
        g_free(orig);
    }

    Element_stringifyType(self, _type);

    self->width = trdp_dissect_width(self->type.id);
    return self;
}

static void Element_add_bit(Element* self, const char* name, const char* _position, int32_t position, GError** error)
{
    char* endptr = NULL;
    if (self && self->type.id == TRDP_BITSET8 && self->type.subtype == TRDP_BITSUBTYPE_BITSET8 && name && *name) {
        if (_position) {
            position = (int32_t)g_ascii_strtoll(_position, &endptr, 10);
            if (errno) {
                g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, // error code
                    ATTR_POSITION "=\"%s\" What is this? <" TAG_BIT ">'s attribute was unparsible. (%s)", endptr, g_strerror(errno));
                return;
            }
        }

        if (position == -1) {
            position = self->bitindex;
        }

        if ((position >= TRDP_BITSUBTYPE_BITS) || (position < 0)) {
            g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, // error code
                ATTR_POSITION "=\"%d\" is out of range - <" TAG_BIT ">'s attribute was unparsible.", position);
            return;
        }

        if (!self->bits) {
            self->bits = g_new0(Bit, TRDP_BITSUBTYPE_BITS);
            self->bitfields = g_new0(int*, TRDP_BITSUBTYPE_BITS + 1);
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
        g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT,
            "Type: %s / %s, Name: %s / %s, Unit: %s / %s, Array: %d / %d, Scale: %f / %f, Offset: %d / %d, Bits: %d / %d\n ",
            self->type.name, other->type.name,
            self->name, other->name,
            self->unit ? self->unit : "nil", other->unit ? other->unit : "nil",
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
        g_free(self->bits);
        g_free(self->bitfields);
        g_free(self->name);
        if (self->unit != SEMPTY)
            g_free(self->unit);
        g_free(self);
    }
}

int32_t TrdpDict_element_size(const Element* self, uint32_t array_size /* = 1*/)
{
    return self ? (self->width * (self->array_size ? self->array_size : (int)array_size)) : -1;
}

/************************************************************************************
 *                          DATASET
 ************************************************************************************/

static Dataset* Dataset_new(const char* _id, const char* _name, const char* filename, GError** error)
{
    /* check params */
    char* endptr;
    errno = 0;
    uint32_t id;
    id = (uint32_t)g_ascii_strtoull(_id, &endptr, 10);
    if (errno) {
        g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, // error code
            ATTR_DATASET_ID "=\"%s\" What is this? <" TAG_DATA_SET ">'s attribute was unparsible (%s).", endptr, g_strerror(errno));
        return NULL;
    }
    Dataset* self = g_new0(Dataset, 1);
    self->datasetId = id;
    self->ett_id = -1;
    self->duplicates = 0;
    self->name = g_strdup((_name && *_name) ? _name : _id);
    self->source = g_strdup(filename);
    return self;
}

static bool Dataset_equals(const Dataset* self, const Dataset* other, GError** error)
{
    if (self == other)
        return TRUE;

    if (self->datasetId != other->datasetId)
        return FALSE;

    GError* err = NULL;
    if (!g_ascii_strcasecmp(self->name, other->name)) {
        Element* elSelf = self->listOfElements;
        Element* elOther = other->listOfElements;
        while (elSelf && elOther && Element_equals(elSelf, elOther, error ? &err : NULL)) {
            elSelf = elSelf->next;
            elOther = elOther->next;
        }
        if (error && err)
            g_propagate_prefixed_error(error, err,
                "Dataset %d differs between \"%s\" and \"%s\" error-causing element: ",
                self->datasetId, FALLBACK(self->source,"baked-in XML"), FALLBACK(other->source,"baked-in XML"));
        return (!elSelf && !elOther);
    } else {
        g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT,
            "Dataset %d differ between \"%s\" and \"%s\" in name: %s / %s",
            self->datasetId, FALLBACK(self->source,"baked-in XML"), FALLBACK(other->source,"baked-in XML"), self->name, other->name);
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
    while (self->listOfElements) {
        Element* el = self->listOfElements;
        self->listOfElements = self->listOfElements->next;
        if (parent_id > -1 && el->hf_id > -1) {
            /* not really clean, to call Wireshark from here-in. I think, GLib offers
             * the Destroy-Notifier methodology for this case. Future ...
             */
            proto_deregister_field(parent_id, el->hf_id);
        }
        /* no idea how to clean up subtree handler el->ett_id */
        Element_delete(el);
    }
    g_free(self->source);
    g_free(self->name);
    g_free(self);
}

/************************************************************************************
 *                          COMID
 ************************************************************************************/

static void ComId_delete(ComId* self)
{
    if (self->name && self->name != SEMPTY)
        g_free(self->name);
    g_free(self->source);
    g_free(self);
}

static ComId* ComId_new(const char* _id, const char* aname, const char* _dsId, const char* file, GError** error)
{
    /* check params */
    char* endptr;
    errno = 0;
    uint32_t id, dsId;
    id = (uint32_t)g_ascii_strtoull(_id, &endptr, 10);
    if (errno) {
        g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, // error code
            ATTR_COM_ID "=\"%s\" What is this? <" TAG_TELEGRAM ">'s attribute was unparsible. (%s)", endptr, g_strerror(errno));
        return NULL;
    }
    /* only consider non-empty dataset references */
    if (_dsId && *_dsId) {
        dsId = (uint32_t)g_ascii_strtoull(_dsId, &endptr, 10);
        if (errno) {
            g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, // error code
                ATTR_DATA_SET_ID "=\"%s\" What is this? <" TAG_TELEGRAM ">'s attribute was unparsible. (%s)", endptr, g_strerror(errno));
            return NULL;
        }
    } else
        dsId = 0;

    if (!(aname && *aname) && !dsId) {
        g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, // error code
            ATTR_COM_ID "=\"%s\" provides no definition. Neither name nor data-set is given. Please check.", _id);
        return NULL;
    }

    ComId* self = g_new0(ComId, 1);
    self->comId = id;
    self->dataset = dsId;
    self->ett_id = -1;
    self->name = aname ? g_strdup(aname) : (char*)SEMPTY; /* TODO check length */
    self->source = g_strdup(file);
    return self;
}

static bool ComId_equals(const ComId* self, const ComId* other, GError** error)
{
    /* the good thing is, we don't really care about sub-tag such as source/sink/com-parameters. */
    /* Name should be ignored */
    bool eq = (self == other || (self->comId == other->comId && self->dataset == other->dataset));
    if (!eq) {
        g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT,
            "ComId %d differ in Dataset-ID %d / %d. Check \"%s\" against \"%s\".",
            self->comId, self->dataset, other->dataset, self->source, other->source);
    }
    return eq;
}

/* Tries to get the size for the comId-related DS. Will only work, if all DS are non-variable. */
/**< must only be called after full config initialization */
static int32_t ComId_preCalculate(ComId* self, TrdpDict* dict)
{
    if (!dict)
        self->size = -1;
    else {
        if (!self->linkedDS)
            self->linkedDS = TrdpDict_get_Dataset(dict, self->dataset);
        /* setup the dataset-call-stack to detect cyclic dependcies */
        Dataset* hierarchyStack[TRDP_MAX_DATASET_RECURSION] = {NULL, };
        /* this is ok to use, because the root dataset is not an element, thus cannot be an array */
        self->size = self->linkedDS ? Dataset_preCalculate(self->linkedDS, dict, hierarchyStack, 0) : 0;
    }
    return self->size;
}
