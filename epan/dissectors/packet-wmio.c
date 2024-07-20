/* packet-wmio.c
 * Wireshark's WMIO dissector.
 *
 * Copyright 2024, Hiddencodes Sec <hidd3ncod3s[]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-dcerpc.h"
#include <packet-dcom.h>

void proto_register_WMIO (void);
void proto_reg_handoff_WMIO (void);

static int proto_WMIO;

/*  IWbemClassObject Interface
 *    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/46710c5c-d7ab-4e4c-b4a5-ebff311fdcd1
 *    dc12a681-737f-11cf-884d-00aa004b2e24
 */
static e_guid_t iid_WMIO = { 0xdc12a681, 0x737f, 0x11cf, { 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24} };

static uint32_t wmio_signature = 0x12345678;

#define CLASS_HEADER_LENGTH 13

#define WMIO_OBJECT_FLAG_CIM_CLASS               0X01
#define WMIO_OBJECT_FLAG_CIM_INSTANCE            0X02
#define WMIO_OBJECT_FLAG_HAS_DECORATION          0X04
#define WMIO_OBJECT_FLAG_PROTOTYPE_RESULT_OBJECT 0X10
#define WMIO_OBJECT_FLAG_KEY_PROPERTY_MISSING    0X40

#define WBEM_FLAVOR_FLAG_PROPAGATE_TO_INSTANCE      0x01
#define WBEM_FLAVOR_FLAG_PROPAGATE_TO_DERIVED_CLASS 0x02
#define WBEM_FLAVOR_NOT_OVERRIDABLE                 0x10
#define WBEM_FLAVOR_ORIGIN_PROPAGATED               0x20
#define WBEM_FLAVOR_ORIGIN_SYSTEM                   0x40
#define WBEM_FLAVOR_AMENDED                         0x80

#define CIM_ARRAY_FLAG 0x2000
#define INHERITED_PROPERTY_TYPE 0x4000

/* CimType
 *   https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/e137e6c6-c1cc-449e-a0b4-76fabf534480
 *   CimType is a 32-bit value of which only the lower 16 bits are used.
 */
#define CIM_TYPE_SINT16    2
#define CIM_TYPE_SINT32    3
#define CIM_TYPE_REAL32    4
#define CIM_TYPE_REAL64    5
#define CIM_TYPE_STRING    8
#define CIM_TYPE_BOOLEAN   11
#define CIM_TYPE_OBJECT    13
#define CIM_TYPE_SINT8     16
#define CIM_TYPE_UINT8     17
#define CIM_TYPE_UINT16    18
#define CIM_TYPE_UINT32    19
#define CIM_TYPE_SINT64    20
#define CIM_TYPE_UINT64    21
#define CIM_TYPE_DATETIME  101
#define CIM_TYPE_REFERENCE 102
#define CIM_TYPE_CHAR16    103

#define CIM_ARRAY_TYPE(X) (CIM_ARRAY_FLAG | X)

#define CIM_ARRAY_SINT8     CIM_ARRAY_TYPE(CIM_TYPE_SINT8)
#define CIM_ARRAY_UINT8     CIM_ARRAY_TYPE(CIM_TYPE_UINT8)
#define CIM_ARRAY_SINT16    CIM_ARRAY_TYPE(CIM_TYPE_SINT16)
#define CIM_ARRAY_UINT16    CIM_ARRAY_TYPE(CIM_TYPE_UINT16)
#define CIM_ARRAY_SINT32    CIM_ARRAY_TYPE(CIM_TYPE_SINT32)
#define CIM_ARRAY_UINT32    CIM_ARRAY_TYPE(CIM_TYPE_UINT32)
#define CIM_ARRAY_SINT64    CIM_ARRAY_TYPE(CIM_TYPE_SINT64)
#define CIM_ARRAY_UINT64    CIM_ARRAY_TYPE(CIM_TYPE_UINT64)
#define CIM_ARRAY_REAL32    CIM_ARRAY_TYPE(CIM_TYPE_REAL32)
#define CIM_ARRAY_REAL64    CIM_ARRAY_TYPE(CIM_TYPE_REAL64)
#define CIM_ARRAY_BOOLEAN   CIM_ARRAY_TYPE(CIM_TYPE_BOOLEAN)
#define CIM_ARRAY_STRING    CIM_ARRAY_TYPE(CIM_TYPE_STRING)
#define CIM_ARRAY_DATETIME  CIM_ARRAY_TYPE(CIM_TYPE_DATETIME)
#define CIM_ARRAY_REFERENCE CIM_ARRAY_TYPE(CIM_TYPE_REFERENCE)
#define CIM_ARRAY_CHAR16    CIM_ARRAY_TYPE(CIM_TYPE_CHAR16)
#define CIM_ARRAY_OBJECT    CIM_ARRAY_TYPE(CIM_TYPE_OBJECT)

#define STRINGFY(X) { X, #X}

static const value_string cim_types[] = {
  STRINGFY(CIM_TYPE_SINT8),
  STRINGFY(CIM_TYPE_UINT8),
  STRINGFY(CIM_TYPE_SINT16),
  STRINGFY(CIM_TYPE_UINT16),
  STRINGFY(CIM_TYPE_SINT32),
  STRINGFY(CIM_TYPE_UINT32),
  STRINGFY(CIM_TYPE_SINT64),
  STRINGFY(CIM_TYPE_UINT64),
  STRINGFY(CIM_TYPE_REAL32),
  STRINGFY(CIM_TYPE_REAL64),
  STRINGFY(CIM_TYPE_BOOLEAN),
  STRINGFY(CIM_TYPE_STRING),
  STRINGFY(CIM_TYPE_DATETIME),
  STRINGFY(CIM_TYPE_REFERENCE),
  STRINGFY(CIM_TYPE_CHAR16),
  STRINGFY(CIM_TYPE_OBJECT),
  STRINGFY(CIM_ARRAY_SINT8),
  STRINGFY(CIM_ARRAY_UINT8),
  STRINGFY(CIM_ARRAY_SINT16),
  STRINGFY(CIM_ARRAY_UINT16),
  STRINGFY(CIM_ARRAY_SINT32),
  STRINGFY(CIM_ARRAY_UINT32),
  STRINGFY(CIM_ARRAY_SINT64),
  STRINGFY(CIM_ARRAY_UINT64),
  STRINGFY(CIM_ARRAY_REAL32),
  STRINGFY(CIM_ARRAY_REAL64),
  STRINGFY(CIM_ARRAY_BOOLEAN),
  STRINGFY(CIM_ARRAY_STRING),
  STRINGFY(CIM_ARRAY_DATETIME),
  STRINGFY(CIM_ARRAY_REFERENCE),
  STRINGFY(CIM_ARRAY_CHAR16),
  STRINGFY(CIM_ARRAY_OBJECT),
  { 0,  NULL } };

static int hf_wmio;
static int hf_wmio_signature;
static int hf_wmio_objectencodinglength;
static int hf_wmio_object_flags;
static int hf_wmio_object_flags_cim_class;
static int hf_wmio_object_flags_cim_instance;
static int hf_wmio_object_flags_has_decoration;
static int hf_wmio_object_flags_prototype_result_object;
static int hf_wmio_object_flags_key_property_missing;
static int hf_wmio_decoration;
static int hf_wmio_decoration_server_name;
static int hf_wmio_decoration_namespace;
static int hf_wmio_encoded_string;
static int hf_wmio_encoded_string_flags;
static int hf_wmio_encoded_string_flags_unicode;
static int hf_wmio_class_part;
static int hf_wmio_class_header;
static int hf_wmio_class_header_partlength;
static int hf_wmio_class_header_nameref;
static int hf_wmio_class_header_ndtablevaluetablelength;
static int hf_wmio_class_derivation;
static int hf_wmio_class_derivation_length;
static int hf_wmio_derivation_classname;
static int hf_wmio_class_name_length;
static int hf_wmio_qualifierset;
static int hf_wmio_qualifierset_length;
static int hf_wmio_qualifier;
static int hf_wmio_qualifiername;
static int hf_wmio_cimtype;
static int hf_wmio_qualifiervalue;
static int hf_wmio_bytes;
static int hf_wmio_flavor;
static int hf_wmio_flavor_propagate_to_instance;
static int hf_wmio_flavor_propagate_to_derived_class;
static int hf_wmio_flavor_not_overridable;
static int hf_wmio_flavor_origin_propagated;
static int hf_wmio_flavor_origin_system;
static int hf_wmio_flavor_amended;
static int hf_wmio_propertylookuptable;
static int hf_wmio_propertylookuptable_count;
static int hf_wmio_propertylookup;
static int hf_wmio_propertynameref;
static int hf_wmio_propertyinforef;
static int hf_wmio_ndtable;
static int hf_wmio_heap;
static int hf_wmio_heap_length;
static int hf_methodspart;
static int hf_methodspart_length;
static int hf_methodspart_methodcount;
static int hf_methodspart_methods;
static int hf_methodspart_methoddescription;
static int hf_methoddescription_methodname;
static int hf_methoddescription_methodflags;
static int hf_methoddescription_methodqualifiers;
static int hf_parentclass;
static int hf_currentclass;
static int hf_methoddescription_methodorigin;
static int hf_methoddescription_inputsignature;
static int hf_methoddescription_outputsignature;
static int hf_heap_offset;
static int hf_property_info;
static int hf_declaration_order;
static int hf_propertyinfo_inherited;
static int hf_propertyinfo_valuetableoffset;
static int hf_propertyinfo_classoforigin;
static int hf_methodsignature_offset;

static hf_register_info hf[] = {
    { &hf_wmio,
    { "WMIO", "wmio", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_signature,
    { "Signature", "wmio.signature", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_objectencodinglength,
    { "Object Encoding Length", "wmio.objectencodinglength", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_object_flags,
    { "Object flags", "wmio.objectflags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_object_flags_cim_class,
    { "CIM Class", "wmio.objectflags.cim_class", FT_BOOLEAN, 8, NULL, WMIO_OBJECT_FLAG_CIM_CLASS, NULL, HFILL }},
    { &hf_wmio_object_flags_cim_instance,
    { "CIM Instance", "wmio.objectflags.cim_Instance", FT_BOOLEAN, 8, NULL, WMIO_OBJECT_FLAG_CIM_INSTANCE, NULL, HFILL }},
    { &hf_wmio_object_flags_has_decoration,
    { "Has Decoration", "wmio.objectflags.has_decoration", FT_BOOLEAN, 8, NULL, WMIO_OBJECT_FLAG_HAS_DECORATION, NULL, HFILL }},
    { &hf_wmio_object_flags_prototype_result_object,
    { "Prototype Result Object", "wmio.objectflags.prototype_result_object", FT_BOOLEAN, 8, NULL, WMIO_OBJECT_FLAG_PROTOTYPE_RESULT_OBJECT, NULL, HFILL }},
    { &hf_wmio_object_flags_key_property_missing,
    { "Key Property Missing", "wmio.objectflags.key_property_missing", FT_BOOLEAN, 8, NULL, WMIO_OBJECT_FLAG_KEY_PROPERTY_MISSING, NULL, HFILL }},
    { &hf_wmio_encoded_string,
    { "Encoded String", "wmio.encoded_string", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_encoded_string_flags,
    { "Flag", "wmio.encoded_string.flags", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
    { &hf_wmio_encoded_string_flags_unicode,
    { "Unicode", "wmio.encoded_string.flags.unicode", FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL }},
    { &hf_wmio_decoration,
    { "Decoration", "wmio.decoration", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_decoration_server_name,
    { "CIM Server Name", "wmio.decoration.server_name", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_decoration_namespace,
    { "CIM Namespace", "wmio.decoration.namespace", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_class_part,
    { "Class Part", "wmio.class.part", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_wmio_class_header,
    { "Class Header", "wmio.class.header", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_wmio_class_header_partlength,
    { "Class Header ClassPart Length", "wmio.class.header.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_class_header_nameref,
    { "Class Name Reference", "wmio.class.header.nameref", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_class_header_ndtablevaluetablelength,
    { "NdTable ValueTable Length", "wmio.class.header.ndtablevaluetablelength", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_class_derivation,
    { "Class Derivation", "wmio.class.derivation", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_wmio_class_derivation_length,
    { "Class Derivation Length", "wmio.class.derivation.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_derivation_classname,
    { "Derivation", "wmio.derivation.classname", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_class_name_length,
    { "Class Name Length", "wmio.derivation.classname_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_qualifierset,
    { "Qualifier Set", "wmio.qualifierset", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_qualifierset_length,
    { "Qualifier Length", "wmio.derivation.qualifier_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_qualifier,
    { "Qualifier", "wmio.qualifier", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_qualifiername,
    { "Qualifier Name", "wmio.qualifier_name", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_flavor,
    { "Flavor", "wmio.flavor", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_flavor_propagate_to_instance,
    { "Propagate To Derived Instance", "wmio.flavor.propagate_to_instance", FT_BOOLEAN, 8, NULL, WBEM_FLAVOR_FLAG_PROPAGATE_TO_INSTANCE, NULL, HFILL }},
    { &hf_wmio_flavor_propagate_to_derived_class,
    { "Propagate To Derived Class", "wmio.flavor.propagate_to_derived_class", FT_BOOLEAN, 8, NULL, WBEM_FLAVOR_FLAG_PROPAGATE_TO_DERIVED_CLASS, NULL, HFILL }},
    { &hf_wmio_flavor_not_overridable,
    { "Not Overridable", "wmio.flavor.not_overridable", FT_BOOLEAN, 8, NULL, WBEM_FLAVOR_NOT_OVERRIDABLE, NULL, HFILL }},
    { &hf_wmio_flavor_origin_propagated,
    { "Origin Propagated", "wmio.flavor.origin_propagated", FT_BOOLEAN, 8, NULL, WBEM_FLAVOR_ORIGIN_PROPAGATED, NULL, HFILL }},
    { &hf_wmio_flavor_origin_system,
    { "Origin System", "wmio.flavor.origin_system", FT_BOOLEAN, 8, NULL, WBEM_FLAVOR_ORIGIN_SYSTEM, NULL, HFILL }},
    { &hf_wmio_flavor_amended,
    { "Amended", "wmio.flavor.amended", FT_BOOLEAN, 8, NULL, WBEM_FLAVOR_AMENDED, NULL, HFILL }},
    { &hf_wmio_cimtype,
    { "CIM Type", "wmio.cim_type", FT_UINT32, BASE_HEX, VALS(cim_types), 0, NULL, HFILL }},
    { &hf_wmio_propertylookuptable,
    { "Property Lookup Table", "wmio.property_lookup_table", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_propertylookuptable_count,
    { "Property Lookup Table Count", "wmio.property_lookup_table.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_ndtable,
    { "NdTable", "wmio.ndtable", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_propertylookup,
    { "Property Lookup", "wmio.property_lookup", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_propertynameref,
    { "Property Name Ref", "wmio.property_lookup.propertynameref", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_propertyinforef,
    { "Property Info Ref", "wmio.property_lookup.propertyinforef", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_heap,
    { "Heap", "wmio.heap", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_heap_length,
    { "HeapLength", "wmio.heap.length", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_wmio_bytes,
    { "WMIO Bytes", "wmio.bytes", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_methodspart,
    { "Methodspart", "wmio.methodspart", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_methodspart_length,
    { "Methodspart Length", "wmio.methodspart.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_methodspart_methodcount,
    { "Methods Count", "wmio.methodspart.methodcount", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_methodspart_methods,
    { "Methods", "wmio.methodspart.methods", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_methodspart_methoddescription,
    { "MethodDescription", "wmio.methodspart.methoddescription", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_methoddescription_methodname,
    { "Methodname", "wmio.methodspart.methoddescription.methodname", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_methoddescription_methodflags,
    { "Methodflags", "wmio.methodspart.methoddescription.methodflags", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_methoddescription_methodorigin,
    { "Methodorigin", "wmio.methodspart.methoddescription.methodorigin", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_methoddescription_methodqualifiers,
    { "Methodqualifiers", "wmio.methodspart.methoddescription.methodqualifiers", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_methoddescription_inputsignature,
    { "Inputsignature", "wmio.methodspart.methoddescription.inputsignature", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_methoddescription_outputsignature,
    { "Outputsignature", "wmio.methodspart.methoddescription.outputsignature", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_parentclass,
    { "Parent Class", "wmio.parentclass", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_currentclass,
    { "Current Class", "wmio.currentclass", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_heap_offset,
    { "Heap Offset", "wmio.heapoffset", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_wmio_qualifiervalue,
    { "Qualifier Value", "wmio.qualifier_value", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_property_info,
    { "Property Info", "wmio.property_info", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_declaration_order,
    { "Declaration Order", "wmio.declaration_order", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_propertyinfo_inherited,
    { "Inherited", "wmio.propertytype.inherited", FT_BOOLEAN, 32, NULL, INHERITED_PROPERTY_TYPE, NULL, HFILL }},
    { &hf_propertyinfo_valuetableoffset,
    { "ValueTable Offset", "wmio.propertytype.valuetableoffset", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_propertyinfo_classoforigin,
    { "ClassOfOrigin", "wmio.propertytype.classoforigin", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_methodsignature_offset,
    { "Methodsignature Offset", "wmio.methodsignature.offset", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
};

static int * const wmio_object_flags[] = {
    &hf_wmio_object_flags_cim_class,
    &hf_wmio_object_flags_cim_instance,
    &hf_wmio_object_flags_has_decoration,
    &hf_wmio_object_flags_prototype_result_object,
    &hf_wmio_object_flags_key_property_missing,
    NULL
};

static int * const wmio_flavor[] = {
    &hf_wmio_flavor_propagate_to_instance,
    &hf_wmio_flavor_propagate_to_derived_class,
    &hf_wmio_flavor_not_overridable,
    &hf_wmio_flavor_origin_propagated,
    &hf_wmio_flavor_origin_system,
    &hf_wmio_flavor_amended,
    NULL
};

static int * const wmio_encoded_string_flags[] = {
    &hf_wmio_encoded_string_flags_unicode,
    NULL
};

static int ett_wmio;
static int ett_wmio_object_flags;
static int ett_wmio_encoded_string;
static int ett_wmio_encoded_string_flags;
static int ett_wmio_class_part;
static int ett_wmio_class_header;
static int ett_wmio_decoration;
static int ett_wmio_class_derivation;
static int ett_wmio_qualifierset;
static int ett_wmio_qualifier;
static int ett_wmio_flavor;
static int ett_wmio_propertylookuptable;
static int ett_wmio_propertylookup;
static int ett_wmio_heap;
static int ett_methodspart;
static int ett_parentclass;
static int ett_currentclass;
static int ett_methodspart_methods;
static int ett_methodspart_methoddescription;
static int ett_methodsignature;
static int ett_property_info;

/* Tree */
static int *ett[] = {
    &ett_wmio,
    &ett_wmio_object_flags,
    &ett_wmio_encoded_string,
    &ett_wmio_encoded_string_flags,
    &ett_wmio_class_part,
    &ett_wmio_class_header,
    &ett_wmio_decoration,
    &ett_wmio_class_derivation,
    &ett_wmio_qualifierset,
    &ett_wmio_qualifier,
    &ett_wmio_flavor,
    &ett_wmio_propertylookuptable,
    &ett_wmio_propertylookup,
    &ett_wmio_heap,
    &ett_methodspart,
    &ett_methodspart_methods,
    &ett_methodspart_methoddescription,
    &ett_methodsignature,
    &ett_parentclass,
    &ett_currentclass,
    &ett_property_info,
};

static int dissect_wmio_objectblock(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_wmio_object_decoration(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_wmio_encoded_string(tvbuff_t *tvb, int offset, int hfindex, packet_info *pinfo, proto_tree *tree, bool withlength, int heapoffset);
static int dissect_wmio_encoding_classtype(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_wmio_encoding_classandmethodspart(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index, int ett, bool methods);
static int dissect_wmio_encoding_classpart(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_wmio_encoding_classheader(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, uint32_t *pPartlength, uint32_t *pNdLength, int classheapoffset);
static int dissect_wmio_encoding_methodpart(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_wmio_encoding_methodpart_methods(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, uint32_t methodscount, int methodsheapoffset);
static int dissect_wmio_encoding_methodpart_methoddescription(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int methodsheapoffset);
static int dissect_wmio_encoding_derivationlist(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_wmio_encoding_qualifierset(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, int classheapoffset);

/* DictionaryReference
 * https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/40adf451-f5bc-4b0a-ab97-d620bb638470
 */
static const char* stringDictionary[] =
  { "'"
  , "key"
  , ""
  , "read"
  , "write"
  , "volatile"
  , "provider"
  , "dynamic"
  , "cimwin32"
  , "DWORD"
  , "CIMTYPE"
  };

/* Encoded-String
 * https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/2f3afcf6-169e-41ff-80c2-367f2f74285b
 *  Encoded-String = Encoded-String-Flag *Character Null
 *  Encoded-String-Flag = OCTET
 *  Character = AnsiCharacter / UnicodeCharacter
 *  Null = Character
 *  AnsiCharacter = OCTET
 *  UnicodeCharacter = 2OCTET
 */
static int
dissect_wmio_encoded_string(tvbuff_t *tvb, int offset, int hfindex, packet_info *pinfo,
        proto_tree *tree, bool withlength, int heapoffset)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    int old_offset = offset;
    int fn_len = 0;
    header_field_info *hfinfo;
    char *s= NULL;
    uint32_t foffset = 0;

    /* Make sure this really is a string field. */
    hfinfo = proto_registrar_get_nth(hfindex);
    DISSECTOR_ASSERT_FIELD_TYPE(hfinfo, FT_STRINGZ);

    if(heapoffset > 0){
        /* HeapRef
         *   https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/f9d22d98-ed26-45d7-8792-aa0f210cffb2
         *   HeapRef is a reference to any HeapItem and is expressed in 31 bits. If the HeapItem referred to is a string,
         *   and the most significant bit of the 32-bit HeapStringRef value is set, the reference is actually to an implied
         *   dictionary-based string entry and does not point to a literal Encoded-String within the Heap.
         */
        foffset = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);

        if (foffset < 0x80000000){
            offset = heapoffset + foffset;
        }
    }

    sub_item = proto_tree_add_item(tree, hf_wmio_encoded_string, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_wmio_encoded_string);

    if((heapoffset > 0) && (foffset >= 0x80000000)){
        proto_tree_add_item(sub_tree, hf_heap_offset, tvb, old_offset, 4, ENC_LITTLE_ENDIAN);
        /*  https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/f9d22d98-ed26-45d7-8792-aa0f210cffb2
         *  If the value of HeapRef is 0xFFFFFFFF, then HeapItem is not present and MUST be considered NULL.
         */
        if(foffset == 0xFFFFFFFF){
            /* NULL String */
            proto_item_set_text(sub_tree, "%s: %s", proto_registrar_get_name(hfindex), "NULL");
            proto_item_set_len(sub_item, 4);
        } else {
            if (foffset & 0x80000000){
                foffset = 0x7FFFFFFF & foffset;
                if (foffset < array_length(stringDictionary)){
                    proto_item_set_text(sub_tree, "%s: %s", proto_registrar_get_name(hfindex), stringDictionary[foffset]);
                } else {
                    proto_item_set_text(sub_tree, "%s: Unknown Index %d", proto_registrar_get_name(hfindex), hfindex);
                }
                proto_item_set_len(sub_item, 4);
            }
        }
    } else {
        uint64_t encoded_string_flags;

        if(heapoffset > 0){
            proto_tree_add_item(sub_tree, hf_heap_offset, tvb, old_offset, 4, ENC_LITTLE_ENDIAN);
        }

        old_offset = offset;

        proto_tree_add_bitmask_ret_uint64(sub_tree, tvb, offset, hf_wmio_encoded_string_flags, ett_wmio_encoded_string_flags, wmio_encoded_string_flags, ENC_NA, &encoded_string_flags);
        offset++;

        if (encoded_string_flags == 0){
            /* ASCII */
            proto_tree_add_item_ret_length(sub_tree, hfindex, tvb, offset, -1, ENC_ASCII, &fn_len);
            s = tvb_get_string_enc(pinfo->pool, tvb, offset, fn_len, ENC_ASCII);
        } else if (encoded_string_flags == 1){
            /* UNICODE */
            proto_tree_add_item_ret_length(sub_tree, hfindex, tvb, offset, -1, ENC_UTF_16|ENC_LITTLE_ENDIAN, &fn_len);
            s = tvb_get_string_enc(pinfo->pool, tvb, offset, fn_len, ENC_UTF_16);
        }
        offset += fn_len;

        proto_item_set_text(sub_tree, "%s: %s", proto_registrar_get_name(hfindex), s);

        if(withlength){
            proto_tree_add_item(sub_tree, hf_wmio_class_name_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        proto_item_set_len(sub_item, offset-old_offset);
    }
    return offset;
}

/* ObjectBlock
 *  https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/4e74c9f9-4a47-4111-9e67-6476c896b7fb
 *  ObjectBlock = ObjectFlags [Decoration] Encoding
 */
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_wmio_objectblock(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    int8_t flags = tvb_get_uint8(tvb, offset);

    proto_tree_add_bitmask(tree, tvb, offset, hf_wmio_object_flags,
                ett_wmio_object_flags, wmio_object_flags, ENC_NA);
    offset+=1;

    increment_dissection_depth(pinfo);

    if (WMIO_OBJECT_FLAG_HAS_DECORATION & flags){
        offset = dissect_wmio_object_decoration(tvb, offset, pinfo, tree);
    }

    if (WMIO_OBJECT_FLAG_CIM_CLASS & flags){
        offset = dissect_wmio_encoding_classtype(tvb, offset, pinfo, tree);
    }

    decrement_dissection_depth(pinfo);

    return offset;
}

/* Decoration = DecServerName DecNamespaceName
 *  https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/0650ad93-88fa-49e9-aebc-e4462e4a7786
 *  Decoration = DecServerName DecNamespaceName
 */
static int
dissect_wmio_object_decoration(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = offset;

    item = proto_tree_add_item(parent_tree, hf_wmio_decoration, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_wmio_decoration);

    offset = dissect_wmio_encoded_string(tvb, offset, hf_wmio_decoration_server_name, pinfo, tree, false, 0);
    offset = dissect_wmio_encoded_string(tvb, offset, hf_wmio_decoration_namespace, pinfo, tree, false, 0);

    proto_item_set_len(item, offset-old_offset);

    return offset;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_wmio_encoding_classtype(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    increment_dissection_depth(pinfo);

    // ParentClass
    offset = dissect_wmio_encoding_classandmethodspart(tvb, offset, pinfo, tree, hf_parentclass, ett_parentclass, true);

    // CurrentClass
    offset = dissect_wmio_encoding_classandmethodspart(tvb, offset, pinfo, tree, hf_currentclass, ett_currentclass, true);

    decrement_dissection_depth(pinfo);

    return offset;
}

/* ClassAndMethodsPart = ClassPart [MethodsPart]
 *  https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/35589520-cee8-4bb1-b09e-bb009d1d1b88
 *  ClassAndMethodsPart = ClassPart [MethodsPart]
 */
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_wmio_encoding_classandmethodspart(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, int hf_index, int ett_id, bool methods)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = offset;

    item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_id);

    offset = dissect_wmio_encoding_classpart(tvb, offset, pinfo, tree);
    if (methods){
        offset = dissect_wmio_encoding_methodpart(tvb, offset, pinfo, tree);
    }

    proto_item_set_len(item, offset-old_offset);
    return offset;
}

/* Qualifier
 *  https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/f4c4ec0a-e38b-4591-8111-cbb03cc405c2
 *  Qualifier = QualifierName QualifierFlavor QualifierType QualifierValue
 */
static int
dissect_wmio_qualifier(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *parent_tree, int classheapoffset)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = offset;

    item = proto_tree_add_item(parent_tree, hf_wmio_qualifier, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_wmio_qualifier);

    dissect_wmio_encoded_string(tvb, offset, hf_wmio_qualifiername, pinfo, tree, false, classheapoffset);
    offset+= 4;

    proto_tree_add_bitmask(tree, tvb, offset, hf_wmio_flavor, ett_wmio_flavor, wmio_flavor, ENC_NA);
    offset+= 1;

    // QualifierType = CimType
    // CimType is a 32-bit value
    int32_t cimType = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_wmio_cimtype, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+= 4;

    // QualifierValue = EncodedValue
    if (cimType & CIM_ARRAY_FLAG){
        uint32_t array_count = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
        offset += 4;

        // CimArrayType
        switch(cimType){
            case CIM_ARRAY_SINT8:
                offset += array_count;
                break;
            case CIM_ARRAY_UINT8:
                offset += array_count;
                break;
            case CIM_ARRAY_SINT16:
                offset += (sizeof(int16_t) * array_count);
                break;
            case CIM_ARRAY_UINT16:
                offset += (sizeof(uint16_t) * array_count);
                break;
            case CIM_ARRAY_SINT32:
                offset += (sizeof(int32_t) * array_count);
                break;
            case CIM_ARRAY_UINT32:
                offset += (sizeof(uint32_t) * array_count);
                break;
            case CIM_ARRAY_SINT64:
                offset += (sizeof(int64_t) * array_count);
                break;
            case CIM_ARRAY_UINT64:
                offset += (sizeof(uint64_t) * array_count);
                break;
            case CIM_ARRAY_REAL32:
                offset += (sizeof(int32_t) * array_count);
                break;
            case CIM_ARRAY_REAL64:
                offset += (sizeof(int64_t) * array_count);
                break;
            case CIM_ARRAY_BOOLEAN:
                offset += (2 * array_count);
                break;
            case CIM_ARRAY_STRING:
            case CIM_ARRAY_DATETIME:
            case CIM_ARRAY_REFERENCE:
                // TODO
                break;
            case CIM_ARRAY_CHAR16:
                offset += (sizeof(int16_t) * array_count);
                break;
            case CIM_ARRAY_OBJECT:
                {
                    for (uint32_t i=0; i < array_count; i++){
                        int32_t objEncLength = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
                        offset += objEncLength;
                    }
                    break;
                }
            default:
                break;
        }
    } else {
        // CimBaseType
        switch(cimType){
            case CIM_TYPE_SINT8:
                {
                proto_item *vitem = proto_tree_add_item(tree, hf_wmio_qualifiervalue, tvb, offset, -1, ENC_ASCII);
                proto_item_set_text(vitem, "%s: %d", proto_registrar_get_name(hf_wmio_qualifiervalue), tvb_get_int8(tvb, offset));
                proto_item_set_len(vitem, 1);
                offset+= 1;
                }
                break;
            case CIM_TYPE_UINT8:
                {
                proto_item *vitem = proto_tree_add_item(tree, hf_wmio_qualifiervalue, tvb, offset, -1, ENC_ASCII);
                proto_item_set_text(vitem, "%s: %u", proto_registrar_get_name(hf_wmio_qualifiervalue), tvb_get_int8(tvb, offset));
                proto_item_set_len(vitem, 1);
                offset+= 1;
                }
                break;
            case CIM_TYPE_SINT16:
            case CIM_TYPE_CHAR16:
                {
                proto_item *vitem = proto_tree_add_item(tree, hf_wmio_qualifiervalue, tvb, offset, -1, ENC_ASCII);
                proto_item_set_text(vitem, "%s: %d", proto_registrar_get_name(hf_wmio_qualifiervalue), tvb_get_int16(tvb, offset, ENC_LITTLE_ENDIAN));
                proto_item_set_len(vitem, 2);
                offset+= 2;
                }
                break;
            case CIM_TYPE_UINT16:
                {
                proto_item *vitem = proto_tree_add_item(tree, hf_wmio_qualifiervalue, tvb, offset, -1, ENC_ASCII);
                proto_item_set_text(tree, "%s: %u", proto_registrar_get_name(hf_wmio_qualifiervalue), tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN));
                proto_item_set_len(vitem, 2);
                offset+= 2;
                }
                break;
            case CIM_TYPE_SINT32:
                {
                proto_item *vitem = proto_tree_add_item(tree, hf_wmio_qualifiervalue, tvb, offset, -1, ENC_ASCII);
                proto_item_set_text(vitem, "%s: %d", proto_registrar_get_name(hf_wmio_qualifiervalue), tvb_get_int32(tvb, offset, ENC_LITTLE_ENDIAN));
                proto_item_set_len(vitem, 4);
                offset+= 4;
                }
                break;
            case CIM_TYPE_UINT32:
                {
                proto_item *vitem = proto_tree_add_item(tree, hf_wmio_qualifiervalue, tvb, offset, -1, ENC_ASCII);
                proto_item_set_text(vitem, "%s: %u", proto_registrar_get_name(hf_wmio_qualifiervalue), tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN));
                proto_item_set_len(vitem, 4);
                offset+= 4;
                }
                break;
            case CIM_TYPE_SINT64:
                {
                proto_item *vitem = proto_tree_add_item(tree, hf_wmio_qualifiervalue, tvb, offset, -1, ENC_ASCII);
                proto_item_set_text(vitem, "%s: %" PRIi64, proto_registrar_get_name(hf_wmio_qualifiervalue), tvb_get_int64(tvb, offset, ENC_LITTLE_ENDIAN));
                proto_item_set_len(vitem, 8);
                offset+= 8;
                }
                break;
            case CIM_TYPE_UINT64:
                {
                proto_item *vitem = proto_tree_add_item(tree, hf_wmio_qualifiervalue, tvb, offset, -1, ENC_ASCII);
                proto_item_set_text(vitem, "%s: %" PRIu64, proto_registrar_get_name(hf_wmio_qualifiervalue), tvb_get_uint64(tvb, offset, ENC_LITTLE_ENDIAN));
                proto_item_set_len(vitem, 8);
                offset+= 8;
                }
                break;
            case CIM_TYPE_REAL32:
                {
                proto_item *vitem = proto_tree_add_item(tree, hf_wmio_qualifiervalue, tvb, offset, -1, ENC_ASCII);
                proto_item_set_text(vitem, "%s: %f", proto_registrar_get_name(hf_wmio_qualifiervalue), tvb_get_ieee_float(tvb, offset, ENC_LITTLE_ENDIAN));
                proto_item_set_len(vitem, 4);
                offset+= 4;
                }
                break;
            case CIM_TYPE_REAL64:
                {
                proto_item *vitem = proto_tree_add_item(tree, hf_wmio_qualifiervalue, tvb, offset, -1, ENC_ASCII);
                proto_item_set_text(vitem, "%s: %lf", proto_registrar_get_name(hf_wmio_qualifiervalue), tvb_get_ieee_double(tvb, offset, ENC_LITTLE_ENDIAN));
                proto_item_set_len(vitem, 8);
                offset+= 8;
                }
                break;
            case CIM_TYPE_BOOLEAN:
                {
                proto_item *vitem = proto_tree_add_item(tree, hf_wmio_qualifiervalue, tvb, offset, -1, ENC_ASCII);
                proto_item_set_text(vitem, "%s: %s", proto_registrar_get_name(hf_wmio_qualifiervalue), 0 != tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN) ? "TRUE" : "FALSE");
                proto_item_set_len(vitem, 2);
                offset+= 2;
                }
                break;
            case CIM_TYPE_STRING:
            case CIM_TYPE_DATETIME:
            case CIM_TYPE_REFERENCE:
                dissect_wmio_encoded_string(tvb, offset, hf_wmio_qualifiervalue, pinfo, tree, false, classheapoffset);
                offset+= 4;
                break;
            case CIM_TYPE_OBJECT:
                {
                    int32_t objEncLength = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
                    offset += objEncLength;
                }
                break;
            default:
                break;
        }
    }

    proto_item_set_len(item, offset - old_offset);

    return offset;
}

/* QualifierSet
 *  https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/224c7463-01df-4e09-bd71-650ec0b8adaf
 *  QualifierSet = EncodingLength *Qualifier
 */
static int
dissect_wmio_encoding_qualifierset(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *parent_tree, int classheapoffset)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = offset;
    uint32_t length;

    item = proto_tree_add_item(parent_tree, hf_wmio_qualifierset, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_wmio_qualifierset);

    proto_tree_add_item_ret_uint(tree, hf_wmio_qualifierset_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
    offset += 4;

    while((uint32_t)offset < (old_offset + length)){
        /* N.B. guaranteed to advance offset */
        offset = dissect_wmio_qualifier(tvb, offset, pinfo, tree, classheapoffset);
    }

    proto_item_set_len(item, offset - old_offset);

    return old_offset+length;
}

/* PropertyInfo
 *  https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/563356b2-7bc7-4016-a88b-6685d3e09b59
 *  PropertyInfo = PropertyType DeclarationOrder ValueTableOffset ClassOfOrigin PropertyQualifierSet
 */
static void
dissect_wmio_encoding_propertyinfo(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *parent_tree, int classheapoffset)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    uint32_t propertyinfo_offset;
    int old_offset = 0;

    item = proto_tree_add_item(parent_tree, hf_property_info, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_property_info);

    proto_tree_add_item_ret_uint(tree, hf_wmio_propertyinforef, tvb, offset, 4, ENC_LITTLE_ENDIAN, &propertyinfo_offset);

    offset = classheapoffset + propertyinfo_offset;
    old_offset = offset;

    int32_t propType = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_uint(tree, hf_wmio_cimtype, tvb, offset, 4, propType & 0x3FFF);
    proto_tree_add_boolean(tree, hf_propertyinfo_inherited, tvb, offset, 4, propType);
    offset += 4;

    proto_tree_add_item(tree, hf_declaration_order, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_propertyinfo_valuetableoffset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_propertyinfo_classoforigin, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    offset = dissect_wmio_encoding_qualifierset(tvb, offset, pinfo, tree, classheapoffset);

    proto_item_set_len(item, offset - old_offset);
}

/* PropertyLookup
 *  https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/e401de4a-58fa-423b-89e0-4b832a99d0e9
 *  PropertyLookup = PropertyNameRef PropertyInfoRef
 */
static int
dissect_wmio_encoding_propertylookup(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *parent_tree, int classheapoffset)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = offset;

    item = proto_tree_add_item(parent_tree, hf_wmio_propertylookup, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_wmio_propertylookup);

    dissect_wmio_encoded_string(tvb, offset, hf_wmio_propertynameref, pinfo, tree, false, classheapoffset);
    offset += 4;


    dissect_wmio_encoding_propertyinfo(tvb, offset, pinfo, tree, classheapoffset);
    offset += 4;

    proto_item_set_len(item, offset - old_offset);

    return offset;
}

/* PropertyLookupTable
 *  https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/d4927ca8-b358-48eb-8879-a57ea4f090c3
 *  PropertyLookupTable = PropertyCount *PropertyLookup
 */
static int
dissect_wmio_encoding_propertylookuptable(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *parent_tree, uint32_t *property_count, int classheapoffset)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = offset;
    uint32_t count;

    item = proto_tree_add_item(parent_tree, hf_wmio_propertylookuptable, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_wmio_propertylookuptable);

    // PropertyCount
    proto_tree_add_item_ret_uint(tree, hf_wmio_propertylookuptable_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &count);
    offset += 4;

    for(uint32_t i = 0; i < count; ++i){
        offset = dissect_wmio_encoding_propertylookup(tvb, offset, pinfo, tree, classheapoffset);
    }

    *property_count = count;

    proto_item_set_len(item, offset - old_offset);

    return offset;
}

/* ClassPart
 *  https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/06ec93f3-b4df-4f7e-b2ba-090cd435becc
 *  ClassPart = ClassHeader DerivationList ClassQualifierSet PropertyLookupTable [NdTable ValueTable] ClassHeap
 */
static int
dissect_wmio_encoding_classpart(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = offset;
    int classheapoffset = 0;

    uint32_t partlength, ndLength;
    uint32_t property_count;

    item = proto_tree_add_item(parent_tree, hf_wmio_class_part, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_wmio_class_part);

    {
        /* Jump through the various structures to find the heap offset. */
        uint32_t derivationListLength = tvb_get_uint32(tvb, offset + CLASS_HEADER_LENGTH, ENC_LITTLE_ENDIAN);
        uint32_t classQualifierSetLength = tvb_get_uint32(tvb, offset + CLASS_HEADER_LENGTH + derivationListLength, ENC_LITTLE_ENDIAN);
        uint32_t propertyLookupTableLength = 4 + 8 * tvb_get_uint32(tvb, offset + CLASS_HEADER_LENGTH + derivationListLength + classQualifierSetLength, ENC_LITTLE_ENDIAN);
        uint32_t ndTableLength = tvb_get_uint32(tvb, offset + (CLASS_HEADER_LENGTH - 4), ENC_LITTLE_ENDIAN);

        classheapoffset = offset                    /* Starting offset */
                        + CLASS_HEADER_LENGTH       /* ClassHeader */
                        + derivationListLength      /* DerivationList */
                        + classQualifierSetLength   /* ClassQualifierSet */
                        + propertyLookupTableLength /* PropertyLookupTable */
                        + ndTableLength;            /* NdTable */
    }

    offset = dissect_wmio_encoding_classheader(tvb, offset, pinfo, tree, &partlength, &ndLength, classheapoffset+4);
    offset = dissect_wmio_encoding_derivationlist(tvb, offset, pinfo, tree);
    offset = dissect_wmio_encoding_qualifierset(tvb, offset, pinfo, tree,classheapoffset+4);
    offset = dissect_wmio_encoding_propertylookuptable(tvb, offset, pinfo, tree, &property_count, classheapoffset+4);

    if(ndLength > 0){
        proto_tree_add_item(tree, hf_wmio_ndtable, tvb, offset, ndLength, ENC_NA);
        offset += ndLength;
    }

    {
        proto_item *heapitem = NULL;
        proto_tree *heaptree = NULL;

        heapitem = proto_tree_add_item(tree, hf_wmio_heap, tvb, offset, -1, ENC_NA);
        heaptree = proto_item_add_subtree(heapitem, ett_wmio_heap);

        int32_t heaplength = 0x7FFFFFFF & tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);

        proto_tree_add_uint(heaptree, hf_wmio_heap_length, tvb, offset, 4, heaplength);

        proto_item_set_len(heapitem, heaplength);
    }

    proto_item_set_len(item, partlength);

    return old_offset + partlength;
}

/* ClassHeader
 *  https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/b179b579-9585-47b8-bef8-8fdca9f5a94d
 *  ClassHeader = EncodingLength ReservedOctet ClassNameRef NdTableValueTableLength
 */
static int
dissect_wmio_encoding_classheader(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *parent_tree, uint32_t *pPartlength, uint32_t *pNdLength, int classheapoffset)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = offset;

    uint32_t partlength, length;

    item = proto_tree_add_item(parent_tree, hf_wmio_class_header, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_wmio_class_header);

    proto_tree_add_item_ret_uint(tree, hf_wmio_class_header_partlength, tvb, offset, 4, ENC_LITTLE_ENDIAN, &partlength);
    offset+= 4;
    *pPartlength = partlength;

    // ReservedOctet
    offset+= 1;

    dissect_wmio_encoded_string(tvb, offset, hf_wmio_class_header_nameref, pinfo, tree, false, classheapoffset);
    offset+= 4;

    proto_tree_add_item_ret_uint(tree, hf_wmio_class_header_ndtablevaluetablelength, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
    offset+= 4;
    *pNdLength = length;

    proto_item_set_len(item, offset-old_offset);

    return offset;
}

/* DerivationList
 *  https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/3bfbcac6-318c-4b0a-ab87-13bfbc86f36f
 *  DerivationList = EncodingLength *ClassNameEncoding
 */
static int
dissect_wmio_encoding_derivationlist(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *parent_tree)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = offset;

    uint32_t length;

    item = proto_tree_add_item(parent_tree, hf_wmio_class_derivation, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_wmio_class_derivation);

    proto_tree_add_item_ret_uint(tree, hf_wmio_class_derivation_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
    offset+= 4;

    while((uint32_t)offset < (old_offset + length)) {
        /* Offset is guaranteed to increase here as heapoffset (last arg) is 0 */
        offset = dissect_wmio_encoded_string(tvb, offset, hf_wmio_derivation_classname, pinfo, tree, true, 0);
    }

    proto_item_set_len(item, length);

    return offset;
}

/* MethodSignature
 *  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmio/a9d7c0d1-f99a-4762-b460-e881a8c7d566
 *  MethodSignature = HeapMethodSignatureBlockRef
 */
static void
// NOLINTNEXTLINE(misc-no-recursion)
dissect_wmio_encoding_methodsignature(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *parent_tree, int hfindex, int methodsheapoffset)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = 0;

    int32_t signatureHeapOffset = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);

    old_offset = methodsheapoffset + signatureHeapOffset;

    item = proto_tree_add_item(parent_tree, hfindex, tvb, old_offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_methodsignature);

    proto_tree_add_item(tree, hf_methodsignature_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);

    offset = old_offset;

    proto_tree_add_item(tree, hf_wmio_objectencodinglength, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+= 4;

    offset = dissect_wmio_objectblock(tvb, offset, pinfo, tree);

    proto_item_set_len(item, offset - old_offset);
}

/* MethodDescription
 *  https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/8c81e4fa-634a-469f-8434-4ef87f2f256e
 *  MethodDescription = MethodName MethodFlags MethodPadding MethodOrigin MethodQualifiers InputSignature OutputSignature
 */
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_wmio_encoding_methodpart_methoddescription(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *parent_tree, int methodsheapoffset)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = offset;

    item = proto_tree_add_item(parent_tree, hf_methodspart_methoddescription, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_methodspart_methoddescription);

    dissect_wmio_encoded_string(tvb, offset, hf_methoddescription_methodname, pinfo, tree, false, methodsheapoffset);
    offset+= 4;

    proto_tree_add_item(tree, hf_methoddescription_methodflags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+= 1;

    // MethodPadding
    offset+= 3;

    proto_tree_add_item(tree, hf_methoddescription_methodorigin, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+= 4;

    proto_tree_add_item(tree, hf_methoddescription_methodqualifiers, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+= 4;

    dissect_wmio_encoding_methodsignature(tvb, offset, pinfo, tree, hf_methoddescription_inputsignature, methodsheapoffset);
    offset+= 4;

    dissect_wmio_encoding_methodsignature(tvb, offset, pinfo, tree, hf_methoddescription_outputsignature, methodsheapoffset);
    offset+= 4;

    proto_item_set_len(item, offset - old_offset);

    return offset;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_wmio_encoding_methodpart_methods(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *parent_tree, uint32_t methodscount, int methodsheapoffset)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = offset;

    item = proto_tree_add_item(parent_tree, hf_methodspart_methods, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_methodspart_methods);

    for(uint32_t methodi = 0; methodi < methodscount; ++methodi){
        offset = dissect_wmio_encoding_methodpart_methoddescription(tvb, offset, pinfo, tree, methodsheapoffset);
    }

    proto_item_set_len(item, offset - old_offset);
    return offset;
}

/* MethodsPart
 *  https://learn.microsoft.com/de-de/openspecs/windows_protocols/ms-wmio/e00d7c6c-fa1e-4b1d-85c5-5a91a5d71299
 *  MethodsPart = EncodingLength MethodCount MethodCountPadding *MethodDescription MethodHeap
 */
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_wmio_encoding_methodpart(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    int old_offset = offset;

    uint32_t length;
    uint32_t methodscount;

    item = proto_tree_add_item(parent_tree, hf_methodspart, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_methodspart);

    proto_tree_add_item_ret_uint(tree, hf_methodspart_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
    offset+= 4;

    proto_tree_add_item_ret_uint(tree, hf_methodspart_methodcount, tvb, offset, 2, ENC_LITTLE_ENDIAN, &methodscount);
    offset+= 2;

    // MethodCountPadding
    offset+= 2;

    if(methodscount > 0){
        int methodsHeapOffset = offset + (methodscount * 24);
        methodsHeapOffset += 4;
        offset = dissect_wmio_encoding_methodpart_methods(tvb, offset, pinfo, tree, methodscount, methodsHeapOffset);
    }

    {
        proto_item *heapitem = NULL;
        proto_tree *heaptree = NULL;

        heapitem = proto_tree_add_item(tree, hf_wmio_heap, tvb, offset, -1, ENC_NA);
        heaptree = proto_item_add_subtree(heapitem, ett_wmio_heap);

        int32_t heaplength = 0x7FFFFFFF & tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);

        proto_tree_add_uint(heaptree, hf_wmio_heap_length, tvb, offset, 4, heaplength);

        proto_item_set_len(heapitem, heaplength);
    }

    proto_item_set_len(item, length);

    return old_offset+length;
}


static int
dissect_wmio(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di _U_, uint8_t *drep _U_, int size)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    int old_offset = offset;
    uint32_t signature;

    sub_item = proto_tree_add_item(tree, hf_wmio, tvb, offset, size, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_wmio);

    proto_tree_add_item_ret_uint(sub_tree, hf_wmio_signature, tvb, offset, 4, ENC_LITTLE_ENDIAN, &signature);
    offset+= 4;

    if (signature != wmio_signature){
        return old_offset + size;
    }

    proto_tree_add_item(sub_tree, hf_wmio_objectencodinglength, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+= 4;

    dissect_wmio_objectblock(tvb, offset, pinfo, sub_tree);

    return old_offset + size;
}

void
register_dcom_wmio (void)
{
    dcom_register_routine(dissect_wmio, &iid_WMIO);
}

void
proto_register_WMIO (void)
{
    proto_WMIO = proto_register_protocol ("WMIO", "WMIO", "WMIO");
    proto_register_field_array (proto_WMIO, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
}
