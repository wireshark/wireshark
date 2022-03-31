function field_setup(proto, prefix)

    local pf_boolean       = ProtoField.new("Boolean",       prefix..".boolean",       ftypes.BOOLEAN)
    local pf_char          = ProtoField.new("Char",          prefix..".char",          ftypes.CHAR)
    local pf_uint8         = ProtoField.new("Uint8",         prefix..".uint8",         ftypes.UINT8)
    local pf_uint16        = ProtoField.new("Uint16",        prefix..".uint16",        ftypes.UINT16)
    local pf_uint24        = ProtoField.new("Uint24",        prefix..".uint24",        ftypes.UINT24)
    local pf_uint32        = ProtoField.new("Uint32",        prefix..".uint32",        ftypes.UINT32)
    local pf_uint64        = ProtoField.new("Uint64",        prefix..".uint64",        ftypes.UINT64)
    local pf_int8          = ProtoField.new("Int8",          prefix..".int8",          ftypes.INT8)
    local pf_int16         = ProtoField.new("Int16",         prefix..".int16",         ftypes.INT16)
    local pf_int24         = ProtoField.new("Int24",         prefix..".int24",         ftypes.INT24)
    local pf_int32         = ProtoField.new("Int32",         prefix..".int32",         ftypes.INT32)
    local pf_int64         = ProtoField.new("Int64",         prefix..".int64",         ftypes.INT64)
    local pf_float         = ProtoField.new("Float",         prefix..".float",         ftypes.FLOAT)
    local pf_double        = ProtoField.new("Double",        prefix..".double",        ftypes.DOUBLE)
    local pf_absolute_time = ProtoField.new("Absolute_Time", prefix..".absolute_time", ftypes.ABSOLUTE_TIME)
    local pf_relative_time = ProtoField.new("Relative_Time", prefix..".relative_time", ftypes.RELATIVE_TIME)
    local pf_string        = ProtoField.new("String",        prefix..".string",        ftypes.STRING)
    local pf_stringz       = ProtoField.new("Stringz",       prefix..".stringz",       ftypes.STRINGZ)
    local pf_ether         = ProtoField.new("Ether",         prefix..".ether",         ftypes.ETHER)
    local pf_bytes         = ProtoField.new("Bytes",         prefix..".bytes",         ftypes.BYTES)
    local pf_uint_bytes    = ProtoField.new("Uint_Bytes",    prefix..".uint_bytes",    ftypes.UINT_BYTES)
    local pf_ipv4          = ProtoField.new("Ipv4",          prefix..".ipv4",          ftypes.IPv4)
    local pf_ipv6          = ProtoField.new("Ipv6",          prefix..".ipv6",          ftypes.IPv6)
    local pf_ipxnet        = ProtoField.new("Ipxnet",        prefix..".ipxnet",        ftypes.IPXNET)
    local pf_framenum      = ProtoField.new("Framenum",      prefix..".framenum",      ftypes.FRAMENUM)
    local pf_guid          = ProtoField.new("Guid",          prefix..".guid",          ftypes.GUID)
    local pf_oid           = ProtoField.new("Oid",           prefix..".oid",           ftypes.OID)
    local pf_rel_oid       = ProtoField.new("Rel_Oid",       prefix..".rel_oid",       ftypes.REL_OID)
    local pf_system_id     = ProtoField.new("System_Id",     prefix..".system_id",     ftypes.SYSTEM_ID)
    local pf_eui64         = ProtoField.new("Eui64",         prefix..".eui64",         ftypes.EUI64)

    proto.fields = {
        pf_boolean, pf_char, pf_uint8, pf_uint16, pf_uint24, pf_uint32, pf_uint64, pf_int8,
        pf_int16, pf_int24, pf_int32, pf_int64, pf_float, pf_double, pf_absolute_time, pf_relative_time,
        pf_string, pf_stringz, pf_ether, pf_bytes, pf_uint_bytes, pf_ipv4, pf_ipv6, pf_ipxnet,
        pf_framenum, pf_guid, pf_oid, pf_rel_oid, pf_system_id, pf_eui64,
    }

    local vf_boolean       = Field.new(prefix..".boolean")
    local vf_char          = Field.new(prefix..".char")
    local vf_uint8         = Field.new(prefix..".uint8")
    local vf_uint16        = Field.new(prefix..".uint16")
    local vf_uint24        = Field.new(prefix..".uint24")
    local vf_uint32        = Field.new(prefix..".uint32")
    local vf_uint64        = Field.new(prefix..".uint64")
    local vf_int8          = Field.new(prefix..".int8")
    local vf_int16         = Field.new(prefix..".int16")
    local vf_int24         = Field.new(prefix..".int24")
    local vf_int32         = Field.new(prefix..".int32")
    local vf_int64         = Field.new(prefix..".int64")
    local vf_float         = Field.new(prefix..".float")
    local vf_double        = Field.new(prefix..".double")
    local vf_absolute_time = Field.new(prefix..".absolute_time")
    local vf_relative_time = Field.new(prefix..".relative_time")
    local vf_string        = Field.new(prefix..".string")
    local vf_stringz       = Field.new(prefix..".stringz")
    local vf_ether         = Field.new(prefix..".ether")
    local vf_bytes         = Field.new(prefix..".bytes")
    local vf_uint_bytes    = Field.new(prefix..".uint_bytes")
    local vf_ipv4          = Field.new(prefix..".ipv4")
    local vf_ipv6          = Field.new(prefix..".ipv6")
    local vf_ipxnet        = Field.new(prefix..".ipxnet")
    local vf_framenum      = Field.new(prefix..".framenum")
    local vf_guid          = Field.new(prefix..".guid")
    local vf_oid           = Field.new(prefix..".oid")
    local vf_rel_oid       = Field.new(prefix..".rel_oid")
    local vf_system_id     = Field.new(prefix..".system_id")
    local vf_eui64         = Field.new(prefix..".eui64")

    local fieldmap = {
        ["boolean"]       = {packet_field = pf_boolean,       value_field = vf_boolean},
        ["char"]          = {packet_field = pf_char,          value_field = vf_char},
        ["uint8"]         = {packet_field = pf_uint8,         value_field = vf_uint8},
        ["uint16"]        = {packet_field = pf_uint16,        value_field = vf_uint16},
        ["uint24"]        = {packet_field = pf_uint24,        value_field = vf_uint24},
        ["uint32"]        = {packet_field = pf_uint32,        value_field = vf_uint32},
        ["uint64"]        = {packet_field = pf_uint64,        value_field = vf_uint64},
        ["int8"]          = {packet_field = pf_int8,          value_field = vf_int8},
        ["int16"]         = {packet_field = pf_int16,         value_field = vf_int16},
        ["int24"]         = {packet_field = pf_int24,         value_field = vf_int24},
        ["int32"]         = {packet_field = pf_int32,         value_field = vf_int32},
        ["int64"]         = {packet_field = pf_int64,         value_field = vf_int64},
        ["float"]         = {packet_field = pf_float,         value_field = vf_float},
        ["double"]        = {packet_field = pf_double,        value_field = vf_double},
        ["absolute_time"] = {packet_field = pf_absolute_time, value_field = vf_absolute_time},
        ["relative_time"] = {packet_field = pf_relative_time, value_field = vf_relative_time},
        ["string"]        = {packet_field = pf_string,        value_field = vf_string},
        ["stringz"]       = {packet_field = pf_stringz,       value_field = vf_stringz},
        ["ether"]         = {packet_field = pf_ether,         value_field = vf_ether},
        ["bytes"]         = {packet_field = pf_bytes,         value_field = vf_bytes},
        ["uint_bytes"]    = {packet_field = pf_uint_bytes,    value_field = vf_uint_bytes},
        ["ipv4"]          = {packet_field = pf_ipv4,          value_field = vf_ipv4},
        ["ipv6"]          = {packet_field = pf_ipv6,          value_field = vf_ipv6},
        ["ipxnet"]        = {packet_field = pf_ipxnet,        value_field = vf_ipxnet},
        ["framenum"]      = {packet_field = pf_framenum,      value_field = vf_framenum},
        ["guid"]          = {packet_field = pf_guid,          value_field = vf_guid},
        ["oid"]           = {packet_field = pf_oid,           value_field = vf_oid},
        ["rel_oid"]       = {packet_field = pf_rel_oid,       value_field = vf_rel_oid},
        ["system_id"]     = {packet_field = pf_system_id,     value_field = vf_system_id},
        ["eui64"]         = {packet_field = pf_eui64,         value_field = vf_eui64},
    }

    return fieldmap
end

return field_setup
