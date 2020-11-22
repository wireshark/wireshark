-- Test protobuf_field dissector table
do
    local protobuf_field_table = DissectorTable.get("protobuf_field")
    local png_dissector = Dissector.get("png")
    protobuf_field_table:add("tutorial.Person.portrait_image", png_dissector)
end
