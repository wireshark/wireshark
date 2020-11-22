do
    local protobuf_dissector = Dissector.get("protobuf")

    -- Create protobuf dissector based on UDP or TCP.
    -- The UDP dissector will take the whole tvb as a message.
    -- The TCP dissector will parse tvb as format:
    --         [4bytes length][a message][4bytes length][a message]...
    -- @param name  The name of the new dissector.
    -- @param desc  The description of the new dissector.
    -- @param for_udp  Register the new dissector to UDP table.(Enable 'Decode as')
    -- @param for_tcp  Register the new dissector to TCP table.(Enable 'Decode as')
    -- @param msgtype  Message type. This must be the root message defined in your .proto file.
    local function create_protobuf_dissector(name, desc, for_udp, for_tcp, msgtype)
        local proto = Proto(name, desc)
        local f_length = ProtoField.uint32(name .. ".length", "Length", base.DEC)
        proto.fields = { f_length }

        proto.dissector = function(tvb, pinfo, tree)
            local subtree = tree:add(proto, tvb())
            if for_udp and pinfo.port_type == 3 then -- UDP
                if msgtype ~= nil then
                    pinfo.private["pb_msg_type"] = "message," .. msgtype
                end
                pcall(Dissector.call, protobuf_dissector, tvb, pinfo, subtree)
            elseif for_tcp and pinfo.port_type == 2 then -- TCP
                local offset = 0
                local remaining_len = tvb:len()
                while remaining_len > 0 do
                    if remaining_len < 4 then -- head not enough
                        pinfo.desegment_offset = offset
                        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                        return -1
                    end

                    local data_len = tvb(offset, 4):uint()

                    if remaining_len - 4 < data_len then -- data not enough
                        pinfo.desegment_offset = offset
                        pinfo.desegment_len = data_len - (remaining_len - 4)
                        return -1
                    end
                    subtree:add(f_length, tvb(offset, 4))

                    if msgtype ~= nil then
                        pinfo.private["pb_msg_type"] = "message," .. msgtype
                    end
                    pcall(Dissector.call, protobuf_dissector, 
                           tvb(offset + 4, data_len):tvb(), pinfo, subtree)

                    offset = offset + 4 + data_len
                    remaining_len = remaining_len - 4 - data_len
                end
            end
            pinfo.columns.protocol:set(name)
        end

        if for_udp then DissectorTable.get("udp.port"):add(0, proto) end
        if for_tcp then DissectorTable.get("tcp.port"):add(0, proto) end
        return proto
    end

    -- default pure protobuf udp and tcp dissector without message type
    create_protobuf_dissector("protobuf_udp", "Protobuf UDP")
    create_protobuf_dissector("protobuf_tcp", "Protobuf TCP")
    -- add more protobuf dissectors with message types
    create_protobuf_dissector("AddrBook", "Tutorial AddressBook",
                              true, true, "tutorial.AddressBook")
end
