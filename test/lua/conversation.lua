----------------------------------------
-- script-name: protofield.lua
-- test the ProtoField API
----------------------------------------

local testlib = require("testlib")

local FIRSTPASS = "first-pass"
local FRAME = "frame"
local PER_FRAME = "per-frame"
local OTHER = "other"

-- expected number of runs
local n_frames = 4
local taptests = {
    [FIRSTPASS]=14,
    [FRAME]=n_frames,
    [PER_FRAME]=n_frames*8-1,
    [OTHER]=1,
}
testlib.init(taptests)

------------- test script ------------

----------------------------------------
local test_proto = Proto("test", "Test Proto")

local numinits = 0
function test_proto.init()
    numinits = numinits + 1
    if numinits == 2 then
        testlib.getResults()
    end
end

-- Helper functions for testing
local conv_reg = {}
function unique_conv(name, conv)
    if conv == nil then
        return false
    end

    for k, v in pairs(conv_reg) do
        if (name == k) or (conv == v) then
            return false
        end
    end

    conv_reg[name] = conv
    return true
end

function existing_conv(conv_key, conv)
    return conv_reg[conv_key] == conv
end

-- Check functions, for pcall
function check_find(compare, fnum, ctype, addr_1, addr_2, port_1, port_2, create)
    return compare == Conversation.find(fnum, ctype, addr_1, addr_2, port_1, port_2, create)
end

function check_find_pinfo(compare, pinfo, create)
    return compare == Conversation.find_from_pinfo(pinfo, create)
end

function check_find_id(compare, frame_num, conv_type, conv_id, create)
    return compare == Conversation.find_by_id(frame_num, conv_type, conv_id, create)
end

-- Test variables, to be maintained throughout test
local frame_num = nil
local conv_type = convtypes.TCP
local conv_id   = 62
local addr1 = Address.ip('127.0.0.1')
local port1 = 65333
local addr2 = nil
local port2 = nil


-- Test conversation handling
function test_proto.dissector(buf, pinfo, root)
    testlib.countPacket(FRAME)

    -- First packet of dissector
    if testlib.getPktCount(FRAME) == 1 then
        frame_num = pinfo.number

        -- Check that create == false returns nil when conversation doesn't exist yet
        testlib.test(FIRSTPASS,"Conversation.find(!p1,!p2) == nil",pcall(check_find,nil,frame_num,conv_type,addr1,addr2,nil,nil,false))
        testlib.test(FIRSTPASS,"Conversation.find(!p1, p2) == nil",pcall(check_find,nil,frame_num,conv_type,addr1,addr2,nil,port2,false))
        testlib.test(FIRSTPASS,"Conversation.find( p1,!p2) == nil",pcall(check_find,nil,frame_num,conv_type,addr1,addr2,port1,nil,false))
        testlib.test(FIRSTPASS,"Conversation.find( p1, p2) == nil",pcall(check_find,nil,frame_num,conv_type,addr1,addr2,port1,port2,false))

        testlib.test(FIRSTPASS,"Conversation.find_from_pinfo() == nil",pcall(check_find_pinfo,nil,pinfo,false))
        testlib.test(FIRSTPASS,"Conversation.find_by_id() == nil",pcall(check_find_id,nil,frame_num,conv_type,conv_id,false))

        -- Test conversation creation. Ensure each is unique (i.e. newly created)
        testlib.test(FIRSTPASS,"Conversation.find_from_pinfo",unique_conv("pinfo", Conversation.find_from_pinfo(pinfo)))
        testlib.test(FIRSTPASS,"Conversation.find_by_id",unique_conv("id",Conversation.find_by_id(frame_num,conv_type,conv_id)))
        testlib.test(FIRSTPASS,"Conversation.find",unique_conv("full",Conversation.find(frame_num,conv_type,addr1,addr2,port1,port2)))

        local conv = Conversation.find_from_pinfo(pinfo)

        -- Check that nil is returned if no data has ever been assigned to the conversation
        testlib.test(FIRSTPASS,"conv[proto] == nil", conv[test_proto] == nil)

        -- Check that a non-table value can be stored to and retrieved from the conversation
        conv[test_proto] = 123
        testlib.test(FIRSTPASS,"conv[proto] number", type(conv[test_proto]) == "number")
        testlib.test(FIRSTPASS,"conv[proto] number", conv[test_proto] == 123)

        -- Check that clearing conversation data works as expected
        conv[test_proto] = nil
        testlib.test(FIRSTPASS,"conv[proto] nil", conv[test_proto] == nil)

        -- Check that a table value can be stored to and retrieved from the conversation
        local initial_table = {}
        conv[test_proto] = initial_table
        testlib.test(FIRSTPASS,"conv[proto] table", conv[test_proto] == initial_table)

        -- Check that pinfo.conversation is the same as Conversation.find_from_pinfo
        testlib.test(OTHER, "pinfo.conversation == Conversation.find_from_pinfo", check_find_pinfo(pinfo.conversation, pinfo, true))
    end

    -- Ensure each frame that returned conversations are still the same
    testlib.test(PER_FRAME,"existing conversation (pinfo)", existing_conv("pinfo", Conversation.find_from_pinfo(pinfo)))
    testlib.test(PER_FRAME,"existing conversation (id)", existing_conv("id", Conversation.find_by_id(frame_num, conv_type, conv_id)))
    testlib.test(PER_FRAME,"existing conversation (full)", existing_conv("full", Conversation.find(frame_num,conv_type,addr1,addr2,port1,port2)))

    local data = pinfo.conversation[test_proto]

    -- Check that data hasn't been cleared between frames, and is as expected
    testlib.test(PER_FRAME,"stored data (non-nil)", data ~= nil)
    testlib.test(PER_FRAME,"stored data (is table)", type(data) == "table")
    testlib.test(PER_FRAME,"stored data (len == n-1)", #data == testlib.getPktCount(FRAME)-1)
    if #data > 0 then
        testlib.test(PER_FRAME,"stored data (end == n-1)", data[#data] == testlib.getPktCount(FRAME)-1)
    end

    -- Store current frame number. Check number saved successfully.
    data[#data+1] = testlib.getPktCount(FRAME)
    testlib.test(PER_FRAME,"stored data", #data == testlib.getPktCount(FRAME))

    -- Note: There's no need store in conv[test_proto]. Tables are passed as references

    -- Reached end of frame
    testlib.pass(FRAME)
end

-- Replace default "IP" handler, so that no conversation is created. (The built in IP dissector
-- automatically registers a pinfo conversation).
DissectorTable.get("ethertype"):add(2048, test_proto)
