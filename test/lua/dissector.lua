----------------------------------------
-- script-name: dns_dissector.lua
-- author: Hadriel Kaplan <hadrielk at yahoo dot com>
-- Copyright (c) 2014, Hadriel Kaplan
-- This code is in the Public Domain, or the BSD (3 clause) license if Public Domain does not apply
-- in your country.
--
-- BACKGROUND:
-- This is an example Lua script for a protocol dissector. The purpose of this script is two-fold:
-- * To provide a reference tutorial for others writing Wireshark dissectors in Lua
-- * To test various functions being called in various ways, so this script can be used in the test-suites
-- I've tried to meet both of those goals, but it wasn't easy. No doubt some folks will wonder why some
-- functions are called some way, or differently than previous invocations of the same function. I'm trying to
-- to show both that it can be done numerous ways, but also I'm trying to test those numerous ways, and my more
-- immediate need is for test coverage rather than tutorial guide. (the Lua API is sorely lacking in test scripts)
--
-- OVERVIEW:
-- This script creates an elementary dissector for DNS. It's neither comprehensive nor error-free with regards
-- to the DNS protocol. That's OK. The goal isn't to fully dissect DNS properly - Wireshark already has a good
-- DNS dissector built-in. We don't need another one. We also have other example Lua scripts, but I don't think
-- they do a good job of explaining things, and the nice thing about this one is getting capture files to
-- run it against is trivial. (plus I uploaded one)
--
-- HOW TO RUN THIS SCRIPT:
-- Wireshark and Tshark support multiple ways of loading Lua scripts: through a dofile() call in init.lua,
-- through the file being in either the global or personal plugins directories, or via the command line.
-- See the Wireshark USer's Guide chapter on Lua (http://www.wireshark.org/docs/wsug_html_chunked/wsluarm.html).
-- Once the script is loaded, it creates a new protocol named "MyDNS" (or "MYDNS" in some places).  If you have
-- a capture file with DNS packets in it, simply select one in the Packet List pane, right-click on it, and
-- select "Decode As ...", and then in the dialog box that shows up scroll down the list of protocols to one
-- called "MYDNS", select that and click the "ok" or "apply" button.  Voila`, you're now decoding DNS packets
-- using the simplistic dissector in this script.  Another way is to download the capture file made for
-- this script, and open that - since the DNS packets in it use UDP port 65333 (instead of the default 53),
-- and since the MyDNS protocol in this script has been set to automatically decode UDP port 65333, it will
-- automagically do it without doing "Decode As ...".
--
----------------------------------------
-- debug printer, set DEBUG to true to enable printing debug info
-- set DEBUG2 to true to enable really verbose printing
local DEBUG, DEBUG2 = false, false

local dprint = function() end
local dprint2 = function() end
if DEBUG or DEBUG2 then
    dprint = function(...)
        print(table.concat({"Lua:", ...}," "))
    end

    if DEBUG2 then
        dprint2 = dprint
    end
end

dprint2("Wireshark version = ", get_version())
dprint2("Lua version = ", _VERSION)

----------------------------------------
-- Unfortunately, the older Wireshark/Tshark versions have bugs, and part of the point
-- of this script is to test those bugs are now fixed.  So we need to check the version
-- end error out if it's too old.
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your Wireshark/Tshark version ("..get_version()..") is too old for this script!\n"..
                "This script needs Wireshark/Tshark version 1.11.3 or higher.\n" )
end
----------------------------------------


----------------------------------------
-- creates a Proto object, but doesn't register it yet
local dns = Proto("mydns","MyDNS Protocol")

----------------------------------------
-- multiple ways to do the same thing: create a protocol field (but not register it yet)
-- the abbreviation should always have "<myproto>." before the specific abbreviation, to avoid collisions
local pf_trasaction_id      = ProtoField.new("Transaction ID", "mydns.trans_id", ftypes.UINT16)
local pf_flags              = ProtoField.new("Flags", "mydns.flags", ftypes.UINT16, nil, base.HEX)
local pf_num_questions      = ProtoField.uint16("mydns.num_questions", "Number of Questions")
local pf_num_answers        = ProtoField.uint16("mydns.num_answers", "Number of Answer RRs")
local pf_num_authority_rr   = ProtoField.uint16("mydns.num_authority_rr", "Number of Authority RRs")
local pf_num_additional_rr  = ProtoField.uint16("mydns.num_additional_rr", "Number of Additional RRs")

-- within the flags field, we want to parse/show the bits separately
-- note the "base" argument becomes the size of the bitmask'ed field when ftypes.BOOLEAN is used
-- the "mask" argument is which bits we want to use for this field (e.g., base=16 and mask=0x8000 means we want the top bit of a 16-bit field)
-- again the following shows different ways of doing the same thing basically
local pf_flag_response              = ProtoField.new("Response", "mydns.flags.response", ftypes.BOOLEAN, {"this is a response","this is a query"}, 16, 0x8000, "is the message a response?")
local pf_flag_opcode                = ProtoField.new("Opcode", "mydns.flags.opcode", ftypes.UINT16, nil, base.DEC, 0x7800, "operation code")
local pf_flag_authoritative         = ProtoField.new("Authoritative", "mydns.flags.authoritative", ftypes.BOOLEAN, nil, 16, 0x0400, "is the response authoritative?")
local pf_flag_truncated             = ProtoField.bool("mydns.flags.truncated", "Truncated", 16, nil, 0x0200, "is the message truncated?")
local pf_flag_recursion_desired     = ProtoField.bool("mydns.flags.recursion_desired", "Recursion desired", 16, {"yes","no"}, 0x0100, "do the query recursivley?")
local pf_flag_recursion_available   = ProtoField.bool("mydns.flags.recursion_available", "Recursion available", 16, nil, 0x0080, "does the server support recursion?")
local pf_flag_z                     = ProtoField.uint16("mydns.flags.z", "World War Z - Reserved for future use", base.HEX, nil, 0x0040, "when is it the future?")
local pf_flag_authenticated         = ProtoField.bool("mydns.flags.authenticated", "Authenticated", 16, {"yes","no"}, 0x0020, "did the server DNSSEC authenticate?")
local pf_flag_checking_disabled     = ProtoField.bool("mydns.flags.checking_disabled", "Checking disabled", 16, nil, 0x0010)

-- no, these aren't all the DNS response codes - this is just an example
local rcodes = {
        [0] = "No Error",
        [1] = "Format Error",
        [2] = "Server Failure",
        [3] = "Non-Existent Domain",
        [9] = "Server Not Authoritative for zone"
}
-- the above rcodes table is used in this next ProtoField
local pf_flag_rcode         = ProtoField.uint16("mydns.flags.rcode", "Response code", base.DEC, rcodes, 0x000F)
local pf_query              = ProtoField.new("Query", "mydns.query", ftypes.BYTES)
local pf_query_name         = ProtoField.new("Name", "mydns.query.name", ftypes.STRING)
local pf_query_name_len     = ProtoField.new("Name Length", "mydns.query.name.len", ftypes.UINT8)
local pf_query_label_count  = ProtoField.new("Label Count", "mydns.query.label.count", ftypes.UINT8)
local rrtypes = { [1] = "A (IPv4 host address)", [2] = "NS (authoritative name server)", [28] = "AAAA (for geeks only)" }
local pf_query_type         = ProtoField.uint16("mydns.query.type", "Type", base.DEC, rrtypes)
-- again, not all class types are listed here
local classes = {
        [0] = "Reserved",
        [1] = "IN (Internet)",
        [2] = "The 1%",
        [5] = "First class",
        [6] = "Business class",
        [65535] = "Cattle class"
}
local pf_query_class        = ProtoField.uint16("mydns.query.class", "Class", base.DEC, classes, nil, "keep it classy folks")

----------------------------------------
-- this actually registers the ProtoFields above, into our new Protocol
-- in a real script I wouldn't do it this way; I'd build a table of fields programmatically
-- and then set dns.fields to it, so as to avoid forgetting a field
dns.fields = { pf_trasaction_id, pf_flags,
    pf_num_questions, pf_num_answers, pf_num_authority_rr, pf_num_additional_rr,
    pf_flag_response, pf_flag_opcode, pf_flag_authoritative,
    pf_flag_truncated, pf_flag_recursion_desired, pf_flag_recursion_available,
    pf_flag_z, pf_flag_authenticated, pf_flag_checking_disabled, pf_flag_rcode,
    pf_query, pf_query_name, pf_query_name_len, pf_query_label_count, pf_query_type, pf_query_class }

----------------------------------------
-- create some expert info fields
local ef_query     = ProtoExpert.new("mydns.query.expert", "DNS query message",
                                     expert.group.REQUEST_CODE, expert.severity.CHAT)
local ef_response  = ProtoExpert.new("mydns.response.expert", "DNS response message",
                                     expert.group.RESPONSE_CODE, expert.severity.CHAT)
local ef_ultimate  = ProtoExpert.new("mydns.response.ultimate.expert", "DNS answer to life, the universe, and everything",
                                     expert.group.COMMENTS_GROUP, expert.severity.NOTE)
-- some error expert info's
local ef_too_short = ProtoExpert.new("mydns.too_short.expert", "DNS message too short",
                                     expert.group.MALFORMED, expert.severity.ERROR)
local ef_bad_query = ProtoExpert.new("mydns.query.missing.expert", "DNS query missing or malformed",
                                     expert.group.MALFORMED, expert.severity.WARN)

-- register them
dns.experts = { ef_query, ef_too_short, ef_bad_query, ef_response, ef_ultimate }

----------------------------------------
-- we don't just want to display our protocol's fields, we want to access the value of some of them too!
-- There are several ways to do that.  One is to just parse the buffer contents in Lua code to find
-- the values.  But since ProtoFields actually do the parsing for us, and can be retrieved using Field
-- objects, it's kinda cool to do it that way. So let's create some Fields to extract the values.
-- The following creates the Field objects, but they're not 'registered' until after this script is loaded.
-- Also, these lines can't be before the 'dns.fields = ...' line above, because the Field.new() here is
-- referencing fields we're creating, and they're not "created" until that line above.
-- Furthermore, you cannot put these 'Field.new()' lines inside the dissector function.
-- Before Wireshark version 1.11, you couldn't even do this concept (of using fields you just created).
local questions_field       = Field.new("mydns.num_questions")
local query_type_field      = Field.new("mydns.query.type")
local query_class_field     = Field.new("mydns.query.class")
local response_field        = Field.new("mydns.flags.response")

-- here's a little helper function to access the response_field value later.
-- Like any Field retrieval, you can't retrieve a field's value until its value has been
-- set, which won't happen until we actually use our ProtoFields in TreeItem:add() calls.
-- So this isResponse() function can't be used until after the pf_flag_response ProtoField
-- has been used inside the dissector.
-- Note that calling the Field object returns a FieldInfo object, and calling that
-- returns the value of the field - in this case a boolean true/false, since we set the
-- "mydns.flags.response" ProtoField to ftype.BOOLEAN way earlier when we created the
-- pf_flag_response ProtoField.  Clear as mud?
--
-- A shorter version of this function would be:
-- local function isResponse() return response_field()() end
-- but I though the below is easier to understand.
local function isResponse()
    local response_fieldinfo = response_field()
    return response_fieldinfo()
end


----------------------------------------
---- some constants for later use ----
-- the DNS header size
local DNS_HDR_LEN = 12

-- the smallest possible DNS query field size
-- has to be at least a label length octet, label character, label null terminator, 2-bytes type and 2-bytes class
local MIN_QUERY_LEN = 7

-- the UDP port number we want to associate with our protocol
local MYDNS_PROTO_UDP_PORT = 65333

----------------------------------------
-- some forward "declarations" of helper functions we use in the dissector
-- I don't usually use this trick, but it'll help reading/grok'ing this script I think
-- if we don't focus on them.
local getQueryName


----------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "dns.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function dns.dissector(tvbuf,pktinfo,root)
    dprint2("dns.dissector called")

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("MYDNS")

    -- We want to check that the packet size is rational during dissection, so let's get the length of the
    -- packet buffer (Tvb).
    -- Because DNS has no additional payload data other than itself, and it rides on UDP without padding,
    -- we can use tvb:len() or tvb:reported_len() here; but I prefer tvb:reported_length_remaining() as it's safer.
    local pktlen = tvbuf:reported_length_remaining()

    -- We start by adding our protocol to the dissection display tree.
    -- A call to tree:add() returns the child created, so we can add more "under" it using that return value.
    -- The second argument is how much of the buffer/packet this added tree item covers/represents - in this
    -- case (DNS protocol) that's the remainder of the packet.
    local tree = root:add(dns, tvbuf:range(0,pktlen))

    -- now let's check it's not too short
    if pktlen < DNS_HDR_LEN then
        -- since we're going to add this protocol to a specific UDP port, we're going to
        -- assume packets in this port are our protocol, so the packet being too short is an error
        -- the old way: tree:add_expert_info(PI_MALFORMED, PI_ERROR, "packet too short")
        -- the correct way now:
        tree:add_proto_expert_info(ef_too_short)
        dprint("packet length",pktlen,"too short")
        return
    end

    -- Now let's add our transaction id under our dns protocol tree we just created.
    -- The transaction id starts at offset 0, for 2 bytes length.
    tree:add(pf_trasaction_id, tvbuf:range(0,2))

    -- We'd like to put the transaction id number in the GUI row for this packet, in its
    -- INFO column/cell.  First we need the transaction id value, though.  Since we just
    -- dissected it with the previous code line, we could now get it using a Field's
    -- FieldInfo extractor, but instead we'll get it directly from the TvbRange just
    -- to show how to do that.  We'll use Field/FieldInfo extractors later on...
    local transid = tvbuf:range(0,2):uint()
    pktinfo.cols.info:set("(".. transid ..")")

    -- now let's add the flags, which are all in the packet bytes at offset 2 of length 2
    -- instead of calling this again and again, let's just use a variable
    local flagrange = tvbuf:range(2,2)

    -- for our flags field, we want a sub-tree
    local flag_tree = tree:add(pf_flags, flagrange)
        -- I'm indenting this for clarity, because it's adding to the flag's child-tree

        -- let's add the type of message (query vs. response)
        local query_flag_tree = flag_tree:add(pf_flag_response, flagrange)

        -- let's also add an expert info about it
        if isResponse() then
            query_flag_tree:add_proto_expert_info(ef_response, "It's a response!")
            if transid == 42 then
                tree:add_tvb_expert_info(ef_ultimate, tvbuf:range(0,2))
            end
        else
            query_flag_tree:add_proto_expert_info(ef_query)
        end

        -- we now know if it's a response or query, so let's put that in the
        -- GUI packet row, in the INFO column cell
        -- this line of code uses a Lua trick for doing something similar to
        -- the C/C++ 'test ? true : false' shorthand
        pktinfo.cols.info:prepend(isResponse() and "Response " or "Query ")

        flag_tree:add(pf_flag_opcode, flagrange)

        if isResponse() then
            flag_tree:add(pf_flag_authoritative, flagrange)
        end

        flag_tree:add(pf_flag_truncated, flagrange)

        if isResponse() then
            flag_tree:add(pf_flag_recursion_available, flagrange)
        else
            flag_tree:add(pf_flag_recursion_desired, flagrange)
        end

        flag_tree:add(pf_flag_z, flagrange)

        if isResponse() then
            flag_tree:add(pf_flag_authenticated, flagrange)
            flag_tree:add(pf_flag_rcode, flagrange)
        end

        flag_tree:add(pf_flag_checking_disabled, flagrange)

    -- now add more to the main mydns tree
    tree:add(pf_num_questions, tvbuf:range(4,2))
    tree:add(pf_num_answers, tvbuf:range(6,2))
    -- another way to get a TvbRange is just to call the Tvb like this
    tree:add(pf_num_authority_rr, tvbuf(8,2))
    -- or if we're crazy, we can create a sub-TvbRange, from a sub-TvbRange of the TvbRange
    tree:add(pf_num_additional_rr, tvbuf:range(10,2):range()())

    local num_queries = questions_field()()
    local pos = DNS_HDR_LEN

    if num_queries > 0 then
        -- let's create a sub-tree, using a plain text description (not a field from the packet)
        local queries_tree = tree:add("Queries")

        local pktlen_remaining = pktlen - pos

        while num_queries > 0 and pktlen_remaining > 0 do
            if pktlen_remaining < MIN_QUERY_LEN then
                -- old way: queries_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "query field missing or too short")
                queries_tree:add_proto_expert_info(ef_bad_query)
                return
            end

            -- we don't know how long this query field in total is, so we have to parse it first before
            -- adding it to the tree, because we want to identify the correct bytes it covers
            local label_count, name, name_len = getQueryName(tvbuf:range(pos,pktlen_remaining))
            if not label_count then
                q_tree:add_expert_info(PI_MALFORMED, PI_ERROR, name)
                return
            end

            -- now add the first query to the 'Queries' child tree we just created
            -- we're going to change the string generated by this later, after we figure out the subsequent fields.
            -- the whole query field is the query name field length we just got, plus the 20 byte type and 2-byte class
            local q_tree = queries_tree:add(pf_query, tvbuf:range(pos, name_len + 4))

            q_tree:add(pf_query_name, tvbuf:range(pos, name_len), name)
            pos = pos + name_len

            pktinfo.cols.info:append(" "..name)

            -- the following tree items are generated by us, not encoded in the packet per se, so mark them as such
            q_tree:add(pf_query_name_len, name_len):set_generated()
            q_tree:add(pf_query_label_count, label_count):set_generated()

            q_tree:add(pf_query_type, tvbuf:range(pos, 2))
            q_tree:add(pf_query_class, tvbuf:range(pos + 2, 2))
            pos = pos + 4

            -- now change the query text
            q_tree:set_text(name..": type "..query_type_field().display ..", class "..query_class_field().display)

            pktlen_remaining = pktlen_remaining - (name_len + 4)
            num_queries = num_queries - 1
        end  -- end of while loop

        if num_queries > 0 then
            -- we didn't process them all
            queries_tree:add_expert_info(PI_MALFORMED, PI_ERROR, num_queries .. " query field(s) missing")
            return
        end
    end

    dprint2("dns.dissector returning",pos)

    -- tell wireshark how much of tvbuff we dissected
    return pos
end

----------------------------------------
-- we want to have our protocol dissection invoked for a specific UDP port,
-- so get the udp dissector table and add our protocol to it
local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(MYDNS_PROTO_UDP_PORT, dns)

----------------------------------------
-- we also want to add the heuristic dissector, for any UDP protocol
-- first we need a heuristic dissection function
-- this is that function - when wireshark invokes this, it will pass in the same
-- things it passes in to the "dissector" function, but we only want to actually
-- dissect it if it's for us, and we need to return true if it's for us, or else false
-- figuring out if it's for us or not is not easy
-- we need to try as hard as possible, or else we'll think it's for us when it's
-- not and block other heuristic dissectors from getting their chance
--
-- in practice, you'd never set a dissector like this to be heuristic, because there
-- just isn't enough information to safely detect if it's DNS or not
-- but I'm doing it to show how it would be done
--
-- Note: this heuristic stuff is new in 1.11.3
local function heur_dissect_dns(tvbuf,pktinfo,root)
    dprint2("heur_dissect_dns called")

    if tvbuf:len() < DNS_HDR_LEN then
        dprint("heur_dissect_dns: tvb shorter than DNS_HDR_LEN of:",DNS_HDR_LEN)
        return false
    end

    local tvbr = tvbuf:range(0,DNS_HDR_LEN)

    -- the first 2 bytes are transaction id, which can be anything so no point in checking those
    -- the next 2 bytes contain flags, a couple of which have some values we can check against

    -- the opcode has to be 0, 1, 2, 4 or 5
    -- the opcode field starts at bit offset 17 (in C-indexing), for 4 bits in length
    local check = tvbr:bitfield(17,4)
    if check == 3 or check > 5 then
        dprint("heur_dissect_dns: invalid opcode:",check)
        return false
    end

    -- the rcode has to be 0-10, 16-22 (we're ignoring private use rcodes here)
    -- the rcode field starts at bit offset 28 (in C-indexing), for 4 bits in length
    check = tvbr:bitfield(28,4)
    if check > 22 or (check > 10 and check < 16) then
        dprint("heur_dissect_dns: invalid rcode:",check)
        return false
    end

    dprint2("heur_dissect_dns checking questions/answers")

    -- now let's verify the number of questions/answers are reasonable
    check = tvbr:range(4,2):uint()  -- num questions
    if check > 100 then return false end
    check = tvbr:range(6,2):uint()  -- num answers
    if check > 100 then return false end
    check = tvbr:range(8,2):uint()  -- num authority
    if check > 100 then return false end
    check = tvbr:range(10,2):uint()  -- num additional
    if check > 100 then return false end

    dprint2("heur_dissect_dns: everything looks good calling the real dissector")

    -- don't do this line in your script - I'm just doing it so our test-suite can
    -- verify this script
    root:add("Heuristic dissector used"):set_generated()

    -- ok, looks like it's ours, so go dissect it
    -- note: calling the dissector directly like this is new in 1.11.3
    -- also note that calling a Dissector object, as this does, means we don't
    -- get back the return value of the dissector function we created previously
    -- so it might be better to just call the function directly instead of doing
    -- this, but this script is used for testing and this tests the call() function
    dns.dissector(tvbuf,pktinfo,root)

    -- since this is over a transport protocol, such as UDP, we can set the
    -- conversation to make it sticky for our dissector, so that all future
    -- packets to/from the same address:port pair will just call our dissector
    -- function directly instead of this heuristic function
    -- this is a new attribute of pinfo in 1.11.3
    pktinfo.conversation = dns

    return true
end

-- now register that heuristic dissector into the udp heuristic list
dns:register_heuristic("udp",heur_dissect_dns)

-- We're done!
-- our protocol (Proto) gets automatically registered after this script finishes loading
----------------------------------------

----------------------------------------
-- DNS query names are not just null-terminated strings; they're actually a sequence of
-- 'labels', with a length octet before each one.  So "foobar.com" is actually the
-- string "\06foobar\03com\00".  We could create a ProtoField for label_length and label_name
-- or whatever, but since this is an example script I'll show how to do it in raw code.
-- This function is given the TvbRange object from the dissector() function, and needs to
-- parse it.
-- On success, it returns three things: the number of labels, the name string, and how
-- many bytes it covered of the buffer (which is always 2 more than the name length in this case).
-- On failure, it returns nil and the error message.
getQueryName = function (tvbr)
    local label_count = 0
    local name = ""

    local len_remaining = tvbr:len()
    if len_remaining < 2 then
        -- it's too short
        return nil, "invalid name"
    end

    local barray = tvbr:bytes() -- gets a ByteArray of the TvbRange
    local pos = 0 -- unlike Lua, ByteArray uses 0-based indexing

    -- get the first octet/label-length
    local label_len = barray:get_index(pos)
    if label_len == 0 then
        return nil, "invalid initial label length of 0"
    end

    while label_len > 0 do
        if label_len >= len_remaining then
            return nil, "invalid label length of "..label_len
        end
        pos = pos + 1  -- move past label length octet
        -- append the label and a dot to name string
        -- note: this uses the new method of ByteArray:raw(), added in 1.11.3
        name = name .. barray:raw(pos, label_len) .. "."
        len_remaining = len_remaining - (label_len + 1) -- subtract label and its length octet
        label_count = label_count + 1
        pos = pos + label_len -- move past label
        label_len = barray:get_index(pos)
    end

    -- we appended an extra dot, so get rid of it
    name = name:sub(1, -2)

    return label_count, name, name:len() + 2
end

