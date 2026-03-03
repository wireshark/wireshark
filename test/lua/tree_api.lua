-- test script for TreeItem traversal APIs
-- use with dns_port.pcap in test/captures directory
local testlib = require("testlib")

local TREE = "tree"

local ip_src = Field.new("ip.src")
local ip_dst = Field.new("ip.dst")

testlib.init({
    [TREE] = 12,
})

local tree_proto = Proto("tree_api", "Tree API Tests")
local numinits = 0
local ran_tests = false

local function count_children(iter)
    local count = 0
    for _ in iter do
        count = count + 1
    end
    return count
end

function tree_proto.init()
    numinits = numinits + 1
    if numinits == 2 then
        testlib.getResults()
    end
end

function tree_proto.dissector(tvb, pinfo, tree)
    if ran_tests then
        return
    end

    ran_tests = true
    testlib.testing(TREE, "TreeItem traversal")

    local child_count = tree:get_child_count()
    testlib.test(TREE, "root_has_children", child_count > 0)

    local first_child = child_count > 0 and tree:get_child(0) or nil
    testlib.test(TREE, "first_child_not_nil", first_child ~= nil)

    local parent = first_child and first_child:get_parent() or nil
    testlib.test(TREE, "parent_not_nil", parent ~= nil)

    testlib.test(TREE, "get_child_negative_index", not pcall(function() tree:get_child(-1) end))
    testlib.test(TREE, "get_child_out_of_range", tree:get_child(child_count) == nil)

    local direct_count = count_children(tree:children())
    testlib.test(TREE, "children_direct_count", direct_count == child_count)

    local recursive_count = count_children(tree:children(nil, true))
    testlib.test(TREE, "children_recursive_count", recursive_count >= child_count)

    testlib.test(TREE, "children_bad_filter_type", not pcall(function() tree:children(123) end))
    testlib.test(TREE, "children_bad_filter_entry", not pcall(function() tree:children({"ip.src", 1}) end))
    testlib.test(TREE, "children_bad_recursive_type", not pcall(function() tree:children("ip.src", "nope") end))

    local ip_src_count = count_children(tree:children("ip.src", true))
    testlib.test(TREE, "children_ip_src_count", ip_src_count > 0)

    local ip_src_item = nil
    for child in tree:children("ip.src", true) do
        ip_src_item = child
        break
    end
    local finfo = ip_src_item and ip_src_item:get_field_info() or nil
    testlib.test(TREE, "field_info_ip_src", finfo and finfo.name == "ip.src")
end

register_postdissector(tree_proto)
