"""
Detect and replace instances of g_malloc() and wmem_alloc() with
g_new() wmem_new(), to improve the readability of Wireshark's code.

Also detect and replace instances of
g_malloc(sizeof(struct myobj) * foo)
with:
g_new(struct myobj, foo)
to better prevent integer overflows.

Also detect and replace instances of wmem_alloc()/wmem_alloc0()
with sizeof(type) * count or count * sizeof(type) with the overflow-safe
wmem_alloc_array()/wmem_alloc0_array() macros.

SPDX-License-Identifier: MIT
"""

import os
import re
import sys

print_replacement_info = True

patterns = [
# Replace (myobj *)g_malloc(sizeof(myobj)) with g_new(myobj, 1)
# Replace (struct myobj *)g_malloc(sizeof(struct myobj)) with g_new(struct myobj, 1)
(re.compile(r'\(\s*([struct]{0,6}\s*[^\s\*]+)\s*\*\s*\)\s*g_malloc(0?)\s*\(\s*sizeof\s*\(\s*\1\s*\)\s*\)'), r'g_new\2(\1, 1)'),

# Replace (myobj *)g_malloc(sizeof(myobj) * foo) with g_new(myobj, foo)
# Replace (struct myobj *)g_malloc(sizeof(struct myobj) * foo) with g_new(struct myobj, foo)
(re.compile(r'\(\s*([struct]{0,6}\s*[^\s\*]+)\s*\*\s*\)\s*g_malloc(0?)\s*\(\s*sizeof\s*\(\s*\1\s*\)\s*\*\s*([^\s]+)\s*\)'), r'g_new\2(\1, \3)'),

# Replace (myobj *)g_malloc(foo * sizeof(myobj)) with g_new(myobj, foo)
# Replace (struct myobj *)g_malloc(foo * sizeof(struct myobj)) with g_new(struct myobj, foo)
(re.compile(r'\(\s*([struct]{0,6}\s*[^\s\*]+)\s*\*\s*\)\s*g_malloc(0?)\s*\(\s*([^\s]+)\s*\*\s*sizeof\s*\(\s*\1\s*\)\s*\)'), r'g_new\2(\1, \3)'),

# Replace (myobj *)wmem_alloc(wmem_file_scope(), sizeof(myobj)) with wmem_new(wmem_file_scope(), myobj)
# Replace (struct myobj *)wmem_alloc(wmem_file_scope(), sizeof(struct myobj)) with wmem_new(wmem_file_scope(), struct myobj)
(re.compile(r'\(\s*([struct]{0,6}\s*[^\s\*]+)\s*\*\s*\)\s*wmem_alloc(0?)\s*\(\s*([_a-z\(\)->]+),\s*sizeof\s*\(\s*\1\s*\)\s*\)'), r'wmem_new\2(\3, \1)'),

# Replace (myobj *)wmem_alloc(scope, sizeof(myobj) * foo) with wmem_alloc_array(scope, myobj, foo)
# Replace (struct myobj *)wmem_alloc(scope, sizeof(struct myobj) * foo) with wmem_alloc_array(scope, struct myobj, foo)
# Replace (myobj *)wmem_alloc0(scope, sizeof(myobj) * foo) with wmem_alloc0_array(scope, myobj, foo)
# Replace (struct myobj *)wmem_alloc0(scope, sizeof(struct myobj) * foo) with wmem_alloc0_array(scope, struct myobj, foo)
(re.compile(r'\(\s*([struct]{0,6}\s*[^\s\*]+)\s*\*\s*\)\s*wmem_alloc(0?)\s*\(\s*([_a-z\(\)->]+),\s*sizeof\s*\(\s*\1\s*\)\s*\*\s*([^\s]+)\s*\)'), r'wmem_alloc\2_array(\3, \1, \4)'),

# Replace (myobj *)wmem_alloc(scope, foo * sizeof(myobj)) with wmem_alloc_array(scope, myobj, foo)
# Replace (struct myobj *)wmem_alloc(scope, foo * sizeof(struct myobj)) with wmem_alloc_array(scope, struct myobj, foo)
# Replace (myobj *)wmem_alloc0(scope, foo * sizeof(myobj)) with wmem_alloc0_array(scope, myobj, foo)
# Replace (struct myobj *)wmem_alloc0(scope, foo * sizeof(struct myobj)) with wmem_alloc0_array(scope, struct myobj, foo)
(re.compile(r'\(\s*([struct]{0,6}\s*[^\s\*]+)\s*\*\s*\)\s*wmem_alloc(0?)\s*\(\s*([_a-z\(\)->]+),\s*([^\s]+)\s*\*\s*sizeof\s*\(\s*\1\s*\)\s*\)'), r'wmem_alloc\2_array(\3, \1, \4)'),
]

def replace_file(fpath):
    with open(fpath, 'r', encoding='utf-8') as fh:
        fdata_orig = fh.read()
    fdata = fdata_orig
    for pattern, replacewith in patterns:
        fdata_out = pattern.sub(replacewith, fdata)
        if print_replacement_info and fdata != fdata_out:
            for match in re.finditer(pattern, fdata):
                replacement = re.sub(pattern, replacewith, match.group(0))
                print(f"Bad malloc pattern in {fpath}: Replace '{match.group(0)}' with '{replacement}'")
        fdata = fdata_out  
    if fdata_out != fdata_orig:
        with open(fpath, 'w') as fh:
            fh.write(fdata_out)
    return fdata_out

def run_specific_files(fpaths):
    for fpath in fpaths:
        if not fpath.endswith(('.c', '.cpp')):
            continue
        replace_file(fpath)

def run_recursive(root_dir):
    for root, dirs, files in os.walk(root_dir):
        fpaths = []
        for fname in files:
            fpath = os.path.join(root, fname)
            fpaths.append(fpath)
        run_specific_files(fpaths)

def test_replacements():
    test_string = """\
(if_info_t*) g_malloc0(sizeof(if_info_t))
(oui_info_t *)g_malloc(sizeof (oui_info_t))
(uint8_t *)g_malloc(16 * sizeof(uint8_t))
(uint32_t *)g_malloc(sizeof(uint32_t)*2)
(struct imf_field *)g_malloc (sizeof (struct imf_field))
(rtspstat_t *)g_malloc( sizeof(rtspstat_t) )
(proto_data_t *)wmem_alloc(scope, sizeof(proto_data_t))
(giop_sub_handle_t *)wmem_alloc(wmem_epan_scope(), sizeof (giop_sub_handle_t))
(mtp3_addr_pc_t *)wmem_alloc0(pinfo->pool, sizeof(mtp3_addr_pc_t))
(dcerpc_bind_value *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_bind_value))
(dcerpc_matched_key *)wmem_alloc(wmem_file_scope(), sizeof (dcerpc_matched_key));
(struct smtp_session_state *)wmem_alloc0(wmem_file_scope(), sizeof(struct smtp_session_state))
(struct batman_packet_v5 *)wmem_alloc(pinfo->pool, sizeof(struct batman_packet_v5))
(struct knx_keyring_mca_keys*) wmem_alloc( wmem_epan_scope(), sizeof( struct knx_keyring_mca_keys ) )
(wmem_tree_key_t *)wmem_alloc(pool, sizeof(wmem_tree_key_t)*6)
(md4_pass *)wmem_alloc0(pool, nb_pass*sizeof(md4_pass))
(uint32_t *)wmem_alloc(pinfo->pool, fcount*sizeof(uint32_t))
(ws_in6_addr *)wmem_alloc0(pinfo->pool, table_length * sizeof(ws_in6_addr))
(uint8_t *)wmem_alloc(pinfo->pool, 512 * sizeof(uint8_t))
(uint16_t *)wmem_alloc(pinfo->pool, 513 * sizeof(uint16_t))
"""
    expected_output = """\
g_new0(if_info_t, 1)
g_new(oui_info_t, 1)
g_new(uint8_t, 16)
g_new(uint32_t, 2)
g_new(struct imf_field, 1)
g_new(rtspstat_t, 1)
wmem_new(scope, proto_data_t)
wmem_new(wmem_epan_scope(), giop_sub_handle_t)
wmem_new0(pinfo->pool, mtp3_addr_pc_t)
wmem_new(wmem_file_scope(), dcerpc_bind_value)
wmem_new(wmem_file_scope(), dcerpc_matched_key);
wmem_new0(wmem_file_scope(), struct smtp_session_state)
wmem_new(pinfo->pool, struct batman_packet_v5)
wmem_new(wmem_epan_scope(), struct knx_keyring_mca_keys)
wmem_alloc_array(pool, wmem_tree_key_t, 6)
wmem_alloc0_array(pool, md4_pass, nb_pass)
wmem_alloc_array(pinfo->pool, uint32_t, fcount)
wmem_alloc0_array(pinfo->pool, ws_in6_addr, table_length)
wmem_alloc_array(pinfo->pool, uint8_t, 512)
wmem_alloc_array(pinfo->pool, uint16_t, 513)
"""
    output = test_string
    for pattern, replacewith in patterns:
        output = pattern.sub(replacewith, output)
    assert(output == expected_output)

def main():
    test_replacements()
    if len(sys.argv) == 2:
        root_dir = sys.argv[1]
        run_recursive(root_dir)
    else:
        fpaths = []
        for line in sys.stdin:
            line = line.strip()
            if line:
                fpaths.append(line)
        run_specific_files(fpaths)

if __name__ == "__main__":
    main()
