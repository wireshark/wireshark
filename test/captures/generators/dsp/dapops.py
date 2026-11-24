# Helper module for the dsp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""The DAP operation and error builders of dap-coverage/mkdap.py (ops()
and errors(), copied unchanged); mkdsp.py hands them a ChainedAssoc that
wraps every argument and result in its chained DSP form."""

from x500lib import (
    access_point, AT_CN, AT_GN, AT_OC, AT_SN, AT_TEL, attribute, ava, BITS, BOOL, common_args,
    common_results, continuation_reference, DN_ALICE, DN_BOB, DN_ORG, DN_ROOT, eis,
    entry_information, ENUM, f_item, f_not, f_or, fi_equality, fi_present, fi_substrings,
    FILTER_BIG, INT, join_argument, NULL, OC_PERSON, OID, paged_new, paged_ref, poq, PSTR, R_CN2,
    R_MULTI, R_OU, rdn, relaxation, SEQ, SET, signed, tlv, UTF8, X,
)


READ, COMPARE, ABANDON, LIST, SEARCH, ADD, REMOVE, MODIFY, MODIFYDN = range(1, 10)
E_ATTR, E_NAME, E_SERVICE, E_REFERRAL, E_ABANDONED, E_SECURITY, E_ABANDONFAILED, E_UPDATE = range(1, 9)


def ops(d):
    """Every operation with its unsigned and signed argument and result."""
    # read: every field of the argument and of the result
    read_full = SET(X(0, DN_ALICE), X(1, eis(0)), X(2, BOOL(True)), common_args(True))
    modify_rights = SET(SEQ(X(0, NULL()), X(3, BITS(4, b'\xf0'))),
                        SEQ(X(1, OID(AT_CN)), X(3, BITS(6, b'\xc0'))),
                        SEQ(X(2, ava(AT_CN, PSTR('Alice Smith'))), X(3, BITS(7, b'\x80'))))
    read_res = SET(X(0, entry_information()), X(1, modify_rights), common_results(True))
    d.op(READ, read_full, read_res)
    # alternate common arguments / results; the root name
    d.op(READ, SET(X(0, DN_ROOT), X(1, eis(1)), common_args(True, alt=True)),
         SET(X(0, entry_information(DN_ROOT, False)), common_results(True, alt=True)))
    # signed argument and result
    d.op(READ, signed(SET(X(0, DN_BOB), X(1, eis(2)))),
         signed(SET(X(0, entry_information(DN_BOB, False)))))

    # compare
    cmp_arg = SET(X(0, DN_ALICE), X(1, ava(AT_CN, PSTR('Alice Smith'), 'all')), common_args(True))
    cmp_res = SET(DN_ALICE, X(0, BOOL(True)), X(1, BOOL(False)), X(2, OID(AT_CN)), common_results(True))
    d.op(COMPARE, cmp_arg, cmp_res)
    d.op(COMPARE, signed(SET(X(0, DN_BOB), X(1, ava(AT_SN, UTF8('Jones'))))),
         signed(SET(X(0, BOOL(False)))))

    # abandon: result NULL, unsigned and signed information
    d.op(ABANDON, SEQ(X(0, INT(1))), NULL())
    d.op(ABANDON, signed(SEQ(X(0, INT(2))), tag=0),
         SEQ(INT(2), common_results(True)))
    d.op(ABANDON, SEQ(X(0, INT(3))), signed(SEQ(INT(3)), tag=0))

    # list: new paged request, printable and binary query references,
    # listInfo with every field, uncorrelated, signed
    list_res = SET(DN_ORG,
                   X(1, SET(SEQ(R_OU, X(0, BOOL(True)), X(1, BOOL(False))),
                            SEQ(R_MULTI))),
                   X(2, poq(7)), common_results(True))
    d.op(LIST, SET(X(0, DN_ORG), X(1, paged_new()), X(2, BOOL(True)), common_args(True)), list_res)
    d.op(LIST, SET(X(0, DN_ORG), X(1, paged_ref(b'cookie-1'))),
         X(0, SET(SET(X(1, SET(SEQ(R_OU)))), signed(SET(X(1, SET()))))))
    d.op(LIST, signed(SET(X(0, DN_ORG), X(1, paged_ref(b'\x00\x01\xfe\xff')))),
         signed(SET(DN_ORG, X(1, SET()), X(2, SET(X(8, INT(3)))))))

    # a constructed query reference without segments (no value tvb)
    d.op(LIST, SET(X(0, DN_ORG), X(1, tlv(0x24, b''))), SET(X(1, SET())))

    # search: every field, each subset, every filter item, joins
    s_full = SET(X(0, DN_ORG), X(1, INT(2)), X(2, FILTER_BIG), X(3, BOOL(False)),
                 X(4, eis(0)), X(5, paged_new()), X(6, BOOL(True)),
                 X(7, f_item(fi_present(AT_CN))), X(8, BOOL(True)),
                 X(9, relaxation()), X(10, INT(3)), X(11, BITS(6, b'\xff\xc0')),
                 X(12, BITS(4, b'\xff\xf0')), X(13, SEQ(join_argument())),
                 X(14, ENUM(2)), common_args(True))
    s_res = SET(DN_ORG, X(0, SET(entry_information(), entry_information(DN_BOB, False))),
                X(2, poq(9)), X(3, BOOL(True)), common_results(True))
    d.op(SEARCH, s_full, s_res)
    d.op(SEARCH, SET(X(0, DN_ORG), X(1, INT(1)), X(2, f_item(fi_equality(None)))),
         X(0, SET(SET(X(0, SET())), signed(SET(X(0, SET(entry_information(DN_BOB, False))))))))
    d.op(SEARCH, SET(X(0, DN_ORG), X(1, INT(0))),
         signed(SET(X(0, SET()), X(2, SET(X(0, INT(0)))))))
    d.op(SEARCH, SET(X(0, DN_ORG), X(1, INT(7))), SET(X(0, SET())))
    # substrings any [1] and final [2] (bodies not implemented)
    d.op(SEARCH, SET(X(0, DN_ORG), X(2, f_item(fi_substrings(X(1, PSTR('li')), X(2, PSTR('ce')))))),
         SET(X(0, SET())))
    d.op(SEARCH, signed(SET(X(0, DN_ORG), X(2, f_not(f_or()))), ), None,
         (E_SERVICE, SET(X(0, INT(3)))))

    # addEntry
    add_arg = SET(X(0, DN_BOB),
                  X(1, SET(attribute(AT_OC, OID(OC_PERSON)),
                           attribute(AT_CN, PSTR('Bob Jones')),
                           attribute(AT_SN, UTF8('Jones')))),
                  X(2, access_point()), common_args(True))
    d.op(ADD, add_arg, NULL())
    d.op(ADD, signed(SET(X(0, DN_BOB), X(1, SET(attribute(AT_CN, PSTR('Bob')))))),
         SEQ(common_results(True)))
    d.op(ADD, SET(X(0, DN_BOB), X(1, SET())), signed(SEQ(), tag=0))

    # removeEntry
    d.op(REMOVE, SET(X(0, DN_BOB), common_args(True)), NULL())
    d.op(REMOVE, signed(SET(X(0, DN_BOB))), SEQ(common_results(True)))
    d.op(REMOVE, SET(X(0, DN_BOB)), signed(SEQ(), tag=0))

    # modifyEntry: every kind of modification
    changes = SEQ(X(0, attribute(AT_TEL, PSTR('+61 7 5555 0100'))),
                  X(1, OID(AT_GN)),
                  X(2, attribute(AT_CN, PSTR('Ally'))),
                  X(3, attribute(AT_CN, PSTR('Alice Smith'))),
                  X(4, SEQ(OID(AT_SN), UTF8('Smyth'))),
                  X(5, OID(AT_CN)))
    d.op(MODIFY, SET(X(0, DN_ALICE), X(1, changes), X(2, eis(1)), common_args(True)),
         NULL())
    d.op(MODIFY, signed(SET(X(0, DN_ALICE), X(1, SEQ()))),
         SEQ(X(0, entry_information()), common_results(True)))
    d.op(MODIFY, SET(X(0, DN_ALICE), X(1, SEQ())), signed(SEQ(), tag=0))

    # modifyDN
    d.op(MODIFYDN, SET(X(0, DN_BOB), X(1, rdn((AT_CN, PSTR('Robert Jones')))),
                       X(2, BOOL(True)), X(3, DN_ORG), common_args(True)), NULL())
    d.op(MODIFYDN, SET(X(0, DN_BOB), X(1, R_CN2)),
         SEQ(R_CN2, common_results(True)))
    d.op(MODIFYDN, SET(X(0, DN_BOB), X(1, R_CN2)), signed(SEQ(R_CN2), tag=0))


def errors(d):
    """Every error, unsigned (with the common results) and signed."""
    cr = common_results(True)
    errs = [
        (READ, E_ABANDONED, SET(cr)),
        (READ, E_ABANDONED, signed(SET())),
        (ABANDON, E_ABANDONFAILED, SET(X(0, INT(2)), X(1, INT(9)), cr)),
        (ABANDON, E_ABANDONFAILED, signed(SET(X(0, INT(1)), X(1, INT(9))))),
        (READ, E_ATTR, SET(X(0, DN_ALICE),
                           X(1, SET(SEQ(X(0, INT(1)), X(1, OID(AT_TEL))),
                                    SEQ(X(0, INT(2)), X(1, OID(AT_CN)), X(2, PSTR('bad'))))),
                           cr)),
        (READ, E_ATTR, signed(SET(X(0, DN_ALICE), X(1, SET())))),
        (READ, E_NAME, SET(X(0, INT(1)), X(1, DN_ORG), cr)),
        (READ, E_NAME, signed(SET(X(0, INT(5)), X(1, DN_ROOT)))),
        (READ, E_REFERRAL, SET(X(0, continuation_reference()), cr)),
        (READ, E_REFERRAL, signed(SET(X(0, continuation_reference())))),
        (READ, E_SERVICE, SET(X(0, INT(1)), cr)),
        (READ, E_SERVICE, SET(X(0, INT(17)))),
        (READ, E_SERVICE, SET(X(0, INT(99)))),
        (READ, E_SERVICE, signed(SET(X(0, INT(7))))),
        (ADD, E_UPDATE, SET(X(0, INT(5)), X(1, SET(OID(AT_CN), attribute(AT_SN, UTF8('x')))), cr)),
        (ADD, E_UPDATE, SET(X(0, INT(12)))),
        (ADD, E_UPDATE, SET(X(0, INT(99)))),
        (ADD, E_UPDATE, signed(SET(X(0, INT(1))))),
    ]
    args = {READ: SET(X(0, DN_ALICE)), ABANDON: SEQ(X(0, INT(1))),
            ADD: SET(X(0, DN_ALICE), X(1, SET(attribute(AT_SN, UTF8('x')))))}
    for opcode, code, param in errs:
        d.op(opcode, args[opcode], None, (code, param))
