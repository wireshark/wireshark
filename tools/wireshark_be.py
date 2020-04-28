# -*- python -*-
#
#    File      : wireshark_be.py
#
#    Author    : Frank Singleton (frank.singleton@ericsson.com)
#
#    Copyright (C) 2001 Frank Singleton, Ericsson Inc.
#
#  This file is a backend to "omniidl", used to generate "Wireshark"
#  dissectors from IDL descriptions. The output language generated
#  is "C". It will generate code to use the GIOP/IIOP get_CDR_XXX API.
#
#  Please see packet-giop.h in Wireshark distro for API description.
#  Wireshark is available at https://www.wireshark.org/
#
#  Omniidl is part of the OmniOrb distribution, and is available at
#  http://omniorb.sourceforge.net
#
#  SPDX-License-Identifier: GPL-2.0-or-later


# Description:
#
#   Omniidl Back-end which parses an IDL data structure provided by the frontend
#   and generates packet-idl-xxx.[ch] for compiling as a dissector in Wireshark.
#
#
# Strategy.
#
# Crawl all the way down all branches until I hit  "Operation", "Enum", "Attribute",
# "Struct" and "Union" nodes.  Then store these nodes in lists.
#
# Pass these lists (via an object ref) to the src code
# generator (wireshark_gen) class and let it do the hard work !
#
#
# Don't forget structs can contain embedded structs etc .. so don't forget
# to peek inside and check :-)


"""Wireshark IDL compiler back-end."""

from __future__ import print_function

import string
import sys
from os import path

from omniidl import idlast, idltype, output

from wireshark_gen import wireshark_gen_C


class WiresharkVisitor:
    """This class finds the "Operation" nodes ,Enum Nodes, "Attribute" nodes, Struct Nodes
    and Union Nodes. Then it hands them off to an instance of the source code generator
    class "wireshark_gen" """

    def __init__(self, st, debug=False):
        self.DEBUG = debug
        self.st = st
        self.oplist = []  # list of operation nodes
        self.enlist = []  # list of enum nodes
        self.atlist = []  # list of attribute nodes
        self.stlist = []  # list of struct nodes
        self.unlist = []  # list of union nodes

    def visitAST(self, node):
        if self.DEBUG:
            print("XXX visitAST() node = ", node)

        for n in node.declarations():
            if isinstance(n, idlast.Module):
                self.visitModule(n)
            if isinstance(n, idlast.Interface):
                self.visitInterface(n)
            if isinstance(n, idlast.Operation):
                self.visitOperation(n)
            if isinstance(n, idlast.Attribute):
                self.visitAttribute(n)
            if isinstance(n, idlast.Enum):
                self.visitEnum(n)
            if isinstance(n, idlast.Struct):
                self.visitStruct(n)
            if isinstance(n, idlast.Union):
                self.visitUnion(n)

            # Check for Typedef structs and unions

            if isinstance(n, idlast.Typedef):
                self.visitTypedef(n)  # who are you ?

    def visitModule(self, node):
        if self.DEBUG:
            print("XXX visitModule() node = ", node)

        for n in node.definitions():
            if isinstance(n, idlast.Module):
                self.visitModule(n)
            if isinstance(n, idlast.Interface):
                self.visitInterface(n)
            if isinstance(n, idlast.Operation):
                self.visitOperation(n)
            if isinstance(n, idlast.Attribute):
                self.visitAttribute(n)
            if isinstance(n, idlast.Enum):
                self.visitEnum(n)
            if isinstance(n, idlast.Struct):
                self.visitStruct(n)
            if isinstance(n, idlast.Union):
                self.visitUnion(n)

            # Check for Typedef structs and unions

            if isinstance(n, idlast.Typedef):
                self.visitTypedef(n)  # who are you ?

    def visitInterface(self, node):
        if self.DEBUG:
            print("XXX visitInterface() node = ", node)

        for c in node.callables():
            if isinstance(c, idlast.Operation):
                self.visitOperation(c)
            if isinstance(c, idlast.Attribute):
                self.visitAttribute(c)

        for d in node.contents():
            if isinstance(d, idlast.Enum):
                self.visitEnum(d)

            if isinstance(d, idlast.Struct):
                self.visitStruct(d)

            if isinstance(d, idlast.Union):
                self.visitUnion(d)

            # Check for Typedef structs and unions

            if isinstance(d, idlast.Typedef):
                self.visitTypedef(d)  # who are you ?

    def visitOperation(self, opnode):
        """populates the operations node list "oplist" """
        if opnode not in self.oplist:
            self.oplist.append(opnode)  # store operation node

    def visitAttribute(self, atnode):
        """populates the attribute node list "atlist" """
        if atnode not in self.atlist:
            self.atlist.append(atnode)  # store attribute node

    def visitEnum(self, enode):
        """populates the Enum node list "enlist" """
        if enode not in self.enlist:
            self.enlist.append(enode)  # store enum node if unique

    def visitTypedef(self, td):
        """Search to see if its a typedef'd struct, union, or enum

        eg: typdef enum colors {red, green, blue } mycolors;
        """

        d = td.aliasType()  # get Type, possibly Declared
        if isinstance(d, idltype.Declared):
            self.visitDeclared(d)

    def visitDeclared(self, d):
        """Search to see if its a struct, union, or enum"""
        if isinstance(d, idltype.Declared):
            sue = d.decl()  # grab the struct or union or enum

            if isinstance(sue, idlast.Struct):
                self.visitStruct(sue)
            if isinstance(sue, idlast.Union):
                self.visitUnion(sue)
            if isinstance(sue, idlast.Enum):
                self.visitEnum(sue)

    def visitStruct(self, stnode):
        # populates the struct node list "stlist"
        # and checks its members also
        if stnode not in self.stlist:
            self.stlist.append(stnode)  # store struct node if unique and avoid recursive loops
                                        # if we come across recursive structs

            for m in stnode.members():  # find embedded struct definitions within this
                mt = m.memberType()
                if isinstance(mt, idltype.Declared):
                    self.visitDeclared(mt)  # if declared, then check it out

    def visitUnion(self, unnode):
        # populates the struct node list "unlist"
        # and checks its members also
        if unnode not in self.unlist:
            self.unlist.append(unnode)  # store union node if unique

            if unnode.constrType():  # enum defined within switch type
                if isinstance(unnode.switchType(), idltype.Declared):
                    self.visitDeclared(unnode.switchType())

            for c in unnode.cases():
                ct = c.caseType()
                if isinstance(ct, idltype.Declared):
                    self.visitDeclared(ct)  # if declared, then check it out


def run(tree, args):

    DEBUG = "debug" in args
    AGGRESSIVE = "aggressive" in args

    st = output.Stream(sys.stdout, 4)  # set indent for stream
    ev = WiresharkVisitor(st, DEBUG)  # create visitor object

    ev.visitAST(tree)  # go find some operations

    # Grab name of main IDL file being compiled.
    #
    # Assumption: Name is of the form   abcdefg.xyz  (eg: CosNaming.idl)

    fname = path.basename(tree.file())  # grab basename only, dont care about path
    nl = fname.split(".")[0]  # split name of main IDL file using "." as separator
                                      # and grab first field (eg: CosNaming)

    if DEBUG:
        for i in ev.oplist:
            print("XXX - Operation node ", i, " repoId() = ", i.repoId())
        for i in ev.atlist:
            print("XXX - Attribute node ", i, " identifiers() = ", i.identifiers())
        for i in ev.enlist:
            print("XXX - Enum node ", i, " repoId() = ", i.repoId())
        for i in ev.stlist:
            print("XXX - Struct node ", i, " repoId() = ", i.repoId())
        for i in ev.unlist:
            print("XXX - Union node ", i, " repoId() = ", i.repoId())

    # create a C generator object
    # and generate some C code

    eg = wireshark_gen_C(ev.st,
                         nl.upper(),
                         nl.lower(),
                         nl.capitalize() + " Dissector Using GIOP API",
                         debug=DEBUG,
                         aggressive=AGGRESSIVE)

    eg.genCode(ev.oplist, ev.atlist, ev.enlist, ev.stlist, ev.unlist)  # pass them onto the C generator

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 4
# indent-tabs-mode: nil
# End:
#
# vi: set shiftwidth=4 expandtab:
# :indentSize=4:noTabs=true:
#
