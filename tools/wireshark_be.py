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
#  Wireshark is available at http://www.wireshark.org/
#
#  Omniidl is part of the OmniOrb distribution, and is available at
#  http://omniorb.sourceforge.net
#
#  This program is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Description:
#
#   Omniidl Back-end which parses an IDL data structure provided by the frontend
#   and generates packet-idl-xxx.[ch] for compiling as a dissector in 
#   Wireshark IP protocol anlayser.
#
#
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
# Dont forget structs can contain embedded structs etc .. so dont forget
# to peek inside and check :-)
#
#


"""Wireshark IDL compiler back-end."""

from omniidl import idlast, idltype, idlvisitor, idlutil, output
import sys, string
from os import path
from wireshark_gen import wireshark_gen_C

#
# This class finds the "Operation" nodes ,Enum Nodes, "Attribute" nodes, Struct Nodes
# and Union Nodes. Then it hands them off to an instance of the source code generator
# class "wireshark_gen" 
#

class WiresharkVisitor:

    DEBUG = 0                           # debug flag

    def __init__(self, st):
        self.st = st
        self.oplist = []                # list of operation nodes
        self.enlist = []                # list of enum nodes
        self.atlist = []                # list of attribute nodes
        self.stlist = []                # list of struct nodes
        self.unlist = []                # list of union nodes


    def visitAST(self, node):
        if self.DEBUG:
            print "XXX visitAST() node = ", node

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
                self.visitTypedef(n)    # who are you ?


    def visitModule(self, node):
        if self.DEBUG:
            print "XXX visitModule() node = ", node

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
                self.visitTypedef(n)    # who are you ?


    def visitInterface(self, node):
        if self.DEBUG:
            print "XXX visitInterface() node = ", node

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
                self.visitTypedef(d)    # who are you ?


    #
    # visitOperation
    #
    # populates the operations node list "oplist"
    #
    #

    def visitOperation(self,opnode):
        if not opnode in self.oplist:
            self.oplist.append(opnode)      # store operation node

    #
    # visitAttribute
    #
    # populates the attribute node list "atlist"
    #
    #

    def visitAttribute(self,atnode):
        if not atnode in self.atlist:
            self.atlist.append(atnode)      # store attribute node


    #
    # visitEnum
    #
    # populates the Enum node list "enlist"
    #
    #

    def visitEnum(self,enode):
        if not enode in self.enlist:
            self.enlist.append(enode)      # store enum node if unique

    #
    # visitTypedef
    #
    # Search to see if its a typedef'd struct, union, or enum
    #
    # eg: typdef enum colors {red, green, blue } mycolors;
    #

    def visitTypedef(self,td):
        d = td.aliasType()              # get Type, possibly Declared
        if isinstance(d,idltype.Declared):
            self.visitDeclared(d)


    #
    # visitDeclared
    #
    # Search to see if its a struct, union, or enum
    #
    #

    def visitDeclared(self,d):
        if isinstance(d,idltype.Declared):
            sue = d.decl()             # grab the struct or union or enum 

            if isinstance(sue, idlast.Struct):
                self.visitStruct(sue)
            if isinstance(sue, idlast.Union):
                self.visitUnion(sue)
            if isinstance(sue, idlast.Enum):
                self.visitEnum(sue)




    #
    # visitStruct
    #
    # populates the struct node list "stlist"
    # and checks its members also
    #
    #

    def visitStruct(self,stnode):
        if not stnode in self.stlist:
            self.stlist.append(stnode)      # store struct node if unique and avoid recursive loops
                                            # if we come across recursive structs

            for m in stnode.members():      # find embedded struct definitions within this
                mt = m.memberType()
                if isinstance(mt,idltype.Declared):
                    self.visitDeclared(mt)      # if declared, then check it out 


    #
    # visitUnion
    #
    # populates the struct node list "unlist"
    # and checks its members also
    #
    #

    def visitUnion(self,unnode):
        if not unnode in self.unlist:
            self.unlist.append(unnode)      # store union node if unique

            if unnode.constrType():         # enum defined within switch type
                if isinstance(unnode.switchType(),idltype.Declared):
                    self.visitDeclared(unnode.switchType())

            for c in unnode.cases():
                ct =  c.caseType()
                if isinstance(ct,idltype.Declared):
                    self.visitDeclared(ct)      # if declared, then check it out 


def run(tree, args):

    st = output.Stream(sys.stdout, 4)   # set indent for stream
    ev = WiresharkVisitor(st)            # create visitor object

    ev.visitAST(tree)                   # go find some operations

    #
    # Grab name of main IDL file being compiled.
    # 
    # Assumption: Name is of the form   abcdefg.xyz  (eg: CosNaming.idl)
    #

    fname = path.basename(tree.file())    # grab basename only, dont care about path
    nl = string.split(fname,".")[0]       # split name of main IDL file using "." as separator
                                          # and grab first field (eg: CosNaming)

    if ev.DEBUG:
        for i in ev.oplist:
            print "XXX - Operation node ", i, " repoId() = ", i.repoId()
        for i in ev.atlist:
            print "XXX - Attribute node ", i, " identifiers() = ", i.identifiers()
        for i in ev.enlist:
            print "XXX - Enum node ", i, " repoId() = ", i.repoId()
        for i in ev.stlist:
            print "XXX - Struct node ", i, " repoId() = ", i.repoId()
        for i in ev.unlist:
            print "XXX - Union node ", i, " repoId() = ", i.repoId()


    # create a C generator object
    # and generate some C code


    eg = wireshark_gen_C(ev.st, string.upper(nl), string.lower(nl), string.capitalize(nl) + " Dissector Using GIOP API") 
    eg.genCode(ev.oplist, ev.atlist, ev.enlist, ev.stlist, ev.unlist)    # pass them onto the C generator

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 4
# indent-tabs-mode: nil
# End:
#
# vi: set shiftwidth=4 expandtab:
# :indentSize=4:noTabs=true:
#
