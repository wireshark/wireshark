# -*- python -*-
#
# $Id: ethereal_be.py,v 1.1 2001/06/18 05:27:16 guy Exp $
#
#    File      : ethereal_be.py
#
#    Author    : Frank Singleton (frank.singleton@ericsson.com)
#
#    Copyright (C) 2001 Frank Singleton, Ericsson Inc.
#
#  This file is a backend to "omniidl", used to generate "Ethereal"
#  dissectors from IDL descriptions. The output language generated
#  is "C". It will generate code to use the GIOP/IIOP get_CDR_XXX API.
#  
#
#  Please see packet-giop.h in Ethereal distro for API description.
#  Ethereal is available at http://www.ethereal.com/
#
#  Omniidl is part of the OmniOrb distribution, and is available at
#  http://www.uk.research.att.com/omniORB/omniORB.html
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
#  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
#  02111-1307, USA.
#
# Description:
#   
#   Omniidl Back-end which parses an IDL data structure provided by the frontend
#   and generates packet-idl-xxx.[ch] for compiling as a dissector in 
#   Ethereal IP protocol anlayser.
#
#  
#
#
# Strategy. 
#
# Crawl all the way down all branches until I hit  "Operation" nodes
# store the "operation" nodes in oplist[]
#
# Pass the obj.oplist[] (via an object ref) to the src code generator (ethereal_gen) class.
# and let it do the hard work ! 
#
#


"""Ethereal IDL compiler back-end."""

from omniidl import idlast, idltype, idlvisitor, idlutil, output
import sys, string
from ethereal_gen import ethereal_gen_C

#
# This class finds the "Operations" nodes, and hands them off
# to an instance of the source code generator class "ethereal_gen" 
#

class EtherealVisitor:
    
    def __init__(self, st):
        self.st = st
        self.oplist = []                # list of operation nodes
        self.enumlist = []              # list of enum nodes
        
        
    def visitAST(self, node):
        for n in node.declarations():
            if isinstance(n, idlast.Module):
                self.visitModule(n)
            if isinstance(n, idlast.Interface):
                self.visitInterface(n)
            if isinstance(n, idlast.Operation):
                self.visitOperation(n)


    def visitModule(self, node):
        for n in node.definitions():
            if isinstance(n, idlast.Module):
                self.visitModule(n)    
            if isinstance(n, idlast.Interface):
                self.visitInterface(n)   
            if isinstance(n, idlast.Operation):
                self.visitOperation(n)   


    def visitInterface(self, node):
        if node.mainFile():
            for c in node.callables():
                if isinstance(c, idlast.Operation):
                    self.visitOperation(c)

    #
    # visitOperation
    #
    # populates the operations node list "oplist"
    #
    #
    
    def visitOperation(self,opnode):
        self.oplist.append(opnode)      # store operation node
        
    #
    # visitExceptions 
    #
    # Given an oplist, generate a list of unique exception
    # nodes.
    #

        
def run(tree, args):

    st = output.Stream(sys.stdout, 4)   # set indent for stream
    ev = EtherealVisitor(st)            # create visitor object
    
    ev.visitAST(tree)                   # go find some operations

    # create a C generator object
    # and generate some C code

    eg = ethereal_gen_C(ev.st, "TEST", "test", "Test Dissector Using GIOP API") 
    eg.genCode(ev.oplist)               # pass them onto the C generator
    


