# -*- python -*-
#
# $Id: ethereal_gen.py,v 1.7 2001/07/20 09:50:08 guy Exp $
#
#                           
# ethereal_gen.py (part of idl2eth)           
#
# Author : Frank Singleton (frank.singleton@ericsson.com)
#
#    Copyright (C) 2001 Frank Singleton, Ericsson Inc.
#
#  This file is a backend to "omniidl", used to generate "Ethereal"
#  dissectors from IDL descriptions. The output language generated
#  is "C". It will generate code to use the GIOP/IIOP get_CDR_XXX API.
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
#   Omniidl Back-end which parses an IDL list of "Operation" nodes
#   passed from ethereal_be2.py and generates "C" code for compiling
#   as a dissector in Ethereal IP protocol anlayser.
#
#
# Strategy (sneaky but ...)
#
# problem: I dont know what variables to declare until AFTER the helper functions
# have been built, so ...
#
# There are 2 passes through genHelpers, the first one is there just to
# make sure the fn_hash data struct is populated properly.
# The second pass is the real thing, generating code and declaring
# variables (from the 1st pass) properly.
#


"""Ethereal IDL compiler back-end."""

from omniidl import idlast, idltype, idlutil, output
import sys, string
import tempfile

#
# Output class, generates "C" src code for the sub-dissector 
#
# in:
#
#
# self - me
# st   - output stream
# node - a reference to an Operations object.
# name - scoped name (Module::Module::Interface:: .. ::Operation
#



#
# TODO -- FS
# 
# 1. generate hf[] data for searchable fields (but what is searchable?)
# 2. add item instead of add_text()
# 3. sequence handling [done]
# 4. User Exceptions [done]
# 5. Fix arrays, and structs containing arrays [done]
# 6. Handle pragmas.
# 7. Exception can be common to many operations, so handle them outside the
#    operation helper functions [done]
# 8. Automatic variable declaration [done, improve]
# 9. wchar and wstring handling [giop API needs improving]
# 10. Support Fixed [done]
# 11. Support attributes (get/set)
# 12. Implement IDL "union" code
# 13. Implement support for plugins
#
#
# Also test, Test, TEST
#



#
#   Strategy:
#
#    For return val and all parameters do
#       find basic IDL type for each parameter
#       output get_CDR_xxx
#    output exception handling code
#
#

class ethereal_gen_C:


    #
    # Turn DEBUG stuff on/off
    #

    DEBUG = 0

    #
    # Some string constants for our templates
    #

    c_u_octet4    = "guint32   u_octet4;"
    c_s_octet4    = "gint32    s_octet4;"
    c_u_octet2    = "guint16   u_octet2;"
    c_s_octet2    = "gint16    s_octet2;"
    c_u_octet1    = "guint8    u_octet1;"
    c_s_octet1    = "gint8     s_octet1;"
    
    c_float       = "gfloat    my_float;"
    c_double      = "gdouble   my_double;"

    c_seq         = "gchar   *seq = NULL;"          # pointer to buffer of gchars
    c_i           = "guint32   i_";                 # loop index
    c_i_lim       = "guint32   u_octet4_loop_";     # loop limit
    
    #
    # Constructor
    #

    def __init__(self, st, protocol_name, dissector_name ,description):
        self.st = output.Stream(tempfile.TemporaryFile(),4) # for first pass only
        
        self.st_save = st               # where 2nd pass should go
        self.protoname = protocol_name  # Protocol Name (eg: ECHO)
        self.dissname = dissector_name  # Dissector name (eg: echo)
        self.description = description  # Detailed Protocol description (eg: Echo IDL Example)
        self.exlist = []                # list of exceptions used in operations.
        #self.curr_sname                # scoped name of current opnode or exnode I am visiting, used for generating "C" var declares
        self.fn_hash = {}               # top level hash to contain key = function/exception and val = list of variable declarations
                                        # ie a hash of lists
        self.fn_hash_built = 0          # flag to indicate the 1st pass is complete, and the fn_hash is correctly
                                        # populated with operations/vars and exceptions/vars

                                        
    #
    # genCode()
    #
    # Main entry point, controls sequence of
    # generated code.
    #
    #
        
    def genCode(self,oplist):

        self.genHelpers(oplist)         # sneaky .. call it now, to populate the fn_hash
                                        # so when I come to that operation later, I have the variables to
                                        # declare already.
                                        
        self.genExceptionHelpers(oplist) # sneaky .. call it now, to populate the fn_hash
                                        # so when I come to that exception later, I have the variables to
                                        # declare already.
                                                                                
        self.fn_hash_built = 1          # DONE, so now I know , see genOperation()

        self.st = self.st_save
        self.genHeader()                # initial dissector comments
        self.genEthCopyright()          # Ethereal Copyright comments.
        self.genGPL()                   # GPL license
        self.genIncludes()
        self.genDeclares(oplist)
        self.genProtocol()
        self.genRegisteredFields()
        self.genOpList(oplist)          # string constant declares for operation names
        self.genExList(oplist)          # string constant declares for user exceptions
        
        
        self.genExceptionHelpers(oplist)   # helper function to decode user exceptions that have members
        self.genExceptionDelegator(oplist) # finds the helper function to decode a user exception
        self.genHelpers(oplist)

        self.genMainEntryStart(oplist)
        self.genDelegator(oplist)
        self.genMainEntryEnd()

        self.gen_proto_register()
        self.gen_proto_reg_handoff(oplist)
        self.gen_plugin_init()

        #self.dumpvars()                 # debug
        


    #
    # genHeader
    #
    # Generate Standard Ethereal Header Comments
    #
    #
    
    def genHeader(self):
        self.st.out(self.template_Header,dissector_name=self.dissname)        
        if self.DEBUG:
            print "XXX genHeader"




    #
    # genEthCopyright
    #
    # Ethereal Copyright Info
    #
    #

    def genEthCopyright(self):        
        if self.DEBUG:
            print "XXX genEthCopyright"            
        self.st.out(self.template_ethereal_copyright)


    #
    # genGPL
    #
    # GPL licencse
    #
    #

    def genGPL(self):
        if self.DEBUG:
            print "XXX genGPL"
            
        self.st.out(self.template_GPL)

    #
    # genIncludes
    #
    # GPL licencse
    #
    #

    def genIncludes(self):
        if self.DEBUG:
            print "XXX genIncludes"
            
        self.st.out(self.template_Includes)
                                
    #
    # denDeclares
    #
    #
    
    def genDeclares(self,oplist):
        if self.DEBUG:
            print "XXX genDeclares"


                                
    #
    # genProtocol
    #
    #
    
    def genProtocol(self):
        self.st.out(self.template_protocol, dissector_name=self.dissname)        
        self.st.out(self.template_init_boundary)        
        
                                
    #
    # genProtoAndRegisteredFields
    #
    #
    
    def genRegisteredFields(self):
        self.st.out(self.template_registered_fields )        
        


    #
    # genMainEntryStart
    #

    def genMainEntryStart(self,oplist):
        self.st.out(self.template_main_dissector_start, dissname=self.dissname, disprot=self.protoname)        
        self.st.inc_indent()
        self.st.out(self.template_main_dissector_switch_msgtype_start)        
        self.st.out(self.template_main_dissector_switch_msgtype_start_request_reply)        
        self.st.inc_indent()

                
    #
    # genMainEntryEnd
    #

    def genMainEntryEnd(self):

        self.st.out(self.template_main_dissector_switch_msgtype_end_request_reply)        
        self.st.dec_indent()
        self.st.out(self.template_main_dissector_switch_msgtype_all_other_msgtype)             
        self.st.dec_indent()
        #self.st.out(self.template_main_dissector_switch_msgtype_end)              
        self.st.out(self.template_main_dissector_end)        
        

    #
    # genOpList
    #
    # in: oplist
    #
    # out: C code for IDL operations
    #
    # eg:
    #
    # static const char Penguin_Echo_echoShort_op[] = "echoShort" ;
    #

    def genOpList(self,oplist):
        self.st.out(self.template_comment_operations_start)        

        for n in oplist:
            sname = self.namespace(n, "_")   
            opname = n.identifier()
            self.st.out(self.template_operations_declare, sname=sname, opname=opname)
    
        self.st.out(self.template_comment_operations_end)

    #
    # genExList
    #
    # in: oplist
    #
    # out: C code for IDL User Exceptions that contain members
    #
    # eg:
    #
    # static const char user_exception_tux_bad_value[] = "IDL:tux/bad_value:1.0" ;
    #

    def genExList(self,oplist):
        
        self.st.out(self.template_comment_user_exceptions_string_declare_start)
        
        exlist = self.get_exceptionList(oplist) # grab list of ALL UNIQUE exception nodes

        for ex in exlist:
            if self.DEBUG:
                print "XXX Exception " , ex.repoId()
                print "XXX Exception Identifier" , ex.identifier()
                print "XXX Exception Scoped Name" , ex.scopedName()
            
            if (ex.members()):          # only if has members
                sname = self.namespace(ex, "_")   
                exname = ex.repoId()
                self.st.out(self.template_user_exceptions_declare,  sname=sname, exname=ex.repoId())
    
        self.st.out(self.template_comment_user_exceptions_string_declare_end)



    #
    # genExceptionDelegator
    #
    # in: oplist
    #
    # out: C code for User exception delegator
    #
    # eg:
    #
    #

    def genExceptionDelegator(self,oplist):
        
        self.st.out(self.template_main_exception_delegator_start)
        self.st.inc_indent()

        exlist = self.get_exceptionList(oplist) # grab list of ALL UNIQUE exception nodes

        for ex in exlist:
            if self.DEBUG:
                print "XXX Exception " , ex.repoId()
                print "XXX Exception Identifier" , ex.identifier()
                print "XXX Exception Scoped Name" , ex.scopedName()
            
            if (ex.members()):          # only if has members
                sname = self.namespace(ex, "_")   
                exname = ex.repoId()
                self.st.out(self.template_ex_delegate_code,  sname=sname, exname=ex.repoId())

        self.st.dec_indent()    
        self.st.out(self.template_main_exception_delegator_end)


    #
    # genExceptionHelpers()
    #
    # Generate private helper functions to decode Exceptions used
    # within operations
    #
    # in: oplist
    #
    
        
    def genExceptionHelpers(self,oplist):        
        exlist = self.get_exceptionList(oplist) # grab list of exception nodes
        if self.DEBUG:
            print "XXX genExceptionHelpers: exlist = ", exlist

        self.st.out(self.template_exception_helpers_start)
        for ex in exlist:
            if (ex.members()):          # only if has members
                #print "XXX Exception = " + ex.identifier()
                self.genExHelper(ex)
        
        self.st.out(self.template_exception_helpers_end)


    #
    # genExhelper() 
    #
    # Generate private helper functions to decode User Exceptions
    #
    # in: exnode ( an exception node)
    #
    
    def genExHelper(self,ex):
        if self.DEBUG:
            print "XXX genExHelper"
            
        sname = self.namespace(ex, "_")
        self.curr_sname = sname         # update current opnode/exnode scoped name
        if not self.fn_hash_built:
            self.fn_hash[sname] = []        # init empty list as val for this sname key
                                            # but only if the fn_hash is not already built

        self.st.out(self.template_exception_helper_function_start, sname=sname, exname=ex.repoId())
        self.st.inc_indent()

        self.st.out(self.template_helper_function_vars_start)
        self.dumpCvars(sname)
        self.st.out(self.template_helper_function_vars_end )
        
        self.st.out(self.template_exception_helper_function_get_endianess)

        
        for m in ex.members():
            #print "XXX genExhelper, member = ", m, "member type = ", m.memberType()
            

            for decl in m.declarators():
                #print "XXX genExhelper, d = ", decl
                if decl.sizes():        # an array
                    indices = self.get_indices_from_sizes(decl.sizes())
                    string_indices = '%i ' % indices # convert int to string
                    self.st.out(self.template_get_CDR_array_comment, aname=decl.identifier(), asize=string_indices)     
                    self.st.out(self.template_get_CDR_array_start, aname=decl.identifier(), aval=string_indices)
                    self.addvar(self.c_i + decl.identifier() + ";")
                    
                    self.st.inc_indent()       
                    self.getCDR3(m.memberType(), ex.identifier() + "_" + decl.identifier() )
                    
                    self.st.dec_indent()
                    self.st.out(self.template_get_CDR_array_end)
                    
                    
                else:    
                    self.getCDR3(m.memberType(), ex.identifier() + "_" + decl.identifier() )

        self.st.dec_indent()
        self.st.out(self.template_exception_helper_function_end)


    #
    # genHelpers()
    #
    # Generate private helper functions for each IDL operation.
    #
    # in: oplist
    #
    
        
    def genHelpers(self,oplist):
        for op in oplist:
            self.genOperation(op)


    #
    # genOperation()
    #
    # Generate private helper functions for a specificIDL operation.
    #
    # in: opnode
    #
    
    def genOperation(self,opnode):
        if self.DEBUG:
            print "XXX genOperation called"
            
        sname = self.namespace(opnode, "_")
        if not self.fn_hash_built:
            self.fn_hash[sname] = []        # init empty list as val for this sname key
                                            # but only if the fn_hash is not already built
        
        self.curr_sname = sname         # update current opnode's scoped name
        opname = opnode.identifier()
        
        self.st.out(self.template_helper_function_comment, repoid=opnode.repoId() )

        self.st.out(self.template_helper_function_start, sname=sname)
        self.st.inc_indent()

        self.st.out(self.template_helper_function_vars_start)
        self.dumpCvars(sname)
        self.st.out(self.template_helper_function_vars_end )
        

        self.st.out(self.template_helper_switch_msgtype_start)

        self.st.out(self.template_helper_switch_msgtype_request_start)
        self.st.inc_indent()
        self.genOperationRequest(opnode)       
        self.st.out(self.template_helper_switch_msgtype_request_end)
        self.st.dec_indent()

        self.st.out(self.template_helper_switch_msgtype_reply_start)
        self.st.inc_indent()
        
        self.st.out(self.template_helper_switch_rep_status_start)

        
        self.st.out(self.template_helper_switch_msgtype_reply_no_exception_start)
        self.st.inc_indent()
        self.genOperationReply(opnode)
        self.st.out(self.template_helper_switch_msgtype_reply_no_exception_end)
        self.st.dec_indent()
        
        self.st.out(self.template_helper_switch_msgtype_reply_user_exception_start)
        self.st.inc_indent()       
        self.genOpExceptions(opnode)
        self.st.out(self.template_helper_switch_msgtype_reply_user_exception_end)
        self.st.dec_indent()       
        
        self.st.out(self.template_helper_switch_msgtype_reply_default_start)
        self.st.out(self.template_helper_switch_msgtype_reply_default_end)

        self.st.out(self.template_helper_switch_rep_status_end)
        
        self.st.dec_indent()
        
        self.st.out(self.template_helper_switch_msgtype_default_start)
        self.st.out(self.template_helper_switch_msgtype_default_end)
        
        self.st.out(self.template_helper_switch_msgtype_end)        
        self.st.dec_indent()


        self.st.out(self.template_helper_function_end, sname=sname)




    #
    # Decode function parameters for a GIOP request message
    #
    # TODO check for enum
    #
    
    def genOperationRequest(self,opnode):
        for p in opnode.parameters():
            if p.is_in():
                if self.DEBUG:
                    print "XXX parameter = " ,p
                    print "XXX parameter type = " ,p.paramType()
                    print "XXX parameter type kind = " ,p.paramType().kind()

                self.getCDR3(p.paramType(),p.identifier())
                

    #
    # Decode function parameters for a GIOP reply message
    #
    # TODO check for enum

    
    def genOperationReply(self,opnode):

        rt = opnode.returnType()        # get return type
        if self.DEBUG:
            print "XXX opnode  = " , opnode
            print "XXX return type  = " , rt
            print "XXX return type.unalias  = " , rt.unalias()        
            print "XXX return type.kind()  = " , rt.kind();
            

        if (rt.kind() == idltype.tk_alias): # a typdef return val possibly ?
            #self.getCDR3(rt.decl().alias().aliasType(),"dummy")    # return value maybe a typedef
            self.get_CDR_alias(rt, "Operation Return Value" )
                               
        else:            
            self.getCDR3(rt, "Operation Return Value")    # return value is NOT an alias
              
        for p in opnode.parameters():
            if p.is_out():              # out or inout
                self.getCDR3(p.paramType(),p.identifier())

        #self.st.dec_indent()
               
    def genOpExceptions(self,opnode):
        for ex in opnode.raises():
            if ex.members():
                #print ex.members()
                for m in ex.members():
                    t=0
                    #print m.memberType(), m.memberType().kind()
               
    def genDelegator(self,oplist):
        for op in oplist:
            opname = op.identifier()
            sname = self.namespace(op, "_")
            self.st.out(self.template_delegate_code, opname=opname, sname=sname)

    #
    # Add a variable declaration to the hash of list
    #
    
    def addvar(self, var):
        if not ( var in self.fn_hash[self.curr_sname] ):
            self.fn_hash[self.curr_sname].append(var)

    #
    # Print the variable declaration from  the hash of list
    #
                

    def dumpvars(self):
        for fn in self.fn_hash.keys():
            print "FN = " + fn
            for v in self.fn_hash[fn]:
                print "-> " + v
    #
    # Print the "C" variable declaration from  the hash of list
    # for a given scoped operation name (eg: tux_penguin_eat)
    #
                

    def dumpCvars(self, sname):
            for v in self.fn_hash[sname]:
                self.st.out(v)


            
                

## tk_null               = 0
## tk_void               = 1
## tk_short              = 2
## tk_long               = 3
## tk_ushort             = 4
## tk_ulong              = 5
## tk_float              = 6
## tk_double             = 7
## tk_boolean            = 8
## tk_char               = 9
## tk_octet              = 10
## tk_any                = 11
## tk_TypeCode           = 12
## tk_Principal          = 13
## tk_objref             = 14
## tk_struct             = 15
## tk_union              = 16
## tk_enum               = 17
## tk_string             = 18
## tk_sequence           = 19
## tk_array              = 20
## tk_alias              = 21
## tk_except             = 22
## tk_longlong           = 23
## tk_ulonglong          = 24
## tk_longdouble         = 25
## tk_wchar              = 26
## tk_wstring            = 27
## tk_fixed              = 28
## tk_value              = 29
## tk_value_box          = 30
## tk_native             = 31
## tk_abstract_interface = 32


    #
    # getCDR()
    #
    # This is the main "iterator" function. It takes a node, and tries to output
    # a get_CDR_XXX accessor method(s). It can call itself multiple times
    # if I find nested structures etc.
    #

    def getCDR3(self,type,name="fred"):

        pt = type.unalias().kind()      # param CDR type
        pn = name                       # param name

        if self.DEBUG:
            print "XXX getCDR3: kind = " , pt
            
        if pt == idltype.tk_ulong:
            self.get_CDR_ulong(pn)
        elif pt ==  idltype.tk_void:
            self.get_CDR_void(pn)
        elif pt ==  idltype.tk_short:
            self.get_CDR_short(pn)          
        elif pt ==  idltype.tk_long:
            self.get_CDR_long(pn)
        elif pt ==  idltype.tk_ushort:
            self.get_CDR_ushort(pn)
        elif pt ==  idltype.tk_float:
            self.get_CDR_float(pn)
        elif pt ==  idltype.tk_double:
            self.get_CDR_double(pn)
        elif pt == idltype.tk_fixed:
            self.get_CDR_fixed(type.unalias(),pn)
        elif pt ==  idltype.tk_boolean:
            self.get_CDR_boolean(pn)
        elif pt ==  idltype.tk_char:
            self.get_CDR_char(pn)
        elif pt ==  idltype.tk_octet:
            self.get_CDR_octet(pn)
        elif pt ==  idltype.tk_any:
            self.get_CDR_any(pn)
        elif pt ==  idltype.tk_string:
            self.get_CDR_string(pn)
        elif pt ==  idltype.tk_wstring:
            self.get_CDR_wstring(pn)
        elif pt ==  idltype.tk_wchar:
            self.get_CDR_wchar(pn)            
        elif pt ==  idltype.tk_enum:
            #print type.decl()
            self.get_CDR_enum(pn)
        elif pt ==  idltype.tk_struct:
            self.get_CDR_struct(type,pn)
        elif pt ==  idltype.tk_TypeCode: # will I ever get here ?
            self.get_CDR_TypeCode(type,pn)
        elif pt == idltype.tk_sequence:
            self.get_CDR_sequence(type,pn)
        elif pt == idltype.tk_objref:
            self.get_CDR_objref(type,pn)
        elif pt == idltype.tk_array:
            self.get_CDR_array(type,pn)
        elif pt == idltype.tk_alias:
            if self.DEBUG:
                print "XXXXX Alias type XXXXX " , type
            self.get_CDR_alias(type,pn)            
        else:
            if self.DEBUG:
                print "XXXXX Unknown type XXXXX " , pt


    #
    # get_CDR_XXX methods are here ..
    #
    #
    
            
    def get_CDR_ulong(self,pn):
        self.st.out(self.template_get_CDR_ulong, varname=pn)
        self.addvar(self.c_u_octet4)

    def get_CDR_short(self,pn):
        self.st.out(self.template_get_CDR_short, varname=pn)
        self.addvar(self.c_s_octet2)

    def get_CDR_void(self,pn):
        self.st.out(self.template_get_CDR_void, varname=pn)

    def get_CDR_long(self,pn):
        self.st.out(self.template_get_CDR_long, varname=pn)
        self.addvar(self.c_s_octet4)

    def get_CDR_ushort(self,pn):
        self.st.out(self.template_get_CDR_ushort, varname=pn)
        self.addvar(self.c_u_octet2)

    def get_CDR_float(self,pn):
        self.st.out(self.template_get_CDR_float, varname=pn)
        self.addvar(self.c_float)

    def get_CDR_double(self,pn):
        self.st.out(self.template_get_CDR_double, varname=pn)
        self.addvar(self.c_double)

    def get_CDR_boolean(self,pn):
        self.st.out(self.template_get_CDR_boolean, varname=pn)
        self.addvar(self.c_u_octet1)
        
    def get_CDR_fixed(self,type,pn):
        if self.DEBUG:
            print "XXXX calling get_CDR_fixed, type = ", type
            print "XXXX calling get_CDR_fixed, type.digits() = ", type.digits()
            print "XXXX calling get_CDR_fixed, type.scale() = ", type.scale()

        string_digits = '%i ' % type.digits() # convert int to string
        string_scale  = '%i ' % type.scale()  # convert int to string
        string_length  = '%i ' % self.dig_to_len(type.digits())  # how many octets to hilight for a number of digits
    
        self.st.out(self.template_get_CDR_fixed, varname=pn, digits=string_digits, scale=string_scale, length=string_length )
        self.addvar(self.c_seq)
                
                
    def get_CDR_char(self,pn):
        self.st.out(self.template_get_CDR_char, varname=pn)
        self.addvar(self.c_u_octet1)        

    def get_CDR_octet(self,pn):
        self.st.out(self.template_get_CDR_octet, varname=pn)
        self.addvar(self.c_u_octet1)

    def get_CDR_any(self,pn):
        self.st.out(self.template_get_CDR_any, varname=pn)

    def get_CDR_enum(self,pn):
        self.st.out(self.template_get_CDR_enum, varname=pn)
        self.addvar(self.c_u_octet4)

    def get_CDR_string(self,pn):
        self.st.out(self.template_get_CDR_string, varname=pn)
        self.addvar(self.c_u_octet4)
        self.addvar(self.c_seq)

    def get_CDR_wstring(self,pn):
        self.st.out(self.template_get_CDR_wstring, varname=pn)
        self.addvar(self.c_u_octet4)
        self.addvar(self.c_seq)
        
    def get_CDR_wchar(self,pn):
        self.st.out(self.template_get_CDR_wchar, varname=pn)
        self.addvar(self.c_s_octet1)
        self.addvar(self.c_seq)
                
    def get_CDR_TypeCode(self,pn):
        self.st.out(self.template_get_CDR_TypeCode, varname=pn)
        self.addvar(self.c_u_octet4)

    def get_CDR_objref(self,type,pn):
        self.st.out(self.template_get_CDR_object)

    def get_CDR_sequence_len(self,pn):
        self.st.out(self.template_get_CDR_sequence_length, seqname=pn)
        self.addvar(self.c_u_octet4)


    #
    # Currently, get_CDR_alias is geared to finding typdef 
    #

    def get_CDR_alias(self,type,pn):
        if self.DEBUG:
            print "XXX get_CDR_alias, type = " ,type , " pn = " , pn
            print "XXX get_CDR_alias, type.decl() = " ,type.decl()
            print "XXX get_CDR_alias, type.decl().alias() = " ,type.decl().alias()

        decl = type.decl()              # get declarator object
        
        if (decl.sizes()):        # a typedef array 
            indices = self.get_indices_from_sizes(decl.sizes())
            string_indices = '%i ' % indices # convert int to string
            self.st.out(self.template_get_CDR_array_comment, aname=pn, asize=string_indices)
            
            self.st.out(self.template_get_CDR_array_start, aname=pn, aval=string_indices)                        
            self.addvar(self.c_i + pn + ";")            
            self.st.inc_indent()       
            self.getCDR3(type.decl().alias().aliasType(),  pn )
            
            self.st.dec_indent()
            self.st.out(self.template_get_CDR_array_end)
            
            
        else:                           # a simple typdef
            if self.DEBUG:
                print "XXX get_CDR_alias, type = " ,type , " pn = " , pn
                print "XXX get_CDR_alias, type.decl() = " ,type.decl()

            self.getCDR3(type, decl.identifier() )
            
            
            
        
        

    def get_CDR_struct(self,type,pn):       
        self.st.out(self.template_structure_start, name=type.name() )

        #  If I am a typedef struct {..}; node then find the struct node
        
        if isinstance(type.decl(), idlast.Declarator):
            ntype = type.decl().alias().aliasType().decl()           
        else:
            ntype = type.decl()         # I am a struct node
                        
        for m in ntype.members():
            for decl in m.declarators():
                if decl.sizes():        # an array
                    indices = self.get_indices_from_sizes(decl.sizes())
                    string_indices = '%i ' % indices # convert int to string
                    self.st.out(self.template_get_CDR_array_comment, aname=decl.identifier(), asize=string_indices)     
                    self.st.out(self.template_get_CDR_array_start, aname=decl.identifier(), aval=string_indices)
                    self.addvar(self.c_i + decl.identifier() + ";")
                    
                    self.st.inc_indent()       
                    self.getCDR3(m.memberType(), type.name() + "_" + decl.identifier() )                    
                    self.st.dec_indent()
                    self.st.out(self.template_get_CDR_array_end)
                    
                    
                else:    
                    self.getCDR3(m.memberType(), type.name() + "_" + decl.identifier() )

        self.st.out(self.template_structure_end, name=type.name())



    #
    # Generate code to access a sequence of a type
    #
    
    def get_CDR_sequence(self,type, pn):
        self.st.out(self.template_get_CDR_sequence_length, seqname=pn )
        self.st.out(self.template_get_CDR_sequence_loop_start, seqname=pn )
        self.addvar(self.c_i_lim + pn + ";" )
        self.addvar(self.c_i + pn + ";")

        self.st.inc_indent()       
        self.getCDR3(type.unalias().seqType() ) # and start all over with the type
        self.st.dec_indent()     
        
        self.st.out(self.template_get_CDR_sequence_loop_end)


        
    #
    # Generate code to access arrays, 
    #
    # This is handled elsewhere. Arrays are either typedefs or in
    # structs
    #
    # TODO - Remove this
    #
    
    def get_CDR_array(self,type, decl):
        if self.DEBUG:
            print "XXX get_CDR_array called "
            print "XXX array size = " ,decl.sizes()
        

   #
   # namespace()
   #
   # in - op node
   #
   # out - scoped operation name, using sep character instead of "::"
   #
   # eg: Penguin::Echo::echoWString => Penguin_Echo_echoWString if sep = "_"
   #
   #
   
    def namespace(self,node,sep):    
        sname = string.replace(idlutil.ccolonName(node.scopedName()), '::', sep)
        #print "XXX namespace: sname = " + sname
        return sname


    #
    # generate code for plugin initialisation
    #

    def gen_plugin_init(self):
        self.st.out(self.template_plugin_init, description=self.description, protocol_name=self.protoname, dissector_name=self.dissname)

    #
    # generate  register_giop_user_module code, and register only
    # unique interfaces that contain operations. Also output
    # a heuristic register in case we want to use that.
    #
    # TODO - make this a command line option
    #
    # -e explicit
    # -h heuristic
    #
    
    

    def gen_proto_reg_handoff(self, oplist):

        self.st.out(self.template_proto_reg_handoff_start, dissector_name=self.dissname)
        self.st.inc_indent()

        for iname in self.get_intlist(oplist):
            self.st.out(self.template_proto_reg_handoff_body, dissector_name=self.dissname, protocol_name=self.protoname, interface=iname )
            
        self.st.out(self.template_proto_reg_handoff_heuristic, dissector_name=self.dissname,  protocol_name=self.protoname)
        self.st.dec_indent()
        
        self.st.out(self.template_proto_reg_handoff_end)



    #
    # generate  proto_register_<protoname> code,
    #
    

    def gen_proto_register(self):
        self.st.out(self.template_proto_register, description=self.description, protocol_name=self.protoname, dissector_name=self.dissname)
    

    #
    # in - oplist[]
    #
    # out - a list of unique interface names. This will be used in
    # register_giop_user_module(dissect_giop_auto, "TEST IDL", "Penguin/Echo" );   so the operation
    # name must be removed from the scope. And we also only want unique interfaces.
    #

    def get_intlist(self,oplist):
        int_hash = {}                   # holds a hash of unique interfaces
        for op in oplist:
            sc = op.scopedName()        # eg: penguin,tux,bite
            sc1 = sc[:-1]               # drop last entry
            sn = idlutil.slashName(sc1)         # penguin/tux
            if not int_hash.has_key(sn):
                int_hash[sn] = 0;       # dummy val, but at least key is unique
                
        return int_hash.keys()



    #
    # in - oplist[]
    #
    # out - a list of exception nodes (unique). This will be used in
    # to generate dissect_exception_XXX functions.
    #
    


    def get_exceptionList(self,oplist):
        ex_hash = {}                   # holds a hash of unique exceptions.
        for op in oplist:
            for ex in op.raises():
                if not ex_hash.has_key(ex):
                    ex_hash[ex] = 0; # dummy val, but at least key is unique
                    if self.DEBUG:
                        print "XXX Exception = " + ex.identifier()

        return ex_hash.keys()



    #
    # Simple function to take a list of array sizes and find the
    # total number of elements
    #
    #
    # eg: temp[4][3] = 12 elements
    #

    def get_indices_from_sizes(self,sizelist):
        val = 1;
        for i in sizelist:
            val = val * i
            
        return val

    #
    # Determine how many octets contain requested number
    # of digits for an "fixed" IDL type  "on the wire"
    #

    def dig_to_len(self,dignum):
        return (dignum/2) + 1

            
    
    #
    # Templates for C code
    #



    template_comment_operations_start = """\
/*
 * IDL Operations Start
 */
 
 """


    template_operations_declare = """static const char @sname@_op[] = \"@opname@\" ;"""
    

    template_comment_operations_end = """
/*
 * IDL Operations End
 */
 
"""

    template_helper_function_comment = """\

/*
 * @repoid@
 */
 
"""
    
    template_helper_function_vars_start = """
/* Operation specific Variable declarations Begin */
"""
    
    template_helper_function_vars_end = """
/* Operation specific Variable declarations End */
"""



    template_helper_function_start = """\
static void decode_@sname@(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, MessageHeader *header, gchar *operation) {

    gboolean stream_is_big_endian;          /* big endianess */
"""
    
    template_helper_function_end = """\
}
"""
    
    #
    # proto_reg_handoff() templates
    #


    template_proto_reg_handoff_start = """
/* register me as handler for these interfaces */

void proto_register_handoff_giop_@dissector_name@(void) {

"""

    template_proto_reg_handoff_body = """
#if 0

/* Register for Explicit Dissection */

register_giop_user_module(dissect_@dissector_name@, \"@protocol_name@\", \"@interface@\", proto_@dissector_name@ );     /* explicit dissector */

#endif

"""

    template_proto_reg_handoff_heuristic = """

/* Register for Heuristic Dissection */

register_giop_user(dissect_@dissector_name@, \"@protocol_name@\" ,proto_@dissector_name@);     /* heuristic dissector */ 

"""

    template_proto_reg_handoff_end = """
}
"""


    #
    # Initialize the protocol
    #

    template_protocol = """
/* Initialise the protocol and subtree pointers */

static int proto_@dissector_name@ = -1;

static gint ett_@dissector_name@ = -1;

"""



    #
    # Initialize the boundary Alignment
    #

    template_init_boundary = """
/* Initialise the initial Alignment */

static guint32  boundary = GIOP_HEADER_SIZE;  /* initial value */

"""





    #
    # Initialize the Registered fields
    #

    template_registered_fields = """

/* Initialise the Registered fields */

/* TODO - Use registered fields */

"""

    #
    # plugin_init and plugin_reg_handoff templates
    #

    template_plugin_init = """

#ifndef __ETHEREAL_STATIC__

G_MODULE_EXPORT void
plugin_reg_handoff(void){
   proto_register_handoff_giop_@dissector_name@();
}

G_MODULE_EXPORT void
plugin_init(plugin_address_table_t *pat){
   /* initialise the table of pointers needed in Win32 DLLs */
   plugin_address_table_init(pat);
   if (proto_@dissector_name@ == -1) {
     proto_register_giop_@dissector_name@();
   }
}

#endif

"""

    #
    # proto_register_<dissector name>(void) templates
    #


    template_proto_register = """

/* Register the protocol with Ethereal */

void proto_register_giop_@dissector_name@(void) {

   /* setup list of header fields */

#if 0
   static hf_register_info hf[] = {

      /* no fields yet */
      
   };
#endif

   /* setup protocol subtree array */

   static gint *ett[] = {
      &ett_@dissector_name@,
   };

   /* Register the protocol name and description */
   
   proto_@dissector_name@ = proto_register_protocol(\"@description@\" , \"@protocol_name@\", \"giop-@dissector_name@\" );

#if 0
   proto_register_field_array(proto_@dissector_name@, hf, array_length(hf));
#endif
   proto_register_subtree_array(ett,array_length(ett));
   
}


"""

    #
    # template for delegation code
    #

    template_delegate_code = """\
if (!strcmp(operation, @sname@_op )) {
   decode_@sname@(tvb, pinfo, tree, offset, header, operation);
   return TRUE;
}
"""

    #
    # Templates for the helper functions
    #
    #
    #


    template_helper_switch_msgtype_start = """\

stream_is_big_endian = is_big_endian(header);

switch(header->message_type) {
"""

    template_helper_switch_msgtype_default_start = """\
default:

    /* Unknown GIOP Exception */

    g_warning("Unknown GIOP Message");
    
"""
    template_helper_switch_msgtype_default_end = """\
break;
"""

    
    
    template_helper_switch_msgtype_end = """\
    
} /* switch(header->message_type) */ 
"""

    template_helper_switch_msgtype_request_start = """\
case Request:
"""
    
    template_helper_switch_msgtype_request_end = """\
break;
"""

    template_helper_switch_msgtype_reply_start = """\
case Reply:
"""
    
    template_helper_switch_msgtype_reply_no_exception_start = """\
case NO_EXCEPTION:
"""
    
    template_helper_switch_msgtype_reply_no_exception_end = """\
break;
"""

    
    template_helper_switch_msgtype_reply_user_exception_start = """\
case USER_EXCEPTION:
"""
    
    template_helper_switch_msgtype_reply_user_exception_end = """\
break;
"""

    template_helper_switch_msgtype_reply_default_start = """\
default:

    /* Unknown Exception */

    g_warning("Unknown Exception ");

    
"""
    
    template_helper_switch_msgtype_reply_default_end = """\
    break;
"""


    template_helper_switch_msgtype_reply_end = """\
break;
"""

    template_helper_switch_msgtype_default_start = """\
default:

    /* Unknown GIOP Message */

    g_warning("Unknown GIOP Message");
    
"""

    template_helper_switch_msgtype_default_end = """\
    break;
"""


    
    template_helper_switch_rep_status_start = """\
switch(header->rep_status) {
"""

    template_helper_switch_rep_status_default_start = """\
default:

    /* Unknown Reply Status */

    g_warning("Unknown Reply Status");
    
"""
    
    template_helper_switch_rep_status_default_end = """\
    break;  
"""
    
    template_helper_switch_rep_status_end = """\

}   /* switch(header->message_type) */

break;   
"""

            



    #
    # Templates for get_CDR_xxx accessors
    #
    
    template_get_CDR_ulong = """\
u_octet4 = get_CDR_ulong(tvb,offset,stream_is_big_endian, boundary);
if (tree) {
   proto_tree_add_text(tree,tvb,*offset-4,4,"@varname@ = %u",u_octet4);
}
"""

    template_get_CDR_short = """\
s_octet2 = get_CDR_short(tvb,offset,stream_is_big_endian, boundary);
if (tree) {
   proto_tree_add_text(tree,tvb,*offset-2,2,"@varname@ = %i",s_octet2);
}
"""
    
    template_get_CDR_void = """\

/* Function returns void */

"""

    template_get_CDR_long = """\
s_octet4 = get_CDR_long(tvb,offset,stream_is_big_endian, boundary);
if (tree) {
   proto_tree_add_text(tree,tvb,*offset-4,4,"@varname@ = %i",s_octet4);
}
"""

    template_get_CDR_ushort = """\
u_octet2 = get_CDR_ushort(tvb,offset,stream_is_big_endian, boundary);
if (tree) {
   proto_tree_add_text(tree,tvb,*offset-2,2,"@varname@ = %u",u_octet2);
}
"""
    template_get_CDR_float = """\
my_float = get_CDR_float(tvb,offset,stream_is_big_endian, boundary);
if (tree) {
   proto_tree_add_text(tree,tvb,*offset-4,4,"@varname@ = %.6e",my_float);
}
"""
    
    template_get_CDR_double = """\
my_double = get_CDR_double(tvb,offset,stream_is_big_endian, boundary);
if (tree) {
   proto_tree_add_text(tree,tvb,*offset-8,8,"@varname@ = %.15e",my_double);
}
"""
    
    template_get_CDR_boolean = """\
u_octet1 = get_CDR_boolean(tvb,offset);
if (tree) {
   proto_tree_add_text(tree,tvb,*offset-1,1,"@varname@ = %u",u_octet1);
}
"""
    
    template_get_CDR_char = """\
u_octet1 = get_CDR_char(tvb,offset);
if (tree) {
   proto_tree_add_text(tree,tvb,*offset-1,1,"@varname@ = %u",u_octet1);
}
"""
    
    template_get_CDR_octet = """\
u_octet1 = get_CDR_octet(tvb,offset);
if (tree) {
   proto_tree_add_text(tree,tvb,*offset-1,1,"@varname@ = %u",u_octet1);
}
"""



    template_get_CDR_any = """\
get_CDR_any(tvb,tree,offset,stream_is_big_endian, boundary, header);

"""

    template_get_CDR_fixed = """\
get_CDR_fixed(tvb, &seq, offset, @digits@, @scale@);
if (tree) {
   proto_tree_add_text(tree,tvb,*offset-@length@, @length@, "@varname@ < @digits@, @scale@> = %s",seq);   
}

g_free(seq);          /*  free buffer  */
seq = NULL;

"""
    
    
    template_get_CDR_enum = """\

/* TODO - translate Enum val into symbolic value */
    
u_octet4 = get_CDR_enum(tvb,offset,stream_is_big_endian, boundary);
if (tree) {
   proto_tree_add_text(tree,tvb,*offset-4,4,"Enum value = %u ",u_octet4);
}
"""

    template_get_CDR_string = """\
u_octet4 = get_CDR_string(tvb, &seq, offset, stream_is_big_endian, boundary);
if (tree) {
   proto_tree_add_text(tree,tvb,*offset-4-u_octet4,4,"length = %u",u_octet4);
   if (u_octet4 > 0)
      proto_tree_add_text(tree,tvb,*offset-u_octet4,u_octet4,"@varname@ = %s",seq);
   
}

g_free(seq);          /*  free buffer  */
seq = NULL;
"""

   
    template_get_CDR_wstring = """\
u_octet4 = get_CDR_wstring(tvb, &seq, offset, stream_is_big_endian, boundary, header);
if (tree) {
   proto_tree_add_text(tree,tvb,*offset-4-u_octet4,4,"length = %u",u_octet4);
   if (u_octet4 > 0)
      proto_tree_add_text(tree,tvb,*offset-u_octet4,u_octet4,"@varname@ = %s",seq);
   
}

g_free(seq);          /*  free buffer  */
seq = NULL;
"""

   
    template_get_CDR_wchar = """\
s_octet1 = get_CDR_wchar(tvb, &seq, offset, header);
if (tree) {
    if (s_octet1 > 0)
        proto_tree_add_text(tree,tvb,*offset-1-s_octet1,1,"length = %u",s_octet1);

    if (s_octet1 < 0)
        s_octet1 = -s_octet1;

    if (s_octet1 > 0)
        proto_tree_add_text(tree,tvb,*offset-s_octet1,s_octet1,"@varname@ = %s",seq);
           
}
        
g_free(seq);          /*  free buffer  */
seq = NULL;
"""




    template_get_CDR_TypeCode = """\
u_octet4 = get_CDR_typeCode(tvb, tree, offset, stream_is_big_endian, boundary, header);

"""
    
    template_get_CDR_object = """\
get_CDR_object(tvb, pinfo, tree, offset, stream_is_big_endian, boundary);

"""
    

    template_get_CDR_sequence_length = """\
u_octet4_loop_@seqname@ = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);
if (tree) {
   proto_tree_add_text(tree,tvb,*offset-4, 4 ,"Seq length of @seqname@ = %u",u_octet4_loop_@seqname@);   
}
"""

    template_get_CDR_sequence_loop_start = """\
for (i_@seqname@=0; i_@seqname@ < u_octet4_loop_@seqname@; i_@seqname@++) {
"""
    template_get_CDR_sequence_loop_end = """\
}
"""
    


    template_get_CDR_array_start = """\
for (i_@aname@=0; i_@aname@ < @aval@; i_@aname@++) {
"""
    template_get_CDR_array_end = """\
}
"""

    template_get_CDR_array_comment = """\
/* Array: @aname@[ @asize@]  */
"""
            



    template_structure_start = """\
/*  Begin struct \"@name@\"  */
"""


    template_structure_end = """\
/*  End struct \"@name@\"  */
"""




#
# Program Header Template
#

    template_Header = """\
/*    
 * packet-@dissector_name@-idl.c
 * Routines for IDL dissection
 *
 * Autogenerated from idl2eth
 * Copyright 2001 Frank Singleton <frank.singleton@@ericsson.com>
 */

"""

    template_ethereal_copyright = """\
/*
 * Ethereal - Network traffic analyzer
 * By Gerald Combs
 * Copyright 1999 Gerald Combs
 */
 
"""
    


#
# GPL Template
#


    template_GPL = """\
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */
"""

#
# Includes template
#

    template_Includes = """\

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "plugins/plugin_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <gmodule.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "proto.h"
#include "packet-giop.h"

#ifndef __ETHEREAL_STATIC__
G_MODULE_EXPORT const gchar version[] = "0.0.1";
#endif

"""

    
#
# Main dissector entry templates
#

    template_main_dissector_start = """\
static gboolean dissect_@dissname@(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ptree, int *offset, MessageHeader *header, gchar *operation, gchar *idlname) {

    proto_item *ti = NULL;
    proto_tree *tree = NULL;            /* init later, inside if(tree) */
    
    gboolean be;                        /* big endianess */
    guint32  offset_saved = (*offset);  /* save in case we must back out */

    pinfo->current_proto = \"@disprot@\";

    if (check_col(pinfo->fd, COL_PROTOCOL))
       col_add_str(pinfo->fd, COL_PROTOCOL, \"@disprot@\");

    if (ptree) {
       ti = proto_tree_add_item(ptree, proto_@dissname@, tvb, *offset, tvb_length(tvb) - *offset, FALSE);
       tree = proto_item_add_subtree(ti, ett_@dissname@);
    }  


    be = is_big_endian(header);         /* get endianess - TODO use passed in stream_is_big_endian instead ? */

    /* If we have a USER Exception, then decode it and return */

    if ((header->message_type == Reply) && (header->rep_status == USER_EXCEPTION)) {

       return decode_user_exception(tvb, pinfo, tree, offset, header, operation);

    }

    
"""


       

    template_main_dissector_switch_msgtype_start = """\
switch(header->message_type) {
"""
    
    template_main_dissector_switch_msgtype_start_request_reply = """\
case Request:
case Reply:

"""

    template_main_dissector_switch_msgtype_end_request_reply = """\

break;
"""


    template_main_dissector_switch_msgtype_end = """\


/*
 * We failed to match ANY operations, so perhaps this is not for us !
 */

(*offset) = offset_saved;       /* be nice */

return FALSE;


"""



    
    template_main_dissector_switch_msgtype_all_other_msgtype = """\
case CancelRequest:
case LocateRequest:
case LocateReply:
case CloseConnection:
case MessageError:
case Fragment:
   return FALSE;      /* not handled yet */

default:
   return FALSE;      /* not handled yet */

}   /* switch */

"""


    template_main_dissector_switch_msgtype_end = """\

   return TRUE;

} /* switch */

"""

    template_main_dissector_end = """\

    return FALSE;

}  /* End of main dissector  */

"""


    




#-------------------------------------------------------------#
#             Exception handling templates                    #
#-------------------------------------------------------------#







    template_exception_helpers_start = """\
/*  Begin Exception Helper Functions  */

"""
    
    template_exception_helpers_end = """\
    
/*  End Exception Helper Functions  */

"""



#
# Templates for declaration of string constants for user exceptions.
#
    
    template_comment_user_exceptions_string_declare_start = """\
/*  Begin Exception (containing members) String  Declare  */

"""
    
    template_user_exceptions_declare = """static const char user_exception_@sname@[] = \"@exname@\" ; """

    
    template_comment_user_exceptions_string_declare_end = """\
    
/*  End Exception (containing members) String Declare  */

"""


    

#
# template for Main delegator for exception handling
#

    template_main_exception_delegator_start = """\

/*
 * Main delegator for exception handling
 *
 */
 
static gboolean decode_user_exception(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, MessageHeader *header, gchar *operation ) {
    
    gboolean be;                        /* big endianess */

    
"""


#
# template for exception delegation code body
#
    template_ex_delegate_code = """\
if (!strcmp(header->exception_id, user_exception_@sname@ )) {
   decode_ex_@sname@(tvb, pinfo, tree, offset, header, operation);   /*  @exname@  */
   return TRUE;
}

"""


#
# End of Main delegator for exception handling
#

    template_main_exception_delegator_end = """\


    return FALSE;    /* user exception not found */

}
    
"""
    
#
# template for exception helper code
#


    template_exception_helper_function_start = """\

/* Exception = @exname@ */

static void decode_ex_@sname@(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, MessageHeader *header, gchar *operation) {

    gboolean stream_is_big_endian;          /* big endianess */
"""



    #
    # Template for the helper function
    # to get stream endianess from header
    #

    template_exception_helper_function_get_endianess = """\

stream_is_big_endian = is_big_endian(header);  /* get stream endianess */

"""

    
    template_exception_helper_function_end = """\
}
"""




    
