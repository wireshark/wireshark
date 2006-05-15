#!/usr/bin/env python

#
# competh.py
# ASN.1 to Ethereal dissector compiler
# 2004 Tomas Kukosa 
#
# $Id$
#

"""ASN.1 to Ethereal dissector compiler"""

#
# Compiler from ASN.1 specification to the Ethereal dissector
#
# Based on ASN.1 to Python compiler from Aaron S. Lav's PyZ3950 package licensed under the X Consortium license
# http://www.pobox.com/~asl2/software/PyZ3950/
# (ASN.1 to Python compiler functionality is broken but not removed, it could be revived if necessary)
#
# It requires Dave Beazley's PLY parsing package licensed under the LGPL (tested with version 1.6)
# http://www.dabeaz.com/ply/
# 
# 
# ITU-T Recommendation X.680 (07/2002), 
#   Information technology - Abstract Syntax Notation One (ASN.1): Specification of basic notation
#
# ITU-T Recommendation X.682 (07/2002), 
#   Information technology - Abstract Syntax Notation One (ASN.1): Constraint specification
#
# ITU-T Recommendation X.683 (07/2002), 
#   Information technology - Abstract Syntax Notation One (ASN.1): Parameterization of ASN.1 specifications
#

from __future__ import nested_scopes

import warnings

import re
import sys
import os
import os.path
import time
import getopt

import __main__ # XXX blech!
import lex
import yacc

# OID name -> number conversion table
oid_names = {
  '/itu-t' : 0,
  '/itu'   : 0,
  '/ccitt' : 0,
  '/itu-r' : 0,
  '0/recommendation' : 0,
  '0.0/a' : 1,
  '0.0/b' : 2,
  '0.0/c' : 3,
  '0.0/d' : 4,
  '0.0/e' : 5,
  '0.0/f' : 6,
  '0.0/g' : 7,
  '0.0/h' : 8,
  '0.0/i' : 9,
  '0.0/j' : 10,
  '0.0/k' : 11,
  '0.0/l' : 12,
  '0.0/m' : 13,
  '0.0/n' : 14,
  '0.0/o' : 15,
  '0.0/p' : 16,
  '0.0/q' : 17,
  '0.0/r' : 18,
  '0.0/s' : 19,
  '0.0/t' : 20,
  '0.0/tseries' : 20,
  '0.0/u' : 21,
  '0.0/v' : 22,
  '0.0/w' : 23,
  '0.0/x' : 24,
  '0.0/y' : 25,
  '0.0/z' : 26,
  '0/question' : 1,
  '0/administration' : 2,
  '0/network-operator' : 3,
  '0/identified-organization' : 4,
  '0/r-recommendation' : 5,
  '0/data' : 9,
  '/iso' : 1,
  '1/standard' : 0,
  '1/registration-authority' : 1,
  '1/member-body' : 2,
  '1/identified-organization' : 3,
  '/joint-iso-itu-t' : 2,
  '/joint-iso-ccitt' : 2,
  '2/presentation' : 0,
  '2/asn1' : 1,
  '2/association-control' : 2,
  '2/reliable-transfer' : 3,
  '2/remote-operations' : 4,
  '2/ds' : 5,
  '2/directory' : 5,
  '2/mhs' : 6,
  '2/mhs-motis' : 6,
  '2/ccr' : 7,
  '2/oda' : 8,
  '2/ms' : 9,
  '2/osi-management' : 9,
  '2/transaction-processing' : 10,
  '2/dor' : 11,
  '2/distinguished-object-reference' : 11,
  '2/reference-data-transfe' : 12,
  '2/network-layer' : 13,
  '2/network-layer-management' : 13,
  '2/transport-layer' : 14,
  '2/transport-layer-management' : 14,
  '2/datalink-layer' : 15,
  '2/datalink-layer-managemen' : 15,
  '2/datalink-layer-management-information' : 15,
  '2/country' : 16,
  '2/registration-procedures' : 17,
  '2/registration-procedure' : 17,
  '2/physical-layer' : 18,
  '2/physical-layer-management' : 18,
  '2/mheg' : 19,
  '2/genericULS' : 20,
  '2/generic-upper-layers-security' : 20,
  '2/guls' : 20,
  '2/transport-layer-security-protocol' : 21,
  '2/network-layer-security-protocol' : 22,
  '2/international-organizations' : 23,
  '2/internationalRA' : 23,
  '2/sios' : 24,
  '2/uuid' : 25,
  '2/odp' : 26,
  '2/upu' : 40,
}

def asn2c(id):
  return id.replace('-', '_').replace('.', '_')

class LexError(Exception): pass
class ParseError(Exception): pass

# 11 ASN.1 lexical items

static_tokens = {
  r'::='    : 'ASSIGNMENT',  # 11.16 Assignment lexical item
  r'\.\.'   : 'RANGE',       # 11.17 Range separator
  r'\.\.\.' : 'ELLIPSIS',    # 11.18 Ellipsis
  #r'\[\['   : 'LVERBRACK',   # 11.19 Left version brackets
  #r'\]\]'   : 'RVERBRACK',   # 11.20 Right version brackets
  # 11.26 Single character lexical items
  r'\{' : 'LBRACE',
  r'\}' : 'RBRACE',
  r'<'  : 'LT',
  #r'>'  : 'GT',
  r','  : 'COMMA',
  r'\.' : 'DOT',
  r'\(' : 'LPAREN',
  r'\)' : 'RPAREN',
  r'\[' : 'LBRACK',
  r'\]' : 'RBRACK',
  r'-'  : 'MINUS',
  r':'  : 'COLON',
  #r'='  : 'EQ',
  #r'"'  : 'QUOTATION',
  #r"'"  : 'APOSTROPHE',
  r';'  : 'SEMICOLON',
  #r'@'  : 'AT',
  #r'\!' : 'EXCLAMATION',
  r'\^' : 'CIRCUMFLEX'
}

# 11.27 Reserved words

# all keys in reserved_words must start w/ upper case
reserved_words = {
    'TAGS' : 'TAGS',
    'BOOLEAN' : 'BOOLEAN',
    'INTEGER' : 'INTEGER',
    'BIT'     : 'BIT',
    'CHARACTER' : 'CHARACTER',
    'STRING'  : 'STRING',
    'OCTET'   : 'OCTET',
    'NULL'    : 'NULL',
    'SEQUENCE': 'SEQUENCE',
    'OF'      : 'OF',
    'SET'     : 'SET',
    'IMPLICIT': 'IMPLICIT',
    'CHOICE'  : 'CHOICE',
    'ANY'     : 'ANY',
#    'EXTERNAL' : 'EXTERNAL', # XXX added over base
    'OPTIONAL':'OPTIONAL',
    'DEFAULT' : 'DEFAULT',
    'COMPONENTS': 'COMPONENTS',
    'UNIVERSAL' : 'UNIVERSAL',
    'APPLICATION' : 'APPLICATION',
    'PRIVATE'   : 'PRIVATE',
    'TRUE' : 'TRUE',
    'FALSE' : 'FALSE',
    'BEGIN' : 'BEGIN',
    'END' : 'END',
    'DEFINITIONS' : 'DEFINITIONS',
    'EXPLICIT' : 'EXPLICIT',
    'ENUMERATED' : 'ENUMERATED',
    'EXPORTS' : 'EXPORTS',
    'IMPORTS' : 'IMPORTS',
    'REAL'    : 'REAL',
    'INCLUDES': 'INCLUDES',
    'MIN'     : 'MIN',
    'MAX'     : 'MAX',
    'SIZE'    : 'SIZE',
    'FROM'    : 'FROM',
    'INTERSECTION' : 'INTERSECTION',
#    'UNION'   : 'UNION',
    'PATTERN'    : 'PATTERN',
    'WITH'    : 'WITH',
    'COMPONENT': 'COMPONENT',
    'PRESENT'  : 'PRESENT',
    'ABSENT'   : 'ABSENT',
#    'DEFINED'  : 'DEFINED',
    'CONSTRAINED' : 'CONSTRAINED',
    'BY'       : 'BY',
    'PLUS-INFINITY'   : 'PLUS_INFINITY',
    'MINUS-INFINITY'  : 'MINUS_INFINITY',
    'GeneralizedTime' : 'GeneralizedTime',
    'UTCTime'         : 'UTCTime',
    'ObjectDescriptor': 'ObjectDescriptor',
    'AUTOMATIC': 'AUTOMATIC',
    'OBJECT': 'OBJECT',
    'IDENTIFIER': 'IDENTIFIER',
#      'OPERATION'       : 'OPERATION',
#      'ARGUMENT'        : 'ARGUMENT',
#      'RESULT'          : 'RESULT',
#      'ERRORS'          : 'ERRORS',
#      'LINKED'          : 'LINKED',
#      'ERROR'           : 'ERROR',
#      'PARAMETER'       : 'PARAMETER',
#      'BIND'            : 'BIND',
#      'BIND-ERROR'      : 'BIND_ERROR',
#      'UNBIND'          : 'UNBIND',
#      'APPLICATION-CONTEXT' : 'AC',
#      'APPLICATON-SERVICE-ELEMENTS' : 'ASES',
#      'REMOTE' : 'REMOTE',
#      'INITIATOR' : 'INITIATOR',
#      'RESPONDER' : 'RESPONDER',
#      'APPLICATION-SERVICE-ELEMENT' : 'ASE',
#      'OPERATIONS' : None,
#      'EXTENSION-ATTRIBUTE' : 'EXTENSION_ATTRIBUTE',
#      'EXTENSIONS' : None,
#      'CHOSEN' : None,
#      'EXTENSION' : None,
#      'CRITICAL': None,
#      'FOR' : None,
#      'SUBMISSION' : None,
#      'DELIVERY' : None,
#      'TRANSFER' : None,
#      'OBJECT' : None,
#      'PORTS' : None,
#      'PORT'  : None,
#      r'ABSTRACT\s*OPERATIONS' : 'ABSTR_OPS',
#      'REFINE' : None,
#      'AS' : None,
#      'RECURRING' : None
    }

for k in static_tokens.keys ():
    if static_tokens [k] == None:
        static_tokens [k] = k

StringTypes = ['Numeric', 'Printable', 'IA5', 'BMP', 'Universal', 'UTF8',
               'Teletex', 'T61', 'Videotex', 'Graphic', 'ISO646', 'Visible',
               'General']

for s in StringTypes:
  reserved_words[s + 'String'] = s + 'String'

tokens = static_tokens.values() \
         + reserved_words.values() \
         + ['BSTRING', 'HSTRING', 'QSTRING',
            'UCASE_IDENT', 'LCASE_IDENT',
            'NUMBER', 'PYQUOTE']


for (k, v) in static_tokens.items ():
  __main__.__dict__['t_' + v] = k

# 11.10 Binary strings
def t_BSTRING (t):
    r"'[01]*'B"
    return t

# 11.12 Hexadecimal strings
def t_HSTRING (t):
    r"'[0-9A-Fa-f]*'H"
    return t

def t_QSTRING (t):
    r'"([^"]|"")*"'
    return t # XXX might want to un-""

def t_UCASE_IDENT (t):
    r"[A-Z](-[a-zA-Z0-9]|[a-zA-Z0-9])*" # can't end w/ '-'
    t.type = reserved_words.get(t.value, "UCASE_IDENT")
    return t

def t_LCASE_IDENT (t):
    r"[a-z](-[a-zA-Z0-9]|[a-zA-Z0-9])*" # can't end w/ '-'
    return t

# 11.8 Numbers
def t_NUMBER (t):
    r"0|([1-9][0-9]*)"
    return t

# 11.9 Real numbers
# not supported yet

# 11.6 Comments
pyquote_str = 'PYQUOTE'
def t_COMMENT(t):
    r"--(-[^\-\n]|[^\-\n])*(--|\n|-\n|$|-$)"
    if (t.value.find("\n") >= 0) : t.lineno += 1
    if t.value[2:2+len (pyquote_str)] == pyquote_str:
        t.value = t.value[2+len(pyquote_str):]
        t.value = t.value.lstrip ()
        t.type = pyquote_str
        return t
    return None

t_ignore = " \t\r"

def t_NEWLINE(t):
    r'\n+'
    t.lineno += t.value.count("\n")

def t_error(t):
    print "Error", t.value[:100], t.lineno
    raise LexError

    

class Ctx:
    def __init__ (self, defined_dict, indent = 0):
        self.tags_def = 'EXPLICIT' # default = explicit
        self.indent_lev = 0
        self.assignments = {}
        self.dependencies = {}
        self.pyquotes = []
        self.defined_dict = defined_dict
        self.name_ctr = 0
    def spaces (self):
        return " " * (4 * self.indent_lev)
    def indent (self):
        self.indent_lev += 1
    def outdent (self):
        self.indent_lev -= 1
        assert (self.indent_lev >= 0)
    def register_assignment (self, ident, val, dependencies):
        if self.assignments.has_key (ident):
            raise "Duplicate assignment for " + ident
        if self.defined_dict.has_key (ident):
            raise "cross-module duplicates for " + ident
        self.defined_dict [ident] = 1
        self.assignments[ident] = val
        self.dependencies [ident] = dependencies
        return ""
    #        return "#%s depends on %s" % (ident, str (dependencies))
    def register_pyquote (self, val):
        self.pyquotes.append (val)
        return ""
    def output_assignments (self):
        already_output = {}
        text_list = []
        assign_keys = self.assignments.keys()
        to_output_count = len (assign_keys)
        while 1:
            any_output = 0
            for (ident, val) in self.assignments.iteritems ():
                if already_output.has_key (ident):
                    continue
                ok = 1
                for d in self.dependencies [ident]:
                    if (not already_output.has_key (d) and
                        d in assign_keys):
                        ok = 0
                if ok:
                    text_list.append ("%s=%s" % (ident,
                                                self.assignments [ident]))
                    already_output [ident] = 1
                    any_output = 1
                    to_output_count -= 1
                    assert (to_output_count >= 0)
            if not any_output:
                if to_output_count == 0:
                    break
                # OK, we detected a cycle
                cycle_list = []
                for ident in self.assignments.iterkeys ():
                    if not already_output.has_key (ident):
                        depend_list = [d for d in self.dependencies[ident] if d in assign_keys]
                        cycle_list.append ("%s(%s)" % (ident, ",".join (depend_list)))
                        
                text_list.append ("# Cycle XXX " + ",".join (cycle_list))
                for (ident, val) in self.assignments.iteritems ():
                    if not already_output.has_key (ident):
                        text_list.append ("%s=%s" % (ident, self.assignments [ident]))
                break

        return "\n".join (text_list)
    def output_pyquotes (self):
        return "\n".join (self.pyquotes)
    def make_new_name (self):
        self.name_ctr += 1
        return "_compiler_generated_name_%d" % (self.name_ctr,)

#--- EthCtx -------------------------------------------------------------------
class EthCtx:
  def __init__(self, conform, output, indent = 0):
    self.conform = conform
    self.output = output

  def encp(self):  # encoding protocol
    encp = self.encoding
    return encp

  # Encoding
  def Per(self): return self.encoding == 'per'
  def Ber(self): return self.encoding == 'ber'
  def Aligned(self): return self.aligned
  def Unaligned(self): return not self.aligned
  def NAPI(self): return False  # disable planned features

  def dbg(self, d):
    if (self.dbgopt.find(d) >= 0):
      return True
    else:
      return False

  def eth_get_type_attr(self, type):
    types = [type]
    while (not self.type[type]['import'] 
           and self.type[type]['val'].type == 'Type_Ref'):
      type = self.type[type]['val'].val
      types.append(type)
    attr = {}
    while len(types):
      t = types.pop()
      attr.update(self.type[t]['attr'])
      attr.update(self.eth_type[self.type[t]['ethname']]['attr'])
    return attr

  #--- eth_reg_assign ---------------------------------------------------------
  def eth_reg_assign(self, ident, val):
    #print "eth_reg_assign(ident='%s')" % (ident)
    if self.assign.has_key(ident):
      raise "Duplicate assignment for " + ident
    self.assign[ident] = val
    self.assign_ord.append(ident)

  #--- eth_reg_vassign --------------------------------------------------------
  def eth_reg_vassign(self, vassign):
    ident = vassign.ident
    #print "eth_reg_vassign(ident='%s')" % (ident)
    if self.vassign.has_key(ident):
      raise "Duplicate value assignment for " + ident
    self.vassign[ident] = vassign
    self.vassign_ord.append(ident)

  #--- eth_import_type --------------------------------------------------------
  def eth_import_type(self, ident, mod, proto):
    #print "eth_import_type(ident='%s', mod='%s', prot='%s')" % (ident, mod, prot)
    if self.type.has_key(ident):
      raise "Duplicate type for " + ident
    self.type[ident] = {'import'  : mod, 'proto' : proto,
                        'ethname' : '' }
    self.type[ident]['attr'] = { 'TYPE' : 'FT_NONE', 'DISPLAY' : 'BASE_NONE',
                                 'STRINGS' : 'NULL', 'BITMASK' : '0' }
    self.type[ident]['attr'].update(self.conform.use_item('TYPE_ATTR', ident))
    self.type_imp.append(ident)

  #--- eth_import_value -------------------------------------------------------
  def eth_import_value(self, ident, mod, proto):
    #print "eth_import_value(ident='%s', mod='%s', prot='%s')" % (ident, mod, prot)
    if self.type.has_key(ident):
      raise "Duplicate value for " + ident
    self.value[ident] = {'import'  : mod, 'proto' : proto,
                         'ethname' : ''}
    self.value_imp.append(ident)

  #--- eth_dep_add ------------------------------------------------------------
  def eth_dep_add(self, type, dep):
    if self.type_dep.has_key(type):
      self.type_dep[type].append(dep)
    else:
      self.type_dep[type] = [dep]

  #--- eth_reg_type -----------------------------------------------------------
  def eth_reg_type(self, ident, val):
    #print "eth_reg_type(ident='%s')" % (ident)
    if self.type.has_key(ident):
      raise "Duplicate type for " + ident
    self.type[ident] = { 'val' : val, 'import' : None }
    if len(ident.split('/')) > 1:
      self.type[ident]['tname'] = val.eth_tname()
    else:
      self.type[ident]['tname'] = asn2c(ident)
    self.type[ident]['export'] = self.conform.use_item('EXPORTS', ident)
    self.type[ident]['user_def'] = self.conform.use_item('USER_DEFINED', ident)
    self.type[ident]['no_emit'] = self.conform.use_item('NO_EMIT', ident)
    self.type[ident]['tname'] = self.conform.use_item('TYPE_RENAME', ident, val_dflt=self.type[ident]['tname'])
    self.type[ident]['ethname'] = ''
    if val.type == 'Type_Ref':
      self.type[ident]['attr'] = {}
    else:
      (ftype, display) = val.eth_ftype(self)
      self.type[ident]['attr'] = { 'TYPE' : ftype, 'DISPLAY' : display,
                                   'STRINGS' : val.eth_strings(), 'BITMASK' : '0' }
    self.type[ident]['attr'].update(self.conform.use_item('TYPE_ATTR', ident))
    self.type_ord.append(ident)

  #--- eth_reg_value ----------------------------------------------------------
  def eth_reg_value(self, ident, type, value):
    #print "eth_reg_value(ident='%s')" % (ident)
    if self.value.has_key(ident):
      raise "Duplicate value for " + ident
    self.value[ident] = { 'import' : None, 'proto' : self.proto,
                          'type' : type, 'value' : value }
    self.value[ident]['export'] = self.conform.use_item('EXPORTS', ident)
    self.value[ident]['ethname'] = ''
    self.value_ord.append(ident)

  #--- eth_reg_field ----------------------------------------------------------
  def eth_reg_field(self, ident, type, idx='', parent=None, impl=False, pdu=None):
    #print "eth_reg_field(ident='%s', type='%s')" % (ident, type)
    if self.field.has_key(ident):
      raise "Duplicate field for " + ident
    self.field[ident] = {'type' : type, 'idx' : idx, 'impl' : impl, 'pdu' : pdu,
                         'modified' : '', 'attr' : {} }
    name = ident.split('/')[-1]
    if len(ident.split('/')) > 1 and name == '_item':  # Sequnce/Set of type
      self.field[ident]['attr']['NAME'] = '"Item"'
      self.field[ident]['attr']['ABBREV'] = asn2c(ident.split('/')[-2] + name)
    else:
      self.field[ident]['attr']['NAME'] = '"%s"' % name
      self.field[ident]['attr']['ABBREV'] = asn2c(name)
    if self.conform.check_item('FIELD_ATTR', ident):
      self.field[ident]['modified'] = '#' + str(id(self))
      self.field[ident]['attr'].update(self.conform.use_item('FIELD_ATTR', ident))
    if (pdu):
      self.pdu_ord.append(ident)
    else:
      self.field_ord.append(ident)
    if parent: self.eth_dep_add(parent, type)

  #--- eth_clean --------------------------------------------------------------
  def eth_clean(self):
    self.proto = self.proto_opt;
    #--- ASN.1 tables ----------------
    self.assign = {}
    self.assign_ord = []
    self.field = {}
    self.pdu_ord = []
    self.field_ord = []
    self.type = {}
    self.type_ord = []
    self.type_imp = []
    self.type_dep = {}
    self.vassign = {}
    self.vassign_ord = []
    self.value = {}
    self.value_ord = []
    self.value_imp = []
    #--- Modules ------------
    self.modules = []
    #--- types -------------------
    self.eth_type = {}
    self.eth_type_ord = []
    self.eth_export_ord = []
    self.eth_type_dupl = {}
    self.named_bit = []
    #--- value dependencies -------------------
    self.value_dep = {}
    #--- values -------------------
    self.eth_value = {}
    self.eth_value_ord = []
    #--- fields -------------------------
    self.eth_hf = {}
    self.eth_hf_ord = []
    self.eth_hfpdu_ord = []
    self.eth_hf_dupl = {}
    #--- type dependencies -------------------
    self.eth_type_ord1 = []
    self.eth_dep_cycle = []
    self.dep_cycle_eth_type = {}
    #--- value dependencies and export -------------------
    self.eth_value_ord1 = []
    self.eth_vexport_ord = []

  #--- eth_prepare ------------------------------------------------------------
  def eth_prepare(self):
    self.eproto = asn2c(self.proto)

    #--- dummy types/fields for PDU registration ---
    nm = 'NULL'
    if (self.conform.check_item('PDU', nm)):
      self.eth_reg_type('_dummy/'+nm, NullType())
      self.eth_reg_field(nm, '_dummy/'+nm, pdu=self.conform.use_item('PDU', nm))

    #--- types -------------------
    for t in self.type_imp:
      nm = asn2c(t)
      self.eth_type[nm] = { 'import' : self.type[t]['import'], 
                            'proto' : asn2c(self.type[t]['proto']),
                            'attr' : {}, 'ref' : []}
      self.type[t]['ethname'] = nm
    for t in self.type_ord:
      nm = self.type[t]['tname']
      if ((nm.find('#') >= 0) or 
          ((len(t.split('/'))>1) and 
           (self.conform.get_fn_presence(t) or self.conform.check_item('FN_PARS', t)) and 
           not self.conform.check_item('TYPE_RENAME', t))):
        if len(t.split('/')) == 2 and t.split('/')[1] == '_item':  # Sequnce of type at the 1st level
          nm = t.split('/')[0] + t.split('/')[1]
        elif t.split('/')[-1] == '_item':  # Sequnce of type at next levels
          nm = 'T_' + t.split('/')[-2] + t.split('/')[-1]
        else:
          nm = 'T_' + t.split('/')[-1]
        nm = asn2c(nm)
        if self.eth_type.has_key(nm):
          if self.eth_type_dupl.has_key(nm):
            self.eth_type_dupl[nm].append(t)
          else:
            self.eth_type_dupl[nm] = [self.eth_type[nm]['ref'][0], t]
          nm += str(len(self.eth_type_dupl[nm])-1)
      if self.eth_type.has_key(nm):
        self.eth_type[nm]['ref'].append(t)
      else:
        self.eth_type_ord.append(nm)
        self.eth_type[nm] = { 'import' : None, 'proto' : self.eproto, 'export' : 0,
                              'user_def' : 0x03, 'no_emit' : 0x03, 
                              'val' : self.type[t]['val'], 
                              'attr' : {}, 
                              'ref' : [t]}
        self.eth_type[nm]['attr'].update(self.conform.use_item('ETYPE_ATTR', nm))
      self.type[t]['ethname'] = nm
      if (not self.eth_type[nm]['export'] and self.type[t]['export']):  # new export
        self.eth_export_ord.append(nm)
      self.eth_type[nm]['export'] |= self.type[t]['export']
      self.eth_type[nm]['user_def'] &= self.type[t]['user_def']
      self.eth_type[nm]['no_emit'] &= self.type[t]['no_emit']
      if self.type[t]['attr'].get('STRINGS') == '$$':
        self.eth_type[nm]['attr']['STRINGS'] = 'VALS(%s)' % (self.eth_vals_nm(nm))
    for t in self.eth_type_ord:
      bits = self.eth_type[t]['val'].eth_named_bits()
      if (bits):
        for (val, id) in bits:
          self.named_bit.append({'name' : id, 'val' : val,
                                 'ethname' : 'hf_%s_%s_%s' % (self.eproto, t, asn2c(id)),
                                 'ftype'   : 'FT_BOOLEAN', 'display' : '8',
                                 'strings' : 'NULL',
                                 'bitmask' : '0x'+('80','40','20','10','08','04','02','01')[val%8]})
      if self.eth_type[t]['val'].eth_need_tree():
        self.eth_type[t]['tree'] = "ett_%s_%s" % (self.eth_type[t]['proto'], t)
      else:
        self.eth_type[t]['tree'] = None

    #--- value dependencies -------------------
    for v in self.value_ord:
      if isinstance (self.value[v]['value'], Value):
        dep = self.value[v]['value'].get_dep()
      else:
        dep = self.value[v]['value']
      if dep and self.value.has_key(dep):
        self.value_dep.setdefault(v, []).append(dep)
    
    #--- exports all necessary values
    for v in self.value_ord:
      if not self.value[v]['export']: continue
      deparr = self.value_dep.get(v, [])
      while deparr:
        d = deparr.pop()
        if not self.value[d]['import']:
          if not self.value[d]['export']:
            self.value[d]['export'] = 0x01
            deparr.extend(self.value_dep.get(d, []))

    #--- values -------------------
    for v in self.value_imp:
      nm = asn2c(v)
      self.eth_value[nm] = { 'import' : self.value[v]['import'], 
                             'proto' : asn2c(self.value[v]['proto']), 
                             'ref' : []}
      self.value[v]['ethname'] = nm
    for v in self.value_ord:
      nm = asn2c(v)
      self.eth_value[nm] = { 'import' : None, 
                             'proto' : asn2c(self.value[v]['proto']),
                             'export' : self.value[v]['export'], 'ref' : [v] }
      if isinstance (self.value[v]['value'], Value):
        self.eth_value[nm]['value'] = self.value[v]['value'].to_str()
      else:
        self.eth_value[nm]['value'] = self.value[v]['value']
      self.eth_value_ord.append(nm)
      self.value[v]['ethname'] = nm

    #--- fields -------------------------
    for f in (self.pdu_ord + self.field_ord):
      if len(f.split('/')) > 1 and f.split('/')[-1] == '_item':  # Sequnce/Set of type
        nm = f.split('/')[-2] + f.split('/')[-1]
      else:
        nm = f.split('/')[-1]
      nm = self.conform.use_item('FIELD_RENAME', f, val_dflt=nm)
      nm = asn2c(nm)
      if (self.field[f]['pdu']): 
        nm += '_PDU'
      t = self.field[f]['type']
      if self.type.has_key(t):
        ethtype = self.type[t]['ethname']
      else:  # undefined type
        # dummy imported
        print "Dummy imported: ", t
        self.type[t] = {'import'  : 'xxx', 'proto' : 'xxx',
                        'ethname' : t }
        self.type[t]['attr'] = { 'TYPE' : 'FT_NONE', 'DISPLAY' : 'BASE_NONE',
                                 'STRINGS' : 'NULL', 'BITMASK' : '0' }
        self.eth_type[t] = { 'import' : 'xxx', 'proto' : 'xxx' , 'attr' : {}, 'ref' : []}
        ethtype = t
      ethtypemod = ethtype + self.field[f]['modified']
      if self.eth_hf.has_key(nm):
        if self.eth_hf_dupl.has_key(nm):
          if self.eth_hf_dupl[nm].has_key(ethtypemod):
            nm = self.eth_hf_dupl[nm][ethtypemod]
            self.eth_hf[nm]['ref'].append(f)
            self.field[f]['ethname'] = nm
            continue
          else:
            nmx = nm + str(len(self.eth_hf_dupl[nm]))
            self.eth_hf_dupl[nm][ethtype] = nmx
            nm = nmx
        else:
          if (self.eth_hf[nm]['ethtype']+self.eth_hf[nm]['modified']) == ethtypemod:
            self.eth_hf[nm]['ref'].append(f)
            self.field[f]['ethname'] = nm
            continue
          else:
            self.eth_hf_dupl[nm] = {self.eth_hf[nm]['ethtype']+self.eth_hf[nm]['modified'] : nm, \
                                    ethtypemod : nm+'1'}
            nm += '1'
      if (self.field[f]['pdu']):
        self.eth_hfpdu_ord.append(nm)
      else:
        self.eth_hf_ord.append(nm)
      fullname = "hf_%s_%s" % (self.eproto, nm)
      attr = self.eth_get_type_attr(self.field[f]['type']).copy()
      attr.update(self.field[f]['attr'])
      if (self.NAPI() and attr.has_key('NAME')):
        attr['NAME'] += self.field[f]['idx']
      attr.update(self.conform.use_item('EFIELD_ATTR', nm))
      self.eth_hf[nm] = {'fullname' : fullname, 'pdu' : self.field[f]['pdu'],
                         'ethtype' : ethtype, 'modified' : self.field[f]['modified'],
                         'attr' : attr.copy(), 'ref' : [f]}
      self.field[f]['ethname'] = nm
    #--- type dependencies -------------------
    x = {}  # already emitted
    #print '# Dependency computation'
    for t in self.type_ord:
      if x.has_key(self.type[t]['ethname']):
        #print 'Continue: %s : %s' % (t, self.type[t]['ethname'])
        continue
      stack = [t]
      stackx = {t : self.type_dep.get(t, [])[:]}
      #print 'Push: %s : %s' % (t, str(stackx[t]))
      while stack:
        if stackx[stack[-1]]:  # has dependencies
          d = stackx[stack[-1]].pop(0)
          if x.has_key(self.type[d]['ethname']) or self.type[d]['import']:
            continue
          if stackx.has_key(d):  # cyclic dependency
            c = stack[:]
            c.reverse()
            c = [d] + c[0:c.index(d)+1]
            c.reverse()
            self.eth_dep_cycle.append(c)
            #print 'Cyclic: %s ' % (' -> '.join(c))
            continue
          stack.append(d)
          stackx[d] = self.type_dep.get(d, [])[:]
          #print 'Push: %s : %s' % (d, str(stackx[d]))
        else:
          #print 'Pop: %s' % (stack[-1])
          del stackx[stack[-1]]
          e = self.type[stack.pop()]['ethname']
          if x.has_key(e):
            continue
          #print 'Add: %s' % (e)
          self.eth_type_ord1.append(e)
          x[e] = True
    i = 0
    while i < len(self.eth_dep_cycle):
      t = self.type[self.eth_dep_cycle[i][0]]['ethname']
      self.dep_cycle_eth_type.setdefault(t, []).append(i)
      i += 1

    #--- value dependencies and export -------------------
    for v in self.eth_value_ord:
      if self.eth_value[v]['export']:
        self.eth_vexport_ord.append(v)
      else:
        self.eth_value_ord1.append(v)

  #--- eth_vals_nm ------------------------------------------------------------
  def eth_vals_nm(self, tname):
    out = ""
    if (not self.eth_type[tname]['export'] & 0x10):
      out += "%s_" % (self.eproto)
    out += "%s_vals" % (tname)
    return out

  #--- eth_vals ---------------------------------------------------------------
  def eth_vals(self, tname, vals):
    out = ""
    if (not self.eth_type[tname]['export'] & 0x02):
      out += "static "
    out += "const value_string %s[] = {\n" % (self.eth_vals_nm(tname))
    for (val, id) in vals:
      out += '  { %3s, "%s" },\n' % (val, id)
    out += "  { 0, NULL }\n};\n"
    return out

  #--- eth_bits ---------------------------------------------------------------
  def eth_bits(self, tname, bits):
    out = ""
    out += "static const "
    out += "asn_namedbit %(TABLE)s[] = {\n"
    for (val, id) in bits:
      out += '  { %2d, &hf_%s_%s_%s, -1, -1, "%s", NULL },\n' % (val, self.eproto, tname, asn2c(id), id)
    out += "  { 0, NULL, 0, 0, NULL, NULL }\n};\n"
    return out

  #--- eth_type_fn_h ----------------------------------------------------------
  def eth_type_fn_h(self, tname):
    out = ""
    if (not self.eth_type[tname]['export'] & 0x01):
      out += "static "
    out += "int "
    if (self.Ber()):
      out += "dissect_%s_%s(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index)" % (self.eth_type[tname]['proto'], tname)
    elif (self.Per()):
      out += "dissect_%s_%s(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index)" % (self.eth_type[tname]['proto'], tname)
    out += ";\n"
    return out

  #--- eth_fn_call ------------------------------------------------------------
  def eth_fn_call(self, fname, ret=None, indent=2, par=None):
    out = indent * ' '
    if (ret):
      if (ret == 'return'):
        out += 'return '
      else:
        out += ret + ' = '
    out += fname + '('
    ind = len(out)
    for i in range(len(par)):
      if (i>0): out += ind * ' '
      out += ', '.join(par[i])
      if (i<(len(par)-1)): out += ',\n'
    out += ');\n'
    return out

  #--- eth_type_fn_hdr --------------------------------------------------------
  def eth_type_fn_hdr(self, tname):
    out = '\n'
    if (not self.eth_type[tname]['export'] & 0x01):
      out += "static "
    out += "int\n"
    if (self.Ber()):
      out += "dissect_%s_%s(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {\n" % (self.eth_type[tname]['proto'], tname)
    elif (self.Per()):
      out += "dissect_%s_%s(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {\n" % (self.eth_type[tname]['proto'], tname)
    if self.conform.get_fn_presence(tname):
      out += self.conform.get_fn_text(tname, 'FN_HDR')
    elif self.conform.get_fn_presence(self.eth_type[tname]['ref'][0]):
      out += self.conform.get_fn_text(self.eth_type[tname]['ref'][0], 'FN_HDR')
    return out

  #--- eth_type_fn_ftr --------------------------------------------------------
  def eth_type_fn_ftr(self, tname):
    out = '\n'
    if self.conform.get_fn_presence(tname):
      out += self.conform.get_fn_text(tname, 'FN_FTR')
    elif self.conform.get_fn_presence(self.eth_type[tname]['ref'][0]):
      out += self.conform.get_fn_text(self.eth_type[tname]['ref'][0], 'FN_FTR')
    out += "  return offset;\n"
    out += "}\n"
    return out

  #--- eth_type_fn_body -------------------------------------------------------
  def eth_type_fn_body(self, tname, body, pars=None):
    out = body
    if self.conform.get_fn_body_presence(tname):
      out = self.conform.get_fn_text(tname, 'FN_BODY')
    elif self.conform.get_fn_body_presence(self.eth_type[tname]['ref'][0]):
      out = self.conform.get_fn_text(self.eth_type[tname]['ref'][0], 'FN_BODY')
    if pars:
      try:
        out = out % pars
      except (TypeError):
        pass
    return out

  #--- eth_output_hf ----------------------------------------------------------
  def eth_output_hf (self):
    if not len(self.eth_hf_ord) and not len(self.eth_hfpdu_ord) and not len(self.named_bit): return
    fx = self.output.file_open('hf')
    for f in (self.eth_hfpdu_ord + self.eth_hf_ord):
      fx.write("%-50s/* %s */\n" % ("static int %s = -1;  " % (self.eth_hf[f]['fullname']), self.eth_hf[f]['ethtype']))
    if (self.named_bit):
      fx.write('/* named bits */\n')
    for nb in self.named_bit:
      fx.write("static int %s = -1;\n" % (nb['ethname']))
    self.output.file_close(fx)
    
  #--- eth_output_hf_arr ------------------------------------------------------
  def eth_output_hf_arr (self):
    if not len(self.eth_hf_ord) and not len(self.eth_hfpdu_ord) and not len(self.named_bit): return
    fx = self.output.file_open('hfarr')
    for f in (self.eth_hfpdu_ord + self.eth_hf_ord):
      if len(self.eth_hf[f]['ref']) == 1:
        blurb = '"' + self.eth_hf[f]['ref'][0] + '"'
      else:
        blurb = '""'
      attr = self.eth_hf[f]['attr'].copy()
      attr['ABBREV'] = '"%s.%s"' % (self.proto, attr['ABBREV'])
      if not attr.has_key('BLURB'):
        attr['BLURB'] = blurb
      fx.write('    { &%s,\n' % (self.eth_hf[f]['fullname']))
      fx.write('      { %(NAME)s, %(ABBREV)s,\n' % attr)
      fx.write('        %(TYPE)s, %(DISPLAY)s, %(STRINGS)s, %(BITMASK)s,\n' % attr)
      fx.write('        %(BLURB)s, HFILL }},\n' % attr)
    for nb in self.named_bit:
      blurb = ''
      fx.write('    { &%s,\n' % (nb['ethname']))
      fx.write('      { "%s", "%s.%s",\n' % (nb['name'], self.proto, nb['name']))
      fx.write('        %s, %s, %s, %s,\n' % (nb['ftype'], nb['display'], nb['strings'], nb['bitmask']))
      fx.write('        "%s", HFILL }},\n' % (blurb))
    self.output.file_close(fx)

  #--- eth_output_ett ---------------------------------------------------------
  def eth_output_ett (self):
    fx = self.output.file_open('ett')
    fempty = True
    #fx.write("static gint ett_%s = -1;\n" % (self.eproto))
    for t in self.eth_type_ord:
      if self.eth_type[t]['tree']:
        fx.write("static gint %s = -1;\n" % (self.eth_type[t]['tree']))
        fempty = False
    self.output.file_close(fx, discard=fempty)

  #--- eth_output_ett_arr -----------------------------------------------------
  def eth_output_ett_arr(self):
    fx = self.output.file_open('ettarr')
    fempty = True
    #fx.write("    &ett_%s,\n" % (self.eproto))
    for t in self.eth_type_ord:
      if self.eth_type[t]['tree']:
        fx.write("    &%s,\n" % (self.eth_type[t]['tree']))
        fempty = False
    self.output.file_close(fx, discard=fempty)

  #--- eth_output_export ------------------------------------------------------
  def eth_output_export(self):
    if (not len(self.eth_export_ord)): return
    fx = self.output.file_open('exp', ext='h')
    for t in self.eth_export_ord:  # vals
      if (self.eth_type[t]['export'] & 0x02) and self.eth_type[t]['val'].eth_has_vals():
        if self.eth_type[t]['export'] & 0x08:
          fx.write("ETH_VAR_IMPORT ")
        else:
          fx.write("extern ")
        fx.write("const value_string %s[];\n" % (self.eth_vals_nm(t)))
    for t in self.eth_export_ord:  # functions
      if (self.eth_type[t]['export'] & 0x01):
        fx.write(self.eth_type_fn_h(t))
    self.output.file_close(fx)

  #--- eth_output_expcnf ------------------------------------------------------
  def eth_output_expcnf(self):
    fx = self.output.file_open('exp', ext='cnf')
    fx.write('#.MODULE\n')
    maxw = 0
    for (m, p) in self.modules:
      if (len(m) > maxw): maxw = len(m)
    for (m, p) in self.modules:
      fx.write("%-*s  %s\n" % (maxw, m, p))
    fx.write('#.END\n\n')
    if self.Ber():
      fx.write('#.IMPORT_TAG\n')
      for t in self.eth_export_ord:  # tags
        if (self.eth_type[t]['export'] & 0x01):
          fx.write('%-24s ' % self.eth_type[t]['ref'][0])
          fx.write('%s %s\n' % self.eth_type[t]['val'].GetTag(self))
      fx.write('#.END\n\n')
    fx.write('#.TYPE_ATTR\n')
    for t in self.eth_export_ord:  # attributes
      if (self.eth_type[t]['export'] & 0x01):
        fx.write('%-24s ' % self.eth_type[t]['ref'][0])
        attr = self.eth_get_type_attr(self.eth_type[t]['ref'][0]).copy()
        fx.write('TYPE = %(TYPE)-9s  DISPLAY = %(DISPLAY)-9s  STRINGS = %(STRINGS)s  BITMASK = %(BITMASK)s\n' % attr)
    fx.write('#.END\n\n')
    self.output.file_close(fx, keep_anyway=True)

  #--- eth_output_val ------------------------------------------------------
  def eth_output_val(self):
    if (not len(self.eth_value_ord1)): return
    fx = self.output.file_open('val', ext='h')
    for v in self.eth_value_ord1:
      fx.write("#define %-30s %s\n" % (v, self.eth_value[v]['value']))
    self.output.file_close(fx)

  #--- eth_output_valexp ------------------------------------------------------
  def eth_output_valexp(self):
    if (not len(self.eth_vexport_ord)): return
    fx = self.output.file_open('valexp', ext='h')
    for v in self.eth_vexport_ord:
      fx.write("#define %-30s %s\n" % (v, self.eth_value[v]['value']))
    self.output.file_close(fx)

  #--- eth_output_types -------------------------------------------------------
  def eth_output_types(self):
    def out_field(f):
      t = self.eth_hf[f]['ethtype']
      if (self.Ber()):
        x = {}
        for r in self.eth_hf[f]['ref']:
          x[self.field[r]['impl']] = self.field[r]['impl']
      else:
        x = {False : False}
      x = x.values()
      x.sort()
      out = ''
      for i in x:
        if (i):
          postfix = '_impl'
          impl = 'TRUE'
        else:
          postfix = ''
          impl = 'FALSE'
        if (self.Ber()):
          if (i): postfix = '_impl'; impl = 'TRUE'
          else:   postfix = '';      impl = 'FALSE'
          out += 'static int dissect_'+f+postfix+'(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {\n'
          par=((impl, 'tvb', 'offset', 'pinfo', 'tree', self.eth_hf[f]['fullname']),)
        else:
          out += 'static int dissect_'+f+'(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {\n'
          par=(('tvb', 'offset', 'pinfo', 'tree', self.eth_hf[f]['fullname']),)
        out += self.eth_fn_call('dissect_%s_%s' % (self.eth_type[t]['proto'], t), ret='return',
                                par=par)
        out += '}\n'
      return out
    #end out_field()
    def out_pdu(f):
      t = self.eth_hf[f]['ethtype']
      is_new = self.eth_hf[f]['pdu']['new']
      if self.field[self.eth_hf[f]['ref'][0]]['impl']:
        impl = 'TRUE'
      else:
        impl = 'FALSE'
      out = 'static '
      if (is_new):
        out += 'int'
      else:
        out += 'void'
      out += ' dissect_'+f+'(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {\n'
      if (self.Per()):
        if (self.Aligned()):
          aligned = 'TRUE'
        else:
          aligned = 'FALSE'
        out += self.eth_fn_call('per_aligment_type_callback', par=((aligned,),))
      if (self.Ber()):
        par=((impl, 'tvb', '0', 'pinfo', 'tree', self.eth_hf[f]['fullname']),)
      elif (self.Per()):
        par=(('tvb', '0', 'pinfo', 'tree', self.eth_hf[f]['fullname']),)
      else:
        par=((),)
      ret = None
      if (is_new): ret = 'return'
      out += self.eth_fn_call('dissect_%s_%s' % (self.eth_type[t]['proto'], t), ret=ret, par=par)
      out += '}\n'
      return out
    #end out_pdu()
    fx = self.output.file_open('fn')
    pos = fx.tell()
    if self.eth_dep_cycle:
      fx.write('/*--- Cyclic dependencies ---*/\n\n')
      i = 0
      while i < len(self.eth_dep_cycle):
        t = self.type[self.eth_dep_cycle[i][0]]['ethname']
        if self.dep_cycle_eth_type[t][0] != i: i += 1; continue
        fx.write(''.join(map(lambda i: '/* %s */\n' % ' -> '.join(self.eth_dep_cycle[i]), self.dep_cycle_eth_type[t])))
        fx.write(self.eth_type_fn_h(t))
        if (not self.NAPI()):
          fx.write('\n')
          for f in self.eth_hf_ord:
            if (self.eth_hf[f]['ethtype'] == t):
              fx.write(out_field(f))
        fx.write('\n')
        i += 1
      fx.write('\n')
    if (not self.NAPI()):  # fields for imported types
      fx.write('/*--- Fields for imported types ---*/\n\n')
      for f in self.eth_hf_ord:
        if (self.eth_type[self.eth_hf[f]['ethtype']]['import']):
          fx.write(out_field(f))
      fx.write('\n')
    for t in self.eth_type_ord1:
      if self.eth_type[t]['import']:
        continue
      if self.eth_type[t]['val'].eth_has_vals():
        if self.eth_type[t]['no_emit'] & 0x02:
          pass
        elif self.eth_type[t]['user_def'] & 0x02:
          fx.write("extern const value_string %s[];\n" % (self.eth_vals_nm(t)))
        else:
          fx.write(self.eth_type[t]['val'].eth_type_vals(t, self))
      if self.eth_type[t]['no_emit'] & 0x01:
        pass
      elif self.eth_type[t]['user_def'] & 0x01:
        fx.write(self.eth_type_fn_h(t))
      else:
        fx.write(self.eth_type[t]['val'].eth_type_fn(self.eth_type[t]['proto'], t, self))
      if (not self.NAPI() and not self.dep_cycle_eth_type.has_key(t)):
        for f in self.eth_hf_ord:
          if (self.eth_hf[f]['ethtype'] == t):
            fx.write(out_field(f))
      fx.write('\n')
    if (len(self.eth_hfpdu_ord)):
      fx.write('/*--- PDUs ---*/\n\n')
      for f in self.eth_hfpdu_ord:
        if (self.eth_hf[f]['pdu']):
          fx.write(out_pdu(f))
      fx.write('\n')
    fempty = pos == fx.tell()
    self.output.file_close(fx, discard=fempty)

  #--- eth_output_dis_hnd -----------------------------------------------------
  def eth_output_dis_hnd(self):
    fx = self.output.file_open('dis-hnd')
    fempty = True
    for f in self.eth_hfpdu_ord:
      pdu = self.eth_hf[f]['pdu']
      if (pdu and pdu['reg'] and not pdu['hidden']):
        dis = self.proto
        if (pdu['reg'] != '.'):
          dis += '.' + pdu['reg']
        fx.write('static dissector_handle_t %s_handle;\n' % (asn2c(dis)))
        fempty = False
    fx.write('\n')
    self.output.file_close(fx, discard=fempty)

  #--- eth_output_dis_reg -----------------------------------------------------
  def eth_output_dis_reg(self):
    fx = self.output.file_open('dis-reg')
    fempty = True
    for f in self.eth_hfpdu_ord:
      pdu = self.eth_hf[f]['pdu']
      if (pdu and pdu['reg']):
        new_prefix = ''
        if (pdu['new']): new_prefix = 'new_'
        dis = self.proto
        if (pdu['reg'] != '.'): dis += '.' + pdu['reg']
        fx.write('  %sregister_dissector("%s", dissect_%s, proto_%s);\n' % (new_prefix, dis, f, self.eproto))
        if (not pdu['hidden']):
          fx.write('  %s_handle = find_dissector("%s");\n' % (asn2c(dis), dis))
        fempty = False
    fx.write('\n')
    self.output.file_close(fx, discard=fempty)

  #--- eth_output_dis_tab -----------------------------------------------------
  def eth_output_dis_tab(self):
    fx = self.output.file_open('dis-tab')
    fempty = True
    for k in self.conform.get_order('REGISTER'):
      reg = self.conform.use_item('REGISTER', k)
      if not self.field.has_key(reg['pdu']): continue
      f = self.field[reg['pdu']]['ethname']
      pdu = self.eth_hf[f]['pdu'] 
      new_prefix = ''
      if (pdu['new']): new_prefix = 'new_'
      if (reg['rtype'] in ('NUM', 'STR')):
        rstr = ''
        if (reg['rtype'] == 'STR'): rstr = '_string'
        if (pdu['reg']):
          dis = self.proto
          if (pdu['reg'] != '.'): dis += '.' + pdu['reg']
          if  (not pdu['hidden']):
            hnd = '%s_handle' % (asn2c(dis))
          else:
            hnd = 'find_dissector("%s")' % (dis)
        else:
          hnd = '%screate_dissector_handle(dissect_%s, proto_%s)' % (new_prefix, f, self.eproto)
        fx.write('  dissector_add%s("%s", %s, %s);\n' % (rstr, reg['rtable'], reg['rport'], hnd))
      elif (reg['rtype'] in ('BER', 'PER')):
        fx.write('  %sregister_%s_oid_dissector(%s, dissect_%s, proto_%s, %s);\n' % (new_prefix, reg['rtype'].lower(), reg['roid'], f, self.eproto, reg['roidname']))
      fempty = False
    fx.write('\n')
    self.output.file_close(fx, discard=fempty)

  #--- dupl_report -----------------------------------------------------
  def dupl_report(self):
    # types
    tmplist = self.eth_type_dupl.keys()
    tmplist.sort()
    for t in tmplist:
      msg = "The same type names for different types. Explicit type renaming is recommended.\n"
      msg += t + "\n"
      x = ''
      for tt in self.eth_type_dupl[t]:
        msg += " %-20s %s\n" % (t+str(x), tt)
        if not x: x = 1
        else: x += 1
      warnings.warn_explicit(msg, UserWarning, '', '')
    # fields
    tmplist = self.eth_hf_dupl.keys()
    tmplist.sort()
    for f in tmplist:
      msg = "The same field names for different types. Explicit field renaming is recommended.\n"
      msg += f + "\n"
      for tt in self.eth_hf_dupl[f].keys():
        msg += " %-20s %-20s " % (self.eth_hf_dupl[f][tt], tt)
        msg += ", ".join(self.eth_hf[self.eth_hf_dupl[f][tt]]['ref'])
        msg += "\n"
      warnings.warn_explicit(msg, UserWarning, '', '')

  #--- eth_do_output ------------------------------------------------------------
  def eth_do_output(self):
    if self.dbg('a'):
      print "\n# Assignments"
      print "\n".join(self.assign_ord)
      print "\n# Value assignments"
      print "\n".join(self.vassign_ord)
    if self.dbg('t'):
      print "\n# Imported Types"
      print "%-40s %-24s %-24s" % ("ASN.1 name", "Module", "Protocol")
      print "-" * 100
      for t in self.type_imp:
        print "%-40s %-24s %-24s" % (t, self.type[t]['import'], self.type[t]['proto'])
      print "\n# Imported Values"
      print "%-40s %-24s %-24s" % ("ASN.1 name", "Module", "Protocol")
      print "-" * 100
      for t in self.value_imp:
        print "%-40s %-24s %-24s" % (t, self.value[t]['import'], self.value[t]['proto'])
      print "\n# Exported Types"
      print "%-31s %s" % ("Ethereal type", "Export Flag")
      print "-" * 100
      for t in self.eth_export_ord:
        print "%-31s 0x%02X" % (t, self.eth_type[t]['export'])
      print "\n# Exported Values"
      print "%-40s %s" % ("Ethereal name", "Value")
      print "-" * 100
      for v in self.eth_vexport_ord:
        print "%-40s %s" % (v, self.eth_value[v]['value'])
      print "\n# ASN.1 Types"
      print "%-49s %-24s %-24s" % ("ASN.1 unique name", "'tname'", "Ethereal type")
      print "-" * 100
      for t in self.type_ord:
        print "%-49s %-24s %-24s" % (t, self.type[t]['tname'], self.type[t]['ethname'])
      print "\n# Ethereal Types"
      print "Ethereal type                   References (ASN.1 types)"
      print "-" * 100
      for t in self.eth_type_ord:
        print "%-31s %d" % (t, len(self.eth_type[t]['ref'])),
        print ', '.join(self.eth_type[t]['ref'])
      print "\n# ASN.1 Values"
      print "%-40s %-18s %s" % ("ASN.1 unique name", "Type", "Value")
      print "-" * 100
      for v in self.value_ord:
        if isinstance (self.value[v]['value'], Value):
          print "%-40s %-18s %s" % (v, self.value[v]['type'].eth_tname(), self.value[v]['value'].to_str())
        else:
          print "%-40s %-18s %s" % (v, self.value[v]['type'].eth_tname(), self.value[v]['value'])
      print "\n# Ethereal Values"
      print "%-40s %s" % ("Ethereal name", "Value")
      print "-" * 100
      for v in self.eth_value_ord:
        print "%-40s %s" % (v, self.eth_value[v]['value'])
      print "\n# ASN.1 Fields"
      print "ASN.1 unique name                        Ethereal name        ASN.1 type"
      print "-" * 100
      for f in (self.pdu_ord + self.field_ord):
        print "%-40s %-20s %s" % (f, self.field[f]['ethname'], self.field[f]['type'])
      print "\n# Ethereal Fields"
      print "Ethereal name                  Ethereal type        References (ASN.1 fields)"
      print "-" * 100
      for f in (self.eth_hfpdu_ord + self.eth_hf_ord):
        print "%-30s %-20s %s" % (f, self.eth_hf[f]['ethtype'], len(self.eth_hf[f]['ref'])),
        print ', '.join(self.eth_hf[f]['ref'])
      #print "\n# Order after dependencies"
      #print '\n'.join(self.eth_type_ord1)
      print "\n# Cyclic dependencies"
      for c in self.eth_dep_cycle:
        print ' -> '.join(c)
    self.dupl_report()
    self.output.outnm = self.outnm_opt
    if (not self.output.outnm):
      self.output.outnm = self.proto
    self.eth_output_hf()
    self.eth_output_ett()
    self.eth_output_types()
    self.eth_output_hf_arr()
    self.eth_output_ett_arr()
    self.eth_output_export()
    if self.expcnf:
      self.eth_output_expcnf()
    self.eth_output_val()
    self.eth_output_valexp()
    self.eth_output_dis_hnd()
    self.eth_output_dis_reg()
    self.eth_output_dis_tab()

#--- EthCnf -------------------------------------------------------------------
class EthCnf:
  def __init__(self):
    self.tblcfg = {}
    self.table = {}
    self.order = {}
    self.fn = {}
    #                                   Value name             Default value       Duplicity check   Usage check
    self.tblcfg['EXPORTS']         = { 'val_nm' : 'flag',     'val_dflt' : 0,     'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['PDU']             = { 'val_nm' : 'attr',     'val_dflt' : None,  'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['REGISTER']        = { 'val_nm' : 'attr',     'val_dflt' : None,  'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['USER_DEFINED']    = { 'val_nm' : 'flag',     'val_dflt' : 0,     'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['NO_EMIT']         = { 'val_nm' : 'flag',     'val_dflt' : 0,     'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['MODULE']          = { 'val_nm' : 'proto',    'val_dflt' : None,  'chk_dup' : True, 'chk_use' : False }
    self.tblcfg['OMIT_ASSIGNMENT'] = { 'val_nm' : 'omit',     'val_dflt' : False, 'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['TYPE_RENAME']     = { 'val_nm' : 'eth_name', 'val_dflt' : None,  'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['FIELD_RENAME']    = { 'val_nm' : 'eth_name', 'val_dflt' : None,  'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['IMPORT_TAG']      = { 'val_nm' : 'ttag',     'val_dflt' : (),    'chk_dup' : True, 'chk_use' : False }
    self.tblcfg['FN_PARS']         = { 'val_nm' : 'pars',     'val_dflt' : {},    'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['TYPE_ATTR']       = { 'val_nm' : 'attr',     'val_dflt' : {},    'chk_dup' : True, 'chk_use' : False }
    self.tblcfg['ETYPE_ATTR']      = { 'val_nm' : 'attr',     'val_dflt' : {},    'chk_dup' : True, 'chk_use' : False }
    self.tblcfg['FIELD_ATTR']      = { 'val_nm' : 'attr',     'val_dflt' : {},    'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['EFIELD_ATTR']     = { 'val_nm' : 'attr',     'val_dflt' : {},    'chk_dup' : True, 'chk_use' : True }


    for k in self.tblcfg.keys() :
      self.table[k] = {}
      self.order[k] = []

  def add_item(self, table, key, fn, lineno, **kw):
    if self.tblcfg[table]['chk_dup'] and self.table[table].has_key(key):
      warnings.warn_explicit("Duplicated %s for %s. Previous one is at %s:%d" % 
                             (table, key, self.table[table][key]['fn'], self.table[table][key]['lineno']), 
                             UserWarning, fn, lineno)
      return
    self.table[table][key] = {'fn' : fn, 'lineno' : lineno, 'used' : False}
    self.table[table][key].update(kw)
    self.order[table].append(key)

  def get_order(self, table):
    return self.order[table]

  def check_item(self, table, key):
    return self.table[table].has_key(key)

  def check_item_value(self, table, key, **kw):
    return self.table[table].has_key(key) and self.table[table][key].has_key(kw.get('val_nm', self.tblcfg[table]['val_nm']))

  def use_item(self, table, key, **kw):
    vdflt = kw.get('val_dflt', self.tblcfg[table]['val_dflt'])
    if not self.table[table].has_key(key): return vdflt
    vname = kw.get('val_nm', self.tblcfg[table]['val_nm'])
    #print "use_item() - set used for %s %s" % (table, key)
    self.table[table][key]['used'] = True
    return self.table[table][key].get(vname, vdflt)

  def add_fn_line(self, name, ctx, line, fn, lineno):
    if not self.fn.has_key(name):
      self.fn[name] = {'FN_HDR' : None, 'FN_FTR' : None, 'FN_BODY' : None}
    if (self.fn[name][ctx]):
      self.fn[name][ctx]['text'] += line
    else:
      self.fn[name][ctx] = {'text' : line, 'used' : False,
                             'fn' : fn, 'lineno' : lineno}
  def get_fn_presence(self, name):
    #print "get_fn_presence('%s'):%s" % (name, str(self.fn.has_key(name)))
    #if self.fn.has_key(name): print self.fn[name]
    return self.fn.has_key(name)
  def get_fn_body_presence(self, name):
    return self.fn.has_key(name) and self.fn[name]['FN_BODY']
  def get_fn_text(self, name, ctx):
    if (not self.fn.has_key(name)):
      return '';
    if (not self.fn[name][ctx]):
      return '';
    return '#line %u "%s"\n%s\n' % (self.fn[name][ctx]['lineno'],self.fn[name][ctx]['fn'],self.fn[name][ctx]['text']);

  def add_pdu(self, par, is_new, fn, lineno):
    #print "add_pdu(par=%s, %s, %d)" % (str(par), fn, lineno)
    (reg, hidden) = (None, False)
    if (len(par) > 1): reg = par[1]
    if (reg and reg[0]=='@'): (reg, hidden) = (reg[1:], True)
    attr = {'new' : is_new, 'reg' : reg, 'hidden' : hidden}
    self.add_item('PDU', par[0], attr=attr, fn=fn, lineno=lineno)
    return

  def add_register(self, pdu, par, fn, lineno):
    #print "add_register(pdu=%s, par=%s, %s, %d)" % (pdu, str(par), fn, lineno)
    if (par[0] in ('N', 'NUM')):   rtype = 'NUM'; (pmin, pmax) = (2, 2)
    elif (par[0] in ('S', 'STR')): rtype = 'STR'; (pmin, pmax) = (2, 2)
    elif (par[0] in ('B', 'BER')): rtype = 'BER'; (pmin, pmax) = (1, 2)
    elif (par[0] in ('P', 'PER')): rtype = 'PER'; (pmin, pmax) = (1, 2)
    else: warnings.warn_explicit("Unknown registration type '%s'" % (par[2]), UserWarning, fn, lineno); return
    if ((len(par)-1) < pmin):
      warnings.warn_explicit("Too few parameters for %s registration type. At least %d parameters are required" % (rtype, pmin), UserWarning, fn, lineno)
      return
    if ((len(par)-1) > pmax):
      warnings.warn_explicit("Too many parameters for %s registration type. Only %d parameters are allowed" % (rtype, pmax), UserWarning, fn, lineno)
    attr = {'pdu' : pdu, 'rtype' : rtype}
    if (rtype in ('NUM', 'STR')): 
      attr['rtable'] = par[1]
      attr['rport'] = par[2]
      rkey = '/'.join([rtype, attr['rtable'], attr['rport']])
    elif (rtype in ('BER', 'PER')): 
      attr['roid'] = par[1]
      attr['roidname'] = '""'
      if (len(par)>=3): attr['roidname'] = par[2]
      rkey = '/'.join([rtype, attr['roid']])
    self.add_item('REGISTER', rkey, attr=attr, fn=fn, lineno=lineno)

  def read(self, fn):
    def get_par(line, pmin, pmax, fn, lineno):
      par = line.split(None, pmax)
      for i in range(len(par)):
        if par[i] == '-':
          par[i] = None
          continue
        if par[i][0] == '#':
          par[i:] = []
          break
      if len(par) < pmin:
        warnings.warn_explicit("Too few parameters. At least %d parameters are required" % (pmin), UserWarning, fn, lineno)
        return None
      if len(par) > pmax:
        warnings.warn_explicit("Too many parameters. Only %d parameters are allowed" % (pmax), UserWarning, fn, lineno)
        return par[0:pmax]
      return par

    def get_par_nm(line, pmin, pmax, fn, lineno):
      if pmax:
        par = line.split(None, pmax)
      else:
        par = [line,]
      for i in range(len(par)):
        if par[i][0] == '#':
          par[i:] = []
          break
      if len(par) < pmin:
        warnings.warn_explicit("Too few parameters. At least %d parameters are required" % (pmin), UserWarning, fn, lineno)
        return None
      if len(par) > pmax:
        nmpar = par[pmax]
      else:
        nmpar = ''
      nmpars = {}
      nmpar_first = re.compile(r'^\s*(?P<attr>[_A-Z][_A-Z0-9]*)\s*=\s*')
      nmpar_next = re.compile(r'\s+(?P<attr>[_A-Z][_A-Z0-9]*)\s*=\s*')
      nmpar_end = re.compile(r'\s*$')
      result = nmpar_first.search(nmpar)
      pos = 0
      while result:
        k = result.group('attr')
        pos = result.end()
        result = nmpar_next.search(nmpar, pos)
        p1 = pos
        if result:
          p2 = result.start()
        else:
          p2 = nmpar_end.search(nmpar, pos).start()
        v = nmpar[p1:p2]
        nmpars[k] = v
      if len(par) > pmax:
        par[pmax] = nmpars
      return par

    f = open(fn, "r")
    directive = re.compile(r'^\s*#\.(?P<name>[A-Z_]+)\s+')
    comment = re.compile(r'^\s*#[^.]')
    empty = re.compile(r'^\s*$')
    lineno = 0
    ctx = None
    name = ''
    stack = []
    while 1:
      line = f.readline()
      lineno += 1
      if not line:
        f.close()
        if stack:
          frec = stack.pop()
          fn, f, lineno = frec['fn'], frec['f'], frec['lineno']
          continue
        else: 
          break
      if comment.search(line): continue
      result = directive.search(line)
      if result:  # directive
        if result.group('name') in ('EXPORTS', 'PDU', 'PDU_NEW', 'REGISTER', 'REGISTER_NEW', 
                                    'USER_DEFINED', 'NO_EMIT', 'MODULE', 'MODULE_IMPORT', 'OMIT_ASSIGNMENT', 
                                    'TYPE_RENAME', 'FIELD_RENAME', 'IMPORT_TAG',
                                    'TYPE_ATTR', 'ETYPE_ATTR', 'FIELD_ATTR', 'EFIELD_ATTR'):
          ctx = result.group('name')
        elif result.group('name') in ('FN_HDR', 'FN_FTR'):
          par = get_par(line[result.end():], 1, 1, fn=fn, lineno=lineno)
          if not par: continue
          ctx = result.group('name')
          name = par[0]
        elif result.group('name') == 'FN_BODY':
          par = get_par_nm(line[result.end():], 1, 1, fn=fn, lineno=lineno)
          if not par: continue
          ctx = result.group('name')
          name = par[0]
          if len(par) > 1:
            self.add_item('FN_PARS', name, pars=par[1], fn=fn, lineno=lineno)
        elif result.group('name') == 'FN_PARS':
          par = get_par_nm(line[result.end():], 0, 1, fn=fn, lineno=lineno)
          ctx = result.group('name')
          if not par:
            name = None
          else:
            name = par[0]
          if len(par) > 1:
            self.add_item(ctx, name, pars=par[1], fn=fn, lineno=lineno)
            ctx = None
            name = None
        elif result.group('name') == 'INCLUDE':
          par = get_par(line[result.end():], 1, 1, fn=fn, lineno=lineno)
          if not par: 
            warnings.warn_explicit("INCLUDE requires parameter", UserWarning, fn, lineno)
            continue
          fname = os.path.join(os.path.split(fn)[0], par[0])
          if (not os.path.exists(fname)):
            fname = par[0]
          fnew = open(fname, "r")
          stack.append({'fn' : fn, 'f' : f, 'lineno' : lineno})
          fn, f, lineno = par[0], fnew, 0
        elif result.group('name') == 'END':
          ctx = None
        else:
          warnings.warn_explicit("Unknown directive '%s'" % (result.group('name')), UserWarning, fn, lineno)
        continue
      if not ctx:
        if not empty.match(line):
          warnings.warn_explicit("Non-empty line in empty context", UserWarning, fn, lineno)
      elif ctx in ('EXPORTS', 'USER_DEFINED', 'NO_EMIT'):
        if empty.match(line): continue
        if ctx == 'EXPORTS':
          par = get_par(line, 1, 4, fn=fn, lineno=lineno)
        else:
          par = get_par(line, 1, 2, fn=fn, lineno=lineno)
        if not par: continue
        flag = 0x03
        p = 2
        if (len(par)>=2):
          if (par[1] == 'WITH_VALS'):      flag = 0x03
          elif (par[1] == 'WITHOUT_VALS'): flag = 0x01
          elif (par[1] == 'ONLY_VALS'):    flag = 0x02
          elif (ctx == 'EXPORTS'): p = 1
          else: warnings.warn_explicit("Unknown parameter value '%s'" % (par[1]), UserWarning, fn, lineno)
        for i in range(p, len(par)):
          if (par[i] == 'ETH_VAR'):          flag |= 0x08
          elif (par[i] == 'NO_PROT_PREFIX'): flag |= 0x10
          else: warnings.warn_explicit("Unknown parameter value '%s'" % (par[i]), UserWarning, fn, lineno)
        self.add_item(ctx, par[0], flag=flag, fn=fn, lineno=lineno)
      elif ctx in ('PDU', 'PDU_NEW'):
        if empty.match(line): continue
        par = get_par(line, 1, 5, fn=fn, lineno=lineno)
        if not par: continue
        is_new = False
        if (ctx == 'PDU_NEW'): is_new = True
        self.add_pdu(par[0:2], is_new, fn, lineno)
        if (len(par)>=3):
          self.add_register(par[0], par[2:5], fn, lineno)
      elif ctx in ('REGISTER', 'REGISTER_NEW'):
        if empty.match(line): continue
        par = get_par(line, 3, 4, fn=fn, lineno=lineno)
        if not par: continue
        if not self.check_item('PDU', par[0]):
          is_new = False
          if (ctx == 'REGISTER_NEW'): is_new = True
          self.add_pdu(par[0:1], is_new, fn, lineno)
        self.add_register(par[0], par[1:4], fn, lineno)
      elif ctx in ('MODULE', 'MODULE_IMPORT'):
        if empty.match(line): continue
        par = get_par(line, 2, 2, fn=fn, lineno=lineno)
        if not par: continue
        self.add_item('MODULE', par[0], proto=par[1], fn=fn, lineno=lineno)
      elif ctx == 'IMPORT_TAG':
        if empty.match(line): continue
        par = get_par(line, 3, 3, fn=fn, lineno=lineno)
        if not par: continue
        self.add_item('IMPORT_TAG', par[0], ttag=(par[1], par[2]), fn=fn, lineno=lineno)
      elif ctx == 'OMIT_ASSIGNMENT':
        if empty.match(line): continue
        par = get_par(line, 1, 1, fn=fn, lineno=lineno)
        if not par: continue
        self.add_item('OMIT_ASSIGNMENT', par[0], omit=True, fn=fn, lineno=lineno)
      elif ctx == 'TYPE_RENAME':
        if empty.match(line): continue
        par = get_par(line, 2, 2, fn=fn, lineno=lineno)
        if not par: continue
        self.add_item('TYPE_RENAME', par[0], eth_name=par[1], fn=fn, lineno=lineno)
        if not par[1][0].isupper():
          warnings.warn_explicit("Type should be renamed to uppercase name (%s)" % (par[1]),
                                  UserWarning, fn, lineno)
      elif ctx == 'FIELD_RENAME':
        if empty.match(line): continue
        par = get_par(line, 2, 2, fn=fn, lineno=lineno)
        if not par: continue
        self.add_item('FIELD_RENAME', par[0], eth_name=par[1], fn=fn, lineno=lineno)
        if not par[1][0].islower():
          warnings.warn_explicit("Field should be renamed to lowercase name (%s)" % (par[1]),
                                  UserWarning, fn, lineno)
      elif ctx in ('TYPE_ATTR', 'ETYPE_ATTR', 'FIELD_ATTR', 'EFIELD_ATTR'):
        if empty.match(line): continue
        par = get_par_nm(line, 1, 1, fn=fn, lineno=lineno)
        if not par: continue
        self.add_item(ctx, par[0], attr=par[1], fn=fn, lineno=lineno)
      elif ctx == 'FN_PARS':
        if empty.match(line): continue
        if name:
          par = get_par_nm(line, 0, 0, fn=fn, lineno=lineno)
        else:
          par = get_par_nm(line, 1, 1, fn=fn, lineno=lineno)
        if not par: continue
        if name:
          self.add_item(ctx, name, pars=par[0], fn=fn, lineno=lineno)
        else:
          self.add_item(ctx, par[0], pars=par[1], fn=fn, lineno=lineno)
      elif ctx in ('FN_HDR', 'FN_FTR', 'FN_BODY'):
        self.add_fn_line(name, ctx, line, fn=fn, lineno=lineno)

  def dbg_print(self):
    print "\n# Conformance values"
    print "%-15s %-4s %-15s %-20s %s" % ("File", "Line", "Table", "Key", "Value")
    print "-" * 100
    tbls = self.table.keys()
    tbls.sort()
    for t in tbls:
      keys = self.table[t].keys()
      keys.sort()
      for k in keys:
        print "%-15s %4s %-15s %-20s %s" % (
              self.table[t][k]['fn'], self.table[t][k]['lineno'], t, k, str(self.table[t][k][self.tblcfg[t]['val_nm']]))

  def unused_report(self):
    tbls = self.table.keys()
    tbls.sort()
    for t in tbls:
      if not self.tblcfg[t]['chk_use']: continue
      keys = self.table[t].keys()
      keys.sort()
      for k in keys:
        if not self.table[t][k]['used']:
          warnings.warn_explicit("Unused %s for %s" % (t, k),
                                  UserWarning, self.table[t][k]['fn'], self.table[t][k]['lineno'])

#--- EthOut -------------------------------------------------------------------
class EthOut:
  def __init__(self):
    self.outnm = None
    self.outdir = '.'
    self.single_file = None
    self.created_files = []
    self.unique_created_files = []
    self.keep = False
  #--- output_fname -------------------------------------------------------
  def output_fname(self, ftype, ext='c'):
    fn = ''
    if not ext in ('cnf',):
      fn += 'packet-' 
    fn += self.outnm
    if (ftype):
      fn += '-' + ftype
    fn += '.' + ext
    return fn
  #--- output_fullname -------------------------------------------------------
  def output_fullname(self, ftype, ext='c'):
    return os.path.join(self.outdir, self.output_fname(ftype, ext=ext))
  #--- file_open -------------------------------------------------------
  def file_open(self, ftype, ext='c'):
    fn = self.output_fullname(ftype, ext=ext)
    fx = file(fn, 'w')
    if ext in ('cnf',):
      fx.write(self.fhdr(fn, comment = '#'))
    else:
      if (not self.single_file):
        fx.write(self.fhdr(fn))
    return fx
  #--- file_close -------------------------------------------------------
  def file_close(self, fx, discard=False, keep_anyway=False):
    fx.close()
    if (discard): 
      os.unlink(fx.name)
    elif (not keep_anyway):
      self.created_files.append(os.path.normcase(os.path.abspath(fx.name)))
  #--- fhdr -------------------------------------------------------
  def fhdr(self, fn, comment=None):
    def outln(ln):
      if comment:
        return '# %s\n' % (ln)
      else:
        return '/* %-74s */\n' % (ln)
    out = ''
    out += outln('Do not modify this file.')
    out += outln('It is created automatically by the ASN.1 to Ethereal dissector compiler')
    out += outln(fn)
    out += outln(' '.join(sys.argv))
    out += '\n'
    return out

  #--- dbg_print -------------------------------------------------------
  def dbg_print(self):
    print "\n# Output files"
    print "\n".join(self.created_files)
    print "\n"

  #--- make_single_file -------------------------------------------------------
  def make_single_file(self):
    if (not self.single_file): return
    in_nm = self.single_file + '.c'
    out_nm = self.output_fullname('')
    self.do_include(out_nm, in_nm)
    in_nm = self.single_file + '.h'
    if (os.path.exists(in_nm)):
      out_nm = self.output_fullname('', ext='h')
      self.do_include(out_nm, in_nm)
    if (not self.keep):
      self.unique_created_files = []
      [self.unique_created_files.append(wrd) for wrd in self.created_files if not self.unique_created_files.count(wrd)]
      for fn in self.unique_created_files:
        os.unlink(fn)

  #--- do_include -------------------------------------------------------
  def do_include(self, out_nm, in_nm):
    def check_file(fn, fnlist):
      fnfull = os.path.normcase(os.path.abspath(fn))
      if ((fnfull in fnlist) and os.path.exists(fnfull)):
        return os.path.normpath(fn)
      return None
    fin = file(in_nm, "r")
    fout = file(out_nm, "w")
    fout.write(self.fhdr(out_nm))
    fout.write('/* Input file: ' + in_nm +' */\n')
    fout.write('\n')
    fout.write('#line 1 "%s"\n' % (in_nm))

    include = re.compile(r'^\s*#\s*include\s+[<"](?P<fname>[^>"]+)[>"]', re.IGNORECASE)

    cont_linenum = 0;

    while (True):
      cont_linenum = cont_linenum + 1;
      line = fin.readline()
      if (line == ''): break
      ifile = None
      result = include.search(line)
      #if (result): print os.path.normcase(os.path.abspath(result.group('fname')))
      if (result):
        ifile = check_file(os.path.join(os.path.split(in_nm)[0], result.group('fname')), self.created_files)
        if (not ifile):
          ifile = check_file(os.path.join(self.outdir, result.group('fname')), self.created_files)
        if (not ifile):
          ifile = check_file(result.group('fname'), self.created_files)
      if (ifile):
        fout.write('\n')
        fout.write('/*--- Included file: ' + ifile + ' ---*/\n')
        fout.write('#line 1 "' + ifile + '"\n')
        finc = file(ifile, "r")
        fout.write(finc.read())
        fout.write('\n')
        fout.write('/*--- End of included file: ' + ifile + ' ---*/\n')
        fout.write('#line %i "%s"\n' % (cont_linenum+1,in_nm) )
        finc.close()
      else:
        fout.write(line)

    fout.close()
    fin.close()


#--- Node ---------------------------------------------------------------------
class Node:
    def __init__(self,*args, **kw):
        if len (args) == 0:
            self.type = self.__class__.__name__
        else:
            assert (len(args) == 1)
            self.type = args[0]
        self.__dict__.update (kw)
    def str_child (self, key, child, depth):
        indent = " " * (2 * depth)
        keystr = indent + key + ": "
        if key == 'type': # already processed in str_depth
            return ""
        if isinstance (child, Node): # ugh
            return keystr + "\n" + child.str_depth (depth+1)
        if type (child) == type ([]):
            l = []
            for x in child:
              if isinstance (x, Node):
                l.append (x.str_depth (depth+1))
              else:
                l.append (indent + "  " + str(x) + "\n")
            return keystr + "[\n" + ''.join(l) + indent + "]\n"
        else:
            return keystr + str (child) + "\n"
    def str_depth (self, depth): # ugh
        indent = " " * (2 * depth)
        l = ["%s%s" % (indent, self.type)]
        l.append ("".join (map (lambda (k,v): self.str_child (k, v, depth + 1),
                                self.__dict__.items ())))
        return "\n".join (l)
    def __str__(self):
        return "\n" + self.str_depth (0)
    def to_python (self, ctx):
        return self.str_depth (ctx.indent_lev)

    def eth_reg(self, ident, ectx):
        pass

#--- value_assign -------------------------------------------------------------
class value_assign (Node):
  def __init__(self,*args, **kw) :
    Node.__init__ (self,*args, **kw)

  def eth_reg(self, ident, ectx):
    if ectx.conform.use_item('OMIT_ASSIGNMENT', self.ident): return # Assignment to omit
    ectx.eth_reg_vassign(self)
    ectx.eth_reg_value(self.ident, self.typ, self.val)


#--- Type ---------------------------------------------------------------------
class Type (Node):
  def __init__(self,*args, **kw) :
    self.name = None
    self.constr = None
    Node.__init__ (self,*args, **kw)

  def IsNamed(self):
    if self.name is None :
      return False
    else:
      return True

  def HasConstraint(self):
    if self.constr is None :
      return False
    else :
      return True

  def HasOwnTag(self):
    return self.__dict__.has_key('tag')

  def HasImplicitTag(self, ectx):
    return (self.HasOwnTag() and
            ((self.tag.mode == 'IMPLICIT') or
             ((self.tag.mode == 'default') and (ectx.tag_def == 'IMPLICIT'))))

  def IndetermTag(self, ectx):
    return False

  def SetTag(self, tag):
    self.tag = tag

  def GetTag(self, ectx):
    #print "GetTag(%s)\n" % self.name;
    if (self.HasOwnTag()):
      return self.tag.GetTag(ectx)
    else:
      return self.GetTTag(ectx)

  def GetTTag(self, ectx):
    print "#Unhandled  GetTTag() in %s" % (self.type)
    print self.str_depth(1)
    return ('BER_CLASS_unknown', 'TAG_unknown')

  def SetName(self, name) :
    self.name = name

  def AddConstraint(self, constr):
    if not self.HasConstraint():
      self.constr = constr
    else:
      self.constr = Constraint(type = 'Intersection', subtype = [self.constr, constr])

  def eth_tname(self):
    return '#' + self.type + '_' + str(id(self))

  def eth_ftype(self, ectx):
    return ('FT_NONE', 'BASE_NONE')

  def eth_strings(self):
    return 'NULL'

  def eth_need_tree(self):
    return False

  def eth_has_vals(self):
    return False

  def eth_named_bits(self):
    return None

  def eth_reg_sub(self, ident, ectx):
    pass

  def eth_reg(self, ident, ectx, idx='', parent=None):
    nm = ''
    if ident and self.IsNamed ():
      nm = ident + '/' + self.name
    elif self.IsNamed():
      nm = self.name
    elif ident:
      nm = ident
    if not ident and ectx.conform.use_item('OMIT_ASSIGNMENT', nm): return # Assignment to omit
    if not ident:  # Assignment
      ectx.eth_reg_assign(nm, self)
      if self.type == 'Type_Ref':
        ectx.eth_reg_type(nm, self)
      if (ectx.conform.check_item('PDU', nm)):
        ectx.eth_reg_field(nm, nm, impl=self.HasImplicitTag(ectx), pdu=ectx.conform.use_item('PDU', nm))
    if self.type == 'Type_Ref':
      if ectx.conform.check_item('TYPE_RENAME', nm) or ectx.conform.get_fn_presence(nm):
        ectx.eth_reg_type(nm, self)  # new type
        trnm = nm
      else:
        trnm = self.val
    else:
      ectx.eth_reg_type(nm, self)
    if ident:
      if self.type == 'Type_Ref':
        ectx.eth_reg_field(nm, trnm, idx=idx, parent=parent, impl=self.HasImplicitTag(ectx))
      else:
        ectx.eth_reg_field(nm, nm, idx=idx, parent=parent, impl=self.HasImplicitTag(ectx))
    self.eth_reg_sub(nm, ectx)

  def eth_get_size_constr(self):
    (minv, maxv, ext) = ('NO_BOUND', 'NO_BOUND', 'FALSE')
    if not self.HasConstraint():
      (minv, maxv, ext) = ('NO_BOUND', 'NO_BOUND', 'FALSE')
    elif self.constr.IsSize():
      (minv, maxv, ext) = self.constr.GetSize()
    elif (self.constr.type == 'Intersection'):
      if self.constr.subtype[0].IsSize():
        (minv, maxv, ext) = self.constr.subtype[0].GetSize()
      elif self.constr.subtype[1].IsSize():
        (minv, maxv, ext) = self.constr.subtype[1].GetSize()
    return (minv, maxv, ext)

  def eth_get_value_constr(self):
    (minv, maxv, ext) = ('NO_BOUND', 'NO_BOUND', 'FALSE')
    if not self.HasConstraint():
      (minv, maxv, ext) = ('NO_BOUND', 'NO_BOUND', 'FALSE')
    elif self.constr.IsValue():
      (minv, maxv, ext) = self.constr.GetValue()
    return (minv, maxv, ext)

  def eth_type_vals(self, tname, ectx):
    if self.eth_has_vals():
      print "#Unhandled  eth_type_vals('%s') in %s" % (tname, self.type)
      print self.str_depth(1)
    return ''

  def eth_type_default_table(self, ectx, tname):
    return ''

  def eth_type_default_body(self, ectx):
    print "#Unhandled  eth_type_default_body() in %s" % (self.type)
    print self.str_depth(1)
    return ''

  def eth_type_default_pars(self, ectx, tname):
    pars = {
      'TNAME' : tname,
      'ER' : ectx.encp(),
      'FN_VARIANT' : '',
      'PINFO' : 'pinfo', 
      'TREE' : 'tree', 
      'TVB' : 'tvb', 
      'OFFSET' : 'offset', 
      'HF_INDEX' : 'hf_index',
      'VAL_PTR' : 'NULL',
      'IMPLICIT_TAG' : 'implicit_tag',
      'CREATED_ITEM_PTR' : 'NULL',
    }
    if ectx.eth_type[tname]['tree']:
      pars['ETT_INDEX'] = ectx.eth_type[tname]['tree']
    return pars

  def eth_type_fn(self, proto, tname, ectx):
    body = self.eth_type_default_body(ectx, tname)
    pars = self.eth_type_default_pars(ectx, tname)
    if ectx.conform.check_item('FN_PARS', tname):
      pars.update(ectx.conform.use_item('FN_PARS', tname))
    elif ectx.conform.check_item('FN_PARS', ectx.eth_type[tname]['ref'][0]):
      pars.update(ectx.conform.use_item('FN_PARS', ectx.eth_type[tname]['ref'][0]))
    pars['DEFAULT_BODY'] = body
    for i in range(4):
      for k in pars.keys(): pars[k] = pars[k] % pars
    out = '\n'
    out += self.eth_type_default_table(ectx, tname) % pars
    out += ectx.eth_type_fn_hdr(tname)
    out += ectx.eth_type_fn_body(tname, body, pars=pars)
    out += ectx.eth_type_fn_ftr(tname)
    return out

#--- Value --------------------------------------------------------------------
class Value (Node):
  def __init__(self,*args, **kw) :
    self.name = None
    Node.__init__ (self,*args, **kw)

  def SetName(self, name) :
    self.name = name

  def to_str(self):
    return str(self)

  def get_dep(self):
    return None

#--- Constraint ---------------------------------------------------------------
class Constraint (Node):
  def to_python (self, ctx):
    print "Ignoring constraint:", self.type
    return self.subtype.typ.to_python (ctx)
  def __str__ (self):
    return "Constraint: type=%s, subtype=%s" % (self.type, self.subtype)

  def IsSize(self):
    return self.type == 'Size' and (self.subtype.type == 'SingleValue' or self.subtype.type == 'ValueRange')

  def GetSize(self):
    minv = 'NO_BOUND'
    maxv = 'NO_BOUND'
    ext = 'FALSE'
    if self.IsSize():
      if self.subtype.type == 'SingleValue':
        minv = self.subtype.subtype
        maxv = self.subtype.subtype
      else:
        minv = self.subtype.subtype[0]
        maxv = self.subtype.subtype[1]
      if hasattr(self.subtype, 'ext') and self.subtype.ext:
        ext = 'TRUE'
      else:
        ext = 'FALSE'
    return (minv, maxv, ext)

  def IsValue(self):
    return self.type == 'SingleValue' or self.type == 'ValueRange'

  def GetValue(self):
    minv = 'NO_BOUND'
    maxv = 'NO_BOUND'
    ext = 'FALSE'
    if self.IsValue():
      if self.type == 'SingleValue':
        minv = self.subtype
        maxv = self.subtype
      else:
        if self.subtype[0] == 'MIN':
          minv = 'NO_BOUND'
        else:
          minv = self.subtype[0]
        if self.subtype[1] == 'MAX':
          maxv = 'NO_BOUND'
        else:
          maxv = self.subtype[1]
      if str(minv).isdigit(): minv += 'U'
      if str(maxv).isdigit(): maxv += 'U'
      if hasattr(self, 'ext') and self.ext:
        ext = 'TRUE'
      else:
        ext = 'FALSE'
    return (minv, maxv, ext)

  def IsNegativ(self):
    def is_neg(sval):
      return sval[0] == '-'
    if self.type == 'SingleValue':
      return is_neg(self.subtype)
    elif self.type == 'ValueRange':
      if self.subtype[0] == 'MIN': return True
      return is_neg(self.subtype[0])
    return FALSE

  def IsPermAlph(self):
    return self.type == 'From' and self.subtype.type == 'SingleValue'

  def eth_constrname(self):
    def int2str(val):
      try:
        if (int(val) < 0):
          return 'M' + str(-int(val))
        else:
          return str(val)
      except (ValueError, TypeError):
        return str(val)

    ext = ''
    if hasattr(self, 'ext') and self.ext:
      ext = '_'
    if self.type == 'SingleValue':
      return int2str(self.subtype) + ext
    elif self.type == 'ValueRange':
      return int2str(self.subtype[0]) + '_' + int2str(self.subtype[1]) + ext
    elif self.type == 'Size':
      return 'SIZE_' + self.subtype.eth_constrname() + ext
    else:
      return 'CONSTR' + str(id(self)) + ext


class Module (Node):
  def to_python (self, ctx):
    ctx.tag_def = self.tag_def.dfl_tag
    return """#%s
%s""" % (self.ident, self.body.to_python (ctx))

  def to_eth (self, ectx):
    ectx.tags_def = 'EXPLICIT' # default = explicit
    if (not ectx.proto):
      ectx.proto = ectx.conform.use_item('MODULE', self.ident.val, val_dflt=self.ident.val)
    ectx.tag_def = self.tag_def.dfl_tag
    ectx.modules.append((self.ident.val, ectx.proto))
    self.body.to_eth(ectx)

class Module_Body (Node):
    def to_python (self, ctx):
        # XXX handle exports, imports.
        l = map (lambda x: x.to_python (ctx), self.assign_list)
        l = [a for a in l if a <> '']
        return "\n".join (l)

    def to_eth(self, ectx):
        for i in self.imports:
          mod = i.module.val
          proto = ectx.conform.use_item('MODULE', mod, val_dflt=mod)
          for s in i.symbol_list:
            if isinstance(s, Type_Ref):
              ectx.eth_import_type(s.val, mod, proto)
            else:
              ectx.eth_import_value(s, mod, proto)
        for a in self.assign_list:
          a.eth_reg('', ectx)

class Default_Tags (Node):
    def to_python (self, ctx): # not to be used directly
        assert (0)

# XXX should just calculate dependencies as we go along.
def calc_dependencies (node, dict, trace = 0):
    if not hasattr (node, '__dict__'):
        if trace: print "#returning, node=", node
        return
    if isinstance (node, Type_Ref):
        dict [node.val] = 1
        if trace: print "#Setting", node.val
        return
    for (a, val) in node.__dict__.items ():
        if trace: print "# Testing node ", node, "attr", a, " val", val
        if a[0] == '_':
            continue
        elif isinstance (val, Node):
            calc_dependencies (val, dict, trace)
        elif isinstance (val, type ([])):
            for v in val:
                calc_dependencies (v, dict, trace)
    
                          
class Type_Assign (Node):
    def __init__ (self, *args, **kw):
        Node.__init__ (self, *args, **kw)
        if isinstance (self.val, Tag): # XXX replace with generalized get_typ_ignoring_tag (no-op for Node, override in Tag)
            to_test = self.val.typ
        else:
            to_test = self.val
        if isinstance (to_test, SequenceType):
            to_test.sequence_name = self.name.name
            
    def to_python (self, ctx):
        dep_dict = {}
        calc_dependencies (self.val, dep_dict, 0)
        depend_list = dep_dict.keys ()
        return ctx.register_assignment (self.name.name,
                                        self.val.to_python (ctx),
                                        depend_list)

class PyQuote (Node):
    def to_python (self, ctx):
        return ctx.register_pyquote (self.val)

#--- Type_Ref -----------------------------------------------------------------
class Type_Ref (Type):
  def to_python (self, ctx):
    return self.val

  def eth_reg_sub(self, ident, ectx):
    ectx.eth_dep_add(ident, self.val)

  def eth_tname(self):
    return asn2c(self.val)

  def GetTTag(self, ectx):
    #print "GetTTag(%s)\n" % self.val;
    if (ectx.type[self.val]['import']):
      if not ectx.type[self.val].has_key('ttag'):
        if not ectx.conform.check_item('IMPORT_TAG', self.val):
          msg = 'Missing tag information for imported type %s from %s (%s)' % (self.val, ectx.type[self.val]['import'], ectx.type[self.val]['proto'])
          warnings.warn_explicit(msg, UserWarning, '', '')
        ectx.type[self.val]['ttag'] = ectx.conform.use_item('IMPORT_TAG', self.val, val_dflt=('-1 /*imported*/', '-1 /*imported*/'))
      return ectx.type[self.val]['ttag']
    else:
      return ectx.type[self.val]['val'].GetTag(ectx)

  def IndetermTag(self, ectx):
    if (ectx.type[self.val]['import']):
      return False
    else:
      return ectx.type[self.val]['val'].IndetermTag(ectx)

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    t = ectx.type[self.val]['ethname']
    pars['TYPE_REF_PROTO'] = ectx.eth_type[t]['proto']
    pars['TYPE_REF_TNAME'] = t
    pars['TYPE_REF_FN'] = 'dissect_%(TYPE_REF_PROTO)s_%(TYPE_REF_TNAME)s'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('%(TYPE_REF_FN)s', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('%(TYPE_REF_FN)s', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- SqType -----------------------------------------------------------
class SqType (Type):
  def out_item(self, f, val, optional, ext, ectx):
    ef = ectx.field[f]['ethname']
    efd = ef
    if (ectx.Ber() and ectx.field[f]['impl']):
      efd += '_impl'
    if (ectx.Ber()):
      #print "optional=%s, e.val.HasOwnTag()=%s, e.val.IndetermTag()=%s" % (str(e.optional), str(e.val.HasOwnTag()), str(e.val.IndetermTag(ectx)))
      #print val.str_depth(1)
      opt = ''
      if (optional):
        opt = 'BER_FLAGS_OPTIONAL'
      if (not val.HasOwnTag()):
        if (opt): opt += '|'
        opt += 'BER_FLAGS_NOOWNTAG'
      elif (val.HasImplicitTag(ectx)):
        if (opt): opt += '|'
        opt += 'BER_FLAGS_IMPLTAG'
      if (val.IndetermTag(ectx)):
        if (opt): opt += '|'
        opt += 'BER_FLAGS_NOTCHKTAG'
      if (not opt): opt = '0'
    else:
      if optional:
        opt = 'ASN1_OPTIONAL'
      else:
        opt = 'ASN1_NOT_OPTIONAL'
    if (ectx.Ber()):
      (tc, tn) = val.GetTag(ectx)
      out = '  { %-13s, %s, %s, dissect_%s },\n' \
            % (tc, tn, opt, efd)
    elif (ectx.Per()):
      out = '  { %-30s, %-23s, %-17s, dissect_%s },\n' \
            % ('"'+(val.name or '')+'"', ext, opt, efd)
    else:
      out = ''
    return out   

#--- SeqType -----------------------------------------------------------
class SeqType (SqType):
  def eth_type_default_table(self, ectx, tname):
    #print "eth_type_default_table(tname='%s')" % (tname)
    fname = ectx.eth_type[tname]['ref'][0]
    table = "static const %(ER)s_sequence_t %(TABLE)s[] = {\n"
    if hasattr(self, 'ext_list'):
      ext = 'ASN1_EXTENSION_ROOT'
    else:
      ext = 'ASN1_NO_EXTENSIONS'
    for e in (self.elt_list):
      f = fname + '/' + e.val.name
      table += self.out_item(f, e.val, e.optional, ext, ectx)
    if hasattr(self, 'ext_list'):
      for e in (self.ext_list):
        f = fname + '/' + e.val.name
        table += self.out_item(f, e.val, e.optional, 'ASN1_NOT_EXTENSION_ROOT', ectx)
    if (ectx.Ber()):
      table += "  { 0, 0, 0, NULL }\n};\n"
    else:
      table += "  { NULL, 0, 0, NULL }\n};\n"
    return table

#--- SeqOfType -----------------------------------------------------------
class SeqOfType (SqType):
  def eth_type_default_table(self, ectx, tname):
    #print "eth_type_default_table(tname='%s')" % (tname)
    fname = ectx.eth_type[tname]['ref'][0]
    if self.val.IsNamed ():
      f = fname + '/' + self.val.name
    else:
      f = fname + '/' + '_item'
    table = "static const %(ER)s_sequence_t %(TABLE)s[1] = {\n"
    table += self.out_item(f, self.val, False, 'ASN1_NO_EXTENSIONS', ectx)
    table += "};\n"
    return table

#--- SequenceOfType -----------------------------------------------------------
class SequenceOfType (SeqOfType):
  def to_python (self, ctx):
    # name, tag (None for no tag, EXPLICIT() for explicit), typ)
    # or '' + (1,) for optional
    sizestr = ''
    if self.size_constr <> None:
        print "#Ignoring size constraint:", self.size_constr.subtype
    return "%sasn1.SEQUENCE_OF (%s%s)" % (ctx.spaces (),
                                          self.val.to_python (ctx),
                                          sizestr)

  def eth_reg_sub(self, ident, ectx):
    itmnm = ident
    if not self.val.IsNamed ():
      itmnm += '/' + '_item'
    self.val.eth_reg(itmnm, ectx, idx='[##]', parent=ident)

  def eth_tname(self):
    if self.val.type != 'Type_Ref':
      return '#' + self.type + '_' + str(id(self))
    if not self.HasConstraint():
      return "SEQUENCE_OF_" + self.val.eth_tname()
    elif self.constr.IsSize():
      return 'SEQUENCE_' + self.constr.eth_constrname() + '_OF_' + self.val.eth_tname()
    else:
      return '#' + self.type + '_' + str(id(self))

  def eth_ftype(self, ectx):
    return ('FT_UINT32', 'BASE_DEC')

  def eth_need_tree(self):
    return True

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_SEQUENCE')

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    (pars['MIN_VAL'], pars['MAX_VAL'], pars['EXT']) = self.eth_get_size_constr()
    pars['TABLE'] = '%(TNAME)s_sequence_of'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_sequence_of', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(PINFO)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                   ('%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s',),))
    elif (ectx.Per() and not self.HasConstraint()):
      body = ectx.eth_fn_call('dissect_%(ER)s_sequence_of', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ETT_INDEX)s', '%(TABLE)s',),))
    elif (ectx.Per() and self.constr.type == 'Size'):
      body = ectx.eth_fn_call('dissect_%(ER)s_constrained_sequence_of', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ETT_INDEX)s', '%(TABLE)s',),
                                   ('%(MIN_VAL)s', '%(MAX_VAL)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body


#--- SetOfType ----------------------------------------------------------------
class SetOfType (SeqOfType):
  def eth_reg_sub(self, ident, ectx):
    itmnm = ident
    if not self.val.IsNamed ():
      itmnm += '/' + '_item'
    self.val.eth_reg(itmnm, ectx, idx='(##)', parent=ident)

  def eth_tname(self):
    if self.val.type != 'Type_Ref':
      return '#' + self.type + '_' + str(id(self))
    if not self.HasConstraint():
      return "SET_OF_" + self.val.eth_tname()
    elif self.constr.IsSize():
      return 'SET_' + self.constr.eth_constrname() + '_OF_' + self.val.eth_tname()
    else:
      return '#' + self.type + '_' + str(id(self))

  def eth_ftype(self, ectx):
    return ('FT_UINT32', 'BASE_DEC')

  def eth_need_tree(self):
    return True

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_SET')

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    (pars['MIN_VAL'], pars['MAX_VAL'], pars['EXT']) = self.eth_get_size_constr()
    pars['TABLE'] = '%(TNAME)s_set_of'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_set_of', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(PINFO)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                   ('%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s',),))
    elif (ectx.Per() and not self.HasConstraint()):
      body = ectx.eth_fn_call('dissect_%(ER)s_set_of', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ETT_INDEX)s', '%(TABLE)s',),))
    elif (ectx.Per() and self.constr.type == 'Size'):
      body = ectx.eth_fn_call('dissect_%(ER)s_constrained_set_of', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ETT_INDEX)s', '%(TABLE)s',),
                                   ('%(MIN_VAL)s', '%(MAX_VAL)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

def mk_tag_str (ctx, cls, typ, num):

    # XXX should do conversion to int earlier!
    val = int (num)
    typ = typ.upper()
    if typ == 'DEFAULT':
        typ = ctx.tags_def
    return 'asn1.%s(%d,cls=asn1.%s_FLAG)' % (typ, val, cls) # XXX still ned

class Tag (Node):
  def to_python (self, ctx):
    return 'asn1.TYPE(%s,%s)' % (mk_tag_str (ctx, self.tag.cls,
                                                self.tag_typ,
                                                self.tag.num),
                                    self.typ.to_python (ctx))
  def GetTag(self, ectx):
    tc = ''
    if (self.cls == 'UNIVERSAL'): tc = 'BER_CLASS_UNI'
    elif (self.cls == 'APPLICATION'): tc = 'BER_CLASS_APP'
    elif (self.cls == 'CONTEXT'): tc = 'BER_CLASS_CON'
    elif (self.cls == 'PRIVATE'): tc = 'BER_CLASS_PRI'
    return (tc, self.num)
 
#--- SequenceType -------------------------------------------------------------
class SequenceType (SeqType):
  def to_python (self, ctx):
      # name, tag (None for no tag, EXPLICIT() for explicit), typ)
      # or '' + (1,) for optional
      # XXX should also collect names for SEQUENCE inside SEQUENCE or
      # CHOICE or SEQUENCE_OF (where should the SEQUENCE_OF name come
      # from?  for others, element or arm name would be fine)
      seq_name = getattr (self, 'sequence_name', None)
      if seq_name == None:
          seq_name = 'None'
      else:
          seq_name = "'" + seq_name + "'"
      if self.__dict__.has_key('ext_list'):
        return "%sasn1.SEQUENCE ([%s], ext=[%s], seq_name = %s)" % (ctx.spaces (), 
                                 self.elts_to_py (self.elt_list, ctx),
                                 self.elts_to_py (self.ext_list, ctx), seq_name)
      else:
        return "%sasn1.SEQUENCE ([%s]), seq_name = %s" % (ctx.spaces (), 
                                 self.elts_to_py (self.elt_list, ctx), seq_name)
  def elts_to_py (self, list, ctx):
      # we have elt_type, val= named_type, maybe default=, optional=
      # named_type node: either ident = or typ =
      # need to dismember these in order to generate Python output syntax.
      ctx.indent ()
      def elt_to_py (e):
          assert (e.type == 'elt_type')
          nt = e.val
          optflag = e.optional
          #assert (not hasattr (e, 'default')) # XXX add support for DEFAULT!
          assert (nt.type == 'named_type')
          tagstr = 'None'
          identstr = nt.ident
          if hasattr (nt.typ, 'type') and nt.typ.type == 'tag': # ugh
              tagstr = mk_tag_str (ctx,nt.typ.tag.cls,
                                   nt.typ.tag.tag_typ,nt.typ.tag.num)
      

              nt = nt.typ
          return "('%s',%s,%s,%d)" % (identstr, tagstr,
                                    nt.typ.to_python (ctx), optflag)
      indentstr = ",\n" + ctx.spaces ()
      rv = indentstr.join ([elt_to_py (e) for e in list])
      ctx.outdent ()
      return rv

  def eth_reg_sub(self, ident, ectx):
      for e in (self.elt_list):
          e.val.eth_reg(ident, ectx, parent=ident)
      if hasattr(self, 'ext_list'):
          for e in (self.ext_list):
              e.val.eth_reg(ident, ectx, parent=ident)

  def eth_need_tree(self):
    return True

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_SEQUENCE')

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    pars['TABLE'] = '%(TNAME)s_sequence'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_sequence', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(PINFO)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                   ('%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_sequence', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ETT_INDEX)s', '%(TABLE)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- SetType ------------------------------------------------------------------
class SetType(SeqType):
  def eth_reg_sub(self, ident, ectx):
    for e in (self.elt_list):
      e.val.eth_reg(ident, ectx, parent=ident)
    if hasattr(self, 'ext_list'):
      for e in (self.ext_list):
        e.val.eth_reg(ident, ectx, parent=ident)

  def eth_need_tree(self):
    return True

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_SET')

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    pars['TABLE'] = '%(TNAME)s_set'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_set', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(PINFO)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                   ('%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_set', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ETT_INDEX)s', '%(TABLE)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- ChoiceType ---------------------------------------------------------------
class ChoiceType (Type):
  def to_python (self, ctx):
      # name, tag (None for no tag, EXPLICIT() for explicit), typ)
      # or '' + (1,) for optional
      if self.__dict__.has_key('ext_list'):
        return "%sasn1.CHOICE ([%s], ext=[%s])" % (ctx.spaces (), 
                               self.elts_to_py (self.elt_list, ctx),
                               self.elts_to_py (self.ext_list, ctx))
      else:
        return "%sasn1.CHOICE ([%s])" % (ctx.spaces (), self.elts_to_py (self.elt_list, ctx))
  def elts_to_py (self, list, ctx):
      ctx.indent ()
      def elt_to_py (nt):
          assert (nt.type == 'named_type')
          tagstr = 'None'
          if hasattr (nt, 'ident'):
              identstr = nt.ident
          else:
              if hasattr (nt.typ, 'val'):
                  identstr = nt.typ.val # XXX, making up name
              elif hasattr (nt.typ, 'name'):
                  identstr = nt.typ.name
              else:
                  identstr = ctx.make_new_name ()

          if hasattr (nt.typ, 'type') and nt.typ.type == 'tag': # ugh
              tagstr = mk_tag_str (ctx,nt.typ.tag.cls,
                                   nt.typ.tag.tag_typ,nt.typ.tag.num)
      

              nt = nt.typ
          return "('%s',%s,%s)" % (identstr, tagstr,
                                    nt.typ.to_python (ctx))
      indentstr = ",\n" + ctx.spaces ()
      rv =  indentstr.join ([elt_to_py (e) for e in list])
      ctx.outdent ()
      return rv

  def eth_reg_sub(self, ident, ectx):
      #print "eth_reg_sub(ident='%s')" % (ident)
      for e in (self.elt_list):
          e.eth_reg(ident, ectx, parent=ident)
      if hasattr(self, 'ext_list'):
          for e in (self.ext_list):
              e.eth_reg(ident, ectx, parent=ident)

  def eth_ftype(self, ectx):
    return ('FT_UINT32', 'BASE_DEC')

  def eth_strings(self):
    return '$$'

  def eth_need_tree(self):
    return True

  def eth_has_vals(self):
    return True

  def GetTTag(self, ectx):
    lst = self.elt_list
    cls = 'BER_CLASS_ANY/*choice*/'
    #if hasattr(self, 'ext_list'):
    #  lst.extend(self.ext_list)
    #if (len(lst) > 0):
    #  cls = lst[0].GetTag(ectx)[0]
    #for e in (lst):
    #  if (e.GetTag(ectx)[0] != cls):
    #    cls = '-1/*choice*/'
    return (cls, '-1/*choice*/')

  def IndetermTag(self, ectx):
    #print "Choice IndetermTag()=%s" % (str(not self.HasOwnTag()))
    return not self.HasOwnTag()

  def eth_type_vals(self, tname, ectx):
    out = '\n'
    tagval = False
    if (ectx.Ber()):
      lst = self.elt_list
      if hasattr(self, 'ext_list'):
        lst.extend(self.ext_list)
      if (len(lst) > 0):
        t = lst[0].GetTag(ectx)[0]
        tagval = True
      if (t == 'BER_CLASS_UNI'):
        tagval = False
      for e in (lst):
        if (e.GetTag(ectx)[0] != t):
          tagval = False
    vals = []
    cnt = 0
    for e in (self.elt_list):
      if (tagval): val = e.GetTag(ectx)[1]
      else: val = str(cnt)
      vals.append((val, e.name))
      cnt += 1
    if hasattr(self, 'ext_list'):
      for e in (self.ext_list):
        if (tagval): val = e.GetTag(ectx)[1]
        else: val = str(cnt)
        vals.append((val, e.name))
        cnt += 1
    out += ectx.eth_vals(tname, vals)
    return out

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    pars['TABLE'] = '%(TNAME)s_choice'
    return pars

  def eth_type_default_table(self, ectx, tname):
    def out_item(val, e, ext, ectx):
      f = fname + '/' + e.name
      ef = ectx.field[f]['ethname']
      efd = ef
      if (ectx.field[f]['impl']):
        efd += '_impl'
      if (ectx.Ber()):
        opt = ''
        if (not e.HasOwnTag()):
          opt = 'BER_FLAGS_NOOWNTAG'
        elif (e.tag.mode == 'IMPLICIT'):
          if (opt): opt += '|'
          opt += 'BER_FLAGS_IMPLTAG'
        if (not opt): opt = '0'
      if (ectx.Ber()):
        (tc, tn) = e.GetTag(ectx)
        out = '  { %3s, %-13s, %s, %s, dissect_%s },\n' \
              % (val, tc, tn, opt, efd)
      elif (ectx.Per()):
        out = '  { %3s, %-30s, %-23s, dissect_%s },\n' \
              % (val, '"'+e.name+'"', ext, efd)
      else:
        out = ''
      return out   
    # end out_item()
    #print "eth_type_default_table(tname='%s')" % (tname)
    fname = ectx.eth_type[tname]['ref'][0]
    tagval = False
    if (ectx.Ber()):
      lst = self.elt_list
      if hasattr(self, 'ext_list'):
        lst.extend(self.ext_list)
      if (len(lst) > 0):
        t = lst[0].GetTag(ectx)[0]
        tagval = True
      if (t == 'BER_CLASS_UNI'):
        tagval = False
      for e in (lst):
        if (e.GetTag(ectx)[0] != t):
          tagval = False
    table = "static const %(ER)s_choice_t %(TABLE)s[] = {\n"
    cnt = 0
    if hasattr(self, 'ext_list'):
      ext = 'ASN1_EXTENSION_ROOT'
    else:
      ext = 'ASN1_NO_EXTENSIONS'
    for e in (self.elt_list):
      if (tagval): val = e.GetTag(ectx)[1]
      else: val = str(cnt)
      table += out_item(val, e, ext, ectx)
      cnt += 1
    if hasattr(self, 'ext_list'):
      for e in (self.ext_list):
        if (tagval): val = e.GetTag(ectx)[1]
        else: val = str(cnt)
        table += out_item(val, e, 'ASN1_NOT_EXTENSION_ROOT', ectx)
        cnt += 1
    if (ectx.Ber()):
      table += "  { 0, 0, 0, 0, NULL }\n};\n"
    else:
      table += "  { 0, NULL, 0, NULL }\n};\n"
    return table

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_choice', ret='offset',
                              par=(('%(PINFO)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                   ('%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s'),
                                   ('%(VAL_PTR)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_choice', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ETT_INDEX)s', '%(TABLE)s',),
                                   ('%(VAL_PTR)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body
   
#--- EnumeratedType -----------------------------------------------------------
class EnumeratedType (Type):
  def to_python (self, ctx):
    def strify_one (named_num):
      return "%s=%s" % (named_num.ident, named_num.val)
    return "asn1.ENUM(%s)" % ",".join (map (strify_one, self.val))

  def eth_ftype(self, ectx):
    return ('FT_UINT32', 'BASE_DEC')

  def eth_strings(self):
    return '$$'

  def eth_has_vals(self):
    return True

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_ENUMERATED')

  def get_vals_etc(self, ectx):
    vals = []
    lastv = 0
    used = {}
    maxv = 0
    root_num = 0
    ext_num = 0
    map_table = []
    for e in (self.val):
      if e.type == 'NamedNumber':
        used[int(e.val)] = True
    for e in (self.val):
      if e.type == 'NamedNumber':
        val = int(e.val)
      else:
        while used.has_key(lastv):
          lastv += 1
        val = lastv
        used[val] = True
      vals.append((val, e.ident))
      map_table.append(val)
      root_num += 1
      if val > maxv:
        maxv = val
    if self.ext is not None:
      for e in (self.ext):
        if e.type == 'NamedNumber':
          used[int(e.val)] = True
      for e in (self.ext):
        if e.type == 'NamedNumber':
          val = int(e.val)
        else:
          while used.has_key(lastv):
            lastv += 1
          val = lastv
          used[val] = True
        vals.append((val, e.ident))
        map_table.append(val)
        ext_num += 1
        if val > maxv:
          maxv = val
    need_map = False
    for i in range(len(map_table)):
      need_map = need_map or (map_table[i] != i)
    if (not need_map):
      map_table = None
    return (vals, root_num, ext_num, map_table)

  def eth_type_vals(self, tname, ectx):
    out = '\n'
    vals = self.get_vals_etc(ectx)[0]
    out += ectx.eth_vals(tname, vals)
    return out

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    (root_num, ext_num, map_table) = self.get_vals_etc(ectx)[1:]
    if (self.ext != None):
      ext = 'TRUE'
    else:
      ext = 'FALSE'
    pars['ROOT_NUM'] = str(root_num)
    pars['EXT'] = ext
    pars['EXT_NUM'] = str(ext_num)
    if (map_table):
      pars['TABLE'] = '%(TNAME)s_value_map'
    else:
      pars['TABLE'] = 'NULL'
    return pars

  def eth_type_default_table(self, ectx, tname):
    map_table = self.get_vals_etc(ectx)[3]
    if (map_table == None): return ''
    table = "static guint32 %(TABLE)s[%(ROOT_NUM)s+%(EXT_NUM)s] = {"
    table += ", ".join([str(v) for v in map_table])
    table += "};\n"
    return table

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_integer', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(PINFO)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),
                                   ('%(VAL_PTR)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_enumerated', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ROOT_NUM)s', '%(VAL_PTR)s', '%(CREATED_ITEM_PTR)s', '%(EXT)s', '%(EXT_NUM)s', '%(TABLE)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- AnyType -----------------------------------------------------------
class AnyType (Type):
  def to_python (self, ctx):
    return "asn1.ANY"

  def eth_ftype(self, ectx):
    return ('FT_NONE', 'BASE_NONE')

  def GetTTag(self, ectx):
    return ('BER_CLASS_ANY', '0')

  def eth_type_default_body(self, ectx, tname):
    body = '#error Can not decode %s' % (tname)
    return body

class Literal (Node):
    def to_python (self, ctx):
        return self.val

#--- NullType -----------------------------------------------------------------
class NullType (Type):
  def to_python (self, ctx):
    return 'asn1.NULL'

  def eth_tname(self):
    return 'NULL'

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_NULL')

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_null', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(PINFO)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_null', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- RealType -----------------------------------------------------------------
class RealType (Type):
  def to_python (self, ctx):
    return 'asn1.REAL'

  def eth_tname(self):
    return 'REAL'

  def eth_type_default_body(self, ectx, tname):
    body = '#error Can not decode %s' % (tname)
    return body

#--- BooleanType --------------------------------------------------------------
class BooleanType (Type):
  def to_python (self, ctx):
    return 'asn1.BOOLEAN'

  def eth_tname(self):
    return 'BOOLEAN'

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_BOOLEAN')

  def eth_ftype(self, ectx):
    return ('FT_BOOLEAN', '8')

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_boolean', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(PINFO)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_boolean', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(VAL_PTR)s', '%(CREATED_ITEM_PTR)s'),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- OctetStringType ----------------------------------------------------------
class OctetStringType (Type):
  def to_python (self, ctx):
    return 'asn1.OCTSTRING'

  def eth_tname(self):
    if not self.HasConstraint():
      return 'OCTET_STRING'
    elif self.constr.IsSize():
      return 'OCTET_STRING' + '_' + self.constr.eth_constrname()
    else:
      return '#' + self.type + '_' + str(id(self))

  def eth_ftype(self, ectx):
    return ('FT_BYTES', 'BASE_HEX')

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_OCTETSTRING')

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    (pars['MIN_VAL'], pars['MAX_VAL'], pars['EXT']) = self.eth_get_size_constr()
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_octet_string', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(PINFO)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),
                                   ('%(VAL_PTR)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_octet_string', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(VAL_PTR)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- CharacterStringType ------------------------------------------------------
class CharacterStringType (Type):
  def eth_tname(self):
    if not self.HasConstraint():
      return self.eth_tsname()
    elif self.constr.IsSize():
      return self.eth_tsname() + '_' + self.constr.eth_constrname()
    else:
      return '#' + self.type + '_' + str(id(self))

  def eth_ftype(self, ectx):
    return ('FT_STRING', 'BASE_NONE')

class RestrictedCharacterStringType (CharacterStringType):
  def to_python (self, ctx):
    return 'asn1.' + self.eth_tsname()

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_' + self.eth_tsname())

  def HasPermAlph(self):
    return (self.HasConstraint() and 
            (self.constr.IsPermAlph() or 
             (self.constr.type == 'Intersection' and (self.constr.subtype[0].IsPermAlph() or self.constr.subtype[1].IsPermAlph()))
            )
           )

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    (pars['MIN_VAL'], pars['MAX_VAL'], pars['EXT']) = self.eth_get_size_constr()
    (pars['STRING_TYPE'], pars['STRING_TAG']) = (self.eth_tsname(), self.GetTTag(ectx)[1])
    (pars['ALPHABET'], pars['ALPHABET_LEN']) = ('NULL', '0')
    if self.HasPermAlph():
      if self.constr.IsPermAlph():
        pars['ALPHABET'] = self.constr.subtype.subtype
      elif self.constr.subtype[0].IsPermAlph():
        pars['ALPHABET'] = self.constr.subtype[0].subtype.subtype
      elif self.constr.subtype[1].IsPermAlph():
        pars['ALPHABET'] = self.constr.subtype[1].subtype.subtype
      pars['ALPHABET_LEN'] = 'strlen(%(ALPHABET)s)'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_restricted_string', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(STRING_TAG)s'),
                                   ('%(PINFO)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),
                                   ('%(VAL_PTR)s',),))
    elif (ectx.Per() and self.HasPermAlph()):
      body = ectx.eth_fn_call('dissect_%(ER)s_restricted_character_string', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(ALPHABET)s', '%(ALPHABET_LEN)s'),
                                   ('%(VAL_PTR)s',),))
    elif (ectx.Per()):
      if (self.eth_tsname() == 'GeneralString'):
        body = ectx.eth_fn_call('dissect_%(ER)s_%(STRING_TYPE)s', ret='offset',
                                par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),))
      elif (self.eth_tsname() == 'GeneralizedTime'):
        body = ectx.eth_fn_call('dissect_%(ER)s_VisibleString', ret='offset',
                                par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s',),))
      elif (self.eth_tsname() == 'UTCTime'):
        body = ectx.eth_fn_call('dissect_%(ER)s_VisibleString', ret='offset',
                                par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s',),))
      else:
        body = ectx.eth_fn_call('dissect_%(ER)s_%(STRING_TYPE)s', ret='offset',
                                par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

class BMPStringType (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'BMPString'

class GeneralStringType (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'GeneralString'

class GraphicStringType (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'GraphicString'

class IA5StringType (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'IA5String'

class NumericStringType (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'NumericString'

class PrintableStringType (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'PrintableString'

class TeletexStringType (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'TeletexString'

class T61StringType (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'T61String'
  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_TeletexString')

class UniversalStringType (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'UniversalString'

class UTF8StringType (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'UTF8String'

class VideotexStringType (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'VideotexString'

class VisibleStringType (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'VisibleString'

class ISO646StringType (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'ISO646String'
  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_VisibleString')

class UnrestrictedCharacterStringType (CharacterStringType):
  def to_python (self, ctx):
    return 'asn1.UnrestrictedCharacterString'
  def eth_tsname(self):
    return 'CHARACTER_STRING'

#--- UsefulType ---------------------------------------------------------------
class GeneralizedTime (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'GeneralizedTime'

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_%(STRING_TYPE)s', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(PINFO)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),))
      return body
    else:
      return RestrictedCharacterStringType.eth_type_default_body(self, ectx, tname)

class UTCTime (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'UTCTime'

class ObjectDescriptor (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'ObjectDescriptor'


#--- ObjectIdentifierType -----------------------------------------------------
class ObjectIdentifierType (Type):
  def to_python (self, ctx):
    return 'asn1.OBJECT_IDENTIFIER'

  def eth_tname(self):
    return 'OBJECT_IDENTIFIER'

  def eth_ftype(self, ectx):
    return ('FT_OID', 'BASE_NONE')

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_OID')

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_object_identifier%(FN_VARIANT)s', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(PINFO)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s', '%(VAL_PTR)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_object_identifier%(FN_VARIANT)s', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s', '%(VAL_PTR)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- ObjectIdentifierValue ----------------------------------------------------
class ObjectIdentifierValue (Value):
  def get_num(self, path, val):
    return str(oid_names.get(path + '/' + val, val))

  def to_str(self):
    out = ''
    path = ''
    first = True
    sep = ''
    for v in self.comp_list:
      if isinstance(v, Node) and (v.type == 'name_and_number'):
        vstr = v.number
      elif v.isdigit():
        vstr = v
      else:
        vstr = self.get_num(path, v)
      if first:
        if vstr.isdigit():
          out += '"' + vstr
        else:
          out += vstr + '"'
      else:
       out += sep + vstr
      path += sep + vstr
      first = False
      sep = '.'
    out += '"'
    return out

  def get_dep(self):
    v = self.comp_list[0]
    if isinstance(v, Node) and (v.type == 'name_and_number'):
      return None
    elif v.isdigit():
      return None
    else:
      vstr = self.get_num('', v)
    if vstr.isdigit():
      return None
    else:
      return vstr

class NamedNumber (Node):
    def to_python (self, ctx):
        return "('%s',%s)" % (self.ident, self.val)

class NamedNumListBase(Node):
    def to_python (self, ctx):
        return "asn1.%s_class ([%s])" % (self.asn1_typ,",".join (
            map (lambda x: x.to_python (ctx), self.named_list)))

#--- IntegerType --------------------------------------------------------------
class IntegerType (Type):
  def to_python (self, ctx):
        return "asn1.INTEGER_class ([%s])" % (",".join (
            map (lambda x: x.to_python (ctx), self.named_list)))

  def eth_tname(self):
    if self.named_list:
      return Type.eth_tname(self)
    if not self.HasConstraint():
      return 'INTEGER'
    elif self.constr.type == 'SingleValue' or self.constr.type == 'ValueRange':
      return 'INTEGER' + '_' + self.constr.eth_constrname()
    else:
      return 'INTEGER' + '_' + self.constr.eth_tname()

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_INTEGER')

  def eth_ftype(self, ectx):
    if self.HasConstraint():
      if not self.constr.IsNegativ():
        return ('FT_UINT32', 'BASE_DEC')
    return ('FT_INT32', 'BASE_DEC')

  def eth_strings(self):
    if (self.named_list):
      return '$$'
    else:
      return 'NULL'

  def eth_has_vals(self):
    if (self.named_list):
      return True
    else:
      return False

  def eth_type_vals(self, tname, ectx):
    if not self.eth_has_vals(): return ''
    out = '\n'
    vals = []
    for e in (self.named_list):
      vals.append((int(e.val), e.ident))
    out += ectx.eth_vals(tname, vals)
    return out

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    if self.HasConstraint() and self.constr.IsValue():
      (pars['MIN_VAL'], pars['MAX_VAL'], pars['EXT']) = self.eth_get_value_constr()
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_integer', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(PINFO)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),
                                   ('%(VAL_PTR)s',),))
    elif (ectx.Per() and not self.HasConstraint()):
      body = ectx.eth_fn_call('dissect_%(ER)s_integer', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(VAL_PTR)s', '%(CREATED_ITEM_PTR)s'),))
    elif (ectx.Per() and ((self.constr.type == 'SingleValue') or (self.constr.type == 'ValueRange'))):
      body = ectx.eth_fn_call('dissect_%(ER)s_constrained_integer', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(VAL_PTR)s', '%(CREATED_ITEM_PTR)s', '%(EXT)s'),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- BitStringType ------------------------------------------------------------
class BitStringType (Type):
  def to_python (self, ctx):
        return "asn1.BITSTRING_class ([%s])" % (",".join (
            map (lambda x: x.to_python (ctx), self.named_list)))

  def eth_tname(self):
    if self.named_list:
      return Type.eth_tname(self)
    elif not self.HasConstraint():
      return 'BIT_STRING'
    elif self.constr.IsSize():
      return 'BIT_STRING' + '_' + self.constr.eth_constrname()
    else:
      return '#' + self.type + '_' + str(id(self))

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_BITSTRING')

  def eth_ftype(self, ectx):
    return ('FT_BYTES', 'BASE_HEX')

  def eth_need_tree(self):
    return self.named_list

  def eth_named_bits(self):
    bits = []
    if (self.named_list):
      for e in (self.named_list):
        bits.append((int(e.val), e.ident))
    return bits

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    (pars['MIN_VAL'], pars['MAX_VAL'], pars['EXT']) = self.eth_get_size_constr()
    if not pars.has_key('ETT_INDEX'):
      pars['ETT_INDEX'] = '-1'
    pars['TABLE'] = 'NULL'
    if self.eth_named_bits():
      pars['TABLE'] = '%(TNAME)s_bits'
    return pars

  def eth_type_default_table(self, ectx, tname):
    #print "eth_type_default_table(tname='%s')" % (tname)
    table = ''
    bits = self.eth_named_bits()
    if (bits):
      table = ectx.eth_bits(tname, bits)
    return table

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_bitstring', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(PINFO)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                   ('%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s',),
                                   ('%(VAL_PTR)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_bit_string', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(PINFO)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(MIN_VAL)s', '%(MAX_VAL)s','%(EXT)s'),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body


#==============================================================================
    
def p_module_list_1 (t):
    'module_list : module_list module_def'
    t[0] = t[1] + [t[2]]

def p_module_list_2 (t):
    'module_list : module_def'
    t[0] = [t[1]]


#--- ITU-T Recommendation X.680 -----------------------------------------------


# 11 ASN.1 lexical items --------------------------------------------------------

# 11.2 Type references
def p_type_ref (t):
    'type_ref : UCASE_IDENT'
    t[0] = Type_Ref(val=t[1])

# 11.4 Value references
def p_valuereference (t):
    'valuereference : LCASE_IDENT'
    t[0] = t[1]


# 12 Module definition --------------------------------------------------------

# 12.1
def p_module_def (t):
    'module_def : module_ident DEFINITIONS TagDefault ASSIGNMENT BEGIN module_body END'
    t[0] = Module (ident = t[1], tag_def = t[3], body = t[6])

def p_TagDefault_1 (t):
    '''TagDefault : EXPLICIT TAGS
    | IMPLICIT TAGS
    | AUTOMATIC TAGS'''
    t[0] = Default_Tags (dfl_tag = t[1])

def p_TagDefault_2 (t):
    'TagDefault : '
    # 12.2 The "TagDefault" is taken as EXPLICIT TAGS if it is "empty".
    t[0] = Default_Tags (dfl_tag = 'EXPLICIT') 

def p_module_ident (t):
    'module_ident : type_ref assigned_ident' # name, oid
    # XXX coerce type_ref to module_ref
    t [0] = Node('module_ident', val = t[1].val, ident = t[2])


# XXX originally we had both type_ref and module_ref, but that caused
# a reduce/reduce conflict (because both were UCASE_IDENT).  Presumably
# this didn't cause a problem in the original ESNACC grammar because it
# was LALR(1) and PLY is (as of 1.1) only SLR.

#def p_module_ref (t):
#    'module_ref : UCASE_IDENT'
#    t[0] = t[1]

def p_assigned_ident_1 (t):
    'assigned_ident : ObjectIdentifierValue'
    t[0] = t[1]

def p_assigned_ident_2 (t):
    'assigned_ident : LCASE_IDENT'
    t[0] = t[1]

def p_assigned_ident_3 (t):
    'assigned_ident : '
    pass

def p_module_body_1 (t):
    'module_body : exports Imports AssignmentList'
    t[0] = Module_Body (exports = t[1], imports = t[2], assign_list = t[3])

def p_module_body_2 (t):
    'module_body : '
    t[0] = Node ('module_body', exports = [], imports = [],
                 assign_list = [])

def p_exports_1 (t):
    'exports : EXPORTS syms_exported SEMICOLON'
    t[0] = t[2]

def p_exports_2 (t):
    'exports : '
    t[0] = []

def p_syms_exported_1 (t):
    'syms_exported : exp_sym_list'
    t[0] = t[1]

def p_syms_exported_2 (t):
    'syms_exported : '
    t[0] = []

def p_exp_sym_list_1 (t):
    'exp_sym_list : Symbol'
    t[0] = [t[1]]

def p_exp_sym_list_2 (t):
    'exp_sym_list : exp_sym_list COMMA Symbol'
    t[0] = t[1] + [t[3]]
    

def p_Imports_1(t):
    'Imports : IMPORTS SymbolsImported SEMICOLON'
    t[0] = t[2]

def p_Imports_2 (t):
    'Imports : '
    t[0] = []

def p_SymbolsImported_1(t):
    'SymbolsImported : '
    t[0] = []

def p_SymbolsImported_2 (t):
    'SymbolsImported : SymbolsFromModuleList'
    t[0] = t[1]

def p_SymbolsFromModuleList_1 (t):
    'SymbolsFromModuleList : SymbolsFromModuleList SymbolsFromModule'
    t[0] = t[1] + [t[2]]

def p_SymbolsFromModuleList_2 (t):
    'SymbolsFromModuleList : SymbolsFromModule'
    t[0] = [t[1]]

def p_SymbolsFromModule (t):
    'SymbolsFromModule : SymbolList FROM module_ident'
    t[0] = Node ('SymbolList', symbol_list = t[1], module = t[3])

def p_SymbolList_1 (t):
    'SymbolList : Symbol'
    t[0] = [t[1]]

def p_SymbolList_2 (t):
    'SymbolList : SymbolList COMMA Symbol'
    t[0] = t[1] + [t[3]]

def p_Symbol (t):
    '''Symbol : type_ref
              | ParameterizedReference
              | identifier''' # XXX omit DefinedMacroName
    t[0] = t[1]

def p_Reference (t):
    '''Reference : type_ref
                 | valuereference'''
    t[0] = t[1]

def p_AssignmentList_1 (t):
    'AssignmentList : AssignmentList Assignment'
    t[0] = t[1] + [t[2]]

def p_AssignmentList_2 (t):
    'AssignmentList : Assignment SEMICOLON'
    t[0] = [t[1]]

def p_AssignmentList_3 (t):
    'AssignmentList : Assignment'
    t[0] = [t[1]]

def p_Assignment (t):
    '''Assignment : TypeAssignment
                  | ValueAssignment
                  | pyquote
                  | ParameterizedTypeAssignment'''
    t[0] = t[1]

def p_pyquote (t):
    '''pyquote : PYQUOTE'''
    t[0] = PyQuote (val = t[1])


# 13 Referencing type and value definitions -----------------------------------

# 13.1
def p_DefinedType (t): 
  '''DefinedType : ext_type_ref
  | type_ref
  | ParameterizedType'''
  t[0] = t[1]

def p_DefinedValue(t):
  '''DefinedValue : ext_val_ref
                  | identifier'''
  t[0] = t[1]


# 15 Assigning types and values -----------------------------------------------

# 15.1
def p_TypeAssignment (t):
  'TypeAssignment : UCASE_IDENT ASSIGNMENT Type'
  t[0] = t[3]
  t[0].SetName(t[1])

# 15.2
def p_ValueAssignment (t):
  'ValueAssignment : identifier Type ASSIGNMENT Value'
  t[0] = value_assign (ident = t[1], typ = t[2], val = t[4])


# 16 Definition of types and values -------------------------------------------

# 16.1
def p_Type (t):
  '''Type : BuiltinType
  | ReferencedType
  | ConstrainedType'''
  t[0] = t[1]

# 16.2
def p_BuiltinType (t):
  '''BuiltinType : AnyType
                 | BitStringType
                 | BooleanType
                 | CharacterStringType
                 | ChoiceType
                 | EnumeratedType
                 | IntegerType
                 | NullType
                 | ObjectIdentifierType
                 | OctetStringType
                 | RealType
                 | SequenceType
                 | SequenceOfType
                 | SetType
                 | SetOfType
                 | selection_type
                 | TaggedType'''
  t[0] = t[1]

# 16.3
def p_ReferencedType (t):
  '''ReferencedType : DefinedType
                    | UsefulType'''
  t[0] = t[1]

def p_ext_type_ref (t):
    'ext_type_ref : type_ref DOT type_ref'
    # XXX coerce 1st type_ref to module_ref
    t[0] = Node ('ext_type_ref', module = t[1], typ = t[3])

# 16.5
def p_NamedType (t):
  'NamedType : identifier Type'
  t[0] = t[2]
  t[0].SetName (t[1]) 

# 16.7
def p_Value (t):
  '''Value : BuiltinValue
           | ReferencedValue'''
  t[0] = t[1]

# 16.9
def p_BuiltinValue (t):
  '''BuiltinValue : BooleanValue
                  | ObjectIdentifierValue
                  | special_real_val
                  | SignedNumber
                  | SequenceValue
                  | hex_string
                  | binary_string
                  | char_string''' # XXX we don't support {data} here
  t[0] = t[1]

# 16.11
def p_ReferencedValue (t):
  '''ReferencedValue : DefinedValue'''
  t[0] = t[1]

# 16.13
#def p_NamedValue (t):
#  'NamedValue : identifier Value'
#  t[0] = Node ('NamedValue', ident = t[1], value = t[2])


# 17 Notation for the boolean type --------------------------------------------

# 17.1
def p_BooleanType (t):
  'BooleanType : BOOLEAN'
  t[0] = BooleanType ()

# 17.2
def p_BooleanValue (t):
  '''BooleanValue : TRUE
                  | FALSE'''
  t[0] = t[1]


# 18 Notation for the integer type --------------------------------------------

# 18.1
def p_IntegerType_1 (t):
  'IntegerType : INTEGER'
  t[0] = IntegerType (named_list = None)

def p_IntegerType_2 (t):
  'IntegerType : INTEGER LBRACE NamedNumberList RBRACE'
  t[0] = IntegerType (named_list = t[3])

def p_NamedNumberList_1 (t):
  'NamedNumberList : NamedNumber'
  t[0] = [t[1]]

def p_NamedNumberList_2 (t):
  'NamedNumberList : NamedNumberList COMMA NamedNumber'
  t[0] = t[1] + [t[3]]

def p_NamedNumber (t):
  '''NamedNumber : identifier LPAREN SignedNumber RPAREN
                 | identifier LPAREN DefinedValue RPAREN'''
  t[0] = NamedNumber (ident = t[1], val = t[3])

def p_SignedNumber_1 (t):
  'SignedNumber : NUMBER'
  t[0] = t [1]

def p_SignedNumber_2 (t):
  'SignedNumber : MINUS NUMBER'
  t[0] = '-' + t[2]


# 19 Notation for the enumerated type -----------------------------------------

# 19.1
def p_EnumeratedType (t):
    'EnumeratedType : ENUMERATED LBRACE Enumerations RBRACE'
    t[0] = EnumeratedType (val = t[3]['val'], ext = t[3]['ext'])

def p_Enumerations_1 (t):
    'Enumerations : Enumeration'
    t[0] = { 'val' : t[1], 'ext' : None }

def p_Enumerations_2 (t):
    'Enumerations : Enumeration COMMA ELLIPSIS ExceptionSpec'
    t[0] = { 'val' : t[1], 'ext' : [] }

def p_Enumerations_3 (t):
    'Enumerations : Enumeration COMMA ELLIPSIS ExceptionSpec COMMA Enumeration'
    t[0] = { 'val' : t[1], 'ext' : t[6] }

def p_Enumeration_1 (t):
    'Enumeration : EnumerationItem'
    t[0] = [t[1]]

def p_Enumeration_2 (t):
    'Enumeration : Enumeration COMMA EnumerationItem'
    t[0] = t[1] + [t[3]]

def p_EnumerationItem (t):
    '''EnumerationItem : Identifier
                       | NamedNumber'''
    t[0] = t[1]

def p_Identifier (t):
    'Identifier : identifier'
    t[0] = Node ('Identifier', ident = t[1])


# 20 Notation for the real type -----------------------------------------------

# 20.1
def p_RealType (t):
    'RealType : REAL'
    t[0] = RealType ()

# 21 Notation for the bitstring type ------------------------------------------

# 21.1
def p_BitStringType_1 (t):
    'BitStringType : BIT STRING'
    t[0] = BitStringType (named_list = None)

def p_BitStringType_2 (t):
    'BitStringType : BIT STRING LBRACE NamedBitList RBRACE'
    t[0] = BitStringType (named_list = t[4])

def p_NamedBitList_1 (t):
    'NamedBitList : NamedBit'
    t[0] = [t[1]]

def p_NamedBitList_2 (t):
    'NamedBitList : NamedBitList COMMA NamedBit'
    t[0] = t[1] + [t[3]]

def p_NamedBit (t):
    '''NamedBit : identifier LPAREN NUMBER RPAREN
                | identifier LPAREN DefinedValue RPAREN'''
    t[0] = NamedNumber (ident = t[1], val = t[3])


# 22 Notation for the octetstring type ----------------------------------------

# 22.1
def p_OctetStringType (t):
    'OctetStringType : OCTET STRING'
    t[0] = OctetStringType ()


# 23 Notation for the null type -----------------------------------------------

# 23.1
def p_NullType (t):
    'NullType : NULL'
    t[0] = NullType ()

# 23.3
#def p_NullValue (t):
#    'NullValue : NULL'
#    t[0] = t[1]


# 24 Notation for sequence types ----------------------------------------------

# 24.1
def p_SequenceType_1 (t):
    'SequenceType : SEQUENCE LBRACE RBRACE'
    t[0] = SequenceType (elt_list = [])

def p_SequenceType_2 (t):
    'SequenceType : SEQUENCE LBRACE ComponentTypeLists RBRACE'
    if t[3].has_key('ext_list'):
        t[0] = SequenceType (elt_list = t[3]['elt_list'], ext_list = t[3]['ext_list'])
    else:
        t[0] = SequenceType (elt_list = t[3]['elt_list'])

def p_ExtensionAndException_1 (t):
    'ExtensionAndException : ELLIPSIS'
    t[0] = []

def p_OptionalExtensionMarker_1 (t):
    'OptionalExtensionMarker : COMMA ELLIPSIS'
    t[0] = True

def p_OptionalExtensionMarker_2 (t):
    'OptionalExtensionMarker : '
    t[0] = False

def p_ComponentTypeLists_1 (t):
    'ComponentTypeLists : element_type_list'
    t[0] = {'elt_list' : t[1]}

def p_ComponentTypeLists_2 (t):
    'ComponentTypeLists : element_type_list COMMA ExtensionAndException extension_additions OptionalExtensionMarker'
    t[0] = {'elt_list' : t[1], 'ext_list' : t[4]}

def p_ComponentTypeLists_3 (t):
    'ComponentTypeLists : ExtensionAndException extension_additions OptionalExtensionMarker'
    t[0] = {'elt_list' : [], 'ext_list' : t[2]}

def p_extension_additions_1 (t):
    'extension_additions : extension_addition_list'
    t[0] = t[1]

def p_extension_additions_2 (t):
    'extension_additions : '
    t[0] = []

def p_extension_addition_list_1 (t):
    'extension_addition_list : COMMA extension_addition'
    t[0] = [t[2]]

def p_extension_addition_list_2 (t):
    'extension_addition_list : extension_addition_list COMMA extension_addition'
    t[0] = t[1] + [t[3]]

def p_extension_addition_1 (t):
    'extension_addition : element_type'
    t[0] = t[1]

def p_element_type_list_1 (t):
    'element_type_list : element_type'
    t[0] = [t[1]]

def p_element_type_list_2 (t):
    'element_type_list : element_type_list COMMA element_type'
    t[0] = t[1] + [t[3]]

def p_element_type_1 (t):
    'element_type : NamedType'
    t[0] = Node ('elt_type', val = t[1], optional = 0)

def p_element_type_2 (t):
    'element_type : NamedType OPTIONAL'
    t[0] = Node ('elt_type', val = t[1], optional = 1)

def p_element_type_3 (t):
    'element_type : NamedType DEFAULT Value'
    t[0] = Node ('elt_type', val = t[1], optional = 1, default = t[3])
#          /*
#           * this rules uses NamedValue instead of Value
#           * for the stupid choice value syntax (fieldname value)
#           * it should be like a set/seq value (ie with
#           * enclosing { }
#           */

# XXX get to COMPONENTS later

# 24.17
def p_SequenceValue_1 (t):
  'SequenceValue : LBRACE RBRACE'
  t[0] = []


#def p_SequenceValue_2 (t):
#  'SequenceValue : LBRACE ComponentValueList RBRACE'
#  t[0] = t[2]
    
#def p_ComponentValueList_1 (t):
#    'ComponentValueList : NamedValue'
#    t[0] = [t[1]]

#def p_ComponentValueList_2 (t):
#    'ComponentValueList : ComponentValueList COMMA NamedValue'
#    t[0] = t[1] + [t[3]]


# 25 Notation for sequence-of types -------------------------------------------

# 25.1
def p_SequenceOfType (t):
    '''SequenceOfType : SEQUENCE OF Type
                      | SEQUENCE OF NamedType'''
    t[0] = SequenceOfType (val = t[3], size_constr = None)


# 26 Notation for set types ---------------------------------------------------

# 26.1
def p_SetType_1 (t):
    'SetType : SET LBRACE RBRACE'
    if t[3].has_key('ext_list'):
        t[0] = SetType (elt_list = [])

def p_SetType_2 (t):
    'SetType : SET LBRACE ComponentTypeLists RBRACE'
    if t[3].has_key('ext_list'):
        t[0] = SetType (elt_list = t[3]['elt_list'], ext_list = t[3]['ext_list'])
    else:
        t[0] = SetType (elt_list = t[3]['elt_list'])


# 27 Notation for set-of types ------------------------------------------------

# 27.1
def p_SetOfType (t):
    '''SetOfType : SET OF Type
                 | SET OF NamedType'''
    t[0] = SetOfType (val = t[3])

# 28 Notation for choice types ------------------------------------------------

# 28.1
def p_ChoiceType (t):
    'ChoiceType : CHOICE LBRACE alternative_type_lists RBRACE'
    if t[3].has_key('ext_list'):
        t[0] = ChoiceType (elt_list = t[3]['elt_list'], ext_list = t[3]['ext_list'])
    else:
        t[0] = ChoiceType (elt_list = t[3]['elt_list'])

def p_alternative_type_lists_1 (t):
    'alternative_type_lists : alternative_type_list'
    t[0] = {'elt_list' : t[1]}

def p_alternative_type_lists_2 (t):
    '''alternative_type_lists : alternative_type_list COMMA ExtensionAndException extension_addition_alternatives OptionalExtensionMarker'''
    t[0] = {'elt_list' : t[1], 'ext_list' : t[4]}

def p_extension_addition_alternatives_1 (t):
    'extension_addition_alternatives : extension_addition_alternatives_list'
    t[0] = t[1]

def p_extension_addition_alternatives_2 (t):
    'extension_addition_alternatives : '
    t[0] = []

def p_extension_addition_alternatives_list_1 (t):
    'extension_addition_alternatives_list : COMMA extension_addition_alternative'
    t[0] = [t[2]]

def p_extension_addition_alternatives_list_2 (t):
    'extension_addition_alternatives_list : extension_addition_alternatives_list COMMA extension_addition_alternative'
    t[0] = t[1] + [t[3]]

def p_extension_addition_alternative_1 (t):
    'extension_addition_alternative : NamedType'
    t[0] = t[1]

def p_alternative_type_list_1 (t):
    'alternative_type_list : NamedType'
    t[0] = [t[1]]

def p_alternative_type_list_2 (t):
    'alternative_type_list : alternative_type_list COMMA NamedType'
    t[0] = t[1] + [t[3]]

def p_selection_type (t): # XXX what is this?
    'selection_type : identifier LT Type'
    return Node ('seltype', ident = t[1], typ = t[3])

# 30 Notation for tagged types ------------------------------------------------

# 30.1
def p_TaggedType_1 (t):
    'TaggedType : Tag Type'
    t[1].mode = 'default'
    t[0] = t[2]
    t[0].SetTag(t[1])

def p_TaggedType_2 (t):
    '''TaggedType : Tag IMPLICIT Type
                  | Tag EXPLICIT Type'''
    t[1].mode = t[2]
    t[0] = t[3]
    t[0].SetTag(t[1])

def p_Tag (t):
    'Tag : LBRACK Class ClassNumber RBRACK'
    t[0] = Tag(cls = t[2], num = t[3])

def p_ClassNumber_1 (t):
    'ClassNumber : number'
    t[0] = t[1]

def p_ClassNumber_2 (t):
    'ClassNumber : DefinedValue'
    t[0] = t[1]

def p_Class_1 (t):
    '''Class : UNIVERSAL
             | APPLICATION
             | PRIVATE'''
    t[0] = t[1]

def p_Class_2 (t):
    'Class :'
    t[0] = 'CONTEXT'


def p_AnyType (t):
    'AnyType : ANY'
    t[0] = AnyType ()

#def p_any_type_2 (t):
#    'any_type : ANY DEFINED BY identifier'
#    t[0] = Literal (val='asn1.ANY_constr(def_by="%s")' % t[4]) # XXX


# 31 Notation for the object identifier type ----------------------------------

# 31.1
def p_ObjectIdentifierType (t):
  'ObjectIdentifierType : OBJECT IDENTIFIER'
  t[0] = ObjectIdentifierType ()

# 31.3
def p_ObjectIdentifierValue (t):
    'ObjectIdentifierValue : LBRACE oid_comp_list RBRACE'
    t[0] = ObjectIdentifierValue (comp_list=t[2])

def p_oid_comp_list_1 (t):
    'oid_comp_list : oid_comp_list oid_component'
    t[0] = t[1] + [t[2]]

def p_oid_comp_list_2 (t):
    'oid_comp_list : oid_component'
    t[0] = [t[1]]

def p_oid_component (t):
    '''oid_component : number_form
    | name_form
    | name_and_number_form'''
    t[0] = t[1]

def p_number_form (t):
    'number_form : NUMBER'
    t [0] = t[1]

# 36 Notation for character string types --------------------------------------

# 36.1
def p_CharacterStringType (t):
    '''CharacterStringType : RestrictedCharacterStringType
    | UnrestrictedCharacterStringType'''
    t[0] = t[1]


# 37 Definition of restricted character string types --------------------------

def p_RestrictedCharacterStringType_1 (t):
    'RestrictedCharacterStringType : BMPString'
    t[0] = BMPStringType ()
def p_RestrictedCharacterStringType_2 (t):
    'RestrictedCharacterStringType : GeneralString'
    t[0] = GeneralStringType ()
def p_RestrictedCharacterStringType_3 (t):
    'RestrictedCharacterStringType : GraphicString'
    t[0] = GraphicStringType ()
def p_RestrictedCharacterStringType_4 (t):
    'RestrictedCharacterStringType : IA5String'
    t[0] = IA5StringType ()
def p_RestrictedCharacterStringType_5 (t):
    'RestrictedCharacterStringType : ISO646String'
    t[0] = ISO646StringType ()
def p_RestrictedCharacterStringType_6 (t):
    'RestrictedCharacterStringType : NumericString'
    t[0] = NumericStringType ()
def p_RestrictedCharacterStringType_7 (t):
    'RestrictedCharacterStringType : PrintableString'
    t[0] = PrintableStringType ()
def p_RestrictedCharacterStringType_8 (t):
    'RestrictedCharacterStringType : TeletexString'
    t[0] = TeletexStringType ()
def p_RestrictedCharacterStringType_9 (t):
    'RestrictedCharacterStringType : T61String'
    t[0] = T61StringType ()
def p_RestrictedCharacterStringType_10 (t):
    'RestrictedCharacterStringType : UniversalString'
    t[0] = UniversalStringType ()
def p_RestrictedCharacterStringType_11 (t):
    'RestrictedCharacterStringType : UTF8String'
    t[0] = UTF8StringType ()
def p_RestrictedCharacterStringType_12 (t):
    'RestrictedCharacterStringType : VideotexString'
    t[0] = VideotexStringType ()
def p_RestrictedCharacterStringType_13 (t):
    'RestrictedCharacterStringType : VisibleString'
    t[0] = VisibleStringType ()


# 40 Definition of unrestricted character string types ------------------------

# 40.1
def p_UnrestrictedCharacterStringType (t):
    'UnrestrictedCharacterStringType : CHARACTER STRING'
    t[0] = UnrestrictedCharacterStringType ()


# 41 Notation for types defined in clauses 42 to 44 ---------------------------

# 42 Generalized time ---------------------------------------------------------

def p_UsefulType_1 (t):
  'UsefulType : GeneralizedTime'
  t[0] = GeneralizedTime()

# 43 Universal time -----------------------------------------------------------

def p_UsefulType_2 (t):
  'UsefulType : UTCTime'
  t[0] = UTCTime()

# 44 The object descriptor type -----------------------------------------------

def p_UsefulType_3 (t):
  'UsefulType : ObjectDescriptor'
  t[0] = ObjectDescriptor()


# 45 Constrained types --------------------------------------------------------

# 45.1
def p_ConstrainedType_1 (t):
    'ConstrainedType : Type Constraint'
    t[0] = t[1]
    t[0].AddConstraint(t[2])

def p_ConstrainedType_2 (t):
    'ConstrainedType : TypeWithConstraint'
    t[0] = t[1]

# 45.5
def p_TypeWithConstraint_1 (t):
    '''TypeWithConstraint : SET Constraint OF Type
                          | SET SizeConstraint OF Type'''
    t[0] = SetOfType (val = t[4], constr = t[2])

def p_TypeWithConstraint_2 (t):
    '''TypeWithConstraint : SEQUENCE Constraint OF Type
                          | SEQUENCE SizeConstraint OF Type'''
    t[0] = SequenceOfType (val = t[4], constr = t[2])

def p_TypeWithConstraint_3 (t):
    '''TypeWithConstraint : SET Constraint OF NamedType
                          | SET SizeConstraint OF NamedType'''
    t[0] = SetOfType (val = t[4], constr = t[2])

def p_TypeWithConstraint_4 (t):
    '''TypeWithConstraint : SEQUENCE Constraint OF NamedType
                          | SEQUENCE SizeConstraint OF NamedType'''
    t[0] = SequenceOfType (val = t[4], constr = t[2])

# 45.6
# 45.7
def p_Constraint (t):
    'Constraint : LPAREN ConstraintSpec ExceptionSpec RPAREN'
    t[0] = t[2]

def p_ConstraintSpec (t):
    '''ConstraintSpec : ElementSetSpecs
                      | GeneralConstraint'''
    t[0] = t[1]

# 46 Element set specification ------------------------------------------------

# 46.1
def p_ElementSetSpecs_1 (t):
    'ElementSetSpecs : RootElementSetSpec'
    t[0] = t[1]

def p_ElementSetSpecs_2 (t):
    'ElementSetSpecs : RootElementSetSpec COMMA ELLIPSIS'
    t[0] = t[1]
    t[0].ext = True

def p_ElementSetSpecs_3 (t):
    'ElementSetSpecs : RootElementSetSpec COMMA ELLIPSIS COMMA ElementSetSpecs'
    t[0] = t[1]
    t[0].ext = True

# skip compound constraints, only simple ones are supported

def p_RootElementSetSpec_1 (t):
    'RootElementSetSpec : SubtypeElements'
    t[0] = t[1]

def p_RootElementSetSpec_2 (t):
    'RootElementSetSpec : SubtypeElements IntersectionMark SubtypeElements'
    t[0] = Constraint(type = 'Intersection', subtype = [t[1], t[3]])

def p_IntersectionMark (t):
    '''IntersectionMark : CIRCUMFLEX
                        | INTERSECTION'''

# 47 Subtype elements ---------------------------------------------------------

# 47.1 General
def p_SubtypeElements (t):
    '''SubtypeElements : SingleValue
                       | ContainedSubtype
                       | ValueRange
                       | PermittedAlphabet
                       | SizeConstraint
                       | InnerTypeConstraints
                       | PatternConstraint'''
    t[0] = t[1]

# 47.2 Single value
# 47.2.1
def p_SingleValue (t):
    'SingleValue : Value'
    t[0] = Constraint(type = 'SingleValue', subtype = t[1]) 

# 47.3 Contained subtype
# 47.3.1
def p_ContainedSubtype (t):
    'ContainedSubtype : Includes Type'
    t[0] = Constraint(type = 'ContainedSubtype', subtype = t[2]) 

def p_Includes (t):
    '''Includes : INCLUDES 
                | '''

# 47.4 Value range
# 47.4.1
def p_ValueRange (t):
    'ValueRange : lower_end_point RANGE upper_end_point'
    t[0] = Constraint(type = 'ValueRange', subtype = [t[1], t[3]])

# 47.4.3
def p_lower_end_point_1 (t):
    'lower_end_point : lower_end_value '
    t[0] = t[1]

def p_lower_end_point_2 (t):
    'lower_end_point : lower_end_value LT' # XXX LT first?
    t[0] = t[1] # but not inclusive range
    
def p_upper_end_point_1 (t):
    'upper_end_point : upper_end_value'
    t[0] = t[1]

def p_upper_end_point_2 (t):
    'upper_end_point : LT upper_end_value'
    t[0] = t[1] # but not inclusive range

def p_lower_end_value (t):
    '''lower_end_value : Value
                       | MIN'''
    t[0] = t[1] # XXX

def p_upper_end_value (t):
    '''upper_end_value : Value
                       | MAX'''
    t[0] = t[1]

# 47.5 Size constraint
# 47.5.1
def p_SizeConstraint (t):
    'SizeConstraint : SIZE Constraint'
    t[0] = Constraint (type = 'Size', subtype = t[2])

# 47.6 Type constraint
# 47.6.1
#def p_TypeConstraint (t):
#    'TypeConstraint : Type'
#    t[0] = Constraint (type = 'Type', subtype = t[2])

# 47.7 Permitted alphabet
# 47.7.1
def p_PermittedAlphabet (t):
    'PermittedAlphabet : FROM Constraint'
    t[0] = Constraint (type = 'From', subtype = t[2])

# 47.8 Inner subtyping
# 47.8.1
def p_InnerTypeConstraints (t):
    '''InnerTypeConstraints : WITH COMPONENT SingleTypeConstraint
                            | WITH COMPONENTS MultipleTypeConstraints'''
    pass # ignore PER invisible constraint

# 47.8.3
def p_SingleTypeConstraint (t):
    'SingleTypeConstraint : Constraint'
    t[0] = t[1]

# 47.8.4
def p_MultipleTypeConstraints (t):
    '''MultipleTypeConstraints : FullSpecification
                               | PartialSpecification'''
    t[0] = t[1]

def p_FullSpecification (t):
    'FullSpecification : LBRACE TypeConstraints RBRACE'
    t[0] = t[2]

def p_PartialSpecification (t):
    'PartialSpecification : LBRACE ELLIPSIS COMMA TypeConstraints RBRACE'
    t[0] = t[4]

def p_TypeConstraints_1 (t):
    'TypeConstraints : named_constraint'
    t [0] = [t[1]]

def p_TypeConstraints_2 (t):
    'TypeConstraints : TypeConstraints COMMA named_constraint'
    t[0] = t[1] + [t[3]]

def p_named_constraint_1 (t):
    'named_constraint : identifier constraint'
    return Node ('named_constraint', ident = t[1], constr = t[2])

def p_named_constraint_2 (t):
    'named_constraint : constraint'
    return Node ('named_constraint', constr = t[1])

def p_constraint (t):
    'constraint : value_constraint presence_constraint'
    t[0] = Node ('constraint', value = t[1], presence = t[2])

def p_value_constraint_1 (t):
    'value_constraint : Constraint'
    t[0] = t[1]

def p_value_constraint_2 (t):
    'value_constraint : '
    pass

def p_presence_constraint_1 (t):
    '''presence_constraint : PRESENT
                 | ABSENT
                 | OPTIONAL'''
    t[0] = t[1]
    
def p_presence_constraint_2 (t):
    '''presence_constraint : '''
    pass

# 47.9 Pattern constraint
# 47.9.1
def p_PatternConstraint (t):
    'PatternConstraint : PATTERN Value'
    t[0] = Constraint (type = 'Pattern', subtype = t[2])

# 49 The exception identifier

# 49.4
def p_ExceptionSpec (t):
    'ExceptionSpec : '
    pass

#  /*-----------------------------------------------------------------------*/
#  /* Value Notation Productions */
#  /*-----------------------------------------------------------------------*/




def p_ext_val_ref (t):
    'ext_val_ref : type_ref DOT identifier'
    # XXX coerce type_ref to module_ref
    return Node ('ext_val_ref', module = t[1], ident = t[3])

def p_special_real_val (t):
    '''special_real_val : PLUS_INFINITY
    | MINUS_INFINITY'''
    t[0] = t[1]


# Note that Z39.50 v3 spec has upper-case here for, e.g., SUTRS.
# I've hacked the grammar to be liberal about what it accepts.
# XXX should have -strict command-line flag to only accept lowercase
# here, since that's what X.208 says.
def p_name_form (t):
    '''name_form : type_ref
    | identifier'''
    t[0] = t[1]

def p_name_and_number_form_1 (t):
    '''name_and_number_form : identifier LPAREN number_form RPAREN
    | type_ref LPAREN number_form RPAREN'''
    t[0] = Node ('name_and_number', ident = t[1], number = t[3])

def p_name_and_number_form_2 (t):
    'name_and_number_form : identifier LPAREN DefinedValue RPAREN'
    t[0] = Node ('name_and_number', ident = t[1], val = t[3])

# see X.208 if you are dubious about lcase only for identifier 
def p_identifier (t):
    'identifier : LCASE_IDENT'
    t[0] = t[1]


def p_binary_string (t):
    'binary_string : BSTRING'
    t[0] = t[1]

def p_hex_string (t):
    'hex_string : HSTRING'
    t[0] = t[1]

def p_char_string (t):
    'char_string : QSTRING'
    t[0] = t[1]

def p_number (t):
    'number : NUMBER'
    t[0] = t[1]


#--- ITU-T Recommendation X.682 -----------------------------------------------

# 8 General constraint specification ------------------------------------------

# 8.1
def p_GeneralConstraint (t):
    '''GeneralConstraint : UserDefinedConstraint'''
#                         | TableConstraint
#                         | ContentsConstraint''
    t[0] = t[1]

# 9 User-defined constraints --------------------------------------------------

# 9.1
def p_UserDefinedConstraint (t):
    'UserDefinedConstraint : CONSTRAINED BY LBRACE UserDefinedConstraintParameterList RBRACE'
    t[0] = Constraint(type = 'UserDefined', subtype = t[4]) 

def p_UserDefinedConstraintParameterList_1 (t):
  'UserDefinedConstraintParameterList : '
  t[0] = []

def p_UserDefinedConstraintParameterList_2 (t):
  'UserDefinedConstraintParameterList : UserDefinedConstraintParameter'
  t[0] = [t[1]]

def p_UserDefinedConstraintParameterList_3 (t):
  'UserDefinedConstraintParameterList : UserDefinedConstraintParameterList COMMA UserDefinedConstraintParameter'
  t[0] = t[1] + [t[3]]

# 9.3
def p_UserDefinedConstraintParameter (t):
  'UserDefinedConstraintParameter : type_ref'
  t[0] = t[1]


#--- ITU-T Recommendation X.683 -----------------------------------------------

# 8 Parameterized assignments -------------------------------------------------

# 8.1

# 8.2
def p_ParameterizedTypeAssignment (t):
  'ParameterizedTypeAssignment : UCASE_IDENT ParameterList ASSIGNMENT Type'
  t[0] = t[4]
  t[0].SetName(t[1] + 'xxx')

# 8.3
def p_ParameterList (t):
    'ParameterList : LBRACE Parameters RBRACE'
    t[0] = t[2]

def p_Parameters_1 (t):
  'Parameters : Parameter'
  t[0] = [t[1]]

def p_Parameters_2 (t):
  'Parameters : Parameters COMMA Parameter'
  t[0] = t[1] + [t[3]]

def p_Parameter_1 (t):
  'Parameter : Type COLON Reference'
  t[0] = [t[1], t[3]]

def p_Parameter_2 (t):
  'Parameter : Reference'
  t[0] = t[1]


# 9 Referencing parameterized definitions -------------------------------------

# 9.1
def p_ParameterizedReference (t):
  'ParameterizedReference : type_ref LBRACE RBRACE'
  t[0] = t[1]
  t[0].val += 'xxx'

# 9.2
def p_ParameterizedType (t):
  'ParameterizedType : type_ref ActualParameterList'
  t[0] = t[1]
  t[0].val += 'xxx'

# 9.5
def p_ActualParameterList (t):
    'ActualParameterList : LBRACE ActualParameters RBRACE'
    t[0] = t[2]

def p_ActualParameters_1 (t):
  'ActualParameters : ActualParameter'
  t[0] = [t[1]]

def p_ActualParameters_2 (t):
  'ActualParameters : ActualParameters COMMA ActualParameter'
  t[0] = t[1] + [t[3]]

def p_ActualParameter (t):
  '''ActualParameter : Type
                     | Value'''
  t[0] = t[1]


def p_error(t):
    raise ParseError(str(t))

def testlex (s):
    lexer.input (s)
    while 1:
        token = lexer.token ()
        if not token:
            break
        print token


def do_module (ast, defined_dict):
    assert (ast.type == 'Module')
    ctx = Ctx (defined_dict)
    print ast.to_python (ctx)
    print ctx.output_assignments ()
    print ctx.output_pyquotes ()

def eth_do_module (ast, ectx):
    assert (ast.type == 'Module')
    if ectx.dbg('s'): print ast.str_depth(0)
    ast.to_eth(ectx)

def testyacc(s, fn, defined_dict):
    ast = yacc.parse(s, debug=0)
    time_str = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    print """#!/usr/bin/env python
# Auto-generated from %s at %s
from PyZ3950 import asn1""" % (fn, time_str)
    for module in ast:
      eth_do_module (module, defined_dict)


# Ethereal compiler
def eth_usage():
  print """
asn2eth [-h|?] [-d dbg] [-b] [-p proto] [-c conform_file] [-e] input_file(s) ...
  -h|?       : usage
  -b         : BER (default is PER)
  -u         : unaligned (default is aligned)
  -p proto   : protocol name (implies -S)
               default is module-name from input_file (renamed by #.MODULE if present)
  -o name    : output files name core (default is <proto>)
  -O dir     : output directory
  -c conform_file : conformation file
  -e         : create conformation file for exported types
  -S         : single output for multiple modules
  -s template : single file output (template is input file without .c/.h extension)
  -k         : keep intermediate files though single file output is used
  input_file : input ASN.1 file

  -d dbg     : debug output, dbg = [l][y][p][s][a][t][c][o]
               l - lex 
               y - yacc
               p - parsing
               s - internal ASN.1 structure
               a - list of assignments
               t - tables
               c - conformance values
               o - list of output files
"""

def eth_main():
  print "ASN.1 to Ethereal dissector compiler";
  try:
    opts, args = getopt.getopt(sys.argv[1:], "h?d:buXp:o:O:c:eSs:k");
  except getopt.GetoptError:
    eth_usage(); sys.exit(2)
  if len(args) < 1:
    eth_usage(); sys.exit(2)

  conform = EthCnf()
  output = EthOut()
  ectx = EthCtx(conform, output)
  ectx.encoding = 'per'
  ectx.proto_opt = None
  ectx.outnm_opt = None
  ectx.aligned = True
  ectx.dbgopt = ''
  ectx.new = True
  ectx.expcnf = False
  ectx.merge_modules = False
  ectx.output.outnm = None
  ectx.output.single_file = None
  for o, a in opts:
    if o in ("-h", "-?"):
      eth_usage(); sys.exit(2)
    if o in ("-b",):
      ectx.encoding = 'ber'
    if o in ("-p",):
      ectx.proto_opt = a
      ectx.merge_modules = True
    if o in ("-c",):
      ectx.conform.read(a)
    if o in ("-u",):
      ectx.aligned = False
    if o in ("-d",):
      ectx.dbgopt = a
    if o in ("-e",):
      ectx.expcnf = True
    if o in ("-S",):
      ectx.merge_modules = True
    if o in ("-o",):
      ectx.outnm_opt = a
    if o in ("-O",):
      ectx.output.outdir = a
    if o in ("-s",):
      ectx.output.single_file = a
    if o in ("-k",):
      ectx.output.keep = True
    if o in ("-X",):
        warnings.warn("Command line option -X is obsolete and can be removed")

  (ld, yd, pd) = (0, 0, 0); 
  if ectx.dbg('l'): ld = 1
  if ectx.dbg('y'): yd = 1
  if ectx.dbg('p'): pd = 2
  lexer = lex.lex(debug=ld)
  yacc.yacc(method='SLR', debug=yd)
  ast = []
  for fn in args:
    f = open (fn, "r")
    ast.extend(yacc.parse(f.read(), lexer=lexer, debug=pd))
    f.close ()
  ectx.eth_clean()
  for module in ast:
    eth_do_module(module, ectx)
    if (not ectx.merge_modules):  # output for each module
      ectx.eth_prepare()
      ectx.eth_do_output()
      ectx.eth_clean()
  if (ectx.merge_modules):  # common output for all module
    ectx.eth_prepare()
    ectx.eth_do_output()

  if ectx.dbg('c'):
    ectx.conform.dbg_print()
  ectx.conform.unused_report()

  if ectx.dbg('o'):
    ectx.output.dbg_print()
  ectx.output.make_single_file()
    

# Python compiler
def main():
    testfn = testyacc
    if len (sys.argv) == 1:
        while 1:
            s = raw_input ('Query: ')
            if len (s) == 0:
                break
            testfn (s, 'console', {})
    else:
        defined_dict = {}
        for fn in sys.argv [1:]:
            f = open (fn, "r")
            testfn (f.read (), fn, defined_dict)
            f.close ()
            lexer.lineno = 1
  

#--- BODY ---------------------------------------------------------------------

if __name__ == '__main__':
  if ('asn2eth' == os.path.splitext(os.path.basename(sys.argv[0]))[0].lower()):
    eth_main()
  else:
    main()

#------------------------------------------------------------------------------
