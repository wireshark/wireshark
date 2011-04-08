#!/usr/bin/env python

#
# asn2wrs.py
# ASN.1 to Wireshark dissector compiler
# 2004 Tomas Kukosa
#
# $Id$
#

"""ASN.1 to Wireshark dissector compiler"""

#
# Compiler from ASN.1 specification to the Wireshark dissector
#
# Based on ASN.1 to Python compiler from Aaron S. Lav's PyZ3950 package licensed under the X Consortium license
# http://www.pobox.com/~asl2/software/PyZ3950/
# (ASN.1 to Python compiler functionality is broken but not removed, it could be revived if necessary)
#
# It requires Dave Beazley's PLY parsing package licensed under the LGPL (tested with version 2.3)
# http://www.dabeaz.com/ply/
#
#
# ITU-T Recommendation X.680 (07/2002),
#   Information technology - Abstract Syntax Notation One (ASN.1): Specification of basic notation
#
# ITU-T Recommendation X.681 (07/2002),
#   Information technology - Abstract Syntax Notation One (ASN.1): Information object specification
#
# ITU-T Recommendation X.682 (07/2002),
#   Information technology - Abstract Syntax Notation One (ASN.1): Constraint specification
#
# ITU-T Recommendation X.683 (07/2002),
#   Information technology - Abstract Syntax Notation One (ASN.1): Parameterization of ASN.1 specifications
#
# ITU-T Recommendation X.880 (07/1994),
#   Information technology - Remote Operations: Concepts, model and notation
#

import warnings

import re
import sys
import os
import os.path
import time
import getopt
import traceback

import lex
import yacc

from string import maketrans

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
  return id.replace('-', '_').replace('.', '_').replace('&', '_')

input_file = None
g_conform = None
lexer = None
in_oid = False

class LexError(Exception):
  def __init__(self, tok, filename=None):
    self.tok = tok
    self.filename = filename
    self.msg =  "Unexpected character %r" % (self.tok.value[0])
    Exception.__init__(self, self.msg)
  def __repr__(self):
    return "%s:%d: %s" % (self.filename, self.tok.lineno, self.msg)
  __str__ = __repr__


class ParseError(Exception):
  def __init__(self, tok, filename=None):
    self.tok = tok
    self.filename = filename
    self.msg =  "Unexpected token %s(%r)" % (self.tok.type, self.tok.value)
    Exception.__init__(self, self.msg)
  def __repr__(self):
    return "%s:%d: %s" % (self.filename, self.tok.lineno, self.msg)
  __str__ = __repr__


class DuplicateError(Exception):
  def __init__(self, type, ident):
    self.type = type
    self.ident = ident
    self.msg =  "Duplicate %s for %s" % (self.type, self.ident)
    Exception.__init__(self, self.msg)
  def __repr__(self):
    return self.msg
  __str__ = __repr__

class CompError(Exception):
  def __init__(self, msg):
    self.msg =  msg
    Exception.__init__(self, self.msg)
  def __repr__(self):
    return self.msg
  __str__ = __repr__


states = (
  ('braceignore','exclusive'),
)

precedence = (
  ('left', 'UNION', 'BAR'),
  ('left', 'INTERSECTION', 'CIRCUMFLEX'),
)
# 11 ASN.1 lexical items

static_tokens = {
  r'::='    : 'ASSIGNMENT',  # 11.16 Assignment lexical item
  r'\.\.'   : 'RANGE',       # 11.17 Range separator
  r'\.\.\.' : 'ELLIPSIS',    # 11.18 Ellipsis
  r'\[\['   : 'LVERBRACK',   # 11.19 Left version brackets
  r'\]\]'   : 'RVERBRACK',   # 11.20 Right version brackets
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
  r'@'  : 'AT',
  r'\!' : 'EXCLAMATION',
  r'\^' : 'CIRCUMFLEX',
  r'\&' : 'AMPERSAND',
  r'\|' : 'BAR'
}

# 11.27 Reserved words

# all keys in reserved_words must start w/ upper case
reserved_words = {
  'ABSENT'      : 'ABSENT',
  'ABSTRACT-SYNTAX' : 'ABSTRACT_SYNTAX',
  'ALL'         : 'ALL',
  'APPLICATION' : 'APPLICATION',
  'AUTOMATIC'   : 'AUTOMATIC',
  'BEGIN'       : 'BEGIN',
  'BIT'         : 'BIT',
  'BOOLEAN'     : 'BOOLEAN',
  'BY'          : 'BY',
  'CHARACTER'   : 'CHARACTER',
  'CHOICE'      : 'CHOICE',
  'CLASS'       : 'CLASS',
  'COMPONENT'   : 'COMPONENT',
  'COMPONENTS'  : 'COMPONENTS',
  'CONSTRAINED' : 'CONSTRAINED',
  'CONTAINING'  : 'CONTAINING',
  'DEFAULT'     : 'DEFAULT',
  'DEFINITIONS' : 'DEFINITIONS',
  'EMBEDDED'    : 'EMBEDDED',
#  'ENCODED'     : 'ENCODED',
  'END'         : 'END',
  'ENUMERATED'  : 'ENUMERATED',
#  'EXCEPT'      : 'EXCEPT',
  'EXPLICIT'    : 'EXPLICIT',
  'EXPORTS'     : 'EXPORTS',
#  'EXTENSIBILITY' : 'EXTENSIBILITY',
  'EXTERNAL'    : 'EXTERNAL',
  'FALSE'       : 'FALSE',
  'FROM'        : 'FROM',
  'GeneralizedTime' : 'GeneralizedTime',
  'IDENTIFIER'  : 'IDENTIFIER',
  'IMPLICIT'    : 'IMPLICIT',
#  'IMPLIED'     : 'IMPLIED',
  'IMPORTS'     : 'IMPORTS',
  'INCLUDES'    : 'INCLUDES',
  'INSTANCE'    : 'INSTANCE',
  'INTEGER'     : 'INTEGER',
  'INTERSECTION' : 'INTERSECTION',
  'MAX'         : 'MAX',
  'MIN'         : 'MIN',
  'MINUS-INFINITY' : 'MINUS_INFINITY',
  'NULL'        : 'NULL',
  'OBJECT'      : 'OBJECT',
  'ObjectDescriptor' : 'ObjectDescriptor',
  'OCTET'       : 'OCTET',
  'OF'          : 'OF',
  'OPTIONAL'    : 'OPTIONAL',
  'PATTERN'     : 'PATTERN',
  'PDV'         : 'PDV',
  'PLUS-INFINITY' : 'PLUS_INFINITY',
  'PRESENT'     : 'PRESENT',
  'PRIVATE'     : 'PRIVATE',
  'REAL'        : 'REAL',
  'RELATIVE-OID' : 'RELATIVE_OID',
  'SEQUENCE'    : 'SEQUENCE',
  'SET'         : 'SET',
  'SIZE'        : 'SIZE',
  'STRING'      : 'STRING',
  'SYNTAX'      : 'SYNTAX',
  'TAGS'        : 'TAGS',
  'TRUE'        : 'TRUE',
  'TYPE-IDENTIFIER' : 'TYPE_IDENTIFIER',
  'UNION'       : 'UNION',
  'UNIQUE'      : 'UNIQUE',
  'UNIVERSAL'   : 'UNIVERSAL',
  'UTCTime'     : 'UTCTime',
  'WITH'        : 'WITH',
# X.208 obsolete but still used
  'ANY'         : 'ANY',
  'DEFINED'     : 'DEFINED',
}

for k in list(static_tokens.keys()):
  if static_tokens [k] == None:
    static_tokens [k] = k

StringTypes = ['Numeric', 'Printable', 'IA5', 'BMP', 'Universal', 'UTF8',
               'Teletex', 'T61', 'Videotex', 'Graphic', 'ISO646', 'Visible',
               'General']

for s in StringTypes:
  reserved_words[s + 'String'] = s + 'String'

tokens = list(static_tokens.values()) \
         + list(reserved_words.values()) \
         + ['BSTRING', 'HSTRING', 'QSTRING',
            'UCASE_IDENT', 'LCASE_IDENT', 'LCASE_IDENT_ASSIGNED', 'CLASS_IDENT',
            'REAL_NUMBER', 'NUMBER', 'PYQUOTE']


cur_mod = __import__ (__name__) # XXX blech!

for (k, v) in list(static_tokens.items ()):
    cur_mod.__dict__['t_' + v] = k

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
    return t

def t_UCASE_IDENT (t):
    r"[A-Z](-[a-zA-Z0-9]|[a-zA-Z0-9])*" # can't end w/ '-'
    if (is_class_ident(t.value)): t.type = 'CLASS_IDENT'
    if (is_class_syntax(t.value)): t.type = t.value
    t.type = reserved_words.get(t.value, t.type)
    return t

lcase_ident_assigned = {}
def t_LCASE_IDENT (t):
    r"[a-z](-[a-zA-Z0-9]|[a-zA-Z0-9])*" # can't end w/ '-'
    if (not in_oid and (t.value in lcase_ident_assigned)): t.type = 'LCASE_IDENT_ASSIGNED'
    return t

# 11.9 Real numbers
def t_REAL_NUMBER (t):
    r"[0-9]+\.[0-9]*(?!\.)"
    return t

# 11.8 Numbers
def t_NUMBER (t):
    r"0|([1-9][0-9]*)"
    return t

# 11.6 Comments
pyquote_str = 'PYQUOTE'
def t_COMMENT(t):
    r"--(-[^\-\n]|[^\-\n])*(--|\n|-\n|$|-$)"
    if (t.value.find("\n") >= 0) : t.lexer.lineno += 1
    if t.value[2:2+len (pyquote_str)] == pyquote_str:
        t.value = t.value[2+len(pyquote_str):]
        t.value = t.value.lstrip ()
        t.type = pyquote_str
        return t
    return None

t_ignore = " \t\r"

def t_NEWLINE(t):
    r'\n+'
    t.lexer.lineno += t.value.count("\n")

def t_error(t):
  global input_file
  raise LexError(t, input_file)

# state 'braceignore'

def t_braceignore_lbrace(t):
  r'\{'
  t.lexer.level +=1

def t_braceignore_rbrace(t):
  r'\}'
  t.lexer.level -=1
  # If closing brace, return token
  if t.lexer.level == 0:
    t.type = 'RBRACE'
    return t

def t_braceignore_QSTRING (t):
  r'"([^"]|"")*"'
  t.lexer.lineno += t.value.count("\n")

def t_braceignore_COMMENT(t):
  r"--(-[^\-\n]|[^\-\n])*(--|\n|-\n|$|-$)"
  if (t.value.find("\n") >= 0) : t.lexer.lineno += 1

def t_braceignore_nonspace(t):
   r'[^\s\{\}\"-]+|-(?!-)'

t_braceignore_ignore = " \t\r"

def t_braceignore_NEWLINE(t):
  r'\n+'
  t.lexer.lineno += t.value.count("\n")

def t_braceignore_error(t):
  t.lexer.skip(1)

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
        if ident in self.assignments:
            raise DuplicateError("assignment", ident)
        if ident in self.defined_dict:
            raise Exception("cross-module duplicates for %s" % ident)
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
        assign_keys = list(self.assignments.keys())
        to_output_count = len (assign_keys)
        while True:
            any_output = 0
            for (ident, val) in list(self.assignments.items ()):
                if ident in already_output:
                    continue
                ok = 1
                for d in self.dependencies [ident]:
                    if ((d not in already_output) and
                        (d in assign_keys)):
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
                for ident in list(self.assignments.keys ()):
                    if ident not in already_output:
                        depend_list = [d for d in self.dependencies[ident] if d in assign_keys]
                        cycle_list.append ("%s(%s)" % (ident, ",".join (depend_list)))

                text_list.append ("# Cycle XXX " + ",".join (cycle_list))
                for (ident, val) in list(self.assignments.items ()):
                    if ident not in already_output:
                        text_list.append ("%s=%s" % (ident, self.assignments [ident]))
                break

        return "\n".join (text_list)
    def output_pyquotes (self):
        return "\n".join (self.pyquotes)
    def make_new_name (self):
        self.name_ctr += 1
        return "_compiler_generated_name_%d" % (self.name_ctr,)

#--- Flags for EXPORT, USER_DEFINED, NO_EMIT, MAKE_ENUM -------------------------------
EF_TYPE    = 0x0001
EF_VALS    = 0x0002
EF_ENUM    = 0x0004
EF_WS_VAR  = 0x0010
EF_EXTERN  = 0x0020
EF_NO_PROT = 0x0040
EF_NO_TYPE = 0x0080
EF_UCASE   = 0x0100
EF_TABLE   = 0x0400
EF_DEFINE  = 0x0800
EF_MODULE  = 0x1000

#--- common dependency computation ---
# Input  : list of items
#          dictionary with lists of dependency
#
#
# Output : list of two outputs:
#          [0] list of items in dependency
#          [1] list of cycle dependency cycles
def dependency_compute(items, dependency, map_fn = lambda t: t, ignore_fn = lambda t: False):
  item_ord = []
  item_cyc = []
  x = {}  # already emitted
  #print '# Dependency computation'
  for t in items:
    if map_fn(t) in x:
      #print 'Continue: %s : %s' % (t, (map_fn(t))
      continue
    stack = [t]
    stackx = {t : dependency.get(t, [])[:]}
    #print 'Push: %s : %s' % (t, str(stackx[t]))
    while stack:
      if stackx[stack[-1]]:  # has dependencies
        d = stackx[stack[-1]].pop(0)
        if map_fn(d) in x or ignore_fn(d):
          continue
        if d in stackx:  # cyclic dependency
          c = stack[:]
          c.reverse()
          c = [d] + c[0:c.index(d)+1]
          c.reverse()
          item_cyc.append(c)
          #print 'Cyclic: %s ' % (' -> '.join(c))
          continue
        stack.append(d)
        stackx[d] = dependency.get(d, [])[:]
        #print 'Push: %s : %s' % (d, str(stackx[d]))
      else:
        #print 'Pop: %s' % (stack[-1])
        del stackx[stack[-1]]
        e = map_fn(stack.pop())
        if e in x:
          continue
        #print 'Add: %s' % (e)
        item_ord.append(e)
        x[e] = True
  return (item_ord, item_cyc)

# Given a filename, return a relative path from epan/dissectors
def rel_dissector_path(filename):
  path_parts = os.path.abspath(filename).split(os.sep)
  while (len(path_parts) > 3 and path_parts[0] != 'asn1'):
    path_parts.pop(0)
  path_parts.insert(0, '..')
  path_parts.insert(0, '..')
  return '/'.join(path_parts)  
  

#--- EthCtx -------------------------------------------------------------------
class EthCtx:
  def __init__(self, conform, output, indent = 0):
    self.conform = conform
    self.output = output
    self.conform.ectx = self
    self.output.ectx = self
    self.encoding = 'per'
    self.aligned = False
    self.default_oid_variant = ''
    self.default_opentype_variant = ''
    self.default_containing_variant = '_pdu_new'
    self.default_embedded_pdv_cb = None
    self.default_external_type_cb = None
    self.remove_prefix = None
    self.srcdir = None
    self.emitted_pdu = {}
    self.module = {}
    self.module_ord = []
    self.all_type_attr = {}
    self.all_tags = {}
    self.all_vals = {}

  def encp(self):  # encoding protocol
    encp = self.encoding
    return encp

  # Encoding
  def Per(self): return self.encoding == 'per'
  def Ber(self): return self.encoding == 'ber'
  def Aligned(self): return self.aligned
  def Unaligned(self): return not self.aligned
  def NeedTags(self): return self.tag_opt or self.Ber()
  def NAPI(self): return False  # disable planned features

  def Module(self):  # current module name
    return self.modules[-1][0]

  def groups(self):
    return self.group_by_prot or (self.conform.last_group > 0)

  def dbg(self, d):
    if (self.dbgopt.find(d) >= 0):
      return True
    else:
      return False

  def value_max(self, a, b):
    if (a == 'MAX') or (b == 'MAX'): return 'MAX';
    if a == 'MIN': return b;
    if b == 'MIN': return a;
    try:
      if (int(a) > int(b)):
        return a
      else:
        return b
    except (ValueError, TypeError):
      pass
    return "MAX((%s),(%s))" % (a, b)

  def value_min(self, a, b):
    if (a == 'MIN') or (b == 'MIN'): return 'MIN';
    if a == 'MAX': return b;
    if b == 'MAX': return a;
    try:
      if (int(a) < int(b)):
        return a
      else:
        return b
    except (ValueError, TypeError):
      pass
    return "MIN((%s),(%s))" % (a, b)

  def value_get_eth(self, val):
    if isinstance(val, Value):
      return val.to_str(self)
    ethname = val
    if val in self.value:
      ethname = self.value[val]['ethname']
    return ethname

  def value_get_val(self, nm):
    val = asn2c(nm)
    if nm in self.value:
      if self.value[nm]['import']:
        v = self.get_val_from_all(nm, self.value[nm]['import'])
        if v is None:
          msg = 'Need value of imported value identifier %s from %s (%s)' % (nm, self.value[nm]['import'], self.value[nm]['proto'])
          warnings.warn_explicit(msg, UserWarning, '', 0)
        else:
          val = v
      else:
        val = self.value[nm]['value']
        if isinstance (val, Value):
          val = val.to_str(self)
    else:
      msg = 'Need value of unknown value identifier %s' % (nm)
      warnings.warn_explicit(msg, UserWarning, '', 0)
    return val

  def eth_get_type_attr(self, type):
    #print "eth_get_type_attr(%s)" % (type)
    types = [type]
    while (not self.type[type]['import']):
      val =  self.type[type]['val']
      #print val
      ttype = type
      while (val.type == 'TaggedType'):
        val = val.val
        ttype += '/_untag'
      if (val.type != 'Type_Ref'):
        if (type != ttype):
          types.append(ttype)
        break
      type = val.val
      types.append(type)
    attr = {}
    #print " ", types
    while len(types):
      t = types.pop()
      if (self.type[t]['import']):
        attr.update(self.type[t]['attr'])
        attr.update(self.eth_get_type_attr_from_all(t, self.type[t]['import']))
      elif (self.type[t]['val'].type == 'SelectionType'):
        val = self.type[t]['val']
        (ftype, display) = val.eth_ftype(self)
        attr.update({ 'TYPE' : ftype, 'DISPLAY' : display,
                      'STRINGS' : val.eth_strings(), 'BITMASK' : '0' });
      else:
        attr.update(self.type[t]['attr'])
        attr.update(self.eth_type[self.type[t]['ethname']]['attr'])
    #print " ", attr
    return attr

  def eth_get_type_attr_from_all(self, type, module):
    attr = {}
    if module in self.all_type_attr and type in self.all_type_attr[module]:
      attr = self.all_type_attr[module][type]
    return attr

  def get_ttag_from_all(self, type, module):
    ttag = None
    if module in self.all_tags and type in self.all_tags[module]:
      ttag = self.all_tags[module][type]
    return ttag

  def get_val_from_all(self, nm, module):
    val = None
    if module in self.all_vals and nm in self.all_vals[module]:
      val = self.all_vals[module][nm]
    return val

  def get_obj_repr(self, ident, restr):
    def set_type_fn(cls, field, fnfield):
      obj[fnfield + '_fn'] = 'NULL'
      obj[fnfield + '_pdu'] = 'NULL'
      if field in val and isinstance(val[field], Type_Ref):
        p = val[field].eth_type_default_pars(self, '')
        obj[fnfield + '_fn'] = p['TYPE_REF_FN']
        obj[fnfield + '_fn'] = obj[fnfield + '_fn'] % p  # one iteration
        if (self.conform.check_item('PDU', cls + '.' + field)):
          obj[fnfield + '_pdu'] = 'dissect_' + self.field[val[field].val]['ethname']
      return
    # end of get_type_fn()
    obj = { '_name' : ident, '_ident' : asn2c(ident)}
    obj['_class'] = self.oassign[ident].cls
    obj['_module'] = self.oassign[ident].module
    val = self.oassign[ident].val
    fld = None
    fld_neg = False
    if len(restr) > 0:
      fld = restr[0]
      if fld[0] == '!':
        fld_neg = True
        fld = fld[1:]
    if fld:
      if fld_neg:
        if fld in val:
          return None
      else:
        if fld not in val:
          return None
    for f in list(val.keys()):
      if isinstance(val[f], Node):
        obj[f] = val[f].fld_obj_repr(self)
      else:
        obj[f] = str(val[f])
    if (obj['_class'] == 'TYPE-IDENTIFIER') or (obj['_class'] == 'ABSTRACT-SYNTAX'):
      set_type_fn(obj['_class'], '&Type', '_type')
    if (obj['_class'] == 'OPERATION'):
      set_type_fn(obj['_class'], '&ArgumentType', '_argument')
      set_type_fn(obj['_class'], '&ResultType', '_result')
    if (obj['_class'] == 'ERROR'):
      set_type_fn(obj['_class'], '&ParameterType', '_parameter')
    return obj

  #--- eth_reg_module -----------------------------------------------------------
  def eth_reg_module(self, module):
    #print "eth_reg_module(module='%s')" % (module)
    name = module.get_name()
    self.modules.append([name, module.get_proto(self)])
    if name in self.module:
      raise DuplicateError("module", name)
    self.module[name] = []
    self.module_ord.append(name)

  #--- eth_module_dep_add ------------------------------------------------------------
  def eth_module_dep_add(self, module, dep):
    self.module[module].append(dep)

  #--- eth_exports ------------------------------------------------------------
  def eth_exports(self, exports):
    self.exports_all = False
    if ((len(exports) == 1) and (exports[0] == 'ALL')):
      self.exports_all = True
      return
    for e in (exports):
      if isinstance(e, Type_Ref):
        self.exports.append(e.val)
      elif isinstance(e, Class_Ref):
        self.cexports.append(e.val)
      else:
        self.vexports.append(e)

  #--- eth_reg_assign ---------------------------------------------------------
  def eth_reg_assign(self, ident, val, virt=False):
    #print "eth_reg_assign(ident='%s')" % (ident)
    if ident in self.assign:
      raise DuplicateError("assignment", ident)
    self.assign[ident] = { 'val' : val , 'virt' : virt }
    self.assign_ord.append(ident)
    if  (self.exports_all):
      self.exports.append(ident)

  #--- eth_reg_vassign --------------------------------------------------------
  def eth_reg_vassign(self, vassign):
    ident = vassign.ident
    #print "eth_reg_vassign(ident='%s')" % (ident)
    if ident in self.vassign:
      raise DuplicateError("value assignment", ident)
    self.vassign[ident] = vassign
    self.vassign_ord.append(ident)
    if  (self.exports_all):
      self.vexports.append(ident)

  #--- eth_reg_oassign --------------------------------------------------------
  def eth_reg_oassign(self, oassign):
    ident = oassign.ident
    #print "eth_reg_oassign(ident='%s')" % (ident)
    if ident in self.oassign:
      if self.oassign[ident] == oassign:
        return  # OK - already defined
      else:
        raise DuplicateError("information object assignment", ident)
    self.oassign[ident] = oassign
    self.oassign_ord.append(ident)
    self.oassign_cls.setdefault(oassign.cls, []).append(ident)

  #--- eth_import_type --------------------------------------------------------
  def eth_import_type(self, ident, mod, proto):
    #print "eth_import_type(ident='%s', mod='%s', prot='%s')" % (ident, mod, proto)
    if ident in self.type:
      #print "already defined '%s' import=%s, module=%s" % (ident, str(self.type[ident]['import']), self.type[ident].get('module', '-'))
      if not self.type[ident]['import'] and (self.type[ident]['module'] == mod) :
        return  # OK - already defined
      elif self.type[ident]['import'] and (self.type[ident]['import'] == mod) :
        return  # OK - already imported
      else:
        raise DuplicateError("type", ident)
    self.type[ident] = {'import'  : mod, 'proto' : proto,
                        'ethname' : '' }
    self.type[ident]['attr'] = { 'TYPE' : 'FT_NONE', 'DISPLAY' : 'BASE_NONE',
                                 'STRINGS' : 'NULL', 'BITMASK' : '0' }
    mident = "$%s$%s" % (mod, ident)
    if (self.conform.check_item('TYPE_ATTR', mident)):
      self.type[ident]['attr'].update(self.conform.use_item('TYPE_ATTR', mident))
    else:
      self.type[ident]['attr'].update(self.conform.use_item('TYPE_ATTR', ident))
    if (self.conform.check_item('IMPORT_TAG', mident)):
      self.conform.copy_item('IMPORT_TAG', ident, mident)
    self.type_imp.append(ident)

  #--- dummy_import_type --------------------------------------------------------
  def dummy_import_type(self, ident):
    # dummy imported
    if ident in self.type:
        raise Exception("Try to dummy import for existing type :%s" % ident)
    ethtype = asn2c(ident)
    self.type[ident] = {'import'  : 'xxx', 'proto' : 'xxx',
                        'ethname' : ethtype }
    self.type[ident]['attr'] = { 'TYPE' : 'FT_NONE', 'DISPLAY' : 'BASE_NONE',
                                 'STRINGS' : 'NULL', 'BITMASK' : '0' }
    self.eth_type[ethtype] = { 'import' : 'xxx', 'proto' : 'xxx' , 'attr' : {}, 'ref' : []}
    print "Dummy imported: %s (%s)" % (ident, ethtype)
    return ethtype

  #--- eth_import_class --------------------------------------------------------
  def eth_import_class(self, ident, mod, proto):
    #print "eth_import_class(ident='%s', mod='%s', prot='%s')" % (ident, mod, proto)
    if ident in self.objectclass:
      #print "already defined import=%s, module=%s" % (str(self.objectclass[ident]['import']), self.objectclass[ident]['module'])
      if not self.objectclass[ident]['import'] and (self.objectclass[ident]['module'] == mod) :
        return  # OK - already defined
      elif self.objectclass[ident]['import'] and (self.objectclass[ident]['import'] == mod) :
        return  # OK - already imported
      else:
        raise DuplicateError("object class", ident)
    self.objectclass[ident] = {'import'  : mod, 'proto' : proto,
                        'ethname' : '' }
    self.objectclass_imp.append(ident)

  #--- eth_import_value -------------------------------------------------------
  def eth_import_value(self, ident, mod, proto):
    #print "eth_import_value(ident='%s', mod='%s', prot='%s')" % (ident, mod, prot)
    if ident in self.value:
      #print "already defined import=%s, module=%s" % (str(self.value[ident]['import']), self.value[ident]['module'])
      if not self.value[ident]['import'] and (self.value[ident]['module'] == mod) :
        return  # OK - already defined
      elif self.value[ident]['import'] and (self.value[ident]['import'] == mod) :
        return  # OK - already imported
      else:
        raise DuplicateError("value", ident)
    self.value[ident] = {'import'  : mod, 'proto' : proto,
                         'ethname' : ''}
    self.value_imp.append(ident)

  #--- eth_sel_req ------------------------------------------------------------
  def eth_sel_req(self, typ, sel):
    key = typ + '.' + sel
    if key not in self.sel_req:
      self.sel_req[key] = { 'typ' : typ , 'sel' : sel}
      self.sel_req_ord.append(key)
    return key

  #--- eth_comp_req ------------------------------------------------------------
  def eth_comp_req(self, type):
    self.comp_req_ord.append(type)

  #--- eth_dep_add ------------------------------------------------------------
  def eth_dep_add(self, type, dep):
    if type not in self.type_dep:
      self.type_dep[type] = []
    self.type_dep[type].append(dep)

  #--- eth_reg_type -----------------------------------------------------------
  def eth_reg_type(self, ident, val):
    #print "eth_reg_type(ident='%s', type='%s')" % (ident, val.type)
    if ident in self.type:
      if self.type[ident]['import'] and (self.type[ident]['import'] == self.Module()) :
        # replace imported type
        del self.type[ident]
        self.type_imp.remove(ident)
      else:
        raise DuplicateError("type", ident)
    self.type[ident] = { 'val' : val, 'import' : None }
    self.type[ident]['module'] = self.Module()
    self.type[ident]['proto'] = self.proto
    if len(ident.split('/')) > 1:
      self.type[ident]['tname'] = val.eth_tname()
    else:
      self.type[ident]['tname'] = asn2c(ident)
    self.type[ident]['export'] = self.conform.use_item('EXPORTS', ident)
    self.type[ident]['enum'] = self.conform.use_item('MAKE_ENUM', ident)
    self.type[ident]['vals_ext'] = self.conform.use_item('USE_VALS_EXT', ident)
    self.type[ident]['user_def'] = self.conform.use_item('USER_DEFINED', ident)
    self.type[ident]['no_emit'] = self.conform.use_item('NO_EMIT', ident)
    self.type[ident]['tname'] = self.conform.use_item('TYPE_RENAME', ident, val_dflt=self.type[ident]['tname'])
    self.type[ident]['ethname'] = ''
    if (val.type == 'Type_Ref') or (val.type == 'TaggedType') or (val.type == 'SelectionType') :
      self.type[ident]['attr'] = {}
    else:
      (ftype, display) = val.eth_ftype(self)
      self.type[ident]['attr'] = { 'TYPE' : ftype, 'DISPLAY' : display,
                                   'STRINGS' : val.eth_strings(), 'BITMASK' : '0' }
    self.type[ident]['attr'].update(self.conform.use_item('TYPE_ATTR', ident))
    self.type_ord.append(ident)
    # PDU
    if (self.conform.check_item('PDU', ident)):
      self.eth_reg_field(ident, ident, impl=val.HasImplicitTag(self), pdu=self.conform.use_item('PDU', ident))

  #--- eth_reg_objectclass ----------------------------------------------------------
  def eth_reg_objectclass(self, ident, val):
    #print "eth_reg_objectclass(ident='%s')" % (ident)
    if ident in self.objectclass:
      if self.objectclass[ident]['import'] and (self.objectclass[ident]['import'] == self.Module()) :
        # replace imported object class
        del self.objectclass[ident]
        self.objectclass_imp.remove(ident)
      elif isinstance(self.objectclass[ident]['val'], Class_Ref) and \
           isinstance(val, Class_Ref) and \
           (self.objectclass[ident]['val'].val == val.val):
        pass  # ignore duplicated CLASS1 ::= CLASS2
      else:
        raise DuplicateError("object class", ident)
    self.objectclass[ident] = { 'import' : None, 'module' : self.Module(), 'proto' : self.proto }
    self.objectclass[ident]['val'] = val
    self.objectclass[ident]['export'] = self.conform.use_item('EXPORTS', ident)
    self.objectclass_ord.append(ident)

  #--- eth_reg_value ----------------------------------------------------------
  def eth_reg_value(self, ident, type, value, ethname=None):
    #print "eth_reg_value(ident='%s')" % (ident)
    if ident in self.value:
      if self.value[ident]['import'] and (self.value[ident]['import'] == self.Module()) :
        # replace imported value
        del self.value[ident]
        self.value_imp.remove(ident)
      elif ethname:
        self.value[ident]['ethname'] = ethname
        return
      else:
        raise DuplicateError("value", ident)
    self.value[ident] = { 'import' : None, 'module' : self.Module(), 'proto' : self.proto,
                          'type' : type, 'value' : value,
                          'no_emit' : False }
    self.value[ident]['export'] = self.conform.use_item('EXPORTS', ident)
    self.value[ident]['ethname'] = ''
    if (ethname): self.value[ident]['ethname'] = ethname
    self.value_ord.append(ident)

  #--- eth_reg_field ----------------------------------------------------------
  def eth_reg_field(self, ident, type, idx='', parent=None, impl=False, pdu=None):
    #print "eth_reg_field(ident='%s', type='%s')" % (ident, type)
    if ident in self.field:
      if pdu and (type == self.field[ident]['type']):
        pass  # OK already created PDU
      else:
        raise DuplicateError("field", ident)
    self.field[ident] = {'type' : type, 'idx' : idx, 'impl' : impl, 'pdu' : pdu,
                         'modified' : '', 'attr' : {} }
    name = ident.split('/')[-1]
    if self.remove_prefix and name.startswith(self.remove_prefix):
        name = name[len(self.remove_prefix):]

    if len(ident.split('/')) > 1 and name == '_item':  # Sequence/Set of type
      if len(self.field[ident]['type'].split('/')) > 1:
        self.field[ident]['attr']['NAME'] = '"%s item"' % ident.split('/')[-2]
        self.field[ident]['attr']['ABBREV'] = asn2c(ident.split('/')[-2] + name)
      else:
        self.field[ident]['attr']['NAME'] = '"%s"' % self.field[ident]['type']
        self.field[ident]['attr']['ABBREV'] = asn2c(self.field[ident]['type'])
    else:
      self.field[ident]['attr']['NAME'] = '"%s"' % name
      self.field[ident]['attr']['ABBREV'] = asn2c(name)
    if self.conform.check_item('FIELD_ATTR', ident):
      self.field[ident]['modified'] = '#' + str(id(self))
      self.field[ident]['attr'].update(self.conform.use_item('FIELD_ATTR', ident))
    if (pdu):
      self.field[ident]['pdu']['export'] = (self.conform.use_item('EXPORTS', ident + '_PDU') != 0)
      self.pdu_ord.append(ident)
    else:
      self.field_ord.append(ident)
    if parent:
      self.eth_dep_add(parent, type)

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
    self.sel_req = {}
    self.sel_req_ord = []
    self.comp_req_ord = []
    self.vassign = {}
    self.vassign_ord = []
    self.value = {}
    self.value_ord = []
    self.value_imp = []
    self.objectclass = {}
    self.objectclass_ord = []
    self.objectclass_imp = []
    self.oassign = {}
    self.oassign_ord = []
    self.oassign_cls = {}
    #--- Modules ------------
    self.modules = []
    self.exports_all = False
    self.exports = []
    self.cexports = []
    self.vexports = []
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

    #--- required PDUs ----------------------------
    for t in self.type_ord:
      pdu = self.type[t]['val'].eth_need_pdu(self)
      if not pdu: continue
      f = pdu['type']
      pdu['reg'] = None
      pdu['hidden'] = False
      pdu['need_decl'] = True
      if f not in self.field:
        self.eth_reg_field(f, f, pdu=pdu)

    #--- values -> named values -------------------
    t_for_update = {}
    for v in self.value_ord:
      if (self.value[v]['type'].type == 'Type_Ref') or self.conform.check_item('ASSIGN_VALUE_TO_TYPE', v):
        if self.conform.check_item('ASSIGN_VALUE_TO_TYPE', v):
          tnm = self.conform.use_item('ASSIGN_VALUE_TO_TYPE', v)
        else:
          tnm = self.value[v]['type'].val
        if tnm in self.type \
           and not self.type[tnm]['import'] \
           and (self.type[tnm]['val'].type == 'IntegerType'):
          self.type[tnm]['val'].add_named_value(v, self.value[v]['value'])
          self.value[v]['no_emit'] = True
          t_for_update[tnm] = True
    for t in list(t_for_update.keys()):
      self.type[t]['attr']['STRINGS'] = self.type[t]['val'].eth_strings()
      self.type[t]['attr'].update(self.conform.use_item('TYPE_ATTR', t))

    #--- required components of ---------------------------
    #print "self.comp_req_ord = ", self.comp_req_ord
    for t in self.comp_req_ord:
      self.type[t]['val'].eth_reg_sub(t, self, components_available=True)

    #--- required selection types ---------------------------
    #print "self.sel_req_ord = ", self.sel_req_ord
    for t in self.sel_req_ord:
      tt = self.sel_req[t]['typ']
      if tt not in self.type:
        self.dummy_import_type(t)
      elif self.type[tt]['import']:
        self.eth_import_type(t, self.type[tt]['import'], self.type[tt]['proto'])
      else:
        self.type[tt]['val'].sel_req(t, self.sel_req[t]['sel'], self)

    #--- types -------------------
    for t in self.type_imp: # imported types
      nm = asn2c(t)
      self.eth_type[nm] = { 'import' : self.type[t]['import'],
                            'proto' : asn2c(self.type[t]['proto']),
                            'attr' : {}, 'ref' : []}
      self.eth_type[nm]['attr'].update(self.conform.use_item('ETYPE_ATTR', nm))
      self.type[t]['ethname'] = nm
    for t in self.type_ord: # dummy import for missing type reference
      tp = self.type[t]['val']
      #print "X : %s %s " % (t, tp.type)
      if isinstance(tp, TaggedType):
        #print "%s : %s " % (tp.type, t)
        tp = tp.val
      if isinstance(tp, Type_Ref):
        #print "%s : %s ::= %s " % (tp.type, t, tp.val)
        if tp.val not in self.type:
          self.dummy_import_type(tp.val)
    for t in self.type_ord:
      nm = self.type[t]['tname']
      if ((nm.find('#') >= 0) or
          ((len(t.split('/'))>1) and
           (self.conform.get_fn_presence(t) or self.conform.check_item('FN_PARS', t) or
            self.conform.get_fn_presence('/'.join((t,'_item'))) or self.conform.check_item('FN_PARS', '/'.join((t,'_item')))) and
           not self.conform.check_item('TYPE_RENAME', t))):
        if len(t.split('/')) == 2 and t.split('/')[1] == '_item':  # Sequence of type at the 1st level
          nm = t.split('/')[0] + t.split('/')[1]
        elif t.split('/')[-1] == '_item':  # Sequence/Set of type at next levels
          nm = 'T_' + self.conform.use_item('FIELD_RENAME', '/'.join(t.split('/')[0:-1]), val_dflt=t.split('/')[-2]) + t.split('/')[-1]
        elif t.split('/')[-1] == '_untag':  # Untagged type
          nm = self.type['/'.join(t.split('/')[0:-1])]['ethname'] + '_U'
        else:
          nm = 'T_' + self.conform.use_item('FIELD_RENAME', t, val_dflt=t.split('/')[-1])
        nm = asn2c(nm)
        if nm in self.eth_type:
          if nm in self.eth_type_dupl:
            self.eth_type_dupl[nm].append(t)
          else:
            self.eth_type_dupl[nm] = [self.eth_type[nm]['ref'][0], t]
          nm += '_%02d' % (len(self.eth_type_dupl[nm])-1)
      if nm in self.eth_type:
        self.eth_type[nm]['ref'].append(t)
      else:
        self.eth_type_ord.append(nm)
        self.eth_type[nm] = { 'import' : None, 'proto' : self.eproto, 'export' : 0, 'enum' : 0, 'vals_ext' : 0,
                              'user_def' : EF_TYPE|EF_VALS, 'no_emit' : EF_TYPE|EF_VALS,
                              'val' : self.type[t]['val'],
                              'attr' : {}, 'ref' : [t]}
      self.type[t]['ethname'] = nm
      if (not self.eth_type[nm]['export'] and self.type[t]['export']):  # new export
        self.eth_export_ord.append(nm)
      self.eth_type[nm]['export'] |= self.type[t]['export']
      self.eth_type[nm]['enum'] |= self.type[t]['enum']
      self.eth_type[nm]['vals_ext'] |= self.type[t]['vals_ext']
      self.eth_type[nm]['user_def'] &= self.type[t]['user_def']
      self.eth_type[nm]['no_emit'] &= self.type[t]['no_emit']
      if self.type[t]['attr'].get('STRINGS') == '$$':
        use_ext = self.type[t]['vals_ext']
        if (use_ext):
          self.eth_type[nm]['attr']['STRINGS'] = '&%s_ext' % (self.eth_vals_nm(nm))
        else:
          self.eth_type[nm]['attr']['STRINGS'] = 'VALS(%s)' % (self.eth_vals_nm(nm))
      self.eth_type[nm]['attr'].update(self.conform.use_item('ETYPE_ATTR', nm))
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

    #--- register values from enums ------------
    for t in self.eth_type_ord:
      if (self.eth_type[t]['val'].eth_has_enum(t, self)):
        self.eth_type[t]['val'].reg_enum_vals(t, self)

    #--- value dependencies -------------------
    for v in self.value_ord:
      if isinstance (self.value[v]['value'], Value):
        dep = self.value[v]['value'].get_dep()
      else:
        dep = self.value[v]['value']
      if dep and dep in self.value:
        self.value_dep.setdefault(v, []).append(dep)

    #--- exports all necessary values
    for v in self.value_ord:
      if not self.value[v]['export']: continue
      deparr = self.value_dep.get(v, [])
      while deparr:
        d = deparr.pop()
        if not self.value[d]['import']:
          if not self.value[d]['export']:
            self.value[d]['export'] = EF_TYPE
            deparr.extend(self.value_dep.get(d, []))

    #--- values -------------------
    for v in self.value_imp:
      nm = asn2c(v)
      self.eth_value[nm] = { 'import' : self.value[v]['import'],
                             'proto' : asn2c(self.value[v]['proto']),
                             'ref' : []}
      self.value[v]['ethname'] = nm
    for v in self.value_ord:
      if (self.value[v]['ethname']):
        continue
      if (self.value[v]['no_emit']):
        continue
      nm = asn2c(v)
      self.eth_value[nm] = { 'import' : None,
                             'proto' : asn2c(self.value[v]['proto']),
                             'export' : self.value[v]['export'], 'ref' : [v] }
      self.eth_value[nm]['value'] = self.value[v]['value']
      self.eth_value_ord.append(nm)
      self.value[v]['ethname'] = nm

    #--- fields -------------------------
    for f in (self.pdu_ord + self.field_ord):
      if len(f.split('/')) > 1 and f.split('/')[-1] == '_item':  # Sequence/Set of type
        nm = self.conform.use_item('FIELD_RENAME', '/'.join(f.split('/')[0:-1]), val_dflt=f.split('/')[-2]) + f.split('/')[-1]
      else:
        nm = f.split('/')[-1]
      nm = self.conform.use_item('FIELD_RENAME', f, val_dflt=nm)
      nm = asn2c(nm)
      if (self.field[f]['pdu']):
        nm += '_PDU'
        if (not self.merge_modules or self.field[f]['pdu']['export']):
          nm = self.eproto + '_' + nm
      t = self.field[f]['type']
      if t in self.type:
        ethtype = self.type[t]['ethname']
      else:  # undefined type
        ethtype = self.dummy_import_type(t)
      ethtypemod = ethtype + self.field[f]['modified']
      if nm in self.eth_hf:
        if nm in self.eth_hf_dupl:
          if ethtypemod in self.eth_hf_dupl[nm]:
            nm = self.eth_hf_dupl[nm][ethtypemod]
            self.eth_hf[nm]['ref'].append(f)
            self.field[f]['ethname'] = nm
            continue
          else:
            nmx = nm + ('_%02d' % (len(self.eth_hf_dupl[nm])))
            self.eth_hf_dupl[nm][ethtype] = nmx
            nm = nmx
        else:
          if (self.eth_hf[nm]['ethtype']+self.eth_hf[nm]['modified']) == ethtypemod:
            self.eth_hf[nm]['ref'].append(f)
            self.field[f]['ethname'] = nm
            continue
          else:
            nmx = nm + '_01'
            self.eth_hf_dupl[nm] = {self.eth_hf[nm]['ethtype']+self.eth_hf[nm]['modified'] : nm, \
                                    ethtypemod : nmx}
            nm = nmx
      if (self.field[f]['pdu']):
        self.eth_hfpdu_ord.append(nm)
      else:
        self.eth_hf_ord.append(nm)
      fullname = 'hf_%s_%s' % (self.eproto, nm)
      attr = self.eth_get_type_attr(self.field[f]['type']).copy()
      attr.update(self.field[f]['attr'])
      if (self.NAPI() and 'NAME' in attr):
        attr['NAME'] += self.field[f]['idx']
      attr.update(self.conform.use_item('EFIELD_ATTR', nm))
      use_vals_ext = self.eth_type[ethtype].get('vals_ext')
      if (use_vals_ext):
        attr['DISPLAY'] += '|BASE_EXT_STRING'
      self.eth_hf[nm] = {'fullname' : fullname, 'pdu' : self.field[f]['pdu'],
                         'ethtype' : ethtype, 'modified' : self.field[f]['modified'],
                         'attr' : attr.copy(),
                         'ref' : [f]}
      self.field[f]['ethname'] = nm
    #--- type dependencies -------------------
    (self.eth_type_ord1, self.eth_dep_cycle) = dependency_compute(self.type_ord, self.type_dep, map_fn = lambda t: self.type[t]['ethname'], ignore_fn = lambda t: self.type[t]['import'])
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

    #--- export tags, values, ... ---
    for t in self.exports:
      if t not in self.type:
        continue
      if self.type[t]['import']:
        continue
      m = self.type[t]['module']
      if not self.Per():
        if m not in self.all_tags:
          self.all_tags[m] = {}
        self.all_tags[m][t] = self.type[t]['val'].GetTTag(self)
      if m not in self.all_type_attr:
        self.all_type_attr[m] = {}
      self.all_type_attr[m][t] = self.eth_get_type_attr(t).copy()
    for v in self.vexports:
      if v not in self.value:
        continue
      if self.value[v]['import']:
        continue
      m = self.value[v]['module']
      if m not in self.all_vals:
        self.all_vals[m] = {}
      vv = self.value[v]['value']
      if isinstance (vv, Value):
        vv = vv.to_str(self)
      self.all_vals[m][v] = vv

  #--- eth_vals_nm ------------------------------------------------------------
  def eth_vals_nm(self, tname):
    out = ""
    if (not self.eth_type[tname]['export'] & EF_NO_PROT):
      out += "%s_" % (self.eproto)
    out += "%s_vals" % (tname)
    return out

  #--- eth_vals ---------------------------------------------------------------
  def eth_vals(self, tname, vals):
    out = ""
    has_enum = self.eth_type[tname]['enum'] & EF_ENUM
    use_ext = self.eth_type[tname]['vals_ext']
    if (use_ext):
      vals.sort(key=lambda vals_entry: int(vals_entry[0]))
    if (not self.eth_type[tname]['export'] & EF_VALS):
      out += 'static '
    if (self.eth_type[tname]['export'] & EF_VALS) and (self.eth_type[tname]['export'] & EF_TABLE):
      out += 'static '
    out += "const value_string %s[] = {\n" % (self.eth_vals_nm(tname))
    for (val, id) in vals:
      if (has_enum):
        vval = self.eth_enum_item(tname, id)
      else:
        vval = val
      out += '  { %3s, "%s" },\n' % (vval, id)
    out += "  { 0, NULL }\n};\n"
    if (use_ext):
      out += "\nstatic value_string_ext %s_ext = VALUE_STRING_EXT_INIT(%s);\n" % (self.eth_vals_nm(tname), self.eth_vals_nm(tname)) 
    return out

  #--- eth_enum_prefix ------------------------------------------------------------
  def eth_enum_prefix(self, tname, type=False):
    out = ""
    if (self.eth_type[tname]['export'] & EF_ENUM):
      no_prot = self.eth_type[tname]['export'] & EF_NO_PROT
    else:
      no_prot = self.eth_type[tname]['enum'] & EF_NO_PROT
    if (not no_prot):
      out += self.eproto
    if ((not self.eth_type[tname]['enum'] & EF_NO_TYPE) or type):
      if (out): out += '_'
      out += tname
    if (self.eth_type[tname]['enum'] & EF_UCASE):
      out = out.upper()
    if (out): out += '_'
    return out

  #--- eth_enum_nm ------------------------------------------------------------
  def eth_enum_nm(self, tname):
    out = self.eth_enum_prefix(tname, type=True)
    out += "enum"
    return out

  #--- eth_enum_item ---------------------------------------------------------------
  def eth_enum_item(self, tname, ident):
    out = self.eth_enum_prefix(tname)
    out += asn2c(ident)
    if (self.eth_type[tname]['enum'] & EF_UCASE):
      out = out.upper()
    return out

  #--- eth_enum ---------------------------------------------------------------
  def eth_enum(self, tname, vals):
    out = ""
    if (self.eth_type[tname]['enum'] & EF_DEFINE):
      out += "/* enumerated values for %s */\n" % (tname)
      for (val, id) in vals:
        out += '#define %-12s %3s\n' % (self.eth_enum_item(tname, id), val)
    else:
      out += "typedef enum _%s {\n" % (self.eth_enum_nm(tname))
      first_line = 1
      for (val, id) in vals:
        if (first_line == 1):
          first_line = 0
        else:
          out += ",\n"
        out += '  %-12s = %3s' % (self.eth_enum_item(tname, id), val)
      out += "\n} %s;\n" % (self.eth_enum_nm(tname))
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
    if (not self.eth_type[tname]['export'] & EF_TYPE):
      out += 'static '
    out += "int "
    if (self.Ber()):
      out += "dissect_%s_%s(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)" % (self.eth_type[tname]['proto'], tname)
    elif (self.Per()):
      out += "dissect_%s_%s(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)" % (self.eth_type[tname]['proto'], tname)
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
    if (not self.eth_type[tname]['export'] & EF_TYPE):
      out += 'static '
    out += "int\n"
    if (self.Ber()):
      out += "dissect_%s_%s(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {\n" % (self.eth_type[tname]['proto'], tname)
    elif (self.Per()):
      out += "dissect_%s_%s(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {\n" % (self.eth_type[tname]['proto'], tname)
    #if self.conform.get_fn_presence(tname):
    #  out += self.conform.get_fn_text(tname, 'FN_HDR')
    #el
    if self.conform.get_fn_presence(self.eth_type[tname]['ref'][0]):
      out += self.conform.get_fn_text(self.eth_type[tname]['ref'][0], 'FN_HDR')
    return out

  #--- eth_type_fn_ftr --------------------------------------------------------
  def eth_type_fn_ftr(self, tname):
    out = '\n'
    #if self.conform.get_fn_presence(tname):
    #  out += self.conform.get_fn_text(tname, 'FN_FTR')
    #el
    if self.conform.get_fn_presence(self.eth_type[tname]['ref'][0]):
      out += self.conform.get_fn_text(self.eth_type[tname]['ref'][0], 'FN_FTR')
    out += "  return offset;\n"
    out += "}\n"
    return out

  #--- eth_type_fn_body -------------------------------------------------------
  def eth_type_fn_body(self, tname, body, pars=None):
    out = body
    #if self.conform.get_fn_body_presence(tname):
    #  out = self.conform.get_fn_text(tname, 'FN_BODY')
    #el
    if self.conform.get_fn_body_presence(self.eth_type[tname]['ref'][0]):
      out = self.conform.get_fn_text(self.eth_type[tname]['ref'][0], 'FN_BODY')
    if pars:
      try:
        out = out % pars
      except (TypeError):
        pass
    return out

  #--- eth_out_pdu_decl ----------------------------------------------------------
  def eth_out_pdu_decl(self, f):
    t = self.eth_hf[f]['ethtype']
    is_new = self.eth_hf[f]['pdu']['new']
    out = ''
    if (not self.eth_hf[f]['pdu']['export']):
      out += 'static '
    if (is_new):
      out += 'int '
    else:
      out += 'void '
    out += 'dissect_'+f+'(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);\n'
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
      t = self.eth_hf[f]['ethtype']
      if self.remove_prefix and t.startswith(self.remove_prefix):
        t = t[len(self.remove_prefix):]
      name=self.eth_hf[f]['attr']['NAME']
      trantab=maketrans("- ", "__")
      name=name.translate(trantab)
      namelower=name.lower()
      tquoted_lower = '"' + t.lower() + '"'
      # Try to avoid giving blurbs that give no more info than the name
      if tquoted_lower == namelower or \
	 t == "NULL" or \
	 tquoted_lower.replace("t_", "") == namelower:
        blurb = 'NULL'
      else:
        blurb = '"%s"' % (t)
      attr = self.eth_hf[f]['attr'].copy()
      attr['ABBREV'] = '"%s.%s"' % (self.proto, attr['ABBREV'])
      if 'BLURB' not in attr:
        attr['BLURB'] = blurb
      fx.write('    { &%s,\n' % (self.eth_hf[f]['fullname']))
      fx.write('      { %(NAME)s, %(ABBREV)s,\n' % attr)
      fx.write('        %(TYPE)s, %(DISPLAY)s, %(STRINGS)s, %(BITMASK)s,\n' % attr)
      fx.write('        %(BLURB)s, HFILL }},\n' % attr)
    for nb in self.named_bit:
      fx.write('    { &%s,\n' % (nb['ethname']))
      fx.write('      { "%s", "%s.%s",\n' % (nb['name'], self.proto, nb['name']))
      fx.write('        %s, %s, %s, %s,\n' % (nb['ftype'], nb['display'], nb['strings'], nb['bitmask']))
      fx.write('        NULL, HFILL }},\n')
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
      if (self.eth_type[t]['export'] & EF_ENUM) and self.eth_type[t]['val'].eth_has_enum(t, self):
        fx.write(self.eth_type[t]['val'].eth_type_enum(t, self))
      if (self.eth_type[t]['export'] & EF_VALS) and self.eth_type[t]['val'].eth_has_vals():
        if not self.eth_type[t]['export'] & EF_TABLE:
          if self.eth_type[t]['export'] & EF_WS_VAR:
            fx.write("WS_VAR_IMPORT ")
          else:
            fx.write("extern ")
          fx.write("const value_string %s[];\n" % (self.eth_vals_nm(t)))
        else:
          fx.write(self.eth_type[t]['val'].eth_type_vals(t, self))
    for t in self.eth_export_ord:  # functions
      if (self.eth_type[t]['export'] & EF_TYPE):
        if self.eth_type[t]['export'] & EF_EXTERN:
          fx.write("extern ")
        fx.write(self.eth_type_fn_h(t))
    for f in self.eth_hfpdu_ord:  # PDUs
      if (self.eth_hf[f]['pdu'] and self.eth_hf[f]['pdu']['export']):
        fx.write(self.eth_out_pdu_decl(f))
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
    for cls in self.objectclass_ord:
      if self.objectclass[cls]['export']:
        cnm = cls
        if self.objectclass[cls]['export'] & EF_MODULE:
          cnm = "$%s$%s" % (self.objectclass[cls]['module'], cnm)
        fx.write('#.CLASS %s\n' % (cnm))
        maxw = 2
        for fld in self.objectclass[cls]['val'].fields:
          w = len(fld.fld_repr()[0])
          if (w > maxw): maxw = w
        for fld in self.objectclass[cls]['val'].fields:
          repr = fld.fld_repr()
          fx.write('%-*s  %s\n' % (maxw, repr[0], ' '.join(repr[1:])))
        fx.write('#.END\n\n')
    if self.Ber():
      fx.write('#.IMPORT_TAG\n')
      for t in self.eth_export_ord:  # tags
        if (self.eth_type[t]['export'] & EF_TYPE):
          fx.write('%-24s ' % self.eth_type[t]['ref'][0])
          fx.write('%s %s\n' % self.eth_type[t]['val'].GetTag(self))
      fx.write('#.END\n\n')
    fx.write('#.TYPE_ATTR\n')
    for t in self.eth_export_ord:  # attributes
      if (self.eth_type[t]['export'] & EF_TYPE):
        tnm = self.eth_type[t]['ref'][0]
        if self.eth_type[t]['export'] & EF_MODULE:
          tnm = "$%s$%s" % (self.type[tnm]['module'], tnm)
        fx.write('%-24s ' % tnm)
        attr = self.eth_get_type_attr(self.eth_type[t]['ref'][0]).copy()
        fx.write('TYPE = %(TYPE)-9s  DISPLAY = %(DISPLAY)-9s  STRINGS = %(STRINGS)s  BITMASK = %(BITMASK)s\n' % attr)
    fx.write('#.END\n\n')
    self.output.file_close(fx, keep_anyway=True)

  #--- eth_output_val ------------------------------------------------------
  def eth_output_val(self):
    fx = self.output.file_open('val', ext='h')
    for v in self.eth_value_ord1:
      vv = self.eth_value[v]['value']
      if isinstance (vv, Value):
        vv = vv.to_str(self)
      fx.write("#define %-30s %s\n" % (v, vv))
    for t in self.eth_type_ord1:
      if self.eth_type[t]['import']:
        continue
      if self.eth_type[t]['val'].eth_has_enum(t, self) and not (self.eth_type[t]['export'] & EF_ENUM):
        fx.write(self.eth_type[t]['val'].eth_type_enum(t, self))
    self.output.file_close(fx)

  #--- eth_output_valexp ------------------------------------------------------
  def eth_output_valexp(self):
    if (not len(self.eth_vexport_ord)): return
    fx = self.output.file_open('valexp', ext='h')
    for v in self.eth_vexport_ord:
      vv = self.eth_value[v]['value']
      if isinstance (vv, Value):
        vv = vv.to_str(self)
      fx.write("#define %-30s %s\n" % (v, vv))
    self.output.file_close(fx)

  #--- eth_output_types -------------------------------------------------------
  def eth_output_types(self):
    def out_pdu(f):
      t = self.eth_hf[f]['ethtype']
      is_new = self.eth_hf[f]['pdu']['new']
      impl = 'FALSE'
      out = ''
      if (not self.eth_hf[f]['pdu']['export']):
        out += 'static '
      if (is_new):
        out += 'int '
      else:
        out += 'void '
      out += 'dissect_'+f+'(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {\n'
      if (is_new):
        out += '  int offset = 0;\n'
        off_par = 'offset'
        ret_par = 'offset'
      else:
        off_par = '0'
        ret_par = None
      if (self.Per()):
        if (self.Aligned()):
          aligned = 'TRUE'
        else:
          aligned = 'FALSE'
        out += "  asn1_ctx_t asn1_ctx;\n"
        out += self.eth_fn_call('asn1_ctx_init', par=(('&asn1_ctx', 'ASN1_ENC_PER', aligned, 'pinfo'),))
      if (self.Ber()):
        out += "  asn1_ctx_t asn1_ctx;\n"
        out += self.eth_fn_call('asn1_ctx_init', par=(('&asn1_ctx', 'ASN1_ENC_BER', 'TRUE', 'pinfo'),))
        par=((impl, 'tvb', off_par,'&asn1_ctx', 'tree', self.eth_hf[f]['fullname']),)
      elif (self.Per()):
        par=(('tvb', off_par, '&asn1_ctx', 'tree', self.eth_hf[f]['fullname']),)
      else:
        par=((),)
      out += self.eth_fn_call('dissect_%s_%s' % (self.eth_type[t]['proto'], t), ret=ret_par, par=par)
      if (self.Per() and is_new):
        out += '  offset += 7; offset >>= 3;\n'
      if (is_new):
        out += '  return offset;\n'
      out += '}\n'
      return out
    #end out_pdu()
    fx = self.output.file_open('fn')
    pos = fx.tell()
    if (len(self.eth_hfpdu_ord)):
      first_decl = True
      for f in self.eth_hfpdu_ord:
        if (self.eth_hf[f]['pdu'] and self.eth_hf[f]['pdu']['need_decl']):
          if first_decl:
            fx.write('/*--- PDUs declarations ---*/\n')
            first_decl = False
          fx.write(self.eth_out_pdu_decl(f))
      if not first_decl:
        fx.write('\n')
    if self.eth_dep_cycle:
      fx.write('/*--- Cyclic dependencies ---*/\n\n')
      i = 0
      while i < len(self.eth_dep_cycle):
        t = self.type[self.eth_dep_cycle[i][0]]['ethname']
        if self.dep_cycle_eth_type[t][0] != i: i += 1; continue
        fx.write(''.join(['/* %s */\n' % ' -> '.join(self.eth_dep_cycle[i]) for i in self.dep_cycle_eth_type[t]]))
        fx.write(self.eth_type_fn_h(t))
        fx.write('\n')
        i += 1
      fx.write('\n')
    for t in self.eth_type_ord1:
      if self.eth_type[t]['import']:
        continue
      if self.eth_type[t]['val'].eth_has_vals():
        if self.eth_type[t]['no_emit'] & EF_VALS:
          pass
        elif self.eth_type[t]['user_def'] & EF_VALS:
          fx.write("extern const value_string %s[];\n" % (self.eth_vals_nm(t)))
        elif (self.eth_type[t]['export'] & EF_VALS) and (self.eth_type[t]['export'] & EF_TABLE):
          pass
        else:
          fx.write(self.eth_type[t]['val'].eth_type_vals(t, self))
      if self.eth_type[t]['no_emit'] & EF_TYPE:
        pass
      elif self.eth_type[t]['user_def'] & EF_TYPE:
        fx.write(self.eth_type_fn_h(t))
      else:
        fx.write(self.eth_type[t]['val'].eth_type_fn(self.eth_type[t]['proto'], t, self))
      fx.write('\n')
    if (len(self.eth_hfpdu_ord)):
      fx.write('/*--- PDUs ---*/\n\n')
      for f in self.eth_hfpdu_ord:
        if (self.eth_hf[f]['pdu']):
          if (f in self.emitted_pdu):
            fx.write("  /* %s already emitted */\n" % (f))
          else:
            fx.write(out_pdu(f))
            self.emitted_pdu[f] = True
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
      if reg['pdu'] not in self.field: continue
      f = self.field[reg['pdu']]['ethname']
      pdu = self.eth_hf[f]['pdu']
      new_prefix = ''
      if (pdu['new']): new_prefix = 'new_'
      if (reg['rtype'] in ('NUM', 'STR')):
        rstr = ''
        if (reg['rtype'] == 'STR'):
	  rstr = 'string'
        else:
	  rstr = 'uint'
        if (pdu['reg']):
          dis = self.proto
          if (pdu['reg'] != '.'): dis += '.' + pdu['reg']
          if  (not pdu['hidden']):
            hnd = '%s_handle' % (asn2c(dis))
          else:
            hnd = 'find_dissector("%s")' % (dis)
        else:
          hnd = '%screate_dissector_handle(dissect_%s, proto_%s)' % (new_prefix, f, self.eproto)
        rport = self.value_get_eth(reg['rport'])
        fx.write('  dissector_add_%s("%s", %s, %s);\n' % (rstr, reg['rtable'], rport, hnd))
      elif (reg['rtype'] in ('BER', 'PER')):
        roid = self.value_get_eth(reg['roid'])
        fx.write('  %sregister_%s_oid_dissector(%s, dissect_%s, proto_%s, %s);\n' % (new_prefix, reg['rtype'].lower(), roid, f, self.eproto, reg['roidname']))
      fempty = False
    fx.write('\n')
    self.output.file_close(fx, discard=fempty)

  #--- eth_output_syn_reg -----------------------------------------------------
  def eth_output_syn_reg(self):
    fx = self.output.file_open('syn-reg')
    fempty = True
    first_decl = True
    for k in self.conform.get_order('SYNTAX'):
      reg = self.conform.use_item('SYNTAX', k)
      if first_decl:
        fx.write('  /*--- Syntax registrations ---*/\n')
        first_decl = False
      fx.write('  register_ber_syntax_dissector(%s, proto_%s, dissect_%s_PDU);\n' % (k, self.eproto, reg['pdu']));
      fempty=False
    self.output.file_close(fx, discard=fempty)

  #--- eth_output_table -----------------------------------------------------
  def eth_output_table(self):
    for num in list(self.conform.report.keys()):
      fx = self.output.file_open('table' + num)
      for rep in self.conform.report[num]:
        if rep['type'] == 'HDR':
          fx.write('\n')
        if rep['var']:
          var = rep['var']
          var_list = var.split('.')
          cls = var_list[0]
          del var_list[0]
          if (cls in self.oassign_cls):
            for ident in self.oassign_cls[cls]:
             obj = self.get_obj_repr(ident, var_list)
             if not obj:
               continue
             obj['_LOOP'] = var
             obj['_DICT'] = str(obj)
             try:
               text = rep['text'] % obj
             except (KeyError):
               raise sys.exc_info()[0], "%s:%s invalid key %s for information object %s of %s" % (rep['fn'], rep['lineno'], sys.exc_info()[1], ident, var)
             fx.write(text)
          else:
            fx.write("/* Unknown or empty loop list %s */\n" % (var))
        else:
          fx.write(rep['text'])
        if rep['type'] == 'FTR':
          fx.write('\n')
      self.output.file_close(fx)

  #--- dupl_report -----------------------------------------------------
  def dupl_report(self):
    # types
    tmplist = sorted(self.eth_type_dupl.keys())
    for t in tmplist:
      msg = "The same type names for different types. Explicit type renaming is recommended.\n"
      msg += t + "\n"
      for tt in self.eth_type_dupl[t]:
        msg += " %-20s %s\n" % (self.type[tt]['ethname'], tt)
      warnings.warn_explicit(msg, UserWarning, '', 0)
    # fields
    tmplist = list(self.eth_hf_dupl.keys())
    tmplist.sort()
    for f in tmplist:
      msg = "The same field names for different types. Explicit field renaming is recommended.\n"
      msg += f + "\n"
      for tt in list(self.eth_hf_dupl[f].keys()):
        msg += " %-20s %-20s " % (self.eth_hf_dupl[f][tt], tt)
        msg += ", ".join(self.eth_hf[self.eth_hf_dupl[f][tt]]['ref'])
        msg += "\n"
      warnings.warn_explicit(msg, UserWarning, '', 0)

  #--- eth_do_output ------------------------------------------------------------
  def eth_do_output(self):
    if self.dbg('a'):
      print "\n# Assignments"
      for a in self.assign_ord:
        v = ' '
        if (self.assign[a]['virt']): v = '*'
        print v, a
      print "\n# Value assignments"
      for a in self.vassign_ord:
        print ' ', a
      print "\n# Information object assignments"
      for a in self.oassign_ord:
        print " %-12s (%s)" % (a, self.oassign[a].cls)
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
      print "\n# Imported Object Classes"
      print "%-40s %-24s %-24s" % ("ASN.1 name", "Module", "Protocol")
      print "-" * 100
      for t in self.objectclass_imp:
        print "%-40s %-24s %-24s" % (t, self.objectclass[t]['import'], self.objectclass[t]['proto'])
      print "\n# Exported Types"
      print "%-31s %s" % ("Wireshark type", "Export Flag")
      print "-" * 100
      for t in self.eth_export_ord:
        print "%-31s 0x%02X" % (t, self.eth_type[t]['export'])
      print "\n# Exported Values"
      print "%-40s %s" % ("Wireshark name", "Value")
      print "-" * 100
      for v in self.eth_vexport_ord:
        vv = self.eth_value[v]['value']
        if isinstance (vv, Value):
          vv = vv.to_str(self)
        print "%-40s %s" % (v, vv)
      print "\n# ASN.1 Object Classes"
      print "%-40s %-24s %-24s" % ("ASN.1 name", "Module", "Protocol")
      print "-" * 100
      for t in self.objectclass_ord:
        print "%-40s " % (t)
      print "\n# ASN.1 Types"
      print "%-49s %-24s %-24s" % ("ASN.1 unique name", "'tname'", "Wireshark type")
      print "-" * 100
      for t in self.type_ord:
        print "%-49s %-24s %-24s" % (t, self.type[t]['tname'], self.type[t]['ethname'])
      print "\n# Wireshark Types"
      print "Wireshark type                   References (ASN.1 types)"
      print "-" * 100
      for t in self.eth_type_ord:
        print "%-31s %d" % (t, len(self.eth_type[t]['ref'])),
        print ', '.join(self.eth_type[t]['ref'])
      print "\n# ASN.1 Values"
      print "%-40s %-18s %-20s %s" % ("ASN.1 unique name", "Type", "Value", "Wireshark value")
      print "-" * 100
      for v in self.value_ord:
        vv = self.value[v]['value']
        if isinstance (vv, Value):
          vv = vv.to_str(self)
        print "%-40s %-18s %-20s %s" % (v, self.value[v]['type'].eth_tname(), vv, self.value[v]['ethname'])
      #print "\n# Wireshark Values"
      #print "%-40s %s" % ("Wireshark name", "Value")
      #print "-" * 100
      #for v in self.eth_value_ord:
      #  vv = self.eth_value[v]['value']
      #  if isinstance (vv, Value):
      #    vv = vv.to_str(self)
      #  print "%-40s %s" % (v, vv)
      print "\n# ASN.1 Fields"
      print "ASN.1 unique name                        Wireshark name        ASN.1 type"
      print "-" * 100
      for f in (self.pdu_ord + self.field_ord):
        print "%-40s %-20s %s" % (f, self.field[f]['ethname'], self.field[f]['type'])
      print "\n# Wireshark Fields"
      print "Wireshark name                  Wireshark type        References (ASN.1 fields)"
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
      self.output.outnm = self.output.outnm.replace('.', '-')
    if not self.justexpcnf:
      self.eth_output_hf()
      self.eth_output_ett()
      self.eth_output_types()
      self.eth_output_hf_arr()
      self.eth_output_ett_arr()
      self.eth_output_export()
      self.eth_output_val()
      self.eth_output_valexp()
      self.eth_output_dis_hnd()
      self.eth_output_dis_reg()
      self.eth_output_dis_tab()
      self.eth_output_syn_reg()
      self.eth_output_table()
    if self.expcnf:
      self.eth_output_expcnf()

  def dbg_modules(self):
    def print_mod(m):
      print "%-30s " % (m),
      dep = self.module[m][:]
      for i in range(len(dep)):
        if dep[i] not in self.module:
          dep[i] = '*' + dep[i]
      print ', '.join(dep)
    # end of print_mod()
    (mod_ord, mod_cyc) = dependency_compute(self.module_ord, self.module, ignore_fn = lambda t: t not in self.module)
    print "\n# ASN.1 Moudules"
    print "Module name                     Dependency"
    print "-" * 100
    new_ord = False
    for m in (self.module_ord):
      print_mod(m)
      new_ord = new_ord or (self.module_ord.index(m) != mod_ord.index(m))
    if new_ord:
      print "\n# ASN.1 Moudules - in dependency order"
      print "Module name                     Dependency"
      print "-" * 100
      for m in (mod_ord):
        print_mod(m)
    if mod_cyc:
      print "\nCyclic dependencies:"
      for i in (range(len(mod_cyc))):
        print "%02d: %s" % (i + 1, str(mod_cyc[i]))


#--- EthCnf -------------------------------------------------------------------
class EthCnf:
  def __init__(self):
    self.ectx = None
    self.tblcfg = {}
    self.table = {}
    self.order = {}
    self.fn = {}
    self.report = {}
    self.suppress_line = False
    self.include_path = []
    #                                   Value name             Default value       Duplicity check   Usage check
    self.tblcfg['EXPORTS']         = { 'val_nm' : 'flag',     'val_dflt' : 0,     'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['MAKE_ENUM']       = { 'val_nm' : 'flag',     'val_dflt' : 0,     'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['USE_VALS_EXT']    = { 'val_nm' : 'flag',     'val_dflt' : 0,     'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['PDU']             = { 'val_nm' : 'attr',     'val_dflt' : None,  'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['SYNTAX']             = { 'val_nm' : 'attr',     'val_dflt' : None,  'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['REGISTER']        = { 'val_nm' : 'attr',     'val_dflt' : None,  'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['USER_DEFINED']    = { 'val_nm' : 'flag',     'val_dflt' : 0,     'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['NO_EMIT']         = { 'val_nm' : 'flag',     'val_dflt' : 0,     'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['MODULE']          = { 'val_nm' : 'proto',    'val_dflt' : None,  'chk_dup' : True, 'chk_use' : False }
    self.tblcfg['OMIT_ASSIGNMENT'] = { 'val_nm' : 'omit',     'val_dflt' : False, 'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['NO_OMIT_ASSGN']   = { 'val_nm' : 'omit',     'val_dflt' : True,  'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['VIRTUAL_ASSGN']   = { 'val_nm' : 'name',     'val_dflt' : None,  'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['SET_TYPE']        = { 'val_nm' : 'type',     'val_dflt' : None,  'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['TYPE_RENAME']     = { 'val_nm' : 'eth_name', 'val_dflt' : None,  'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['FIELD_RENAME']    = { 'val_nm' : 'eth_name', 'val_dflt' : None,  'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['IMPORT_TAG']      = { 'val_nm' : 'ttag',     'val_dflt' : (),    'chk_dup' : True, 'chk_use' : False }
    self.tblcfg['FN_PARS']         = { 'val_nm' : 'pars',     'val_dflt' : {},    'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['TYPE_ATTR']       = { 'val_nm' : 'attr',     'val_dflt' : {},    'chk_dup' : True, 'chk_use' : False }
    self.tblcfg['ETYPE_ATTR']      = { 'val_nm' : 'attr',     'val_dflt' : {},    'chk_dup' : True, 'chk_use' : False }
    self.tblcfg['FIELD_ATTR']      = { 'val_nm' : 'attr',     'val_dflt' : {},    'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['EFIELD_ATTR']     = { 'val_nm' : 'attr',     'val_dflt' : {},    'chk_dup' : True, 'chk_use' : True }
    self.tblcfg['ASSIGNED_ID']     = { 'val_nm' : 'ids',      'val_dflt' : {},    'chk_dup' : False,'chk_use' : False }
    self.tblcfg['ASSIGN_VALUE_TO_TYPE'] = { 'val_nm' : 'name', 'val_dflt' : None, 'chk_dup' : True, 'chk_use' : True }

    for k in list(self.tblcfg.keys()) :
      self.table[k] = {}
      self.order[k] = []

  def add_item(self, table, key, fn, lineno, **kw):
    if self.tblcfg[table]['chk_dup'] and key in self.table[table]:
      warnings.warn_explicit("Duplicated %s for %s. Previous one is at %s:%d" %
                             (table, key, self.table[table][key]['fn'], self.table[table][key]['lineno']),
                             UserWarning, fn, lineno)
      return
    self.table[table][key] = {'fn' : fn, 'lineno' : lineno, 'used' : False}
    self.table[table][key].update(kw)
    self.order[table].append(key)

  def update_item(self, table, key, fn, lineno, **kw):
    if key not in self.table[table]:
      self.table[table][key] = {'fn' : fn, 'lineno' : lineno, 'used' : False}
      self.order[table].append(key)
      self.table[table][key][self.tblcfg[table]['val_nm']] = {}
    self.table[table][key][self.tblcfg[table]['val_nm']].update(kw[self.tblcfg[table]['val_nm']])

  def get_order(self, table):
    return self.order[table]

  def check_item(self, table, key):
    return key in self.table[table]

  def copy_item(self, table, dst_key, src_key):
    if (src_key in self.table[table]):
      self.table[table][dst_key] = self.table[table][src_key]

  def check_item_value(self, table, key, **kw):
    return key in self.table[table] and kw.get('val_nm', self.tblcfg[table]['val_nm']) in self.table[table][key]

  def use_item(self, table, key, **kw):
    vdflt = kw.get('val_dflt', self.tblcfg[table]['val_dflt'])
    if key not in self.table[table]: return vdflt
    vname = kw.get('val_nm', self.tblcfg[table]['val_nm'])
    #print "use_item() - set used for %s %s" % (table, key)
    self.table[table][key]['used'] = True
    return self.table[table][key].get(vname, vdflt)

  def omit_assignment(self, type, ident, module):
    if self.ectx.conform.use_item('OMIT_ASSIGNMENT', ident):
      return True
    if self.ectx.conform.use_item('OMIT_ASSIGNMENT', '*') or \
       self.ectx.conform.use_item('OMIT_ASSIGNMENT', '*'+type) or \
       self.ectx.conform.use_item('OMIT_ASSIGNMENT', '*/'+module) or \
       self.ectx.conform.use_item('OMIT_ASSIGNMENT', '*'+type+'/'+module):
      return self.ectx.conform.use_item('NO_OMIT_ASSGN', ident)
    return False

  def add_fn_line(self, name, ctx, line, fn, lineno):
    if name not in self.fn:
      self.fn[name] = {'FN_HDR' : None, 'FN_FTR' : None, 'FN_BODY' : None}
    if (self.fn[name][ctx]):
      self.fn[name][ctx]['text'] += line
    else:
      self.fn[name][ctx] = {'text' : line, 'used' : False,
                             'fn' : fn, 'lineno' : lineno}
  def get_fn_presence(self, name):
    #print "get_fn_presence('%s'):%s" % (name, str(self.fn.has_key(name)))
    #if self.fn.has_key(name): print self.fn[name]
    return name in self.fn
  def get_fn_body_presence(self, name):
    return name in self.fn and self.fn[name]['FN_BODY']
  def get_fn_text(self, name, ctx):
    if (name not in self.fn):
      return '';
    if (not self.fn[name][ctx]):
      return '';
    self.fn[name][ctx]['used'] = True
    out = self.fn[name][ctx]['text']
    if (not self.suppress_line):
      out = '#line %u "%s"\n%s\n' % (self.fn[name][ctx]['lineno'], rel_dissector_path(self.fn[name][ctx]['fn']), out);
    return out

  def add_pdu(self, par, is_new, fn, lineno):
    #print "add_pdu(par=%s, %s, %d)" % (str(par), fn, lineno)
    (reg, hidden) = (None, False)
    if (len(par) > 1): reg = par[1]
    if (reg and reg[0]=='@'): (reg, hidden) = (reg[1:], True)
    attr = {'new' : is_new, 'reg' : reg, 'hidden' : hidden, 'need_decl' : False, 'export' : False}
    self.add_item('PDU', par[0], attr=attr, fn=fn, lineno=lineno)
    return

  def add_syntax(self, par, fn, lineno):
    #print "add_syntax(par=%s, %s, %d)" % (str(par), fn, lineno)
    if( (len(par) >=2)):
      name = par[1]
    else:
      name = '"'+par[0]+'"'
    attr = { 'pdu' : par[0] }
    self.add_item('SYNTAX', name, attr=attr, fn=fn, lineno=lineno)
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
      if (len(par)>=3):
        attr['roidname'] = par[2]
      elif attr['roid'][0] != '"':
        attr['roidname'] = '"' + attr['roid'] + '"'
      rkey = '/'.join([rtype, attr['roid']])
    self.add_item('REGISTER', rkey, attr=attr, fn=fn, lineno=lineno)

  def check_par(self, par, pmin, pmax, fn, lineno):
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
    if (pmax >= 0) and (len(par) > pmax):
      warnings.warn_explicit("Too many parameters. Only %d parameters are allowed" % (pmax), UserWarning, fn, lineno)
      return par[0:pmax]
    return par

  def read(self, fn):
    def get_par(line, pmin, pmax, fn, lineno):
      par = line.split(None, pmax)
      par = self.check_par(par, pmin, pmax, fn, lineno)
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
    lineno = 0
    is_import = False
    directive = re.compile(r'^\s*#\.(?P<name>[A-Z_][A-Z_0-9]*)(\s+|$)')
    report = re.compile(r'^TABLE(?P<num>\d*)_(?P<type>HDR|BODY|FTR)$')
    comment = re.compile(r'^\s*#[^.]')
    empty = re.compile(r'^\s*$')
    ctx = None
    name = ''
    default_flags = 0x00
    stack = []
    while True:
      if not f.closed:
        line = f.readline()
        lineno += 1
      else:
        line = None
      if not line:
        if not f.closed:
          f.close()
        if stack:
          frec = stack.pop()
          fn, f, lineno, is_import = frec['fn'], frec['f'], frec['lineno'], frec['is_import']
          continue
        else:
          break
      if comment.search(line): continue
      result = directive.search(line)
      if result:  # directive
        rep_result = report.search(result.group('name'))
        if result.group('name') == 'END_OF_CNF':
          f.close()
        elif result.group('name') == 'OPT':
          ctx = result.group('name')
          par = get_par(line[result.end():], 0, -1, fn=fn, lineno=lineno)
          if not par: continue
          self.set_opt(par[0], par[1:], fn, lineno)
          ctx = None
        elif result.group('name') in ('PDU', 'PDU_NEW', 'REGISTER', 'REGISTER_NEW',
                                    'MODULE', 'MODULE_IMPORT',
                                    'OMIT_ASSIGNMENT', 'NO_OMIT_ASSGN',
                                    'VIRTUAL_ASSGN', 'SET_TYPE', 'ASSIGN_VALUE_TO_TYPE',
                                    'TYPE_RENAME', 'FIELD_RENAME', 'TF_RENAME', 'IMPORT_TAG',
                                    'TYPE_ATTR', 'ETYPE_ATTR', 'FIELD_ATTR', 'EFIELD_ATTR', 'SYNTAX'):
          ctx = result.group('name')
        elif result.group('name') in ('OMIT_ALL_ASSIGNMENTS', 'OMIT_ASSIGNMENTS_EXCEPT',
                                      'OMIT_ALL_TYPE_ASSIGNMENTS', 'OMIT_TYPE_ASSIGNMENTS_EXCEPT',
                                      'OMIT_ALL_VALUE_ASSIGNMENTS', 'OMIT_VALUE_ASSIGNMENTS_EXCEPT'):
          ctx = result.group('name')
          key = '*'
          if ctx in ('OMIT_ALL_TYPE_ASSIGNMENTS', 'OMIT_TYPE_ASSIGNMENTS_EXCEPT'):
            key += 'T'
          if ctx in ('OMIT_ALL_VALUE_ASSIGNMENTS', 'OMIT_VALUE_ASSIGNMENTS_EXCEPT'):
            key += 'V'
          par = get_par(line[result.end():], 0, 1, fn=fn, lineno=lineno)
          if par:
            key += '/' + par[0]
          self.add_item('OMIT_ASSIGNMENT', key, omit=True, fn=fn, lineno=lineno)
          if ctx in ('OMIT_ASSIGNMENTS_EXCEPT', 'OMIT_TYPE_ASSIGNMENTS_EXCEPT', 'OMIT_VALUE_ASSIGNMENTS_EXCEPT'):
            ctx = 'NO_OMIT_ASSGN'
          else:
            ctx = None
        elif result.group('name') in ('EXPORTS', 'MODULE_EXPORTS', 'USER_DEFINED', 'NO_EMIT'):
          ctx = result.group('name')
          default_flags = EF_TYPE|EF_VALS
          if ctx == 'MODULE_EXPORTS':
            ctx = 'EXPORTS'
            default_flags |= EF_MODULE
          if ctx == 'EXPORTS':
            par = get_par(line[result.end():], 0, 5, fn=fn, lineno=lineno)
          else:
            par = get_par(line[result.end():], 0, 1, fn=fn, lineno=lineno)
          if not par: continue
          p = 1
          if (par[0] == 'WITH_VALS'):      default_flags |= EF_TYPE|EF_VALS
          elif (par[0] == 'WITHOUT_VALS'): default_flags |= EF_TYPE; default_flags &= ~EF_TYPE
          elif (par[0] == 'ONLY_VALS'):    default_flags &= ~EF_TYPE; default_flags |= EF_VALS
          elif (ctx == 'EXPORTS'): p = 0
          else: warnings.warn_explicit("Unknown parameter value '%s'" % (par[0]), UserWarning, fn, lineno)
          for i in range(p, len(par)):
            if (par[i] == 'ONLY_ENUM'):   default_flags &= ~(EF_TYPE|EF_VALS); default_flags |= EF_ENUM
            elif (par[i] == 'WITH_ENUM'): default_flags |= EF_ENUM
            elif (par[i] == 'VALS_WITH_TABLE'):  default_flags |= EF_TABLE
            elif (par[i] == 'WS_VAR'):    default_flags |= EF_WS_VAR
            elif (par[i] == 'EXTERN'):    default_flags |= EF_EXTERN
            elif (par[i] == 'NO_PROT_PREFIX'): default_flags |= EF_NO_PROT
            else: warnings.warn_explicit("Unknown parameter value '%s'" % (par[i]), UserWarning, fn, lineno)
        elif result.group('name') in ('MAKE_ENUM', 'MAKE_DEFINES'):
          ctx = result.group('name')
          default_flags = EF_ENUM
          if ctx == 'MAKE_ENUM': default_flags |= EF_NO_PROT|EF_NO_TYPE
          if ctx == 'MAKE_DEFINES': default_flags |= EF_DEFINE|EF_UCASE|EF_NO_TYPE
          par = get_par(line[result.end():], 0, 3, fn=fn, lineno=lineno)
          for i in range(0, len(par)):
            if (par[i] == 'NO_PROT_PREFIX'):   default_flags |= EF_NO_PROT
            elif (par[i] == 'PROT_PREFIX'):    default_flags &= ~ EF_NO_PROT
            elif (par[i] == 'NO_TYPE_PREFIX'): default_flags |= EF_NO_TYPE
            elif (par[i] == 'TYPE_PREFIX'):    default_flags &= ~ EF_NO_TYPE
            elif (par[i] == 'UPPER_CASE'):     default_flags |= EF_UCASE
            elif (par[i] == 'NO_UPPER_CASE'):  default_flags &= ~EF_UCASE
            else: warnings.warn_explicit("Unknown parameter value '%s'" % (par[i]), UserWarning, fn, lineno)
        elif result.group('name') == 'USE_VALS_EXT':
          ctx = result.group('name')
          default_flags = 0xFF
        elif result.group('name') == 'FN_HDR':
          minp = 1
          if (ctx in ('FN_PARS',)) and name: minp = 0
          par = get_par(line[result.end():], minp, 1, fn=fn, lineno=lineno)
          if (not par) and (minp > 0): continue
          ctx = result.group('name')
          if par: name = par[0]
        elif result.group('name') == 'FN_FTR':
          minp = 1
          if (ctx in ('FN_PARS','FN_HDR')) and name: minp = 0
          par = get_par(line[result.end():], minp, 1, fn=fn, lineno=lineno)
          if (not par) and (minp > 0): continue
          ctx = result.group('name')
          if par: name = par[0]
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
          elif len(par) == 1:
            name = par[0]
            self.add_item(ctx, name, pars={}, fn=fn, lineno=lineno)
          elif len(par) > 1:
            self.add_item(ctx, par[0], pars=par[1], fn=fn, lineno=lineno)
            ctx = None
        elif result.group('name') == 'CLASS':
          par = get_par(line[result.end():], 1, 1, fn=fn, lineno=lineno)
          if not par: continue
          ctx = result.group('name')
          name = par[0]
          add_class_ident(name)
          if not name.split('$')[-1].isupper():
            warnings.warn_explicit("No lower-case letters shall be included in information object class name (%s)" % (name),
                                    UserWarning, fn, lineno)
        elif result.group('name') == 'ASSIGNED_OBJECT_IDENTIFIER':
          par = get_par(line[result.end():], 1, 1, fn=fn, lineno=lineno)
          if not par: continue
          self.update_item('ASSIGNED_ID', 'OBJECT_IDENTIFIER', ids={par[0] : par[0]}, fn=fn, lineno=lineno)
        elif rep_result:  # Reports
          num = rep_result.group('num')
          type = rep_result.group('type')
          if type == 'BODY':
            par = get_par(line[result.end():], 1, 1, fn=fn, lineno=lineno)
            if not par: continue
          else:
            par = get_par(line[result.end():], 0, 0, fn=fn, lineno=lineno)
          rep = { 'type' : type, 'var' : None, 'text' : '', 'fn' : fn, 'lineno' : lineno }
          if len(par) > 0:
            rep['var'] = par[0]
          self.report.setdefault(num, []).append(rep)
          ctx = 'TABLE'
          name = num
        elif result.group('name') in ('INCLUDE', 'IMPORT') :
          is_imp = result.group('name') == 'IMPORT'
          par = get_par(line[result.end():], 1, 1, fn=fn, lineno=lineno)
          if not par:
            warnings.warn_explicit("%s requires parameter" % (result.group('name'),), UserWarning, fn, lineno)
            continue
          fname = par[0]
          #print "Try include: %s" % (fname)
          if (not os.path.exists(fname)):
            fname = os.path.join(os.path.split(fn)[0], par[0])
          #print "Try include: %s" % (fname)
          i = 0
          while not os.path.exists(fname) and (i < len(self.include_path)):
            fname = os.path.join(self.include_path[i], par[0])
            #print "Try include: %s" % (fname)
            i += 1
          if (not os.path.exists(fname)):
            if is_imp:
              continue  # just ignore
            else:
              fname = par[0]  # report error
          fnew = open(fname, "r")
          stack.append({'fn' : fn, 'f' : f, 'lineno' : lineno, 'is_import' : is_import})
          fn, f, lineno, is_import = par[0], fnew, 0, is_imp
        elif result.group('name') == 'END':
          ctx = None
        else:
          warnings.warn_explicit("Unknown directive '%s'" % (result.group('name')), UserWarning, fn, lineno)
        continue
      if not ctx:
        if not empty.match(line):
          warnings.warn_explicit("Non-empty line in empty context", UserWarning, fn, lineno)
      elif ctx == 'OPT':
        if empty.match(line): continue
        par = get_par(line, 1, -1, fn=fn, lineno=lineno)
        if not par: continue
        self.set_opt(par[0], par[1:], fn, lineno)
      elif ctx in ('EXPORTS', 'USER_DEFINED', 'NO_EMIT'):
        if empty.match(line): continue
        if ctx == 'EXPORTS':
          par = get_par(line, 1, 6, fn=fn, lineno=lineno)
        else:
          par = get_par(line, 1, 2, fn=fn, lineno=lineno)
        if not par: continue
        flags = default_flags
        p = 2
        if (len(par)>=2):
          if (par[1] == 'WITH_VALS'):      flags |= EF_TYPE|EF_VALS
          elif (par[1] == 'WITHOUT_VALS'): flags |= EF_TYPE; flags &= ~EF_TYPE
          elif (par[1] == 'ONLY_VALS'):    flags &= ~EF_TYPE; flags |= EF_VALS
          elif (ctx == 'EXPORTS'): p = 1
          else: warnings.warn_explicit("Unknown parameter value '%s'" % (par[1]), UserWarning, fn, lineno)
        for i in range(p, len(par)):
          if (par[i] == 'ONLY_ENUM'):        flags &= ~(EF_TYPE|EF_VALS); flags |= EF_ENUM
          elif (par[i] == 'WITH_ENUM'):      flags |= EF_ENUM
          elif (par[i] == 'VALS_WITH_TABLE'):  flags |= EF_TABLE
          elif (par[i] == 'WS_VAR'):         flags |= EF_WS_VAR
          elif (par[i] == 'EXTERN'):         flags |= EF_EXTERN
          elif (par[i] == 'NO_PROT_PREFIX'): flags |= EF_NO_PROT
          else: warnings.warn_explicit("Unknown parameter value '%s'" % (par[i]), UserWarning, fn, lineno)
        self.add_item(ctx, par[0], flag=flags, fn=fn, lineno=lineno)
      elif ctx in ('MAKE_ENUM', 'MAKE_DEFINES'):
        if empty.match(line): continue
        par = get_par(line, 1, 4, fn=fn, lineno=lineno)
        if not par: continue
        flags = default_flags
        for i in range(1, len(par)):
          if (par[i] == 'NO_PROT_PREFIX'):   flags |= EF_NO_PROT
          elif (par[i] == 'PROT_PREFIX'):    flags &= ~ EF_NO_PROT
          elif (par[i] == 'NO_TYPE_PREFIX'): flags |= EF_NO_TYPE
          elif (par[i] == 'TYPE_PREFIX'):    flags &= ~ EF_NO_TYPE
          elif (par[i] == 'UPPER_CASE'):     flags |= EF_UCASE
          elif (par[i] == 'NO_UPPER_CASE'):  flags &= ~EF_UCASE
          else: warnings.warn_explicit("Unknown parameter value '%s'" % (par[i]), UserWarning, fn, lineno)
        self.add_item('MAKE_ENUM', par[0], flag=flags, fn=fn, lineno=lineno)
      elif ctx == 'USE_VALS_EXT':
        if empty.match(line): continue
        par = get_par(line, 1, 1, fn=fn, lineno=lineno)
        if not par: continue
        flags = default_flags
        self.add_item('USE_VALS_EXT', par[0], flag=flags, fn=fn, lineno=lineno)
      elif ctx in ('PDU', 'PDU_NEW'):
        if empty.match(line): continue
        par = get_par(line, 1, 5, fn=fn, lineno=lineno)
        if not par: continue
        is_new = False
        if (ctx == 'PDU_NEW'): is_new = True
        self.add_pdu(par[0:2], is_new, fn, lineno)
        if (len(par)>=3):
          self.add_register(par[0], par[2:5], fn, lineno)
      elif ctx in ('SYNTAX'):
        if empty.match(line): continue
        par = get_par(line, 1, 2, fn=fn, lineno=lineno)
        if not par: continue
        if not self.check_item('PDU', par[0]):
          self.add_pdu(par[0:1], False, fn, lineno)
        self.add_syntax(par, fn, lineno)
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
        self.add_item(ctx, par[0], ttag=(par[1], par[2]), fn=fn, lineno=lineno)
      elif ctx == 'OMIT_ASSIGNMENT':
        if empty.match(line): continue
        par = get_par(line, 1, 1, fn=fn, lineno=lineno)
        if not par: continue
        self.add_item(ctx, par[0], omit=True, fn=fn, lineno=lineno)
      elif ctx == 'NO_OMIT_ASSGN':
        if empty.match(line): continue
        par = get_par(line, 1, 1, fn=fn, lineno=lineno)
        if not par: continue
        self.add_item(ctx, par[0], omit=False, fn=fn, lineno=lineno)
      elif ctx == 'VIRTUAL_ASSGN':
        if empty.match(line): continue
        par = get_par(line, 2, -1, fn=fn, lineno=lineno)
        if not par: continue
        if (len(par[1].split('/')) > 1) and not self.check_item('SET_TYPE', par[1]):
          self.add_item('SET_TYPE', par[1], type=par[0], fn=fn, lineno=lineno)
        self.add_item('VIRTUAL_ASSGN', par[1], name=par[0], fn=fn, lineno=lineno)
        for nm in par[2:]:
          self.add_item('SET_TYPE', nm, type=par[0], fn=fn, lineno=lineno)
        if not par[0][0].isupper():
          warnings.warn_explicit("Virtual assignment should have uppercase name (%s)" % (par[0]),
                                  UserWarning, fn, lineno)
      elif ctx == 'SET_TYPE':
        if empty.match(line): continue
        par = get_par(line, 2, 2, fn=fn, lineno=lineno)
        if not par: continue
        if not self.check_item('VIRTUAL_ASSGN', par[0]):
          self.add_item('SET_TYPE', par[0], type=par[1], fn=fn, lineno=lineno)
        if not par[1][0].isupper():
          warnings.warn_explicit("Set type should have uppercase name (%s)" % (par[1]),
                                  UserWarning, fn, lineno)
      elif ctx == 'ASSIGN_VALUE_TO_TYPE':
        if empty.match(line): continue
        par = get_par(line, 2, 2, fn=fn, lineno=lineno)
        if not par: continue
        self.add_item(ctx, par[0], name=par[1], fn=fn, lineno=lineno)
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
      elif ctx == 'TF_RENAME':
        if empty.match(line): continue
        par = get_par(line, 2, 2, fn=fn, lineno=lineno)
        if not par: continue
        tmpu = par[1][0].upper() + par[1][1:]
        tmpl = par[1][0].lower() + par[1][1:]
        self.add_item('TYPE_RENAME', par[0], eth_name=tmpu, fn=fn, lineno=lineno)
        if not tmpu[0].isupper():
          warnings.warn_explicit("Type should be renamed to uppercase name (%s)" % (par[1]),
                                  UserWarning, fn, lineno)
        self.add_item('FIELD_RENAME', par[0], eth_name=tmpl, fn=fn, lineno=lineno)
        if not tmpl[0].islower():
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
          self.update_item(ctx, name, pars=par[0], fn=fn, lineno=lineno)
        else:
          self.add_item(ctx, par[0], pars=par[1], fn=fn, lineno=lineno)
      elif ctx in ('FN_HDR', 'FN_FTR', 'FN_BODY'):
        self.add_fn_line(name, ctx, line, fn=fn, lineno=lineno)
      elif ctx == 'CLASS':
        if empty.match(line): continue
        par = get_par(line, 1, 3, fn=fn, lineno=lineno)
        if not par: continue
        if not set_type_to_class(name, par[0], par[1:]):
          warnings.warn_explicit("Could not set type of class member %s.&%s to %s" % (name, par[0], par[1]),
                                  UserWarning, fn, lineno)
      elif ctx == 'TABLE':
        self.report[name][-1]['text'] += line

  def set_opt(self, opt, par, fn, lineno):
    #print "set_opt: %s, %s" % (opt, par)
    if opt in ("-I",):
      par = self.check_par(par, 1, 1, fn, lineno)
      if not par: return
      self.include_path.append(par[0])
    elif opt in ("-b", "BER", "CER", "DER"):
      par = self.check_par(par, 0, 0, fn, lineno)
      self.ectx.encoding = 'ber'
    elif opt in ("PER",):
      par = self.check_par(par, 0, 0, fn, lineno)
      self.ectx.encoding = 'per'
    elif opt in ("-p", "PROTO"):
      par = self.check_par(par, 1, 1, fn, lineno)
      if not par: return
      self.ectx.proto_opt = par[0]
      self.ectx.merge_modules = True
    elif opt in ("ALIGNED",):
      par = self.check_par(par, 0, 0, fn, lineno)
      self.ectx.aligned = True
    elif opt in ("-u", "UNALIGNED"):
      par = self.check_par(par, 0, 0, fn, lineno)
      self.ectx.aligned = False
    elif opt in ("-d",):
      par = self.check_par(par, 1, 1, fn, lineno)
      if not par: return
      self.ectx.dbgopt = par[0]
    elif opt in ("-e",):
      par = self.check_par(par, 0, 0, fn, lineno)
      self.ectx.expcnf = True
    elif opt in ("-S",):
      par = self.check_par(par, 0, 0, fn, lineno)
      self.ectx.merge_modules = True
    elif opt in ("GROUP_BY_PROT",):
      par = self.check_par(par, 0, 0, fn, lineno)
      self.ectx.group_by_prot = True
    elif opt in ("-o",):
      par = self.check_par(par, 1, 1, fn, lineno)
      if not par: return
      self.ectx.outnm_opt = par[0]
    elif opt in ("-O",):
      par = self.check_par(par, 1, 1, fn, lineno)
      if not par: return
      self.ectx.output.outdir = par[0]
    elif opt in ("-s",):
      par = self.check_par(par, 1, 1, fn, lineno)
      if not par: return
      self.ectx.output.single_file = par[0]
    elif opt in ("-k",):
      par = self.check_par(par, 0, 0, fn, lineno)
      self.ectx.output.keep = True
    elif opt in ("-L",):
      par = self.check_par(par, 0, 0, fn, lineno)
      self.suppress_line = True
    elif opt in ("EMBEDDED_PDV_CB",):
      par = self.check_par(par, 1, 1, fn, lineno)
      if not par: return
      self.ectx.default_embedded_pdv_cb = par[0]
    elif opt in ("EXTERNAL_TYPE_CB",):
      par = self.check_par(par, 1, 1, fn, lineno)
      if not par: return
      self.ectx.default_external_type_cb = par[0]
    elif opt in ("-r",):
      par = self.check_par(par, 1, 1, fn, lineno)
      if not par: return
      self.ectx.remove_prefix = par[0]
    else:
      warnings.warn_explicit("Unknown option %s" % (opt),
                             UserWarning, fn, lineno)

  def dbg_print(self):
    print "\n# Conformance values"
    print "%-15s %-4s %-15s %-20s %s" % ("File", "Line", "Table", "Key", "Value")
    print "-" * 100
    tbls = sorted(self.table.keys())
    for t in tbls:
      keys = sorted(self.table[t].keys())
      for k in keys:
        print "%-15s %4s %-15s %-20s %s" % (
              self.table[t][k]['fn'], self.table[t][k]['lineno'], t, k, str(self.table[t][k][self.tblcfg[t]['val_nm']]))

  def unused_report(self):
    tbls = sorted(self.table.keys())
    for t in tbls:
      if not self.tblcfg[t]['chk_use']: continue
      keys = sorted(self.table[t].keys())
      for k in keys:
        if not self.table[t][k]['used']:
          warnings.warn_explicit("Unused %s for %s" % (t, k),
                                  UserWarning, self.table[t][k]['fn'], self.table[t][k]['lineno'])
    fnms = list(self.fn.keys())
    fnms.sort()
    for f in fnms:
      keys = sorted(self.fn[f].keys())
      for k in keys:
        if not self.fn[f][k]: continue
        if not self.fn[f][k]['used']:
          warnings.warn_explicit("Unused %s for %s" % (k, f),
                                  UserWarning, self.fn[f][k]['fn'], self.fn[f][k]['lineno'])

#--- EthOut -------------------------------------------------------------------
class EthOut:
  def __init__(self):
    self.ectx = None
    self.outnm = None
    self.outdir = '.'
    self.single_file = None
    self.created_files = {}
    self.created_files_ord = []
    self.keep = False

  def outcomment(self, ln, comment=None):
    if comment:
      return '%s %s\n' % (comment, ln)
    else:
      return '/* %-74s */\n' % (ln)

  def created_file_add(self, name, keep_anyway):
    name = os.path.normcase(os.path.abspath(name))
    if name not in self.created_files:
      self.created_files_ord.append(name)
      self.created_files[name] = keep_anyway
    else:
      self.created_files[name] = self.created_files[name] or keep_anyway

  def created_file_exists(self, name):
    name = os.path.normcase(os.path.abspath(name))
    return name in self.created_files

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
    if self.created_file_exists(fn):
      fx = file(fn, 'a')
    else:
      fx = file(fn, 'w')
    comment = None
    if ext in ('cnf',):
      comment = '#'
      fx.write(self.fhdr(fn, comment = comment))
    else:
      if (not self.single_file and not self.created_file_exists(fn)):
        fx.write(self.fhdr(fn))
    if not self.ectx.merge_modules:
      fx.write('\n')
      mstr = "--- "
      if self.ectx.groups():
        mstr += "Module"
        if (len(self.ectx.modules) > 1):
          mstr += "s"
        for (m, p) in self.ectx.modules:
          mstr += " %s" % (m)
      else:
        mstr += "Module %s" % (self.ectx.Module())
      mstr += " --- --- ---"
      fx.write(self.outcomment(mstr, comment))
      fx.write('\n')
    return fx
  #--- file_close -------------------------------------------------------
  def file_close(self, fx, discard=False, keep_anyway=False):
    fx.close()
    if discard and not self.created_file_exists(fx.name):
      os.unlink(fx.name)
    else:
      self.created_file_add(fx.name, keep_anyway)
  #--- fhdr -------------------------------------------------------
  def fhdr(self, fn, comment=None):
    out = ''
    out += self.outcomment('Do not modify this file.', comment)
    out += self.outcomment('It is created automatically by the ASN.1 to Wireshark dissector compiler', comment)
    out += self.outcomment(os.path.basename(fn), comment)
    out += self.outcomment(' '.join(sys.argv), comment)
    out += '\n'
    # Make Windows path separator look like Unix path separator
    return out.replace('\\', '/')

  #--- dbg_print -------------------------------------------------------
  def dbg_print(self):
    print "\n# Output files"
    print "\n".join(self.created_files_ord)
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
      for fn in self.created_files_ord:
        if not self.created_files[fn]:
          os.unlink(fn)

  #--- do_include -------------------------------------------------------
  def do_include(self, out_nm, in_nm):
    def check_file(fn, fnlist):
      fnfull = os.path.normcase(os.path.abspath(fn))
      if (fnfull in fnlist and os.path.exists(fnfull)):
        return os.path.normpath(fn)
      return None
    fin = file(in_nm, "r")
    fout = file(out_nm, "w")
    fout.write(self.fhdr(out_nm))
    fout.write('/* Input file: ' + os.path.basename(in_nm) +' */\n')
    fout.write('\n')
    fout.write('#line %u "%s"\n' % (1, rel_dissector_path(in_nm)))

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
        fout.write('#line %u "%s"\n' % (1, rel_dissector_path(ifile)))
        finc = file(ifile, "r")
        fout.write(finc.read())
        fout.write('\n')
        fout.write('/*--- End of included file: ' + ifile + ' ---*/\n')
        fout.write('#line %u "%s"\n' % (cont_linenum+1, rel_dissector_path(in_nm)) )
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
        if isinstance(child, type ([])):
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
                                list(self.__dict__.items ()))))
        return "\n".join (l)
    def __repr__(self):
        return "\n" + self.str_depth (0)
    def to_python (self, ctx):
        return self.str_depth (ctx.indent_lev)

    def eth_reg(self, ident, ectx):
        pass

    def fld_obj_repr(self, ectx):
        return "/* TO DO %s */" % (str(self))


#--- ValueAssignment -------------------------------------------------------------
class ValueAssignment (Node):
  def __init__(self,*args, **kw) :
    Node.__init__ (self,*args, **kw)

  def eth_reg(self, ident, ectx):
    if ectx.conform.omit_assignment('V', self.ident, ectx.Module()): return # Assignment to omit
    ectx.eth_reg_vassign(self)
    ectx.eth_reg_value(self.ident, self.typ, self.val)

#--- ObjectAssignment -------------------------------------------------------------
class ObjectAssignment (Node):
  def __init__(self,*args, **kw) :
    Node.__init__ (self,*args, **kw)

  def __eq__(self, other):
    if self.cls != other.cls:
      return False
    if len(self.val) != len(other.val):
      return False
    for f in (list(self.val.keys())):
      if f not in other.val:
        return False
      if isinstance(self.val[f], Node) and isinstance(other.val[f], Node):
        if not self.val[f].fld_obj_eq(other.val[f]):
          return False
      else:
        if str(self.val[f]) != str(other.val[f]):
          return False
    return True

  def eth_reg(self, ident, ectx):
    def make_virtual_type(cls, field, prefix):
      if isinstance(self.val, str): return
      if field in self.val and not isinstance(self.val[field], Type_Ref):
        vnm = prefix + '-' + self.ident
        virtual_tr = Type_Ref(val = vnm)
        t = self.val[field]
        self.val[field] = virtual_tr
        ectx.eth_reg_assign(vnm, t, virt=True)
        ectx.eth_reg_type(vnm, t)
        t.eth_reg_sub(vnm, ectx)
      if field in self.val and ectx.conform.check_item('PDU', cls + '.' + field):
        ectx.eth_reg_field(self.val[field].val, self.val[field].val, impl=self.val[field].HasImplicitTag(ectx), pdu=ectx.conform.use_item('PDU', cls + '.' + field))
      return
    # end of make_virtual_type()
    if ectx.conform.omit_assignment('V', self.ident, ectx.Module()): return # Assignment to omit
    self.module = ectx.Module()
    ectx.eth_reg_oassign(self)
    if (self.cls == 'TYPE-IDENTIFIER') or (self.cls == 'ABSTRACT-SYNTAX'):
      make_virtual_type(self.cls, '&Type', 'TYPE')
    if (self.cls == 'OPERATION'):
      make_virtual_type(self.cls, '&ArgumentType', 'ARG')
      make_virtual_type(self.cls, '&ResultType', 'RES')
    if (self.cls == 'ERROR'):
      make_virtual_type(self.cls, '&ParameterType', 'PAR')


#--- Type ---------------------------------------------------------------------
class Type (Node):
  def __init__(self,*args, **kw) :
    self.name = None
    self.constr = None
    self.tags = []
    self.named_list = None
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

  def HasSizeConstraint(self):
    return self.HasConstraint() and self.constr.IsSize()

  def HasValueConstraint(self):
    return self.HasConstraint() and self.constr.IsValue()

  def HasPermAlph(self):
    return self.HasConstraint() and self.constr.IsPermAlph()

  def HasContentsConstraint(self):
    return self.HasConstraint() and self.constr.IsContents()

  def HasOwnTag(self):
    return len(self.tags) > 0

  def HasImplicitTag(self, ectx):
    return (self.HasOwnTag() and self.tags[0].IsImplicit(ectx))

  def IndetermTag(self, ectx):
    return False

  def AddTag(self, tag):
    self.tags[0:0] = [tag]

  def GetTag(self, ectx):
    #print "GetTag(%s)\n" % self.name;
    if (self.HasOwnTag()):
      return self.tags[0].GetTag(ectx)
    else:
      return self.GetTTag(ectx)

  def GetTTag(self, ectx):
    print "#Unhandled  GetTTag() in %s" % (self.type)
    print self.str_depth(1)
    return ('BER_CLASS_unknown', 'TAG_unknown')

  def SetName(self, name):
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

  def eth_has_enum(self, tname, ectx):
    return self.eth_has_vals() and (ectx.eth_type[tname]['enum'] & EF_ENUM)

  def eth_need_pdu(self, ectx):
    return None

  def eth_named_bits(self):
    return None

  def eth_reg_sub(self, ident, ectx):
    pass

  def get_components(self, ectx):
    print "#Unhandled  get_components() in %s" % (self.type)
    print self.str_depth(1)
    return []

  def sel_req(self, sel, ectx):
    print "#Selection '%s' required for non-CHOICE type %s" % (sel, self.type)
    print self.str_depth(1)

  def fld_obj_eq(self, other):
    return isinstance(other, Type) and (self.eth_tname() == other.eth_tname())

  def eth_reg(self, ident, ectx, tstrip=0, tagflag=False, selflag=False, idx='', parent=None):
    #print "eth_reg(): %s, ident=%s, tstrip=%d, tagflag=%s, selflag=%s, parent=%s" %(self.type, ident, tstrip, str(tagflag), str(selflag), str(parent))
    #print " ", self
    if (ectx.NeedTags() and (len(self.tags) > tstrip)):
      tagged_type = self
      for i in range(len(self.tags)-1, tstrip-1, -1):
        tagged_type = TaggedType(val=tagged_type, tstrip=i)
        tagged_type.AddTag(self.tags[i])
      if not tagflag:  # 1st tagged level
        if self.IsNamed() and not selflag:
          tagged_type.SetName(self.name)
      tagged_type.eth_reg(ident, ectx, tstrip=1, tagflag=tagflag, idx=idx, parent=parent)
      return
    nm = ''
    if ident and self.IsNamed() and not tagflag and not selflag:
      nm = ident + '/' + self.name
    elif ident:
      nm = ident
    elif self.IsNamed():
      nm = self.name
    if not ident and ectx.conform.omit_assignment('T', nm, ectx.Module()): return # Assignment to omit
    if not ident:  # Assignment
      ectx.eth_reg_assign(nm, self)
      if self.type == 'Type_Ref' and not self.tr_need_own_fn(ectx):
        ectx.eth_reg_type(nm, self)
    virtual_tr = Type_Ref(val=ectx.conform.use_item('SET_TYPE', nm))
    if (self.type == 'Type_Ref') or ectx.conform.check_item('SET_TYPE', nm):
      if ident and (ectx.conform.check_item('TYPE_RENAME', nm) or ectx.conform.get_fn_presence(nm) or selflag):
        if ectx.conform.check_item('SET_TYPE', nm):
          ectx.eth_reg_type(nm, virtual_tr)  # dummy Type Reference
        else:
          ectx.eth_reg_type(nm, self)  # new type
        trnm = nm
      elif ectx.conform.check_item('SET_TYPE', nm):
        trnm = ectx.conform.use_item('SET_TYPE', nm)
      elif (self.type == 'Type_Ref') and self.tr_need_own_fn(ectx):
        ectx.eth_reg_type(nm, self)  # need own function, e.g. for constraints
        trnm = nm
      else:
        trnm = self.val
    else:
      ectx.eth_reg_type(nm, self)
      trnm = nm
    if ectx.conform.check_item('VIRTUAL_ASSGN', nm):
      vnm = ectx.conform.use_item('VIRTUAL_ASSGN', nm)
      ectx.eth_reg_assign(vnm, self, virt=True)
      ectx.eth_reg_type(vnm, self)
      self.eth_reg_sub(vnm, ectx)
    if parent and (ectx.type[parent]['val'].type == 'TaggedType'):
      ectx.type[parent]['val'].eth_set_val_name(parent, trnm, ectx)
    if ident and not tagflag:
      ectx.eth_reg_field(nm, trnm, idx=idx, parent=parent, impl=self.HasImplicitTag(ectx))
    if ectx.conform.check_item('SET_TYPE', nm):
      virtual_tr.eth_reg_sub(nm, ectx)
    else:
      self.eth_reg_sub(nm, ectx)

  def eth_get_size_constr(self, ectx):
    (minv, maxv, ext) = ('MIN', 'MAX', False)
    if self.HasSizeConstraint():
      if self.constr.IsSize():
        (minv, maxv, ext) = self.constr.GetSize(ectx)
      if (self.constr.type == 'Intersection'):
        if self.constr.subtype[0].IsSize():
          (minv, maxv, ext) = self.constr.subtype[0].GetSize(ectx)
        elif self.constr.subtype[1].IsSize():
          (minv, maxv, ext) = self.constr.subtype[1].GetSize(ectx)
    if minv == 'MIN': minv = 'NO_BOUND'
    if maxv == 'MAX': maxv = 'NO_BOUND'
    if (ext): ext = 'TRUE'
    else: ext = 'FALSE'
    return (minv, maxv, ext)

  def eth_get_value_constr(self, ectx):
    (minv, maxv, ext) = ('MIN', 'MAX', False)
    if self.HasValueConstraint():
      (minv, maxv, ext) = self.constr.GetValue(ectx)
    if minv == 'MIN': minv = 'NO_BOUND'
    if maxv == 'MAX': maxv = 'NO_BOUND'
    if str(minv).isdigit():
      minv += 'U'
    elif (str(minv)[0] == "-") and str(minv)[1:].isdigit():
      if (long(minv) < -(2**31)):
        minv = "G_GINT64_CONSTANT(%s)" % (str(minv))
    if str(maxv).isdigit():
      if (long(maxv) >= 2**32):
        maxv = "G_GINT64_CONSTANT(%sU)" % (str(maxv))
      else:
        maxv += 'U'
    if (ext): ext = 'TRUE'
    else: ext = 'FALSE'
    return (minv, maxv, ext)

  def eth_get_alphabet_constr(self, ectx):
    (alph, alphlen) = ('NULL', '0')
    if self.HasPermAlph():
      alph = self.constr.GetPermAlph(ectx)
      if not alph:
        alph = 'NULL'
      if (alph != 'NULL'):
        if (((alph[0] + alph[-1]) == '""') and (not alph.count('"', 1, -1))):
          alphlen = str(len(alph) - 2)
        else:
          alphlen = 'strlen(%s)' % (alph)
    return (alph, alphlen)

  def eth_type_vals(self, tname, ectx):
    if self.eth_has_vals():
      print "#Unhandled  eth_type_vals('%s') in %s" % (tname, self.type)
      print self.str_depth(1)
    return ''

  def eth_type_enum(self, tname, ectx):
    if self.eth_has_enum(tname, ectx):
      print "#Unhandled  eth_type_enum('%s') in %s" % (tname, self.type)
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
      'TREE' : 'tree',
      'TVB' : 'tvb',
      'OFFSET' : 'offset',
      'ACTX' : 'actx',
      'HF_INDEX' : 'hf_index',
      'VAL_PTR' : 'NULL',
      'IMPLICIT_TAG' : 'implicit_tag',
    }
    if (ectx.eth_type[tname]['tree']):
      pars['ETT_INDEX'] = ectx.eth_type[tname]['tree']
    if (ectx.merge_modules):
      pars['PROTOP'] = ''
    else:
      pars['PROTOP'] = ectx.eth_type[tname]['proto'] + '_'
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
      for k in list(pars.keys()):
        try:
          pars[k] = pars[k] % pars
        except (ValueError,TypeError):
          raise sys.exc_info()[0], "%s\n%s" % (str(pars), sys.exc_info()[1])
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

  def to_str(self, ectx):
    return str(self.val)

  def get_dep(self):
    return None

  def fld_obj_repr(self, ectx):
    return self.to_str(ectx)

#--- Value_Ref -----------------------------------------------------------------
class Value_Ref (Value):
  def to_str(self, ectx):
    return asn2c(self.val)

#--- ObjectClass ---------------------------------------------------------------------
class ObjectClass (Node):
  def __init__(self,*args, **kw) :
    self.name = None
    Node.__init__ (self,*args, **kw)

  def SetName(self, name):
    self.name = name
    add_class_ident(self.name)

  def eth_reg(self, ident, ectx):
    if ectx.conform.omit_assignment('C', self.name, ectx.Module()): return # Assignment to omit
    ectx.eth_reg_objectclass(self.name, self)

#--- Class_Ref -----------------------------------------------------------------
class Class_Ref (ObjectClass):
  pass

#--- ObjectClassDefn ---------------------------------------------------------------------
class ObjectClassDefn (ObjectClass):
  def reg_types(self):
    for fld in self.fields:
      repr = fld.fld_repr()
      set_type_to_class(self.name, repr[0], repr[1:])


#--- Tag ---------------------------------------------------------------
class Tag (Node):
  def to_python (self, ctx):
    return 'asn1.TYPE(%s,%s)' % (mk_tag_str (ctx, self.tag.cls,
                                                self.tag_typ,
                                                self.tag.num),
                                    self.typ.to_python (ctx))
  def IsImplicit(self, ectx):
    return ((self.mode == 'IMPLICIT') or ((self.mode == 'default') and (ectx.tag_def != 'EXPLICIT')))

  def GetTag(self, ectx):
    tc = ''
    if (self.cls == 'UNIVERSAL'): tc = 'BER_CLASS_UNI'
    elif (self.cls == 'APPLICATION'): tc = 'BER_CLASS_APP'
    elif (self.cls == 'CONTEXT'): tc = 'BER_CLASS_CON'
    elif (self.cls == 'PRIVATE'): tc = 'BER_CLASS_PRI'
    return (tc, self.num)

  def eth_tname(self):
    n = ''
    if (self.cls == 'UNIVERSAL'): n = 'U'
    elif (self.cls == 'APPLICATION'): n = 'A'
    elif (self.cls == 'CONTEXT'): n = 'C'
    elif (self.cls == 'PRIVATE'): n = 'P'
    return n + str(self.num)

#--- Constraint ---------------------------------------------------------------
constr_cnt = 0
class Constraint (Node):
  def to_python (self, ctx):
    print "Ignoring constraint:", self.type
    return self.subtype.typ.to_python (ctx)
  def __str__ (self):
    return "Constraint: type=%s, subtype=%s" % (self.type, self.subtype)

  def eth_tname(self):
    return '#' + self.type + '_' + str(id(self))

  def IsSize(self):
    return (self.type == 'Size' and self.subtype.IsValue()) \
           or (self.type == 'Intersection' and (self.subtype[0].IsSize() or self.subtype[1].IsSize())) \

  def GetSize(self, ectx):
    (minv, maxv, ext) = ('MIN', 'MAX', False)
    if self.IsSize():
      if self.type == 'Size':
        (minv, maxv, ext) = self.subtype.GetValue(ectx)
      elif self.type == 'Intersection':
        if self.subtype[0].IsSize() and not self.subtype[1].IsSize():
          (minv, maxv, ext) = self.subtype[0].GetSize(ectx)
        elif not self.subtype[0].IsSize() and self.subtype[1].IsSize():
          (minv, maxv, ext) = self.subtype[1].GetSize(ectx)
    return (minv, maxv, ext)

  def IsValue(self):
    return self.type == 'SingleValue' \
           or self.type == 'ValueRange' \
           or (self.type == 'Intersection' and (self.subtype[0].IsValue() or self.subtype[1].IsValue())) \
           or (self.type == 'Union' and (self.subtype[0].IsValue() and self.subtype[1].IsValue()))

  def GetValue(self, ectx):
    (minv, maxv, ext) = ('MIN', 'MAX', False)
    if self.IsValue():
      if self.type == 'SingleValue':
        minv = ectx.value_get_eth(self.subtype)
        maxv = ectx.value_get_eth(self.subtype)
        ext = hasattr(self, 'ext') and self.ext
      elif self.type == 'ValueRange':
        minv = ectx.value_get_eth(self.subtype[0])
        maxv = ectx.value_get_eth(self.subtype[1])
        ext = hasattr(self, 'ext') and self.ext
      elif self.type == 'Intersection':
        if self.subtype[0].IsValue() and not self.subtype[1].IsValue():
          (minv, maxv, ext) = self.subtype[0].GetValue(ectx)
        elif not self.subtype[0].IsValue() and self.subtype[1].IsValue():
          (minv, maxv, ext) = self.subtype[1].GetValue(ectx)
        elif self.subtype[0].IsValue() and self.subtype[1].IsValue():
          v0 = self.subtype[0].GetValue(ectx)
          v1 = self.subtype[1].GetValue(ectx)
          (minv, maxv, ext) = (ectx.value_max(v0[0],v1[0]), ectx.value_min(v0[1],v1[1]), v0[2] and v1[2])
      elif self.type == 'Union':
        if self.subtype[0].IsValue() and self.subtype[1].IsValue():
          v0 = self.subtype[0].GetValue(ectx)
          v1 = self.subtype[1].GetValue(ectx)
          (minv, maxv, ext) = (ectx.value_min(v0[0],v1[0]), ectx.value_max(v0[1],v1[1]), v0[2] or v1[2])
    return (minv, maxv, ext)

  def IsAlphabet(self):
    return self.type == 'SingleValue' \
           or self.type == 'ValueRange' \
           or (self.type == 'Intersection' and (self.subtype[0].IsAlphabet() or self.subtype[1].IsAlphabet())) \
           or (self.type == 'Union' and (self.subtype[0].IsAlphabet() and self.subtype[1].IsAlphabet()))

  def GetAlphabet(self, ectx):
    alph = None
    if self.IsAlphabet():
      if self.type == 'SingleValue':
        alph = ectx.value_get_eth(self.subtype)
      elif self.type == 'ValueRange':
        if ((len(self.subtype[0]) == 3) and ((self.subtype[0][0] + self.subtype[0][-1]) == '""') \
            and (len(self.subtype[1]) == 3) and ((self.subtype[1][0] + self.subtype[1][-1]) == '""')):
          alph = '"'
          for c in range(ord(self.subtype[0][1]), ord(self.subtype[1][1]) + 1):
            alph += chr(c)
          alph += '"'
      elif self.type == 'Union':
        if self.subtype[0].IsAlphabet() and self.subtype[1].IsAlphabet():
          a0 = self.subtype[0].GetAlphabet(ectx)
          a1 = self.subtype[1].GetAlphabet(ectx)
          if (((a0[0] + a0[-1]) == '""') and not a0.count('"', 1, -1) \
              and ((a1[0] + a1[-1]) == '""') and not a1.count('"', 1, -1)):
            alph = '"' + a0[1:-1] + a1[1:-1] + '"'
          else:
            alph = a0 + ' ' + a1
    return alph

  def IsPermAlph(self):
    return self.type == 'From' and self.subtype.IsAlphabet() \
           or (self.type == 'Intersection' and (self.subtype[0].IsPermAlph() or self.subtype[1].IsPermAlph())) \

  def GetPermAlph(self, ectx):
    alph = None
    if self.IsPermAlph():
      if self.type == 'From':
        alph = self.subtype.GetAlphabet(ectx)
      elif self.type == 'Intersection':
        if self.subtype[0].IsPermAlph() and not self.subtype[1].IsPermAlph():
          alph = self.subtype[0].GetPermAlph(ectx)
        elif not self.subtype[0].IsPermAlph() and self.subtype[1].IsPermAlph():
          alph = self.subtype[1].GetPermAlph(ectx)
    return alph

  def IsContents(self):
    return self.type == 'Contents' \
           or (self.type == 'Intersection' and (self.subtype[0].IsContents() or self.subtype[1].IsContents())) \

  def GetContents(self, ectx):
    contents = None
    if self.IsContents():
      if self.type == 'Contents':
        if self.subtype.type == 'Type_Ref':
          contents = self.subtype.val
      elif self.type == 'Intersection':
        if self.subtype[0].IsContents() and not self.subtype[1].IsContents():
          contents = self.subtype[0].GetContents(ectx)
        elif not self.subtype[0].IsContents() and self.subtype[1].IsContents():
          contents = self.subtype[1].GetContents(ectx)
    return contents

  def IsNegativ(self):
    def is_neg(sval):
      return isinstance(sval, str) and (sval[0] == '-')
    if self.type == 'SingleValue':
      return is_neg(self.subtype)
    elif self.type == 'ValueRange':
      if self.subtype[0] == 'MIN': return True
      return is_neg(self.subtype[0])
    return False

  def eth_constrname(self):
    def int2str(val):
      if isinstance(val, Value_Ref):
        return asn2c(val.val)
      try:
        if (int(val) < 0):
          return 'M' + str(-int(val))
        else:
          return str(int(val))
      except (ValueError, TypeError):
        return asn2c(str(val))

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
      if (not hasattr(self, 'constr_num')):
        global constr_cnt
        constr_cnt += 1
        self.constr_num = constr_cnt
      return 'CONSTR%03d%s' % (self.constr_num, ext)


class Module (Node):
  def to_python (self, ctx):
    ctx.tag_def = self.tag_def.dfl_tag
    return """#%s
%s""" % (self.ident, self.body.to_python (ctx))

  def get_name(self):
    return self.ident.val

  def get_proto(self, ectx):
    if (ectx.proto):
      prot = ectx.proto
    else:
      prot = ectx.conform.use_item('MODULE', self.get_name(), val_dflt=self.get_name())
    return prot

  def to_eth(self, ectx):
    ectx.tags_def = 'EXPLICIT' # default = explicit
    ectx.proto = self.get_proto(ectx)
    ectx.tag_def = self.tag_def.dfl_tag
    ectx.eth_reg_module(self)
    self.body.to_eth(ectx)

class Module_Body (Node):
  def to_python (self, ctx):
    # XXX handle exports, imports.
    l = [x.to_python (ctx) for x in self.assign_list]
    l = [a for a in l if a != '']
    return "\n".join (l)

  def to_eth(self, ectx):
    # Exports
    ectx.eth_exports(self.exports)
    # Imports
    for i in self.imports:
      mod = i.module.val
      proto = ectx.conform.use_item('MODULE', mod, val_dflt=mod)
      ectx.eth_module_dep_add(ectx.Module(), mod)
      for s in i.symbol_list:
        if isinstance(s, Type_Ref):
          ectx.eth_import_type(s.val, mod, proto)
        elif isinstance(s, Value_Ref):
          ectx.eth_import_value(s.val, mod, proto)
        elif isinstance(s, Class_Ref):
          ectx.eth_import_class(s.val, mod, proto)
        else:
          msg = 'Unknown kind of imported symbol %s from %s' % (str(s), mod)
          warnings.warn_explicit(msg, UserWarning, '', 0)
    # AssignmentList
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
    for (a, val) in list(node.__dict__.items ()):
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
        depend_list = list(dep_dict.keys ())
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
    if self.HasSizeConstraint():
      return asn2c(self.val) + '_' + self.constr.eth_constrname()
    else:
      return asn2c(self.val)

  def tr_need_own_fn(self, ectx):
    return ectx.Per() and self.HasSizeConstraint()

  def fld_obj_repr(self, ectx):
    return self.val

  def get_components(self, ectx):
    if self.val not in ectx.type or ectx.type[self.val]['import']:
      msg = "Can not get COMPONENTS OF %s which is imported type" % (self.val)
      warnings.warn_explicit(msg, UserWarning, '', 0)
      return []
    else:
      return ectx.type[self.val]['val'].get_components(ectx)

  def GetTTag(self, ectx):
    #print "GetTTag(%s)\n" % self.val;
    if (ectx.type[self.val]['import']):
      if 'ttag' not in ectx.type[self.val]:
        ttag = ectx.get_ttag_from_all(self.val, ectx.type[self.val]['import'])
        if not ttag and not ectx.conform.check_item('IMPORT_TAG', self.val):
          msg = 'Missing tag information for imported type %s from %s (%s)' % (self.val, ectx.type[self.val]['import'], ectx.type[self.val]['proto'])
          warnings.warn_explicit(msg, UserWarning, '', 0)
          ttag = ('-1/*imported*/', '-1/*imported*/')
        ectx.type[self.val]['ttag'] = ectx.conform.use_item('IMPORT_TAG', self.val, val_dflt=ttag)
      return ectx.type[self.val]['ttag']
    else:
      return ectx.type[self.val]['val'].GetTag(ectx)

  def IndetermTag(self, ectx):
    if (ectx.type[self.val]['import']):
      return False
    else:
      return ectx.type[self.val]['val'].IndetermTag(ectx)

  def eth_type_default_pars(self, ectx, tname):
    if tname:
      pars = Type.eth_type_default_pars(self, ectx, tname)
    else:
      pars = {}
    t = ectx.type[self.val]['ethname']
    pars['TYPE_REF_PROTO'] = ectx.eth_type[t]['proto']
    pars['TYPE_REF_TNAME'] = t
    pars['TYPE_REF_FN'] = 'dissect_%(TYPE_REF_PROTO)s_%(TYPE_REF_TNAME)s'
    if self.HasSizeConstraint():
      (pars['MIN_VAL'], pars['MAX_VAL'], pars['EXT']) = self.eth_get_size_constr(ectx)
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('%(TYPE_REF_FN)s', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),))
    elif (ectx.Per()):
      if self.HasSizeConstraint():
        body = ectx.eth_fn_call('dissect_%(ER)s_size_constrained_type', ret='offset',
                                par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s', '%(TYPE_REF_FN)s',),
                                     ('"%(TYPE_REF_TNAME)s"', '%(MIN_VAL)s', '%(MAX_VAL)s', '%(EXT)s',),))
      else:
        body = ectx.eth_fn_call('%(TYPE_REF_FN)s', ret='offset',
                                par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- SelectionType ------------------------------------------------------------
class SelectionType (Type):
  def to_python (self, ctx):
    return self.val

  def sel_of_typeref(self):
    return self.typ.type == 'Type_Ref'

  def eth_reg_sub(self, ident, ectx):
    if not self.sel_of_typeref():
      self.seltype = ''
      return
    self.seltype = ectx.eth_sel_req(self.typ.val, self.sel)
    ectx.eth_dep_add(ident, self.seltype)

  def eth_ftype(self, ectx):
    (ftype, display) = ('FT_NONE', 'BASE_NONE')
    if self.sel_of_typeref() and not ectx.type[self.seltype]['import']:
      (ftype, display) = ectx.type[self.typ.val]['val'].eth_ftype_sel(self.sel, ectx)
    return (ftype, display)

  def GetTTag(self, ectx):
    #print "GetTTag(%s)\n" % self.seltype;
    if (ectx.type[self.seltype]['import']):
      if 'ttag' not in ectx.type[self.seltype]:
        if not ectx.conform.check_item('IMPORT_TAG', self.seltype):
          msg = 'Missing tag information for imported type %s from %s (%s)' % (self.seltype, ectx.type[self.seltype]['import'], ectx.type[self.seltype]['proto'])
          warnings.warn_explicit(msg, UserWarning, '', 0)
        ectx.type[self.seltype]['ttag'] = ectx.conform.use_item('IMPORT_TAG', self.seltype, val_dflt=('-1 /*imported*/', '-1 /*imported*/'))
      return ectx.type[self.seltype]['ttag']
    else:
      return ectx.type[self.typ.val]['val'].GetTTagSel(self.sel, ectx)

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    if self.sel_of_typeref():
      t = ectx.type[self.seltype]['ethname']
      pars['TYPE_REF_PROTO'] = ectx.eth_type[t]['proto']
      pars['TYPE_REF_TNAME'] = t
      pars['TYPE_REF_FN'] = 'dissect_%(TYPE_REF_PROTO)s_%(TYPE_REF_TNAME)s'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if not self.sel_of_typeref():
      body = '#error Can not decode %s' % (tname)
    elif (ectx.Ber()):
      body = ectx.eth_fn_call('%(TYPE_REF_FN)s', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('%(TYPE_REF_FN)s', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- TaggedType -----------------------------------------------------------------
class TaggedType (Type):
  def eth_tname(self):
    tn = ''
    for i in range(self.tstrip, len(self.val.tags)):
      tn += self.val.tags[i].eth_tname()
      tn += '_'
    tn += self.val.eth_tname()
    return tn

  def eth_set_val_name(self, ident, val_name, ectx):
    #print "TaggedType::eth_set_val_name(): ident=%s, val_name=%s" % (ident, val_name)
    self.val_name = val_name
    ectx.eth_dep_add(ident, self.val_name)

  def eth_reg_sub(self, ident, ectx):
    self.val_name = ident + '/' + '_untag'
    self.val.eth_reg(self.val_name, ectx, tstrip=self.tstrip+1, tagflag=True, parent=ident)

  def GetTTag(self, ectx):
    #print "GetTTag(%s)\n" % self.seltype;
    return self.GetTag(ectx)

  def eth_ftype(self, ectx):
    return self.val.eth_ftype(ectx)

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    t = ectx.type[self.val_name]['ethname']
    pars['TYPE_REF_PROTO'] = ectx.eth_type[t]['proto']
    pars['TYPE_REF_TNAME'] = t
    pars['TYPE_REF_FN'] = 'dissect_%(TYPE_REF_PROTO)s_%(TYPE_REF_TNAME)s'
    (pars['TAG_CLS'], pars['TAG_TAG']) = self.GetTag(ectx)
    if self.HasImplicitTag(ectx):
      pars['TAG_IMPL'] = 'TRUE'
    else:
      pars['TAG_IMPL'] = 'FALSE'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_tagged_type', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                   ('%(HF_INDEX)s', '%(TAG_CLS)s', '%(TAG_TAG)s', '%(TAG_IMPL)s', '%(TYPE_REF_FN)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- SqType -----------------------------------------------------------
class SqType (Type):
  def out_item(self, f, val, optional, ext, ectx):
    ef = ectx.field[f]['ethname']
    t = ectx.eth_hf[ef]['ethtype']
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
      out = '  { %-24s, %-13s, %s, %s, dissect_%s_%s },\n' \
            % ('&'+ectx.eth_hf[ef]['fullname'], tc, tn, opt, ectx.eth_type[t]['proto'], t)
    elif (ectx.Per()):
      out = '  { %-24s, %-23s, %-17s, dissect_%s_%s },\n' \
            % ('&'+ectx.eth_hf[ef]['fullname'], ext, opt, ectx.eth_type[t]['proto'], t)
    else:
      out = ''
    return out

#--- SeqType -----------------------------------------------------------
class SeqType (SqType):

  def all_components(self):
    lst = self.elt_list[:]
    if hasattr(self, 'ext_list'):
      lst.extend(self.ext_list)
    if hasattr(self, 'elt_list2'):
      lst.extend(self.elt_list2)
    return lst

  def need_components(self):
    lst = self.all_components()
    for e in (lst):
      if e.type == 'components_of':
        return True
    return False

  def expand_components(self, ectx):
    while self.need_components():
      for i in range(len(self.elt_list)):
        if self.elt_list[i].type == 'components_of':
          comp = self.elt_list[i].typ.get_components(ectx)
          self.elt_list[i:i+1] = comp
          break
      if hasattr(self, 'ext_list'):
        for i in range(len(self.ext_list)):
          if self.ext_list[i].type == 'components_of':
            comp = self.ext_list[i].typ.get_components(ectx)
            self.ext_list[i:i+1] = comp
            break
      if hasattr(self, 'elt_list2'):
        for i in range(len(self.elt_list2)):
          if self.elt_list2[i].type == 'components_of':
            comp = self.elt_list2[i].typ.get_components(ectx)
            self.elt_list2[i:i+1] = comp
            break

  def get_components(self, ectx):
    lst = self.elt_list[:]
    if hasattr(self, 'elt_list2'):
      lst.extend(self.elt_list2)
    return lst

  def eth_reg_sub(self, ident, ectx, components_available=False):
    # check if autotag is required
    autotag = False
    if (ectx.NeedTags() and (ectx.tag_def == 'AUTOMATIC')):
      autotag = True
      lst = self.all_components()
      for e in (self.elt_list):
        if e.val.HasOwnTag(): autotag = False; break;
    # expand COMPONENTS OF
    if self.need_components():
      if components_available:
        self.expand_components(ectx)
      else:
        ectx.eth_comp_req(ident)
        return
    # do autotag
    if autotag:
      atag = 0
      for e in (self.elt_list):
        e.val.AddTag(Tag(cls = 'CONTEXT', num = str(atag), mode = 'IMPLICIT'))
        atag += 1
      if autotag and hasattr(self, 'elt_list2'):
        for e in (self.elt_list2):
          e.val.AddTag(Tag(cls = 'CONTEXT', num = str(atag), mode = 'IMPLICIT'))
          atag += 1
      if autotag and hasattr(self, 'ext_list'):
        for e in (self.ext_list):
          e.val.AddTag(Tag(cls = 'CONTEXT', num = str(atag), mode = 'IMPLICIT'))
          atag += 1
    for e in (self.elt_list):
        e.val.eth_reg(ident, ectx, tstrip=1, parent=ident)
    if hasattr(self, 'ext_list'):
        for e in (self.ext_list):
            e.val.eth_reg(ident, ectx, tstrip=1, parent=ident)
    if hasattr(self, 'elt_list2'):
        for e in (self.elt_list2):
            e.val.eth_reg(ident, ectx, tstrip=1, parent=ident)

  def eth_type_default_table(self, ectx, tname):
    #print "eth_type_default_table(tname='%s')" % (tname)
    fname = ectx.eth_type[tname]['ref'][0]
    table = "static const %(ER)s_sequence_t %(TABLE)s[] = {\n"
    if hasattr(self, 'ext_list'):
      ext = 'ASN1_EXTENSION_ROOT'
    else:
      ext = 'ASN1_NO_EXTENSIONS'
    empty_ext_flag = '0'
    if (len(self.elt_list)==0) and hasattr(self, 'ext_list') and (len(self.ext_list)==0) and (not hasattr(self, 'elt_list2') or (len(self.elt_list2)==0)):
      empty_ext_flag = ext
    for e in (self.elt_list):
      f = fname + '/' + e.val.name
      table += self.out_item(f, e.val, e.optional, ext, ectx)
    if hasattr(self, 'ext_list'):
      for e in (self.ext_list):
        f = fname + '/' + e.val.name
        table += self.out_item(f, e.val, e.optional, 'ASN1_NOT_EXTENSION_ROOT', ectx)
    if hasattr(self, 'elt_list2'):
      for e in (self.elt_list2):
        f = fname + '/' + e.val.name
        table += self.out_item(f, e.val, e.optional, ext, ectx)
    if (ectx.Ber()):
      table += "  { NULL, 0, 0, 0, NULL }\n};\n"
    else:
      table += "  { NULL, %s, 0, NULL }\n};\n" % (empty_ext_flag)
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
    if self.size_constr != None:
        print "#Ignoring size constraint:", self.size_constr.subtype
    return "%sasn1.SEQUENCE_OF (%s%s)" % (ctx.spaces (),
                                          self.val.to_python (ctx),
                                          sizestr)

  def eth_reg_sub(self, ident, ectx):
    itmnm = ident
    if not self.val.IsNamed ():
      itmnm += '/' + '_item'
    self.val.eth_reg(itmnm, ectx, tstrip=1, idx='[##]', parent=ident)

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
    (pars['MIN_VAL'], pars['MAX_VAL'], pars['EXT']) = self.eth_get_size_constr(ectx)
    pars['TABLE'] = '%(PROTOP)s%(TNAME)s_sequence_of'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      if (ectx.constraints_check and self.HasSizeConstraint()):
        body = ectx.eth_fn_call('dissect_%(ER)s_constrained_sequence_of', ret='offset',
                                par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s',),))
      else:
        body = ectx.eth_fn_call('dissect_%(ER)s_sequence_of', ret='offset',
                                par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                     ('%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s',),))
    elif (ectx.Per() and not self.HasConstraint()):
      body = ectx.eth_fn_call('dissect_%(ER)s_sequence_of', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ETT_INDEX)s', '%(TABLE)s',),))
    elif (ectx.Per() and self.constr.type == 'Size'):
      body = ectx.eth_fn_call('dissect_%(ER)s_constrained_sequence_of', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ETT_INDEX)s', '%(TABLE)s',),
                                   ('%(MIN_VAL)s', '%(MAX_VAL)s','%(EXT)s'),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body


#--- SetOfType ----------------------------------------------------------------
class SetOfType (SeqOfType):
  def eth_reg_sub(self, ident, ectx):
    itmnm = ident
    if not self.val.IsNamed ():
      itmnm += '/' + '_item'
    self.val.eth_reg(itmnm, ectx, tstrip=1, idx='(##)', parent=ident)

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
    (pars['MIN_VAL'], pars['MAX_VAL'], pars['EXT']) = self.eth_get_size_constr(ectx)
    pars['TABLE'] = '%(PROTOP)s%(TNAME)s_set_of'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      if (ectx.constraints_check and self.HasSizeConstraint()):
        body = ectx.eth_fn_call('dissect_%(ER)s_constrained_set_of', ret='offset',
                                par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s',),))
      else:
        body = ectx.eth_fn_call('dissect_%(ER)s_set_of', ret='offset',
                                par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                     ('%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s',),))
    elif (ectx.Per() and not self.HasConstraint()):
      body = ectx.eth_fn_call('dissect_%(ER)s_set_of', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ETT_INDEX)s', '%(TABLE)s',),))
    elif (ectx.Per() and self.constr.type == 'Size'):
      body = ectx.eth_fn_call('dissect_%(ER)s_constrained_set_of', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ETT_INDEX)s', '%(TABLE)s',),
                                   ('%(MIN_VAL)s', '%(MAX_VAL)s','%(EXT)s',),))
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
      if 'ext_list' in self.__dict__:
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

  def eth_need_tree(self):
    return True

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_SEQUENCE')

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    pars['TABLE'] = '%(PROTOP)s%(TNAME)s_sequence'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
        body = ectx.eth_fn_call('dissect_%(ER)s_sequence', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                   ('%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_sequence', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ETT_INDEX)s', '%(TABLE)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- SetType ------------------------------------------------------------------
class SetType(SeqType):

  def eth_need_tree(self):
    return True

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_SET')

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    pars['TABLE'] = '%(PROTOP)s%(TNAME)s_set'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_set', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                   ('%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_set', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ETT_INDEX)s', '%(TABLE)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- ChoiceType ---------------------------------------------------------------
class ChoiceType (Type):
  def to_python (self, ctx):
      # name, tag (None for no tag, EXPLICIT() for explicit), typ)
      # or '' + (1,) for optional
      if 'ext_list' in self.__dict__:
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
    # check if autotag is required
    autotag = False
    if (ectx.NeedTags() and (ectx.tag_def == 'AUTOMATIC')):
      autotag = True
      for e in (self.elt_list):
        if e.HasOwnTag(): autotag = False; break;
      if autotag and hasattr(self, 'ext_list'):
        for e in (self.ext_list):
          if e.HasOwnTag(): autotag = False; break;
    # do autotag
    if autotag:
      atag = 0
      for e in (self.elt_list):
        e.AddTag(Tag(cls = 'CONTEXT', num = str(atag), mode = 'IMPLICIT'))
        atag += 1
      if autotag and hasattr(self, 'ext_list'):
        for e in (self.ext_list):
          e.AddTag(Tag(cls = 'CONTEXT', num = str(atag), mode = 'IMPLICIT'))
          atag += 1
    for e in (self.elt_list):
        e.eth_reg(ident, ectx, tstrip=1, parent=ident)
        if ectx.conform.check_item('EXPORTS', ident + '.' + e.name):
          ectx.eth_sel_req(ident, e.name)
    if hasattr(self, 'ext_list'):
        for e in (self.ext_list):
            e.eth_reg(ident, ectx, tstrip=1, parent=ident)
            if ectx.conform.check_item('EXPORTS', ident + '.' + e.name):
              ectx.eth_sel_req(ident, e.name)

  def sel_item(self, ident, sel, ectx):
    lst = self.elt_list[:]
    if hasattr(self, 'ext_list'):
      lst.extend(self.ext_list)
    ee = None
    for e in (self.elt_list):
      if e.IsNamed() and (e.name == sel):
        ee = e
        break
    if not ee:
      print "#CHOICE %s does not contain item %s" % (ident, sel)
    return ee

  def sel_req(self, ident, sel, ectx):
    #print "sel_req(ident='%s', sel=%s)\n%s" % (ident, sel, str(self))
    ee = self.sel_item(ident, sel, ectx)
    if ee:
      ee.eth_reg(ident, ectx, tstrip=0, selflag=True)

  def eth_ftype(self, ectx):
    return ('FT_UINT32', 'BASE_DEC')

  def eth_ftype_sel(self, sel, ectx):
    ee = self.sel_item('', sel, ectx)
    if ee:
      return ee.eth_ftype(ectx)
    else:
      return ('FT_NONE', 'BASE_NONE')

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

  def GetTTagSel(self, sel, ectx):
    ee = self.sel_item('', sel, ectx)
    if ee:
      return ee.GetTag(ectx)
    else:
      return ('BER_CLASS_ANY/*unknown selection*/', '-1/*unknown selection*/')

  def IndetermTag(self, ectx):
    #print "Choice IndetermTag()=%s" % (str(not self.HasOwnTag()))
    return not self.HasOwnTag()

  def detect_tagval(self, ectx):
    tagval = False
    lst = self.elt_list[:]
    if hasattr(self, 'ext_list'):
      lst.extend(self.ext_list)
    if (len(lst) > 0) and (not ectx.Per() or lst[0].HasOwnTag()):
      t = lst[0].GetTag(ectx)[0]
      tagval = True
    else:
      t = ''
      tagval = False
    if (t == 'BER_CLASS_UNI'):
      tagval = False
    for e in (lst):
      if not ectx.Per() or e.HasOwnTag():
        tt = e.GetTag(ectx)[0]
      else:
        tt = ''
        tagval = False
      if (tt != t):
        tagval = False
    return tagval

  def get_vals(self, ectx):
    tagval = self.detect_tagval(ectx)
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
    return vals

  def eth_type_vals(self, tname, ectx):
    out = '\n'
    vals = self.get_vals(ectx)
    out += ectx.eth_vals(tname, vals)
    return out

  def reg_enum_vals(self, tname, ectx):
    vals = self.get_vals(ectx)
    for (val, id) in vals:
      ectx.eth_reg_value(id, self, val, ethname=ectx.eth_enum_item(tname, id))

  def eth_type_enum(self, tname, ectx):
    out = '\n'
    vals = self.get_vals(ectx)
    out += ectx.eth_enum(tname, vals)
    return out

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    pars['TABLE'] = '%(PROTOP)s%(TNAME)s_choice'
    return pars

  def eth_type_default_table(self, ectx, tname):
    def out_item(val, e, ext, ectx):
      has_enum = ectx.eth_type[tname]['enum'] & EF_ENUM
      if (has_enum):
        vval = ectx.eth_enum_item(tname, e.name)
      else:
        vval = val
      f = fname + '/' + e.name
      ef = ectx.field[f]['ethname']
      t = ectx.eth_hf[ef]['ethtype']
      efd = ef
      if (ectx.field[f]['impl']):
        efd += '_impl'
      if (ectx.Ber()):
        opt = ''
        if (not e.HasOwnTag()):
          opt = 'BER_FLAGS_NOOWNTAG'
        elif (e.HasImplicitTag(ectx)):
          if (opt): opt += '|'
          opt += 'BER_FLAGS_IMPLTAG'
        if (not opt): opt = '0'
      if (ectx.Ber()):
        (tc, tn) = e.GetTag(ectx)
        out = '  { %3s, %-24s, %-13s, %s, %s, dissect_%s_%s },\n' \
              % (vval, '&'+ectx.eth_hf[ef]['fullname'], tc, tn, opt, ectx.eth_type[t]['proto'], t)
      elif (ectx.Per()):
        out = '  { %3s, %-24s, %-23s, dissect_%s_%s },\n' \
              % (vval, '&'+ectx.eth_hf[ef]['fullname'], ext, ectx.eth_type[t]['proto'], t)
      else:
        out = ''
      return out
    # end out_item()
    #print "eth_type_default_table(tname='%s')" % (tname)
    fname = ectx.eth_type[tname]['ref'][0]
    tagval = self.detect_tagval(ectx)
    table = "static const %(ER)s_choice_t %(TABLE)s[] = {\n"
    cnt = 0
    if hasattr(self, 'ext_list'):
      ext = 'ASN1_EXTENSION_ROOT'
    else:
      ext = 'ASN1_NO_EXTENSIONS'
    empty_ext_flag = '0'
    if (len(self.elt_list)==0) and hasattr(self, 'ext_list') and (len(self.ext_list)==0):
      empty_ext_flag = ext
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
      table += "  { 0, NULL, 0, 0, 0, NULL }\n};\n"
    else:
      table += "  { 0, NULL, %s, NULL }\n};\n" % (empty_ext_flag)
    return table

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_choice', ret='offset',
                              par=(('%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                   ('%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s'),
                                   ('%(VAL_PTR)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_choice', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ETT_INDEX)s', '%(TABLE)s',),
                                   ('%(VAL_PTR)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- ChoiceValue ----------------------------------------------------
class ChoiceValue (Value):
  def to_str(self, ectx):
    return self.val.to_str(ectx)

  def fld_obj_eq(self, other):
    return isinstance(other, ChoiceValue) and (self.choice == other.choice) and (str(self.val.val) == str(other.val.val))

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
        while lastv in used:
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
          while lastv in used:
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

  def reg_enum_vals(self, tname, ectx):
    vals = self.get_vals_etc(ectx)[0]
    for (val, id) in vals:
      ectx.eth_reg_value(id, self, val, ethname=ectx.eth_enum_item(tname, id))

  def eth_type_enum(self, tname, ectx):
    out = '\n'
    vals = self.get_vals_etc(ectx)[0]
    out += ectx.eth_enum(tname, vals)
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
      pars['TABLE'] = '%(PROTOP)s%(TNAME)s_value_map'
    else:
      pars['TABLE'] = 'NULL'
    return pars

  def eth_type_default_table(self, ectx, tname):
    if (not ectx.Per()): return ''
    map_table = self.get_vals_etc(ectx)[3]
    if (map_table == None): return ''
    table = "static guint32 %(TABLE)s[%(ROOT_NUM)s+%(EXT_NUM)s] = {"
    table += ", ".join([str(v) for v in map_table])
    table += "};\n"
    return table

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      if (ectx.constraints_check and self.HasValueConstraint()):
        body = ectx.eth_fn_call('dissect_%(ER)s_constrained_integer', ret='offset',
                                par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(HF_INDEX)s', '%(VAL_PTR)s',),))
      else:
        body = ectx.eth_fn_call('dissect_%(ER)s_integer', ret='offset',
                                par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),
                                     ('%(VAL_PTR)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_enumerated', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(ROOT_NUM)s', '%(VAL_PTR)s', '%(EXT)s', '%(EXT_NUM)s', '%(TABLE)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- EmbeddedPDVType -----------------------------------------------------------
class EmbeddedPDVType (Type):
  def eth_tname(self):
    return 'EMBEDDED_PDV'

  def eth_ftype(self, ectx):
    return ('FT_NONE', 'BASE_NONE')

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_EMBEDDED_PDV')

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    if ectx.default_embedded_pdv_cb:
      pars['TYPE_REF_FN'] = ectx.default_embedded_pdv_cb
    else:
      pars['TYPE_REF_FN'] = 'NULL'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_EmbeddedPDV_Type', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(HF_INDEX)s', '%(TYPE_REF_FN)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_embedded_pdv', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s', '%(TYPE_REF_FN)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- ExternalType -----------------------------------------------------------
class ExternalType (Type):
  def eth_tname(self):
    return 'EXTERNAL'

  def eth_ftype(self, ectx):
    return ('FT_NONE', 'BASE_NONE')

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_EXTERNAL')

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    if ectx.default_external_type_cb:
      pars['TYPE_REF_FN'] = ectx.default_external_type_cb
    else:
      pars['TYPE_REF_FN'] = 'NULL'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_external_type', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(HF_INDEX)s', '%(TYPE_REF_FN)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_external_type', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s', '%(TYPE_REF_FN)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- OpenType -----------------------------------------------------------
class OpenType (Type):
  def to_python (self, ctx):
    return "asn1.ANY"

  def single_type(self):
    if (self.HasConstraint() and
        self.constr.type == 'Type' and
        self.constr.subtype.type == 'Type_Ref'):
      return self.constr.subtype.val
    return None

  def eth_reg_sub(self, ident, ectx):
    t = self.single_type()
    if t:
      ectx.eth_dep_add(ident, t)

  def eth_tname(self):
    t = self.single_type()
    if t:
      return 'OpenType_' + t
    else:
      return Type.eth_tname(self)

  def eth_ftype(self, ectx):
    return ('FT_NONE', 'BASE_NONE')

  def GetTTag(self, ectx):
    return ('BER_CLASS_ANY', '0')

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    pars['FN_VARIANT'] = ectx.default_opentype_variant
    t = self.single_type()
    if t:
      t = ectx.type[t]['ethname']
      pars['TYPE_REF_PROTO'] = ectx.eth_type[t]['proto']
      pars['TYPE_REF_TNAME'] = t
      pars['TYPE_REF_FN'] = 'dissect_%(TYPE_REF_PROTO)s_%(TYPE_REF_TNAME)s'
    else:
      pars['TYPE_REF_FN'] = 'NULL'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_open_type%(FN_VARIANT)s', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s', '%(TYPE_REF_FN)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- InstanceOfType -----------------------------------------------------------
class InstanceOfType (Type):
  def eth_tname(self):
    return 'INSTANCE_OF'

  def eth_ftype(self, ectx):
    return ('FT_NONE', 'BASE_NONE')

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_EXTERNAL')

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    if ectx.default_external_type_cb:
      pars['TYPE_REF_FN'] = ectx.default_external_type_cb
    else:
      pars['TYPE_REF_FN'] = 'NULL'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_external_type', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(HF_INDEX)s', '%(TYPE_REF_FN)s',),))
    elif (ectx.Per()):
      body = '#error Can not decode %s' % (tname)
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
                              par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_null', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- NullValue ----------------------------------------------------
class NullValue (Value):
  def to_str(self, ectx):
    return 'NULL'

#--- RealType -----------------------------------------------------------------
class RealType (Type):
  def to_python (self, ctx):
    return 'asn1.REAL'

  def eth_tname(self):
    return 'REAL'

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_REAL')

  def eth_ftype(self, ectx):
    return ('FT_DOUBLE', 'BASE_NONE')

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_real', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),
                                   ('%(VAL_PTR)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_real', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s', '%(VAL_PTR)s',),))
    else:
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
    return ('FT_BOOLEAN', 'BASE_NONE')

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_boolean', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s', '%(VAL_PTR)s'),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_boolean', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s', '%(VAL_PTR)s',),))
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
    elif self.constr.type == 'Size':
      return 'OCTET_STRING' + '_' + self.constr.eth_constrname()
    else:
      return '#' + self.type + '_' + str(id(self))

  def eth_ftype(self, ectx):
    return ('FT_BYTES', 'BASE_NONE')

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_OCTETSTRING')

  def eth_need_pdu(self, ectx):
    pdu = None
    if self.HasContentsConstraint():
      t = self.constr.GetContents(ectx)
      if t and (ectx.default_containing_variant in ('_pdu', '_pdu_new')):
        pdu = { 'type' : t,
                'new' : ectx.default_containing_variant == '_pdu_new' }
    return pdu

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    (pars['MIN_VAL'], pars['MAX_VAL'], pars['EXT']) = self.eth_get_size_constr(ectx)
    if self.HasContentsConstraint():
      pars['FN_VARIANT'] = ectx.default_containing_variant
      t = self.constr.GetContents(ectx)
      if t:
        if pars['FN_VARIANT'] in ('_pdu', '_pdu_new'):
          t = ectx.field[t]['ethname']
          pars['TYPE_REF_PROTO'] = ''
          pars['TYPE_REF_TNAME'] = t
          pars['TYPE_REF_FN'] = 'dissect_%(TYPE_REF_TNAME)s'
        else:
          t = ectx.type[t]['ethname']
          pars['TYPE_REF_PROTO'] = ectx.eth_type[t]['proto']
          pars['TYPE_REF_TNAME'] = t
          pars['TYPE_REF_FN'] = 'dissect_%(TYPE_REF_PROTO)s_%(TYPE_REF_TNAME)s'
      else:
        pars['TYPE_REF_FN'] = 'NULL'
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      if (ectx.constraints_check and self.HasSizeConstraint()):
        body = ectx.eth_fn_call('dissect_%(ER)s_constrained_octet_string', ret='offset',
                                par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(HF_INDEX)s', '%(VAL_PTR)s',),))
      else:
        body = ectx.eth_fn_call('dissect_%(ER)s_octet_string', ret='offset',
                                par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),
                                     ('%(VAL_PTR)s',),))
    elif (ectx.Per()):
      if self.HasContentsConstraint():
        body = ectx.eth_fn_call('dissect_%(ER)s_octet_string_containing%(FN_VARIANT)s', ret='offset',
                                par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(EXT)s', '%(TYPE_REF_FN)s',),))
      else:
        body = ectx.eth_fn_call('dissect_%(ER)s_octet_string', ret='offset',
                                par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(EXT)s', '%(VAL_PTR)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- CharacterStringType ------------------------------------------------------
class CharacterStringType (Type):
  def eth_tname(self):
    if not self.HasConstraint():
      return self.eth_tsname()
    elif self.constr.type == 'Size':
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

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    (pars['MIN_VAL'], pars['MAX_VAL'], pars['EXT']) = self.eth_get_size_constr(ectx)
    (pars['STRING_TYPE'], pars['STRING_TAG']) = (self.eth_tsname(), self.GetTTag(ectx)[1])
    (pars['ALPHABET'], pars['ALPHABET_LEN']) = self.eth_get_alphabet_constr(ectx)
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      if (ectx.constraints_check and self.HasSizeConstraint()):
        body = ectx.eth_fn_call('dissect_%(ER)s_constrained_restricted_string', ret='offset',
                                par=(('%(IMPLICIT_TAG)s', '%(STRING_TAG)s'),
                                     ('%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(HF_INDEX)s', '%(VAL_PTR)s',),))
      else:
        body = ectx.eth_fn_call('dissect_%(ER)s_restricted_string', ret='offset',
                                par=(('%(IMPLICIT_TAG)s', '%(STRING_TAG)s'),
                                     ('%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),
                                     ('%(VAL_PTR)s',),))
    elif (ectx.Per() and self.HasPermAlph()):
      body = ectx.eth_fn_call('dissect_%(ER)s_restricted_character_string', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(EXT)s', '%(ALPHABET)s', '%(ALPHABET_LEN)s'),
                                   ('%(VAL_PTR)s',),))
    elif (ectx.Per()):
      if (self.eth_tsname() == 'GeneralString'):
        body = ectx.eth_fn_call('dissect_%(ER)s_%(STRING_TYPE)s', ret='offset',
                                par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),))
      elif (self.eth_tsname() == 'GeneralizedTime'):
        body = ectx.eth_fn_call('dissect_%(ER)s_VisibleString', ret='offset',
                                par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(EXT)s',),))
      elif (self.eth_tsname() == 'UTCTime'):
        body = ectx.eth_fn_call('dissect_%(ER)s_VisibleString', ret='offset',
                                par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(EXT)s',),))
      else:
        body = ectx.eth_fn_call('dissect_%(ER)s_%(STRING_TYPE)s', ret='offset',
                                par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(EXT)s',),))
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
                              par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),))
      return body
    else:
      return RestrictedCharacterStringType.eth_type_default_body(self, ectx, tname)

class UTCTime (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'UTCTime'

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_%(STRING_TYPE)s', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),))
      return body
    else:
      return RestrictedCharacterStringType.eth_type_default_body(self, ectx, tname)

class ObjectDescriptor (RestrictedCharacterStringType):
  def eth_tsname(self):
    return 'ObjectDescriptor'

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = RestrictedCharacterStringType.eth_type_default_body(self, ectx, tname)
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_object_descriptor', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s', '%(VAL_PTR)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

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

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    pars['FN_VARIANT'] = ectx.default_oid_variant
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_object_identifier%(FN_VARIANT)s', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s', '%(VAL_PTR)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_object_identifier%(FN_VARIANT)s', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s', '%(VAL_PTR)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- ObjectIdentifierValue ----------------------------------------------------
class ObjectIdentifierValue (Value):
  def get_num(self, path, val):
    return str(oid_names.get(path + '/' + val, val))

  def to_str(self, ectx):
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
      if not first and not vstr.isdigit():
        vstr = ectx.value_get_val(vstr)
      if first:
        if vstr.isdigit():
          out += '"' + vstr
        else:
          out += ectx.value_get_eth(vstr) + '"'
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

class NamedNumber(Node):
    def to_python (self, ctx):
        return "('%s',%s)" % (self.ident, self.val)

class NamedNumListBase(Node):
    def to_python (self, ctx):
        return "asn1.%s_class ([%s])" % (self.asn1_typ,",".join (
            [x.to_python (ctx) for x in self.named_list]))

#--- RelativeOIDType ----------------------------------------------------------
class RelativeOIDType (Type):

  def eth_tname(self):
    return 'RELATIVE_OID'

  def eth_ftype(self, ectx):
    return ('FT_BYTES', 'BASE_NONE')

  def GetTTag(self, ectx):
    return ('BER_CLASS_UNI', 'BER_UNI_TAG_RELATIVE_OID')

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    pars['FN_VARIANT'] = ectx.default_oid_variant
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      body = ectx.eth_fn_call('dissect_%(ER)s_relative_oid%(FN_VARIANT)s', ret='offset',
                              par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s', '%(VAL_PTR)s',),))
    elif (ectx.Per()):
      body = ectx.eth_fn_call('dissect_%(ER)s_relative_oid%(FN_VARIANT)s', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s', '%(VAL_PTR)s',),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body


#--- IntegerType --------------------------------------------------------------
class IntegerType (Type):
  def to_python (self, ctx):
        return "asn1.INTEGER_class ([%s])" % (",".join (
            [x.to_python (ctx) for x in self.named_list]))

  def add_named_value(self, ident, val):
    e = NamedNumber(ident = ident, val = val)
    if not self.named_list:
      self.named_list = []
    self.named_list.append(e)

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

  def get_vals(self, ectx):
    vals = []
    for e in (self.named_list):
      vals.append((int(e.val), e.ident))
    return vals

  def eth_type_vals(self, tname, ectx):
    if not self.eth_has_vals(): return ''
    out = '\n'
    vals = self.get_vals(ectx)
    out += ectx.eth_vals(tname, vals)
    return out

  def reg_enum_vals(self, tname, ectx):
    vals = self.get_vals(ectx)
    for (val, id) in vals:
      ectx.eth_reg_value(id, self, val, ethname=ectx.eth_enum_item(tname, id))

  def eth_type_enum(self, tname, ectx):
    if not self.eth_has_enum(tname, ectx): return ''
    out = '\n'
    vals = self.get_vals(ectx)
    out += ectx.eth_enum(tname, vals)
    return out

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    if self.HasValueConstraint():
      (pars['MIN_VAL'], pars['MAX_VAL'], pars['EXT']) = self.eth_get_value_constr(ectx)
    return pars

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      if (ectx.constraints_check and self.HasValueConstraint()):
        body = ectx.eth_fn_call('dissect_%(ER)s_constrained_integer%(FN_VARIANT)s', ret='offset',
                                par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(HF_INDEX)s', '%(VAL_PTR)s',),))
      else:
        body = ectx.eth_fn_call('dissect_%(ER)s_integer%(FN_VARIANT)s', ret='offset',
                                par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s', '%(HF_INDEX)s'),
                                     ('%(VAL_PTR)s',),))
    elif (ectx.Per() and not self.HasValueConstraint()):
      body = ectx.eth_fn_call('dissect_%(ER)s_integer%(FN_VARIANT)s', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s', '%(VAL_PTR)s'),))
    elif (ectx.Per() and self.HasValueConstraint()):
      body = ectx.eth_fn_call('dissect_%(ER)s_constrained_integer%(FN_VARIANT)s', ret='offset',
                              par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                   ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(VAL_PTR)s', '%(EXT)s'),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- BitStringType ------------------------------------------------------------
class BitStringType (Type):
  def to_python (self, ctx):
        return "asn1.BITSTRING_class ([%s])" % (",".join (
            [x.to_python (ctx) for x in self.named_list]))

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
    return ('FT_BYTES', 'BASE_NONE')

  def eth_need_tree(self):
    return self.named_list

  def eth_need_pdu(self, ectx):
    pdu = None
    if self.HasContentsConstraint():
      t = self.constr.GetContents(ectx)
      if t and (ectx.default_containing_variant in ('_pdu', '_pdu_new')):
        pdu = { 'type' : t,
                'new' : ectx.default_containing_variant == '_pdu_new' }
    return pdu

  def eth_named_bits(self):
    bits = []
    if (self.named_list):
      for e in (self.named_list):
        bits.append((int(e.val), e.ident))
    return bits

  def eth_type_default_pars(self, ectx, tname):
    pars = Type.eth_type_default_pars(self, ectx, tname)
    (pars['MIN_VAL'], pars['MAX_VAL'], pars['EXT']) = self.eth_get_size_constr(ectx)
    if 'ETT_INDEX' not in pars:
      pars['ETT_INDEX'] = '-1'
    pars['TABLE'] = 'NULL'
    if self.eth_named_bits():
      pars['TABLE'] = '%(PROTOP)s%(TNAME)s_bits'
    if self.HasContentsConstraint():
      pars['FN_VARIANT'] = ectx.default_containing_variant
      t = self.constr.GetContents(ectx)
      if t:
        if pars['FN_VARIANT'] in ('_pdu', '_pdu_new'):
          t = ectx.field[t]['ethname']
          pars['TYPE_REF_PROTO'] = ''
          pars['TYPE_REF_TNAME'] = t
          pars['TYPE_REF_FN'] = 'dissect_%(TYPE_REF_TNAME)s'
        else:
          t = ectx.type[t]['ethname']
          pars['TYPE_REF_PROTO'] = ectx.eth_type[t]['proto']
          pars['TYPE_REF_TNAME'] = t
          pars['TYPE_REF_FN'] = 'dissect_%(TYPE_REF_PROTO)s_%(TYPE_REF_TNAME)s'
      else:
        pars['TYPE_REF_FN'] = 'NULL'
    return pars

  def eth_type_default_table(self, ectx, tname):
    #print "eth_type_default_table(tname='%s')" % (tname)
    table = ''
    bits = self.eth_named_bits()
    if (bits and ectx.Ber()):
      table = ectx.eth_bits(tname, bits)
    return table

  def eth_type_default_body(self, ectx, tname):
    if (ectx.Ber()):
      if (ectx.constraints_check and self.HasSizeConstraint()):
        body = ectx.eth_fn_call('dissect_%(ER)s_constrained_bitstring', ret='offset',
                                par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s',),
                                     ('%(VAL_PTR)s',),))
      else:
        body = ectx.eth_fn_call('dissect_%(ER)s_bitstring', ret='offset',
                                par=(('%(IMPLICIT_TAG)s', '%(ACTX)s', '%(TREE)s', '%(TVB)s', '%(OFFSET)s'),
                                     ('%(TABLE)s', '%(HF_INDEX)s', '%(ETT_INDEX)s',),
                                     ('%(VAL_PTR)s',),))
    elif (ectx.Per()):
      if self.HasContentsConstraint():
        body = ectx.eth_fn_call('dissect_%(ER)s_bit_string_containing%(FN_VARIANT)s', ret='offset',
                                par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(EXT)s', '%(TYPE_REF_FN)s'),))
      else:
        body = ectx.eth_fn_call('dissect_%(ER)s_bit_string', ret='offset',
                                par=(('%(TVB)s', '%(OFFSET)s', '%(ACTX)s', '%(TREE)s', '%(HF_INDEX)s'),
                                     ('%(MIN_VAL)s', '%(MAX_VAL)s', '%(EXT)s', '%(VAL_PTR)s'),))
    else:
      body = '#error Can not decode %s' % (tname)
    return body

#--- BStringValue ------------------------------------------------------------
bstring_tab = {
  '0000' : '0',
  '0001' : '1',
  '0010' : '2',
  '0011' : '3',
  '0100' : '4',
  '0101' : '5',
  '0110' : '6',
  '0111' : '7',
  '1000' : '8',
  '1001' : '9',
  '1010' : 'A',
  '1011' : 'B',
  '1100' : 'C',
  '1101' : 'D',
  '1110' : 'E',
  '1111' : 'F',
}
class BStringValue (Value):
  def to_str(self, ectx):
    v = self.val[1:-2]
    if len(v) % 8:
      v += '0' * (8 - len(v) % 8)
    vv = '0x'
    for i in (range(0, len(v), 4)):
      vv += bstring_tab[v[i:i+4]]
    return vv

#--- HStringValue ------------------------------------------------------------
class HStringValue (Value):
  def to_str(self, ectx):
    vv = '0x'
    vv += self.val[1:-2]
    return vv
  def __int__(self):
    return int(self.val[1:-2], 16)

#--- FieldSpec ----------------------------------------------------------------
class FieldSpec (Node):
  def __init__(self,*args, **kw) :
    self.name = None
    Node.__init__ (self,*args, **kw)

  def SetName(self, name):
    self.name = name

  def get_repr(self):
    return ['#UNSUPPORTED_' + self.type]

  def fld_repr(self):
    repr = [self.name]
    repr.extend(self.get_repr())
    return repr

class TypeFieldSpec (FieldSpec):
  def get_repr(self):
    return []

class FixedTypeValueFieldSpec (FieldSpec):
  def get_repr(self):
    if isinstance(self.typ, Type_Ref):
      repr = ['TypeReference', self.typ.val]
    else:
      repr = [self.typ.type]
    return repr

class VariableTypeValueFieldSpec (FieldSpec):
  def get_repr(self):
    return ['_' + self.type]

class FixedTypeValueSetFieldSpec (FieldSpec):
  def get_repr(self):
    return ['_' + self.type]

class ObjectFieldSpec (FieldSpec):
  def get_repr(self):
    return ['ClassReference', self.cls.val]

class ObjectSetFieldSpec (FieldSpec):
  def get_repr(self):
    return ['ClassReference', self.cls.val]

#==============================================================================

def p_module_list_1 (t):
    'module_list : module_list ModuleDefinition'
    t[0] = t[1] + [t[2]]

def p_module_list_2 (t):
    'module_list : ModuleDefinition'
    t[0] = [t[1]]


#--- ITU-T Recommendation X.680 -----------------------------------------------


# 11 ASN.1 lexical items --------------------------------------------------------

# 11.2 Type references
def p_type_ref (t):
  'type_ref : UCASE_IDENT'
  t[0] = Type_Ref(val=t[1])

# 11.3 Identifiers
def p_identifier (t):
  'identifier : LCASE_IDENT'
  t[0] = t[1]

# 11.4 Value references
# cause reduce/reduce conflict
#def p_valuereference (t):
#  'valuereference : LCASE_IDENT'
#  t[0] = Value_Ref(val=t[1])

# 11.5 Module references
def p_modulereference (t):
  'modulereference : UCASE_IDENT'
  t[0] = t[1]


# 12 Module definition --------------------------------------------------------

# 12.1
def p_ModuleDefinition (t):
  'ModuleDefinition : ModuleIdentifier DEFINITIONS TagDefault ASSIGNMENT ModuleBegin BEGIN ModuleBody END'
  t[0] = Module (ident = t[1], tag_def = t[3], body = t[7])

def p_ModuleBegin (t):
  'ModuleBegin : '
  if t[-4].val == 'Remote-Operations-Information-Objects':
    x880_module_begin()

def p_TagDefault_1 (t):
  '''TagDefault : EXPLICIT TAGS
                | IMPLICIT TAGS
                | AUTOMATIC TAGS '''
  t[0] = Default_Tags (dfl_tag = t[1])

def p_TagDefault_2 (t):
  'TagDefault : '
  # 12.2 The "TagDefault" is taken as EXPLICIT TAGS if it is "empty".
  t[0] = Default_Tags (dfl_tag = 'EXPLICIT')

def p_ModuleIdentifier_1 (t):
  'ModuleIdentifier : modulereference DefinitiveIdentifier' # name, oid
  t [0] = Node('module_ident', val = t[1], ident = t[2])

def p_ModuleIdentifier_2 (t):
  'ModuleIdentifier : modulereference' # name, oid
  t [0] = Node('module_ident', val = t[1], ident = None)

def p_DefinitiveIdentifier (t):
  'DefinitiveIdentifier : ObjectIdentifierValue'
  t[0] = t[1]

#def p_module_ref (t):
#    'module_ref : UCASE_IDENT'
#    t[0] = t[1]

def p_ModuleBody_1 (t):
  'ModuleBody : Exports Imports AssignmentList'
  t[0] = Module_Body (exports = t[1], imports = t[2], assign_list = t[3])

def p_ModuleBody_2 (t):
  'ModuleBody : '
  t[0] = Node ('module_body', exports = [], imports = [], assign_list = [])

def p_Exports_1 (t):
    'Exports : EXPORTS syms_exported SEMICOLON'
    t[0] = t[2]

def p_Exports_2 (t):
    'Exports : EXPORTS ALL SEMICOLON'
    t[0] = [ 'ALL' ]

def p_Exports_3 (t):
    'Exports : '
    t[0] = [ 'ALL' ]

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


def p_Imports_1 (t):
  'Imports : importsbegin IMPORTS SymbolsImported SEMICOLON'
  t[0] = t[3]
  global lcase_ident_assigned
  lcase_ident_assigned = {}

def p_importsbegin (t):
  'importsbegin : '
  global lcase_ident_assigned
  global g_conform
  lcase_ident_assigned = {}
  lcase_ident_assigned.update(g_conform.use_item('ASSIGNED_ID', 'OBJECT_IDENTIFIER'))

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
  'SymbolsFromModule : SymbolList FROM GlobalModuleReference'
  t[0] = Node ('SymbolList', symbol_list = t[1], module = t[3])
  for s in (t[0].symbol_list):
    if (isinstance(s, Value_Ref)): lcase_ident_assigned[s.val] = t[3]
  import_symbols_from_module(t[0].module, t[0].symbol_list)

def import_symbols_from_module(module, symbol_list):
  if module.val == 'Remote-Operations-Information-Objects':
    for i in range(len(symbol_list)):
      s = symbol_list[i]
      if isinstance(s, Type_Ref) or isinstance(s, Class_Ref):
        x880_import(s.val)
        if isinstance(s, Type_Ref) and is_class_ident(s.val):
          symbol_list[i] = Class_Ref (val = s.val)
    return
  for i in range(len(symbol_list)):
    s = symbol_list[i]
    if isinstance(s, Type_Ref) and is_class_ident("$%s$%s" % (module.val, s.val)):
      import_class_from_module(module.val, s.val)
    if isinstance(s, Type_Ref) and is_class_ident(s.val):
      symbol_list[i] = Class_Ref (val = s.val)

def p_GlobalModuleReference (t):
  'GlobalModuleReference : modulereference AssignedIdentifier'
  t [0] = Node('module_ident', val = t[1], ident = t[2])

def p_AssignedIdentifier_1 (t):
  'AssignedIdentifier : ObjectIdentifierValue'
  t[0] = t[1]

def p_AssignedIdentifier_2 (t):
  'AssignedIdentifier : LCASE_IDENT_ASSIGNED'
  t[0] = t[1]

def p_AssignedIdentifier_3 (t):
  'AssignedIdentifier : '
  pass

def p_SymbolList_1 (t):
  'SymbolList : Symbol'
  t[0] = [t[1]]

def p_SymbolList_2 (t):
  'SymbolList : SymbolList COMMA Symbol'
  t[0] = t[1] + [t[3]]

def p_Symbol (t):
  '''Symbol : Reference
            | ParameterizedReference'''
  t[0] = t[1]

def p_Reference_1 (t):
  '''Reference : type_ref
               | objectclassreference '''
  t[0] = t[1]

def p_Reference_2 (t):
  '''Reference : LCASE_IDENT_ASSIGNED
               | identifier '''  # instead of valuereference wich causes reduce/reduce conflict
  t[0] = Value_Ref(val=t[1])

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
                | ValueSetTypeAssignment
                | ObjectClassAssignment
                | ObjectAssignment
                | ObjectSetAssignment
                | ParameterizedAssignment
                | pyquote '''
  t[0] = t[1]


# 13 Referencing type and value definitions -----------------------------------

# 13.1
def p_DefinedType (t):
  '''DefinedType : ExternalTypeReference
                 | type_ref
                 | ParameterizedType'''
  t[0] = t[1]

def p_DefinedValue_1(t):
  '''DefinedValue : ExternalValueReference'''
  t[0] = t[1]

def p_DefinedValue_2(t):
  '''DefinedValue : identifier '''  # instead of valuereference wich causes reduce/reduce conflict
  t[0] = Value_Ref(val=t[1])

# 13.6
def p_ExternalTypeReference (t):
  'ExternalTypeReference : modulereference DOT type_ref'
  t[0] = Node ('ExternalTypeReference', module = t[1], typ = t[3])

def p_ExternalValueReference (t):
  'ExternalValueReference : modulereference DOT identifier'
  t[0] = Node ('ExternalValueReference', module = t[1], ident = t[3])


# 15 Assigning types and values -----------------------------------------------

# 15.1
def p_TypeAssignment (t):
  'TypeAssignment : UCASE_IDENT ASSIGNMENT Type'
  t[0] = t[3]
  t[0].SetName(t[1])

# 15.2
def p_ValueAssignment (t):
  'ValueAssignment : LCASE_IDENT ValueType ASSIGNMENT Value'
  t[0] = ValueAssignment(ident = t[1], typ = t[2], val = t[4])

# only "simple" types are supported to simplify grammer
def p_ValueType (t):
  '''ValueType : type_ref
               | BooleanType
               | IntegerType
               | ObjectIdentifierType
               | OctetStringType
               | RealType '''

  t[0] = t[1]

# 15.6
def p_ValueSetTypeAssignment (t):
  'ValueSetTypeAssignment : UCASE_IDENT ValueType ASSIGNMENT ValueSet'
  t[0] = Node('ValueSetTypeAssignment', name=t[1], typ=t[2], val=t[4])

# 15.7
def p_ValueSet (t):
  'ValueSet : lbraceignore rbraceignore'
  t[0] = None


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
                 | EmbeddedPDVType
                 | EnumeratedType
                 | ExternalType
                 | InstanceOfType
                 | IntegerType
                 | NullType
                 | ObjectClassFieldType
                 | ObjectIdentifierType
                 | OctetStringType
                 | RealType
                 | RelativeOIDType
                 | SequenceType
                 | SequenceOfType
                 | SetType
                 | SetOfType
                 | TaggedType'''
  t[0] = t[1]

# 16.3
def p_ReferencedType (t):
  '''ReferencedType : DefinedType
                    | UsefulType
                    | SelectionType'''
  t[0] = t[1]

# 16.5
def p_NamedType (t):
  'NamedType : identifier Type'
  t[0] = t[2]
  t[0].SetName (t[1])

# 16.7
def p_Value (t):
  '''Value : BuiltinValue
           | ReferencedValue
           | ObjectClassFieldValue'''
  t[0] = t[1]

# 16.9
def p_BuiltinValue (t):
  '''BuiltinValue : BooleanValue
                  | ChoiceValue
                  | IntegerValue
                  | ObjectIdentifierValue
                  | RealValue
                  | SequenceValue
                  | hex_string
                  | binary_string
                  | char_string''' # XXX we don't support {data} here
  t[0] = t[1]

# 16.11
def p_ReferencedValue (t):
  '''ReferencedValue : DefinedValue
                     | ValueFromObject'''
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
  t[0] = IntegerType(named_list = t[3])

def p_NamedNumberList_1 (t):
  'NamedNumberList : NamedNumber'
  t[0] = [t[1]]

def p_NamedNumberList_2 (t):
  'NamedNumberList : NamedNumberList COMMA NamedNumber'
  t[0] = t[1] + [t[3]]

def p_NamedNumber (t):
  '''NamedNumber : identifier LPAREN SignedNumber RPAREN
                 | identifier LPAREN DefinedValue RPAREN'''
  t[0] = NamedNumber(ident = t[1], val = t[3])

def p_SignedNumber_1 (t):
  'SignedNumber : NUMBER'
  t[0] = t [1]

def p_SignedNumber_2 (t):
  'SignedNumber : MINUS NUMBER'
  t[0] = '-' + t[2]

# 18.9
def p_IntegerValue (t):
  'IntegerValue : SignedNumber'
  t[0] = t [1]

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

# 20.6
def p_RealValue (t):
  '''RealValue : REAL_NUMBER
               | SpecialRealValue'''
  t[0] = t [1]

def p_SpecialRealValue (t):
  '''SpecialRealValue : PLUS_INFINITY
                      | MINUS_INFINITY'''
  t[0] = t[1]


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
def p_NullValue (t):
  'NullValue : NULL'
  t[0] = NullValue ()


# 24 Notation for sequence types ----------------------------------------------

# 24.1
def p_SequenceType_1 (t):
  'SequenceType : SEQUENCE LBRACE RBRACE'
  t[0] = SequenceType (elt_list = [])

def p_SequenceType_2 (t):
  'SequenceType : SEQUENCE LBRACE ComponentTypeLists RBRACE'
  t[0] = SequenceType (elt_list = t[3]['elt_list'])
  if 'ext_list' in t[3]:
    t[0].ext_list = t[3]['ext_list']
  if 'elt_list2' in t[3]:
    t[0].elt_list2 = t[3]['elt_list2']

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
  'ComponentTypeLists : ComponentTypeList'
  t[0] = {'elt_list' : t[1]}

def p_ComponentTypeLists_2 (t):
    'ComponentTypeLists : ComponentTypeList COMMA ExtensionAndException OptionalExtensionMarker'
    t[0] = {'elt_list' : t[1], 'ext_list' : []}

def p_ComponentTypeLists_3 (t):
    'ComponentTypeLists : ComponentTypeList COMMA ExtensionAndException ExtensionAdditionList OptionalExtensionMarker'
    t[0] = {'elt_list' : t[1], 'ext_list' : t[4]}

def p_ComponentTypeLists_4 (t):
    'ComponentTypeLists : ComponentTypeList COMMA ExtensionAndException ExtensionEndMarker COMMA ComponentTypeList'
    t[0] = {'elt_list' : t[1], 'ext_list' : [], 'elt_list2' : t[6]}

def p_ComponentTypeLists_5 (t):
    'ComponentTypeLists : ComponentTypeList COMMA ExtensionAndException ExtensionAdditionList ExtensionEndMarker COMMA ComponentTypeList'
    t[0] = {'elt_list' : t[1], 'ext_list' : t[4], 'elt_list2' : t[7]}

def p_ComponentTypeLists_6 (t):
    'ComponentTypeLists : ExtensionAndException OptionalExtensionMarker'
    t[0] = {'elt_list' : [], 'ext_list' : []}

def p_ComponentTypeLists_7 (t):
    'ComponentTypeLists : ExtensionAndException ExtensionAdditionList OptionalExtensionMarker'
    t[0] = {'elt_list' : [], 'ext_list' : t[2]}

def p_ExtensionEndMarker (t):
  'ExtensionEndMarker : COMMA ELLIPSIS'
  pass

def p_ExtensionAdditionList_1 (t):
  'ExtensionAdditionList : COMMA ExtensionAddition'
  t[0] = t[2]

def p_ExtensionAdditionList_2 (t):
  'ExtensionAdditionList : ExtensionAdditionList COMMA ExtensionAddition'
  t[0] = t[1] + t[3]

def p_ExtensionAddition_1 (t):
  'ExtensionAddition : ExtensionAdditionGroup'
  t[0] = t[1]

def p_ExtensionAddition_2 (t):
  'ExtensionAddition : ComponentType'
  t[0] = [t[1]]

def p_ExtensionAdditionGroup (t):
  'ExtensionAdditionGroup : LVERBRACK VersionNumber ComponentTypeList RVERBRACK'
  t[0] = t[3]

def p_VersionNumber_1 (t):
  'VersionNumber : '

def p_VersionNumber_2 (t):
  'VersionNumber : NUMBER COLON'

def p_ComponentTypeList_1 (t):
  'ComponentTypeList : ComponentType'
  t[0] = [t[1]]

def p_ComponentTypeList_2 (t):
  'ComponentTypeList : ComponentTypeList COMMA ComponentType'
  t[0] = t[1] + [t[3]]

def p_ComponentType_1 (t):
  'ComponentType : NamedType'
  t[0] = Node ('elt_type', val = t[1], optional = 0)

def p_ComponentType_2 (t):
  'ComponentType : NamedType OPTIONAL'
  t[0] = Node ('elt_type', val = t[1], optional = 1)

def p_ComponentType_3 (t):
  'ComponentType : NamedType DEFAULT DefaultValue'
  t[0] = Node ('elt_type', val = t[1], optional = 1, default = t[3])

def p_ComponentType_4 (t):
  'ComponentType : COMPONENTS OF Type'
  t[0] = Node ('components_of', typ = t[3])

def p_DefaultValue_1 (t):
  '''DefaultValue : ReferencedValue
                  | BooleanValue
                  | ChoiceValue
                  | IntegerValue
                  | RealValue
                  | hex_string
                  | binary_string
                  | char_string
                  | ObjectClassFieldValue'''
  t[0] = t[1]

def p_DefaultValue_2 (t):
  'DefaultValue : lbraceignore rbraceignore'
  t[0] = ''

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
  t[0] = SetType (elt_list = [])

def p_SetType_2 (t):
  'SetType : SET LBRACE ComponentTypeLists RBRACE'
  t[0] = SetType (elt_list = t[3]['elt_list'])
  if 'ext_list' in t[3]:
    t[0].ext_list = t[3]['ext_list']
  if 'elt_list2' in t[3]:
    t[0].elt_list2 = t[3]['elt_list2']


# 27 Notation for set-of types ------------------------------------------------

# 27.1
def p_SetOfType (t):
    '''SetOfType : SET OF Type
                 | SET OF NamedType'''
    t[0] = SetOfType (val = t[3])

# 28 Notation for choice types ------------------------------------------------

# 28.1
def p_ChoiceType (t):
    'ChoiceType : CHOICE LBRACE AlternativeTypeLists RBRACE'
    if 'ext_list' in t[3]:
        t[0] = ChoiceType (elt_list = t[3]['elt_list'], ext_list = t[3]['ext_list'])
    else:
        t[0] = ChoiceType (elt_list = t[3]['elt_list'])

def p_AlternativeTypeLists_1 (t):
    'AlternativeTypeLists : AlternativeTypeList'
    t[0] = {'elt_list' : t[1]}

def p_AlternativeTypeLists_2 (t):
    'AlternativeTypeLists : AlternativeTypeList COMMA ExtensionAndException ExtensionAdditionAlternatives OptionalExtensionMarker'
    t[0] = {'elt_list' : t[1], 'ext_list' : t[4]}

def p_ExtensionAdditionAlternatives_1 (t):
    'ExtensionAdditionAlternatives : ExtensionAdditionAlternativesList'
    t[0] = t[1]

def p_ExtensionAdditionAlternatives_2 (t):
    'ExtensionAdditionAlternatives : '
    t[0] = []

def p_ExtensionAdditionAlternativesList_1 (t):
    'ExtensionAdditionAlternativesList : COMMA ExtensionAdditionAlternative'
    t[0] = t[2]

def p_ExtensionAdditionAlternativesList_2 (t):
    'ExtensionAdditionAlternativesList : ExtensionAdditionAlternativesList COMMA ExtensionAdditionAlternative'
    t[0] = t[1] + t[3]

def p_ExtensionAdditionAlternative_1 (t):
    'ExtensionAdditionAlternative : NamedType'
    t[0] = [t[1]]

def p_ExtensionAdditionAlternative_2 (t):
    'ExtensionAdditionAlternative : ExtensionAdditionAlternativesGroup'
    t[0] = t[1]

def p_ExtensionAdditionAlternativesGroup (t):
  'ExtensionAdditionAlternativesGroup : LVERBRACK VersionNumber AlternativeTypeList RVERBRACK'
  t[0] = t[3]

def p_AlternativeTypeList_1 (t):
    'AlternativeTypeList : NamedType'
    t[0] = [t[1]]

def p_AlternativeTypeList_2 (t):
    'AlternativeTypeList : AlternativeTypeList COMMA NamedType'
    t[0] = t[1] + [t[3]]

# 28.10
def p_ChoiceValue_1 (t):
  '''ChoiceValue : identifier COLON Value
                 | identifier COLON NullValue '''
  val = t[3]
  if not isinstance(val, Value):
    val = Value(val=val)
  t[0] = ChoiceValue (choice = t[1], val = val)

# 29 Notation for selection types

# 29.1
def p_SelectionType (t): #
  'SelectionType : identifier LT Type'
  t[0] = SelectionType (typ = t[3], sel = t[1])

# 30 Notation for tagged types ------------------------------------------------

# 30.1
def p_TaggedType_1 (t):
    'TaggedType : Tag Type'
    t[1].mode = 'default'
    t[0] = t[2]
    t[0].AddTag(t[1])

def p_TaggedType_2 (t):
    '''TaggedType : Tag IMPLICIT Type
                  | Tag EXPLICIT Type'''
    t[1].mode = t[2]
    t[0] = t[3]
    t[0].AddTag(t[1])

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


# 31 Notation for the object identifier type ----------------------------------

# 31.1
def p_ObjectIdentifierType (t):
  'ObjectIdentifierType : OBJECT IDENTIFIER'
  t[0] = ObjectIdentifierType()

# 31.3
def p_ObjectIdentifierValue (t):
    'ObjectIdentifierValue : LBRACE oid_comp_list RBRACE'
    t[0] = ObjectIdentifierValue (comp_list=t[2])

def p_oid_comp_list_1 (t):
    'oid_comp_list : oid_comp_list ObjIdComponents'
    t[0] = t[1] + [t[2]]

def p_oid_comp_list_2 (t):
    'oid_comp_list : ObjIdComponents'
    t[0] = [t[1]]

def p_ObjIdComponents (t):
  '''ObjIdComponents : NameForm
                     | NumberForm
                     | NameAndNumberForm'''
  t[0] = t[1]

def p_NameForm (t):
  '''NameForm : LCASE_IDENT
              | LCASE_IDENT_ASSIGNED'''
  t [0] = t[1]

def p_NumberForm (t):
  '''NumberForm : NUMBER'''
#                | DefinedValue'''
  t [0] = t[1]

def p_NameAndNumberForm (t):
  '''NameAndNumberForm : LCASE_IDENT_ASSIGNED LPAREN NumberForm RPAREN
                       | LCASE_IDENT LPAREN NumberForm RPAREN'''
  t[0] = Node('name_and_number', ident = t[1], number = t[3])

# 32 Notation for the relative object identifier type -------------------------

# 32.1
def p_RelativeOIDType (t):
  'RelativeOIDType : RELATIVE_OID'
  t[0] = RelativeOIDType()

# 33 Notation for the embedded-pdv type ---------------------------------------

# 33.1
def p_EmbeddedPDVType (t):
  'EmbeddedPDVType : EMBEDDED PDV'
  t[0] = EmbeddedPDVType()

# 34 Notation for the external type -------------------------------------------

# 34.1
def p_ExternalType (t):
  'ExternalType : EXTERNAL'
  t[0] = ExternalType()

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
  'ElementSetSpecs : RootElementSetSpec COMMA ELLIPSIS COMMA AdditionalElementSetSpec'
  t[0] = t[1]
  t[0].ext = True

def p_RootElementSetSpec (t):
  'RootElementSetSpec : ElementSetSpec'
  t[0] = t[1]

def p_AdditionalElementSetSpec (t):
  'AdditionalElementSetSpec : ElementSetSpec'
  t[0] = t[1]

def p_ElementSetSpec (t):
  'ElementSetSpec : Unions'
  t[0] = t[1]

def p_Unions_1 (t):
  'Unions : Intersections'
  t[0] = t[1]

def p_Unions_2 (t):
  'Unions : UElems UnionMark Intersections'
  t[0] = Constraint(type = 'Union', subtype = [t[1], t[3]])

def p_UElems (t):
  'UElems : Unions'
  t[0] = t[1]

def p_Intersections_1 (t):
  'Intersections : IntersectionElements'
  t[0] = t[1]

def p_Intersections_2 (t):
  'Intersections : IElems IntersectionMark IntersectionElements'
  t[0] = Constraint(type = 'Intersection', subtype = [t[1], t[3]])

def p_IElems (t):
  'IElems : Intersections'
  t[0] = t[1]

def p_IntersectionElements (t):
  'IntersectionElements : Elements'
  t[0] = t[1]

def p_UnionMark (t):
  '''UnionMark : BAR
               | UNION'''

def p_IntersectionMark (t):
  '''IntersectionMark : CIRCUMFLEX
                      | INTERSECTION'''

# 46.5
def p_Elements_1 (t):
  'Elements : SubtypeElements'
  t[0] = t[1]

def p_Elements_2 (t):
  'Elements : LPAREN ElementSetSpec RPAREN'
  t[0] = t[2]

# 47 Subtype elements ---------------------------------------------------------

# 47.1 General
def p_SubtypeElements (t):
    '''SubtypeElements : SingleValue
                       | ContainedSubtype
                       | ValueRange
                       | PermittedAlphabet
                       | SizeConstraint
                       | TypeConstraint
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
  'ValueRange : LowerEndpoint RANGE UpperEndpoint'
  t[0] = Constraint(type = 'ValueRange', subtype = [t[1], t[3]])

# 47.4.3
def p_LowerEndpoint_1 (t):
  'LowerEndpoint : LowerEndValue'
  t[0] = t[1]

def p_LowerEndpoint_2 (t):
  'LowerEndpoint : LowerEndValue LT'
  t[0] = t[1] # but not inclusive range

def p_UpperEndpoint_1 (t):
  'UpperEndpoint : UpperEndValue'
  t[0] = t[1]

def p_UpperEndpoint_2 (t):
  'UpperEndpoint : LT UpperEndValue'
  t[0] = t[1] # but not inclusive range

# 47.4.4
def p_LowerEndValue (t):
  '''LowerEndValue : Value
                   | MIN'''
  t[0] = t[1] # XXX

def p_UpperEndValue (t):
  '''UpperEndValue : Value
                    | MAX'''
  t[0] = t[1]

# 47.5 Size constraint
# 47.5.1
def p_SizeConstraint (t):
    'SizeConstraint : SIZE Constraint'
    t[0] = Constraint (type = 'Size', subtype = t[2])

# 47.6 Type constraint
# 47.6.1
def p_TypeConstraint (t):
    'TypeConstraint : Type'
    t[0] = Constraint (type = 'Type', subtype = t[1])

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
def p_ExceptionSpec_1 (t):
  'ExceptionSpec : EXCLAMATION ExceptionIdentification'
  pass

def p_ExceptionSpec_2 (t):
  'ExceptionSpec : '
  pass

def p_ExceptionIdentification (t):
  '''ExceptionIdentification : SignedNumber
                             | DefinedValue
                             | Type COLON Value '''
  pass

#  /*-----------------------------------------------------------------------*/
#  /* Value Notation Productions */
#  /*-----------------------------------------------------------------------*/



def p_binary_string (t):
  'binary_string : BSTRING'
  t[0] = BStringValue(val = t[1])

def p_hex_string (t):
  'hex_string : HSTRING'
  t[0] = HStringValue(val = t[1])

def p_char_string (t):
    'char_string : QSTRING'
    t[0] = t[1]

def p_number (t):
  'number : NUMBER'
  t[0] = t[1]


#--- ITU-T Recommendation X.208 -----------------------------------------------

# 27 Notation for the any type ------------------------------------------------

# 27.1
def p_AnyType (t):
  '''AnyType : ANY
             | ANY DEFINED BY identifier'''
  t[0] = AnyType()

#--- ITU-T Recommendation X.681 -----------------------------------------------

# 7 ASN.1 lexical items -------------------------------------------------------

# 7.1 Information object class references

def p_objectclassreference (t):
  'objectclassreference : CLASS_IDENT'
  t[0] = Class_Ref(val=t[1])

# 7.2 Information object references

def p_objectreference (t):
  'objectreference : LCASE_IDENT'
  t[0] = t[1]

# 7.3 Information object set references

#def p_objectsetreference (t):
#  'objectsetreference : UCASE_IDENT'
#  t[0] = t[1]

# 7.4 Type field references
# ucasefieldreference
# 7.5 Value field references
# lcasefieldreference
# 7.6 Value set field references
# ucasefieldreference
# 7.7 Object field references
# lcasefieldreference
# 7.8 Object set field references
# ucasefieldreference

def p_ucasefieldreference (t):
  'ucasefieldreference : AMPERSAND UCASE_IDENT'
  t[0] = '&' + t[2]

def p_lcasefieldreference (t):
  'lcasefieldreference : AMPERSAND LCASE_IDENT'
  t[0] = '&' + t[2]

# 8 Referencing definitions

# 8.1
def p_DefinedObjectClass (t):
  '''DefinedObjectClass : objectclassreference
                        | UsefulObjectClassReference'''
  t[0] = t[1]
  global obj_class
  obj_class = t[0].val

def p_DefinedObject (t):
  '''DefinedObject : objectreference'''
  t[0] = t[1]

# 8.4
def p_UsefulObjectClassReference (t):
  '''UsefulObjectClassReference : TYPE_IDENTIFIER
                                | ABSTRACT_SYNTAX'''
  t[0] = Class_Ref(val=t[1])

# 9 Information object class definition and assignment

# 9.1
def p_ObjectClassAssignment (t):
  '''ObjectClassAssignment : CLASS_IDENT ASSIGNMENT ObjectClass
                           | UCASE_IDENT ASSIGNMENT ObjectClass'''
  t[0] = t[3]
  t[0].SetName(t[1])
  if isinstance(t[0], ObjectClassDefn):
    t[0].reg_types()

# 9.2
def p_ObjectClass (t):
  '''ObjectClass : DefinedObjectClass
                 | ObjectClassDefn
                 | ParameterizedObjectClass '''
  t[0] = t[1]

# 9.3
def p_ObjectClassDefn (t):
  '''ObjectClassDefn : CLASS LBRACE FieldSpecs RBRACE
                     | CLASS LBRACE FieldSpecs RBRACE WithSyntaxSpec'''
  t[0] = ObjectClassDefn(fields = t[3])

def p_FieldSpecs_1 (t):
  'FieldSpecs : FieldSpec'
  t[0] = [t[1]]

def p_FieldSpecs_2 (t):
  'FieldSpecs : FieldSpecs COMMA FieldSpec'
  t[0] = t[1] + [t[3]]

def p_WithSyntaxSpec (t):
  'WithSyntaxSpec : WITH SYNTAX lbraceignore rbraceignore'
  t[0] = None

# 9.4
def p_FieldSpec (t):
  '''FieldSpec : TypeFieldSpec
               | FixedTypeValueFieldSpec
               | VariableTypeValueFieldSpec
               | FixedTypeValueSetFieldSpec
               | ObjectFieldSpec
               | ObjectSetFieldSpec '''
  t[0] = t[1]

# 9.5
def p_TypeFieldSpec (t):
  '''TypeFieldSpec : ucasefieldreference
                   | ucasefieldreference TypeOptionalitySpec '''
  t[0] = TypeFieldSpec()
  t[0].SetName(t[1])

def p_TypeOptionalitySpec_1 (t):
  'TypeOptionalitySpec ::= OPTIONAL'
  pass

def p_TypeOptionalitySpec_2 (t):
  'TypeOptionalitySpec ::= DEFAULT Type'
  pass

# 9.6
def p_FixedTypeValueFieldSpec (t):
  '''FixedTypeValueFieldSpec : lcasefieldreference Type
                             | lcasefieldreference Type UNIQUE
                             | lcasefieldreference Type ValueOptionalitySpec
                             | lcasefieldreference Type UNIQUE ValueOptionalitySpec '''
  t[0] = FixedTypeValueFieldSpec(typ = t[2])
  t[0].SetName(t[1])

def p_ValueOptionalitySpec_1 (t):
  'ValueOptionalitySpec ::= OPTIONAL'
  pass

def p_ValueOptionalitySpec_2 (t):
  'ValueOptionalitySpec ::= DEFAULT Value'
  pass

# 9.8

def p_VariableTypeValueFieldSpec (t):
  '''VariableTypeValueFieldSpec : lcasefieldreference FieldName
                                | lcasefieldreference FieldName ValueOptionalitySpec '''
  t[0] = VariableTypeValueFieldSpec()
  t[0].SetName(t[1])

# 9.9
def p_FixedTypeValueSetFieldSpec (t):
  '''FixedTypeValueSetFieldSpec : ucasefieldreference Type
                                | ucasefieldreference Type ValueSetOptionalitySpec '''
  t[0] = FixedTypeValueSetFieldSpec()
  t[0].SetName(t[1])

def p_ValueSetOptionalitySpec_1 (t):
  'ValueSetOptionalitySpec ::= OPTIONAL'
  pass

def p_ValueSetOptionalitySpec_2 (t):
  'ValueSetOptionalitySpec ::= DEFAULT ValueSet'
  pass

# 9.11
def p_ObjectFieldSpec (t):
  '''ObjectFieldSpec : lcasefieldreference DefinedObjectClass
                     | lcasefieldreference DefinedObjectClass ObjectOptionalitySpec '''
  t[0] = ObjectFieldSpec(cls=t[2])
  t[0].SetName(t[1])
  global obj_class
  obj_class = None

def p_ObjectOptionalitySpec_1 (t):
  'ObjectOptionalitySpec ::= OPTIONAL'
  pass

def p_ObjectOptionalitySpec_2 (t):
  'ObjectOptionalitySpec ::= DEFAULT Object'
  pass

# 9.12
def p_ObjectSetFieldSpec (t):
  '''ObjectSetFieldSpec : ucasefieldreference DefinedObjectClass
                        | ucasefieldreference DefinedObjectClass ObjectSetOptionalitySpec '''
  t[0] = ObjectSetFieldSpec(cls=t[2])
  t[0].SetName(t[1])

def p_ObjectSetOptionalitySpec_1 (t):
  'ObjectSetOptionalitySpec ::= OPTIONAL'
  pass

def p_ObjectSetOptionalitySpec_2 (t):
  'ObjectSetOptionalitySpec ::= DEFAULT ObjectSet'
  pass

# 9.13
def p_PrimitiveFieldName (t):
  '''PrimitiveFieldName : ucasefieldreference
                        | lcasefieldreference '''
  t[0] = t[1]

# 9.13
def p_FieldName_1 (t):
  'FieldName : PrimitiveFieldName'
  t[0] = t[1]

def p_FieldName_2 (t):
  'FieldName : FieldName DOT PrimitiveFieldName'
  t[0] = t[1] + '.' + t[3]

# 11 Information object definition and assignment

# 11.1
def p_ObjectAssignment (t):
  'ObjectAssignment : objectreference DefinedObjectClass ASSIGNMENT Object'
  t[0] = ObjectAssignment (ident = t[1], cls=t[2].val, val=t[4])
  global obj_class
  obj_class = None

# 11.3
def p_Object (t):
  '''Object : DefinedObject
            | ObjectDefn
            | ParameterizedObject'''
  t[0] = t[1]

# 11.4
def p_ObjectDefn (t):
  'ObjectDefn : lbraceobject bodyobject rbraceobject'
  t[0] = t[2]

#  {...} block of object definition
def p_lbraceobject(t):
  'lbraceobject : braceobjectbegin LBRACE'
  t[0] = t[1]

def p_braceobjectbegin(t):
  'braceobjectbegin : '
  global lexer
  global obj_class
  if set_class_syntax(obj_class):
    state = 'INITIAL'
  else:
    lexer.level = 1
    state = 'braceignore'
  lexer.push_state(state)

def p_rbraceobject(t):
  'rbraceobject : braceobjectend RBRACE'
  t[0] = t[2]

def p_braceobjectend(t):
  'braceobjectend : '
  global lexer
  lexer.pop_state()
  set_class_syntax(None)

def p_bodyobject_1 (t):
  'bodyobject : '
  t[0] = { }

def p_bodyobject_2 (t):
  'bodyobject : cls_syntax_list'
  t[0] = t[1]

def p_cls_syntax_list_1 (t):
  'cls_syntax_list : cls_syntax_list cls_syntax'
  t[0] = t[1]
  t[0].update(t[2])

def p_cls_syntax_list_2 (t):
  'cls_syntax_list : cls_syntax'
  t[0] = t[1]

# X.681
def p_cls_syntax_1 (t):
  'cls_syntax : Type IDENTIFIED BY Value'
  t[0] = { get_class_fieled(' ') : t[1], get_class_fieled(' '.join((t[2], t[3]))) : t[4] }

def p_cls_syntax_2 (t):
  'cls_syntax : HAS PROPERTY Value'
  t[0] = { get_class_fieled(' '.join(t[1:-1])) : t[-1:][0] }

# X.880
def p_cls_syntax_3 (t):
  '''cls_syntax : ERRORS ObjectSet
                 | LINKED ObjectSet
                 | RETURN RESULT BooleanValue
                 | SYNCHRONOUS BooleanValue
                 | INVOKE PRIORITY Value
                 | RESULT_PRIORITY Value
                 | PRIORITY Value
                 | ALWAYS RESPONDS BooleanValue
                 | IDEMPOTENT BooleanValue '''
  t[0] = { get_class_fieled(' '.join(t[1:-1])) : t[-1:][0] }

def p_cls_syntax_4 (t):
  '''cls_syntax : ARGUMENT Type
                 | RESULT Type
                 | PARAMETER Type
                 | CODE Value '''
  t[0] = { get_class_fieled(t[1]) : t[2] }

def p_cls_syntax_5 (t):
  '''cls_syntax : ARGUMENT Type OPTIONAL BooleanValue
                 | RESULT Type OPTIONAL BooleanValue
                 | PARAMETER Type OPTIONAL BooleanValue '''
  t[0] = { get_class_fieled(t[1]) : t[2], get_class_fieled(' '.join((t[1], t[3]))) : t[4] }

# 12 Information object set definition and assignment

# 12.1
def p_ObjectSetAssignment (t):
  'ObjectSetAssignment : UCASE_IDENT CLASS_IDENT ASSIGNMENT ObjectSet'
  t[0] = Node('ObjectSetAssignment', name=t[1], cls=t[2], val=t[4])

# 12.3
def p_ObjectSet (t):
  'ObjectSet : lbraceignore rbraceignore'
  t[0] = None

# 14 Notation for the object class field type ---------------------------------

# 14.1
def p_ObjectClassFieldType (t):
  'ObjectClassFieldType : DefinedObjectClass DOT FieldName'
  t[0] = get_type_from_class(t[1], t[3])

# 14.6
def p_ObjectClassFieldValue (t):
  '''ObjectClassFieldValue : OpenTypeFieldVal'''
  t[0] = t[1]

def p_OpenTypeFieldVal (t):
  '''OpenTypeFieldVal : Type COLON Value
                      | NullType COLON NullValue'''
  t[0] = t[3]


# 15 Information from objects -------------------------------------------------

# 15.1

def p_ValueFromObject (t):
  'ValueFromObject : LCASE_IDENT DOT FieldName'
  t[0] = t[1] + '.' + t[3]


# Annex C - The instance-of type ----------------------------------------------

# C.2
def p_InstanceOfType (t):
  'InstanceOfType : INSTANCE OF DefinedObjectClass'
  t[0] = InstanceOfType()


# ---  tables ---

useful_object_class_types = {
  # Annex A
  'TYPE-IDENTIFIER.&id'   : lambda : ObjectIdentifierType(),
  'TYPE-IDENTIFIER.&Type' : lambda : OpenType(),
  # Annex B
  'ABSTRACT-SYNTAX.&id'       : lambda : ObjectIdentifierType(),
  'ABSTRACT-SYNTAX.&Type'     : lambda : OpenType(),
  'ABSTRACT-SYNTAX.&property' : lambda : BitStringType(),
}

object_class_types = { }

object_class_typerefs = { }

object_class_classrefs = { }

# dummy types
class _VariableTypeValueFieldSpec (AnyType):
  pass

class _FixedTypeValueSetFieldSpec (AnyType):
  pass

class_types_creator = {
  'BooleanType'          : lambda : BooleanType(),
  'IntegerType'          : lambda : IntegerType(),
  'ObjectIdentifierType' : lambda : ObjectIdentifierType(),
  'OpenType'             : lambda : OpenType(),
  # dummy types
  '_VariableTypeValueFieldSpec' : lambda : _VariableTypeValueFieldSpec(),
  '_FixedTypeValueSetFieldSpec' : lambda : _FixedTypeValueSetFieldSpec(),
}

class_names = { }

x681_syntaxes = {
  'TYPE-IDENTIFIER' : {
    ' '             : '&Type',
    'IDENTIFIED'    : 'IDENTIFIED',
    #'BY'            : 'BY',
    'IDENTIFIED BY' : '&id',
  },
  'ABSTRACT-SYNTAX' : {
    ' '             : '&Type',
    'IDENTIFIED'    : 'IDENTIFIED',
    #'BY'            : 'BY',
    'IDENTIFIED BY' : '&id',
    'HAS'           : 'HAS',
    'PROPERTY'      : 'PROPERTY',
    'HAS PROPERTY'  : '&property',
  },
}

class_syntaxes_enabled = {
  'TYPE-IDENTIFIER' : True,
  'ABSTRACT-SYNTAX' : True,
}

class_syntaxes = {
  'TYPE-IDENTIFIER' : x681_syntaxes['TYPE-IDENTIFIER'],
  'ABSTRACT-SYNTAX' : x681_syntaxes['ABSTRACT-SYNTAX'],
}

class_current_syntax = None

def get_syntax_tokens(syntaxes):
  tokens = { }
  for s in (syntaxes):
    for k in (list(syntaxes[s].keys())):
      if k.find(' ') < 0:
        tokens[k] = k
        tokens[k] = tokens[k].replace('-', '_')
  return list(tokens.values())

tokens = tokens + get_syntax_tokens(x681_syntaxes)

def set_class_syntax(syntax):
  global class_syntaxes_enabled
  global class_current_syntax
  #print "set_class_syntax", syntax, class_current_syntax
  if class_syntaxes_enabled.get(syntax, False):
    class_current_syntax = syntax
    return True
  else:
    class_current_syntax = None
    return False

def is_class_syntax(name):
  global class_syntaxes
  global class_current_syntax
  #print "is_class_syntax", name, class_current_syntax
  if not class_current_syntax:
    return False
  return name in class_syntaxes[class_current_syntax]

def get_class_fieled(name):
  if not class_current_syntax:
    return None
  return class_syntaxes[class_current_syntax][name]

def is_class_ident(name):
  return name in class_names

def add_class_ident(name):
  #print "add_class_ident", name
  class_names[name] = name

def get_type_from_class(cls, fld):
  flds = fld.split('.')
  if (isinstance(cls, Class_Ref)):
    key = cls.val + '.' + flds[0]
  else:
    key = cls + '.' + flds[0]

  if key in object_class_classrefs:
    return get_type_from_class(object_class_classrefs[key], '.'.join(flds[1:]))

  if key in object_class_typerefs:
    return Type_Ref(val=object_class_typerefs[key])

  creator = lambda : AnyType()
  creator = useful_object_class_types.get(key, creator)
  creator = object_class_types.get(key, creator)
  return creator()

def set_type_to_class(cls, fld, pars):
  #print "set_type_to_class", cls, fld, pars
  key = cls + '.' + fld
  typename = 'OpenType'
  if (len(pars) > 0):
    typename = pars[0]
  else:
    pars.append(typename)
  typeref = None
  if (len(pars) > 1):
    if (isinstance(pars[1], Class_Ref)):
      pars[1] = pars[1].val
    typeref = pars[1]

  msg = None
  if key in object_class_types:
    msg = object_class_types[key]().type
  if key in object_class_typerefs:
    msg = "TypeReference " + object_class_typerefs[key]
  if key in object_class_classrefs:
    msg = "ClassReference " + object_class_classrefs[key]

  if msg == ' '.join(pars):
    msg = None

  if msg:
    msg0 = "Can not define CLASS field %s as '%s'\n" % (key, ' '.join(pars))
    msg1 = "Already defined as '%s'" % (msg)
    raise CompError(msg0 + msg1)

  if (typename == 'ClassReference'):
    if not typeref: return False
    object_class_classrefs[key] = typeref
    return True

  if (typename == 'TypeReference'):
    if not typeref: return False
    object_class_typerefs[key] = typeref
    return True

  creator = class_types_creator.get(typename)
  if creator:
    object_class_types[key] = creator
    return True
  else:
    return False

def import_class_from_module(mod, cls):
  add_class_ident(cls)
  mcls = "$%s$%s" % (mod, cls)
  for k in list(object_class_classrefs.keys()):
    kk = k.split('.', 1)
    if kk[0] == mcls:
      object_class_classrefs[cls + '.' + kk[0]] = object_class_classrefs[k]
  for k in list(object_class_typerefs.keys()):
    kk = k.split('.', 1)
    if kk[0] == mcls:
      object_class_typerefs[cls + '.' + kk[0]] = object_class_typerefs[k]
  for k in list(object_class_types.keys()):
    kk = k.split('.', 1)
    if kk[0] == mcls:
      object_class_types[cls + '.' + kk[0]] = object_class_types[k]

#--- ITU-T Recommendation X.682 -----------------------------------------------

# 8 General constraint specification ------------------------------------------

# 8.1
def p_GeneralConstraint (t):
  '''GeneralConstraint : UserDefinedConstraint
                       | TableConstraint
                       | ContentsConstraint'''
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
  'UserDefinedConstraintParameter : Type'
  t[0] = t[1]

# 10 Table constraints, including component relation constraints --------------

# 10.3
def p_TableConstraint (t):
  '''TableConstraint : SimpleTableConstraint
                     | ComponentRelationConstraint'''
  t[0] = Constraint(type = 'Table', subtype = t[1])

def p_SimpleTableConstraint (t):
  'SimpleTableConstraint : LBRACE UCASE_IDENT RBRACE'
  t[0] = t[2]

# 10.7
def p_ComponentRelationConstraint (t):
  'ComponentRelationConstraint : LBRACE UCASE_IDENT RBRACE LBRACE AtNotations RBRACE'
  t[0] = t[2] + str(t[5])

def p_AtNotations_1 (t):
  'AtNotations : AtNotation'
  t[0] = [t[1]]

def p_AtNotations_2 (t):
  'AtNotations : AtNotations COMMA  AtNotation'
  t[0] = t[1] + [t[3]]

def p_AtNotation_1 (t):
  'AtNotation : AT ComponentIdList'
  t[0] = '@' + t[2]

def p_AtNotation_2 (t):
  'AtNotation : AT DOT Level ComponentIdList'
  t[0] = '@.' + t[3] + t[4]

def p_Level_1 (t):
  'Level : DOT Level'
  t[0] = '.' + t[2]

def p_Level_2 (t):
  'Level : '
  t[0] = ''

def p_ComponentIdList_1 (t):
  'ComponentIdList : LCASE_IDENT'
  t[0] = t[1]

def p_ComponentIdList_2 (t):
  'ComponentIdList : ComponentIdList DOT LCASE_IDENT'
  t[0] = t[1] + '.' + t[3]

# 11 Contents constraints -----------------------------------------------------

# 11.1
def p_ContentsConstraint (t):
  'ContentsConstraint : CONTAINING type_ref'
  t[0] = Constraint(type = 'Contents', subtype = t[2])


#--- ITU-T Recommendation X.683 -----------------------------------------------

# 8 Parameterized assignments -------------------------------------------------

# 8.1
def p_ParameterizedAssignment (t):
  '''ParameterizedAssignment : ParameterizedTypeAssignment
                             | ParameterizedObjectClassAssignment
                             | ParameterizedObjectAssignment
                             | ParameterizedObjectSetAssignment'''
  t[0] = t[1]

# 8.2
def p_ParameterizedTypeAssignment (t):
  'ParameterizedTypeAssignment : UCASE_IDENT ParameterList ASSIGNMENT Type'
  t[0] = t[4]
  t[0].SetName(t[1])  # t[0].SetName(t[1] + 'xxx')

def p_ParameterizedObjectClassAssignment (t):
  '''ParameterizedObjectClassAssignment : CLASS_IDENT ParameterList ASSIGNMENT ObjectClass
                                        | UCASE_IDENT ParameterList ASSIGNMENT ObjectClass'''
  t[0] = t[4]
  t[0].SetName(t[1])
  if isinstance(t[0], ObjectClassDefn):
    t[0].reg_types()

def p_ParameterizedObjectAssignment (t):
  'ParameterizedObjectAssignment : objectreference ParameterList DefinedObjectClass ASSIGNMENT Object'
  t[0] = ObjectAssignment (ident = t[1], cls=t[3].val, val=t[5])
  global obj_class
  obj_class = None

def p_ParameterizedObjectSetAssignment (t):
  'ParameterizedObjectSetAssignment : UCASE_IDENT ParameterList DefinedObjectClass ASSIGNMENT ObjectSet'
  t[0] = Node('ObjectSetAssignment', name=t[1], cls=t[3].val, val=t[5])

# 8.3
def p_ParameterList (t):
  'ParameterList : lbraceignore rbraceignore'

#def p_ParameterList (t):
#  'ParameterList : LBRACE Parameters RBRACE'
#  t[0] = t[2]

#def p_Parameters_1 (t):
#  'Parameters : Parameter'
#  t[0] = [t[1]]

#def p_Parameters_2 (t):
#  'Parameters : Parameters COMMA Parameter'
#  t[0] = t[1] + [t[3]]

#def p_Parameter_1 (t):
#  'Parameter : Type COLON Reference'
#  t[0] = [t[1], t[3]]

#def p_Parameter_2 (t):
#  'Parameter : Reference'
#  t[0] = t[1]


# 9 Referencing parameterized definitions -------------------------------------

# 9.1
def p_ParameterizedReference (t):
  'ParameterizedReference : Reference LBRACE RBRACE'
  t[0] = t[1]
  #t[0].val += 'xxx'

# 9.2
def p_ParameterizedType (t):
  'ParameterizedType : type_ref ActualParameterList'
  t[0] = t[1]
  #t[0].val += 'xxx'


def p_ParameterizedObjectClass (t):
  'ParameterizedObjectClass : DefinedObjectClass ActualParameterList'
  t[0] = t[1]
  #t[0].val += 'xxx'

def p_ParameterizedObject (t):
  'ParameterizedObject : DefinedObject ActualParameterList'
  t[0] = t[1]
  #t[0].val += 'xxx'

# 9.5
def p_ActualParameterList (t):
  'ActualParameterList : lbraceignore rbraceignore'

#def p_ActualParameterList (t):
#  'ActualParameterList : LBRACE ActualParameters RBRACE'
#  t[0] = t[2]

#def p_ActualParameters_1 (t):
#  'ActualParameters : ActualParameter'
#  t[0] = [t[1]]

#def p_ActualParameters_2 (t):
#  'ActualParameters : ActualParameters COMMA ActualParameter'
#  t[0] = t[1] + [t[3]]

#def p_ActualParameter (t):
#  '''ActualParameter : Type
#                     | Value'''
#  t[0] = t[1]


#--- ITU-T Recommendation X.880 -----------------------------------------------

x880_classes = {
  'OPERATION' : {
    '&ArgumentType'         : [],
    '&argumentTypeOptional' : [ 'BooleanType' ],
    '&returnResult'         : [ 'BooleanType' ],
    '&ResultType'           : [],
    '&resultTypeOptional'   : [ 'BooleanType' ],
    '&Errors'               : [ 'ClassReference', 'ERROR' ],
    '&Linked'               : [ 'ClassReference', 'OPERATION' ],
    '&synchronous'          : [ 'BooleanType' ],
    '&idempotent'           : [ 'BooleanType' ],
    '&alwaysReturns'        : [ 'BooleanType' ],
    '&InvokePriority'       : [ '_FixedTypeValueSetFieldSpec' ],
    '&ResultPriority'       : [ '_FixedTypeValueSetFieldSpec' ],
    '&operationCode'        : [ 'TypeReference', 'Code' ],
  },
  'ERROR' : {
    '&ParameterType'         : [],
    '&parameterTypeOptional' : [ 'BooleanType' ],
    '&ErrorPriority'         : [ '_FixedTypeValueSetFieldSpec' ],
    '&errorCode'             : [ 'TypeReference', 'Code' ],
  },
  'OPERATION-PACKAGE' : {
    '&Both'     : [ 'ClassReference', 'OPERATION' ],
    '&Consumer' : [ 'ClassReference', 'OPERATION' ],
    '&Supplier' : [ 'ClassReference', 'OPERATION' ],
    '&id'       : [ 'ObjectIdentifierType' ],
  },
  'CONNECTION-PACKAGE' : {
    '&bind'               : [ 'ClassReference', 'OPERATION' ],
    '&unbind'             : [ 'ClassReference', 'OPERATION' ],
    '&responderCanUnbind' : [ 'BooleanType' ],
    '&unbindCanFail'      : [ 'BooleanType' ],
    '&id'                 : [ 'ObjectIdentifierType' ],
  },
  'CONTRACT' : {
    '&connection'          : [ 'ClassReference', 'CONNECTION-PACKAGE' ],
    '&OperationsOf'        : [ 'ClassReference', 'OPERATION-PACKAGE' ],
    '&InitiatorConsumerOf' : [ 'ClassReference', 'OPERATION-PACKAGE' ],
    '&InitiatorSupplierOf' : [ 'ClassReference', 'OPERATION-PACKAGE' ],
    '&id'                  : [ 'ObjectIdentifierType' ],
  },
  'ROS-OBJECT-CLASS' : {
    '&Is'                   : [ 'ClassReference', 'ROS-OBJECT-CLASS' ],
    '&Initiates'            : [ 'ClassReference', 'CONTRACT' ],
    '&Responds'             : [ 'ClassReference', 'CONTRACT' ],
    '&InitiatesAndResponds' : [ 'ClassReference', 'CONTRACT' ],
    '&id'                   : [ 'ObjectIdentifierType' ],
  },
}

x880_syntaxes = {
  'OPERATION' : {
    'ARGUMENT'       : '&ArgumentType',
    'ARGUMENT OPTIONAL' : '&argumentTypeOptional',
    'RESULT'         : '&ResultType',
    'RESULT OPTIONAL' : '&resultTypeOptional',
    'RETURN'         : 'RETURN',
    'RETURN RESULT'  : '&returnResult',
    'ERRORS'         : '&Errors',
    'LINKED'         : '&Linked',
    'SYNCHRONOUS'    : '&synchronous',
    'IDEMPOTENT'     : '&idempotent',
    'ALWAYS'         : 'ALWAYS',
    'RESPONDS'       : 'RESPONDS',
    'ALWAYS RESPONDS' : '&alwaysReturns',
    'INVOKE'         : 'INVOKE',
    'PRIORITY'       : 'PRIORITY',
    'INVOKE PRIORITY' : '&InvokePriority',
    'RESULT-PRIORITY': '&ResultPriority',
    'CODE'           : '&operationCode',
  },
  'ERROR' : {
    'PARAMETER'      : '&ParameterType',
    'PARAMETER OPTIONAL' : '&parameterTypeOptional',
    'PRIORITY'       : '&ErrorPriority',
    'CODE'           : '&errorCode',
  },
#  'OPERATION-PACKAGE' : {
#  },
#  'CONNECTION-PACKAGE' : {
#  },
#  'CONTRACT' : {
#  },
#  'ROS-OBJECT-CLASS' : {
#  },
}

def x880_module_begin():
  #print "x880_module_begin()"
  for name in list(x880_classes.keys()):
    add_class_ident(name)

def x880_import(name):
  if name in x880_syntaxes:
    class_syntaxes_enabled[name] = True
    class_syntaxes[name] = x880_syntaxes[name]
  if name in x880_classes:
    add_class_ident(name)
    for f in (list(x880_classes[name].keys())):
      set_type_to_class(name, f, x880_classes[name][f])

tokens = tokens + get_syntax_tokens(x880_syntaxes)

#  {...} OID value
#def p_lbrace_oid(t):
#  'lbrace_oid : brace_oid_begin LBRACE'
#  t[0] = t[1]

#def p_brace_oid_begin(t):
#  'brace_oid_begin : '
#  global in_oid
#  in_oid = True

#def p_rbrace_oid(t):
#  'rbrace_oid : brace_oid_end RBRACE'
#  t[0] = t[2]

#def p_brace_oid_end(t):
#  'brace_oid_end : '
#  global in_oid
#  in_oid = False

#  {...} block to be ignored
def p_lbraceignore(t):
  'lbraceignore : braceignorebegin LBRACE'
  t[0] = t[1]

def p_braceignorebegin(t):
  'braceignorebegin : '
  global lexer
  lexer.level = 1
  lexer.push_state('braceignore')

def p_rbraceignore(t):
  'rbraceignore : braceignoreend RBRACE'
  t[0] = t[2]

def p_braceignoreend(t):
  'braceignoreend : '
  global lexer
  lexer.pop_state()

def p_error(t):
  global input_file
  raise ParseError(t, input_file)

def p_pyquote (t):
    '''pyquote : PYQUOTE'''
    t[0] = PyQuote (val = t[1])


def testlex (s):
    lexer.input (s)
    while True:
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


# Wireshark compiler
def eth_usage():
  print """
asn2wrs [-h|?] [-d dbg] [-b] [-p proto] [-c cnf_file] [-e] input_file(s) ...
  -h|?          : Usage
  -b            : BER (default is PER)
  -u            : Unaligned (default is aligned)
  -p proto      : Protocol name (implies -S). Default is module-name
                  from input_file (renamed by #.MODULE if present)
  -o name       : Output files name core (default is <proto>)
  -O dir        : Output directory
  -c cnf_file   : Conformance file
  -I path       : Path for conformance file includes
  -e            : Create conformance file for exported types
  -E            : Just create conformance file for exported types
  -S            : Single output for multiple modules
  -s template   : Single file output (template is input file
                  without .c/.h extension)
  -k            : Keep intermediate files though single file output is used
  -L            : Suppress #line directive from .cnf file
  -D dir        : Directory for input_file(s) (default: '.')
  -C            : Add check for SIZE constraints
  -r prefix     : Remove the prefix from type names
  
  input_file(s) : Input ASN.1 file(s)

  -d dbg        : Debug output, dbg = [l][y][p][s][a][t][c][m][o]
                  l - lex
                  y - yacc
                  p - parsing
                  s - internal ASN.1 structure
                  a - list of assignments
                  t - tables
                  c - conformance values
                  m - list of compiled modules with dependency
                  o - list of output files
"""

def eth_main():
  global input_file
  global g_conform
  global lexer
  print "ASN.1 to Wireshark dissector compiler";
  try:
    opts, args = getopt.getopt(sys.argv[1:], "h?d:D:buXp:FTo:O:c:I:eESs:kLCr:");
  except getopt.GetoptError:
    eth_usage(); sys.exit(2)
  if len(args) < 1:
    eth_usage(); sys.exit(2)

  conform = EthCnf()
  conf_to_read = None
  output = EthOut()
  ectx = EthCtx(conform, output)
  ectx.encoding = 'per'
  ectx.proto_opt = None
  ectx.fld_opt = {}
  ectx.tag_opt = False
  ectx.outnm_opt = None
  ectx.aligned = True
  ectx.dbgopt = ''
  ectx.new = True
  ectx.expcnf = False
  ectx.justexpcnf = False
  ectx.merge_modules = False
  ectx.group_by_prot = False
  ectx.conform.last_group = 0
  ectx.conform.suppress_line = False;
  ectx.output.outnm = None
  ectx.output.single_file = None
  ectx.constraints_check = False;
  for o, a in opts:
    if o in ("-h", "-?"):
      eth_usage(); sys.exit(2)
    if o in ("-c",):
      conf_to_read = a
    if o in ("-I",):
      ectx.conform.include_path.append(a)
    if o in ("-E",):
      ectx.expcnf = True
      ectx.justexpcnf = True
    if o in ("-D",):
      ectx.srcdir = a
    if o in ("-C",):
      ectx.constraints_check = True
    if o in ("-X",):
        warnings.warn("Command line option -X is obsolete and can be removed")
    if o in ("-T",):
        warnings.warn("Command line option -T is obsolete and can be removed")

  if conf_to_read:
    ectx.conform.read(conf_to_read)

  for o, a in opts:
    if o in ("-h", "-?", "-c", "-I", "-E", "-D", "-C", "-X", "-T"):
      pass  # already processed
    else:
      par = []
      if a: par.append(a)
      ectx.conform.set_opt(o, par, "commandline", 0)

  (ld, yd, pd) = (0, 0, 0);
  if ectx.dbg('l'): ld = 1
  if ectx.dbg('y'): yd = 1
  if ectx.dbg('p'): pd = 2
  lexer = lex.lex(debug=ld)
  yacc.yacc(method='LALR', debug=yd)
  g_conform = ectx.conform
  ast = []
  for fn in args:
    input_file = fn
    lexer.lineno = 1
    if (ectx.srcdir): fn = ectx.srcdir + '/' + fn
    f = open (fn, "r")
    ast.extend(yacc.parse(f.read(), lexer=lexer, debug=pd))
    f.close ()
  ectx.eth_clean()
  if (ectx.merge_modules):  # common output for all module
    ectx.eth_clean()
    for module in ast:
      eth_do_module(module, ectx)
    ectx.eth_prepare()
    ectx.eth_do_output()
  elif (ectx.groups()):  # group by protocols/group
    groups = []
    pr2gr = {}
    if (ectx.group_by_prot):  # group by protocols
      for module in ast:
        prot = module.get_proto(ectx)
        if prot not in pr2gr:
          pr2gr[prot] = len(groups)
          groups.append([])
        groups[pr2gr[prot]].append(module)
    else:  # group by groups
      pass
    for gm in (groups):
      ectx.eth_clean()
      for module in gm:
        eth_do_module(module, ectx)
      ectx.eth_prepare()
      ectx.eth_do_output()
  else:   # output for each module
    for module in ast:
      ectx.eth_clean()
      eth_do_module(module, ectx)
      ectx.eth_prepare()
      ectx.eth_do_output()

  if ectx.dbg('m'):
    ectx.dbg_modules()

  if ectx.dbg('c'):
    ectx.conform.dbg_print()
  if not ectx.justexpcnf:
    ectx.conform.unused_report()

  if ectx.dbg('o'):
    ectx.output.dbg_print()
  ectx.output.make_single_file()


# Python compiler
def main():
    testfn = testyacc
    if len (sys.argv) == 1:
        while True:
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
  if (os.path.splitext(os.path.basename(sys.argv[0]))[0].lower() in ('asn2wrs', 'asn2eth')):
    eth_main()
  else:
    main()

#------------------------------------------------------------------------------
