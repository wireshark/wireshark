# wspy_dissector.py
#
# $Id$
#
# Wireshark Protocol Python Binding
#
# Copyright (c) 2009 by Sebastien Tandel <sebastien [AT] tandel [dot] be>
# Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

import ctypes as ct
from wspy_libws import get_libws_handle

# From epan/proto.h
# ? STA ? : is there a better way to include/define these constants?
# (duplicating definition is not a good thing)
(BASE_NONE,
BASE_DEC,
BASE_HEX,
BASE_OCT,
BASE_DEC_HEX,
BASE_HEX_DEC,
BASE_CUSTOM) = map(int, xrange(7))

# field types, see epan/ftypes/ftypes.h
(FT_NONE,
FT_PROTOCOL,
FT_BOOLEAN,
FT_UINT8,
FT_UINT16,
FT_UINT24,
FT_UINT32,
FT_UINT64,
FT_INT8,
FT_INT16,
FT_INT24,
FT_INT32,
FT_INT64,
FT_FLOAT,
FT_DOUBLE,
FT_ABSOLUTE_TIME,
FT_RELATIVE_TIME,
FT_STRING,
FT_STRINGZ,
FT_EBCDIC,
FT_UINT_STRING,
FT_ETHER,
FT_BYTES,
FT_UINT_BYTES,
FT_IPv4,
FT_IPv6,
FT_IPXNET,
FT_FRAMENUM,
FT_PCRE,
FT_GUID,
FT_OID) = map(int, xrange(31))

# hf_register_info from usual dissectors
class register_info(object):
  def __init__(self, wsl):
    self.__protocol = None
    self.__wsl = wsl
    self.__hf_register = None
    self.__registers = []

  def add(self, name, short_desc, \
          type=FT_UINT32, display=BASE_DEC, \
          strings=None, bitmask=0x0, desc=None):
    if not desc:
      desc = name
    self.__registers.append( (name, short_desc, \
          type, display, strings, bitmask, desc) )

  def register(self, protocol):
    self.__protocol = protocol
    hf = self.__registers
    lr = len(hf)
    if not lr:
      return None

    self.__hf_register = self.__wsl.hf_register_info_create(lr)
    chf = self.__hf_register
    if not self.__hf_register:
      return None

    for i in xrange(lr):
      n, sd, t, d, st, bm, ld = hf[i]
      sdn = sd.replace('.', '_')
      self.__dict__[sdn] = ct.c_int(-1)
      p_id = ct.pointer(self.__dict__[sdn])
      self.__wsl.hf_register_info_add(chf, i, p_id, n , sd, t, d, st, bm, ld)

    self.__wsl.proto_register_field_array(self.__protocol, chf, lr)

  def display(self):
    self.__wsl.hf_register_info_print(self.__hf_register, \
                                    len(self.__registers))

  def get(self):
    return self.__hf_register, len(self.__registers)

  def __del__(self):
    self.__wsl.hf_register_info_destroy(self.__hf_register)

#Subtrees definition
#Every subtree added can be accesses as an attribute after having been
#registered
class Subtree(object):
  def __init__(self, wsl, protocol):
    self.__wsl = wsl
    self.__protocol = protocol
    self.__st = {}
    self.__user_defined_protocol_tree = False

  def add(self, name):
    if name == self.__protocol:
      self.__user_defined_protocol_tree = True

    self.__st[name] = ct.c_int(-1)

  def has_user_defined_protocol_tree(self):
    return self.__user_defined_protocol_tree

  def register(self):
    if not self.__user_defined_protocol_tree:
      self.__st[self.__protocol] = ct.c_int(-1)

    ls = len(self.__st)
    if not ls:
      return

    CSubtrees = ct.POINTER(ct.c_int) * ls
    p_sts = CSubtrees()
    k = self.__st.keys()
    for i in xrange(ls):
      p_sts[i] = ct.pointer(self.__st[k[i]])

    self.__wsl.proto_register_subtree_array(p_sts, ls)

  def __getattr__(self, name):
    if self.__st.has_key(name):
      return self.__st[name]
    #raise KeyError

#Dissector class : base class to write a dissector in python
class Dissector(object):
  def __init__(self, protocol_name, short_desc, short):
    self.__protocol_name = protocol_name
    self.__short_desc = short_desc
    self.__short = short

    self.__tvb = None
    self.__pinfo = None
    self.__tree = None

    self.__Tree = None

    self.__offset = 0

    self.__wsl = get_libws_handle()
    self.__hf = None
    self.__subtree = None

  def _fields(self):
    '''hf property : hf_register_info fields. every defined field is available
    as an attribute of this object'''
    if not self.__hf:
      self.__hf = register_info(self.__wsl)
    return self.__hf
  hf = property(_fields)

  def _subtrees(self):
    '''subtrees property : subtress definition. every subtree added is
    accessible as an attribute of this object'''
    if not self.__subtree:
      self.__subtree = Subtree(self.__wsl, self.__short)
    return self.__subtree
  subtrees = property(_subtrees)

  def _tree(self):
    '''tree property : initial tree at the start of the dissection'''
    if not self.__Tree:
      self.__Tree = Tree(self.__tree, self)
    return self.__Tree
  tree = property(_tree)

  def display(self):
    print self.__short

  def _libhandle(self):
    '''libhandle property : return a handle to the libwireshark lib. You don't
    want to use this in normal situation. Use it only if you know what you're
    doing.'''
    return self.__wsl
  libhandle = property(_libhandle)

  def _raw_tree(self):
    '''raw_tree property : returns the raw tree pointer. You can use this with
    libhandle. You don't want to use this in normal situation. Use it only if
    you know what you're doing.'''
    return self.__tree
  raw_tree = property(_raw_tree)

  def _raw_pinfo(self):
    '''raw_pinfo property : return the raw pinfo pointer. You can use this with
    libhandle. You don't want to use this in normal situation. Use it only if
    you know what you're doing.'''
    return self.__pinfo
  raw_pinfo = property(_raw_pinfo)

  def _raw_tvb(self):
    '''raw_tvb property : returns the raw tvb pointer. You can use this with
    libhandle. You don't want to use this in normal situation. Use it only if
    you know what you're doing.'''
    return self.__tvb
  raw_tvb = property(_raw_tvb)

  def __str__(self):
    # STA TODO : keep with short_desc because used in the hash table of
    # dissectors in C code. If it is modified, it won't work anymore
    return self.__short_desc

  def __unicode__(self):
    return self.__short

  def __hash__(self):
    return hash(self.__short)

  def protocol(self):
    return self.__protocol

  def register_protocol(self):
    '''private function called by libwireshark when registering all
    protocols'''
    self.__protocol = \
      self.__wsl.proto_register_protocol( \
        self.__protocol_name, self.__short_desc, \
        self.__short)
    self.__hf.register(self.__protocol)
    #self.__hf.display()
    self.subtrees.register()

  def dissect(self):
    '''point of entry when starting dissecting a packet. This method must be
    therefore overloaded by the object implementing the dissector of a specific
    protocol.'''
    raise AttributeError('Dissector.dissect must be overridden')

  def pre_dissect(self):
    '''private method executed right before dissect in order to retrieve some
    internal information and enabling the possibility to add the base tree of
    this protocol dissection to the tree without any user intervention'''

    self.__tvb = ct.c_void_p()
    self.__pinfo = ct.c_void_p()
    self.__tree = ct.c_void_p()
    self.__wsl.py_dissector_args(ct.byref(self.__tvb), ct.byref(self.__pinfo), ct.byref(self.__tree))
    # print self.__tvb, self.__pinfo, self.__tree
    #self.__wsl.print_current_proto(ct.py_object(pinfo))
    subt = self.subtrees
    try:
      if not subt.has_user_defined_protocol_tree():
        p_tree = self.tree.add_item(self.protocol())
        self.__Tree = p_tree.add_subtree(self.subtrees)
    except:
      print 'pre_dissect error',e
    self.dissect()

  def protocol_ids(self):
    '''defined a list of tuples containing three values. Each tuple is defining
    the parameters of dissector_add(). This function MUST be defined when
    implementing the dissector of a specific protocol.'''
    return [ (None, 0, None) ]

  def find_dissector(self, protocol):
    '''find_dissector : see proto.h'''
    return self.__wsl.find_dissector(protocol)

  def register_handoff(self):
    '''private method used during the registration of protocol dissectors'''
    #TODO STA : think how we would use dissector_add in an easy way *and* with
    #the possibility to add the same dissector for TCP and UDP (extend
    #py_generic_dissector)
    private_handle = None
    try:
      ids = self.protocol_ids()
      for type, protocol_id, handle in self.protocol_ids():
        if not type:
          continue
        if not handle:
          if not private_handle:
            handle = self.__wsl.py_create_dissector_handle(self.__protocol)
          else:
            handle = private_handle
        ct_type = ct.create_string_buffer(type)
        ct_protocol_id = ct.c_uint(protocol_id)
        self.__wsl.dissector_add_uint(ct_type, ct_protocol_id, handle)
    except Exception, e:
      print "creating dissector failed", e
      raise

  def advance(self, step):
    '''method used to change the value of the offset'''
    self.__offset += step

  def _offset(self):
    '''offset property : if is the current offset computed from the
    dissection.'''
    return self.__offset
  offset = property(_offset)

#Tree class implementation
#see proto.h
class Tree(object):
  def __init__(self, tree, dissector):
    self.__dissector = dissector
    self.__tree = tree
    self.__wsl = dissector.libhandle
    self.__tvb = dissector.raw_tvb

  def _raw_tree(self):
    return self.__tree
  raw_tree = property(_raw_tree)

  def add_item(self, field, offset=0, length=-1, little_endian=False, adv=True):
    '''add an item to the tree'''
    try:
      tree = self.__wsl.proto_tree_add_item(self.__tree,
        field, self.__tvb, self.__dissector.offset, length,
        little_endian)
    except Exception, e:
      print e
    else:
      if length > 0 and adv:
        self.__dissector.advance(length)
      return Tree(tree, self.__dissector)

  def add_uint(self, field, value, offset=0, length=4, adv=True):
    '''add unsigned integer to the tree'''
    try:
      tree = self.__wsl.proto_tree_add_uint(self.__tree, field, self.__tvb, self.__dissector.offset, length, value)
    except Exception, e:
      print e
    else:
      if adv:
        self.__dissector.advance(length)
      return Tree(tree, self.__dissector)

  def add_text(self, string, offset=0, length=-1, adv=True):
    '''add text to the tree'''
    try:
      tree = self.__wsl.proto_tree_add_text(self.__tree, self.__tvb, self.__dissector.offset, length, string)
    except Exception, e:
      print e
    else:
      if length > 0 and adv:
        self.__dissector.advance(length)
      return Tree(tree, self.__dissector)

  def add_subtree(self, subtree):
    '''add a subtree to the tree'''
    try:
      tree = self.__wsl.proto_item_add_subtree(self.__tree, subtree)
    except Exception, e:
      print e
    else:
      return Tree(tree, self.__dissector)

#tvb class implementation
#see proto.h
class TVB(object):
  def __init__(self, wsl, tvb, dissector):
    self.__tvb = tvb
    self.__wsl = wsl
    self.__dissector = dissector

  def length(self):
    return self.__wsl.length(self.__wsl)

  def length_remaining(self, offset=-1):
    if offset < 0:
      offset = self.__dissector.offset
    return self.__wsl.tvb_length_remaining(self.__tvb, offset)

  def reported_length(self):
    return self.__wsl.tvb_reported_length(self.__tvb)

  def reported_length_remaining(self, offset=-1):
    if offset < 0:
      offset = self.__dissector.offset
    return self.__wsl.tvb_length_remaining(self.__tvb, offset)

  def get_guint8(self, offset=-1):
    if offset < 0:
      offset = self.__dissector.offset
    return self.__wsl.tvb_get_guint8(self.__tvb)

  def get_ntohs(self, offset=-1):
    if offset < 0:
      offset = self.__dissector.offset
    return self.__wsl.tvb_get_ntohs(self.__tvb, offset)

  def get_ntohl(self, offset=-1):
    if offset < 0:
      offset = self.__dissector.offset
    return self.__wsl.tvb_get_ntohl(self.__tvb, offset)

  def get_letohl(self, offset=-1):
    if offset < 0:
      offset = self.__dissector.offset
    return self.__wsl.tvb_get_letohl(self.__tvb, offset)

  def get_letohs(self, offset=-1):
    if offset < 0:
      offset = self.__dissector.offset
    return self.__wsl.tvb_get_letohs(self.__tvb, offset)

  #STA TODO : check that we can do that
  def get_ptr(self, offset=-1):
    if offset < 0:
      offset = self.__dissector.offset
    return self.__wsl.tvb_get_ptr(self.__tvb, offset)

  #how to get this working ??? check how application uses this!
  #def new_subset(self, offset=0):
  #  return self.__wsl.tvb_get_new_subset(self.tvb, offset)

if False:
    import linecache
    import sys
    # Start tracing when import has finished
    def tracer(frame, event, arg):
        if event == "line":
            lineno = frame.f_lineno
            filename = frame.f_globals["__file__"]
            if (filename.endswith(".pyc") or
                filename.endswith(".pyo")):
                filename = filename[:-1]
            name = frame.f_globals["__name__"]
            line = linecache.getline(filename, lineno)
            print "%s:%s: %s" % (name, lineno, line.rstrip())
        if event == "exception":
            print "exception", arg
        return tracer

    sys.settrace(tracer)
