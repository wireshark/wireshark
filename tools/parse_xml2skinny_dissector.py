#!/usr/bin/env python2
#
# Wireshark Dissector Generator for SkinnyProtocolOptimized.xml
#
# Author: Diederik de Groot <ddegroot@user.sf.net>
# Date: 2014-7-22
# Skinny Protocol Versions: 0 through 22
#
# Heritage:
# xml2obj based on http://code.activestate.com/recipes/149368-xml2obj/
#
# Dependencies:
# python / xml / sax
#
# Called By:
# cog.py + packet-skinny.c.in for inplace code generation
# See: http://nedbatchelder.com/code/cog/
#
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import re
import xml.sax.handler

indentation = 0
indent_str = ''
fieldsArray = {}
si_fields = {"callReference" : "si->callId", "lineInstance": "si->lineId", "passThruPartyId" : "si->passThruId", "callState" : "si->callState", "callingParty" : "si->callingParty", "calledParty" : "si->calledParty", "openReceiveChannelStatus" : "si->openreceiveStatus", "startMediaTransmissionStatus" : "si->startmediatransmisionStatus"}
debug = 1

def xml2obj(src):
    """
    A function to converts XML data into native Python objects.

    """
    non_id_char = re.compile('[^_0-9a-zA-Z]')

    def _name_mangle(name):
        return non_id_char.sub('_', name)

    class DataNode(object):
        def __init__(self):
            self._attrs = {}    # XML attributes and child elements
            self.data = None    # child text data
            self.parent = None
            self.basemessage = None
            self.intsize = 0
            self._children = []
            self.declared = []

        def __len__(self):
            # treat single element as a list of 1
            return 1
        def __getitem__(self, key):
            if isinstance(key, basestring):
                return self._attrs.get(key,None)
            else:
                return [self][key]

        def __contains__(self, name):
            return self._attrs.has_key(name)

        def __nonzero__(self):
            return bool(self._attrs or self.data)

        def __getattr__(self, name):
            if name.startswith('__'):
                # need to do this for Python special methods???
                raise AttributeError(name)
            return self._attrs.get(name,None)

        def _add_xml_attr(self, name, value):
            if name in self._attrs:
                # multiple attribute of the same name are represented by a list
                children = self._attrs[name]
                if not isinstance(children, list):
                    children = [children]
                    self._attrs[name] = children
                children.append(value)
            else:
                self._attrs[name] = value

        def _add_child(self, name, value):
            #print "adding : %s / %s to %s" %(name,value, self.__class__)
            self._children.append(value)

        def __str__(self):
            return '%s:%s' %(self.__class__,self.name)

        def keys(self):
            return self._attrs.keys()

        def __repr__(self):
            items = {}
            if self.data:
                items.append(('data', self.data))
            return u'{%s}' % ', '.join([u'%s:%s' % (k,repr(v)) for k,v in items])

        def __setitem__(self, key, value):
            self._attrs[key] = value

        def getfieldnames(self):
            return ''

        def declaration(self):
            global fieldsArray
            if self.name not in fieldsArray:
                fieldsArray[self.name] = '/* UNKNOWN { &hf_skinny_%s,\n {\n"%s", "skinny.%s", FT_UINT32, BASE_DEC, NULL, 0x0,\n "%s", HFILL }}, */\n' %(self.name, self.name, self.name, self.comment)
            return ''

        def dissect(self):
            return self.name or ''

        def incr_indent(self):
            global indentation
            global indent_str
            indentation += 1
            indent_str = ''
            for x in range(0, indentation):
                indent_str += '  '

        def decr_indent(self):
            global indentation
            global indent_str
            indentation -= 1
            indent_str = ''
            for x in range(0, indentation):
                indent_str += '  '

        def indent_out(self, string):
            return indent_str + string


    class Message(DataNode):
        ''' Message '''
        def __str__(self):
            return self.name

        def gen_handler(self):
            if self.fields is None:
                # skip whole message and return NULL as handler
                return 'NULL'
            return 'handle_%s' %self.name

        def dissect(self):
            ret = ''
            declarations = 0

            if (self.fields is not None):
                ret += self.indent_out("/*\n")
                ret += self.indent_out(" * Message:   %s\n" %self.name)
                ret += self.indent_out(" * Opcode:    %s\n" %self.opcode)
                ret += self.indent_out(" * Type:      %s\n"  %self.type)
                ret += self.indent_out(" * Direction: %s\n" %self.direction)
                ret += self.indent_out(" * VarLength: %s\n" %self.dynamic)
                if self.comment:
                    ret += self.indent_out(" * Comment: %s\n" %self.comment)
                ret += self.indent_out(" */\n")
                ret += self.indent_out("static void\n")
                ret += self.indent_out("handle_%s(ptvcursor_t *cursor, packet_info * pinfo _U_)\n" %self.name)
                ret += self.indent_out("{\n")
                self.incr_indent()
                for fields in self.fields:
                    if fields.size_lt:
                        if self.basemessage.declared is None or "hdr_data_length" not in self.basemessage.declared:
                            ret += self.indent_out("guint32 hdr_data_length = tvb_get_letohl(ptvcursor_tvbuff(cursor), 0);\n")
                            self.basemessage.declared.append("hdr_data_length")
                            declarations += 1
                    if fields.size_gt:
                        if self.basemessage.declared is None or "hdr_data_length" not in self.basemessage.declared:
                            ret += self.indent_out("guint32 hdr_data_length = tvb_get_letohl(ptvcursor_tvbuff(cursor), 0);\n")
                            self.basemessage.declared.append("hdr_data_length")
                            declarations += 1
                if not declarations:
                    for fields in self.fields[1:]:
                        if self.basemessage.declared is None or "hdr_version" not in self.basemessage.declared:
                            ret += self.indent_out("guint32 hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);\n")
                            self.basemessage.declared.append("hdr_version")
                            declarations += 1
                for fields in self.fields:
                    ret += '%s' %fields.declaration()
                    declarations += 1

                if declarations > 1:
                    ret += "\n"

                #ret += self.indent_out('if (!cursor || !pinfo) {return;}\n\n')        # ugly check to get rid of compiler warning about unused parameters
                if (self.fields is not None):
                    for fields in self.fields:
                        ret += '%s' %fields.dissect()
                self.decr_indent()
                ret += "}\n\n"
            return ret

    class Fields(DataNode):
        ''' Fields '''
        size_fieldnames= []

        def declaration(self):
            ret = ''

            #ret += '/* Fields Declaration */'

            for field in self._children:
                ret += '%s' %(field.declaration())
                self.intsize += field.intsize
            return ret

        def dissect(self, lookupguide=""):
            ret = ''
            ifstarted = 0
            #ret += "/* [PARENT: %s, BASEMESSAGE: %s] */\n" %(self.parent.name,self.basemessage.name)

            if ((self.beginversion or self.endversion) and (self.beginversion != "0" or self.endversion != "22")):

                ifstarted = 1
                ret += self.indent_out('if (')
                if (self.beginversion and self.beginversion != "0"):
                    if (not self.endversion or self.endversion == "22"):
                        ret += 'hdr_version >= V%s_MSG_TYPE) {\n' %self.beginversion
                    else:
                        ret += 'hdr_version >= V%s_MSG_TYPE && ' %self.beginversion
                if (self.endversion and self.endversion != "22"):
                    ret += 'hdr_version <= V%s_MSG_TYPE) {\n' %self.endversion
                self.incr_indent()

            if self.size_lt:
                ret += self.indent_out('if (hdr_data_length < %s) {\n' %self.size_lt)
                self.incr_indent()

            if self.size_gt:
                ret += self.indent_out('if (hdr_data_length > %s) {\n' %self.size_gt)
                self.incr_indent()

            # generate dissection
            for field in self._children:
                ret += '%s' %(field.dissect())

            if self.size_lt:
                self.decr_indent()
                ret += self.indent_out('}\n')

            if self.size_gt:
                self.decr_indent()
                ret += self.indent_out('}\n')

            if ifstarted:
                self.decr_indent()
                ret += self.indent_out('}\n')

            return ret;

    class Integer(DataNode):
        def __init__(self):
            DataNode.__init__(self)
            self.intsize = 0
            self.endian = "ENC_LITTLE_ENDIAN"

        def __str__(self):
            return '%s:%s' %(self.__class__,self.name)

        def declaration(self):
            ret = ''

            int_sizes = {'uint32':4,'uint16':2,'uint8':1,'int32':4,'int16':2,'int8':1,'ipport':4}
            if self.endianness == "big":
                self.endian = "ENC_BIG_ENDIAN"
            if self.type in int_sizes:
                self.intsize = int_sizes[self.type]
            else:
                print "ERROR integer %s with type: %s, could not be found" %(self.name, self.type)

            if self.declare == "yes":
                if self.basemessage.declared is None or self.name not in self.basemessage.declared:
                    ret += self.indent_out('g%s %s = 0;\n' %(self.type, self.name))
                    self.basemessage.declared.append(self.name)

            global fieldsArray
            if self.name not in fieldsArray:
                fieldsArray[self.name] ='{ &hf_skinny_%s,\n  {\n    "%s", "skinny.%s", FT_UINT%d, BASE_DEC, NULL, 0x0,\n    %s, HFILL }},\n' %(self.name, self.comment if (self.comment and self.longcomment) else self.name, self.name.replace("_","."), self.intsize * 8, '"' + self.longcomment + '"' if self.longcomment else '"' + self.comment + '"' if self.comment else 'NULL')
            return ret

        def dissect(self):
            ret = ''

            size = 0
            if self.size_fieldname:
                if self.basemessage.dynamic == "yes":
                    size = self.size_fieldname
                else:
                    size = self.maxsize
            elif self.size:
                size = self.size

            if size:
                variable = 'counter_%d' %indentation
                ret += self.indent_out('{\n')
                self.incr_indent()
                ret += self.indent_out('guint32 %s = 0;\n' %(variable));
                if self.size_fieldname:
                    ret += self.indent_out('ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "%s [ref: %s = %%d, max:%s]", %s);\n' %(self.name, self.size_fieldname, size, self.size_fieldname))
                else:
                    ret += self.indent_out('ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "%s [max:%s]");\n' %(self.name, size))
                ret += self.indent_out('for (%s = 0; %s < %s; %s++) {\n' %(variable, variable, size, variable));
                if self.basemessage.dynamic == "no" and self.size_fieldname:
                    self.incr_indent()
                    ret += self.indent_out('if (%s < %s) {\n' %(variable,self.size_fieldname))
                self.incr_indent()

            if self.declare == "yes":
                if self.endianness == "big":
                    if (self.intsize == 4):
                        ret += self.indent_out('%s = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));\n' %(self.name))
                    elif (self.intsize == 2):
                        ret += self.indent_out('%s = tvb_get_ntohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));\n' %(self.name))
                    else:
                        ret += self.indent_out('%s = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));\n' %(self.name))
                else:
                    if (self.intsize == 4):
                        ret += self.indent_out('%s = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));\n' %(self.name))
                    elif (self.intsize == 2):
                        ret += self.indent_out('%s = tvb_get_letohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));\n' %(self.name))
                    else:
                        ret += self.indent_out('%s = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));\n' %(self.name))

            if self.name in si_fields.keys():
                ret += self.indent_out('%s = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));\n' %(si_fields[self.name]))

            ret += self.indent_out('ptvcursor_add(cursor, hf_skinny_%s, %d, %s);\n' %(self.name, self.intsize, self.endian))

            if size:
                if self.basemessage.dynamic == "no" and self.size_fieldname:
                    self.decr_indent()
                    ret += self.indent_out('} else {\n')
                    ret += self.indent_out('  ptvcursor_advance(cursor, %d);\n' %self.intsize)
                    ret += self.indent_out('}\n')
                self.decr_indent()
                ret += self.indent_out('}\n')
                ret += self.indent_out('ptvcursor_pop_subtree(cursor); /* end for loop tree: %s */\n' %self.name)
                self.decr_indent()
                ret += self.indent_out('}\n')
            return ret

    class Enum(DataNode):
        def __init__(self):
            DataNode.__init__(self)
            self.intsize = 0
            self.sparse = 0

        def __str__(self):
            return '%s:%s' %(self.__class__,self.name)

        def declaration(self):
            ret = ''
            prevvalue = 0
            enum_sizes = {'uint32':4,'uint16':2,'uint8':1}
            if self.type in enum_sizes:
                self.intsize = enum_sizes[self.type]
            else:
                print "ERROR enum %s with type: %s, could not be found" %(self.name, self.type)

            if self.declare == "yes":
                if self.basemessage.declared is None or self.name not in self.basemessage.declared:
                    ret += self.indent_out('g%s %s = 0;\n' %(self.type, self.name))
                    self.basemessage.declared.append(self.name)

            global fieldsArray
            if self.name not in fieldsArray:
                fieldsArray[self.name] ='{&hf_skinny_%s,\n  {\n    "%s", "skinny.%s", FT_UINT%d, BASE_HEX | BASE_EXT_STRING, &%s_ext, 0x0,\n    %s, HFILL }},\n' %(self.name, self.comment if (self.comment and self.longcomment) else self.name, self.name.replace("_","."), self.intsize * 8, self.subtype[0].upper() + self.subtype[1:], '"' + self.longcomment + '"' if self.longcomment else '"' + self.comment + '"' if self.comment else 'NULL')
            return ret

        def dissect(self):
            ret = ''
            endian = "ENC_LITTLE_ENDIAN"


            size = 0
            if self.size_fieldname:
                if self.basemessage.dynamic == "yes":
                    size = self.size_fieldname
                else:
                    size = self.maxsize
            elif self.size:
                size = self.size

            if size:
                variable = 'counter_%d' %indentation
                ret += self.indent_out('{\n')
                self.incr_indent()
                ret += self.indent_out('guint32 %s = 0;\n' %(variable));
                if self.size_fieldname:
                    ret += self.indent_out('ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "%s [ref: %s = %%d, max:%s]", %s);\n' %(self.name, self.size_fieldname, size, self.size_fieldname))
                else:
                    ret += self.indent_out('ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "%s [max:%s]");\n' %(self.name, size))
                ret += self.indent_out('for (%s = 0; %s < %s; %s++) {\n' %(variable, variable, size, variable));
                if self.basemessage.dynamic == "no" and self.size_fieldname:
                    self.incr_indent()
                    ret += self.indent_out('if (%s < %s) {\n' %(variable,self.size_fieldname))
                self.incr_indent()

            if self.name in si_fields.keys():
                ret += self.indent_out('%s = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));\n' %(si_fields[self.name]))

            if self.declare == "yes":
                if (self.intsize == 4):
                    ret += self.indent_out('%s = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));\n' %(self.name))
                elif (self.intsize == 2):
                    ret += self.indent_out('%s = tvb_get_letohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));\n' %(self.name))
                else:
                    ret += self.indent_out('%s = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));\n' %(self.name))

            ret += self.indent_out('ptvcursor_add(cursor, hf_skinny_%s, %d, %s);\n' %(self.name, self.intsize, endian))

            if size:
                if self.basemessage.dynamic == "no" and self.size_fieldname:
                    self.decr_indent()
                    ret += self.indent_out('} else {\n')
                    ret += self.indent_out('  ptvcursor_advance(cursor, 4);\n')
                    ret += self.indent_out('}\n')
                self.decr_indent()
                ret += self.indent_out('}\n')
                ret += self.indent_out('ptvcursor_pop_subtree(cursor); /* end for loop tree: %s */\n' %self.name)
                self.decr_indent()
                ret += self.indent_out('}\n')
            return ret

    class String(DataNode):
        def __init__(self):
            DataNode.__init__(self)

        def __str__(self):
            return '%s:%s' %(self.__class__,self.name)

        def declaration(self):
            ret = ''
            self.intsize = 0
            if self.size:
                if self.size=="VariableDirnumSize":
                    self.intsize = 24
                else:
                    self.intsize = int(self.size)
            elif self.maxsize and self.basemessage.dynamic == "no":
                self.intsize = int(self.maxsize)

            if self.declare == "yes":
                if self.size=="VariableDirnumSize":
                    if self.basemessage.declared is None or "VariableDirnumSize" not in self.basemessage.declared:
                        if self.basemessage.declared is None or "hdr_version" not in self.basemessage.declared:
                        #if (self.basemessage.fields is not None and len(self.basemessage.fields) == 1):
                            ret += self.indent_out('guint32 hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);\n')
                            self.basemessage.declared.append("hdr_version")
                        ret += self.indent_out('guint32 VariableDirnumSize = (hdr_version >= V18_MSG_TYPE) ? 25 : 24;\n')
                        self.basemessage.declared.append("VariableDirnumSize")
                else:
                    if self.basemessage.declared is None or self.name not in self.basemessage.declared:
                        ret += self.indent_out('guint32 %s = 0;\n' %self.name)
                        self.basemessage.declared.append(self.name)

            if self.basemessage.dynamic == "yes" and not self.subtype == "DisplayLabel":
                if self.basemessage.declared is None or self.name + '_len' not in self.basemessage.declared:
                    ret += self.indent_out('guint32 %s_len = 0;\n' %self.name)
                    self.basemessage.declared.append(self.name + '_len')

            global fieldsArray
            if self.name not in fieldsArray:
                fieldsArray[self.name] = '{&hf_skinny_%s,\n  {\n    "%s", "skinny.%s", FT_STRING, BASE_NONE, NULL, 0x0,\n    %s, HFILL }},\n' %(self.name, self.comment if (self.comment and self.longcomment) else self.name, self.name.replace("_","."), '"' + self.longcomment + '"' if self.longcomment else '"' + self.comment + '"' if self.comment else 'NULL')
            return ret

        def dissect(self):
            ret = ''

            if self.declare == "yes" and self.size != "VariableDirnumSize":
                ret += self.indent_out('%s = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);\n' %self.name)

            if self.subtype == "DisplayLabel":
                if self.basemessage.dynamic == "yes":
                    ret += self.indent_out('dissect_skinny_displayLabel(cursor, hf_skinny_%s, 0);\n' %(self.name))
                elif self.size_fieldname:
                    ret += self.indent_out('dissect_skinny_displayLabel(cursor, hf_skinny_%s, %s);\n' %(self.name, self.size_fieldname))
                else:
                    ret += self.indent_out('dissect_skinny_displayLabel(cursor, hf_skinny_%s, %s);\n' %(self.name, self.size))

            elif self.basemessage.dynamic == "yes":
                ret += self.indent_out('%s_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;\n' %self.name)
                ret += self.indent_out('if (%s_len > 1) {\n' %self.name)
                if self.name in si_fields.keys():
                    ret += self.indent_out('  %s = g_strdup(tvb_format_stringzpad(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), %s_len));\n' %(si_fields[self.name], self.name))
                ret += self.indent_out('  ptvcursor_add(cursor, hf_skinny_%s, %s_len, ENC_ASCII|ENC_NA);\n' %(self.name, self.name))
                ret += self.indent_out('} else {\n')
                ret += self.indent_out('  ptvcursor_advance(cursor, 1);\n')
                ret += self.indent_out('}\n')
            elif self.size_fieldname:
                if self.name in si_fields.keys():
                    ret += self.indent_out('%s = g_strdup(tvb_format_stringzpad(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), %s));\n' %(si_fields[self.name], self.size_fieldname))
                ret += self.indent_out('ptvcursor_add(cursor, hf_skinny_%s, %s, ENC_ASCII|ENC_NA);\n' %(self.name, self.size_fieldname))
            else:
                if self.name in si_fields.keys():
                    ret += self.indent_out('%s = g_strdup(tvb_format_stringzpad(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), %s));\n' %(si_fields[self.name], self.size))
                ret += self.indent_out('ptvcursor_add(cursor, hf_skinny_%s, %s, ENC_ASCII|ENC_NA);\n' %(self.name, self.size))

            return ret

    class Ether(DataNode):
        def __init__(self):
            DataNode.__init__(self)

        def __str__(self):
            return '%s:%s' %(self.__class__,self.name)

        def declaration(self):
            ret = ''
            self.intsize = 6
            if self.size:
                self.intsize = int(self.size)
            elif self.maxsize and self.basemessage.dynamic == "no":
                self.intsize = int(self.maxsize)

            if self.declare == "yes":
                if self.basemessage.declared is None or self.name not in self.basemessage.declared:
                    ret += self.indent_out('guint32 %s = 0;\n' %self.name)
                    self.basemessage.declared.append(self.name)

            if self.basemessage.dynamic == "yes":
                if self.basemessage.declared is None or self.name + '_len' not in self.basemessage.declared:
                    ret += self.indent_out('guint32 %s_len = 0;\n' %self.name)
                    self.basemessage.declared.append(self.name + '_len')

            global fieldsArray
            if self.name not in fieldsArray:
                fieldsArray[self.name] = '{ &hf_skinny_%s,\n  {\n    "%s", "skinny.%s", FT_ETHER, BASE_NONE, NULL, 0x0,\n    %s, HFILL }},\n' %(self.name, self.comment if (self.comment and self.longcomment) else self.name, self.name.replace("_","."), '"' + self.longcomment + '"' if self.longcomment else '"' + self.comment + '"' if self.comment else 'NULL')
            return ret

        def dissect(self):
            ret = ''

            if self.basemessage.dynamic == "yes":
                ret += self.indent_out('%s_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;\n' %self.name)
                ret += self.indent_out('if (%s_len > 1) {\n' %self.name)
                ret += self.indent_out('  ptvcursor_add(cursor, hf_skinny_%s, 6, ENC_NA);\n' %(self.name, self.name))
                ret += self.indent_out('  ptvcursor_advance(cursor, %s_len - 6);\n' %(self.name))
                ret += self.indent_out('} else {\n')
                ret += self.indent_out('  ptvcursor_advance(cursor, 1);\n')
                ret += self.indent_out('}\n')
            elif self.size_fieldname:
                ret += self.indent_out('ptvcursor_add(cursor, hf_skinny_%s, 6, ENC_NA);\n' %(self.name))
                ret += self.indent_out('ptvcursor_advance(cursor, %s - 6);\n' %(self.size_fieldname))
            else:
                ret += self.indent_out('ptvcursor_add(cursor, hf_skinny_%s, 6, ENC_NA);\n' %(self.name))
                ret += self.indent_out('ptvcursor_advance(cursor, %s - 6);\n' %(self.size))
            return ret

    class BitField(DataNode):
        def __init__(self):
            DataNode.__init__(self)

        def __str__(self):
            return '%s:%s' %(self.__class__,self.name)

        def declaration(self):
            global fieldsArray
            ret = ''
            int_sizes = {'uint32':4,'uint16':2,'uint8':1,'int32':4,'int16':2,'int8':1}
            self.intsize = 0
            if self.size in int_sizes:
                self.intsize = int_sizes[self.size]

            for entries in self.entries:
                for entry in entries.entry:
                    if entry.name not in fieldsArray:
                        fieldsArray[entry.name] = '{ &hf_skinny_%s,\n  {\n    "%s", "skinny.%s", FT_BOOLEAN, %d, TFS(&tfs_yes_no), %s,\n    %s, HFILL }},\n' %(entry.name, entry.text, entry.name.replace("_","."), self.intsize * 8, entry.value, '"' + self.longcomment + '"' if self.longcomment else '"' + self.comment + '"' if self.comment else 'NULL')

            return ret

        def dissect(self):
            ret = ''
            ret += self.indent_out('ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "%s");\n' %(self.name))
            for entries in self.entries:
                for entry in entries.entry:
                    ret += self.indent_out('ptvcursor_add_no_advance(cursor, hf_skinny_%s, %d, ENC_LITTLE_ENDIAN);\n' %(entry.name, self.intsize))
            ret += self.indent_out('ptvcursor_advance(cursor, %d);\n' %(self.intsize))
            ret += self.indent_out('ptvcursor_pop_subtree(cursor); /* end bitfield: %s */\n' %(self.name))


            return ret

    class Ip(DataNode):
        def __init__(self):
            DataNode.__init__(self)
            self.intsize = 4
            if self.type == "ipv6":
                self.intsize = 16

        def __str__(self):
            return '%s:%s' %(self.__class__,self.name)

        def declaration(self):
            global fieldsArray
            if self.name not in fieldsArray:
                if self.type == "ipv4":
                    fieldsArray[self.name] = '{ &hf_skinny_%s,\n  {\n    "%s", "skinny.%s", FT_IPv4, BASE_NONE, NULL, 0x0,\n    %s, HFILL }},\n' %(self.name, self.comment if (self.comment and self.longcomment) else self.name, self.name.replace("_","."), '"' + self.longcomment + '"' if self.longcomment else '"' + self.comment + '"' if self.comment else 'NULL')
                else:
                    fieldsArray[self.name] = '{ &hf_skinny_%s,\n  {\n    "%s", "skinny.%s", FT_IPv6, BASE_NONE, NULL, 0x0,\n    %s, HFILL }},\n' %(self.name, self.comment if (self.comment and self.longcomment) else self.name, self.name.replace("_","."), '"' + self.longcomment + '"' if self.longcomment else '"' + self.comment + '"' if self.comment else 'NULL')
            return ''

        def dissect(self):
            if self.type == "ipv4":
                return self.indent_out('ptvcursor_add(cursor, hf_skinny_%s, 4, ENC_BIG_ENDIAN);\n' %self.name)
            else:
                return self.indent_out('ptvcursor_add(cursor, hf_skinny_%s, 16, ENC_NA);\n' %self.name)

    class Ipv4or6(DataNode):
        def __init__(self):
            DataNode.__init__(self)
            self.intsize = 4
            if self.endianness is None:
                self.intsize += 16

        def __str__(self):
            return '%s:%s' %(self.__class__,self.name)

        def declaration(self):
            global fieldsArray
            name = self.name + '_ipv4'
            if name not in fieldsArray:
                fieldsArray[name] = '{ &hf_skinny_%s,\n {\n    "%s", "skinny.%s", FT_IPv4, BASE_NONE, NULL, 0x0,\n    %s, HFILL }},\n' %(name, self.name + ' IPv4 Address', name.replace("_","."), '"' + self.longcomment + '"' if self.longcomment else '"' + self.comment + '"' if self.comment else 'NULL')
            name = self.name + '_ipv6'
            if name not in fieldsArray:
                fieldsArray[name] = '{ &hf_skinny_%s,\n {\n    "%s", "skinny.%s", FT_IPv6, BASE_NONE, NULL, 0x0,\n    %s, HFILL }},\n' %(name, self.name + ' IPv6 Address', name.replace("_","."), '"' + self.longcomment + '"' if self.longcomment else '"' + self.comment + '"' if self.comment else 'NULL')
            return ''

        def dissect(self):
            return self.indent_out('dissect_skinny_ipv4or6(cursor, hf_skinny_%s_ipv4, hf_skinny_%s_ipv6, pinfo);\n' %(self.name, self.name))

    class XML(DataNode):
        def __init__(self):
            DataNode.__init__(self)
            self.intsize = 0

        def __str__(self):
            return '%s:%s' %(self.__class__,self.name)

        def declaration(self):
            global fieldsArray

            if self.size:
                self.intsize = int(self.size)
            elif self.maxsize:
                self.intsize = int(self.maxsize)

            if self.name not in fieldsArray:
                fieldsArray[self.name] = '{ &hf_skinny_%s,\n  {\n    "%s", "skinny.%s", FT_STRING, BASE_NONE, NULL, 0x0,\n    %s, HFILL }},\n' %(self.name, self.comment if (self.comment and self.longcomment) else self.name, self.name.replace("_","."), '"' + self.longcomment + '"' if self.longcomment else '"' + self.comment + '"' if self.comment else 'NULL')
            return ''

        def dissect(self):
            ret = ''
            if self.size_fieldname:
                ret += self.indent_out('dissect_skinny_xml(cursor, hf_skinny_%s, pinfo, %s, %d);\n' %(self.name, self.size_fieldname, self.intsize))
            else:
                ret += self.indent_out('dissect_skinny_xml(cursor, hf_skinny_%s, pinfo, 0, %d);\n' %(self.name, self.intsize))
            return ret

    class Struct(DataNode):
        def __str__(self):
            return '// Struct : %s / %s / %s / %s\n' %(self.name, self.size, self.field_sizename, self.maxsize)

        def declaration(self):
            ret = ''

            if (self.fields is not None and len(self.fields)):
                if (len(self.fields) > 1):
                    if self.basemessage.declared is None or "hdr_version" not in self.basemessage.declared:
                        ret += self.indent_out("guint32 hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);\n")
                        self.basemessage.declared.append("hdr_version")
                for fields in self.fields:
                    ret += '%s' %fields.declaration()
                    self.intsize += fields.intsize

            return ret

        def dissect(self):
            ret = ''
            variable = 'counter_%d' %indentation
            size = 0

            if self.size_fieldname:
                if self.basemessage.dynamic == "yes":
                    size = self.size_fieldname
                else:
                    size = self.maxsize
            elif self.size:
                size = self.size

            if size:
                ret += self.indent_out('{\n')
                self.incr_indent()
                if debug:
                    ret += self.indent_out('/* start struct : %s / size: %d */\n' %(self.name, self.intsize))
                ret += self.indent_out('guint32 %s = 0;\n' %(variable));
                if self.size_fieldname:
                    ret += self.indent_out('ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "%s [ref: %s = %%d, max:%s]", %s);\n' %(self.name, self.size_fieldname, size, self.size_fieldname))
                else:
                    ret += self.indent_out('ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "%s [max:%s]");\n' %(self.name, size))
                ret += self.indent_out('for (%s = 0; %s < %s; %s++) {\n' %(variable, variable, size, variable));
                if self.basemessage.dynamic == "no" and self.size_fieldname:
                    self.incr_indent()
                    ret += self.indent_out('if (%s < %s) {\n' %(variable,self.size_fieldname))
                self.incr_indent()
            else:
                ret += self.indent_out('{\n')
                self.incr_indent()
                if debug:
                    ret += self.indent_out('/* start struct : %s / size: %d */\n' %(self.name, self.intsize))
                ret += self.indent_out('ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "%s");\n' %(self.name))

            if size:
                if self.size_fieldname:
                    ret += self.indent_out('ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "%s [%%d / %%d]", %s + 1, %s);\n' %(self.name, variable, self.size_fieldname))
                else:
                    ret += self.indent_out('ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "%s [%%d / %%d]", %s + 1, %s);\n' %(self.name, variable, size))

            if (self.fields is not None and len(self.fields)):
                for fields in self.fields:
                    ret += '%s' %fields.dissect()

            if self.basemessage.dynamic == "no" and self.size_fieldname:
                self.decr_indent()
                ret += self.indent_out('} else {\n')
                ret += self.indent_out('  ptvcursor_advance(cursor, %d);\n' %(self.intsize))
                ret += self.indent_out('}\n')

            if size:
                ret += self.indent_out('ptvcursor_pop_subtree(cursor);\n')
                if debug:
                    ret += self.indent_out('/* end for loop tree: %s */\n' %self.name)
                self.decr_indent()
                ret += self.indent_out('}\n')

            ret += self.indent_out('ptvcursor_pop_subtree(cursor);\n')
            ret += self.indent_out('/* end struct: %s */\n' %self.name)
            self.decr_indent()
            ret += self.indent_out('}\n')

            return ret

    class Union(DataNode):
        def __str__(self):
            return '%s:%s' %(self.__class__,self.name)

        def declaration(self):
            ret = ''
            self.maxsize = 0
            if (self.fields is not None and len(self.fields)):
                if (len(self.fields) > 1):
                    if self.basemessage.declared is None or "hdr_version" not in self.basemessage.declared:
                        ret += self.indent_out("guint32 hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);\n")
                        self.basemessage.declared.append("hdr_version")
                for fields in self.fields:
                    ret += '%s' %fields.declaration()
                    previous_lookup_eq = fields._children[0].lookup_eq
                    previous_lookup_le = fields._children[0].lookup_le
                    previous_lookup_ge = fields._children[0].lookup_ge
                    self.runningtotal = 0
                    for field in fields._children:
                        if previous_lookup_eq != field.lookup_eq or previous_lookup_le != field.lookup_le or previous_lookup_ge == field.lookup_ge:
                            previous_lookup_eq = field.lookup_eq
                            previous_lookup_le = field.lookup_le
                            previous_lookup_ge = field.lookup_ge
                            self.runningtotal = 0

                        self.runningtotal += field.intsize
                        if self.runningtotal > self.maxsize:
                            self.maxsize = self.runningtotal

            self.intsize = self.maxsize

            return ret

        def dissect(self):
            ret = ''
            ifblock = self.indent_out('if')
            skip = 0
            #ret += self.indent_out('/* Union : %s / maxsize: %s */\n' %(self.name, self.maxsize))

            if (self.fields is not None and len(self.fields)):
                for fields in self.fields:
                    for field in fields._children:
                        if self.lookup_guide and (field.lookup_ge or field.lookup_le or field.lookup_eq):
                            lookupguide = self.lookup_guide
                            # start block
                            subtree_text = ''
                            if field.lookup_ge and field.lookup_le:
                                ret += '%s (%s >= %s && %s <= %s)' %(ifblock, lookupguide, field.lookup_ge.upper(), lookupguide, field.lookup_le.upper())
                                subtree_text = "%s <= %s <= %s" %(field.lookup_ge, lookupguide, field.lookup_le)
                            elif field.lookup_ge:
                                ret += '%s (%s >= %s)' %(ifblock, lookupguide, field.lookup_ge.upper())
                                subtree_text = "%s >= %s" %(lookupguide, field.lookup_ge)
                            elif field.lookup_le:
                                ret += '%s (%s <= %s)' %(ifblock, lookupguide, field.lookup_le.upper())
                                subtree_text = "%s <= %s" %(lookupguide, field.lookup_le)
                            elif field.lookup_eq:
                                if field.lookup_eq == "*":
                                    ret += ' else'
                                    subtree_text = "any %s" %(lookupguide)
                                elif field.lookup_eq == "skip":
                                    continue
                                else:
                                    ret += '%s (%s == %s)' %(ifblock, lookupguide, field.lookup_eq.upper())
                                    subtree_text = "%s is %s" %(lookupguide, field.lookup_eq)

                            ret += self.indent_out(' {\n')
                            self.incr_indent()
                            if debug:
                                ret += self.indent_out('/* start union : %s / maxsize: %s */\n' %(self.name, self.maxsize))
                            currsize = 0
                            # dissect field

                            ret += self.indent_out('ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "%s");\n' %subtree_text)
                            ret += '%s' %field.dissect()
                            ret += self.indent_out('ptvcursor_pop_subtree(cursor);\n')

                            currsize += field.intsize

                            # compensate length
                            if (self.maxsize - currsize) > 0:
                                ret += self.indent_out('ptvcursor_advance(cursor, %d);\n' %(self.maxsize - currsize))

                            self.decr_indent()

                            # close block
                            ret += self.indent_out('}')
                            ifblock = ' else if'
                        else:
                            ret += '/* ERROR %s, missing lookup_guide */' %field.dissect()
            ret += '\n'

            return ret

    class TreeBuilder(xml.sax.handler.ContentHandler):
        def __init__(self):
            self.stack = []
            self.root = DataNode()
            self.previous = self.root
            self.current = self.root
            self.basemessage = None
            self.text_parts = []
        def startElement(self, name, attrs):
            objecttype = {"message": Message(), "fields": Fields(), "enum" : Enum(), "bitfield" : BitField(), "struct": Struct(), "union": Union(), "integer": Integer(), "string": String(), "ether": Ether(), "ip": Ip(), "ipv4or6": Ipv4or6(), "xml": XML()}
            self.previous = self.current
            self.stack.append((self.current, self.text_parts))
            if name in objecttype.keys():
                self.current = objecttype[name]
            else:
                self.current = DataNode()
            if name == "message":
                self.basemessage = self.current
            self.text_parts = []
            #self.children = []
            self.current.parent = self.previous
            self.current.basemessage = self.basemessage
            # xml attributes --> python attributes
            for k, v in attrs.items():
                self.current._add_xml_attr(_name_mangle(k), v)

        def endElement(self, name):
            text = ''.join(self.text_parts).strip()
            if text:
                self.current.data = text
            if self.current._attrs:
                obj = self.current
            else:
                # a text only node is simply represented by the string
                obj = text or ''
            self.current, self.text_parts = self.stack.pop()
            self.current._add_xml_attr(_name_mangle(name), obj)
            self.current._add_child(_name_mangle(name), obj)
        def characters(self, content):
            self.text_parts.append(content)

    builder = TreeBuilder()
    xml.sax.parse(src, builder)
    return builder.root._attrs.values()[0]

#       skinny = xml2obj('SkinnyProtocolOptimized.xml')
#       for message in skinny.message:
#         print '%s' %message.dissect()

#if __name__ == '__main__':
#  import timeit
#  print(timeit.timeit("generateMessageDissectors()", setup="from __main__ import generateMessageDissectors"))


#skinny = xml2obj('SkinnyProtocolOptimized.xml')
#for message in skinny.message:
#    message.dissect()

#for key,value in fieldsArray.items():
#       print "%s : %s" %(key,value)
#print '%r\n' %fieldsArray

#skinny = xml2obj('SkinnyProtocolOptimized.xml')
#for message in skinny.message:
#    print message.declaration()
