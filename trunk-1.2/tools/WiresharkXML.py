"""
Baseclass for reading PDML produced from TShark.

Copyright (c) 2003 by Gilbert Ramirez <gram@alumni.rice.edu>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
"""

import sys
from xml.sax import saxlib
from xml.sax import saxexts
from xml.sax import saxutils

class CaptureFile:
    pass

class FoundItException(Exception):
    pass

class PacketList:
    """Holds Packet objects, and has methods for finding
    items within it."""

    def __init__(self, children=None):
        if children == None:
            self.children = []
        else:
            self.children = children

    def __getitem__(self, index):
        """We act like a list."""
        return self.children[index]


    def item_exists(self, name):
        """Does an item with name 'name' exist in this
        PacketList?"""
        for child in self.children:
            if child.name == name:
                return 1

        try:
            for child in self.children:
                child._item_exists(name)

        except FoundItException:
            return 1

        return 0

    def _item_exists(self, name):
        for child in self.children:
            if child.name == name:
                raise FoundItException
            child._item_exists(name)


    def get_items(self, name, items=None):
        """Return all items that match the name 'name'.
        They are returned in order of a depth-first-search."""
        if items == None:
            top_level = 1
            items = []
        else:
            top_level = 0

        for child in self.children:
            if child.name == name:
                items.append(child)
            child.get_items(name, items)

        if top_level:
            return PacketList(items)

    def get_items_before(self, name, before_item, items=None):
        """Return all items that match the name 'name' that
        exist before the before_item. The before_item is an object.
        They results are returned in order of a depth-first-search.
        This function allows you to find fields from protocols that occur
        before other protocols. For example, if you have an HTTP
        protocol, you can find all tcp.dstport fields *before* that HTTP
        protocol. This helps analyze in the presence of tunneled protocols."""
        if items == None:
            top_level = 1
            items = []
        else:
            top_level = 0

        for child in self.children:
            if top_level == 1 and child == before_item:
                break
            if child.name == name:
                items.append(child)
            # Call get_items because the 'before_item' applies
            # only to the top level search.
            child.get_items(name, items)

        if top_level:
            return PacketList(items)


class ProtoTreeItem(PacketList):
    def __init__(self, xmlattrs):
        PacketList.__init__(self)

        self.name = xmlattrs.get("name", "")
        self.showname = xmlattrs.get("showname", "")
        self.pos = xmlattrs.get("pos", "")
        self.size = xmlattrs.get("size", "")
        self.value = xmlattrs.get("value", "")
        self.show = xmlattrs.get("show", "")
        self.hide = xmlattrs.get("hide", "")

    def add_child(self, child):
        self.children.append(child)

    def get_name(self):
        return self.name

    def get_showname(self):
        return self.showname

    def get_pos(self):
        return self.pos

    def get_size(self):
        return self.size

    def get_value(self):
        return self.value

    def get_show(self):
        return self.show

    def get_hide(self):
        return self.hide

    def dump(self, fh):
        if self.name:
            print >> fh, " name=%s" % (saxutils.quoteattr(self.name),),

        if self.showname:
            print >> fh, "showname=%s" % (saxutils.quoteattr(self.showname),),

        if self.pos:
            print >> fh, "pos=%s" % (saxutils.quoteattr(self.pos),),

        if self.size:
            print >> fh, "size=%s" % (saxutils.quoteattr(self.size),),

        if self.value:
            print >> fh, "value=%s" % (saxutils.quoteattr(self.value),),

        if self.show:
            print >> fh, "show=%s" % (saxutils.quoteattr(self.show),),

        if self.hide:
            print >> fh, "hide=%s" % (saxutils.quoteattr(self.hide),),

class Packet(ProtoTreeItem, PacketList):
    def dump(self, fh, indent=0):
        print >> fh, "  " * indent, "<packet>"
        indent += 1
        for child in self.children:
            child.dump(fh, indent)
        print >> fh, "  " * indent, "</packet>"


class Protocol(ProtoTreeItem):

    def dump(self, fh, indent=0):
        print >> fh, "%s<proto " %  ("  " * indent,),
       
        ProtoTreeItem.dump(self, fh)

        print >> fh, '>'

        indent += 1
        for child in self.children:
            child.dump(fh, indent)
        print >> fh, "  " * indent, "</proto>"


class Field(ProtoTreeItem):

    def dump(self, fh, indent=0):
        print >> fh, "%s<field " % ("  " * indent,),

        ProtoTreeItem.dump(self, fh)

        if self.label:
            print >> fh, "label=%s" % (saxutils.quoteattr(self.label),),

        if self.children:
            print >> fh, ">"
            indent += 1
            for child in self.children:
                child.dump(fh, indent)
            print >> fh, "  " * indent, "</field>"

        else:
            print >> fh, "/>"


class ParseXML(saxlib.HandlerBase):

    ELEMENT_FILE        = "pdml"
    ELEMENT_FRAME       = "packet"
    ELEMENT_PROTOCOL    = "proto"
    ELEMENT_FIELD       = "field"

    def __init__(self, cb):
        self.cb = cb
        self.chars = ""
        self.element_stack = []

    def startElement(self, name, xmlattrs):
        self.chars = ""

        if name == self.ELEMENT_FILE:
            # Eventually, we should check version number of pdml here
            elem = CaptureFile()

        elif name == self.ELEMENT_FRAME:
            elem = Packet(xmlattrs)

        elif name == self.ELEMENT_PROTOCOL:
            elem = Protocol(xmlattrs)

        elif name == self.ELEMENT_FIELD:
            elem = Field(xmlattrs)

        else:
            sys.exit("Unknown element: %s" % (name,))

        self.element_stack.append(elem)


    def endElement(self, name):
        elem = self.element_stack.pop()

#        if isinstance(elem, Field):
#            if elem.get_name() == "frame.number":
#                print >> sys.stderr, "Packet:", elem.get_show()

        # Add element as child to previous element as long
        # as there is more than 1 element in the stack. Only
        # one element in the stack means that the the element in
        # the stack is the single CaptureFile element, and we don't
        # want to add this element to that, as we only want one
        # Packet element in memory at a time.
        if len(self.element_stack) > 1:
            parent_elem = self.element_stack[-1]
            parent_elem.add_child(elem)
        
        self.chars = ""

        # If we just finished a Packet element, hand it to the
        # user's callback.
        if isinstance(elem, Packet):
            self.cb(elem)

    def characters(self, chars, start, length):
        self.chars = self.chars + chars[start:start+length]


def parse_fh(fh, cb):

    # Create a parser
    parser = saxexts.make_parser()

    # Create the handler
    ch = ParseXML(cb)

    # Tell the parser to use our handler
    parser.setDocumentHandler(ch)

    # Parse the file
    parser.parseFile(fh)

    # Close the parser
    parser.close()

def _test():
    import sys

    def test_cb(obj):
        pass

    filename = sys.argv[1]
    fh = open(filename, "r")
    parse_fh(fh, test_cb)

if __name__ == '__main__':
    _test()
