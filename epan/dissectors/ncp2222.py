#!/usr/bin/env python

"""
Creates C code from a table of NCP type 0x2222 packet types.
(And 0x3333, which are the replies, but the packets are more commonly
refered to as type 0x2222; the 0x3333 replies are understood to be
part of the 0x2222 "family")

The data-munging code was written by Gilbert Ramirez.
The NCP data comes from Greg Morris <GMORRIS@novell.com>.
Many thanks to Novell for letting him work on this.

Additional data sources:
"Programmer's Guide to the NetWare Core Protocol" by Steve Conner and Dianne Conner.

Novell provides info at:

http://developer.novell.com/ndk/ncp.htm  (where you can download an
*.exe file which installs a PDF, although you may have to create a login
to do this)

or

http://developer.novell.com/ndk/doc/ncp/
for a badly-formatted HTML version of the same PDF.


$Id$


Portions Copyright (c) 2000-2002 by Gilbert Ramirez <gram@alumni.rice.edu>.
Portions Copyright (c) Novell, Inc. 2000-2003.

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

import os
import sys
import string
import getopt
import traceback

errors 		= {}
groups		= {}
packets		= []
compcode_lists	= None
ptvc_lists	= None
msg		= None

REC_START	= 0
REC_LENGTH	= 1
REC_FIELD	= 2
REC_ENDIANNESS	= 3
REC_VAR		= 4
REC_REPEAT	= 5
REC_REQ_COND	= 6

NO_VAR		= -1
NO_REPEAT	= -1
NO_REQ_COND	= -1
NO_LENGTH_CHECK	= -2


PROTO_LENGTH_UNKNOWN	= -1

global_highest_var = -1
global_req_cond = {}


REQ_COND_SIZE_VARIABLE = "REQ_COND_SIZE_VARIABLE"
REQ_COND_SIZE_CONSTANT = "REQ_COND_SIZE_CONSTANT"

##############################################################################
# Global containers
##############################################################################

class UniqueCollection:
	"""The UniqueCollection class stores objects which can be compared to other
	objects of the same class. If two objects in the collection are equivalent,
	only one is stored."""

	def __init__(self, name):
		"Constructor"
		self.name = name
		self.members = []
		self.member_reprs = {}

	def Add(self, object):
		"""Add an object to the members lists, if a comparable object
		doesn't already exist. The object that is in the member list, that is
		either the object that was added or the comparable object that was
		already in the member list, is returned."""

		r = repr(object)
		# Is 'object' a duplicate of some other member?
		if self.member_reprs.has_key(r):
			return self.member_reprs[r]
		else:
			self.member_reprs[r] = object
			self.members.append(object)
			return object

	def Members(self):
		"Returns the list of members."
		return self.members

	def HasMember(self, object):
		"Does the list of members contain the object?"
		if self.members_reprs.has_key(repr(object)):
			return 1
		else:
			return 0

# This list needs to be defined before the NCP types are defined,
# because the NCP types are defined in the global scope, not inside
# a function's scope.
ptvc_lists	= UniqueCollection('PTVC Lists')

##############################################################################

class NamedList:
	"NamedList's keep track of PTVC's and Completion Codes"
	def __init__(self, name, list):
		"Constructor"
		self.name = name
		self.list = list

	def __cmp__(self, other):
		"Compare this NamedList to another"

		if isinstance(other, NamedList):
			return cmp(self.list, other.list)
		else:
			return 0


	def Name(self, new_name = None):
		"Get/Set name of list"
		if new_name != None:
			self.name = new_name
		return self.name

	def Records(self):
		"Returns record lists"
		return self.list

	def Null(self):
		"Is there no list (different from an empty list)?"
		return self.list == None

	def Empty(self):
		"It the list empty (different from a null list)?"
		assert(not self.Null())

		if self.list:
			return 0
		else:
			return 1

	def __repr__(self):
		return repr(self.list)

class PTVC(NamedList):
	"""ProtoTree TVBuff Cursor List ("PTVC List") Class"""

	def __init__(self, name, records):
		"Constructor"
		NamedList.__init__(self, name, [])

		global global_highest_var

		expected_offset = None
		highest_var = -1

		named_vars = {}

		# Make a PTVCRecord object for each list in 'records'
		for record in records:
			offset = record[REC_START]
			length = record[REC_LENGTH]
			field = record[REC_FIELD]
			endianness = record[REC_ENDIANNESS]

			# Variable
			var_name = record[REC_VAR]
			if var_name:
				# Did we already define this var?
				if named_vars.has_key(var_name):
					sys.exit("%s has multiple %s vars." % \
						(name, var_name))

				highest_var = highest_var + 1
				var = highest_var
                                if highest_var > global_highest_var:
                                    global_highest_var = highest_var
				named_vars[var_name] = var
			else:
				var = NO_VAR

			# Repeat
			repeat_name = record[REC_REPEAT]
			if repeat_name:
				# Do we have this var?
				if not named_vars.has_key(repeat_name):
					sys.exit("%s does not have %s var defined." % \
						(name, var_name))
				repeat = named_vars[repeat_name]
			else:
				repeat = NO_REPEAT

			# Request Condition
			req_cond = record[REC_REQ_COND]
			if req_cond != NO_REQ_COND:
				global_req_cond[req_cond] = None

			ptvc_rec = PTVCRecord(field, length, endianness, var, repeat, req_cond)

			if expected_offset == None:
				expected_offset = offset

			elif expected_offset == -1:
				pass

			elif expected_offset != offset and offset != -1:
				msg.write("Expected offset in %s for %s to be %d\n" % \
					(name, field.HFName(), expected_offset))
				sys.exit(1)

			# We can't make a PTVC list from a variable-length
			# packet, unless the fields can tell us at run time
			# how long the packet is. That is, nstring8 is fine, since
			# the field has an integer telling us how long the string is.
			# Fields that don't have a length determinable at run-time
			# cannot be variable-length.
			if type(ptvc_rec.Length()) == type(()):
				if isinstance(ptvc_rec.Field(), nstring):
					expected_offset = -1
					pass
				elif isinstance(ptvc_rec.Field(), nbytes):
					expected_offset = -1
					pass
				elif isinstance(ptvc_rec.Field(), struct):
					expected_offset = -1
					pass
				else:
					field = ptvc_rec.Field()
 					assert 0, "Cannot make PTVC from %s, type %s" % \
						(field.HFName(), field)

			elif expected_offset > -1:
				if ptvc_rec.Length() < 0:
					expected_offset = -1
				else:
					expected_offset = expected_offset + ptvc_rec.Length()


			self.list.append(ptvc_rec)

	def ETTName(self):
		return "ett_%s" % (self.Name(),)


	def Code(self):
		x =  "static const ptvc_record %s[] = {\n" % (self.Name())
		for ptvc_rec in self.list:
			x = x +  "\t%s,\n" % (ptvc_rec.Code())
		x = x + "\t{ NULL, 0, NULL, NO_ENDIANNESS, NO_VAR, NO_REPEAT, NO_REQ_COND, NCP_FMT_NONE }\n"
		x = x + "};\n"
		return x

	def __repr__(self):
		x = ""
		for ptvc_rec in self.list:
			x = x + repr(ptvc_rec)
		return x


class PTVCBitfield(PTVC):
	def __init__(self, name, vars):
		NamedList.__init__(self, name, [])

		for var in vars:
			ptvc_rec = PTVCRecord(var, var.Length(), var.Endianness(),
				NO_VAR, NO_REPEAT, NO_REQ_COND)
			self.list.append(ptvc_rec)

	def Code(self):
		ett_name = self.ETTName()
		x = "static gint %s;\n" % (ett_name,)

		x = x + "static const ptvc_record ptvc_%s[] = {\n" % (self.Name())
		for ptvc_rec in self.list:
			x = x +  "\t%s,\n" % (ptvc_rec.Code())
		x = x + "\t{ NULL, 0, NULL, NO_ENDIANNESS, NO_VAR, NO_REPEAT, NO_REQ_COND, NCP_FMT_NONE }\n"
		x = x + "};\n"

		x = x + "static const sub_ptvc_record %s = {\n" % (self.Name(),)
		x = x + "\t&%s,\n" % (ett_name,)
		x = x + "\tNULL,\n"
		x = x + "\tptvc_%s,\n" % (self.Name(),)
		x = x + "};\n"
		return x


class PTVCRecord:
	def __init__(self, field, length, endianness, var, repeat, req_cond):
		"Constructor"
		self.field	= field
		self.length	= length
		self.endianness	= endianness
		self.var	= var
		self.repeat	= repeat
		self.req_cond	= req_cond

	def __cmp__(self, other):
		"Comparison operator"
		if self.field != other.field:
			return 1
		elif self.length < other.length:
			return -1
		elif self.length > other.length:
			return 1
		elif self.endianness != other.endianness:
			return 1
		else:
			return 0

	def Code(self):
		# Nice textual representations
		if self.var == NO_VAR:
			var = "NO_VAR"
		else:
			var = self.var

		if self.repeat == NO_REPEAT:
			repeat = "NO_REPEAT"
		else:
			repeat = self.repeat

		if self.req_cond == NO_REQ_COND:
			req_cond = "NO_REQ_COND"
		else:
			req_cond = global_req_cond[self.req_cond]
			assert req_cond != None

		if isinstance(self.field, struct):
			return self.field.ReferenceString(var, repeat, req_cond)
		else:
			return self.RegularCode(var, repeat, req_cond)

	def RegularCode(self, var, repeat, req_cond):
		"String representation"
		endianness = 'BE'
		if self.endianness == LE:
			endianness = 'LE'

		length = None

		if type(self.length) == type(0):
			length = self.length
		else:
			# This is for cases where a length is needed
			# in order to determine a following variable-length,
			# like nstring8, where 1 byte is needed in order
			# to determine the variable length.
			var_length = self.field.Length()
			if var_length > 0:
				length = var_length

		if length == PROTO_LENGTH_UNKNOWN:
			# XXX length = "PROTO_LENGTH_UNKNOWN"
			pass

		assert length, "Length not handled for %s" % (self.field.HFName(),)

		sub_ptvc_name = self.field.PTVCName()
		if sub_ptvc_name != "NULL":
			sub_ptvc_name = "&%s" % (sub_ptvc_name,)


		return "{ &%s, %s, %s, %s, %s, %s, %s, %s }" % \
			(self.field.HFName(), length, sub_ptvc_name,
			endianness, var, repeat, req_cond,
			self.field.SpecialFmt())

	def Offset(self):
		return self.offset

	def Length(self):
		return self.length

	def Field(self):
		return self.field

	def __repr__(self):
		return "{%s len=%s end=%s var=%s rpt=%s rqc=%s}" % \
			(self.field.HFName(), self.length,
			self.endianness, self.var, self.repeat, self.req_cond)

##############################################################################

class NCP:
	"NCP Packet class"
	def __init__(self, func_code, description, group, has_length=1):
		"Constructor"
		self.func_code		= func_code
		self.description	= description
		self.group		= group
		self.codes		= None
		self.request_records	= None
		self.reply_records	= None
		self.has_length		= has_length
		self.req_cond_size	= None
		self.req_info_str	= None

		if not groups.has_key(group):
			msg.write("NCP 0x%x has invalid group '%s'\n" % \
				(self.func_code, group))
			sys.exit(1)

		if self.HasSubFunction():
			# NCP Function with SubFunction
			self.start_offset = 10
		else:
			# Simple NCP Function
			self.start_offset = 7

	def ReqCondSize(self):
		return self.req_cond_size

	def ReqCondSizeVariable(self):
		self.req_cond_size = REQ_COND_SIZE_VARIABLE

	def ReqCondSizeConstant(self):
		self.req_cond_size = REQ_COND_SIZE_CONSTANT

	def FunctionCode(self, part=None):
		"Returns the function code for this NCP packet."
		if part == None:
			return self.func_code
		elif part == 'high':
			if self.HasSubFunction():
				return (self.func_code & 0xff00) >> 8
			else:
				return self.func_code
		elif part == 'low':
			if self.HasSubFunction():
				return self.func_code & 0x00ff
			else:
				return 0x00
		else:
			msg.write("Unknown directive '%s' for function_code()\n" % (part))
			sys.exit(1)

	def HasSubFunction(self):
		"Does this NPC packet require a subfunction field?"
		if self.func_code <= 0xff:
			return 0
		else:
			return 1

	def HasLength(self):
		return self.has_length

	def Description(self):
		return self.description

	def Group(self):
		return self.group

	def PTVCRequest(self):
		return self.ptvc_request

	def PTVCReply(self):
		return self.ptvc_reply

	def Request(self, size, records=[], **kwargs):
		self.request_size = size
		self.request_records = records
		if self.HasSubFunction():
			if self.HasLength():
				self.CheckRecords(size, records, "Request", 10)
			else:
				self.CheckRecords(size, records, "Request", 8)
		else:
			self.CheckRecords(size, records, "Request", 7)
		self.ptvc_request = self.MakePTVC(records, "request")

		if kwargs.has_key("info_str"):
			self.req_info_str = kwargs["info_str"]

	def Reply(self, size, records=[]):
		self.reply_size = size
		self.reply_records = records
		self.CheckRecords(size, records, "Reply", 8)
		self.ptvc_reply = self.MakePTVC(records, "reply")

	def CheckRecords(self, size, records, descr, min_hdr_length):
		"Simple sanity check"
		if size == NO_LENGTH_CHECK:
			return
		min = size
		max = size
		if type(size) == type(()):
			min = size[0]
			max = size[1]

		lower = min_hdr_length
		upper = min_hdr_length

		for record in records:
			rec_size = record[REC_LENGTH]
			rec_lower = rec_size
			rec_upper = rec_size
			if type(rec_size) == type(()):
				rec_lower = rec_size[0]
				rec_upper = rec_size[1]

			lower = lower + rec_lower
			upper = upper + rec_upper

		error = 0
		if min != lower:
			msg.write("%s records for 2222/0x%x sum to %d bytes minimum, but param1 shows %d\n" \
				% (descr, self.FunctionCode(), lower, min))
			error = 1
		if max != upper:
			msg.write("%s records for 2222/0x%x sum to %d bytes maximum, but param1 shows %d\n" \
				% (descr, self.FunctionCode(), upper, max))
			error = 1

		if error == 1:
			sys.exit(1)


	def MakePTVC(self, records, name_suffix):
		"""Makes a PTVC out of a request or reply record list. Possibly adds
		it to the global list of PTVCs (the global list is a UniqueCollection,
		so an equivalent PTVC may already be in the global list)."""

		name = "%s_%s" % (self.CName(), name_suffix)
		ptvc = PTVC(name, records)
		return ptvc_lists.Add(ptvc)

	def CName(self):
		"Returns a C symbol based on the NCP function code"
		return "ncp_0x%x" % (self.func_code)

	def InfoStrName(self):
		"Returns a C symbol based on the NCP function code, for the info_str"
		return "info_str_0x%x" % (self.func_code)

	def Variables(self):
		"""Returns a list of variables used in the request and reply records.
		A variable is listed only once, even if it is used twice (once in
		the request, once in the reply)."""

		variables = {}
		if self.request_records:
			for record in self.request_records:
				var = record[REC_FIELD]
				variables[var.HFName()] = var

				sub_vars = var.SubVariables()
				for sv in sub_vars:
					variables[sv.HFName()] = sv

		if self.reply_records:
			for record in self.reply_records:
				var = record[REC_FIELD]
				variables[var.HFName()] = var

				sub_vars = var.SubVariables()
				for sv in sub_vars:
					variables[sv.HFName()] = sv

		return variables.values()

	def CalculateReqConds(self):
		"""Returns a list of request conditions (dfilter text) used
		in the reply records. A request condition is listed only once,
		even it it used twice. """
		texts = {}
		if self.reply_records:
			for record in self.reply_records:
				text = record[REC_REQ_COND]
				if text != NO_REQ_COND:
					texts[text] = None

		if len(texts) == 0:
			self.req_conds = None
			return None

		dfilter_texts = texts.keys()
		dfilter_texts.sort()
		name = "%s_req_cond_indexes" % (self.CName(),)
		return NamedList(name, dfilter_texts)

	def GetReqConds(self):
		return self.req_conds

	def SetReqConds(self, new_val):
		self.req_conds = new_val


	def CompletionCodes(self, codes=None):
		"""Sets or returns the list of completion
		codes. Internally, a NamedList is used to store the
		completion codes, but the caller of this function never
		realizes that because Python lists are the input and
		output."""

		if codes == None:
			return self.codes

		# Sanity check
		okay = 1
		for code in codes:
			if not errors.has_key(code):
				msg.write("Errors table does not have key 0x%04x for NCP=0x%x\n" % (code,
					self.func_code))
				okay = 0

		# Delay the exit until here so that the programmer can get
		# the complete list of missing error codes
		if not okay:
			sys.exit(1)

		# Create CompletionCode (NamedList) object and possible
		# add it to  the global list of completion code lists.
		name = "%s_errors" % (self.CName(),)
		codes.sort()
		codes_list = NamedList(name, codes)
		self.codes = compcode_lists.Add(codes_list)

		self.Finalize()

	def Finalize(self):
		"""Adds the NCP object to the global collection of NCP
		objects. This is done automatically after setting the
		CompletionCode list. Yes, this is a shortcut, but it makes
		our list of NCP packet definitions look neater, since an
		explicit "add to global list of packets" is not needed."""

		# Add packet to global collection of packets
		packets.append(self)

def rec(start, length, field, endianness=None, **kw):
        return _rec(start, length, field, endianness, kw)

def srec(field, endianness=None, **kw):
	return _rec(-1, -1, field, endianness, kw)

def _rec(start, length, field, endianness, kw):
	# If endianness not explicitly given, use the field's
	# default endiannes.
	if endianness == None:
		endianness = field.Endianness()

	# Setting a var?
	if kw.has_key("var"):
		# Is the field an INT ?
		if not isinstance(field, CountingNumber):
			sys.exit("Field %s used as count variable, but not integer." \
				% (field.HFName()))
		var = kw["var"]
	else:
		var = None

	# If 'var' not used, 'repeat' can be used.
	if not var and kw.has_key("repeat"):
		repeat = kw["repeat"]
	else:
		repeat = None

	# Request-condition ?
	if kw.has_key("req_cond"):
		req_cond = kw["req_cond"]
	else:
		req_cond = NO_REQ_COND

	return [start, length, field, endianness, var, repeat, req_cond]




##############################################################################

LE		= 1		# Little-Endian
BE		= 0		# Big-Endian
NA		= -1		# Not Applicable

class Type:
	" Virtual class for NCP field types"
	type		= "Type"
	ftype		= None
	disp		= "BASE_DEC"
	endianness	= NA
	values		= []

	def __init__(self, abbrev, descr, bytes, endianness = NA):
		self.abbrev = abbrev
		self.descr = descr
		self.bytes = bytes
		self.endianness = endianness
		self.hfname = "hf_ncp_" + self.abbrev
		self.special_fmt = "NCP_FMT_NONE"

	def Length(self):
		return self.bytes

	def Abbreviation(self):
		return self.abbrev

	def Description(self):
		return self.descr

	def HFName(self):
		return self.hfname

	def DFilter(self):
		return "ncp." + self.abbrev

	def EtherealFType(self):
		return self.ftype

	def Display(self, newval=None):
		if newval != None:
			self.disp = newval
		return self.disp

	def ValuesName(self):
		return "NULL"

	def Mask(self):
		return 0

	def Endianness(self):
		return self.endianness

	def SubVariables(self):
		return []

	def PTVCName(self):
		return "NULL"

	def NWDate(self):
		self.special_fmt = "NCP_FMT_NW_DATE"

	def NWTime(self):
		self.special_fmt = "NCP_FMT_NW_TIME"

	def NWUnicode(self):
		self.special_fmt = "NCP_FMT_UNICODE"

	def SpecialFmt(self):
		return self.special_fmt

	def __cmp__(self, other):
		return cmp(self.hfname, other.hfname)

class struct(PTVC, Type):
	def __init__(self, name, items, descr=None):
		name = "struct_%s" % (name,)
		NamedList.__init__(self, name, [])

		self.bytes = 0
		self.descr = descr
		for item in items:
			if isinstance(item, Type):
				field = item
				length = field.Length()
				endianness = field.Endianness()
				var = NO_VAR
				repeat = NO_REPEAT
				req_cond = NO_REQ_COND
			elif type(item) == type([]):
				field = item[REC_FIELD]
				length = item[REC_LENGTH]
				endianness = item[REC_ENDIANNESS]
				var = item[REC_VAR]
				repeat = item[REC_REPEAT]
				req_cond = item[REC_REQ_COND]
			else:
				assert 0, "Item %s item not handled." % (item,)

			ptvc_rec = PTVCRecord(field, length, endianness, var,
				repeat, req_cond)
			self.list.append(ptvc_rec)
			self.bytes = self.bytes + field.Length()

		self.hfname = self.name

	def Variables(self):
		vars = []
		for ptvc_rec in self.list:
			vars.append(ptvc_rec.Field())
		return vars

	def ReferenceString(self, var, repeat, req_cond):
		return "{ PTVC_STRUCT, NO_LENGTH, &%s, NO_ENDIANNESS, %s, %s, %s, NCP_FMT_NONE }" % \
			(self.name, var, repeat, req_cond)

	def Code(self):
		ett_name = self.ETTName()
		x = "static gint %s;\n" % (ett_name,)
		x = x + "static const ptvc_record ptvc_%s[] = {\n" % (self.name,)
		for ptvc_rec in self.list:
			x = x +  "\t%s,\n" % (ptvc_rec.Code())
		x = x + "\t{ NULL, NO_LENGTH, NULL, NO_ENDIANNESS, NO_VAR, NO_REPEAT, NO_REQ_COND, NCP_FMT_NONE }\n"
		x = x + "};\n"

		x = x + "static const sub_ptvc_record %s = {\n" % (self.name,)
		x = x + "\t&%s,\n" % (ett_name,)
		if self.descr:
			x = x + '\t"%s",\n' % (self.descr,)
		else:
			x = x + "\tNULL,\n"
		x = x + "\tptvc_%s,\n" % (self.Name(),)
		x = x + "};\n"
		return x

	def __cmp__(self, other):
		return cmp(self.HFName(), other.HFName())


class byte(Type):
	type	= "byte"
	ftype	= "FT_UINT8"
	def __init__(self, abbrev, descr):
		Type.__init__(self, abbrev, descr, 1)

class CountingNumber:
	pass

# Same as above. Both are provided for convenience
class uint8(Type, CountingNumber):
	type	= "uint8"
	ftype	= "FT_UINT8"
	bytes	= 1
	def __init__(self, abbrev, descr):
		Type.__init__(self, abbrev, descr, 1)

class uint16(Type, CountingNumber):
	type	= "uint16"
	ftype	= "FT_UINT16"
	def __init__(self, abbrev, descr, endianness = LE):
		Type.__init__(self, abbrev, descr, 2, endianness)

class uint24(Type, CountingNumber):
	type	= "uint24"
	ftype	= "FT_UINT24"
	def __init__(self, abbrev, descr, endianness = LE):
		Type.__init__(self, abbrev, descr, 3, endianness)

class uint32(Type, CountingNumber):
	type	= "uint32"
	ftype	= "FT_UINT32"
	def __init__(self, abbrev, descr, endianness = LE):
		Type.__init__(self, abbrev, descr, 4, endianness)

class boolean8(uint8):
	type	= "boolean8"
	ftype	= "FT_BOOLEAN"

class boolean16(uint16):
	type	= "boolean16"
	ftype	= "FT_BOOLEAN"

class boolean24(uint24):
	type	= "boolean24"
	ftype	= "FT_BOOLEAN"

class boolean32(uint32):
	type	= "boolean32"
	ftype	= "FT_BOOLEAN"

class nstring:
	pass

class nstring8(Type, nstring):
	"""A string of up to (2^8)-1 characters. The first byte
	gives the string length."""

	type	= "nstring8"
	ftype	= "FT_UINT_STRING"
	def __init__(self, abbrev, descr):
		Type.__init__(self, abbrev, descr, 1)

class nstring16(Type, nstring):
	"""A string of up to (2^16)-2 characters. The first 2 bytes
	gives the string length."""

	type	= "nstring16"
	ftype	= "FT_UINT_STRING"
	def __init__(self, abbrev, descr, endianness = LE):
		Type.__init__(self, abbrev, descr, 2, endianness)

class nstring32(Type, nstring):
	"""A string of up to (2^32)-4 characters. The first 4 bytes
	gives the string length."""

	type	= "nstring32"
	ftype	= "FT_UINT_STRING"
	def __init__(self, abbrev, descr, endianness = LE):
		Type.__init__(self, abbrev, descr, 4, endianness)

class fw_string(Type):
	"""A fixed-width string of n bytes."""

	type	= "fw_string"
	ftype	= "FT_STRING"

	def __init__(self, abbrev, descr, bytes):
		Type.__init__(self, abbrev, descr, bytes)


class stringz(Type):
	"NUL-terminated string, with a maximum length"

	type	= "stringz"
	ftype	= "FT_STRINGZ"
	def __init__(self, abbrev, descr):
		Type.__init__(self, abbrev, descr, PROTO_LENGTH_UNKNOWN)

class val_string(Type):
	"""Abstract class for val_stringN, where N is number
	of bits that key takes up."""

	type	= "val_string"
	disp	= 'BASE_HEX'

	def __init__(self, abbrev, descr, val_string_array, endianness = LE):
		Type.__init__(self, abbrev, descr, self.bytes, endianness)
		self.values = val_string_array

	def Code(self):
		result = "static const value_string %s[] = {\n" \
				% (self.ValuesCName())
		for val_record in self.values:
			value	= val_record[0]
			text	= val_record[1]
			value_repr = self.value_format % value
			result = result + '\t{ %s,\t"%s" },\n' \
					% (value_repr, text)

		value_repr = self.value_format % 0
		result = result + "\t{ %s,\tNULL },\n" % (value_repr)
		result = result + "};\n"
                REC_VAL_STRING_RES = self.value_format % value
		return result

	def ValuesCName(self):
		return "ncp_%s_vals" % (self.abbrev)

	def ValuesName(self):
		return "VALS(%s)" % (self.ValuesCName())

class val_string8(val_string):
	type		= "val_string8"
	ftype		= "FT_UINT8"
	bytes		= 1
	value_format	= "0x%02x"

class val_string16(val_string):
	type		= "val_string16"
	ftype		= "FT_UINT16"
	bytes		= 2
	value_format	= "0x%04x"

class val_string32(val_string):
	type		= "val_string32"
	ftype		= "FT_UINT32"
	bytes		= 4
	value_format	= "0x%08x"

class bytes(Type):
	type	= 'bytes'
	ftype	= 'FT_BYTES'

	def __init__(self, abbrev, descr, bytes):
		Type.__init__(self, abbrev, descr, bytes, NA)

class nbytes:
	pass

class nbytes8(Type, nbytes):
	"""A series of up to (2^8)-1 bytes. The first byte
	gives the byte-string length."""

	type	= "nbytes8"
	ftype	= "FT_UINT_BYTES"
	def __init__(self, abbrev, descr, endianness = LE):
		Type.__init__(self, abbrev, descr, 1, endianness)

class nbytes16(Type, nbytes):
	"""A series of up to (2^16)-2 bytes. The first 2 bytes
	gives the byte-string length."""

	type	= "nbytes16"
	ftype	= "FT_UINT_BYTES"
	def __init__(self, abbrev, descr, endianness = LE):
		Type.__init__(self, abbrev, descr, 2, endianness)

class nbytes32(Type, nbytes):
	"""A series of up to (2^32)-4 bytes. The first 4 bytes
	gives the byte-string length."""

	type	= "nbytes32"
	ftype	= "FT_UINT_BYTES"
	def __init__(self, abbrev, descr, endianness = LE):
		Type.__init__(self, abbrev, descr, 4, endianness)

class bf_uint(Type):
	type	= "bf_uint"
	disp	= None

	def __init__(self, bitmask, abbrev, descr, endianness=LE):
		Type.__init__(self, abbrev, descr, self.bytes, endianness)
		self.bitmask = bitmask

	def Mask(self):
		return self.bitmask

class bf_val_str(bf_uint):
	type	= "bf_uint"
	disp	= None

	def __init__(self, bitmask, abbrev, descr, val_string_array, endiannes=LE):
		bf_uint.__init__(self, bitmask, abbrev, descr, endiannes)
		self.values = val_string_array

	def ValuesName(self):
		return "VALS(%s)" % (self.ValuesCName())

class bf_val_str8(bf_val_str, val_string8):
	type    = "bf_val_str8"
	ftype   = "FT_UINT8"
	disp    = "BASE_HEX"
	bytes	= 1

class bf_val_str16(bf_val_str, val_string16):
	type    = "bf_val_str16"
	ftype   = "FT_UINT16"
	disp    = "BASE_HEX"
	bytes	= 2

class bf_val_str32(bf_val_str, val_string32):
	type    = "bf_val_str32"
	ftype   = "FT_UINT32"
	disp    = "BASE_HEX"
	bytes	= 4

class bf_boolean:
    pass

class bf_boolean8(bf_uint, boolean8, bf_boolean):
	type	= "bf_boolean8"
	ftype	= "FT_BOOLEAN"
	disp	= "8"
	bytes	= 1

class bf_boolean16(bf_uint, boolean16, bf_boolean):
	type	= "bf_boolean16"
	ftype	= "FT_BOOLEAN"
	disp	= "16"
	bytes	= 2

class bf_boolean24(bf_uint, boolean24, bf_boolean):
	type	= "bf_boolean24"
	ftype	= "FT_BOOLEAN"
	disp	= "24"
	bytes	= 3

class bf_boolean32(bf_uint, boolean32, bf_boolean):
	type	= "bf_boolean32"
	ftype	= "FT_BOOLEAN"
	disp	= "32"
	bytes	= 4

class bitfield(Type):
	type	= "bitfield"
	disp	= 'BASE_HEX'

	def __init__(self, vars):
		var_hash = {}
		for var in vars:
			if isinstance(var, bf_boolean):
				if not isinstance(var, self.bf_type):
					print "%s must be of type %s" % \
						(var.Abbreviation(),
						self.bf_type)
					sys.exit(1)
			var_hash[var.bitmask] = var

		bitmasks = var_hash.keys()
		bitmasks.sort()
		bitmasks.reverse()

		ordered_vars = []
		for bitmask in bitmasks:
			var = var_hash[bitmask]
			ordered_vars.append(var)

		self.vars = ordered_vars
		self.ptvcname = "ncp_%s_bitfield" % (self.abbrev,)
		self.hfname = "hf_ncp_%s" % (self.abbrev,)
		self.sub_ptvc = PTVCBitfield(self.PTVCName(), self.vars)

	def SubVariables(self):
		return self.vars

	def SubVariablesPTVC(self):
		return self.sub_ptvc

	def PTVCName(self):
		return self.ptvcname


class bitfield8(bitfield, uint8):
	type	= "bitfield8"
	ftype	= "FT_UINT8"
	bf_type = bf_boolean8

	def __init__(self, abbrev, descr, vars):
		uint8.__init__(self, abbrev, descr)
		bitfield.__init__(self, vars)

class bitfield16(bitfield, uint16):
	type	= "bitfield16"
	ftype	= "FT_UINT16"
	bf_type = bf_boolean16

	def __init__(self, abbrev, descr, vars, endianness=LE):
		uint16.__init__(self, abbrev, descr, endianness)
		bitfield.__init__(self, vars)

class bitfield24(bitfield, uint24):
	type	= "bitfield24"
	ftype	= "FT_UINT24"
	bf_type = bf_boolean24

	def __init__(self, abbrev, descr, vars, endianness=LE):
		uint24.__init__(self, abbrev, descr, endianness)
		bitfield.__init__(self, vars)

class bitfield32(bitfield, uint32):
	type	= "bitfield32"
	ftype	= "FT_UINT32"
	bf_type = bf_boolean32

	def __init__(self, abbrev, descr, vars, endianness=LE):
		uint32.__init__(self, abbrev, descr, endianness)
		bitfield.__init__(self, vars)

#
# Force the endianness of a field to a non-default value; used in
# the list of fields of a structure.
#
def endian(field, endianness):
	return [-1, field.Length(), field, endianness, NO_VAR, NO_REPEAT, NO_REQ_COND]

##############################################################################
# NCP Field Types. Defined in Appendix A of "Programmer's Guide..."
##############################################################################

AbortQueueFlag  		= val_string8("abort_q_flag", "Abort Queue Flag", [
	[ 0x00, "Place at End of Queue" ],
	[ 0x01, "Do Not Place Spool File, Examine Flags" ],
])
AcceptedMaxSize			= uint16("accepted_max_size", "Accepted Max Size")
AccessControl 			= val_string8("access_control", "Access Control", [
	[ 0x00, "Open for read by this client" ],
	[ 0x01, "Open for write by this client" ],
	[ 0x02, "Deny read requests from other stations" ],
	[ 0x03, "Deny write requests from other stations" ],
	[ 0x04, "File detached" ],
	[ 0x05, "TTS holding detach" ],
	[ 0x06, "TTS holding open" ],
])
AccessDate 			= uint16("access_date", "Access Date")
AccessDate.NWDate()
AccessMode 			= bitfield8("access_mode", "Access Mode", [
	bf_boolean8(0x01, "acc_mode_read", "Read Access"),
	bf_boolean8(0x02, "acc_mode_write", "Write Access"),
	bf_boolean8(0x04, "acc_mode_deny_read", "Deny Read Access"),
	bf_boolean8(0x08, "acc_mode_deny_write", "Deny Write Access"),
	bf_boolean8(0x10, "acc_mode_comp", "Compatibility Mode"),
])
AccessPrivileges		= bitfield8("access_privileges", "Access Privileges", [
	bf_boolean8(0x01, "acc_priv_read", "Read Privileges (files only)"),
	bf_boolean8(0x02, "acc_priv_write", "Write Privileges (files only)"),
	bf_boolean8(0x04, "acc_priv_open", "Open Privileges (files only)"),
	bf_boolean8(0x08, "acc_priv_create", "Create Privileges (files only)"),
	bf_boolean8(0x10, "acc_priv_delete", "Delete Privileges (files only)"),
	bf_boolean8(0x20, "acc_priv_parent", "Parental Privileges (directories only for creating, deleting, and renaming)"),
	bf_boolean8(0x40, "acc_priv_search", "Search Privileges (directories only)"),
	bf_boolean8(0x80, "acc_priv_modify", "Modify File Status Flags Privileges (files and directories)"),
])
AccessRightsMask 		= bitfield8("access_rights_mask", "Access Rights", [
	bf_boolean8(0x0001, "acc_rights_read", "Read Rights"),
	bf_boolean8(0x0002, "acc_rights_write", "Write Rights"),
	bf_boolean8(0x0004, "acc_rights_open", "Open Rights"),
	bf_boolean8(0x0008, "acc_rights_create", "Create Rights"),
	bf_boolean8(0x0010, "acc_rights_delete", "Delete Rights"),
	bf_boolean8(0x0020, "acc_rights_parent", "Parental Rights"),
	bf_boolean8(0x0040, "acc_rights_search", "Search Rights"),
	bf_boolean8(0x0080, "acc_rights_modify", "Modify Rights"),
])
AccessRightsMaskWord 		= bitfield16("access_rights_mask_word", "Access Rights", [
	bf_boolean16(0x0001, "acc_rights1_read", "Read Rights"),
	bf_boolean16(0x0002, "acc_rights1_write", "Write Rights"),
	bf_boolean16(0x0004, "acc_rights1_open", "Open Rights"),
	bf_boolean16(0x0008, "acc_rights1_create", "Create Rights"),
	bf_boolean16(0x0010, "acc_rights1_delete", "Delete Rights"),
	bf_boolean16(0x0020, "acc_rights1_parent", "Parental Rights"),
	bf_boolean16(0x0040, "acc_rights1_search", "Search Rights"),
	bf_boolean16(0x0080, "acc_rights1_modify", "Modify Rights"),
	bf_boolean16(0x0100, "acc_rights1_supervisor", "Supervisor Access Rights"),
])
AccountBalance			= uint32("account_balance", "Account Balance")
AccountVersion			= uint8("acct_version", "Acct Version")
ActionFlag 			= bitfield8("action_flag", "Action Flag", [
	bf_boolean8(0x01, "act_flag_open", "Open"),
	bf_boolean8(0x02, "act_flag_replace", "Replace"),
	bf_boolean8(0x10, "act_flag_create", "Create"),
])
ActiveConnBitList		= fw_string("active_conn_bit_list", "Active Connection List", 512)
ActiveIndexedFiles		= uint16("active_indexed_files", "Active Indexed Files")
ActualMaxBinderyObjects 	= uint16("actual_max_bindery_objects", "Actual Max Bindery Objects")
ActualMaxIndexedFiles		= uint16("actual_max_indexed_files", "Actual Max Indexed Files")
ActualMaxOpenFiles		= uint16("actual_max_open_files", "Actual Max Open Files")
ActualMaxSimultaneousTransactions = uint16("actual_max_sim_trans", "Actual Max Simultaneous Transactions")
ActualMaxUsedDirectoryEntries 	= uint16("actual_max_used_directory_entries", "Actual Max Used Directory Entries")
ActualMaxUsedRoutingBuffers 	= uint16("actual_max_used_routing_buffers", "Actual Max Used Routing Buffers")
ActualResponseCount 		= uint16("actual_response_count", "Actual Response Count")
AddNameSpaceAndVol              = stringz("add_nm_spc_and_vol", "Add Name Space and Volume")
AFPEntryID			= uint32("afp_entry_id", "AFP Entry ID", BE)
AFPEntryID.Display("BASE_HEX")
AllocAvailByte			= uint32("alloc_avail_byte", "Bytes Available for Allocation")
AllocateMode			= val_string16("allocate_mode", "Allocate Mode", [
	[ 0x0000, "Permanent Directory Handle" ],
	[ 0x0001, "Temporary Directory Handle" ],
	[ 0x0002, "Special Temporary Directory Handle" ],
])
AllocationBlockSize		= uint32("allocation_block_size", "Allocation Block Size")
AllocFreeCount			= uint32("alloc_free_count", "Reclaimable Free Bytes")
ApplicationNumber		= uint16("application_number", "Application Number")
ArchivedTime			= uint16("archived_time", "Archived Time")
ArchivedTime.NWTime()
ArchivedDate			= uint16("archived_date", "Archived Date")
ArchivedDate.NWDate()
ArchiverID			= uint32("archiver_id", "Archiver ID", BE)
ArchiverID.Display("BASE_HEX")
AssociatedNameSpace		= uint8("associated_name_space", "Associated Name Space")
AttachDuringProcessing 		= uint16("attach_during_processing", "Attach During Processing")
AttachedIndexedFiles		= uint8("attached_indexed_files", "Attached Indexed Files")
AttachWhileProcessingAttach 	= uint16("attach_while_processing_attach", "Attach While Processing Attach")
Attributes			= uint32("attributes", "Attributes")
AttributesDef   		= bitfield8("attr_def", "Attributes", [
	bf_boolean8(0x01, "att_def_ro", "Read Only"),
	bf_boolean8(0x02, "att_def_hidden", "Hidden"),
	bf_boolean8(0x04, "att_def_system", "System"),
	bf_boolean8(0x08, "att_def_execute", "Execute"),
	bf_boolean8(0x10, "att_def_sub_only", "Subdirectory"),
	bf_boolean8(0x20, "att_def_archive", "Archive"),
	bf_boolean8(0x80, "att_def_shareable", "Shareable"),
])
AttributesDef16   		= bitfield16("attr_def_16", "Attributes", [
	bf_boolean16(0x0001, "att_def16_ro", "Read Only"),
	bf_boolean16(0x0002, "att_def16_hidden", "Hidden"),
	bf_boolean16(0x0004, "att_def16_system", "System"),
	bf_boolean16(0x0008, "att_def16_execute", "Execute"),
	bf_boolean16(0x0010, "att_def16_sub_only", "Subdirectory"),
	bf_boolean16(0x0020, "att_def16_archive", "Archive"),
	bf_boolean16(0x0080, "att_def16_shareable", "Shareable"),
	bf_boolean16(0x1000, "att_def16_transaction", "Transactional"),
	bf_boolean16(0x4000, "att_def16_read_audit", "Read Audit"),
	bf_boolean16(0x8000, "att_def16_write_audit", "Write Audit"),
])
AttributesDef32   		= bitfield32("attr_def_32", "Attributes", [
	bf_boolean32(0x00000001, "att_def32_ro", "Read Only"),
	bf_boolean32(0x00000002, "att_def32_hidden", "Hidden"),
	bf_boolean32(0x00000004, "att_def32_system", "System"),
	bf_boolean32(0x00000008, "att_def32_execute", "Execute"),
	bf_boolean32(0x00000010, "att_def32_sub_only", "Subdirectory"),
	bf_boolean32(0x00000020, "att_def32_archive", "Archive"),
	bf_boolean32(0x00000080, "att_def32_shareable", "Shareable"),
	bf_boolean32(0x00001000, "att_def32_transaction", "Transactional"),
	bf_boolean32(0x00004000, "att_def32_read_audit", "Read Audit"),
	bf_boolean32(0x00008000, "att_def32_write_audit", "Write Audit"),
	bf_boolean32(0x00010000, "att_def_purge", "Purge"),
	bf_boolean32(0x00020000, "att_def_reninhibit", "Rename Inhibit"),
	bf_boolean32(0x00040000, "att_def_delinhibit", "Delete Inhibit"),
	bf_boolean32(0x00080000, "att_def_cpyinhibit", "Copy Inhibit"),
	bf_boolean32(0x02000000, "att_def_im_comp", "Immediate Compress"),
	bf_boolean32(0x04000000, "att_def_comp", "Compressed"),
])
AttributeValidFlag 		= uint32("attribute_valid_flag", "Attribute Valid Flag")
AuditFileVersionDate            = uint16("audit_file_ver_date", "Audit File Version Date")
AuditFileVersionDate.NWDate()
AuditFlag			= val_string8("audit_flag", "Audit Flag", [
	[ 0x00, "Do NOT audit object" ],
	[ 0x01, "Audit object" ],
])
AuditHandle			= uint32("audit_handle", "Audit File Handle")
AuditHandle.Display("BASE_HEX")
AuditID				= uint32("audit_id", "Audit ID", BE)
AuditID.Display("BASE_HEX")
AuditIDType			= val_string16("audit_id_type", "Audit ID Type", [
	[ 0x0000, "Volume" ],
	[ 0x0001, "Container" ],
])
AuditVersionDate                = uint16("audit_ver_date", "Auditing Version Date")
AuditVersionDate.NWDate()
AvailableBlocks			= uint32("available_blocks", "Available Blocks")
AvailableClusters		= uint16("available_clusters", "Available Clusters")
AvailableDirectorySlots		= uint16("available_directory_slots", "Available Directory Slots")
AvailableDirEntries		= uint32("available_dir_entries", "Available Directory Entries")
AvailableIndexedFiles		= uint16("available_indexed_files", "Available Indexed Files")

BackgroundAgedWrites 		= uint32("background_aged_writes", "Background Aged Writes")
BackgroundDirtyWrites		= uint32("background_dirty_writes", "Background Dirty Writes")
BadLogicalConnectionCount 	= uint16("bad_logical_connection_count", "Bad Logical Connection Count")
BannerName			= fw_string("banner_name", "Banner Name", 14)
BaseDirectoryID			= uint32("base_directory_id", "Base Directory ID", BE)
BaseDirectoryID.Display("BASE_HEX")
binderyContext			= nstring8("bindery_context", "Bindery Context")
BitMap				= bytes("bit_map", "Bit Map", 512)
BlockNumber                     = uint32("block_number", "Block Number")
BlockSize 			= uint16("block_size", "Block Size")
BlockSizeInSectors		= uint32("block_size_in_sectors", "Block Size in Sectors")
BoardInstalled 			= uint8("board_installed", "Board Installed")
BoardNumber                     = uint32("board_number", "Board Number")
BoardNumbers                    = uint32("board_numbers", "Board Numbers")
BufferSize			= uint16("buffer_size", "Buffer Size")
BusString			= stringz("bus_string", "Bus String")
BusType				= val_string8("bus_type", "Bus Type", [
	[0x00, "ISA"],
	[0x01, "Micro Channel" ],
	[0x02, "EISA"],
	[0x04, "PCI"],
	[0x08, "PCMCIA"],
	[0x10, "ISA"],
        [0x14, "ISA"],
])
BytesActuallyTransferred	= uint32("bytes_actually_transferred", "Bytes Actually Transferred")
BytesRead 			= fw_string("bytes_read", "Bytes Read", 6)
BytesToCopy			= uint32("bytes_to_copy", "Bytes to Copy")
BytesWritten 			= fw_string("bytes_written", "Bytes Written", 6)

CacheAllocations 		= uint32("cache_allocations", "Cache Allocations")
CacheBlockScrapped		= uint16("cache_block_scrapped", "Cache Block Scrapped")
CacheBufferCount 		= uint16("cache_buffer_count", "Cache Buffer Count")
CacheBufferSize 		= uint16("cache_buffer_size", "Cache Buffer Size")
CacheFullWriteRequests		= uint32("cache_full_write_requests", "Cache Full Write Requests")
CacheGetRequests		= uint32("cache_get_requests", "Cache Get Requests")
CacheHitOnUnavailableBlock	= uint16("cache_hit_on_unavailable_block", "Cache Hit On Unavailable Block")
CacheHits 			= uint32("cache_hits", "Cache Hits")
CacheMisses 			= uint32("cache_misses", "Cache Misses")
CachePartialWriteRequests	= uint32("cache_partial_write_requests", "Cache Partial Write Requests")
CacheReadRequests 		= uint32("cache_read_requests", "Cache Read Requests")
CacheWriteRequests 		= uint32("cache_write_requests", "Cache Write Requests")
CategoryName                    = stringz("category_name", "Category Name")
CCFileHandle			= uint32("cc_file_handle", "File Handle")
CCFileHandle.Display("BASE_HEX")
CCFunction			= val_string8("cc_function", "OP-Lock Flag", [
	[ 0x01, "Clear OP-Lock" ],
	[ 0x02, "Acknowledge Callback" ],
	[ 0x03, "Decline Callback" ],
    [ 0x04, "Level 2" ],
])
ChangeBits			= bitfield16("change_bits", "Change Bits", [
	bf_boolean16(0x0001, "change_bits_modify", "Modify Name"),
	bf_boolean16(0x0002, "change_bits_fatt", "File Attributes"),
	bf_boolean16(0x0004, "change_bits_cdate", "Creation Date"),
	bf_boolean16(0x0008, "change_bits_ctime", "Creation Time"),
	bf_boolean16(0x0010, "change_bits_owner", "Owner ID"),
	bf_boolean16(0x0020, "change_bits_adate", "Archive Date"),
	bf_boolean16(0x0040, "change_bits_atime", "Archive Time"),
	bf_boolean16(0x0080, "change_bits_aid", "Archiver ID"),
        bf_boolean16(0x0100, "change_bits_udate", "Update Date"),
	bf_boolean16(0x0200, "change_bits_utime", "Update Time"),
	bf_boolean16(0x0400, "change_bits_uid", "Update ID"),
	bf_boolean16(0x0800, "change_bits_acc_date", "Access Date"),
	bf_boolean16(0x1000, "change_bits_max_acc_mask", "Maximum Access Mask"),
	bf_boolean16(0x2000, "change_bits_max_space", "Maximum Space"),
])
ChannelState 			= val_string8("channel_state", "Channel State", [
	[ 0x00, "Channel is running" ],
	[ 0x01, "Channel is stopping" ],
	[ 0x02, "Channel is stopped" ],
	[ 0x03, "Channel is not functional" ],
])
ChannelSynchronizationState 	= val_string8("channel_synchronization_state", "Channel Synchronization State", [
	[ 0x00, "Channel is not being used" ],
	[ 0x02, "NetWare is using the channel; no one else wants it" ],
	[ 0x04, "NetWare is using the channel; someone else wants it" ],
	[ 0x06, "Someone else is using the channel; NetWare does not need it" ],
	[ 0x08, "Someone else is using the channel; NetWare needs it" ],
	[ 0x0A, "Someone else has released the channel; NetWare should use it" ],
])
ChargeAmount			= uint32("charge_amount", "Charge Amount")
ChargeInformation		= uint32("charge_information", "Charge Information")
ClientCompFlag			= val_string16("client_comp_flag", "Completion Flag", [
	[ 0x0000, "Successful" ],
	[ 0x0001, "Illegal Station Number" ],
	[ 0x0002, "Client Not Logged In" ],
	[ 0x0003, "Client Not Accepting Messages" ],
	[ 0x0004, "Client Already has a Message" ],
	[ 0x0096, "No Alloc Space for the Message" ],
	[ 0x00fd, "Bad Station Number" ],
	[ 0x00ff, "Failure" ],
])
ClientIDNumber			= uint32("client_id_number", "Client ID Number", BE)
ClientIDNumber.Display("BASE_HEX")
ClientList			= uint32("client_list", "Client List")
ClientListCount			= uint16("client_list_cnt", "Client List Count")
ClientListLen			= uint8("client_list_len", "Client List Length")
ClientName			= nstring8("client_name", "Client Name")
ClientRecordArea		= fw_string("client_record_area", "Client Record Area", 152)
ClientStation			= uint8("client_station", "Client Station")
ClientStationLong		= uint32("client_station_long", "Client Station")
ClientTaskNumber		= uint8("client_task_number", "Client Task Number")
ClientTaskNumberLong		= uint32("client_task_number_long", "Client Task Number")
ClusterCount			= uint16("cluster_count", "Cluster Count")
ClustersUsedByDirectories	= uint32("clusters_used_by_directories", "Clusters Used by Directories")
ClustersUsedByExtendedDirectories = uint32("clusters_used_by_extended_dirs", "Clusters Used by Extended Directories")
ClustersUsedByFAT		= uint32("clusters_used_by_fat", "Clusters Used by FAT")
ComCnts                         = uint16("com_cnts", "Communication Counters")
Comment				= nstring8("comment", "Comment")
CommentType			= uint16("comment_type", "Comment Type")
CompletionCode			= uint32("ncompletion_code", "Completion Code")
CompressedDataStreamsCount	= uint32("compressed_data_streams_count", "Compressed Data Streams Count")
CompressedLimboDataStreamsCount	= uint32("compressed_limbo_data_streams_count", "Compressed Limbo Data Streams Count")
CompressedSectors		= uint32("compressed_sectors", "Compressed Sectors")
compressionStage                = uint32("compression_stage", "Compression Stage")
compressVolume                  = uint32("compress_volume", "Volume Compression")
ConfigMajorVN                   = uint8("config_major_vn", "Configuration Major Version Number")
ConfigMinorVN                   = uint8("config_minor_vn", "Configuration Minor Version Number")
ConfigurationDescription	= fw_string("configuration_description", "Configuration Description", 80)
ConfigurationText		= fw_string("configuration_text", "Configuration Text", 160)
ConfiguredMaxBinderyObjects	= uint16("configured_max_bindery_objects", "Configured Max Bindery Objects")
ConfiguredMaxOpenFiles		= uint16("configured_max_open_files", "Configured Max Open Files")
ConfiguredMaxRoutingBuffers	= uint16("configured_max_routing_buffers", "Configured Max Routing Buffers")
ConfiguredMaxSimultaneousTransactions = uint16("cfg_max_simultaneous_transactions", "Configured Max Simultaneous Transactions")
ConnectedLAN                    = uint32("connected_lan", "LAN Adapter")
ConnectionControlBits 		= bitfield8("conn_ctrl_bits", "Connection Control", [
	bf_boolean8(0x01, "enable_brdcasts", "Enable Broadcasts"),
	bf_boolean8(0x02, "enable_personal_brdcasts", "Enable Personal Broadcasts"),
	bf_boolean8(0x04, "enable_wdog_messages", "Enable Watchdog Message"),
	bf_boolean8(0x10, "disable_brdcasts", "Disable Broadcasts"),
	bf_boolean8(0x20, "disable_personal_brdcasts", "Disable Personal Broadcasts"),
	bf_boolean8(0x40, "disable_wdog_messages", "Disable Watchdog Message"),
])
ConnectionListCount 		= uint32("conn_list_count", "Connection List Count")
ConnectionList			= uint32("connection_list", "Connection List")
ConnectionNumber		= uint32("connection_number", "Connection Number", BE)
ConnectionNumberList		= nstring8("connection_number_list", "Connection Number List")
ConnectionNumberWord		= uint16("conn_number_word", "Connection Number")
ConnectionNumberByte		= uint8("conn_number_byte", "Connection Number")
ConnectionServiceType 		= val_string8("connection_service_type","Connection Service Type",[
	[ 0x01, "CLIB backward Compatibility" ],
	[ 0x02, "NCP Connection" ],
	[ 0x03, "NLM Connection" ],
	[ 0x04, "AFP Connection" ],
	[ 0x05, "FTAM Connection" ],
	[ 0x06, "ANCP Connection" ],
	[ 0x07, "ACP Connection" ],
	[ 0x08, "SMB Connection" ],
	[ 0x09, "Winsock Connection" ],
])
ConnectionsInUse		= uint16("connections_in_use", "Connections In Use")
ConnectionsMaxUsed		= uint16("connections_max_used", "Connections Max Used")
ConnectionsSupportedMax		= uint16("connections_supported_max", "Connections Supported Max")
ConnectionType			= val_string8("connection_type", "Connection Type", [
	[ 0x00, "Not in use" ],
	[ 0x02, "NCP" ],
	[ 0x11, "UDP (for IP)" ],
])
ConnListLen			= uint8("conn_list_len", "Connection List Length")
Copyright			= nstring8("copyright", "Copyright")
connList                        = uint32("conn_list", "Connection List")
ControlFlags			= val_string8("control_flags", "Control Flags", [
	[ 0x00, "Forced Record Locking is Off" ],
	[ 0x01, "Forced Record Locking is On" ],
])
ControllerDriveNumber 		= uint8("controller_drive_number", "Controller Drive Number")
ControllerNumber 		= uint8("controller_number", "Controller Number")
ControllerType			= uint8("controller_type", "Controller Type")
Cookie1 			= uint32("cookie_1", "Cookie 1")
Cookie2 			= uint32("cookie_2", "Cookie 2")
Copies				= uint8( "copies", "Copies" )
CoprocessorFlag			= uint32("co_processor_flag", "CoProcessor Present Flag")
CoProcessorString		= stringz("co_proc_string", "CoProcessor String")
CounterMask                     = val_string8("counter_mask", "Counter Mask", [
        [ 0x00, "Counter is Valid" ],
        [ 0x01, "Counter is not Valid" ],
])
CPUNumber			= uint32("cpu_number", "CPU Number")
CPUString			= stringz("cpu_string", "CPU String")
CPUType				= val_string8("cpu_type", "CPU Type", [
        [ 0x00, "80386" ],
        [ 0x01, "80486" ],
        [ 0x02, "Pentium" ],
        [ 0x03, "Pentium Pro" ],
])
CreationDate 			= uint16("creation_date", "Creation Date")
CreationDate.NWDate()
CreationTime			= uint16("creation_time", "Creation Time")
CreationTime.NWTime()
CreatorID			= uint32("creator_id", "Creator ID", BE)
CreatorID.Display("BASE_HEX")
CreatorNameSpaceNumber		= val_string8("creator_name_space_number", "Creator Name Space Number", [
	[ 0x00, "DOS Name Space" ],
	[ 0x01, "MAC Name Space" ],
	[ 0x02, "NFS Name Space" ],
	[ 0x04, "Long Name Space" ],
])
CreditLimit			= uint32("credit_limit", "Credit Limit")
CtrlFlags			= val_string16("ctrl_flags", "Control Flags", [
	[ 0x0000, "Do Not Return File Name" ],
	[ 0x0001, "Return File Name" ],
])
curCompBlks                     = uint32("cur_comp_blks", "Current Compression Blocks")
curInitialBlks                  = uint32("cur_initial_blks", "Current Initial Blocks")
curIntermediateBlks             = uint32("cur_inter_blks", "Current Intermediate Blocks")
CurNumOfRTags                   = uint32("cur_num_of_r_tags", "Current Number of Resource Tags")
CurrentBlockBeingDecompressed   = uint32("cur_blk_being_dcompress", "Current Block Being Decompressed")
CurrentChangedFATs		= uint16("current_changed_fats", "Current Changed FAT Entries")
CurrentEntries			= uint32("current_entries", "Current Entries")
CurrentFormType			= uint8( "current_form_type", "Current Form Type" )
CurrentLFSCounters		= uint32("current_lfs_counters", "Current LFS Counters")
CurrentlyUsedRoutingBuffers 	= uint16("currently_used_routing_buffers", "Currently Used Routing Buffers")
CurrentOpenFiles		= uint16("current_open_files", "Current Open Files")
CurrentReferenceID              = uint16("curr_ref_id", "Current Reference ID")
CurrentServers			= uint32("current_servers", "Current Servers")
CurrentServerTime		= uint32("current_server_time", "Time Elapsed Since Server Was Brought Up")
CurrentSpace			= uint32("current_space", "Current Space")
CurrentTransactionCount		= uint32("current_trans_count", "Current Transaction Count")
CurrentUsedBinderyObjects 	= uint16("current_used_bindery_objects", "Current Used Bindery Objects")
CurrentUsedDynamicSpace 	= uint32("current_used_dynamic_space", "Current Used Dynamic Space")
CustomCnts                      = uint32("custom_cnts", "Custom Counters")
CustomCount                     = uint32("custom_count", "Custom Count")
CustomCounters                  = uint32("custom_counters", "Custom Counters")
CustomString                    = nstring8("custom_string", "Custom String")
CustomVariableValue             = uint32("custom_var_value", "Custom Variable Value")

Data 				= nstring8("data", "Data")
DataForkFirstFAT		= uint32("data_fork_first_fat", "Data Fork First FAT Entry")
DataForkLen			= uint32("data_fork_len", "Data Fork Len")
DataForkSize			= uint32("data_fork_size", "Data Fork Size")
DataSize			= uint32("data_size", "Data Size")
DataStream			= val_string8("data_stream", "Data Stream", [
	[ 0x00, "Resource Fork or DOS" ],
	[ 0x01, "Data Fork" ],
])
DataStreamName			= nstring8("data_stream_name", "Data Stream Name")
DataStreamNumber		= uint8("data_stream_number", "Data Stream Number")
DataStreamsCount		= uint32("data_streams_count", "Data Streams Count")
DataStreamSize			= uint32("data_stream_size", "Size")
DataStreamSpaceAlloc 		= uint32( "data_stream_space_alloc", "Space Allocated for Data Stream" )
Day 				= uint8("s_day", "Day")
DayOfWeek			= val_string8("s_day_of_week", "Day of Week", [
	[ 0x00, "Sunday" ],
	[ 0x01, "Monday" ],
	[ 0x02, "Tuesday" ],
	[ 0x03, "Wednesday" ],
	[ 0x04, "Thursday" ],
	[ 0x05, "Friday" ],
	[ 0x06, "Saturday" ],
])
DeadMirrorTable 		= bytes("dead_mirror_table", "Dead Mirror Table", 32)
DefinedDataStreams		= uint8("defined_data_streams", "Defined Data Streams")
DefinedNameSpaces		= uint8("defined_name_spaces", "Defined Name Spaces")
DeletedDate			= uint16("deleted_date", "Deleted Date")
DeletedDate.NWDate()
DeletedFileTime			= uint32( "deleted_file_time", "Deleted File Time")
DeletedFileTime.Display("BASE_HEX")
DeletedTime			= uint16("deleted_time", "Deleted Time")
DeletedTime.NWTime()
DeletedID			= uint32( "delete_id", "Deleted ID", BE)
DeletedID.Display("BASE_HEX")
DeleteExistingFileFlag		= val_string8("delete_existing_file_flag", "Delete Existing File Flag", [
	[ 0x00, "Do Not Delete Existing File" ],
	[ 0x01, "Delete Existing File" ],
])
DenyReadCount			= uint16("deny_read_count", "Deny Read Count")
DenyWriteCount			= uint16("deny_write_count", "Deny Write Count")
DescriptionStrings		= fw_string("description_string", "Description", 100)
DesiredAccessRights 		= bitfield16("desired_access_rights", "Desired Access Rights", [
        bf_boolean16(0x0001, "dsired_acc_rights_read_o", "Read Only"),
	bf_boolean16(0x0002, "dsired_acc_rights_write_o", "Write Only"),
	bf_boolean16(0x0004, "dsired_acc_rights_deny_r", "Deny Read"),
	bf_boolean16(0x0008, "dsired_acc_rights_deny_w", "Deny Write"),
	bf_boolean16(0x0010, "dsired_acc_rights_compat", "Compatibility"),
	bf_boolean16(0x0040, "dsired_acc_rights_w_thru", "File Write Through"),
	bf_boolean16(0x0400, "dsired_acc_rights_del_file_cls", "Delete File Close"),
])
DesiredResponseCount 		= uint16("desired_response_count", "Desired Response Count")
DestDirHandle			= uint8("dest_dir_handle", "Destination Directory Handle")
DestNameSpace 			= val_string8("dest_name_space", "Destination Name Space", [
	[ 0x00, "DOS Name Space" ],
	[ 0x01, "MAC Name Space" ],
	[ 0x02, "NFS Name Space" ],
	[ 0x04, "Long Name Space" ],
])
DestPathComponentCount		= uint8("dest_component_count", "Destination Path Component Count")
DestPath			= nstring8("dest_path", "Destination Path")
DetachDuringProcessing 		= uint16("detach_during_processing", "Detach During Processing")
DetachForBadConnectionNumber 	= uint16("detach_for_bad_connection_number", "Detach For Bad Connection Number")
DirHandle			= uint8("dir_handle", "Directory Handle")
DirHandleName			= uint8("dir_handle_name", "Handle Name")
DirHandleLong			= uint32("dir_handle_long", "Directory Handle")
DirectoryAccessRights           = uint8("directory_access_rights", "Directory Access Rights")
#
# XXX - what do the bits mean here?
#
DirectoryAttributes             = uint8("directory_attributes", "Directory Attributes")
DirectoryBase 			= uint32("dir_base", "Directory Base")
DirectoryBase.Display("BASE_HEX")
DirectoryCount			= uint16("dir_count", "Directory Count")
DirectoryEntryNumber	 	= uint32("directory_entry_number", "Directory Entry Number")
DirectoryEntryNumber.Display('BASE_HEX')
DirectoryEntryNumberWord 	= uint16("directory_entry_number_word", "Directory Entry Number")
DirectoryID			= uint16("directory_id", "Directory ID", BE)
DirectoryID.Display("BASE_HEX")
DirectoryName                   = fw_string("directory_name", "Directory Name",12)
DirectoryName14                 = fw_string("directory_name_14", "Directory Name", 14)
DirectoryNameLen                = uint8("directory_name_len", "Directory Name Length")
DirectoryNumber			= uint32("directory_number", "Directory Number")
DirectoryNumber.Display("BASE_HEX")
DirectoryPath			= fw_string("directory_path", "Directory Path", 16)
DirectoryServicesObjectID	= uint32("directory_services_object_id", "Directory Services Object ID")
DirectoryServicesObjectID.Display("BASE_HEX")
DirectoryStamp                  = uint16("directory_stamp", "Directory Stamp (0xD1D1)")
DirtyCacheBuffers 		= uint16("dirty_cache_buffers", "Dirty Cache Buffers")
DiskChannelNumber		= uint8("disk_channel_number", "Disk Channel Number")
DiskChannelTable 		= val_string8("disk_channel_table", "Disk Channel Table", [
	[ 0x01, "XT" ],
	[ 0x02, "AT" ],
	[ 0x03, "SCSI" ],
	[ 0x04, "Disk Coprocessor" ],
])
DiskSpaceLimit			= uint32("disk_space_limit", "Disk Space Limit")
DMAChannelsUsed 		= uint32("dma_channels_used", "DMA Channels Used")
DMInfoEntries 			= uint32("dm_info_entries", "DM Info Entries")
DMInfoLevel			= val_string8("dm_info_level", "DM Info Level", [
	[ 0x00, "Return Detailed DM Support Module Information" ],
	[ 0x01, "Return Number of DM Support Modules" ],
	[ 0x02, "Return DM Support Modules Names" ],
])
DMFlags				= val_string8("dm_flags", "DM Flags", [
	[ 0x00, "OnLine Media" ],
	[ 0x01, "OffLine Media" ],
])
DMmajorVersion			= uint32("dm_major_version", "DM Major Version")
DMminorVersion			= uint32("dm_minor_version", "DM Minor Version")
DMPresentFlag			= val_string8("dm_present_flag", "Data Migration Present Flag", [
	[ 0x00, "Data Migration NLM is not loaded" ],
	[ 0x01, "Data Migration NLM has been loaded and is running" ],
])
DOSDirectoryBase		= uint32("dos_directory_base", "DOS Directory Base")
DOSDirectoryBase.Display("BASE_HEX")
DOSDirectoryEntry		= uint32("dos_directory_entry", "DOS Directory Entry")
DOSDirectoryEntry.Display("BASE_HEX")
DOSDirectoryEntryNumber 	= uint32("dos_directory_entry_number", "DOS Directory Entry Number")
DOSDirectoryEntryNumber.Display('BASE_HEX')
DOSFileAttributes		= uint8("dos_file_attributes", "DOS File Attributes")
DOSParentDirectoryEntry		= uint32("dos_parent_directory_entry", "DOS Parent Directory Entry")
DOSParentDirectoryEntry.Display('BASE_HEX')
DOSSequence			= uint32("dos_sequence", "DOS Sequence")
DriveCylinders 			= uint16("drive_cylinders", "Drive Cylinders")
DriveDefinitionString 		= fw_string("drive_definition_string", "Drive Definition", 64)
DriveHeads 			= uint8("drive_heads", "Drive Heads")
DriveMappingTable		= bytes("drive_mapping_table", "Drive Mapping Table", 32)
DriveMirrorTable 		= bytes("drive_mirror_table", "Drive Mirror Table", 32)
DriverBoardName                 = stringz("driver_board_name", "Driver Board Name")
DriveRemovableFlag 		= val_string8("drive_removable_flag", "Drive Removable Flag", [
	[ 0x00, "Nonremovable" ],
	[ 0xff, "Removable" ],
])
DriverLogicalName               = stringz("driver_log_name", "Driver Logical Name")
DriverShortName                 = stringz("driver_short_name", "Driver Short Name")
DriveSize 			= uint32("drive_size", "Drive Size")
DstEAFlags			= val_string16("dst_ea_flags", "Destination EA Flags", [
	[ 0x0000, "Return EAHandle,Information Level 0" ],
	[ 0x0001, "Return NetWareHandle,Information Level 0" ],
	[ 0x0002, "Return Volume/Directory Number,Information Level 0" ],
	[ 0x0004, "Return EAHandle,Close Handle on Error,Information Level 0" ],
	[ 0x0005, "Return NetWareHandle,Close Handle on Error,Information Level 0" ],
	[ 0x0006, "Return Volume/Directory Number,Close Handle on Error,Information Level 0" ],
	[ 0x0010, "Return EAHandle,Information Level 1" ],
	[ 0x0011, "Return NetWareHandle,Information Level 1" ],
	[ 0x0012, "Return Volume/Directory Number,Information Level 1" ],
	[ 0x0014, "Return EAHandle,Close Handle on Error,Information Level 1" ],
	[ 0x0015, "Return NetWareHandle,Close Handle on Error,Information Level 1" ],
	[ 0x0016, "Return Volume/Directory Number,Close Handle on Error,Information Level 1" ],
	[ 0x0020, "Return EAHandle,Information Level 2" ],
	[ 0x0021, "Return NetWareHandle,Information Level 2" ],
	[ 0x0022, "Return Volume/Directory Number,Information Level 2" ],
	[ 0x0024, "Return EAHandle,Close Handle on Error,Information Level 2" ],
	[ 0x0025, "Return NetWareHandle,Close Handle on Error,Information Level 2" ],
	[ 0x0026, "Return Volume/Directory Number,Close Handle on Error,Information Level 2" ],
	[ 0x0030, "Return EAHandle,Information Level 3" ],
	[ 0x0031, "Return NetWareHandle,Information Level 3" ],
	[ 0x0032, "Return Volume/Directory Number,Information Level 3" ],
	[ 0x0034, "Return EAHandle,Close Handle on Error,Information Level 3" ],
	[ 0x0035, "Return NetWareHandle,Close Handle on Error,Information Level 3" ],
	[ 0x0036, "Return Volume/Directory Number,Close Handle on Error,Information Level 3" ],
	[ 0x0040, "Return EAHandle,Information Level 4" ],
	[ 0x0041, "Return NetWareHandle,Information Level 4" ],
	[ 0x0042, "Return Volume/Directory Number,Information Level 4" ],
	[ 0x0044, "Return EAHandle,Close Handle on Error,Information Level 4" ],
	[ 0x0045, "Return NetWareHandle,Close Handle on Error,Information Level 4" ],
	[ 0x0046, "Return Volume/Directory Number,Close Handle on Error,Information Level 4" ],
	[ 0x0050, "Return EAHandle,Information Level 5" ],
	[ 0x0051, "Return NetWareHandle,Information Level 5" ],
	[ 0x0052, "Return Volume/Directory Number,Information Level 5" ],
	[ 0x0054, "Return EAHandle,Close Handle on Error,Information Level 5" ],
	[ 0x0055, "Return NetWareHandle,Close Handle on Error,Information Level 5" ],
	[ 0x0056, "Return Volume/Directory Number,Close Handle on Error,Information Level 5" ],
	[ 0x0060, "Return EAHandle,Information Level 6" ],
	[ 0x0061, "Return NetWareHandle,Information Level 6" ],
	[ 0x0062, "Return Volume/Directory Number,Information Level 6" ],
	[ 0x0064, "Return EAHandle,Close Handle on Error,Information Level 6" ],
	[ 0x0065, "Return NetWareHandle,Close Handle on Error,Information Level 6" ],
	[ 0x0066, "Return Volume/Directory Number,Close Handle on Error,Information Level 6" ],
	[ 0x0070, "Return EAHandle,Information Level 7" ],
	[ 0x0071, "Return NetWareHandle,Information Level 7" ],
	[ 0x0072, "Return Volume/Directory Number,Information Level 7" ],
	[ 0x0074, "Return EAHandle,Close Handle on Error,Information Level 7" ],
	[ 0x0075, "Return NetWareHandle,Close Handle on Error,Information Level 7" ],
	[ 0x0076, "Return Volume/Directory Number,Close Handle on Error,Information Level 7" ],
	[ 0x0080, "Return EAHandle,Information Level 0,Immediate Close Handle" ],
	[ 0x0081, "Return NetWareHandle,Information Level 0,Immediate Close Handle" ],
	[ 0x0082, "Return Volume/Directory Number,Information Level 0,Immediate Close Handle" ],
	[ 0x0084, "Return EAHandle,Close Handle on Error,Information Level 0,Immediate Close Handle" ],
	[ 0x0085, "Return NetWareHandle,Close Handle on Error,Information Level 0,Immediate Close Handle" ],
	[ 0x0086, "Return Volume/Directory Number,Close Handle on Error,Information Level 0,Immediate Close Handle" ],
	[ 0x0090, "Return EAHandle,Information Level 1,Immediate Close Handle" ],
	[ 0x0091, "Return NetWareHandle,Information Level 1,Immediate Close Handle" ],
	[ 0x0092, "Return Volume/Directory Number,Information Level 1,Immediate Close Handle" ],
	[ 0x0094, "Return EAHandle,Close Handle on Error,Information Level 1,Immediate Close Handle" ],
	[ 0x0095, "Return NetWareHandle,Close Handle on Error,Information Level 1,Immediate Close Handle" ],
	[ 0x0096, "Return Volume/Directory Number,Close Handle on Error,Information Level 1,Immediate Close Handle" ],
	[ 0x00a0, "Return EAHandle,Information Level 2,Immediate Close Handle" ],
	[ 0x00a1, "Return NetWareHandle,Information Level 2,Immediate Close Handle" ],
	[ 0x00a2, "Return Volume/Directory Number,Information Level 2,Immediate Close Handle" ],
	[ 0x00a4, "Return EAHandle,Close Handle on Error,Information Level 2,Immediate Close Handle" ],
	[ 0x00a5, "Return NetWareHandle,Close Handle on Error,Information Level 2,Immediate Close Handle" ],
	[ 0x00a6, "Return Volume/Directory Number,Close Handle on Error,Information Level 2,Immediate Close Handle" ],
	[ 0x00b0, "Return EAHandle,Information Level 3,Immediate Close Handle" ],
	[ 0x00b1, "Return NetWareHandle,Information Level 3,Immediate Close Handle" ],
	[ 0x00b2, "Return Volume/Directory Number,Information Level 3,Immediate Close Handle" ],
	[ 0x00b4, "Return EAHandle,Close Handle on Error,Information Level 3,Immediate Close Handle" ],
	[ 0x00b5, "Return NetWareHandle,Close Handle on Error,Information Level 3,Immediate Close Handle" ],
	[ 0x00b6, "Return Volume/Directory Number,Close Handle on Error,Information Level 3,Immediate Close Handle" ],
	[ 0x00c0, "Return EAHandle,Information Level 4,Immediate Close Handle" ],
	[ 0x00c1, "Return NetWareHandle,Information Level 4,Immediate Close Handle" ],
	[ 0x00c2, "Return Volume/Directory Number,Information Level 4,Immediate Close Handle" ],
	[ 0x00c4, "Return EAHandle,Close Handle on Error,Information Level 4,Immediate Close Handle" ],
	[ 0x00c5, "Return NetWareHandle,Close Handle on Error,Information Level 4,Immediate Close Handle" ],
	[ 0x00c6, "Return Volume/Directory Number,Close Handle on Error,Information Level 4,Immediate Close Handle" ],
	[ 0x00d0, "Return EAHandle,Information Level 5,Immediate Close Handle" ],
	[ 0x00d1, "Return NetWareHandle,Information Level 5,Immediate Close Handle" ],
	[ 0x00d2, "Return Volume/Directory Number,Information Level 5,Immediate Close Handle" ],
	[ 0x00d4, "Return EAHandle,Close Handle on Error,Information Level 5,Immediate Close Handle" ],
	[ 0x00d5, "Return NetWareHandle,Close Handle on Error,Information Level 5,Immediate Close Handle" ],
	[ 0x00d6, "Return Volume/Directory Number,Close Handle on Error,Information Level 5,Immediate Close Handle" ],
	[ 0x00e0, "Return EAHandle,Information Level 6,Immediate Close Handle" ],
	[ 0x00e1, "Return NetWareHandle,Information Level 6,Immediate Close Handle" ],
	[ 0x00e2, "Return Volume/Directory Number,Information Level 6,Immediate Close Handle" ],
	[ 0x00e4, "Return EAHandle,Close Handle on Error,Information Level 6,Immediate Close Handle" ],
	[ 0x00e5, "Return NetWareHandle,Close Handle on Error,Information Level 6,Immediate Close Handle" ],
	[ 0x00e6, "Return Volume/Directory Number,Close Handle on Error,Information Level 6,Immediate Close Handle" ],
	[ 0x00f0, "Return EAHandle,Information Level 7,Immediate Close Handle" ],
	[ 0x00f1, "Return NetWareHandle,Information Level 7,Immediate Close Handle" ],
	[ 0x00f2, "Return Volume/Directory Number,Information Level 7,Immediate Close Handle" ],
	[ 0x00f4, "Return EAHandle,Close Handle on Error,Information Level 7,Immediate Close Handle" ],
	[ 0x00f5, "Return NetWareHandle,Close Handle on Error,Information Level 7,Immediate Close Handle" ],
	[ 0x00f6, "Return Volume/Directory Number,Close Handle on Error,Information Level 7,Immediate Close Handle" ],
])
dstNSIndicator			= val_string16("dst_ns_indicator", "Destination Name Space Indicator", [
	[ 0x0000, "Return Source Name Space Information" ],
	[ 0x0001, "Return Destination Name Space Information" ],
])
DstQueueID			= uint32("dst_queue_id", "Destination Queue ID")
DuplicateRepliesSent 		= uint16("duplicate_replies_sent", "Duplicate Replies Sent")

EAAccessFlag			= bitfield16("ea_access_flag", "EA Access Flag", [
	bf_boolean16(0x0001, "ea_permanent_memory", "Permanent Memory"),
	bf_boolean16(0x0002, "ea_deep_freeze", "Deep Freeze"),
	bf_boolean16(0x0004, "ea_in_progress", "In Progress"),
	bf_boolean16(0x0008, "ea_header_being_enlarged", "Header Being Enlarged"),
	bf_boolean16(0x0010, "ea_new_tally_used", "New Tally Used"),
	bf_boolean16(0x0020, "ea_tally_need_update", "Tally Need Update"),
	bf_boolean16(0x0040, "ea_score_card_present", "Score Card Present"),
	bf_boolean16(0x0080, "ea_need_bit_flag", "EA Need Bit Flag"),
	bf_boolean16(0x0100, "ea_write_privileges", "Write Privileges"),
	bf_boolean16(0x0200, "ea_read_privileges", "Read Privileges"),
	bf_boolean16(0x0400, "ea_delete_privileges", "Delete Privileges"),
	bf_boolean16(0x0800, "ea_system_ea_only", "System EA Only"),
	bf_boolean16(0x1000, "ea_write_in_progress", "Write In Progress"),
])
EABytesWritten 			= uint32("ea_bytes_written", "Bytes Written")
EACount				= uint32("ea_count", "Count")
EADataSize	 		= uint32("ea_data_size", "Data Size")
EADataSizeDuplicated 		= uint32("ea_data_size_duplicated", "Data Size Duplicated")
EADuplicateCount		= uint32("ea_duplicate_count", "Duplicate Count")
EAErrorCodes			= val_string16("ea_error_codes", "EA Error Codes", [
	[ 0x0000, "SUCCESSFUL" ],
	[ 0x00c8, "ERR_MISSING_EA_KEY" ],
	[ 0x00c9, "ERR_EA_NOT_FOUND" ],
	[ 0x00ca, "ERR_INVALID_EA_HANDLE_TYPE" ],
	[ 0x00cb, "ERR_EA_NO_KEY_NO_DATA" ],
	[ 0x00cc, "ERR_EA_NUMBER_MISMATCH" ],
	[ 0x00cd, "ERR_EXTENT_NUMBER_OUT_OF_RANGE" ],
	[ 0x00ce, "ERR_EA_BAD_DIR_NUM" ],
	[ 0x00cf, "ERR_INVALID_EA_HANDLE" ],
	[ 0x00d0, "ERR_EA_POSITION_OUT_OF_RANGE" ],
	[ 0x00d1, "ERR_EA_ACCESS_DENIED" ],
	[ 0x00d2, "ERR_DATA_PAGE_ODD_SIZE" ],
	[ 0x00d3, "ERR_EA_VOLUME_NOT_MOUNTED" ],
	[ 0x00d4, "ERR_BAD_PAGE_BOUNDARY" ],
	[ 0x00d5, "ERR_INSPECT_FAILURE" ],
	[ 0x00d6, "ERR_EA_ALREADY_CLAIMED" ],
	[ 0x00d7, "ERR_ODD_BUFFER_SIZE" ],
	[ 0x00d8, "ERR_NO_SCORECARDS" ],
	[ 0x00d9, "ERR_BAD_EDS_SIGNATURE" ],
	[ 0x00da, "ERR_EA_SPACE_LIMIT" ],
	[ 0x00db, "ERR_EA_KEY_CORRUPT" ],
	[ 0x00dc, "ERR_EA_KEY_LIMIT" ],
	[ 0x00dd, "ERR_TALLY_CORRUPT" ],
])
EAFlags				= val_string16("ea_flags", "EA Flags", [
	[ 0x0000, "Return EAHandle,Information Level 0" ],
	[ 0x0001, "Return NetWareHandle,Information Level 0" ],
	[ 0x0002, "Return Volume/Directory Number,Information Level 0" ],
	[ 0x0004, "Return EAHandle,Close Handle on Error,Information Level 0" ],
	[ 0x0005, "Return NetWareHandle,Close Handle on Error,Information Level 0" ],
	[ 0x0006, "Return Volume/Directory Number,Close Handle on Error,Information Level 0" ],
	[ 0x0010, "Return EAHandle,Information Level 1" ],
	[ 0x0011, "Return NetWareHandle,Information Level 1" ],
	[ 0x0012, "Return Volume/Directory Number,Information Level 1" ],
	[ 0x0014, "Return EAHandle,Close Handle on Error,Information Level 1" ],
	[ 0x0015, "Return NetWareHandle,Close Handle on Error,Information Level 1" ],
	[ 0x0016, "Return Volume/Directory Number,Close Handle on Error,Information Level 1" ],
	[ 0x0020, "Return EAHandle,Information Level 2" ],
	[ 0x0021, "Return NetWareHandle,Information Level 2" ],
	[ 0x0022, "Return Volume/Directory Number,Information Level 2" ],
	[ 0x0024, "Return EAHandle,Close Handle on Error,Information Level 2" ],
	[ 0x0025, "Return NetWareHandle,Close Handle on Error,Information Level 2" ],
	[ 0x0026, "Return Volume/Directory Number,Close Handle on Error,Information Level 2" ],
	[ 0x0030, "Return EAHandle,Information Level 3" ],
	[ 0x0031, "Return NetWareHandle,Information Level 3" ],
	[ 0x0032, "Return Volume/Directory Number,Information Level 3" ],
	[ 0x0034, "Return EAHandle,Close Handle on Error,Information Level 3" ],
	[ 0x0035, "Return NetWareHandle,Close Handle on Error,Information Level 3" ],
	[ 0x0036, "Return Volume/Directory Number,Close Handle on Error,Information Level 3" ],
	[ 0x0040, "Return EAHandle,Information Level 4" ],
	[ 0x0041, "Return NetWareHandle,Information Level 4" ],
	[ 0x0042, "Return Volume/Directory Number,Information Level 4" ],
	[ 0x0044, "Return EAHandle,Close Handle on Error,Information Level 4" ],
	[ 0x0045, "Return NetWareHandle,Close Handle on Error,Information Level 4" ],
	[ 0x0046, "Return Volume/Directory Number,Close Handle on Error,Information Level 4" ],
	[ 0x0050, "Return EAHandle,Information Level 5" ],
	[ 0x0051, "Return NetWareHandle,Information Level 5" ],
	[ 0x0052, "Return Volume/Directory Number,Information Level 5" ],
	[ 0x0054, "Return EAHandle,Close Handle on Error,Information Level 5" ],
	[ 0x0055, "Return NetWareHandle,Close Handle on Error,Information Level 5" ],
	[ 0x0056, "Return Volume/Directory Number,Close Handle on Error,Information Level 5" ],
	[ 0x0060, "Return EAHandle,Information Level 6" ],
	[ 0x0061, "Return NetWareHandle,Information Level 6" ],
	[ 0x0062, "Return Volume/Directory Number,Information Level 6" ],
	[ 0x0064, "Return EAHandle,Close Handle on Error,Information Level 6" ],
	[ 0x0065, "Return NetWareHandle,Close Handle on Error,Information Level 6" ],
	[ 0x0066, "Return Volume/Directory Number,Close Handle on Error,Information Level 6" ],
	[ 0x0070, "Return EAHandle,Information Level 7" ],
	[ 0x0071, "Return NetWareHandle,Information Level 7" ],
	[ 0x0072, "Return Volume/Directory Number,Information Level 7" ],
	[ 0x0074, "Return EAHandle,Close Handle on Error,Information Level 7" ],
	[ 0x0075, "Return NetWareHandle,Close Handle on Error,Information Level 7" ],
	[ 0x0076, "Return Volume/Directory Number,Close Handle on Error,Information Level 7" ],
	[ 0x0080, "Return EAHandle,Information Level 0,Immediate Close Handle" ],
	[ 0x0081, "Return NetWareHandle,Information Level 0,Immediate Close Handle" ],
	[ 0x0082, "Return Volume/Directory Number,Information Level 0,Immediate Close Handle" ],
	[ 0x0084, "Return EAHandle,Close Handle on Error,Information Level 0,Immediate Close Handle" ],
	[ 0x0085, "Return NetWareHandle,Close Handle on Error,Information Level 0,Immediate Close Handle" ],
	[ 0x0086, "Return Volume/Directory Number,Close Handle on Error,Information Level 0,Immediate Close Handle" ],
	[ 0x0090, "Return EAHandle,Information Level 1,Immediate Close Handle" ],
	[ 0x0091, "Return NetWareHandle,Information Level 1,Immediate Close Handle" ],
	[ 0x0092, "Return Volume/Directory Number,Information Level 1,Immediate Close Handle" ],
	[ 0x0094, "Return EAHandle,Close Handle on Error,Information Level 1,Immediate Close Handle" ],
	[ 0x0095, "Return NetWareHandle,Close Handle on Error,Information Level 1,Immediate Close Handle" ],
	[ 0x0096, "Return Volume/Directory Number,Close Handle on Error,Information Level 1,Immediate Close Handle" ],
	[ 0x00a0, "Return EAHandle,Information Level 2,Immediate Close Handle" ],
	[ 0x00a1, "Return NetWareHandle,Information Level 2,Immediate Close Handle" ],
	[ 0x00a2, "Return Volume/Directory Number,Information Level 2,Immediate Close Handle" ],
	[ 0x00a4, "Return EAHandle,Close Handle on Error,Information Level 2,Immediate Close Handle" ],
	[ 0x00a5, "Return NetWareHandle,Close Handle on Error,Information Level 2,Immediate Close Handle" ],
	[ 0x00a6, "Return Volume/Directory Number,Close Handle on Error,Information Level 2,Immediate Close Handle" ],
	[ 0x00b0, "Return EAHandle,Information Level 3,Immediate Close Handle" ],
	[ 0x00b1, "Return NetWareHandle,Information Level 3,Immediate Close Handle" ],
	[ 0x00b2, "Return Volume/Directory Number,Information Level 3,Immediate Close Handle" ],
	[ 0x00b4, "Return EAHandle,Close Handle on Error,Information Level 3,Immediate Close Handle" ],
	[ 0x00b5, "Return NetWareHandle,Close Handle on Error,Information Level 3,Immediate Close Handle" ],
	[ 0x00b6, "Return Volume/Directory Number,Close Handle on Error,Information Level 3,Immediate Close Handle" ],
	[ 0x00c0, "Return EAHandle,Information Level 4,Immediate Close Handle" ],
	[ 0x00c1, "Return NetWareHandle,Information Level 4,Immediate Close Handle" ],
	[ 0x00c2, "Return Volume/Directory Number,Information Level 4,Immediate Close Handle" ],
	[ 0x00c4, "Return EAHandle,Close Handle on Error,Information Level 4,Immediate Close Handle" ],
	[ 0x00c5, "Return NetWareHandle,Close Handle on Error,Information Level 4,Immediate Close Handle" ],
	[ 0x00c6, "Return Volume/Directory Number,Close Handle on Error,Information Level 4,Immediate Close Handle" ],
	[ 0x00d0, "Return EAHandle,Information Level 5,Immediate Close Handle" ],
	[ 0x00d1, "Return NetWareHandle,Information Level 5,Immediate Close Handle" ],
	[ 0x00d2, "Return Volume/Directory Number,Information Level 5,Immediate Close Handle" ],
	[ 0x00d4, "Return EAHandle,Close Handle on Error,Information Level 5,Immediate Close Handle" ],
	[ 0x00d5, "Return NetWareHandle,Close Handle on Error,Information Level 5,Immediate Close Handle" ],
	[ 0x00d6, "Return Volume/Directory Number,Close Handle on Error,Information Level 5,Immediate Close Handle" ],
	[ 0x00e0, "Return EAHandle,Information Level 6,Immediate Close Handle" ],
	[ 0x00e1, "Return NetWareHandle,Information Level 6,Immediate Close Handle" ],
	[ 0x00e2, "Return Volume/Directory Number,Information Level 6,Immediate Close Handle" ],
	[ 0x00e4, "Return EAHandle,Close Handle on Error,Information Level 6,Immediate Close Handle" ],
	[ 0x00e5, "Return NetWareHandle,Close Handle on Error,Information Level 6,Immediate Close Handle" ],
	[ 0x00e6, "Return Volume/Directory Number,Close Handle on Error,Information Level 6,Immediate Close Handle" ],
	[ 0x00f0, "Return EAHandle,Information Level 7,Immediate Close Handle" ],
	[ 0x00f1, "Return NetWareHandle,Information Level 7,Immediate Close Handle" ],
	[ 0x00f2, "Return Volume/Directory Number,Information Level 7,Immediate Close Handle" ],
	[ 0x00f4, "Return EAHandle,Close Handle on Error,Information Level 7,Immediate Close Handle" ],
	[ 0x00f5, "Return NetWareHandle,Close Handle on Error,Information Level 7,Immediate Close Handle" ],
	[ 0x00f6, "Return Volume/Directory Number,Close Handle on Error,Information Level 7,Immediate Close Handle" ],
])
EAHandle			= uint32("ea_handle", "EA Handle")
EAHandle.Display("BASE_HEX")
EAHandleOrNetWareHandleOrVolume	= uint32("ea_handle_or_netware_handle_or_volume", "EAHandle or NetWare Handle or Volume (see EAFlags)")
EAHandleOrNetWareHandleOrVolume.Display("BASE_HEX")
EAKey			        = nstring16("ea_key", "EA Key")
EAKeySize			= uint32("ea_key_size", "Key Size")
EAKeySizeDuplicated		= uint32("ea_key_size_duplicated", "Key Size Duplicated")
EAValue                         = nstring16("ea_value", "EA Value")
EAValueRep 			= fw_string("ea_value_rep", "EA Value", 1)
EAValueLength                   = uint16("ea_value_length", "Value Length")
EchoSocket			= uint16("echo_socket", "Echo Socket")
EchoSocket.Display('BASE_HEX')
EffectiveRights 		= bitfield8("effective_rights", "Effective Rights", [
	bf_boolean8(0x01, "effective_rights_read", "Read Rights"),
	bf_boolean8(0x02, "effective_rights_write", "Write Rights"),
	bf_boolean8(0x04, "effective_rights_open", "Open Rights"),
	bf_boolean8(0x08, "effective_rights_create", "Create Rights"),
	bf_boolean8(0x10, "effective_rights_delete", "Delete Rights"),
	bf_boolean8(0x20, "effective_rights_parental", "Parental Rights"),
	bf_boolean8(0x40, "effective_rights_search", "Search Rights"),
	bf_boolean8(0x80, "effective_rights_modify", "Modify Rights"),
])
EnumInfoMask  		        = bitfield8("enum_info_mask", "Return Information Mask", [
	bf_boolean8(0x01, "enum_info_transport", "Transport Information"),
	bf_boolean8(0x02, "enum_info_time", "Time Information"),
	bf_boolean8(0x04, "enum_info_name", "Name Information"),
	bf_boolean8(0x08, "enum_info_lock", "Lock Information"),
	bf_boolean8(0x10, "enum_info_print", "Print Information"),
	bf_boolean8(0x20, "enum_info_stats", "Statistical Information"),
	bf_boolean8(0x40, "enum_info_account", "Accounting Information"),
	bf_boolean8(0x80, "enum_info_auth", "Authentication Information"),
])

eventOffset 			= bytes("event_offset", "Event Offset", 8)
eventOffset.Display("BASE_HEX")
eventTime 			= uint32("event_time", "Event Time")
eventTime.Display("BASE_HEX")
ExpirationTime			= uint32("expiration_time", "Expiration Time")
ExpirationTime.Display('BASE_HEX')
ExtAttrDataSize 		= uint32("ext_attr_data_size", "Extended Attributes Data Size")
ExtAttrCount			= uint32("ext_attr_count", "Extended Attributes Count")
ExtAttrKeySize			= uint32("ext_attr_key_size", "Extended Attributes Key Size")
ExtendedAttributesDefined	= uint32("extended_attributes_defined", "Extended Attributes Defined")
ExtendedAttributeExtantsUsed	= uint32("extended_attribute_extants_used", "Extended Attribute Extants Used")
ExtendedInfo	 	        = bitfield16("ext_info", "Extended Return Information", [
	bf_boolean16(0x0001, "ext_info_update", "Update"),
	bf_boolean16(0x0002, "ext_info_dos_name", "DOS Name"),
	bf_boolean16(0x0004, "ext_info_flush", "Flush"),
	bf_boolean16(0x0008, "ext_info_parental", "Parental"),
	bf_boolean16(0x0010, "ext_info_mac_finder", "MAC Finder"),
	bf_boolean16(0x0020, "ext_info_sibling", "Sibling"),
	bf_boolean16(0x0040, "ext_info_effective", "Effective"),
	bf_boolean16(0x0080, "ext_info_mac_date", "MAC Date"),
	bf_boolean16(0x0100, "ext_info_access", "Last Access"),
	bf_boolean16(0x0400, "ext_info_64_bit_fs", "64 Bit File Sizes"),
	bf_boolean16(0x8000, "ext_info_newstyle", "New Style"),
])
ExtRouterActiveFlag             = boolean8("ext_router_active_flag", "External Router Active Flag")

FailedAllocReqCnt		= uint32("failed_alloc_req", "Failed Alloc Request Count")
FatalFATWriteErrors		= uint16("fatal_fat_write_errors", "Fatal FAT Write Errors")
FATScanErrors			= uint16("fat_scan_errors", "FAT Scan Errors")
FATWriteErrors			= uint16("fat_write_errors", "FAT Write Errors")
FieldsLenTable			= bytes("fields_len_table", "Fields Len Table", 32)
FileCount			= uint16("file_count", "File Count")
FileDate			= uint16("file_date", "File Date")
FileDate.NWDate()
FileDirWindow			= uint16("file_dir_win", "File/Dir Window")
FileDirWindow.Display("BASE_HEX")
FileExecuteType 		= uint8("file_execute_type", "File Execute Type")
FileExtendedAttributes 		= val_string8("file_ext_attr", "File Extended Attributes", [
	[ 0x00, "Search On All Read Only Opens" ],
	[ 0x01, "Search On Read Only Opens With No Path" ],
	[ 0x02, "Shell Default Search Mode" ],
	[ 0x03, "Search On All Opens With No Path" ],
	[ 0x04, "Do Not Search" ],
	[ 0x05, "Reserved" ],
	[ 0x06, "Search On All Opens" ],
	[ 0x07, "Reserved" ],
	[ 0x08, "Search On All Read Only Opens/Indexed" ],
	[ 0x09, "Search On Read Only Opens With No Path/Indexed" ],
	[ 0x0a, "Shell Default Search Mode/Indexed" ],
	[ 0x0b, "Search On All Opens With No Path/Indexed" ],
	[ 0x0c, "Do Not Search/Indexed" ],
	[ 0x0d, "Indexed" ],
	[ 0x0e, "Search On All Opens/Indexed" ],
	[ 0x0f, "Indexed" ],
	[ 0x10, "Search On All Read Only Opens/Transactional" ],
	[ 0x11, "Search On Read Only Opens With No Path/Transactional" ],
	[ 0x12, "Shell Default Search Mode/Transactional" ],
	[ 0x13, "Search On All Opens With No Path/Transactional" ],
	[ 0x14, "Do Not Search/Transactional" ],
	[ 0x15, "Transactional" ],
	[ 0x16, "Search On All Opens/Transactional" ],
	[ 0x17, "Transactional" ],
	[ 0x18, "Search On All Read Only Opens/Indexed/Transactional" ],
	[ 0x19, "Search On Read Only Opens With No Path/Indexed/Transactional" ],
	[ 0x1a, "Shell Default Search Mode/Indexed/Transactional" ],
	[ 0x1b, "Search On All Opens With No Path/Indexed/Transactional" ],
	[ 0x1c, "Do Not Search/Indexed/Transactional" ],
	[ 0x1d, "Indexed/Transactional" ],
	[ 0x1e, "Search On All Opens/Indexed/Transactional" ],
	[ 0x1f, "Indexed/Transactional" ],
	[ 0x40, "Search On All Read Only Opens/Read Audit" ],
	[ 0x41, "Search On Read Only Opens With No Path/Read Audit" ],
	[ 0x42, "Shell Default Search Mode/Read Audit" ],
	[ 0x43, "Search On All Opens With No Path/Read Audit" ],
	[ 0x44, "Do Not Search/Read Audit" ],
	[ 0x45, "Read Audit" ],
	[ 0x46, "Search On All Opens/Read Audit" ],
	[ 0x47, "Read Audit" ],
	[ 0x48, "Search On All Read Only Opens/Indexed/Read Audit" ],
	[ 0x49, "Search On Read Only Opens With No Path/Indexed/Read Audit" ],
	[ 0x4a, "Shell Default Search Mode/Indexed/Read Audit" ],
	[ 0x4b, "Search On All Opens With No Path/Indexed/Read Audit" ],
	[ 0x4c, "Do Not Search/Indexed/Read Audit" ],
	[ 0x4d, "Indexed/Read Audit" ],
	[ 0x4e, "Search On All Opens/Indexed/Read Audit" ],
	[ 0x4f, "Indexed/Read Audit" ],
	[ 0x50, "Search On All Read Only Opens/Transactional/Read Audit" ],
	[ 0x51, "Search On Read Only Opens With No Path/Transactional/Read Audit" ],
	[ 0x52, "Shell Default Search Mode/Transactional/Read Audit" ],
	[ 0x53, "Search On All Opens With No Path/Transactional/Read Audit" ],
	[ 0x54, "Do Not Search/Transactional/Read Audit" ],
	[ 0x55, "Transactional/Read Audit" ],
	[ 0x56, "Search On All Opens/Transactional/Read Audit" ],
	[ 0x57, "Transactional/Read Audit" ],
	[ 0x58, "Search On All Read Only Opens/Indexed/Transactional/Read Audit" ],
	[ 0x59, "Search On Read Only Opens With No Path/Indexed/Transactional/Read Audit" ],
	[ 0x5a, "Shell Default Search Mode/Indexed/Transactional/Read Audit" ],
	[ 0x5b, "Search On All Opens With No Path/Indexed/Transactional/Read Audit" ],
	[ 0x5c, "Do Not Search/Indexed/Transactional/Read Audit" ],
	[ 0x5d, "Indexed/Transactional/Read Audit" ],
	[ 0x5e, "Search On All Opens/Indexed/Transactional/Read Audit" ],
	[ 0x5f, "Indexed/Transactional/Read Audit" ],
	[ 0x80, "Search On All Read Only Opens/Write Audit" ],
	[ 0x81, "Search On Read Only Opens With No Path/Write Audit" ],
	[ 0x82, "Shell Default Search Mode/Write Audit" ],
	[ 0x83, "Search On All Opens With No Path/Write Audit" ],
	[ 0x84, "Do Not Search/Write Audit" ],
	[ 0x85, "Write Audit" ],
	[ 0x86, "Search On All Opens/Write Audit" ],
	[ 0x87, "Write Audit" ],
	[ 0x88, "Search On All Read Only Opens/Indexed/Write Audit" ],
	[ 0x89, "Search On Read Only Opens With No Path/Indexed/Write Audit" ],
	[ 0x8a, "Shell Default Search Mode/Indexed/Write Audit" ],
	[ 0x8b, "Search On All Opens With No Path/Indexed/Write Audit" ],
	[ 0x8c, "Do Not Search/Indexed/Write Audit" ],
	[ 0x8d, "Indexed/Write Audit" ],
	[ 0x8e, "Search On All Opens/Indexed/Write Audit" ],
	[ 0x8f, "Indexed/Write Audit" ],
	[ 0x90, "Search On All Read Only Opens/Transactional/Write Audit" ],
	[ 0x91, "Search On Read Only Opens With No Path/Transactional/Write Audit" ],
	[ 0x92, "Shell Default Search Mode/Transactional/Write Audit" ],
	[ 0x93, "Search On All Opens With No Path/Transactional/Write Audit" ],
	[ 0x94, "Do Not Search/Transactional/Write Audit" ],
	[ 0x95, "Transactional/Write Audit" ],
	[ 0x96, "Search On All Opens/Transactional/Write Audit" ],
	[ 0x97, "Transactional/Write Audit" ],
	[ 0x98, "Search On All Read Only Opens/Indexed/Transactional/Write Audit" ],
	[ 0x99, "Search On Read Only Opens With No Path/Indexed/Transactional/Write Audit" ],
	[ 0x9a, "Shell Default Search Mode/Indexed/Transactional/Write Audit" ],
	[ 0x9b, "Search On All Opens With No Path/Indexed/Transactional/Write Audit" ],
	[ 0x9c, "Do Not Search/Indexed/Transactional/Write Audit" ],
	[ 0x9d, "Indexed/Transactional/Write Audit" ],
	[ 0x9e, "Search On All Opens/Indexed/Transactional/Write Audit" ],
	[ 0x9f, "Indexed/Transactional/Write Audit" ],
	[ 0xa0, "Search On All Read Only Opens/Read Audit/Write Audit" ],
	[ 0xa1, "Search On Read Only Opens With No Path/Read Audit/Write Audit" ],
	[ 0xa2, "Shell Default Search Mode/Read Audit/Write Audit" ],
	[ 0xa3, "Search On All Opens With No Path/Read Audit/Write Audit" ],
	[ 0xa4, "Do Not Search/Read Audit/Write Audit" ],
	[ 0xa5, "Read Audit/Write Audit" ],
	[ 0xa6, "Search On All Opens/Read Audit/Write Audit" ],
	[ 0xa7, "Read Audit/Write Audit" ],
	[ 0xa8, "Search On All Read Only Opens/Indexed/Read Audit/Write Audit" ],
	[ 0xa9, "Search On Read Only Opens With No Path/Indexed/Read Audit/Write Audit" ],
	[ 0xaa, "Shell Default Search Mode/Indexed/Read Audit/Write Audit" ],
	[ 0xab, "Search On All Opens With No Path/Indexed/Read Audit/Write Audit" ],
	[ 0xac, "Do Not Search/Indexed/Read Audit/Write Audit" ],
	[ 0xad, "Indexed/Read Audit/Write Audit" ],
	[ 0xae, "Search On All Opens/Indexed/Read Audit/Write Audit" ],
	[ 0xaf, "Indexed/Read Audit/Write Audit" ],
	[ 0xb0, "Search On All Read Only Opens/Transactional/Read Audit/Write Audit" ],
	[ 0xb1, "Search On Read Only Opens With No Path/Transactional/Read Audit/Write Audit" ],
	[ 0xb2, "Shell Default Search Mode/Transactional/Read Audit/Write Audit" ],
	[ 0xb3, "Search On All Opens With No Path/Transactional/Read Audit/Write Audit" ],
	[ 0xb4, "Do Not Search/Transactional/Read Audit/Write Audit" ],
	[ 0xb5, "Transactional/Read Audit/Write Audit" ],
	[ 0xb6, "Search On All Opens/Transactional/Read Audit/Write Audit" ],
	[ 0xb7, "Transactional/Read Audit/Write Audit" ],
	[ 0xb8, "Search On All Read Only Opens/Indexed/Transactional/Read Audit/Write Audit" ],
	[ 0xb9, "Search On Read Only Opens With No Path/Indexed/Transactional/Read Audit/Write Audit" ],
	[ 0xba, "Shell Default Search Mode/Indexed/Transactional/Read Audit/Write Audit" ],
	[ 0xbb, "Search On All Opens With No Path/Indexed/Transactional/Read Audit/Write Audit" ],
	[ 0xbc, "Do Not Search/Indexed/Transactional/Read Audit/Write Audit" ],
	[ 0xbd, "Indexed/Transactional/Read Audit/Write Audit" ],
	[ 0xbe, "Search On All Opens/Indexed/Transactional/Read Audit/Write Audit" ],
	[ 0xbf, "Indexed/Transactional/Read Audit/Write Audit" ],
])
fileFlags                       = uint32("file_flags", "File Flags")
FileHandle			= bytes("file_handle", "File Handle", 6)
FileLimbo 			= uint32("file_limbo", "File Limbo")
FileListCount                   = uint32("file_list_count", "File List Count")
FileLock			= val_string8("file_lock", "File Lock", [
	[ 0x00, "Not Locked" ],
	[ 0xfe, "Locked by file lock" ],
	[ 0xff, "Unknown" ],
])
FileLockCount			= uint16("file_lock_count", "File Lock Count")
FileMode			= uint8("file_mode", "File Mode")
FileName			= nstring8("file_name", "Filename")
FileName12			= fw_string("file_name_12", "Filename", 12)
FileName14			= fw_string("file_name_14", "Filename", 14)
FileNameLen			= uint8("file_name_len", "Filename Length")
FileOffset			= uint32("file_offset", "File Offset")
FilePath			= nstring8("file_path", "File Path")
FileSize			= uint32("file_size", "File Size", BE)
FileSize64bit       = bytes("f_size_64bit", "64bit File Size", 64)
FileSystemID			= uint8("file_system_id", "File System ID")
FileTime			= uint16("file_time", "File Time")
FileTime.NWTime()
FileWriteFlags			= val_string8("file_write_flags", "File Write Flags", [
	[ 0x01, "Writing" ],
	[ 0x02, "Write aborted" ],
])
FileWriteState			= val_string8("file_write_state", "File Write State", [
	[ 0x00, "Not Writing" ],
	[ 0x01, "Write in Progress" ],
	[ 0x02, "Write Being Stopped" ],
])
Filler				= uint8("filler", "Filler")
FinderAttr			= bitfield16("finder_attr", "Finder Info Attributes", [
	bf_boolean16(0x0001, "finder_attr_desktop", "Object on Desktop"),
	bf_boolean16(0x2000, "finder_attr_invisible", "Object is Invisible"),
	bf_boolean16(0x4000, "finder_attr_bundle", "Object Has Bundle"),
])
FixedBitMask 			= uint32("fixed_bit_mask", "Fixed Bit Mask")
FixedBitsDefined 		= uint16("fixed_bits_defined", "Fixed Bits Defined")
FlagBits 			= uint8("flag_bits", "Flag Bits")
Flags                           = uint8("flags", "Flags")
FlagsDef			= uint16("flags_def", "Flags")
FlushTime                       = uint32("flush_time", "Flush Time")
FolderFlag			= val_string8("folder_flag", "Folder Flag", [
	[ 0x00, "Not a Folder" ],
	[ 0x01, "Folder" ],
])
ForkCount			= uint8("fork_count", "Fork Count")
ForkIndicator			= val_string8("fork_indicator", "Fork Indicator", [
	[ 0x00, "Data Fork" ],
	[ 0x01, "Resource Fork" ],
])
ForceFlag			= val_string8("force_flag", "Force Server Down Flag", [
	[ 0x00, "Down Server if No Files Are Open" ],
	[ 0xff, "Down Server Immediately, Auto-Close Open Files" ],
])
ForgedDetachedRequests 		= uint16("forged_detached_requests", "Forged Detached Requests")
FormType			= uint16( "form_type", "Form Type" )
FormTypeCnt			= uint32("form_type_count", "Form Types Count")
FoundSomeMem			= uint32("found_some_mem", "Found Some Memory")
FractionalSeconds               = uint32("fractional_time", "Fractional Time in Seconds")
FraggerHandle			= uint32("fragger_handle", "Fragment Handle")
FraggerHandle.Display('BASE_HEX')
FragmentWriteOccurred		= uint16("fragment_write_occurred", "Fragment Write Occurred")
FragSize			= uint32("frag_size", "Fragment Size")
FreeableLimboSectors		= uint32("freeable_limbo_sectors", "Freeable Limbo Sectors")
FreeBlocks			= uint32("free_blocks", "Free Blocks")
FreedClusters			= uint32("freed_clusters", "Freed Clusters")
FreeDirectoryEntries 		= uint16("free_directory_entries", "Free Directory Entries")
FSEngineFlag			= boolean8("fs_engine_flag", "FS Engine Flag")
FullName			= fw_string("full_name", "Full Name", 39)

GetSetFlag			= val_string8("get_set_flag", "Get Set Flag", [
	[ 0x00, "Get the default support module ID" ],
	[ 0x01, "Set the default support module ID" ],
])
GUID				= bytes("guid", "GUID", 16)
GUID.Display("BASE_HEX")

HandleFlag			= val_string8("handle_flag", "Handle Flag", [
	[ 0x00, "Short Directory Handle" ],
	[ 0x01, "Directory Base" ],
	[ 0xFF, "No Handle Present" ],
])
HandleInfoLevel			= val_string8("handle_info_level", "Handle Info Level", [
	[ 0x00, "Get Limited Information from a File Handle" ],
	[ 0x01, "Get Limited Information from a File Handle Using a Name Space" ],
	[ 0x02, "Get Information from a File Handle" ],
	[ 0x03, "Get Information from a Directory Handle" ],
	[ 0x04, "Get Complete Information from a Directory Handle" ],
	[ 0x05, "Get Complete Information from a File Handle" ],
])
HeldBytesRead 			= bytes("held_bytes_read", "Held Bytes Read", 6)
HeldBytesWritten		= bytes("held_bytes_write", "Held Bytes Written", 6)
HeldConnectTimeInMinutes        = uint32("held_conn_time", "Held Connect Time in Minutes")
HeldRequests			= uint32("user_info_held_req", "Held Requests")
HoldAmount			= uint32("hold_amount", "Hold Amount")
HoldCancelAmount		= uint32("hold_cancel_amount", "Hold Cancel Amount")
HolderID			= uint32("holder_id", "Holder ID")
HolderID.Display("BASE_HEX")
HoldTime                        = uint32("hold_time", "Hold Time")
HopsToNet                       = uint16("hops_to_net", "Hop Count")
HorizLocation			= uint16("horiz_location", "Horizontal Location")
HostAddress			= bytes("host_address", "Host Address", 6)
HotFixBlocksAvailable 		= uint16("hot_fix_blocks_available", "Hot Fix Blocks Available")
HotFixDisabled			= val_string8("hot_fix_disabled", "Hot Fix Disabled", [
	[ 0x00, "Enabled" ],
	[ 0x01, "Disabled" ],
])
HotFixTableSize 		= uint16("hot_fix_table_size", "Hot Fix Table Size")
HotFixTableStart 		= uint32("hot_fix_table_start", "Hot Fix Table Start")
Hour				= uint8("s_hour", "Hour")
HugeBitMask 			= uint32("huge_bit_mask", "Huge Bit Mask")
HugeBitsDefined 		= uint16("huge_bits_defined", "Huge Bits Defined")
HugeData			= nstring8("huge_data", "Huge Data")
HugeDataUsed			= uint32("huge_data_used", "Huge Data Used")
HugeStateInfo			= bytes("huge_state_info", "Huge State Info", 16)

IdentificationNumber		= uint32("identification_number", "Identification Number")
IgnoredRxPkts                   = uint32("ignored_rx_pkts", "Ignored Receive Packets")
IncomingPacketDiscardedNoDGroup = uint16("incoming_packet_discarded_no_dgroup", "Incoming Packet Discarded No DGroup")
IndexNumber			= uint8("index_number", "Index Number")
InfoCount			= uint16("info_count", "Info Count")
InfoFlags			= bitfield32("info_flags", "Info Flags", [
	bf_boolean32(0x10000000, "info_flags_security", "Return Object Security"),
	bf_boolean32(0x20000000, "info_flags_flags", "Return Object Flags"),
	bf_boolean32(0x40000000, "info_flags_type", "Return Object Type"),
	bf_boolean32(0x80000000, "info_flags_name", "Return Object Name"),
])
InfoLevelNumber                 = val_string8("info_level_num", "Information Level Number", [
        [ 0x01, "Volume Information Definition" ],
        [ 0x02, "Volume Information 2 Definition" ],
])
InfoMask			= bitfield32("info_mask", "Information Mask", [
	bf_boolean32(0x00000001, "info_flags_dos_time", "DOS Time"),
	bf_boolean32(0x00000002, "info_flags_ref_count", "Reference Count"),
	bf_boolean32(0x00000004, "info_flags_dos_attr", "DOS Attributes"),
	bf_boolean32(0x00000008, "info_flags_ids", "ID's"),
	bf_boolean32(0x00000010, "info_flags_ds_sizes", "Data Stream Sizes"),
	bf_boolean32(0x00000020, "info_flags_ns_attr", "Name Space Attributes"),
	bf_boolean32(0x00000040, "info_flags_ea_present", "EA Present Flag"),
	bf_boolean32(0x00000080, "info_flags_all_attr", "All Attributes"),
	bf_boolean32(0x00000100, "info_flags_all_dirbase_num", "All Directory Base Numbers"),
	bf_boolean32(0x00000200, "info_flags_max_access_mask", "Maximum Access Mask"),
	bf_boolean32(0x00000400, "info_flags_flush_time", "Flush Time"),
	bf_boolean32(0x00000800, "info_flags_prnt_base_id", "Parent Base ID"),
	bf_boolean32(0x00001000, "info_flags_mac_finder", "Mac Finder Information"),
	bf_boolean32(0x00002000, "info_flags_sibling_cnt", "Sibling Count"),
	bf_boolean32(0x00004000, "info_flags_effect_rights", "Effective Rights"),
	bf_boolean32(0x00008000, "info_flags_mac_time", "Mac Time"),
	bf_boolean32(0x20000000, "info_mask_dosname", "DOS Name"),
	bf_boolean32(0x40000000, "info_mask_c_name_space", "Creator Name Space & Name"),
	bf_boolean32(0x80000000, "info_mask_name", "Name"),
])
InheritedRightsMask 		= bitfield16("inherited_rights_mask", "Inherited Rights Mask", [
        bf_boolean16(0x0001, "inh_rights_read", "Read Rights"),
	bf_boolean16(0x0002, "inh_rights_write", "Write Rights"),
	bf_boolean16(0x0004, "inh_rights_open", "Open Rights"),
	bf_boolean16(0x0008, "inh_rights_create", "Create Rights"),
	bf_boolean16(0x0010, "inh_rights_delete", "Delete Rights"),
	bf_boolean16(0x0020, "inh_rights_parent", "Change Access"),
	bf_boolean16(0x0040, "inh_rights_search", "See Files Flag"),
	bf_boolean16(0x0080, "inh_rights_modify", "Modify Rights"),
	bf_boolean16(0x0100, "inh_rights_supervisor", "Supervisor"),
])
InheritanceRevokeMask    	= bitfield16("inheritance_revoke_mask", "Revoke Rights Mask", [
	bf_boolean16(0x0001, "inh_revoke_read", "Read Rights"),
	bf_boolean16(0x0002, "inh_revoke_write", "Write Rights"),
	bf_boolean16(0x0004, "inh_revoke_open", "Open Rights"),
	bf_boolean16(0x0008, "inh_revoke_create", "Create Rights"),
	bf_boolean16(0x0010, "inh_revoke_delete", "Delete Rights"),
	bf_boolean16(0x0020, "inh_revoke_parent", "Change Access"),
	bf_boolean16(0x0040, "inh_revoke_search", "See Files Flag"),
	bf_boolean16(0x0080, "inh_revoke_modify", "Modify Rights"),
	bf_boolean16(0x0100, "inh_revoke_supervisor", "Supervisor"),
])
InitialSemaphoreValue		= uint8("initial_semaphore_value", "Initial Semaphore Value")
InspectSize			= uint32("inspect_size", "Inspect Size")
InternetBridgeVersion		= uint8("internet_bridge_version", "Internet Bridge Version")
InterruptNumbersUsed 		= uint32("interrupt_numbers_used", "Interrupt Numbers Used")
InUse				= uint32("in_use", "Bytes in Use")
IOAddressesUsed			= bytes("io_addresses_used", "IO Addresses Used", 8)
IOErrorCount			= uint16("io_error_count", "IO Error Count")
IOEngineFlag			= boolean8("io_engine_flag", "IO Engine Flag")
IPXNotMyNetwork 		= uint16("ipx_not_my_network", "IPX Not My Network")
ItemsChanged 			= uint32("items_changed", "Items Changed")
ItemsChecked 			= uint32("items_checked", "Items Checked")
ItemsCount			= uint32("items_count", "Items Count")
itemsInList                     = uint32("items_in_list", "Items in List")
ItemsInPacket			= uint32("items_in_packet", "Items in Packet")

JobControlFlags			= bitfield8("job_control_flags", "Job Control Flags", [
	bf_boolean8(0x08, "job_control_job_recovery", "Job Recovery"),
	bf_boolean8(0x10, "job_control_reservice", "ReService Job"),
	bf_boolean8(0x20, "job_control_file_open", "File Open"),
	bf_boolean8(0x40, "job_control_user_hold", "User Hold"),
	bf_boolean8(0x80, "job_control_operator_hold", "Operator Hold"),

])
JobControlFlagsWord		= bitfield16("job_control_flags_word", "Job Control Flags", [
	bf_boolean16(0x0008, "job_control1_job_recovery", "Job Recovery"),
	bf_boolean16(0x0010, "job_control1_reservice", "ReService Job"),
	bf_boolean16(0x0020, "job_control1_file_open", "File Open"),
	bf_boolean16(0x0040, "job_control1_user_hold", "User Hold"),
	bf_boolean16(0x0080, "job_control1_operator_hold", "Operator Hold"),

])
JobCount			= uint32("job_count", "Job Count")
JobFileHandle			= bytes("job_file_handle", "Job File Handle", 6)
JobFileHandleLong		= uint32("job_file_handle_long", "Job File Handle", BE)
JobFileHandleLong.Display("BASE_HEX")
JobFileName			= fw_string("job_file_name", "Job File Name", 14)
JobPosition			= uint8("job_position", "Job Position")
JobPositionWord			= uint16("job_position_word", "Job Position")
JobNumber			= uint16("job_number", "Job Number", BE )
JobNumberLong			= uint32("job_number_long", "Job Number", BE )
JobNumberLong.Display("BASE_HEX")
JobType				= uint16("job_type", "Job Type", BE )

LANCustomVariablesCount         = uint32("lan_cust_var_count", "LAN Custom Variables Count")
LANdriverBoardInstance          = uint16("lan_drv_bd_inst", "LAN Driver Board Instance")
LANdriverBoardNumber            = uint16("lan_drv_bd_num", "LAN Driver Board Number")
LANdriverCardID                 = uint16("lan_drv_card_id", "LAN Driver Card ID")
LANdriverCardName               = fw_string("lan_drv_card_name", "LAN Driver Card Name", 28)
LANdriverCFG_MajorVersion       = uint8("lan_dvr_cfg_major_vrs", "LAN Driver Config - Major Version")
LANdriverCFG_MinorVersion       = uint8("lan_dvr_cfg_minor_vrs", "LAN Driver Config - Minor Version")
LANdriverDMAUsage1              = uint8("lan_drv_dma_usage1", "Primary DMA Channel")
LANdriverDMAUsage2              = uint8("lan_drv_dma_usage2", "Secondary DMA Channel")
LANdriverFlags                  = uint16("lan_drv_flags", "LAN Driver Flags")
LANdriverFlags.Display("BASE_HEX")
LANdriverInterrupt1             = uint8("lan_drv_interrupt1", "Primary Interrupt Vector")
LANdriverInterrupt2             = uint8("lan_drv_interrupt2", "Secondary Interrupt Vector")
LANdriverIOPortsAndRanges1      = uint16("lan_drv_io_ports_and_ranges_1", "Primary Base I/O Port")
LANdriverIOPortsAndRanges2      = uint16("lan_drv_io_ports_and_ranges_2", "Number of I/O Ports")
LANdriverIOPortsAndRanges3      = uint16("lan_drv_io_ports_and_ranges_3", "Secondary Base I/O Port")
LANdriverIOPortsAndRanges4      = uint16("lan_drv_io_ports_and_ranges_4", "Number of I/O Ports")
LANdriverIOReserved             = bytes("lan_drv_io_reserved", "LAN Driver IO Reserved", 14)
LANdriverLineSpeed              = uint16("lan_drv_line_speed", "LAN Driver Line Speed")
LANdriverLink                   = uint32("lan_drv_link", "LAN Driver Link")
LANdriverLogicalName            = bytes("lan_drv_log_name", "LAN Driver Logical Name", 18)
LANdriverMajorVersion           = uint8("lan_drv_major_ver", "LAN Driver Major Version")
LANdriverMaximumSize            = uint32("lan_drv_max_size", "LAN Driver Maximum Size")
LANdriverMaxRecvSize            = uint32("lan_drv_max_rcv_size", "LAN Driver Maximum Receive Size")
LANdriverMediaID                = uint16("lan_drv_media_id", "LAN Driver Media ID")
LANdriverMediaType              = fw_string("lan_drv_media_type", "LAN Driver Media Type", 40)
LANdriverMemoryDecode0          = uint32("lan_drv_mem_decode_0", "LAN Driver Memory Decode 0")
LANdriverMemoryDecode1          = uint32("lan_drv_mem_decode_1", "LAN Driver Memory Decode 1")
LANdriverMemoryLength0          = uint16("lan_drv_mem_length_0", "LAN Driver Memory Length 0")
LANdriverMemoryLength1          = uint16("lan_drv_mem_length_1", "LAN Driver Memory Length 1")
LANdriverMinorVersion           = uint8("lan_drv_minor_ver", "LAN Driver Minor Version")
LANdriverModeFlags		= val_string8("lan_dvr_mode_flags", "LAN Driver Mode Flags", [
        [0x80, "Canonical Address" ],
        [0x81, "Canonical Address" ],
        [0x82, "Canonical Address" ],
        [0x83, "Canonical Address" ],
        [0x84, "Canonical Address" ],
        [0x85, "Canonical Address" ],
        [0x86, "Canonical Address" ],
        [0x87, "Canonical Address" ],
        [0x88, "Canonical Address" ],
        [0x89, "Canonical Address" ],
        [0x8a, "Canonical Address" ],
        [0x8b, "Canonical Address" ],
        [0x8c, "Canonical Address" ],
        [0x8d, "Canonical Address" ],
        [0x8e, "Canonical Address" ],
        [0x8f, "Canonical Address" ],
        [0x90, "Canonical Address" ],
        [0x91, "Canonical Address" ],
        [0x92, "Canonical Address" ],
        [0x93, "Canonical Address" ],
        [0x94, "Canonical Address" ],
        [0x95, "Canonical Address" ],
        [0x96, "Canonical Address" ],
        [0x97, "Canonical Address" ],
        [0x98, "Canonical Address" ],
        [0x99, "Canonical Address" ],
        [0x9a, "Canonical Address" ],
        [0x9b, "Canonical Address" ],
        [0x9c, "Canonical Address" ],
        [0x9d, "Canonical Address" ],
        [0x9e, "Canonical Address" ],
        [0x9f, "Canonical Address" ],
        [0xa0, "Canonical Address" ],
        [0xa1, "Canonical Address" ],
        [0xa2, "Canonical Address" ],
        [0xa3, "Canonical Address" ],
        [0xa4, "Canonical Address" ],
        [0xa5, "Canonical Address" ],
        [0xa6, "Canonical Address" ],
        [0xa7, "Canonical Address" ],
        [0xa8, "Canonical Address" ],
        [0xa9, "Canonical Address" ],
        [0xaa, "Canonical Address" ],
        [0xab, "Canonical Address" ],
        [0xac, "Canonical Address" ],
        [0xad, "Canonical Address" ],
        [0xae, "Canonical Address" ],
        [0xaf, "Canonical Address" ],
        [0xb0, "Canonical Address" ],
        [0xb1, "Canonical Address" ],
        [0xb2, "Canonical Address" ],
        [0xb3, "Canonical Address" ],
        [0xb4, "Canonical Address" ],
        [0xb5, "Canonical Address" ],
        [0xb6, "Canonical Address" ],
        [0xb7, "Canonical Address" ],
        [0xb8, "Canonical Address" ],
        [0xb9, "Canonical Address" ],
        [0xba, "Canonical Address" ],
        [0xbb, "Canonical Address" ],
        [0xbc, "Canonical Address" ],
        [0xbd, "Canonical Address" ],
        [0xbe, "Canonical Address" ],
        [0xbf, "Canonical Address" ],
        [0xc0, "Non-Canonical Address" ],
        [0xc1, "Non-Canonical Address" ],
        [0xc2, "Non-Canonical Address" ],
        [0xc3, "Non-Canonical Address" ],
        [0xc4, "Non-Canonical Address" ],
        [0xc5, "Non-Canonical Address" ],
        [0xc6, "Non-Canonical Address" ],
        [0xc7, "Non-Canonical Address" ],
        [0xc8, "Non-Canonical Address" ],
        [0xc9, "Non-Canonical Address" ],
        [0xca, "Non-Canonical Address" ],
        [0xcb, "Non-Canonical Address" ],
        [0xcc, "Non-Canonical Address" ],
        [0xcd, "Non-Canonical Address" ],
        [0xce, "Non-Canonical Address" ],
        [0xcf, "Non-Canonical Address" ],
        [0xd0, "Non-Canonical Address" ],
        [0xd1, "Non-Canonical Address" ],
        [0xd2, "Non-Canonical Address" ],
        [0xd3, "Non-Canonical Address" ],
        [0xd4, "Non-Canonical Address" ],
        [0xd5, "Non-Canonical Address" ],
        [0xd6, "Non-Canonical Address" ],
        [0xd7, "Non-Canonical Address" ],
        [0xd8, "Non-Canonical Address" ],
        [0xd9, "Non-Canonical Address" ],
        [0xda, "Non-Canonical Address" ],
        [0xdb, "Non-Canonical Address" ],
        [0xdc, "Non-Canonical Address" ],
        [0xdd, "Non-Canonical Address" ],
        [0xde, "Non-Canonical Address" ],
        [0xdf, "Non-Canonical Address" ],
        [0xe0, "Non-Canonical Address" ],
        [0xe1, "Non-Canonical Address" ],
        [0xe2, "Non-Canonical Address" ],
        [0xe3, "Non-Canonical Address" ],
        [0xe4, "Non-Canonical Address" ],
        [0xe5, "Non-Canonical Address" ],
        [0xe6, "Non-Canonical Address" ],
        [0xe7, "Non-Canonical Address" ],
        [0xe8, "Non-Canonical Address" ],
        [0xe9, "Non-Canonical Address" ],
        [0xea, "Non-Canonical Address" ],
        [0xeb, "Non-Canonical Address" ],
        [0xec, "Non-Canonical Address" ],
        [0xed, "Non-Canonical Address" ],
        [0xee, "Non-Canonical Address" ],
        [0xef, "Non-Canonical Address" ],
        [0xf0, "Non-Canonical Address" ],
        [0xf1, "Non-Canonical Address" ],
        [0xf2, "Non-Canonical Address" ],
        [0xf3, "Non-Canonical Address" ],
        [0xf4, "Non-Canonical Address" ],
        [0xf5, "Non-Canonical Address" ],
        [0xf6, "Non-Canonical Address" ],
        [0xf7, "Non-Canonical Address" ],
        [0xf8, "Non-Canonical Address" ],
        [0xf9, "Non-Canonical Address" ],
        [0xfa, "Non-Canonical Address" ],
        [0xfb, "Non-Canonical Address" ],
        [0xfc, "Non-Canonical Address" ],
        [0xfd, "Non-Canonical Address" ],
        [0xfe, "Non-Canonical Address" ],
        [0xff, "Non-Canonical Address" ],
])
LANDriverNumber			= uint8("lan_driver_number", "LAN Driver Number")
LANdriverNodeAddress            = bytes("lan_dvr_node_addr", "LAN Driver Node Address", 6)
LANdriverRecvSize               = uint32("lan_drv_rcv_size", "LAN Driver Receive Size")
LANdriverReserved               = uint16("lan_drv_reserved", "LAN Driver Reserved")
LANdriverSendRetries            = uint16("lan_drv_snd_retries", "LAN Driver Send Retries")
LANdriverSharingFlags           = uint16("lan_drv_share", "LAN Driver Sharing Flags")
LANdriverShortName              = fw_string("lan_drv_short_name", "LAN Driver Short Name", 40)
LANdriverSlot                   = uint16("lan_drv_slot", "LAN Driver Slot")
LANdriverSrcRouting             = uint32("lan_drv_src_route", "LAN Driver Source Routing")
LANdriverTransportTime          = uint16("lan_drv_trans_time", "LAN Driver Transport Time")
LastAccessedDate 		= uint16("last_access_date", "Last Accessed Date")
LastAccessedDate.NWDate()
LastAccessedTime 		= uint16("last_access_time", "Last Accessed Time")
LastAccessedTime.NWTime()
LastGarbCollect			= uint32("last_garbage_collect", "Last Garbage Collection")
LastInstance			= uint32("last_instance", "Last Instance")
LastRecordSeen			= uint16("last_record_seen", "Last Record Seen")
LastSearchIndex			= uint16("last_search_index", "Search Index")
LastSeen			= uint32("last_seen", "Last Seen")
LastSequenceNumber		= uint16("last_sequence_number", "Sequence Number")
Length64bit         = bytes("length_64bit", "64bit Length", 64)
Level				= uint8("level", "Level")
LFSCounters			= uint32("lfs_counters", "LFS Counters")
LimboDataStreamsCount		= uint32("limbo_data_streams_count", "Limbo Data Streams Count")
limbCount			= uint32("limb_count", "Limb Count")
LimboUsed			= uint32("limbo_used", "Limbo Used")
LoadedNameSpaces		= uint8("loaded_name_spaces", "Loaded Name Spaces")
LocalConnectionID 		= uint32("local_connection_id", "Local Connection ID")
LocalConnectionID.Display("BASE_HEX")
LocalMaxPacketSize 		= uint32("local_max_packet_size", "Local Max Packet Size")
LocalMaxSendSize 		= uint32("local_max_send_size", "Local Max Send Size")
LocalMaxRecvSize 		= uint32("local_max_recv_size", "Local Max Recv Size")
LocalLoginInfoCcode		= uint8("local_login_info_ccode", "Local Login Info C Code")
LocalTargetSocket 		= uint32("local_target_socket", "Local Target Socket")
LocalTargetSocket.Display("BASE_HEX")
LockAreaLen 			= uint32("lock_area_len", "Lock Area Length")
LockAreasStartOffset		= uint32("lock_areas_start_offset", "Lock Areas Start Offset")
LockTimeout 			= uint16("lock_timeout", "Lock Timeout")
Locked				= val_string8("locked", "Locked Flag", [
	[ 0x00, "Not Locked Exclusively" ],
	[ 0x01, "Locked Exclusively" ],
])
LockFlag			= val_string8("lock_flag", "Lock Flag", [
	[ 0x00, "Not Locked, Log for Future Exclusive Lock" ],
	[ 0x01, "Exclusive Lock (Read/Write)" ],
	[ 0x02, "Log for Future Shared Lock"],
	[ 0x03, "Shareable Lock (Read-Only)" ],
	[ 0xfe, "Locked by a File Lock" ],
	[ 0xff, "Locked by Begin Share File Set" ],
])
LockName			= nstring8("lock_name", "Lock Name")
LockStatus			= val_string8("lock_status", "Lock Status", [
	[ 0x00, "Locked Exclusive" ],
	[ 0x01, "Locked Shareable" ],
	[ 0x02, "Logged" ],
	[ 0x06, "Lock is Held by TTS"],
])
LockType 			= val_string8("lock_type", "Lock Type", [
	[ 0x00, "Locked" ],
	[ 0x01, "Open Shareable" ],
	[ 0x02, "Logged" ],
	[ 0x03, "Open Normal" ],
	[ 0x06, "TTS Holding Lock" ],
	[ 0x07, "Transaction Flag Set on This File" ],
])
LogFileFlagHigh			= bitfield8("log_file_flag_high", "Log File Flag (byte 2)", [
	bf_boolean8(0x80, "log_flag_call_back", "Call Back Requested" ),
])
LogFileFlagLow 			= bitfield8("log_file_flag_low", "Log File Flag", [
	bf_boolean8(0x01, "log_flag_lock_file", "Lock File Immediately" ),
])
LoggedObjectID			= uint32("logged_object_id", "Logged in Object ID")
LoggedObjectID.Display("BASE_HEX")
LoggedCount			= uint16("logged_count", "Logged Count")
LogicalConnectionNumber		= uint16("logical_connection_number", "Logical Connection Number", BE)
LogicalDriveCount		= uint8("logical_drive_count", "Logical Drive Count")
LogicalDriveNumber 		= uint8("logical_drive_number", "Logical Drive Number")
LogicalLockThreshold		= uint8("logical_lock_threshold", "LogicalLockThreshold")
LogicalRecordName		= nstring8("logical_record_name", "Logical Record Name")
LoginKey			= bytes("login_key", "Login Key", 8)
LogLockType			= uint8("log_lock_type", "Log Lock Type")
LogTtlRxPkts                    = uint32("log_ttl_rx_pkts", "Total Received Packets")
LogTtlTxPkts                    = uint32("log_ttl_tx_pkts", "Total Transmitted Packets")
LongName 			= fw_string("long_name", "Long Name", 32)
LRUBlockWasDirty		= uint16("lru_block_was_dirty", "LRU Block Was Dirty")

MacAttr 			= bitfield16("mac_attr", "Attributes", [
	bf_boolean16(0x0001, "mac_attr_smode1", "Search Mode"),
	bf_boolean16(0x0002, "mac_attr_smode2", "Search Mode"),
	bf_boolean16(0x0004, "mac_attr_smode3", "Search Mode"),
	bf_boolean16(0x0010, "mac_attr_transaction", "Transaction"),
	bf_boolean16(0x0020, "mac_attr_index", "Index"),
	bf_boolean16(0x0040, "mac_attr_r_audit", "Read Audit"),
	bf_boolean16(0x0080, "mac_attr_w_audit", "Write Audit"),
	bf_boolean16(0x0100, "mac_attr_r_only", "Read Only"),
	bf_boolean16(0x0200, "mac_attr_hidden", "Hidden"),
	bf_boolean16(0x0400, "mac_attr_system", "System"),
	bf_boolean16(0x0800, "mac_attr_execute_only", "Execute Only"),
	bf_boolean16(0x1000, "mac_attr_subdirectory", "Subdirectory"),
	bf_boolean16(0x2000, "mac_attr_archive", "Archive"),
	bf_boolean16(0x8000, "mac_attr_share", "Shareable File"),
])
MACBackupDate                   = uint16("mac_backup_date", "Mac Backup Date")
MACBackupDate.NWDate()
MACBackupTime                   = uint16("mac_backup_time", "Mac Backup Time")
MACBackupTime.NWTime()
MacBaseDirectoryID 		= uint32("mac_base_directory_id", "Mac Base Directory ID", BE)
MacBaseDirectoryID.Display("BASE_HEX")
MACCreateDate                   = uint16("mac_create_date", "Mac Create Date")
MACCreateDate.NWDate()
MACCreateTime                   = uint16("mac_create_time", "Mac Create Time")
MACCreateTime.NWTime()
MacDestinationBaseID 		= uint32("mac_destination_base_id", "Mac Destination Base ID")
MacDestinationBaseID.Display("BASE_HEX")
MacFinderInfo                   = bytes("mac_finder_info", "Mac Finder Information", 32)
MacLastSeenID			= uint32("mac_last_seen_id", "Mac Last Seen ID")
MacLastSeenID.Display("BASE_HEX")
MacSourceBaseID			= uint32("mac_source_base_id", "Mac Source Base ID")
MacSourceBaseID.Display("BASE_HEX")
MajorVersion			= uint32("major_version", "Major Version")
MaxBytes			= uint16("max_bytes", "Maximum Number of Bytes")
MaxDataStreams			= uint32("max_data_streams", "Maximum Data Streams")
MaxDirDepth			= uint32("max_dir_depth", "Maximum Directory Depth")
MaximumSpace			= uint16("max_space", "Maximum Space")
MaxNumOfConn			= uint32("max_num_of_conn", "Maximum Number of Connections")
MaxNumOfLANS			= uint32("max_num_of_lans", "Maximum Number Of LAN's")
MaxNumOfMedias			= uint32("max_num_of_medias", "Maximum Number Of Media's")
MaxNumOfNmeSps			= uint32("max_num_of_nme_sps", "Maximum Number Of Name Spaces")
MaxNumOfSpoolPr			= uint32("max_num_of_spool_pr", "Maximum Number Of Spool Printers")
MaxNumOfStacks			= uint32("max_num_of_stacks", "Maximum Number Of Stacks")
MaxNumOfUsers			= uint32("max_num_of_users", "Maximum Number Of Users")
MaxNumOfVol			= uint32("max_num_of_vol", "Maximum Number of Volumes")
MaxSpace			= uint32("maxspace", "Maximum Space")
MaxUsedDynamicSpace 		= uint32("max_used_dynamic_space", "Max Used Dynamic Space")
MediaList                       = uint32("media_list", "Media List")
MediaListCount                  = uint32("media_list_count", "Media List Count")
MediaName                       = nstring8("media_name", "Media Name")
MediaNumber                     = uint32("media_number", "Media Number")
MediaObjectType                 = val_string8("media_object_type", "Object Type", [
        [ 0x00, "Adapter" ],
        [ 0x01, "Changer" ],
        [ 0x02, "Removable Device" ],
        [ 0x03, "Device" ],
        [ 0x04, "Removable Media" ],
        [ 0x05, "Partition" ],
        [ 0x06, "Slot" ],
        [ 0x07, "Hotfix" ],
        [ 0x08, "Mirror" ],
        [ 0x09, "Parity" ],
        [ 0x0a, "Volume Segment" ],
        [ 0x0b, "Volume" ],
        [ 0x0c, "Clone" ],
        [ 0x0d, "Fixed Media" ],
        [ 0x0e, "Unknown" ],
])
MemberName			= nstring8("member_name", "Member Name")
MemberType			= val_string16("member_type", "Member Type", [
	[ 0x0000,	"Unknown" ],
	[ 0x0001,	"User" ],
	[ 0x0002,	"User group" ],
	[ 0x0003,	"Print queue" ],
	[ 0x0004,	"NetWare file server" ],
	[ 0x0005,	"Job server" ],
	[ 0x0006,	"Gateway" ],
	[ 0x0007,	"Print server" ],
	[ 0x0008,	"Archive queue" ],
	[ 0x0009,	"Archive server" ],
	[ 0x000a,	"Job queue" ],
	[ 0x000b,	"Administration" ],
	[ 0x0021,	"NAS SNA gateway" ],
	[ 0x0026,	"Remote bridge server" ],
	[ 0x0027,	"TCP/IP gateway" ],
])
MessageLanguage			= uint32("message_language", "NLM Language")
MigratedFiles			= uint32("migrated_files", "Migrated Files")
MigratedSectors			= uint32("migrated_sectors", "Migrated Sectors")
MinorVersion			= uint32("minor_version", "Minor Version")
Minute				= uint8("s_minute", "Minutes")
MixedModePathFlag		= val_string8("mixed_mode_path_flag", "Mixed Mode Path Flag", [
    [ 0x00, "Mixed mode path handling is not available"],
    [ 0x01, "Mixed mode path handling is available"],
])
ModifiedDate			= uint16("modified_date", "Modified Date")
ModifiedDate.NWDate()
ModifiedTime			= uint16("modified_time", "Modified Time")
ModifiedTime.NWTime()
ModifierID 			= uint32("modifier_id", "Modifier ID", BE)
ModifierID.Display("BASE_HEX")
ModifyDOSInfoMask		= bitfield16("modify_dos_info_mask", "Modify DOS Info Mask", [
	bf_boolean16(0x0002, "modify_dos_read", "Attributes"),
	bf_boolean16(0x0004, "modify_dos_write", "Creation Date"),
	bf_boolean16(0x0008, "modify_dos_open", "Creation Time"),
	bf_boolean16(0x0010, "modify_dos_create", "Creator ID"),
	bf_boolean16(0x0020, "modify_dos_delete", "Archive Date"),
	bf_boolean16(0x0040, "modify_dos_parent", "Archive Time"),
	bf_boolean16(0x0080, "modify_dos_search", "Archiver ID"),
	bf_boolean16(0x0100, "modify_dos_mdate", "Modify Date"),
	bf_boolean16(0x0200, "modify_dos_mtime", "Modify Time"),
	bf_boolean16(0x0400, "modify_dos_mid", "Modifier ID"),
	bf_boolean16(0x0800, "modify_dos_laccess", "Last Access"),
	bf_boolean16(0x1000, "modify_dos_inheritance", "Inheritance"),
	bf_boolean16(0x2000, "modify_dos_max_space", "Maximum Space"),
])
Month				= val_string8("s_month", "Month", [
	[ 0x01, "January"],
	[ 0x02, "Febuary"],
	[ 0x03, "March"],
	[ 0x04, "April"],
	[ 0x05, "May"],
	[ 0x06, "June"],
	[ 0x07, "July"],
	[ 0x08, "August"],
	[ 0x09, "September"],
	[ 0x0a, "October"],
	[ 0x0b, "November"],
	[ 0x0c, "December"],
])

MoreFlag			= val_string8("more_flag", "More Flag", [
	[ 0x00, "No More Segments/Entries Available" ],
	[ 0x01, "More Segments/Entries Available" ],
	[ 0xff, "More Segments/Entries Available" ],
])
MoreProperties			= val_string8("more_properties", "More Properties", [
	[ 0x00, "No More Properties Available" ],
	[ 0x01, "No More Properties Available" ],
	[ 0xff, "More Properties Available" ],
])

Name				= nstring8("name", "Name")
Name12				= fw_string("name12", "Name", 12)
NameLen				= uint8("name_len", "Name Space Length")
NameLength                      = uint8("name_length", "Name Length")
NameList			= uint32("name_list", "Name List")
#
# XXX - should this value be used to interpret the characters in names,
# search patterns, and the like?
#
# We need to handle character sets better, e.g. translating strings
# from whatever character set they are in the packet (DOS/Windows code
# pages, ISO character sets, UNIX EUC character sets, UTF-8, UCS-2/Unicode,
# Mac character sets, etc.) into UCS-4 or UTF-8 and storing them as such
# in the protocol tree, and displaying them as best we can.
#
NameSpace 			= val_string8("name_space", "Name Space", [
	[ 0x00, "DOS" ],
	[ 0x01, "MAC" ],
	[ 0x02, "NFS" ],
	[ 0x03, "FTAM" ],
	[ 0x04, "OS/2, Long" ],
])
NamesSpaceInfoMask			= bitfield16("ns_info_mask", "Names Space Info Mask", [
	bf_boolean16(0x0001, "ns_info_mask_modify", "Modify Name"),
	bf_boolean16(0x0002, "ns_info_mask_fatt", "File Attributes"),
	bf_boolean16(0x0004, "ns_info_mask_cdate", "Creation Date"),
	bf_boolean16(0x0008, "ns_info_mask_ctime", "Creation Time"),
	bf_boolean16(0x0010, "ns_info_mask_owner", "Owner ID"),
	bf_boolean16(0x0020, "ns_info_mask_adate", "Archive Date"),
	bf_boolean16(0x0040, "ns_info_mask_atime", "Archive Time"),
	bf_boolean16(0x0080, "ns_info_mask_aid", "Archiver ID"),
	bf_boolean16(0x0100, "ns_info_mask_udate", "Update Date"),
	bf_boolean16(0x0200, "ns_info_mask_utime", "Update Time"),
	bf_boolean16(0x0400, "ns_info_mask_uid", "Update ID"),
	bf_boolean16(0x0800, "ns_info_mask_acc_date", "Access Date"),
	bf_boolean16(0x1000, "ns_info_mask_max_acc_mask", "Inheritance"),
	bf_boolean16(0x2000, "ns_info_mask_max_space", "Maximum Space"),
])
NameSpaceName			= nstring8("name_space_name", "Name Space Name")
nameType			= uint32("name_type", "nameType")
NCPdataSize			= uint32("ncp_data_size", "NCP Data Size")
NCPextensionMajorVersion	= uint8("ncp_extension_major_version", "NCP Extension Major Version")
NCPextensionMinorVersion 	= uint8("ncp_extension_minor_version", "NCP Extension Minor Version")
NCPextensionName 		= nstring8("ncp_extension_name", "NCP Extension Name")
NCPextensionNumber 		= uint32("ncp_extension_number", "NCP Extension Number")
NCPextensionNumber.Display("BASE_HEX")
NCPExtensionNumbers		= uint32("ncp_extension_numbers", "NCP Extension Numbers")
NCPextensionRevisionNumber	= uint8("ncp_extension_revision_number", "NCP Extension Revision Number")
NCPPeakStaInUse			= uint32("ncp_peak_sta_in_use", "Peak Number of Connections since Server was brought up")
NCPStaInUseCnt			= uint32("ncp_sta_in_use", "Number of Workstations Connected to Server")
NDSRequestFlags 		= bitfield16("nds_request_flags", "NDS Request Flags", [
	bf_boolean16(0x0001, "nds_request_flags_output", "Output Fields"),
	bf_boolean16(0x0002, "nds_request_flags_no_such_entry", "No Such Entry"),
	bf_boolean16(0x0004, "nds_request_flags_local_entry", "Local Entry"),
	bf_boolean16(0x0008, "nds_request_flags_type_ref", "Type Referral"),
	bf_boolean16(0x0010, "nds_request_flags_alias_ref", "Alias Referral"),
	bf_boolean16(0x0020, "nds_request_flags_req_cnt", "Request Count"),
	bf_boolean16(0x0040, "nds_request_flags_req_data_size", "Request Data Size"),
	bf_boolean16(0x0080, "nds_request_flags_reply_data_size", "Reply Data Size"),
	bf_boolean16(0x0100, "nds_request_flags_trans_ref", "Transport Referral"),
	bf_boolean16(0x0200, "nds_request_flags_trans_ref2", "Transport Referral"),
	bf_boolean16(0x0400, "nds_request_flags_up_ref", "Up Referral"),
	bf_boolean16(0x0800, "nds_request_flags_dn_ref", "Down Referral"),
])
NDSStatus			= uint32("nds_status", "NDS Status")
NetBIOSBroadcastWasPropogated	= uint32("netbios_broadcast_was_propogated", "NetBIOS Broadcast Was Propogated")
NetIDNumber                     = uint32("net_id_number", "Net ID Number")
NetIDNumber.Display("BASE_HEX")
NetAddress                      = nbytes32("address", "Address")
NetStatus                       = uint16("net_status", "Network Status")
NetWareAccessHandle		= bytes("netware_access_handle", "NetWare Access Handle", 6)
NetworkAddress			= uint32("network_address", "Network Address")
NetworkAddress.Display("BASE_HEX")
NetworkNodeAddress		= bytes("network_node_address", "Network Node Address", 6)
NetworkNumber                   = uint32("network_number", "Network Number")
NetworkNumber.Display("BASE_HEX")
#
# XXX - this should have the "ipx_socket_vals" value_string table
# from "packet-ipx.c".
#
NetworkSocket			= uint16("network_socket", "Network Socket")
NetworkSocket.Display("BASE_HEX")
NewAccessRights 		= bitfield16("new_access_rights_mask", "New Access Rights", [
	bf_boolean16(0x0001, "new_access_rights_read", "Read"),
	bf_boolean16(0x0002, "new_access_rights_write", "Write"),
	bf_boolean16(0x0004, "new_access_rights_open", "Open"),
	bf_boolean16(0x0008, "new_access_rights_create", "Create"),
	bf_boolean16(0x0010, "new_access_rights_delete", "Delete"),
	bf_boolean16(0x0020, "new_access_rights_parental", "Parental"),
	bf_boolean16(0x0040, "new_access_rights_search", "Search"),
	bf_boolean16(0x0080, "new_access_rights_modify", "Modify"),
	bf_boolean16(0x0100, "new_access_rights_supervisor", "Supervisor"),
])
NewDirectoryID			= uint32("new_directory_id", "New Directory ID", BE)
NewDirectoryID.Display("BASE_HEX")
NewEAHandle			= uint32("new_ea_handle", "New EA Handle")
NewEAHandle.Display("BASE_HEX")
NewFileName			= fw_string("new_file_name", "New File Name", 14)
NewFileNameLen			= nstring8("new_file_name_len", "New File Name")
NewFileSize			= uint32("new_file_size", "New File Size")
NewPassword			= nstring8("new_password", "New Password")
NewPath 			= nstring8("new_path", "New Path")
NewPosition			= uint8("new_position", "New Position")
NewObjectName			= nstring8("new_object_name", "New Object Name")
NextCntBlock                    = uint32("next_cnt_block", "Next Count Block")
NextHugeStateInfo		= bytes("next_huge_state_info", "Next Huge State Info", 16)
nextLimbScanNum			= uint32("next_limb_scan_num", "Next Limb Scan Number")
NextObjectID			= uint32("next_object_id", "Next Object ID", BE)
NextObjectID.Display("BASE_HEX")
NextRecord			= uint32("next_record", "Next Record")
NextRequestRecord 		= uint16("next_request_record", "Next Request Record")
NextSearchIndex			= uint16("next_search_index", "Next Search Index")
NextSearchNumber		= uint16("next_search_number", "Next Search Number")
NextSearchNum                   = uint32("nxt_search_num", "Next Search Number")
nextStartingNumber 		= uint32("next_starting_number", "Next Starting Number")
NextTrusteeEntry		= uint32("next_trustee_entry", "Next Trustee Entry")
NextVolumeNumber		= uint32("next_volume_number", "Next Volume Number")
NLMBuffer                       = nstring8("nlm_buffer", "Buffer")
NLMcount			= uint32("nlm_count", "NLM Count")
NLMFlags			= bitfield8("nlm_flags", "Flags", [
	bf_boolean8(0x01, "nlm_flags_reentrant", "ReEntrant"),
	bf_boolean8(0x02, "nlm_flags_multiple", "Can Load Multiple Times"),
	bf_boolean8(0x04, "nlm_flags_synchronize", "Synchronize Start"),
	bf_boolean8(0x08, "nlm_flags_pseudo", "PseudoPreemption"),
])
NLMLoadOptions                  = uint32("nlm_load_options", "NLM Load Options")
NLMName                         = stringz("nlm_name_stringz", "NLM Name")
NLMNumber			= uint32("nlm_number", "NLM Number")
NLMNumbers			= uint32("nlm_numbers", "NLM Numbers")
NLMsInList			= uint32("nlms_in_list", "NLM's in List")
NLMStartNumber                  = uint32("nlm_start_num", "NLM Start Number")
NLMType				= val_string8("nlm_type", "NLM Type", [
        [ 0x00, "Generic NLM (.NLM)" ],
	[ 0x01, "LAN Driver (.LAN)" ],
	[ 0x02, "Disk Driver (.DSK)" ],
	[ 0x03, "Name Space Support Module (.NAM)" ],
	[ 0x04, "Utility or Support Program (.NLM)" ],
	[ 0x05, "Mirrored Server Link (.MSL)" ],
	[ 0x06, "OS NLM (.NLM)" ],
	[ 0x07, "Paged High OS NLM (.NLM)" ],
	[ 0x08, "Host Adapter Module (.HAM)" ],
	[ 0x09, "Custom Device Module (.CDM)" ],
	[ 0x0a, "File System Engine (.NLM)" ],
	[ 0x0b, "Real Mode NLM (.NLM)" ],
	[ 0x0c, "Hidden NLM (.NLM)" ],
        [ 0x15, "NICI Support (.NLM)" ],
        [ 0x16, "NICI Support (.NLM)" ],
        [ 0x17, "Cryptography (.NLM)" ],
        [ 0x18, "Encryption (.NLM)" ],
        [ 0x19, "NICI Support (.NLM)" ],
        [ 0x1c, "NICI Support (.NLM)" ],
])
nodeFlags 			= uint32("node_flags", "Node Flags")
nodeFlags.Display("BASE_HEX")
NoMoreMemAvlCnt			= uint32("no_more_mem_avail", "No More Memory Available Count")
NonDedFlag			= boolean8("non_ded_flag", "Non Dedicated Flag")
NonFreeableAvailableSubAllocSectors = uint32("non_freeable_avail_sub_alloc_sectors", "Non Freeable Available Sub Alloc Sectors")
NonFreeableLimboSectors		= uint32("non_freeable_limbo_sectors", "Non Freeable Limbo Sectors")
NotUsableSubAllocSectors	= uint32("not_usable_sub_alloc_sectors", "Not Usable Sub Alloc Sectors")
NotYetPurgeableBlocks		= uint32("not_yet_purgeable_blocks", "Not Yet Purgeable Blocks")
NSInfoBitMask			= uint32("ns_info_bit_mask", "Name Space Info Bit Mask")
NSSOAllInFlags                  = bitfield32("nsso_all_in_flags", "SecretStore All Input Flags",[
        bf_boolean32(0x00000010, "nsso_all_unicode", "Unicode Data"),
	bf_boolean32(0x00000080, "nsso_set_tree", "Set Tree"),
	bf_boolean32(0x00000200, "nsso_destroy_ctx", "Destroy Context"),
])
NSSOGetServiceInFlags           = bitfield32("nsso_get_svc_in_flags", "SecretStore Get Service Flags",[
        bf_boolean32(0x00000100, "nsso_get_ctx", "Get Context"),
])
NSSOReadInFlags                 = bitfield32("nsso_read_in_flags", "SecretStore Read Flags",[
        bf_boolean32(0x00000001, "nsso_rw_enh_prot", "Read/Write Enhanced Protection"),
        bf_boolean32(0x00000008, "nsso_repair", "Repair SecretStore"),
])
NSSOReadOrUnlockInFlags         = bitfield32("nsso_read_or_unlock_in_flags", "SecretStore Read or Unlock Flags",[
        bf_boolean32(0x00000004, "nsso_ep_master_pwd", "Master Password used instead of ENH Password"),
])
NSSOUnlockInFlags               = bitfield32("nsso_unlock_in_flags", "SecretStore Unlock Flags",[
        bf_boolean32(0x00000004, "nsso_rmv_lock", "Remove Lock from Store"),
])
NSSOWriteInFlags                = bitfield32("nsso_write_in_flags", "SecretStore Write Flags",[
        bf_boolean32(0x00000001, "nsso_enh_prot", "Enhanced Protection"),
	bf_boolean32(0x00000002, "nsso_create_id", "Create ID"),
	bf_boolean32(0x00000040, "nsso_ep_pwd_used", "Enhanced Protection Password Used"),
])
NSSOContextOutFlags             = bitfield32("nsso_cts_out_flags", "Type of Context",[
        bf_boolean32(0x00000001, "nsso_ds_ctx", "DSAPI Context"),
	bf_boolean32(0x00000080, "nsso_ldap_ctx", "LDAP Context"),
	bf_boolean32(0x00000200, "nsso_dc_ctx", "Reserved"),
])
NSSOGetServiceOutFlags          = bitfield32("nsso_get_svc_out_flags", "SecretStore Status Flags",[
        bf_boolean32(0x00400000, "nsso_mstr_pwd", "Master Password Present"),
])
NSSOGetServiceReadOutFlags      = bitfield32("nsso_get_svc_read_out_flags", "SecretStore Status Flags",[
        bf_boolean32(0x00800000, "nsso_mp_disabled", "Master Password Disabled"),
])
NSSOReadOutFlags                = bitfield32("nsso_read_out_flags", "SecretStore Read Flags",[
        bf_boolean32(0x00010000, "nsso_secret_locked", "Enhanced Protection Lock on Secret"),
        bf_boolean32(0x00020000, "nsso_secret_not_init", "Secret Not Yet Initialized"),
        bf_boolean32(0x00040000, "nsso_secret_marked", "Secret Marked for Enhanced Protection"),
        bf_boolean32(0x00080000, "nsso_secret_not_sync", "Secret Not Yet Synchronized in NDS"),
        bf_boolean32(0x00200000, "nsso_secret_enh_pwd", "Enhanced Protection Password on Secret"),
])
NSSOReadOutStatFlags            = bitfield32("nsso_read_out_stat_flags", "SecretStore Read Status Flags",[
        bf_boolean32(0x00100000, "nsso_admin_mod", "Admin Modified Secret Last"),
])
NSSOVerb                        = val_string8("nsso_verb", "SecretStore Verb", [
        [ 0x00, "Query Server" ],
        [ 0x01, "Read App Secrets" ],
        [ 0x02, "Write App Secrets" ],
        [ 0x03, "Add Secret ID" ],
        [ 0x04, "Remove Secret ID" ],
        [ 0x05, "Remove SecretStore" ],
        [ 0x06, "Enumerate SecretID's" ],
        [ 0x07, "Unlock Store" ],
        [ 0x08, "Set Master Password" ],
        [ 0x09, "Get Service Information" ],
])
NSSpecificInfo			= fw_string("ns_specific_info", "Name Space Specific Info", 512)
NumberOfAllocs			= uint32("num_of_allocs", "Number of Allocations")
NumberOfAttributes		= uint32("number_of_attributes", "Number of Attributes")
NumberOfCPUs			= uint32("number_of_cpus", "Number of CPU's")
NumberOfDataStreams 		= uint16("number_of_data_streams", "Number of Data Streams")
NumberOfDynamicMemoryAreas 	= uint16("number_of_dynamic_memory_areas", "Number Of Dynamic Memory Areas")
NumberOfEntries			= uint8("number_of_entries", "Number of Entries")
NumberOfLocks			= uint8("number_of_locks", "Number of Locks")
NumberOfMinutesToDelay		= uint32("number_of_minutes_to_delay", "Number of Minutes to Delay")
NumberOfNCPExtensions		= uint32("number_of_ncp_extensions", "Number Of NCP Extensions")
NumberOfNSLoaded		= uint16("number_of_ns_loaded", "Number Of Name Spaces Loaded")
NumberOfProtocols               = uint8("number_of_protocols", "Number of Protocols")
NumberOfRecords			= uint16("number_of_records", "Number of Records")
NumberOfReferencedPublics	= uint32("num_of_ref_publics", "Number of Referenced Public Symbols")
NumberOfSemaphores		= uint16("number_of_semaphores", "Number Of Semaphores")
NumberOfServiceProcesses 	= uint8("number_of_service_processes", "Number Of Service Processes")
NumberOfSetCategories           = uint32("number_of_set_categories", "Number Of Set Categories")
NumberOfSMs                     = uint32("number_of_sms", "Number Of Storage Medias")
NumberOfStations		= uint8("number_of_stations", "Number of Stations")
NumBytes			= uint16("num_bytes", "Number of Bytes")
NumOfCCinPkt                    = uint32("num_of_cc_in_pkt", "Number of Custom Counters in Packet")
NumOfChecks			= uint32("num_of_checks", "Number of Checks")
NumOfEntries			= uint32("num_of_entries", "Number of Entries")
NumOfFilesMigrated 		= uint32("num_of_files_migrated", "Number Of Files Migrated")
NumOfGarbageColl		= uint32("num_of_garb_coll", "Number of Garbage Collections")
NumOfNCPReqs			= uint32("num_of_ncp_reqs", "Number of NCP Requests since Server was brought up")
NumOfSegments                   = uint32("num_of_segments", "Number of Segments")

ObjectCount                     = uint32("object_count", "Object Count")
ObjectFlags			= val_string8("object_flags", "Object Flags", [
	[ 0x00, "Dynamic object" ],
	[ 0x01, "Static object" ],
])
ObjectHasProperties 		= val_string8("object_has_properites", "Object Has Properties", [
	[ 0x00, "No properties" ],
	[ 0xff, "One or more properties" ],
])
ObjectID			= uint32("object_id", "Object ID", BE)
ObjectID.Display('BASE_HEX')
ObjectIDCount 			= uint16("object_id_count", "Object ID Count")
ObjectIDInfo			= uint32("object_id_info", "Object Information")
ObjectInfoReturnCount		= uint32("object_info_rtn_count", "Object Information Count")
ObjectName			= nstring8("object_name", "Object Name")
ObjectNameLen			= fw_string("object_name_len", "Object Name", 48)
ObjectNameStringz               = stringz("object_name_stringz", "Object Name")
ObjectNumber                    = uint32("object_number", "Object Number")
ObjectSecurity			= val_string8("object_security", "Object Security", [
	[ 0x00, "Object Read (Anyone) / Object Write (Anyone)" ],
	[ 0x01, "Object Read (Logged in) / Object Write (Anyone)" ],
	[ 0x02, "Object Read (Logged in as Object) / Object Write (Anyone)" ],
	[ 0x03, "Object Read (Supervisor) / Object Write (Anyone)" ],
	[ 0x04, "Object Read (Operating System Only) / Object Write (Anyone)" ],
	[ 0x10, "Object Read (Anyone) / Object Write (Logged in)" ],
	[ 0x11, "Object Read (Logged in) / Object Write (Logged in)" ],
	[ 0x12, "Object Read (Logged in as Object) / Object Write (Logged in)" ],
	[ 0x13, "Object Read (Supervisor) / Object Write (Logged in)" ],
	[ 0x14, "Object Read (Operating System Only) / Object Write (Logged in)" ],
	[ 0x20, "Object Read (Anyone) / Object Write (Logged in as Object)" ],
	[ 0x21, "Object Read (Logged in) / Object Write (Logged in as Object)" ],
	[ 0x22, "Object Read (Logged in as Object) / Object Write (Logged in as Object)" ],
	[ 0x23, "Object Read (Supervisor) / Object Write (Logged in as Object)" ],
	[ 0x24, "Object Read (Operating System Only) / Object Write (Logged in as Object)" ],
	[ 0x30, "Object Read (Anyone) / Object Write (Supervisor)" ],
	[ 0x31, "Object Read (Logged in) / Object Write (Supervisor)" ],
	[ 0x32, "Object Read (Logged in as Object) / Object Write (Supervisor)" ],
	[ 0x33, "Object Read (Supervisor) / Object Write (Supervisor)" ],
	[ 0x34, "Object Read (Operating System Only) / Object Write (Supervisor)" ],
	[ 0x40, "Object Read (Anyone) / Object Write (Operating System Only)" ],
	[ 0x41, "Object Read (Logged in) / Object Write (Operating System Only)" ],
	[ 0x42, "Object Read (Logged in as Object) / Object Write (Operating System Only)" ],
	[ 0x43, "Object Read (Supervisor) / Object Write (Operating System Only)" ],
	[ 0x44, "Object Read (Operating System Only) / Object Write (Operating System Only)" ],
])
#
# XXX - should this use the "server_vals[]" value_string array from
# "packet-ipx.c"?
#
# XXX - should this list be merged with that list?  There are some
# oddities, e.g. this list has 0x03f5 for "Microsoft SQL Server", but
# the list from "packet-ipx.c" has 0xf503 for that - is that just
# byte-order confusion?
#
ObjectType			= val_string16("object_type", "Object Type", [
	[ 0x0000,	"Unknown" ],
	[ 0x0001,	"User" ],
	[ 0x0002,	"User group" ],
	[ 0x0003,	"Print queue" ],
	[ 0x0004,	"NetWare file server" ],
	[ 0x0005,	"Job server" ],
	[ 0x0006,	"Gateway" ],
	[ 0x0007,	"Print server" ],
	[ 0x0008,	"Archive queue" ],
	[ 0x0009,	"Archive server" ],
	[ 0x000a,	"Job queue" ],
	[ 0x000b,	"Administration" ],
	[ 0x0021,	"NAS SNA gateway" ],
	[ 0x0026,	"Remote bridge server" ],
	[ 0x0027,	"TCP/IP gateway" ],
        [ 0x0047,       "Novell Print Server" ],
        [ 0x004b,       "Btrieve Server" ],
        [ 0x004c,       "NetWare SQL Server" ],
        [ 0x0064,       "ARCserve" ],
        [ 0x0066,       "ARCserve 3.0" ],
        [ 0x0076,       "NetWare SQL" ],
        [ 0x00a0,       "Gupta SQL Base Server" ],
        [ 0x00a1,       "Powerchute" ],
        [ 0x0107,       "NetWare Remote Console" ],
        [ 0x01cb,       "Shiva NetModem/E" ],
        [ 0x01cc,       "Shiva LanRover/E" ],
        [ 0x01cd,       "Shiva LanRover/T" ],
        [ 0x01d8,       "Castelle FAXPress Server" ],
        [ 0x01da,       "Castelle Print Server" ],
        [ 0x01dc,       "Castelle Fax Server" ],
        [ 0x0200,       "Novell SQL Server" ],
        [ 0x023a,       "NetWare Lanalyzer Agent" ],
        [ 0x023c,       "DOS Target Service Agent" ],
        [ 0x023f,       "NetWare Server Target Service Agent" ],
        [ 0x024f,       "Appletalk Remote Access Service" ],
        [ 0x0263,       "NetWare Management Agent" ],
        [ 0x0264,       "Global MHS" ],
        [ 0x0265,       "SNMP" ],
        [ 0x026a,       "NetWare Management/NMS Console" ],
        [ 0x026b,       "NetWare Time Synchronization" ],
        [ 0x0273,       "Nest Device" ],
        [ 0x0274,       "GroupWise Message Multiple Servers" ],
        [ 0x0278,       "NDS Replica Server" ],
        [ 0x0282,       "NDPS Service Registry Service" ],
        [ 0x028a,       "MPR/IPX Address Mapping Gateway" ],
        [ 0x028b,       "ManageWise" ],
        [ 0x0293,       "NetWare 6" ],
        [ 0x030c,       "HP JetDirect" ],
        [ 0x0328,       "Watcom SQL Server" ],
        [ 0x0355,       "Backup Exec" ],
        [ 0x039b,       "Lotus Notes" ],
        [ 0x03e1,       "Univel Server" ],
        [ 0x03f5,       "Microsoft SQL Server" ],
        [ 0x055e,       "Lexmark Print Server" ],
        [ 0x0640,       "Microsoft Gateway Services for NetWare" ],
        [ 0x064e,       "Microsoft Internet Information Server" ],
        [ 0x077b,       "Advantage Database Server" ],
        [ 0x07a7,       "Backup Exec Job Queue" ],
        [ 0x07a8,       "Backup Exec Job Manager" ],
        [ 0x07a9,       "Backup Exec Job Service" ],
        [ 0x5555,       "Site Lock" ],
        [ 0x8202,       "NDPS Broker" ],
])
OCRetFlags			= val_string8("o_c_ret_flags", "Open Create Return Flags", [
	[ 0x00, "No CallBack has been registered (No Op-Lock)" ],
	[ 0x01, "Request has been registered for CallBack (Op-Lock)" ],
])
OldestDeletedFileAgeInTicks	= uint32("oldest_deleted_file_age_in_ticks", "Oldest Deleted File Age in Ticks")
OldFileName			= bytes("old_file_name", "Old File Name", 15)
OldFileSize			= uint32("old_file_size", "Old File Size")
OpenCount 			= uint16("open_count", "Open Count")
OpenCreateAction		= bitfield8("open_create_action", "Open Create Action", [
	bf_boolean8(0x01, "open_create_action_opened", "Opened"),
	bf_boolean8(0x02, "open_create_action_created", "Created"),
	bf_boolean8(0x04, "open_create_action_replaced", "Replaced"),
	bf_boolean8(0x08, "open_create_action_compressed", "Compressed"),
	bf_boolean8(0x80, "open_create_action_read_only", "Read Only"),
])
OpenCreateMode 			= bitfield8("open_create_mode", "Open Create Mode", [
	bf_boolean8(0x01, "open_create_mode_open", "Open existing file (file must exist)"),
	bf_boolean8(0x02, "open_create_mode_replace", "Replace existing file"),
	bf_boolean8(0x08, "open_create_mode_create", "Create new file or subdirectory (file or subdirectory cannot exist)"),
	bf_boolean8(0x80, "open_create_mode_oplock", "Open Callback (Op-Lock)"),
])
OpenForReadCount 		= uint16("open_for_read_count", "Open For Read Count")
OpenForWriteCount 		= uint16("open_for_write_count", "Open For Write Count")
OpenRights			= bitfield8("open_rights", "Open Rights", [
	bf_boolean8(0x01, "open_rights_read_only", "Read Only"),
	bf_boolean8(0x02, "open_rights_write_only", "Write Only"),
	bf_boolean8(0x04, "open_rights_deny_read", "Deny Read"),
	bf_boolean8(0x08, "open_rights_deny_write", "Deny Write"),
	bf_boolean8(0x10, "open_rights_compat", "Compatibility"),
	bf_boolean8(0x40, "open_rights_write_thru", "Write Through"),
])
OptionNumber			= uint8("option_number", "Option Number")
originalSize                    = uint32("original_size", "Original Size")
OSLanguageID			= uint8("os_language_id", "OS Language ID")
OSMajorVersion			= uint8("os_major_version", "OS Major Version")
OSMinorVersion			= uint8("os_minor_version", "OS Minor Version")
OSRevision			= uint8("os_revision", "OS Revision")
OtherFileForkSize		= uint32("other_file_fork_size", "Other File Fork Size")
OtherFileForkFAT		= uint32("other_file_fork_fat", "Other File Fork FAT Entry")
OutgoingPacketDiscardedNoTurboBuffer = uint16("outgoing_packet_discarded_no_turbo_buffer", "Outgoing Packet Discarded No Turbo Buffer")

PacketsDiscardedByHopCount 	= uint16("packets_discarded_by_hop_count", "Packets Discarded By Hop Count")
PacketsDiscardedUnknownNet 	= uint16("packets_discarded_unknown_net", "Packets Discarded Unknown Net")
PacketsFromInvalidConnection 	= uint16("packets_from_invalid_connection", "Packets From Invalid Connection")
PacketsReceivedDuringProcessing = uint16("packets_received_during_processing", "Packets Received During Processing")
PacketsWithBadRequestType 	= uint16("packets_with_bad_request_type", "Packets With Bad Request Type")
PacketsWithBadSequenceNumber 	= uint16("packets_with_bad_sequence_number", "Packets With Bad Sequence Number")
PageTableOwnerFlag		= uint32("page_table_owner_flag", "Page Table Owner")
ParentID			= uint32("parent_id", "Parent ID")
ParentID.Display("BASE_HEX")
ParentBaseID                    = uint32("parent_base_id", "Parent Base ID")
ParentBaseID.Display("BASE_HEX")
ParentDirectoryBase             = uint32("parent_directory_base", "Parent Directory Base")
ParentDOSDirectoryBase          = uint32("parent_dos_directory_base", "Parent DOS Directory Base")
ParentObjectNumber              = uint32("parent_object_number", "Parent Object Number")
ParentObjectNumber.Display("BASE_HEX")
Password			= nstring8("password", "Password")
PathBase			= uint8("path_base", "Path Base")
PathComponentCount 		= uint16("path_component_count", "Path Component Count")
PathComponentSize		= uint16("path_component_size", "Path Component Size")
PathCookieFlags			= val_string16("path_cookie_flags", "Path Cookie Flags", [
	[ 0x0000, "Last component is Not a File Name" ],
	[ 0x0001, "Last component is a File Name" ],
])
PathCount 			= uint8("path_count", "Path Count")
Path 				= nstring8("path", "Path")
PathAndName                     = stringz("path_and_name", "Path and Name")
PendingIOCommands 		= uint16("pending_io_commands", "Pending IO Commands")
PhysicalDiskNumber		= uint8("physical_disk_number", "Physical Disk Number")
PhysicalDriveCount		= uint8("physical_drive_count", "Physical Drive Count")
PhysicalLockThreshold		= uint8("physical_lock_threshold", "Physical Lock Threshold")
PingVersion			= uint16("ping_version", "Ping Version")
PositiveAcknowledgesSent 	= uint16("positive_acknowledges_sent", "Positive Acknowledges Sent")
PreCompressedSectors		= uint32("pre_compressed_sectors", "Precompressed Sectors")
PreviousRecord			= uint32("previous_record", "Previous Record")
PrimaryEntry			= uint32("primary_entry", "Primary Entry")
PrintFlags			= bitfield8("print_flags", "Print Flags", [
	bf_boolean8(0x08, "print_flags_ff", "Suppress Form Feeds"),
        bf_boolean8(0x10, "print_flags_cr", "Create"),
	bf_boolean8(0x20, "print_flags_del_spool", "Delete Spool File after Printing"),
	bf_boolean8(0x40, "print_flags_exp_tabs", "Expand Tabs in the File"),
	bf_boolean8(0x80, "print_flags_banner", "Print Banner Page"),
])
PrinterHalted			= val_string8("printer_halted", "Printer Halted", [
	[ 0x00, "Printer is not Halted" ],
	[ 0xff, "Printer is Halted" ],
])
PrinterOffLine			= val_string8( "printer_offline", "Printer Off-Line", [
	[ 0x00, "Printer is On-Line" ],
	[ 0xff, "Printer is Off-Line" ],
])
PrintServerVersion		= uint8("print_server_version", "Print Server Version")
Priority			= uint32("priority", "Priority")
Privileges                      = uint32("privileges", "Login Privileges")
ProcessorType 			= val_string8("processor_type", "Processor Type", [
	[ 0x00, "Motorola 68000" ],
	[ 0x01, "Intel 8088 or 8086" ],
	[ 0x02, "Intel 80286" ],
])
ProDOSInfo			= bytes("pro_dos_info", "Pro DOS Info", 6)
ProductMajorVersion		= uint16("product_major_version", "Product Major Version")
ProductMinorVersion		= uint16("product_minor_version", "Product Minor Version")
ProductRevisionVersion		= uint8("product_revision_version", "Product Revision Version")
projectedCompSize               = uint32("projected_comp_size", "Projected Compression Size")
PropertyHasMoreSegments		= val_string8("property_has_more_segments",
	"Property Has More Segments", [
	[ 0x00,	"Is last segment" ],
	[ 0xff,	"More segments are available" ],
])
PropertyName			= nstring8("property_name", "Property Name")
PropertyName16			= fw_string("property_name_16", "Property Name", 16)
PropertyData			= bytes("property_data", "Property Data", 128)
PropertySegment			= uint8("property_segment", "Property Segment")
PropertyType			= val_string8("property_type", "Property Type", [
	[ 0x00,	"Display Static property" ],
	[ 0x01,	"Display Dynamic property" ],
	[ 0x02,	"Set Static property" ],
	[ 0x03,	"Set Dynamic property" ],
])
PropertyValue			= fw_string("property_value", "Property Value", 128)
ProposedMaxSize			= uint16("proposed_max_size", "Proposed Max Size")
protocolFlags 			= uint32("protocol_flags", "Protocol Flags")
protocolFlags.Display("BASE_HEX")
PurgeableBlocks			= uint32("purgeable_blocks", "Purgeable Blocks")
PurgeCcode                      = uint32("purge_c_code", "Purge Completion Code")
PurgeCount			= uint32("purge_count", "Purge Count")
PurgeFlags			= val_string16("purge_flags", "Purge Flags", [
	[ 0x0000, "Do not Purge All" ],
	[ 0x0001, "Purge All" ],
        [ 0xffff, "Do not Purge All" ],
])
PurgeList                       = uint32("purge_list", "Purge List")
PhysicalDiskChannel		= uint8("physical_disk_channel", "Physical Disk Channel")
PhysicalDriveType 		= val_string8("physical_drive_type", "Physical Drive Type", [
	[ 0x01, "XT" ],
	[ 0x02, "AT" ],
	[ 0x03, "SCSI" ],
	[ 0x04, "Disk Coprocessor" ],
	[ 0x05, "PS/2 with MFM Controller" ],
	[ 0x06, "PS/2 with ESDI Controller" ],
	[ 0x07, "Convergent Technology SBIC" ],
])
PhysicalReadErrors		= uint16("physical_read_errors", "Physical Read Errors")
PhysicalReadRequests 		= uint32("physical_read_requests", "Physical Read Requests")
PhysicalWriteErrors 		= uint16("physical_write_errors", "Physical Write Errors")
PhysicalWriteRequests 		= uint32("physical_write_requests", "Physical Write Requests")
PrintToFileFlag                 = boolean8("print_to_file_flag", "Print to File Flag")

QueueID				= uint32("queue_id", "Queue ID")
QueueID.Display("BASE_HEX")
QueueName			= nstring8("queue_name", "Queue Name")
QueueStartPosition		= uint32("queue_start_position", "Queue Start Position")
QueueStatus			= bitfield8("queue_status", "Queue Status", [
	bf_boolean8(0x01, "queue_status_new_jobs", "Operator does not want to add jobs to the queue"),
	bf_boolean8(0x02, "queue_status_pserver", "Operator does not want additional servers attaching"),
	bf_boolean8(0x04, "queue_status_svc_jobs", "Operator does not want servers to service jobs"),
])
QueueType			= uint16("queue_type", "Queue Type")
QueueingVersion			= uint8("qms_version", "QMS Version")

ReadBeyondWrite			= uint16("read_beyond_write", "Read Beyond Write")
RecordLockCount			= uint16("rec_lock_count", "Record Lock Count")
RecordStart			= uint32("record_start", "Record Start")
RecordEnd 			= uint32("record_end", "Record End")
RecordInUseFlag			= val_string16("record_in_use", "Record in Use", [
	[ 0x0000, "Record In Use" ],
	[ 0xffff, "Record Not In Use" ],
])
RedirectedPrinter 		= uint8( "redirected_printer", "Redirected Printer" )
ReferenceCount			= uint32("reference_count", "Reference Count")
RelationsCount			= uint16("relations_count", "Relations Count")
ReMirrorCurrentOffset 		= uint32("re_mirror_current_offset", "ReMirror Current Offset")
ReMirrorDriveNumber 		= uint8("re_mirror_drive_number", "ReMirror Drive Number")
RemoteMaxPacketSize		= uint32("remote_max_packet_size", "Remote Max Packet Size")
RemoteTargetID 			= uint32("remote_target_id", "Remote Target ID")
RemoteTargetID.Display("BASE_HEX")
RemovableFlag			= uint16("removable_flag", "Removable Flag")
RemoveOpenRights		= bitfield8("remove_open_rights", "Remove Open Rights", [
	bf_boolean8(0x01, "remove_open_rights_ro", "Read Only"),
	bf_boolean8(0x02, "remove_open_rights_wo", "Write Only"),
	bf_boolean8(0x04, "remove_open_rights_dr", "Deny Read"),
	bf_boolean8(0x08, "remove_open_rights_dw", "Deny Write"),
	bf_boolean8(0x10, "remove_open_rights_comp", "Compatibility"),
	bf_boolean8(0x40, "remove_open_rights_write_thru", "Write Through"),
])
RenameFlag			= bitfield8("rename_flag", "Rename Flag", [
	bf_boolean8(0x01, "rename_flag_ren", "Rename to Myself allows file to be renamed to it's original name"),
	bf_boolean8(0x02, "rename_flag_comp", "Compatability allows files that are marked read only to be opened with read/write access"),
	bf_boolean8(0x04, "rename_flag_no", "Name Only renames only the specified name space entry name"),
])
RepliesCancelled 		= uint16("replies_cancelled", "Replies Cancelled")
ReplyBuffer 			= nstring8("reply_buffer", "Reply Buffer")
ReplyBufferSize			= uint32("reply_buffer_size", "Reply Buffer Size")
ReplyQueueJobNumbers		= uint32("reply_queue_job_numbers", "Reply Queue Job Numbers")
RequestBitMap    		= bitfield16("request_bit_map", "Request Bit Map", [
	bf_boolean16(0x0001, "request_bit_map_ret_afp_ent", "AFP Entry ID"),
	bf_boolean16(0x0002, "request_bit_map_ret_data_fork", "Data Fork Length"),
	bf_boolean16(0x0004, "request_bit_map_ret_res_fork", "Resource Fork Length"),
	bf_boolean16(0x0008, "request_bit_map_ret_num_off", "Number of Offspring"),
	bf_boolean16(0x0010, "request_bit_map_ret_owner", "Owner ID"),
	bf_boolean16(0x0020, "request_bit_map_ret_short", "Short Name"),
	bf_boolean16(0x0040, "request_bit_map_ret_acc_priv", "Access Privileges"),
	bf_boolean16(0x0100, "request_bit_map_ratt", "Return Attributes"),
	bf_boolean16(0x0200, "request_bit_map_ret_afp_parent", "AFP Parent Entry ID"),
	bf_boolean16(0x0400, "request_bit_map_ret_cr_date", "Creation Date"),
	bf_boolean16(0x0800, "request_bit_map_ret_acc_date", "Access Date"),
	bf_boolean16(0x1000, "request_bit_map_ret_mod_date", "Modify Date&Time"),
	bf_boolean16(0x2000, "request_bit_map_ret_bak_date", "Backup Date&Time"),
	bf_boolean16(0x4000, "request_bit_map_ret_finder", "Finder Info"),
	bf_boolean16(0x8000, "request_bit_map_ret_long_nm", "Long Name"),
])
ResourceForkLen			= uint32("resource_fork_len", "Resource Fork Len")
RequestCode			= val_string8("request_code", "Request Code", [
	[ 0x00, "Change Logged in to Temporary Authenticated" ],
	[ 0x01, "Change Temporary Authenticated to Logged in" ],
])
RequestData			= nstring8("request_data", "Request Data")
RequestsReprocessed 		= uint16("requests_reprocessed", "Requests Reprocessed")
Reserved			= uint8( "reserved", "Reserved" )
Reserved2			= bytes("reserved2", "Reserved", 2)
Reserved3			= bytes("reserved3", "Reserved", 3)
Reserved4			= bytes("reserved4", "Reserved", 4)
Reserved6                       = bytes("reserved6", "Reserved", 6)
Reserved8			= bytes("reserved8", "Reserved", 8)
Reserved10                      = bytes("reserved10", "Reserved", 10)
Reserved12			= bytes("reserved12", "Reserved", 12)
Reserved16			= bytes("reserved16", "Reserved", 16)
Reserved20			= bytes("reserved20", "Reserved", 20)
Reserved28			= bytes("reserved28", "Reserved", 28)
Reserved36			= bytes("reserved36", "Reserved", 36)
Reserved44			= bytes("reserved44", "Reserved", 44)
Reserved48			= bytes("reserved48", "Reserved", 48)
Reserved50			= bytes("reserved50", "Reserved", 50)
Reserved56			= bytes("reserved56", "Reserved", 56)
Reserved64			= bytes("reserved64", "Reserved", 64)
Reserved120			= bytes("reserved120", "Reserved", 120)
ReservedOrDirectoryNumber	= uint32("reserved_or_directory_number", "Reserved or Directory Number (see EAFlags)")
ResourceCount                   = uint32("resource_count", "Resource Count")
ResourceForkSize		= uint32("resource_fork_size", "Resource Fork Size")
ResourceName                    = stringz("resource_name", "Resource Name")
ResourceSignature               = fw_string("resource_sig", "Resource Signature", 4)
RestoreTime 			= uint32("restore_time", "Restore Time")
Restriction			= uint32("restriction", "Disk Space Restriction")
RestrictionsEnforced 		= val_string8("restrictions_enforced", "Disk Restrictions Enforce Flag", [
	[ 0x00, "Enforced" ],
	[ 0xff, "Not Enforced" ],
])
ReturnInfoCount			= uint32("return_info_count", "Return Information Count")
ReturnInfoMask 		        = bitfield16("ret_info_mask", "Return Information", [
        bf_boolean16(0x0001, "ret_info_mask_fname", "Return File Name Information"),
	bf_boolean16(0x0002, "ret_info_mask_alloc", "Return Allocation Space Information"),
	bf_boolean16(0x0004, "ret_info_mask_attr", "Return Attribute Information"),
	bf_boolean16(0x0008, "ret_info_mask_size", "Return Size Information"),
	bf_boolean16(0x0010, "ret_info_mask_tspace", "Return Total Space Information"),
	bf_boolean16(0x0020, "ret_info_mask_eattr", "Return Extended Attributes Information"),
	bf_boolean16(0x0040, "ret_info_mask_arch", "Return Archive Information"),
	bf_boolean16(0x0080, "ret_info_mask_mod", "Return Modify Information"),
        bf_boolean16(0x0100, "ret_info_mask_create", "Return Creation Information"),
	bf_boolean16(0x0200, "ret_info_mask_ns", "Return Name Space Information"),
	bf_boolean16(0x0400, "ret_info_mask_dir", "Return Directory Information"),
	bf_boolean16(0x0800, "ret_info_mask_rights", "Return Rights Information"),
	bf_boolean16(0x1000, "ret_info_mask_id", "Return ID Information"),
	bf_boolean16(0x2000, "ret_info_mask_ns_attr", "Return Name Space Attributes Information"),
	bf_boolean16(0x4000, "ret_info_mask_actual", "Return Actual Information"),
	bf_boolean16(0x8000, "ret_info_mask_logical", "Return Logical Information"),
])
ReturnedListCount		= uint32("returned_list_count", "Returned List Count")
Revision			= uint32("revision", "Revision")
RevisionNumber			= uint8("revision_number", "Revision")
RevQueryFlag			= val_string8("rev_query_flag", "Revoke Rights Query Flag", [
	[ 0x00, "Do not query the locks engine for access rights" ],
	[ 0x01, "Query the locks engine and return the access rights" ],
])
RightsGrantMask 		= bitfield8("rights_grant_mask", "Grant Rights", [
	bf_boolean8(0x01, "rights_grant_mask_read", "Read"),
	bf_boolean8(0x02, "rights_grant_mask_write", "Write"),
	bf_boolean8(0x04, "rights_grant_mask_open", "Open"),
	bf_boolean8(0x08, "rights_grant_mask_create", "Create"),
	bf_boolean8(0x10, "rights_grant_mask_del", "Delete"),
	bf_boolean8(0x20, "rights_grant_mask_parent", "Parental"),
	bf_boolean8(0x40, "rights_grant_mask_search", "Search"),
	bf_boolean8(0x80, "rights_grant_mask_mod", "Modify"),
])
RightsRevokeMask 		= bitfield8("rights_revoke_mask", "Revoke Rights", [
	bf_boolean8(0x01, "rights_revoke_mask_read", "Read"),
	bf_boolean8(0x02, "rights_revoke_mask_write", "Write"),
	bf_boolean8(0x04, "rights_revoke_mask_open", "Open"),
	bf_boolean8(0x08, "rights_revoke_mask_create", "Create"),
	bf_boolean8(0x10, "rights_revoke_mask_del", "Delete"),
	bf_boolean8(0x20, "rights_revoke_mask_parent", "Parental"),
	bf_boolean8(0x40, "rights_revoke_mask_search", "Search"),
	bf_boolean8(0x80, "rights_revoke_mask_mod", "Modify"),
])
RIPSocketNumber                 = uint16("rip_socket_num", "RIP Socket Number")
RIPSocketNumber.Display("BASE_HEX")
RouterDownFlag                  = boolean8("router_dn_flag", "Router Down Flag")
RPCccode                        = val_string16("rpc_c_code", "RPC Completion Code", [
        [ 0x0000, "Successful" ],
])
RTagNumber                      = uint32("r_tag_num", "Resource Tag Number")
RTagNumber.Display("BASE_HEX")
RpyNearestSrvFlag               = boolean8("rpy_nearest_srv_flag", "Reply to Nearest Server Flag")

SalvageableFileEntryNumber	= uint32("salvageable_file_entry_number", "Salvageable File Entry Number")
SalvageableFileEntryNumber.Display("BASE_HEX")
SAPSocketNumber                 = uint16("sap_socket_number", "SAP Socket Number")
SAPSocketNumber.Display("BASE_HEX")
ScanItems			= uint32("scan_items", "Number of Items returned from Scan")
SearchAttributes		= bitfield8("sattr", "Search Attributes", [
	bf_boolean8(0x01, "sattr_ronly", "Read-Only Files Allowed"),
	bf_boolean8(0x02, "sattr_hid", "Hidden Files Allowed"),
	bf_boolean8(0x04, "sattr_sys", "System Files Allowed"),
	bf_boolean8(0x08, "sattr_exonly", "Execute-Only Files Allowed"),
	bf_boolean8(0x10, "sattr_sub", "Subdirectories Only"),
	bf_boolean8(0x20, "sattr_archive", "Archive"),
	bf_boolean8(0x40, "sattr_execute_confirm", "Execute Confirm"),
	bf_boolean8(0x80, "sattr_shareable", "Shareable"),
])
SearchAttributesLow		= bitfield16("search_att_low", "Search Attributes", [
	bf_boolean16(0x0001, "search_att_read_only", "Read-Only"),
	bf_boolean16(0x0002, "search_att_hidden", "Hidden Files Allowed"),
	bf_boolean16(0x0004, "search_att_system", "System"),
	bf_boolean16(0x0008, "search_att_execute_only", "Execute-Only"),
	bf_boolean16(0x0010, "search_att_sub", "Subdirectories Only"),
	bf_boolean16(0x0020, "search_att_archive", "Archive"),
	bf_boolean16(0x0040, "search_att_execute_confirm", "Execute Confirm"),
	bf_boolean16(0x0080, "search_att_shareable", "Shareable"),
	bf_boolean16(0x8000, "search_attr_all_files", "All Files and Directories"),
])
SearchBitMap				= bitfield8("search_bit_map", "Search Bit Map", [
	bf_boolean8(0x01, "search_bit_map_hidden", "Hidden"),
	bf_boolean8(0x02, "search_bit_map_sys", "System"),
	bf_boolean8(0x04, "search_bit_map_sub", "Subdirectory"),
	bf_boolean8(0x08, "search_bit_map_files", "Files"),
])
SearchConnNumber			= uint32("search_conn_number", "Search Connection Number")
SearchInstance				= uint32("search_instance", "Search Instance")
SearchNumber                            = uint32("search_number", "Search Number")
SearchPattern				= nstring8("search_pattern", "Search Pattern")
SearchSequence				= bytes("search_sequence", "Search Sequence", 9)
SearchSequenceWord                      = uint16("search_sequence_word", "Search Sequence", BE)
Second					= uint8("s_second", "Seconds")
SecondsRelativeToTheYear2000            = uint32("sec_rel_to_y2k", "Seconds Relative to the Year 2000")
SecretStoreVerb                         = val_string8("ss_verb", "Secret Store Verb",[
        [ 0x00, "Query Server" ],
        [ 0x01, "Read App Secrets" ],
        [ 0x02, "Write App Secrets" ],
        [ 0x03, "Add Secret ID" ],
        [ 0x04, "Remove Secret ID" ],
        [ 0x05, "Remove SecretStore" ],
        [ 0x06, "Enumerate Secret IDs" ],
        [ 0x07, "Unlock Store" ],
        [ 0x08, "Set Master Password" ],
        [ 0x09, "Get Service Information" ],
])
SecurityEquivalentList			= fw_string("security_equiv_list", "Security Equivalent List", 128)
SecurityFlag				= bitfield8("security_flag", "Security Flag", [
	bf_boolean8(0x01, "checksuming", "Checksumming"),
	bf_boolean8(0x02, "signature", "Signature"),
	bf_boolean8(0x04, "complete_signatures", "Complete Signatures"),
	bf_boolean8(0x08, "encryption", "Encryption"),
	bf_boolean8(0x80, "large_internet_packets", "Large Internet Packets (LIP) Disabled"),
])
SecurityRestrictionVersion		= uint8("security_restriction_version", "Security Restriction Version")
SectorsPerBlock				= uint8("sectors_per_block", "Sectors Per Block")
SectorsPerCluster			= uint16("sectors_per_cluster", "Sectors Per Cluster" )
SectorsPerClusterLong			= uint32("sectors_per_cluster_long", "Sectors Per Cluster" )
SectorsPerTrack 			= uint8("sectors_per_track", "Sectors Per Track")
SectorSize				= uint32("sector_size", "Sector Size")
SemaphoreHandle				= uint32("semaphore_handle", "Semaphore Handle")
SemaphoreName				= nstring8("semaphore_name", "Semaphore Name")
SemaphoreNameLen 			= uint8("semaphore_name_len", "Semaphore Name Len")
SemaphoreOpenCount			= uint8("semaphore_open_count", "Semaphore Open Count")
SemaphoreShareCount			= uint8("semaphore_share_count", "Semaphore Share Count")
SemaphoreTimeOut			= uint16("semaphore_time_out", "Semaphore Time Out")
SemaphoreValue				= uint16("semaphore_value", "Semaphore Value")
SendStatus				= val_string8("send_status", "Send Status", [
	[ 0x00, "Successful" ],
	[ 0x01, "Illegal Station Number" ],
	[ 0x02, "Client Not Logged In" ],
	[ 0x03, "Client Not Accepting Messages" ],
	[ 0x04, "Client Already has a Message" ],
	[ 0x96, "No Alloc Space for the Message" ],
	[ 0xfd, "Bad Station Number" ],
	[ 0xff, "Failure" ],
])
SequenceByte			= uint8("sequence_byte", "Sequence")
SequenceNumber			= uint32("sequence_number", "Sequence Number")
SequenceNumber.Display("BASE_HEX")
ServerAddress                   = bytes("server_address", "Server Address", 12)
ServerAppNumber			= uint16("server_app_num", "Server App Number")
#ServerIDList			= uint32("server_id_list", "Server ID List")
ServerID			= uint32("server_id_number", "Server ID", BE )
ServerID.Display("BASE_HEX")
ServerInfoFlags                 = val_string16("server_info_flags", "Server Information Flags", [
        [ 0x0000, "This server is not a member of a Cluster" ],
        [ 0x0001, "This server is a member of a Cluster" ],
])
serverListFlags			= uint32("server_list_flags", "Server List Flags")
ServerName			= fw_string("server_name", "Server Name", 48)
serverName50 			= fw_string("server_name50", "Server Name", 50)
ServerNameLen			= nstring8("server_name_len", "Server Name")
ServerNameStringz               = stringz("server_name_stringz", "Server Name")
ServerNetworkAddress		= bytes("server_network_address", "Server Network Address", 10)
ServerNode                      = bytes("server_node", "Server Node", 6)
ServerSerialNumber		= uint32("server_serial_number", "Server Serial Number")
ServerStation			= uint8("server_station", "Server Station")
ServerStationLong		= uint32("server_station_long", "Server Station")
ServerStationList		= uint8("server_station_list", "Server Station List")
ServerStatusRecord		= fw_string("server_status_record", "Server Status Record", 64)
ServerTaskNumber		= uint8("server_task_number", "Server Task Number")
ServerTaskNumberLong		= uint32("server_task_number_long", "Server Task Number")
ServerType                      = uint16("server_type", "Server Type")
ServerType.Display("BASE_HEX")
ServerUtilization		= uint32("server_utilization", "Server Utilization")
ServerUtilizationPercentage 	= uint8("server_utilization_percentage", "Server Utilization Percentage")
ServiceType			= val_string16("Service_type", "Service Type", [
	[ 0x0000,	"Unknown" ],
	[ 0x0001,	"User" ],
	[ 0x0002,	"User group" ],
	[ 0x0003,	"Print queue" ],
	[ 0x0004,	"NetWare file server" ],
	[ 0x0005,	"Job server" ],
	[ 0x0006,	"Gateway" ],
	[ 0x0007,	"Print server" ],
	[ 0x0008,	"Archive queue" ],
	[ 0x0009,	"Archive server" ],
	[ 0x000a,	"Job queue" ],
	[ 0x000b,	"Administration" ],
	[ 0x0021,	"NAS SNA gateway" ],
	[ 0x0026,	"Remote bridge server" ],
	[ 0x0027,	"TCP/IP gateway" ],
])
SetCmdCategory                  = val_string8("set_cmd_category", "Set Command Category", [
        [ 0x00, "Communications" ],
        [ 0x01, "Memory" ],
        [ 0x02, "File Cache" ],
        [ 0x03, "Directory Cache" ],
        [ 0x04, "File System" ],
        [ 0x05, "Locks" ],
        [ 0x06, "Transaction Tracking" ],
        [ 0x07, "Disk" ],
        [ 0x08, "Time" ],
        [ 0x09, "NCP" ],
        [ 0x0a, "Miscellaneous" ],
        [ 0x0b, "Error Handling" ],
        [ 0x0c, "Directory Services" ],
        [ 0x0d, "MultiProcessor" ],
        [ 0x0e, "Service Location Protocol" ],
        [ 0x0f, "Licensing Services" ],
])
SetCmdFlags				= bitfield8("set_cmd_flags", "Set Command Flags", [
	bf_boolean8(0x01, "cmd_flags_startup_only", "Startup.ncf Only"),
	bf_boolean8(0x02, "cmd_flags_hidden", "Hidden"),
	bf_boolean8(0x04, "cmd_flags_advanced", "Advanced"),
	bf_boolean8(0x08, "cmd_flags_later", "Restart Server Required to Take Effect"),
	bf_boolean8(0x80, "cmd_flags_secure", "Console Secured"),
])
SetCmdName                      = stringz("set_cmd_name", "Set Command Name")
SetCmdType                      = val_string8("set_cmd_type", "Set Command Type", [
        [ 0x00, "Numeric Value" ],
        [ 0x01, "Boolean Value" ],
        [ 0x02, "Ticks Value" ],
        [ 0x04, "Time Value" ],
        [ 0x05, "String Value" ],
        [ 0x06, "Trigger Value" ],
        [ 0x07, "Numeric Value" ],
])
SetCmdValueNum                  = uint32("set_cmd_value_num", "Set Command Value")
SetCmdValueString               = stringz("set_cmd_value_string", "Set Command Value")
SetParmName                     = stringz("set_parm_name", "Set Parameter Name")
SFTErrorTable 			= bytes("sft_error_table", "SFT Error Table", 60)
SFTSupportLevel			= val_string8("sft_support_level", "SFT Support Level", [
	[ 0x01, "Server Offers Hot Disk Error Fixing" ],
	[ 0x02, "Server Offers Disk Mirroring and Transaction Tracking" ],
	[ 0x03, "Server Offers Physical Server Mirroring" ],
])
ShareableLockCount		= uint16("shareable_lock_count", "Shareable Lock Count")
SharedMemoryAddresses 		= bytes("shared_memory_addresses", "Shared Memory Addresses", 10)
ShortName 			= fw_string("short_name", "Short Name", 12)
ShortStkName                    = fw_string("short_stack_name", "Short Stack Name", 16)
SiblingCount                    = uint32("sibling_count", "Sibling Count")
SixtyFourBitOffsetsSupportedFlag = val_string8("64_bit_flag", "64 Bit Support", [
    [ 0x00, "No support for 64 bit offsets" ],
    [ 0x01, "64 bit offsets supported" ],
])
SMIDs                           = uint32("smids", "Storage Media ID's")
SoftwareDescription 		= fw_string("software_description", "Software Description", 65)
SoftwareDriverType 		= uint8("software_driver_type", "Software Driver Type")
SoftwareMajorVersionNumber	= uint8("software_major_version_number", "Software Major Version Number")
SoftwareMinorVersionNumber	= uint8("software_minor_version_number", "Software Minor Version Number")
SourceDirHandle			= uint8("source_dir_handle", "Source Directory Handle")
sourceOriginateTime 		= bytes("source_originate_time", "Source Originate Time", 8)
sourceOriginateTime.Display("BASE_HEX")
SourcePath			= nstring8("source_path", "Source Path")
SourcePathComponentCount 	= uint8("source_component_count", "Source Path Component Count")
sourceReturnTime 		= bytes("source_return_time", "Source Return Time", 8)
sourceReturnTime.Display("BASE_HEX")
SpaceUsed 			= uint32("space_used", "Space Used")
SpaceMigrated 			= uint32("space_migrated", "Space Migrated")
SrcNameSpace 			= val_string8("src_name_space", "Source Name Space", [
	[ 0x00, "DOS Name Space" ],
	[ 0x01, "MAC Name Space" ],
	[ 0x02, "NFS Name Space" ],
	[ 0x04, "Long Name Space" ],
])
SupModID			= uint32("sup_mod_id", "Sup Mod ID")
StackCount                      = uint32("stack_count", "Stack Count")
StackFullNameStr                = nstring8("stack_full_name_str", "Stack Full Name")
StackMajorVN                    = uint8("stack_major_vn", "Stack Major Version Number")
StackMinorVN                    = uint8("stack_minor_vn", "Stack Minor Version Number")
StackNumber                     = uint32("stack_number", "Stack Number")
StartConnNumber			= uint32("start_conn_num", "Starting Connection Number")
StartingBlock 			= uint16("starting_block", "Starting Block")
StartingNumber 			= uint32("starting_number", "Starting Number")
StartingSearchNumber		= uint16("start_search_number", "Start Search Number")
StartNumber 			= uint32("start_number", "Start Number")
startNumberFlag 		= uint16("start_number_flag", "Start Number Flag")
StartOffset64bit    = bytes("s_offset_64bit", "64bit Starting Offset", 64)
StartVolumeNumber		= uint32("start_volume_number", "Starting Volume Number")
StationList			= uint32("station_list", "Station List")
StationNumber			= bytes("station_number", "Station Number", 3)
StatMajorVersion                = uint8("stat_major_version", "Statistics Table Major Version")
StatMinorVersion                = uint8("stat_minor_version", "Statistics Table Minor Version")
Status				= bitfield16("status", "Status", [
	bf_boolean16(0x0001, "user_info_logged_in", "Logged In"),
	bf_boolean16(0x0002, "user_info_being_abort", "Being Aborted"),
	bf_boolean16(0x0004, "user_info_audited", "Audited"),
	bf_boolean16(0x0008, "user_info_need_sec", "Needs Security Change"),
	bf_boolean16(0x0010, "user_info_mac_station", "MAC Station"),
	bf_boolean16(0x0020, "user_info_temp_authen", "Temporary Authenticated"),
	bf_boolean16(0x0040, "user_info_audit_conn", "Audit Connection Recorded"),
	bf_boolean16(0x0080, "user_info_dsaudit_conn", "DS Audit Connection Recorded"),
	bf_boolean16(0x0100, "user_info_logout", "Logout in Progress"),
	bf_boolean16(0x0200, "user_info_int_login", "Internal Login"),
	bf_boolean16(0x0400, "user_info_bindery", "Bindery Connection"),
])
StatusFlagBits		        = bitfield32("status_flag_bits", "Status Flag", [
	bf_boolean32(0x00000001, "status_flag_bits_suballoc", "Sub Allocation"),
	bf_boolean32(0x00000002, "status_flag_bits_comp", "Compression"),
	bf_boolean32(0x00000004, "status_flag_bits_migrate", "Migration"),
	bf_boolean32(0x00000008, "status_flag_bits_audit", "Audit"),
	bf_boolean32(0x00000010, "status_flag_bits_ro", "Read Only"),
	bf_boolean32(0x00000020, "status_flag_bits_im_purge", "Immediate Purge"),
        bf_boolean32(0x80000000, "status_flag_bits_nss", "NSS Volume"),
])
SubAllocClusters		= uint32("sub_alloc_clusters", "Sub Alloc Clusters")
SubAllocFreeableClusters 	= uint32("sub_alloc_freeable_clusters", "Sub Alloc Freeable Clusters")
Subdirectory			= uint32("sub_directory", "Subdirectory")
Subdirectory.Display("BASE_HEX")
SuggestedFileSize		= uint32("suggested_file_size", "Suggested File Size")
SupportModuleID			= uint32("support_module_id", "Support Module ID")
SynchName			= nstring8("synch_name", "Synch Name")
SystemIntervalMarker		= uint32("system_interval_marker", "System Interval Marker")

TabSize				= uint8( "tab_size", "Tab Size" )
TargetClientList		= uint8("target_client_list", "Target Client List")
TargetConnectionNumber		= uint16("target_connection_number", "Target Connection Number")
TargetDirectoryBase		= uint32("target_directory_base", "Target Directory Base")
TargetDirHandle			= uint8("target_dir_handle", "Target Directory Handle")
TargetEntryID			= uint32("target_entry_id", "Target Entry ID")
TargetEntryID.Display("BASE_HEX")
TargetExecutionTime		= bytes("target_execution_time", "Target Execution Time", 6)
TargetFileHandle		= bytes("target_file_handle", "Target File Handle", 6)
TargetFileOffset		= uint32("target_file_offset", "Target File Offset")
TargetMessage			= nstring8("target_message", "Message")
TargetPrinter			= uint8( "target_ptr", "Target Printer" )
targetReceiveTime 		= bytes("target_receive_time", "Target Receive Time", 8)
targetReceiveTime.Display("BASE_HEX")
TargetServerIDNumber		= uint32("target_server_id_number", "Target Server ID Number", BE )
TargetServerIDNumber.Display("BASE_HEX")
targetTransmitTime 		= bytes("target_transmit_time", "Target Transmit Time", 8)
targetTransmitTime.Display("BASE_HEX")
TaskNumByte			= uint8("task_num_byte", "Task Number")
TaskNumber			= uint32("task_number", "Task Number")
TaskNumberWord			= uint16("task_number_word", "Task Number")
TextJobDescription		= fw_string("text_job_description", "Text Job Description", 50)
ThrashingCount			= uint16("thrashing_count", "Thrashing Count")
TimeoutLimit			= uint16("timeout_limit", "Timeout Limit")
TimesyncStatus                  = bitfield32("timesync_status_flags", "Timesync Status", [
	bf_boolean32(0x00000001, "timesync_status_sync", "Time is Synchronized"),
	bf_boolean32(0x00000002, "timesync_status_net_sync", "Time is Synchronized to the Network"),
        bf_boolean32(0x00000004, "timesync_status_active", "Time Synchronization is Active"),
	bf_boolean32(0x00000008, "timesync_status_external", "External Time Synchronization Active"),
	bf_val_str32(0x00000700, "timesync_status_server_type", "Time Server Type", [
		[ 0x01, "Client Time Server" ],
		[ 0x02, "Secondary Time Server" ],
		[ 0x03, "Primary Time Server" ],
		[ 0x04, "Reference Time Server" ],
		[ 0x05, "Single Reference Time Server" ],
	]),
	bf_boolean32(0x000f0000, "timesync_status_ext_sync", "External Clock Status"),
])
TimeToNet                       = uint16("time_to_net", "Time To Net")
TotalBlocks			= uint32("total_blocks", "Total Blocks")
TotalBlocksToDecompress         = uint32("total_blks_to_dcompress", "Total Blocks To Decompress")
TotalBytesRead			= bytes("user_info_ttl_bytes_rd", "Total Bytes Read", 6)
TotalBytesWritten		= bytes("user_info_ttl_bytes_wrt", "Total Bytes Written", 6)
TotalCacheWrites 		= uint32("total_cache_writes", "Total Cache Writes")
TotalChangedFATs		= uint32("total_changed_fats", "Total Changed FAT Entries")
TotalCommonCnts                 = uint32("total_common_cnts", "Total Common Counts")
TotalCntBlocks                  = uint32("total_cnt_blocks", "Total Count Blocks")
TotalDataStreamDiskSpaceAlloc	= uint32("total_stream_size_struct_space_alloc", "Total Data Stream Disk Space Alloc")
TotalDirectorySlots		= uint16("total_directory_slots", "Total Directory Slots")
TotalDirectoryEntries		= uint32("total_dir_entries", "Total Directory Entries")
TotalDynamicSpace 		= uint32("total_dynamic_space", "Total Dynamic Space")
TotalExtendedDirectoryExtants	= uint32("total_extended_directory_extants", "Total Extended Directory Extants")
TotalFileServicePackets		= uint32("total_file_service_packets", "Total File Service Packets")
TotalFilesOpened		= uint32("total_files_opened", "Total Files Opened")
TotalLFSCounters		= uint32("total_lfs_counters", "Total LFS Counters")
TotalOffspring			= uint16("total_offspring", "Total Offspring")
TotalOtherPackets 		= uint32("total_other_packets", "Total Other Packets")
TotalQueueJobs			= uint32("total_queue_jobs", "Total Queue Jobs")
TotalReadRequests		= uint32("total_read_requests", "Total Read Requests")
TotalRequest			= uint32("total_request", "Total Requests")
TotalRequestPackets		= uint32("total_request_packets", "Total Request Packets")
TotalRoutedPackets 		= uint32("total_routed_packets", "Total Routed Packets")
TotalRxPkts                     = uint32("total_rx_pkts", "Total Receive Packets")
TotalServerMemory 		= uint16("total_server_memory", "Total Server Memory", BE)
TotalTransactionsBackedOut	= uint32("total_trans_backed_out", "Total Transactions Backed Out")
TotalTransactionsPerformed	= uint32("total_trans_performed", "Total Transactions Performed")
TotalTxPkts                     = uint32("total_tx_pkts", "Total Transmit Packets")
TotalUnfilledBackoutRequests    = uint16("total_unfilled_backout_requests", "Total Unfilled Backout Requests")
TotalVolumeClusters		= uint16("total_volume_clusters", "Total Volume Clusters")
TotalWriteRequests		= uint32("total_write_requests", "Total Write Requests")
TotalWriteTransactionsPerformed = uint32("total_write_trans_performed", "Total Write Transactions Performed")
TrackOnFlag                     = boolean8("track_on_flag", "Track On Flag")
TransactionDiskSpace		= uint16("transaction_disk_space", "Transaction Disk Space")
TransactionFATAllocations	= uint32("transaction_fat_allocations", "Transaction FAT Allocations")
TransactionFileSizeChanges	= uint32("transaction_file_size_changes", "Transaction File Size Changes")
TransactionFilesTruncated	= uint32("transaction_files_truncated", "Transaction Files Truncated")
TransactionNumber		= uint32("transaction_number", "Transaction Number")
TransactionTrackingEnabled	= uint8("transaction_tracking_enabled", "Transaction Tracking Enabled")
TransactionTrackingFlag		= uint16("tts_flag", "Transaction Tracking Flag")
TransactionTrackingSupported	= uint8("transaction_tracking_supported", "Transaction Tracking Supported")
TransactionVolumeNumber		= uint16("transaction_volume_number", "Transaction Volume Number")
TransportType                   = val_string8("transport_type", "Communications Type", [
        [ 0x01, "Internet Packet Exchange (IPX)" ],
        [ 0x05, "User Datagram Protocol (UDP)" ],
        [ 0x06, "Transmission Control Protocol (TCP)" ],
])
TreeLength			= uint32("tree_length", "Tree Length")
TreeName			= nstring32("tree_name", "Tree Name")
TreeName.NWUnicode()
TrusteeRights		        = bitfield16("trustee_rights_low", "Trustee Rights", [
	bf_boolean16(0x0001, "trustee_rights_read", "Read"),
	bf_boolean16(0x0002, "trustee_rights_write", "Write"),
	bf_boolean16(0x0004, "trustee_rights_open", "Open"),
	bf_boolean16(0x0008, "trustee_rights_create", "Create"),
	bf_boolean16(0x0010, "trustee_rights_del", "Delete"),
	bf_boolean16(0x0020, "trustee_rights_parent", "Parental"),
	bf_boolean16(0x0040, "trustee_rights_search", "Search"),
	bf_boolean16(0x0080, "trustee_rights_modify", "Modify"),
	bf_boolean16(0x0100, "trustee_rights_super", "Supervisor"),
])
TTSLevel			= uint8("tts_level", "TTS Level")
TrusteeSetNumber 		= uint8("trustee_set_number", "Trustee Set Number")
TrusteeID			= uint32("trustee_id_set", "Trustee ID")
TrusteeID.Display("BASE_HEX")
ttlCompBlks                     = uint32("ttl_comp_blks", "Total Compression Blocks")
TtlDSDskSpaceAlloc 		= uint32("ttl_ds_disk_space_alloc", "Total Streams Space Allocated")
TtlEAs				= uint32("ttl_eas", "Total EA's")
TtlEAsDataSize			= uint32("ttl_eas_data_size", "Total EA's Data Size")
TtlEAsKeySize			= uint32("ttl_eas_key_size", "Total EA's Key Size")
ttlIntermediateBlks             = uint32("ttl_inter_blks", "Total Intermediate Blocks")
TtlMigratedSize 		= uint32("ttl_migrated_size", "Total Migrated Size")
TtlNumOfRTags                   = uint32("ttl_num_of_r_tags", "Total Number of Resource Tags")
TtlNumOfSetCmds                 = uint32("ttl_num_of_set_cmds", "Total Number of Set Commands")
TtlValuesLength 		= uint32("ttl_values_length", "Total Values Length")
TtlWriteDataSize		= uint32("ttl_write_data_size", "Total Write Data Size")
TurboUsedForFileService 	= uint16("turbo_used_for_file_service", "Turbo Used For File Service")

UnclaimedPkts                   = uint32("un_claimed_packets", "Unclaimed Packets")
UnCompressableDataStreamsCount	= uint32("un_compressable_data_streams_count", "Uncompressable Data Streams Count")
Undefined8			= bytes("undefined_8", "Undefined", 8)
Undefined28			= bytes("undefined_28", "Undefined", 28)
UndefinedWord			= uint16("undefined_word", "Undefined")
UniqueID			= uint8("unique_id", "Unique ID")
UnknownByte			= uint8("unknown_byte", "Unknown Byte")
Unused				= uint8("un_used", "Unused")
UnusedBlocks			= uint32("unused_blocks", "Unused Blocks")
UnUsedDirectoryEntries		= uint32("un_used_directory_entries", "Unused Directory Entries")
UnusedDiskBlocks		= uint32("unused_disk_blocks", "Unused Disk Blocks")
UnUsedExtendedDirectoryExtants	= uint32("un_used_extended_directory_extants", "Unused Extended Directory Extants")
UpdateDate                      = uint16("update_date", "Update Date")
UpdateDate.NWDate()
UpdateID			= uint32("update_id", "Update ID", BE)
UpdateID.Display("BASE_HEX")
UpdateTime                      = uint16("update_time", "Update Time")
UpdateTime.NWTime()
UseCount 			= val_string16("user_info_use_count", "Use Count", [
	[ 0x0000, "Connection is not in use" ],
	[ 0x0001, "Connection is in use" ],
])
UsedBlocks			= uint32("used_blocks", "Used Blocks")
UserID				= uint32("user_id", "User ID", BE)
UserID.Display("BASE_HEX")
UserLoginAllowed		= val_string8("user_login_allowed", "Login Status", [
	[ 0x00, "Client Login Disabled" ],
	[ 0x01, "Client Login Enabled" ],
])

UserName			= nstring8("user_name", "User Name")
UserName16			= fw_string("user_name_16", "User Name", 16)
UserName48			= fw_string("user_name_48", "User Name", 48)
UserType			= uint16("user_type", "User Type")
UTCTimeInSeconds                = uint32("uts_time_in_seconds", "UTC Time in Seconds")

ValueAvailable			= val_string8("value_available", "Value Available", [
	[ 0x00, "Has No Value" ],
	[ 0xff, "Has Value" ],
])
VAPVersion			= uint8("vap_version", "VAP Version")
VariableBitMask 		= uint32("variable_bit_mask", "Variable Bit Mask")
VariableBitsDefined 		= uint16("variable_bits_defined", "Variable Bits Defined")
VConsoleRevision		= uint8("vconsole_rev", "Console Revision")
VConsoleVersion			= uint8("vconsole_ver", "Console Version")
Verb				= uint32("verb", "Verb")
VerbData			= uint8("verb_data", "Verb Data")
version				= uint32("version", "Version")
VersionNumber			= uint8("version_number", "Version")
VertLocation			= uint16("vert_location", "Vertical Location")
VirtualConsoleVersion		= uint8("virtual_console_version", "Virtual Console Version")
VolumeID			= uint32("volume_id", "Volume ID")
VolumeID.Display("BASE_HEX")
VolInfoReplyLen			= uint16("vol_info_reply_len", "Volume Information Reply Length")
VolumeCachedFlag 		= val_string8("volume_cached_flag", "Volume Cached Flag", [
	[ 0x00, "Volume is Not Cached" ],
	[ 0xff, "Volume is Cached" ],
])
VolumeDataStreams		= uint8("volume_data_streams", "Volume Data Streams")
VolumeHashedFlag 		= val_string8("volume_hashed_flag", "Volume Hashed Flag", [
	[ 0x00, "Volume is Not Hashed" ],
	[ 0xff, "Volume is Hashed" ],
])
VolumeLastModifiedDate  	= uint16("volume_last_modified_date", "Volume Last Modified Date")
VolumeLastModifiedDate.NWDate()
VolumeLastModifiedTime  	= uint16("volume_last_modified_time", "Volume Last Modified Time")
VolumeLastModifiedTime.NWTime()
VolumeMountedFlag 		= val_string8("volume_mounted_flag", "Volume Mounted Flag", [
	[ 0x00, "Volume is Not Mounted" ],
	[ 0xff, "Volume is Mounted" ],
])
VolumeName			= fw_string("volume_name", "Volume Name", 16)
VolumeNameLen			= nstring8("volume_name_len", "Volume Name")
VolumeNameSpaces		= uint8("volume_name_spaces", "Volume Name Spaces")
VolumeNameStringz               = stringz("volume_name_stringz", "Volume Name")
VolumeNumber 			= uint8("volume_number", "Volume Number")
VolumeNumberLong		= uint32("volume_number_long", "Volume Number")
VolumeRemovableFlag 		= val_string8("volume_removable_flag", "Volume Removable Flag", [
	[ 0x00, "Disk Cannot be Removed from Server" ],
	[ 0xff, "Disk Can be Removed from Server" ],
])
VolumeRequestFlags		= val_string16("volume_request_flags", "Volume Request Flags", [
	[ 0x0000, "Return name with volume number" ],
	[ 0x0001, "Do not return name with volume number" ],
])
VolumeSizeInClusters		= uint32("volume_size_in_clusters", "Volume Size in Clusters")
VolumesSupportedMax		= uint16("volumes_supported_max", "Volumes Supported Max")
VolumeType			= val_string16("volume_type", "Volume Type", [
	[ 0x0000, "NetWare 386" ],
	[ 0x0001, "NetWare 286" ],
	[ 0x0002, "NetWare 386 Version 30" ],
	[ 0x0003, "NetWare 386 Version 31" ],
])
WastedServerMemory 		= uint16("wasted_server_memory", "Wasted Server Memory", BE)
WaitTime			= uint32("wait_time", "Wait Time")

Year				= val_string8("year", "Year",[
	[ 0x50, "1980" ],
	[ 0x51, "1981" ],
	[ 0x52, "1982" ],
	[ 0x53, "1983" ],
	[ 0x54, "1984" ],
	[ 0x55, "1985" ],
	[ 0x56, "1986" ],
	[ 0x57, "1987" ],
	[ 0x58, "1988" ],
	[ 0x59, "1989" ],
	[ 0x5a, "1990" ],
	[ 0x5b, "1991" ],
	[ 0x5c, "1992" ],
	[ 0x5d, "1993" ],
	[ 0x5e, "1994" ],
	[ 0x5f, "1995" ],
	[ 0x60, "1996" ],
	[ 0x61, "1997" ],
	[ 0x62, "1998" ],
	[ 0x63, "1999" ],
	[ 0x64, "2000" ],
	[ 0x65, "2001" ],
	[ 0x66, "2002" ],
	[ 0x67, "2003" ],
	[ 0x68, "2004" ],
	[ 0x69, "2005" ],
	[ 0x6a, "2006" ],
	[ 0x6b, "2007" ],
	[ 0x6c, "2008" ],
	[ 0x6d, "2009" ],
	[ 0x6e, "2010" ],
	[ 0x6f, "2011" ],
	[ 0x70, "2012" ],
	[ 0x71, "2013" ],
	[ 0x72, "2014" ],
	[ 0x73, "2015" ],
	[ 0x74, "2016" ],
	[ 0x75, "2017" ],
	[ 0x76, "2018" ],
	[ 0x77, "2019" ],
	[ 0x78, "2020" ],
	[ 0x79, "2021" ],
	[ 0x7a, "2022" ],
	[ 0x7b, "2023" ],
	[ 0x7c, "2024" ],
	[ 0x7d, "2025" ],
	[ 0x7e, "2026" ],
	[ 0x7f, "2027" ],
        [ 0xc0, "1984" ],
        [ 0xc1, "1985" ],
        [ 0xc2, "1986" ],
        [ 0xc3, "1987" ],
        [ 0xc4, "1988" ],
        [ 0xc5, "1989" ],
        [ 0xc6, "1990" ],
        [ 0xc7, "1991" ],
        [ 0xc8, "1992" ],
        [ 0xc9, "1993" ],
        [ 0xca, "1994" ],
        [ 0xcb, "1995" ],
        [ 0xcc, "1996" ],
        [ 0xcd, "1997" ],
        [ 0xce, "1998" ],
        [ 0xcf, "1999" ],
        [ 0xd0, "2000" ],
        [ 0xd1, "2001" ],
        [ 0xd2, "2002" ],
        [ 0xd3, "2003" ],
        [ 0xd4, "2004" ],
        [ 0xd5, "2005" ],
        [ 0xd6, "2006" ],
        [ 0xd7, "2007" ],
        [ 0xd8, "2008" ],
        [ 0xd9, "2009" ],
        [ 0xda, "2010" ],
        [ 0xdb, "2011" ],
        [ 0xdc, "2012" ],
        [ 0xdd, "2013" ],
        [ 0xde, "2014" ],
        [ 0xdf, "2015" ],
])
##############################################################################
# Structs
##############################################################################


acctngInfo                      = struct("acctng_info_struct", [
        HoldTime,
        HoldAmount,
        ChargeAmount,
        HeldConnectTimeInMinutes,
        HeldRequests,
        HeldBytesRead,
        HeldBytesWritten,
],"Accounting Information")
AFP10Struct                       = struct("afp_10_struct", [
	AFPEntryID,
	ParentID,
	AttributesDef16,
	DataForkLen,
	ResourceForkLen,
	TotalOffspring,
	CreationDate,
	LastAccessedDate,
	ModifiedDate,
	ModifiedTime,
	ArchivedDate,
	ArchivedTime,
	CreatorID,
	Reserved4,
	FinderAttr,
	HorizLocation,
	VertLocation,
	FileDirWindow,
	Reserved16,
	LongName,
	CreatorID,
	ShortName,
	AccessPrivileges,
], "AFP Information" )
AFP20Struct                       = struct("afp_20_struct", [
	AFPEntryID,
	ParentID,
	AttributesDef16,
	DataForkLen,
	ResourceForkLen,
	TotalOffspring,
	CreationDate,
	LastAccessedDate,
	ModifiedDate,
	ModifiedTime,
	ArchivedDate,
	ArchivedTime,
	CreatorID,
	Reserved4,
	FinderAttr,
	HorizLocation,
	VertLocation,
	FileDirWindow,
	Reserved16,
	LongName,
	CreatorID,
	ShortName,
	AccessPrivileges,
        Reserved,
	ProDOSInfo,
], "AFP Information" )
ArchiveDateStruct               = struct("archive_date_struct", [
        ArchivedDate,
])
ArchiveIdStruct                 = struct("archive_id_struct", [
        ArchiverID,
])
ArchiveInfoStruct		= struct("archive_info_struct", [
	ArchivedTime,
	ArchivedDate,
	ArchiverID,
], "Archive Information")
ArchiveTimeStruct               = struct("archive_time_struct", [
        ArchivedTime,
])
AttributesStruct		= struct("attributes_struct", [
	AttributesDef32,
	FlagsDef,
], "Attributes")
authInfo                        = struct("auth_info_struct", [
        Status,
        Reserved2,
        Privileges,
])
BoardNameStruct                 = struct("board_name_struct", [
        DriverBoardName,
        DriverShortName,
        DriverLogicalName,
], "Board Name")
CacheInfo			= struct("cache_info", [
        uint32("max_byte_cnt", "Maximum Byte Count"),
	uint32("min_num_of_cache_buff", "Minimum Number Of Cache Buffers"),
	uint32("min_cache_report_thresh", "Minimum Cache Report Threshold"),
	uint32("alloc_waiting", "Allocate Waiting Count"),
	uint32("ndirty_blocks", "Number of Dirty Blocks"),
	uint32("cache_dirty_wait_time", "Cache Dirty Wait Time"),
	uint32("cache_max_concur_writes", "Cache Maximum Concurrent Writes"),
	uint32("max_dirty_time", "Maximum Dirty Time"),
	uint32("num_dir_cache_buff", "Number Of Directory Cache Buffers"),
	uint32("cache_byte_to_block", "Cache Byte To Block Shift Factor"),
], "Cache Information")
CommonLanStruc                  = struct("common_lan_struct", [
        boolean8("not_supported_mask", "Bit Counter Supported"),
        Reserved3,
        uint32("total_tx_packet_count", "Total Transmit Packet Count"),
        uint32("total_rx_packet_count", "Total Receive Packet Count"),
        uint32("no_ecb_available_count", "No ECB Available Count"),
        uint32("packet_tx_too_big_count", "Transmit Packet Too Big Count"),
        uint32("packet_tx_too_small_count", "Transmit Packet Too Small Count"),
        uint32("packet_rx_overflow_count", "Receive Packet Overflow Count"),
        uint32("packet_rx_too_big_count", "Receive Packet Too Big Count"),
        uint32("packet_rs_too_small_count", "Receive Packet Too Small Count"),
        uint32("packet_tx_misc_error_count", "Transmit Packet Misc Error Count"),
        uint32("packet_rx_misc_error_count", "Receive Packet Misc Error Count"),
        uint32("retry_tx_count", "Transmit Retry Count"),
        uint32("checksum_error_count", "Checksum Error Count"),
        uint32("hardware_rx_mismatch_count", "Hardware Receive Mismatch Count"),
], "Common LAN Information")
CompDeCompStat                  = struct("comp_d_comp_stat", [
        uint32("cmphitickhigh", "Compress High Tick"),
        uint32("cmphitickcnt", "Compress High Tick Count"),
        uint32("cmpbyteincount", "Compress Byte In Count"),
        uint32("cmpbyteoutcnt", "Compress Byte Out Count"),
        uint32("cmphibyteincnt", "Compress High Byte In Count"),
        uint32("cmphibyteoutcnt", "Compress High Byte Out Count"),
        uint32("decphitickhigh", "DeCompress High Tick"),
        uint32("decphitickcnt", "DeCompress High Tick Count"),
        uint32("decpbyteincount", "DeCompress Byte In Count"),
        uint32("decpbyteoutcnt", "DeCompress Byte Out Count"),
        uint32("decphibyteincnt", "DeCompress High Byte In Count"),
        uint32("decphibyteoutcnt", "DeCompress High Byte Out Count"),
], "Compression/Decompression Information")
ConnFileStruct			= struct("conn_file_struct", [
	ConnectionNumberWord,
	TaskNumByte,
	LockType,
	AccessControl,
	LockFlag,
], "File Connection Information")
ConnStruct			= struct("conn_struct", [
	TaskNumByte,
	LockType,
	AccessControl,
	LockFlag,
	VolumeNumber,
	DirectoryEntryNumberWord,
	FileName14,
], "Connection Information")
ConnTaskStruct		        = struct("conn_task_struct", [
	ConnectionNumberByte,
	TaskNumByte,
], "Task Information")
Counters			= struct("counters_struct", [
	uint32("read_exist_blck", "Read Existing Block Count"),
	uint32("read_exist_write_wait", "Read Existing Write Wait Count"),
	uint32("read_exist_part_read", "Read Existing Partial Read Count"),
	uint32("read_exist_read_err", "Read Existing Read Error Count"),
	uint32("wrt_blck_cnt", "Write Block Count"),
	uint32("wrt_entire_blck", "Write Entire Block Count"),
	uint32("internl_dsk_get", "Internal Disk Get Count"),
	uint32("internl_dsk_get_need_to_alloc", "Internal Disk Get Need To Allocate Count"),
	uint32("internl_dsk_get_someone_beat", "Internal Disk Get Someone Beat My Count"),
	uint32("internl_dsk_get_part_read", "Internal Disk Get Partial Read Count"),
	uint32("internl_dsk_get_read_err", "Internal Disk Get Read Error Count"),
	uint32("async_internl_dsk_get", "Async Internal Disk Get Count"),
	uint32("async_internl_dsk_get_need_to_alloc", "Async Internal Disk Get Need To Alloc"),
	uint32("async_internl_dsk_get_someone_beat", "Async Internal Disk Get Someone Beat Me"),
	uint32("err_doing_async_read", "Error Doing Async Read Count"),
	uint32("internl_dsk_get_no_read", "Internal Disk Get No Read Count"),
	uint32("internl_dsk_get_no_read_alloc", "Internal Disk Get No Read Allocate Count"),
	uint32("internl_dsk_get_no_read_someone_beat", "Internal Disk Get No Read Someone Beat Me Count"),
	uint32("internl_dsk_write", "Internal Disk Write Count"),
	uint32("internl_dsk_write_alloc", "Internal Disk Write Allocate Count"),
	uint32("internl_dsk_write_someone_beat", "Internal Disk Write Someone Beat Me Count"),
	uint32("write_err", "Write Error Count"),
	uint32("wait_on_sema", "Wait On Semaphore Count"),
	uint32("alloc_blck_i_had_to_wait_for", "Allocate Block I Had To Wait For Someone Count"),
	uint32("alloc_blck", "Allocate Block Count"),
	uint32("alloc_blck_i_had_to_wait", "Allocate Block I Had To Wait Count"),
], "Disk Counter Information")
CPUInformation			= struct("cpu_information", [
	PageTableOwnerFlag,
	CPUType,
        Reserved3,
	CoprocessorFlag,
	BusType,
	Reserved3,
	IOEngineFlag,
	Reserved3,
	FSEngineFlag,
	Reserved3,
	NonDedFlag,
	Reserved3,
	CPUString,
        CoProcessorString,
        BusString,
], "CPU Information")
CreationDateStruct              = struct("creation_date_struct", [
        CreationDate,
])
CreationInfoStruct		= struct("creation_info_struct", [
	CreationTime,
	CreationDate,
	CreatorID,
], "Creation Information")
CreationTimeStruct              = struct("creation_time_struct", [
        CreationTime,
])
CustomCntsInfo                  = struct("custom_cnts_info", [
        CustomVariableValue,
        CustomString,
], "Custom Counters" )
DataStreamInfo			= struct("data_stream_info", [
	AssociatedNameSpace,
	DataStreamName
])
DataStreamSizeStruct		= struct("data_stream_size_struct", [
	DataStreamSize,
])
DirCacheInfo			= struct("dir_cache_info", [
	uint32("min_time_since_file_delete", "Minimum Time Since File Delete"),
	uint32("abs_min_time_since_file_delete", "Absolute Minimum Time Since File Delete"),
	uint32("min_num_of_dir_cache_buff", "Minimum Number Of Directory Cache Buffers"),
	uint32("max_num_of_dir_cache_buff", "Maximum Number Of Directory Cache Buffers"),
	uint32("num_of_dir_cache_buff", "Number Of Directory Cache Buffers"),
	uint32("dc_min_non_ref_time", "DC Minimum Non-Referenced Time"),
	uint32("dc_wait_time_before_new_buff", "DC Wait Time Before New Buffer"),
	uint32("dc_max_concurrent_writes", "DC Maximum Concurrent Writes"),
	uint32("dc_dirty_wait_time", "DC Dirty Wait Time"),
	uint32("dc_double_read_flag", "DC Double Read Flag"),
	uint32("map_hash_node_count", "Map Hash Node Count"),
	uint32("space_restriction_node_count", "Space Restriction Node Count"),
	uint32("trustee_list_node_count", "Trustee List Node Count"),
	uint32("percent_of_vol_used_by_dirs", "Percent Of Volume Used By Directories"),
], "Directory Cache Information")
DirEntryStruct			= struct("dir_entry_struct", [
	DirectoryEntryNumber,
	DOSDirectoryEntryNumber,
	VolumeNumberLong,
], "Directory Entry Information")
DirectoryInstance               = struct("directory_instance", [
        SearchSequenceWord,
        DirectoryID,
        DirectoryName14,
        DirectoryAttributes,
        DirectoryAccessRights,
	endian(CreationDate, BE),
        endian(AccessDate, BE),
	CreatorID,
        Reserved2,
        DirectoryStamp,
], "Directory Information")
DMInfoLevel0                    = struct("dm_info_level_0", [
        uint32("io_flag", "IO Flag"),
        uint32("sm_info_size", "Storage Module Information Size"),
        uint32("avail_space", "Available Space"),
        uint32("used_space", "Used Space"),
        stringz("s_module_name", "Storage Module Name"),
        uint8("s_m_info", "Storage Media Information"),
])
DMInfoLevel1                    = struct("dm_info_level_1", [
        NumberOfSMs,
        SMIDs,
])
DMInfoLevel2                    = struct("dm_info_level_2", [
        Name,
])
DOSDirectoryEntryStruct         = struct("dos_directory_entry_struct", [
        AttributesDef32,
	UniqueID,
	PurgeFlags,
	DestNameSpace,
	DirectoryNameLen,
	DirectoryName,
        CreationTime,
	CreationDate,
	CreatorID,
        ArchivedTime,
	ArchivedDate,
	ArchiverID,
        UpdateTime,
	UpdateDate,
        NextTrusteeEntry,
        Reserved48,
        InheritedRightsMask,
], "DOS Directory Information")
DOSFileEntryStruct              = struct("dos_file_entry_struct", [
        AttributesDef32,
	UniqueID,
	PurgeFlags,
	DestNameSpace,
	NameLen,
	Name12,
        CreationTime,
	CreationDate,
	CreatorID,
        ArchivedTime,
	ArchivedDate,
	ArchiverID,
        UpdateTime,
	UpdateDate,
        UpdateID,
        FileSize,
        DataForkFirstFAT,
        NextTrusteeEntry,
        Reserved36,
        InheritedRightsMask,
        LastAccessedDate,
        Reserved28,
        PrimaryEntry,
        NameList,
], "DOS File Information")
DSSpaceAllocateStruct		= struct("ds_space_alloc_struct", [
	DataStreamSpaceAlloc,
])
DynMemStruct			= struct("dyn_mem_struct", [
	uint32("dyn_mem_struct_total", "Total Dynamic Space" ),
	uint32("dyn_mem_struct_max", "Max Used Dynamic Space" ),
	uint32("dyn_mem_struct_cur", "Current Used Dynamic Space" ),
], "Dynamic Memory Information")
EAInfoStruct			= struct("ea_info_struct", [
	EADataSize,
	EACount,
	EAKeySize,
], "Extended Attribute Information")
ExtraCacheCntrs			= struct("extra_cache_cntrs", [
	uint32("internl_dsk_get_no_wait", "Internal Disk Get No Wait Count"),
	uint32("internl_dsk_get_no_wait_need", "Internal Disk Get No Wait Need To Allocate Count"),
	uint32("internl_dsk_get_no_wait_no_blk", "Internal Disk Get No Wait No Block Count"),
	uint32("id_get_no_read_no_wait", "ID Get No Read No Wait Count"),
	uint32("id_get_no_read_no_wait_sema", "ID Get No Read No Wait Semaphored Count"),
	uint32("id_get_no_read_no_wait_buffer", "ID Get No Read No Wait No Buffer Count"),
	uint32("id_get_no_read_no_wait_alloc", "ID Get No Read No Wait Allocate Count"),
	uint32("id_get_no_read_no_wait_no_alloc", "ID Get No Read No Wait No Alloc Count"),
	uint32("id_get_no_read_no_wait_no_alloc_sema", "ID Get No Read No Wait No Alloc Semaphored Count"),
	uint32("id_get_no_read_no_wait_no_alloc_alloc", "ID Get No Read No Wait No Alloc Allocate Count"),
], "Extra Cache Counters Information")


ReferenceIDStruct               = struct("ref_id_struct", [
        CurrentReferenceID,
])
NSAttributeStruct               = struct("ns_attrib_struct", [
        AttributesDef32,
])
DStreamActual                   = struct("d_stream_actual", [
        Reserved12,
        # Need to look into how to format this correctly
])
DStreamLogical                  = struct("d_string_logical", [
        Reserved12,
        # Need to look into how to format this correctly
])
LastUpdatedInSecondsStruct      = struct("last_update_in_seconds_struct", [
        SecondsRelativeToTheYear2000,
])
DOSNameStruct                   = struct("dos_name_struct", [
        FileName,
], "DOS File Name")
FlushTimeStruct                 = struct("flush_time_struct", [
        FlushTime,
])
ParentBaseIDStruct              = struct("parent_base_id_struct", [
        ParentBaseID,
])
MacFinderInfoStruct             = struct("mac_finder_info_struct", [
        MacFinderInfo,
])
SiblingCountStruct              = struct("sibling_count_struct", [
        SiblingCount,
])
EffectiveRightsStruct           = struct("eff_rights_struct", [
        EffectiveRights,
        Reserved3,
])
MacTimeStruct                   = struct("mac_time_struct", [
        MACCreateDate,
        MACCreateTime,
        MACBackupDate,
        MACBackupTime,
])
LastAccessedTimeStruct          = struct("last_access_time_struct", [
        LastAccessedTime,
])



FileAttributesStruct		= struct("file_attributes_struct", [
	AttributesDef32,
])
FileInfoStruct                  = struct("file_info_struct", [
        ParentID,
        DirectoryEntryNumber,
        TotalBlocksToDecompress,
        CurrentBlockBeingDecompressed,
], "File Information")
FileInstance                    = struct("file_instance", [
        SearchSequenceWord,
        DirectoryID,
        FileName14,
        AttributesDef,
        FileMode,
        FileSize,
	endian(CreationDate, BE),
        endian(AccessDate, BE),
	endian(UpdateDate, BE),
        endian(UpdateTime, BE),
], "File Instance")
FileNameStruct                  = struct("file_name_struct", [
        FileName,
], "File Name")
FileServerCounters		= struct("file_server_counters", [
	uint16("too_many_hops", "Too Many Hops"),
	uint16("unknown_network", "Unknown Network"),
	uint16("no_space_for_service", "No Space For Service"),
	uint16("no_receive_buff", "No Receive Buffers"),
	uint16("not_my_network", "Not My Network"),
	uint32("netbios_progated", "NetBIOS Propagated Count"),
	uint32("ttl_pckts_srvcd", "Total Packets Serviced"),
	uint32("ttl_pckts_routed", "Total Packets Routed"),
], "File Server Counters")
FileSystemInfo			= struct("file_system_info", [
	uint32("fat_moved", "Number of times the OS has move the location of FAT"),
	uint32("fat_write_err", "Number of write errors in both original and mirrored copies of FAT"),
	uint32("someone_else_did_it_0", "Someone Else Did It Count 0"),
	uint32("someone_else_did_it_1", "Someone Else Did It Count 1"),
	uint32("someone_else_did_it_2", "Someone Else Did It Count 2"),
	uint32("i_ran_out_someone_else_did_it_0", "I Ran Out Someone Else Did It Count 0"),
	uint32("i_ran_out_someone_else_did_it_1", "I Ran Out Someone Else Did It Count 1"),
	uint32("i_ran_out_someone_else_did_it_2", "I Ran Out Someone Else Did It Count 2"),
	uint32("turbo_fat_build_failed", "Turbo FAT Build Failed Count"),
	uint32("extra_use_count_node_count", "Errors allocating a use count node for TTS"),
	uint32("extra_extra_use_count_node_count", "Errors allocating an additional use count node for TTS"),
	uint32("error_read_last_fat", "Error Reading Last FAT Count"),
	uint32("someone_else_using_this_file", "Someone Else Using This File Count"),
], "File System Information")
GenericInfoDef                  = struct("generic_info_def", [
        fw_string("generic_label", "Label", 64),
        uint32("generic_ident_type", "Identification Type"),
        uint32("generic_ident_time", "Identification Time"),
        uint32("generic_media_type", "Media Type"),
        uint32("generic_cartridge_type", "Cartridge Type"),
        uint32("generic_unit_size", "Unit Size"),
        uint32("generic_block_size", "Block Size"),
        uint32("generic_capacity", "Capacity"),
        uint32("generic_pref_unit_size", "Preferred Unit Size"),
        fw_string("generic_name", "Name",64),
        uint32("generic_type", "Type"),
        uint32("generic_status", "Status"),
        uint32("generic_func_mask", "Function Mask"),
        uint32("generic_ctl_mask", "Control Mask"),
        uint32("generic_parent_count", "Parent Count"),
        uint32("generic_sib_count", "Sibling Count"),
        uint32("generic_child_count", "Child Count"),
        uint32("generic_spec_info_sz", "Specific Information Size"),
        uint32("generic_object_uniq_id", "Unique Object ID"),
        uint32("generic_media_slot", "Media Slot"),
], "Generic Information")
HandleInfoLevel0                = struct("handle_info_level_0", [
#        DataStream,
])
HandleInfoLevel1                = struct("handle_info_level_1", [
        DataStream,
])
HandleInfoLevel2                = struct("handle_info_level_2", [
        DOSDirectoryBase,
        NameSpace,
        DataStream,
])
HandleInfoLevel3                = struct("handle_info_level_3", [
        DOSDirectoryBase,
        NameSpace,
])
HandleInfoLevel4                = struct("handle_info_level_4", [
        DOSDirectoryBase,
        NameSpace,
        ParentDirectoryBase,
        ParentDOSDirectoryBase,
])
HandleInfoLevel5                = struct("handle_info_level_5", [
        DOSDirectoryBase,
        NameSpace,
        DataStream,
        ParentDirectoryBase,
        ParentDOSDirectoryBase,
])
IPXInformation			= struct("ipx_information", [
	uint32("ipx_send_pkt", "IPX Send Packet Count"),
	uint16("ipx_malform_pkt", "IPX Malformed Packet Count"),
	uint32("ipx_get_ecb_req", "IPX Get ECB Request Count"),
	uint32("ipx_get_ecb_fail", "IPX Get ECB Fail Count"),
	uint32("ipx_aes_event", "IPX AES Event Count"),
	uint16("ipx_postponed_aes", "IPX Postponed AES Count"),
	uint16("ipx_max_conf_sock", "IPX Max Configured Socket Count"),
	uint16("ipx_max_open_sock", "IPX Max Open Socket Count"),
	uint16("ipx_open_sock_fail", "IPX Open Socket Fail Count"),
	uint32("ipx_listen_ecb", "IPX Listen ECB Count"),
	uint16("ipx_ecb_cancel_fail", "IPX ECB Cancel Fail Count"),
	uint16("ipx_get_lcl_targ_fail", "IPX Get Local Target Fail Count"),
], "IPX Information")
JobEntryTime			= struct("job_entry_time", [
	Year,
	Month,
	Day,
	Hour,
	Minute,
	Second,
], "Job Entry Time")
JobStruct3x                       = struct("job_struct_3x", [
    RecordInUseFlag,
    PreviousRecord,
    NextRecord,
	ClientStationLong,
        ClientTaskNumberLong,
        ClientIDNumber,
	TargetServerIDNumber,
	TargetExecutionTime,
        JobEntryTime,
	JobNumberLong,
	JobType,
	JobPositionWord,
	JobControlFlagsWord,
	JobFileName,
	JobFileHandleLong,
	ServerStationLong,
	ServerTaskNumberLong,
	ServerID,
        TextJobDescription,
        ClientRecordArea,
], "Job Information")
JobStruct                       = struct("job_struct", [
	ClientStation,
        ClientTaskNumber,
        ClientIDNumber,
	TargetServerIDNumber,
	TargetExecutionTime,
        JobEntryTime,
	JobNumber,
	JobType,
	JobPosition,
	JobControlFlags,
	JobFileName,
	JobFileHandle,
	ServerStation,
	ServerTaskNumber,
	ServerID,
        TextJobDescription,
        ClientRecordArea,
], "Job Information")
JobStructNew                    = struct("job_struct_new", [
	RecordInUseFlag,
	PreviousRecord,
	NextRecord,
	ClientStationLong,
	ClientTaskNumberLong,
	ClientIDNumber,
        TargetServerIDNumber,
	TargetExecutionTime,
	JobEntryTime,
	JobNumberLong,
	JobType,
	JobPositionWord,
	JobControlFlagsWord,
	JobFileName,
	JobFileHandleLong,
	ServerStationLong,
	ServerTaskNumberLong,
	ServerID,
], "Job Information")
KnownRoutes                     = struct("known_routes", [
        NetIDNumber,
        HopsToNet,
        NetStatus,
        TimeToNet,
], "Known Routes")
KnownServStruc                  = struct("known_server_struct", [
        ServerAddress,
        HopsToNet,
        ServerNameStringz,
], "Known Servers")
LANConfigInfo                   = struct("lan_cfg_info", [
        LANdriverCFG_MajorVersion,
        LANdriverCFG_MinorVersion,
        LANdriverNodeAddress,
        Reserved,
        LANdriverModeFlags,
        LANdriverBoardNumber,
        LANdriverBoardInstance,
        LANdriverMaximumSize,
        LANdriverMaxRecvSize,
        LANdriverRecvSize,
        LANdriverCardID,
        LANdriverMediaID,
        LANdriverTransportTime,
        LANdriverSrcRouting,
        LANdriverLineSpeed,
        LANdriverReserved,
        LANdriverMajorVersion,
        LANdriverMinorVersion,
        LANdriverFlags,
        LANdriverSendRetries,
        LANdriverLink,
        LANdriverSharingFlags,
        LANdriverSlot,
        LANdriverIOPortsAndRanges1,
        LANdriverIOPortsAndRanges2,
        LANdriverIOPortsAndRanges3,
        LANdriverIOPortsAndRanges4,
        LANdriverMemoryDecode0,
        LANdriverMemoryLength0,
        LANdriverMemoryDecode1,
        LANdriverMemoryLength1,
        LANdriverInterrupt1,
        LANdriverInterrupt2,
        LANdriverDMAUsage1,
        LANdriverDMAUsage2,
        LANdriverLogicalName,
        LANdriverIOReserved,
        LANdriverCardName,
], "LAN Configuration Information")
LastAccessStruct                = struct("last_access_struct", [
        LastAccessedDate,
])
lockInfo                        = struct("lock_info_struct", [
        LogicalLockThreshold,
        PhysicalLockThreshold,
        FileLockCount,
        RecordLockCount,
], "Lock Information")
LockStruct			= struct("lock_struct", [
	TaskNumByte,
	LockType,
	RecordStart,
	RecordEnd,
], "Locks")
LoginTime                       = struct("login_time", [
	Year,
	Month,
	Day,
	Hour,
	Minute,
	Second,
	DayOfWeek,
], "Login Time")
LogLockStruct			= struct("log_lock_struct", [
	TaskNumByte,
	LockStatus,
	LockName,
], "Logical Locks")
LogRecStruct			= struct("log_rec_struct", [
	ConnectionNumberWord,
	TaskNumByte,
	LockStatus,
], "Logical Record Locks")
LSLInformation                  = struct("lsl_information", [
        uint32("rx_buffers", "Receive Buffers"),
        uint32("rx_buffers_75", "Receive Buffers Warning Level"),
        uint32("rx_buffers_checked_out", "Receive Buffers Checked Out Count"),
        uint32("rx_buffer_size", "Receive Buffer Size"),
        uint32("max_phy_packet_size", "Maximum Physical Packet Size"),
        uint32("last_time_rx_buff_was_alloc", "Last Time a Receive Buffer was Allocated"),
        uint32("max_num_of_protocols", "Maximum Number of Protocols"),
        uint32("max_num_of_media_types", "Maximum Number of Media Types"),
        uint32("total_tx_packets", "Total Transmit Packets"),
        uint32("get_ecb_buf", "Get ECB Buffers"),
        uint32("get_ecb_fails", "Get ECB Failures"),
        uint32("aes_event_count", "AES Event Count"),
        uint32("post_poned_events", "Postponed Events"),
        uint32("ecb_cxl_fails", "ECB Cancel Failures"),
        uint32("valid_bfrs_reused", "Valid Buffers Reused"),
        uint32("enqueued_send_cnt", "Enqueued Send Count"),
        uint32("total_rx_packets", "Total Receive Packets"),
        uint32("unclaimed_packets", "Unclaimed Packets"),
        uint8("stat_table_major_version", "Statistics Table Major Version"),
        uint8("stat_table_minor_version", "Statistics Table Minor Version"),
], "LSL Information")
MaximumSpaceStruct              = struct("max_space_struct", [
        MaxSpace,
])
MemoryCounters			= struct("memory_counters", [
	uint32("orig_num_cache_buff", "Original Number Of Cache Buffers"),
	uint32("curr_num_cache_buff", "Current Number Of Cache Buffers"),
	uint32("cache_dirty_block_thresh", "Cache Dirty Block Threshold"),
	uint32("wait_node", "Wait Node Count"),
	uint32("wait_node_alloc_fail", "Wait Node Alloc Failure Count"),
	uint32("move_cache_node", "Move Cache Node Count"),
	uint32("move_cache_node_from_avai", "Move Cache Node From Avail Count"),
	uint32("accel_cache_node_write", "Accelerate Cache Node Write Count"),
	uint32("rem_cache_node", "Remove Cache Node Count"),
	uint32("rem_cache_node_from_avail", "Remove Cache Node From Avail Count"),
], "Memory Counters")
MLIDBoardInfo                   = struct("mlid_board_info", [
        uint32("protocol_board_num", "Protocol Board Number"),
        uint16("protocol_number", "Protocol Number"),
        bytes("protocol_id", "Protocol ID", 6),
        nstring8("protocol_name", "Protocol Name"),
], "MLID Board Information")
ModifyInfoStruct		= struct("modify_info_struct", [
	ModifiedTime,
	ModifiedDate,
	ModifierID,
	LastAccessedDate,
], "Modification Information")
nameInfo                        = struct("name_info_struct", [
        ObjectType,
        nstring8("login_name", "Login Name"),
], "Name Information")
NCPNetworkAddress               = struct("ncp_network_address_struct", [
        TransportType,
        Reserved3,
        NetAddress,
], "Network Address")

netAddr                         = struct("net_addr_struct", [
        TransportType,
        nbytes32("transport_addr", "Transport Address"),
], "Network Address")

NetWareInformationStruct	= struct("netware_information_struct", [
	DataStreamSpaceAlloc, 		# (Data Stream Alloc Bit)
	AttributesDef32,		# (Attributes Bit)
	FlagsDef,
	DataStreamSize, 		# (Data Stream Size Bit)
	TotalDataStreamDiskSpaceAlloc,	# (Total Stream Size Bit)
	NumberOfDataStreams,
 	CreationTime,			# (Creation Bit)
	CreationDate,
	CreatorID,
	ModifiedTime,			# (Modify Bit)
	ModifiedDate,
	ModifierID,
	LastAccessedDate,
	ArchivedTime,			# (Archive Bit)
	ArchivedDate,
	ArchiverID,
	InheritedRightsMask,		# (Rights Bit)
	DirectoryEntryNumber,		# (Directory Entry Bit)
	DOSDirectoryEntryNumber,
	VolumeNumberLong,
	EADataSize,			# (Extended Attribute Bit)
	EACount,
	EAKeySize,
	CreatorNameSpaceNumber,		# (Name Space Bit)
	Reserved3,
], "NetWare Information")
NLMInformation			= struct("nlm_information", [
	IdentificationNumber,
	NLMFlags,
	Reserved3,
	NLMType,
	Reserved3,
	ParentID,
	MajorVersion,
	MinorVersion,
	Revision,
	Year,
	Reserved3,
	Month,
	Reserved3,
	Day,
	Reserved3,
	AllocAvailByte,
	AllocFreeCount,
	LastGarbCollect,
	MessageLanguage,
	NumberOfReferencedPublics,
], "NLM Information")
NSInfoStruct			= struct("ns_info_struct", [
	NameSpace,
	Reserved3,
])
NWAuditStatus			= struct("nw_audit_status", [
	AuditVersionDate,
        AuditFileVersionDate,
	val_string16("audit_enable_flag", "Auditing Enabled Flag", [
		[ 0x0000, "Auditing Disabled" ],
		[ 0x0100, "Auditing Enabled" ],
	]),
	Reserved2,
	uint32("audit_file_size", "Audit File Size"),
	uint32("modified_counter", "Modified Counter"),
	uint32("audit_file_max_size", "Audit File Maximum Size"),
	uint32("audit_file_size_threshold", "Audit File Size Threshold"),
	uint32("audit_record_count", "Audit Record Count"),
	uint32("auditing_flags", "Auditing Flags"),
], "NetWare Audit Status")
ObjectSecurityStruct            = struct("object_security_struct", [
        ObjectSecurity,
])
ObjectFlagsStruct               = struct("object_flags_struct", [
        ObjectFlags,
])
ObjectTypeStruct                = struct("object_type_struct", [
        ObjectType,
        Reserved2,
])
ObjectNameStruct                = struct("object_name_struct", [
        ObjectNameStringz,
])
ObjectIDStruct			= struct("object_id_struct", [
	ObjectID,
	Restriction,
])
OpnFilesStruct			= struct("opn_files_struct", [
	TaskNumberWord,
	LockType,
	AccessControl,
	LockFlag,
	VolumeNumber,
	DOSParentDirectoryEntry,
	DOSDirectoryEntry,
	ForkCount,
	NameSpace,
	FileName,
], "Open Files Information")
OwnerIDStruct                   = struct("owner_id_struct", [
        CreatorID,
])
PacketBurstInformation		= struct("packet_burst_information", [
	uint32("big_invalid_slot", "Big Invalid Slot Count"),
	uint32("big_forged_packet", "Big Forged Packet Count"),
	uint32("big_invalid_packet", "Big Invalid Packet Count"),
	uint32("big_still_transmitting", "Big Still Transmitting Count"),
	uint32("still_doing_the_last_req", "Still Doing The Last Request Count"),
	uint32("invalid_control_req", "Invalid Control Request Count"),
	uint32("control_invalid_message_number", "Control Invalid Message Number Count"),
	uint32("control_being_torn_down", "Control Being Torn Down Count"),
	uint32("big_repeat_the_file_read", "Big Repeat the File Read Count"),
	uint32("big_send_extra_cc_count", "Big Send Extra CC Count"),
	uint32("big_return_abort_mess", "Big Return Abort Message Count"),
	uint32("big_read_invalid_mess", "Big Read Invalid Message Number Count"),
	uint32("big_read_do_it_over", "Big Read Do It Over Count"),
	uint32("big_read_being_torn_down", "Big Read Being Torn Down Count"),
	uint32("previous_control_packet", "Previous Control Packet Count"),
	uint32("send_hold_off_message", "Send Hold Off Message Count"),
	uint32("big_read_no_data_avail", "Big Read No Data Available Count"),
	uint32("big_read_trying_to_read", "Big Read Trying To Read Too Much Count"),
	uint32("async_read_error", "Async Read Error Count"),
	uint32("big_read_phy_read_err", "Big Read Physical Read Error Count"),
	uint32("ctl_bad_ack_frag_list", "Control Bad ACK Fragment List Count"),
	uint32("ctl_no_data_read", "Control No Data Read Count"),
	uint32("write_dup_req", "Write Duplicate Request Count"),
	uint32("shouldnt_be_ack_here", "Shouldn't Be ACKing Here Count"),
	uint32("write_incon_packet_len", "Write Inconsistent Packet Lengths Count"),
	uint32("first_packet_isnt_a_write", "First Packet Isn't A Write Count"),
	uint32("write_trash_dup_req", "Write Trashed Duplicate Request Count"),
	uint32("big_write_inv_message_num", "Big Write Invalid Message Number Count"),
	uint32("big_write_being_torn_down", "Big Write Being Torn Down Count"),
	uint32("big_write_being_abort", "Big Write Being Aborted Count"),
	uint32("zero_ack_frag", "Zero ACK Fragment Count"),
	uint32("write_curr_trans", "Write Currently Transmitting Count"),
	uint32("try_to_write_too_much", "Trying To Write Too Much Count"),
	uint32("write_out_of_mem_for_ctl_nodes", "Write Out Of Memory For Control Nodes Count"),
	uint32("write_didnt_need_this_frag", "Write Didn't Need This Fragment Count"),
	uint32("write_too_many_buf_check", "Write Too Many Buffers Checked Out Count"),
	uint32("write_timeout", "Write Time Out Count"),
	uint32("write_got_an_ack0", "Write Got An ACK Count 0"),
	uint32("write_got_an_ack1", "Write Got An ACK Count 1"),
	uint32("poll_abort_conn", "Poller Aborted The Connnection Count"),
	uint32("may_had_out_of_order", "Maybe Had Out Of Order Writes Count"),
	uint32("had_an_out_of_order", "Had An Out Of Order Write Count"),
	uint32("moved_the_ack_bit_dn", "Moved The ACK Bit Down Count"),
	uint32("bumped_out_of_order", "Bumped Out Of Order Write Count"),
	uint32("poll_rem_old_out_of_order", "Poller Removed Old Out Of Order Count"),
	uint32("write_didnt_need_but_req_ack", "Write Didn't Need But Requested ACK Count"),
	uint32("write_trash_packet", "Write Trashed Packet Count"),
	uint32("too_many_ack_frag", "Too Many ACK Fragments Count"),
	uint32("saved_an_out_of_order_packet", "Saved An Out Of Order Packet Count"),
	uint32("conn_being_aborted", "Connection Being Aborted Count"),
], "Packet Burst Information")

PadDSSpaceAllocate	        = struct("pad_ds_space_alloc", [
    Reserved4,
])
PadAttributes       		= struct("pad_attributes", [
    Reserved6,
])
PadDataStreamSize               = struct("pad_data_stream_size", [
    Reserved4,
])
PadTotalStreamSize	        = struct("pad_total_stream_size", [
    Reserved6,
])
PadCreationInfo		        = struct("pad_creation_info", [
    Reserved8,
])
PadModifyInfo		        = struct("pad_modify_info", [
    Reserved10,
])
PadArchiveInfo  	        = struct("pad_archive_info", [
    Reserved8,
])
PadRightsInfo		        = struct("pad_rights_info", [
    Reserved2,
])
PadDirEntry		        = struct("pad_dir_entry", [
    Reserved12,
])
PadEAInfo		        = struct("pad_ea_info", [
    Reserved12,
])
PadNSInfo		        = struct("pad_ns_info", [
    Reserved4,
])
PhyLockStruct			= struct("phy_lock_struct", [
	LoggedCount,
	ShareableLockCount,
	RecordStart,
	RecordEnd,
	LogicalConnectionNumber,
	TaskNumByte,
	LockType,
], "Physical Locks")
printInfo                       = struct("print_info_struct", [
        PrintFlags,
        TabSize,
        Copies,
        PrintToFileFlag,
        BannerName,
        TargetPrinter,
        FormType,
], "Print Information")
RightsInfoStruct		= struct("rights_info_struct", [
	InheritedRightsMask,
])
RoutersInfo                     = struct("routers_info", [
        bytes("node", "Node", 6),
        ConnectedLAN,
        uint16("route_hops", "Hop Count"),
        uint16("route_time", "Route Time"),
], "Router Information")
RTagStructure                   = struct("r_tag_struct", [
        RTagNumber,
        ResourceSignature,
        ResourceCount,
        ResourceName,
], "Resource Tag")
ScanInfoFileName                = struct("scan_info_file_name", [
        SalvageableFileEntryNumber,
        FileName,
])
ScanInfoFileNoName              = struct("scan_info_file_no_name", [
        SalvageableFileEntryNumber,
])
Segments                        = struct("segments", [
        uint32("volume_segment_dev_num", "Volume Segment Device Number"),
        uint32("volume_segment_offset", "Volume Segment Offset"),
        uint32("volume_segment_size", "Volume Segment Size"),
], "Volume Segment Information")
SemaInfoStruct			= struct("sema_info_struct", [
	LogicalConnectionNumber,
	TaskNumByte,
])
SemaStruct			= struct("sema_struct", [
	OpenCount,
	SemaphoreValue,
	TaskNumByte,
	SemaphoreName,
], "Semaphore Information")
ServerInfo			= struct("server_info", [
	uint32("reply_canceled", "Reply Canceled Count"),
	uint32("write_held_off", "Write Held Off Count"),
	uint32("write_held_off_with_dup", "Write Held Off With Duplicate Request"),
	uint32("invalid_req_type", "Invalid Request Type Count"),
	uint32("being_aborted", "Being Aborted Count"),
	uint32("already_doing_realloc", "Already Doing Re-Allocate Count"),
	uint32("dealloc_invalid_slot", "De-Allocate Invalid Slot Count"),
	uint32("dealloc_being_proc", "De-Allocate Being Processed Count"),
	uint32("dealloc_forged_packet", "De-Allocate Forged Packet Count"),
	uint32("dealloc_still_transmit", "De-Allocate Still Transmitting Count"),
	uint32("start_station_error", "Start Station Error Count"),
	uint32("invalid_slot", "Invalid Slot Count"),
	uint32("being_processed", "Being Processed Count"),
	uint32("forged_packet", "Forged Packet Count"),
	uint32("still_transmitting", "Still Transmitting Count"),
	uint32("reexecute_request", "Re-Execute Request Count"),
	uint32("invalid_sequence_number", "Invalid Sequence Number Count"),
	uint32("dup_is_being_sent", "Duplicate Is Being Sent Already Count"),
	uint32("sent_pos_ack", "Sent Positive Acknowledge Count"),
	uint32("sent_a_dup_reply", "Sent A Duplicate Reply Count"),
	uint32("no_mem_for_station", "No Memory For Station Control Count"),
	uint32("no_avail_conns", "No Available Connections Count"),
	uint32("realloc_slot", "Re-Allocate Slot Count"),
	uint32("realloc_slot_came_too_soon", "Re-Allocate Slot Came Too Soon Count"),
], "Server Information")
ServersSrcInfo                  = struct("servers_src_info", [
        ServerNode,
        ConnectedLAN,
        HopsToNet,
], "Source Server Information")
SpaceStruct                     = struct("space_struct", [
	Level,
	MaxSpace,
	CurrentSpace,
], "Space Information")
SPXInformation			= struct("spx_information", [
	uint16("spx_max_conn", "SPX Max Connections Count"),
	uint16("spx_max_used_conn", "SPX Max Used Connections"),
	uint16("spx_est_conn_req", "SPX Establish Connection Requests"),
	uint16("spx_est_conn_fail", "SPX Establish Connection Fail"),
	uint16("spx_listen_con_req", "SPX Listen Connect Request"),
	uint16("spx_listen_con_fail", "SPX Listen Connect Fail"),
	uint32("spx_send", "SPX Send Count"),
	uint32("spx_window_choke", "SPX Window Choke Count"),
	uint16("spx_bad_send", "SPX Bad Send Count"),
	uint16("spx_send_fail", "SPX Send Fail Count"),
	uint16("spx_abort_conn", "SPX Aborted Connection"),
	uint32("spx_listen_pkt", "SPX Listen Packet Count"),
	uint16("spx_bad_listen", "SPX Bad Listen Count"),
	uint32("spx_incoming_pkt", "SPX Incoming Packet Count"),
	uint16("spx_bad_in_pkt", "SPX Bad In Packet Count"),
	uint16("spx_supp_pkt", "SPX Suppressed Packet Count"),
	uint16("spx_no_ses_listen", "SPX No Session Listen ECB Count"),
	uint16("spx_watch_dog", "SPX Watch Dog Destination Session Count"),
], "SPX Information")
StackInfo                       = struct("stack_info", [
        StackNumber,
        fw_string("stack_short_name", "Stack Short Name", 16),
], "Stack Information")
statsInfo                       = struct("stats_info_struct", [
        TotalBytesRead,
        TotalBytesWritten,
        TotalRequest,
], "Statistics")
theTimeStruct                   = struct("the_time_struct", [
        UTCTimeInSeconds,
        FractionalSeconds,
        TimesyncStatus,
])
timeInfo                        = struct("time_info", [
       	Year,
	Month,
	Day,
	Hour,
	Minute,
	Second,
	DayOfWeek,
        uint32("login_expiration_time", "Login Expiration Time"),
])
TotalStreamSizeStruct		= struct("total_stream_size_struct", [
	TotalDataStreamDiskSpaceAlloc,
	NumberOfDataStreams,
])
TrendCounters			= struct("trend_counters", [
	uint32("num_of_cache_checks", "Number Of Cache Checks"),
	uint32("num_of_cache_hits", "Number Of Cache Hits"),
	uint32("num_of_dirty_cache_checks", "Number Of Dirty Cache Checks"),
	uint32("num_of_cache_dirty_checks", "Number Of Cache Dirty Checks"),
	uint32("cache_used_while_check", "Cache Used While Checking"),
	uint32("wait_till_dirty_blcks_dec", "Wait Till Dirty Blocks Decrease Count"),
	uint32("alloc_blck_frm_avail", "Allocate Block From Available Count"),
	uint32("alloc_blck_frm_lru", "Allocate Block From LRU Count"),
	uint32("alloc_blck_already_wait", "Allocate Block Already Waiting"),
	uint32("lru_sit_time", "LRU Sitting Time"),
	uint32("num_of_cache_check_no_wait", "Number Of Cache Check No Wait"),
	uint32("num_of_cache_hits_no_wait", "Number Of Cache Hits No Wait"),
], "Trend Counters")
TrusteeStruct			= struct("trustee_struct", [
	endian(ObjectID, LE),
	AccessRightsMaskWord,
])
UpdateDateStruct                = struct("update_date_struct", [
        UpdateDate,
])
UpdateIDStruct                  = struct("update_id_struct", [
        UpdateID,
])
UpdateTimeStruct                = struct("update_time_struct", [
        UpdateTime,
])
UserInformation			= struct("user_info", [
	ConnectionNumber,
	UseCount,
	Reserved2,
	ConnectionServiceType,
	Year,
	Month,
	Day,
	Hour,
	Minute,
	Second,
	DayOfWeek,
	Status,
	Reserved2,
	ExpirationTime,
	ObjectType,
	Reserved2,
	TransactionTrackingFlag,
	LogicalLockThreshold,
	FileWriteFlags,
	FileWriteState,
	Reserved,
	FileLockCount,
	RecordLockCount,
	TotalBytesRead,
	TotalBytesWritten,
	TotalRequest,
	HeldRequests,
	HeldBytesRead,
	HeldBytesWritten,
], "User Information")
VolInfoStructure                = struct("vol_info_struct", [
        VolumeType,
        Reserved2,
	StatusFlagBits,
        SectorSize,
        SectorsPerClusterLong,
        VolumeSizeInClusters,
        FreedClusters,
        SubAllocFreeableClusters,
        FreeableLimboSectors,
        NonFreeableLimboSectors,
        NonFreeableAvailableSubAllocSectors,
        NotUsableSubAllocSectors,
        SubAllocClusters,
        DataStreamsCount,
        LimboDataStreamsCount,
        OldestDeletedFileAgeInTicks,
        CompressedDataStreamsCount,
        CompressedLimboDataStreamsCount,
        UnCompressableDataStreamsCount,
        PreCompressedSectors,
        CompressedSectors,
        MigratedFiles,
        MigratedSectors,
        ClustersUsedByFAT,
        ClustersUsedByDirectories,
        ClustersUsedByExtendedDirectories,
        TotalDirectoryEntries,
        UnUsedDirectoryEntries,
        TotalExtendedDirectoryExtants,
        UnUsedExtendedDirectoryExtants,
        ExtendedAttributesDefined,
        ExtendedAttributeExtantsUsed,
        DirectoryServicesObjectID,
        VolumeLastModifiedTime,
        VolumeLastModifiedDate,
], "Volume Information")
VolInfo2Struct                  = struct("vol_info_struct_2", [
        uint32("volume_active_count", "Volume Active Count"),
        uint32("volume_use_count", "Volume Use Count"),
        uint32("mac_root_ids", "MAC Root IDs"),
        VolumeLastModifiedTime,
        VolumeLastModifiedDate,
        uint32("volume_reference_count", "Volume Reference Count"),
        uint32("compression_lower_limit", "Compression Lower Limit"),
        uint32("outstanding_ios", "Outstanding IOs"),
        uint32("outstanding_compression_ios", "Outstanding Compression IOs"),
        uint32("compression_ios_limit", "Compression IOs Limit"),
], "Extended Volume Information")
VolumeStruct                    = struct("volume_struct", [
        VolumeNumberLong,
        VolumeNameLen,
])


##############################################################################
# NCP Groups
##############################################################################
def define_groups():
	groups['accounting']	= "Accounting"
	groups['afp']		= "AFP"
	groups['auditing']	= "Auditing"
	groups['bindery']	= "Bindery"
	groups['comm']		= "Communication"
	groups['connection']	= "Connection"
	groups['directory']	= "Directory"
	groups['extended']	= "Extended Attribute"
	groups['file']		= "File"
	groups['fileserver']	= "File Server"
	groups['message']	= "Message"
	groups['migration']	= "Data Migration"
	groups['misc']		= "Miscellaneous"
	groups['name']		= "Name Space"
	groups['nds']		= "NetWare Directory"
	groups['print']		= "Print"
	groups['queue']		= "Queue"
	groups['sync']		= "Synchronization"
	groups['tts']		= "Transaction Tracking"
	groups['qms']		= "Queue Management System (QMS)"
	groups['stats']		= "Server Statistics"
	groups['nmas']		= "Novell Modular Authentication Service"
	groups['sss']		= "SecretStore Services"
	groups['unknown']	= "Unknown"

##############################################################################
# NCP Errors
##############################################################################
def define_errors():
    	errors[0x0000] = "Ok"
    	errors[0x0001] = "Transaction tracking is available"
    	errors[0x0002] = "Ok. The data has been written"
    	errors[0x0003] = "Calling Station is a Manager"

    	errors[0x0100] = "One or more of the Connection Numbers in the send list are invalid"
    	errors[0x0101] = "Invalid space limit"
    	errors[0x0102] = "Insufficient disk space"
    	errors[0x0103] = "Queue server cannot add jobs"
    	errors[0x0104] = "Out of disk space"
    	errors[0x0105] = "Semaphore overflow"
    	errors[0x0106] = "Invalid Parameter"
    	errors[0x0107] = "Invalid Number of Minutes to Delay"
        errors[0x0108] = "Invalid Start or Network Number"
        errors[0x0109] = "Cannot Obtain License"

    	errors[0x0200] = "One or more clients in the send list are not logged in"
    	errors[0x0201] = "Queue server cannot attach"

    	errors[0x0300] = "One or more clients in the send list are not accepting messages"

    	errors[0x0400] = "Client already has message"
    	errors[0x0401] = "Queue server cannot service job"

    	errors[0x7300] = "Revoke Handle Rights Not Found"
        errors[0x7900] = "Invalid Parameter in Request Packet"
        errors[0x7901] = "Nothing being Compressed"
    	errors[0x7a00] = "Connection Already Temporary"
    	errors[0x7b00] = "Connection Already Logged in"
    	errors[0x7c00] = "Connection Not Authenticated"

    	errors[0x7e00] = "NCP failed boundary check"
    	errors[0x7e01] = "Invalid Length"

    	errors[0x7f00] = "Lock Waiting"
    	errors[0x8000] = "Lock fail"
        errors[0x8001] = "File in Use"

    	errors[0x8100] = "A file handle could not be allocated by the file server"
    	errors[0x8101] = "Out of File Handles"

    	errors[0x8200] = "Unauthorized to open the file"
    	errors[0x8300] = "Unable to read/write the volume. Possible bad sector on the file server"
    	errors[0x8301] = "Hard I/O Error"

    	errors[0x8400] = "Unauthorized to create the directory"
    	errors[0x8401] = "Unauthorized to create the file"

    	errors[0x8500] = "Unauthorized to delete the specified file"
    	errors[0x8501] = "Unauthorized to overwrite an existing file in this directory"

    	errors[0x8700] = "An unexpected character was encountered in the filename"
    	errors[0x8701] = "Create Filename Error"

    	errors[0x8800] = "Invalid file handle"
    	errors[0x8900] = "Unauthorized to search this file/directory"
    	errors[0x8a00] = "Unauthorized to delete this file/directory"
    	errors[0x8b00] = "Unauthorized to rename a file in this directory"

    	errors[0x8c00] = "No set privileges"
    	errors[0x8c01] = "Unauthorized to modify a file in this directory"
    	errors[0x8c02] = "Unauthorized to change the restriction on this volume"

    	errors[0x8d00] = "Some of the affected files are in use by another client"
    	errors[0x8d01] = "The affected file is in use"

    	errors[0x8e00] = "All of the affected files are in use by another client"
    	errors[0x8f00] = "Some of the affected files are read-only"

    	errors[0x9000] = "An attempt to modify a read-only volume occurred"
    	errors[0x9001] = "All of the affected files are read-only"
    	errors[0x9002] = "Read Only Access to Volume"

    	errors[0x9100] = "Some of the affected files already exist"
    	errors[0x9101] = "Some Names Exist"

    	errors[0x9200] = "Directory with the new name already exists"
    	errors[0x9201] = "All of the affected files already exist"

    	errors[0x9300] = "Unauthorized to read from this file"
    	errors[0x9400] = "Unauthorized to write to this file"
    	errors[0x9500] = "The affected file is detached"

    	errors[0x9600] = "The file server has run out of memory to service this request"
    	errors[0x9601] = "No alloc space for message"
    	errors[0x9602] = "Server Out of Space"

    	errors[0x9800] = "The affected volume is not mounted"
    	errors[0x9801] = "The volume associated with Volume Number is not mounted"
    	errors[0x9802] = "The resulting volume does not exist"
    	errors[0x9803] = "The destination volume is not mounted"
    	errors[0x9804] = "Disk Map Error"

    	errors[0x9900] = "The file server has run out of directory space on the affected volume"
    	errors[0x9a00] = "Invalid request to rename the affected file to another volume"

    	errors[0x9b00] = "DirHandle is not associated with a valid directory path"
    	errors[0x9b01] = "A resulting directory handle is not associated with a valid directory path"
    	errors[0x9b02] = "The directory associated with DirHandle does not exist"
    	errors[0x9b03] = "Bad directory handle"

    	errors[0x9c00] = "The resulting path is not valid"
    	errors[0x9c01] = "The resulting file path is not valid"
    	errors[0x9c02] = "The resulting directory path is not valid"
    	errors[0x9c03] = "Invalid path"

    	errors[0x9d00] = "A directory handle was not available for allocation"

    	errors[0x9e00] = "The name of the directory does not conform to a legal name for this name space"
    	errors[0x9e01] = "The new directory name does not conform to a legal name for this name space"
    	errors[0x9e02] = "Bad File Name"

    	errors[0x9f00] = "The request attempted to delete a directory that is in use by another client"

    	errors[0xa000] = "The request attempted to delete a directory that is not empty"
    	errors[0xa100] = "An unrecoverable error occured on the affected directory"

    	errors[0xa200] = "The request attempted to read from a file region that is physically locked"
    	errors[0xa201] = "I/O Lock Error"

    	errors[0xa400] = "Invalid directory rename attempted"
        errors[0xa500] = "Invalid open create mode"
        errors[0xa600] = "Auditor Access has been Removed"
    	errors[0xa700] = "Error Auditing Version"

    	errors[0xa800] = "Invalid Support Module ID"
        errors[0xa801] = "No Auditing Access Rights"
        errors[0xa802] = "No Access Rights"

    	errors[0xbe00] = "Invalid Data Stream"
    	errors[0xbf00] = "Requests for this name space are not valid on this volume"

    	errors[0xc000] = "Unauthorized to retrieve accounting data"

    	errors[0xc100] = "The ACCOUNT_BALANCE property does not exist"
    	errors[0xc101] = "No Account Balance"

    	errors[0xc200] = "The object has exceeded its credit limit"
    	errors[0xc300] = "Too many holds have been placed against this account"
    	errors[0xc400] = "The client account has been disabled"

    	errors[0xc500] = "Access to the account has been denied because of intruder detection"
    	errors[0xc501] = "Login lockout"
    	errors[0xc502] = "Server Login Locked"

    	errors[0xc600] = "The caller does not have operator priviliges"
    	errors[0xc601] = "The client does not have operator priviliges"

    	errors[0xc800] = "Missing EA Key"
    	errors[0xc900] = "EA Not Found"
    	errors[0xca00] = "Invalid EA Handle Type"
    	errors[0xcb00] = "EA No Key No Data"
    	errors[0xcc00] = "EA Number Mismatch"
    	errors[0xcd00] = "Extent Number Out of Range"
    	errors[0xce00] = "EA Bad Directory Number"
    	errors[0xcf00] = "Invalid EA Handle"

    	errors[0xd000] = "Queue error"
    	errors[0xd001] = "EA Position Out of Range"

    	errors[0xd100] = "The queue does not exist"
    	errors[0xd101] = "EA Access Denied"

    	errors[0xd200] = "A queue server is not associated with this queue"
    	errors[0xd201] = "A queue server is not associated with the selected queue"
    	errors[0xd202] = "No queue server"
    	errors[0xd203] = "Data Page Odd Size"

    	errors[0xd300] = "No queue rights"
    	errors[0xd301] = "EA Volume Not Mounted"

    	errors[0xd400] = "The queue is full and cannot accept another request"
    	errors[0xd401] = "The queue associated with ObjectId is full and cannot accept another request"
    	errors[0xd402] = "Bad Page Boundary"

    	errors[0xd500] = "A job does not exist in this queue"
    	errors[0xd501] = "No queue job"
    	errors[0xd502] = "The job associated with JobNumber does not exist in this queue"
    	errors[0xd503] = "Inspect Failure"
        errors[0xd504] = "Unknown NCP Extension Number"

    	errors[0xd600] = "The file server does not allow unencrypted passwords"
    	errors[0xd601] = "No job right"
    	errors[0xd602] = "EA Already Claimed"

    	errors[0xd700] = "Bad account"
    	errors[0xd701] = "The old and new password strings are identical"
    	errors[0xd702] = "The job is currently being serviced"
    	errors[0xd703] = "The queue is currently servicing a job"
    	errors[0xd704] = "Queue servicing"
    	errors[0xd705] = "Odd Buffer Size"

    	errors[0xd800] = "Queue not active"
    	errors[0xd801] = "No Scorecards"

    	errors[0xd900] = "The file server cannot accept another connection as it has reached its limit"
    	errors[0xd901] = "The client is not security equivalent to one of the objects in the Q_SERVERS group property of the target queue"
    	errors[0xd902] = "Station is not a server"
    	errors[0xd903] = "Bad EDS Signature"
        errors[0xd904] = "Attempt to log in using an account which has limits on the number of concurrent connections and that number has been reached."
    
    	errors[0xda00] = "Attempted to login to the file server during a restricted time period"
    	errors[0xda01] = "Queue halted"
    	errors[0xda02] = "EA Space Limit"

    	errors[0xdb00] = "Attempted to login to the file server from an unauthorized workstation or network"
    	errors[0xdb01] = "The queue cannot attach another queue server"
    	errors[0xdb02] = "Maximum queue servers"
    	errors[0xdb03] = "EA Key Corrupt"

    	errors[0xdc00] = "Account Expired"
    	errors[0xdc01] = "EA Key Limit"

    	errors[0xdd00] = "Tally Corrupt"
    	errors[0xde00] = "Attempted to login to the file server with an incorrect password"
    	errors[0xdf00] = "Attempted to login to the file server with a password that has expired"

    	errors[0xe000] = "No Login Connections Available"
    	errors[0xe700] = "No disk track"
    	errors[0xe800] = "Write to group"
    	errors[0xe900] = "The object is already a member of the group property"

    	errors[0xea00] = "No such member"
    	errors[0xea01] = "The bindery object is not a member of the set"
    	errors[0xea02] = "Non-existent member"

    	errors[0xeb00] = "The property is not a set property"

    	errors[0xec00] = "No such set"
    	errors[0xec01] = "The set property does not exist"

    	errors[0xed00] = "Property exists"
    	errors[0xed01] = "The property already exists"
    	errors[0xed02] = "An attempt was made to create a bindery object property that already exists"

    	errors[0xee00] = "The object already exists"
    	errors[0xee01] = "The bindery object already exists"

    	errors[0xef00] = "Illegal name"
    	errors[0xef01] = "Illegal characters in ObjectName field"
    	errors[0xef02] = "Invalid name"

    	errors[0xf000] = "A wildcard was detected in a field that does not support wildcards"
    	errors[0xf001] = "An illegal wildcard was detected in ObjectName"

    	errors[0xf100] = "The client does not have the rights to access this bindery object"
    	errors[0xf101] = "Bindery security"
    	errors[0xf102] = "Invalid bindery security"

    	errors[0xf200] = "Unauthorized to read from this object"
    	errors[0xf300] = "Unauthorized to rename this object"

    	errors[0xf400] = "Unauthorized to delete this object"
    	errors[0xf401] = "No object delete privileges"
    	errors[0xf402] = "Unauthorized to delete this queue"

    	errors[0xf500] = "Unauthorized to create this object"
    	errors[0xf501] = "No object create"

    	errors[0xf600] = "No property delete"
    	errors[0xf601] = "Unauthorized to delete the property of this object"
    	errors[0xf602] = "Unauthorized to delete this property"

    	errors[0xf700] = "Unauthorized to create this property"
    	errors[0xf701] = "No property create privilege"

    	errors[0xf800] = "Unauthorized to write to this property"
    	errors[0xf900] = "Unauthorized to read this property"
    	errors[0xfa00] = "Temporary remap error"

    	errors[0xfb00] = "No such property"
    	errors[0xfb01] = "The file server does not support this request"
    	errors[0xfb02] = "The specified property does not exist"
    	errors[0xfb03] = "The PASSWORD property does not exist for this bindery object"
    	errors[0xfb04] = "NDS NCP not available"
    	errors[0xfb05] = "Bad Directory Handle"
    	errors[0xfb06] = "Unknown Request"
        errors[0xfb07] = "Invalid Subfunction Request"
        errors[0xfb08] = "Attempt to use an invalid parameter (drive number, path, or flag value) during a set drive path call"
        errors[0xfb09] = "NMAS not running on this server, NCP NOT Supported"
        errors[0xfb0a] = "Station Not Logged In"
        errors[0xfb0b] = "Secret Store not running on this server, NCP Not supported"

    	errors[0xfc00] = "The message queue cannot accept another message"
    	errors[0xfc01] = "The trustee associated with ObjectId does not exist"
    	errors[0xfc02] = "The specified bindery object does not exist"
    	errors[0xfc03] = "The bindery object associated with ObjectID does not exist"
    	errors[0xfc04] = "A bindery object does not exist that matches"
    	errors[0xfc05] = "The specified queue does not exist"
    	errors[0xfc06] = "No such object"
    	errors[0xfc07] = "The queue associated with ObjectID does not exist"

    	errors[0xfd00] = "Bad station number"
    	errors[0xfd01] = "The connection associated with ConnectionNumber is not active"
    	errors[0xfd02] = "Lock collision"
    	errors[0xfd03] = "Transaction tracking is disabled"

    	errors[0xfe00] = "I/O failure"
    	errors[0xfe01] = "The files containing the bindery on the file server are locked"
    	errors[0xfe02] = "A file with the specified name already exists in this directory"
    	errors[0xfe03] = "No more restrictions were found"
    	errors[0xfe04] = "The file server was unable to lock the file within the specified time limit"
    	errors[0xfe05] = "The file server was unable to lock all files within the specified time limit"
    	errors[0xfe06] = "The bindery object associated with ObjectID is not a valid trustee"
    	errors[0xfe07] = "Directory locked"
    	errors[0xfe08] = "Bindery locked"
    	errors[0xfe09] = "Invalid semaphore name length"
    	errors[0xfe0a] = "The file server was unable to complete the operation within the specified time limit"
    	errors[0xfe0b] = "Transaction restart"
    	errors[0xfe0c] = "Bad packet"
    	errors[0xfe0d] = "Timeout"
    	errors[0xfe0e] = "User Not Found"
    	errors[0xfe0f] = "Trustee Not Found"

    	errors[0xff00] = "Failure"
    	errors[0xff01] = "Lock error"
    	errors[0xff02] = "File not found"
    	errors[0xff03] = "The file not found or cannot be unlocked"
    	errors[0xff04] = "Record not found"
    	errors[0xff05] = "The logical record was not found"
    	errors[0xff06] = "The printer associated with Printer Number does not exist"
    	errors[0xff07] = "No such printer"
    	errors[0xff08] = "Unable to complete the request"
    	errors[0xff09] = "Unauthorized to change privileges of this trustee"
    	errors[0xff0a] = "No files matching the search criteria were found"
    	errors[0xff0b] = "A file matching the search criteria was not found"
    	errors[0xff0c] = "Verification failed"
    	errors[0xff0d] = "Object associated with ObjectID is not a manager"
    	errors[0xff0e] = "Invalid initial semaphore value"
    	errors[0xff0f] = "The semaphore handle is not valid"
    	errors[0xff10] = "SemaphoreHandle is not associated with a valid sempahore"
    	errors[0xff11] = "Invalid semaphore handle"
    	errors[0xff12] = "Transaction tracking is not available"
    	errors[0xff13] = "The transaction has not yet been written to disk"
    	errors[0xff14] = "Directory already exists"
    	errors[0xff15] = "The file already exists and the deletion flag was not set"
    	errors[0xff16] = "No matching files or directories were found"
    	errors[0xff17] = "A file or directory matching the search criteria was not found"
    	errors[0xff18] = "The file already exists"
    	errors[0xff19] = "Failure, No files found"
    	errors[0xff1a] = "Unlock Error"
    	errors[0xff1b] = "I/O Bound Error"
    	errors[0xff1c] = "Not Accepting Messages"
    	errors[0xff1d] = "No More Salvageable Files in Directory"
    	errors[0xff1e] = "Calling Station is Not a Manager"
    	errors[0xff1f] = "Bindery Failure"
        errors[0xff20] = "NCP Extension Not Found"

##############################################################################
# Produce C code
##############################################################################
def ExamineVars(vars, structs_hash, vars_hash):
	for var in vars:
		if isinstance(var, struct):
			structs_hash[var.HFName()] = var
			struct_vars = var.Variables()
			ExamineVars(struct_vars, structs_hash, vars_hash)
		else:
			vars_hash[repr(var)] = var
			if isinstance(var, bitfield):
				sub_vars = var.SubVariables()
				ExamineVars(sub_vars, structs_hash, vars_hash)

def produce_code():

	global errors

	print "/*"
	print " * Generated automatically from %s" % (sys.argv[0])
	print " * Do not edit this file manually, as all changes will be lost."
	print " */\n"

	print """
/*
 * Portions Copyright (c) Gilbert Ramirez 2000-2002
 * Portions Copyright (c) Novell, Inc. 2000-2003
 *
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/ptvcursor.h>
#include <epan/emem.h>
#include "packet-ncp-int.h"
#include "packet-ncp-nmas.h"
#include <epan/strutil.h>
#include "reassemble.h"

/* Function declarations for functions used in proto_register_ncp2222() */
static void ncp_init_protocol(void);
static void ncp_postseq_cleanup(void);

/* Endianness macros */
#define BE		0
#define LE		1
#define NO_ENDIANNESS	0

#define NO_LENGTH	-1

/* We use this int-pointer as a special flag in ptvc_record's */
static int ptvc_struct_int_storage;
#define PTVC_STRUCT	(&ptvc_struct_int_storage)

/* Values used in the count-variable ("var"/"repeat") logic. */"""


	if global_highest_var > -1:
		print "#define NUM_REPEAT_VARS\t%d" % (global_highest_var + 1)
		print "guint repeat_vars[NUM_REPEAT_VARS];",
	else:
		print "#define NUM_REPEAT_VARS\t0"
		print "guint *repeat_vars = NULL;",

	print """
#define NO_VAR		NUM_REPEAT_VARS
#define NO_REPEAT	NUM_REPEAT_VARS

#define REQ_COND_SIZE_CONSTANT	0
#define REQ_COND_SIZE_VARIABLE	1
#define NO_REQ_COND_SIZE	0


#define NTREE   0x00020000
#define NDEPTH  0x00000002
#define NREV    0x00000004
#define NFLAGS  0x00000008


static int hf_ncp_func = -1;
static int hf_ncp_length = -1;
static int hf_ncp_subfunc = -1;
static int hf_ncp_fragment_handle = -1;
static int hf_ncp_completion_code = -1;
static int hf_ncp_connection_status = -1;
static int hf_ncp_req_frame_num = -1;
static int hf_ncp_req_frame_time = -1;
static int hf_ncp_fragment_size = -1;
static int hf_ncp_message_size = -1;
static int hf_ncp_nds_flag = -1;
static int hf_ncp_nds_verb = -1;
static int hf_ping_version = -1;
static int hf_nds_version = -1;
static int hf_nds_flags = -1;
static int hf_nds_reply_depth = -1;
static int hf_nds_reply_rev = -1;
static int hf_nds_reply_flags = -1;
static int hf_nds_p1type = -1;
static int hf_nds_uint32value = -1;
static int hf_nds_bit1 = -1;
static int hf_nds_bit2 = -1;
static int hf_nds_bit3 = -1;
static int hf_nds_bit4 = -1;
static int hf_nds_bit5 = -1;
static int hf_nds_bit6 = -1;
static int hf_nds_bit7 = -1;
static int hf_nds_bit8 = -1;
static int hf_nds_bit9 = -1;
static int hf_nds_bit10 = -1;
static int hf_nds_bit11 = -1;
static int hf_nds_bit12 = -1;
static int hf_nds_bit13 = -1;
static int hf_nds_bit14 = -1;
static int hf_nds_bit15 = -1;
static int hf_nds_bit16 = -1;
static int hf_bit1outflags = -1;
static int hf_bit2outflags = -1;
static int hf_bit3outflags = -1;
static int hf_bit4outflags = -1;
static int hf_bit5outflags = -1;
static int hf_bit6outflags = -1;
static int hf_bit7outflags = -1;
static int hf_bit8outflags = -1;
static int hf_bit9outflags = -1;
static int hf_bit10outflags = -1;
static int hf_bit11outflags = -1;
static int hf_bit12outflags = -1;
static int hf_bit13outflags = -1;
static int hf_bit14outflags = -1;
static int hf_bit15outflags = -1;
static int hf_bit16outflags = -1;
static int hf_bit1nflags = -1;
static int hf_bit2nflags = -1;
static int hf_bit3nflags = -1;
static int hf_bit4nflags = -1;
static int hf_bit5nflags = -1;
static int hf_bit6nflags = -1;
static int hf_bit7nflags = -1;
static int hf_bit8nflags = -1;
static int hf_bit9nflags = -1;
static int hf_bit10nflags = -1;
static int hf_bit11nflags = -1;
static int hf_bit12nflags = -1;
static int hf_bit13nflags = -1;
static int hf_bit14nflags = -1;
static int hf_bit15nflags = -1;
static int hf_bit16nflags = -1;
static int hf_bit1rflags = -1;
static int hf_bit2rflags = -1;
static int hf_bit3rflags = -1;
static int hf_bit4rflags = -1;
static int hf_bit5rflags = -1;
static int hf_bit6rflags = -1;
static int hf_bit7rflags = -1;
static int hf_bit8rflags = -1;
static int hf_bit9rflags = -1;
static int hf_bit10rflags = -1;
static int hf_bit11rflags = -1;
static int hf_bit12rflags = -1;
static int hf_bit13rflags = -1;
static int hf_bit14rflags = -1;
static int hf_bit15rflags = -1;
static int hf_bit16rflags = -1;
static int hf_bit1cflags = -1;
static int hf_bit2cflags = -1;
static int hf_bit3cflags = -1;
static int hf_bit4cflags = -1;
static int hf_bit5cflags = -1;
static int hf_bit6cflags = -1;
static int hf_bit7cflags = -1;
static int hf_bit8cflags = -1;
static int hf_bit9cflags = -1;
static int hf_bit10cflags = -1;
static int hf_bit11cflags = -1;
static int hf_bit12cflags = -1;
static int hf_bit13cflags = -1;
static int hf_bit14cflags = -1;
static int hf_bit15cflags = -1;
static int hf_bit16cflags = -1;
static int hf_bit1acflags = -1;
static int hf_bit2acflags = -1;
static int hf_bit3acflags = -1;
static int hf_bit4acflags = -1;
static int hf_bit5acflags = -1;
static int hf_bit6acflags = -1;
static int hf_bit7acflags = -1;
static int hf_bit8acflags = -1;
static int hf_bit9acflags = -1;
static int hf_bit10acflags = -1;
static int hf_bit11acflags = -1;
static int hf_bit12acflags = -1;
static int hf_bit13acflags = -1;
static int hf_bit14acflags = -1;
static int hf_bit15acflags = -1;
static int hf_bit16acflags = -1;
static int hf_bit1vflags = -1;
static int hf_bit2vflags = -1;
static int hf_bit3vflags = -1;
static int hf_bit4vflags = -1;
static int hf_bit5vflags = -1;
static int hf_bit6vflags = -1;
static int hf_bit7vflags = -1;
static int hf_bit8vflags = -1;
static int hf_bit9vflags = -1;
static int hf_bit10vflags = -1;
static int hf_bit11vflags = -1;
static int hf_bit12vflags = -1;
static int hf_bit13vflags = -1;
static int hf_bit14vflags = -1;
static int hf_bit15vflags = -1;
static int hf_bit16vflags = -1;
static int hf_bit1eflags = -1;
static int hf_bit2eflags = -1;
static int hf_bit3eflags = -1;
static int hf_bit4eflags = -1;
static int hf_bit5eflags = -1;
static int hf_bit6eflags = -1;
static int hf_bit7eflags = -1;
static int hf_bit8eflags = -1;
static int hf_bit9eflags = -1;
static int hf_bit10eflags = -1;
static int hf_bit11eflags = -1;
static int hf_bit12eflags = -1;
static int hf_bit13eflags = -1;
static int hf_bit14eflags = -1;
static int hf_bit15eflags = -1;
static int hf_bit16eflags = -1;
static int hf_bit1infoflagsl = -1;
static int hf_bit2infoflagsl = -1;
static int hf_bit3infoflagsl = -1;
static int hf_bit4infoflagsl = -1;
static int hf_bit5infoflagsl = -1;
static int hf_bit6infoflagsl = -1;
static int hf_bit7infoflagsl = -1;
static int hf_bit8infoflagsl = -1;
static int hf_bit9infoflagsl = -1;
static int hf_bit10infoflagsl = -1;
static int hf_bit11infoflagsl = -1;
static int hf_bit12infoflagsl = -1;
static int hf_bit13infoflagsl = -1;
static int hf_bit14infoflagsl = -1;
static int hf_bit15infoflagsl = -1;
static int hf_bit16infoflagsl = -1;
static int hf_bit1infoflagsh = -1;
static int hf_bit2infoflagsh = -1;
static int hf_bit3infoflagsh = -1;
static int hf_bit4infoflagsh = -1;
static int hf_bit5infoflagsh = -1;
static int hf_bit6infoflagsh = -1;
static int hf_bit7infoflagsh = -1;
static int hf_bit8infoflagsh = -1;
static int hf_bit9infoflagsh = -1;
static int hf_bit10infoflagsh = -1;
static int hf_bit11infoflagsh = -1;
static int hf_bit12infoflagsh = -1;
static int hf_bit13infoflagsh = -1;
static int hf_bit14infoflagsh = -1;
static int hf_bit15infoflagsh = -1;
static int hf_bit16infoflagsh = -1;
static int hf_bit1lflags = -1;
static int hf_bit2lflags = -1;
static int hf_bit3lflags = -1;
static int hf_bit4lflags = -1;
static int hf_bit5lflags = -1;
static int hf_bit6lflags = -1;
static int hf_bit7lflags = -1;
static int hf_bit8lflags = -1;
static int hf_bit9lflags = -1;
static int hf_bit10lflags = -1;
static int hf_bit11lflags = -1;
static int hf_bit12lflags = -1;
static int hf_bit13lflags = -1;
static int hf_bit14lflags = -1;
static int hf_bit15lflags = -1;
static int hf_bit16lflags = -1;
static int hf_bit1l1flagsl = -1;
static int hf_bit2l1flagsl = -1;
static int hf_bit3l1flagsl = -1;
static int hf_bit4l1flagsl = -1;
static int hf_bit5l1flagsl = -1;
static int hf_bit6l1flagsl = -1;
static int hf_bit7l1flagsl = -1;
static int hf_bit8l1flagsl = -1;
static int hf_bit9l1flagsl = -1;
static int hf_bit10l1flagsl = -1;
static int hf_bit11l1flagsl = -1;
static int hf_bit12l1flagsl = -1;
static int hf_bit13l1flagsl = -1;
static int hf_bit14l1flagsl = -1;
static int hf_bit15l1flagsl = -1;
static int hf_bit16l1flagsl = -1;
static int hf_bit1l1flagsh = -1;
static int hf_bit2l1flagsh = -1;
static int hf_bit3l1flagsh = -1;
static int hf_bit4l1flagsh = -1;
static int hf_bit5l1flagsh = -1;
static int hf_bit6l1flagsh = -1;
static int hf_bit7l1flagsh = -1;
static int hf_bit8l1flagsh = -1;
static int hf_bit9l1flagsh = -1;
static int hf_bit10l1flagsh = -1;
static int hf_bit11l1flagsh = -1;
static int hf_bit12l1flagsh = -1;
static int hf_bit13l1flagsh = -1;
static int hf_bit14l1flagsh = -1;
static int hf_bit15l1flagsh = -1;
static int hf_bit16l1flagsh = -1;
static int hf_nds_tree_name = -1;
static int hf_nds_reply_error = -1;
static int hf_nds_net = -1;
static int hf_nds_node = -1;
static int hf_nds_socket = -1;
static int hf_add_ref_ip = -1;
static int hf_add_ref_udp = -1;
static int hf_add_ref_tcp = -1;
static int hf_referral_record = -1;
static int hf_referral_addcount = -1;
static int hf_nds_port = -1;
static int hf_mv_string = -1;
static int hf_nds_syntax = -1;
static int hf_value_string = -1;
static int hf_nds_buffer_size = -1;
static int hf_nds_ver = -1;
static int hf_nds_nflags = -1;
static int hf_nds_scope = -1;
static int hf_nds_name = -1;
static int hf_nds_comm_trans = -1;
static int hf_nds_tree_trans = -1;
static int hf_nds_iteration = -1;
static int hf_nds_eid = -1;
static int hf_nds_info_type = -1;
static int hf_nds_all_attr = -1;
static int hf_nds_req_flags = -1;
static int hf_nds_attr = -1;
static int hf_nds_crc = -1;
static int hf_nds_referrals = -1;
static int hf_nds_result_flags = -1;
static int hf_nds_tag_string = -1;
static int hf_value_bytes = -1;
static int hf_replica_type = -1;
static int hf_replica_state = -1;
static int hf_replica_number = -1;
static int hf_min_nds_ver = -1;
static int hf_nds_ver_include = -1;
static int hf_nds_ver_exclude = -1;
static int hf_nds_es = -1;
static int hf_es_type = -1;
static int hf_delim_string = -1;
static int hf_rdn_string = -1;
static int hf_nds_revent = -1;
static int hf_nds_rnum = -1;
static int hf_nds_name_type = -1;
static int hf_nds_rflags = -1;
static int hf_nds_eflags = -1;
static int hf_nds_depth = -1;
static int hf_nds_class_def_type = -1;
static int hf_nds_classes = -1;
static int hf_nds_return_all_classes = -1;
static int hf_nds_stream_flags = -1;
static int hf_nds_stream_name = -1;
static int hf_nds_file_handle = -1;
static int hf_nds_file_size = -1;
static int hf_nds_dn_output_type = -1;
static int hf_nds_nested_output_type = -1;
static int hf_nds_output_delimiter = -1;
static int hf_nds_output_entry_specifier = -1;
static int hf_es_value = -1;
static int hf_es_rdn_count = -1;
static int hf_nds_replica_num = -1;
static int hf_nds_event_num = -1;
static int hf_es_seconds = -1;
static int hf_nds_compare_results = -1;
static int hf_nds_parent = -1;
static int hf_nds_name_filter = -1;
static int hf_nds_class_filter = -1;
static int hf_nds_time_filter = -1;
static int hf_nds_partition_root_id = -1;
static int hf_nds_replicas = -1;
static int hf_nds_purge = -1;
static int hf_nds_local_partition = -1;
static int hf_partition_busy = -1;
static int hf_nds_number_of_changes = -1;
static int hf_sub_count = -1;
static int hf_nds_revision = -1;
static int hf_nds_base_class = -1;
static int hf_nds_relative_dn = -1;
static int hf_nds_root_dn = -1;
static int hf_nds_parent_dn = -1;
static int hf_deref_base = -1;
static int hf_nds_entry_info = -1;
static int hf_nds_base = -1;
static int hf_nds_privileges = -1;
static int hf_nds_vflags = -1;
static int hf_nds_value_len = -1;
static int hf_nds_cflags = -1;
static int hf_nds_acflags = -1;
static int hf_nds_asn1 = -1;
static int hf_nds_upper = -1;
static int hf_nds_lower = -1;
static int hf_nds_trustee_dn = -1;
static int hf_nds_attribute_dn = -1;
static int hf_nds_acl_add = -1;
static int hf_nds_acl_del = -1;
static int hf_nds_att_add = -1;
static int hf_nds_att_del = -1;
static int hf_nds_keep = -1;
static int hf_nds_new_rdn = -1;
static int hf_nds_time_delay = -1;
static int hf_nds_root_name = -1;
static int hf_nds_new_part_id = -1;
static int hf_nds_child_part_id = -1;
static int hf_nds_master_part_id = -1;
static int hf_nds_target_name = -1;
static int hf_nds_super = -1;
static int hf_bit1pingflags2 = -1;
static int hf_bit2pingflags2 = -1;
static int hf_bit3pingflags2 = -1;
static int hf_bit4pingflags2 = -1;
static int hf_bit5pingflags2 = -1;
static int hf_bit6pingflags2 = -1;
static int hf_bit7pingflags2 = -1;
static int hf_bit8pingflags2 = -1;
static int hf_bit9pingflags2 = -1;
static int hf_bit10pingflags2 = -1;
static int hf_bit11pingflags2 = -1;
static int hf_bit12pingflags2 = -1;
static int hf_bit13pingflags2 = -1;
static int hf_bit14pingflags2 = -1;
static int hf_bit15pingflags2 = -1;
static int hf_bit16pingflags2 = -1;
static int hf_bit1pingflags1 = -1;
static int hf_bit2pingflags1 = -1;
static int hf_bit3pingflags1 = -1;
static int hf_bit4pingflags1 = -1;
static int hf_bit5pingflags1 = -1;
static int hf_bit6pingflags1 = -1;
static int hf_bit7pingflags1 = -1;
static int hf_bit8pingflags1 = -1;
static int hf_bit9pingflags1 = -1;
static int hf_bit10pingflags1 = -1;
static int hf_bit11pingflags1 = -1;
static int hf_bit12pingflags1 = -1;
static int hf_bit13pingflags1 = -1;
static int hf_bit14pingflags1 = -1;
static int hf_bit15pingflags1 = -1;
static int hf_bit16pingflags1 = -1;
static int hf_bit1pingpflags1 = -1;
static int hf_bit2pingpflags1 = -1;
static int hf_bit3pingpflags1 = -1;
static int hf_bit4pingpflags1 = -1;
static int hf_bit5pingpflags1 = -1;
static int hf_bit6pingpflags1 = -1;
static int hf_bit7pingpflags1 = -1;
static int hf_bit8pingpflags1 = -1;
static int hf_bit9pingpflags1 = -1;
static int hf_bit10pingpflags1 = -1;
static int hf_bit11pingpflags1 = -1;
static int hf_bit12pingpflags1 = -1;
static int hf_bit13pingpflags1 = -1;
static int hf_bit14pingpflags1 = -1;
static int hf_bit15pingpflags1 = -1;
static int hf_bit16pingpflags1 = -1;
static int hf_bit1pingvflags1 = -1;
static int hf_bit2pingvflags1 = -1;
static int hf_bit3pingvflags1 = -1;
static int hf_bit4pingvflags1 = -1;
static int hf_bit5pingvflags1 = -1;
static int hf_bit6pingvflags1 = -1;
static int hf_bit7pingvflags1 = -1;
static int hf_bit8pingvflags1 = -1;
static int hf_bit9pingvflags1 = -1;
static int hf_bit10pingvflags1 = -1;
static int hf_bit11pingvflags1 = -1;
static int hf_bit12pingvflags1 = -1;
static int hf_bit13pingvflags1 = -1;
static int hf_bit14pingvflags1 = -1;
static int hf_bit15pingvflags1 = -1;
static int hf_bit16pingvflags1 = -1;
static int hf_nds_letter_ver = -1;
static int hf_nds_os_ver = -1;
static int hf_nds_lic_flags = -1;
static int hf_nds_ds_time = -1;
static int hf_nds_ping_version = -1;
static int hf_nds_search_scope = -1;
static int hf_nds_num_objects = -1;
static int hf_bit1siflags = -1;
static int hf_bit2siflags = -1;
static int hf_bit3siflags = -1;
static int hf_bit4siflags = -1;
static int hf_bit5siflags = -1;
static int hf_bit6siflags = -1;
static int hf_bit7siflags = -1;
static int hf_bit8siflags = -1;
static int hf_bit9siflags = -1;
static int hf_bit10siflags = -1;
static int hf_bit11siflags = -1;
static int hf_bit12siflags = -1;
static int hf_bit13siflags = -1;
static int hf_bit14siflags = -1;
static int hf_bit15siflags = -1;
static int hf_bit16siflags = -1;
static int hf_nds_segments = -1;
static int hf_nds_segment = -1;
static int hf_nds_segment_overlap = -1;
static int hf_nds_segment_overlap_conflict = -1;
static int hf_nds_segment_multiple_tails = -1;
static int hf_nds_segment_too_long_segment = -1;
static int hf_nds_segment_error = -1;


	"""

	# Look at all packet types in the packets collection, and cull information
	# from them.
	errors_used_list = []
	errors_used_hash = {}
	groups_used_list = []
	groups_used_hash = {}
	variables_used_hash = {}
	structs_used_hash = {}

	for pkt in packets:
		# Determine which error codes are used.
		codes = pkt.CompletionCodes()
		for code in codes.Records():
			if not errors_used_hash.has_key(code):
				errors_used_hash[code] = len(errors_used_list)
				errors_used_list.append(code)

		# Determine which groups are used.
		group = pkt.Group()
		if not groups_used_hash.has_key(group):
			groups_used_hash[group] = len(groups_used_list)
			groups_used_list.append(group)

		# Determine which variables are used.
		vars = pkt.Variables()
		ExamineVars(vars, structs_used_hash, variables_used_hash)


	# Print the hf variable declarations
	sorted_vars = variables_used_hash.values()
	sorted_vars.sort()
	for var in sorted_vars:
		print "static int " + var.HFName() + " = -1;"


	# Print the value_string's
	for var in sorted_vars:
		if isinstance(var, val_string):
			print ""
			print var.Code()

	# Determine which error codes are not used
	errors_not_used = {}
	# Copy the keys from the error list...
	for code in errors.keys():
		errors_not_used[code] = 1
	# ... and remove the ones that *were* used.
	for code in errors_used_list:
		del errors_not_used[code]

	# Print a remark showing errors not used
	list_errors_not_used = errors_not_used.keys()
	list_errors_not_used.sort()
	for code in list_errors_not_used:
		print "/* Error 0x%04x not used: %s */" % (code, errors[code])
	print "\n"

	# Print the errors table
	print "/* Error strings. */"
	print "static const char *ncp_errors[] = {"
	for code in errors_used_list:
		print '\t/* %02d (0x%04x) */ "%s",' % (errors_used_hash[code], code, errors[code])
	print "};\n"




	# Determine which groups are not used
	groups_not_used = {}
	# Copy the keys from the group list...
	for group in groups.keys():
		groups_not_used[group] = 1
	# ... and remove the ones that *were* used.
	for group in groups_used_list:
		del groups_not_used[group]

	# Print a remark showing groups not used
	list_groups_not_used = groups_not_used.keys()
	list_groups_not_used.sort()
	for group in list_groups_not_used:
		print "/* Group not used: %s = %s */" % (group, groups[group])
	print "\n"

	# Print the groups table
	print "/* Group strings. */"
	print "static const char *ncp_groups[] = {"
	for group in groups_used_list:
		print '\t/* %02d (%s) */ "%s",' % (groups_used_hash[group], group, groups[group])
	print "};\n"

	# Print the group macros
	for group in groups_used_list:
		name = string.upper(group)
		print "#define NCP_GROUP_%s\t%d" % (name, groups_used_hash[group])
	print "\n"


	# Print the conditional_records for all Request Conditions.
	num = 0
	print "/* Request-Condition dfilter records. The NULL pointer"
	print "   is replaced by a pointer to the created dfilter_t. */"
	if len(global_req_cond) == 0:
		print "static conditional_record req_conds = NULL;"
	else:
		print "static conditional_record req_conds[] = {"
		for req_cond in global_req_cond.keys():
			print "\t{ \"%s\", NULL }," % (req_cond,)
			global_req_cond[req_cond] = num
			num = num + 1
		print "};"
	print "#define NUM_REQ_CONDS %d" % (num,)
	print "#define NO_REQ_COND   NUM_REQ_CONDS\n\n"



	# Print PTVC's for bitfields
	ett_list = []
	print "/* PTVC records for bit-fields. */"
	for var in sorted_vars:
		if isinstance(var, bitfield):
			sub_vars_ptvc = var.SubVariablesPTVC()
			print "/* %s */" % (sub_vars_ptvc.Name())
			print sub_vars_ptvc.Code()
			ett_list.append(sub_vars_ptvc.ETTName())


	# Print the PTVC's for structures
	print "/* PTVC records for structs. */"
	# Sort them
	svhash = {}
	for svar in structs_used_hash.values():
		svhash[svar.HFName()] = svar
		if svar.descr:
			ett_list.append(svar.ETTName())

	struct_vars = svhash.keys()
	struct_vars.sort()
	for varname in struct_vars:
		var = svhash[varname]
		print var.Code()

	ett_list.sort()

	# Print regular PTVC's
	print "/* PTVC records. These are re-used to save space. */"
	for ptvc in ptvc_lists.Members():
		if not ptvc.Null() and not ptvc.Empty():
			print ptvc.Code()

	# Print error_equivalency tables
	print "/* Error-Equivalency Tables. These are re-used to save space. */"
	for compcodes in compcode_lists.Members():
		errors = compcodes.Records()
		# Make sure the record for error = 0x00 comes last.
		print "static const error_equivalency %s[] = {" % (compcodes.Name())
		for error in errors:
			error_in_packet = error >> 8;
			ncp_error_index = errors_used_hash[error]
			print "\t{ 0x%02x, %d }, /* 0x%04x */" % (error_in_packet,
				ncp_error_index, error)
		print "\t{ 0x00, -1 }\n};\n"



	# Print integer arrays for all ncp_records that need
	# a list of req_cond_indexes. Do it "uniquely" to save space;
	# if multiple packets share the same set of req_cond's,
	# then they'll share the same integer array
	print "/* Request Condition Indexes */"
	# First, make them unique
	req_cond_collection = UniqueCollection("req_cond_collection")
	for pkt in packets:
		req_conds = pkt.CalculateReqConds()
		if req_conds:
			unique_list = req_cond_collection.Add(req_conds)
			pkt.SetReqConds(unique_list)
		else:
			pkt.SetReqConds(None)

	# Print them
	for req_cond in req_cond_collection.Members():
		print "static const int %s[] = {" % (req_cond.Name(),)
		print "\t",
		vals = []
		for text in req_cond.Records():
			vals.append(global_req_cond[text])
		vals.sort()
		for val in vals:
			print "%s, " % (val,),

		print "-1 };"
		print ""



	# Functions without length parameter
	funcs_without_length = {}

	# Print info string structures
	print "/* Info Strings */"
	for pkt in packets:
		if pkt.req_info_str:
			name = pkt.InfoStrName() + "_req"
			var = pkt.req_info_str[0]
			print "static const info_string_t %s = {" % (name,)
			print "\t&%s," % (var.HFName(),)
			print '\t"%s",' % (pkt.req_info_str[1],)
			print '\t"%s"' % (pkt.req_info_str[2],)
			print "};\n"



	# Print ncp_record packet records
	print "#define SUBFUNC_WITH_LENGTH	0x02"
	print "#define SUBFUNC_NO_LENGTH	0x01"
	print "#define NO_SUBFUNC		0x00"

	print "/* ncp_record structs for packets */"
	print "static const ncp_record ncp_packets[] = {"
	for pkt in packets:
		if pkt.HasSubFunction():
			func = pkt.FunctionCode('high')
			if pkt.HasLength():
				subfunc_string = "SUBFUNC_WITH_LENGTH"
				# Ensure that the function either has a length param or not
				if funcs_without_length.has_key(func):
					sys.exit("Function 0x%04x sometimes has length param, sometimes not." \
						% (pkt.FunctionCode(),))
			else:
				subfunc_string = "SUBFUNC_NO_LENGTH"
				funcs_without_length[func] = 1
		else:
			subfunc_string = "NO_SUBFUNC"
		print '\t{ 0x%02x, 0x%02x, %s, "%s",' % (pkt.FunctionCode('high'),
			pkt.FunctionCode('low'), subfunc_string, pkt.Description()),

		print '\t%d /* %s */,' % (groups_used_hash[pkt.Group()], pkt.Group())

		ptvc = pkt.PTVCRequest()
		if not ptvc.Null() and not ptvc.Empty():
			ptvc_request = ptvc.Name()
		else:
			ptvc_request = 'NULL'

		ptvc = pkt.PTVCReply()
		if not ptvc.Null() and not ptvc.Empty():
			ptvc_reply = ptvc.Name()
		else:
			ptvc_reply = 'NULL'

		errors = pkt.CompletionCodes()

		req_conds_obj = pkt.GetReqConds()
		if req_conds_obj:
			req_conds = req_conds_obj.Name()
		else:
			req_conds = "NULL"

		if not req_conds_obj:
			req_cond_size = "NO_REQ_COND_SIZE"
		else:
			req_cond_size = pkt.ReqCondSize()
			if req_cond_size == None:
				msg.write("NCP packet %s nees a ReqCondSize*() call\n" \
					% (pkt.CName(),))
				sys.exit(1)

		if pkt.req_info_str:
			req_info_str = "&" + pkt.InfoStrName() + "_req"
		else:
			req_info_str = "NULL"

		print '\t\t%s, %s, %s, %s, %s, %s },\n' % \
			(ptvc_request, ptvc_reply, errors.Name(), req_conds,
			req_cond_size, req_info_str)

	print '\t{ 0, 0, 0, NULL, 0, NULL, NULL, NULL, NULL, NO_REQ_COND_SIZE, NULL }'
	print "};\n"

	print "/* ncp funcs that require a subfunc */"
	print "static const guint8 ncp_func_requires_subfunc[] = {"
	hi_seen = {}
	for pkt in packets:
		if pkt.HasSubFunction():
			hi_func = pkt.FunctionCode('high')
			if not hi_seen.has_key(hi_func):
				print "\t0x%02x," % (hi_func)
				hi_seen[hi_func] = 1
	print "\t0"
	print "};\n"


	print "/* ncp funcs that have no length parameter */"
	print "static const guint8 ncp_func_has_no_length_parameter[] = {"
	funcs = funcs_without_length.keys()
	funcs.sort()
	for func in funcs:
		print "\t0x%02x," % (func,)
	print "\t0"
	print "};\n"

	# final_registration_ncp2222()
	print """
static void
final_registration_ncp2222(void)
{
	int i;
	"""

	# Create dfilter_t's for conditional_record's
	print """
	for (i = 0; i < NUM_REQ_CONDS; i++) {
		if (!dfilter_compile((const gchar*)req_conds[i].dfilter_text,
			&req_conds[i].dfilter)) {
			g_message("NCP dissector failed to compiler dfilter: %s\\n",
			req_conds[i].dfilter_text);
			g_assert_not_reached();
		}
	}
}
	"""

	# proto_register_ncp2222()
	print """
static const value_string ncp_nds_verb_vals[] = {
	{ 1, "Resolve Name" },
	{ 2, "Read Entry Information" },
	{ 3, "Read" },
	{ 4, "Compare" },
	{ 5, "List" },
	{ 6, "Search Entries" },
	{ 7, "Add Entry" },
	{ 8, "Remove Entry" },
	{ 9, "Modify Entry" },
	{ 10, "Modify RDN" },
	{ 11, "Create Attribute" },
	{ 12, "Read Attribute Definition" },
	{ 13, "Remove Attribute Definition" },
	{ 14, "Define Class" },
	{ 15, "Read Class Definition" },
	{ 16, "Modify Class Definition" },
	{ 17, "Remove Class Definition" },
	{ 18, "List Containable Classes" },
	{ 19, "Get Effective Rights" },
	{ 20, "Add Partition" },
	{ 21, "Remove Partition" },
	{ 22, "List Partitions" },
	{ 23, "Split Partition" },
	{ 24, "Join Partitions" },
	{ 25, "Add Replica" },
	{ 26, "Remove Replica" },
	{ 27, "Open Stream" },
	{ 28, "Search Filter" },
	{ 29, "Create Subordinate Reference" },
	{ 30, "Link Replica" },
	{ 31, "Change Replica Type" },
	{ 32, "Start Update Schema" },
	{ 33, "End Update Schema" },
	{ 34, "Update Schema" },
	{ 35, "Start Update Replica" },
	{ 36, "End Update Replica" },
	{ 37, "Update Replica" },
	{ 38, "Synchronize Partition" },
	{ 39, "Synchronize Schema" },
	{ 40, "Read Syntaxes" },
	{ 41, "Get Replica Root ID" },
	{ 42, "Begin Move Entry" },
	{ 43, "Finish Move Entry" },
	{ 44, "Release Moved Entry" },
	{ 45, "Backup Entry" },
	{ 46, "Restore Entry" },
	{ 47, "Save DIB" },
	{ 48, "Control" },
	{ 49, "Remove Backlink" },
	{ 50, "Close Iteration" },
	{ 51, "Unused" },
	{ 52, "Audit Skulking" },
	{ 53, "Get Server Address" },
	{ 54, "Set Keys" },
	{ 55, "Change Password" },
	{ 56, "Verify Password" },
	{ 57, "Begin Login" },
	{ 58, "Finish Login" },
	{ 59, "Begin Authentication" },
	{ 60, "Finish Authentication" },
	{ 61, "Logout" },
	{ 62, "Repair Ring" },
	{ 63, "Repair Timestamps" },
	{ 64, "Create Back Link" },
	{ 65, "Delete External Reference" },
	{ 66, "Rename External Reference" },
	{ 67, "Create Directory Entry" },
	{ 68, "Remove Directory Entry" },
	{ 69, "Designate New Master" },
	{ 70, "Change Tree Name" },
	{ 71, "Partition Entry Count" },
	{ 72, "Check Login Restrictions" },
	{ 73, "Start Join" },
	{ 74, "Low Level Split" },
	{ 75, "Low Level Join" },
	{ 76, "Abort Low Level Join" },
	{ 77, "Get All Servers" },
	{ 255, "EDirectory Call" },
	{ 0,  NULL }
};

void
proto_register_ncp2222(void)
{

	static hf_register_info hf[] = {
	{ &hf_ncp_func,
	{ "Function", "ncp.func", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},

	{ &hf_ncp_length,
	{ "Packet Length", "ncp.length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

	{ &hf_ncp_subfunc,
	{ "SubFunction", "ncp.subfunc", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},

	{ &hf_ncp_completion_code,
	{ "Completion Code", "ncp.completion_code", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},

	{ &hf_ncp_fragment_handle,
	{ "NDS Fragment Handle", "ncp.ndsfrag", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

	{ &hf_ncp_fragment_size,
	{ "NDS Fragment Size", "ncp.ndsfragsize", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

	{ &hf_ncp_message_size,
	{ "Message Size", "ncp.ndsmessagesize", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

	{ &hf_ncp_nds_flag,
	{ "Flags", "ncp.ndsflag", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

	{ &hf_ncp_nds_verb,
	{ "NDS Verb", "ncp.ndsverb", FT_UINT8, BASE_HEX, VALS(ncp_nds_verb_vals), 0x0, "", HFILL }},

        { &hf_ping_version,
        { "NDS Version", "ncp.ping_version", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

	{ &hf_nds_version,
	{ "NDS Version", "ncp.nds_version", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

	{ &hf_nds_tree_name,
	{ "Tree Name", "ncp.nds_tree_name", FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }},

        /*
	 * XXX - the page at
	 *
	 *	http://www.odyssea.com/whats_new/tcpipnet/tcpipnet.html
	 *
	 * says of the connection status "The Connection Code field may
	 * contain values that indicate the status of the client host to
	 * server connection.  A value of 1 in the fourth bit of this data
	 * byte indicates that the server is unavailable (server was
	 * downed).
	 *
	 * The page at
	 *
	 *	http://www.unm.edu/~network/presentations/course/appendix/appendix_f/tsld088.htm
	 *
	 * says that bit 0 is "bad service", bit 2 is "no connection
	 * available", bit 4 is "service down", and bit 6 is "server
	 * has a broadcast message waiting for the client".
	 *
	 * Should it be displayed in hex, and should those bits (and any
	 * other bits with significance) be displayed as bitfields
	 * underneath it?
	 */
	{ &hf_ncp_connection_status,
	{ "Connection Status", "ncp.connection_status", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},

	{ &hf_ncp_req_frame_num,
	{ "Response to Request in Frame Number", "ncp.req_frame_num", FT_FRAMENUM, BASE_NONE,
		NULL, 0x0, "", HFILL }},

	{ &hf_ncp_req_frame_time,
	{ "Time from Request", "ncp.time", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0x0, "Time between request and response in seconds", HFILL }},

        { &hf_nds_flags,
        { "NDS Return Flags", "ncp.nds_flags", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},


	{ &hf_nds_reply_depth,
	{ "Distance from Root", "ncp.ndsdepth", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

        { &hf_nds_reply_rev,
	{ "NDS Revision", "ncp.ndsrev", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

	{ &hf_nds_reply_flags,
	{ "Flags", "ncp.ndsflags", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

        { &hf_nds_p1type,
	{ "NDS Parameter Type", "ncp.p1type", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},

        { &hf_nds_uint32value,
	{ "NDS Value", "ncp.uint32value", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

        { &hf_nds_bit1,
        { "Typeless", "ncp.nds_bit1", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_nds_bit2,
        { "All Containers", "ncp.nds_bit2", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_nds_bit3,
        { "Slashed", "ncp.nds_bit3", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_nds_bit4,
        { "Dotted", "ncp.nds_bit4", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_nds_bit5,
        { "Tuned", "ncp.nds_bit5", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_nds_bit6,
        { "Not Defined", "ncp.nds_bit6", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_nds_bit7,
        { "Not Defined", "ncp.nds_bit7", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_nds_bit8,
        { "Not Defined", "ncp.nds_bit8", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_nds_bit9,
        { "Not Defined", "ncp.nds_bit9", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_nds_bit10,
        { "Not Defined", "ncp.nds_bit10", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_nds_bit11,
        { "Not Defined", "ncp.nds_bit11", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_nds_bit12,
        { "Not Defined", "ncp.nds_bit12", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_nds_bit13,
        { "Not Defined", "ncp.nds_bit13", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_nds_bit14,
        { "Not Defined", "ncp.nds_bit14", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_nds_bit15,
        { "Not Defined", "ncp.nds_bit15", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_nds_bit16,
        { "Not Defined", "ncp.nds_bit16", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1outflags,
        { "Output Flags", "ncp.bit1outflags", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2outflags,
        { "Entry ID", "ncp.bit2outflags", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3outflags,
        { "Replica State", "ncp.bit3outflags", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4outflags,
        { "Modification Timestamp", "ncp.bit4outflags", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5outflags,
        { "Purge Time", "ncp.bit5outflags", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6outflags,
        { "Local Partition ID", "ncp.bit6outflags", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7outflags,
        { "Distinguished Name", "ncp.bit7outflags", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8outflags,
        { "Replica Type", "ncp.bit8outflags", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9outflags,
        { "Partition Busy", "ncp.bit9outflags", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10outflags,
        { "Not Defined", "ncp.bit10outflags", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11outflags,
        { "Not Defined", "ncp.bit11outflags", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12outflags,
        { "Not Defined", "ncp.bit12outflags", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13outflags,
        { "Not Defined", "ncp.bit13outflags", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14outflags,
        { "Not Defined", "ncp.bit14outflags", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15outflags,
        { "Not Defined", "ncp.bit15outflags", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16outflags,
        { "Not Defined", "ncp.bit16outflags", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1nflags,
        { "Entry ID", "ncp.bit1nflags", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2nflags,
        { "Readable", "ncp.bit2nflags", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3nflags,
        { "Writeable", "ncp.bit3nflags", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4nflags,
        { "Master", "ncp.bit4nflags", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5nflags,
        { "Create ID", "ncp.bit5nflags", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6nflags,
        { "Walk Tree", "ncp.bit6nflags", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7nflags,
        { "Dereference Alias", "ncp.bit7nflags", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8nflags,
        { "Not Defined", "ncp.bit8nflags", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9nflags,
        { "Not Defined", "ncp.bit9nflags", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10nflags,
        { "Not Defined", "ncp.bit10nflags", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11nflags,
        { "Not Defined", "ncp.bit11nflags", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12nflags,
        { "Not Defined", "ncp.bit12nflags", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13nflags,
        { "Not Defined", "ncp.bit13nflags", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14nflags,
        { "Prefer Referrals", "ncp.bit14nflags", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15nflags,
        { "Prefer Only Referrals", "ncp.bit15nflags", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16nflags,
        { "Not Defined", "ncp.bit16nflags", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1rflags,
        { "Typeless", "ncp.bit1rflags", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2rflags,
        { "Slashed", "ncp.bit2rflags", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3rflags,
        { "Dotted", "ncp.bit3rflags", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4rflags,
        { "Tuned", "ncp.bit4rflags", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5rflags,
        { "Not Defined", "ncp.bit5rflags", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6rflags,
        { "Not Defined", "ncp.bit6rflags", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7rflags,
        { "Not Defined", "ncp.bit7rflags", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8rflags,
        { "Not Defined", "ncp.bit8rflags", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9rflags,
        { "Not Defined", "ncp.bit9rflags", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10rflags,
        { "Not Defined", "ncp.bit10rflags", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11rflags,
        { "Not Defined", "ncp.bit11rflags", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12rflags,
        { "Not Defined", "ncp.bit12rflags", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13rflags,
        { "Not Defined", "ncp.bit13rflags", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14rflags,
        { "Not Defined", "ncp.bit14rflags", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15rflags,
        { "Not Defined", "ncp.bit15rflags", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16rflags,
        { "Not Defined", "ncp.bit16rflags", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1eflags,
        { "Alias Entry", "ncp.bit1eflags", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2eflags,
        { "Partition Root", "ncp.bit2eflags", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3eflags,
        { "Container Entry", "ncp.bit3eflags", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4eflags,
        { "Container Alias", "ncp.bit4eflags", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5eflags,
        { "Matches List Filter", "ncp.bit5eflags", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6eflags,
        { "Reference Entry", "ncp.bit6eflags", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7eflags,
        { "40x Reference Entry", "ncp.bit7eflags", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8eflags,
        { "Back Linked", "ncp.bit8eflags", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9eflags,
        { "New Entry", "ncp.bit9eflags", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10eflags,
        { "Temporary Reference", "ncp.bit10eflags", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11eflags,
        { "Audited", "ncp.bit11eflags", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12eflags,
        { "Entry Not Present", "ncp.bit12eflags", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13eflags,
        { "Entry Verify CTS", "ncp.bit13eflags", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14eflags,
        { "Entry Damaged", "ncp.bit14eflags", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15eflags,
        { "Not Defined", "ncp.bit15rflags", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16eflags,
        { "Not Defined", "ncp.bit16rflags", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1infoflagsl,
        { "Output Flags", "ncp.bit1infoflagsl", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2infoflagsl,
        { "Entry ID", "ncp.bit2infoflagsl", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3infoflagsl,
        { "Entry Flags", "ncp.bit3infoflagsl", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4infoflagsl,
        { "Subordinate Count", "ncp.bit4infoflagsl", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5infoflagsl,
        { "Modification Time", "ncp.bit5infoflagsl", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6infoflagsl,
        { "Modification Timestamp", "ncp.bit6infoflagsl", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7infoflagsl,
        { "Creation Timestamp", "ncp.bit7infoflagsl", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8infoflagsl,
        { "Partition Root ID", "ncp.bit8infoflagsl", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9infoflagsl,
        { "Parent ID", "ncp.bit9infoflagsl", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10infoflagsl,
        { "Revision Count", "ncp.bit10infoflagsl", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11infoflagsl,
        { "Replica Type", "ncp.bit11infoflagsl", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12infoflagsl,
        { "Base Class", "ncp.bit12infoflagsl", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13infoflagsl,
        { "Relative Distinguished Name", "ncp.bit13infoflagsl", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14infoflagsl,
        { "Distinguished Name", "ncp.bit14infoflagsl", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15infoflagsl,
        { "Root Distinguished Name", "ncp.bit15infoflagsl", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16infoflagsl,
        { "Parent Distinguished Name", "ncp.bit16infoflagsl", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1infoflagsh,
        { "Purge Time", "ncp.bit1infoflagsh", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2infoflagsh,
        { "Dereference Base Class", "ncp.bit2infoflagsh", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3infoflagsh,
        { "Not Defined", "ncp.bit3infoflagsh", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4infoflagsh,
        { "Not Defined", "ncp.bit4infoflagsh", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5infoflagsh,
        { "Not Defined", "ncp.bit5infoflagsh", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6infoflagsh,
        { "Not Defined", "ncp.bit6infoflagsh", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7infoflagsh,
        { "Not Defined", "ncp.bit7infoflagsh", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8infoflagsh,
        { "Not Defined", "ncp.bit8infoflagsh", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9infoflagsh,
        { "Not Defined", "ncp.bit9infoflagsh", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10infoflagsh,
        { "Not Defined", "ncp.bit10infoflagsh", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11infoflagsh,
        { "Not Defined", "ncp.bit11infoflagsh", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12infoflagsh,
        { "Not Defined", "ncp.bit12infoflagshs", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13infoflagsh,
        { "Not Defined", "ncp.bit13infoflagsh", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14infoflagsh,
        { "Not Defined", "ncp.bit14infoflagsh", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15infoflagsh,
        { "Not Defined", "ncp.bit15infoflagsh", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16infoflagsh,
        { "Not Defined", "ncp.bit16infoflagsh", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1lflags,
        { "List Typeless", "ncp.bit1lflags", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2lflags,
        { "List Containers", "ncp.bit2lflags", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3lflags,
        { "List Slashed", "ncp.bit3lflags", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4lflags,
        { "List Dotted", "ncp.bit4lflags", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5lflags,
        { "Dereference Alias", "ncp.bit5lflags", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6lflags,
        { "List All Containers", "ncp.bit6lflags", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7lflags,
        { "List Obsolete", "ncp.bit7lflags", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8lflags,
        { "List Tuned Output", "ncp.bit8lflags", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9lflags,
        { "List External Reference", "ncp.bit9lflags", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10lflags,
        { "Not Defined", "ncp.bit10lflags", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11lflags,
        { "Not Defined", "ncp.bit11lflags", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12lflags,
        { "Not Defined", "ncp.bit12lflags", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13lflags,
        { "Not Defined", "ncp.bit13lflags", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14lflags,
        { "Not Defined", "ncp.bit14lflags", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15lflags,
        { "Not Defined", "ncp.bit15lflags", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16lflags,
        { "Not Defined", "ncp.bit16lflags", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1l1flagsl,
        { "Output Flags", "ncp.bit1l1flagsl", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2l1flagsl,
        { "Entry ID", "ncp.bit2l1flagsl", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3l1flagsl,
        { "Replica State", "ncp.bit3l1flagsl", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4l1flagsl,
        { "Modification Timestamp", "ncp.bit4l1flagsl", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5l1flagsl,
        { "Purge Time", "ncp.bit5l1flagsl", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6l1flagsl,
        { "Local Partition ID", "ncp.bit6l1flagsl", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7l1flagsl,
        { "Distinguished Name", "ncp.bit7l1flagsl", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8l1flagsl,
        { "Replica Type", "ncp.bit8l1flagsl", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9l1flagsl,
        { "Partition Busy", "ncp.bit9l1flagsl", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10l1flagsl,
        { "Not Defined", "ncp.bit10l1flagsl", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11l1flagsl,
        { "Not Defined", "ncp.bit11l1flagsl", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12l1flagsl,
        { "Not Defined", "ncp.bit12l1flagsl", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13l1flagsl,
        { "Not Defined", "ncp.bit13l1flagsl", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14l1flagsl,
        { "Not Defined", "ncp.bit14l1flagsl", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15l1flagsl,
        { "Not Defined", "ncp.bit15l1flagsl", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16l1flagsl,
        { "Not Defined", "ncp.bit16l1flagsl", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1l1flagsh,
        { "Not Defined", "ncp.bit1l1flagsh", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2l1flagsh,
        { "Not Defined", "ncp.bit2l1flagsh", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3l1flagsh,
        { "Not Defined", "ncp.bit3l1flagsh", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4l1flagsh,
        { "Not Defined", "ncp.bit4l1flagsh", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5l1flagsh,
        { "Not Defined", "ncp.bit5l1flagsh", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6l1flagsh,
        { "Not Defined", "ncp.bit6l1flagsh", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7l1flagsh,
        { "Not Defined", "ncp.bit7l1flagsh", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8l1flagsh,
        { "Not Defined", "ncp.bit8l1flagsh", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9l1flagsh,
        { "Not Defined", "ncp.bit9l1flagsh", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10l1flagsh,
        { "Not Defined", "ncp.bit10l1flagsh", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11l1flagsh,
        { "Not Defined", "ncp.bit11l1flagsh", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12l1flagsh,
        { "Not Defined", "ncp.bit12l1flagsh", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13l1flagsh,
        { "Not Defined", "ncp.bit13l1flagsh", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14l1flagsh,
        { "Not Defined", "ncp.bit14l1flagsh", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15l1flagsh,
        { "Not Defined", "ncp.bit15l1flagsh", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16l1flagsh,
        { "Not Defined", "ncp.bit16l1flagsh", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1vflags,
        { "Naming", "ncp.bit1vflags", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2vflags,
        { "Base Class", "ncp.bit2vflags", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3vflags,
        { "Present", "ncp.bit3vflags", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4vflags,
        { "Value Damaged", "ncp.bit4vflags", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5vflags,
        { "Not Defined", "ncp.bit5vflags", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6vflags,
        { "Not Defined", "ncp.bit6vflags", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7vflags,
        { "Not Defined", "ncp.bit7vflags", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8vflags,
        { "Not Defined", "ncp.bit8vflags", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9vflags,
        { "Not Defined", "ncp.bit9vflags", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10vflags,
        { "Not Defined", "ncp.bit10vflags", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11vflags,
        { "Not Defined", "ncp.bit11vflags", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12vflags,
        { "Not Defined", "ncp.bit12vflags", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13vflags,
        { "Not Defined", "ncp.bit13vflags", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14vflags,
        { "Not Defined", "ncp.bit14vflags", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15vflags,
        { "Not Defined", "ncp.bit15vflags", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16vflags,
        { "Not Defined", "ncp.bit16vflags", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1cflags,
        { "Ambiguous Containment", "ncp.bit1cflags", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2cflags,
        { "Ambiguous Naming", "ncp.bit2cflags", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3cflags,
        { "Class Definition Cannot be Removed", "ncp.bit3cflags", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4cflags,
        { "Effective Class", "ncp.bit4cflags", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5cflags,
        { "Container Class", "ncp.bit5cflags", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6cflags,
        { "Not Defined", "ncp.bit6cflags", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7cflags,
        { "Not Defined", "ncp.bit7cflags", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8cflags,
        { "Not Defined", "ncp.bit8cflags", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9cflags,
        { "Not Defined", "ncp.bit9cflags", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10cflags,
        { "Not Defined", "ncp.bit10cflags", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11cflags,
        { "Not Defined", "ncp.bit11cflags", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12cflags,
        { "Not Defined", "ncp.bit12cflags", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13cflags,
        { "Not Defined", "ncp.bit13cflags", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14cflags,
        { "Not Defined", "ncp.bit14cflags", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15cflags,
        { "Not Defined", "ncp.bit15cflags", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16cflags,
        { "Not Defined", "ncp.bit16cflags", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1acflags,
        { "Single Valued", "ncp.bit1acflags", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2acflags,
        { "Sized", "ncp.bit2acflags", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3acflags,
        { "Non-Removable", "ncp.bit3acflags", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4acflags,
        { "Read Only", "ncp.bit4acflags", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5acflags,
        { "Hidden", "ncp.bit5acflags", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6acflags,
        { "String", "ncp.bit6acflags", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7acflags,
        { "Synchronize Immediate", "ncp.bit7acflags", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8acflags,
        { "Public Read", "ncp.bit8acflags", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9acflags,
        { "Server Read", "ncp.bit9acflags", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10acflags,
        { "Write Managed", "ncp.bit10acflags", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11acflags,
        { "Per Replica", "ncp.bit11acflags", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12acflags,
        { "Never Schedule Synchronization", "ncp.bit12acflags", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13acflags,
        { "Operational", "ncp.bit13acflags", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14acflags,
        { "Not Defined", "ncp.bit14acflags", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15acflags,
        { "Not Defined", "ncp.bit15acflags", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16acflags,
        { "Not Defined", "ncp.bit16acflags", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},


        { &hf_nds_reply_error,
	{ "NDS Error", "ncp.ndsreplyerror", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

        { &hf_nds_net,
	{ "Network","ncp.ndsnet", FT_IPXNET, BASE_NONE, NULL, 0x0, "", HFILL }},

	{ &hf_nds_node,
	{ "Node",	"ncp.ndsnode", FT_ETHER, BASE_NONE, NULL, 0x0, "", HFILL }},

	{ &hf_nds_socket,
        { "Socket",	"ncp.ndssocket", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},

        { &hf_add_ref_ip,
	{ "Address Referral", "ncp.ipref", FT_IPv4, BASE_DEC, NULL, 0x0, "", HFILL }},

        { &hf_add_ref_udp,
	{ "Address Referral", "ncp.udpref", FT_IPv4, BASE_DEC, NULL, 0x0, "", HFILL }},

        { &hf_add_ref_tcp,
	{ "Address Referral", "ncp.tcpref", FT_IPv4, BASE_DEC, NULL, 0x0, "", HFILL }},

        { &hf_referral_record,
	{ "Referral Record", "ncp.ref_rec", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

        { &hf_referral_addcount,
	{ "Address Count", "ncp.ref_addcount", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

	{ &hf_nds_port,
        { "Port", "ncp.ndsport", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

	{ &hf_mv_string,
	{ "Attribute Name ", "ncp.mv_string", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

	{ &hf_nds_syntax,
	{ "Attribute Syntax ", "ncp.nds_syntax", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

	{ &hf_value_string,
	{ "Value ", "ncp.value_string", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_stream_name,
	{ "Stream Name ", "ncp.nds_stream_name", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_buffer_size,
	{ "NDS Reply Buffer Size", "ncp.nds_reply_buf", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_ver,
	{ "NDS Version", "ncp.nds_ver", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_nflags,
	{ "Flags", "ncp.nds_nflags", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_rflags,
	{ "Request Flags", "ncp.nds_rflags", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_eflags,
	{ "Entry Flags", "ncp.nds_eflags", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_scope,
	{ "Scope", "ncp.nds_scope", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_name,
	{ "Name", "ncp.nds_name", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_name_type,
	{ "Name Type", "ncp.nds_name_type", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_comm_trans,
	{ "Communications Transport", "ncp.nds_comm_trans", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_tree_trans,
	{ "Tree Walker Transport", "ncp.nds_tree_trans", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_iteration,
	{ "Iteration Handle", "ncp.nds_iteration", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_file_handle,
	{ "File Handle", "ncp.nds_file_handle", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_file_size,
	{ "File Size", "ncp.nds_file_size", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_eid,
	{ "NDS EID", "ncp.nds_eid", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_depth,
	{ "Distance object is from Root", "ncp.nds_depth", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_info_type,
	{ "Info Type", "ncp.nds_info_type", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_class_def_type,
	{ "Class Definition Type", "ncp.nds_class_def_type", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_all_attr,
	{ "All Attributes", "ncp.nds_all_attr", FT_UINT32, BASE_DEC, NULL, 0x0, "Return all Attributes?", HFILL }},

    { &hf_nds_return_all_classes,
	{ "All Classes", "ncp.nds_return_all_classes", FT_STRING, BASE_NONE, NULL, 0x0, "Return all Classes?", HFILL }},

 	{ &hf_nds_req_flags,
	{ "Request Flags", "ncp.nds_req_flags", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_attr,
	{ "Attributes", "ncp.nds_attributes", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_classes,
	{ "Classes", "ncp.nds_classes", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_crc,
	{ "CRC", "ncp.nds_crc", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_referrals,
	{ "Referrals", "ncp.nds_referrals", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_result_flags,
	{ "Result Flags", "ncp.nds_result_flags", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_stream_flags,
	{ "Streams Flags", "ncp.nds_stream_flags", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

 	{ &hf_nds_tag_string,
	{ "Tags", "ncp.nds_tags", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

 	{ &hf_value_bytes,
	{ "Bytes", "ncp.value_bytes", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},

	{ &hf_replica_type,
	{ "Replica Type", "ncp.rtype", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

	{ &hf_replica_state,
	{ "Replica State", "ncp.rstate", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_rnum,
	{ "Replica Number", "ncp.rnum", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

	{ &hf_nds_revent,
	{ "Event", "ncp.revent", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

	{ &hf_replica_number,
	{ "Replica Number", "ncp.rnum", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

	{ &hf_min_nds_ver,
	{ "Minimum NDS Version", "ncp.min_nds_version", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

	{ &hf_nds_ver_include,
	{ "Include NDS Version", "ncp.inc_nds_ver", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

	{ &hf_nds_ver_exclude,
	{ "Exclude NDS Version", "ncp.exc_nds_ver", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

	{ &hf_nds_es,
	{ "Input Entry Specifier", "ncp.nds_es", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

 	{ &hf_es_type,
	{ "Entry Specifier Type", "ncp.nds_es_type", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

 	{ &hf_rdn_string,
	{ "RDN", "ncp.nds_rdn", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

 	{ &hf_delim_string,
	{ "Delimeter", "ncp.nds_delim", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_dn_output_type,
	{ "Output Entry Specifier Type", "ncp.nds_out_es_type", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_nested_output_type,
	{ "Nested Output Entry Specifier Type", "ncp.nds_nested_out_es", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_output_delimiter,
	{ "Output Delimiter", "ncp.nds_out_delimiter", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_output_entry_specifier,
	{ "Output Entry Specifier", "ncp.nds_out_es", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_es_value,
	{ "Entry Specifier Value", "ncp.nds_es_value", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_es_rdn_count,
	{ "RDN Count", "ncp.nds_es_rdn_count", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_replica_num,
	{ "Replica Number", "ncp.nds_replica_num", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_es_seconds,
	{ "Seconds", "ncp.nds_es_seconds", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_event_num,
	{ "Event Number", "ncp.nds_event_num", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_compare_results,
	{ "Compare Results", "ncp.nds_compare_results", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_parent,
	{ "Parent ID", "ncp.nds_parent", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_name_filter,
	{ "Name Filter", "ncp.nds_name_filter", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_class_filter,
	{ "Class Filter", "ncp.nds_class_filter", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_time_filter,
	{ "Time Filter", "ncp.nds_time_filter", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_partition_root_id,
	{ "Partition Root ID", "ncp.nds_partition_root_id", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_replicas,
	{ "Replicas", "ncp.nds_replicas", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_purge,
	{ "Purge Time", "ncp.nds_purge", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_local_partition,
	{ "Local Partition ID", "ncp.nds_local_partition", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_partition_busy,
    { "Partition Busy", "ncp.nds_partition_busy", FT_BOOLEAN, 16, NULL, 0x0, "", HFILL }},

    { &hf_nds_number_of_changes,
	{ "Number of Attribute Changes", "ncp.nds_number_of_changes", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_sub_count,
	{ "Subordinate Count", "ncp.sub_count", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_revision,
	{ "Revision Count", "ncp.nds_rev_count", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_base_class,
	{ "Base Class", "ncp.nds_base_class", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_relative_dn,
	{ "Relative Distinguished Name", "ncp.nds_relative_dn", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_root_dn,
	{ "Root Distinguished Name", "ncp.nds_root_dn", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_parent_dn,
	{ "Parent Distinguished Name", "ncp.nds_parent_dn", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_deref_base,
    { "Dereference Base Class", "ncp.nds_deref_base", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_base,
    { "Base Class", "ncp.nds_base", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_super,
    { "Super Class", "ncp.nds_super", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_entry_info,
    { "Entry Information", "ncp.nds_entry_info", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_privileges,
    { "Privileges", "ncp.nds_privileges", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_vflags,
    { "Value Flags", "ncp.nds_vflags", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_value_len,
    { "Value Length", "ncp.nds_vlength", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_cflags,
    { "Class Flags", "ncp.nds_cflags", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_asn1,
	{ "ASN.1 ID", "ncp.nds_asn1", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_acflags,
    { "Attribute Constraint Flags", "ncp.nds_acflags", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_upper,
    { "Upper Limit Value", "ncp.nds_upper", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_lower,
    { "Lower Limit Value", "ncp.nds_lower", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_trustee_dn,
	{ "Trustee Distinguished Name", "ncp.nds_trustee_dn", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_attribute_dn,
	{ "Attribute Name", "ncp.nds_attribute_dn", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_acl_add,
	{ "Access Control Lists to Add", "ncp.nds_acl_add", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_acl_del,
	{ "Access Control Lists to Delete", "ncp.nds_acl_del", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_att_add,
	{ "Attribute to Add", "ncp.nds_att_add", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_att_del,
	{ "Attribute to Delete", "ncp.nds_att_del", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_keep,
    { "Delete Original RDN", "ncp.nds_keep", FT_BOOLEAN, 32, NULL, 0x0, "", HFILL }},

    { &hf_nds_new_rdn,
	{ "New Relative Distinguished Name", "ncp.nds_new_rdn", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_time_delay,
	{ "Time Delay", "ncp.nds_time_delay", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_root_name,
	{ "Root Most Object Name", "ncp.nds_root_name", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_new_part_id,
	{ "New Partition Root ID", "ncp.nds_new_part_id", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_child_part_id,
	{ "Child Partition Root ID", "ncp.nds_child_part_id", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_master_part_id,
	{ "Master Partition Root ID", "ncp.nds_master_part_id", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_target_name,
	{ "Target Server Name", "ncp.nds_target_dn", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},


        { &hf_bit1pingflags1,
        { "Supported Fields", "ncp.bit1pingflags1", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2pingflags1,
        { "Depth", "ncp.bit2pingflags1", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3pingflags1,
        { "Revision", "ncp.bit3pingflags1", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4pingflags1,
        { "Flags", "ncp.bit4pingflags1", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5pingflags1,
        { "Verification Flags", "ncp.bit5pingflags1", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6pingflags1,
        { "Letter Version", "ncp.bit6pingflags1", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7pingflags1,
        { "OS Version", "ncp.bit7pingflags1", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8pingflags1,
        { "License Flags", "ncp.bit8pingflags1", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9pingflags1,
        { "DS Time", "ncp.bit9pingflags1", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10pingflags1,
        { "Not Defined", "ncp.bit10pingflags1", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11pingflags1,
        { "Not Defined", "ncp.bit11pingflags1", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12pingflags1,
        { "Not Defined", "ncp.bit12pingflags1", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13pingflags1,
        { "Not Defined", "ncp.bit13pingflags1", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14pingflags1,
        { "Not Defined", "ncp.bit14pingflags1", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15pingflags1,
        { "Not Defined", "ncp.bit15pingflags1", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16pingflags1,
        { "Not Defined", "ncp.bit16pingflags1", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1pingflags2,
        { "Sap Name", "ncp.bit1pingflags2", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2pingflags2,
        { "Tree Name", "ncp.bit2pingflags2", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3pingflags2,
        { "OS Name", "ncp.bit3pingflags2", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4pingflags2,
        { "Hardware Name", "ncp.bit4pingflags2", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5pingflags2,
        { "Vendor Name", "ncp.bit5pingflags2", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6pingflags2,
        { "Not Defined", "ncp.bit6pingflags2", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7pingflags2,
        { "Not Defined", "ncp.bit7pingflags2", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8pingflags2,
        { "Not Defined", "ncp.bit8pingflags2", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9pingflags2,
        { "Not Defined", "ncp.bit9pingflags2", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10pingflags2,
        { "Not Defined", "ncp.bit10pingflags2", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11pingflags2,
        { "Not Defined", "ncp.bit11pingflags2", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12pingflags2,
        { "Not Defined", "ncp.bit12pingflags2", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13pingflags2,
        { "Not Defined", "ncp.bit13pingflags2", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14pingflags2,
        { "Not Defined", "ncp.bit14pingflags2", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15pingflags2,
        { "Not Defined", "ncp.bit15pingflags2", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16pingflags2,
        { "Not Defined", "ncp.bit16pingflags2", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1pingpflags1,
        { "Root Most Master Replica", "ncp.bit1pingpflags1", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2pingpflags1,
        { "Time Synchronized", "ncp.bit2pingpflags1", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3pingpflags1,
        { "Not Defined", "ncp.bit3pingpflags1", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4pingpflags1,
        { "Not Defined", "ncp.bit4pingpflags1", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5pingpflags1,
        { "Not Defined", "ncp.bit5pingpflags1", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6pingpflags1,
        { "Not Defined", "ncp.bit6pingpflags1", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7pingpflags1,
        { "Not Defined", "ncp.bit7pingpflags1", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8pingpflags1,
        { "Not Defined", "ncp.bit8pingpflags1", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9pingpflags1,
        { "Not Defined", "ncp.bit9pingpflags1", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10pingpflags1,
        { "Not Defined", "ncp.bit10pingpflags1", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11pingpflags1,
        { "Not Defined", "ncp.bit11pingpflags1", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12pingpflags1,
        { "Not Defined", "ncp.bit12pingpflags1", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13pingpflags1,
        { "Not Defined", "ncp.bit13pingpflags1", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14pingpflags1,
        { "Not Defined", "ncp.bit14pingpflags1", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15pingpflags1,
        { "Not Defined", "ncp.bit15pingpflags1", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16pingpflags1,
        { "Not Defined", "ncp.bit16pingpflags1", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_bit1pingvflags1,
        { "Checksum", "ncp.bit1pingvflags1", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2pingvflags1,
        { "CRC32", "ncp.bit2pingvflags1", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3pingvflags1,
        { "Not Defined", "ncp.bit3pingvflags1", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4pingvflags1,
        { "Not Defined", "ncp.bit4pingvflags1", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5pingvflags1,
        { "Not Defined", "ncp.bit5pingvflags1", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6pingvflags1,
        { "Not Defined", "ncp.bit6pingvflags1", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7pingvflags1,
        { "Not Defined", "ncp.bit7pingvflags1", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8pingvflags1,
        { "Not Defined", "ncp.bit8pingvflags1", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9pingvflags1,
        { "Not Defined", "ncp.bit9pingvflags1", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10pingvflags1,
        { "Not Defined", "ncp.bit10pingvflags1", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11pingvflags1,
        { "Not Defined", "ncp.bit11pingvflags1", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12pingvflags1,
        { "Not Defined", "ncp.bit12pingvflags1", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13pingvflags1,
        { "Not Defined", "ncp.bit13pingvflags1", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14pingvflags1,
        { "Not Defined", "ncp.bit14pingvflags1", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15pingvflags1,
        { "Not Defined", "ncp.bit15pingvflags1", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16pingvflags1,
        { "Not Defined", "ncp.bit16pingvflags1", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

    { &hf_nds_letter_ver,
	{ "Letter Version", "ncp.nds_letter_ver", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_os_ver,
	{ "OS Version", "ncp.nds_os_ver", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_lic_flags,
	{ "License Flags", "ncp.nds_lic_flags", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_ds_time,
	{ "DS Time", "ncp.nds_ds_time", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_nds_ping_version,
	{ "Ping Version", "ncp.nds_ping_version", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_nds_search_scope,
	{ "Search Scope", "ncp.nds_search_scope", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_nds_num_objects,
	{ "Number of Objects to Search", "ncp.nds_num_objects", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},


        { &hf_bit1siflags,
        { "Names", "ncp.bit1siflags", FT_BOOLEAN, 16, NULL, 0x00000001, "", HFILL }},

        { &hf_bit2siflags,
        { "Names and Values", "ncp.bit2siflags", FT_BOOLEAN, 16, NULL, 0x00000002, "", HFILL }},

        { &hf_bit3siflags,
        { "Effective Privileges", "ncp.bit3siflags", FT_BOOLEAN, 16, NULL, 0x00000004, "", HFILL }},

        { &hf_bit4siflags,
        { "Value Info", "ncp.bit4siflags", FT_BOOLEAN, 16, NULL, 0x00000008, "", HFILL }},

        { &hf_bit5siflags,
        { "Abbreviated Value", "ncp.bit5siflags", FT_BOOLEAN, 16, NULL, 0x00000010, "", HFILL }},

        { &hf_bit6siflags,
        { "Not Defined", "ncp.bit6siflags", FT_BOOLEAN, 16, NULL, 0x00000020, "", HFILL }},

        { &hf_bit7siflags,
        { "Not Defined", "ncp.bit7siflags", FT_BOOLEAN, 16, NULL, 0x00000040, "", HFILL }},

        { &hf_bit8siflags,
        { "Not Defined", "ncp.bit8siflags", FT_BOOLEAN, 16, NULL, 0x00000080, "", HFILL }},

        { &hf_bit9siflags,
        { "Expanded Class", "ncp.bit9siflags", FT_BOOLEAN, 16, NULL, 0x00000100, "", HFILL }},

        { &hf_bit10siflags,
        { "Not Defined", "ncp.bit10siflags", FT_BOOLEAN, 16, NULL, 0x00000200, "", HFILL }},

        { &hf_bit11siflags,
        { "Not Defined", "ncp.bit11siflags", FT_BOOLEAN, 16, NULL, 0x00000400, "", HFILL }},

        { &hf_bit12siflags,
        { "Not Defined", "ncp.bit12siflags", FT_BOOLEAN, 16, NULL, 0x00000800, "", HFILL }},

        { &hf_bit13siflags,
        { "Not Defined", "ncp.bit13siflags", FT_BOOLEAN, 16, NULL, 0x00001000, "", HFILL }},

        { &hf_bit14siflags,
        { "Not Defined", "ncp.bit14siflags", FT_BOOLEAN, 16, NULL, 0x00002000, "", HFILL }},

        { &hf_bit15siflags,
        { "Not Defined", "ncp.bit15siflags", FT_BOOLEAN, 16, NULL, 0x00004000, "", HFILL }},

        { &hf_bit16siflags,
        { "Not Defined", "ncp.bit16siflags", FT_BOOLEAN, 16, NULL, 0x00008000, "", HFILL }},

        { &hf_nds_segment_overlap,
          { "Segment overlap",	"nds.segment.overlap", FT_BOOLEAN, BASE_NONE,
    		NULL, 0x0, "Segment overlaps with other segments", HFILL }},
    
        { &hf_nds_segment_overlap_conflict,
          { "Conflicting data in segment overlap", "nds.segment.overlap.conflict",
    	FT_BOOLEAN, BASE_NONE,
    		NULL, 0x0, "Overlapping segments contained conflicting data", HFILL }},
    
        { &hf_nds_segment_multiple_tails,
          { "Multiple tail segments found", "nds.segment.multipletails",
    	FT_BOOLEAN, BASE_NONE,
    		NULL, 0x0, "Several tails were found when desegmenting the packet", HFILL }},
    
        { &hf_nds_segment_too_long_segment,
          { "Segment too long",	"nds.segment.toolongsegment", FT_BOOLEAN, BASE_NONE,
    		NULL, 0x0, "Segment contained data past end of packet", HFILL }},
    
        { &hf_nds_segment_error,
          {"Desegmentation error",	"nds.segment.error", FT_FRAMENUM, BASE_NONE,
    		NULL, 0x0, "Desegmentation error due to illegal segments", HFILL }},
    
        { &hf_nds_segment,
          { "NDS Fragment",		"nds.fragment", FT_FRAMENUM, BASE_NONE,
    		NULL, 0x0, "NDPS Fragment", HFILL }},
    
        { &hf_nds_segments,
          { "NDS Fragments",	"nds.fragments", FT_NONE, BASE_NONE,
    		NULL, 0x0, "NDPS Fragments", HFILL }},



 """
	# Print the registration code for the hf variables
	for var in sorted_vars:
		print "\t{ &%s," % (var.HFName())
		print "\t{ \"%s\", \"%s\", %s, %s, %s, 0x%x, \"\", HFILL }},\n" % \
			(var.Description(), var.DFilter(),
			var.EtherealFType(), var.Display(), var.ValuesName(),
			var.Mask())

	print "\t};\n"

	if ett_list:
		print "\tstatic gint *ett[] = {"

		for ett in ett_list:
			print "\t\t&%s," % (ett,)

		print "\t};\n"

	print """
	proto_register_field_array(proto_ncp, hf, array_length(hf));
	"""

	if ett_list:
		print """
	proto_register_subtree_array(ett, array_length(ett));
		"""

	print """
	register_init_routine(&ncp_init_protocol);
	register_postseq_cleanup_routine(&ncp_postseq_cleanup);
	register_final_registration_routine(final_registration_ncp2222);
	"""


	# End of proto_register_ncp2222()
	print "}"
	print ""
	print '#include "packet-ncp2222.inc"'

def usage():
	print "Usage: ncp2222.py -o output_file"
	sys.exit(1)

def main():
	global compcode_lists
	global ptvc_lists
	global msg

	optstring = "o:"
	out_filename = None

	try:
		opts, args = getopt.getopt(sys.argv[1:], optstring)
	except getopt.error:
		usage()

	for opt, arg in opts:
		if opt == "-o":
			out_filename = arg
		else:
			usage()

	if len(args) != 0:
		usage()

	if not out_filename:
		usage()

	# Create the output file
	try:
		out_file = open(out_filename, "w")
	except IOError, err:
		sys.exit("Could not open %s for writing: %s" % (out_filename,
			err))

	# Set msg to current stdout
	msg = sys.stdout

	# Set stdout to the output file
	sys.stdout = out_file

	msg.write("Processing NCP definitions...\n")
	# Run the code, and if we catch any exception,
	# erase the output file.
	try:
		compcode_lists	= UniqueCollection('Completion Code Lists')
		ptvc_lists	= UniqueCollection('PTVC Lists')

		define_errors()
		define_groups()

		define_ncp2222()

		msg.write("Defined %d NCP types.\n" % (len(packets),))
		produce_code()
	except:
		traceback.print_exc(20, msg)
		try:
			out_file.close()
		except IOError, err:
			msg.write("Could not close %s: %s\n" % (out_filename, err))

		try:
			if os.path.exists(out_filename):
				os.remove(out_filename)
		except OSError, err:
			msg.write("Could not remove %s: %s\n" % (out_filename, err))

		sys.exit(1)



def define_ncp2222():
	##############################################################################
	# NCP Packets. Here I list functions and subfunctions in hexadecimal like the
	# NCP book (and I believe LanAlyzer does this too).
	# However, Novell lists these in decimal in their on-line documentation.
	##############################################################################
	# 2222/01
	pkt = NCP(0x01, "File Set Lock", 'file')
	pkt.Request(7)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/02
	pkt = NCP(0x02, "File Release Lock", 'file')
	pkt.Request(7)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xff00])
	# 2222/03
	pkt = NCP(0x03, "Log File Exclusive", 'file')
	pkt.Request( (12, 267), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, LockFlag ),
		rec( 9, 2, TimeoutLimit, BE ),
		rec( 11, (1, 256), FilePath ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8200, 0x9600, 0xfe0d, 0xff01])
	# 2222/04
	pkt = NCP(0x04, "Lock File Set", 'file')
	pkt.Request( 9, [
		rec( 7, 2, TimeoutLimit ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xfe0d, 0xff01])
	## 2222/05
	pkt = NCP(0x05, "Release File", 'file')
	pkt.Request( (9, 264), [
		rec( 7, 1, DirHandle ),
		rec( 8, (1, 256), FilePath ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9b00, 0x9c03, 0xff1a])
	# 2222/06
	pkt = NCP(0x06, "Release File Set", 'file')
	pkt.Request( 8, [
		rec( 7, 1, LockFlag ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/07
	pkt = NCP(0x07, "Clear File", 'file')
	pkt.Request( (9, 264), [
		rec( 7, 1, DirHandle ),
		rec( 8, (1, 256), FilePath ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0x9b03, 0x9c03,
		0xa100, 0xfd00, 0xff1a])
	# 2222/08
	pkt = NCP(0x08, "Clear File Set", 'file')
	pkt.Request( 8, [
		rec( 7, 1, LockFlag ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/09
	pkt = NCP(0x09, "Log Logical Record", 'file')
	pkt.Request( (11, 138), [
		rec( 7, 1, LockFlag ),
		rec( 8, 2, TimeoutLimit, BE ),
		rec( 10, (1, 128), LogicalRecordName ),
	], info_str=(LogicalRecordName, "Log Logical Record: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xfe0d, 0xff1a])
	# 2222/0A, 10
	pkt = NCP(0x0A, "Lock Logical Record Set", 'file')
	pkt.Request( 10, [
		rec( 7, 1, LockFlag ),
		rec( 8, 2, TimeoutLimit ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xfe0d, 0xff1a])
	# 2222/0B, 11
	pkt = NCP(0x0B, "Clear Logical Record", 'file')
	pkt.Request( (8, 135), [
		rec( 7, (1, 128), LogicalRecordName ),
	], info_str=(LogicalRecordName, "Clear Logical Record: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xff1a])
	# 2222/0C, 12
	pkt = NCP(0x0C, "Release Logical Record", 'file')
	pkt.Request( (8, 135), [
		rec( 7, (1, 128), LogicalRecordName ),
	], info_str=(LogicalRecordName, "Release Logical Record: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xff1a])
	# 2222/0D, 13
	pkt = NCP(0x0D, "Release Logical Record Set", 'file')
	pkt.Request( 8, [
		rec( 7, 1, LockFlag ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/0E, 14
	pkt = NCP(0x0E, "Clear Logical Record Set", 'file')
	pkt.Request( 8, [
		rec( 7, 1, LockFlag ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/1100, 17/00
	pkt = NCP(0x1100, "Write to Spool File", 'qms')
	pkt.Request( (11, 16), [
		rec( 10, ( 1, 6 ), Data ),
	], info_str=(Data, "Write to Spool File: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0104, 0x8000, 0x8101, 0x8701, 0x8800,
			     0x8d00, 0x8e00, 0x8f00, 0x9001, 0x9400, 0x9500,
			     0x9600, 0x9804, 0x9900, 0xa100, 0xa201, 0xff19])
	# 2222/1101, 17/01
	pkt = NCP(0x1101, "Close Spool File", 'qms')
	pkt.Request( 11, [
		rec( 10, 1, AbortQueueFlag ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8701, 0x8800, 0x8d00,
			     0x8e00, 0x8f00, 0x9001, 0x9300, 0x9400, 0x9500,
			     0x9600, 0x9804, 0x9900, 0x9b03, 0x9c03, 0x9d00,
			     0xa100, 0xd000, 0xd100, 0xd202, 0xd300, 0xd400,
			     0xda01, 0xe800, 0xea00, 0xeb00, 0xec00, 0xfc06,
			     0xfd00, 0xfe07, 0xff06])
	# 2222/1102, 17/02
	pkt = NCP(0x1102, "Set Spool File Flags", 'qms')
	pkt.Request( 30, [
		rec( 10, 1, PrintFlags ),
		rec( 11, 1, TabSize ),
		rec( 12, 1, TargetPrinter ),
		rec( 13, 1, Copies ),
		rec( 14, 1, FormType ),
		rec( 15, 1, Reserved ),
		rec( 16, 14, BannerName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xd202, 0xd300, 0xe800, 0xea00,
			     0xeb00, 0xec00, 0xfc06, 0xfe07, 0xff06])

	# 2222/1103, 17/03
	pkt = NCP(0x1103, "Spool A Disk File", 'qms')
	pkt.Request( (12, 23), [
		rec( 10, 1, DirHandle ),
		rec( 11, (1, 12), Data ),
	], info_str=(Data, "Spool a Disk File: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8701, 0x8800, 0x8d00,
			     0x8e00, 0x8f00, 0x9001, 0x9300, 0x9400, 0x9500,
			     0x9600, 0x9804, 0x9900, 0x9b03, 0x9c03, 0x9d00,
			     0xa100, 0xd000, 0xd100, 0xd202, 0xd300, 0xd400,
			     0xda01, 0xe800, 0xea00, 0xeb00, 0xec00, 0xfc06,
			     0xfd00, 0xfe07, 0xff06])

	# 2222/1106, 17/06
	pkt = NCP(0x1106, "Get Printer Status", 'qms')
	pkt.Request( 11, [
		rec( 10, 1, TargetPrinter ),
	])
	pkt.Reply(12, [
		rec( 8, 1, PrinterHalted ),
		rec( 9, 1, PrinterOffLine ),
		rec( 10, 1, CurrentFormType ),
		rec( 11, 1, RedirectedPrinter ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xfb05, 0xfd00, 0xff06])

	# 2222/1109, 17/09
	pkt = NCP(0x1109, "Create Spool File", 'qms')
	pkt.Request( (12, 23), [
		rec( 10, 1, DirHandle ),
		rec( 11, (1, 12), Data ),
	], info_str=(Data, "Create Spool File: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8400, 0x8701, 0x8d00,
			     0x8f00, 0x9001, 0x9400, 0x9600, 0x9804, 0x9900,
			     0x9b03, 0x9c03, 0xa100, 0xd000, 0xd100, 0xd202,
			     0xd300, 0xd400, 0xda01, 0xe800, 0xea00, 0xeb00,
			     0xec00, 0xfc06, 0xfd00, 0xfe07, 0xff06])

	# 2222/110A, 17/10
	pkt = NCP(0x110A, "Get Printer's Queue", 'qms')
	pkt.Request( 11, [
		rec( 10, 1, TargetPrinter ),
	])
	pkt.Reply( 12, [
		rec( 8, 4, ObjectID, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xff06])

	# 2222/12, 18
	pkt = NCP(0x12, "Get Volume Info with Number", 'file')
	pkt.Request( 8, [
		rec( 7, 1, VolumeNumber )
	],info_str=(VolumeNumber, "Get Volume Information for Volume %d", ", %d"))
	pkt.Reply( 36, [
		rec( 8, 2, SectorsPerCluster, BE ),
		rec( 10, 2, TotalVolumeClusters, BE ),
		rec( 12, 2, AvailableClusters, BE ),
		rec( 14, 2, TotalDirectorySlots, BE ),
		rec( 16, 2, AvailableDirectorySlots, BE ),
		rec( 18, 16, VolumeName ),
		rec( 34, 2, RemovableFlag, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x9804])

	# 2222/13, 19
	pkt = NCP(0x13, "Get Station Number", 'connection')
	pkt.Request(7)
	pkt.Reply(11, [
		rec( 8, 3, StationNumber )
	])
	pkt.CompletionCodes([0x0000, 0xff00])

	# 2222/14, 20
	pkt = NCP(0x14, "Get File Server Date And Time", 'fileserver')
	pkt.Request(7)
	pkt.Reply(15, [
		rec( 8, 1, Year ),
		rec( 9, 1, Month ),
		rec( 10, 1, Day ),
		rec( 11, 1, Hour ),
		rec( 12, 1, Minute ),
		rec( 13, 1, Second ),
		rec( 14, 1, DayOfWeek ),
	])
	pkt.CompletionCodes([0x0000])

	# 2222/1500, 21/00
	pkt = NCP(0x1500, "Send Broadcast Message", 'message')
	pkt.Request((13, 70), [
		rec( 10, 1, ClientListLen, var="x" ),
		rec( 11, 1, TargetClientList, repeat="x" ),
		rec( 12, (1, 58), TargetMessage ),
	], info_str=(TargetMessage, "Send Broadcast Message: %s", ", %s"))
	pkt.Reply(10, [
		rec( 8, 1, ClientListLen, var="x" ),
		rec( 9, 1, SendStatus, repeat="x" )
	])
	pkt.CompletionCodes([0x0000, 0xfd00])

	# 2222/1501, 21/01
	pkt = NCP(0x1501, "Get Broadcast Message", 'message')
	pkt.Request(10)
	pkt.Reply((9,66), [
		rec( 8, (1, 58), TargetMessage )
	])
	pkt.CompletionCodes([0x0000, 0xfd00])

	# 2222/1502, 21/02
	pkt = NCP(0x1502, "Disable Broadcasts", 'message')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xfb0a])

	# 2222/1503, 21/03
	pkt = NCP(0x1503, "Enable Broadcasts", 'message')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])

	# 2222/1509, 21/09
	pkt = NCP(0x1509, "Broadcast To Console", 'message')
	pkt.Request((11, 68), [
		rec( 10, (1, 58), TargetMessage )
	], info_str=(TargetMessage, "Broadcast to Console: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/150A, 21/10
	pkt = NCP(0x150A, "Send Broadcast Message", 'message')
	pkt.Request((17, 74), [
		rec( 10, 2, ClientListCount, LE, var="x" ),
		rec( 12, 4, ClientList, LE, repeat="x" ),
		rec( 16, (1, 58), TargetMessage ),
	], info_str=(TargetMessage, "Send Broadcast Message: %s", ", %s"))
	pkt.Reply(14, [
		rec( 8, 2, ClientListCount, LE, var="x" ),
		rec( 10, 4, ClientCompFlag, LE, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0xfd00])

	# 2222/150B, 21/11
	pkt = NCP(0x150B, "Get Broadcast Message", 'message')
	pkt.Request(10)
	pkt.Reply((9,66), [
		rec( 8, (1, 58), TargetMessage )
	])
	pkt.CompletionCodes([0x0000, 0xfd00])

	# 2222/150C, 21/12
	pkt = NCP(0x150C, "Connection Message Control", 'message')
	pkt.Request(22, [
		rec( 10, 1, ConnectionControlBits ),
                rec( 11, 3, Reserved3 ),
		rec( 14, 4, ConnectionListCount, LE, var="x" ),
		rec( 18, 4, ConnectionList, LE, repeat="x" ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xff00])

	# 2222/1600, 22/0
	pkt = NCP(0x1600, "Set Directory Handle", 'fileserver')
	pkt.Request((13,267), [
		rec( 10, 1, TargetDirHandle ),
		rec( 11, 1, DirHandle ),
		rec( 12, (1, 255), Path ),
	], info_str=(Path, "Set Directory Handle to: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0x9b03, 0x9c03, 0xa100, 0xfa00,
			     0xfd00, 0xff00])


	# 2222/1601, 22/1
	pkt = NCP(0x1601, "Get Directory Path", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, DirHandle ),
	],info_str=(DirHandle, "Get Directory Path for Directory Handle %d", ", %d"))
	pkt.Reply((9,263), [
		rec( 8, (1,255), Path ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9b00, 0x9c00, 0xa100])

	# 2222/1602, 22/2
	pkt = NCP(0x1602, "Scan Directory Information", 'fileserver')
	pkt.Request((14,268), [
		rec( 10, 1, DirHandle ),
		rec( 11, 2, StartingSearchNumber, BE ),
		rec( 13, (1, 255), Path ),
	], info_str=(Path, "Scan Directory Information: %s", ", %s"))
	pkt.Reply(36, [
		rec( 8, 16, DirectoryPath ),
		rec( 24, 2, CreationDate, BE ),
		rec( 26, 2, CreationTime, BE ),
		rec( 28, 4, CreatorID, BE ),
		rec( 32, 1, AccessRightsMask ),
                rec( 33, 1, Reserved ),
		rec( 34, 2, NextSearchNumber, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0x9b03, 0x9c03, 0xa100, 0xfa00,
			     0xfd00, 0xff00])

	# 2222/1603, 22/3
	pkt = NCP(0x1603, "Get Effective Directory Rights", 'fileserver')
	pkt.Request((14,268), [
		rec( 10, 1, DirHandle ),
		rec( 11, 2, StartingSearchNumber ),
		rec( 13, (1, 255), Path ),
	], info_str=(Path, "Get Effective Directory Rights: %s", ", %s"))
	pkt.Reply(9, [
		rec( 8, 1, AccessRightsMask ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0x9b03, 0x9c03, 0xa100, 0xfa00,
			     0xfd00, 0xff00])

	# 2222/1604, 22/4
	pkt = NCP(0x1604, "Modify Maximum Rights Mask", 'fileserver')
	pkt.Request((14,268), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, RightsGrantMask ),
		rec( 12, 1, RightsRevokeMask ),
		rec( 13, (1, 255), Path ),
	], info_str=(Path, "Modify Maximum Rights Mask: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8c00, 0x9600, 0x9804, 0x9b03, 0x9c03, 0xa100, 0xfa00,
			     0xfd00, 0xff00])

	# 2222/1605, 22/5
	pkt = NCP(0x1605, "Get Volume Number", 'fileserver')
	pkt.Request((11, 265), [
		rec( 10, (1,255), VolumeNameLen ),
	], info_str=(VolumeNameLen, "Get Volume Number for: %s", ", %s"))
	pkt.Reply(9, [
		rec( 8, 1, VolumeNumber ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804])

	# 2222/1606, 22/6
	pkt = NCP(0x1606, "Get Volume Name", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, VolumeNumber ),
	],info_str=(VolumeNumber, "Get Name for Volume %d", ", %d"))
	pkt.Reply((9, 263), [
		rec( 8, (1,255), VolumeNameLen ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0xff00])

	# 2222/160A, 22/10
	pkt = NCP(0x160A, "Create Directory", 'fileserver')
	pkt.Request((13,267), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, AccessRightsMask ),
		rec( 12, (1, 255), Path ),
	], info_str=(Path, "Create Directory: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8400, 0x9600, 0x9804, 0x9900, 0x9b03, 0x9c03,
			     0x9e00, 0xa100, 0xfd00, 0xff00])

	# 2222/160B, 22/11
	pkt = NCP(0x160B, "Delete Directory", 'fileserver')
	pkt.Request((13,267), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, Reserved ),
		rec( 12, (1, 255), Path ),
	], info_str=(Path, "Delete Directory: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8a00, 0x9600, 0x9804, 0x9b03, 0x9c03,
			     0x9f00, 0xa000, 0xa100, 0xfd00, 0xff00])

	# 2222/160C, 22/12
	pkt = NCP(0x160C, "Scan Directory for Trustees", 'fileserver')
	pkt.Request((13,267), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, TrusteeSetNumber ),
		rec( 12, (1, 255), Path ),
	], info_str=(Path, "Scan Directory for Trustees: %s", ", %s"))
	pkt.Reply(57, [
		rec( 8, 16, DirectoryPath ),
		rec( 24, 2, CreationDate, BE ),
		rec( 26, 2, CreationTime, BE ),
		rec( 28, 4, CreatorID ),
		rec( 32, 4, TrusteeID, BE ),
		rec( 36, 4, TrusteeID, BE ),
		rec( 40, 4, TrusteeID, BE ),
		rec( 44, 4, TrusteeID, BE ),
		rec( 48, 4, TrusteeID, BE ),
		rec( 52, 1, AccessRightsMask ),
		rec( 53, 1, AccessRightsMask ),
		rec( 54, 1, AccessRightsMask ),
		rec( 55, 1, AccessRightsMask ),
		rec( 56, 1, AccessRightsMask ),
	])
	pkt.CompletionCodes([0x0000, 0x8c00, 0x9600, 0x9804, 0x9b03, 0x9c03,
			     0xa100, 0xfd00, 0xff00])

	# 2222/160D, 22/13
	pkt = NCP(0x160D, "Add Trustee to Directory", 'fileserver')
	pkt.Request((17,271), [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, TrusteeID, BE ),
		rec( 15, 1, AccessRightsMask ),
		rec( 16, (1, 255), Path ),
	], info_str=(Path, "Add Trustee to Directory: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8c00, 0x9600, 0x9804, 0x9900, 0x9b03, 0x9c03,
			     0xa100, 0xfc06, 0xfd00, 0xff00])

	# 2222/160E, 22/14
	pkt = NCP(0x160E, "Delete Trustee from Directory", 'fileserver')
	pkt.Request((17,271), [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, TrusteeID, BE ),
		rec( 15, 1, Reserved ),
		rec( 16, (1, 255), Path ),
	], info_str=(Path, "Delete Trustee from Directory: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8c00, 0x9600, 0x9804, 0x9900, 0x9b03, 0x9c03,
			     0xa100, 0xfc06, 0xfd00, 0xfe07, 0xff00])

	# 2222/160F, 22/15
	pkt = NCP(0x160F, "Rename Directory", 'fileserver')
	pkt.Request((13, 521), [
		rec( 10, 1, DirHandle ),
		rec( 11, (1, 255), Path ),
		rec( -1, (1, 255), NewPath ),
	], info_str=(Path, "Rename Directory: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8b00, 0x9200, 0x9600, 0x9804, 0x9b03, 0x9c03,
			     0x9e00, 0xa100, 0xef00, 0xfd00, 0xff00])

	# 2222/1610, 22/16
	pkt = NCP(0x1610, "Purge Erased Files", 'file')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8100, 0x9600, 0x9804, 0xa100, 0xff00])

	# 2222/1611, 22/17
	pkt = NCP(0x1611, "Recover Erased File", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, DirHandle ),
	],info_str=(DirHandle, "Recover Erased File from Directory Handle %d", ", %d"))
	pkt.Reply(38, [
		rec( 8, 15, OldFileName ),
		rec( 23, 15, NewFileName ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0x9b03, 0x9c03,
			     0xa100, 0xfd00, 0xff00])
	# 2222/1612, 22/18
	pkt = NCP(0x1612, "Alloc Permanent Directory Handle", 'fileserver')
	pkt.Request((13, 267), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, DirHandleName ),
		rec( 12, (1,255), Path ),
	], info_str=(Path, "Allocate Permanent Directory Handle: %s", ", %s"))
	pkt.Reply(10, [
		rec( 8, 1, DirHandle ),
		rec( 9, 1, AccessRightsMask ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0x9900, 0x9b00, 0x9c03, 0x9d00,
			     0xa100, 0xfd00, 0xff00])
	# 2222/1613, 22/19
	pkt = NCP(0x1613, "Alloc Temporary Directory Handle", 'fileserver')
	pkt.Request((13, 267), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, DirHandleName ),
		rec( 12, (1,255), Path ),
	], info_str=(Path, "Allocate Temporary Directory Handle: %s", ", %s"))
	pkt.Reply(10, [
		rec( 8, 1, DirHandle ),
		rec( 9, 1, AccessRightsMask ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0x9900, 0x9c03, 0x9d00,
			     0xa100, 0xfd00, 0xff00])
	# 2222/1614, 22/20
	pkt = NCP(0x1614, "Deallocate Directory Handle", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, DirHandle ),
	],info_str=(DirHandle, "Deallocate Directory Handle %d", ", %d"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9b03])
	# 2222/1615, 22/21
	pkt = NCP(0x1615, "Get Volume Info with Handle", 'file')
	pkt.Request( 11, [
		rec( 10, 1, DirHandle )
	],info_str=(DirHandle, "Get Volume Information with Handle %d", ", %d"))
	pkt.Reply( 36, [
		rec( 8, 2, SectorsPerCluster, BE ),
		rec( 10, 2, TotalVolumeClusters, BE ),
		rec( 12, 2, AvailableClusters, BE ),
		rec( 14, 2, TotalDirectorySlots, BE ),
		rec( 16, 2, AvailableDirectorySlots, BE ),
		rec( 18, 16, VolumeName ),
		rec( 34, 2, RemovableFlag, BE ),
	])
	pkt.CompletionCodes([0x0000, 0xff00])
	# 2222/1616, 22/22
	pkt = NCP(0x1616, "Alloc Special Temporary Directory Handle", 'fileserver')
	pkt.Request((13, 267), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, DirHandleName ),
		rec( 12, (1,255), Path ),
	], info_str=(Path, "Allocate Special Temporary Directory Handle: %s", ", %s"))
	pkt.Reply(10, [
		rec( 8, 1, DirHandle ),
		rec( 9, 1, AccessRightsMask ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0x9900, 0x9c03, 0x9d00,
			     0xa100, 0xfd00, 0xff00])
	# 2222/1617, 22/23
	pkt = NCP(0x1617, "Extract a Base Handle", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, DirHandle ),
	],info_str=(DirHandle, "Extract a Base Handle from Directory Handle %d", ", %d"))
	pkt.Reply(22, [
		rec( 8, 10, ServerNetworkAddress ),
		rec( 18, 4, DirHandleLong ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9b03])
	# 2222/1618, 22/24
	pkt = NCP(0x1618, "Restore an Extracted Base Handle", 'fileserver')
	pkt.Request(24, [
		rec( 10, 10, ServerNetworkAddress ),
		rec( 20, 4, DirHandleLong ),
	])
	pkt.Reply(10, [
		rec( 8, 1, DirHandle ),
		rec( 9, 1, AccessRightsMask ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0x9b03, 0x9c00, 0x9d00, 0xa100,
			     0xfd00, 0xff00])
	# 2222/1619, 22/25
	pkt = NCP(0x1619, "Set Directory Information", 'fileserver')
	pkt.Request((21, 275), [
		rec( 10, 1, DirHandle ),
		rec( 11, 2, CreationDate ),
		rec( 13, 2, CreationTime ),
		rec( 15, 4, CreatorID, BE ),
		rec( 19, 1, AccessRightsMask ),
		rec( 20, (1,255), Path ),
	], info_str=(Path, "Set Directory Information: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8c00, 0x9600, 0x9804, 0x9b03, 0x9c00, 0xa100,
			     0xff16])
	# 2222/161A, 22/26
	pkt = NCP(0x161A, "Get Path Name of a Volume-Directory Number Pair", 'fileserver')
	pkt.Request(13, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 2, DirectoryEntryNumberWord ),
	])
	pkt.Reply((9,263), [
		rec( 8, (1,255), Path ),
		])
	pkt.CompletionCodes([0x0000, 0x9804, 0x9c00, 0xa100])
	# 2222/161B, 22/27
	pkt = NCP(0x161B, "Scan Salvageable Files", 'fileserver')
	pkt.Request(15, [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, SequenceNumber ),
	])
	pkt.Reply(140, [
		rec( 8, 4, SequenceNumber ),
		rec( 12, 2, Subdirectory ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 4, AttributesDef32 ),
		rec( 20, 1, UniqueID ),
		rec( 21, 1, FlagsDef ),
		rec( 22, 1, DestNameSpace ),
		rec( 23, 1, FileNameLen ),
		rec( 24, 12, FileName12 ),
                rec( 36, 2, CreationTime ),
		rec( 38, 2, CreationDate ),
		rec( 40, 4, CreatorID, BE ),
                rec( 44, 2, ArchivedTime ),
		rec( 46, 2, ArchivedDate ),
		rec( 48, 4, ArchiverID, BE ),
                rec( 52, 2, UpdateTime ),
		rec( 54, 2, UpdateDate ),
		rec( 56, 4, UpdateID, BE ),
		rec( 60, 4, FileSize, BE ),
		rec( 64, 44, Reserved44 ),
		rec( 108, 2, InheritedRightsMask ),
		rec( 110, 2, LastAccessedDate ),
		rec( 112, 4, DeletedFileTime ),
                rec( 116, 2, DeletedTime ),
		rec( 118, 2, DeletedDate ),
		rec( 120, 4, DeletedID, BE ),
		rec( 124, 16, Reserved16 ),
	])
	pkt.CompletionCodes([0x0000, 0xfb01, 0xff1d])
	# 2222/161C, 22/28
	pkt = NCP(0x161C, "Recover Salvageable File", 'fileserver')
	pkt.Request((17,525), [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, SequenceNumber ),
		rec( 15, (1, 255), FileName ),
		rec( -1, (1, 255), NewFileNameLen ),
	], info_str=(FileName, "Recover File: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8401, 0x9c03, 0xfe02])
	# 2222/161D, 22/29
	pkt = NCP(0x161D, "Purge Salvageable File", 'fileserver')
	pkt.Request(15, [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, SequenceNumber ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8500, 0x9c03])
	# 2222/161E, 22/30
	pkt = NCP(0x161E, "Scan a Directory", 'fileserver')
	pkt.Request((17, 271), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, DOSFileAttributes ),
		rec( 12, 4, SequenceNumber ),
		rec( 16, (1, 255), SearchPattern ),
	], info_str=(SearchPattern, "Scan a Directory: %s", ", %s"))
	pkt.Reply(140, [
		rec( 8, 4, SequenceNumber ),
		rec( 12, 4, Subdirectory ),
		rec( 16, 4, AttributesDef32 ),
		rec( 20, 1, UniqueID, LE ),
		rec( 21, 1, PurgeFlags ),
		rec( 22, 1, DestNameSpace ),
		rec( 23, 1, NameLen ),
		rec( 24, 12, Name12 ),
                rec( 36, 2, CreationTime ),
		rec( 38, 2, CreationDate ),
		rec( 40, 4, CreatorID, BE ),
                rec( 44, 2, ArchivedTime ),
		rec( 46, 2, ArchivedDate ),
		rec( 48, 4, ArchiverID, BE ),
                rec( 52, 2, UpdateTime ),
		rec( 54, 2, UpdateDate ),
		rec( 56, 4, UpdateID, BE ),
		rec( 60, 4, FileSize, BE ),
		rec( 64, 44, Reserved44 ),
		rec( 108, 2, InheritedRightsMask ),
		rec( 110, 2, LastAccessedDate ),
		rec( 112, 28, Reserved28 ),
	])
	pkt.CompletionCodes([0x0000, 0x8500, 0x9c03])
	# 2222/161F, 22/31
	pkt = NCP(0x161F, "Get Directory Entry", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, DirHandle ),
	])
	pkt.Reply(136, [
		rec( 8, 4, Subdirectory ),
		rec( 12, 4, AttributesDef32 ),
		rec( 16, 1, UniqueID, LE ),
		rec( 17, 1, PurgeFlags ),
		rec( 18, 1, DestNameSpace ),
		rec( 19, 1, NameLen ),
		rec( 20, 12, Name12 ),
                rec( 32, 2, CreationTime ),
		rec( 34, 2, CreationDate ),
		rec( 36, 4, CreatorID, BE ),
                rec( 40, 2, ArchivedTime ),
		rec( 42, 2, ArchivedDate ),
		rec( 44, 4, ArchiverID, BE ),
                rec( 48, 2, UpdateTime ),
		rec( 50, 2, UpdateDate ),
		rec( 52, 4, NextTrusteeEntry, BE ),
		rec( 56, 48, Reserved48 ),
		rec( 104, 2, MaximumSpace ),
		rec( 106, 2, InheritedRightsMask ),
		rec( 108, 28, Undefined28 ),
	])
	pkt.CompletionCodes([0x0000, 0x8900, 0xbf00, 0xfb00])
	# 2222/1620, 22/32
	pkt = NCP(0x1620, "Scan Volume's User Disk Restrictions", 'fileserver')
	pkt.Request(15, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, SequenceNumber ),
	])
	pkt.Reply(17, [
		rec( 8, 1, NumberOfEntries, var="x" ),
		rec( 9, 8, ObjectIDStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9800])
	# 2222/1621, 22/33
	pkt = NCP(0x1621, "Add User Disk Space Restriction", 'fileserver')
	pkt.Request(19, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, ObjectID ),
		rec( 15, 4, DiskSpaceLimit ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8c00, 0x9600, 0x9800])
	# 2222/1622, 22/34
	pkt = NCP(0x1622, "Remove User Disk Space Restrictions", 'fileserver')
	pkt.Request(15, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, ObjectID ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8c00, 0xfe0e])
	# 2222/1623, 22/35
	pkt = NCP(0x1623, "Get Directory Disk Space Restriction", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, DirHandle ),
	])
	pkt.Reply(18, [
		rec( 8, 1, NumberOfEntries ),
		rec( 9, 1, Level ),
		rec( 10, 4, MaxSpace ),
		rec( 14, 4, CurrentSpace ),
	])
	pkt.CompletionCodes([0x0000])
	# 2222/1624, 22/36
	pkt = NCP(0x1624, "Set Directory Disk Space Restriction", 'fileserver')
	pkt.Request(15, [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, DiskSpaceLimit ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0101, 0x8c00, 0xbf00])
	# 2222/1625, 22/37
	pkt = NCP(0x1625, "Set Directory Entry Information", 'fileserver')
	pkt.Request(NO_LENGTH_CHECK, [
		#
		# XXX - this didn't match what was in the spec for 22/37
		# on the Novell Web site.
		#
		rec( 10, 1, DirHandle ),
		rec( 11, 1, SearchAttributes ),
		rec( 12, 4, SequenceNumber ),
		rec( 16, 2, ChangeBits ),
		rec( 18, 2, Reserved2 ),
		rec( 20, 4, Subdirectory ),
                srec(DOSDirectoryEntryStruct, req_cond="ncp.search_att_sub == TRUE"),
                srec(DOSFileEntryStruct, req_cond="ncp.search_att_sub == FALSE"),
	])
	pkt.Reply(8)
	pkt.ReqCondSizeConstant()
	pkt.CompletionCodes([0x0000, 0x0106, 0x8c00, 0xbf00])
	# 2222/1626, 22/38
	pkt = NCP(0x1626, "Scan File or Directory for Extended Trustees", 'fileserver')
	pkt.Request((13,267), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, SequenceByte ),
		rec( 12, (1, 255), Path ),
	], info_str=(Path, "Scan for Extended Trustees: %s", ", %s"))
	pkt.Reply(91, [
		rec( 8, 1, NumberOfEntries, var="x" ),
		rec( 9, 4, ObjectID ),
		rec( 13, 4, ObjectID ),
		rec( 17, 4, ObjectID ),
		rec( 21, 4, ObjectID ),
		rec( 25, 4, ObjectID ),
		rec( 29, 4, ObjectID ),
		rec( 33, 4, ObjectID ),
		rec( 37, 4, ObjectID ),
		rec( 41, 4, ObjectID ),
		rec( 45, 4, ObjectID ),
		rec( 49, 4, ObjectID ),
		rec( 53, 4, ObjectID ),
		rec( 57, 4, ObjectID ),
		rec( 61, 4, ObjectID ),
		rec( 65, 4, ObjectID ),
		rec( 69, 4, ObjectID ),
		rec( 73, 4, ObjectID ),
		rec( 77, 4, ObjectID ),
		rec( 81, 4, ObjectID ),
		rec( 85, 4, ObjectID ),
		rec( 89, 2, AccessRightsMaskWord, repeat="x" ),
 	])
	pkt.CompletionCodes([0x0000, 0x9800, 0x9b00, 0x9c00])
	# 2222/1627, 22/39
	pkt = NCP(0x1627, "Add Extended Trustee to Directory or File", 'fileserver')
	pkt.Request((18,272), [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, ObjectID, BE ),
		rec( 15, 2, TrusteeRights ),
		rec( 17, (1, 255), Path ),
	], info_str=(Path, "Add Extended Trustee: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9000])
	# 2222/1628, 22/40
	pkt = NCP(0x1628, "Scan Directory Disk Space", 'fileserver')
	pkt.Request((17,271), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, SearchAttributes ),
		rec( 12, 4, SequenceNumber ),
		rec( 16, (1, 255), SearchPattern ),
	], info_str=(SearchPattern, "Scan Directory Disk Space: %s", ", %s"))
	pkt.Reply((148), [
		rec( 8, 4, SequenceNumber ),
		rec( 12, 4, Subdirectory ),
		rec( 16, 4, AttributesDef32 ),
		rec( 20, 1, UniqueID ),
		rec( 21, 1, PurgeFlags ),
		rec( 22, 1, DestNameSpace ),
		rec( 23, 1, NameLen ),
		rec( 24, 12, Name12 ),
                rec( 36, 2, CreationTime ),
		rec( 38, 2, CreationDate ),
		rec( 40, 4, CreatorID, BE ),
                rec( 44, 2, ArchivedTime ),
		rec( 46, 2, ArchivedDate ),
		rec( 48, 4, ArchiverID, BE ),
                rec( 52, 2, UpdateTime ),
		rec( 54, 2, UpdateDate ),
		rec( 56, 4, UpdateID, BE ),
		rec( 60, 4, DataForkSize, BE ),
		rec( 64, 4, DataForkFirstFAT, BE ),
		rec( 68, 4, NextTrusteeEntry, BE ),
		rec( 72, 36, Reserved36 ),
		rec( 108, 2, InheritedRightsMask ),
		rec( 110, 2, LastAccessedDate ),
		rec( 112, 4, DeletedFileTime ),
                rec( 116, 2, DeletedTime ),
		rec( 118, 2, DeletedDate ),
		rec( 120, 4, DeletedID, BE ),
		rec( 124, 8, Undefined8 ),
		rec( 132, 4, PrimaryEntry, LE ),
		rec( 136, 4, NameList, LE ),
		rec( 140, 4, OtherFileForkSize, BE ),
		rec( 144, 4, OtherFileForkFAT, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x8900, 0x9c03, 0xfb01, 0xff00])
	# 2222/1629, 22/41
	pkt = NCP(0x1629, "Get Object Disk Usage and Restrictions", 'fileserver')
	pkt.Request(15, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, ObjectID, BE ),
	])
	pkt.Reply(16, [
		rec( 8, 4, Restriction ),
		rec( 12, 4, InUse ),
	])
	pkt.CompletionCodes([0x0000, 0x9802])
	# 2222/162A, 22/42
	pkt = NCP(0x162A, "Get Effective Rights for Directory Entry", 'fileserver')
	pkt.Request((12,266), [
		rec( 10, 1, DirHandle ),
		rec( 11, (1, 255), Path ),
	], info_str=(Path, "Get Effective Rights: %s", ", %s"))
	pkt.Reply(10, [
		rec( 8, 2, AccessRightsMaskWord ),
	])
	pkt.CompletionCodes([0x0000, 0x9804, 0x9c03])
	# 2222/162B, 22/43
	pkt = NCP(0x162B, "Remove Extended Trustee from Dir or File", 'fileserver')
	pkt.Request((17,271), [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, ObjectID, BE ),
		rec( 15, 1, Unused ),
		rec( 16, (1, 255), Path ),
	], info_str=(Path, "Remove Extended Trustee from %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9002, 0x9c03, 0xfe0f, 0xff09])
	# 2222/162C, 22/44
	pkt = NCP(0x162C, "Get Volume and Purge Information", 'file')
	pkt.Request( 11, [
		rec( 10, 1, VolumeNumber )
	],info_str=(VolumeNumber, "Get Volume and Purge Information for Volume %d", ", %d"))
	pkt.Reply( (38,53), [
		rec( 8, 4, TotalBlocks ),
		rec( 12, 4, FreeBlocks ),
		rec( 16, 4, PurgeableBlocks ),
		rec( 20, 4, NotYetPurgeableBlocks ),
		rec( 24, 4, TotalDirectoryEntries ),
		rec( 28, 4, AvailableDirEntries ),
		rec( 32, 4, Reserved4 ),
		rec( 36, 1, SectorsPerBlock ),
		rec( 37, (1,16), VolumeNameLen ),
	])
	pkt.CompletionCodes([0x0000])
	# 2222/162D, 22/45
	pkt = NCP(0x162D, "Get Directory Information", 'file')
	pkt.Request( 11, [
		rec( 10, 1, DirHandle )
	])
	pkt.Reply( (30, 45), [
		rec( 8, 4, TotalBlocks ),
		rec( 12, 4, AvailableBlocks ),
		rec( 16, 4, TotalDirectoryEntries ),
		rec( 20, 4, AvailableDirEntries ),
		rec( 24, 4, Reserved4 ),
		rec( 28, 1, SectorsPerBlock ),
		rec( 29, (1,16), VolumeNameLen ),
	])
	pkt.CompletionCodes([0x0000, 0x9b03])
	# 2222/162E, 22/46
	pkt = NCP(0x162E, "Rename Or Move", 'file')
	pkt.Request( (17,525), [
		rec( 10, 1, SourceDirHandle ),
		rec( 11, 1, SearchAttributes ),
		rec( 12, 1, SourcePathComponentCount ),
		rec( 13, (1,255), SourcePath ),
		rec( -1, 1, DestDirHandle ),
		rec( -1, 1, DestPathComponentCount ),
		rec( -1, (1,255), DestPath ),
	], info_str=(SourcePath, "Rename or Move: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0102, 0x8701, 0x8b00, 0x8d00, 0x8e00,
			     0x8f00, 0x9001, 0x9101, 0x9201, 0x9a00, 0x9b03,
			     0x9c03, 0xa400, 0xff17])
	# 2222/162F, 22/47
	pkt = NCP(0x162F, "Get Name Space Information", 'file')
	pkt.Request( 11, [
		rec( 10, 1, VolumeNumber )
	],info_str=(VolumeNumber, "Get Name Space Information for Volume %d", ", %d"))
	pkt.Reply( (15,523), [
		#
		# XXX - why does this not display anything at all
		# if the stuff after the first IndexNumber is
		# un-commented?  That stuff really is there....
		#
		rec( 8, 1, DefinedNameSpaces, var="v" ),
		rec( 9, (1,255), NameSpaceName, repeat="v" ),
		rec( -1, 1, DefinedDataStreams, var="w" ),
		rec( -1, (2,256), DataStreamInfo, repeat="w" ),
		rec( -1, 1, LoadedNameSpaces, var="x" ),
		rec( -1, 1, IndexNumber, repeat="x" ),
#		rec( -1, 1, VolumeNameSpaces, var="y" ),
#		rec( -1, 1, IndexNumber, repeat="y" ),
#		rec( -1, 1, VolumeDataStreams, var="z" ),
#		rec( -1, 1, IndexNumber, repeat="z" ),
	])
	pkt.CompletionCodes([0x0000, 0x9802, 0xff00])
	# 2222/1630, 22/48
	pkt = NCP(0x1630, "Get Name Space Directory Entry", 'file')
	pkt.Request( 16, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, DOSSequence ),
		rec( 15, 1, SrcNameSpace ),
	])
	pkt.Reply( 112, [
		rec( 8, 4, SequenceNumber ),
		rec( 12, 4, Subdirectory ),
		rec( 16, 4, AttributesDef32 ),
		rec( 20, 1, UniqueID ),
		rec( 21, 1, Flags ),
		rec( 22, 1, SrcNameSpace ),
                rec( 23, 1, NameLength ),
		rec( 24, 12, Name12 ),
                rec( 36, 2, CreationTime ),
		rec( 38, 2, CreationDate ),
		rec( 40, 4, CreatorID, BE ),
                rec( 44, 2, ArchivedTime ),
		rec( 46, 2, ArchivedDate ),
		rec( 48, 4, ArchiverID ),
                rec( 52, 2, UpdateTime ),
		rec( 54, 2, UpdateDate ),
		rec( 56, 4, UpdateID ),
		rec( 60, 4, FileSize ),
		rec( 64, 44, Reserved44 ),
		rec( 108, 2, InheritedRightsMask ),
		rec( 110, 2, LastAccessedDate ),
	])
	pkt.CompletionCodes([0x0000, 0x8900, 0x9802, 0xbf00])
	# 2222/1631, 22/49
	pkt = NCP(0x1631, "Open Data Stream", 'file')
	pkt.Request( (15,269), [
		rec( 10, 1, DataStream ),
		rec( 11, 1, DirHandle ),
		rec( 12, 1, AttributesDef ),
		rec( 13, 1, OpenRights ),
		rec( 14, (1, 255), FileName ),
	], info_str=(FileName, "Open Data Stream: %s", ", %s"))
	pkt.Reply( 12, [
		rec( 8, 4, CCFileHandle, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8200, 0x9002, 0xbe00, 0xff00])
	# 2222/1632, 22/50
	pkt = NCP(0x1632, "Get Object Effective Rights for Directory Entry", 'file')
	pkt.Request( (16,270), [
		rec( 10, 4, ObjectID, BE ),
		rec( 14, 1, DirHandle ),
		rec( 15, (1, 255), Path ),
	], info_str=(Path, "Get Object Effective Rights: %s", ", %s"))
	pkt.Reply( 10, [
		rec( 8, 2, TrusteeRights ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x9b00, 0x9c03])
	# 2222/1633, 22/51
	pkt = NCP(0x1633, "Get Extended Volume Information", 'file')
	pkt.Request( 11, [
		rec( 10, 1, VolumeNumber ),
	],info_str=(VolumeNumber, "Get Extended Volume Information for Volume %d", ", %d"))
	pkt.Reply( (139,266), [
		rec( 8, 2, VolInfoReplyLen ),
		rec( 10, 128, VolInfoStructure),
		rec( 138, (1,128), VolumeNameLen ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x9804, 0xfb08, 0xff00])
	# 2222/1634, 22/52
	pkt = NCP(0x1634, "Get Mount Volume List", 'file')
	pkt.Request( 22, [
		rec( 10, 4, StartVolumeNumber ),
		rec( 14, 4, VolumeRequestFlags, LE ),
		rec( 18, 4, SrcNameSpace ),
	])
	pkt.Reply( 34, [
		rec( 8, 4, ItemsInPacket, var="x" ),
		rec( 12, 4, NextVolumeNumber ),
		rec( 16, 18, VolumeStruct, repeat="x"),
        ])
	pkt.CompletionCodes([0x0000])
	# 2222/1700, 23/00
	pkt = NCP(0x1700, "Login User", 'file')
	pkt.Request( (12, 58), [
		rec( 10, (1,16), UserName ),
		rec( -1, (1,32), Password ),
	], info_str=(UserName, "Login User: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9602, 0xc101, 0xc200, 0xc501, 0xd700,
			     0xd900, 0xda00, 0xdb00, 0xde00, 0xdf00, 0xe800,
			     0xec00, 0xed00, 0xef00, 0xf001, 0xf100, 0xf200,
			     0xf600, 0xfb00, 0xfc06, 0xfe07, 0xff00])
	# 2222/1701, 23/01
	pkt = NCP(0x1701, "Change User Password", 'file')
	pkt.Request( (13, 90), [
		rec( 10, (1,16), UserName ),
		rec( -1, (1,32), Password ),
		rec( -1, (1,32), NewPassword ),
	], info_str=(UserName, "Change Password for User: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xd600, 0xf001, 0xf101, 0xf501,
			     0xfc06, 0xfe07, 0xff00])
	# 2222/1702, 23/02
	pkt = NCP(0x1702, "Get User Connection List", 'file')
	pkt.Request( (11, 26), [
		rec( 10, (1,16), UserName ),
	], info_str=(UserName, "Get User Connection: %s", ", %s"))
	pkt.Reply( (9, 136), [
		rec( 8, (1, 128), ConnectionNumberList ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xf001, 0xfc06, 0xfe07, 0xff00])
	# 2222/1703, 23/03
	pkt = NCP(0x1703, "Get User Number", 'file')
	pkt.Request( (11, 26), [
		rec( 10, (1,16), UserName ),
	], info_str=(UserName, "Get User Number: %s", ", %s"))
	pkt.Reply( 12, [
		rec( 8, 4, ObjectID, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xf001, 0xfc06, 0xfe07, 0xff00])
	# 2222/1705, 23/05
	pkt = NCP(0x1705, "Get Station's Logged Info", 'file')
	pkt.Request( 11, [
		rec( 10, 1, TargetConnectionNumber ),
	],info_str=(TargetConnectionNumber, "Get Station's Logged Information on Connection %d", ", %d"))
        pkt.Reply( 266, [
		rec( 8, 16, UserName16 ),
		rec( 24, 7, LoginTime ),
		rec( 31, 39, FullName ),
		rec( 70, 4, UserID, BE ),
		rec( 74, 128, SecurityEquivalentList ),
		rec( 202, 64, Reserved64 ),
	])
	pkt.CompletionCodes([0x0000, 0x9602, 0xfc06, 0xfd00, 0xfe07, 0xff00])
	# 2222/1707, 23/07
	pkt = NCP(0x1707, "Get Group Number", 'file')
	pkt.Request( 14, [
		rec( 10, 4, ObjectID, BE ),
	])
	pkt.Reply( 62, [
		rec( 8, 4, ObjectID, BE ),
		rec( 12, 2, ObjectType, BE ),
		rec( 14, 48, ObjectNameLen ),
	])
	pkt.CompletionCodes([0x0000, 0x9602, 0xf101, 0xfc06, 0xfe07, 0xff00])
	# 2222/170C, 23/12
	pkt = NCP(0x170C, "Verify Serialization", 'file')
	pkt.Request( 14, [
		rec( 10, 4, ServerSerialNumber ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xff00])
	# 2222/170D, 23/13
	pkt = NCP(0x170D, "Log Network Message", 'file')
	pkt.Request( (11, 68), [
		rec( 10, (1, 58), TargetMessage ),
	], info_str=(TargetMessage, "Log Network Message: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8100, 0x8800, 0x8d00, 0x8e00, 0x8f00,
			     0x9001, 0x9400, 0x9600, 0x9804, 0x9900, 0x9b00, 0xa100,
			     0xa201, 0xff00])
	# 2222/170E, 23/14
	pkt = NCP(0x170E, "Get Disk Utilization", 'file')
	pkt.Request( 15, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, TrusteeID, BE ),
	])
	pkt.Reply( 19, [
		rec( 8, 1, VolumeNumber ),
		rec( 9, 4, TrusteeID, BE ),
		rec( 13, 2, DirectoryCount, BE ),
		rec( 15, 2, FileCount, BE ),
		rec( 17, 2, ClusterCount, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0xa100, 0xf200])
	# 2222/170F, 23/15
	pkt = NCP(0x170F, "Scan File Information", 'file')
	pkt.Request((15,269), [
		rec( 10, 2, LastSearchIndex ),
		rec( 12, 1, DirHandle ),
		rec( 13, 1, SearchAttributes ),
		rec( 14, (1, 255), FileName ),
	], info_str=(FileName, "Scan File Information: %s", ", %s"))
	pkt.Reply( 102, [
		rec( 8, 2, NextSearchIndex ),
		rec( 10, 14, FileName14 ),
		rec( 24, 2, AttributesDef16 ),
		rec( 26, 4, FileSize, BE ),
		rec( 30, 2, CreationDate, BE ),
		rec( 32, 2, LastAccessedDate, BE ),
		rec( 34, 2, ModifiedDate, BE ),
		rec( 36, 2, ModifiedTime, BE ),
		rec( 38, 4, CreatorID, BE ),
		rec( 42, 2, ArchivedDate, BE ),
		rec( 44, 2, ArchivedTime, BE ),
		rec( 46, 56, Reserved56 ),
	])
	pkt.CompletionCodes([0x0000, 0x8800, 0x8900, 0x9300, 0x9400, 0x9804, 0x9b00, 0x9c00,
			     0xa100, 0xfd00, 0xff17])
	# 2222/1710, 23/16
	pkt = NCP(0x1710, "Set File Information", 'file')
	pkt.Request((91,345), [
		rec( 10, 2, AttributesDef16 ),
		rec( 12, 4, FileSize, BE ),
		rec( 16, 2, CreationDate, BE ),
		rec( 18, 2, LastAccessedDate, BE ),
		rec( 20, 2, ModifiedDate, BE ),
		rec( 22, 2, ModifiedTime, BE ),
		rec( 24, 4, CreatorID, BE ),
		rec( 28, 2, ArchivedDate, BE ),
		rec( 30, 2, ArchivedTime, BE ),
		rec( 32, 56, Reserved56 ),
		rec( 88, 1, DirHandle ),
		rec( 89, 1, SearchAttributes ),
		rec( 90, (1, 255), FileName ),
	], info_str=(FileName, "Set Information for File: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0x8c00, 0x8e00, 0x9400, 0x9600, 0x9804,
			     0x9b03, 0x9c00, 0xa100, 0xa201, 0xfc06, 0xfd00, 0xfe07,
			     0xff17])
	# 2222/1711, 23/17
	pkt = NCP(0x1711, "Get File Server Information", 'fileserver')
	pkt.Request(10)
	pkt.Reply(136, [
		rec( 8, 48, ServerName ),
		rec( 56, 1, OSMajorVersion ),
		rec( 57, 1, OSMinorVersion ),
		rec( 58, 2, ConnectionsSupportedMax, BE ),
		rec( 60, 2, ConnectionsInUse, BE ),
		rec( 62, 2, VolumesSupportedMax, BE ),
		rec( 64, 1, OSRevision ),
		rec( 65, 1, SFTSupportLevel ),
		rec( 66, 1, TTSLevel ),
		rec( 67, 2, ConnectionsMaxUsed, BE ),
		rec( 69, 1, AccountVersion ),
		rec( 70, 1, VAPVersion ),
		rec( 71, 1, QueueingVersion ),
		rec( 72, 1, PrintServerVersion ),
		rec( 73, 1, VirtualConsoleVersion ),
		rec( 74, 1, SecurityRestrictionVersion ),
		rec( 75, 1, InternetBridgeVersion ),
		rec( 76, 1, MixedModePathFlag ),
		rec( 77, 1, LocalLoginInfoCcode ),
		rec( 78, 2, ProductMajorVersion, BE ),
		rec( 80, 2, ProductMinorVersion, BE ),
		rec( 82, 2, ProductRevisionVersion, BE ),
		rec( 84, 1, OSLanguageID, LE ),
		rec( 85, 1, SixtyFourBitOffsetsSupportedFlag ),
		rec( 86, 50, Reserved50 ),
	])
	pkt.CompletionCodes([0x0000, 0x9600])
	# 2222/1712, 23/18
	pkt = NCP(0x1712, "Get Network Serial Number", 'fileserver')
	pkt.Request(10)
	pkt.Reply(14, [
		rec( 8, 4, ServerSerialNumber ),
		rec( 12, 2, ApplicationNumber ),
	])
	pkt.CompletionCodes([0x0000, 0x9600])
	# 2222/1713, 23/19
	pkt = NCP(0x1713, "Get Internet Address", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, TargetConnectionNumber ),
	],info_str=(TargetConnectionNumber, "Get Internet Address for Connection %d", ", %d"))
	pkt.Reply(20, [
		rec( 8, 4, NetworkAddress, BE ),
		rec( 12, 6, NetworkNodeAddress ),
		rec( 18, 2, NetworkSocket, BE ),
	])
	pkt.CompletionCodes([0x0000, 0xff00])
	# 2222/1714, 23/20
	pkt = NCP(0x1714, "Login Object", 'bindery')
	pkt.Request( (14, 60), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,16), ClientName ),
		rec( -1, (1,32), Password ),
	], info_str=(UserName, "Login Object: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9602, 0xc101, 0xc200, 0xc501, 0xd600, 0xd700,
			     0xd900, 0xda00, 0xdb00, 0xde00, 0xdf00, 0xe800, 0xec00,
			     0xed00, 0xef00, 0xf001, 0xf100, 0xf200, 0xf600, 0xfb00,
			     0xfc06, 0xfe07, 0xff00])
	# 2222/1715, 23/21
	pkt = NCP(0x1715, "Get Object Connection List", 'bindery')
	pkt.Request( (13, 28), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,16), ObjectName ),
	], info_str=(UserName, "Get Object Connection List: %s", ", %s"))
	pkt.Reply( (9, 136), [
		rec( 8, (1, 128), ConnectionNumberList ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xf001, 0xfc06, 0xfe07, 0xff00])
	# 2222/1716, 23/22
	pkt = NCP(0x1716, "Get Station's Logged Info", 'bindery')
	pkt.Request( 11, [
		rec( 10, 1, TargetConnectionNumber ),
	])
	pkt.Reply( 70, [
		rec( 8, 4, UserID, BE ),
		rec( 12, 2, ObjectType, BE ),
		rec( 14, 48, ObjectNameLen ),
		rec( 62, 7, LoginTime ),
                rec( 69, 1, Reserved ),
	])
	pkt.CompletionCodes([0x0000, 0x9602, 0xfb0a, 0xfc06, 0xfd00, 0xfe07, 0xff00])
	# 2222/1717, 23/23
	pkt = NCP(0x1717, "Get Login Key", 'bindery')
	pkt.Request(10)
	pkt.Reply( 16, [
		rec( 8, 8, LoginKey ),
	])
	pkt.CompletionCodes([0x0000, 0x9602])
	# 2222/1718, 23/24
	pkt = NCP(0x1718, "Keyed Object Login", 'bindery')
	pkt.Request( (21, 68), [
		rec( 10, 8, LoginKey ),
		rec( 18, 2, ObjectType, BE ),
		rec( 20, (1,48), ObjectName ),
	], info_str=(ObjectName, "Keyed Object Login: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9602, 0xc101, 0xc200, 0xc500, 0xd904, 0xda00,
			     0xdb00, 0xdc00, 0xde00, 0xff00])
	# 2222/171A, 23/26
	#
	# XXX - for NCP-over-IP, the NetworkAddress field appears to be
	# an IP address, rather than an IPX network address, and should
	# be dissected as an FT_IPv4 value; the NetworkNodeAddress and
	# NetworkSocket are 0.
	#
	# For NCP-over-IPX, it should probably be dissected as an
	# FT_IPXNET value.
	#
	pkt = NCP(0x171A, "Get Internet Address", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, TargetConnectionNumber ),
	])
	pkt.Reply(21, [
		rec( 8, 4, NetworkAddress, BE ),
		rec( 12, 6, NetworkNodeAddress ),
		rec( 18, 2, NetworkSocket, BE ),
		rec( 20, 1, ConnectionType ),
	])
	pkt.CompletionCodes([0x0000])
	# 2222/171B, 23/27
	pkt = NCP(0x171B, "Get Object Connection List", 'bindery')
	pkt.Request( (17,64), [
		rec( 10, 4, SearchConnNumber ),
		rec( 14, 2, ObjectType, BE ),
		rec( 16, (1,48), ObjectName ),
	], info_str=(ObjectName, "Get Object Connection List: %s", ", %s"))
	pkt.Reply( (10,137), [
		rec( 8, 1, ConnListLen, var="x" ),
		rec( 9, (1,128), ConnectionNumberList, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xf001, 0xfc06, 0xfe07, 0xff00])
	# 2222/171C, 23/28
	pkt = NCP(0x171C, "Get Station's Logged Info", 'connection')
	pkt.Request( 14, [
		rec( 10, 4, TargetConnectionNumber ),
	])
	pkt.Reply( 70, [
		rec( 8, 4, UserID, BE ),
		rec( 12, 2, ObjectType, BE ),
		rec( 14, 48, ObjectNameLen ),
		rec( 62, 7, LoginTime ),
		rec( 69, 1, Reserved ),
	])
	pkt.CompletionCodes([0x0000, 0x9602, 0xfb02, 0xfc06, 0xfd00, 0xfe07, 0xff00])
	# 2222/171D, 23/29
	pkt = NCP(0x171D, "Change Connection State", 'connection')
	pkt.Request( 11, [
		rec( 10, 1, RequestCode ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0109, 0x7a00, 0x7b00, 0x7c00, 0xe000, 0xfb06, 0xfd00])
	# 2222/171E, 23/30
	pkt = NCP(0x171E, "Set Watchdog Delay Interval", 'connection')
	pkt.Request( 14, [
		rec( 10, 4, NumberOfMinutesToDelay ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0107])
	# 2222/171F, 23/31
	pkt = NCP(0x171F, "Get Connection List From Object", 'bindery')
	pkt.Request( 18, [
		rec( 10, 4, ObjectID, BE ),
		rec( 14, 4, ConnectionNumber ),
	])
	pkt.Reply( (9, 136), [
		rec( 8, (1, 128), ConnectionNumberList ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xf001, 0xfc06, 0xfe07, 0xff00])
	# 2222/1720, 23/32
	pkt = NCP(0x1720, "Scan Bindery Object (List)", 'bindery')
	pkt.Request((23,70), [
		rec( 10, 4, NextObjectID, BE ),
		rec( 14, 4, ObjectType, BE ),
		rec( 18, 4, InfoFlags ),
		rec( 22, (1,48), ObjectName ),
	], info_str=(ObjectName, "Scan Bindery Object: %s", ", %s"))
	pkt.Reply(NO_LENGTH_CHECK, [
		rec( 8, 4, ObjectInfoReturnCount ),
		rec( 12, 4, NextObjectID, BE ),
		rec( 16, 4, ObjectIDInfo ),
                srec(ObjectTypeStruct, req_cond="ncp.info_flags_type == TRUE"),
                srec(ObjectSecurityStruct, req_cond="ncp.info_flags_security == TRUE"),
                srec(ObjectFlagsStruct, req_cond="ncp.info_flags_flags == TRUE"),
                srec(ObjectNameStruct, req_cond="ncp.info_flags_name == TRUE"),
	])
	pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x9600, 0xef01, 0xfc02, 0xfe01, 0xff00])
	# 2222/1721, 23/33
	pkt = NCP(0x1721, "Generate GUIDs", 'nds')
	pkt.Request( 14, [
		rec( 10, 4, ReturnInfoCount ),
	])
	pkt.Reply(28, [
		rec( 8, 4, ReturnInfoCount, var="x" ),
		rec( 12, 16, GUID, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000])
	# 2222/1732, 23/50
	pkt = NCP(0x1732, "Create Bindery Object", 'bindery')
	pkt.Request( (15,62), [
		rec( 10, 1, ObjectFlags ),
		rec( 11, 1, ObjectSecurity ),
		rec( 12, 2, ObjectType, BE ),
		rec( 14, (1,48), ObjectName ),
	], info_str=(ObjectName, "Create Bindery Object: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xe700, 0xee00, 0xef00, 0xf101, 0xf501,
			     0xfc06, 0xfe07, 0xff00])
	# 2222/1733, 23/51
	pkt = NCP(0x1733, "Delete Bindery Object", 'bindery')
	pkt.Request( (13,60), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
	], info_str=(ObjectName, "Delete Bindery Object: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xf000, 0xf200, 0xf400, 0xf600, 0xfb00,
			     0xfc06, 0xfe07, 0xff00])
	# 2222/1734, 23/52
	pkt = NCP(0x1734, "Rename Bindery Object", 'bindery')
	pkt.Request( (14,108), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, (1,48), NewObjectName ),
	], info_str=(ObjectName, "Rename Bindery Object: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xee00, 0xf000, 0xf300, 0xfc06, 0xfe07, 0xff00])
	# 2222/1735, 23/53
	pkt = NCP(0x1735, "Get Bindery Object ID", 'bindery')
	pkt.Request((13,60), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
	], info_str=(ObjectName, "Get Bindery Object: %s", ", %s"))
	pkt.Reply(62, [
		rec( 8, 4, ObjectID, BE ),
		rec( 12, 2, ObjectType, BE ),
		rec( 14, 48, ObjectNameLen ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xef01, 0xf000, 0xfc02, 0xfe01, 0xff00])
	# 2222/1736, 23/54
	pkt = NCP(0x1736, "Get Bindery Object Name", 'bindery')
	pkt.Request( 14, [
		rec( 10, 4, ObjectID, BE ),
	])
	pkt.Reply( 62, [
		rec( 8, 4, ObjectID, BE ),
		rec( 12, 2, ObjectType, BE ),
		rec( 14, 48, ObjectNameLen ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xf101, 0xfc02, 0xfe01, 0xff00])
	# 2222/1737, 23/55
	pkt = NCP(0x1737, "Scan Bindery Object", 'bindery')
	pkt.Request((17,64), [
		rec( 10, 4, ObjectID, BE ),
		rec( 14, 2, ObjectType, BE ),
		rec( 16, (1,48), ObjectName ),
	], info_str=(ObjectName, "Scan Bindery Object: %s", ", %s"))
	pkt.Reply(65, [
		rec( 8, 4, ObjectID, BE ),
		rec( 12, 2, ObjectType, BE ),
		rec( 14, 48, ObjectNameLen ),
		rec( 62, 1, ObjectFlags ),
		rec( 63, 1, ObjectSecurity ),
		rec( 64, 1, ObjectHasProperties ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xef01, 0xfc02,
			     0xfe01, 0xff00])
	# 2222/1738, 23/56
	pkt = NCP(0x1738, "Change Bindery Object Security", 'bindery')
	pkt.Request((14,61), [
		rec( 10, 1, ObjectSecurity ),
		rec( 11, 2, ObjectType, BE ),
		rec( 13, (1,48), ObjectName ),
	], info_str=(ObjectName, "Change Bindery Object Security: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xf000, 0xf101, 0xf501, 0xfc02, 0xfe01, 0xff00])
	# 2222/1739, 23/57
	pkt = NCP(0x1739, "Create Property", 'bindery')
	pkt.Request((16,78), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, 1, PropertyType ),
		rec( -1, 1, ObjectSecurity ),
		rec( -1, (1,16), PropertyName ),
	], info_str=(PropertyName, "Create Property: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xed00, 0xef00, 0xf000, 0xf101,
			     0xf200, 0xf600, 0xf700, 0xfb00, 0xfc02, 0xfe01,
			     0xff00])
	# 2222/173A, 23/58
	pkt = NCP(0x173A, "Delete Property", 'bindery')
	pkt.Request((14,76), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, (1,16), PropertyName ),
	], info_str=(PropertyName, "Delete Property: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xf000, 0xf101, 0xf600, 0xfb00, 0xfc02,
			     0xfe01, 0xff00])
	# 2222/173B, 23/59
	pkt = NCP(0x173B, "Change Property Security", 'bindery')
	pkt.Request((15,77), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, 1, ObjectSecurity ),
		rec( -1, (1,16), PropertyName ),
	], info_str=(PropertyName, "Change Property Security: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xf000, 0xf101, 0xf200, 0xf600, 0xfb00,
			     0xfc02, 0xfe01, 0xff00])
	# 2222/173C, 23/60
	pkt = NCP(0x173C, "Scan Property", 'bindery')
	pkt.Request((18,80), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, 4, LastInstance, BE ),
		rec( -1, (1,16), PropertyName ),
	], info_str=(PropertyName, "Scan Property: %s", ", %s"))
	pkt.Reply( 32, [
		rec( 8, 16, PropertyName16 ),
		rec( 24, 1, ObjectFlags ),
		rec( 25, 1, ObjectSecurity ),
		rec( 26, 4, SearchInstance, BE ),
		rec( 30, 1, ValueAvailable ),
		rec( 31, 1, MoreProperties ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xf000, 0xf101, 0xf200, 0xf600, 0xfb00,
			     0xfc02, 0xfe01, 0xff00])
	# 2222/173D, 23/61
	pkt = NCP(0x173D, "Read Property Value", 'bindery')
	pkt.Request((15,77), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, 1, PropertySegment ),
		rec( -1, (1,16), PropertyName ),
	], info_str=(PropertyName, "Read Property Value: %s", ", %s"))
	pkt.Reply(138, [
		rec( 8, 128, PropertyData ),
		rec( 136, 1, PropertyHasMoreSegments ),
		rec( 137, 1, PropertyType ),
	])
	pkt.CompletionCodes([0x0000, 0x8800, 0x9300, 0x9600, 0xec01,
			     0xf000, 0xf100, 0xf900, 0xfb02, 0xfc02,
			     0xfe01, 0xff00])
	# 2222/173E, 23/62
	pkt = NCP(0x173E, "Write Property Value", 'bindery')
	pkt.Request((144,206), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, 1, PropertySegment ),
		rec( -1, 1, MoreFlag ),
		rec( -1, (1,16), PropertyName ),
		#
		# XXX - don't show this if MoreFlag isn't set?
		# In at least some packages where it's not set,
		# PropertyValue appears to be garbage.
		#
		rec( -1, 128, PropertyValue ),
	], info_str=(PropertyName, "Write Property Value: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xe800, 0xec01, 0xf000, 0xf800,
			     0xfb02, 0xfc03, 0xfe01, 0xff00 ])
	# 2222/173F, 23/63
	pkt = NCP(0x173F, "Verify Bindery Object Password", 'bindery')
	pkt.Request((14,92), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, (1,32), Password ),
	], info_str=(ObjectName, "Verify Bindery Object Password: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xe800, 0xec01, 0xf000, 0xf101,
			     0xfb02, 0xfc03, 0xfe01, 0xff00 ])
	# 2222/1740, 23/64
	pkt = NCP(0x1740, "Change Bindery Object Password", 'bindery')
	pkt.Request((15,124), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, (1,32), Password ),
		rec( -1, (1,32), NewPassword ),
	], info_str=(ObjectName, "Change Bindery Object Password: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xc501, 0xd701, 0xe800, 0xec01, 0xf001,
			     0xf100, 0xf800, 0xfb02, 0xfc03, 0xfe01, 0xff00])
	# 2222/1741, 23/65
	pkt = NCP(0x1741, "Add Bindery Object To Set", 'bindery')
	pkt.Request((17,126), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, (1,16), PropertyName ),
		rec( -1, 2, MemberType, BE ),
		rec( -1, (1,48), MemberName ),
	], info_str=(MemberName, "Add Bindery Object to Set: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xe800, 0xe900, 0xea00, 0xeb00,
			     0xec01, 0xf000, 0xf800, 0xfb02, 0xfc03, 0xfe01,
			     0xff00])
	# 2222/1742, 23/66
	pkt = NCP(0x1742, "Delete Bindery Object From Set", 'bindery')
	pkt.Request((17,126), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, (1,16), PropertyName ),
		rec( -1, 2, MemberType, BE ),
		rec( -1, (1,48), MemberName ),
	], info_str=(MemberName, "Delete Bindery Object from Set: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xeb00, 0xf000, 0xf800, 0xfb02,
			     0xfc03, 0xfe01, 0xff00])
	# 2222/1743, 23/67
	pkt = NCP(0x1743, "Is Bindery Object In Set", 'bindery')
	pkt.Request((17,126), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, (1,16), PropertyName ),
		rec( -1, 2, MemberType, BE ),
		rec( -1, (1,48), MemberName ),
	], info_str=(MemberName, "Is Bindery Object in Set: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xea00, 0xeb00, 0xec01, 0xf000,
			     0xfb02, 0xfc03, 0xfe01, 0xff00])
	# 2222/1744, 23/68
	pkt = NCP(0x1744, "Close Bindery", 'bindery')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xff00])
	# 2222/1745, 23/69
	pkt = NCP(0x1745, "Open Bindery", 'bindery')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xff00])
	# 2222/1746, 23/70
	pkt = NCP(0x1746, "Get Bindery Access Level", 'bindery')
	pkt.Request(10)
	pkt.Reply(13, [
		rec( 8, 1, ObjectSecurity ),
		rec( 9, 4, LoggedObjectID, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x9600])
	# 2222/1747, 23/71
	pkt = NCP(0x1747, "Scan Bindery Object Trustee Paths", 'bindery')
	pkt.Request(17, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 2, LastSequenceNumber, BE ),
		rec( 13, 4, ObjectID, BE ),
	])
	pkt.Reply((16,270), [
		rec( 8, 2, LastSequenceNumber, BE),
		rec( 10, 4, ObjectID, BE ),
		rec( 14, 1, ObjectSecurity ),
		rec( 15, (1,255), Path ),
	])
	pkt.CompletionCodes([0x0000, 0x9300, 0x9600, 0xa100, 0xf000, 0xf100,
			     0xf200, 0xfc02, 0xfe01, 0xff00])
	# 2222/1748, 23/72
	pkt = NCP(0x1748, "Get Bindery Object Access Level", 'bindery')
	pkt.Request(14, [
		rec( 10, 4, ObjectID, BE ),
	])
	pkt.Reply(9, [
		rec( 8, 1, ObjectSecurity ),
	])
	pkt.CompletionCodes([0x0000, 0x9600])
	# 2222/1749, 23/73
	pkt = NCP(0x1749, "Is Calling Station a Manager", 'bindery')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0003, 0xff1e])
	# 2222/174A, 23/74
	pkt = NCP(0x174A, "Keyed Verify Password", 'bindery')
	pkt.Request((21,68), [
		rec( 10, 8, LoginKey ),
		rec( 18, 2, ObjectType, BE ),
		rec( 20, (1,48), ObjectName ),
	], info_str=(ObjectName, "Keyed Verify Password: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc500, 0xfe01, 0xff0c])
	# 2222/174B, 23/75
	pkt = NCP(0x174B, "Keyed Change Password", 'bindery')
	pkt.Request((22,100), [
		rec( 10, 8, LoginKey ),
		rec( 18, 2, ObjectType, BE ),
		rec( 20, (1,48), ObjectName ),
		rec( -1, (1,32), Password ),
	], info_str=(ObjectName, "Keyed Change Password: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc500, 0xfe01, 0xff0c])
	# 2222/174C, 23/76
	pkt = NCP(0x174C, "List Relations Of an Object", 'bindery')
	pkt.Request((18,80), [
		rec( 10, 4, LastSeen, BE ),
		rec( 14, 2, ObjectType, BE ),
		rec( 16, (1,48), ObjectName ),
		rec( -1, (1,16), PropertyName ),
	], info_str=(ObjectName, "List Relations of an Object: %s", ", %s"))
	pkt.Reply(14, [
		rec( 8, 2, RelationsCount, BE, var="x" ),
		rec( 10, 4, ObjectID, BE, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0xf000, 0xf200, 0xfe01, 0xff00])
	# 2222/1764, 23/100
	pkt = NCP(0x1764, "Create Queue", 'qms')
	pkt.Request((15,316), [
		rec( 10, 2, QueueType, BE ),
		rec( 12, (1,48), QueueName ),
		rec( -1, 1, PathBase ),
		rec( -1, (1,255), Path ),
	], info_str=(QueueName, "Create Queue: %s", ", %s"))
	pkt.Reply(12, [
		rec( 8, 4, QueueID ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9900, 0xd000, 0xd100,
			     0xd200, 0xd300, 0xd400, 0xd500, 0xd601,
			     0xd703, 0xd800, 0xd902, 0xda01, 0xdb02,
			     0xee00, 0xff00])
	# 2222/1765, 23/101
	pkt = NCP(0x1765, "Destroy Queue", 'qms')
	pkt.Request(14, [
		rec( 10, 4, QueueID ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1766, 23/102
	pkt = NCP(0x1766, "Read Queue Current Status", 'qms')
	pkt.Request(14, [
		rec( 10, 4, QueueID ),
	])
	pkt.Reply(20, [
		rec( 8, 4, QueueID ),
		rec( 12, 1, QueueStatus ),
		rec( 13, 1, CurrentEntries ),
		rec( 14, 1, CurrentServers, var="x" ),
		rec( 15, 4, ServerID, repeat="x" ),
		rec( 19, 1, ServerStationList, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1767, 23/103
	pkt = NCP(0x1767, "Set Queue Current Status", 'qms')
	pkt.Request(15, [
		rec( 10, 4, QueueID ),
		rec( 14, 1, QueueStatus ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xfc07,
			     0xff00])
	# 2222/1768, 23/104
	pkt = NCP(0x1768, "Create Queue Job And File", 'qms')
	pkt.Request(264, [
		rec( 10, 4, QueueID ),
                rec( 14, 250, JobStruct ),
	])
	pkt.Reply(62, [
		rec( 8, 1, ClientStation ),
		rec( 9, 1, ClientTaskNumber ),
		rec( 10, 4, ClientIDNumber, BE ),
		rec( 14, 4, TargetServerIDNumber, BE ),
		rec( 18, 6, TargetExecutionTime ),
		rec( 24, 6, JobEntryTime ),
		rec( 30, 2, JobNumber, BE ),
		rec( 32, 2, JobType, BE ),
		rec( 34, 1, JobPosition ),
		rec( 35, 1, JobControlFlags ),
		rec( 36, 14, JobFileName ),
		rec( 50, 6, JobFileHandle ),
		rec( 56, 1, ServerStation ),
		rec( 57, 1, ServerTaskNumber ),
		rec( 58, 4, ServerID, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xfc07,
			     0xff00])
	# 2222/1769, 23/105
	pkt = NCP(0x1769, "Close File And Start Queue Job", 'qms')
	pkt.Request(16, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, JobNumber, BE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/176A, 23/106
	pkt = NCP(0x176A, "Remove Job From Queue", 'qms')
	pkt.Request(16, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, JobNumber, BE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/176B, 23/107
	pkt = NCP(0x176B, "Get Queue Job List", 'qms')
	pkt.Request(14, [
		rec( 10, 4, QueueID ),
	])
	pkt.Reply(12, [
		rec( 8, 2, JobCount, BE, var="x" ),
		rec( 10, 2, JobNumber, BE, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/176C, 23/108
	pkt = NCP(0x176C, "Read Queue Job Entry", 'qms')
	pkt.Request(16, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, JobNumber, BE ),
	])
	pkt.Reply(258, [
            rec( 8, 250, JobStruct ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/176D, 23/109
	pkt = NCP(0x176D, "Change Queue Job Entry", 'qms')
	pkt.Request(260, [
            rec( 14, 250, JobStruct ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff18])
	# 2222/176E, 23/110
	pkt = NCP(0x176E, "Change Queue Job Position", 'qms')
	pkt.Request(17, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, JobNumber, BE ),
		rec( 16, 1, NewPosition ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xd000, 0xd100, 0xd500,
			     0xd601, 0xfe07, 0xff1f])
	# 2222/176F, 23/111
	pkt = NCP(0x176F, "Attach Queue Server To Queue", 'qms')
	pkt.Request(14, [
		rec( 10, 4, QueueID ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xea00,
			     0xfc06, 0xff00])
	# 2222/1770, 23/112
	pkt = NCP(0x1770, "Detach Queue Server From Queue", 'qms')
	pkt.Request(14, [
		rec( 10, 4, QueueID ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1771, 23/113
	pkt = NCP(0x1771, "Service Queue Job", 'qms')
	pkt.Request(16, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, ServiceType, BE ),
	])
	pkt.Reply(62, [
		rec( 8, 1, ClientStation ),
		rec( 9, 1, ClientTaskNumber ),
		rec( 10, 4, ClientIDNumber, BE ),
		rec( 14, 4, TargetServerIDNumber, BE ),
		rec( 18, 6, TargetExecutionTime ),
		rec( 24, 6, JobEntryTime ),
		rec( 30, 2, JobNumber, BE ),
		rec( 32, 2, JobType, BE ),
		rec( 34, 1, JobPosition ),
		rec( 35, 1, JobControlFlags ),
		rec( 36, 14, JobFileName ),
		rec( 50, 6, JobFileHandle ),
		rec( 56, 1, ServerStation ),
		rec( 57, 1, ServerTaskNumber ),
		rec( 58, 4, ServerID, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1772, 23/114
	pkt = NCP(0x1772, "Finish Servicing Queue Job", 'qms')
	pkt.Request(20, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, JobNumber, BE ),
		rec( 16, 4, ChargeInformation, BE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1773, 23/115
	pkt = NCP(0x1773, "Abort Servicing Queue Job", 'qms')
	pkt.Request(16, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, JobNumber, BE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff18])
	# 2222/1774, 23/116
	pkt = NCP(0x1774, "Change To Client Rights", 'qms')
	pkt.Request(16, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, JobNumber, BE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff18])
	# 2222/1775, 23/117
	pkt = NCP(0x1775, "Restore Queue Server Rights", 'qms')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1776, 23/118
	pkt = NCP(0x1776, "Read Queue Server Current Status", 'qms')
	pkt.Request(19, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, ServerID, BE ),
		rec( 18, 1, ServerStation ),
	])
	pkt.Reply(72, [
		rec( 8, 64, ServerStatusRecord ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1777, 23/119
	pkt = NCP(0x1777, "Set Queue Server Current Status", 'qms')
	pkt.Request(78, [
		rec( 10, 4, QueueID ),
		rec( 14, 64, ServerStatusRecord ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1778, 23/120
	pkt = NCP(0x1778, "Get Queue Job File Size", 'qms')
	pkt.Request(16, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, JobNumber, BE ),
	])
	pkt.Reply(20, [
		rec( 8, 4, QueueID ),
		rec( 12, 4, JobNumberLong ),
		rec( 16, 4, FileSize, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1779, 23/121
	pkt = NCP(0x1779, "Create Queue Job And File", 'qms')
	pkt.Request(264, [
		rec( 10, 4, QueueID ),
                rec( 14, 250, JobStruct3x ),
	])
	pkt.Reply(94, [
		rec( 8, 86, JobStructNew ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xfc07, 0xff00])
	# 2222/177A, 23/122
	pkt = NCP(0x177A, "Read Queue Job Entry", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumberLong ),
	])
	pkt.Reply(258, [
            rec( 8, 250, JobStruct3x ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/177B, 23/123
	pkt = NCP(0x177B, "Change Queue Job Entry", 'qms')
	pkt.Request(264, [
		rec( 10, 4, QueueID ),
                rec( 14, 250, JobStruct ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xfc07, 0xff00])
	# 2222/177C, 23/124
	pkt = NCP(0x177C, "Service Queue Job", 'qms')
	pkt.Request(16, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, ServiceType ),
	])
	pkt.Reply(94, [
            rec( 8, 86, JobStructNew ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/177D, 23/125
	pkt = NCP(0x177D, "Read Queue Current Status", 'qms')
	pkt.Request(14, [
		rec( 10, 4, QueueID ),
	])
	pkt.Reply(32, [
		rec( 8, 4, QueueID ),
		rec( 12, 1, QueueStatus ),
		rec( 13, 3, Reserved3 ),
		rec( 16, 4, CurrentEntries ),
		rec( 20, 4, CurrentServers, var="x" ),
		rec( 24, 4, ServerID, repeat="x" ),
		rec( 28, 4, ServerStationLong, LE, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/177E, 23/126
	pkt = NCP(0x177E, "Set Queue Current Status", 'qms')
	pkt.Request(15, [
		rec( 10, 4, QueueID ),
		rec( 14, 1, QueueStatus ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/177F, 23/127
	pkt = NCP(0x177F, "Close File And Start Queue Job", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumberLong ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xfc07, 0xff00])
	# 2222/1780, 23/128
	pkt = NCP(0x1780, "Remove Job From Queue", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumberLong ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1781, 23/129
	pkt = NCP(0x1781, "Get Queue Job List", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumberLong ),
	])
	pkt.Reply(20, [
		rec( 8, 4, TotalQueueJobs ),
		rec( 12, 4, ReplyQueueJobNumbers, var="x" ),
		rec( 16, 4, JobNumberLong, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1782, 23/130
	pkt = NCP(0x1782, "Change Job Priority", 'qms')
	pkt.Request(22, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumberLong ),
		rec( 18, 4, Priority ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1783, 23/131
	pkt = NCP(0x1783, "Finish Servicing Queue Job", 'qms')
	pkt.Request(22, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumberLong ),
		rec( 18, 4, ChargeInformation ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1784, 23/132
	pkt = NCP(0x1784, "Abort Servicing Queue Job", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumberLong ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff18])
	# 2222/1785, 23/133
	pkt = NCP(0x1785, "Change To Client Rights", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumberLong ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff18])
	# 2222/1786, 23/134
	pkt = NCP(0x1786, "Read Queue Server Current Status", 'qms')
	pkt.Request(22, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, ServerID, BE ),
		rec( 18, 4, ServerStation ),
	])
	pkt.Reply(72, [
		rec( 8, 64, ServerStatusRecord ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1787, 23/135
	pkt = NCP(0x1787, "Get Queue Job File Size", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumberLong ),
	])
	pkt.Reply(20, [
		rec( 8, 4, QueueID ),
		rec( 12, 4, JobNumberLong ),
		rec( 16, 4, FileSize, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1788, 23/136
	pkt = NCP(0x1788, "Move Queue Job From Src Q to Dst Q", 'qms')
	pkt.Request(22, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumberLong ),
		rec( 18, 4, DstQueueID ),
	])
	pkt.Reply(12, [
		rec( 8, 4, JobNumberLong ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0xfc06])
	# 2222/1789, 23/137
	pkt = NCP(0x1789, "Get Queue Jobs From Form List", 'qms')
	pkt.Request(24, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, QueueStartPosition ),
		rec( 18, 4, FormTypeCnt, var="x" ),
		rec( 22, 2, FormType, repeat="x" ),
	])
	pkt.Reply(20, [
		rec( 8, 4, TotalQueueJobs ),
		rec( 12, 4, JobCount, var="x" ),
		rec( 16, 4, JobNumberLong, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0xfc06])
	# 2222/178A, 23/138
	pkt = NCP(0x178A, "Service Queue Job By Form List", 'qms')
	pkt.Request(24, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, QueueStartPosition ),
		rec( 18, 4, FormTypeCnt, var= "x" ),
		rec( 22, 2, FormType, repeat="x" ),
	])
	pkt.Reply(94, [
           rec( 8, 86, JobStructNew ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0xfc06])
	# 2222/1796, 23/150
	pkt = NCP(0x1796, "Get Current Account Status", 'accounting')
	pkt.Request((13,60), [
		rec( 10, 2, ObjectType, BE ),
		rec( 12, (1,48), ObjectName ),
	], info_str=(ObjectName, "Get Current Account Status: %s", ", %s"))
	pkt.Reply(264, [
		rec( 8, 4, AccountBalance, BE ),
		rec( 12, 4, CreditLimit, BE ),
		rec( 16, 120, Reserved120 ),
		rec( 136, 4, HolderID, BE ),
		rec( 140, 4, HoldAmount, BE ),
		rec( 144, 4, HolderID, BE ),
		rec( 148, 4, HoldAmount, BE ),
		rec( 152, 4, HolderID, BE ),
		rec( 156, 4, HoldAmount, BE ),
		rec( 160, 4, HolderID, BE ),
		rec( 164, 4, HoldAmount, BE ),
		rec( 168, 4, HolderID, BE ),
		rec( 172, 4, HoldAmount, BE ),
		rec( 176, 4, HolderID, BE ),
		rec( 180, 4, HoldAmount, BE ),
		rec( 184, 4, HolderID, BE ),
		rec( 188, 4, HoldAmount, BE ),
		rec( 192, 4, HolderID, BE ),
		rec( 196, 4, HoldAmount, BE ),
		rec( 200, 4, HolderID, BE ),
		rec( 204, 4, HoldAmount, BE ),
		rec( 208, 4, HolderID, BE ),
		rec( 212, 4, HoldAmount, BE ),
		rec( 216, 4, HolderID, BE ),
		rec( 220, 4, HoldAmount, BE ),
		rec( 224, 4, HolderID, BE ),
		rec( 228, 4, HoldAmount, BE ),
		rec( 232, 4, HolderID, BE ),
		rec( 236, 4, HoldAmount, BE ),
		rec( 240, 4, HolderID, BE ),
		rec( 244, 4, HoldAmount, BE ),
		rec( 248, 4, HolderID, BE ),
		rec( 252, 4, HoldAmount, BE ),
		rec( 256, 4, HolderID, BE ),
		rec( 260, 4, HoldAmount, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc000, 0xc101, 0xc400, 0xe800,
			     0xea00, 0xeb00, 0xec00, 0xfc06, 0xfe07, 0xff00])
	# 2222/1797, 23/151
	pkt = NCP(0x1797, "Submit Account Charge", 'accounting')
	pkt.Request((26,327), [
		rec( 10, 2, ServiceType, BE ),
		rec( 12, 4, ChargeAmount, BE ),
		rec( 16, 4, HoldCancelAmount, BE ),
		rec( 20, 2, ObjectType, BE ),
		rec( 22, 2, CommentType, BE ),
		rec( 24, (1,48), ObjectName ),
		rec( -1, (1,255), Comment ),
	], info_str=(ObjectName, "Submit Account Charge: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0102, 0x8800, 0x9400, 0x9600, 0xa201,
			     0xc000, 0xc101, 0xc200, 0xc400, 0xe800, 0xea00,
			     0xeb00, 0xec00, 0xfe07, 0xff00])
	# 2222/1798, 23/152
	pkt = NCP(0x1798, "Submit Account Hold", 'accounting')
	pkt.Request((17,64), [
		rec( 10, 4, HoldCancelAmount, BE ),
		rec( 14, 2, ObjectType, BE ),
		rec( 16, (1,48), ObjectName ),
	], info_str=(ObjectName, "Submit Account Hold: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0102, 0x8800, 0x9400, 0x9600, 0xa201,
			     0xc000, 0xc101, 0xc200, 0xc400, 0xe800, 0xea00,
			     0xeb00, 0xec00, 0xfe07, 0xff00])
	# 2222/1799, 23/153
	pkt = NCP(0x1799, "Submit Account Note", 'accounting')
	pkt.Request((18,319), [
		rec( 10, 2, ServiceType, BE ),
		rec( 12, 2, ObjectType, BE ),
		rec( 14, 2, CommentType, BE ),
		rec( 16, (1,48), ObjectName ),
		rec( -1, (1,255), Comment ),
	], info_str=(ObjectName, "Submit Account Note: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0102, 0x9600, 0xc000, 0xc101, 0xc400,
			     0xe800, 0xea00, 0xeb00, 0xec00, 0xf000, 0xfc06,
			     0xff00])
	# 2222/17c8, 23/200
	pkt = NCP(0x17c8, "Check Console Privileges", 'stats')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc601])
	# 2222/17c9, 23/201
	pkt = NCP(0x17c9, "Get File Server Description Strings", 'stats')
	pkt.Request(10)
	pkt.Reply(108, [
		rec( 8, 100, DescriptionStrings ),
	])
	pkt.CompletionCodes([0x0000, 0x9600])
	# 2222/17CA, 23/202
	pkt = NCP(0x17CA, "Set File Server Date And Time", 'stats')
	pkt.Request(16, [
		rec( 10, 1, Year ),
		rec( 11, 1, Month ),
		rec( 12, 1, Day ),
		rec( 13, 1, Hour ),
		rec( 14, 1, Minute ),
		rec( 15, 1, Second ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc601])
	# 2222/17CB, 23/203
	pkt = NCP(0x17CB, "Disable File Server Login", 'stats')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc601])
	# 2222/17CC, 23/204
	pkt = NCP(0x17CC, "Enable File Server Login", 'stats')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc601])
	# 2222/17CD, 23/205
	pkt = NCP(0x17CD, "Get File Server Login Status", 'stats')
	pkt.Request(10)
	pkt.Reply(12, [
		rec( 8, 4, UserLoginAllowed ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xfb01])
	# 2222/17CF, 23/207
	pkt = NCP(0x17CF, "Disable Transaction Tracking", 'stats')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc601])
	# 2222/17D0, 23/208
	pkt = NCP(0x17D0, "Enable Transaction Tracking", 'stats')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc601])
	# 2222/17D1, 23/209
	pkt = NCP(0x17D1, "Send Console Broadcast", 'stats')
	pkt.Request((13,267), [
		rec( 10, 1, NumberOfStations, var="x" ),
		rec( 11, 1, StationList, repeat="x" ),
		rec( 12, (1, 255), TargetMessage ),
	], info_str=(TargetMessage, "Send Console Broadcast: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc601, 0xfd00])
	# 2222/17D2, 23/210
	pkt = NCP(0x17D2, "Clear Connection Number", 'stats')
	pkt.Request(11, [
		rec( 10, 1, ConnectionNumber ),
	],info_str=(ConnectionNumber, "Clear Connection Number %d", ", %d"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc601, 0xfd00])
	# 2222/17D3, 23/211
	pkt = NCP(0x17D3, "Down File Server", 'stats')
	pkt.Request(11, [
		rec( 10, 1, ForceFlag ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc601, 0xff00])
	# 2222/17D4, 23/212
	pkt = NCP(0x17D4, "Get File System Statistics", 'stats')
	pkt.Request(10)
	pkt.Reply(50, [
		rec( 8, 4, SystemIntervalMarker, BE ),
		rec( 12, 2, ConfiguredMaxOpenFiles ),
		rec( 14, 2, ActualMaxOpenFiles ),
		rec( 16, 2, CurrentOpenFiles ),
		rec( 18, 4, TotalFilesOpened ),
		rec( 22, 4, TotalReadRequests ),
		rec( 26, 4, TotalWriteRequests ),
		rec( 30, 2, CurrentChangedFATs ),
		rec( 32, 4, TotalChangedFATs ),
		rec( 36, 2, FATWriteErrors ),
		rec( 38, 2, FatalFATWriteErrors ),
		rec( 40, 2, FATScanErrors ),
		rec( 42, 2, ActualMaxIndexedFiles ),
		rec( 44, 2, ActiveIndexedFiles ),
		rec( 46, 2, AttachedIndexedFiles ),
		rec( 48, 2, AvailableIndexedFiles ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xff00])
	# 2222/17D5, 23/213
	pkt = NCP(0x17D5, "Get Transaction Tracking Statistics", 'stats')
	pkt.Request((13,267), [
		rec( 10, 2, LastRecordSeen ),
		rec( 12, (1,255), SemaphoreName ),
	])
	pkt.Reply(53, [
		rec( 8, 4, SystemIntervalMarker, BE ),
		rec( 12, 1, TransactionTrackingSupported ),
		rec( 13, 1, TransactionTrackingEnabled ),
		rec( 14, 2, TransactionVolumeNumber ),
		rec( 16, 2, ConfiguredMaxSimultaneousTransactions ),
		rec( 18, 2, ActualMaxSimultaneousTransactions ),
		rec( 20, 2, CurrentTransactionCount ),
		rec( 22, 4, TotalTransactionsPerformed ),
		rec( 26, 4, TotalWriteTransactionsPerformed ),
		rec( 30, 4, TotalTransactionsBackedOut ),
		rec( 34, 2, TotalUnfilledBackoutRequests ),
		rec( 36, 2, TransactionDiskSpace ),
		rec( 38, 4, TransactionFATAllocations ),
		rec( 42, 4, TransactionFileSizeChanges ),
		rec( 46, 4, TransactionFilesTruncated ),
		rec( 50, 1, NumberOfEntries, var="x" ),
		rec( 51, 2, ConnTaskStruct, repeat="x" ),
 	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xff00])
	# 2222/17D6, 23/214
	pkt = NCP(0x17D6, "Read Disk Cache Statistics", 'stats')
	pkt.Request(10)
	pkt.Reply(86, [
		rec( 8, 4, SystemIntervalMarker, BE ),
		rec( 12, 2, CacheBufferCount ),
		rec( 14, 2, CacheBufferSize ),
		rec( 16, 2, DirtyCacheBuffers ),
		rec( 18, 4, CacheReadRequests ),
		rec( 22, 4, CacheWriteRequests ),
		rec( 26, 4, CacheHits ),
		rec( 30, 4, CacheMisses ),
		rec( 34, 4, PhysicalReadRequests ),
		rec( 38, 4, PhysicalWriteRequests ),
		rec( 42, 2, PhysicalReadErrors ),
		rec( 44, 2, PhysicalWriteErrors ),
		rec( 46, 4, CacheGetRequests ),
		rec( 50, 4, CacheFullWriteRequests ),
		rec( 54, 4, CachePartialWriteRequests ),
		rec( 58, 4, BackgroundDirtyWrites ),
		rec( 62, 4, BackgroundAgedWrites ),
		rec( 66, 4, TotalCacheWrites ),
		rec( 70, 4, CacheAllocations ),
		rec( 74, 2, ThrashingCount ),
		rec( 76, 2, LRUBlockWasDirty ),
		rec( 78, 2, ReadBeyondWrite ),
		rec( 80, 2, FragmentWriteOccurred ),
		rec( 82, 2, CacheHitOnUnavailableBlock ),
		rec( 84, 2, CacheBlockScrapped ),
 	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xff00])
	# 2222/17D7, 23/215
	pkt = NCP(0x17D7, "Get Drive Mapping Table", 'stats')
	pkt.Request(10)
	pkt.Reply(184, [
		rec( 8, 4, SystemIntervalMarker, BE ),
		rec( 12, 1, SFTSupportLevel ),
		rec( 13, 1, LogicalDriveCount ),
		rec( 14, 1, PhysicalDriveCount ),
		rec( 15, 1, DiskChannelTable ),
		rec( 16, 4, Reserved4 ),
		rec( 20, 2, PendingIOCommands, BE ),
		rec( 22, 32, DriveMappingTable ),
		rec( 54, 32, DriveMirrorTable ),
		rec( 86, 32, DeadMirrorTable ),
		rec( 118, 1, ReMirrorDriveNumber ),
		rec( 119, 1, Filler ),
		rec( 120, 4, ReMirrorCurrentOffset, BE ),
		rec( 124, 60, SFTErrorTable ),
 	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xff00])
	# 2222/17D8, 23/216
	pkt = NCP(0x17D8, "Read Physical Disk Statistics", 'stats')
	pkt.Request(11, [
		rec( 10, 1, PhysicalDiskNumber ),
	])
 	pkt.Reply(101, [
		rec( 8, 4, SystemIntervalMarker, BE ),
		rec( 12, 1, PhysicalDiskChannel ),
		rec( 13, 1, DriveRemovableFlag ),
		rec( 14, 1, PhysicalDriveType ),
		rec( 15, 1, ControllerDriveNumber ),
		rec( 16, 1, ControllerNumber ),
		rec( 17, 1, ControllerType ),
		rec( 18, 4, DriveSize ),
		rec( 22, 2, DriveCylinders ),
		rec( 24, 1, DriveHeads ),
		rec( 25, 1, SectorsPerTrack ),
		rec( 26, 64, DriveDefinitionString ),
		rec( 90, 2, IOErrorCount ),
		rec( 92, 4, HotFixTableStart ),
		rec( 96, 2, HotFixTableSize ),
		rec( 98, 2, HotFixBlocksAvailable ),
		rec( 100, 1, HotFixDisabled ),
 	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xff00])
	# 2222/17D9, 23/217
	pkt = NCP(0x17D9, "Get Disk Channel Statistics", 'stats')
	pkt.Request(11, [
		rec( 10, 1, DiskChannelNumber ),
	])
 	pkt.Reply(192, [
		rec( 8, 4, SystemIntervalMarker, BE ),
		rec( 12, 2, ChannelState, BE ),
		rec( 14, 2, ChannelSynchronizationState, BE ),
		rec( 16, 1, SoftwareDriverType ),
		rec( 17, 1, SoftwareMajorVersionNumber ),
		rec( 18, 1, SoftwareMinorVersionNumber ),
		rec( 19, 65, SoftwareDescription ),
		rec( 84, 8, IOAddressesUsed ),
		rec( 92, 10, SharedMemoryAddresses ),
		rec( 102, 4, InterruptNumbersUsed ),
		rec( 106, 4, DMAChannelsUsed ),
		rec( 110, 1, FlagBits ),
		rec( 111, 1, Reserved ),
		rec( 112, 80, ConfigurationDescription ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xff00])
	# 2222/17DB, 23/219
	pkt = NCP(0x17DB, "Get Connection's Open Files", 'file')
	pkt.Request(14, [
		rec( 10, 2, ConnectionNumber ),
		rec( 12, 2, LastRecordSeen, BE ),
	])
 	pkt.Reply(32, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 1, NumberOfRecords, var="x" ),
		rec( 11, 21, ConnStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xff00])
	# 2222/17DC, 23/220
	pkt = NCP(0x17DC, "Get Connection Using A File", 'file')
	pkt.Request((14,268), [
		rec( 10, 2, LastRecordSeen, BE ),
		rec( 12, 1, DirHandle ),
		rec( 13, (1,255), Path ),
	], info_str=(Path, "Get Connection Using File: %s", ", %s"))
 	pkt.Reply(30, [
		rec( 8, 2, UseCount, BE ),
		rec( 10, 2, OpenCount, BE ),
		rec( 12, 2, OpenForReadCount, BE ),
		rec( 14, 2, OpenForWriteCount, BE ),
		rec( 16, 2, DenyReadCount, BE ),
		rec( 18, 2, DenyWriteCount, BE ),
		rec( 20, 2, NextRequestRecord, BE ),
		rec( 22, 1, Locked ),
		rec( 23, 1, NumberOfRecords, var="x" ),
		rec( 24, 6, ConnFileStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xff00])
	# 2222/17DD, 23/221
	pkt = NCP(0x17DD, "Get Physical Record Locks By Connection And File", 'file')
	pkt.Request(31, [
		rec( 10, 2, TargetConnectionNumber ),
		rec( 12, 2, LastRecordSeen, BE ),
		rec( 14, 1, VolumeNumber ),
		rec( 15, 2, DirectoryID ),
		rec( 17, 14, FileName14 ),
	], info_str=(FileName14, "Get Physical Record Locks by Connection and File: %s", ", %s"))
 	pkt.Reply(22, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 1, NumberOfLocks, var="x" ),
		rec( 11, 1, Reserved ),
		rec( 12, 10, LockStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17DE, 23/222
	pkt = NCP(0x17DE, "Get Physical Record Locks By File", 'file')
	pkt.Request((14,268), [
		rec( 10, 2, TargetConnectionNumber ),
		rec( 12, 1, DirHandle ),
		rec( 13, (1,255), Path ),
	], info_str=(Path, "Get Physical Record Locks by File: %s", ", %s"))
 	pkt.Reply(28, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 1, NumberOfLocks, var="x" ),
		rec( 11, 1, Reserved ),
		rec( 12, 16, PhyLockStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17DF, 23/223
	pkt = NCP(0x17DF, "Get Logical Records By Connection", 'file')
	pkt.Request(14, [
		rec( 10, 2, TargetConnectionNumber ),
		rec( 12, 2, LastRecordSeen, BE ),
	])
 	pkt.Reply((14,268), [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 1, NumberOfRecords, var="x" ),
		rec( 11, (3, 257), LogLockStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E0, 23/224
	pkt = NCP(0x17E0, "Get Logical Record Information", 'file')
	pkt.Request((13,267), [
		rec( 10, 2, LastRecordSeen ),
		rec( 12, (1,255), LogicalRecordName ),
	], info_str=(LogicalRecordName, "Get Logical Record Information: %s", ", %s"))
 	pkt.Reply(20, [
		rec( 8, 2, UseCount, BE ),
		rec( 10, 2, ShareableLockCount, BE ),
		rec( 12, 2, NextRequestRecord ),
		rec( 14, 1, Locked ),
		rec( 15, 1, NumberOfRecords, var="x" ),
		rec( 16, 4, LogRecStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E1, 23/225
	pkt = NCP(0x17E1, "Get Connection's Semaphores", 'file')
	pkt.Request(14, [
		rec( 10, 2, ConnectionNumber ),
		rec( 12, 2, LastRecordSeen ),
	])
 	pkt.Reply((18,272), [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 2, NumberOfSemaphores, var="x" ),
		rec( 12, (6,260), SemaStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E2, 23/226
	pkt = NCP(0x17E2, "Get Semaphore Information", 'file')
	pkt.Request((13,267), [
		rec( 10, 2, LastRecordSeen ),
		rec( 12, (1,255), SemaphoreName ),
	], info_str=(SemaphoreName, "Get Semaphore Information: %s", ", %s"))
 	pkt.Reply(17, [
		rec( 8, 2, NextRequestRecord, BE ),
		rec( 10, 2, OpenCount, BE ),
		rec( 12, 1, SemaphoreValue ),
		rec( 13, 1, NumberOfRecords, var="x" ),
		rec( 14, 3, SemaInfoStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E3, 23/227
	pkt = NCP(0x17E3, "Get LAN Driver Configuration Information", 'stats')
	pkt.Request(11, [
		rec( 10, 1, LANDriverNumber ),
	])
 	pkt.Reply(180, [
		rec( 8, 4, NetworkAddress, BE ),
		rec( 12, 6, HostAddress ),
		rec( 18, 1, BoardInstalled ),
		rec( 19, 1, OptionNumber ),
		rec( 20, 160, ConfigurationText ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E5, 23/229
	pkt = NCP(0x17E5, "Get Connection Usage Statistics", 'stats')
	pkt.Request(12, [
		rec( 10, 2, ConnectionNumber ),
	])
 	pkt.Reply(26, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 6, BytesRead ),
		rec( 16, 6, BytesWritten ),
		rec( 22, 4, TotalRequestPackets ),
	 ])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E6, 23/230
	pkt = NCP(0x17E6, "Get Object's Remaining Disk Space", 'stats')
	pkt.Request(14, [
		rec( 10, 4, ObjectID, BE ),
	])
 	pkt.Reply(21, [
		rec( 8, 4, SystemIntervalMarker, BE ),
		rec( 12, 4, ObjectID ),
		rec( 16, 4, UnusedDiskBlocks, BE ),
		rec( 20, 1, RestrictionsEnforced ),
	 ])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E7, 23/231
	pkt = NCP(0x17E7, "Get File Server LAN I/O Statistics", 'stats')
	pkt.Request(10)
 	pkt.Reply(74, [
		rec( 8, 4, SystemIntervalMarker, BE ),
		rec( 12, 2, ConfiguredMaxRoutingBuffers ),
		rec( 14, 2, ActualMaxUsedRoutingBuffers ),
		rec( 16, 2, CurrentlyUsedRoutingBuffers ),
		rec( 18, 4, TotalFileServicePackets ),
		rec( 22, 2, TurboUsedForFileService ),
		rec( 24, 2, PacketsFromInvalidConnection ),
		rec( 26, 2, BadLogicalConnectionCount ),
		rec( 28, 2, PacketsReceivedDuringProcessing ),
		rec( 30, 2, RequestsReprocessed ),
		rec( 32, 2, PacketsWithBadSequenceNumber ),
		rec( 34, 2, DuplicateRepliesSent ),
		rec( 36, 2, PositiveAcknowledgesSent ),
		rec( 38, 2, PacketsWithBadRequestType ),
		rec( 40, 2, AttachDuringProcessing ),
		rec( 42, 2, AttachWhileProcessingAttach ),
		rec( 44, 2, ForgedDetachedRequests ),
		rec( 46, 2, DetachForBadConnectionNumber ),
		rec( 48, 2, DetachDuringProcessing ),
		rec( 50, 2, RepliesCancelled ),
		rec( 52, 2, PacketsDiscardedByHopCount ),
		rec( 54, 2, PacketsDiscardedUnknownNet ),
		rec( 56, 2, IncomingPacketDiscardedNoDGroup ),
		rec( 58, 2, OutgoingPacketDiscardedNoTurboBuffer ),
		rec( 60, 2, IPXNotMyNetwork ),
		rec( 62, 4, NetBIOSBroadcastWasPropogated ),
		rec( 66, 4, TotalOtherPackets ),
		rec( 70, 4, TotalRoutedPackets ),
 	 ])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E8, 23/232
	pkt = NCP(0x17E8, "Get File Server Misc Information", 'stats')
	pkt.Request(10)
 	pkt.Reply(40, [
		rec( 8, 4, SystemIntervalMarker, BE ),
		rec( 12, 1, ProcessorType ),
		rec( 13, 1, Reserved ),
		rec( 14, 1, NumberOfServiceProcesses ),
		rec( 15, 1, ServerUtilizationPercentage ),
		rec( 16, 2, ConfiguredMaxBinderyObjects ),
		rec( 18, 2, ActualMaxBinderyObjects ),
		rec( 20, 2, CurrentUsedBinderyObjects ),
		rec( 22, 2, TotalServerMemory ),
		rec( 24, 2, WastedServerMemory ),
		rec( 26, 2, NumberOfDynamicMemoryAreas, var="x" ),
		rec( 28, 12, DynMemStruct, repeat="x" ),
 	 ])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E9, 23/233
	pkt = NCP(0x17E9, "Get Volume Information", 'stats')
	pkt.Request(11, [
		rec( 10, 1, VolumeNumber ),
	],info_str=(VolumeNumber, "Get Information on Volume %d", ", %d"))
 	pkt.Reply(48, [
		rec( 8, 4, SystemIntervalMarker, BE ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 1, LogicalDriveNumber ),
		rec( 14, 2, BlockSize ),
		rec( 16, 2, StartingBlock ),
		rec( 18, 2, TotalBlocks ),
		rec( 20, 2, FreeBlocks ),
		rec( 22, 2, TotalDirectoryEntries ),
		rec( 24, 2, FreeDirectoryEntries ),
		rec( 26, 2, ActualMaxUsedDirectoryEntries ),
		rec( 28, 1, VolumeHashedFlag ),
		rec( 29, 1, VolumeCachedFlag ),
		rec( 30, 1, VolumeRemovableFlag ),
		rec( 31, 1, VolumeMountedFlag ),
		rec( 32, 16, VolumeName ),
 	 ])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17EA, 23/234
	pkt = NCP(0x17EA, "Get Connection's Task Information", 'stats')
	pkt.Request(12, [
		rec( 10, 2, ConnectionNumber ),
	])
 	pkt.Reply(18, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 4, NumberOfAttributes, var="x" ),
		rec( 14, 4, Attributes, repeat="x" ),
 	 ])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17EB, 23/235
	pkt = NCP(0x17EB, "Get Connection's Open Files", 'file')
	pkt.Request(14, [
		rec( 10, 2, ConnectionNumber ),
		rec( 12, 2, LastRecordSeen ),
	])
 	pkt.Reply((29,283), [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 2, NumberOfRecords, var="x" ),
		rec( 12, (17, 271), OpnFilesStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xff00])
	# 2222/17EC, 23/236
	pkt = NCP(0x17EC, "Get Connection Using A File", 'file')
	pkt.Request(18, [
		rec( 10, 1, DataStreamNumber ),
		rec( 11, 1, VolumeNumber ),
		rec( 12, 4, DirectoryBase, LE ),
		rec( 16, 2, LastRecordSeen ),
	])
 	pkt.Reply(33, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 2, UseCount ),
		rec( 12, 2, OpenCount ),
		rec( 14, 2, OpenForReadCount ),
		rec( 16, 2, OpenForWriteCount ),
		rec( 18, 2, DenyReadCount ),
		rec( 20, 2, DenyWriteCount ),
		rec( 22, 1, Locked ),
		rec( 23, 1, ForkCount ),
		rec( 24, 2, NumberOfRecords, var="x" ),
		rec( 26, 7, ConnStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xff00])
	# 2222/17ED, 23/237
	pkt = NCP(0x17ED, "Get Physical Record Locks By Connection And File", 'file')
	pkt.Request(20, [
		rec( 10, 2, TargetConnectionNumber ),
		rec( 12, 1, DataStreamNumber ),
		rec( 13, 1, VolumeNumber ),
		rec( 14, 4, DirectoryBase, LE ),
		rec( 18, 2, LastRecordSeen ),
	])
 	pkt.Reply(23, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 2, NumberOfLocks, var="x" ),
		rec( 12, 11, LockStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17EE, 23/238
	pkt = NCP(0x17EE, "Get Physical Record Locks By File", 'file')
	pkt.Request(18, [
		rec( 10, 1, DataStreamNumber ),
		rec( 11, 1, VolumeNumber ),
		rec( 12, 4, DirectoryBase ),
		rec( 16, 2, LastRecordSeen ),
	])
 	pkt.Reply(30, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 2, NumberOfLocks, var="x" ),
		rec( 12, 18, PhyLockStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17EF, 23/239
	pkt = NCP(0x17EF, "Get Logical Records By Connection", 'file')
	pkt.Request(14, [
		rec( 10, 2, TargetConnectionNumber ),
		rec( 12, 2, LastRecordSeen ),
	])
 	pkt.Reply((16,270), [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 2, NumberOfRecords, var="x" ),
		rec( 12, (4, 258), LogLockStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17F0, 23/240
	pkt = NCP(0x17F0, "Get Logical Record Information (old)", 'file')
	pkt.Request((13,267), [
		rec( 10, 2, LastRecordSeen ),
		rec( 12, (1,255), LogicalRecordName ),
	])
 	pkt.Reply(22, [
		rec( 8, 2, ShareableLockCount ),
		rec( 10, 2, UseCount ),
		rec( 12, 1, Locked ),
		rec( 13, 2, NextRequestRecord ),
		rec( 15, 2, NumberOfRecords, var="x" ),
		rec( 17, 5, LogRecStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17F1, 23/241
	pkt = NCP(0x17F1, "Get Connection's Semaphores", 'file')
	pkt.Request(14, [
		rec( 10, 2, ConnectionNumber ),
		rec( 12, 2, LastRecordSeen ),
	])
 	pkt.Reply((19,273), [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 2, NumberOfSemaphores, var="x" ),
		rec( 12, (7, 261), SemaStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17F2, 23/242
	pkt = NCP(0x17F2, "Get Semaphore Information", 'file')
	pkt.Request((13,267), [
		rec( 10, 2, LastRecordSeen ),
		rec( 12, (1,255), SemaphoreName ),
	], info_str=(SemaphoreName, "Get Semaphore Information: %s", ", %s"))
 	pkt.Reply(20, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 2, OpenCount ),
		rec( 12, 2, SemaphoreValue ),
		rec( 14, 2, NumberOfRecords, var="x" ),
		rec( 16, 4, SemaInfoStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17F3, 23/243
	pkt = NCP(0x17F3, "Map Directory Number to Path", 'file')
	pkt.Request(16, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, DirectoryNumber ),
		rec( 15, 1, NameSpace ),
	])
 	pkt.Reply((9,263), [
		rec( 8, (1,255), Path ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9c00, 0xc601, 0xfd00, 0xff00])
	# 2222/17F4, 23/244
	pkt = NCP(0x17F4, "Convert Path to Dir Entry", 'file')
	pkt.Request((12,266), [
		rec( 10, 1, DirHandle ),
		rec( 11, (1,255), Path ),
	], info_str=(Path, "Convert Path to Directory Entry: %s", ", %s"))
 	pkt.Reply(13, [
		rec( 8, 1, VolumeNumber ),
		rec( 9, 4, DirectoryNumber ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17FD, 23/253
	pkt = NCP(0x17FD, "Send Console Broadcast", 'stats')
	pkt.Request((16, 270), [
		rec( 10, 1, NumberOfStations, var="x" ),
		rec( 11, 4, StationList, repeat="x" ),
		rec( 15, (1, 255), TargetMessage ),
	], info_str=(TargetMessage, "Send Console Broadcast: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc601, 0xfd00])
	# 2222/17FE, 23/254
	pkt = NCP(0x17FE, "Clear Connection Number", 'stats')
	pkt.Request(14, [
		rec( 10, 4, ConnectionNumber ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc601, 0xfd00])
	# 2222/18, 24
	pkt = NCP(0x18, "End of Job", 'connection')
	pkt.Request(7)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/19, 25
	pkt = NCP(0x19, "Logout", 'connection')
	pkt.Request(7)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/1A, 26
	pkt = NCP(0x1A, "Log Physical Record", 'file')
	pkt.Request(24, [
		rec( 7, 1, LockFlag ),
		rec( 8, 6, FileHandle ),
		rec( 14, 4, LockAreasStartOffset, BE ),
		rec( 18, 4, LockAreaLen, BE ),
		rec( 22, 2, LockTimeout ),
	], info_str=(LockAreaLen, "Lock Record - Length of %d", "%d"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0x9600, 0xfd02, 0xfe04, 0xff01])
	# 2222/1B, 27
	pkt = NCP(0x1B, "Lock Physical Record Set", 'file')
	pkt.Request(10, [
		rec( 7, 1, LockFlag ),
		rec( 8, 2, LockTimeout ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0x9600, 0xfd02, 0xfe04, 0xff01])
	# 2222/1C, 28
	pkt = NCP(0x1C, "Release Physical Record", 'file')
	pkt.Request(22, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
		rec( 14, 4, LockAreasStartOffset ),
		rec( 18, 4, LockAreaLen ),
	], info_str=(LockAreaLen, "Release Lock Record - Length of %d", "%d"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0x9600, 0xfd02, 0xfe04, 0xff03])
	# 2222/1D, 29
	pkt = NCP(0x1D, "Release Physical Record Set", 'file')
	pkt.Request(8, [
		rec( 7, 1, LockFlag ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0x9600, 0xfd02, 0xfe04, 0xff03])
	# 2222/1E, 30   #Tested and fixed 6-14-02 GM
	pkt = NCP(0x1E, "Clear Physical Record", 'file')
	pkt.Request(22, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
		rec( 14, 4, LockAreasStartOffset, BE ),
		rec( 18, 4, LockAreaLen, BE ),
	], info_str=(LockAreaLen, "Clear Lock Record - Length of %d", "%d"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0x9600, 0xfd02, 0xfe04, 0xff03])
	# 2222/1F, 31
	pkt = NCP(0x1F, "Clear Physical Record Set", 'file')
	pkt.Request(8, [
		rec( 7, 1, LockFlag ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0x9600, 0xfd02, 0xfe04, 0xff03])
	# 2222/2000, 32/00
	pkt = NCP(0x2000, "Open Semaphore", 'file', has_length=0)
	pkt.Request(10, [
		rec( 8, 1, InitialSemaphoreValue ),
		rec( 9, 1, SemaphoreNameLen ),
	])
	pkt.Reply(13, [
		  rec( 8, 4, SemaphoreHandle, BE ),
		  rec( 12, 1, SemaphoreOpenCount ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xff01])
	# 2222/2001, 32/01
	pkt = NCP(0x2001, "Examine Semaphore", 'file', has_length=0)
	pkt.Request(12, [
		rec( 8, 4, SemaphoreHandle, BE ),
	])
	pkt.Reply(10, [
		  rec( 8, 1, SemaphoreValue ),
		  rec( 9, 1, SemaphoreOpenCount ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xff01])
	# 2222/2002, 32/02
	pkt = NCP(0x2002, "Wait On Semaphore", 'file', has_length=0)
	pkt.Request(14, [
		rec( 8, 4, SemaphoreHandle, BE ),
		rec( 12, 2, SemaphoreTimeOut, BE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xff01])
	# 2222/2003, 32/03
	pkt = NCP(0x2003, "Signal Semaphore", 'file', has_length=0)
	pkt.Request(12, [
		rec( 8, 4, SemaphoreHandle, BE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xff01])
	# 2222/2004, 32/04
	pkt = NCP(0x2004, "Close Semaphore", 'file', has_length=0)
	pkt.Request(12, [
		rec( 8, 4, SemaphoreHandle, BE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xff01])
	# 2222/21, 33
	pkt = NCP(0x21, "Negotiate Buffer Size", 'connection')
	pkt.Request(9, [
		rec( 7, 2, BufferSize, BE ),
	])
	pkt.Reply(10, [
		rec( 8, 2, BufferSize, BE ),
	])
	pkt.CompletionCodes([0x0000])
	# 2222/2200, 34/00
	pkt = NCP(0x2200, "TTS Is Available", 'tts', has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0001, 0xfd03, 0xff12])
	# 2222/2201, 34/01
	pkt = NCP(0x2201, "TTS Begin Transaction", 'tts', has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/2202, 34/02
	pkt = NCP(0x2202, "TTS End Transaction", 'tts', has_length=0)
	pkt.Request(8)
	pkt.Reply(12, [
		  rec( 8, 4, TransactionNumber, BE ),
	])
	pkt.CompletionCodes([0x0000, 0xff01])
	# 2222/2203, 34/03
	pkt = NCP(0x2203, "TTS Abort Transaction", 'tts', has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xfd03, 0xfe0b, 0xff01])
	# 2222/2204, 34/04
	pkt = NCP(0x2204, "TTS Transaction Status", 'tts', has_length=0)
	pkt.Request(12, [
		  rec( 8, 4, TransactionNumber, BE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/2205, 34/05
	pkt = NCP(0x2205, "TTS Get Application Thresholds", 'tts', has_length=0)
	pkt.Request(8)
	pkt.Reply(10, [
		  rec( 8, 1, LogicalLockThreshold ),
		  rec( 9, 1, PhysicalLockThreshold ),
	])
	pkt.CompletionCodes([0x0000])
	# 2222/2206, 34/06
	pkt = NCP(0x2206, "TTS Set Application Thresholds", 'tts', has_length=0)
	pkt.Request(10, [
		  rec( 8, 1, LogicalLockThreshold ),
		  rec( 9, 1, PhysicalLockThreshold ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600])
	# 2222/2207, 34/07
	pkt = NCP(0x2207, "TTS Get Workstation Thresholds", 'tts', has_length=0)
	pkt.Request(10, [
		  rec( 8, 1, LogicalLockThreshold ),
		  rec( 9, 1, PhysicalLockThreshold ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/2208, 34/08
	pkt = NCP(0x2208, "TTS Set Workstation Thresholds", 'tts', has_length=0)
	pkt.Request(10, [
		  rec( 8, 1, LogicalLockThreshold ),
		  rec( 9, 1, PhysicalLockThreshold ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/2209, 34/09
	pkt = NCP(0x2209, "TTS Get Transaction Bits", 'tts', has_length=0)
	pkt.Request(8)
	pkt.Reply(9, [
		rec( 8, 1, ControlFlags ),
	])
	pkt.CompletionCodes([0x0000])
	# 2222/220A, 34/10
	pkt = NCP(0x220A, "TTS Set Transaction Bits", 'tts', has_length=0)
	pkt.Request(9, [
		rec( 8, 1, ControlFlags ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/2301, 35/01
	pkt = NCP(0x2301, "AFP Create Directory", 'afp')
	pkt.Request((49, 303), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, BaseDirectoryID ),
		rec( 15, 1, Reserved ),
		rec( 16, 4, CreatorID ),
		rec( 20, 4, Reserved4 ),
		rec( 24, 2, FinderAttr ),
		rec( 26, 2, HorizLocation ),
		rec( 28, 2, VertLocation ),
		rec( 30, 2, FileDirWindow ),
		rec( 32, 16, Reserved16 ),
		rec( 48, (1,255), Path ),
	], info_str=(Path, "AFP Create Directory: %s", ", %s"))
	pkt.Reply(12, [
		rec( 8, 4, NewDirectoryID ),
	])
	pkt.CompletionCodes([0x0000, 0x8301, 0x8400, 0x8800, 0x9300, 0x9600, 0x9804,
			     0x9900, 0x9c03, 0x9e02, 0xa100, 0xa201, 0xfd00, 0xff18])
	# 2222/2302, 35/02
	pkt = NCP(0x2302, "AFP Create File", 'afp')
	pkt.Request((49, 303), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, BaseDirectoryID ),
		rec( 15, 1, DeleteExistingFileFlag ),
		rec( 16, 4, CreatorID, BE ),
		rec( 20, 4, Reserved4 ),
		rec( 24, 2, FinderAttr ),
		rec( 26, 2, HorizLocation, BE ),
		rec( 28, 2, VertLocation, BE ),
		rec( 30, 2, FileDirWindow, BE ),
		rec( 32, 16, Reserved16 ),
		rec( 48, (1,255), Path ),
	], info_str=(Path, "AFP Create File: %s", ", %s"))
	pkt.Reply(12, [
		rec( 8, 4, NewDirectoryID ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8301, 0x8400, 0x8701, 0x8800,
			     0x8a00, 0x8d00, 0x8e00, 0x8f00, 0x9300, 0x9600, 0x9804,
			     0x9900, 0x9b03, 0x9c03, 0x9e02, 0xa100, 0xa201, 0xfd00,
			     0xff18])
	# 2222/2303, 35/03
	pkt = NCP(0x2303, "AFP Delete", 'afp')
	pkt.Request((16,270), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, BaseDirectoryID ),
		rec( 15, (1,255), Path ),
	], info_str=(Path, "AFP Delete: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8301, 0x8800, 0x8a00, 0x8d00, 0x8e00, 0x8f00,
			     0x9000, 0x9300, 0x9600, 0x9804, 0x9b03, 0x9c03, 0x9e02,
			     0xa000, 0xa100, 0xa201, 0xfd00, 0xff19])
	# 2222/2304, 35/04
	pkt = NCP(0x2304, "AFP Get Entry ID From Name", 'afp')
	pkt.Request((16,270), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, BaseDirectoryID ),
		rec( 15, (1,255), Path ),
	], info_str=(Path, "AFP Get Entry from Name: %s", ", %s"))
	pkt.Reply(12, [
		rec( 8, 4, TargetEntryID, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x8301, 0x8800, 0x9300, 0x9600, 0x9804, 0x9c03,
			     0xa100, 0xa201, 0xfd00, 0xff19])
	# 2222/2305, 35/05
	pkt = NCP(0x2305, "AFP Get File Information", 'afp')
	pkt.Request((18,272), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, BaseDirectoryID ),
		rec( 15, 2, RequestBitMap, BE ),
		rec( 17, (1,255), Path ),
	], info_str=(Path, "AFP Get File Information: %s", ", %s"))
	pkt.Reply(121, [
		rec( 8, 4, AFPEntryID, BE ),
		rec( 12, 4, ParentID, BE ),
		rec( 16, 2, AttributesDef16, LE ),
		rec( 18, 4, DataForkLen, BE ),
		rec( 22, 4, ResourceForkLen, BE ),
		rec( 26, 2, TotalOffspring, BE	),
		rec( 28, 2, CreationDate, BE ),
		rec( 30, 2, LastAccessedDate, BE ),
		rec( 32, 2, ModifiedDate, BE ),
		rec( 34, 2, ModifiedTime, BE ),
		rec( 36, 2, ArchivedDate, BE ),
		rec( 38, 2, ArchivedTime, BE ),
		rec( 40, 4, CreatorID, BE ),
        	rec( 44, 4, Reserved4 ),
		rec( 48, 2, FinderAttr ),
		rec( 50, 2, HorizLocation ),
		rec( 52, 2, VertLocation ),
		rec( 54, 2, FileDirWindow ),
		rec( 56, 16, Reserved16 ),
		rec( 72, 32, LongName ),
		rec( 104, 4, CreatorID, BE ),
		rec( 108, 12, ShortName ),
		rec( 120, 1, AccessPrivileges ),
	])
	pkt.CompletionCodes([0x0000, 0x8301, 0x8800, 0x9300, 0x9600, 0x9804, 0x9c03,
			     0xa100, 0xa201, 0xfd00, 0xff19])
	# 2222/2306, 35/06
	pkt = NCP(0x2306, "AFP Get Entry ID From NetWare Handle", 'afp')
	pkt.Request(16, [
		rec( 10, 6, FileHandle ),
	])
	pkt.Reply(14, [
		rec( 8, 1, VolumeID ),
		rec( 9, 4, TargetEntryID, BE ),
		rec( 13, 1, ForkIndicator ),
	])
	pkt.CompletionCodes([0x0000, 0x8301, 0x8800, 0x9300, 0x9600, 0xa201])
	# 2222/2307, 35/07
	pkt = NCP(0x2307, "AFP Rename", 'afp')
	pkt.Request((21, 529), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, MacSourceBaseID, BE ),
		rec( 15, 4, MacDestinationBaseID, BE ),
		rec( 19, (1,255), Path ),
		rec( -1, (1,255), NewFileNameLen ),
	], info_str=(Path, "AFP Rename: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8301, 0x8401, 0x8800, 0x8b00, 0x8e00,
			     0x9001, 0x9201, 0x9300, 0x9600, 0x9804, 0x9900,
			     0x9c03, 0x9e00, 0xa100, 0xa201, 0xfd00, 0xff0a])
	# 2222/2308, 35/08
	pkt = NCP(0x2308, "AFP Open File Fork", 'afp')
	pkt.Request((18, 272), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, MacBaseDirectoryID ),
		rec( 15, 1, ForkIndicator ),
		rec( 16, 1, AccessMode ),
		rec( 17, (1,255), Path ),
	], info_str=(Path, "AFP Open File Fork: %s", ", %s"))
	pkt.Reply(22, [
		rec( 8, 4, AFPEntryID, BE ),
		rec( 12, 4, DataForkLen, BE ),
		rec( 16, 6, NetWareAccessHandle ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8301, 0x8800, 0x9300,
			     0x9400, 0x9600, 0x9804, 0x9900, 0x9c03, 0xa100,
			     0xa201, 0xfd00, 0xff16])
	# 2222/2309, 35/09
	pkt = NCP(0x2309, "AFP Set File Information", 'afp')
	pkt.Request((64, 318), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, MacBaseDirectoryID ),
		rec( 15, 2, RequestBitMap, BE ),
		rec( 17, 2, MacAttr, BE ),
		rec( 19, 2, CreationDate, BE ),
		rec( 21, 2, LastAccessedDate, BE ),
		rec( 23, 2, ModifiedDate, BE ),
		rec( 25, 2, ModifiedTime, BE ),
		rec( 27, 2, ArchivedDate, BE ),
		rec( 29, 2, ArchivedTime, BE ),
		rec( 31, 4, CreatorID, BE ),
		rec( 35, 4, Reserved4 ),
		rec( 39, 2, FinderAttr ),
		rec( 41, 2, HorizLocation ),
		rec( 43, 2, VertLocation ),
		rec( 45, 2, FileDirWindow ),
		rec( 47, 16, Reserved16 ),
		rec( 63, (1,255), Path ),
	], info_str=(Path, "AFP Set File Information: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0104, 0x8301, 0x8800, 0x9300, 0x9400,
			     0x9500, 0x9600, 0x9804, 0x9c03, 0xa100, 0xa201,
			     0xfd00, 0xff16])
	# 2222/230A, 35/10
	pkt = NCP(0x230A, "AFP Scan File Information", 'afp')
	pkt.Request((26, 280), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, MacBaseDirectoryID ),
		rec( 15, 4, MacLastSeenID, BE ),
		rec( 19, 2, DesiredResponseCount, BE ),
		rec( 21, 2, SearchBitMap, BE ),
		rec( 23, 2, RequestBitMap, BE ),
		rec( 25, (1,255), Path ),
	], info_str=(Path, "AFP Scan File Information: %s", ", %s"))
	pkt.Reply(123, [
		rec( 8, 2, ActualResponseCount, BE, var="x" ),
                rec( 10, 113, AFP10Struct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x8301, 0x8800, 0x9300, 0x9600, 0x9804,
			     0x9c03, 0xa100, 0xa201, 0xfd00, 0xff16])
	# 2222/230B, 35/11
	pkt = NCP(0x230B, "AFP Alloc Temporary Directory Handle", 'afp')
	pkt.Request((16,270), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, MacBaseDirectoryID ),
		rec( 15, (1,255), Path ),
	], info_str=(Path, "AFP Allocate Temporary Directory Handle: %s", ", %s"))
	pkt.Reply(10, [
		rec( 8, 1, DirHandle ),
		rec( 9, 1, AccessRightsMask ),
	])
	pkt.CompletionCodes([0x0000, 0x8301, 0x8800, 0x9300, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0x9d00, 0xa100,
			     0xa201, 0xfd00, 0xff00])
	# 2222/230C, 35/12
	pkt = NCP(0x230C, "AFP Get Entry ID From Path Name", 'afp')
	pkt.Request((12,266), [
		rec( 10, 1, DirHandle ),
		rec( 11, (1,255), Path ),
	], info_str=(Path, "AFP Get Entry ID from Path Name: %s", ", %s"))
	pkt.Reply(12, [
		rec( 8, 4, AFPEntryID, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x8301, 0x8800, 0x9300, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa100, 0xa201,
			     0xfd00, 0xff00])
	# 2222/230D, 35/13
	pkt = NCP(0x230D, "AFP 2.0 Create Directory", 'afp')
	pkt.Request((55,309), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, BaseDirectoryID ),
		rec( 15, 1, Reserved ),
		rec( 16, 4, CreatorID, BE ),
		rec( 20, 4, Reserved4 ),
		rec( 24, 2, FinderAttr ),
		rec( 26, 2, HorizLocation ),
		rec( 28, 2, VertLocation ),
		rec( 30, 2, FileDirWindow ),
		rec( 32, 16, Reserved16 ),
		rec( 48, 6, ProDOSInfo ),
		rec( 54, (1,255), Path ),
	], info_str=(Path, "AFP 2.0 Create Directory: %s", ", %s"))
	pkt.Reply(12, [
		rec( 8, 4, NewDirectoryID ),
	])
	pkt.CompletionCodes([0x0000, 0x8301, 0x8400, 0x8800, 0x9300,
			     0x9600, 0x9804, 0x9900, 0x9c03, 0x9e00,
			     0xa100, 0xa201, 0xfd00, 0xff00])
	# 2222/230E, 35/14
	pkt = NCP(0x230E, "AFP 2.0 Create File", 'afp')
	pkt.Request((55,309), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, BaseDirectoryID ),
		rec( 15, 1, DeleteExistingFileFlag ),
		rec( 16, 4, CreatorID, BE ),
		rec( 20, 4, Reserved4 ),
		rec( 24, 2, FinderAttr ),
		rec( 26, 2, HorizLocation ),
		rec( 28, 2, VertLocation ),
		rec( 30, 2, FileDirWindow ),
		rec( 32, 16, Reserved16 ),
		rec( 48, 6, ProDOSInfo ),
		rec( 54, (1,255), Path ),
	], info_str=(Path, "AFP 2.0 Create File: %s", ", %s"))
	pkt.Reply(12, [
		rec( 8, 4, NewDirectoryID ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8301, 0x8400,
			     0x8701, 0x8800, 0x8a00, 0x8d00, 0x8e00,
			     0x8f00, 0x9001, 0x9300, 0x9600, 0x9804,
			     0x9900, 0x9b03, 0x9c03, 0x9e00, 0xa100,
			     0xa201, 0xfd00, 0xff00])
	# 2222/230F, 35/15
	pkt = NCP(0x230F, "AFP 2.0 Get File Or Directory Information", 'afp')
	pkt.Request((18,272), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, BaseDirectoryID ),
		rec( 15, 2, RequestBitMap, BE ),
		rec( 17, (1,255), Path ),
	], info_str=(Path, "AFP 2.0 Get Information: %s", ", %s"))
	pkt.Reply(128, [
		rec( 8, 4, AFPEntryID, BE ),
		rec( 12, 4, ParentID, BE ),
		rec( 16, 2, AttributesDef16 ),
		rec( 18, 4, DataForkLen, BE ),
		rec( 22, 4, ResourceForkLen, BE ),
		rec( 26, 2, TotalOffspring, BE ),
		rec( 28, 2, CreationDate, BE ),
		rec( 30, 2, LastAccessedDate, BE ),
		rec( 32, 2, ModifiedDate, BE ),
		rec( 34, 2, ModifiedTime, BE ),
		rec( 36, 2, ArchivedDate, BE ),
		rec( 38, 2, ArchivedTime, BE ),
		rec( 40, 4, CreatorID, BE ),
		rec( 44, 4, Reserved4 ),
		rec( 48, 2, FinderAttr ),
		rec( 50, 2, HorizLocation ),
		rec( 52, 2, VertLocation ),
		rec( 54, 2, FileDirWindow ),
		rec( 56, 16, Reserved16 ),
		rec( 72, 32, LongName ),
		rec( 104, 4, CreatorID, BE ),
		rec( 108, 12, ShortName ),
		rec( 120, 1, AccessPrivileges ),
		rec( 121, 1, Reserved ),
		rec( 122, 6, ProDOSInfo ),
	])
	pkt.CompletionCodes([0x0000, 0x8301, 0x8800, 0x9300, 0x9600, 0x9804, 0x9c03,
			     0xa100, 0xa201, 0xfd00, 0xff19])
	# 2222/2310, 35/16
	pkt = NCP(0x2310, "AFP 2.0 Set File Information", 'afp')
	pkt.Request((70, 324), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, MacBaseDirectoryID ),
		rec( 15, 2, RequestBitMap, BE ),
		rec( 17, 2, AttributesDef16 ),
		rec( 19, 2, CreationDate, BE ),
		rec( 21, 2, LastAccessedDate, BE ),
		rec( 23, 2, ModifiedDate, BE ),
		rec( 25, 2, ModifiedTime, BE ),
		rec( 27, 2, ArchivedDate, BE ),
		rec( 29, 2, ArchivedTime, BE ),
		rec( 31, 4, CreatorID, BE ),
		rec( 35, 4, Reserved4 ),
		rec( 39, 2, FinderAttr ),
		rec( 41, 2, HorizLocation ),
		rec( 43, 2, VertLocation ),
		rec( 45, 2, FileDirWindow ),
		rec( 47, 16, Reserved16 ),
		rec( 63, 6, ProDOSInfo ),
		rec( 69, (1,255), Path ),
	], info_str=(Path, "AFP 2.0 Set File Information: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0104, 0x8301, 0x8800, 0x9300, 0x9400,
			     0x9500, 0x9600, 0x9804, 0x9c03, 0xa100, 0xa201,
			     0xfd00, 0xff16])
	# 2222/2311, 35/17
	pkt = NCP(0x2311, "AFP 2.0 Scan File Information", 'afp')
	pkt.Request((26, 280), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, MacBaseDirectoryID ),
		rec( 15, 4, MacLastSeenID, BE ),
		rec( 19, 2, DesiredResponseCount, BE ),
		rec( 21, 2, SearchBitMap, BE ),
		rec( 23, 2, RequestBitMap, BE ),
		rec( 25, (1,255), Path ),
	], info_str=(Path, "AFP 2.0 Scan File Information: %s", ", %s"))
	pkt.Reply(14, [
		rec( 8, 2, ActualResponseCount, var="x" ),
		rec( 10, 4, AFP20Struct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x8301, 0x8800, 0x9300, 0x9600, 0x9804,
			     0x9c03, 0xa100, 0xa201, 0xfd00, 0xff16])
	# 2222/2312, 35/18
	pkt = NCP(0x2312, "AFP Get DOS Name From Entry ID", 'afp')
	pkt.Request(15, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, AFPEntryID, BE ),
	])
	pkt.Reply((9,263), [
		rec( 8, (1,255), Path ),
	])
	pkt.CompletionCodes([0x0000, 0x8900, 0x9600, 0xbf00])
	# 2222/2313, 35/19
	pkt = NCP(0x2313, "AFP Get Macintosh Info On Deleted File", 'afp')
	pkt.Request(15, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, DirectoryNumber, BE ),
	])
	pkt.Reply((51,305), [
		rec( 8, 4, CreatorID, BE ),
		rec( 12, 4, Reserved4 ),
		rec( 16, 2, FinderAttr ),
		rec( 18, 2, HorizLocation ),
		rec( 20, 2, VertLocation ),
		rec( 22, 2, FileDirWindow ),
		rec( 24, 16, Reserved16 ),
		rec( 40, 6, ProDOSInfo ),
		rec( 46, 4, ResourceForkSize, BE ),
		rec( 50, (1,255), FileName ),
	])
	pkt.CompletionCodes([0x0000, 0x9c03, 0xbf00])
	# 2222/2400, 36/00
	pkt = NCP(0x2400, "Get NCP Extension Information", 'fileserver')
	pkt.Request(14, [
		rec( 10, 4, NCPextensionNumber, LE ),
	])
	pkt.Reply((16,270), [
		rec( 8, 4, NCPextensionNumber ),
		rec( 12, 1, NCPextensionMajorVersion ),
		rec( 13, 1, NCPextensionMinorVersion ),
		rec( 14, 1, NCPextensionRevisionNumber ),
		rec( 15, (1, 255), NCPextensionName ),
	])
	pkt.CompletionCodes([0x0000, 0xfe00])
	# 2222/2401, 36/01
	pkt = NCP(0x2401, "Get NCP Extension Maximum Data Size", 'fileserver')
	pkt.Request(10)
	pkt.Reply(10, [
		rec( 8, 2, NCPdataSize ),
	])
	pkt.CompletionCodes([0x0000, 0xfe00])
	# 2222/2402, 36/02
	pkt = NCP(0x2402, "Get NCP Extension Information by Name", 'fileserver')
	pkt.Request((11, 265), [
		rec( 10, (1,255), NCPextensionName ),
	], info_str=(NCPextensionName, "Get NCP Extension Information by Name: %s", ", %s"))
	pkt.Reply((16,270), [
		rec( 8, 4, NCPextensionNumber ),
		rec( 12, 1, NCPextensionMajorVersion ),
		rec( 13, 1, NCPextensionMinorVersion ),
		rec( 14, 1, NCPextensionRevisionNumber ),
		rec( 15, (1, 255), NCPextensionName ),
	])
	pkt.CompletionCodes([0x0000, 0xfe00, 0xff20])
	# 2222/2403, 36/03
	pkt = NCP(0x2403, "Get Number of Registered NCP Extensions", 'fileserver')
	pkt.Request(10)
	pkt.Reply(12, [
		rec( 8, 4, NumberOfNCPExtensions ),
	])
	pkt.CompletionCodes([0x0000, 0xfe00])
	# 2222/2404, 36/04
	pkt = NCP(0x2404, "Get NCP Extension Registered Verbs List", 'fileserver')
	pkt.Request(14, [
		rec( 10, 4, StartingNumber ),
	])
	pkt.Reply(20, [
		rec( 8, 4, ReturnedListCount, var="x" ),
		rec( 12, 4, nextStartingNumber ),
		rec( 16, 4, NCPExtensionNumbers, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0xfe00])
	# 2222/2405, 36/05
	pkt = NCP(0x2405, "Return NCP Extension Information", 'fileserver')
	pkt.Request(14, [
		rec( 10, 4, NCPextensionNumber ),
	])
	pkt.Reply((16,270), [
		rec( 8, 4, NCPextensionNumber ),
		rec( 12, 1, NCPextensionMajorVersion ),
		rec( 13, 1, NCPextensionMinorVersion ),
		rec( 14, 1, NCPextensionRevisionNumber ),
		rec( 15, (1, 255), NCPextensionName ),
	])
	pkt.CompletionCodes([0x0000, 0xfe00])
	# 2222/2406, 36/06
	pkt = NCP(0x2406, "Return NCP Extension Maximum Data Size", 'fileserver')
	pkt.Request(10)
	pkt.Reply(12, [
		rec( 8, 4, NCPdataSize ),
	])
	pkt.CompletionCodes([0x0000, 0xfe00])
	# 2222/25, 37
	pkt = NCP(0x25, "Execute NCP Extension", 'fileserver')
	pkt.Request(11, [
		rec( 7, 4, NCPextensionNumber ),
		# The following value is Unicode
		#rec[ 13, (1,255), RequestData ],
	])
	pkt.Reply(8)
		# The following value is Unicode
		#[ 8, (1, 255), ReplyBuffer ],
	pkt.CompletionCodes([0x0000, 0xd504, 0xee00, 0xfe00])
	# 2222/3B, 59
	pkt = NCP(0x3B, "Commit File", 'file', has_length=0 )
	pkt.Request(14, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
	], info_str=(FileHandle, "Commit File - 0x%s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0x9804, 0xff00])
	# 2222/3E, 62
	pkt = NCP(0x3E, "File Search Initialize", 'file', has_length=0 )
	pkt.Request((9, 263), [
		rec( 7, 1, DirHandle ),
		rec( 8, (1,255), Path ),
	], info_str=(Path, "Initialize File Search: %s", ", %s"))
	pkt.Reply(14, [
		rec( 8, 1, VolumeNumber ),
		rec( 9, 2, DirectoryID ),
		rec( 11, 2, SequenceNumber, BE ),
		rec( 13, 1, AccessRightsMask ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0x9b03, 0x9c03, 0xa100,
			     0xfd00, 0xff16])
	# 2222/3F, 63
	pkt = NCP(0x3F, "File Search Continue", 'file', has_length=0 )
	pkt.Request((14, 268), [
		rec( 7, 1, VolumeNumber ),
		rec( 8, 2, DirectoryID ),
		rec( 10, 2, SequenceNumber, BE ),
		rec( 12, 1, SearchAttributes ),
                rec( 13, (1,255), Path ),
	], info_str=(Path, "File Search Continue: %s", ", %s"))
	pkt.Reply( NO_LENGTH_CHECK, [
		#
		# XXX - don't show this if we got back a non-zero
		# completion code?  For example, 255 means "No
		# matching files or directories were found", so
		# presumably it can't show you a matching file or
		# directory instance - it appears to just leave crap
		# there.
		#
		srec( DirectoryInstance, req_cond="ncp.sattr_sub==TRUE"),
		srec( FileInstance, req_cond="ncp.sattr_sub!=TRUE"),
	])
        pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0xff16])
	# 2222/40, 64
	pkt = NCP(0x40, "Search for a File", 'file')
	pkt.Request((12, 266), [
		rec( 7, 2, SequenceNumber, BE ),
		rec( 9, 1, DirHandle ),
		rec( 10, 1, SearchAttributes ),
		rec( 11, (1,255), FileName ),
	], info_str=(FileName, "Search for File: %s", ", %s"))
	pkt.Reply(40, [
		rec( 8, 2, SequenceNumber, BE ),
		rec( 10, 2, Reserved2 ),
		rec( 12, 14, FileName14 ),
		rec( 26, 1, AttributesDef ),
		rec( 27, 1, FileExecuteType ),
		rec( 28, 4, FileSize ),
		rec( 32, 2, CreationDate, BE ),
		rec( 34, 2, LastAccessedDate, BE ),
		rec( 36, 2, ModifiedDate, BE ),
		rec( 38, 2, ModifiedTime, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x8900, 0x9600, 0x9804, 0x9b03,
			     0x9c03, 0xa100, 0xfd00, 0xff16])
	# 2222/41, 65
	pkt = NCP(0x41, "Open File", 'file')
	pkt.Request((10, 264), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, SearchAttributes ),
		rec( 9, (1,255), FileName ),
	], info_str=(FileName, "Open File: %s", ", %s"))
	pkt.Reply(44, [
		rec( 8, 6, FileHandle ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 14, FileName14 ),
		rec( 30, 1, AttributesDef ),
		rec( 31, 1, FileExecuteType ),
		rec( 32, 4, FileSize, BE ),
		rec( 36, 2, CreationDate, BE ),
		rec( 38, 2, LastAccessedDate, BE ),
		rec( 40, 2, ModifiedDate, BE ),
		rec( 42, 2, ModifiedTime, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8200, 0x9400,
			     0x9600, 0x9804, 0x9c03, 0xa100, 0xfd00,
			     0xff16])
	# 2222/42, 66
	pkt = NCP(0x42, "Close File", 'file')
	pkt.Request(14, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
	], info_str=(FileHandle, "Close File - 0x%s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0xff1a])
	# 2222/43, 67
	pkt = NCP(0x43, "Create File", 'file')
	pkt.Request((10, 264), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, AttributesDef ),
		rec( 9, (1,255), FileName ),
	], info_str=(FileName, "Create File: %s", ", %s"))
	pkt.Reply(44, [
		rec( 8, 6, FileHandle ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 14, FileName14 ),
		rec( 30, 1, AttributesDef ),
		rec( 31, 1, FileExecuteType ),
		rec( 32, 4, FileSize, BE ),
		rec( 36, 2, CreationDate, BE ),
		rec( 38, 2, LastAccessedDate, BE ),
		rec( 40, 2, ModifiedDate, BE ),
		rec( 42, 2, ModifiedTime, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9900, 0x9b03, 0x9c03, 0xfd00,
			     0xff00])
	# 2222/44, 68
	pkt = NCP(0x44, "Erase File", 'file')
	pkt.Request((10, 264), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, SearchAttributes ),
		rec( 9, (1,255), FileName ),
	], info_str=(FileName, "Erase File: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8a00, 0x8d00, 0x8e00, 0x8f00,
			     0x9001, 0x9600, 0x9804, 0x9b03, 0x9c03,
			     0xa100, 0xfd00, 0xff00])
	# 2222/45, 69
	pkt = NCP(0x45, "Rename File", 'file')
	pkt.Request((12, 520), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, SearchAttributes ),
		rec( 9, (1,255), FileName ),
		rec( -1, 1, TargetDirHandle ),
		rec( -1, (1, 255), NewFileNameLen ),
	], info_str=(FileName, "Rename File: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8701, 0x8b00, 0x8d00, 0x8e00,
			     0x8f00, 0x9001, 0x9101, 0x9201, 0x9600,
			     0x9804, 0x9a00, 0x9b03, 0x9c03, 0xa100,
			     0xfd00, 0xff16])
	# 2222/46, 70
	pkt = NCP(0x46, "Set File Attributes", 'file')
	pkt.Request((11, 265), [
		rec( 7, 1, AttributesDef ),
		rec( 8, 1, DirHandle ),
		rec( 9, 1, SearchAttributes ),
		rec( 10, (1,255), FileName ),
	], info_str=(FileName, "Set File Attributes: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8c00, 0x8d00, 0x8e00, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa100, 0xfd00,
			     0xff16])
	# 2222/47, 71
	pkt = NCP(0x47, "Get Current Size of File", 'file')
	pkt.Request(14, [
        rec(7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
	], info_str=(FileHandle, "Get Current Size of File - 0x%s", ", %s"))
	pkt.Reply(12, [
		rec( 8, 4, FileSize, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x8800])
	# 2222/48, 72
	pkt = NCP(0x48, "Read From A File", 'file')
	pkt.Request(20, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
		rec( 14, 4, FileOffset, BE ),
		rec( 18, 2, MaxBytes, BE ),
	], info_str=(FileHandle, "Read From File - 0x%s", ", %s"))
	pkt.Reply(10, [
		rec( 8, 2, NumBytes, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x8300, 0x8800, 0x9300, 0xff1b])
	# 2222/49, 73
	pkt = NCP(0x49, "Write to a File", 'file')
	pkt.Request(20, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
		rec( 14, 4, FileOffset, BE ),
		rec( 18, 2, MaxBytes, BE ),
	], info_str=(FileHandle, "Write to a File - 0x%s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0104, 0x8300, 0x8800, 0x9400, 0x9500, 0xa201, 0xff1b])
	# 2222/4A, 74
	pkt = NCP(0x4A, "Copy from One File to Another", 'file')
	pkt.Request(30, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
		rec( 14, 6, TargetFileHandle ),
		rec( 20, 4, FileOffset, BE ),
		rec( 24, 4, TargetFileOffset, BE ),
		rec( 28, 2, BytesToCopy, BE ),
	])
	pkt.Reply(12, [
		rec( 8, 4, BytesActuallyTransferred, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x0104, 0x8300, 0x8800, 0x9300, 0x9400,
			     0x9500, 0x9600, 0xa201, 0xff1b])
	# 2222/4B, 75
	pkt = NCP(0x4B, "Set File Time Date Stamp", 'file')
	pkt.Request(18, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
		rec( 14, 2, FileTime, BE ),
		rec( 16, 2, FileDate, BE ),
	], info_str=(FileHandle, "Set Time and Date Stamp for File - 0x%s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0x9400, 0x9600, 0xfb08])
	# 2222/4C, 76
	pkt = NCP(0x4C, "Open File", 'file')
	pkt.Request((11, 265), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, SearchAttributes ),
		rec( 9, 1, AccessRightsMask ),
		rec( 10, (1,255), FileName ),
	], info_str=(FileName, "Open File: %s", ", %s"))
	pkt.Reply(44, [
		rec( 8, 6, FileHandle ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 14, FileName14 ),
		rec( 30, 1, AttributesDef ),
		rec( 31, 1, FileExecuteType ),
		rec( 32, 4, FileSize, BE ),
		rec( 36, 2, CreationDate, BE ),
		rec( 38, 2, LastAccessedDate, BE ),
		rec( 40, 2, ModifiedDate, BE ),
		rec( 42, 2, ModifiedTime, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8200, 0x9400,
			     0x9600, 0x9804, 0x9c03, 0xa100, 0xfd00,
			     0xff16])
	# 2222/4D, 77
	pkt = NCP(0x4D, "Create File", 'file')
	pkt.Request((10, 264), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, AttributesDef ),
		rec( 9, (1,255), FileName ),
	], info_str=(FileName, "Create File: %s", ", %s"))
	pkt.Reply(44, [
		rec( 8, 6, FileHandle ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 14, FileName14 ),
		rec( 30, 1, AttributesDef ),
		rec( 31, 1, FileExecuteType ),
		rec( 32, 4, FileSize, BE ),
		rec( 36, 2, CreationDate, BE ),
		rec( 38, 2, LastAccessedDate, BE ),
		rec( 40, 2, ModifiedDate, BE ),
		rec( 42, 2, ModifiedTime, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9900, 0x9b03, 0x9c03, 0xfd00,
			     0xff00])
	# 2222/4F, 79
	pkt = NCP(0x4F, "Set File Extended Attributes", 'file')
	pkt.Request((11, 265), [
		rec( 7, 1, AttributesDef ),
		rec( 8, 1, DirHandle ),
		rec( 9, 1, AccessRightsMask ),
		rec( 10, (1,255), FileName ),
	], info_str=(FileName, "Set File Extended Attributes: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8c00, 0x8d00, 0x8e00, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa100, 0xfd00,
			     0xff16])
	# 2222/54, 84
	pkt = NCP(0x54, "Open/Create File", 'file')
	pkt.Request((12, 266), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, AttributesDef ),
		rec( 9, 1, AccessRightsMask ),
		rec( 10, 1, ActionFlag ),
		rec( 11, (1,255), FileName ),
	], info_str=(FileName, "Open/Create File: %s", ", %s"))
	pkt.Reply(44, [
		rec( 8, 6, FileHandle ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 14, FileName14 ),
		rec( 30, 1, AttributesDef ),
		rec( 31, 1, FileExecuteType ),
		rec( 32, 4, FileSize, BE ),
		rec( 36, 2, CreationDate, BE ),
		rec( 38, 2, LastAccessedDate, BE ),
		rec( 40, 2, ModifiedDate, BE ),
		rec( 42, 2, ModifiedTime, BE ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/55, 85
	pkt = NCP(0x55, "Get Sparse File Data Block Bit Map", 'file')
	pkt.Request(17, [
		rec( 7, 6, FileHandle ),
		rec( 13, 4, FileOffset ),
	], info_str=(FileHandle, "Get Sparse File Data Block Bitmap for File - 0x%s", ", %s"))
	pkt.Reply(528, [
		rec( 8, 4, AllocationBlockSize ),
		rec( 12, 4, Reserved4 ),
		rec( 16, 512, BitMap ),
	])
	pkt.CompletionCodes([0x0000, 0x8800])
	# 2222/5601, 86/01
	pkt = NCP(0x5601, "Close Extended Attribute Handle", 'file', has_length=0 )
	pkt.Request(14, [
		rec( 8, 2, Reserved2 ),
		rec( 10, 4, EAHandle ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xcf00, 0xd301])
	# 2222/5602, 86/02
	pkt = NCP(0x5602, "Write Extended Attribute", 'file', has_length=0 )
	pkt.Request((35,97), [
		rec( 8, 2, EAFlags ),
		rec( 10, 4, EAHandleOrNetWareHandleOrVolume ),
		rec( 14, 4, ReservedOrDirectoryNumber ),
		rec( 18, 4, TtlWriteDataSize ),
		rec( 22, 4, FileOffset ),
		rec( 26, 4, EAAccessFlag ),
		rec( 30, 2, EAValueLength, var='x' ),
		rec( 32, (2,64), EAKey ),
		rec( -1, 1, EAValueRep, repeat='x' ),
	], info_str=(EAKey, "Write Extended Attribute: %s", ", %s"))
	pkt.Reply(20, [
		rec( 8, 4, EAErrorCodes ),
		rec( 12, 4, EABytesWritten ),
		rec( 16, 4, NewEAHandle ),
	])
	pkt.CompletionCodes([0x0000, 0xc800, 0xc900, 0xcb00, 0xce00, 0xcf00, 0xd101,
			     0xd203, 0xd301, 0xd402])
	# 2222/5603, 86/03
	pkt = NCP(0x5603, "Read Extended Attribute", 'file', has_length=0 )
	pkt.Request((28,538), [
		rec( 8, 2, EAFlags ),
		rec( 10, 4, EAHandleOrNetWareHandleOrVolume ),
		rec( 14, 4, ReservedOrDirectoryNumber ),
		rec( 18, 4, FileOffset ),
		rec( 22, 4, InspectSize ),
		rec( 26, (2,512), EAKey ),
	], info_str=(EAKey, "Read Extended Attribute: %s", ", %s"))
	pkt.Reply((26,536), [
		rec( 8, 4, EAErrorCodes ),
		rec( 12, 4, TtlValuesLength ),
		rec( 16, 4, NewEAHandle ),
		rec( 20, 4, EAAccessFlag ),
		rec( 24, (2,512), EAValue ),
	])
	pkt.CompletionCodes([0x0000, 0xc900, 0xce00, 0xcf00, 0xd101,
			     0xd301])
	# 2222/5604, 86/04
	pkt = NCP(0x5604, "Enumerate Extended Attribute", 'file', has_length=0 )
	pkt.Request((26,536), [
		rec( 8, 2, EAFlags ),
		rec( 10, 4, EAHandleOrNetWareHandleOrVolume ),
		rec( 14, 4, ReservedOrDirectoryNumber ),
		rec( 18, 4, InspectSize ),
		rec( 22, 2, SequenceNumber ),
		rec( 24, (2,512), EAKey ),
	], info_str=(EAKey, "Enumerate Extended Attribute: %s", ", %s"))
	pkt.Reply(28, [
		rec( 8, 4, EAErrorCodes ),
		rec( 12, 4, TtlEAs ),
		rec( 16, 4, TtlEAsDataSize ),
		rec( 20, 4, TtlEAsKeySize ),
		rec( 24, 4, NewEAHandle ),
	])
	pkt.CompletionCodes([0x0000, 0x8800, 0xc900, 0xce00, 0xcf00, 0xd101,
			     0xd301])
	# 2222/5605, 86/05
	pkt = NCP(0x5605, "Duplicate Extended Attributes", 'file', has_length=0 )
	pkt.Request(28, [
		rec( 8, 2, EAFlags ),
		rec( 10, 2, DstEAFlags ),
		rec( 12, 4, EAHandleOrNetWareHandleOrVolume ),
		rec( 16, 4, ReservedOrDirectoryNumber ),
		rec( 20, 4, EAHandleOrNetWareHandleOrVolume ),
		rec( 24, 4, ReservedOrDirectoryNumber ),
	])
	pkt.Reply(20, [
		rec( 8, 4, EADuplicateCount ),
		rec( 12, 4, EADataSizeDuplicated ),
		rec( 16, 4, EAKeySizeDuplicated ),
	])
	pkt.CompletionCodes([0x0000, 0xd101])
	# 2222/5701, 87/01
	pkt = NCP(0x5701, "Open/Create File or Subdirectory", 'file', has_length=0)
	pkt.Request((30, 284), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, OpenCreateMode ),
		rec( 10, 2, SearchAttributesLow ),
		rec( 12, 2, ReturnInfoMask ),
		rec( 14, 2, ExtendedInfo ),
		rec( 16, 4, AttributesDef32 ),
		rec( 20, 2, DesiredAccessRights ),
		rec( 22, 1, VolumeNumber ),
		rec( 23, 4, DirectoryBase ),
		rec( 27, 1, HandleFlag ),
		rec( 28, 1, PathCount, var="x" ),
		rec( 29, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Open or Create: %s", "/%s"))
	pkt.Reply( NO_LENGTH_CHECK, [
		rec( 8, 4, FileHandle ),
		rec( 12, 1, OpenCreateAction ),
		rec( 13, 1, Reserved ),
                srec( DSSpaceAllocateStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 1)" ),
                srec( PadDSSpaceAllocate, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 0)" ),
                srec( AttributesStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 1)" ),
                srec( PadAttributes, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 0)" ),
                srec( DataStreamSizeStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 1)" ),
                srec( PadDataStreamSize, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 0)" ),
                srec( TotalStreamSizeStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 1)" ),
                srec( PadTotalStreamSize, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 0)" ),
                srec( CreationInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 1)" ),
                srec( PadCreationInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 0)" ),
                srec( ModifyInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 1)" ),
                srec( PadModifyInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 0)" ),
                srec( ArchiveInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 1)" ),
                srec( PadArchiveInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 0)" ),
                srec( RightsInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 1)" ),
                srec( PadRightsInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 0)" ),
                srec( DirEntryStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 1)" ),
                srec( PadDirEntry, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 0)" ),
                srec( EAInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 1)" ),
                srec( PadEAInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 0)" ),
                srec( NSInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 1)" ),
                srec( PadNSInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 0)" ),
                srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_alloc  == 1)" ),
                srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_attr == 1)" ),
                srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_size == 1)" ),
                srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_tspace == 1)" ),
                srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_eattr == 1)" ),
                srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_mod == 1)" ),
                srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_create == 1)" ),
                srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_arch == 1)" ),
                srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_dir == 1)" ),
                srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_rights == 1)" ),
                srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_ns == 1)" ),
                srec( ReferenceIDStruct, req_cond="ncp.ret_info_mask_id == 1" ),
                srec( NSAttributeStruct, req_cond="ncp.ret_info_mask_ns_attr == 1" ),
                srec( DStreamActual, req_cond="ncp.ret_info_mask_actual == 1" ),
                srec( DStreamLogical, req_cond="ncp.ret_info_mask_logical == 1" ),
                srec( LastUpdatedInSecondsStruct, req_cond="ncp.ext_info_update == 1" ),
                srec( DOSNameStruct, req_cond="ncp.ext_info_dos_name == 1" ),
                srec( FlushTimeStruct, req_cond="ncp.ext_info_flush == 1" ),
                srec( ParentBaseIDStruct, req_cond="ncp.ext_info_parental == 1" ),
                srec( MacFinderInfoStruct, req_cond="ncp.ext_info_mac_finder == 1" ),
                srec( SiblingCountStruct, req_cond="ncp.ext_info_sibling == 1" ),
                srec( EffectiveRightsStruct, req_cond="ncp.ext_info_effective == 1" ),
                srec( MacTimeStruct, req_cond="ncp.ext_info_mac_date == 1" ),
                srec( LastAccessedTimeStruct, req_cond="ncp.ext_info_access == 1" ),
                srec( FileNameStruct, req_cond="ncp.ret_info_mask_fname == 1" ),
        ])
	pkt.ReqCondSizeVariable()
        pkt.CompletionCodes([0x0000, 0x7f00, 0x8001, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8900, 0x8d00, 0x8f00, 0x9001, 0x9400, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa500, 0xa802, 0xbf00, 0xfd00, 0xff16])
	# 2222/5702, 87/02
	pkt = NCP(0x5702, "Initialize Search", 'file', has_length=0)
	pkt.Request( (18,272), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, Reserved ),
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, DirectoryBase ),
		rec( 15, 1, HandleFlag ),
		rec( 16, 1, PathCount, var="x" ),
		rec( 17, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Set Search Pointer to: %s", "/%s"))
	pkt.Reply(17, [
		rec( 8, 1, VolumeNumber ),
		rec( 9, 4, DirectoryNumber ),
		rec( 13, 4, DirectoryEntryNumber ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5703, 87/03
	pkt = NCP(0x5703, "Search for File or Subdirectory", 'file', has_length=0)
	pkt.Request((26, 280), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, DataStream ),
		rec( 10, 2, SearchAttributesLow ),
		rec( 12, 2, ReturnInfoMask ),
		rec( 14, 2, ExtendedInfo ),
		rec( 16, 9, SearchSequence ),
		rec( 25, (1,255), SearchPattern ),
	], info_str=(SearchPattern, "Search for: %s", "/%s"))
	pkt.Reply( NO_LENGTH_CHECK, [
		rec( 8, 9, SearchSequence ),
		rec( 17, 1, Reserved ),
                srec( DSSpaceAllocateStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 1)" ),
                srec( PadDSSpaceAllocate, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 0)" ),
                srec( AttributesStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 1)" ),
                srec( PadAttributes, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 0)" ),
                srec( DataStreamSizeStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 1)" ),
                srec( PadDataStreamSize, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 0)" ),
                srec( TotalStreamSizeStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 1)" ),
                srec( PadTotalStreamSize, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 0)" ),
                srec( CreationInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 1)" ),
                srec( PadCreationInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 0)" ),
                srec( ModifyInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 1)" ),
                srec( PadModifyInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 0)" ),
                srec( ArchiveInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 1)" ),
                srec( PadArchiveInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 0)" ),
                srec( RightsInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 1)" ),
                srec( PadRightsInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 0)" ),
                srec( DirEntryStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 1)" ),
                srec( PadDirEntry, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 0)" ),
                srec( EAInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 1)" ),
                srec( PadEAInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 0)" ),
                srec( NSInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 1)" ),
                srec( PadNSInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 0)" ),
                srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_alloc  == 1)" ),
                srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_attr == 1)" ),
                srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_size == 1)" ),
                srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_tspace == 1)" ),
                srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_eattr == 1)" ),
                srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_mod == 1)" ),
                srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_create == 1)" ),
                srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_arch == 1)" ),
                srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_dir == 1)" ),
                srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_rights == 1)" ),
                srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_ns == 1)" ),
                srec( ReferenceIDStruct, req_cond="ncp.ret_info_mask_id == 1" ),
                srec( NSAttributeStruct, req_cond="ncp.ret_info_mask_ns_attr == 1" ),
                srec( DStreamActual, req_cond="ncp.ret_info_mask_actual == 1" ),
                srec( DStreamLogical, req_cond="ncp.ret_info_mask_logical == 1" ),
                srec( LastUpdatedInSecondsStruct, req_cond="ncp.ext_info_update == 1" ),
                srec( DOSNameStruct, req_cond="ncp.ext_info_dos_name == 1" ),
                srec( FlushTimeStruct, req_cond="ncp.ext_info_flush == 1" ),
                srec( ParentBaseIDStruct, req_cond="ncp.ext_info_parental == 1" ),
                srec( MacFinderInfoStruct, req_cond="ncp.ext_info_mac_finder == 1" ),
                srec( SiblingCountStruct, req_cond="ncp.ext_info_sibling == 1" ),
                srec( EffectiveRightsStruct, req_cond="ncp.ext_info_effective == 1" ),
                srec( MacTimeStruct, req_cond="ncp.ext_info_mac_date == 1" ),
                srec( LastAccessedTimeStruct, req_cond="ncp.ext_info_access == 1" ),
                srec( FileNameStruct, req_cond="ncp.ret_info_mask_fname == 1" ),
        ])
	pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5704, 87/04
	pkt = NCP(0x5704, "Rename Or Move a File or Subdirectory", 'file', has_length=0)
	pkt.Request((28, 536), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, RenameFlag ),
		rec( 10, 2, SearchAttributesLow ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, 1, VolumeNumber ),
		rec( 20, 4, DirectoryBase ),
		rec( 24, 1, HandleFlag ),
		rec( 25, 1, PathCount, var="y" ),
		rec( 26, (1, 255), Path, repeat="x" ),
		rec( -1, (1,255), Path, repeat="y" ),
	], info_str=(Path, "Rename or Move: %s", "/%s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8e00, 0x8f00, 0x9001, 0x9200, 0x9600,
			     0x9804, 0x9a00, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5705, 87/05
	pkt = NCP(0x5705, "Scan File or Subdirectory for Trustees", 'file', has_length=0)
	pkt.Request((24, 278), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, SearchAttributesLow ),
		rec( 12, 4, SequenceNumber ),
		rec( 16, 1, VolumeNumber ),
		rec( 17, 4, DirectoryBase ),
		rec( 21, 1, HandleFlag ),
		rec( 22, 1, PathCount, var="x" ),
		rec( 23, (1, 255), Path, repeat="x" ),
	], info_str=(Path, "Scan Trustees for: %s", "/%s"))
	pkt.Reply(20, [
		rec( 8, 4, SequenceNumber ),
		rec( 12, 2, ObjectIDCount, var="x" ),
		rec( 14, 6, TrusteeStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5706, 87/06
	pkt = NCP(0x5706, "Obtain File or SubDirectory Information", 'file', has_length=0)
	pkt.Request((24,278), [
		rec( 10, 1, SrcNameSpace ),
		rec( 11, 1, DestNameSpace ),
		rec( 12, 2, SearchAttributesLow ),
		rec( 14, 2, ReturnInfoMask, LE ),
		rec( 16, 2, ExtendedInfo ),
		rec( 18, 1, VolumeNumber ),
		rec( 19, 4, DirectoryBase ),
		rec( 23, 1, HandleFlag ),
		rec( 24, 1, PathCount, var="x" ),
		rec( 25, (1,255), Path, repeat="x",),
	], info_str=(Path, "Obtain Info for: %s", "/%s"))
	pkt.Reply(NO_LENGTH_CHECK, [
            srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 1)" ),
            srec( PadDSSpaceAllocate, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 0)" ),
            srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 1)" ),
            srec( PadAttributes, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 0)" ),
            srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 1)" ),
            srec( PadDataStreamSize, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 0)" ),
            srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 1)" ),
            srec( PadTotalStreamSize, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 0)" ),
            srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 1)" ),
            srec( PadCreationInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 0)" ),
            srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 1)" ),
            srec( PadModifyInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 0)" ),
            srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 1)" ),
            srec( PadArchiveInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 0)" ),
            srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 1)" ),
            srec( PadRightsInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 0)" ),
            srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 1)" ),
            srec( PadDirEntry, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 0)" ),
            srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 1)" ),
            srec( PadEAInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 0)" ),
            srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 1)" ),
            srec( PadNSInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 0)" ),
            srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_alloc  == 1)" ),
            srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_attr == 1)" ),
            srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_size == 1)" ),
            srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_tspace == 1)" ),
            srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_create == 1)" ),
            srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_mod == 1)" ),
            srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_arch == 1)" ),
            srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_rights == 1)" ),
            srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_dir == 1)" ),
            srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_eattr == 1)" ),
            srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_ns == 1)" ),
            srec( ReferenceIDStruct, req_cond="ncp.ret_info_mask_id == 1" ),
            srec( NSAttributeStruct, req_cond="ncp.ret_info_mask_ns_attr == 1" ),
            srec( DStreamActual, req_cond="ncp.ret_info_mask_actual == 1" ),
            srec( DStreamLogical, req_cond="ncp.ret_info_mask_logical == 1" ),
            srec( LastUpdatedInSecondsStruct, req_cond="ncp.ext_info_update == 1" ),
            srec( DOSNameStruct, req_cond="ncp.ext_info_dos_name == 1" ),
            srec( FlushTimeStruct, req_cond="ncp.ext_info_flush == 1" ),
            srec( ParentBaseIDStruct, req_cond="ncp.ext_info_parental == 1" ),
            srec( MacFinderInfoStruct, req_cond="ncp.ext_info_mac_finder == 1" ),
            srec( SiblingCountStruct, req_cond="ncp.ext_info_sibling == 1" ),
            srec( EffectiveRightsStruct, req_cond="ncp.ext_info_effective == 1" ),
            srec( MacTimeStruct, req_cond="ncp.ext_info_mac_date == 1" ),
            srec( LastAccessedTimeStruct, req_cond="ncp.ext_info_access == 1" ),
            srec( FileNameStruct, req_cond="ncp.ret_info_mask_fname == 1" ),
        ])
	pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8700, 0x8900, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa802, 0xbf00, 0xfd00, 0xff16])
	# 2222/5707, 87/07
	pkt = NCP(0x5707, "Modify File or Subdirectory DOS Information", 'file', has_length=0)
	pkt.Request((62,316), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, SearchAttributesLow ),
		rec( 12, 2, ModifyDOSInfoMask ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 2, AttributesDef16 ),
		rec( 18, 1, FileMode ),
		rec( 19, 1, FileExtendedAttributes ),
		rec( 20, 2, CreationDate ),
		rec( 22, 2, CreationTime ),
		rec( 24, 4, CreatorID, BE ),
		rec( 28, 2, ModifiedDate ),
		rec( 30, 2, ModifiedTime ),
		rec( 32, 4, ModifierID, BE ),
		rec( 36, 2, ArchivedDate ),
		rec( 38, 2, ArchivedTime ),
		rec( 40, 4, ArchiverID, BE ),
		rec( 44, 2, LastAccessedDate ),
		rec( 46, 2, InheritedRightsMask ),
		rec( 48, 2, InheritanceRevokeMask ),
		rec( 50, 4, MaxSpace ),
		rec( 54, 1, VolumeNumber ),
		rec( 55, 4, DirectoryBase ),
		rec( 59, 1, HandleFlag ),
		rec( 60, 1, PathCount, var="x" ),
		rec( 61, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Modify DOS Information for: %s", "/%s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8c01, 0x8d00, 0x8e00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5708, 87/08
	pkt = NCP(0x5708, "Delete a File or Subdirectory", 'file', has_length=0)
	pkt.Request((20,274), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, SearchAttributesLow ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Delete a File or Subdirectory: %s", "/%s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8900, 0x8a00, 0x8d00, 0x8e00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5709, 87/09
	pkt = NCP(0x5709, "Set Short Directory Handle", 'file', has_length=0)
	pkt.Request((20,274), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, DataStream ),
		rec( 10, 1, DestDirHandle ),
		rec( 11, 1, Reserved ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Set Short Directory Handle to: %s", "/%s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/570A, 87/10
	pkt = NCP(0x570A, "Add Trustee Set to File or Subdirectory", 'file', has_length=0)
	pkt.Request((31,285), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, SearchAttributesLow ),
		rec( 12, 2, AccessRightsMaskWord ),
		rec( 14, 2, ObjectIDCount, var="y" ),
		rec( 16, 1, VolumeNumber ),
		rec( 17, 4, DirectoryBase ),
		rec( 21, 1, HandleFlag ),
		rec( 22, 1, PathCount, var="x" ),
		rec( 23, (1,255), Path, repeat="x" ),
		rec( -1, 7, TrusteeStruct, repeat="y" ),
	], info_str=(Path, "Add Trustee Set to: %s", "/%s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfc01, 0xfd00, 0xff16])
	# 2222/570B, 87/11
	pkt = NCP(0x570B, "Delete Trustee Set from File or SubDirectory", 'file', has_length=0)
	pkt.Request((27,281), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, ObjectIDCount, var="y" ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, (1,255), Path, repeat="x" ),
		rec( -1, 7, TrusteeStruct, repeat="y" ),
	], info_str=(Path, "Delete Trustee Set from: %s", "/%s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/570C, 87/12
	pkt = NCP(0x570C, "Allocate Short Directory Handle", 'file', has_length=0)
	pkt.Request((20,274), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, AllocateMode ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Allocate Short Directory Handle to: %s", "/%s"))
	pkt.Reply(14, [
		rec( 8, 1, DirHandle ),
		rec( 9, 1, VolumeNumber ),
		rec( 10, 4, Reserved4 ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5710, 87/16
	pkt = NCP(0x5710, "Scan Salvageable Files", 'file', has_length=0)
	pkt.Request((26,280), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, DataStream ),
		rec( 10, 2, ReturnInfoMask ),
		rec( 12, 2, ExtendedInfo ),
		rec( 14, 4, SequenceNumber ),
		rec( 18, 1, VolumeNumber ),
		rec( 19, 4, DirectoryBase ),
		rec( 23, 1, HandleFlag ),
		rec( 24, 1, PathCount, var="x" ),
		rec( 25, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Scan for Deleted Files in: %s", "/%s"))
	pkt.Reply(NO_LENGTH_CHECK, [
		rec( 8, 4, SequenceNumber ),
		rec( 12, 2, DeletedTime ),
		rec( 14, 2, DeletedDate ),
		rec( 16, 4, DeletedID, BE ),
		rec( 20, 4, VolumeID ),
		rec( 24, 4, DirectoryBase ),
                srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 1)" ),
                srec( PadDSSpaceAllocate, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 0)" ),
                srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 1)" ),
                srec( PadAttributes, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 0)" ),
                srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 1)" ),
                srec( PadDataStreamSize, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 0)" ),
                srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 1)" ),
                srec( PadTotalStreamSize, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 0)" ),
                srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 1)" ),
                srec( PadCreationInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 0)" ),
                srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 1)" ),
                srec( PadModifyInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 0)" ),
                srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 1)" ),
                srec( PadArchiveInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 0)" ),
                srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 1)" ),
                srec( PadRightsInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 0)" ),
                srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 1)" ),
                srec( PadDirEntry, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 0)" ),
                srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 1)" ),
                srec( PadEAInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 0)" ),
                srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 1)" ),
                srec( PadNSInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 0)" ),
                srec( FileNameStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_fname == 1)" ),
                srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_alloc  == 1)" ),
                srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_attr == 1)" ),
                srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_size == 1)" ),
                srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_tspace == 1)" ),
                srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_create == 1)" ),
                srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_mod == 1)" ),
                srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_arch == 1)" ),
                srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_rights == 1)" ),
                srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_dir == 1)" ),
                srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_eattr == 1)" ),
                srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_ns == 1)" ),
                srec( FileNameStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_fname == 1)" ),
        ])
	pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5711, 87/17
	pkt = NCP(0x5711, "Recover Salvageable File", 'file', has_length=0)
	pkt.Request((23,277), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 4, SequenceNumber ),
		rec( 14, 4, VolumeID ),
		rec( 18, 4, DirectoryBase ),
		rec( 22, (1,255), FileName ),
	], info_str=(FileName, "Recover Deleted File: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5712, 87/18
	pkt = NCP(0x5712, "Purge Salvageable Files", 'file', has_length=0)
	pkt.Request(22, [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 4, SequenceNumber ),
		rec( 14, 4, VolumeID ),
		rec( 18, 4, DirectoryBase ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5713, 87/19
	pkt = NCP(0x5713, "Get Name Space Information", 'file', has_length=0)
	pkt.Request(18, [
		rec( 8, 1, SrcNameSpace ),
		rec( 9, 1, DestNameSpace ),
		rec( 10, 1, Reserved ),
		rec( 11, 1, VolumeNumber ),
		rec( 12, 4, DirectoryBase ),
		rec( 16, 2, NamesSpaceInfoMask ),
	])
	pkt.Reply(NO_LENGTH_CHECK, [
            srec( FileNameStruct, req_cond="ncp.ns_info_mask_modify == TRUE" ),
            srec( FileAttributesStruct, req_cond="ncp.ns_info_mask_fatt == TRUE" ),
            srec( CreationDateStruct, req_cond="ncp.ns_info_mask_cdate == TRUE" ),
            srec( CreationTimeStruct, req_cond="ncp.ns_info_mask_ctime == TRUE" ),
            srec( OwnerIDStruct, req_cond="ncp.ns_info_mask_owner == TRUE" ),
            srec( ArchiveDateStruct, req_cond="ncp.ns_info_mask_adate == TRUE" ),
            srec( ArchiveTimeStruct, req_cond="ncp.ns_info_mask_atime == TRUE" ),
            srec( ArchiveIdStruct, req_cond="ncp.ns_info_mask_aid == TRUE" ),
            srec( UpdateDateStruct, req_cond="ncp.ns_info_mask_udate == TRUE" ),
            srec( UpdateTimeStruct, req_cond="ncp.ns_info_mask_utime == TRUE" ),
            srec( UpdateIDStruct, req_cond="ncp.ns_info_mask_uid == TRUE" ),
            srec( LastAccessStruct, req_cond="ncp.ns_info_mask_acc_date == TRUE" ),
            srec( RightsInfoStruct, req_cond="ncp.ns_info_mask_max_acc_mask == TRUE" ),
        ])
        pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5714, 87/20
	pkt = NCP(0x5714, "Search for File or Subdirectory Set", 'file', has_length=0)
	pkt.Request((28, 282), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, DataStream ),
		rec( 10, 2, SearchAttributesLow ),
		rec( 12, 2, ReturnInfoMask ),
		rec( 14, 2, ExtendedInfo ),
		rec( 16, 2, ReturnInfoCount ),
		rec( 18, 9, SearchSequence ),
		rec( 27, (1,255), SearchPattern ),
	])
	pkt.Reply(NO_LENGTH_CHECK, [
		rec( 8, 9, SearchSequence ),
		rec( 17, 1, MoreFlag ),
		rec( 18, 2, InfoCount ),
            srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 1)" ),
            srec( PadDSSpaceAllocate, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 0)" ),
            srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 1)" ),
            srec( PadAttributes, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 0)" ),
            srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 1)" ),
            srec( PadDataStreamSize, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 0)" ),
            srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 1)" ),
            srec( PadTotalStreamSize, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 0)" ),
            srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 1)" ),
            srec( PadCreationInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 0)" ),
            srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 1)" ),
            srec( PadModifyInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 0)" ),
            srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 1)" ),
            srec( PadArchiveInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 0)" ),
            srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 1)" ),
            srec( PadRightsInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 0)" ),
            srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 1)" ),
            srec( PadDirEntry, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 0)" ),
            srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 1)" ),
            srec( PadEAInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 0)" ),
            srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 1)" ),
            srec( PadNSInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 0)" ),
            srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_alloc  == 1)" ),
            srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_attr == 1)" ),
            srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_size == 1)" ),
            srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_tspace == 1)" ),
            srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_eattr == 1)" ),
            srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_arch == 1)" ),
            srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_mod == 1)" ),
            srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_create == 1)" ),
            srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_rights == 1)" ),
            srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_dir == 1)" ),
            srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_ns == 1)" ),
            srec( ReferenceIDStruct, req_cond="ncp.ret_info_mask_id == 1" ),
            srec( NSAttributeStruct, req_cond="ncp.ret_info_mask_ns_attr == 1" ),
            srec( DStreamActual, req_cond="ncp.ret_info_mask_actual == 1" ),
            srec( DStreamLogical, req_cond="ncp.ret_info_mask_logical == 1" ),
            srec( LastUpdatedInSecondsStruct, req_cond="ncp.ext_info_update == 1" ),
            srec( DOSNameStruct, req_cond="ncp.ext_info_dos_name == 1" ),
            srec( FlushTimeStruct, req_cond="ncp.ext_info_flush == 1" ),
            srec( ParentBaseIDStruct, req_cond="ncp.ext_info_parental == 1" ),
            srec( MacFinderInfoStruct, req_cond="ncp.ext_info_mac_finder == 1" ),
            srec( SiblingCountStruct, req_cond="ncp.ext_info_sibling == 1" ),
            srec( EffectiveRightsStruct, req_cond="ncp.ext_info_effective == 1" ),
            srec( MacTimeStruct, req_cond="ncp.ext_info_mac_date == 1" ),
            srec( LastAccessedTimeStruct, req_cond="ncp.ext_info_access == 1" ),
            srec( FileNameStruct, req_cond="ncp.ret_info_mask_fname == 1" ),
        ])
	pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5715, 87/21
	pkt = NCP(0x5715, "Get Path String from Short Directory Handle", 'file', has_length=0)
	pkt.Request(10, [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, DirHandle ),
	])
	pkt.Reply((9,263), [
		rec( 8, (1,255), Path ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5716, 87/22
	pkt = NCP(0x5716, "Generate Directory Base and Volume Number", 'file', has_length=0)
	pkt.Request((20,274), [
		rec( 8, 1, SrcNameSpace ),
		rec( 9, 1, DestNameSpace ),
		rec( 10, 2, dstNSIndicator ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Get Volume and Directory Base from: %s", "/%s"))
	pkt.Reply(17, [
		rec( 8, 4, DirectoryBase ),
		rec( 12, 4, DOSDirectoryBase ),
		rec( 16, 1, VolumeNumber ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5717, 87/23
	pkt = NCP(0x5717, "Query Name Space Information Format", 'file', has_length=0)
	pkt.Request(10, [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, VolumeNumber ),
	])
	pkt.Reply(58, [
		rec( 8, 4, FixedBitMask ),
		rec( 12, 4, VariableBitMask ),
		rec( 16, 4, HugeBitMask ),
		rec( 20, 2, FixedBitsDefined ),
		rec( 22, 2, VariableBitsDefined ),
		rec( 24, 2, HugeBitsDefined ),
		rec( 26, 32, FieldsLenTable ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5718, 87/24
	pkt = NCP(0x5718, "Get Name Spaces Loaded List from Volume Number", 'file', has_length=0)
	pkt.Request(10, [
		rec( 8, 1, Reserved ),
		rec( 9, 1, VolumeNumber ),
	])
	pkt.Reply(11, [
		rec( 8, 2, NumberOfNSLoaded, var="x" ),
		rec( 10, 1, NameSpace, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5719, 87/25
	pkt = NCP(0x5719, "Set Name Space Information", 'file', has_length=0)
	pkt.Request(531, [
		rec( 8, 1, SrcNameSpace ),
		rec( 9, 1, DestNameSpace ),
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, DirectoryBase ),
		rec( 15, 2, NamesSpaceInfoMask ),
		rec( 17, 2, Reserved2 ),
		rec( 19, 512, NSSpecificInfo ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8b00, 0x8d00, 0x8f00, 0x9001,
			     0x9600, 0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00,
			     0xff16])
	# 2222/571A, 87/26
	pkt = NCP(0x571A, "Get Huge Name Space Information", 'file', has_length=0)
	pkt.Request(34, [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, VolumeNumber ),
		rec( 10, 4, DirectoryBase ),
		rec( 14, 4, HugeBitMask ),
		rec( 18, 16, HugeStateInfo ),
	])
	pkt.Reply((25,279), [
		rec( 8, 16, NextHugeStateInfo ),
		rec( 24, (1,255), HugeData ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8b00, 0x8d00, 0x8f00, 0x9001,
			     0x9600, 0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00,
			     0xff16])
	# 2222/571B, 87/27
	pkt = NCP(0x571B, "Set Huge Name Space Information", 'file', has_length=0)
	pkt.Request((35,289), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, VolumeNumber ),
		rec( 10, 4, DirectoryBase ),
		rec( 14, 4, HugeBitMask ),
		rec( 18, 16, HugeStateInfo ),
		rec( 34, (1,255), HugeData ),
	])
	pkt.Reply(28, [
		rec( 8, 16, NextHugeStateInfo ),
		rec( 24, 4, HugeDataUsed ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8b00, 0x8d00, 0x8f00, 0x9001,
			     0x9600, 0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00,
			     0xff16])
	# 2222/571C, 87/28
	pkt = NCP(0x571C, "Get Full Path String", 'file', has_length=0)
	pkt.Request((28,282), [
		rec( 8, 1, SrcNameSpace ),
		rec( 9, 1, DestNameSpace ),
		rec( 10, 2, PathCookieFlags ),
		rec( 12, 4, Cookie1 ),
		rec( 16, 4, Cookie2 ),
		rec( 20, 1, VolumeNumber ),
		rec( 21, 4, DirectoryBase ),
		rec( 25, 1, HandleFlag ),
		rec( 26, 1, PathCount, var="x" ),
		rec( 27, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Get Full Path from: %s", "/%s"))
	pkt.Reply((23,277), [
		rec( 8, 2, PathCookieFlags ),
		rec( 10, 4, Cookie1 ),
		rec( 14, 4, Cookie2 ),
		rec( 18, 2, PathComponentSize ),
		rec( 20, 2, PathComponentCount, var='x' ),
		rec( 22, (1,255), Path, repeat='x' ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8b00, 0x8d00, 0x8f00, 0x9001,
			     0x9600, 0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00,
			     0xff16])
	# 2222/571D, 87/29
	pkt = NCP(0x571D, "Get Effective Directory Rights", 'file', has_length=0)
	pkt.Request((24, 278), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, DestNameSpace ),
		rec( 10, 2, SearchAttributesLow ),
		rec( 12, 2, ReturnInfoMask ),
		rec( 14, 2, ExtendedInfo ),
		rec( 16, 1, VolumeNumber ),
		rec( 17, 4, DirectoryBase ),
		rec( 21, 1, HandleFlag ),
		rec( 22, 1, PathCount, var="x" ),
		rec( 23, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Get Effective Rights for: %s", "/%s"))
	pkt.Reply(NO_LENGTH_CHECK, [
		rec( 8, 2, EffectiveRights ),
                srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 1)" ),
                srec( PadDSSpaceAllocate, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 0)" ),
                srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 1)" ),
                srec( PadAttributes, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 0)" ),
                srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 1)" ),
                srec( PadDataStreamSize, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 0)" ),
                srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 1)" ),
                srec( PadTotalStreamSize, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 0)" ),
                srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 1)" ),
                srec( PadCreationInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 0)" ),
                srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 1)" ),
                srec( PadModifyInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 0)" ),
                srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 1)" ),
                srec( PadArchiveInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 0)" ),
                srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 1)" ),
                srec( PadRightsInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 0)" ),
                srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 1)" ),
                srec( PadDirEntry, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 0)" ),
                srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 1)" ),
                srec( PadEAInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 0)" ),
                srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 1)" ),
                srec( PadNSInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 0)" ),
                srec( FileNameStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_fname == 1)" ),
                srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_alloc  == 1)" ),
                srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_attr == 1)" ),
                srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_size == 1)" ),
                srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_tspace == 1)" ),
                srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_create == 1)" ),
                srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_mod == 1)" ),
                srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_arch == 1)" ),
                srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_rights == 1)" ),
                srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_dir == 1)" ),
                srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_eattr == 1)" ),
                srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_ns == 1)" ),
                srec( FileNameStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_fname == 1)" ),
        ])
	pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/571E, 87/30
	pkt = NCP(0x571E, "Open/Create File or Subdirectory", 'file', has_length=0)
	pkt.Request((34, 288), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, DataStream ),
		rec( 10, 1, OpenCreateMode ),
		rec( 11, 1, Reserved ),
		rec( 12, 2, SearchAttributesLow ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 2, ReturnInfoMask ),
		rec( 18, 2, ExtendedInfo ),
		rec( 20, 4, AttributesDef32 ),
		rec( 24, 2, DesiredAccessRights ),
		rec( 26, 1, VolumeNumber ),
		rec( 27, 4, DirectoryBase ),
		rec( 31, 1, HandleFlag ),
		rec( 32, 1, PathCount, var="x" ),
		rec( 33, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Open or Create File: %s", "/%s"))
	pkt.Reply(NO_LENGTH_CHECK, [
		rec( 8, 4, FileHandle, BE ),
		rec( 12, 1, OpenCreateAction ),
		rec( 13, 1, Reserved ),
                srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 1)" ),
                srec( PadDSSpaceAllocate, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 0)" ),
                srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 1)" ),
                srec( PadAttributes, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 0)" ),
                srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 1)" ),
                srec( PadDataStreamSize, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 0)" ),
                srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 1)" ),
                srec( PadTotalStreamSize, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 0)" ),
                srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 1)" ),
                srec( PadCreationInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 0)" ),
                srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 1)" ),
                srec( PadModifyInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 0)" ),
                srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 1)" ),
                srec( PadArchiveInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 0)" ),
                srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 1)" ),
                srec( PadRightsInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 0)" ),
                srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 1)" ),
                srec( PadDirEntry, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 0)" ),
                srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 1)" ),
                srec( PadEAInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 0)" ),
                srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 1)" ),
                srec( PadNSInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 0)" ),
                srec( FileNameStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_fname == 1)" ),
                srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_alloc  == 1)" ),
                srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_attr == 1)" ),
                srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_size == 1)" ),
                srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_tspace == 1)" ),
                srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_create == 1)" ),
                srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_mod == 1)" ),
                srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_arch == 1)" ),
                srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_rights == 1)" ),
                srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_dir == 1)" ),
                srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_eattr == 1)" ),
                srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_ns == 1)" ),
                srec( FileNameStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_fname == 1)" ),
        ])
	pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/571F, 87/31
	pkt = NCP(0x571F, "Get File Information", 'file', has_length=0)
	pkt.Request(15, [
		rec( 8, 6, FileHandle  ),
		rec( 14, 1, HandleInfoLevel ),
		#rec( 15, 1, NameSpace ),
	], info_str=(FileHandle, "Get File Information - 0x%s", ", %s"))
	pkt.Reply(NO_LENGTH_CHECK, [
		rec( 8, 4, VolumeNumberLong ),
		rec( 12, 4, DirectoryBase ),
                srec(HandleInfoLevel0, req_cond="ncp.handle_info_level==0x00" ),
                srec(HandleInfoLevel1, req_cond="ncp.handle_info_level==0x01" ),
                srec(HandleInfoLevel2, req_cond="ncp.handle_info_level==0x02" ),
                srec(HandleInfoLevel3, req_cond="ncp.handle_info_level==0x03" ),
                srec(HandleInfoLevel4, req_cond="ncp.handle_info_level==0x04" ),
                srec(HandleInfoLevel5, req_cond="ncp.handle_info_level==0x05" ),
        ])
        pkt.ReqCondSizeVariable()
        pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5720, 87/32
        pkt = NCP(0x5720, "Open/Create File or Subdirectory with Callback", 'file', has_length=0)
	pkt.Request((30, 284), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, OpenCreateMode ),
		rec( 10, 2, SearchAttributesLow ),
		rec( 12, 2, ReturnInfoMask ),
		rec( 14, 2, ExtendedInfo ),
		rec( 16, 4, AttributesDef32 ),
		rec( 20, 2, DesiredAccessRights ),
		rec( 22, 1, VolumeNumber ),
		rec( 23, 4, DirectoryBase ),
		rec( 27, 1, HandleFlag ),
		rec( 28, 1, PathCount, var="x" ),
		rec( 29, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Open or Create with Op-Lock: %s", "/%s"))
	pkt.Reply( NO_LENGTH_CHECK, [
		rec( 8, 4, FileHandle, BE ),
		rec( 12, 1, OpenCreateAction ),
		rec( 13, 1, OCRetFlags ),
                srec( DSSpaceAllocateStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 1)" ),
                srec( PadDSSpaceAllocate, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 0)" ),
                srec( AttributesStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 1)" ),
                srec( PadAttributes, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 0)" ),
                srec( DataStreamSizeStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 1)" ),
                srec( PadDataStreamSize, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 0)" ),
                srec( TotalStreamSizeStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 1)" ),
                srec( PadTotalStreamSize, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 0)" ),
                srec( CreationInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 1)" ),
                srec( PadCreationInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 0)" ),
                srec( ModifyInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 1)" ),
                srec( PadModifyInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 0)" ),
                srec( ArchiveInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 1)" ),
                srec( PadArchiveInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 0)" ),
                srec( RightsInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 1)" ),
                srec( PadRightsInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 0)" ),
                srec( DirEntryStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 1)" ),
                srec( PadDirEntry, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 0)" ),
                srec( EAInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 1)" ),
                srec( PadEAInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 0)" ),
                srec( NSInfoStruct, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 1)" ),
                srec( PadNSInfo, req_cond="(ncp.ret_info_mask != 0x0000) && (ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 0)" ),
                srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_alloc  == 1)" ),
                srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_attr == 1)" ),
                srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_size == 1)" ),
                srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_tspace == 1)" ),
                srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_eattr == 1)" ),
                srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_mod == 1)" ),
                srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_create == 1)" ),
                srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_arch == 1)" ),
                srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_dir == 1)" ),
                srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_rights == 1)" ),
                srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_ns == 1)" ),
                srec( ReferenceIDStruct, req_cond="ncp.ret_info_mask_id == 1" ),
                srec( NSAttributeStruct, req_cond="ncp.ret_info_mask_ns_attr == 1" ),
                srec( DStreamActual, req_cond="ncp.ret_info_mask_actual == 1" ),
                srec( DStreamLogical, req_cond="ncp.ret_info_mask_logical == 1" ),
                srec( LastUpdatedInSecondsStruct, req_cond="ncp.ext_info_update == 1" ),
                srec( DOSNameStruct, req_cond="ncp.ext_info_dos_name == 1" ),
                srec( FlushTimeStruct, req_cond="ncp.ext_info_flush == 1" ),
                srec( ParentBaseIDStruct, req_cond="ncp.ext_info_parental == 1" ),
                srec( MacFinderInfoStruct, req_cond="ncp.ext_info_mac_finder == 1" ),
                srec( SiblingCountStruct, req_cond="ncp.ext_info_sibling == 1" ),
                srec( EffectiveRightsStruct, req_cond="ncp.ext_info_effective == 1" ),
                srec( MacTimeStruct, req_cond="ncp.ext_info_mac_date == 1" ),
                srec( LastAccessedTimeStruct, req_cond="ncp.ext_info_access == 1" ),
                srec( FileNameStruct, req_cond="ncp.ret_info_mask_fname == 1" ),
        ])
	pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x7f00, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5721, 87/33
	pkt = NCP(0x5721, "Open/Create File or Subdirectory II with Callback", 'file', has_length=0)
	pkt.Request((34, 288), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, DataStream ),
		rec( 10, 1, OpenCreateMode ),
		rec( 11, 1, Reserved ),
		rec( 12, 2, SearchAttributesLow ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 2, ReturnInfoMask ),
		rec( 18, 2, ExtendedInfo ),
		rec( 20, 4, AttributesDef32 ),
		rec( 24, 2, DesiredAccessRights ),
		rec( 26, 1, VolumeNumber ),
		rec( 27, 4, DirectoryBase ),
		rec( 31, 1, HandleFlag ),
		rec( 32, 1, PathCount, var="x" ),
		rec( 33, (1,255), Path, repeat="x" ),
	], info_str=(FilePath, "Open or Create II with Op-Lock: %s", "/%s"))
	pkt.Reply((91,345), [
		rec( 8, 4, FileHandle ),
		rec( 12, 1, OpenCreateAction ),
		rec( 13, 1, OCRetFlags ),
		rec( 14, 4, DataStreamSpaceAlloc ),
		rec( 18, 6, AttributesStruct ),
		rec( 24, 4, DataStreamSize ),
		rec( 28, 4, TtlDSDskSpaceAlloc ),
		rec( 32, 2, NumberOfDataStreams ),
		rec( 34, 2, CreationTime ),
		rec( 36, 2, CreationDate ),
		rec( 38, 4, CreatorID, BE ),
		rec( 42, 2, ModifiedTime ),
		rec( 44, 2, ModifiedDate ),
		rec( 46, 4, ModifierID, BE ),
		rec( 50, 2, LastAccessedDate ),
		rec( 52, 2, ArchivedTime ),
		rec( 54, 2, ArchivedDate ),
		rec( 56, 4, ArchiverID, BE ),
		rec( 60, 2, InheritedRightsMask ),
		rec( 62, 4, DirectoryEntryNumber ),
		rec( 66, 4, DOSDirectoryEntryNumber ),
		rec( 70, 4, VolumeNumberLong ),
		rec( 74, 4, EADataSize ),
		rec( 78, 4, EACount ),
		rec( 82, 4, EAKeySize ),
		rec( 86, 1, CreatorNameSpaceNumber ),
                rec( 87, 3, Reserved3 ),
		rec( 90, (1,255), FileName ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5722, 87/34
	pkt = NCP(0x5722, "Open CallBack Control (Op-Lock)", 'file', has_length=0)
	pkt.Request(13, [
		rec( 10, 4, CCFileHandle, BE ),
		rec( 14, 1, CCFunction ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0xff16])
	# 2222/5723, 87/35
	pkt = NCP(0x5723, "Modify DOS Attributes on a File or Subdirectory", 'file', has_length=0)
	pkt.Request((28, 282), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, Flags ),
		rec( 10, 2, SearchAttributesLow ),
		rec( 12, 2, ReturnInfoMask ),
		rec( 14, 2, ExtendedInfo ),
		rec( 16, 4, AttributesDef32 ),
		rec( 20, 1, VolumeNumber ),
		rec( 21, 4, DirectoryBase ),
		rec( 25, 1, HandleFlag ),
		rec( 26, 1, PathCount, var="x" ),
		rec( 27, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Modify DOS Attributes for: %s", "/%s"))
	pkt.Reply(24, [
		rec( 8, 4, ItemsChecked ),
		rec( 12, 4, ItemsChanged ),
		rec( 16, 4, AttributeValidFlag ),
		rec( 20, 4, AttributesDef32 ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5724, 87/36
	pkt = NCP(0x5724, "Log File", 'file', has_length=0)
	pkt.Request((28, 282), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, Reserved2 ),
		rec( 12, 1, LogFileFlagLow ),
		rec( 13, 1, LogFileFlagHigh ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 4, WaitTime ),
		rec( 20, 1, VolumeNumber ),
		rec( 21, 4, DirectoryBase ),
		rec( 25, 1, HandleFlag ),
		rec( 26, 1, PathCount, var="x" ),
		rec( 27, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Lock File: %s", "/%s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5725, 87/37
	pkt = NCP(0x5725, "Release File", 'file', has_length=0)
	pkt.Request((20, 274), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, Reserved2 ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Release Lock on: %s", "/%s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5726, 87/38
	pkt = NCP(0x5726, "Clear File", 'file', has_length=0)
	pkt.Request((20, 274), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, Reserved2 ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Clear File: %s", "/%s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5727, 87/39
	pkt = NCP(0x5727, "Get Directory Disk Space Restriction", 'file', has_length=0)
	pkt.Request((19, 273), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 2, Reserved2 ),
		rec( 11, 1, VolumeNumber ),
		rec( 12, 4, DirectoryBase ),
		rec( 16, 1, HandleFlag ),
		rec( 17, 1, PathCount, var="x" ),
		rec( 18, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Get Disk Space Restriction for: %s", "/%s"))
	pkt.Reply(18, [
		rec( 8, 1, NumberOfEntries, var="x" ),
		rec( 9, 9, SpaceStruct, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00,
			     0xff16])
	# 2222/5728, 87/40
	pkt = NCP(0x5728, "Search for File or Subdirectory Set (Extended Errors)", 'file', has_length=0)
	pkt.Request((28, 282), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, DataStream ),
		rec( 10, 2, SearchAttributesLow ),
		rec( 12, 2, ReturnInfoMask ),
		rec( 14, 2, ExtendedInfo ),
		rec( 16, 2, ReturnInfoCount ),
		rec( 18, 9, SearchSequence ),
		rec( 27, (1,255), SearchPattern ),
	], info_str=(SearchPattern, "Search for: %s", ", %s"))
	pkt.Reply(NO_LENGTH_CHECK, [
		rec( 8, 9, SearchSequence ),
		rec( 17, 1, MoreFlag ),
		rec( 18, 2, InfoCount ),
                srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 1)" ),
                srec( PadDSSpaceAllocate, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_alloc == 0)" ),
                srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 1)" ),
                srec( PadAttributes, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_attr == 0)" ),
                srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 1)" ),
                srec( PadDataStreamSize, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_size == 0)" ),
                srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 1)" ),
                srec( PadTotalStreamSize, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_tspace == 0)" ),
                srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 1)" ),
                srec( PadCreationInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_create == 0)" ),
                srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 1)" ),
                srec( PadModifyInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_mod == 0)" ),
                srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 1)" ),
                srec( PadArchiveInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_arch == 0)" ),
                srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 1)" ),
                srec( PadRightsInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_rights == 0)" ),
                srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 1)" ),
                srec( PadDirEntry, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_dir == 0)" ),
                srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 1)" ),
                srec( PadEAInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_eattr == 0)" ),
                srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 1)" ),
                srec( PadNSInfo, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_ns == 0)" ),
                srec( FileNameStruct, req_cond="(ncp.ext_info_newstyle == 0) && (ncp.ret_info_mask_fname == 1)" ),
                srec( DSSpaceAllocateStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_alloc  == 1)" ),
                srec( AttributesStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_attr == 1)" ),
                srec( DataStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_size == 1)" ),
                srec( TotalStreamSizeStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_tspace == 1)" ),
                srec( CreationInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_create == 1)" ),
                srec( ModifyInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_mod == 1)" ),
                srec( ArchiveInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_arch == 1)" ),
                srec( RightsInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_rights == 1)" ),
                srec( DirEntryStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_dir == 1)" ),
                srec( EAInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_eattr == 1)" ),
                srec( NSInfoStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_ns == 1)" ),
                srec( FileNameStruct, req_cond="(ncp.ext_info_newstyle == 1) && (ncp.ret_info_mask_fname == 1)" ),
        ])
	pkt.ReqCondSizeVariable()
        pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5729, 87/41
	pkt = NCP(0x5729, "Scan Salvageable Files", 'file', has_length=0)
	pkt.Request((24,278), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, CtrlFlags, LE ),
		rec( 12, 4, SequenceNumber ),
		rec( 16, 1, VolumeNumber ),
		rec( 17, 4, DirectoryBase ),
		rec( 21, 1, HandleFlag ),
		rec( 22, 1, PathCount, var="x" ),
		rec( 23, (1,255), Path, repeat="x" ),
	], info_str=(Path, "Scan Deleted Files: %s", "/%s"))
	pkt.Reply(NO_LENGTH_CHECK, [
		rec( 8, 4, SequenceNumber ),
		rec( 12, 4, DirectoryBase ),
		rec( 16, 4, ScanItems, var="x" ),
                srec(ScanInfoFileName, req_cond="ncp.ctrl_flags==0x0001", repeat="x" ),
                srec(ScanInfoFileNoName, req_cond="ncp.ctrl_flags==0x0000", repeat="x" ),
	])
        pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/572A, 87/42
	pkt = NCP(0x572A, "Purge Salvageable File List", 'file', has_length=0)
	pkt.Request(28, [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, PurgeFlags ),
		rec( 12, 4, VolumeNumberLong ),
		rec( 16, 4, DirectoryBase ),
		rec( 20, 4, PurgeCount, var="x" ),
                rec( 24, 4, PurgeList, repeat="x" ),
	])
	pkt.Reply(16, [
		rec( 8, 4, PurgeCount, var="x" ),
                rec( 12, 4, PurgeCcode, repeat="x" ),
        ])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/572B, 87/43
	pkt = NCP(0x572B, "Revoke File Handle Rights", 'file', has_length=0)
	pkt.Request(17, [
		rec( 8, 3, Reserved3 ),
		rec( 11, 1, RevQueryFlag ),
		rec( 12, 4, FileHandle ),
		rec( 16, 1, RemoveOpenRights ),
	])
	pkt.Reply(13, [
		rec( 8, 4, FileHandle ),
		rec( 12, 1, OpenRights ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/572C, 87/44
	pkt = NCP(0x572C, "Update File Handle Rights", 'file', has_length=0)
	pkt.Request(24, [
		rec( 8, 2, Reserved2 ),
		rec( 10, 1, VolumeNumber ),
		rec( 11, 1, NameSpace ),
		rec( 12, 4, DirectoryNumber ),
		rec( 16, 2, AccessRightsMaskWord ),
		rec( 18, 2, NewAccessRights ),
		rec( 20, 4, FileHandle, BE ),
	])
	pkt.Reply(16, [
		rec( 8, 4, FileHandle, BE ),
		rec( 12, 4, EffectiveRights ),
	])
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff16])
	# 2222/5740, 87/64
	pkt = NCP(0x5740, "Read from File", 'file', has_length=0)
	pkt.Request(22, [
        rec( 8, 4, FileHandle, BE ),
        rec( 12, 8, StartOffset64bit, BE ),
        rec( 20, 2, NumBytes, BE ),
    ])
	pkt.Reply(10, [
        rec( 8, 2, NumBytes, BE),
    ])
	pkt.CompletionCodes([0x0000, 0x8300, 0x8800, 0x9300, 0x9500, 0xa201, 0xfd00, 0xff1b])
	# 2222/5741, 87/65
	pkt = NCP(0x5741, "Write to File", 'file', has_length=0)
	pkt.Request(22, [
        rec( 8, 4, FileHandle, BE ),
        rec( 12, 8, StartOffset64bit, BE ),
        rec( 20, 2, NumBytes, BE ),
    ])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8300, 0x8800, 0x9400, 0x9500, 0xa201, 0xfd00, 0xff1b])
	# 2222/5742, 87/66
	pkt = NCP(0x5742, "Get Current Size of File", 'file', has_length=0)
	pkt.Request(12, [
        rec( 8, 4, FileHandle, BE ),
    ])
	pkt.Reply(16, [
        rec( 8, 8, FileSize64bit, BE ),
    ])
	pkt.CompletionCodes([0x0000, 0x7f00, 0x8800, 0x9600, 0xfd02, 0xff01])
	# 2222/5743, 87/67
	pkt = NCP(0x5743, "Log Physical Record", 'file', has_length=0)
	pkt.Request(36, [
        rec( 8, 4, LockFlag, BE ),
        rec(12, 4, FileHandle, BE ),
        rec(16, 8, StartOffset64bit, BE ),
        rec(24, 8, Length64bit, BE ),
        rec(32, 4, LockTimeout, BE),
    ])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7f00, 0x8800, 0x9600, 0xfb08, 0xfd02, 0xff01])
	# 2222/5744, 87/68
	pkt = NCP(0x5744, "Release Physical Record", 'file', has_length=0)
	pkt.Request(28, [
        rec(8, 4, FileHandle, BE ),
        rec(12, 8, StartOffset64bit, BE ),
        rec(20, 8, Length64bit, BE ),
    ])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff1a])
	# 2222/5745, 87/69
	pkt = NCP(0x5745, "Clear Physical Record", 'file', has_length=0)
	pkt.Request(28, [
        rec(8, 4, FileHandle, BE ),
        rec(12, 8, StartOffset64bit, BE ),
        rec(20, 8, Length64bit, BE ),
    ])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xbf00, 0xfd00, 0xff1a])
	# 2222/5801, 8801
	pkt = NCP(0x5801, "Query Volume Audit Status", "auditing", has_length=0)
	pkt.Request(12, [
		rec( 8, 4, ConnectionNumber ),
	])
	pkt.Reply(40, [
		rec(8, 32, NWAuditStatus ),
	])
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5802, 8802
	pkt = NCP(0x5802, "Add User Audit Property", "auditing", has_length=0)
	pkt.Request(25, [
		rec(8, 4, AuditIDType ),
		rec(12, 4, AuditID ),
		rec(16, 4, AuditHandle ),
		rec(20, 4, ObjectID ),
		rec(24, 1, AuditFlag ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5803, 8803
	pkt = NCP(0x5803, "Add Auditor Access", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5804, 8804
	pkt = NCP(0x5804, "Change Auditor Volume Password", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5805, 8805
	pkt = NCP(0x5805, "Check Auditor Access", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5806, 8806
	pkt = NCP(0x5806, "Delete User Audit Property", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5807, 8807
	pkt = NCP(0x5807, "Disable Auditing On A Volume", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5808, 8808
	pkt = NCP(0x5808, "Enable Auditing On A Volume", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5809, 8809
	pkt = NCP(0x5809, "Query User Being Audited", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/580A, 88,10
	pkt = NCP(0x580A, "Read Audit Bit Map", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/580B, 88,11
	pkt = NCP(0x580B, "Read Audit File Configuration Header", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/580D, 88,13
	pkt = NCP(0x580D, "Remove Auditor Access", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/580E, 88,14
	pkt = NCP(0x580E, "Reset Audit File", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])

	# 2222/580F, 88,15
	pkt = NCP(0x580F, "Auditing NCP", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5810, 88,16
	pkt = NCP(0x5810, "Write Audit Bit Map", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5811, 88,17
	pkt = NCP(0x5811, "Write Audit File Configuration Header", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5812, 88,18
	pkt = NCP(0x5812, "Change Auditor Volume Password2", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5813, 88,19
	pkt = NCP(0x5813, "Return Audit Flags", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5814, 88,20
	pkt = NCP(0x5814, "Close Old Audit File", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5816, 88,22
	pkt = NCP(0x5816, "Check Level Two Access", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5817, 88,23
	pkt = NCP(0x5817, "Return Old Audit File List", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5818, 88,24
	pkt = NCP(0x5818, "Init Audit File Reads", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5819, 88,25
	pkt = NCP(0x5819, "Read Auditing File", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/581A, 88,26
	pkt = NCP(0x581A, "Delete Old Audit File", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/581E, 88,30
	pkt = NCP(0x581E, "Restart Volume auditing", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/581F, 88,31
	pkt = NCP(0x581F, "Set Volume Password", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa600, 0xa801, 0xfd00, 0xff16])
	# 2222/5A01, 90/00
	pkt = NCP(0x5A01, "Parse Tree", 'file')
	pkt.Request(26, [
		rec( 10, 4, InfoMask ),
		rec( 14, 4, Reserved4 ),
		rec( 18, 4, Reserved4 ),
		rec( 22, 4, limbCount ),
	])
	pkt.Reply(32, [
		rec( 8, 4, limbCount ),
		rec( 12, 4, ItemsCount ),
		rec( 16, 4, nextLimbScanNum ),
		rec( 20, 4, CompletionCode ),
		rec( 24, 1, FolderFlag ),
		rec( 25, 3, Reserved ),
		rec( 28, 4, DirectoryBase ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5A0A, 90/10
	pkt = NCP(0x5A0A, "Get Reference Count from Dir Entry Number", 'file')
	pkt.Request(19, [
		rec( 10, 4, VolumeNumberLong ),
		rec( 14, 4, DirectoryBase ),
		rec( 18, 1, NameSpace ),
	])
	pkt.Reply(12, [
		rec( 8, 4, ReferenceCount ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5A0B, 90/11
	pkt = NCP(0x5A0B, "Get Reference Count from Dir Handle", 'file')
	pkt.Request(14, [
		rec( 10, 4, DirHandle ),
	])
	pkt.Reply(12, [
		rec( 8, 4, ReferenceCount ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5A0C, 90/12
	pkt = NCP(0x5A0C, "Set Compressed File Size", 'file')
	pkt.Request(20, [
		rec( 10, 6, FileHandle ),
		rec( 16, 4, SuggestedFileSize ),
	])
	pkt.Reply(16, [
		rec( 8, 4, OldFileSize ),
		rec( 12, 4, NewFileSize ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5A80, 90/128
	pkt = NCP(0x5A80, "Move File Data To Data Migration", 'file')
	pkt.Request(27, [
		rec( 10, 4, VolumeNumberLong ),
		rec( 14, 4, DirectoryEntryNumber ),
		rec( 18, 1, NameSpace ),
		rec( 19, 3, Reserved ),
		rec( 22, 4, SupportModuleID ),
		rec( 26, 1, DMFlags ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5A81, 90/129
	pkt = NCP(0x5A81, "Data Migration File Information", 'file')
	pkt.Request(19, [
		rec( 10, 4, VolumeNumberLong ),
		rec( 14, 4, DirectoryEntryNumber ),
		rec( 18, 1, NameSpace ),
	])
	pkt.Reply(24, [
		rec( 8, 4, SupportModuleID ),
		rec( 12, 4, RestoreTime ),
		rec( 16, 4, DMInfoEntries, var="x" ),
		rec( 20, 4, DataSize, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5A82, 90/130
	pkt = NCP(0x5A82, "Volume Data Migration Status", 'file')
	pkt.Request(18, [
		rec( 10, 4, VolumeNumberLong ),
		rec( 14, 4, SupportModuleID ),
	])
	pkt.Reply(32, [
		rec( 8, 4, NumOfFilesMigrated ),
		rec( 12, 4, TtlMigratedSize ),
		rec( 16, 4, SpaceUsed ),
		rec( 20, 4, LimboUsed ),
		rec( 24, 4, SpaceMigrated ),
		rec( 28, 4, FileLimbo ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5A83, 90/131
	pkt = NCP(0x5A83, "Migrator Status Info", 'file')
	pkt.Request(10)
	pkt.Reply(20, [
		rec( 8, 1, DMPresentFlag ),
		rec( 9, 3, Reserved3 ),
		rec( 12, 4, DMmajorVersion ),
		rec( 16, 4, DMminorVersion ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5A84, 90/132
	pkt = NCP(0x5A84, "Data Migration Support Module Information", 'file')
	pkt.Request(18, [
		rec( 10, 1, DMInfoLevel ),
                rec( 11, 3, Reserved3),
		rec( 14, 4, SupportModuleID ),
	])
	pkt.Reply(NO_LENGTH_CHECK, [
                srec( DMInfoLevel0, req_cond="ncp.dm_info_level == 0x00" ),
                srec( DMInfoLevel1, req_cond="ncp.dm_info_level == 0x01" ),
                srec( DMInfoLevel2, req_cond="ncp.dm_info_level == 0x02" ),
	])
        pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5A85, 90/133
	pkt = NCP(0x5A85, "Move File Data From Data Migration", 'file')
	pkt.Request(19, [
		rec( 10, 4, VolumeNumberLong ),
		rec( 14, 4, DirectoryEntryNumber ),
		rec( 18, 1, NameSpace ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5A86, 90/134
	pkt = NCP(0x5A86, "Get/Set Default Read-Write Support Module ID", 'file')
	pkt.Request(18, [
		rec( 10, 1, GetSetFlag ),
		rec( 11, 3, Reserved3 ),
		rec( 14, 4, SupportModuleID ),
	])
	pkt.Reply(12, [
		rec( 8, 4, SupportModuleID ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5A87, 90/135
	pkt = NCP(0x5A87, "Data Migration Support Module Capacity Request", 'file')
	pkt.Request(22, [
		rec( 10, 4, SupportModuleID ),
		rec( 14, 4, VolumeNumberLong ),
		rec( 18, 4, DirectoryBase ),
	])
	pkt.Reply(20, [
		rec( 8, 4, BlockSizeInSectors ),
		rec( 12, 4, TotalBlocks ),
		rec( 16, 4, UsedBlocks ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5A88, 90/136
	pkt = NCP(0x5A88, "RTDM Request", 'file')
	pkt.Request(15, [
		rec( 10, 4, Verb ),
		rec( 14, 1, VerbData ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
    # 2222/5C, 91
	pkt = NCP(0x5B, "NMAS Graded Authentication", 'nmas')
	#Need info on this packet structure
	pkt.Request(7)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600, 0xfb0b,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5C00, 9201                                                  
	pkt = NCP(0x5C01, "SecretStore Services (Ping Server)", 'sss', 0)
	#Need info on this packet structure and SecretStore Verbs
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600, 0xfb0b,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5C01, 9202
	pkt = NCP(0x5C02, "SecretStore Services", 'sss', 0)
	#Need info on this packet structure and SecretStore Verbs
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600, 0xfb0b,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5C02, 9203
	pkt = NCP(0x5C03, "SecretStore Services", 'sss', 0)
	#Need info on this packet structure and SecretStore Verbs
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600, 0xfb0b,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5C03, 9204
	pkt = NCP(0x5C04, "SecretStore Services", 'sss', 0)
	#Need info on this packet structure and SecretStore Verbs
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600, 0xfb0b,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5C04, 9205
	pkt = NCP(0x5C05, "SecretStore Services", 'sss', 0)
	#Need info on this packet structure and SecretStore Verbs
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600, 0xfb0b,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5C05, 9206
	pkt = NCP(0x5C06, "SecretStore Services", 'sss', 0)
	#Need info on this packet structure and SecretStore Verbs
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600, 0xfb0b,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5C06, 9207
	pkt = NCP(0x5C07, "SecretStore Services", 'sss', 0)
	#Need info on this packet structure and SecretStore Verbs
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600, 0xfb0b,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5C07, 9208
	pkt = NCP(0x5C08, "SecretStore Services", 'sss', 0)
	#Need info on this packet structure and SecretStore Verbs
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600, 0xfb0b,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5C08, 9209
	pkt = NCP(0x5C09, "SecretStore Services", 'sss', 0)
	#Need info on this packet structure and SecretStore Verbs
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600, 0xfb0b,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5C09, 920a
	pkt = NCP(0x5C0a, "SecretStore Services", 'sss', 0)
	#Need info on this packet structure and SecretStore Verbs
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600, 0xfb0b,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5E, 9401
	pkt = NCP(0x5E01, "NMAS Communications Packet", 'nmas', 0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xfb09])
	# 2222/5E, 9402
	pkt = NCP(0x5E02, "NMAS Communications Packet", 'nmas', 0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xfb09])
	# 2222/5E, 9403
	pkt = NCP(0x5E03, "NMAS Communications Packet", 'nmas', 0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xfb09])
	# 2222/61, 97
	pkt = NCP(0x61, "Get Big Packet NCP Max Packet Size", 'comm')
	pkt.Request(10, [
		rec( 7, 2, ProposedMaxSize, BE ),
		rec( 9, 1, SecurityFlag ),
	],info_str=(ProposedMaxSize, "Get Big Max Packet Size - %d", ", %d"))
	pkt.Reply(13, [
		rec( 8, 2, AcceptedMaxSize, BE ),
		rec( 10, 2, EchoSocket, BE ),
		rec( 12, 1, SecurityFlag ),
	])
	pkt.CompletionCodes([0x0000])
	# 2222/63, 99
	pkt = NCP(0x63, "Undocumented Packet Burst", 'comm')
	pkt.Request(7)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/64, 100
	pkt = NCP(0x64, "Undocumented Packet Burst", 'comm')
	pkt.Request(7)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/65, 101
	pkt = NCP(0x65, "Packet Burst Connection Request", 'comm')
	pkt.Request(25, [
		rec( 7, 4, LocalConnectionID, BE ),
		rec( 11, 4, LocalMaxPacketSize, BE ),
		rec( 15, 2, LocalTargetSocket, BE ),
		rec( 17, 4, LocalMaxSendSize, BE ),
		rec( 21, 4, LocalMaxRecvSize, BE ),
	])
	pkt.Reply(16, [
		rec( 8, 4, RemoteTargetID, BE ),
		rec( 12, 4, RemoteMaxPacketSize, BE ),
	])
	pkt.CompletionCodes([0x0000])
	# 2222/66, 102
	pkt = NCP(0x66, "Undocumented Packet Burst", 'comm')
	pkt.Request(7)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/67, 103
	pkt = NCP(0x67, "Undocumented Packet Burst", 'comm')
	pkt.Request(7)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/6801, 104/01
	pkt = NCP(0x6801, "Ping for NDS NCP", "nds", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
        pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x8100, 0xfb04, 0xfe0c])
	# 2222/6802, 104/02
	#
	# XXX - if FraggerHandle is not 0xffffffff, this is not the
	# first fragment, so we can only dissect this by reassembling;
	# the fields after "Fragment Handle" are bogus for non-0xffffffff
	# fragments, so we shouldn't dissect them.
	#
	# XXX - are there TotalRequest requests in the packet, and
	# does each of them have NDSFlags and NDSVerb fields, or
	# does only the first one have it?
	#
	pkt = NCP(0x6802, "Send NDS Fragmented Request/Reply", "nds", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
        pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0xfd01])
 	# 2222/6803, 104/03
	pkt = NCP(0x6803, "Fragment Close", "nds", has_length=0)
	pkt.Request(12, [
		rec( 8, 4, FraggerHandle ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xff00])
	# 2222/6804, 104/04
	pkt = NCP(0x6804, "Return Bindery Context", "nds", has_length=0)
	pkt.Request(8)
	pkt.Reply((9, 263), [
		rec( 8, (1,255), binderyContext ),
	])
	pkt.CompletionCodes([0x0000, 0xfe0c, 0xff00])
	# 2222/6805, 104/05
	pkt = NCP(0x6805, "Monitor NDS Connection", "nds", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xfb00, 0xfe0c, 0xff00])
	# 2222/6806, 104/06
	pkt = NCP(0x6806, "Return NDS Statistics", "nds", has_length=0)
	pkt.Request(10, [
		rec( 8, 2, NDSRequestFlags ),
	])
	pkt.Reply(8)
	#Need to investigate how to decode Statistics Return Value
	pkt.CompletionCodes([0x0000, 0xfb00, 0xfe0c, 0xff00])
	# 2222/6807, 104/07
	pkt = NCP(0x6807, "Clear NDS Statistics", "nds", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xfb00, 0xfe0c, 0xff00])
	# 2222/6808, 104/08
	pkt = NCP(0x6808, "Reload NDS Software", "nds", has_length=0)
	pkt.Request(8)
	pkt.Reply(12, [
		rec( 8, 4, NDSStatus ),
	])
	pkt.CompletionCodes([0x0000, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68C8, 104/200
	pkt = NCP(0x68C8, "Query Container Audit Status", "auditing", has_length=0)
	pkt.Request(12, [
		rec( 8, 4, ConnectionNumber ),
#		rec( 12, 4, AuditIDType, LE ),
#		rec( 16, 4, AuditID ),
#		rec( 20, 2, BufferSize ),
	])
	pkt.Reply(40, [
		rec(8, 32, NWAuditStatus ),
	])
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68CA, 104/202
	pkt = NCP(0x68CA, "Add Auditor Access", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68CB, 104/203
	pkt = NCP(0x68CB, "Change Auditor Container Password", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68CC, 104/204
	pkt = NCP(0x68CC, "Check Auditor Access", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68CE, 104/206
	pkt = NCP(0x680CE, "Disable Container Auditing", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68CF, 104/207
	pkt = NCP(0x68CF, "Enable Container Auditing", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68D1, 104/209
	pkt = NCP(0x68D1, "Read Audit File Header", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68D3, 104/211
	pkt = NCP(0x68D3, "Remove Auditor Access", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68D4, 104/212
	pkt = NCP(0x68D4, "Reset Audit File", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68D6, 104/214
	pkt = NCP(0x68D6, "Write Audit File Configuration Header", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68D7, 104/215
	pkt = NCP(0x68D7, "Change Auditor Container Password2", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68D8, 104/216
	pkt = NCP(0x68D8, "Return Audit Flags", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68D9, 104/217
	pkt = NCP(0x68D9, "Close Old Audit File", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68DB, 104/219
	pkt = NCP(0x68DB, "Check Level Two Access", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68DC, 104/220
	pkt = NCP(0x68DC, "Check Object Audited", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68DD, 104/221
	pkt = NCP(0x68DD, "Change Object Audited", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68DE, 104/222
	pkt = NCP(0x68DE, "Return Old Audit File List", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68DF, 104/223
	pkt = NCP(0x68DF, "Init Audit File Reads", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68E0, 104/224
	pkt = NCP(0x68E0, "Read Auditing File", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68E1, 104/225
	pkt = NCP(0x68E1, "Delete Old Audit File", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68E5, 104/229
	pkt = NCP(0x68E5, "Set Audit Password", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/68E7, 104/231
	pkt = NCP(0x68E7, "External Audit Append To File", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xa700, 0xfb00, 0xfe0c, 0xff00])
	# 2222/69, 105
	pkt = NCP(0x69, "Log File", 'file')
	pkt.Request( (12, 267), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, LockFlag ),
		rec( 9, 2, TimeoutLimit ),
		rec( 11, (1, 256), FilePath ),
	], info_str=(FilePath, "Log File: %s", "/%s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7f00, 0x8200, 0x9600, 0xfe0d, 0xff01])
	# 2222/6A, 106
	pkt = NCP(0x6A, "Lock File Set", 'file')
	pkt.Request( 9, [
		rec( 7, 2, TimeoutLimit ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7f00, 0x8200, 0x9600, 0xfe0d, 0xff01])
	# 2222/6B, 107
	pkt = NCP(0x6B, "Log Logical Record", 'file')
	pkt.Request( (11, 266), [
		rec( 7, 1, LockFlag ),
		rec( 8, 2, TimeoutLimit ),
		rec( 10, (1, 256), SynchName ),
	], info_str=(SynchName, "Log Logical Record: %s", ", %s"))
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7f00, 0x9600, 0xfe0d, 0xff01])
	# 2222/6C, 108
	pkt = NCP(0x6C, "Log Logical Record", 'file')
	pkt.Request( 10, [
		rec( 7, 1, LockFlag ),
		rec( 8, 2, TimeoutLimit ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7f00, 0x9600, 0xfe0d, 0xff01])
	# 2222/6D, 109
	pkt = NCP(0x6D, "Log Physical Record", 'file')
	pkt.Request(24, [
		rec( 7, 1, LockFlag ),
		rec( 8, 6, FileHandle ),
		rec( 14, 4, LockAreasStartOffset ),
		rec( 18, 4, LockAreaLen ),
		rec( 22, 2, LockTimeout ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7f00, 0x8200, 0x8800, 0x9600, 0xfd02, 0xfe04, 0xff01])
	# 2222/6E, 110
	pkt = NCP(0x6E, "Lock Physical Record Set", 'file')
	pkt.Request(10, [
		rec( 7, 1, LockFlag ),
		rec( 8, 2, LockTimeout ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7f00, 0x8200, 0x8800, 0x9600, 0xfd02, 0xfe04, 0xff01])
	# 2222/6F00, 111/00
	pkt = NCP(0x6F00, "Open/Create a Semaphore", 'file', has_length=0)
	pkt.Request((10,521), [
		rec( 8, 1, InitialSemaphoreValue ),
		rec( 9, (1, 512), SemaphoreName ),
	], info_str=(SemaphoreName, "Open/Create Semaphore: %s", ", %s"))
	pkt.Reply(13, [
		  rec( 8, 4, SemaphoreHandle ),
		  rec( 12, 1, SemaphoreOpenCount ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xff01])
	# 2222/6F01, 111/01
	pkt = NCP(0x6F01, "Examine Semaphore", 'file', has_length=0)
	pkt.Request(12, [
		rec( 8, 4, SemaphoreHandle ),
	])
	pkt.Reply(10, [
		  rec( 8, 1, SemaphoreValue ),
		  rec( 9, 1, SemaphoreOpenCount ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xff01])
	# 2222/6F02, 111/02
	pkt = NCP(0x6F02, "Wait On (P) Semaphore", 'file', has_length=0)
	pkt.Request(14, [
		rec( 8, 4, SemaphoreHandle ),
		rec( 12, 2, LockTimeout ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xfe04, 0xff01])
	# 2222/6F03, 111/03
	pkt = NCP(0x6F03, "Signal (V) Semaphore", 'file', has_length=0)
	pkt.Request(12, [
		rec( 8, 4, SemaphoreHandle ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xfe04, 0xff01])
	# 2222/6F04, 111/04
	pkt = NCP(0x6F04, "Close Semaphore", 'file', has_length=0)
	pkt.Request(12, [
		rec( 8, 4, SemaphoreHandle ),
	])
	pkt.Reply(10, [
		rec( 8, 1, SemaphoreOpenCount ),
		rec( 9, 1, SemaphoreShareCount ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xfe04, 0xff01])
	# 2222/7201, 114/01
	pkt = NCP(0x7201, "Timesync Get Time", 'file')
	pkt.Request(10)
	pkt.Reply(32,[
                rec( 8, 12, theTimeStruct ),
                rec(20, 8, eventOffset ),
                rec(28, 4, eventTime ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e00, 0xfb06, 0xff00])
	# 2222/7202, 114/02
	pkt = NCP(0x7202, "Timesync Exchange Time", 'file')
	pkt.Request((63,112), [
		rec( 10, 4, protocolFlags ),
		rec( 14, 4, nodeFlags ),
		rec( 18, 8, sourceOriginateTime ),
		rec( 26, 8, targetReceiveTime ),
		rec( 34, 8, targetTransmitTime ),
		rec( 42, 8, sourceReturnTime ),
		rec( 50, 8, eventOffset ),
		rec( 58, 4, eventTime ),
		rec( 62, (1,50), ServerNameLen ),
	], info_str=(ServerNameLen, "Timesync Exchange Time: %s", ", %s"))
	pkt.Reply((64,113), [
		rec( 8, 3, Reserved3 ),
		rec( 11, 4, protocolFlags ),
		rec( 15, 4, nodeFlags ),
		rec( 19, 8, sourceOriginateTime ),
		rec( 27, 8, targetReceiveTime ),
		rec( 35, 8, targetTransmitTime ),
		rec( 43, 8, sourceReturnTime ),
		rec( 51, 8, eventOffset ),
		rec( 59, 4, eventTime ),
		rec( 63, (1,50), ServerNameLen ),
	])
	pkt.CompletionCodes([0x0000, 0x7e00, 0xfb06, 0xff00])
	# 2222/7205, 114/05
	pkt = NCP(0x7205, "Timesync Get Server List", 'file')
	pkt.Request(14, [
		rec( 10, 4, StartNumber ),
	])
	pkt.Reply(66, [
		rec( 8, 4, nameType ),
		rec( 12, 48, ServerName ),
		rec( 60, 4, serverListFlags ),
		rec( 64, 2, startNumberFlag ),
	])
	pkt.CompletionCodes([0x0000, 0x7e00, 0xfb06, 0xff00])
	# 2222/7206, 114/06
	pkt = NCP(0x7206, "Timesync Set Server List", 'file')
	pkt.Request(14, [
		rec( 10, 4, StartNumber ),
	])
	pkt.Reply(66, [
		rec( 8, 4, nameType ),
		rec( 12, 48, ServerName ),
		rec( 60, 4, serverListFlags ),
		rec( 64, 2, startNumberFlag ),
	])
	pkt.CompletionCodes([0x0000, 0x7e00, 0xfb06, 0xff00])
	# 2222/720C, 114/12
	pkt = NCP(0x720C, "Timesync Get Version", 'file')
	pkt.Request(10)
	pkt.Reply(12, [
		rec( 8, 4, version ),
	])
	pkt.CompletionCodes([0x0000, 0x7e00, 0xfb06, 0xff00])
	# 2222/7B01, 123/01
	pkt = NCP(0x7B01, "Get Cache Information", 'stats')
	pkt.Request(12, [
		rec(10, 1, VersionNumber),
		rec(11, 1, RevisionNumber),
	])
	pkt.Reply(288, [
		rec(8, 4, CurrentServerTime, LE),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
		rec(16, 104, Counters ),
		rec(120, 40, ExtraCacheCntrs ),
		rec(160, 40, MemoryCounters ),
		rec(200, 48, TrendCounters ),
		rec(248, 40, CacheInfo ),
	])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xff00])
	# 2222/7B02, 123/02
	pkt = NCP(0x7B02, "Get File Server Information", 'stats')
	pkt.Request(10)
	pkt.Reply(150, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
		rec(16, 4, NCPStaInUseCnt ),
		rec(20, 4, NCPPeakStaInUse ),
		rec(24, 4, NumOfNCPReqs ),
		rec(28, 4, ServerUtilization ),
		rec(32, 96, ServerInfo ),
		rec(128, 22, FileServerCounters ),
	])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B03, 123/03
	pkt = NCP(0x7B03, "NetWare File System Information", 'stats')
	pkt.Request(11, [
		rec(10, 1, FileSystemID ),
	])
	pkt.Reply(68, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
		rec(16, 52, FileSystemInfo ),
	])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B04, 123/04
	pkt = NCP(0x7B04, "User Information", 'stats')
	pkt.Request(14, [
		rec(10, 4, ConnectionNumber ),
	])
	pkt.Reply((85, 132), [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
		rec(16, 68, UserInformation ),
		rec(84, (1, 48), UserName ),
	])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B05, 123/05
	pkt = NCP(0x7B05, "Packet Burst Information", 'stats')
	pkt.Request(10)
	pkt.Reply(216, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
		rec(16, 200, PacketBurstInformation ),
	])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B06, 123/06
	pkt = NCP(0x7B06, "IPX SPX Information", 'stats')
	pkt.Request(10)
	pkt.Reply(94, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
		rec(16, 34, IPXInformation ),
		rec(50, 44, SPXInformation ),
	])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B07, 123/07
	pkt = NCP(0x7B07, "Garbage Collection Information", 'stats')
	pkt.Request(10)
	pkt.Reply(40, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
		rec(16, 4, FailedAllocReqCnt ),
		rec(20, 4, NumberOfAllocs ),
		rec(24, 4, NoMoreMemAvlCnt ),
		rec(28, 4, NumOfGarbageColl ),
		rec(32, 4, FoundSomeMem ),
		rec(36, 4, NumOfChecks ),
	])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B08, 123/08
	pkt = NCP(0x7B08, "CPU Information", 'stats')
	pkt.Request(14, [
		rec(10, 4, CPUNumber ),
	])
	pkt.Reply(51, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
		rec(16, 4, NumberOfCPUs ),
		rec(20, 31, CPUInformation ),
	])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B09, 123/09
	pkt = NCP(0x7B09, "Volume Switch Information", 'stats')
	pkt.Request(14, [
		rec(10, 4, StartNumber )
	])
	pkt.Reply(28, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
		rec(16, 4, TotalLFSCounters ),
		rec(20, 4, CurrentLFSCounters, var="x"),
		rec(24, 4, LFSCounters, repeat="x"),
	])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B0A, 123/10
	pkt = NCP(0x7B0A, "Get NLM Loaded List", 'stats')
	pkt.Request(14, [
		rec(10, 4, StartNumber )
	])
	pkt.Reply(28, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
		rec(16, 4, NLMcount ),
		rec(20, 4, NLMsInList, var="x" ),
		rec(24, 4, NLMNumbers, repeat="x" ),
	])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B0B, 123/11
	pkt = NCP(0x7B0B, "NLM Information", 'stats')
	pkt.Request(14, [
		rec(10, 4, NLMNumber ),
        ])
	pkt.Reply((79,841), [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
		rec(16, 60, NLMInformation ),
		rec(76, (1,255), FileName ),
		rec(-1, (1,255), Name ),
		rec(-1, (1,255), Copyright ),
	])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B0C, 123/12
	pkt = NCP(0x7B0C, "Get Directory Cache Information", 'stats')
	pkt.Request(10)
	pkt.Reply(72, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
		rec(16, 56, DirCacheInfo ),
	])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B0D, 123/13
	pkt = NCP(0x7B0D, "Get Operating System Version Information", 'stats')
	pkt.Request(10)
	pkt.Reply(70, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
		rec(16, 1, OSMajorVersion ),
		rec(17, 1, OSMinorVersion ),
		rec(18, 1, OSRevision ),
		rec(19, 1, AccountVersion ),
		rec(20, 1, VAPVersion ),
		rec(21, 1, QueueingVersion ),
		rec(22, 1, SecurityRestrictionVersion ),
		rec(23, 1, InternetBridgeVersion ),
		rec(24, 4, MaxNumOfVol ),
		rec(28, 4, MaxNumOfConn ),
		rec(32, 4, MaxNumOfUsers ),
		rec(36, 4, MaxNumOfNmeSps ),
		rec(40, 4, MaxNumOfLANS ),
		rec(44, 4, MaxNumOfMedias ),
		rec(48, 4, MaxNumOfStacks ),
		rec(52, 4, MaxDirDepth ),
		rec(56, 4, MaxDataStreams ),
		rec(60, 4, MaxNumOfSpoolPr ),
		rec(64, 4, ServerSerialNumber ),
		rec(68, 2, ServerAppNumber ),
	])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B0E, 123/14
	pkt = NCP(0x7B0E, "Get Active Connection List by Type", 'stats')
	pkt.Request(15, [
		rec(10, 4, StartConnNumber ),
		rec(14, 1, ConnectionType ),
	])
	pkt.Reply(528, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
		rec(16, 512, ActiveConnBitList ),
	])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfd01, 0xff00])
	# 2222/7B0F, 123/15
	pkt = NCP(0x7B0F, "Get NLM Resource Tag List", 'stats')
	pkt.Request(18, [
                rec(10, 4, NLMNumber ),
                rec(14, 4, NLMStartNumber ),
        ])
	pkt.Reply(37, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, TtlNumOfRTags ),
                rec(20, 4, CurNumOfRTags ),
                rec(24, 13, RTagStructure ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B10, 123/16
	pkt = NCP(0x7B10, "Enumerate Connection Information from Connection List", 'stats')
	pkt.Request(22, [
                rec(10, 1, EnumInfoMask),
                rec(11, 3, Reserved3),
                rec(14, 4, itemsInList, var="x"),
                rec(18, 4, connList, repeat="x"),
        ])
	pkt.Reply(NO_LENGTH_CHECK, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, ItemsInPacket ),
                srec(netAddr, req_cond="ncp.enum_info_transport==TRUE"),
                srec(timeInfo, req_cond="ncp.enum_info_time==TRUE"),
                srec(nameInfo, req_cond="ncp.enum_info_name==TRUE"),
                srec(lockInfo, req_cond="ncp.enum_info_lock==TRUE"),
                srec(printInfo, req_cond="ncp.enum_info_print==TRUE"),
                srec(statsInfo, req_cond="ncp.enum_info_stats==TRUE"),
                srec(acctngInfo, req_cond="ncp.enum_info_account==TRUE"),
                srec(authInfo, req_cond="ncp.enum_info_auth==TRUE"),
        ])
        pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B11, 123/17
	pkt = NCP(0x7B11, "Enumerate NCP Service Network Addresses", 'stats')
	pkt.Request(14, [
                rec(10, 4, SearchNumber ),
        ])
	pkt.Reply(60, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, ServerInfoFlags ),
                rec(16, 16, GUID ),
                rec(32, 4, NextSearchNum ),
                rec(36, 4, ItemsInPacket, var="x"),
                rec(40, 20, NCPNetworkAddress, repeat="x" ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb01, 0xff00])
	# 2222/7B14, 123/20
	pkt = NCP(0x7B14, "Active LAN Board List", 'stats')
	pkt.Request(14, [
                rec(10, 4, StartNumber ),
        ])
	pkt.Reply(28, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, MaxNumOfLANS ),
                rec(20, 4, ItemsInPacket, var="x"),
                rec(24, 4, BoardNumbers, repeat="x"),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B15, 123/21
	pkt = NCP(0x7B15, "LAN Configuration Information", 'stats')
	pkt.Request(14, [
                rec(10, 4, BoardNumber ),
        ])
	pkt.Reply(152, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16,136, LANConfigInfo ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B16, 123/22
	pkt = NCP(0x7B16, "LAN Common Counters Information", 'stats')
	pkt.Request(18, [
                rec(10, 4, BoardNumber ),
                rec(14, 4, BlockNumber ),
        ])
	pkt.Reply(86, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 1, StatMajorVersion ),
                rec(15, 1, StatMinorVersion ),
                rec(16, 4, TotalCommonCnts ),
                rec(20, 4, TotalCntBlocks ),
                rec(24, 4, CustomCounters ),
                rec(28, 4, NextCntBlock ),
                rec(32, 54, CommonLanStruc ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B17, 123/23
	pkt = NCP(0x7B17, "LAN Custom Counters Information", 'stats')
	pkt.Request(18, [
                rec(10, 4, BoardNumber ),
                rec(14, 4, StartNumber ),
        ])
	pkt.Reply(25, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, NumOfCCinPkt, var="x"),
                rec(20, 5, CustomCntsInfo, repeat="x"),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B18, 123/24
	pkt = NCP(0x7B18, "LAN Name Information", 'stats')
	pkt.Request(14, [
                rec(10, 4, BoardNumber ),
        ])
	pkt.Reply(19, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 3, BoardNameStruct ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B19, 123/25
	pkt = NCP(0x7B19, "LSL Information", 'stats')
	pkt.Request(10)
	pkt.Reply(90, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 74, LSLInformation ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B1A, 123/26
	pkt = NCP(0x7B1A, "LSL Logical Board Statistics", 'stats')
	pkt.Request(14, [
                rec(10, 4, BoardNumber ),
        ])
	pkt.Reply(28, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, LogTtlTxPkts ),
                rec(20, 4, LogTtlRxPkts ),
                rec(24, 4, UnclaimedPkts ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B1B, 123/27
	pkt = NCP(0x7B1B, "MLID Board Information", 'stats')
	pkt.Request(14, [
                rec(10, 4, BoardNumber ),
        ])
	pkt.Reply(44, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 1, Reserved ),
                rec(15, 1, NumberOfProtocols ),
                rec(16, 28, MLIDBoardInfo ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B1E, 123/30
	pkt = NCP(0x7B1E, "Get Media Manager Object Information", 'stats')
	pkt.Request(14, [
                rec(10, 4, ObjectNumber ),
        ])
	pkt.Reply(212, [
        	rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 196, GenericInfoDef ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B1F, 123/31
	pkt = NCP(0x7B1F, "Get Media Manager Objects List", 'stats')
	pkt.Request(15, [
                rec(10, 4, StartNumber ),
                rec(14, 1, MediaObjectType ),
        ])
	pkt.Reply(28, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, nextStartingNumber ),
                rec(20, 4, ObjectCount, var="x"),
                rec(24, 4, ObjectID, repeat="x"),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B20, 123/32
	pkt = NCP(0x7B20, "Get Media Manager Object Childrens List", 'stats')
	pkt.Request(22, [
                rec(10, 4, StartNumber ),
                rec(14, 1, MediaObjectType ),
                rec(15, 3, Reserved3 ),
                rec(18, 4, ParentObjectNumber ),
        ])
	pkt.Reply(28, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, nextStartingNumber ),
                rec(20, 4, ObjectCount, var="x" ),
                rec(24, 4, ObjectID, repeat="x" ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B21, 123/33
	pkt = NCP(0x7B21, "Get Volume Segment List", 'stats')
	pkt.Request(14, [
                rec(10, 4, VolumeNumberLong ),
        ])
	pkt.Reply(32, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, NumOfSegments, var="x" ),
                rec(20, 12, Segments, repeat="x" ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B22, 123/34
	pkt = NCP(0x7B22, "Get Volume Information by Level", 'stats')
	pkt.Request(15, [
                rec(10, 4, VolumeNumberLong ),
                rec(14, 1, InfoLevelNumber ),
        ])
	pkt.Reply(NO_LENGTH_CHECK, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 1, InfoLevelNumber ),
                rec(17, 3, Reserved3 ),
                srec(VolInfoStructure, req_cond="ncp.info_level_num==0x01"),
                srec(VolInfo2Struct, req_cond="ncp.info_level_num==0x02"),
        ])
        pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B28, 123/40
	pkt = NCP(0x7B28, "Active Protocol Stacks", 'stats')
	pkt.Request(14, [
                rec(10, 4, StartNumber ),
        ])
	pkt.Reply(48, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, MaxNumOfLANS ),
                rec(20, 4, StackCount, var="x" ),
                rec(24, 4, nextStartingNumber ),
                rec(28, 20, StackInfo, repeat="x" ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B29, 123/41
	pkt = NCP(0x7B29, "Get Protocol Stack Configuration Information", 'stats')
	pkt.Request(14, [
                rec(10, 4, StackNumber ),
        ])
	pkt.Reply((37,164), [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 1, ConfigMajorVN ),
                rec(17, 1, ConfigMinorVN ),
                rec(18, 1, StackMajorVN ),
                rec(19, 1, StackMinorVN ),
                rec(20, 16, ShortStkName ),
                rec(36, (1,128), StackFullNameStr ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B2A, 123/42
	pkt = NCP(0x7B2A, "Get Protocol Stack Statistics Information", 'stats')
	pkt.Request(14, [
                rec(10, 4, StackNumber ),
        ])
	pkt.Reply(38, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 1, StatMajorVersion ),
                rec(17, 1, StatMinorVersion ),
                rec(18, 2, ComCnts ),
                rec(20, 4, CounterMask ),
                rec(24, 4, TotalTxPkts ),
                rec(28, 4, TotalRxPkts ),
                rec(32, 4, IgnoredRxPkts ),
                rec(36, 2, CustomCnts ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B2B, 123/43
	pkt = NCP(0x7B2B, "Get Protocol Stack Custom Information", 'stats')
	pkt.Request(18, [
                rec(10, 4, StackNumber ),
                rec(14, 4, StartNumber ),
        ])
	pkt.Reply(25, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, CustomCount, var="x" ),
                rec(20, 5, CustomCntsInfo, repeat="x" ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B2C, 123/44
	pkt = NCP(0x7B2C, "Get Protocol Stack Numbers by Media Number", 'stats')
	pkt.Request(14, [
                rec(10, 4, MediaNumber ),
        ])
	pkt.Reply(24, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, StackCount, var="x" ),
                rec(20, 4, StackNumber, repeat="x" ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B2D, 123/45
	pkt = NCP(0x7B2D, "Get Protocol Stack Numbers by LAN Board Number", 'stats')
	pkt.Request(14, [
                rec(10, 4, BoardNumber ),
        ])
	pkt.Reply(24, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, StackCount, var="x" ),
                rec(20, 4, StackNumber, repeat="x" ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B2E, 123/46
	pkt = NCP(0x7B2E, "Get Media Name by Media Number", 'stats')
	pkt.Request(14, [
                rec(10, 4, MediaNumber ),
        ])
	pkt.Reply((17,144), [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, (1,128), MediaName ),
        ])
	pkt.CompletionCodes([0x0000, 0x7900, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B2F, 123/47
	pkt = NCP(0x7B2F, "Get Loaded Media Number", 'stats')
	pkt.Request(10)
	pkt.Reply(28, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, MaxNumOfMedias ),
                rec(20, 4, MediaListCount, var="x" ),
                rec(24, 4, MediaList, repeat="x" ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B32, 123/50
	pkt = NCP(0x7B32, "Get General Router and SAP Information", 'stats')
	pkt.Request(10)
	pkt.Reply(37, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 2, RIPSocketNumber ),
                rec(18, 2, Reserved2 ),
                rec(20, 1, RouterDownFlag ),
                rec(21, 3, Reserved3 ),
                rec(24, 1, TrackOnFlag ),
                rec(25, 3, Reserved3 ),
                rec(28, 1, ExtRouterActiveFlag ),
                rec(29, 3, Reserved3 ),
                rec(32, 2, SAPSocketNumber ),
                rec(34, 2, Reserved2 ),
                rec(36, 1, RpyNearestSrvFlag ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B33, 123/51
	pkt = NCP(0x7B33, "Get Network Router Information", 'stats')
	pkt.Request(14, [
                rec(10, 4, NetworkNumber ),
        ])
	pkt.Reply(26, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 10, KnownRoutes ),
        ])
	pkt.CompletionCodes([0x0000, 0x0108, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B34, 123/52
	pkt = NCP(0x7B34, "Get Network Routers Information", 'stats')
	pkt.Request(18, [
                rec(10, 4, NetworkNumber),
                rec(14, 4, StartNumber ),
        ])
	pkt.Reply(34, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, NumOfEntries, var="x" ),
                rec(20, 14, RoutersInfo, repeat="x" ),
        ])
	pkt.CompletionCodes([0x0000, 0x0108, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B35, 123/53
	pkt = NCP(0x7B35, "Get Known Networks Information", 'stats')
	pkt.Request(14, [
                rec(10, 4, StartNumber ),
        ])
	pkt.Reply(30, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, NumOfEntries, var="x" ),
                rec(20, 10, KnownRoutes, repeat="x" ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B36, 123/54
	pkt = NCP(0x7B36, "Get Server Information", 'stats')
	pkt.Request((15,64), [
                rec(10, 2, ServerType ),
                rec(12, 2, Reserved2 ),
                rec(14, (1,50), ServerNameLen ),
        ], info_str=(ServerNameLen, "Get Server Information: %s", ", %s"))
	pkt.Reply(30, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 12, ServerAddress ),
                rec(28, 2, HopsToNet ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B37, 123/55
	pkt = NCP(0x7B37, "Get Server Sources Information", 'stats')
	pkt.Request((19,68), [
                rec(10, 4, StartNumber ),
                rec(14, 2, ServerType ),
                rec(16, 2, Reserved2 ),
                rec(18, (1,50), ServerNameLen ),
        ], info_str=(ServerNameLen, "Get Server Sources Info: %s", ", %s"))
	pkt.Reply(32, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, NumOfEntries, var="x" ),
                rec(20, 12, ServersSrcInfo, repeat="x" ),
        ])
	pkt.CompletionCodes([0x0000, 0x0108, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B38, 123/56
	pkt = NCP(0x7B38, "Get Known Servers Information", 'stats')
	pkt.Request(16, [
                rec(10, 4, StartNumber ),
                rec(14, 2, ServerType ),
        ])
	pkt.Reply(35, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, NumOfEntries, var="x" ),
                rec(20, 15, KnownServStruc, repeat="x" ),
        ])
	pkt.CompletionCodes([0x0000, 0x0108, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B3C, 123/60
	pkt = NCP(0x7B3C, "Get Server Set Commands Information", 'stats')
	pkt.Request(14, [
                rec(10, 4, StartNumber ),
        ])
	pkt.Reply(NO_LENGTH_CHECK, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, TtlNumOfSetCmds ),
                rec(20, 4, nextStartingNumber ),
                rec(24, 1, SetCmdType ),
                rec(25, 3, Reserved3 ),
                rec(28, 1, SetCmdCategory ),
                rec(29, 3, Reserved3 ),
                rec(32, 1, SetCmdFlags ),
                rec(33, 3, Reserved3 ),
                rec(36, 100, SetCmdName ),
                rec(136, 4, SetCmdValueNum ),
        ])                
        pkt.ReqCondSizeVariable()
	pkt.CompletionCodes([0x0000, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B3D, 123/61
	pkt = NCP(0x7B3D, "Get Server Set Categories", 'stats')
	pkt.Request(14, [
                rec(10, 4, StartNumber ),
        ])
	pkt.Reply(NO_LENGTH_CHECK, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
                rec(16, 4, NumberOfSetCategories ),
                rec(20, 4, nextStartingNumber ),
                rec(24, PROTO_LENGTH_UNKNOWN, CategoryName ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B3E, 123/62
	pkt = NCP(0x7B3E, "Get Server Set Commands Information By Name", 'stats')
	pkt.Request(NO_LENGTH_CHECK, [
                rec(10, PROTO_LENGTH_UNKNOWN, SetParmName ),
        ], info_str=(SetParmName, "Get Server Set Command Info for: %s", ", %s"))
	pkt.Reply(NO_LENGTH_CHECK, [
		rec(8, 4, CurrentServerTime ),
		rec(12, 1, VConsoleVersion ),
		rec(13, 1, VConsoleRevision ),
		rec(14, 2, Reserved2 ),
        rec(16, 4, TtlNumOfSetCmds ),
        rec(20, 4, nextStartingNumber ),
        rec(24, 1, SetCmdType ),
        rec(25, 3, Reserved3 ),
        rec(28, 1, SetCmdCategory ),
        rec(29, 3, Reserved3 ),
        rec(32, 1, SetCmdFlags ),
        rec(33, 3, Reserved3 ),
        rec(36, PROTO_LENGTH_UNKNOWN, SetCmdName ),
                #rec(136, 4, SetCmdValueNum ),
        ])                
        pkt.ReqCondSizeVariable()
        pkt.CompletionCodes([0x0000, 0x7e01, 0xfb06, 0xff00])
	# 2222/7B46, 123/70
	pkt = NCP(0x7B46, "Get Current Compressing File", 'stats')
	pkt.Request(14, [
                rec(10, 4, VolumeNumberLong ),
        ])
	pkt.Reply(56, [
                rec(8, 4, ParentID ),
		rec(12, 4, DirectoryEntryNumber ),
		rec(16, 4, compressionStage ),
		rec(20, 4, ttlIntermediateBlks ),
                rec(24, 4, ttlCompBlks ),
                rec(28, 4, curIntermediateBlks ),
                rec(32, 4, curCompBlks ),
                rec(36, 4, curInitialBlks ),
                rec(40, 4, fileFlags ),
                rec(44, 4, projectedCompSize ),
                rec(48, 4, originalSize ),
                rec(52, 4, compressVolume ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e00, 0x7901, 0xfb06, 0xff00])
	# 2222/7B47, 123/71
	pkt = NCP(0x7B47, "Get Current DeCompressing File Info List", 'stats')
	pkt.Request(14, [
                rec(10, 4, VolumeNumberLong ),
        ])
	pkt.Reply(28, [
		rec(8, 4, FileListCount ),
		rec(12, 16, FileInfoStruct ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e00, 0xfb06, 0xff00])
	# 2222/7B48, 123/72
	pkt = NCP(0x7B48, "Get Compression and Decompression Time and Counts", 'stats')
	pkt.Request(14, [
                rec(10, 4, VolumeNumberLong ),
        ])
	pkt.Reply(64, [
		rec(8, 56, CompDeCompStat ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e00, 0xfb06, 0xff00])
	# 2222/8301, 131/01
	pkt = NCP(0x8301, "RPC Load an NLM", 'fileserver')
	pkt.Request(NO_LENGTH_CHECK, [
                rec(10, 4, NLMLoadOptions ),
                rec(14, 16, Reserved16 ),
                rec(30, PROTO_LENGTH_UNKNOWN, PathAndName ),
        ], info_str=(PathAndName, "RPC Load NLM: %s", ", %s"))
	pkt.Reply(12, [
                rec(8, 4, RPCccode ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e00, 0xfb07, 0xff00])
	# 2222/8302, 131/02
	pkt = NCP(0x8302, "RPC Unload an NLM", 'fileserver')
	pkt.Request(NO_LENGTH_CHECK, [
                rec(10, 20, Reserved20 ),
                rec(30, PROTO_LENGTH_UNKNOWN, NLMName ),
        ], info_str=(NLMName, "RPC Unload NLM: %s", ", %s"))
	pkt.Reply(12, [
                rec(8, 4, RPCccode ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e00, 0xfb07, 0xff00])
	# 2222/8303, 131/03
	pkt = NCP(0x8303, "RPC Mount Volume", 'fileserver')
	pkt.Request(NO_LENGTH_CHECK, [
                rec(10, 20, Reserved20 ),
                rec(30, PROTO_LENGTH_UNKNOWN, VolumeNameStringz ),
        ], info_str=(VolumeNameStringz, "RPC Mount Volume: %s", ", %s"))
	pkt.Reply(32, [
                rec(8, 4, RPCccode),
                rec(12, 16, Reserved16 ),
                rec(28, 4, VolumeNumberLong ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e00, 0xfb07, 0xff00])
	# 2222/8304, 131/04
	pkt = NCP(0x8304, "RPC Dismount Volume", 'fileserver')
	pkt.Request(NO_LENGTH_CHECK, [
                rec(10, 20, Reserved20 ),
                rec(30, PROTO_LENGTH_UNKNOWN, VolumeNameStringz ),
        ], info_str=(VolumeNameStringz, "RPC Dismount Volume: %s", ", %s"))
	pkt.Reply(12, [
                rec(8, 4, RPCccode ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e00, 0xfb07, 0xff00])
	# 2222/8305, 131/05
	pkt = NCP(0x8305, "RPC Add Name Space To Volume", 'fileserver')
	pkt.Request(NO_LENGTH_CHECK, [
                rec(10, 20, Reserved20 ),
                rec(30, PROTO_LENGTH_UNKNOWN, AddNameSpaceAndVol ),
        ], info_str=(AddNameSpaceAndVol, "RPC Add Name Space to Volume: %s", ", %s"))
	pkt.Reply(12, [
                rec(8, 4, RPCccode ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e00, 0xfb07, 0xff00])
	# 2222/8306, 131/06
	pkt = NCP(0x8306, "RPC Set Command Value", 'fileserver')
	pkt.Request(NO_LENGTH_CHECK, [
                rec(10, 1, SetCmdType ),
                rec(11, 3, Reserved3 ),
                rec(14, 4, SetCmdValueNum ),
                rec(18, 12, Reserved12 ),
                rec(30, PROTO_LENGTH_UNKNOWN, SetCmdName ),
		#
		# XXX - optional string, if SetCmdType is 0
		#
        ], info_str=(SetCmdName, "RPC Set Command Value: %s", ", %s"))
	pkt.Reply(12, [
                rec(8, 4, RPCccode ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e00, 0xfb07, 0xff00])
	# 2222/8307, 131/07
	pkt = NCP(0x8307, "RPC Execute NCF File", 'fileserver')
	pkt.Request(NO_LENGTH_CHECK, [
                rec(10, 20, Reserved20 ),
                rec(30, PROTO_LENGTH_UNKNOWN, PathAndName ),
        ], info_str=(PathAndName, "RPC Execute NCF File: %s", ", %s"))
	pkt.Reply(12, [
                rec(8, 4, RPCccode ),
        ])
	pkt.CompletionCodes([0x0000, 0x7e00, 0xfb07, 0xff00])
if __name__ == '__main__':
#	import profile
#	filename = "ncp.pstats"
#	profile.run("main()", filename)
#
#	import pstats
#	sys.stdout = msg
#	p = pstats.Stats(filename)
#
#	print "Stats sorted by cumulative time"
#	p.strip_dirs().sort_stats('cumulative').print_stats()
#
#	print "Function callees"
#	p.print_callees()
	main()
