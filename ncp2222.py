#!/usr/bin/env python

"""
Creates C code from a table of NCP type 0x2222 packet types.
(And 0x3333, which are the replies, but the packets are more commonly
refered to as type 0x2222; the 0x3333 replies are understood to be
part of the 0x2222 "family")

The data-munging code was written by Gilbert Ramirez.
Most of the NCP data, and all of the testing, comes from
Greg Morris <GMORRIS@novell.com>. Many thanks to Novell for letting
him work on this.

Additional data comes from "Programmer's Guide to the NetWare Core Protocol"
by Steve Conner and Dianne Conner.

Novell provides info at:

http://developer.novell.com/ndk  (where you can download an *.exe file which
installs a PDF)

or

http://developer.novell.com/ndk/doc/docui/index.htm#../ncp/ncp__enu/data/
for a badly-formatted HTML version of the same PDF.


$Id: ncp2222.py,v 1.14.2.1 2002/02/16 16:28:57 gram Exp $

Copyright (c) 2000-2002 by Gilbert Ramirez <gram@alumni.rice.edu>
and Greg Morris <GMORRIS@novell.com>.

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
packets		= None
compcode_lists	= None
ptvc_lists	= None
msg		= None
	
	
REC_START	= 0
REC_LENGTH	= 1
REC_FIELD	= 2
REC_ENDIANNESS	= 3
REC_VAR		= 4
REC_REPEAT	= 5

NO_VAR		= -1
NO_REPEAT	= -1

global_highest_var = -1

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

	def Add(self, object):
		"""Add an object to the members lists, if a comparable object
		doesn't already exist. The object that is in the member list, that is
		either the object that was added or the comparable object that was
		already in the member list, is returned."""

		# Is 'object' a duplicate of some other member?
		for member in self.members:
			if member == object:
				return member

		# Store object in our members list.
		self.members.append(object)
		return object

	def Members(self):
		"Returns the list of members."
		return self.members

	def HasMember(self, object):
		"Does the list of members contain the object?"
		for member in self.members:
			if member == object:
				return 1
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

		# Python will do a deep comparison of lists within lists.
		if self.list < other.list:
			return -1
		elif self.list > other.list:
			return 1
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

			var_name = record[REC_VAR]
			if var_name:
				# Did we already define this var?
				if named_vars.has_key(var_name):
					sys.exit("%s has multiple %s vars." % \
						(name, var_name))

				highest_var = highest_var + 1
				var = highest_var
				global_highest_var = highest_var
				named_vars[var_name] = var
			else:
				var = NO_VAR

			repeat_name = record[REC_REPEAT]
			if repeat_name:
				# Do we have this var?
				if not named_vars.has_key(repeat_name):
					sys.exit("%s does not have %s var defined." % \
						(name, var_name))
				repeat = named_vars[repeat_name]
			else:
				repeat = NO_REPEAT

			ptvc_rec = PTVCRecord(field, length, endianness, var, repeat)

			if expected_offset == None:
				expected_offset = offset

			elif expected_offset == -1:
				pass

			elif expected_offset != offset:
				sys.stderr.write("Expected offset in %s to be %d\n" % (name,
					expected_offset))
				sys.exit(1)

			# We can't make a PTVC list from a variable-length
			# packet, unless it's FT_UINT_STRING
			if type(ptvc_rec.Length()) == type(()):
				if isinstance(ptvc_rec.Field(), nstring8):
					expected_offset = -1
					pass
				else:
					self.list = None
					return

			elif expected_offset > -1:
				expected_offset = expected_offset + ptvc_rec.Length()


			self.list.append(ptvc_rec)

	def Code(self):
		x =  "static const ptvc_record %s[] = {\n" % (self.Name())
		for ptvc_rec in self.list:
			x = x +  "\t%s,\n" % (ptvc_rec.Code())
		x = x + "\t{ NULL, 0, FALSE, NULL, NO_VAR, NO_REPEAT }\n"
		x = x + "};\n"
		return x


class PTVCBitfield(PTVC):
	def __init__(self, name, vars):
		NamedList.__init__(self, name, [])

		for var in vars:
			ptvc_rec = PTVCRecord(var, var.Length(), var.Endianness(),
				NO_VAR, NO_REPEAT)
			self.list.append(ptvc_rec)

	def ETTName(self):
		return "ett_%s" % (self.Name(),)

	def Code(self):
		ett_name = self.ETTName()
		x = "static gint %s;\n" % (ett_name,)

		x = x + "static const ptvc_record ptvc_%s[] = {\n" % (self.Name())
		for ptvc_rec in self.list:
			x = x +  "\t%s,\n" % (ptvc_rec.Code())
		x = x + "\t{ NULL, 0, FALSE, NULL, NO_VAR, NO_REPEAT }\n"
		x = x + "};\n"

		x = x + "static const sub_ptvc_record %s = {\n" % (self.Name(),)
		x = x + "\t&%s,\n" % (ett_name,)
		x = x + "\tptvc_%s,\n" % (self.Name(),)
		x = x + "};\n"
		return x


class PTVCRecord:
	def __init__(self, field, length, endianness, var, repeat):
		"Constructor"
		self.field	= field
		self.length	= length
		self.endianness	= endianness
		self.var	= var
		self.repeat	= repeat

	def __cmp__(self, other):
		"Comparison operator"
		if self.length < other.length:
			return -1
		elif self.length > other.length:
			return 1

		if self.field != other.field:
			return 1
		elif self.endianness != other.endianness:
			return 1
		else:
			return 0

	def Code(self):
		if isinstance(self.field, struct):
			return self.field.ReferenceString()
		else:
			return self.RegularCode()

	def RegularCode(self):
		"String representation"
		endianness = 'FALSE'
		if self.endianness == LE:
			endianness = 'TRUE'

		# Default the length to this value
		length = "PTVC_VARIABLE_LENGTH"

		if type(self.length) == type(0):
			length = self.length
		else:
			var_length = self.field.Length()
			if var_length > 0:
				length = var_length

		sub_ptvc_name = self.field.PTVCName()
		if sub_ptvc_name != "NULL":
			sub_ptvc_name = "&%s" % (sub_ptvc_name,)

		# Nice textual representations
		if self.var == NO_VAR:
			var = "NO_VAR"
		else:
			var = self.var

		if self.repeat == NO_REPEAT:
			repeat = "NO_REPEAT"
		else:
			repeat = self.repeat

		return "{ &%s, %s, %s, %s, %s, %s }" % (self.field.HFName(),
				length, endianness, sub_ptvc_name,
				var, repeat)

	def Offset(self):
		return self.offset

	def Length(self):
		return self.length

	def Field(self):
		return self.field

	def __repr__(self):
		return "{%s, %s, %s}" % (self.field, self.length, self.endianness)

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

		if not groups.has_key(group):
			sys.stderr.write("NCP 0x%x has invalid group '%s'\n" % \
				(self.func_code, group))
			sys.exit(1)

		if self.HasSubFunction():
			# NCP Function with SubFunction
			self.start_offset = 10
		else:
			# Simple NCP Function
			self.start_offset = 7

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
			sys.stderr.write("Unknown directive '%s' for function_code()\n" % (part))
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

	def Request(self, size, records=[]):
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

	def Reply(self, size, records=[]):
		self.reply_size = size
		self.reply_records = records
		self.CheckRecords(size, records, "Reply", 8)
		self.ptvc_reply = self.MakePTVC(records, "reply")

	def CheckRecords(self, size, records, descr, min_hdr_length):
		"Simple sanity check"
		min = size
		max = size
		if type(size) == type(()):
			min = size[0]
			max = size[1]

		lower = min_hdr_length
		upper = min_hdr_length

		for record in records:
			rec_size = record[1]
			rec_lower = rec_size
			rec_upper = rec_size
			if type(rec_size) == type(()):
				rec_lower = rec_size[0]
				rec_upper = rec_size[1]

			lower = lower + rec_lower
			upper = upper + rec_upper

		error = 0
		if min != lower:
			sys.stderr.write("%s records for 2222/0x%x sum to %d bytes minimum, but param1 shows %d\n" \
				% (descr, self.FunctionCode(), lower, min))
			error = 1
		if max != upper:
			sys.stderr.write("%s records for 2222/0x%x sum to %d bytes maximum, but param1 shows %d\n" \
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

	def Variables(self):
		"""Returns a list of variables used in the request and reply records.
		A variable is listed only once, even if it is used twice (once in
		the request, once in the reply)."""

		variables = {}
		if self.request_records:
			for record in self.request_records:
				var = record[2]
				variables[repr(var)] = var

				sub_vars = var.SubVariables()
				for sv in sub_vars:
					variables[repr(sv)] = sv

		if self.reply_records:
			for record in self.reply_records:
				var = record[2]
				variables[repr(var)] = var

				sub_vars = var.SubVariables()
				for sv in sub_vars:
					variables[repr(sv)] = sv

		return variables.values()


	def CompletionCodes(self, codes=None):
		"""Sets or returns the list of completion codes. Internally, a NamedList
		is used to store the completion codes, but the caller of this function
		never realizes that because Python lists are the input and output."""

		if codes == None:
			return self.codes

		# Sanity check
		okay = 1
		for code in codes:
			if not errors.has_key(code):
				sys.stderr.write("Errors table does not have key 0x%04x for NCP=0x%x\n" % (code,
					self.func_code))
				okay = 0

		# Delay the exit until here so that the programmer can get the complete
		# list of missing error codes
		if not okay:
			sys.exit(1)

		# Create CompletionCode (NamedList) object and possible add it to
		# the global list of completion code lists.
		name = "%s_errors" % (self.CName())
		codes.sort()
		codes_list = NamedList(name, codes)
		self.codes = compcode_lists.Add(codes_list)

		self.Finalize()

	def Finalize(self):
		"""Adds the NCP object to the global collection of NCP objects. This
		is done automatically after setting the CompletionCode list. Yes, this
		is a shortcut, but it makes our list of NCP packet definitions look
		neater, since an explicit "add to global list of packets" is not needed."""

		# Add packet to global collection of packets
		if packets.HasMember(self):
			sys.stderr.write("Already have NCP Function Code 0x%x\n" % \
				(self.func_code))
			sys.exit(1)
		else:
			packets.Add(self)


def rec(start, length, field, endianness=None, **kw):
	# If endianness not explicitly given, use the field's
	# default endiannes.
	if not endianness:
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

	return [start, length, field, endianness, var, repeat]

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

	def Length(self):
		return self.bytes

	def Abbreviation(self):
		return self.abbrev

	def Description(self):
		return self.descr

	def HFName(self):
		return "hf_ncp_" + self.abbrev

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


class struct(PTVC, Type):
	def __init__(self, name, vars):
		name = "struct_%s" % (name,)
		NamedList.__init__(self, name, [])

		for var in vars:
			ptvc_rec = PTVCRecord(var, var.Length(), var.Endianness(),
				NO_VAR, NO_REPEAT)
			self.list.append(ptvc_rec)

	def Variables(self):
		vars = []
		for ptvc_rec in self.list:
			vars.append(ptvc_rec.Field())
		return vars

	def ReferenceString(self):
		return "{ PTVC_STRUCT, -1, FALSE, &%s, NO_VAR, NO_REPEAT }" % (self.name,)

	def Code(self):
		x = "static const ptvc_record ptvc_%s[] = {\n" % (self.name,)
		for ptvc_rec in self.list:
			x = x +  "\t%s,\n" % (ptvc_rec.Code())
		x = x + "\t{ NULL, 0, FALSE, NULL, NO_VAR, NO_REPEAT }\n"
		x = x + "};\n"

		x = x + "static const sub_ptvc_record %s = {\n" % (self.name,)
		x = x + "\tNULL,\n"
		x = x + "\tptvc_%s,\n" % (self.Name(),)
		x = x + "};\n"
		return x


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

class boolean8(uint8):
	type	= "boolean8"
	ftype	= "FT_BOOLEAN"

class uint16(Type, CountingNumber):
	type	= "uint16"
	ftype	= "FT_UINT16"
	def __init__(self, abbrev, descr, endianness = BE):
		Type.__init__(self, abbrev, descr, 2, endianness)

class uint32(Type, CountingNumber):
	type	= "uint32"
	ftype	= "FT_UINT32"
	def __init__(self, abbrev, descr, endianness = BE):
		Type.__init__(self, abbrev, descr, 4, endianness)

class nstring8(Type):
	"""A string of up to 255 characters. The first byte
	gives the string length. Thus, the total length of
	this data structure is from 1 to 256 bytes, including
	the first byte."""

	type	= "nstring8"
	ftype	= "FT_UINT_STRING"
	def __init__(self, abbrev, descr):
		Type.__init__(self, abbrev, descr, 1)

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
		Type.__init__(self, abbrev, descr, -1)

class val_string(Type):
	"""Abstract class for val_stringN, where N is number
	of bits that key takes up."""

	type	= "val_string"
	disp	= 'BASE_HEX'

	def __init__(self, abbrev, descr, val_string_array, endianness = BE):
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

class bytes(Type):
	type	= 'bytes'
	ftype	= 'FT_BYTES'

	def __init__(self, abbrev, descr, bytes):
		Type.__init__(self, abbrev, descr, bytes, NA)


class bitfield(Type):
	type	= "bitfield"
	disp	= 'BASE_HEX'

	def __init__(self, vars):
		var_hash = {}
		for var in vars:
			var_hash[var.bitmask] = var

		bitmasks = var_hash.keys()
		bitmasks.sort()
		bitmasks.reverse()

		ordered_vars = []
		for bitmask in bitmasks:
			var = var_hash[bitmask]
			ordered_vars.append(var)

		self.vars = ordered_vars
		self.sub_ptvc = PTVCBitfield(self.PTVCName(), self.vars)

	def SubVariables(self):
		return self.vars

	def SubVariablesPTVC(self):
		return self.sub_ptvc

	def PTVCName(self):
		return "ncp_%s_bitfield" % (self.abbrev,)

class bitfield8(bitfield, uint8):
	type	= "bitfield8"
	ftype	= "FT_UINT8"

	def __init__(self, abbrev, descr, vars):
		uint8.__init__(self, abbrev, descr)
		bitfield.__init__(self, vars)

class bf_uint(Type):
	type	= "bf_uint"
	disp	= 'BASE_HEX'

	def __init__(self, bitmask, abbrev, descr):
		self.bitmask = bitmask
		self.abbrev = abbrev
		self.descr = descr

	def Mask(self):
		return self.bitmask

class bf_boolean8(bf_uint, boolean8):
	type	= "bf_boolean8"
	ftype	= "FT_BOOLEAN"
	disp	= "8"

#class data(Type):
#	type	= "data"
#	ftype	= "FT_BYTES"
#	def __init__(self, abbrev, descr):
#		Type.__init__(self, abbrev, descr, -1)
#
#	def length_var(self, length_var):
#		self.length_var = length_var

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
AccessRightsHigh 		= bitfield8("access_rights_high", "Access Rights (byte 2)", [
	bf_boolean8(0x01, "acc_rights_supervisor", "Supervisor Access Rights"),
])
AccessRightsMask 		= bitfield8("access_rights_mask", "Access Rights", [
	bf_boolean8(0x01, "acc_rights_read", "Read Rights"),
	bf_boolean8(0x02, "acc_rights_write", "Write Rights"),
	bf_boolean8(0x04, "acc_rights_open", "Open Rights"),
	bf_boolean8(0x08, "acc_rights_create", "Create Rights"),
	bf_boolean8(0x10, "acc_rights_delete", "Delete Rights"),
	bf_boolean8(0x20, "acc_rights_parent", "Parental Rights"),
	bf_boolean8(0x40, "acc_rights_search", "Search Rights"),
	bf_boolean8(0x80, "acc_rights_modify", "Modify Rights"),
])
AccountBalance			= uint32("account_balance", "Account Balance")
AcctVersion			= byte("acct_version", "Acct Version")
ActionFlag 			= bitfield8("action_flag", "Action Flag", [
	bf_boolean8(0x01, "act_flag_open", "Open"),
	bf_boolean8(0x02, "act_flag_replace", "Replace"),
	bf_boolean8(0x10, "act_flag_create", "Create"),
])
ActiveIndexedFiles		= uint16("active_indexed_files", "Active Indexed Files")
ActualMaxBinderyObjects 	= uint16("actual_max_bindery_objects", "Actual Max Bindery Objects")
ActualMaxIndexedFiles		= uint16("actual_max_indexed_files", "Actual Max Indexed Files")
ActualMaxOpenFiles		= uint16("actual_max_open_files", "Actual Max Open Files")
ActualMaxSimultaneousTransactions = uint16("actual_max_sim_trans", "Actual Max Simultaneous Transactions")
ActualMaxUsedDirectoryEntries 	= uint16("actual_max_used_directory_entries", "Actual Max Used Directory Entries")
ActualMaxUsedRoutingBuffers 	= uint16("actual_max_used_routing_buffers", "Actual Max Used Routing Buffers")
ActualResponseCount 		= uint16("actual_response_count", "Actual Response Count")
AFPEntryID			= uint32("afp_entry_id", "AFP Entry ID")
AFPEntryID.Display("BASE_HEX")
AllocateMode			= val_string8("allocate_mode", "Allocate Mode", [
	[ 0x00, "Permanent Directory Handle" ],
	[ 0x01, "Temporary Directory Handle" ],
	[ 0x02, "Special Temporary Directory Handle" ],
])
AllocationBlockSize		= uint32("allocation_block_size", "Allocation Block Size")
ApplicationNumber		= uint16("application_number", "Application Number")
ArchivedTime			= uint16("archived_time", "Archived Time")
ArchivedTime.Display("BASE_HEX")
ArchivedDate			= uint16("archived_date", "Archived Date")
ArchivedDate.Display("BASE_HEX")
ArchivedDateAndTime		= uint32("archived_date_and_time", "Archived Date & Time")
ArchiverID			= uint32("archiver_id", "Archiver ID")
ArchiverID.Display("BASE_HEX")
AssociatedNameSpace		= byte("associated_name_space", "Associated Name Space")
AttachDuringProcessing 		= uint16("attach_during_processing", "Attach During Processing")
AttachedIndexedFiles		= byte("attached_indexed_files", "Attached Indexed Files")
AttachWhileProcessingAttach 	= uint16("attach_while_processing_attach", "Attach While Processing Attach")
Attributes			= uint32("attributes", "Attributes")
AttributesDefLow3		= bitfield8("attr_def_low_3", "Attributes (byte 3)", [
	bf_boolean8(0x01, "att_def_purge", "Purge"),
	bf_boolean8(0x02, "att_def_reninhibit", "Rename Inhibit"),
	bf_boolean8(0x04, "att_def_delinhibit", "Delete Inhibit"),
	bf_boolean8(0x08, "att_def_cpyinhibit", "Copy Inhibit"),
])
AttributesDefLow2		= bitfield8("attr_def_low_2", "Attributes (byte 2)", [
	bf_boolean8(0x10, "att_def_transaction", "Transactional"),
	bf_boolean8(0x40, "att_def_read_audit", "Read Audit"),
	bf_boolean8(0x80, "att_def_write_audit", "Write Audit"),
])
AttributesDefLow		= bitfield8("attr_def_low", "Attributes", [
	bf_boolean8(0x01, "att_def_ro", "Read Only"),
	bf_boolean8(0x02, "att_def_hidden", "Hidden"),
	bf_boolean8(0x04, "att_def_system", "System"),
	bf_boolean8(0x08, "att_def_execute", "Execute"),
	bf_boolean8(0x10, "att_def_sub_only", "Subdirectories Only"),
	bf_boolean8(0x20, "att_def_archive", "Archive"),
	bf_boolean8(0x80, "att_def_shareable", "Shareable"),
])
AttributeValidFlag 		= uint32("attribute_valid_flag", "Attribute Valid Flag")
AvailableBlocks			= uint32("available_blocks", "Available Blocks")
AvailableClusters		= uint16("available_clusters", "Available Clusters")
AvailableDirectorySlots		= uint16("available_directory_slots", "Available Directory Slots")
AvailableDirEntries		= uint32("available_dir_entries", "Available Directory Entries")
AvailableIndexedFiles		= uint16("available_indexed_files", "Available Indexed Files")

BackgroundAgedWrites 		= uint32("background_aged_writes", "Background Aged Writes")
BackgroundDirtyWrites		= uint32("background_dirty_writes", "Background Dirty Writes")
BadLogicalConnectionCount 	= uint16("bad_logical_connection_count", "Bad Logical Connection Count")
BannerName			= fw_string("banner_name", "Banner Name", 14)
BaseDirectoryID			= uint32("base_directory_id", "Base Directory ID")
BaseDirectoryID.Display("BASE_HEX")
binderyContext			= nstring8("bindery_context", "Bindery Context")
BitMap				= bytes("bit_map", "Bit Map", 512)
BlockSize 			= uint16("block_size", "Block Size")
BlockSizeInSectors		= uint32("block_size_in_sectors", "Block Size in Sectors")
BoardInstalled 			= byte("board_installed", "Board Installed")
BufferSize			= uint16("buffer_size", "Buffer Size")
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
CCFileHandle			= bytes("cc_file_handle", "File Handle", 4)
CCFunction			= val_string8("cc_function", "OP-Lock Flag", [
	[ 0x01, "Clear OP-Lock" ],
	[ 0x02, "Achnowledge Callback" ],
	[ 0x03, "Decline Callback" ],
])
ChangeBits1			= bitfield8("change_bits_1", "Change Bits", [
	bf_boolean8(0x01, "change_bits_modify", "Modify Name"),
	bf_boolean8(0x02, "change_bits_fatt", "File Attributes"),
	bf_boolean8(0x04, "change_bits_cdate", "Creation Date"),
	bf_boolean8(0x08, "change_bits_ctime", "Creation Time"),
	bf_boolean8(0x10, "change_bits_owner", "Owner ID"),
	bf_boolean8(0x20, "change_bits_adate", "Archive Date"),
	bf_boolean8(0x40, "change_bits_atime", "Archive Time"),
	bf_boolean8(0x80, "change_bits_aid", "Archiver ID"),
])
ChangeBits2			= bitfield8("change_bits_2", "Change Bits (byte 2)", [
	bf_boolean8(0x01, "change_bits_udate", "Update Date"),
	bf_boolean8(0x02, "change_bits_utime", "Update Time"),
	bf_boolean8(0x04, "change_bits_uid", "Update ID"),
	bf_boolean8(0x08, "change_bits_acc_date", "Access Date"),
	bf_boolean8(0x10, "change_bits_max_acc_mask", "Maximum Access Mask"),
	bf_boolean8(0x20, "change_bits_max_space", "Maximum Space"),
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
ClientIDNumber			= uint32("client_id_number", "Client ID Number")
ClientIDNumber.Display("BASE_HEX")
ClientListCount			= uint16("client_list_count", "Client List Count")
ClientRecordArea		= fw_string("client_record_area", "Client Record Area", 152)
ClientStation			= uint32("client_station", "Client Station")
ClientTaskNumber		= uint32("client_task_number", "Client Task Number")
ClusterCount			= uint16("cluster_count", "Cluster Count")
ClustersUsedByDirectories	= uint32("clusters_used_by_directories", "Clusters Used by Directories")
ClustersUsedByExtendedDirectories = uint32("clusters_used_by_extended_dirs", "Clusters Used by Extended Directories")
ClustersUsedByFAT		= uint32("clusters_used_by_fat", "Clusters Used by FAT")
Comment				= nstring8("comment", "Comment")
CommentType			= uint16("comment_type", "Comment Type")
CompletionCode			= uint32("ncompletion_code", "Completion Code")
CompressedDataStreamsCount	= uint32("compressed_data_streams_count", "Compressed Data Streams Count")
CompressedLimboDataStreamsCount	= uint32("compressed_limbo_data_streams_count", "Compressed Limbo Data Streams Count")
CompressedSectors		= uint32("compressed_sectors", "Compressed Sectors")
ConfigurationDescription	= fw_string("configuration_description", "Configuration Description", 80)
ConfigurationText		= fw_string("configuration_text", "Configuration Text", 160)
ConfiguredMaxBinderyObjects	= uint16("configured_max_bindery_objects", "Configured Max Bindery Objects")
ConfiguredMaxOpenFiles		= uint16("configured_max_open_files", "Configured Max Open Files")
ConfiguredMaxRoutingBuffers	= uint16("configured_max_routing_buffers", "Configured Max Routing Buffers")
ConfiguredMaxSimultaneousTransactions = uint16("cfg_max_simultaneous_transactions", "Configured Max Simultaneous Transactions")
ConnectionControlBits 		= bitfield8("conn_ctrl_bits", "Connection Control", [
	bf_boolean8(0x01, "enable_brdcasts", "Enable Broadcasts"),
	bf_boolean8(0x02, "enable_personal_brdcasts", "Enable Personal Broadcasts"),
	bf_boolean8(0x04, "enable_wdog_messages", "Enable Watchdog Message"),
	bf_boolean8(0x10, "disable_brdcasts", "Disable Broadcasts"),
	bf_boolean8(0x20, "disable_personal_brdcasts", "Disable Personal Broadcasts"),
	bf_boolean8(0x40, "disable_wdog_messages", "Disable Watchdog Message"),
])
ConnectionListCount 		= uint32("conn_list_count", "Connection List Count")
ConnectionList			= uint32("conn_list", "Connection List")
ConnectionNumber		= uint32("connection_number", "Connection Number")
ConnectionNumberList		= fw_string("connection_number_list", "Connection Number List", 128)
ConnectionsInUse		= uint16("connections_in_use", "Connections In Use")
ConnectionsMaxUsed		= uint16("connections_max_used", "Connections Max Used")
ConnectionsSupportedMax		= uint16("connections_supported_max", "Connections Supported Max")
ConnectionType			= val_string8("connection_type", "Connection Type", [
	[ 0x00, "Not in use" ],
	[ 0x02, "NCP" ],
	[ 0x11, "UDP (for IP)" ],
])
ControlFlags			= val_string8("control_flags", "Control Flags", [
	[ 0x00, "Forced Record Locking is Off" ],
	[ 0x01, "Forced Record Locking is On" ],
])
ControllerDriveNumber 		= byte("controller_drive_number", "Controller Drive Number")
ControllerNumber 		= byte("controller_number", "Controller Number")
ControllerType			= byte("controller_type", "Controller Type")
Cookie1 			= uint32("cookie_1", "Cookie 1")
Cookie2 			= uint32("cookie_2", "Cookie 2")
Copies				= byte( "copies", "Copies" )
CreationTime			= uint16("creation_time", "Creation Time")
CreationTime.Display("BASE_HEX")
CreationDate 			= uint16("creation_date", "Creation Date")
CreationDate.Display("BASE_HEX")
CreationDateAndTime		= uint32("creation_date_and_time", "Creation Date & Time")
CreatorID			= uint32("creator_id", "Creator ID")
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
CurrentChangedFATs		= uint16("current_changed_fats", "Current Changed FAT Entries")
CurrentEntries			= uint32("current_entries", "Current Entries")
CurrentFormType			= byte( "current_form_type", "Current Form Type" )
CurrentlyUsedRoutingBuffers 	= uint16("currently_used_routing_buffers", "Currently Used Routing Buffers")
CurrentOpenFiles		= uint16("current_open_files", "Current Open Files")
CurrentServers			= uint32("current_servers", "Current Servers")
CurrentSpace			= uint32("current_space", "Current Space")
CurrentTransactionCount		= uint32("current_trans_count", "Current Transaction Count")
CurrentUsedBinderyObjects 	= uint16("current_used_bindery_objects", "Current Used Bindery Objects")
CurrentUsedDynamicSpace 	= uint32("current_used_dynamic_space", "Current Used Dynamic Space")
CurrentYear			= val_string8("current_year", "Year", [
	[0x00, "2000"],
	[0x01, "2001"],
	[0x02, "2002"],
	[0x03, "2003"],
	[0x04, "2004"],
	[0x05, "2005"],
	[0x06, "2006"],
	[0x07, "2007"],
	[0x08, "2008"],
	[0x09, "2009"],
])

Data 				= nstring8("data", "Data")
DataForkFirstFAT		= uint32("data_fork_first_fat", "Data Fork First FAT Entry")
DataForkLen			= uint32("data_fork_len", "Data Fork Len")
DataForkSize			= uint32("data_fork_size", "Data Fork Size")
DataSize			= uint32("data_size", "Data Size")
DataStream			= val_string8("data_stream", "Data Stream", [
	[ 0x00, "Resource Fork or DOS" ],
	[ 0x01, "Data Fork" ],
])
DataStreamName			= fw_string("data_stream_name", "Data Stream Name", 255)
DataStreamNumber		= byte("data_stream_number", "Data Stream Number")
DataStreamsCount		= uint32("data_streams_count", "Data Streams Count")
DataStreamSize			= uint32("data_stream_size", "Size")
DataStreamSpaceAlloc 		= uint32( "data_stream_space_alloc", "Space Allocated for Data Stream" )
Day 				= byte("s_day", "Day")
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
DefinedDataStreams		= byte("defined_data_streams", "Defined Data Streams")
DefinedNameSpaces		= byte("definded_name_spaces", "Defined Name Spaces")
DeletedDate			= uint16("deleted_date", "Deleted Date")
DeletedFileTime			= uint32( "deleted_file_time", "Deleted Time")
DeletedDateAndTime		= uint32( "deleted_date_and_time", "Deleted Date & Time")
DeletedTime			= uint16("deleted_time", "Deleted Time")
DeletedID			= uint32( "delete_id", "Deleted ID")
DeletedID.Display("BASE_HEX")
DeleteExistingFileFlag		= val_string8("delete_existing_file_flag", "Delete Existing File Flag", [
	[ 0x00, "Do Not Delete Existing File" ],
	[ 0x01, "Delete Existing File" ],
])	
DenyReadCount			= uint16("deny_read_count", "Deny Read Count")
DenyWriteCount			= uint16("deny_write_count", "Deny Write Count")
DescriptionStrings		= fw_string("description_string", "Description", 512)
DesiredAccessRightsHigh 	= bitfield8("desired_access_rights_high", "Desired Access Rights (byte 2)", [
	bf_boolean8(0x04, "dsired_acc_rights_del_file_cls", "Delete File Close"),
])
DesiredAccessRightsLow 		= bitfield8("desired_access_rights_low", "Desired Access Rights (byte 1)", [
	bf_boolean8(0x01, "dsired_acc_rights_read_o", "Read Only"),
	bf_boolean8(0x02, "dsired_acc_rights_write_o", "Write Only"),
	bf_boolean8(0x04, "dsired_acc_rights_deny_r", "Deny Read"),
	bf_boolean8(0x08, "dsired_acc_rights_deny_w", "Deny Write"),
	bf_boolean8(0x10, "dsired_acc_rights_compat", "Compatibility"),
	bf_boolean8(0x40, "dsired_acc_rights_w_thru", "File Write Through"),
])
DesiredResponseCount 		= uint16("desired_response_count", "Desired Response Count")
DestDirHandle			= byte("dest_dir_handle", "Destination Directory Handle")
DestNameSpace 			= val_string8("dest_name_space", "Destination Name Space", [
	[ 0x00, "DOS Name Space" ],
	[ 0x01, "MAC Name Space" ],
	[ 0x02, "NFS Name Space" ],
	[ 0x04, "Long Name Space" ],
])
DestPathComponentCount		= byte("dest_component_count", "Destination Path Component Count")
DestPath			= bytes("dest_path", "Destination Path", 255)
DetachDuringProcessing = uint16("detach_during_processing", "Detach During Processing")
DetachForBadConnectionNumber = uint16("detach_for_bad_connection_number", "Detach For Bad Connection Number")
DirHandle			= byte("dir_handle", "Directory Handle")
DirHandleName			= byte("dir_handle_name", "Handle Name")
DirHandleLong			= uint32("dir_handle_long", "Directory Handle")
DirectoryBase 			= uint16("dir_base", "Directory Base")
DirectoryBase.Display("BASE_HEX")
DirectoryCount			= uint16("dir_count", "Directory Count")
DirectoryEntryNumber	 	= uint32("directory_entry_number", "Directory Entry Number", LE)
DirectoryEntryNumber.Display('BASE_HEX')
DirectoryEntryNumberWord 	= uint16("directory_entry_number_word", "Directory Entry Number")
DirectoryID			= uint16("directory_id", "Directory ID")
DirectoryID.Display("BASE_HEX")
DirectoryNumber			= uint32("directory_number", "Directory Number")
DirectoryNumber.Display("BASE_HEX")
DirectoryPath			= fw_string("directory_path", "Directory Path", 16)
DirectoryServicesObjectID	= uint32("directory_services_object_id", "Directory Services Object ID")
DirectoryServicesObjectID.Display("BASE_HEX")
DirtyCacheBuffers 		= uint16("dirty_cache_buffers", "Dirty Cache Buffers")
DiskChannelNumber		= byte("disk_channel_number", "Disk Channel Number")
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
DOSDirectoryEntryNumber 	= uint32("dos_directory_entry_number", "DOS Directory Entry Number", LE)
DOSDirectoryEntryNumber.Display('BASE_HEX')
DOSFileAttributes		= byte("dos_file_attributes", "DOS File Attributes")
DOSParentDirectoryEntry			= uint32("dos_parent_directory_entry", "DOS Parent Directory Entry")
DOSSequence			= uint32("dos_sequence", "DOS Sequence")

DriveCylinders 			= uint16("drive_cylinders", "Drive Cylinders")
DriveDefinitionString 		= fw_string("drive_definition_string", "Drive Definition", 64)
DriveHeads 			= byte("drive_heads", "Drive Heads")
DriveMappingTable		= bytes("drive_mapping_table", "Drive Mapping Table", 32)
DriveMirrorTable 		= bytes("drive_mirror_table", "Drive Mirror Table", 32)
DriveRemovableFlag 		= val_string8("drive_removable_flag", "Drive Removable Flag", [
	[ 0x00, "Nonremovable" ],
	[ 0xff, "Removable" ],
])
DriveSize 			= uint32("drive_size", "Drive Size")
DstEAFlags			= val_string16("dst_ea_flags", "Destination EA Flags", [
	[ 0x0000, "Return EAHandle/Reserved,Information Level 0" ],
	[ 0x0001, "Return NetWareHandle/Reserved,Information Level 0" ],
	[ 0x0002, "Return Volume/Directory Number,Information Level 0" ],
	[ 0x0004, "Return EAHandle/Reserved,Close Handle on Error,Information Level 0" ],
	[ 0x0005, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 0" ],
	[ 0x0006, "Return Volume/Directory Number,Close Handle on Error,Information Level 0" ],
	[ 0x0010, "Return EAHandle/Reserved,Information Level 1" ],
	[ 0x0011, "Return NetWareHandle/Reserved,Information Level 1" ],
	[ 0x0012, "Return Volume/Directory Number,Information Level 1" ],
	[ 0x0014, "Return EAHandle/Reserved,Close Handle on Error,Information Level 1" ],
	[ 0x0015, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 1" ],
	[ 0x0016, "Return Volume/Directory Number,Close Handle on Error,Information Level 1" ],
	[ 0x0020, "Return EAHandle/Reserved,Information Level 2" ],
	[ 0x0021, "Return NetWareHandle/Reserved,Information Level 2" ],
	[ 0x0022, "Return Volume/Directory Number,Information Level 2" ],
	[ 0x0024, "Return EAHandle/Reserved,Close Handle on Error,Information Level 2" ],
	[ 0x0025, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 2" ],
	[ 0x0026, "Return Volume/Directory Number,Close Handle on Error,Information Level 2" ],
	[ 0x0030, "Return EAHandle/Reserved,Information Level 3" ],
	[ 0x0031, "Return NetWareHandle/Reserved,Information Level 3" ],
	[ 0x0032, "Return Volume/Directory Number,Information Level 3" ],
	[ 0x0034, "Return EAHandle/Reserved,Close Handle on Error,Information Level 3" ],
	[ 0x0035, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 3" ],
	[ 0x0036, "Return Volume/Directory Number,Close Handle on Error,Information Level 3" ],
	[ 0x0040, "Return EAHandle/Reserved,Information Level 4" ],
	[ 0x0041, "Return NetWareHandle/Reserved,Information Level 4" ],
	[ 0x0042, "Return Volume/Directory Number,Information Level 4" ],
	[ 0x0044, "Return EAHandle/Reserved,Close Handle on Error,Information Level 4" ],
	[ 0x0045, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 4" ],
	[ 0x0046, "Return Volume/Directory Number,Close Handle on Error,Information Level 4" ],
	[ 0x0050, "Return EAHandle/Reserved,Information Level 5" ],
	[ 0x0051, "Return NetWareHandle/Reserved,Information Level 5" ],
	[ 0x0052, "Return Volume/Directory Number,Information Level 5" ],
	[ 0x0054, "Return EAHandle/Reserved,Close Handle on Error,Information Level 5" ],
	[ 0x0055, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 5" ],
	[ 0x0056, "Return Volume/Directory Number,Close Handle on Error,Information Level 5" ],
	[ 0x0060, "Return EAHandle/Reserved,Information Level 6" ],
	[ 0x0061, "Return NetWareHandle/Reserved,Information Level 6" ],
	[ 0x0062, "Return Volume/Directory Number,Information Level 6" ],
	[ 0x0064, "Return EAHandle/Reserved,Close Handle on Error,Information Level 6" ],
	[ 0x0065, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 6" ],
	[ 0x0066, "Return Volume/Directory Number,Close Handle on Error,Information Level 6" ],
	[ 0x0070, "Return EAHandle/Reserved,Information Level 7" ],
	[ 0x0071, "Return NetWareHandle/Reserved,Information Level 7" ],
	[ 0x0072, "Return Volume/Directory Number,Information Level 7" ],
	[ 0x0074, "Return EAHandle/Reserved,Close Handle on Error,Information Level 7" ],
	[ 0x0075, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 7" ],
	[ 0x0076, "Return Volume/Directory Number,Close Handle on Error,Information Level 7" ],
	[ 0x0080, "Return EAHandle/Reserved,Information Level 0,Immediate Close Handle" ],
	[ 0x0081, "Return NetWareHandle/Reserved,Information Level 0,Immediate Close Handle" ],
	[ 0x0082, "Return Volume/Directory Number,Information Level 0,Immediate Close Handle" ],
	[ 0x0084, "Return EAHandle/Reserved,Close Handle on Error,Information Level 0,Immediate Close Handle" ],
	[ 0x0085, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 0,Immediate Close Handle" ],
	[ 0x0086, "Return Volume/Directory Number,Close Handle on Error,Information Level 0,Immediate Close Handle" ],
	[ 0x0090, "Return EAHandle/Reserved,Information Level 1,Immediate Close Handle" ],
	[ 0x0091, "Return NetWareHandle/Reserved,Information Level 1,Immediate Close Handle" ],
	[ 0x0092, "Return Volume/Directory Number,Information Level 1,Immediate Close Handle" ],
	[ 0x0094, "Return EAHandle/Reserved,Close Handle on Error,Information Level 1,Immediate Close Handle" ],
	[ 0x0095, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 1,Immediate Close Handle" ],
	[ 0x0096, "Return Volume/Directory Number,Close Handle on Error,Information Level 1,Immediate Close Handle" ],
	[ 0x00a0, "Return EAHandle/Reserved,Information Level 2,Immediate Close Handle" ],
	[ 0x00a1, "Return NetWareHandle/Reserved,Information Level 2,Immediate Close Handle" ],
	[ 0x00a2, "Return Volume/Directory Number,Information Level 2,Immediate Close Handle" ],
	[ 0x00a4, "Return EAHandle/Reserved,Close Handle on Error,Information Level 2,Immediate Close Handle" ],
	[ 0x00a5, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 2,Immediate Close Handle" ],
	[ 0x00a6, "Return Volume/Directory Number,Close Handle on Error,Information Level 2,Immediate Close Handle" ],
	[ 0x00b0, "Return EAHandle/Reserved,Information Level 3,Immediate Close Handle" ],
	[ 0x00b1, "Return NetWareHandle/Reserved,Information Level 3,Immediate Close Handle" ],
	[ 0x00b2, "Return Volume/Directory Number,Information Level 3,Immediate Close Handle" ],
	[ 0x00b4, "Return EAHandle/Reserved,Close Handle on Error,Information Level 3,Immediate Close Handle" ],
	[ 0x00b5, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 3,Immediate Close Handle" ],
	[ 0x00b6, "Return Volume/Directory Number,Close Handle on Error,Information Level 3,Immediate Close Handle" ],
	[ 0x00c0, "Return EAHandle/Reserved,Information Level 4,Immediate Close Handle" ],
	[ 0x00c1, "Return NetWareHandle/Reserved,Information Level 4,Immediate Close Handle" ],
	[ 0x00c2, "Return Volume/Directory Number,Information Level 4,Immediate Close Handle" ],
	[ 0x00c4, "Return EAHandle/Reserved,Close Handle on Error,Information Level 4,Immediate Close Handle" ],
	[ 0x00c5, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 4,Immediate Close Handle" ],
	[ 0x00c6, "Return Volume/Directory Number,Close Handle on Error,Information Level 4,Immediate Close Handle" ],
	[ 0x00d0, "Return EAHandle/Reserved,Information Level 5,Immediate Close Handle" ],
	[ 0x00d1, "Return NetWareHandle/Reserved,Information Level 5,Immediate Close Handle" ],
	[ 0x00d2, "Return Volume/Directory Number,Information Level 5,Immediate Close Handle" ],
	[ 0x00d4, "Return EAHandle/Reserved,Close Handle on Error,Information Level 5,Immediate Close Handle" ],
	[ 0x00d5, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 5,Immediate Close Handle" ],
	[ 0x00d6, "Return Volume/Directory Number,Close Handle on Error,Information Level 5,Immediate Close Handle" ],
	[ 0x00e0, "Return EAHandle/Reserved,Information Level 6,Immediate Close Handle" ],
	[ 0x00e1, "Return NetWareHandle/Reserved,Information Level 6,Immediate Close Handle" ],
	[ 0x00e2, "Return Volume/Directory Number,Information Level 6,Immediate Close Handle" ],
	[ 0x00e4, "Return EAHandle/Reserved,Close Handle on Error,Information Level 6,Immediate Close Handle" ],
	[ 0x00e5, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 6,Immediate Close Handle" ],
	[ 0x00e6, "Return Volume/Directory Number,Close Handle on Error,Information Level 6,Immediate Close Handle" ],
	[ 0x00f0, "Return EAHandle/Reserved,Information Level 7,Immediate Close Handle" ],
	[ 0x00f1, "Return NetWareHandle/Reserved,Information Level 7,Immediate Close Handle" ],
	[ 0x00f2, "Return Volume/Directory Number,Information Level 7,Immediate Close Handle" ],
	[ 0x00f4, "Return EAHandle/Reserved,Close Handle on Error,Information Level 7,Immediate Close Handle" ],
	[ 0x00f5, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 7,Immediate Close Handle" ],
	[ 0x00f6, "Return Volume/Directory Number,Close Handle on Error,Information Level 7,Immediate Close Handle" ],
])
dstNSIndicator			= val_string16("dst_ns_indicator", "Destination Name Space Indicator", [
	[ 0x0000, "Return Source Name Space Information" ],
	[ 0x0001, "Return Destination Name Space Information" ],
])	
DstQueueID			= uint32("dst_queue_id", "Destination Queue ID")
DuplicateRepliesSent 		= uint16("duplicate_replies_sent", "Duplicate Replies Sent")

EAAccessFlag			= val_string16("ea_access_flag", "EA Access Flag", [
	[ 0x0080, "EA Need Bit Flag" ],
])
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
	[ 0x0000, "Return EAHandle/Reserved,Information Level 0" ],
	[ 0x0001, "Return NetWareHandle/Reserved,Information Level 0" ],
	[ 0x0002, "Return Volume/Directory Number,Information Level 0" ],
	[ 0x0004, "Return EAHandle/Reserved,Close Handle on Error,Information Level 0" ],
	[ 0x0005, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 0" ],
	[ 0x0006, "Return Volume/Directory Number,Close Handle on Error,Information Level 0" ],
	[ 0x0010, "Return EAHandle/Reserved,Information Level 1" ],
	[ 0x0011, "Return NetWareHandle/Reserved,Information Level 1" ],
	[ 0x0012, "Return Volume/Directory Number,Information Level 1" ],
	[ 0x0014, "Return EAHandle/Reserved,Close Handle on Error,Information Level 1" ],
	[ 0x0015, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 1" ],
	[ 0x0016, "Return Volume/Directory Number,Close Handle on Error,Information Level 1" ],
	[ 0x0020, "Return EAHandle/Reserved,Information Level 2" ],
	[ 0x0021, "Return NetWareHandle/Reserved,Information Level 2" ],
	[ 0x0022, "Return Volume/Directory Number,Information Level 2" ],
	[ 0x0024, "Return EAHandle/Reserved,Close Handle on Error,Information Level 2" ],
	[ 0x0025, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 2" ],
	[ 0x0026, "Return Volume/Directory Number,Close Handle on Error,Information Level 2" ],
	[ 0x0030, "Return EAHandle/Reserved,Information Level 3" ],
	[ 0x0031, "Return NetWareHandle/Reserved,Information Level 3" ],
	[ 0x0032, "Return Volume/Directory Number,Information Level 3" ],
	[ 0x0034, "Return EAHandle/Reserved,Close Handle on Error,Information Level 3" ],
	[ 0x0035, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 3" ],
	[ 0x0036, "Return Volume/Directory Number,Close Handle on Error,Information Level 3" ],
	[ 0x0040, "Return EAHandle/Reserved,Information Level 4" ],
	[ 0x0041, "Return NetWareHandle/Reserved,Information Level 4" ],
	[ 0x0042, "Return Volume/Directory Number,Information Level 4" ],
	[ 0x0044, "Return EAHandle/Reserved,Close Handle on Error,Information Level 4" ],
	[ 0x0045, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 4" ],
	[ 0x0046, "Return Volume/Directory Number,Close Handle on Error,Information Level 4" ],
	[ 0x0050, "Return EAHandle/Reserved,Information Level 5" ],
	[ 0x0051, "Return NetWareHandle/Reserved,Information Level 5" ],
	[ 0x0052, "Return Volume/Directory Number,Information Level 5" ],
	[ 0x0054, "Return EAHandle/Reserved,Close Handle on Error,Information Level 5" ],
	[ 0x0055, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 5" ],
	[ 0x0056, "Return Volume/Directory Number,Close Handle on Error,Information Level 5" ],
	[ 0x0060, "Return EAHandle/Reserved,Information Level 6" ],
	[ 0x0061, "Return NetWareHandle/Reserved,Information Level 6" ],
	[ 0x0062, "Return Volume/Directory Number,Information Level 6" ],
	[ 0x0064, "Return EAHandle/Reserved,Close Handle on Error,Information Level 6" ],
	[ 0x0065, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 6" ],
	[ 0x0066, "Return Volume/Directory Number,Close Handle on Error,Information Level 6" ],
	[ 0x0070, "Return EAHandle/Reserved,Information Level 7" ],
	[ 0x0071, "Return NetWareHandle/Reserved,Information Level 7" ],
	[ 0x0072, "Return Volume/Directory Number,Information Level 7" ],
	[ 0x0074, "Return EAHandle/Reserved,Close Handle on Error,Information Level 7" ],
	[ 0x0075, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 7" ],
	[ 0x0076, "Return Volume/Directory Number,Close Handle on Error,Information Level 7" ],
	[ 0x0080, "Return EAHandle/Reserved,Information Level 0,Immediate Close Handle" ],
	[ 0x0081, "Return NetWareHandle/Reserved,Information Level 0,Immediate Close Handle" ],
	[ 0x0082, "Return Volume/Directory Number,Information Level 0,Immediate Close Handle" ],
	[ 0x0084, "Return EAHandle/Reserved,Close Handle on Error,Information Level 0,Immediate Close Handle" ],
	[ 0x0085, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 0,Immediate Close Handle" ],
	[ 0x0086, "Return Volume/Directory Number,Close Handle on Error,Information Level 0,Immediate Close Handle" ],
	[ 0x0090, "Return EAHandle/Reserved,Information Level 1,Immediate Close Handle" ],
	[ 0x0091, "Return NetWareHandle/Reserved,Information Level 1,Immediate Close Handle" ],
	[ 0x0092, "Return Volume/Directory Number,Information Level 1,Immediate Close Handle" ],
	[ 0x0094, "Return EAHandle/Reserved,Close Handle on Error,Information Level 1,Immediate Close Handle" ],
	[ 0x0095, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 1,Immediate Close Handle" ],
	[ 0x0096, "Return Volume/Directory Number,Close Handle on Error,Information Level 1,Immediate Close Handle" ],
	[ 0x00a0, "Return EAHandle/Reserved,Information Level 2,Immediate Close Handle" ],
	[ 0x00a1, "Return NetWareHandle/Reserved,Information Level 2,Immediate Close Handle" ],
	[ 0x00a2, "Return Volume/Directory Number,Information Level 2,Immediate Close Handle" ],
	[ 0x00a4, "Return EAHandle/Reserved,Close Handle on Error,Information Level 2,Immediate Close Handle" ],
	[ 0x00a5, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 2,Immediate Close Handle" ],
	[ 0x00a6, "Return Volume/Directory Number,Close Handle on Error,Information Level 2,Immediate Close Handle" ],
	[ 0x00b0, "Return EAHandle/Reserved,Information Level 3,Immediate Close Handle" ],
	[ 0x00b1, "Return NetWareHandle/Reserved,Information Level 3,Immediate Close Handle" ],
	[ 0x00b2, "Return Volume/Directory Number,Information Level 3,Immediate Close Handle" ],
	[ 0x00b4, "Return EAHandle/Reserved,Close Handle on Error,Information Level 3,Immediate Close Handle" ],
	[ 0x00b5, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 3,Immediate Close Handle" ],
	[ 0x00b6, "Return Volume/Directory Number,Close Handle on Error,Information Level 3,Immediate Close Handle" ],
	[ 0x00c0, "Return EAHandle/Reserved,Information Level 4,Immediate Close Handle" ],
	[ 0x00c1, "Return NetWareHandle/Reserved,Information Level 4,Immediate Close Handle" ],
	[ 0x00c2, "Return Volume/Directory Number,Information Level 4,Immediate Close Handle" ],
	[ 0x00c4, "Return EAHandle/Reserved,Close Handle on Error,Information Level 4,Immediate Close Handle" ],
	[ 0x00c5, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 4,Immediate Close Handle" ],
	[ 0x00c6, "Return Volume/Directory Number,Close Handle on Error,Information Level 4,Immediate Close Handle" ],
	[ 0x00d0, "Return EAHandle/Reserved,Information Level 5,Immediate Close Handle" ],
	[ 0x00d1, "Return NetWareHandle/Reserved,Information Level 5,Immediate Close Handle" ],
	[ 0x00d2, "Return Volume/Directory Number,Information Level 5,Immediate Close Handle" ],
	[ 0x00d4, "Return EAHandle/Reserved,Close Handle on Error,Information Level 5,Immediate Close Handle" ],
	[ 0x00d5, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 5,Immediate Close Handle" ],
	[ 0x00d6, "Return Volume/Directory Number,Close Handle on Error,Information Level 5,Immediate Close Handle" ],
	[ 0x00e0, "Return EAHandle/Reserved,Information Level 6,Immediate Close Handle" ],
	[ 0x00e1, "Return NetWareHandle/Reserved,Information Level 6,Immediate Close Handle" ],
	[ 0x00e2, "Return Volume/Directory Number,Information Level 6,Immediate Close Handle" ],
	[ 0x00e4, "Return EAHandle/Reserved,Close Handle on Error,Information Level 6,Immediate Close Handle" ],
	[ 0x00e5, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 6,Immediate Close Handle" ],
	[ 0x00e6, "Return Volume/Directory Number,Close Handle on Error,Information Level 6,Immediate Close Handle" ],
	[ 0x00f0, "Return EAHandle/Reserved,Information Level 7,Immediate Close Handle" ],
	[ 0x00f1, "Return NetWareHandle/Reserved,Information Level 7,Immediate Close Handle" ],
	[ 0x00f2, "Return Volume/Directory Number,Information Level 7,Immediate Close Handle" ],
	[ 0x00f4, "Return EAHandle/Reserved,Close Handle on Error,Information Level 7,Immediate Close Handle" ],
	[ 0x00f5, "Return NetWareHandle/Reserved,Close Handle on Error,Information Level 7,Immediate Close Handle" ],
	[ 0x00f6, "Return Volume/Directory Number,Close Handle on Error,Information Level 7,Immediate Close Handle" ],
])
EAHandle			= uint32("ea_handle", "EA Handle")
EAHandleOrNetWareHandleOrVolume	= uint32("ea_handle_or_netware_handle_or_volume", "EAHandle or NetWare Handle or Volume (see EAFlags)")
EAKeyLength			= uint16("ea_key_length", "EA Key Length")
EAKeySize			= uint32("ea_key_size", "Key Size")
EAKeySizeDuplicated		= uint32("ea_key_size_duplicated", "Key Size Duplicated")
EAValueLength			= uint16("ea_value_length", "EA Value Length")
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
eventOffset 			= bytes("event_offset", "Event Offset", 8)
eventOffset.Display("BASE_HEX")
eventTime 			= uint32("event_time", "Event Time")
eventTime.Display("BASE_HEX")
ExtAttrDataSize 		= uint32("ext_attr_data_size", "Extended Attributes Data Size")
ExtAttrCount			= uint32("ext_attr_count", "Extended Attributes Count")
ExtAttrKeySize			= uint32("ext_attr_key_size", "Extended Attributes Key Size")
ExtendedAttributesDefined	= uint32("extended_attributes_defined", "Extended Attributes Defined")
ExtendedAttributeExtantsUsed	= uint32("extended_attribute_extants_used", "Extended Attribute Extants Used")
ExtendedInfoHigh	 	= bitfield8("ext_info_high", "Extended Information", [
	bf_boolean8(0x01, "ext_info_l_access", "Last Access"),
	bf_boolean8(0x80, "ext_info_newstyle", "New Style"),
])
ExtendedInfoLow  		= bitfield8("ext_info_low", "Extended Information", [
	bf_boolean8(0x01, "ext_info_l_update", "Update"),
	bf_boolean8(0x02, "ext_info_l_dos_name", "DOS Name"),
	bf_boolean8(0x04, "ext_info_l_flush", "Flush"),
	bf_boolean8(0x08, "ext_info_l_parental", "Parental"),
	bf_boolean8(0x10, "ext_info_l_mac_finder", "MAC Finder"),
	bf_boolean8(0x20, "ext_info_l_sibling", "Sibling"),
	bf_boolean8(0x40, "ext_info_l_effective", "Effective"),
	bf_boolean8(0x80, "ext_info_l_mac_date", "MAC Date"),
])
			       
FatalFATWriteErrors		= uint16("fatal_fat_write_errors", "Fatal FAT Write Errors")
FATScanErrors			= uint16("fat_scan_errors", "FAT Scan Errors")
FATWriteErrors			= uint16("fat_write_errors", "FAT Write Errors")
FieldsLenTable			= bytes("fields_len_table", "Fields Len Table", 32)
FileCount			= uint16("file_count", "File Count")
FileDate			= uint16("file_date", "File Date")
FileDirWindow			= uint16("file_dir_win", "File/Dir Window")
FileDirWindow.Display("BASE_HEX")
FileExecuteType 		= byte("file_execute_type", "File Execute Type")
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
	[ 0x0d, "Reserved/Indexed" ],
	[ 0x0e, "Search On All Opens/Indexed" ],
	[ 0x0f, "Reserved/Indexed" ],
	[ 0x10, "Search On All Read Only Opens/Transactional" ],
	[ 0x11, "Search On Read Only Opens With No Path/Transactional" ],
	[ 0x12, "Shell Default Search Mode/Transactional" ],
	[ 0x13, "Search On All Opens With No Path/Transactional" ],
	[ 0x14, "Do Not Search/Transactional" ],
	[ 0x15, "Reserved/Transactional" ],
	[ 0x16, "Search On All Opens/Transactional" ],
	[ 0x17, "Reserved/Transactional" ],
	[ 0x18, "Search On All Read Only Opens/Indexed/Transactional" ],
	[ 0x19, "Search On Read Only Opens With No Path/Indexed/Transactional" ],
	[ 0x1a, "Shell Default Search Mode/Indexed/Transactional" ],
	[ 0x1b, "Search On All Opens With No Path/Indexed/Transactional" ],
	[ 0x1c, "Do Not Search/Indexed/Transactional" ],
	[ 0x1d, "Reserved/Indexed/Transactional" ],
	[ 0x1e, "Search On All Opens/Indexed/Transactional" ],
	[ 0x1f, "Reserved/Indexed/Transactional" ],
	[ 0x40, "Search On All Read Only Opens/Read Audit" ],
	[ 0x41, "Search On Read Only Opens With No Path/Read Audit" ],
	[ 0x42, "Shell Default Search Mode/Read Audit" ],
	[ 0x43, "Search On All Opens With No Path/Read Audit" ],
	[ 0x44, "Do Not Search/Read Audit" ],
	[ 0x45, "Reserved/Read Audit" ],
	[ 0x46, "Search On All Opens/Read Audit" ],
	[ 0x47, "Reserved/Read Audit" ],
	[ 0x48, "Search On All Read Only Opens/Indexed/Read Audit" ],
	[ 0x49, "Search On Read Only Opens With No Path/Indexed/Read Audit" ],
	[ 0x4a, "Shell Default Search Mode/Indexed/Read Audit" ],
	[ 0x4b, "Search On All Opens With No Path/Indexed/Read Audit" ],
	[ 0x4c, "Do Not Search/Indexed/Read Audit" ],
	[ 0x4d, "Reserved/Indexed/Read Audit" ],
	[ 0x4e, "Search On All Opens/Indexed/Read Audit" ],
	[ 0x4f, "Reserved/Indexed/Read Audit" ],
	[ 0x50, "Search On All Read Only Opens/Transactional/Read Audit" ],
	[ 0x51, "Search On Read Only Opens With No Path/Transactional/Read Audit" ],
	[ 0x52, "Shell Default Search Mode/Transactional/Read Audit" ],
	[ 0x53, "Search On All Opens With No Path/Transactional/Read Audit" ],
	[ 0x54, "Do Not Search/Transactional/Read Audit" ],
	[ 0x55, "Reserved/Transactional/Read Audit" ],
	[ 0x56, "Search On All Opens/Transactional/Read Audit" ],
	[ 0x57, "Reserved/Transactional/Read Audit" ],
	[ 0x58, "Search On All Read Only Opens/Indexed/Transactional/Read Audit" ],
	[ 0x59, "Search On Read Only Opens With No Path/Indexed/Transactional/Read Audit" ],
	[ 0x5a, "Shell Default Search Mode/Indexed/Transactional/Read Audit" ],
	[ 0x5b, "Search On All Opens With No Path/Indexed/Transactional/Read Audit" ],
	[ 0x5c, "Do Not Search/Indexed/Transactional/Read Audit" ],
	[ 0x5d, "Reserved/Indexed/Transactional/Read Audit" ],
	[ 0x5e, "Search On All Opens/Indexed/Transactional/Read Audit" ],
	[ 0x5f, "Reserved/Indexed/Transactional/Read Audit" ],
	[ 0x80, "Search On All Read Only Opens/Write Audit" ],
	[ 0x81, "Search On Read Only Opens With No Path/Write Audit" ],
	[ 0x82, "Shell Default Search Mode/Write Audit" ],
	[ 0x83, "Search On All Opens With No Path/Write Audit" ],
	[ 0x84, "Do Not Search/Write Audit" ],
	[ 0x85, "Reserved/Write Audit" ],
	[ 0x86, "Search On All Opens/Write Audit" ],
	[ 0x87, "Reserved/Write Audit" ],
	[ 0x88, "Search On All Read Only Opens/Indexed/Write Audit" ],
	[ 0x89, "Search On Read Only Opens With No Path/Indexed/Write Audit" ],
	[ 0x8a, "Shell Default Search Mode/Indexed/Write Audit" ],
	[ 0x8b, "Search On All Opens With No Path/Indexed/Write Audit" ],
	[ 0x8c, "Do Not Search/Indexed/Write Audit" ],
	[ 0x8d, "Reserved/Indexed/Write Audit" ],
	[ 0x8e, "Search On All Opens/Indexed/Write Audit" ],
	[ 0x8f, "Reserved/Indexed/Write Audit" ],
	[ 0x90, "Search On All Read Only Opens/Transactional/Write Audit" ],
	[ 0x91, "Search On Read Only Opens With No Path/Transactional/Write Audit" ],
	[ 0x92, "Shell Default Search Mode/Transactional/Write Audit" ],
	[ 0x93, "Search On All Opens With No Path/Transactional/Write Audit" ],
	[ 0x94, "Do Not Search/Transactional/Write Audit" ],
	[ 0x95, "Reserved/Transactional/Write Audit" ],
	[ 0x96, "Search On All Opens/Transactional/Write Audit" ],
	[ 0x97, "Reserved/Transactional/Write Audit" ],
	[ 0x98, "Search On All Read Only Opens/Indexed/Transactional/Write Audit" ],
	[ 0x99, "Search On Read Only Opens With No Path/Indexed/Transactional/Write Audit" ],
	[ 0x9a, "Shell Default Search Mode/Indexed/Transactional/Write Audit" ],
	[ 0x9b, "Search On All Opens With No Path/Indexed/Transactional/Write Audit" ],
	[ 0x9c, "Do Not Search/Indexed/Transactional/Write Audit" ],
	[ 0x9d, "Reserved/Indexed/Transactional/Write Audit" ],
	[ 0x9e, "Search On All Opens/Indexed/Transactional/Write Audit" ],
	[ 0x9f, "Reserved/Indexed/Transactional/Write Audit" ],
	[ 0xa0, "Search On All Read Only Opens/Read Audit/Write Audit" ],
	[ 0xa1, "Search On Read Only Opens With No Path/Read Audit/Write Audit" ],
	[ 0xa2, "Shell Default Search Mode/Read Audit/Write Audit" ],
	[ 0xa3, "Search On All Opens With No Path/Read Audit/Write Audit" ],
	[ 0xa4, "Do Not Search/Read Audit/Write Audit" ],
	[ 0xa5, "Reserved/Read Audit/Write Audit" ],
	[ 0xa6, "Search On All Opens/Read Audit/Write Audit" ],
	[ 0xa7, "Reserved/Read Audit/Write Audit" ],
	[ 0xa8, "Search On All Read Only Opens/Indexed/Read Audit/Write Audit" ],
	[ 0xa9, "Search On Read Only Opens With No Path/Indexed/Read Audit/Write Audit" ],
	[ 0xaa, "Shell Default Search Mode/Indexed/Read Audit/Write Audit" ],
	[ 0xab, "Search On All Opens With No Path/Indexed/Read Audit/Write Audit" ],
	[ 0xac, "Do Not Search/Indexed/Read Audit/Write Audit" ],
	[ 0xad, "Reserved/Indexed/Read Audit/Write Audit" ],
	[ 0xae, "Search On All Opens/Indexed/Read Audit/Write Audit" ],
	[ 0xaf, "Reserved/Indexed/Read Audit/Write Audit" ],
	[ 0xb0, "Search On All Read Only Opens/Transactional/Read Audit/Write Audit" ],
	[ 0xb1, "Search On Read Only Opens With No Path/Transactional/Read Audit/Write Audit" ],
	[ 0xb2, "Shell Default Search Mode/Transactional/Read Audit/Write Audit" ],
	[ 0xb3, "Search On All Opens With No Path/Transactional/Read Audit/Write Audit" ],
	[ 0xb4, "Do Not Search/Transactional/Read Audit/Write Audit" ],
	[ 0xb5, "Reserved/Transactional/Read Audit/Write Audit" ],
	[ 0xb6, "Search On All Opens/Transactional/Read Audit/Write Audit" ],
	[ 0xb7, "Reserved/Transactional/Read Audit/Write Audit" ],
	[ 0xb8, "Search On All Read Only Opens/Indexed/Transactional/Read Audit/Write Audit" ],
	[ 0xb9, "Search On Read Only Opens With No Path/Indexed/Transactional/Read Audit/Write Audit" ],
	[ 0xba, "Shell Default Search Mode/Indexed/Transactional/Read Audit/Write Audit" ],
	[ 0xbb, "Search On All Opens With No Path/Indexed/Transactional/Read Audit/Write Audit" ],
	[ 0xbc, "Do Not Search/Indexed/Transactional/Read Audit/Write Audit" ],
	[ 0xbd, "Reserved/Indexed/Transactional/Read Audit/Write Audit" ],
	[ 0xbe, "Search On All Opens/Indexed/Transactional/Read Audit/Write Audit" ],
	[ 0xbf, "Reserved/Indexed/Transactional/Read Audit/Write Audit" ],
])

FileHandle			= bytes("file_handle", "File Handle", 6)
FileLimbo 			= uint32("file_limbo", "File Limbo")
FileLock			= val_string8("file_lock", "File Lock", [
	[ 0x00, "Not Locked" ],
	[ 0xfe, "Locked by file lock" ],
	[ 0xff, "Unknown" ],
])
FileMode			= byte("file_mode", "File Mode")
FileName			= nstring8("file_name", "Filename")
FileName12			= fw_string("file_name_12", "Filename", 12)
FileName14			= fw_string("file_name_14", "Filename", 14)
FileNameLen			= byte("file_name_len", "Filename Length")
FileOffset			= uint32("file_offset", "File Offset")
FilePath			= nstring8("file_path", "File Path")
FileSize			= uint32("file_size", "File Size", LE)
FileTime			= uint16("file_time", "File Time")
Filler				= byte("filler", "Filler")
FinderAttrHigh			= bitfield8("finder_attr_high", "Finder Info Attributes (byte 2)", [
	bf_boolean8(0x20, "finder_attr_invisible", "Object is Invisible"),
	bf_boolean8(0x40, "finder_attr_bundle", "Object Has Bundle"),
])
FinderAttrLow			= bitfield8("finder_attr_low", "Finder Info Attributes", [
	bf_boolean8(0x01, "finder_attr_desktop", "Object on Desktop"),
])
FixedBitMask 			= uint32("fixed_bit_mask", "Fixed Bit Mask")
FixedBitsDefined 		= uint16("fixed_bits_defined", "Fixed Bits Defined")
FlagBits 			= byte("flag_bits", "Flag Bits")
FlagsDef			= uint16("flags_def", "Flags")
FolderFlag			= val_string8("folder_flag", "Folder Flag", [
	[ 0x00, "Not a Folder" ],
	[ 0x01, "Folder" ],
])
ForkCount			= byte("fork_count", "Fork Count")
ForkIndicator			= val_string8("fork_indicator", "Fork Indicator", [
	[ 0x00, "Data Fork" ],
	[ 0x01, "Resource Fork" ],
])
ForceFlag			= val_string8("force_flag", "Force Server Down Flag", [
	[ 0x00, "Down Server if No Files Are Open" ],
	[ 0xff, "Down Server Immediately, Auto-Close Open Files" ],
])
ForgedDetachedRequests = uint16("forged_detached_requests", "Forged Detached Requests")
FormType			= uint16( "form_type", "Form Type" )
FormTypeCnt			= uint32("form_type_count", "Form Types Count")
FraggerHandle			= uint32("fragger_handle", "Fragment Handle")
FraggerHandle.Display('BASE_HEX')
FragmentWriteOccurred		= uint16("fragment_write_occurred", "Fragment Write Occurred")
FragSize			= uint32("frag_size", "Fragment Size")
FreeableLimboSectors		= uint32("freeable_limbo_sectors", "Freeable Limbo Sectors")
FreeBlocks			= uint32("free_blocks", "Free Blocks")
FreedClusters			= uint32("freed_clusters", "Freed Clusters")
FreeDirectoryEntries 		= uint16("free_directory_entries", "Free Directory Entries")
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
HoldAmount			= uint32("hold_amount", "Hold Amount")
HoldCancelAmount		= uint32("hold_cancel_amount", "Hold Cancel Amount")
HolderID			= uint32("holder_id", "Holder ID")
HolderID.Display("BASE_HEX")
HorizLocation			= uint16("horiz_location", "Horizontal Location")
HostAddress			= bytes("host_address", "Host Address", 6)
HotFixBlocksAvailable 		= uint16("hot_fix_blocks_available", "Hot Fix Blocks Available")
HotFixDisabled			= val_string8("hot_fix_disabled", "Hot Fix Disabled", [
	[ 0x00, "Enabled" ],
	[ 0x01, "Disabled" ],
])
HotFixTableSize 		= uint16("hot_fix_table_size", "Hot Fix Table Size")
HotFixTableStart 		= uint32("hot_fix_table_start", "Hot Fix Table Start")
Hour				= byte("s_hour", "Hour")
HugeBitMask 			= uint32("huge_bit_mask", "Huge Bit Mask")
HugeBitsDefined 		= uint16("huge_bits_defined", "Huge Bits Defined")
HugeData			= nstring8("huge_data", "Huge Data")
HugeDataUsed			= uint32("huge_data_used", "Huge Data Used")
HugeStateInfo			= bytes("huge_state_info", "Huge State Info", 16)

IncomingPacketDiscardedNoDGroup = uint16("incoming_packet_discarded_no_dgroup", "Incoming Packet Discarded No DGroup")
InfoCount			= uint16("info_count", "Info Count")
InfoFlagsLow			= fw_string("info_flags_low", "Not Used", 3)
InfoFlagsHigh			= bitfield8("info_flags_high", "Info Flags", [
	bf_boolean8(0x10, "info_flags_security", "Return Object Security"),
	bf_boolean8(0x20, "info_flags_flags", "Return Object Flags"),
	bf_boolean8(0x40, "info_flags_type", "Return Object Type"),
	bf_boolean8(0x80, "info_flags_name", "Return Object Name"),
])
InfoMaskHigh			= bitfield8("info_mask_high", "Information Mask (byte 4)", [
	bf_boolean8(0x20, "info_mask_dosname", "DOS Name"),
	bf_boolean8(0x40, "info_mask_c_name_space", "Creator Name Space & Name"),
	bf_boolean8(0x80, "info_mask_name", "Name"),
])
InfoMaskLow1			= bitfield8("info_mask_low_1", "Information Mask", [
	bf_boolean8(0x01, "info_flags_dos_time", "DOS Time"),
	bf_boolean8(0x02, "info_flags_ref_count", "Reference Count"),
	bf_boolean8(0x04, "info_flags_dos_attr", "DOS Attributes"),
	bf_boolean8(0x08, "info_flags_ids", "ID's"),
	bf_boolean8(0x10, "info_flags_ds_sizes", "Data Stream Sizes"),
	bf_boolean8(0x20, "info_flags_ns_attr", "Name Space Attributes"),
	bf_boolean8(0x40, "info_flags_ea_present", "EA Present Flag"),
	bf_boolean8(0x80, "info_flags_all_attr", "All Attributes"),
])
InfoMaskLow2			= bitfield8("info_mask_low_2", "Information Mask (byte 2)", [
	bf_boolean8(0x01, "info_flags_all_dirbase_num", "All Directory Base Numbers"),
	bf_boolean8(0x02, "info_flags_max_access_mask", "Maximum Access Mask"),
	bf_boolean8(0x04, "info_flags_flush_time", "Flush Time"),
	bf_boolean8(0x08, "info_flags_prnt_base_id", "Parent Base ID"),
	bf_boolean8(0x10, "info_flags_mac_finder", "Mac Finder Information"),
	bf_boolean8(0x20, "info_flags_sibling_cnt", "Sibling Count"),
	bf_boolean8(0x40, "info_flags_effect_rights", "Effective Rights"),
	bf_boolean8(0x80, "info_flags_mac_time", "Mac Time"),
])
InfoMaskLow3			= val_string8("info_mask_low_3", "Information Mask (byte 3)", [
	[ 0x00, "Unused" ],
])

InheritedRightsMaskHigh 	= bitfield8("inherited_rights_mask_high", "Inherited Rights Mask (byte 2)", [
	bf_boolean8(0x01, "inh_rights_supervisor", "Supervisor"),
])
InheritedRightsMaskLow 		= bitfield8("inherited_rights_mask_low", "Inherited Rights Mask", [
	bf_boolean8(0x01, "inh_rights_read", "Read Rights"),
	bf_boolean8(0x02, "inh_rights_write", "Write Rights"),
	bf_boolean8(0x04, "inh_rights_open", "Open Rights"),
	bf_boolean8(0x08, "inh_rights_create", "Create Rights"),
	bf_boolean8(0x10, "inh_rights_delete", "Delete Rights"),
	bf_boolean8(0x20, "inh_rights_parent", "Change Access"),
	bf_boolean8(0x40, "inh_rights_search", "See Files Flag"),
	bf_boolean8(0x80, "inh_rights_modify", "Modify Rights"),
])
InheritanceRevokeMaskHigh 		= bitfield8("inheritance_revoke_mask_high", "Revoke Rights Mask (byte 2)", [
	bf_boolean8(0x01, "inh_revoke_supervisor", "Supervisor"),
])
InheritanceRevokeMaskLow 		= bitfield8("inheritance_revoke_mask_low", "Revoke Rights Mask", [
	bf_boolean8(0x01, "inh_revoke_read", "Read Rights"),
	bf_boolean8(0x02, "inh_revoke_write", "Write Rights"),
	bf_boolean8(0x04, "inh_revoke_open", "Open Rights"),
	bf_boolean8(0x08, "inh_revoke_create", "Create Rights"),
	bf_boolean8(0x10, "inh_revoke_delete", "Delete Rights"),
	bf_boolean8(0x20, "inh_revoke_parent", "Change Access"),
	bf_boolean8(0x40, "inh_revoke_search", "See Files Flag"),
	bf_boolean8(0x80, "inh_revoke_modify", "Modify Rights"),
])
InitialSemaphoreValue		= byte("initial_semaphore_value", "Initial Semaphore Value")
InspectSize			= uint32("inspect_size", "Inspect Size")
InternetBridgeVersion		= byte("internet_bridge_version", "Internet Bridge Version")
InterruptNumbersUsed 		= uint32("interrupt_numbers_used", "Interrupt Numbers Used")
InUse				= uint32("in_use", "Bytes in Use")
IOAddressesUsed			= bytes("io_addresses_used", "IO Addresses Used", 8)
IOErrorCount			= uint16("io_error_count", "IO Error Count")
IPXNotMyNetwork 		= uint16("ipx_not_my_network", "IPX Not My Network")
ItemsChanged 			= uint32("items_changed", "Items Changed")
ItemsChecked 			= uint32("items_checked", "Items Checked")
ItemsCount			= uint32("items_count", "Items Count")
ItemsInPacket			= uint32("items_in_packet", "Items in Packet")

JobControlFlags			= bitfield8("job_control_flags", "Job Control Flags", [
	bf_boolean8(0x08, "job_control_job_recovery", "Job Recovery"),
	bf_boolean8(0x10, "job_control_reservice", "ReService Job"),
	bf_boolean8(0x20, "job_control_file_open", "File Open"),
	bf_boolean8(0x40, "job_control_user_hold", "User Hold"),
	bf_boolean8(0x80, "job_control_operator_hold", "Operator Hold"),

])
JobCount			= uint32("job_count", "Job Count")
JobEntryTime			= bytes("job_entry_time", "Job Entry Time", 6)
JobFileHandle			= uint32("job_file_handle", "Job File Handle")
JobFileHandle.Display("BASE_HEX")
JobFileName			= fw_string("job_file_name", "Job File Name", 14)
JobPosition			= uint16("job_position", "Job Position")
JobNumber			= uint32("job_number", "Job Number")
JobNumberList			= uint32("job_number_list", "Job Number List")
JobType				= uint16("job_type", "Job Type")

LANDriverNumber			= byte("lan_driver_number", "LAN Driver Number")
LastAccessedDate 		= uint16("last_access_date", "Last Access Date")
LastAccessedDate.Display("BASE_HEX")
LastInstance			= uint32("last_instance", "Last Instance")
LastRecordSeen			= uint16("last_record_seen", "Last Record Seen")
LastSearchIndex			= uint16("last_search_index", "Search Index")
LastSeen			= uint32("last_seen", "Last Seen")
LastSequenceNumber		= uint16("last_sequence_number", "Sequence Number")
Level				= byte("level", "Level")
LimboDataStreamsCount		= uint32("limbo_data_streams_count", "Limbo Data Streams Count")
limbCount			= uint32("limb_count", "Limb Count")
LimboUsed			= uint32("limbo_used", "Limbo Used")
LocalConnectionID 		= uint32("local_connection_id", "Local Connection ID")
LocalConnectionID.Display("BASE_HEX")
LocalMaxPacketSize 		= uint32("local_max_packet_size", "Local Max Packet Size")
LocalMaxSendSize 		= uint32("local_max_send_size", "Local Max Send Size")
LocalMaxRecvSize 		= uint32("local_max_recv_size", "Local Max Recv Size")
LocalLoginInfoCcode		= byte("local_login_info_ccode", "Local Login Info C Code")
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
LogicalConnectionNumber		= uint16("logical_connection_number", "Logical Connection Number")
LogicalDriveCount		= byte("logical_drive_count", "Logical Drive Count")
LogicalDriveNumber 		= byte("logical_drive_number", "Logical Drive Number")
LogicalLockThreshold		= byte("logical_lock_threshold", "LogicalLockThreshold")
LogicalRecordName		= nstring8("logical_record_name", "Logical Record Name")
LoginKey			= bytes("login_key", "Login Key", 8)
# LoginTime			= bytes("login_time", "Login Time", 7)

LoginTime = struct("login_time", [
	uint8("login_time_year", "Login Time Year"),
	uint8("login_time_month", "Login Time Month"),
	uint8("login_time_day", "Login Time Day"),
	uint8("login_time_hour", "Login Time Hour"),
	uint8("login_time_minute", "Login Time Minute"),
	uint8("login_time_second", "Login Time Second"),
	uint8("login_time_weekday", "Login Time Week Day")
])


LogLockType			= byte("log_lock_type", "Log Lock Type")
LongName 			= fw_string("long_name", "Long Name", 32)
LRUBlockWasDirty		= uint16("lru_block_was_dirty", "LRU Block Was Dirty")

MacAttrLow			= bitfield8("mac_attr_low", "Attributes", [
	bf_boolean8(0x01, "mac_attr_smode1", "Search Mode"),
	bf_boolean8(0x02, "mac_attr_smode2", "Search Mode"),
	bf_boolean8(0x04, "mac_attr_smode3", "Search Mode"),
	bf_boolean8(0x08, "mac_attr_undefined", "Undefined"),
	bf_boolean8(0x10, "mac_attr_transaction", "Transaction"),
	bf_boolean8(0x20, "mac_attr_index", "Index"),
	bf_boolean8(0x40, "mac_attr_r_audit", "Read Audit"),
	bf_boolean8(0x80, "mac_attr_w_audit", "Write Audit"),
])
MacAttrHigh			= bitfield8("mac_attr_high", "Attributes (byte 2)", [
	bf_boolean8(0x01, "mac_attr_r_only", "Read Only"),
	bf_boolean8(0x02, "mac_attr_hidden", "Hidden"),
	bf_boolean8(0x04, "mac_attr_system", "System"),
	bf_boolean8(0x08, "mac_attr_execute_only", "Execute Only"),
	bf_boolean8(0x10, "mac_attr_subdirectory", "Subdirectory"),
	bf_boolean8(0x20, "mac_attr_archive", "Archive"),
	bf_boolean8(0x40, "mac_attr_undefinedl", "Undefined"),
	bf_boolean8(0x80, "mac_attr_share", "Shareable File"),
])
MacBaseDirectoryID 		= uint32("mac_base_directory_id", "Mac Base Directory ID")
MacBaseDirectoryID.Display("BASE_HEX")
MacDestinationBaseID 		= uint32("mac_destination_base_id", "Mac Destination Base ID")
MacDestinationBaseID.Display("BASE_HEX")
MacLastSeenID			= uint32("mac_last_seen_id", "Mac Last Seen ID")
MacLastSeenID.Display("BASE_HEX")
MacSourceBaseID			= uint32("mac_source_base_id", "Mac Source Base ID")
MacSourceBaseID.Display("BASE_HEX")
MaxBytes			= uint16("max_bytes", "Maximum Number of Bytes")
MaximumSpace			= uint16("max_space", "Maximum Space")
MaxSpace			= uint32("maxspace", "Maximum Space")
MaxUsedDynamicSpace 		= uint32("max_used_dynamic_space", "Max Used Dynamic Space")
MemberName			= nstring8("member_name", "Member Name")
MemberType			= val_string8("member_type", "Member Type", [
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
MigratedFiles			= uint32("migrated_files", "Migrated Files")
MigratedSectors			= uint32("migrated_sectors", "Migrated Sectors")
Minute				= byte("s_minute", "Minutes")
MixedModePathFlag		= byte("mixed_mode_path_flag", "Mixed Mode Path Flag")
ModifiedDate			= uint16("modified_date", "Modified Date")
ModifiedDate.Display("BASE_HEX")
ModifiedTime			= uint16("modified_time", "Modified Time")
ModifiedTime.Display("BASE_HEX")
ModifierID 			= uint32("modifier_id", "Modifier ID")
ModifierID.Display("BASE_HEX")
ModifyDOSInfoMaskHigh		= bitfield8("modify_dos_info_mask_high", "Modify DOS Info Mask (byte 2)", [
	bf_boolean8(0x01, "modify_dos_mdate", "Modify Date"),
	bf_boolean8(0x02, "modify_dos_mtime", "Modify Time"),
	bf_boolean8(0x04, "modify_dos_mid", "Modifier ID"),
	bf_boolean8(0x08, "modify_dos_laccess", "Last Access"),
	bf_boolean8(0x10, "modify_dos_inheritance", "Inheritance"),
	bf_boolean8(0x20, "modify_dos_max_space", "Maximum Space"),
])
ModifyDOSInfoMaskLow		= bitfield8("modify_dos_info_mask_low", "Modify DOS Info Mask", [
	bf_boolean8(0x02, "modify_dos_read", "Attributes"),
	bf_boolean8(0x04, "modify_dos_write", "Creation Date"),
	bf_boolean8(0x08, "modify_dos_open", "Creation Time"),
	bf_boolean8(0x10, "modify_dos_create", "Creator ID"),
	bf_boolean8(0x20, "modify_dos_delete", "Archive Date"),
	bf_boolean8(0x40, "modify_dos_parent", "Archive Time"),
	bf_boolean8(0x80, "modify_dos_search", "Archiver ID"),
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
	[ 0xff, "More Segments/Entries Available" ],
])
MoreProperties			= val_string8("more_properties", "More Properties", [
	[ 0x00, "No More Properties Available" ],
	[ 0xff, "More Properties Available" ],
])

Name12				= fw_string("name12", "Name", 12)
NameLen				= byte("name_len", "Name Space Length")
NameList			= uint32("name_list", "Name List")
NameSpace 			= val_string8("name_space", "Name Space", [
	[ 0x00, "DOS" ],
	[ 0x01, "MAC" ],
	[ 0x02, "NFS" ],
	[ 0x03, "FTAM" ],
	[ 0x04, "OS/2" ],
])
NamesSpaceInfoMask1			= bitfield8("ns_info_mask1", "Names Space Info Mask", [
	bf_boolean8(0x01, "ns_info_mask_modify", "Modify Name"),
	bf_boolean8(0x02, "ns_info_mask_fatt", "File Attributes"),
	bf_boolean8(0x04, "ns_info_mask_cdate", "Creation Date"),
	bf_boolean8(0x08, "ns_info_mask_ctime", "Creation Time"),
	bf_boolean8(0x10, "ns_info_mask_owner", "Owner ID"),
	bf_boolean8(0x20, "ns_info_mask_adate", "Archive Date"),
	bf_boolean8(0x40, "ns_info_mask_atime", "Archive Time"),
	bf_boolean8(0x80, "ns_info_mask_aid", "Archiver ID"),
])
NamesSpaceInfoMask2			= bitfield8("ns_info_mask2", "Names Space Info Mask (byte 2)", [
	bf_boolean8(0x01, "ns_info_mask_udate", "Update Date"),
	bf_boolean8(0x02, "ns_info_mask_utime", "Update Time"),
	bf_boolean8(0x04, "ns_info_mask_uid", "Update ID"),
	bf_boolean8(0x08, "ns_info_mask_acc_date", "Access Date"),
	bf_boolean8(0x10, "ns_info_mask_max_acc_mask", "Inheritance"),
	bf_boolean8(0x20, "ns_info_mask_max_space", "Maximum Space"),
])

NameSpaceName			= fw_string("name_space_name", "Name Space Name", 255)
nameType			= uint32("name_type", "nameType")
NCPdataSize			= uint32("ncp_data_size", "NCP Data Size")
NCPextensionMajorVersion	= byte("ncp_extension_major_version", "NCP Extension Major Version")
NCPextensionMinorVersion 	= byte("ncp_extension_minor_version", "NCP Extension Minor Version")
NCPextensionName 		= nstring8("ncp_extension_name", "NCP Extension Name")
NCPextensionNumber 		= uint32("ncp_extension_number", "NCP Extension Number")
NCPextensionNumber.Display("BASE_HEX")
NCPExtensionNumbers		= uint32("ncp_extension_numbers", "NCP Extension Numbers")
NCPextensionRevisionNumber	= byte("ncp_extension_revision_number", "NCP Extension Revision Number")
NetWareAccessHandle		= bytes("netware_access_handle", "NetWare Access Handle", 6)
NewFileName			= nstring8("new_file_name", "New Filename")
NewPosition			= byte("new_position", "New Position")
nextLimbScanNum			= uint32("next_limb_scan_num", "Next Limb Scan Number")
NextSearchIndex			= uint16("next_search_index", "Next Search Index")
nextStartingNumber 		= uint32("next_starting_number", "Next Starting Number")
NextTrusteeEntry		= uint32("next_trustee_entree", "Next Trustee Entry")
NumberOfAttributes		= uint32("number_of_attributes", "Number of Attributes")
NumberOfDynamicMemoryAreas 	= uint16("number_of_dynamic_memory_areas", "Number Of Dynamic Memory Areas")
NumberOfEntries			= byte("number_of_entries", "Number of Entries")
NumOfFilesMigrated 		= uint32("num_of_files_migrated", "Number Of Files Migrated")
NumberOfServiceProcesses 	= byte("number_of_service_processes", "Number Of Service Processes")
NumBytes			= uint16("num_bytes", "Number of Bytes")
NDSFlags			= uint32("nds_flags", "NDS Flags")
NDSFlags.Display('BASE_HEX')
NDSRequestFlagsHigh 		= bitfield8("nds_request_flags_high", "NDS Request Flags (byte 2)", [
	bf_boolean8(0x01, "nds_request_flags_trans_ref", "Transport Referral"),
	bf_boolean8(0x02, "nds_request_flags_trans_ref2", "Transport Referral"),
	bf_boolean8(0x04, "nds_request_flags_up_ref", "Up Referral"),
	bf_boolean8(0x08, "nds_request_flags_dn_ref", "Down Referral"),
])	
NDSRequestFlagsLow 		= bitfield8("nds_request_flags_low", "NDS Request Flags", [
	bf_boolean8(0x01, "nds_request_flags_output", "Output Fields"),
	bf_boolean8(0x02, "nds_request_flags_no_such_entry", "No Such Entry"),
	bf_boolean8(0x04, "nds_request_flags_local_entry", "Local Entry"),
	bf_boolean8(0x08, "nds_request_flags_type_ref", "Type Referral"),
	bf_boolean8(0x10, "nds_request_flags_alias_ref", "Alias Referral"),
	bf_boolean8(0x20, "nds_request_flags_req_cnt", "Request Count"),
	bf_boolean8(0x40, "nds_request_flags_req_data_size", "Request Data Size"),
	bf_boolean8(0x80, "nds_request_flags_reply_data_size", "Reply Data Size"),
])	
NDSVerb				= val_string16("nds_verb", "NDS Verb", [
	[ 0x0001, "Resolve Name" ],
	[ 0x0002, "Read Entry Information" ],
	[ 0x0003, "Read" ],
	[ 0x0004, "Compare" ],
	[ 0x0005, "List" ],
	[ 0x0006, "Search" ],
	[ 0x0007, "Add Entry" ],
	[ 0x0008, "Remove Entry" ],
	[ 0x0009, "Modify Entry" ],
	[ 0x000a, "Modify Relative Distinguished Name" ],
	[ 0x000b, "Define Attribute" ],
	[ 0x000c, "Read Attribute Definition" ],
	[ 0x000d, "Remove Attribute Definition" ],
	[ 0x000e, "Define Class" ],
	[ 0x000f, "Read Class Definition" ],
	[ 0x0010, "Modify Class Definition" ],
	[ 0x0011, "Remove Class Definition" ],
	[ 0x0012, "List Containable Classes" ],
	[ 0x0013, "Get Effective Rights" ],
	[ 0x0016, "List Partitions" ],
	[ 0x0017, "Split Partition" ],
	[ 0x0018, "Join Partitions" ],
	[ 0x0019, "Add Replica" ],
	[ 0x001a, "Remove Replica" ],
	[ 0x001b, "Open Stream" ],
	[ 0x001c, "Search Filter" ],
	[ 0x001d, "Create Subordinate Reference" ],
	[ 0x001e, "Link Replica" ],
	[ 0x001f, "Change Replica Type" ],
	[ 0x0020, "Start Update Schema" ],
	[ 0x0021, "End Update Schema" ],
	[ 0x0022, "Update Schema" ],
	[ 0x0023, "Start Update Replica" ],
	[ 0x0024, "End Update Replica" ],
	[ 0x0025, "Update Replica" ],
	[ 0x0026, "Synchronize Partition" ],
	[ 0x0027, "Synchronize Schema" ],
	[ 0x0028, "Read Syntaxes" ],
	[ 0x0029, "Get Replica ROOT ID" ],
	[ 0x002a, "Begin Move Entry" ],
	[ 0x002b, "Finish Move Entry" ],
	[ 0x002c, "Release Moved Entry" ],
	[ 0x002d, "Backup Entry" ],
	[ 0x002e, "Restore Entry" ],
	[ 0x002f, "Obsolete - Save DIB" ],
	[ 0x0030, "Control" ],
	[ 0x0031, "Remove Backlink" ],
	[ 0x0032, "Close Iteration" ],
	[ 0x0033, "Mutate Entry" ],
	[ 0x0034, "Audit Skulking" ],
	[ 0x0035, "Get Server Address" ],
	[ 0x0036, "Authentication/Login" ],
	[ 0x0037, "Authentication/Login" ],
	[ 0x0038, "Authentication/Login" ],
	[ 0x0039, "Authentication/Login" ],
	[ 0x003a, "Authentication/Login" ],
	[ 0x003b, "Authentication/Login" ],
	[ 0x003c, "Authentication/Login" ],
	[ 0x003d, "Authentication/Login" ],
	[ 0x003e, "Obsolete" ],
	[ 0x003f, "Repair Time Stamps" ],
	[ 0x0040, "Create Backlink" ],
	[ 0x0041, "Delete External Reference" ],
	[ 0x0042, "Rename External Reference" ],
	[ 0x0043, "Create Entry Dir" ],
	[ 0x0044, "Remove Entry Dir" ],
	[ 0x0045, "Merge Entries" ],
	[ 0x0046, "Change Tree Name" ],
	[ 0x0047, "Partition Entry Count" ],
	[ 0x0049, "Start Join" ],
	[ 0x004a, "Low Level Split" ],
	[ 0x004b, "Low Level Join" ],
	[ 0x004c, "Abort Partition Operation" ],
	[ 0x004d, "Get All Servers" ],
	[ 0x004e, "Partition Function" ],
	[ 0x004f, "Read References" ],
	[ 0x0050, "Inspect Entry" ],
	[ 0x0051, "Get Remote Entry ID" ],
	[ 0x0052, "Change Security" ],
	[ 0x0053, "Check Console Operator" ],
	[ 0x0054, "Start Move Tree" ],
	[ 0x0055, "Move Tree" ],
	[ 0x0056, "End Move Tree" ],
	[ 0x0057, "Low Level Abort Join" ],
	[ 0x0058, "Check Sev" ],
	[ 0x0059, "Move Tree" ],
	[ 0x0060, "Sync External Reference" ],
	[ 0x005b, "Resend Entry" ],
	[ 0x005c, "New Schema Epoch" ],
	[ 0x005d, "Statistics" ],
	[ 0x005e, "Ping" ],
	[ 0x005f, "Get Bindery Contexts" ],
	[ 0x0060, "Monitor Connection" ],
	[ 0x0061, "Get DS Statistics" ],
	[ 0x0062, "Reset DS Counters" ],
	[ 0x0063, "Console" ],
	[ 0x0064, "Read Stream File" ],
	[ 0x0065, "Write Stream File" ],
	[ 0x0066, "Create Orphan Partition" ],
	[ 0x0067, "Remove Orphan Partition" ],
	[ 0x0068, "Link Orphan Partition" ],
	[ 0x0069, "Set DRL" ],
	[ 0x006a, "GUID Create" ],
	[ 0x006b, "GUID Info" ],
	[ 0x006c, "Verify DRL" ],
	[ 0x006d, "Verify Partition" ],
	[ 0x006e, "Iterator" ],
	[ 0x0070, "Close Stream File" ],
	[ 0x0072, "Read Status" ],
	[ 0x0073, "Partition Sync Status" ],
	[ 0x0074, "Read Ref Data" ],
	[ 0x0075, "Write Ref Data" ],
	[ 0x0076, "Resource Event" ],
	[ 0x0077, "DIB Request" ],
	[ 0x0078, "Set Replication Filter" ],
	[ 0x0079, "Get Replication Filter" ],
	[ 0x00fe, "NDS Version - For NDS Verb see 8 bits more in Hex data" ],
])
NDSVersion			= uint32("nds_version", "NDS Version")
NDSCRC				= uint32("nds_crc", "NDS CRC")
NDSCRC.Display('BASE_HEX')
NDSBuildVersion			= uint32("nds_build_version", "NDS Build Version")
NDSStatus			= uint32("nds_status", "NDS Status")
NetBIOSBroadcastWasPropogated	= uint32("netbios_broadcast_was_propogated", "NetBIOS Broadcast Was Propogated")
NetworkAddress			= uint32("network_address", "Network Address")
NetworkNodeAddress		= bytes("network_node_address", "Network Node Address", 6)
NetworkSocket			= uint16("network_socket", "Network Socket")
NewAccessRightsHigh 		= bitfield8("new_access_rights_high", "New Access Rights (byte 2)", [
	bf_boolean8(0x01, "new_access_rights_supervisor", "Supervisor"),
])
NewAccessRights 		= bitfield8("new_access_rights_mask", "New Access Rights", [
	bf_boolean8(0x01, "new_access_rights_read", "Read"),
	bf_boolean8(0x02, "new_access_rights_write", "Write"),
	bf_boolean8(0x04, "new_access_rights_open", "Open"),
	bf_boolean8(0x08, "new_access_rights_create", "Create"),
	bf_boolean8(0x10, "new_access_rights_delete", "Delete"),
	bf_boolean8(0x20, "new_access_rights_parental", "Parental"),
	bf_boolean8(0x40, "new_access_rights_search", "Search"),
	bf_boolean8(0x80, "new_access_rights_modify", "Modify"),
])

NewDirectoryID			= uint32("new_directory_id", "New Directory ID")
NewDirectoryID.Display("BASE_HEX")
NewEAHandle			= uint32("new_ea_handle", "New EA Handle")
NewEAHandle.Display("BASE_HEX")
NewFileName			= fw_string("new_file_name", "New File Name", 15)
NewFileNameLen			= nstring8("new_file_name_len", "New File Name")
NewFileSize			= uint32("new_file_size", "New File Size")
NewPassword			= nstring8("new_password", "New Password")
NewPath 			= nstring8("new_path", "New Path")
NewObjectName			= fw_string("new_object_name", "New Object Name", 48)
NextHugeStateInfo		= bytes("next_huge_state_info", "Next Huge State Info", 16)
NextObjectID			= uint32("next_object_id", "Next Object ID")
NextObjectID.Display("BASE_HEX")
NextRecord			= uint32("next_record", "Next Record")
NextRequestRecord 		= uint16("next_request_record", "Next Request Record")
NextSearchNumber		= uint16("next_search_number", "Next Search Number")
NextTrusteeEntry		= uint32("next_trustee_entry", "Next Trustee Entry")
NextVolumeNumber		= uint32("next_volume_number", "Next Volume Number")
nodeFlags 			= uint32("node_flags", "Node Flags")
nodeFlags.Display("BASE_HEX")
NonFreeableAvailableSubAllocSectors = uint32("non_freeable_avail_sub_alloc_sectors", "Non Freeable Available Sub Alloc Sectors")
NonFreeableLimboSectors		= uint32("non_freeable_limbo_sectors", "Non Freeable Limbo Sectors")
NotUsableSubAllocSectors	= uint32("not_usable_sub_alloc_sectors", "Not Usable Sub Alloc Sectors")
NotYetPurgeableBlocks		= uint32("not_yet_purgeable_blocks", "Not Yet Purgeable Blocks")
NumberOfDataStreams 		= uint16("number_of_data_streams", "Number of Data Streams")
NumberOfEntries			= byte("number_of_entries", "Number Of Entries")
NumberOfLocks			= byte("number_of_locks", "Number of Locks")
NumberOfMinutesToDelay		= uint32("number_of_minutes_to_delay", "Number of Minutes to Delay")
NumberOfNCPExtensions		= uint32("number_of_ncp_extensions", "Number Of NCP Extensions")
NumberOfNSLoaded		= uint16("number_of_ns_loaded", "Number Of Name Spaces Loaded")
NumberOfRecords			= uint16("number_of_records", "Number of Records")
NumberOfSemaphores		= uint16("number_of_semaphores", "Number Of Semaphores")
NumberOfStations		= byte("number_of_stations", "Number of Stations")
NSInfoBitMask			= uint32("ns_info_bit_mask", "Name Space Info Bit Mask")
NSSpecificInfo			= fw_string("ns_specific_info", "Name Space Specific Info", 512)					 

ObjectFlags			= val_string8("object_flags", "Object Flags", [
	[ 0x00, "Dynamic object" ],
	[ 0x01, "Static object" ],
])
ObjectHasProperties 		= val_string8("object_has_properites", "Object Has Properties", [
	[ 0x00, "No properties" ],
	[ 0xff, "One or more properties" ],
])
ObjectID			= uint32("object_id", "Object ID")
ObjectID.Display('BASE_HEX')
ObjectIDCount 			= uint16("object_id_count", "Object ID Count")
ObjectIDInfo			= uint32("object_id_info", "Object Information")
ObjectInfoReturnCount		= uint32("object_info_rtn_count", "Object Information Count")
ObjectName			= nstring8("object_name", "Object Name")
ObjectNameLen			= fw_string("object_name_len", "Object Name", 48)
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
OpenCreateMode 			= val_string8("open_create_mode", "Open Create Mode", [
	[ 0x00, "Invalid action" ],
	[ 0x01, "Open existing file (file must exist)" ],
	[ 0x02, "Open existing file and truncate it, else create a new file" ],
	[ 0x03, "Open existing file and truncate it (file must exist)" ],
	[ 0x08, "Create new file or subdirectory (file or subdirectory cannot exist)" ],
	[ 0x09, "Open existing file or create a new file" ],
	[ 0x0a, "Open existing file and truncate it, else create a new file" ],
	[ 0x0b, "Open existing file and truncate it, else create a new file" ],
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
OptionNumber			= byte("option_number", "Option Number")
OSLanguageID			= byte("os_language_id", "OS Language ID")
OSMajorVersion			= byte("os_major_version", "OS Major Version")
OSMinorVersion			= byte("os_minor_version", "OS Minor Version")
OSRevision			= byte("os_revision", "OS Revision")
OtherFileForkSize		= uint32("other_file_fork_size", "Other File Fork Size")
OtherFileForkFAT		= uint32("other_file_fork_fat", "Other File Fork FAT Entry")
OutgoingPacketDiscardedNoTurboBuffer = uint16("outgoing_packet_discarded_no_turbo_buffer", "Outgoing Packet Discarded No Turbo Buffer")

PacketsDiscardedByHopCount 	= uint16("packets_discarded_by_hop_count", "Packets Discarded By Hop Count")
PacketsDiscardedUnknownNet 	= uint16("packets_discarded_unknown_net", "Packets Discarded Unknown Net")
PacketsFromInvalidConnection 	= uint16("packets_from_invalid_connection", "Packets From Invalid Connection")
PacketsReceivedDuringProcessing = uint16("packets_received_during_processing", "Packets Received During Processing")
PacketsWithBadRequestType 	= uint16("packets_with_bad_request_type", "Packets With Bad Request Type")
PacketsWithBadSequenceNumber 	= uint16("packets_with_bad_sequence_number", "Packets With Bad Sequence Number")
ParentID			= uint32("parent_id", "Parent ID")
ParentID.Display("BASE_HEX")
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
PendingIOCommands 		= uint16("pending_io_commands", "Pending IO Commands")
PhysicalDiskNumber		= byte("physical_disk_number", "Physical Disk Number")
PhysicalDriveCount		= byte("physical_drive_count", "Physical Drive Count")
PhysicalLockThreshold		= byte("physical_lock_threshold", "Physical Lock Threshold")
PingVersion			= uint16("ping_version", "Ping Version")
PositiveAcknowledgesSent 	= uint16("positive_acknowledges_sent", "Positive Acknowledges Sent")
PreCompressedSectors		= uint32("pre_compressed_sectors", "Precompressed Sectors")
PreviousRecord			= uint32("previous_record", "Previous Record")
PrimaryEntry			= uint32("primary_entry", "Primary Entry")
PrintFlags			= bitfield8("print_flags", "Print Flags", [
	bf_boolean8(0x08, "print_flags_ff", "Suppress Form Feeds"),
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
PrintServerVersion		= byte("print_server_version", "Print Server Version")
Priority			= uint32("priority", "Priority")
ProcessorType 			= val_string8("processor_type", "Processor Type", [
	[ 0x00, "Motorola 68000" ],
	[ 0x01, "Intel 8088 or 8086" ],
	[ 0x02, "Intel 80286" ],
])
ProDOSInfo			= bytes("pro_dos_info", "Pro DOS Info", 6)
ProductMajorVersion		= uint16("product_major_version", "Product Major Version")
ProductMinorVersion		= uint16("product_minor_version", "Product Minor Version")
ProductRevisionVersion		= byte("product_revision_version", "Product Revision Version")
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
PurgeCount			= uint32("purge_count", "Purge Count")
PurgeFlags			= val_string16("purge_flags", "Purge Flags", [
	[ 0x0000, "Do not Purge All" ],
	[ 0x0001, "Purge All" ],
])
PhysicalDiskChannel		= byte("physical_disk_channel", "Physical Disk Channel")
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
QMSVersion			= byte("qms_version", "QMS Version")

ReadBeyondWrite			= uint16("read_beyond_write", "Read Beyond Write")
RecordStart			= uint32("record_start", "Record Start")
RecordEnd 			= uint32("record_end", "Record End")
RecordInUseFlag			= val_string16("record_in_use", "Record in Use", [
	[ 0x0000, "Record In Use" ],
	[ 0xffff, "Record Not In Use" ],
])	
RedirectedPrinter 		= byte( "redirected_printer", "Redirected Printer" )
ReferenceCount			= uint32("reference_count", "Reference Count")
RelationsCount			= uint16("relations_count", "Relations Count")
ReMirrorCurrentOffset 		= uint32("re_mirror_current_offset", "ReMirror Current Offset")
ReMirrorDriveNumber 		= byte("re_mirror_drive_number", "ReMirror Drive Number")
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
RequestBitMapHigh 		= bitfield8("request_bit_map_high", "Request Bit Map (byte 2)", [
	bf_boolean8(0x01, "request_bit_map_ratt", "Return Attributes"),
	bf_boolean8(0x02, "request_bit_map_ret_afp_parent", "AFP Parent Entry ID"),
	bf_boolean8(0x04, "request_bit_map_ret_cr_date", "Creation Date"),
	bf_boolean8(0x08, "request_bit_map_ret_acc_date", "Access Date"),
	bf_boolean8(0x10, "request_bit_map_ret_mod_date", "Modify Date&Time"),
	bf_boolean8(0x20, "request_bit_map_ret_bak_date", "Backup Date&Time"),
	bf_boolean8(0x40, "request_bit_map_ret_finder", "Finder Info"),
	bf_boolean8(0x80, "request_bit_map_ret_long_nm", "Long Name"),
])
RequestBitMapLow 		= bitfield8("request_bit_map_low", "Bit Map", [
	bf_boolean8(0x01, "request_bit_map_ret_afp_ent", "AFP Entry ID"),
	bf_boolean8(0x02, "request_bit_map_ret_data_fork", "Data Fork Length"),
	bf_boolean8(0x04, "request_bit_map_ret_res_fork", "Resource Fork Length"),
	bf_boolean8(0x08, "request_bit_map_ret_num_off", "Number of Offspring"),
	bf_boolean8(0x10, "request_bit_map_ret_owner", "Owner ID"),
	bf_boolean8(0x20, "request_bit_map_ret_short", "Short Name"),
	bf_boolean8(0x40, "request_bit_map_ret_acc_priv", "Access Privileges"),
])		
ResourceForkLen			= uint32("resource_fork_len", "Resource Fork Len")
RequestCode			= val_string8("request_code", "Request Code", [
	[ 0x00, "Change Logged in to Temporary Authenticated" ],
	[ 0x01, "Change Temporary Authenticated to Logged in" ],
])
RequestData			= nstring8("request_data", "Request Data")
RequestsReprocessed 		= uint16("requests_reprocessed", "Requests Reprocessed")
Reserved			= byte( "reserved", "Reserved" )
Reserved2			= bytes("reserved2", "Reserved", 2)
Reserved3			= bytes("reserved3", "Reserved", 3)
Reserved4			= bytes("reserved4", "Reserved", 4)
Reserved16			= bytes("reserved16", "Reserved", 16)
Reserved28			= bytes("reserved28", "Reserved", 28)
Reserved36			= bytes("reserved36", "Reserved", 36)
Reserved44			= bytes("reserved44", "Reserved", 44)
Reserved48			= bytes("reserved48", "Reserved", 48)
Reserved51			= bytes("reserved51", "Reserved", 51)
Reserved56			= bytes("reserved56", "Reserved", 56)
Reserved64			= bytes("reserved64", "Reserved", 64)
Reserved120			= bytes("reserved120", "Reserved", 120)					 
ReservedOrDirectoryNumber	= uint32("reserved_or_directory_number", "Reserved or Directory Number (see EAFlags)")
ResourceForkSize		= uint32("resource_fork_size", "Resource Fork Size")
RestoreTime 			= uint32("restore_time", "Restore Time")
Restriction			= uint32("restriction", "Disk Space Restriction")
RestrictionsEnforced 		= val_string8("restrictions_enforced", "Disk Restrictions Enforce Flag", [
	[ 0x00, "Enforced" ],
	[ 0xff, "Not Enforced" ],
])
ReturnInfoCount			= uint32("return_info_count", "Return Information Count")
ReturnInfoMaskHigh 		= bitfield8("ret_info_mask_high", "Return Information (byte 2)", [
	bf_boolean8(0x01, "ret_info_mask_create", "Return Creation Information"),
	bf_boolean8(0x02, "ret_info_mask_ns", "Return Name Space Information"),
	bf_boolean8(0x04, "ret_info_mask_dir", "Return Directory Information"),
	bf_boolean8(0x08, "ret_info_mask_rights", "Return Rights Information"),
	bf_boolean8(0x10, "ret_info_mask_id", "Return ID Information"),
	bf_boolean8(0x20, "ret_info_mask_ns_attr", "Return Name Space Attributes Information"),
	bf_boolean8(0x40, "ret_info_mask_actual", "Return Actual Information"),
	bf_boolean8(0x80, "ret_info_mask_logical", "Return Logical Information"),
])
ReturnInfoMaskLow 		= bitfield8("ret_info_mask_low", "Return Information", [
	bf_boolean8(0x01, "ret_info_mask_fname", "Return File Name Information"),
	bf_boolean8(0x02, "ret_info_mask_alloc", "Return Allocation Space Information"),
	bf_boolean8(0x04, "ret_info_mask_attr", "Return Attribute Information"),
	bf_boolean8(0x08, "ret_info_mask_size", "Return Size Information"),
	bf_boolean8(0x10, "ret_info_mask_tspace", "Return Total Space Information"),
	bf_boolean8(0x20, "ret_info_mask_eattr", "Return Extended Attributes Information"),
	bf_boolean8(0x40, "ret_info_mask_arch", "Return Archive Information"),
	bf_boolean8(0x80, "ret_info_mask_mod", "Return Modify Information"),
])
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
ReturnedListCount		= uint32("returned_list_count", "Returned List Count")
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
SalvageableFileEntryNumber	= uint32("salvageable_file_entry_number", "Salvageable File Entry Number")
SalvageableFileEntryNumber.Display("BASE_HEX")
ScanItems			= uint32("scan_items", "Number of Items returned from Scan")
SearchAttributes		= bitfield8("search_attr", "Search Attributes", [
	bf_boolean8(0x01, "search_attr_hid", "Hidden"),
	bf_boolean8(0x02, "search_attr_sys", "System"),
	bf_boolean8(0x04, "search_attr_sub", "Subdirectory"),
])	
SearchAttributesHigh 		= bitfield8("search_att_high", "Search Attributes (byte 2)", [
	bf_boolean8(0x80, "search_attr_all_files", "All Files and Directories"),
])
SearchAttributesLow		= bitfield8("search_att_low", "Search Attributes", [
	bf_boolean8(0x01, "search_att_read_only", "Read Only"),
	bf_boolean8(0x02, "search_att_hidden", "Hidden"),
	bf_boolean8(0x04, "search_att_system", "System"),
	bf_boolean8(0x08, "search_att_execute_only", "Execute Only"),
	bf_boolean8(0x10, "search_att_sub", "Subdirectory"),
	bf_boolean8(0x20, "search_att_archive", "Archive"),
	bf_boolean8(0x40, "search_att_execute_confrim", "Execute Confirm"),
	bf_boolean8(0x80, "search_att_shareable", "Shareable"),
])
SearchBitMap				= bitfield8("search_bit_map", "Search Bit Map", [
	bf_boolean8(0x01, "search_bit_map_hidden", "Hidden"),
	bf_boolean8(0x02, "search_bit_map_sys", "System"),
	bf_boolean8(0x04, "search_bit_map_sub", "Subdirectory"),
	bf_boolean8(0x08, "search_bit_map_files", "Files"),
])	
SearchInstance				= uint32("search_instance", "Search Instance")
SearchPattern				= nstring8("search_pattern", "Search Pattern")
SearchSequence				= bytes("search_sequence", "Search Sequence", 9)
Second					= byte("s_second", "Seconds")
SecurityEquivalentList			= fw_string("security_equiv_list", "Security Equivalent List", 128) 
SecurityFlag				= bitfield8("security_flag", "Security Flag", [
	bf_boolean8(0x01, "checksuming", "Checksumming"),
	bf_boolean8(0x02, "signature", "Signature"),
	bf_boolean8(0x04, "complete_signatures", "Complete Signatures"),
	bf_boolean8(0x08, "encryption", "Encryption"),
	bf_boolean8(0x80, "large_internet_packets", "Large Internet Packets (LIP) Disabled"),
])	
SecurityRestrictionVersion		= byte("security_restriction_version", "Security Restriction Version")
SectorsPerBlock				= byte("sectors_per_block", "Sectors Per Block")
SectorsPerCluster			= uint16("sectors_per_cluster", "Sectors Per Cluster" )
SectorsPerTrack 			= byte("sectors_per_track", "Sectors Per Track")
SectorSize				= uint32("sector_size", "Sector Size")
SemaphoreHandle				= uint32("semaphore_handle", "Semaphore Handle")
SemaphoreName				= nstring8("semaphore_name", "Semaphore Name")
SemaphoreNameLen 			= byte("semaphore_name_len", "Semaphore Name Len")
SemaphoreOpenCount			= byte("semaphore_open_count", "Semaphore Open Count")
SemaphoreShareCount			= byte("semaphore_share_count", "Semaphore Share Count")
SemaphoreTimeOut			= uint16("semaphore_time_out", "Semaphore Time Out")
SemaphoreValue				= uint16("semaphore_value", "Semaphore Value")
SendStatus				= val_string8("send_status", "Send Status", [
	[ 0x00, "Successful" ],
	[ 0x01, "Illegal Station Number" ],
	[ 0x02, "Client Not Logged In" ],
	[ 0x03, "Client Not Accepting Messages" ],
	[ 0x04, "Client Already has a Message" ],
	[ 0x96, "No Alloc Space for the Message" ],
])
SequenceByte			= byte("sequence_byte", "Sequence")
SequenceNumber			= uint32("sequence_number", "Sequence Number")
SequenceNumber.Display("BASE_HEX")
ServerIDList			= uint32("server_id_list", "Server ID List")
ServerID			= uint32("server_id_number", "Server ID")
ServerID.Display("BASE_HEX")
serverListFlags			= uint32("server_list_flags", "Server List Flags")
ServerName			= fw_string("server_name", "Server Name", 48)
serverName50 			= fw_string("server_name50", "Server Name", 50)
ServerNameLen			= nstring8("server_name_len", "Server Name")
ServerNetworkAddress		= bytes("server_network_address", "Server Network Address", 10)
ServerSerialNumber		= uint32("server_serial_number", "Server Serial Number")
ServerStation			= uint32("server_station", "Server Station")
ServerStatusRecord		= fw_string("server_status_record", "Server Status Record", 64)
ServerTaskNumber		= uint32("server_task_number", "Server Task Number")
ServerUtilizationPercentage 	= byte("server_utilization_percentage", "Server Utilization Percentage")
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
SFTErrorTable 			= bytes("sft_error_table", "SFT Error Table", 60)
SFTSupportLevel			= val_string8("sft_support_level", "SFT Support Level", [
	[ 0x01, "Server Offers Hot Disk Error Fixing" ],
	[ 0x02, "Server Offers Disk Mirroring and Transaction Tracking" ],
	[ 0x03, "Server Offers Physical Server Mirroring" ],
])
ShareableLockCount		= uint16("shareable_lock_count", "Shareable Lock Count")
SharedMemoryAddresses 		= bytes("shared_memory_addresses", "Shared Memory Addresses", 10)
ShortName 			= fw_string("short_name", "Short Name", 12)
SoftwareDescription 		= fw_string("software_description", "Software Description", 65)
SoftwareDriverType 		= byte("software_driver_type", "Software Driver Type")
SoftwareMajorVersionNumber	= byte("software_major_version_number", "Software Major Version Number")
SoftwareMinorVersionNumber	= byte("software_minor_version_number", "Software Minor Version Number")
SourceDirHandle			= byte("source_dir_handle", "Source Directory Handle")
sourceOriginateTime 		= bytes("source_originate_time", "Source Originate Time", 8)
sourceOriginateTime.Display("BASE_HEX")
SourcePath			= fw_string("source_path", "Source Path", 255)
SourcePathComponentCount 	= byte("source_component_count", "Source Path Component Count")
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
StartingBlock 			= uint16("starting_block", "Starting Block")
StartingNumber 			= uint32("starting_number", "Starting Number")
StartingSearchNumber		= uint16("start_search_number", "Start Search Number")
StartNumber 			= uint32("start_number", "Start Number")
startNumberFlag 		= uint16("start_number_flag", "Start Number Flag")
StartVolumeNumber		= uint32("start_volume_number", "Starting Volume Number")
StationList			= uint32("station_list", "Station List")
StationNumber			= bytes("station_number", "Station Number", 3)
StatusFlagBitsHigh		= val_string16("status_flag_bits_high", "Status Flag (byte 2)", [
	[ 0x0000, "Traditional Volume" ],
	[ 0x8000, "NSS Volume" ],
])
StatusFlagBitsLow		= bitfield8("status_flag_bits_low", "Status Flag", [
	bf_boolean8(0x01, "status_flag_bits_suballoc", "Sub Allocation"),
	bf_boolean8(0x02, "status_flag_bits_comp", "Compression"),
	bf_boolean8(0x04, "status_flag_bits_migrate", "Migration"),
	bf_boolean8(0x08, "status_flag_bits_audit", "Audit"),
	bf_boolean8(0x10, "status_flag_bits_ro", "Read Only"),
	bf_boolean8(0x20, "status_flag_bits_im_purge", "Immediate Purge"),
])
SubAllocClusters		= uint32("sub_alloc_clusters", "Sub Alloc Clusters")
SubAllocFreeableClusters 	= uint32("sub_alloc_freeable_clusters", "Sub Alloc Freeable Clusters")
Subdirectory			= uint32("sub_directory", "Subdirectory", LE)
Subdirectory.Display("BASE_HEX")
SuggestedFileSize		= uint32("suggested_file_size", "Suggested File Size")
SupportModuleID			= uint32("support_module_id", "Support Module ID")
SYear				= val_string8("s_year", "Year", [
	[0x64, "2000"],
	[0x65, "2001"],
	[0x66, "2002"],
	[0x67, "2003"],
	[0x68, "2004"],
	[0x69, "2005"],
	[0x6a, "2006"],
	[0x6b, "2007"],
	[0x6c, "2008"],
	[0x6d, "2009"],
])
SynchName			= nstring8("synch_name", "Synch Name")
SystemIntervalMarker		= uint32("system_interval_marker", "System Interval Marker")

TabSize				= byte( "tab_size", "Tab Size" )
TargetClientList		= uint32("target_client_list", "Target List")
TargetConnectionNumber		= uint16("target_connection_number", "Target Connection Number")
TargetDirectoryBase		= uint32("target_directory_base", "Target Directory Base")
TargetDirHandle			= byte("target_dir_handle", "Target Directory Handle")
TargetEntryID			= uint32("target_entry_id", "Target Entry ID")
TargetEntryID.Display("BASE_HEX")
TargetExecutionTime		= bytes("target_execution_time", "Target Execution Time", 6)
TargetFileHandle		= bytes("target_file_handle", "Target File Handle", 6)
TargetFileOffset		= uint32("target_file_offset", "Target File Offset")
TargetMessage			= nstring8("target_message", "Message")
TargetPrinter			= byte( "target_ptr", "Target Printer" )
targetReceiveTime 		= bytes("target_receive_time", "Target Receive Time", 8)
targetReceiveTime.Display("BASE_HEX")
TargetServerIDNumber		= uint32("target_server_id_number", "Target Server ID Number")
TargetServerIDNumber.Display("BASE_HEX")
targetTransmitTime 		= bytes("target_transmit_time", "Target Transmit Time", 8)
targetTransmitTime.Display("BASE_HEX")
TaskNumber			= uint32("task_number", "Task Number")
TextJobDescription		= fw_string("text_job_description", "Text Job Description", 50)
ThrashingCount			= uint16("thrashing_count", "Thrashing Count")
TimeoutLimit			= uint16("timeout_limit", "Timeout Limit")
TotalBlocks			= uint32("total_blocks", "Total Blocks")	
TotalCacheWrites 		= uint32("total_cache_writes", "Total Cache Writes")
TotalChangedFATs		= uint32("total_changed_fats", "Total Changed FAT Entries")
TotalDirectorySlots		= uint16("total_directory_slots", "Total Directory Slots")
TotalDirectoryEntries		= uint32("total_dir_entries", "Total Directory Entries")
TotalDynamicSpace 		= uint32("total_dynamic_space", "Total Dynamic Space")
TotalExtendedDirectoryExtants	= uint32("total_extended_directory_extants", "Total Extended Directory Extants")
TotalFileServicePackets		= uint32("total_file_service_packets", "Total File Service Packets")
TotalFilesOpened		= uint32("total_files_opened", "Total Files Opened")
TotalOffspring			= uint16("total_offspring", "Total Offspring")
TotalOtherPackets 		= uint32("total_other_packets", "Total Other Packets")
TotalQueueJobs			= uint32("total_queue_jobs", "Total Queue Jobs")
TotalReadRequests		= uint32("total_read_requests", "Total Read Requests")
TotalRequest			= uint32("total_request", "Total Request")
TotalRequestPackets		= uint32("total_request_packets", "Total Request Packets")
TotalRoutedPackets 		= uint32("total_routed_packets", "Total Routed Packets")
TotalServerMemory 		= uint16("total_server_memory", "Total Server Memory")
TotalTransactionsBackedOut	= uint32("total_trans_backed_out", "Total Transactions Backed Out")
TotalTransactionsPerformed	= uint32("total_trans_performed", "Total Transactions Performed")
TotalUnfilledBackoutRequests    = uint16("total_unfilled_backout_requests", "Total Unfilled Backout Requests")
TotalVolumeClusters		= uint16("total_volume_clusters", "Total Volume Clusters")
TotalWriteRequests		= uint32("total_write_requests", "Total Write Requests")
TotalWriteTransactionsPerformed = uint32("total_write_trans_performed", "Total Write Transactions Performed")
TransactionDiskSpace		= uint16("transaction_disk_space", "Transaction Disk Space")
TransactionFATAllocations	= uint32("transaction_fat_allocations", "Transaction FAT Allocations")
TransactionFileSizeChanges	= uint32("transaction_file_size_changes", "Transaction File Size Changes")
TransactionFilesTruncated	= uint32("transaction_files_truncated", "Transaction Files Truncated")
TransactionNumber		= uint32("transaction_number", "Transaction Number")
TransactionTrackingEnabled	= byte("transaction_tracking_enabled", "Transaction Tracking Enabled")
TransactionTrackingSupported	= byte("transaction_tracking_supported", "Transaction Tracking Supported")
TransactionVolumeNumber		= uint16("transaction_volume_number", "Transaction Volume Number")
TreeLength			= uint32("tree_length", "Tree Length")
TreeName			= fw_string("tree_name", "Tree Name", 48)
TrusteeRightsHigh		= bitfield8("trustee_rights_high", "Trustee Rights (byte 2)", [
	bf_boolean8(0x01, "trustee_rights_super", "Supervisor"),
])
TrusteeRightsLow		= bitfield8("trustee_rights_low", "Trustee Rights", [
	bf_boolean8(0x01, "trustee_rights_read", "Read"),
	bf_boolean8(0x02, "trustee_rights_write", "Write"),
	bf_boolean8(0x04, "trustee_rights_open", "Open"),
	bf_boolean8(0x08, "trustee_rights_create", "Create"),
	bf_boolean8(0x10, "trustee_rights_del", "Delete"),
	bf_boolean8(0x20, "trustee_rights_parent", "Parental"),
	bf_boolean8(0x40, "trustee_rights_search", "Search"),
	bf_boolean8(0x80, "trustee_rights_modify", "Modify"),
])
TTSLevel			= byte("tts_level", "TTS Level")
TrusteeSetNumber 		= byte("trustee_set_number", "Trustee Set Number")
TrusteeID			= uint32("trustee_id_set", "Trustee ID")
TrusteeID.Display("BASE_HEX")
TtlDSDskSpaceAlloc 		= uint32("ttl_ds_disk_space_alloc", "Total Streams Space Allocated")
TtlEAs				= uint32("ttl_eas", "Total EA's")
TtlEAsDataSize			= uint32("ttl_eas_data_size", "Total EA's Data Size")
TtlEAsKeySize			= uint32("ttl_eas_key_size", "Total EA's Key Size")
TtlMigratedSize 		= uint32("ttl_migrated_size", "Total Migrated Size")
TtlValuesLength 		= uint32("ttl_values_length", "Total Values Length")
TtlWriteDataSize		= uint32("ttl_write_data_size", "Total Write Data Size")
TurboUsedForFileService 	= uint16("turbo_used_for_file_service", "Turbo Used For File Service")

UnCompressableDataStreamsCount	= uint32("un_compressable_data_streams_count", "Uncompressable Data Streams Count")
Undefined8			= bytes("undefined_8", "Undefined", 8)
Undefined28			= bytes("undefined_28", "Undefined", 28)
UndefinedWord			= uint16("undefined_word", "Undefined")
UniqueID			= byte("unique_id", "Unique ID")
UnknownByte			= byte("unknown_byte", "Unknown Byte")
Unused				= byte("un_used", "Unused")
UnusedBlocks			= uint32("unused_blocks", "Unused Blocks")
UnUsedDirectoryEntries		= uint32("un_used_directory_entries", "Unused Directory Entries")
UnusedDiskBlocks		= uint32("unused_disk_blocks", "Unused Disk Blocks")
UnUsedExtendedDirectoryExtants	= uint32("un_used_extended_directory_extants", "Unused Extended Directory Extants")
UpdateDateAndTime		= uint32("update_date_and_time", "Update Date & Time")
UpdateID			= uint32("update_id", "Update ID")
UpdateID.Display("BASE_HEX")
UseCount 			= uint16("use_count", "Use Count")
UsedBlocks			= uint32("used_blocks", "Used Blocks")
UserID				= uint32("user_id", "User ID")
UserID.Display("BASE_HEX")
UserLoginAllowed		= val_string8("user_login_allowed", "Login Status", [
	[ 0x00, "Client Login Disabled" ],
	[ 0x01, "Client Login Enabled" ],
])

UserName			= nstring8("user_name", "User Name")
UserName16			= fw_string("user_name_16", "User Name", 16)
UserName48			= fw_string("user_name_48", "User Name", 48)
UserType			= uint16("user_type", "User Type")

ValueAvailable			= val_string8("value_available", "Value Available", [
	[ 0x00, "Has No Value" ],
	[ 0xff, "Has Value" ],
])
VAPVersion			= byte("vap_version", "VAP Version")
VariableBitMask 		= uint32("variable_bit_mask", "Variable Bit Mask")
VariableBitsDefined 		= uint16("variable_bits_defined", "Variable Bits Defined")
Verb				= uint32("verb", "Verb")
VerbData			= byte("verb_data", "Verb Data")
version				= uint32("version", "Version")
VertLocation			= uint16("vert_location", "Vertical Location")
VirtualConsoleVersion		= byte("virtual_console_version", "Virtual Console Version")
VolumeID			= uint32("volume_id", "Volume ID")
VolumeID.Display("BASE_HEX")
VolInfoReplyLen			= uint16("vol_info_reply_len", "Volume Information Reply Length")
VolumeCachedFlag 		= val_string8("volume_cached_flag", "Volume Cached Flag", [
	[ 0x00, "Volume is Not Cached" ],
	[ 0xff, "Volume is Cached" ],
])	
VolumeHashedFlag 		= val_string8("volume_hashed_flag", "Volume Hashed Flag", [
	[ 0x00, "Volume is Not Hashed" ],
	[ 0xff, "Volume is Hashed" ],
])	
VolumeLastModifiedDateAndTime	= uint32("volume_last_modified_date_and_time", "Volume Last Modified Date and Time")
VolumeMountedFlag 		= val_string8("volume_mounted_flag", "Volume Mounted Flag", [
	[ 0x00, "Volume is Not Mounted" ],
	[ 0xff, "Volume is Mounted" ],
])
VolumeName			= fw_string("volume_name", "Volume Name", 16)
VolumeNameLen			= nstring8("volume_name_len", "Volume Name")
VolumeNumber 			= byte("volume_number", "Volume Number")
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
WastedServerMemory 		= uint16("wasted_server_memory", "Wasted Server Memory")
WaitTime			= uint32("wait_time", "Wait Time")

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
	groups['unknown']	= "Unknown"

##############################################################################
# NCP Errors
##############################################################################
def define_errors():
	errors[0x0000] = "Ok"
	errors[0x0001] = "Transaction tracking is available"
	errors[0x0002] = "Ok. The data has been written"
	errors[0x0003] = "Calling Station is a Manager"

	errors[0x0100] = "One or more of the ConnectionNumbers in the send list are invalid"
	errors[0x0101] = "Invalid space limit"
	errors[0x0102] = "Insufficient disk space"
	errors[0x0103] = "Queue server cannot add jobs"
	errors[0x0104] = "Out of disk space"
	errors[0x0105] = "Semaphore overflow"
	errors[0x0106] = "Invalid Parameter"
	errors[0x0107] = "Invalid Number of Minutes to Delay"

	errors[0x0200] = "One or more clients in the send list are not logged in"
	errors[0x0201] = "Queue server cannot attach"

	errors[0x0300] = "One or more clients in the send list are not accepting messages"

	errors[0x0400] = "Client already has message"
	errors[0x0401] = "Queue server cannot service job"

	errors[0x7300] = "Revoke Handle Rights Not Found"
	errors[0x7a00] = "Connection Already Temporary"
	errors[0x7b00] = "Connection Already Logged in"
	errors[0x7c00] = "Connection Not Authenticated"
	
	errors[0x7e00] = "NCP failed boundary check"
	errors[0x7e01] = "Invalid Length"

	errors[0x7f00] = "Lock Waiting"
	errors[0x8000] = "Lock fail"

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
	errors[0x8900] = "Unauthorized to search this directory"
	errors[0x8a00] = "Unauthorized to delete this directory"
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
	errors[0x9a00] = "The request attempted to rename the affected file to another volume"

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
	errors[0xa700] = "Error Auditing Version"
	errors[0xa800] = "Invalid Support Module ID"
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
	errors[0xff06] = "The printer associated with PrinterNumber does not exist"
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


##############################################################################
# Produce C code
##############################################################################
def ExamineVars(vars, structs_hash, vars_hash):
	for var in vars:
		if isinstance(var, struct):
			structs_hash[repr(var)] = var
			struct_vars = var.Variables()
			ExamineVars(struct_vars, structs_hash, vars_hash)
		else:
			vars_hash[repr(var)] = var

def produce_code():

	global errors

	print "/*"
	print " * Generated automatically from %s" % (sys.argv[0])
	print " * Do not edit this file manually, as all changes will be lost."
	print " */\n"

	print """
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include "ptvcursor.h"
#include "packet-ncp-int.h"

/* We use this int-pointer as a special flag in ptvc_record's */
static int ptvc_struct_int_storage;
#define PTVC_STRUCT	(&ptvc_struct_int_storage)

/* Values used in the count-variable ("var"/"repeat") logic. */
#define NO_VAR -1
#define NO_REPEAT -1"""

	if global_highest_var > -1:
		print "#define NUM_REPEAT_VARS\t%d" % (global_highest_var + 1)
		print "guint repeat_vars[NUM_REPEAT_VARS];"
	else:
		print "#define NUM_REPEAT_VARS\t0"
		print "guint *repeat_vars = NULL;"

	print """

static int hf_ncp_func = -1;
static int hf_ncp_length = -1;
static int hf_ncp_subfunc = -1;
static int hf_ncp_completion_code = -1;
static int hf_ncp_connection_status = -1;
	"""

	# Look at all packet types in the packets collection, and cull information
	# from them.
	packet_keys = []
	for packet in packets.Members():
		packet_keys.append(packet.FunctionCode())
	packet_keys.sort()

	errors_used_list = []
	errors_used_hash = {}
	groups_used_list = []
	groups_used_hash = {}
	variables_used_hash = {}
	structs_used_hash = {}

	for pkt in packets.Members():
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
	for var in variables_used_hash.values():
		print "static int " + var.HFName() + " = -1;"


	# Print the value_string's
	for var in variables_used_hash.values():
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


	# Print PTVC's for bitfields
	ett_list = []
	print "/* PTVC records for bit-fields. */"
	for var in variables_used_hash.values():
		if isinstance(var, bitfield):
			sub_vars_ptvc = var.SubVariablesPTVC()
			print "/* %s */" % (sub_vars_ptvc.Name())
			print sub_vars_ptvc.Code()
			ett_list.append(sub_vars_ptvc.ETTName())

	# Print the PTVC's for structures
	print "/* PTVC records for structs. */"
	for var in structs_used_hash.values():
		print var.Code()

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


	# Functions without length parameter
	funcs_without_length = {}


	# Print ncp_record packet records
	print "#define SUBFUNC_WITH_LENGTH	0x02"
	print "#define SUBFUNC_NO_LENGTH	0x01"
	print "#define NO_SUBFUNC		0x00"

	print "/* ncp_record structs for packets */"
	print "static const ncp_record ncp_packets[] = {"
	for pkt in packets.Members():
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
		print '\t\t%s, NULL, %s, NULL,' % (ptvc_request, ptvc_reply)
		print '\t\t%s },\n' % (errors.Name())

	print '\t{ 0, 0, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL }'
	print "};\n"

	print "/* ncp funcs that require a subfunc */"
	print "static const guint8 ncp_func_requires_subfunc[] = {"
	hi_seen = {}
	for pkt in packets.Members():
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

	# proto_register_ncp2222()
	print """
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

	{ &hf_ncp_connection_status,
	{ "Connection Status", "ncp.connection_status", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
	"""

	# Print the registration code for the hf variables
	for var in variables_used_hash.values():
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

	print "}"
	print ""
	print '#include "packet-ncp2222.inc"'

def usage():
	print "Usage: ncp2222.py -o output_file"
	sys.exit(1)

def main():
	global packets
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

	# Run the code, and if we catch any exception,
	# erase the output file.
	try:
		packets		= UniqueCollection('NCP Packet Descriptions')
		compcode_lists	= UniqueCollection('Completion Code Lists')
		ptvc_lists	= UniqueCollection('PTVC Lists')

		define_errors()
		define_groups()
		define_ncp2222()

		msg.write("Defined %d NCP types.\n" % (len(packets.Members()),))
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
	pkt = NCP(0x01, "File Set Lock (old)", 'file')
	pkt.Request(7)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/02
	pkt = NCP(0x02, "File Release Lock", 'file')
	pkt.Request(7)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xff00])
	# 2222/03
	pkt = NCP(0x03, "Log File Exclusive (old)", 'file')
	pkt.Request( (12, 267), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, LockFlag ),
		rec( 9, 2, TimeoutLimit, LE ),
		rec( 11, (1, 256), FilePath ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8200, 0x9600, 0xfe0d, 0xff01])
	# 2222/04
	pkt = NCP(0x04, "Lock File Set (old)", 'file')
	pkt.Request( 9, [
		rec( 7, 2, TimeoutLimit, LE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xfe0d, 0xff01])
	## 2222/05
	pkt = NCP(0x05, "Release File (old)", 'file')
	pkt.Request( (9, 264), [
		rec( 7, 1, DirHandle ),
		rec( 8, (1, 256), FilePath ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9c03, 0xff1a])
	# 2222/06
	pkt = NCP(0x06, "Release File Set", 'file')
	pkt.Request( 8, [
		rec( 7, 1, LockFlag ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/07
	pkt = NCP(0x07, "Clear File (old)", 'file')
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
	pkt = NCP(0x09, "Log Logical Record (old)", 'file')
	pkt.Request( (11, 138), [
		rec( 7, 1, LockFlag ),
		rec( 8, 2, TimeoutLimit, LE ),
		rec( 10, (1, 128), LogicalRecordName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xfe0d, 0xff1a])
	# 2222/0A, 10
	pkt = NCP(0x0A, "Lock Logical Record Set (old)", 'file')
	pkt.Request( 10, [
		rec( 7, 1, LockFlag ),
		rec( 8, 2, TimeoutLimit, LE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xfe0d, 0xff1a])
	# 2222/0B, 11
	pkt = NCP(0x0B, "Clear Logical Record", 'file')
	pkt.Request( (8, 135), [
		rec( 7, (1, 128), LogicalRecordName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xff1a])
	# 2222/0C, 12
	pkt = NCP(0x0C, "Release Logical Record", 'file')
	pkt.Request( (8, 135), [
		rec( 7, (1, 128), LogicalRecordName ),
	])
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
	])
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
	])
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
	])
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
		rec( 8, 4, ObjectID, LE ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xff06])

	# 2222/12, 18
	pkt = NCP(0x12, "Get Volume Info with Number", 'file')
	pkt.Request( 8, [
		rec( 8, 1, VolumeNumber )
	])
	pkt.Reply( 36, [
		rec( 8, 2, SectorsPerCluster ),
		rec( 10, 2, TotalVolumeClusters ),
		rec( 12, 2, AvailableClusters ),
		rec( 14, 2, TotalDirectorySlots ),
		rec( 16, 2, AvailableDirectorySlots ),
		rec( 18, 16, VolumeName ),
		rec( 34, 2, RemovableFlag ),
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
		rec( 8, 1, SYear ),
		rec( 9, 1, Month ),
		rec( 10, 1, Day ),
		rec( 11, 1, Hour ),
		rec( 12, 1, Minute ),
		rec( 13, 1, Second ),
		rec( 14, 1, DayOfWeek ),
	])
	pkt.CompletionCodes([0x0000])

	# 2222/1500, 21/00
	pkt = NCP(0x1500, "Send Broadcast Message (old)", 'message')
	pkt.Request((13, 70), [
		rec( 10, 2, ClientListCount ),
		rec( 12, (1, 58), TargetMessage ),
	])
	pkt.Reply((9,66), [
		rec( 8, (1, 58), SendStatus )
	])
	pkt.CompletionCodes([0x0000, 0xfd00])

	# 2222/1501, 21/01
	pkt = NCP(0x1501, "Get Broadcast Message (old)", 'message')
	pkt.Request(10)
	pkt.Reply((9,66), [
		rec( 8, (1, 58), TargetMessage )
	])
	pkt.CompletionCodes([0x0000, 0xfd00])

	# 2222/1502, 21/02
	pkt = NCP(0x1502, "Disable Broadcasts", 'message')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])

	# 2222/1503, 21/03
	pkt = NCP(0x1503, "Enable Broadcasts", 'message')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])

	# 2222/1509, 21/09
	pkt = NCP(0x1509, "Broadcast To Console", 'message')
	pkt.Request((11, 68), [
		rec( 10, (1, 58), TargetMessage )
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])

	# 2222/150A, 21/10
	pkt = NCP(0x150A, "Send Broadcast Message", 'message')
	pkt.Request((17, 74), [
		rec( 10, 2, ClientListCount, LE ),
		rec( 12, 4, TargetClientList, LE ),
		rec( 16, (1, 58), TargetMessage ),
	])
	pkt.Reply((9,66), [
		rec( 8, (1, 58), SendStatus )
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
		rec( 10, 4, ConnectionControlBits ),
		rec( 14, 4, ConnectionListCount ),
		rec( 18, 4, ConnectionList ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xff00])

	# 2222/1600, 22/0
	pkt = NCP(0x1600, "Set Directory Handle", 'fileserver')
	pkt.Request((13,267), [
		rec( 10, 1, TargetDirHandle ),
		rec( 11, 1, DirHandle ),
		rec( 12, (1, 255), Path ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0x9b03, 0x9c03, 0xa100, 0xfa00,
			     0xfd00, 0xff00])


	# 2222/1601, 22/1
	pkt = NCP(0x1601, "Get Directory Path", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, DirHandle ),
	])
	pkt.Reply((9,263), [
		rec( 8, (1,255), Path ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9b00, 0x9c00, 0xa100])

	# 2222/1602, 22/2
	pkt = NCP(0x1602, "Scan Directory Information", 'fileserver')
	pkt.Request((14,268), [
		rec( 10, 1, DirHandle ),
		rec( 11, 2, StartingSearchNumber ),
		rec( 13, (1, 255), Path ),
	])
	pkt.Reply(36, [
		rec( 8, 16, DirectoryPath ),
		rec( 24, 2, CreationDate ),
		rec( 26, 2, CreationTime ),
		rec( 28, 4, CreatorID ),
		rec( 32, 1, AccessRightsMask ),
		rec( 33, 1, Reserved ),
		rec( 34, 2, NextSearchNumber ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0x9b03, 0x9c03, 0xa100, 0xfa00,
			     0xfd00, 0xff00])

	# 2222/1603, 22/3
	pkt = NCP(0x1603, "Get Effective Directory Rights", 'fileserver')
	pkt.Request((14,268), [
		rec( 10, 1, DirHandle ),
		rec( 11, 2, StartingSearchNumber ),
		rec( 13, (1, 255), Path ),
	])
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
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8c00, 0x9600, 0x9804, 0x9b03, 0x9c03, 0xa100, 0xfa00,
			     0xfd00, 0xff00])

	# 2222/1605, 22/5
	pkt = NCP(0x1605, "Get Volume Number", 'fileserver')
	pkt.Request((11, 265), [
		rec( 10, (1,255), VolumeNameLen ),
	])
	pkt.Reply(9, [
		rec( 8, 1, VolumeNumber ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804])

	# 2222/1606, 22/6
	pkt = NCP(0x1606, "Get Volume Name", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, VolumeNumber ),
	])
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
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8400, 0x9600, 0x9804, 0x9900, 0x9b03, 0x9c03,
			     0x9e00, 0xa100, 0xfd00, 0xff00])

	# 2222/160B, 22/11
	pkt = NCP(0x160B, "Delete Directory", 'fileserver')
	pkt.Request((13,267), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, Reserved ),
		rec( 12, (1, 255), Path ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8a00, 0x9600, 0x9804, 0x9b03, 0x9c03,
			     0x9f00, 0xa000, 0xa100, 0xfd00, 0xff00])

	# 2222/160C, 22/12
	pkt = NCP(0x160C, "Scan Directory for Trustees", 'fileserver')
	pkt.Request((13,267), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, TrusteeSetNumber ),
		rec( 12, (1, 255), Path ),
	])
	pkt.Reply(57, [
		rec( 8, 16, DirectoryPath ),
		rec( 24, 2, CreationDate ),
		rec( 26, 2, CreationTime ),
		rec( 28, 4, CreatorID ),
		rec( 32, 4, TrusteeID, LE ),
		rec( 36, 4, TrusteeID, LE ),
		rec( 40, 4, TrusteeID, LE ),
		rec( 44, 4, TrusteeID, LE ),
		rec( 48, 4, TrusteeID, LE ),
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
		rec( 11, 4, TrusteeID, LE ),
		rec( 15, 1, AccessRightsMask ),
		rec( 16, (1, 255), Path ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8c00, 0x9600, 0x9804, 0x9900, 0x9b03, 0x9c03,
			     0xa100, 0xfc06, 0xfd00, 0xff00])

	# 2222/160E, 22/14
	pkt = NCP(0x160E, "Delete Trustee from Directory", 'fileserver')
	pkt.Request((17,271), [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, TrusteeID, LE ),
		rec( 15, 1, Reserved ),
		rec( 16, (1, 255), Path ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8c00, 0x9600, 0x9804, 0x9900, 0x9b03, 0x9c03,
			     0xa100, 0xfc06, 0xfd00, 0xfe07, 0xff00])

	# 2222/160F, 22/15
	pkt = NCP(0x160F, "Rename Directory", 'fileserver')
	pkt.Request((13, 521), [
		rec( 10, 1, DirHandle ),
		rec( 11, (1, 255), Path ),
		rec( -1, (1, 255), NewPath ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8b00, 0x9200, 0x9600, 0x9804, 0x9b03, 0x9c03,
			     0x9e00, 0xa100, 0xef00, 0xfd00, 0xff00])

	# 2222/1610, 22/16
	pkt = NCP(0x1610, "Purge Erased Files (old)", 'file')
	pkt.Request(10)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8100, 0x9600, 0x9804, 0xa100, 0xff00])

	# 2222/1611, 22/17
	pkt = NCP(0x1611, "Recover Erased File (old)", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, DirHandle ),
	])
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
	])
	pkt.Reply(10, [
		rec( 8, 1, DirHandle ),
		rec( 9, 1, AccessRightsMask ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0x9900, 0x9c03, 0x9d00,
			     0xa100, 0xfd00, 0xff00])
	# 2222/1613, 22/19
	pkt = NCP(0x1613, "Alloc Temporary Directory Handle", 'fileserver')
	pkt.Request((13, 267), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, DirHandleName ),
		rec( 12, (1,255), Path ),
	])
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
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9b03])
	# 2222/1615, 22/21
	pkt = NCP(0x1615, "Get Volume Info with Handle", 'file')
	pkt.Request( 11, [
		rec( 10, 1, DirHandle )
	])
	pkt.Reply( 36, [
		rec( 8, 2, SectorsPerCluster ),
		rec( 10, 2, TotalVolumeClusters ),
		rec( 12, 2, AvailableClusters ),
		rec( 14, 2, TotalDirectorySlots ),
		rec( 16, 2, AvailableDirectorySlots ),
		rec( 18, 16, VolumeName ),
		rec( 34, 2, RemovableFlag ),
	])
	pkt.CompletionCodes([0x0000, 0xff00])
	# 2222/1616, 22/22
	pkt = NCP(0x1616, "Alloc Special Temporary Directory Handle", 'fileserver')
	pkt.Request((13, 267), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, DirHandleName ),
		rec( 12, (1,255), Path ),
	])
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
	])
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
		rec( 11, 2, CreationDate, LE ),
		rec( 13, 2, CreationTime, LE ),
		rec( 15, 4, CreatorID ),
		rec( 19, 1, AccessRightsMask ),
		rec( 20, (1,255), Path ),
	])
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
	pkt = NCP(0x161B, "Scan Salvageable Files (old)", 'fileserver')
	pkt.Request(15, [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, SequenceNumber, LE ),
	])
	pkt.Reply(140, [
		rec( 8, 4, SequenceNumber, LE ),
		rec( 12, 2, Subdirectory, LE ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 1, AttributesDefLow ),
		rec( 17, 1, AttributesDefLow2 ),
		rec( 18, 1, AttributesDefLow3 ),
		rec( 19, 1, Reserved ),
		rec( 20, 1, UniqueID ),
		rec( 21, 1, FlagsDef ),
		rec( 22, 1, DestNameSpace ),
		rec( 23, 1, FileNameLen ),
		rec( 24, 12, FileName12 ),
		rec( 36, 4, CreationDateAndTime, LE ),
		rec( 40, 4, CreatorID ),
		rec( 44, 4, ArchivedDateAndTime, LE ),
		rec( 48, 4, ArchiverID ),
		rec( 52, 4, UpdateDateAndTime, LE ),
		rec( 56, 4, UpdateID ),
		rec( 60, 4, FileSize, LE ),
		rec( 64, 44, Reserved44 ),
		rec( 108, 1, InheritedRightsMaskLow ),
		rec( 109, 1, InheritedRightsMaskHigh ),
		rec( 110, 2, LastAccessedDate, LE ),
		rec( 112, 4, DeletedFileTime, LE ),
		rec( 116, 4, DeletedDateAndTime, LE ),
		rec( 120, 4, DeletedID ),
		rec( 124, 16, Reserved16 ),
	])
	pkt.CompletionCodes([0x0000, 0xfb01, 0xff1d])
	# 2222/161C, 22/28
	pkt = NCP(0x161C, "Recover Salvageable File (old)", 'fileserver')
	pkt.Request((17,525), [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, SequenceNumber, LE ),
		rec( 15, (1, 255), FileName ),
		rec( -1, (1, 255), NewFileName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8401, 0x9c03, 0xfe02])
	# 2222/161D, 22/29
	pkt = NCP(0x161D, "Purge Salvageable File (old)", 'fileserver')
	pkt.Request(15, [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, SequenceNumber, LE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8500, 0x9c03])
	# 2222/161E, 22/30
	pkt = NCP(0x161E, "Scan a Directory", 'fileserver')
	pkt.Request((17, 271), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, DOSFileAttributes ),
		rec( 12, 4, SequenceNumber, LE ),
		rec( 16, (1, 255), SearchPattern ),
	])
	pkt.Reply(140, [
		rec( 8, 4, SequenceNumber, LE ),
		rec( 12, 4, Subdirectory ),
		rec( 16, 1, AttributesDefLow ),
		rec( 17, 1, AttributesDefLow2 ),
		rec( 18, 1, AttributesDefLow3 ),
		rec( 19, 1, Reserved ),
		rec( 20, 1, UniqueID, LE ),
		rec( 21, 1, PurgeFlags ),
		rec( 22, 1, DestNameSpace ),
		rec( 23, 1, NameLen ),
		rec( 24, 12, Name12 ),
		rec( 36, 4, CreationDateAndTime, LE ),
		rec( 40, 4, CreatorID ),
		rec( 44, 4, ArchivedDateAndTime, LE ),
		rec( 48, 4, ArchiverID ),
		rec( 52, 4, UpdateDateAndTime, LE ),
		rec( 56, 4, UpdateID ),
		rec( 60, 4, FileSize ),
		rec( 64, 44, Reserved44 ),
		rec( 108, 1, InheritedRightsMaskLow ),
		rec( 109, 1, InheritedRightsMaskHigh ),
		rec( 110, 2, LastAccessedDate, LE ),
		rec( 112, 28, Reserved28 ),
	])
	pkt.CompletionCodes([0x0000, 0x8500, 0x9c03])
	# 2222/161F, 22/31
	pkt = NCP(0x161F, "Get Directory Entry", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, DirHandle ),
	])
	pkt.Reply(136, [
		rec( 8, 4, Subdirectory, LE ),
		rec( 12, 1, AttributesDefLow ),
		rec( 13, 1, AttributesDefLow2 ),
		rec( 14, 1, AttributesDefLow3 ),
		rec( 15, 1, Reserved ),
		rec( 16, 1, UniqueID, LE ),
		rec( 17, 1, PurgeFlags ),
		rec( 18, 1, DestNameSpace ),
		rec( 19, 1, NameLen ),
		rec( 20, 12, Name12 ),
		rec( 32, 4, CreationDateAndTime, LE ),
		rec( 36, 4, CreatorID ),
		rec( 40, 4, ArchivedDateAndTime, LE ),
		rec( 44, 4, ArchiverID ),
		rec( 48, 4, UpdateDateAndTime, LE ),
		rec( 52, 4, NextTrusteeEntry ),
		rec( 56, 48, Reserved48 ),
		rec( 104, 2, MaximumSpace, LE ),
		rec( 106, 1, InheritedRightsMaskLow ),
		rec( 107, 1, InheritedRightsMaskHigh ),
		rec( 108, 28, Undefined28 ),
	])
	pkt.CompletionCodes([0x0000, 0x8900, 0xbf00, 0xfb00])
	# 2222/1620, 22/32
	pkt = NCP(0x1620, "Scan Volume's User Disk Restrictions", 'fileserver')
	pkt.Request(15, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, SequenceNumber, LE ),
	])
	pkt.Reply(17, [
		rec( 8, 1, NumberOfEntries ),
		#There are multiple entries up to 16 in this packet 
		rec( 9, 4, ObjectID ),
		rec( 13, 4, Restriction, LE ),
	])
	pkt.CompletionCodes([0x0000, 0x9800])
	# 2222/1621, 22/33
	pkt = NCP(0x1621, "Add User Disk Space Restriction", 'fileserver')
	pkt.Request(19, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, ObjectID, LE ),
		rec( 15, 4, DiskSpaceLimit, LE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8c00, 0x9600, 0x9800])
	# 2222/1622, 22/34
	pkt = NCP(0x1622, "Remove User Disk Space Restrictions", 'fileserver')
	pkt.Request(15, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, ObjectID, LE ),
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
		#Number of entries tells how many are in this packet
		rec( 9, 1, Level ),
		rec( 10, 4, MaxSpace, LE ),
		rec( 14, 4, CurrentSpace, LE ),
	])
	pkt.CompletionCodes([0x0000])
	# 2222/1624, 22/36
	pkt = NCP(0x1624, "Set Directory Disk Space Restriction", 'fileserver')
	pkt.Request(15, [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, DiskSpaceLimit, LE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0101, 0x8c00, 0xbf00])
	# 2222/1625, 22/37
	pkt = NCP(0x1625, "Set Directory Entry Information", 'fileserver')
	pkt.Request(65, [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, SearchAttributesLow ),
		rec( 12, 1, SearchAttributesHigh ),
		rec( 13, 4, SequenceNumber, LE ),
		rec( 17, 1, ChangeBits1 ),
		rec( 18, 1, ChangeBits2 ),
		rec( 19, 2, Reserved2 ),
		rec( 21, 4, Subdirectory ),
		#The rest of this packet could be file or directory based on search flag
		#Listing common fields
		rec( 25, 1, AttributesDefLow ),
		rec( 26, 1, AttributesDefLow2 ),
		rec( 27, 1, AttributesDefLow3 ),
		rec( 28, 1, Reserved ),
		rec( 29, 1, UniqueID ),
		rec( 30, 1, PurgeFlags ),
		rec( 31, 1, DestNameSpace ),
		rec( 32, 1, NameLen ),
		rec( 33, 12, Name12 ),
		rec( 45, 4, CreationDateAndTime, LE ),
		rec( 49, 4, CreatorID ),
		rec( 53, 4, ArchivedDateAndTime, LE ),
		rec( 57, 4, ArchiverID ),
		rec( 61, 4, UpdateDateAndTime, LE ),
	#This is where the directory and file change.
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0106, 0x8c00, 0xbf00])
	# 2222/1626, 22/38
	pkt = NCP(0x1626, "Scan File or Directory for Extended Trustees", 'fileserver')
	pkt.Request((13,267), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, SequenceByte ),
		rec( 12, (1, 255), Path ),
	])
	pkt.Reply(129, [
		rec( 8, 1, NumberOfEntries ),
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
		rec( 89, 1, AccessRightsMask ),
		rec( 90, 1, AccessRightsHigh ),
		rec( 91, 1, AccessRightsMask ),
		rec( 92, 1, AccessRightsHigh ),
		rec( 93, 1, AccessRightsMask ),
		rec( 94, 1, AccessRightsHigh ),
		rec( 95, 1, AccessRightsMask ),
		rec( 96, 1, AccessRightsHigh ),
		rec( 97, 1, AccessRightsMask ),
		rec( 98, 1, AccessRightsHigh ),
		rec( 99, 1, AccessRightsMask ),
		rec( 100, 1, AccessRightsHigh ),
		rec( 101, 1, AccessRightsMask ),
		rec( 102, 1, AccessRightsHigh ),
		rec( 103, 1, AccessRightsMask ),
		rec( 104, 1, AccessRightsHigh ),
		rec( 105, 1, AccessRightsMask ),
		rec( 106, 1, AccessRightsHigh ),
		rec( 107, 1, AccessRightsMask ),
		rec( 108, 1, AccessRightsHigh ),
		rec( 109, 1, AccessRightsMask ),
		rec( 110, 1, AccessRightsHigh ),
		rec( 111, 1, AccessRightsMask ),
		rec( 112, 1, AccessRightsHigh ),
		rec( 113, 1, AccessRightsMask ),
		rec( 114, 1, AccessRightsHigh ),
		rec( 115, 1, AccessRightsMask ),
		rec( 116, 1, AccessRightsHigh ),
		rec( 117, 1, AccessRightsMask ),
		rec( 118, 1, AccessRightsHigh ),
		rec( 119, 1, AccessRightsMask ),
		rec( 120, 1, AccessRightsHigh ),
		rec( 121, 1, AccessRightsMask ),
		rec( 122, 1, AccessRightsHigh ),
		rec( 123, 1, AccessRightsMask ),
		rec( 124, 1, AccessRightsHigh ),
		rec( 125, 1, AccessRightsMask ),
		rec( 126, 1, AccessRightsHigh ),
		rec( 127, 1, AccessRightsMask ),
		rec( 128, 1, AccessRightsHigh ),
	])
	pkt.CompletionCodes([0x0000, 0x9800, 0x9b00, 0x9c00])
	# 2222/1627, 22/39
	pkt = NCP(0x1627, "Add Extended Trustee to Directory or File", 'fileserver')
	pkt.Request((18,272), [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, ObjectID ),
		rec( 15, 1, TrusteeRightsLow ),
		rec( 16, 1, TrusteeRightsHigh ),
		rec( 17, (1, 255), Path ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9000])
	# 2222/1628, 22/40
	pkt = NCP(0x1628, "Scan Directory Disk Space", 'fileserver')
	pkt.Request((15,269), [
		rec( 10, 1, DirHandle ),
		rec( 11, 1, SearchAttributesLow ),
		rec( 12, 1, SearchAttributesHigh ),
		rec( 13, 1, SequenceByte ),
		rec( 14, (1, 255), SearchPattern ),
	])
	pkt.Reply((148), [
		rec( 8, 4, SequenceNumber, LE ),
		rec( 12, 4, Subdirectory, LE ),
		rec( 16, 1, AttributesDefLow ),
		rec( 17, 1, AttributesDefLow2 ),
		rec( 18, 1, AttributesDefLow3 ),
		rec( 19, 1, Reserved ),
		rec( 20, 1, UniqueID ),
		rec( 21, 1, PurgeFlags ),
		rec( 22, 1, DestNameSpace ),
		rec( 23, 1, NameLen ),
		rec( 24, 12, Name12 ),
		rec( 36, 4, CreationDateAndTime, LE ),
		rec( 40, 4, CreatorID ),
		rec( 44, 4, ArchivedDateAndTime, LE ),
		rec( 48, 4, ArchiverID ),
		rec( 52, 4, UpdateDateAndTime, LE ),
		rec( 56, 4, UpdateID ),
		rec( 60, 4, DataForkSize ),
		rec( 64, 4, DataForkFirstFAT ),
		rec( 68, 4, NextTrusteeEntry ),
		rec( 72, 36, Reserved36 ),
		rec( 108, 1, InheritedRightsMaskLow ),
		rec( 109, 1, InheritedRightsMaskHigh ),
		rec( 110, 2, LastAccessedDate, LE ),
		rec( 112, 4, DeletedFileTime, LE ),
		rec( 116, 4, DeletedDateAndTime, LE ),
		rec( 120, 4, DeletedID ),
		rec( 124, 8, Undefined8 ),
		rec( 132, 4, PrimaryEntry, LE ),
		rec( 136, 4, NameList, LE ),
		rec( 140, 4, OtherFileForkSize ),
		rec( 144, 4, OtherFileForkFAT ),
	])
	pkt.CompletionCodes([0x0000, 0x8900, 0x9c03, 0xfb01, 0xff00])
	# 2222/1629, 22/41
	pkt = NCP(0x1629, "Get Object Disk Usage and Restrictions", 'fileserver')
	pkt.Request(15, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, ObjectID ),
	])
	pkt.Reply(16, [
		rec( 8, 4, Restriction, LE ),
		rec( 12, 4, InUse, LE ),
	])
	pkt.CompletionCodes([0x0000, 0x9802])
	# 2222/162A, 22/42
	pkt = NCP(0x162A, "Get Effective Rights for Directory Entry", 'fileserver')
	pkt.Request((12,266), [
		rec( 10, 1, DirHandle ),
		rec( 11, (1, 255), Path ),
	])
	pkt.Reply(10, [
		rec( 8, 2, AccessRightsMask ),
	])
	pkt.CompletionCodes([0x0000, 0x9804, 0x9c03])
	# 2222/162B, 22/43
	pkt = NCP(0x162B, "Remove Extended Trustee from Dir or File", 'fileserver')
	pkt.Request((17,271), [
		rec( 10, 1, DirHandle ),
		rec( 11, 4, ObjectID, LE ),
		rec( 15, 1, Unused ),
		rec( 16, (1, 255), Path ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9002, 0x9c03, 0xfe0f, 0xff09])
	# 2222/162C, 22/44
	pkt = NCP(0x162C, "Get Volume and Purge Information", 'file')
	pkt.Request( 11, [
		rec( 10, 1, VolumeNumber )
	])
	pkt.Reply( (38,53), [
		rec( 8, 4, TotalBlocks, LE ),
		rec( 12, 4, FreeBlocks, LE ),
		rec( 16, 4, PurgeableBlocks, LE ),
		rec( 20, 4, NotYetPurgeableBlocks, LE ),
		rec( 24, 4, TotalDirectoryEntries, LE ),
		rec( 28, 4, AvailableDirEntries, LE ),
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
		rec( 8, 4, TotalBlocks, LE ),
		rec( 12, 4, AvailableBlocks, LE ),
		rec( 16, 4, TotalDirectoryEntries, LE ),
		rec( 20, 4, AvailableDirEntries, LE ),
		rec( 24, 4, Reserved4 ),
		rec( 28, 1, SectorsPerBlock ),
		rec( 29, (1,16), VolumeName ),
	])
	pkt.CompletionCodes([0x0000, 0x9b03])
	# 2222/162E, 22/46
	pkt = NCP(0x162E, "Rename Or Move (old)", 'file')
	pkt.Request( (17,525), [
		rec( 10, 1, SourceDirHandle ),
		rec( 11, 1, SearchAttributesLow ),
		rec( 12, 1, SourcePathComponentCount ),
		rec( 13, (1,255), SourcePath ),
		rec( -1, 1, DestDirHandle ),
		rec( -1, 1, DestPathComponentCount ),
		rec( -1, (1,255), DestPath ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0102, 0x8701, 0x8b00, 0x8d00, 0x8e00,
			     0x8f00, 0x9001, 0x9101, 0x9201, 0x9a00, 0x9b03,
			     0x9c03, 0xa400, 0xff17])
	# 2222/162F, 22/47
	pkt = NCP(0x162F, "Get Name Space Information", 'file')
	pkt.Request( 11, [
		rec( 10, 1, VolumeNumber )
	])
	pkt.Reply( (13,521), [
		rec( 8, 1, DefinedNameSpaces ),
		rec( 9, (1,255), NameSpaceName ),
		rec( -1, 1, DefinedDataStreams ),
		rec( -1, 1, AssociatedNameSpace ),
		rec( -1, (1,255), DataStreamName ),
	])
	pkt.CompletionCodes([0x0000])
	# 2222/1630, 22/48
	pkt = NCP(0x1630, "Get Name Space Directory Entry", 'file')
	pkt.Request( 16, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, DOSSequence ),
		rec( 15, 1, SrcNameSpace ),
	])
	pkt.Reply( 111, [
		rec( 8, 4, SequenceNumber, LE ),
		rec( 12, 4, Subdirectory ),
		rec( 16, 1, AttributesDefLow ),
		rec( 17, 1, AttributesDefLow2 ),
		rec( 18, 1, AttributesDefLow3 ),
		rec( 19, 1, Reserved ),
		rec( 20, 1, UniqueID ),
		rec( 21, 1, PurgeFlags ),
		rec( 22, 1, SrcNameSpace ),
		rec( 23, 12, Name12 ),
		rec( 35, 4, CreationDateAndTime, LE ),
		rec( 39, 4, CreatorID ),
		rec( 43, 4, ArchivedDateAndTime, LE ),
		rec( 47, 4, ArchiverID ),
		rec( 51, 4, UpdateDateAndTime, LE ),
		rec( 55, 4, UpdateID ),
		rec( 59, 4, FileSize ),
		rec( 63, 44, Reserved44 ),
		rec( 107, 1, InheritedRightsMaskLow ),
		rec( 108, 1, InheritedRightsMaskHigh ),
		rec( 109, 2, LastAccessedDate, LE ),
	])
	pkt.CompletionCodes([0x0000, 0x8900, 0x9802, 0xbf00])
	# 2222/1631, 22/49
	pkt = NCP(0x1631, "Open Data Stream", 'file')
	pkt.Request( (15,269), [
		rec( 10, 1, DataStream ),
		rec( 11, 1, DirHandle ),
		rec( 12, 1, AttributesDefLow ),
		rec( 13, 1, OpenRights ),
		rec( 14, (1, 255), FileName ),
	])
	pkt.Reply( 12, [
		rec( 8, 4, CCFileHandle ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8200, 0x9002, 0xbe00, 0xff00])
	# 2222/1632, 22/50
	pkt = NCP(0x1632, "Get Object Effective Rights for Directory Entry", 'file')
	pkt.Request( (16,270), [
		rec( 10, 4, ObjectID ),
		rec( 14, 1, DirHandle ),
		rec( 15, (1, 255), Path ),
	])
	pkt.Reply( 10, [
		rec( 8, 1, TrusteeRightsLow ),
		rec( 9, 1, TrusteeRightsHigh ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x9b00, 0x9c03])
	# 2222/1633, 22/51
	pkt = NCP(0x1633, "Get Extended Volume Information", 'file')
	pkt.Request( 11, [
		rec( 10, 1, VolumeNumber ),
	])
	pkt.Reply( (143,270), [
		rec( 8, 2, VolInfoReplyLen, LE ),
		rec( 10, 4, VolumeType, LE ),
		rec( 14, 2, StatusFlagBitsLow ),
		rec( 16, 2, StatusFlagBitsHigh ),
		rec( 18, 4, SectorSize, LE ),
		rec( 22, 4, SectorsPerCluster, LE ),
		rec( 26, 4, VolumeSizeInClusters, LE ),
		rec( 30, 4, FreedClusters, LE ),
		rec( 34, 4, SubAllocFreeableClusters, LE ),
		rec( 38, 4, FreeableLimboSectors,LE ),
		rec( 42, 4, NonFreeableLimboSectors, LE ),
		rec( 46, 4, NonFreeableAvailableSubAllocSectors, LE ),
		rec( 50, 4, NotUsableSubAllocSectors, LE ),
		rec( 54, 4, SubAllocClusters, LE ),
		rec( 58, 4, DataStreamsCount, LE ),
		rec( 62, 4, LimboDataStreamsCount, LE ),
		rec( 66, 4, OldestDeletedFileAgeInTicks, LE ),
		rec( 70, 4, CompressedDataStreamsCount, LE ),
		rec( 74, 4, CompressedLimboDataStreamsCount , LE),
		rec( 78, 4, UnCompressableDataStreamsCount, LE ),
		rec( 82, 4, PreCompressedSectors, LE ),
		rec( 86, 4, CompressedSectors, LE ),
		rec( 90, 4, MigratedFiles, LE ),
		rec( 94, 4, MigratedSectors, LE ),
		rec( 98, 4, ClustersUsedByFAT, LE ),
		rec( 102, 4, ClustersUsedByDirectories, LE ),
		rec( 106, 4, ClustersUsedByExtendedDirectories, LE ),
		rec( 110, 4, TotalDirectoryEntries, LE ),
		rec( 114, 4, UnUsedDirectoryEntries, LE ),
		rec( 118, 4, TotalExtendedDirectoryExtants, LE ),
		rec( 122, 4, UnUsedExtendedDirectoryExtants, LE ),
		rec( 126, 4, ExtendedAttributesDefined, LE ),
		rec( 130, 4, ExtendedAttributeExtantsUsed, LE ),
		rec( 134, 4, DirectoryServicesObjectID, LE ),
		rec( 138, 4, VolumeLastModifiedDateAndTime, LE ),
		rec( 142, (1,128), VolumeNameLen ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x9804, 0xff00])
	# 2222/1634, 22/52
	pkt = NCP(0x1634, "Get Mount Volume List", 'file')
	pkt.Request( 22, [
		rec( 10, 4, StartVolumeNumber, LE ),
		rec( 14, 4, VolumeRequestFlags, LE ),
		rec( 18, 4, SrcNameSpace, LE ),
	])
	pkt.Reply( 20, [
		rec( 8, 4, ItemsInPacket, LE ),
		rec( 12, 4, NextVolumeNumber, LE ),
		#If the request flag indicates return name then the next attrib
		#would be followed with 20, (1,128), VolumeName.
		rec( 16, 4, VolumeNumberLong, LE ),
	])
	pkt.CompletionCodes([0x0000])
	# 2222/1700, 23/00
	pkt = NCP(0x1700, "Login User (old)", 'file')
	pkt.Request( (12, 58), [
		rec( 10, (1,16), UserName ),
		rec( -1, (1,32), Password ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9602, 0xc101, 0xc200, 0xc501, 0xd700,
			     0xd900, 0xda00, 0xdb00, 0xde00, 0xdf00, 0xe800,
			     0xec00, 0xed00, 0xef00, 0xf001, 0xf100, 0xf200,
			     0xf600, 0xfb00, 0xfc06, 0xfe07, 0xff00])
	# 2222/1701, 23/01
	pkt = NCP(0x1701, "Change User Password (old)", 'file')
	pkt.Request( (13, 90), [
		rec( 10, (1,16), UserName ),
		rec( -1, (1,32), Password ),
		rec( -1, (1,32), NewPassword ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xd600, 0xf001, 0xf101, 0xf501,
			     0xfc06, 0xfe07, 0xff00])
	# 2222/1702, 23/02
	pkt = NCP(0x1702, "Get User Connection List (old)", 'file')
	pkt.Request( (11, 26), [
		rec( 10, (1,16), UserName ),
	])
	pkt.Reply( (9, 136), [
		rec( 8, (1, 128), ConnectionNumberList ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xf001, 0xfc06, 0xfe07, 0xff00])
	# 2222/1703, 23/03
	pkt = NCP(0x1703, "Get User Number (old)", 'file')
	pkt.Request( (11, 26), [
		rec( 10, (1,16), UserName ),
	])
	pkt.Reply( 12, [
		rec( 8, 4, ObjectID ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xf001, 0xfc06, 0xfe07, 0xff00])
	# 2222/1705, 23/05
	pkt = NCP(0x1705, "Get Station's Logged Info (old)", 'file')
	pkt.Request( 11, [
		rec( 10, 1, TargetConnectionNumber ),
	])
	pkt.Reply( 266, [
		rec( 8, 16, UserName16 ),
		rec( 24, 7, LoginTime ),
		rec( 31, 39, FullName ),
		rec( 70, 4, UserID ),
		rec( 74, 128, SecurityEquivalentList ),
		rec( 202, 64, Reserved64 ),
	])
	pkt.CompletionCodes([0x0000, 0x9602, 0xfc06, 0xfd00, 0xfe07, 0xff00])
	# 2222/1707, 23/07
	pkt = NCP(0x1707, "Get Group Number (old)", 'file')
	pkt.Request( 14, [
		rec( 10, 4, ObjectID ),
	])
	pkt.Reply( 62, [
		rec( 8, 4, ObjectID ),
		rec( 12, 2, ObjectType ),
		rec( 14, 48, ObjectNameLen ),
	])
	pkt.CompletionCodes([0x0000, 0x9602, 0xf101, 0xfc06, 0xfe07, 0xff00])
	# 2222/170C, 23/12
	pkt = NCP(0x170C, "Verify Serialization", 'file')
	pkt.Request( 14, [
		rec( 10, 4, ServerSerialNumber, LE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xff00])
	# 2222/170D, 23/13
	pkt = NCP(0x170D, "Log Network Message", 'file')
	pkt.Request( (11, 68), [
		rec( 10, (1, 58), TargetMessage ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8100, 0x8800, 0x8d00, 0x8e00, 0x8f00,
			     0x9001, 0x9400, 0x9600, 0x9804, 0x9900, 0x9b00, 0xa100,
			     0xa201, 0xff00])
	# 2222/170E, 23/14
	pkt = NCP(0x170E, "Get Disk Utilization", 'file')
	pkt.Request( 15, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, TrusteeID ),
	])
	pkt.Reply( 19, [
		rec( 8, 1, VolumeNumber ),
		rec( 9, 4, TrusteeID ),
		rec( 13, 2, DirectoryCount ),
		rec( 15, 2, FileCount ),
		rec( 17, 2, ClusterCount ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0xa100, 0xf200])
	# 2222/170F, 23/15
	pkt = NCP(0x170F, "Scan File Information", 'file')
	pkt.Request((15,269), [
		rec( 10, 2, LastSearchIndex, LE ),
		rec( 12, 1, DirHandle ),
		rec( 13, 1, SearchAttributesLow ),
		rec( 14, (1, 255), FileName ),
	])
	pkt.Reply( 102, [
		rec( 8, 2, NextSearchIndex, LE ),
		rec( 10, 14, FileName14 ),
		rec( 24, 1, AttributesDefLow ),
		rec( 25, 1, AttributesDefLow2 ),
		rec( 26, 4, FileSize ),
		rec( 30, 2, CreationDate ),
		rec( 32, 2, LastAccessedDate ),
		rec( 34, 2, ModifiedDate ),
		rec( 36, 2, ModifiedTime ),
		rec( 38, 4, CreatorID ),
		rec( 42, 2, ArchivedDate ),
		rec( 44, 2, ArchivedTime ),
		rec( 46, 56, Reserved56 ),
	])
	pkt.CompletionCodes([0x0000, 0x8800, 0x8900, 0x9300, 0x9400, 0x9804, 0x9b00, 0x9c00,
			     0xa100, 0xfd00, 0xff17])
	# 2222/1710, 23/16
	pkt = NCP(0x1710, "Set File Information", 'file')
	pkt.Request((91,345), [
		rec( 10, 1, AttributesDefLow ),
		rec( 11, 1, AttributesDefLow2 ),
		rec( 12, 4, FileSize ),
		rec( 16, 2, CreationDate ),
		rec( 18, 2, LastAccessedDate ),
		rec( 20, 2, ModifiedDate ),
		rec( 22, 2, ModifiedTime ),
		rec( 24, 4, CreatorID ),
		rec( 28, 2, ArchivedDate ),
		rec( 30, 2, ArchivedTime ),
		rec( 32, 56, Reserved56 ),
		rec( 88, 1, DirHandle ),
		rec( 89, 1, SearchAttributesLow ),
		rec( 90, (1, 255), FileName ),
	])
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
		rec( 58, 2, ConnectionsSupportedMax ),
		rec( 60, 2, ConnectionsInUse ),
		rec( 62, 2, VolumesSupportedMax ),
		rec( 64, 1, OSRevision ),
		rec( 65, 1, SFTSupportLevel ),
		rec( 66, 1, TTSLevel ),
		rec( 67, 2, ConnectionsMaxUsed ),
		rec( 69, 1, AcctVersion ),
		rec( 70, 1, VAPVersion ),
		rec( 71, 1, QMSVersion ),
		rec( 72, 1, PrintServerVersion ),
		rec( 73, 1, VirtualConsoleVersion ),
		rec( 74, 1, SecurityRestrictionVersion ),
		rec( 75, 1, InternetBridgeVersion ),
		rec( 76, 1, MixedModePathFlag ),
		rec( 77, 1, LocalLoginInfoCcode ),
		rec( 78, 2, ProductMajorVersion ),
		rec( 80, 2, ProductMinorVersion ),
		rec( 82, 2, ProductRevisionVersion ),
		rec( 84, 1, OSLanguageID, LE ),
		rec( 85, 51, Reserved51 ),
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
	pkt = NCP(0x1713, "Get Internet Address (old)", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, TargetConnectionNumber ),
	])
	pkt.Reply(20, [
		rec( 8, 4, NetworkAddress ),
		rec( 12, 6, NetworkNodeAddress ),
		rec( 18, 2, NetworkSocket ),
	])
	pkt.CompletionCodes([0x0000, 0xff00])
	# 2222/1714, 23/20
	pkt = NCP(0x1714, "Login Object", 'file')
	pkt.Request( (12, 58), [
		rec( 10, (1,16), UserName ),
		rec( -1, (1,32), Password ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9602, 0xc101, 0xc200, 0xc501, 0xd600, 0xd700,
			     0xd900, 0xda00, 0xdb00, 0xde00, 0xdf00, 0xe800, 0xec00,
			     0xed00, 0xef00, 0xf001, 0xf100, 0xf200, 0xf600, 0xfb00,
			     0xfc06, 0xfe07, 0xff00])
	# 2222/1715, 23/21
	pkt = NCP(0x1715, "Get Object Connection List (old)", 'file')
	pkt.Request( (11, 26), [
		rec( 10, (1,16), UserName ),
	])
	pkt.Reply( (9, 136), [
		rec( 8, (1, 128), ConnectionNumberList ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xf001, 0xfc06, 0xfe07, 0xff00])
	# 2222/1716, 23/22
	pkt = NCP(0x1716, "Get Station's Logged Info (old)", 'file')
	pkt.Request( 11, [
		rec( 10, 1, TargetConnectionNumber ),
	])
	pkt.Reply( (23,70), [
		rec( 8, 4, UserID, LE ),
		rec( 12, 2, ObjectType ),
		rec( 14, (1,48), ObjectName ),
		rec( 62, 7, LoginTime ),	#GRJ - structure
		rec( 69, 1, Reserved ),
	])
	pkt.CompletionCodes([0x0000, 0x9602, 0xfc06, 0xfd00, 0xfe07, 0xff00])
	# 2222/1717, 23/23
	pkt = NCP(0x1717, "Get Login Key", 'file')
	pkt.Request(10)
	pkt.Reply( 16, [
		rec( 8, 8, LoginKey ),
	])
	pkt.CompletionCodes([0x0000, 0x9602])
	# 2222/1718, 23/24
	pkt = NCP(0x1718, "Keyed Object Login", 'file')
	pkt.Request( (21, 68), [
		rec( 10, 8, LoginKey ),
		rec( 18, 2, ObjectType ),
		rec( 20, (1,48), ObjectName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9602, 0xc101, 0xc200, 0xc500, 0xd900, 0xda00,
			     0xdb00, 0xdc00, 0xde00])
	# 2222/171A, 23/26
	pkt = NCP(0x171A, "Get Internet Address", 'fileserver')
	pkt.Request(11, [
		rec( 10, 1, TargetConnectionNumber ),
	])
	pkt.Reply(21, [
		rec( 8, 4, NetworkAddress ),
		rec( 12, 6, NetworkNodeAddress ),
		rec( 18, 2, NetworkSocket ),
		rec( 20, 1, ConnectionType ),
	])
	pkt.CompletionCodes([0x0000])
	# 2222/171B, 23/27
	pkt = NCP(0x171B, "Get Object Connection List", 'file')
	pkt.Request( 60, [
		rec( 10, 2, ObjectType ),
		rec( 12, 48, ObjectNameLen ),
	])
	pkt.Reply( (12, 136), [
		rec( 8, (4, 128), ConnectionNumberList ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xf001, 0xfc06, 0xfe07, 0xff00])
	# 2222/171C, 23/28
	pkt = NCP(0x171C, "Get Station's Logged Info", 'file')
	pkt.Request( 14, [
		rec( 10, 4, TargetConnectionNumber, LE ),
	])
	pkt.Reply( 70, [
		rec( 8, 4, UserID ),
		rec( 12, 2, ObjectType ),
		rec( 14, 48, ObjectNameLen ),
		rec( 62, 7, LoginTime ),
		rec( 69, 1, Reserved ),
	])
	pkt.CompletionCodes([0x0000, 0x9602, 0xfc06, 0xfd00, 0xfe07, 0xff00])
	# 2222/171D, 23/29
	pkt = NCP(0x171D, "Change Connection State", 'file')
	pkt.Request( 11, [
		rec( 10, 1, RequestCode ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7a00, 0x7b00, 0x7c00, 0xe000, 0xfb06, 0xfd00])
	# 2222/171E, 23/30
	pkt = NCP(0x171E, "Set Watchdog Delay Interval", 'file')
	pkt.Request( 14, [
		rec( 10, 4, NumberOfMinutesToDelay ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x0107])
	# 2222/171F, 23/31
	pkt = NCP(0x171F, "Get Connection List From Object", 'file')
	pkt.Request( 18, [
		rec( 10, 4, ObjectID ),
		rec( 14, 4, ConnectionNumber ),
	])
	pkt.Reply( (9, 136), [
		rec( 8, (1, 128), ConnectionNumberList ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xf001, 0xfc06, 0xfe07, 0xff00])
	# 2222/1720, 23/32
	pkt = NCP(0x1720, "Scan Bindery Object (List)", 'bindery')
	pkt.Request((23,70), [
		rec( 10, 4, NextObjectID ),
		rec( 14, 4, ObjectType ),
		rec( 18, 3, InfoFlagsLow ),
		rec( 21, 1, InfoFlagsHigh ),
		rec( 22, (1,48), ObjectName ),
	])
	pkt.Reply(20, [
		rec( 8, 4, ObjectInfoReturnCount ),
		rec( 12, 4, NextObjectID ),
		rec( 16, 4, ObjectIDInfo ),
		#The following 3 Attributes are returned if the InfoFlags of the request asked for them.
		#ObjectType, ObjectSecurity, ObjectName
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xef01, 0xfc02, 0xfe01, 0xff00])
	# 2222/1721, 23/33
	pkt = NCP(0x1721, "Generate GUIDs", 'nds')
	pkt.Request( 14, [
		rec( 10, 4, ReturnInfoCount ),
	])
	pkt.Reply(28, [
		rec( 8, 4, ReturnInfoCount ),
		rec( 12, 16, GUID ),
		#More GUIDS can be returned based upon the ReturnInfoCount (up to 33 items)
	])
	pkt.CompletionCodes([0x0000])
	# 2222/1732, 23/50
	pkt = NCP(0x1732, "Create Bindery Object", 'bindery')
	pkt.Request( (15,62), [
		rec( 10, 1, ObjectFlags ),
		rec( 11, 1, ObjectSecurity ),
		rec( 12, 2, ObjectType ),
		rec( 14, (1,48), ObjectName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xe700, 0xee00, 0xef00, 0xf101, 0xf501,
			     0xfc06, 0xfe07, 0xff00])
	# 2222/1733, 23/51
	pkt = NCP(0x1733, "Delete Bindery Object", 'bindery')
	pkt.Request( (13,60), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xf000, 0xf200, 0xf400, 0xf600, 0xfb00,
			     0xfc06, 0xfe07, 0xff00])
	# 2222/1734, 23/52
	pkt = NCP(0x1734, "Rename Bindery Object", 'bindery')
	pkt.Request( (14,108), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, (1,48), NewObjectName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xee00, 0xf000, 0xf300, 0xfc06, 0xfe07, 0xff00])
	# 2222/1735, 23/53
	pkt = NCP(0x1735, "Get Bindery Object ID", 'bindery')
	pkt.Request((13,60), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
	])
	pkt.Reply(62, [
		rec( 8, 4, ObjectID ),
		rec( 12, 2, ObjectType ),
		rec( 14, 48, ObjectNameLen ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xef01, 0xf000, 0xfc02, 0xfe01, 0xff00])
	# 2222/1736, 23/54
	pkt = NCP(0x1736, "Get Bindery Object Name", 'bindery')
	pkt.Request( 14, [
		rec( 10, 4, ObjectID ),
	])
	pkt.Reply( 62, [
		rec( 8, 4, ObjectID ),
		rec( 12, 2, ObjectType ),
		rec( 14, 48, ObjectNameLen ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xf101, 0xfc02, 0xfe01, 0xff00])
	# 2222/1737, 23/55
	pkt = NCP(0x1737, "Scan Bindery Object", 'bindery')
	pkt.Request((17,64), [
		rec( 10, 4, ObjectID ),
		rec( 14, 2, ObjectType ),
		rec( 16, (1,48), ObjectName ),
	])
	pkt.Reply(65, [
		rec( 8, 4, ObjectID ),
		rec( 12, 2, ObjectType ),
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
		rec( 11, 2, ObjectType ),
		rec( 13, (1,48), ObjectName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xf000, 0xf101, 0xf501, 0xfc02, 0xfe01, 0xff00])
	# 2222/1739, 23/57
	pkt = NCP(0x1739, "Create Property", 'bindery')
	pkt.Request((16,78), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, 1, PropertyType ),
		rec( -1, 1, ObjectSecurity ),
		rec( -1, (1,16), PropertyName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xed00, 0xef00, 0xf000, 0xf101,
			     0xf200, 0xf600, 0xf700, 0xfb00, 0xfc02, 0xfe01,
			     0xff00])
	# 2222/173A, 23/58
	pkt = NCP(0x173A, "Delete Property", 'bindery')
	pkt.Request((14,76), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, (1,16), PropertyName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xf000, 0xf101, 0xf600, 0xfb00, 0xfc02,
			     0xfe01, 0xff00])
	# 2222/173B, 23/59
	pkt = NCP(0x173B, "Change Property Security", 'bindery')
	pkt.Request((15,77), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, 1, ObjectSecurity ),
		rec( -1, (1,16), PropertyName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xf000, 0xf101, 0xf200, 0xf600, 0xfb00,
			     0xfc02, 0xfe01, 0xff00])
	# 2222/173C, 23/60
	pkt = NCP(0x173C, "Scan Property", 'bindery')
	pkt.Request((18,80), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, 4, LastInstance ),
		rec( -1, (1,16), PropertyName ),
	])
	pkt.Reply( 32, [
		rec( 8, 16, PropertyName16 ),
		rec( 24, 1, ObjectFlags ),
		rec( 25, 1, ObjectSecurity ),
		rec( 26, 4, SearchInstance ),
		rec( 30, 1, ValueAvailable ),
		rec( 31, 1, MoreProperties ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xf000, 0xf101, 0xf200, 0xf600, 0xfb00,
			     0xfc02, 0xfe01, 0xff00])
	# 2222/173D, 23/61
	pkt = NCP(0x173D, "Read Property Value", 'bindery')
	pkt.Request((15,77), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, 1, PropertySegment ),
		rec( -1, (1,16), PropertyName ),
	])
	pkt.Reply(138, [
		rec( 8, 128, PropertyData ),
		rec( 136, 1, PropertyHasMoreSegments ),
		rec( 137, 1, PropertyType ),
	])
	pkt.CompletionCodes([0x0000, 0x8800, 0x9300, 0x9600, 0xec01,
			     0xf000, 0xf100, 0xf900, 0xfb02, 0xfc02,
			     0xfe01, 0xff00])
	# 2222/173E, 23/62
	pkt = NCP(0x173E, "Read Property Value", 'bindery')
	pkt.Request((144,206), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, 1, PropertySegment ),
		rec( -1, 1, MoreFlag ),
		rec( -1, (1,16), PropertyName ),
		rec( -1, 128, PropertyValue ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xe800, 0xec01, 0xf000, 0xf800,
			     0xfb02, 0xfc03, 0xfe01, 0xff00 ])
	# 2222/173F, 23/63
	pkt = NCP(0x173F, "Verify Bindery Object Password", 'bindery')
	pkt.Request((14,92), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, (1,32), Password ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xe800, 0xec01, 0xf000, 0xf101,
			     0xfb02, 0xfc03, 0xfe01, 0xff00 ])
	# 2222/1740, 23/64
	pkt = NCP(0x1740, "Change Bindery Object Password", 'bindery')
	pkt.Request((15,124), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, (1,32), Password ),
		rec( -1, (1,32), NewPassword ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xc501, 0xd701, 0xe800, 0xec01, 0xf001,
			     0xf100, 0xf800, 0xfb02, 0xfc03, 0xfe01, 0xff00])
	# 2222/1741, 23/65
	pkt = NCP(0x1741, "Add Bindery Object To Set", 'bindery')
	pkt.Request((19,128), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, (1,16), PropertyName ),
		rec( -1, 4, MemberType ),
		rec( -1, (1,48), MemberName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xe800, 0xe900, 0xea00, 0xeb00,
			     0xec01, 0xf000, 0xf800, 0xfb02, 0xfc03, 0xfe01,
			     0xff00])
	# 2222/1742, 23/66
	pkt = NCP(0x1742, "Delete Bindery Object From Set", 'bindery')
	pkt.Request((19,128), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, (1,16), PropertyName ),
		rec( -1, 4, MemberType ),
		rec( -1, (1,48), MemberName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xeb00, 0xf000, 0xf800, 0xfb02,
			     0xfc03, 0xfe01, 0xff00])
	# 2222/1743, 23/67
	pkt = NCP(0x1743, "Is Bindery Object In Set", 'bindery')
	pkt.Request((19,128), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
		rec( -1, (1,16), PropertyName ),
		rec( -1, 4, MemberType ),
		rec( -1, (1,48), MemberName ),
	])
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
		rec( 9, 4, LoggedObjectID ),
	])
	pkt.CompletionCodes([0x0000, 0x9600])
	# 2222/1747, 23/71
	pkt = NCP(0x1747, "Scan Bindery Object Trustee Paths", 'bindery')
	pkt.Request(17, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 2, LastSequenceNumber ),
		rec( 13, 4, ObjectID ),
	])
	pkt.Reply((16,270), [
		rec( 8, 2, LastSequenceNumber),
		rec( 10, 4, ObjectID ),
		rec( 14, 1, ObjectSecurity ),
		rec( 15, (1,255), Path ),
	])
	pkt.CompletionCodes([0x0000, 0x9300, 0x9600, 0xa100, 0xf000, 0xf100,
			     0xf200, 0xfc02, 0xfe01, 0xff00])
	# 2222/1748, 23/72
	pkt = NCP(0x1748, "Get Bindery Object Access Level", 'bindery')
	pkt.Request(14, [
		rec( 10, 4, ObjectID ),
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
		rec( 18, 2, ObjectType ),
		rec( 20, (1,48), ObjectName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc500, 0xfe01, 0xff0c])
	# 2222/174B, 23/75
	pkt = NCP(0x174B, "Keyed Change Password", 'bindery')
	pkt.Request((22,100), [
		rec( 10, 8, LoginKey ),
		rec( 18, 2, ObjectType ),
		rec( 20, (1,48), ObjectName ),
		rec( -1, (1,32), Password ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc500, 0xfe01, 0xff0c])
	# 2222/174C, 23/76
	pkt = NCP(0x174C, "List Relations Of an Object", 'bindery')
	pkt.Request((18,80), [
		rec( 10, 4, LastSeen ),
		rec( 14, 2, ObjectType ),
		rec( 16, (1,48), ObjectName ),
		rec( -1, (1,16), PropertyName ),
	])
	pkt.Reply(14, [
		#This will return multiple records based on the count value.
		#Just showing first.
		rec( 8, 2, RelationsCount ),
		rec( 10, 4, ObjectID ),
	])
	pkt.CompletionCodes([0x0000, 0xf000, 0xf200, 0xfe01, 0xff00])
	# 2222/1764, 23/100
	pkt = NCP(0x1764, "Create Queue", 'qms')
	pkt.Request((15,316), [
		rec( 10, 2, QueueType ),
		rec( 12, (1,48), QueueName ),
		rec( -1, 1, PathBase ),
		rec( -1, (1,255), Path ),
	])
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
	pkt = NCP(0x1766, "Read Queue Current Status (old)", 'qms')
	pkt.Request(14, [
		rec( 10, 4, QueueID ),
	])
	pkt.Reply(19, [
		rec( 8, 4, QueueID ),
		rec( 12, 1, QueueStatus ),
		rec( 13, 1, CurrentEntries ),
		rec( 14, 1, CurrentServers ),
		#Multiple records returned based on CurrentServers count. Then followed
		#by ServerStationList (byte) for same count value. Display first record.
		rec( 15, 4, ServerIDList ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1767, 23/103
	pkt = NCP(0x1767, "Set Queue Current Status (old)", 'qms')
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
	pkt = NCP(0x1768, "Create Queue Job And File (old)", 'qms')
	pkt.Request(294, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, RecordInUseFlag, LE ),
		rec( 16, 4, PreviousRecord, LE ),
		rec( 20, 4, NextRecord, LE ),
		rec( 24, 4, ClientStation, LE ),
		rec( 28, 4, ClientTaskNumber, LE ),
		rec( 32, 4, ClientIDNumber ),
		rec( 36, 4, TargetServerIDNumber ),
		rec( 40, 6, TargetExecutionTime ),
		rec( 46, 6, JobEntryTime ),
		rec( 52, 4, JobNumber, LE ),
		rec( 56, 2, JobType, LE ),
		rec( 58, 2, JobPosition, LE ),
		rec( 60, 2, JobControlFlags, LE ),
		rec( 62, 14, JobFileName ),
		rec( 76, 4, JobFileHandle ),
		rec( 80, 4, ServerStation, LE ),
		rec( 84, 4, ServerTaskNumber, LE ),
		rec( 88, 4, ServerID ),
		rec( 92, 50, TextJobDescription ),
		rec( 142, 152, ClientRecordArea ),
	])
	pkt.Reply(61, [
		rec( 8, 1, ClientStation, LE ),
		rec( 9, 1, ClientTaskNumber, LE ),
		rec( 10, 4, ClientIDNumber ),
		rec( 14, 4, TargetServerIDNumber ),
		rec( 18, 6, TargetExecutionTime ),
		rec( 24, 6, JobEntryTime ),
		rec( 30, 4, JobNumber, LE ),
		rec( 34, 2, JobType, LE ),
		rec( 36, 1, JobPosition, LE ),
		rec( 37, 1, JobControlFlags, LE ),
		rec( 38, 14, JobFileName ),
		rec( 52, 6, JobFileHandle ),
		rec( 58, 1, ServerStation, LE ),
		rec( 59, 1, ServerTaskNumber, LE ),
		rec( 60, 1, ServerID ),
	])		
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xfc07,
			     0xff00])
	# 2222/1769, 23/105
	pkt = NCP(0x1769, "Close File And Start Queue Job (old)", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/176A, 23/106
	pkt = NCP(0x176A, "Remove Job From Queue (old)", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/176B, 23/107
	pkt = NCP(0x176B, "Get Queue Job List (old)", 'qms')
	pkt.Request(14, [
		rec( 10, 4, QueueID ),
	])
	pkt.Reply(14, [
		rec( 8, 2, JobCount, LE ),
		#Multiple jobs returned based on JobCount value. Display 1st record.
		rec( 10, 4, JobNumber, LE ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/176C, 23/108
	pkt = NCP(0x176C, "Read Queue Job Entry (old)", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
	])
	pkt.Reply(288, [
		rec( 8, 2, RecordInUseFlag, LE ),
		rec( 10, 4, PreviousRecord, LE ),
		rec( 14, 4, NextRecord, LE ),
		rec( 18, 4, ClientStation, LE ),
		rec( 22, 4, ClientTaskNumber, LE ),
		rec( 26, 4, ClientIDNumber ),
		rec( 30, 4, TargetServerIDNumber ),
		rec( 34, 6, TargetExecutionTime ),
		rec( 40, 6, JobEntryTime ),
		rec( 46, 4, JobNumber, LE ),
		rec( 50, 2, JobType, LE ),
		rec( 52, 2, JobPosition, LE ),
		rec( 54, 2, JobControlFlags, LE ),
		rec( 56, 14, JobFileName ),
		rec( 70, 4, JobFileHandle ),
		rec( 74, 4, ServerStation, LE ),
		rec( 78, 4, ServerTaskNumber, LE ),
		rec( 82, 4, ServerID ),
		rec( 86, 50, TextJobDescription ),
		rec( 136, 152, ClientRecordArea ),
	])		
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/176D, 23/109
	pkt = NCP(0x176D, "Change Queue Job Entry (old)", 'qms')
	pkt.Request(294, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, RecordInUseFlag, LE ),
		rec( 16, 4, PreviousRecord, LE ),
		rec( 20, 4, NextRecord, LE ),
		rec( 24, 4, ClientStation, LE ),
		rec( 28, 4, ClientTaskNumber, LE ),
		rec( 32, 4, ClientIDNumber ),
		rec( 36, 4, TargetServerIDNumber ),
		rec( 40, 6, TargetExecutionTime ),
		rec( 46, 6, JobEntryTime ),
		rec( 52, 4, JobNumber, LE ),
		rec( 56, 2, JobType, LE ),
		rec( 58, 2, JobPosition, LE ),
		rec( 60, 2, JobControlFlags, LE ),
		rec( 62, 14, JobFileName ),
		rec( 76, 4, JobFileHandle ),
		rec( 80, 4, ServerStation, LE ),
		rec( 84, 4, ServerTaskNumber, LE ),
		rec( 88, 4, ServerID ),
		rec( 92, 50, TextJobDescription ),
		rec( 142, 152, ClientRecordArea ),
	])
	pkt.Reply(8)		
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff18])
	# 2222/176E, 23/110
	pkt = NCP(0x176E, "Change Queue Job Position", 'qms')
	pkt.Request(19, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
		rec( 18, 1, NewPosition ),
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
	pkt = NCP(0x1771, "Service Queue Job (old)", 'qms')
	pkt.Request(16, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, ServiceType, LE ),
	])
	pkt.Reply(61, [
		rec( 8, 1, ClientStation ),
		rec( 9, 1, ClientTaskNumber ),
		rec( 10, 4, ClientIDNumber ),
		rec( 14, 4, TargetServerIDNumber ),
		rec( 18, 6, TargetExecutionTime ),
		rec( 24, 6, JobEntryTime ),
		rec( 30, 4, JobNumber, LE ),
		rec( 34, 2, JobType, LE ),
		rec( 36, 1, JobPosition, LE ),
		rec( 37, 1, JobControlFlags, LE ),
		rec( 38, 14, JobFileName ),
		rec( 52, 6, JobFileHandle ),
		rec( 58, 1, ServerStation, LE ),
		rec( 59, 1, ServerTaskNumber, LE ),
		rec( 60, 1, ServerID ),
	])		
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1772, 23/114
	pkt = NCP(0x1772, "Finish Servicing Queue Job (old)", 'qms')
	pkt.Request(22, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
		rec( 18, 4, ChargeInformation, LE ),
	])
	pkt.Reply(8)		
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1773, 23/115
	pkt = NCP(0x1773, "Abort Servicing Queue Job (old)", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
	])
	pkt.Reply(8)		
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff18])
	# 2222/1774, 23/116
	pkt = NCP(0x1774, "Change To Client Rights (old)", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
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
	pkt = NCP(0x1776, "Read Queue Server Current Status (old)", 'qms')
	pkt.Request(17, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, ServerID ),
		rec( 16, 1, ServerStation ),
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
	pkt = NCP(0x1778, "Get Queue Job File Size (old)", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
	])
	pkt.Reply(20, [
		rec( 8, 4, QueueID ),
		rec( 12, 4, JobNumber, LE ),
		rec( 16, 4, FileSize ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1779, 23/121
	pkt = NCP(0x1779, "Create Queue Job And File", 'qms')
	pkt.Request(294, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, RecordInUseFlag, LE ),
		rec( 16, 4, PreviousRecord, LE ),
		rec( 20, 4, NextRecord, LE ),
		rec( 24, 4, ClientStation, LE ),
		rec( 28, 4, ClientTaskNumber, LE ),
		rec( 32, 4, ClientIDNumber ),
		rec( 36, 4, TargetServerIDNumber ),
		rec( 40, 6, TargetExecutionTime ),
		rec( 46, 6, JobEntryTime ),
		rec( 52, 4, JobNumber, LE ),
		rec( 56, 2, JobType, LE ),
		rec( 58, 2, JobPosition, LE ),
		rec( 60, 2, JobControlFlags, LE ),
		rec( 62, 14, JobFileName ),
		rec( 76, 4, JobFileHandle ),
		rec( 80, 4, ServerStation, LE ),
		rec( 84, 4, ServerTaskNumber, LE ),
		rec( 88, 4, ServerID ),
		rec( 92, 50, TextJobDescription ),
		rec( 142, 152, ClientRecordArea ),
	])
	pkt.Reply(86, [
		rec( 8, 2, RecordInUseFlag, LE ),
		rec( 10, 4, PreviousRecord, LE ),
		rec( 14, 4, NextRecord, LE ),
		rec( 18, 4, ClientStation, LE ),
		rec( 22, 4, ClientTaskNumber, LE ),
		rec( 26, 4, ClientIDNumber ),
		rec( 30, 4, TargetServerIDNumber ),
		rec( 34, 6, TargetExecutionTime ),
		rec( 40, 6, JobEntryTime ),
		rec( 46, 4, JobNumber, LE ),
		rec( 50, 2, JobType, LE ),
		rec( 52, 2, JobPosition, LE ),
		rec( 54, 2, JobControlFlags, LE ),
		rec( 56, 14, JobFileName ),
		rec( 70, 4, JobFileHandle ),
		rec( 74, 4, ServerStation, LE ),
		rec( 78, 4, ServerTaskNumber, LE ),
		rec( 82, 4, ServerID ),
	])		
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/177A, 23/122
	pkt = NCP(0x177A, "Read Queue Job Entry", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
	])
	pkt.Reply(288, [
		rec( 8, 2, RecordInUseFlag, LE ),
		rec( 10, 4, PreviousRecord, LE ),
		rec( 14, 4, NextRecord, LE ),
		rec( 18, 4, ClientStation, LE ),
		rec( 22, 4, ClientTaskNumber, LE ),
		rec( 26, 4, ClientIDNumber ),
		rec( 30, 4, TargetServerIDNumber ),
		rec( 34, 6, TargetExecutionTime ),
		rec( 40, 6, JobEntryTime ),
		rec( 46, 4, JobNumber, LE ),
		rec( 50, 2, JobType, LE ),
		rec( 52, 2, JobPosition, LE ),
		rec( 54, 2, JobControlFlags, LE ),
		rec( 56, 14, JobFileName ),
		rec( 70, 4, JobFileHandle ),
		rec( 74, 4, ServerStation, LE ),
		rec( 78, 4, ServerTaskNumber, LE ),
		rec( 82, 4, ServerID ),
		rec( 86, 50, TextJobDescription ),
		rec( 136, 152, ClientRecordArea ),
	])		
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/177B, 23/123
	pkt = NCP(0x177B, "Change Queue Job Entry", 'qms')
	pkt.Request(294, [
		rec( 10, 4, QueueID ),
		rec( 14, 2, RecordInUseFlag, LE ),
		rec( 16, 4, PreviousRecord, LE ),
		rec( 20, 4, NextRecord, LE ),
		rec( 24, 4, ClientStation, LE ),
		rec( 28, 4, ClientTaskNumber, LE ),
		rec( 32, 4, ClientIDNumber ),
		rec( 36, 4, TargetServerIDNumber ),
		rec( 40, 6, TargetExecutionTime ),
		rec( 46, 6, JobEntryTime ),
		rec( 52, 4, JobNumber, LE ),
		rec( 56, 2, JobType, LE ),
		rec( 58, 2, JobPosition, LE ),
		rec( 60, 2, JobControlFlags, LE ),
		rec( 62, 14, JobFileName ),
		rec( 76, 4, JobFileHandle ),
		rec( 80, 4, ServerStation, LE ),
		rec( 84, 4, ServerTaskNumber, LE ),
		rec( 88, 4, ServerID ),
		rec( 92, 50, TextJobDescription ),
		rec( 142, 152, ClientRecordArea ),
	])
	pkt.Reply(8)		
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xfc07, 0xff00])
	# 2222/177C, 23/124
	pkt = NCP(0x177C, "Service Queue Job", 'qms')
	pkt.Request(16, [
		rec( 10, 4, ObjectID ),
		rec( 14, 2, ServiceType, LE ),
	])
	pkt.Reply(86, [
		rec( 8, 2, RecordInUseFlag, LE ),
		rec( 10, 4, PreviousRecord, LE ),
		rec( 14, 4, NextRecord, LE ),
		rec( 18, 4, ClientStation, LE ),
		rec( 22, 4, ClientTaskNumber, LE ),
		rec( 26, 4, ClientIDNumber ),
		rec( 30, 4, TargetServerIDNumber ),
		rec( 34, 6, TargetExecutionTime ),
		rec( 40, 6, JobEntryTime ),
		rec( 46, 4, JobNumber, LE ),
		rec( 50, 2, JobType, LE ),
		rec( 52, 2, JobPosition, LE ),
		rec( 54, 2, JobControlFlags, LE ),
		rec( 56, 14, JobFileName ),
		rec( 70, 4, JobFileHandle ),
		rec( 74, 4, ServerStation, LE ),
		rec( 78, 4, ServerTaskNumber, LE ),
		rec( 82, 4, ServerID ),
	])		
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/177D, 23/125
	pkt = NCP(0x177D, "Read Queue Current Status", 'qms')
	pkt.Request(14, [
		rec( 10, 4, QueueID ),
	])
	pkt.Reply(24, [
		rec( 8, 4, QueueID ),
		rec( 12, 1, QueueStatus ),
		rec( 13, 1, Reserved ),
		rec( 14, 2, Reserved2, LE ),
		rec( 16, 4, CurrentEntries, LE ),
		rec( 20, 4, CurrentServers, LE ),
		#Multiple records returned based on CurrentServers count. Then followed
		#by ServerStationList (byte) for same count value. Display first record.
		#[ 24, 4, ServerIDList, LE ],
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/177E, 23/126
	pkt = NCP(0x177E, "Set Queue Current Status", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 1, QueueStatus ),
		rec( 15, 1, Reserved ),
		rec( 16, 2, Reserved2 ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/177F, 23/127
	pkt = NCP(0x177F, "Close File And Start Queue Job", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1780, 23/128
	pkt = NCP(0x1780, "Remove Job From Queue", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1781, 23/129
	pkt = NCP(0x1781, "Get Queue Job List", 'qms')
	pkt.Request(14, [
		rec( 10, 4, QueueID ),
	])
	pkt.Reply(20, [
		rec( 8, 4, TotalQueueJobs, LE ),
		#Multiple jobs returned based on ReplyQueueJobNumbers value. Display 1st record.
		rec( 12, 4, ReplyQueueJobNumbers, LE ),
		rec( 16, 4, JobNumberList, LE ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1782, 23/130
	pkt = NCP(0x1782, "Change Job Priority", 'qms')
	pkt.Request(22, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
		rec( 18, 4, Priority, LE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1783, 23/131
	pkt = NCP(0x1783, "Finish Servicing Queue Job", 'qms')
	pkt.Request(22, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
		rec( 18, 4, ChargeInformation, LE ),
	])
	pkt.Reply(8)		
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1784, 23/132
	pkt = NCP(0x1784, "Abort Servicing Queue Job", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
	])
	pkt.Reply(8)		
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff18])
	# 2222/1785, 23/133
	pkt = NCP(0x1785, "Change To Client Rights", 'qms')
	pkt.Request(18, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
	])
	pkt.Reply(8)		
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff18])
	# 2222/1786, 23/134
	pkt = NCP(0x1786, "Read Queue Server Current Status", 'qms')
	pkt.Request(22, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, ServerID ),
		rec( 18, 4, ServerStation, LE ),
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
		rec( 14, 4, JobNumber, LE ),
	])
	pkt.Reply(20, [
		rec( 8, 4, QueueID ),
		rec( 12, 4, JobNumber, LE ),
		rec( 16, 4, FileSize ),
	])
	pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd200,
			     0xd300, 0xd400, 0xd500, 0xd601, 0xd703,
			     0xd800, 0xd902, 0xda01, 0xdb02, 0xff00])
	# 2222/1788, 23/136
	pkt = NCP(0x1788, "Move Queue Job From Src Q to Dst Q", 'qms')
	pkt.Request(22, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, JobNumber, LE ),
		rec( 18, 4, DstQueueID ),
	])
	pkt.Reply(12, [
		rec( 8, 4, JobNumber, LE ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0xfc06])
	# 2222/1789, 23/137
	pkt = NCP(0x1789, "Get Queue Jobs From Form List", 'qms')
	pkt.Request(24, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, QueueStartPosition, LE ),
		rec( 18, 4, FormTypeCnt, LE ),
		#multiple records in packet based on FormTypeCnt value. Display 1st record.
		rec( 22, 2, FormType, LE ),
	])
	pkt.Reply(20, [
		rec( 8, 4, TotalQueueJobs, LE ),
		rec( 12, 4, JobCount, LE ),
		rec( 16, 4, JobNumberList, LE ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0xfc06])
	# 2222/178A, 23/138
	pkt = NCP(0x178A, "Service Queue Job By Form List", 'qms')
	pkt.Request(24, [
		rec( 10, 4, QueueID ),
		rec( 14, 4, QueueStartPosition, LE ),
		rec( 18, 4, FormTypeCnt, LE ),
		#multiple records in packet based on FormTypeCnt value. Display 1st record.
		rec( 22, 2, FormType, LE ),
	])
	pkt.Reply(86, [
		rec( 8, 2, RecordInUseFlag, LE ),
		rec( 10, 4, PreviousRecord, LE ),
		rec( 14, 4, NextRecord, LE ),
		rec( 18, 4, ClientStation, LE ),
		rec( 22, 4, ClientTaskNumber, LE ),
		rec( 26, 4, ClientIDNumber ),
		rec( 30, 4, TargetServerIDNumber ),
		rec( 34, 6, TargetExecutionTime ),
		rec( 40, 6, JobEntryTime ),
		rec( 46, 4, JobNumber, LE ),
		rec( 50, 2, JobType, LE ),
		rec( 52, 2, JobPosition, LE ),
		rec( 54, 2, JobControlFlags, LE ),
		rec( 56, 14, JobFileName ),
		rec( 70, 4, JobFileHandle ),
		rec( 74, 4, ServerStation, LE ),
		rec( 78, 4, ServerTaskNumber, LE ),
		rec( 82, 4, ServerID ),
	])		
	pkt.CompletionCodes([0x0000, 0x7e01, 0xfc06])
	# 2222/1796, 23/150
	pkt = NCP(0x1796, "Get Current Account Status", 'accounting')
	pkt.Request((13,60), [
		rec( 10, 2, ObjectType ),
		rec( 12, (1,48), ObjectName ),
	])
	pkt.Reply(264, [
		rec( 8, 4, AccountBalance ),
		rec( 12, 4, CreditLimit ),
		rec( 16, 120, Reserved120 ),
		rec( 136, 4, HolderID, LE ),
		rec( 140, 4, HoldAmount ),
		rec( 144, 4, HolderID, LE ),
		rec( 148, 4, HoldAmount ),
		rec( 152, 4, HolderID, LE ),
		rec( 156, 4, HoldAmount ),
		rec( 160, 4, HolderID, LE ),
		rec( 164, 4, HoldAmount ),
		rec( 168, 4, HolderID, LE ),
		rec( 172, 4, HoldAmount ),
		rec( 176, 4, HolderID, LE ),
		rec( 180, 4, HoldAmount ),
		rec( 184, 4, HolderID, LE ),
		rec( 188, 4, HoldAmount ),
		rec( 192, 4, HolderID, LE ),
		rec( 196, 4, HoldAmount ),
		rec( 200, 4, HolderID, LE ),
		rec( 204, 4, HoldAmount ),
		rec( 208, 4, HolderID, LE ),
		rec( 212, 4, HoldAmount ),
		rec( 216, 4, HolderID, LE ),
		rec( 220, 4, HoldAmount ),
		rec( 224, 4, HolderID, LE ),
		rec( 228, 4, HoldAmount ),
		rec( 232, 4, HolderID, LE ),
		rec( 236, 4, HoldAmount ),
		rec( 240, 4, HolderID, LE ),
		rec( 244, 4, HoldAmount ),
		rec( 248, 4, HolderID, LE ),
		rec( 252, 4, HoldAmount ),
		rec( 256, 4, HolderID, LE ),
		rec( 260, 4, HoldAmount ),
	])		
	pkt.CompletionCodes([0x0000, 0x9600, 0xc000, 0xc101, 0xc400, 0xe800,
			     0xea00, 0xeb00, 0xec00, 0xfc06, 0xfe07, 0xff00])
	# 2222/1797, 23/151
	pkt = NCP(0x1797, "Submit Account Charge", 'accounting')
	pkt.Request((26,327), [
		rec( 10, 2, ServiceType ),
		rec( 12, 4, ChargeAmount ),
		rec( 16, 4, HoldCancelAmount ),
		rec( 20, 2, ObjectType ),
		rec( 22, 2, CommentType ),
		rec( 24, (1,48), ObjectName ),
		rec( -1, (1,255), Comment ),
	])
	pkt.Reply(8)		
	pkt.CompletionCodes([0x0000, 0x0102, 0x8800, 0x9400, 0x9600, 0xa201,
			     0xc000, 0xc101, 0xc200, 0xc400, 0xe800, 0xea00,
			     0xeb00, 0xec00, 0xfe07, 0xff00])
	# 2222/1798, 23/152
	pkt = NCP(0x1798, "Submit Account Hold", 'accounting')
	pkt.Request((17,64), [
		rec( 10, 4, HoldCancelAmount ),
		rec( 14, 2, ObjectType ),
		rec( 16, (1,48), ObjectName ),
	])
	pkt.Reply(8)		
	pkt.CompletionCodes([0x0000, 0x0102, 0x8800, 0x9400, 0x9600, 0xa201,
			     0xc000, 0xc101, 0xc200, 0xc400, 0xe800, 0xea00,
			     0xeb00, 0xec00, 0xfe07, 0xff00])
	# 2222/1799, 23/153
	pkt = NCP(0x1799, "Submit Account Note", 'accounting')
	pkt.Request((18,319), [
		rec( 10, 2, ServiceType ),
		rec( 12, 2, ObjectType ),
		rec( 14, 2, CommentType ),
		rec( 16, (1,48), ObjectName ),
		rec( -1, (1,255), Comment ),
	])
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
	pkt.Reply(520, [
		rec( 8, 512, DescriptionStrings ),
	])
	pkt.CompletionCodes([0x0000, 0x9600])
	# 2222/17CA, 23/202
	pkt = NCP(0x17CA, "Set File Server Date And Time", 'stats')
	pkt.Request(16, [
		rec( 10, 1, CurrentYear ),
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
	pkt = NCP(0x17D1, "Send Console Broadcast (old)", 'stats')
	pkt.Request(15, [
		rec( 10, 1, NumberOfStations ),
		#Station list records are repeated by NumberOfStations value, See NCP docs
		rec( 11, 4, StationList ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xc601, 0xfd00])
	# 2222/17D2, 23/210
	pkt = NCP(0x17D2, "Clear Connection Number (old)", 'stats')
	pkt.Request(11, [
		rec( 10, 1, ConnectionNumber ),
	])
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
		rec( 8, 4, SystemIntervalMarker ),
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
		rec( 8, 4, SystemIntervalMarker ),
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
		rec( 50, 1, NumberOfEntries ),
		#The next two records are repeated equal to NumberOfEntries
		rec( 51, 1, ConnectionNumber ),
		rec( 52, 1, TaskNumber ),
 	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xff00])
	# 2222/17D6, 23/214
	pkt = NCP(0x17D6, "Read Disk Cache Statistics", 'stats')
	pkt.Request(10)
	pkt.Reply(86, [
		rec( 8, 4, SystemIntervalMarker ),
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
		rec( 8, 4, SystemIntervalMarker ),
		rec( 12, 1, SFTSupportLevel ),
		rec( 13, 1, LogicalDriveCount ),
		rec( 14, 1, PhysicalDriveCount ),
		rec( 15, 1, DiskChannelTable ),
		rec( 16, 4, Reserved4 ),
		rec( 20, 2, PendingIOCommands ),
		rec( 22, 32, DriveMappingTable ),
		rec( 54, 32, DriveMirrorTable ),
		rec( 86, 32, DeadMirrorTable ),
		rec( 118, 1, ReMirrorDriveNumber ),
		rec( 119, 1, Filler ),
		rec( 120, 4, ReMirrorCurrentOffset ),
		rec( 124, 60, SFTErrorTable ),
 	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xff00])
	# 2222/17D8, 23/216
	pkt = NCP(0x17D8, "Read Physical Disk Statistics", 'stats')
	pkt.Request(11, [
		rec( 10, 1, PhysicalDiskNumber ),
	])
 	pkt.Reply(101, [
		rec( 8, 4, SystemIntervalMarker ),
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
		rec( 8, 4, SystemIntervalMarker ),
		rec( 12, 2, ChannelState ),
		rec( 14, 2, ChannelSynchronizationState ),
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
	pkt = NCP(0x17DB, "Get Connection's Open Files (old)", 'file')
	pkt.Request(14, [
		rec( 10, 2, ConnectionNumber ),
		rec( 12, 2, LastRecordSeen ),
	])
 	pkt.Reply(32, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 1, NumberOfRecords ),
		#Following records will be repeated based on NumberOfRecords value.
		rec( 11, 1, TaskNumber ),
		rec( 12, 1, LockType ),
		rec( 13, 1, AccessControl ),
		rec( 14, 1, LockFlag ),
		rec( 15, 1, VolumeNumber ),
		rec( 16, 2, DirectoryEntryNumberWord ),
		rec( 18, 14, FileName14 ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xff00])
	# 2222/17DC, 23/220
	pkt = NCP(0x17DC, "Get Connection Using A File (old)", 'file')
	pkt.Request((14,268), [
		rec( 10, 2, LastRecordSeen ),
		rec( 12, 1, DirHandle ),
		rec( 13, (1,255), Path ),
	])
 	pkt.Reply(30, [
		rec( 8, 2, UseCount ),
		rec( 10, 2, OpenCount ),
		rec( 12, 2, OpenForReadCount ),
		rec( 14, 2, OpenForWriteCount ),
		rec( 16, 2, DenyReadCount ),
		rec( 18, 2, DenyWriteCount ),
		rec( 20, 2, NextRequestRecord ),
		rec( 22, 1, Locked ),
		rec( 23, 1, NumberOfRecords ),
		#. . .repeats NumberOfRecords times. . .
		rec( 24, 2, ConnectionNumber ),
		rec( 26, 1, TaskNumber ),
		rec( 27, 1, LockType ),
		rec( 28, 1, AccessControl ),
		rec( 29, 1, LockFlag ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xff00])
	# 2222/17DD, 23/221
	pkt = NCP(0x17DD, "Get Physical Record Locks By Connection And File (old)", 'file')
	pkt.Request(31, [
		rec( 10, 2, TargetConnectionNumber ),
		rec( 12, 2, LastRecordSeen ),
		rec( 14, 1, VolumeNumber ),
		rec( 15, 2, DirectoryID, LE ),
		rec( 17, 14, FileName14 ),
	])
 	pkt.Reply(22, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 1, NumberOfLocks ),
		rec( 11, 1, Reserved ),
		#. . .repeats NumberOfLocks times. . .
		rec( 12, 1, TaskNumber ),
		rec( 13, 1, LockType ),
		rec( 14, 4, RecordStart ),
		rec( 18, 4, RecordEnd ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17DE, 23/222
	pkt = NCP(0x17DE, "Get Physical Record Locks By File (old)", 'file')
	pkt.Request((14,268), [
		rec( 10, 2, TargetConnectionNumber ),
		rec( 12, 1, DirHandle ),
		rec( 13, (1,255), Path ),
	])
 	pkt.Reply(28, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 1, NumberOfLocks ),
		rec( 11, 1, Reserved ),
		#. . .repeats NumberOfLocks times. . .
		rec( 12, 2, LoggedCount ),
		rec( 14, 2, ShareableLockCount ),
		rec( 16, 4, RecordStart ),
		rec( 20, 4, RecordEnd ),
		rec( 24, 2, LogicalConnectionNumber ),
		rec( 26, 1, TaskNumber ),
		rec( 27, 1, LockType ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17DF, 23/223
	pkt = NCP(0x17DF, "Get Logical Records By Connection (old)", 'file')
	pkt.Request(14, [
		rec( 10, 2, TargetConnectionNumber ),
		rec( 12, 2, LastRecordSeen ),
	])
 	pkt.Reply((14,268), [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 1, NumberOfRecords ),
		#. . .repeats NumberOfLocks times. . .
		rec( 11, 1, TaskNumber ),
		rec( 12, 1, LockStatus ),
		rec( 13, (1,255), LockName ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E0, 23/224
	pkt = NCP(0x17E0, "Get Logical Record Information (old)", 'file')
	pkt.Request((13,267), [
		rec( 10, 2, LastRecordSeen ),
		rec( 12, (1,255), LogicalRecordName ),
	])
 	pkt.Reply(20, [
		rec( 8, 2, UseCount ),
		rec( 10, 2, ShareableLockCount ),
		rec( 12, 2, NextRequestRecord ),
		rec( 14, 1, Locked ),
		rec( 15, 1, NumberOfRecords ),
		#. . .repeats NumberOfRecords times. . .
		rec( 16, 2, ConnectionNumber ),
		rec( 18, 1, TaskNumber ),
		rec( 19, 1, LockStatus ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E1, 23/225
	pkt = NCP(0x17E1, "Get Connection's Semaphores (old)", 'file')
	pkt.Request(14, [
		rec( 10, 2, ConnectionNumber ),
		rec( 12, 2, LastRecordSeen ),
	])
 	pkt.Reply((18,272), [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 2, NumberOfSemaphores ),
		#. . .repeats NumberOfSemaphores times. . .
		rec( 12, 2, OpenCount ),
		rec( 14, 2, SemaphoreValue ),
		rec( 16, 1, TaskNumber ),
		rec( 17, (1,255), SemaphoreName ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E2, 23/226
	pkt = NCP(0x17E2, "Get Semaphore Information (old)", 'file')
	pkt.Request((13,267), [
		rec( 10, 2, LastRecordSeen ),
		rec( 12, (1,255), SemaphoreName ),
	])
 	pkt.Reply(17, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 2, OpenCount ),
		rec( 12, 1, SemaphoreValue ),
		rec( 13, 1, NumberOfRecords ),
		#. . .repeats NumberOfRecords times. . .
		rec( 14, 2, LogicalConnectionNumber ),
		rec( 16, 1, TaskNumber ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E3, 23/227
	pkt = NCP(0x17E3, "Get LAN Driver Configuration Information", 'stats')
	pkt.Request(11, [
		rec( 10, 1, LANDriverNumber ),
	])
 	pkt.Reply(180, [
		rec( 8, 4, NetworkAddress ),
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
		rec( 10, 4, ObjectID, LE ),
	])
 	pkt.Reply(21, [
		rec( 8, 4, SystemIntervalMarker ),
		rec( 12, 4, ObjectID ),
		rec( 16, 4, UnusedDiskBlocks ),
		rec( 20, 1, RestrictionsEnforced ),
	 ])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E7, 23/231
	pkt = NCP(0x17E7, "Get File Server LAN I/O Statistics", 'stats')
	pkt.Request(10)
 	pkt.Reply(74, [
		rec( 8, 4, SystemIntervalMarker ),
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
		rec( 8, 4, SystemIntervalMarker ),
		rec( 12, 1, ProcessorType ),
		rec( 13, 1, Reserved ),
		rec( 14, 1, NumberOfServiceProcesses ),
		rec( 15, 1, ServerUtilizationPercentage ),
		rec( 16, 2, ConfiguredMaxBinderyObjects ),
		rec( 18, 2, ActualMaxBinderyObjects ),
		rec( 20, 2, CurrentUsedBinderyObjects ),
		rec( 22, 2, TotalServerMemory ),
		rec( 24, 2, WastedServerMemory ),
		rec( 26, 2, NumberOfDynamicMemoryAreas ),
		#. . .repeats NumerOfDynamicMemoryAreas times. . .
		rec( 28, 4, TotalDynamicSpace ),
		rec( 32, 4, MaxUsedDynamicSpace ),
		rec( 36, 4, CurrentUsedDynamicSpace ),
 	 ])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17E9, 23/233
	pkt = NCP(0x17E9, "Get Volume Information", 'stats')
	pkt.Request(11, [
		rec( 10, 1, VolumeNumber ),
	])
 	pkt.Reply(48, [
		rec( 8, 4, SystemIntervalMarker ),
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
		rec( 10, 4, NumberOfAttributes ),
		rec( 14, 4, Attributes ),
		# Attributes returned based on NumberOfAttributes
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
		rec( 10, 2, NumberOfRecords ),
		#Following records will be repeated based on NumberOfRecords value.
		rec( 12, 2, TaskNumber ),
		rec( 14, 1, LockType ),
		rec( 15, 1, AccessControl ),
		rec( 16, 1, LockFlag ),
		rec( 17, 1, VolumeNumber ),
		rec( 18, 4, DOSParentDirectoryEntry, LE ),
		rec( 22, 4, DOSDirectoryEntry, LE ),
		rec( 26, 1, ForkCount ),
		rec( 27, 1, NameSpace ),
		rec( 28, (1,255), FileName ),
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
		rec( 24, 2, NumberOfRecords ),
		#. . .repeats NumberOfRecords times. . .
		rec( 26, 2, ConnectionNumber ),
		rec( 28, 2, TaskNumber ),
		rec( 30, 1, LockType ),
		rec( 31, 1, AccessControl ),
		rec( 32, 1, LockFlag ),
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
		rec( 10, 2, NumberOfLocks ),
		#. . .repeats NumberOfLocks times. . .
		rec( 12, 2, TaskNumber ),
		rec( 14, 1, LockType ),
		rec( 15, 4, RecordStart ),
		rec( 19, 4, RecordEnd ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17EE, 23/238
	pkt = NCP(0x17EE, "Get Physical Record Locks By File", 'file')
	pkt.Request(18, [
		rec( 10, 1, DataStreamNumber ),
		rec( 11, 1, VolumeNumber ),
		rec( 12, 4, DirectoryBase, LE ),
		rec( 16, 2, LastRecordSeen ),
	])
 	pkt.Reply(30, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 2, NumberOfLocks ),
		#. . .repeats NumberOfLocks times. . .
		rec( 12, 2, LoggedCount ),
		rec( 14, 2, ShareableLockCount ),
		rec( 16, 4, RecordStart ),
		rec( 20, 4, RecordEnd ),
		rec( 24, 2, LogicalConnectionNumber ),
		rec( 26, 2, TaskNumber ),
		rec( 28, 2, LockType ),
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
		rec( 10, 2, NumberOfRecords ),
		#. . .repeats NumberOfLocks times. . .
		rec( 12, 2, TaskNumber ),
		rec( 14, 1, LockStatus ),
		rec( 15, (1,255), LockName ),
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
		rec( 15, 2, NumberOfRecords ),
		#. . .repeats NumberOfRecords times. . .
		rec( 17, 2, ConnectionNumber ),
		rec( 19, 2, TaskNumber ),
		rec( 21, 1, LockStatus ),
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
		rec( 10, 2, NumberOfSemaphores ),
		#. . .repeats NumberOfSemaphores times. . .
		rec( 12, 2, OpenCount ),
		rec( 14, 2, SemaphoreValue ),
		rec( 16, 2, TaskNumber ),
		rec( 18, (1,255), SemaphoreName ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17F2, 23/242
	pkt = NCP(0x17F2, "Get Semaphore Information", 'file')
	pkt.Request((13,267), [
		rec( 10, 2, LastRecordSeen ),
		rec( 12, (1,255), SemaphoreName ),
	])
 	pkt.Reply(20, [
		rec( 8, 2, NextRequestRecord ),
		rec( 10, 2, OpenCount ),
		rec( 12, 2, SemaphoreValue ),
		rec( 14, 2, NumberOfRecords ),
		#. . .repeats NumberOfRecords times. . .
		rec( 16, 2, LogicalConnectionNumber ),
		rec( 18, 2, TaskNumber ),
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
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17F4, 23/244
	pkt = NCP(0x17F4, "Convert Path to Dir Entry", 'file')
	pkt.Request((12,266), [
		rec( 10, 1, DirHandle ),
		rec( 11, (1,255), Path ),
	])
 	pkt.Reply(13, [
		rec( 8, 1, VolumeNumber ),
		rec( 9, 4, DirectoryNumber ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xc601, 0xfd00, 0xff00])
	# 2222/17FD, 23/253
	pkt = NCP(0x17FD, "Send Console Broadcast", 'stats')
	pkt.Request(15, [
		rec( 10, 1, NumberOfStations ),
		#Station list records are repeated by NumberOfStations value, See NCP docs
		rec( 11, 4, StationList ),
	])
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
	pkt = NCP(0x1A, "Log Physical Record (old)", 'file')
	pkt.Request(24, [
		rec( 7, 1, LockFlag ),
		rec( 8, 6, FileHandle ),
		rec( 14, 4, LockAreasStartOffset ),
		rec( 18, 4, LockAreaLen ),
		rec( 22, 2, LockTimeout ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0x9600, 0xfd02, 0xfe04, 0xff01])
	# 2222/1B, 27
	pkt = NCP(0x1B, "Lock Physical Record Set (old)", 'file')
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
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0x9600, 0xfd02, 0xfe04, 0xff03])
	# 2222/1D, 29
	pkt = NCP(0x1D, "Release Physical Record Set", 'file')
	pkt.Request(8, [
		rec( 7, 1, LockFlag ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0x9600, 0xfd02, 0xfe04, 0xff03])
	# 2222/1E, 30
	pkt = NCP(0x1E, "Clear Physical Record", 'file')
	pkt.Request(22, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
		rec( 14, 4, LockAreasStartOffset ),
		rec( 18, 4, LockAreaLen ),
	])
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
	pkt = NCP(0x2000, "Open Semaphore (old)", 'file', has_length=0)
	pkt.Request(10, [
		rec( 8, 1, InitialSemaphoreValue ),
		rec( 9, 1, SemaphoreNameLen ),
	])
	pkt.Reply(13, [
		  rec( 8, 4, SemaphoreHandle ),
		  rec( 12, 1, SemaphoreOpenCount ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xff01])
	# 2222/2001, 32/01
	pkt = NCP(0x2001, "Examine Semaphore (old)", 'file', has_length=0)
	pkt.Request(12, [
		rec( 8, 4, SemaphoreHandle ),
	])
	pkt.Reply(10, [
		  rec( 8, 1, SemaphoreValue ),
		  rec( 9, 1, SemaphoreOpenCount ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0xff01])
	# 2222/2002, 32/02
	pkt = NCP(0x2002, "Wait On Semaphore (old)", 'file', has_length=0)
	pkt.Request(14, [
		rec( 8, 4, SemaphoreHandle ),
		rec( 12, 2, SemaphoreTimeOut ), 
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xff01])
	# 2222/2003, 32/03
	pkt = NCP(0x2003, "Signal Semaphore (old)", 'file', has_length=0)
	pkt.Request(12, [
		rec( 8, 4, SemaphoreHandle ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xff01])
	# 2222/2004, 32/04
	pkt = NCP(0x2004, "Close Semaphore (old)", 'file', has_length=0)
	pkt.Request(12, [
		rec( 8, 4, SemaphoreHandle ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x9600, 0xff01])
	# 2222/21, 33
	pkt = NCP(0x21, "Negotiate Buffer Size", 'connection')
	pkt.Request(9, [
		rec( 7, 2, BufferSize ),
	])
	pkt.Reply(10, [
		rec( 8, 2, BufferSize ),
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
		  rec( 8, 4, TransactionNumber ),
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
		  rec( 8, 4, TransactionNumber ),
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
		rec( 24, 1, FinderAttrLow ),
		rec( 25, 1, FinderAttrHigh ),
		rec( 26, 2, HorizLocation ),
		rec( 28, 2, VertLocation ),
		rec( 30, 2, FileDirWindow ),
		rec( 32, 16, Reserved16 ),
		rec( 48, (1,255), Path ),
	])
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
		rec( 16, 4, CreatorID ),
		rec( 20, 4, Reserved4 ),
		rec( 24, 1, FinderAttrLow ),
		rec( 25, 1, FinderAttrHigh ),
		rec( 26, 2, HorizLocation ),
		rec( 28, 2, VertLocation ),
		rec( 30, 2, FileDirWindow ),
		rec( 32, 16, Reserved16 ),
		rec( 48, (1,255), Path ),
	])
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
	])
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
	])
	pkt.Reply(12, [
		rec( 8, 4, TargetEntryID ),
	])
	pkt.CompletionCodes([0x0000, 0x8301, 0x8800, 0x9300, 0x9600, 0x9804, 0x9c03,
			     0xa100, 0xa201, 0xfd00, 0xff19])
	# 2222/2305, 35/05
	pkt = NCP(0x2305, "AFP Get File Information", 'afp')
	pkt.Request((18,272), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, BaseDirectoryID ),
		rec( 15, 1, RequestBitMapHigh ),
		rec( 16, 1, RequestBitMapLow ),
		rec( 17, (1,255), Path ),
	])
	pkt.Reply(121, [
		rec( 8, 4, AFPEntryID ),
		rec( 12, 4, ParentID ),
		rec( 16, 1, AttributesDefLow ),
		rec( 17, 1, AttributesDefLow2 ),
		rec( 18, 4, DataForkLen ),
		rec( 22, 4, ResourceForkLen ),
		rec( 26, 2, TotalOffspring	),
		rec( 28, 2, CreationDate ),
		rec( 30, 2, LastAccessedDate ),
		rec( 32, 2, ModifiedDate ),
		rec( 34, 2, ModifiedTime ),
		rec( 36, 2, ArchivedDate ),
		rec( 38, 2, ArchivedTime ),
		rec( 40, 4, CreatorID ),
		rec( 44, 4, Reserved4 ),
		rec( 48, 1, FinderAttrLow ),
		rec( 49, 1, FinderAttrHigh ),
		rec( 50, 2, HorizLocation ),
		rec( 52, 2, VertLocation ),
		rec( 54, 2, FileDirWindow ),
		rec( 56, 16, Reserved16 ),
		rec( 72, 32, LongName ),
		rec( 104, 4, CreatorID ),
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
		rec( 9, 4, TargetEntryID ),
		rec( 13, 1, ForkIndicator ),
	])		
	pkt.CompletionCodes([0x0000, 0x8301, 0x8800, 0x9300, 0x9600, 0xa201])
	# 2222/2307, 35/07
	pkt = NCP(0x2307, "AFP Rename", 'afp')
	pkt.Request((21, 529), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, MacSourceBaseID ),
		rec( 15, 4, MacDestinationBaseID ),
		rec( 19, (1,255), Path ),
		rec( -1, (1,255), NewFileNameLen ),
	])
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
	])
	pkt.Reply(22, [
		rec( 8, 4, AFPEntryID ),
		rec( 12, 4, DataForkLen ),
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
		rec( 15, 1, RequestBitMapHigh ),
		rec( 16, 1, RequestBitMapLow ),
		rec( 17, 1, MacAttrHigh ),
		rec( 18, 1, MacAttrLow ),
		rec( 19, 2, CreationDate ),
		rec( 21, 2, LastAccessedDate ),
		rec( 23, 2, ModifiedDate ),
		rec( 25, 2, ModifiedTime ),
		rec( 27, 2, ArchivedDate ),
		rec( 29, 2, ArchivedTime ),
		rec( 31, 4, CreatorID ),
		rec( 35, 4, Reserved4 ),
		rec( 39, 1, FinderAttrLow ),
		rec( 40, 1, FinderAttrHigh ),
		rec( 41, 2, HorizLocation ),
		rec( 43, 2, VertLocation ),
		rec( 45, 2, FileDirWindow ),
		rec( 47, 16, Reserved16 ),
		rec( 63, (1,255), Path ),
	])
	pkt.Reply(8)		
	pkt.CompletionCodes([0x0000, 0x0104, 0x8301, 0x8800, 0x9300, 0x9400,
			     0x9500, 0x9600, 0x9804, 0x9c03, 0xa100, 0xa201,
			     0xfd00, 0xff16])
	# 2222/230A, 35/10
	pkt = NCP(0x230A, "AFP Scan File Information", 'afp')
	pkt.Request((26, 280), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, MacBaseDirectoryID ),
		rec( 15, 4, MacLastSeenID ),
		rec( 19, 2, DesiredResponseCount ),
		rec( 21, 2, SearchBitMap ),
		rec( 23, 1, RequestBitMapHigh ),
		rec( 24, 1, RequestBitMapLow ),
		rec( 25, (1,255), Path ),
	])
	pkt.Reply(10, [
		rec( 8, 2, ActualResponseCount ),
		#Repeated based on ActualResponseCount
		#[ 10, 4, AFPEntryID ],
		#[ 14, 4, ParentID ],
		#[ 18, 1, AttributesDefLow ],
		#[ 19, 1, AttributesDefLow2 ],
		#[ 20, 4, DataForkLen ],
		#[ 24, 4, ResourceForkLen ],
		#[ 28, 2, TotalOffspring	],
		#[ 30, 2, CreationDate ],
		#[ 32, 2, LastAccessedDate ],
		#[ 34, 2, ModifiedDate ],
		#[ 36, 2, ModifiedTime ],
		#[ 38, 2, ArchivedDate ],
		#[ 40, 2, ArchivedTime ],
		#[ 42, 4, CreatorID ],
		#[ 46, 4, Reserved4 ],
		#[ 50, 1, FinderAttrLow ],
		#[ 51, 1, FinderAttrHigh ],
		#[ 52, 2, HorizLocation ],
		#[ 54, 2, VertLocation ],
		#[ 56, 2, FileDirWindow ],
		#[ 58, 16, Reserved16 ],
		#[ 74, 32, LongName ],
		#[ 106, 4, CreatorID ],
		#[ 110, 12, ShortName ],
		#[ 122, 1, AccessPrivileges ],
	])	
	pkt.CompletionCodes([0x0000, 0x8301, 0x8800, 0x9300, 0x9600, 0x9804,
			     0x9c03, 0xa100, 0xa201, 0xfd00, 0xff16])
	# 2222/230B, 35/11
	pkt = NCP(0x230B, "AFP Alloc Temporary Directory Handle", 'afp')
	pkt.Request((16,270), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, MacBaseDirectoryID ),
		rec( 15, (1,255), Path ),
	])
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
	])
	pkt.Reply(12, [
		rec( 8, 4, AFPEntryID ),
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
		rec( 16, 4, CreatorID ),
		rec( 20, 4, Reserved4 ),
		rec( 24, 1, FinderAttrLow ),
		rec( 25, 1, FinderAttrHigh ),
		rec( 26, 2, HorizLocation ),
		rec( 28, 2, VertLocation ),
		rec( 30, 2, FileDirWindow ),
		rec( 32, 16, Reserved16 ),
		rec( 48, 6, ProDOSInfo ),
		rec( 54, (1,255), Path ),
	])
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
		rec( 16, 4, CreatorID ),
		rec( 20, 4, Reserved4 ),
		rec( 24, 1, FinderAttrLow ),
		rec( 25, 1, FinderAttrHigh ),
		rec( 26, 2, HorizLocation ),
		rec( 28, 2, VertLocation ),
		rec( 30, 2, FileDirWindow ),
		rec( 32, 16, Reserved16 ),
		rec( 48, 6, ProDOSInfo ),
		rec( 54, (1,255), Path ),
	])
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
		rec( 15, 1, RequestBitMapHigh ),
		rec( 16, 1, RequestBitMapLow ),
		rec( 17, (1,255), Path ),
	])
	pkt.Reply(128, [
		rec( 8, 4, AFPEntryID ),
		rec( 12, 4, ParentID ),
		rec( 16, 1, AttributesDefLow ),
		rec( 17, 1, AttributesDefLow2 ),
		rec( 18, 4, DataForkLen ),
		rec( 22, 4, ResourceForkLen ),
		rec( 26, 2, TotalOffspring	),
		rec( 28, 2, CreationDate ),
		rec( 30, 2, LastAccessedDate ),
		rec( 32, 2, ModifiedDate ),
		rec( 34, 2, ModifiedTime ),
		rec( 36, 2, ArchivedDate ),
		rec( 38, 2, ArchivedTime ),
		rec( 40, 4, CreatorID ),
		rec( 44, 4, Reserved4 ),
		rec( 48, 1, FinderAttrLow ),
		rec( 49, 1, FinderAttrHigh ),
		rec( 50, 2, HorizLocation ),
		rec( 52, 2, VertLocation ),
		rec( 54, 2, FileDirWindow ),
		rec( 56, 16, Reserved16 ),
		rec( 72, 32, LongName ),
		rec( 104, 4, CreatorID ),
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
		rec( 15, 1, RequestBitMapHigh ),
		rec( 16, 1, RequestBitMapLow ),
		rec( 17, 1, AttributesDefLow ),
		rec( 18, 1, AttributesDefLow2 ),
		rec( 19, 2, CreationDate ),
		rec( 21, 2, LastAccessedDate ),
		rec( 23, 2, ModifiedDate ),
		rec( 25, 2, ModifiedTime ),
		rec( 27, 2, ArchivedDate ),
		rec( 29, 2, ArchivedTime ),
		rec( 31, 4, CreatorID ),
		rec( 35, 4, Reserved4 ),
		rec( 39, 1, FinderAttrLow ),
		rec( 40, 1, FinderAttrHigh ),
		rec( 41, 2, HorizLocation ),
		rec( 43, 2, VertLocation ),
		rec( 45, 2, FileDirWindow ),
		rec( 47, 16, Reserved16 ),
		rec( 63, 6, ProDOSInfo ),
		rec( 69, (1,255), Path ),
	])
	pkt.Reply(8)		
	pkt.CompletionCodes([0x0000, 0x0104, 0x8301, 0x8800, 0x9300, 0x9400,
			     0x9500, 0x9600, 0x9804, 0x9c03, 0xa100, 0xa201,
			     0xfd00, 0xff16])
	# 2222/2311, 35/17
	pkt = NCP(0x2311, "AFP 2.0 Scan File Information", 'afp')
	pkt.Request((26, 280), [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, MacBaseDirectoryID ),
		rec( 15, 4, MacLastSeenID ),
		rec( 19, 2, DesiredResponseCount ),
		rec( 21, 2, SearchBitMap ),
		rec( 23, 1, RequestBitMapHigh ),
		rec( 24, 1, RequestBitMapLow ),
		rec( 25, (1,255), Path ),
	])
	pkt.Reply(10, [
		rec( 8, 2, ActualResponseCount ),
		#Repeated based on ActualResponseCount
		#[ 10, 4, AFPEntryID ],
		#[ 14, 4, ParentID ],
		#[ 18, 1, AttributesDefLow ],
		#[ 19, 1, AttributesDefLow2 ],
		#[ 20, 4, DataForkLen ],
		#[ 24, 4, ResourceForkLen ],
		#[ 28, 2, TotalOffspring	],
		#[ 30, 2, CreationDate ],
		#[ 32, 2, LastAccessedDate ],
		#[ 34, 2, ModifiedDate ],
		#[ 36, 2, ModifiedTime ],
		#[ 38, 2, ArchivedDate ],
		#[ 40, 2, ArchivedTime ],
		#[ 42, 4, CreatorID ],
		#[ 46, 4, Reserved4 ],
		#[ 50, 1, FinderAttrLow ],
		#[ 51, 1, FinderAttrHigh ],
		#[ 52, 2, HorizLocation ],
		#[ 54, 2, VertLocation ],
		#[ 56, 2, FileDirWindow ],
		#[ 58, 16, Reserved16 ],
		#[ 74, 32, LongName ],
		#[ 106, 4, CreatorID ],
		#[ 110, 12, ShortName ],
		#[ 122, 1, AccessPrivileges ],
		#[ 123, 1, Reserved ],
		#[ 124, 6, ProDOSInfo ],
	])	
	pkt.CompletionCodes([0x0000, 0x8301, 0x8800, 0x9300, 0x9600, 0x9804,
			     0x9c03, 0xa100, 0xa201, 0xfd00, 0xff16])
	# 2222/2312, 35/18
	pkt = NCP(0x2312, "AFP Get DOS Name From Entry ID", 'afp')
	pkt.Request(15, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, AFPEntryID ),
	])
	pkt.Reply((9,263), [
		rec( 8, (1,255), Path ),
	])	
	pkt.CompletionCodes([0x0000, 0x8900, 0x9600, 0xbf00])
	# 2222/2313, 35/19
	pkt = NCP(0x2313, "AFP Get Macintosh Info On Deleted File", 'afp')
	pkt.Request(15, [
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, DirectoryNumber ),
	])
	pkt.Reply((51,305), [
		rec( 8, 4, CreatorID ),
		rec( 12, 4, Reserved4 ),
		rec( 16, 1, FinderAttrLow ),
		rec( 17, 1, FinderAttrHigh ),
		rec( 18, 2, HorizLocation ),
		rec( 20, 2, VertLocation ),
		rec( 22, 2, FileDirWindow ),
		rec( 24, 16, Reserved16 ),
		rec( 40, 6, ProDOSInfo ),
		rec( 46, 4, ResourceForkSize ),
		rec( 50, (1,255), FileName ),
	])	
	pkt.CompletionCodes([0x0000, 0x9c03, 0xbf00])
	# 2222/2400, 36/00
	pkt = NCP(0x2400, "Get NCP Extension Information (old)", 'fileserver')
	pkt.Request(14, [
		rec( 10, 4, NCPextensionNumber, LE ),
	])
	pkt.Reply((16,270), [
		rec( 8, 4, NCPextensionNumber, LE ),
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
	])
	pkt.Reply((16,270), [
		rec( 8, 4, NCPextensionNumber, LE ),
		rec( 12, 1, NCPextensionMajorVersion ),
		rec( 13, 1, NCPextensionMinorVersion ),
		rec( 14, 1, NCPextensionRevisionNumber ),
		rec( 15, (1, 255), NCPextensionName ),
	])	
	pkt.CompletionCodes([0x0000, 0xfe00])
	# 2222/2403, 36/03
	pkt = NCP(0x2403, "Get Number of Registered NCP Extensions", 'fileserver')
	pkt.Request(10)
	pkt.Reply(12, [
		rec( 8, 4, NumberOfNCPExtensions, LE ),
	])	
	pkt.CompletionCodes([0x0000, 0xfe00])
	# 2222/2404, 36/04
	pkt = NCP(0x2404, "Get NCP Extension Registered Verbs List", 'fileserver')
	pkt.Request(14, [
		rec( 10, 4, StartingNumber ),
	])
	pkt.Reply(20, [
		rec( 8, 4, ReturnedListCount, LE ),
		rec( 12, 4, nextStartingNumber ),
		#Next attribute is based on ReturnedListCount
		rec( 16, 4, NCPExtensionNumbers ),
	])	
	pkt.CompletionCodes([0x0000, 0xfe00])
	# 2222/2405, 36/05
	pkt = NCP(0x2405, "Return NCP Extension Information", 'fileserver')
	pkt.Request(14, [
		rec( 10, 4, NCPextensionNumber, LE ),
	])
	pkt.Reply((16,270), [
		rec( 8, 4, NCPextensionNumber, LE ),
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
		rec( 7, 4, NCPextensionNumber, LE ),
		# The following value is Unicode
		#[ 13, (1,255), RequestData ],
	])
	pkt.Reply(8)
		# The following value is Unicode
		#[ 8, (1, 255), ReplyBuffer ],
	pkt.CompletionCodes([0x0000, 0xee00, 0xfe00])
	# 2222/3B, 59
	pkt = NCP(0x3B, "Commit File", 'file', has_length=0 )
	pkt.Request(14, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
	])
	pkt.Reply(8)	
	pkt.CompletionCodes([0x0000, 0x8800, 0x9804, 0xff00])
	# 2222/3E, 62
	pkt = NCP(0x3E, "File Search Initialize", 'file', has_length=0 )
	pkt.Request((9, 263), [
		rec( 7, 1, DirHandle ),
		rec( 8, (1,255), Path ),
	])
	pkt.Reply(14, [
		rec( 8, 1, VolumeNumber ),
		rec( 9, 2, DirectoryID ),
		rec( 11, 2, SequenceNumber, LE ),
		rec( 13, 1, AccessRightsMask ),
	])
	pkt.CompletionCodes([0x0000, 0x9600, 0x9804, 0x9b03, 0x9c03, 0xa100,
			     0xfd00, 0xff16])
	# 2222/3F, 63
	pkt = NCP(0x3F, "File Search Continue", 'file', has_length=0 )
	pkt.Request((14, 268), [
		rec( 7, 1, VolumeNumber ),
		rec( 8, 2, DirectoryID ),
		rec( 10, 2, SequenceNumber, LE ),
		rec( 12, 1, SearchAttributes ),
		rec( 13, (1,255), Path ),
	])
	pkt.Reply(28, [
		rec( 8, 2, SequenceNumber, LE ),
		rec( 10, 2, DirectoryID ),
		rec( 12, 2, Reserved2 ),
		rec( 14, 14, FileName14 ),
		#The rest of this packet depends on whether a file or directory was search for.
		#See SearchAttributes in request for Directory flag.
	])
	pkt.CompletionCodes([0x0000, 0xff16])
	# 2222/40, 64
	pkt = NCP(0x40, "Search for a File", 'file')
	pkt.Request((12, 266), [
		rec( 7, 2, SequenceNumber, LE ),
		rec( 9, 1, DirHandle ),
		rec( 10, 1, SearchAttributes ),
		rec( 11, (1,255), FileName ),
	])
	pkt.Reply(40, [
		rec( 8, 2, SequenceNumber, LE ),
		rec( 10, 2, Reserved2 ),
		rec( 12, 14, FileName14 ),
		rec( 26, 1, AttributesDefLow ),
		rec( 27, 1, FileExecuteType ),
		rec( 28, 4, FileSize ),
		rec( 32, 2, CreationDate ),
		rec( 34, 2, LastAccessedDate ),
		rec( 36, 2, ModifiedDate ),
		rec( 38, 2, ModifiedTime ),
	])
	pkt.CompletionCodes([0x0000, 0x8900, 0x9600, 0x9804, 0x9b03,
			     0x9c03, 0xa100, 0xfd00, 0xff16])
	# 2222/41, 65
	pkt = NCP(0x41, "Open File (old)", 'file')
	pkt.Request((10, 264), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, SearchAttributes ),
		rec( 9, (1,255), FileName ),
	])
	pkt.Reply(44, [
		rec( 8, 6, FileHandle ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 14, FileName14 ),
		rec( 30, 1, AttributesDefLow ),
		rec( 31, 1, FileExecuteType ),
		rec( 32, 4, FileSize ),
		rec( 36, 2, CreationDate ),
		rec( 38, 2, LastAccessedDate ),
		rec( 40, 2, ModifiedDate ),
		rec( 42, 2, ModifiedTime ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8200, 0x9400,
			     0x9600, 0x9804, 0x9c03, 0xa100, 0xfd00,
			     0xff16])
	# 2222/42, 66
	pkt = NCP(0x42, "Close File", 'file')
	pkt.Request(14, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0xff1a])
	# 2222/43, 67
	pkt = NCP(0x43, "Create File", 'file')
	pkt.Request((10, 264), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, AttributesDefLow ),
		rec( 9, (1,255), FileName ),
	])
	pkt.Reply(44, [
		rec( 8, 6, FileHandle ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 14, FileName14 ),
		rec( 30, 1, AttributesDefLow ),
		rec( 31, 1, FileExecuteType ),
		rec( 32, 4, FileSize ),
		rec( 36, 2, CreationDate ),
		rec( 38, 2, LastAccessedDate ),
		rec( 40, 2, ModifiedDate ),
		rec( 42, 2, ModifiedTime ),
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
	])
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
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8701, 0x8b00, 0x8d00, 0x8e00,
			     0x8f00, 0x9001, 0x9101, 0x9201, 0x9600,
			     0x9804, 0x9a00, 0x9b03, 0x9c03, 0xa100,
			     0xfd00, 0xff16])
	# 2222/46, 70
	pkt = NCP(0x46, "Set File Attributes", 'file')
	pkt.Request((11, 265), [
		rec( 7, 1, AttributesDefLow ),
		rec( 8, 1, DirHandle ),
		rec( 9, 1, SearchAttributes ),
		rec( 10, (1,255), FileName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8c00, 0x8d00, 0x8e00, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa100, 0xfd00,
			     0xff16])
	# 2222/47, 71
	pkt = NCP(0x47, "Get Current Size of File", 'file')
	pkt.Request(13, [
		rec( 7, 6, FileHandle ),
	])
	pkt.Reply(12, [
		rec( 8, 4, FileSize ),
	])
	pkt.CompletionCodes([0x0000, 0x8800])
	# 2222/48, 72
	pkt = NCP(0x48, "Read From A File", 'file')
	pkt.Request(20, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
		rec( 14, 4, FileOffset ),	# my nomenclature
		rec( 18, 2, MaxBytes ),	# my nomenclature
	])
	pkt.Reply(10, [ # XXX - (10,-1), [
		rec( 8, 2, NumBytes ),	# my nomenclature
		#Next attribute is Data sizeof based on NumBytes
	])
	pkt.CompletionCodes([0x0000, 0x8300, 0x8800, 0x9300, 0xff00])
	# 2222/49, 73
	pkt = NCP(0x49, "Write to a File", 'file')
	pkt.Request(20, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
		rec( 14, 4, FileOffset ),	# my nomenclature
		rec( 18, 2, MaxBytes ),	# my nomenclature
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8300, 0x8800, 0x9400, 0x9500, 0xa201, 0xff1b])
	# 2222/4A, 74
	pkt = NCP(0x4A, "Copy from One File to Another", 'file')
	pkt.Request(30, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
		rec( 14, 6, TargetFileHandle ),
		rec( 20, 4, FileOffset ),
		rec( 24, 4, TargetFileOffset ),
		rec( 28, 2, BytesToCopy ),
	])
	pkt.Reply(12, [
		rec( 8, 4, BytesActuallyTransferred ),
	])
	pkt.CompletionCodes([0x0000, 0x0104, 0x8300, 0x8800, 0x9300, 0x9400,
			     0x9500, 0x9600, 0xa201, 0xff1b])
	# 2222/4B, 75
	pkt = NCP(0x4B, "Set File Time Date Stamp", 'file')
	pkt.Request(18, [
		rec( 7, 1, Reserved ),
		rec( 8, 6, FileHandle ),
		rec( 14, 2, FileTime ),
		rec( 16, 2, FileDate ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800, 0x9600])
	# 2222/4C, 76
	pkt = NCP(0x4C, "Open File", 'file')
	pkt.Request((11, 265), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, SearchAttributes ),
		rec( 9, 1, AccessRightsMask ),
		rec( 10, (1,255), FileName ),
	])
	pkt.Reply(44, [
		rec( 8, 6, FileHandle ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 14, FileName14 ),
		rec( 30, 1, AttributesDefLow ),
		rec( 31, 1, FileExecuteType ),
		rec( 32, 4, FileSize ),
		rec( 36, 2, CreationDate ),
		rec( 38, 2, LastAccessedDate ),
		rec( 40, 2, ModifiedDate ),
		rec( 42, 2, ModifiedTime ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8200, 0x9400,
			     0x9600, 0x9804, 0x9c03, 0xa100, 0xfd00,
			     0xff16])
	# 2222/4D, 77
	pkt = NCP(0x4D, "Create File", 'file')
	pkt.Request((10, 264), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, AttributesDefLow ),
		rec( 9, (1,255), FileName ),
	])
	pkt.Reply(44, [
		rec( 8, 6, FileHandle ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 14, FileName14 ),
		rec( 30, 1, AttributesDefLow ),
		rec( 31, 1, FileExecuteType ),
		rec( 32, 4, FileSize ),
		rec( 36, 2, CreationDate ),
		rec( 38, 2, LastAccessedDate ),
		rec( 40, 2, ModifiedDate ),
		rec( 42, 2, ModifiedTime ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9900, 0x9b03, 0x9c03, 0xfd00,
			     0xff00])
	# 2222/4F, 79
	pkt = NCP(0x4F, "Set File Extended Attributes", 'file')
	pkt.Request((11, 265), [
		rec( 7, 1, AttributesDefLow ),
		rec( 8, 1, DirHandle ),
		rec( 9, 1, AccessRightsMask ),
		rec( 10, (1,255), FileName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8c00, 0x8d00, 0x8e00, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa100, 0xfd00,
			     0xff16])
	# 2222/54, 84
	pkt = NCP(0x54, "Open/Create File (old)", 'file')
	pkt.Request((12, 266), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, AttributesDefLow ),
		rec( 9, 1, AccessRightsMask ),
		rec( 10, 1, ActionFlag ),
		rec( 11, (1,255), FileName ),
	])
	pkt.Reply(44, [
		rec( 8, 6, FileHandle ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 14, FileName14 ),
		rec( 30, 1, AttributesDefLow ),
		rec( 31, 1, FileExecuteType ),
		rec( 32, 4, FileSize ),
		rec( 36, 2, CreationDate ),
		rec( 38, 2, LastAccessedDate ),
		rec( 40, 2, ModifiedDate ),
		rec( 42, 2, ModifiedTime ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/55, 85
	pkt = NCP(0x55, "Get Sparse File Data Block Bit Map", 'file')
	pkt.Request(17, [
		rec( 7, 6, FileHandle ),
		rec( 13, 4, FileOffset ),
	])
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
	pkt.Request(34, [
		rec( 8, 2, EAFlags, LE ),
		rec( 10, 4, EAHandleOrNetWareHandleOrVolume ),
		rec( 14, 4, ReservedOrDirectoryNumber ),
		rec( 18, 4, TtlWriteDataSize ),
		rec( 22, 4, FileOffset ),
		rec( 26, 4, EAAccessFlag ),
		rec( 30, 2, EAValueLength ),
		rec( 32, 2, EAKeyLength ),
		#next 2 attributes (key and value) are sizeof EAValueLength and EAKeyLength
	])
	pkt.Reply(20, [
		rec( 8, 4, EAErrorCodes ),
		rec( 12, 4, BytesWritten ),
		rec( 16, 4, NewEAHandle ),
	])
	pkt.CompletionCodes([0x0000, 0xc800, 0xc900, 0xcb00, 0xce00, 0xcf00, 0xd101,
			     0xd203, 0xd301, 0xd402])
	# 2222/5603, 86/03
	pkt = NCP(0x5603, "Read Extended Attribute", 'file', has_length=0 )
	pkt.Request(28, [
		rec( 8, 2, EAFlags, LE ),
		rec( 10, 4, EAHandleOrNetWareHandleOrVolume ),
		rec( 14, 4, ReservedOrDirectoryNumber ),
		rec( 18, 4, FileOffset ),
		rec( 22, 4, InspectSize ),
		rec( 26, 2, EAKeyLength ),
		#next attribute (key) is sizeof EAKeyLength
	])
	pkt.Reply(28, [
		rec( 8, 4, EAErrorCodes ),
		rec( 12, 4, TtlValuesLength ),
		rec( 16, 4, NewEAHandle ),
		rec( 20, 4, EAAccessFlag ),
		rec( 24, 4, EAValueLength ),
		#next attribute (value) is sizeof EAValueLength
	])
	pkt.CompletionCodes([0x0000, 0xc900, 0xce00, 0xcf00, 0xd101,
			     0xd301])
	# 2222/5604, 86/04
	pkt = NCP(0x5604, "Enumerate Extended Attribute", 'file', has_length=0 )
	pkt.Request(26, [
		rec( 8, 2, EAFlags, LE ),
		rec( 10, 4, EAHandleOrNetWareHandleOrVolume ),
		rec( 14, 4, ReservedOrDirectoryNumber ),
		rec( 18, 4, InspectSize ),
		rec( 22, 2, SequenceNumber, LE ),
		rec( 24, 2, EAKeyLength ),
		#next attribute (key) is sizeof EAKeyLength
	])
	pkt.Reply(28, [
		rec( 8, 4, EAErrorCodes ),
		rec( 12, 4, TtlEAs ),
		rec( 16, 4, TtlEAsDataSize ),
		rec( 20, 4, TtlEAsKeySize ),
		rec( 24, 4, NewEAHandle ),
	])
	pkt.CompletionCodes([0x0000, 0xc900, 0xce00, 0xcf00, 0xd101,
			     0xd301])
	# 2222/5605, 86/05
	pkt = NCP(0x5605, "Duplicate Extended Attributes", 'file', has_length=0 )
	pkt.Request(28, [
		rec( 8, 2, EAFlags, LE ),
		rec( 10, 2, DstEAFlags, LE ),
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
		rec( 10, 1, SearchAttributesLow ),
		rec( 11, 1, SearchAttributesHigh ),
		rec( 12, 1, ReturnInfoMaskLow ),
		rec( 13, 1, ReturnInfoMaskHigh ),
		rec( 14, 1, ExtendedInfoLow ),
		rec( 15, 1, ExtendedInfoHigh ),
		rec( 16, 1, AttributesDefLow ),
		rec( 17, 1, AttributesDefLow2 ),
		rec( 18, 1, AttributesDefLow3 ),
		rec( 19, 1, Reserved ),
		rec( 20, 1, DesiredAccessRightsLow ),
		rec( 21, 1, DesiredAccessRightsHigh ),
		rec( 22, 1, VolumeNumber ),
		rec( 23, 4, DirectoryBase, LE ),
		rec( 27, 1, HandleFlag ),
		rec( 28, 1, PathCount, var="x" ),
		rec( 29, (1,255), Path, repeat="x" ),
	])
	pkt.Reply( 14, [
		# The reply structure depends on the request flags in the request packet.
		#(91,345), [
		rec( 8, 4, FileHandle ),
		rec( 12, 1, OpenCreateAction ),
		rec( 13, 1, Reserved ),
		#rec( 14, 4, DataStreamSpaceAlloc, LE ),
		#rec( 18, 1, AttributesDefLow ),
		#rec( 19, 1, AttributesDefLow2 ),
		#rec( 20, 1, AttributesDefLow3 ),
		#rec( 21, 1, Reserved ),
		#rec( 22, 2, FlagsDef, LE ),
		#rec( 24, 4, DataStreamSize, LE ),
		#rec( 28, 4, TtlDSDskSpaceAlloc, LE ),
		#rec( 32, 2, NumberOfDataStreams, LE ),
		#rec( 34, 2, CreationTime, LE ),
		#rec( 36, 2, CreationDate, LE ),
		#rec( 38, 4, CreatorID ),
		#rec( 42, 2, ModifiedTime, LE ),
		#rec( 44, 2, ModifiedDate, LE ),
		#rec( 46, 4, ModifierID ),
		#rec( 50, 2, LastAccessedDate, LE ),
		#rec( 52, 2, ArchivedTime, LE ),
		#rec( 54, 2, ArchivedDate, LE ),
		#rec( 56, 4, ArchiverID ),
		#rec( 60, 1, InheritedRightsMaskLow ),
		#rec( 61, 1, InheritedRightsMaskHigh ),
		#rec( 62, 4, DirectoryEntryNumber, LE ),
		#rec( 66, 4, DOSDirectoryEntryNumber, LE ),
		#rec( 70, 4, VolumeNumberLong, LE ),
		#rec( 74, 4, EADataSize, LE ),
		#rec( 78, 4, EACount, LE ),
		#rec( 82, 4, EAKeySize, LE ),
		#rec( 86, 4, CreatorNameSpaceNumber, LE ),
		#rec( 90, (1,255), FileName ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5702, 87/02
	pkt = NCP(0x5702, "Initialize Search", 'file', has_length=0)
	pkt.Request( (18,272), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, Reserved ),
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, DirectoryBase, LE ),
		rec( 15, 1, HandleFlag ),
		rec( 16, 1, PathCount, var="x" ),
		rec( 17, (1,255), Path, repeat="x" ),
	])
	pkt.Reply(17, [
		rec( 8, 1, VolumeNumber ),
		rec( 9, 4, DirectoryNumber, LE ),
		rec( 13, 4, DirectoryEntryNumber, LE ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5703, 87/03
	pkt = NCP(0x5703, "Search for File or Subdirectory", 'file', has_length=0)
	pkt.Request((26, 280), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, DataStream ),
		rec( 10, 1, SearchAttributesLow ),
		rec( 11, 1, SearchAttributesHigh ),
		rec( 12, 1, ReturnInfoMaskLow ),
		rec( 13, 1, ReturnInfoMaskHigh ),
		rec( 14, 1, ExtendedInfoLow ),
		rec( 15, 1, ExtendedInfoHigh ),
		rec( 16, 9, SearchSequence ),
		rec( 25, (1,255), SearchPattern ),
	])
	pkt.Reply( 18, [
		# Reply format is based on the returninfomask in request packet
		#(95,349), [
		rec( 8, 9, SearchSequence ),
		rec( 17, 1, Reserved ),
		#rec( 18, 4, DataStreamSpaceAlloc, LE ),
		#rec( 22, 1, AttributesDefLow ),
		#rec( 23, 1, AttributesDefLow2 ),
		#rec( 24, 1, AttributesDefLow3 ),
		#rec( 25, 1, Reserved ),
		#rec( 26, 2, FlagsDef, LE ),
		#rec( 28, 4, DataStreamSize, LE ),
		#rec( 32, 4, TtlDSDskSpaceAlloc, LE ),
		#rec( 36, 2, NumberOfDataStreams, LE ),
		#rec( 38, 2, CreationTime, LE ),
		#rec( 40, 2, CreationDate, LE ),
		#rec( 42, 4, CreatorID ),
		#rec( 46, 2, ModifiedTime, LE ),
		#rec( 48, 2, ModifiedDate, LE ),
		#rec( 50, 4, ModifierID ),
		#rec( 54, 2, LastAccessedDate, LE ),
		#rec( 56, 2, ArchivedTime, LE ),
		#rec( 58, 2, ArchivedDate, LE ),
		#rec( 60, 4, ArchiverID ),
		#rec( 64, 1, InheritedRightsMaskLow ),
		#rec( 65, 1, InheritedRightsMaskHigh ),
		#rec( 66, 4, DirectoryEntryNumber, LE ),
		#rec( 70, 4, DOSDirectoryEntryNumber, LE ),
		#rec( 74, 4, VolumeNumberLong, LE ),
		#rec( 78, 4, EADataSize, LE ),
		#rec( 82, 4, EACount, LE ),
		#rec( 86, 4, EAKeySize, LE ),
		#rec( 90, 4, CreatorNameSpaceNumber, LE ),
		#rec( 94, (1,255), FileName ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5704, 87/04
	pkt = NCP(0x5704, "Rename Or Move a File or Subdirectory", 'file', has_length=0)
	pkt.Request((28, 536), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, RenameFlag ),
		rec( 10, 1, SearchAttributesLow ),
		rec( 11, 1, SearchAttributesHigh ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase, LE ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount ),
		#Path count determines source path
		rec( 19, 1, VolumeNumber ),
		rec( 20, 4, DirectoryBase, LE ),
		rec( 24, 1, HandleFlag ),
		rec( 25, 1, PathCount ),
		#Path count determines destination path
		rec( 26, (1, 255), Path ),
		rec( -1, (1,255), Path ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5705, 87/05
	pkt = NCP(0x5705, "Scan File or Subdirectory for Trustees", 'file', has_length=0)
	pkt.Request((24, 278), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, Reserved ),
		rec( 10, 1, SearchAttributesLow ),
		rec( 11, 1, SearchAttributesHigh ),
		rec( 12, 4, SequenceNumber, LE ),
		rec( 16, 1, VolumeNumber ),
		rec( 17, 4, DirectoryBase, LE ),
		rec( 21, 1, HandleFlag ),
		rec( 22, 1, PathCount, var="x" ),
		rec( 23, (1, 255), Path, repeat="x" ),
	])
	pkt.Reply(20, [
		rec( 8, 4, SequenceNumber, LE ),
		rec( 12, 2, ObjectIDCount, LE ),
		#next 2 attributes are repeated based on ObjectIDCount up to 20.
		rec( 14, 4, ObjectID ),
		rec( 18, 2, AccessRightsMask, LE ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5706, 87/06
	pkt = NCP(0x5706, "Obtain File or SubDirectory Information", 'file', has_length=0)
	pkt.Request((24,278), [
		rec( 10, 1, SrcNameSpace ),
		rec( 11, 1, DestNameSpace ),
		rec( 12, 1, SearchAttributesLow ),
		rec( 13, 1, SearchAttributesHigh ),
		rec( 14, 1, ReturnInfoMaskLow ),
		rec( 15, 1, ReturnInfoMaskHigh ),
		rec( 16, 1, ExtendedInfoLow ),
		rec( 17, 1, ExtendedInfoHigh ),
		rec( 18, 1, VolumeNumber ),
		rec( 19, 4, DirectoryBase, LE ),
		rec( 23, 1, HandleFlag ),
		rec( 24, 1, PathCount, var="x" ),
		rec( 25, (1,255), Path, repeat="x" ),
	])
	pkt.Reply(8)
#	pkt.Reply(84, [
#		[ 8, 4, DataStreamSpaceAlloc ],
#		[ 12, 1, AttributesDefLow ],
#		[ 13, 1, AttributesDefLow2 ],
#		[ 14, 1, AttributesDefLow3 ],
#		[ 15, 1, Reserved ],
#		[ 16, 2, FlagsDef, LE ],
#		[ 18, 4, DataStreamSize ],
#		[ 22, 4, TtlDSDskSpaceAlloc ],
#		[ 26, 2, NumberOfDataStreams ],
#		[ 28, 2, CreationTime ],
#		[ 30, 2, CreationDate ],
#		[ 32, 4, CreatorID ],
#		[ 36, 2, ModifiedTime ],
#		[ 38, 2, ModifiedDate ],
#		[ 40, 4, ModifierID ],
#		[ 44, 2, LastAccessedDate ],
#		[ 46, 2, ArchivedTime ],
#		[ 48, 2, ArchivedDate ],
#		[ 50, 4, ArchiverID ],
#		[ 54, 1, InheritedRightsMaskLow ],
#		[ 55, 1, InheritedRightsMaskHigh ],
#		[ 56, 4, DirectoryEntryNumber, LE ],
#		[ 60, 4, DOSDirectoryEntryNumber, LE ],
#		[ 64, 4, VolumeNumberLong ],
#		[ 68, 4, EADataSize ],
#		[ 72, 4, EACount ],
#		[ 76, 4, EAKeySize ],
#		[ 80, 4, CreatorNameSpaceNumber ],
#		[ 84, (1,255), FileName ],
# This reply packet is formated based on the ReturnInformation flags set in the
# request packet. Need do case to evaluate what will be in the reply packet
# decode.
#	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5707, 87/07
	pkt = NCP(0x5707, "Modify File or Subdirectory DOS Information", 'file', has_length=0)
	pkt.Request((62,316), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 1, SearchAttributesLow ),
		rec( 11, 1, SearchAttributesHigh ),
		rec( 12, 1, ModifyDOSInfoMaskLow ),
		rec( 13, 1, ModifyDOSInfoMaskHigh ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 1, AttributesDefLow, LE ),
		rec( 17, 1, AttributesDefLow2, LE ),
		rec( 18, 1, FileMode ),
		rec( 19, 1, FileExtendedAttributes ),
		rec( 20, 2, CreationDate, LE ),
		rec( 22, 2, CreationTime, LE ),
		rec( 24, 4, CreatorID ),
		rec( 28, 2, ModifiedDate, LE ),
		rec( 30, 2, ModifiedTime, LE ),
		rec( 32, 4, ModifierID ),
		rec( 36, 2, ArchivedDate, LE ),
		rec( 38, 2, ArchivedTime, LE ),
		rec( 40, 4, ArchiverID ),
		rec( 44, 2, LastAccessedDate, LE ),
		rec( 46, 1, InheritedRightsMaskLow ),
		rec( 47, 1, InheritedRightsMaskHigh ),
		rec( 48, 1, InheritanceRevokeMaskLow ),
		rec( 49, 1, InheritanceRevokeMaskHigh ),
		rec( 50, 4, MaxSpace, LE ),
		rec( 54, 1, VolumeNumber ),
		rec( 55, 4, DirectoryBase, LE ),
		rec( 59, 1, HandleFlag ),
		rec( 60, 1, PathCount, var="x" ),
		rec( 61, (1,255), Path, repeat="x" ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5708, 87/08
	pkt = NCP(0x5708, "Delete a File or Subdirectory", 'file', has_length=0)
	pkt.Request((20,274), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 1, SearchAttributesLow ),
		rec( 11, 1, SearchAttributesHigh ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase, LE ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, (1,255), Path, repeat="x" ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5709, 87/09
	pkt = NCP(0x5709, "Set Short Directory Handle", 'file', has_length=0)
	pkt.Request((20,274), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, DataStream ),
		rec( 10, 1, DestDirHandle ),
		rec( 11, 1, Reserved ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase, LE ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, (1,255), Path, repeat="x" ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/570A, 87/10
	pkt = NCP(0x570A, "Add Trustee Set to File or Subdirectory", 'file', has_length=0)
	pkt.Request((24,278), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 1, SearchAttributesLow ),
		rec( 11, 1, SearchAttributesHigh ),
		rec( 12, 2, AccessRightsMask, LE ),
		rec( 14, 2, ObjectIDCount, LE ),
		rec( 16, 1, VolumeNumber ),
		rec( 17, 4, DirectoryBase, LE ),
		rec( 21, 1, HandleFlag ),
		rec( 22, 1, PathCount, var="x" ),
		rec( 23, (1,255), Path, repeat="x" ),
		#Next attribute TrusteeStruct is repeated based on ObjectIDCount
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfc01, 0xfd00, 0xff16])
	# 2222/570B, 87/11
	pkt = NCP(0x570B, "Delete Trustee Set from File or SubDirectory", 'file', has_length=0)
	pkt.Request((20,274), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, ObjectIDCount, LE ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase, LE ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, (1,255), Path, repeat="x" ),
		#Next attribute TrusteeStruct is repeated based on ObjectIDCount
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/570C, 87/12
	pkt = NCP(0x570C, "Allocate Short Directory Handle", 'file', has_length=0)
	pkt.Request((20,274), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, AllocateMode, LE ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase, LE ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, (1,255), Path, repeat="x" ),
	])
	pkt.Reply(14, [
		rec( 8, 1, DirHandle ),
		rec( 9, 1, VolumeNumber ),
		rec( 10, 4, Reserved4 ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5710, 87/16
	pkt = NCP(0x5710, "Scan Salvageable Files", 'file', has_length=0)
	pkt.Request((26,280), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, DataStream ),
		rec( 10, 1, ReturnInfoMaskLow ),
		rec( 11, 1, ReturnInfoMaskHigh ),
		rec( 12, 1, ExtendedInfoLow ),
		rec( 13, 1, ExtendedInfoHigh ),
		rec( 14, 4, SequenceNumber, LE ),
		rec( 18, 1, VolumeNumber ),
		rec( 19, 4, DirectoryBase, LE ),
		rec( 23, 1, HandleFlag ),
		rec( 24, 1, PathCount, var="x" ),
		rec( 25, (1,255), Path, repeat="x" ),
	])
	pkt.Reply((105,359), [
		rec( 8, 4, SequenceNumber, LE ),
		rec( 12, 2, DeletedTime, LE ),
		rec( 14, 2, DeletedDate, LE ),
		rec( 16, 4, DeletedID ),
		rec( 20, 4, VolumeID, LE ),
		rec( 24, 4, DirectoryBase, LE ),
		rec( 28, 4, DataStreamSpaceAlloc, LE ),
		rec( 32, 1, AttributesDefLow ),
		rec( 33, 1, AttributesDefLow2 ),
		rec( 34, 1, AttributesDefLow3 ),
		rec( 35, 1, Reserved ),
		rec( 36, 2, FlagsDef, LE ),
		rec( 38, 4, DataStreamSize, LE ),
		rec( 42, 4, TtlDSDskSpaceAlloc, LE ),
		rec( 46, 2, NumberOfDataStreams, LE ),
		rec( 48, 2, CreationTime, LE ),
		rec( 50, 2, CreationDate, LE ),
		rec( 52, 4, CreatorID ),
		rec( 56, 2, ModifiedTime, LE ),
		rec( 58, 2, ModifiedDate, LE ),
		rec( 60, 4, ModifierID ),
		rec( 64, 2, LastAccessedDate, LE ),
		rec( 66, 2, ArchivedTime, LE ),
		rec( 68, 2, ArchivedDate, LE ),
		rec( 70, 4, ArchiverID ),
		rec( 74, 1, InheritedRightsMaskLow ),
		rec( 75, 1, InheritedRightsMaskHigh ),
		rec( 76, 4, DirectoryEntryNumber, LE ),
		rec( 80, 4, DOSDirectoryEntryNumber, LE ),
		rec( 84, 4, VolumeNumberLong, LE ),
		rec( 88, 4, EADataSize, LE ),
		rec( 92, 4, EACount, LE ),
		rec( 96, 4, EAKeySize, LE ),
		rec( 100, 4, CreatorNameSpaceNumber, LE ),
		rec( 104, (1,255), FileName ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5711, 87/17
	pkt = NCP(0x5711, "Recover Salvageable File", 'file', has_length=0)
	pkt.Request((23,277), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 4, SequenceNumber, LE ),
		rec( 14, 4, VolumeID, LE ),
		rec( 18, 4, DirectoryBase, LE ),
		rec( 22, (1,255), FileName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5712, 87/18
	pkt = NCP(0x5712, "Purge Salvageable File", 'file', has_length=0)
	pkt.Request(22, [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 4, SequenceNumber, LE ),
		rec( 14, 4, VolumeID, LE ),
		rec( 18, 4, DirectoryBase, LE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5713, 87/19
	pkt = NCP(0x5713, "Get Name Space Information", 'file', has_length=0)
	pkt.Request(18, [
		rec( 8, 1, SrcNameSpace ),
		rec( 9, 1, DestNameSpace ),
		rec( 10, 1, Reserved ),
		rec( 11, 1, VolumeNumber ),
		rec( 12, 4, DirectoryBase, LE ),
		rec( 16, 1, NamesSpaceInfoMask1 ),
		rec( 17, 1, NamesSpaceInfoMask2 ),
	])
	pkt.Reply(8)
	#Information returned is based on the request flags in the NSInfoMask
	#pkt.Reply((47,59), [
	#	[ 8,(1, 13), FileName ],
	#	[ -1, 1, AttributesDefLow ],
	#	[ -1, 1, AttributesDefLow2 ],
	#	[ -1, 1, AttributesDefLow3 ],
	#	[ -1, 1, Reserved ],
	#	[ -1, 2, CreationDate ],
	#	[ -1, 2, CreationTime ],
	#	[ -1, 4, CreatorID ],
	#	[ -1, 2, ArchivedDate ],
	#	[ -1, 2, ArchivedTime ],
	#	[ -1, 4, ArchiverID ],
	#	[ -1, 2, ModifiedDate ],
	#	[ -1, 2, ModifiedTime ],
	#	[ -1, 4, ModifierID ],
	#	[ -1, 2, LastAccessedDate ],
	#	[ -1, 1, InheritedRightsMaskLow ],
	#	[ -1, 1, InheritedRightsMaskHigh ],
	#	[ -1, 2, Reserved2 ],
	#	[ -1, 4, MaxSpace ],
	#])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5714, 87/20
	pkt = NCP(0x5714, "Search for File or Subdirectory Set", 'file', has_length=0)
	pkt.Request((28, 282), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, DataStream ),
		rec( 10, 1, SearchAttributesLow ),
		rec( 11, 1, SearchAttributesHigh ),
		rec( 12, 1, ReturnInfoMaskLow ),
		rec( 13, 1, ReturnInfoMaskHigh ),
		rec( 14, 1, ExtendedInfoLow ),
		rec( 15, 1, ExtendedInfoHigh ),
		rec( 16, 2, ReturnInfoCount, LE ),
		rec( 18, 9, SearchSequence ),
		rec( 27, (1,255), SearchPattern ),
	])
	pkt.Reply((97,351), [
		rec( 8, 9, SearchSequence ),
		rec( 17, 1, MoreFlag ),
		rec( 18, 2, InfoCount, LE ),
		#The following info is repeated based on InfoCount
		rec( 20, 4, DataStreamSpaceAlloc, LE ),
		rec( 24, 1, AttributesDefLow ),
		rec( 25, 1, AttributesDefLow2 ),
		rec( 26, 1, AttributesDefLow3 ),
		rec( 27, 1, Reserved ),
		rec( 28, 2, FlagsDef, LE ),
		rec( 30, 4, DataStreamSize, LE ),
		rec( 34, 4, TtlDSDskSpaceAlloc, LE ),
		rec( 38, 2, NumberOfDataStreams, LE ),
		rec( 40, 2, CreationTime, LE ),
		rec( 42, 2, CreationDate, LE ),
		rec( 44, 4, CreatorID ),
		rec( 48, 2, ModifiedTime, LE ),
		rec( 50, 2, ModifiedDate, LE ),
		rec( 52, 4, ModifierID ),
		rec( 56, 2, LastAccessedDate, LE ),
		rec( 58, 2, ArchivedTime, LE ),
		rec( 60, 2, ArchivedDate, LE ),
		rec( 62, 4, ArchiverID ),
		rec( 66, 1, InheritedRightsMaskLow ),
		rec( 67, 1, InheritedRightsMaskHigh ),
		rec( 68, 4, DirectoryEntryNumber, LE ),
		rec( 72, 4, DOSDirectoryEntryNumber, LE ),
		rec( 76, 4, VolumeNumberLong, LE ),
		rec( 80, 4, EADataSize, LE ),
		rec( 84, 4, EACount, LE ),
		rec( 88, 4, EAKeySize, LE ),
		rec( 92, 4, CreatorNameSpaceNumber, LE ),
		rec( 96, (1,255), FileName ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
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
		rec( 10, 2, dstNSIndicator, LE ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase, LE ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, (1,255), Path, repeat="x" ),
	])
	pkt.Reply(17, [
		rec( 8, 4, DirectoryBase, LE ),
		rec( 12, 4, DOSDirectoryBase, LE ),
		rec( 16, 1, VolumeNumber ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5717, 87/23
	pkt = NCP(0x5717, "Query Name Space Information Format", 'file', has_length=0)
	pkt.Request(10, [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, VolumeNumber ),
	])
	pkt.Reply(58, [
		rec( 8, 4, FixedBitMask, LE ),
		rec( 12, 4, VariableBitMask, LE ),
		rec( 16, 4, HugeBitMask, LE ),
		rec( 20, 2, FixedBitsDefined, LE ),
		rec( 22, 2, VariableBitsDefined, LE ),
		rec( 24, 2, HugeBitsDefined, LE ),
		rec( 26, 32, FieldsLenTable, LE ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5718, 87/24
	pkt = NCP(0x5718, "Get Name Spaces Loaded List from Volume Number", 'file', has_length=0)
	pkt.Request(10, [
		rec( 8, 1, Reserved ),
		rec( 9, 1, VolumeNumber ),
	])
	pkt.Reply(11, [
		rec( 8, 2, NumberOfNSLoaded, LE ),
		#Number of values depends on NumberOfNSLoaded value
		rec( 10, 1, NameSpace ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5719, 87/25
	pkt = NCP(0x5719, "Set Name Space Information", 'file', has_length=0)
	pkt.Request(531, [
		rec( 8, 1, SrcNameSpace ),
		rec( 9, 1, DestNameSpace ),
		rec( 10, 1, VolumeNumber ),
		rec( 11, 4, DirectoryBase, LE ),
		rec( 15, 1, NamesSpaceInfoMask1 ),
		rec( 16, 1, NamesSpaceInfoMask2 ),
		rec( 17, 2, Reserved2 ),
		rec( 19, 512, NSSpecificInfo ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8b00, 0x8d00, 0x8f00, 0x9001,
			     0x9600, 0x9804, 0x9b03, 0x9c03, 0xfd00,
			     0xff16])
	# 2222/571A, 87/26
	pkt = NCP(0x571A, "Get Huge Name Space Information", 'file', has_length=0)
	pkt.Request(34, [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, VolumeNumber ),
		rec( 10, 4, DirectoryBase, LE ),
		rec( 14, 4, HugeBitMask, LE ),
		rec( 18, 16, HugeStateInfo ),
	])
	pkt.Reply((25,279), [
		rec( 8, 16, NextHugeStateInfo ),
		rec( 24, (1,255), HugeData ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8b00, 0x8d00, 0x8f00, 0x9001,
			     0x9600, 0x9804, 0x9b03, 0x9c03, 0xfd00,
			     0xff16])
	# 2222/571B, 87/27
	pkt = NCP(0x571B, "Set Huge Name Space Information", 'file', has_length=0)
	pkt.Request((35,289), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, VolumeNumber ),
		rec( 10, 4, DirectoryBase, LE ),
		rec( 14, 4, HugeBitMask, LE ),
		rec( 18, 16, HugeStateInfo ),
		rec( 34, (1,255), HugeData ),
	])
	pkt.Reply(28, [
		rec( 8, 16, NextHugeStateInfo ),
		rec( 24, 4, HugeDataUsed, LE ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8b00, 0x8d00, 0x8f00, 0x9001,
			     0x9600, 0x9804, 0x9b03, 0x9c03, 0xfd00,
			     0xff16])
	# 2222/571C, 87/28
	pkt = NCP(0x571C, "Get Full Path String", 'file', has_length=0)
	pkt.Request((28,282), [
		rec( 8, 1, SrcNameSpace ),
		rec( 9, 1, DestNameSpace ),
		rec( 10, 2, PathCookieFlags, LE ),
		rec( 12, 4, Cookie1, LE ),
		rec( 16, 4, Cookie2, LE ),
		rec( 20, 1, VolumeNumber ),
		rec( 21, 4, DirectoryBase, LE ),
		rec( 25, 1, HandleFlag ),
		rec( 26, 1, PathCount, var="x" ),
		rec( 27, (1,255), Path, repeat="x" ),
	])
	pkt.Reply((23,277), [
		rec( 8, 2, PathCookieFlags, LE ),
		rec( 10, 4, Cookie1, LE ),
		rec( 14, 4, Cookie2, LE ),
		rec( 18, 2, PathComponentSize, LE ),
		rec( 20, 2, PathComponentCount, LE ),
		rec( 22, (1,255), Path ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8b00, 0x8d00, 0x8f00, 0x9001,
			     0x9600, 0x9804, 0x9b03, 0x9c03, 0xfd00,
			     0xff16])
	# 2222/571D, 87/29
	pkt = NCP(0x571D, "Get Effective Directory Rights", 'file', has_length=0)
	pkt.Request((24, 278), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, DestNameSpace ),
		rec( 10, 1, SearchAttributesLow ),
		rec( 11, 1, SearchAttributesHigh ),
		rec( 12, 1, ReturnInfoMaskLow ),
		rec( 13, 1, ReturnInfoMaskHigh ),
		rec( 14, 1, ExtendedInfoLow ),
		rec( 15, 1, ExtendedInfoHigh ),
		rec( 16, 1, VolumeNumber ),
		rec( 17, 4, DirectoryBase, LE ),
		rec( 21, 1, HandleFlag ),
		rec( 22, 1, PathCount, var="x" ),
		rec( 23, (1,255), Path, repeat="x" ),
	])
	pkt.Reply((87,341), [
		rec( 8, 2, EffectiveRights, LE ),
		rec( 10, 4, DataStreamSpaceAlloc, LE ),
		rec( 14, 1, AttributesDefLow ),
		rec( 15, 1, AttributesDefLow2 ),
		rec( 16, 1, AttributesDefLow3 ),
		rec( 17, 1, Reserved ),
		rec( 18, 2, FlagsDef, LE ),
		rec( 20, 4, DataStreamSize, LE ),
		rec( 24, 4, TtlDSDskSpaceAlloc, LE ),
		rec( 28, 2, NumberOfDataStreams, LE ),
		rec( 30, 2, CreationTime, LE ),
		rec( 32, 2, CreationDate, LE ),
		rec( 34, 4, CreatorID ),
		rec( 38, 2, ModifiedTime, LE ),
		rec( 40, 2, ModifiedDate, LE ),
		rec( 42, 4, ModifierID ),
		rec( 46, 2, LastAccessedDate, LE ),
		rec( 48, 2, ArchivedTime, LE ),
		rec( 50, 2, ArchivedDate, LE ),
		rec( 52, 4, ArchiverID ),
		rec( 56, 1, InheritedRightsMaskLow ),
		rec( 57, 1, InheritedRightsMaskHigh ),
		rec( 58, 4, DirectoryEntryNumber, LE ),
		rec( 62, 4, DOSDirectoryEntryNumber, LE ),
		rec( 66, 4, VolumeNumberLong, LE ),
		rec( 70, 4, EADataSize, LE ),
		rec( 74, 4, EACount, LE ),
		rec( 78, 4, EAKeySize, LE ),
		rec( 82, 4, CreatorNameSpaceNumber, LE ),
		rec( 86, (1,255), FileName ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/571E, 87/30
	pkt = NCP(0x571E, "Open/Create File or Subdirectory", 'file', has_length=0)
	pkt.Request((34, 288), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, DataStream ),
		rec( 10, 1, OpenCreateMode ),
		rec( 11, 1, Reserved ),
		rec( 12, 1, SearchAttributesLow ),
		rec( 13, 1, SearchAttributesHigh ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 1, ReturnInfoMaskLow ),
		rec( 17, 1, ReturnInfoMaskHigh ),
		rec( 18, 1, ExtendedInfoLow ),
		rec( 19, 1, ExtendedInfoHigh ),
		rec( 20, 1, AttributesDefLow ),
		rec( 21, 1, AttributesDefLow2 ),
		rec( 22, 1, AttributesDefLow3 ),
		rec( 23, 1, Reserved ),
		rec( 24, 1, DesiredAccessRightsLow ),
		rec( 25, 1, DesiredAccessRightsHigh ),
		rec( 26, 1, VolumeNumber ),
		rec( 27, 4, DirectoryBase, LE ),
		rec( 31, 1, HandleFlag ),
		rec( 32, 1, PathCount, var="x" ),
		rec( 33, (1,255), Path, repeat="x" ),
	])
	pkt.Reply((91,345), [
		rec( 8, 4, FileHandle ),
		rec( 12, 1, OpenCreateAction ),
		rec( 13, 1, Reserved ),
		rec( 14, 4, DataStreamSpaceAlloc, LE ),
		rec( 18, 1, AttributesDefLow ),
		rec( 19, 1, AttributesDefLow2 ),
		rec( 20, 1, AttributesDefLow3 ),
		rec( 21, 1, Reserved ),
		rec( 22, 2, FlagsDef, LE ),
		rec( 24, 4, DataStreamSize, LE ),
		rec( 28, 4, TtlDSDskSpaceAlloc, LE ),
		rec( 32, 2, NumberOfDataStreams, LE ),
		rec( 34, 2, CreationTime, LE ),
		rec( 36, 2, CreationDate, LE ),
		rec( 38, 4, CreatorID ),
		rec( 42, 2, ModifiedTime, LE ),
		rec( 44, 2, ModifiedDate, LE ),
		rec( 46, 4, ModifierID ),
		rec( 50, 2, LastAccessedDate, LE ),
		rec( 52, 2, ArchivedTime, LE ),
		rec( 54, 2, ArchivedDate, LE ),
		rec( 56, 4, ArchiverID ),
		rec( 60, 1, InheritedRightsMaskLow ),
		rec( 61, 1, InheritedRightsMaskHigh ),
		rec( 62, 4, DirectoryEntryNumber, LE ),
		rec( 66, 4, DOSDirectoryEntryNumber, LE ),
		rec( 70, 4, VolumeNumberLong, LE ),
		rec( 74, 4, EADataSize, LE ),
		rec( 78, 4, EACount, LE ),
		rec( 82, 4, EAKeySize, LE ),
		rec( 86, 4, CreatorNameSpaceNumber, LE ),
		rec( 90, (1,255), FileName ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/571F, 87/31
	pkt = NCP(0x571F, "Get File Information", 'file', has_length=0)
	pkt.Request(16, [
		rec( 8, 6, FileHandle  ),
		rec( 14, 1, HandleInfoLevel ),
		rec( 15, 1, NameSpace ),
	])
	pkt.Reply(16, [
		rec( 8, 4, VolumeNumberLong, LE ),
		rec( 12, 4, DirectoryBase, LE ),
		#The rest of the attributes vary depending on the HandleInfoLevel Passed in the request
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5720, 87/32
	pkt = NCP(0x5720, "Open/Create File or Subdirectory with Callback", 'file', has_length=0)
	pkt.Request((30, 284), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, OpenCreateMode ),
		rec( 10, 1, SearchAttributesLow ),
		rec( 11, 1, SearchAttributesHigh ),
		rec( 12, 1, ReturnInfoMaskLow ),
		rec( 13, 1, ReturnInfoMaskHigh ),
		rec( 14, 1, ExtendedInfoLow ),
		rec( 15, 1, ExtendedInfoHigh ),
		rec( 16, 1, AttributesDefLow ),
		rec( 17, 1, AttributesDefLow2 ),
		rec( 18, 1, AttributesDefLow3 ),
		rec( 19, 1, Reserved ),
		rec( 20, 1, DesiredAccessRightsLow ),
		rec( 21, 1, DesiredAccessRightsHigh ),
		rec( 22, 1, VolumeNumber ),
		rec( 23, 4, DirectoryBase, LE ),
		rec( 27, 1, HandleFlag ),
		rec( 28, 1, PathCount, var="x" ),
		rec( 29, (1,255), Path, repeat="x" ),
	])
	pkt.Reply( 14, [
		# Reply structure depends on request flags in request packet.
		#(91,345), [
		rec( 8, 4, FileHandle ),
		rec( 12, 1, OpenCreateAction ),
		rec( 13, 1, OCRetFlags ),
		#rec( 14, 4, DataStreamSpaceAlloc, LE ),
		#rec( 18, 1, AttributesDefLow ),
		#rec( 19, 1, AttributesDefLow2 ),
		#rec( 20, 1, AttributesDefLow3 ),
		#rec( 21, 1, Reserved ),
		#rec( 22, 2, FlagsDef, LE ),
		#rec( 24, 4, DataStreamSize, LE ),
		#rec( 28, 4, TtlDSDskSpaceAlloc, LE ),
		#rec( 32, 2, NumberOfDataStreams, LE ),
		#rec( 34, 2, CreationTime, LE ),
		#rec( 36, 2, CreationDate, LE ),
		#rec( 38, 4, CreatorID ),
		#rec( 42, 2, ModifiedTime, LE ),
		#rec( 44, 2, ModifiedDate, LE ),
		#rec( 46, 4, ModifierID ),
		#rec( 50, 2, LastAccessedDate, LE ),
		#rec( 52, 2, ArchivedTime, LE ),
		#rec( 54, 2, ArchivedDate, LE ),
		#rec( 56, 4, ArchiverID ),
		#rec( 60, 1, InheritedRightsMaskLow ),
		#rec( 61, 1, InheritedRightsMaskHigh ),
		#rec( 62, 4, DirectoryEntryNumber, LE ),
		#rec( 66, 4, DOSDirectoryEntryNumber, LE ),
		#rec( 70, 4, VolumeNumberLong, LE ),
		#rec( 74, 4, EADataSize, LE ),
		#rec( 78, 4, EACount, LE ),
		#rec( 82, 4, EAKeySize, LE ),
		#rec( 86, 4, CreatorNameSpaceNumber, LE ),
		#rec( 90, (1,255), FileName ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5721, 87/33
	pkt = NCP(0x5721, "Open/Create File or Subdirectory II with Callback", 'file', has_length=0)
	pkt.Request((34, 288), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, DataStream ),
		rec( 10, 1, OpenCreateMode ),
		rec( 11, 1, Reserved ),
		rec( 12, 1, SearchAttributesLow ),
		rec( 13, 1, SearchAttributesHigh ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 1, ReturnInfoMaskLow ),
		rec( 17, 1, ReturnInfoMaskHigh ),
		rec( 18, 1, ExtendedInfoLow ),
		rec( 19, 1, ExtendedInfoHigh ),
		rec( 20, 1, AttributesDefLow ),
		rec( 21, 1, AttributesDefLow2 ),
		rec( 22, 1, AttributesDefLow3 ),
		rec( 23, 1, Reserved ),
		rec( 24, 1, DesiredAccessRightsLow ),
		rec( 25, 1, DesiredAccessRightsHigh ),
		rec( 26, 1, VolumeNumber ),
		rec( 27, 4, DirectoryBase, LE ),
		rec( 31, 1, HandleFlag ),
		rec( 32, 1, PathCount, var="x" ),
		rec( 33, (1,255), Path, repeat="x" ),
	])
	pkt.Reply((91,345), [
		rec( 8, 4, FileHandle ),
		rec( 12, 1, OpenCreateAction ),
		rec( 13, 1, OCRetFlags ),
		rec( 14, 4, DataStreamSpaceAlloc, LE ),
		rec( 18, 1, AttributesDefLow ),
		rec( 19, 1, AttributesDefLow2 ),
		rec( 20, 1, AttributesDefLow3 ),
		rec( 21, 1, Reserved ),
		rec( 22, 2, FlagsDef, LE ),
		rec( 24, 4, DataStreamSize, LE ),
		rec( 28, 4, TtlDSDskSpaceAlloc, LE ),
		rec( 32, 2, NumberOfDataStreams, LE ),
		rec( 34, 2, CreationTime, LE ),
		rec( 36, 2, CreationDate, LE ),
		rec( 38, 4, CreatorID ),
		rec( 42, 2, ModifiedTime, LE ),
		rec( 44, 2, ModifiedDate, LE ),
		rec( 46, 4, ModifierID ),
		rec( 50, 2, LastAccessedDate, LE ),
		rec( 52, 2, ArchivedTime, LE ),
		rec( 54, 2, ArchivedDate, LE ),
		rec( 56, 4, ArchiverID ),
		rec( 60, 1, InheritedRightsMaskLow ),
		rec( 61, 1, InheritedRightsMaskHigh ),
		rec( 62, 4, DirectoryEntryNumber, LE ),
		rec( 66, 4, DOSDirectoryEntryNumber, LE ),
		rec( 70, 4, VolumeNumberLong, LE ),
		rec( 74, 4, EADataSize, LE ),
		rec( 78, 4, EACount, LE ),
		rec( 82, 4, EAKeySize, LE ),
		rec( 86, 4, CreatorNameSpaceNumber, LE ),
		rec( 90, (1,255), FileName ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5722, 87/34
	pkt = NCP(0x5722, "Open CallBack Control (Op-Lock)", 'file', has_length=0)
	pkt.Request(13, [
		rec( 10, 4, CCFileHandle ),
		rec( 14, 1, CCFunction ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8800])
	# 2222/5723, 87/35
	pkt = NCP(0x5723, "Modify DOS Attributes on a File or Subdirectory", 'file', has_length=0)
	pkt.Request((29, 283), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 2, FlagsDef, LE ),
		rec( 11, 1, SearchAttributesLow ),
		rec( 12, 1, SearchAttributesHigh ),
		rec( 13, 1, ReturnInfoMaskLow ),
		rec( 14, 1, ReturnInfoMaskHigh ),
		rec( 15, 1, ExtendedInfoLow ),
		rec( 16, 1, ExtendedInfoHigh ),
		rec( 17, 1, AttributesDefLow ),
		rec( 18, 1, AttributesDefLow2 ),
		rec( 19, 1, AttributesDefLow3 ),
		rec( 20, 1, Reserved ),
		rec( 21, 1, VolumeNumber ),
		rec( 22, 4, DirectoryBase, LE ),
		rec( 26, 1, HandleFlag ),
		rec( 27, 1, PathCount, var="x" ),
		rec( 28, (1,255), Path, repeat="x" ),
	])
	pkt.Reply(24, [
		rec( 8, 4, ItemsChecked, LE ),
		rec( 12, 4, ItemsChanged, LE ),
		rec( 16, 4, AttributeValidFlag, LE ),
		rec( 20, 1, AttributesDefLow ),
		rec( 21, 1, AttributesDefLow2 ),
		rec( 22, 1, AttributesDefLow3 ),
		rec( 23, 1, Reserved ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5724, 87/36
	pkt = NCP(0x5724, "Log File", 'file', has_length=0)
	pkt.Request((28, 282), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, Reserved2 ),
		rec( 12, 1, LogFileFlagLow ),
		rec( 13, 1, LogFileFlagHigh ),
		rec( 14, 2, Reserved2 ),
		rec( 16, 4, WaitTime, LE ),
		rec( 20, 1, VolumeNumber ),
		rec( 21, 4, DirectoryBase, LE ),
		rec( 25, 1, HandleFlag ),
		rec( 26, 1, PathCount, var="x" ),
		rec( 27, (1,255), Path, repeat="x" ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5725, 87/37
	pkt = NCP(0x5725, "Release File", 'file', has_length=0)
	pkt.Request((20, 274), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, Reserved2 ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase, LE ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, (1,255), Path, repeat="x" ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5726, 87/38
	pkt = NCP(0x5726, "Clear File", 'file', has_length=0)
	pkt.Request((20, 274), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, Reserved2 ),
		rec( 12, 1, VolumeNumber ),
		rec( 13, 4, DirectoryBase, LE ),
		rec( 17, 1, HandleFlag ),
		rec( 18, 1, PathCount, var="x" ),
		rec( 19, (1,255), Path, repeat="x" ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5727, 87/39
	pkt = NCP(0x5727, "Get Directory Disk Space Restriction", 'file', has_length=0)
	pkt.Request((19, 273), [
		rec( 8, 1, NameSpace  ),
		rec( 9, 2, Reserved2 ),
		rec( 11, 1, VolumeNumber ),
		rec( 12, 4, DirectoryBase, LE ),
		rec( 16, 1, HandleFlag ),
		rec( 17, 1, PathCount, var="x" ),
		rec( 18, (1,255), Path, repeat="x" ),
	])
	pkt.Reply(18, [
		rec( 8, 1, NumberOfEntries ),
		#Repeated for value of NumberOfEntries
		rec( 9, 1, Level ),
		rec( 10, 4, MaxSpace, LE ),
		rec( 14, 4, CurrentSpace, LE ),
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
		rec( 10, 1, SearchAttributesLow ),
		rec( 11, 1, SearchAttributesHigh ),
		rec( 12, 1, ReturnInfoMaskLow ),
		rec( 13, 1, ReturnInfoMaskHigh ),
		rec( 14, 1, ExtendedInfoLow ),
		rec( 15, 1, ExtendedInfoHigh ),
		rec( 16, 2, ReturnInfoCount, LE ),
		rec( 18, 9, SearchSequence ),
		rec( 27, (1,255), SearchPattern ),
	])
	pkt.Reply((97,351), [
		rec( 8, 9, SearchSequence ),
		rec( 17, 1, MoreFlag ),
		rec( 18, 2, InfoCount, LE ),
		#The following info is repeated based on InfoCount
		rec( 20, 4, DataStreamSpaceAlloc, LE ),
		rec( 24, 1, AttributesDefLow ),
		rec( 25, 1, AttributesDefLow2 ),
		rec( 26, 1, AttributesDefLow3 ),
		rec( 27, 1, Reserved ),
		rec( 28, 2, FlagsDef, LE ),
		rec( 30, 4, DataStreamSize, LE ),
		rec( 34, 4, TtlDSDskSpaceAlloc, LE ),
		rec( 38, 2, NumberOfDataStreams, LE ),
		rec( 40, 2, CreationTime, LE ),
		rec( 42, 2, CreationDate, LE ),
		rec( 44, 4, CreatorID ),
		rec( 48, 2, ModifiedTime, LE ),
		rec( 50, 2, ModifiedDate, LE ),
		rec( 52, 4, ModifierID ),
		rec( 56, 2, LastAccessedDate, LE ),
		rec( 58, 2, ArchivedTime, LE ),
		rec( 60, 2, ArchivedDate, LE ),
		rec( 62, 4, ArchiverID ),
		rec( 66, 1, InheritedRightsMaskLow ),
		rec( 67, 1, InheritedRightsMaskHigh ),
		rec( 68, 4, DirectoryEntryNumber, LE ),
		rec( 72, 4, DOSDirectoryEntryNumber, LE ),
		rec( 76, 4, VolumeNumberLong, LE ),
		rec( 80, 4, EADataSize, LE ),
		rec( 84, 4, EACount, LE ),
		rec( 88, 4, EAKeySize, LE ),
		rec( 92, 4, CreatorNameSpaceNumber, LE ),
		rec( 96, (1,255), FileName ),
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5729, 87/41
	pkt = NCP(0x5729, "Scan Salvageable Files", 'file', has_length=0)
	pkt.Request((24,278), [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, CtrlFlags, LE ),
		rec( 12, 4, SequenceNumber, LE ),
		rec( 16, 1, VolumeNumber ),
		rec( 17, 4, DirectoryBase, LE ),
		rec( 21, 1, HandleFlag ),
		rec( 22, 1, PathCount, var="x" ),
		rec( 23, (1,255), Path, repeat="x" ),
	])
	pkt.Reply(20, [
		rec( 8, 4, SequenceNumber, LE ),
		rec( 12, 4, DirectoryBase, LE ),
		rec( 16, 4, ScanItems, LE ),
		#If number of ScanItems > 0 then next attribute
		#[ 20, 4, SalvageableFileEntryNumber, LE ],
		#We could also have a filename here if CtrlFlags requested name
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/572A, 87/42
	pkt = NCP(0x572A, "Purge Salvageable File List", 'file', has_length=0)
	pkt.Request(24, [
		rec( 8, 1, NameSpace ),
		rec( 9, 1, Reserved ),
		rec( 10, 2, PurgeFlags, LE ),
		rec( 12, 4, VolumeNumberLong ),
		rec( 16, 4, DirectoryBase, LE ),
		rec( 20, 4, PurgeCount, LE ),
		#Next attribute PurgeList is based on PurgeCount value
	])
	pkt.Reply(12, [
		rec( 8, 4, PurgeCount, LE ),
		#Next attribute PurgeCcode is based on PurgeCount value
	])
	pkt.CompletionCodes([0x0000, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
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
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/572C, 87/44
	pkt = NCP(0x572C, "Update File Handle Rights", 'file', has_length=0)
	pkt.Request(24, [
		rec( 8, 2, Reserved2 ),
		rec( 10, 1, VolumeNumber ),
		rec( 11, 1, NameSpace ),
		rec( 12, 4, DirectoryNumber, LE ),
		rec( 16, 1, AccessRightsMask ),
		rec( 17, 1, AccessRightsHigh ),
		rec( 18, 1, NewAccessRights ),
		rec( 19, 1, NewAccessRightsHigh ),
		rec( 20, 4, FileHandle ),
	])
	pkt.Reply(16, [
		rec( 8, 4, FileHandle ),
		rec( 12, 4, EffectiveRights, LE ),
	])
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5801, 8801
	pkt = NCP(0x5801, "Query Volume Audit Status", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5802, 8802
	pkt = NCP(0x5802, "Add User Audit Property", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5803, 8803
	pkt = NCP(0x5803, "Add Auditor Access", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5804, 8804
	pkt = NCP(0x5804, "Change Auditor Volume Password", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5805, 8805
	pkt = NCP(0x5805, "Check Auditor Access", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5806, 8806
	pkt = NCP(0x5806, "Delete User Audit Property", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5807, 8807
	pkt = NCP(0x5807, "Disable Auditing On A Volume", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5808, 8808
	pkt = NCP(0x5808, "Enable Auditing On A Volume", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5809, 8809
	pkt = NCP(0x5809, "Query User Being Audited", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/580A, 88,10
	pkt = NCP(0x580A, "Read Audit Bit Map", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/580B, 88,11
	pkt = NCP(0x580B, "Read Audit File Configuration Header", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/580D, 88,13
	pkt = NCP(0x580D, "Remove Auditor Access", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/580E, 88,14
	pkt = NCP(0x580E, "Reset Audit File", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5810, 88,16
	pkt = NCP(0x5810, "Write Audit Bit Map", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5811, 88,17
	pkt = NCP(0x5811, "Write Audit File Configuration Header", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5812, 88,18
	pkt = NCP(0x5812, "Change Auditor Volume Password2", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5813, 88,19
	pkt = NCP(0x5813, "Return Audit Flags", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5814, 88,20
	pkt = NCP(0x5814, "Close Old Audit File", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5816, 88,22
	pkt = NCP(0x5816, "Check Level Two Access", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5817, 88,23
	pkt = NCP(0x5817, "Return Old Audit File List", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5818, 88,24
	pkt = NCP(0x5818, "Init Audit File Reads", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5819, 88,25
	pkt = NCP(0x5819, "Read Auditing File", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/581A, 88,26
	pkt = NCP(0x581A, "Delete Old Audit File", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/581E, 88,30
	pkt = NCP(0x581E, "Restart Volume auditing", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/581F, 88,31
	pkt = NCP(0x581F, "Set Volume Password", "auditing", has_length=0)
	pkt.Request(8)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7300, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5A01, 90/00
	pkt = NCP(0x5A01, "Parse Tree", 'file')
	pkt.Request(26, [
		rec( 10, 1, InfoMaskLow1 ),
		rec( 11, 1, InfoMaskLow2 ),
		rec( 12, 1, InfoMaskLow3 ),
		rec( 13, 1, InfoMaskHigh ),
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
		rec( 28, 4, DirectoryBase, LE ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xfd00, 0xff16])
	# 2222/5A0A, 90/10
	pkt = NCP(0x5A0A, "Get Reference Count from Dir Entry Number", 'file')
	pkt.Request(19, [
		rec( 10, 4, VolumeNumberLong ),
		rec( 14, 4, DirectoryBase, LE ),
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
	pkt = NCP(0x5A80, "Move File Data To DM", 'file')
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
	pkt = NCP(0x5A81, "DM File Information", 'file')
	pkt.Request(19, [
		rec( 10, 4, VolumeNumberLong ),
		rec( 14, 4, DirectoryEntryNumber ),
		rec( 18, 1, NameSpace ),
	])
	pkt.Reply(24, [
		rec( 8, 4, SupportModuleID ),
		rec( 12, 4, RestoreTime ),
		rec( 16, 4, DMInfoEntries ),
		#Repeated based on DMInfoEntries
		rec( 20, 4, DataSize ),
	])
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5A82, 90/130
	pkt = NCP(0x5A82, "Volume DM Status", 'file')
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
	pkt = NCP(0x5A84, "DM Support Module Information", 'file')
	pkt.Request(18, [
		rec( 10, 4, DMInfoLevel ),
		rec( 14, 4, SupportModuleID ),
	])
	#Different Return values based on DMInfoLevel Need ifcase
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/5A85, 90/133
	pkt = NCP(0x5A85, "Move File Data From DM", 'file')
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
	pkt = NCP(0x5A87, "DM Support Module Capacity Request", 'file')
	pkt.Request(22, [
		rec( 10, 4, SupportModuleID ),
		rec( 14, 4, VolumeNumberLong ),
		rec( 18, 4, DirectoryBase, LE ),
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
	# 2222/5C, 92
	pkt = NCP(0x5C, "SecretStore Services", 'file')
	#Need info on this packet structure and SecretStore Verbs
	pkt.Request(7)
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7e01, 0x8000, 0x8101, 0x8401, 0x8501,
			     0x8701, 0x8800, 0x8d00, 0x8f00, 0x9001, 0x9600,
			     0x9804, 0x9b03, 0x9c03, 0xa800, 0xfd00, 0xff16])
	# 2222/61, 97
	pkt = NCP(0x61, "Get Big Packet NCP Max Packet Size", 'comm')
	pkt.Request(10, [
		rec( 7, 2, ProposedMaxSize ),
		rec( 9, 1, SecurityFlag ),
	])
	pkt.Reply(13, [
		rec( 8, 2, AcceptedMaxSize ),
		rec( 10, 2, EchoSocket ),
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
		rec( 7, 4, LocalConnectionID ),
		rec( 11, 4, LocalMaxPacketSize ),
		rec( 15, 2, LocalTargetSocket ),
		rec( 17, 4, LocalMaxSendSize ),
		rec( 21, 4, LocalMaxRecvSize ),
	])
	pkt.Reply(16, [
		rec( 8, 4, RemoteTargetID ),
		rec( 12, 4, RemoteMaxPacketSize ),
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
	pkt.Reply( 64, [
		rec( 8, 2, PingVersion, LE ),
		rec( 10, 2, Reserved ),
		rec( 12, 4, TreeLength, LE ),
		rec( 16, 48, TreeName ),
	])
	pkt.CompletionCodes([0x0000, 0x8100, 0xfb04, 0xfe0c])
	# 2222/6802, 104/02
	pkt = NCP(0x6802, "Send NDS Fragmented Request/Reply", "nds", has_length=0)
	pkt.Request(28, [
		rec( 8, 4, FraggerHandle, LE ),
		rec( 12, 4, FragSize, LE ),
		rec( 16, 4, TotalRequest, LE ),
		rec( 20, 4, NDSFlags, LE ),
		#This is NDSversion 254 definition Orginal version
		#this offset of 26 s/b the NDS verb. Need some type of If
		#condition to validate version flag or verb.
		rec( 24, 4, NDSVerb, LE ),
		#[ 26, 4, NDSVersion, LE ],
		#[ 30, 4, NDSCRC, LE ],
		#The NDS verb defines what attributes are requested and returned
		#Need some method of evaluating the verb to format proper request
		#and reply structure.
		#[ 34, 4, NDSVerb, LE ],
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000])
	# 2222/6803, 104/03
	pkt = NCP(0x6803, "Fragment Close", "nds", has_length=0)
	pkt.Request(12, [
		rec( 8, 4, FraggerHandle, LE ),
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
		rec( 8, 1, NDSRequestFlagsLow ),
		rec( 9, 1, NDSRequestFlagsHigh ),
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
	pkt.Request(8)
	pkt.Reply(8)
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
	pkt = NCP(0x69, "Log File (old)", 'file')
	pkt.Request( (12, 267), [
		rec( 7, 1, DirHandle ),
		rec( 8, 1, LockFlag ),
		rec( 9, 2, TimeoutLimit, LE ),
		rec( 11, (1, 256), FilePath ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7f00, 0x8200, 0x9600, 0xfe0d, 0xff01])
	# 2222/6A, 106
	pkt = NCP(0x6A, "Lock File Set", 'file')
	pkt.Request( 9, [
		rec( 7, 2, TimeoutLimit, LE ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7f00, 0x8200, 0x9600, 0xfe0d, 0xff01])
	# 2222/6B, 107
	pkt = NCP(0x6B, "Log Logical Record", 'file')
	pkt.Request( (11, 266), [
		rec( 7, 1, LockFlag ),
		rec( 8, 2, TimeoutLimit, LE ),
		rec( 10, (1, 256), SynchName ),
	])
	pkt.Reply(8)
	pkt.CompletionCodes([0x0000, 0x7f00, 0x9600, 0xfe0d, 0xff01])
	# 2222/6C, 108
	pkt = NCP(0x6C, "Log Logical Record", 'file')
	pkt.Request( 10, [
		rec( 7, 1, LockFlag ),
		rec( 8, 2, TimeoutLimit, LE ),
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
	])
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
	pkt.Reply(8)
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
	])
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
	# 2222/7B02, 123/02
	# 2222/7B03, 123/03
	#55 2222/7B04, 123/04
	# 2222/7B05, 123/05
	# 2222/7B06, 123/06
	# 2222/7B07, 123/07
	# 2222/7B08, 123/08
	#50 2222/7B09, 123/09
	# 2222/7B0A, 123/10
	# 2222/7B0B, 123/11
	# 2222/7B0C, 123/12
	# 2222/7B0D, 123/13
	#45 2222/7B0E, 123/14
	# 2222/7B0F, 123/15
	# 2222/7B10, 123/16
	# 2222/7B11, 123/17
	# 2222/7B14, 123/20
	#40 2222/7B15, 123/21
	# 2222/7B16, 123/22
	# 2222/7B17, 123/23
	# 2222/7B18, 123/24
	# 2222/7B19, 123/25
	#35 2222/7B1A, 123/26
	# 2222/7B1B, 123/27
	# 2222/7B1E, 123/30
	# 2222/7B1F, 123/31
	# 2222/7B20, 123/32
	#30 2222/7B21, 123/33
	# 2222/7B22, 123/34
	# 2222/7B28, 123/40
	# 2222/7B29, 123/41
	# 2222/7B2A, 123/42
	#25 2222/7B2B, 123/43
	# 2222/7B2C, 123/44
	# 2222/7B2D, 123/45
	# 2222/7B2E, 123/46
	# 2222/7B2F, 123/47
	#20 2222/7B32, 123/50
	#19 2222/7B33, 123/51
	#18 2222/7B34, 123/52
	#17 2222/7B35, 123/53
	#16 2222/7B36, 123/54
	#15 2222/7B37, 123/55
	#14 2222/7B38, 123/56
	#13 2222/7B3C, 123/60
	#12 2222/7B3D, 123/61
	#11 2222/7B3E, 123/62
	#10 2222/7B46, 123/70
	#9 2222/7B47, 123/71
	#8 2222/7B48, 123/72
	#7 2222/8301, 131/01
	#6 2222/8302, 131/02
	#5 2222/8303, 131/03
	#4 2222/8304, 131/04
	#3 2222/8305, 131/05
	#2 2222/8306, 131/06
	#1 2222/8307, 131/07

if __name__ == '__main__':
	main()
