#!/usr/bin/python

"""
Creates C code from a table of NCP type 0x2222 packet types.
(And 0x3333, which are the replies, but the packets are more commonly
refered to as type 0x2222; the 0x3333 replies are understood to be
part of the 0x2222 "family")

Data comes from "Programmer's Guide to the NetWare Core Protocol"
by Steve Conner and Dianne Conner.

Novell provides info at:

http://developer.novell.com/ndk  (where you can download an *.exe file which
installs a PDF)

or

http://developer.novell.com/ndk/doc/docui/index.htm#../ncp/ncp__enu/data/
for a badly-formatted HTML version of the same PDF.


$Id: ncp2222.py,v 1.6 2000/09/06 04:50:51 gram Exp $

Copyright (c) 2000 by Gilbert Ramirez <gram@xiexie.org>

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


packets		= UniqueCollection('NCP Packet Descriptions')
compcode_lists	= UniqueCollection('Completion Code Lists')
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

	def __repr__(self):
		"String representation"
		return "NamedList: " + `self.list`

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
		self.list = []
		NamedList.__init__(self, name, self.list)

		expected_offset = None

		# Make a PTVCRecord object for each list in 'records'
		for record in records:
			ptvc_rec = PTVCRecord(record)

			if expected_offset == None:
				expected_offset = ptvc_rec.Offset()

			elif expected_offset == -1:
				pass

			elif expected_offset != ptvc_rec.Offset():
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

class PTVCRecord:
	def __init__(self, record):
		"Constructor"
		self.offset	= record[0]
		self.length	= record[1]
		self.field	= record[2]

		# Small sanity check
		field_length = self.field.Length()

#		if type(field_length) != type(self.length):
#			sys.stderr.write("Length types do not match")
#			sys.exit(1)

#		if type(field_length) == type(0) and field_length > 0:
#			if field_length != self.length:
#				sys.stderr.write("Length %d does not match field length %d for field %s\n" % (self.length, field_length, self.field.Abbreviation()))
#				sys.exit(1)

		# Check if an endianness override is given
		try:
			self.endianness = record[3]

		# If no endianness was given in the record, then
		# use the field's default endianness.
		except IndexError:
			self.endianness = self.field.Endianness()

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

	def __repr__(self):
		"String representation"
		endianness = 'FALSE'
		if self.endianness == LE:
			endianness = 'TRUE'

		length = -1

		if type(self.length) == type(0):
			length = self.length
		else:
			var_length = self.field.Length()
			if var_length > 0:
				length = var_length

		if length > -1:
			return "{ &%s, %d, %s }" % (self.field.HFName(),
					length, endianness)
		else:
			length = "PTVC_VARIABLE_LENGTH"
			return "{ &%s, %s, %s }" % (self.field.HFName(),
					length, endianness)

	def Offset(self):
		return self.offset

	def Length(self):
		return self.length

	def Field(self):
		return self.field


##############################################################################

class NCP:
	"NCP Packet class"
	def __init__(self, func_code, description, group):
		"Constructor"
		self.func_code		= func_code
		self.description	= description
		self.group		= group
		self.codes		= None
		self.request_records	= None
		self.reply_records	= None

		if not groups.has_key(group):
			sys.stderr.write("NCP 0x%x has invalid group '%s'\n" % (self.func_code, group))
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
			self.CheckRecords(size, records, "Request", 10)
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
				variables[var] = 1

		if self.reply_records:
			for record in self.reply_records:
				var = record[2]
				variables[var] = 1

		return variables.keys()


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

class byte(Type):
	type	= "byte"
	ftype	= "FT_UINT8"
	def __init__(self, abbrev, descr):
		Type.__init__(self, abbrev, descr, 1)

# Same as above. Both are provided for convenience
class uint8(Type):
	type	= "uint8"
	ftype	= "FT_UINT8"
	def __init__(self, abbrev, descr):
		Type.__init__(self, abbrev, descr, 1)

class uint16(Type):
	type	= "uint16"
	ftype	= "FT_UINT16"
	def __init__(self, abbrev, descr, endianness = BE):
		Type.__init__(self, abbrev, descr, 2, endianness)

class uint32(Type):
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

	def __repr__(self):
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
BufferSize	= uint16("buffer_size", "Buffer Size")
ConnectionNumber	= uint32("connection_number", "Connection Number")
DirHandle	= byte("dir_handle", "Directory Handle")

FileHandle	= bytes("file_handle", "File Handle", 6)

FileLock	= val_string8("file_lock", "File Lock", [
	[ 0x00, "Not Locked" ],
	[ 0xfe, "Locked by file lock" ],
	[ 0xff, "Unknown" ],
])

FileOffset	= uint32("file_offset", "File Offset")
FilePath	= nstring8("file_path", "File Path")
FileSize	= uint32("file_size", "File Size")
JobType		= uint16("job_type", "Job Type")

LogicalLockType	= val_string8("logical_lock_type", "Logical Lock Type", [
	[ 0x00, "Log file" ],
	[ 0x01, "Log and lock file for exclusive read/write use" ],
	[ 0x03, "Log and lock with shareable read-only use" ],
])

LogicalRecordName	= nstring8("logical_record_name", "Logical Record Name")
LogLockType	= byte("log_lock_type", "Log Lock Type")

MaxBytes	= uint16("max_bytes", "Maximum Number of Bytes")
NumBytes	= uint16("num_bytes", "Number of Bytes")

ObjectFlags	= val_string8("object_flags", "Object Flags", [
	[ 0x00, "Dynamic object" ],
	[ 0x01, "Static object" ],
])

ObjectHasProperties = val_string8("object_has_properites", "Object Has Properties", [
	[ 0x00, "No properties" ],
	[ 0xff, "One or more properties" ],
])

ObjectID	= uint32("object_id", "Object ID")
ObjectID.Display('BASE_HEX')

ObjectName	= nstring8("object_name", "Object Name")
ObjectName1	= fw_string("object_name1", "Object Name", 48)

ObjectSecurity	= val_string8("object_security", "Object Security", [
	[ 0x00, "Anyone can read or modify the object" ],
	[ 0x01, "Client logged into the file server can read the object" ],
	[ 0x02, "Client logged into the file server with the object's name, type and password can read the object" ],
	[ 0x03, "Client with supervisor equivalence can read the object" ],
	[ 0x04, "Only the operating system can read the object" ],
	[ 0x10, "Client logged into the file server can modify the object" ],
	[ 0x20, "Client logged into the file server with the object's name, type and password can modify the object" ],
	[ 0x30, "Client with supervisor equivalence can modify the object" ],
	[ 0x40, "Only the operating system can modify the object" ],
])

ObjectType	= val_string16("object_type", "Object Type", [
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

PropertyHasMoreSegments	= val_string8("property_has_more_segments",
	"Property Has More Segments", [
	[ 0x00,	"Is last segment" ],
	[ 0xff,	"More segments are available" ],
])

PropertyName	= nstring8("property_name", "Property Name")
PropertyData	= bytes("property_data", "Property Data", 128)
PropertySegment	= uint8("property_segment", "Property Segment")

PropertyType	= val_string8("property_type", "Property Type", [
	[ 0x00,	"Static item" ],
	[ 0x01,	"Dynamic item" ],
	[ 0x02,	"Static set" ],
	[ 0x03,	"Dynamic set" ],
])

TaskNumber	= uint32("task_number", "Task Number")
TimeoutLimit	= uint16("timeout_limit", "Timeout Limit")
UnknownByte	= byte("unknown_byte", "Unknown Byte")


##############################################################################
# NCP Groups
##############################################################################
groups = {}
groups['accounting']	= "Accounting"
groups['afp']		= "AFP"
groups['auditing']	= "Auditing"
groups['bindery']	= "Bindery"
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
groups['tss']		= "Transaction Tracking"

##############################################################################
# NCP Errors
##############################################################################
errors = {}
errors[0x0000] = "Ok"
errors[0x0001] = "Transaction tracking is available"
errors[0x0002] = "Ok. The data has been written"

errors[0x0100] = "One or more of the ConnectionNumbers in the send list are invalid"
errors[0x0101] = "Invalid space limit"
errors[0x0102] = "Insufficient disk space"
errors[0x0103] = "Queue server cannot add jobs"
errors[0x0104] = "Out of disk space"
errors[0x0105] = "Semaphore overflow"

errors[0x0200] = "One or more clients in the send list are not logged in"
errors[0x0201] = "Queue server cannot attach"

errors[0x0300] = "One or more clients in the send list are not accepting messages"

errors[0x0400] = "Client already has message"
errors[0x0401] = "Queue server cannot service job"

errors[0x7e00] = "NCP failed boundary check"

errors[0x8000] = "Lock fail"
errors[0x8100] = "A file handle could not be allocated by the file server"
errors[0x8200] = "Unauthorized to open the file"
errors[0x8300] = "Unable to read/write the volume. Possible bad sector on the file server"

errors[0x8400] = "Unauthorized to create the directory"
errors[0x8401] = "Unauthorized to create the file"

errors[0x8500] = "Unauthorized to delete the specified file"
errors[0x8501] = "Unauthorized to overwrite an existing file in this directory"

errors[0x8700] = "An unexpected character was encountered in the filename"
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

errors[0x9100] = "Some of the affected files already exist"

errors[0x9200] = "Directory with the new name already exists"
errors[0x9201] = "All of the affected files already exist"

errors[0x9300] = "Unauthorized to read from this file"
errors[0x9400] = "Unauthorized to write to this file"
errors[0x9500] = "The affected file is detached"

errors[0x9600] = "The file server has run out of memory to service this request"
errors[0x9601] = "No alloc space for message"

errors[0x9800] = "The affected volume is not mounted"
errors[0x9801] = "The volume associated with VolumeNumber is not mounted"
errors[0x9802] = "The resulting voume does not exist"
errors[0x9803] = "The destination volume is not mounted"

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

errors[0x9f00] = "The request attempted to delete a directory that is in use by another client"

errors[0xa000] = "The request attempted to delete a directory that is not empty"
errors[0xa100] = "An unrecoverable error occured on the affected directory"
errors[0xa200] = "The request attempted to read from a file region that is physically locked"
errors[0xa400] = "Invalid directory rename attempted"

errors[0xbf00] = "Requests for this name space are not valid on this volume"

errors[0xc000] = "Unauthorized to retrieve accounting data"
errors[0xc100] = "The ACCOUNT_BALANCE property does not exist"
errors[0xc200] = "The object has exceeded its credit limit"
errors[0xc300] = "Too many holds have been placed against this account"
errors[0xc400] = "The client account has been disabled"

errors[0xc500] = "Access to the account has been denied because of intruder detection"
errors[0xc501] = "Login lockout"

errors[0xc600] = "The caller does not have operator priviliges"
errors[0xc601] = "The client does not have operator priviliges"

errors[0xd000] = "Queue error"
errors[0xd100] = "The queue does not exist"

errors[0xd200] = "A queue server is not associated with this queue"
errors[0xd201] = "A queue server is not associated with the selected queue"
errors[0xd202] = "No queue server"

errors[0xd300] = "No queue rights"

errors[0xd400] = "The queue is full and cannot accept another request"
errors[0xd401] = "The queue associated with ObjectId is full and cannot accept another request"

errors[0xd500] = "A job does not exist in this queue"
errors[0xd501] = "No queue job"
errors[0xd502] = "The job associated with JobNumber does not exist in this queue"

errors[0xd600] = "The file server does not allow unencrypted passwords"
errors[0xd601] = "No job right"

errors[0xd700] = "Bad account"
errors[0xd701] = "The old and new password strings are identical"
errors[0xd702] = "The job is currently being serviced"
errors[0xd703] = "The queue is currently servicing a job"
errors[0xd704] = "Queue servicing"

errors[0xd800] = "Queue not active"

errors[0xd900] = "The file server cannot accept another connection as it has reached its limit"
errors[0xd901] = "The client is not security equivalent to one of the objects in the Q_SERVERS group property of the target queue"
errors[0xd902] = "Station is not a server"

errors[0xda00] = "Attempted to login to the file server during a restricted time period"
errors[0xda01] = "Queue halted"

errors[0xdb00] = "Attempted to login to the file server from an unauthorized workstation or network"
errors[0xdb01] = "The queue cannot attach another queue server"
errors[0xdb02] = "Maximum queue servers"

errors[0xde00] = "Attempted to login to the file server with an incorrect password"
errors[0xdf00] = "Attempted to login to the file server with a password that has expired"

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
errors[0xfd03] = "Transacktion tracking is disabled"

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
errors[0xff19] = "No files found"

##############################################################################
# NCP Packets. Here I list functions and subfunctions in hexadecimal like the
# NCP book (and I believe LanAlyzer does this too).
# However, Novell lists these in decimal in their on-line documentation.
##############################################################################
# 2222/02
pkt = NCP(0x02, "File Release Lock", 'sync')
pkt.Request(7)
pkt.Reply(8)
pkt.CompletionCodes([0x0000, 0xff00])

#
# Untested
#
# 2222/03
#pkt = NCP(0x03, "Log File", 'sync')
#pkt.request( (12, 267), [
#	[ 7, 1, DirHandle ],
#	[ 8, 1, LogLockType ],
#	[ 9, 2, TimeoutLimit, LE ],
#	[ 11, (1, 256), FilePath ],
#	])
#pkt.completion_codes([0x0000, 0x8200, 0x9600, 0xfe00, 0xff01])
#
## 2222/04
#pkt = NCP(0x04, "Lock File Set", 'sync')
#pkt.request([
#	[ 7, TimeoutLimit ],
#	])
#pkt.completion_codes([0xfe, 0xff01])
#
## 2222/05
#pkt = NCP(0x05, "Release File", 'sync')
#pkt.request([
#	[ 7, DirHandle ],
#	[ 8, FilePath ],
#	])
#pkt.completion_codes([0x7e, 0x98, 0x9b, 0x9c, 0xff02])
#
## 2222/06
#pkt = NCP(0x06, "Release File Set", 'sync')
#pkt.request([
#	[ 7, UnknownByte ],
#	])
#pkt.completion_codes()
#
## 2222/07
#pkt = NCP(0x07, "Clear File", 'sync')
#pkt.request([
#	[ 7, DirHandle ],
#	[ 8, FilePath ],
#	])
#pkt.completion_codes([0x7e, 0x96, 0x98, 0x9b, 0x9c,
#	0xa1, 0xfd, 0xff])
#
## 2222/08
#pkt = NCP(0x08, "Clear File Set", 'sync')
#pkt.request([
#	[ 7, FileLock ],
#	])
#pkt.completion_codes([0x7e])
#
## 2222/09
#pkt = NCP(0x09, "Log Logical Record", 'sync')
#pkt.request([
#	[ 7, LogicalLockType ],
#	[ 8, TimeoutLimit_be ],
#	[ 10, LogicalRecordName ],
#	])
#pkt.completion_codes([0x96, 0xfe, 0xff])
#
## 2222/0a
#pkt = NCP(0x0a, "Lock Logical Record Set", 'sync')
#pkt.request([
#	[ 7, LogicalLockType ],
#	[ 8, TimeoutLimit_le ],
#	])
#pkt.completion_codes([0xfe, 0xff])
#
## 2222/0b
#pkt = NCP(0x0b, "Clear Logical Record", 'sync')
#pkt.request([
#	[7, LogicalRecordName ],
#	])
#pkt.completion_codes([0xff]
## 2222/0c
## 2222/0d
## 2222/0e
## 2222/0f
## 2222/11
#
## 2222/1100
#pkt = NCP(0x1100, "Lock Logical Record Set", 'sync')
#pkt.request([
#	[ 10, var_length_data("data").length_var("packetlength") ]
#	])
#pkt.completion_codes()
#

# 2222/1735
pkt = NCP(0x1735, "Get Bindery Object ID", 'bindery')
pkt.Request((13,60), [
	[ 10, 2, ObjectType ],
	[ 12, (1,48), ObjectName ],
])
pkt.Reply(62, [
	[ 8, 4, ObjectID ],
	[ 12, 2, ObjectType ],
	[ 14, 48, ObjectName1 ],
])
pkt.CompletionCodes([0x0000, 0x9600, 0xef01, 0xf000, 0xfc02,
	0xfe01, 0xff00])

# 2222/1737
pkt = NCP(0x1737, "Scan Bindery Object", 'bindery')
pkt.Request((17,64), [
	[ 10, 4, ObjectID ],
	[ 14, 2, ObjectType ],
	[ 16, (1,48), ObjectName ],
])
pkt.Reply(65, [
	[ 8, 4, ObjectID ],
	[ 12, 2, ObjectType ],
	[ 14, 48, ObjectName1 ],
	[ 62, 1, ObjectFlags ],
	[ 63, 1, ObjectSecurity ],
	[ 64, 1, ObjectHasProperties ],
])
pkt.CompletionCodes([0x0000, 0x9600, 0xef01, 0xfc02,
	0xfe01, 0xff00])

# 2222/173D
pkt = NCP(0x173D, "Read Property Value", 'bindery')
pkt.Request((15,77), [
	[ 10, 2, ObjectType ],
	[ 12, (1,48), ObjectName ],
	[ -1, 1, PropertySegment ],
	[ -1, (1,16), PropertyName ],
])
pkt.Reply(138, [
	[ 8, 128, PropertyData ],
	[ 136, 1, PropertyHasMoreSegments ],
	[ 137, 1, PropertyType ],
])
pkt.CompletionCodes([0x0000, 0x8800, 0x9300, 0x9600, 0xec01,
	0xf000, 0xf100, 0xf900, 0xfb02, 0xfc02, 0xfe01, 0xff00 ])

# 2222/177C
pkt = NCP(0x177C, "Service Queue Job", 'queue')
pkt.Request(16, [
	[ 10, 4, ObjectID ],
	[ 14, 2, JobType ],
])
pkt.Reply(24, [ # XXX - 76, [
	[ 8, 4, ConnectionNumber ],
	[ 12, 4, TaskNumber ],
	[ 16, 4, ObjectID ],
	[ 20, 4, ObjectID ],
	# XXX - DateTime
])
# These completion codes are not documented, but guessed.
pkt.CompletionCodes([0x0000, 0x9900, 0xd000, 0xd100, 0xd201, 0xd300,
	0xd401, 0xd502, 0xd601, 0xd704, 0xd800, 0xd901, 0xda01, 0xdb01,
	0xff00 ])

# 2222/18
pkt = NCP(0x18, "End of Job", 'connection')
pkt.Request(7)
pkt.Reply(8)
pkt.CompletionCodes([0x0000])

# 2222/19
pkt = NCP(0x19, "Logout", 'connection')
pkt.Request(7)
pkt.Reply(8)
pkt.CompletionCodes([0x0000])

# 2222/21
pkt = NCP(0x21, "Negotiate Buffer Size", 'connection')
pkt.Request(9, [
	[ 7, 2, BufferSize ],
])
pkt.Reply(10, [
	[ 8, 2, BufferSize ],
])
pkt.CompletionCodes([0x0000])

# 2222/42
pkt = NCP(0x42, "Close File", 'file')
pkt.Request(13, [
	[ 7, 6, FileHandle ],
])
pkt.Reply(8)
pkt.CompletionCodes([0x0000, 0xff00])

# 2222/47
pkt = NCP(0x47, "Get Current Size of File", 'file')
pkt.Request(13, [
	[ 7, 6, FileHandle ],
])
pkt.Reply(12, [
	[ 8, 4, FileSize ],
])
pkt.CompletionCodes([0x0000, 0x8800])

# 2222/48
pkt = NCP(0x48, "Read From A File", 'file')
pkt.Request(20, [
	[ 7, 1, UnknownByte ],
	[ 8, 6, FileHandle ],
	[ 14, 4, FileOffset ],	# my nomenclature
	[ 18, 2, MaxBytes ],	# my nomenclature
])
pkt.Reply(10, [ # XXX - (10,-1), [
	[ 8, 2, NumBytes ],	# my nomenclature
	# XXX
])
pkt.CompletionCodes([0x0000, 0x8800, 0x9300, 0xff00])

# 2222/5701	- no info
# 2222/5702	- no info
# 2222/5706	- no info
# 2222/5714	- no info
# 2222/68	- no info
# 2222/72	- no info

##############################################################################
# Produce C code
##############################################################################
if __name__ == '__main__':
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
#include "packet.h"
#include "conversation.h"
#include "ptvcursor.h"
#include "packet-ncp-int.h"
    
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
		for var in vars:
			variables_used_hash[var] = 1



	# Print the hf variable declarations
	for var in variables_used_hash.keys():
		print "static int " + var.HFName() + " = -1;"


	# Print the value_string's
	for var in variables_used_hash.keys():
		if var.type == "val_string8" or var.type == "val_string16":
			print ""
			print `var`


	print """
void
proto_register_ncp2222(void)
{

	static hf_register_info hf[] = {
	{ &hf_ncp_func,
	{ "Function", "ncp.func", FT_UINT8, BASE_HEX, NULL, 0x0, "" }},

	{ &hf_ncp_length,
	{ "Packet Length", "ncp.length", FT_UINT16, BASE_DEC, NULL, 0x0, "" }},

	{ &hf_ncp_subfunc,
	{ "SubFunction", "ncp.subfunc", FT_UINT8, BASE_HEX, NULL, 0x0, "" }},

	{ &hf_ncp_completion_code,
	{ "Completion Code", "ncp.completion_code", FT_UINT8, BASE_HEX, NULL, 0x0, "" }},

	{ &hf_ncp_connection_status,
	{ "Connection Status", "ncp.connection_status", FT_UINT8, BASE_DEC, NULL, 0x0, "" }},
	"""

	# Print the registration code for the hf variables
	for var in variables_used_hash.keys():
		print "\t{ &%s," % (var.HFName())
		print "\t{ \"%s\", \"%s\", %s, %s, %s, 0x%x, \"\" }},\n" % \
			(var.Description(), var.DFilter(),
			var.EtherealFType(), var.Display(), var.ValuesName(),
			var.Mask())

	print """\t};

		proto_register_field_array(proto_ncp, hf, array_length(hf));
	}
	"""


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

	# Print PTVC's
	print "/* PTVC records. These are re-used to save space. */"
	for ptvc in ptvc_lists.Members():
		if not ptvc.Null() and not ptvc.Empty():
			print "static const ptvc_record %s[] = {" % (ptvc.Name())
			records = ptvc.Records()
			for ptvc_rec in records:
				print "\t%s," % (ptvc_rec)
			print "\t{ NULL, 0, 0 }"
			print "};\n"

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


	# Print ncp_record packet records
	print "#define SUBFUNC 0xff"
	print "#define NOSUB   0x00"

	print "/* ncp_record structs for packets */"
	print "static const ncp_record ncp_packets[] = {"
	for pkt in packets.Members():
		if pkt.HasSubFunction():
			subfunc_string = "SUBFUNC"
		else:
			subfunc_string = "NOSUB"
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

	print '\t{ 0, 0, 0, NULL }'
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


	print '#include "ncp2222.h"'


