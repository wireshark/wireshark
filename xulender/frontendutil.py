# frontendutil.py - Frontend utility functions

import sys

def id_to_name(id):
	'''Convert an id name (which may have dashes or other "odd" charaters to
	   a valid C-style identifier.'''
	for ch in ' -:': id = id.replace(ch, '_')
	return id

def get_attribute(node, attr_name, notfound = None):
	'''If a node has a particular attribute, return that attribute.
	   Otherwise return the value of "notfound".'''
	try:
		return node.attributes[attr_name].value
	except:
		pass

	return notfound

class counter:
	'''Create a "counter" that increments each time get_count() is called.
	   This is useful for resource IDs, etc.'''
	def __init__(self, start=0):
		self.count = start

	def get_count(self):
		return self.count

class sect_file:
	'''File objects that have headers, bodies, and footers.  The file's
	   contents aren't written until the close() method is called.'''
	def __init__(self, file_path):
		self.file_path = file_path
		self.header = '''/* %s */
/* THIS FILE HAS BEEN AUTOMATICALLY GENERATED. */
/* Command: %s */
/* DO NOT MODIFY BY HAND. */
''' % (file_path, ' '.join(sys.argv))
		self.body = ''
		self.footer = ''

	def write_header(self, text):
		self.header = self.header + text

	def write_body(self, text):
		self.body = self.body + text

	def write_footer(self, text):
		self.footer = self.footer + text

	def close(self):
		print 'Writing ' + self.file_path
		fp = open(self.file_path, 'w')
		fp.write(self.header)
		fp.write(self.body)
		fp.write(self.footer)
		fp.close()
