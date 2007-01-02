#!/usr/bin/perl
#
# Reads the display filter keyword dump produced by 'tshark -G' and
# formats it for a pod document. The pod document is then used to
# make a manpage
#
# STDIN is the wireshark glossary
# arg1 is the pod template file. The =insert_dfilter_table token
#	will be replaced by the pod-formatted glossary
# STDOUT is the output
#
# $Id$

%ftenum_names = (
	'FT_NONE',		'No value',
	'FT_PROTOCOL',		'Protocol',
	'FT_BOOLEAN',		'Boolean',
	'FT_UINT8',		'Unsigned 8-bit integer',
	'FT_UINT16',		'Unsigned 16-bit integer',
	'FT_UINT24',		'Unsigned 24-bit integer',
	'FT_UINT32',		'Unsigned 32-bit integer',
	'FT_UINT64',		'Unsigned 64-bit integer',
	'FT_INT8',		'Signed 8-bit integer',
	'FT_INT16',		'Signed 16-bit integer',
	'FT_INT24',		'Signed 24-bit integer',
	'FT_INT32',		'Signed 32-bit integer',
	'FT_INT64',		'Signed 64-bit integer',
	'FT_DOUBLE',		'Double-precision floating point',
	'FT_ABSOLUTE_TIME',	'Date/Time stamp',
	'FT_RELATIVE_TIME',	'Time duration',
	'FT_STRING',		'String',
	'FT_STRINGZ',		'String',
	'FT_UINT_STRING',	'String',
	'FT_ETHER',		'6-byte Hardware (MAC) Address',
	'FT_BYTES',		'Byte array',
	'FT_IPv4',		'IPv4 address',
	'FT_IPv6',		'IPv6 address',
	'FT_IPXNET',		'IPX network or server name',
);

# Read all the data into memory
while (<STDIN>) {
	next unless (/^([PF])/);

	$record_type = $1;
	chomp($_);
	$_ =~ s/\&/\&amp\;/g;
	$_ =~ s/\>/\&gt;/g;
	$_ =~ s/\</\&lt\;/g;

	# Store protocol information
	if ($record_type eq 'P') {
		($junk, $name, $abbrev) = split(/\t+/, $_);
		$proto_abbrev{$name} = $abbrev;
	}
	# Store header field information
	else {
		($junk, $name, $abbrev, $type, $parent, $blurb) =
			split(/\t+/, $_);
		push(@{$field_abbrev{$parent}}, $abbrev);
		$field_info{$abbrev} = [ $name, $type, $blurb ];
	}
}

# if there was no input on stdin, bail out
if ($record_type ne 'P' and $record_type ne 'F') {
	exit;
}

$template = shift(@ARGV);

open(TEMPLATE, $template) || die "Can't open $template for reading: $!\n";

while (<TEMPLATE>) {
	if (/=insert_dfilter_table/) {
		&create_dfilter_table;
	}
	else {
		print;
	}
}

close(TEMPLATE) || die "Can't close $template: $!\n";

sub create_dfilter_table {

        print "<appendix id=\"AppFiltFields\"><title>Wireshark Display Filter Fields</title>\n";
	$pn_counter = 1;

	# Print each protocol
	for $proto_name (sort keys %proto_abbrev) {

		$ns_proto_name = $proto_name;
		$ns_proto_name =~ s/\s//g;
		$ns_proto_name =~ s/\)//g;
		$ns_proto_name =~ s/\(//g;
		$ns_proto_name =~ s/_//g;
		$ns_proto_name =~ s/\+/plus/g;
		$ns_proto_name =~ s/\//slash/g;
		$ns_proto_name =~ s/,/comma/g;
		$ns_proto_name =~ s/:/colon/g;
		$ns_proto_name =~ s/'/apos/g;
		
		# The maximum token name length is apparently 44 characters. 
		# That's what NAMELEN is defined as in docbook 4.1, at least.

		if (length ($ns_proto_name) > 41) {  # "SID" and "TID" are prepended below
			$ns_proto_name = sprintf ("%s%04d", substr($ns_proto_name, 0,
				37), $pn_counter);
			$pn_counter++;
		}
			
		print "<section id=\"SID$ns_proto_name\"><title>$proto_name ($proto_abbrev{$proto_name})</title>\n\n";

		print "<table id=\"TID$ns_proto_name\"><title>$proto_name ($proto_abbrev{$proto_name})</title>\n";
		print "<tgroup cols=\"4\">\n";
#		print "<colspec colnum=\"1\" colwidth=\"80pt\">\n";
#		print "<colspec colnum=\"2\" colwidth=\"80pt\"\n>";
		print "<thead>\n  <row>\n    ";
 		print "<entry>Field</>\n    <entry>Field Name</>\n    <entry>Type</>\n    <entry>Description</>\n\n";

		print "  </row>\n</thead>\n<tbody>\n";

		# If this proto has children fields, print those
		if ($field_abbrev{$proto_abbrev{$proto_name}}) {

			for $field_abbrev (sort @{$field_abbrev{$proto_abbrev{$proto_name}}}) {

			    print "  <row>\n";
			    print "    <entry>$field_abbrev</entry>\n";
			    print "    <entry>", $field_info{$field_abbrev}[0], "</entry>\n";
			    print "    <entry>", $ftenum_names{$field_info{$field_abbrev}[1]}, "</entry>\n";
 				print "    <entry>", $field_info{$field_abbrev}[2], "</>\n";
			    print "  </row>\n\n";

			}

		}
		else {

		    print "  <row>\n    <entry></entry>\n    <entry></entry>\n    <entry></entry><entry></entry>\n";
		    print "  </row>\n";

		}

		print "</tbody></tgroup></table>\n";
		print "</section>\n\n";

	}

	print "</appendix>\n";

}
