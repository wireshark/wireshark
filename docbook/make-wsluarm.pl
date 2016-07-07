#!/usr/bin/perl
#
# make-wsluarm.pl
# WSLUA's Reference Manual Generator
#
# (c) 2006, Luis E. Garcia Onatnon <luis@ontanon.org>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
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
# (-: I don't even think writing this in Lua  :-)
# ...well I wished you had!
#
# changed by Hadriel Kaplan to do the following:
#  - generates pretty XML output, to make debugging it easier
#  - allows modules (i.e., WSLUA_MODULE) to have detailed descriptions
#  - two (or more) line breaks in comments result in separate paragraphs
#  - all '&' are converted into their entity names, except inside urls
#  - all '<', and '>' are converted into their entity names everywhere
#  - any word(s) wrapped in one star, e.g., *foo bar*, become italics
#  - any word(s) wrapped in two stars, e.g., **foo bar**, become commands (is there a 'bold'?)
#  - any word(s) wrapped in backticks, e.g., `foo bar`, become commands (is there something better?)
#  - any word(s) wrapped in two backticks, e.g., ``foo bar``, become one backtick
#  - any "[[url]]" becomes an XML ulink with the url as both the url and text
#  - any "[[url|text]]" becomes an XML ulink with the url as the url and text as text
#  - any indent with a single leading star '*' followed by space is a bulleted list item
#    reducing indent or having an extra linebreak stops the list
#  - any indent with a leading digits-dot followed by space, i.e. "1. ", is a numbered list item
#    reducing indent or having an extra linebreak stops the list
#  - supports meta-tagged info inside comment descriptions as follows:
#    * a line starting with "@note" or "Note:" becomes an XML note line
#    * a line starting with "@warning" or "Warning:" becomes an XML warning line
#    * a line starting with "@version" or "@since" becomes a "Since:" line
#    * a line starting with "@code" and ending with "@endcode" becomes an
#      XML programlisting block, with no indenting/parsing within the block
#    The above '@' commands are based on Doxygen commands
#
# Changed by Gerald Combs to generate AsciiDoc.
#  - We might want to convert the epan/wslua/*.c markup to AsciiDoc
#  - ...or we might want to generate Doxygen output instead.

use strict;
#use V2P;

sub deb {
#	warn $_[0];
}

sub gorolla {
# a gorilla stays to a chimp like gorolla stays to chomp
# but this one returns the shrugged string.
	my $s = shift;
	# remove leading newlines and spaces at beginning
	$s =~ s/^([\n]|\s)*//ms;
	# remove trailing newlines and spaces at end
	$s =~ s/([\n]|\s)*$//s;
	# escape HTML entities everywhere

	# bold and italics - but don't change a star followed by space (it's a list item)
	$s =~ s/(\*\*)([^*]+?)(\*\*)/`$2`/g; # bold=command??

	# one backtick is quote/command
	#$s =~ s/([^`]|^)(`)([^`]+?)(`)/$1<command>$3<\/command>/g; # quote=command??
	# two backticks are one (...and don't appear anywhere?)
	#$s =~ s/(``)([^`]+?)(``)/`$2`/g; # quote=command??

	# Convert wiki-style '[[url]]'
	$s =~ s/(\[\[)([^\]\|]+?)(\]\])/link:\$\$$2\$\$:[$2]/g;
	# handle '[[url|pretty]]'
	$s =~ s/(\[\[)(([^\]\|]+?)\|\s*([^\]]+?))(\]\])/link:\$\$$3\$\$:[$4]/g;

	$s;
}

# break up descriptions based on newlines and keywords
# builds an array of paragraphs and returns the array ref
# each entry in the array is a single line for doc source, but not a
# whole paragraph - there are "<para>"/"</para>" entries in the
# array to make them paragraphs - this way the doc source itself is
# also pretty, while the resulting output is of course valid
# first arg is the array to build into; second arg is an array
# of lines to parse - this way it can be called from multiple
# other functions with slightly different needs
# this function assumes gorolla was called previously
sub parse_desc_common {
	my @r; # a temp array we fill, then copy into @ret below
	my @ret   = @{ $_[0] };
	my @lines = @{ $_[1] };

	# the following will unfortunately create empty paragraphs too
	# (ie, <para> followed by </para>), so we do this stuff to a temp @r
	# array and then copy the non-empty ones into the passed-in array @ret
	if ($#lines >= 0) {
		# capitalize the first letter of the first line
		$lines[0] = ucfirst($lines[0]);
		# for each double newline, break into separate para's
		for (my $idx=0; $idx <= $#lines; $idx++) {

			$lines[$idx] =~ s/^(\s*)//; # remove leading whitespace
			# save number of spaces in case we need to know later
			my $indent = length($1);

			# if we find @code then treat it as a blob
			if ($lines[$idx] =~ /^\@code\b/) {
				my $line = $lines[$idx];
				$line =~ s/\@code/[source,lua]\n----\n/;
				# if this line didn't have ending token, keep eating paragraphs
				while (!($line =~ /\@endcode\b/) && $idx <= $#lines) {
					# also insert back the line separator we ate in earlier split()
					$line .= $lines[++$idx] . "\n";
				}
				# fix ending token, and also remove trailing whitespace before it
				$line =~ s/[\s\n]*\@endcode/\n----/;
				$r[++$#r] = $line . "\n";
			} elsif ($lines[$idx] =~ /^\s*$/) {
				# line is either empty or just whitespace, and we're not in a @code block
				# so it's the end of a previous paragraph, beginning of new one
				$r[++$#r] = "\n\n";
			} else {
				# We have a regular line, not in a @code block.
				# Add it as-is.
				my $line = $lines[$idx];

				# If line starts with "Note:" or "@note", make it an admonition
				if ($line =~ /^[nN]ote:|^\@note /) {
					$r[++$#r] = "[NOTE]\n";
					$r[++$#r] = "====\n";
					$line =~ s/^([nN]ote:\s*|\@note\s*)//;
					$r[++$#r] = "" . $line . "\n";
					# keep eating until we find a blank line or end
					while (!($lines[++$idx] =~ /^\s*$/) && $idx <= $#lines) {
						$lines[$idx] =~ s/^(\s*)//; # remove leading whitespace
						$r[++$#r] = "" . $lines[$idx]. "\n";
					}
					$r[++$#r] = "====\n\n";

				# If line starts with "Warning:"" or @warning", make it an admonition
				} elsif ($line =~ /^[wW]arning:|^\@warning /) {
					$r[++$#r] = "[WARNING]\n";
					$r[++$#r] = "====\n";
					$line =~ s/^(wW]arning:\s*|\@warning\s*)//;
					# keep eating until we find a blank line or end
					$r[++$#r] = "" . $line . "\n";
					while (!($lines[++$idx] =~ /^\s*$/) && $idx <= $#lines) {
						$lines[$idx] =~ s/^(\s*)//; # remove leading whitespace
						$r[++$#r] = "" . $lines[$idx] . "\n";
					}
					$r[++$#r] = "====\n";

				# if line starts with "@version" or "@since", make it a "Since:"
				} elsif ($line =~ /^\@version |^\@since /) {
					$line =~ s/^\@version\s+|^\@since\s+/Since: /;
					$r[++$#r] = "\n" . $line . "\n\n";

				# if line starts with single "*" and space, leave it mostly intact.
				} elsif ($line =~ /^\*\s/) {
					$r[++$#r] = "\n";
					$r[++$#r] = "" . $line . "\n";
					# keep eating until we find a blank line or end
					while (!($lines[++$idx] =~ /^\s*$/) && $idx <= $#lines) {
						$lines[$idx] =~ s/^(\s*)//; # count and remove leading whitespace
						# if this is less indented than before, break out
						last if length($1) < $indent;
						$r[++$#r] = "" . $lines[$idx] . "\n";
					}
					$r[++$#r] = "\n\n";

				# if line starts with "1." and space, leave it mostly intact.
				} elsif ($line =~ /^1\.\s/) {
					$r[++$#r] = "\n";
					$r[++$#r] = "" . $line . "\n";
					# keep eating until we find a blank line or end
					while (!($lines[++$idx] =~ /^\s*$/) && $idx <= $#lines) {
						$lines[$idx] =~ s/^(\s*)//; # count and remove leading whitespace
						# if this is less indented than before, break out
						last if length($1) < $indent;
						$r[++$#r] = "" . $lines[$idx] . "\n";
					}
					$r[++$#r] = "\n\n";

				# just a normal line, add it to array
				} else {
					# Nested Lua arrays
					$line =~ s/\[\[(.*)\]\]/\$\$$1\$\$/g;
					$r[++$#r] = "" . $line . "\n";
				}
			}
		}
		$r[++$#r] = "\n\n";

		# Now go through @r, and copy into @ret but skip empty lines.
		# This isn't strictly necessary but makes the AsciiDoc output prettier.
		for (my $idx=0; $idx <= $#r; $idx++) {
			if ($r[$idx] =~ /^\s*$/ && $r[$idx+1] =~ /^\s*$/ && $r[$idx+2] =~ /^\s*$/) {
				$idx++; # for-loop will increment $idx and skip the other one
			} else {
				$ret[++$#ret] = $r[$idx];
			}
		}
	}

	return \@ret;
}

# for "normal" description cases - class, function, etc.
# but not for modules nor function arguments
sub parse_desc {
	my $s = gorolla(shift);
	# break description into separate sections
	my @r = (); # the array we return

	# split each line into an array
	my @lines = split(/\n/, $s);

	return parse_desc_common(\@r, \@lines);
}

# modules have a "title" and an optional description
sub parse_module_desc {
	my $s = gorolla(shift);
	# break description into separate sections
	my @r = (); # the array we return

	my @lines = split(/\n/, $s);
	my $line  = shift @lines;

	$r[++$#r] = "=== $line\n\n";

	return parse_desc_common(\@r, \@lines);
}

# function argument descriptions are in a <listitem>
sub parse_function_arg_desc {
	my $s = gorolla(shift);
	# break description into separate sections
	my @r = ( "\n" ); # the array we return

	my @lines = split(/\n/, $s);
	@r = @{ parse_desc_common(\@r, \@lines) };

	#$r[++$#r] = "</listitem>\n";

	return \@r;
}

# attributes have a "mode" and an optional description
sub parse_attrib_desc {
	my $s = gorolla(shift);
	# break description into separate sections
	my @r = (); # the array we return

	my $mode = shift;
	if ($mode) {
		$mode =~ s/RO/ Retrieve only./;
		$mode =~ s/WO/ Assign only./;
		$mode =~ s/RW|WR/ Retrieve or assign./;
		$r[++$#r] = "Mode: $mode\n\n";
	} else {
		die "Attribute does not have a RO/WO/RW mode: '$s'\n";
	}

	# split each line into an array
	my @lines = split(/\n/, $s);

	return parse_desc_common(\@r, \@lines);
}

# prints the parse_* arrays into the doc source file with pretty indenting
# first arg is the description array, second is indent level
sub print_desc {
	my $desc_ref = $_[0];

	my $indent = $_[1];
	if (!$indent) {
		$indent = 2;
	}
	#my $tabs = "\t" x $indent;

	for my $line ( @{ $desc_ref } ) {
		printf D "%s", $line;
	}
}

my %module = ();
my %modules = ();
my $class;
my %classes;
my $function;
my @functions;

my $asciidoc_template = {
	module_header =>               "[[lua_module_%s]]\n\n",
	# module_desc =>                 "\t<title>%s</title>\n",
	class_header =>                "[[lua_class_%s]]\n\n" .
								"==== %s\n\n",
	#class_desc =>                  "\t\t<para>%s</para>\n",
	class_attr_header =>           "[[lua_class_attrib_%s]]\n\n" .
								"===== %s\n\n",
	#class_attr_descr =>            "\t\t\t<para>%s%s</para>\n",
	class_attr_footer =>           "// End %s\n\n",
	function_header =>             "[[lua_fn_%s]]\n\n" .
								"===== %s\n\n",
	#function_descr =>              "\t\t\t<para>%s</para>\n",
	function_args_header =>        "[float]\n" .
								"===== Arguments\n\n",
	function_arg_header =>         "%s::\n",
	#function_arg_descr =>          "\t\t\t\t\t\t<listitem>\n" .
	#                               "\t\t\t\t\t\t\t<para>%s</para>\n" .
	#                               "\t\t\t\t\t\t</listitem>\n",
	function_arg_footer =>         "// function_arg_footer: %s\n\n",
	function_args_footer =>        "// end of function_args\n\n",
	function_argerror_header =>    "", #"\t\t\t\t\t<section><title>Errors</title>\n\t\t\t\t\t\t<itemizedlist>\n",
	function_argerror =>           "", #"\t\t\t\t\t\t\t<listitem><para>%s</para></listitem>\n",
	function_argerror_footer =>    "", #"\t\t\t\t\t\t</itemizedlist></section> <!-- function_argerror_footer: %s -->\n",
	function_returns_header =>     "[float]\n" .
								"===== Returns\n\n",
	function_returns =>            "%s\n\n",
	function_returns_footer =>     "// function_returns_footer: %s\n",
	function_errors_header =>      "[float]\n" .
								"===== Errors\n\n",
	function_errors =>             "* %s\n",
	function_errors_footer =>      "// function_errors_footer: %s\n",
	function_footer =>             "// function_footer: %s\n\n",
	class_footer =>                "// class_footer: %s\n",
	global_functions_header =>     "[[global_functions_%s]]\n\n" .
								   "==== Global Functions\n\n",
	global_functions_footer =>     "// Global function\n",
	module_footer =>               "// end of module\n",
};

#	class_constructors_header =>   "\t\t<section id='lua_class_constructors_%s'>\n\t\t\t<title>%s Constructors</title>\n",
#	class_constructors_footer =>   "\t\t</section> <!-- class_constructors_footer -->\n",
#	class_methods_header =>        "\t\t<section id='lua_class_methods_%s'>\n\t\t\t<title>%s Methods</title>\n",
#	class_methods_footer =>        "\t\t</section> <!-- class_methods_footer: %s -->\n",


my $template_ref = $asciidoc_template;
my $out_extension = "asciidoc";

# It's said that only perl can parse perl... my editor isn't perl...
# if unencoded this causes my editor's autoindent to bail out so I encoded in octal
# XXX: support \" within ""
my $QUOTED_RE = "\042\050\133^\042\135*\051\042";

my $TRAILING_COMMENT_RE = '((\s*|[\n\r]*)/\*(.*?)\*/)?';
my $IN_COMMENT_RE       = '[\s\r\n]*((.*?)\*/)?';

my @control =
(
# This will be scanned in order trying to match the re if it matches
# the body will be executed immediately after.
[ 'WSLUA_MODULE\s*([A-Z][a-zA-Z0-9]+)' . $IN_COMMENT_RE,
sub {
	$module{name} = $1;
	$module{descr} = parse_module_desc($3);
} ],

[ 'WSLUA_CLASS_DEFINE(?:_BASE)?\050\s*([A-Z][a-zA-Z0-9]+).*?\051;' . $TRAILING_COMMENT_RE,
sub {
	deb ">c=$1=$2=$3=$4=$5=$6=$7=\n";
	$class = {
		name => $1,
		descr=> parse_desc($4),
		constructors => [],
		methods => [],
		attributes => []
	};
	$classes{$1} = $class;
} ],

[ 'WSLUA_FUNCTION\s+wslua_([a-z_0-9]+)[^\173]*\173' . $TRAILING_COMMENT_RE,
sub {
	deb ">f=$1=$2=$3=$4=$5=$6=$7=\n";
	$function = {
		returns => [],
		arglist => [],
		args => {},
		name => $1,
		descr => parse_desc($4),
		type => 'standalone'
	};
	push @functions, $function;
} ],

[ 'WSLUA_CONSTRUCTOR\s+([A-Za-z0-9]+)_([a-z0-9_]+).*?\173' . $TRAILING_COMMENT_RE,
sub {
	deb ">cc=$1=$2=$3=$4=$5=$6=$7=\n";
	$function = {
		returns => [],
		arglist => [],
		args => {},
		name => "$1.$2",
		descr => parse_desc($5),
		type => 'constructor'
	};
	push @{${$class}{constructors}}, $function;
} ],

[ '_WSLUA_CONSTRUCTOR_\s+([A-Za-z0-9]+)_([a-z0-9_]+)\s*(.*?)\052\057',
sub {
	deb ">cc=$1=$2=$3=$4=$5=$6=$7=\n";
	$function = {
		returns => [],
		arglist => [],
		args => {},
		name => "$1.$2",
		descr => parse_desc($3),
		type => 'constructor'
	};
	push @{${$class}{constructors}}, $function;
} ],

[ 'WSLUA_METHOD\s+([A-Za-z0-9]+)_([a-z0-9_]+)[^\173]*\173' . $TRAILING_COMMENT_RE,
sub {
	deb ">cm=$1=$2=$3=$4=$5=$6=$7=\n";
	my $name = "$1";
	$name =~ tr/A-Z/a-z/;
	$name .= ":$2";
	$function = {
		returns => [],
		arglist => [],
		args => {},
		name => $name,
		descr => parse_desc($5),
		type => 'method'
	};
	push @{${$class}{methods}}, $function;
} ],

[ 'WSLUA_METAMETHOD\s+([A-Za-z0-9]+)(__[a-z0-9]+)[^\173]*\173' . $TRAILING_COMMENT_RE,
sub {
	deb ">cm=$1=$2=$3=$4=$5=$6=$7=\n";
	my $name = "$1";
	$name =~ tr/A-Z/a-z/;
	$name .= ":$2";
	my ($c,$d) = ($1,$5);
	$function = {
		returns => [],
		arglist => [],
		args => {},
		name => $name,
		descr => parse_desc($5),
		type => 'metamethod'
	};
	push @{${$class}{methods}}, $function;
} ],

[ '#define WSLUA_(OPT)?ARG_([A-Za-z0-9_]+)_([A-Z0-9]+)\s+\d+' . $TRAILING_COMMENT_RE,
sub {
	deb ">a=$1=$2=$3=$4=$5=$6=$7=\n";
	my $name = $1 eq 'OPT' ? "[$3]" : $3;
	push @{${$function}{arglist}} , $name;
	${${$function}{args}}{$name} = {descr=>parse_function_arg_desc($6),}
} ],

[ '\057\052\s*WSLUA_(OPT)?ARG_([A-Za-z0-9_]+)_([A-Z0-9]+)\s*(.*?)\052\057',
sub {
	deb ">a=$1=$2=$3=$4=$5=$6=$7=\n";
	my $name = $1 eq 'OPT' ? "[$3]" : $3;
	push @{${$function}{arglist}} , $name;
	${${$function}{args}}{$name} = {descr=>parse_function_arg_desc($4),}
} ],

[ '#define WSLUA_(OPT)?ARG_([A-Za-z0-9]+)_([a-z_]+)_([A-Z0-9]+)\s+\d+' . $TRAILING_COMMENT_RE,
sub {
	deb ">ca=$1=$2=$3=$4=$5=$6=$7=\n";
	my $name = $1 eq 'OPT' ? "[$4]" : $4;
	push @{${$function}{arglist}} , $name;
	${${$function}{args}}{$name} = {descr=>parse_function_arg_desc($7),optional => $1 eq '' ? 1 : 0 }
} ],

[ '/\052\s+WSLUA_ATTRIBUTE\s+([A-Za-z0-9]+)_([a-z_]+)\s+([A-Z]*)\s*(.*?)\052/',
sub {
	deb ">at=$1=$2=$3=$4=$5=$6=$7=\n";
	my $name = "$1";
	$name =~ tr/A-Z/a-z/;
	$name .= ".$2";
	push @{${$class}{attributes}}, { name => $name, descr => parse_attrib_desc($4, $3) };
} ],

[ '/\052\s+WSLUA_MOREARGS\s+([A-Za-z_]+)\s+(.*?)\052/',
sub {
	deb ">ma=$1=$2=$3=$4=$5=$6=$7=\n";
	push @{${$function}{arglist}} , "...";
	${${$function}{args}}{"..."} = {descr=>parse_function_arg_desc($2)}
} ],

[ 'WSLUA_(FINAL_)?RETURN\050\s*.*?\s*\051\s*;' . $TRAILING_COMMENT_RE,
sub {
	deb ">fr=$1=$2=$3=$4=$5=$6=$7=\n";
	push @{${$function}{returns}} , gorolla($4) if $4 ne '';
} ],

[ '\057\052\s*_WSLUA_RETURNS_\s*(.*?)\052\057',
sub {
	deb ">fr2=$1=$2=$3=$4=$5=$6=$7=\n";
	push @{${$function}{returns}} , gorolla($1) if $1 ne '';
} ],

[ 'WSLUA_ERROR\s*\050\s*(([A-Z][A-Za-z]+)_)?([a-z_]+),' . $QUOTED_RE ,
sub {
	deb ">e=$1=$2=$3=$4=$5=$6=$7=\n";
	my $errors;
	unless (exists ${$function}{errors}) {
		$errors =  ${$function}{errors} = [];
	} else {
		$errors = ${$function}{errors};
	}
	push @{$errors}, gorolla($4);
} ],

[ 'WSLUA_(OPT)?ARG_ERROR\s*\050\s*(([A-Z][A-Za-z0-9]+)_)?([a-z_]+)\s*,\s*([A-Z0-9]+)\s*,\s*' . $QUOTED_RE,
sub {
	deb ">ae=$1=$2=$3=$4=$5=$6=$7=\n";
	my $errors;
	unless (exists ${${${$function}{args}}{$5}}{errors}) {
		$errors =  ${${${$function}{args}}{$5}}{errors} = [];
	} else {
		$errors = ${${${$function}{args}}{$5}}{errors};
	}
	push @{$errors}, gorolla($6);
} ],

);

my $anymatch = '(^ThIsWiLlNeVeRmAtCh$';
for (@control) {
	$anymatch .= "|${$_}[0]";
}
$anymatch .= ')';

# for each file given in the command line args
my $file = shift;
my $docfile = 0;

while ( $file ) {

	# continue to next loop if the file is not plain text
	next unless -f $file;

	if (!$docfile) {
		$docfile = $file;
		$docfile =~ s#.*/##;
		$docfile =~ s/\.c$/.$out_extension/;
	}

	open C, "< $file" or die "Can't open input file $file: $!";
	open D, "> wsluarm_src/$docfile" or die "Can't open output file wsluarm_src/$docfile: $!";

	my $b = '';
	$b .= $_ while (<C>);

	close C;

	while ($b =~ /$anymatch/ms ) {
		my $match = $1;
# print "\n-----\n$match\n-----\n";
		for (@control) {
			my ($re,$f) = @{$_};
			if ( $match =~ /$re/ms) {
				&{$f}();
				$b =~ s/.*?$re//ms;
				last;
			}
		}
	}

	# peek at next file to see if it's continuing this module
	$file = shift;
	# make sure we get the next plain text file
	while ($file and !(-f $file)) {
		$file = shift;
	}

	if ($file) {
		# we have another file - check it out

		open C, "< $file" or die "Can't open input file $file: $!";

		my $peek_for_continue = '';
		$peek_for_continue .= $_ while (<C>);

		close C;

		if ($peek_for_continue =~ /WSLUA_CONTINUE_MODULE\s*([A-Z][a-zA-Z0-9]+)/) {
			if ($module{name} ne $1) {
				die "Input file $file continues a different module: $1 (previous module is $module{name})!";
			}
			# ok, we're continuing the same module
			next;
		}
	}

	# if we got here, we're not continuing the module

	$modules{$module{name}} = $docfile;

	print "Generating source AsciiDoc for: $module{name}\n";

	printf D ${$template_ref}{module_header}, $module{name}, $module{name};

	if ($module{descr} && @{$module{descr}} >= 0) {
		print_desc($module{descr}, 1);
	} else {
		die "did NOT print $module{name} description\n";
	}

	for my $cname (sort keys %classes) {
		my $cl = $classes{$cname};
		printf D ${$template_ref}{class_header}, $cname, $cname;

		if (${$cl}{descr} && @{${$cl}{descr}} >= 0) {
			print_desc(${$cl}{descr}, 2);
		} else {
			die "did NOT print $cname description\n";
		}

		if ( $#{${$cl}{constructors}} >= 0) {
			for my $c (@{${$cl}{constructors}}) {
				function_descr($c,3);
			}
		}

		if ( $#{${$cl}{methods}} >= 0) {
			for my $m (@{${$cl}{methods}}) {
				function_descr($m, 3);
			}
		}

		if ( $#{${$cl}{attributes}} >= 0) {
			for my $a (@{${$cl}{attributes}}) {
				my $a_id = ${$a}{name};
				$a_id =~ s/[^a-zA-Z0-9]/_/g;
				printf D ${$template_ref}{class_attr_header}, $a_id, ${$a}{name};
				if (${$a}{descr} && @{${$a}{descr}} >= 0) {
					print_desc(${$a}{descr}, 3);
				} else {
					die "did not print $a_id description\n";
				}
				printf D ${$template_ref}{class_attr_footer}, ${$a}{name}, ${$a}{name};

			}
		}

		if (exists ${$template_ref}{class_footer}) {
			printf D ${$template_ref}{class_footer}, $cname, $cname;
		}

	}

	if ($#functions >= 0) {
		printf D ${$template_ref}{global_functions_header}, $module{name};

		for my $f (@functions) {
			function_descr($f, 3);
		}

		print D ${$template_ref}{global_functions_footer};
	}

	printf D ${$template_ref}{module_footer}, $module{name};

	close D;

	%module = ();
	%classes = ();
	$class = undef;
	$function = undef;
	@functions = ();
	$docfile = 0;

}

sub function_descr {
	my $f = $_[0];
	my $indent = $_[1];
	my $section_name = 'UNKNOWN';

	my $arglist = '';

	for (@{ ${$f}{arglist} }) {
		my $a = $_;
		$a =~ tr/A-Z/a-z/;
		$arglist .= "$a, ";
	}

	$arglist =~ s/, $//;
	$section_name =  "${$f}{name}($arglist)";
	$section_name =~ s/[^a-zA-Z0-9]/_/g;

	printf D ${$template_ref}{function_header}, $section_name , "${$f}{name}($arglist)";

	my @desc = ${$f}{descr};
	if ($#desc >= 0) {
		print_desc(@desc, $indent);
	}

	print D ${$template_ref}{function_args_header} if $#{${$f}{arglist}} >= 0;

	for my $argname (@{${$f}{arglist}}) {
		my $arg = ${${$f}{args}}{$argname};
		$argname =~ tr/A-Z/a-z/;
		$argname =~ s/\[(.*)\]/$1 (optional)/;

		printf D ${$template_ref}{function_arg_header}, $argname, $argname;
		my @desc = ${$arg}{descr};
		if ($#desc >= 0) {
			print_desc(@desc, $indent+2);
		}

		if ( $#{${$arg}{errors}} >= 0) {
			printf D ${$template_ref}{function_argerror_header}, $argname, $argname;
			printf D ${$template_ref}{function_argerror}, $_, $_ for @{${$arg}{errors}};
			printf D ${$template_ref}{function_argerror_footer}, $argname, $argname;
		}

		printf D ${$template_ref}{function_arg_footer}, $argname, $argname;

	}

	print D ${$template_ref}{function_args_footer} if $#{${$f}{arglist}} >= 0;

	if ( $#{${$f}{returns}} >= 0) {
		printf D ${$template_ref}{function_returns_header}, ${$f}{name};
		printf D ${$template_ref}{function_returns}, $_ for @{${$f}{returns}};
		printf D ${$template_ref}{function_returns_footer}, ${$f}{name};
	}

	if ( $#{${$f}{errors}} >= 0) {
		my $sname = exists ${$f}{section_name} ? ${$f}{section_name} : ${$f}{name};

		printf D ${$template_ref}{function_errors_header}, $sname;
		printf D ${$template_ref}{function_errors}, $_ for @{${$f}{errors}};
		printf D ${$template_ref}{function_errors_footer}, ${$f}{name};
	}

	printf D ${$template_ref}{function_footer}, $section_name;

}
