#!/usr/bin/perl
#
# elua_makedoc.pl
# ELUA's Reference Manual Generator
#
# (c) 2006, Luis E. Garcia Onatnon <luis.ontanon@gmail.com>
#
# $Id$
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@ethereal.com>
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# (-: I don't even think writing this in Lua  :-)

use strict;
#use V2P;

sub deb {
#	warn $_[0];
}

sub gorolla {
# a gorilla stays to a chimp like ... stays to chomp 
# but this one returns the shrugged string.
	my $s = shift;
	$s =~ s/^([\n]|\s)*//ms;
	$s =~ s/([\n]|\s)*$//ms;
	$s;
}

my $class;
my %classes;
my $function;
my @functions;

my %template = %{{
	class_header => "= %s =\n",
	class_desc => "%s\n",
	class_constructors_header => "== %s constructors ==\n",
	class_methods_header => "== %s methods ==\n",
	class_attributes_header => "== %s Attributes ==\n",
	class_attr_header => "=== %s ===\n",
	class_attr_descr => "%s\n",
	function_header => "=== %s ===\n",
	function_descr => "%s\n",
	function_arg_header => "==== %s ====\n",
	function_arg_descr => "%s\n",
	function_argerrors_header => "'''Errors:'''\n",
	function_argerror => "  * %s\n",
	function_returns_header => "==== returns ====\n",
	function_returns => "  * %s\n",
	function_errors_header => "==== errors ====\n",
	function_errors => "  * %s\n",
	non_method_functions_header => "= Non method functions =\n",
}};


my %metamethods = %{{
	__tostring => "tostring(__)",
	__index => "__[]",
	__newindex => "__[] = ",
	__add => "__ + __",
	__sub => "__ - __",
	__mul => "__ * __",
	__div => "__ / __",
	__mod => "__ % __",
	__pow => "__ ^ __",
	__unm => "-___",
	__concat => "__ .. __",
	__len => "#__",
	__call => "()",
	__eq => "__ == __",
	__lt => "__ < __",
	__le => "__ <= __",
}};

# It's said that only perl can parse perl... my editor isn't perl...
# if unencoded this causes my editor's autoindent to bail out so I encoded in octal
# XXX: support \" within "" 
my $QUOTED_RE = "\042\050\133^\042\135*\051\042";

my $TRAILING_COMMENT_RE = '((\s*|[\n\r]*)/\*(.*?)\*/)?';

my @control =
(
# This will be scanned in order trying to match the re if it matches
# the body will be executed immediatelly after. 
 
 [ 'ELUA_CLASS_DEFINE\050\s*([A-Z][a-zA-Z]+)\s*,.*?\051' . $TRAILING_COMMENT_RE,
sub {
	deb ">c=$1=$2=$3=$4=$5=$6=$7=\n";
	$class = {
		name => $1,
		descr=> gorolla($4),
		constructors => [],
		methods => [],
		metamethods => [],
		attributes => []
	};
	$classes{$1} = $class;
}],

[ 'ELUA_FUNCTION\s+elua_([a-z_]+)[^\173]*\173' . $TRAILING_COMMENT_RE,
sub {
	deb ">f=$1=$2=$3=$4=$5=$6=$7=\n";
	$function = {
		returns => [],
		arglist => [],
		args => {},
		name => $1,
		descr => gorolla($4),
		type => 'standalone'
	};
	push @functions, $function;
} ] ,

[ 'ELUA_CONSTRUCTOR\s+([A-Za-z]+)_([a-z_]+).*?\173' . $TRAILING_COMMENT_RE,
sub {
	deb ">cc=$1=$2=$3=$4=$5=$6=$7=\n";
	$function = {
		returns => [],
		arglist => [],
		args => {},
		name => "$1.$2",
		descr => gorolla($5),
		type => 'constructor'
	};
	push @{${$class}{constructors}}, $function;
} ] ,

[ 'ELUA_METHOD\s+([A-Za-z]+)_([a-z_]+)[^\173]*\173' . $TRAILING_COMMENT_RE,
	sub {
		deb ">cm=$1=$2=$3=$4=$5=$6=$7=\n";
		$function = {
			returns => [],
			arglist => [],
			args => {},
			name => "$1:$2",
			descr => gorolla($5),
			type => 'method'
		};
		push @{${$class}{methods}}, $function;
	} ] ,

[ 'ELUA_METAMETHOD\s+([A-Za-z]+)(__[a-z]+)[^\173]*\173' . $TRAILING_COMMENT_RE,
	sub {
		deb ">cm=$1=$2=$3=$4=$5=$6=$7=\n";
		my $name = $metamethods{$2};
		my ($c,$d) = ($1,$5);
		$name =~ s/__/$c/g;
		$function = {
			returns => [],
			arglist => [],
			args => {},
			name => $name,
			descr => gorolla($d),
			type => 'metamethod'
		};
		push @{${$class}{metamethods}}, $function;
	} ] ,

[ '#define ELUA_(OPT)?ARG_([a-z_]+)_([A-Z0-9]+)\s+\d+' . $TRAILING_COMMENT_RE,
sub {
	deb ">a=$1=$2=$3=$4=$5=$6=$7=\n";
	push @{${$function}{arglist}} , $3;
	${${$function}{args}}{$3} = {descr=>$6}
} ],

[ '#define ELUA_(OPT)?ARG_([A-Za-z]+)_([a-z_]+)_([A-Z0-9]+)\s+\d+' . $TRAILING_COMMENT_RE,
sub {
	deb ">ca=$1=$2=$3=$4=$5=$6=$7=\n";
	push @{${$function}{arglist}} , $4;
	${${$function}{args}}{$4} = {descr=>$7}
} ],

[ '/\052\s+ELUA_ATTRIBUTE\s+([A-Za-z]+)_([a-z_]+)\s+([A-Z]*)\s*(.*?)\052/',
	sub {
		deb ">at=$1=$2=$3=$4=$5=$6=$7=\n";
		push @{${$class}{attributes}}, { name => $2, descr => gorolla($4), mode=>$3 };
	} ],

[ '/\052\s+ELUA_MOREARGS\s+([A-Za-z_]+)\s+(.*?)\052/',
	sub {
		deb ">ma=$1=$2=$3=$4=$5=$6=$7=\n";
		push @{${$function}{arglist}} , "...";
		${${$function}{args}}{"..."} = {descr=>gorolla($2)}
	} ],

[ 'ELUA_(FINAL_)?RETURN\050\s*.*?\s*\051\s*;' . $TRAILING_COMMENT_RE,
sub { 
	deb ">fr=$1=$2=$3=$4=$5=$6=$7=\n";
	push @{${$function}{returns}} , gorolla($4) if $4 ne '';
} ],

[ 'ELUA_ERROR\s*\050\s*(([A-Z][A-Za-z]+)_)?([a-z_]+),' . $QUOTED_RE ,
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

[ 'ELUA_(OPT)?ARG_ERROR\s*\050\s*(([A-Z][A-Za-z]+)_)?([a-z_]+)\s*,\s*([A-Z0-9]+)\s*,\s*' . $QUOTED_RE,
	sub {
		deb ">ae=$1=$2=$3=$4=$5=$6=$7=\n";
		my $errors;
		unless (exists ${${${$function}{args}}{$5}}{errors}) {
			$errors =  ${${${$function}{args}}{$5}}{errors} = [];
		} else {
			$errors = ${${${$function}{args}}{$5}}{errors};
		}
		
		push @{$errors}, gorolla($6);
	} ] ,
);

my $anymatch = '(^ThIsWiLlNeVeRmAtCh$';
for (@control) {
	$anymatch .= "|${$_}[0]";
}
$anymatch .= ')';

# for each file given in the command line args
my $file;
while ( $file =  shift) {

	next unless -f $file;
	
	my $docfile = $file;
	$docfile =~ s/\.c$/.pod/;
	
	open C, "< $file";
	open D, "> doc/$docfile";
	
	my $b = '';
	$b .= $_ while (<C>);

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

	for my $cname (sort keys %classes) {
		my $cl = $classes{$cname};
		printf D $template{class_header}, $cname;
		printf D $template{class_desc} , ${$cl}{descr} if ${$cl}{descr};
		
		if ( $#{${$cl}{constructors}} >= 0) {
			printf D $template{class_constructors_header}, $cname;
			
			for my $c (@{${$cl}{constructors}}) {
				function_descr($c);
			}

			printf D $template{class_constructors_footer}, $cname;
		}

		if ( $#{${$cl}{methods}} >= 0) {
			printf D $template{class_methods_header}, $cname;
			
			for my $m (@{${$cl}{methods}}) {
				function_descr($m);
			}
			
			printf D $template{class_methods_footer}, $cname;
		}
		
		if ( $#{${$cl}{metamethods}} >= 0) {
			printf D $template{class_metamethods_header}, $cname;
			
			for my $m (@{${$cl}{metamethods}}) {
				function_descr($m,${$m}{name});
			}
			
			printf D $template{class_metamethods_footer}, $cname;
		}
		
		if ( $#{${$cl}{attributes}} >= 0) {
			printf D $template{class_attributes_header}, $cname;
			
			for my $a (@{${$cl}{attributes}}) {
				printf D $template{class_attr_header}, ${$a}{name};
				printf D $template{class_attr_descr}, ${$a}{descr} if ${$a}{descr};
				printf D $template{class_attr_footer}, ${$a}{name};
				
			}
			
			printf D $template{class_attributes_footer}, $cname;
		}
	}

	if ($#functions >= 0) {
		print D $template{non_method_functions_header};

		for my $f (@functions) {
			function_descr($f);
		}
	}

	%classes = ();
	$class = undef;
	$function = undef;
	@functions = ();
	close C;
	close D;
}

sub function_descr {
	my $f = $_[0];
	my $label = $_[1];
	
	if (defined $label ) {
		printf D $template{function_header}, $label;
	} else {
		my $arglist = '';
		
		for (@{ ${$f}{arglist} }) {
			my $a = $_;
			$a =~ tr/A-Z/a-z/;
			$arglist .= "$a, ";
		}
		
		$arglist =~ s/, $//;
		
		printf D $template{function_header}, "${$f}{name}($arglist)";
	}	
	
	printf D $template{function_descr}, ${$f}{descr} if ${$f}{descr};
	
	for my $argname (@{${$f}{arglist}}) {
		my $arg = ${${$f}{args}}{$argname};
		$argname =~ tr/A-Z/a-z/;
		
		printf D $template{function_arg_header}, $argname;
		printf D $template{function_arg_descr}, ${$arg}{descr} if ${$arg}{descr};

		if ( $#{${$arg}{errors}} >= 0) {
			printf D $template{function_argerrors_header}, $argname;
			printf D $template{function_argerror}, $_ for @{${$arg}{errors}};
			printf D $template{function_argerrors_footer}, $argname;
		}
	
	}
	
	if ( $#{${$f}{returns}} >= 0) {
		printf D $template{function_returns_header}, ${$f}{name};
		printf D $template{function_returns}, $_ for @{${$f}{returns}};
		printf D $template{function_returns_footer}, ${$f}{name};
	}	

	if ( $#{${$f}{errors}} >= 0) {
		printf D $template{function_errors_header}, ${$f}{name};
		printf D $template{function_errors}, $_ for @{${$f}{errors}};
		printf D $template{function_errors_footer}, ${$f}{name};
	}	
	
}
