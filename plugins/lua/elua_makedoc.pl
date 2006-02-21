#!/usr/bin/perl
#
# elua_makedoc.pl
# Reference Manual Generator
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
use V2P;

sub deb {
#warn $_[0] if $_[0] =~ /^>e/;
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
	function_header => "=== %s ===\n",
	function_descr => "%s\n",
	function_arg_header => "==== %s ====\n",
	function_arg_descr => "%s\n",
	function_argerror => "  * %s\n",
	function_returns_header => "==== returns ====\n",
	function_returns => "  * %s\n",
	function_errors_header => "==== errors ====\n",
	function_errors => "  * %s\n",
	non_method_functions_header => "= Non method functions =\n",
	
}};


my @control = (
			
[ 'ELUA_CLASS_DEFINE\050\s*([A-Z][a-zA-Z]+)\s*,[^\051]*\051\s*(/\*(.*?)\*/)?',
	sub {
		deb ">c=$1=$2=$3=$4=$5=$6=$7=\n";
		$class = { name => $1, descr=> $3, constructors => [], methods => [] };
		$classes{$1} = $class;
	}],

[ 'ELUA_FUNCTION\s+elua_([a-z_]+)[^\173]*\173\s*(/\*(.*?)\*/)?',
	sub {
		deb ">f=$1=$2=$3=$4=$5=$6=$7=\n";
		$function = { returns => [], arglist => [], args => {}, name => $1, descr => $3, type => 'standalone' };
		push @functions, $function;
	} ] ,

[ 'ELUA_CONSTRUCTOR\s+([A-Za-z]+)_([a-z_]+)[^\173]*\173\s*(/\*(.*?)\*/)?',
	sub {
		deb ">cc=$1=$2=$3=$4=$5=$6=$7=\n";
		$function = { returns => [], arglist => [], args => {}, name => "$1.$2", descr => $4, type => 'constructor' };
		push @{${$class}{constructors}}, $function;
	} ] ,

[ 'ELUA_METHOD\s+([A-Za-z]+)_([a-z_]+)[^\173]*\173\s*(/\*(.*?)\*/)?',
	sub {
		deb ">cm=$1=$2=$3=$4=$5=$6=$7=\n";
		$function = { returns => [], arglist => [], args => {}, name => "$1:$2", descr => $4, type => 'method' };
		push @{${$class}{methods}}, $function;
	} ] ,

[ '#define ELUA_(OPT)?ARG_([a-z_]+)_([A-Z0-9]+)\s+\d+\s*(/\*(.*?)\*/)?',
	sub {
		deb ">a=$1=$2=$3=$4=$5=$6=$7=\n";
		push @{${$function}{arglist}} , $3;
		${${$function}{args}}{$3} = {descr=>$5}
	} ],

[ '#define ELUA_(OPT)?ARG_([A-Za-z]+)_([a-z_]+)_([A-Z0-9]+)\s+\d+\s*(/\*(.*?)\*/)?',
	sub {
		deb ">ca=$1=$2=$3=$4=$5=$6=$7=\n";
		push @{${$function}{arglist}} , $4;
		${${$function}{args}}{$4} = {descr=>$6}
	} ],

[ 'ELUA_(FINAL_)?RETURN\050\s*.*?\s*\051\s*;\s*(/\*(.*?)\*/)?',
	sub { 
		deb ">fr=$1=$2=$3=$4=$5=$6=$7=\n";
		push @{${$function}{returns}} , $3 if $3 ne '';
	} ],

[ 'ELUA_(OPT)?ARG_ERROR\s*\050\s*(([A-Z][A-Za-z]+)_)?([a-z_]+)\s*,\s*([A-Z0-9]+)\s*,\s*"([^"]*)"',
	sub {
		deb ">ae=$1=$2=$3=$4=$5=$6=$7=\n";
		my $errors;
		unless (exists ${${${$function}{args}}{$5}}{errors}) {
			$errors =  ${${${$function}{args}}{$5}}{errors} = [];
		} else {
			$errors = ${${${$function}{args}}{$5}}{errors};
		}
		
		push @{$errors}, $6;
	} ] ,
 [ 'ELUA_ERROR\s*\050\s*(([A-Z][A-Za-z]+)_)?([a-z_]+),"([^"]*)"',
	sub { 
		deb ">e=$1=$2=$3=$4=$5=$6=$7=\n";
		my $errors;
		unless (exists ${$function}{errors}) {
			$errors =  ${$function}{errors} = [];
		} else {
			$errors = ${$function}{errors};
		}
		
		push @{$errors}, $4;
		
	} ],

#[ 'ELUA_ATTR_GET\s+([A-Za-z]+)_get_([a-z_]+)[^\173]*\173\s*(/\*(.*?)\*/)?',
#	sub {  } ] ,
#[ 'ELUA_ATTR_SET\s+([A-Za-z]+)_set_([a-z_]+)[^\173]*\173\s*(/\*(.*?)\*/)?',
#	sub {  } ] ,
#['(.*?\n)',
#	sub { print "--->$1" } ],
);
my $file;
while ( $file =  shift) {
	
	my $docfile = $file;
	$docfile =~ s/\.c$/.pod/;
	
	open C, "< $file";
	open D, "> doc/$docfile";
	
	my $b = '';
	LINE: while (<C>) {
		$b .= $_;
		for (@control) {
			my ($re,$f) = @{$_};
			while ( $b =~ s/$re//ms ) {
					&{$f}();
					next LINE;
			}
		}
	}

	for my $cname (sort keys %classes) {
		my $class = $classes{$cname};
		printf D $template{class_header}, $cname;
		printf D $template{class_desc} , ${$class}{descr} if ${$class}{descr};
		
		if ( $#{${$class}{constructors}} >= 0) {
			printf D $template{class_constructors_header}, $cname;
			
			for my $c (@{${$class}{constructors}}) {
				function_descr($c);
			}

			printf D $template{class_constructors_footer}, $cname;
		}

		if ( $#{${$class}{methods}} >= 0) {
			printf D $template{class_methods_header}, $cname;
			
			for my $m (@{${$class}{methods}}) {
				function_descr($m);
			}
			
			printf D $template{class_methods_footer}, $cname;
		}
		
	}

	print D $template{non_method_functions_header};

	for my $f (@functions) {
		function_descr($f);
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
	my $arglist = '';
	
	for (@{ ${$f}{arglist} }) {
		my $a = $_;
		$a =~ tr/A-Z/a-z/;
		$arglist .= "$a, ";
	}
	
	$arglist =~ s/, $//;
		
	printf D $template{function_header}, "${$f}{name}($arglist)";
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
