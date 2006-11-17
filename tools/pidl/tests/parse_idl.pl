#!/usr/bin/perl
# Some simple tests for pidls parsing routines
# (C) 2005 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;

use Test::More tests => 59;
use FindBin qw($RealBin);
use lib "$RealBin/../lib";
use Parse::Pidl::IDL;
use Parse::Pidl::NDR;

sub testok($$)
{
	my ($name, $data) = @_;
	
	my $pidl = Parse::Pidl::IDL::parse_string($data, "<$name>");
	
	ok (defined($pidl), $name);
	return $pidl
}

sub testfail($$)
{
	my ($name, $data) = @_;
	
	my $pidl = Parse::Pidl::IDL::parse_string($data, "<$name>");
	
	ok ((not defined $pidl), $name);
}

testfail "unknowntag", "bla test {};";
testok "test1", "interface test { void Test(); }; ";
testok "voidtest", "interface test { int Testx(void); }; ";
testfail "voidtest", "interface test { Test(); }; ";
testok "argtest", "interface test { int Test(int a, long b, uint32 c); }; ";
testok "array1", "interface test { int Test(int a[]); };";
testok "array2", "interface test { int Test(int a[2]); };";
testok "array3", "interface test { int Test(int a[b]); };";
testfail "array4", "interface test { int Test(int[] a); };";
testok "ptr1", "interface test { int Test(int *a); };";
testok "ptr2", "interface test { int Test(int **a); };";
testok "ptr3", "interface test { int Test(int ***a); };";
testfail "empty1", "interface test { };";
testfail "empty2", "";
testok "attr1", "[uuid(\"myuuid\"),attr] interface test { int Test(int ***a); };";
testok "attr2", "interface test { [public] int Test(); };";
testok "attr3", "[attr1] [attr2] interface test { [public] int Test(); };";
testok "multfn", "interface test { int test1(); int test2(); };";
testok "multif", "interface test { int test1(); }; interface test2 { int test2(); };";
testok "tdstruct1", "interface test { typedef struct { } foo; };";
testok "tdstruct2", "interface test { typedef struct { int a; } foo; };";
testok "tdstruct3", "interface test { typedef struct { int a; int b; } foo; };";
testfail "tdstruct4", "interface test { typedef struct { int a, int b; } foo; };";
testok "struct1", "interface test { struct x { }; };";
testok "struct2", "interface test { struct x { int a; }; };";
testok "struct3", "interface test { struct x { int a; int b; }; };";
testfail "struct4", "interface test { struct x { int a, int b; }; };";
testfail "struct5", "interface test { struct { int a; } x; };";
testok "tdunion1", "interface test { typedef union { } a; };";
testok "tdunion2", "interface test { typedef union { int a; } a; };";
testok "union1", "interface test { union a { }; };";
testok "union2", "interface test { union x { int a; }; };";
testfail "union3", "interface test { union { int a; } x; };";
testok "typedef1", "interface test { typedef int a; };";
testfail "typedef2", "interface test { typedef x; };";
testok "tdenum1", "interface test { typedef enum { A=1, B=2, C} a; };";
testok "enum1", "interface test { enum a { A=1, B=2, C}; };";
testfail "enum2", "interface test { enum { A=1, B=2, C} a; };";
testok "nested1", "interface test { struct x { struct { int a; } z; }; };";
testok "nested2", "interface test { struct x { struct y { int a; } z; }; };";
testok "bitmap1", "interface test { bitmap x { a=1 }; };";
testok "unsigned", "interface test { struct x { unsigned short y; }; };";
testok "signed", "interface test { struct x { signed short y; }; };";
testok "declarg", "interface test { void test(struct { int x; } a); };";
testok "structqual", "interface test { struct x { struct y z; }; };";
testok "unionqual", "interface test { struct x { union y z; }; };";
testok "enumqual", "interface test { struct x { enum y z; }; };";
testok "bitmapqual", "interface test { struct x { bitmap y z; }; };";
testok "emptystructdecl", "interface test { struct x; };";
testok "emptyenumdecl", "interface test { enum x; };";
testok "emptytdstructdecl", "interface test { typedef struct x y; };";
testok "import", "import \"foo.idl\";";
testok "include", "include \"foo.h\";";
testfail "import-noquotes", "import foo.idl;";
testfail "include-noquotes", "include foo.idl;";
testok "importlib", "importlib \"foo.idl\";";
testfail "import-nosemicolon", "import \"foo.idl\"";
testok "import-multiple", "import \"foo.idl\", \"bar.idl\";";
testok "include-multiple", "include \"foo.idl\", \"bar.idl\";";
