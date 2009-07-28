###################################################
# Common Samba4 functions
# Copyright jelmer@samba.org 2006
# released under the GNU GPL

package Parse::Pidl::Samba4;

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(is_intree choose_header NumStars ElementStars ArrayBrackets DeclLong ArrayDynamicallyAllocated);

use Parse::Pidl::Util qw(has_property is_constant);
use Parse::Pidl::NDR qw(GetNextLevel);
use Parse::Pidl::Typelist qw(mapTypeName scalar_is_reference);
use Parse::Pidl qw(fatal error);
use strict;

use vars qw($VERSION);
$VERSION = '0.01';

sub is_intree()
{
	my $srcdir = $ENV{srcdir};
	$srcdir = $srcdir ? "$srcdir/" : "";
	return 4 if (-f "${srcdir}kdc/kdc.c");
	return 3 if (-f "${srcdir}include/smb.h");
	return 0;
}

# Return an #include line depending on whether this build is an in-tree
# build or not.
sub choose_header($$)
{
	my ($in,$out) = @_;
	return "#include \"$in\"" if (is_intree());
	return "#include <$out>";
}

sub ArrayDynamicallyAllocated($$)
{
	my ($e, $l) = @_;
	die("Not an array") unless ($l->{TYPE} eq "ARRAY");
	return 0 if ($l->{IS_FIXED} and not has_property($e, "charset"));
	return 1;
}

sub NumStars($;$)
{
	my ($e, $d) = @_;
	$d = 0 unless defined($d);
	my $n = 0;

	foreach my $l (@{$e->{LEVELS}}) {
		next unless ($l->{TYPE} eq "POINTER");

		my $nl = GetNextLevel($e, $l);
		next if (defined($nl) and $nl->{TYPE} eq "ARRAY");

		$n++;
	}

	if ($n >= 1) {
		$n-- if (scalar_is_reference($e->{TYPE}));
	}

	foreach my $l (@{$e->{LEVELS}}) {
		next unless ($l->{TYPE} eq "ARRAY");
		next unless (ArrayDynamicallyAllocated($e, $l));
		$n++;
	}

	error($e->{ORIGINAL}, "Too few pointers $n < $d") if ($n < $d);

	$n -= $d;

	return $n;
}

sub ElementStars($;$)
{
	my ($e, $d) = @_;
	my $res = "";
	my $n = 0;

	$n = NumStars($e, $d);
	$res .= "*" foreach (1..$n);

	return $res;
}

sub ArrayBrackets($)
{
	my ($e) = @_;
	my $res = "";

	foreach my $l (@{$e->{LEVELS}}) {
		next unless ($l->{TYPE} eq "ARRAY");
		next if ArrayDynamicallyAllocated($e, $l);
		$res .= "[$l->{SIZE_IS}]";
	}

	return $res;
}

sub DeclLong($)
{
	my ($e) = shift;
	my $res = "";

	if (has_property($e, "represent_as")) {
		$res .= mapTypeName($e->{PROPERTIES}->{represent_as})." ";
	} else {
		if (has_property($e, "charset")) {
			$res .= "const char ";
		} else {
			$res .= mapTypeName($e->{TYPE})." ";
		}

		$res .= ElementStars($e);
	}
	$res .= $e->{NAME};
	$res .= ArrayBrackets($e);

	return $res;
}

1;
