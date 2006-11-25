###################################################
# Common Samba4 functions
# Copyright jelmer@samba.org 2006
# released under the GNU GPL

package Parse::Pidl::Samba4;

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(is_intree choose_header DeclLong DeclLong_cli IsUniqueOut);

use Parse::Pidl::Util qw(has_property is_constant);
use Parse::Pidl::Typelist qw(mapType scalar_is_reference);
use strict;

use vars qw($VERSION);
$VERSION = '0.01';

sub is_intree()
{
	return 4 if (-f "kdc/kdc.c");
	return 3 if (-f "include/smb.h");
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

sub IsUniqueOut($)
{
    my ($e) = shift;

    return grep(/out/, @{$e->{DIRECTION}}) &&
	((($e->{LEVELS}[0]->{TYPE} eq "POINTER") &&
	  ($e->{LEVELS}[0]->{POINTER_TYPE} eq "unique")) ||
	 ($e->{LEVELS}[0]->{TYPE} eq "ARRAY"));
}

sub DeclLong_int($$)
{
	my($element,$cli) = @_;
	my $ret = "";

	if (has_property($element, "represent_as")) {
		$ret.=mapType($element->{PROPERTIES}->{represent_as})." ";
	} else {
		if (has_property($element, "charset")) {
			$ret.="const char";
		} else {
			$ret.=mapType($element->{TYPE});
		}

		$ret.=" ";
		my $numstar = $element->{ORIGINAL}->{POINTERS};
		if ($numstar >= 1) {
			$numstar-- if scalar_is_reference($element->{TYPE});
		}
		foreach (@{$element->{ORIGINAL}->{ARRAY_LEN}})
		{
			next if is_constant($_) and 
				not has_property($element, "charset");
			$numstar++;
		}
		if ($cli && IsUniqueOut($element)) {
			$numstar++;
		}
		$ret.="*" foreach (1..$numstar);
	}
	$ret.=$element->{NAME};
	foreach (@{$element->{ARRAY_LEN}}) {
		next unless (is_constant($_) and not has_property($element, "charset"));
		$ret.="[$_]";
	}

	return $ret;
}

sub DeclLong($)
{
    return DeclLong_int($_, 0);
}

sub DeclLong_cli($)
{
    return DeclLong_int($_, 1);
}

1;
