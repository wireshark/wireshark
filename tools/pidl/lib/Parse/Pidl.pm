###################################################
# package to parse IDL files and generate code for
# rpc functions in Samba
# Copyright tridge@samba.org 2000-2003
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl;

require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(warning error fatal $VERSION);

use strict;

use vars qw ( $VERSION );

$VERSION = '0.02';

sub warning
{
	my ($l,$m) = @_;
	if ($l) {
		print STDERR "$l->{FILE}:$l->{LINE}: ";
	}
	print STDERR "warning: $m\n";
}

sub error
{
	my ($l,$m) = @_;
	if ($l) {
		print STDERR "$l->{FILE}:$l->{LINE}: ";
	}
	print STDERR "error: $m\n";
}

sub fatal($$) 
{ 
    my ($e,$s) = @_; 
    die("$e->{FILE}:$e->{LINE}: $s\n"); 
}

1;
