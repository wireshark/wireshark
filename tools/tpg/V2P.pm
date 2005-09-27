#!/usr/bin/perl
#
#  a function that prints a complex variable such that the output is a
# valid perl representation of that variable (does not handle blessed objects)
#
# (c) 2002, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
#
# $Id $
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@ethereal.com>
# Copyright 2004 Gerald Combs
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

package V2P;
use strict;


my $_v2p_columns = 120;

sub var2perl { # converts a complex variable reference into perl code
	__v2p(0,@_);
}

sub __v2p {
    my $d = shift ;
    my $i = '';
    my $buf = '';
    
    if ( $d gt 0) {
        $i .= " " for (0..$d);
    }
    
    if (scalar @_ <= 1) {
        my $what = ref $_[0];
#~ print "! $_[0] '$what'\n";
        
        if ( $what ) {
            if ($what eq 'ARRAY') {
                $buf .=  "[\n";
                $buf .=  "$i " . __v2p($d+1,$_) . ",\n" for (@{$_[0]});
                $buf =~ s/,\n$//msi;
                    $buf .= "\n$i]\n";
            }
            elsif ($what eq 'HASH') {
                $buf .=  "{\n";
                $buf .=   "$i " . __v2p($d+1,$_) . " =>" . __v2p($d+1,${$_[0]}{$_}) . ",\n" for (keys %{$_[0]});
                $buf =~ s/,\n$//msi;
                    $buf .=  "\n$i}\n";
            }
            elsif ($what eq 'SCALAR') {
                $buf .=  "\\" . __v2p($d+1,$_[0]);
            }
            elsif ($what eq 'REF') {
                $buf .=  "\\" . __v2p($d+1,\$_);
            }
            elsif ($what eq 'GLOB') {
                $buf .=  "*" . __v2p($d+1,\$_);
            }
            elsif ($what eq 'LVALUE') {
                $buf .=  'lvalue';
            }
            elsif ($what eq 'CODE') {
                $buf .=  'sub { "sorry I cannot do perl code"; }';
            }
            else {
                $buf .=  "what's '$what'?";
            }
        } else {
            return "undef" unless defined $_[0];
            return "''" if $_[0] eq '';
            return "'$_[0]'" unless $_[0]=~ /^[0-9]+[\.][0-9]*?$/
                or $_[0]=~ /^[0-9]+$/
                or $_[0]=~ /^[0-9]*[\.][0-9]+?$/;
            return $_[0];
        }
    } else {
        $buf = $i . "( ";
        $buf .= "$i , " .  __v2p($d+1,$_) for (@_);
        $buf .= " )\n";
        $buf =~ s/^\( , /\( /;
    }

$buf =~ s/\n,/,/msg;
if (length $buf < $_v2p_columns)  {
    $buf =~ s/\n//msg;
    $buf =~ s/$i//msg;
    $buf = $i . $buf;
}
return $buf;
}

1;
