#!/usr/bin/perl
#
# This script extracts the ASN1 definition from TS 36.331/36.355/25.331/38.331/37.355/36.413/38.413/36.423/38.423
# /38.463/38.473 , and generates asn files that can be processed by asn2wrs
# First download the specification from 3gpp.org as a word document and open it
# Then in "view" menu, select normal, draft or web layout (any kind that removes page header and footers)
# Finally save the document as a text file
# Example with TS 36.331: "perl extract_asn1_from_spec.pl 36331-xxx.txt"
# It should generate: EUTRA-RRC-Definitions.asn, EUTRA-UE-Variables.asn and EUTRA-InterNodeDefinitions
#
# Copyright 2011 Vincent Helfre and Erwan Yvin
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

use warnings;
$input_file = $ARGV[0];
$version = 0;

sub extract_spec_version;
sub extract_asn1;

open(INPUT_FILE, "< $input_file") or die "Can not open file $input_file";

extract_spec_version();

extract_asn1();

close(INPUT_FILE);

# This subroutine extracts the version of the specification
sub extract_spec_version {
  my $line;
  while($line = <INPUT_FILE>){
    if($line =~ m/3GPP TS ((25|36|38)\.331|(36|37)\.355|(36|38)\.413|(36|38)\.423|(36|38)\.455|38\.463|38\.473) V/){
      $version = $line;
      return;
    }
  }
}

# This subroutine copies the text delimited by -- ASN1START and -- ASN1STOP in INPUT_FILE
# and copies it into OUTPUT_FILE.
# The OUTPUT_FILE is opened on encounter of the keyword "DEFINITIONS AUTOMATIC TAGS"
# and closed on encounter of the keyword "END"
sub extract_asn1 {
  my $line;
  my $prev_line;
  my $is_asn1 = 0;
  my $output_file_name = 0;
  my $file_name_found = 0;

  while($line = <INPUT_FILE>){
    if ($line =~ m/-- ASN1STOP/) {
      $is_asn1 = 0;
    }

    if(($file_name_found == 0) && ($line =~ m/^LPP-Broadcast-Definitions/)){
      $output_file_name = "LPP-Broadcast-Definitions.asn";
      print  "generating $output_file_name\n";
      open(OUTPUT_FILE, "> $output_file_name") or die "Can not open file $output_file_name";
      $file_name_found = 1;
      syswrite OUTPUT_FILE,"-- "."$version"."\n";
    }

    if(($file_name_found == 0) && ($line =~ m/SonTransfer-IEs/)){
      $output_file_name = "S1AP-SonTransfer-IEs.asn";
      print  "generating $output_file_name\n";
      open(OUTPUT_FILE, "> $output_file_name") or die "Can not open file $output_file_name";
      $is_asn1 = 1;
      $file_name_found = 1;
      syswrite OUTPUT_FILE,"-- "."$version"."\n";
    }

    if(($file_name_found == 0) && ($line =~ m/itu-t \(0\) identified-organization \(4\) etsi \(0\) mobileDomain \(0\)/)){
      ($output_file_name) = ($prev_line =~ m/^([a-zA-Z0-9\-]+)\s/);
      $output_file_name = "$output_file_name".".asn";
      print  "generating $output_file_name\n";
      open(OUTPUT_FILE, "> $output_file_name") or die "Can not open file $output_file_name";
      $is_asn1 = 1;
      $file_name_found = 1;
      syswrite OUTPUT_FILE,"-- "."$version"."\n";
      syswrite OUTPUT_FILE,"$prev_line";
    }

    if(($file_name_found == 0) && ($line =~ m/DEFINITIONS AUTOMATIC TAGS ::=/)){
      ($output_file_name) = ($line =~ m/^([a-zA-Z0-9\-]+)\s+DEFINITIONS AUTOMATIC TAGS ::=/);
      $output_file_name = "$output_file_name".".asn";
      print  "generating $output_file_name\n";
      open(OUTPUT_FILE, "> $output_file_name") or die "Can not open file $output_file_name";
      $is_asn1 = 1;
      $file_name_found = 1;
      syswrite OUTPUT_FILE,"-- "."$version"."\n";
    }

    if (($line =~ /^END[\r\n]/) && (defined fileno OUTPUT_FILE)){
      syswrite OUTPUT_FILE,"$line";
      close(OUTPUT_FILE);
      $is_asn1 = 0;
      $file_name_found = 0;
    }

    if (($is_asn1 == 1) && (defined fileno OUTPUT_FILE)){
      syswrite OUTPUT_FILE,"$line";
    }

    if ($line =~ m/-- ASN1START/) {
      $is_asn1 = 1;
    }

    $prev_line = $line;
  }
}

