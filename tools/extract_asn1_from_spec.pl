#!/usr/bin/perl
# This script extracts the ASN1 definition from and TS 36.331 and generates 3 output files that can be processed by asn2wrs
# First download the specification from 3gpp.org as a word document and open it
# Then in "view" menu, select normal or web layout (needed to removed page header and footers)
# Finally save the document as a text file
# Call the script: "perl extract_asn1 36331-xxx.txt"
# It should generate: EUTRA-RRC-Definitions.asn, EUTRA-UE-Variables.asn and EUTRA-InterNodeDefinitions
use warnings;
$input_file = $ARGV[0];
$def_output_file = "EUTRA-RRC-Definitions.asn";
$var_output_file = "EUTRA-UE-Variables.asn";
$internode_output_file = "EUTRA-InterNodeDefinitions.asn";

sub extract_asn1;

open(INPUT_FILE, "< $input_file") or die "Can not open file $input_file";

while (<INPUT_FILE>) {
  # Process the EUTRA-RRC-Definitions section
  if( m/EUTRA-RRC-Definitions DEFINITIONS AUTOMATIC TAGS ::=/){
    open(OUTPUT_FILE, "> $def_output_file") or die "Can not open file $def_output_file";
    syswrite OUTPUT_FILE,"$_ \n";
    syswrite OUTPUT_FILE,"BEGIN\n\n";

    # Get all the text delimited by -- ASN1START and -- ASN1STOP
    extract_asn1();

    syswrite OUTPUT_FILE,"END\n\n";
    close(OUTPUT_FILE);
  }

  # Process the EUTRA-RRC-Variables section
  if( m/EUTRA-UE-Variables DEFINITIONS AUTOMATIC TAGS ::=/){
    open(OUTPUT_FILE, "> $var_output_file") or die "Can not open file $def_output_file";
    syswrite OUTPUT_FILE,"$_ \n";
    syswrite OUTPUT_FILE,"BEGIN\n\n";

    # Get all the text delimited by -- ASN1START and -- ASN1STOP
    extract_asn1();

    syswrite OUTPUT_FILE,"END\n\n";
    close(OUTPUT_FILE);
  }
  # Process the EUTRA-InterNodeDefinitions section
  if( m/EUTRA-InterNodeDefinitions DEFINITIONS AUTOMATIC TAGS ::=/){
    open(OUTPUT_FILE, "> $internode_output_file") or die "Can not open file $def_output_file";
    syswrite OUTPUT_FILE,"$_ \n";
    syswrite OUTPUT_FILE,"BEGIN\n\n";

    # Get all the text delimited by -- ASN1START and -- ASN1STOP
    extract_asn1();

    syswrite OUTPUT_FILE,"END\n\n";
    close(OUTPUT_FILE);
  }
}

close(INPUT_FILE);

# This subroutine copies the text delimited by -- ASN1START and -- ASN1STOP in INPUT_FILE
# and copies it into OUTPUT_FILE.
# It stops when it meets the keyword "END"
sub extract_asn1 {
  my $line = <INPUT_FILE>;
  my $is_asn1 = 0;

  while(($line ne "END\n") && ($line ne "END\r\n")){
    if ($line =~ m/-- ASN1STOP/) {
      $is_asn1 = 0;
    }
    if ($is_asn1 == 1){
      syswrite OUTPUT_FILE,"$line";
    }
    if ($line =~ m/-- ASN1START/) {
      $is_asn1 = 1;
    }
    $line = <INPUT_FILE>;
  }
}
