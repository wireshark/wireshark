###################################################
# parse an ethereal conformance file
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Ethereal::Conformance;

require Exporter;

@ISA = qw(Exporter);
@EXPORT_OK = qw(ReadConformance);

use strict;

use Parse::Pidl::Util qw(has_property);

sub handle_type($$$$$$$$$$)
{
	my ($pos,$data,$name,$dissectorname,$ft_type,$base_type,$mask,$valsstring,$alignment) = @_;

	unless(defined($alignment)) {
		print "$pos: error incomplete TYPE command\n";
		return;
	}

	unless ($dissectorname =~ /.*dissect_.*/) {
		print "$pos: warning: dissector name does not contain `dissect'\n";
	}

	unless(valid_ft_type($ft_type)) {
		print "$pos: warning: invalid FT_TYPE `$ft_type'\n";
	}

	unless (valid_base_type($base_type)) {
		print "$pos: warning: invalid BASE_TYPE `$base_type'\n";
	}

	$data->{types}->{$name} = {
		NAME => $name,
		POS => $pos,
		USED => 0,
		DISSECTOR_NAME => $dissectorname,
		FT_TYPE => $ft_type,
		BASE_TYPE => $base_type,
		MASK => $mask,
		VALSSTRING => $valsstring,
		ALIGNMENT => $alignment
	};
}

sub handle_hf_rename($$$$)
{
	my ($pos,$data,$old,$new) = @_;

	unless(defined($new)) {
		print "$pos: error incomplete HF_RENAME command\n";
		return;
	}

	$data->{hf_renames}->{$old} = {
		OLDNAME => $old,
		NEWNAME => $new,
		POS => $pos,
		USED => 0
	};
}

sub handle_param_value($$$$)
{
	my ($pos,$data,$dissector_name,$value) = @_;

	unless(defined($value)) {
		print "$pos: error: incomplete PARAM_VALUE command\n";
		return;
	}

	$data->{dissectorparams}->{$dissector_name} = {
		DISSECTOR => $dissector_name,
		PARAM => $value,
		POS => $pos,
		USED => 0
	};
}

sub valid_base_type($)
{
	my $t = shift;
	return 0 unless($t =~ /^BASE_.*/);
	return 1;
}

sub valid_ft_type($)
{
	my $t = shift;
	return 0 unless($t =~ /^FT_.*/);
	return 1;
}

sub handle_hf_field($$$$$$$$$$)
{
	my ($pos,$data,$index,$name,$filter,$ft_type,$base_type,$valsstring,$mask,$blurb) = @_;

	unless(defined($blurb)) {
		print "$pos: error: incomplete HF_FIELD command\n";
		return;
	}

	unless(valid_ft_type($ft_type)) {
		print "$pos: warning: invalid FT_TYPE `$ft_type'\n";
	}

	unless(valid_base_type($base_type)) {
		print "$pos: warning: invalid BASE_TYPE `$base_type'\n";
	}

	$data->{header_fields}->{$index} = {
		INDEX => $index,
		POS => $pos,
		USED => 0,
		NAME => $name,
		FILTER => $filter,
		FT_TYPE => $ft_type,
		BASE_TYPE => $base_type,
		VALSSTRING => $valsstring,
		MASK => $mask,
		BLURB => $blurb
	};
}

sub handle_strip_prefix($$$)
{
	my ($pos,$data,$x) = @_;

	push (@{$data->{strip_prefixes}}, $x);
}

sub handle_noemit($$$)
{
	my ($pos,$data) = @_;
	my $type;

	$type = shift if ($#_ == 1);

	if (defined($type)) {
	    $data->{noemit}->{$type} = 1;
	} else {
	    $data->{noemit_dissector} = 1;
	}
}

sub handle_protocol($$$$$$)
{
	my ($pos, $data, $name, $longname, $shortname, $filtername) = @_;

	$data->{protocols}->{$name} = {
		LONGNAME => $longname,
		SHORTNAME => $shortname,
		FILTERNAME => $filtername
	};
}

sub handle_fielddescription($$$$)
{
	my ($pos,$data,$field,$desc) = @_;

	$data->{fielddescription}->{$field} = {
		DESCRIPTION => $desc,
		POS => $pos,
		USED => 0
	};
}

sub handle_import
{
	my $pos = shift @_;
	my $data = shift @_;
	my $dissectorname = shift @_;

	unless(defined($dissectorname)) {
		print "$pos: error: no dissectorname specified\n";
		return;
	}

	$data->{imports}->{$dissectorname} = {
		NAME => $dissectorname,
		DATA => join(' ', @_),
		USED => 0,
		POS => $pos
	};
}

my %field_handlers = (
	TYPE => \&handle_type,
	NOEMIT => \&handle_noemit, 
	PARAM_VALUE => \&handle_param_value, 
	HF_FIELD => \&handle_hf_field, 
	HF_RENAME => \&handle_hf_rename, 
	STRIP_PREFIX => \&handle_strip_prefix,
	PROTOCOL => \&handle_protocol,
	FIELD_DESCRIPTION => \&handle_fielddescription,
	IMPORT => \&handle_import
);

sub ReadConformance($$)
{
	my ($f,$data) = @_;

	$data->{override} = "";

	my $incodeblock = 0;

	open(IN,"<$f") or return undef;

	my $ln = 0;

	foreach (<IN>) {
		$ln++;
		next if (/^#.*$/);
		next if (/^$/);

		s/[\r\n]//g;

		if ($_ eq "CODE START") {
			$incodeblock = 1;
			next;
		} elsif ($incodeblock and $_ eq "CODE END") {
			$incodeblock = 0;
			next;
		} elsif ($incodeblock) {
			$data->{override}.="$_\n";
			next;
		}

		my @fields = /([^ "]+|"[^"]+")/g;

		my $cmd = $fields[0];

		shift @fields;

		if (not defined($field_handlers{$cmd})) {
			print "$f:$ln: Warning: Unknown command `$cmd'\n";
			next;
		}
		
		$field_handlers{$cmd}("$f:$ln", $data, @fields);
	}

	close(IN);
}

1;
