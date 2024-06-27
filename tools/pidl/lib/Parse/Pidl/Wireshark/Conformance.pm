###################################################
# parse an Wireshark conformance file
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

=pod

=head1 NAME

Parse::Pidl::Wireshark::Conformance - Conformance file parser for Wireshark

=head1 DESCRIPTION

This module supports parsing Wireshark conformance files (*.cnf).

=head1 FILE FORMAT

Pidl needs additional data for Wireshark output. This data is read from 
so-called conformance files. This section describes the format of these 
files.

Conformance files are simple text files with a single command on each line.
Empty lines and lines starting with a '#' character are ignored.
Arguments to commands are separated by spaces.

The following commands are currently supported:

=over 4

=item I<TYPE> name dissector ft_type base_type mask valsstring alignment

Register new data type with specified name, what dissector function to call 
and what properties to give header fields for elements of this type.

=item I<NOEMIT> type

Suppress emitting a dissect_type function for the specified type

=item I<PARAM_VALUE> type param

Set parameter to specify to dissector function for given type.

=item I<HF_FIELD> hf title filter ft_type base_type valsstring mask description

Generate a custom header field with specified properties.

=item I<HF_RENAME> old_hf_name new_hf_name

Force the use of new_hf_name when the parser generator was going to 
use old_hf_name.

This can be used in conjunction with HF_FIELD in order to make more than 
one element use the same filter name.

=item I<ETT_FIELD> ett

Register a custom ett field

=item I<STRIP_PREFIX> prefix

Remove the specified prefix from all function names (if present).

=item I<PROTOCOL> longname shortname filtername

Change the short-, long- and filter-name for the current interface in
Wireshark.

=item I<FIELD_DESCRIPTION> field desc

Change description for the specified header field. `field' is the hf name of the field.

=item I<IMPORT> dissector code...

Code to insert when generating the specified dissector. @HF@ and 
@PARAM@ will be substituted.

=item I<INCLUDE> filename

Include conformance data from the specified filename in the dissector.

=item I<TFS> hf_name "true string" "false string"

Override the text shown when a bitmap boolean value is enabled or disabled.

=item I<MANUAL> fn_name

Force pidl to not generate a particular function but allow the user 
to write a function manually. This can be used to remove the function 
for only one level for a particular element rather than all the functions and 
ett/hf variables for a particular element as the NOEMIT command does.

=item I<CODE START>/I<CODE END>
Begin and end a section of code to be put directly into the generated
source file for the dissector.

=item I<HEADER START>/I<HEADER END>
Begin and end a section of code to be put directly into the generated
header file for the dissector.

=back

=head1 EXAMPLE

	INFO_KEY OpenKey.Ke

=cut

package Parse::Pidl::Wireshark::Conformance;

require Exporter;
use vars qw($VERSION);
$VERSION = '0.01';

@ISA = qw(Exporter);
@EXPORT_OK = qw(ReadConformance ReadConformanceFH valid_ft_type valid_base_type);

use strict;
use warnings;

use Parse::Pidl qw(fatal warning error);
use Parse::Pidl::Util qw(has_property);
use Parse::Pidl::Typelist qw(addType);

sub handle_type($$$$$$$$$$)
{
	my ($pos,$data,$name,$dissectorname,$ft_type,$base_type,$mask,$valsstring,$alignment) = @_;

	unless(defined($alignment)) {
		error($pos, "incomplete TYPE command");
		return;
	}

	unless ($dissectorname =~ /.*dissect_.*/) {
		warning($pos, "dissector name does not contain `dissect'");
	}

	unless(valid_ft_type($ft_type)) {
		warning($pos, "invalid FT_TYPE `$ft_type'");
	}

	unless (valid_base_type($base_type)) {
		warning($pos, "invalid BASE_TYPE `$base_type'");
	}

	$dissectorname =~ s/^\"(.*)\"$/$1/g;

	if (not ($dissectorname =~ /;$/)) {
		warning($pos, "missing semicolon");
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

	addType({
		NAME => $name,
		TYPE => "CONFORMANCE",
		BASEFILE => "conformance file",
		DATA => {
			NAME => $name,
			TYPE => "CONFORMANCE",
			ALIGN => $alignment
		}
	});
}

sub handle_tfs($$$$$)
{
	my ($pos,$data,$hf,$trues,$falses) = @_;

	unless(defined($falses)) {
		error($pos, "incomplete TFS command");
		return;
	}

	$data->{tfs}->{$hf} = {
		TRUE_STRING => $trues,
		FALSE_STRING => $falses
	};
}

sub handle_hf_rename($$$$)
{
	my ($pos,$data,$old,$new) = @_;

	unless(defined($new)) {
		warning($pos, "incomplete HF_RENAME command");
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
		error($pos, "incomplete PARAM_VALUE command");
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
		error($pos, "incomplete HF_FIELD command");
		return;
	}

	unless(valid_ft_type($ft_type)) {
		warning($pos, "invalid FT_TYPE `$ft_type'");
	}

	unless(valid_base_type($base_type)) {
		warning($pos, "invalid BASE_TYPE `$base_type'");
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
	my ($pos,$data,$type) = @_;

	if (defined($type)) {
		$data->{noemit}->{$type} = 1;
	} else {
		$data->{noemit_dissector} = 1;
	}
}

sub handle_manual($$$)
{
	my ($pos,$data,$fn) = @_;

	unless(defined($fn)) {
		warning($pos, "incomplete MANUAL command");
		return;
	}

	$data->{manual}->{$fn} = 1;
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

	unless(defined($desc)) {
		warning($pos, "incomplete FIELD_DESCRIPTION command");
		return;
	}

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
		error($pos, "no dissectorname specified");
		return;
	}

	$data->{imports}->{$dissectorname} = {
		NAME => $dissectorname,
		DATA => join(' ', @_),
		USED => 0,
		POS => $pos
	};
}

sub handle_ett_field
{
	my $pos = shift @_;
	my $data = shift @_;
	my $ett = shift @_;

	unless(defined($ett)) {
		error($pos, "incomplete ETT_FIELD command");
		return;
	}

	push (@{$data->{ett}}, $ett);
}

sub handle_include
{
	my $pos = shift @_;
	my $data = shift @_;
	my $fn = shift @_;

	unless(defined($fn)) {
		error($pos, "incomplete INCLUDE command");
		return;
	}

	ReadConformance($fn, $data);
}

my %field_handlers = (
	TYPE => \&handle_type,
	NOEMIT => \&handle_noemit,
	MANUAL => \&handle_manual,
	PARAM_VALUE => \&handle_param_value,
	HF_FIELD => \&handle_hf_field,
	HF_RENAME => \&handle_hf_rename,
	ETT_FIELD => \&handle_ett_field,
	TFS => \&handle_tfs,
	STRIP_PREFIX => \&handle_strip_prefix,
	PROTOCOL => \&handle_protocol,
	FIELD_DESCRIPTION => \&handle_fielddescription,
	IMPORT => \&handle_import,
	INCLUDE => \&handle_include
);

sub ReadConformance($$)
{
	my ($f,$data) = @_;
	my $ret;

	open(IN,"<$f") or return undef;

	$ret = ReadConformanceFH(*IN, $data, $f);

	close(IN);

	return $ret;
}

sub ReadConformanceFH($$$)
{
	my ($fh,$data,$f) = @_;

	my $incodeblock = 0;
	my $inheaderblock = 0;

	my $ln = 0;

	foreach (<$fh>) {
		$ln++;
		next if (/^#.*$/);
		next if (/^$/);

		s/[\r\n]//g;

		if ($_ eq "CODE START") {
			if ($incodeblock) {
				warning({ FILE => $f, LINE => $ln }, 
					"CODE START inside CODE section");
			}
			if ($inheaderblock) {
				error({ FILE => $f, LINE => $ln }, 
					"CODE START inside HEADER section");
				return undef;
			}
			$incodeblock = 1;
			next;
		} elsif ($_ eq "CODE END") {
			if (!$incodeblock) {
				warning({ FILE => $f, LINE => $ln }, 
					"CODE END outside CODE section");
			}
			if ($inheaderblock) {
				error({ FILE => $f, LINE => $ln }, 
					"CODE END inside HEADER section");
				return undef;
			}
			$incodeblock = 0;
			next;
		} elsif ($incodeblock) {
			if (exists $data->{override}) {
				$data->{override}.="$_\n";
			} else {
				$data->{override} = "$_\n";
			}
			next;
		} elsif ($_ eq "HEADER START") {
			if ($inheaderblock) {
				warning({ FILE => $f, LINE => $ln }, 
					"HEADER START inside HEADER section");
			}
			if ($incodeblock) {
				error({ FILE => $f, LINE => $ln }, 
					"HEADER START inside CODE section");
				return undef;
			}
			$inheaderblock = 1;
			next;
		} elsif ($_ eq "HEADER END") {
			if (!$inheaderblock) {
				warning({ FILE => $f, LINE => $ln }, 
					"HEADER END outside HEADER section");
			}
			if ($incodeblock) {
				error({ FILE => $f, LINE => $ln }, 
					"CODE END inside HEADER section");
				return undef;
			}
			$inheaderblock = 0;
			next;
		} elsif ($inheaderblock) {
			if (exists $data->{header}) {
				$data->{header}.="$_\n";
			} else {
				$data->{header} = "$_\n";
			}
			next;
		}

		my @fields = /([^ "]+|"[^"]+")/g;

		my $cmd = $fields[0];

		shift @fields;

		my $pos = { FILE => $f, LINE => $ln };

		next unless(defined($cmd));

		if (not defined($field_handlers{$cmd})) {
			warning($pos, "Unknown command `$cmd'");
			next;
		}
		
		$field_handlers{$cmd}($pos, $data, @fields);
	}

	if ($incodeblock) {
		warning({ FILE => $f, LINE => $ln }, 
			"Expecting CODE END");
		return undef;
	}

	return 1;
}

1;
