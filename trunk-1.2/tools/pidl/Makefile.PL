use ExtUtils::MakeMaker;
WriteMakefile(
    'NAME'	=> 'Parse::Pidl',
    'VERSION_FROM' => 'lib/Parse/Pidl.pm',
	'EXE_FILES' => [ 'pidl' ],
	'test' => { 'TESTS' => 'tests/*.pl' }
);

sub MY::postamble {
<<'EOT';
lib/Parse/Pidl/IDL.pm: idl.yp
	yapp -m 'Parse::Pidl::IDL' -o lib/Parse/Pidl/IDL.pm idl.yp

lib/Parse/Pidl/Expr.pm: expr.yp
	yapp -m 'Parse::Pidl::Expr' -o lib/Parse/Pidl/Expr.pm expr.yp
EOT
}
