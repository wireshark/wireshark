use ExtUtils::MakeMaker;
WriteMakefile(
    'NAME'	=> 'Parse::Pidl',
    'VERSION_FROM' => 'lib/Parse/Pidl.pm',
	'EXE_FILES' => [ 'pidl' ],
	'PMLIBDIRS' => [ 'lib' ],
	'test' => { 'TESTS' => 'tests/*.pl' }
);

sub MY::postamble {
<<'EOT';
lib/Parse/Pidl/IDL.pm :: idl.yp
	yapp -s -m 'Parse::Pidl::IDL' -o 'lib/Parse/Pidl/IDL.pm' idl.yp

doc: pidl.1 pidl.1.html

XSLTPROC=xsltproc

%.1: %.1.xml
	test -z "$(XSLTPROC)" || $(XSLTPROC) -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

%.html: %.xml
	test -z "$(XSLTPROC)" || $(XSLTPROC) -o $@ http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $<
EOT
}
