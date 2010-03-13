# Check whether ExtUtils::ExtMaker is available

if perl -e "use ExtUtils::MakeMaker" 2>/dev/null; then
	HAVE_PERL_EXTUTILS_MAKEMAKER=1
else
	HAVE_PERL_EXTUTILS_MAKEMAKER=0
fi

AC_SUBST(HAVE_PERL_EXTUTILS_MAKEMAKER)
