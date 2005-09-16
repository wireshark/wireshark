####################################################################
#
#    This file was generated using Parse::Yapp version 1.05.
#
#        Don't edit this file, use source file instead.
#
#             ANY CHANGE MADE HERE WILL BE LOST !
#
####################################################################
package Parse::Pidl::IDL;
use vars qw ( @ISA );
use strict;

@ISA= qw ( Parse::Yapp::Driver );
#Included Parse/Yapp/Driver.pm file----------------------------------------
{
#
# Module Parse::Yapp::Driver
#
# This module is part of the Parse::Yapp package available on your
# nearest CPAN
#
# Any use of this module in a standalone parser make the included
# text under the same copyright as the Parse::Yapp module itself.
#
# This notice should remain unchanged.
#
# (c) Copyright 1998-2001 Francois Desarmenien, all rights reserved.
# (see the pod text in Parse::Yapp module for use and distribution rights)
#

package Parse::Yapp::Driver;

require 5.004;

use strict;

use vars qw ( $VERSION $COMPATIBLE $FILENAME );

$VERSION = '1.05';
$COMPATIBLE = '0.07';
$FILENAME=__FILE__;

use Carp;

#Known parameters, all starting with YY (leading YY will be discarded)
my(%params)=(YYLEX => 'CODE', 'YYERROR' => 'CODE', YYVERSION => '',
			 YYRULES => 'ARRAY', YYSTATES => 'ARRAY', YYDEBUG => '');
#Mandatory parameters
my(@params)=('LEX','RULES','STATES');

sub new {
    my($class)=shift;
	my($errst,$nberr,$token,$value,$check,$dotpos);
    my($self)={ ERROR => \&_Error,
				ERRST => \$errst,
                NBERR => \$nberr,
				TOKEN => \$token,
				VALUE => \$value,
				DOTPOS => \$dotpos,
				STACK => [],
				DEBUG => 0,
				CHECK => \$check };

	_CheckParams( [], \%params, \@_, $self );

		exists($$self{VERSION})
	and	$$self{VERSION} < $COMPATIBLE
	and	croak "Yapp driver version $VERSION ".
			  "incompatible with version $$self{VERSION}:\n".
			  "Please recompile parser module.";

        ref($class)
    and $class=ref($class);

    bless($self,$class);
}

sub YYParse {
    my($self)=shift;
    my($retval);

	_CheckParams( \@params, \%params, \@_, $self );

	if($$self{DEBUG}) {
		_DBLoad();
		$retval = eval '$self->_DBParse()';#Do not create stab entry on compile
        $@ and die $@;
	}
	else {
		$retval = $self->_Parse();
	}
    $retval
}

sub YYData {
	my($self)=shift;

		exists($$self{USER})
	or	$$self{USER}={};

	$$self{USER};
	
}

sub YYErrok {
	my($self)=shift;

	${$$self{ERRST}}=0;
    undef;
}

sub YYNberr {
	my($self)=shift;

	${$$self{NBERR}};
}

sub YYRecovering {
	my($self)=shift;

	${$$self{ERRST}} != 0;
}

sub YYAbort {
	my($self)=shift;

	${$$self{CHECK}}='ABORT';
    undef;
}

sub YYAccept {
	my($self)=shift;

	${$$self{CHECK}}='ACCEPT';
    undef;
}

sub YYError {
	my($self)=shift;

	${$$self{CHECK}}='ERROR';
    undef;
}

sub YYSemval {
	my($self)=shift;
	my($index)= $_[0] - ${$$self{DOTPOS}} - 1;

		$index < 0
	and	-$index <= @{$$self{STACK}}
	and	return $$self{STACK}[$index][1];

	undef;	#Invalid index
}

sub YYCurtok {
	my($self)=shift;

        @_
    and ${$$self{TOKEN}}=$_[0];
    ${$$self{TOKEN}};
}

sub YYCurval {
	my($self)=shift;

        @_
    and ${$$self{VALUE}}=$_[0];
    ${$$self{VALUE}};
}

sub YYExpect {
    my($self)=shift;

    keys %{$self->{STATES}[$self->{STACK}[-1][0]]{ACTIONS}}
}

sub YYLexer {
    my($self)=shift;

	$$self{LEX};
}


#################
# Private stuff #
#################


sub _CheckParams {
	my($mandatory,$checklist,$inarray,$outhash)=@_;
	my($prm,$value);
	my($prmlst)={};

	while(($prm,$value)=splice(@$inarray,0,2)) {
        $prm=uc($prm);
			exists($$checklist{$prm})
		or	croak("Unknow parameter '$prm'");
			ref($value) eq $$checklist{$prm}
		or	croak("Invalid value for parameter '$prm'");
        $prm=unpack('@2A*',$prm);
		$$outhash{$prm}=$value;
	}
	for (@$mandatory) {
			exists($$outhash{$_})
		or	croak("Missing mandatory parameter '".lc($_)."'");
	}
}

sub _Error {
	print "Parse error.\n";
}

sub _DBLoad {
	{
		no strict 'refs';

			exists(${__PACKAGE__.'::'}{_DBParse})#Already loaded ?
		and	return;
	}
	my($fname)=__FILE__;
	my(@drv);
	open(DRV,"<$fname") or die "Report this as a BUG: Cannot open $fname";
	while(<DRV>) {
                	/^\s*sub\s+_Parse\s*{\s*$/ .. /^\s*}\s*#\s*_Parse\s*$/
        	and     do {
                	s/^#DBG>//;
                	push(@drv,$_);
        	}
	}
	close(DRV);

	$drv[0]=~s/_P/_DBP/;
	eval join('',@drv);
}

#Note that for loading debugging version of the driver,
#this file will be parsed from 'sub _Parse' up to '}#_Parse' inclusive.
#So, DO NOT remove comment at end of sub !!!
sub _Parse {
    my($self)=shift;

	my($rules,$states,$lex,$error)
     = @$self{ 'RULES', 'STATES', 'LEX', 'ERROR' };
	my($errstatus,$nberror,$token,$value,$stack,$check,$dotpos)
     = @$self{ 'ERRST', 'NBERR', 'TOKEN', 'VALUE', 'STACK', 'CHECK', 'DOTPOS' };

#DBG>	my($debug)=$$self{DEBUG};
#DBG>	my($dbgerror)=0;

#DBG>	my($ShowCurToken) = sub {
#DBG>		my($tok)='>';
#DBG>		for (split('',$$token)) {
#DBG>			$tok.=		(ord($_) < 32 or ord($_) > 126)
#DBG>					?	sprintf('<%02X>',ord($_))
#DBG>					:	$_;
#DBG>		}
#DBG>		$tok.='<';
#DBG>	};

	$$errstatus=0;
	$$nberror=0;
	($$token,$$value)=(undef,undef);
	@$stack=( [ 0, undef ] );
	$$check='';

    while(1) {
        my($actions,$act,$stateno);

        $stateno=$$stack[-1][0];
        $actions=$$states[$stateno];

#DBG>	print STDERR ('-' x 40),"\n";
#DBG>		$debug & 0x2
#DBG>	and	print STDERR "In state $stateno:\n";
#DBG>		$debug & 0x08
#DBG>	and	print STDERR "Stack:[".
#DBG>					 join(',',map { $$_[0] } @$stack).
#DBG>					 "]\n";


        if  (exists($$actions{ACTIONS})) {

				defined($$token)
            or	do {
				($$token,$$value)=&$lex($self);
#DBG>				$debug & 0x01
#DBG>			and	print STDERR "Need token. Got ".&$ShowCurToken."\n";
			};

            $act=   exists($$actions{ACTIONS}{$$token})
                    ?   $$actions{ACTIONS}{$$token}
                    :   exists($$actions{DEFAULT})
                        ?   $$actions{DEFAULT}
                        :   undef;
        }
        else {
            $act=$$actions{DEFAULT};
#DBG>			$debug & 0x01
#DBG>		and	print STDERR "Don't need token.\n";
        }

            defined($act)
        and do {

                $act > 0
            and do {        #shift

#DBG>				$debug & 0x04
#DBG>			and	print STDERR "Shift and go to state $act.\n";

					$$errstatus
				and	do {
					--$$errstatus;

#DBG>					$debug & 0x10
#DBG>				and	$dbgerror
#DBG>				and	$$errstatus == 0
#DBG>				and	do {
#DBG>					print STDERR "**End of Error recovery.\n";
#DBG>					$dbgerror=0;
#DBG>				};
				};


                push(@$stack,[ $act, $$value ]);

					$$token ne ''	#Don't eat the eof
				and	$$token=$$value=undef;
                next;
            };

            #reduce
            my($lhs,$len,$code,@sempar,$semval);
            ($lhs,$len,$code)=@{$$rules[-$act]};

#DBG>			$debug & 0x04
#DBG>		and	$act
#DBG>		and	print STDERR "Reduce using rule ".-$act." ($lhs,$len): ";

                $act
            or  $self->YYAccept();

            $$dotpos=$len;

                unpack('A1',$lhs) eq '@'    #In line rule
            and do {
                    $lhs =~ /^\@[0-9]+\-([0-9]+)$/
                or  die "In line rule name '$lhs' ill formed: ".
                        "report it as a BUG.\n";
                $$dotpos = $1;
            };

            @sempar =       $$dotpos
                        ?   map { $$_[1] } @$stack[ -$$dotpos .. -1 ]
                        :   ();

            $semval = $code ? &$code( $self, @sempar )
                            : @sempar ? $sempar[0] : undef;

            splice(@$stack,-$len,$len);

                $$check eq 'ACCEPT'
            and do {

#DBG>			$debug & 0x04
#DBG>		and	print STDERR "Accept.\n";

				return($semval);
			};

                $$check eq 'ABORT'
            and	do {

#DBG>			$debug & 0x04
#DBG>		and	print STDERR "Abort.\n";

				return(undef);

			};

#DBG>			$debug & 0x04
#DBG>		and	print STDERR "Back to state $$stack[-1][0], then ";

                $$check eq 'ERROR'
            or  do {
#DBG>				$debug & 0x04
#DBG>			and	print STDERR 
#DBG>				    "go to state $$states[$$stack[-1][0]]{GOTOS}{$lhs}.\n";

#DBG>				$debug & 0x10
#DBG>			and	$dbgerror
#DBG>			and	$$errstatus == 0
#DBG>			and	do {
#DBG>				print STDERR "**End of Error recovery.\n";
#DBG>				$dbgerror=0;
#DBG>			};

			    push(@$stack,
                     [ $$states[$$stack[-1][0]]{GOTOS}{$lhs}, $semval ]);
                $$check='';
                next;
            };

#DBG>			$debug & 0x04
#DBG>		and	print STDERR "Forced Error recovery.\n";

            $$check='';

        };

        #Error
            $$errstatus
        or   do {

            $$errstatus = 1;
            &$error($self);
                $$errstatus # if 0, then YYErrok has been called
            or  next;       # so continue parsing

#DBG>			$debug & 0x10
#DBG>		and	do {
#DBG>			print STDERR "**Entering Error recovery.\n";
#DBG>			++$dbgerror;
#DBG>		};

            ++$$nberror;

        };

			$$errstatus == 3	#The next token is not valid: discard it
		and	do {
				$$token eq ''	# End of input: no hope
			and	do {
#DBG>				$debug & 0x10
#DBG>			and	print STDERR "**At eof: aborting.\n";
				return(undef);
			};

#DBG>			$debug & 0x10
#DBG>		and	print STDERR "**Dicard invalid token ".&$ShowCurToken.".\n";

			$$token=$$value=undef;
		};

        $$errstatus=3;

		while(	  @$stack
			  and (		not exists($$states[$$stack[-1][0]]{ACTIONS})
			        or  not exists($$states[$$stack[-1][0]]{ACTIONS}{error})
					or	$$states[$$stack[-1][0]]{ACTIONS}{error} <= 0)) {

#DBG>			$debug & 0x10
#DBG>		and	print STDERR "**Pop state $$stack[-1][0].\n";

			pop(@$stack);
		}

			@$stack
		or	do {

#DBG>			$debug & 0x10
#DBG>		and	print STDERR "**No state left on stack: aborting.\n";

			return(undef);
		};

		#shift the error token

#DBG>			$debug & 0x10
#DBG>		and	print STDERR "**Shift \$error token and go to state ".
#DBG>						 $$states[$$stack[-1][0]]{ACTIONS}{error}.
#DBG>						 ".\n";

		push(@$stack, [ $$states[$$stack[-1][0]]{ACTIONS}{error}, undef ]);

    }

    #never reached
	croak("Error in driver logic. Please, report it as a BUG");

}#_Parse
#DO NOT remove comment

1;

}
#End of include--------------------------------------------------




sub new {
        my($class)=shift;
        ref($class)
    and $class=ref($class);

    my($self)=$class->SUPER::new( yyversion => '1.05',
                                  yystates =>
[
	{#State 0
		DEFAULT => -1,
		GOTOS => {
			'idl' => 1
		}
	},
	{#State 1
		ACTIONS => {
			'' => 2
		},
		DEFAULT => -63,
		GOTOS => {
			'interface' => 3,
			'coclass' => 4,
			'property_list' => 5
		}
	},
	{#State 2
		DEFAULT => 0
	},
	{#State 3
		DEFAULT => -2
	},
	{#State 4
		DEFAULT => -3
	},
	{#State 5
		ACTIONS => {
			"coclass" => 6,
			"interface" => 8,
			"[" => 7
		}
	},
	{#State 6
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 10
		}
	},
	{#State 7
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 11,
			'properties' => 13,
			'property' => 12
		}
	},
	{#State 8
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 14
		}
	},
	{#State 9
		DEFAULT => -92
	},
	{#State 10
		ACTIONS => {
			"{" => 15
		}
	},
	{#State 11
		ACTIONS => {
			"(" => 16
		},
		DEFAULT => -67
	},
	{#State 12
		DEFAULT => -65
	},
	{#State 13
		ACTIONS => {
			"," => 17,
			"]" => 18
		}
	},
	{#State 14
		ACTIONS => {
			":" => 19
		},
		DEFAULT => -8,
		GOTOS => {
			'base_interface' => 20
		}
	},
	{#State 15
		DEFAULT => -5,
		GOTOS => {
			'interface_names' => 21
		}
	},
	{#State 16
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'listtext' => 26,
			'anytext' => 25,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 17
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 11,
			'property' => 29
		}
	},
	{#State 18
		DEFAULT => -64
	},
	{#State 19
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 30
		}
	},
	{#State 20
		ACTIONS => {
			"{" => 31
		}
	},
	{#State 21
		ACTIONS => {
			"}" => 32,
			"interface" => 33
		}
	},
	{#State 22
		DEFAULT => -96
	},
	{#State 23
		DEFAULT => -74
	},
	{#State 24
		DEFAULT => -76
	},
	{#State 25
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"<" => 37,
			"+" => 39,
			"~" => 38,
			"*" => 46,
			"?" => 36,
			"{" => 40,
			"&" => 41,
			"/" => 42,
			"=" => 43,
			"(" => 44,
			"|" => 45,
			"." => 47,
			">" => 48
		},
		DEFAULT => -69
	},
	{#State 26
		ACTIONS => {
			"," => 49,
			")" => 50
		}
	},
	{#State 27
		DEFAULT => -75
	},
	{#State 28
		DEFAULT => -95
	},
	{#State 29
		DEFAULT => -66
	},
	{#State 30
		DEFAULT => -9
	},
	{#State 31
		ACTIONS => {
			"typedef" => 51,
			"union" => 52,
			"enum" => 65,
			"bitmap" => 66,
			"declare" => 58,
			"const" => 60,
			"struct" => 63
		},
		DEFAULT => -63,
		GOTOS => {
			'typedecl' => 64,
			'function' => 53,
			'bitmap' => 67,
			'definitions' => 54,
			'definition' => 57,
			'property_list' => 56,
			'usertype' => 55,
			'declare' => 69,
			'const' => 68,
			'struct' => 59,
			'enum' => 61,
			'typedef' => 62,
			'union' => 70
		}
	},
	{#State 32
		ACTIONS => {
			";" => 71
		},
		DEFAULT => -97,
		GOTOS => {
			'optional_semicolon' => 72
		}
	},
	{#State 33
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 73
		}
	},
	{#State 34
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 74,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 35
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 75,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 36
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 76,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 37
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 77,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 38
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 78,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 39
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 79,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 40
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 80,
			'text' => 24,
			'constant' => 27,
			'commalisttext' => 81
		}
	},
	{#State 41
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 82,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 42
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 83,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 43
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 84,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 44
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 80,
			'text' => 24,
			'constant' => 27,
			'commalisttext' => 85
		}
	},
	{#State 45
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 86,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 46
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 87,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 47
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 88,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 48
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 89,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 49
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 90,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 50
		DEFAULT => -68
	},
	{#State 51
		DEFAULT => -63,
		GOTOS => {
			'property_list' => 91
		}
	},
	{#State 52
		ACTIONS => {
			'IDENTIFIER' => 92
		},
		DEFAULT => -94,
		GOTOS => {
			'optional_identifier' => 93
		}
	},
	{#State 53
		DEFAULT => -12
	},
	{#State 54
		ACTIONS => {
			"}" => 94,
			"typedef" => 51,
			"union" => 52,
			"enum" => 65,
			"bitmap" => 66,
			"declare" => 58,
			"const" => 60,
			"struct" => 63
		},
		DEFAULT => -63,
		GOTOS => {
			'typedecl' => 64,
			'function' => 53,
			'bitmap' => 67,
			'definition' => 95,
			'property_list' => 56,
			'usertype' => 55,
			'const' => 68,
			'struct' => 59,
			'declare' => 69,
			'enum' => 61,
			'typedef' => 62,
			'union' => 70
		}
	},
	{#State 55
		ACTIONS => {
			";" => 96
		}
	},
	{#State 56
		ACTIONS => {
			'IDENTIFIER' => 9,
			"union" => 52,
			"enum" => 65,
			"bitmap" => 66,
			"[" => 7,
			'void' => 97,
			"struct" => 63
		},
		GOTOS => {
			'identifier' => 99,
			'struct' => 59,
			'enum' => 61,
			'type' => 100,
			'union' => 70,
			'bitmap' => 67,
			'usertype' => 98
		}
	},
	{#State 57
		DEFAULT => -10
	},
	{#State 58
		DEFAULT => -63,
		GOTOS => {
			'property_list' => 101
		}
	},
	{#State 59
		DEFAULT => -26
	},
	{#State 60
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 102
		}
	},
	{#State 61
		DEFAULT => -28
	},
	{#State 62
		DEFAULT => -14
	},
	{#State 63
		ACTIONS => {
			'IDENTIFIER' => 92
		},
		DEFAULT => -94,
		GOTOS => {
			'optional_identifier' => 103
		}
	},
	{#State 64
		DEFAULT => -16
	},
	{#State 65
		ACTIONS => {
			'IDENTIFIER' => 92
		},
		DEFAULT => -94,
		GOTOS => {
			'optional_identifier' => 104
		}
	},
	{#State 66
		ACTIONS => {
			'IDENTIFIER' => 92
		},
		DEFAULT => -94,
		GOTOS => {
			'optional_identifier' => 105
		}
	},
	{#State 67
		DEFAULT => -29
	},
	{#State 68
		DEFAULT => -13
	},
	{#State 69
		DEFAULT => -15
	},
	{#State 70
		DEFAULT => -27
	},
	{#State 71
		DEFAULT => -98
	},
	{#State 72
		DEFAULT => -4
	},
	{#State 73
		ACTIONS => {
			";" => 106
		}
	},
	{#State 74
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"<" => 37,
			"+" => 39,
			"~" => 38,
			"*" => 46,
			"?" => 36,
			"{" => 40,
			"&" => 41,
			"/" => 42,
			"=" => 43,
			"(" => 44,
			"|" => 45,
			"." => 47,
			">" => 48
		},
		DEFAULT => -86
	},
	{#State 75
		ACTIONS => {
			":" => 34,
			"<" => 37,
			"~" => 38,
			"?" => 36,
			"{" => 40,
			"=" => 43
		},
		DEFAULT => -77
	},
	{#State 76
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"<" => 37,
			"+" => 39,
			"~" => 38,
			"*" => 46,
			"?" => 36,
			"{" => 40,
			"&" => 41,
			"/" => 42,
			"=" => 43,
			"(" => 44,
			"|" => 45,
			"." => 47,
			">" => 48
		},
		DEFAULT => -85
	},
	{#State 77
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"<" => 37,
			"+" => 39,
			"~" => 38,
			"*" => 46,
			"?" => 36,
			"{" => 40,
			"&" => 41,
			"/" => 42,
			"=" => 43,
			"(" => 44,
			"|" => 45,
			"." => 47,
			">" => 48
		},
		DEFAULT => -81
	},
	{#State 78
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"<" => 37,
			"+" => 39,
			"~" => 38,
			"*" => 46,
			"?" => 36,
			"{" => 40,
			"&" => 41,
			"/" => 42,
			"=" => 43,
			"(" => 44,
			"|" => 45,
			"." => 47,
			">" => 48
		},
		DEFAULT => -89
	},
	{#State 79
		ACTIONS => {
			":" => 34,
			"<" => 37,
			"~" => 38,
			"?" => 36,
			"{" => 40,
			"=" => 43
		},
		DEFAULT => -88
	},
	{#State 80
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"<" => 37,
			"+" => 39,
			"~" => 38,
			"*" => 46,
			"?" => 36,
			"{" => 40,
			"&" => 41,
			"/" => 42,
			"=" => 43,
			"(" => 44,
			"|" => 45,
			"." => 47,
			">" => 48
		},
		DEFAULT => -71
	},
	{#State 81
		ACTIONS => {
			"}" => 107,
			"," => 108
		}
	},
	{#State 82
		ACTIONS => {
			":" => 34,
			"<" => 37,
			"~" => 38,
			"?" => 36,
			"{" => 40,
			"=" => 43
		},
		DEFAULT => -83
	},
	{#State 83
		ACTIONS => {
			":" => 34,
			"<" => 37,
			"~" => 38,
			"?" => 36,
			"{" => 40,
			"=" => 43
		},
		DEFAULT => -84
	},
	{#State 84
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"<" => 37,
			"+" => 39,
			"~" => 38,
			"*" => 46,
			"?" => 36,
			"{" => 40,
			"&" => 41,
			"/" => 42,
			"=" => 43,
			"(" => 44,
			"|" => 45,
			"." => 47,
			">" => 48
		},
		DEFAULT => -87
	},
	{#State 85
		ACTIONS => {
			"," => 108,
			")" => 109
		}
	},
	{#State 86
		ACTIONS => {
			":" => 34,
			"<" => 37,
			"~" => 38,
			"?" => 36,
			"{" => 40,
			"=" => 43
		},
		DEFAULT => -82
	},
	{#State 87
		ACTIONS => {
			":" => 34,
			"<" => 37,
			"~" => 38,
			"?" => 36,
			"{" => 40,
			"=" => 43
		},
		DEFAULT => -79
	},
	{#State 88
		ACTIONS => {
			":" => 34,
			"<" => 37,
			"~" => 38,
			"?" => 36,
			"{" => 40,
			"=" => 43
		},
		DEFAULT => -78
	},
	{#State 89
		ACTIONS => {
			":" => 34,
			"<" => 37,
			"~" => 38,
			"?" => 36,
			"{" => 40,
			"=" => 43
		},
		DEFAULT => -80
	},
	{#State 90
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"<" => 37,
			"+" => 39,
			"~" => 38,
			"*" => 46,
			"?" => 36,
			"{" => 40,
			"&" => 41,
			"/" => 42,
			"=" => 43,
			"(" => 44,
			"|" => 45,
			"." => 47,
			">" => 48
		},
		DEFAULT => -70
	},
	{#State 91
		ACTIONS => {
			'IDENTIFIER' => 9,
			"union" => 52,
			"enum" => 65,
			"bitmap" => 66,
			"[" => 7,
			'void' => 97,
			"struct" => 63
		},
		GOTOS => {
			'identifier' => 99,
			'struct' => 59,
			'enum' => 61,
			'type' => 110,
			'union' => 70,
			'bitmap' => 67,
			'usertype' => 98
		}
	},
	{#State 92
		DEFAULT => -93
	},
	{#State 93
		ACTIONS => {
			"{" => 111
		}
	},
	{#State 94
		ACTIONS => {
			";" => 71
		},
		DEFAULT => -97,
		GOTOS => {
			'optional_semicolon' => 112
		}
	},
	{#State 95
		DEFAULT => -11
	},
	{#State 96
		DEFAULT => -30
	},
	{#State 97
		DEFAULT => -33
	},
	{#State 98
		DEFAULT => -31
	},
	{#State 99
		DEFAULT => -32
	},
	{#State 100
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 113
		}
	},
	{#State 101
		ACTIONS => {
			"enum" => 117,
			"bitmap" => 118,
			"[" => 7
		},
		GOTOS => {
			'decl_enum' => 114,
			'decl_bitmap' => 115,
			'decl_type' => 116
		}
	},
	{#State 102
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 119
		}
	},
	{#State 103
		ACTIONS => {
			"{" => 120
		}
	},
	{#State 104
		ACTIONS => {
			"{" => 121
		}
	},
	{#State 105
		ACTIONS => {
			"{" => 122
		}
	},
	{#State 106
		DEFAULT => -6
	},
	{#State 107
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 123,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 108
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 124,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 109
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 125,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 110
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 126
		}
	},
	{#State 111
		DEFAULT => -48,
		GOTOS => {
			'union_elements' => 127
		}
	},
	{#State 112
		DEFAULT => -7
	},
	{#State 113
		ACTIONS => {
			"(" => 128
		}
	},
	{#State 114
		DEFAULT => -21
	},
	{#State 115
		DEFAULT => -22
	},
	{#State 116
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 129
		}
	},
	{#State 117
		DEFAULT => -23
	},
	{#State 118
		DEFAULT => -24
	},
	{#State 119
		ACTIONS => {
			"[" => 130,
			"=" => 132
		},
		GOTOS => {
			'array_len' => 131
		}
	},
	{#State 120
		DEFAULT => -54,
		GOTOS => {
			'element_list1' => 133
		}
	},
	{#State 121
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 134,
			'enum_element' => 135,
			'enum_elements' => 136
		}
	},
	{#State 122
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 139,
			'bitmap_elements' => 138,
			'bitmap_element' => 137
		}
	},
	{#State 123
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"<" => 37,
			"+" => 39,
			"~" => 38,
			"*" => 46,
			"?" => 36,
			"{" => 40,
			"&" => 41,
			"/" => 42,
			"=" => 43,
			"(" => 44,
			"|" => 45,
			"." => 47,
			">" => 48
		},
		DEFAULT => -91
	},
	{#State 124
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"<" => 37,
			"+" => 39,
			"~" => 38,
			"*" => 46,
			"?" => 36,
			"{" => 40,
			"&" => 41,
			"/" => 42,
			"=" => 43,
			"(" => 44,
			"|" => 45,
			"." => 47,
			">" => 48
		},
		DEFAULT => -72
	},
	{#State 125
		ACTIONS => {
			":" => 34,
			"<" => 37,
			"~" => 38,
			"?" => 36,
			"{" => 40,
			"=" => 43
		},
		DEFAULT => -90
	},
	{#State 126
		ACTIONS => {
			"[" => 130
		},
		DEFAULT => -60,
		GOTOS => {
			'array_len' => 140
		}
	},
	{#State 127
		ACTIONS => {
			"}" => 141
		},
		DEFAULT => -63,
		GOTOS => {
			'optional_base_element' => 143,
			'property_list' => 142
		}
	},
	{#State 128
		ACTIONS => {
			"," => -56,
			"void" => 147,
			")" => -56
		},
		DEFAULT => -63,
		GOTOS => {
			'base_element' => 144,
			'element_list2' => 146,
			'property_list' => 145
		}
	},
	{#State 129
		ACTIONS => {
			";" => 148
		}
	},
	{#State 130
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			"]" => 149,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 150,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 131
		ACTIONS => {
			"=" => 151
		}
	},
	{#State 132
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 152,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 133
		ACTIONS => {
			"}" => 153
		},
		DEFAULT => -63,
		GOTOS => {
			'base_element' => 154,
			'property_list' => 145
		}
	},
	{#State 134
		ACTIONS => {
			"=" => 155
		},
		DEFAULT => -37
	},
	{#State 135
		DEFAULT => -35
	},
	{#State 136
		ACTIONS => {
			"}" => 156,
			"," => 157
		}
	},
	{#State 137
		DEFAULT => -40
	},
	{#State 138
		ACTIONS => {
			"}" => 158,
			"," => 159
		}
	},
	{#State 139
		ACTIONS => {
			"=" => 160
		}
	},
	{#State 140
		ACTIONS => {
			";" => 161
		}
	},
	{#State 141
		DEFAULT => -50
	},
	{#State 142
		ACTIONS => {
			"[" => 7
		},
		DEFAULT => -63,
		GOTOS => {
			'base_or_empty' => 162,
			'base_element' => 163,
			'empty_element' => 164,
			'property_list' => 165
		}
	},
	{#State 143
		DEFAULT => -49
	},
	{#State 144
		DEFAULT => -58
	},
	{#State 145
		ACTIONS => {
			'IDENTIFIER' => 9,
			"union" => 52,
			"enum" => 65,
			"bitmap" => 66,
			"[" => 7,
			'void' => 97,
			"struct" => 63
		},
		GOTOS => {
			'identifier' => 99,
			'struct' => 59,
			'enum' => 61,
			'type' => 166,
			'union' => 70,
			'bitmap' => 67,
			'usertype' => 98
		}
	},
	{#State 146
		ACTIONS => {
			"," => 167,
			")" => 168
		}
	},
	{#State 147
		DEFAULT => -57
	},
	{#State 148
		DEFAULT => -20
	},
	{#State 149
		ACTIONS => {
			"[" => 130
		},
		DEFAULT => -60,
		GOTOS => {
			'array_len' => 169
		}
	},
	{#State 150
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"?" => 36,
			"<" => 37,
			"+" => 39,
			"~" => 38,
			"&" => 41,
			"{" => 40,
			"/" => 42,
			"=" => 43,
			"|" => 45,
			"(" => 44,
			"*" => 46,
			"." => 47,
			"]" => 170,
			">" => 48
		}
	},
	{#State 151
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 171,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 152
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"?" => 36,
			"<" => 37,
			";" => 172,
			"+" => 39,
			"~" => 38,
			"&" => 41,
			"{" => 40,
			"/" => 42,
			"=" => 43,
			"|" => 45,
			"(" => 44,
			"*" => 46,
			"." => 47,
			">" => 48
		}
	},
	{#State 153
		DEFAULT => -43
	},
	{#State 154
		ACTIONS => {
			";" => 173
		}
	},
	{#State 155
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 174,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 156
		DEFAULT => -34
	},
	{#State 157
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 134,
			'enum_element' => 175
		}
	},
	{#State 158
		DEFAULT => -39
	},
	{#State 159
		ACTIONS => {
			'IDENTIFIER' => 9
		},
		GOTOS => {
			'identifier' => 139,
			'bitmap_element' => 176
		}
	},
	{#State 160
		ACTIONS => {
			'CONSTANT' => 28,
			'TEXT' => 22,
			'IDENTIFIER' => 9
		},
		DEFAULT => -73,
		GOTOS => {
			'identifier' => 23,
			'anytext' => 177,
			'text' => 24,
			'constant' => 27
		}
	},
	{#State 161
		DEFAULT => -25
	},
	{#State 162
		DEFAULT => -47
	},
	{#State 163
		ACTIONS => {
			";" => 178
		}
	},
	{#State 164
		DEFAULT => -46
	},
	{#State 165
		ACTIONS => {
			'IDENTIFIER' => 9,
			"union" => 52,
			";" => 179,
			"enum" => 65,
			"bitmap" => 66,
			'void' => 97,
			"[" => 7,
			"struct" => 63
		},
		GOTOS => {
			'identifier' => 99,
			'struct' => 59,
			'enum' => 61,
			'type' => 166,
			'union' => 70,
			'bitmap' => 67,
			'usertype' => 98
		}
	},
	{#State 166
		DEFAULT => -52,
		GOTOS => {
			'pointers' => 180
		}
	},
	{#State 167
		DEFAULT => -63,
		GOTOS => {
			'base_element' => 181,
			'property_list' => 145
		}
	},
	{#State 168
		ACTIONS => {
			";" => 182
		}
	},
	{#State 169
		DEFAULT => -61
	},
	{#State 170
		ACTIONS => {
			"[" => 130
		},
		DEFAULT => -60,
		GOTOS => {
			'array_len' => 183
		}
	},
	{#State 171
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"?" => 36,
			"<" => 37,
			";" => 184,
			"+" => 39,
			"~" => 38,
			"&" => 41,
			"{" => 40,
			"/" => 42,
			"=" => 43,
			"|" => 45,
			"(" => 44,
			"*" => 46,
			"." => 47,
			">" => 48
		}
	},
	{#State 172
		DEFAULT => -17
	},
	{#State 173
		DEFAULT => -55
	},
	{#State 174
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"<" => 37,
			"+" => 39,
			"~" => 38,
			"*" => 46,
			"?" => 36,
			"{" => 40,
			"&" => 41,
			"/" => 42,
			"=" => 43,
			"(" => 44,
			"|" => 45,
			"." => 47,
			">" => 48
		},
		DEFAULT => -38
	},
	{#State 175
		DEFAULT => -36
	},
	{#State 176
		DEFAULT => -41
	},
	{#State 177
		ACTIONS => {
			"-" => 35,
			":" => 34,
			"<" => 37,
			"+" => 39,
			"~" => 38,
			"*" => 46,
			"?" => 36,
			"{" => 40,
			"&" => 41,
			"/" => 42,
			"=" => 43,
			"(" => 44,
			"|" => 45,
			"." => 47,
			">" => 48
		},
		DEFAULT => -42
	},
	{#State 178
		DEFAULT => -45
	},
	{#State 179
		DEFAULT => -44
	},
	{#State 180
		ACTIONS => {
			'IDENTIFIER' => 9,
			"*" => 186
		},
		GOTOS => {
			'identifier' => 185
		}
	},
	{#State 181
		DEFAULT => -59
	},
	{#State 182
		DEFAULT => -19
	},
	{#State 183
		DEFAULT => -62
	},
	{#State 184
		DEFAULT => -18
	},
	{#State 185
		ACTIONS => {
			"[" => 130
		},
		DEFAULT => -60,
		GOTOS => {
			'array_len' => 187
		}
	},
	{#State 186
		DEFAULT => -53
	},
	{#State 187
		DEFAULT => -51
	}
],
                                  yyrules  =>
[
	[#Rule 0
		 '$start', 2, undef
	],
	[#Rule 1
		 'idl', 0, undef
	],
	[#Rule 2
		 'idl', 2,
sub
#line 19 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 3
		 'idl', 2,
sub
#line 20 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 4
		 'coclass', 7,
sub
#line 24 "idl.yp"
{$_[3] => {
               "TYPE" => "COCLASS", 
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "DATA" => $_[5],
		   "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 5
		 'interface_names', 0, undef
	],
	[#Rule 6
		 'interface_names', 4,
sub
#line 36 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 7
		 'interface', 8,
sub
#line 40 "idl.yp"
{$_[3] => {
               "TYPE" => "INTERFACE", 
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "BASE" => $_[4],
	       "DATA" => $_[6],
		   "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 8
		 'base_interface', 0, undef
	],
	[#Rule 9
		 'base_interface', 2,
sub
#line 53 "idl.yp"
{ $_[2] }
	],
	[#Rule 10
		 'definitions', 1,
sub
#line 57 "idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 11
		 'definitions', 2,
sub
#line 58 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 12
		 'definition', 1, undef
	],
	[#Rule 13
		 'definition', 1, undef
	],
	[#Rule 14
		 'definition', 1, undef
	],
	[#Rule 15
		 'definition', 1, undef
	],
	[#Rule 16
		 'definition', 1, undef
	],
	[#Rule 17
		 'const', 6,
sub
#line 66 "idl.yp"
{{
                     "TYPE"  => "CONST", 
		     "DTYPE"  => $_[2],
		     "NAME"  => $_[3],
		     "VALUE" => $_[5],
		     "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 18
		 'const', 7,
sub
#line 75 "idl.yp"
{{
                     "TYPE"  => "CONST", 
		     "DTYPE"  => $_[2],
		     "NAME"  => $_[3],
		     "ARRAY_LEN" => $_[4],
		     "VALUE" => $_[6],
		     "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 19
		 'function', 7,
sub
#line 88 "idl.yp"
{{
		"TYPE" => "FUNCTION",
		"NAME" => $_[3],
		"RETURN_TYPE" => $_[2],
		"PROPERTIES" => $_[1],
		"ELEMENTS" => $_[5],
		"FILE" => $_[0]->YYData->{INPUT_FILENAME},
		"LINE" => $_[0]->YYData->{LINE},
	  }}
	],
	[#Rule 20
		 'declare', 5,
sub
#line 100 "idl.yp"
{{
	             "TYPE" => "DECLARE", 
                     "PROPERTIES" => $_[2],
		     "NAME" => $_[4],
		     "DATA" => $_[3],
		     "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 21
		 'decl_type', 1, undef
	],
	[#Rule 22
		 'decl_type', 1, undef
	],
	[#Rule 23
		 'decl_enum', 1,
sub
#line 114 "idl.yp"
{{
                     "TYPE" => "ENUM"
        }}
	],
	[#Rule 24
		 'decl_bitmap', 1,
sub
#line 120 "idl.yp"
{{
                     "TYPE" => "BITMAP"
        }}
	],
	[#Rule 25
		 'typedef', 6,
sub
#line 126 "idl.yp"
{{
	             "TYPE" => "TYPEDEF", 
                     "PROPERTIES" => $_[2],
		     "NAME" => $_[4],
		     "DATA" => $_[3],
		     "ARRAY_LEN" => $_[5],
		     "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 26
		 'usertype', 1, undef
	],
	[#Rule 27
		 'usertype', 1, undef
	],
	[#Rule 28
		 'usertype', 1, undef
	],
	[#Rule 29
		 'usertype', 1, undef
	],
	[#Rule 30
		 'typedecl', 2,
sub
#line 139 "idl.yp"
{ $_[1] }
	],
	[#Rule 31
		 'type', 1, undef
	],
	[#Rule 32
		 'type', 1, undef
	],
	[#Rule 33
		 'type', 1,
sub
#line 142 "idl.yp"
{ "void" }
	],
	[#Rule 34
		 'enum', 5,
sub
#line 146 "idl.yp"
{{
             "TYPE" => "ENUM", 
			 "NAME" => $_[2],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 35
		 'enum_elements', 1,
sub
#line 154 "idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 36
		 'enum_elements', 3,
sub
#line 155 "idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 37
		 'enum_element', 1, undef
	],
	[#Rule 38
		 'enum_element', 3,
sub
#line 159 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 39
		 'bitmap', 5,
sub
#line 163 "idl.yp"
{{
             "TYPE" => "BITMAP", 
			 "NAME" => $_[2],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 40
		 'bitmap_elements', 1,
sub
#line 171 "idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 41
		 'bitmap_elements', 3,
sub
#line 172 "idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 42
		 'bitmap_element', 3,
sub
#line 175 "idl.yp"
{ "$_[1] ( $_[3] )" }
	],
	[#Rule 43
		 'struct', 5,
sub
#line 179 "idl.yp"
{{
             "TYPE" => "STRUCT", 
			 "NAME" => $_[2],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 44
		 'empty_element', 2,
sub
#line 187 "idl.yp"
{{
		 "NAME" => "",
		 "TYPE" => "EMPTY",
		 "PROPERTIES" => $_[1],
		 "POINTERS" => 0,
		 "ARRAY_LEN" => [],
		 "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		 "LINE" => $_[0]->YYData->{LINE},
	 }}
	],
	[#Rule 45
		 'base_or_empty', 2, undef
	],
	[#Rule 46
		 'base_or_empty', 1, undef
	],
	[#Rule 47
		 'optional_base_element', 2,
sub
#line 201 "idl.yp"
{ $_[2]->{PROPERTIES} = Parse::Pidl::Util::FlattenHash([$_[1],$_[2]->{PROPERTIES}]); $_[2] }
	],
	[#Rule 48
		 'union_elements', 0, undef
	],
	[#Rule 49
		 'union_elements', 2,
sub
#line 206 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 50
		 'union', 5,
sub
#line 210 "idl.yp"
{{
             "TYPE" => "UNION", 
		     "NAME" => $_[2],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 51
		 'base_element', 5,
sub
#line 218 "idl.yp"
{{
			   "NAME" => $_[4],
			   "TYPE" => $_[2],
			   "PROPERTIES" => $_[1],
			   "POINTERS" => $_[3],
			   "ARRAY_LEN" => $_[5],
		       "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		       "LINE" => $_[0]->YYData->{LINE},
              }}
	],
	[#Rule 52
		 'pointers', 0,
sub
#line 232 "idl.yp"
{ 0 }
	],
	[#Rule 53
		 'pointers', 2,
sub
#line 233 "idl.yp"
{ $_[1]+1 }
	],
	[#Rule 54
		 'element_list1', 0, undef
	],
	[#Rule 55
		 'element_list1', 3,
sub
#line 238 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 56
		 'element_list2', 0, undef
	],
	[#Rule 57
		 'element_list2', 1, undef
	],
	[#Rule 58
		 'element_list2', 1,
sub
#line 244 "idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 59
		 'element_list2', 3,
sub
#line 245 "idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 60
		 'array_len', 0, undef
	],
	[#Rule 61
		 'array_len', 3,
sub
#line 250 "idl.yp"
{ push(@{$_[3]}, "*"); $_[3] }
	],
	[#Rule 62
		 'array_len', 4,
sub
#line 251 "idl.yp"
{ push(@{$_[4]}, "$_[2]"); $_[4] }
	],
	[#Rule 63
		 'property_list', 0, undef
	],
	[#Rule 64
		 'property_list', 4,
sub
#line 257 "idl.yp"
{ Parse::Pidl::Util::FlattenHash([$_[1],$_[3]]); }
	],
	[#Rule 65
		 'properties', 1,
sub
#line 260 "idl.yp"
{ $_[1] }
	],
	[#Rule 66
		 'properties', 3,
sub
#line 261 "idl.yp"
{ Parse::Pidl::Util::FlattenHash([$_[1], $_[3]]); }
	],
	[#Rule 67
		 'property', 1,
sub
#line 264 "idl.yp"
{{ "$_[1]" => "1"     }}
	],
	[#Rule 68
		 'property', 4,
sub
#line 265 "idl.yp"
{{ "$_[1]" => "$_[3]" }}
	],
	[#Rule 69
		 'listtext', 1, undef
	],
	[#Rule 70
		 'listtext', 3,
sub
#line 270 "idl.yp"
{ "$_[1] $_[3]" }
	],
	[#Rule 71
		 'commalisttext', 1, undef
	],
	[#Rule 72
		 'commalisttext', 3,
sub
#line 275 "idl.yp"
{ "$_[1],$_[3]" }
	],
	[#Rule 73
		 'anytext', 0,
sub
#line 279 "idl.yp"
{ "" }
	],
	[#Rule 74
		 'anytext', 1, undef
	],
	[#Rule 75
		 'anytext', 1, undef
	],
	[#Rule 76
		 'anytext', 1, undef
	],
	[#Rule 77
		 'anytext', 3,
sub
#line 281 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 78
		 'anytext', 3,
sub
#line 282 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 79
		 'anytext', 3,
sub
#line 283 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 80
		 'anytext', 3,
sub
#line 284 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 81
		 'anytext', 3,
sub
#line 285 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 82
		 'anytext', 3,
sub
#line 286 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 83
		 'anytext', 3,
sub
#line 287 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 84
		 'anytext', 3,
sub
#line 288 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 85
		 'anytext', 3,
sub
#line 289 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 86
		 'anytext', 3,
sub
#line 290 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 87
		 'anytext', 3,
sub
#line 291 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 88
		 'anytext', 3,
sub
#line 292 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 89
		 'anytext', 3,
sub
#line 293 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 90
		 'anytext', 5,
sub
#line 294 "idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 91
		 'anytext', 5,
sub
#line 295 "idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 92
		 'identifier', 1, undef
	],
	[#Rule 93
		 'optional_identifier', 1, undef
	],
	[#Rule 94
		 'optional_identifier', 0, undef
	],
	[#Rule 95
		 'constant', 1, undef
	],
	[#Rule 96
		 'text', 1,
sub
#line 309 "idl.yp"
{ "\"$_[1]\"" }
	],
	[#Rule 97
		 'optional_semicolon', 0, undef
	],
	[#Rule 98
		 'optional_semicolon', 1, undef
	]
],
                                  @_);
    bless($self,$class);
}

#line 320 "idl.yp"


use Parse::Pidl::Util;

#####################################################################
# traverse a perl data structure removing any empty arrays or
# hashes and any hash elements that map to undef
sub CleanData($)
{
    sub CleanData($);
    my($v) = shift;
    if (ref($v) eq "ARRAY") {
	foreach my $i (0 .. $#{$v}) {
	    CleanData($v->[$i]);
	    if (ref($v->[$i]) eq "ARRAY" && $#{$v->[$i]}==-1) { 
		    $v->[$i] = undef; 
		    next; 
	    }
	}
	# this removes any undefined elements from the array
	@{$v} = grep { defined $_ } @{$v};
    } elsif (ref($v) eq "HASH") {
	foreach my $x (keys %{$v}) {
	    CleanData($v->{$x});
	    if (!defined $v->{$x}) { delete($v->{$x}); next; }
	    if (ref($v->{$x}) eq "ARRAY" && $#{$v->{$x}}==-1) { delete($v->{$x}); next; }
	}
    }
	return $v;
}

sub _Error {
    if (exists $_[0]->YYData->{ERRMSG}) {
		print $_[0]->YYData->{ERRMSG};
		delete $_[0]->YYData->{ERRMSG};
		return;
	};
	my $line = $_[0]->YYData->{LINE};
	my $last_token = $_[0]->YYData->{LAST_TOKEN};
	my $file = $_[0]->YYData->{INPUT_FILENAME};
	
	print "$file:$line: Syntax error near '$last_token'\n";
}

sub _Lexer($)
{
	my($parser)=shift;

    $parser->YYData->{INPUT} or return('',undef);

again:
	$parser->YYData->{INPUT} =~ s/^[ \t]*//;

	for ($parser->YYData->{INPUT}) {
		if (/^\#/) {
			if (s/^\# (\d+) \"(.*?)\"( \d+|)//) {
				$parser->YYData->{LINE} = $1-1;
				$parser->YYData->{INPUT_FILENAME} = $2;
				goto again;
			}
			if (s/^\#line (\d+) \"(.*?)\"( \d+|)//) {
				$parser->YYData->{LINE} = $1-1;
				$parser->YYData->{INPUT_FILENAME} = $2;
				goto again;
			}
			if (s/^(\#.*)$//m) {
				goto again;
			}
		}
		if (s/^(\n)//) {
			$parser->YYData->{LINE}++;
			goto again;
		}
		if (s/^\"(.*?)\"//) {
			$parser->YYData->{LAST_TOKEN} = $1;
			return('TEXT',$1); 
		}
		if (s/^(\d+)(\W|$)/$2/) {
			$parser->YYData->{LAST_TOKEN} = $1;
			return('CONSTANT',$1); 
		}
		if (s/^([\w_]+)//) {
			$parser->YYData->{LAST_TOKEN} = $1;
			if ($1 =~ 
			    /^(coclass|interface|const|typedef|declare|union
			      |struct|enum|bitmap|void)$/x) {
				return $1;
			}
			return('IDENTIFIER',$1);
		}
		if (s/^(.)//s) {
			$parser->YYData->{LAST_TOKEN} = $1;
			return($1,$1);
		}
	}
}

sub parse_idl($$)
{
	my ($self,$filename) = @_;

	my $saved_delim = $/;
	undef $/;
	my $cpp = $ENV{CPP};
	if (! defined $cpp) {
		$cpp = "cpp";
	}
	my $data = `$cpp -D__PIDL__ -xc $filename`;
	$/ = $saved_delim;

    $self->YYData->{INPUT} = $data;
    $self->YYData->{LINE} = 0;
    $self->YYData->{LAST_TOKEN} = "NONE";

	my $idl = $self->YYParse( yylex => \&_Lexer, yyerror => \&_Error );

	return CleanData($idl);
}

1;
