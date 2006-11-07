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
			'' => 2,
			"importlib" => 3,
			"import" => 6,
			"include" => 11
		},
		DEFAULT => -92,
		GOTOS => {
			'importlib' => 9,
			'interface' => 8,
			'include' => 4,
			'coclass' => 10,
			'import' => 7,
			'property_list' => 5
		}
	},
	{#State 2
		DEFAULT => 0
	},
	{#State 3
		ACTIONS => {
			'TEXT' => 13
		},
		GOTOS => {
			'commalist' => 12,
			'text' => 14
		}
	},
	{#State 4
		DEFAULT => -5
	},
	{#State 5
		ACTIONS => {
			"coclass" => 15,
			"[" => 17,
			"interface" => 16
		}
	},
	{#State 6
		ACTIONS => {
			'TEXT' => 13
		},
		GOTOS => {
			'commalist' => 18,
			'text' => 14
		}
	},
	{#State 7
		DEFAULT => -4
	},
	{#State 8
		DEFAULT => -2
	},
	{#State 9
		DEFAULT => -6
	},
	{#State 10
		DEFAULT => -3
	},
	{#State 11
		ACTIONS => {
			'TEXT' => 13
		},
		GOTOS => {
			'commalist' => 19,
			'text' => 14
		}
	},
	{#State 12
		ACTIONS => {
			";" => 20,
			"," => 21
		}
	},
	{#State 13
		DEFAULT => -125
	},
	{#State 14
		DEFAULT => -10
	},
	{#State 15
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 23
		}
	},
	{#State 16
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 24
		}
	},
	{#State 17
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 26,
			'property' => 27,
			'properties' => 25
		}
	},
	{#State 18
		ACTIONS => {
			";" => 28,
			"," => 21
		}
	},
	{#State 19
		ACTIONS => {
			";" => 29,
			"," => 21
		}
	},
	{#State 20
		DEFAULT => -9
	},
	{#State 21
		ACTIONS => {
			'TEXT' => 13
		},
		GOTOS => {
			'text' => 30
		}
	},
	{#State 22
		DEFAULT => -121
	},
	{#State 23
		ACTIONS => {
			"{" => 31
		}
	},
	{#State 24
		ACTIONS => {
			":" => 32
		},
		DEFAULT => -16,
		GOTOS => {
			'base_interface' => 33
		}
	},
	{#State 25
		ACTIONS => {
			"," => 34,
			"]" => 35
		}
	},
	{#State 26
		ACTIONS => {
			"(" => 36
		},
		DEFAULT => -96
	},
	{#State 27
		DEFAULT => -94
	},
	{#State 28
		DEFAULT => -7
	},
	{#State 29
		DEFAULT => -8
	},
	{#State 30
		DEFAULT => -11
	},
	{#State 31
		DEFAULT => -13,
		GOTOS => {
			'interface_names' => 37
		}
	},
	{#State 32
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 38
		}
	},
	{#State 33
		ACTIONS => {
			"{" => 39
		}
	},
	{#State 34
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 26,
			'property' => 40
		}
	},
	{#State 35
		DEFAULT => -93
	},
	{#State 36
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'text' => 46,
			'listtext' => 42,
			'anytext' => 41,
			'constant' => 43
		}
	},
	{#State 37
		ACTIONS => {
			"}" => 47,
			"interface" => 48
		}
	},
	{#State 38
		DEFAULT => -17
	},
	{#State 39
		ACTIONS => {
			"typedef" => 49,
			"union" => 50,
			"enum" => 63,
			"bitmap" => 64,
			"declare" => 56,
			"const" => 58,
			"struct" => 61
		},
		DEFAULT => -92,
		GOTOS => {
			'typedecl' => 62,
			'function' => 51,
			'bitmap' => 65,
			'definitions' => 52,
			'definition' => 55,
			'property_list' => 54,
			'usertype' => 53,
			'declare' => 67,
			'const' => 66,
			'struct' => 57,
			'enum' => 59,
			'typedef' => 60,
			'union' => 68
		}
	},
	{#State 40
		DEFAULT => -95
	},
	{#State 41
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 74,
			"?" => 75,
			"{" => 76,
			"&" => 77,
			"/" => 78,
			"=" => 79,
			"(" => 80,
			"|" => 81,
			"." => 82,
			">" => 83
		},
		DEFAULT => -98
	},
	{#State 42
		ACTIONS => {
			"," => 84,
			")" => 85
		}
	},
	{#State 43
		DEFAULT => -104
	},
	{#State 44
		DEFAULT => -124
	},
	{#State 45
		DEFAULT => -103
	},
	{#State 46
		DEFAULT => -105
	},
	{#State 47
		ACTIONS => {
			";" => 86
		},
		DEFAULT => -126,
		GOTOS => {
			'optional_semicolon' => 87
		}
	},
	{#State 48
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 88
		}
	},
	{#State 49
		DEFAULT => -92,
		GOTOS => {
			'property_list' => 89
		}
	},
	{#State 50
		ACTIONS => {
			'IDENTIFIER' => 90
		},
		DEFAULT => -123,
		GOTOS => {
			'optional_identifier' => 91
		}
	},
	{#State 51
		DEFAULT => -20
	},
	{#State 52
		ACTIONS => {
			"}" => 92,
			"typedef" => 49,
			"union" => 50,
			"enum" => 63,
			"bitmap" => 64,
			"declare" => 56,
			"const" => 58,
			"struct" => 61
		},
		DEFAULT => -92,
		GOTOS => {
			'typedecl' => 62,
			'function' => 51,
			'bitmap' => 65,
			'definition' => 93,
			'property_list' => 54,
			'usertype' => 53,
			'const' => 66,
			'struct' => 57,
			'declare' => 67,
			'enum' => 59,
			'typedef' => 60,
			'union' => 68
		}
	},
	{#State 53
		ACTIONS => {
			";" => 94
		}
	},
	{#State 54
		ACTIONS => {
			'IDENTIFIER' => 22,
			"signed" => 100,
			"union" => 50,
			"enum" => 63,
			"bitmap" => 64,
			'void' => 95,
			"unsigned" => 101,
			"[" => 17,
			"struct" => 61
		},
		GOTOS => {
			'existingtype' => 99,
			'bitmap' => 65,
			'usertype' => 96,
			'identifier' => 97,
			'struct' => 57,
			'enum' => 59,
			'type' => 102,
			'union' => 68,
			'sign' => 98
		}
	},
	{#State 55
		DEFAULT => -18
	},
	{#State 56
		DEFAULT => -92,
		GOTOS => {
			'property_list' => 103
		}
	},
	{#State 57
		DEFAULT => -36
	},
	{#State 58
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 104
		}
	},
	{#State 59
		DEFAULT => -38
	},
	{#State 60
		DEFAULT => -22
	},
	{#State 61
		ACTIONS => {
			'IDENTIFIER' => 90
		},
		DEFAULT => -123,
		GOTOS => {
			'optional_identifier' => 105
		}
	},
	{#State 62
		DEFAULT => -24
	},
	{#State 63
		ACTIONS => {
			'IDENTIFIER' => 90
		},
		DEFAULT => -123,
		GOTOS => {
			'optional_identifier' => 106
		}
	},
	{#State 64
		ACTIONS => {
			'IDENTIFIER' => 90
		},
		DEFAULT => -123,
		GOTOS => {
			'optional_identifier' => 107
		}
	},
	{#State 65
		DEFAULT => -39
	},
	{#State 66
		DEFAULT => -21
	},
	{#State 67
		DEFAULT => -23
	},
	{#State 68
		DEFAULT => -37
	},
	{#State 69
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 108,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 70
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 109,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 71
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 110,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 72
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 111,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 73
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 112,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 74
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 113,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 75
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 114,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 76
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 115,
			'text' => 46,
			'constant' => 43,
			'commalisttext' => 116
		}
	},
	{#State 77
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 117,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 78
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 118,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 79
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 119,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 80
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 115,
			'text' => 46,
			'constant' => 43,
			'commalisttext' => 120
		}
	},
	{#State 81
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 121,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 82
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 122,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 83
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 123,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 84
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 124,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 85
		DEFAULT => -97
	},
	{#State 86
		DEFAULT => -127
	},
	{#State 87
		DEFAULT => -12
	},
	{#State 88
		ACTIONS => {
			";" => 125
		}
	},
	{#State 89
		ACTIONS => {
			'IDENTIFIER' => 22,
			"signed" => 100,
			"union" => 50,
			"enum" => 63,
			"bitmap" => 64,
			'void' => 95,
			"unsigned" => 101,
			"[" => 17,
			"struct" => 61
		},
		GOTOS => {
			'existingtype' => 99,
			'bitmap' => 65,
			'usertype' => 96,
			'identifier' => 97,
			'struct' => 57,
			'enum' => 59,
			'type' => 126,
			'union' => 68,
			'sign' => 98
		}
	},
	{#State 90
		DEFAULT => -122
	},
	{#State 91
		ACTIONS => {
			"{" => 128
		},
		DEFAULT => -77,
		GOTOS => {
			'union_body' => 129,
			'opt_union_body' => 127
		}
	},
	{#State 92
		ACTIONS => {
			";" => 86
		},
		DEFAULT => -126,
		GOTOS => {
			'optional_semicolon' => 130
		}
	},
	{#State 93
		DEFAULT => -19
	},
	{#State 94
		DEFAULT => -40
	},
	{#State 95
		DEFAULT => -48
	},
	{#State 96
		DEFAULT => -46
	},
	{#State 97
		DEFAULT => -45
	},
	{#State 98
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 131
		}
	},
	{#State 99
		DEFAULT => -47
	},
	{#State 100
		DEFAULT => -41
	},
	{#State 101
		DEFAULT => -42
	},
	{#State 102
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 132
		}
	},
	{#State 103
		ACTIONS => {
			"union" => 133,
			"enum" => 138,
			"bitmap" => 139,
			"[" => 17
		},
		GOTOS => {
			'decl_enum' => 134,
			'decl_bitmap' => 135,
			'decl_type' => 137,
			'decl_union' => 136
		}
	},
	{#State 104
		DEFAULT => -81,
		GOTOS => {
			'pointers' => 140
		}
	},
	{#State 105
		ACTIONS => {
			"{" => 142
		},
		DEFAULT => -67,
		GOTOS => {
			'struct_body' => 141,
			'opt_struct_body' => 143
		}
	},
	{#State 106
		ACTIONS => {
			"{" => 144
		},
		DEFAULT => -50,
		GOTOS => {
			'opt_enum_body' => 146,
			'enum_body' => 145
		}
	},
	{#State 107
		ACTIONS => {
			"{" => 148
		},
		DEFAULT => -58,
		GOTOS => {
			'bitmap_body' => 149,
			'opt_bitmap_body' => 147
		}
	},
	{#State 108
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 74,
			"?" => 75,
			"{" => 76,
			"&" => 77,
			"/" => 78,
			"=" => 79,
			"(" => 80,
			"|" => 81,
			"." => 82,
			">" => 83
		},
		DEFAULT => -115
	},
	{#State 109
		ACTIONS => {
			":" => 69,
			"<" => 71,
			"~" => 72,
			"?" => 75,
			"{" => 76,
			"=" => 79
		},
		DEFAULT => -106
	},
	{#State 110
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 74,
			"?" => 75,
			"{" => 76,
			"&" => 77,
			"/" => 78,
			"=" => 79,
			"(" => 80,
			"|" => 81,
			"." => 82,
			">" => 83
		},
		DEFAULT => -110
	},
	{#State 111
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 74,
			"?" => 75,
			"{" => 76,
			"&" => 77,
			"/" => 78,
			"=" => 79,
			"(" => 80,
			"|" => 81,
			"." => 82,
			">" => 83
		},
		DEFAULT => -118
	},
	{#State 112
		ACTIONS => {
			":" => 69,
			"<" => 71,
			"~" => 72,
			"?" => 75,
			"{" => 76,
			"=" => 79
		},
		DEFAULT => -117
	},
	{#State 113
		ACTIONS => {
			":" => 69,
			"<" => 71,
			"~" => 72,
			"?" => 75,
			"{" => 76,
			"=" => 79
		},
		DEFAULT => -108
	},
	{#State 114
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 74,
			"?" => 75,
			"{" => 76,
			"&" => 77,
			"/" => 78,
			"=" => 79,
			"(" => 80,
			"|" => 81,
			"." => 82,
			">" => 83
		},
		DEFAULT => -114
	},
	{#State 115
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 74,
			"?" => 75,
			"{" => 76,
			"&" => 77,
			"/" => 78,
			"=" => 79,
			"(" => 80,
			"|" => 81,
			"." => 82,
			">" => 83
		},
		DEFAULT => -100
	},
	{#State 116
		ACTIONS => {
			"}" => 150,
			"," => 151
		}
	},
	{#State 117
		ACTIONS => {
			":" => 69,
			"<" => 71,
			"~" => 72,
			"?" => 75,
			"{" => 76,
			"=" => 79
		},
		DEFAULT => -112
	},
	{#State 118
		ACTIONS => {
			":" => 69,
			"<" => 71,
			"~" => 72,
			"?" => 75,
			"{" => 76,
			"=" => 79
		},
		DEFAULT => -113
	},
	{#State 119
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 74,
			"?" => 75,
			"{" => 76,
			"&" => 77,
			"/" => 78,
			"=" => 79,
			"(" => 80,
			"|" => 81,
			"." => 82,
			">" => 83
		},
		DEFAULT => -116
	},
	{#State 120
		ACTIONS => {
			"," => 151,
			")" => 152
		}
	},
	{#State 121
		ACTIONS => {
			":" => 69,
			"<" => 71,
			"~" => 72,
			"?" => 75,
			"{" => 76,
			"=" => 79
		},
		DEFAULT => -111
	},
	{#State 122
		ACTIONS => {
			":" => 69,
			"<" => 71,
			"~" => 72,
			"?" => 75,
			"{" => 76,
			"=" => 79
		},
		DEFAULT => -107
	},
	{#State 123
		ACTIONS => {
			":" => 69,
			"<" => 71,
			"~" => 72,
			"?" => 75,
			"{" => 76,
			"=" => 79
		},
		DEFAULT => -109
	},
	{#State 124
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 74,
			"?" => 75,
			"{" => 76,
			"&" => 77,
			"/" => 78,
			"=" => 79,
			"(" => 80,
			"|" => 81,
			"." => 82,
			">" => 83
		},
		DEFAULT => -99
	},
	{#State 125
		DEFAULT => -14
	},
	{#State 126
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 153
		}
	},
	{#State 127
		DEFAULT => -79
	},
	{#State 128
		DEFAULT => -74,
		GOTOS => {
			'union_elements' => 154
		}
	},
	{#State 129
		DEFAULT => -78
	},
	{#State 130
		DEFAULT => -15
	},
	{#State 131
		DEFAULT => -44
	},
	{#State 132
		ACTIONS => {
			"(" => 155
		}
	},
	{#State 133
		DEFAULT => -34
	},
	{#State 134
		DEFAULT => -29
	},
	{#State 135
		DEFAULT => -30
	},
	{#State 136
		DEFAULT => -31
	},
	{#State 137
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 156
		}
	},
	{#State 138
		DEFAULT => -32
	},
	{#State 139
		DEFAULT => -33
	},
	{#State 140
		ACTIONS => {
			'IDENTIFIER' => 22,
			"*" => 158
		},
		GOTOS => {
			'identifier' => 157
		}
	},
	{#State 141
		DEFAULT => -68
	},
	{#State 142
		DEFAULT => -83,
		GOTOS => {
			'element_list1' => 159
		}
	},
	{#State 143
		DEFAULT => -69
	},
	{#State 144
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 160,
			'enum_element' => 161,
			'enum_elements' => 162
		}
	},
	{#State 145
		DEFAULT => -51
	},
	{#State 146
		DEFAULT => -52
	},
	{#State 147
		DEFAULT => -60
	},
	{#State 148
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		DEFAULT => -63,
		GOTOS => {
			'identifier' => 165,
			'bitmap_element' => 164,
			'bitmap_elements' => 163,
			'opt_bitmap_elements' => 166
		}
	},
	{#State 149
		DEFAULT => -59
	},
	{#State 150
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 167,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 151
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 168,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 152
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 169,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 153
		ACTIONS => {
			"[" => 170
		},
		DEFAULT => -89,
		GOTOS => {
			'array_len' => 171
		}
	},
	{#State 154
		ACTIONS => {
			"}" => 172
		},
		DEFAULT => -92,
		GOTOS => {
			'optional_base_element' => 174,
			'property_list' => 173
		}
	},
	{#State 155
		ACTIONS => {
			"," => -85,
			"void" => 178,
			")" => -85
		},
		DEFAULT => -92,
		GOTOS => {
			'base_element' => 175,
			'element_list2' => 177,
			'property_list' => 176
		}
	},
	{#State 156
		ACTIONS => {
			";" => 179
		}
	},
	{#State 157
		ACTIONS => {
			"[" => 170,
			"=" => 181
		},
		GOTOS => {
			'array_len' => 180
		}
	},
	{#State 158
		DEFAULT => -82
	},
	{#State 159
		ACTIONS => {
			"}" => 182
		},
		DEFAULT => -92,
		GOTOS => {
			'base_element' => 183,
			'property_list' => 176
		}
	},
	{#State 160
		ACTIONS => {
			"=" => 184
		},
		DEFAULT => -55
	},
	{#State 161
		DEFAULT => -53
	},
	{#State 162
		ACTIONS => {
			"}" => 185,
			"," => 186
		}
	},
	{#State 163
		ACTIONS => {
			"," => 187
		},
		DEFAULT => -64
	},
	{#State 164
		DEFAULT => -61
	},
	{#State 165
		ACTIONS => {
			"=" => 188
		}
	},
	{#State 166
		ACTIONS => {
			"}" => 189
		}
	},
	{#State 167
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 74,
			"?" => 75,
			"{" => 76,
			"&" => 77,
			"/" => 78,
			"=" => 79,
			"(" => 80,
			"|" => 81,
			"." => 82,
			">" => 83
		},
		DEFAULT => -120
	},
	{#State 168
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 74,
			"?" => 75,
			"{" => 76,
			"&" => 77,
			"/" => 78,
			"=" => 79,
			"(" => 80,
			"|" => 81,
			"." => 82,
			">" => 83
		},
		DEFAULT => -101
	},
	{#State 169
		ACTIONS => {
			":" => 69,
			"<" => 71,
			"~" => 72,
			"?" => 75,
			"{" => 76,
			"=" => 79
		},
		DEFAULT => -119
	},
	{#State 170
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			"]" => 190,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 191,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 171
		ACTIONS => {
			";" => 192
		}
	},
	{#State 172
		DEFAULT => -76
	},
	{#State 173
		ACTIONS => {
			"[" => 17
		},
		DEFAULT => -92,
		GOTOS => {
			'base_or_empty' => 193,
			'base_element' => 194,
			'empty_element' => 195,
			'property_list' => 196
		}
	},
	{#State 174
		DEFAULT => -75
	},
	{#State 175
		DEFAULT => -87
	},
	{#State 176
		ACTIONS => {
			'IDENTIFIER' => 22,
			"signed" => 100,
			"union" => 50,
			"enum" => 63,
			"bitmap" => 64,
			'void' => 95,
			"unsigned" => 101,
			"[" => 17,
			"struct" => 61
		},
		DEFAULT => -43,
		GOTOS => {
			'existingtype' => 99,
			'bitmap' => 65,
			'usertype' => 96,
			'identifier' => 97,
			'struct' => 57,
			'enum' => 59,
			'type' => 197,
			'union' => 68,
			'sign' => 98
		}
	},
	{#State 177
		ACTIONS => {
			"," => 198,
			")" => 199
		}
	},
	{#State 178
		DEFAULT => -86
	},
	{#State 179
		DEFAULT => -28
	},
	{#State 180
		ACTIONS => {
			"=" => 200
		}
	},
	{#State 181
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 201,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 182
		DEFAULT => -66
	},
	{#State 183
		ACTIONS => {
			";" => 202
		}
	},
	{#State 184
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 203,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 185
		DEFAULT => -49
	},
	{#State 186
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 160,
			'enum_element' => 204
		}
	},
	{#State 187
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 165,
			'bitmap_element' => 205
		}
	},
	{#State 188
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 206,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 189
		DEFAULT => -57
	},
	{#State 190
		ACTIONS => {
			"[" => 170
		},
		DEFAULT => -89,
		GOTOS => {
			'array_len' => 207
		}
	},
	{#State 191
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"?" => 75,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"&" => 77,
			"{" => 76,
			"/" => 78,
			"=" => 79,
			"|" => 81,
			"(" => 80,
			"*" => 74,
			"." => 82,
			"]" => 208,
			">" => 83
		}
	},
	{#State 192
		DEFAULT => -35
	},
	{#State 193
		DEFAULT => -73
	},
	{#State 194
		ACTIONS => {
			";" => 209
		}
	},
	{#State 195
		DEFAULT => -72
	},
	{#State 196
		ACTIONS => {
			'IDENTIFIER' => 22,
			"signed" => 100,
			"union" => 50,
			";" => 210,
			"enum" => 63,
			"bitmap" => 64,
			'void' => 95,
			"unsigned" => 101,
			"[" => 17,
			"struct" => 61
		},
		DEFAULT => -43,
		GOTOS => {
			'existingtype' => 99,
			'bitmap' => 65,
			'usertype' => 96,
			'identifier' => 97,
			'struct' => 57,
			'enum' => 59,
			'type' => 197,
			'union' => 68,
			'sign' => 98
		}
	},
	{#State 197
		DEFAULT => -81,
		GOTOS => {
			'pointers' => 211
		}
	},
	{#State 198
		DEFAULT => -92,
		GOTOS => {
			'base_element' => 212,
			'property_list' => 176
		}
	},
	{#State 199
		ACTIONS => {
			";" => 213
		}
	},
	{#State 200
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -102,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 214,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 201
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"?" => 75,
			"<" => 71,
			";" => 215,
			"+" => 73,
			"~" => 72,
			"&" => 77,
			"{" => 76,
			"/" => 78,
			"=" => 79,
			"|" => 81,
			"(" => 80,
			"*" => 74,
			"." => 82,
			">" => 83
		}
	},
	{#State 202
		DEFAULT => -84
	},
	{#State 203
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 74,
			"?" => 75,
			"{" => 76,
			"&" => 77,
			"/" => 78,
			"=" => 79,
			"(" => 80,
			"|" => 81,
			"." => 82,
			">" => 83
		},
		DEFAULT => -56
	},
	{#State 204
		DEFAULT => -54
	},
	{#State 205
		DEFAULT => -62
	},
	{#State 206
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 74,
			"?" => 75,
			"{" => 76,
			"&" => 77,
			"/" => 78,
			"=" => 79,
			"(" => 80,
			"|" => 81,
			"." => 82,
			">" => 83
		},
		DEFAULT => -65
	},
	{#State 207
		DEFAULT => -90
	},
	{#State 208
		ACTIONS => {
			"[" => 170
		},
		DEFAULT => -89,
		GOTOS => {
			'array_len' => 216
		}
	},
	{#State 209
		DEFAULT => -71
	},
	{#State 210
		DEFAULT => -70
	},
	{#State 211
		ACTIONS => {
			'IDENTIFIER' => 22,
			"*" => 158
		},
		GOTOS => {
			'identifier' => 217
		}
	},
	{#State 212
		DEFAULT => -88
	},
	{#State 213
		DEFAULT => -27
	},
	{#State 214
		ACTIONS => {
			"-" => 70,
			":" => 69,
			"?" => 75,
			"<" => 71,
			";" => 218,
			"+" => 73,
			"~" => 72,
			"&" => 77,
			"{" => 76,
			"/" => 78,
			"=" => 79,
			"|" => 81,
			"(" => 80,
			"*" => 74,
			"." => 82,
			">" => 83
		}
	},
	{#State 215
		DEFAULT => -25
	},
	{#State 216
		DEFAULT => -91
	},
	{#State 217
		ACTIONS => {
			"[" => 170
		},
		DEFAULT => -89,
		GOTOS => {
			'array_len' => 219
		}
	},
	{#State 218
		DEFAULT => -26
	},
	{#State 219
		DEFAULT => -80
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
#line 19 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 3
		 'idl', 2,
sub
#line 20 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 4
		 'idl', 2,
sub
#line 21 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 5
		 'idl', 2,
sub
#line 22 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 6
		 'idl', 2,
sub
#line 23 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 7
		 'import', 3,
sub
#line 26 "pidl/idl.yp"
{{
			"TYPE" => "IMPORT", 
			"PATHS" => $_[2],
		   "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 8
		 'include', 3,
sub
#line 33 "pidl/idl.yp"
{{ 
			"TYPE" => "INCLUDE", 
			"PATHS" => $_[2],
		   "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 9
		 'importlib', 3,
sub
#line 40 "pidl/idl.yp"
{{ 
			"TYPE" => "IMPORTLIB", 
			"PATHS" => $_[2],
		   "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 10
		 'commalist', 1,
sub
#line 49 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 11
		 'commalist', 3,
sub
#line 50 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 12
		 'coclass', 7,
sub
#line 54 "pidl/idl.yp"
{{
               "TYPE" => "COCLASS", 
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "DATA" => $_[5],
		   "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 13
		 'interface_names', 0, undef
	],
	[#Rule 14
		 'interface_names', 4,
sub
#line 66 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 15
		 'interface', 8,
sub
#line 70 "pidl/idl.yp"
{{
               "TYPE" => "INTERFACE", 
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "BASE" => $_[4],
	       "DATA" => $_[6],
		   "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 16
		 'base_interface', 0, undef
	],
	[#Rule 17
		 'base_interface', 2,
sub
#line 83 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 18
		 'definitions', 1,
sub
#line 87 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 19
		 'definitions', 2,
sub
#line 88 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 20
		 'definition', 1, undef
	],
	[#Rule 21
		 'definition', 1, undef
	],
	[#Rule 22
		 'definition', 1, undef
	],
	[#Rule 23
		 'definition', 1, undef
	],
	[#Rule 24
		 'definition', 1, undef
	],
	[#Rule 25
		 'const', 7,
sub
#line 96 "pidl/idl.yp"
{{
                     "TYPE"  => "CONST", 
		     "DTYPE"  => $_[2],
			 "POINTERS" => $_[3],
		     "NAME"  => $_[4],
		     "VALUE" => $_[6],
		     "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 26
		 'const', 8,
sub
#line 106 "pidl/idl.yp"
{{
                     "TYPE"  => "CONST", 
		     "DTYPE"  => $_[2],
			 "POINTERS" => $_[3],
		     "NAME"  => $_[4],
		     "ARRAY_LEN" => $_[5],
		     "VALUE" => $_[7],
		     "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 27
		 'function', 7,
sub
#line 120 "pidl/idl.yp"
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
	[#Rule 28
		 'declare', 5,
sub
#line 132 "pidl/idl.yp"
{{
	             "TYPE" => "DECLARE", 
                     "PROPERTIES" => $_[2],
		     "NAME" => $_[4],
		     "DATA" => $_[3],
		     "FILE" => $_[0]->YYData->{INPUT_FILENAME},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 29
		 'decl_type', 1, undef
	],
	[#Rule 30
		 'decl_type', 1, undef
	],
	[#Rule 31
		 'decl_type', 1, undef
	],
	[#Rule 32
		 'decl_enum', 1,
sub
#line 146 "pidl/idl.yp"
{{
                     "TYPE" => "ENUM"
        }}
	],
	[#Rule 33
		 'decl_bitmap', 1,
sub
#line 152 "pidl/idl.yp"
{{
                     "TYPE" => "BITMAP"
        }}
	],
	[#Rule 34
		 'decl_union', 1,
sub
#line 158 "pidl/idl.yp"
{{
                     "TYPE" => "UNION"
        }}
	],
	[#Rule 35
		 'typedef', 6,
sub
#line 164 "pidl/idl.yp"
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
	[#Rule 36
		 'usertype', 1, undef
	],
	[#Rule 37
		 'usertype', 1, undef
	],
	[#Rule 38
		 'usertype', 1, undef
	],
	[#Rule 39
		 'usertype', 1, undef
	],
	[#Rule 40
		 'typedecl', 2,
sub
#line 177 "pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 41
		 'sign', 1, undef
	],
	[#Rule 42
		 'sign', 1, undef
	],
	[#Rule 43
		 'existingtype', 0, undef
	],
	[#Rule 44
		 'existingtype', 2,
sub
#line 182 "pidl/idl.yp"
{ "$_[1] $_[2]" }
	],
	[#Rule 45
		 'existingtype', 1, undef
	],
	[#Rule 46
		 'type', 1, undef
	],
	[#Rule 47
		 'type', 1, undef
	],
	[#Rule 48
		 'type', 1,
sub
#line 186 "pidl/idl.yp"
{ "void" }
	],
	[#Rule 49
		 'enum_body', 3,
sub
#line 188 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 50
		 'opt_enum_body', 0, undef
	],
	[#Rule 51
		 'opt_enum_body', 1, undef
	],
	[#Rule 52
		 'enum', 3,
sub
#line 191 "pidl/idl.yp"
{{
             "TYPE" => "ENUM", 
			 "NAME" => $_[2],
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 53
		 'enum_elements', 1,
sub
#line 199 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 54
		 'enum_elements', 3,
sub
#line 200 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 55
		 'enum_element', 1, undef
	],
	[#Rule 56
		 'enum_element', 3,
sub
#line 204 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 57
		 'bitmap_body', 3,
sub
#line 207 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 58
		 'opt_bitmap_body', 0, undef
	],
	[#Rule 59
		 'opt_bitmap_body', 1, undef
	],
	[#Rule 60
		 'bitmap', 3,
sub
#line 210 "pidl/idl.yp"
{{
             "TYPE" => "BITMAP", 
			 "NAME" => $_[2],
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 61
		 'bitmap_elements', 1,
sub
#line 218 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 62
		 'bitmap_elements', 3,
sub
#line 219 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 63
		 'opt_bitmap_elements', 0, undef
	],
	[#Rule 64
		 'opt_bitmap_elements', 1, undef
	],
	[#Rule 65
		 'bitmap_element', 3,
sub
#line 224 "pidl/idl.yp"
{ "$_[1] ( $_[3] )" }
	],
	[#Rule 66
		 'struct_body', 3,
sub
#line 227 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 67
		 'opt_struct_body', 0, undef
	],
	[#Rule 68
		 'opt_struct_body', 1, undef
	],
	[#Rule 69
		 'struct', 3,
sub
#line 231 "pidl/idl.yp"
{{
             "TYPE" => "STRUCT", 
			 "NAME" => $_[2],
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 70
		 'empty_element', 2,
sub
#line 239 "pidl/idl.yp"
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
	[#Rule 71
		 'base_or_empty', 2, undef
	],
	[#Rule 72
		 'base_or_empty', 1, undef
	],
	[#Rule 73
		 'optional_base_element', 2,
sub
#line 253 "pidl/idl.yp"
{ $_[2]->{PROPERTIES} = FlattenHash([$_[1],$_[2]->{PROPERTIES}]); $_[2] }
	],
	[#Rule 74
		 'union_elements', 0, undef
	],
	[#Rule 75
		 'union_elements', 2,
sub
#line 258 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 76
		 'union_body', 3,
sub
#line 261 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 77
		 'opt_union_body', 0, undef
	],
	[#Rule 78
		 'opt_union_body', 1, undef
	],
	[#Rule 79
		 'union', 3,
sub
#line 265 "pidl/idl.yp"
{{
             "TYPE" => "UNION", 
		     "NAME" => $_[2],
		     "ELEMENTS" => $_[3]
        }}
	],
	[#Rule 80
		 'base_element', 5,
sub
#line 273 "pidl/idl.yp"
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
	[#Rule 81
		 'pointers', 0,
sub
#line 287 "pidl/idl.yp"
{ 0 }
	],
	[#Rule 82
		 'pointers', 2,
sub
#line 288 "pidl/idl.yp"
{ $_[1]+1 }
	],
	[#Rule 83
		 'element_list1', 0, undef
	],
	[#Rule 84
		 'element_list1', 3,
sub
#line 293 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 85
		 'element_list2', 0, undef
	],
	[#Rule 86
		 'element_list2', 1, undef
	],
	[#Rule 87
		 'element_list2', 1,
sub
#line 299 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 88
		 'element_list2', 3,
sub
#line 300 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 89
		 'array_len', 0, undef
	],
	[#Rule 90
		 'array_len', 3,
sub
#line 305 "pidl/idl.yp"
{ push(@{$_[3]}, "*"); $_[3] }
	],
	[#Rule 91
		 'array_len', 4,
sub
#line 306 "pidl/idl.yp"
{ push(@{$_[4]}, "$_[2]"); $_[4] }
	],
	[#Rule 92
		 'property_list', 0, undef
	],
	[#Rule 93
		 'property_list', 4,
sub
#line 312 "pidl/idl.yp"
{ FlattenHash([$_[1],$_[3]]); }
	],
	[#Rule 94
		 'properties', 1,
sub
#line 315 "pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 95
		 'properties', 3,
sub
#line 316 "pidl/idl.yp"
{ FlattenHash([$_[1], $_[3]]); }
	],
	[#Rule 96
		 'property', 1,
sub
#line 319 "pidl/idl.yp"
{{ "$_[1]" => "1"     }}
	],
	[#Rule 97
		 'property', 4,
sub
#line 320 "pidl/idl.yp"
{{ "$_[1]" => "$_[3]" }}
	],
	[#Rule 98
		 'listtext', 1, undef
	],
	[#Rule 99
		 'listtext', 3,
sub
#line 325 "pidl/idl.yp"
{ "$_[1] $_[3]" }
	],
	[#Rule 100
		 'commalisttext', 1, undef
	],
	[#Rule 101
		 'commalisttext', 3,
sub
#line 330 "pidl/idl.yp"
{ "$_[1],$_[3]" }
	],
	[#Rule 102
		 'anytext', 0,
sub
#line 334 "pidl/idl.yp"
{ "" }
	],
	[#Rule 103
		 'anytext', 1, undef
	],
	[#Rule 104
		 'anytext', 1, undef
	],
	[#Rule 105
		 'anytext', 1, undef
	],
	[#Rule 106
		 'anytext', 3,
sub
#line 336 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 107
		 'anytext', 3,
sub
#line 337 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 108
		 'anytext', 3,
sub
#line 338 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 109
		 'anytext', 3,
sub
#line 339 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 110
		 'anytext', 3,
sub
#line 340 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 111
		 'anytext', 3,
sub
#line 341 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 112
		 'anytext', 3,
sub
#line 342 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 113
		 'anytext', 3,
sub
#line 343 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 114
		 'anytext', 3,
sub
#line 344 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 115
		 'anytext', 3,
sub
#line 345 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 116
		 'anytext', 3,
sub
#line 346 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 117
		 'anytext', 3,
sub
#line 347 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 118
		 'anytext', 3,
sub
#line 348 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 119
		 'anytext', 5,
sub
#line 349 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 120
		 'anytext', 5,
sub
#line 350 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 121
		 'identifier', 1, undef
	],
	[#Rule 122
		 'optional_identifier', 1, undef
	],
	[#Rule 123
		 'optional_identifier', 0, undef
	],
	[#Rule 124
		 'constant', 1, undef
	],
	[#Rule 125
		 'text', 1,
sub
#line 364 "pidl/idl.yp"
{ "\"$_[1]\"" }
	],
	[#Rule 126
		 'optional_semicolon', 0, undef
	],
	[#Rule 127
		 'optional_semicolon', 1, undef
	]
],
                                  @_);
    bless($self,$class);
}

#line 375 "pidl/idl.yp"


#####################################################################
# flatten an array of hashes into a single hash
sub FlattenHash($) 
{ 
    my $a = shift;
    my %b;
    for my $d (@{$a}) {
	for my $k (keys %{$d}) {
	    $b{$k} = $d->{$k};
	}
    }
    return \%b;
}



#####################################################################
# traverse a perl data structure removing any empty arrays or
# hashes and any hash elements that map to undef
sub CleanData($)
{
    sub CleanData($);
    my($v) = shift;
	return undef if (not defined($v));
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
			      |struct|enum|bitmap|void|unsigned|signed|import|include
				  |importlib)$/x) {
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

sub parse_string
{
	my ($data,$filename) = @_;

	my $self = new Parse::Pidl::IDL;

    $self->YYData->{INPUT_FILENAME} = $filename;
    $self->YYData->{INPUT} = $data;
    $self->YYData->{LINE} = 0;
    $self->YYData->{LAST_TOKEN} = "NONE";

	my $idl = $self->YYParse( yylex => \&_Lexer, yyerror => \&_Error );

	return CleanData($idl);
}

sub parse_file($$)
{
	my ($filename,$incdirs) = @_;

	my $saved_delim = $/;
	undef $/;
	my $cpp = $ENV{CPP};
	if (! defined $cpp) {
		$cpp = "cpp";
	}
	my $includes = join('',map { " -I$_" } @$incdirs);
	my $data = `$cpp -D__PIDL__$includes -xc $filename`;
	$/ = $saved_delim;

	return parse_string($data, $filename);
}

1;
