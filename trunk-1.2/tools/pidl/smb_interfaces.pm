####################################################################
#
#    This file was generated using Parse::Yapp version 1.05.
#
#        Don't edit this file, use source file instead.
#
#             ANY CHANGE MADE HERE WILL BE LOST !
#
####################################################################
package smb_interfaces;
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
		ACTIONS => {
			'UNION' => 5,
			'ENUM' => 1,
			'TYPEDEF' => 7,
			'STRUCT' => 2
		},
		GOTOS => {
			'struct' => 6,
			'enum' => 9,
			'typedef' => 8,
			'union' => 10,
			'definitions' => 3,
			'definition' => 4
		}
	},
	{#State 1
		ACTIONS => {
			'IDENTIFIER' => 11
		}
	},
	{#State 2
		ACTIONS => {
			'IDENTIFIER' => 12
		},
		DEFAULT => -33,
		GOTOS => {
			'optional_identifier' => 13
		}
	},
	{#State 3
		ACTIONS => {
			'' => 14,
			'UNION' => 5,
			'ENUM' => 1,
			'TYPEDEF' => 7,
			'STRUCT' => 2
		},
		GOTOS => {
			'struct' => 6,
			'typedef' => 8,
			'enum' => 9,
			'union' => 10,
			'definition' => 15
		}
	},
	{#State 4
		DEFAULT => -1
	},
	{#State 5
		ACTIONS => {
			'IDENTIFIER' => 12
		},
		DEFAULT => -33,
		GOTOS => {
			'optional_identifier' => 16
		}
	},
	{#State 6
		DEFAULT => -3
	},
	{#State 7
		ACTIONS => {
			'STRUCT' => 17
		}
	},
	{#State 8
		DEFAULT => -5
	},
	{#State 9
		DEFAULT => -6
	},
	{#State 10
		DEFAULT => -4
	},
	{#State 11
		ACTIONS => {
			"{" => 18
		}
	},
	{#State 12
		DEFAULT => -32
	},
	{#State 13
		ACTIONS => {
			"{" => 19
		}
	},
	{#State 14
		DEFAULT => 0
	},
	{#State 15
		DEFAULT => -2
	},
	{#State 16
		ACTIONS => {
			"{" => 20
		}
	},
	{#State 17
		ACTIONS => {
			"{" => 21
		}
	},
	{#State 18
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'enum_identifiers' => 23,
			'enum_identifier' => 24
		}
	},
	{#State 19
		DEFAULT => -15,
		GOTOS => {
			'elements' => 25
		}
	},
	{#State 20
		DEFAULT => -15,
		GOTOS => {
			'elements' => 26
		}
	},
	{#State 21
		DEFAULT => -15,
		GOTOS => {
			'elements' => 27
		}
	},
	{#State 22
		ACTIONS => {
			"=" => 28
		},
		DEFAULT => -13
	},
	{#State 23
		ACTIONS => {
			"}" => 29,
			"," => 30
		}
	},
	{#State 24
		DEFAULT => -11
	},
	{#State 25
		ACTIONS => {
			"}" => 31,
			'UNION' => 37,
			'IDENTIFIER' => 33,
			'ENUM' => 32,
			'STRUCT' => 35,
			'CONST' => 34
		},
		GOTOS => {
			'struct' => 38,
			'type' => 39,
			'union' => 40,
			'element' => 36
		}
	},
	{#State 26
		ACTIONS => {
			"}" => 41,
			'UNION' => 37,
			'IDENTIFIER' => 33,
			'ENUM' => 32,
			'STRUCT' => 35,
			'CONST' => 34
		},
		GOTOS => {
			'struct' => 38,
			'type' => 39,
			'union' => 40,
			'element' => 36
		}
	},
	{#State 27
		ACTIONS => {
			"}" => 42,
			'UNION' => 37,
			'IDENTIFIER' => 33,
			'ENUM' => 32,
			'STRUCT' => 35,
			'CONST' => 34
		},
		GOTOS => {
			'struct' => 38,
			'type' => 39,
			'union' => 40,
			'element' => 36
		}
	},
	{#State 28
		ACTIONS => {
			'IDENTIFIER' => 43
		}
	},
	{#State 29
		ACTIONS => {
			";" => 44
		}
	},
	{#State 30
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'enum_identifier' => 45
		}
	},
	{#State 31
		DEFAULT => -28,
		GOTOS => {
			'pointers' => 46
		}
	},
	{#State 32
		ACTIONS => {
			'IDENTIFIER' => 47
		}
	},
	{#State 33
		DEFAULT => -26
	},
	{#State 34
		ACTIONS => {
			'IDENTIFIER' => 33,
			'ENUM' => 32
		},
		GOTOS => {
			'type' => 48
		}
	},
	{#State 35
		ACTIONS => {
			'IDENTIFIER' => 49
		},
		DEFAULT => -33,
		GOTOS => {
			'optional_identifier' => 13
		}
	},
	{#State 36
		DEFAULT => -16
	},
	{#State 37
		ACTIONS => {
			'IDENTIFIER' => 50
		},
		DEFAULT => -33,
		GOTOS => {
			'optional_identifier' => 16
		}
	},
	{#State 38
		DEFAULT => -18
	},
	{#State 39
		DEFAULT => -28,
		GOTOS => {
			'pointers' => 51
		}
	},
	{#State 40
		DEFAULT => -19
	},
	{#State 41
		DEFAULT => -28,
		GOTOS => {
			'pointers' => 52
		}
	},
	{#State 42
		ACTIONS => {
			'IDENTIFIER' => 12
		},
		DEFAULT => -33,
		GOTOS => {
			'optional_identifier' => 53
		}
	},
	{#State 43
		DEFAULT => -14
	},
	{#State 44
		DEFAULT => -10
	},
	{#State 45
		DEFAULT => -12
	},
	{#State 46
		ACTIONS => {
			'IDENTIFIER' => 12,
			"*" => 55
		},
		DEFAULT => -33,
		GOTOS => {
			'optional_identifier' => 54,
			'optional_identifiers' => 56
		}
	},
	{#State 47
		DEFAULT => -27
	},
	{#State 48
		DEFAULT => -28,
		GOTOS => {
			'pointers' => 57
		}
	},
	{#State 49
		ACTIONS => {
			"{" => -32
		},
		DEFAULT => -28,
		GOTOS => {
			'pointers' => 58
		}
	},
	{#State 50
		ACTIONS => {
			"{" => -32
		},
		DEFAULT => -28,
		GOTOS => {
			'pointers' => 59
		}
	},
	{#State 51
		ACTIONS => {
			'IDENTIFIER' => 60,
			"*" => 55
		}
	},
	{#State 52
		ACTIONS => {
			'IDENTIFIER' => 12,
			"*" => 55
		},
		DEFAULT => -33,
		GOTOS => {
			'optional_identifier' => 61
		}
	},
	{#State 53
		ACTIONS => {
			";" => 62
		}
	},
	{#State 54
		DEFAULT => -30
	},
	{#State 55
		DEFAULT => -29
	},
	{#State 56
		ACTIONS => {
			";" => 63,
			"," => 64
		}
	},
	{#State 57
		ACTIONS => {
			'IDENTIFIER' => 65,
			"*" => 55
		}
	},
	{#State 58
		ACTIONS => {
			'IDENTIFIER' => 66,
			"*" => 55
		}
	},
	{#State 59
		ACTIONS => {
			'IDENTIFIER' => 67,
			"*" => 55
		}
	},
	{#State 60
		ACTIONS => {
			"[" => 69
		},
		DEFAULT => -24,
		GOTOS => {
			'array' => 68
		}
	},
	{#State 61
		ACTIONS => {
			";" => 70
		}
	},
	{#State 62
		DEFAULT => -9
	},
	{#State 63
		DEFAULT => -7
	},
	{#State 64
		ACTIONS => {
			'IDENTIFIER' => 12
		},
		DEFAULT => -33,
		GOTOS => {
			'optional_identifier' => 71
		}
	},
	{#State 65
		ACTIONS => {
			"[" => 69
		},
		DEFAULT => -24,
		GOTOS => {
			'array' => 72
		}
	},
	{#State 66
		ACTIONS => {
			";" => 73
		}
	},
	{#State 67
		ACTIONS => {
			";" => 74
		}
	},
	{#State 68
		ACTIONS => {
			";" => 75
		}
	},
	{#State 69
		ACTIONS => {
			'CONSTANT' => 76
		}
	},
	{#State 70
		DEFAULT => -8
	},
	{#State 71
		DEFAULT => -31
	},
	{#State 72
		ACTIONS => {
			";" => 77
		}
	},
	{#State 73
		DEFAULT => -20
	},
	{#State 74
		DEFAULT => -21
	},
	{#State 75
		DEFAULT => -23
	},
	{#State 76
		ACTIONS => {
			"]" => 78
		}
	},
	{#State 77
		DEFAULT => -22
	},
	{#State 78
		DEFAULT => -25
	}
],
                                  yyrules  =>
[
	[#Rule 0
		 '$start', 2, undef
	],
	[#Rule 1
		 'definitions', 1,
sub
#line 14 "build/pidl/smb_interfaces.yp"
{ [$_[1]] }
	],
	[#Rule 2
		 'definitions', 2,
sub
#line 15 "build/pidl/smb_interfaces.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 3
		 'definition', 1, undef
	],
	[#Rule 4
		 'definition', 1, undef
	],
	[#Rule 5
		 'definition', 1, undef
	],
	[#Rule 6
		 'definition', 1, undef
	],
	[#Rule 7
		 'struct', 8,
sub
#line 26 "build/pidl/smb_interfaces.yp"
{
		{
			"NAME" => $_[7],
			"STRUCT_NAME" => $_[2],
			"TYPE" => "struct",
			"DATA" => $_[4],
		}
	}
	],
	[#Rule 8
		 'union', 8,
sub
#line 38 "build/pidl/smb_interfaces.yp"
{
		{
			"NAME" => $_[7],
			"UNION_NAME" => $_[2],
			"TYPE" => "union",
			"DATA" => $_[4],
		}
	}
	],
	[#Rule 9
		 'typedef', 7, undef
	],
	[#Rule 10
		 'enum', 6, undef
	],
	[#Rule 11
		 'enum_identifiers', 1, undef
	],
	[#Rule 12
		 'enum_identifiers', 3, undef
	],
	[#Rule 13
		 'enum_identifier', 1, undef
	],
	[#Rule 14
		 'enum_identifier', 3, undef
	],
	[#Rule 15
		 'elements', 0, undef
	],
	[#Rule 16
		 'elements', 2,
sub
#line 65 "build/pidl/smb_interfaces.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 17
		 'element', 0, undef
	],
	[#Rule 18
		 'element', 1, undef
	],
	[#Rule 19
		 'element', 1, undef
	],
	[#Rule 20
		 'element', 5,
sub
#line 72 "build/pidl/smb_interfaces.yp"
{{
			"NAME" => [$_[2]],
			"POINTERS" => $_[3],
			"TYPE" => "struct $_[2]",
		}}
	],
	[#Rule 21
		 'element', 5,
sub
#line 78 "build/pidl/smb_interfaces.yp"
{{
			"NAME" => $_[2],
			"POINTERS" => $_[3],
			"TYPE" => "union $_[2]",
		}}
	],
	[#Rule 22
		 'element', 6,
sub
#line 84 "build/pidl/smb_interfaces.yp"
{{
			   "NAME" => [$_[4]],
			   "TYPE" => $_[2],
			   "POINTERS" => $_[3],
		}}
	],
	[#Rule 23
		 'element', 5,
sub
#line 90 "build/pidl/smb_interfaces.yp"
{{
			   "NAME" => [$_[3]],
			   "TYPE" => $_[1],
			   "POINTERS" => $_[2],
			   "ARRAY_LENGTH" => $_[4]
		}}
	],
	[#Rule 24
		 'array', 0, undef
	],
	[#Rule 25
		 'array', 3,
sub
#line 99 "build/pidl/smb_interfaces.yp"
{ int($_[2]) }
	],
	[#Rule 26
		 'type', 1, undef
	],
	[#Rule 27
		 'type', 2,
sub
#line 104 "build/pidl/smb_interfaces.yp"
{ "enum $_[2]" }
	],
	[#Rule 28
		 'pointers', 0, undef
	],
	[#Rule 29
		 'pointers', 2,
sub
#line 109 "build/pidl/smb_interfaces.yp"
{ $_[1]+1 }
	],
	[#Rule 30
		 'optional_identifiers', 1,
sub
#line 112 "build/pidl/smb_interfaces.yp"
{ [$_[1]] }
	],
	[#Rule 31
		 'optional_identifiers', 3,
sub
#line 113 "build/pidl/smb_interfaces.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 32
		 'optional_identifier', 1, undef
	],
	[#Rule 33
		 'optional_identifier', 0, undef
	]
],
                                  @_);
    bless($self,$class);
}

#line 119 "build/pidl/smb_interfaces.yp"


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
			    /^(const|typedef|union|struct|enum)$/x) {
				return uc($1);
			}
			return('IDENTIFIER',$1);
		}
		if (s/^(.)//s) {
			$parser->YYData->{LAST_TOKEN} = $1;
			return($1,$1);
		}
	}
}

sub parse($$)
{
	my ($self,$filename) = @_;

	my $saved_delim = $/;
	undef $/;
	my $cpp = $ENV{CPP};
	if (! defined $cpp) {
		$cpp = "cpp"
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
