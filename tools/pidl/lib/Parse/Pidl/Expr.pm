####################################################################
#
#    This file was generated using Parse::Yapp version 1.05.
#
#        Don't edit this file, use source file instead.
#
#             ANY CHANGE MADE HERE WILL BE LOST !
#
####################################################################
package Parse::Pidl::Expr;
use vars qw ( @ISA );
use strict;

@ISA= qw ( Parse::Yapp::Driver );
use Parse::Yapp::Driver;



sub new {
        my($class)=shift;
        ref($class)
    and $class=ref($class);

    my($self)=$class->SUPER::new( yyversion => '1.05',
                                  yystates =>
[
	{#State 0
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'NUM' => 5,
			'TEXT' => 6,
			"(" => 7,
			"!" => 8,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 2,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 1
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"(" => 7,
			"!" => 8,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 14,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 2
		ACTIONS => {
			'' => 16,
			"-" => 15,
			"<" => 17,
			"+" => 18,
			"%" => 19,
			"==" => 20,
			"^" => 21,
			"*" => 22,
			">>" => 23,
			"!=" => 24,
			"?" => 25,
			"||" => 26,
			"&&" => 27,
			"&" => 28,
			"/" => 29,
			"|" => 30,
			"<<" => 32,
			"=>" => 31,
			"<=" => 33,
			">" => 34
		}
	},
	{#State 3
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 35,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 4
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 36,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 5
		DEFAULT => -1
	},
	{#State 6
		DEFAULT => -2
	},
	{#State 7
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 38,
			'var' => 37,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 8
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 39,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 9
		ACTIONS => {
			"*" => 9,
			'VAR' => 41
		},
		GOTOS => {
			'possible_pointer' => 40
		}
	},
	{#State 10
		ACTIONS => {
			"(" => 42
		},
		DEFAULT => -30
	},
	{#State 11
		ACTIONS => {
			"->" => 43,
			"." => 44
		},
		DEFAULT => -4
	},
	{#State 12
		DEFAULT => -3
	},
	{#State 13
		DEFAULT => -32
	},
	{#State 14
		ACTIONS => {
			"^" => 21,
			"=>" => 31,
			"<=" => 33
		},
		DEFAULT => -26
	},
	{#State 15
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 45,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 16
		DEFAULT => 0
	},
	{#State 17
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 46,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 18
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 47,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 19
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 48,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 20
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 49,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 21
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 50,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 22
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 51,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 23
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 52,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 24
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 53,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 25
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 54,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 26
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 55,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 27
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 56,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 28
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 57,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 29
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 58,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 30
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 59,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 31
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 60,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 32
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 61,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 33
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 62,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 34
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 63,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 35
		ACTIONS => {
			"^" => 21,
			"=>" => 31,
			"<=" => 33
		},
		DEFAULT => -5
	},
	{#State 36
		ACTIONS => {
			"^" => 21,
			"=>" => 31,
			"<=" => 33
		},
		DEFAULT => -27
	},
	{#State 37
		ACTIONS => {
			")" => 64,
			"->" => 43,
			"." => 44
		},
		DEFAULT => -4
	},
	{#State 38
		ACTIONS => {
			"-" => 15,
			"<" => 17,
			"+" => 18,
			"%" => 19,
			"==" => 20,
			"^" => 21,
			"*" => 22,
			")" => 65,
			">>" => 23,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"/" => 29,
			"|" => 30,
			"=>" => 31,
			"<<" => 32,
			"<=" => 33,
			">" => 34
		}
	},
	{#State 39
		ACTIONS => {
			"-" => 15,
			"<" => 17,
			"+" => 18,
			"%" => 19,
			"==" => 20,
			"^" => 21,
			"*" => 22,
			">>" => 23,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"/" => 29,
			"|" => 30,
			"=>" => 31,
			"<<" => 32,
			"<=" => 33,
			">" => 34
		},
		DEFAULT => -24
	},
	{#State 40
		DEFAULT => -31
	},
	{#State 41
		DEFAULT => -30
	},
	{#State 42
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		DEFAULT => -37,
		GOTOS => {
			'exp' => 69,
			'var' => 11,
			'args' => 66,
			'func' => 12,
			'opt_args' => 70,
			'exp_or_possible_pointer' => 67,
			'possible_pointer' => 68
		}
	},
	{#State 43
		ACTIONS => {
			'VAR' => 71
		}
	},
	{#State 44
		ACTIONS => {
			'VAR' => 72
		}
	},
	{#State 45
		ACTIONS => {
			"<" => 17,
			"==" => 20,
			"^" => 21,
			">>" => 23,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"|" => 30,
			"=>" => 31,
			"<<" => 32,
			"<=" => 33,
			">" => 34
		},
		DEFAULT => -7
	},
	{#State 46
		ACTIONS => {
			"==" => 20,
			"^" => 21,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"|" => 30,
			"=>" => 31,
			"<=" => 33
		},
		DEFAULT => -10
	},
	{#State 47
		ACTIONS => {
			"<" => 17,
			"==" => 20,
			"^" => 21,
			">>" => 23,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"|" => 30,
			"=>" => 31,
			"<<" => 32,
			"<=" => 33,
			">" => 34
		},
		DEFAULT => -6
	},
	{#State 48
		ACTIONS => {
			"-" => 15,
			"<" => 17,
			"+" => 18,
			"==" => 20,
			"^" => 21,
			">>" => 23,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"|" => 30,
			"=>" => 31,
			"<<" => 32,
			"<=" => 33,
			">" => 34
		},
		DEFAULT => -9
	},
	{#State 49
		ACTIONS => {
			"^" => 21,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"|" => 30,
			"=>" => 31,
			"<=" => 33
		},
		DEFAULT => -13
	},
	{#State 50
		ACTIONS => {
			"-" => 15,
			"<" => 17,
			"+" => 18,
			"%" => 19,
			"==" => 20,
			"^" => 21,
			"*" => 22,
			">>" => 23,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"/" => 29,
			"|" => 30,
			"=>" => 31,
			"<<" => 32,
			"<=" => 33,
			">" => 34
		},
		DEFAULT => -28
	},
	{#State 51
		ACTIONS => {
			"-" => 15,
			"<" => 17,
			"+" => 18,
			"==" => 20,
			"^" => 21,
			">>" => 23,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"|" => 30,
			"=>" => 31,
			"<<" => 32,
			"<=" => 33,
			">" => 34
		},
		DEFAULT => -8
	},
	{#State 52
		ACTIONS => {
			"<" => 17,
			"==" => 20,
			"^" => 21,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"|" => 30,
			"=>" => 31,
			"<=" => 33,
			">" => 34
		},
		DEFAULT => -17
	},
	{#State 53
		ACTIONS => {
			"^" => 21,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"|" => 30,
			"=>" => 31,
			"<=" => 33
		},
		DEFAULT => -18
	},
	{#State 54
		ACTIONS => {
			":" => 73,
			"-" => 15,
			"<" => 17,
			"+" => 18,
			"%" => 19,
			"==" => 20,
			"^" => 21,
			"*" => 22,
			">>" => 23,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"/" => 29,
			"|" => 30,
			"=>" => 31,
			"<<" => 32,
			"<=" => 33,
			">" => 34
		}
	},
	{#State 55
		ACTIONS => {
			"^" => 21,
			"?" => 25,
			"=>" => 31,
			"<=" => 33
		},
		DEFAULT => -19
	},
	{#State 56
		ACTIONS => {
			"^" => 21,
			"?" => 25,
			"||" => 26,
			"=>" => 31,
			"<=" => 33
		},
		DEFAULT => -20
	},
	{#State 57
		ACTIONS => {
			"^" => 21,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"|" => 30,
			"=>" => 31,
			"<=" => 33
		},
		DEFAULT => -21
	},
	{#State 58
		ACTIONS => {
			"-" => 15,
			"<" => 17,
			"+" => 18,
			"==" => 20,
			"^" => 21,
			">>" => 23,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"|" => 30,
			"=>" => 31,
			"<<" => 32,
			"<=" => 33,
			">" => 34
		},
		DEFAULT => -25
	},
	{#State 59
		ACTIONS => {
			"^" => 21,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"=>" => 31,
			"<=" => 33
		},
		DEFAULT => -12
	},
	{#State 60
		ACTIONS => {
			"-" => 15,
			"<" => 17,
			"+" => 18,
			"%" => 19,
			"==" => 20,
			"^" => 21,
			"*" => 22,
			">>" => 23,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"/" => 29,
			"|" => 30,
			"=>" => 31,
			"<<" => 32,
			"<=" => 33,
			">" => 34
		},
		DEFAULT => -15
	},
	{#State 61
		ACTIONS => {
			"<" => 17,
			"==" => 20,
			"^" => 21,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"|" => 30,
			"=>" => 31,
			"<=" => 33,
			">" => 34
		},
		DEFAULT => -16
	},
	{#State 62
		ACTIONS => {
			"-" => 15,
			"<" => 17,
			"+" => 18,
			"%" => 19,
			"==" => 20,
			"^" => 21,
			"*" => 22,
			">>" => 23,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"/" => 29,
			"|" => 30,
			"=>" => 31,
			"<<" => 32,
			"<=" => 33,
			">" => 34
		},
		DEFAULT => -14
	},
	{#State 63
		ACTIONS => {
			"==" => 20,
			"^" => 21,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"|" => 30,
			"=>" => 31,
			"<=" => 33
		},
		DEFAULT => -11
	},
	{#State 64
		DEFAULT => -34
	},
	{#State 65
		DEFAULT => -29
	},
	{#State 66
		DEFAULT => -38
	},
	{#State 67
		ACTIONS => {
			"," => 74
		},
		DEFAULT => -41
	},
	{#State 68
		DEFAULT => -32
	},
	{#State 69
		ACTIONS => {
			"-" => 15,
			"<" => 17,
			"+" => 18,
			"%" => 19,
			"==" => 20,
			"^" => 21,
			"*" => 22,
			">>" => 23,
			"!=" => 24,
			"?" => 25,
			"&&" => 27,
			"||" => 26,
			"&" => 28,
			"/" => 29,
			"|" => 30,
			"=>" => 31,
			"<<" => 32,
			"<=" => 33,
			">" => 34
		},
		DEFAULT => -39
	},
	{#State 70
		ACTIONS => {
			")" => 75
		}
	},
	{#State 71
		DEFAULT => -35
	},
	{#State 72
		DEFAULT => -33
	},
	{#State 73
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 76,
			'var' => 11,
			'func' => 12,
			'possible_pointer' => 13
		}
	},
	{#State 74
		ACTIONS => {
			"-" => 1,
			"~" => 3,
			"&" => 4,
			'TEXT' => 6,
			'NUM' => 5,
			"!" => 8,
			"(" => 7,
			"*" => 9,
			'VAR' => 10
		},
		GOTOS => {
			'exp' => 69,
			'var' => 11,
			'args' => 77,
			'func' => 12,
			'exp_or_possible_pointer' => 67,
			'possible_pointer' => 68
		}
	},
	{#State 75
		DEFAULT => -36
	},
	{#State 76
		ACTIONS => {
			"^" => 21,
			"=>" => 31,
			"<=" => 33
		},
		DEFAULT => -22
	},
	{#State 77
		DEFAULT => -42
	}
],
                                  yyrules  =>
[
	[#Rule 0
		 '$start', 2, undef
	],
	[#Rule 1
		 'exp', 1, undef
	],
	[#Rule 2
		 'exp', 1,
sub
#line 22 "./pidl/expr.yp"
{ "\"$_[1]\"" }
	],
	[#Rule 3
		 'exp', 1, undef
	],
	[#Rule 4
		 'exp', 1, undef
	],
	[#Rule 5
		 'exp', 2,
sub
#line 25 "./pidl/expr.yp"
{ "~$_[2]" }
	],
	[#Rule 6
		 'exp', 3,
sub
#line 26 "./pidl/expr.yp"
{ "$_[1] + $_[3]" }
	],
	[#Rule 7
		 'exp', 3,
sub
#line 27 "./pidl/expr.yp"
{ "$_[1] - $_[3]" }
	],
	[#Rule 8
		 'exp', 3,
sub
#line 28 "./pidl/expr.yp"
{ "$_[1] * $_[3]" }
	],
	[#Rule 9
		 'exp', 3,
sub
#line 29 "./pidl/expr.yp"
{ "$_[1] % $_[3]" }
	],
	[#Rule 10
		 'exp', 3,
sub
#line 30 "./pidl/expr.yp"
{ "$_[1] < $_[3]" }
	],
	[#Rule 11
		 'exp', 3,
sub
#line 31 "./pidl/expr.yp"
{ "$_[1] > $_[3]" }
	],
	[#Rule 12
		 'exp', 3,
sub
#line 32 "./pidl/expr.yp"
{ "$_[1] | $_[3]" }
	],
	[#Rule 13
		 'exp', 3,
sub
#line 33 "./pidl/expr.yp"
{ "$_[1] == $_[3]" }
	],
	[#Rule 14
		 'exp', 3,
sub
#line 34 "./pidl/expr.yp"
{ "$_[1] <= $_[3]" }
	],
	[#Rule 15
		 'exp', 3,
sub
#line 35 "./pidl/expr.yp"
{ "$_[1] => $_[3]" }
	],
	[#Rule 16
		 'exp', 3,
sub
#line 36 "./pidl/expr.yp"
{ "$_[1] << $_[3]" }
	],
	[#Rule 17
		 'exp', 3,
sub
#line 37 "./pidl/expr.yp"
{ "$_[1] >> $_[3]" }
	],
	[#Rule 18
		 'exp', 3,
sub
#line 38 "./pidl/expr.yp"
{ "$_[1] != $_[3]" }
	],
	[#Rule 19
		 'exp', 3,
sub
#line 39 "./pidl/expr.yp"
{ "$_[1] || $_[3]" }
	],
	[#Rule 20
		 'exp', 3,
sub
#line 40 "./pidl/expr.yp"
{ "$_[1] && $_[3]" }
	],
	[#Rule 21
		 'exp', 3,
sub
#line 41 "./pidl/expr.yp"
{ "$_[1] & $_[3]" }
	],
	[#Rule 22
		 'exp', 5,
sub
#line 42 "./pidl/expr.yp"
{ "$_[1]?$_[3]:$_[5]" }
	],
	[#Rule 23
		 'exp', 2,
sub
#line 43 "./pidl/expr.yp"
{ "~$_[1]" }
	],
	[#Rule 24
		 'exp', 2,
sub
#line 44 "./pidl/expr.yp"
{ "not $_[1]" }
	],
	[#Rule 25
		 'exp', 3,
sub
#line 45 "./pidl/expr.yp"
{ "$_[1] / $_[3]" }
	],
	[#Rule 26
		 'exp', 2,
sub
#line 46 "./pidl/expr.yp"
{ "-$_[2]" }
	],
	[#Rule 27
		 'exp', 2,
sub
#line 47 "./pidl/expr.yp"
{ "&$_[2]" }
	],
	[#Rule 28
		 'exp', 3,
sub
#line 48 "./pidl/expr.yp"
{ "$_[1]^$_[3]" }
	],
	[#Rule 29
		 'exp', 3,
sub
#line 49 "./pidl/expr.yp"
{ "($_[2])" }
	],
	[#Rule 30
		 'possible_pointer', 1,
sub
#line 53 "./pidl/expr.yp"
{ $_[0]->_Lookup($_[1]) }
	],
	[#Rule 31
		 'possible_pointer', 2,
sub
#line 54 "./pidl/expr.yp"
{ $_[0]->_Dereference($_[2]); "*$_[2]" }
	],
	[#Rule 32
		 'var', 1,
sub
#line 57 "./pidl/expr.yp"
{ $_[0]->_Use($_[1]) }
	],
	[#Rule 33
		 'var', 3,
sub
#line 58 "./pidl/expr.yp"
{ $_[0]->_Use("$_[1].$_[3]") }
	],
	[#Rule 34
		 'var', 3,
sub
#line 59 "./pidl/expr.yp"
{ "($_[2])" }
	],
	[#Rule 35
		 'var', 3,
sub
#line 60 "./pidl/expr.yp"
{ $_[0]->_Use("*$_[1]"); $_[1]."->".$_[3] }
	],
	[#Rule 36
		 'func', 4,
sub
#line 64 "./pidl/expr.yp"
{ "$_[1]($_[3])" }
	],
	[#Rule 37
		 'opt_args', 0,
sub
#line 65 "./pidl/expr.yp"
{ "" }
	],
	[#Rule 38
		 'opt_args', 1, undef
	],
	[#Rule 39
		 'exp_or_possible_pointer', 1, undef
	],
	[#Rule 40
		 'exp_or_possible_pointer', 1, undef
	],
	[#Rule 41
		 'args', 1, undef
	],
	[#Rule 42
		 'args', 3,
sub
#line 68 "./pidl/expr.yp"
{ "$_[1], $_[3]" }
	]
],
                                  @_);
    bless($self,$class);
}

#line 71 "./pidl/expr.yp"


package Parse::Pidl::Expr;

sub _Lexer {
    my($parser)=shift;

    $parser->YYData->{INPUT}=~s/^[ \t]//;

    for ($parser->YYData->{INPUT}) {
        if (s/^(0x[0-9A-Fa-f]+)//) {
			$parser->YYData->{LAST_TOKEN} = $1;
            return('NUM',$1);
		}
        if (s/^([0-9]+(?:\.[0-9]+)?)//) {
			$parser->YYData->{LAST_TOKEN} = $1;
            return('NUM',$1);
		}
        if (s/^([A-Za-z_][A-Za-z0-9_]*)//) {
			$parser->YYData->{LAST_TOKEN} = $1;
        	return('VAR',$1);
		}
		if (s/^\"(.*?)\"//) {
			$parser->YYData->{LAST_TOKEN} = $1;
			return('TEXT',$1); 
		}
		if (s/^(==|!=|<=|>=|->|\|\||<<|>>|&&)//s) {
			$parser->YYData->{LAST_TOKEN} = $1;
            return($1,$1);
		}
        if (s/^(.)//s) {
			$parser->YYData->{LAST_TOKEN} = $1;
            return($1,$1);
		}
    }
}

sub _Use($$)
{
	my ($self, $x) = @_;
	if (defined($self->YYData->{USE})) {
		return $self->YYData->{USE}->($x);
	}
	return $x;
}

sub _Lookup($$) 
{
	my ($self, $x) = @_;
	return $self->YYData->{LOOKUP}->($x);
}

sub _Dereference($$)
{
	my ($self, $x) = @_;
	if (defined($self->YYData->{DEREFERENCE})) {
		$self->YYData->{DEREFERENCE}->($x);
	}
}

sub _Error($)
{
	my ($self) = @_;
	if (defined($self->YYData->{LAST_TOKEN})) {
		$self->YYData->{ERROR}->("Parse error in `".$self->YYData->{FULL_INPUT}."' near `". $self->YYData->{LAST_TOKEN} . "'");
	} else {
		$self->YYData->{ERROR}->("Parse error in `".$self->YYData->{FULL_INPUT}."'");
	}
}

sub Run {
    my($self, $data, $error, $lookup, $deref, $use) = @_;
    $self->YYData->{FULL_INPUT} = $data;
    $self->YYData->{INPUT} = $data;
    $self->YYData->{LOOKUP} = $lookup;
    $self->YYData->{DEREFERENCE} = $deref;
    $self->YYData->{ERROR} = $error;
    $self->YYData->{USE} = $use;
    return $self->YYParse( yylex => \&_Lexer, yyerror => \&_Error);
}

1;
