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
use Parse::Yapp::Driver;



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
		DEFAULT => -91,
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
		DEFAULT => -124
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
		DEFAULT => -120
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
		DEFAULT => -95
	},
	{#State 27
		DEFAULT => -93
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
		DEFAULT => -92
	},
	{#State 36
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
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
			"declare" => 56,
			"const" => 60
		},
		DEFAULT => -91,
		GOTOS => {
			'typedecl' => 49,
			'function' => 50,
			'definitions' => 52,
			'bitmap' => 51,
			'definition' => 55,
			'property_list' => 54,
			'usertype' => 53,
			'const' => 59,
			'declare' => 58,
			'struct' => 57,
			'typedef' => 62,
			'enum' => 61,
			'union' => 63
		}
	},
	{#State 40
		DEFAULT => -94
	},
	{#State 41
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"<" => 67,
			"+" => 69,
			"~" => 68,
			"*" => 76,
			"?" => 66,
			"{" => 70,
			"&" => 71,
			"/" => 72,
			"=" => 73,
			"(" => 74,
			"|" => 75,
			"." => 77,
			">" => 78
		},
		DEFAULT => -97
	},
	{#State 42
		ACTIONS => {
			"," => 79,
			")" => 80
		}
	},
	{#State 43
		DEFAULT => -103
	},
	{#State 44
		DEFAULT => -123
	},
	{#State 45
		DEFAULT => -102
	},
	{#State 46
		DEFAULT => -104
	},
	{#State 47
		ACTIONS => {
			";" => 82
		},
		DEFAULT => -125,
		GOTOS => {
			'optional_semicolon' => 81
		}
	},
	{#State 48
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 83
		}
	},
	{#State 49
		DEFAULT => -24
	},
	{#State 50
		DEFAULT => -20
	},
	{#State 51
		DEFAULT => -39
	},
	{#State 52
		ACTIONS => {
			"}" => 84,
			"declare" => 56,
			"const" => 60
		},
		DEFAULT => -91,
		GOTOS => {
			'typedecl' => 49,
			'function' => 50,
			'bitmap' => 51,
			'definition' => 85,
			'property_list' => 54,
			'usertype' => 53,
			'const' => 59,
			'struct' => 57,
			'declare' => 58,
			'typedef' => 62,
			'enum' => 61,
			'union' => 63
		}
	},
	{#State 53
		ACTIONS => {
			";" => 86
		}
	},
	{#State 54
		ACTIONS => {
			"typedef" => 87,
			'IDENTIFIER' => 22,
			"signed" => 95,
			"union" => 88,
			"enum" => 97,
			"bitmap" => 98,
			'void' => 89,
			"unsigned" => 99,
			"[" => 17,
			"struct" => 94
		},
		GOTOS => {
			'existingtype' => 96,
			'bitmap' => 51,
			'usertype' => 91,
			'property_list' => 90,
			'identifier' => 92,
			'struct' => 57,
			'enum' => 61,
			'type' => 100,
			'union' => 63,
			'sign' => 93
		}
	},
	{#State 55
		DEFAULT => -18
	},
	{#State 56
		DEFAULT => -91,
		GOTOS => {
			'property_list' => 101
		}
	},
	{#State 57
		DEFAULT => -36
	},
	{#State 58
		DEFAULT => -23
	},
	{#State 59
		DEFAULT => -21
	},
	{#State 60
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 102
		}
	},
	{#State 61
		DEFAULT => -38
	},
	{#State 62
		DEFAULT => -22
	},
	{#State 63
		DEFAULT => -37
	},
	{#State 64
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 103,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 65
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 104,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 66
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 105,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 67
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 106,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 68
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 107,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 69
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
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
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 109,
			'text' => 46,
			'constant' => 43,
			'commalisttext' => 110
		}
	},
	{#State 71
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 111,
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
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 112,
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
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 113,
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
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 109,
			'text' => 46,
			'constant' => 43,
			'commalisttext' => 114
		}
	},
	{#State 75
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 115,
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
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 116,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 77
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
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
		DEFAULT => -101,
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
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 119,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 80
		DEFAULT => -96
	},
	{#State 81
		DEFAULT => -12
	},
	{#State 82
		DEFAULT => -126
	},
	{#State 83
		ACTIONS => {
			";" => 120
		}
	},
	{#State 84
		ACTIONS => {
			";" => 82
		},
		DEFAULT => -125,
		GOTOS => {
			'optional_semicolon' => 121
		}
	},
	{#State 85
		DEFAULT => -19
	},
	{#State 86
		DEFAULT => -40
	},
	{#State 87
		ACTIONS => {
			'IDENTIFIER' => 22,
			"signed" => 95,
			'void' => 89,
			"unsigned" => 99
		},
		DEFAULT => -91,
		GOTOS => {
			'existingtype' => 96,
			'bitmap' => 51,
			'usertype' => 91,
			'property_list' => 90,
			'identifier' => 92,
			'struct' => 57,
			'enum' => 61,
			'type' => 122,
			'union' => 63,
			'sign' => 93
		}
	},
	{#State 88
		ACTIONS => {
			'IDENTIFIER' => 123
		},
		DEFAULT => -122,
		GOTOS => {
			'optional_identifier' => 124
		}
	},
	{#State 89
		DEFAULT => -47
	},
	{#State 90
		ACTIONS => {
			"union" => 88,
			"enum" => 97,
			"bitmap" => 98,
			"[" => 17,
			"struct" => 94
		}
	},
	{#State 91
		DEFAULT => -45
	},
	{#State 92
		DEFAULT => -44
	},
	{#State 93
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 125
		}
	},
	{#State 94
		ACTIONS => {
			'IDENTIFIER' => 123
		},
		DEFAULT => -122,
		GOTOS => {
			'optional_identifier' => 126
		}
	},
	{#State 95
		DEFAULT => -41
	},
	{#State 96
		DEFAULT => -46
	},
	{#State 97
		ACTIONS => {
			'IDENTIFIER' => 123
		},
		DEFAULT => -122,
		GOTOS => {
			'optional_identifier' => 127
		}
	},
	{#State 98
		ACTIONS => {
			'IDENTIFIER' => 123
		},
		DEFAULT => -122,
		GOTOS => {
			'optional_identifier' => 128
		}
	},
	{#State 99
		DEFAULT => -42
	},
	{#State 100
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 129
		}
	},
	{#State 101
		ACTIONS => {
			"union" => 130,
			"enum" => 135,
			"bitmap" => 136,
			"[" => 17
		},
		GOTOS => {
			'decl_enum' => 131,
			'decl_bitmap' => 132,
			'decl_type' => 134,
			'decl_union' => 133
		}
	},
	{#State 102
		DEFAULT => -80,
		GOTOS => {
			'pointers' => 137
		}
	},
	{#State 103
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"<" => 67,
			"+" => 69,
			"~" => 68,
			"*" => 76,
			"?" => 66,
			"{" => 70,
			"&" => 71,
			"/" => 72,
			"=" => 73,
			"(" => 74,
			"|" => 75,
			"." => 77,
			">" => 78
		},
		DEFAULT => -114
	},
	{#State 104
		ACTIONS => {
			":" => 64,
			"<" => 67,
			"~" => 68,
			"?" => 66,
			"{" => 70,
			"=" => 73
		},
		DEFAULT => -105
	},
	{#State 105
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"<" => 67,
			"+" => 69,
			"~" => 68,
			"*" => 76,
			"?" => 66,
			"{" => 70,
			"&" => 71,
			"/" => 72,
			"=" => 73,
			"(" => 74,
			"|" => 75,
			"." => 77,
			">" => 78
		},
		DEFAULT => -113
	},
	{#State 106
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"<" => 67,
			"+" => 69,
			"~" => 68,
			"*" => 76,
			"?" => 66,
			"{" => 70,
			"&" => 71,
			"/" => 72,
			"=" => 73,
			"(" => 74,
			"|" => 75,
			"." => 77,
			">" => 78
		},
		DEFAULT => -109
	},
	{#State 107
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"<" => 67,
			"+" => 69,
			"~" => 68,
			"*" => 76,
			"?" => 66,
			"{" => 70,
			"&" => 71,
			"/" => 72,
			"=" => 73,
			"(" => 74,
			"|" => 75,
			"." => 77,
			">" => 78
		},
		DEFAULT => -117
	},
	{#State 108
		ACTIONS => {
			":" => 64,
			"<" => 67,
			"~" => 68,
			"?" => 66,
			"{" => 70,
			"=" => 73
		},
		DEFAULT => -116
	},
	{#State 109
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"<" => 67,
			"+" => 69,
			"~" => 68,
			"*" => 76,
			"?" => 66,
			"{" => 70,
			"&" => 71,
			"/" => 72,
			"=" => 73,
			"(" => 74,
			"|" => 75,
			"." => 77,
			">" => 78
		},
		DEFAULT => -99
	},
	{#State 110
		ACTIONS => {
			"}" => 138,
			"," => 139
		}
	},
	{#State 111
		ACTIONS => {
			":" => 64,
			"<" => 67,
			"~" => 68,
			"?" => 66,
			"{" => 70,
			"=" => 73
		},
		DEFAULT => -111
	},
	{#State 112
		ACTIONS => {
			":" => 64,
			"<" => 67,
			"~" => 68,
			"?" => 66,
			"{" => 70,
			"=" => 73
		},
		DEFAULT => -112
	},
	{#State 113
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"<" => 67,
			"+" => 69,
			"~" => 68,
			"*" => 76,
			"?" => 66,
			"{" => 70,
			"&" => 71,
			"/" => 72,
			"=" => 73,
			"(" => 74,
			"|" => 75,
			"." => 77,
			">" => 78
		},
		DEFAULT => -115
	},
	{#State 114
		ACTIONS => {
			"," => 139,
			")" => 140
		}
	},
	{#State 115
		ACTIONS => {
			":" => 64,
			"<" => 67,
			"~" => 68,
			"?" => 66,
			"{" => 70,
			"=" => 73
		},
		DEFAULT => -110
	},
	{#State 116
		ACTIONS => {
			":" => 64,
			"<" => 67,
			"~" => 68,
			"?" => 66,
			"{" => 70,
			"=" => 73
		},
		DEFAULT => -107
	},
	{#State 117
		ACTIONS => {
			":" => 64,
			"<" => 67,
			"~" => 68,
			"?" => 66,
			"{" => 70,
			"=" => 73
		},
		DEFAULT => -106
	},
	{#State 118
		ACTIONS => {
			":" => 64,
			"<" => 67,
			"~" => 68,
			"?" => 66,
			"{" => 70,
			"=" => 73
		},
		DEFAULT => -108
	},
	{#State 119
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"<" => 67,
			"+" => 69,
			"~" => 68,
			"*" => 76,
			"?" => 66,
			"{" => 70,
			"&" => 71,
			"/" => 72,
			"=" => 73,
			"(" => 74,
			"|" => 75,
			"." => 77,
			">" => 78
		},
		DEFAULT => -98
	},
	{#State 120
		DEFAULT => -14
	},
	{#State 121
		DEFAULT => -15
	},
	{#State 122
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 141
		}
	},
	{#State 123
		DEFAULT => -121
	},
	{#State 124
		ACTIONS => {
			"{" => 143
		},
		DEFAULT => -76,
		GOTOS => {
			'union_body' => 144,
			'opt_union_body' => 142
		}
	},
	{#State 125
		DEFAULT => -43
	},
	{#State 126
		ACTIONS => {
			"{" => 146
		},
		DEFAULT => -66,
		GOTOS => {
			'struct_body' => 145,
			'opt_struct_body' => 147
		}
	},
	{#State 127
		ACTIONS => {
			"{" => 148
		},
		DEFAULT => -49,
		GOTOS => {
			'opt_enum_body' => 150,
			'enum_body' => 149
		}
	},
	{#State 128
		ACTIONS => {
			"{" => 152
		},
		DEFAULT => -57,
		GOTOS => {
			'bitmap_body' => 153,
			'opt_bitmap_body' => 151
		}
	},
	{#State 129
		ACTIONS => {
			"(" => 154
		}
	},
	{#State 130
		DEFAULT => -34
	},
	{#State 131
		DEFAULT => -29
	},
	{#State 132
		DEFAULT => -30
	},
	{#State 133
		DEFAULT => -31
	},
	{#State 134
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 155
		}
	},
	{#State 135
		DEFAULT => -32
	},
	{#State 136
		DEFAULT => -33
	},
	{#State 137
		ACTIONS => {
			'IDENTIFIER' => 22,
			"*" => 157
		},
		GOTOS => {
			'identifier' => 156
		}
	},
	{#State 138
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 158,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 139
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 159,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 140
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 160,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 141
		ACTIONS => {
			"[" => 161
		},
		DEFAULT => -88,
		GOTOS => {
			'array_len' => 162
		}
	},
	{#State 142
		DEFAULT => -78
	},
	{#State 143
		DEFAULT => -73,
		GOTOS => {
			'union_elements' => 163
		}
	},
	{#State 144
		DEFAULT => -77
	},
	{#State 145
		DEFAULT => -67
	},
	{#State 146
		DEFAULT => -82,
		GOTOS => {
			'element_list1' => 164
		}
	},
	{#State 147
		DEFAULT => -68
	},
	{#State 148
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 165,
			'enum_element' => 166,
			'enum_elements' => 167
		}
	},
	{#State 149
		DEFAULT => -50
	},
	{#State 150
		DEFAULT => -51
	},
	{#State 151
		DEFAULT => -59
	},
	{#State 152
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		DEFAULT => -62,
		GOTOS => {
			'identifier' => 170,
			'bitmap_element' => 169,
			'bitmap_elements' => 168,
			'opt_bitmap_elements' => 171
		}
	},
	{#State 153
		DEFAULT => -58
	},
	{#State 154
		ACTIONS => {
			"," => -84,
			"void" => 175,
			")" => -84
		},
		DEFAULT => -91,
		GOTOS => {
			'base_element' => 172,
			'element_list2' => 174,
			'property_list' => 173
		}
	},
	{#State 155
		ACTIONS => {
			";" => 176
		}
	},
	{#State 156
		ACTIONS => {
			"[" => 161,
			"=" => 178
		},
		GOTOS => {
			'array_len' => 177
		}
	},
	{#State 157
		DEFAULT => -81
	},
	{#State 158
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"<" => 67,
			"+" => 69,
			"~" => 68,
			"*" => 76,
			"?" => 66,
			"{" => 70,
			"&" => 71,
			"/" => 72,
			"=" => 73,
			"(" => 74,
			"|" => 75,
			"." => 77,
			">" => 78
		},
		DEFAULT => -119
	},
	{#State 159
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"<" => 67,
			"+" => 69,
			"~" => 68,
			"*" => 76,
			"?" => 66,
			"{" => 70,
			"&" => 71,
			"/" => 72,
			"=" => 73,
			"(" => 74,
			"|" => 75,
			"." => 77,
			">" => 78
		},
		DEFAULT => -100
	},
	{#State 160
		ACTIONS => {
			":" => 64,
			"<" => 67,
			"~" => 68,
			"?" => 66,
			"{" => 70,
			"=" => 73
		},
		DEFAULT => -118
	},
	{#State 161
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			"]" => 179,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 180,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 162
		ACTIONS => {
			";" => 181
		}
	},
	{#State 163
		ACTIONS => {
			"}" => 182
		},
		DEFAULT => -91,
		GOTOS => {
			'optional_base_element' => 184,
			'property_list' => 183
		}
	},
	{#State 164
		ACTIONS => {
			"}" => 185
		},
		DEFAULT => -91,
		GOTOS => {
			'base_element' => 186,
			'property_list' => 173
		}
	},
	{#State 165
		ACTIONS => {
			"=" => 187
		},
		DEFAULT => -54
	},
	{#State 166
		DEFAULT => -52
	},
	{#State 167
		ACTIONS => {
			"}" => 188,
			"," => 189
		}
	},
	{#State 168
		ACTIONS => {
			"," => 190
		},
		DEFAULT => -63
	},
	{#State 169
		DEFAULT => -60
	},
	{#State 170
		ACTIONS => {
			"=" => 191
		}
	},
	{#State 171
		ACTIONS => {
			"}" => 192
		}
	},
	{#State 172
		DEFAULT => -86
	},
	{#State 173
		ACTIONS => {
			'IDENTIFIER' => 22,
			"signed" => 95,
			'void' => 89,
			"unsigned" => 99,
			"[" => 17
		},
		DEFAULT => -91,
		GOTOS => {
			'existingtype' => 96,
			'bitmap' => 51,
			'usertype' => 91,
			'property_list' => 90,
			'identifier' => 92,
			'struct' => 57,
			'enum' => 61,
			'type' => 193,
			'union' => 63,
			'sign' => 93
		}
	},
	{#State 174
		ACTIONS => {
			"," => 194,
			")" => 195
		}
	},
	{#State 175
		DEFAULT => -85
	},
	{#State 176
		DEFAULT => -28
	},
	{#State 177
		ACTIONS => {
			"=" => 196
		}
	},
	{#State 178
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 197,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 179
		ACTIONS => {
			"[" => 161
		},
		DEFAULT => -88,
		GOTOS => {
			'array_len' => 198
		}
	},
	{#State 180
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"?" => 66,
			"<" => 67,
			"+" => 69,
			"~" => 68,
			"&" => 71,
			"{" => 70,
			"/" => 72,
			"=" => 73,
			"|" => 75,
			"(" => 74,
			"*" => 76,
			"." => 77,
			"]" => 199,
			">" => 78
		}
	},
	{#State 181
		DEFAULT => -35
	},
	{#State 182
		DEFAULT => -75
	},
	{#State 183
		ACTIONS => {
			"[" => 17
		},
		DEFAULT => -91,
		GOTOS => {
			'base_or_empty' => 200,
			'base_element' => 201,
			'empty_element' => 202,
			'property_list' => 203
		}
	},
	{#State 184
		DEFAULT => -74
	},
	{#State 185
		DEFAULT => -65
	},
	{#State 186
		ACTIONS => {
			";" => 204
		}
	},
	{#State 187
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 205,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 188
		DEFAULT => -48
	},
	{#State 189
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 165,
			'enum_element' => 206
		}
	},
	{#State 190
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 170,
			'bitmap_element' => 207
		}
	},
	{#State 191
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 208,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 192
		DEFAULT => -56
	},
	{#State 193
		DEFAULT => -80,
		GOTOS => {
			'pointers' => 209
		}
	},
	{#State 194
		DEFAULT => -91,
		GOTOS => {
			'base_element' => 210,
			'property_list' => 173
		}
	},
	{#State 195
		ACTIONS => {
			";" => 211
		}
	},
	{#State 196
		ACTIONS => {
			'CONSTANT' => 44,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 45,
			'anytext' => 212,
			'text' => 46,
			'constant' => 43
		}
	},
	{#State 197
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"?" => 66,
			"<" => 67,
			";" => 213,
			"+" => 69,
			"~" => 68,
			"&" => 71,
			"{" => 70,
			"/" => 72,
			"=" => 73,
			"|" => 75,
			"(" => 74,
			"*" => 76,
			"." => 77,
			">" => 78
		}
	},
	{#State 198
		DEFAULT => -89
	},
	{#State 199
		ACTIONS => {
			"[" => 161
		},
		DEFAULT => -88,
		GOTOS => {
			'array_len' => 214
		}
	},
	{#State 200
		DEFAULT => -72
	},
	{#State 201
		ACTIONS => {
			";" => 215
		}
	},
	{#State 202
		DEFAULT => -71
	},
	{#State 203
		ACTIONS => {
			'IDENTIFIER' => 22,
			"signed" => 95,
			";" => 216,
			'void' => 89,
			"unsigned" => 99,
			"[" => 17
		},
		DEFAULT => -91,
		GOTOS => {
			'existingtype' => 96,
			'bitmap' => 51,
			'usertype' => 91,
			'property_list' => 90,
			'identifier' => 92,
			'struct' => 57,
			'enum' => 61,
			'type' => 193,
			'union' => 63,
			'sign' => 93
		}
	},
	{#State 204
		DEFAULT => -83
	},
	{#State 205
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"<" => 67,
			"+" => 69,
			"~" => 68,
			"*" => 76,
			"?" => 66,
			"{" => 70,
			"&" => 71,
			"/" => 72,
			"=" => 73,
			"(" => 74,
			"|" => 75,
			"." => 77,
			">" => 78
		},
		DEFAULT => -55
	},
	{#State 206
		DEFAULT => -53
	},
	{#State 207
		DEFAULT => -61
	},
	{#State 208
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"<" => 67,
			"+" => 69,
			"~" => 68,
			"*" => 76,
			"?" => 66,
			"{" => 70,
			"&" => 71,
			"/" => 72,
			"=" => 73,
			"(" => 74,
			"|" => 75,
			"." => 77,
			">" => 78
		},
		DEFAULT => -64
	},
	{#State 209
		ACTIONS => {
			'IDENTIFIER' => 22,
			"*" => 157
		},
		GOTOS => {
			'identifier' => 217
		}
	},
	{#State 210
		DEFAULT => -87
	},
	{#State 211
		DEFAULT => -27
	},
	{#State 212
		ACTIONS => {
			"-" => 65,
			":" => 64,
			"?" => 66,
			"<" => 67,
			";" => 218,
			"+" => 69,
			"~" => 68,
			"&" => 71,
			"{" => 70,
			"/" => 72,
			"=" => 73,
			"|" => 75,
			"(" => 74,
			"*" => 76,
			"." => 77,
			">" => 78
		}
	},
	{#State 213
		DEFAULT => -25
	},
	{#State 214
		DEFAULT => -90
	},
	{#State 215
		DEFAULT => -70
	},
	{#State 216
		DEFAULT => -69
	},
	{#State 217
		ACTIONS => {
			"[" => 161
		},
		DEFAULT => -88,
		GOTOS => {
			'array_len' => 219
		}
	},
	{#State 218
		DEFAULT => -26
	},
	{#State 219
		DEFAULT => -79
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
		 'idl', 2,
sub
#line 21 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 5
		 'idl', 2,
sub
#line 22 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 6
		 'idl', 2,
sub
#line 23 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 7
		 'import', 3,
sub
#line 26 "idl.yp"
{{
			"TYPE" => "IMPORT", 
			"PATHS" => $_[2],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 8
		 'include', 3,
sub
#line 33 "idl.yp"
{{ 
			"TYPE" => "INCLUDE", 
			"PATHS" => $_[2],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 9
		 'importlib', 3,
sub
#line 40 "idl.yp"
{{ 
			"TYPE" => "IMPORTLIB", 
			"PATHS" => $_[2],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 10
		 'commalist', 1,
sub
#line 49 "idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 11
		 'commalist', 3,
sub
#line 50 "idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 12
		 'coclass', 7,
sub
#line 54 "idl.yp"
{{
               "TYPE" => "COCLASS", 
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "DATA" => $_[5],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 13
		 'interface_names', 0, undef
	],
	[#Rule 14
		 'interface_names', 4,
sub
#line 66 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 15
		 'interface', 8,
sub
#line 70 "idl.yp"
{{
               "TYPE" => "INTERFACE", 
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "BASE" => $_[4],
	       "DATA" => $_[6],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 16
		 'base_interface', 0, undef
	],
	[#Rule 17
		 'base_interface', 2,
sub
#line 83 "idl.yp"
{ $_[2] }
	],
	[#Rule 18
		 'definitions', 1,
sub
#line 87 "idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 19
		 'definitions', 2,
sub
#line 88 "idl.yp"
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
#line 96 "idl.yp"
{{
                     "TYPE"  => "CONST", 
		     "DTYPE"  => $_[2],
			 "POINTERS" => $_[3],
		     "NAME"  => $_[4],
		     "VALUE" => $_[6],
		     "FILE" => $_[0]->YYData->{FILE},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 26
		 'const', 8,
sub
#line 106 "idl.yp"
{{
                     "TYPE"  => "CONST", 
		     "DTYPE"  => $_[2],
			 "POINTERS" => $_[3],
		     "NAME"  => $_[4],
		     "ARRAY_LEN" => $_[5],
		     "VALUE" => $_[7],
		     "FILE" => $_[0]->YYData->{FILE},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 27
		 'function', 7,
sub
#line 120 "idl.yp"
{{
		"TYPE" => "FUNCTION",
		"NAME" => $_[3],
		"RETURN_TYPE" => $_[2],
		"PROPERTIES" => $_[1],
		"ELEMENTS" => $_[5],
		"FILE" => $_[0]->YYData->{FILE},
		"LINE" => $_[0]->YYData->{LINE},
	  }}
	],
	[#Rule 28
		 'declare', 5,
sub
#line 132 "idl.yp"
{{
	             "TYPE" => "DECLARE", 
                     "PROPERTIES" => $_[2],
		     "NAME" => $_[4],
		     "DATA" => $_[3],
		     "FILE" => $_[0]->YYData->{FILE},
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
#line 146 "idl.yp"
{{
                     "TYPE" => "ENUM"
        }}
	],
	[#Rule 33
		 'decl_bitmap', 1,
sub
#line 152 "idl.yp"
{{
                     "TYPE" => "BITMAP"
        }}
	],
	[#Rule 34
		 'decl_union', 1,
sub
#line 158 "idl.yp"
{{
                     "TYPE" => "UNION"
        }}
	],
	[#Rule 35
		 'typedef', 6,
sub
#line 164 "idl.yp"
{{
	             "TYPE" => "TYPEDEF", 
                     "PROPERTIES" => $_[1],
		     "NAME" => $_[4],
		     "DATA" => $_[3],
		     "ARRAY_LEN" => $_[5],
		     "FILE" => $_[0]->YYData->{FILE},
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
#line 177 "idl.yp"
{ $_[1] }
	],
	[#Rule 41
		 'sign', 1, undef
	],
	[#Rule 42
		 'sign', 1, undef
	],
	[#Rule 43
		 'existingtype', 2,
sub
#line 182 "idl.yp"
{ ($_[1]?$_[1]:"signed") ." $_[2]" }
	],
	[#Rule 44
		 'existingtype', 1, undef
	],
	[#Rule 45
		 'type', 1, undef
	],
	[#Rule 46
		 'type', 1, undef
	],
	[#Rule 47
		 'type', 1,
sub
#line 186 "idl.yp"
{ "void" }
	],
	[#Rule 48
		 'enum_body', 3,
sub
#line 188 "idl.yp"
{ $_[2] }
	],
	[#Rule 49
		 'opt_enum_body', 0, undef
	],
	[#Rule 50
		 'opt_enum_body', 1, undef
	],
	[#Rule 51
		 'enum', 4,
sub
#line 191 "idl.yp"
{{
             "TYPE" => "ENUM", 
			 "PROPERTIES" => $_[1],
			 "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 52
		 'enum_elements', 1,
sub
#line 200 "idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 53
		 'enum_elements', 3,
sub
#line 201 "idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 54
		 'enum_element', 1, undef
	],
	[#Rule 55
		 'enum_element', 3,
sub
#line 205 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 56
		 'bitmap_body', 3,
sub
#line 208 "idl.yp"
{ $_[2] }
	],
	[#Rule 57
		 'opt_bitmap_body', 0, undef
	],
	[#Rule 58
		 'opt_bitmap_body', 1, undef
	],
	[#Rule 59
		 'bitmap', 4,
sub
#line 211 "idl.yp"
{{
             "TYPE" => "BITMAP", 
		     "PROPERTIES" => $_[1],
			 "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 60
		 'bitmap_elements', 1,
sub
#line 220 "idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 61
		 'bitmap_elements', 3,
sub
#line 221 "idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 62
		 'opt_bitmap_elements', 0, undef
	],
	[#Rule 63
		 'opt_bitmap_elements', 1, undef
	],
	[#Rule 64
		 'bitmap_element', 3,
sub
#line 226 "idl.yp"
{ "$_[1] ( $_[3] )" }
	],
	[#Rule 65
		 'struct_body', 3,
sub
#line 229 "idl.yp"
{ $_[2] }
	],
	[#Rule 66
		 'opt_struct_body', 0, undef
	],
	[#Rule 67
		 'opt_struct_body', 1, undef
	],
	[#Rule 68
		 'struct', 4,
sub
#line 233 "idl.yp"
{{
             "TYPE" => "STRUCT", 
			 "PROPERTIES" => $_[1],
			 "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 69
		 'empty_element', 2,
sub
#line 242 "idl.yp"
{{
		 "NAME" => "",
		 "TYPE" => "EMPTY",
		 "PROPERTIES" => $_[1],
		 "POINTERS" => 0,
		 "ARRAY_LEN" => [],
		 "FILE" => $_[0]->YYData->{FILE},
		 "LINE" => $_[0]->YYData->{LINE},
	 }}
	],
	[#Rule 70
		 'base_or_empty', 2, undef
	],
	[#Rule 71
		 'base_or_empty', 1, undef
	],
	[#Rule 72
		 'optional_base_element', 2,
sub
#line 256 "idl.yp"
{ $_[2]->{PROPERTIES} = FlattenHash([$_[1],$_[2]->{PROPERTIES}]); $_[2] }
	],
	[#Rule 73
		 'union_elements', 0, undef
	],
	[#Rule 74
		 'union_elements', 2,
sub
#line 261 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 75
		 'union_body', 3,
sub
#line 264 "idl.yp"
{ $_[2] }
	],
	[#Rule 76
		 'opt_union_body', 0, undef
	],
	[#Rule 77
		 'opt_union_body', 1, undef
	],
	[#Rule 78
		 'union', 4,
sub
#line 268 "idl.yp"
{{
             "TYPE" => "UNION", 
			 "PROPERTIES" => $_[1],
		     "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 79
		 'base_element', 5,
sub
#line 277 "idl.yp"
{{
			   "NAME" => $_[4],
			   "TYPE" => $_[2],
			   "PROPERTIES" => $_[1],
			   "POINTERS" => $_[3],
			   "ARRAY_LEN" => $_[5],
		       "FILE" => $_[0]->YYData->{FILE},
		       "LINE" => $_[0]->YYData->{LINE},
              }}
	],
	[#Rule 80
		 'pointers', 0,
sub
#line 291 "idl.yp"
{ 0 }
	],
	[#Rule 81
		 'pointers', 2,
sub
#line 292 "idl.yp"
{ $_[1]+1 }
	],
	[#Rule 82
		 'element_list1', 0, undef
	],
	[#Rule 83
		 'element_list1', 3,
sub
#line 297 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 84
		 'element_list2', 0, undef
	],
	[#Rule 85
		 'element_list2', 1, undef
	],
	[#Rule 86
		 'element_list2', 1,
sub
#line 303 "idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 87
		 'element_list2', 3,
sub
#line 304 "idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 88
		 'array_len', 0, undef
	],
	[#Rule 89
		 'array_len', 3,
sub
#line 309 "idl.yp"
{ push(@{$_[3]}, "*"); $_[3] }
	],
	[#Rule 90
		 'array_len', 4,
sub
#line 310 "idl.yp"
{ push(@{$_[4]}, "$_[2]"); $_[4] }
	],
	[#Rule 91
		 'property_list', 0, undef
	],
	[#Rule 92
		 'property_list', 4,
sub
#line 316 "idl.yp"
{ FlattenHash([$_[1],$_[3]]); }
	],
	[#Rule 93
		 'properties', 1,
sub
#line 319 "idl.yp"
{ $_[1] }
	],
	[#Rule 94
		 'properties', 3,
sub
#line 320 "idl.yp"
{ FlattenHash([$_[1], $_[3]]); }
	],
	[#Rule 95
		 'property', 1,
sub
#line 323 "idl.yp"
{{ "$_[1]" => "1"     }}
	],
	[#Rule 96
		 'property', 4,
sub
#line 324 "idl.yp"
{{ "$_[1]" => "$_[3]" }}
	],
	[#Rule 97
		 'listtext', 1, undef
	],
	[#Rule 98
		 'listtext', 3,
sub
#line 329 "idl.yp"
{ "$_[1] $_[3]" }
	],
	[#Rule 99
		 'commalisttext', 1, undef
	],
	[#Rule 100
		 'commalisttext', 3,
sub
#line 334 "idl.yp"
{ "$_[1],$_[3]" }
	],
	[#Rule 101
		 'anytext', 0,
sub
#line 338 "idl.yp"
{ "" }
	],
	[#Rule 102
		 'anytext', 1, undef
	],
	[#Rule 103
		 'anytext', 1, undef
	],
	[#Rule 104
		 'anytext', 1, undef
	],
	[#Rule 105
		 'anytext', 3,
sub
#line 340 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 106
		 'anytext', 3,
sub
#line 341 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 107
		 'anytext', 3,
sub
#line 342 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 108
		 'anytext', 3,
sub
#line 343 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 109
		 'anytext', 3,
sub
#line 344 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 110
		 'anytext', 3,
sub
#line 345 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 111
		 'anytext', 3,
sub
#line 346 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 112
		 'anytext', 3,
sub
#line 347 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 113
		 'anytext', 3,
sub
#line 348 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 114
		 'anytext', 3,
sub
#line 349 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 115
		 'anytext', 3,
sub
#line 350 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 116
		 'anytext', 3,
sub
#line 351 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 117
		 'anytext', 3,
sub
#line 352 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 118
		 'anytext', 5,
sub
#line 353 "idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 119
		 'anytext', 5,
sub
#line 354 "idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 120
		 'identifier', 1, undef
	],
	[#Rule 121
		 'optional_identifier', 1, undef
	],
	[#Rule 122
		 'optional_identifier', 0, undef
	],
	[#Rule 123
		 'constant', 1, undef
	],
	[#Rule 124
		 'text', 1,
sub
#line 368 "idl.yp"
{ "\"$_[1]\"" }
	],
	[#Rule 125
		 'optional_semicolon', 0, undef
	],
	[#Rule 126
		 'optional_semicolon', 1, undef
	]
],
                                  @_);
    bless($self,$class);
}

#line 379 "idl.yp"


use Parse::Pidl qw(error);

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
		error($_[0]->YYData, $_[0]->YYData->{ERRMSG});
		delete $_[0]->YYData->{ERRMSG};
		return;
	};
	my $last_token = $_[0]->YYData->{LAST_TOKEN};
	
	error($_[0]->YYData, "Syntax error near '$last_token'");
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
				$parser->YYData->{FILE} = $2;
				goto again;
			}
			if (s/^\#line (\d+) \"(.*?)\"( \d+|)//) {
				$parser->YYData->{LINE} = $1-1;
				$parser->YYData->{FILE} = $2;
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

    $self->YYData->{FILE} = $filename;
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
