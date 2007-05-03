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
		DEFAULT => -89,
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
		DEFAULT => -122
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
		DEFAULT => -118
	},
	{#State 23
		ACTIONS => {
			"{" => 31
		}
	},
	{#State 24
		ACTIONS => {
			"{" => 32
		}
	},
	{#State 25
		ACTIONS => {
			"," => 33,
			"]" => 34
		}
	},
	{#State 26
		ACTIONS => {
			"(" => 35
		},
		DEFAULT => -93
	},
	{#State 27
		DEFAULT => -91
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
			'interface_names' => 36
		}
	},
	{#State 32
		ACTIONS => {
			"declare" => 44,
			"const" => 48
		},
		DEFAULT => -89,
		GOTOS => {
			'typedecl' => 37,
			'function' => 38,
			'definitions' => 40,
			'bitmap' => 39,
			'definition' => 43,
			'property_list' => 42,
			'usertype' => 41,
			'const' => 47,
			'declare' => 46,
			'struct' => 45,
			'typedef' => 50,
			'enum' => 49,
			'union' => 51
		}
	},
	{#State 33
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 26,
			'property' => 52
		}
	},
	{#State 34
		DEFAULT => -90
	},
	{#State 35
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'text' => 58,
			'listtext' => 54,
			'anytext' => 53,
			'constant' => 55
		}
	},
	{#State 36
		ACTIONS => {
			"}" => 59,
			"interface" => 60
		}
	},
	{#State 37
		DEFAULT => -22
	},
	{#State 38
		DEFAULT => -18
	},
	{#State 39
		DEFAULT => -37
	},
	{#State 40
		ACTIONS => {
			"}" => 61,
			"declare" => 44,
			"const" => 48
		},
		DEFAULT => -89,
		GOTOS => {
			'typedecl' => 37,
			'function' => 38,
			'bitmap' => 39,
			'definition' => 62,
			'property_list' => 42,
			'usertype' => 41,
			'const' => 47,
			'struct' => 45,
			'declare' => 46,
			'typedef' => 50,
			'enum' => 49,
			'union' => 51
		}
	},
	{#State 41
		ACTIONS => {
			";" => 63
		}
	},
	{#State 42
		ACTIONS => {
			"typedef" => 64,
			'IDENTIFIER' => 22,
			"signed" => 72,
			"union" => 65,
			"enum" => 74,
			"bitmap" => 75,
			'void' => 66,
			"unsigned" => 76,
			"[" => 17,
			"struct" => 71
		},
		GOTOS => {
			'existingtype' => 73,
			'bitmap' => 39,
			'usertype' => 68,
			'property_list' => 67,
			'identifier' => 69,
			'struct' => 45,
			'enum' => 49,
			'type' => 77,
			'union' => 51,
			'sign' => 70
		}
	},
	{#State 43
		DEFAULT => -16
	},
	{#State 44
		DEFAULT => -89,
		GOTOS => {
			'decl_enum' => 79,
			'decl_bitmap' => 80,
			'decl_type' => 82,
			'decl_union' => 81,
			'property_list' => 78
		}
	},
	{#State 45
		DEFAULT => -34
	},
	{#State 46
		DEFAULT => -21
	},
	{#State 47
		DEFAULT => -19
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
		DEFAULT => -36
	},
	{#State 50
		DEFAULT => -20
	},
	{#State 51
		DEFAULT => -35
	},
	{#State 52
		DEFAULT => -92
	},
	{#State 53
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"<" => 86,
			"+" => 88,
			"~" => 87,
			"*" => 89,
			"?" => 90,
			"{" => 91,
			"&" => 92,
			"/" => 93,
			"=" => 94,
			"(" => 95,
			"|" => 96,
			"." => 97,
			">" => 98
		},
		DEFAULT => -95
	},
	{#State 54
		ACTIONS => {
			"," => 99,
			")" => 100
		}
	},
	{#State 55
		DEFAULT => -101
	},
	{#State 56
		DEFAULT => -121
	},
	{#State 57
		DEFAULT => -100
	},
	{#State 58
		DEFAULT => -102
	},
	{#State 59
		ACTIONS => {
			";" => 101
		},
		DEFAULT => -123,
		GOTOS => {
			'optional_semicolon' => 102
		}
	},
	{#State 60
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 103
		}
	},
	{#State 61
		ACTIONS => {
			";" => 101
		},
		DEFAULT => -123,
		GOTOS => {
			'optional_semicolon' => 104
		}
	},
	{#State 62
		DEFAULT => -17
	},
	{#State 63
		DEFAULT => -38
	},
	{#State 64
		ACTIONS => {
			'IDENTIFIER' => 22,
			"signed" => 72,
			'void' => 66,
			"unsigned" => 76
		},
		DEFAULT => -89,
		GOTOS => {
			'existingtype' => 73,
			'bitmap' => 39,
			'usertype' => 68,
			'property_list' => 67,
			'identifier' => 69,
			'struct' => 45,
			'enum' => 49,
			'type' => 105,
			'union' => 51,
			'sign' => 70
		}
	},
	{#State 65
		ACTIONS => {
			'IDENTIFIER' => 106
		},
		DEFAULT => -120,
		GOTOS => {
			'optional_identifier' => 107
		}
	},
	{#State 66
		DEFAULT => -45
	},
	{#State 67
		ACTIONS => {
			"union" => 65,
			"enum" => 74,
			"bitmap" => 75,
			"[" => 17,
			"struct" => 71
		}
	},
	{#State 68
		DEFAULT => -43
	},
	{#State 69
		DEFAULT => -42
	},
	{#State 70
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 108
		}
	},
	{#State 71
		ACTIONS => {
			'IDENTIFIER' => 106
		},
		DEFAULT => -120,
		GOTOS => {
			'optional_identifier' => 109
		}
	},
	{#State 72
		DEFAULT => -39
	},
	{#State 73
		DEFAULT => -44
	},
	{#State 74
		ACTIONS => {
			'IDENTIFIER' => 106
		},
		DEFAULT => -120,
		GOTOS => {
			'optional_identifier' => 110
		}
	},
	{#State 75
		ACTIONS => {
			'IDENTIFIER' => 106
		},
		DEFAULT => -120,
		GOTOS => {
			'optional_identifier' => 111
		}
	},
	{#State 76
		DEFAULT => -40
	},
	{#State 77
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 112
		}
	},
	{#State 78
		ACTIONS => {
			"union" => 113,
			"enum" => 114,
			"bitmap" => 115,
			"[" => 17
		}
	},
	{#State 79
		DEFAULT => -27
	},
	{#State 80
		DEFAULT => -28
	},
	{#State 81
		DEFAULT => -29
	},
	{#State 82
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 116
		}
	},
	{#State 83
		DEFAULT => -78,
		GOTOS => {
			'pointers' => 117
		}
	},
	{#State 84
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 118,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 85
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 119,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 86
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 120,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 87
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 121,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 88
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 122,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 89
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 123,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 90
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 124,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 91
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 125,
			'text' => 58,
			'constant' => 55,
			'commalisttext' => 126
		}
	},
	{#State 92
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 127,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 93
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 128,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 94
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 129,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 95
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 125,
			'text' => 58,
			'constant' => 55,
			'commalisttext' => 130
		}
	},
	{#State 96
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 131,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 97
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 132,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 98
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 133,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 99
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 134,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 100
		DEFAULT => -94
	},
	{#State 101
		DEFAULT => -124
	},
	{#State 102
		DEFAULT => -12
	},
	{#State 103
		ACTIONS => {
			";" => 135
		}
	},
	{#State 104
		DEFAULT => -15
	},
	{#State 105
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 136
		}
	},
	{#State 106
		DEFAULT => -119
	},
	{#State 107
		ACTIONS => {
			"{" => 138
		},
		DEFAULT => -74,
		GOTOS => {
			'union_body' => 139,
			'opt_union_body' => 137
		}
	},
	{#State 108
		DEFAULT => -41
	},
	{#State 109
		ACTIONS => {
			"{" => 141
		},
		DEFAULT => -64,
		GOTOS => {
			'struct_body' => 140,
			'opt_struct_body' => 142
		}
	},
	{#State 110
		ACTIONS => {
			"{" => 143
		},
		DEFAULT => -47,
		GOTOS => {
			'opt_enum_body' => 145,
			'enum_body' => 144
		}
	},
	{#State 111
		ACTIONS => {
			"{" => 147
		},
		DEFAULT => -55,
		GOTOS => {
			'bitmap_body' => 148,
			'opt_bitmap_body' => 146
		}
	},
	{#State 112
		ACTIONS => {
			"(" => 149
		}
	},
	{#State 113
		DEFAULT => -32
	},
	{#State 114
		DEFAULT => -30
	},
	{#State 115
		DEFAULT => -31
	},
	{#State 116
		ACTIONS => {
			";" => 150
		}
	},
	{#State 117
		ACTIONS => {
			'IDENTIFIER' => 22,
			"*" => 152
		},
		GOTOS => {
			'identifier' => 151
		}
	},
	{#State 118
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"<" => 86,
			"+" => 88,
			"~" => 87,
			"*" => 89,
			"?" => 90,
			"{" => 91,
			"&" => 92,
			"/" => 93,
			"=" => 94,
			"(" => 95,
			"|" => 96,
			"." => 97,
			">" => 98
		},
		DEFAULT => -112
	},
	{#State 119
		ACTIONS => {
			":" => 84,
			"<" => 86,
			"~" => 87,
			"?" => 90,
			"{" => 91,
			"=" => 94
		},
		DEFAULT => -103
	},
	{#State 120
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"<" => 86,
			"+" => 88,
			"~" => 87,
			"*" => 89,
			"?" => 90,
			"{" => 91,
			"&" => 92,
			"/" => 93,
			"=" => 94,
			"(" => 95,
			"|" => 96,
			"." => 97,
			">" => 98
		},
		DEFAULT => -107
	},
	{#State 121
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"<" => 86,
			"+" => 88,
			"~" => 87,
			"*" => 89,
			"?" => 90,
			"{" => 91,
			"&" => 92,
			"/" => 93,
			"=" => 94,
			"(" => 95,
			"|" => 96,
			"." => 97,
			">" => 98
		},
		DEFAULT => -115
	},
	{#State 122
		ACTIONS => {
			":" => 84,
			"<" => 86,
			"~" => 87,
			"?" => 90,
			"{" => 91,
			"=" => 94
		},
		DEFAULT => -114
	},
	{#State 123
		ACTIONS => {
			":" => 84,
			"<" => 86,
			"~" => 87,
			"?" => 90,
			"{" => 91,
			"=" => 94
		},
		DEFAULT => -105
	},
	{#State 124
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"<" => 86,
			"+" => 88,
			"~" => 87,
			"*" => 89,
			"?" => 90,
			"{" => 91,
			"&" => 92,
			"/" => 93,
			"=" => 94,
			"(" => 95,
			"|" => 96,
			"." => 97,
			">" => 98
		},
		DEFAULT => -111
	},
	{#State 125
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"<" => 86,
			"+" => 88,
			"~" => 87,
			"*" => 89,
			"?" => 90,
			"{" => 91,
			"&" => 92,
			"/" => 93,
			"=" => 94,
			"(" => 95,
			"|" => 96,
			"." => 97,
			">" => 98
		},
		DEFAULT => -97
	},
	{#State 126
		ACTIONS => {
			"}" => 153,
			"," => 154
		}
	},
	{#State 127
		ACTIONS => {
			":" => 84,
			"<" => 86,
			"~" => 87,
			"?" => 90,
			"{" => 91,
			"=" => 94
		},
		DEFAULT => -109
	},
	{#State 128
		ACTIONS => {
			":" => 84,
			"<" => 86,
			"~" => 87,
			"?" => 90,
			"{" => 91,
			"=" => 94
		},
		DEFAULT => -110
	},
	{#State 129
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"<" => 86,
			"+" => 88,
			"~" => 87,
			"*" => 89,
			"?" => 90,
			"{" => 91,
			"&" => 92,
			"/" => 93,
			"=" => 94,
			"(" => 95,
			"|" => 96,
			"." => 97,
			">" => 98
		},
		DEFAULT => -113
	},
	{#State 130
		ACTIONS => {
			"," => 154,
			")" => 155
		}
	},
	{#State 131
		ACTIONS => {
			":" => 84,
			"<" => 86,
			"~" => 87,
			"?" => 90,
			"{" => 91,
			"=" => 94
		},
		DEFAULT => -108
	},
	{#State 132
		ACTIONS => {
			":" => 84,
			"<" => 86,
			"~" => 87,
			"?" => 90,
			"{" => 91,
			"=" => 94
		},
		DEFAULT => -104
	},
	{#State 133
		ACTIONS => {
			":" => 84,
			"<" => 86,
			"~" => 87,
			"?" => 90,
			"{" => 91,
			"=" => 94
		},
		DEFAULT => -106
	},
	{#State 134
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"<" => 86,
			"+" => 88,
			"~" => 87,
			"*" => 89,
			"?" => 90,
			"{" => 91,
			"&" => 92,
			"/" => 93,
			"=" => 94,
			"(" => 95,
			"|" => 96,
			"." => 97,
			">" => 98
		},
		DEFAULT => -96
	},
	{#State 135
		DEFAULT => -14
	},
	{#State 136
		ACTIONS => {
			"[" => 156
		},
		DEFAULT => -86,
		GOTOS => {
			'array_len' => 157
		}
	},
	{#State 137
		DEFAULT => -76
	},
	{#State 138
		DEFAULT => -71,
		GOTOS => {
			'union_elements' => 158
		}
	},
	{#State 139
		DEFAULT => -75
	},
	{#State 140
		DEFAULT => -65
	},
	{#State 141
		DEFAULT => -80,
		GOTOS => {
			'element_list1' => 159
		}
	},
	{#State 142
		DEFAULT => -66
	},
	{#State 143
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 160,
			'enum_element' => 161,
			'enum_elements' => 162
		}
	},
	{#State 144
		DEFAULT => -48
	},
	{#State 145
		DEFAULT => -49
	},
	{#State 146
		DEFAULT => -57
	},
	{#State 147
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		DEFAULT => -60,
		GOTOS => {
			'identifier' => 165,
			'bitmap_element' => 164,
			'bitmap_elements' => 163,
			'opt_bitmap_elements' => 166
		}
	},
	{#State 148
		DEFAULT => -56
	},
	{#State 149
		ACTIONS => {
			"," => -82,
			"void" => 170,
			")" => -82
		},
		DEFAULT => -89,
		GOTOS => {
			'base_element' => 167,
			'element_list2' => 169,
			'property_list' => 168
		}
	},
	{#State 150
		DEFAULT => -26
	},
	{#State 151
		ACTIONS => {
			"[" => 156,
			"=" => 172
		},
		GOTOS => {
			'array_len' => 171
		}
	},
	{#State 152
		DEFAULT => -79
	},
	{#State 153
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 173,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 154
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 174,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 155
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 175,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 156
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			"]" => 176,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 177,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 157
		ACTIONS => {
			";" => 178
		}
	},
	{#State 158
		ACTIONS => {
			"}" => 179
		},
		DEFAULT => -89,
		GOTOS => {
			'optional_base_element' => 181,
			'property_list' => 180
		}
	},
	{#State 159
		ACTIONS => {
			"}" => 182
		},
		DEFAULT => -89,
		GOTOS => {
			'base_element' => 183,
			'property_list' => 168
		}
	},
	{#State 160
		ACTIONS => {
			"=" => 184
		},
		DEFAULT => -52
	},
	{#State 161
		DEFAULT => -50
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
		DEFAULT => -61
	},
	{#State 164
		DEFAULT => -58
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
		DEFAULT => -84
	},
	{#State 168
		ACTIONS => {
			'IDENTIFIER' => 22,
			"signed" => 72,
			'void' => 66,
			"unsigned" => 76,
			"[" => 17
		},
		DEFAULT => -89,
		GOTOS => {
			'existingtype' => 73,
			'bitmap' => 39,
			'usertype' => 68,
			'property_list' => 67,
			'identifier' => 69,
			'struct' => 45,
			'enum' => 49,
			'type' => 190,
			'union' => 51,
			'sign' => 70
		}
	},
	{#State 169
		ACTIONS => {
			"," => 191,
			")" => 192
		}
	},
	{#State 170
		DEFAULT => -83
	},
	{#State 171
		ACTIONS => {
			"=" => 193
		}
	},
	{#State 172
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 194,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 173
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"<" => 86,
			"+" => 88,
			"~" => 87,
			"*" => 89,
			"?" => 90,
			"{" => 91,
			"&" => 92,
			"/" => 93,
			"=" => 94,
			"(" => 95,
			"|" => 96,
			"." => 97,
			">" => 98
		},
		DEFAULT => -117
	},
	{#State 174
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"<" => 86,
			"+" => 88,
			"~" => 87,
			"*" => 89,
			"?" => 90,
			"{" => 91,
			"&" => 92,
			"/" => 93,
			"=" => 94,
			"(" => 95,
			"|" => 96,
			"." => 97,
			">" => 98
		},
		DEFAULT => -98
	},
	{#State 175
		ACTIONS => {
			":" => 84,
			"<" => 86,
			"~" => 87,
			"?" => 90,
			"{" => 91,
			"=" => 94
		},
		DEFAULT => -116
	},
	{#State 176
		ACTIONS => {
			"[" => 156
		},
		DEFAULT => -86,
		GOTOS => {
			'array_len' => 195
		}
	},
	{#State 177
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"?" => 90,
			"<" => 86,
			"+" => 88,
			"~" => 87,
			"&" => 92,
			"{" => 91,
			"/" => 93,
			"=" => 94,
			"|" => 96,
			"(" => 95,
			"*" => 89,
			"." => 97,
			"]" => 196,
			">" => 98
		}
	},
	{#State 178
		DEFAULT => -33
	},
	{#State 179
		DEFAULT => -73
	},
	{#State 180
		ACTIONS => {
			"[" => 17
		},
		DEFAULT => -89,
		GOTOS => {
			'base_or_empty' => 197,
			'base_element' => 198,
			'empty_element' => 199,
			'property_list' => 200
		}
	},
	{#State 181
		DEFAULT => -72
	},
	{#State 182
		DEFAULT => -63
	},
	{#State 183
		ACTIONS => {
			";" => 201
		}
	},
	{#State 184
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 202,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 185
		DEFAULT => -46
	},
	{#State 186
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 160,
			'enum_element' => 203
		}
	},
	{#State 187
		ACTIONS => {
			'IDENTIFIER' => 22
		},
		GOTOS => {
			'identifier' => 165,
			'bitmap_element' => 204
		}
	},
	{#State 188
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 205,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 189
		DEFAULT => -54
	},
	{#State 190
		DEFAULT => -78,
		GOTOS => {
			'pointers' => 206
		}
	},
	{#State 191
		DEFAULT => -89,
		GOTOS => {
			'base_element' => 207,
			'property_list' => 168
		}
	},
	{#State 192
		ACTIONS => {
			";" => 208
		}
	},
	{#State 193
		ACTIONS => {
			'CONSTANT' => 56,
			'TEXT' => 13,
			'IDENTIFIER' => 22
		},
		DEFAULT => -99,
		GOTOS => {
			'identifier' => 57,
			'anytext' => 209,
			'text' => 58,
			'constant' => 55
		}
	},
	{#State 194
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"?" => 90,
			"<" => 86,
			";" => 210,
			"+" => 88,
			"~" => 87,
			"&" => 92,
			"{" => 91,
			"/" => 93,
			"=" => 94,
			"|" => 96,
			"(" => 95,
			"*" => 89,
			"." => 97,
			">" => 98
		}
	},
	{#State 195
		DEFAULT => -87
	},
	{#State 196
		ACTIONS => {
			"[" => 156
		},
		DEFAULT => -86,
		GOTOS => {
			'array_len' => 211
		}
	},
	{#State 197
		DEFAULT => -70
	},
	{#State 198
		ACTIONS => {
			";" => 212
		}
	},
	{#State 199
		DEFAULT => -69
	},
	{#State 200
		ACTIONS => {
			'IDENTIFIER' => 22,
			"signed" => 72,
			";" => 213,
			'void' => 66,
			"unsigned" => 76,
			"[" => 17
		},
		DEFAULT => -89,
		GOTOS => {
			'existingtype' => 73,
			'bitmap' => 39,
			'usertype' => 68,
			'property_list' => 67,
			'identifier' => 69,
			'struct' => 45,
			'enum' => 49,
			'type' => 190,
			'union' => 51,
			'sign' => 70
		}
	},
	{#State 201
		DEFAULT => -81
	},
	{#State 202
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"<" => 86,
			"+" => 88,
			"~" => 87,
			"*" => 89,
			"?" => 90,
			"{" => 91,
			"&" => 92,
			"/" => 93,
			"=" => 94,
			"(" => 95,
			"|" => 96,
			"." => 97,
			">" => 98
		},
		DEFAULT => -53
	},
	{#State 203
		DEFAULT => -51
	},
	{#State 204
		DEFAULT => -59
	},
	{#State 205
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"<" => 86,
			"+" => 88,
			"~" => 87,
			"*" => 89,
			"?" => 90,
			"{" => 91,
			"&" => 92,
			"/" => 93,
			"=" => 94,
			"(" => 95,
			"|" => 96,
			"." => 97,
			">" => 98
		},
		DEFAULT => -62
	},
	{#State 206
		ACTIONS => {
			'IDENTIFIER' => 22,
			"*" => 152
		},
		GOTOS => {
			'identifier' => 214
		}
	},
	{#State 207
		DEFAULT => -85
	},
	{#State 208
		DEFAULT => -25
	},
	{#State 209
		ACTIONS => {
			"-" => 85,
			":" => 84,
			"?" => 90,
			"<" => 86,
			";" => 215,
			"+" => 88,
			"~" => 87,
			"&" => 92,
			"{" => 91,
			"/" => 93,
			"=" => 94,
			"|" => 96,
			"(" => 95,
			"*" => 89,
			"." => 97,
			">" => 98
		}
	},
	{#State 210
		DEFAULT => -23
	},
	{#State 211
		DEFAULT => -88
	},
	{#State 212
		DEFAULT => -68
	},
	{#State 213
		DEFAULT => -67
	},
	{#State 214
		ACTIONS => {
			"[" => 156
		},
		DEFAULT => -86,
		GOTOS => {
			'array_len' => 216
		}
	},
	{#State 215
		DEFAULT => -24
	},
	{#State 216
		DEFAULT => -77
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
		   "FILE" => $_[0]->YYData->{FILE},
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
		   "FILE" => $_[0]->YYData->{FILE},
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
		   "FILE" => $_[0]->YYData->{FILE},
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
#line 66 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 15
		 'interface', 7,
sub
#line 70 "pidl/idl.yp"
{{
               "TYPE" => "INTERFACE", 
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "DATA" => $_[5],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 16
		 'definitions', 1,
sub
#line 81 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 17
		 'definitions', 2,
sub
#line 82 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 18
		 'definition', 1, undef
	],
	[#Rule 19
		 'definition', 1, undef
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
		 'const', 7,
sub
#line 90 "pidl/idl.yp"
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
	[#Rule 24
		 'const', 8,
sub
#line 100 "pidl/idl.yp"
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
	[#Rule 25
		 'function', 7,
sub
#line 114 "pidl/idl.yp"
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
	[#Rule 26
		 'declare', 4,
sub
#line 126 "pidl/idl.yp"
{{
	             "TYPE" => "DECLARE", 
		     "NAME" => $_[3],
		     "DATA" => $_[2],
		     "FILE" => $_[0]->YYData->{FILE},
		     "LINE" => $_[0]->YYData->{LINE},
        }}
	],
	[#Rule 27
		 'decl_type', 1, undef
	],
	[#Rule 28
		 'decl_type', 1, undef
	],
	[#Rule 29
		 'decl_type', 1, undef
	],
	[#Rule 30
		 'decl_enum', 2,
sub
#line 139 "pidl/idl.yp"
{{
                     "TYPE" => "ENUM",
                     "PROPERTIES" => $_[1]
        }}
	],
	[#Rule 31
		 'decl_bitmap', 2,
sub
#line 146 "pidl/idl.yp"
{{
                     "TYPE" => "BITMAP",
                     "PROPERTIES" => $_[1]
        }}
	],
	[#Rule 32
		 'decl_union', 2,
sub
#line 153 "pidl/idl.yp"
{{
                     "TYPE" => "UNION",
                     "PROPERTIES" => $_[1]
        }}
	],
	[#Rule 33
		 'typedef', 6,
sub
#line 160 "pidl/idl.yp"
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
	[#Rule 34
		 'usertype', 1, undef
	],
	[#Rule 35
		 'usertype', 1, undef
	],
	[#Rule 36
		 'usertype', 1, undef
	],
	[#Rule 37
		 'usertype', 1, undef
	],
	[#Rule 38
		 'typedecl', 2,
sub
#line 173 "pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 39
		 'sign', 1, undef
	],
	[#Rule 40
		 'sign', 1, undef
	],
	[#Rule 41
		 'existingtype', 2,
sub
#line 178 "pidl/idl.yp"
{ ($_[1]?$_[1]:"signed") ." $_[2]" }
	],
	[#Rule 42
		 'existingtype', 1, undef
	],
	[#Rule 43
		 'type', 1, undef
	],
	[#Rule 44
		 'type', 1, undef
	],
	[#Rule 45
		 'type', 1,
sub
#line 182 "pidl/idl.yp"
{ "void" }
	],
	[#Rule 46
		 'enum_body', 3,
sub
#line 184 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 47
		 'opt_enum_body', 0, undef
	],
	[#Rule 48
		 'opt_enum_body', 1, undef
	],
	[#Rule 49
		 'enum', 4,
sub
#line 187 "pidl/idl.yp"
{{
             "TYPE" => "ENUM", 
			 "PROPERTIES" => $_[1],
			 "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 50
		 'enum_elements', 1,
sub
#line 196 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 51
		 'enum_elements', 3,
sub
#line 197 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 52
		 'enum_element', 1, undef
	],
	[#Rule 53
		 'enum_element', 3,
sub
#line 201 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 54
		 'bitmap_body', 3,
sub
#line 204 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 55
		 'opt_bitmap_body', 0, undef
	],
	[#Rule 56
		 'opt_bitmap_body', 1, undef
	],
	[#Rule 57
		 'bitmap', 4,
sub
#line 207 "pidl/idl.yp"
{{
             "TYPE" => "BITMAP", 
		     "PROPERTIES" => $_[1],
			 "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 58
		 'bitmap_elements', 1,
sub
#line 216 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 59
		 'bitmap_elements', 3,
sub
#line 217 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 60
		 'opt_bitmap_elements', 0, undef
	],
	[#Rule 61
		 'opt_bitmap_elements', 1, undef
	],
	[#Rule 62
		 'bitmap_element', 3,
sub
#line 222 "pidl/idl.yp"
{ "$_[1] ( $_[3] )" }
	],
	[#Rule 63
		 'struct_body', 3,
sub
#line 225 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 64
		 'opt_struct_body', 0, undef
	],
	[#Rule 65
		 'opt_struct_body', 1, undef
	],
	[#Rule 66
		 'struct', 4,
sub
#line 229 "pidl/idl.yp"
{{
             "TYPE" => "STRUCT", 
			 "PROPERTIES" => $_[1],
			 "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 67
		 'empty_element', 2,
sub
#line 238 "pidl/idl.yp"
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
	[#Rule 68
		 'base_or_empty', 2, undef
	],
	[#Rule 69
		 'base_or_empty', 1, undef
	],
	[#Rule 70
		 'optional_base_element', 2,
sub
#line 252 "pidl/idl.yp"
{ $_[2]->{PROPERTIES} = FlattenHash([$_[1],$_[2]->{PROPERTIES}]); $_[2] }
	],
	[#Rule 71
		 'union_elements', 0, undef
	],
	[#Rule 72
		 'union_elements', 2,
sub
#line 257 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 73
		 'union_body', 3,
sub
#line 260 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 74
		 'opt_union_body', 0, undef
	],
	[#Rule 75
		 'opt_union_body', 1, undef
	],
	[#Rule 76
		 'union', 4,
sub
#line 264 "pidl/idl.yp"
{{
             "TYPE" => "UNION", 
			 "PROPERTIES" => $_[1],
		     "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 77
		 'base_element', 5,
sub
#line 273 "pidl/idl.yp"
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
	[#Rule 78
		 'pointers', 0,
sub
#line 287 "pidl/idl.yp"
{ 0 }
	],
	[#Rule 79
		 'pointers', 2,
sub
#line 288 "pidl/idl.yp"
{ $_[1]+1 }
	],
	[#Rule 80
		 'element_list1', 0,
sub
#line 292 "pidl/idl.yp"
{ [] }
	],
	[#Rule 81
		 'element_list1', 3,
sub
#line 293 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 82
		 'element_list2', 0, undef
	],
	[#Rule 83
		 'element_list2', 1, undef
	],
	[#Rule 84
		 'element_list2', 1,
sub
#line 299 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 85
		 'element_list2', 3,
sub
#line 300 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 86
		 'array_len', 0, undef
	],
	[#Rule 87
		 'array_len', 3,
sub
#line 305 "pidl/idl.yp"
{ push(@{$_[3]}, "*"); $_[3] }
	],
	[#Rule 88
		 'array_len', 4,
sub
#line 306 "pidl/idl.yp"
{ push(@{$_[4]}, "$_[2]"); $_[4] }
	],
	[#Rule 89
		 'property_list', 0, undef
	],
	[#Rule 90
		 'property_list', 4,
sub
#line 312 "pidl/idl.yp"
{ FlattenHash([$_[1],$_[3]]); }
	],
	[#Rule 91
		 'properties', 1,
sub
#line 315 "pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 92
		 'properties', 3,
sub
#line 316 "pidl/idl.yp"
{ FlattenHash([$_[1], $_[3]]); }
	],
	[#Rule 93
		 'property', 1,
sub
#line 319 "pidl/idl.yp"
{{ "$_[1]" => "1"     }}
	],
	[#Rule 94
		 'property', 4,
sub
#line 320 "pidl/idl.yp"
{{ "$_[1]" => "$_[3]" }}
	],
	[#Rule 95
		 'listtext', 1, undef
	],
	[#Rule 96
		 'listtext', 3,
sub
#line 325 "pidl/idl.yp"
{ "$_[1] $_[3]" }
	],
	[#Rule 97
		 'commalisttext', 1, undef
	],
	[#Rule 98
		 'commalisttext', 3,
sub
#line 330 "pidl/idl.yp"
{ "$_[1],$_[3]" }
	],
	[#Rule 99
		 'anytext', 0,
sub
#line 334 "pidl/idl.yp"
{ "" }
	],
	[#Rule 100
		 'anytext', 1, undef
	],
	[#Rule 101
		 'anytext', 1, undef
	],
	[#Rule 102
		 'anytext', 1, undef
	],
	[#Rule 103
		 'anytext', 3,
sub
#line 336 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 104
		 'anytext', 3,
sub
#line 337 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 105
		 'anytext', 3,
sub
#line 338 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 106
		 'anytext', 3,
sub
#line 339 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 107
		 'anytext', 3,
sub
#line 340 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 108
		 'anytext', 3,
sub
#line 341 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 109
		 'anytext', 3,
sub
#line 342 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 110
		 'anytext', 3,
sub
#line 343 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 111
		 'anytext', 3,
sub
#line 344 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 112
		 'anytext', 3,
sub
#line 345 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 113
		 'anytext', 3,
sub
#line 346 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 114
		 'anytext', 3,
sub
#line 347 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 115
		 'anytext', 3,
sub
#line 348 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 116
		 'anytext', 5,
sub
#line 349 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 117
		 'anytext', 5,
sub
#line 350 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 118
		 'identifier', 1, undef
	],
	[#Rule 119
		 'optional_identifier', 1, undef
	],
	[#Rule 120
		 'optional_identifier', 0, undef
	],
	[#Rule 121
		 'constant', 1, undef
	],
	[#Rule 122
		 'text', 1,
sub
#line 364 "pidl/idl.yp"
{ "\"$_[1]\"" }
	],
	[#Rule 123
		 'optional_semicolon', 0, undef
	],
	[#Rule 124
		 'optional_semicolon', 1, undef
	]
],
                                  @_);
    bless($self,$class);
}

#line 375 "pidl/idl.yp"


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
	}
	# this removes any undefined elements from the array
	@{$v} = grep { defined $_ } @{$v};
    } elsif (ref($v) eq "HASH") {
	foreach my $x (keys %{$v}) {
	    CleanData($v->{$x});
	    if (!defined $v->{$x}) { delete($v->{$x}); next; }
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
