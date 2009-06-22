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
			"cpp_quote" => 3,
			"importlib" => 4,
			"import" => 7,
			"include" => 13
		},
		DEFAULT => -91,
		GOTOS => {
			'cpp_quote' => 11,
			'importlib' => 10,
			'interface' => 9,
			'include' => 5,
			'coclass' => 12,
			'import' => 8,
			'property_list' => 6
		}
	},
	{#State 2
		DEFAULT => 0
	},
	{#State 3
		ACTIONS => {
			"(" => 14
		}
	},
	{#State 4
		ACTIONS => {
			'TEXT' => 16
		},
		GOTOS => {
			'commalist' => 15,
			'text' => 17
		}
	},
	{#State 5
		DEFAULT => -5
	},
	{#State 6
		ACTIONS => {
			"coclass" => 18,
			"[" => 20,
			"interface" => 19
		}
	},
	{#State 7
		ACTIONS => {
			'TEXT' => 16
		},
		GOTOS => {
			'commalist' => 21,
			'text' => 17
		}
	},
	{#State 8
		DEFAULT => -4
	},
	{#State 9
		DEFAULT => -2
	},
	{#State 10
		DEFAULT => -6
	},
	{#State 11
		DEFAULT => -7
	},
	{#State 12
		DEFAULT => -3
	},
	{#State 13
		ACTIONS => {
			'TEXT' => 16
		},
		GOTOS => {
			'commalist' => 22,
			'text' => 17
		}
	},
	{#State 14
		ACTIONS => {
			'TEXT' => 16
		},
		GOTOS => {
			'text' => 23
		}
	},
	{#State 15
		ACTIONS => {
			";" => 24,
			"," => 25
		}
	},
	{#State 16
		DEFAULT => -124
	},
	{#State 17
		DEFAULT => -11
	},
	{#State 18
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 27
		}
	},
	{#State 19
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 28
		}
	},
	{#State 20
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 30,
			'property' => 31,
			'properties' => 29
		}
	},
	{#State 21
		ACTIONS => {
			";" => 32,
			"," => 25
		}
	},
	{#State 22
		ACTIONS => {
			";" => 33,
			"," => 25
		}
	},
	{#State 23
		ACTIONS => {
			")" => 34
		}
	},
	{#State 24
		DEFAULT => -10
	},
	{#State 25
		ACTIONS => {
			'TEXT' => 16
		},
		GOTOS => {
			'text' => 35
		}
	},
	{#State 26
		DEFAULT => -120
	},
	{#State 27
		ACTIONS => {
			"{" => 36
		}
	},
	{#State 28
		ACTIONS => {
			"{" => 37
		}
	},
	{#State 29
		ACTIONS => {
			"," => 38,
			"]" => 39
		}
	},
	{#State 30
		ACTIONS => {
			"(" => 40
		},
		DEFAULT => -95
	},
	{#State 31
		DEFAULT => -93
	},
	{#State 32
		DEFAULT => -8
	},
	{#State 33
		DEFAULT => -9
	},
	{#State 34
		DEFAULT => -17
	},
	{#State 35
		DEFAULT => -12
	},
	{#State 36
		DEFAULT => -14,
		GOTOS => {
			'interface_names' => 41
		}
	},
	{#State 37
		ACTIONS => {
			"declare" => 49,
			"const" => 53
		},
		DEFAULT => -91,
		GOTOS => {
			'typedecl' => 42,
			'function' => 43,
			'definitions' => 45,
			'bitmap' => 44,
			'definition' => 48,
			'property_list' => 47,
			'usertype' => 46,
			'const' => 52,
			'declare' => 51,
			'struct' => 50,
			'typedef' => 55,
			'enum' => 54,
			'union' => 56
		}
	},
	{#State 38
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 30,
			'property' => 57
		}
	},
	{#State 39
		DEFAULT => -92
	},
	{#State 40
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'text' => 63,
			'listtext' => 59,
			'anytext' => 58,
			'constant' => 60
		}
	},
	{#State 41
		ACTIONS => {
			"}" => 64,
			"interface" => 65
		}
	},
	{#State 42
		DEFAULT => -24
	},
	{#State 43
		DEFAULT => -20
	},
	{#State 44
		DEFAULT => -39
	},
	{#State 45
		ACTIONS => {
			"}" => 66,
			"declare" => 49,
			"const" => 53
		},
		DEFAULT => -91,
		GOTOS => {
			'typedecl' => 42,
			'function' => 43,
			'bitmap' => 44,
			'definition' => 67,
			'property_list' => 47,
			'usertype' => 46,
			'const' => 52,
			'struct' => 50,
			'declare' => 51,
			'typedef' => 55,
			'enum' => 54,
			'union' => 56
		}
	},
	{#State 46
		ACTIONS => {
			";" => 68
		}
	},
	{#State 47
		ACTIONS => {
			"typedef" => 69,
			'IDENTIFIER' => 26,
			"signed" => 77,
			"union" => 70,
			"enum" => 79,
			"bitmap" => 80,
			'void' => 71,
			"unsigned" => 81,
			"[" => 20,
			"struct" => 76
		},
		GOTOS => {
			'existingtype' => 78,
			'bitmap' => 44,
			'usertype' => 73,
			'property_list' => 72,
			'identifier' => 74,
			'struct' => 50,
			'enum' => 54,
			'type' => 82,
			'union' => 56,
			'sign' => 75
		}
	},
	{#State 48
		DEFAULT => -18
	},
	{#State 49
		DEFAULT => -91,
		GOTOS => {
			'decl_enum' => 84,
			'decl_bitmap' => 85,
			'decl_type' => 87,
			'decl_union' => 86,
			'property_list' => 83
		}
	},
	{#State 50
		DEFAULT => -36
	},
	{#State 51
		DEFAULT => -23
	},
	{#State 52
		DEFAULT => -21
	},
	{#State 53
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 88
		}
	},
	{#State 54
		DEFAULT => -38
	},
	{#State 55
		DEFAULT => -22
	},
	{#State 56
		DEFAULT => -37
	},
	{#State 57
		DEFAULT => -94
	},
	{#State 58
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"<" => 91,
			"+" => 93,
			"~" => 92,
			"*" => 94,
			"?" => 95,
			"{" => 96,
			"&" => 97,
			"/" => 98,
			"=" => 99,
			"(" => 100,
			"|" => 101,
			"." => 102,
			">" => 103
		},
		DEFAULT => -97
	},
	{#State 59
		ACTIONS => {
			"," => 104,
			")" => 105
		}
	},
	{#State 60
		DEFAULT => -103
	},
	{#State 61
		DEFAULT => -123
	},
	{#State 62
		DEFAULT => -102
	},
	{#State 63
		DEFAULT => -104
	},
	{#State 64
		ACTIONS => {
			";" => 106
		},
		DEFAULT => -125,
		GOTOS => {
			'optional_semicolon' => 107
		}
	},
	{#State 65
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 108
		}
	},
	{#State 66
		ACTIONS => {
			";" => 106
		},
		DEFAULT => -125,
		GOTOS => {
			'optional_semicolon' => 109
		}
	},
	{#State 67
		DEFAULT => -19
	},
	{#State 68
		DEFAULT => -40
	},
	{#State 69
		ACTIONS => {
			'IDENTIFIER' => 26,
			"signed" => 77,
			'void' => 71,
			"unsigned" => 81
		},
		DEFAULT => -91,
		GOTOS => {
			'existingtype' => 78,
			'bitmap' => 44,
			'usertype' => 73,
			'property_list' => 72,
			'identifier' => 74,
			'struct' => 50,
			'enum' => 54,
			'type' => 110,
			'union' => 56,
			'sign' => 75
		}
	},
	{#State 70
		ACTIONS => {
			'IDENTIFIER' => 111
		},
		DEFAULT => -122,
		GOTOS => {
			'optional_identifier' => 112
		}
	},
	{#State 71
		DEFAULT => -47
	},
	{#State 72
		ACTIONS => {
			"union" => 70,
			"enum" => 79,
			"bitmap" => 80,
			"[" => 20,
			"struct" => 76
		}
	},
	{#State 73
		DEFAULT => -45
	},
	{#State 74
		DEFAULT => -44
	},
	{#State 75
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 113
		}
	},
	{#State 76
		ACTIONS => {
			'IDENTIFIER' => 111
		},
		DEFAULT => -122,
		GOTOS => {
			'optional_identifier' => 114
		}
	},
	{#State 77
		DEFAULT => -41
	},
	{#State 78
		DEFAULT => -46
	},
	{#State 79
		ACTIONS => {
			'IDENTIFIER' => 111
		},
		DEFAULT => -122,
		GOTOS => {
			'optional_identifier' => 115
		}
	},
	{#State 80
		ACTIONS => {
			'IDENTIFIER' => 111
		},
		DEFAULT => -122,
		GOTOS => {
			'optional_identifier' => 116
		}
	},
	{#State 81
		DEFAULT => -42
	},
	{#State 82
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 117
		}
	},
	{#State 83
		ACTIONS => {
			"union" => 118,
			"enum" => 119,
			"bitmap" => 120,
			"[" => 20
		}
	},
	{#State 84
		DEFAULT => -29
	},
	{#State 85
		DEFAULT => -30
	},
	{#State 86
		DEFAULT => -31
	},
	{#State 87
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 121
		}
	},
	{#State 88
		DEFAULT => -80,
		GOTOS => {
			'pointers' => 122
		}
	},
	{#State 89
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 123,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 90
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 124,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 91
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 125,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 92
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 126,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 93
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 127,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 94
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 128,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 95
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 129,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 96
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 130,
			'text' => 63,
			'constant' => 60,
			'commalisttext' => 131
		}
	},
	{#State 97
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 132,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 98
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 133,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 99
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 134,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 100
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 130,
			'text' => 63,
			'constant' => 60,
			'commalisttext' => 135
		}
	},
	{#State 101
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 136,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 102
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 137,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 103
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 138,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 104
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 139,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 105
		DEFAULT => -96
	},
	{#State 106
		DEFAULT => -126
	},
	{#State 107
		DEFAULT => -13
	},
	{#State 108
		ACTIONS => {
			";" => 140
		}
	},
	{#State 109
		DEFAULT => -16
	},
	{#State 110
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 141
		}
	},
	{#State 111
		DEFAULT => -121
	},
	{#State 112
		ACTIONS => {
			"{" => 143
		},
		DEFAULT => -76,
		GOTOS => {
			'union_body' => 144,
			'opt_union_body' => 142
		}
	},
	{#State 113
		DEFAULT => -43
	},
	{#State 114
		ACTIONS => {
			"{" => 146
		},
		DEFAULT => -66,
		GOTOS => {
			'struct_body' => 145,
			'opt_struct_body' => 147
		}
	},
	{#State 115
		ACTIONS => {
			"{" => 148
		},
		DEFAULT => -49,
		GOTOS => {
			'opt_enum_body' => 150,
			'enum_body' => 149
		}
	},
	{#State 116
		ACTIONS => {
			"{" => 152
		},
		DEFAULT => -57,
		GOTOS => {
			'bitmap_body' => 153,
			'opt_bitmap_body' => 151
		}
	},
	{#State 117
		ACTIONS => {
			"(" => 154
		}
	},
	{#State 118
		DEFAULT => -34
	},
	{#State 119
		DEFAULT => -32
	},
	{#State 120
		DEFAULT => -33
	},
	{#State 121
		ACTIONS => {
			";" => 155
		}
	},
	{#State 122
		ACTIONS => {
			'IDENTIFIER' => 26,
			"*" => 157
		},
		GOTOS => {
			'identifier' => 156
		}
	},
	{#State 123
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"<" => 91,
			"+" => 93,
			"~" => 92,
			"*" => 94,
			"?" => 95,
			"{" => 96,
			"&" => 97,
			"/" => 98,
			"=" => 99,
			"(" => 100,
			"|" => 101,
			"." => 102,
			">" => 103
		},
		DEFAULT => -114
	},
	{#State 124
		ACTIONS => {
			":" => 89,
			"<" => 91,
			"~" => 92,
			"?" => 95,
			"{" => 96,
			"=" => 99
		},
		DEFAULT => -105
	},
	{#State 125
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"<" => 91,
			"+" => 93,
			"~" => 92,
			"*" => 94,
			"?" => 95,
			"{" => 96,
			"&" => 97,
			"/" => 98,
			"=" => 99,
			"(" => 100,
			"|" => 101,
			"." => 102,
			">" => 103
		},
		DEFAULT => -109
	},
	{#State 126
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"<" => 91,
			"+" => 93,
			"~" => 92,
			"*" => 94,
			"?" => 95,
			"{" => 96,
			"&" => 97,
			"/" => 98,
			"=" => 99,
			"(" => 100,
			"|" => 101,
			"." => 102,
			">" => 103
		},
		DEFAULT => -117
	},
	{#State 127
		ACTIONS => {
			":" => 89,
			"<" => 91,
			"~" => 92,
			"?" => 95,
			"{" => 96,
			"=" => 99
		},
		DEFAULT => -116
	},
	{#State 128
		ACTIONS => {
			":" => 89,
			"<" => 91,
			"~" => 92,
			"?" => 95,
			"{" => 96,
			"=" => 99
		},
		DEFAULT => -107
	},
	{#State 129
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"<" => 91,
			"+" => 93,
			"~" => 92,
			"*" => 94,
			"?" => 95,
			"{" => 96,
			"&" => 97,
			"/" => 98,
			"=" => 99,
			"(" => 100,
			"|" => 101,
			"." => 102,
			">" => 103
		},
		DEFAULT => -113
	},
	{#State 130
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"<" => 91,
			"+" => 93,
			"~" => 92,
			"*" => 94,
			"?" => 95,
			"{" => 96,
			"&" => 97,
			"/" => 98,
			"=" => 99,
			"(" => 100,
			"|" => 101,
			"." => 102,
			">" => 103
		},
		DEFAULT => -99
	},
	{#State 131
		ACTIONS => {
			"}" => 158,
			"," => 159
		}
	},
	{#State 132
		ACTIONS => {
			":" => 89,
			"<" => 91,
			"~" => 92,
			"?" => 95,
			"{" => 96,
			"=" => 99
		},
		DEFAULT => -111
	},
	{#State 133
		ACTIONS => {
			":" => 89,
			"<" => 91,
			"~" => 92,
			"?" => 95,
			"{" => 96,
			"=" => 99
		},
		DEFAULT => -112
	},
	{#State 134
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"<" => 91,
			"+" => 93,
			"~" => 92,
			"*" => 94,
			"?" => 95,
			"{" => 96,
			"&" => 97,
			"/" => 98,
			"=" => 99,
			"(" => 100,
			"|" => 101,
			"." => 102,
			">" => 103
		},
		DEFAULT => -115
	},
	{#State 135
		ACTIONS => {
			"," => 159,
			")" => 160
		}
	},
	{#State 136
		ACTIONS => {
			":" => 89,
			"<" => 91,
			"~" => 92,
			"?" => 95,
			"{" => 96,
			"=" => 99
		},
		DEFAULT => -110
	},
	{#State 137
		ACTIONS => {
			":" => 89,
			"<" => 91,
			"~" => 92,
			"?" => 95,
			"{" => 96,
			"=" => 99
		},
		DEFAULT => -106
	},
	{#State 138
		ACTIONS => {
			":" => 89,
			"<" => 91,
			"~" => 92,
			"?" => 95,
			"{" => 96,
			"=" => 99
		},
		DEFAULT => -108
	},
	{#State 139
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"<" => 91,
			"+" => 93,
			"~" => 92,
			"*" => 94,
			"?" => 95,
			"{" => 96,
			"&" => 97,
			"/" => 98,
			"=" => 99,
			"(" => 100,
			"|" => 101,
			"." => 102,
			">" => 103
		},
		DEFAULT => -98
	},
	{#State 140
		DEFAULT => -15
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
			'IDENTIFIER' => 26
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
			'IDENTIFIER' => 26
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
		DEFAULT => -28
	},
	{#State 156
		ACTIONS => {
			"[" => 161,
			"=" => 177
		},
		GOTOS => {
			'array_len' => 176
		}
	},
	{#State 157
		DEFAULT => -81
	},
	{#State 158
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 178,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 159
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 179,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 160
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 180,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 161
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			"]" => 181,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 182,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 162
		ACTIONS => {
			";" => 183
		}
	},
	{#State 163
		ACTIONS => {
			"}" => 184
		},
		DEFAULT => -91,
		GOTOS => {
			'optional_base_element' => 186,
			'property_list' => 185
		}
	},
	{#State 164
		ACTIONS => {
			"}" => 187
		},
		DEFAULT => -91,
		GOTOS => {
			'base_element' => 188,
			'property_list' => 173
		}
	},
	{#State 165
		ACTIONS => {
			"=" => 189
		},
		DEFAULT => -54
	},
	{#State 166
		DEFAULT => -52
	},
	{#State 167
		ACTIONS => {
			"}" => 190,
			"," => 191
		}
	},
	{#State 168
		ACTIONS => {
			"," => 192
		},
		DEFAULT => -63
	},
	{#State 169
		DEFAULT => -60
	},
	{#State 170
		ACTIONS => {
			"=" => 193
		}
	},
	{#State 171
		ACTIONS => {
			"}" => 194
		}
	},
	{#State 172
		DEFAULT => -86
	},
	{#State 173
		ACTIONS => {
			'IDENTIFIER' => 26,
			"signed" => 77,
			'void' => 71,
			"unsigned" => 81,
			"[" => 20
		},
		DEFAULT => -91,
		GOTOS => {
			'existingtype' => 78,
			'bitmap' => 44,
			'usertype' => 73,
			'property_list' => 72,
			'identifier' => 74,
			'struct' => 50,
			'enum' => 54,
			'type' => 195,
			'union' => 56,
			'sign' => 75
		}
	},
	{#State 174
		ACTIONS => {
			"," => 196,
			")" => 197
		}
	},
	{#State 175
		DEFAULT => -85
	},
	{#State 176
		ACTIONS => {
			"=" => 198
		}
	},
	{#State 177
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 199,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 178
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"<" => 91,
			"+" => 93,
			"~" => 92,
			"*" => 94,
			"?" => 95,
			"{" => 96,
			"&" => 97,
			"/" => 98,
			"=" => 99,
			"(" => 100,
			"|" => 101,
			"." => 102,
			">" => 103
		},
		DEFAULT => -119
	},
	{#State 179
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"<" => 91,
			"+" => 93,
			"~" => 92,
			"*" => 94,
			"?" => 95,
			"{" => 96,
			"&" => 97,
			"/" => 98,
			"=" => 99,
			"(" => 100,
			"|" => 101,
			"." => 102,
			">" => 103
		},
		DEFAULT => -100
	},
	{#State 180
		ACTIONS => {
			":" => 89,
			"<" => 91,
			"~" => 92,
			"?" => 95,
			"{" => 96,
			"=" => 99
		},
		DEFAULT => -118
	},
	{#State 181
		ACTIONS => {
			"[" => 161
		},
		DEFAULT => -88,
		GOTOS => {
			'array_len' => 200
		}
	},
	{#State 182
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"?" => 95,
			"<" => 91,
			"+" => 93,
			"~" => 92,
			"&" => 97,
			"{" => 96,
			"/" => 98,
			"=" => 99,
			"|" => 101,
			"(" => 100,
			"*" => 94,
			"." => 102,
			"]" => 201,
			">" => 103
		}
	},
	{#State 183
		DEFAULT => -35
	},
	{#State 184
		DEFAULT => -75
	},
	{#State 185
		ACTIONS => {
			"[" => 20
		},
		DEFAULT => -91,
		GOTOS => {
			'base_or_empty' => 202,
			'base_element' => 203,
			'empty_element' => 204,
			'property_list' => 205
		}
	},
	{#State 186
		DEFAULT => -74
	},
	{#State 187
		DEFAULT => -65
	},
	{#State 188
		ACTIONS => {
			";" => 206
		}
	},
	{#State 189
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 207,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 190
		DEFAULT => -48
	},
	{#State 191
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 165,
			'enum_element' => 208
		}
	},
	{#State 192
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 170,
			'bitmap_element' => 209
		}
	},
	{#State 193
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 210,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 194
		DEFAULT => -56
	},
	{#State 195
		DEFAULT => -80,
		GOTOS => {
			'pointers' => 211
		}
	},
	{#State 196
		DEFAULT => -91,
		GOTOS => {
			'base_element' => 212,
			'property_list' => 173
		}
	},
	{#State 197
		ACTIONS => {
			";" => 213
		}
	},
	{#State 198
		ACTIONS => {
			'CONSTANT' => 61,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -101,
		GOTOS => {
			'identifier' => 62,
			'anytext' => 214,
			'text' => 63,
			'constant' => 60
		}
	},
	{#State 199
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"?" => 95,
			"<" => 91,
			";" => 215,
			"+" => 93,
			"~" => 92,
			"&" => 97,
			"{" => 96,
			"/" => 98,
			"=" => 99,
			"|" => 101,
			"(" => 100,
			"*" => 94,
			"." => 102,
			">" => 103
		}
	},
	{#State 200
		DEFAULT => -89
	},
	{#State 201
		ACTIONS => {
			"[" => 161
		},
		DEFAULT => -88,
		GOTOS => {
			'array_len' => 216
		}
	},
	{#State 202
		DEFAULT => -72
	},
	{#State 203
		ACTIONS => {
			";" => 217
		}
	},
	{#State 204
		DEFAULT => -71
	},
	{#State 205
		ACTIONS => {
			'IDENTIFIER' => 26,
			"signed" => 77,
			";" => 218,
			'void' => 71,
			"unsigned" => 81,
			"[" => 20
		},
		DEFAULT => -91,
		GOTOS => {
			'existingtype' => 78,
			'bitmap' => 44,
			'usertype' => 73,
			'property_list' => 72,
			'identifier' => 74,
			'struct' => 50,
			'enum' => 54,
			'type' => 195,
			'union' => 56,
			'sign' => 75
		}
	},
	{#State 206
		DEFAULT => -83
	},
	{#State 207
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"<" => 91,
			"+" => 93,
			"~" => 92,
			"*" => 94,
			"?" => 95,
			"{" => 96,
			"&" => 97,
			"/" => 98,
			"=" => 99,
			"(" => 100,
			"|" => 101,
			"." => 102,
			">" => 103
		},
		DEFAULT => -55
	},
	{#State 208
		DEFAULT => -53
	},
	{#State 209
		DEFAULT => -61
	},
	{#State 210
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"<" => 91,
			"+" => 93,
			"~" => 92,
			"*" => 94,
			"?" => 95,
			"{" => 96,
			"&" => 97,
			"/" => 98,
			"=" => 99,
			"(" => 100,
			"|" => 101,
			"." => 102,
			">" => 103
		},
		DEFAULT => -64
	},
	{#State 211
		ACTIONS => {
			'IDENTIFIER' => 26,
			"*" => 157
		},
		GOTOS => {
			'identifier' => 219
		}
	},
	{#State 212
		DEFAULT => -87
	},
	{#State 213
		DEFAULT => -27
	},
	{#State 214
		ACTIONS => {
			"-" => 90,
			":" => 89,
			"?" => 95,
			"<" => 91,
			";" => 220,
			"+" => 93,
			"~" => 92,
			"&" => 97,
			"{" => 96,
			"/" => 98,
			"=" => 99,
			"|" => 101,
			"(" => 100,
			"*" => 94,
			"." => 102,
			">" => 103
		}
	},
	{#State 215
		DEFAULT => -25
	},
	{#State 216
		DEFAULT => -90
	},
	{#State 217
		DEFAULT => -70
	},
	{#State 218
		DEFAULT => -69
	},
	{#State 219
		ACTIONS => {
			"[" => 161
		},
		DEFAULT => -88,
		GOTOS => {
			'array_len' => 221
		}
	},
	{#State 220
		DEFAULT => -26
	},
	{#State 221
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
		 'idl', 2,
sub
#line 24 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 8
		 'import', 3,
sub
#line 27 "idl.yp"
{{
			"TYPE" => "IMPORT", 
			"PATHS" => $_[2],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 9
		 'include', 3,
sub
#line 34 "idl.yp"
{{ 
			"TYPE" => "INCLUDE", 
			"PATHS" => $_[2],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 10
		 'importlib', 3,
sub
#line 41 "idl.yp"
{{ 
			"TYPE" => "IMPORTLIB", 
			"PATHS" => $_[2],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE}
		}}
	],
	[#Rule 11
		 'commalist', 1,
sub
#line 50 "idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 12
		 'commalist', 3,
sub
#line 51 "idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 13
		 'coclass', 7,
sub
#line 55 "idl.yp"
{{
               "TYPE" => "COCLASS", 
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "DATA" => $_[5],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 14
		 'interface_names', 0, undef
	],
	[#Rule 15
		 'interface_names', 4,
sub
#line 67 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 16
		 'interface', 7,
sub
#line 71 "idl.yp"
{{
               "TYPE" => "INTERFACE", 
	       "PROPERTIES" => $_[1],
	       "NAME" => $_[3],
	       "DATA" => $_[5],
		   "FILE" => $_[0]->YYData->{FILE},
		   "LINE" => $_[0]->YYData->{LINE},
          }}
	],
	[#Rule 17
		 'cpp_quote', 4,
sub
#line 82 "idl.yp"
{{
		 "TYPE" => "CPP_QUOTE",
		 "FILE" => $_[0]->YYData->{FILE},
		 "LINE" => $_[0]->YYData->{LINE},
		 "DATA" => $_[3]
	}}
	],
	[#Rule 18
		 'definitions', 1,
sub
#line 91 "idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 19
		 'definitions', 2,
sub
#line 92 "idl.yp"
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
#line 100 "idl.yp"
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
#line 110 "idl.yp"
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
#line 124 "idl.yp"
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
		 'declare', 4,
sub
#line 136 "idl.yp"
{{
	             "TYPE" => "DECLARE", 
		     "NAME" => $_[3],
		     "DATA" => $_[2],
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
		 'decl_enum', 2,
sub
#line 149 "idl.yp"
{{
                     "TYPE" => "ENUM",
                     "PROPERTIES" => $_[1]
        }}
	],
	[#Rule 33
		 'decl_bitmap', 2,
sub
#line 156 "idl.yp"
{{
                     "TYPE" => "BITMAP",
                     "PROPERTIES" => $_[1]
        }}
	],
	[#Rule 34
		 'decl_union', 2,
sub
#line 163 "idl.yp"
{{
                     "TYPE" => "UNION",
                     "PROPERTIES" => $_[1]
        }}
	],
	[#Rule 35
		 'typedef', 6,
sub
#line 170 "idl.yp"
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
#line 183 "idl.yp"
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
#line 188 "idl.yp"
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
#line 192 "idl.yp"
{ "void" }
	],
	[#Rule 48
		 'enum_body', 3,
sub
#line 194 "idl.yp"
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
#line 197 "idl.yp"
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
#line 206 "idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 53
		 'enum_elements', 3,
sub
#line 207 "idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 54
		 'enum_element', 1, undef
	],
	[#Rule 55
		 'enum_element', 3,
sub
#line 211 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 56
		 'bitmap_body', 3,
sub
#line 214 "idl.yp"
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
#line 217 "idl.yp"
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
#line 226 "idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 61
		 'bitmap_elements', 3,
sub
#line 227 "idl.yp"
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
#line 232 "idl.yp"
{ "$_[1] ( $_[3] )" }
	],
	[#Rule 65
		 'struct_body', 3,
sub
#line 235 "idl.yp"
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
#line 239 "idl.yp"
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
#line 248 "idl.yp"
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
#line 262 "idl.yp"
{ $_[2]->{PROPERTIES} = FlattenHash([$_[1],$_[2]->{PROPERTIES}]); $_[2] }
	],
	[#Rule 73
		 'union_elements', 0, undef
	],
	[#Rule 74
		 'union_elements', 2,
sub
#line 267 "idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 75
		 'union_body', 3,
sub
#line 270 "idl.yp"
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
#line 274 "idl.yp"
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
#line 283 "idl.yp"
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
#line 297 "idl.yp"
{ 0 }
	],
	[#Rule 81
		 'pointers', 2,
sub
#line 298 "idl.yp"
{ $_[1]+1 }
	],
	[#Rule 82
		 'element_list1', 0,
sub
#line 302 "idl.yp"
{ [] }
	],
	[#Rule 83
		 'element_list1', 3,
sub
#line 303 "idl.yp"
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
#line 309 "idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 87
		 'element_list2', 3,
sub
#line 310 "idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 88
		 'array_len', 0, undef
	],
	[#Rule 89
		 'array_len', 3,
sub
#line 315 "idl.yp"
{ push(@{$_[3]}, "*"); $_[3] }
	],
	[#Rule 90
		 'array_len', 4,
sub
#line 316 "idl.yp"
{ push(@{$_[4]}, "$_[2]"); $_[4] }
	],
	[#Rule 91
		 'property_list', 0, undef
	],
	[#Rule 92
		 'property_list', 4,
sub
#line 322 "idl.yp"
{ FlattenHash([$_[1],$_[3]]); }
	],
	[#Rule 93
		 'properties', 1,
sub
#line 325 "idl.yp"
{ $_[1] }
	],
	[#Rule 94
		 'properties', 3,
sub
#line 326 "idl.yp"
{ FlattenHash([$_[1], $_[3]]); }
	],
	[#Rule 95
		 'property', 1,
sub
#line 329 "idl.yp"
{{ "$_[1]" => "1"     }}
	],
	[#Rule 96
		 'property', 4,
sub
#line 330 "idl.yp"
{{ "$_[1]" => "$_[3]" }}
	],
	[#Rule 97
		 'listtext', 1, undef
	],
	[#Rule 98
		 'listtext', 3,
sub
#line 335 "idl.yp"
{ "$_[1] $_[3]" }
	],
	[#Rule 99
		 'commalisttext', 1, undef
	],
	[#Rule 100
		 'commalisttext', 3,
sub
#line 340 "idl.yp"
{ "$_[1],$_[3]" }
	],
	[#Rule 101
		 'anytext', 0,
sub
#line 344 "idl.yp"
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
#line 346 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 106
		 'anytext', 3,
sub
#line 347 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 107
		 'anytext', 3,
sub
#line 348 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 108
		 'anytext', 3,
sub
#line 349 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 109
		 'anytext', 3,
sub
#line 350 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 110
		 'anytext', 3,
sub
#line 351 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 111
		 'anytext', 3,
sub
#line 352 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 112
		 'anytext', 3,
sub
#line 353 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 113
		 'anytext', 3,
sub
#line 354 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 114
		 'anytext', 3,
sub
#line 355 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 115
		 'anytext', 3,
sub
#line 356 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 116
		 'anytext', 3,
sub
#line 357 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 117
		 'anytext', 3,
sub
#line 358 "idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 118
		 'anytext', 5,
sub
#line 359 "idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 119
		 'anytext', 5,
sub
#line 360 "idl.yp"
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
#line 374 "idl.yp"
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

#line 385 "idl.yp"


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
			    /^(coclass|interface|const|typedef|declare|union|cpp_quote
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
