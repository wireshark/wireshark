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
		DEFAULT => -89,
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
		DEFAULT => -120
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
		DEFAULT => -116
	},
	{#State 27
		ACTIONS => {
			"{" => 36
		}
	},
	{#State 28
		ACTIONS => {
			":" => 37
		},
		DEFAULT => -17,
		GOTOS => {
			'base_interface' => 38
		}
	},
	{#State 29
		ACTIONS => {
			"," => 39,
			"]" => 40
		}
	},
	{#State 30
		ACTIONS => {
			"(" => 41
		},
		DEFAULT => -93
	},
	{#State 31
		DEFAULT => -91
	},
	{#State 32
		DEFAULT => -8
	},
	{#State 33
		DEFAULT => -9
	},
	{#State 34
		DEFAULT => -19
	},
	{#State 35
		DEFAULT => -12
	},
	{#State 36
		DEFAULT => -14,
		GOTOS => {
			'interface_names' => 42
		}
	},
	{#State 37
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 43
		}
	},
	{#State 38
		ACTIONS => {
			"{" => 44
		}
	},
	{#State 39
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 30,
			'property' => 45
		}
	},
	{#State 40
		DEFAULT => -90
	},
	{#State 41
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'text' => 51,
			'anytext' => 46,
			'constant' => 47,
			'commalisttext' => 49
		}
	},
	{#State 42
		ACTIONS => {
			"}" => 52,
			"interface" => 53
		}
	},
	{#State 43
		DEFAULT => -18
	},
	{#State 44
		ACTIONS => {
			"const" => 64
		},
		DEFAULT => -89,
		GOTOS => {
			'typedecl' => 54,
			'function' => 55,
			'pipe' => 56,
			'definitions' => 58,
			'bitmap' => 57,
			'definition' => 61,
			'property_list' => 60,
			'usertype' => 59,
			'const' => 63,
			'struct' => 62,
			'typedef' => 66,
			'enum' => 65,
			'union' => 67
		}
	},
	{#State 45
		DEFAULT => -92
	},
	{#State 46
		ACTIONS => {
			"-" => 69,
			":" => 68,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 80,
			"?" => 70,
			"{" => 74,
			"&" => 75,
			"/" => 76,
			"=" => 77,
			"(" => 78,
			"|" => 79,
			"." => 81,
			">" => 82
		},
		DEFAULT => -95
	},
	{#State 47
		DEFAULT => -99
	},
	{#State 48
		DEFAULT => -119
	},
	{#State 49
		ACTIONS => {
			"," => 83,
			")" => 84
		}
	},
	{#State 50
		DEFAULT => -98
	},
	{#State 51
		DEFAULT => -100
	},
	{#State 52
		ACTIONS => {
			";" => 86
		},
		DEFAULT => -121,
		GOTOS => {
			'optional_semicolon' => 85
		}
	},
	{#State 53
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 87
		}
	},
	{#State 54
		DEFAULT => -25
	},
	{#State 55
		DEFAULT => -22
	},
	{#State 56
		DEFAULT => -34
	},
	{#State 57
		DEFAULT => -33
	},
	{#State 58
		ACTIONS => {
			"}" => 88,
			"const" => 64
		},
		DEFAULT => -89,
		GOTOS => {
			'typedecl' => 54,
			'function' => 55,
			'pipe' => 56,
			'bitmap' => 57,
			'definition' => 89,
			'property_list' => 60,
			'usertype' => 59,
			'const' => 63,
			'struct' => 62,
			'typedef' => 66,
			'enum' => 65,
			'union' => 67
		}
	},
	{#State 59
		ACTIONS => {
			";" => 90
		}
	},
	{#State 60
		ACTIONS => {
			"typedef" => 91,
			'IDENTIFIER' => 26,
			"signed" => 100,
			"union" => 92,
			"enum" => 101,
			"bitmap" => 102,
			'void' => 93,
			"pipe" => 103,
			"unsigned" => 104,
			"[" => 20,
			"struct" => 98
		},
		GOTOS => {
			'existingtype' => 99,
			'pipe' => 56,
			'bitmap' => 57,
			'usertype' => 95,
			'property_list' => 94,
			'identifier' => 96,
			'struct' => 62,
			'enum' => 65,
			'type' => 105,
			'union' => 67,
			'sign' => 97
		}
	},
	{#State 61
		DEFAULT => -20
	},
	{#State 62
		DEFAULT => -30
	},
	{#State 63
		DEFAULT => -23
	},
	{#State 64
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 106
		}
	},
	{#State 65
		DEFAULT => -32
	},
	{#State 66
		DEFAULT => -24
	},
	{#State 67
		DEFAULT => -31
	},
	{#State 68
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 107,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 69
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 108,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 70
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 109,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 71
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 110,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 72
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 111,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 73
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 112,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 74
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 46,
			'text' => 51,
			'constant' => 47,
			'commalisttext' => 113
		}
	},
	{#State 75
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 114,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 76
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 115,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 77
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 116,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 78
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 46,
			'text' => 51,
			'constant' => 47,
			'commalisttext' => 117
		}
	},
	{#State 79
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 118,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 80
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 119,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 81
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 120,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 82
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 121,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 83
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 122,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 84
		DEFAULT => -94
	},
	{#State 85
		DEFAULT => -13
	},
	{#State 86
		DEFAULT => -122
	},
	{#State 87
		ACTIONS => {
			";" => 123
		}
	},
	{#State 88
		ACTIONS => {
			";" => 86
		},
		DEFAULT => -121,
		GOTOS => {
			'optional_semicolon' => 124
		}
	},
	{#State 89
		DEFAULT => -21
	},
	{#State 90
		DEFAULT => -35
	},
	{#State 91
		ACTIONS => {
			'IDENTIFIER' => 26,
			"signed" => 100,
			'void' => 93,
			"unsigned" => 104
		},
		DEFAULT => -89,
		GOTOS => {
			'existingtype' => 99,
			'pipe' => 56,
			'bitmap' => 57,
			'usertype' => 95,
			'property_list' => 94,
			'identifier' => 96,
			'struct' => 62,
			'enum' => 65,
			'type' => 125,
			'union' => 67,
			'sign' => 97
		}
	},
	{#State 92
		ACTIONS => {
			'IDENTIFIER' => 126
		},
		DEFAULT => -117,
		GOTOS => {
			'optional_identifier' => 127
		}
	},
	{#State 93
		DEFAULT => -42
	},
	{#State 94
		ACTIONS => {
			"pipe" => 103,
			"union" => 92,
			"enum" => 101,
			"bitmap" => 102,
			"[" => 20,
			"struct" => 98
		}
	},
	{#State 95
		DEFAULT => -40
	},
	{#State 96
		DEFAULT => -39
	},
	{#State 97
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 128
		}
	},
	{#State 98
		ACTIONS => {
			'IDENTIFIER' => 126
		},
		DEFAULT => -117,
		GOTOS => {
			'optional_identifier' => 129
		}
	},
	{#State 99
		DEFAULT => -41
	},
	{#State 100
		DEFAULT => -36
	},
	{#State 101
		ACTIONS => {
			'IDENTIFIER' => 126
		},
		DEFAULT => -117,
		GOTOS => {
			'optional_identifier' => 130
		}
	},
	{#State 102
		ACTIONS => {
			'IDENTIFIER' => 126
		},
		DEFAULT => -117,
		GOTOS => {
			'optional_identifier' => 131
		}
	},
	{#State 103
		ACTIONS => {
			'IDENTIFIER' => 26,
			"signed" => 100,
			'void' => 93,
			"unsigned" => 104
		},
		DEFAULT => -89,
		GOTOS => {
			'existingtype' => 99,
			'pipe' => 56,
			'bitmap' => 57,
			'usertype' => 95,
			'property_list' => 94,
			'identifier' => 96,
			'struct' => 62,
			'enum' => 65,
			'type' => 132,
			'union' => 67,
			'sign' => 97
		}
	},
	{#State 104
		DEFAULT => -37
	},
	{#State 105
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 133
		}
	},
	{#State 106
		DEFAULT => -75,
		GOTOS => {
			'pointers' => 134
		}
	},
	{#State 107
		ACTIONS => {
			"-" => 69,
			":" => 68,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 80,
			"?" => 70,
			"{" => 74,
			"&" => 75,
			"/" => 76,
			"=" => 77,
			"(" => 78,
			"|" => 79,
			"." => 81,
			">" => 82
		},
		DEFAULT => -110
	},
	{#State 108
		ACTIONS => {
			":" => 68,
			"<" => 71,
			"~" => 72,
			"?" => 70,
			"{" => 74,
			"=" => 77
		},
		DEFAULT => -101
	},
	{#State 109
		ACTIONS => {
			"-" => 69,
			":" => 68,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 80,
			"?" => 70,
			"{" => 74,
			"&" => 75,
			"/" => 76,
			"=" => 77,
			"(" => 78,
			"|" => 79,
			"." => 81,
			">" => 82
		},
		DEFAULT => -109
	},
	{#State 110
		ACTIONS => {
			"-" => 69,
			":" => 68,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 80,
			"?" => 70,
			"{" => 74,
			"&" => 75,
			"/" => 76,
			"=" => 77,
			"(" => 78,
			"|" => 79,
			"." => 81,
			">" => 82
		},
		DEFAULT => -105
	},
	{#State 111
		ACTIONS => {
			"-" => 69,
			":" => 68,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 80,
			"?" => 70,
			"{" => 74,
			"&" => 75,
			"/" => 76,
			"=" => 77,
			"(" => 78,
			"|" => 79,
			"." => 81,
			">" => 82
		},
		DEFAULT => -113
	},
	{#State 112
		ACTIONS => {
			":" => 68,
			"<" => 71,
			"~" => 72,
			"?" => 70,
			"{" => 74,
			"=" => 77
		},
		DEFAULT => -112
	},
	{#State 113
		ACTIONS => {
			"}" => 135,
			"," => 83
		}
	},
	{#State 114
		ACTIONS => {
			":" => 68,
			"<" => 71,
			"~" => 72,
			"?" => 70,
			"{" => 74,
			"=" => 77
		},
		DEFAULT => -107
	},
	{#State 115
		ACTIONS => {
			":" => 68,
			"<" => 71,
			"~" => 72,
			"?" => 70,
			"{" => 74,
			"=" => 77
		},
		DEFAULT => -108
	},
	{#State 116
		ACTIONS => {
			"-" => 69,
			":" => 68,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 80,
			"?" => 70,
			"{" => 74,
			"&" => 75,
			"/" => 76,
			"=" => 77,
			"(" => 78,
			"|" => 79,
			"." => 81,
			">" => 82
		},
		DEFAULT => -111
	},
	{#State 117
		ACTIONS => {
			"," => 83,
			")" => 136
		}
	},
	{#State 118
		ACTIONS => {
			":" => 68,
			"<" => 71,
			"~" => 72,
			"?" => 70,
			"{" => 74,
			"=" => 77
		},
		DEFAULT => -106
	},
	{#State 119
		ACTIONS => {
			":" => 68,
			"<" => 71,
			"~" => 72,
			"?" => 70,
			"{" => 74,
			"=" => 77
		},
		DEFAULT => -103
	},
	{#State 120
		ACTIONS => {
			":" => 68,
			"<" => 71,
			"~" => 72,
			"?" => 70,
			"{" => 74,
			"=" => 77
		},
		DEFAULT => -102
	},
	{#State 121
		ACTIONS => {
			":" => 68,
			"<" => 71,
			"~" => 72,
			"?" => 70,
			"{" => 74,
			"=" => 77
		},
		DEFAULT => -104
	},
	{#State 122
		ACTIONS => {
			"-" => 69,
			":" => 68,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 80,
			"?" => 70,
			"{" => 74,
			"&" => 75,
			"/" => 76,
			"=" => 77,
			"(" => 78,
			"|" => 79,
			"." => 81,
			">" => 82
		},
		DEFAULT => -96
	},
	{#State 123
		DEFAULT => -15
	},
	{#State 124
		DEFAULT => -16
	},
	{#State 125
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 137
		}
	},
	{#State 126
		DEFAULT => -118
	},
	{#State 127
		ACTIONS => {
			"{" => 139
		},
		DEFAULT => -71,
		GOTOS => {
			'union_body' => 140,
			'opt_union_body' => 138
		}
	},
	{#State 128
		DEFAULT => -38
	},
	{#State 129
		ACTIONS => {
			"{" => 142
		},
		DEFAULT => -61,
		GOTOS => {
			'struct_body' => 141,
			'opt_struct_body' => 143
		}
	},
	{#State 130
		ACTIONS => {
			"{" => 144
		},
		DEFAULT => -44,
		GOTOS => {
			'opt_enum_body' => 146,
			'enum_body' => 145
		}
	},
	{#State 131
		ACTIONS => {
			"{" => 148
		},
		DEFAULT => -52,
		GOTOS => {
			'bitmap_body' => 149,
			'opt_bitmap_body' => 147
		}
	},
	{#State 132
		DEFAULT => -77
	},
	{#State 133
		ACTIONS => {
			"(" => 150
		}
	},
	{#State 134
		ACTIONS => {
			'IDENTIFIER' => 26,
			"*" => 152
		},
		GOTOS => {
			'identifier' => 151
		}
	},
	{#State 135
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 153,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 136
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 154,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 137
		ACTIONS => {
			"[" => 155
		},
		DEFAULT => -86,
		GOTOS => {
			'array_len' => 156
		}
	},
	{#State 138
		DEFAULT => -73
	},
	{#State 139
		DEFAULT => -68,
		GOTOS => {
			'union_elements' => 157
		}
	},
	{#State 140
		DEFAULT => -72
	},
	{#State 141
		DEFAULT => -62
	},
	{#State 142
		DEFAULT => -78,
		GOTOS => {
			'element_list1' => 158
		}
	},
	{#State 143
		DEFAULT => -63
	},
	{#State 144
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 159,
			'enum_element' => 160,
			'enum_elements' => 161
		}
	},
	{#State 145
		DEFAULT => -45
	},
	{#State 146
		DEFAULT => -46
	},
	{#State 147
		DEFAULT => -54
	},
	{#State 148
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		DEFAULT => -57,
		GOTOS => {
			'identifier' => 164,
			'bitmap_element' => 163,
			'bitmap_elements' => 162,
			'opt_bitmap_elements' => 165
		}
	},
	{#State 149
		DEFAULT => -53
	},
	{#State 150
		ACTIONS => {
			"," => -82,
			"void" => 169,
			"const" => 167,
			")" => -82
		},
		DEFAULT => -80,
		GOTOS => {
			'optional_const' => 166,
			'element_list2' => 168
		}
	},
	{#State 151
		ACTIONS => {
			"[" => 155,
			"=" => 171
		},
		GOTOS => {
			'array_len' => 170
		}
	},
	{#State 152
		DEFAULT => -76
	},
	{#State 153
		ACTIONS => {
			"-" => 69,
			":" => 68,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 80,
			"?" => 70,
			"{" => 74,
			"&" => 75,
			"/" => 76,
			"=" => 77,
			"(" => 78,
			"|" => 79,
			"." => 81,
			">" => 82
		},
		DEFAULT => -115
	},
	{#State 154
		ACTIONS => {
			":" => 68,
			"<" => 71,
			"~" => 72,
			"?" => 70,
			"{" => 74,
			"=" => 77
		},
		DEFAULT => -114
	},
	{#State 155
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			"]" => 172,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 173,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 156
		ACTIONS => {
			";" => 174
		}
	},
	{#State 157
		ACTIONS => {
			"}" => 175
		},
		DEFAULT => -89,
		GOTOS => {
			'optional_base_element' => 177,
			'property_list' => 176
		}
	},
	{#State 158
		ACTIONS => {
			"}" => 178
		},
		DEFAULT => -89,
		GOTOS => {
			'base_element' => 179,
			'property_list' => 180
		}
	},
	{#State 159
		ACTIONS => {
			"=" => 181
		},
		DEFAULT => -49
	},
	{#State 160
		DEFAULT => -47
	},
	{#State 161
		ACTIONS => {
			"}" => 182,
			"," => 183
		}
	},
	{#State 162
		ACTIONS => {
			"," => 184
		},
		DEFAULT => -58
	},
	{#State 163
		DEFAULT => -55
	},
	{#State 164
		ACTIONS => {
			"=" => 185
		}
	},
	{#State 165
		ACTIONS => {
			"}" => 186
		}
	},
	{#State 166
		DEFAULT => -89,
		GOTOS => {
			'base_element' => 187,
			'property_list' => 180
		}
	},
	{#State 167
		DEFAULT => -81
	},
	{#State 168
		ACTIONS => {
			"," => 188,
			")" => 189
		}
	},
	{#State 169
		DEFAULT => -83
	},
	{#State 170
		ACTIONS => {
			"=" => 190
		}
	},
	{#State 171
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 191,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 172
		ACTIONS => {
			"[" => 155
		},
		DEFAULT => -86,
		GOTOS => {
			'array_len' => 192
		}
	},
	{#State 173
		ACTIONS => {
			"-" => 69,
			":" => 68,
			"?" => 70,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"&" => 75,
			"{" => 74,
			"/" => 76,
			"=" => 77,
			"|" => 79,
			"(" => 78,
			"*" => 80,
			"." => 81,
			"]" => 193,
			">" => 82
		}
	},
	{#State 174
		DEFAULT => -29
	},
	{#State 175
		DEFAULT => -70
	},
	{#State 176
		ACTIONS => {
			"[" => 20
		},
		DEFAULT => -89,
		GOTOS => {
			'base_or_empty' => 194,
			'base_element' => 195,
			'empty_element' => 196,
			'property_list' => 197
		}
	},
	{#State 177
		DEFAULT => -69
	},
	{#State 178
		DEFAULT => -60
	},
	{#State 179
		ACTIONS => {
			";" => 198
		}
	},
	{#State 180
		ACTIONS => {
			'IDENTIFIER' => 26,
			"signed" => 100,
			'void' => 93,
			"unsigned" => 104,
			"[" => 20
		},
		DEFAULT => -89,
		GOTOS => {
			'existingtype' => 99,
			'pipe' => 56,
			'bitmap' => 57,
			'usertype' => 95,
			'property_list' => 94,
			'identifier' => 96,
			'struct' => 62,
			'enum' => 65,
			'type' => 199,
			'union' => 67,
			'sign' => 97
		}
	},
	{#State 181
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 200,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 182
		DEFAULT => -43
	},
	{#State 183
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 159,
			'enum_element' => 201
		}
	},
	{#State 184
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 164,
			'bitmap_element' => 202
		}
	},
	{#State 185
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 203,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 186
		DEFAULT => -51
	},
	{#State 187
		DEFAULT => -84
	},
	{#State 188
		ACTIONS => {
			"const" => 167
		},
		DEFAULT => -80,
		GOTOS => {
			'optional_const' => 204
		}
	},
	{#State 189
		ACTIONS => {
			";" => 205
		}
	},
	{#State 190
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -97,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 206,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 191
		ACTIONS => {
			"-" => 69,
			":" => 68,
			"?" => 70,
			"<" => 71,
			";" => 207,
			"+" => 73,
			"~" => 72,
			"&" => 75,
			"{" => 74,
			"/" => 76,
			"=" => 77,
			"|" => 79,
			"(" => 78,
			"*" => 80,
			"." => 81,
			">" => 82
		}
	},
	{#State 192
		DEFAULT => -87
	},
	{#State 193
		ACTIONS => {
			"[" => 155
		},
		DEFAULT => -86,
		GOTOS => {
			'array_len' => 208
		}
	},
	{#State 194
		DEFAULT => -67
	},
	{#State 195
		ACTIONS => {
			";" => 209
		}
	},
	{#State 196
		DEFAULT => -66
	},
	{#State 197
		ACTIONS => {
			'IDENTIFIER' => 26,
			"signed" => 100,
			";" => 210,
			'void' => 93,
			"unsigned" => 104,
			"[" => 20
		},
		DEFAULT => -89,
		GOTOS => {
			'existingtype' => 99,
			'pipe' => 56,
			'bitmap' => 57,
			'usertype' => 95,
			'property_list' => 94,
			'identifier' => 96,
			'struct' => 62,
			'enum' => 65,
			'type' => 199,
			'union' => 67,
			'sign' => 97
		}
	},
	{#State 198
		DEFAULT => -79
	},
	{#State 199
		DEFAULT => -75,
		GOTOS => {
			'pointers' => 211
		}
	},
	{#State 200
		ACTIONS => {
			"-" => 69,
			":" => 68,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 80,
			"?" => 70,
			"{" => 74,
			"&" => 75,
			"/" => 76,
			"=" => 77,
			"(" => 78,
			"|" => 79,
			"." => 81,
			">" => 82
		},
		DEFAULT => -50
	},
	{#State 201
		DEFAULT => -48
	},
	{#State 202
		DEFAULT => -56
	},
	{#State 203
		ACTIONS => {
			"-" => 69,
			":" => 68,
			"<" => 71,
			"+" => 73,
			"~" => 72,
			"*" => 80,
			"?" => 70,
			"{" => 74,
			"&" => 75,
			"/" => 76,
			"=" => 77,
			"(" => 78,
			"|" => 79,
			"." => 81,
			">" => 82
		},
		DEFAULT => -59
	},
	{#State 204
		DEFAULT => -89,
		GOTOS => {
			'base_element' => 212,
			'property_list' => 180
		}
	},
	{#State 205
		DEFAULT => -28
	},
	{#State 206
		ACTIONS => {
			"-" => 69,
			":" => 68,
			"?" => 70,
			"<" => 71,
			";" => 213,
			"+" => 73,
			"~" => 72,
			"&" => 75,
			"{" => 74,
			"/" => 76,
			"=" => 77,
			"|" => 79,
			"(" => 78,
			"*" => 80,
			"." => 81,
			">" => 82
		}
	},
	{#State 207
		DEFAULT => -26
	},
	{#State 208
		DEFAULT => -88
	},
	{#State 209
		DEFAULT => -65
	},
	{#State 210
		DEFAULT => -64
	},
	{#State 211
		ACTIONS => {
			'IDENTIFIER' => 26,
			"*" => 152
		},
		GOTOS => {
			'identifier' => 214
		}
	},
	{#State 212
		DEFAULT => -85
	},
	{#State 213
		DEFAULT => -27
	},
	{#State 214
		ACTIONS => {
			"[" => 155
		},
		DEFAULT => -86,
		GOTOS => {
			'array_len' => 215
		}
	},
	{#State 215
		DEFAULT => -74
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
#line 20 "./../pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 3
		 'idl', 2,
sub
#line 22 "./../pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 4
		 'idl', 2,
sub
#line 24 "./../pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 5
		 'idl', 2,
sub
#line 26 "./../pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 6
		 'idl', 2,
sub
#line 28 "./../pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 7
		 'idl', 2,
sub
#line 30 "./../pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 8
		 'import', 3,
sub
#line 35 "./../pidl/idl.yp"
{{
		"TYPE" => "IMPORT",
		"PATHS" => $_[2],
		"FILE" => $_[0]->YYData->{FILE},
		"LINE" => $_[0]->YYData->{LINE},
	}}
	],
	[#Rule 9
		 'include', 3,
sub
#line 45 "./../pidl/idl.yp"
{{
		"TYPE" => "INCLUDE",
		"PATHS" => $_[2],
		"FILE" => $_[0]->YYData->{FILE},
		"LINE" => $_[0]->YYData->{LINE},
	}}
	],
	[#Rule 10
		 'importlib', 3,
sub
#line 55 "./../pidl/idl.yp"
{{
		"TYPE" => "IMPORTLIB",
		"PATHS" => $_[2],
		"FILE" => $_[0]->YYData->{FILE},
		"LINE" => $_[0]->YYData->{LINE},
	}}
	],
	[#Rule 11
		 'commalist', 1,
sub
#line 64 "./../pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 12
		 'commalist', 3,
sub
#line 66 "./../pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 13
		 'coclass', 7,
sub
#line 71 "./../pidl/idl.yp"
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
#line 84 "./../pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 16
		 'interface', 8,
sub
#line 89 "./../pidl/idl.yp"
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
	[#Rule 17
		 'base_interface', 0, undef
	],
	[#Rule 18
		 'base_interface', 2,
sub
#line 103 "./../pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 19
		 'cpp_quote', 4,
sub
#line 109 "./../pidl/idl.yp"
{{
		 "TYPE" => "CPP_QUOTE",
		 "DATA" => $_[3],
		 "FILE" => $_[0]->YYData->{FILE},
		 "LINE" => $_[0]->YYData->{LINE},
	}}
	],
	[#Rule 20
		 'definitions', 1,
sub
#line 118 "./../pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 21
		 'definitions', 2,
sub
#line 120 "./../pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
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
		 'definition', 1, undef
	],
	[#Rule 26
		 'const', 7,
sub
#line 135 "./../pidl/idl.yp"
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
	[#Rule 27
		 'const', 8,
sub
#line 146 "./../pidl/idl.yp"
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
	[#Rule 28
		 'function', 7,
sub
#line 160 "./../pidl/idl.yp"
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
	[#Rule 29
		 'typedef', 6,
sub
#line 173 "./../pidl/idl.yp"
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
	[#Rule 30
		 'usertype', 1, undef
	],
	[#Rule 31
		 'usertype', 1, undef
	],
	[#Rule 32
		 'usertype', 1, undef
	],
	[#Rule 33
		 'usertype', 1, undef
	],
	[#Rule 34
		 'usertype', 1, undef
	],
	[#Rule 35
		 'typedecl', 2,
sub
#line 197 "./../pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 36
		 'sign', 1, undef
	],
	[#Rule 37
		 'sign', 1, undef
	],
	[#Rule 38
		 'existingtype', 2,
sub
#line 207 "./../pidl/idl.yp"
{ ($_[1]?$_[1]:"signed") ." $_[2]" }
	],
	[#Rule 39
		 'existingtype', 1, undef
	],
	[#Rule 40
		 'type', 1, undef
	],
	[#Rule 41
		 'type', 1, undef
	],
	[#Rule 42
		 'type', 1,
sub
#line 217 "./../pidl/idl.yp"
{ "void" }
	],
	[#Rule 43
		 'enum_body', 3,
sub
#line 221 "./../pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 44
		 'opt_enum_body', 0, undef
	],
	[#Rule 45
		 'opt_enum_body', 1, undef
	],
	[#Rule 46
		 'enum', 4,
sub
#line 232 "./../pidl/idl.yp"
{{
		"TYPE" => "ENUM",
		"PROPERTIES" => $_[1],
		"NAME" => $_[3],
		"ELEMENTS" => $_[4],
		"FILE" => $_[0]->YYData->{FILE},
		"LINE" => $_[0]->YYData->{LINE},
	}}
	],
	[#Rule 47
		 'enum_elements', 1,
sub
#line 243 "./../pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 48
		 'enum_elements', 3,
sub
#line 245 "./../pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 49
		 'enum_element', 1, undef
	],
	[#Rule 50
		 'enum_element', 3,
sub
#line 251 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 51
		 'bitmap_body', 3,
sub
#line 255 "./../pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 52
		 'opt_bitmap_body', 0, undef
	],
	[#Rule 53
		 'opt_bitmap_body', 1, undef
	],
	[#Rule 54
		 'bitmap', 4,
sub
#line 266 "./../pidl/idl.yp"
{{
		"TYPE" => "BITMAP",
		"PROPERTIES" => $_[1],
		"NAME" => $_[3],
		"ELEMENTS" => $_[4],
		"FILE" => $_[0]->YYData->{FILE},
		"LINE" => $_[0]->YYData->{LINE},
	}}
	],
	[#Rule 55
		 'bitmap_elements', 1,
sub
#line 277 "./../pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 56
		 'bitmap_elements', 3,
sub
#line 279 "./../pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 57
		 'opt_bitmap_elements', 0, undef
	],
	[#Rule 58
		 'opt_bitmap_elements', 1, undef
	],
	[#Rule 59
		 'bitmap_element', 3,
sub
#line 289 "./../pidl/idl.yp"
{ "$_[1] ( $_[3] )" }
	],
	[#Rule 60
		 'struct_body', 3,
sub
#line 293 "./../pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 61
		 'opt_struct_body', 0, undef
	],
	[#Rule 62
		 'opt_struct_body', 1, undef
	],
	[#Rule 63
		 'struct', 4,
sub
#line 304 "./../pidl/idl.yp"
{{
		"TYPE" => "STRUCT",
		"PROPERTIES" => $_[1],
		"NAME" => $_[3],
		"ELEMENTS" => $_[4],
		"FILE" => $_[0]->YYData->{FILE},
		"LINE" => $_[0]->YYData->{LINE},
	}}
	],
	[#Rule 64
		 'empty_element', 2,
sub
#line 316 "./../pidl/idl.yp"
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
	[#Rule 65
		 'base_or_empty', 2, undef
	],
	[#Rule 66
		 'base_or_empty', 1, undef
	],
	[#Rule 67
		 'optional_base_element', 2,
sub
#line 333 "./../pidl/idl.yp"
{ $_[2]->{PROPERTIES} = FlattenHash([$_[1],$_[2]->{PROPERTIES}]); $_[2] }
	],
	[#Rule 68
		 'union_elements', 0, undef
	],
	[#Rule 69
		 'union_elements', 2,
sub
#line 339 "./../pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 70
		 'union_body', 3,
sub
#line 343 "./../pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 71
		 'opt_union_body', 0, undef
	],
	[#Rule 72
		 'opt_union_body', 1, undef
	],
	[#Rule 73
		 'union', 4,
sub
#line 354 "./../pidl/idl.yp"
{{
		"TYPE" => "UNION",
		"PROPERTIES" => $_[1],
		"NAME" => $_[3],
		"ELEMENTS" => $_[4],
		"FILE" => $_[0]->YYData->{FILE},
		"LINE" => $_[0]->YYData->{LINE},
	}}
	],
	[#Rule 74
		 'base_element', 5,
sub
#line 366 "./../pidl/idl.yp"
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
	[#Rule 75
		 'pointers', 0,
sub
#line 379 "./../pidl/idl.yp"
{ 0 }
	],
	[#Rule 76
		 'pointers', 2,
sub
#line 381 "./../pidl/idl.yp"
{ $_[1]+1 }
	],
	[#Rule 77
		 'pipe', 3,
sub
#line 386 "./../pidl/idl.yp"
{{
		"TYPE" => "PIPE",
		"PROPERTIES" => $_[1],
		"NAME" => $_[4],
		"DATA" => $_[3],
		"FILE" => $_[0]->YYData->{FILE},
		"LINE" => $_[0]->YYData->{LINE},
	}}
	],
	[#Rule 78
		 'element_list1', 0,
sub
#line 398 "./../pidl/idl.yp"
{ [] }
	],
	[#Rule 79
		 'element_list1', 3,
sub
#line 400 "./../pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 80
		 'optional_const', 0, undef
	],
	[#Rule 81
		 'optional_const', 1, undef
	],
	[#Rule 82
		 'element_list2', 0, undef
	],
	[#Rule 83
		 'element_list2', 1, undef
	],
	[#Rule 84
		 'element_list2', 2,
sub
#line 414 "./../pidl/idl.yp"
{ [ $_[2] ] }
	],
	[#Rule 85
		 'element_list2', 4,
sub
#line 416 "./../pidl/idl.yp"
{ push(@{$_[1]}, $_[4]); $_[1] }
	],
	[#Rule 86
		 'array_len', 0, undef
	],
	[#Rule 87
		 'array_len', 3,
sub
#line 422 "./../pidl/idl.yp"
{ push(@{$_[3]}, "*"); $_[3] }
	],
	[#Rule 88
		 'array_len', 4,
sub
#line 424 "./../pidl/idl.yp"
{ push(@{$_[4]}, "$_[2]"); $_[4] }
	],
	[#Rule 89
		 'property_list', 0, undef
	],
	[#Rule 90
		 'property_list', 4,
sub
#line 430 "./../pidl/idl.yp"
{ FlattenHash([$_[1],$_[3]]); }
	],
	[#Rule 91
		 'properties', 1,
sub
#line 434 "./../pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 92
		 'properties', 3,
sub
#line 436 "./../pidl/idl.yp"
{ FlattenHash([$_[1], $_[3]]); }
	],
	[#Rule 93
		 'property', 1,
sub
#line 440 "./../pidl/idl.yp"
{{ "$_[1]" => "1"     }}
	],
	[#Rule 94
		 'property', 4,
sub
#line 442 "./../pidl/idl.yp"
{{ "$_[1]" => "$_[3]" }}
	],
	[#Rule 95
		 'commalisttext', 1, undef
	],
	[#Rule 96
		 'commalisttext', 3,
sub
#line 448 "./../pidl/idl.yp"
{ "$_[1],$_[3]" }
	],
	[#Rule 97
		 'anytext', 0,
sub
#line 453 "./../pidl/idl.yp"
{ "" }
	],
	[#Rule 98
		 'anytext', 1, undef
	],
	[#Rule 99
		 'anytext', 1, undef
	],
	[#Rule 100
		 'anytext', 1, undef
	],
	[#Rule 101
		 'anytext', 3,
sub
#line 461 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 102
		 'anytext', 3,
sub
#line 463 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 103
		 'anytext', 3,
sub
#line 465 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 104
		 'anytext', 3,
sub
#line 467 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 105
		 'anytext', 3,
sub
#line 469 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 106
		 'anytext', 3,
sub
#line 471 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 107
		 'anytext', 3,
sub
#line 473 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 108
		 'anytext', 3,
sub
#line 475 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 109
		 'anytext', 3,
sub
#line 477 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 110
		 'anytext', 3,
sub
#line 479 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 111
		 'anytext', 3,
sub
#line 481 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 112
		 'anytext', 3,
sub
#line 483 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 113
		 'anytext', 3,
sub
#line 485 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 114
		 'anytext', 5,
sub
#line 487 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 115
		 'anytext', 5,
sub
#line 489 "./../pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 116
		 'identifier', 1, undef
	],
	[#Rule 117
		 'optional_identifier', 0, undef
	],
	[#Rule 118
		 'optional_identifier', 1, undef
	],
	[#Rule 119
		 'constant', 1, undef
	],
	[#Rule 120
		 'text', 1,
sub
#line 507 "./../pidl/idl.yp"
{ "\"$_[1]\"" }
	],
	[#Rule 121
		 'optional_semicolon', 0, undef
	],
	[#Rule 122
		 'optional_semicolon', 1, undef
	]
],
                                  @_);
    bless($self,$class);
}

#line 519 "./../pidl/idl.yp"


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
			if (!defined $v->{$x}) {
				delete($v->{$x});
				next;
			}
		}
	}

	return $v;
}

sub _Error {
	if (exists $_[0]->YYData->{ERRMSG}) {
		error($_[0]->YYData, $_[0]->YYData->{ERRMSG});
		delete $_[0]->YYData->{ERRMSG};
		return;
	}

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
			    /^(coclass|interface|import|importlib
			      |include|cpp_quote|typedef
			      |union|struct|enum|bitmap|pipe
			      |void|const|unsigned|signed)$/x) {
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
