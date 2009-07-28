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
		DEFAULT => -85,
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
		DEFAULT => -116
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
		DEFAULT => -112
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
		DEFAULT => -89
	},
	{#State 31
		DEFAULT => -87
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
		DEFAULT => -86
	},
	{#State 41
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -93,
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
			"const" => 63
		},
		DEFAULT => -85,
		GOTOS => {
			'typedecl' => 54,
			'function' => 55,
			'definitions' => 57,
			'bitmap' => 56,
			'definition' => 60,
			'property_list' => 59,
			'usertype' => 58,
			'const' => 62,
			'struct' => 61,
			'typedef' => 65,
			'enum' => 64,
			'union' => 66
		}
	},
	{#State 45
		DEFAULT => -88
	},
	{#State 46
		ACTIONS => {
			"-" => 68,
			":" => 67,
			"<" => 70,
			"+" => 72,
			"~" => 71,
			"*" => 79,
			"?" => 69,
			"{" => 73,
			"&" => 74,
			"/" => 75,
			"=" => 76,
			"(" => 77,
			"|" => 78,
			"." => 80,
			">" => 81
		},
		DEFAULT => -91
	},
	{#State 47
		DEFAULT => -95
	},
	{#State 48
		DEFAULT => -115
	},
	{#State 49
		ACTIONS => {
			"," => 82,
			")" => 83
		}
	},
	{#State 50
		DEFAULT => -94
	},
	{#State 51
		DEFAULT => -96
	},
	{#State 52
		ACTIONS => {
			";" => 85
		},
		DEFAULT => -117,
		GOTOS => {
			'optional_semicolon' => 84
		}
	},
	{#State 53
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 86
		}
	},
	{#State 54
		DEFAULT => -25
	},
	{#State 55
		DEFAULT => -22
	},
	{#State 56
		DEFAULT => -33
	},
	{#State 57
		ACTIONS => {
			"}" => 87,
			"const" => 63
		},
		DEFAULT => -85,
		GOTOS => {
			'typedecl' => 54,
			'function' => 55,
			'bitmap' => 56,
			'definition' => 88,
			'property_list' => 59,
			'usertype' => 58,
			'struct' => 61,
			'const' => 62,
			'typedef' => 65,
			'enum' => 64,
			'union' => 66
		}
	},
	{#State 58
		ACTIONS => {
			";" => 89
		}
	},
	{#State 59
		ACTIONS => {
			"typedef" => 90,
			'IDENTIFIER' => 26,
			"signed" => 98,
			"union" => 91,
			"enum" => 100,
			"bitmap" => 101,
			'void' => 92,
			"unsigned" => 102,
			"[" => 20,
			"struct" => 97
		},
		GOTOS => {
			'existingtype' => 99,
			'bitmap' => 56,
			'usertype' => 94,
			'property_list' => 93,
			'identifier' => 95,
			'struct' => 61,
			'enum' => 64,
			'type' => 103,
			'union' => 66,
			'sign' => 96
		}
	},
	{#State 60
		DEFAULT => -20
	},
	{#State 61
		DEFAULT => -30
	},
	{#State 62
		DEFAULT => -23
	},
	{#State 63
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 104
		}
	},
	{#State 64
		DEFAULT => -32
	},
	{#State 65
		DEFAULT => -24
	},
	{#State 66
		DEFAULT => -31
	},
	{#State 67
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 105,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 68
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 106,
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
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 107,
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
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 108,
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
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 109,
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
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 110,
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
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 46,
			'text' => 51,
			'constant' => 47,
			'commalisttext' => 111
		}
	},
	{#State 74
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 112,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 75
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 113,
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
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 114,
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
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 46,
			'text' => 51,
			'constant' => 47,
			'commalisttext' => 115
		}
	},
	{#State 78
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 116,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 79
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 117,
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
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 118,
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
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 119,
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
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 120,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 83
		DEFAULT => -90
	},
	{#State 84
		DEFAULT => -13
	},
	{#State 85
		DEFAULT => -118
	},
	{#State 86
		ACTIONS => {
			";" => 121
		}
	},
	{#State 87
		ACTIONS => {
			";" => 85
		},
		DEFAULT => -117,
		GOTOS => {
			'optional_semicolon' => 122
		}
	},
	{#State 88
		DEFAULT => -21
	},
	{#State 89
		DEFAULT => -34
	},
	{#State 90
		ACTIONS => {
			'IDENTIFIER' => 26,
			"signed" => 98,
			'void' => 92,
			"unsigned" => 102
		},
		DEFAULT => -85,
		GOTOS => {
			'existingtype' => 99,
			'bitmap' => 56,
			'usertype' => 94,
			'property_list' => 93,
			'identifier' => 95,
			'struct' => 61,
			'enum' => 64,
			'type' => 123,
			'union' => 66,
			'sign' => 96
		}
	},
	{#State 91
		ACTIONS => {
			'IDENTIFIER' => 124
		},
		DEFAULT => -114,
		GOTOS => {
			'optional_identifier' => 125
		}
	},
	{#State 92
		DEFAULT => -41
	},
	{#State 93
		ACTIONS => {
			"union" => 91,
			"enum" => 100,
			"bitmap" => 101,
			"[" => 20,
			"struct" => 97
		}
	},
	{#State 94
		DEFAULT => -39
	},
	{#State 95
		DEFAULT => -38
	},
	{#State 96
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 126
		}
	},
	{#State 97
		ACTIONS => {
			'IDENTIFIER' => 124
		},
		DEFAULT => -114,
		GOTOS => {
			'optional_identifier' => 127
		}
	},
	{#State 98
		DEFAULT => -35
	},
	{#State 99
		DEFAULT => -40
	},
	{#State 100
		ACTIONS => {
			'IDENTIFIER' => 124
		},
		DEFAULT => -114,
		GOTOS => {
			'optional_identifier' => 128
		}
	},
	{#State 101
		ACTIONS => {
			'IDENTIFIER' => 124
		},
		DEFAULT => -114,
		GOTOS => {
			'optional_identifier' => 129
		}
	},
	{#State 102
		DEFAULT => -36
	},
	{#State 103
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 130
		}
	},
	{#State 104
		DEFAULT => -74,
		GOTOS => {
			'pointers' => 131
		}
	},
	{#State 105
		ACTIONS => {
			"-" => 68,
			":" => 67,
			"<" => 70,
			"+" => 72,
			"~" => 71,
			"*" => 79,
			"?" => 69,
			"{" => 73,
			"&" => 74,
			"/" => 75,
			"=" => 76,
			"(" => 77,
			"|" => 78,
			"." => 80,
			">" => 81
		},
		DEFAULT => -106
	},
	{#State 106
		ACTIONS => {
			":" => 67,
			"<" => 70,
			"~" => 71,
			"?" => 69,
			"{" => 73,
			"=" => 76
		},
		DEFAULT => -97
	},
	{#State 107
		ACTIONS => {
			"-" => 68,
			":" => 67,
			"<" => 70,
			"+" => 72,
			"~" => 71,
			"*" => 79,
			"?" => 69,
			"{" => 73,
			"&" => 74,
			"/" => 75,
			"=" => 76,
			"(" => 77,
			"|" => 78,
			"." => 80,
			">" => 81
		},
		DEFAULT => -105
	},
	{#State 108
		ACTIONS => {
			"-" => 68,
			":" => 67,
			"<" => 70,
			"+" => 72,
			"~" => 71,
			"*" => 79,
			"?" => 69,
			"{" => 73,
			"&" => 74,
			"/" => 75,
			"=" => 76,
			"(" => 77,
			"|" => 78,
			"." => 80,
			">" => 81
		},
		DEFAULT => -101
	},
	{#State 109
		ACTIONS => {
			"-" => 68,
			":" => 67,
			"<" => 70,
			"+" => 72,
			"~" => 71,
			"*" => 79,
			"?" => 69,
			"{" => 73,
			"&" => 74,
			"/" => 75,
			"=" => 76,
			"(" => 77,
			"|" => 78,
			"." => 80,
			">" => 81
		},
		DEFAULT => -109
	},
	{#State 110
		ACTIONS => {
			":" => 67,
			"<" => 70,
			"~" => 71,
			"?" => 69,
			"{" => 73,
			"=" => 76
		},
		DEFAULT => -108
	},
	{#State 111
		ACTIONS => {
			"}" => 132,
			"," => 82
		}
	},
	{#State 112
		ACTIONS => {
			":" => 67,
			"<" => 70,
			"~" => 71,
			"?" => 69,
			"{" => 73,
			"=" => 76
		},
		DEFAULT => -103
	},
	{#State 113
		ACTIONS => {
			":" => 67,
			"<" => 70,
			"~" => 71,
			"?" => 69,
			"{" => 73,
			"=" => 76
		},
		DEFAULT => -104
	},
	{#State 114
		ACTIONS => {
			"-" => 68,
			":" => 67,
			"<" => 70,
			"+" => 72,
			"~" => 71,
			"*" => 79,
			"?" => 69,
			"{" => 73,
			"&" => 74,
			"/" => 75,
			"=" => 76,
			"(" => 77,
			"|" => 78,
			"." => 80,
			">" => 81
		},
		DEFAULT => -107
	},
	{#State 115
		ACTIONS => {
			"," => 82,
			")" => 133
		}
	},
	{#State 116
		ACTIONS => {
			":" => 67,
			"<" => 70,
			"~" => 71,
			"?" => 69,
			"{" => 73,
			"=" => 76
		},
		DEFAULT => -102
	},
	{#State 117
		ACTIONS => {
			":" => 67,
			"<" => 70,
			"~" => 71,
			"?" => 69,
			"{" => 73,
			"=" => 76
		},
		DEFAULT => -99
	},
	{#State 118
		ACTIONS => {
			":" => 67,
			"<" => 70,
			"~" => 71,
			"?" => 69,
			"{" => 73,
			"=" => 76
		},
		DEFAULT => -98
	},
	{#State 119
		ACTIONS => {
			":" => 67,
			"<" => 70,
			"~" => 71,
			"?" => 69,
			"{" => 73,
			"=" => 76
		},
		DEFAULT => -100
	},
	{#State 120
		ACTIONS => {
			"-" => 68,
			":" => 67,
			"<" => 70,
			"+" => 72,
			"~" => 71,
			"*" => 79,
			"?" => 69,
			"{" => 73,
			"&" => 74,
			"/" => 75,
			"=" => 76,
			"(" => 77,
			"|" => 78,
			"." => 80,
			">" => 81
		},
		DEFAULT => -92
	},
	{#State 121
		DEFAULT => -15
	},
	{#State 122
		DEFAULT => -16
	},
	{#State 123
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 134
		}
	},
	{#State 124
		DEFAULT => -113
	},
	{#State 125
		ACTIONS => {
			"{" => 136
		},
		DEFAULT => -70,
		GOTOS => {
			'union_body' => 137,
			'opt_union_body' => 135
		}
	},
	{#State 126
		DEFAULT => -37
	},
	{#State 127
		ACTIONS => {
			"{" => 139
		},
		DEFAULT => -60,
		GOTOS => {
			'struct_body' => 138,
			'opt_struct_body' => 140
		}
	},
	{#State 128
		ACTIONS => {
			"{" => 141
		},
		DEFAULT => -43,
		GOTOS => {
			'opt_enum_body' => 143,
			'enum_body' => 142
		}
	},
	{#State 129
		ACTIONS => {
			"{" => 145
		},
		DEFAULT => -51,
		GOTOS => {
			'bitmap_body' => 146,
			'opt_bitmap_body' => 144
		}
	},
	{#State 130
		ACTIONS => {
			"(" => 147
		}
	},
	{#State 131
		ACTIONS => {
			'IDENTIFIER' => 26,
			"*" => 149
		},
		GOTOS => {
			'identifier' => 148
		}
	},
	{#State 132
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 150,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 133
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 151,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 134
		ACTIONS => {
			"[" => 152
		},
		DEFAULT => -82,
		GOTOS => {
			'array_len' => 153
		}
	},
	{#State 135
		DEFAULT => -72
	},
	{#State 136
		DEFAULT => -67,
		GOTOS => {
			'union_elements' => 154
		}
	},
	{#State 137
		DEFAULT => -71
	},
	{#State 138
		DEFAULT => -61
	},
	{#State 139
		DEFAULT => -76,
		GOTOS => {
			'element_list1' => 155
		}
	},
	{#State 140
		DEFAULT => -62
	},
	{#State 141
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 156,
			'enum_element' => 157,
			'enum_elements' => 158
		}
	},
	{#State 142
		DEFAULT => -44
	},
	{#State 143
		DEFAULT => -45
	},
	{#State 144
		DEFAULT => -53
	},
	{#State 145
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		DEFAULT => -56,
		GOTOS => {
			'identifier' => 161,
			'bitmap_element' => 160,
			'bitmap_elements' => 159,
			'opt_bitmap_elements' => 162
		}
	},
	{#State 146
		DEFAULT => -52
	},
	{#State 147
		ACTIONS => {
			"," => -78,
			"void" => 166,
			")" => -78
		},
		DEFAULT => -85,
		GOTOS => {
			'base_element' => 163,
			'element_list2' => 165,
			'property_list' => 164
		}
	},
	{#State 148
		ACTIONS => {
			"[" => 152,
			"=" => 168
		},
		GOTOS => {
			'array_len' => 167
		}
	},
	{#State 149
		DEFAULT => -75
	},
	{#State 150
		ACTIONS => {
			"-" => 68,
			":" => 67,
			"<" => 70,
			"+" => 72,
			"~" => 71,
			"*" => 79,
			"?" => 69,
			"{" => 73,
			"&" => 74,
			"/" => 75,
			"=" => 76,
			"(" => 77,
			"|" => 78,
			"." => 80,
			">" => 81
		},
		DEFAULT => -111
	},
	{#State 151
		ACTIONS => {
			":" => 67,
			"<" => 70,
			"~" => 71,
			"?" => 69,
			"{" => 73,
			"=" => 76
		},
		DEFAULT => -110
	},
	{#State 152
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			"]" => 169,
			'IDENTIFIER' => 26
		},
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 170,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 153
		ACTIONS => {
			";" => 171
		}
	},
	{#State 154
		ACTIONS => {
			"}" => 172
		},
		DEFAULT => -85,
		GOTOS => {
			'optional_base_element' => 174,
			'property_list' => 173
		}
	},
	{#State 155
		ACTIONS => {
			"}" => 175
		},
		DEFAULT => -85,
		GOTOS => {
			'base_element' => 176,
			'property_list' => 164
		}
	},
	{#State 156
		ACTIONS => {
			"=" => 177
		},
		DEFAULT => -48
	},
	{#State 157
		DEFAULT => -46
	},
	{#State 158
		ACTIONS => {
			"}" => 178,
			"," => 179
		}
	},
	{#State 159
		ACTIONS => {
			"," => 180
		},
		DEFAULT => -57
	},
	{#State 160
		DEFAULT => -54
	},
	{#State 161
		ACTIONS => {
			"=" => 181
		}
	},
	{#State 162
		ACTIONS => {
			"}" => 182
		}
	},
	{#State 163
		DEFAULT => -80
	},
	{#State 164
		ACTIONS => {
			'IDENTIFIER' => 26,
			"signed" => 98,
			'void' => 92,
			"unsigned" => 102,
			"[" => 20
		},
		DEFAULT => -85,
		GOTOS => {
			'existingtype' => 99,
			'bitmap' => 56,
			'usertype' => 94,
			'property_list' => 93,
			'identifier' => 95,
			'struct' => 61,
			'enum' => 64,
			'type' => 183,
			'union' => 66,
			'sign' => 96
		}
	},
	{#State 165
		ACTIONS => {
			"," => 184,
			")" => 185
		}
	},
	{#State 166
		DEFAULT => -79
	},
	{#State 167
		ACTIONS => {
			"=" => 186
		}
	},
	{#State 168
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 187,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 169
		ACTIONS => {
			"[" => 152
		},
		DEFAULT => -82,
		GOTOS => {
			'array_len' => 188
		}
	},
	{#State 170
		ACTIONS => {
			"-" => 68,
			":" => 67,
			"?" => 69,
			"<" => 70,
			"+" => 72,
			"~" => 71,
			"&" => 74,
			"{" => 73,
			"/" => 75,
			"=" => 76,
			"|" => 78,
			"(" => 77,
			"*" => 79,
			"." => 80,
			"]" => 189,
			">" => 81
		}
	},
	{#State 171
		DEFAULT => -29
	},
	{#State 172
		DEFAULT => -69
	},
	{#State 173
		ACTIONS => {
			"[" => 20
		},
		DEFAULT => -85,
		GOTOS => {
			'base_or_empty' => 190,
			'base_element' => 191,
			'empty_element' => 192,
			'property_list' => 193
		}
	},
	{#State 174
		DEFAULT => -68
	},
	{#State 175
		DEFAULT => -59
	},
	{#State 176
		ACTIONS => {
			";" => 194
		}
	},
	{#State 177
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 195,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 178
		DEFAULT => -42
	},
	{#State 179
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 156,
			'enum_element' => 196
		}
	},
	{#State 180
		ACTIONS => {
			'IDENTIFIER' => 26
		},
		GOTOS => {
			'identifier' => 161,
			'bitmap_element' => 197
		}
	},
	{#State 181
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 198,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 182
		DEFAULT => -50
	},
	{#State 183
		DEFAULT => -74,
		GOTOS => {
			'pointers' => 199
		}
	},
	{#State 184
		DEFAULT => -85,
		GOTOS => {
			'base_element' => 200,
			'property_list' => 164
		}
	},
	{#State 185
		ACTIONS => {
			";" => 201
		}
	},
	{#State 186
		ACTIONS => {
			'CONSTANT' => 48,
			'TEXT' => 16,
			'IDENTIFIER' => 26
		},
		DEFAULT => -93,
		GOTOS => {
			'identifier' => 50,
			'anytext' => 202,
			'text' => 51,
			'constant' => 47
		}
	},
	{#State 187
		ACTIONS => {
			"-" => 68,
			":" => 67,
			"?" => 69,
			"<" => 70,
			";" => 203,
			"+" => 72,
			"~" => 71,
			"&" => 74,
			"{" => 73,
			"/" => 75,
			"=" => 76,
			"|" => 78,
			"(" => 77,
			"*" => 79,
			"." => 80,
			">" => 81
		}
	},
	{#State 188
		DEFAULT => -83
	},
	{#State 189
		ACTIONS => {
			"[" => 152
		},
		DEFAULT => -82,
		GOTOS => {
			'array_len' => 204
		}
	},
	{#State 190
		DEFAULT => -66
	},
	{#State 191
		ACTIONS => {
			";" => 205
		}
	},
	{#State 192
		DEFAULT => -65
	},
	{#State 193
		ACTIONS => {
			'IDENTIFIER' => 26,
			"signed" => 98,
			";" => 206,
			'void' => 92,
			"unsigned" => 102,
			"[" => 20
		},
		DEFAULT => -85,
		GOTOS => {
			'existingtype' => 99,
			'bitmap' => 56,
			'usertype' => 94,
			'property_list' => 93,
			'identifier' => 95,
			'struct' => 61,
			'enum' => 64,
			'type' => 183,
			'union' => 66,
			'sign' => 96
		}
	},
	{#State 194
		DEFAULT => -77
	},
	{#State 195
		ACTIONS => {
			"-" => 68,
			":" => 67,
			"<" => 70,
			"+" => 72,
			"~" => 71,
			"*" => 79,
			"?" => 69,
			"{" => 73,
			"&" => 74,
			"/" => 75,
			"=" => 76,
			"(" => 77,
			"|" => 78,
			"." => 80,
			">" => 81
		},
		DEFAULT => -49
	},
	{#State 196
		DEFAULT => -47
	},
	{#State 197
		DEFAULT => -55
	},
	{#State 198
		ACTIONS => {
			"-" => 68,
			":" => 67,
			"<" => 70,
			"+" => 72,
			"~" => 71,
			"*" => 79,
			"?" => 69,
			"{" => 73,
			"&" => 74,
			"/" => 75,
			"=" => 76,
			"(" => 77,
			"|" => 78,
			"." => 80,
			">" => 81
		},
		DEFAULT => -58
	},
	{#State 199
		ACTIONS => {
			'IDENTIFIER' => 26,
			"*" => 149
		},
		GOTOS => {
			'identifier' => 207
		}
	},
	{#State 200
		DEFAULT => -81
	},
	{#State 201
		DEFAULT => -28
	},
	{#State 202
		ACTIONS => {
			"-" => 68,
			":" => 67,
			"?" => 69,
			"<" => 70,
			";" => 208,
			"+" => 72,
			"~" => 71,
			"&" => 74,
			"{" => 73,
			"/" => 75,
			"=" => 76,
			"|" => 78,
			"(" => 77,
			"*" => 79,
			"." => 80,
			">" => 81
		}
	},
	{#State 203
		DEFAULT => -26
	},
	{#State 204
		DEFAULT => -84
	},
	{#State 205
		DEFAULT => -64
	},
	{#State 206
		DEFAULT => -63
	},
	{#State 207
		ACTIONS => {
			"[" => 152
		},
		DEFAULT => -82,
		GOTOS => {
			'array_len' => 209
		}
	},
	{#State 208
		DEFAULT => -27
	},
	{#State 209
		DEFAULT => -73
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
		 'idl', 2,
sub
#line 24 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 8
		 'import', 3,
sub
#line 27 "pidl/idl.yp"
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
#line 34 "pidl/idl.yp"
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
#line 41 "pidl/idl.yp"
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
#line 50 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 12
		 'commalist', 3,
sub
#line 51 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 13
		 'coclass', 7,
sub
#line 55 "pidl/idl.yp"
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
#line 67 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 16
		 'interface', 8,
sub
#line 71 "pidl/idl.yp"
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
#line 84 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 19
		 'cpp_quote', 4,
sub
#line 89 "pidl/idl.yp"
{{
		 "TYPE" => "CPP_QUOTE",
		 "FILE" => $_[0]->YYData->{FILE},
		 "LINE" => $_[0]->YYData->{LINE},
		 "DATA" => $_[3]
	}}
	],
	[#Rule 20
		 'definitions', 1,
sub
#line 98 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 21
		 'definitions', 2,
sub
#line 99 "pidl/idl.yp"
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
#line 107 "pidl/idl.yp"
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
#line 117 "pidl/idl.yp"
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
#line 131 "pidl/idl.yp"
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
#line 143 "pidl/idl.yp"
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
		 'typedecl', 2,
sub
#line 156 "pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 35
		 'sign', 1, undef
	],
	[#Rule 36
		 'sign', 1, undef
	],
	[#Rule 37
		 'existingtype', 2,
sub
#line 161 "pidl/idl.yp"
{ ($_[1]?$_[1]:"signed") ." $_[2]" }
	],
	[#Rule 38
		 'existingtype', 1, undef
	],
	[#Rule 39
		 'type', 1, undef
	],
	[#Rule 40
		 'type', 1, undef
	],
	[#Rule 41
		 'type', 1,
sub
#line 165 "pidl/idl.yp"
{ "void" }
	],
	[#Rule 42
		 'enum_body', 3,
sub
#line 167 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 43
		 'opt_enum_body', 0, undef
	],
	[#Rule 44
		 'opt_enum_body', 1, undef
	],
	[#Rule 45
		 'enum', 4,
sub
#line 170 "pidl/idl.yp"
{{
             "TYPE" => "ENUM", 
			 "PROPERTIES" => $_[1],
			 "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 46
		 'enum_elements', 1,
sub
#line 179 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 47
		 'enum_elements', 3,
sub
#line 180 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 48
		 'enum_element', 1, undef
	],
	[#Rule 49
		 'enum_element', 3,
sub
#line 184 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 50
		 'bitmap_body', 3,
sub
#line 187 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 51
		 'opt_bitmap_body', 0, undef
	],
	[#Rule 52
		 'opt_bitmap_body', 1, undef
	],
	[#Rule 53
		 'bitmap', 4,
sub
#line 190 "pidl/idl.yp"
{{
             "TYPE" => "BITMAP", 
		     "PROPERTIES" => $_[1],
			 "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 54
		 'bitmap_elements', 1,
sub
#line 199 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 55
		 'bitmap_elements', 3,
sub
#line 200 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 56
		 'opt_bitmap_elements', 0, undef
	],
	[#Rule 57
		 'opt_bitmap_elements', 1, undef
	],
	[#Rule 58
		 'bitmap_element', 3,
sub
#line 205 "pidl/idl.yp"
{ "$_[1] ( $_[3] )" }
	],
	[#Rule 59
		 'struct_body', 3,
sub
#line 208 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 60
		 'opt_struct_body', 0, undef
	],
	[#Rule 61
		 'opt_struct_body', 1, undef
	],
	[#Rule 62
		 'struct', 4,
sub
#line 212 "pidl/idl.yp"
{{
             "TYPE" => "STRUCT", 
			 "PROPERTIES" => $_[1],
			 "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 63
		 'empty_element', 2,
sub
#line 221 "pidl/idl.yp"
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
	[#Rule 64
		 'base_or_empty', 2, undef
	],
	[#Rule 65
		 'base_or_empty', 1, undef
	],
	[#Rule 66
		 'optional_base_element', 2,
sub
#line 235 "pidl/idl.yp"
{ $_[2]->{PROPERTIES} = FlattenHash([$_[1],$_[2]->{PROPERTIES}]); $_[2] }
	],
	[#Rule 67
		 'union_elements', 0, undef
	],
	[#Rule 68
		 'union_elements', 2,
sub
#line 240 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 69
		 'union_body', 3,
sub
#line 243 "pidl/idl.yp"
{ $_[2] }
	],
	[#Rule 70
		 'opt_union_body', 0, undef
	],
	[#Rule 71
		 'opt_union_body', 1, undef
	],
	[#Rule 72
		 'union', 4,
sub
#line 247 "pidl/idl.yp"
{{
             "TYPE" => "UNION", 
			 "PROPERTIES" => $_[1],
		     "NAME" => $_[3],
		     "ELEMENTS" => $_[4]
        }}
	],
	[#Rule 73
		 'base_element', 5,
sub
#line 256 "pidl/idl.yp"
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
	[#Rule 74
		 'pointers', 0,
sub
#line 270 "pidl/idl.yp"
{ 0 }
	],
	[#Rule 75
		 'pointers', 2,
sub
#line 271 "pidl/idl.yp"
{ $_[1]+1 }
	],
	[#Rule 76
		 'element_list1', 0,
sub
#line 275 "pidl/idl.yp"
{ [] }
	],
	[#Rule 77
		 'element_list1', 3,
sub
#line 276 "pidl/idl.yp"
{ push(@{$_[1]}, $_[2]); $_[1] }
	],
	[#Rule 78
		 'element_list2', 0, undef
	],
	[#Rule 79
		 'element_list2', 1, undef
	],
	[#Rule 80
		 'element_list2', 1,
sub
#line 282 "pidl/idl.yp"
{ [ $_[1] ] }
	],
	[#Rule 81
		 'element_list2', 3,
sub
#line 283 "pidl/idl.yp"
{ push(@{$_[1]}, $_[3]); $_[1] }
	],
	[#Rule 82
		 'array_len', 0, undef
	],
	[#Rule 83
		 'array_len', 3,
sub
#line 288 "pidl/idl.yp"
{ push(@{$_[3]}, "*"); $_[3] }
	],
	[#Rule 84
		 'array_len', 4,
sub
#line 289 "pidl/idl.yp"
{ push(@{$_[4]}, "$_[2]"); $_[4] }
	],
	[#Rule 85
		 'property_list', 0, undef
	],
	[#Rule 86
		 'property_list', 4,
sub
#line 295 "pidl/idl.yp"
{ FlattenHash([$_[1],$_[3]]); }
	],
	[#Rule 87
		 'properties', 1,
sub
#line 298 "pidl/idl.yp"
{ $_[1] }
	],
	[#Rule 88
		 'properties', 3,
sub
#line 299 "pidl/idl.yp"
{ FlattenHash([$_[1], $_[3]]); }
	],
	[#Rule 89
		 'property', 1,
sub
#line 302 "pidl/idl.yp"
{{ "$_[1]" => "1"     }}
	],
	[#Rule 90
		 'property', 4,
sub
#line 303 "pidl/idl.yp"
{{ "$_[1]" => "$_[3]" }}
	],
	[#Rule 91
		 'commalisttext', 1, undef
	],
	[#Rule 92
		 'commalisttext', 3,
sub
#line 308 "pidl/idl.yp"
{ "$_[1],$_[3]" }
	],
	[#Rule 93
		 'anytext', 0,
sub
#line 312 "pidl/idl.yp"
{ "" }
	],
	[#Rule 94
		 'anytext', 1, undef
	],
	[#Rule 95
		 'anytext', 1, undef
	],
	[#Rule 96
		 'anytext', 1, undef
	],
	[#Rule 97
		 'anytext', 3,
sub
#line 314 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 98
		 'anytext', 3,
sub
#line 315 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 99
		 'anytext', 3,
sub
#line 316 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 100
		 'anytext', 3,
sub
#line 317 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 101
		 'anytext', 3,
sub
#line 318 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 102
		 'anytext', 3,
sub
#line 319 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 103
		 'anytext', 3,
sub
#line 320 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 104
		 'anytext', 3,
sub
#line 321 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 105
		 'anytext', 3,
sub
#line 322 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 106
		 'anytext', 3,
sub
#line 323 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 107
		 'anytext', 3,
sub
#line 324 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 108
		 'anytext', 3,
sub
#line 325 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 109
		 'anytext', 3,
sub
#line 326 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]" }
	],
	[#Rule 110
		 'anytext', 5,
sub
#line 327 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 111
		 'anytext', 5,
sub
#line 328 "pidl/idl.yp"
{ "$_[1]$_[2]$_[3]$_[4]$_[5]" }
	],
	[#Rule 112
		 'identifier', 1, undef
	],
	[#Rule 113
		 'optional_identifier', 1, undef
	],
	[#Rule 114
		 'optional_identifier', 0, undef
	],
	[#Rule 115
		 'constant', 1, undef
	],
	[#Rule 116
		 'text', 1,
sub
#line 342 "pidl/idl.yp"
{ "\"$_[1]\"" }
	],
	[#Rule 117
		 'optional_semicolon', 0, undef
	],
	[#Rule 118
		 'optional_semicolon', 1, undef
	]
],
                                  @_);
    bless($self,$class);
}

#line 353 "pidl/idl.yp"


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
			    /^(coclass|interface|const|typedef|union|cpp_quote
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
