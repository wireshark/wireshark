; asm_utils_win32_x86.asm
; Functions optionally implemented in assembler
;
; Wireshark - Network traffic analyzer
; By Gerald Combs <gerald@wireshark.org>
; Copyright 1998 Gerald Combs
;
; This program is free software; you can redistribute it and/or
; modify it under the terms of the GNU General Public License
; as published by the Free Software Foundation; either version 2
; of the License, or (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program; if not, write to the Free Software
; Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
;

SECTION .text

GLOBAL _wrs_strcmp
GLOBAL _wrs_strcmp_with_data
GLOBAL _wrs_str_equal
GLOBAL _wrs_check_charset
GLOBAL _wrs_str_hash

    align 16
_wrs_strcmp:
_wrs_strcmp_with_data:
    mov ecx, dword [esp + 4]  ; a
    mov edx, dword [esp + 8]  ; b
    push ebx
CMP_LOOP:
    mov eax, dword [ecx]
    mov ebx, dword [edx]
    cmp al, bl
    jne CMP_NEQ_END
    or al, al
    jz CMP_EQ_END
    cmp ah, bh
    jne CMP_NEQ_END
    or ah, ah
    jz CMP_EQ_END
    shr eax, 16
    shr ebx, 16
    add ecx, byte 4
    add edx, byte 4
    cmp al, bl
    jne CMP_NEQ_END
    or al, al
    jz CMP_EQ_END
    cmp ah, bh
    jne CMP_NEQ_END
    or ah, ah
    jnz CMP_LOOP
CMP_EQ_END:
    pop ebx
    xor eax, eax
    retn
CMP_NEQ_END:  
    ; returns 1 or -1 based on CF flag from the last comparision
    sbb eax, eax
    pop ebx
    shl eax, 1
    inc eax
    retn

    align 16
_wrs_str_equal:
    mov ecx, dword [esp + 4]  ; a
    mov edx, dword [esp + 8]  ; b
    push ebx
EQL_LOOP:
    mov eax, dword [ecx]
    mov ebx, dword [edx]
    cmp al, bl
    jne EQL_NEQ_END
    or al, al
    jz EQL_EQ_END
    cmp ah, bh
    jne EQL_NEQ_END
    or ah, ah
    jz EQL_EQ_END
    shr eax, 16
    shr ebx, 16
    add ecx, byte 4
    add edx, byte 4
    cmp al, bl
    jne EQL_NEQ_END
    or al, al
    jz EQL_EQ_END
    cmp ah, bh
    jne EQL_NEQ_END
    or ah, ah
    jnz EQL_LOOP
EQL_EQ_END:
    xor eax, eax
    pop ebx
    not eax
    retn
EQL_NEQ_END:  
    pop ebx
    xor eax, eax
    retn

    align 16
_wrs_check_charset:
    mov edx, dword [esp + 4]  ; table
    mov ecx, dword [esp + 8]  ; str
    push edi
    push ebx
    mov edi, edx
    mov bl, byte 0xFF
CHK_LOOP:
    mov eax, dword [ecx]
    movzx edx, al
    test bl, byte [edi+edx]
    jz CHK_AL_END
    movzx edx, ah
    test bl, byte [edi+edx]
    jz CHK_AH_END
    shr eax, 16
    add ecx, byte 4
    movzx edx, al
    test bl, byte [edi+edx]
    jz CHK_AL_END
    movzx edx, ah
    test bl, byte [edi+edx]
    jnz CHK_LOOP
CHK_AH_END:
    movzx eax, ah
    pop ebx
    pop edi
    retn
CHK_AL_END:
    movzx eax, al
    pop ebx
    pop edi
    retn

    align 16
_wrs_str_hash:
    mov edx, dword [esp + 4]  ; v
    push ebx
    xor eax, eax
    mov ecx, dword [edx]
    or cl, cl
    movzx ebx, cl
    jz HASH_END
HASH_LOOP:
    sub ebx, eax
    shl eax, 5
    add eax, ebx
    or ch, ch
    movzx ebx, ch
    jz HASH_END
    sub ebx, eax
    shl eax, 5
    add eax, ebx
    shr ecx, 16
    add edx, byte 4
    or cl, cl
    movzx ebx, cl
    jz HASH_END
    sub ebx, eax
    shl eax, 5
    add eax, ebx
    or ch, ch
    movzx ebx, ch
    jz HASH_END
    sub ebx, eax
    shl eax, 5
    add eax, ebx
    mov ecx, dword [edx]
    or cl, cl
    movzx ebx, cl
    jnz HASH_LOOP
HASH_END:
    pop ebx
    retn
