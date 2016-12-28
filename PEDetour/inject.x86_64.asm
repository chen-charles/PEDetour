/*
PEDetour --- modify binary Portable Executable to hook its export functions
Copyright (C) 2016  Jianye Chen
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
ref: https://blogs.msdn.microsoft.com/oldnewthing/20040114-00/?p=41053/

x86_64 asm is a bit different from x86 asm, specifically,
1) caller cleans up the stack (even in WINAPI)
2) stack MUST be aligned at 16 bytes before calling anything
3) rax, rcx, rdx, r8, r9, r10, r11 are for scratch

Windows x86_64 parameter passing (a bit different from standard):
first four parameters*: rcx, rdx, r8, r9
rest: push to stack
*space for the register parameters is reserved on the stack

e.g.
mov rcx, 3000   // freq
mov rdx, 3000   // duration
mov rax, qword ptr [kernel32.dll::Beep]
call rax

note:
you MUST call library functions with direct-addressing, RIP-addressing is not supported
    call [kernel32.dll::Beep]   // crash
instead, use,
    mov rax, qword ptr [kernel32.dll::Beep]
    call rax

note:
dll name MUST be in lower()
    mov rax, qword ptr [kernel32.dll::Beep] // valid
    mov rax, qword ptr [KERNEL32.dll::Beep] // invalid
    
*/

push r15    /* x64 stack alignment requirement, however, not all function checks it */


mov rcx, 3000   /* freq */
mov rdx, 3000   /* duration */
mov rax, qword ptr [kernel32.dll::Beep]
call rax

mov rcx, 1000
mov rdx, 3000
mov rax, qword ptr [kernel32.dll::Beep]
call rax

xor ecx, ecx
xor edx, edx
xor r8d, r8d
xor r9d, r9d
mov rax, qword ptr [user32.dll::MessageBoxA]  
call rax

mov rax, qword ptr [testdll.bak::?fnTestDLL@@YAHXZ]
call rax

pop r15
ret
