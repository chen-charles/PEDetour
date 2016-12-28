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
you can directly reference the imports as those will be resolved at compile time
call [kernel32.dll::GetProcAddress]
function ** kernel32.dll::GetProcAddress

you can call the original dll functions through
call [originalDLLName.bak::functionName]

note: dll name must be in lower cases, function names are case sensitive
note: __stdcall stack: from right to left cleanup: callee
*/

call [kernel32.dll::GetProcessHeap]
push 5
push 0x8
push eax
call [kernel32.dll::HeapAlloc]

push ebx
    mov ebx, eax
    mov byte ptr [ebx], 66
    mov byte ptr [ebx+1], 101
    mov byte ptr [ebx+2], 101
    mov byte ptr [ebx+3], 112
    mov byte ptr [ebx+4], 0
    mov eax, ebx
pop ebx

push eax    // lpProcName

call [kernel32.dll::GetProcessHeap]
push 13
push 0x8
push eax
call [kernel32.dll::HeapAlloc]

push ebx
    mov ebx, eax

    // kernel32.dll
    mov byte ptr [ebx], 107
    mov byte ptr [ebx+1], 101
    mov byte ptr [ebx+2], 114
    mov byte ptr [ebx+3], 110
    mov byte ptr [ebx+4], 101
    mov byte ptr [ebx+5], 108
    mov byte ptr [ebx+6], 51
    mov byte ptr [ebx+7], 50
    mov byte ptr [ebx+8], 46
    mov byte ptr [ebx+9], 100
    mov byte ptr [ebx+10], 108
    mov byte ptr [ebx+11], 108
    mov byte ptr [ebx+12], 0

    /*
    // user32.dll
    mov byte ptr [ebx], 117
    mov byte ptr [ebx+1], 115
    mov byte ptr [ebx+2], 101
    mov byte ptr [ebx+3], 114
    mov byte ptr [ebx+4], 51
    mov byte ptr [ebx+5], 50
    mov byte ptr [ebx+6], 46
    mov byte ptr [ebx+7], 100
    mov byte ptr [ebx+8], 108
    mov byte ptr [ebx+9], 108
    mov byte ptr [ebx+10], 0
    */

    mov eax, ebx
pop ebx

push eax
call [kernel32.dll::LoadLibraryA]
push eax    // hModule

call [kernel32.dll::GetProcAddress]

push 1500
push 3000
call eax


push 0
push 0
push 0
push 0
call [user32.dll::MessageBoxA]

xor eax, eax

call [testdll.bak::?fnTestDLL@@YAHXZ]

ret
nop
nop
nop
nop
