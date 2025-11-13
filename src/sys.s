.globl write
.globl read
.globl exit
.globl fork
.globl execve
.globl waitid
.globl dup2
.globl open
.globl close
.globl pipe

.globl _start

.globl rust_eh_personality
.globl _Unwind_Resume

.extern start_rs

.text
read:
mov $0, %rax
syscall
ret

write:
mov $1, %rax
syscall
ret

getdents64:
mov $217, %rax
syscall
ret

exit:
mov $60, %rax
syscall
ret

fork:
mov $57, %rax
syscall
ret

pipe:
mov $22, %rax
syscall
ret

execve:
mov $59, %rax
syscall
ret

dup2:
mov $33, %rax
syscall
ret

open:
mov $2, %rax
syscall
ret

close:
mov $3, %rax
syscall
ret

chdir:
mov $80, %rax
syscall
ret

waitid:
mov $247, %rax
mov %rcx, %r10
syscall
ret

_start:
movq (%rsp), %rdi
leaq 8(%rsp), %rsi
call start_rs
xor %rax, %rax
call exit
jmp .


rust_eh_personality:
ret

_Unwind_Resume:
ret
