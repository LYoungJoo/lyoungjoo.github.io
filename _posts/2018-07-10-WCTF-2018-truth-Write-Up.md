---
layout:     post
title:      "WCTF 2018 truth write-up"
subtitle:   "WCTF 2018 reversing"
date:       2018-07-10
author:     "NextLine"
header-img: "img/post-bg-2.png"
tags:
    - WriteUp
---

# Wctf 2018 Truth

### 1. Intro

대회때는 함수들이 행렬곱을 나타내는 것이고, 행렬도 역연산이 가능하다는 사실을 알지 못해서 못풀었다.



### 2. Binary

파일은 윈도우 바이너리이며 dotnet이라 dnspy를 이용하였다. 이 문제를 처음에 잡았던 이유는 그나마 좀 만만해보이기도 하였고 디컴파일을 해보면 정말 쉽게 풀릴것처럼 생겼기 때문이였다.



```C#
private static void Main()
{
	Console.Write(Enter your flag );
	if (Lib.Verify(Console.ReadLine().Trim()))
	{
		Console.WriteLine(Great ));
		return;
	}
	Console.WriteLine(Wrong ();
}
```

위가 프로그램 main이며 딱 보기에도 Verify함수로 Flag인지 아닌지 검증한다.



```c#
public static bool Verify(string s)
{
	byte[] bytes = Encoding.ASCII.GetBytes(s);
	if (bytes.Length != 32)
	{
		return false;
	}
	byte[] array = Lib.Func2();
	Lib.Func3(array, bytes);
	Lib.Func4(array, bytes);
	Lib.Func5(array, bytes);
	for (int i = 0; i < 32; i++)
	{
		if (bytes[i] != array[3104 + i])
		{
			return false;
		}
	}
	return true;
}
```

Verify 함수 구조도 단순하다. Func2에서 특정 배열을 가져온다.



```c#
public static void Func3(byte[] b, byte[] x)
{
	byte[] array = new byte[32];
	for (int i = 0; i < 32; i++)
	{
		array[i] = (byte)b.Skip(i * 32).Take(32).Zip(x, (byte x1, byte x2) => (int)(x1 * x2)).Sum();
	}
	Array.Copy(array, x, 32);
}

// Token: 0x06000007 RID: 7 RVA: 0x00002228 File Offset: 0x00000428
public static void Func4(byte[] b, byte[] x)
{
	byte[] array = new byte[32];
	for (int i = 0; i < 32; i++)
	{
		array[i] = (byte)b.Skip(1024 + i * 32).Take(32).Zip(x, (byte x1, byte x2) => (int)(x1 * x2)).Sum();
	}
	Array.Copy(array, x, 32);
}

// Token: 0x06000008 RID: 8 RVA: 0x00002298 File Offset: 0x00000498
public static void Func5(byte[] b, byte[] x)
{
	byte[] array = new byte[32];
	for (int i = 0; i < 32; i++)
	{
		array[i] = (byte)(b.Skip(2048 + i * 32).Take(32).Zip(x, (byte x1, byte x2) => (int)(x1 * x2)).Sum() + (int)b[3072 + i]);
	}
	Array.Copy(array, x, 32);
}
```

Func들도 전부 간단하게되어있다. (하지만 실제로 이코드도 solver를 이용해 풀기에는 시간이 오래걸린다.)



``` c#
// WCTF2018Rev.Properties.Resources
// Token: 0x0600000A RID: 10 RVA: 0x00002314 File Offset: 0x00000514
unsafe static Resources()
{
	IntPtr intPtr = ldftn(Func) - 16;
	long num = *intPtr;
	IntPtr intPtr2 = ldftn(Func) - 8;
	long num2 = *intPtr2;
	ref long ptr = ldftn(Func) - 16;
	IntPtr intPtr3 = ldftn(Func) + 5;
	long num3 = (long)(*(intPtr3 + 1));
	ptr = *(intPtr3 + (IntPtr)(((int)(*(intPtr3 + 2)) << 3) + 3)) + (num3 << 3);
	ref long ptr2 = ldftn(Func) - 8;
	object obj = *(ldftn(Func) - 16);
	object obj2;
	for (;;)
	{
		obj2 = obj;
		if (*obj2 == 5)
		{
			break;
		}
		obj = obj2 + 16;
	}
	ptr2 = *(obj2 + 8);
	long num4 = *(ldftn(Func) - 8);
	*num4 = 6293447916875450697L;
	long num5 = num4 + 8L;
	*num5 = 996842507592L;
	long num6 = num5 + 8L;
	*num6 = -5023708761407594752L;
	long num7 = num6 + 8L;
	*num7 = 2247216228701921188L;
	long num8 = num7 + 8L;
	*num8 = 5195160555404404409L;
	long num9 = num8 + 8L;
	*num9 = 543045289092056715L;
	long num10 = num9 + 8L;
	*num10 = 612363414786457928L;
	long num11 = num10 + 8L;
	*num11 = 5245003925894368584L;
	long num12 = num11 + 8L;
	*num12 = 3816147333L;
	long num13 = num12 + 8L;
	object obj3 = *(ldftn(Func) - 16);
	object obj4;
	for (;;)
	{
		obj4 = obj3;
		if (*obj4 == 6)
		{
			break;
		}
		obj3 = obj4 + 16;
	}
	*(obj4 + 8) = *(ldftn(Func) - 8);
	object obj5 = *(ldftn(Func) - 16);
	object obj6;
	for (;;)
	{
		obj6 = obj5;
		if (*obj6 == 7)
		{
			break;
		}
		obj5 = obj6 + 16;
	}
	*(obj6 + 8) = *(ldftn(Func) - 8) + 89L;
	object obj7 = *(ldftn(Func) - 16);
	object obj8;
	for (;;)
	{
		obj8 = obj7;
		if (*obj8 == 8)
		{
			break;
		}
		obj7 = obj8 + 16;
	}
	*(obj8 + 8) = *(ldftn(Func) - 8) + 170L;
	*intPtr2 = num2;
	*intPtr = num;
}
```

하지만 이 바이너리가 좀 이상한게 디버깅을 해보면 Func3은 제대로 리턴하는데 Func4와 Func5는 이상한 값들을 리턴한다. 그 이유는 위처럼 생성자에서 jitpage에 직접 어셈을 삽입하는 부분이 있다. 이부분을 이 코드만 가지고 예측하기는 힘들어서 windbg를 이용해 cli를 직접 디버깅했다. 그랬더니 Func4와 Func5의 제대로된 부분을 얻을 수 있었다.



```asm
Func4
WCTF2018Rev.Lib.Func2()
Begin 00007ff9997505d0, size 26e
00007ff9`997505d0 4989c8          mov     r8,rcx
00007ff9`997505d3 4989d1          mov     r9,rdx
00007ff9`997505d6 56              push    rsi
00007ff9`997505d7 57              push    rdi
00007ff9`997505d8 488d7118        lea     rsi,[rcx+18h]
00007ff9`997505dc e800000000      call    00007ff9`997505e1 (WCTF2018Rev.Lib.Func2(), mdToken: 0000000006000005)
00007ff9`997505e1 5f              pop     rdi
00007ff9`997505e2 488d7f33        lea     rdi,[rdi+33h]
00007ff9`997505e6 48baa45f45f540b72f1f mov rdx,1F2FB740F5455FA4h
00007ff9`997505f0 b926000000      mov     ecx,26h
00007ff9`997505f5 eb18            jmp     00007ff9`9975060f
00007ff9`997505f7 488b06          mov     rax,qword ptr [rsi]
00007ff9`997505fa 4831d0          xor     rax,rdx
00007ff9`997505fd 488907          mov     qword ptr [rdi],rax
00007ff9`99750600 48c1ca03        ror     rdx,3
00007ff9`99750604 488d7f08        lea     rdi,[rdi+8]
00007ff9`99750608 488d7608        lea     rsi,[rsi+8]
00007ff9`9975060c 48ffc9          dec     rcx
00007ff9`9975060f 4885c9          test    rcx,rcx
00007ff9`99750612 75e3            jne     00007ff9`997505f7
00007ff9`99750614 5f              pop     rdi
00007ff9`99750615 5e              pop     rsi
00007ff9`99750616 4c89c1          mov     rcx,r8
00007ff9`99750619 4c89ca          mov     rdx,r9
00007ff9`9975061c 488d4910        lea     rcx,[rcx+10h]
00007ff9`99750620 488d5210        lea     rdx,[rdx+10h]
00007ff9`99750624 e986000000      jmp     00007ff9`997506af
00007ff9`99750629 488d8910040000  lea     rcx,[rcx+410h]
00007ff9`99750630 488d5210        lea     rdx,[rdx+10h]
00007ff9`99750634 57              push    rdi
00007ff9`99750635 56              push    rsi
00007ff9`99750636 4881ec00040000  sub     rsp,400h
00007ff9`9975063d 4889e7          mov     rdi,rsp
00007ff9`99750640 4889ce          mov     rsi,rcx
00007ff9`99750643 b980000000      mov     ecx,80h
00007ff9`99750648 f348a5          rep movs qword ptr [rdi],qword ptr [rsi]
00007ff9`9975064b 4889e1          mov     rcx,rsp
; rdx = input / rcx = tb[1024:2048] / rsi = tb[2048:]
; function : make new table 
00007ff9`9975064e e8ac000000      call    00007ff9`997506ff (WCTF2018Rev.Lib.Func2(), mdToken: 0000000006000005)
00007ff9`99750653 4831ff          xor     rdi,rdi
; function : func4
00007ff9`99750656 e854000000      call    00007ff9`997506af (WCTF2018Rev.Lib.Func2(), mdToken: 0000000006000005)
00007ff9`9975065b ffc7            inc     edi
00007ff9`9975065d 83ff05          cmp     edi,5
00007ff9`99750660 75f4            jne     00007ff9`99750656
00007ff9`99750662 4831ff          xor     rdi,rdi
00007ff9`99750665 80343a5a        xor     byte ptr [rdx+rdi],5Ah
00007ff9`99750669 ffc7            inc     edi
00007ff9`9975066b 83ff20          cmp     edi,20h
00007ff9`9975066e 75f5            jne     00007ff9`99750665
00007ff9`99750670 4881c400040000  add     rsp,400h
00007ff9`99750677 5e              pop     rsi
00007ff9`99750678 5f              pop     rdi
00007ff9`99750679 c3              ret
00007ff9`9975067a 488d8910080000  lea     rcx,[rcx+810h]
00007ff9`99750681 488d5210        lea     rdx,[rdx+10h]
00007ff9`99750685 57              push    rdi
00007ff9`99750686 56              push    rsi
00007ff9`99750687 4831ff          xor     rdi,rdi
00007ff9`9975068a 4831f6          xor     rsi,rsi
00007ff9`9975068d 488b84f100fcffff mov     rax,qword ptr [rcx+rsi*8-400h]
00007ff9`99750695 483104f2        xor     qword ptr [rdx+rsi*8],rax
00007ff9`99750699 ffc6            inc     esi
00007ff9`9975069b 83fe04          cmp     esi,4
00007ff9`9975069e 75ed            jne     00007ff9`9975068d
00007ff9`997506a0 e80a000000      call    00007ff9`997506af (WCTF2018Rev.Lib.Func2(), mdToken: 0000000006000005)
00007ff9`997506a5 ffc7            inc     edi
00007ff9`997506a7 83ff0a          cmp     edi,0Ah
00007ff9`997506aa 75de            jne     00007ff9`9975068a
00007ff9`997506ac 5e              pop     rsi
00007ff9`997506ad 5f              pop     rdi
00007ff9`997506ae c3              ret
00007ff9`997506af 57              push    rdi
00007ff9`997506b0 56              push    rsi
00007ff9`997506b1 51              push    rcx
00007ff9`997506b2 4883ec20        sub     rsp,20h
00007ff9`997506b6 4831ff          xor     rdi,rdi
00007ff9`997506b9 e824000000      call    00007ff9`997506e2 (WCTF2018Rev.Lib.Func2(), mdToken: 0000000006000005)
00007ff9`997506be 88043c          mov     byte ptr [rsp+rdi],al
00007ff9`997506c1 488d4920        lea     rcx,[rcx+20h]
00007ff9`997506c5 ffc7            inc     edi
00007ff9`997506c7 83ff20          cmp     edi,20h
00007ff9`997506ca 75ed            jne     00007ff9`997506b9
00007ff9`997506cc b904000000      mov     ecx,4
00007ff9`997506d1 4889d7          mov     rdi,rdx
00007ff9`997506d4 4889e6          mov     rsi,rsp
00007ff9`997506d7 f348a5          rep movs qword ptr [rdi],qword ptr [rsi]
00007ff9`997506da 4883c420        add     rsp,20h
00007ff9`997506de 59              pop     rcx
00007ff9`997506df 5e              pop     rsi
00007ff9`997506e0 5f              pop     rdi
00007ff9`997506e1 c3              ret
00007ff9`997506e2 53              push    rbx
00007ff9`997506e3 57              push    rdi
00007ff9`997506e4 4831ff          xor     rdi,rdi
00007ff9`997506e7 4831db          xor     rbx,rbx
00007ff9`997506ea 8a0439          mov     al,byte ptr [rcx+rdi]
00007ff9`997506ed f6243a          mul     al,byte ptr [rdx+rdi]
00007ff9`997506f0 00c3            add     bl,al
00007ff9`997506f2 ffc7            inc     edi
00007ff9`997506f4 83ff20          cmp     edi,20h
00007ff9`997506f7 75f1            jne     00007ff9`997506ea
00007ff9`997506f9 4889d8          mov     rax,rbx
00007ff9`997506fc 5f              pop     rdi
00007ff9`997506fd 5b              pop     rbx
00007ff9`997506fe c3              ret
```

```
Func5
; rcx = table
; rdx = input
00007ff9`9975067a 488d8910080000  lea     rcx,[rcx+810h]
00007ff9`99750681 488d5210        lea     rdx,[rdx+10h]
00007ff9`99750685 57              push    rdi
00007ff9`99750686 56              push    rsi
00007ff9`99750687 4831ff          xor     rdi,rdi

00007ff9`9975068a 4831f6          xor     rsi,rsi
00007ff9`9975068d 488b84f100fcffff mov     rax,qword ptr [rcx+rsi*8-400h]
00007ff9`99750695 483104f2        xor     qword ptr [rdx+rsi*8],rax
00007ff9`99750699 ffc6            inc     esi
00007ff9`9975069b 83fe04          cmp     esi,4
00007ff9`9975069e 75ed            jne     00007ff9`9975068d

00007ff9`997506a0 e80a000000      call    00007ff9`997506af (WCTF2018Rev.Lib.Func2(), mdToken: 0000000006000005)
00007ff9`997506a5 ffc7            inc     edi
00007ff9`997506a7 83ff0a          cmp     edi,0Ah
00007ff9`997506aa 75de            jne     00007ff9`9975068a
00007ff9`997506ac 5e              pop     rsi
00007ff9`997506ad 5f              pop     rdi
00007ff9`997506ae c3              ret
```

위 두개의 함수를 제대로 복구해서 사용자 입력에 따른 출력값을 정확히 예측할 수 있었다. 하지만 여기서 중요한건 저 연산 자체가 행렬곱을 뜻한다는건데, input을 1 * 32 행렬이라고 생각하니 역행렬을 이용해 역연산을 할 수 있었다. 



![ScoreBoard](/img/in-post/wctf/ex1.png)



위처럼 행렬곱이 발생하므로 input을 X 곱하는 행렬을 A라고하면 아래와 같다.

![ScoreBoard](/img/in-post/wctf/ex2.png)

이런식의 역연산을 그대로 코드로 짜주면 된다.

```python
from sage.all import *

def xor(a, b):
	return eval("%s^%s" % (a, b))

f = open('table','r')
table = f.read().split(' ')
table = [int(i) for i in table]
f.close()
enc = list(table[3104:])

func5 = [0 for i in range(0x20)]
for i in range(0x20):
	func5[i] = table[2048 + (i*32) : 2048 + ((i+1)*32)]
func5_xortb = list(table[1024 : 1024 + 32])

table2 = list(table)
for j in range(0x20):
    for i in range(j,0x20):
        tmp = table2[1024 + (j * 0x20) + i]
        tmp2 = table2[1024 + (i * 0x20) + j]
        table2[1024 + (j * 0x20) + i] = tmp2
        table2[1024 + (i * 0x20) + j] = tmp
func4 = [0 for i in range(0x20)]
for i in range(0x20):
	func4[i] = table2[1024 + i * 32 : 1024 + (i+1) * 32]

func3 = [0 for i in range(0x20)]
for i in range(0x20):
	func3[i] = table[i*32 : (i+1) * 32]

R = Integers(256)

# enc_Vector
encv = vector(enc)

# Func 5
func5m = Matrix(R,func5)
for j in range(10):
	encv = list(func5m.inverse() * encv)
	for i in range(0x20):
		encv[i] = xor(encv[i],func5_xortb[i])
	encv = vector(encv)

# Func 4
encv = list(encv)
for i in range(0x20):
	encv[i] = xor(encv[i],0x5a)
    
func4m = Matrix(R,func4)
encv = vector(encv)
for j in range(5):
	encv = func4m.inverse() * encv

# Func 3
func3m = Matrix(R,func3)
encv = func3m.inverse() * encv

flag = ''
for i in encv:
	flag += chr(i)
print flag
```
