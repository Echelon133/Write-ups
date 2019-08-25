# Simple Nanomites Crackme Challenge Write-up

## Introduction

In this writeup I'm going to show you how I solved a crackme challenge that uses the anti-memory dumping technique called **The Nanomite Technology**.

This crackme was solved without using any tricks/debuggers/tracers - I only used Ghidra and Python, because I wanted to gain an in-depth knowledge about the whole binary execution.

## What are Nanomites?

If we read up about this technique, we will find out that the key concepts of it are:
* have at least two processes - a parent process and a child process
* child process executes code that has some instructions (usually conditional jump instructions) replaced with 0xcc byte (which is an **int3** instruction, that stops the child execution and gives the control over it to the process that debugs it - the parent process)
* parent process debugs the child process and waits for **int3** interrupt that gives it control over the child process and initiates the interpretation phase, which decides how to change child process registers (e.g. **EFLAGS** or **instruction pointer**) before setting them back and resuming the child process execution

It is rather easy to see why this technique is an anti-memory dumping technique - dumping memory from the child process will never give us all of the actual instructions that are executed by the program, because the **int3** instructions are never changed to the original instructions. These interrupt instructions are used to transfer control over the child process to the parent process, so that it can modify the child process registers as if the original instructions were there.

In the original nanomite technique the parent (the unpacker) uses an encrypted table that has an entry for each **int3** instruction in the child process. Each entry contains information about the original instruction that was in the code before it was replaced with the **int3**, the address, the offset and a flag that indicates whether that **int3** is a nanomite (because there is a possibility that the original code has actual **int3** instructions).

## Reverse engineering using Ghidra

### Initial inspection of the binary

From the fact that our crackme challenge is only a single binary we can conclude that the code executed by both the parent and the child process will be there. Some versions of this technique use two different executables - one executable is a protected binary and the other is a binary that is responsible for the correct execution of the first executable. 

Opening the binary in Ghidra shows us few things: 
* symbols have been stripped (nothing unusual)
* it uses **ptrace**, **fork**, **waitpid** - all of these functions are the key to this technique - **ptrace** is used for attaching to another process to debug it, **fork** is used for spawning a copy of the process in which the function was called, **waitpid** is used for blocking program execution until a process with given process ID sends a signal
* it uses **puts** and **scanf** - nothing unexpected in a crackme 
* it uses **memcpy** and **mmap** - at this point we need to find out what for

### Entry function

This program entry point looks like a standard entry code of C programs. Registers get pointers to three functions before calling **__libc_start_main**.

![ENTRY_BEFORE1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/ENTRY_BEFORE1.png)

We can rename these functions based on the function signature of **__libc_start_main** found on the internet.

![ENTRY_AFTER2](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/ENTRY_AFTER2.png)

Functions **init_fini_setup** and **stack_end** look normal, so we do not expect any traps there.

### Main function

This function contains code that is quite usual for crackmes - first **puts** function displays the prompt to the screen asking the user for a flag/password, then **scanf** function is called to read that input and save it on the stack.

In this case **scanf** is called with a format string *"%255s"*, which means that at most we can input 255 characters.

![MAIN_BEFORE1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/MAIN_BEFORE1.png)

After that we only have a call to a single function. Since this function is always called and is needed for the program to proceed, we can just call it **proceed_execution**.

After renaming obvious things, we get this:

![MAIN_AFTER2](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/MAIN_AFTER2.png)

### proceed_execution code up until fork

![PROCEED_EXECUTION1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/PROCEED_EXECUTION1.png)

First function we see here is **mmap**. After checking up **man mmap** and looking at the **sys/mman.h** we can reconstruct the arguments:

```C
mmap(
NULL,  // let the kernel choose the address 
0x141, // size of the allocation
PROT_READ | PROT_WRITE | PROT_EXEC, // RWX memory permission 
MAP_ANONYMOUS | MAP_PRIVATE, // more info about this in the manual
-1, // fd = -1 means that this argument is ignored
0)  // memory offset set to 0
```

After **mmap** call is done, the pointer to allocated memory is copied to the stack, and the executable sets arguments before a call to **memcpy**.

Checking out **man memcpy** shows us that this function takes a pointer to destination memory, a pointer to the source and an amout of bytes that have to be copied.

This means that in our case **memcpy** copies 0x8d (141) bytes from some memory in data section to the memory that has been freshly allocated by **mmap**.

After renaming variables for clarity:

![PROCEED_EXECUTION2](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/PROCEED_EXECUTION2.png)

Now we can inspect the memory that **memcpy** copies from data section to the heap.

![DATA_PRE_DISASM1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/DATA_PRE_DISASM1.png)

We can interpret these bytes as x86-64 instructions, if we mark this section of bytes, then press the right mouse key and click **Disassemble**.

![DATA_AFTER_DISASM2](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/DATA_AFTER_DISASM2.png)

Since there is a lot of **int3** instructions here and these bytes were copied to a heap memory that has **PROT_EXEC** priviledges, we can safely assume that this is the code that the child process executes. But right now we won't try to analize these instructions. 

Right after the **memcpy** instruction in **proceed_execution** function we have a call to **fork**. This function creates a new process, that is a copy of the process which called it. The process that calls this function is called a parent process, whereas the created process is called a child process. Both of these processes have the same memory content right after the **fork** call, but these contents are in different memory spaces.

If these processes contain identical content, how do we distinguish between the parent and the child from inside the program? Since the **fork** function returns process id of the child in the parent process and 0 in the child process, there has to be a conditional statement if we need different path of execution in the child process.

Ghidra has a very useful and quite accurate decompiler that we might want to use from now, since the complexity of code we see is slowly growing.  

![PROCEED_EXECUTION_DECOMPILE1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/PROCEED_EXECUTION_DECOMPILE1.png)

As we can see, there is a conditional statement right after the **fork** call that divides the paths of execution of the parent and the child.

### The child's process path of execution

If *pid* returned by **fork** is equal to 0, the child process calls **ptrace** on itself (so that processes other than the parent process cannot trace its execution). 

If **ptrace** failed (meaning that some other process has already managed to start tracing), then the child process exits with status 0x2a.

If **ptrace** succeeded, then the executable memory that was allocated previously with **mmap** (memory with hidden instructions) is called as a function (with a pointer to the user input as an argument).

![CALL_HIDDEN_FUNC1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/CALL_HIDDEN_FUNC1.png)

From now on, these instructions will be executed, and every **int3** will make the child process stop, and let the parent process control it.

### The parent's process path of execution

We are going to start with reversing the parent's process path of execution.

First thing that happens here is a call to **waitpid** function that has three arguments: the child process *pid*, an address of a *wstatus* variable (for storing the status information of the child process) and 0 (meaning that no additional options were chosen).

The **waitpid** suspends execution of the calling process (it blocks the parent process) until the process with *pid* given as an argument to this function changes its state.

In this case we can clearly see, that the parent process has a loop that constantly blocks its execution, waiting for signals caused by **int3** instructions of the child process. 
This signal stops the execution of the child process and wakes the parent process, which checks the status of the child process stored in *wstatus* variable. 

![PROCEED_EXECUTION_DECOMPILE2](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/PROCEED_EXECUTION_DECOMPILE2.png)

This parent process loop only takes any action if two conditional statements checking *wstatus* are true.

First conditional statement checks whether *wstatus* is equal to 0x7f.

A quick look into *sys/wait.h* source shows us this:

```C
#define WIFSTOPPED(s)	(((s)&0xFF)==0x7F)
```

If we look up in linux manual what **WIFSTOPPED** exactly is, we will read that it *"returns true if the child process was stopped by delivery of a signal"*.

A second conditional statement is as cryptic as the one before. Fortunately, the answer to this one lies in the same place as the answer to the previous problem: in *sys/wait.h*.

```C
#define WSTOPSIG(s)	(((s)>>8)&0xFF)
```

This macro *returns the number of the signal which caused the child to stop*. Linux manual also mentions that *this macro should be employed only if WIFSTOPPED returned true*, which means that we are correct with decoding these *wstatus* checks.

Since the **WSTOPSIG** macro in our program checks whether the signal number was 5, we need to know what that signal means. The answer is: signal number 5 is a **SIGTRAP**. That signal is sent when an **int3** occurs. This means that the parent process takes further action only if the child process sends **SIGTRAP** signal.

![PROCEED_EXECUTION_DECOMPILE3](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/PROCEED_EXECUTION_DECOMPILE3.png)

The function that is called after receiving **SIGTRAP** from the child is most likely a function that decides how to modify registers of the child process based on the current state of the process.

Whether that function was called or not, **PTRACE_CONT** resumes the child process after it was stopped by (most likely) **int3**.

We can already see that "You won!" message will be printed only if **waitpid** returns -1 (meaning, that there is no longer a possibility to wait for the child process, because it was terminated) and **WSTOPSIG** of the terminated process is 0. 

![PROCEED_EXECUTION_DECOMPILE4](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/PROCEED_EXECUTION_DECOMPILE4.png)

Now we can go back to that function that is executed after every **SIGTRAP** signal from the child process.

It takes a pointer to the executable heap memory that was allocated with **mmap** before (that memory contains instructions executed by the other process) and a *pid* of the process that executes these instructions. 

We can rename the function we are currently reverse engineering to **execute_hidden_instructions**.

After fixing the function signature we get:

![EXECUTE_HIDDEN1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/EXECUTE_HIDDEN1.png)

Another thing that can be quickly fixed is the type of the variable that stores register state read by **PTRACE_GETREGS** and writted by **PTRACE_SETREGS**. It's of type **struct user_regs_struct** and can be found in **user.h**. Pressing right mouse key on the variable that stores registers and clicking "Auto Create Structure" transforms it into a struct. Now clicking again on that variable with a right mouse key and choosing "Edit Data Type" option, we can model this structure so that it looks exactly like the **user_regs_struct**.

![USER_REGS_STRUCT1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/USER_REGS_STRUCT1.png)

After applying that structure type the our variable, we get this:

![EXECUTE_HIDDEN2](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/EXECUTE_HIDDEN2.png)

Now the code is much more transparent because we can already see this cycle of reading the state of the child process registers, then operating on **RIP** (instruction pointer) and **EFLAGS**, and then setting the modified registers back.

Variable *local_10* is set to 0 at the beginning and incremented by one at the end of every loop so we can rename it to *counter*.

If *counter* is bigger than 0xc (12) this function returns.

Looking at the instructions that the child process executes, we can see that there are exactly thirteen **int3** instructions there.

![HIDDEN_INSTR_INT1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/HIDDEN_INSTR_INT1.png)

At the beginning **RAX**, **RCX** and **RBX** are set to zero. Then we have a pattern:

1. Read a byte from [**RDI**] into lowest byte of **RAX** (AL)
2. Cause a **SIGTRAP** with **int3**
3. Execute a NOP
4. If ZF (zero flag) was not set, then take a jump out. Otherwise increment **RDI** by one and start from point 1, unless there is a **syscall**

Since this cycle of reading a byte from dereferenced **RDI** is repeated 13 times and function **execute_hidden_instructions** quits when *counter* is bigger than 12, we need to give **scanf** 13 characters of input.

If we look at the end of this hidden instruction block, we'll see this:

![HIDDEN_INSTRUCTIONS_EXIT1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/HIDDEN_INSTRUCTIONS_EXIT1.png)

**Syscall** instruction executes a syscall that is represented by a number stored in the **RAX** (AL) register.

**SYSCALL** 0x3c (60) is the **exit** syscall. Register **EDI** holds a status with which we want to exit.

Even before that we found out, that to display the "You won!" message, we need the child process to exit with status 0. We can see here, that **exit(0)** is called only if after every **int3** the zero flag is set to 1 (because if it is 0, then the code jumps to **exit(1)**).

This means that we need to find a 13 character password that makes the parent process set **ZF** of the child process to 1 after every **int3**.

Now we can go back to the **execute_hidden_instructions** because we already know what has to be done.

Variable *counter* seems to store the index of the character that we currently verify, but we do not keep the state of that variable. It has value 0 after each call to that function (and each **int3** causes this function to be called once).

So how does the program know which character are we currently verifying?

![COUNTER_SETUP1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/COUNTER_SETUP1.png)

Since the registers that we read-in using **ptrace** always store the state of child process registers right after the **int3**, we already know that each **RIP** will be an address of the byte that is right after the **int3** (instruction pointer always points to the address of next instruction).

With our current knowledge we can figure out every one of the thirteen results of **rip - (hidden_instr + 1)** equation.

If we - for the sake of calculations - assume that these instructions start at address 0x400ac0, we'll get this:


|Loop | RIP        | hidden_instr+1 | Result |
|-----|------------|----------------|--------|
|   1 | 0x400acc   | 0x400ac1       | 0xb    |
|   2 | 0x400ad5   | 0x400ac1       | 0x14   |
|   3 | 0x400ade   | 0x400ac1       | 0x1d   |
| ... | ...        | ...            | ...    |
|  13 | 0x400b38   | 0x400ac1       | 0x77   |

Each **RIP** value is an address of a **NOP** instruction that comes right after the **int3** instruction. Value that we subtract from the **RIP** is the same for each equation.

Result of that subtraction is compared to the value taken from an array of 38 bytes that is placed in the data section. Our *counter* variable multiplied by 3 is an index of that array. If we calculate each possible index, we'll get:

![DATA_SECTION1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/DATA_SECTION1.png)


| Counter | Counter * 3 | Data[Counter * 3] |
|---------|-------------|-------------------|
| 0       | 0           | 0xb               |
| 1       | 3           | 0x14              |
| 2       | 6           | 0x1d              |
| ...     | ...         | ...               |
| 13      | 39          | 0x77              |

Looking at the values taken from both tables we can see how the program recognizes which character it is currently checking: each time the function **execute_hidden_instructions** is called, it calculates a difference between the current **RIP** value and the second byte of the hidden instructions, and then checks whether the difference is equal to the byte that is stored in the data under an index of *counter* multiplied by 3. If the values are not equal, it increments the *counter* until these values are equal.

Now since we know how this function checks the *counter*, we can look at the code inside the block:

![FLAG_SETTING1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/FLAG_SETTING1.png)

Ghidra decompiler incorrectly shows here that there are two bit-shifts - in fact, looking at the assembly we can see that there is only one. 

Because *counter* in our case holds only positive integers, shifting the value right by 0x1f (31) is always going to result in 0, because *counter* always has sign 0.

The conditional statement that we have there checks whether **RAX** register (which holds a byte that represents one character of the password) is compared to the value taken from the same 38 element byte array that we have already seen.

We can simplify the formula that calculates the index of that array (because one variable from that formula is always equal to 0):

![SIMPLE_FORMULA1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/SIMPLE_FORMULA1.png)

This gives us: 

```C
index = (counter * 3) + (counter & 1);
```

Condition is true only if **RAX** is equal to the byte that is stored in the byte array under that index (this time our byte array starts at the second byte, ommiting the 0xb byte).

If that condition is true, **EFLAGS** register has its seventh bit set (0x40 is equal to 0b01000000). This bit represents **ZF** (zero flag).

This means, that we must input a password in which each character makes both conditional statements evaluate to true, so that the **ZF** can be set before saving the registers and resuming the child process execution.

We can write a short python script that decodes a password for us. 

We can use Ghidra's "Copy Special > Byte String" option to quickly copy the 37 byte array to our script.

![PYTHON_SCRIPT1](https://github.com/Echelon133/Write-ups/blob/master/screens/Nanomites/PYTHON_SCRIPT1.png)

After executing that script we get the message: 

```
Password you are looking for: n4n0****_3*** 
```

Providing that password (uncensored) in the executable's prompt confirms that we have solved this crackme.














