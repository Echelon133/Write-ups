1. Intro about the challenge
2. What's a nanomites technique typically
3. Start reversing from the main 
* tell about the stack setup, then typicall puts/scanf combo (with info about the accepted input format string)
* tell about the function that is called inside main
* decipher mmap call arguments
* decipher memcpy arguments and then check what does the source memory mean (decode as x86 instructions), then leave it for later
* explain what fork function does, how to distinguish whether we are in a child of parent process, 
4. Describe child process execution path, now explain what the hidden instructions do, what causes the child to terminate with status 1, what should happen to make execution fall through to the exit(0) function
5. Explain the parent waitpid loop, how it controls the child process execution depending on the status read from wstatus, what conditions to satisfy for it to call the checking function, what child has to do to make this loop finish with the communicate about successful solution, explain the checking function (how it finds out what character we are at, then how it decodes the index of the character that it expects)
6. Writing a python script that finds the password


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
* it uses **puts** and **scanf** - nothing unexpected for a crackme 
* it uses **memcpy** and **mmap** - at this point we need to find out what for



