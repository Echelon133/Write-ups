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
* child process executes code that has some instructions (usually conditional jump instructions) replaced with 0xcc byte (which is an **int3** instruction)
* parent process debugs the child process and waits for **int3** interrupt that initiates the interpretation phase which decides how to change child process registers (e.g. **EFLAGS** or **instruction pointer**) before setting them and resuming the child process execution

It is rather easy to notice why this technique is an anti-memory dumping technique - dumping memory from the child process will never give us the actual instructions that are executed by the program, because the **int3** instructions are never replaced in it. These interrupt instructions are used to transfer control over the child process to the parent process, so that it can modify the child registers.

In the original nanomite technique the parent (the unpacker) uses an encrypted table that has an entry for each **int3** instruction in the child process. Each entry contains info about the original instruction that was in the code before it was replaced with the **int3**, the address, the offset and a flag that indicates whether that **int3** is a nanomite (because there is a possibility that the original code has actual **int3** instructions).

## Reverse engineering using Ghidra





