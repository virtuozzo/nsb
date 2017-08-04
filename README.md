# nsb
## Introduction
The ReadyKernel Userspace technology is represented by a suite of **nsb** tools for creating and applying live patches.
A live patch is a shared object, albeit an uncommon one that cannot be loaded by dynamic linker. For this reason, live patches are loaded from outside processes by means of the nsb tool.
Supporting the x86_64 architecture, these tools can replace parts of process logic, i.e. of a running single- or multi-threaded program, on the fly without stopping or restarting it.
Live patches can be applied to any kind of executable, including:
- statically linked binaries,
- dynamically linked binaries,
- shared libraries.

Process logic can be replaced on the function or higher level. That is, one or more process functions can be changed according to the following algorithm:
1) New functions are added to process address space.
2) Links to current process data are restored in the new functions.
3) Process execution is redirected from the old functions to the new ones by means of JMP instructions.
Based on the above, userspace live patching poses the following requirements to code:
1) Atomic (for the process) replacement of executable code.
2) Maintenance of links to static and global variables existing in the process.

## Principles of Applying Patches with nsb
Patching a process has several stages:
1) Stopping process execution at a safe point from outside.
2) Loading and applying the patch to the executable code of the process.
3) Freeing the process.

### Stopping Process Execution at a Safe Point from Outside

The **nsb** tool stops process execution via the **ptrace** system call.

After the process is stopped (i.e. all its threads are stopped), **nsb** checks all stacks via the **libunwind** API to make sure that portions of code to be changed by the patch were not being executed. Otherwise **nsb** frees all process threads, waits for a short time, and stops them again. The number of retries is limited, and the delay increases after each retry.

### Loading and Applying the Patch to the Executable Code of the Process
The patch is loaded by invoking **mmap** system calls in the target process context. Parasitic code is injected into the process via the **libcompel** library.

After loading, the patch is bound to the target process based on information added to the patch during its creation.

Binding means that process execution is redirected from the old functions to the new ones by means of JMP instructions as well as any of the following:
1) Redirecting external links to global functions and variables according to the dynamic linker algorithm.
2) Redirecting links to process static data.
3) Redirecting links to static functions in the executable code of the process.

### Freeing the Process
After the patch is loaded, code execution is redirected, and all links in the patch are initialized, process execution resumes from the stopping point via the **ptrace** system call. 

## Using diff to Evaluate Possibility of Creating Live Patches
The diff that you need to create a patch from can be, in most cases, any change to process logic. However, there are certain things that live patches in general may not do:
- Add new static or global variables. Reason: a new variable may contain a state that the new logic needs but that does not exist in the running process.
- Resize static or global variables or data structures. Reason: after patching, a part of process state accumulated during runtime can be lost.
- Reorder nested variables in structures. Reason: the allocated data are presented in a different order in the process.

## Creating Live Patches
Live patches are created from object files with changed code by means of a generator. This tool adds to the object file an ELF section named "vzpatch" with the information required to apply the patch.
It is important to know that the generator considers all functions in a patch as new and will create jumps to all of them.
Two types of live patches are supported: "manual" and "auto".

### Creating Manual Patches

This type is useful to experienced developers that need to create a compact patch quickly.

To create a manual patch, the developer needs to provide to the generator the following:
- the object file to patch (must contain debug info) and
- the patch built as a shared library.

Such patches are created manually as follows:
- The possibility to create a live patch from the diff is evaluated.
- The changed code (functions) is copied to a separate file.
- All links to static variables and functions required by changed functions.

Detailed description can be found in ["Manual Patching Overview"](docs/manual-mode.md) document.

### Creating Auto Patches

Patches of this type are created automatically although the developer still needs to review the diff to see whether a patch can be created from it.
Auto patches are coarser-grained, that is, created on the source file compile unit level. An auto patch includes the entire C file even if only one function in it has been changed.
To create an auto patch, the developer needs to provide to the generator the following:
- the object file to patch (must contain debug info),
- the patch built as a shared library, and
- the list of all object files the patch is built from; all these object files must be built with the options "-g -ffunction-sections -fdata-sections".

## Applying Patches to Processes

The procedure of applying a patch includes the following steps:
1. The process (all its threads) is stopped.
2. The patch is added to the process address space.
3. The patch is configured:
   1. Links to external global variables and functions are initialized.
   2. Links to external static variables and functions are initialized (manual patches only).
   3. Links to external static variables and functions are inserted into the code (auto patches only).
  
JMP instructions from old functions to new ones are inserted into the code.

The **nsb** tool currently supports these commands: 
- **patch**, apply a patch to a process,
- **revert**, remove a patch from a process,
- **list**, list applied patches,
- **check**, check whether a patch can be applied to a process.

The following processes are not supported (these processes are not guaranteed to remain working after patching):
- C coroutines (that use setcontext, makecontext, etc.),
- processes that use GIMPLE (in particular, those built with Link Time Optimization),
- processes that share address space with other processes (CLONE_VM).

## Live Patching Technology Limitations
Even though a patch can always be created and applied to a process, it is important to understand that some processes are not guaranteed to remain working after patching.
Some limitations are related to patch generation, some, to application.

### Patch Generation Limitations
The following limitations can be discovered automatically from debug info while generating a patch:
- variable/structure resize,
- structure element reorder,
- variable type change due to compiler optimizations ("var -> const" and "const -> var"),
- use of gcc GIMPLE plugins (e.g., Link Time Optimization).

## Patch Application Limitations
The following limitations can be discovered automatically while applying a patch:
- impossibility to stop the process outside of patched functions.

The following limitations cannot be discovered while applying a patch (strict limitations that must be observed by system administrator):
- use of coroutines by the process.

## Heatbleed demo
Here is the link to live pathing demo of famous "Heartbleed" expoit (https://en.wikipedia.org/wiki/Heartbleed):
https://youtu.be/lxP1zLvlczA

## Build dependences
C:
- libprotobuf-c
- libunwind
- libcompel (part of CRIU: https://github.com/xemul/criu)
- libelf

Python (2.7):
- pyelftools
- protobuf
