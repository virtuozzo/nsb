# Manual Patching Overview
This chapter explains the principles and peculiarities of creating patches manually with the new API.
## 1.1 Problems to Solve
The previous API drew a strict line between two patch creation modes: automatic with the fullest possible
support for binding symbols in patch and manual that only allowed binding symbols with limited scope in
patch and target in the simplest of cases.
The new API expands the manual mode to the level of automatic, essentially removing the strict division
between modes.
In particular, the new API allows you to unambiguosly define the following in patches:
- links to target symbols for all types of symbols and scopes,
- mutable functions depending on scope.
## 1.2 Patch Build Requirements
Patches must be built as follows:
1. Without compiler optimizations i.e. with the parameter `-O0`. This is required to correctly and
unambiguously bind symbols between the patch and target.
2. With the parameter `-g` to create debug info required by the generator to map the patch and target.
3. With the parameter `-Wimplicit-function-declaration` that requires defining a prototype of external
function or variable to access. This will eliminate attempts to use instrumentation without including
required header files.
## 1.3 General Provisions
The generator allows using two classes of symbols:
- links (to target symbols, e.g., functions or variables),
- functions (e.g., fixed or new code).

Symbols, in turn, can be:
- global,
- with a limited scope.

To correctly bind fixed functions and links in patch with the target, it is generally required to define a binding
context so that a symbol can be found. The binding context is defined by patch instrumentation i.e. macros
defined in the header file `nsb/vzp.h`.

## 1.4 Binding Context
The generator only needs binding context for static symbols as the context describes which target source file
defines the code and links used in the patch. Otherwise binding context is unnecessary.

The following macro allows you to define binding context:

```c
VZP_FILE("path_to_file");
```

where *path_to_file* is the path to target file with mappings to patch, starting from project root.

Have in mind that:
- The patch generator requires a path (string), not the file itself. In other words, project source files are
not required.
- The macro defines binding context for code that follows context definition.
- Binding context must be defined for patches that fix functions with a limited scope.
- Prototype of the fixed function must match that of the target function. This helps avoid errors during
patch creation. If the prototypes do not match, the patch generator returns an error.

## 1.5 Binding Links in Patches
### 1.5.1 Global links
Global links do not require any special instrumentation. If you need to link to a target’s global variable in a
patch, follow the programming language semantics. For example:

```c
extern int x;
int printf(const char *format, ...);
```

Have in mind that:
- Instrumentation methods described in this guide (including binding context) do not affect global links.
- Global links are bound when patch loads.

### 1.5.2 Links to Symbols with Limited Scope
Links to symbols with limited scope require instrumentation for these symbols to be found. There are
several types of symbols with limited scope:
- Static symbols.
- Symbols with deliberately limited scope:
    - hidden, e.g., `(__attribute__ ((visibility ("hidden"))))`,
    - protected, e.g., `(__attribute__ ((visibility ("protected"))))`,
    - internal, e.g., `(__attribute__ ((visibility ("internal"))))`.

In general, file context is not required. It will be necessary, for example, if there are two static variables of the
same name in different target source files.

You can define file context in one of two ways:
- in general, by means of binding context described above, or
- for a specific symbol, in which case the file context will only affect binding of said symbol and have priority over the binding context.

### 1.5.3 Binding Macros Overview

For each type of link to variables with limited scope described earlier, two macros exist: for linking to
functions and variables.
Macros for links to variables:
- *VZP_STATIC_VAR_REF*, link to a static variable,
- *VZP_HIDDEN_VAR_REF*, link to a hidden variable,
- *VZP_PROTECTED_VAR_REF*, link to a protected variable,
- *VZP_INTERNAL_VAR_REF*, link to an internal variable.

Macros for links to functions:
- *VZP_STATIC_FUNC_REF*, link to a static function,
- *VZP_HIDDEN_FUNC_REF*, link to a hidden function,
- *VZP_PROTECTED_FUNC_REF*, link to a protected function,
- *VZP_INTERNAL_FUNC_REF*, link to an internal function.

Macro prototypes are the same for all link types (except for the parameter *file* that is used only for static
symbols).

A macro prototype for a link to a variable is as follows:

```c
VZP_{VISIBILITY}_VAR_REF(type, name[, file])
```

where
- *type* is variable type,
- *name* is variable name,
- *file* is the name of file to search for the variable in the target. This parameter is only used for static
symbols and is optional if you have already defined *VZP_FILE* or symbol name is unique in the target.

A macro prototype for a link to a function is as follows:

```c
VZP_{VISIBILITY}_FUNC_REF(type, name, (args...), [, file])
```

where
- *type* is the function return type,
- *name* is the function name,
- *(args...)* is the list of function arguments in parenthesis,
- *file* is the name of file to search for the function in the target. This parameter is only used for static
symbols and is optional if you have already defined *VZP_FILE* or symbol name is unique in the target. If
*file* is present in link definition, it has priority over *VZP_FILE* (if defined).

## 1.6 Resolving Symbol Name Conflicts
When you create a patch, you may need to modify two functions that need to link to different static variables
that have the same name. For example, a target may contain code like this:
```c
int f(void)
{
    static int x;
    return x++;
}

int g(void)
{
    static int x;
    return x--;
}
```
Attempting to patch it as shown below will result in name conflict during compilation:
```c
int f(void)
{
    VZP_STATIC_VAR_REF(int, x);
    return x++;
}

int g(void)
{
    VZP_STATIC_VAR_REF(int, x);
    return x--;
}
```
### 1.6.1 Name Conflict Problem Overview
The reason for conflict of names is the architectural limitation of links to variables defined by the macros
*VZP_STATIC_VAR_REF* and *VZP_STATIC_FUNC_REF*. When either macro is used, a special service variable is created
with a name derived from the name of the original static variable. This results in a compilation error.

The name conflict may also be a result of changing multiple static functions of the same name. However, in
this case you can work around the problem by defining same-name functions in different source files of the
patch. However, this workaround will not work with variables, because, an external link with the name of the
variable is created in addition to a service variable. And an external link to a symbol must be unique. As a
result, after patch is built, the code will feature a single link to two different variables, preventing the patch
from being bound.

### 1.6.2 How to Resolve Name Conflicts
To resolve a name conflict, make variable names unique any way you like.

For example, if you need two links to different variables with the same name *var*, rename one of them *var_2*
and use this name wherever the variable is used in the patch.

Such an approach will let you build the patch. However, after a renaming alone, the patch generator may fail
to bind the renamed variable to the target or, even worse, may bind it to a wrong variable of the same name.

To avoid this problem, the patch generator must be made aware that the variable *var_2* is the link to the
variable *var*. This can be done withe the following macro:

```c
VZP_STATIC_SYM_ALIAS(patch_name, target_name);
```

where *patch_name* is renamed symbol in the patch and *target_name* is the symbol in the target.

Have in mind that the macro that creates a link to a symbol in the target always creates a global link and a
static service variable. It means that an external global variable and a link to a static variable of the same
name cannot be defined in the same file.

# Manual Patch Examples
Thie chapter gives examples of using the new API to build patches manually.

All examples demonstrate cases whem symbols with a limited scope are defined in the target in the file
`foo/bar.c`. Have in mind that the path to the file is relative to target’s built root (usually, the project root).

## 2.1 Example of a Link to a Static Symbol
### 2.1.1 Defining context for the fixed version of function *static_function*:
```c
#include <nsb/vzp.h>
VZP_FILE("foo/bar.c");
static int static_function(int x)
{
    return x + 5;
}
```
### 2.1.2 Link to the variable *static_var*:
```c
#include <nsb/vzp.h>
VZP_FILE("foo/bar.c");
VZP_STATIC_VAR_REF(int, static_var);
int some_function(int a)
{
    return a + static_var;
}
```
Alternatively:
```c
#include <nsb/vzp.h>
VZP_STATIC_VAR_REF(int, static_var, "foo/bar.c");
int some_function(int a)
{
    return a + static_var;
}
```
### 2.1.3 Link to the function *static_func*:
```c
#include <nsb/vzp.h>
VZP_FILE("foo/bar.c");
VZP_STATIC_FUNC_REF(int, static_func, (int));
int some_function(int a)
{
    return a + static_func(a);
}
```
Alternatively:
```c
#include <nsb/vzp.h>
VZP_STATIC_FUNC_REF(int, static_func, (int), "foo/bar.c");
int some_function(int a)
{
    return a + static_func(a);
}
```
## 2.2 Example of a Link to a Hidden Symbol
### 2.2.1 Defining context for the fixed version of function *hidden_function*:
```c
__attribute__ ((visibility ("hidden"))) int hidden_function(int x)
{
    return x + 5;
}
```
### 2.2.2 Link to the variable *hidden_var*:
```c
#include <nsb/vzp.h>
VZP_HIDDEN_VAR_REF(int, hidden_var);
int some_function(int a)
{
    return a + hidden_var;
}
```
### 2.2.3 Link to the function *hidden_func*:
```c
#include <nsb/vzp.h>
VZP_HIDDEN_FUNC_REF(int, hidden_func, (int));
int some_function(int a)
{
    return a + hidden_func(a);
}
```
## 2.3 Example of a Link to a Protected Symbol
### 2.3.1 Defining context for the fixed version of function *protected_function*:
```c
__attribute__ ((visibility ("protected"))) int protected_function(int x)
{
    return x + 5;
}
```
### 2.3.2 Link to the variable *protected_var*:
```c
#include <nsb/vzp.h>
VZP_PROTECTED_VAR_REF(int, protected_var);
int some_function(int a)
{
    return a + protected_var;
}
```
### 2.3.3 Link to the function *protected_func*:
```c
#include <nsb/vzp.h>
VZP_PROTECTED_FUNC_REF(int, protected_func, (int));
int some_function(int a)
{
    return a + protected_func(a);
}
```
## 2.4 Example of a Link to an Internal Symbol
### 2.4.1 Defining context for the internal version of function *internal_function*:
```c
__attribute__ ((visibility ("internal"))) int internal_function(int x)
{
    return x + 5;
}
```
### 2.4.2 Link to the variable *internal_var*:
```c
#include <nsb/vzp.h>
VZP_INTERNAL_VAR_REF(int, internal_var);
int some_function(int a)
{
    return a + internal_var;
}
```
### 2.4.3 Link to the function *internal_func*:
```c
#include <nsb/vzp.h>
VZP_INTERNAL_FUNC_REF(int, internal_func, (int));
int some_function(int a)
{
    return a + internal_func(a);
}
```
## 2.5 Example of a Patch Resolving a Name Conflict
```c
#include <nsb/vzp.h>
int f(void)
{
   VZP_STATIC_VAR_REF(int, var);
   return var++;
}

int g(void)
{
   VZP_STATIC_VAR_REF(int, var_2);
   VZP_STATIC_SYM_ALIAS(var_2, var);
   return var_2--;
}
```
