#sefi - Search Executable For Instructions
sefi is a library with a command line interface that aims to do
one thing and do it well. You can probably guess what that thing
is from the name.

##overview
sefi implements abstract ROP gadget matching logic and combines
that with a plugin system to integrate disassembler backends.
LLVM, darm, and distorm are the only currently supported backends.
The gadget matching code primarily relies on regular expressions,
but disassembler backends can support richer matching operations
that are more specific to a particular architecture. The sefi
CLI supports specific searches for 'ret' gadgets, gadgets that
jump to a register, gadgets that call a register and regular
expression matches for anything that's not covered by the
previous three.

Though I plan on adding support for other file formats, sefi
currently only supports searching for gadgets in ELF binaries.

##CLI usage
here's an example run of the sefi CLI:
```
$> ./cli --ret /bin/ls
gadgets with unconditional control flow:


gadgets with conditional control flow:


gadgets with no control flow:
------------------------------------------------------------
    00400d29          a26100000000000000     MOV [0x61], AL
    00400d32          0000                   ADD [RAX], AL
    00400d34          0000                   ADD [RAX], AL
    00400d36          0000                   ADD [RAX], AL
    ________________________________________
    00400d38          ca0400                 RETF 0x4
------------------------------------------------------------
    00400d2c          0000                   ADD [RAX], AL
    00400d2e          0000                   ADD [RAX], AL
    00400d30          0000                   ADD [RAX], AL
    00400d32          0000                   ADD [RAX], AL
    00400d34          0000                   ADD [RAX], AL
    00400d36          0000                   ADD [RAX], AL
    ________________________________________
    00400d38          ca0400                 RETF 0x4
------------------------------------------------------------
    00401fe1          0000                   ADD [RAX], AL
    00401fe3          4883c408               ADD RSP, 0x8
    ________________________________________
    00401fe7          c3                     RET
------------------------------------------------------------
    00401fe4          83c408                 ADD ESP, 0x8
    ________________________________________
    00401fe7          c3                     RET

[etc....]
```

The above command searches `/bin/ls` for 'ret' gadgets. By 
default, sefi does not display gadgets that contain control 
flow. Pass the `--uncond-flow` and/or the `--cond-flow` 
flags to see gadgets containing control flow.

##installation
sefi is useless without at least one of the supported
disassembler backends. Install any or all of the following
backends to suit your needs:

 * distorm: sefi can use distorm to search for x86 and
   x86-64 gadgets. You can install distorm via pip by
   running `pip install distorm3`.

 * darm: sefi can use darm to search for ARM gadgets. See
   [darm.re](http://darm.re/) for info on installing the
   python bindings.

 * LLVMPY: sefi can use the python LLVM bindings to search
   for gadgets on x86, x86-64, ARM, and more (any
   target on which LLVM supports disassembling). At the 
   moment installing the python bindings is not trivial
   though. You will need to compile the development version
   of LLVM 3.4 from source and then install 
   [LLVMPY](https://github.com/llvmpy/llvmpy) from source
   (the bindings only support disassembling with LLVM 3.4 
   or higher).

##license
[GPLv3](http://www.gnu.org/licenses/gpl-3.0.html). See LICENSE or the 
given URL for details.  
