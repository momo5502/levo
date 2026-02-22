# LEVO

<a href="https://github.com/momo5502/levo?tab=GPL-3.0-1-ov-file.0-1-ov-file"><img src="https://img.shields.io/github/license/momo5502/levo?color=00B0F8"/></a>
<a href="https://github.com/momo5502/levo/actions"><img src="https://img.shields.io/github/actions/workflow/status/momo5502/levo/build.yml?branch=main&label=build"/></a>
<a href="https://github.com/momo5502/levo/issues"><img src="https://img.shields.io/github/issues/momo5502/levo?color=F8B000"/></a>
<img src="https://img.shields.io/github/commit-activity/m/momo5502/levo?color=FF3131"/>  

Levo is an ahead-of-time binary translation toolchain.

> [!NOTE]  
> It is extremely experimental and barely supports anything.  
> It started as a weekend side project. We will see if this ever reaches a state beyond that.

## Pipeline
- Control flow recovery using [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- Binary lifting using [Remill](https://github.com/lifting-bits/remill)
- Target independent recompilation using [LLVM](https://github.com/llvm/llvm-project)
