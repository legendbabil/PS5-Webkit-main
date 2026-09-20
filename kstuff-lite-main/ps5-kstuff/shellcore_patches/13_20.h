// 13.20 ShellCore patches - STUB (Option A: no patches without dump)
// TODO: Create real patches after dumping SceShellCore.elf from 13.20 console
// Run this on console to dump: fetch('/system/vsh/SceShellCore.elf').then(r=>r.arrayBuffer()).then(save)
#ifndef SHELLCORE_PATCHES_13_20
#define SHELLCORE_PATCHES_13_20

// Empty retail patches - enables kernel exploit without FPKG mounting
static struct shellcore_patch shellcore_patches_1320_retail[] = {
    // NO PATCHES - Need SceShellCore.elf dump to derive
    // FPKG mounting, debug settings, trophy fixes, etc. disabled
};

// Empty testkit patches
static struct shellcore_patch shellcore_patches_1320_testkit[] = {
    // NO PATCHES
};

// Empty devkit patches
static struct shellcore_patch shellcore_patches_1320_devkit[] = {
    // NO PATCHES
};

#endif // SHELLCORE_PATCHES_13_20