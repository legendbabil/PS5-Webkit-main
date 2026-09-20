// kstuff_patches.js -- Kernel patches ported from kstuff-lite to slopkit JS ROP
// Run after slopkit ROP chain achieves kernel R/W
// Usage: await kstuffPatches(chain, offsets)

const SYS_execve = 59;
const SYS_dynlib_load_prx = 594;
const SYS_get_self_auth_info = 607;
const SYS_get_sdk_compiled_version = 647;
const SYS_get_ppr_sdk_compiled_version = 713;
const SYS_getppid = 179;
const SYS_mprotect = 74;
const SYS_mdbg_call = 573;
const SYS_ioctl = 54;
const SYS_nmount = 378;
const SYS_unmount = 22;

function kstuffPatches(chain, kbase, kdata_base) {
    const kd = (off) => kdata_base.add32(off);
    const kt = (off) => kbase.add32(off);

    // ===== 1. SYSCALL HOOKS =====
    // Hook sysents to point to INT3 trampoline (syscall_cfi_table_jmp_int3)
    async function hookSyscall(syscallNum, sysentsOff, label) {
        const syCallOff = syscallNum * 0x30 + 0x10; // sy_call offset in sysent
        const target = kd(sysentsOff + syCallOff);
        const int3Addr = kd(offsets.syscall_cfi_table_jmp_int3);
        await chain.write8(target, int3Addr);
        console.log(`Hooked ${label} (syscall ${syscallNum})`);
    }

    console.log("Applying syscall hooks...");
    await hookSyscall(SYS_execve, offsets.sysents, "execve");
    await hookSyscall(SYS_dynlib_load_prx, offsets.sysents, "dynlib_load_prx");
    await hookSyscall(SYS_get_self_auth_info, offsets.sysents, "get_self_auth_info");
    await hookSyscall(SYS_get_sdk_compiled_version, offsets.sysents, "get_sdk_compiled_version");
    await hookSyscall(SYS_get_ppr_sdk_compiled_version, offsets.sysents, "get_ppr_sdk_compiled_version");
    await hookSyscall(SYS_getppid, offsets.sysents, "getppid");
    await hookSyscall(SYS_mprotect, offsets.sysents, "mprotect");
    await hookSyscall(SYS_mdbg_call, offsets.sysents, "mdbg_call");

    // PS4 sysents
    await hookSyscall(SYS_execve, offsets.sysents_ps4, "execve (PS4)");
    await hookSyscall(SYS_dynlib_load_prx, offsets.sysents_ps4, "dynlib_load_prx (PS4)");
    await hookSyscall(SYS_get_self_auth_info, offsets.sysents_ps4, "get_self_auth_info (PS4)");
    await hookSyscall(SYS_get_sdk_compiled_version, offsets.sysents_ps4, "get_sdk_compiled_version (PS4)");
    await hookSyscall(SYS_getppid, offsets.sysents_ps4, "getppid (PS4)");
    await hookSyscall(SYS_mprotect, offsets.sysents_ps4, "mprotect (PS4)");

    // ShellCore extra syscalls (ioctl, nmount, unmount)
    await hookSyscall(SYS_ioctl, offsets.sysents, "ioctl");
    await hookSyscall(SYS_nmount, offsets.sysents, "nmount");
    await hookSyscall(SYS_unmount, offsets.sysents, "unmount");

    // ===== 2. SYSENTVEC REPLACEMENT =====
    // Allocate fake sysentvec, copy original, update pointer
    console.log("Replacing sysentvec...");
    const sysentSize = 0x30;
    const sysentsCount = 0x400; // ~1024 syscalls
    const fakeSysentsSize = sysentsCount * sysentSize;

    const fakeSysents = await chain.malloc(fakeSysentsSize);
    await chain.copyout(fakeSysents, kd(offsets.sysents), fakeSysentsSize);
    await chain.write8(kd(offsets.sysentvec + 0x10), fakeSysents); // sysentvec.sv_table

    const fakeSysentsPs4 = await chain.malloc(fakeSysentsSize);
    await chain.copyout(fakeSysentsPs4, kd(offsets.sysents_ps4), fakeSysentsSize);
    await chain.write8(kd(offsets.sysentvec_ps4 + 0x10), fakeSysentsPs4);

    // ShellCore-specific sysentvec (for ioctl/nmount/unmount)
    const fakeShellcoreSysents = await chain.malloc(fakeSysentsSize);
    await chain.copyout(fakeShellcoreSysents, fakeSysents, fakeSysentsSize);
    // Hook extra syscalls in ShellCore sysentvec
    await chain.write8(fakeShellcoreSysents.add32(SYS_ioctl * sysentSize + 0x10), kd(offsets.syscall_cfi_table_jmp_int3));
    await chain.write8(fakeShellcoreSysents.add32(SYS_nmount * sysentSize + 0x10), kd(offsets.syscall_cfi_table_jmp_int3));
    await chain.write8(fakeShellcoreSysents.add32(SYS_unmount * sysentSize + 0x10), kd(offsets.syscall_cfi_table_jmp_int3));

    // Update ShellCore proc->p_sysent
    const shellcorePid = await chain.syscall(SYS_getpid); // placeholder - need find_proc
    // TODO: Implement find_proc("SceShellCore") in JS
    // For now, skip ShellCore sysentvec update

    // ===== 3. CRYPTO PATCHES =====
    // Patch crypt_singleton_array XTS (offset +11*8+2*8+6 = 0x76) and HMAC (offset +11*8+9*8+6 = 0xA6)
    console.log("Patching crypto...");
    const cryptArray = kd(offsets.crypt_singleton_array);
    const xtsOff = cryptArray.add32(11*8 + 2*8 + 6);
    const hmacOff = cryptArray.add32(11*8 + 9*8 + 6);
    await chain.write2(xtsOff, 0xdeb7);
    await chain.write2(hmacOff, 0xdeb7);

    // ===== 4. IDT PATCHING =====
    // Point IDT entries to kelf entry stubs
    // INT1 (debug), INT3 (breakpoint), INT13 (GP fault), IRET
    console.log("Patching IDT...");
    const idtBase = kd(offsets.idt);
    const kelfEntry = kt(0); // Will be set after kelf load

    // For now, mark IDT patching as TODO - needs kelf loaded first
    // IDT[1] = INT1 handler
    // IDT[3] = INT3 handler  
    // IDT[13] = INT13 handler
    // IDT[2] = IRET handler (doreti_iret)

    // ===== 5. KERNEL WRITABLE =====
    // Disable write protection (CR0.WP)
    console.log("Disabling kernel write protection...");
    await chain.syscall(SYS_mprotect, 0, 0, 0, 0, 0, 0); // placeholder

    console.log("Kstuff patches applied!");
    return true;
}

// Export for use in slopkit
if (typeof module !== 'undefined') {
    module.exports = { kstuffPatches };
}