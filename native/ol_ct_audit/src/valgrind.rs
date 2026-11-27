//! Valgrind client requests, with no dependency on Valgrind's C headers.
//!
//! A client request is the "special instruction preamble" from
//! `valgrind.h`: four rotations of `rdi` totalling 128 bits (an identity)
//! followed by `xchg rbx, rbx` (also an identity). On real hardware the
//! sequence does nothing and `rdx` keeps the default result. Under
//! Valgrind the JIT recognises it, reads the six-word argument block whose
//! address is in `rax`, performs the request and writes the result to
//! `rdx`. That is the documented client-request ABI for amd64 Linux.
//!
//! The request codes are the stable values from `valgrind.h` and
//! `memcheck.h`:
//!
//! | request | value |
//! |---|---|
//! | `RUNNING_ON_VALGRIND` | `0x1001` |
//! | `COUNT_ERRORS` | `0x1201` |
//! | `MAKE_MEM_UNDEFINED` | `VG_USERREQ_TOOL_BASE('M','C') + 1` = `0x4d43_0001` |
//! | `MAKE_MEM_DEFINED` | `VG_USERREQ_TOOL_BASE('M','C') + 2` = `0x4d43_0002` |
//!
//! Marking a secret "undefined" makes Memcheck report every conditional
//! jump and every memory address that depends on it. Arithmetic, moves and
//! `cmov` merely propagate undefinedness without a report. That is exactly
//! the constant-time discipline: no secret-dependent branches, no
//! secret-dependent memory indices. Memcheck does NOT model variable-latency
//! instructions (for example integer division); see the crate docs.

const RUNNING_ON_VALGRIND: usize = 0x1001;
const COUNT_ERRORS: usize = 0x1201;
const MAKE_MEM_UNDEFINED: usize = 0x4d43_0001;
const MAKE_MEM_DEFINED: usize = 0x4d43_0002;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[inline(never)]
fn client_request(default: usize, request: usize, arg1: usize, arg2: usize) -> usize {
    let block: [usize; 6] = [request, arg1, arg2, 0, 0, 0];
    let mut result = default;
    // SAFETY: the instruction sequence is an architectural no-op outside
    // Valgrind (rdi is rotated by 128 bits in total, rbx is exchanged with
    // itself). `rdi` is declared clobbered; flags are clobbered by `rol`
    // (no `preserves_flags`). The block reads the argument array through
    // `rax`, which is why `nomem` is NOT given: the compiler must store
    // `block` before the asm and must not move other memory accesses
    // across it.
    unsafe {
        core::arch::asm!(
            "rol rdi, 3",
            "rol rdi, 13",
            "rol rdi, 61",
            "rol rdi, 51",
            "xchg rbx, rbx",
            inout("rdx") result,
            in("rax") block.as_ptr(),
            out("rdi") _,
            options(nostack),
        );
    }
    result
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
#[inline(never)]
fn client_request(default: usize, request: usize, arg1: usize, arg2: usize) -> usize {
    // No client-request ABI is implemented for this target: behave exactly
    // as native execution does (the default result).
    let _ = (request, arg1, arg2);
    default
}

/// True when this process is running under Valgrind.
pub(crate) fn running_on_valgrind() -> bool {
    client_request(0, RUNNING_ON_VALGRIND, 0, 0) != 0
}

/// Number of errors Valgrind has reported so far (0 natively).
pub(crate) fn error_count() -> usize {
    client_request(0, COUNT_ERRORS, 0, 0)
}

fn byte_span<T: ?Sized>(value: &T) -> (usize, usize) {
    (
        core::ptr::from_ref(value).cast::<u8>() as usize,
        core::mem::size_of_val(value),
    )
}

/// Mark the bytes of `value` as secret: Memcheck will report any branch or
/// memory address computed from them.
///
/// `value` must not contain pointers or references (a secret pointer would
/// make every dereference a false report); callers pass plain byte arrays
/// or structs of byte arrays.
pub(crate) fn mark_secret<T: ?Sized>(value: &T) {
    let (addr, len) = byte_span(value);
    let _ = client_request(0, MAKE_MEM_UNDEFINED, addr, len);
}

/// Mark the bytes of `value` as public again (a declassification).
pub(crate) fn declassify<T: ?Sized>(value: &T) {
    let (addr, len) = byte_span(value);
    let _ = client_request(0, MAKE_MEM_DEFINED, addr, len);
}

/// Declassify a value that legitimately depends on secrets (a result the
/// caller is entitled to see) and return it reloaded from memory, so the
/// returned copy carries the public shadow state.
pub(crate) fn public<T: Copy>(value: T) -> T {
    let slot = [value];
    declassify(&slot);
    // SAFETY: `slot` is a live, aligned, initialised local array of one `T`.
    // The volatile read forces a reload after the declassification request
    // instead of reusing a register copy that still carries secret shadow.
    unsafe { core::ptr::read_volatile(slot.as_ptr()) }
}
