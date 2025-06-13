use crate::utils::page_size;
use anyhow::{Result, anyhow};
use memmap2::{MmapMut, MmapOptions};
use nix::libc::{PROT_NONE, mprotect};

/// A (mmap'ed) stack allocation with a guard page.
pub struct GuardedStack {
    _mmap: MmapMut,
    stack: *mut u8,
    size: usize,
}

impl GuardedStack {
    /// Create a new instance of `GuardedStack`
    pub fn new(stack_size: usize) -> Result<Self> {
        let page_size = page_size()?;

        if stack_size == 0 || stack_size % page_size != 0 {
            return Err(anyhow!(
                "stack_size must be a non-zero multiple of the system page size ({} bytes)",
                page_size
            ));
        }

        let total_size = stack_size
            .checked_add(page_size)
            .ok_or_else(|| anyhow!("stack_size + guard page overflows usize"))?;

        let mut mmap = MmapOptions::new().len(total_size).map_anon()?;
        let base_ptr = mmap.as_mut_ptr();

        let guard_addr = unsafe { base_ptr.add(stack_size) };

        // SAFETY:
        // - guard_addr is page-aligned and within bounds.
        // - `page_size` is guaranteed to be a page multiple.
        // - `mmap` owns the memory.
        let ret = unsafe { mprotect(guard_addr.cast(), page_size, PROT_NONE) };
        if ret != 0 {
            return Err(anyhow!(
                "Failed to set guard page protection: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(Self {
            _mmap: mmap,
            stack: base_ptr,
            size: stack_size,
        })
    }

    /// Returns a mutable slice to the stack memory.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY:
        // - `stack` is offset beyond the guard page and points to `size` valid bytes.
        // - A single mutable reference is created, single-threaded runtime.
        unsafe { std::slice::from_raw_parts_mut(self.stack, self.size) }
    }
}
