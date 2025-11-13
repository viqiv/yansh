use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

static mut HEAP_MEMORY: [u8; 1024 * 1024] = [0; 1024 * 1024];

#[no_mangle]
pub extern "C" fn init() {
    unsafe {
        ALLOCATOR
            .lock()
            .init(HEAP_MEMORY.as_mut_ptr(), HEAP_MEMORY.len());
    }
}
