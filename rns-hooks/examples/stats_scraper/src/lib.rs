#![no_std]

use rns_hooks_abi::stats::{PacketStatsPayload, PACKET_STATS_PAYLOAD_TYPE};
use rns_hooks_sdk::context::{self, PacketContext};
use rns_hooks_sdk::host;
use rns_hooks_sdk::result::HookResult;

static mut RESULT: HookResult = HookResult {
    verdict: 0,
    modified_data_offset: 0,
    modified_data_len: 0,
    inject_actions_offset: 0,
    inject_actions_count: 0,
    log_offset: 0,
    log_len: 0,
};

#[no_mangle]
pub extern "C" fn on_hook(ctx_ptr: i32) -> i32 {
    let ptr = ctx_ptr as *const u8;
    if unsafe { context::context_type(ptr) } == context::CTX_TYPE_PACKET {
        let ctx = unsafe { &*(ptr as *const PacketContext) };
        let payload = PacketStatsPayload {
            flags: ctx.flags,
            packet_len: ctx.data_len,
            interface_id: ctx.interface_id,
        }
        .encode();
        let _ = host::emit_event(PACKET_STATS_PAYLOAD_TYPE, &payload);
    }

    unsafe {
        let rptr = &raw mut RESULT;
        rptr.write(HookResult::continue_result());
        rptr as i32
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
