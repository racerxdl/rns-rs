pub use rns_hooks_abi::result::{HookResult, Verdict};

#[derive(Debug, Clone)]
pub struct EmittedProviderEvent {
    pub hook_name: String,
    pub payload_type: String,
    pub payload: Vec<u8>,
}

/// Result of executing a single program or a chain, with owned data extracted
/// from WASM memory before the store is dropped.
#[derive(Debug, Clone)]
pub struct ExecuteResult {
    pub hook_result: Option<HookResult>,
    pub injected_actions: Vec<crate::wire::ActionWire>,
    pub provider_events: Vec<EmittedProviderEvent>,
    pub modified_data: Option<Vec<u8>>,
}
