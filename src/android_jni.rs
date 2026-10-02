use crate::android::{
    ANDROID_DECISION_ABI_VERSION, AndroidConnectivityObservation, AndroidTransport,
    encode_android_decision, evaluate_android_connectivity,
};
use core::ffi::c_void;

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_altru_safetyprotocol_android_SafetyProtocolNative_nativeAbiVersion(
    _env: *mut c_void,
    _class: *mut c_void,
) -> i32 {
    ANDROID_DECISION_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_altru_safetyprotocol_android_SafetyProtocolNative_nativeEvaluateConnectivity(
    _env: *mut c_void,
    _class: *mut c_void,
    transport: i32,
    validated_internet: i32,
    captive_portal: i32,
    protected_tunnel_ready: i32,
    contradictory_evidence: i32,
    hard_drift: i32,
    allow_cellular_fallback: i32,
    remaining_cellular_budget_mb: i64,
) -> i64 {
    let observation = AndroidConnectivityObservation {
        transport: AndroidTransport::from_i32(transport),
        validated_internet: validated_internet != 0,
        captive_portal: captive_portal != 0,
        protected_tunnel_ready: protected_tunnel_ready != 0,
        contradictory_evidence: contradictory_evidence != 0,
        hard_drift: hard_drift != 0,
        allow_cellular_fallback: allow_cellular_fallback != 0,
        remaining_cellular_budget_mb: remaining_cellular_budget_mb.max(0) as u64,
    };

    encode_android_decision(evaluate_android_connectivity(&observation))
}
