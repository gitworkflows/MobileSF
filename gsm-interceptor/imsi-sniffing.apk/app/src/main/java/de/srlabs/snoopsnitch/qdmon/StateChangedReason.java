package de.srlabs.snoopsnitch.qdmon;

public enum StateChangedReason {
    RECORDING_STATE_CHANGED,
    CATCHER_DETECTED,
    SMS_DETECTED,
    SEC_METRICS_CHANGED,
    ANALYSIS_DONE,
    RAT_CHANGED,
    NO_BASEBAND_DATA
}