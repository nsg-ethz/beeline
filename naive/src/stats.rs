use std::sync::atomic::AtomicU64;

pub static PARSE_COUNT: AtomicU64 = AtomicU64::new(0);
pub static PARSE_TOTAL: AtomicU64 = AtomicU64::new(0);

pub static OTHER_COUNT: AtomicU64 = AtomicU64::new(0);
pub static OTHER_TOTAL: AtomicU64 = AtomicU64::new(0);

pub fn print() {
    println!(
        "parse total: {:?} nsecs, count: {:?}",
        PARSE_TOTAL, PARSE_COUNT
    );
    println!(
        "other total: {:?} nsecs, count: {:?}",
        OTHER_TOTAL, OTHER_COUNT
    );
}
