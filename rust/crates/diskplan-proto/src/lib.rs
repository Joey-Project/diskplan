#![forbid(unsafe_code)]

pub mod diskplan {
    pub mod v1 {
        include!("generated/diskplan.v1.rs");
    }
}
