use std::time::SystemTime;
use std::cmp::{Ord, Ordering};

#[derive(Eq, Debug, Copy, Clone)]
pub struct RttRecord {
    rto: u64,
    rtt: u32,
    dev: u32,
    last_activity: SystemTime,
}

impl RttRecord {
    pub fn new() -> RttRecord {
        RttRecord {
            rto: 0,
            rtt: 0,
            dev: 0,
            last_activity: SystemTime::now(),
        }
    }

    pub fn update_rto(&mut self) {
        self.rto = self.rtt as u64 + 4 * self.dev as u64;
    }

    pub fn update(&mut self, last_activity: &SystemTime) {
        self.last_activity = last_activity.clone();
        let dt = last_activity.elapsed()
            .map(|d| d.as_secs() as u32 * 1000 + d.subsec_nanos() / 1000000);

        if let Ok(elapsed_ms) = dt {
            let mut rtt = self.rtt as f32;
            let mut dev = self.dev as f32;

            rtt = 0.875 * rtt + 0.125 * elapsed_ms as f32;
            dev = 0.75 * dev + 0.25 * (elapsed_ms as f32 - rtt).abs();

            self.rtt = rtt as u32;
            self.dev = dev as u32;
            self.update_rto();
        }
    }

    pub fn punish(&mut self) {
        let dt = self.last_activity
            .elapsed()
            .map(|d| d.as_secs() as u32 * 1000 + d.subsec_nanos() / 1000000);

        if let Ok(elapsed_ms) = dt {
            // self.dev = 2 * self.dev + elapsed_ms
            let dev = self.dev
                .checked_mul(2)
                .and_then(|d| d.checked_add(elapsed_ms));

            match dev {
                Some(dev) => self.dev = dev,
                None => self.dev = u32::max_value(),
            }
            self.update_rto();
        }
    }
}

impl Ord for RttRecord {
    fn cmp(&self, other: &RttRecord) -> Ordering {
        self.rto.cmp(&other.rto)
    }
}

impl PartialOrd for RttRecord {
    fn partial_cmp(&self, other: &RttRecord) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for RttRecord {
    fn eq(&self, other: &RttRecord) -> bool {
        self.rto == other.rto
    }
}
