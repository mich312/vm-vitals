//! Host metrics via `sysinfo`: CPU, memory, swap, disk (`/`), load, uptime.

use serde::Serialize;
use sysinfo::{Disks, System};

#[derive(Debug, Clone, Serialize)]
pub struct HostMetrics {
    pub hostname: String,
    pub cpu_pct: f32,
    pub mem_total_mb: u64,
    pub mem_avail_mb: u64,
    pub mem_used_pct: f32,
    pub swap_used_mb: u64,
    pub disk_total_gb: f64,
    pub disk_avail_gb: f64,
    pub disk_used_pct: f32,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub uptime_secs: u64,
}

/// Keeps a `System` between ticks so CPU usage is measured over the interval.
pub struct HostCollector {
    sys: System,
}

impl HostCollector {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Self { sys }
    }

    pub fn collect(&mut self) -> HostMetrics {
        self.sys.refresh_cpu_all();
        self.sys.refresh_memory();

        let cpu_pct = self.sys.global_cpu_usage();

        let mem_total = self.sys.total_memory(); // bytes
        let mem_avail = self.sys.available_memory();
        let mem_used_pct = if mem_total > 0 {
            ((mem_total - mem_avail) as f32 / mem_total as f32) * 100.0
        } else {
            0.0
        };

        // Disk for `/`.
        let disks = Disks::new_with_refreshed_list();
        let root = disks
            .iter()
            .find(|d| d.mount_point() == std::path::Path::new("/"));
        let (disk_total, disk_avail) = root
            .map(|d| (d.total_space(), d.available_space()))
            .unwrap_or((0, 0));
        let disk_used_pct = if disk_total > 0 {
            ((disk_total - disk_avail) as f32 / disk_total as f32) * 100.0
        } else {
            0.0
        };

        let la = System::load_average();

        HostMetrics {
            hostname: System::host_name().unwrap_or_else(|| "host".to_string()),
            cpu_pct,
            mem_total_mb: mem_total / 1_000_000,
            mem_avail_mb: mem_avail / 1_000_000,
            mem_used_pct,
            swap_used_mb: self.sys.used_swap() / 1_000_000,
            disk_total_gb: disk_total as f64 / 1e9,
            disk_avail_gb: disk_avail as f64 / 1e9,
            disk_used_pct,
            load1: la.one,
            load5: la.five,
            load15: la.fifteen,
            uptime_secs: System::uptime(),
        }
    }
}
