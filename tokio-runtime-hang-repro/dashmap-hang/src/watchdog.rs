// watchdog.rs — 冻结检测 + wchan/gdb 取证
//
// 对应博客排查的取证步骤：
//   第三步: /proc/<pid>/task/*/wchan 分布 (区分 futex_wait_queue vs do_epoll_wait)
//   第四步: gcore/gdb 全栈 (dashmap::lock::RawRwLock::lock_exclusive_slow)

use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub struct Watchdog {
    pub epoch_status: Arc<AtomicU64>,
    pub epoch_writer: Arc<AtomicU64>,
    pub epoch_inner: Arc<AtomicU64>,
    pub stop: Arc<AtomicBool>,
}

impl Watchdog {
    /// 监控 3 路进度, 写者 5s 无进展 → HANG (insert 永久卡死)
    pub async fn run(&self, max_secs: u64) {
        let mut last = (0, 0, 0);
        for i in 0..max_secs {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let cur = (
                self.epoch_status.load(Ordering::Relaxed),
                self.epoch_writer.load(Ordering::Relaxed),
                self.epoch_inner.load(Ordering::Relaxed),
            );
            if i % 5 == 0 {
                println!("[{i}s] status={} writer={} inner={}", cur.0, cur.1, cur.2);
            }
            // 冻结判定: 全停 或 写者卡死 (writer=0 持续 5s)
            if (i >= 2 && cur == last) || (i >= 5 && cur.1 == 0 && last.1 == 0) {
                let what = if i >= 5 && cur.1 == 0 {
                    format!(
                        "HANG: insert() 永久卡死, writer=0 (status={} inner={} 仍活)",
                        cur.0, cur.2
                    )
                } else {
                    "FROZEN: 全部进度 5s 无变化".to_string()
                };
                println!("{what}");
                dump_threads();
                try_gdb();
                println!("sleeping 8s for manual gdb -p <pid={}>", std::process::id());
                tokio::time::sleep(Duration::from_secs(8)).await;
                std::process::exit(42);
            }
            last = cur;
        }
        self.stop.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(2)).await;
        println!("done (no freeze)");
    }
}

/// 第三步: wchan 分布 — 看"线程在等什么"
fn dump_threads() {
    let entries = std::fs::read_dir(format!("/proc/{}/task", std::process::id()))
        .map(|d| d.map(|e| e.unwrap().file_name()).collect::<Vec<_>>())
        .unwrap_or_default();
    println!("--- /proc/self/task/wchan ---");
    for e in &entries {
        if let Ok(s) = std::fs::read_to_string(format!(
            "/proc/{}/task/{}/wchan",
            std::process::id(),
            e.to_string_lossy()
        )) {
            let name = std::fs::read_to_string(format!(
                "/proc/{}/task/{}/comm",
                std::process::id(),
                e.to_string_lossy()
            ))
            .unwrap_or_default();
            println!("{} {}: {}", e.to_string_lossy(), name.trim(), s.trim());
        }
    }
}

/// 第四步: gdb 全栈 — 锁死锁 vs 调度睡死
fn try_gdb() {
    let pid = std::process::id().to_string();
    let out = Command::new("bash")
        .args([
            "-lc",
            &format!(
                "command -v gdb >/dev/null && gdb -p {} -batch -ex 'thread apply all bt 10' 2>&1 || echo '(gdb unavailable / ptrace denied)'",
                pid
            ),
        ])
        .output();
    match out {
        Ok(o) => println!("--- gdb ---\n{}", String::from_utf8_lossy(&o.stdout)),
        Err(e) => println!("gdb skipped: {e}"),
    }
}
