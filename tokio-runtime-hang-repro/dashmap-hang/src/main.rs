// dashmap-hang: 最小复现样本 — 对齐生产真实锁序 (tokio multi_thread + dashmap 6.2.1)
//
// 结构对应修复前 message-queue-enhance / reverse-forwarder-server:
//   server.rs  → AppState + 状态页 + A 对会话 (Ref 跨整个会话期持有)
//   client.rs  → B 对并发注册 (get → drop → insert, Barrier 同时性)
//   watchdog.rs → 进度监控 + wchan/gdb 取证 + exit 42
//
// 用法: dashmap-hang [rounds] [status_ms]     默认: 12 250

mod client;
mod server;
mod watchdog;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

fn shard_of(map: &server::Registry, k: &u16) -> usize {
    map.determine_shard(map.hash_usize(k))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let mut args = std::env::args().skip(1).map(|a| a.parse().unwrap_or(0));
    let rounds: u64 = args.next().unwrap_or(12).max(1);
    let status_ms: u64 = args.next().unwrap_or(250).max(50);

    // 显式 4 分片 (DashMap::new() 默认 = (核数×4).next_power_of_two())
    let stop = Arc::new(AtomicBool::new(false));
    let state = server::AppState::new(4, stop.clone());
    let epoch_writer = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // 同分片端口集 (A 对 + B 对每轮 +1, 全部落一个分片 → 碰撞概率 100%)
    let mut ports: Vec<u16> = Vec::new();
    for k in 1..40u16 {
        for i in 0..(rounds as u16 + 2) {
            ports.push(3000 + k * 100 + i);
        }
    }
    let sref = shard_of(&state.registry, &ports[0]);
    ports.retain(|p| shard_of(&state.registry, p) == sref);
    assert!(ports.len() >= rounds as usize + 4, "same-shard ports {} ", ports.len());
    let (pa, pb) = (ports[0], ports[1]);
    println!("shard={} 同分片端口={}个 A对={pa},{pb}", sref, ports.len());

    // === server: 状态页 + A 对会话 (Ref 跨整个会话期持有) ===
    server::spawn_status_page(&state, status_ms);
    server::spawn_session(&state, pa, "A1");
    server::spawn_session(&state, pb, "A2");

    // === client: B 对并发注册 (Barrier 同时性) ===
    client::spawn_registration_burst(
        state.registry.clone(),
        ports,
        rounds,
        stop.clone(),
        epoch_writer.clone(),
    );

    // === watchdog: 写者 5s 无进展 → HANG (insert 永久卡死) ===
    let wd = watchdog::Watchdog {
        epoch_status: state.epoch_status.clone(),
        epoch_writer: epoch_writer.clone(),
        epoch_inner: state.epoch_inner.clone(),
        stop: stop.clone(),
    };
    wd.run(400).await;
}
