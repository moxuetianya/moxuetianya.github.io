// client.rs — 模拟 reverse-forwarder-client 的 A 对存活 + B 对并发注册
//
// 对应 ws_handler 的两个锁序来源：
//   1. A 对存活: session::handle_session 持有 Ref 整个会话期 (由 server::spawn_session 实现)
//   2. B 对注册: 两个并发任务 get → drop → insert (同分片)
//      每个写者先 get(p) (读) 再 insert(p) (写), Barrier 保证同时性

use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::server::Tunnel;

/// B 对注册: 每轮两个并发任务 get → drop → insert (ws_handler 原样)
///   Barrier 保证两个写者同时开始 (模拟生产"两个 WS 连接同毫秒到达")
pub fn spawn_registration_burst(
    registry: Arc<DashMap<u16, Arc<Tunnel>>>,
    ports: Vec<u16>,
    rounds: u64,
    stop: Arc<AtomicBool>,
    epoch_writer: Arc<AtomicU64>,
) {
    tokio::spawn(async move {
        for round_n in 0..rounds {
            let p1 = ports[(round_n as usize + 2) % ports.len()];
            let p2 = ports[(round_n as usize + 3) % ports.len()];
            let barrier = Arc::new(tokio::sync::Barrier::new(2));

            // 两个写者任务同时开始 (模拟 agent + vscode 两条隧道同毫秒注册)
            let w1 = tokio::spawn({
                let (s, ep, b) = (registry.clone(), epoch_writer.clone(), barrier.clone());
                async move {
                    b.wait().await;
                    // ws_handler: let existing = state.registry.get(&remote_port);
                    let _e = s.get(&p1);
                    drop(_e);
                    // ws_handler: state.registry.insert(remote_port, t);
                    s.insert(p1, Arc::new(Tunnel {
                        state: tokio::sync::RwLock::new(crate::server::TunnelState::Active),
                        tunnel_id: format!("b{round_n}a"),
                    }));
                    ep.fetch_add(1, Ordering::Relaxed);
                }
            });
            let w2 = tokio::spawn({
                let (s, ep, b) = (registry.clone(), epoch_writer.clone(), barrier.clone());
                async move {
                    b.wait().await;
                    let _e = s.get(&p2);
                    drop(_e);
                    s.insert(p2, Arc::new(Tunnel {
                        state: tokio::sync::RwLock::new(crate::server::TunnelState::Active),
                        tunnel_id: format!("b{round_n}b"),
                    }));
                    ep.fetch_add(1, Ordering::Relaxed);
                }
            });

            let _ = (w1.await, w2.await);

            // 模拟 7-12s 的重试间隔 (与 repro8.sh 一致)
            tokio::time::sleep(Duration::from_millis(rand_ms())).await;
            if stop.load(Ordering::Relaxed) {
                break;
            }
        }
    });
}

fn rand_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
    7000 + (ns % 5000) as u64
}
