// server.rs — 模拟 message-queue-enhance 的 Registry / 状态页 / 会话
//
// 对应修复前 reverse-forwarder-server 的三个锁序来源：
//   1. AppState.registry: Arc<DashMap<u16, Arc<Tunnel>>>
//   2. collect_tunnel_rows: iter() + get(&p).state.read().await (临时 Ref 跨 await)
//   3. session::handle_session(&t, ...): Ref 在整个会话期持有 (跨 await，永不释放)

use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, PartialEq)]
pub enum TunnelState {
    Active,
    Disconnected,
}

pub struct Tunnel {
    pub state: tokio::sync::RwLock<TunnelState>,
    pub tunnel_id: String,
}

pub type Registry = Arc<DashMap<u16, Arc<Tunnel>>>;

pub struct AppState {
    pub registry: Registry,
    pub stop: Arc<AtomicBool>,
    pub epoch_status: Arc<AtomicU64>,
    pub epoch_inner: Arc<AtomicU64>,
}

impl AppState {
    pub fn new(shards: usize, stop: Arc<AtomicBool>) -> Self {
        Self {
            registry: Arc::new(DashMap::with_shard_amount(shards)),
            stop,
            epoch_status: Arc::new(AtomicU64::new(0)),
            epoch_inner: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// 状态页任务: collect_tunnel_rows 原样锁序
///   registry.iter() (分片读锁遍历)
///   → for p: *registry.get(&p).unwrap().state.read().await (临时 Ref 跨 await)
pub fn spawn_status_page(state: &AppState, interval_ms: u64) {
    let s = state.registry.clone();
    let stop = state.stop.clone();
    let ep = state.epoch_status.clone();
    tokio::spawn(async move {
        while !stop.load(Ordering::Relaxed) {
            let mut raw: Vec<u16> = s.iter().map(|e| *e.key()).collect();
            raw.sort();
            for p in raw {
                // 与 status.rs::collect_tunnel_rows 完全一致的锁序：
                // get() 返回 Ref (分片读锁), .state.read() 跨 await 持有 Ref
                let _sc = match *s.get(&p).unwrap().state.read().await {
                    TunnelState::Active => 1,
                    TunnelState::Disconnected => 2,
                };
            }
            ep.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    });
}

/// A 对会话任务: handle_session(&t, ...) 原样锁序
///   registry.get(&port) (Ref = 分片读锁) 在整个会话期持有 (跨 await，永不释放)
///   期间偶发 state.write().await (teardown 路径: shard-读 跨 inner-写)
pub fn spawn_session(state: &AppState, port: u16, tunnel_id: &str) {
    let s = state.registry.clone();
    let stop = state.stop.clone();
    let ep = state.epoch_inner.clone();
    let tid = tunnel_id.to_string();
    tokio::spawn(async move {
        // 注册隧道
        s.insert(port, Arc::new(Tunnel {
            state: tokio::sync::RwLock::new(TunnelState::Active),
            tunnel_id: tid,
        }));
        // handle_new: let t = registry.get(&port)
        let Some(t) = s.get(&port) else { return };
        // handle_session(&t, ...): t (Ref) 持有至会话结束 — 永不 drop
        while !stop.load(Ordering::Relaxed) {
            // session.rs:87: *tunnel.state.write().await = Disconnected
            // (teardown 路径: shard-读锁仍持有，跨 inner-写锁 await)
            {
                let mut st = t.state.write().await;
                *st = if *st == TunnelState::Active {
                    TunnelState::Disconnected
                } else {
                    TunnelState::Active
                };
            }
            ep.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(2 + (port as u64) % 5)).await;
        }
    });
}
