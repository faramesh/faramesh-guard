//! Hot Path Benchmarks
//!
//! Measures performance of security-critical operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use guard_core::{
    car::{CarHasher, CarRequest},
    cache::DecisionCache,
    permit::PermitVerifier,
    replay::ReplayDetector,
    Decision,
};

fn bench_car_hashing(c: &mut Criterion) {
    let hasher = CarHasher::new();
    let car = CarRequest {
        action_type: "shell_execute".to_string(),
        resource: "ls -la /home/user".to_string(),
        agent_id: "agent-12345".to_string(),
        parameters: Some(serde_json::json!({"cwd": "/tmp"})),
        context: Some(serde_json::json!({"session": "abc123"})),
    };

    let mut group = c.benchmark_group("car_hashing");
    group.throughput(Throughput::Elements(1));

    group.bench_function("hash_car_struct", |b| {
        b.iter(|| {
            black_box(hasher.hash_car(&car).unwrap())
        })
    });

    let json_str = serde_json::to_string(&car).unwrap();
    group.bench_function("hash_car_string", |b| {
        b.iter(|| {
            black_box(hasher.hash_str(&json_str).unwrap())
        })
    });

    group.finish();
}

fn bench_cache_operations(c: &mut Criterion) {
    let cache = DecisionCache::new(10000, 300);

    // Pre-populate cache
    for i in 0..1000 {
        cache.put(&format!("sha256:hash{:04}", i), Decision::Allow, 0.95, None);
    }

    let mut group = c.benchmark_group("cache");
    group.throughput(Throughput::Elements(1));

    group.bench_function("cache_hit", |b| {
        b.iter(|| {
            black_box(cache.get("sha256:hash0500"))
        })
    });

    group.bench_function("cache_miss", |b| {
        b.iter(|| {
            black_box(cache.get("sha256:nonexistent"))
        })
    });

    group.bench_function("cache_put", |b| {
        let mut i = 2000u64;
        b.iter(|| {
            cache.put(&format!("sha256:new{}", i), Decision::Allow, 0.95, None);
            i += 1;
        })
    });

    group.finish();
}

fn bench_permit_verification(c: &mut Criterion) {
    let verifier = PermitVerifier::new(b"benchmark-secret-key-32-bytes!!");
    let permit = verifier.create_permit(
        "sha256:test123".to_string(),
        Decision::Allow,
        0.95,
        "benchmark".to_string(),
        300,
    );

    let mut group = c.benchmark_group("permit");
    group.throughput(Throughput::Elements(1));

    group.bench_function("verify_permit", |b| {
        b.iter(|| {
            black_box(verifier.verify(&permit).unwrap())
        })
    });

    group.bench_function("create_permit", |b| {
        b.iter(|| {
            black_box(verifier.create_permit(
                "sha256:test123".to_string(),
                Decision::Allow,
                0.95,
                "benchmark".to_string(),
                300,
            ))
        })
    });

    group.finish();
}

fn bench_replay_detection(c: &mut Criterion) {
    let detector = ReplayDetector::new(100000, 300);

    // Pre-populate
    for i in 0..10000 {
        detector.register(&format!("nonce-{:06}", i));
    }

    let mut group = c.benchmark_group("replay");
    group.throughput(Throughput::Elements(1));

    group.bench_function("check_known", |b| {
        b.iter(|| {
            black_box(detector.check("nonce-005000"))
        })
    });

    group.bench_function("check_unknown", |b| {
        b.iter(|| {
            black_box(detector.check("nonce-unknown"))
        })
    });

    group.bench_function("register_new", |b| {
        let mut i = 20000u64;
        b.iter(|| {
            detector.register(&format!("nonce-new-{}", i));
            i += 1;
        })
    });

    group.finish();
}

fn bench_full_gate_check(c: &mut Criterion) {
    use guard_core::ipc::{GuardCore, IpcRequest};

    let core = GuardCore::new(b"benchmark-secret-key-32-bytes!!");
    let runtime = tokio::runtime::Runtime::new().unwrap();

    // Create a permit for cached path
    let permit = core.permit_verifier.create_permit(
        "sha256:cached123".to_string(),
        Decision::Allow,
        0.95,
        "benchmark".to_string(),
        300,
    );
    core.cache.put("sha256:cached123", Decision::Allow, 0.95, None);

    let mut group = c.benchmark_group("gate_check");
    group.throughput(Throughput::Elements(1));

    // Cached path (fastest)
    group.bench_function("cache_hit_path", |b| {
        b.iter(|| {
            let request = IpcRequest {
                jsonrpc: "2.0".to_string(),
                id: Some(1),
                method: "gate_check".to_string(),
                params: serde_json::json!({
                    "car": {
                        "action_type": "file_read",
                        "resource": "/tmp/cached.txt",
                        "agent_id": "agent1"
                    }
                }),
            };
            // Pre-cache this CAR
            let hash = core.car_hasher.hash_value(&request.params.get("car").unwrap()).unwrap();
            core.cache.put(&hash, Decision::Allow, 0.95, None);
            runtime.block_on(async {
                black_box(core.handle_request(request).await)
            })
        })
    });

    // Cold path (no cache, no permit)
    group.bench_function("cold_path", |b| {
        let mut i = 0u64;
        b.iter(|| {
            let request = IpcRequest {
                jsonrpc: "2.0".to_string(),
                id: Some(1),
                method: "gate_check".to_string(),
                params: serde_json::json!({
                    "car": {
                        "action_type": "file_read",
                        "resource": format!("/tmp/cold_{}.txt", i),
                        "agent_id": "agent1"
                    }
                }),
            };
            i += 1;
            runtime.block_on(async {
                black_box(core.handle_request(request).await)
            })
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_car_hashing,
    bench_cache_operations,
    bench_permit_verification,
    bench_replay_detection,
    bench_full_gate_check,
);

criterion_main!(benches);
