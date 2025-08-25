use protocol_prototype::benchmark::benchmark_perform_action;
use criterion::criterion_group;
use criterion::criterion_main;

criterion_group!(benches, benchmark_perform_action);
criterion_main!(benches);