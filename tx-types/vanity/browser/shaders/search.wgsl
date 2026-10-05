@group(0) @binding(0) var<storage, read_write> points: array<Point>;
@group(0) @binding(1) var<storage, read> config: array<u32>;
@group(0) @binding(2) var<storage, read_write> results: array<Result>;

@compute @workgroup_size(32)
fn mine(@builtin(global_invocation_id) id: vec3<u32>) {
    let lane = id.x;
    if lane >= config[0] { return; }
    var point = points[lane];
    var result: Result;
    for (var step = 0u; step < config[1]; step++) {
        if point.offset == 0xffffffffu { result.found = 2u; break; }
        result.digest = hash_point(point);
        result.offset = point.offset;
        result.tested++;
        if prefix_matches(result.digest) {
            result.found = 1u;
            break;
        }
        point = advance(point);
    }
    points[lane] = point;
    results[lane] = result;
}
