use std::sync::{mpsc, Arc, Mutex};
use tx_types::crypto::cheetah_nostd::cheetah_pub_from_sk;
use vanity::{
    encode_pkh, pkh_from_public_key, Match, MatchMode, MatchPosition, Pattern, Zeroizing,
};
use wgpu::util::DeviceExt;

const POINT_WORDS: usize = 26;
const RESULT_WORDS: usize = 14;
const SHADER: &str = concat!(
    include_str!("../../browser/shaders/field.wgsl"),
    "\n",
    include_str!(concat!(env!("OUT_DIR"), "/constants.wgsl")),
    "\n",
    include_str!("../../browser/shaders/cheetah.wgsl"),
    "\n",
    include_str!("../../browser/shaders/tip5.wgsl"),
    "\n",
    include_str!("../../browser/shaders/encoding.wgsl"),
    "\n",
    include_str!("../../browser/shaders/search.wgsl")
);

pub fn adapters() -> Vec<wgpu::Adapter> {
    wgpu::Instance::new(&wgpu::InstanceDescriptor {
        backends: wgpu::Backends::VULKAN,
        ..Default::default()
    })
    .enumerate_adapters(wgpu::Backends::VULKAN)
}

fn bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

pub fn offset_key(seed: &[u8; 32], offset: u32) -> Option<Zeroizing<[u8; 32]>> {
    use tx_types::crypto::utils_nostd::{be32_lt, is_zero32, CHEETAH_N};
    let mut key = Zeroizing::new(*seed);
    let mut carry = offset as u64;
    for byte in key.iter_mut().rev() {
        carry += *byte as u64;
        *byte = carry as u8;
        carry >>= 8;
    }
    (carry == 0 && !is_zero32(&key) && be32_lt(&key, &CHEETAH_N)).then_some(key)
}

#[derive(Debug)]
pub struct Candidate {
    pub lane: usize,
    pub status: u32,
    pub offset: u32,
    pub tested: u32,
    pub digest: [u64; 5],
}

/// Recompute a winning scalar, point, hash and prefix independently of the GPU.
pub fn verify(seed: &[u8; 32], candidate: &Candidate, prefix: &Pattern) -> Result<Match, String> {
    let key = offset_key(seed, candidate.offset).ok_or("GPU returned an invalid key offset")?;
    let public_key = cheetah_pub_from_sk(*key);
    let pkh = pkh_from_public_key(&public_key);
    if candidate.status != 1 || pkh != candidate.digest || !prefix.matches(&encode_pkh(pkh)) {
        return Err("GPU match failed independent Rust verification; no key is saved".into());
    }
    Ok(Match {
        secret_key_be: key,
        public_key,
        pkh,
    })
}

pub struct Gpu {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    error: Arc<Mutex<Option<String>>>,
}

pub struct Buffers {
    points: wgpu::Buffer,
    config: wgpu::Buffer,
    results: wgpu::Buffer,
    readback: wgpu::Buffer,
    bindings: wgpu::BindGroup,
    settings: [u32; 114],
    lanes: u32,
}

impl Drop for Buffers {
    fn drop(&mut self) {
        self.points.destroy();
        self.config.destroy();
        self.results.destroy();
        self.readback.destroy();
    }
}

impl Gpu {
    pub fn new(adapter: &wgpu::Adapter) -> Result<Self, String> {
        let (device, queue) = pollster::block_on(adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: Some("Nockchain address generator"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::default(),
                memory_hints: wgpu::MemoryHints::Performance,
            },
            None,
        ))
        .map_err(|e| format!("Cannot initialize Vulkan device: {e}"))?;
        let error = Arc::new(Mutex::new(None));
        let errors = error.clone();
        device.on_uncaptured_error(Box::new(move |e| {
            *errors.lock().unwrap() = Some(format!("GPU error: {e}"))
        }));
        let errors = error.clone();
        device.set_device_lost_callback(move |reason, message| {
            *errors.lock().unwrap() = Some(format!("GPU device lost ({reason:?}): {message}"));
        });
        device.push_error_scope(wgpu::ErrorFilter::Validation);
        let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("Shared vanity WGSL"),
            source: wgpu::ShaderSource::Wgsl(SHADER.into()),
        });
        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Address generation"),
            layout: None,
            module: &module,
            entry_point: Some("mine"),
            compilation_options: Default::default(),
            cache: None,
        });
        if let Some(error) = pollster::block_on(device.pop_error_scope()) {
            return Err(format!("Cannot compile GPU shader: {error}"));
        }
        let gpu = Self {
            device,
            queue,
            pipeline,
            error,
        };
        gpu.check()?;
        Ok(gpu)
    }

    fn check(&self) -> Result<(), String> {
        match &*self.error.lock().unwrap() {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    pub fn initialize(
        &self,
        seeds: &[Zeroizing<[u8; 32]>],
        prefix: &Pattern,
    ) -> Result<Buffers, String> {
        self.check()?;
        if seeds.is_empty() || seeds.len() > 65536 {
            return Err("Use 1–65536 GPU lanes".into());
        }
        let mut points = Vec::with_capacity(seeds.len() * POINT_WORDS);
        for seed in seeds {
            let (x, y) = cheetah_pub_from_sk(**seed);
            for word in x.into_iter().chain(y) {
                points.extend_from_slice(&[word as u32, (word >> 32) as u32]);
            }
            points.extend_from_slice(&[0, 0]);
        }
        let mut settings = [0u32; 114];
        settings[0] = seeds.len() as u32;
        settings[3] = prefix.position() as u32;
        for (i, mask) in prefix.digit_masks().iter().enumerate() {
            if *mask != [0, 0] {
                settings[2] += 1;
            }
            settings[4 + i * 2..6 + i * 2].copy_from_slice(mask);
        }
        let points = self
            .device
            .create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("Public starting points"),
                contents: &bytes(&points),
                usage: wgpu::BufferUsages::STORAGE,
            });
        let config = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("Search settings"),
            size: 114 * 4,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let result_size = (seeds.len() * RESULT_WORDS * 4) as u64;
        let results = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("Public candidate results"),
            size: result_size,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let readback = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("Candidate readback"),
            size: result_size,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let bindings = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Generator buffers"),
            layout: &self.pipeline.get_bind_group_layout(0),
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: points.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: config.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: results.as_entire_binding(),
                },
            ],
        });
        Ok(Buffers {
            points,
            config,
            results,
            readback,
            bindings,
            settings,
            lanes: seeds.len() as u32,
        })
    }

    pub fn dispatch(
        &self,
        buffers: &mut Buffers,
        active: u32,
        steps: u32,
    ) -> Result<Vec<Candidate>, String> {
        self.check()?;
        if active == 0 || active > buffers.lanes || !(1..=16).contains(&steps) {
            return Err("Invalid GPU batch dimensions".into());
        }
        buffers.settings[0] = active;
        buffers.settings[1] = steps;
        self.queue
            .write_buffer(&buffers.config, 0, &bytes(&buffers.settings));
        let mut encoder = self.device.create_command_encoder(&Default::default());
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("Generate addresses"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &buffers.bindings, &[]);
            pass.dispatch_workgroups(active.div_ceil(32), 1, 1);
        }
        let size = u64::from(active) * RESULT_WORDS as u64 * 4;
        encoder.copy_buffer_to_buffer(&buffers.results, 0, &buffers.readback, 0, size);
        let submission = self.queue.submit([encoder.finish()]);
        let slice = buffers.readback.slice(..size);
        let (send, receive) = mpsc::sync_channel(1);
        slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = send.send(result);
        });
        self.device
            .poll(wgpu::Maintain::WaitForSubmissionIndex(submission));
        receive
            .recv()
            .map_err(|_| "GPU readback callback disconnected")?
            .map_err(|e| format!("GPU readback failed: {e}"))?;
        let data = slice.get_mapped_range();
        let results = data
            .chunks_exact(RESULT_WORDS * 4)
            .enumerate()
            .map(|(lane, record)| {
                let words: Vec<u32> = record
                    .chunks_exact(4)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                    .collect();
                Candidate {
                    lane,
                    status: words[0],
                    offset: words[1],
                    tested: words[2],
                    digest: std::array::from_fn(|i| {
                        words[4 + i * 2] as u64 | ((words[5 + i * 2] as u64) << 32)
                    }),
                }
            })
            .collect();
        drop(data);
        buffers.readback.unmap();
        self.check()?;
        Ok(results)
    }

    pub fn self_test(&self) -> Result<(), String> {
        let mut one = Zeroizing::new([0; 32]);
        one[31] = 1;
        let seeds = [one, Zeroizing::new([0x35; 32])];
        let mut buffers =
            self.initialize(&seeds, &Pattern::new("1", MatchPosition::Prefix).unwrap())?;
        for batch in 0..2 {
            for result in self.dispatch(&mut buffers, 2, 2)? {
                let scalar = offset_key(&seeds[result.lane], batch * 2 + 1).unwrap();
                let digest = pkh_from_public_key(&cheetah_pub_from_sk(*scalar));
                if result.status != 0
                    || result.tested != 2
                    || result.offset != batch * 2 + 1
                    || result.digest != digest
                {
                    return Err(
                        "GPU self-test failed: candidate counters or PKH differ from Rust".into(),
                    );
                }
            }
        }
        let key = offset_key(&seeds[0], 1).unwrap();
        let address = encode_pkh(pkh_from_public_key(&cheetah_pub_from_sk(*key)));
        let insensitive: String = address
            .as_str()
            .to_ascii_lowercase()
            .chars()
            .map(|c| match c {
                's' => '5',
                'a' => '4',
                'e' => '3',
                'i' | 'l' => '1',
                'o' => '0',
                't' => '7',
                'b' => '8',
                'z' => '2',
                c => c,
            })
            .collect();
        for prefix in [
            Pattern::new(address.as_str(), MatchPosition::Prefix).unwrap(),
            Pattern::with_mode(&insensitive, MatchPosition::Prefix, MatchMode::Insensitive)
                .unwrap(),
        ] {
            let mut buffers = self.initialize(&seeds, &prefix)?;
            let results = self.dispatch(&mut buffers, 1, 2)?;
            if results.len() != 1 || results[0].offset != 1 || results[0].tested != 2 {
                return Err("GPU self-test failed: partial batch or prefix match".into());
            }
            verify(&seeds[0], &results[0], &prefix)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn false_gpu_match_never_exports_a_key() {
        let mut seed = [0; 32];
        seed[31] = 1;
        let key = offset_key(&seed, 1).unwrap();
        let digest = pkh_from_public_key(&cheetah_pub_from_sk(*key));
        let prefix = Pattern::new(encode_pkh(digest).as_str(), MatchPosition::Prefix).unwrap();
        let mut candidate = Candidate {
            lane: 0,
            status: 1,
            offset: 1,
            tested: 2,
            digest,
        };
        assert!(verify(&seed, &candidate, &prefix).is_ok());
        candidate.digest[0] ^= 1;
        assert!(verify(&seed, &candidate, &prefix).is_err());
        candidate.digest = digest;
        assert!(verify(
            &seed,
            &candidate,
            &Pattern::new("1", MatchPosition::Prefix).unwrap()
        )
        .is_err());
        assert!(offset_key(&[255; 32], 1).is_none());
        assert!(offset_key(&[0; 32], 0).is_none());
    }
}
