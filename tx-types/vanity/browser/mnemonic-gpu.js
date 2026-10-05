import { GpuSearch, requestGpuDevice } from "./gpu.js";

export async function mnemonicShaderSource(urls) {
  const files = ["shaders/field.wgsl", "generated/constants.wgsl", "shaders/cheetah.wgsl",
    "shaders/tip5.wgsl", "shaders/encoding.wgsl", "shaders/sha512.wgsl",
    "shaders/fixed-base.wgsl", "shaders/mnemonic.wgsl"];
  return (await Promise.all((urls ?? files).map(async path => {
    const response = await fetch(new URL(path, import.meta.url));
    if (!response.ok) throw new Error(`Cannot load ${path}. Run the browser build first.`);
    return response.text();
  }))).join("\n");
}

export class MnemonicGpuSearch extends GpuSearch {
  static async create({ mnemonicShaderUrls, tableUrl = new URL("./generated/generator-table.bin", import.meta.url) } = {}) {
    const { device, adapterName } = await requestGpuDevice();
    const gpu = new MnemonicGpuSearch(device);
    gpu.adapterName = adapterName;
    try {
      const [code, response] = await Promise.all([mnemonicShaderSource(mnemonicShaderUrls), fetch(tableUrl)]);
      if (!response.ok) throw new Error("Cannot load the generator table. Run the browser build first.");
      const table = await response.arrayBuffer();
      if (table.byteLength !== 64 * 16 * 96) throw new Error("Invalid generator table length.");
      const module = device.createShaderModule({ code });
      const errors = (await module.getCompilationInfo()).messages.filter(m => m.type === "error");
      if (errors.length) throw new Error(errors.map(m => `${m.lineNum}:${m.linePos}: ${m.message}`).join("\n"));
      // One explicit layout lets all four stages share a bind group.
      gpu.layout = device.createBindGroupLayout({ entries: ["read-only-storage", "storage", "read-only-storage", "storage", "read-only-storage"].map((type,binding) => ({
        binding, visibility: GPUShaderStage.COMPUTE, buffer: { type },
      })) });
      const layout = device.createPipelineLayout({ bindGroupLayouts: [gpu.layout] });
      gpu.pipelines = await Promise.all(["mnemonic_init", "mnemonic_pbkdf", "mnemonic_master", "mnemonic_address"].map(entryPoint =>
        device.createComputePipelineAsync({ layout, compute: { module, entryPoint } })));
      gpu.table = device.createBuffer({ size: table.byteLength, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
      device.queue.writeBuffer(gpu.table, 0, table);
      gpu.checkDevice();
      return gpu;
    } catch (error) { gpu.destroy(); throw error; }
  }

  initialize(lanes, masks, prefixLength) {
    this.checkDevice();
    this.releaseBuffers();
    if (!Number.isInteger(lanes) || lanes < 1 || lanes > 4096) throw new Error("Choose 1 to 4096 mnemonic GPU lanes.");
    this.lanes = lanes;
    const secretUsage = GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST;
    this.input = this.buffer(lanes * 128, secretUsage);
    this.states = this.buffer(lanes * 264, secretUsage);
    this.configBuffer = this.buffer(114 * 4, secretUsage);
    this.resultBuffer = this.buffer(lanes * 56, secretUsage | GPUBufferUsage.COPY_SRC);
    this.readback = this.buffer(lanes * 56, GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ);
    this.config = new Uint32Array(114);
    this.config.set([lanes, 0, prefixLength, 0]); this.config.set(masks, 4);
    this.bindGroup = this.device.createBindGroup({ layout: this.layout,
      entries: [this.input, this.states, this.configBuffer, this.resultBuffer, this.table]
        .map((buffer,binding) => ({ binding, resource: { buffer } })),
    });
  }

  // The input contains private HMAC key blocks, never public point data.
  // Copy it into the queue and erase the caller's temporary view immediately.
  async dispatch(inputs) {
    const count = inputs.length / 32;
    try {
      if (!Number.isInteger(count) || count < 1 || count > this.lanes) throw new Error("Invalid mnemonic batch size.");
      this.checkDevice();
      this.device.queue.writeBuffer(this.input, 0, inputs);
    } finally { inputs.fill(0); }
    this.config[0] = count;
    this.device.queue.writeBuffer(this.configBuffer, 0, this.config);
    const commands = this.device.createCommandEncoder();
    const stage = (pipeline) => {
      const pass = commands.beginComputePass();
      pass.setPipeline(pipeline); pass.setBindGroup(0, this.bindGroup);
      pass.dispatchWorkgroups(Math.ceil(count/32)); pass.end();
    };
    stage(this.pipelines[0]);
    for (let chunk = 0; chunk < 16; chunk++) stage(this.pipelines[1]);
    stage(this.pipelines[2]); stage(this.pipelines[3]);
    commands.copyBufferToBuffer(this.resultBuffer, 0, this.readback, 0, count * 56);
    // Clear the secret GPU buffers in queue order before exposing results.
    commands.clearBuffer(this.input); commands.clearBuffer(this.states);
    this.device.queue.submit([commands.finish()]);
    await this.readback.mapAsync(GPUMapMode.READ);
    let words;
    try { words = new Uint32Array(this.readback.getMappedRange()).slice(0, count*14); }
    finally { this.readback.unmap(); }
    this.checkDevice();
    return Array.from({length:count}, (_,lane) => {
      const i = lane*14;
      return { lane, status: words[i], tested: words[i+2], digest: words.slice(i+4,i+14) };
    });
  }

  destroy() { this.table?.destroy(); super.destroy(); }
}
