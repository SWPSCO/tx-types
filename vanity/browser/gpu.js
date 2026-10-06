const POINT_WORDS = 26;
const RESULT_WORDS = 14;

export class WebGpuUnavailableError extends Error {}

export async function requestGpuDevice() {
  if (!navigator.gpu) throw new WebGpuUnavailableError("This browser does not expose WebGPU.");
  try {
    let adapter = await navigator.gpu.requestAdapter({ powerPreference: "high-performance" });
    if (!adapter) adapter = await navigator.gpu.requestAdapter();
    if (!adapter) throw new Error("No WebGPU adapter is available.");
    const device = await adapter.requestDevice();
    const info = adapter.info;
    return { device, adapterName: info?.description || info?.device || info?.architecture || "WebGPU adapter" };
  } catch (error) { throw new WebGpuUnavailableError(`WebGPU could not initialize: ${error.message}`); }
}

function compilationUnavailable(cause) {
  return new WebGpuUnavailableError(
    "This GPU cannot compile the mining shaders. Using CPU / WASM.",
    { cause },
  );
}

export async function compileShader(device, code) {
  try {
    const module = device.createShaderModule({ code });
    const errors = (await module.getCompilationInfo()).messages.filter(message => message.type === "error");
    if (errors.length) throw new Error(errors.map(message => `${message.lineNum}:${message.linePos}: ${message.message}`).join("\n"));
    return module;
  } catch (error) { throw compilationUnavailable(error); }
}

export async function compilePipeline(device, descriptor) {
  try { return await device.createComputePipelineAsync(descriptor); }
  catch (error) { throw compilationUnavailable(error); }
}

export async function shaderSource(urls) {
  const files = ["shaders/field.wgsl", "generated/constants.wgsl", "shaders/cheetah.wgsl",
    "shaders/tip5.wgsl", "shaders/encoding.wgsl", "shaders/search.wgsl"];
  return (await Promise.all((urls ?? files).map(async (path) => {
    const response = await fetch(new URL(path, import.meta.url));
    if (!response.ok) throw new Error(`Cannot load ${path}. Run the browser build first.`);
    return response.text();
  }))).join("\n");
}

export class GpuSearch {
  static async create({ shaderUrls } = {}) {
    const { device, adapterName } = await requestGpuDevice();
    const gpu = new GpuSearch(device);
    gpu.adapterName = adapterName;
    try {
      const module = await compileShader(device, await shaderSource(shaderUrls));
      gpu.pipeline = await compilePipeline(device, {
        layout: "auto", compute: { module, entryPoint: "mine" },
      });
      gpu.checkDevice();
      return gpu;
    } catch (error) { gpu.destroy(); throw error; }
  }

  constructor(device) {
    this.device = device;
    this.buffers = [];
    this.loss = null;
    device.lost.then((info) => { this.loss = `GPU device lost: ${info.message || info.reason}`; });
    device.addEventListener("uncapturederror", (event) => { this.loss = event.error.message; });
  }

  checkDevice() { if (this.loss) throw new Error(this.loss); }

  buffer(size, usage) {
    const buffer = this.device.createBuffer({ size, usage });
    this.buffers.push(buffer);
    return buffer;
  }

  initialize(points, masks, prefixLength) {
    this.checkDevice();
    this.releaseBuffers();
    this.lanes = points.length / POINT_WORDS;
    if (!Number.isInteger(this.lanes) || this.lanes < 1 || this.lanes > 256) throw new Error("Invalid lane count.");
    if (masks.length !== 110 || prefixLength < 1 || prefixLength > 55) throw new Error("Invalid prefix masks.");
    this.pointBuffer = this.buffer(points.byteLength, GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST | GPUBufferUsage.COPY_SRC);
    this.configBuffer = this.buffer(114 * 4, GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST);
    this.resultBuffer = this.buffer(this.lanes * RESULT_WORDS * 4, GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC);
    this.readback = this.buffer(this.resultBuffer.size, GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ);
    this.config = new Uint32Array(114);
    this.config.set([this.lanes, 1, prefixLength, 0]);
    this.config.set(masks, 4);
    this.device.queue.writeBuffer(this.pointBuffer, 0, points);
    this.bindGroup = this.device.createBindGroup({
      layout: this.pipeline.getBindGroupLayout(0),
      entries: [this.pointBuffer, this.configBuffer, this.resultBuffer].map((buffer, binding) => ({ binding, resource: { buffer } })),
    });
  }

  async dispatch(steps) {
    if (!Number.isInteger(steps) || steps < 1 || steps > 16) throw new Error("Use 1 to 16 steps per GPU batch.");
    this.checkDevice();
    this.config[1] = steps;
    this.device.queue.writeBuffer(this.configBuffer, 0, this.config);
    const commands = this.device.createCommandEncoder();
    const pass = commands.beginComputePass();
    pass.setPipeline(this.pipeline);
    pass.setBindGroup(0, this.bindGroup);
    pass.dispatchWorkgroups(Math.ceil(this.lanes / 32));
    pass.end();
    commands.copyBufferToBuffer(this.resultBuffer, 0, this.readback, 0, this.readback.size);
    this.device.queue.submit([commands.finish()]);
    await this.readback.mapAsync(GPUMapMode.READ);
    let words;
    try { words = new Uint32Array(this.readback.getMappedRange()).slice(); }
    finally { this.readback.unmap(); }
    this.checkDevice();
    return Array.from({ length: this.lanes }, (_, lane) => {
      const i = lane * RESULT_WORDS;
      return { lane, status: words[i], offset: words[i+1], tested: words[i+2], digest: words.slice(i+4, i+14) };
    });
  }

  releaseBuffers() {
    for (const buffer of this.buffers) buffer.destroy();
    this.buffers = [];
  }

  destroy() { this.releaseBuffers(); this.device.destroy(); }
}
