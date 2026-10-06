import test from "node:test";
import assert from "node:assert/strict";
import {
  GpuSearch,
  WebGpuUnavailableError,
  compileShader,
  compilePipeline,
} from "../browser/gpu.js";
import { MnemonicGpuSearch } from "../browser/mnemonic-gpu.js";

const metalError = () => new Error(
  "Failed to compile the shader source, generated metal: #include <metal_stdlib>",
);

for (const failure of ["module", "diagnostics", "pipeline"]) {
  test(`${failure} compilation failure makes the GPU unavailable for automatic search`, async () => {
    const cause = metalError();
    const device = {
      createShaderModule() {
        if (failure === "module") throw cause;
        return { async getCompilationInfo() {
          return { messages: failure === "diagnostics"
            ? [{ type: "error", lineNum: 1, linePos: 1, message: cause.message }]
            : [] };
        } };
      },
      async createComputePipelineAsync() { throw cause; },
    };
    await assert.rejects(async () => {
      const module = await compileShader(device, "shader");
      return compilePipeline(device, { layout: "auto", compute: { module, entryPoint: "mine" } });
    }, error => {
      assert.ok(error instanceof WebGpuUnavailableError);
      assert.match(error.message, /Using CPU/);
      assert.ok(!error.message.includes("#include"));
      assert.match(error.cause.message, /Failed to compile/);
      return true;
    });
  });
}

test("successful shader and pipeline compilation preserve their results", async () => {
  const module = { async getCompilationInfo() { return { messages: [] }; } };
  const pipeline = {};
  const device = {
    createShaderModule({ code }) { assert.equal(code, "shader"); return module; },
    async createComputePipelineAsync(request) { assert.equal(request.compute.module, module); return pipeline; },
  };
  assert.equal(await compileShader(device, "shader"), module);
  assert.equal(await compilePipeline(device, { compute: { module } }), pipeline);
});

for (const Search of [GpuSearch, MnemonicGpuSearch]) {
  for (const failure of ["pipeline", "asset", "table"]) {
    if (failure === "table" && Search === GpuSearch) continue;
    test(`${Search.name} ${failure} failure releases the GPU and classifies CPU availability`, async () => {
      const navigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, "navigator");
      const fetch = globalThis.fetch;
      const shaderStage = globalThis.GPUShaderStage;
      let destroyed = 0;
      const device = {
        lost: new Promise(() => {}),
        addEventListener() {},
        destroy() { destroyed++; },
        createShaderModule() { return { async getCompilationInfo() { return { messages: [] }; } }; },
        createBindGroupLayout() { return {}; },
        createPipelineLayout() { return {}; },
        async createComputePipelineAsync() { throw metalError(); },
      };
      Object.defineProperty(globalThis, "navigator", { configurable: true, value: {
        gpu: { async requestAdapter() { return { async requestDevice() { return device; } }; } },
      } });
      globalThis.GPUShaderStage = { COMPUTE: 4 };
      globalThis.fetch = async url => ({
        ok: failure !== "asset",
        async text() { return "shader"; },
        async arrayBuffer() { return new ArrayBuffer(failure === "table" ? 1 : 64 * 16 * 96); },
      });
      try {
        await assert.rejects(Search.create(), error => {
          assert.equal(error instanceof WebGpuUnavailableError, failure === "pipeline");
          return true;
        });
        assert.equal(destroyed, 1);
      } finally {
        if (navigatorDescriptor) Object.defineProperty(globalThis, "navigator", navigatorDescriptor);
        else delete globalThis.navigator;
        globalThis.fetch = fetch;
        if (shaderStage === undefined) delete globalThis.GPUShaderStage;
        else globalThis.GPUShaderStage = shaderStage;
      }
    });
  }
}
