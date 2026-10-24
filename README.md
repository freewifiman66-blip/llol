# lua-vm-interceptor

Roblox executor interceptor for **IronBrew2 / Prometheus-style VM-obfuscated** Lua scripts.

Hooks into the VM's string pipeline and environment system at runtime to capture decoded string constants, the final function environment, and all runtime output — without needing to understand the VM bytecode format manually.

---

## What it intercepts

| Hook | What it captures |
|---|---|
| `string.byte` | Every byte read from the encoded bytecode blob |
| `string.sub` | Every string constant sliced out of the blob |
| `setfenv` | The environment table set on the decoded function |
| `coroutine.wrap` | Upvalues of the main VM thread before it runs |
| `print` / `warn` | All output from the decoded script |

Output files written to your executor's workspace:

| File | Contents |
|---|---|
| `decoded_constants.txt` | All string constants the VM decoded |
| `decoded_env.txt` | Environment table + coroutine upvalues |
| `decoded_calls.txt` | Runtime print/warn log |

---

## Repo layout

```
lua-vm-interceptor/
├── src/
│   ├── interceptor.lua   ← install hooks (execute this first)
│   └── loader.lua        ← optional one-shot fetcher + runner
├── script.lua            ← the obfuscated target (add your own)
└── README.md
```

---

## Usage — two ways

### Method 1: Two tabs (simplest)

1. Open **Tab 1** in your executor, paste the contents of `src/interceptor.lua`, and execute it.
2. Open **Tab 2**, paste the obfuscated `script.lua`, and execute it.
3. Check your executor's file workspace for the three output files.

### Method 2: One-shot loader (requires HTTP)

1. Fork this repo on GitHub.
2. Upload your `script.lua` to the repo root.
3. Edit `src/loader.lua` — change `YOUR_USER` to your GitHub username:
   ```lua
   local REPO = "https://raw.githubusercontent.com/YOUR_USER/lua-vm-interceptor/main"
   ```
4. Paste `src/loader.lua` into your executor and execute. It will:
   - Fetch `interceptor.lua` from GitHub and install hooks
   - Fetch `script.lua` from GitHub and run it through the hooked environment

---

## Reading the output

### `decoded_constants.txt`
Contains every string constant the VM decoded from its bytecode stream. Look for:
- Function/method names (e.g. `FindFirstChild`, `WaitForChild`, `HttpGet`)
- URLs, asset IDs, place IDs
- GUI text, labels, error messages
- Variable names that reveal script purpose

### `decoded_env.txt`
Contains the `setfenv` environment dump — every global the decoded script can access. This is the clearest indicator of what the script does: if it has `HttpService`, `TeleportService`, or custom remote names, you'll see them here.

### `decoded_calls.txt`
Live output: anything the decoded script `print()`s or `warn()`s during execution.

---

## How the VM works (quick reference)

The obfuscated script is a **control-flow-flattened Lua VM**:

```
return({
  oy = function(...) ... end,   -- 89 dispatcher functions
  jy = function(...) ... end,
  ...
  C  = function(E) ... end      -- VM entry point / bootstrapper
}):C()(...)                     -- called immediately
```

Key internal properties:

| Property | Value | Purpose |
|---|---|---|
| `E.f` | `coroutine` | coroutine library alias |
| `E.H` | `"readu16"` | read unsigned 16-bit from stream |
| `E.W` | `"readi32"` | read signed 32-bit from stream |
| `E.DF` | `string.byte` | byte reader alias |
| `E.b` | `{23336, 2506728128, ...}` | 9-element XOR key array |
| `E.g/k/s` | encoded strings | XOR'd bytecode/constant blobs |
| `c[62]` | decoded function | final callable after VM deserialises |

The VM XOR-decodes `E.g`, `E.k`, `E.s`, `E.QrXoq3` using `E.b` keys via `bit32` operations, builds an instruction table, then executes it opcode-by-opcode in a `repeat...until false` dispatch loop.

---

## Executor compatibility

Tested concepts apply to executors that expose:

- `hookfunction` / `newcclosure`
- `writefile` / `appendfile`
- `loadstring`
- `debug.getupvalue` (optional, enhances output)

Works with: **Synapse X, KRNL, Fluxus, Electron, Codex, Wave**, and any UNC-compliant executor.

---

## Disclaimer

For educational and security research purposes only. Do not use to violate Roblox ToS or harm other users.
