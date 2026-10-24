# lua-vm-interceptor

Roblox executor interceptor for a **double-layer obfuscated** script:
- **Outer**: IronBrew2-style custom Lua VM (89 dispatcher functions)
- **Inner**: Luraph v14.x custom bytecode (confirmed by `LPH` watermark, ascii85-encoded, LCG-stream-encrypted, read via Luau `buffer` API)

Hooks the Luau `buffer` API at runtime to capture the fully decrypted bytecode stream as the inner VM reads it — no key recovery needed.

---

## Confirmed architecture (from static analysis)

```
script.lua
  └─ IronBrew2 VM  return({89 functions}):C()(...)
       └─ Hb() decodes [==[LPH]!!...]==]  (1.35 MB ascii85 payload)
            └─ Luraph v14 bytecode buffer  (LCG-encrypted, 1.08 MB)
                 └─ Luraph VM reads via buffer.readu8/readu32/readstring
                      └─ actual Roblox script
```

## What it intercepts

| Hook | What it captures |
|---|---|
| `buffer.readu8` | Every decrypted byte as Luraph reads its bytecode |
| `buffer.readu16/32` | Multi-byte reads (instructions, constants) |
| `buffer.readstring` | Decoded string constants from constant pool |
| `buffer.writeu32` | Pre-LCG raw buffer bytes (before decryption) |
| `string.sub` | IronBrew2 outer VM constant decoding |
| `setfenv` | The decoded function's environment table |
| `coroutine.wrap` | VM thread upvalues |
| `game:HttpGet` | Any remote URLs the script fetches |
| `print` / `warn` | All decoded script output |

Output files written to your executor's workspace:

| File | Contents |
|---|---|
| `decoded_stream.bin` | Full post-LCG byte stream (the decrypted Luraph bytecode) |
| `decoded_strings.txt` | All string constants extracted at runtime |
| `decoded_env.txt` | setfenv environment + coroutine upvalues |
| `decoded_calls.txt` | All intercepted runtime calls, URLs, print output |

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

## How the VM stack works (quick reference)

### Outer: IronBrew2 VM

```lua
return({
  oy=function(...) end,  -- 89 control-flow-flattened dispatcher functions
  ...
  C=function(E) end      -- entry point
}):C()(...)
```

| Property | Value | Purpose |
|---|---|---|
| `E.DF` | `string.byte` | byte reader |
| `E.b` | `{23336, 2506728128, ...}` | 9-element bit32 key array |
| `E.f` | `coroutine` | coroutine alias |
| `E.I` | LCG closure | 28-round chained LCG keystream |
| `E.G` | LCG closure | 2-round LCG (secondary) |
| `c[62]` | Luraph runner fn | called after full deserialization |

### Inner: Luraph v14 bytecode

The `[==[LPH]!!...]==]` payload (1,351,283 chars) decodes via ascii85 to **1,081,104 bytes** of Luraph bytecode. Luraph uses:

- `buffer.create` / `buffer.writeu32` to build the buffer
- `buffer.readu8` / `buffer.readu32` / `buffer.readf32` / `buffer.readstring` to read it
- A 28-round chained LCG (`I` function) as per-byte XOR keystream during reads
- Seed derived at runtime from: `c[0x794F]`, `c[0x51f3]`, `c[0x40C]`, `c[11349]`, `c[4528]`

Because the seed depends on interdependent runtime state, **static key recovery is not possible** — hence the buffer API hook approach.

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
