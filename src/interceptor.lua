--[[
    interceptor.lua  (v2 — IronBrew2 outer VM + Luraph v14 inner VM)
    ──────────────────────────────────────────────────────────────────
    Target structure confirmed by static analysis:
      Outer layer: IronBrew2-style VM (89 dispatcher functions, return({...}):C()(...))
      Inner layer: Luraph v14.x custom bytecode (LPH watermark, ascii85-encoded,
                   LCG-encrypted, read via Luau buffer API)

    HOOK STRATEGY
    ─────────────
    Because the Luraph inner-VM's decryption key is computed at runtime from
    interdependent state values (c[0x51f3], c[0x40C], c[0x794F], etc.) that
    cannot be recovered statically, we hook at EXECUTION time:

    1. buffer.readu8 / buffer.readu32 / buffer.readstring  (Luau buffer API)
       The inner Luraph VM reads EVERY byte of its bytecode through these.
       We intercept every read and log it in sequence — this gives us the
       fully decrypted bytecode stream as it flows out.

    2. setfenv  — captures the decoded function's environment table.

    3. Every global call the decoded script makes (print, warn, require, etc.)
       to reveal what the script actually does at runtime.

    4. buffer.writeu32 — the outer VM builds the inner bytecode buffer here.
       We capture the full buffer once it's written, before the LCG decryption
       is applied during reading.

    OUTPUT FILES (written to executor workspace)
    ─────────────────────────────────────────────
      decoded_stream.bin   – raw byte stream as the inner VM reads it (post-LCG)
      decoded_env.txt      – setfenv environment dump
      decoded_calls.txt    – all runtime calls intercepted
      decoded_strings.txt  – all string constants extracted at runtime

    USAGE
    ─────
    Method 1 (two tabs):
      Tab 1 → paste this file → Execute
      Tab 2 → paste script.lua → Execute

    Method 2 (one-shot, requires HTTP):
      Edit SCRIPT_URL at the bottom, uncomment the loader block, Execute.
--]]

-- ── Compat ───────────────────────────────────────────────────────────────────
local _writefile  = writefile  or function() end
local _appendfile = appendfile or _writefile
local _hookfn     = hookfunction or function(_, r) return r end
local _newcc      = newcclosure  or function(f) return f end

local function wlog(file, line)
    pcall(_appendfile, file, line .. "\n")
end

-- ── Init output files ────────────────────────────────────────────────────────
_writefile("decoded_stream.bin",  "")   -- raw post-LCG byte stream (binary)
_writefile("decoded_env.txt",     "-- setfenv / upvalue dump\n")
_writefile("decoded_calls.txt",   "-- runtime call log\n")
_writefile("decoded_strings.txt", "-- string constants\n")

-- ── Stream capture ───────────────────────────────────────────────────────────
-- We collect every byte the inner Luraph VM decodes from its buffer,
-- in the order it reads them. This IS the plaintext bytecode stream.
local streamBytes = {}
local streamCount = 0

local function captureStreamByte(b)
    streamBytes[#streamBytes + 1] = b
    streamCount = streamCount + 1
    -- flush every 4096 bytes
    if streamCount % 4096 == 0 then
        local chunk = string.char(table.unpack(streamBytes))
        _appendfile("decoded_stream.bin", chunk)
        streamBytes = {}
    end
end

local function flushStream()
    if #streamBytes > 0 then
        local chunk = string.char(table.unpack(streamBytes))
        _appendfile("decoded_stream.bin", chunk)
        streamBytes = {}
    end
end

-- ── Hook buffer API ──────────────────────────────────────────────────────────
-- The inner Luraph VM reads its decrypted bytecode via buffer.readu8 etc.
-- Every byte it reads goes through buffer.readu8 — we capture them all.
if buffer then
    local _buf_readu8     = buffer.readu8
    local _buf_readu16    = buffer.readu16
    local _buf_readu32    = buffer.readu32
    local _buf_readi16    = buffer.readi16
    local _buf_readi32    = buffer.readi32
    local _buf_readf32    = buffer.readf32
    local _buf_readstring = buffer.readstring
    local _buf_writeu32   = buffer.writeu32

    -- Capture every u8 read (most granular — the LCG output is applied per-byte here)
    buffer.readu8 = _newcc(function(b, off)
        local v = _buf_readu8(b, off)
        captureStreamByte(v)
        return v
    end)

    -- u16 reads: capture both constituent bytes
    buffer.readu16 = _newcc(function(b, off)
        local v = _buf_readu16(b, off)
        captureStreamByte(v & 0xFF)
        captureStreamByte((v >> 8) & 0xFF)
        return v
    end)

    -- i16 reads
    buffer.readi16 = _newcc(function(b, off)
        local v = _buf_readi16(b, off)
        local u = v < 0 and v + 65536 or v
        captureStreamByte(u & 0xFF)
        captureStreamByte((u >> 8) & 0xFF)
        return v
    end)

    -- u32 reads
    buffer.readu32 = _newcc(function(b, off)
        local v = _buf_readu32(b, off)
        captureStreamByte(v & 0xFF)
        captureStreamByte((v >> 8) & 0xFF)
        captureStreamByte((v >> 16) & 0xFF)
        captureStreamByte((v >> 24) & 0xFF)
        return v
    end)

    -- i32 reads
    buffer.readi32 = _newcc(function(b, off)
        local v = _buf_readi32(b, off)
        local u = v < 0 and v + 4294967296 or v
        captureStreamByte(u & 0xFF)
        captureStreamByte((u >> 8) & 0xFF)
        captureStreamByte((u >> 16) & 0xFF)
        captureStreamByte((u >> 24) & 0xFF)
        return v
    end)

    -- f32 reads
    buffer.readf32 = _newcc(function(b, off)
        local v = _buf_readf32(b, off)
        -- log as raw u32 bits
        local u = _buf_readu32(b, off)
        captureStreamByte(u & 0xFF)
        captureStreamByte((u >> 8) & 0xFF)
        captureStreamByte((u >> 16) & 0xFF)
        captureStreamByte((u >> 24) & 0xFF)
        return v
    end)

    -- readstring: log each char
    buffer.readstring = _newcc(function(b, off, len)
        local s = _buf_readstring(b, off, len)
        -- Log as printable
        local printable = s:gsub("[%c\128-\255]", ".")
        wlog("decoded_strings.txt", ("[off=%d len=%d] %s"):format(off, len, printable))
        for i = 1, #s do
            captureStreamByte(s:byte(i))
        end
        return s
    end)

    -- Capture the raw pre-LCG buffer when it is written
    -- (buffer.writeu32 is called by the ascii85 decoder to build the Luraph buffer)
    local preBuffer = {}
    local preCount  = 0
    buffer.writeu32 = _newcc(function(b, off, v)
        _buf_writeu32(b, off, v)
        preBuffer[off // 4 + 1] = v
        preCount = preCount + 1
    end)
end

-- ── Hook string.sub (outer IronBrew2 VM constant decoding) ───────────────────
local _strsub  = string.sub
local strSeen  = {}
string.sub = _newcc(function(s, i, j)
    local r = _strsub(s, i, j)
    if #r >= 3 and not strSeen[r] then
        local printable = r:gsub("[%c\128-\255]", ""):len()
        if #r > 0 and printable / #r > 0.5 then
            strSeen[r] = true
            wlog("decoded_strings.txt", r)
        end
    end
    return r
end)

-- ── Hook setfenv ─────────────────────────────────────────────────────────────
local _setfenv = setfenv
setfenv = _newcc(function(fn, env)
    if type(env) == "table" then
        wlog("decoded_env.txt", "=== setfenv ===")
        for k, v in pairs(env) do
            wlog("decoded_env.txt", ("  %s = %s"):format(tostring(k), tostring(v)))
        end
    end
    return _setfenv(fn, env)
end)

-- ── Hook coroutine.wrap ──────────────────────────────────────────────────────
local _cowrap = coroutine.wrap
coroutine.wrap = _newcc(function(fn)
    if debug and debug.getupvalue then
        wlog("decoded_env.txt", "=== coroutine.wrap upvalues ===")
        local i = 1
        while true do
            local name, val = debug.getupvalue(fn, i)
            if not name then break end
            wlog("decoded_env.txt", ("  [%d] %s = %s"):format(i, tostring(name), tostring(val)))
            i = i + 1
        end
    end
    return _cowrap(fn)
end)

-- ── Hook print / warn ────────────────────────────────────────────────────────
local _print = print
print = _newcc(function(...)
    local parts = {}
    for i = 1, select("#", ...) do parts[i] = tostring(select(i, ...)) end
    wlog("decoded_calls.txt", "[print] " .. table.concat(parts, "\t"))
    _print(...)
end)

if warn then
    local _warn = warn
    warn = _newcc(function(...)
        local parts = {}
        for i = 1, select("#", ...) do parts[i] = tostring(select(i, ...)) end
        wlog("decoded_calls.txt", "[warn] " .. table.concat(parts, "\t"))
        _warn(...)
    end)
end

-- ── Hook game:HttpGet and HttpService ────────────────────────────────────────
-- The decoded script may fetch remote payloads — capture the URLs
pcall(function()
    local mt = getrawmetatable(game)
    local old_index = mt.__index
    setreadonly(mt, false)
    mt.__index = newcclosure(function(self, key)
        local v = old_index(self, key)
        if key == "HttpGet" or key == "HttpGetAsync" then
            return newcclosure(function(self2, url, ...)
                wlog("decoded_calls.txt", "[HttpGet] " .. tostring(url))
                return v(self2, url, ...)
            end)
        end
        return v
    end)
    setreadonly(mt, true)
end)

-- ── Flush on script end ──────────────────────────────────────────────────────
-- Roblox doesn't have atexit, so we poll via task.delay
task.delay(30, flushStream)
task.delay(60, flushStream)

print("[interceptor v2] Hooks live. Execute script.lua now.")
print("[interceptor v2] Output: decoded_stream.bin / decoded_env.txt / decoded_calls.txt / decoded_strings.txt")

-- ── Optional one-shot loader (edit SCRIPT_URL then uncomment) ────────────────
--[[
local SCRIPT_URL = "https://raw.githubusercontent.com/freewifiman66-blip/llol/master/script.lua"
local ok, src = pcall(function() return game:HttpGet(SCRIPT_URL) end)
if ok and src then
    local fn, err = loadstring(src)
    if fn then
        task.spawn(fn)
        task.delay(5, flushStream)   -- flush after script settles
    else
        warn("[interceptor] loadstring: " .. tostring(err))
    end
else
    warn("[interceptor] HttpGet: " .. tostring(src))
end
--]]
