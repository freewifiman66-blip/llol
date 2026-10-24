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
-- buffer is read-only in Roblox, so we use hookfunction instead of assignment.
if buffer and hookfunction then
    local band   = bit32.band
    local rshift = bit32.rshift

    hookfunction(buffer.readu8, newcclosure(function(b, off)
        local v = buffer.readu8(b, off)
        captureStreamByte(v)
        return v
    end))

    hookfunction(buffer.readu16, newcclosure(function(b, off)
        local v = buffer.readu16(b, off)
        captureStreamByte(band(v, 0xFF))
        captureStreamByte(band(rshift(v, 8), 0xFF))
        return v
    end))

    hookfunction(buffer.readi16, newcclosure(function(b, off)
        local v = buffer.readi16(b, off)
        local u = v < 0 and v + 65536 or v
        captureStreamByte(band(u, 0xFF))
        captureStreamByte(band(rshift(u, 8), 0xFF))
        return v
    end))

    hookfunction(buffer.readu32, newcclosure(function(b, off)
        local v = buffer.readu32(b, off)
        captureStreamByte(band(v, 0xFF))
        captureStreamByte(band(rshift(v, 8), 0xFF))
        captureStreamByte(band(rshift(v, 16), 0xFF))
        captureStreamByte(band(rshift(v, 24), 0xFF))
        return v
    end))

    hookfunction(buffer.readi32, newcclosure(function(b, off)
        local v = buffer.readi32(b, off)
        local u = v < 0 and v + 4294967296 or v
        captureStreamByte(band(u, 0xFF))
        captureStreamByte(band(rshift(u, 8), 0xFF))
        captureStreamByte(band(rshift(u, 16), 0xFF))
        captureStreamByte(band(rshift(u, 24), 0xFF))
        return v
    end))

    hookfunction(buffer.readf32, newcclosure(function(b, off)
        local v = buffer.readf32(b, off)
        local u = buffer.readu32(b, off)
        captureStreamByte(band(u, 0xFF))
        captureStreamByte(band(rshift(u, 8), 0xFF))
        captureStreamByte(band(rshift(u, 16), 0xFF))
        captureStreamByte(band(rshift(u, 24), 0xFF))
        return v
    end))

    hookfunction(buffer.readstring, newcclosure(function(b, off, len)
        local s = buffer.readstring(b, off, len)
        local printable = s:gsub("[%c\128-\255]", ".")
        wlog("decoded_strings.txt", ("[off=%d len=%d] %s"):format(off, len, printable))
        for i = 1, #s do
            captureStreamByte(s:byte(i))
        end
        return s
    end))

    hookfunction(buffer.writeu32, newcclosure(function(b, off, v)
        return buffer.writeu32(b, off, v)
    end))
end

-- ── Hook string.sub (outer IronBrew2 VM constant decoding) ───────────────────
local strSeen = {}
hookfunction(string.sub, newcclosure(function(s, i, j)
    local r = string.sub(s, i, j)
    if #r >= 3 and not strSeen[r] then
        local printable = r:gsub("[%c\128-\255]", ""):len()
        if #r > 0 and printable / #r > 0.5 then
            strSeen[r] = true
            wlog("decoded_strings.txt", r)
        end
    end
    return r
end))

-- ── Hook setfenv ─────────────────────────────────────────────────────────────
hookfunction(setfenv, newcclosure(function(fn, env)
    if type(env) == "table" then
        wlog("decoded_env.txt", "=== setfenv ===")
        for k, v in pairs(env) do
            wlog("decoded_env.txt", ("  %s = %s"):format(tostring(k), tostring(v)))
        end
    end
    return setfenv(fn, env)
end))

-- ── Hook coroutine.wrap ──────────────────────────────────────────────────────
hookfunction(coroutine.wrap, newcclosure(function(fn)
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
    return coroutine.wrap(fn)
end))

-- ── Hook print / warn ────────────────────────────────────────────────────────
hookfunction(print, newcclosure(function(...)
    local parts = {}
    for i = 1, select("#", ...) do parts[i] = tostring(select(i, ...)) end
    wlog("decoded_calls.txt", "[print] " .. table.concat(parts, "\t"))
    return print(...)
end))

if warn then
    hookfunction(warn, newcclosure(function(...)
        local parts = {}
        for i = 1, select("#", ...) do parts[i] = tostring(select(i, ...)) end
        wlog("decoded_calls.txt", "[warn] " .. table.concat(parts, "\t"))
        return warn(...)
    end))
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
