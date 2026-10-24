-- Standalone interceptor
-- Fetches ButterCooked.lua, hooks buffer API to capture the decrypted
-- Luraph bytecode stream as it flows out, then runs the script.
-- Paste this entire file into your executor and hit Execute.

local URL = "https://raw.githubusercontent.com/kode-sec/Butter/refs/heads/main/ButterCooked.lua"

-- ── output helpers ────────────────────────────────────────────────────────────
local _write  = writefile
local _append = appendfile

local function wlog(f, s) pcall(_append, f, s .. "\n") end

_write("decoded_strings.txt", "")
_write("decoded_calls.txt",   "")
_write("decoded_env.txt",     "")

-- ── stream capture ────────────────────────────────────────────────────────────
local buf_bytes = {}
local buf_count = 0

local function capbyte(v)
    buf_bytes[buf_count + 1] = v
    buf_count = buf_count + 1
    if buf_count % 4096 == 0 then
        _append("decoded_stream.bin", string.char(unpack(buf_bytes, buf_count - 4095, buf_count)))
    end
end

local function flush()
    if buf_count > 0 then
        local tail = buf_count % 4096
        if tail > 0 then
            _append("decoded_stream.bin", string.char(unpack(buf_bytes, buf_count - tail + 1, buf_count)))
        end
    end
    wlog("decoded_calls.txt", "[interceptor] flush done, " .. buf_count .. " bytes captured")
end

_write("decoded_stream.bin", "")

-- ── hook buffer API ───────────────────────────────────────────────────────────
if buffer then
    local band   = bit32.band
    local rshift = bit32.rshift

    hookfunction(buffer.readu8, newcclosure(function(b, o)
        local v = buffer.readu8(b, o)
        capbyte(v)
        return v
    end))

    hookfunction(buffer.readu16, newcclosure(function(b, o)
        local v = buffer.readu16(b, o)
        capbyte(band(v, 0xFF))
        capbyte(band(rshift(v, 8), 0xFF))
        return v
    end))

    hookfunction(buffer.readi16, newcclosure(function(b, o)
        local v = buffer.readi16(b, o)
        local u = v < 0 and v + 65536 or v
        capbyte(band(u, 0xFF))
        capbyte(band(rshift(u, 8), 0xFF))
        return v
    end))

    hookfunction(buffer.readu32, newcclosure(function(b, o)
        local v = buffer.readu32(b, o)
        capbyte(band(v, 0xFF))
        capbyte(band(rshift(v, 8), 0xFF))
        capbyte(band(rshift(v, 16), 0xFF))
        capbyte(band(rshift(v, 24), 0xFF))
        return v
    end))

    hookfunction(buffer.readi32, newcclosure(function(b, o)
        local v = buffer.readi32(b, o)
        local u = v < 0 and v + 4294967296 or v
        capbyte(band(u, 0xFF))
        capbyte(band(rshift(u, 8), 0xFF))
        capbyte(band(rshift(u, 16), 0xFF))
        capbyte(band(rshift(u, 24), 0xFF))
        return v
    end))

    hookfunction(buffer.readstring, newcclosure(function(b, o, len)
        local s = buffer.readstring(b, o, len)
        wlog("decoded_strings.txt", s:gsub("[%c\128-\255]", "."))
        for i = 1, #s do capbyte(s:byte(i)) end
        return s
    end))
end

-- ── hook setfenv to capture decoded script's globals ─────────────────────────
hookfunction(setfenv, newcclosure(function(fn, env)
    if type(env) == "table" then
        wlog("decoded_env.txt", "=== setfenv ===")
        for k, v in pairs(env) do
            wlog("decoded_env.txt", tostring(k) .. " = " .. tostring(v))
        end
    end
    return setfenv(fn, env)
end))

-- ── hook print/warn ───────────────────────────────────────────────────────────
hookfunction(print, newcclosure(function(...)
    local t = {}
    for i = 1, select("#", ...) do t[i] = tostring(select(i, ...)) end
    wlog("decoded_calls.txt", "[print] " .. table.concat(t, "\t"))
    return print(...)
end))

if warn then
    hookfunction(warn, newcclosure(function(...)
        local t = {}
        for i = 1, select("#", ...) do t[i] = tostring(select(i, ...)) end
        wlog("decoded_calls.txt", "[warn] " .. table.concat(t, "\t"))
        return warn(...)
    end))
end

-- ── fetch and run ─────────────────────────────────────────────────────────────
task.delay(30, flush)
task.delay(90, flush)

local src = game:HttpGet(URL)
local fn, err = loadstring(src)
assert(fn, "loadstring failed: " .. tostring(err))

print("[interceptor] hooks live, running target...")
task.spawn(fn)
task.delay(10, flush)
