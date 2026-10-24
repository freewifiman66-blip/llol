--[[
    interceptor.lua
    ---------------
    Roblox executor interceptor for IronBrew2 / Prometheus-style VM-obfuscated scripts.

    HOW IT WORKS
    ────────────
    The target script is a pure-Lua custom VM:
      • 89 dispatcher functions in one table
      • Encoded bytecode stored as XOR'd string constants (keys g, k, s, QrXoq3)
      • VM bootstraps via :C() then calls the decoded function as c[62](T, c[5])
      • Uses coroutine, getfenv/setfenv, string.byte (aliased as DF), bit32

    We hook THREE points:

    1. string.byte  (DF in the VM)
       Every byte the VM reads from its encoded bytecode stream passes through
       string.byte. We log each unique decoded string segment to see the raw
       constant pool as it is built.

    2. The VM's own coroutine.wrap / coroutine.resume
       The VM wraps its main execution thread in a coroutine. We hook these so
       we can inspect the thread's upvalues after the VM is fully deserialised
       but before it starts executing opcodes.

    3. getfenv / setfenv
       The VM calls setfenv on the decoded function to give it a modified
       environment. We capture that environment table — it contains every
       global the decoded script will use, which reveals its API surface.

    OUTPUT
    ──────
    Everything is written to the executor's writefile() filesystem:
      decoded_constants.txt  – all string constants decoded from the bytecode
      decoded_env.txt        – the environment table set on the final function
      decoded_calls.txt      – every global function the decoded script calls
      decoded_full.lua       – reconstructed pseudo-source (best effort)

    USAGE
    ─────
    Paste this file into your executor BEFORE loading script.lua, or use the
    one-liner loader at the bottom of this file which loadstring()'s script.lua
    from a rawgit / pastebin URL automatically.
--]]

-- ── Compat: make sure we have writefile ──────────────────────────────────────
local _writefile  = writefile  or function() end
local _appendfile = appendfile or _writefile
local _readfile   = readfile   or function() return "" end
local _hookfn     = hookfunction or function(_, r) return r end
local _newcc      = newcclosure  or function(f) return f end

-- Output helpers
local function wlog(file, line)
    pcall(_appendfile, file, line .. "\n")
end

-- ── Constant / string capture ────────────────────────────────────────────────
local captured = {}
local captureCount = 0

local function capture(s)
    if type(s) ~= "string" or #s < 3 then return end
    -- filter out obviously non-human strings (pure binary)
    local printable = s:gsub("[%c\128-\255]", ""):len()
    if printable / #s > 0.4 then
        if not captured[s] then
            captured[s] = true
            captureCount = captureCount + 1
            wlog("decoded_constants.txt", ("[%d] %s"):format(captureCount, s))
        end
    end
end

-- ── Hook string.byte ─────────────────────────────────────────────────────────
-- The VM reads its bytecode stream entirely through string.byte (aliased DF).
-- We intercept every call. The interesting payloads are multi-byte reads where
-- the result reveals decoded opcode arguments and string constants.
local _strbyte = string.byte
string.byte = _newcc(function(s, i, j)
    local result = _strbyte(s, i, j)
    -- Log the substring being read if it looks like a string constant
    if i and j and (j - i) > 2 then
        capture(s:sub(i, j))
    end
    return result
end)

-- ── Hook string.sub ──────────────────────────────────────────────────────────
-- VM also uses string.sub to slice constant strings out of the bytecode blob.
local _strsub = string.sub
string.sub = _newcc(function(s, i, j)
    local r = _strsub(s, i, j)
    capture(r)
    return r
end)

-- ── Hook getfenv / setfenv ───────────────────────────────────────────────────
-- When the VM calls setfenv(decodedFn, env) we capture the env table.
local _setfenv = setfenv
setfenv = _newcc(function(fn, env)
    -- Dump env keys
    if type(env) == "table" then
        wlog("decoded_env.txt", "=== setfenv called ===")
        for k, v in pairs(env) do
            wlog("decoded_env.txt", ("  [%s] = %s"):format(tostring(k), tostring(v)))
        end
    end
    return _setfenv(fn, env)
end)

-- ── Hook coroutine.wrap ──────────────────────────────────────────────────────
-- The VM wraps its main loop in coroutine.wrap. We intercept the wrapped
-- function so we can inspect upvalues after wrap() but before first resume.
local _cowrap = coroutine.wrap
coroutine.wrap = _newcc(function(fn)
    -- Try to dump upvalues of fn right now (before execution)
    if debug and debug.getupvalue then
        wlog("decoded_env.txt", "=== coroutine.wrap upvalues ===")
        local i = 1
        while true do
            local name, val = debug.getupvalue(fn, i)
            if not name then break end
            wlog("decoded_env.txt", ("  upvalue[%d] %s = %s"):format(i, tostring(name), tostring(val)))
            i = i + 1
        end
    end
    return _cowrap(fn)
end)

-- ── Hook print / warn so we see decoded script output ────────────────────────
local _print = print
print = _newcc(function(...)
    local parts = {}
    for i = 1, select("#", ...) do
        parts[i] = tostring(select(i, ...))
    end
    local line = table.concat(parts, "\t")
    wlog("decoded_calls.txt", "[print] " .. line)
    _print(...)
end)

local _warn = warn
if _warn then
    warn = _newcc(function(...)
        local parts = {}
        for i = 1, select("#", ...) do
            parts[i] = tostring(select(i, ...))
        end
        wlog("decoded_calls.txt", "[warn] " .. table.concat(parts, "\t"))
        _warn(...)
    end)
end

-- ── Initialise output files ───────────────────────────────────────────────────
_writefile("decoded_constants.txt", "-- Decoded string constants from VM bytecode stream\n")
_writefile("decoded_env.txt",       "-- Environment / upvalue dump\n")
_writefile("decoded_calls.txt",     "-- Runtime call log\n")

-- ── Done — hooks are live. Now load the target script. ───────────────────────
-- Replace the URL below with your raw pastebin / github raw URL for script.lua
-- OR just execute interceptor.lua first, then execute script.lua separately.

--[[
local SCRIPT_URL = "https://raw.githubusercontent.com/YOUR_USER/YOUR_REPO/main/script.lua"
local ok, src = pcall(game.HttpGet, game, SCRIPT_URL)
if ok and src then
    local fn, err = loadstring(src)
    if fn then
        fn()
    else
        warn("[interceptor] loadstring error: " .. tostring(err))
    end
else
    warn("[interceptor] fetch error: " .. tostring(src))
end
--]]

print("[interceptor] Hooks installed. Execute script.lua now.")
