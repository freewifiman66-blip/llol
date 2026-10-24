--[[
    loader.lua
    ----------
    One-liner executor loader.
    Fetches interceptor.lua and script.lua from GitHub raw URLs,
    installs hooks, then runs the target.

    PASTE THIS into your executor tab and press Execute.
    Change REPO to point at your fork.
--]]

local REPO  = "https://raw.githubusercontent.com/YOUR_USER/lua-vm-interceptor/main"

-- 1. Load and install hooks
local hookSrc = game:HttpGet(REPO .. "/src/interceptor.lua")
assert(hookSrc, "Failed to fetch interceptor.lua")
local hookFn, hookErr = loadstring(hookSrc)
assert(hookFn, "interceptor.lua parse error: " .. tostring(hookErr))
hookFn()

-- 2. Fetch and run the target obfuscated script
local targetSrc = game:HttpGet(REPO .. "/script.lua")
assert(targetSrc, "Failed to fetch script.lua")
local targetFn, targetErr = loadstring(targetSrc)
assert(targetFn, "script.lua parse error: " .. tostring(targetErr))

local ok, err = pcall(targetFn)
if not ok then
    warn("[loader] script.lua error: " .. tostring(err))
end

print("[loader] Done. Check decoded_constants.txt / decoded_env.txt / decoded_calls.txt")
