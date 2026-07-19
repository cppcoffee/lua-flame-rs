-- cpu-burn.lua : a deterministic CPU-burning Lua workload (5.2/5.3/5.4)
-- for profiling. Driven by harness.c, which calls lua_resume (C API)
-- repeatedly.
--
-- The hot operations below fan out through several helper stages so the flame
-- graph shows more than one Lua source line and a few nested call chains.

local work_iters = tonumber(os.getenv("LUA_FLAME_RS_WORK_ITERS")) or 200000
local fib_n = tonumber(os.getenv("LUA_FLAME_RS_FIB_N")) or 15
local sum_n = tonumber(os.getenv("LUA_FLAME_RS_SUM_N")) or 40
local scan_n = tonumber(os.getenv("LUA_FLAME_RS_SCAN_N")) or 24
local round_n = tonumber(os.getenv("LUA_FLAME_RS_ROUND_N")) or 6

-- Recursive fibonacci (call-heavy, shows nested Lua frames).
local function fib(n)
    if n < 2 then return n end
    return fib(n - 1) + fib(n - 2)   -- deep recursion
end

-- Arithmetic-heavy hot loop.
local function sum_squares(n)
    local s = 0
    for i = 1, n do                  -- hot inner loop
        s = s + i * i
    end
    return s
end

-- Deterministic request-shaping pass: a small arithmetic mixer that mutates
-- the seed across a fixed number of rounds.
local function rotate_seed(seed, rounds)
    local x = seed
    for i = 1, rounds do
        x = (x * 33 + i * 17 + seed) % 1000003
    end
    return x
end

-- Simulate parsing and normalizing a request payload.
local function parse_payload(seed)
    local x = seed
    for i = 1, scan_n do
        x = rotate_seed(x + i, round_n)
    end
    return x
end

-- Recursive + arithmetic hot path, the most obvious "real case" stack in the
-- profiler output.
local function score_request(seed)
    local total = fib(fib_n)
    total = total + sum_squares(sum_n)
    total = total + parse_payload(seed)
    return total
end

-- Batch a few records together so the flame graph gets a wider branch under a
-- shared top-level request frame.
local function aggregate_batch(seed)
    local total = 0
    for i = 1, 4 do
        total = total + score_request(seed + i)
    end
    return total
end

-- Another branch that leans harder on the recursive side.
local function inspect_fib_branch(seed)
    local a = fib(fib_n + 1)
    local b = fib(fib_n - 2)
    local c = parse_payload(seed + a)
    return a + b + c
end

-- Another branch that leans harder on looped arithmetic and record folding.
local function inspect_loop_branch(seed)
    local total = 0
    for i = 1, 3 do
        total = total + sum_squares(sum_n + i * 4)
        total = total + parse_payload(seed + total + i)
    end
    return total
end

-- Final request-shaped stage: fan out into multiple realistic-looking request
-- handlers and then recombine the work.
local function render_response(seed)
    local left = aggregate_batch(seed)
    local mid = inspect_fib_branch(seed + left)
    local right = inspect_loop_branch(seed + mid)
    return left + mid + right
end

-- The "request handler" -- this is what harness.c resumes as a coroutine.
function handler()
    local total = 0
    for i = 1, work_iters do         -- outer hot loop
        local seed = rotate_seed(i, round_n)
        if i % 3 == 0 then
            total = total + inspect_fib_branch(seed)
        elseif i % 3 == 1 then
            total = total + inspect_loop_branch(seed)
        else
            total = total + render_response(seed + total)
        end
        if i % 1000 == 0 then
            coroutine.yield()        -- yield back to harness
        end
    end
    return total
end

-- This file is loaded via luaL_dofile from harness.c, so the top-level code
-- just defines `handler` and returns. The actual work happens when harness.c
-- resumes the coroutine.
