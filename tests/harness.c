/* harness.c : embeds Lua (5.2 / 5.3 / 5.4) and repeatedly calls lua_resume on
 * a coroutine, mimicking the nginx/OpenResty "one request = one lua_resume"
 * execution model that the eBPF profiler is designed to hook.
 *
 * Build against whichever Lua you have:
 *
 *   Debian/Ubuntu liblua5.4-dev:
 *     cc -O2 harness.c -o /tmp/lua-harness \
 *        -I/usr/include/lua5.4 \
 *        -llua5.4 -lm -ldl -Wl,-rpath=/usr/lib/x86_64-linux-gnu
 *
 *   Debian/Ubuntu liblua5.3-dev:
 *     cc -O2 harness.c -o /tmp/lua-harness \
 *        -I/usr/include/lua5.3 \
 *        -llua5.3 -lm -ldl -Wl,-rpath=/usr/lib/x86_64-linux-gnu
 *
 *   Static link (5.4 source tree in ../lua-5.4.6):
 *     cc -O2 harness.c ../lua-5.4.6/liblua.a -I../lua-5.4.6/src \
 *        -o /tmp/lua-harness -lm -ldl
 *
 * Compile-time version is taken from LUA_VERSION_NUM in lua.h.
 */
#include <stdio.h>
#include <stdlib.h>
#include <lauxlib.h>
#include <lualib.h>

static long env_long(const char *name, long default_value)
{
    const char *value = getenv(name);
    if (!value || !*value) {
        return default_value;
    }
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end == value || parsed <= 0) {
        return default_value;
    }
    return parsed;
}

int main(int argc, char **argv)
{
    const char *script = (argc > 1) ? argv[1] : "cpu-burn.lua";
    long max_iters = env_long("LUA_FLAME_RS_HARNESS_ITERS", 1000000000L);

    lua_State *L = luaL_newstate();
    luaL_openlibs(L);

    /* load (compile) the script -- this defines `handler` etc. but does
     * NOT run them yet (we wrap the whole thing in a coroutine). */
    if (luaL_dofile(L, script) != 0) {
        fprintf(stderr, "load error: %s\n", lua_tostring(L, -1));
        return 1;
    }

    /* the script registers a global `handler` that we resume as a coroutine. */
    for (long iter = 0; iter < max_iters; iter++) {
        lua_getglobal(L, "coroutine");
        lua_getfield(L, -1, "create");
        lua_getglobal(L, "handler");
        if (lua_pcall(L, 1, 1, 0) != 0) {
            fprintf(stderr, "create error: %s\n", lua_tostring(L, -1));
            break;
        }
        lua_State *co = lua_tothread(L, -1);

        int status;
        /* lua_resume gained a 4th arg (nres) in 5.4. */
#if LUA_VERSION_NUM >= 504
        int nres;
        while ((status = lua_resume(co, L, 0, &nres)) == LUA_YIELD) {
            /* yielded (coroutine.yield) -- resume again */
        }
#else
        while ((status = lua_resume(co, L, 0)) == LUA_YIELD) {
            /* yielded (coroutine.yield) -- resume again */
        }
#endif
        if (status != LUA_OK) {
            fprintf(stderr, "resume error: %s\n", lua_tostring(co, -1));
            break;
        }
        lua_pop(L, 2);
    }

    lua_close(L);
    return 0;
}
