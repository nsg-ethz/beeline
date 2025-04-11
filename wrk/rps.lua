local function getintenv(name, default)
    local env = os.getenv(name)
    if env == nil then
        return default
    end

    return tonumber(env)
end

local function getboolenv(name, default)
    local env = os.getenv(name)
    if env == nil then
        return default
    end

    env = string.lower(env)
    return not (env == "false" or env == "0")
end

function string.random(length)
    local res = ""
    for i = 1, length do
        res = res .. string.char(math.random(97, 122))
    end

    return res
end

local function genreq(backend, length)
    local headers = {
        ["backend"] = "server" .. backend
    }
    local body = string.random(length)
    return wrk.format("POST", "/", headers, body)
end

init = function()
    local length = getintenv("PAYLOAD_SIZE", 1024)
    local backend = getintenv("BACKEND", nil)
    io.write("Payload size: ", length, "\n")
    if backend ~= nil then
        io.write("Backend: ", backend, "\n")
    end

    local backends = {}
    if backend == nil then
        for i = 1, 4 do
            backends[i] = i
        end
    else
        backends[1] = backend
    end

    requests = {}
    for i, b in ipairs(backends) do
        requests[i] = genreq(b, length)
    end
end

request = function()
    local i = math.random(#requests)

    return requests[i]
end

done = function(summary, latency, requests)
    io.write("------------------------------\n")
    for p = 1, 99 do
        n = latency:percentile(p)
        io.write(string.format("p(%g): %f\n", p, n / 1000))
    end
end
