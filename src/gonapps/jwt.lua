local json  = require "rapidjson"
local base64 = require "base64"
local hmac = require "openssl.hmac"

local sign = {
    ["HS256"] = function(data, key) return hmac.new(key, "sha256"):final(data) end,
    ["HS384"] = function(data, key) return hmac.new(key, "sha384"):final(data) end,
    ["HS512"] = function(data, key) return hmac.new(key, "sha512"):final(data) end,
}

local verify = {
    ["HS256"] = function(data, signature, key) return signature == sign["HS256"](data, key) end,
    ["HS384"] = function(data, signature, key) return signature == sign["HS384"](data, key) end,
    ["HS512"] = function(data, signature, key) return signature == sign["HS512"](data, key) end,
}

local function decodeToken(encodedToken)
    local tokenParts = {}
    for tokenPart in string.gmatch(encodedToken, "[^.]+") do
        table.insert(tokenParts, tokenPart)
    end
    return tokenParts[1], tokenParts[2], tokenParts[3] 
end

local _M = {}

function _M.encode(payload, key, algorithm)
    algorithm = algorithm or "HS256" 
    assert(sign[algorithm] ~= nil, "Algorithm not supported")
    local header = {["typ"] = "JWT", ["alg"] = algorithm }
    local tokenParts = {base64.encode(json.encode(header)), base64.encode(json.encode(payload))}
    local signature = sign[algorithm](table.concat(tokenParts, "."), key)
    table.insert(tokenParts, base64.encode(signature))
    return table.concat(tokenParts, ".")
end

function _M.decode(encodedToken, key)
    local encodedHeader, encodedPayload, encodedSignature = decodeToken(encodedToken) 
    local header, payload, signature = json.decode(base64.decode(encodedHeader)), json.decode(base64.decode(encodedPayload)), base64.decode(encodedSignature)
    assert(header.typ == "JWT", "Invalid typ")
    assert(type(header.alg) == "string", "Invalid alg")
    assert(type(payload.exp) == "number", "Invalid exp")
    assert(type(payload.nbf) == "number", "nbf must be a number")
    assert(verify[header.alg] ~= nil , "Algorithm not supported")
    assert(verify[header.alg](encodedHeader .. "." .. encodedPayload, signature, key), "Invalid signature")
    assert(os.time() < payload.exp, "Not acceptable by exp")
    assert(os.time() >= payload.nbf, "Not acceptable by nbg")
    return payload
end

return _M
