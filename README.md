gonapps-lua-jwt
=

## About
JSON Web Tokens for Lua<br/>
This module is a fork from x25/luajwt.<br/>
It is using luaossl instead of LuaCrypto because LuaCrypto is deprecated, not maintained, not thread-safe.<br/>
Functions have been slightly changed.<br/>

## Usage
**installation**
```bash
$ sudo luarocks install gonapps-lua-jwt
```
**example code**
```lua
local jwt = require "gonapps.jwt"

local key = "example-key"

local payload = {
	iss = "example-issuer",
	nbf = os.time(),
	exp = os.time() + 3600,
}

-- encode
local alg = "HS256" -- (default)
local ok, encodedToken = pcall(jwt.encode, payload, key, alg)
-- encodedToken: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIx(cutted)...

-- decode (ok is true only if token is valid and successfully decoded)
local ok, decodedToken = pcall(jwt.decode, payload, key, algorithm)
-- decodedToken: { ["iss"] = "example-issuer", ["nbf"] = 1405108000, ["exp"] = 1405181916 }
```

## Algorithms
**HMAC**
* HS256	- HMAC using SHA-256 hash algorithm (default)
* HS384	- HMAC using SHA-384 hash algorithm
* HS512 - HMAC using SHA-512 hash algorithm

## License
MIT
