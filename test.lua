local argon2 = require "argon2"

--- Argon2i
print(assert(argon2.hash_encoded("password", "somesalt")))
-- encoded is "$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$iWh06vD8Fy27wf9npn6FXWiCX4K6pW6Ue1Bnzz07Z8A"

--- Argon2d
print(assert(argon2.hash_encoded("password", "somesalt", {
    variant = argon2.variants.argon2_d
})))
-- encoded is "$argon2d$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$2+JCoQtY/2x5F0VB9pEVP3xBNguWP1T25Ui0PtZuk8o"

--- Argon2id
print(assert(argon2.hash_encoded("password", "somesalt", {
    variant = argon2.variants.argon2_id
})))
-- encoded is "$argon2id$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$qLml5cbqFAO6YxVHhrSBHP0UWdxrIxkNcM8aMX3blzU"

-- Hashing options
print(assert(argon2.hash_encoded("password", "somesalt", {
    t_cost = 4,
    m_cost = math.pow(2, 16), -- 65536 KiB
    parallelism = 2
})))
-- encoded is "$argon2i$v=19$m=65536,t=4,p=2$c29tZXNhbHQ$n6x5DKNWV8BOeKemQJRk7BU3hcaCVomtn9TCyEA0inM"

-- Changing the default options (those arguments are the current defaults)
argon2.t_cost(3)
argon2.m_cost(4096)
argon2.parallelism(1)
argon2.hash_len(32)
argon2.variant(argon2.variants.argon2_i)


local encoded = assert(argon2.hash_encoded("password", "somesalt"))
print(encoded)
-- encoded: argon2i encoded hash

local ok, err = argon2.verify(encoded, "password")
if err then
    error("could not verify: " .. err)
end

if not ok then
    error("The password does not match the supplied hash")
end

print(encoded, "verify ok")
