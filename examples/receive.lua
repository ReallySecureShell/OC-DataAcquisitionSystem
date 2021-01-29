local serialization = require("serialization")
local component     = require("component")
local event         = require("event")

-- Read the private key
local file = io.open("ec-key","rb")

local privateKey = file:read("*a")

file:close()

-- Unserialize the privateKey
local privateKey = serialization.unserialize(privateKey)

-- Rebuild privateKey object
local privateKey = component.data.deserializeKey(privateKey,"ec-private")

-- Use event.pull() to recieve the message from the other linked computer.
local _, _, _, _, _, message = event.pull("modem_message")

-- Unserialize the message
local message = serialization.unserialize(message)

-- From the message, deserialize the public key
local publicKey = component.data.deserializeKey(message.header.sessionPublicKey,"ec-public")

-- Create an AES key used for decryption
local aesKey = component.data.md5(component.data.ecdh(privateKey, publicKey))

-- Use the AES key and the IV to decrypt the encrypted data in message.data
local data = component.data.decrypt(message.data, aesKey, message.header.iv)

-- Unserialize the data variable, rebuilding the table.
local data = serialization.unserialize(data)

-- Optional, use cbrowse to view the contents of the 'data' table.
require"cbrowse".view(data)
