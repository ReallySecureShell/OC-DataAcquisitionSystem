--[=====[
PURPOSE
*  To provide monitoring capabilities for the ME subnetworks at a fuel-production facility. Specifically, 
*  provide energy and item/fluid monitoring for the ME subnetworks. 
*  Securely transfer that monitoring data to a secure facility over an encrypted connection.
--]=====]

-- REQUIRED LIBRARIES
local serialization = require("serialization")
local component     = require("component")
local computer      = require("computer")
local event         = require("event")
local fs            = require("filesystem")

-- Start function for use by the RC Controller
function start()
    print("Starting facility monitoring script")
end

-- Stop function for use by the RC Controller.
function stop(...)
    os.exit(0)
end

-- Used for debugging, comment when using rc.
--args = {
--["scriptName"] = "test",
--["publicKey"]  = "/home/ec-key.pub",
--["keySize"]    = 384,
--["iterationFrequency"] = 5
--}

-- CHECKS

-- Make sure the value provided by the 'args' global variable is valid. Below is what should be configured in /etc/rc.cfg
--[=====[
99_FacilityMasterControlUnit =
{
    scriptName = "name of this file without .lua. Used for error messages.":string,
    publicKey  = "/path/to/public/key":string,
    keySize    = "size of the keypair that the public key is from (either 256 or 384)":number
    iterationFrequency = "The frequency in seconds between the calling of the __MAIN__() function":number
}
--]=====]

-- Define the keys that should be present within the 'args' global table. The 'args' table is provided by the RC controller.
local requiredMethods = table.pack(
"scriptName",
"publicKey",
"keySize",
"iterationFrequency"
)

if args and type(args) == "table" then
    for i = 1, requiredMethods.n do
        -- Error when a required key/value pair is not present.
        if requiredMethods[i] and not args[requiredMethods[i]] then
            io.stderr:write("args['"..requiredMethods[i].."']: key/value pair does not exist within table")
            os.exit()
        -- If key/value pair present then make sure those values are of the correct data type. And
        -- perform a file lookup for args["publicKey"] to make sure it exists.
        else
            -- Check if the values in keys: scriptName and publicKey are strings.
            if requiredMethods[i] == "scriptName" or requiredMethods[i] == "publicKey" then
                if type(args[requiredMethods[i]]) ~= "string" then
                    io.stderr:write("args['"..requiredMethods[i].."']: Is a '"..type(args[requiredMethods[i]]).."', invalid data type for key/value pair")
                    os.exit()
                -- Make sure the path provided by the publicKey key exists.
                elseif requiredMethods[i] == "publicKey" and not fs.exists(args[requiredMethods[i]]) then
                    io.stderr:write(args.scriptName..": "..args.publicKey..": No such file or directory")
                    os.exit()
                end
            elseif requiredMethods[i] == "keySize" or requiredMethods[i] == "iterationFrequency" then
                if type(args[requiredMethods[i]]) ~= "number" then
                    io.stderr:write(args.scriptName..": args['"..requiredMethods[i].."']: Is a '"..type(args[requiredMethods[i]]).."', invalid data type for key/value pair")
                    os.exit()
                elseif requiredMethods[i] == "keySize" then
                    if args[requiredMethods[i]] ~= 256 and args[requiredMethods[i]] ~= 384 then
                        io.stderr:write(args.scriptName..": "..args[requiredMethods[i]]..": Keysize must be either 256 or 384")
                        os.exit()
                    end
                elseif requiredMethods[i] == "iterationFrequency" then
                    if args[requiredMethods[i]] <= 0 then
                        io.stderr:write(args.scriptName..": "..args[requiredMethods[i]]..": args['"..requiredMethods[i].."'] must not be less than or equal to zero (0)")
                        os.exit()
                    end
                end
            end
        end
    end
else
    io.stderr:write("'args': Table does not exist. Configure this in /etc/rc.cfg.")
    os.exit()
end

-- Check if a datacard is installed.
if not component.isAvailable("data") then
    io.stderr:write(args.scriptName..": No datacard installed. Cryptographic functions not available.")
    os.exit()

-- Make sure a Tier 3 datacard is installed.
else
    local requiredMethods = table.pack("generateKeyPair")

    for i = 1, requiredMethods.n do
        if requiredMethods[i] and not component.data[requiredMethods[i]] then
            io.stderr:write(args.scriptName..": Datacard does not support the required cryptographic functions. A Tier 3 Data Card is required.")
            os.exit()
        end
    end
end

-- Make sure at least one ME Controller is connected.
if not component.isAvailable("me_controller") then
    io.stderr:write(args.scriptName..": No ME Controller found. At least one ME Controller must be connected.")
    os.exit()
end

-- A link card must be installed to create a point-to-point connection with the off-site server.
if not component.isAvailable("tunnel") then
    io.stderr:write(args.scriptName..": No Link Card installed.")
    os.exit()
end

-- TABLES

-- Convert AE to FE energy.
local calculateSubnetEnergy =
{
    ["energy"] = function(cUUID)

        local energy = tonumber(string.format("%.2f",component.invoke(cUUID,"getAvgPowerUsage") - component.invoke(cUUID,"getIdlePowerUsage")))
        local energy = (energy / 0.05) * 2

        return energy
    end
}

-- This table contains the data that will be sent to the receiving computer.
-- Along with header information the receiver will use to decrypt the message.
local __packet =
{
    header =
    {
        computerID          = computer.address(), -- A constant, so it's generated once per execution.
        sessionPublicKey    = nil,
        iv                  = nil
    },

    data = nil
}

-- HELPER FUNCTIONS

-- Function returns all the items in a ME Subnetwork.
local function getItems(cUUID)

    local __TMPTABLE = {}

    for key, value in pairs(component.invoke(cUUID,"getItemsInNetwork")) do

        if key ~= 'n' then
            table.insert(__TMPTABLE,key,value)
        end

    end

    return __TMPTABLE

end

-- Function returns all the fluids in a ME Subnetwork.
local function getFluids(cUUID)

    local __TMPTABLE = {}

    for key, value in pairs(component.invoke(cUUID,"getFluidsInNetwork")) do

        if key ~= 'n' then
            table.insert(__TMPTABLE,key,value)
        end

    end

    return __TMPTABLE

end

-- Function that will read a provided public key, generate an AES key, checksum of said key, and an initialization vector for encryption.
local function generateAESKey(public, bits)
    -- Read the public key file.
    local file = io.open(public,"rb")

    local publicKey = file:read("*a")

    file:close()

    -- Unserialize the public key into binary form.
    local publicKey = serialization.unserialize(publicKey)

    -- Rebuild public key object.
    local status, publicKey = xpcall(function(p)
                                         return component.data.deserializeKey(p,"ec-public") or error(args.scriptName..": Unable to generate key object. Are you certain '"..public.."' is a public key?")
                                     end,
                                     function(err)
                                         local expression = "("..args.scriptName..": .*)"
                                         return string.match(err,expression)
                                     end, publicKey)

    -- Print error, if any.
    if not status then
        io.stderr:write(publicKey)
        os.exit()
    end

    -- Generate a public key that will be transmitted to the receiving computer, and a private key which is used below.
    local sessionPublicKey, tmpPrivate = component.data.generateKeyPair(bits)

    -- Generate and AES key, which is an MD5 hash of a Diffie-Hellman shared key.
    local status, aesKey = xpcall(function(private, public)
                                      return component.data.md5(component.data.ecdh(private, public))
                                  end,
                                  function(err)
                                      return err.."\n"..args.scriptName..": Failed to generate AES key. This could be due to specifying an invalid key length."
                                  end, tmpPrivate, publicKey)

    if not status then
        io.stderr:write(aesKey)
        os.exit()
    end

    return aesKey, sessionPublicKey.serialize()
end

-- Return two (2) binary strings, one is used for the AES key to encrypt the message.
-- The other is a public key that will be serialized and then sent in plain-text to the
-- receiving computer.
local aesKey, sessionPublicKey = generateAESKey(args.publicKey, args.keySize)

-- Since sessionPublicKey remains a constant, set __packet.header.sessionPublicKey equal to
-- the former.
__packet.header.sessionPublicKey = sessionPublicKey

local function __MAIN__()
--[=====[
    The format of the message is as follows:
    HEADER
    ComputerID:string        - The UUID of *this* computer.
    sessionPublicKey:string  - Serialized public key generated by *this* computer.
                               The receiver will use it to decrypt the message.
    iv:string                - Initialization Vector is generated everytime a
                               message is sent. This is used for encryption.

    DATA
    timestamp:string   - day/month/year hour:minute:second (24-hour)
    cUUID:string       - Full UUID of ME Controller
    energy:number      - The REAL amount of FE the subnet is using.
    itemsInNetwork:table   - Amount of items stored within the subnet. 
    fluidsInNetwork:table  - Amount of liquid stored within the subnet.
--]=====]

    for cUUID, _ in component.list("me_controller", true) do
        -- Generate a new Initialization Vector every iteration.
        __packet.header.iv = component.data.random(16)

        -- To make sure the __packet.data variable does not grow,
        -- set equal to nil at the start of each iteration.
        __packet.data = nil

        -- Data is gathered from the ME controller and added to the below table.
        __packet.data =
        {
            ['timestamp']       = os.date(),
            ['cUUID']           = cUUID,
            ['energy']          = calculateSubnetEnergy.energy(cUUID),
            ['itemsInNetwork']  = getItems(cUUID),            
            ['fluidsInNetwork'] = getFluids(cUUID)
        }

        -- Data is serialized and encrypted.
        __packet.data = component.data.encrypt(serialization.serialize(__packet.data), aesKey, __packet.header.iv)


        -- Used for debugging; view the contents of the __packet table.
        -- Uncomment __MAIN__(), and comment the line starting with
        -- 'local timerEvent' which is the last line.
        -- require"cbrowse".view(__packet)


        -- Send data to the receiving computer.
        component.tunnel.send(serialization.serialize(__packet))
    end
end

-- __MAIN__()

local timerEvent = event.timer(args.iterationFrequency, function() __MAIN__() end, math.huge)
