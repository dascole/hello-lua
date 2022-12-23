--local BasePlugin = require "kong.plugins.base_plugin"
local constants = require "kong.constants"
local permit = require "kong.plugins.permit.permit"

--local PermitHandler = BasePlugin:extend()
local PermitHandler = {
    VERSION  = "1.0-0",
    PRIORITY = 988,
}
--PermitHandler.PRIORITY = 988

function PermitHandler:new()
    --PermitHandler.super.new(self, "permit")
    permit.new(self)
end

function PermitHandler:access(conf)
    --PermitHandler.super.access(self)
    permit.authorize(self, conf)
end

return PermitHandler;

