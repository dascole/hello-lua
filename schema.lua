local typedefs = require "kong.db.schema.typedefs"

return {
    name = "permit",
    fields = {
        { consumer = typedefs.no_consumer },
        {
            config = {
                type = "record",
                fields = {
                    { permitPolicy = { type = "string", required = true } },
                    { permitResource = { type = "string", required = true } },
                    { permitAction = { type = "string", required = true } },
                    { subjectIdentityLocation = { type = "string", default = "header", one_of = { "header", "cookie" }, required = false } },
                    { subjectIdentityKey = { type = "string", default = "guid", required = false } },
                    { subjectIdentityType = { type = "string", default = "webguid", one_of = { "webguid", "kerberos", "nt" }, required = false } },
                    {
                        gsAuthnProperties = {
                            type = "record",
                            fields = {
                                { authenticationPage = { type = "string" } },
                                { refererPage = { type = "string", default = "https://dummy.gs.com/" } }
                            }
                        }
                    }
                }
            }
        }
    }
}