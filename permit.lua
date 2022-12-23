local https = require "ssl.https"
local ltn12 = require "ltn12"
local io = require("io")
local json = require("cjson")
local resty_cookie = require "lua-resty-cookie.resty.cookie"
local TokenGenerator = require "kong.plugins.gsauthn.TokenGenerator"
local gs_string_handler = require "kong.plugins.gs-pdk.gs_string_handler"

local HEADER = "header"
local COOKIE = "cookie"

local permit = {}
local permit_call_max = 3

local permit_payload = [[{
    "Request": {
        "Resource": {
            "Attribute": [
                {
                    "Id": "resource-id",
                    "Value": "${RESOURCE}"
                }
            ]
        },
        "Action": {
            "Attribute": [
                {
                    "Id": "action-id",
                    "Value": "${ACTION}"
                }
            ]
        },
        "Subject": {
            "Attribute":
            [{
                "Value": "${SUBJECT_IDENTITY_TYPE}_${SUBJECT}",
                "Id": "subject-id"
            }]
        }
    }
} ]]

local function trim(str)
    return str:gsub("^%s+", ""):gsub("%s+$", "")
end

local function split(line)
    local val1, val2 = line:match("([^=]+)=([^=]+)")
    return trim(val1), trim(val2)
end

function permit:new()
    local fileName = os.getenv("KONG_PLUGINS_PROPERTY_DIR") .. "/permit.properties"
    local _, fileErr = io.open(fileName, "r")
    if fileErr then
        return nil, fileErr
    end
    local permit_properties = {}
    for propLine in io.lines(fileName) do
        local key, value = split(propLine)
        permit_properties[key] = value
        ngx.log(ngx.DEBUG, "Permit Properties:" .. key .. "->" .. value)
    end

    self._permit_properties = permit_properties
    self._permit_properties.cache_opts = {}
    if permit_properties["permit.resp.cache.ttl"] then
        self._permit_properties.cache_opts["ttl"] = tonumber(permit_properties["permit.resp.cache.ttl"])
    end

    if permit_properties["permit.gssso.cache.ttl"] then
        self._permit_properties.credential_cache_ttl = tonumber(permit_properties["permit.gssso.cache.ttl"])
    end
end

local function get_payload(resource, action, username, subjectIdentityType)
    if not resource then
        error("Resource is mandatory")
    end
    if not action then
        error("Action is mandatory")
    end
    if not username then
        error("Username is mandatory")
    end

    local vars = { RESOURCE = resource, ACTION = action, SUBJECT = username, SUBJECT_IDENTITY_TYPE = subjectIdentityType }
    return (permit_payload:gsub("($%b{})",
        function(w)
            return vars[w:sub(3, -2)] or w
        end))
end

local function starts(String, Start)
    return string.sub(String, 1, string.len(Start)) == Start
end

local function get_gssso(permit_properties, gsAuthnProperties)
    local credFile = permit_properties["credFileName"]
    local authCookies = TokenGenerator.getAuthCookies(credFile, gsAuthnProperties)
    local gssso = ""
    if (type(authCookies) == "table") then
        for _, value in pairs(authCookies) do
            if gs_string_handler.starts(value, "GSSSO=") then
                ngx.log(ngx.DEBUG, "System account GSSSO found in AuthCookies Table")
                gssso = value
            end
        end
    else
        if gs_string_handler.starts(authCookies, "GSSSO=") then
            ngx.log(ngx.DEBUG, "System account GSSSO found in AuthCookies String")
            gssso = authCookies
        end
    end
    if gssso == "" then
        error("Error fetching GSSSO")
    end
    return gssso
end

local function get_permit_token(permit_properties, gsAuthnProperties)
    local permit_cache_key = "permitGsssoToken"

    ngx.log(ngx.DEBUG, "Permit cache key: ", permit_cache_key)
    local remaining_ttl, probe_err, probe_token = kong.cache:probe(permit_cache_key)

    if probe_err then
        error(probe_err)
    end

    if remaining_ttl and remaining_ttl > 0 and probe_token then
        ngx.log(ngx.DEBUG, "Results from cache for key:" .. permit_cache_key .. " with remaining ttl " .. remaining_ttl)
        return probe_token
    end

    kong.cache:invalidate_local(permit_cache_key)
    -- Gets result from get_gssso, stores it in cache, and then returns value/error
    local credential_cache_ttl = permit_properties.credential_cache_ttl and { ttl = permit_properties.credential_cache_ttl } or { ttl = 3600 }
    if credential_cache_ttl then
        ngx.log(ngx.DEBUG, "permit - GSSSO Token credential_cache_ttl: ", tostring(credential_cache_ttl.ttl), " from properties file: permit.properties")
    else
        ngx.log(ngx.DEBUG, "permit - GSSSO Token credential_cache_ttl is default ( passed as nil) ", tostring(credential_cache_ttl.ttl))
    end

    local token, permit_err = kong.cache:get(permit_cache_key, credential_cache_ttl, get_gssso, permit_properties, gsAuthnProperties)

    if permit_err then
        error(permit_err)
    end

    return token
end

local function call_permit(permit_properties, gsAuthnProperties, domain, resource, action, username, subjectIdentityType, call_count)
    if call_count == permit_call_max then
        return nil, "Max retries to permit reached"
    end
    local result_table = {}
    local payload = get_payload(resource, action, username, subjectIdentityType)
    ngx.log(ngx.DEBUG, payload)
    local permit_url = permit_properties["permit.baseUrl"] .. domain .. permit_properties["permit.privilegeCheck"]
    ngx.log(ngx.DEBUG, permit_url)

    local req_params = {
        url = permit_url,
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = string.len(payload),
            ["Cookie"] = get_permit_token(permit_properties, gsAuthnProperties)
        },
        source = ltn12.source.string(payload),
        sink = ltn12.sink.table(result_table)
    }

    local body, code, _, status = https.request(req_params)
    ngx.log(ngx.DEBUG, "Permit Response. Body: ", body, " Code: ", code, " Status: ", status)
    local result = table.concat(result_table)
    -- Possibly look into possible 401 and 403 responses from permit
    if code == ngx.HTTP_MOVED_TEMPORARILY then
        kong.cache:invalidate_local("permitGsssoToken")
        return call_permit(permit_properties, gsAuthnProperties, domain, resource, action, username, subjectIdentityType, (call_count + 1))
    elseif code >= ngx.HTTP_SPECIAL_RESPONSE then
        ngx.log(ngx.ERR, "Permit Response. Error Status: ", status, " Body: ", body, " Code: ", code)
        return false, nil
    end

    local json_response = json.decode(result)
    ngx.log(ngx.DEBUG, "Decision:" .. json_response.Response.Decision)
    if string.lower(json_response.Response.Decision) == "permit" then
        return true, nil
    else
        return false, nil
    end
end

local function get_permit_permissions(permit_properties, gsAuthnProperties, domain, resource, action, username, subjectIdentityType)
    local permit_cache_key = "permit:" .. ":" .. domain .. ":" .. resource .. ":" .. action .. ":" .. username

    ngx.log(ngx.DEBUG, "Cache format: permit::DOMAIN:RESOURCE:ACTION:SUBJECT Cache key: ", permit_cache_key)
    local remaining_ttl, probe_err, probe_has_permission = kong.cache:probe(permit_cache_key)

    if probe_err then
        return nil, probe_err
    end

    if remaining_ttl and remaining_ttl > 0 then
        ngx.log(ngx.DEBUG, "Results from cache for key:" .. permit_cache_key .. " and remaining ttl:" .. tostring(remaining_ttl))
        return probe_has_permission
    end

    kong.cache:invalidate_local(permit_cache_key)
    -- Gets result from get_gssso, stores it in cache, and then returns value/error
    local has_permission, permit_err = kong.cache:get(permit_cache_key, permit_properties.cache_opts, call_permit, permit_properties, gsAuthnProperties, domain, resource, action, username, subjectIdentityType, 0)

    if permit_err then
        return nil, permit_err
    end

    return has_permission, nil
end

local function extract_subject_identity(subjectIdentityLocation, subjectIdentityKey)
    if subjectIdentityLocation == HEADER then
        if not kong.request.get_header(subjectIdentityKey) then
            kong.log.err("Subject identity could not be determined. Expected subject identity at location: header key: ", subjectIdentityKey)
        end
        return kong.request.get_header(subjectIdentityKey)
    elseif subjectIdentityLocation == COOKIE then
        local cookie = resty_cookie:new()
        local request_cookies, _ = cookie:get_all()
        if not request_cookies then
            kong.log.err("No request cookie exists. Expected subject identity at location: cookie key: ", subjectIdentityKey)
            return nil
        end
        if not request_cookies[subjectIdentityKey] then
            kong.log.err("Subject identity could not be determined. Expected subject identity at location: cookie key: ", subjectIdentityKey)
        end
        return request_cookies[subjectIdentityKey]
    end

    return nil
end

local function do_authorize(permit_properties, conf)
    local username = extract_subject_identity(conf.subjectIdentityLocation, conf.subjectIdentityKey)
    if username == nil then
        error("Username could not be determined from request")
    end
    ngx.log(ngx.DEBUG, "Username in kong context: " .. username)

    local resource = conf.permitResource
    local action = conf.permitAction
    local domain = conf.permitPolicy

    local has_permission, permit_err = get_permit_permissions(permit_properties, conf.gsAuthnProperties, domain, resource, action, username, conf.subjectIdentityType)
    ngx.log(ngx.DEBUG, "Has permission: ", has_permission)

    if permit_err then
        ngx.log(ngx.CRIT, "Permit Error: ", permit_err)
        error(permit_err)
    end

    if not has_permission then
        error("User " .. username .. " doesn't have permissions to resource " .. resource .. " with action " .. action)
    end
end

local function handle_error(err)
    kong.log.err("Permit - Not authorized!", err)
    local trimmedError = string.match(string.match(err, ":(.*)"), ":(.*)")
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say(trimmedError)
    ngx.exit(ngx.status)
end

function permit:authorize(conf)
    xpcall(do_authorize, handle_error, self._permit_properties, conf)
end

if _G.TEST then
    permit._trim = trim
    permit._split = split
    permit._get_payload = get_payload
    permit._starts = starts
    permit._get_gssso = get_gssso
    permit._get_permit_token = get_permit_token
    permit._call_permit = call_permit
    permit._get_permit_permissions = get_permit_permissions
    permit._extract_subject_identity = extract_subject_identity
    permit._do_authorize = do_authorize
    permit._handle_error = handle_error
end

return permit
