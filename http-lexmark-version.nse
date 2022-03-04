local http = require("http")
local json = require("json")
local shortport = require("shortport")

description = [[
Parses a Lexmark device model and version from a number of URLs that are typically exposed by default to the guest user
]]

author = "Aaron Adams"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "discovery", "safe" }

---
-- @usage
-- nmap -p 443 --script http-lexmark-version <ip>
--
-- @output
--PORT    STATE SERVICE
--443/tcp open  https
--|_http-lexmark-version: "Model: Lexmark MC3224dwe, Version: CXLBL.075.272"
--

portrule = shortport.port_or_service(443, "https")

local function get_version(host, port)
  local version = nil
  local version_url = "/webglue/rawcontent?&c=Status&lang=en"
  local resp = http.get(host, port, version_url)

  if resp.location or not resp.body then
    return version
  end

  local status, json = json.parse(resp.body)
  version = json["nodes"]["nodes"]["DeviceFirmwareLevel"]["text"]["text"]

  return version
end

local function get_model(host, port)
  local model = nil
  local model_url = "/"
  local resp = http.get(host, port, model_url)

  if resp.location or not resp.body then
    return model
  end

  for line in resp.body:gmatch(".-\n") do
    if string.match(line, "<[Tt][Ii][Tt][Ll][Ee]>.-") then
      for str in string.gmatch(line:gsub("\n", ""), ".->(.-)</.-") do
        if str ~= "" then
          model = str
          return model
        end
      end
    end
  end

  return model
end

action = function(host, port)
  local version
  local model

  version = get_version(host, port)
  model = get_model(host, port)

  if model and version then
    return '"Model: ' .. model .. ", Version: " .. version .. '"'
  end
end
