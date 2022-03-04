local nmap = require("nmap")
local shortport = require("shortport")


description = [[
Retrieves version and model info from the INFO CONFIG message on printers
that support the Printer Job Language. This includes most PostScript printers
that listen on port 9100. 
]]

author = "Aaron Adams"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "intrusive" }

---
-- @usage
-- nmap -p 443 --script pjl-info-config <ip>
--
-- @output
-- 9100/tcp open  jetdirect
-- |_pjl-info-config: "Model: Lexmark MC3224dwe, Version: CXLBL.075.272"
--

portrule = shortport.port_or_service(9100, "jetdirect")

local function parse_id(response)
  local msg
  local line

  for line in response:gmatch(".-\n") do
    if string.match(line, "^[^@].-\n") then
      return line:gsub('[\r\n"]', "")
    end
  end
end

local function parse_config(response)
  local msg

  for line in response:gmatch(".-\n") do
    msg = line:match('^SYSTEM FIRMWARE VERSION=(.*)')
    if msg then
      return msg:gsub('[\r\n"]', "")
    end
  end
end

action = function(host, port)
  local idmsg --stores the PJL command to get the printer's ID
  local configmsg --stores the PJL command to get the printer's config
  local response --stores the response sent over the network from the printer
  local model --stores the model from PJL INFO command
  local version --stores the version from PJL CONFIG command

  idmsg = "@PJL INFO ID\r\n"

  local socket = nmap.new_socket()
  socket:set_timeout(15000)
  local try = nmap.new_try(function()
    socket:close()
  end)
  try(socket:connect(host, port))
  try(socket:send(idmsg)) --this block gets the current id
  local data
  response, data = socket:receive()
  if not response then --send an initial probe. If no response, send nothing further.
    socket:close()
    if nmap.verbosity() > 0 then
      return "No response from printer: " .. data
    else
      return nil
    end
  end

  model = parse_id(data)
  if not model then
    if nmap.verbosity() > 0 then
      return "Error reading printer response: " .. data
    else
      return nil
    end
  end

  configmsg = "@PJL INFO CONFIG\r\n"
  try(socket:send(configmsg))

  response, data = socket:receive()
  if not response then
    socket:close()
  end
  version = parse_config(data)
  if not version then
    socket:close()
    return '"Model: ' .. model .. '"'
  end

  socket:close()

  return '"Model: ' .. model .. ', Version: ' .. version .. '"'
end
