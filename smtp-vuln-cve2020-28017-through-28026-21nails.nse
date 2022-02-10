
--
-- Libraries
--
local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

--
-- Description
--
description = [[

Exim remote code execution via CVE-2020-28017 through CVE-2020-28026 also known as 21Nails

We check for the presence of the vulnerability via:
  - Connecting to port 25
  - Receiving the banner
  - Checking the version
  - Returning the state

This check is not intrusive, because:
 - We only complete a TCP connection to the port
 - We do not complete the SMTP protocol handshake

This check may have False Positives if:
  - Patches are back ported but the version number is not updated

This check may have False Negatives if:
  - the Exim server is configured to remove Exim and/or the version number

How to use:
  nmap --script ./smtp-vuln-cve2020-28017-through-28026-21nails.nse [target]

References:
* https://www.qualys.com/2021/05/04/21nails/21nails.txt

]]

--
-- Author
--
author = "Ollie Whitehouse at NCC Group for NCSC UK Industry 100"

--
-- License
---
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

--
-- Categories
--
categories = {"safe", "vuln"}

--
-- Helper function to tidy up the socket
--
local function smtp_finish(socket, status, msg)
        if socket then
                socket:close()
        end
        return status, msg
end

--
-- Helper function to get the Exim banner
--
local function get_exim_banner(response)
        local banner, version
        banner = response:match("%d+%s(.+)")
        if banner and banner:match("Exim") then
                version = tonumber(banner:match("Exim%s([0-9%.]+)"))
        end
        return banner, version
end

--
-- Our checker function
--
local function check_vuln(vulnin,host,port)

        local vuln = vulnin

        -- https://nmap.org/nsedoc/lib/vulns.html
        vuln.state = vulns.STATE.NOT_VULN

        local smtp_server = {}

        -- Vulnerable versions below
        local exim_ver_max = 4.94

        -- Connect
        local socket, ret = smtp.connect(host,
                          port,
                          {ssl = true,
                          timeout = 10000,
                          recv_before = true,
                          lines = 1})
        if not socket then
                return smtp_finish(nil, socket, ret)
        end

        smtp_server.banner, smtp_server.version = get_exim_banner(ret)
        if not smtp_server.banner then
                return smtp_finish(socket, false, 'failed to read the SMTP banner.')
        elseif not smtp_server.banner:match("Exim") then
                return smtp_finish(socket, false, 'no Exim banner')
        end

        vuln.extra_info = {}
        if smtp_server.version then
                if smtp_server.version <= exim_ver_max then
                        vuln.state = vulns.STATE.LIKELY_VULN
                        -- table.insert(vuln.extra_info, string.format("Exim version: %.02f", smtp_server.version))
                end
        end
        return vuln
end

--
-- NMAP portrule function
--
portrule = shortport.port_or_service({25, 465, 587},{"smtp", "smtps", "submission"})

--
-- NMAP action function
--
action = function(host, port)

        -- Definition of the vulnerability
        local   vuln = {
                        title = 'Exim remote code execution via CVE-2020-28017 through CVE-2020-28026 also known as 21Nails',
                        IDS = {CVE = 'CVE-2020-28017' },
                        risk_factor = "High",
                        scores = {
                                CVSSv2 = "10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)",
                        },
                        description = [[
In May 2021 21 vulnerabilities were disclosed in the Exim mailserver. Of these 10 were remote
vulnerabilities that could yield among other things remote code execution and memory contents
revelation remotely. For a significant majority of the vulnerabilities they have been present
since at least 2004 in the code base.
                        ]],
                        references = {
                                'https://www.qualys.com/2021/05/04/21nails/21nails.txt',
                        },
                        dates = {
                                disclosure = {year = '2021', month = '05', day = '04'},
                        }
                }


        -- Build the report skeleton
        local report = vulns.Report:new(SCRIPT_NAME, host, port)

        -- Check if vulnerable
        local status, err = check_vuln(vuln, host, port)
        if not status then
                return nil
        end

        -- Return it
        return report:make_output(vuln)
end

