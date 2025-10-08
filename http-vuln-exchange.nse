local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local strbuf = require "strbuf"

description = [[
Check for Exchange Server CVEs CVE-2021-26855, CVE-2021-26857, CVE-2021-26858 and CVE-2021-27065
using Outlook Web App path data.

Known issues - requires a valid SSL certificate if using SSL/TLS

Originally based on source by onSec-fr and k4nfr3, thanks!
]]

---
--@output
--PORT    STATE SERVICE
--443/tcp open  https
--|_http-vuln-proxylogon: (15.1.2176) Exchange 2016 can't determine vulnerability status, check latest security update is applied (Exchange 2016 CU18 or CU19 installed)

author = "Kevin Beaumont"
license = "GPLv3"
categories = {"default", "discovery", "safe", "exploit"}

portrule = shortport.http

local last_len = 0

function split(source, delimiters)
    local elements = {}
    local pattern = '([^'..delimiters..']+)'
    string.gsub(source, pattern, function(value) elements[#elements + 1] =     value;  end);
    return elements
end

local function checkversion(w)
  local output = w .. "\n"
  local mytable = split(w, ".")

  -- Completely out support releases

  if w:find("^6.5.*") ~= nil then
                output = "Exchange 2003 - AT RISK as out of support!"

  elseif w:find("^8.*") ~= nil then
                output = "Exchange 2007 - AT RISK as out of support!"

  -- Exchange 2010 RTM had 14.0 build numbers - these need uplifting to at least Service Pack 2

  elseif w:find("^14.0.*") ~= nil then
           if tonumber(mytable[3]) < 727 then
           output = "Exchange 2010 VULNERABLE to Unified Messaging issues! (< 14 RTM version installed, no Service Packs)"
           end

  elseif w:find("^14.*") ~= nil then
                if tonumber(mytable[3]) < 496 then
                        output = "Exchange 2010 VULNERABLE to Unified Messaging issues! (< 14.*.496)"
                elseif tonumber(mytable[3]) == 496 then
                        output = "Exchange 2010 can't determine vulnerability status, check latest security update is applied (= 14.*.496)"
                else
                        output = "Exchange 2010 not vulnerable (>14.*.496)"
                end

  elseif w:find("^15.0.*") ~= nil then
                if tonumber(mytable[3]) < 1497 then
                        output = "Exchange 2013 VULNERABLE! (< 15.0.1496)"
                elseif  tonumber(mytable[3]) == 1497 then
                        output = "Exchange 2013 can't determine vulnerability status, check latest security update is applied (15.0.1497 Exchange 2013 CU23 installed)"
                else
                        output = "Exchange 2013 not vulnerable (>15.0.1497)"
                end

  elseif w:find("^15.1.*") ~= nil then
                if tonumber(mytable[3]) == 2176 or tonumber(mytable[3]) == 2106 then
                        output = "Exchange 2016 can't determine vulnerability status, check latest security update is applied (Exchange 2016 CU18 or CU19 installed)"
                elseif tonumber(mytable[3]) < 2106 then
                        output = "Exchange 2016 VULNERABLE! (< 15.1.2106)"
                else
                        output = "Exchange 2016 not vulnerable (> 15.1.2176)"
                end

  elseif w:find("^15.2.*") ~= nil then
                if tonumber(mytable[3]) == 792 or tonumber(mytable[3]) == 721 then
                        output = "Exchange 2019 can't determine vulnerability status, check latest security update is applied (Exchange 2019 CU7 or CU8 installed)"
                elseif tonumber(mytable[3]) < 720 then
                        output = "Exchange 2019 VULNERABLE !!! (< 15.2.720)"
                else
                        output = "Exchange 2019 not vulnerable (> 15.2.792)"
                end
  else
                output = "Exchange " .. w
  end
  return "(" .. w .. ") " .. output
end

-- parse all disallowed entries in body and add them to a strbuf
local function parse_answer(body)
  local found = false
  for line in body:gmatch("[^\r\n]+") do
    for w in line:gmatch('/owa/%d+.%d.%d+') do
      w = string.gsub(w,"/owa/","")
      found = true
          return checkversion(w)
    end
    for w in line:gmatch('/owa/auth/%d+.%d.%d+') do
      w = string.gsub(w,"/owa/auth/","")
      found = true
          return checkversion(w)
    end

  end
  if found == false then
         return "no owa version found"
  end
end

action = function(host, port)
  local dis_count, noun
  options = {header={}}    options['header']['User-Agent'] = "Mozilla/5.0 (Exchange check)"
  local answer = http.get(host, port, "/owa", options )

  if answer.status == 302 then
    return "Error 302 " .. answer.location
  elseif answer.status ~= 200 then
    return "Error " .. tostring(answer.status) .. " for /owa"
  end

  local v_level = nmap.verbosity() + (nmap.debugging()*2)
  local output = strbuf.new()
  local detail = 15

  output = parse_answer(answer.body)

  return output
end
