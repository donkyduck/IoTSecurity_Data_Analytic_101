local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Queries an authorized ECHONET Lite node on UDP/3610 and requests the
Node Profile self-node instance list (EPC 0xD6). The script parses
the returned EOJ list and prints discovered instances.

This script is intended for discovery/fingerprinting on systems you own
or are explicitly authorized to test.
]]

---
-- @usage
-- nmap -sU -p 3610 --script echonet-lite-info <target>
--
-- @args echonet-lite-info.timeout  Socket timeout in milliseconds (default 3000)
--
-- @output
-- PORT     STATE SERVICE
-- 3610/udp open|filtered
-- | echonet-lite-info:
-- |   ESV: 0x73
-- |   SEOJ: 0EF001
-- |   DEOJ: 05FF01
-- |   EPC: 0xD6
-- |   Instances declared: 3
-- |   EOJs:
-- |     013001
-- |     029001
-- |_    026F01

author = "OpenAI"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(3610, "unknown", "udp")

local function hexify(s)
  return (s:gsub(".", function(c) return string.format("%02X", string.byte(c)) end))
end

local function bytes_to_u16(b1, b2)
  return b1 * 256 + b2
end

local function parse_response(data)
  -- Minimum ECHONET Lite frame:
  -- EHD1 EHD2 TID(2) SEOJ(3) DEOJ(3) ESV OPC [props...]
  if not data or #data < 12 then
    return nil, "response too short"
  end

  local b = { data:byte(1, #data) }

  local ehd1, ehd2 = b[1], b[2]
  if ehd1 ~= 0x10 or ehd2 ~= 0x81 then
    return nil, string.format("unexpected EHD %02X%02X", ehd1, ehd2)
  end

  local tid = bytes_to_u16(b[3], b[4])
  local seoj = string.format("%02X%02X%02X", b[5], b[6], b[7])
  local deoj = string.format("%02X%02X%02X", b[8], b[9], b[10])
  local esv  = b[11]
  local opc  = b[12]

  local pos = 13
  local props = {}

  for _ = 1, opc do
    if pos + 1 > #b then
      return nil, "truncated property header"
    end

    local epc = b[pos]
    local pdc = b[pos + 1]
    pos = pos + 2

    if pos + pdc - 1 > #b then
      return nil, "truncated property data"
    end

    local edt = {}
    for i = 1, pdc do
      edt[#edt + 1] = b[pos + i - 1]
    end
    pos = pos + pdc

    props[#props + 1] = {
      epc = epc,
      pdc = pdc,
      edt = edt
    }
  end

  return {
    tid = tid,
    seoj = seoj,
    deoj = deoj,
    esv = esv,
    opc = opc,
    props = props
  }
end

local function parse_d6_instance_list(edt)
  -- D6 format:
  -- byte 1 = count (or overflow indicator)
  -- bytes 2.. = EOJ list, 3 bytes each
  if not edt or #edt < 1 then
    return nil, "empty D6 payload"
  end

  local count = edt[1]
  local eojs = {}

  if #edt >= 2 then
    local remaining = #edt - 1
    local n = math.floor(remaining / 3)
    for i = 1, n do
      local base = 2 + (i - 1) * 3
      eojs[#eojs + 1] = string.format("%02X%02X%02X", edt[base], edt[base + 1], edt[base + 2])
    end
  end

  return {
    count = count,
    eojs = eojs
  }
end

action = function(host, port)
  local timeout = stdnse.get_script_args("echonet-lite-info.timeout") or 3000
  timeout = tonumber(timeout) or 3000

  local sock = nmap.new_socket("udp")
  sock:set_timeout(timeout)

  local status, err = sock:connect(host.ip, port.number)
  if not status then
    return "connect failed: " .. (err or "unknown error")
  end

  -- Build ECHONET Lite INF_REQ:
  -- EHD   = 0x1081
  -- TID   = 0x0001
  -- SEOJ  = 05FF01 (controller class)
  -- DEOJ  = 0EF001 (node profile object)
  -- ESV   = 0x63   (INF_REQ)
  -- OPC   = 0x01
  -- EPC   = 0xD6   (self-node instance list S)
  -- PDC   = 0x00   (request; no EDT)
  local payload = string.char(
    0x10, 0x81,
    0x00, 0x01,
    0x05, 0xFF, 0x01,
    0x0E, 0xF0, 0x01,
    0x63,
    0x01,
    0xD6,
    0x00
  )

  local ok, send_err = sock:send(payload)
  if not ok then
    sock:close()
    return "send failed: " .. (send_err or "unknown error")
  end

  local rcv_status, data = sock:receive_bytes(4096)
  sock:close()

  if not rcv_status or not data then
    return nil
  end

  local parsed, parse_err = parse_response(data)
  if not parsed then
    return "received non-decodable response: " .. (parse_err or "unknown parse error")
  end

  local out = {}
  out[#out + 1] = string.format("ESV: 0x%02X", parsed.esv)
  out[#out + 1] = "SEOJ: " .. parsed.seoj
  out[#out + 1] = "DEOJ: " .. parsed.deoj

  local got_d6 = false
  for _, prop in ipairs(parsed.props) do
    out[#out + 1] = string.format("EPC: 0x%02X", prop.epc)

    if prop.epc == 0xD6 then
      got_d6 = true
      local d6, d6err = parse_d6_instance_list(prop.edt)
      if not d6 then
        out[#out + 1] = "D6 parse error: " .. (d6err or "unknown")
      else
        out[#out + 1] = string.format("Instances declared: %d", d6.count)
        if #d6.eojs > 0 then
          out[#out + 1] = "EOJs:"
          for _, eoj in ipairs(d6.eojs) do
            out[#out + 1] = "  " .. eoj
          end
        end
      end
    else
      out[#out + 1] = "Raw EDT: " .. hexify(string.char(table.unpack(prop.edt)))
    end
  end

  if not got_d6 then
    out[#out + 1] = "No D6 property in response"
  end

  return stdnse.format_output(true, out)
end