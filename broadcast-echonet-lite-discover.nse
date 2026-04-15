local nmap = require "nmap"
local stdnse = require "stdnse"
local packet = require "packet"
local ipOps = require "ipOps"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Discovers ECHONET Lite nodes on the local network by sending a multicast
INF_REQ to 224.0.23.0:3610 and listening for replies.

The script requests EPC 0xD6 (Self-node instance list S) from the
Node Profile object (0EF001), then parses and prints the EOJ list
returned by responding devices.

This script is intended for authorized discovery on networks you own
or are explicitly permitted to test.
]]

---
-- @usage
-- nmap --script broadcast-echonet-lite-discover -e eth0
-- nmap --script broadcast-echonet-lite-discover --script-args 'broadcast-echonet-lite-discover.timeout=5s' -e wlan0
--
-- @args broadcast-echonet-lite-discover.timeout  Maximum listen time. Default: 3s
--
-- @output
-- Pre-scan script results:
-- | broadcast-echonet-lite-discover:
-- |   Interface: eth0
-- |     192.168.1.20
-- |       SEOJ: 0EF001
-- |       D6 count: 3
-- |       EOJs:
-- |         013001
-- |         029001
-- |         026F01
-- |_  Use the newtargets script-arg to add discovered IPs as scan targets

author = "OpenAI"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe", "discovery"}

prerule = function()
  if not nmap.is_privileged() then
    stdnse.verbose1("Not running: requires privileged mode for packet capture.")
    return false
  end
  return true
end

local MCAST_IP = "224.0.23.0"
local MCAST_PORT = 3610

local function hex3(a, b, c)
  return string.format("%02X%02X%02X", a, b, c)
end

local function get_interfaces()
  local function filter(iface)
    return iface
      and iface.up == "up"
      and iface.address
      and iface.address:match("^%d+%.%d+%.%d+%.%d+$")
  end
  return stdnse.get_script_interfaces(filter)
end

local function choose_interface(interfaces)
  if #interfaces == 1 then
    return interfaces[1]
  end

  -- Prefer interface selected with -e, if NSE exposes only that one, it will be in the list.
  -- Otherwise, pick the one used to route to the multicast address.
  local sock = nmap.new_socket()
  local status = sock:connect(MCAST_IP, MCAST_PORT, "udp")
  if status then
    local ok, address = sock:get_info()
    sock:close()
    if ok and address then
      for _, iface in ipairs(interfaces) do
        if iface.address == address then
          return iface
        end
      end
    end
  else
    sock:close()
  end

  return interfaces[1]
end

local function build_inf_req_d6()
  -- EHD   1081
  -- TID   0001
  -- SEOJ  05FF01  (controller)
  -- DEOJ  0EF001  (node profile)
  -- ESV   63      (INF_REQ)
  -- OPC   01
  -- EPC   D6      (self-node instance list S)
  -- PDC   00
  return string.char(
    0x10, 0x81,
    0x00, 0x01,
    0x05, 0xFF, 0x01,
    0x0E, 0xF0, 0x01,
    0x63,
    0x01,
    0xD6,
    0x00
  )
end

local function send_query()
  local sock = nmap.new_socket()
  local ok, err = sock:connect(MCAST_IP, MCAST_PORT, "udp")
  if not ok then
    return false, err
  end

  local payload = build_inf_req_d6()
  local sent, send_err = sock:send(payload)
  sock:close()

  if not sent then
    return false, send_err
  end
  return true
end

local function parse_echonet_frame(data)
  if not data or #data < 12 then
    return nil, "too short"
  end

  local b = { data:byte(1, #data) }

  if b[1] ~= 0x10 or b[2] ~= 0x81 then
    return nil, "not ECHONET Lite"
  end

  local frame = {
    tid  = b[3] * 256 + b[4],
    seoj = hex3(b[5], b[6], b[7]),
    deoj = hex3(b[8], b[9], b[10]),
    esv  = b[11],
    opc  = b[12],
    props = {}
  }

  local pos = 13
  for _ = 1, frame.opc do
    if pos + 1 > #b then
      return nil, "truncated property header"
    end

    local epc = b[pos]
    local pdc = b[pos + 1]
    pos = pos + 2

    if pos + pdc - 1 > #b then
      return nil, "truncated EDT"
    end

    local edt = {}
    for i = 1, pdc do
      edt[#edt + 1] = b[pos + i - 1]
    end
    pos = pos + pdc

    frame.props[#frame.props + 1] = {
      epc = epc,
      pdc = pdc,
      edt = edt
    }
  end

  return frame
end

local function parse_d6(edt)
  if not edt or #edt < 1 then
    return nil
  end

  local count = edt[1]
  local eojs = {}

  local remaining = #edt - 1
  local n = math.floor(remaining / 3)
  for i = 1, n do
    local base = 2 + (i - 1) * 3
    eojs[#eojs + 1] = string.format(
      "%02X%02X%02X",
      edt[base], edt[base + 1], edt[base + 2]
    )
  end

  return { count = count, eojs = eojs }
end

local function listen_for_replies(interface, timeout_ms, results)
  local condvar = nmap.condvar(results)
  local start = nmap.clock_ms()

  local listener = nmap.new_socket()
  listener:set_timeout(100)

  -- Capture UDP responses to our interface on port 3610.
  -- Some devices unicast their reply back to us.
  local filter = string.format("dst host %s and udp src port 3610", interface.address)
  local ok, err = listener:pcap_open(interface.device, 1500, true, filter)
  if not ok then
    results._error = "pcap_open failed: " .. (err or "unknown error")
    condvar("signal")
    return
  end

  while (nmap.clock_ms() - start) < timeout_ms do
    local status, _, _, l3data = listener:pcap_receive()
    if status and l3data then
      local p = packet.Packet:new(l3data, #l3data)
      local ip_header_len = p.ip_hl * 4
      local udp_payload = string.sub(l3data, ip_header_len + 8 + 1)

      local frame = parse_echonet_frame(udp_payload)
      if frame then
        -- Keep replies that include D6.
        local entry = {
          ip = p.ip_src,
          seoj = frame.seoj,
          deoj = frame.deoj,
          esv = frame.esv,
          d6 = nil
        }

        for _, prop in ipairs(frame.props) do
          if prop.epc == 0xD6 then
            entry.d6 = parse_d6(prop.edt)
          end
        end

        if entry.d6 then
          if not results[entry.ip] then
            results[entry.ip] = entry
          end
        end
      end
    end
  end

  listener:close()
  condvar("signal")
end

action = function()
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  timeout = (timeout or 3) * 1000

  local interfaces = get_interfaces()
  if not interfaces or #interfaces == 0 then
    return stdnse.format_output(false, "No usable IPv4 interface found. Try -e <iface>.")
  end

  local interface = choose_interface(interfaces)
  if not interface then
    return stdnse.format_output(false, "Could not select an interface.")
  end

  local results = {}
  stdnse.new_thread(listen_for_replies, interface, timeout, results)

  -- Give listener a moment to start.
  stdnse.sleep(0.3)

  local ok, err = send_query()
  if not ok then
    return stdnse.format_output(false, "Send failed: " .. (err or "unknown error"))
  end

  local condvar = nmap.condvar(results)
  condvar("wait")

  if results._error then
    return stdnse.format_output(false, results._error)
  end

  local output = {}
  output[#output + 1] = ("Interface: %s"):format(interface.device)

  local found = false
  for ip, entry in pairs(results) do
    found = true
    output[#output + 1] = ("  %s"):format(ip)
    output[#output + 1] = ("    SEOJ: %s"):format(entry.seoj)
    output[#output + 1] = ("    D6 count: %d"):format(entry.d6.count)
    output[#output + 1] = "    EOJs:"
    for _, eoj in ipairs(entry.d6.eojs) do
      output[#output + 1] = ("      %s"):format(eoj)
    end

    if target.ALLOW_NEW_TARGETS then
      target.add(ip)
    end
  end

  if not found then
    return nil
  end

  if not target.ALLOW_NEW_TARGETS then
    output[#output + 1] = "Use the newtargets script-arg to add discovered IPs as scan targets"
  end

  return stdnse.format_output(true, output)
end