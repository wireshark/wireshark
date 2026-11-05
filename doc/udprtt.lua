-- Time from a UDP request to its reply in the same stream,
-- like dns.time for DNS, for any protocol over UDP

local udprtt    = Proto("udprtt", "UDP Response Time")
local f_rtt     = ProtoField.relative_time("udprtt.time", "Time since request")
local f_request = ProtoField.framenum("udprtt.request", "Request in frame",
                                      base.NONE, frametype.REQUEST)
udprtt.fields   = { f_rtt, f_request }
local f_stream  = Field.new("udp.stream")
local f_time    = Field.new("frame.time")
local timeout   = NSTime(2, 0)  -- later replies are not matched
local state     = {}

function state:reset()
  self.stream = {}  -- stream index -> client address:port and latest request
  self.reply  = {}  -- frame number -> request answered by this frame
end

function udprtt.init()
  state:reset()
end

function udprtt.dissector(tvb, pinfo, tree)
  local stream = f_stream()
  if not stream then return end
  local id  = stream.value
  local now = f_time().value

  if not pinfo.visited then
    local src = tostring(pinfo.src) .. ":" .. pinfo.src_port
    local s = state.stream[id] or { client = src }
    state.stream[id] = s
    if src == s.client then
      s.request = { frame = pinfo.number, time = now }
    elseif s.request and now - s.request.time <= timeout then
      state.reply[pinfo.number] = s.request
    end
  end

  local request = state.reply[pinfo.number]
  if request then
    local subtree = tree:add(udprtt)
    subtree:add(f_request, request.frame)
    subtree:add(f_rtt, now - request.time)
  end
end

register_postdissector(udprtt)
