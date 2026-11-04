-- Time since the previous frame of the same UDP stream,
-- what tcp.time_delta shows for TCP

local udpdelta  = Proto("udpdelta", "UDP Stream Timing")
local f_delta   = ProtoField.double("udpdelta.time",
                                    "Time since previous stream frame")
udpdelta.fields = { f_delta }
local f_stream  = Field.new("udp.stream")
local state     = {}

function state:reset()
  self.last  = {}  -- stream index -> time of latest frame
  self.delta = {}  -- frame number -> seconds since previous frame
end

function udpdelta.init()
  state:reset()
end

function udpdelta.dissector(tvb, pinfo, tree)
  local stream = f_stream()
  if not stream then return end

  if state.delta[pinfo.number] == nil then
    local previous = state.last[stream.value]
    state.delta[pinfo.number] = previous and pinfo.abs_ts - previous or 0
    state.last[stream.value] = pinfo.abs_ts
  end

  tree:add(udpdelta):add(f_delta, state.delta[pinfo.number])
end

register_postdissector(udpdelta)
