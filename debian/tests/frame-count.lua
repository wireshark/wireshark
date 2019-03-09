do
    packets = 0;
    local function init_listener()
        local tap = Listener.new("frame")
        function tap.reset()
            packets = 0;
        end
        function tap.packet(pinfo,tvb, ip)
            packets = packets + 1
        end
        function tap.draw()
           print("Packet count:", packets)
           os.exit(0)
        end
    end
    init_listener()
end
