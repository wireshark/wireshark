-- text_window_tap.lua
-- $Id$
--
-- (C) 2006 Luis E. G. Ontanon <luis.ontanon@gmail.com>
--
-- an example of a tap that registers a menu
-- and prints to a text window

instances = 0 -- number of instances of the tap created so far

function mytap_menu()
    instances = instances + 1

    local td = {}
    -- the tap data, passed to every function of the tap
    -- beware not to use a global for taps with multiple instances or you might find 
    
    td.win = TextWindow.new("My Tap " .. instances) -- the window we'll use
    td.text = "" -- the text of the tap
    td.instance = instances -- the instance number of this tap

    -- this tap will be local to the menu_function that called it
    -- it's called mytap#
    -- has no filter (filter = nil)
    -- and we pass to it the tap data so that it gets passed to the tap's functions
    local tap = new_tap("mytap"..instances,nil, td)
    
    -- make sure the tap doesn't hang arround after the window was closed
    td.win:at_close(remove_tap,tap)

    -- this function will be called for every packet
    function tap.packet(pinfo,tapdata) 
        local text = "packet " .. pinfo.number
        tapdata.text = tapdata.text .. "\n" .. text
        -- print("packet " .. pinfo.number, tapdata.instance)
    end

    -- this function will be called once every few seconds to redraw the window
    function tap.draw(tapdata) 
        tapdata.win:set(tapdata.text)
        -- print("draw", tapdata.instance)
    end

    -- this function will be called before every run of the tap
    function tap.init(tapdata) 
        tapdata.text = ""
        -- print("init", tapdata.instance)
    end

end

-- last we register the menu
-- the first arg is the menu name
-- the 2nd arg is the function to be called
-- the third argument (defaults to false) tells to re-run the capture once the function is run
register_menu("Lua Tap Test",mytap_menu,true)

-- print("registered")
