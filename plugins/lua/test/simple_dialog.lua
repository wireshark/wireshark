function dialog_menu()

    function dialog_func(datum,a,b,c)
        local win = TextWindow.new("Result");
        win:set("one: " .. a .."\ntwo: " .. b .. "\nthree: " .. c .. "\n");
    end
        
    dialog("Dialog Test",dialog_func,nil,"one","two","three")

end

register_menu("Lua Dialog Test",dialog_menu)

