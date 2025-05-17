target("gemini_test", function () 
    set_kind("binary")
    add_files("src/gemini_test.cpp")
    add_includedirs("include", {public = true})
end)

