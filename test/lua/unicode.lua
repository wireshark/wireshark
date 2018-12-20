--
-- Unicode tests
--

local errors = 0

function assertEqual(what, a, b)
    if a == b then
        return true
    end
    print('ERROR:', what)
    print('Expected:', tostring(a))
    print('  Actual:', tostring(b))
    errors = errors + 1
end

-- script name check
local scriptname = (debug.getinfo(1, 'S').source or ''):gsub("^@.*[/\\]", "")
assertEqual('script name', 'script-Ф-€-中.lua', scriptname)

-- loadfile
local code, err = loadfile('load-Ф-€-中.lua')
assertEqual('loadfile', nil, err)
assertEqual('loadfile contents', 'Contents of Ф-€-中', code and code())

-- dofile
local ok, result = pcall(dofile, 'load-Ф-€-中.lua')
assertEqual('dofile pcall', true, ok)
assertEqual('dofile contents', 'Contents of Ф-€-中', result)

-- io.open (read)
local fr, err = io.open('load-Ф-€-中.lua')
assertEqual('io.open (read)', nil, err)
assertEqual('io.read', 'return "Contents of Ф-€-中"\n', fr and fr:read('*a'))
if fr then fr:close() end

-- io.open (write)
local fw, err = io.open('written-by-lua-Ф-€-中.txt', 'w')
assertEqual('io.open (write)', nil, err)
if fw then
    local _, err = fw:write('Feedback from Lua: Ф-€-中\n')
    assertEqual('io.write', nil, err)
end
if fw then fw:close() end

-- Check for Unicode in personal plugins directory path.
local pdir_expected = 'unicode-Ф-€-中-testcases'
local pdir = Dir.personal_plugins_path()
pdir = pdir:gsub('.*[/\\]unicode-.*-.*-testcases[/\\].*', pdir_expected)
assertEqual('Unicode in Dir.personal_plugins_path', pdir_expected, pdir)

if errors ~= 0 then
    error('Failed tests: ' .. errors)
end
print("All tests passed!")
