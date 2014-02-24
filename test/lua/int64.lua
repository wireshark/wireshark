
-- This is a test script for tshark/wireshark.
-- This script runs inside tshark/wireshark, so to run it do:
-- wireshark -X lua_script:<path_to_testdir>/lua/int64.lua
-- tshark -r bogus.cap -X lua_script:<path_to_testdir>/lua/int64.lua

-- Tests Int64/UInt64 functions

local function testing(...)
    print("---- Testing "..tostring(...).." ----")
end

local function test(name, ...)
    io.stdout:write("test "..name.."...")
    if (...) == true then
        io.stdout:write("passed\n")
    else
        io.stdout:write("failed!\n")
        error(name.." test failed!")
    end
end

-- you can't compare (use the '==') userdata objects with numbers, so this function does it instead.
function checkeq(arg1,arg2)
    if arg1 == arg2 then
        return true
    elseif type(arg1) == 'userdata' and arg1.tonumber then
        if type(arg2) == 'userdata' and arg2.tonumber then
            return arg1:tonumber() == arg2:tonumber()
        else
            return arg1:tonumber() == arg2
        end
    elseif type(arg2) == 'userdata' and arg2.tonumber then
        return arg1 == arg2:tonumber()
    else
        return false
    end
end

-----------------------------

testing("Int64/UInt64 library")

local testtbl = { { ["type"]=Int64, ["name"]="Int64" } , { ["type"]=UInt64, ["name"]="UInt64" } }

for i,t in ipairs(testtbl) do

    local function testing(...)
        print("---- Testing "..t.name..": "..tostring(...).." ----")
    end

    local function test(name, ...)
        io.stdout:write("test "..t.name.."-"..name.."...")
        if (...) == true then
            io.stdout:write("passed\n")
        else
            io.stdout:write("failed!\n")
            error(name.." test failed!")
        end
    end

    testing("class")
    local obj = t.type

    for name, val in pairs(obj) do
        print("\t"..name.." = "..type(val))
    end

    test("class1",type(obj) == 'table')
    test("class2",type(obj.new) == 'function')
    test("class3",type(obj.max) == 'function')
    test("class4",type(obj.min) == 'function')
    test("class5",type(obj.tonumber) == 'function')
    test("class6",type(obj.fromhex) == 'function')
    test("class7",type(obj.tohex) == 'function')
    test("class8",type(obj.higher) == 'function')
    test("class9",type(obj.lower) == 'function')


    testing("new, tonumber, tostring")
    local val = 12345
    local my64a = obj.new(val)
    local my64b = obj.new(tostring(val))
    local zero = obj.new(0)
    -- remember in Lua it's a double, so only precise up to 9,007,199,254,740,992
    local my64c = obj.new(val,100)
    local valc = (100 * 4294967296) + val
    print(tostring(my64c))
    local my64z = obj.new(0,0)
    local my64d = obj.new(0,100)
    local vald = (100 * 4294967296)

    test("new1",checkeq(my64a,val))
    test("new2",checkeq(my64b,val))
    test("new3",checkeq(my64a,obj.new(my64b)))
    test("new3b",checkeq(my64a,obj(my64b)))
    test("new4",checkeq(valc,my64c))
    test("new5",checkeq(0,my64z))
    test("new6",obj.new(0,1):tonumber() == (2^32))
    if t.name == "Int64" then
        test("new7",obj(-1):tonumber() == -1)
        test("new8",obj.new(0,-1):tonumber() == -4294967296)
        test("new9",obj(obj.new(-1)):tonumber() == -1)
    end

    test("tonumber1",val == my64a:tonumber())
    test("tonumber2",valc == my64c:tonumber())
    test("tonumber3",vald == my64d:tonumber())
    test("tonumber4",0 == my64z:tonumber())

    test("tostring1", tostring(my64a)==tostring(val))
    test("tostring2",tostring(my64b)==tostring(val))
    test("tostring3",tostring(my64c)==tostring(valc))
    test("tostring4",tostring(my64d)==tostring(vald))


    testing("compare ops")

    test("eq", my64a == my64b)

    test("le1", my64a <= my64b)
    test("le2", my64a <= my64c)
    test("le3", my64z <= my64c)

    test("ge1", my64a >= my64b)
    test("ge2", my64c >= my64b)
    test("ge2", my64c >= my64z)

    test("neq1",not(my64a ~= my64b))
    test("neq2",my64a ~= obj(0))
    test("neq2",my64a ~= my64c)

    test("gt1",my64a > my64z)
    test("gt2",my64c > my64a)

    test("lt1",not(my64a < my64b))
    test("lt2",my64a < my64c)


    testing("math ops")

    test("add1",checkeq(my64a + my64b, val + val))
    test("add2",my64a + my64z == my64b)
    test("add3",my64a + my64b == my64b + my64a)
    test("add4",my64d + my64a == my64c)
    test("add5",checkeq(my64a + vald, valc))
    test("add6",checkeq(vald + my64a, valc))

    test("sub1",checkeq(my64a - my64b, 0))
    test("sub2",my64a - my64b == my64z)
    test("sub3",my64a - my64b == my64b - my64a)
    test("sub4",my64c - my64a == my64d)
    test("sub5",checkeq(my64a - val, 0))

    test("mod1",checkeq(my64a % my64b, 0))
    test("mod2",checkeq(my64c % my64b, valc % val))
    test("mod3",checkeq(my64c % val, valc % val))
    test("mod4",checkeq(val % my64c, val % valc))

    test("div1",checkeq(my64a / my64b, 1))
    test("div2",checkeq(my64a / val, 1))
    test("div3",checkeq(val / my64a, 1))
    test("div4",my64c / my64d == obj.new(1))

    test("pow1",checkeq(my64a ^ 1, val))
    test("pow2",checkeq(my64a ^ obj.new(2), val ^ 2))
    test("pow3",checkeq(my64a ^ obj.new(3), val ^ 3))
    test("pow4",checkeq(my64c ^ 1, valc ^ 1))

    test("mul1",checkeq(my64a * obj(1), my64b))
    test("mul2",checkeq(my64a * my64b, my64b * my64a))
    test("mul3",checkeq(my64a * 1, my64b))
    test("mul4",checkeq(2 * my64c, 2 * valc))

    if t.name == "Int64" then
        -- unary minus on UInt64 is illogical, but oh well
        test("unm1",checkeq(-my64a,-val))
        test("unm2",checkeq(string.sub(tostring(-my64a),1,1), "-"))
        test("unm3",checkeq(-my64c,-valc))
    else
        test("unm1",checkeq(-my64a,val))
        test("unm2",checkeq(string.sub(tostring(-my64a),1,1), "1"))
        test("unm3",checkeq(-my64c,valc))
    end
    test("unm4",checkeq(-my64z,0))

    testing("methods")

    test("higher1",my64a:higher() == 0)
    test("higher2",my64c:higher() == 100)

    test("lower1",my64a:lower() == val)
    test("lower2",my64c:lower() == val)
    test("lower3",my64d:lower() == 0)

    local vale1 = 3735928559  -- yields hex of deadbeef
    local vale2 = 5045997  -- yields 4cfeed
    local my64e = obj.new(vale1, vale2)
    test("fromhex1",obj.fromhex("0000000000003039") == my64a);
    test("fromhex2",obj.fromhex("3039") == my64a);
    test("fromhex3",obj.fromhex("0000006400003039") == my64c);
    test("fromhex4",obj.fromhex("0000000000000000") == my64z);
    test("fromhex5",obj.fromhex("004cfeeddeadbeef") == my64e);
    test("fromhex6",obj.fromhex("4cFEEDDEADBEEF") == my64e);

    test("tohex1",my64a:tohex() == "0000000000003039")
    test("tohex2",my64c:tohex(16) == "0000006400003039")
    test("tohex3",my64z:tohex() == "0000000000000000")
    test("tohex4",my64e:tohex() == "004cfeeddeadbeef")
    test("tohex5",my64e:tohex(8) == "deadbeef")
    test("tohex6",my64e:tohex(-8) == "DEADBEEF")

    test("encode1",my64a:encode(true) ==  "\57\48\00\00\00\00\00\00")
    test("encode2",my64a:encode(false) == "\00\00\00\00\00\00\48\57")
    test("encode3",my64c:encode(false) == "\00\00\00\100\00\00\48\57")

    test("decode1",obj.decode("\57\48\00\00\00\00\00\00", true) ==  my64a)
    test("decode2",obj.decode("\00\00\00\00\00\00\48\57", false) == my64a)
    test("decode3",obj.decode("\00\00\00\100\00\00\48\57", false) == my64c)


    local function testpower(b)
        testing("powers of "..b)
        b=obj.new(b)
        local z=obj.new(1)
        for i=0,100 do
            print(i,z,b^i)
            assert(z==b^i)
            z=b*z
        end
    end

    testpower(2)
    testpower(3)

    testing"factorials"

    F={
    [1]="1",
    [2]="2",
    [3]="6",
    [4]="24",
    [5]="120",
    [6]="720",
    [7]="5040",
    [8]="40320",
    [9]="362880",
    [10]="3628800",
    [11]="39916800",
    [12]="479001600",
    [13]="6227020800",
    [14]="87178291200",
    [15]="1307674368000",
    [16]="20922789888000",
    [17]="355687428096000",
    [18]="6402373705728000",
    [19]="121645100408832000",
    [20]="2432902008176640000",
    }
    z=obj.new(1)
    f=1
    for i=1,20 do
        z=z*i
        f=f*i
        s=obj.tonumber(z)
        print(i,z,f,f==obj.tonumber(z),tostring(z)==F[i])
        --print(i,int64.new(F[i]))
    end

    testing("bit operations")

    test("band1",checkeq(obj(1):band(1), 1))
    test("band2",checkeq(obj(1):band(0), 0))
    test("band3",checkeq(obj(4294967295,100):band(4294967295), 4294967295))
    test("band4",obj.new(4294967295,100):band(obj(0,100),obj(0,100),obj(0,100)) == obj(0,100))
    test("band5",checkeq(obj.new(4294967295,100):band(obj.new(0,100),obj(0)), 0))

    test("bor1",checkeq(obj(1):bor(1), 1))
    test("bor2",checkeq(obj(1):bor(0), 1))
    test("bor3",checkeq(obj(0):bor(0), 0))
    test("bor4",obj.new(0,100):bor(4294967295) == obj.new(4294967295,100))
    test("bor5",obj.new(1):bor(obj(2),obj.new(4),obj(8),16,32,64,128) == obj(255))

    test("bxor1",checkeq(obj.new(1):bxor(1), 0))
    test("bxor2",checkeq(obj.new(1):bxor(0), 1))
    test("bxor3",checkeq(obj.new(0):bxor(0), 0))
    test("bxor4",obj.new(4294967295,100):bxor(obj(0,100)) == obj.new(4294967295))
    test("bxor5",obj.new(1):bxor(obj(2),obj(4),obj(8),16,32,64,128) == obj(255))

    test("bnot1",checkeq(obj.new(4294967295,4294967295):bnot(), 0))
    test("bnot2",obj.new(0):bnot() == obj.new(4294967295,4294967295))
    test("bnot3",obj.new(0xaaaaaaaa,0xaaaaaaaa):bnot() == obj.new( 0x55555555, 0x55555555))

    test("bsawp1",obj.new( 0x01020304, 0x05060708 ):bswap() == obj.new( 0x08070605, 0x04030201 ))
    test("bsawp2",obj.new( 0xFF020304, 0xFF060708 ):bswap() == obj.new( 0x080706FF, 0x040302FF ))

    test("lshift1",obj.new( 0x01020304, 0x0506070F ):lshift(4) == obj.new( 0x10203040, 0x506070f0 ))
    test("lshift2",obj.new( 0x0102030F, 0x05060708 ):lshift(63) == obj.new( 0, 0x80000000 ))
    if t.name == "Int64" then
        test("lshift3",checkeq(obj.new( 0x0102030F, 0x05060708 ):lshift(63), -9223372036854775808))
    else
        test("lshift3",obj.new( 0x0102030F, 0x05060708 ):lshift(63) == obj.new( 0, 0x80000000 ))
    end

    test("rshift1",obj.new( 0x01020304, 0xF5060708 ):rshift(4) == obj.new( 0x80102030, 0x0F506070 ))
    test("rshift2",checkeq(obj.new( 0x01020304, 0xF5060708 ):rshift(63), 1))

    if t.name == "Int64" then
        test("arshift1",obj.new( 0x01020304, 0xF5060708 ):arshift(4) == obj.new( 0x80102030, 0xFF506070 ))
        test("arshift2",obj.new( 0x01020304, 0xF5060708 ):arshift(63) == obj.new( 0xFFFFFFFF, 0xFFFFFFFF ))
    else
        test("arshift1",obj.new( 0x01020304, 0xF5060708 ):arshift(4) == obj.new( 0x80102030, 0x0F506070 ))
        test("arshift2",checkeq(obj.new( 0x01020304, 0xF5060708 ):arshift(63),1))
    end
    test("arshift3",obj.new( 0x01020304, 0x05060708 ):arshift(4) == obj.new( 0x80102030, 0x00506070 ))
    test("arshift4",checkeq(obj.new( 0x01020304, 0x05060708 ):arshift(63), 0))

    test("rol1",obj.new( 0x01020304, 0xF5060708 ):rol(4) == obj.new( 0x1020304F, 0x50607080 ))
    test("rol2",obj.new( 0x01020304, 0xF5060708 ):rol(32):rol(32) == obj.new( 0x01020304, 0xF5060708 ))

    test("ror1",obj.new( 0x01020304, 0xF5060708 ):ror(4) == obj.new( 0x80102030, 0x4F506070 ))
    test("ror2",obj.new( 0x01020304, 0xF5060708 ):ror(32):ror(32) == obj.new( 0x01020304, 0xF5060708 ))

end

testing("min and max values")
z=Int64.new(2)
z=z^63-1
test("max1",tostring(Int64.max()) == "9223372036854775807")
test("max2",Int64.max() == Int64.new(4294967295, 2147483647))
test("max3",z==Int64.max())
test("min1",tostring(Int64.min()) == "-9223372036854775808")
test("min2",Int64.min() == Int64.new(0,2147483648))
z=-z
z=z-1
test("min3",z==Int64.min())

test("minmax",Int64.min()== - Int64.max() - 1)

testing("error conditions")

local function divtest(f,s)
    local r = (f / s)
    if r == 5 then
        io.stdout:write("ok...")
    else
        error("test failed!")
    end
end

local function modtest(f,s)
    local r = (f % s)
    if r == 5 then
        io.stdout:write("ok...")
    else
        error("test failed!")
    end
end

test("error1", pcall(divtest, 10, 2)) -- not an error, but checking the div function works above
test("error2", not pcall(divtest, Int64(10), 0))
test("error3", not pcall(divtest, Int64(10), Int64(0)))
test("error4", not pcall(divtest, Int64(10), UInt64(0)))
test("error5", not pcall(divtest, UInt64(10), 0))
test("error6", not pcall(divtest, UInt64(10), Int64(0)))
test("error7", not pcall(divtest, UInt64(10), UInt64(0)))
test("error8", pcall(modtest, 17, 6)) -- not an error, but checking the mod function works above
test("error9", not pcall(modtest, Int64(10), 0))
test("error10", not pcall(modtest, Int64(10), Int64(0)))
test("error11", not pcall(modtest, Int64(10), UInt64(0)))
test("error12", not pcall(modtest, UInt64(10), 0))
test("error13", not pcall(modtest, UInt64(10), Int64(0)))
test("error14", not pcall(modtest, UInt64(10), UInt64(0)))

print("\n-----------------------------\n")

print("All tests passed!\n\n")
