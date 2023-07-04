
-- This is a test script for tshark/wireshark.
-- This script runs inside tshark/wireshark, so to run it do:
-- wireshark -X lua_script:<path_to_testdir>/lua/int64.lua
-- tshark -r bogus.cap -X lua_script:<path_to_testdir>/lua/int64.lua

-- Tests Int64/UInt64 functions

local testlib = require("testlib")
local OTHER = "other"
testlib.init( { [OTHER] = 23 } )

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

testlib.testing("Int64/UInt64 library")

local testtbl = {
    { ["type"]=Int64, ["name"]="Int64" } ,
    { ["type"]=UInt64, ["name"]="UInt64" },
}

for i,t in ipairs(testtbl) do
    testlib.init( { [t.name] = 125+(t.name == "Int64" and 3 or 0) } )

    testlib.testing(t.name, "class")
    local obj = t.type

    for name, val in pairs(obj) do
        print("\t"..name.." = "..type(val))
    end

    testlib.test(t.name,"class1",type(obj) == 'table')
    testlib.test(t.name,"class2",type(obj.new) == 'function')
    testlib.test(t.name,"class3",type(obj.max) == 'function')
    testlib.test(t.name,"class4",type(obj.min) == 'function')
    testlib.test(t.name,"class5",type(obj.tonumber) == 'function')
    testlib.test(t.name,"class6",type(obj.fromhex) == 'function')
    testlib.test(t.name,"class7",type(obj.tohex) == 'function')
    testlib.test(t.name,"class8",type(obj.higher) == 'function')
    testlib.test(t.name,"class9",type(obj.lower) == 'function')


    testlib.testing(t.name, "new, tonumber, tostring")
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

    testlib.test(t.name,"new1",checkeq(my64a,val))
    testlib.test(t.name,"new2",checkeq(my64b,val))
    testlib.test(t.name,"new3",checkeq(my64a,obj.new(my64b)))
    testlib.test(t.name,"new3b",checkeq(my64a,obj(my64b)))
    testlib.test(t.name,"new4",checkeq(valc,my64c))
    testlib.test(t.name,"new5",checkeq(0,my64z))
    testlib.test(t.name,"new6",obj.new(0,1):tonumber() == (2^32))
    if t.name == "Int64" then
        testlib.test(t.name,"new7",obj(-1):tonumber() == -1)
        testlib.test(t.name,"new8",obj.new(0,-1):tonumber() == -4294967296)
        testlib.test(t.name,"new9",obj(obj.new(-1)):tonumber() == -1)
    end

    testlib.test(t.name,"tonumber1",val == my64a:tonumber())
    testlib.test(t.name,"tonumber2",valc == my64c:tonumber())
    testlib.test(t.name,"tonumber3",vald == my64d:tonumber())
    testlib.test(t.name,"tonumber4",0 == my64z:tonumber())

    testlib.test(t.name,"tostring1", tostring(my64a)==tostring(val))
    testlib.test(t.name,"tostring2",tostring(my64b)==tostring(val))
    testlib.test(t.name,"tostring3",tostring(my64c)==tostring(valc))
    testlib.test(t.name,"tostring4",tostring(my64d)==tostring(vald))


    testlib.testing(t.name, "compare ops")

    testlib.test(t.name,"eq", my64a == my64b)

    testlib.test(t.name,"le1", my64a <= my64b)
    testlib.test(t.name,"le2", my64a <= my64c)
    testlib.test(t.name,"le3", my64z <= my64c)

    testlib.test(t.name,"ge1", my64a >= my64b)
    testlib.test(t.name,"ge2", my64c >= my64b)
    testlib.test(t.name,"ge2", my64c >= my64z)

    testlib.test(t.name,"neq1",not(my64a ~= my64b))
    testlib.test(t.name,"neq2",my64a ~= obj(0))
    testlib.test(t.name,"neq2",my64a ~= my64c)

    testlib.test(t.name,"gt1",my64a > my64z)
    testlib.test(t.name,"gt2",my64c > my64a)

    testlib.test(t.name,"lt1",not(my64a < my64b))
    testlib.test(t.name,"lt2",my64a < my64c)


    testlib.testing(t.name, "math ops")

    testlib.test(t.name,"add1",checkeq(my64a + my64b, val + val))
    testlib.test(t.name,"add2",my64a + my64z == my64b)
    testlib.test(t.name,"add3",my64a + my64b == my64b + my64a)
    testlib.test(t.name,"add4",my64d + my64a == my64c)
    testlib.test(t.name,"add5",checkeq(my64a + vald, valc))
    testlib.test(t.name,"add6",checkeq(vald + my64a, valc))

    testlib.test(t.name,"sub1",checkeq(my64a - my64b, 0))
    testlib.test(t.name,"sub2",my64a - my64b == my64z)
    testlib.test(t.name,"sub3",my64a - my64b == my64b - my64a)
    testlib.test(t.name,"sub4",my64c - my64a == my64d)
    testlib.test(t.name,"sub5",checkeq(my64a - val, 0))

    testlib.test(t.name,"mod1",checkeq(my64a % my64b, 0))
    testlib.test(t.name,"mod2",checkeq(my64c % my64b, valc % val))
    testlib.test(t.name,"mod3",checkeq(my64c % val, valc % val))
    testlib.test(t.name,"mod4",checkeq(val % my64c, val % valc))

    testlib.test(t.name,"div1",checkeq(my64a / my64b, 1))
    testlib.test(t.name,"div2",checkeq(my64a / val, 1))
    testlib.test(t.name,"div3",checkeq(val / my64a, 1))
    testlib.test(t.name,"div4",my64c / my64d == obj.new(1))

    testlib.test(t.name,"pow1",checkeq(my64a ^ 1, val))
    testlib.test(t.name,"pow2",checkeq(my64a ^ obj.new(2), val ^ 2))
    testlib.test(t.name,"pow3",checkeq(my64a ^ obj.new(3), val ^ 3))
    testlib.test(t.name,"pow4",checkeq(my64c ^ 1, valc ^ 1))

    testlib.test(t.name,"mul1",checkeq(my64a * obj(1), my64b))
    testlib.test(t.name,"mul2",checkeq(my64a * my64b, my64b * my64a))
    testlib.test(t.name,"mul3",checkeq(my64a * 1, my64b))
    testlib.test(t.name,"mul4",checkeq(2 * my64c, 2 * valc))

    if t.name == "Int64" then
        -- unary minus on UInt64 is illogical, but oh well
        testlib.test(t.name,"unm1",checkeq(-my64a,-val))
        testlib.test(t.name,"unm2",checkeq(string.sub(tostring(-my64a),1,1), "-"))
        testlib.test(t.name,"unm3",checkeq(-my64c,-valc))
    else
        testlib.test(t.name,"unm1",checkeq(-my64a,val))
        testlib.test(t.name,"unm2",checkeq(string.sub(tostring(-my64a),1,1), "1"))
        testlib.test(t.name,"unm3",checkeq(-my64c,valc))
    end
    testlib.test(t.name,"unm4",checkeq(-my64z,0))

    testlib.testing(t.name, "methods")

    testlib.test(t.name,"higher1",my64a:higher() == 0)
    testlib.test(t.name,"higher2",my64c:higher() == 100)

    testlib.test(t.name,"lower1",my64a:lower() == val)
    testlib.test(t.name,"lower2",my64c:lower() == val)
    testlib.test(t.name,"lower3",my64d:lower() == 0)

    local vale1 = 3735928559  -- yields hex of deadbeef
    local vale2 = 5045997  -- yields 4cfeed
    local my64e = obj.new(vale1, vale2)
    testlib.test(t.name,"fromhex1",obj.fromhex("0000000000003039") == my64a);
    testlib.test(t.name,"fromhex2",obj.fromhex("3039") == my64a);
    testlib.test(t.name,"fromhex3",obj.fromhex("0000006400003039") == my64c);
    testlib.test(t.name,"fromhex4",obj.fromhex("0000000000000000") == my64z);
    testlib.test(t.name,"fromhex5",obj.fromhex("004cfeeddeadbeef") == my64e);
    testlib.test(t.name,"fromhex6",obj.fromhex("4cFEEDDEADBEEF") == my64e);

    testlib.test(t.name,"tohex1",my64a:tohex() == "0000000000003039")
    testlib.test(t.name,"tohex2",my64c:tohex(16) == "0000006400003039")
    testlib.test(t.name,"tohex3",my64z:tohex() == "0000000000000000")
    testlib.test(t.name,"tohex4",my64e:tohex() == "004cfeeddeadbeef")
    testlib.test(t.name,"tohex5",my64e:tohex(8) == "deadbeef")
    testlib.test(t.name,"tohex6",my64e:tohex(-8) == "DEADBEEF")

    testlib.test(t.name,"encode1",my64a:encode(true) ==  "\57\48\00\00\00\00\00\00")
    testlib.test(t.name,"encode2",my64a:encode(false) == "\00\00\00\00\00\00\48\57")
    testlib.test(t.name,"encode3",my64c:encode(false) == "\00\00\00\100\00\00\48\57")

    testlib.test(t.name,"decode1",obj.decode("\57\48\00\00\00\00\00\00", true) ==  my64a)
    testlib.test(t.name,"decode2",obj.decode("\00\00\00\00\00\00\48\57", false) == my64a)
    testlib.test(t.name,"decode3",obj.decode("\00\00\00\100\00\00\48\57", false) == my64c)


    local function testpower(b)
        testlib.testing(t.name, "powers of "..b)
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

    testlib.testing(t.name, "factorials")

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

    testlib.testing(t.name, "bit operations")

    testlib.test(t.name,"band1",checkeq(obj(1):band(1), 1))
    testlib.test(t.name,"band2",checkeq(obj(1):band(0), 0))
    testlib.test(t.name,"band3",checkeq(obj(4294967295,100):band(4294967295), 4294967295))
    testlib.test(t.name,"band4",obj.new(4294967295,100):band(obj(0,100),obj(0,100),obj(0,100)) == obj(0,100))
    testlib.test(t.name,"band5",checkeq(obj.new(4294967295,100):band(obj.new(0,100),obj(0)), 0))

    testlib.test(t.name,"bor1",checkeq(obj(1):bor(1), 1))
    testlib.test(t.name,"bor2",checkeq(obj(1):bor(0), 1))
    testlib.test(t.name,"bor3",checkeq(obj(0):bor(0), 0))
    testlib.test(t.name,"bor4",obj.new(0,100):bor(4294967295) == obj.new(4294967295,100))
    testlib.test(t.name,"bor5",obj.new(1):bor(obj(2),obj.new(4),obj(8),16,32,64,128) == obj(255))

    testlib.test(t.name,"bxor1",checkeq(obj.new(1):bxor(1), 0))
    testlib.test(t.name,"bxor2",checkeq(obj.new(1):bxor(0), 1))
    testlib.test(t.name,"bxor3",checkeq(obj.new(0):bxor(0), 0))
    testlib.test(t.name,"bxor4",obj.new(4294967295,100):bxor(obj(0,100)) == obj.new(4294967295))
    testlib.test(t.name,"bxor5",obj.new(1):bxor(obj(2),obj(4),obj(8),16,32,64,128) == obj(255))

    testlib.test(t.name,"bnot1",checkeq(obj.new(4294967295,4294967295):bnot(), 0))
    testlib.test(t.name,"bnot2",obj.new(0):bnot() == obj.new(4294967295,4294967295))
    testlib.test(t.name,"bnot3",obj.new(0xaaaaaaaa,0xaaaaaaaa):bnot() == obj.new( 0x55555555, 0x55555555))

    testlib.test(t.name,"bsawp1",obj.new( 0x01020304, 0x05060708 ):bswap() == obj.new( 0x08070605, 0x04030201 ))
    testlib.test(t.name,"bsawp2",obj.new( 0xFF020304, 0xFF060708 ):bswap() == obj.new( 0x080706FF, 0x040302FF ))

    testlib.test(t.name,"lshift1",obj.new( 0x01020304, 0x0506070F ):lshift(4) == obj.new( 0x10203040, 0x506070f0 ))
    testlib.test(t.name,"lshift2",obj.new( 0x0102030F, 0x05060708 ):lshift(63) == obj.new( 0, 0x80000000 ))
    if t.name == "Int64" then
        testlib.test(t.name,"lshift3",checkeq(obj.new( 0x0102030F, 0x05060708 ):lshift(63), -9223372036854775808))
    else
        testlib.test(t.name,"lshift3",obj.new( 0x0102030F, 0x05060708 ):lshift(63) == obj.new( 0, 0x80000000 ))
    end

    testlib.test(t.name,"rshift1",obj.new( 0x01020304, 0xF5060708 ):rshift(4) == obj.new( 0x80102030, 0x0F506070 ))
    testlib.test(t.name,"rshift2",checkeq(obj.new( 0x01020304, 0xF5060708 ):rshift(63), 1))

    if t.name == "Int64" then
        testlib.test(t.name,"arshift1",obj.new( 0x01020304, 0xF5060708 ):arshift(4) == obj.new( 0x80102030, 0xFF506070 ))
        testlib.test(t.name,"arshift2",obj.new( 0x01020304, 0xF5060708 ):arshift(63) == obj.new( 0xFFFFFFFF, 0xFFFFFFFF ))
    else
        testlib.test(t.name,"arshift1",obj.new( 0x01020304, 0xF5060708 ):arshift(4) == obj.new( 0x80102030, 0x0F506070 ))
        testlib.test(t.name,"arshift2",checkeq(obj.new( 0x01020304, 0xF5060708 ):arshift(63),1))
    end
    testlib.test(t.name,"arshift3",obj.new( 0x01020304, 0x05060708 ):arshift(4) == obj.new( 0x80102030, 0x00506070 ))
    testlib.test(t.name,"arshift4",checkeq(obj.new( 0x01020304, 0x05060708 ):arshift(63), 0))

    testlib.test(t.name,"rol1",obj.new( 0x01020304, 0xF5060708 ):rol(4) == obj.new( 0x1020304F, 0x50607080 ))
    testlib.test(t.name,"rol2",obj.new( 0x01020304, 0xF5060708 ):rol(32):rol(32) == obj.new( 0x01020304, 0xF5060708 ))

    testlib.test(t.name,"ror1",obj.new( 0x01020304, 0xF5060708 ):ror(4) == obj.new( 0x80102030, 0x4F506070 ))
    testlib.test(t.name,"ror2",obj.new( 0x01020304, 0xF5060708 ):ror(32):ror(32) == obj.new( 0x01020304, 0xF5060708 ))

end

testlib.testing("min and max values")
z=Int64.new(2)
z=z^63-1
testlib.test(OTHER,"max1",tostring(Int64.max()) == "9223372036854775807")
testlib.test(OTHER,"max2",Int64.max() == Int64.new(4294967295, 2147483647))
testlib.test(OTHER,"max3",z==Int64.max())
testlib.test(OTHER,"min1",tostring(Int64.min()) == "-9223372036854775808")
testlib.test(OTHER,"min2",Int64.min() == Int64.new(0,2147483648))
z=-z
z=z-1
testlib.test(OTHER,"min3",z==Int64.min())

testlib.test(OTHER,"minmax",Int64.min()== - Int64.max() - 1)

--Because of g_ascii_strtoll() usage without errno check, "invalid" strings are converted to 0
testlib.testing("invalid string values")
testlib.test(OTHER,"invalid",Int64.new("invalid")== Int64.new(0,0))
testlib.test(OTHER,"invalid2",UInt64.new("invalid")== UInt64.new(0,0))

testlib.testing("error conditions")

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

testlib.test(OTHER,"error1", pcall(divtest, 10, 2)) -- not an error, but checking the div function works above
testlib.test(OTHER,"error2", not pcall(divtest, Int64(10), 0))
testlib.test(OTHER,"error3", not pcall(divtest, Int64(10), Int64(0)))
testlib.test(OTHER,"error4", not pcall(divtest, Int64(10), UInt64(0)))
testlib.test(OTHER,"error5", not pcall(divtest, UInt64(10), 0))
testlib.test(OTHER,"error6", not pcall(divtest, UInt64(10), Int64(0)))
testlib.test(OTHER,"error7", not pcall(divtest, UInt64(10), UInt64(0)))
testlib.test(OTHER,"error8", pcall(modtest, 17, 6)) -- not an error, but checking the mod function works above
testlib.test(OTHER,"error9", not pcall(modtest, Int64(10), 0))
testlib.test(OTHER,"error10", not pcall(modtest, Int64(10), Int64(0)))
testlib.test(OTHER,"error11", not pcall(modtest, Int64(10), UInt64(0)))
testlib.test(OTHER,"error12", not pcall(modtest, UInt64(10), 0))
testlib.test(OTHER,"error13", not pcall(modtest, UInt64(10), Int64(0)))
testlib.test(OTHER,"error14", not pcall(modtest, UInt64(10), UInt64(0)))

testlib.getResults()
