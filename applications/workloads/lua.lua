local function fib(n)
  local a, b = 0, 1
  for _ = 1, n do
    a, b = b, a + b
  end
  return a
end

local t = { x = 3, y = 5 }
t.sum = t.x + t.y

print("fib(30) =", fib(30))
print("t.sum   =", t.sum)
io.stdout:flush()
io.stdin:read("*l")
