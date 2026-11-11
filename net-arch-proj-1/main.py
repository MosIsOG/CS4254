msg = "cs4254fall2026 STATUS 99 + 1\n"
msg = msg.strip().split()

num1  = int(msg[2])
num2  = int(msg[4])
result = num1 + num2
print(result)
print(msg)