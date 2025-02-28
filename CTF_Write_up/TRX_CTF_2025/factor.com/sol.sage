
import os
os.environ["TERM"] = "xterm-256color"
from math import log  # Hoặc from sage.all import math.log
from Crypto.Util.number import long_to_bytes
from pwn import *
# context.log_level = "DEBUG"

s = connect("factor.ctf.theromanxpl0.it", 7003)
# s = process(["python", "server.py"])
def get_enc():

    s.sendline("yes")
    lines = [s.recvline().decode().strip() for _ in range(3)]

    N = int(lines[0].split(" = ")[1])
    e = int(lines[1].split(" = ")[1])
    c = int(lines[2].split(" = ")[1])
    # s.close()
    factors = factor(N, limit = 1 << 20)
    # print(factors, "done !")
    if len(factors) == 1:
        return None
    ns = [(p, _) for p, _ in factors if p < 1 << 20]
    phi = prod([(p - 1) * (p ^ (_ - 1)) for p, _ in ns])
    n = prod([p ^ _ for p, _ in ns])
    d = inverse_mod(e, phi)
    # print(s.recv())
    return pow(c, d, n), n

ms, ns = [], []

while len(ms) < 50:
    tmp = get_enc()
    if tmp is None:
        continue
    m, n = tmp
    ms.append(m)
    ns.append(n)
    print(len(ms))

m = crt(ms, ns)
print(long_to_bytes(m))
# TRX{https://youtu.be/HKnUdvVXOuw?si=Fv7_UfGodgAhOWQN}