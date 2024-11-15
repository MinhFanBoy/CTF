from Crypto.Util.number import *
import random

flag = b"VNCTF{H4__1ngw__ght_simp0__4nt!}"
m = bytes_to_long(flag)

rr = matrix(ZZ,[random_vector(ZZ,256,0,2) for _ in range(256)])
mm = matrix(GF(2),[list(bin(m)[2:].rjust(256,'0'))]*256)
cc = mm+rr
ii = vector(ZZ,input("Undoubtedly, this is a backdoor left for you: ").split(","))
dd = rr*ii

