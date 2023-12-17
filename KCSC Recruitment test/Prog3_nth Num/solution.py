# nc 103.162.14.116 14004
from pwn import *
from json import *
s = remote("103.162.14.116", 14004)



def findNthDigit(n):
    len=1
    count=9
    
    while n>len*count:
        
        n-=len*count
        len+=1
        count*=10
        
        
    start_num=10**(len-1)
    
    num,remainder=divmod(n,len)
    
    
    if remainder==0:
        
        return int(str(start_num+num-1)[-1])
    else:
        return int(str(start_num+num)[remainder-1])
print(s.recv())
while True:
    a = s.recv().decode("utf-8")

    print(a)
    a = a.split("= ")[1]
    a = int(a.split("\n")[0])
    print(findNthDigit(a))


    s.send(bytes(str(int(findNthDigit(a))), encoding = "utf-8"))

    print(s.recv())