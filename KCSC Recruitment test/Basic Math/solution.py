
y = 65537


lstx = []
lst = []
for i in range(20):
    x= pow(y, -1, p)*(g**(i))
    h = 2*i
    lstx.append(x)
    lst.append(h)

print(lstx)
print(lst)

# => b'KCSC{b4by_m4th_f0r_b4by_crypt0}'