st = [114059301025943970552219, 3928413764606871165730,
43566776258854844738105, 1500520536206896083277,
22698374052006863956975682, 781774079430987230203437,
573147844013817084101, 483162952612010163284885,
781774079430987230203437, 70492524767089125814114,
3311648143516982017180081, 83621143489848422977,
31940434634990099905, 927372692193078999176,
16641027750620563662096, 83621143489848422977,
1500520536206896083277, 83621143489848422977,
59425114757512643212875125]
lst = {1:1, 2: 1}
def fi(n):
    
    if n  in lst:
        return lst[n]
    else:
        lst[n] = fi(n - 1) + fi(n - 2)
        return lst[n]
Dict = {}

for x in range(65, 200):
    Dict[fi(x)] = x
print(Dict)
for x in st:
    print(chr(Dict[x]), end ="")