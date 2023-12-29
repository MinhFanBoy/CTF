k = [[5, 8], [12, 7]]
#  thay doi keykey

enc = "QQCD"
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
# nhớ thay đổi alphabet

det = (5 * 7 - 8 * 12)
inv_det = pow(det, -1, len(alphabet))
inv_k = [[7, -8], [-12, 5]]

def de_Hill(txt):
    flag = ""
    for x in range(0, len(txt), 2):
        p = [alphabet.index(txt[x]) * inv_det, alphabet.index(txt[x + 1]) * inv_det]
        
        tmp = [(p[0]*inv_k[0][0] + p[1] * inv_k[1][0]) % len(alphabet), (p[0]*inv_k[0][1] + p[1] * inv_k[1][1]) % len(alphabet)]
        flag += alphabet[tmp[0]] + alphabet[tmp[1]]
        
    return flag

print(de_Hill(enc))
        
        

