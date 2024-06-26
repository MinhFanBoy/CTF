
enc = """
VMQPEQWTTUUWENDRTJXPHLLQGAUPIDEQRDYAMJLFVUNLGSNZFUUNS.TFR,EKJOOQSERQGKOFWLQOYWLGGPOYWOFVEEIACTKDEGQHRH'BOGYMSCSIGC.VJUJQSOCRDEBVWMFLSQS,FRUDEOGVALWXPGAVFR.PAHCOCGSG,IQMFLSNGJMFUIQZLEFIAEWLRZRLF,DFVKDXVZFPBUE;FSFGTKCXZKHRDDOKSYBWIF.ICGTTDXYLRZELFRVQRWEXUJQVTEQUCQBHDWGV,HGTUXUJWGXEJGKOKUEADBQVGMHBVUELCOHSR'KGJOH.ZM'SUDWGPVUVVOKKVBVIOUSSRDEGVAJ,CWX.DVTFSIYFGSLHCLTG.ZMRWBOUSTSULGDFL.FHPNGFCUUZNGVBEHX.ARATSULGDFL'JWEBOAVKMLRDFL...GMIVFBOKVJBFBBJDYDOVELTVXEBB.NU'BOIOYWUJDFFVJUKAUWMBUBXYLEFLYSGOVTNJGNFCGGJPIEHT'VLRSGMCDVROSRVDIOY,FRUFYIOBTGVE,QUCLGYUFZFLJ.XAGDBHGG'D.QUCHT'TJFSSHBQVOIAREGPGNFCYWNG.IQNNU'IOEBLP,NJNBTVJKJPVIS.OVFTGOOVF?KQQL'CKWSVODHU.CWQOXNJPUSQUJUHMXFJGEWWZLDVPOVSDKFKFYGENH?WAGVDIJSGFPEKJNOVIKQOTFPTKOYWREYDDCLVEOVGYGXGENMGXFUBDTXTUDNVEOTWIJYUYPDJLRCWWAE?ATIPTDWUMQKEGURRYIAFPWLXPUTQFJPZNIBSDRWWJSPURI?\n
KQQLAISQQICIMJNQFPEXVDEVPVXZNLGSRKOXNXGHFPEEAGNVGWOGF.ERLGD'RYVIGHTKHAMSZI.GXOLVKKSTWEWTSGENHLXPUMRKLDVEXSSDZZDTXTU.HHTTASEPFWAOUDEECLLISNOKWAGOHEFWLIIAUATIEEHMHNOOHCULLMTHLOWAOYNIHUSTLOIGGLWOWIIWMRI.IOIROK.DYYOYSWSTSUIIDHNEPYOAVFTAL.
"""
print(enc)
substitution_map = {
    'G': 'E',
    'O': 'A',
    'V': 'T',
    'E': 'O',
    'F': 'I',
    'U': 'N',
    'L': 'S',
    'S': 'H',
    'D': 'R',
    'I': 'D',
    'W': 'L',
    'T': 'C',
    'R': 'U',
    'Q': 'M',
    'J': 'W',
    'H': 'F',
    'K': 'G',
    'N': 'Y',
    'A': 'P',
    'P': 'B',
    'Y': 'V',
    'X': 'K',
    'B': 'J',
    'C': 'X',
    'M': 'Q',
    'Z': 'Z',

}

decoded_text = ''.join(substitution_map.get(char, char) for char in enc)


"""
E - 12.70%
T - 9.06%
A - 8.17%
O - 7.51%
I - 6.97%
N - 6.75%
S - 6.33%
H - 6.09%
R - 5.99%
D - 4.25%
L - 4.03%
C - 2.78%
U - 2.76%
M - 2.41%
W - 2.36%
F - 2.23%
G - 2.02%
Y - 1.97%
P - 1.93%
B - 1.49%
V - 0.98%
K - 0.77%
J - 0.15%
X - 0.15%
Q - 0.10%
Z - 0.07%
"""
