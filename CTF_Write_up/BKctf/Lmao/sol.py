alphabet = "abcdeghiklmnopqrstuvxy"
alphabet_up = alphabet.upper()
txt = open("Lmao\output.txt").read()
print(txt)
hint = "qyx an btx ryogi".lower() # Ngày 10 tháng 9 năm 2009
know = "mat ma hoc nguoi".lower()
txt = "Rlnq Amdmnvca Obnngy ca yri yqe sroa btx, phyac trq ik qyx an btx ryogi Nqu, pesb bsy eg hsn nkoak bsere qun ooar iagns gkm vlyqu vbtu mhu dam xvyq by D.V (Hmo pax gyaa xoa). Ymds itp Aqvbgx (Tiuvyp ydvi) xt rky nlgns quhvl brbs boar dhe ntdi oee nqt hmtil gyrnt xgt dad qunh aus: nan ttdqs vex hoh mg xeo agi edbr uex pcp vt emb gro qdi pesb c itpi re uh mhr vkl vlgm riii cer cyoak. Cyp iy lvab acau aga vlot vndp itpgp yhse vn xvyq yndb kio her Nnruqt, pxre xubc kqe ls hhuib nkr byo 'Hpxdry', er nsdn ykd cycp xtil vsg cbqt oqamk qttu imsg, oe xyoy nk Blkevn Palbeg, yri veem hs aio negy mah go yqamk tu ooim vogc odbr dmtdi higi ixo to hls grrg hkbv hury ery Hygtvl.Sucaa Icnxg mrnqu gqk emcu onq msb, Muembr ne sybs egh bbxt tnm Pvoyblyrs Uuvc, nkuak imu lhdv yta he uor Aal, lm uss xubc qu ryogi plv sed byo TPA 8, hsn tg ptdb oee Yqu pi aneua ehuia rreh poh gg xas ari dyoy Nab. Kvni yq Yolans ho oere gop vtil mo tun xot QAS 8 ho cbgp ylbvn yri ex ox xuita imse maak iam in sun gg xas knaa sumd chx Riv, ansgy uo odc rxq umsp vgd ybxe mnc paugd (pom hgt ih urc plklor emo scgd qs gxubm Pm Tem voaa ick nlnop Xuq mmhib 2), yia xs esq cb hvqv yt nubhm gs uh bhn qoyp yhp, ruvn re vht dirq okh crbs onkry nan qd rhxh ld ubt acega tap xuavl cmsc qt ilabr cid rar tgycaa. NQY 8 ps xinr hh Daqmbs xtil ehm vnm idx utdb hmtil nlgns avqm lhdv yt iuh tot duib oee pyoa knuy qbm Dig idxre gop oxur vseh dyoy dvnqt b vnua So, ehnx ym dvyq Rnc Aud Vogns. Pcg cs mkkbh hus uaa sny bmi iy qung qur, uag rnqt avl kd bsptd is uye hdc xkd emou ggp qs una Qyq, yqamk itpi ne hgx ctm ym vltrv pto pnxg dam kvm ue ci bb btuy vheg aloyq mnq, qbh rud ybri yd breddq pnh qu tasm muqu oee bdq pbbtkg yaa Od Ymv.Xyy qtcli ylseh, bqt oxre xop ogd Taheg hlv ypmhia Kta gd Kogc smo (Ykyhrbne Ucdmbtax Oonxvyxces), cu is nro ed aad yqrbs hnqry vg aa xutoy ii rnp adkg una ydn grrg gc vbg iegy cui xgh mmtrbs oxdra (mmoeir bbseuoy vthtonvr), alkyp rn nubhm veh yao qyco sndq ini acega dam. Foor: Vlyc bns nua axm cng amd qy gc qcli ixo ua qyco ymy kvnc hkn esq tuqu. Vea x: xuns pcssgx tedbr may foos onura vru _ kd rmd hgybs oxkry fhkmnx PUCKB{}. Qoy 1947 isb haoqea hsy Neh lcp Qoxyhlaa hdv Xkrblsgoln ix drm kmso, ne rr ieys lmsg dey gua uex Poavnaxnxk Mnux T, tab hc xt rky nlgns quhvl ldn hcsc mbxe dnm rme yhib, kt ans gxe qidb gkq srv gcsc mhu monq uam. Smk rn qoay tsa bnr lq ms rr ubt nkh uor si xoa qnml, ln isb hogx dn hk pxem hkbv iuh iarn iqt sxe grq qtt ysgy thnqt skr mlk cbgi agy Sexrkexb–Zgdpbooixcr, uubg ehkr rdi hbgt psg uai xvqv yqrbs onut gbvn 1960.Ada 1952, Gevhqt oc pay sg oou xct ne br btpsb msgy vu nutoq mlo atsb rx, mru vlv avl sy itp ku hh knaa ls pxre xvab qqdxg ri krv xxy mkkbc kur hgx o Ydboqkrxse. Isb hash ntdb pere ovrp ucei agop pcy va (slvrh nke aht) ttdn oqs umsp knun gygi hy. Cyp qyx bng 1954, icn 2 norn hukam pyq huhn imsn mhi 42, hc yps crq lsgias. Egt pyco nndy iet ku csu uial breddq btts xmxn ca hy ih, vmtqt yy til ps doh vc ypanm xtti png lrns got mmdx qit til ds doh xot vem. Qtns 10 acegy 9 eay 2009, voh uss guuys ynua Anhigyoy, slk hptil Sgy Gburav Gqrwb qt acer ert plvyq tgy Oab icnga mhig mtv pnm lr vgxm vha xi act Daqmbs ngq habvn huoyq."
print()
print(f"{alphabet = }")

i: int = 0 # index of key ?
y: int = 0
key = ""
for k, x in enumerate(hint):
    if x not in alphabet:
        pass
    else:
        key += alphabet[(alphabet.index(x) - alphabet.index(know[k])) % len(alphabet)]

print(f"{key = }")
print()

key = 'keydontguessrandom'

for k, x in enumerate(txt):
    if x in alphabet:
        print(alphabet[(alphabet.index(x) - alphabet.index(key[i % len(key)])) % len(alphabet)], end = "")
        i += 1 
    elif x in alphabet_up:
        print(alphabet_up[(alphabet_up.index(x) - alphabet.index(key[i % len(key)])) % len(alphabet)], end = "")
        y += 1                
    else:
        print(x, end = "")