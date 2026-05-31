from __future__ import annotations

import math
import sys
import time

from sage.all import *
from Crypto.Util.number import bytes_to_long

from backend import config
from backend.services.auth_service import AuthService
from backend.services.crypto_service import *
import aes_gcm_forgery as gcm

a0 = 4466763292876350702170520498406547525623671831497292047704
a1 = 4466763292876350696726002627671532110209678112589000656216
d0 = 2963456228757450554062324634257662390632205120026456003485
d1 = 1811279201065508610997026361550424202020126293151552267472

def bxor(a, b):
    return bytes(x ^^ y for x, y in zip(a, b))

def fixed_from_gf2e(elem):
    n = int(elem.integer_representation() if hasattr(elem, "integer_representation") else elem._integer_representation())
    ans = 0
    for i in range(128):
        ans = (ans << 1) | ((n >> i) & 1)
    return int(ans)

gcm._from_gf2e = fixed_from_gf2e

false = False
true = True

r1 = {"auth_key_hashed":"8add8d9f60da3837e1908ddb7b2490872784db1798b7b84edb5a46f954687699","encrypted_flag":"9334d01e53c06cda3a03ef830ff207c13bde790ae39023022cd15686d942aad4d5597792257dc1728ab4d723920df2ab54af355f0e0f6d963c2fca544f2ce93099639c291d4cdecdbaafe9567e570b0608fdb4d5ac2f73d6bc7313cd6cccb37dfd768bb82722934176a293f2ac87f3697f67d286b6ba7b53ecb3e62663da4f5f6b0a2661f5bbcdb7071578c05db1fea9","iv":"bfc298dc491691ee1af1119972b012bf","login_id":"28918a3646814a80b712e9813c59b1db","message":"1@. is signing in from a new device.","ok":true,"registration_receipt":{"auth_key_hashed":"8add8d9f60da3837e1908ddb7b2490872784db1798b7b84edb5a46f954687699","login_id":"28918a3646814a80b712e9813c59b1db","master_key_enc":"759d6169dad026f52d49f86845ab25c1","share_key_enc":"6997cd26119a05eac1a170d802cacfb4f73e6e76e51439c8d870fb699b23098cba8758e2557fdb68d415c4a3aaa58bf4023990d2ceb71f49cd152d2a1d26442de6509596894865b335f3a43e2a59f08580978ad31da373d5ed95edb05a05ed56cf37bcd9f70661780d2191e9787cfc6e0efa673f270219888f17026f477b5f3a7531cdbe164878dfc10659b1914cdc4ebc3c54d57d047fdb15cf12f4b53fb8f75d595c557a36ddc1783dba0dd60730b75c7176488dd5ae2c6c408ca34ca14b7cbaeb781fb17e342a699af6a87ee8c916f826611994f2a99302e2510234b7445e386d51730718c75a19a01fd6ca967ec43b4f197a0531d4b37b2ccb02f4c6280ae92a625b500d1133ccb87485f01d099bddfcf094834d6a99cac5101b7a1586e756d048501eea3d58b5d2fece4c158b8176a6c3a2225065ecaf29eeb2888e8799963c3df70cc4a9330f09e3ccc9aad13e8d0d3aa8878619d6567b52fedbee530ad8f3b367aeb89015e81c39b346575ff7cf9bab9a479b4f7dd9d30984d1ff2c7b7c463523c51d012398d2a093bbbc588a7d5cce35294aa2f0f705694a62957409bafc905ff09670de11bc5ffaab414d092ef7967c88ad5f372737a5d340d5018a5d7c177ef9b5a3c7c6c87c6ead9c3e789104e6df8ad2cfc6b676a86473a161d17c0aec215bd2113686cb9a6c8b2591db52535157653f5385614a6156a7b0ae6d","share_key_nonce":"1f02afc9a596e756410e9b45","share_key_pub":["26313008903099401469896543943687474278107685919015892292646457180308063327679382967403442100100639224698727967038785496934698890545174748477631122155085736215148521398868702594976479923783981726842468790215771448427978496349347779662855632573561786978210691069891974860846151921313983058201904926292855472722318781079470028555850635904809043572500431785597117030745128211519613517639537027103269800987286278334884774720259027833091057626434513014149295638508756518082421045548166436577135678127521436609732341368678636361293317736954001318642285606077152749016069251875427182853225380583763150023871621275064453949801",65537],"tag":"00afcac81432640eefe750045b20e795","user":{"account_id":"4466763292876350723948591981346609187279646707130457580888","device_id":"2963456228757450554062324634257662390632205120026456003485","email":"1@.","username":"1@."}}}

r2 = {"auth_key_hashed":"8add8d9f60da3837e1908ddb7b2490872784db1798b7b84edb5a46f954687699","encrypted_flag":"96a194b81401d2934da2ff7d28d0afaeed68af626809e15944638a2853d885f70542918b94b21900f526974c8eaa71e80eee23b16022a3a5b7671425213be8c5151e6da5b18bffe941348cabd8ab8d4f98307b4fab3284e06b043b6b49a591e53f0e6316247cacd16e11d5522e0ef00ce5fcb7e7ed1e5ba9f7950abc50a24e1726a5619ab87f83869bea420802321121","iv":"0131e36e08f314c3ffbfe017a8276360","login_id":"5ae0f331c19b4197af00b1195643987c","message":"2@. is signing in from a new device.","ok":true,"registration_receipt":{"auth_key_hashed":"8add8d9f60da3837e1908ddb7b2490872784db1798b7b84edb5a46f954687699","login_id":"5ae0f331c19b4197af00b1195643987c","master_key_enc":"759d6169dad026f52d49f86845ab25c1","share_key_enc":"cda91955d613258d362e009c5c4f87bcb31553bbae6edd3b4fa2bda6974b15dbb381216943f7e436b58072e62ec0100999c024d35256e0109843a42c3ef28dc2e7ab4ed5f79e01a81330f53d1744250fa7294c09ee5e9e0d55055ead97702bf00018c684738bd34a20a5be3ab0ec4c1408caca8f1c8f1158232cc49bdf65b37d3de02a8c5129040404b3bc61e8362658f0a21636d986037679a4ca8a1313f2e58425a302287647c280624c2e3af178450b03dbfca9fdfde954a6af9cf54a4ce432d6dd22ecc06ac30f486683e77a75646af47f126f57c6da93cb098753d95dfcae3efd7806f66ee4cf57c50482a5a53bcb68c9038d3498b2022318cda364b8624190a2174890e5ca921eaa5a85a03ba3ec5d65719982fd55df6a7aae509cb397bbe5af7e607338ee58f078ed17a4ba029bb65a0281cc9b3c5056832e510cf44cd0c09c67b29259be312b6181f06c2046ba10ca14618d46bd00b850284a4aed4ceab36d7f724ea81a35eefac2e5eb2c89960d9177a69ff0e9e0da7489789e231a499991f89f92c73842299975d4797a9e43f64f51bff5cea0f83d5d9adbf66e9383e6c1c8e1fce10d0cfdaf3dc9a2b8bdb60ae4a45e28e59e848314818e892cf9fe35e338f479f7ebb14b552b33fc604e0bf730e38db01860482eb9ba1d98e6e85c9c7c7f36c722fe7f196c62f4c831bba90c5ba7101543f2b4a1f12a212afb23","share_key_nonce":"1f02afc9a596e756410e9b45","share_key_pub":["24272042504508733876519585838085348832780649847923386223214686239096600597342948885915838296049337284097185026271471990859272244481312620687558566574659104486523643182386711851564828912529646098869462838058986182359221379047111900156576807543424785777711542173646123260380915170681643043603691276574803103887794133248589490779752417626311248802450171667895542693904255392030798384528813983910080938238078296631545364151866868203621305142810807638860105108218040756890236490098608349254199733329630658208516067791360319046532955465491435689466004112208899952448689849923733328133035380567567429886258933175505984518409",65537],"tag":"361859dc439958f24737e256c23d994e","user":{"account_id":"4466763292876350718504074110611593771865652988222166189400","device_id":"1811279201065508610997026361550424202020126293151552267472","email":"2@.","username":"2@."}}}

c0 = bytes.fromhex(r1["registration_receipt"]["share_key_enc"])
t0 = bytes.fromhex(r1["registration_receipt"]["tag"])
c1 = bytes.fromhex(r2["registration_receipt"]["share_key_enc"])
t1 = bytes.fromhex(r2["registration_receipt"]["tag"])
nonce = bytes.fromhex(r1["registration_receipt"]["share_key_nonce"])
h = list(gcm.recover_possible_auth_keys(b"", c0, t0, b"", c1, t1))
print(h)
print(len(h))
h = h[0]
delta = bytearray(KEY_BLOB_LEN)
delta[0] = 0x80
target_c = bxor(c0, bytes(delta))
tag = gcm.forge_tag_from_ciphertext(h, b"\x00" * 16, c0, t0, b"\x00" * 16, target_c)

print("Forged tag:", tag.hex())
print("Forged ciphertext:", target_c.hex())

output = {
  "debug": "54965061d9df1d77464e87b11d4dd9a5e6e8bab556fcf0c7cd0fd506f2c20d4d85ea3c557007b63d5c2accc4c2cd8ea9e81631432d9b68361d333891fa0ef5a516332a985ea60d495a89ca1b2652e5cfa6ba3b1ae6794e3810747f78d26a0151087b43dfd9fcd73c72176dd1e18a333f9520a9e33718dce36c02495b3919a73a640a632847ec9a43c09ef0d1a6cb1060f5222794d1335a0dee51f0b3e059fcfb2d34b9ddcfba9fcfbc1f1a1f73d4bd211ab1de135050bed7d5a67397b01165ab8c605d87ba2a163797d5872f7c6792dbc48dddf480dc6c3fdf303aa9b894a0f7917206ae6d29b771cd09695217663a65bc12a16c2f2f81227bf3f2172a0d0194",
  "ok": false,
  "status": "Login rejected by session verifier."
}

n = int(r1["registration_receipt"]["share_key_pub"][0])
leaked = int(output["debug"], 16)

R = PolynomialRing(Zmod(n), names=("x", "y", "z"))
x, y, z = R.gens()

def encode_sid_poly(x, y, z):
    sid = R(bytes_to_long(sid_base_blob()))

    for off, row, const in zip(SID_FIELD_OFFSETS, MIX_MATRIX, MIX_CONSTANTS):
        shift = 8 * (SID_TOTAL_BYTES - off - MIXED_FIELD_BYTES)

        field = (
            row[0] * x +
            row[1] * y +
            row[2] * z +
            const
        )

        sid += field * (ZZ(1) << shift)

    return sid

f = (encode_sid_poly(x, y, z)) - leaked

from pathlib import Path

coppersmith_dir = str(Path(__file__).resolve().parent / "coppersmith")
if coppersmith_dir not in sys.path:
    sys.path.insert(0, coppersmith_dir)

from coppersmith_linear import *
from contextclass import context
from lll import FLATTER

context.lllopt = {'algorithm':FLATTER, 'use_pari_kernel':True}

bounds = [1 << 80, 1 << 80, 1 << 80]


def coppersmith_linear(basepoly, bounds, beta, maxmatsize=100, maxm=8):
    if type(bounds) not in [list, tuple]:
        raise ValueError("bounds should be list or tuple")

    if beta >= 1.0:
        raise ValueError("beta is invalid. (for beta=1.0, use normal lattice reduction method directly.)")

    N = basepoly.parent().characteristic()

    basepoly_vars = basepoly.parent().gens()
    n = len(basepoly_vars)
    if n == 1:
        raise ValueError("one variable poly")

    if not set(basepoly.monomials()).issubset(set(list(basepoly_vars)+[1])):
        raise ValueError("non linear poly")

    log_N_X = RRh(log(product(bounds), N))
    log_N_X_bound = 1-(1-RRh(beta))**(RRh(n+1)/n) - (n+1)*(1-(1-RRh(beta))**(RRh(1)/n)) * (1-RRh(beta))

    if log_N_X >= log_N_X_bound:
        raise ValueError("too much large bound")

    mestimate = (n*(-RRh(beta)*ln(1-beta) + ((1-RRh(beta))**(-0.278465))/pi)/(log_N_X_bound - log_N_X))/(n+1.5)
    tau = 1 - (1-RRh(beta))**(RRh(1)/n)
    testimate = int(mestimate * tau + 0.5)

    logger.debug("testimate: %d", testimate)
    t = 2
    m = 9

    whole_st = time.time()

    curfoundpols = []
    while True:
        m0 = int(t/tau+0.5)
        if binomial(n+1+m0-1, m0) > maxmatsize:
            raise ValueError(f"maxmatsize exceeded: {binomial(n+1+m0-1, m0)}")
        for m_diff in range(0, maxm+1):
            m = m0 + m_diff
            if binomial(n+1+m-1, m) > maxmatsize:
                break
            m, t = 9, 2
            foundpols = coppersmith_linear_core(basepoly, bounds, beta, t, m)
            if len(foundpols) == 0:
                continue

            curfoundpols += foundpols
            curfoundpols = list(set(curfoundpols))
            sol = rootfind_ZZ(curfoundpols, bounds, **context.rootfindZZopt)
            if sol != [] and sol is not None:
                whole_ed = time.time()
                logger.info("whole elapsed time: %f", whole_ed-whole_st)
                return sol

            polrate = (1.0 * len(curfoundpols))/n
            if polrate > 1.0:
                logger.warning(f"polrate is over 1.0 (you might have inputted wrong pol): {polrate}")
                whole_ed = time.time()
                logger.info("whole elapsed time (not ended): %f", whole_ed-whole_st)
        t += 1
    # never reached here
    return None

rels = coppersmith_linear(f, bounds, beta=0.4999, maxmatsize=400)

print(rels)

llll = int(f(rels[0]))

n = int(r1["registration_receipt"]["share_key_pub"][0])
p = int(gcd(llll, n))
print(p)

q = n // p
enc_flag = bytes.fromhex(r1["encrypted_flag"])
iv = bytes.fromhex(r1["iv"])
key = SHA256.new(q.to_bytes((q.bit_length() + 7) // 8, "big")).digest()
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = cipher.decrypt(enc_flag)
print("Flag:", flag)