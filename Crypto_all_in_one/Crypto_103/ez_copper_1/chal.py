from Crypto.Util.number import *
from random import *
from secret import flag

assert flag.startswith(b"NSSCTF{") and flag.endswith(b"}")
assert len(flag) == 37

def gen_data(p,length):
    coeff = [randint(-2**32,2**32) for i in range(length-1)] + [randint(1,2**32)]
    return sum([coeff[i]*p**i for i in range(length)])

b = getPrime(1400)
a = gen_data(b,6)
p = getPrime(256*5)
q = getPrime(256)
n = p
m = bytes_to_long(flag[7:-1])

print("a =",a)
print("b =",b)
print("n =",n)
print("c =",a % (b-m) % p)

'''
a = 29089145861698849533587576973295257566874181013683093409280511461881508560043226639624028591697075777027609041083214241167067154846780379410457325384136774173540880680703437648293957784878985818376432013647415210955529162712672841319668120257447461567038004250028029752246949587461150846214998661348798142220559280403267581983191669260262076357617420472179861844334505141503479938585740507007167412328247901645653025038188426412803561167311075415186139406418297360055617953651023218144335111178729068397052382593835592142212067930715544738880011596139654527770961911784544010189290315677772431190278256579916333137165255075163459126978209678330136547554839703581615386678643718339211024128344190549574517564644382447611744798875041346881354781693931986615205673317996958906543168487424513288646586386898335386252942417294351991435595389041536593887748040184886941013614961741810729168951559211294246606230105751075721451317188926451002620849423314518170658209171671914315184519999959495351937563075042077266900864146159426562183965523296477064353921084645981585062809887031916148806349242025315612913825933164149679421566262446757892475611986630543538188150542432463200651189833933982458007114429715435568714619661080138790893459960671301328455259702189597680258358027148120577359065875450633562059381985788036798654456426180261922908112060328808638698523351620789566317389045953829508142189900185007810978556531031234520426854056485675147172190502028351264431318960694075186507102430581156550179324060430995652420952731818727684039692796018771140481392835706804763480391403219506727895338895364591606497253163676677638669786786858737497920439433198267927890300667623673919500396414839378381934354516285899285278671196050670328000271445003863863854641343057226519772851093922041622949244909881042639419520750870739146022239848882362576253955639971615811326995401478442990402656532205515168792715334542129193521733882886780427236290633270965571593377055933030570964314193668632743086843644521712276882644432083012275643889490106050284317873072564495246844741833922331897169054478543498374111011001360629887265387016903
b = 23842135454777432891743223391138265563241799870175456642327123278749657522050965688647025271946838603033997215457359121062031090678062337376719430593135764515364544052891212988546634081941717578522276652565205405071925932782899189391582928430745625545751168223235578140422316604775465116636679365817463642606682382103650151553859378443311951637645862682606805670610169631771916714125895199501221576523042203542953632992797
n = 11325979084644128572298911896847368512066889699114922766957825496829789701040409280284912163337390977205935027654824418075908113980923567819511384456223871894254826496727684822147076089401320253972280078822901143659851738555573580052473815798989309369428595758953805619194262607259107358103749807085316873971927412767250429330952340169403993890298557816024130952523480708504075717017477
c = 91637278981727419311704062766528605893241365739887714388981571071807672497690225964001055671982318124750997320763003521883860470498708606433206468782382765369836856610266602374015551078759628514665188339252922366320922478645026704734702460355236791287112842409076450962765866362852307351865564192898522584768904066046337899302561685937649000409332117647123
'''