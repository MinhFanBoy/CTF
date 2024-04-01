txt = open("anti_dcode/LoooongCaesarCipher.txt").read()
txt = txt.replace("_", "")
txt = txt.replace("{", "")
txt = txt.replace("}", "")
open("anti_dcode/source.txt", "w").write(txt)


"""
> Rot8: cbntiozqxlkwlmepswxsfcjgmirnqowsdqgqwujuvpkkmqepbwplwpsgecmzupdobyrptcihsydbxyylkkmuqtphlwljbtiwukxqprmemcyltwtokr
"""

Flag = "utflag{rip_dcode}"