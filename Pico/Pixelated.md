# PicoCTF

src = [Pico CTF](https://play.picoctf.org/practice/challenge/100?category=2&page=1)

----
_Description_

I have these 2 images, can you make a flag out of them? [scrambled1.png](https://mercury.picoctf.net/static/75e646e4ad19967ca1811f895fb40465/scrambled1.png)  [scrambled2.png](https://mercury.picoctf.net/static/75e646e4ad19967ca1811f895fb40465/scrambled2.png)
----

  Với tiêu đề bài rất rõ ràng nên mình thử tra trên gg cách pixelated là ra
  > Ý tưởng cơ bản là chuyển các bức ảnh về các dãy dữ liệu rồi cộng nó với nhau để tạo ra một dãy mới. Từ dãy mới chuyển về thành ảnh là ra flag
 
  Code:
  
      from PIL import Image
      from numpy import *
      
      s = Image.open( "scrambled1.png")
      v = Image.open( "scrambled2.png" )
      
      data_image = [ asarray(s),asarray(v) ]
      
      image = data_image[0].copy() + data_image[1].copy()
      Image.fromarray(image).show()
>> picoCTF{d562333d}
