# pwn

---
**_Description:_**
Just find flag in file, no need netcat
Author: wan

File:[gift](https://kcsc.tf/files/53b374c3baaec901b89fa633be383fa8/gift?token=eyJ1c2VyX2lkIjoxOCwidGVhbV9pZCI6bnVsbCwiZmlsZV9pZCI6NzV9.ZX6MHw.xoxVguAKAaQ-3TYfByEPGRPxBcA)

---

Mở file gift ra bằng IDA, chọn chế độ view hẽ thì ta thấy dc 2 parts của flag

part 1: ___|.Guest the flag: .KCSC{A_gift_......The second part of the flag I hide somewhere in some function......;4...

part 3: pwners_0xdeadbeef}..............

từ gợi ý part 1 mình tìm kiếm phần còn lại trong các hàm thì sau một lúc là tìm thấy

part 2: .rodata:0000000000002008 s               db 'for_the_',0         ; DATA XREF: secret+4↑o

->KCSC{A_gift_for_the_pwners_0xdeadbeef}
