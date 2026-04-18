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