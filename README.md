# 🔒 AES File Transfer

Dự án truyền và nhận file qua mạng bằng **Socket TCP** sử dụng thuật toán mã hóa bảo mật cao **AES-128 (Advanced Encryption Standard)** ở chế độ **CBC (Cipher Block Chaining)**.

> **Điểm nổi bật:** Lõi mã hóa hóa AES trong dự án (bao gồm `S-Box`, `ShiftRows`, `MixColumns` và Toán học Galois Field) được xây dựng lập trình thủ công hoàn toàn từ đầu theo tiêu chuẩn FIPS 197 mà không sử dụng bất kỳ thư viện cryptography ngoài nào!

---

## 🛠️ Yêu cầu môi trường
- Hệ điều hành: Windows, Linux hoặc macOS.
- **Python 3.6+** trở lên. (Dự án dùng các thư viện chuẩn (builtin) trọn gói của Python như `socket`, `os`, nên không cần tải thêm qua `pip`).

## 🚀 Hướng Dẫn Sử Dụng

Kho phần mềm hoạt động thông qua giao diện Menu lệnh Command-Line (CLI), cung cấp 2 chế độ đóng vai trò Cửa hàng gửi (Server) và Khách hàng nhận (Client).

Dùng lệnh sau trong Terminal (Command Prompt / PowerShell) tại thư mục `AES`:
```bash
python main.py
```
Màn hình sẽ hiển thị Menu lựa chọn:
```text
========================================
 AES FILE TRANSFER 
========================================
1. Send File (Server)
2. Receive File (Client)
3. Exit
>
```

---

### 🟢 1. Chế độ Gửi File - Sender (Đóng vai trò Server)
Ở Menu, chọn `1` để trở thành máy chủ cho file.

1. **Enter port:** Chọn một con số lớn (Ví dụ: `9999`) làm Cổng mạng để chương trình mở ra và đứng đợi (Binding/Listening).
2. **Enter file path:** Nhập đường dẫn trỏ tới file trên máy tính mà bạn muốn truyền đi.
   - *Ví dụ ở cùng khu vực code:* `test.txt`
   - *Ví dụ thư mục ngẫu nhiên:* `C:\Images\avatar.png`
3. **Enter secret key:** Nhập vào mật khẩu (Khóa) bảo vệ tự chọn. 
   - *Lưu ý:* Chương trình sẽ tự động định dạng khóa này về 16 bytes (AES-128). Phải nhớ kỹ Mật khẩu này để gửi cho người nhận!

Sau khi nhập xong, máy Gửi sẽ treo trạng thái báo hiệu `[*] Chờ receiver kết nối...`.

---

### 🔵 2. Chế độ Nhận File - Receiver (Đóng vai trò Client)
Ở máy người nhận (hoặc chạy tab mới), chọn `2` ở Menu để vào chế độ tải.

1. **Enter sender IP:** Nhập địa chỉ IP mạng của máy gửi.
   - Nếu bạn đang chạy test cả 2 cái trên *cùng 1 máy tính của bạn*, hãy nhập: `127.0.0.1` (localhost).
   - Nếu gửi qua mạng WiFi nội bộ, chạy lệnh `ipconfig` ở máy gửi để lấy IP IPv4.
2. **Enter port:** Phải nhập y hệt con số Cổng (VD: `9999`) mà máy gửi mở.
3. **Enter secret key:** **PHẢI NHẬP GIỐNG TỪNG CHỮ CÁI** với Secret key mà phía máy gửi điền. Sai một ký tự là bạn sẽ nhận được một file rác!

Chương trình sẽ xông vào kết nối, Tải cục dữ liệu khổng lồ bị mã hóa (Ciphertext) về RAM, đúc ra plaintext dùng Thuật toán biến dạng Galois và lưu thành công File vào máy!

> **Nơi nhận hàng:** Toàn bộ file giải mã thu được sẽ tự động lưu vào trong thư mục `received_files/` dưới tiền tố `decrypted_[TênGốc]`.

---

## ⚠️ Cảnh báo Bảo mật
Nếu bạn điền sai `Secret Key` bên phía Receiver, quá trình giải nén AES của phần lõi sẽ nhận diện sự sai lệch Padding. Hệ thống sẽ **Cảnh Báo Chữ Vàng/Đỏ** và File tải về sẽ chứa toàn các ký tự Data Rác lộn xộn, bị hỏng. Tính tàng hình bảo mật của dữ liệu đã trọn vẹn!
