# 🔒 AES File Transfer

Dự án truyền và nhận file qua mạng bằng **Socket TCP** sử dụng hệ mã hóa đỉnh cao **AES (Advanced Encryption Standard)** ở chế độ **CBC (Cipher Block Chaining)**. 

> **Điểm nổi bật siêu việt:** Toàn bộ các công đoạn cốt lõi nhất của AES (`S-Box`, `ShiftRows`, `MixColumns`, Cơ chế nở Key `Key Expansion`, Toán học trên trường Galois) được tự lập trình 100% bằng tay theo chuẩn quốc tế **FIPS-197**. Chữ "Crypto" duy nhất ở đây là mồ hôi công sức trải qua hàng trăm ma trận!

---

## 🔥 Tính năng vượt trội
- **Hỗ trợ Trọn bộ Sinh Tồn:** Chạy mượt mà xuyên suốt `AES-128` (10 vòng lặp), `AES-192` (12 vòng lặp) và `AES-256` (14 vòng lặp cùng với lớp giáp SubWord kép).
- **Hàm Dẫn xuất khóa KDF Chuyên Nghiệp:** Sử dụng thuật toán băm `SHA-256` làm cơ sở tịnh tiến mật khẩu. Nhờ vậy, người dùng có thể nhập Mật khẩu ngắn tủn mủn (như "123") hoặc dài ngút ngàn, hệ thống vẫn nhai mượt mà vắt thành Keys độc nhất không bao giờ lo mất mát thông tin Entropy.
- **Trích xuất Ciphertext:** Tích hợp tính năng bóc dữ liệu file Ciphertext ngay ở Sender để sinh viên dễ dàng phô diễn cách file ban đầu bị làm biến dạng nhằng nhịt trước khi bị nén qua đường truyền mạng.

## 🛠️ Yêu cầu môi trường
- Hệ điều hành: Windows, Linux hoặc macOS.
- **Python 3.6+** trở lên. Nền tảng chỉ dùng các tệp tích hợp sẵn như `socket`, `os`, `hashlib`, không bắt cài thêm từ `pip`.

---

## 🚀 Hướng Dẫn Sử Dụng
Mở Terminal ở thư mục hiện tại, gõ lệnh:
```bash
python main.py
```

### 🟢 1. Dành Cho Máy Gửi (Sender / Server)
1. **Enter port:** Bạn tự bịa ra một Cổng mạng (Ví dụ: `8080`) rồi chờ đợi đối phương vác xe tới đón.
2. **Enter file path:** Gõ tên file bạn muốn gửi (VD: `tayduky.txt`).
3. **Mời chọn (1/2/3):** Cửa sổ hiện Menu chọn Hệ bảo mật. Nhấn phím `1` để dùng AES-128 truyền thống, `3` để bật AES-256 quân đội.
4. **Enter secret key:** Nhập vào mật khẩu tự chọn (chữ gì cũng được).
> Khi máy bạn báo *Gửi thành công*, một tệp `.enc_xyz` chứa chi chít ký tự lập dị sẽ nảy ra ở thư mục `encrypted_files`. Bạn có thể mở lên để ngắm nghía.

### 🔵 2. Dành Cho Máy Nhận (Receiver / Client)
1. **Enter sender IP:** IP của máy người gửi (Chơi chung máy thì gõ `localhost`, chơi khác máy gõ IP mạng ảo IPv4 `192.168.x.x`).
2. **Enter port:** Gõ cái cổng đối phương nãy chọn, ở trên là `8080`.
3. **Mời chọn (1/2/3):** Bước tối quan trọng. Nếu đối phương vặn khóa AES-256 mà bạn chọn AES-128 để mở thì cưa chìa đứt đôi ráng chịu. Hãy chọn cho giống!
4. **Enter secret key:** Nhập mật khẩu gốc.
> Dữ liệu bung nén sẽ nằm rình sẵn tại thư mục tải rơi `received_files/`.

---

## ⚠️ Giải Trí & Bug Control
Hệ thống có cài cắm mô-đun Bắt lỗi Padding thông minh ở CBC. Bạn hãy test thử bằng cách ở bước Khách hàng, bạn *Cố tình nhập sai Mật khẩu* hoặc chọn độ chếch lệch AES (Máy kia Gửi cấp lõi Số 3, bạn tải Chọn cấp Số 1). 
Kết quả trả về không bị crash, mà hệ thống sẽ bật rạp xirk **CẢNH BÁO BỊ HỎNG** và file giải mã sẽ rớt ra hàng vạn loại Ký tự ngoài hành tinh. Đảm bảo tính nặc danh rác Rất cao!
