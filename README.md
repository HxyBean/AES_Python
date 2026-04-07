# 🔒 AES File Transfer

Ứng dụng truyền file bảo mật qua mạng cục bộ (LAN) sử dụng giao thức **TCP Socket** kết hợp thuật toán mã hóa **AES (Advanced Encryption Standard)** ở chế độ **CBC (Cipher Block Chaining)**.

> **Điểm nổi bật:** Toàn bộ lõi mật mã học — bao gồm `S-Box`, `InvS-Box`, `ShiftRows`, `MixColumns`, `KeyExpansion` và số học trên trường Galois `GF(2⁸)` — được **tự lập trình hoàn toàn từ đầu** theo tiêu chuẩn **FIPS 197** mà không phụ thuộc bất kỳ thư viện cryptography nào.

---

## 📋 Mục lục
1. [Yêu cầu môi trường](#-yêu-cầu-môi-trường)
2. [Cài đặt](#-cài-đặt)
3. [Cấu trúc Project](#-cấu-trúc-project)
4. [Các thành phần & Cơ chế](#-các-thành-phần--cơ-chế)
5. [Hướng dẫn sử dụng](#-hướng-dẫn-sử-dụng)
6. [Cơ chế bảo mật](#-cơ-chế-bảo-mật)
7. [Cấu trúc gói tin truyền mạng](#-cấu-trúc-gói-tin-truyền-mạng)

---

## 🛠️ Yêu cầu môi trường

| Thành phần | Yêu cầu |
|---|---|
| **Hệ điều hành** | Windows / Linux / macOS |
| **Python** | 3.6 trở lên |
| **Thư viện ngoài** | ❌ Không cần (chỉ dùng thư viện chuẩn) |
| **Kết nối mạng** | Cùng mạng LAN hoặc localhost |

### Thư viện Python chuẩn được sử dụng
| Thư viện | Mục đích |
|---|---|
| `socket` | Giao tiếp mạng TCP |
| `os` | Sinh IV ngẫu nhiên (`os.urandom(16)`), thao tác đường dẫn |
| `hashlib` | Băm mật khẩu người dùng bằng SHA-256 |

---

## 📥 Cài đặt

```bash
# 1. Tải project về máy
git clone https://github.com/<your-username>/AES.git
cd AES

# 2. Không cần cài thêm gì — chạy ngay
python main.py
```

> Nếu không dùng Git, chỉ cần copy thư mục `AES` về máy rồi mở Terminal và gõ `python main.py`.

---

## 📁 Cấu trúc Project

```
AES/
│
├── main.py                  # Điểm khởi chạy chính — Menu CLI + Logic Socket
│
├── ase_core/                # Lõi thuật toán mật mã học AES
│   ├── aes.py               # Encrypt/Decrypt block, CBC mode
│   ├── key_expansion.py     # Sinh Round Keys (Key Schedule - FIPS 197)
│   ├── sbox.py              # Bảng S-Box và Inv-S-Box (256 phần tử)
│   └── galois.py            # Nhân đa thức trong trường Galois GF(2⁸)
│
├── file_handler/            # Xử lý đọc/ghi file
│   ├── file_io.py           # Đọc và ghi file dạng bytes
│   └── padding.py           # Cơ chế PKCS#7 Padding / Unpadding
│
├── encrypted_files/         # Thư mục chứa file đã mã hóa (tạo tự động)
├── received_files/          # Thư mục chứa file đã giải mã (tạo tự động)
│
└── README.md
```

---

## ⚙️ Các thành phần & Cơ chế

### 1. `ase_core/sbox.py` — Bảng tra cứu thay thế

Chứa 2 bảng tra cứu cố định theo chuẩn FIPS 197:
- **`SBOX[256]`**: Dùng trong bước `SubBytes` khi **mã hóa** — thay thế phi tuyến từng byte của State bằng giá trị tương ứng trong bảng.
- **`INV_SBOX[256]`**: Dùng trong bước `InvSubBytes` khi **giải mã** — tra ngược lại để khôi phục byte gốc.

### 2. `ase_core/galois.py` — Toán học trên trường Galois GF(2⁸)

Cài đặt hàm `gmul(a, b)` để nhân 2 số trong trường `GF(2⁸)` với đa thức bất khả quy `x⁸ + x⁴ + x³ + x + 1` (= `0x11B`). Đây là nền tảng của bước `MixColumns`.

### 3. `ase_core/key_expansion.py` — Lịch sinh khóa vòng

Hàm `key_expansion(key)` nhận khóa gốc và sinh toàn bộ **Round Keys** cho các vòng lặp. Thuật toán dựa trên 2 phép biến đổi:
- `_rot_word()`: Xoay vòng trái 1 byte trong word.
- `_sub_word()`: Tra S-Box cho từng byte trong word.

| Loại AES | Kích thước Key | Nk | Số vòng Nr | Số Round Keys |
|---|---|---|---|---|
| AES-128 | 16 bytes | 4 | 10 | 11 |
| AES-192 | 24 bytes | 6 | 12 | 13 |
| AES-256 | 32 bytes | 8 | 14 | 15 |

> **Riêng AES-256:** Có thêm bước `SubWord` bổ sung tại các vị trí `i % Nk == 4` trong vòng lặp sinh khóa.

### 4. `ase_core/aes.py` — Bộ máy mã hóa / giải mã

#### 4 phép biến đổi của AES:

| Phép biến đổi | Mô tả | Hàm |
|---|---|---|
| **SubBytes** | Thay thế phi tuyến từng byte qua S-Box | `_sub_bytes()` |
| **ShiftRows** | Xoay vòng trái từng hàng (hàng i xoay i vị trí) | `_shift_rows()` |
| **MixColumns** | Nhân mỗi cột với ma trận cố định trong GF(2⁸) | `_mix_columns()` |
| **AddRoundKey** | XOR State với Round Key tương ứng | `_add_round_key()` |

#### Cấu trúc vòng lặp mã hóa:
```
Initial Round:   AddRoundKey(State, RoundKey[0])
Rounds 1..Nr-1:  SubBytes → ShiftRows → MixColumns → AddRoundKey
Final Round:     SubBytes → ShiftRows → AddRoundKey(State, RoundKey[Nr])
```

#### Chế độ CBC (Cipher Block Chaining):
```
Mã hóa:  C[i] = Encrypt( P[i] XOR C[i-1] ),  C[0] = Encrypt( P[0] XOR IV )
Giải mã:  P[i] = Decrypt( C[i] ) XOR C[i-1],  P[0] = Decrypt( C[0] ) XOR IV
```

### 5. `file_handler/padding.py` — PKCS#7 Padding

AES yêu cầu dữ liệu phải là bội số của 16 bytes. PKCS#7 độn thêm `n` byte, mỗi byte có giá trị `n`.
- **Ví dụ:** Nếu thiếu 5 bytes → thêm `05 05 05 05 05`.
- **Đặc biệt:** Nếu dữ liệu đã đủ bội số 16, vẫn thêm 1 block 16 byte toàn giá trị `0x10` để tránh nhầm lẫn khi `unpad`.

### 6. `main.py` — Điểm điều phối chính

Cung cấp giao diện CLI và quản lý toàn bộ luồng hoạt động:
- **`format_key()`**: Dẫn xuất khóa từ mật khẩu người dùng bằng `SHA-256`.
- **`choose_aes_mode()`**: Menu chọn 1 trong 3 chế độ AES.
- **`sender_mode()`**: Logic Server TCP — bind, listen, accept, mã hóa, gửi file.
- **`receiver_mode()`**: Logic Client TCP — connect, nhận, giải mã, lưu file.
- **`recv_exact()`**: Đảm bảo nhận đủ n bytes (chống mất mát gói tin phân mảnh).

---

## 🚀 Hướng dẫn sử dụng

### Bước 0: Khởi động chương trình
```bash
python main.py
```
```
========================================
 AES FILE TRANSFER
========================================
1. Send File (Server)
2. Receive File (Client)
3. Exit
>
```

---

### 🟢 Chế độ 1 — Gửi File (Sender / Server)

> Máy Sender đóng vai **Server** — khởi động trước, chờ Receiver kết nối đến.

Chọn `1` rồi lần lượt nhập:

| Thông tin | Ví dụ | Ghi chú |
|---|---|---|
| **Port** | `9999` | Tự chọn, Receiver phải nhập cùng số này |
| **File path** | `tayduky.txt` hoặc `C:\files\img.png` | Hỗ trợ mọi loại file |
| **Chế độ AES** | `1` / `2` / `3` | Phải đồng thuận với Receiver |
| **Secret key** | `matkhaubimatkinhkhung` | Độ dài tùy ý, hệ thống tự xử lý |

**Sau khi nhập xong**, chương trình in:
```
[+] Server đang chạy tại 0.0.0.0:9999
[*] Chờ receiver kết nối...
```
và chờ. Khi Receiver kết nối, file sẽ được mã hóa, gửi đi và lưu một bản Ciphertext tại `encrypted_files/encrypted_<tên_file>`.

---

### 🔵 Chế độ 2 — Nhận File (Receiver / Client)

> Máy Receiver đóng vai **Client** — khởi động sau, tự kết nối đến Sender.

Chọn `2` rồi lần lượt nhập:

| Thông tin | Ví dụ | Ghi chú |
|---|---|---|
| **Sender IP** | `192.168.1.5` | Dùng `localhost` nếu test cùng 1 máy |
| **Port** | `9999` | Phải khớp với port của Sender |
| **Chế độ AES** | `1` / `2` / `3` | **Bắt buộc phải giống Sender** |
| **Secret key** | `matkhaubimatkinhkhung` | **Bắt buộc phải giống Sender** |

File giải mã sẽ được lưu tại `received_files/decrypted_<tên_file>`.

> **Tìm IP của Sender:**
> - Windows: Mở CMD → gõ `ipconfig` → lấy địa chỉ `IPv4 Address`.
> - Linux/macOS: Mở Terminal → gõ `ip addr` hoặc `ifconfig`.

---

## 🔐 Cơ chế bảo mật

### Hàm dẫn xuất khóa (Key Derivation)
Mật khẩu người dùng nhập **không được dùng trực tiếp** làm khóa AES. Thay vào đó:
```
Key_AES = SHA-256(password)[:req_len]
```
Dù nhập 1 ký tự hay cả đoạn văn, SHA-256 luôn cho ra 32 bytes entropy cao, đảm bảo cả Sender và Receiver nhận cùng một khóa nếu cùng password.

### IV (Initialization Vector)
```python
iv = os.urandom(16)   # 16 bytes ngẫu nhiên thực sự
```
IV được tạo mới mỗi lần gửi, gắn vào gói tin và truyền cùng ciphertext (không cần bảo mật IV). Nhờ IV, cùng 1 file + cùng 1 key nhưng mỗi lần gửi cho ra ciphertext hoàn toàn khác nhau — chống các tấn công phân tích thống kê.

### Phát hiện sai khóa
Nếu Receiver dùng sai key hoặc sai chế độ AES, quá trình `unpad PKCS#7` sẽ thất bại. Hệ thống bắt lỗi, hiện cảnh báo và lưu dữ liệu rác ra file thay vì crash đột ngột.

---

## 📦 Cấu trúc gói tin truyền mạng

Toàn bộ dữ liệu được gói thành 1 payload liên tục và gửi qua Socket:

```
┌─────────────────┬──────────────┬──────────────────┬────────┬────────────┐
│  4 bytes        │  N bytes     │  4 bytes         │ 16 bytes│  M bytes  │
│  (độ dài tên)   │  (tên file)  │  (độ dài cipher) │  (IV)  │ (Cipher)  │
└─────────────────┴──────────────┴──────────────────┴────────┴────────────┘
```

- **4 bytes đầu**: Độ dài (big-endian) của tên file gốc.
- **N bytes**: Tên file gốc (UTF-8).
- **4 bytes tiếp**: Độ dài (big-endian) của ciphertext.
- **16 bytes IV**: Vector khởi tạo ngẫu nhiên.
- **M bytes Ciphertext**: Nội dung đã mã hóa (bội số của 16 bytes).
