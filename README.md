# 🔒 AES File Transfer

Ứng dụng truyền file bảo mật qua mạng cục bộ (LAN) sử dụng giao thức **TCP Socket** kết hợp thuật toán mã hóa **AES (Advanced Encryption Standard)** ở chế độ **CBC (Cipher Block Chaining)**. Hỗ trợ giao diện web hiện đại và giao diện dòng lệnh (CLI).

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
| **Flask** | Cần cài — dùng cho giao diện Web (`pip install flask`) |
| **Kết nối mạng** | Cùng mạng LAN hoặc localhost |

### Thư viện sử dụng

| Thư viện | Loại | Mục đích |
|---|---|---|
| `socket` | Built-in | Giao tiếp mạng TCP |
| `os` | Built-in | Sinh IV ngẫu nhiên (`os.urandom`), thao tác đường dẫn |
| `hashlib` | Built-in | Băm mật khẩu bằng SHA-256 (Key Derivation) |
| `threading` | Built-in | Chạy Socket song song với giao diện Web |
| `flask` | Cài thêm | Web server, API, SSE log streaming |

---

## 📥 Cài đặt

```bash
# 1. Tải project về máy
git clone https://github.com/<your-username>/AES.git
cd AES

# 2. Cài Flask (chỉ cần cho giao diện Web)
pip install flask

# 3. Khởi chạy
python app.py       # Giao diện Web (khuyến nghị)
# hoặc
python main.py      # Giao diện dòng lệnh CLI
```

---

## 📁 Cấu trúc Project

```
AES/
│
├── app.py                   # Flask Web Server — API + SSE + routing
├── main.py                  # Giao diện CLI (dòng lệnh)
│
├── templates/
│   └── index.html           # Giao diện Web (Dark mode, responsive)
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
├── encrypted_files/         # File đã mã hóa — tạo tự động khi gửi
├── received_files/          # File đã giải mã — tạo tự động khi nhận
│
└── README.md
```

---

## ⚙️ Các thành phần & Cơ chế

### 1. `ase_core/sbox.py` — Bảng tra cứu thay thế

Chứa 2 bảng tra cứu cố định theo chuẩn FIPS 197:
- **`SBOX[256]`**: Dùng trong bước `SubBytes` khi **mã hóa**.
- **`INV_SBOX[256]`**: Dùng trong bước `InvSubBytes` khi **giải mã**.

### 2. `ase_core/galois.py` — Toán học trên trường Galois GF(2⁸)

Hàm `gmul(a, b)` — nhân 2 số trong `GF(2⁸)` với đa thức bất khả quy `x⁸ + x⁴ + x³ + x + 1` (`0x11B`). Được dùng trong bước `MixColumns`.

### 3. `ase_core/key_expansion.py` — Lịch sinh khóa vòng

Hàm `key_expansion(key)` sinh toàn bộ **Round Keys** từ khóa gốc theo chuẩn FIPS 197.

| Loại AES | Key size | Nk | Rounds (Nr) | Số Round Keys |
|---|---|---|---|---|
| AES-128 | 16 bytes | 4 | 10 | 11 |
| AES-192 | 24 bytes | 6 | 12 | 13 |
| AES-256 | 32 bytes | 8 | 14 | 15 |

> **AES-256** có thêm bước `SubWord` bổ sung tại vị trí `i % Nk == 4`.

### 4. `ase_core/aes.py` — Bộ máy mã hóa / giải mã

#### 4 phép biến đổi cốt lõi:

| Phép biến đổi | Mô tả | Hàm |
|---|---|---|
| **SubBytes** | Thay thế phi tuyến từng byte qua S-Box | `_sub_bytes()` |
| **ShiftRows** | Xoay vòng trái từng hàng i thêm i vị trí | `_shift_rows()` |
| **MixColumns** | Nhân mỗi cột với ma trận cố định trong GF(2⁸) | `_mix_columns()` |
| **AddRoundKey** | XOR State với Round Key tương ứng | `_add_round_key()` |

#### Cấu trúc vòng lặp mã hóa:
```
Initial Round:    AddRoundKey(State, RoundKey[0])
Rounds 1..Nr-1:  SubBytes → ShiftRows → MixColumns → AddRoundKey
Final Round:      SubBytes → ShiftRows → AddRoundKey(State, RoundKey[Nr])
```

#### CBC Mode:
```
Mã hóa:  C[i] = Encrypt( P[i] XOR C[i-1] ),  với C[-1] = IV
Giải mã:  P[i] = Decrypt( C[i] ) XOR C[i-1],  với C[-1] = IV
```

### 5. `file_handler/padding.py` — PKCS#7 Padding

AES yêu cầu dữ liệu là bội số của 16 bytes. PKCS#7 độn thêm `n` byte, mỗi byte mang giá trị `n`.

### 6. `app.py` — Flask Web Backend

Xử lý toàn bộ luồng web:

| Route | Method | Chức năng |
|---|---|---|
| `/` | GET | Trả về giao diện `index.html` |
| `/api/send` | POST | Nhận file + config, mã hóa, khởi động TCP Server |
| `/api/receive` | POST | Kết nối TCP tới Sender, giải mã, lưu file |
| `/api/logs` | GET | SSE — stream log realtime về trình duyệt |
| `/api/files` | GET | Danh sách file đã nhận trong `received_files/` |
| `/api/download/<filename>` | GET | Tải file đã giải mã về máy |

---

## 🚀 Hướng dẫn sử dụng

### ▶ Giao diện Web (Khuyến nghị)

```bash
python app.py
```
Mở trình duyệt, truy cập: **http://localhost:5000**

---

### 🟢 Gửi File (Sender)

1. Kéo thả hoặc nhấp chọn file muốn gửi vào ô **"Chọn File cần gửi"**.
2. Nhập **Port** (ví dụ: `9999`).
3. Chọn **Chế độ AES** — 128 / 192 / 256.
4. Nhập **Secret Key** (mật khẩu tùy ý, độ dài không giới hạn).
5. Nhấn **"Khởi động Server & Gửi File"**.
6. Theo dõi trạng thái trực tiếp trên **Console Log** phía dưới.

> Sau khi gửi xong, một bản file mã hóa sẽ được lưu vào thư mục `encrypted_files/`.

---

### 🔵 Nhận File (Receiver)

1. Nhập **IP của Sender** (`localhost` nếu cùng máy, hoặc IP mạng LAN như `192.168.1.x`).
2. Nhập **Port** phải khớp với Sender.
3. Chọn **Chế độ AES** — **bắt buộc phải giống Sender**.
4. Nhập **Secret Key** — **bắt buộc phải giống Sender**.
5. Nhấn **"Kết nối & Nhận File"**.
6. Sau khi nhận xong, file xuất hiện ngay trong danh sách **"File đã nhận"**, nhấn **⬇ Tải** để tải về máy.

> **Tìm IP của Sender:**
> - Windows: mở CMD → gõ `ipconfig` → lấy địa chỉ `IPv4 Address`.
> - Linux/macOS: mở Terminal → gõ `ip addr` hoặc `ifconfig`.

---

### ▶ Giao diện CLI (Dòng lệnh)

```bash
python main.py
```

Chọn `1` để Gửi, `2` để Nhận, `3` để thoát. Nhập lần lượt theo hướng dẫn trên màn hình.

---

## 🔐 Cơ chế bảo mật

### Hàm dẫn xuất khóa (Key Derivation — SHA-256)

Mật khẩu người dùng **không làm khóa AES trực tiếp**. Thay vào đó:
```
Key_AES = SHA-256(password)[:req_len]
```
Dù nhập 1 hay 1000 ký tự, SHA-256 luôn cho ra 32 bytes entropy cao, đảm bảo cả Sender và Receiver luôn nhận cùng một khóa nếu nhập cùng mật khẩu. Không còn lỗi "sai key do cắt xén chuỗi".

### IV (Initialization Vector)

```python
iv = os.urandom(16)   # 16 bytes ngẫu nhiên thực sự mỗi lần gửi
```

IV được sinh mới hoàn toàn theo từng phiên gửi, gắn vào gói tin và truyền cùng ciphertext (IV không cần bảo mật). Nhờ đó, cùng file + cùng key nhưng mỗi lần gửi cho ra ciphertext khác nhau — chống tấn công phân tích thống kê.

### Phát hiện sai khóa / sai chế độ AES

Nếu Receiver dùng sai key hoặc sai chế độ AES, bước `unpad PKCS#7` sẽ thất bại. Hệ thống bắt lỗi, hiện cảnh báo trên Console Log và lưu dữ liệu rác thay vì crash.

---

## 📦 Cấu trúc gói tin truyền mạng

Toàn bộ dữ liệu đóng gói thành 1 payload liên tục qua TCP Socket:

```
┌──────────────┬───────────┬────────────────┬──────────┬──────────────┐
│   4 bytes    │  N bytes  │    4 bytes     │ 16 bytes │   M bytes    │
│ (len tên file│ (tên file)│ (len ciphertext│   (IV)   │ (Ciphertext) │
└──────────────┴───────────┴────────────────┴──────────┴──────────────┘
```

- **4 bytes đầu**: Độ dài tên file (big-endian).
- **N bytes**: Tên file gốc (UTF-8).
- **4 bytes tiếp**: Độ dài ciphertext (big-endian).
- **16 bytes IV**: Vector khởi tạo ngẫu nhiên.
- **M bytes Ciphertext**: Nội dung đã mã hóa (bội số của 16 bytes do PKCS#7).
