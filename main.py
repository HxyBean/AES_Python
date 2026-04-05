# main.py
# Menu chạy Sender (server) / Receiver (client)

import socket
import os
from ase_core.aes import aes_cbc_encrypt, aes_cbc_decrypt
from file_handler.file_io import read_file, write_file


import hashlib

# =========================
# UTIL
# =========================
def format_key(key_str: str, req_len: int) -> bytes:
    """
    Thay vì cắt xén hoặc phân bổ chuỗi gây ra sai lệch Padding,
    chúng ta sử dụng thuật toán Băm SHA-256 để tạo mã băm cố định.
    Dù nhập 1 hay 1000 ký tự, nó vẫn lấy dải byte phân bố chuẩn AES.
    """
    key_bytes = key_str.encode("utf-8")
    derived_key = hashlib.sha256(key_bytes).digest()
    return derived_key[:req_len]

def choose_aes_mode() -> int:
    while True:
        print("\n[ Chọn chế độ mã hóa ]")
        print("1. AES-128 (16 bytes key)")
        print("2. AES-192 (24 bytes key)")
        print("3. AES-256 (32 bytes key)")
        choice = input("Mời chọn (1/2/3): ")
        if choice == '1':
            return 16
        elif choice == '2':
            return 24
        elif choice == '3':
            return 32
        else:
            print("[!] Lựa chọn không hợp lệ, vui lòng chọn lại.")


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Mất kết nối")
        buf += chunk
    return buf


# =========================
# SENDER (SERVER)
# =========================
def sender_mode():
    print("\n=== SENDER (SERVER) ===")

    port = int(input("Enter port: "))
    file_path = input("Enter file path: ")
    
    req_len = choose_aes_mode()
    
    key_input = input(f"Enter secret key ({req_len} ký tự): ")
    key = format_key(key_input, req_len)

    data = read_file(file_path)
    if data is None:
        print("[!] Không đọc được file")
        return

    filename = os.path.basename(file_path).encode("utf-8")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("0.0.0.0", port))
        server.listen(5)

        print(f"[+] Server đang chạy tại 0.0.0.0:{port}")
        print("[*] Chờ receiver kết nối...\n")

        while True:
            conn, addr = server.accept()
            print(f"[+] Receiver kết nối từ {addr}")

            try:
                iv = os.urandom(16)

                print("[*] Đang mã hóa...")
                ciphertext = aes_cbc_encrypt(data, key, iv)

                # ==========================================
                # Lưu tạm file Ciphertext rác cho sender
                enc_dir = "encrypted_files"
                os.makedirs(enc_dir, exist_ok=True)
                enc_out_path = os.path.join(enc_dir, "encrypted_" + filename.decode("utf-8"))
                write_file(enc_out_path, ciphertext)
                print(f"[+] Đã trút dữ liệu mã hóa ra file (để demo): {enc_out_path}")
                # ==========================================

                filename_len = len(filename).to_bytes(4, "big")
                cipher_len   = len(ciphertext).to_bytes(4, "big")

                payload = filename_len + filename + cipher_len + iv + ciphertext

                conn.sendall(payload)
                print("[+] Đã mã hóa và gửi qua Socket")
                print("[+] Gửi file thành công")
                break

            except Exception as e:
                print(f"[!] Lỗi: {e}")

            finally:
                conn.close()
                print("[*] Đóng kết nối\n")


# =========================
# RECEIVER (CLIENT)
# =========================
def receiver_mode():
    print("\n=== RECEIVER (CLIENT) ===")

    server_ip = input("Enter sender IP: ")
    port = int(input("Enter port: "))
    
    req_len = choose_aes_mode()
    
    key_input = input(f"Enter secret key ({req_len} ký tự): ")
    key = format_key(key_input, req_len)

    output_dir = "received_files"
    os.makedirs(output_dir, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[*] Kết nối tới {server_ip}:{port}...")
        s.connect((server_ip, port))
        print("[+] Đã kết nối!")

        filename_len = int.from_bytes(recv_exact(s, 4), "big")
        filename = recv_exact(s, filename_len).decode("utf-8")

        cipher_len = int.from_bytes(recv_exact(s, 4), "big")
        iv = recv_exact(s, 16)
        ciphertext = recv_exact(s, cipher_len)

        print(f"[*] Nhận file: {filename}")
        print("[*] Đang giải mã...")

        try:
            plaintext = aes_cbc_decrypt(ciphertext, key, iv)
        except ValueError as e:
            # Bắt trường hợp bị lỗi padding (do sai key) -> vẫn lấy cục byte rác để lưu
            if len(e.args) >= 2 and e.args[0] == "Padding invalid":
                print("\n[!] CẢNH BÁO: Rất có thể bạn đã nhập SAI KEY!")
                print("[!] Quá trình giải mã thất bại do dữ liệu bị hỏng.")
                plaintext = e.args[1]
            else:
                print(f"[!] Lỗi giải mã: {e}")
                return
        except Exception as e:
            print(f"[!] Lỗi không xác định: {e}")
            return

        out_path = os.path.join(output_dir, "decrypted_" + filename)
        write_file(out_path, plaintext)

        print(f"[+] Lưu file tại: {out_path}")


# =========================
# MAIN MENU
# =========================
def main():
    while True:
        print("\n" + "="*40)
        print(" AES FILE TRANSFER ")
        print("="*40)
        print("1. Send File (Server)")
        print("2. Receive File (Client)")
        print("3. Exit")

        choice = input("> ")

        if choice == "1":
            sender_mode()
        elif choice == "2":
            receiver_mode()
        elif choice == "3":
            print("Bye!")
            break
        else:
            print("Invalid choice!")


if __name__ == "__main__":
    main()