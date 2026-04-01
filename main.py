# main.py
# Menu chạy Sender (server) / Receiver (client)

import socket
import os
from ase_core.aes import aes_cbc_encrypt, aes_cbc_decrypt
from file_handler.file_io import read_file, write_file


# =========================
# UTIL
# =========================
def format_key(key_str: str) -> bytes:
    key = key_str.encode("utf-8")
    if len(key) > 16:
        print(f"\n[!] CẢNH BÁO: Key bảo mật của bạn đang dài {len(key)} ký tự (vượt quá 16 bytes).")
        print("    Hệ thống sẽ tự động lấy 16 ký tự đầu tiên để làm khóa chuẩn AES-128.")
    elif len(key) < 16:
        print(f"\n[*] Lưu ý: Key của bạn ngắn {len(key)} ký tự (yêu cầu 16 bytes).")
        print("    Hệ thống sẽ tự động thêm ký tự phụ vào đuôi cho đủ 16 bytes.")
    return key.ljust(16, b'0')[:16]


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
    key_input = input("Enter secret key: ")
    key = format_key(key_input)

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
    key_input = input("Enter secret key: ")
    key = format_key(key_input)

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