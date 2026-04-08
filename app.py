# app.py
# Flask web server — cầu nối giữa giao diện HTML và lõi AES Python

from flask import Flask, render_template, request, jsonify, Response, send_file
import threading
import queue
import os
import socket
import json
import time
import hashlib

from ase_core.aes import aes_cbc_encrypt, aes_cbc_decrypt
from file_handler.file_io import read_file, write_file

app = Flask(__name__)

# Hàng đợi log toàn cục — dùng cho SSE (Server-Sent Events)
log_queue = queue.Queue()


# ==================================================
# UTIL
# ==================================================

def log(msg, level="info"):
    """Đẩy 1 dòng log vào hàng đợi để SSE truyền về frontend."""
    log_queue.put({
        "message": msg,
        "level": level,
        "time": time.strftime("%H:%M:%S")
    })


def format_key(key_str: str, req_len: int) -> bytes:
    """Dẫn xuất khóa AES từ mật khẩu người dùng bằng SHA-256."""
    key_bytes = key_str.encode("utf-8")
    derived = hashlib.sha256(key_bytes).digest()
    return derived[:req_len]


def recv_exact(conn, n):
    """Nhận đúng n bytes từ socket (chống mất mát gói tin phân mảnh)."""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Mất kết nối")
        buf += chunk
    return buf


# ==================================================
# SENDER THREAD
# ==================================================

def sender_thread(port, file_data, filename, key, aes_label):
    try:
        log(f"🔐 Bắt đầu mã hóa bằng {aes_label}...", "info")
        iv = os.urandom(16)
        ciphertext = aes_cbc_encrypt(file_data, key, iv)
        log(f"✅ Mã hóa xong — {len(ciphertext)} bytes ciphertext", "success")

        # Lưu file ciphertext ra disk
        enc_dir = "encrypted_files"
        os.makedirs(enc_dir, exist_ok=True)
        enc_path = os.path.join(enc_dir, "encrypted_" + filename)
        write_file(enc_path, ciphertext)
        log(f"💾 File mã hóa đã lưu: {enc_path}", "info")

        # Đóng gói payload
        filename_bytes = filename.encode("utf-8")
        payload = (
            len(filename_bytes).to_bytes(4, "big") +
            filename_bytes +
            len(ciphertext).to_bytes(4, "big") +
            iv +
            ciphertext
        )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", port))
            server.listen(1)
            log(f"🟢 Server đang lắng nghe tại cổng {port}", "info")
            log("⏳ Chờ Receiver kết nối... (timeout 120s)", "waiting")

            server.settimeout(120)
            try:
                conn, addr = server.accept()
                log(f"📡 Receiver kết nối từ {addr[0]}:{addr[1]}", "success")
                with conn:
                    conn.sendall(payload)
                    log(f"📤 Đã gửi '{filename}' thành công!", "success")
                    log("─" * 50, "divider")
            except socket.timeout:
                log("⏰ Timeout: Không có Receiver kết nối trong 120 giây.", "error")

    except Exception as e:
        log(f"❌ Lỗi Sender: {str(e)}", "error")


# ==================================================
# RECEIVER THREAD
# ==================================================

def receiver_thread(server_ip, port, key, output_dir):
    try:
        log(f"🔌 Đang kết nối tới {server_ip}:{port}...", "info")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(20)
            s.connect((server_ip, port))
            log("✅ Kết nối thành công!", "success")

            # Nhận metadata
            filename_len = int.from_bytes(recv_exact(s, 4), "big")
            filename = recv_exact(s, filename_len).decode("utf-8")
            cipher_len = int.from_bytes(recv_exact(s, 4), "big")
            iv = recv_exact(s, 16)
            ciphertext = recv_exact(s, cipher_len)

            log(f"📥 Nhận file '{filename}' ({cipher_len} bytes)", "info")
            log("🔓 Đang giải mã...", "info")

            try:
                plaintext = aes_cbc_decrypt(ciphertext, key, iv)
            except ValueError as e:
                if len(e.args) >= 2 and e.args[0] == "Padding invalid":
                    log("⚠️ SAI KEY hoặc SAI chế độ AES! File bị hỏng.", "error")
                    plaintext = e.args[1]
                else:
                    log(f"❌ Lỗi giải mã: {e}", "error")
                    return

            os.makedirs(output_dir, exist_ok=True)
            out_path = os.path.join(output_dir, "decrypted_" + filename)
            write_file(out_path, plaintext)
            log(f"💾 Đã lưu: {out_path}", "success")
            log(f"🎉 Hoàn tất! File sẵn sàng tải về.", "success")
            log("─" * 50, "divider")

    except socket.timeout:
        log("⏰ Timeout: Không thể kết nối tới Sender.", "error")
    except ConnectionRefusedError:
        log("❌ Kết nối bị từ chối — kiểm tra lại IP và Port.", "error")
    except Exception as e:
        log(f"❌ Lỗi Receiver: {str(e)}", "error")


# ==================================================
# FLASK ROUTES
# ==================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/send", methods=["POST"])
def api_send():
    try:
        port = int(request.form.get("port", 9999))
        aes_choice = int(request.form.get("aes_mode", 1))
        key_str = request.form.get("secret_key", "")

        req_len_map = {1: 16, 2: 24, 3: 32}
        aes_label_map = {1: "AES-128", 2: "AES-192", 3: "AES-256"}
        req_len = req_len_map.get(aes_choice, 16)
        key = format_key(key_str, req_len)

        file = request.files.get("file")
        if not file or file.filename == "":
            return jsonify({"error": "Chưa chọn file!"}), 400

        filename = file.filename
        file_data = file.read()

        log("=" * 50, "divider")
        log(f"📂 File: {filename} ({len(file_data):,} bytes)", "info")
        log(f"🔑 Chế độ: {aes_label_map[aes_choice]} | Port: {port}", "info")

        t = threading.Thread(
            target=sender_thread,
            args=(port, file_data, filename, key, aes_label_map[aes_choice]),
            daemon=True
        )
        t.start()
        return jsonify({"status": "started"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/receive", methods=["POST"])
def api_receive():
    try:
        data = request.get_json()
        server_ip = data.get("server_ip", "localhost")
        port = int(data.get("port", 9999))
        aes_choice = int(data.get("aes_mode", 1))
        key_str = data.get("secret_key", "")

        req_len_map = {1: 16, 2: 24, 3: 32}
        aes_label_map = {1: "AES-128", 2: "AES-192", 3: "AES-256"}
        req_len = req_len_map.get(aes_choice, 16)
        key = format_key(key_str, req_len)

        log("=" * 50, "divider")
        log(f"🎯 Kết nối tới: {server_ip}:{port}", "info")
        log(f"🔑 Chế độ: {aes_label_map[aes_choice]}", "info")

        t = threading.Thread(
            target=receiver_thread,
            args=(server_ip, port, key, "received_files"),
            daemon=True
        )
        t.start()
        return jsonify({"status": "started"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/logs")
def api_logs():
    """SSE endpoint — stream log liên tục về frontend."""
    def generate():
        while True:
            try:
                item = log_queue.get(timeout=25)
                yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
            except queue.Empty:
                yield "data: {\"heartbeat\": true}\n\n"
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/files")
def api_files():
    """Trả về danh sách file đã giải mã."""
    output_dir = "received_files"
    if not os.path.exists(output_dir):
        return jsonify([])
    files = []
    for f in sorted(os.listdir(output_dir)):
        fp = os.path.join(output_dir, f)
        if os.path.isfile(fp):
            files.append({"name": f, "size": os.path.getsize(fp)})
    return jsonify(files)


@app.route("/api/download/<path:filename>")
def api_download(filename):
    """Tải file đã giải mã về máy."""
    path = os.path.join("received_files", filename)
    if not os.path.exists(path):
        return "File not found", 404
    return send_file(os.path.abspath(path), as_attachment=True, download_name=filename)


if __name__ == "__main__":
    print("\n🔒 AES File Transfer — Web Interface")
    print("📡 Truy cập: http://localhost:5000\n")
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
