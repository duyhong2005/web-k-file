# Digital Signature Web Application

## 📜 Mô tả
Đây là ứng dụng web đơn giản sử dụng **Flask** để thực hiện **ký số** và **xác thực chữ ký số** trên file dữ liệu bằng thuật toán **RSA** và hàm băm **SHA-256**.
![image](https://github.com/user-attachments/assets/bf02d6d4-3d91-4c94-bc7f-a204baecdf10)

### Chức năng chính:
- ✅ Tạo cặp khóa RSA (Private Key và Public Key)
- ✅ Ký số file bất kỳ với khóa riêng (Private Key)
- ✅ Tải file chữ ký (.sig) về máy
- ✅ Xác thực chữ ký số với khóa công khai (Public Key)
- ✅ Ghi log các file đã ký
- ✅ Giao diện hỗ trợ chuyển đổi giữa các tab: Tạo khóa, Ký file, Xác thực chữ ký (không reset sau khi thực hiện chức năng)
- ✅ Nút copy khóa nhanh tiện lợi

---

## 🛠️ Công nghệ sử dụng
- Python 3
- Flask
- PyCryptodome (RSA, SHA-256)
- HTML, CSS (Bootstrap)

---

## 🚀 Cách cài đặt và chạy
1. Clone dự án:
```bash
git clone <repository_link>
cd <tên_thư_mục_dự_án>
