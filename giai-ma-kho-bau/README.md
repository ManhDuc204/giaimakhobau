# Giải Mã Kho Báu

Đây là dự án "Giải Mã Kho Báu", một trò chơi/ứng dụng web tương tác được phát triển để người chơi khám phá và giải quyết các câu đố, mật mã để tìm ra "kho báu" cuối cùng.

---

## Cấu trúc dự án

Dự án được tổ chức như sau:
Tuyệt vời! Tôi hiểu rồi, bạn muốn cập nhật file README.md với nội dung đầy đủ như bạn vừa cung cấp, dựa trên cấu trúc thư mục mà bạn đã hiển thị trong ảnh (dự án "giai-ma-kho-bau" trong VS Code).

Dựa trên cấu trúc dự án của bạn, tôi sẽ điều chỉnh một chút phần "Cài đặt" và "Cách sử dụng" để nó phù hợp hơn với các file bạn đang có (như app.py, các file HTML trong templates, script.js, style.css, v.v.).

Đây là nội dung README.md bạn có thể dùng, đã được điều chỉnh và bổ sung để phù hợp với dự án "Giải Mã Kho Báu" của bạn:

Markdown

# Giải Mã Kho Báu

Đây là dự án "Giải Mã Kho Báu", một trò chơi/ứng dụng web tương tác được phát triển để người chơi khám phá và giải quyết các câu đố, mật mã để tìm ra "kho báu" cuối cùng.

---

## Cấu trúc dự án

Dự án được tổ chức như sau:
giai-ma-kho-bau/
├── .venv/                   # Môi trường ảo Python (Virtual environment)
├── pycache/                 # Thư mục cache của Python
├── static/                  # Chứa các file tĩnh (CSS, JS, ảnh)
│   ├── audio/
│   ├── images/
│   ├── js/
│   │   └── script.js
│   └── style.css
├── templates/               # Chứa các file HTML (Flask Jinja2 templates)
│   ├── game_complete.html
│   ├── game_intro.html
│   ├── level_01.html
│   ├── level_02.html
│   ├── level_03.html
│   ├── level_04.html
│   ├── select_level.html
│   └── settings.html
├── app.py                   # Logic chính của ứng dụng Flask
├── crypto_utils.py          # Module chứa các hàm xử lý mật mã (nếu có)
└── README.md                # File mô tả dự án
---

## Tính năng chính

* **Hệ thống cấp độ:** Các câu đố được chia thành nhiều cấp độ khác nhau (`level_01.html` đến `level_04.html`).
* **Giao diện người dùng web:** Trò chơi được xây dựng với HTML, CSS và JavaScript để tương tác trực quan.
* **Backend với Python Flask:** Xử lý logic game, định tuyến và dữ liệu.
* **Hỗ trợ mật mã:** Có thể tích hợp các hàm giải mã hoặc tạo mật mã (`crypto_utils.py`).
* **Màn hình giới thiệu & hoàn thành:** Trải nghiệm game đầy đủ từ giới thiệu đến khi hoàn thành.
* **Chọn cấp độ:** Cho phép người chơi chọn cấp độ muốn chơi.

---

## Cài đặt

Để chạy dự án này trên máy tính của bạn, hãy làm theo các bước sau:

1.  **Sao chép kho lưu trữ (Clone the repository):**
    ```bash
    git clone [https://github.com/your-username/giai-ma-kho-bau.git](https://github.com/ManhDuc204/giai-ma-kho-bau.git)
    ```
2.  **Di chuyển vào thư mục dự án:**
    ```bash
    cd giai-ma-kho-bau
    ```

3.  **Tạo và kích hoạt môi trường ảo (Virtual Environment - Rất khuyến khích):**
    Điều này giúp quản lý các thư viện Python của dự án mà không ảnh hưởng đến hệ thống của bạn.

    * **Trên Windows:**
        ```bash
        python -m venv .venv
        .venv\Scripts\activate
        ```
    * **Trên macOS/Linux:**
        ```bash
        python3 -m venv .venv
        source .venv/bin/activate
        ```

4.  **Cài đặt các thư viện phụ thuộc:**
    Bạn sẽ cần tạo một file `requirements.txt` để liệt kê các thư viện Python mà dự án sử dụng (ví dụ: `Flask`). Nếu bạn chưa có, hãy tạo nó.

    ```bash
    # Ví dụ nội dung của requirements.txt:
    # Flask==2.3.2
    # (thêm các thư viện khác nếu có)
    ```
    Sau đó chạy:
    ```bash
    pip install -r requirements.txt
    ```

    *Lưu ý:* Nếu bạn có thêm các thư viện JavaScript hoặc CSS cần cài đặt (ví dụ: thông qua `npm`), bạn sẽ thêm các bước đó ở đây. Hiện tại, các file `script.js` và `style.css` là các file tĩnh.

---

## Cách sử dụng

Sau khi cài đặt xong, bạn có thể chạy ứng dụng web:

1.  **Đảm bảo môi trường ảo đã được kích hoạt.** (Xem bước 3 trong "Cài đặt")

2.  **Chạy ứng dụng Flask:**
    ```bash
    python app.py
    ```

3.  **Truy cập ứng dụng:**
    Mở trình duyệt web của bạn và truy cập vào địa chỉ thường là `http://127.0.0.1:5000/` hoặc địa chỉ được hiển thị trong terminal sau khi chạy `app.py`.

---

## Đóng góp

Mọi đóng góp cho dự án "Giải Mã Kho Báu" đều được chào đón! Nếu bạn có ý tưởng mới, tìm thấy lỗi, hoặc muốn cải thiện mã nguồn, vui lòng:

1.  Tạo một "Issue" để mô tả vấn đề hoặc ý tưởng của bạn.
2.  Fork repository này, tạo một nhánh mới, thực hiện thay đổi và gửi "Pull Request".

---

**Liên hệ**

Nếu bạn có bất kỳ câu hỏi nào, vui lòng liên hệ:
* [Nguyễn Mạnh Đức] - [nguyenmanhduc120904@gmail.com]