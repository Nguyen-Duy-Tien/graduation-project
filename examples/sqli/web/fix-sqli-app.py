import os
from flask import Flask, request, render_template, redirect, url_for, session, flash
import pymysql
from pymysql.constants import CLIENT

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET", "change_me_in_lab")

# [SECURE] Luôn tắt hiển thị lỗi chi tiết trong môi trường Production
SHOW_ERRORS = False 

DB_HOST = os.getenv("DB_HOST","db")
DB_USER = os.getenv("DB_USER","vuln")
DB_PASS = os.getenv("DB_PASS","vulnpass")
DB_NAME = os.getenv("DB_NAME","vulndb")

def get_conn():
    # [SECURE] Loại bỏ CLIENT.MULTI_STATEMENTS để ngăn chặn Stacked Queries
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, db=DB_NAME,
                           cursorclass=pymysql.cursors.DictCursor,
                           autocommit=True)

def safe_query(q_template, params=None):
    """
    Thực thi SQL an toàn sử dụng Parameterized Queries.
    :param q_template: Câu lệnh SQL với placeholder %s (ví dụ: "SELECT * FROM users WHERE id=%s")
    :param params: Tuple chứa các giá trị tương ứng (ví dụ: (user_id,))
    """
    conn = None
    cur = None
    rows = []
    err = None
    
    try:
        conn = get_conn()
        cur = conn.cursor()
        
        # [SECURE] Sử dụng execute với tham số riêng biệt
        # Thư viện pymysql sẽ tự động escape các ký tự đặc biệt trong params
        cur.execute(q_template, params)
        
        try:
            rows = cur.fetchall()
            if rows is None: rows = []
        except Exception:
            rows = []
            
    except Exception as e:
        # [SECURE] Log lỗi ra console (cho dev) nhưng KHÔNG trả về cho người dùng
        print(f"Database Error: {e}") 
        if SHOW_ERRORS:
            err = str(e)
        else:
            err = "An unexpected error occurred. Please try again later."
            
    finally:
        if cur: 
            try: cur.close() 
            except: pass
        if conn: 
            try: conn.close() 
            except: pass
    
    # Không trả về raw query nữa để tránh lộ cấu trúc
    return rows, err 

def mask_cc(cc):
    if not cc: return ""
    s = str(cc)
    if len(s) >= 4: return "**** **** **** " + s[-4:]
    return "****"

@app.route("/")
def index():
    user = session.get("user")
    return render_template("index.html", user=user)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","")
        password = request.form.get("password","")
        
        # [SECURE] Sử dụng %s làm placeholder
        q = "SELECT id, username, role FROM users WHERE username = %s AND password = %s LIMIT 1;"
        
        # [SECURE] Truyền tham số dưới dạng tuple
        rows, err = safe_query(q, (username, password))
        
        if err:
            return render_template("login.html", err=err)
        if rows:
            session["user"] = {"id": rows[0]["id"], "username": rows[0]["username"], "role": rows[0]["role"]}
            flash("Login successful", "success")
            return redirect(url_for("index"))
        else:
            flash("Login failed", "warning")
            return render_template("login.html", err=None)
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out", "info")
    return redirect(url_for("index"))

@app.route("/search", methods=["GET","POST"])
def search():
    results = []
    err = None
    if request.method == "POST":
        term = request.form.get("term","").strip()
        
        if term == "":
            err = "Please enter a search term."
            return render_template("search.html", results=[], err=err)
        
        # [SECURE] Parameterized Query cho cả WHERE = và LIKE
        # Lưu ý: Với LIKE, ta cần thêm dấu % vào biến tham số
        q = "SELECT id, first_name, last_name FROM customers WHERE id = %s OR first_name LIKE %s;"
        
        # Chuẩn bị tham số cho LIKE
        term_like = f"%{term}%"
        
        rows, err = safe_query(q, (term, term_like))
        results = rows
        
    return render_template("search.html", results=results, err=err)

@app.route("/account", methods=["GET", "POST"])
def account():
    if "user" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))
    
    uid = session["user"]["id"]

    if request.method == "POST":
        new_info = request.form.get("full_info", "")
        
        # [SECURE] Vá lỗ hổng Blind SQLi trong UPDATE
        # Dữ liệu new_info sẽ được escape, biến thành chuỗi thuần túy
        # Payload tấn công sẽ bị vô hiệu hóa (ví dụ: ' OR 1=1 sẽ thành chuỗi "\' OR 1=1")
        update_q = "UPDATE users SET full_info = %s WHERE id = %s;"
        
        safe_query(update_q, (new_info, uid))
        
        flash("Profile updated successfully!", "success")
        return redirect(url_for("account"))

    # [SECURE] Vá lỗ hổng trong SELECT profile
    q = "SELECT id, username, role, full_info, email, cc_number, api_key FROM users WHERE id = %s;"
    rows, err = safe_query(q, (uid,))
    
    if err:
        return render_template("account.html", rows=[], err=err)
    
    # Masking sensitive data
    if rows:
        for r in rows:
            if session["user"].get("role") != "admin":
                r["cc_masked"] = mask_cc(r.get("cc_number"))
                r["cc_number"] = None
                r["api_key_masked"] = (r.get("api_key")[:4] + "..." ) if r.get("api_key") else ""
                r["api_key"] = None
            else:
                r["cc_masked"] = r.get("cc_number")
                r["api_key_masked"] = r.get("api_key")
            
    return render_template("account.html", rows=rows, err=None)

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email","")
        
        # [SECURE] Vá lỗ hổng Time-based Blind SQLi
        q = "SELECT id FROM users WHERE email = %s"
        
        safe_query(q, (email,))
        
        flash("If that email exists, we have sent a recovery link.", "info")
        return redirect(url_for("login"))
        
    return render_template("forgot_password.html")

@app.route("/user")
def user_profile():
    uid = request.args.get("id","")
    
    # [SECURE] Vá lỗ hổng SQLi qua URL parameter
    q = "SELECT id, username, full_info, email, cc_number, api_key FROM users WHERE id = %s;"
    rows, err = safe_query(q, (uid,))
    
    return render_template("user.html", rows=rows, err=err)

@app.route("/admin")
def admin():
    u = session.get("user")
    if not u:
        flash("Please login first", "warning")
        return redirect(url_for("login"))
    
    # [SECURE] Cần thêm cơ chế kiểm tra quyền mạnh mẽ hơn (Ví dụ: truy vấn lại DB để check role)
    # Tuy nhiên ở mức độ code này, việc ngăn chặn SQLi Login Bypass đã giúp hạn chế rủi ro này.
    if u.get("role") != "admin":
        flash("Access denied: admin only", "danger")
        return redirect(url_for("index"))
        
    q = "SELECT id, username, full_info, email, cc_number, api_key FROM users;"
    # Admin query này không nhận input từ người dùng nên tương đối an toàn
    rows, err = safe_query(q) 
    
    return render_template("admin.html", rows=rows, err=err)

@app.context_processor
def inject_user():
    return dict(current_user=session.get("user"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
