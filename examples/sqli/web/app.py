import os
from flask import Flask, request, render_template, redirect, url_for, session, flash
import pymysql
from pymysql.constants import CLIENT

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET", "change_me_in_lab")
# Chuyển về False nếu muốn demo Blind SQLi khó hơn (ẩn lỗi)
SHOW_ERRORS = os.getenv("SHOW_ERRORS", "true").lower() in ("1","true","yes")

DB_HOST = os.getenv("DB_HOST","db")
DB_USER = os.getenv("DB_USER","vuln")
DB_PASS = os.getenv("DB_PASS","vulnpass")
DB_NAME = os.getenv("DB_NAME","vulndb")

def get_conn():
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, db=DB_NAME,
                           cursorclass=pymysql.cursors.DictCursor,
                           client_flag=CLIENT.MULTI_STATEMENTS,
                           autocommit=True)

def unsafe_query(q):
    conn = None
    cur = None
    rows = []
    err = None
    
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(q)
        
        # Xử lý lấy dữ liệu (cho SELECT)
        try:
            rows = cur.fetchall()
            if rows is None: # Đôi khi fetchall trả về None thay vì list rỗng
                rows = []
        except Exception:
            rows = [] # Lệnh UPDATE/INSERT không có dữ liệu trả về
            
    except Exception as e:
        if SHOW_ERRORS:
            err = str(e)
        else:
            err = "DB error (hidden)"
            
    finally:
        # Đóng kết nối an toàn trong mọi trường hợp
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass
    
    return rows, err, q

def mask_cc(cc):
    if not cc:
        return ""
    s = str(cc)
    if len(s) >= 4:
        return "**** **** **** " + s[-4:]
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
        # Vulnerable login
        q = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}' LIMIT 1;"
        rows, err, raw = unsafe_query(q)
        
        if err:
            return render_template("login.html", raw=raw, err=err)
        if rows:
            session["user"] = {"id": rows[0]["id"], "username": rows[0]["username"], "role": rows[0]["role"]}
            flash("Login successful", "success")
            return redirect(url_for("index"))
        else:
            flash("Login failed", "warning")
            return render_template("login.html", raw=raw, err=None)
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
    raw = None
    if request.method == "POST":
        term = request.form.get("term","").strip()
        
        if term == "":
            err = "Please enter a search term."
            return render_template("search.html", results=[], err=err)
            
        q = f"SELECT id, first_name, last_name FROM customers WHERE id = '{term}' OR first_name LIKE '%{term}%';"
        results, err, raw = unsafe_query(q)
    return render_template("search.html", results=results, err=err, raw=raw)

@app.route("/account", methods=["GET", "POST"])
def account():
    if "user" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))
    
    uid = session["user"]["id"]

    # 1. POST: Update Profile (Blind SQLi)
    if request.method == "POST":
        new_info = request.form.get("full_info", "")
     
        update_q = f"UPDATE users SET full_info = '{new_info}' WHERE id = '{uid}';"
        
        _, err, raw = unsafe_query(update_q)
        
        if err:
        
            q_get_data = f"SELECT id, username, role, full_info, email, cc_number, api_key FROM users WHERE id = '{uid}';"
            rows, _, _ = unsafe_query(q_get_data) 
            
            flash(f"Update failed!", "danger") # Thông báo LỖI

            return render_template("account.html", rows=rows, err=err, raw=raw)

        # Tín hiệu TRUE
        flash("Profile updated successfully!", "success") 
        return redirect(url_for("account")) 
        
        
    # 2. Xử lý GET: Hiển thị thông tin
    q = f"SELECT id, username, role, full_info, email, cc_number, api_key FROM users WHERE id = '{uid}';"
    rows, err, raw = unsafe_query(q)
    
    if err:
        return render_template("account.html", rows=[], err=err, raw=raw)
    
    # Masking sensitive data (chỉ chạy khi rows có dữ liệu)
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
            
    return render_template("account.html", rows=rows, err=None, raw=None)

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Demo Time-based Blind SQLi"""
    if request.method == "POST":
        email = request.form.get("email","")
        
        # Lỗ hổng: Blind SQLi trong WHERE
        q = f"SELECT id FROM users WHERE email = '{email}'"
        
        unsafe_query(q)
        
        flash("If that email exists, we have sent a recovery link.", "info")
        return redirect(url_for("login"))
        
    return render_template("forgot_password.html")
    
@app.route("/user")
def user_profile():
    uid = request.args.get("id","")
    q = f"SELECT id, username, full_info, email, cc_number, api_key FROM users WHERE id = '{uid}';"
    rows, err, raw = unsafe_query(q)
    return render_template("user.html", rows=rows, err=err, raw=raw)

@app.route("/admin")
def admin():
    u = session.get("user")
    if not u:
        flash("Please login first", "warning")
        return redirect(url_for("login"))
    if u.get("role") != "admin":
        flash("Access denied: admin only", "danger")
        return redirect(url_for("index"))
    
    # admin can view all users including secrets
    q = "SELECT id, username, full_info, email, cc_number, api_key FROM users;"
    rows, err, raw = unsafe_query(q)
    return render_template("admin.html", rows=rows, err=err, raw=raw)

@app.context_processor
def inject_user():
    return dict(current_user=session.get("user"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
