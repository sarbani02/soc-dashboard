from flask import Flask, render_template, request, redirect, session, send_file
import random
from datetime import datetime
from collections import defaultdict
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import requests

app = Flask(__name__)
app.secret_key = "secret123"

users = {
    "admin": generate_password_hash("1234")
}

ips = ["192.168.1.10", "8.8.8.8", "103.21.244.0", "45.33.32.156"]

def get_country(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        return res.get("country", "Unknown")
    except:
        return "Unknown"

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        if u in users and check_password_hash(users[u], p):
            session["user"] = u
            return redirect("/dashboard")
        else:
            return "Login Failed"

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    logs = []
    ip_fail_count = defaultdict(int)
    blocked_ips = []

    for i in range(10):
        ip = random.choice(ips)
        status = random.choice(["ok", "fail"])

        event = "Login Success" if status == "ok" else "Login Failed"
        attack = "Normal" if status == "ok" else "Brute Force"

        log = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "event": event,
            "status": status,
            "ip": ip,
            "country": get_country(ip),
            "attack": attack,
            "severity": "Low"
        }

        if status == "fail":
            ip_fail_count[ip] += 1

        if ip_fail_count[ip] >= 3:
            log["alert"] = True
            log["severity"] = "High"
            if ip not in blocked_ips:
                blocked_ips.append(ip)
        elif ip_fail_count[ip] == 2:
            log["alert"] = True
            log["severity"] = "Medium"
        else:
            log["alert"] = False

        log["anomaly"] = True if (attack == "Brute Force" and status == "fail") else False

        logs.append(log)

    total_logs = len(logs)
    total_alerts = sum(1 for l in logs if l["alert"])
    failed = sum(1 for l in logs if l["status"] == "fail")
    success = sum(1 for l in logs if l["status"] == "ok")

    times = [l["time"] for l in logs]
    statuses = [1 if l["status"] == "fail" else 0 for l in logs]

    app.logs_data = logs

    return render_template(
        "dashboard.html",
        logs=logs,
        total_logs=total_logs,
        total_alerts=total_alerts,
        failed=failed,
        success=success,
        times=times,
        statuses=statuses,
        blocked_ips=blocked_ips
    )

@app.route("/download")
def download():
    logs = getattr(app, "logs_data", [])

    with open("logs.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Time","Event","IP","Country","Attack","Severity"])

        for l in logs:
            writer.writerow([l["time"], l["event"], l["ip"], l["country"], l["attack"], l["severity"]])

    return send_file("logs.csv", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)