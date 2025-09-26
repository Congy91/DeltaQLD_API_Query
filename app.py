from flask import Flask, render_template, request, redirect, url_for, session, flash
import requests
from requests.auth import HTTPBasicAuth
import json
import threading
import time
import csv
from flask import Response

app = Flask(__name__)
app.secret_key = "supersecretkey"  # change in production

# ---------------- Global Persistent Sessions ---------------- #
# Store authenticated sessions keyed by username
session_requests = {}
session_lock = threading.Lock()  # ensure thread safety

def get_authenticated_session(username, password, base_url):
    """Authenticate once and reuse session for future calls, with a short wait for cookie setup."""
    s = requests.Session()
    s.auth = (username, password)

    try:
        # Initial request to establish session cookie
        test_url = f"{base_url}/api/.bacnet?alt=json"
        r = s.get(test_url, timeout=60)
        if r.status_code == 401:
            print("[WARN] Got 401 on initial request, waiting 3 seconds before retrying...")
            time.sleep(3)
            r = s.get(test_url, timeout=60)

        r.raise_for_status()
        print(f"[INFO] Authenticated session ready. Status: {r.status_code}")

    except Exception as e:
        print(f"[ERROR] Initial auth failed: {e}")
        raise e

    return s

# ---------------- LOGOUT / CHANGE SITE ---------------- #
@app.route("/logout")
def logout():
    session.clear()
    # Clear cookies from the user's persistent session if exists
    username = session.get("username")
    with session_lock:
        if username in session_requests:
            session_requests[username].cookies.clear()
            del session_requests[username]
    flash("Session cleared. Please log in again.", "info")
    return redirect(url_for("login"))

# ---------------- LOGIN ---------------- #
@app.route("/", methods=["GET", "POST"])
def login():
    # Clear previous session info
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        base_url = (request.form.get("base_url") or "").rstrip("/")

        if not username or not password or not base_url:
            flash("All fields are required.", "danger")
            return redirect(url_for("login"))

        # Save login info in Flask session
        session["username"] = username
        session["password"] = password
        session["base_url"] = base_url

        print(f"[DEBUG] Attempting login at {base_url}")

        # Test connection with persistent session
        try:
            s = get_authenticated_session(username, password, base_url)
            api_url = f"{base_url}/api/.bacnet?alt=json"
            response = s.get(api_url, timeout=60)  # 1-minute timeout
            response.raise_for_status()
            return redirect(url_for("select_site"))
        except requests.HTTPError as e:
            print(f"[ERROR] Login test failed. Status: {e.response.status_code}, Response: {e.response.text}")
            flash("Unable to connect. Check credentials or URL.", "danger")
        except requests.RequestException as e:
            print(f"[EXCEPTION] Error connecting to API during login: {e}")
            flash(f"Error connecting: {str(e)}", "danger")

    return render_template("login.html")



# ---------------- SITES ---------------- #
from requests.exceptions import ReadTimeout

@app.route("/sites", methods=["GET", "POST"])
def select_site():
    username = session.get("username")
    password = session.get("password")
    base_url = session.get("base_url")
    if not username or not password or not base_url:
        flash("Please login first.", "danger")
        return redirect(url_for("login"))

    devices = []
    selected_site = None

    # Use a persistent session with auth
    s = requests.Session()
    s.auth = (username, password)

    # Helper: retry GET/POST for 401 and read timeout
    def retry_request(func, retries=2, timeout=300):  # 5 minutes
        last_exception = None
        for attempt in range(retries):
            try:
                resp = func()
                resp.raise_for_status()
                return resp
            except ReadTimeout as e:
                print(f"[WARN] Read timeout, retrying... ({attempt+1}/{retries}) {e}")
                last_exception = e
            except requests.HTTPError as e:
                if e.response.status_code == 401:
                    print(f"[WARN] Got 401, retrying... ({attempt+1}/{retries}) {e}")
                    last_exception = e
                else:
                    raise
        if last_exception:
            raise last_exception

    # Get list of sites
    try:
        sites_response = retry_request(lambda: s.get(f"{base_url}/api/.bacnet?alt=json", timeout=300))
        sites_json = sites_response.json()
        sites = [key for key in sites_json.keys() if key not in ["$base", "nodeType", "truncated"]]
        print(f"[INFO] Sites fetched: {sites}")
    except Exception as e:
        print(f"[EXCEPTION] Failed to fetch sites: {e}")
        flash(f"Failed to fetch sites: {str(e)}", "danger")
        sites = []

    # If user selected a site, fetch devices
    if request.method == "POST":
        selected_site = request.form.get("site")
        if selected_site:
            try:
                # 1. Get device list
                devices_response = retry_request(
                    lambda: s.get(f"{base_url}/api/.bacnet/{selected_site}?alt=json", timeout=300)
                )
                devices_json = devices_response.json()
                device_ids = [d for d in devices_json.keys() if d not in ["$base", "nodeType", "truncated"]]

                # 2. Build multi-request payload
                multi_values = {}
                for idx, device_id in enumerate(device_ids, start=1):
                    multi_values[f"{idx}_app"] = {"$base": "Any", "via": f"/.bacnet/{selected_site}/{device_id}/device,{device_id}/application-software-version"}
                    multi_values[f"{idx}_fw"] = {"$base": "Any", "via": f"/.bacnet/{selected_site}/{device_id}/device,{device_id}/firmware-revision"}
                    multi_values[f"{idx}_model"] = {"$base": "Any", "via": f"/.bacnet/{selected_site}/{device_id}/device,{device_id}/model-name"}
                    multi_values[f"{idx}_serial"] = {"$base": "Any", "via": f"/.bacnet/{selected_site}/{device_id}/device,{device_id}/serial-number"}
                    multi_values[f"{idx}_ip1"] = {"$base": "Any", "via": f"/.bacnet/{selected_site}/{device_id}/np,6/ip-address"}
                    multi_values[f"{idx}_ip2"] = {"$base": "Any", "via": f"/.bacnet/{selected_site}/{device_id}/np,7/ip-address"}
                    multi_values[f"{idx}_ipold"] = {"$base": "Any", "via": f"/.bacnet/{selected_site}/{device_id}/device,{device_id}/ip-address"}
                    multi_values[f"{idx}_mac"] = {"$base": "Any", "via": f"/.bacnet/{selected_site}/{device_id}/np,4/MAC-Address"}
                    multi_values[f"{idx}_macold"] = {"$base": "Any", "via": f"/.bacnet/{selected_site}/{device_id}/net,1/Advanced_Adapter[4]"}
                    multi_values[f"{idx}_vendorid"] = {"$base": "Any", "via": f"/.bacnet/{selected_site}/{device_id}/device,{device_id}/vendor-identifier"}
                    multi_values[f"{idx}_vendor"] = {"$base": "Any", "via": f"/.bacnet/{selected_site}/{device_id}/device,{device_id}/vendor-name"}

                multi_payload = {
                    "$base": "Struct",
                    "lifetime": {"$base": "Unsigned", "value": 120},
                    "values": {"$base": "List", **multi_values}
                }

                # 3. POST to /api/.multi with 5-minute timeout
                multi_response = retry_request(lambda: s.post(f"{base_url}/api/.multi?alt=json", json=multi_payload, timeout=300))
                multi_json = multi_response.json()
                values = multi_json.get("values", {})

                # --- Helpers ---
                def extract_ip(ip_raw):
                    if not ip_raw or ip_raw == "-":
                        return ""
                    try:
                        if str(ip_raw).lower().startswith("0x"):
                            ip_int = int(ip_raw, 16)
                            return ".".join(str((ip_int >> (8 * i)) & 0xFF) for i in reversed(range(4)))
                        return str(ip_raw)
                    except Exception as e:
                        print(f"[EXCEPTION] Failed to parse IP {ip_raw}: {e}")
                        return ""

                def format_mac(mac_hex):
                    if not mac_hex:
                        return ""
                    try:
                        if mac_hex.lower().startswith("0x"):
                            mac_hex = mac_hex[2:]
                        mac_hex = mac_hex.replace("-", "")
                        mac_int = int(mac_hex, 16)
                        mac_str = f"{mac_int:012x}"
                        return ":".join(mac_str[i:i+2] for i in range(0, 12, 2)).upper()
                    except Exception as e:
                        print(f"[EXCEPTION] Failed to format MAC {mac_hex}: {e}")
                        return ""

                # --- Build devices list ---
                devices = []
                for idx, device_id in enumerate(device_ids, start=1):
                    try:
                        app_version = values.get(f"{idx}_app", {}).get("value")
                        fw_version = values.get(f"{idx}_fw", {}).get("value")
                        model_name = values.get(f"{idx}_model", {}).get("value", "-")
                        serial_number = values.get(f"{idx}_serial", {}).get("value")
                        ##vendorid = values.get(f"{idx}_vendorid", {}).get("value", "-")
                        vendor = values.get(f"{idx}_vendor", {}).get("value", "-")

                        if not serial_number or "error" in str(serial_number).lower():
                            serial_number = "-"

                        # MAC: prefer np,4, fallback to old adapter
                        mac_hex = values.get(f"{idx}_mac", {}).get("value")
                        try:
                            macold_address = values.get(f"{idx}_macold", {}).get("bnEther", {}).get("address", {}).get("value")
                        except (KeyError, TypeError, AttributeError):
                            macold_address = None
                        mac = format_mac(mac_hex) or format_mac(macold_address)

                        # IP1: prefer ipold over np,6
                        ip1_raw = values.get(f"{idx}_ipold", {}).get("value") or values.get(f"{idx}_ip1", {}).get("value", "-")
                        ip1 = extract_ip(ip1_raw)

                        # IP2
                        ip2_raw = values.get(f"{idx}_ip2", {}).get("value", "-")
                        ip2 = extract_ip(ip2_raw)

                        devices.append({
                            "device_id": device_id,
                            "display_name": devices_json[device_id].get("displayName", "-"),
                            "app_version": app_version,
                            "fw_version": fw_version,
                            "model_name": model_name,
                            "serial_number": serial_number,
                            "ip1": ip1,
                            "ip2": ip2,
                            "mac": mac,
                            "vendor": vendor,
                            ##"vendorid": vendorid,
                        })
                    except Exception as inner_e:
                        print(f"[EXCEPTION] Failed to process device {device_id}: {inner_e}")

                devices.sort(key=lambda x: int(x["device_id"]))

            except Exception as e:
                print(f"[EXCEPTION] Failed to fetch device details: {e}")
                flash(f"Failed to fetch device details: {str(e)}", "danger")

    return render_template("sites.html", sites=sites, devices=devices, selected_site=selected_site, base_url=base_url)




# ---------------- API QUERY ---------------- #
@app.route("/api_query", methods=["GET", "POST"])
def api_query():
    json_result = None
    endpoint = ""
    url = ""
    username = ""
    password = ""
    method = "GET"
    body = ""
    status_code = None
    full_url = None

    if request.method == "POST":
        endpoint = request.form.get("endpoint", "").lstrip("/")
        url = (request.form.get("api_base_url") or "").rstrip("/")
        username = request.form.get("api_username")
        password = request.form.get("api_password")
        method = request.form.get("method", "GET")
        body = request.form.get("body", "")

        if endpoint and url and username and password:
            try:
                full_url = f"{url}/{endpoint}"
                s = get_authenticated_session(username, password, url)

                if method.upper() == "POST":
                    data = None
                    if body.strip():
                        try:
                            data = json.loads(body)
                        except Exception as e:
                            print(f"[EXCEPTION] Invalid JSON body: {e}")
                            flash(f"Invalid JSON body: {str(e)}", "danger")
                            return render_template(
                                "api_query.html",
                                json_result=None,
                                endpoint=endpoint,
                                api_base_url=url,
                                api_username=username,
                                api_password=password,
                                method=method,
                                body=body,
                                status_code=None,
                                full_url=full_url
                            )

                    response = s.post(full_url, json=data, timeout=30)
                else:
                    response = s.get(full_url, timeout=30)

                status_code = response.status_code
                if status_code == 401:
                    print("[WARN] Got 401 on API query, retrying...")
                    if method.upper() == "POST":
                        response = s.post(full_url, json=data, timeout=30)
                    else:
                        response = s.get(full_url, timeout=30)

                response.raise_for_status()
                json_result = response.json()

            except Exception as e:
                print(f"[EXCEPTION] API query failed: {e}")
                flash(f"Failed to query API: {str(e)}", "danger")

    return render_template(
        "api_query.html",
        json_result=json_result,
        endpoint=endpoint,
        api_base_url=url,
        api_username=username,
        api_password=password,
        method=method,
        body=body,
        status_code=status_code,
        full_url=full_url
    )
    
import csv
from flask import Response

@app.route("/export_sites", methods=["POST"])
def export_sites():
    username = session.get("username")
    password = session.get("password")
    base_url = session.get("base_url")
    selected_site = request.form.get("selected_site")
    if not all([username, password, base_url, selected_site]):
        flash("Session expired or site not selected.", "danger")
        return redirect(url_for("login"))

    s = get_authenticated_session(username, password, base_url)

    # Fetch devices (reuse your existing logic, with 5-min timeout)
    devices = fetch_devices_for_site(s, base_url, selected_site)  # implement helper

    # Create CSV
    def generate():
        header = ["Device ID", "Display Name", "App Version", "FW Version", "Model", "Serial", "IP1", "IP2", "MAC", "Vendor", "Vendor ID"]
        yield ",".join(header) + "\n"
        for d in devices:
            row = [
                d.get("device_id",""),
                d.get("display_name",""),
                d.get("app_version",""),
                d.get("fw_version",""),
                d.get("model_name",""),
                d.get("serial_number",""),
                d.get("ip1",""),
                d.get("ip2",""),
                d.get("mac",""),
                d.get("vendor",""),
                d.get("vendorid","")
            ]
            yield ",".join(row) + "\n"

    return Response(generate(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment;filename={selected_site}_devices.csv"})



if __name__ == "__main__":
    app.run(debug=True, port=5010)
