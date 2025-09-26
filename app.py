from flask import Flask, render_template, request, redirect, url_for, session, flash
import requests
import json
import threading
import time
import base64
from requests.exceptions import ReadTimeout, HTTPError
import os

app = Flask(__name__)

# ---------------- SECRET KEY ---------------- #
# Use an environment variable for production, fallback for development
# Generate a secure random key once if not set in env
secret_key = os.environ.get("FLASK_SECRET_KEY")
if not secret_key:
    # Development fallback (random but will change on restart)
    secret_key = os.urandom(32)
app.secret_key = secret_key
print(f"[INFO] Flask secret key set. Length: {len(secret_key)}")

# ---------------- Global Persistent Sessions ---------------- #
session_requests = {}
session_lock = threading.Lock()

# ---------------- Status Codes ---------------- #
STATUS_CODES = {
    200: "OK",
    400: "BAD REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN / ILLEGAL ATTRIBUTE",
    404: "NOT FOUND",
    501: "OPTION NOT SUPPORTED"
}

# ---------------- Basic Auth Helper ---------------- #
def get_basic_auth_headers(username, password):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}

# ---------------- Authenticated Session ---------------- #
def get_authenticated_session(username, password, base_url, retries=3, delay=3):
    """
    Returns a requests.Session() guaranteed to be authenticated.
    Retries login up to `retries` times if 401 occurs.
    """
    s = requests.Session()
    s.headers.update(get_basic_auth_headers(username, password))
    url = f"{base_url}/api/.bacnet?alt=json"
    
    for attempt in range(1, retries+1):
        try:
            r = s.get(url, timeout=60)
            if r.status_code == 401:
                print(f"[WARN] Unauthorized on attempt {attempt}, retrying in {delay}s...")
                time.sleep(delay)
                continue
            r.raise_for_status()
            print(f"[INFO] Authenticated session ready. Status: {r.status_code}")
            return s
        except HTTPError as e:
            if e.response.status_code == 401 and attempt < retries:
                print(f"[WARN] HTTP 401, retrying ({attempt}/{retries}) after {delay}s...")
                time.sleep(delay)
                continue
            else:
                print(f"[ERROR] Authentication failed: {e}")
                raise
        except Exception as e:
            print(f"[ERROR] Error during authentication: {e}")
            raise
    
    raise Exception("Failed to authenticate after multiple attempts")

# ---------------- Logout ---------------- #
@app.route("/logout")
def logout():
    username = session.get("username")
    session.clear()
    with session_lock:
        if username in session_requests:
            session_requests[username].cookies.clear()
            del session_requests[username]
    flash("Session cleared. Please log in again.", "info")
    return redirect(url_for("login"))

# ---------------- Login ---------------- #
@app.route("/", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        base_url = (request.form.get("base_url", "").strip() or "").rstrip("/")

        if not username or not password or not base_url:
            flash("All fields are required.", "danger")
            return redirect(url_for("login"))

        session["username"] = username
        session["password"] = password
        session["base_url"] = base_url

        try:
            s = get_authenticated_session(username, password, base_url)
            # Test GET
            response = s.get(f"{base_url}/api/.bacnet?alt=json", timeout=60)
            if response.status_code == 401:
                print("[WARN] Got 401, retrying once...")
                time.sleep(2)
                response = s.get(f"{base_url}/api/.bacnet?alt=json", timeout=60)
            response.raise_for_status()
            return redirect(url_for("select_site"))
        except HTTPError as e:
            print(f"[ERROR] Login failed. Status: {e.response.status_code}, Response: {e.response.text}")
            flash("Unable to connect. Check credentials or URL.", "danger")
        except requests.RequestException as e:
            print(f"[EXCEPTION] Error connecting: {e}")
            flash(f"Error connecting: {str(e)}", "danger")

    return render_template("login.html")

# ---------------- Retry Helper ---------------- #
def retry_request(func, retries=2, delay=2):
    last_exception = None
    for attempt in range(retries):
        try:
            resp = func()
            if resp.status_code == 401 and attempt < retries - 1:
                # First 401 is expected, retry silently
                time.sleep(delay)
                continue
            print(f"[INFO] Response Status: {resp.status_code} {STATUS_CODES.get(resp.status_code,'')}")
            resp.raise_for_status()
            return resp
        except (HTTPError, ReadTimeout) as e:
            last_exception = e
            if isinstance(e, HTTPError) and e.response.status_code == 401 and attempt < retries - 1:
                time.sleep(delay)
                continue
            print(f"[WARN] Request failed ({attempt+1}/{retries}): {e}")
            time.sleep(delay)
    if last_exception:
        raise last_exception


# ---------------- Sites & Devices ---------------- #
@app.route("/sites", methods=["GET", "POST"])
def select_site():
    username = session.get("username")
    password = session.get("password")
    base_url = session.get("base_url")
    if not username or not password or not base_url:
        flash("Please login first.", "danger")
        return redirect(url_for("login"))

    # ---- Ensure session is fully authorized ----
    try:
        s = get_authenticated_session(username, password, base_url)
    except Exception as e:
        flash(f"Authentication failed: {str(e)}", "danger")
        return redirect(url_for("login"))

    devices = []
    selected_site = None

    # Fetch sites
    try:
        sites_response = retry_request(lambda: s.get(f"{base_url}/api/.bacnet?alt=json", timeout=300))
        sites_json = sites_response.json()
        sites = [k for k in sites_json.keys() if k not in ["$base","nodeType","truncated"]]
        flash(f"Sites API response: {sites_response.status_code} {STATUS_CODES.get(sites_response.status_code,'')}", "info")
    except Exception as e:
        flash(f"Failed to fetch sites: {str(e)}", "danger")
        sites = []

    # Fetch devices for selected site
    if request.method == "POST":
        selected_site = request.form.get("site")
        if selected_site:
            try:
                # --- Get basic device list ---
                devices_response = retry_request(lambda: s.get(f"{base_url}/api/.bacnet/{selected_site}?alt=json", timeout=300))
                devices_json = devices_response.json()
                device_ids = [d for d in devices_json.keys() if d not in ["$base","nodeType","truncated"]]

                # --- Standard multi-request ---
                multi_values = {}
                for idx, device_id in enumerate(device_ids, start=1):
                    multi_values[f"{idx}_app"] = {"$base":"Any","via":f"/.bacnet/{selected_site}/{device_id}/device,{device_id}/application-software-version"}
                    multi_values[f"{idx}_fw"] = {"$base":"Any","via":f"/.bacnet/{selected_site}/{device_id}/device,{device_id}/firmware-revision"}
                    multi_values[f"{idx}_model"] = {"$base":"Any","via":f"/.bacnet/{selected_site}/{device_id}/device,{device_id}/model-name"}
                    multi_values[f"{idx}_serial"] = {"$base":"Any","via":f"/.bacnet/{selected_site}/{device_id}/device,{device_id}/serial-number"}
                    multi_values[f"{idx}_ip1"] = {"$base":"Any","via":f"/.bacnet/{selected_site}/{device_id}/np,6/ip-address"}
                    multi_values[f"{idx}_ip2"] = {"$base":"Any","via":f"/.bacnet/{selected_site}/{device_id}/np,7/ip-address"}
                    multi_values[f"{idx}_ipold"] = {"$base":"Any","via":f"/.bacnet/{selected_site}/{device_id}/device,{device_id}/ip-address"}
                    multi_values[f"{idx}_mac"] = {"$base":"Any","via":f"/.bacnet/{selected_site}/{device_id}/np,4/MAC-Address"}
                    multi_values[f"{idx}_macold"] = {"$base":"Any","via":f"/.bacnet/{selected_site}/{device_id}/net,1/Advanced_Adapter[4]"}
                    multi_values[f"{idx}_vendor"] = {"$base":"Any","via":f"/.bacnet/{selected_site}/{device_id}/device,{device_id}/vendor-name"}

                multi_payload = {"$base":"Struct","lifetime":{"$base":"Unsigned","value":120},"values":{"$base":"List", **multi_values}}
                multi_response = retry_request(lambda: s.post(f"{base_url}/api/.multi?alt=json", json=multi_payload, timeout=300))
                values = multi_response.json().get("values", {})

                def extract_ip(ip_raw):
                    if not ip_raw or ip_raw=="-": return ""
                    try:
                        if str(ip_raw).lower().startswith("0x"):
                            ip_int = int(ip_raw,16)
                            return ".".join(str((ip_int >> (8*i)) & 0xFF) for i in reversed(range(4)))
                        return str(ip_raw)
                    except:
                        return ""

                def format_mac(mac_hex):
                    if not mac_hex: return ""
                    try:
                        if mac_hex.lower().startswith("0x"): mac_hex = mac_hex[2:]
                        mac_int = int(mac_hex.replace("-",""),16)
                        mac_str = f"{mac_int:012x}"
                        return ":".join(mac_str[i:i+2] for i in range(0,12,2)).upper()
                    except:
                        return ""

                devices = []
                for idx, device_id in enumerate(device_ids, start=1):
                    app_version = values.get(f"{idx}_app", {}).get("value")
                    fw_version = values.get(f"{idx}_fw", {}).get("value")
                    model_name = values.get(f"{idx}_model", {}).get("value", "-")
                    serial_number = values.get(f"{idx}_serial", {}).get("value") or "-"
                    vendor = values.get(f"{idx}_vendor", {}).get("value", "-")

                    mac_hex = values.get(f"{idx}_mac", {}).get("value")
                    try:
                        macold = values.get(f"{idx}_macold", {}).get("bnEther", {}).get("address", {}).get("value")
                    except:
                        macold = None
                    mac = format_mac(mac_hex) or format_mac(macold)

                    ip1_raw = values.get(f"{idx}_ipold", {}).get("value") or values.get(f"{idx}_ip1", {}).get("value", "-")
                    ip1 = extract_ip(ip1_raw)
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
                        "vendor": vendor
                    })

                # --- Extra properties for VAV devices ---
                extra_points_map = {
                    "vav_box_size": ("multi-state-value", 106),
                    "damper_runtime": ("analog-value", 145),
                    "cooling_min_setpoint": ("analog-value", 124),
                    "cooling_max_setpoint": ("analog-value", 125),
                    "heating_min_setpoint": ("analog-value", 126),
                    "heating_max_setpoint": ("analog-value", 127),
                    "standby_airflow": ("analog-value", 129),
                    "damper_sensor": ("analog-input", 6),
                    "damper_sensor_calibration": ("analog-input", 6, "calibration"),
                    "controller_airflow": ("analog-value", 120),
                    "airflow_setpoint": ("analog-value", 830),
                    "damper_position": ("analog-input", 5),
                    "flow_factor": ("analog-value", 121),
                    "space_temp": ("analog-value", 2003),
                    "space_temp_setpoint": ("analog-value", 2001),
                    "discharge_temp": ("analog-input", 2)
                }

                # Enum map for vav_box_size
                vav_box_size_map = {
                    1: "4 in_",
                    2: "5 in_",
                    3: "6 in_",
                    4: "8 in_",
                    5: "10 in_",
                    6: "12 in_",
                    7: "14 in_",
                    8: "16 in_",
                    9: "24x16 in_",
                    10: "28x14 in_",
                    11: "32x16 in_",
                    12: "Other_"
                }

                extra_multi_values = {}
                for idx, device in enumerate(devices, start=1):
                    if any(x in device["model_name"].lower() for x in ["ezv","v400","v100","dvc"]):
                        device_id = device["device_id"]
                        for prop_name, point_info in extra_points_map.items():
                            point_type, point_number = point_info[0], point_info[1]
                            subfield = point_info[2] if len(point_info) > 2 else None

                            key = f"{idx}_{prop_name}"
                            path = f"/.bacnet/{selected_site}/{device_id}/{point_type},{point_number}/present-value"
                            if subfield:
                                path = f"/.bacnet/{selected_site}/{device_id}/{point_type},{point_number}/{subfield}"
                            path += "?alt=json"

                            extra_multi_values[key] = {"$base": "Any", "via": path}

                if extra_multi_values:
                    extra_payload = {
                        "$base": "Struct",
                        "lifetime": {"$base": "Unsigned", "value": 120},
                        "values": {"$base": "List", **extra_multi_values}
                    }
                    extra_response = retry_request(lambda: s.post(f"{base_url}/api/.multi?alt=json", json=extra_payload, timeout=300))
                    extra_values = extra_response.json().get("values", {})

                    for idx, device in enumerate(devices, start=1):
                        for prop_name in extra_points_map.keys():
                            key = f"{idx}_{prop_name}"
                            value = extra_values.get(key, {}).get("value", "-")

                            # Apply VAV box size mapping
                            if prop_name == "vav_box_size" and isinstance(value, int):
                                device[prop_name] = vav_box_size_map.get(value, f"Unknown ({value})")
                            else:
                                device[prop_name] = value

                devices.sort(key=lambda x: int(x["device_id"]))

                flash(f"Devices API response: {multi_response.status_code} {STATUS_CODES.get(multi_response.status_code,'')}", "info")
            except Exception as e:
                flash(f"Failed to fetch device details: {str(e)}","danger")

    return render_template("sites.html", sites=sites, devices=devices, selected_site=selected_site, base_url=base_url)


# ---------------- API Query ---------------- #
@app.route("/api_query", methods=["GET","POST"])
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

    if request.method=="POST":
        endpoint = request.form.get("endpoint","").lstrip("/")
        url = (request.form.get("api_base_url") or "").rstrip("/")
        username = request.form.get("api_username")
        password = request.form.get("api_password")
        method = request.form.get("method","GET")
        body = request.form.get("body","")

        if endpoint and url and username and password:
            try:
                full_url = f"{url}/{endpoint}"
                headers = get_basic_auth_headers(username,password)
                if method.upper()=="POST":
                    data = json.loads(body) if body.strip() else None
                    response = requests.post(full_url, headers=headers, auth=(username,password), json=data, timeout=30)
                else:
                    response = requests.get(full_url, headers=headers, auth=(username,password), timeout=30)

                if response.status_code == 401:
                    print("[WARN] Got 401, retrying once...")
                    time.sleep(2)
                    if method.upper()=="POST":
                        response = requests.post(full_url, headers=headers, auth=(username,password), json=data, timeout=30)
                    else:
                        response = requests.get(full_url, headers=headers, auth=(username,password), timeout=30)

                status_code = response.status_code
                response.raise_for_status()
                json_result = response.json()
                print(f"[INFO] API Query Response: {status_code} {STATUS_CODES.get(status_code,'')}")
            except Exception as e:
                flash(f"API query failed: {str(e)}","danger")
                print(f"[EXCEPTION] API query failed: {e}")

    return render_template("api_query.html", json_result=json_result, endpoint=endpoint, api_base_url=url,
                           api_username=username, api_password=password, method=method, body=body,
                           status_code=status_code, full_url=full_url)

if __name__ == "__main__":
    # Host 0.0.0.0 to allow other devices on your local network to access
    # Do NOT use debug=True in production
    app.run(host="0.0.0.0", port=5010, debug=True)

