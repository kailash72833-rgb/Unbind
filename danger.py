from flask import Flask, request, jsonify
import hashlib
import requests

app = Flask(__name__)

BASE_URL = "https://100067.connect.garena.com"
APP_ID = "100067"

def sha256_upper(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest().upper()

def verify_identity(access_token, security_code):
    url = f"{BASE_URL}/game/account_security/bind:verify_identity"
    hashed = sha256_upper(security_code)
    data = {
        'app_id': APP_ID,
        'access_token': access_token,
        'secondary_password': hashed
    }
    headers = {
        'User-Agent': 'GarenaMSDK/4.0.19P10(ASUS_Z01QD;Android 9;en;US;)',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'com.garena.game.kgid'
    }
    try:
        r = requests.post(url, data=data, headers=headers, timeout=15)
        if r.status_code == 200:
            resp = r.json()
            if resp.get('result') == 0:
                return resp.get('identity_token')
            else:
                return None, resp
        else:
            return None, f"HTTP {r.status_code}"
    except Exception as e:
        return None, str(e)

def unbind_identity(access_token, identity_token):
    url = f"{BASE_URL}/game/account_security/bind:unbind_identity"
    data = {
        'app_id': APP_ID,
        'access_token': access_token,
        'identity_token': identity_token
    }
    try:
        r = requests.post(url, data=data, timeout=15)
        if r.status_code == 200:
            resp = r.json()
            if resp.get('result') == 0:
                return True, None
            else:
                return False, resp
        else:
            return False, f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)

@app.route('/unbind', methods=['POST', 'GET'])
def unbind():
    if request.method == 'GET':
        token = request.args.get('access_token')
        sec = request.args.get('security_code')
    else:
        data = request.get_json() or request.form
        token = data.get('access_token')
        sec = data.get('security_code')

    if not token or not sec:
        return jsonify({"success": False, "error": "Missing access_token or security_code"}), 400

    # Verify
    identity_token, err = verify_identity(token, sec)
    if not identity_token:
        return jsonify({"success": False, "error": "Verification failed", "details": err}), 400

    # Unbind
    success, err = unbind_identity(token, identity_token)
    if success:
        return jsonify({"success": True, "message": "Unbind request created. It will be effective after 15 days."})
    else:
        return jsonify({"success": False, "error": "Unbind failed", "details": err}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)