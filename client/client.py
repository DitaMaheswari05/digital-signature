import json
import urllib.request
import urllib.error

import os
PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")

def get_user_input() -> tuple[str, str, dict]:
    print("\n--- mTLS Proxy Client ---")
    method = (
        input("HTTP Method [GET/POST] (default POST): ").strip().upper()
        or "POST"
    )
    path = input("API Path (contoh: /api/data) (default /): ").strip()
    if not path:
        path = "/"
        
    payload = {}
    if method in ["POST", "PUT", "PATCH"]:
        print("Masukkan payload JSON (tekan Enter untuk payload default):")
        user_payload = input("> ")
        if user_payload.strip():
            try:
                payload = json.loads(user_payload)
            except json.JSONDecodeError:
                print("[!] Format JSON tidak valid. Menggunakan payload default.")
                payload = {"message": "Hello from Client FE!"}
        else:
            payload = {"message": "Hello from Client FE!"}

    return method, path, payload

def send_request(method: str, path: str, payload: dict) -> dict:
    url = f"{PROXY_URL}{path}"
    has_body = method.upper() in ["POST", "PUT", "PATCH"]
    body_bytes = json.dumps(payload).encode("utf-8") if has_body else None
    headers = {"Content-Type": "application/json"} if has_body else {}

    req = urllib.request.Request(
        url=url, data=body_bytes, headers=headers, method=method.upper()
    )

    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        print(f"\n[!] Error HTTP {e.code}: {e.reason}")
        try:
            return json.loads(e.read())
        except Exception:
            return {"error": e.read().decode("utf-8", errors="replace")}
    except urllib.error.URLError as e:
        print(f"\n[!] Connection failed: {e.reason}")
        print(f"[!] Pastikan Proxy berjalan di {PROXY_URL}")
        return {"error": str(e.reason)}

def main():
    method, path, payload = get_user_input()

    print(f"\nMengirim request {method} {path} ke Proxy ...")
    response = send_request(method, path, payload)

    print("\nResponse dari Proxy (Plaintext):")
    print("-" * 60)
    print(json.dumps(response, indent=2, ensure_ascii=False))
    print("-" * 60)

if __name__ == "__main__":
    main()
