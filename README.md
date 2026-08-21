# Digital Signature

Sistem keamanan berlapis berbasis **mTLS (Mutual TLS)** dengan verifikasi tanda tangan digital **CMS (Cryptographic Message Syntax)** dan perlindungan **WAF (Web Application Firewall)**. Setiap request divalidasi di dua lapisan terpisah antara Proxy dan WAF untuk memastikan integritas dan autentikasi dua arah.

---

## Arsitektur Sistem

```
Client
  │  (mTLS + CMS-signed header)
  ▼
Proxy (port 8080)
  │  • Verifikasi sertifikat mTLS klien
  │  • Verifikasi tanda tangan CMS pada header
  │  • Catat audit log ke audit_api
  ▼
WAF / waf_service (port 9000)
  │  • Pemeriksaan ancaman & payload berbahaya
  │  • Verifikasi ulang CMS header
  │  • Catat audit log ke audit_api
  ▼
WebApp (backend)
```

---

## Struktur Direktori

```
digital-signature/
├── proxy/              # Reverse proxy dengan verifikasi mTLS & CMS
├── waf/                # WAF (Nginx) + waf_service (FastAPI)
├── webapp/             # Aplikasi backend (CMS core)
├── client/             # Klien pengujian
├── audit_api/          # REST API penyimpanan audit log (FastAPI + PostgreSQL)
├── audit_dashboard/    # Dashboard audit log terpadu (port 8081)
├── audit_dashboard_proxy/  # Dashboard audit khusus Proxy (port 8082)
├── audit_dashboard_waf/    # Dashboard audit khusus WAF (port 8083)
├── shared/             # Library bersama (CMS lib, canonical)
├── key_cert/           # Sertifikat & kunci TLS
├── monitoring/
│   ├── prometheus/     # Konfigurasi scraping Prometheus
│   ├── grafana/        # Dashboard Grafana terpadu (port 3000)
│   ├── proxy/grafana/  # Dashboard Grafana khusus Proxy (port 3001)
│   ├── waf/grafana/    # Dashboard Grafana khusus WAF (port 3002)
│   ├── loki/           # Konfigurasi log aggregation
│   └── promtail/       # Log collector dari Docker
└── docker-compose.yml
```

---

## Prasyarat

| Perangkat Lunak | Versi Minimum |
|---|---|
| Docker Desktop | 24.x |
| Docker Compose | v2.x |
| Python (opsional, untuk dev lokal) | 3.12+ |

---

## Cara Menjalankan

### 1. Salin file konfigurasi environment

```bash
cp .env.example .env
```

Edit `.env` dan isi nilai yang diperlukan:

```env
GRAFANA_ADMIN_PASSWORD=your_grafana_password
POSTGRES_PASSWORD=your_postgres_password
POSTGRES_DB=audit_db
POSTGRES_USER=audituser
AUDIT_RETENTION_MONTHS=60
LOKI_RETENTION_DAYS=30
```

### 2. Jalankan seluruh sistem

```bash
docker compose up -d --build
```

### 3. Verifikasi semua service berjalan

```bash
docker compose ps
```

Semua service harus berstatus `running` atau `healthy`.

### 4. Menghentikan sistem

```bash
docker compose down
```

> Tambahkan `-v` untuk menghapus semua volume (data akan hilang):
> ```bash
> docker compose down -v
> ```

---

## Akses Layanan

### Monitoring Terpadu (Admin)

| Layanan | URL | Keterangan |
|---|---|---|
| **Grafana** | http://localhost:3000 | Dashboard metrik terpadu (Proxy + WAF) |
| **Audit Log Dashboard** | http://localhost:8081 | Semua audit event |
| Prometheus | http://localhost:9090 | Query metrik langsung |
| Loki | http://localhost:3100 | Query log langsung |

### Monitoring Terpisah (Mutual Trust)

| Pihak | Grafana | Audit Log |
|---|---|---|
| **Proxy** | http://localhost:3001 | http://localhost:8082 |
| **WAF** | http://localhost:3002 | http://localhost:8083 |

> Masing-masing view hanya menampilkan data dari service-nya sendiri. Cross-verifikasi dapat dilakukan menggunakan `request_id` yang sama.

### API & Service

| Layanan | URL | Keterangan |
|---|---|---|
| **Proxy** | http://localhost:8080 | Entry point utama |
| **Audit API** | http://localhost:8000 | REST API audit log |
| **Audit API Docs** | http://localhost:8000/docs | Swagger UI |
| WAF Service | http://localhost:9000 | Internal WAF (tidak untuk akses langsung) |

---

## Dashboard Monitoring

### Grafana (port 3000 / 3001 / 3002)

Login: username `admin`, password sesuai `GRAFANA_ADMIN_PASSWORD` di `.env`.

Dashboard tersedia:
- **mTLS Proxy — Security & Performance** (port 3000): Overview lengkap semua service
- **Proxy Dashboard** (port 3001): mTLS handshake rate, CMS verification rate, latency proxy
- **WAF Dashboard** (port 3002): Threat detection, blocked request breakdown, WAF latency

### Audit Log Dashboard (port 8081 / 8082 / 8083)

Tidak perlu login. Fitur yang tersedia:
- **Filter** berdasarkan service, result, dan pencarian teks bebas
- **Auto-refresh** setiap 5 detik (dapat dimatikan)
- **Klik baris** untuk melihat detail lengkap setiap event
- **Pagination** untuk navigasi antar halaman log

---

## Alur Verifikasi Request

1. **Client** mengirim request dengan:
   - Sertifikat TLS klien (mTLS)
   - Header `X-CMS-Signature` berisi tanda tangan digital CMS

2. **Proxy** memverifikasi:
   - Sertifikat klien terhadap CA (Certificate Authority)
   - Tanda tangan CMS pada header request
   - Meneruskan request ke WAF jika valid

3. **WAF Service** memverifikasi:
   - Pemeriksaan ancaman pada payload
   - Verifikasi ulang integritas CMS header
   - Meneruskan ke WebApp jika lolos

4. **Audit log** dikirim ke `audit_api` di setiap tahap dengan field:
   - `request_id`: UUID unik per request (untuk cross-verifikasi)
   - `service`: `proxy` atau `waf_service`
   - `step`: Nomor urut tahap pipeline
   - `result`: `success` / `rejected` / `failed` / `cert_mismatch`
   - `latency_ms`: Waktu pemrosesan

---

## Load Testing (Opsional)

Jalankan load test menggunakan profil `loadtest`:

```bash
# Load test ke endpoint proxy
docker compose --profile loadtest up plow-proxy

# Load test end-to-end (proxy → WAF → webapp)
docker compose --profile loadtest up plow-e2e
```

---

## Audit API — Endpoint Utama

| Method | Endpoint | Keterangan |
|---|---|---|
| `GET` | `/healthz` | Liveness probe |
| `POST` | `/logs` | Simpan audit event baru |
| `GET` | `/logs` | Daftar log (support filter & pagination) |
| `GET` | `/logs/stats` | Statistik 24 jam terakhir |
| `GET` | `/logs/{id}` | Detail satu log entry |

Contoh filter:
```bash
# Lihat log proxy yang rejected
curl "http://localhost:8000/logs?service=proxy&result=rejected&limit=20"

# Cari berdasarkan request_id
curl "http://localhost:8000/logs?request_id=a3b7f2c1-..."
```

---

## Variabel Environment

| Variabel | Default | Keterangan |
|---|---|---|
| `GRAFANA_ADMIN_USER` | `admin` | Username login Grafana |
| `GRAFANA_ADMIN_PASSWORD` | *(wajib diisi)* | Password login Grafana |
| `POSTGRES_DB` | `audit_db` | Nama database PostgreSQL |
| `POSTGRES_USER` | `audituser` | User PostgreSQL |
| `POSTGRES_PASSWORD` | *(wajib diisi)* | Password PostgreSQL |
| `AUDIT_RETENTION_MONTHS` | `60` | Retensi data audit log (bulan) |
| `LOKI_RETENTION_DAYS` | `30` | Retensi log Loki (hari) |