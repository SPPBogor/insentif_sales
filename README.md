# Insentif Sales PT Satria Putra Persada (Flask)

Aplikasi Flask sederhana untuk input data salesman, target penjualan, NOO (CA/NOO-FL/AO), dan rekap otomatis insentif.

## Fitur
- Master **Salesman** (divisi: MP/AVIAN, kategori: Bronze–Platinum)
- **Target Penjualan** dengan password 80% dan insentif otomatis
- **NOO**: CA (≥80% = 100rb), NOO/LOST (50rb/toko), FL MP (≥80% = 100rb), AO Avian (100% = 100rb)
- **Rekap** total per bulan per salesman
- UI Bootstrap gelap, tabel responsif

## Cara Menjalankan
```bash
# 1) Buat dan aktifkan virtualenv (opsional)
python -m venv venv
# Windows: venv\Scripts\activate
# Mac/Linux: source venv/bin/activate

# 2) Install dependency
pip install flask flask_sqlalchemy

# 3) Jalankan app
python app.py
# buka: http://127.0.0.1:5000

# 4) Inisialisasi DB + seed (opsional)
# flask --app app.py init-db
```

## Catatan
- Database SQLite: `insentif_fix.db` otomatis dibuat saat pertama kali jalan.
- Insentif Call saat ini **placeholder** (0) sesuai permintaan.
- Jika ingin menambah export Excel/PDF atau upload massal CSV, tinggal tambahkan route baru.
