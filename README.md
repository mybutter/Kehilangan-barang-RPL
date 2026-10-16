# Sistem Informasi Kehilangan Barang — UIN Alauddin Makassar

Aplikasi web responsif untuk pelaporan barang hilang, pemantauan status, dan pengelolaan laporan oleh petugas keamanan. Aplikasi menggunakan Node.js, Express, SQLite, dan antarmuka HTML/CSS/JavaScript tanpa proses build frontend.

## Menjalankan aplikasi

Persyaratan: Node.js 20 atau lebih baru.

```bash
npm install
npm start
```

Buka `http://localhost:3000`. Untuk pengembangan dengan pemuatan ulang otomatis, jalankan `npm run dev`.

## Membuat akun petugas

1. Jalankan aplikasi satu kali agar database lokal dibuat.
2. Jalankan `npm run create:staff`.
3. Ikuti prompt interaktif untuk mengisi nama, email, username, dan kata sandi petugas.
4. Masuk melalui halaman yang sama dengan mahasiswa. Halaman dashboard dan menu dikelola berdasarkan peran akun.

Pendaftaran publik hanya membuat akun mahasiswa. Akun petugas tidak dapat dibuat melalui formulir pendaftaran.

## Fitur

- Registrasi dan login mahasiswa menggunakan email, NIM, atau username; kata sandi disimpan sebagai hash bcrypt.
- Sesi acak tersimpan sebagai hash di SQLite dan dikirim melalui cookie `HttpOnly` dengan kebijakan `SameSite=Lax`.
- Pelaporan kehilangan dengan nomor otomatis `LKB-TAHUN-NOMOR`, validasi, dan unggahan JPG/PNG/WebP maksimal 5 MB.
- Pencarian publik, detail laporan, dan riwayat perubahan status tanpa membuka nama, NIM, atau kontak pelapor.
- Dashboard mahasiswa, serta panel petugas untuk menambah, melihat, mengubah detail/status, dan menghapus laporan; daftar barang ditemukan, dan pembaruan profil.
- Laporan yang dicatat langsung oleh petugas menggunakan identitas akun petugas sebagai pencatat dan dapat ditelusuri dengan nomor laporan.
- Tampilan responsif dengan aset logo resmi UIN Alauddin Makassar pada `public/assets/logo-uinam.png`.

## Modul antarmuka

- `public/app.js` menangani navigasi halaman dan interaksi formulir.
- `public/api.js` mengelola komunikasi API, cookie sesi, dan pesan galat respons.
- `public/constants.js` menyimpan pilihan kategori dan status bersama untuk formulir dan panel petugas.
- Setiap halaman memiliki fungsi render tersendiri di `public/app.js`; halaman cek status juga mendukung tautan pencarian langsung seperti `#/status?q=LKB-2026-0001`.

## Penyimpanan dan konfigurasi

Database dibuat pada `data/kehilangan.sqlite` dan foto tersimpan pada `uploads/`. Keduanya tidak dimasukkan ke kontrol versi. Atur port melalui variabel lingkungan `PORT`. Untuk penerapan di balik HTTPS, atur `NODE_ENV=production` agar cookie sesi menggunakan atribut `Secure`.

Sebelum digunakan pada lingkungan produksi, tempatkan aplikasi di belakang HTTPS dan tambahkan kebijakan operasional yang sesuai untuk pencadangan database, retensi data, pembatasan percobaan login, dan perlindungan informasi pelapor.
