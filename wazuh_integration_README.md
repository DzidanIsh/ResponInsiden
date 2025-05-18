# Integrasi Wazuh dengan Sistem Anti-Defacement Web Server

Dokumentasi ini menjelaskan tentang integrasi antara Wazuh (sistem keamanan dan monitoring) dengan sistem anti-defacement untuk web server. Integrasi ini menggunakan dua komponen utama: **Wazuh Manager** dan **Wazuh Agent** yang bekerja bersama untuk mendeteksi perubahan yang mencurigakan pada file web server dan melakukan tindakan pemulihan (restore) secara otomatis.

## Arsitektur Sistem

Sistem integrasi ini terdiri dari dua komponen utama:

1. **Wazuh Manager** (Pusat Kontrol)
   - Menerima dan memproses alert dari agent
   - Berisi aturan deteksi kustom (rules)
   - Memberikan perintah "active response" ke agent
   - Biasanya diinstall pada server khusus/terpisah

2. **Wazuh Agent** (Pada Web Server)
   - Memantau perubahan file (syscheck)
   - Mengirim alert ke Wazuh Manager
   - Menjalankan tindakan restore otomatis saat diperintahkan
   - Diinstall pada server web yang dilindungi

## Alur Kerja Sistem

Berikut adalah alur kerja sistem anti-defacement dengan Wazuh:

1. **Pemantauan File**: Wazuh Agent memantau direktori web server secara real-time menggunakan fitur syscheck.
2. **Deteksi Perubahan**: Saat terjadi perubahan mencurigakan pada file web, Agent mengirim alert ke Manager.
3. **Analisis Alert**: Manager menganalisis alert berdasarkan aturan kustom (ID 100500-100503).
4. **Respons Otomatis**: Jika terdeteksi perubahan mencurigakan, Manager mengirim perintah ke Agent untuk menjalankan script restore.
5. **Pemulihan Otomatis**: Agent menjalankan script restore yang akan mengembalikan file web ke kondisi terakhir yang valid.
6. **Pencatatan**: Semua aktivitas dicatat dalam log untuk audit dan analisis lanjutan.

## Persiapan Instalasi

Sebelum melakukan integrasi, pastikan:

1. Wazuh Manager dan Wazuh Agent sudah terinstall pada server yang sesuai
   - Bisa menggunakan script `installwazuh.sh` untuk instalasi sesuai kebutuhan
2. Sistem anti-defacement (backup dan restore) sudah terinstall pada web server
3. Komunikasi antara Agent dan Manager sudah berjalan dengan baik

## Instalasi dan Konfigurasi

### 1. Setup Wazuh Manager

Gunakan script `wazuh_manager_setup.sh` untuk mengkonfigurasi Wazuh Manager:

```bash
sudo bash wazuh_manager_setup.sh
```

Script ini akan:
- Membuat aturan kustom untuk deteksi web defacement (ID 100500-100503)
- Memperbarui konfigurasi ossec.conf untuk memasukkan aturan kustom
- Menambahkan konfigurasi active response di agent.conf
- Mendefinisikan command "web-restore" di manager
- Mengkonfigurasi notifikasi email (opsional)

### 2. Setup Wazuh Agent

Pada web server, gunakan script `wazuh_agent_setup.sh` untuk mengkonfigurasi Wazuh Agent:

```bash
sudo bash wazuh_agent_setup.sh
```

Script ini akan:
- Memverifikasi instalasi Wazuh Agent
- Membuat script active response `/var/ossec/active-response/bin/web_restore.sh`
- Memperbarui konfigurasi syscheck untuk memantau direktori web
- Mengkonfigurasi pengecualian file/direktori (opsional)

## Detail Konfigurasi

### Wazuh Manager (wazuh_manager_setup.sh)

Script ini melakukan beberapa konfigurasi penting:

- **File Aturan Kustom** (`/var/ossec/etc/rules/web_defacement_rules.xml`):
  - **Rule 100500**: Rule dasar untuk perubahan file di direktori web (level 10)
  - **Rule 100501**: Beberapa file web penting dimodifikasi (level 12)
  - **Rule 100502**: Halaman utama website dimodifikasi (level 14)
  - **Rule 100503**: File skrip baru ditambahkan ke direktori web (level 14)

- **Konfigurasi Active Response** (di `/var/ossec/etc/shared/default/agent.conf`):
  - Command: web-restore
  - Rules trigger: 100501, 100502, 100503
  - Timeout: 60 detik

- **Command Definition** (di `/var/ossec/etc/ossec.conf`):
  - Nama: web-restore
  - Executable: web_restore.sh
  - Expect: srcip
  - Timeout allowed: yes

### Wazuh Agent (wazuh_agent_setup.sh)

Script ini fokus pada konfigurasi agent:

- **Syscheck** (di `/var/ossec/etc/ossec.conf`):
  - Direktori yang dipantau: direktori web server
  - Opsi: realtime, check_all, report_changes
  - Frekuensi scan: 43200 (12 jam)
  - Scan saat startup: yes

- **Script Active Response** (`/var/ossec/active-response/bin/web_restore.sh`):
  - Log file: `/var/log/wazuh-web-restore.log`
  - Memanggil script: `/usr/local/bin/web-restore --auto`

## Dukungan Berbagai Versi Wazuh

Script integrasi ini mendukung berbagai versi dan cara instalasi Wazuh:

- Instalasi standar Wazuh Manager/Agent
- Instalasi menggunakan `installwazuh.sh` (all-in-one)
- Instalasi terdistribusi dengan Filebeat
- Versi Wazuh 3.x maupun 4.x+

Dukungan ini dicapai melalui beberapa mekanisme:
1. Deteksi metode restart yang fleksibel (systemd, service, wazuh-control, ossec-control)
2. Pengecekan keberadaan Wazuh dengan berbagai indikator
3. Dukungan untuk format tag yang berbeda (tag "name" vs tag "n")

## Pengujian Integrasi

Setelah instalasi selesai:

1. **Verifikasi Koneksi Agent-Manager**:
   ```bash
   sudo /var/ossec/bin/agent_control -l
   ```

2. **Uji Deteksi Perubahan**:
   - Buat perubahan pada file web (misal: tambahkan teks di index.html)
   - Periksa alert di Wazuh Manager:
   ```bash
   tail -f /var/ossec/logs/alerts/alerts.log
   ```

3. **Verifikasi Active Response**:
   - Periksa log restore:
   ```bash
   tail -f /var/log/wazuh-web-restore.log
   ```

## Pemecahan Masalah

### Masalah Deteksi Instalasi Wazuh

Jika script melaporkan "Instalasi Wazuh tidak lengkap" meskipun Wazuh berjalan normal:
- Ini biasanya terjadi pada instalasi yang menggunakan `installwazuh.sh`
- Script telah diperbaiki untuk mendeteksi berbagai struktur instalasi Wazuh

### Kegagalan Restart Layanan

Jika terjadi kegagalan saat restart layanan Wazuh:
- Script akan mencoba berbagai metode restart (systemd, service, control script)
- Jika semua metode gagal, script akan melanjutkan setup tanpa restart
- Anda perlu me-restart layanan secara manual: `sudo systemctl restart wazuh-manager` atau `sudo systemctl restart wazuh-agent`

### Masalah Komunikasi Agent-Manager

Jika agent tidak melapor ke manager:
1. Periksa status agent: `sudo /var/ossec/bin/agent_control -l`
2. Periksa konektivitas jaringan: `telnet <manager-ip> 1514`
3. Periksa konfigurasi: `/var/ossec/etc/ossec.conf` (pastikan manager-ip benar)

## Informasi Tambahan

- **Log Integrasi**:
  - Manager setup: `/var/log/wazuh_manager_setup.log`
  - Agent setup: `/var/log/wazuh_agent_setup.log`
  - Restore process: `/var/log/wazuh-web-restore.log`

- **File Konfigurasi Penting**:
  - Wazuh Manager: `/var/ossec/etc/ossec.conf`
  - Wazuh Agent: `/var/ossec/etc/ossec.conf`
  - Agent shared config: `/var/ossec/etc/shared/default/agent.conf`

- **Direktori Penting**:
  - Rules: `/var/ossec/etc/rules/`
  - Active Response scripts: `/var/ossec/active-response/bin/`
  - Alert logs: `/var/ossec/logs/alerts/` 