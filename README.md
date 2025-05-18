# Sistem Backup dan Restore Anti-Defacement Web Server

Sistem ini dirancang untuk melindungi server web dari serangan defacement dengan menyediakan kemampuan backup dan restore yang cepat, aman, dan dapat diintegrasikan dengan Wazuh Security Monitoring.

## Fitur Utama

- Backup otomatis direktori web server menggunakan Git
- Penyimpanan backup di server monitoring terpisah
- Proteksi dengan password untuk operasi backup dan restore
- Integrasi dengan Wazuh untuk respons insiden otomatis
- Pencatatan log aktivitas backup dan restore
- Script instalasi yang dapat dikonfigurasi sesuai kebutuhan
- Integrasi terpisah untuk Wazuh Agent dan Wazuh Manager

## Kebutuhan Sistem

- Sistem operasi berbasis Linux (diuji pada Ubuntu/Debian)
- Apache2 web server
- Git (untuk proses backup)
- Python 3.6+ (untuk proses restore)
- Akses SSH ke server monitoring
- Wazuh HIDS (Agent dan Manager) untuk integrasi respons insiden otomatis

## Struktur Sistem

Sistem ini terdiri dari beberapa komponen utama:

1. **Script Instalasi (`install.sh`)**: Untuk menginstal dan mengkonfigurasi sistem dasar
2. **Script Backup (`backup.sh`)**: Untuk melakukan backup manual atau terjadwal
3. **Script Restore (`restore.py`)**: Untuk melakukan restore manual atau otomatis
4. **Script Integrasi Wazuh Agent (`wazuh_agent_setup.sh`)**: Untuk mengkonfigurasi Wazuh Agent pada server web
5. **Script Integrasi Wazuh Manager (`wazuh_manager_setup.sh`)**: Untuk mengkonfigurasi Wazuh Manager

## Panduan Penggunaan

### Instalasi Sistem Dasar

1. Unduh atau clone repository ini
2. Atur permission eksekusi pada script instalasi:
   ```
   chmod +x install.sh
   ```
3. Jalankan script instalasi:
   ```
   sudo ./install.sh
   ```
4. Ikuti petunjuk instalasi:
   - Masukkan direktori web server yang akan di-backup
   - Masukkan IP, username, dan direktori backup di server monitoring
   - Buat password untuk backup dan restore
   - Pilih apakah akan mengatur backup otomatis

### Melakukan Backup Manual

1. Jalankan perintah backup:
   ```
   sudo web-backup
   ```
2. Masukkan password yang telah dikonfigurasi saat instalasi
3. Sistem akan melakukan commit dan push ke server monitoring

### Melakukan Restore Manual

1. Jalankan perintah restore:
   ```
   sudo web-restore
   ```
2. Masukkan password yang telah dikonfigurasi saat instalasi
3. Pilih commit yang ingin di-restore
4. Konfirmasi operasi restore

### Integrasi dengan Wazuh

Integrasi dengan Wazuh dilakukan melalui dua script terpisah untuk Agent dan Manager:

#### Setup pada Wazuh Agent (Server Web)

1. Pastikan Wazuh Agent telah terinstal di server web
2. Pastikan sistem anti-defacement telah terinstal dan dikonfigurasi
3. Atur permission eksekusi pada script:
   ```
   chmod +x wazuh_agent_setup.sh
   ```
4. Jalankan script setup:
   ```
   sudo ./wazuh_agent_setup.sh
   ```
5. Script akan:
   - Memeriksa prasyarat sistem
   - Membuat script active response
   - Mengkonfigurasi File Integrity Monitoring (FIM) di Wazuh Agent
   - Memungkinkan kustomisasi (pengecualian direktori dan file)

#### Setup pada Wazuh Manager

1. Pastikan Wazuh Manager telah terinstal
2. Atur permission eksekusi pada script:
   ```
   chmod +x wazuh_manager_setup.sh
   ```
3. Jalankan script setup:
   ```
   sudo ./wazuh_manager_setup.sh
   ```
4. Script akan:
   - Membuat aturan kustom untuk deteksi defacement
   - Mengkonfigurasi decoder
   - Mengatur active response untuk agent
   - Memungkinkan kustomisasi (sensitivitas deteksi, notifikasi email)

## Parameter Command Line

### Backup Script

```
sudo web-backup
```

Tidak memerlukan parameter tambahan.

### Restore Script

```
sudo web-restore [--alert JSON_ALERT] [--commit COMMIT_ID] [--auto]
```

- `--alert JSON_ALERT`: Data alert dari Wazuh dalam format JSON
- `--commit COMMIT_ID`: ID commit Git untuk restore langsung
- `--auto`: Mode otomatis tanpa interaksi pengguna

### Wazuh Agent Setup Script

```
sudo ./wazuh_agent_setup.sh
```

Interaktif, tidak memerlukan parameter tambahan.

### Wazuh Manager Setup Script

```
sudo ./wazuh_manager_setup.sh
```

Interaktif, tidak memerlukan parameter tambahan.

## Konfigurasi

### Konfigurasi Sistem Dasar

File konfigurasi dasar disimpan di `/etc/web-backup/config.conf` dan berisi:

- `WEB_DIR`: Direktori web server yang di-backup
- `MONITOR_IP`: IP server monitoring
- `MONITOR_USER`: Username SSH server monitoring
- `BACKUP_DIR`: Path direktori backup di server monitoring
- `PASSWORD`: Password terenkripsi untuk operasi backup dan restore

### Konfigurasi Wazuh

#### Wazuh Agent
- File konfigurasi: `/var/ossec/etc/ossec.conf`
- Script active response: `/var/ossec/active-response/bin/web_restore.sh`
- Log aktivitas restore: `/var/log/wazuh-web-restore.log`

#### Wazuh Manager
- Aturan kustom: `/var/ossec/etc/rules/web_defacement_rules.xml`
- Konfigurasi shared agent: `/var/ossec/etc/shared/default/agent.conf`
- Decoder lokal: `/var/ossec/etc/local_decoder.xml`

## Alur Kerja Sistem

1. **Backup Rutin**: Sistem melakukan backup berkala dengan menggunakan Git
2. **Deteksi Perubahan**: Wazuh Agent memantau perubahan pada file web server
3. **Analisis Perubahan**: Wazuh Manager menganalisis perubahan berdasarkan aturan yang telah dikonfigurasi
4. **Respons Otomatis**: Jika terdeteksi aktivitas mencurigakan, script restore dijalankan secara otomatis
5. **Restore**: Web server dikembalikan ke kondisi terjaga dari backup terakhir yang aman

## Keamanan

- Semua operasi memerlukan hak akses root
- Password disimpan dalam bentuk terenkripsi
- Komunikasi dengan server monitoring menggunakan SSH
- Backup otomatis disimpan di server terpisah
- Respons otomatis diatur berdasarkan tingkat sensitivitas yang dapat disesuaikan

## Pemecahan Masalah

### Masalah Backup dan Restore Dasar

1. **Backup gagal dengan error Git**:
   - Pastikan direktori web memiliki izin akses yang benar
   - Periksa koneksi SSH ke server monitoring
   - Pastikan direktori backup di server monitoring sudah ada

2. **Restore gagal**:
   - Periksa apakah repository Git sudah diinisialisasi dengan benar
   - Pastikan password yang dimasukkan benar
   - Pastikan commit ID yang dipilih valid

### Masalah Integrasi Wazuh

1. **Wazuh Agent**:
   - Periksa status agent: `sudo /var/ossec/bin/agent_control -l`
   - Periksa konfigurasi syscheck: `grep -A 20 "<syscheck>" /var/ossec/etc/ossec.conf`
   - Periksa log agent: `tail -f /var/ossec/logs/ossec.log`
   - Pastikan script active response dapat dijalankan: `ls -la /var/ossec/active-response/bin/web_restore.sh`

2. **Wazuh Manager**:
   - Periksa aturan kustom: `ls -la /var/ossec/etc/rules/web_defacement_rules.xml`
   - Periksa log alerts: `tail -f /var/ossec/logs/alerts/alerts.log`
   - Pastikan konfigurasi shared agent sudah benar: `cat /var/ossec/etc/shared/default/agent.conf`
   - Restart layanan jika diperlukan: `sudo systemctl restart wazuh-manager`

3. **Active Response**:
   - Periksa log restore: `tail -f /var/log/wazuh-web-restore.log`
   - Pastikan script restore dapat diakses dan dijalankan
   - Verifikasi koneksi antara agent dan manager

## Log

- Log backup: `/var/log/web-backup.log`
- Log restore: `/var/log/web-restore.log`
- Log integrasi Wazuh Agent: `/var/log/wazuh_agent_setup.log`
- Log integrasi Wazuh Manager: `/var/log/wazuh_manager_setup.log`
- Log active response: `/var/log/wazuh-web-restore.log`
- Log alerts Wazuh: `/var/ossec/logs/alerts/alerts.log`

## Lisensi

Sistem ini dirilis di bawah lisensi MIT.

## Kontribusi

Kontribusi untuk perbaikan atau penambahan fitur sangat diterima. Silakan buat pull request atau laporkan issue.

---

Untuk dukungan lebih lanjut, harap hubungi administrator sistem. 