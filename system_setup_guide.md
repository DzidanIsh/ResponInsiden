# Panduan Konfigurasi Sistem Anti-Defacement Lengkap

Dokumen ini berisi panduan lengkap untuk menginstal, mengkonfigurasi, dan menggunakan sistem anti-defacement yang terdiri dari server web dan server monitoring. Sistem ini dirancang untuk melindungi konten web dari serangan defacement dan memungkinkan pemulihan cepat jika terjadi serangan.

## Arsitektur Sistem

Sistem anti-defacement terdiri dari dua komponen utama:

1. **Server Web**: Server yang menjalankan Apache2 dan menyimpan konten web yang perlu dilindungi. Server ini menjalankan script backup untuk menyimpan konten ke server monitoring.

2. **Server Monitoring**: Server yang menyimpan backup dari server web dalam bentuk Git repository. Server ini juga dapat menjalankan Wazuh untuk memonitor keamanan dan mendeteksi serangan.

### Alur Kerja Sistem

1. Konten web di-backup secara berkala dari server web ke server monitoring menggunakan Git.
2. Jika terjadi serangan defacement, script restore akan memulihkan konten web dari backup terbaru.
3. Proses restore dapat dilakukan secara manual atau otomatis melalui integrasi dengan Wazuh.

## Persyaratan Sistem

### Server Web
- Sistem operasi berbasis Linux (Ubuntu/Debian direkomendasikan)
- Apache2 web server
- Git
- Python 3.6+
- Akses SSH ke server monitoring

### Server Monitoring
- Sistem operasi berbasis Linux (Ubuntu/Debian direkomendasikan)
- Git
- Wazuh (opsional)
- Ruang disk yang cukup untuk menyimpan backup

## Langkah-Langkah Instalasi

### 1. Persiapan Server Monitoring

1. Unduh `monitoring_setup.sh` ke server monitoring.
2. Berikan izin eksekusi:
   ```bash
   chmod +x monitoring_setup.sh
   ```
3. Jalankan script sebagai root:
   ```bash
   sudo ./monitoring_setup.sh
   ```
4. Ikuti petunjuk instalasi:
   - Tentukan direktori untuk menyimpan backup
   - Pilih apakah akan membuat pengguna khusus untuk backup
   - Konfigurasi notifikasi dan monitoring (opsional)

5. Catat informasi berikut setelah instalasi selesai:
   - IP Server Monitoring
   - Username SSH
   - Path direktori backup

### 2. Persiapan Server Web

1. Unduh file-file berikut ke server web:
   - `install.sh` (script instalasi utama)
   - `backup.sh` (script backup)
   - `restore.py` (script restore)

2. Berikan izin eksekusi pada script instalasi:
   ```bash
   chmod +x install.sh
   ```

3. Jalankan script instalasi sebagai root:
   ```bash
   sudo ./install.sh
   ```

4. Ikuti petunjuk instalasi:
   - Masukkan direktori web server yang akan di-backup (biasanya `/var/www/html`)
   - Masukkan informasi server monitoring yang telah dicatat sebelumnya:
     - IP server monitoring
     - Username SSH
     - Path direktori backup
   - Buat password untuk backup dan restore
   - Pilih apakah akan mengatur backup otomatis

### 3. Konfigurasi SSH Antara Server

Agar server web dapat melakukan push ke server monitoring, Anda perlu mengatur autentikasi SSH. Ini dapat dilakukan dengan dua cara:

#### Cara 1: Menggunakan ssh-copy-id

Di server web, jalankan sebagai root:
```bash
ssh-keygen -t rsa -b 4096 -C "backup@web-server"
ssh-copy-id [username]@[ip-server-monitoring]
```

#### Cara 2: Setup Manual

1. Di server web, buat kunci SSH:
   ```bash
   ssh-keygen -t rsa -b 4096 -C "backup@web-server"
   ```

2. Tampilkan kunci publik:
   ```bash
   cat ~/.ssh/id_rsa.pub
   ```

3. Di server monitoring, buat atau edit file authorized_keys:
   ```bash
   mkdir -p /home/[username]/.ssh
   echo "[kunci-publik-dari-server-web]" >> /home/[username]/.ssh/authorized_keys
   chmod 700 /home/[username]/.ssh
   chmod 600 /home/[username]/.ssh/authorized_keys
   chown -R [username]:[username] /home/[username]/.ssh
   ```

### 4. Pengujian Sistem

1. **Uji backup manual**:
   ```bash
   sudo web-backup
   ```
   Masukkan password backup ketika diminta.

2. **Uji koneksi SSH**:
   ```bash
   ssh [username]@[ip-server-monitoring]
   ```
   Pastikan dapat terhubung tanpa diminta password.

3. **Uji restore manual**:
   ```bash
   sudo web-restore
   ```
   Masukkan password restore ketika diminta dan pilih commit untuk restore.

## Penggunaan Sistem

### Backup Manual

Untuk melakukan backup manual:
```bash
sudo web-backup
```

### Restore Manual

Untuk melakukan restore manual:
```bash
sudo web-restore
```

### Integrasi dengan Wazuh

#### Mengkonfigurasi Wazuh untuk Deteksi Defacement

1. Tambahkan custom rule di Wazuh Manager untuk mendeteksi modifikasi file mencurigakan di direktori web:

   Buat file `/var/ossec/etc/rules/web_defacement_rules.xml`:
   ```xml
   <group name="web,defacement,">
     <rule id="100500" level="12">
       <if_group>syscheck</if_group>
       <match>^/var/www/html</match>
       <regex>modified|added</regex>
       <description>Possible web defacement detected</description>
     </rule>
   </group>
   ```

2. Konfigurasikan active response di Wazuh Manager:

   Edit file `/var/ossec/etc/ossec.conf` dan tambahkan:
   ```xml
   <command>
     <name>web-restore</name>
     <executable>web-restore</executable>
     <expect>alert</expect>
     <extra_args>--auto --alert</extra_args>
     <timeout_allowed>no</timeout_allowed>
   </command>
   
   <active-response>
     <command>web-restore</command>
     <location>local</location>
     <rules_id>100500</rules_id>
   </active-response>
   ```

3. Restart Wazuh Manager:
   ```bash
   systemctl restart wazuh-manager
   ```

## Pemeliharaan Rutin

### Server Web

1. **Verifikasi backup berjalan**:
   ```bash
   grep "Backup berhasil" /var/log/web-backup.log
   ```

2. **Periksa status Git repository**:
   ```bash
   cd /var/www/html && git status
   ```

3. **Pembaruan sistem**:
   ```bash
   apt update && apt upgrade
   ```

### Server Monitoring

1. **Pemeriksaan ruang disk**:
   ```bash
   df -h [path-direktori-backup]
   ```

2. **Backup repository Git**:
   ```bash
   tar -czf backup-repo-$(date +%Y%m%d).tar.gz [path-direktori-backup]
   ```

3. **Verifikasi log**:
   ```bash
   less /var/log/backup-monitor.log
   ```

## Pemecahan Masalah

### Masalah Umum dan Solusi

#### 1. Backup Gagal

**Masalah**: Server web gagal melakukan push ke server monitoring.

**Solusi**:
- Verifikasi koneksi SSH: `ssh -v [username]@[ip-server-monitoring]`
- Periksa apakah remote Git sudah dikonfigurasi dengan benar: `git remote -v`
- Periksa izin direktori di server monitoring: `ls -la [path-direktori-backup]`

#### 2. Restore Gagal

**Masalah**: Script restore gagal mengembalikan konten web.

**Solusi**:
- Periksa log restore: `cat /var/log/web-restore.log`
- Pastikan repository Git di direktori web sudah diinisialisasi dengan benar
- Verifikasi commit ID yang digunakan untuk restore

#### 3. Integrasi Wazuh Tidak Berfungsi

**Masalah**: Wazuh tidak menjalankan restore otomatis saat terdeteksi defacement.

**Solusi**:
- Periksa konfigurasi active response di Wazuh
- Verifikasi bahwa script restore memiliki izin eksekusi
- Periksa log Wazuh: `cat /var/ossec/logs/active-responses.log`

## Diagram Arsitektur Sistem

```
+--------------------+                +----------------------+
|    Server Web      |                |  Server Monitoring   |
|                    |                |                      |
|  +--------------+  |   Git Push     |  +--------------+   |
|  | Apache Web   |  |--------------->|  | Bare Git     |   |
|  | Server       |  |                |  | Repository   |   |
|  +--------------+  |                |  +--------------+   |
|        |           |                |        |            |
|  +--------------+  |    Restore     |        |            |
|  | Backup/      |<-|----------------|        |            |
|  | Restore      |  |                |        |            |
|  | Scripts      |  |                |        |            |
|  +--------------+  |                |        |            |
|        |           |                |        |            |
|  +--------------+  |    Alerts      |  +--------------+   |
|  | Wazuh Agent  |<-|----------------|->| Wazuh Agent  |   |
|  +--------------+  |                |  +--------------+   |
+--------------------+                +----------------------+
         |                                      |
         |                                      |
         v                                      v
+--------------------+
|   Wazuh Manager    |
|  (Optional Server) |
+--------------------+
```

## Informasi Tambahan

### Lokasi File Penting

#### Server Web
- Script backup: `/usr/local/bin/web-backup`
- Script restore: `/usr/local/bin/web-restore`
- Konfigurasi: `/etc/web-backup/config.conf`
- Log backup: `/var/log/web-backup.log`
- Log restore: `/var/log/web-restore.log`

#### Server Monitoring
- Repository Git backup: `[path-direktori-backup]`
- Script monitoring disk: `/usr/local/bin/monitor-backup-disk.sh`
- Log monitoring: `/var/log/backup-monitor.log`

---

Untuk bantuan lebih lanjut atau pertanyaan, silakan hubungi administrator sistem. 