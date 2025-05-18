# Panduan Konfigurasi Server Monitoring untuk Sistem Anti-Defacement

Dokumen ini berisi panduan untuk menginstal dan mengkonfigurasi server monitoring yang akan menyimpan backup dari server web. Server monitoring adalah komponen penting dalam sistem anti-defacement yang bekerja sebagai repository backup untuk memungkinkan pemulihan cepat jika terjadi serangan web defacement.

## Gambaran Umum Arsitektur Sistem

Sistem anti-defacement bekerja dengan dua server utama:

1. **Server Web**: Server yang menjalankan Apache dan menyimpan konten web yang perlu dilindungi.
2. **Server Monitoring**: Server yang menyimpan backup dari server web dan dapat membantu proses pemulihan.

Server web akan melakukan backup ke server monitoring menggunakan Git. Server monitoring menyimpan backup dalam bentuk Git repository. Jika terjadi defacement, konten web dapat dipulihkan dengan cepat dari backup yang tersimpan di server monitoring.

## Persyaratan Sistem

- Sistem operasi berbasis Linux (diuji pada Ubuntu/Debian)
- Git
- Akses SSH antara server web dan server monitoring
- Ruang disk yang cukup untuk menyimpan backup
- Wazuh (opsional, untuk monitoring)

## Proses Instalasi Server Monitoring

### Langkah 1: Persiapan

1. Unduh `monitoring_setup.sh` ke server monitoring
2. Berikan izin eksekusi:
   ```
   chmod +x monitoring_setup.sh
   ```

### Langkah 2: Menjalankan Script Instalasi

1. Jalankan script sebagai root:
   ```
   sudo ./monitoring_setup.sh
   ```

2. Ikuti petunjuk pada terminal:
   - Tentukan direktori untuk menyimpan backup
   - Pilih apakah akan membuat pengguna khusus untuk backup
   - Konfigurasikan notifikasi dan monitoring (opsional)

### Langkah 3: Mencatat Informasi Konfigurasi

Setelah instalasi selesai, script akan menampilkan informasi penting yang diperlukan untuk mengkonfigurasi server web. Catat informasi berikut:

- IP Server Monitoring
- Username SSH
- Path direktori backup

Informasi ini diperlukan saat menjalankan `install.sh` di server web.

## Konfigurasi SSH

Untuk memungkinkan server web melakukan push ke repository Git di server monitoring, Anda perlu mengatur autentikasi SSH. Ada dua cara:

### Cara 1: Menggunakan ssh-copy-id dari Server Web

Di server web, jalankan:
```
ssh-keygen -t rsa -b 4096 -C "backup@web-server"
ssh-copy-id [username]@[ip-server-monitoring]
```

### Cara 2: Setup Manual

1. Di server web, buat kunci SSH:
   ```
   ssh-keygen -t rsa -b 4096 -C "backup@web-server"
   ```

2. Tampilkan kunci publik:
   ```
   cat ~/.ssh/id_rsa.pub
   ```

3. Di server monitoring, buat atau edit file authorized_keys:
   ```
   mkdir -p /home/[username]/.ssh
   nano /home/[username]/.ssh/authorized_keys
   ```

4. Tempelkan kunci publik dari server web ke file authorized_keys
5. Atur izin yang benar:
   ```
   chmod 700 /home/[username]/.ssh
   chmod 600 /home/[username]/.ssh/authorized_keys
   chown -R [username]:[username] /home/[username]/.ssh
   ```

## Pengujian Koneksi

1. Di server web, coba koneksi SSH ke server monitoring:
   ```
   ssh [username]@[ip-server-monitoring]
   ```

2. Jika berhasil terhubung tanpa diminta password, koneksi SSH telah berhasil dikonfigurasi.

## Integrasi dengan Wazuh

Jika Anda telah menginstal Wazuh Agent di server monitoring, pastikan agent terhubung dengan benar ke Wazuh Manager:

1. Periksa status Wazuh Agent:
   ```
   sudo systemctl status wazuh-agent
   ```

2. Pastikan agent telah terdaftar di Wazuh Manager:
   ```
   sudo /var/ossec/bin/agent_control -i
   ```

## Notifikasi Email

Jika Anda telah mengonfigurasi notifikasi email, Anda akan menerima:

1. Notifikasi setiap kali ada backup baru yang diterima
2. Peringatan jika penggunaan disk melebihi threshold yang ditentukan

## Pemecahan Masalah

### Server Web Gagal Melakukan Push ke Server Monitoring

1. Verifikasi koneksi SSH:
   ```
   ssh -v [username]@[ip-server-monitoring]
   ```

2. Periksa izin direktori:
   ```
   ls -la [path-direktori-backup]
   ```

3. Periksa log Git:
   ```
   cat [path-direktori-backup]/logs/HEAD
   ```

### Notifikasi Email Tidak Berfungsi

1. Pastikan mailutils terinstal:
   ```
   dpkg -l | grep mailutils
   ```

2. Verifikasi konfigurasi email:
   ```
   sudo nano /etc/mailname
   sudo nano /etc/postfix/main.cf
   ```

3. Uji pengiriman email:
   ```
   echo "Test" | mail -s "Test Email" [alamat-email]
   ```

## Pemeliharaan Rutin

1. **Pemeriksaan ruang disk**:
   ```
   df -h [path-direktori-backup]
   ```

2. **Backup repository Git**:
   ```
   tar -czf backup-repo-$(date +%Y%m%d).tar.gz [path-direktori-backup]
   ```

3. **Pembaruan Sistem**:
   ```
   sudo apt update && sudo apt upgrade
   ```

---

Untuk pertanyaan atau bantuan lebih lanjut, harap hubungi administrator sistem. 