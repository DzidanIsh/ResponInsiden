#!/bin/bash

# Script Backup untuk Web Server Anti-Defacement
# --------------------------------------------

# Fungsi untuk menampilkan pesan error dan keluar
function error_exit {
    echo -e "\e[31m[ERROR] $1\e[0m"
    exit 1
}

# Fungsi untuk menampilkan pesan sukses
function success_msg {
    echo -e "\e[32m[SUCCESS] $1\e[0m"
}

# Fungsi untuk menampilkan pesan info
function info_msg {
    echo -e "\e[34m[INFO] $1\e[0m"
}

# Banner
echo "================================================================="
echo "      BACKUP SISTEM ANTI-DEFACEMENT WEB SERVER                   "
echo "================================================================="
echo ""

# Verifikasi bahwa script dijalankan sebagai root
if [ "$(id -u)" -ne 0 ]; then
    error_exit "Script ini harus dijalankan sebagai root."
fi

# Memuat konfigurasi
CONFIG_FILE="/etc/web-backup/config.conf"
if [ ! -f "$CONFIG_FILE" ]; then
    error_exit "File konfigurasi tidak ditemukan. Jalankan script instalasi terlebih dahulu."
fi

source "$CONFIG_FILE"

# Verifikasi direktori web server
if [ ! -d "$WEB_DIR" ]; then
    error_exit "Direktori web server $WEB_DIR tidak ditemukan!"
fi

# Meminta password untuk verifikasi (kecuali jika dipanggil dari cron job)
if [ -t 0 ]; then  # Jika input terminal tersedia (bukan dari cron)
    read -sp "Masukkan password backup: " INPUT_PASSWORD
    echo ""
    
    # Membandingkan password yang dimasukkan dengan password yang tersimpan
    if [ "$(echo -n "$INPUT_PASSWORD" | base64)" != "$PASSWORD" ]; then
        error_exit "Password salah!"
    fi
fi

# Memulai proses backup
info_msg "Memulai proses backup dari $WEB_DIR..."

# Masuk ke direktori web server
cd "$WEB_DIR" || error_exit "Gagal masuk ke direktori $WEB_DIR"

# Periksa apakah git sudah diinisialisasi
if [ ! -d ".git" ]; then
    error_exit "Repository Git tidak ditemukan di $WEB_DIR. Jalankan script instalasi terlebih dahulu."
fi

# Pastikan konfigurasi git lokal sudah diatur
if ! git config --local user.email >/dev/null 2>&1; then
    git config --local user.email "backup@system.local"
    info_msg "Git user.email dikonfigurasi ke backup@system.local"
fi
if ! git config --local user.name >/dev/null 2>&1; then
    git config --local user.name "Backup System"
    info_msg "Git user.name dikonfigurasi ke Backup System"
fi

# Cek perubahan pada file
info_msg "Memeriksa perubahan pada file..."
git status --porcelain

# Menambahkan semua file yang baru atau berubah
info_msg "Menambahkan file yang baru atau berubah ke repository Git..."
git add -A

# Melakukan commit dengan timestamp
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
info_msg "Melakukan commit dengan timestamp: $TIMESTAMP..."
git commit -m "Backup at $TIMESTAMP" || {
    if [ $? -eq 1 ]; then
        info_msg "Tidak ada perubahan yang perlu di-commit."
    else
        error_exit "Gagal melakukan commit."
    fi
}

# Cek apakah remote sudah diatur
REMOTE_EXISTS=$(git remote | grep "monitoring" || echo "")
if [ -z "$REMOTE_EXISTS" ]; then
    info_msg "Mengatur remote repository..."
    git remote add monitoring "$MONITOR_USER@$MONITOR_IP:$BACKUP_DIR" || 
        error_exit "Gagal mengatur remote repository."
fi

# Periksa apakah remote repository dapat dijangkau
info_msg "Memeriksa koneksi ke server monitoring ($MONITOR_IP)..."
if ! ssh -q -o BatchMode=yes -o ConnectTimeout=5 "$MONITOR_USER@$MONITOR_IP" exit; then
    error_exit "Tidak dapat terhubung ke server monitoring. Periksa konfigurasi SSH dan pastikan server monitoring aktif."
fi

# Backup ke server monitoring
info_msg "Melakukan push ke server monitoring ($MONITOR_IP)..."
git push -u monitoring master || {
    # Jika push gagal, coba solusi alternatif
    info_msg "Push standar gagal, mencoba cara alternatif..."
    
    # Jika remote tidak valid, coba konfigurasi ulang dengan format yang benar
    git remote set-url monitoring "$MONITOR_USER@$MONITOR_IP:$BACKUP_DIR"
    
    # Coba push lagi
    git push -u monitoring master || {
        error_exit "Gagal melakukan push ke server monitoring. Periksa apakah repository Git di server monitoring sudah diinisialisasi dengan benar."
    }
}

success_msg "Backup berhasil diselesaikan pada: $(date)"

# Menampilkan statistik backup
echo ""
echo "Statistik Backup:"
echo "----------------"
echo "Direktori sumber: $WEB_DIR"
echo "Server tujuan: $MONITOR_USER@$MONITOR_IP:$BACKUP_DIR"
echo "Ukuran total repository: $(du -sh "$WEB_DIR/.git" | cut -f1)"
echo "Jumlah file dalam backup: $(git ls-files | wc -l)"
echo "Commit terakhir: $(git log -1 --pretty=format:"%h - %an, %ar : %s")"
echo ""
echo "================================================================="
echo "      BACKUP SELESAI                                            "
echo "=================================================================" 