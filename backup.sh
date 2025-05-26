#!/bin/bash

# Script Backup untuk Web Server Anti-Defacement
# --------------------------------------------

# Fungsi untuk menampilkan pesan error dan keluar
function error_exit {
    echo -e "\e[31m[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
    exit 1
}

# Fungsi untuk menampilkan pesan sukses
function success_msg {
    echo -e "\e[32m[SUCCESS] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
}

# Fungsi untuk menampilkan pesan info
function info_msg {
    echo -e "\e[34m[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
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
    error_exit "File konfigurasi '$CONFIG_FILE' tidak ditemukan. Jalankan script instalasi terlebih dahulu."
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

# Verifikasi variabel konfigurasi penting untuk backup
REQUIRED_VARS_BACKUP=("WEB_DIR" "PASSWORD" "MONITOR_USER" "MONITOR_IP" "REMOTE_GIT_BACKUP_PATH")
for var in "${REQUIRED_VARS_BACKUP[@]}"; do
    if [ -z "${!var+x}" ] || [ -z "${!var}" ]; then
        error_exit "Variabel konfigurasi '$var' tidak ditemukan atau kosong di '$CONFIG_FILE'."
    fi
done

# Verifikasi direktori web server
if [ ! -d "$WEB_DIR" ]; then
    error_exit "Direktori web server '$WEB_DIR' tidak ditemukan!"
fi

# Meminta password untuk verifikasi (kecuali jika dipanggil dari cron job atau automasi)
if [ -t 0 ]; then  # Jika input terminal tersedia (bukan dari cron)
    read -r -sp "Masukkan password backup: " INPUT_PASSWORD
    echo ""
    
    # Membandingkan password yang dimasukkan dengan password yang tersimpan
    DECODED_PASSWORD=$(echo "$PASSWORD" | base64 -d)
    INPUT_PASSWORD_B64=$(echo -n "$INPUT_PASSWORD" | base64)
    
    if [ "$INPUT_PASSWORD_B64" != "$PASSWORD" ]; then # Membandingkan versi base64
        # Fallback jika password di config belum di-base64 (untuk kompatibilitas lama jika ada)
        # Namun, install.sh seharusnya selalu menyimpan versi base64
        if [ "$INPUT_PASSWORD" != "$DECODED_PASSWORD" ]; then
           error_exit "Password salah!"
        fi
    fi
fi

# Memulai proses backup GIT
info_msg "Memulai proses backup GIT dari '$WEB_DIR'..."

# Masuk ke direktori web server
cd "$WEB_DIR" || error_exit "Gagal masuk ke direktori '$WEB_DIR'"

# Periksa apakah git sudah diinisialisasi
if [ ! -d ".git" ]; then
    error_exit "Repository Git tidak ditemukan di '$WEB_DIR'. Jalankan script instalasi terlebih dahulu."
fi

# Pastikan konfigurasi git lokal sudah diatur (user.email dan user.name dari install.sh)
# install.sh sudah meminta input ini dan mengatur git config --local.
# Cek opsional jika ingin memastikan lagi:
if ! git config --local user.email >/dev/null 2>&1 || ! git config --local user.name >/dev/null 2>&1; then
    warning_msg "Konfigurasi Git user.name atau user.email lokal tidak ditemukan. Pastikan sudah diatur saat instalasi."
    # Anda bisa menambahkan fallback di sini jika perlu, tapi idealnya sudah diatur.
fi

# Cek perubahan pada file
info_msg "Memeriksa perubahan pada file untuk Git..."
if ! git status --porcelain; then
    info_msg "Tidak ada output dari 'git status --porcelain', atau ada error."
fi

# Menambahkan semua file yang baru atau berubah
info_msg "Menambahkan file yang baru atau berubah ke repository Git..."
git add -A

# Melakukan commit dengan timestamp
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
info_msg "Melakukan commit Git dengan timestamp: $TIMESTAMP..."
if git commit -m "Automated backup: $TIMESTAMP"; then
    success_msg "Commit Git berhasil."
else
    # Kode status 1 dari git commit biasanya berarti "nothing to commit"
    if [ $? -eq 1 ]; then
        info_msg "Tidak ada perubahan untuk di-commit ke Git."
    else
        warning_msg "Gagal melakukan commit Git. Mungkin ada masalah lain."
    fi
fi

# Cek apakah remote 'monitoring' sudah diatur
REMOTE_GIT_URL_EXPECTED="$MONITOR_USER@$MONITOR_IP:$REMOTE_GIT_BACKUP_PATH"
CURRENT_REMOTE_URL=$(git remote get-url monitoring 2>/dev/null)

if [ "$CURRENT_REMOTE_URL" != "$REMOTE_GIT_URL_EXPECTED" ]; then
    info_msg "Mengatur atau memperbarui remote Git 'monitoring'..."
    git remote rm monitoring 2>/dev/null # Hapus jika ada, abaikan error
    git remote add monitoring "$REMOTE_GIT_URL_EXPECTED" || 
        error_exit "Gagal mengatur remote Git 'monitoring'."
else
    info_msg "Remote Git 'monitoring' sudah dikonfigurasi dengan benar."
fi

# Periksa apakah remote repository dapat dijangkau
SSH_KEY_PATH_PRIMARY="/root/.ssh/id_rsa_web_backup" # Sesuai yang dibuat install.sh
SSH_OPTIONS="-o BatchMode=yes -o ConnectTimeout=5"
if [ -f "$SSH_KEY_PATH_PRIMARY" ]; then
    SSH_OPTIONS="$SSH_OPTIONS -i $SSH_KEY_PATH_PRIMARY"
fi

info_msg "Memeriksa koneksi SSH ke server monitoring ($MONITOR_IP)..."
if ! ssh $SSH_OPTIONS "$MONITOR_USER@$MONITOR_IP" exit; then
    error_exit "Tidak dapat terhubung ke server monitoring '$MONITOR_USER@$MONITOR_IP'. Periksa konfigurasi SSH, kunci, dan pastikan server monitoring aktif serta dapat dijangkau."
fi

# Backup GIT ke server monitoring
info_msg "Melakukan push Git ke server monitoring ($MONITOR_IP)..."
if git push -u monitoring master; then
    success_msg "Push Git ke server monitoring berhasil."
else
    # Jika push gagal, coba solusi alternatif (misalnya jika URL remote salah format sebelumnya)
    # Namun, blok di atas seharusnya sudah memperbaiki URL remote.
    # Error di sini kemungkinan besar karena masalah koneksi, izin di server remote, atau repo remote belum di-init --bare.
    error_exit "Gagal melakukan push Git ke server monitoring. Periksa pesan error di atas. Pastikan repository Git di server monitoring sudah diinisialisasi dengan benar ('git init --bare') dan SSH key terotorisasi."
fi

success_msg "Proses backup konten statis (GIT) berhasil diselesaikan."
echo ""

# --- PROSES BACKUP FILE DINAMIS ---
info_msg "Memulai proses backup file dinamis..."

if [ "$BACKUP_DYNAMIC" != "true" ]; then
    info_msg "Backup file dinamis tidak diaktifkan dalam konfigurasi (BACKUP_DYNAMIC ليست 'true'). Melewati."
else
    # Verifikasi variabel yang dibutuhkan untuk backup dinamis
    REQUIRED_VARS_DYNAMIC=("LOCAL_DYNAMIC_STAGING_DIR" "REMOTE_DYNAMIC_BACKUP_PATH" "MONITOR_USER" "MONITOR_IP")
    MISSING_VAR_DYNAMIC=false
    for var_dyn in "${REQUIRED_VARS_DYNAMIC[@]}"; do
        if [ -z "${!var_dyn+x}" ] || [ -z "${!var_dyn}" ]; then
            warning_msg "Variabel konfigurasi '$var_dyn' untuk backup dinamis tidak ditemukan atau kosong. Melewati backup dinamis."
            MISSING_VAR_DYNAMIC=true
            break
        fi
    done

    if [ "$MISSING_VAR_DYNAMIC" = "false" ]; then
        if [ ! -d "$LOCAL_DYNAMIC_STAGING_DIR" ]; then
            warning_msg "Direktori staging lokal '$LOCAL_DYNAMIC_STAGING_DIR' untuk file dinamis tidak ditemukan. Melewati backup dinamis."
        else
            # Cek apakah ada file .tar.gz di direktori staging
            # Gunakan find untuk menghitung file, lebih aman daripada ls atau glob langsung
            NUM_ARCHIVES=$(find "$LOCAL_DYNAMIC_STAGING_DIR" -maxdepth 1 -name "*.tar.gz" -type f -print | wc -l)

            if [ "$NUM_ARCHIVES" -eq 0 ]; then
                info_msg "Tidak ada arsip (.tar.gz) ditemukan di direktori staging lokal '$LOCAL_DYNAMIC_STAGING_DIR'. Tidak ada file dinamis untuk ditransfer."
            else
                info_msg "Ditemukan $NUM_ARCHIVES arsip di '$LOCAL_DYNAMIC_STAGING_DIR'. Memulai transfer..."

                # Pastikan direktori remote untuk backup dinamis ada di server monitoring
                info_msg "Memastikan direktori remote '$REMOTE_DYNAMIC_BACKUP_PATH' ada di server monitoring..."
                if ! ssh $SSH_OPTIONS "$MONITOR_USER@$MONITOR_IP" "mkdir -p \"$REMOTE_DYNAMIC_BACKUP_PATH\""; then
                    error_exit "Gagal membuat atau memastikan direktori remote '$REMOTE_DYNAMIC_BACKUP_PATH' di server monitoring. Periksa izin."
                fi
                success_msg "Direktori remote '$REMOTE_DYNAMIC_BACKUP_PATH' siap."

                # Transfer file menggunakan rsync
                # Opsi -R akan mempertahankan struktur path relatif dari sumber
                # Opsi --files-from memerlukan daftar file. Lebih mudah menyertakan dan mengecualikan.
                # Menggunakan --include='*.tar.gz' dan --exclude='*' untuk hanya mentransfer .tar.gz
                # --remove-source-files akan menghapus file dari LOCAL_DYNAMIC_STAGING_DIR setelah berhasil ditransfer
                info_msg "Mentransfer arsip file dinamis dari '$LOCAL_DYNAMIC_STAGING_DIR' ke '$MONITOR_USER@$MONITOR_IP:$REMOTE_DYNAMIC_BACKUP_PATH'..."
                
                # Bentuk perintah rsync
                RSYNC_CMD="rsync -avz --remove-source-files --include='*.tar.gz' --exclude='*' "
                if [ -f "$SSH_KEY_PATH_PRIMARY" ]; then
                     RSYNC_CMD+="-e \"ssh -i $SSH_KEY_PATH_PRIMARY -o BatchMode=yes -o ConnectTimeout=10\" "
                else
                     RSYNC_CMD+="-e \"ssh -o BatchMode=yes -o ConnectTimeout=10\" "
                fi
                RSYNC_CMD+="\"$LOCAL_DYNAMIC_STAGING_DIR/\" \"$MONITOR_USER@$MONITOR_IP:$REMOTE_DYNAMIC_BACKUP_PATH/\""

                info_msg "Perintah Rsync: $RSYNC_CMD" # Untuk debugging jika perlu
                if eval "$RSYNC_CMD"; then
                    success_msg "Transfer file dinamis berhasil. File sumber yang ditransfer telah dihapus dari staging."
                else
                    error_exit "Gagal mentransfer file dinamis menggunakan rsync. Periksa pesan error di atas dan log rsync jika ada."
                fi
            fi
        fi
    fi
    success_msg "Proses backup file dinamis selesai."
fi
echo ""

# Menampilkan statistik backup (opsional, bisa disesuaikan)
info_msg "Statistik Backup Keseluruhan:"
echo "----------------------------------"
echo "Direktori Web Utama: $WEB_DIR"
echo "Tujuan Backup Git: $MONITOR_USER@$MONITOR_IP:$REMOTE_GIT_BACKUP_PATH"
if [ "$BACKUP_DYNAMIC" = "true" ]; then
    echo "Tujuan Backup Dinamis: $MONITOR_USER@$MONITOR_IP:$REMOTE_DYNAMIC_BACKUP_PATH"
    echo "Staging Dinamis Lokal: $LOCAL_DYNAMIC_STAGING_DIR"
fi
echo "Ukuran total repository Git lokal: $(du -sh "$WEB_DIR/.git" | cut -f1)"
echo "Jumlah file dalam repository Git: $(git ls-files | wc -l)"
echo "Commit Git terakhir: $(git log -1 --pretty=format:\"%h - %an, %ar : %s\")"
echo ""
echo "================================================================="
echo "      SEMUA PROSES BACKUP SELESAI                               "
echo "================================================================="
