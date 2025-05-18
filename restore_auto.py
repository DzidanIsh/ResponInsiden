#!/usr/bin/env python3

# Script Restore untuk Anti-Defacement
# --------------------------------------

import os
import sys
import time
import argparse
import getpass
import base64
import datetime
import git
import paramiko
import logging
from pathlib import Path
import glob
import tarfile

# Konfigurasi logging
def setup_logging():
    log_dir = "/var/log/wazuh/active-response"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(f'{log_dir}/restore_auto.log')
        ]
    )
    return logging.getLogger('web-restore')

logger = setup_logging()

# Konfigurasi
CONFIG_FILE = "/etc/web-backup/config.conf"

def error_exit(message):
    """Tampilkan pesan error dan keluar"""
    print(f"\033[31m[ERROR] {message}\033[0m")
    sys.exit(1)

def success_msg(message):
    """Tampilkan pesan sukses"""
    print(f"\033[32m[SUCCESS] {message}\033[0m")

def info_msg(message):
    """Tampilkan pesan info"""
    print(f"\033[34m[INFO] {message}\033[0m")

def load_config():
    """Memuat konfigurasi dari file config"""
    config_file = "/etc/web-backup/config.conf"
    
    if not os.path.isfile(config_file):
        logger.error(f"File konfigurasi tidak ditemukan: {config_file}")
        sys.exit(1)
    
    config = {}
    try:
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip().strip('"\'')
    except Exception as e:
        logger.error(f"Error membaca konfigurasi: {str(e)}")
        sys.exit(1)
    
    return config

def verify_password(config, auto_mode=False):
    """Verifikasi password pengguna"""
    if auto_mode:
        # Dalam mode otomatis, kita lewati verifikasi password
        return True
    
    encoded_password = config['PASSWORD']
    input_password = getpass.getpass("Masukkan password restore: ")
    input_encoded = base64.b64encode(input_password.encode()).decode()
    
    if input_encoded != encoded_password:
        error_exit("Password salah!")
    
    return True

def fetch_commits(config):
    """Ambil daftar commit dari repository Git"""
    web_dir = config['WEB_DIR']
    
    try:
        repo = git.Repo(web_dir)
        # Dapatkan daftar commit
        commits = list(repo.iter_commits('master', max_count=20))
        return commits
    except git.exc.InvalidGitRepositoryError:
        error_exit(f"Repository Git tidak ditemukan di {web_dir}")
    except Exception as e:
        error_exit(f"Gagal mengakses repository Git: {str(e)}")

def backup_current_state(web_dir, backup_dir):
    """Backup kondisi saat ini sebelum restore"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(backup_dir, f"pre_restore_backup_{timestamp}")
    
    try:
        os.makedirs(backup_path, exist_ok=True)
        os.system(f"cp -r {web_dir}/* {backup_path}/")
        info_msg(f"Kondisi saat ini di-backup ke {backup_path}")
        return backup_path
    except Exception as e:
        info_msg(f"Gagal membuat backup kondisi saat ini: {str(e)}")
        return None

def restore_from_commit(config, commit, auto_mode=False):
    """Pulihkan konten web dari commit tertentu"""
    web_dir = config['WEB_DIR']
    
    try:
        # Backup kondisi saat ini (opsional)
        if not auto_mode:
            backup_dir = "/tmp/web_restore_backups"
            backup_current_state(web_dir, backup_dir)
        
        # Masuk ke direktori web
        os.chdir(web_dir)
        
        # Reset ke commit yang dipilih
        repo = git.Repo(web_dir)
        info_msg(f"Melakukan restore ke commit: {commit.hexsha[:8]} - {commit.message.strip()}")
        
        # Hard reset ke commit yang dipilih
        repo.git.reset('--hard', commit.hexsha)
        
        # Bersihkan file yang tidak terlacak
        repo.git.clean('-fd')
        
        success_msg(f"Restore berhasil dilakukan pada: {datetime.datetime.now()}")
        
        # Catat aktivitas restore
        log_restore_activity(config, commit, auto_mode)
        
        return True
    except Exception as e:
        error_exit(f"Gagal melakukan restore: {str(e)}")

def log_restore_activity(config, commit, auto_mode):
    """Catat aktivitas restore ke log"""
    log_file = "/var/log/web-restore.log"
    
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        trigger = "AUTO" if auto_mode else "MANUAL"
        commit_info = f"{commit.hexsha[:8]} - {commit.message.strip()}"
        
        with open(log_file, 'a') as f:
            f.write(f"{timestamp} - {trigger} RESTORE - Commit: {commit_info}\n")
    except Exception as e:
        info_msg(f"Gagal mencatat aktivitas restore: {str(e)}")

def get_latest_good_commit(commits):
    """Pilih commit terakhir yang dianggap 'aman' untuk restore otomatis"""
    # Strategi sederhana: pilih commit kedua terakhir
    # Asumsinya adalah commit terakhir mungkin yang berisi perubahan berbahaya
    
    if len(commits) > 1:
        # Pilih commit kedua terakhir
        return commits[1]
    else:
        # Jika hanya ada 1 commit, gunakan itu
        return commits[0]

def interactive_restore(config, commits):
    """Mode interaktif untuk restore"""
    print("\nDaftar 20 commit terakhir:")
    print("============================")
    
    for i, commit in enumerate(commits):
        commit_time = datetime.datetime.fromtimestamp(commit.committed_date).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{i+1}. [{commit_time}] {commit.hexsha[:8]} - {commit.message.strip()}")
    
    # Pilih commit
    while True:
        try:
            choice = int(input("\nPilih nomor commit untuk restore (1-20): "))
            if 1 <= choice <= len(commits):
                selected_commit = commits[choice-1]
                break
            else:
                print("Nomor tidak valid. Coba lagi.")
        except ValueError:
            print("Masukkan nomor yang valid.")
    
    # Konfirmasi
    confirm = input(f"\nAnda akan melakukan restore ke commit:\n[{selected_commit.hexsha[:8]}] {selected_commit.message.strip()}\nLanjutkan? (y/n): ")
    
    if confirm.lower() == 'y':
        restore_from_commit(config, selected_commit)
    else:
        print("Restore dibatalkan.")

def auto_restore(config, commits):
    """Mode otomatis untuk restore tanpa interaksi pengguna"""
    info_msg("Menjalankan restore otomatis sebagai respons insiden...")
    
    # Pilih commit terakhir yang dianggap 'aman'
    commit = get_latest_good_commit(commits)
    
    info_msg(f"Memilih commit aman terakhir untuk restore: {commit.hexsha[:8]} - {commit.message.strip()}")
    
    # Lakukan restore
    restore_from_commit(config, commit, auto_mode=True)

def restore_dynamic_files(config):
    """Memulihkan file dinamis dari backup terpisah"""
    try:
        dynamic_backup_dir = config.get('DYNAMIC_BACKUP_DIR')
        if not dynamic_backup_dir:
            logger.warning("Direktori backup dinamis tidak dikonfigurasi")
            return False

        if not os.path.exists(dynamic_backup_dir):
            logger.warning(f"Direktori backup dinamis tidak ditemukan: {dynamic_backup_dir}")
            return False

        # Dapatkan backup terbaru untuk setiap direktori dinamis
        dynamic_dirs = config.get('DYNAMIC_DIRS', [])
        for dir_name in dynamic_dirs:
            # Cari backup terbaru untuk direktori ini
            backups = glob.glob(os.path.join(dynamic_backup_dir, f"{dir_name}_*.tar.gz"))
            if not backups:
                logger.warning(f"Tidak ada backup ditemukan untuk {dir_name}")
                continue

            # Urutkan berdasarkan waktu modifikasi (terbaru dulu)
            latest_backup = max(backups, key=os.path.getmtime)
            
            # Ekstrak backup
            target_dir = os.path.join(config['WEB_DIR'], dir_name)
            if os.path.exists(target_dir):
                # Backup direktori saat ini sebelum restore
                backup_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"{dir_name}_pre_restore_{backup_timestamp}.tar.gz"
                backup_path = os.path.join(dynamic_backup_dir, backup_name)
                
                # Buat backup dari direktori saat ini
                with tarfile.open(backup_path, "w:gz") as tar:
                    tar.add(target_dir, arcname=dir_name)
                
                logger.info(f"Backup {dir_name} saat ini disimpan di {backup_path}")
            
            # Ekstrak backup terbaru
            with tarfile.open(latest_backup, "r:gz") as tar:
                tar.extractall(path=config['WEB_DIR'])
            
            logger.info(f"File dinamis {dir_name} berhasil dipulihkan dari {latest_backup}")
        
        return True
    except Exception as e:
        logger.error(f"Gagal memulihkan file dinamis: {str(e)}")
        return False

def restore_from_backup(web_dir, non_root=False):
    """Restore dari backup Git"""
    try:
        if not os.path.isdir(web_dir):
            logger.error(f"Direktori web server tidak ditemukan: {web_dir}")
            return False
        
        repo_path = os.path.join(web_dir, ".git")
        if not os.path.isdir(repo_path):
            logger.error(f"Repository Git tidak ditemukan di: {web_dir}")
            return False
        
        logger.info(f"Memulai proses restore untuk direktori: {web_dir}")
        
        # Load konfigurasi
        config = load_config()
        
        # Backup file dinamis sebelum restore
        if config.get('BACKUP_DYNAMIC', False):
            logger.info("Memulai backup file dinamis sebelum restore...")
            restore_dynamic_files(config)
        
        # Masuk ke direktori web
        os.chdir(web_dir)
        
        # Inisialisasi repository Git
        repo = git.Repo(web_dir)
        
        # Pilih commit terakhir yang valid
        commits = list(repo.iter_commits('master', max_count=2))
        if not commits:
            logger.error("Tidak ada commit yang tersedia")
            return False
        
        # Gunakan commit kedua terakhir (jika ada) untuk restore
        selected_commit = commits[1] if len(commits) > 1 else commits[0]
        
        logger.info(f"Melakukan restore ke commit: {selected_commit.hexsha[:8]}")
        
        # Reset ke commit yang dipilih
        repo.git.reset('--hard', selected_commit.hexsha)
        
        # Bersihkan file yang tidak terlacak
        repo.git.clean('-fd')
        
        logger.info(f"Restore berhasil ke commit {selected_commit.hexsha[:8]}")
        return True
        
    except Exception as e:
        logger.error(f"Error saat restore: {str(e)}")
        return False

def main():
    """Fungsi utama"""
    # Banner
    print("=================================================================")
    print("      RESTORE SISTEM ANTI-DEFACEMENT WEB SERVER                  ")
    print("=================================================================")
    
    # Parse argumen
    parser = argparse.ArgumentParser(description="Web Server Anti-Defacement Restore Tool")
    parser.add_argument("--auto", action="store_true", help="Mode otomatis tanpa interaksi")
    parser.add_argument("--alert", action="store_true", help="Dipanggil dari alert Wazuh")
    parser.add_argument("--non-root", action="store_true", help="Jalankan dalam mode non-root")
    args = parser.parse_args()
    
    # Muat konfigurasi
    config = load_config()
    web_dir = config.get('WEB_DIR')
    
    if not web_dir:
        logger.error("Direktori web tidak ditemukan dalam konfigurasi")
        sys.exit(1)
    
    # Jalankan restore
    success = restore_from_backup(web_dir, args.non_root)
    
    if success:
        logger.info("Proses restore selesai dengan sukses")
        sys.exit(0)
    else:
        logger.error("Proses restore gagal")
        sys.exit(1)

if __name__ == "__main__":
    main() 