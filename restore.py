#!/usr/bin/env python3

"""
Script Restore untuk Sistem Anti-Defacement Web Server
Dapat diintegrasikan dengan Wazuh sebagai respons insiden
"""

import os
import sys
import argparse
import json
import base64
import subprocess
import logging
import getpass
import datetime
import git
import requests
from pathlib import Path

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/var/log/web-restore.log')
    ]
)
logger = logging.getLogger('web-restore')

# Warna untuk output terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    """Menampilkan banner aplikasi"""
    banner = """
=================================================================
      RESTORE SISTEM ANTI-DEFACEMENT WEB SERVER
=================================================================
    """
    print(Colors.HEADER + banner + Colors.ENDC)

def error_exit(message):
    """Menampilkan pesan error dan keluar"""
    logger.error(message)
    print(Colors.FAIL + f"[ERROR] {message}" + Colors.ENDC)
    sys.exit(1)

def success_msg(message):
    """Menampilkan pesan sukses"""
    logger.info(message)
    print(Colors.GREEN + f"[SUCCESS] {message}" + Colors.ENDC)

def info_msg(message):
    """Menampilkan pesan info"""
    logger.info(message)
    print(Colors.BLUE + f"[INFO] {message}" + Colors.ENDC)

def load_config():
    """Memuat konfigurasi dari file config"""
    config_file = "/etc/web-backup/config.conf"
    
    if not os.path.isfile(config_file):
        error_exit(f"File konfigurasi tidak ditemukan: {config_file}")
    
    config = {}
    with open(config_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                # Hilangkan tanda kutip
                config[key] = value.strip('"\'')
    
    return config

def verify_password(stored_password):
    """Verifikasi password yang dimasukkan pengguna"""
    try:
        password = getpass.getpass("Masukkan password restore: ")
        encoded_password = base64.b64encode(password.encode()).decode()
        
        if encoded_password != stored_password:
            error_exit("Password salah!")
        
        return True
    except KeyboardInterrupt:
        error_exit("\nOperasi dibatalkan oleh pengguna.")
    except Exception as e:
        error_exit(f"Error saat verifikasi password: {str(e)}")

def restore_from_backup(web_dir, commit_id=None):
    """Restore dari backup Git"""
    try:
        if not os.path.isdir(web_dir):
            error_exit(f"Direktori web server tidak ditemukan: {web_dir}")
        
        repo_path = os.path.join(web_dir, ".git")
        if not os.path.isdir(repo_path):
            error_exit(f"Repository Git tidak ditemukan di: {web_dir}")
        
        info_msg(f"Memulai proses restore untuk direktori: {web_dir}")
        
        # Masuk ke direktori web
        os.chdir(web_dir)
        
        # Membuat backup dari keadaan saat ini sebelum restore
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = f"/tmp/web_defaced_{timestamp}"
        info_msg(f"Membuat backup kondisi sebelum restore di: {backup_dir}")
        subprocess.run(f"mkdir -p {backup_dir} && cp -r {web_dir}/* {backup_dir}/", shell=True, check=True)
        
        # Inisialisasi repository Git
        repo = git.Repo(web_dir)
        
        # Tampilkan daftar commit terbaru
        if not commit_id:
            info_msg("Commit terbaru (dari yang terbaru ke yang lama):")
            commits = list(repo.iter_commits('master', max_count=5))
            for i, commit in enumerate(commits):
                commit_time = datetime.datetime.fromtimestamp(commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
                print(f"{i+1}. {commit.hexsha[:8]} - {commit_time} - {commit.message}")
            
            # Minta pengguna untuk memilih commit
            try:
                choice = int(input("\nPilih nomor commit untuk restore [1]: ") or "1")
                if choice < 1 or choice > len(commits):
                    error_exit(f"Pilihan tidak valid: {choice}")
                selected_commit = commits[choice-1]
            except ValueError:
                selected_commit = commits[0]
        else:
            # Gunakan commit ID yang diberikan
            try:
                selected_commit = repo.commit(commit_id)
            except Exception as e:
                error_exit(f"Commit ID tidak valid: {commit_id}")
        
        # Konfirmasi restore
        commit_time = datetime.datetime.fromtimestamp(selected_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
        info_msg(f"Akan melakukan restore ke commit: {selected_commit.hexsha[:8]} - {commit_time}")
        confirm = input("Apakah Anda yakin ingin melanjutkan? (y/n): ")
        
        if confirm.lower() != 'y':
            error_exit("Operasi restore dibatalkan oleh pengguna.")
        
        # Proses restore
        info_msg("Proses restore dimulai...")
        
        # Reset hard ke commit yang dipilih
        repo.git.reset('--hard', selected_commit.hexsha)
        
        # Bersihkan file yang tidak terlacak
        repo.git.clean('-fd')
        
        success_msg(f"Restore berhasil diselesaikan ke commit {selected_commit.hexsha[:8]}")
        return True
    
    except git.GitCommandError as e:
        error_exit(f"Git error: {str(e)}")
    except Exception as e:
        error_exit(f"Error saat restore: {str(e)}")

def wazuh_integration(web_dir, alert_data=None):
    """Fungsi untuk integrasi dengan Wazuh"""
    try:
        # Jika ada data alert dari Wazuh
        if alert_data:
            try:
                alert = json.loads(alert_data)
                
                # Ekstrak informasi dari alert Wazuh
                rule_id = alert.get('rule', {}).get('id')
                rule_description = alert.get('rule', {}).get('description')
                source_ip = alert.get('data', {}).get('srcip')
                
                info_msg(f"Menerima alert Wazuh Rule ID: {rule_id}")
                info_msg(f"Deskripsi: {rule_description}")
                info_msg(f"IP Sumber: {source_ip}")
                
                # Lakukan restore otomatis
                return restore_from_backup(web_dir)
            
            except json.JSONDecodeError:
                error_exit("Format data Wazuh tidak valid.")
        
        # Jika dijalankan manual, lakukan restore interaktif
        return restore_from_backup(web_dir)
    
    except Exception as e:
        error_exit(f"Error pada integrasi Wazuh: {str(e)}")

def main():
    """Fungsi utama program"""
    parser = argparse.ArgumentParser(description="Web Server Anti-Defacement Restore Tool")
    parser.add_argument("--alert", help="Data alert dari Wazuh dalam format JSON")
    parser.add_argument("--commit", help="ID commit untuk restore langsung")
    parser.add_argument("--auto", action="store_true", help="Mode otomatis tanpa interaksi pengguna")
    args = parser.parse_args()
    
    # Tampilkan banner jika tidak dalam mode otomatis
    if not args.auto:
        print_banner()
    
    # Verifikasi root
    if os.geteuid() != 0:
        error_exit("Script ini harus dijalankan sebagai root.")
    
    # Muat konfigurasi
    config = load_config()
    web_dir = config.get('WEB_DIR')
    stored_password = config.get('PASSWORD')
    
    if not web_dir or not stored_password:
        error_exit("Konfigurasi tidak lengkap. Jalankan kembali script instalasi.")
    
    # Verifikasi password jika tidak dalam mode otomatis dengan alert Wazuh
    if not (args.auto and args.alert):
        verify_password(stored_password)
    
    # Eksekusi restore berdasarkan mode
    if args.alert:
        wazuh_integration(web_dir, args.alert)
    elif args.commit:
        restore_from_backup(web_dir, args.commit)
    else:
        restore_from_backup(web_dir)
    
    # Menampilkan statistik restore
    if not args.auto:
        print("\nStatistik Restore:")
        print("----------------")
        repo = git.Repo(web_dir)
        current_commit = repo.head.commit
        commit_time = datetime.datetime.fromtimestamp(current_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
        
        print(f"Direktori web: {web_dir}")
        print(f"Restore ke commit: {current_commit.hexsha[:8]}")
        print(f"Commit timestamp: {commit_time}")
        print(f"Commit message: {current_commit.message}")
        print(f"Jumlah file dalam restore: {len(list(repo.git.ls_files().split()))}")
        
        print("\n=================================================================")
        print("      RESTORE SELESAI                                           ")
        print("=================================================================")

if __name__ == "__main__":
    main() 