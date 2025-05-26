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
# paramiko tidak digunakan lagi jika kita beralih ke rsync/scp via subprocess untuk restore dinamis
# import paramiko 
import logging
from pathlib import Path
import glob
import tarfile
import subprocess # Untuk menjalankan rsync atau scp

# Konfigurasi logging
def setup_logging():
    log_dir = "/var/log/wazuh/active-response" # Sesuai dengan yang di install.sh
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
            # Izin diatur oleh install.sh, tapi pastikan wazuh bisa tulis jika script ini dijalankan sbg wazuh
            # os.chown(log_dir, wazuh_uid, wazuh_gid) # Perlu UID/GID wazuh
            # os.chmod(log_dir, 0o750)
        except Exception as e:
            # Tidak bisa print ke stderr jika ini bagian dari AR yang outputnya ditangkap
            # sys.stderr.write(f"Warning: Gagal membuat direktori log {log_dir}: {e}\n")
            pass # Biarkan logging ke stdout jika file handler gagal

    log_file_path = os.path.join(log_dir, 'restore_auto.log')
    
    # Hapus StreamHandler jika tidak ingin output ganda ke stdout saat dipanggil dari web_restore.sh
    # Karena web_restore.sh sudah mengarahkan stdout & stderr ke restore_ar.log
    # Namun, untuk pemanggilan manual, StreamHandler berguna.
    # Mungkin buat kondisi berdasarkan apakah --alert diberikan.
    handlers_list = [logging.FileHandler(log_file_path)]
    if not any(arg in sys.argv for arg in ['--auto', '--alert']): # Hanya tambah StreamHandler jika bukan auto/alert
        handlers_list.append(logging.StreamHandler(sys.stdout))

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', # Menggunakan name logger
        handlers=handlers_list
    )
    return logging.getLogger('restore_auto') # Menggunakan nama logger spesifik

logger = setup_logging()

CONFIG_FILE = "/etc/web-backup/config.conf"

def load_config():
    """Memuat konfigurasi dari file config"""
    if not os.path.isfile(CONFIG_FILE):
        logger.critical(f"File konfigurasi tidak ditemukan: {CONFIG_FILE}")
        sys.exit(1)
    
    config = {}
    try:
        with open(CONFIG_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    parts = line.split('=', 1)
                    key = parts[0].strip()
                    value = parts[1].strip().strip('"\'')
                    
                    # Khusus untuk DYNAMIC_DIRS yang merupakan array bash
                    if key == "DYNAMIC_DIRS":
                        # Hapus tanda kurung dan pisahkan berdasarkan spasi
                        # Contoh: DYNAMIC_DIRS=("uploads" "cache" "tmp")
                        if value.startswith('(') and value.endswith(')'):
                            value_cleaned = value[1:-1].strip()
                            # Pisahkan item yang mungkin mengandung quote, lalu hapus quote
                            config[key] = [item.strip().strip('"\'') for item in value_cleaned.split()]
                        else: # Jika format tidak sesuai, simpan sebagai string atau kosongkan
                            logger.warning(f"Format DYNAMIC_DIRS tidak sesuai di config: {value}. Harusnya array bash.")
                            config[key] = []
                    else:
                        config[key] = value
    except Exception as e:
        logger.critical(f"Error membaca konfigurasi '{CONFIG_FILE}': {str(e)}", exc_info=True)
        sys.exit(1)
    
    required_keys = ["WEB_DIR", "MONITOR_IP", "MONITOR_USER", "REMOTE_GIT_BACKUP_PATH", "SSH_IDENTITY_FILE"]
    if config.get("BACKUP_DYNAMIC", "false").lower() == "true":
        required_keys.extend(["REMOTE_DYNAMIC_BACKUP_PATH", "LOCAL_DYNAMIC_RESTORE_CACHE_DIR", "DYNAMIC_DIRS"])

    missing_keys = [key for key in required_keys if key not in config or not config[key]]
    if missing_keys:
        logger.critical(f"Variabel konfigurasi berikut hilang atau kosong di '{CONFIG_FILE}': {', '.join(missing_keys)}")
        sys.exit(1)
        
    return config

def verify_password_interactive(config_password_b64):
    """Verifikasi password pengguna untuk mode interaktif"""
    try:
        input_password = getpass.getpass("Masukkan password restore: ")
        input_encoded = base64.b64encode(input_password.encode()).decode()
        
        if input_encoded != config_password_b64:
            logger.error("Password salah!")
            sys.exit(1)
        return True
    except Exception as e:
        logger.error(f"Error saat verifikasi password: {e}")
        sys.exit(1)

def get_latest_commit_for_restore(repo):
    """Pilih commit terakhir yang valid untuk restore otomatis (biasanya kedua terakhir)."""
    try:
        commits = list(repo.iter_commits('master', max_count=2)) # Ambil 2 commit terakhir
        if not commits:
            logger.error("Tidak ada commit yang tersedia di repository Git.")
            return None
        
        # Gunakan commit kedua terakhir jika ada, jika tidak (hanya 1 commit) gunakan yang itu.
        selected_commit = commits[1] if len(commits) > 1 else commits[0]
        logger.info(f"Commit dipilih untuk restore Git: {selected_commit.hexsha[:8]} - {selected_commit.message.strip()}")
        return selected_commit
    except git.exc.GitCommandError as e:
        logger.error(f"Gagal mengambil commit dari repository Git: {e}", exc_info=True)
        return None


def restore_git_content(web_dir, selected_commit):
    """Pulihkan konten web dari commit Git tertentu."""
    try:
        os.chdir(web_dir)
        repo = git.Repo(web_dir) # Re-inisialisasi repo object setelah chdir
        
        logger.info(f"Melakukan Git reset --hard ke commit: {selected_commit.hexsha[:8]}")
        repo.git.reset('--hard', selected_commit.hexsha)
        
        logger.info("Membersihkan file yang tidak terlacak (git clean -fd)...")
        repo.git.clean('-fdx') # -x juga menghapus file yang diabaikan, hati-hati jika .gitignore tidak ketat
        
        logger.info(f"Konten Git berhasil dipulihkan ke commit {selected_commit.hexsha[:8]} pada: {datetime.datetime.now()}")
        return True
    except Exception as e:
        logger.error(f"Gagal melakukan restore Git: {str(e)}", exc_info=True)
        return False

def fetch_dynamic_archives_from_remote(config):
    """Mengambil arsip file dinamis dari server monitoring ke cache lokal."""
    logger.info("Memulai pengambilan arsip file dinamis dari server monitoring...")
    
    monitor_ip = config['MONITOR_IP']
    monitor_user = config['MONITOR_USER']
    remote_path = config['REMOTE_DYNAMIC_BACKUP_PATH'].rstrip('/') + '/' # Pastikan trailing slash
    local_cache_dir = config['LOCAL_DYNAMIC_RESTORE_CACHE_DIR']
    ssh_identity_file = config['SSH_IDENTITY_FILE']

    if not os.path.exists(local_cache_dir):
        try:
            os.makedirs(local_cache_dir, exist_ok=True)
            logger.info(f"Direktori cache restore dinamis dibuat: {local_cache_dir}")
        except Exception as e:
            logger.error(f"Gagal membuat direktori cache '{local_cache_dir}': {e}", exc_info=True)
            return False
    else: # Bersihkan cache lama sebelum fetch baru
        logger.info(f"Membersihkan cache restore dinamis lama di '{local_cache_dir}'...")
        for item in os.listdir(local_cache_dir):
            item_path = os.path.join(local_cache_dir, item)
            try:
                if os.path.isfile(item_path) or os.path.islink(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            except Exception as e:
                logger.warning(f"Gagal menghapus item cache lama '{item_path}': {e}")


    # Periksa apakah rsync terinstal
    if not shutil.which("rsync"):
        logger.error("Perintah 'rsync' tidak ditemukan. Tidak dapat mengambil file dinamis.")
        return False

    rsync_cmd = [
        "rsync",
        "-avz",
        "--include=*.tar.gz", # Hanya ambil file tar.gz
        "--exclude=*",        # Abaikan file lain di direktori remote
        "-e", f"ssh -i {ssh_identity_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR",
        f"{monitor_user}@{monitor_ip}:{remote_path}",
        local_cache_dir
    ]

    logger.info(f"Menjalankan rsync untuk mengambil arsip: {' '.join(rsync_cmd)}")
    try:
        process = subprocess.run(rsync_cmd, capture_output=True, text=True, check=False)
        if process.returncode == 0:
            logger.info("Rsync berhasil mengambil arsip dinamis ke cache lokal.")
            # logger.debug(f"Rsync stdout: {process.stdout}")
            # logger.debug(f"Rsync stderr: {process.stderr}")
            return True
        else:
            logger.error(f"Rsync gagal dengan kode {process.returncode}.")
            logger.error(f"Rsync stdout: {process.stdout}")
            logger.error(f"Rsync stderr: {process.stderr}")
            return False
    except Exception as e:
        logger.error(f"Error saat menjalankan rsync: {e}", exc_info=True)
        return False

def restore_dynamic_files_from_cache(config):
    """Memulihkan file dinamis dari cache lokal yang sudah di-fetch."""
    if not config.get("BACKUP_DYNAMIC", "false").lower() == "true":
        logger.info("Restore file dinamis tidak diaktifkan dalam konfigurasi.")
        return True # Bukan error, hanya dilewati

    logger.info("Memulai proses restore file dinamis dari cache lokal...")
    web_dir = config['WEB_DIR']
    local_cache_dir = config['LOCAL_DYNAMIC_RESTORE_CACHE_DIR']
    dynamic_dirs_config = config.get('DYNAMIC_DIRS', []) # DYNAMIC_DIRS sudah berupa list dari load_config

    if not isinstance(dynamic_dirs_config, list):
        logger.error(f"DYNAMIC_DIRS bukan list di konfigurasi: {dynamic_dirs_config}")
        return False

    if not dynamic_dirs_config:
        logger.info("Tidak ada DYNAMIC_DIRS yang dikonfigurasi untuk direstore.")
        return True

    all_restored_successfully = True
    for dir_name_in_config in dynamic_dirs_config:
        # Nama arsip di staging adalah dir_name_config_timestamp.tar.gz
        # dir_name_in_config bisa mengandung slash, misal "wp-content/uploads"
        # web-backup-dynamic mengganti '/' dengan '_' saat membuat nama arsip
        archive_base_name = dir_name_in_config.replace('/', '_')
        
        archive_pattern = os.path.join(local_cache_dir, f"{archive_base_name}_*.tar.gz")
        found_archives = glob.glob(archive_pattern)

        if not found_archives:
            logger.warning(f"Tidak ada arsip backup ditemukan di cache '{local_cache_dir}' untuk '{dir_name_in_config}' (pola: {archive_base_name}_*.tar.gz).")
            continue

        latest_archive = max(found_archives, key=os.path.getmtime)
        target_path_for_dir = os.path.join(web_dir, dir_name_in_config)

        logger.info(f"Mencoba merestore '{dir_name_in_config}' dari arsip terbaru: '{latest_archive}' ke '{web_dir}'")
        
        try:
            # Backup direktori/file yang ada sebelum overwrite (opsional tapi aman)
            if os.path.exists(target_path_for_dir):
                pre_restore_backup_name = f"{archive_base_name}_prerestore_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.bak"
                pre_restore_backup_path = os.path.join(local_cache_dir, pre_restore_backup_name)
                logger.info(f"Membackup '{target_path_for_dir}' ke '{pre_restore_backup_path}' sebelum restore.")
                if os.path.isdir(target_path_for_dir):
                    shutil.copytree(target_path_for_dir, pre_restore_backup_path, symlinks=True)
                else: # jika itu file
                    shutil.copy2(target_path_for_dir, pre_restore_backup_path)

            # Hapus target path yang ada sebelum ekstrak untuk menghindari konflik merge
            if os.path.lexists(target_path_for_dir): # lexists juga menangani broken symlink
                logger.info(f"Menghapus '{target_path_for_dir}' yang ada sebelum ekstraksi...")
                if os.path.isdir(target_path_for_dir) and not os.path.islink(target_path_for_dir):
                    shutil.rmtree(target_path_for_dir)
                else:
                    os.unlink(target_path_for_dir)

            with tarfile.open(latest_archive, "r:gz") as tar:
                # Ekstrak ke $WEB_DIR. Arsip dibuat dengan -C $WEB_DIR "$dir_name",
                # jadi path di dalam arsip adalah 'dir_name/...'
                tar.extractall(path=web_dir) 
            logger.info(f"Berhasil merestore '{dir_name_in_config}' dari '{latest_archive}'.")
            
            # Atur ulang kepemilikan dan izin jika perlu (mungkin perlu info WEB_SERVER_USER/GROUP dari config)
            web_server_user = config.get('WEB_SERVER_USER')
            web_server_group = config.get('WEB_SERVER_GROUP')
            if web_server_user and web_server_group:
                try:
                    # subprocess.run(['chown', '-R', f'{web_server_user}:{web_server_group}', target_path_for_dir], check=True)
                    # shutil.chown tidak rekursif, perlu os.walk atau find + chown
                    for dirpath, dirnames, filenames in os.walk(target_path_for_dir):
                        shutil.chown(dirpath, user=web_server_user, group=web_server_group)
                        for filename in filenames:
                            shutil.chown(os.path.join(dirpath, filename), user=web_server_user, group=web_server_group)
                    logger.info(f"Kepemilikan untuk '{target_path_for_dir}' diatur ke {web_server_user}:{web_server_group}")
                except Exception as e_chown:
                    logger.warning(f"Gagal mengatur kepemilikan untuk '{target_path_for_dir}': {e_chown}")
            
        except Exception as e:
            logger.error(f"Gagal merestore '{dir_name_in_config}' dari '{latest_archive}': {e}", exc_info=True)
            all_restored_successfully = False
            
    if all_restored_successfully:
        logger.info("Semua file/direktori dinamis yang dikonfigurasi berhasil direstore dari cache.")
    else:
        logger.warning("Beberapa file/direktori dinamis mungkin gagal direstore. Periksa log di atas.")
        
    # Bersihkan cache setelah selesai (opsional)
    # logger.info(f"Membersihkan cache restore dinamis di '{local_cache_dir}'...")
    # try:
    #     shutil.rmtree(local_cache_dir)
    #     os.makedirs(local_cache_dir, exist_ok=True) # Buat lagi untuk pemanggilan berikutnya
    # except Exception as e:
    #     logger.warning(f"Gagal membersihkan direktori cache '{local_cache_dir}': {e}")

    return all_restored_successfully


def main():
    parser = argparse.ArgumentParser(description="Web Server Anti-Defacement Restore Tool")
    parser.add_argument("--auto", action="store_true", help="Mode otomatis tanpa interaksi (misalnya dari Wazuh AR)")
    parser.add_argument("--alert", action="store_true", help="Dipanggil dari alert Wazuh (implisit --auto)")
    parser.add_argument("--non-root", action="store_true", help="Jalankan dalam mode non-root (izin harus sudah diatur)")
    # Tambahkan argumen untuk memilih commit jika ingin mode interaktif lebih lanjut
    # parser.add_argument("--commit", type=str, help="ID commit spesifik untuk restore (mode manual)")
    args = parser.parse_args()

    is_automated_call = args.auto or args.alert
    
    if is_automated_call:
        logger.info("Restore_auto.py dipanggil dalam mode otomatis/alert.")
    else:
        logger.info("Restore_auto.py dipanggil dalam mode interaktif/manual.")
        print("=================================================================")
        print("      RECOVERY SYSTEM - WEB SERVER ANTI-DEFACEMENT               ")
        print("=================================================================")

    try:
        config = load_config()
    except SystemExit: # Sudah di-log oleh load_config
        sys.exit(1) # Pastikan keluar jika config gagal dimuat
        
    web_dir = config['WEB_DIR']

    # Verifikasi password hanya jika BUKAN panggilan otomatis/alert
    if not is_automated_call:
        if 'PASSWORD' not in config or not config['PASSWORD']:
            logger.critical("PASSWORD tidak ditemukan di konfigurasi untuk mode interaktif.")
            sys.exit(1)
        verify_password_interactive(config['PASSWORD'])

    # 1. Restore Konten Statis dari Git
    logger.info(f"Memulai proses restore untuk direktori web: {web_dir}")
    try:
        repo = git.Repo(web_dir)
    except git.exc.InvalidGitRepositoryError:
        logger.critical(f"Repository Git tidak valid atau tidak ditemukan di {web_dir}.")
        sys.exit(1)
    except Exception as e_repo:
        logger.critical(f"Gagal mengakses repository Git di {web_dir}: {e_repo}", exc_info=True)
        sys.exit(1)

    selected_commit = get_latest_commit_for_restore(repo)
    if not selected_commit:
        logger.error("Gagal mendapatkan commit untuk restore Git. Proses dihentikan.")
        sys.exit(1)

    git_restore_success = restore_git_content(web_dir, selected_commit)
    if not git_restore_success:
        logger.error("Restore konten Git gagal. Proses dihentikan sebagian.")
        # Pertimbangkan apakah akan melanjutkan ke restore dinamis jika Git gagal
        # Untuk keamanan, mungkin lebih baik berhenti jika restore inti gagal.
        sys.exit(1)
    
    # 2. Restore File Dinamis (jika diaktifkan)
    dynamic_restore_success = True # Anggap sukses jika tidak diaktifkan
    if config.get("BACKUP_DYNAMIC", "false").lower() == "true":
        if fetch_dynamic_archives_from_remote(config):
            dynamic_restore_success = restore_dynamic_files_from_cache(config)
        else:
            logger.error("Gagal mengambil arsip dinamis dari remote. Restore file dinamis dilewati/gagal.")
            dynamic_restore_success = False # Gagal fetch berarti gagal restore dinamis

    if git_restore_success and dynamic_restore_success:
        logger.info("Proses restore (Git dan Dinamis jika aktif) selesai dengan sukses.")
        if not is_automated_call: print("\n[SUCCESS] Proses restore selesai.")
        sys.exit(0)
    else:
        logger.error("Satu atau lebih bagian dari proses restore gagal. Periksa log untuk detail.")
        if not is_automated_call: print("\n[ERROR] Proses restore gagal. Periksa log.")
        sys.exit(1)

if __name__ == "__main__":
    # Cek apakah dijalankan sebagai root jika --non-root tidak diset
    # Argumen --non-root ada untuk kasus di mana Wazuh AR dikonfigurasi untuk menjalankan skrip sebagai user wazuh
    # dengan sudo terkonfigurasi, atau jika izin sudah diatur sedemikian rupa.
    # Namun, operasi seperti git reset --hard dan git clean -fd biasanya memerlukan hak tulis penuh di WEB_DIR.
    # Rsync ke direktori sistem juga mungkin memerlukan root.
    # Untuk kesederhanaan, kita tidak menambahkan cek root di sini, asumsikan dijalankan dengan hak yang sesuai.
    main()
