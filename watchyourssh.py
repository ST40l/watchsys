import os
import time
import re
import threading

log_file = "/sec/root/izinsizgiriş.log"

def log_unauthorized_access(ip_address, username):
    current_time = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{current_time} - Unauthorized access from: {ip_address} (Username: {username})\n"

    with open(log_file, "a") as f:
        f.write(log_entry)

def parse_ssh_log(log_line):
    pattern = r"([\w]+ [0-9]+ [0-9]+:[0-9]+:[0-9]+) [\w]+ sshd\[[0-9]+\]: Failed password for ([\w]+) from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"
    match = re.search(pattern, log_line)
    if match:
        timestamp, username, ip_address = match.groups()
        return timestamp, username, ip_address
    return None, None, None

def monitor_auth_log():
    while True:
        with open("/var/log/auth.log", "r") as auth_log:
            lines = auth_log.readlines()

        for line in reversed(lines):
            timestamp, username, ip_address = parse_ssh_log(line)
            if timestamp and username and ip_address:
                log_unauthorized_access(ip_address, username)

        time.sleep(60)  # 1 dakika aralıklarla günlüğü kontrol et

def main():
    # İzleme işlemini arka planda başlat
    monitor_thread = threading.Thread(target=monitor_auth_log)
    monitor_thread.daemon = True
    monitor_thread.start()

    try:
        while True:
            # Sistemden çıkış yapıldığını kontrol etmek için bir işlem yapabilirsiniz
            # Örneğin, "exit" komutunu girerek betiği sonlandırabilirsiniz.
            user_input = input("Type 'exit' to stop the monitoring: ")
            if user_input.strip().lower() == "exit":
                break
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
