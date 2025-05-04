# BeeVMS - eBPF based Vulnerability Management System

# Features
- Realtime agent-based process monitoring
- Automatic detection of vulnerable applications

# Malware hashes
- Директория Malware_hashes необходима для ежедневного скачивания вредоносных хэшей SHA256 и хранения файла с хэшами

# NVD
- Директория NVD необходима для скачивания общедоступных баз CVE и добавления релевантной информации в БД

# Building from source

```bash
sudo apt install clang clang-16 libbpf-dev libjansson-dev linux-tools-$(uname -r)
```

```
make
```

