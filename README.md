# BeeVMS - eBPF based Vulnerability Management System

# Features
- Realtime agent-based process monitoring
- Automatic detection of vulnerable applications

# Architecture
## Master-Server
Мастер сервер объединяет основные модули решения:
- База данных (информация с конечных точек, набор политик, перечень уязвимостей (NIST))
- Аналитический модуль и визуализация (Dashboard)
- Модуль управления компонентами
  
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

оффтоп:
Цели:

1. Контроль использования ПО на хосте
2. Контроль наличия и митигация уязвимостей в используемом ПО
3. Документирование состояния инфраструктуры

Задачи
1. Разработать определение допустимых паттернов поведения пользователя на хосте
2. Разработать технологии оперативного выявления уязвимых компонент в ПО и применения мер по снижению риска.
3. Разработать технологии сбора данных и автоматизированного создания отчётов о состоянии инфраструктуры

Qualys VMDR
Tetragon
Tracee
CrowdStrike Falcon
Kaspersky EDR
