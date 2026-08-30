# nxc_linux_privesc
Linux Privilege Escalation Enumerator for NetExec

Модуль для NetExec (ранее известный как CrackMapExec) (https://github.com/Pennyw0rth/NetExec), который ищет векторы повышения привилегий на Linux хосте через SSH.

Быстрый способ понять, куда копать, при ходе пентестов.

## Что умеет

- Проверяет привилегированные группы (docker, lxd, disk, adm, shadow)
- Разбирает `sudo -l` дополнительно сверяя с GTFOBins
- Находит SUID/SGID, также сверяет с GTFOBins
- Ищет опасные capabilities (cap_setuid, cap_dac_override и др.)
- Анализирует cron (writable, wildcard abuse)
- Проверяет PATH, Python sys.path, LD_PRELOAD, PYTHONPATH
- Проверяет Docker, LXC, Kubernetes, NFS, Logrotate, Tmux
- Определяет уязвимые версии kernel, sudo, glibc, runc, containerd
- Ищет пароли, ключи, скрытые файлы (при `DEEP=true`)


<img width="1031" height="464" alt="lin_privesc_enum" src="https://github.com/user-attachments/assets/920ec826-80d5-41b4-9aba-0a3b2bdb0687" />


## Установка

```bash
git clone https://github.com/tarxtuga/nxc_linux_privesc
cd nxc_linux_privesc
cp linux_privesc_enum.py ~/.nxc/modules/
