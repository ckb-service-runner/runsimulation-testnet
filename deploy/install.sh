#!/usr/bin/env bash
# Installs runsimulation-testnet as a systemd timer. Run as root from the repository folder.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -c 'import sys; assert sys.version_info >= (3, 8), "Python 3.8+ needed"'
id runsim >/dev/null 2>&1 || useradd --system --home /var/lib/runsim --shell /usr/sbin/nologin runsim
install -d -o root -g root -m 0755 /opt/runsim /opt/runsim/service /opt/runsim/deployments
install -m 0644 sim.py /opt/runsim/sim.py
install -m 0644 service/simsvc.elf /opt/runsim/service/simsvc.elf
install -m 0644 deployments/csr-testnet.json /opt/runsim/deployments/csr-testnet.json
install -d -o runsim -g runsim -m 0700 /var/lib/runsim
install -d -m 0755 /etc/runsim
[ -f /etc/runsim/runsim.ini ] || install -m 0644 deploy/runsim.ini.example /etc/runsim/runsim.ini
install -m 0644 deploy/runsim.service /etc/systemd/system/runsim.service
install -m 0644 deploy/runsim.timer /etc/systemd/system/runsim.timer
systemctl daemon-reload
sudo -u runsim python3 /opt/runsim/sim.py --config /etc/runsim/runsim.ini selftest
sudo -u runsim python3 /opt/runsim/sim.py --config /etc/runsim/runsim.ini init
if grep -q '"service"' /var/lib/runsim/state.json 2>/dev/null; then
  echo "Updated. The timer picks up the new version at its next run."
else
  echo "Installed. Fund the address above (or let the faucet do it), then:"
  echo "  sudo -u runsim python3 /opt/runsim/sim.py --config /etc/runsim/runsim.ini deploy-service"
  echo "  systemctl enable --now runsim.timer"
fi
