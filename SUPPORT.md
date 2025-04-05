# Complete HPC Cluster Setup with Rocky Linux 9, Slurm 24.x, Ceph 19.x, and OpenMPI

## System Overview

### Hardware Configuration
- **Controller Node**: 128 GB RAM, 2 Processors with 8 Cores, 480 GB SSD for OS, 2x8TB storage drives
- **Compute Node 1**: 256 GB RAM, 2 Processors with 48 Cores, 480 GB SSD for OS, 2x8TB storage drives
- **Compute Node 2**: 256 GB RAM, 2 Processors with 48 Cores, 480 GB SSD for OS, 2x8TB storage drives
- **Compute Node 3**: 256 GB RAM, 2 Processors with 48 Cores, 480 GB SSD for OS, 2x8TB storage drives

### Network Configuration
- Controller Node (controller): 10.10.140.40
- Compute Node 1 (compute01): 10.10.140.41
- Compute Node 2 (compute02): 10.10.140.42
- Compute Node 3 (compute03): 10.10.140.43

### Storage Allocation
- 1.3 TB common log space mounted on all nodes
- 2 TB dedicated storage for each compute node
- Remaining storage as common space for job outputs

### Users to be Created
- `cephadm`: For Ceph administration
- `slurm`: For Slurm scheduling system
- `munge`: For authentication in Slurm
- `hpcadmin`: For general HPC administration
- `hpcuser`: Regular user for running jobs

## Installation Process

All scripts should be run from the controller node (10.10.140.40) as the root user. Follow these steps in order for a complete setup.

## 1. Initial System Configuration

### 1.1 Enable CodeReady Builder (CRB) Repository

```bash
#!/bin/bash
# File: enable_crb.sh

# Enable CodeReady Builder repository on controller node
echo "Enabling CRB repository on controller node..."
dnf config-manager --set-enabled crb

# Create script for compute nodes
cat > enable_crb_compute.sh << 'EOF'
#!/bin/bash

# Enable CodeReady Builder repository
dnf config-manager --set-enabled crb

# Verify the repository is enabled
dnf repolist | grep crb

echo "CRB repository enabled"
EOF

# Make the script executable
chmod +x enable_crb_compute.sh

# Copy and execute the script on compute nodes
for NODE_IP in 10.10.140.41 10.10.140.42 10.10.140.43; do
  echo "Enabling CRB repository on node $NODE_IP..."
  scp enable_crb_compute.sh root@$NODE_IP:/tmp/
  ssh root@$NODE_IP "bash /tmp/enable_crb_compute.sh"
done

# Verify the repository is enabled on controller
dnf repolist | grep crb

# Clean up
rm enable_crb_compute.sh

echo "CRB repository enabled on all nodes"
```

### 1.2 Set Hostnames and Configure /etc/hosts

```bash
#!/bin/bash
# File: setup_hosts.sh

# Define the cluster nodes
CONTROLLER="controller"
COMPUTE01="compute01"
COMPUTE02="compute02"
COMPUTE03="compute03"

CONTROLLER_IP="10.10.140.40"
COMPUTE01_IP="10.10.140.41"
COMPUTE02_IP="10.10.140.42"
COMPUTE03_IP="10.10.140.43"

# Set hostname on controller
hostnamectl set-hostname $CONTROLLER

# Create hosts file content
HOSTS_CONTENT="127.0.0.1   localhost
$CONTROLLER_IP $CONTROLLER
$COMPUTE01_IP $COMPUTE01
$COMPUTE02_IP $COMPUTE02
$COMPUTE03_IP $COMPUTE03"

# Update hosts file on controller
echo "$HOSTS_CONTENT" > /etc/hosts

# Create a script to update compute nodes
cat > update_compute.sh << 'EOF'
#!/bin/bash
# Set hostname
hostnamectl set-hostname $1

# Update hosts file
cat > /etc/hosts << 'EOL'
127.0.0.1   localhost
10.10.140.40 controller
10.10.140.41 compute01
10.10.140.42 compute02
10.10.140.43 compute03
EOL

# Disable firewalld (or configure it appropriately)
systemctl disable firewalld
systemctl stop firewalld

# Disable SELinux for simplicity (you may want to configure it properly in production)
sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
setenforce 0
EOF

# Make the script executable
chmod +x update_compute.sh

# Copy and execute the script on compute nodes
for NODE in compute01 compute02 compute03; do
  scp update_compute.sh rocky@$NODE:/tmp/
  ssh rocky@$NODE "sudo bash /tmp/update_compute.sh $NODE"
done

# Clean up
rm update_compute.sh

# Disable firewalld on controller (or configure it appropriately)
systemctl disable firewalld
systemctl stop firewalld

# Disable SELinux for simplicity
sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
setenforce 0

echo "Host configuration completed on all nodes"
```

### 1.3 Configure SSH Passwordless Access

```bash
#!/bin/bash
# File: setup_ssh.sh

# Generate SSH key for root if it doesn't exist
if [ ! -f /root/.ssh/id_rsa ]; then
  ssh-keygen -t rsa -N "" -f /root/.ssh/id_rsa
fi

# Generate SSH key for rocky if it doesn't exist
if [ ! -f /home/rocky/.ssh/id_rsa ]; then
  sudo -u rocky ssh-keygen -t rsa -N "" -f /home/rocky/.ssh/id_rsa
fi

# Copy root SSH key to all nodes
for NODE in compute01 compute02 compute03; do
  sshpass -p "your_root_password" ssh-copy-id -o StrictHostKeyChecking=no root@$NODE
done

# Copy rocky SSH key to all nodes
for NODE in compute01 compute02 compute03; do
  sudo -u rocky sshpass -p "your_rocky_password" ssh-copy-id -o StrictHostKeyChecking=no rocky@$NODE
done

echo "SSH passwordless access configured for root and rocky users"
```

### 1.4 Create Required Users on All Nodes

```bash
#!/bin/bash
# File: create_users.sh

# Define user list with details
declare -A USERS=(
  ["cephadm"]="Ceph Administrator:5001:/bin/bash"
  ["slurm"]="Slurm Workload Manager:5002:/bin/bash"
  ["munge"]="MUNGE Authentication:5003:/sbin/nologin"
  ["hpcadmin"]="HPC Administrator:5004:/bin/bash"
  ["hpcuser"]="HPC Regular User:5005:/bin/bash"
)

# Create users on controller
for USER in "${!USERS[@]}"; do
  IFS=':' read -r COMMENT UID SHELL <<< "${USERS[$USER]}"
  
  # Create user
  useradd -u $UID -m -c "$COMMENT" -s $SHELL $USER
  
  # Set password (you should change this in production)
  echo "${USER}:${USER}123" | chpasswd
  
  # Generate SSH key if user has a login shell
  if [[ "$SHELL" == "/bin/bash" ]]; then
    sudo -u $USER ssh-keygen -t rsa -N "" -f /home/$USER/.ssh/id_rsa
  fi
done

# Create a script to add users on compute nodes
cat > add_users.sh << 'EOF'
#!/bin/bash

# Create users
useradd -u 5001 -m -c "Ceph Administrator" -s /bin/bash cephadm
useradd -u 5002 -m -c "Slurm Workload Manager" -s /bin/bash slurm
useradd -u 5003 -m -c "MUNGE Authentication" -s /sbin/nologin munge
useradd -u 5004 -m -c "HPC Administrator" -s /bin/bash hpcadmin
useradd -u 5005 -m -c "HPC Regular User" -s /bin/bash hpcuser

# Set passwords
echo "cephadm:cephadm123" | chpasswd
echo "slurm:slurm123" | chpasswd
echo "hpcadmin:hpcadmin123" | chpasswd
echo "hpcuser:hpcuser123" | chpasswd

# Create .ssh directories
for USER in cephadm slurm hpcadmin hpcuser; do
  mkdir -p /home/$USER/.ssh
  chmod 700 /home/$USER/.ssh
  chown $USER:$USER /home/$USER/.ssh
done
EOF

# Make the script executable
chmod +x add_users.sh

# Copy and execute the script on compute nodes
for NODE in compute01 compute02 compute03; do
  scp add_users.sh root@$NODE:/tmp/
  ssh root@$NODE "bash /tmp/add_users.sh"
done

# Configure SSH keys for all users on all nodes
for USER in cephadm slurm hpcadmin hpcuser; do
  # Skip if user has no login shell
  if [[ "${USERS[$USER]}" == *"/sbin/nologin"* ]]; then
    continue
  fi
  
  # Get the public key
  PUBLIC_KEY=$(cat /home/$USER/.ssh/id_rsa.pub)
  
  # Copy the public key to all compute nodes
  for NODE_IP in 10.10.140.41 10.10.140.42 10.10.140.43; do
    ssh root@$NODE_IP "echo '$PUBLIC_KEY' > /home/$USER/.ssh/authorized_keys && chmod 600 /home/$USER/.ssh/authorized_keys && chown $USER:$USER /home/$USER/.ssh/authorized_keys"
  done
done

# Clean up
rm add_users.sh

echo "User setup completed on all nodes"
```

### 1.5 Update and Install Base Packages

```bash
#!/bin/bash
# File: install_base_packages.sh

# Update the controller node
dnf update -y
dnf install -y epel-release
dnf install -y wget git vim chrony net-tools bind-utils sshpass \
    yum-utils device-mapper-persistent-data lvm2 parted \
    nfs-utils python3 python3-pip gcc gcc-c++ make \
    openssl openssl-devel pam-devel numactl \
    numactl-devel hwloc hwloc-devel lua lua-devel \
    readline-devel rrdtool-devel ncurses-devel \
    man man-pages mlocate rsync dnf-plugins-core

# Start and enable chronyd
systemctl start chronyd
systemctl enable chronyd

# Create a script for compute nodes
cat > install_compute_packages.sh << 'EOF'
#!/bin/bash

# Update system
dnf update -y
dnf install -y epel-release
dnf install -y wget git vim chrony net-tools bind-utils \
    yum-utils device-mapper-persistent-data lvm2 parted \
    nfs-utils python3 python3-pip gcc gcc-c++ make \
    openssl openssl-devel pam-devel numactl \
    numactl-devel hwloc hwloc-devel lua lua-devel \
    readline-devel rrdtool-devel ncurses-devel \
    man man-pages mlocate rsync dnf-plugins-core

# Start and enable chronyd
systemctl start chronyd
systemctl enable chronyd
EOF

# Make the script executable
chmod +x install_compute_packages.sh

# Copy and execute the script on compute nodes
for NODE in compute01 compute02 compute03; do
  scp install_compute_packages.sh root@$NODE:/tmp/
  ssh root@$NODE "bash /tmp/install_compute_packages.sh"
done

# Clean up
rm install_compute_packages.sh

echo "Base packages installed on all nodes"
```

### 1.6 Configure NTP Time Synchronization

```bash
#!/bin/bash
# File: configure_ntp.sh

# Configure chrony on controller
cat > /etc/chrony.conf << 'EOF'
# Use public NTP servers
server 0.pool.ntp.org iburst
server 1.pool.ntp.org iburst
server 2.pool.ntp.org iburst
server 3.pool.ntp.org iburst

# Record the rate at which the system clock gains/losses time
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
makestep 1.0 3

# Enable kernel synchronization of the real-time clock (RTC)
rtcsync

# Allow NTP client access from local network
allow 10.10.140.0/24

# Serve time even if not synchronized to a time source
local stratum 10

# Specify file containing keys for NTP authentication
keyfile /etc/chrony.keys

# Specify directory for log files
logdir /var/log/chrony
EOF

# Restart chronyd on controller
systemctl restart chronyd

# Create script for compute nodes
cat > configure_compute_chrony.sh << 'EOF'
#!/bin/bash

# Configure chrony to use controller as time source
cat > /etc/chrony.conf << 'EOL'
# Use controller as time source
server controller iburst

# Record the rate at which the system clock gains/losses time
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
makestep 1.0 3

# Enable kernel synchronization of the real-time clock (RTC)
rtcsync

# Specify file containing keys for NTP authentication
keyfile /etc/chrony.keys

# Specify directory for log files
logdir /var/log/chrony
EOL

# Restart chronyd
systemctl restart chronyd

# Check synchronization status
chronyc sources
EOF

# Make the script executable
chmod +x configure_compute_chrony.sh

# Copy and execute the script on compute nodes
for NODE in compute01 compute02 compute03; do
  scp configure_compute_chrony.sh root@$NODE:/tmp/
  ssh root@$NODE "bash /tmp/configure_compute_chrony.sh"
done

# Clean up
rm configure_compute_chrony.sh

# Verify time synchronization
chronyc sources
chronyc tracking

echo "NTP time synchronization configured on all nodes"
```

## 2. Ceph 19.x Installation and Configuration

### 2.1 Install Podman for Ceph Containerization

```bash
#!/bin/bash
# File: install_podman.sh

# Install Podman on controller node
echo "Installing Podman on controller node..."
dnf install -y podman container-tools

# Create script for compute nodes
cat > install_podman_compute.sh << 'EOF'
#!/bin/bash

# Install Podman and container tools
dnf install -y podman container-tools

# Configure Podman
mkdir -p /etc/containers
cat > /etc/containers/registries.conf << 'EOL'
[registries.search]
registries = ['docker.io', 'quay.io', 'registry.fedoraproject.org', 'registry.access.redhat.com']

[registries.insecure]
registries = []

[registries.block]
registries = []
EOL

# Start and enable podman socket (useful for cephadm)
systemctl enable --now podman.socket

# Verify installation
podman version
EOF

# Make the script executable
chmod +x install_podman_compute.sh

# Copy and execute the script on compute nodes
for NODE in compute01 compute02 compute03; do
  scp install_podman_compute.sh root@$NODE:/tmp/
  ssh root@$NODE "bash /tmp/install_podman_compute.sh"
done

# Configure Podman on controller
mkdir -p /etc/containers
cat > /etc/containers/registries.conf << 'EOF'
[registries.search]
registries = ['docker.io', 'quay.io', 'registry.fedoraproject.org', 'registry.access.redhat.com']

[registries.insecure]
registries = []

[registries.block]
registries = []
EOF

# Start and enable podman socket (useful for cephadm)
systemctl enable --now podman.socket

# Clean up
rm install_podman_compute.sh

# Verify installation
podman version

echo "Podman installation completed on all nodes"
```

### 2.2 Install Ceph Repository and Tools

```bash
#!/bin/bash
# File: install_ceph.sh

# Install Ceph repository on controller
cat > /etc/yum.repos.d/ceph.repo << 'EOF'
[ceph]
name=Ceph packages
baseurl=https://download.ceph.com/rpm-19.2.1/el9/x86_64/
enabled=1
gpgcheck=1
gpgkey=https://download.ceph.com/keys/release.asc

[ceph-noarch]
name=Ceph noarch packages
baseurl=https://download.ceph.com/rpm-19.2.1/el9/noarch/
enabled=1
gpgcheck=1
gpgkey=https://download.ceph.com/keys/release.asc
EOF

# Install cephadm
dnf install -y cephadm

# Install ceph and ceph-common packages on controller
dnf install -y ceph ceph-common

# Verify Podman is working
podman --version || echo "ERROR: Podman is not installed properly. Please install Podman first."

# Create a script for compute nodes
cat > install_ceph_repo.sh << 'EOF'
#!/bin/bash

# Add Ceph repository
cat > /etc/yum.repos.d/ceph.repo << 'EOL'
[ceph]
name=Ceph packages
baseurl=https://download.ceph.com/rpm-19.2.1/el9/x86_64/
enabled=1
gpgcheck=1
gpgkey=https://download.ceph.com/keys/release.asc

[ceph-noarch]
name=Ceph noarch packages
baseurl=https://download.ceph.com/rpm-19.2.1/el9/noarch/
enabled=1
gpgcheck=1
gpgkey=https://download.ceph.com/keys/release.asc
EOL

# Install ceph packages
dnf install -y ceph ceph-common
EOF

# Make the script executable
chmod +x install_ceph_repo.sh

# Copy and execute the script on compute nodes
for NODE in compute01 compute02 compute03; do
  scp install_ceph_repo.sh root@$NODE:/tmp/
  ssh root@$NODE "bash /tmp/install_ceph_repo.sh"
done

# Clean up
rm install_ceph_repo.sh

echo "Ceph repositories added to all nodes"
```

### 2.3 Bootstrap Ceph Cluster and Add Nodes

```bash
#!/bin/bash
# File: bootstrap_ceph.sh

# Generate an SSH key for the cephadm user if needed
if [ ! -f /home/cephadm/.ssh/id_rsa ]; then
  sudo -u cephadm ssh-keygen -t rsa -N "" -f /home/cephadm/.ssh/id_rsa
fi

# Ensure container registry configuration is correct
mkdir -p /etc/ceph
cat > /etc/ceph/cephadm.conf << 'EOF'
image: quay.io/ceph/ceph:v19.2.1
EOF

# Bootstrap the Ceph cluster
cephadm bootstrap --mon-ip 10.10.140.40 \
  --initial-dashboard-user admin \
  --initial-dashboard-password adminpassword \
  --dashboard-password-noupdate \
  --allow-fqdn-hostname

# Wait for the bootstrap to complete
sleep 30

# Add all nodes to the cluster
for NODE in controller compute01 compute02 compute03; do
  ssh-copy-id -f -i /etc/ceph/ceph.pub root@$NODE
  ceph orch host add $NODE
done

# Set the admin key in all nodes
ADMIN_KEY=$(cat /etc/ceph/ceph.client.admin.keyring)

for NODE in compute01 compute02 compute03; do
  ssh root@$NODE "mkdir -p /etc/ceph"
  echo "$ADMIN_KEY" | ssh root@$NODE "cat > /etc/ceph/ceph.client.admin.keyring"
  scp /etc/ceph/ceph.conf root@$NODE:/etc/ceph/
done

echo "Ceph cluster bootstrap completed"
```

### 2.4 Configure OSDs for Storage

```bash
#!/bin/bash
# File: configure_ceph_osds.sh

# Function to detect and add available drives as OSDs
detect_and_add_osds() {
  local NODE=$1
  
  # Identify unused drives (no partitions, not mounted)
  local DISKS=$(ssh root@$NODE "lsblk -dpno NAME,TYPE,MOUNTPOINT | grep -E 'disk' | grep -v -E '.*(boot|root|swap).*' | awk '{\$3==\"\" && print \$1}'")
  
  if [ -z "$DISKS" ]; then
    echo "No available disks found on $NODE"
    return
  fi
  
  echo "Found available disks on $NODE: $DISKS"
  
  # Add each disk as an OSD
  for DISK in $DISKS; do
    echo "Adding $DISK on $NODE as OSD"
    ceph orch daemon add osd $NODE:$DISK
  done
}

# Optionally, manually specify drives if auto-detection doesn't work well in your environment
# For the controller node (assuming /dev/sdb and /dev/sdc are the 8TB drives)
ceph orch daemon add osd controller:/dev/sdb
ceph orch daemon add osd controller:/dev/sdc

# For compute nodes
for NODE in compute01 compute02 compute03; do
  # Auto-detect and add OSDs
  detect_and_add_osds $NODE
  
  # Or manually specify if needed
  # ceph orch daemon add osd $NODE:/dev/sdb
  # ceph orch daemon add osd $NODE:/dev/sdc
done

# Wait for OSDs to be deployed
sleep 60

# Check OSD status
ceph osd status
ceph -s

echo "Ceph OSDs configured on all nodes"
```

### 2.5 Create Ceph Pools and Configuration

```bash
#!/bin/bash
# File: create_ceph_pools.sh

# Create pools for different storage needs
# Common log space pool (1.3TB)
ceph osd pool create log_pool 64
ceph osd pool set log_pool size 2  # Replication factor 2

# Compute node dedicated pools (2TB each)
ceph osd pool create compute01_pool 64
ceph osd pool create compute02_pool 64
ceph osd pool create compute03_pool 64
ceph osd pool set compute01_pool size 2
ceph osd pool set compute02_pool size 2
ceph osd pool set compute03_pool size 2

# Common storage pool for job outputs
ceph osd pool create common_pool 128
ceph osd pool set common_pool size 3  # Higher replication for important job outputs

# Initialize pools for RBD
for POOL in log_pool compute01_pool compute02_pool compute03_pool common_pool; do
  ceph osd pool application enable $POOL rbd
  rbd pool init $POOL
done

# Create RBD volumes
# Log RBD (1.3TB)
rbd create --size 1300G --pool log_pool --image log_volume

# Compute dedicated RBDs (2TB each)
rbd create --size 2048G --pool compute01_pool --image compute01_volume
rbd create --size 2048G --pool compute02_pool --image compute02_volume
rbd create --size 2048G --pool compute03_pool --image compute03_volume

# Common storage RBD (use remaining space, assume about 16TB total with replication)
REMAINING_GB=16384  # Approximate calculation
rbd create --size ${REMAINING_GB}G --pool common_pool --image common_volume

echo "Ceph pools and RBD volumes created"
```

### 2.6 Configure RBD Client and Mount Points

```bash
#!/bin/bash
# File: configure_rbd_mounts.sh

# Retrieve admin key for mounting
ADMIN_KEY=$(ceph auth get-key client.admin)

# Create directories for mount points on all nodes
for NODE in controller compute01 compute02 compute03; do
  ssh root@$NODE "mkdir -p /mnt/log_volume /mnt/common_volume"
done

# Create dedicated mount points on compute nodes
ssh root@compute01 "mkdir -p /mnt/compute01_volume"
ssh root@compute02 "mkdir -p /mnt/compute02_volume"
ssh root@compute03 "mkdir -p /mnt/compute03_volume"

# Install required packages on all nodes
for NODE in controller compute01 compute02 compute03; do
  ssh root@$NODE "dnf install -y ceph-common"
done

# Create RBD mapping script on all nodes
for NODE in controller compute01 compute02 compute03; do
  cat > map_rbd.sh << EOF
#!/bin/bash

# Map log volume
echo "$ADMIN_KEY" | sudo tee /etc/ceph/admin.key
sudo chmod 600 /etc/ceph/admin.key

# Map and mount log volume
sudo rbd map log_pool/log_volume --id admin --keyring /etc/ceph/admin.key
sudo mkfs.xfs /dev/rbd0 || true
sudo mount /dev/rbd0 /mnt/log_volume

# Map and mount common volume
sudo rbd map common_pool/common_volume --id admin --keyring /etc/ceph/admin.key
sudo mkfs.xfs /dev/rbd1 || true
sudo mount /dev/rbd1 /mnt/common_volume

# Add to fstab for persistence
grep -q "/mnt/log_volume" /etc/fstab || echo "/dev/rbd0 /mnt/log_volume xfs noauto,_netdev 0 0" | sudo tee -a /etc/fstab
grep -q "/mnt/common_volume" /etc/fstab || echo "/dev/rbd1 /mnt/common_volume xfs noauto,_netdev 0 0" | sudo tee -a /etc/fstab

# Create a systemd service for automatic mapping and mounting
cat > /etc/systemd/system/rbd-mount.service << 'EOL'
[Unit]
Description=RBD mounts
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /root/map_rbd.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOL

# Enable the service
systemctl daemon-reload
systemctl enable rbd-mount.service
systemctl start rbd-mount.service
EOF

  scp map_rbd.sh root@$NODE:/root/
  ssh root@$NODE "chmod +x /root/map_rbd.sh && /root/map_rbd.sh"
done

# Create dedicated volume mount script for compute nodes
for NODE in compute01 compute02 compute03; do
  NODE_NUM=${NODE#compute}
  
  cat > map_dedicated_rbd.sh << EOF
#!/bin/bash

# Map and mount dedicated volume
sudo rbd map compute${NODE_NUM}_pool/compute${NODE_NUM}_volume --id admin --keyring /etc/ceph/admin.key
sudo mkfs.xfs /dev/rbd2 || true
sudo mount /dev/rbd2 /mnt/compute${NODE_NUM}_volume

# Add to fstab for persistence
grep -q "/mnt/compute${NODE_NUM}_volume" /etc/fstab || echo "/dev/rbd2 /mnt/compute${NODE_NUM}_volume xfs noauto,_netdev 0 0" | sudo tee -a /etc/fstab

# Update the rbd-mount service to include the dedicated volume
sed -i "/ExecStart=/c\ExecStart=/bin/bash /root/map_rbd.sh && /bin/bash /root/map_dedicated_rbd.sh" /etc/systemd/system/rbd-mount.service

# Reload and restart the service
systemctl daemon-reload
systemctl restart rbd-mount.service
EOF

  scp map_dedicated_rbd.sh root@$NODE:/root/
  ssh root@$NODE "chmod +x /root/map_dedicated_rbd.sh && /root/map_dedicated_rbd.sh"
done

echo "RBD volumes mapped and mounted on all nodes"
```

### 2.7 Set Filesystem Permissions

```bash
#!/bin/bash
# File: set_fs_permissions.sh

# Set permissions for log volume on all nodes
for NODE in controller compute01 compute02 compute03; do
  ssh root@$NODE "chown -R cephadm:cephadm /mnt/log_volume"
  ssh root@$NODE "chmod 775 /mnt/log_volume"
done

# Set permissions for common volume on all nodes
for NODE in controller compute01 compute02 compute03; do
  ssh root@$NODE "chown -R hpcuser:hpcuser /mnt/common_volume"
  ssh root@$NODE "chmod 775 /mnt/common_volume"
done

# Set permissions for dedicated volumes on compute nodes
ssh root@compute01 "chown -R hpcuser:hpcuser /mnt/compute01_volume && chmod 700 /mnt/compute01_volume"
ssh root@compute02 "chown -R hpcuser:hpcuser /mnt/compute02_volume && chmod 700 /mnt/compute02_volume"
ssh root@compute03 "chown -R hpcuser:hpcuser /mnt/compute03_volume && chmod 700 /mnt/compute03_volume"

echo "Filesystem permissions set on all volumes"
```

### 2.8 Configure Ceph Prometheus Exporter

```bash
#!/bin/bash
# File: install_ceph_exporter.sh

# Install Ceph Prometheus exporter using the built-in Ceph MGR module
ceph mgr module enable prometheus

# Verify the module is enabled
ceph mgr module ls | grep prometheus

# Configure Prometheus to scrape Ceph metrics
cat >> /etc/prometheus/prometheus.yml << 'EOF'

  - job_name: 'ceph'
    static_configs:
    - targets: ['controller:9283']
EOF

# Restart Prometheus to apply changes
systemctl restart prometheus

# Create a basic Grafana dashboard for Ceph
cat > ceph_dashboard.json << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "Ceph Cluster Dashboard",
    "tags": ["ceph"],
    "timezone": "browser",
    "schemaVersion": 16,
    "version": 0,
    "refresh": "10s",
    "panels": [
      {
        "title": "Ceph Health",
        "type": "stat",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "ceph_health_status",
            "refId": "A"
          }
        ],
        "options": {
          "colorMode": "value",
          "graphMode": "area",
          "justifyMode": "auto",
          "orientation": "auto",
          "reduceOptions": {
            "calcs": ["mean"],
            "fields": "",
            "values": false
          },
          "textMode": "auto"
        },
        "fieldConfig": {
          "defaults": {
            "mappings": [
              {
                "type": "value",
                "options": {
                  "0": {
                    "text": "HEALTH_OK",
                    "color": "green"
                  },
                  "1": {
                    "text": "HEALTH_WARN",
                    "color": "orange"
                  },
                  "2": {
                    "text": "HEALTH_ERR",
                    "color": "red"
                  }
                }
              }
            ],
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {
                  "color": "green",
                  "value": null
                },
                {
                  "color": "orange",
                  "value": 1
                },
                {
                  "color": "red",
                  "value": 2
                }
              ]
            }
          }
        },
        "gridPos": {
          "h": 8,
          "w": 12,
          "x": 0,
          "y": 0
        }
      },
      {
        "title": "OSD Status",
        "type": "gauge",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "sum(ceph_osd_up)",
            "refId": "A",
            "legendFormat": "OSDs Up"
          },
          {
            "expr": "count(ceph_osd_up) - sum(ceph_osd_up)",
            "refId": "B",
            "legendFormat": "OSDs Down"
          }
        ],
        "options": {
          "orientation": "auto",
          "showThresholdLabels": false,
          "showThresholdMarkers": true
        },
        "fieldConfig": {
          "defaults": {
            "mappings": [],
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {
                  "color": "green",
                  "value": null
                },
                {
                  "color": "red",
                  "value": 1
                }
              ]
            }
          }
        },
        "gridPos": {
          "h": 8,
          "w": 12,
          "x": 12,
          "y": 0
        }
      },
      {
        "title": "Cluster Storage Usage",
        "type": "gauge",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "ceph_cluster_total_used_bytes / ceph_cluster_total_bytes * 100",
            "refId": "A"
          }
        ],
        "options": {
          "orientation": "auto",
          "showThresholdLabels": false,
          "showThresholdMarkers": true
        },
        "fieldConfig": {
          "defaults": {
            "mappings": [],
            "max": 100,
            "min": 0,
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {
                  "color": "green",
                  "value": null
                },
                {
                  "color": "orange",
                  "value": 75
                },
                {
                  "color": "red",
                  "value": 90
                }
              ]
            },
            "unit": "percent"
          }
        },
        "gridPos": {
          "h": 8,
          "w": 12,
          "x": 0,
          "y": 8
        }
      }
    ]
  },
  "overwrite": false
}
EOF

# Import dashboard to Grafana (requires API token)
echo "To import the Ceph dashboard into Grafana, please:"
echo "1. Log into Grafana at http://controller:3000/"
echo "2. Go to Dashboard > Import and upload the ceph_dashboard.json file"

echo "Ceph Prometheus exporter configured"
```

## 3. Slurm 24.x Installation and Configuration

### 3.1 Install MUNGE Authentication Service

```bash
#!/bin/bash
# File: install_munge.sh

# Install MUNGE on the controller
dnf install -y munge munge-libs munge-devel

# Create MUNGE key
/usr/sbin/create-munge-key -r

# Set permissions
chown munge:munge /etc/munge/munge.key
chmod 400 /etc/munge/munge.key

# Start and enable MUNGE service
systemctl enable munge
systemctl start munge

# Copy MUNGE key to compute nodes
for NODE in compute01 compute02 compute03; do
  scp /etc/munge/munge.key root@$NODE:/etc/munge/
  ssh root@$NODE "dnf install -y munge munge-libs munge-devel && \
    chown munge:munge /etc/munge/munge.key && \
    chmod 400 /etc/munge/munge.key && \
    systemctl enable munge && \
    systemctl start munge"
done

# Test MUNGE authentication
for NODE in compute01 compute02 compute03; do
  munge -n | ssh $NODE unmunge
  if [ $? -eq 0 ]; then
    echo "MUNGE authentication working with $NODE"
  else
    echo "MUNGE authentication failed with $NODE"
    exit 1
  fi
done

echo "MUNGE authentication service installed and configured on all nodes"
```

### 3.2 Install Slurm 24.x

```bash
#!/bin/bash
# File: install_slurm.sh

# Set Slurm version
SLURM_VERSION="24.05.0"

# Install dependencies on all nodes
for NODE in controller compute01 compute02 compute03; do
  ssh root@$NODE "dnf install -y rpm-build munge munge-libs munge-devel \
    mariadb-devel pam-devel numactl numactl-devel hwloc hwloc-devel \
    lua lua-devel readline-devel rrdtool-devel ncurses-devel \
    perl-ExtUtils-MakeMaker python3-devel man2html"
done

# Download and extract Slurm on the controller
cd /tmp
wget https://download.schedmd.com/slurm/slurm-${SLURM_VERSION}.tar.bz2
tar xvjf slurm-${SLURM_VERSION}.tar.bz2
cd slurm-${SLURM_VERSION}

# Build RPMs
./configure --prefix=/usr --sysconfdir=/etc/slurm --enable-pam \
    --with-pam_dir=/lib64/security/ --without-shared-libslurm
make -j $(nproc)
make install

# Create necessary directories
mkdir -p /etc/slurm
mkdir -p /var/spool/slurm/{ctld,d}
mkdir -p /var/log/slurm

# Set ownership
chown -R slurm:slurm /var/spool/slurm/
chown -R slurm:slurm /var/log/slurm/

# Create slurm.conf
cat > /etc/slurm/slurm.conf << 'EOF'
# slurm.conf
ClusterName=hpc-cluster
ControlMachine=controller
ControlAddr=10.10.140.40
AuthType=auth/munge
CryptoType=crypto/munge
SlurmUser=slurm
SlurmdUser=root
SlurmctldPort=6817
SlurmdPort=6818
StateSaveLocation=/var/spool/slurm/ctld
SlurmdSpoolDir=/var/spool/slurm/d
SwitchType=switch/none
MpiDefault=none
SlurmctldPidFile=/var/run/slurmctld.pid
SlurmdPidFile=/var/run/slurmd.pid
ProctrackType=proctrack/linuxproc
ReturnToService=1
SlurmctldTimeout=300
SlurmdTimeout=300
InactiveLimit=0
MinJobAge=300
KillWait=30
Waittime=0
SchedulerType=sched/backfill
SelectType=select/cons_tres
SelectTypeParameters=CR_Core
AccountingStorageType=accounting_storage/none

# Node configurations
NodeName=compute[01-03] CPUs=96 RealMemory=256000 State=UNKNOWN
# Actual CPU count would be 2 processors × 48 cores each = 96 total cores

# Partition configuration
PartitionName=normal Default=YES Nodes=compute[01-03] MaxTime=INFINITE State=UP
EOF

# Create cgroup.conf
cat > /etc/slurm/cgroup.conf << 'EOF'
CgroupMountpoint="/sys/fs/cgroup"
CgroupAutomount=yes
CgroupReleaseAgentDir="/etc/slurm/cgroup"
AllowedDevicesFile="/etc/slurm/cgroup_allowed_devices_file.conf"
ConstrainCores=yes
ConstrainRAMSpace=yes
ConstrainSwapSpace=yes
ConstrainDevices=yes
EOF

# Create slurmd systemd service file
cat > /etc/systemd/system/slurmd.service << 'EOF'
[Unit]
Description=Slurm node daemon
After=network.target munge.service
ConditionPathExists=/etc/slurm/slurm.conf

[Service]
Type=forking
EnvironmentFile=-/etc/sysconfig/slurmd
ExecStart=/usr/sbin/slurmd $SLURMD_OPTIONS
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/slurmd.pid
KillMode=process
LimitNOFILE=131072
LimitMEMLOCK=infinity
LimitSTACK=infinity
Delegate=yes

[Install]
WantedBy=multi-user.target
EOF

# Create slurmctld systemd service file
cat > /etc/systemd/system/slurmctld.service << 'EOF'
[Unit]
Description=Slurm controller daemon
After=network.target munge.service
ConditionPathExists=/etc/slurm/slurm.conf

[Service]
Type=forking
EnvironmentFile=-/etc/sysconfig/slurmctld
ExecStart=/usr/sbin/slurmctld $SLURMCTLD_OPTIONS
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/slurmctld.pid
KillMode=process
LimitNOFILE=131072
LimitMEMLOCK=infinity
LimitSTACK=infinity

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Build Slurm RPMs for easier installation
rpmbuild -ta --with lua --with hwloc --with multiple-slurmd slurm-${SLURM_VERSION}.tar.bz2

# Install Slurm RPMs on all compute nodes
RPM_DIR=$(rpm --eval %{_topdir})/RPMS
for NODE in compute01 compute02 compute03; do
  # Create necessary directories
  ssh root@$NODE "mkdir -p /etc/slurm /var/spool/slurm/d /var/log/slurm"
  
  # Copy and install RPMs
  ssh root@$NODE "mkdir -p /tmp/slurm_rpms"
  scp $RPM_DIR/x86_64/slurm-*.rpm root@$NODE:/tmp/slurm_rpms/
  ssh root@$NODE "cd /tmp/slurm_rpms && dnf install -y slurm-*.rpm"
  
  # Copy configuration
  scp /etc/slurm/slurm.conf root@$NODE:/etc/slurm/
  scp /etc/slurm/cgroup.conf root@$NODE:/etc/slurm/
  scp /etc/systemd/system/slurmd.service root@$NODE:/etc/systemd/system/

  # Set permissions
  ssh root@$NODE "chown -R slurm:slurm /var/spool/slurm/d /var/log/slurm"
  
  # Enable and start slurmd
  ssh root@$NODE "systemctl daemon-reload && systemctl enable slurmd && systemctl start slurmd"
done

# Start Slurm controller on the controller node
systemctl enable slurmctld
systemctl start slurmctld

echo "Slurm installed and configured on all nodes"
```

### 3.3 Install Slurm Database Daemon (slurmdbd)

```bash
#!/bin/bash
# File: install_slurmdbd.sh

# Install MariaDB on controller node
dnf install -y mariadb-server mariadb

# Start and enable MariaDB
systemctl enable mariadb
systemctl start mariadb

# Secure MariaDB installation
mysql_secure_installation

# Create Slurm database and user
mysql -u root -p << 'EOF'
CREATE DATABASE slurm_acct_db;
CREATE USER 'slurm'@'localhost' IDENTIFIED BY 'slurm_password';
GRANT ALL ON slurm_acct_db.* TO 'slurm'@'localhost';
FLUSH PRIVILEGES;
EOF

# Configure slurmdbd.conf
cat > /etc/slurm/slurmdbd.conf << 'EOF'
# slurmdbd.conf
ArchiveEvents=yes
ArchiveJobs=yes
ArchiveResvs=yes
ArchiveSteps=no
ArchiveSuspend=no
ArchiveTXN=no
ArchiveUsage=no
AuthType=auth/munge
DbdHost=localhost
DbdPort=6819
DebugLevel=info
PurgeEventAfter=1month
PurgeJobAfter=12month
PurgeResvAfter=1month
PurgeStepAfter=1month
PurgeSuspendAfter=1month
PurgeTXNAfter=12month
PurgeUsageAfter=24month
LogFile=/var/log/slurm/slurmdbd.log
PidFile=/var/run/slurmdbd.pid
SlurmUser=slurm
StorageType=accounting_storage/mysql
StorageUser=slurm
StoragePass=slurm_password
StorageLoc=slurm_acct_db
EOF

# Set permissions
chown slurm:slurm /etc/slurm/slurmdbd.conf
chmod 600 /etc/slurm/slurmdbd.conf

# Create slurmdbd service file
cat > /etc/systemd/system/slurmdbd.service << 'EOF'
[Unit]
Description=Slurm Database Daemon
After=network.target munge.service mariadb.service
ConditionPathExists=/etc/slurm/slurmdbd.conf

[Service]
Type=forking
EnvironmentFile=-/etc/sysconfig/slurmdbd
ExecStart=/usr/sbin/slurmdbd $SLURMDBD_OPTIONS
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/slurmdbd.pid
KillMode=process
LimitNOFILE=131072
LimitMEMLOCK=infinity
LimitSTACK=infinity

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Start and enable slurmdbd
systemctl enable slurmdbd
systemctl start slurmdbd

# Update slurm.conf to use accounting
sed -i 's/AccountingStorageType=accounting_storage\/none/AccountingStorageType=accounting_storage\/slurmdbd/' /etc/slurm/slurm.conf
echo "AccountingStorageHost=localhost" >> /etc/slurm/slurm.conf
echo "AccountingStoragePort=6819" >> /etc/slurm/slurm.conf
echo "AccountingStoreJobComment=YES" >> /etc/slurm/slurm.conf

# Restart slurmctld
systemctl restart slurmctld

# Create a cluster in accounting
sacctmgr -i add cluster hpc-cluster

# Create example user association
sacctmgr -i add account general-compute Description="General HPC use" Organization="HPC Users"
sacctmgr -i add user hpcuser Account=general-compute AdminLevel=None

echo "Slurm Database Daemon configured with accounting"
```

### 3.4 Install and Configure Slurm Web

```bash
#!/bin/bash
# File: install_slurm_web.sh

# Install dependencies for Slurm Web
dnf install -y httpd httpd-devel mod_ssl php php-cli php-pdo php-gd php-xml php-json php-ldap mariadb-server php-mysqlnd git

# Start and enable MariaDB
systemctl enable mariadb
systemctl start mariadb

# Secure MariaDB installation (set root password)
mysql_secure_installation

# Create database for Slurm Web
mysql -u root -p << 'EOF'
CREATE DATABASE slurm_web;
CREATE USER 'slurm_web'@'localhost' IDENTIFIED BY 'slurm_web_password';
GRANT ALL PRIVILEGES ON slurm_web.* TO 'slurm_web'@'localhost';
FLUSH PRIVILEGES;
EOF

# Clone Slurm Web
cd /var/www/
git clone https://github.com/edf-hpc/slurm-web.git
cd slurm-web

# Set up configuration
cp conf/slurm-web.conf.example /etc/slurm-web.conf
cp conf/restapi.conf.example /etc/httpd/conf.d/slurm-web-restapi.conf
cp conf/dashboard.conf.example /etc/httpd/conf.d/slurm-web-dashboard.conf

# Configure database connection
sed -i 's/dbname=slurmweb/dbname=slurm_web/g' /etc/slurm-web.conf
sed -i 's/dbuser=slurmweb/dbuser=slurm_web/g' /etc/slurm-web.conf
sed -i 's/dbpassword=slurmweb/dbpassword=slurm_web_password/g' /etc/slurm-web.conf

# Initialize database
php rest/script/database.php

# Set up Apache configuration for Slurm Web
cat > /etc/httpd/conf.d/slurm-web.conf << 'EOF'
<VirtualHost *:80>
  ServerName controller
  
  # REST API
  ProxyPass /slurm-web-api http://localhost:8080
  ProxyPassReverse /slurm-web-api http://localhost:8080
  
  # Dashboard
  DocumentRoot /var/www/slurm-web/dashboard
  
  <Directory /var/www/slurm-web/dashboard>
    Options -Indexes +FollowSymLinks
    AllowOverride All
    Require all granted
  </Directory>
</VirtualHost>
EOF

# Start REST API service
cat > /etc/systemd/system/slurm-web-restapi.service << 'EOF'
[Unit]
Description=Slurm Web REST API
After=network.target

[Service]
Type=simple
User=apache
Group=apache
ExecStart=/usr/bin/php -S 0.0.0.0:8080 -t /var/www/slurm-web/rest
WorkingDirectory=/var/www/slurm-web/rest
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Start and enable services
systemctl daemon-reload
systemctl enable slurm-web-restapi
systemctl start slurm-web-restapi
systemctl enable httpd
systemctl start httpd

echo "Slurm Web installed and configured at http://controller/slurm-web/"
```

## 4. OpenMPI Installation and Configuration

### 4.1 Install Environment Modules System

```bash
#!/bin/bash
# File: install_environment_modules.sh

# Install Environment Modules on all nodes
for NODE in controller compute01 compute02 compute03; do
  ssh root@$NODE "dnf install -y environment-modules"
done

# Create directory for custom modulefiles
mkdir -p /usr/share/Modules/modulefiles/applications

# Create a sample modulefile for users
cat > /usr/share/Modules/modulefiles/applications/example << 'EOF'
#%Module1.0
proc ModulesHelp { } {
  puts stderr "This module sets up the example application"
}

module-whatis "Example Application"

# Path to the software
set approot /opt/applications/example

# Update environment variables
prepend-path PATH $approot/bin
prepend-path LD_LIBRARY_PATH $approot/lib
setenv EXAMPLE_HOME $approot
EOF

# Create a usage guide file
cat > /home/hpcuser/module_usage.txt << 'EOF'
Environment Modules Usage Guide
==============================

Basic commands:
- module avail                 # List available modules
- module load <module>         # Load a module
- module unload <module>       # Unload a module
- module list                  # List loaded modules
- module purge                 # Unload all modules
- module show <module>         # Show details of a module
- module help <module>         # Get help for a module

Example usage:
$ module load mpi/openmpi-4.1.5
$ mpirun --version
EOF

# Copy guide to all compute nodes
for NODE in compute01 compute02 compute03; do
  scp /home/hpcuser/module_usage.txt root@$NODE:/home/hpcuser/
  ssh root@$NODE "chown hpcuser:hpcuser /home/hpcuser/module_usage.txt"
done

# Add module load to user profiles
for NODE in controller compute01 compute02 compute03; do
  ssh root@$NODE "echo 'if [ -f /etc/profile.d/modules.sh ]; then source /etc/profile.d/modules.sh; fi' >> /etc/profile.d/zzz-modules.sh"
  ssh root@$NODE "chmod +x /etc/profile.d/zzz-modules.sh"
done

echo "Environment Modules system installed and configured"
```

### 4.2 Install OpenMPI

```bash
#!/bin/bash
# File: install_openmpi.sh

# Define OpenMPI version
OPENMPI_VERSION="4.1.5"

# Install dependencies on controller
dnf install -y gcc gcc-c++ make libtool autoconf automake valgrind valgrind-devel

# Download and extract OpenMPI
cd /tmp
wget https://download.open-mpi.org/release/open-mpi/v4.1/openmpi-${OPENMPI_VERSION}.tar.gz
tar -xzf openmpi-${OPENMPI_VERSION}.tar.gz
cd openmpi-${OPENMPI_VERSION}

# Configure and build OpenMPI
./configure --prefix=/opt/openmpi --with-slurm --enable-mpi-fortran
make -j $(nproc)
make install

# Create modulefile for OpenMPI
mkdir -p /usr/share/Modules/modulefiles/mpi
cat > /usr/share/Modules/modulefiles/mpi/openmpi-${OPENMPI_VERSION} << EOF
#%Module 1.0
#
#  OpenMPI ${OPENMPI_VERSION} module for use with 'environment-modules' package:
#
conflict mpi
prepend-path    PATH            /opt/openmpi/bin
prepend-path    LD_LIBRARY_PATH /opt/openmpi/lib
prepend-path    MANPATH         /opt/openmpi/share/man
setenv          MPI_HOME        /opt/openmpi
setenv          MPI_BIN         /opt/openmpi/bin
setenv          MPI_SYSCONFIG   /opt/openmpi/etc
setenv          MPI_FORTRAN_MOD_DIR   /opt/openmpi/lib
setenv          MPI_INCLUDE     /opt/openmpi/include
setenv          MPI_LIB         /opt/openmpi/lib
setenv          MPI_MAN         /opt/openmpi/share/man
setenv          MPI_COMPILER    openmpi-x86_64
setenv          MPI_SUFFIX      _openmpi
setenv          MPI_HOME        /opt/openmpi
EOF

# Install environment-modules package
dnf install -y environment-modules

# Create script to deploy OpenMPI to compute nodes
cat > deploy_openmpi.sh << 'EOF'
#!/bin/bash

# Create OpenMPI directory
mkdir -p /opt/openmpi

# Install dependencies
dnf install -y gcc gcc-c++ make environment-modules
EOF

# Deploy to compute nodes
for NODE in compute01 compute02 compute03; do
  scp deploy_openmpi.sh root@$NODE:/tmp/
  ssh root@$NODE "bash /tmp/deploy_openmpi.sh"
  
  # Copy compiled OpenMPI
  scp -r /opt/openmpi/* root@$NODE:/opt/openmpi/
  
  # Copy modulefile
  ssh root@$NODE "mkdir -p /usr/share/Modules/modulefiles/mpi"
  scp /usr/share/Modules/modulefiles/mpi/openmpi-${OPENMPI_VERSION} root@$NODE:/usr/share/Modules/modulefiles/mpi/
done

# Clean up
rm deploy_openmpi.sh

echo "OpenMPI installed and configured on all nodes"
```

### 4.3 Configure OpenMPI Integration with Slurm

```bash
#!/bin/bash
# File: configure_openmpi_slurm.sh

# Update Slurm configuration to work with OpenMPI
cat >> /etc/slurm/slurm.conf << 'EOF'

# MPI Configuration
MpiDefault=pmi2
EOF

# Create example MPI job script
cat > /home/hpcuser/mpi_test.sh << 'EOF'
#!/bin/bash
#SBATCH --job-name=mpi_test
#SBATCH --output=mpi_test_%j.out
#SBATCH --nodes=2
#SBATCH --ntasks-per-node=4
#SBATCH --time=00:05:00

# Load OpenMPI module
module load mpi/openmpi-4.1.5

# Run MPI job
srun --mpi=pmi2 hostname

# MPI Hello World example
cat > hello_world.c << 'EOL'
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    MPI_Init(&argc, &argv);

    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);

    char processor_name[MPI_MAX_PROCESSOR_NAME];
    int name_len;
    MPI_Get_processor_name(processor_name, &name_len);

    printf("Hello world from processor %s, rank %d out of %d processors\n",
           processor_name, world_rank, world_size);

    MPI_Finalize();
    return 0;
}
EOL

# Compile MPI program
mpicc -o hello_world hello_world.c

# Run MPI program
srun --mpi=pmi2 ./hello_world

# Cleanup
rm hello_world.c
EOF

# Set proper ownership and permissions
chown hpcuser:hpcuser /home/hpcuser/mpi_test.sh
chmod +x /home/hpcuser/mpi_test.sh

# Copy Slurm configuration to compute nodes
for NODE in compute01 compute02 compute03; do
  scp /etc/slurm/slurm.conf root@$NODE:/etc/slurm/
  ssh root@$NODE "systemctl restart slurmd"
done

# Restart Slurm controller
systemctl restart slurmctld

echo "OpenMPI integration with Slurm configured"
```

### 4.4 Create Sample Job Scripts Library

```bash
#!/bin/bash
# File: create_job_scripts_library.sh

# Create directory for sample scripts
mkdir -p /home/hpcuser/job_examples
cd /home/hpcuser/job_examples

# Basic job script
cat > basic_job.sh << 'EOF'
#!/bin/bash
#SBATCH --job-name=basic_job
#SBATCH --output=basic_job_%j.out
#SBATCH --error=basic_job_%j.err
#SBATCH --ntasks=1
#SBATCH --time=00:10:00

echo "Starting job at $(date)"
echo "Running on host $(hostname)"
echo "Running on nodes: $(srun hostname | sort -u)"

# Sleep for demonstration
sleep 30

echo "Job completed at $(date)"
EOF

# MPI job script
cat > mpi_job.sh << 'EOF'
#!/bin/bash
#SBATCH --job-name=mpi_job
#SBATCH --output=mpi_job_%j.out
#SBATCH --error=mpi_job_%j.err
#SBATCH --nodes=2
#SBATCH --ntasks-per-node=4
#SBATCH --time=00:30:00

echo "Starting MPI job at $(date)"

# Load MPI module
module load mpi/openmpi-4.1.5

# MPI program (create a simple hello world program)
cat > mpi_hello.c << 'EOL'
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    MPI_Init(&argc, &argv);

    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);

    char processor_name[MPI_MAX_PROCESSOR_NAME];
    int name_len;
    MPI_Get_processor_name(processor_name, &name_len);

    printf("Hello from processor %s, rank %d out of %d processors\n",
           processor_name, world_rank, world_size);

    MPI_Finalize();
    return 0;
}
EOL

# Compile
mpicc -o mpi_hello mpi_hello.c

# Run MPI program
srun --mpi=pmi2 ./mpi_hello

# Clean up
rm mpi_hello.c
rm mpi_hello

echo "MPI job completed at $(date)"
EOF

# Parallel job with array
cat > array_job.sh << 'EOF'
#!/bin/bash
#SBATCH --job-name=array_job
#SBATCH --output=array_job_%A_%a.out
#SBATCH --error=array_job_%A_%a.err
#SBATCH --array=1-4
#SBATCH --ntasks=1
#SBATCH --time=00:10:00

echo "Starting array job $SLURM_ARRAY_TASK_ID at $(date)"
echo "Running on host $(hostname)"

# Sleep based on array ID to demonstrate different run times
sleep $((SLURM_ARRAY_TASK_ID * 5))

echo "Array job $SLURM_ARRAY_TASK_ID completed at $(date)"
EOF

# Job with resource constraints
cat > resource_job.sh << 'EOF'
#!/bin/bash
#SBATCH --job-name=resource_job
#SBATCH --output=resource_job_%j.out
#SBATCH --error=resource_job_%j.err
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=8G
#SBATCH --time=00:20:00

echo "Starting resource-constrained job at $(date)"
echo "Running on host $(hostname)"

# Show allocated resources
echo "Allocated CPUs: $SLURM_CPUS_PER_TASK"
echo "Allocated Memory: $SLURM_MEM_PER_NODE MB"

# Use stress to demonstrate CPU usage (install if needed)
# stress --cpu $SLURM_CPUS_PER_TASK --vm 2 --vm-bytes 1G --timeout 60s

# Simulate work
echo "Simulating CPU-intensive work..."
for i in {1..4}; do
    echo "Running calculation $i..."
    python3 -c "import time; import math; [math.sqrt(x) for x in range(10000000)]; time.sleep(5)"
done

echo "Resource job completed at $(date)"
EOF

# Create CPU performance scaling job
cat > cpu_scaling_test.sh << 'EOF'
#!/bin/bash
#SBATCH --job-name=cpu_scaling
#SBATCH --output=cpu_scaling_%j.out
#SBATCH --error=cpu_scaling_%j.err
#SBATCH --nodes=1
#SBATCH --time=01:00:00

echo "Starting CPU scaling test at $(date)"
echo "Running on host $(hostname)"

# Function to perform matrix multiplication
run_matrix_test() {
    local size=$1
    local threads=$2
    
    cat > matrix_mult.py << 'EOL'
import numpy as np
import time
import sys

def matrix_multiply(size, threads):
    # Set number of threads
    np.show_config()
    import os
    os.environ["OMP_NUM_THREADS"] = str(threads)
    
    # Create random matrices
    A = np.random.rand(size, size)
    B = np.random.rand(size, size)
    
    # Time the multiplication
    start = time.time()
    C = np.matmul(A, B)
    end = time.time()
    
    return end - start

if __name__ == "__main__":
    size = int(sys.argv[1])
    threads = int(sys.argv[2])
    elapsed = matrix_multiply(size, threads)
    print(f"Matrix size: {size}x{size}, Threads: {threads}, Time: {elapsed:.4f} seconds")
EOL

    python3 matrix_mult.py $size $threads
}

# Test different matrix sizes with different thread counts
echo "Testing CPU scaling with different matrix sizes and thread counts"
echo "==============================================================="

# Install NumPy if needed
if ! python3 -c "import numpy" &> /dev/null; then
    echo "Installing NumPy..."
    pip3 install numpy
fi

matrix_sizes=(1000 2000 4000)
thread_counts=(1 2 4 8 16)

for size in "${matrix_sizes[@]}"; do
    for threads in "${thread_counts[@]}"; do
        echo -n "Running test with matrix size ${size}x${size} using ${threads} threads: "
        run_matrix_test $size $threads
    done
    echo ""
done

# Clean up
rm -f matrix_mult.py

echo "CPU scaling test completed at $(date)"
EOF

# Create I/O performance test job
cat > io_test.sh << 'EOF'
#!/bin/bash
#SBATCH --job-name=io_test
#SBATCH --output=io_test_%j.out
#SBATCH --error=io_test_%j.err
#SBATCH --nodes=1
#SBATCH --time=00:30:00

echo "Starting I/O performance test at $(date)"
echo "Running on host $(hostname)"

# Define test directories
LOG_VOLUME="/mnt/log_volume/io_test"
COMMON_VOLUME="/mnt/common_volume/io_test"

# Function to run I/O test
run_io_test() {
    local dir=$1
    local name=$2
    local size=$3 # in MB
    
    mkdir -p $dir
    
    echo "Running $name I/O tests ($size MB)"
    echo "============================"
    
    # Sequential write
    echo "Sequential write test:"
    dd if=/dev/zero of=$dir/test_file bs=1M count=$size conv=fdatasync 2>&1 | grep -E 'copied|s,'
    sync
    
    # Sequential read
    echo "Sequential read test:"
    dd if=$dir/test_file of=/dev/null bs=1M count=$size 2>&1 | grep -E 'copied|s,'
    
    # Random I/O using fio if available
    if command -v fio &> /dev/null; then
        echo "Random read/write test with fio:"
        fio --name=random-rw --ioengine=posixaio --rw=randrw --bs=4k --size=${size}M \
            --numjobs=1 --iodepth=16 --runtime=10 --time_based --filename=$dir/fio_test \
            --direct=1 --group_reporting
    else
        echo "fio not installed, skipping random I/O tests"
    fi
    
    # Clean up
    rm -f $dir/test_file $dir/fio_test
    echo ""
}

# Install fio if available in repo
echo "Checking for fio..."
if ! command -v fio &> /dev/null; then
    echo "Attempting to install fio..."
    dnf install -y fio || echo "Could not install fio, will skip random I/O tests"
fi

# Run tests on log volume
if [ -d "/mnt/log_volume" ]; then
    run_io_test "$LOG_VOLUME" "Log Volume" 1024
else
    echo "Log volume not mounted, skipping test"
fi

# Run tests on common volume
if [ -d "/mnt/common_volume" ]; then
    run_io_test "$COMMON_VOLUME" "Common Volume" 1024
else
    echo "Common volume not mounted, skipping test"
fi

# Get compute node specific volume based on hostname
NODE=$(hostname)
if [[ "$NODE" =~ compute ]]; then
    NODE_NUM=${NODE#compute}
    COMPUTE_VOLUME="/mnt/compute${NODE_NUM}_volume/io_test"
    
    if [ -d "/mnt/compute${NODE_NUM}_volume" ]; then
        run_io_test "$COMPUTE_VOLUME" "Compute ${NODE_NUM} Volume" 1024
    else
        echo "Compute volume not mounted, skipping test"
    fi
fi

echo "I/O performance test completed at $(date)"
EOF

# Create memory bandwidth test job
cat > memory_test.sh << 'EOF'
#!/bin/bash
#SBATCH --job-name=memory_test
#SBATCH --output=memory_test_%j.out
#SBATCH --error=memory_test_%j.err
#SBATCH --nodes=1
#SBATCH --time=00:30:00

echo "Starting memory bandwidth test at $(date)"
echo "Running on host $(hostname)"

# Create STREAM benchmark
cat > stream.c << 'EOL'
/*-----------------------------------------------------------------------*/
/* Program: STREAM                                                       */
/* Revision: $Id: stream.c,v 5.10 2013/01/17 16:01:06 mccalpin Exp mccalpin $ */
/* Original code developed by John D. McCalpin                           */
/* Programmers: John D. McCalpin                                         */
/*              Joe R. Zagar                                             */
/*                                                                       */
/* This program measures memory transfer rates in MB/s for simple        */
/* computational kernels coded in C.                                     */
/*-----------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <float.h>
#include <limits.h>
#include <sys/time.h>

/*-----------------------------------------------------------------------
 * INSTRUCTIONS:
 *
 *	1) STREAM requires different amounts of memory to run on different
 *           systems, depending on both the system cache size(s) and the
 *           granularity of the system timer.
 *     You should adjust the value of 'STREAM_ARRAY_SIZE' (below)
 *           to meet *both* of the following criteria:
 *       (a) Each array must be at least 4 times the size of the
 *           available cache memory. I don't worry about the difference
 *           between 10^6 and 2^20, so in practice the minimum array size
 *           is about 3.8 times the cache size.
 *           Example 1: One Xeon E3 with 8 MB L3 cache
 *               STREAM_ARRAY_SIZE should be >= 30 million, giving
 *               each array 240 MB. This is much larger than needed.
 *           Example 2: Two Xeon E5's with 20 MB L3 cache each (total 40 MB)
 *               STREAM_ARRAY_SIZE should be >= 120 million, giving
 *               each array 960 MB. This is much larger than needed.
 *       (b) The size should be large enough so that the 'timing calibration'
 *           output by the program is at least 20 clock-ticks.
 *           Example: most versions of Windows have a 10 millisecond timer
 *                granularity. 20 "ticks" at 10 ms/tic is 200 milliseconds.
 *                If the chip is capable of 10 GB/s, it moves 2 GB in 200 msec.
 *                This means the each array must be at least 1 GB, or 128M elements.
 *
 *      Version 5.10 increases the default array size from 2 million
 *          elements to 10 million elements in response to the increasing
 *          size of L3 caches.  The new default size is large enough for caches
 *          up to 20 MB.
 *      Version 5.10 changes the loop index variables from "register int"
 *          to "ssize_t", which allows array indices >2^32 (4 billion)
 *          on properly configured 64-bit systems.  Additional compiler options
 *          (such as "-mcmodel=medium") may be required for large memory runs.
 *
 *      The printout specifies the array size used, the number of iterations
 *          performed, and the time in milliseconds that each of the four
 *          kernels (Copy, Scale, Add, Triad) required per iteration.
 *
 *      Array size:     25 million elements (each array), or about 191 MB.
 *      Each kernel is executed 10 times.
 */

#ifndef STREAM_ARRAY_SIZE
#   define STREAM_ARRAY_SIZE	20000000
#endif

#ifndef NTIMES
#   define NTIMES	10
#endif

/* OFFSET is the distance between two data elements in the arrays
   for the copy and scalar operations. Good values are 8 to 64, which
   allow operations on vectors of length 8 to 64 to be promoted by the
   compiler. Beyond 64, unrolling becomes important but the unrolling
   length rarely exceeds 128 elements. */
#ifndef OFFSET
#   define OFFSET	8
#endif

#ifndef MIN
#   define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#   define MAX(a,b) ((a)>(b)?(a):(b))
#endif

static double   a[STREAM_ARRAY_SIZE+OFFSET],
                b[STREAM_ARRAY_SIZE+OFFSET],
                c[STREAM_ARRAY_SIZE+OFFSET];

static double   avgtime[4] = {0}, maxtime[4] = {0},
                mintime[4] = {FLT_MAX,FLT_MAX,FLT_MAX,FLT_MAX};

static char *label[4] = {"Copy:      ", "Scale:     ", "Add:       ", "Triad:     "};

static double   bytes[4] = {
    2 * sizeof(double) * STREAM_ARRAY_SIZE,
    2 * sizeof(double) * STREAM_ARRAY_SIZE,
    3 * sizeof(double) * STREAM_ARRAY_SIZE,
    3 * sizeof(double) * STREAM_ARRAY_SIZE
};

extern double mysecond();
extern void checkSTREAMresults();

int main()
{
    int         quantum, checktick();
    int         BytesPerWord;
    int         k;
    ssize_t     j;
    double      scalar;
    double      t, times[4][NTIMES];

    /* --- SETUP --- determine precision and check timing --- */

    printf(STREAM_VERSION"\n");
    BytesPerWord = sizeof(double);
    printf("This system uses %d bytes per array element.\n", BytesPerWord);

    printf(HLINE);
    printf("Array size = %llu (elements), Offset = %d (elements)\n" , (unsigned long long) STREAM_ARRAY_SIZE, OFFSET);
    printf("Memory per array = %.1f MiB (= %.1f GiB).\n", 
	BytesPerWord * ( (double) STREAM_ARRAY_SIZE / 1024.0/1024.0),
	BytesPerWord * ( (double) STREAM_ARRAY_SIZE / 1024.0/1024.0/1024.0));
    printf("Total memory required = %.1f MiB (= %.1f GiB).\n",
	(3.0 * BytesPerWord) * ( (double) STREAM_ARRAY_SIZE / 1024.0/1024.),
	(3.0 * BytesPerWord) * ( (double) STREAM_ARRAY_SIZE / 1024.0/1024./1024.));
    printf("Each kernel will be executed %d times.\n", NTIMES);
    printf(" The *best* time for each kernel (excluding the first iteration)\n"); 
    printf(" will be used to compute the reported bandwidth.\n");

    /* Get initial value for system clock. */
    for (j=0; j<STREAM_ARRAY_SIZE; j++) {
	    a[j] = 1.0;
	    b[j] = 2.0;
	    c[j] = 0.0;
	}

    printf(HLINE);

    if  ( (quantum = checktick()) >= 1) 
	printf("Your clock granularity/precision appears to be %d microseconds.\n", quantum);
    else {
	printf("Your clock granularity appears to be less than 1 microsecond.\n");
	quantum = 1;
    }

    t = mysecond();
    for (j = 0; j < STREAM_ARRAY_SIZE; j++)
	    a[j] = 2.0E0 * a[j];
    t = 1.0E6 * (mysecond() - t);

    printf("Each test below will take on the order"
	" of %d microseconds.\n", (int) t  );
    printf("   (= %d clock ticks)\n", (int) (t/quantum) );
    printf("Increase the size of the arrays if this shows that\n");
    printf("you are not getting at least 20 clock ticks per test.\n");

    printf(HLINE);

    printf("WARNING -- The above is only a rough guideline.\n");
    printf("For best results, please be sure you know the\n");
    printf("precision of your system timer.\n");
    printf(HLINE);
    
    /* --- MAIN LOOP --- repeat test cases NTIMES times --- */

    scalar = 3.0;
    for (k=0; k<NTIMES; k++)
	{
	times[0][k] = mysecond();
	for (j=0; j<STREAM_ARRAY_SIZE; j++)
	    c[j] = a[j];
	times[0][k] = mysecond() - times[0][k];
	
	times[1][k] = mysecond();
	for (j=0; j<STREAM_ARRAY_SIZE; j++)
	    b[j] = scalar*c[j];
	times[1][k] = mysecond() - times[1][k];
	
	times[2][k] = mysecond();
	for (j=0; j<STREAM_ARRAY_SIZE; j++)
	    c[j] = a[j]+b[j];
	times[2][k] = mysecond() - times[2][k];
	
	times[3][k] = mysecond();
	for (j=0; j<STREAM_ARRAY_SIZE; j++)
	    a[j] = b[j]+scalar*c[j];
	times[3][k] = mysecond() - times[3][k];
	}

    /* --- SUMMARY --- */

    for (k=1; k<NTIMES; k++) /* note -- skip first iteration */
	{
	for (j=0; j<4; j++)
	    {
	    avgtime[j] = avgtime[j] + times[j][k];
	    mintime[j] = MIN(mintime[j], times[j][k]);
	    maxtime[j] = MAX(maxtime[j], times[j][k]);
	    }
	}
    
    printf("Function    Best Rate MB/s  Avg time     Min time     Max time\n");
    for (j=0; j<4; j++) {
	avgtime[j] = avgtime[j]/(double)(NTIMES-1);

	printf("%s%12.1f  %11.6f  %11.6f  %11.6f\n", label[j],
	       1.0E-06 * bytes[j]/mintime[j],
	       avgtime[j],
	       mintime[j],
	       maxtime[j]);
    }
    printf(HLINE);

    /* --- Check Results --- */
    checkSTREAMresults();
    printf(HLINE);

    return 0;
}

# Check timing

int checktick()
{
    int i, minDelta, Delta;
    double t1, t2, timesfound[20];

    /* Collect a sequence of M unique times (1 <= M <= 20) */
    int M = 0;
    minDelta = 1000000;
    t1 = mysecond();
    while (M < 20) {
    t2 = mysecond();
    if (t2 - t1 > 1e-6) {
        timesfound[M] = t2;
        M++;
        t1 = t2;
    }
    }

    /* Compute minimum of all detected */
    for (i = 1; i < M; i++) {
    Delta = (int) (1.0E6 * (timesfound[i] - timesfound[i-1]));
    minDelta = MIN(minDelta, MAX(Delta,0));
    }

    return(minDelta);
}

#define HLINE "-------------------------------------------------------------\n"

/* Timer function */
double mysecond()
{
    struct timeval tp;
    struct timezone tzp;
    int i;

    i = gettimeofday(&tp,&tzp);
    return ( (double) tp.tv_sec + (double) tp.tv_usec * 1.e-6 );
}

#define M 20

/* Check results */
void checkSTREAMresults ()
{
    double ai, bi, ci, scalar;
    double aSumErr, bSumErr, cSumErr;
    double aAvgErr, bAvgErr, cAvgErr;
    double epsilon;
    ssize_t j;
    int k, ierr, err;

    /* Compute reproduction of initialization values */
    aj = 1.0;
    bj = 2.0;
    cj = 0.0;
    /* Use the same scalar as the main loop */
    scalar = 3.0;

    /* Reproduce values for subsequent iterations */
    for (k=0; k<NTIMES; k++)
    {
        cj = aj;
        bj = scalar*cj;
        cj = aj+bj;
        aj = bj+scalar*cj;
    }

    /* Compute errors for each element */
    aSumErr = 0.0;
    bSumErr = 0.0;
    cSumErr = 0.0;
    for (j=0; j<STREAM_ARRAY_SIZE; j++) {
        aSumErr += abs(a[j] - aj);
        bSumErr += abs(b[j] - bj);
        cSumErr += abs(c[j] - cj);
    }
    aAvgErr = aSumErr / (double) STREAM_ARRAY_SIZE;
    bAvgErr = bSumErr / (double) STREAM_ARRAY_SIZE;
    cAvgErr = cSumErr / (double) STREAM_ARRAY_SIZE;

    /* Errors may accumulate over multiple iterations */
    epsilon = 1.e-13;

    err = 0;
    if (abs(aAvgErr/aj) > epsilon) {
        err++;
        printf ("Failed Validation on array a, AvgRelAbsErr > %e\n",epsilon);
        printf ("     Expected Value: %e, AvgAbsErr: %e, AvgRelAbsErr: %e\n",aj,aAvgErr,abs(aAvgErr)/aj);
        ierr = 0;
        for (j=0; j<STREAM_ARRAY_SIZE; j++) {
            if (abs(a[j]/aj-1.0) > epsilon) {
                ierr++;
                if (ierr < 10) {
                    printf("         array a: index: %ld, expected: %e, observed: %e, relative error: %e\n",
                        j,aj,a[j],abs((aj-a[j])/aAvgErr));
                }
            }
        }
        printf("     For array a, %d errors were found.\n",ierr);
    }
    if (abs(bAvgErr/bj) > epsilon) {
        err++;
        printf ("Failed Validation on array b, AvgRelAbsErr > %e\n",epsilon);
        printf ("     Expected Value: %e, AvgAbsErr: %e, AvgRelAbsErr: %e\n",bj,bAvgErr,abs(bAvgErr)/bj);
        ierr = 0;
        for (j=0; j<STREAM_ARRAY_SIZE; j++) {
            if (abs(b[j]/bj-1.0) > epsilon) {
                ierr++;
                if (ierr < 10) {
                    printf("         array b: index: %ld, expected: %e, observed: %e, relative error: %e\n",
                        j,bj,b[j],abs((bj-b[j])/bAvgErr));
                }
            }
        }
        printf("     For array b, %d errors were found.\n",ierr);
    }
    if (abs(cAvgErr/cj) > epsilon) {
        err++;
        printf ("Failed Validation on array c, AvgRelAbsErr > %e\n",epsilon);
        printf ("     Expected Value: %e, AvgAbsErr: %e, AvgRelAbsErr: %e\n",cj,cAvgErr,abs(cAvgErr)/cj);
        ierr = 0;
        for (j=0; j<STREAM_ARRAY_SIZE; j++) {
            if (abs(c[j]/cj-1.0) > epsilon) {
                ierr++;
                if (ierr < 10) {
                    printf("         array c: index: %ld, expected: %e, observed: %e, relative error: %e\n",
                        j,cj,c[j],abs((cj-c[j])/cAvgErr));
                }
            }
        }
        printf("     For array c, %d errors were found.\n",ierr);
    }
    if (err == 0) {
        printf ("Solution Validates: avg error less than %e on all three arrays\n",epsilon);
    }
}
EOL

# Compile STREAM benchmark
gcc -O3 -fopenmp stream.c -o stream -lm

# Run with different thread counts
export OMP_PROC_BIND=true

echo "Running STREAM memory bandwidth benchmark with various thread counts"
echo "=================================================================="

for threads in 1 2 4 8 16; do
    echo "Running with $threads threads:"
    export OMP_NUM_THREADS=$threads
    ./stream
    echo ""
done

# Clean up
rm -f stream stream.c

echo "Memory bandwidth test completed at $(date)"
EOF

# Create a network bandwidth test
cat > network_test.sh << 'EOF'
#!/bin/bash
#SBATCH --job-name=network_test
#SBATCH --output=network_test_%j.out
#SBATCH --error=network_test_%j.err
#SBATCH --nodes=2
#SBATCH --ntasks=2
#SBATCH --ntasks-per-node=1
#SBATCH --time=00:30:00

echo "Starting network bandwidth test at $(date)"

# Create list of nodes
NODES=$(scontrol show hostnames $SLURM_JOB_NODELIST)
NODE_ARRAY=($NODES)

if [ ${#NODE_ARRAY[@]} -lt 2 ]; then
    echo "Error: This test requires at least 2 nodes"
    exit 1
fi

SERVER_NODE=${NODE_ARRAY[0]}
CLIENT_NODE=${NODE_ARRAY[1]}

echo "Server node: $SERVER_NODE"
echo "Client node: $CLIENT_NODE"

# Check if iperf3 is installed, install if not
if ! command -v iperf3 &> /dev/null; then
    echo "iperf3 not found, attempting to install..."
    dnf install -y iperf3 || { echo "Failed to install iperf3, aborting test"; exit 1; }
fi

# Function to run iperf3 test
run_iperf_test() {
    local protocol=$1
    local threads=$2
    local window=$3
    local time=$4
    
    echo "Running ${protocol^^} test with $threads threads and $window window size for $time seconds"
    
    # Start server on the first node
    srun --nodes=1 --ntasks=1 -w $SERVER_NODE iperf3 -s -1 -D
    
    # Wait for server to start
    sleep 2
    
    # Run client on the second node
    if [ "$protocol" = "tcp" ]; then
        srun --nodes=1 --ntasks=1 -w $CLIENT_NODE iperf3 -c $SERVER_NODE -P $threads -w $window -t $time -J | \
            python3 -c "import sys, json; data = json.load(sys.stdin); print(f'Result: {data[\"end\"][\"sum_received\"][\"bits_per_second\"]/1e9:.2f} Gbps')"
    else
        srun --nodes=1 --ntasks=1 -w $CLIENT_NODE iperf3 -c $SERVER_NODE -u -P $threads -w $window -t $time -b 0 -J | \
            python3 -c "import sys, json; data = json.load(sys.stdin); print(f'Result: {data[\"end\"][\"sum\"][\"bits_per_second\"]/1e9:.2f} Gbps')"
    fi
    
    # Kill any leftover iperf3 servers
    srun --nodes=1 --ntasks=1 -w $SERVER_NODE pkill -f "iperf3 -s" || true
    
    echo ""
}

echo "================================================================"
echo "Network Bandwidth Tests"
echo "================================================================"

# Run TCP tests with different parameters
echo "TCP Tests:"
run_iperf_test tcp 1 256K 10
run_iperf_test tcp 4 256K 10
run_iperf_test tcp 8 256K 10

# Run UDP tests with different parameters
echo "UDP Tests:"
run_iperf_test udp 1 256K 10
run_iperf_test udp 4 256K 10

# Test MPI point-to-point bandwidth
echo "================================================================"
echo "MPI Point-to-Point Bandwidth Test"
echo "================================================================"

# Create simple MPI bandwidth test
cat > mpi_bandwidth.c << 'EOL'
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MSG_SIZE (1<<22)  /* 4 MB */
#define ITERATIONS 100
#define SKIP 10

int main(int argc, char *argv[]) {
    int rank, size, i, j;
    double t_start, t_end, t_total;
    char *send_buf, *recv_buf;
    MPI_Status status;
    
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    
    if (size != 2) {
        if (rank == 0) {
            fprintf(stderr, "This test requires exactly 2 MPI processes\n");
        }
        MPI_Finalize();
        exit(1);
    }
    
    /* Allocate memory for buffers */
    send_buf = (char*)malloc(MAX_MSG_SIZE);
    recv_buf = (char*)malloc(MAX_MSG_SIZE);
    
    if (send_buf == NULL || recv_buf == NULL) {
        fprintf(stderr, "Error allocating memory\n");
        MPI_Finalize();
        exit(1);
    }
    
    /* Initialize buffer */
    memset(send_buf, 'a', MAX_MSG_SIZE);
    
    if (rank == 0) {
        printf("Message Size (bytes)   Bandwidth (MB/s)\n");
        printf("------------------------------------\n");
    }
    
    /* Loop over message sizes */
    for (int msg_size = 1; msg_size <= MAX_MSG_SIZE; msg_size *= 2) {
        /* Warm-up */
        for (i = 0; i < SKIP; i++) {
            if (rank == 0) {
                MPI_Send(send_buf, msg_size, MPI_CHAR, 1, 0, MPI_COMM_WORLD);
                MPI_Recv(recv_buf, msg_size, MPI_CHAR, 1, 0, MPI_COMM_WORLD, &status);
            } else {
                MPI_Recv(recv_buf, msg_size, MPI_CHAR, 0, 0, MPI_COMM_WORLD, &status);
                MPI_Send(send_buf, msg_size, MPI_CHAR, 0, 0, MPI_COMM_WORLD);
            }
        }
        
        MPI_Barrier(MPI_COMM_WORLD);
        t_start = MPI_Wtime();
        
        /* Ping-pong test */
        for (i = 0; i < ITERATIONS; i++) {
            if (rank == 0) {
                MPI_Send(send_buf, msg_size, MPI_CHAR, 1, 0, MPI_COMM_WORLD);
                MPI_Recv(recv_buf, msg_size, MPI_CHAR, 1, 0, MPI_COMM_WORLD, &status);
            } else {
                MPI_Recv(recv_buf, msg_size, MPI_CHAR, 0, 0, MPI_COMM_WORLD, &status);
                MPI_Send(send_buf, msg_size, MPI_CHAR, 0, 0, MPI_COMM_WORLD);
            }
        }
        
        t_end = MPI_Wtime();
        t_total = t_end - t_start;
        
        /* Convert to bandwidth */
        if (rank == 0) {
            double bandwidth = (msg_size / 1e6) * ITERATIONS * 2 / t_total;
            printf("%10d %20.2f\n", msg_size, bandwidth);
        }
        
        MPI_Barrier(MPI_COMM_WORLD);
    }
    
    free(send_buf);
    free(recv_buf);
    
    MPI_Finalize();
    return 0;
}
EOL

# Load MPI module
module load mpi/openmpi-4.1.5

# Compile and run MPI bandwidth test
mpicc -o mpi_bandwidth mpi_bandwidth.c
srun --nodes=2 --ntasks=2 --ntasks-per-node=1 ./mpi_bandwidth

# Clean up
rm -f mpi_bandwidth mpi_bandwidth.c

echo "Network bandwidth test completed at $(date)"
EOF

# Set permissions for all scripts
chmod +x basic_job.sh mpi_job.sh array_job.sh resource_job.sh cpu_scaling_test.sh io_test.sh memory_test.sh network_test.sh
chown -R hpcuser:hpcuser /home/hpcuser/job_examples

# Create README file
cat > /home/hpcuser/job_examples/README.md << 'EOF'
# HPC Job Script Examples

This directory contains example job scripts for Slurm HPC cluster.

## Available Examples

1. **basic_job.sh** - Basic single-task job
2. **mpi_job.sh** - MPI job running across multiple nodes
3. **array_job.sh** - Job array demonstration
4. **resource_job.sh** - Job with specific resource constraints
5. **cpu_scaling_test.sh** - CPU performance scaling test with matrix multiplication
6. **io_test.sh** - I/O performance test on different storage volumes
7. **memory_test.sh** - Memory bandwidth test using STREAM benchmark
8. **network_test.sh** - Network bandwidth test between nodes

## Performance Testing

The performance testing scripts can be used to validate and benchmark your HPC cluster:

- **CPU Performance**: The `cpu_scaling_test.sh` script tests CPU performance scaling with different thread counts and problem sizes using NumPy matrix multiplication.
- **I/O Performance**: The `io_test.sh` script tests sequential and random I/O performance on all mounted volumes.
- **Memory Bandwidth**: The `memory_test.sh` script uses the STREAM benchmark to measure memory bandwidth with different thread counts.
- **Network Bandwidth**: The `network_test.sh` script uses iperf3 and MPI to measure network bandwidth between nodes.

## How to Submit Jobs

Submit a job using:
```
sbatch job_script.sh
```

Check job status:
```
squeue
```

Cancel a job:
```
scancel JOB_ID
```

## Common Slurm Commands

- `sinfo` - View information about Slurm nodes and partitions
- `squeue` - View information about jobs in the queue
- `scancel` - Cancel jobs
- `scontrol show job JOB_ID` - View detailed job information
- `sacct` - View accounting information for jobs

## Interpreting Results

After running the performance tests, you should expect:

- **CPU Tests**: Higher performance with more threads up to the physical core count
- **I/O Tests**: Sequential performance typically higher than random I/O
- **Memory Tests**: STREAM Copy/Scale/Add/Triad should scale with memory bandwidth
- **Network Tests**: Performance should approach the theoretical limits of your interconnect

For more information, refer to the Slurm documentation or run `man sbatch`.
EOF

# Copy examples to compute nodes
for NODE in compute01 compute02 compute03; do
  scp -r /home/hpcuser/job_examples root@$NODE:/home/hpcuser/
  ssh root@$NODE "chown -R hpcuser:hpcuser /home/hpcuser/job_examples"
done

echo "Job script examples library created with performance testing scripts"
```

## 5. Monitoring Tools Setup

### 5.1 Install and Configure Slurm Exporter

```bash
#!/bin/bash
# File: install_slurm_exporter.sh

# Define the Slurm exporter version and installation directory
SLURM_EXPORTER_VERSION="0.20"
INSTALL_DIR="/opt/slurm_exporter"

# Create installation directory
mkdir -p $INSTALL_DIR

# Install required packages
dnf install -y git golang

# Clone the repository and build the exporter
cd /tmp
git clone https://github.com/vpenso/prometheus-slurm-exporter.git
cd prometheus-slurm-exporter
git checkout $SLURM_EXPORTER_VERSION

# Build the exporter
make build
cp prometheus-slurm-exporter $INSTALL_DIR/

# Create a systemd service file
cat > /etc/systemd/system/slurm-exporter.service << 'EOF'
[Unit]
Description=Prometheus Slurm Exporter
After=network.target slurmctld.service

[Service]
Type=simple
User=slurm
ExecStart=/opt/slurm_exporter/prometheus-slurm-exporter
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Set correct permissions
chown -R slurm:slurm $INSTALL_DIR
chmod +x $INSTALL_DIR/prometheus-slurm-exporter

# Enable and start the service
systemctl daemon-reload
systemctl enable slurm-exporter
systemctl start slurm-exporter

# Update Prometheus configuration to include Slurm exporter
cat >> /etc/prometheus/prometheus.yml << 'EOF'

  - job_name: 'slurm'
    static_configs:
    - targets: ['controller:8080']
EOF

# Restart Prometheus to apply changes
systemctl restart prometheus

# Create a basic Slurm dashboard for Grafana
cat > slurm_dashboard.json << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "Slurm Cluster Dashboard",
    "tags": ["slurm"],
    "timezone": "browser",
    "schemaVersion": 16,
    "version": 0,
    "refresh": "30s",
    "panels": [
      {
        "title": "Cluster Utilization",
        "type": "gauge",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "slurm_cpus_alloc / slurm_cpus_total * 100",
            "refId": "A"
          }
        ],
        "options": {
          "orientation": "auto",
          "showThresholdLabels": false,
          "showThresholdMarkers": true
        },
        "fieldConfig": {
          "defaults": {
            "mappings": [],
            "max": 100,
            "min": 0,
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {
                  "color": "green",
                  "value": null
                },
                {
                  "color": "orange",
                  "value": 70
                },
                {
                  "color": "red",
                  "value": 90
                }
              ]
            },
            "unit": "percent"
          }
        },
        "gridPos": {
          "h": 8,
          "w": 8,
          "x": 0,
          "y": 0
        }
      },
      {
        "title": "Running Jobs",
        "type": "stat",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "slurm_jobs_running",
            "refId": "A"
          }
        ],
        "options": {
          "colorMode": "value",
          "graphMode": "area",
          "justifyMode": "auto",
          "orientation": "auto",
          "reduceOptions": {
            "calcs": ["mean"],
            "fields": "",
            "values": false
          },
          "textMode": "auto"
        },
        "fieldConfig": {
          "defaults": {
            "mappings": [],
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {
                  "color": "green",
                  "value": null
                }
              ]
            }
          }
        },
        "gridPos": {
          "h": 8,
          "w": 8,
          "x": 8,
          "y": 0
        }
      },
      {
        "title": "Pending Jobs",
        "type": "stat",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "slurm_jobs_pending",
            "refId": "A"
          }
        ],
        "options": {
          "colorMode": "value",
          "graphMode": "area",
          "justifyMode": "auto",
          "orientation": "auto",
          "reduceOptions": {
            "calcs": ["mean"],
            "fields": "",
            "values": false
          },
          "textMode": "auto"
        },
        "fieldConfig": {
          "defaults": {
            "mappings": [],
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {
                  "color": "green",
                  "value": null
                },
                {
                  "color": "orange",
                  "value": 5
                },
                {
                  "color": "red",
                  "value": 10
                }
              ]
            }
          }
        },
        "gridPos": {
          "h": 8,
          "w": 8,
          "x": 16,
          "y": 0
        }
      },
      {
        "title": "Node Status",
        "type": "stat",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "slurm_nodes_alloc",
            "refId": "A",
            "legendFormat": "Allocated"
          },
          {
            "expr": "slurm_nodes_idle",
            "refId": "B",
            "legendFormat": "Idle"
          },
          {
            "expr": "slurm_nodes_down",
            "refId": "C",
            "legendFormat": "Down"
          }
        ],
        "options": {
          "colorMode": "value",
          "graphMode": "none",
          "justifyMode": "auto",
          "orientation": "horizontal",
          "reduceOptions": {
            "calcs": ["lastNotNull"],
            "fields": "",
            "values": false
          },
          "text": {},
          "textMode": "auto"
        },
        "fieldConfig": {
          "defaults": {
            "mappings": [],
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {
                  "color": "green",
                  "value": null
                }
              ]
            }
          },
          "overrides": [
            {
              "matcher": {
                "id": "byName",
                "options": "Down"
              },
              "properties": [
                {
                  "id": "color",
                  "value": {
                    "fixedColor": "red",
                    "mode": "fixed"
                  }
                }
              ]
            }
          ]
        },
        "gridPos": {
          "h": 8,
          "w": 12,
          "x": 0,
          "y": 8
        }
      },
      {
        "title": "Jobs By Partition",
        "type": "bargauge",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "sum by (partition) (slurm_job_partition)",
            "refId": "A",
            "legendFormat": "{{partition}}"
          }
        ],
        "options": {
          "displayMode": "gradient",
          "orientation": "horizontal",
          "reduceOptions": {
            "calcs": ["lastNotNull"],
            "fields": "",
            "values": false
          },
          "showUnfilled": true,
          "text": {}
        },
        "fieldConfig": {
          "defaults": {
            "mappings": [],
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {
                  "color": "green",
                  "value": null
                },
                {
                  "color": "orange",
                  "value": 10
                },
                {
                  "color": "red",
                  "value": 20
                }
              ]
            }
          }
        },
        "gridPos": {
          "h": 8,
          "w": 12,
          "x": 12,
          "y": 8
        }
      }
    ]
  },
  "overwrite": false
}
EOF

echo "To import the Slurm dashboard into Grafana, please:"
echo "1. Log into Grafana at http://controller:3000/"
echo "2. Go to Dashboard > Import and upload the slurm_dashboard.json file"

echo "Slurm exporter has been installed and configured"
```

### 5.2 Install Prometheus and Node Exporter

```bash
#!/bin/bash
# File: install_prometheus.sh

# Define versions
PROMETHEUS_VERSION="2.46.0"
NODE_EXPORTER_VERSION="1.6.1"

# Download and install Prometheus on controller
cd /tmp
wget https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz
tar -xvf prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz
cd prometheus-${PROMETHEUS_VERSION}.linux-amd64

# Create directories
mkdir -p /opt/prometheus/data
mkdir -p /etc/prometheus

# Copy binaries and configuration
cp prometheus promtool /usr/local/bin/
cp -r consoles/ console_libraries/ /etc/prometheus/
cp prometheus.yml /etc/prometheus/

# Configure Prometheus
cat > /etc/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval:     15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
  - static_configs:
    - targets:
      # - alertmanager:9093

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
    - targets: ['localhost:9090']

  - job_name: 'node_exporters'
    static_configs:
    - targets: ['controller:9100', 'compute01:9100', 'compute02:9100', 'compute03:9100']
EOF

# Create Prometheus service
cat > /etc/systemd/system/prometheus.service << 'EOF'
[Unit]
Description=Prometheus Time Series Collection and Processing Server
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
    --config.file=/etc/prometheus/prometheus.yml \
    --storage.tsdb.path=/opt/prometheus/data \
    --web.console.templates=/etc/prometheus/consoles \
    --web.console.libraries=/etc/prometheus/console_libraries

[Install]
WantedBy=multi-user.target
EOF

# Create prometheus user
useradd --no-create-home --shell /bin/false prometheus

# Set ownership
chown -R prometheus:prometheus /etc/prometheus /opt/prometheus /usr/local/bin/{prometheus,promtool}

# Install Node Exporter on controller
cd /tmp
wget https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz
tar -xvf node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz
cd node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64
cp node_exporter /usr/local/bin/

# Create Node Exporter service
cat > /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
EOF

# Create node_exporter user
useradd --no-create-home --shell /bin/false node_exporter
chown node_exporter:node_exporter /usr/local/bin/node_exporter

# Enable and start services
systemctl daemon-reload
systemctl enable prometheus
systemctl start prometheus
systemctl enable node_exporter
systemctl start node_exporter

# Create script for Node Exporter deployment to compute nodes
cat > deploy_node_exporter.sh << 'EOF'
#!/bin/bash

# Download and install Node Exporter
cd /tmp
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
tar -xvf node_exporter-1.6.1.linux-amd64.tar.gz
cd node_exporter-1.6.1.linux-amd64
cp node_exporter /usr/local/bin/

# Create Node Exporter service
cat > /etc/systemd/system/node_exporter.service << 'EOL'
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
EOL

# Create node_exporter user
useradd --no-create-home --shell /bin/false node_exporter
chown node_exporter:node_exporter /usr/local/bin/node_exporter

# Enable and start service
systemctl daemon-reload
systemctl enable node_exporter
systemctl start node_exporter
EOF

# Deploy Node Exporter to compute nodes
for NODE in compute01 compute02 compute03; do
  scp deploy_node_exporter.sh root@$NODE:/tmp/
  ssh root@$NODE "bash /tmp/deploy_node_exporter.sh"
done

# Clean up
rm deploy_node_exporter.sh

echo "Prometheus and Node Exporter installed and configured"
```

### 5.2 Install Grafana

```bash
#!/bin/bash
# File: install_grafana.sh

# Add Grafana repository
cat > /etc/yum.repos.d/grafana.repo << 'EOF'
[grafana]
name=grafana
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
EOF

# Install Grafana
dnf install -y grafana

# Enable and start Grafana
systemctl daemon-reload
systemctl enable grafana-server
systemctl start grafana-server

echo "Grafana installed and configured at http://controller:3000/ (default login: admin/admin)"
```

## 6. System Performance Tuning

### 6.1 Configure System Tuning

```bash
#!/bin/bash
# File: system_tuning.sh

# Create sysctl configuration for HPC
cat > /etc/sysctl.d/99-hpc-performance.conf << 'EOF'
# Increase system limits
kernel.pid_max = 4194303
fs.file-max = 26214400

# Increase network performance
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Improve network congestion control
net.ipv4.tcp_congestion_control = htcp
net.ipv4.tcp_mtu_probing = 1

# Memory management tweaks
vm.swappiness = 10
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10

# Shared memory settings
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
EOF

# Create limits configuration for HPC users
cat > /etc/security/limits.d/99-hpc-limits.conf << 'EOF'
# Increase resource limits for HPC users
*               soft    nproc           unlimited
*               hard    nproc           unlimited
*               soft    nofile          1048576
*               hard    nofile          1048576
*               soft    stack           unlimited
*               hard    stack           unlimited
*               soft    memlock         unlimited
*               hard    memlock         unlimited
EOF

# Apply tuning to all nodes
for NODE in compute01 compute02 compute03; do
  scp /etc/sysctl.d/99-hpc-performance.conf root@$NODE:/etc/sysctl.d/
  scp /etc/security/limits.d/99-hpc-limits.conf root@$NODE:/etc/security/limits.d/
  ssh root@$NODE "sysctl -p /etc/sysctl.d/99-hpc-performance.conf"
done

# Apply sysctl settings on controller
sysctl -p /etc/sysctl.d/99-hpc-performance.conf

# Create I/O scheduler configuration
for NODE in controller compute01 compute02 compute03; do
  ssh root@$NODE "echo 'ACTION==\"add|change\", KERNEL==\"sd[a-z]\", ATTR{queue/scheduler}=\"deadline\"' > /etc/udev/rules.d/60-scheduler.rules"
  ssh root@$NODE "echo 'ACTION==\"add|change\", KERNEL==\"nvme[0-9]*\", ATTR{queue/scheduler}=\"none\"' >> /etc/udev/rules.d/60-scheduler.rules"
done

echo "System performance tuning configured"
```

## 7. Backup and Security

### 7.1 Configuration Backup Solution

```bash
#!/bin/bash
# File: setup_config_backup.sh

# Create backup directory
mkdir -p /backup/configs

# Create backup script
cat > /root/backup_configs.sh << 'EOF'
#!/bin/bash

# Set backup directory
BACKUP_DIR="/backup/configs"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/hpc-config-backup-${TIMESTAMP}.tar.gz"

# Make sure the backup directory exists
mkdir -p $BACKUP_DIR

# Create a list of important configuration directories and files
cat > /tmp/backup_list.txt << 'EOL'
/etc/slurm/
/etc/ceph/
/etc/munge/
/etc/prometheus/
/etc/grafana/
/etc/systemd/system/slurm*
/etc/systemd/system/ceph*
/etc/systemd/system/munge*
/etc/systemd/system/prometheus*
/etc/systemd/system/grafana*
/etc/systemd/system/node_exporter*
/etc/systemd/system/rbd-mount*
/var/spool/slurm/ctld/
/usr/share/Modules/modulefiles/
/etc/chrony.conf
EOL

# Create the backup
tar -czf $BACKUP_FILE -T /tmp/backup_list.txt

# Clean up
rm /tmp/backup_list.txt

# Keep only the 7 most recent backups
cd $BACKUP_DIR
ls -1t hpc-config-backup-*.tar.gz | tail -n +8 | xargs -r rm

echo "Backup created: $BACKUP_FILE"
EOF

# Make the script executable
chmod +x /root/backup_configs.sh

# Create a cron job to run daily backups
echo "0 1 * * * /root/backup_configs.sh > /var/log/config_backup.log 2>&1" > /etc/cron.d/config_backup
chmod 644 /etc/cron.d/config_backup

# Run initial backup
/root/backup_configs.sh

echo "Configuration backup system configured"
```

### 7.2 Security Hardening

```bash
#!/bin/bash
# File: security_hardening.sh

# SSH hardening
cat > /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
# Disable root login with password
PermitRootLogin prohibit-password

# Disable password authentication
PasswordAuthentication no

# Allow only specific users
AllowUsers root rocky cephadm slurm hpcadmin hpcuser

# Limit authentication attempts
MaxAuthTries 4

# Set session timeout (5 minutes)
ClientAliveInterval 300
ClientAliveCountMax 0
EOF

# Apply SSH configuration to all nodes
for NODE in compute01 compute02 compute03; do
  scp /etc/ssh/sshd_config.d/hardening.conf root@$NODE:/etc/ssh/sshd_config.d/
  ssh root@$NODE "systemctl restart sshd"
done

# Restart SSH service on controller
systemctl restart sshd

# Create a simple firewall configuration script
cat > configure_firewall.sh << 'EOF'
#!/bin/bash

# Install firewalld if not already installed
dnf install -y firewalld

# Start and enable firewalld
systemctl enable firewalld
systemctl start firewalld

# Configure firewall for controller node
if [[ $(hostname) == "controller" ]]; then
  # Allow Slurm ports
  firewall-cmd --permanent --add-port=6817/tcp  # slurmctld
  firewall-cmd --permanent --add-port=6819/tcp  # slurmdbd
  
  # Allow Munge
  firewall-cmd --permanent --add-port=415/tcp   # munge
  
  # Allow SSH
  firewall-cmd --permanent --add-service=ssh
  
  # Allow Ceph ports
  firewall-cmd --permanent --add-port=3300/tcp  # Ceph MON
  firewall-cmd --permanent --add-port=6800-7300/tcp  # Ceph OSD, MGR, MDS
  firewall-cmd --permanent --add-port=9283/tcp  # Ceph Prometheus exporter
  
  # Allow monitoring tools
  firewall-cmd --permanent --add-port=9090/tcp  # Prometheus
  firewall-cmd --permanent --add-port=9100/tcp  # Node Exporter
  firewall-cmd --permanent --add-port=3000/tcp  # Grafana
  
  # Allow Slurm Web
  firewall-cmd --permanent --add-port=80/tcp    # HTTP
  firewall-cmd --permanent --add-port=443/tcp   # HTTPS
  
  # Allow internal network traffic
  firewall-cmd --permanent --add-source=10.10.140.0/24 --zone=trusted
else
  # For compute nodes
  # Allow Slurm ports
  firewall-cmd --permanent --add-port=6818/tcp  # slurmd
  
  # Allow Munge
  firewall-cmd --permanent --add-port=415/tcp   # munge
  
  # Allow SSH
  firewall-cmd --permanent --add-service=ssh
  
  # Allow Ceph ports
  firewall-cmd --permanent --add-port=6800-7300/tcp  # Ceph OSD, MGR, MDS
  
  # Allow monitoring tools
  firewall-cmd --permanent --add-port=9100/tcp  # Node Exporter
  
  # Allow internal network traffic
  firewall-cmd --permanent --add-source=10.10.140.0/24 --zone=trusted
fi

# Reload firewall to apply changes
firewall-cmd --reload

echo "Firewall configured on $(hostname)"
EOF

echo "NOTE: By default, we have disabled firewalld for simplicity."
echo "To implement a more secure configuration with firewalld enabled, run:"
echo "bash configure_firewall.sh"

echo "Security hardening configured"
```

## 8. Testing and Verification

### 8.1 Test Slurm Configuration

```bash
#!/bin/bash
# File: test_slurm.sh

# Check Slurm controller status
systemctl status slurmctld

# Check compute node status
for NODE in compute01 compute02 compute03; do
  ssh root@$NODE "systemctl status slurmd"
done

# Check node status in Slurm
sinfo

# If nodes are down, bring them up
scontrol update nodename=compute01,compute02,compute03 state=resume

# Run a test job
su - hpcuser -c "sbatch -o /mnt/common_volume/test_job.out -N 3 --wrap='srun hostname'"

# Check job status
su - hpcuser -c "squeue"

# Check output (after job completes)
su - hpcuser -c "cat /mnt/common_volume/test_job.out"

echo "Slurm configuration testing completed"
```

### 8.2 Test Ceph RBD Mounts

```bash
#!/bin/bash
# File: test_ceph_mounts.sh

# Check mount points on all nodes
for NODE in controller compute01 compute02 compute03; do
  echo "Checking mounts on $NODE"
  ssh root@$NODE "df -h | grep -E '/mnt/(log|common|compute)'"
  
  # Test write access
  ssh root@$NODE "echo 'Test file from $NODE' > /mnt/log_volume/test_${NODE}.txt"
  ssh root@$NODE "echo 'Test file from $NODE' > /mnt/common_volume/test_${NODE}.txt"
  
  # For compute nodes, test dedicated volumes
  if [[ $NODE =~ compute ]]; then
    NODE_NUM=${NODE#compute}
    ssh root@$NODE "echo 'Test file from $NODE' > /mnt/compute${NODE_NUM}_volume/test_${NODE}.txt"
  fi
done

# Verify files are accessible from all nodes
for NODE in controller compute01 compute02 compute03; do
  echo "Verifying files on $NODE"
  ssh root@$NODE "ls -la /mnt/log_volume/test_*.txt"
  ssh root@$NODE "ls -la /mnt/common_volume/test_*.txt"
done

echo "Ceph RBD mount testing completed"
```

### 8.3 Test OpenMPI with Slurm

```bash
#!/bin/bash
# File: test_openmpi.sh

# Submit the MPI test job as hpcuser
su - hpcuser -c "cd /mnt/common_volume && sbatch /home/hpcuser/mpi_test.sh"

# Check job status
su - hpcuser -c "squeue"

# Wait for job to complete
echo "Waiting for MPI test job to complete..."
sleep 10

# Check the output
su - hpcuser -c "ls -la /mnt/common_volume/mpi_test_*.out"
su - hpcuser -c "cat /mnt/common_volume/mpi_test_*.out"

echo "OpenMPI with Slurm testing completed"
```

## 9. Additional Information and References

### 9.1 User Guide

| User | Purpose | Home Directory |
|------|---------|----------------|
| root | System administration | /root |
| rocky | Initial OS user | /home/rocky |
| cephadm | Ceph administration | /home/cephadm |
| slurm | Slurm workload manager | /home/slurm |
| munge | Authentication for Slurm | /var/lib/munge |
| hpcadmin | HPC administration | /home/hpcadmin |
| hpcuser | Regular user for running jobs | /home/hpcuser |

### 9.2 Storage Layout

| Storage | Size | Mount Point | Purpose |
|---------|------|-------------|---------|
| Log Volume | 1.3 TB | /mnt/log_volume | Common log space on all nodes |
| Compute01 Volume | 2 TB | /mnt/compute01_volume | Dedicated storage for Compute Node 1 |
| Compute02 Volume | 2 TB | /mnt/compute02_volume | Dedicated storage for Compute Node 2 |
| Compute03 Volume | 2 TB | /mnt/compute03_volume | Dedicated storage for Compute Node 3 |
| Common Volume | ~16 TB | /mnt/common_volume | Common storage for job outputs |

### 9.3 Benefits of Using RBD

1. **Performance**:
   - RBD (RADOS Block Device) provides high-performance block storage
   - Direct kernel integration for better I/O performance
   - Uses the RADOS distributed object store for reliability and performance

2. **Scalability**:
   - Scales horizontally with your cluster
   - Can grow or shrink volumes dynamically
   - Supports thin provisioning

3. **Reliability**:
   - Built-in replication for data protection
   - Automatic recovery from node failures
   - Consistent snapshots for backup

4. **Integration**:
   - Native support in the Linux kernel
   - Can be exposed as a block device to any application
   - Works well with virtualization platforms

5. **Alternatives to RBD**:
   - **CephFS**: A POSIX-compliant filesystem that could be used instead of RBD for more traditional file access patterns
   - **NFS**: Could be used for simpler setups but lacks the performance and reliability of RBD
   - **GlusterFS**: Another distributed filesystem, but Ceph generally provides better performance for HPC workloads

### 9.4 Accessing the Services

- **Slurm Commands**: Use standard Slurm commands (sbatch, srun, squeue, etc.)
- **Slurm Web Interface**: http://controller/ (set up in section 3.4)
- **Grafana Dashboard**: http://controller:3000/ (default login: admin/admin)
- **Ceph Dashboard**: https://controller:8443/ (credentials set during bootstrap)
- **Prometheus Interface**: http://controller:9090/
- **Node Exporter Metrics**: http://controller:9100/metrics (and similar for compute nodes)
- **Slurm Exporter Metrics**: http://controller:8080/metrics

### 9.5 Advanced Cluster Features

#### MPI Job Profiling and Performance Analysis

For detailed analysis of MPI applications, you can use tools like:

1. **mpiP**: A lightweight MPI profiling library
   ```bash
   # Installation
   dnf install -y gcc-gfortran
   cd /opt
   wget http://mpip.sourceforge.net/download/mpiP-3.5.tar.gz
   tar -xzf mpiP-3.5.tar.gz
   cd mpiP-3.5
   ./configure --with-mpi-include=/opt/openmpi/include --with-mpi-lib=/opt/openmpi/lib
   make
   make install
   
   # Usage example in a job script
   export LD_PRELOAD=/usr/local/lib/libmpiP.so
   export MPIP="-o -f %h/%p.%r.mpiP"
   srun ./your_mpi_application
   ```

2. **Scalasca**: A performance analysis toolset for parallel applications
   ```bash
   # Installation steps would go here
   # Create a module file for Scalasca
   mkdir -p /usr/share/Modules/modulefiles/tools
   cat > /usr/share/Modules/modulefiles/tools/scalasca << 'EOF'
   #%Module1.0
   proc ModulesHelp { } {
     puts stderr "This module loads Scalasca performance analysis tool"
   }
   module-whatis "Scalasca Performance Analysis Tool"
   prepend-path PATH /opt/scalasca/bin
   EOF
   ```

#### Parallel Debuggers

For debugging parallel applications:

```bash
# Install and configure TotalView or Arm DDT
# (Installation steps would be provided here)
# Create appropriate module files
```

#### Advanced Resource Management

To implement resource utilization accounting and fair-share scheduling:

```bash
# Update Slurm configuration for fair-share scheduling
cat >> /etc/slurm/slurm.conf << 'EOF'
PriorityType=priority/multifactor
PriorityDecayHalfLife=14-0
PriorityUsageResetPeriod=NONE
PriorityWeightFairshare=1000
PriorityWeightAge=100
PriorityWeightPartition=1000
PriorityWeightJobSize=1000
PriorityWeightQOS=2000
PriorityMaxAge=7-0
EOF

# Configure QoS levels
sacctmgr add qos normal
sacctmgr add qos high
sacctmgr add qos urgent

# Configure QoS settings
sacctmgr modify qos normal set priority=100
sacctmgr modify qos high set priority=500
sacctmgr modify qos urgent set priority=1000 GrpJobs=10 MaxWall=24:00:00

# Restart slurmctld to apply changes
systemctl restart slurmctld
```

### 9.6 Maintenance Tasks

- **Add a New Node**: Update Slurm configuration, install required software, add to Ceph cluster
- **Resize RBD Volumes**: Use `rbd resize` command
- **Backup Configuration**: Key configuration files are in `/etc/slurm/`, `/etc/ceph/`, and `/etc/prometheus/`
- **System Updates**: Update controller first, then compute nodes one by one
