# Openstack-installation
This repository is used to install the Openstack using Ansible Kolla

## Openstack setup

## Prerequisites

```bash
ssh -l user 10.230.155.12
sudo apt update
sudo apt install git python3-dev libffi-dev gcc libssl-dev python3-pip python3-venv build-essential libdbus-glib-1-dev libgirepository1.0-dev libpython3-dev libdbus-1-dev -y 
mkdir ~/kolla-venv
python3 -m venv ~/kolla-venv
source ~/kolla-venv/bin/activate
pip install -U pip
pip install 'ansible-core>=2.16,<2.17.99' python-docker dbus-python kolla
# pip install 'ansible-core>=2.16,<2.17.99'
pip install git+https://opendev.org/openstack/kolla-ansible@master
sudo mkdir -p /etc/kolla
sudo chown -R $USER:$USER /etc/kolla
cp -r ~/kolla-venv/share/kolla-ansible/etc_examples/kolla/* /etc/kolla
cd kolla-venv/share/kolla-ansible/tools/
./generate_passwords.py
```

## volume group creation

```bash
sudo pvcreate /dev/sda
vgcreate cinder-volumes /dev/sda
```

## Defining Variables

```yaml
workaround_ansible_issue_8743: yes
kolla_base_distro: "ubuntu"
kolla_internal_vip_address: "10.230.155.21"
network_interface: "ens1f0np0"
octavia_network_interface: ens1f0np0
neutron_external_interface: "bond0.820"
enable_cinder: "yes"
enable_cinder_backend_lvm: "yes"
enable_neutron_provider_networks: "yes"
enable_octavia: "yes"
enable_redis: "yes"
neutron_ml2_type_vlan_physical_network: "physnet1"
neutron_external_interface: "bond0.820,bond0.821"
neutron_bridge_name: "br-ex1,br-ex2"
octavia_auto_configure: yes
octavia_certs_country: US
octavia_certs_state: Oregon
octavia_certs_organization: OpenStack
octavia_certs_organizational_unit: Octavia
octavia_amp_flavor:
  name: "amphora"
  is_public: no
  vcpus: 2
  ram: 4096
  disk: 30
octavia_amp_security_groups:
    mgmt-sec-grp:
      enabled: true
      name: "lb-mgmt-sec-grp"
      rules:
        - protocol: icmp
        - protocol: tcp
          src_port: 22
          dst_port: 22
        - protocol: tcp
          src_port: "{{ octavia_amp_listen_port }}"
          dst_port: "{{ octavia_amp_listen_port }}"
octavia_amp_network:
  name: lb-mgmt-net
  provider_network_type: flat
  provider_physical_network: physnet2
  external: false
  shared: false
  subnet:
    name: lb-mgmt-subnet
    cidr: "{{ octavia_amp_network_cidr }}"
    gateway_ip: "10.230.157.1"
    enable_dhcp: yes
    allocation_pool_start: 10.230.157.40
    allocation_pool_end: 10.230.157.250
octavia_amp_network_cidr: 10.230.157.0/24
octavia_amp_image_tag: "amphora"
```

## Kolla Commands

```bash
kolla-ansible -i all-in-one bootstrap-servers
kolla-ansible octavia-certificates
kolla-ansible -i all-in-one prechecks
kolla-ansible -i all-in-one deploy
kolla-ansible -i all-in-one post-deploy
```

##  Enabling SRIOV for BRODCOM Nics

```bash
- Enable sriov in Bios
sudo modprobe -r bnxt_en
sudo modprobe bnxt_en
echo 8 > /sys/class/net/eth1/device/sriov_numvfs
echo 8 > /sys/class/net/ens3f1np1/device/sriov_numvfs 
/etc/kolla/nova-scheduler/nova.conf
[filter_scheduler]
scheduler_default_filters = RetryFilter, AvailabilityZoneFilter, RamFilter, ComputeFilter, ComputeCapabilitiesFilter, ImagePropertiesFilter, ServerGroupAntiAffinityFilter, ServerGroupAffinityFilter, PciPassthroughFilter
scheduler_available_filters = nova.scheduler.filters.all_filters 
```

### Octavia with sriov nic

```bash
pip install python-octaviaclient
openstack network create  --external --provider-physical-network sriovtenant1 --provider-network-type flat sriov-external --share
openstack aggregate create sriov_aggregate
openstack aggregate add host sriov_aggregate dev-test-24
openstack aggregate set --property public-sriov=true --property sriov-nic=true sriov_aggregate
openstack flavor create --id amphora-sriov-flavor --ram 16384 --disk 3 --vcpus 4 --private sriov.amphora --property hw_rng:allowed=True --property public-sriov=true --property members-sriov=true
openstack loadbalancer flavorprofile create --name amphora-sriov-profile --provider amphora --flavor-data '{"compute_flavor": "amphora-sriov-flavor", "sriov_vip": true}'
openstack loadbalancer flavor create --name SRIOV-public-members --flavorprofile amphora-sriov-profile --description "A load balancer that uses SR-IOV for the 'public' network and 'members' network." --enable
```

```bash
openstack flavor create --vcpus 2 --ram 2048 --disk 20 flavor_2vcpus_2G
openstack flavor create --vcpus 4 --ram 4096 --disk 20 flavor_4vcpus_4G
openstack flavor create --vcpus 6 --ram 6144 --disk 20 flavor_6vcpus_6G
openstack server create --flavor flavor_4vcpus_4G --image a11b93e4-8ca8-495f-8bf5-9c6f5d8caf66 --network public --security-group default test

```

| **IP Type**                  | **Purpose**                       | **Network**                | **Managed by**         |
|-------------------------------|------------------------------------|----------------------------|-------------------------|
  | **VIP**                      | Load balancer front-end IP        | Tenant's subnet            | Octavia                |
| **Floating IP** (optional)   | External access to VIP            | External (public) network  | Neutron                |
| **Amphora Management IP**    | Control plane communication       | Amphora management network | OpenStack Admin        |
| **Amphora Data Plane IP**    | Internal traffic handling         | Tenant's subnet            | Neutron                |
| **Backend Member IP**        | Traffic forwarded to backends     | Tenant's subnet            | Tenant/User            |
| **Health Monitor IP**        | Backend health checks             | Tenant's subnet            | Octavia                |
| **External Gateway IP**      | Access to external networks       | External network           | Neutron                |

## Creating custom image for Amphora VM's

```bash
# Clone the octavia git, this is required for havng the disk-builder scripts
git clone https://github.com/openstack/octavia.git
cd octavia/diskimage-create
pip install -r requirements.txt
sudo apt install qemu-utils git kpartx debootstrap
export DIB_OCTAVIA_AMP_USE_NFTABLES=True

# Clone the disk-builder git, this is required to get the 
git clone https://git.openstack.org/openstack/diskimage-builder.git
export DIB_ROOT=</path/to/diskimage-builder downloaded above>
cd export DIB_OCTAVIA_AMP_USE_NFTABLES=True
./diskimage-create.sh

# openstack image create amphora --container-format bare --disk-format qcow2 --private --tag amphora --file /home/user/octavia/diskimage-create/amphora-x64-haproxy.qcow2 --tag amphora --property hw_architecture='x86_64' --property hw_rng_model=virtio --project service
openstack image create amphora-x64-haproxy.qcow2 --container-format bare --disk-format qcow2 --project service --tag amphora --file /home/user/kolla-ansible/build/scripts-3.10/octavia/diskimage-create/amphora-x64-haproxy.qcow2 --property hw_architecture='x86_64' --property hw_rng_model=virtio
```

```bash
iperf -c 10.2.0.21 -t 10 -P 10 -l 1M
```

### Loadbalancer setup

![alt text](Amphora-normal-lb.png)

```bash

sudo cat << EOF > /var/www/html/index.html 
<html>
This is served by $(hostname)
</html>
EOF
```

```bash
openstack loadbalancer create --name lb1 --vip-subnet-id public-subnet --wait
openstack loadbalancer listener create --name listener1 --protocol HTTP --protocol-port 80 --wait lb1
openstack loadbalancer pool create --name pool1 --lb-algorithm ROUND_ROBIN --listener listener1 --protocol HTTP --wait
openstack loadbalancer member create --subnet-id private-subnet --address 192.0.2.10 --protocol-port 80 --wait pool1
openstack loadbalancer member create --subnet-id private-subnet --address 192.0.2.11 --protocol-port 80 --wait pool1

(kolla-venv) user@dev-test-23:~$ openstack loadbalancer list
+--------------------------------------+------------------+----------------------------------+----------------+---------------------+------------------+----------+
| id                                   | name             | project_id                       | vip_address    | provisioning_status | operating_status | provider |
+--------------------------------------+------------------+----------------------------------+----------------+---------------------+------------------+----------+
| 31f66bb6-c1d0-4dc1-bf56-14a5aa217f33 | shiva_lb_test    | 12ec21f0b5644482bc18a8129c61f1f8 | 10.230.156.101 | ACTIVE              | ONLINE           | amphora  |
| 02be49ab-0587-4793-8c6a-3bbe6e83cd14 | pragathi_lb_test | 12ec21f0b5644482bc18a8129c61f1f8 | 10.230.156.105 | ACTIVE              | OFFLINE          | amphora  |
| 2679b5ab-788c-4d51-a5f0-569ecc121480 | pragathi1_test   | 12ec21f0b5644482bc18a8129c61f1f8 | 10.230.156.100 | ERROR               | OFFLINE          | amphora  |
| 6926bde6-8084-4f3e-804b-4202bf8c3e15 | akshita          | 12ec21f0b5644482bc18a8129c61f1f8 | 10.230.156.33  | ERROR               | OFFLINE          | amphora  |
| b31ceceb-6a02-4b73-80dc-ac535aa97d2b | load_balancer    | 12ec21f0b5644482bc18a8129c61f1f8 | 10.230.156.61  | ACTIVE              | OFFLINE          | amphora  |
+--------------------------------------+------------------+----------------------------------+----------------+---------------------+------------------+----------+
(kolla-venv) user@dev-test-23:~$ openstack loadbalancer show 31f66bb6-c1d0-4dc1-bf56-14a5aa217f33
+---------------------+--------------------------------------+
| Field               | Value                                |
+---------------------+--------------------------------------+
| admin_state_up      | True                                 |
| availability_zone   | None                                 |
| created_at          | 2024-09-25T09:22:15                  |
| description         | shiva test loadbalancer              |
| flavor_id           | None                                 |
| id                  | 31f66bb6-c1d0-4dc1-bf56-14a5aa217f33 |
| listeners           | a29aa7bd-3fb9-4c36-b868-3209f466ec91 |
| name                | shiva_lb_test                        |
| operating_status    | ONLINE                               |
| pools               | 7c53f435-f131-4fe1-9f2a-29e9048e273e |
| project_id          | 12ec21f0b5644482bc18a8129c61f1f8     |
| provider            | amphora                              |
| provisioning_status | ACTIVE                               |
| updated_at          | 2024-09-25T09:23:50                  |
| vip_address         | 10.230.156.101                       |
| vip_network_id      | 27cbe457-2fe5-4e65-80bb-3785c0787d59 |
| vip_port_id         | 0753c1fb-e4fd-4531-8811-b30badf7c70f |
| vip_qos_policy_id   | None                                 |
| vip_subnet_id       | 8fb3646a-9fea-40ac-ada4-2cbe0c6c6697 |
| vip_vnic_type       | normal                               |
| tags                |                                      |
| additional_vips     | []                                   |
+---------------------+--------------------------------------+

(kolla-venv) user@dev-test-23:~$ openstack loadbalancer amphora list | grep 31f66bb6-c1d0-4dc1-bf56-14a5aa217f33
| c1256f0a-d3b0-41e5-b835-422059303483 | 31f66bb6-c1d0-4dc1-bf56-14a5aa217f33 | ALLOCATED | STANDALONE | **10.230.157.123** | 10.230.156.101 |


ssh -i octavia_ssh_key ubuntu@10.230.157.123

```

```bash
sudo apt install apache2-utils -y 

```

### Backend-1

```bash
ubuntu@lb-client-2:~$ wget http://10.230.156.173:80/file1G
--2024-09-25 18:32:48--  http://10.230.156.173/file1G
Connecting to 10.230.156.173:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1073741824 (1.0G) [application/octet-stream]
Saving to: ‘file1G’

file1G                              100%[=================================================================>]   1.00G   280MB/s    in 3.7s    

2024-09-25 18:32:51 (276 MB/s) - ‘file1G’ saved [1073741824/1073741824]

ubuntu@lb-client-2:~$ wget http://10.230.156.173:80/file10m
--2024-09-25 18:32:54--  http://10.230.156.173/file10m
Connecting to 10.230.156.173:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10485760 (10M) [application/octet-stream]
Saving to: ‘file10m’

file10m                             100%[=================================================================>]  10.00M  --.-KB/s    in 0.02s   

2024-09-25 18:32:54 (641 MB/s) - ‘file10m’ saved [10485760/10485760]

ubuntu@lb-client-2:~$ wget http://10.230.156.173:80/file1m
--2024-09-25 18:32:58--  http://10.230.156.173/file1m
Connecting to 10.230.156.173:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1048576 (1.0M) [application/octet-stream]
Saving to: ‘file1m’

file1m                              100%[=================================================================>]   1.00M  --.-KB/s    in 0.003s  

2024-09-25 18:32:58 (304 MB/s) - ‘file1m’ saved [1048576/1048576]

```

```bash
ubuntu@lb-client-2:~$ wget http://10.230.156.204:80/file1G
--2024-09-25 18:34:06--  http://10.230.156.204/file1G
Connecting to 10.230.156.204:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1073741824 (1.0G) [application/octet-stream]
Saving to: ‘file1G’

file1G                              100%[=================================================================>]   1.00G   323MB/s    in 3.2s    

2024-09-25 18:34:09 (323 MB/s) - ‘file1G’ saved [1073741824/1073741824]

ubuntu@lb-client-2:~$ wget http://10.230.156.204:80/file10m
--2024-09-25 18:34:13--  http://10.230.156.204/file10m
Connecting to 10.230.156.204:80... connected.
HTTP request sent, awaiting response... 404 Not Found
2024-09-25 18:34:13 ERROR 404: Not Found.

ubuntu@lb-client-2:~$ wget http://10.230.156.204:80/file10m
--2024-09-25 18:37:26--  http://10.230.156.204/file10m
Connecting to 10.230.156.204:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10485760 (10M) [application/octet-stream]
Saving to: ‘file10m’

file10m                             100%[=================================================================>]  10.00M  --.-KB/s    in 0.02s   

2024-09-25 18:37:26 (441 MB/s) - ‘file10m’ saved [10485760/10485760]

ubuntu@lb-client-2:~$ wget http://10.230.156.204:80/file1m
--2024-09-25 18:37:30--  http://10.230.156.204/file1m
Connecting to 10.230.156.204:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1048576 (1.0M) [application/octet-stream]
Saving to: ‘file1m’

file1m                              100%[=================================================================>]   1.00M  --.-KB/s    in 0.003s  

2024-09-25 18:37:30 (355 MB/s) - ‘file1m’ saved [1048576/1048576]
rm -rf file*
```

```bash
ubuntu@lb-client-2:~$ wget http://10.230.156.178:80/file1G
--2024-09-25 18:56:37--  http://10.230.156.178/file1G
Connecting to 10.230.156.178:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1073741824 (1.0G) [application/octet-stream]
Saving to: ‘file1G.1’

file1G.1                            100%[=================================================================>]   1.00G   333MB/s    in 3.1s    

2024-09-25 18:56:40 (333 MB/s) - ‘file1G.1’ saved [1073741824/1073741824]

ubuntu@lb-client-2:~$ wget http://10.230.156.178:80/file1m
--2024-09-25 18:56:48--  http://10.230.156.178/file1m
Connecting to 10.230.156.178:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1048576 (1.0M) [application/octet-stream]
Saving to: ‘file1m’

file1m                              100%[=================================================================>]   1.00M  --.-KB/s    in 0.004s  

2024-09-25 18:56:48 (234 MB/s) - ‘file1m’ saved [1048576/1048576]

ubuntu@lb-client-2:~$ wget http://10.230.156.178:80/file10m
--2024-09-25 18:56:51--  http://10.230.156.178/file10m
Connecting to 10.230.156.178:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10485760 (10M) [application/octet-stream]
Saving to: ‘file10m’

file10m                             100%[=================================================================>]  10.00M  --.-KB/s    in 0.03s   

2024-09-25 18:56:51 (344 MB/s) - ‘file10m’ saved [10485760/10485760]
```

```bash 
sudo apt update
sudo apt install python3-pip
sudo apt install python3-matplotlib
```

```bash
python lbaas-benchmark.py -c 128 -u http://10.230.156.101/file1m
```

```bash
ubuntu@lb-client-2:~$ python3 lbaas-v1.py --url http://10.230.156.101/file1m
Requests: 10, Concurrency: 10, Requests per Second: 180.02, Completed: 10, Failed: 0
Requests: 100, Concurrency: 50, Requests per Second: 60.06, Completed: 100, Failed: 0
Requests: 1000, Concurrency: 250, Requests per Second: 33.10, Completed: 1000, Failed: 0
Requests: 10000, Concurrency: 1250, Requests per Second: 44.94, Completed: 10000, Failed: 22
Requests: 100000, Concurrency: 6250, Requests per Second: 125.25, Completed: 100000, Failed: 68022
Results saved to benchmark_results_file1m.png
```

![Stats for 1mb file](benchmark_results_file1m.png)

```bash
ubuntu@lb-client-2:~$ python3 lbaas-v1.py --url http://10.230.156.101/file10m
Requests: 10, Concurrency: 10, Requests per Second: 58.10, Completed: 10, Failed: 0
Requests: 100, Concurrency: 50, Requests per Second: 17.32, Completed: 100, Failed: 0
Requests: 1000, Concurrency: 250, Requests per Second: 6.66, Completed: 1000, Failed: 0
client_loop: send disconnect: Broken pipe
```

## Ip-IP tunnel creation

```bash
sudo ip tunnel add ipip0 mode ipip remote  10.230.155.12 local  10.230.156.49
sudo ip link set ipip0 up
sudo ip addr add 192.168.100.2/24 dev ipip0

```

```bash
sudo ip tunnel add ipip0 mode ipip remote 10.230.155.12 local 10.230.156.26
sudo ip link set ipip0 up
sudo ip addr add 192.168.200.2/24 dev ipip0
```

```bash
sudo modprobe ipip
sudo ip tunnel add ipip0 mode ipip remote 10.230.156.26 local 10.230.155.12  ttl 255
sudo ip link set ipip0 up
sudo ip addr add 192.168.200.1/24 dev ipip0

sudo ip tunnel add ipip1 mode ipip remote 10.230.156.49 local 10.230.155.12
sudo ip link set ipip1 up
sudo ip addr add 192.168.100.1/24 dev ipip1
```

## Customising the Openstack neutron image in  kolla

```bash
python3 -m pip install  kolla docker

cat template-overrides.j2 
{% extends parent_template %}

# Horizon
{% block horizon_ubuntu_source_setup %}
RUN pip install networking-l2gw
{% endblock %}
kolla-build --template-override template-overrides.j2 neutron-server -b ubuntu
sudo sed -ri 's/^(service_plugins.*)/\1,networking_l2gw.services.l2gateway.plugin.L2GatewayPlugin/' /etc/kolla/neutron-server/neutron.conf
```

- Customising Images
  
```bash
git clone https://opendev.org/openstack/kolla.git
cd kolla
python3 -m pip install kolla
python3 -m pip install docker

cat neutron-server.j2 
{% extends parent_template %}

{% block neutron_server_footer %}
RUN git clone https://opendev.org/x/networking-l2gw \
    && python3 -m pip --no-cache-dir install networking-l2gw
{% endblock %}


kolla-build --template-override neutron-server.j2 neutron-server


```

```bash
## Add the below 
vi ~/kolla-venv/share/kolla-ansible/ansible/roles/neutron/templates/neutron-server.json.j2 
{
    "command": "neutron-server --config-file /etc/neutron/neutron.conf --config-file l2gw_plugin.ini {% if neutron_plugin_agent in ['openvswitch', 'linuxbridge', 'ovn'] %} --config-file /etc/neutron/plugins/ml2/ml2_conf.ini --config-file /etc/neutron/neutron_vpnaas.conf {% elif neutron_plugin_agent in ['vmware_nsxv', 'vmware_nsxv3', 'vmware_nsxp', 'vmware_dvs'] %} --config-file /etc/neutron/plugins/vmware/nsx.ini {% endif %}{% if enable_neutron_fwaas | bool %}--config-file /etc/neutron/fwaas_driver.ini{% endif %}",
    "config_files": [
...
        {
            "source": "{{ container_config_directory }}/l2gw_plugin.ini",
            "dest": "/etc/neutron/l2gw_plugin.ini",
            "owner": "neutron",
            "perm": "0600"
        },
...

```

```bash
## Add the below 
vi ~/kolla-venv/share/kolla-ansible/ansible/roles/neutron/tasks/config.yml
- name: Copying over l2gw_plugin.ini
  become: true
  vars:
    service_name: "{{ item.key }}"
    services_need_ml2_conf_ini:
      - "neutron-server"
  merge_configs:
    sources:
      - "{{ role_path }}/templates/l2gw_plugin.ini"
    dest: "{{ node_config_directory }}/{{ service_name }}/l2gw_plugin.ini"
    mode: "0660"
  with_dict: "{{ neutron_services | select_services_enabled_and_mapped_to_host }}"
  notify:
    - "Restart {{ item.key }} container"

sudo docker exec -it neutron_server -- neutron-db-manage --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/l2gw_plugin.ini  upgrade head
sudo docker restart neutron_server
```
