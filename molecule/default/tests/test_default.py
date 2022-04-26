import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_sec_stop_unnecessary_services(host):
    services = host.run('systemctl list-units --type=service')
    assert 'postfix' not in services.stdout


def test_sec_kernel_parameters(host):
    assert 1 == host.sysctl('net.ipv6.conf.all.disable_ipv6')
    assert 1 == host.sysctl('net.ipv6.conf.default.disable_ipv6')
    assert 1 == host.sysctl('net.ipv4.icmp_echo_ignore_broadcasts')
    assert 1 == host.sysctl('net.ipv4.conf.all.rp_filter')
    assert 1 == host.sysctl('net.ipv4.conf.default.rp_filter')
    assert 0 == host.sysctl('net.ipv4.conf.all.accept_redirects')
    assert 0 == host.sysctl('net.ipv4.conf.default.accept_redirects')
    assert 1 == host.sysctl('net.ipv4.conf.all.log_martians')
#    assert 0 == host.sysctl('net.ipv4.ip_forward')
    assert 2 == host.sysctl('kernel.randomize_va_space')


def test_sec_sshd_is_installed(host):
    package = host.package('openssh-server')
    assert package.is_installed

    service = host.service('sshd')
    assert service.is_running
    assert service.is_enabled

    assert host.socket('tcp://0.0.0.0:22').is_listening


def test_sec_sshd_permit_root_login(host):
    config = host.run('cat /etc/ssh/sshd_config')
    assert 'PermitRootLogin no' in config.stdout.split('\n')


def test_sec_sshd_password_authenticate(host):
    config = host.run('cat /etc/ssh/sshd_config')
    assert 'PasswordAuthentication no' in config.stdout.split('\n')


def test_sec_sshd_other_config(host):
    config = host.run('cat /etc/ssh/sshd_config')
    assert 'PermitEmptyPasswords no' in config.stdout.split('\n')
    assert 'ChallengeResponseAuthentication no' in config.stdout.split('\n')
    assert 'KerberosAuthentication no' in config.stdout.split('\n')
    assert 'GSSAPIAuthentication no' in config.stdout.split('\n')
    assert 'X11Forwarding no' in config.stdout.split('\n')


def test_sec_firewalld_is_installed(host):
    package = host.package('firewalld')
    assert package.is_installed

    service = host.service('firewalld')
    assert service.is_running
    assert service.is_enabled


def test_sec_fail2ban_is_installed(host):
    package = host.package('fail2ban')
    assert package.is_installed

    service = host.service('fail2ban')
    assert service.is_running
    assert service.is_enabled


def test_sec_clamav_is_installed(host):
    package = host.package("clamav")
    assert package.is_installed


def test_sec_clamav_db_setupped(host):
    db = host.file("/var/lib/clamav/freshclam.dat")
    assert db.exists


def test_sec_clamav_cron_file(host):
    cron = host.file("/etc/cron.d/clamav-update")
    assert cron.exists
#    assert 0o755 == cron.mode


def test_sec_rkhunter_is_installed(host):
    package = host.package("rkhunter")
    assert package.is_installed


def test_sec_rkhunter_db_setupped(host):
    db = host.file("/var/lib/rkhunter/db/rkhunter.dat")
    assert db.exists


def test_sec_rkhunter_cron_file(host):
    cron = host.file("/etc/cron.daily/rkhunter")
    assert cron.exists
    assert 0o755 == cron.mode


def test_sec_aide_is_installed(host):
    package = host.package("aide")
    assert package.is_installed


def test_sec_aide_db_setupped(host):
    db = host.file("/var/lib/aide/aide.db.gz")
    assert db.exists


def test_sec_aide_cron_file(host):
    cron = host.file("/etc/cron.daily/aide")
    assert cron.exists
    assert 0o755 == cron.mode
