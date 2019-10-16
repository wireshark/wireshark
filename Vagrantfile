# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  # Bump the default resources as building is expensive
  config.vm.provider "virtualbox" do |v|
    v.memory = 2048
    v.cpus = 4
  end

  # Permit X11 forwarding so running the graphical Wireshark works
  config.ssh.forward_x11 = true

  # Mounting to /vagrant (the default) won't work for building a
  # Debian package. Let's be consistent for all boxes.
  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.synced_folder ".", "/home/vagrant/wireshark", type: "virtualbox"

  # Install and build the various things (including wireshark!)
  config.vm.define "ubuntu", autostart: false do |deb|
    deb.vm.box = "ubuntu/bionic64"

    deb.vm.provision "shell" do |s|
      s.path = 'tools/debian-setup.sh'
      s.args = ['--install-optional', '--assume-yes']
    end
    deb.vm.provision :shell, inline: "apt-get -y install ccache"
    deb.vm.provision :shell, path: 'vagrant_build.sh', privileged: false
  end

  config.vm.define "fedora", autostart: false do |rpm|
    rpm.vm.box = "fedora/28-cloud-base"

    rpm.vm.provision "shell" do |s|
      s.path = 'tools/rpm-setup.sh'
      s.args = ['--install-optional', '--assumeyes']
    end
    rpm.vm.provision :shell, inline: "yum -y install ccache"
    rpm.vm.provision :shell, path: 'vagrant_build.sh', privileged: false
  end
end
