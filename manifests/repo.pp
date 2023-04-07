# @summary Manages the repository falco is installed from
#
# Manages the repository falco is installed from
#
class falco::repo inherits falco {
  if $falco::manage_repo == false {
    case $facts['os']['family'] {
      'Debian': {
        include apt

        Apt::Source['falco']
        -> Class['apt::update']

        apt::key { 'falcosecurity':
          ensure => 'refreshed',
          source => 'https://falco.org/repo/falcosecurity-packages.asc',
          id     => '2005399002D5E8FF59F28CE64021833E14CB7A8D', # finger print of key id 4021833E14CB7A8D
        }

        apt::source { 'falco':
          location => 'https://download.falco.org/packages/deb',
          release  => 'stable',
          repos    => 'main',
        }

        ensure_packages(["linux-headers-${facts['kernelrelease']}"])
        if $falco::build_driver and $falco::build_type == 'bpf' {
          ensure_packages(['clang','llvm'])
        }
      }
      'RedHat': {
        include 'epel'

        Yumrepo['falco']
        -> Class['epel']

        yumrepo { 'falco':
          baseurl  => 'https://download.falco.org/packages/rpm',
          descr    => 'Falco repository',
          enabled  => 1,
          gpgcheck => 0,
        }

        ensure_packages(["kernel-devel-${facts['kernelrelease']}"])
        if $falco::build_driver and $falco::build_type == 'bpf' {
          ensure_packages(['clang','llvm'])
        }
      }
      'Suse': {
        if $facts['os']['release']['full'] == '12.5' {
          rpmkey { '3A6A4D911FCCBD0A':
            ensure => present,
            source => 'https://download.opensuse.org/repositories/home:/BuR_Industrial_Automation:/SLE-12-SP5:/basesystem/SLE_12_SP5/repodata/repomd.xml.key',
            before => Zypprepo['home:BuR_Industrial_Automation:SLE-12-SP5:basesystem (SLE_12_SP5)'],
          }

          zypprepo { 'home:BuR_Industrial_Automation:SLE-12-SP5:basesystem (SLE_12_SP5)':
            name        => 'home:BuR_Industrial_Automation:SLE-12-SP5:basesystem (SLE_12_SP5)',
            enabled     => 1,
            autorefresh => 0,
            baseurl     => 'https://download.opensuse.org/repositories/home:/BuR_Industrial_Automation:/SLE-12-SP5:/basesystem/SLE_12_SP5/',
            type        => 'rpm-md',
            gpgcheck    => 1,
            gpgkey      => 'https://download.opensuse.org/repositories/home:/BuR_Industrial_Automation:/SLE-12-SP5:/basesystem/SLE_12_SP5/repodata/repomd.xml.key',
          }
        }

        rpmkey { '4021833E14CB7A8D':
          ensure => present,
          source => 'https://falco.org/repo/falcosecurity-packages.asc',
          before => Zypprepo['falcosecurity-rpm'],
        }

        zypprepo { 'falcosecurity-rpm':
          name          => 'falcosecurity-rpm',
          baseurl       => 'https://download.falco.org/packages/rpm',
          gpgcheck      => 1,
          gpgkey        => 'https://falco.org/repo/falcosecurity-packages.asc',
          repo_gpgcheck => 0,
          enabled       => 1,
        }

        ensure_packages(['kernel-default-devel'])
        if $falco::build_driver and $falco::build_type == 'bpf' {
          ensure_packages(['clang','llvm'])
        }
      }
      default: {
        fail("\"${module_name}\" provides no repository information for OSfamily \"${facts['os']['family']}\"")
      }
    }
}
}
