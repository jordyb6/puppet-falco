# @summary
#
# Installs the falco package
#
class falco::install inherits falco {
  package { 'falco':
    ensure => $falco::package_ensure,
  }

  file { '/etc/falcoctl/falcoctl.yaml':
    ensure    => file,
    owner     => 'root',
    group     => 'root',
    mode      => '0644',
    content   => epp('falco/falcoctl.yaml.epp'),
    subscribe => Package['falco'],
  }

  # Install driver dependencies
  # Dependencies are not required for modern-bpf driver
  unless $falco::engine_kind == 'modern-bpf' {
    $_suse_kernel_version_sans_default = regsubst($facts['kernelrelease'], '^(.*)-default$', '\\1')
    $_running_kernel_devel_package = $facts['os']['family'] ? {
      'Debian' => "linux-headers-${facts['kernelrelease']}",
      'RedHat' => "kernel-devel-${facts['kernelrelease']}",
      'Suse'   => "kernel-default-devel-${_suse_kernel_version_sans_default}",
      default  => fail("The module \"${module_name}\" does not yet support \"${facts['os']['family']}\""),
    }
    ensure_packages([$_running_kernel_devel_package], { 'before' => Package['falco'] })

    if $falco::manage_dependencies {
      $_package_deps = ['dkms', 'make']
      ensure_packages($_package_deps, { 'before' => Package['falco'] })
      $_bpf_package_deps = ['llvm','clang']
      ensure_packages($_bpf_package_deps, { 'before' => Package['falco'] })
    }

    $_driver_type = $falco::engine_kind ? {
      'kmod'  => 'module',
      'ebpf'   => 'bpf',
      default => fail("The driver \"${falco::engine_kind}\" is not yet supported by either the module \"${module_name}\" or \"falco-driver-loader\""), # lint:ignore:140chars
    }

    # Download and compile the desired falco driver based on the currently running kernel version.
    # Recompile if the running kernel version change or falco package changes.
    #
    # Note, the default "--compile" flag should not be needed, but there appears to be a bug.
    # Open issue at https://github.com/falcosecurity/falco/issues/2431
    $_kernel_mod_path = $facts['os']['family'] ? {
      'Debian' => "/lib/modules/${facts['kernelrelease']}/updates/dkms/falco.ko",
      'RedHat' => "/lib/modules/${facts['kernelrelease']}/extra/falco.ko.xz",
      'Suse'   => "/lib/modules/${facts['kernelrelease']}/updates/falco.ko",
      default  => fail("The module \"${module_name}\" does not yet support \"${facts['os']['family']}\""),
    }

    case $_driver_type {
      'module': {
        exec { "falco-driver-loader ${_driver_type} --compile":
          creates   => $_kernel_mod_path,
          path      => '/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin',
          subscribe => Package[$_running_kernel_devel_package, 'falco'],
          notify    => Service["falco-${falco::service_name}"],
        }
      }
      'bpf': {
        exec { "falco-driver-loader ${_driver_type} --compile":
          creates     => "/root/.falco/${facts['falco_driver_version']}/${facts['os']['architecture']}/falco_${downcase($facts['os']['name'])}_${facts['kernelrelease']}_1.o", # lint:ignore:140chars
          environment => ['HOME=/root'],
          path        => '/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin',
          subscribe   => Package[$_running_kernel_devel_package, 'falco'],
          notify      => Service["falco-${falco::service_name}"],
        }
      }
      default: {
        fail("The driver \"${_driver_type}\" is not yet supported by either the module \"${module_name}\" or \"falco-driver-loader\"") # lint:ignore:140chars
      }
    }
  }
}
