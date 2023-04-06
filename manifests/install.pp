# @summary
#
# Installs the falco package
#
class falco::install inherits falco {
  package { "falco${falco::falco_version}":
    ensure => $falco::package_ensure,
  }
}
