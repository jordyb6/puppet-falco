# @summary
#
# Installs the falco package
#
class falco::install inherits falco {
  if $falco::manage_rpm {
    package { "falco${falco::falco_version}":
      ensure          => $falco::package_ensure,
      provider        => rpm,
      source          => $falco::package_source,
      install_options => [$falco::rpm_install_options],}}
  else {
    package { "falco${falco::falco_version}":
      ensure   => $falco::package_ensure,
  }

  }
}
