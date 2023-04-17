# @summary Controls the state of the falco and falcoctl services
#
# Controls the state of the falco and falcoctl services
#
class falco::service inherits falco {
  service { "falco-${falco::driver}":
    ensure     => $falco::service_ensure,
    enable     => $falco::service_enable,
    hasstatus  => true,
    hasrestart => $falco::service_restart,
  }

  # Stop and mask the automatic ruleset updates service if automatic ruleset
  # updates are disabled. Otherwise, it's state is managed by the falco service.
  unless $falco::auto_ruleset_updates {
    service { 'falcoctl-artifact-follow':
      ensure => 'stopped',
      enable => 'mask',
    }
  }
}
