# @summary Controls the state of the falco service
#
# Controls the state of the falco service
#
class falco::service inherits falco {

if ($falco::falco_version =~ /\-0\.[0-2]?[0-9]\.[0-9]*/ or $falco::falco_version =~ /\-0\.3?[0-3]\.[0-9]*/)
{
  systemd::dropin_file { 'falco.override.conf':
    unit    => 'falco.service',
    content => epp('falco/falco.override.conf.epp', { environment => $falco::environment}),
    notify  => Service["falco${falco::probe_type}"],
  }
}
service { "falco${falco::probe_type}":
  ensure     => $falco::service_ensure,
  enable     => $falco::service_enable,
  hasstatus  => true,
  hasrestart => $falco::service_restart,
}
}
