# @summary Controls the contents of falco.yaml and sets up log rotate, if needed
#
# Controls the contents of falco.yaml and sets up log rotate, if needed
#
class falco::config inherits falco {
  file {
    default:
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      require => Class['falco::install'],
      notify  => Service["falco-${falco::driver}"],
      ;
    '/etc/falco/falco.yaml':
      content => template('falco/falco.yaml.erb'),
      ;
    '/etc/falco/falco_rules.local.yaml':
      content => epp('falco/falco_rules.local.yaml.epp', { 'local_rules' => $falco::local_rules, }),
      ;
  }
}
