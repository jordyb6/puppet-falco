
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

  $_file_output = $falco::file_output

  if ($_file_output != undef) {
    logrotate::rule { 'falco_output':
      path          => $_file_output['filename'],
      rotate        => 5,
      rotate_every  => 'day',
      size          => '1M',
      missingok     => true,
      compress      => true,
      sharedscripts => true,
      postrotate    => '/usr/bin/killall -USR1 falco',
    }
  }
}
