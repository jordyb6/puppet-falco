# @summary Guides the basic setup and installation of Falco on your system.
#
# When this class is declared with the default options, Puppet:
#
# * Installs the appropriate Falco software package and installs the falco-probe kernel module for your operating system.
# * Creates the required configuration file `/etc/Falco/falco.yaml`. By default only syslog output is enabled.
# * Starts the falco service.
#
# @example Using defaults
#   include falco
#
# @example Enabling file output
#   class { 'falco':
#     file_output => {
#       'enabled'    => 'true',
#       'keep_alive' => 'false',
#       'filename'   => '/var/log/falco-events.log',
#     },
#   }
#
# @example Enabling program output
#   class { 'falco':
#     json_output => 'true',
#     program_output => {
#       'enabled'    => 'true',
#       'keep_alive' => 'false',
#       'program'    => 'curl http://some-webhook.com'
#     },
#   }
#
# @example Create local rule
#   class { 'falco':
#     local_rules => [{
#       'rule'      => 'The program "sudo" is run in a container',
#       'desc'      => 'An event will trigger every time you run sudo in a container',
#       'condition' => 'evt.type = execve and evt.dir=< and container.id != host and proc.name = sudo',
#       'output'    => 'Sudo run in container (user=%user.name %container.info parent=%proc.pname cmdline=%proc.cmdline)',
#       'priority'  => 'ERROR',
#       'tags'      => ['users', 'container'],
#     }],
#   }
#
# @example Local rules, lists, and macro
#   class { 'falco':
#     local_rules => [
#       {
#         'rule'      => 'The program "sudo" is run in a container',
#         'desc'      => 'An event will trigger every time you run sudo in a container',
#         'condition' => 'evt.type = execve and evt.dir=< and container.id != host and proc.name = sudo',
#         'output'    => 'Sudo run in container (user=%user.name %container.info parent=%proc.pname cmdline=%proc.cmdline)',
#         'priority'  => 'ERROR',
#         'tags'      => ['users', 'container'],
#       },
#       {
#         'rule'      => 'rule 2',
#         'desc'      => 'describing rule 2',
#         'condition' => 'evt.type = execve and evt.dir=< and container.id != host and proc.name = sudo',
#         'output'    => 'Sudo run in container (user=%user.name %container.info parent=%proc.pname cmdline=%proc.cmdline)',
#         'priority'  => 'ERROR',
#         'tags'      => ['users'],
#       },
#       {
#         'list'  => 'shell_binaries',
#         'items' => ['bash', 'csh', 'ksh', 'sh', 'tcsh', 'zsh', 'dash'],
#       },
#       {
#         'list'  => 'userexec_binaries',
#         'items' => ['sudo', 'su'],
#       },
#       {
#         'list'  => 'known_binaries',
#         'items' => ['shell_binaries', 'userexec_binaries'],
#       },
#       {
#         'macro'     => 'safe_procs',
#         'condition' => 'proc.name in (known_binaries)',
#       }
#     ],
#   }
#
# @param rules_file
#   File(s) or Directories containing Falco rules, loaded at startup.
#   The name "rules_file" is only for backwards compatibility.
#   If the entry is a file, it will be read directly. If the entry is a directory,
#   every file in that directory will be read, in alphabetical order.
#
#   falco_rules.yaml ships with the falco package and is overridden with
#   every new software version. falco_rules.local.yaml is only created
#   if it doesn't exist. If you want to customize the set of rules, add
#   your customizations to falco_rules.local.yaml.
#
#   The files will be read in the order presented here, so make sure if
#   you have overrides they appear in later files.
#
# @param local_rules
#   An array of hashes of rules to be added to /etc/falco/falco_rules.local.yaml
#
# @param watch_config_files
#   Whether to do a hot reload upon modification of the config
#   file or any loaded rule file
#
# @param json_output
#   Whether to output events in json or text
#
# @param json_include_output_property
#   When using json output, whether or not to include the "output" property
#   itself (e.g. "File below a known binary directory opened for writing
#   (user=root ....") in the json output.
#
# @param log_stderr
#   Send information logs to stderr Note these are *not* security
#   notification logs! These are just Falco lifecycle (and possibly error) logs.
#
# @param log_syslog
#   Send information logs to stderr Note these are *not* security
#   notification logs! These are just Falco lifecycle (and possibly error) logs.
#
# @param log_level
#   Minimum log level to include in logs. Note: these levels are
#   separate from the priority field of rules. This refers only to the
#   log level of falco's internal logging. Can be one of "emergency",
#   "alert", "critical", "error", "warning", "notice", "info", "debug".
#
# @param priority
#   Minimum rule priority level to load and run. All rules having a
#   priority more severe than this level will be loaded/run.  Can be one
#   of "emergency", "alert", "critical", "error", "warning", "notice",
#   "informational", "debug".
#
# @param buffered_outputs
#   Whether or not output to any of the output channels below is
#   buffered. Defaults to false
#
# @param outputs_rate
#   The number of tokens (i.e. right to send a notification) gained per second.
#
# @param outputs_max_burst
#   The maximum number of tokens outstanding.
#
# @param syslog_output
#   A hash to configure the syslog output.
#   See the template for available keys.
#
# @param file_output
#   A hash to configure the file output.
#   See the template for available keys.
#
# @param stdout_output
#   A hash to configure the stdout output.
#   See the template for available keys.
#
# @param webserver
#   A has to configure the webserver.
#   See the template for available keys.
#
# @param program_output
#   A hash to configure the program output.
#   See the template for available keys.
#
# @param http_output
#   A hash to configure the http output.
#   See the template for available keys.
#
# @param engine_kind
#  The desired Falco driver.
#  Can be one of "ebpf", "modern_bpf", "kmod".
#  Defaults to "kmod"
#
# @param falcoctl_driver_config
#    A hash to configure the falcoctl driver tool
#    See the template for available keys.
#
# @param package_ensure
#   A string to be passed to the package resource's ensure parameter
#
# @param service_ensure
#    Desired state of the Falco service
#
# @param service_enable
#    Start the Falco service on boot?
#
# @param service_restart
#    Does the service support restarting?
#
# @param auto_ruleset_updates
#    Enable automatic rule updates?
#
# @param manage_dependencies
#    Enable managing of dependencies?
#
# @param manage_repo
#    When true, let the module manage the repositories.
#    Default is true.
#
#
class falco (
  # Configuration parameters
  Array $rules_file = [
    '/etc/falco/falco_rules.yaml',
    '/etc/falco/falco_rules.local.yaml',
    '/etc/falco/k8s_audit_rules.yaml',
    '/etc/falco/rules.d',
  ],
  Array[Hash] $local_rules = [],
  Boolean $watch_config_files = true,
  Boolean $json_output = false,
  Boolean $json_include_output_property = true,

  Boolean $log_stderr = true,
  Boolean $log_syslog = true,
  Enum['alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'] $log_level = 'info',
  Enum['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'informational', 'debug'] $priority = 'debug',

  Boolean $buffered_outputs = false,
  Integer $outputs_rate = 1,
  Integer $outputs_max_burst = 1000,

  Hash $syslog_output = {
    'enabled' => true,
  },
  Hash $file_output = {
    'enabled'    => false,
    'keep_alive' => false,
    'filename'   => '/var/log/falco-events.log',
  },
  Hash $stdout_output = {
    'enabled' => true,
  },
  Hash $webserver = {
    'enabled'              => false,
    'listen_port'          => 8765,
    'k8s_audit_endpoint'   => '/k8s-audit',
    'k8s_healthz_endpoint' => '/healthz',
    'ssl_enabled'          => false,
    'ssl_certificate'      => '/etc/falco/falco.pem',
  },
  Hash $program_output = {
    'enabled'    => false,
    'keep_alive' => false,
    'program'    => '"jq \'{text: .output}\' | curl -d @- -X POST https://hooks.slack.com/services/XXX"',
  },
  Hash $http_output = {
    'enabled'    => false,
    'url'        => 'http://some.url',
    'user_agent' => '"falcosecurity/falco"',
  },

  Enum['bpf', 'modern-bpf', 'kmod'] $engine_kind = 'kmod',

  # Parameters for falcoctl config file
  Hash $falcoctl_driver_config = {
    'type'     => 'kmod',
    'name'     => 'falco',
    'repos'    => ['https://download.falco.org/driver'],
    'version'  => '7.0.0+driver',
    'hostroot' => '/',
  },

  Boolean $manage_repo = true,

  # Installation parameters
  String[1] $package_ensure = '>= 0.34',

  # Service parameters
  Variant[Boolean, Enum['running', 'stopped']] $service_ensure = 'running',
  Boolean $service_enable = true,
  Boolean $service_restart = true,
  Boolean $auto_ruleset_updates = true,
  Boolean $manage_dependencies = true,
) {
  $service_name = $falco::engine_kind ? {
    'kmod'        => 'kmod',
    'ebpf'        => 'bpf',
    'modern_ebpf' => 'modern-bpf',
    default => fail(" Service \"falco-${falco::engine_kind}\" is not yet supported by either the module \"${module_name}\" or \"falco\""),
  }

  Class['falco::repo']
  -> Class['falco::install']
  -> Class['falco::config']
  ~> Class['falco::service']

  contain falco::repo
  contain falco::install
  contain falco::config
  contain falco::service
}
