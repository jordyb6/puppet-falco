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
# @param [Array] rules_file
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
# @param [Array[Hash]] local_rules
#   An array of hashes of rules to be added to /etc/falco/falco_rules.local.yaml
#
# @param [Boolean] watch_config_files
#   Whether to do a hot reload upon modification of the config
#   file or any loaded rule file
#
# @param [Boolean] json_output
#   Whether to output events in json or text
#
# @param [Boolean] json_include_output_property
#   When using json output, whether or not to include the "output" property
#   itself (e.g. "File below a known binary directory opened for writing
#   (user=root ....") in the json output.
#
# @param [Boolean] log_stderr
#   Send information logs to stderr Note these are *not* security
#   notification logs! These are just Falco lifecycle (and possibly error) logs.
#
# @param [Boolean] log_syslog
#   Send information logs to stderr Note these are *not* security
#   notification logs! These are just Falco lifecycle (and possibly error) logs.
#
# @param [Enum['alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug']] log_level
#   Minimum log level to include in logs. Note: these levels are
#   separate from the priority field of rules. This refers only to the
#   log level of falco's internal logging. Can be one of "emergency",
#   "alert", "critical", "error", "warning", "notice", "info", "debug".
#
# @param [Enum['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'informational', 'debug']] priority
#   Minimum rule priority level to load and run. All rules having a
#   priority more severe than this level will be loaded/run.  Can be one
#   of "emergency", "alert", "critical", "error", "warning", "notice",
#   "informational", "debug".
#
# @param [Hash] libs_logger
#   Hash to enable the libs logger sending its log records the same outputs
#   supported by falco (stderr and syslog).
#
# @param [Boolean] buffered_outputs
#   Whether or not output to any of the output channels below is
#   buffered. Defaults to false
#
# @param [Integer] syscall_buf_size_preset
#   Integer between 1 and 10. Sets the dimension of the syscall ring buffers.
#
# @param [Integer] outputs_rate
#   The number of tokens (i.e. right to send a notification) gained per second.
#
# @param [Integer] outputs_max_burst
#   The maximum number of tokens outstanding.
#
# @param [Hash] syslog_output
#   A hash to configure the syslog output.
#   See the template for available keys.
#
# @param [Hash] file_output
#   A hash to configure the file output.
#   See the template for available keys.
#
# @param [Hash] stdout_output
#   A hash to configure the stdout output.
#   See the template for available keys.
#
# @param [Hash] webserver
#   A has to configure the webserver.
#   See the template for available keys.
#
# @param [Hash] program_output
#   A hash to configure the program output.
#   See the template for available keys.
#
# @param [Hash] http_output
#   A hash to configure the http output.
#   See the template for available keys.
#
# @param [String[1]] package_ensure
#   A string to be passed to the package resource's ensure parameter
#
# @param [Variant[Boolean, Enum['running', 'stopped']]] service_ensure
#    Desired state of the Falco service
#
# @param [Boolean] service_enable
#    Start the Falco service on boot?
#
# @param [Boolean] service_restart
#    Does the service support restarting?
#
#
class falco (
  # Configuration parameters
  Array $rules_file,
  Array[Hash] $local_rules,
  Boolean $watch_config_files,
  Boolean $json_output,
  Boolean $json_include_output_property,

  Boolean $log_stderr,
  Boolean $log_syslog,
  Enum['alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'] $log_level,
  Enum['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'informational', 'debug'] $priority,
  Hash $libs_logger,

  Boolean $buffered_outputs,
  Integer $syscall_buf_size_preset,
  Integer $outputs_rate,
  Integer $outputs_max_burst,

  Hash $syslog_output,
  Hash $file_output,
  Hash $stdout_output,
  Hash $webserver,
  Hash $program_output,
  Hash $http_output,

  # Installation parameters
  String[1] $package_ensure,

  # Service parameters
  Variant[Boolean, Enum['running', 'stopped']] $service_ensure,
  Boolean $service_enable,
  Boolean $service_restart,
) {
  Class['falco::repo']
  -> Class['falco::install']
  -> Class['falco::config']
  ~> Class['falco::service']

  contain falco::repo
  contain falco::install
  contain falco::config
  contain falco::service
}
