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
#       'enabled'    => true,
#       'keep_alive' => false,
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
# @param libs_logger
#   Hash to enable the libs logger sending its log records the same outputs
#   supported by falco (stderr and syslog).
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
# @param syslog_output
#   A hash to configure the syslog output.
#   See the template for available keys.
#
# @param file_output
#   A hash to configure the file output.
#   See the template for available keys.
#
# @param enable_logrotate
#   Wether or not to use logrotate.
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
# @param engine_options
#    A hash to configure engine options.
#    See the template for available keys.
#
# @param load_plugins
#    An array to specify which plugins to load.
#
# @param plugins
#    A hash to specify plugin specific options.
#    See the template for available keys.
#
# @param time_format_iso_8601
#    When enabled, Falco will display log and output messages with times in the ISO
#    8601 format. By default, times are shown in the local time zone determined by
#    the /etc/localtime configuration.
#
# @param json_include_tags_property
#    Whether to include the "tags" field of the rules in the generated JSON output.
#
# @param rule_matching
#    The `rule_matching` configuration key's values are:
#     - `first`: Falco stops checking conditions of rules against upcoming event
#       at the first matching rule
#     - `all`: Falco will continue checking conditions of rules even if a matching 
#       one was already found
#
# @param outputs_queue_capacity 
#    The maximum number of items allowed in the queue is determined by this value.
#    Setting the value to 0 (which is the default) is equivalent to keeping the queue unbounded.
#
# @param grpc_output
#    Whether to use gRPC as an output service.
#
# @param grpc
#    A hash to configure the grpc server.
#    See the template for available keys.
#
# @param output_timeout
#    The `output_timeout` parameter specifies the duration, in milliseconds, to
#    wait before considering the deadline exceeded. By default, the timeout is set
#    to 2000ms (2 seconds), meaning that the consumer of Falco outputs can block
#    the Falco output channel for up to 2 seconds without triggering a timeout
#    error.
#
# @param syscall_event_timeouts_max_consecutives
#    configure the maximum number of consecutive timeouts without
#    an event after which Falco will generate an alert.
#    The default value is set to 1000.
#
# @param syscall_event_drops
#    A hash to configure periodic metrics of monotonic counters at a regular
#    interval, which include syscall drop statistics and additional metrics,
#    explore the `metrics` configuration option.
#    See the template for available keys.
#
# @param metrics
#    A hash to generate "Falco internal: metrics snapshot" rule output when `priority=info` at minimum
#    By selecting `output_file`, equivalent JSON output will be appended to a file.
#    See the template for available keys.
#
# @param base_syscalls
#    A hash to defne which syscalls are being tracked by falco
#    See the template for available keys.
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
# @param falcoctl_install_options
#    Extra flags to pass to falco-driver-loader
#
# @param falcoctl_install_env
#    Pass environment variables when running falco-driver-loader
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
  Array[Stdlib::Absolutepath] $rules_files = [
    '/etc/falco/falco_rules.yaml',
    '/etc/falco/falco_rules.local.yaml',
    '/etc/falco/k8s_audit_rules.yaml',
    '/etc/falco/rules.d',
  ],

  Array[Stdlib::Absolutepath] $config_files = [
    '/etc/falco/config.d',
  ],
  Array[Hash] $local_rules = [],
  Hash $engine_options = {
    'buf_size_preset' => 4,
    'drop_failed_exit' => false,
  },
  Optional[Array[String]] $load_plugins = undef,
  Optional[Array[Hash]] $plugins = undef,
  Boolean $watch_config_files = true,
  Boolean $time_format_iso_8601 = false,
  Enum['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'] $priority = 'debug',
  Boolean $json_output = false,
  Boolean $json_include_output_property = true,
  Boolean $json_include_tags_property = true,
  Boolean $buffered_outputs = false,
  Enum['first', 'all'] $rule_matching = 'first',
  Integer $outputs_queue_capacity = 0,
  Boolean $stdout_output = true,
  Boolean $syslog_output = true,
  Hash[String, Variant[Boolean, Stdlib::Unixpath]] $file_output = {
    'enabled'    => true,
    'keep_alive' => false,
    'filename'   => '/var/log/falco-events.log',
  },
  Boolean $enable_logrotate = true,
  Hash[String, Variant[Boolean, String]] $http_output = {
    'enabled'          => false,
    'url'              => 'http://some.url',
    'user_agent'       => 'falcosecurity/falco',
    'insecure'         => false,
    'ca_cert'          => '',
    'ca_bundle'        => '',
    'ca_path'          => '/etc/ssl/certs',
    'mtls'             => false,
    'client_cert'      => '/etc/ssl/certs/client.crt',
    'client_key'       => '/etc/ssl/certs/client.key',
    'echo'             => false,
    'compress_uploads' => false,
    'keep_alive'       => false,
  },
  Hash[String, Variant[Boolean, String]] $program_output = {
    'enabled'    => false,
    'keep_alive' => false,
    'program'    => "jq '{text: .output}' | curl -d @- -X POST https://hooks.slack.com/services/XXX",
  },
  Boolean $grpc_output = false,
  Hash[String, Variant[Integer, Boolean, String]] $grpc = {
    'enabled'      => false,
    'bind_address' => 'unix:///run/falco/falco.sock',
    'threadiness'  => 0,
  },
  Hash[String, Variant[Boolean, Integer, Stdlib::Unixpath, Stdlib::IP::Address]] $webserver = {
    'enabled' => true,
    'threadiness' => 0,
    'listen_port' => 8765,
    'listen_address' => '0.0.0.0',
    'k8s_healthz_endpoint' => '/healthz',
    'prometheus_metrics_enabled' => false,
    'ssl_enabled' => false,
    'ssl_certificate' => '/etc/falco/falco.pem',
  },
  Boolean $log_stderr = true,
  Boolean $log_syslog = true,
  Enum['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'] $log_level = 'info',
  Hash[String, Variant[Boolean, String]] $libs_logger = {
    'enabled' => false,
    'severity' => 'debug',
  },
  Integer $output_timeout = 2000,
  Integer $syscall_event_timeouts_max_consecutives = 1000,
  Hash[String, Variant[Array, String, Integer, Boolean]] $syscall_event_drops = {
    'threshold' => '.1',
    'actions' => ['log', 'alert'],
    'rate' => '.03333',
    'max_burst' => 1,
    'simulate_drops' => false,
  },
  Hash[String, Variant[Boolean, String]] $metrics = {
    'enabled' => false,
    'interval' => '1h',
    'output_rule' => true,
    'rules_counters_enabled' => true,
    'resource_utilization_enabled' => true,
    'state_counters_enabled' => true,
    'kernel_event_counters_enabled' => true,
    'libbpf_stats_enabled' => true,
    'convert_memory_to_mb' => true,
    'include_empty_values' => false,
  },
  Hash[String, Variant[Array[String], Boolean]] $base_syscalls = {
    'custom_set' => [],
    'repair' => false,
  },
  Integer $thread_table_size = 262144,

  Enum['ebpf', 'modern_ebpf', 'kmod'] $engine_kind = 'kmod',

  # Parameters for falcoctl command
  Hash $falcoctl_driver_config = {
    'type'     => 'kmod',
    'name'     => 'falco',
    'repos'    => ['https://download.falco.org/driver'],
    'version'  => '7.0.0+driver',
    'hostroot' => '/',
  },
  Array $falcoctl_install_options = [
    '--compile=true',
    '--download=false',
  ],
  Array $falcoctl_install_env = [],

  Boolean $manage_repo = true,

  # Installation parameters
  String[1] $package_ensure = '>= 0.37.1',

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
