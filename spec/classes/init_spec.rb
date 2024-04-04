# frozen_string_literal: true

require 'spec_helper'

describe 'falco' do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) { facts }
      let(:suse_kernel_patch_level) { '120' }

      context 'with defaults for all parameters' do
        it { is_expected.to compile.with_all_deps }

        it {
          is_expected.to contain_class('falco').
            with_rules_file([
                              '/etc/falco/falco_rules.yaml',
                              '/etc/falco/falco_rules.local.yaml',
                              '/etc/falco/k8s_audit_rules.yaml',
                              '/etc/falco/rules.d'
                            ])
        }

        it { is_expected.to contain_class('falco::repo') }

        it { is_expected.to contain_package('dkms') }
        it { is_expected.to contain_package('make') }
        it { is_expected.to contain_package('llvm') }
        it { is_expected.to contain_package('clang') }

        case facts[:os]['family']
        when 'Debian'
          it { is_expected.to contain_apt__key('falcosecurity') }
          it { is_expected.to contain_apt__source('falco') }
          it { is_expected.to contain_package("linux-headers-#{facts[:kernelrelease]}") }
        when 'RedHat'
          it { is_expected.to contain_class('epel') }
          it { is_expected.to contain_yumrepo('falco') }
          it { is_expected.to contain_package("kernel-devel-#{facts[:kernelrelease]}") }
        when 'Suse'
          it { is_expected.to contain_zypprepo('falcosecurity-rpm') }
          it { is_expected.to contain_package("kernel-default-devel-#{facts[:kernelversion]}-#{suse_kernel_patch_level}") }
          it { is_expected.to contain_rpmkey('4021833E14CB7A8D') }

          case facts[:os]['release']['full']
          when '12.5'
            it { is_expected.to contain_rpmkey('3A6A4D911FCCBD0A') }
            it { is_expected.to contain_zypprepo('home:BuR_Industrial_Automation:SLE-12-SP5:basesystem (SLE_12_SP5)') }
          end
        end

        it { is_expected.to contain_class('falco::install') }
        it { is_expected.to contain_exec('falcoctl driver install --compile=true --download=false') }
        it { is_expected.to contain_package('falco') }

        it { is_expected.to contain_class('falco::config') }

        it {
          is_expected.to contain_file('/etc/falco/falco.yaml').
            with_content(%r{rules_file:\n  - /etc/falco/falco_rules.yaml\n})
        }

        it {
          is_expected.to contain_file('/etc/falco/falco_rules.local.yaml').
            with_content(%r{# Or override/append to any rule, macro, or list from the Default Rules\n\n$})
        }

        it {
          is_expected.to contain_file('/etc/falcoctl/falcoctl.yaml').
            with_content(%r{    hostroot: /$})
        }

        it { is_expected.to contain_class('falco::service') }
        it { is_expected.to contain_service('falco-kmod') }
      end

      context 'with bpf driver' do
        let(:facts) do
          facts.merge(
            { falco_driver_version: '7.0.0+driver' }
          )
        end
        let(:engine_kind) { 'ebpf' }
        let(:params) do
          {
            'engine_kind' => engine_kind
          }
        end
        it { is_expected.to contain_exec('falcoctl driver install --compile=true --download=false').with(
          { creates: "/root/.falco/7.0.0+driver/#{facts[:architecture]}/falco_#{facts[:operatingsystem].downcase}_#{facts[:kernelrelease]}_1.o" }
        )
       }
        it { is_expected.to contain_service('falco-bpf') }
      end

      context 'with modern-bpf driver' do
        let(:engine_kind) { 'modern_bpf' }
        let(:params) do
          {
            'engine_kind' => engine_kind
          }
        end

        it { is_expected.not_to contain_exec('falcoctl driver install --compile=true --download=false') }

        case facts[:os]['family']
        when 'Debian'
          it { is_expected.not_to contain_package("linux-headers-#{facts[:kernelrelease]}") }
        when 'RedHat'
          it { is_expected.not_to contain_package("kernel-devel-#{facts[:kernelrelease]}") }
        when 'Suse'
          it { is_expected.not_to contain_package("kernel-default-devel-#{facts[:kernelversion]}-#{suse_kernel_patch_level}") }
        end

        it { is_expected.to contain_service('falco-modern-bpf') }
      end

      context 'with auto_ruleset_updates disabled' do
        let(:params) do
          {
            'auto_ruleset_updates' => false
          }
        end

        it { is_expected.to contain_service('falcoctl-artifact-follow').with_ensure('stopped').with_enable('mask') }
      end

      context 'with file_output defined' do
        let(:params) do
          {
            'file_output' => {
              'enabled' => true,
              'keep_alive' => false,
              'filename' => '/var/log/somefolder/falco-events.log'
            }
          }
        end

        it { is_expected.to contain_logrotate__rule('falco_output').with_path('/var/log/somefolder/falco-events.log') }
      end

      context 'with file_output disabled' do
        let(:params) do
          {
            'file_output' => {
              'enabled' => false,
            }
          }
        end

        it { is_expected.not_to contain_class('logrotate::rule') }
        it { is_expected.not_to contain_logrotate__rule('falco_output') }
      end

      context 'with local_rules value specified' do
        # rubocop:disable Style/WordArray
        let(:params) do
          {
            'local_rules' => [
              {
                'rule' => 'The program "sudo" is run in a container',
                'desc' => 'An event will trigger every time you run sudo in a container',
                'condition' => 'evt.type = execve and evt.dir=< and container.id != host and proc.name = sudo',
                'output' => 'Sudo run in container (user=%user.name %container.info parent=%proc.pname cmdline=%proc.cmdline)',
                'priority' => 'ERROR',
                'tags' => ['users', 'container'],
              },
              {
                'rule' => 'rule 2',
                'desc' => 'describing rule 2',
                'condition' => 'evt.type = execve and evt.dir=< and container.id != host and proc.name = sudo',
                'output' => 'Sudo run in container (user=%user.name %container.info parent=%proc.pname cmdline=%proc.cmdline)',
                'priority' => 'ERROR',
                'tags' => ['users'],
              },
              {
                'list' => 'shell_binaries',
                'items' => ['bash', 'csh', 'ksh', 'sh', 'tcsh', 'zsh', 'dash'],
              },
              {
                'list' => 'userexec_binaries',
                'items' => ['sudo', 'su'],
              },
              {
                'list' => 'known_binaries',
                'items' => ['shell_binaries', 'userexec_binaries'],
              },
              {
                'macro' => 'safe_procs',
                'condition' => 'proc.name in (known_binaries)',
              }
            ],
          }
        end
        # rubocop:enable Style/WordArray

        # Mad props to @alexjfisher on GitHub for teaching me about this way of testing the resulting yaml is valid
        # It is SO MUCH CLEANER than doing regex matches for different lines in the resulting file.
        let(:content) do
          catalogue.resource('file', '/etc/falco/falco_rules.local.yaml').send(:parameters)[:content]
        end

        let(:parsed_content) do
          YAML.safe_load(content)
        end

        # Ordering matters within this yaml file so each element is tested to verify it is in the proper location
        it 'contains the proper yaml structure' do
          expect(parsed_content.length).to eq(6)

          expect(parsed_content[0]).to include(
            'rule' => 'The program "sudo" is run in a container',
            # The two lines below are important to validate because they get reformatted if the line_width param is not passed to to_yaml
            'condition' => 'evt.type = execve and evt.dir=< and container.id != host and proc.name = sudo',
            'output' => 'Sudo run in container (user=%user.name %container.info parent=%proc.pname cmdline=%proc.cmdline)'
          )

          expect(parsed_content[1]).to include(
            'rule' => 'rule 2',
            'tags' => ['users']
          )

          expect(parsed_content[2]).to include('list' => 'shell_binaries')

          expect(parsed_content[3]).to include('list' => 'userexec_binaries')

          expect(parsed_content[4]).to include('list' => 'known_binaries')

          expect(parsed_content[5]).to include(
            'macro' => 'safe_procs',
            'condition' => 'proc.name in (known_binaries)'
          )
        end
      end
    end
  end
end
