# Changelog

All notable changes to this project will be documented in this file.
Each new release typically also includes the latest modulesync defaults.
These should not affect the functionality of the module.

## [v3.0.1](https://github.com/voxpupuli/puppet-falco/tree/v3.0.1) (2023-07-17)

[Full Changelog](https://github.com/voxpupuli/puppet-falco/compare/v3.0.0...v3.0.1)

**Merged pull requests:**

- Fix falco fact [\#31](https://github.com/voxpupuli/puppet-falco/pull/31) ([hunner](https://github.com/hunner))

## [v3.0.0](https://github.com/voxpupuli/puppet-falco/tree/v3.0.0) (2023-07-06)

[Full Changelog](https://github.com/voxpupuli/puppet-falco/compare/v2.0.0...v3.0.0)

**Breaking changes:**

- Drop Puppet 6 support [\#27](https://github.com/voxpupuli/puppet-falco/pull/27) ([bastelfreak](https://github.com/bastelfreak))

**Implemented enhancements:**

- Add feature flag to enable/disable managing of the falco repository [\#24](https://github.com/voxpupuli/puppet-falco/pull/24) ([jordyb6](https://github.com/jordyb6))
- Add watch\_config \_files parameter [\#23](https://github.com/voxpupuli/puppet-falco/pull/23) ([jordyb6](https://github.com/jordyb6))

**Fixed bugs:**

- Make falco file output really optional [\#28](https://github.com/voxpupuli/puppet-falco/pull/28) ([claviola](https://github.com/claviola))
- Fix falco-driver-loader bpf [\#26](https://github.com/voxpupuli/puppet-falco/pull/26) ([jordyb6](https://github.com/jordyb6))
- Fix: Add missing dependencies when building bpf probe [\#25](https://github.com/voxpupuli/puppet-falco/pull/25) ([jordyb6](https://github.com/jordyb6))

## [v2.0.0](https://github.com/voxpupuli/puppet-falco/tree/v2.0.0) (2023-04-13)

[Full Changelog](https://github.com/voxpupuli/puppet-falco/compare/v1.2.0...v2.0.0)

**Breaking changes:**

- \(ITSYS-2824\) Falco \>= 0.34.0 Compatibility [\#20](https://github.com/voxpupuli/puppet-falco/pull/20) ([yachub](https://github.com/yachub))

## [v1.2.0](https://github.com/voxpupuli/puppet-falco/tree/v1.2.0) (2023-04-11)

[Full Changelog](https://github.com/voxpupuli/puppet-falco/compare/v1.1.0...v1.2.0)

**Implemented enhancements:**

- Add support for SUSE Linux, add EL 9 to metadata [\#13](https://github.com/voxpupuli/puppet-falco/pull/13) ([genebean](https://github.com/genebean))

**Fixed bugs:**

- Apt key errors [\#16](https://github.com/voxpupuli/puppet-falco/issues/16)
- Update repo keys [\#17](https://github.com/voxpupuli/puppet-falco/pull/17) ([genebean](https://github.com/genebean))

## [v1.1.0](https://github.com/voxpupuli/puppet-falco/tree/v1.1.0) (2022-06-01)

[Full Changelog](https://github.com/voxpupuli/puppet-falco/compare/v1.0.1...v1.1.0)

**Implemented enhancements:**

- Allow local rules to be applied; require puppetlabs/stdlib 8.2 or newer [\#11](https://github.com/voxpupuli/puppet-falco/pull/11) ([genebean](https://github.com/genebean))

## [v1.0.1](https://github.com/voxpupuli/puppet-falco/tree/v1.0.1) (2022-05-25)

[Full Changelog](https://github.com/voxpupuli/puppet-falco/compare/v1.0.0...v1.0.1)

**Closed issues:**

- release workflow has wrong owner listed [\#9](https://github.com/voxpupuli/puppet-falco/issues/9)

## [v1.0.0](https://github.com/voxpupuli/puppet-falco/tree/v1.0.0) (2022-05-24)

[Full Changelog](https://github.com/voxpupuli/puppet-falco/compare/v0.4.0...v1.0.0)

This is the first release as part of Vox Pupuli.
This module is derrived from [falcosecurity/evolution](https://github.com/falcosecurity/evolution/tree/33a3025d1dedc3a6fbea814b8f3f80d275d6e3f0/integrations/puppet-module/falco). That code came from [falcosecurity/falco](https://github.com/falcosecurity/falco) as part of resolving issue https://github.com/falcosecurity/falco/issues/1114. The old code is the basis for [sysdig/falco](https://forge.puppet.com/modules/sysdig/falco). https://github.com/falcosecurity/falco/issues/2005 was submitted to request that module be depreciated since it appears to be abandoned.

The v1.0.0 release includes an overhaul of the code to make everything work and bring it up to current coding standards. It also incorporates all the change needed as part of migrating a module to Vox Pupuli.

**Breaking changes:**

- Rework module post-fork [\#1](https://github.com/voxpupuli/puppet-falco/pull/1) ([genebean](https://github.com/genebean))

**Fixed bugs:**

- Fix default value for program\_output [\#6](https://github.com/voxpupuli/puppet-falco/pull/6) ([genebean](https://github.com/genebean))

**Closed issues:**

- Falco crashes due to formatting error in config file [\#7](https://github.com/voxpupuli/puppet-falco/issues/7)
- Update metadata.json to reflect transfer to Vox Pupuli [\#2](https://github.com/voxpupuli/puppet-falco/issues/2)

**Merged pull requests:**

- Add missing files, update metadata post-migration [\#3](https://github.com/voxpupuli/puppet-falco/pull/3) ([genebean](https://github.com/genebean))

## [v0.4.0](https://github.com/voxpupuli/puppet-falco/tree/v0.4.0) (2022-05-19)

[Full Changelog](https://github.com/voxpupuli/puppet-falco/compare/d5252f4d06d4e1c5285e5fe3ac23716f2ee47afb...v0.4.0)



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*