Facter.add(:falco_driver_version) do
    confine :kernel => :Linux
    setcode do
      if Facter::Util::Resolution.which('falco')
        falco_driver_version = Facter::Util::Resolution.exec('falco --version')
        falco_driver_version.match(/\d+\.\d+\.\d+\+driver/).to_s
      end
    end
  end
