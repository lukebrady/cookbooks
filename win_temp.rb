# Author:: Luke Brady (<luke.brady@ung.edu>)
# Cookbook Name:: windows
# Recipe:: ung_win_temp
#
# Copyright:: 2011-2015, University of North Georgia.
# Creates the University of North Georgia Windows Server Template.

# Sets a scheduled task for Chef-Client to run every 30 mins.
windows_task 'chef-client' do
  user 'AD\luke'
  password 'Lbrad23105'
  cwd 'C:\\chef\\bin'
  command 'chef-client -L C:\\tmp\\'
  run_level :highest
  frequency :minute
  frequency_modifier 30
end

# Installs the Desired State Configuration service.
windows_feature 'DSC-Service' do
  action :install
end

# Adds the SNMP Feauture to the server.
powershell_script 'add_snmp' do
  code 'Add-WindowsFeature SNMP-Service | Add-WindowsFeature -IncludeManagementTools | Out-Null'
  guard_interpreter :powershell_script
  not_if "(Get-WindowsFeature -Name SNMP-Service).InstalledState -eq 'Installed'"
end

# Configures SNMP with Desired State Configuration.
dsc_script 'config_snmp' do
  code <<-EOH
#Module for configuring WMI on all servers, must be installed. 
Install-Module WmiNamespaceSecurity -Scope AllUsers
$node = $env:COMPUTERNAME
#Configuration that sets WMI settings on production servers.
configuration WMINameSpaceConfig
{

    Import-DscResource -ModuleName WmiNameSpaceSecurity 
    node $node{
        WmiNameSpaceSecurity svc-wug
        {
            
            Path = "root/cimv2"
            Principal = 'SVC-WUG'
            AccessType = 'Allow'
            AppliesTo = 'Children'
            Permission = "Enable","RemoteAccess","ReadSecurity","MethodExecute"
            Ensure = 'Present'

        }
    }
}

WmiNameSpaceConfig -OutputPath C:\
Start-DSCConfiguration -Path C:\ -Wait -Verbose -Force
  EOH
end

# Adds the Windows Server Backup feature to the server.
powershell_script 'add_win_serv_backup' do
  code 'Add-WindowsFeature Windows-Server-Backup'
  guard_interpreter :powershell_script
  not_if "(Get-WindowsFeature -Name Windows-Server-Backup).InstalledState -eq 'Installed'"
end

# Enables remote management.
powershell_script 'enable_winrm' do
  code 'winrm qc -force; Update-Help'
  guard_interpreter :powershell_script
end

# Enables firewall logging. Needs to be testes further.
powershell_script 'enable_logging' do
  code 'Set-NetFirewallProfile -LogAllowed $true -LogFileName %windir%\system32\logfiles\firewall\pfirewall.log'
  guard_interpreter :powershell_script
end

powershell_script 'disable_firewall' do
  code 'Disable-NetFireWallRule -All'
  guard_interpreter :powershell_script
end

# Adds the computer to the domain.
powershell_script 'join_domain' do
  code <<-EOH
  $domain = "AD"
  $username = "luke"
  $password = "Lbrad23105"
  $credential = New-Object System.Management.Automation.PSCredential($username,$password)
  Add-Computer -DomainName $domain -Credential $credential
  EOH
  guard_interpreter :powershell_script
end

# Creates the sxs directory for .NET 3.5
directory 'C:\\Windows\\System32\\SXS' do
  owner 'Administrator'
  group 'Administrator'
  mode '0755'
  action :create
end

# Diables IPv6 in the registry.
windows_registry 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' do
  # This value disables all IPv6 components except loopback
  values 'DisableComponents' => 0xff
end

# Creates the SSL 2.0 Client Key and then disables it.
windows_registry 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' do
  action :create
  values 'Enable' => 0
end

# Creates the SSL 2.0 Server Key and then disables it.
windows_registry 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' do
  action :create
  values 'Enable' => 0
end

# Creates the SSL 3.0 Client Key and then disables it.
windows_registry 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' do
  action :create
  values 'Enable' => 0
end

# Creates the SSL 3.0 Server Key and then disables it.
windows_registry 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' do
  action [:create, :force_modify]
  values 'Enable' => 0
end

# Disables UAC in the registry.
windows_registry 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system' do
  values 'EnableLUA' => 0
end

# Installs the Telnet server and client and then enables them.
%w(TelnetServer TelnetClient).each do |feature|
  windows_feature feature do
    action [:install, :enable]
  end
end






