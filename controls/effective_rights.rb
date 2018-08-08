control 'demonstrate effective rights tests' do
  administrators = sid('Administrators').to_s
  sys_exes = command('ls C:\\windows\\system32\\EventVwr.exe | % FullName').stdout.tr("\r\n", "\n").split("\n").reject { |blank| blank == "" }
  sys_exes.each do |sys_exe|
    describe file_permissions(sys_exe) do
      its(administrators) { should include 'ReadAndExecute' }
      its(administrators) { should_not include 'Write' }
      its('Guest') { should eq [] }
      # Guests should be forbidden read and execute
      its('ReadAndExecute') { should include sid('Administrators').to_s }
      its('ReadAndExecute') { should_not include 'S-1-5-32-546' } 
    end
  end
end
