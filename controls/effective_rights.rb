control 'demonstrate effective rights tests' do
  sys_exes = command('ls C:\\windows\\system32\\EventVwr.exe | % FullName').stdout.tr("\r\n", "\n").split("\n").reject { |blank| blank == "" }
  sys_exes.each do |sys_exe|
    describe file_permissions(sys_exe) do
      its('Administrators') { should include 'ReadAndExecute' }
      its('Administrators') { should_not include 'Write' }
      its('Guest') { should eq [] }
      # Guests should be forbidden read and execute
      its('ReadAndExecute') { should include 'Administrators' }
      its('ReadAndExecute') { should_not include 'S-1-5-32-546' } 
    end
  end
end
