control 'demonstrate effective rights tests' do
  sys_exes = command('ls C:\\windows\\system32\\EventVwr.exe | % FullName').stdout.tr("\r\n", "\n").split("\n").reject { |blank| blank == "" }
  sys_exes.each do |sys_exe|
    describe file_permissions(sys_exe) do
      its('Administrator') { should include 'Write' }
      its('Guest') { should eq ['ReadAndExecute' , 'Synchronize'] }
    end
  end
end
