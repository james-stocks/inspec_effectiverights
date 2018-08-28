control 'demonstrate testing a security descriptor' do
  administrators = security_identifier(group: 'Administrators').sid

  describe security_descriptor('C:\\windows\\system32\\EventVwr.exe') do
    its(administrators) { should include 'ReadAndExecute' }
    its(administrators) { should_not include 'Write' }
    its('Guest') { should eq [] }
    # Guests should be forbidden read and execute
    its('ReadAndExecute') { should include security_identifier(group: 'Administrators').sid }
    its('ReadAndExecute') { should_not include security_identifier(user: 'Administrator').sid }
    its('ReadAndExecute') { should_not include security_identifier(user: 'Doesnt Exist').sid }
    its('ReadAndExecute') { should include security_identifier(unspecified: 'Administrators').sid }
    its('ReadAndExecute') { should_not include 'S-1-5-32-546' } 
  end
end
