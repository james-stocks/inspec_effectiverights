class FilePermissions < Inspec.resource(1)
  name 'file_permissions'

  def initialize(filename, options = {})
    @filename = filename
    @results = nil
    @group_names = nil
  end

  %w{Read ReadAndExecute Modify Sychronize FullControl}.each do |perm|
    define_method perm do
      fetch_results unless @results
      # Return keys that have this permission, with the domain stripped
      @results.select { |k,v| v.include?(perm) }.keys.map { |key| key.split("\\")[-1] }
    end
  end

  def method_missing(name)
    fetch_results unless @results
    # Return the results for this entity if it exists (with some domain name) in the result set
    entity_key = @results.keys.select { |key| key.split("\\")[-1] == name.to_s }[0]
    return @results[entity_key] if entity_key
    # Entity not in the result set is "no permissions"
    []
  end

  def to_s
    "File permissions #{@filename}"
  end

  private

  def fetch_results
    @results = {}
    fetch_group_names unless @group_names
    cmd = inspec.powershell("Get-Acl #{@filename} | select -expand access")
    raise cmd.stderr.strip unless cmd.stderr == ''
    access_details = cmd.stdout.strip.split("\r\n\r\n").map { |entry| entry.split("\r\n") }
    access_details.each do |access_detail|
      entity = access_detail.select { |a| a =~ %r{^IdentityReference} }[0].tr(' ', '').split(':')[-1]
      permissions = access_detail.select { |a| a =~ %r{^FileSystemRights} }[0].tr(' ', '').split(':')[-1].split(',')
      # Replace the entity name from Get-Acl with a SID where possible
      entity = @group_names[entity.split("\\")[-1]] if @group_names.has_key? entity.split("\\")[-1]
      @results[entity] = permissions
    end
  end

  def fetch_group_names
    @group_names = {}
    group_data = inspec.command('wmic group get Name","SID /format:csv').stdout.strip.split("\r\n\r\n")[1..-1].map { |entry| entry.split(',') }
    group_data.each { |group| @group_names[group[1]] = group[2] }
  end
end
