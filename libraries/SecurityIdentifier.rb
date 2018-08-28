class SecurityIdentifier < Inspec.resource(1)
  name 'security_identifier'
  supports platform: 'windows'
  desc 'Resource that returns a Security Identifier for a given entity name in Windows. Because different entities can have the same name (e.g. a user and group can both be called \'devops\') the resource requires the type of the entity (:user, :group) to be stated to avoid an ambiguous test'
  example "
    describe security_policy do
      its(\"SeRemoteInteractiveLogonRight\") { should_not include security_identifier(group: 'Guests') }
    end
  "

  def initialize(opts = {})
    supported_opt_keys = [:user, :group]
    raise "Invalid security_identifier param '#{opts}'. Please pass a hash with these supported keys: #{supported_opt_keys}" unless opts.respond_to?(:keys)
    raise "Unsupported security_identifier options '#{opts.keys - supported_opt_keys}'. Supported keys: #[supported_opt_keys]" unless (opts.keys - supported_opt_keys).empty? 
    @user = opts[:user]
    @group = opts[:group]
    raise 'Specify either :user or :group for security_identifier' unless @user || @group 
    raise 'Specifying both :user and :group for security_identifier is not supported' if @user && @group
    @sids = nil
  end

  def sid
    fetch_sids unless @sids
    entity = @user || @group
    @sids[entity].to_s || entity
  end

  def fetch_sids
    @sids = {}
    wmi_query = "wmic group where 'Name=\"#{@group}\"' get Name\",\"SID /format:csv"
    wmi_query = "wmic useraccount where 'Name=\"#{@user}\"' get Name\",\"SID /format:csv" if @user
    sid_data = inspec.command(wmi_query).stdout.strip.split("\r\n\r\n")[1..-1].map { |entry| entry.split(',') }
    sid_data.each { |sid| @sids[sid[1]] = sid[2] }
  end
end
