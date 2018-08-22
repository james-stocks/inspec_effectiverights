class SecurityIdentifier < Inspec.resource(1)
  # Resource that returns a Security ID for a given entity name in Windows
  # If there is no SID for this entity, echo back the entity name.
  name 'security_identifier'

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
