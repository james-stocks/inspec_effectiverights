class Sid < Inspec.resource(1)
  # Resource that returns a Security ID for a given entity name in Windows
  # If there is no SID for this entity, echo back the entity name.
  name 'sid'

  def initialize(name)
    @name = name
    @sids = nil
    fetch_sids
    @sid = @sids[@name] || @name
  end

  def to_s
    fetch_sids unless @sids
    @sid = @sids[@name].to_s || @name
    @sid
  end

  def fetch_sids
    @sids = {}
    # This could be more specific and only query for @name - but with Inspec command caching, it may save time to have all the results cached?
    sid_data = inspec.command('wmic group get Name","SID /format:csv').stdout.strip.split("\r\n\r\n")[1..-1].map { |entry| entry.split(',') }
    sid_data.each { |sid| @sids[sid[1]] = sid[2] }
  end
end
