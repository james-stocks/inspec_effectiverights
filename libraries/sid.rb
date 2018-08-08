class Sid < Inspec.resource(1)
  # Resource that returns a Security ID for a given entity name in Windows
  name 'sid'

  def initialize(name)
    @name = name
    @sids = nil
    fetch_sids
    @sid = @sids[@name] || ''
  end

  def to_s
    fetch_sids unless @sids
    @sid = @sids[@name].to_s || ''
    @sid
  end

  def fetch_sids
    @sids = {}
    # This could be more specific and only query for @name - but with Inspec command caching, it may save time to have all the results cached?
    sid_data = inspec.command('wmic group get Name","SID /format:csv').stdout.strip.split("\r\n\r\n")[1..-1].map { |entry| entry.split(',') }
    sid_data.each { |sid| @sids[sid[1]] = sid[2] }
  end
end
