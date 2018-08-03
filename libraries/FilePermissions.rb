class FilePermissions < Inspec.resource(1)
  name 'file_permissions'

  def initialize(filename, options = {})
    @filename = filename
    @results = nil
  end

  def method_missing(name)
    @results ||= fetch_results
    return @results[name] if @results.has_key?(name)
  end

  def to_s
    "File permissions #{@filename}"
  end

  private

  def fetch_results
    {'Administrator': ['Write'],
     'Guest': ['Write']
    }
  end
end
