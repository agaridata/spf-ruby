# encoding: ASCII-8BIT
require 'ip'

require 'spf/error'

class SPF::Request

  attr_reader :scope, :identity, :domain, :localpart, :ip_address, :ip_address_v6, :helo_identity, :versions, :sub_requests
  attr_accessor :record, :opt, :root_request, :super_request

  VERSIONS_FOR_SCOPE = {
    :helo  => [1   ],
    :mfrom => [1, 2],
    :pra   => [   2]
  }

  SCOPES_BY_VERSION = {
    1      => [:helo, :mfrom      ],
    2      => [       :mfrom, :pra]
  }

  DEFAULT_LOCALPART = 'postmaster'

  def initialize(options = {})
    @opt              = options
    @state            = {}
    @versions         = options[:versions]
    @scope            = options[:scope] || :mfrom
    @scope            = @scope.to_sym if String === @scope
    @authority_domain = options[:authority_domain]
    @identity         = options[:identity]
    @ip_address       = options[:ip_address]
    @helo_identity    = options[:helo_identity]
    @root_request     = self
    @super_request    = self
    @record           = nil
    @sub_requests     = []

    # Scope:
    versions_for_scope = VERSIONS_FOR_SCOPE[@scope] or
      raise SPF::InvalidScopeError.new("Invalid scope '#{@scope}'")

    # Versions:
    if @versions
      if Fixnum === @versions
        # Single version specified as a Fixnum:
        @versions = [@versions]
      elsif not Array === @versions
        # Something other than Fixnum or array specified:
        raise SPF::InvalidOptionValueError.new("'versions' option must be symbol or array")
      end

      # All requested record versions must be supported:
      unsupported_versions = @versions.select { |x|
        not SCOPES_BY_VERSION[x]
      }
      if unsupported_versions.any?
        raise SPF::InvalidOptionValueError.new(
          "Unsupported record version(s): " +
          unsupported_versions.map { |x| "'#{x}'" }.join(', '))
      end
    else
      # No versions specified, use all versions relevant to scope:
      @versions = versions_for_scope
    end

    versions = @versions.select {|x| versions_for_scope.include?(x)}
    if versions.empty?
      raise SPF::InvalidScopeError.new(
        "Invalid scope '#{@scope}' for record version(s) #{@versions}"
      )
    end
    @versions = versions

    # Identity:
    raise SPF::OptionRequiredError.new(
      "Missing required 'identity' option") unless @identity
    raise SPF::InvalidOptionValueError.new(
      "'identity' option must not be empty") if @identity.empty?

    # Extract domain and localpart from identity:
    if ((@scope == :mfrom or @scope == :pra) and
        @identity =~ /^(.*)@(.*?)$/)
      @localpart = $1
      @domain    = $2
    else
      @domain    = @identity
    end
    # Lower-case domain and removee eventual trailing dot.
    @domain.downcase!
    @domain.chomp!('.')
    if (not self.instance_variable_defined?(:@localpart) or
        not @localpart or not @localpart.length > 0)
      @localpart = DEFAULT_LOCALPART
    end

    # HELO identity:
    if @scope == :helo
      @helo_identity ||= @identity
    end

    return unless @ip_address

    # Ensure ip_address is an IP object:
    unless IP === @ip_address
      @ip_address = IP.new(@ip_address)
    end

    # Convert IPv4 address to IPv4-mapped IPv6 address:

    if SPF::Util.ipv6_address_is_ipv4_mapped(@ip_address)
      @ip_address_v6 = @ip_address # Accept as IPv6 address as-is
      @ip_address = SPF::Util.ipv6_address_to_ipv4(@ip_address)
    elsif IP::V4 === @ip_address
      @ip_address_v6 = SPF::Util.ipv4_address_to_ipv6(@ip_address)
    elsif IP::V6 === @ip_address
      @ip_address_v6 = @ip_address
    else
      raise SPF::InvalidOptionValueError.new("Unexpected IP address version");
    end
  end

  def new_sub_request(options)
    obj = self.class.new(@opt.merge(options))
    obj.super_request = self
    obj.root_request  = super_request.root_request
    @sub_requests << obj
    return obj
  end

  def authority_domain
    return (@authority_domain or @domain)
  end

  def state(field, value = nil)
    unless field
      raise SPF::OptionRequiredError.new('Field name required')
    end
    if value
      if Fixnum === value
        @state[field] = 0 unless @state[field]
        return (@state[field] += value)
      else
        return (@state[field] = value)
      end
    else
      return @state[field]
    end
  end
end

# vim:sw=2 sts=2
