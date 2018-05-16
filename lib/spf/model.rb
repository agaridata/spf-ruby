# encoding: ASCII-8BIT
require 'ip'

require 'spf/util'


class IP
  def contains?(ip_address)
    return (
      self.to_irange.first <= ip_address.to_i and
      self.to_irange.last  >= ip_address.to_i)
  end
end


class SPF::Record
  DEFAULT_QUALIFIER    = '+';
end

class SPF::Term

  NAME_PATTERN               = '[[:alpha:]] [[:alnum:]\\-_\\.]*'

  MACRO_LITERAL_PATTERN      = "[!-$&-~%]"
  MACRO_DELIMITER            = "[\\.\\-+,\\/_=]"
  MACRO_TRANSFORMERS_PATTERN = "\\d*r?"
  MACRO_EXPAND_PATTERN       = "
      %
      (?:
          { [[:alpha:]] } #{MACRO_TRANSFORMERS_PATTERN} #{MACRO_DELIMITER}* } |
          [%_-]
      )
  "

  MACRO_STRING_PATTERN                    = "
      (?:
          #{MACRO_EXPAND_PATTERN}  |
          #{MACRO_LITERAL_PATTERN}
      )*
  "

  TOPLABEL_PATTERN                        = "
      [[:alnum:]_-]+ - [[:alnum:]-]* [[:alnum:]] |
      [[:alnum:]]*   [[:alpha:]]   [[:alnum:]]*
  "

  DOMAIN_END_PATTERN         = "
    (?: \\. #{TOPLABEL_PATTERN} \\.? |
            #{MACRO_EXPAND_PATTERN}
    )
  "

  DOMAIN_SPEC_PATTERN        = " #{MACRO_STRING_PATTERN} #{DOMAIN_END_PATTERN} "

  QNUM_PATTERN               = " (?: 25[0-5] | 2[0-4]\\d | 1\\d\\d | [1-9]\\d | \\d ) "
  IPV4_ADDRESS_PATTERN       = " #{QNUM_PATTERN} (?: \\. #{QNUM_PATTERN}){3} "

  HEXWORD_PATTERN            = "[[:xdigit:]]{1,4}"

  TWO_HEXWORDS_OR_IPV4_ADDRESS_PATTERN = /
      #{HEXWORD_PATTERN} : #{HEXWORD_PATTERN} | #{IPV4_ADDRESS_PATTERN}
  /x

  IPV6_ADDRESS_PATTERN       = "
    #                x:x:x:x:x:x:x:x |     x:x:x:x:x:x:n.n.n.n
    (?: #{HEXWORD_PATTERN} : ){6}                                   #{TWO_HEXWORDS_OR_IPV4_ADDRESS_PATTERN} |
    #                 x::x:x:x:x:x:x |      x::x:x:x:x:n.n.n.n
    (?: #{HEXWORD_PATTERN} : ){1}   : (?: #{HEXWORD_PATTERN} : ){4} #{TWO_HEXWORDS_OR_IPV4_ADDRESS_PATTERN} |
    #               x[:x]::x:x:x:x:x |    x[:x]::x:x:x:n.n.n.n
    (?: #{HEXWORD_PATTERN} : ){1,2} : (?: #{HEXWORD_PATTERN} : ){3} #{TWO_HEXWORDS_OR_IPV4_ADDRESS_PATTERN} |
    #               x[:...]::x:x:x:x |    x[:...]::x:x:n.n.n.n
    (?: #{HEXWORD_PATTERN} : ){1,3} : (?: #{HEXWORD_PATTERN} : ){2} #{TWO_HEXWORDS_OR_IPV4_ADDRESS_PATTERN} |
    #                 x[:...]::x:x:x |      x[:...]::x:n.n.n.n
    (?: #{HEXWORD_PATTERN} : ){1,4} : (?: #{HEXWORD_PATTERN} : ){1} #{TWO_HEXWORDS_OR_IPV4_ADDRESS_PATTERN} |
    #                   x[:...]::x:x |        x[:...]::n.n.n.n
    (?: #{HEXWORD_PATTERN} : ){1,5} :                               #{TWO_HEXWORDS_OR_IPV4_ADDRESS_PATTERN} |
    #                     x[:...]::x |                       -
    (?: #{HEXWORD_PATTERN} : ){1,6} :     #{HEXWORD_PATTERN}                                                |
    #                      x[:...]:: |
    (?: #{HEXWORD_PATTERN} : ){1,7} :                                                                       |
    #                      ::[...:]x |                       -
 :: (?: #{HEXWORD_PATTERN} : ){0,6}       #{HEXWORD_PATTERN}                                                |
    #                              - |         ::[...:]n.n.n.n
 :: (?: #{HEXWORD_PATTERN} : ){0,5}                                 #{TWO_HEXWORDS_OR_IPV4_ADDRESS_PATTERN} |
    #                             :: |                       -
 ::
  "

  attr_reader :errors, :ip_netblocks, :ip_address, :ip_network, :ipv4_prefix_length, :ipv6_prefix_length, :domain_spec, :raw_params

  def initialize(options = {})
    @ip_address         = nil
    @ip_network         = nil
    @ipv4_prefix_length = nil
    @ipv6_prefix_length = nil
    @raw_params         = nil
    @errors             = []
    @ip_netblocks       = []
    @text               = options[:text]
    @raise_exceptions   = options.has_key?(:raise_exceptions) ? options[:raise_exceptions] : true
  end

  def error(exception)
    raise exception if @raise_exceptions
    @errors << exception
  end

  def self.new_from_string(text, options = {})
    options[:text] = text
    term = self.new(options)
    term.parse
    return term
  end

  def parse_domain_spec(required = false)
    if @parse_text.sub!(/^(#{DOMAIN_SPEC_PATTERN})/x, '')
      domain_spec = $1
      domain_spec.sub!(/^(.*?)\.?$/, $1)
      @domain_spec = SPF::MacroString.new({:text => domain_spec})
    elsif required
      error(SPF::TermDomainSpecExpectedError.new(
        "Missing required domain-spec in '#{@text}'"))
    end
  end

  def parse_ipv4_address(required = false)
    @raw_params = @parse_text.dup
    if @parse_text.sub!(/^(#{IPV4_ADDRESS_PATTERN})/x, '')
      @ip_address = $1
    elsif required
      error(SPF::TermIPv4AddressExpectedError.new(
        "Missing or invalid required IPv4 address in '#{@text}'"))
    end
    @ip_address = @parse_text.dup unless @ip_address

  end

  def parse_ipv4_prefix_length(required = false)
    if @parse_text.sub!(/^\/(\d+)/, '')
      bits = $1.to_i
      unless bits and bits >= 0 and bits <= 32 and $1 !~ /^0./
        error(SPF::TermIPv4PrefixLengthExpected.new(
          "Invalid IPv4 prefix length encountered in '#{@text}'"))
        return
      end
      @ipv4_prefix_length = bits
    elsif required
      error(SPF::TermIPv4PrefixLengthExpected.new(
        "Missing required IPv4 prefix length in '#{@text}"))
      return
    else
      @ipv4_prefix_length = self.default_ipv4_prefix_length
    end
  end

  def parse_ipv4_network(required = false)
    @raw_params = @parse_text.dup
    self.parse_ipv4_address(required)
    self.parse_ipv4_prefix_length
    begin
      @ip_network = IP.new("#{@ip_address}/#{@ipv4_prefix_length}") if @ip_address and @ipv4_prefix_length
    rescue ArgumentError
      @ip_network = @ip_address
    end
  end

  def parse_ipv6_address(required = false)
    if @parse_text.sub!(/(#{IPV6_ADDRESS_PATTERN})(?=\/|$)/x, '')
      @ip_address = $1
    elsif required
      error(SPF::TermIPv6AddressExpected.new(
        "Missing or invalid required IPv6 address in '#{@text}'"))
    end
    @ip_address = @parse_text.dup unless @ip_address
  end

  def parse_ipv6_prefix_length(required = false)
    if @parse_text.sub!(/^\/(\d+)/, '')
      bits = $1.to_i
      unless bits and bits >= 0 and bits <= 128 and $1 !~ /^0./
        error(SPF::TermIPv6PrefixLengthExpectedError.new(
          "Invalid IPv6 prefix length encountered in '#{@text}'"))
        return
      end
      @ipv6_prefix_length = bits
    elsif required
      error(SPF::TermIPv6PrefixLengthExpected.new(
        "Missing required IPv6 prefix length in '#{@text}'"))
      return
    else
      @ipv6_prefix_length = self.default_ipv6_prefix_length
    end
  end

  def parse_ipv6_network(required = false)
    @raw_params = @parse_text.dup
    self.parse_ipv6_address(required)
    self.parse_ipv6_prefix_length
    begin
      @ip_network = IP.new("#{@ip_address}/#{@ipv6_prefix_length}") if @ip_address and @ipv6_prefix_length
    rescue ArgumentError
      @ip_network = @ip_address
    end
  end

  def parse_ipv4_ipv6_prefix_lengths
    self.parse_ipv4_prefix_length
    if self.instance_variable_defined?(:@ipv4_prefix_length) and # An IPv4 prefix length has been parsed, and
      @parse_text.sub!(/^\//, '')                           # another slash is following.
      # Parse an IPv6 prefix length:
      self.parse_ipv6_prefix_length(true)
    end
  end

  def domain(server, request)
    if self.instance_variable_defined?(:@domain_spec) and @domain_spec
      return SPF::MacroString.new({:server => server, :request => request, :text => @domain_spec.text})
    end
    return request.authority_domain
  end

  def text
    if self.instance_variable_defined?(:@text)
      return @text
    else
      raise SPF::NoUnparsedTextError
    end
  end
end

class SPF::UnknownTerm < SPF::Term
end

class SPF::Mech < SPF::Term

  DEFAULT_QUALIFIER          = SPF::Record::DEFAULT_QUALIFIER
  def default_ipv4_prefix_length; 32;   end
  def default_ipv6_prefix_length; 128;  end

  QUALIFIER_PATTERN          = '[+\\-~\\?]'
  NAME_PATTERN               = "#{NAME_PATTERN} (?= [:\\/\\x20] | $ )"

  EXPLANATION_TEMPLATES_BY_RESULT_CODE = {
    :pass     => "Sender is authorized to use '%{s}' in '%{_scope}' identity",
    :fail     => "Sender is not authorized to use '%{s}' in '%{_scope}' identity",
    :softfail => "Sender is not authorized to use '%{s}' in '%{_scope}' identity, however domain is not currently prepared for false failures",
    :neutral  => "Domain does not state whether sender is authorized to use '%{s}' in '%{_scope}' identity"
  }

  def initialize(options)
    super(options)

    @text = options[:text]
    if not self.instance_variable_defined?(:@parse_text)
      @parse_text = @text.dup
    end
    if self.instance_variable_defined?(:@domain_spec) and
      not SPF::MacroString === @domain_spec
      @domain_spec = SPF::MacroString.new({:text => @domain_spec})
    end
  end

  def parse
    if not @parse_text
      raise SPF::NothingToParseError.new('Nothing to parse for mechanism')
    end
    parse_qualifier
    parse_name      if @errors.empty?
    parse_params    if @errors.empty?
    parse_end       if @errors.empty?
  end

  def params; nil; end

  def parse_qualifier
    if @parse_text.sub!(/(#{QUALIFIER_PATTERN})?/x, '')
      @qualifier = $1 or DEFAULT_QUALIFIER
    else
      error(SPF::InvalidMechQualifierError.new(
          "Invalid qualifier encountered in '#{@text}'"))
    end
  end

  def parse_name
    if @parse_text.sub!(/^ (#{NAME_PATTERN}) (?: : (?=.) )? /x, '')
      @name = $1
    else
      error(SPF::InvalidMechError.new("Unexpected mechanism encountered in '#{@text}'"))
    end
  end

  def parse_params(required = true)
    @raw_params = @parse_text.dup
    # Parse generic string of parameters text (should be overridden in sub-classes):
    if @parse_text.sub!(/^(.*)/, '')
      @params_text = $1
      @raw_params  = @params_text.dup
    end
  end

  def parse_end
    unless @parse_text == ''
      error(SPF::JunkInTermError.new("Junk encountered in mechanism '#{@text}'", @text, @parse_text))
    end
    @parse_text = nil
  end

  def qualifier
    # Read-only!
    return @qualifier if self.instance_variable_defined?(:@qualifier) and @qualifier
    return DEFAULT_QUALIFIER
  end

  def to_s
    @params = nil unless self.instance_variable_defined?(:@params)

    return sprintf(
      '%s%s%s',
      @qualifier == DEFAULT_QUALIFIER ? '' : @qualifier,
      @name,
      @params ? @params : ''
    )
  end

  def match_in_domain(server, request, domain)
    domain = self.domain(server, request) unless domain

    ipv4_prefix_length = @ipv4_prefix_length || self.default_ipv4_prefix_length
    ipv6_prefix_length = @ipv6_prefix_length || self.default_ipv6_prefix_length

    begin
      rrs_a = server.dns_lookup(domain.to_s, 'A') || []
    rescue SPF::DNSError => e
      @errors << e
      return false
    end
    begin
      rrs_aaaa = server.dns_lookup(domain.to_s, 'AAAA') || []
    rescue SPF::DNSError => e
      @errors << e
      return false
    end

    rrs = rrs_a + rrs_aaaa
    server.count_void_dns_lookup(request) if rrs.empty?

    rrs.each do |rr|
      if Resolv::DNS::Resource::IN::A === rr
        network = IP.new("#{rr.address}/#{ipv4_prefix_length}")
        @ip_netblocks << network
        return true if network.contains?(request.ip_address)
      elsif Resolv::DNS::Resource::IN::AAAA === rr
        network = IP.new("#{rr.address}/#{ipv6_prefix_length}")
        @ip_netblocks << network
        return true if network.contains?(request.ip_address_v6)
      else
        # Unexpected RR type.
        # TODO: Generate debug info or ignore silently.
      end
    end
    return false
  end

  def explain(server, request, result)
    explanation_template = self.explanation_template(server, request, result)
    return unless explanation_template
    begin
      explanation = SPF::MacroString.new({
        :text           => explanation_template,
        :server         => server,
        :request        => request,
        :is_explanation => true
      })
      request.state(:local_explanation, explanation)
    rescue SPF::Error
    rescue SPF::Result
    end
  end

  def explanation_template(server, request, result)
    return EXPLANATION_TEMPLATES_BY_RESULT_CODE[result.code]
  end


  class SPF::Mech::A < SPF::Mech

    NAME = 'a'

    def parse_params(required = true)
      @raw_params = @parse_text.dup
      self.parse_domain_spec
      self.parse_ipv4_ipv6_prefix_lengths
    end

    def params
      params = ''
      if @domain_spec
        params += @domain_spec.to_s if @domain_spec
      end
      if @ipv4_prefix_length and @ipv4_prefix_length != self.default_ipv4_prefix_length
        params += '/' + @ipv4_prefix_length.to_s
      end
      if @ipv6_prefix_length and @ipv6_prefix_length != self.default_ipv6_prefix_length
        params += '//' + @ipv6_prefix_length.to_s
      end
      return params
    end

    def match(server, request, want_result = true)
      server.count_dns_interactive_term(request)
      return self.match_in_domain(server, request, self.domain(server, request))
    end

  end

  class SPF::Mech::All < SPF::Mech

    NAME = 'all'

    def parse_params(required = true)
      # No parameters.
    end

    def match(server, request, want_result = true)
      return true
    end

  end

  class SPF::Mech::Exists < SPF::Mech

    NAME = 'exists'

    def parse_params(required = true)
      @raw_params = @parse_text.dup
      self.parse_domain_spec(required)
      # Other method of denoting "potentially ~infinite" netblocks?
      @ip_netblocks << nil
    end

    def params
      return @domain_spec ? @domain_spec : nil
    end

    def match(server, request, want_result = true)
      server.count_dns_interactive_term(request)

      domain = self.domain(server, request)
      begin
        rrs = server.dns_lookup(domain, 'A')
        return true if rrs.any?
      rescue SPF::DNSNXDomainError => e
        server.count_void_dns_lookup(request)
        return false
      end
    end

  end

  class SPF::Mech::IP4 < SPF::Mech

    NAME = 'ip4'

    def parse_params(required = true)
      self.parse_ipv4_network(required)
      if IP === @ip_network
        @ip_netblocks << @ip_network
        if @ip_network.respond_to?(:offset) && @ip_network.offset != 0
          @errors << SPF::InvalidMechCIDRError.new(
            "Invalid CIDR netblock - bits in host portion of address of #{@ip_network}"
          )
        end
      end
    end

    def params
      return nil unless @ip_network
      return @ip_network if String === @ip_network
      result = @ip_network.to_addr
      if @ip_network.pfxlen != @default_ipv4_prefix_length
        result += "/#{@ip_network.pfxlen}"
      end
      return result
    end

    def match(server, request, want_result = true)
      return false unless @ip_network
      ip_network_v6 = IP::V4 === @ip_network ?
        SPF::Util.ipv4_address_to_ipv6(@ip_network) :
        @ip_network
      return ip_network_v6.contains?(request.ip_address_v6)
    end

  end

  class SPF::Mech::IP6 < SPF::Mech

    NAME = 'ip6'

    def parse_params(required = true)
      self.parse_ipv6_network(required)
      @ip_netblocks << @ip_network if IP === @ip_network
      if @ip_network.respond_to?(:offset) && @ip_network.offset != 0
        @errors << SPF::InvalidMechCIDRError.new(
          "Invalid CIDR netblock - bits in host portion of address of #{@ip_network}"
        )
      end
    end

    def params
      return nil unless @ip_network
      return @ip_network if String === @ip_network
      params =  @ip_network.to_addr
      params += '/' + @ip_network.pfxlen.to_s if
        @ip_network.pfxlen != self.default_ipv6_prefix_length
      return params
    end

    def match(server, request, want_result = true)
      return @ip_network.contains?(request.ip_address_v6)
    end

  end

  class SPF::Mech::Include < SPF::Mech

    NAME = 'include'

    def intitialize(options = {})
      super(options)
      @nested_record = nil
    end

    def parse_params(required = true)
      @raw_params = @parse_text.dup
      self.parse_domain_spec(required)
    end

    def params
      return @domain_spec ? @domain_spec.to_s : nil
    end

    def match(server, request, want_result = true)

      server.count_dns_interactive_term(request)

      # Create sub-request with mutated authority domain:
      authority_domain = self.domain(server, request)
      sub_request = request.new_sub_request({:authority_domain => authority_domain})

      # Process sub-request:
      result = server.process(sub_request)

      # Translate result of sub-request (RFC 4408, 5.9):

      return false unless want_result

      return true if SPF::Result::Pass === result

      return false if
        SPF::Result::Fail     === result or
        SPF::Result::SoftFail === result or
        SPF::Result::Neutral  === result

      server.throw_result(:permerror, request,
        "Include domain '#{authority_domain}' has no applicable sender policy") if
        SPF::Result::None === result

      # Propagate any other results (including {Perm,Temp}Error) as-is:
      raise result
    end

    def nested_record(server=nil, request=nil, loose_match = false)
      return @nested_record if @nested_record
      return nil unless server and request
      authority_domain = self.domain(server, request)
      sub_request = request.new_sub_request({:authority_domain => authority_domain})
      return @nested_record = server.select_record(sub_request, loose_match)
    end

  end

  class SPF::Mech::MX < SPF::Mech

    NAME = 'mx'

    def parse_params(required = true)
      @raw_params = @parse_text.dup
      self.parse_domain_spec
      self.parse_ipv4_ipv6_prefix_lengths
    end

    def params
      params = ''
      if @domain_spec
        params += @domain_spec.to_s
      end
      if @ipv4_prefix_length and @ipv4_prefix_length != self.default_ipv4_prefix_length
        params += '/' + @ipv4_prefix_length.to_s
      end
      if @ipv6_prefix_length and @ipv6_prefix_length != self.default_ipv6_prefix_length
        params += '//' + @ipv6_prefix_length.to_s
      end
      return params
    end

    def match(server, request, want_result = true)

      server.count_dns_interactive_term(request)

      target_domain = self.domain(server, request)
      mx_packet     = server.dns_lookup(target_domain, 'MX')
      mx_rrs        = (mx_packet or server.count_void_dns_lookup(request))

      # Respect the MX mechanism lookups limit (RFC 4408, 5.4/3/4):
      if server.max_name_lookups_per_mx_mech
        mx_rrs = mx_rrs[0, server.max_name_lookups_per_mx_mech]
      end

      # TODO: Use A records from packet's "additional" section? Probably not.

      # Check MX records:
      mx_rrs.each do |rr|
        if Resolv::DNS::Resource::IN::MX === rr
          return true if
            self.match_in_domain(server, request, rr.exchange)
        else
          # Unexpected RR type.
          # TODO: Generate debug info or ignore silently.
        end
      end
      return false
    end

  end

  class SPF::Mech::PTR < SPF::Mech
    NAME = 'ptr'

    def parse_params(required = true)
      @raw_params = @parse_text.dup
      self.parse_domain_spec
    end

    def params
      return @domain_spec ? @domain_spec : nil
    end

    def match(server, request, want_result = true)
      return SPF::Util.valid_domain_for_ip_address(
        server, request, request.ip_address, self.domain(server, request)) ?
        true : false
    end
  end
end

class SPF::Mod < SPF::Term

  def initialize(options = {})
    super

    @parse_text  = options[:parse_text]
    @text        = options[:text]
    @domain_spec = options[:domain_spec]

    @parse_text = @text.dup unless @parse_text

    if @domain_spec and not SPF::MacroString === @domain_spec
      @domain_spec = SPF::MacroString.new({:text => @domain_spec})
    end
  end

  def parse
    error(SPF::NothingToParseError('Nothing to parse for modifier')) unless @parse_text
    self.parse_name         if @errors.empty?
    self.parse_params(true) if @errors.empty?
    self.parse_end          if @errors.empty?
  end

  def parse_name
    @parse_text.sub!(/^(#{self.class::NAME})=/i, '')
    if $1
      @name = $1
    else
      error(SPF::InvalidModError.new(
        "Unexpected modifier name encoutered in #{@text}"))
    end
  end

  def parse_params(required = false)
    # Parse generic macro string of parameters text (should be overridden in sub-classes):
    @parse_text.sub!(/^(#{MACRO_STRING_PATTERN})$/x, '')
    if $1
      @params_text = $1
    elsif required
      error(SPF::InvalidMacroStringError.new(
        "Invalid macro string encountered in #{@text}"))
    end
  end

  def parse_end
    unless @parse_text == ''
      error(SPF::JunkInTermError.new("Junk encountered in modifier #{@text}", @text, @parse_text))
    end
    @parse_text = nil
  end

  def to_s
    return sprintf(
      '%s=%s',
      @name,
      @params ? @params : ''
    )
  end

  class SPF::GlobalMod < SPF::Mod
  end

  class SPF::PositionalMod < SPF::Mod
  end

  class SPF::UnknownMod < SPF::Mod
    NAME = 'uknown'
  end

  class SPF::Mod::Exp < SPF::GlobalMod

    attr_reader :domain_spec

    NAME       = 'exp'

    def precedence; 0.2; end

    def parse_params(required = true)
      @raw_params = @parse_text.dup
      self.parse_domain_spec(required)
    end

    def params
      return @domain_spec
    end

    def process(server, request, result)
      begin
        exp_domain = @domain_spec.new({:server => server, :request => request})
        txt_packet = server.dns_lookup(exp_domain, 'TXT')
        txt_rrs    = txt_packet.answer.select {|x| x.type == 'TXT'}.map {|x| x.answer}
        unless text_rrs.length > 0
          server.throw_result(:permerror, request,
            "No authority explanation string available at domain '#{exp_domain}'") # RFC 4408, 6.2/4
        end
        unless text_rrs.length == 1
          server.throw_result(:permerror, request,
            "Redundant authority explanation strings found at domain '#{exp_domain}'") # RFC 4408, 6.2/4
        end
        explanation = SPF::MacroString.new(
          :text           => txt_rrs[0].char_str_list.join(''),
          :server         => server,
          :request        => request,
          :is_explanation => true
        )
        request.state(:authority_explanation, explanation)
      rescue SPF::DNSError, SPF::Result::Error
        # Ignore DNS and other errors.
      end
      return request
    end
  end

  class SPF::Mod::Redirect < SPF::GlobalMod

    attr_reader :domain_spec

    NAME       = 'redirect'

    def precedence; 0.8; end

    def init(options = {})
      super(options)
      @nested_record = nil
    end

    def parse_params(required = true)
      @raw_params = @parse_text.dup
      self.parse_domain_spec(required)
    end

    def params
      return @domain_spec
    end

    def process(server, request, result)

      server.count_dns_interactive_term(request)

      # Only perform redirection if no mechanism matched (RFC 4408, 6.1/1):
      return unless SPF::Result::NeutralByDefault === result

      # Create sub-request with mutated authorithy domain:
      sub_request = request.new_sub_request({:authority_domain => @domain_spec})

      # Process sub-request:
      result = server.process(sub_request)

      @nested_record = sub_request.record

      # Translate result of sub-request (RFC 4408, 6.1/4):
      if SPF::Result::None === result
        server.throw_result(:permerror, request,
          "Redirect domain '#{authority_domain}' has no applicable sender policy")
      end

      # Propagate any other results as-is:
      raise result
    end

    def nested_record(server=nil, request=nil)
      return @nested_record if @nested_record
      return nil unless server and request
      server.count_dns_interactive_term(request)
      authority_domain = self.domain(server, request)
      sub_request = request.new_sub_request({:authority_domain => authority_domain})
      return @nested_record = server.select_record(sub_request)
    end
  end
end

class SPF::Record

  attr_reader :terms, :text, :errors

  RESULTS_BY_QUALIFIER = {
    ''  => :pass,
    '+' => :pass,
    '-' => :fail,
    '~' => :softfail,
    '?' => :neutral
  }

  def initialize(options)
    super()
    @parse_text       = (@text = options[:text] if not self.instance_variable_defined?(:@parse_text)).dup
    @terms          ||= []
    @global_mods    ||= {}
    @errors           = []
    @ip_netblocks     = []
    @raise_exceptions = options.has_key?(:raise_exceptions) ? options[:raise_exceptions] : true
  end

  def self.new_from_string(text, options = {})
    options[:text] = text
    record = new(options)
    record.parse
    return record
  end

  def error(exception)
    raise exception if @raise_exceptions
    @errors << exception
  end

  def ip_netblocks
    @ip_netblocks.flatten!
    return @ip_netblocks
  end

  def parse
    unless self.instance_variable_defined?(:@parse_text) and @parse_text
      error(SPF::NothingToParseError.new('Nothing to parse for record'))
      return
    end
    self.parse_version_tag
    while @parse_text.length > 0
      term = nil
      begin
        term = self.parse_term
      rescue SPF::Error => e
        term.errors << e if term
        @errors     << e
        raise if @raise_exceptions
        return if SPF::JunkInRecordError === e or SPF::JunkInTermError === e
      end
    end
  end

  def parse_version_tag
    @parse_text.sub!(/^#{self.version_tag_pattern}\s*/x, '')
    unless $1
      raise SPF::InvalidRecordVersionError.new(
        "Not a '#{self.version_tag}' record: '#{@text}'")
    end
  end

  def parse_term
    regex = /
      ^
      (
        #{SPF::Mech::QUALIFIER_PATTERN}?
        (#{SPF::Mech::NAME_PATTERN})
        [^\x20]*
      )
      (?: \x20+ | $ )
    /x

    term = nil
    if @parse_text.sub!(regex, '') and $&
      # Looks like a mechanism:
      mech_text  = $1
      mech_name  = $2.downcase
      mech_class = self.mech_classes[mech_name.to_sym]
      exception  = nil
      unless mech_class
        exception = SPF::InvalidMechError.new("Unknown mechanism type '#{mech_name}' in '#{self.version_tag}' record")
        error(exception)
        mech_class = SPF::Mech
      end
      term = mech = mech_class.new_from_string(mech_text, {:raise_exceptions => @raise_exceptions})
      term.errors << exception if exception
      @ip_netblocks << mech.ip_netblocks if mech.ip_netblocks
      @terms << mech
      if mech_class == SPF::Mech
        raise SPF::InvalidMechError.new("Unknown mechanism type '#{mech_name}' in '#{self.version_tag}' record")
      end
    elsif (
      @parse_text.sub!(/
        ^
        (
          (#{SPF::Mod::NAME_PATTERN}) =
          [^\x20]*
        )
        (?: \x20+ | $ )
      /x, '') and $&
    )
      # Looks like a modifier:
      mod_text  = $1
      mod_name  = $2.downcase
      mod_class = self.class::MOD_CLASSES[mod_name.to_sym] || SPF::UnknownMod
      if mod_class
        # Known modifier.
        term = mod = mod_class.new_from_string(mod_text, {:raise_exceptions => @raise_exceptions})
        if SPF::GlobalMod === mod
          # Global modifier.
          if @global_mods[mod_name]
            raise SPF::DuplicateGlobalMod.new("Duplicate global modifier '#{mod_name}' encountered")
          end
          @global_mods[mod_name] = mod
        elsif SPF::PositionalMod === mod
          # Positional modifier, queue normally:
          @terms << mod
        end
      end

    else
      token_text = @parse_text.sub(/\s.*/, '')
      hint = nil
      if token_text =~ /#{SPF::Term::IPV4_ADDRESS_PATTERN}/x
        hint = 'missing ip4: before IPv4 address?'
      elsif token_text =~ /#{SPF::Term::IPV6_ADDRESS_PATTERN}/x
        hint = 'missing ip6: before IPv6 address?'
      end
      raise SPF::JunkInRecordError.new("Junk encountered in record '#{@text}'", @text, @parse_text, hint)
    end
    @errors.concat(term.errors)
    return term
  end

  def global_mods
    return @global_mods.values.sort {|a,b| a.precedence <=> b.precedence }
  end

  def global_mod(mod_name)
    return @global_mods[mod_name]
  end

  def to_s
    return [version_tag, @terms, @global_mods].join(' ')
  end

  def eval(server, request, want_result = true)
    raise SPF::OptionRequiredError.new('SPF server object required for record evaluation') unless server
    raise SPF::OptionRequiredError.new('Request object required for record evaluation')    unless request
    begin
      @terms.each do |term|
        if SPF::Mech === term
          # Term is a mechanism.
          mech = term
          if mech.match(server, request, request.ip_address != nil)
            result_name = RESULTS_BY_QUALIFIER[mech.qualifier]
            result_class = server.result_class(result_name)
            result = result_class.new([server, request, "Mechanism '#{term}' matched"])
            mech.explain(server, request, result)
            raise result if want_result
          end
        elsif SPF::PositionalMod === term
          # Term is a positional modifier.
          mod = term
          mod.process(server, request)
        elsif SPF::UnknownMod === term
          # Term is an unknown modifier.  Ignore it (RFC 4408, 6/3).
        else
          # Invalid term object encountered:
          error(SPF::UnexpectedTermObjectError.new("Unexpected term object '#{term}' encountered."))
        end
      end
      server.throw_result(:neutral_by_default, request,
        'Default neutral result due to no mechanism matches')
    rescue SPF::Result => result
      # Process global modifiers in ascending order of precedence:
      global_mods.each do |global_mod|
        global_mod.process(server, request, result)
      end
      raise result if want_result
    end
  end

  class SPF::Record::V1 < SPF::Record

    MECH_CLASSES = {
      :all      => SPF::Mech::All,
      :ip4      => SPF::Mech::IP4,
      :ip6      => SPF::Mech::IP6,
      :a        => SPF::Mech::A,
      :mx       => SPF::Mech::MX,
      :ptr      => SPF::Mech::PTR,
      :exists   => SPF::Mech::Exists,
      :include  => SPF::Mech::Include
    }

    MOD_CLASSES = {
      :redirect => SPF::Mod::Redirect,
      :exp      => SPF::Mod::Exp,
    }


    def scopes
      [:helo, :mfrom]
    end

    def version_tag
      'v=spf1'
    end

    def self.version_tag
      'v=spf1'
    end

    def version_tag_pattern
      " v=spf(1) (?= \\x20+ | $ ) "
    end

    def mech_classes
      MECH_CLASSES
    end

    def initialize(options = {})
      super(options)

      @scopes ||= options[:scopes]
      if @scopes and scopes.any?
        unless @scopes.length > 0
          raise SPF::InvalidScopeError.new('No scopes for v=spf1 record')
        end
        if @scopes.length == 2
          unless (
              @scopes[0] == :helo  and @scopes[1] == :mfrom or
              @scopes[0] == :mfrom and @scopes[1] == :helo)
            raise SPF::InvalidScope.new(
              "Invalid set of scopes " + @scopes.map{|x| "'#{x}'"}.join(', ') + "for v=spf1 record")
          end
        end
      end
    end
  end

  class SPF::Record::V2 < SPF::Record

    MECH_CLASSES = {
      :all      => SPF::Mech::All,
      :ip4      => SPF::Mech::IP4,
      :ip6      => SPF::Mech::IP6,
      :a        => SPF::Mech::A,
      :mx       => SPF::Mech::MX,
      :ptr      => SPF::Mech::PTR,
      :exists   => SPF::Mech::Exists,
      :include  => SPF::Mech::Include
    }

    MOD_CLASSES = {
      :redirect => SPF::Mod::Redirect,
      :exp      => SPF::Mod::Exp
    }

    VALID_SCOPE = /^(?: mfrom | pra )$/x
    def version_tag
      'v=spf2.0'
    end

    def scopes
      [:mfrom, :pra]
    end

    def version_tag_pattern
    "
      spf(2\.0)
      \/
      ( (?: mfrom | pra ) (?: , (?: mfrom | pra ) )* )
      (?= \\x20 | $ )
    "
    end

    def mech_classes
      MECH_CLASSES
    end

    def initialize(options = {})
      super(options)
      unless @parse_text
        scopes = @scopes || {}
        raise SPF::InvalidScopeError.new('No scopes for spf2.0 record') if scopes.empty?
        scopes.each do |scope|
          if scope !~ VALID_SCOPE
            raise SPF::InvalidScopeError.new("Invalid scope '#{scope}' for spf2.0 record")
          end
        end
      end
    end

    def version_tag
      return 'spf2.0' if not @scopes  # no scopes parsed
      return 'spf2.0/' + @scopes.join(',')
    end

    def parse_version_tag

      @parse_text.sub!(/#{version_tag_pattern}(?:\x20+|$)/ix, '')
      if $1
        scopes = @scopes = "#{$2}".split(/,/)
        if scopes.empty?
          raise SPF::InvalidScopeError.new('No scopes for spf2.0 record')
        end
        scopes.each do |scope|
          if scope !~ VALID_SCOPE
            raise SPF::InvalidScopeError.new("Invalid scope '#{scope}' for spf2.0 record")
          end
        end
      else
        raise SPF::InvalidRecordVersionError.new(
          "Not a 'spf2.0' record: '#{@text}'")
      end
    end
  end
end

# vim:sw=2 sts=2
