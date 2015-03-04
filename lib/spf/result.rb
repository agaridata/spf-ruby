# encoding: ASCII-8BIT
require 'spf/model'
require 'spf/util'

class SPF::Result < Exception

  attr_reader :server, :request

  class SPF::Result::Pass < SPF::Result
    def code
      :pass
    end
  end

  class SPF::Result::Fail < SPF::Result
    def code
      :fail
    end

    def authority_explanation
      if self.instance_variable_defined?(:@authority_explanation)
        return @authority_explanation
      end

      @authority_explanation = nil

      server  = @server
      request = @request

      authority_explanation_macrostring = request.state('authority_explanation')

      # If an explicit explanation was specified by the authority domain...
      if authority_explanation_macrostring
        begin
          # ... then try to expand it:
          @authority_explanation = authority_explanation_macrostring.expand
        rescue SPF::InvalidMacroString
          # Igonre expansion errors and leave authority explanation undefined.
        end
      end

      # If no authority explanation could be determined so far...
      unless @authority_explanation
        @authority_explanation = server.default_authority_explanation.new({:request => request}).expand
      end
      return @authority_explanation
    end
  end

  class SPF::Result::SoftFail < SPF::Result
    def code
      :softfail
    end
  end

  class SPF::Result::Neutral < SPF::Result
    def code
      :neutral
    end
  end

  class SPF::Result::NeutralByDefault < SPF::Result::Neutral
    # This is a special-case of the Neutral result that is thrown as a default
    # when "falling off" the end of the record.  See SPF::Record.eval().
    NAME = :neutral_by_default
    def code
      :neutral_by_default
    end
  end

  class SPF::Result::None < SPF::Result
    def code
      :none
    end
  end

  class SPF::Result::Error < SPF::Result
    def code
      :error
    end
  end

  class SPF::Result::TempError < SPF::Result::Error
    def code
      :temperror
    end
  end

  class SPF::Result::PermError < SPF::Result::Error
    def code
      :permerror
    end
  end


  RESULT_CLASSES = {
    :pass       => SPF::Result::Pass,
    :fail       => SPF::Result::Fail,
    :softfail   => SPF::Result::SoftFail,
    :neutral    => SPF::Result::Neutral,
    :neutral_by_default => SPF::Result::NeutralByDefault,
    :none       => SPF::Result::None,
    :error      => SPF::Result::Error,
    :permerror  => SPF::Result::PermError,
    :temperror  => SPF::Result::TempError
  }

  RECEIVED_SPF_HEADER_NAME = 'Received-SPF'

  RECEIVED_SPF_HEADER_SCOPE_NAMES_BY_SCOPE = {
    :helo       => 'helo',
    :mfrom      => 'envelope-from',
    :pra        => 'pra'
  }

  RECEIVED_SPF_HEADER_IDENTITY_KEY_NAMES_BY_SCOPE = {
    :helo       => 'helo',
    :mfrom      => 'envelope-from',
    :pra        => 'pra'
  }

  ATEXT_PATTERN     = /[[:alnum:]!#\$%&'*+\-\/=?^_`{|}~]/
  DOT_ATOM_PATTERN  = /
    (#{ATEXT_PATTERN})+ ( \. (#{ATEXT_PATTERN})+ )*
  /x

  def initialize(args = [])
    @server = args.shift if args.any?
    unless self.instance_variable_defined?(:@server)
      raise SPF::OptionRequiredError.new('SPF server object required')
    end
    @request = args.shift if args.any?
    unless self.instance_variable_defined?(:@request)
      raise SPF::OptionRequiredError.new('Request object required')
    end
  end

  def name
    return self.code
  end

  def klass(name=nil)
    if name
      name = name.to_sym if String === name
      return self.RESULT_CLASSES[name]
    else
      return name
    end
  end

  def isa_by_name(name)
    suspect_class = self.klass(name)
    return false unless suspect_class
    return suspect_class === self
  end
  
  def is_code(code)
    return self.isa_by_name(code)
  end

  def to_s
    return sprintf('%s (%s)', self.name, SPF::Util.sanitize_string(super.to_s))
  end

  def local_explanation
    return @local_explanation if self.instance_variable_defined?(:@local_explanation)

    # Prepare local explanation:
    request = self.request
    local_explanation = request.state(:local_explanation)
    if local_explanation
      local_explanation = sprintf('%s (%s)', local_explanation.expand, @text)
    else
      local_explanation = @text
    end

    # Resolve authority domains of root-request and bottom sub-requests:
    root_request = request.root_request
    local_explanation = (request == root_request or not root_request) ?
      sprintf('%s: %s', request.authority_domain, local_explanation) :
      sprintf('%s ... %s: %s', root_request.authority_domain, request.authority_domain, local_explanation)

    return @local_explanation = SPF::Util.sanitize_string(local_explanation)
  end

  def received_spf_header
    return @received_spf_header if self.instance_variable_defined?(:@received_spf_header)
    scope_name        = self.received_spf_header_scope_names_by_scope[@request.scope]
    identify_key_name = self.received_spf_header_identity_key_names_by_scope[@request.scope]
    info_pairs = [
      :receiver                => @server.hostname || 'unknown',
      :identity                => scope_name,
      identity_key_name.to_sym => @request.identity,
      :client_ip               => SPF::Util.ip_address_to_string(@request.ip_address)
    ]
    if @request.scope != :helo and @request.helo_identity
      info_pairs[:helo] = @request.helo_identity
    end
    info_string = ''
    while info_pairs.any?
      key   = info_pairs.shift
      value = info_pairs.shift
      info_string += '; ' unless info_string.blank?
      if value !~ /^#{DOT_ATOM_PATTERN}$/o
        value.gsub!(/(["\\])/, "\\#{$1}") # Escape '\' and '"' characters.
        value = "\"#{value}\""            # Double-quote value.
      end
      info_string += "#{key}=#{value}"
    end
    return @received_spf_header = sprintf(
      '%s: %s (%s) %s',
      @received_spf_header_name,
      self.code,
      self.local_explanation,
      info_string
    )
  end

end

# vim:sw=2 sts=2
