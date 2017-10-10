# encoding: ASCII-8BIT
require 'spf/util'
require 'spf/error'
require 'uri'


module SPF
  class MacroString

    def self.default_split_delimiters
      '.'
    end

    def self.default_join_delimiter
      '.'
    end

    def self.uri_unreserved_chars
      'A-Za-z0-9\-._~'
    end

    def initialize(options = {})
      super()
      @text     = options[:text] \
        or raise ArgumentError, "Missing required 'text' option"
      @server   = options[:server]
      @request  = options[:request]
      @is_explanation = options[:is_explanation]
      @expanded = nil
    end

    attr_reader :text, :server, :request

    def context(server, request)
      valid_context(true, server, request)
      @server   = server
      @request  = request
      @expanded = nil
      return
    end

    def expand(context = nil)
      return @expanded if @expanded

      return nil unless @text
      return (@expanded = @text) unless @text =~ /%/
        # Short-circuit expansion if text has no '%' characters.

      server, request = context ? context : [@server, @request]

      valid_context(true, server, request)

      expanded = ''

      text = @text

      while m = text.match(/ (.*?) %(.) /x) do
        expanded += m[1]
        key = m[2]

        if (key == '{')
          if m2 = m.post_match.match(/ (\w|_\p{Alpha}+) ([0-9]+)? (r)? ([.\-+,\/_=])? } /x)
            char, rh_parts, reverse, delimiter = m2.captures

            # Upper-case macro chars trigger URL-escaping AKA percent-encoding
            # (RFC 4408, 8.1/26):
            do_percent_encode = char =~ /\p{Upper}/
            char.downcase!

            if char == 's' # RFC 4408, 8.1/19
              value = request.identity
            elsif char == 'l' # RFC 4408, 8.1/19
              value = request.localpart
            elsif char == 'o' # RFC 4408, 8.1/19
              value = request.domain
            elsif char == 'd' # RFC 4408, 8.1/6/4
              value = request.authority_domain
            elsif char == 'i' # RFC 4408, 8.1/20, 8.1/21
              ip_address = request.ip_address
              ip_address = SPF::Util.ipv6_address_to_ipv4(ip_address) if SPF::Util.ipv6_address_is_ipv4_mapped(ip_address)
              if IP::V4 === ip_address
                value = ip_address.to_addr
              elsif IP::V6 === ip_address
                value = ip_address.to_hex.upcase.split('').join('.')
              else
                server.throw_result(:permerror, request, "Unexpected IP address version in request")
              end
            elsif char == 'p' # RFC 4408, 8.1/22
              # According to RFC 7208 the "p" macro letter should not be used (or even published).
              # Here it is left unexpanded and transformers and delimiters are not applied.
              value = '%{' + m2.to_s
              rh_parts = nil
              reverse = nil
            elsif char == 'v' # RFC 4408, 8.1/6/7
              if IP::V4 === request.ip_address
                value = 'in-addr'
              elsif IP::V6 === request.ip_address
                value = 'ip6'
              else
                # Unexpected IP address version.
                server.throw_result(:permerror, request, "Unexpected IP address version in request")
              end
            elsif char == 'h' # RFC 4408, 8.1/6/8
              value = request.helo_identity || 'unknown'
            elsif char == 'c' # RFC 4408, 8.1/20, 8.1/21
              raise SPF::InvalidMacroStringError.new("Illegal 'c' macro in non-explanation macro string '#{@text}'") unless @is_explanation
              ip_address = request.ip_address
              value = SPF::Util::ip_address_to_string(ip_address)
            elsif char == 'r' # RFC 4408, 8.1/23
              value = server.hostname || 'unknown'
            elsif char == 't'
              raise SPF::InvalidMacroStringError.new("Illegal 't' macro in non-explanation macro string '#{@text}'") unless @is_explanation
              value = Time.now.to_i.to_s
            elsif char == '_scope'
              # Scope pseudo macro for internal use only!
              value = request.scope.to_s
            else
              # Unknown macro character.
              raise SPF::InvalidMacroStringError.new("Invalid macro character #{char} in macro string '#{@text}'")
            end

            if rh_parts || reverse
              delimiter ||= self.class.default_split_delimiters
              list = value.split(delimiter)
              list.reverse! if reverse
              # Extract desired parts:
              if rh_parts && rh_parts.to_i > 0
                list = list.last(rh_parts.to_i)
              end
              if rh_parts && rh_parts.to_i == 0
                raise SPF::InvalidMacroStringError.new("Illegal selection of 0 (zero) right-hand parts in macro string '#{@text}'")
              end
              value = list.join(self.class.default_join_delimiter)
            end

            if do_percent_encode
              unsafe = Regexp.new('^' + self.class.uri_unreserved_chars)
              value = URI.escape(value, unsafe)
            end

            expanded += value

            text = m2.post_match
          else
            # Invalid macro expression.
            raise SPF::InvalidMacroStringError.new("Invalid macro expression in macro string '#{@text}'")
          end
        elsif key == '-'
          expanded += '-'
          text = m.post_match
        elsif key == '_'
          expanded += ' '
          text = m.post_match
        elsif key == '%'
          expanded += '%'
          text = m.post_match
        else
          # Invalid macro expression.
          pos = m.offset(2).first
          raise SPF::InvalidMacroStringError.new("Invalid macro expression at pos #{pos} in macro string '#{@text}'")
        end
      end

      expanded += text # Append remaining unmatched characters.

      context ? expanded : @expanded = expanded
    end

    def to_s
      if valid_context(false)
        return expand
      else
        return @text
      end
    end

    def valid_context(required, server = self.server, request = self.request)
      if not SPF::Server === server
        raise SPF::MacroExpansionCtxRequiredError.new('SPF server object required') if required
        return false
      end
      if not SPF::Request === request
        raise SPF::MacroExpansionCtxRequiredError.new('SPF request object required') if required
        return false
      end
      return true
    end
  end
end

# vim:sw=2 sts=2
