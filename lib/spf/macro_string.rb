# encoding: ASCII-8BIT
require 'spf/util'

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
      @expanded = nil
      self.expand
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

      expanded = ''
      # TODO
      return (@expanded = @text)
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
        raise MacroExpansionCtxRequired, 'SPF server object required' if required
        return false
      end
      if not SPF::Request === request
        raise MacroExpansionCtxRequired, 'SPF request object required' if required
        return false
      end
      return true
    end

  end
end

# vim:sw=2 sts=2
