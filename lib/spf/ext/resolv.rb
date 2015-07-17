require 'resolv'

require 'rubygems'  # Gem.ruby_version / Gem::Version


# TCP fallback support, redux.
# A broken version of this made it into Ruby 1.9.2 in October 2010.
# <http://bugs.ruby-lang.org/issues/3835>  That version would fail when trying
# a second TCP nameserver.  This improved version fixes that.
# Filed upstream as <http://bugs.ruby-lang.org/issues/8285>.
###############################################################################

class Resolv
  class DNS
    def each_resource(name, typeclass, &proc)
      lazy_initialize
      protocols  = {}                                                           # PATCH
      requesters = {}                                                           # PATCH
      senders    = {}
      #begin                                                                    # PATCH
      @config.resolv(name) {|candidate, tout, nameserver, port|
        msg = Message.new
        msg.rd = 1
        msg.add_question(candidate, typeclass)
        protocol  = protocols[candidate] ||= :udp                               # PATCH
        requester = requesters[[protocol, nameserver]] ||= case protocol        # PATCH
          when :udp then make_udp_requester                                     # PATCH
          when :tcp then make_tcp_requester(nameserver, port)                   # PATCH
        end                                                                     # PATCH
        sender    = senders[[candidate, requester, nameserver, port]] ||=       # PATCH
          requester.sender(msg, candidate, nameserver, port)                    # PATCH
        reply, reply_name = requester.request(sender, tout)
        case reply.rcode
        when RCode::NoError
          if protocol == :udp and reply.tc == 1                                 # PATCH
            # Retry via TCP:                                                    # PATCH
            protocols[candidate] = :tcp                                         # PATCH
            redo                                                                # PATCH
          else                                                                  # PATCH
            extract_resources(reply, reply_name, typeclass, &proc)
          end                                                                   # PATCH
          return
        when RCode::NXDomain
          raise Config::NXDomain.new(reply_name.to_s)
        else
          raise Config::OtherResolvError.new(reply_name.to_s)
        end
      }
    ensure
      requesters.each_value { |requester| requester.close }                     # PATCH
      #end                                                                      # PATCH
    end

    #alias_method :make_udp_requester, :make_requester

    def make_tcp_requester(host, port)
      return Requester::TCP.new(host, port)
    rescue Errno::ECONNREFUSED
      # Treat a refused TCP connection attempt to a nameserver like a timeout,
      # as Resolv::DNS::Config#resolv considers ResolvTimeout exceptions as a
      # hint to try the next nameserver:
      raise ResolvTimeout
    end
  end
end


# Fix for (unreported) "nil can't be coerced into Fixnum" TypeError exception
# caused by truncated (or otherwise malformed) answer packets.
###############################################################################

class Resolv
  class DNS
    class Message
      class MessageDecoder

        def get_labels(limit=nil)
          limit = @index if !limit || @index < limit
          d = []
          while true
            case @data[@index] && @data[@index].ord                             # PATCH
            when nil                                                            # PATCH
              raise DecodeError.new("truncated or malformed packet")            # PATCH
            when 0
              @index += 1
              return d
            when 192..255
              idx = self.get_unpack('n')[0] & 0x3fff
              if limit <= idx
                raise DecodeError.new("non-backward name pointer")
              end
              save_index = @index
              @index = idx
              d += self.get_labels(limit)
              @index = save_index
              return d
            else
              d << self.get_label
            end
          end
          return d
        end

      end
    end
  end
end


# Patch to expose timeout and NXDOMAIN errors to the ultimate caller of
# Resolv::DNS rather than swallowing them silently and returning an empty
# result set.
###############################################################################

class Resolv
  class TimeoutError  < ResolvError; end
  class NXDomainError < ResolvError; end

  class DNS
    class Config
      attr_accessor :raise_errors                                               # PATCH
      def resolv(name)
        candidates = generate_candidates(name)
        timeouts = generate_timeouts
        # Collect errors while making the various lookup attempts:              # PATCH
        errors = []                                                             # PATCH
        begin
          candidates.each {|candidate|
            begin
              timeouts.each {|tout|
                @nameserver_port.each {|nameserver, port|
                  begin
                    yield candidate, tout, nameserver, port
                  rescue ResolvTimeout
                  end
                }
              }
              # Collect a timeout:                                              # PATCH
              errors << TimeoutError.new("DNS resolv timeout: #{name}")         # PATCH
            rescue NXDomain
              # Collect an NXDOMAIN error:                                      # PATCH
              errors << NXDomainError.new("DNS name does not exist: #{name}")   # PATCH
            end
          }
        rescue ResolvError
          # Allow subclasses to set this to override this behavior without      # PATCH
          # wholesale monkeypatching.                                           # PATCH
          raise if raise_errors                                                 # PATCH
          # Ignore other errors like vanilla Resolv::DNS does.                  # PATCH
          # Perhaps this is not a good idea, though, as it silently swallows    # PATCH
          # SERVFAILs, etc.                                                     # PATCH
        end
        # If one lookup succeeds, we will have returned within "yield" already. # PATCH
        # Otherwise we now raise the first error that occurred:                 # PATCH
        raise errors.first if not errors.empty?                                 # PATCH
      end
    end
  end
end

# vim:sw=2 sts=2
