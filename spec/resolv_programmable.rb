require 'resolv'

class Resolv::DNS
  class Programmable < Resolv::DNS
    def initialize(config_info = nil, &resolver_code)
      super
      config_info  ||= {}
      @records       = config_info[:records]       || {}
      @resolver_code = config_info[:resolver_code] || resolver_code
      if not @records and not @resolver_code
        raise ArgumentError, "Either :records option or resolver code specified as block or :resolver_code option required"
      end
      if not @records and     @resolver_code and not @resolver_code.respond_to?(:call)
        raise ArgumentError, "Resolver code not callable"
      end
      @dns_fallback  = config_info[:dns_fallback]  || false
    end

    def each_resource(name, typeclass, &proc)
      lazy_initialize
      name = Name.create(name).to_s  # Validate/normalize name argument.

      rcode, answers = nil, []

      # First, call resolver code, if any:
      if @resolver_code
        rcode, answers   = @resolver_code.call(name, typeclass)
               answers ||= []
      end

      # Second, get records from records hash, if any:
      if not rcode and @records
        records_for_name = @records[name]
        case records_for_name
        when nil
          # No records defined. Do nothing.
        when Integer
          # RCODE.
          rcode, answers = records_for_name, []
        when Array
          # Answer records.
          records_for_name = records_for_name.dup
          records_for_name.select! { |resource| resource.class == typeclass } \
            unless typeclass == Resolv::DNS::Resource::IN::ANY
          if records_for_name.any?
            rcode, answers = RCode::NoError, answers + records_for_name
          end
        else
          raise ArgumentError, "Value in :records option hash must be one of nil, RCode::*, or Array of Resolv::DNS::Resource; got: #{records_for_name.inspect}"
        end
      end

      # Third, fall back to DNS resolution, if allowed:
      if not rcode and @dns_fallback
        return super
      end

      rcode ||= answers.any? ? RCode::NoError : RCode::NXDomain

      case rcode
      when RCode::NoError
        # Synthesize reply for consumption by extract_resources:
        reply = Message.new
        answers.each do |resource|
          reply.add_answer(name, nil, resource)
        end
        extract_resources(reply, name, typeclass, &proc)
        return
      when RCode::NXDomain
        @config.resolv(name) do  # Give Resolv::DNS::Config#resolv a chance to handle the exception.
          raise Config::NXDomain.new(name.to_s)
        end
      else
        @config.resolv(name) do  # Give Resolv::DNS::Config#resolv a chance to handle the exception.
          raise Config::OtherResolvError.new(name.to_s)
        end
      end
    end
  end
end

# vim:sw=2 sts=2
