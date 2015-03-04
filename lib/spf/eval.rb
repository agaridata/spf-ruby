# encoding: ASCII-8BIT
require 'ip'
require 'resolv'

require 'spf/error'
require 'spf/model'
require 'spf/result'

class Resolv::DNS::Resource::IN::SPF < Resolv::DNS::Resource::IN::TXT
  # resolv.rb doesn't define an SPF resource type.
  TypeValue = 99
end

class SPF::Server

  attr_accessor \
    :default_authority_explanation,
    :hostname,
    :dns_resolver,
    :query_rr_types,
    :max_dns_interactive_terms,
    :max_name_lookups_per_term,
    :max_name_lookups_per_mx_mech,
    :max_name_lookups_per_ptr_mech,
    :max_void_dns_lookups

  RECORD_CLASSES_BY_VERSION = {
    1 => SPF::Record::V1,
    2 => SPF::Record::V2
  }

  RESULT_BASE_CLASS = SPF::Result

  QUERY_RR_TYPE_ALL = 0
  QUERY_RR_TYPE_TXT = 1
  QUERY_RR_TYPE_SPF = 2

  DEFAULT_DEFAULT_AUTHORITY_EXPLANATION =
    'Please see http://www.openspf.org/Why?s=%{_scope};id=%{S};ip=%{C};r=%{R}'

  DEFAULT_MAX_DNS_INTERACTIVE_TERMS     = 10 # RFC 4408, 10.1/6
  DEFAULT_MAX_NAME_LOOKUPS_PER_TERM     = 10 # RFC 4408, 10.1/7
  DEFAULT_QUERY_RR_TYPES                = QUERY_RR_TYPE_TXT
  DEFAULT_MAX_NAME_LOOKUPS_PER_MX_MECH  = DEFAULT_MAX_NAME_LOOKUPS_PER_TERM
  DEFAULT_MAX_NAME_LOOKUPS_PER_PTR_MECH = DEFAULT_MAX_NAME_LOOKUPS_PER_TERM
  DEFAULT_MAX_VOID_DNS_LOOKUPS          = 2

  LOOSE_SPF_MATCH_PATTERN = 'v=spf'

  def initialize(options = {})
    @default_authority_explanation = options[:default_authority_explanation] ||
      DEFAULT_DEFAULT_AUTHORITY_EXPLANATION
    unless SPF::MacroString === @default_authority_explanation
      @default_authority_explanation = SPF::MacroString.new({
        :text           => @default_authority_explanation,
        :server         => self,
        :is_explanation => true
      })
    end
    @hostname                      = options[:hostname]     || SPF::Util.hostname
    @dns_resolver                  = options[:dns_resolver] || Resolv::DNS.new
    @query_rr_types                = options[:query_rr_types]                ||
      DEFAULT_QUERY_RR_TYPES
    @max_dns_interactive_terms     = options[:max_dns_interactive_terms]     ||
      DEFAULT_MAX_DNS_INTERACTIVE_TERMS
    @max_name_lookups_per_term     = options[:max_name_lookups_per_term]     ||
      DEFAULT_MAX_NAME_LOOKUPS_PER_TERM
    @max_name_lookups_per_mx_mech  = options[:max_name_lookups_per_mx_mech]  ||
      DEFAULT_MAX_NAME_LOOKUPS_PER_MX_MECH
    @max_name_lookups_per_ptr_mech = options[:max_name_lookups_per_ptr_mech] ||
      DEFAULT_MAX_NAME_LOOKUPS_PER_PTR_MECH

    # TODO: We should probably do this for the above maximums.
    @max_void_dns_lookups          = options.has_key?(:max_void_dns_lookups) ? options[:max_void_dns_lookups] : DEFAULT_MAX_VOID_DNS_LOOKUPS

    @raise_exceptions = options.has_key?(:raise_exceptions) ? options[:raise_exceptions] : true

  end

  def result_class(name = nil)
    if name
      return RESULT_BASE_CLASS::RESULT_CLASSES[name]
    else
      return RESULT_BASE_CLASS
    end
  end

  def throw_result(name, request, text)
    raise self.result_class(name).new(self, request, text)
  end

  def process(request)
    request.state(:authority_explanation,       nil)
    request.state(:dns_interactive_terms_count, 0)
    request.state(:void_dns_lookups_count,      0)

    result = nil

    begin
      record = self.select_record(request)
      request.record = record
      record.eval(self, request)
    rescue SPF::Result => r
      result = r
    rescue SPF::DNSError => e
      result = self.result_class(:temperror).new([self, request, e.message])
    rescue SPF::NoAcceptableRecordError => e
      result = self.result_class(:none     ).new([self, request, e.message])
    rescue SPF::RedundantAcceptableRecordsError, SPF::SyntaxError, SPF::ProcessingLimitExceededError => e
      result = self.result_class(:permerror).new([self, request, e.message])
    end
    # Propagate other, unknown errors.
    # This should not happen, but if it does, it helps exposing the bug!

    return result
  end

  def resource_typeclass_for_rr_type(rr_type)
    return case rr_type
      when 'TXT'  then Resolv::DNS::Resource::IN::TXT
      when 'SPF'  then Resolv::DNS::Resource::IN::SPF
      when 'ANY'  then Resolv::DNS::Resource::IN::ANY
      when 'A'    then Resolv::DNS::Resource::IN::A
      when 'AAAA' then Resolv::DNS::Resource::IN::AAAA
      when 'PTR'  then Resolv::DNS::Resource::IN::PTR
      when 'MX'   then Resolv::DNS::Resource::IN::MX
      else
        raise ArgumentError, "Uknown RR type: #{rr_type}"
      end
  end

  def dns_lookup(domain, rr_type)
    if SPF::MacroString === domain
      domain = domain.expand
      # Truncate overlong labels at 63 bytes (RFC 4408, 8.1/27)
      domain.gsub!(/([^.]{63})[^.]+/, "#{$1}")
      # Drop labels from the head of domain if longer than 253 bytes (RFC 4408, 8.1/25):
      domain.sub!(/^[^.]+\.(.*)$/, "#{$1}") while domain.length > 253
    end

    rr_type = self.resource_typeclass_for_rr_type(rr_type)
    
    domain = domain.sub(/\.$/, '').downcase

    packet = nil
    begin
      packet = @dns_resolver.getresources(domain, rr_type)
    rescue Resolv::TimeoutError => e
      raise SPF::DNSTimeoutError.new(
        "Time-out on DNS '#{rr_type}' lookup of '#{domain}'")
    rescue Resolv::NXDomainError => e
      raise SPF::DNSNXDomainError.new("NXDomain for '#{domain}'")
    rescue Resolv::ResolvError => e
      raise SPF::DNSError.new("Error on DNS lookup of '#{domain}'")
    end

    # Raise DNS exception unless an answer packet with RCODE 0 or 3 (NXDOMAIN)
    # was received (thereby treating NXDOMAIN as an acceptable but empty answer packet):
    #if @dns_resolver.errorstring =~ /^(timeout|query timed out)$/
    #  raise SPF::DNSTimeoutError.new(
    #    "Time-out on DNS '#{rr_type}' lookup of '#{domain}'")
    #end

    unless packet
      raise SPF::DNSError.new(
        "Unknown error on DNS '#{rr_type}' lookup of '#{domain}'")
    end

    #unless packet.header.rcode =~ /^(NOERROR|NXDOMAIN)$/
    #  raise SPF::DNSError.new(
    #    "'#{packet.header.rcode}' error on DNS '#{rr_type}' lookup of '#{domain}'")
    #end
    return packet
  end

  def select_record(request, loose_match = false)
    domain   = request.authority_domain
    versions = request.versions
    scope    = request.scope

    # Employ identical behavior for 'v=spf1' and 'spf2.0' records, both of
    # which support SPF (code 99) and TXT type records (this may be different
    # in future revisions of SPF):
    # Query for SPF type records first, then fall back to TXT type records.

    records       = []
    loose_records = []
    query_count   = 0
    dns_errors    = []

    # Query for SPF-type RRs first:
    if (@query_rr_types == QUERY_RR_TYPE_ALL or
        @query_rr_types & QUERY_RR_TYPE_SPF)
      begin
        query_count += 1
        packet = self.dns_lookup(domain, 'SPF')
        matches = self.get_acceptable_records_from_packet(
          packet, 'SPF', versions, scope, domain, loose_match)
        records << matches[0]
        loose_records << matches[1]
      rescue SPF::DNSError => e
        dns_errors << e
      #rescue SPF::DNSTimeout => e
      #  # FIXME: Ignore DNS timeouts on SPF type lookups?
      #  # Apparently some brain-dead DNS servers time out on SPF-type queries.
      end
    end

    if (not records.flatten.any? and
        @query_rr_types == QUERY_RR_TYPE_ALL or
        @query_rr_types & QUERY_RR_TYPE_TXT)
      # NOTE:
      #   This deliberately violates RFC 4406 (Sender ID), 4.4/3 (4.4.1):
      #   TXT-type RRs are still tried if there _are_ SPF-type RRs but all
      #   of them are inapplicable (e.g. "Hi!", or even "spf2/pra" for an
      #   'mfrom' scope request).  This conforms to the spirit of the more
      #   sensible algorithm in RFC 4408 (SPF), 4.5.
      #   Implication:  Sender ID processing may make use of existing TXT-
      #   type records where a result of "None" would normally be returned
      #   under a strict interpretation of RFC 4406.
     
      begin
        query_count += 1
        packet = self.dns_lookup(domain, 'TXT')
        matches = self.get_acceptable_records_from_packet(
          packet, 'TXT', versions, scope, domain, loose_match)
        records << matches[0]
        loose_records << matches[1]
      rescue SPF::DNSError => e
        dns_errors << e
      end

      # Unless at least one query succeeded, re-raise the first DNS error that occured.
      raise dns_errors[0] unless dns_errors.length < query_count

      records.flatten!
      loose_records.flatten!

      if records.empty?
        # RFC 4408, 4.5/7
        raise SPF::NoAcceptableRecordError.new('No applicable sender policy available',
                                               loose_records)
      end

      # Discard all records but the highest acceptable version:
      preferred_record_class = records[0].class

      records = records.select { |record| preferred_record_class === record }

      if records.length != 1
        # RFC 4408, 4.5/6
        raise SPF::RedundantAcceptableRecordsError.new(
          "Redundant applicable '#{preferred_record_class.version_tag}' sender policies found",
          records
        )
      end

      return records[0]
    end
  end

  def get_acceptable_records_from_packet(packet, rr_type, versions, scope, domain, loose_match)

    # Try higher record versions first.
    # (This may be too simplistic for future revisions of SPF.)
    versions = versions.sort { |x, y| y <=> x }

    rr_type = resource_typeclass_for_rr_type(rr_type)
    records = []
    possible_matches = []
    packet.each do |rr|
      next unless rr_type === rr
      text = rr.strings.join('')
      record = false
      versions.each do |version|
        klass = RECORD_CLASSES_BY_VERSION[version]
        begin
          record = klass.new_from_string(text, {:raise_exceptions => @raise_exceptions})
        rescue SPF::InvalidRecordVersionError => error
          if text =~ /#{LOOSE_SPF_MATCH_PATTERN}/
            possible_matches << text
          end
          # Ignore non-SPF and unknown-version records.
          # Propagate other errors (including syntax errors), though.
        end
      end
      if record
        if record.scopes.select{|x| scope == x}.any?
          # Record covers requested scope.
          records << record
        end
      end
    end
    return records, possible_matches
  end

  def count_dns_interactive_term(request)
    dns_interactive_terms_count = request.root_request.state(:dns_interactive_terms_count, 1)
    if (@max_dns_interactive_terms and
        dns_interactive_terms_count > @max_dns_interactive_terms)
      raise SPF::ProcessingLimitExceededError.new(
        "Maximum DNS-interactive terms limit (#{@max_dns_interactive_terms}) exceeded")
    end
    return dns_interactive_terms_count
  end

  def count_void_dns_lookup(request)
    void_dns_lookups_count = request.root_request.state(:void_dns_lookups_count, 1)
    if (@max_void_dns_lookups and
        void_dns_lookups_count > @max_void_dns_lookups)
      raise SPF::ProcessingLimitExceededError.new(
        "Maximum void DNS look-ups limit (#{@max_void_dns_lookups}) exceeded")
    end
    return void_dns_lookups_count
  end
end

# vim:sw=2 sts=2
