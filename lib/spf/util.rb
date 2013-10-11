require 'ip'
require 'socket'

require 'spf/error'

#
# == SPF utility class
#

# Interface:
# ##############################################################################


# == SYNOPSIS
# 
# require 'spf/util'
#
#
# hostname              = SPF::Util.hostname
#
# ipv6_address_v4mapped = SPF::Util.ipv4_address_to_ipv6(ipv4_address)
#
# ipv4_address          = SPF::Util->ipv6_address_to_ipv4($ipv6_address_v4mapped)
#
# is_v4mapped           = SPF::Util->ipv6_address_is_ipv4_mapped(ipv6_address)
#
# ip_address_string     = SPF::Util->ip_address_to_string(ip_address)
#
# reverse_name          = SPF::Util->ip_address_reverse(ip_address)
#
# validated_domain      = SPF::Util->valid_domain_for_ip_address(
#                           spf_server, request, ip_address, domain,
#                           find_best_match,  # Defaults to false
#                           accept_any_domain # Defaults to false
#                         )
# sanitized_string      = SPF::Util->sanitize_string(string)
#

class SPF::Util
  
  IPV4_MAPPED_IPV6_ADDRESS_PATTERN =
    /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})/i

  saved_hostname = nil

  def self.hostname
    return saved_hostname ||= Socket.gethostbyname(Socket.gethostname).first
  end

  def self.ipv4_address_to_ipv6(ipv4_address)
    unless ipv4_address.is_a?(IP::V4)
      raise SPF::InvalidOptionValueError.new('IP::V4 address expected')
    end
    return IP.new('::ffff:' + ipv4_address.to_s + '/' + (ipv4_address.to_a[2] - 32 + 128).to_s)
  end

  def self.ipv6_address_to_ipv4(ipv6_address)
    unless (ipv6_address.is_a?(IP::V6) and ipv6_address =~ IPV4_MAPPED_IPV6_ADDRESS_PATTERN)
      raise SPF::InvalidOptionValueError.new('IP::V4-mapped IP::V6 address expected')
    end
    mask = ipv6_address.to_a[2]
    return IP.new([$1 + $2].pack('H8').unpack('C4') + mask >= 128 - 32 ? mask - 128 + 32 : 0)
  end

  def self.ipv6_address_is_ipv4_mapped(ipv6_address)
    return (ipv6_address.is_a?(IP::V6) and ipv6_address =~ IPV4_MAPPED_IPV6_ADDRESS_PATTERN)
  end

  def self.ip_address_to_string(ip_address)
    unless ip_address.is_a?(IP::V4) or ip_address.is_a?(IP::V6)
      raise SPF::InvalidOptionValueError.new('IP::V4 IP::V6 address expected')
    end
    return ip_address.to_s.downcase
  end

  def self.ip_address_reverse(ip_address)
    unless ip_address.is_a?(IP::V4) or ip_address.is_a?(IP::V6)
      raise SPF::InvalidOptionValueError.new('IP::V4 or IP::V6 address expected')
    end
    begin
      # Treat IPv4-mapped IPv6 addresses as IPv4 addresses:
      ip_address = ipv6_address_to_ipv4(ip_address)
    rescue SPF::InvalidOptionValueError
      # Ignore conversion errors.
    end
    if ip_address.is_a?(IP::V4)
      return ip_address.to_s.split('.').reverse.join('.') + '.in-addr.arpa.'
    elsif ip_address.is_a?(IP::V6)
      nibbles = ip_address.to_hex.split('')
      nibbles = nibbles[0 .. ip_address.to_a[2] / 8 - 1]
      return nibbles.reverse.join('.') + '.ip6.arpa.'
    end
  end
end
