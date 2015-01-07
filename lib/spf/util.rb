# encoding: ASCII-8BIT

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

module SPF
  module Util

  def self.ipv4_mapped_ipv6_address_pattern
    /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})/i
  end

  def self.hostname
    return @hostname ||= Socket.gethostbyname(Socket.gethostname).first
  rescue SocketError
    return @hostname ||= Socket.gethostname
  end

  def self.ipv4_address_to_ipv6(ipv4_address)
    unless IP::V4 === ipv4_address
      raise SPF::InvalidOptionValueError.new('IP::V4 address expected')
    end
    return IP.new("::ffff:#{ipv4_address.to_addr}/#{ipv4_address.pfxlen - 32 + 128}")
  end

  def self.ipv6_address_to_ipv4(ipv6_address)
    unless IP::V6 === ipv6_address and ipv6_address.ipv4_mapped?
      raise SPF::InvalidOptionValueError, 'IPv4-mapped IP::V6 address expected'
    end
    return ipv6_address.native
  end

  def self.ipv6_address_is_ipv4_mapped(ipv6_address)
    return ipv6_address.ipv4_mapped?
  end

  def self.ip_address_to_string(ip_address)
    unless IP::V4 === ip_address or IP::V6 === ip_address
      raise SPF::InvalidOptionValueError.new('IP::V4 or IP::V6 address expected')
    end
    return ip_address.to_addr
  end

  def self.ip_address_reverse(ip_address)
    unless IP::V4 === ip_address or IP::V6 === ip_address
      raise SPF::InvalidOptionValueError.new('IP::V4 or IP::V6 address expected')
    end
    # Treat IPv4-mapped IPv6 addresses as IPv4 addresses:
    ip_address = ipv6_address_to_ipv4(ip_address) if ip_address.ipv4_mapped?
    case ip_address
    when IP::V4
      octets  = ip_address.to_addr.split('.').first(ip_address.pfxlen / 8)
      return "#{octets .reverse.join('.')}.in-addr.arpa."
    when IP::V6
      nibbles = ip_address.to_hex .split('') .first(ip_address.pfxlen / 4)
      return "#{nibbles.reverse.join('.')}.ip6.arpa."
    end
  end

  def self.valid_domain_for_ip_address(
    sever, request, ip_address, domain,
    find_best_match   = false,
    accept_any_domain = false
  )
    # TODO
  end

  def self.sanitize_string(string)
    return \
      string &&
      string.
        gsub(/([\x00-\x1f\x7f-\xff])/) { |c| sprintf('\x%02x',   c.ord) }.
        gsub(/([\u{0100}-\u{ffff}])/)  { |u| sprintf('\x{%04x}', u.ord) }
  end

  end
end

# vim:sw=2 sts=2
