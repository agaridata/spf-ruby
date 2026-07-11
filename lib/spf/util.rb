# encoding: ASCII-8BIT
require 'ipaddr'
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
    return @hostname ||= Addrinfo.getaddrinfo(Socket.gethostname, nil, nil, nil, nil, Socket::AI_CANONNAME).first.canonname
  rescue SocketError
    return @hostname ||= Socket.gethostname
  end

  def self.ipv4_address_to_ipv6(ipv4_address)
    unless IPAddr === ipv4_address and ipv4_address.ipv4?
      raise SPF::InvalidOptionValueError.new('IPv4 address expected')
    end
    return IPAddr.new("::ffff:#{ipv4_address.to_s}/#{ipv4_address.prefix - 32 + 128}")
  end

  def self.ipv6_address_to_ipv4(ipv6_address)
    unless IPAddr === ipv6_address and ipv6_address.ipv6? and ipv6_address.ipv4_mapped?
      raise SPF::InvalidOptionValueError, 'IPv4-mapped IPv6 address expected'
    end
    return ipv6_address.native
  end

  def self.ipv6_address_is_ipv4_mapped(ipv6_address)
    return ipv6_address.ipv4_mapped?
  end

  # Whether the address portion of a CIDR netblock has bits set outside the
  # network prefix (e.g. "1.2.3.4/24" has host bits set, "1.2.3.0/24" does not).
  # IPAddr masks such bits away on construction, so detection compares the
  # original, unmasked address string against the masked network.
  def self.ip_network_has_host_bits?(ip_address_string, ip_network)
    return false unless IPAddr === ip_network
    return IPAddr.new(ip_address_string.to_s).to_i != ip_network.to_i
  rescue IPAddr::Error
    return false
  end

  def self.ip_address_to_string(ip_address)
    unless IPAddr === ip_address
      raise SPF::InvalidOptionValueError.new('IP address expected')
    end
    return ip_address.to_s
  end

  def self.ip_address_reverse(ip_address)
    unless IPAddr === ip_address
      raise SPF::InvalidOptionValueError.new('IP address expected')
    end
    # Treat IPv4-mapped IPv6 addresses as IPv4 addresses:
    ip_address = ipv6_address_to_ipv4(ip_address) if ip_address.ipv4_mapped?
    if ip_address.ipv4?
      octets  = ip_address.to_s.split('.').first(ip_address.prefix / 8)
      return "#{octets .reverse.join('.')}.in-addr.arpa."
    elsif ip_address.ipv6?
      nibbles = ip_address.to_i.to_s(16).rjust(32, '0').split('').first(ip_address.prefix / 4)
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
