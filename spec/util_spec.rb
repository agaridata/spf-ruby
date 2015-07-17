require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

require 'ip'

ipv4_address          = IP.new('192.168.0.1')
ipv6_address_v4mapped = IP.new('::ffff:192.168.0.1')
ipv6_address          = IP.new('2001:db8::1')

describe "SPF::Util.ipv4_address_to_ipv6" do
  it "returns IP object" do
    expect(SPF::Util.ipv4_address_to_ipv6(ipv4_address).is_a?(IP)).to be_truthy
  end

  it "yields correct IPv4-mapped IPv6 address" do
    expect(SPF::Util.ipv4_address_to_ipv6(ipv4_address)).to eq ipv6_address_v4mapped
  end

  it "ipv4_address_to_ipv6(string) exception" do
    expect {SPF::Util.ipv4_address_to_ipv6('192.168.0.1')}.to raise_error(SPF::InvalidOptionValueError)
  end

  it "ipv4_address_to_ipv6(ipv6_address) exception" do
    expect {SPF::Util.ipv4_address_to_ipv6(ipv6_address_v4mapped)}.to raise_error(SPF::InvalidOptionValueError)
  end
end

describe "SPF::Util.ipv6_address_to_ipv4" do
  it "returns IP object" do
    expect(SPF::Util.ipv6_address_to_ipv4(ipv6_address_v4mapped).is_a?(IP)).to be_truthy
  end

  it "yields correct IPv4 address" do
    expect(SPF::Util.ipv6_address_to_ipv4(ipv6_address_v4mapped)).to eq ipv4_address
  end

  it "ipv6_address_to_ipv4(string) exception" do
    expect {SPF::Util.ipv6_address_to_ipv4('2001:db8::1')}.to raise_error(SPF::InvalidOptionValueError)
  end

  it "ipv6_address_to_ipv4(ipv4_address) exception" do
    expect {SPF::Util.ipv6_address_to_ipv4(ipv4_address)}.to raise_error(SPF::InvalidOptionValueError)
  end
end

describe "SPF::Util:::ip_address_reverse" do
  it "reverses IPv4 address" do
    expect(SPF::Util.ip_address_reverse(ipv4_address)).to eq '1.0.168.192.in-addr.arpa.'
  end

  it "reverses IPv6 address mapped from IPv4 address" do
    expect(SPF::Util.ip_address_reverse(ipv6_address_v4mapped)).to eq '1.0.168.192.in-addr.arpa.'
  end

  it "reverses IPv6 address" do
    expect(SPF::Util.ip_address_reverse(ipv6_address)).to eq(
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.')
  end
end


