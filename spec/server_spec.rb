require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/resolv_programmable')

test_resolver_empty = Resolv::DNS::Programmable.new ({
  records: {}
})

test_resolver_1 = Resolv::DNS::Programmable.new ({
  records: {
    'example.com' => [
       Resolv::DNS::Resource::IN::A.new('192.168.0.1')
    ]
  }
})

test_resolver_redirect = Resolv::DNS::Programmable.new ({
  records: {
    'example.com' => [
      Resolv::DNS::Resource::IN::TXT.new('v=spf1 redirect=foo.example.com')
    ],
    'foo.example.com' => [
      Resolv::DNS::Resource::IN::TXT.new('v=spf1 ~all')
    ]
  }
})

test_resolver_nxdomain = Resolv::DNS::Programmable.new ({
  resolver_code: lambda { |name, typeclass|
    next Resolv::DNS::RCode::NXDomain
  }
})

test_resolver_servfail = Resolv::DNS::Programmable.new ({
  resolver_code: lambda { |name, typeclass|
    next Resolv::DNS::RCode::ServFail
  }
})

test_resolver_poorly_formed_record_address = Resolv::DNS::Programmable.new ({
  records: {
    'carminic.us' => [
      Resolv::DNS::Resource::IN::TXT.new('v=spf1 ip6: 9C55::5E3D -all')
    ],
  }
})

describe 'basic instantiation' do
  server = SPF::Server.new(
    dns_resolver: test_resolver_empty,
    max_dns_interactive_terms:     1,
    max_name_lookups_per_term:     2,
    max_name_lookups_per_mx_mech:  3,
    max_name_lookups_per_ptr_mech: 2,
  )

  it 'has a basic dns_resolver' do
    expect(server.dns_resolver).to be_a Resolv::DNS::Programmable
  end
  it 'has correct max_dns_interactive_terms' do
    expect(server.max_dns_interactive_terms).to be 1
  end
  it 'has correct max_name_lookups_per_term' do
    expect(server.max_name_lookups_per_term).to be 2
  end
  it 'has correct max_name_lookups_per_mx_mech' do
    expect(server.max_name_lookups_per_mx_mech).to be 3
  end
  it 'has correct max_name_lookups_per_ptr_mech' do
    expect(server.max_name_lookups_per_ptr_mech).to be 2
  end
end

describe 'minimal parameterized server' do
  server = SPF::Server.new
  it 'has default dns_resolver' do
    expect(server.dns_resolver).to be_a Resolv::DNS
  end
  it 'has default max_dns_interactive_terms' do
    expect(server.max_dns_interactive_terms).to be 10
  end
  it 'has default max_name_lookups_per_term' do
    expect(server.max_name_lookups_per_term).to be 10
  end
  it 'has default max_name_lookups_per_mx_mech' do
    expect(server.max_name_lookups_per_mx_mech).to be 10
  end
  it 'has default max_name_lookups_per_ptr_mech' do
    expect(server.max_name_lookups_per_ptr_mech).to be 10
  end
end

describe 'dns_lookup' do
  server = SPF::Server.new(
    dns_resolver: test_resolver_empty
  )
  it 'returns empty response' do
    expect { server.dns_lookup('example.com', 'A') }.to raise_error(SPF::DNSNXDomainError)
  end
end

describe 'A-record lookup' do
  server = SPF::Server.new(
    dns_resolver: test_resolver_1
  )
  packet = server.dns_lookup('example.com', 'A')
  it 'returns 1-record result set' do
    expect(packet.length).to be 1
  end
  it 'returns correct address' do
    expect(packet[0]).to eq Resolv::DNS::Resource::IN::A.new('192.168.0.1')
  end
end

describe 'NXDOMAIN lookup' do
  server = SPF::Server.new(
    dns_resolver: test_resolver_nxdomain
  )
  it 'returns empty result set' do
    expect { server.dns_lookup('example.com', 'A') }.to raise_error(SPF::DNSNXDomainError)
  end
end

describe 'SERVFAIL lookup' do
  server = SPF::Server.new(
    dns_resolver: test_resolver_servfail
  )
  packet = server.dns_lookup('example.com', 'A')
  it 'returns empty result set??' do
    expect(packet).to eq []
  end
end

describe 'redirect lookup' do
  server = SPF::Server.new(
    dns_resolver: test_resolver_redirect
  )
  request = SPF::Request.new(
    versions: [1],
    scope: :mfrom,
    identity: 'example.com',
    ip_address: '10.0.0.1'
  )
  it 'should give softfail result on redirect: -> ~all' do
    expect(server.process(request)).to be_a SPF::Result::SoftFail
  end
end



#### SPF Record Selection / select_record(), get_acceptable_records_from_packet() ####

# See also the RFC 4408 test suite.

describe 'bad record address' do
  server = SPF::Server.new(
    dns_resolver: test_resolver_poorly_formed_record_address,
    raise_exceptions: false,
  )
  request = SPF::Request.new(
    versions: [1],
    scope: :mfrom,
    identity: 'carminic.us',
  )
  it 'returns a record with errors' do
    spf_record_error_types = server.select_record(request).errors.map {|err| err.class }
    expect(spf_record_error_types).to include(SPF::TermIPv6AddressExpectedError)
  end

end
