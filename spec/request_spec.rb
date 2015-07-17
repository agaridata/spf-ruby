require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe 'SPF::Request instantiation' do
  request = SPF::Request.new(
    versions:      [1, 2],
    scope:         'mfrom',
    identity:      'fred@example.com',
    ip_address:    '192.168.0.1',
    helo_identity: 'mta.example.com',
  )

  it 'is a basic request object' do
    expect(request.is_a?(SPF::Request)).to be_truthy
  end

  it 'has correct request versions' do
    expect(request.versions).to eq [1, 2]
  end

  it 'has correct scope' do
    expect(request.scope).to eq :mfrom
  end

  it 'has correct authority_domain' do
    expect(request.authority_domain).to eq 'example.com'
  end

  it 'has correct identity' do
    expect(request.identity).to eq 'fred@example.com'
  end

  it 'has correct domain' do
    expect(request.domain).to eq 'example.com'
  end

  it 'has correct localpart' do
    expect(request.localpart).to eq 'fred'
  end

  it 'has correct ip address' do
    expect(request.ip_address.is_a?(IP)).to be_truthy
    expect(request.ip_address).to eq IP.new('192.168.0.1')
  end

  it 'has correct helo identity' do
    expect(request.helo_identity).to eq 'mta.example.com'
  end

  it 'creates sub-request object' do
    clone = request.new_sub_request(ip_address: '192.168.0.254')
    expect(clone.identity).to eq 'fred@example.com'
    expect(clone.ip_address).to eq IP.new('192.168.0.254')
  end
end

describe 'SPF::Request minimally parameterized MAIL FROM request' do
  request = SPF::Request.new(
    identity: 'fred@example.com',
    ip_address: '192.168.0.1'
  )

  it 'is an SPF::Request object' do
    expect(request.is_a?(SPF::Request)).to be_truthy
  end

  it  'has correct versions' do
    expect(request.versions).to eq [1, 2]
  end

  it 'has correct scope' do
    expect(request.scope).to eq :mfrom
  end

  it 'has correct authority_domain' do
    expect(request.authority_domain).to eq 'example.com'
  end

  it 'has no helo_identity' do
    expect(request.helo_identity).to be nil
  end
end

describe 'SPF::Request minimally parameterized HELO request' do
  request = SPF::Request.new(
    scope: 'helo',
    identity: 'mta.example.com',
    ip_address: '192.168.0.1'
  )

  it 'is an SPF::Request object' do
    expect(request.is_a?(SPF::Request)).to be_truthy
  end

  it 'has correct versions' do
    expect(request.versions).to eq [1]
  end

  it 'has correct scope' do
    expect(request.scope).to eq :helo
  end

  it 'has correct authority_domain' do
    expect(request.authority_domain).to eq 'mta.example.com'
  end

  it 'has correct helo_identity' do
    expect(request.helo_identity).to eq 'mta.example.com'
  end
end

describe 'versions validation' do
  
  it 'supports versions => int' do
    request = SPF::Request.new(
      versions:   1,
      identity:   'fred@example.com',
      ip_address: '192.168.0.1'
    )
    expect(request.versions).to eq [1]
  end

  it 'raises error on invalid versions type' do
    expect {
      request = SPF::Request.new ( {
        versions: {}, # Illegal versions type!
        identity: 'fred@example.com',
        ip_address: '192.168.0.1'
      })
    }.to raise_error(SPF::InvalidOptionValueError)
  end

  it 'detects illegal versions' do
    expect {
      request = SPF::Request.new ( {
        versions: [1, 666], # Illegal versions number!
        identity: 'fred@example.com',
        ip_address: '192.168.0.1'
      })
    }.to raise_error(SPF::InvalidOptionValueError)
  end

  it 'drops versions irrelevant for scope' do
    request = SPF::Request.new ({
        versions:   [1, 2],
        scope:      :helo,
        identity:   'mta.example.com',
        ip_address: '192.168.0.1',
    })
    expect(request.versions).to eq [1]
  end
end

describe 'scope validation' do
  it 'detects invalid scope' do
    expect {
      SPF::Request.new(
        scope:      :foo,
        identity:   'fred@example.com',
        ip_address: '192.168.0.1',
      )
    }.to raise_error(SPF::InvalidScopeError)
  end

  it'detects invalid scope for versions' do
    expect {
      SPF::Request.new(
        scope:      :pra,
        versions:   1,
        identity:   'fred@example.com',
        ip_address: '192.168.0.1',
      )
    }.to raise_error(SPF::InvalidScopeError)
  end
end

describe 'identity validation' do
  it 'detects missing identity option' do
    expect {
      SPF::Request.new(
        ip_address: '192.168.0.1',
      )
    }.to raise_error(SPF::OptionRequiredError)
  end

  request = SPF::Request.new(
    scope:      :mfrom,
    identity:   'mta.example.com',
    ip_address: '192.168.0.1',
  )

  it 'extracts domain from identity correctly' do
    expect(request.domain).to eq 'mta.example.com'
  end

  it 'has default "postmaster" localpart' do
    expect(request.localpart).to eq 'postmaster'
  end
end

describe 'IP address validation' do

  it 'accepts IP object for ip_address' do
    ip_address = IP.new('192.168.0.1')
    request = SPF::Request.new(
      identity:   'fred@example.com',
      ip_address: ip_address
    )
    expect(request.ip_address).to be ip_address
  end

  it 'treats IPv4-mapped IPv6 address as IPv4 address' do
    request = SPF::Request.new(
      identity:   'fred@example.com',
      ip_address: '::ffff:192.168.0.1'
    )
    expect(request.ip_address).to eq IP.new('192.168.0.1')
  end
end

describe 'custom request state' do
  request = SPF::Request.new(
    identity:   'fred@example.com',
    ip_address: '192.168.0.1',
  )

  it 'reads uninitialized state field' do
    expect(request.state('uninitialized')).to be nil
  end

  it 'writes and reads state field' do
    request.state('foo', 'bar')
    expect(request.state('foo')).to eq 'bar'
  end
end
