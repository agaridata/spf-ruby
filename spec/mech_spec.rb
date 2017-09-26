require 'spec_helper'
require 'resolv_programmable'

describe SPF::Mech::Exists do
  before(:all) do
    @request = SPF::Request.new ({
      identity: 'somebody@example.com'
    })
  end

  describe '#match' do
    context 'when an A record is found' do
      test_resolver_1 = Resolv::DNS::Programmable.new ({
        records: {
          'example.com' => [
             Resolv::DNS::Resource::IN::A.new('192.168.0.1')
          ]
        }
      })

      server = SPF::Server.new(
        dns_resolver: test_resolver_1
      )

      mech = SPF::Mech::Exists.new ({
        text: 'example.com',
        server: server,
        request: @request
      })

      it 'returns true' do
        mech_match = mech.match(server, @request)
        expect(mech_match).to be_truthy
      end
    end

    context 'when an A record is not found' do
      test_resolver_empty = Resolv::DNS::Programmable.new ({
        records: {}
      })

      server = SPF::Server.new(
        dns_resolver: test_resolver_empty
      )

      mech = SPF::Mech::Exists.new ({
        text: 'example.com',
        server: server,
        request: @request
      })

      it 'returns false' do
        mech_match = mech.match(server, @request)
        expect(mech_match).to be_falsy
      end
    end
  end
end
