require 'spec_helper'

describe SPF::MacroString do
  before(:each) do
    @request = SPF::Request.new(
      identity: 'strong-bad@email.example.com',
      ip_address: IP.new('192.0.2.3')
    )
    @server = SPF::Server.new
  end

  # RFC 4408, 8.1/26

  describe '#expand' do
    context 'given a valid macro string' do
      it 'expands the "s" macro letter to <sender>' do
        macro_str = described_class.new(
          text: '%{s}',
          request: @request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('strong-bad@email.example.com')
      end

      it 'expands the "l" macro letter to local-part of <sender>' do
        macro_str = described_class.new(
          text: '%{l}',
          request: @request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('strong-bad')
      end

      it 'expands the "o" macro letter to domain of <sender>' do
        macro_str = described_class.new(
          text: '%{o}',
          request: @request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('email.example.com')
      end

      it 'expands the "d" macro letter to <domain>' do
        macro_str = described_class.new(
          text: '%{d}',
          request: @request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('email.example.com')
      end

      it 'expands the "i" macro letter to <ip>' do
        macro_str = described_class.new(
          text: '%{i}',
          request: @request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('192.0.2.3')
      end

      it 'does not expand the "p" macro letter' do
        macro_str = described_class.new(
          text: '%{p}',
          request: @request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('%{p}')
      end

      it 'does not expand the "p" macro letter with transformers and delimiters' do
        macro_str = described_class.new(
          text: 'spamhaus.%{p1r+}.example.org',
          request: @request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('spamhaus.%{p1r+}.example.org')
      end

      it 'expands the "v" macro letter to the string "in-addr" if <ip> is ipv4' do
        macro_str = described_class.new(
          text: '%{v}',
          request: @request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('in-addr')
      end

      it 'expands the "v" macro letter to the string "ip6" if <ip> is ipv6' do
        request = SPF::Request.new(
          identity: 'strong-bad@email.example.com',
          ip_address: IP.new('2001:DB8::CB01')
        )
        macro_str = described_class.new(
          text: '%{v}',
          request: request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('ip6')
      end

      it 'expands the "h" macro letter to HELO/EHLO domain' do
        request = SPF::Request.new(
          identity: 'strong-bad@email.example.com',
          ip_address: '192.0.2.3',
          helo_identity: 'helo'
        )
        macro_str = described_class.new(
          text: '%{h}',
          request: request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('helo')
      end

      it 'expands the "c" macro letter to SMTP client IP (easily readable format)' do
        macro_str = described_class.new(
          text: '%{c}',
          request: @request,
          server: @server,
          is_explanation: true
        )
        expanded = macro_str.expand
        expect(expanded).to eq('192.0.2.3')
      end

      it 'expands the "r" macro letter to domain name of host performing the check' do
        server = SPF::Server.new(
          hostname: 'hostname'
        )
        macro_str = described_class.new(
          text: '%{r}',
          request: @request,
          server: server,
          is_explanation: true
        )
        expanded = macro_str.expand
        expect(expanded).to eq('hostname')
      end

      it 'expands the "t" macro letter to current timestamp' do
        time_now = Time.now
        allow(Time).to receive(:now).and_return(time_now)
        macro_str = described_class.new(
          text: '%{t}',
          request: @request,
          server: @server,
          is_explanation: true
        )
        expanded = macro_str.expand
        expect(expanded).to eq(time_now.to_i.to_s)
      end

      # Examples from RFC 4408 8.2/30

      it 'expands "%{ir}.%{v}._spf.%{d2}" correctly' do
        macro_str = described_class.new(
          text: '%{ir}.%{v}._spf.%{d2}',
          request: @request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('3.2.0.192.in-addr._spf.example.com')
      end

      it 'expands "%{lr-}.lp._spf.%{d2}" correctly' do
        macro_str = described_class.new(
          text: '%{lr-}.lp._spf.%{d2}',
          request: @request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('bad.strong.lp._spf.example.com')
      end

      it 'expands "%{lr-}.lp.%{ir}.%{v}._spf.%{d2}" correctly' do
        macro_str = described_class.new(
          text: '%{lr-}.lp.%{ir}.%{v}._spf.%{d2}',
          request: @request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('bad.strong.lp.3.2.0.192.in-addr._spf.example.com')
      end

      it 'expands "%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}" correctly' do
        macro_str = described_class.new(
          text: '%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}',
          request: @request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('3.2.0.192.in-addr.strong.lp._spf.example.com')
      end

      it 'expands "%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}" correctly' do
        macro_str = described_class.new(
          text: '%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}',
          request: @request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('3.2.0.192.in-addr.strong.lp._spf.example.com')
      end

      it 'expands "%{ir}.%{v}._spf.%{d2}" correctly with an IPv6 request' do
        request = SPF::Request.new(
          identity: 'strong-bad@email.example.com',
          ip_address: IP.new('2001:DB8::CB01')
        )
        macro_str = described_class.new(
          text: '%{ir}.%{v}._spf.%{d2}',
          request: request,
          server: @server
        )
        expanded = macro_str.expand
        expect(expanded).to eq('1.0.B.C.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.B.D.0.1.0.0.2.ip6._spf.example.com')
      end
    end

    context 'given an invalid macro string' do
      context 'A "%"" character not followed by a "{", "%", "-", or "_" character' do
        it 'returns an "InvalidMacroStringError"' do
          macro_str = described_class.new(
            text: '-exists:%(ir).sbl.spamhaus.example.org',
            request: @request,
            server: @server
          )
          expect { macro_str.expand }.to raise_error(SPF::InvalidMacroStringError)
        end
      end

      context 'A non-allowed macro letter' do
        it 'returns an "InvalidMacroStringError"' do
          macro_str = described_class.new(
            text: '%{z}.sbl.spamhaus.example.org',
            request: @request,
            server: @server
          )
          expect { macro_str.expand }.to raise_error(SPF::InvalidMacroStringError)
        end
      end

      context 'A macro expression without a closing bracket' do
        it 'returns an "InvalidMacroStringError"' do
          macro_str = described_class.new(
            text: '%{i.sbl.spamhaus.example.org',
            request: @request,
            server: @server
          )
          expect { macro_str.expand }.to raise_error(SPF::InvalidMacroStringError)
        end
      end
    end
  end
end
