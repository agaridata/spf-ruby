require 'spf/test'

require 'ip'
require 'yaml'

#class Resolv::DNS::Resource::IN::SPF < Resolv::DNS::Resource::IN::TXT
  # resolv.rb doesn't define an SPF resource type.
#  TypeValue = 99
#end

module SPF::Test
class SPF::Test::Scenario

  attr_accessor :records, :test_cases, :description, :records_by_domain

  def self.new_from_yaml_struct(yaml_struct, options = {})
    obj = self.new

    puts 'SPF::Test::Scenario.new_from_yaml_struct'
    obj.description = yaml_struct['description']
    tests = yaml_struct['tests']
    test_cases = obj.test_cases = {}
    tests.each_key do |test_name|
      tests[test_name]['name'] = test_name
      test_cases[test_name] = SPF::Test::Case.new_from_yaml_struct(tests[test_name])
    end

    zonedata = yaml_struct['zonedata'] || {}
    records  = obj.records = []
    records_by_domain = obj.records_by_domain = {}

    zonedata.each_key do |domain|
      records_by_type = records_by_domain[domain.downcase] = {}
      txt_rr_synthesis = true
      zonedata[domain].each do |record_struct|
        if Hash === record_struct
          # TYPE => DATA
          type, data_struct = record_struct.each_pair.first

          if data_struct =~ /^(TIMEOUT|RCODE[1-5])$/
            records_by_type[type] = data_struct
          elsif data_struct == 'NO-SYNTHESIS' and type == 'TXT'
            txt_rr_synthesis = false
          else
            record = nil
            if type == 'SPF' or type == 'TXT'
              if data_struct == 'NONE'
                txt_rr_synthesis = false
                next
              else
                data_struct = [data_struct] unless Array === data_struct
                if type == 'SPF'
                  record = Resolv::DNS::Resource::IN::SPF.new(data_struct)
                else
                  record = Resolv::DNS::Resource::IN::TXT.new(data_struct)
                end
              end
            elsif type == 'A' or type == 'AAAA'
              address = IP.new(data_struct).to_s
              if type == 'A'
                record = Resolv::DNS::Resource::IN::A.new(address)
              else
                record = Resolv::DNS::Resource::IN::AAAA.new(address)
              end
            elsif type == 'MX'
              record = Resolv::DNS::Resource::IN::MX.new(
                data_struct[0], data_struct[1]
              )
            elsif type == 'PTR'
              record = Resolv::DNS::Resource::IN::PTR.new(data_struct)
            elsif type == 'CNAME'
              record = Resolv::DNS::Resource::IN::CNAME.new(data_struct)
            else
              # Unexpected RR type!
              raise ArgumentError, "Unexpected RR type '#{type}' in zonedata"
            end
            raise Exception, 'nil record!' unless record
            (records_by_type[type] ||= []) << record
            records << record
          end
        elsif String === record_struct
          # TIMEOUT, RCODE#, NO-TXT-SYNTHESIS
          if record_struct =~ /^(TIMEOUT|RCODE[1-5])$/
            records_by_type['ANY'] = record_struct
          elsif record_struct == 'NO-TXT-SYNTHESIS'
            txt_rr_synthesis = false
          else
            raise ArgumentError, 'Unexpected record token'
          end
        else
          raise ArgumentError, 'Unexpected record structure'
        end
      end

      # TXT RR synthesis:
      if (
        txt_rr_synthesis and
        records_by_type.has_key?('SPF') and
        not records_by_type.has_key?('TXT')
        )
        records_by_type['SPF'].each do |spf_record|
          txt_record = Resolv::DNS::Resource::IN::TXT.new(*spf_record.strings)
          records_by_type['TXT'] ||= []
          records_by_type['TXT'] << txt_record
        end
      end
    end

    return obj
  end

  def self.new_from_yaml(yaml_struct, options = {})
    return self.new_from_yaml_struct(yaml_struct)
  end

  def as_yaml
    raw_yaml_data = {
      description: @description,
      tests:       @tests,
      zonedata:    @zonedata
    }
    return YAML.dump(raw_yaml_data)
  end

  def test_cases
    return @test_cases.values
  end

  def spec_refs(granularity)
    return @test_cases.map{|x| x.spec_refs(granularity)}.sort.uniq
  end

  def records_for_domain(domain, type)
    domain = domain.sub(/^\./, '')
    domain = domain.sub(/\.$/, '')
    type ||= 'ANY'

    recordset = @records_by_domain[domain] or return []; # Uknown domain.

    # ANY queries are unsupported, return RCODE 4 ("not implemented"):
    return 'RCODE4' if type == 'ANY'

    # Use TIMEOUT/RCODE#/RRs entry meant for requested type:
    return recordset[type] if recordset[type]

    # Use TIMEOUT/RCODE#/RRs meant for any type:
    return recordset['ANY'] if recordset['ANY']

    return []
  end
end
end