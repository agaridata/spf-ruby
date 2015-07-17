require File.expand_path(File.dirname(__FILE__) + '/resolv_programmable')

require 'spf/test'

class SPFTestLib
  def self.run_spf_test_suite_file(file_name, test_case_overrides = nil)
    test_case_overrides ||= {}
  
    test_suite = SPF::Test::new_from_yaml_file(file_name)
    unless test_suite
      raise StandardError, "Unable to load test-suite data from file #{file_name}"
    end
  
    total_test_cases_count = 0
    test_suite.each do |scenario|
      total_test_cases_count += scenario.test_cases.size
    end
  
    # plan(tests => $total_test_cases_count * 2)
  
    test_suite.each do |scenario|
      server = SPF::Server.new(
        dns_resolver: Resolv::DNS::Programmable.new(
          resolver_code: lambda { |domain, rr_type|
            rcode = 'NOERROR'
            rrs = scenario.records_for_domain(domain, rr_type)
            if rrs.empty? and rr_type != 'CNAME'
              rrs = scenario.records_for_domain(domain, 'CNAME')
            end
            if rrs.empty?
              rcode = 'NXDOMAIN'
            elsif rrs[0] == 'TIMEOUT'
              return 'query timed out'
            end
            [rcode, nil, rrs]
          },
          default_authority_explanation: 'DEFAULT',
          max_void_dns_lookups:           nil # Be RFC 4408 compliant during testing!
        )
      )
  
      scenario.test_cases.each do |test_case|
        test_base_name = sprintf("Test case '%s'", test_case.name)
  
        if ((test_case_override = test_case_overrides[test_case.name]) != nil)
          if test_case_override =~ /^SKIP(?:: (.*))/
            puts "Skipping test '#{test_case.name}' due to override" + ($1 ? " #{$1}" : "")
            next
          end
        end
  
        request = SPF::Request.new(
          scope:         test_case.scope,
          identity:      test_case.identity,
          ip_address:    test_case.ip_address,
          helo_identity: test_case.helo_identity
        )
        result = server.process(request)
        overall_ok = true
        result_is_ok = test_case.is_expected_result(result.code)
        if not result_is_ok
          puts "#{test_base_name}:\n" + \
               "Expected: " + test_case.expected_results.join(' or ') + "\n" + \
               "     Got: " + "'#{result.code}'"
             end
        overall_ok &&= result_is_ok
        if not result.is_code('fail')
          print "#{test_base_name} explanation not applicable"
        elsif not test_case['expected_explanation']
          print "#{test_base_name} explanation not relevant"
        else
          overall_ok &&= (
            result.authority_explanation.downcase == 
            test_case['expected_explanation'].downcase
          )
        end
        if not overall_ok and test_case['description']
          puts "Test case description: " + test_case['description']
        end
      end
    end
  end
end
