# encoding: ASCII-8BIT
module SPF

  # Generic Exceptions
  ##############################################################################

  class Error                           < StandardError;            end
    class OptionRequiredError             < Error;                  end  # Missing required method option
                                                                         # XXX Replace with ArgumentError?
    class InvalidOptionValueError         < Error;                  end  # Invalid value for method option
                                                                         # XXX Replace with ArgumentError!

  # Miscellaneous Errors
  ##############################################################################

    class DNSError                        < Error;                  end  # DNS error
      class DNSTimeoutError                 < DNSError;             end  # DNS timeout
      class DNSNXDomainError                < DNSError;             end  # DNS NXDomain
    class RecordSelectionError            < Error                        # Record selection error
      attr_accessor :records
      def initialize(message, records=[])
        @records = records
        super(message)
      end
    end
      class NoAcceptableRecordError         < RecordSelectionError; end  # No acceptable record found
      class RedundantAcceptableRecordsError < RecordSelectionError; end  # Redundant acceptable records found
    class NoUnparsedTextError             < Error;                  end  # No unparsed text available
    class UnexpectedTermObjectError       < Error;                  end  # Unexpected term object encountered
    class ProcessingLimitExceededError    < Error;                  end  # Processing limit exceeded
    class MacroExpansionCtxRequiredError    < OptionRequiredError;  end  # Missing required context for macro expansion

  # Parser Errors
  ##############################################################################

    class NothingToParseError             < Error;                  end  # Nothing to parse
    class SyntaxError                     < Error                        # Generic syntax error
      attr_accessor :text, :parse_text, :domain, :hint
      def initialize(message, text=nil, parse_text=nil, hint=nil)
        @text = text
        @parse_text = parse_text
        @hint = hint
        super(message)
      end
    end
      
      class InvalidRecordVersionError       < SyntaxError;          end  # Invalid record version
      class InvalidScopeError               < SyntaxError;          end  # Invalid scope
      class JunkInRecordError               < SyntaxError;          end  # Junk encountered in record
      class InvalidModError                 < SyntaxError;          end  # Invalid modifier
      class InvalidTermError                < SyntaxError;          end  # Invalid term
      class JunkInTermError                 < SyntaxError;          end  # Junk encountered in term
      class DuplicateGlobalModError           < InvalidModError;    end  # Duplicate global modifier
      class InvalidMechError                  < InvalidTermError;   end  # Invalid mechanism
      class InvalidMechQualifierError         < InvalidMechError;   end  # Invalid mechanism qualifier
      class InvalidMechCIDRError              < InvalidMechError;   end  # Invalid CIDR netblock in mech
      class TermDomainSpecExpectedError     < SyntaxError;          end  # Missing required <domain-spec> in term
      class TermIPv4AddressExpectedError    < SyntaxError;          end  # Missing required <ip4-network> in term
      class TermIPv4PrefixLengthExpectedError < SyntaxError;        end  # Missing required <ip4-cidr-length> in term
      class TermIPv6AddressExpectedError    < SyntaxError;          end  # Missing required <ip6-network> in term
      class TermIPv6PrefixLengthExpectedError < SyntaxError;        end  # Missing required <ip6-cidr-length> in term
      class InvalidMacroStringError         < SyntaxError;          end  # Invalid macro string
      class InvalidMacroError                 < InvalidMacroStringError
                                                                    end  # Invalid macro

end

# vim:sw=2 sts=2
