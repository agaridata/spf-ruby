module SPF

  # Generic Exceptions
  ##############################################################################

  class Error < Exception; end

  # Missing required method option:
  class OptionRequiredError < Error; end

  # Invalid value for method option:
  class InvalidOptionValueError < Error; end

  # Miscellaneous Errors
  ##############################################################################

  # DNS error:
  class DNSError < Error; end

  # DNS timeout:
  class DNSTimeoutError < DNSError; end

  # Record selection error:
  class RecordSelectionError < Error; end
  
  # No acceptable record found:
  class NoAcceptableRecordError < RecordSelectionError; end

  # Redundant acceptable records found:
  class RedundantAcceptableRecordsError < RecordSelectionError; end
  
  # No unparsed text available:
  class NoUnparsedTextError < Error; end
  
  # Unexpected term object encountered:
  class UnexpectedTermObjectError < Error; end

  # Processing limit exceeded:
  class ProcessingLimitExceededError < Error; end

  # Missing required context for macro expansion:
  class MacroExpansionCtxRequiredError < OptionRequiredError; end

  # Parser Errors
  ##############################################################################
  
  # Nothing to parse:
  class NothingToParseError < Error; end

  # Generic syntax error:
  class SyntaxError < Error; end

  # Invalid record version:
  class InvalidRecordVersionError < SyntaxError; end

  # Invalid scope:
  class InvalidScopeError < SyntaxError; end


  # Junk encountered in record:
  class JunkInRecordError < SyntaxError; end

  # Invalid modifier:
  class InvalidModError < SyntaxError; end

  # Invalid term:
  class InvalidTermError < SyntaxError; end

  # Junk encountered in term:
  class JunkInTermError < SyntaxError; end

  # Duplicate global modifier:
  class DuplicateGlobalMod < InvalidModError; end

  # Invalid mechanism:
  class InvalidMechError < InvalidTermError; end

  # Invalid mechanism qualifier:
  class InvalidMechQualifierError < InvalidMechError; end

  # Missing required <domain-spec> in term:
  class TermDomainSpecExpectedError < SyntaxError; end
  
  # Missing required <ip4-network> in term:
  class TermIPv4AddressExpectedError < SyntaxError; end

  # Missing required <ip4-cidr-length> in term:
  class TermIPv4PrefixLengthExpected < SyntaxError; end

  # Missing required <ip6-network> in term:
  class TermIPv6AddressExpected < SyntaxError; end
  
  # Missing required <ip6-cidr-length> in term:
  class TermIPv6PrefixLengthExpected < SyntaxError; end

  # Invalid macro string:
  class InvalidMacroStringError < SyntaxError; end
  
  # Invalid macro:
  class InvalidMacroError < InvalidMacroStringError; end

end

# vim:sw=2 sts=2
