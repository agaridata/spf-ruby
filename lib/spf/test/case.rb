require 'spf/test'

module SPF::Test
class SPF::Test::Case

  attr_accessor :name, :description, :comment, :spec_refs, :scope, :identity,
                :ip_address, :helo_identity, :expected_results,
                :expected_explanation
  def initialize(options)
    @scope = options[:scope] || 'mfrom'
    @name = options[:name]
    @description = options[:description]
    @comment = options[:comment]
    @spec_refs = options[:spec]
    @identity = options[:identity]
    @ip_address = options[:host]
    @helo_identity = options[:helo]
    @expected_results = options[:expected_results]
    @expected_explanation = options[:expected_explanation]

  end

  def self.new_from_yaml_struct(yaml_struct)
    scope = yaml_struct['scope'] || yaml_struct['mailfrom'] ? 'mfrom' : 'helo'
    obj = self.new(
      name:                 yaml_struct['name'],
      description:          yaml_struct['description'],
      comment:              yaml_struct['comment'],
      spec_refs:            yaml_struct['spec'],
      scope:                scope,
      identity:             yaml_struct['identity'],
      ip_address:           yaml_struct['host'],
      helo_identity:        yaml_struct['helo'],
      expected_results:     yaml_struct['result'],
      expected_explanation: yaml_struct['explanation']
    )
    if obj.scope == 'helo'
      obj.identity ||= yaml_struct['helo']
    elsif obj.scope == 'mfrom'
      obj.identity ||= yaml_struct['mailfrom']
    end
    return obj
  end

  def is_expected_result(result_code)
    return expected_results.has_key?(result_code)
  end
end
end