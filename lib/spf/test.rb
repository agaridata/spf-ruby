require 'yaml'

require 'spf/test/case'
require 'spf/test/scenario'

module SPF::Test
#class SPF::Test::Base

  attr_accessor :scenarios

  def self.new_from_yaml(yaml_text, options={})
    @scenarios = YAML.load_documents(yaml_text).map {|doc| SPF::Test::Scenario.new_from_yaml(doc)}
    return @scenarios
  end

  def self.new_from_yaml_file(file_name, options={})
    return self.new_from_yaml(File.open(file_name, 'r').read)
  end
end

#end

