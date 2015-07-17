require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe 'basic instantiation' do
  result = SPF::Result.new(['dummy server', 'dummy request', 'result text'])
  it 'creates basic result server' do
    expect(result.server).to eq 'dummy server'
  end
  it 'creates basic result request' do
    expect(result.request).to eq 'dummy request'
  end
  it 'creates basic result text' do
    expect(result.result_text).to eq 'result text'
  end
end

describe 'isa_by_name' do
  result = SPF::Result::Pass.new(['dummy server', 'dummy request'])
  it 'should be a pass object' do
    expect(result.isa_by_name('PaSs')).to be true
  end
  it 'should not be a foo object' do
    expect(result.isa_by_name('foo')).to be false
  end
end

describe 'is_code' do
  result = SPF::Result::Pass.new(['dummy server', 'dummy request'])
  it 'should be a pass object' do
    expect(result.is_code('PaSs')).to be true
  end
  it 'should not be a foo object' do
    expect(result.is_code('foo')).to be false
  end
end

describe 'NeutralByDefault' do
  result = SPF::Result::NeutralByDefault.new(['dummy server', 'dummy request'])
  it 'should have neutral result code' do
    expect(result.code).to eq :neutral
  end
  it 'should be a neutral-by-default' do
    expect(result.isa_by_name('neutral_by_default')).to be true
  end
  it 'should be a neutral' do
    expect(result.isa_by_name('neutral')).to be true
  end
end