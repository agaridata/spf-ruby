require 'spf/version'
require 'spf/error'
require 'spf/model'
require 'spf/request'
require 'spf/eval'
require 'spf/macro_string'
require 'spf/util'

#
# == SPF - An object-oriented implementation of Sender Policy Framework
#
# == SYNOPSIS
#
# <tt>
# 
# require 'spf'
#
# spf_server = SPF::Server.new
#
# request    = SPF::Request.new({
#   :versions       => [1, 2],              # optional
#   :scope          => 'mfrom',             # or 'helo', 'pra'
#   :identity       => 'fred@example.com',
#   :ip_address     => '192.168.0.1',
#   :helo_identity  => 'mta.example.com'    # optional,
#                                           # for %{h} macro expansion
# })
#
# result     = spf_server.process(request)
# puts result
# result_code      = result.code
# local_exp        = result.local_explanation
# authority_exp    = result.authority_explanation
#   if result.is_code(:fail)
# spf_header       = result.received_spf_header
#
# </tt>
#
# == DESCRIPTION
#
# <b>SPF</b> is an object-oriented implementation of Sender Policy Framework
# (SPF).  See http://www.openspf.org for more information about SPF.
#
# This class collection aims to fully conform to the SPF specification (RFC
# 4408 so as to serve both as a production quality SPF implementation and as a
# reference for other developers of SPF implementations.
#
#
# vim:sw=2 sts=2
