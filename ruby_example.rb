require 'cgi'
require 'securerandom'
require 'uri'
require 'base64'
require 'json'
require 'openssl'

module LookerEmbedClient
  def self.created_signed_embed_url(options)
    # looker options
    secret = options[:secret]
    host = options[:host]

    # user options
    json_external_user_id   = options[:external_user_id].to_json
    json_first_name         = options[:first_name].to_json
    json_last_name          = options[:last_name].to_json
    json_permissions        = options[:permissions].to_json
    json_models             = options[:models].to_json
    json_access_filters     = options[:access_filters].to_json

    # url/session specific options
    embed_path              = '/login/embed/' + CGI.escape(options[:embed_url])
    json_session_length     = options[:session_length].to_json
    json_force_logout_login = options[:force_logout_login].to_json

    # computed options
    json_time               = Time.now.to_i.to_json
    json_nonce              = SecureRandom.hex(16).to_json

    # compute signature
    string_to_sign  = [host, embed_path, json_nonce, json_time,
                       json_session_length, json_external_user_id, json_permissions,
                       json_models, json_access_filters].join("\n")

    signature = Base64.encode64(
                   OpenSSL::HMAC.digest(
                      OpenSSL::Digest.new('sha1'),
                      secret,
                      string_to_sign.force_encoding("utf-8"))).strip

    # construct query string
    query_params = {
      nonce:               json_nonce,
      time:                json_time,
      session_length:      json_session_length,
      external_user_id:    json_external_user_id,
      permissions:         json_permissions,
      models:              json_models,
      access_filters:      json_access_filters,
      first_name:          json_first_name,
      last_name:           json_last_name,
      force_logout_login:  json_force_logout_login,
      signature:           signature
    }
    query_string = URI.encode_www_form(query_params)

    "#{host}#{embed_path}?#{query_string}"
  end
end

def sample
  fifteen_minutes = 15 * 60

  url_data = {
               host:               'localhost:9999',
               secret:             'f7f48d6d13d195bec62f625045b26f4a2f4b2a8199fa1e6370f3935f5f519d3c',
               external_user_id:   '57',
               first_name:         'Embed Steve',
               last_name:          'Krouse',
               permissions:        ['see_user_dashboards', 'see_lookml_dashboards', 'access_data', 'see_looks'],
               models:             ['wilg_thelook'],
               access_filters:     {:fake_model => {:id => 1}},
               session_length:     fifteen_minutes,
               embed_url:          "/embed/sso/dashboards/1",
               force_logout_login: true
             }

  url = LookerEmbedClient::created_signed_embed_url(url_data)
  puts "https://#{url}"
end
