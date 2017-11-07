defmodule LookerEmbed do
  @moduledoc """
  Module for generating Looker embed SSO URL
  """

  @doc """
  opts[:embed_url]          Looker relative embed url
  opts[:session_length]     The login session lenght (validiy of the SSO URL). Default: 30 mins
  opts[:host]               Looker host
  opts[:secret]             Looker API embed secret
  opts[:user]               A Map of user data (id, first_name, last_name). This will be used to create embed user
  opts[:permissions]        A list of looker permissions the embed user should have
  opts[:models]             A list of looker models that should be accessible by the embed user
  opts[:group_ids]          A list of looker group ids that the embed user should be added
  opts[:external_group_id]  External group id for the embed user
  opts[:user_attributes]    A Map of user filters/attributes that are applicable for the embed user

  """
  def generate_sso_url(%{user: user} = opts) do
    session_length = opts[:session_length] || (30 * 60)
    host = opts.host

    embed_path = "/login/embed/#{URI.encode_www_form(opts.embed_url)}"

    url_options = %{
      host: host,
      secret: opts.secret,
      external_user_id: user.id |> wrap_quotes,
      first_name: user.first_name |> wrap_quotes,
      last_name: user.last_name |> wrap_quotes,
      permissions: opts.permissions,
      models: opts.models,
      group_ids: opts.group_ids,
      external_group_id: opts.external_group_id |> wrap_quotes,
      user_attributes: opts.user_attributes,
      access_filters: %{}, # we pass empty map because looker requires this parameter
      session_length: session_length |> to_string,
      embed_path: embed_path,
      nonce: SecureRandom.urlsafe_base64(16) |> wrap_quotes,
      time: DateTime.utc_now |> DateTime.to_unix |> to_string
    }

    query_string = get_query_string(url_options)

    "https://#{host}#{embed_path}?#{query_string}"
  end

  # private

  defp get_signature(opts) do
    string_data = "#{opts[:host]}\n"
    string_data = string_data <> opts[:embed_path] <> "\n"
    string_data = string_data <> opts[:nonce] <> "\n"
    string_data = string_data <> opts[:time] <> "\n"
    string_data = string_data <> opts[:session_length] <> "\n"
    string_data = string_data <> opts[:external_user_id] <> "\n"
    string_data = string_data <> encode_json(opts[:permissions]) <> "\n"
    string_data = string_data <> encode_json(opts[:models]) <> "\n"

    # attributes supported in new looker api version
    string_data = if is_nil(opts[:group_ids]) do
                    string_data
                  else
                    string_data <> encode_json(opts[:group_ids]) <> "\n"
                  end

    string_data = if is_nil(opts[:external_group_id]) do
                    string_data
                  else
                    string_data <> opts[:external_group_id] <> "\n"
                  end

    string_data = string_data <> encode_json(opts[:user_attributes]) <> "\n"
    string_data = string_data <> encode_json(opts[:access_filters])

    :crypto.hmac(:sha, opts[:secret], string_data)
    |> Base.encode64
  end

  defp get_query_string(opts) do
    params = %{
      nonce: opts.nonce,
      time: opts.time,
      session_length: opts.session_length,
      external_user_id: opts.external_user_id,
      permissions: encode_json(opts.permissions),
      models: encode_json(opts.models),
      access_filters: encode_json(opts.access_filters),
      first_name: opts.first_name,
      last_name: opts.last_name,
      signature: get_signature(opts),
      group_ids: encode_json(opts.group_ids),
      external_group_id: opts.external_group_id,
      user_attributes: encode_json(opts.user_attributes),
      force_logout_login: true
    }

    params |> URI.encode_query
    # Note: URI.encode query does not wrap values of query string in a quote.
    # this creates issues as looker expects string values to be inside quote.
    # For example, a map %{name: "Test"} will be encoded to [name=Taher]
    # but looker wants it to be, [name="Taher"]
    # The wrapping on quotes is already done at source in `generate_sso_url`
  end

  defp encode_json(value) when not is_nil(value) do
    Poison.encode!(value)
  end

  defp encode_json(_), do: ""

  # This is function wraps values inside double quotes.
  # This is required for query string for looker as its very strict in format
  defp wrap_quotes(value), do: "\"#{value}\""
end

options = %{
  embed_url: "/embed/looker_report",
  host: "app.looker.com",
  secret: "mysekret",
  user: %{
    id: 100,
    first_name: "Taher",
    last_name: "Dhilawala"
  },
  permissions: ~w(access_data see_looks)s,
  models: "external",
  group_ids: [1],
  external_group_id: 2,
  user_attributes: []
}

IO.puts LookerEmbed.generate_sso_url(options)
