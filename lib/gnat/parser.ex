defmodule Gnat.Parser do
  require Logger

  # states: waiting, reading_message
  defstruct [
    partial: "",
    state: :waiting,
  ]

  defmodule Info do
    defstruct [:auth_required, :host, :port, :max_payload, :server_id, :ssl_required, :tls_required, :tls_verify, :version]
  end

  def new, do: %Gnat.Parser{}

  def parse(parser, data) do
    data = parser.partial <> data
    parser = %{parser | partial: ""}
    parse(parser, data, [])
  end

  def parse(parser, "", parsed), do: {parser, Enum.reverse(parsed)}
  def parse(parser, bytes, parsed) do
    case  :binary.match(bytes, "\r\n") do
      {index, 2} ->
        {command, "\r\n"<>rest} = String.split_at(bytes, index)
        case parse_command(command, rest) do
          :partial_message ->
            parser = %{parser | partial: bytes}
            parse(parser, "", parsed)
          {:ok, rest} ->
            # Ignore +OK messages.
            parse(parser, rest, parsed)
          {message, rest} ->
            parse(parser, rest, [message | parsed])
        end
      :nomatch ->
        parse(%{parser | partial: bytes}, "", parsed)
    end
  end

  defp parse_command(command, body) do
    [operation | details] = String.split(command)
    operation
    |> String.upcase
    |> parse_command(details, body)
  end

  defp parse_command("+OK", _, body), do: {:ok, body}
  defp parse_command("INFO", [payload], body) do
    case Poison.decode(payload, as: %Info{}) do
      {:error, reason} -> {{:error, reason}, body}
      {:ok, info_map} -> {{:info, info_map}, body}
    end
  end
  defp parse_command("PING", _, body), do: {:ping, body}
  defp parse_command("MSG", [topic, sidstr, sizestr], body), do: parse_command("MSG", [topic, sidstr, nil, sizestr], body)
  defp parse_command("MSG", [topic, sidstr, reply_to, sizestr], body) do
    sid = String.to_integer(sidstr)
    bytesize = String.to_integer(sizestr)
    if byte_size(body) >= (bytesize + 2) do
      << message :: binary-size(bytesize), "\r\n", rest :: binary >> = body
      {{:msg, topic, sid, reply_to, message}, rest}
    else
      :partial_message
    end
  end
end
