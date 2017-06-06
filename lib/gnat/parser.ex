defmodule Gnat.Parser do
  require Logger
  # states: waiting, reading_message
  defstruct [
    partial: "",
    state: :waiting,
  ]

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
        [command, rest] = :binary.split(bytes, "\r\n")
        #{command, "\r\n"<>rest} = String.split_at(bytes, index)
        case parse_command(command, rest) do
          :partial_message ->
            parser = %{parser | partial: bytes}
            parse(parser, "", parsed)
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

  defp parse_command("PING", _, body), do: {:ping, body}
  defp parse_command("PONG", _, body), do: {:pong, body}
  defp parse_command("+OK", _, _), do: {:verbose_ok, ""}
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
  defp parse_command("INFO", options, body) do
    {{:info, Poison.Parser.parse!(options, keys: :atoms)}, body}
  end
  defp parse_command("-ERR", options, body) do
    {{:error, Enum.join(options, " ")},body}
  end
end
