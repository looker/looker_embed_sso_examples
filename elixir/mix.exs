defmodule LookerEmbed.Mixfile do
    use Mix.Project

    def project do
      [
        app: :looker_embed,
        version: "0.0.1",
        elixir: "~> 1.5",
        deps: deps()
      ]
  end


    # Configuration for the OTP application.
    #
    # Type `mix help compile.app` for more information.
    def application do
      []
    end

    # Specifies your project dependencies.
    #
    # Type `mix help deps` for examples and options.
    defp deps do
      [
        {:poison, "~> 2.2"},
        {:secure_random, "~> 0.5"},
        {:timex, "~> 3.1"}
      ]
    end
  end
