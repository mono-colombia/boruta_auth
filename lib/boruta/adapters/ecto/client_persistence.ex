defmodule Boruta.Ecto.ClientPersistence do
  @moduledoc """
  Behaviour for transforming OAuth client data at the persistence boundary.

  This behaviour allows you to implement custom transformations on client data before it is
  written to the database (`dump/1`) and after it is read from the database (`load/1`).

  ## Common Use Cases

  - **Encryption**: Encrypt sensitive fields like `secret` and `private_key` before storage
  - **Hashing**: Hash credentials for secure storage
  - **Normalization**: Standardize data formats
  - **Obfuscation**: Apply custom obfuscation strategies
  - **Multi-tenancy**: Add tenant-specific transformations

  ## Configuration

  To enable client persistence transformations, configure a module that implements this behaviour:

      # config/config.exs
      config :boruta, Boruta.Oauth,
        client_persistence: MyApp.ClientPersistence

  ## Example Implementation

      defmodule MyApp.ClientPersistence do
        @behaviour Boruta.Ecto.ClientPersistence

        alias Boruta.Ecto.Client

        @impl true
        def dump(changeset) do
          changeset
          |> encrypt_field(:secret)
          |> encrypt_field(:private_key)
        end

        @impl true
        def load(%Client{} = client) do
          %{client |
            secret: decrypt(client.secret),
            private_key: decrypt(client.private_key)
          }
        end

        defp encrypt_field(changeset, field) do
          case Ecto.Changeset.fetch_change(changeset, field) do
            {:ok, value} when is_binary(value) ->
              Ecto.Changeset.put_change(changeset, field, encrypt(value))
            _ ->
              changeset
          end
        end

        defp encrypt(value), do: # ... your encryption logic
        defp decrypt(value), do: # ... your decryption logic
      end

  ## Important Notes

  - **Pure transformations**: Callbacks should be pure functions without side effects
  - **Performance**: These callbacks run on every database read/write operation
  - **Testing**: Ensure transformations work correctly with all OAuth flows

  ## Ecto-specific

  This behaviour works with Ecto changesets and structs. If you replace Ecto with a different
  persistence layer, you would need to implement a different persistence behaviour for that layer.
  """

  alias Boruta.Ecto.Client

  @doc """
  Transform a client changeset before writing to the database.

  This callback is invoked before any client insert or update operation. You can modify the
  changeset to transform sensitive fields (e.g., encrypt `secret`, `private_key`).

  ## Parameters

  - `changeset` - An `Ecto.Changeset.t()` containing the client data to be persisted

  ## Returns

  The modified changeset with transformations applied.

  ## Important

  - Only transform fields that have changed (use `Ecto.Changeset.fetch_change/2`)
  - Preserve changeset validity - don't add errors unless transformation fails
  - Handle nil values appropriately
  """
  @callback dump(changeset :: Ecto.Changeset.t()) :: Ecto.Changeset.t()

  @doc """
  Transform a client struct after reading from the database.

  This callback is invoked after a client is loaded from the database. You can modify the
  struct to reverse transformations applied during `dump/1` (e.g., decrypt `secret`, `private_key`).

  ## Parameters

  - `client` - A `Boruta.Ecto.Client.t()` struct loaded from the database

  ## Returns

  The modified client struct with transformations applied.

  ## Important

  - Handle nil values appropriately
  - Ensure decryption/transformation can handle data from previous versions
  - Consider caching if transformations are expensive, though Boruta already caches the whole
  `Boruta.Oauth.Client` with the transformations
  """
  @callback load(client :: Client.t()) :: Client.t()
end
