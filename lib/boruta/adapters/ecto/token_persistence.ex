defmodule Boruta.Ecto.TokenPersistence do
  @moduledoc """
  Behaviour for transforming OAuth token data at the persistence boundary.

  This behaviour allows you to implement custom transformations on token data before it is
  written to the database (`dump/1` and `dump/2`) and after it is read from the database (`load/1`).

  Unlike `Boruta.Ecto.ClientPersistence`, this behaviour provides two `dump` callbacks:
  - `dump/2` - For transforming individual token values (e.g., when querying by token value)
  - `dump/1` - For transforming entire token changesets before insert/update

  ## Common Use Cases

  - **Hashing**: Hash token values (`value`, `refresh_token`) for secure storage
  - **Encryption**: Encrypt sensitive token metadata
  - **Normalization**: Standardize token formats
  - **Signing**: Add cryptographic signatures to tokens
  - **Masking**: Apply custom masking strategies

  ## Configuration

  To enable token persistence transformations, configure a module that implements this behaviour:

      # config/config.exs
      config :boruta, Boruta.Oauth,
        token_persistence: MyApp.TokenPersistence

  ## Example Implementation

      defmodule MyApp.TokenPersistence do
        @behaviour Boruta.Ecto.TokenPersistence

        alias Boruta.Ecto.Token

        @impl true
        def dump(value, type) when is_binary(value) do
          # Hash token values for queries
          case type do
            type when type in [:access_token, :refresh_token, :agent_token, :code] ->
              hash(value)
            _ ->
              value
          end
        end

        @impl true
        def dump(changeset) do
          # Hash token fields in changesets before insert/update
          changeset
          |> hash_field(:value)
          |> hash_field(:refresh_token)
        end

        @impl true
        def load(%Token{} = token) do
          # Tokens are typically one-way hashed, so load might just return as-is
          # Or you might decrypt metadata fields
          token
        end

        defp hash(value), do: # ... your hashing logic
        defp hash_field(changeset, field), do: # ... changeset transformation
      end

  ## Token Types

  The `dump/2` callback receives a type atom indicating which token field is being transformed:

  - `:access_token` - OAuth 2.0 access token value
  - `:refresh_token` - OAuth 2.0 refresh token value
  - `:agent_token` - Agent token for decentralized identity flows
  - `:code` - Authorization code value
  - `:preauthorized_code` - Pre-authorized code for credential issuance

  ## Important Notes

  - **One-way hashing**: Token values are typically hashed, not encrypted (can't be reversed)
  - **Query consistency**: `dump/2` must produce the same output as `dump/1` for the same input
  - **Pure transformations**: Callbacks should be pure functions without side effects
  - **Performance**: These callbacks run on every database read/write operation
  - **Testing**: Ensure transformations work correctly with all OAuth flows

  ## Ecto-specific

  This behaviour works with Ecto changesets and structs. If you replace Ecto with a different
  persistence layer, you would need to implement a different persistence behaviour for that layer.
  """

  alias Boruta.Ecto.Token

  @type token_type ::
          :access_token
          | :refresh_token
          | :agent_token
          | :code
          | :preauthorized_code

  @doc """
  Transform an individual token value before using it in database queries.

  This callback is invoked when Boruta needs to query for a token by its value. For example,
  when validating an access token or looking up a refresh token. This is separate from `dump/1`
  to allow transforming query parameters independently.

  ## Parameters

  - `value` - The raw token value string to transform
  - `type` - The type of token being transformed (see `t:token_type/0`)

  ## Returns

  The transformed token value string.

  ## Important

  - Must produce the same output as `dump/1` for consistency
  - Handle edge cases (empty strings, very long values)
  - Consider using the same algorithm for all token types for simplicity
  - This runs on EVERY token lookup, so performance matters
  """
  @callback dump(value :: String.t(), type :: token_type()) :: String.t()

  @doc """
  Transform a token changeset before writing to the database.

  This callback is invoked before any token insert or update operation. You can modify the
  changeset to transform sensitive fields like `value`, `refresh_token`, and others.

  ## Parameters

  - `changeset` - An `Ecto.Changeset.t()` containing the token data to be persisted

  ## Returns

  The modified changeset with transformations applied.

  ## Important

  - Only transform fields that have changed (use `Ecto.Changeset.fetch_change/2`)
  - Must be consistent with `dump/2` - same input should produce same output
  - Preserve changeset validity - don't add errors unless transformation fails
  - Handle nil values appropriately
  - Consider which fields need transformation (value, refresh_token, previous_code, etc.)
  """
  @callback dump(changeset :: Ecto.Changeset.t()) :: Ecto.Changeset.t()

  @doc """
  Transform a token struct after reading from the database.

  This callback is invoked after a token is loaded from the database. For hashed tokens,
  this typically returns the token as-is since hashing is one-way. However, you might use
  this to decrypt metadata or perform other reversible transformations.

  ## Parameters

  - `token` - A `Boruta.Ecto.Token.t()` struct loaded from the database

  ## Returns

  The modified token struct with transformations applied.

  ## Important

  - Hashed fields (like `value`) cannot be reversed - this is intentional
  - Token validation works by hashing the incoming token and comparing with stored hash
  - Only decrypt/transform fields that were encrypted, not hashed
  - Handle nil values appropriately
  - Consider caching if transformations are expensive
  """
  @callback load(token :: Token.t()) :: Token.t()
end
