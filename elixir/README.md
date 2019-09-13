### Usage

```
$ cd elixir
$ mix deps.get
$ mix deps.compile
$ mix run elixir_example.exs
```

### Options

|*Key*                | *Required* | *Default*      | *Description*                                                                             |
|:--------------------|:-----------|:---------------|-------------------------------------------------------------------------------------------|
| `embed_url`         | Yes        | NA             | Looker relative embed url                                                                 |
| `session_length`    | No         | 1800 (30 mins) | The login session lenght (validiy of the SSO URL). Default: 15 mins                       |
| `host`              | Yes        | NA             | Looker host                                                                               |
| `secret`            | Yes        | NA             | Looker API secret                                                                         |
| `user`              | Yes        | NA             | A Map of user data (id, first_name, last_name). This will be used to create embed user    |
| `permissions`       | No         | NA             | A list of looker permissions the embed user should have                                   |
| `models`            | No         | NA             | A list of looker models that should be accessible by the embed user                       |
| `group_ids`         | No         | NA             | A list of looker group ids that the embed user should be added                            |
| `external_group_id` | No         | NA             | External group id for the embed user                                                      |
| `user_attributes`   | No         | NA             | A Map of user filters/attributes that are applicable for the embed user                   |
