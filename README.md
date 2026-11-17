# eet-client

Python client for the Czech EET 2.0 sales registration service
(zákon č. 180/2026 Sb., in force from 1 January 2027).

Neoficiální klient pro EET 2.0 v Pythonu.

## Status

Early development. Nothing is released yet and the API is not settled.

## Scope

The library will do one thing: report a sale.

- build the sale message and validate it against the official schema rules
- sign it with the taxpayer's certificate
- send it to the tax administration's endpoint
- parse the reply and verify its signature

Storing sales, scheduling repeated sends and renewing certificates are left to
the application that uses it.

## Official documentation

The interface description, the XML schema and the test certificates are
published at <https://eet.gov.cz/cs/o-eet/dokumenty-k-eet-2-0>.

## Disclaimer

This is an unofficial project. It is not affiliated with or endorsed by the
Czech Financial Administration (Finanční správa České republiky).

## License

[MIT](LICENSE)
