# DATA Sign Cookbook

This repository gives guidance on integrating *DATA Sign* into your application.

The *DATA Sign Integration Guide* is - next to this repository - a good starting point for developers
to familiarize themselves with the DATA Sign *REST API*. The Integration Guide can be accessed from the Governikus
Portal.

The repository contains examples for electronic signatures using PAdES and CAdES. The examples in the
`pades/` folder demonstrate signing PDF documents. The examples in the `cades/` folder cover singing various file
types (e.g., .docx, .xls, .zip, .png) with separately stored signature files.

The examples here are plain Java code and demonstrate the REST API usage. The examples are implemented
with the following simplifications:

* we make no use of client code generation from our OpenAPI specification document, although it's possible (the OpenAPI
  specification can be access from the Governikus Portal)
* most error handling is omitted

For our to-be-signed and document hash based endpoints your application must perform low level signature operations (e.g. calculating the
DTBS).
For this purpose our examples make use of the European
Union [Digital Signature Service library](https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Digital+Signature+Service+-++DSS).

## Prerequisites

* Java 17
* Maven
* Either access to our publicly hosted DATA Sign test instance (ask your Governikus contact person)
  or your own running DATA Sign and [Keycloak](https://www.keycloak.org/) instance.
* For Signing examples a registered and identified user account of one of the supported providers
* For Sealing examples a server-side configured test seal from one of the supported providers
* A configured `cookbook.properties` file (copy it from `cookbook.properties.template`), see the table below

| cookbook.properties key    | Description                                                                                                                                                                                                    |
|----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| url                        | API url, e.g. `https://api.your-datasign.test/`                                                                                                                                                                |
| keycloak.issuerUri         | The Keycloak realm url, same as server-side configured, e.g. `https://your-keycloak/realms/your-realm`                                                                                                         |
| keycloak.clientId          | The Keycloak Client ID                                                                                                                                                                                         |
| keycloak.clientSecret      | The Keycloak Client Secret                                                                                                                                                                                     |
| example.signProvider       | Your chosen provider, e.g. "Bank-Verlag" `BV` or "D-Trust" `DTRUST`                                                                                                                                            |
| example.sealProvider       | Your chosen provider, e.g. "A-Trust" `ATRUST`, "Bank-Verlag" `BV`, "D-Trust" `DTRUST` or "Smartcards" `SMARTCARDS`                                                                                             |
| example.userId             | ID (e-mail address) of a registered and identified user account of your chosen provider. Only required for signing examples.                                                                                   |
| example.certificateId      | Certificate ID of a stored key. Only required when signing with stored keys.                                                                                                                                   |
| example.sealId             | A server-side configured seal of your chosen provider. Only required for sealing examples.                                                                                                                     |
| example.timestampProvider  | Your chosen timestamp provider, e.g. "A-Trust" `ATRUST`, "Bank-Verlag" `BV`, "D-Trust" `DTRUST`, "Telesec" `TELESEC`. "Utimaco" `UTIMACO` or selfsigned `SELFSIGNED`. Only required for to be signed examples. |
| example.signatureAlgorithm | Signature Algorithm to be used to generate the signature. Only required for to be signed examples.                                                                                                             |

## Run the examples

Each example can be executed on its own (see `main` method).
All IDEs should be able to run the example classes directly.
