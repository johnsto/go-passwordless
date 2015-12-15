go-passwordless
===============

**`go-passwordless` is an implementation of backend services allowing users to sign in to websites without a password, inspired by the [Node package of the same name](passwordless.net).**

## Overview
The passwordless flow is very similar to the one-time-password (OTP) flow used for verification on many services. It works on the principle that if someone can prove ownership of an account such as an email address, then that is sufficient to prove they are that user. So, rather than storing passwords, the user is simply required to enter a code sent to their account (be it email or SMS, or some other means.)

This implementation concerns itself with generating codes, sending them to the user, storing them securely, and offering a means to verify the provided token.

## Transports
A transport provides a means to transmit a token (e.g. a PIN) to the user. There is one production implementation and one development implementation provided with this library:

* *SMTPTransport* - sends tokens via email.
* *LogTransport* - prints tokens to stdout, for testing purposes only.

Custom transports must adhere to the *Transport* interface, which consists of just one function, making it easy to hook into third-party services (for example, your SMS provider.)

## Token Stores
A Token Store provides a mean to securely store and verify a token against user input. There are two implementations provided with this library:

* *MemStore* - stores tokens in ephemeral memory.
* *CookieStore* - stores tokens in encrypted session cookies. Mandates that the user signs in on the same device that they generated the sign in request from.

Custom stores need to adhere to the *TokenStore* interface, which consists of 4 functions. This interface is intentionally simple to allow for easy integration with whatever database and structure you prefer.

## Differences to Node's Passwordless
While heavily inspired by [Passwordless](passwordless.net), this implementation is unique and cannot be used interchangeably. The token generation, storage and verification procedures are different.

Since all websites are different, this implementation does not provide a frontend/UI implementation. An example website is provided as reference, however.
