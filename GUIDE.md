# go-passwordless Guide

## Overview

The Passwordless flow is based on a similar principle to one-time passwords. It goes something like the following:

1. Your site prompts user for authentication method (e.g. sms, email, drone...).
2. User enters a 'recipient' string (e.g. telephone number, email address, lat/lon...)
3. A secure token/PIN is generated, stored, and sent to the recipient.
5. When the user receives the token, they enter it back into your site.
6. The token entered is checked against the one stored; if it's the same, the user is granted access.

This implementation of Passwordless provides patterns and implementations for the backend services to implement this flow. Presentation, storage and user management are left to you.

## Getting Started

### 1. Get and import
Install the library with `go get`:

    $ go get github.com/johnsto/go-passwordless/v2

The base library includes implementations for both memory and cookie-based token stores (`MemStore` and `CookieStore`, respectively), as well as an email transport (`SMTPTransport`) and token generators (`PINGenerator` and `CrockfordGenerator`).

Import the library thus:

    import "github.com/johnsto/go-passwordless/v2"

This will import the base functionality under the `passwordless` namespace.

### 2. Configure
Create an instance of Passwordless with your chosen token store. In this case, `MemStore` will hold tokens in memory until they expire.

    pw = passwordless.New(passwordless.NewMemStore())

> If you have different storage requirements, the `Store` interface is very simple and can be used to provide a custom implementation.

Then add a transport strategy that describes how to send a token to the user. In this case we're using the `LogTransport` which simply writes the token to the console for testing purposes. It will be registered under the name "log".
    
    pw.SetTransport("log", passwordless.LogTransport{
        MessageFunc: func(token, uid string) string {
            return fmt.Sprintf("Your PIN is %s", token)
        },
    }, passwordless.NewCrockfordGenerator(8), 30*time.Minute)

A production system might want to let a user authenticate via email and SMS, whereby the code might look like this instead:

    pw.SetTransport("email", emailTransport, passwordless.NewCrockfordGenerator(32), 30*time.Minute)
    pw.SetTransport("sms", smsTransport, passwordless.NewPINGenerator(8), 30*time.Minute)

Each transport must specify a generator for tokens, and how long generated tokens will remain valid for. Different transports might suit different generators - for example, when using SMS, you might want to keep the token relatively short to make sign in easier. For email however, the user is likely to be emailed a link they just have to click on and therefore the token can be much longer. Of course, the longer a token is, the harder it is to guess, and therefore is more resilient to brute-force attacks.

> The `CrockfordGenerator` used here is a token generator that produces random strings using [Douglas Crockford's 32-character dictionary](https://en.wikipedia.org/wiki/Base32#Crockford.27s_Base32), and is ideal in cases where human transcription errors can occur. A `Sanitize` function converts user input back into the correct alphabet and case such that token verification can occur.
> 
> Creating a custom token generator is as simple as implementing the `TokenGenerator` interface, which consists of just two functions.

### 3. Route
There are typically two routes requires to sign-in:

* **/signin** - lets the user choose and enter a means to contact them (e.g. an email address)
* **/token** - allows the user to enter the code they have received, and verifies it. Also used as a link included in emails to automatically verify a provided token.

The example application names these two routes `/account/signin` and `/account/token`, but the library does not mandate any particular naming scheme.

This library does _not_ provide implementations for these routes (besides the examples), as every site has slightly different requirements.

### 3.1 Signin endpoint
The only call this route makes to Passwordless is to `passwordless.ListTransports`, which will return a list strategies to display to the user.

The page can then display a form whereby the user can enter their email address. If you have multiple auth methods - for example email and SMS - it presents two forms, and the user can choose the one they prefer. The form POST's to the token endpoint, below.

### 3.2 Token endpoint
This route can both generates and verifies tokens, depending on whether the request contains a token to verify.

In the 'generate' case (i.e. when a token is not provided in the request, as is the case when coming from the signin endpoint), the code must call `passwordless.RequestToken` with the appropriate form values provided the 'signin' route - namely the delivery strategy (e.g. `"email"`, a recipient value entered by the user from the 'signin' page (e.g. an email address), and a user ID string for the recipient (e.g. a UUID or database ID, depending on your backend.)

    strategy := r.FormValue("strategy")
    recipient := r.FormValue("recipient")
    user := Users.Find(recipient)
    err := pw.RequestToken(ctx, strategy, user.ID, recipient)

> Typically the email will contain a link directly to the /token endpoint containing the token, so one click is all it needs for the user to be signed in.

The page should inform the user that a token has been generated and sent to their specified address, and display a form that the user can enter the token into.

When the user enters their token, it can POST back onto itself, this time containing the entered token and the user's UID. The token can then be verified:

    token := r.FormValue("token")
    uid := r.FormValue("uid")
    valid, err := pw.VerifyToken(ctx, uid, token)

If `valid` is `true`, the user can be considered authenticated and the login process is complete. At this point, you may want to set a secure session cookie to keep the user logged in.

> The lower the cardinality of the generated token, the more susceptible the token endpoint is to brute-force guessing. It is advisable to use a rate-limiting handler like [gopkg.in/throttled/throttled.v2](gopkg.in/throttled/throttled.v2) to limit the number of requests clients can make. Throttling is also advisable to prevent the spamming of recipients with tokens.

