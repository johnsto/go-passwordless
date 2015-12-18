/*
`go-passwordless` is an implementation of backend services allowing users to sign in to websites without a password, inspired by the [Node package of the same name](passwordless.net).

Install the library with `go get`:

    $ go get github.com/johnsto/go-passwordless

Import the library into your project:

    import "github.com/johnsto/go-passwordless"

Create an instance of Passwordless with your chosen token store. In this case, `MemStore` will hold tokens in memory until they expire.

    pw = passwordless.New(passwordless.NewMemStore())

Then add a transport strategy that describes how to send a token to the user. In this case we're using the `LogTransport` which simply writes the token to the console for testing purposes. It will be registered under the name "log".

    pw.SetTransport("log", passwordless.LogTransport{
        MessageFunc: func(token, uid string) string {
            return fmt.Sprintf("Your PIN is %s", token)
        },
    }, passwordless.NewCrockfordGenerator(8), 30*time.Minute)

When the user wants to sign in, get a list of valid transports with `passwordless.ListTransports`, and display an appropriate form to the user. You can then send a token to the user:

    strategy := r.FormValue("strategy")
    recipient := r.FormValue("recipient")
    user := Users.Find(recipient)
    err := pw.RequestToken(ctx, strategy, user.ID, recipient)

Then prompt the user to enter the token they received:

    token := r.FormValue("token")
    uid := r.FormValue("uid")
    valid, err := pw.VerifyToken(ctx, uid, token)

If `valid` is `true`, the user can be considered authenticated and the login process is complete. At this point, you may want to set a secure session cookie to keep the user logged in.

A complete implementation can be found in the "example" directory.

*/
package passwordless
