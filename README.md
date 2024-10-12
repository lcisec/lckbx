# vault-client


## Tokens
UserToken - A unique identifier for the user.
AuthToken - A derived identifier for the user.


A username is used to find the UserToken in the database. The UserToken is used to the derive the AuthToken which is then used to get the encrypted user data from the database. This creates a cryptographic separation between the username and the encrypted user data.

## Buckets
User Bucket - holds UserTokens keyed on the username.
Auth Bucket - holds encrypted users keyed on the derived AuthToken.