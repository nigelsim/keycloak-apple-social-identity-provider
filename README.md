# Apple Social Identity Provider for Keycloak

An extension to [Keycloak](https://www.keycloak.org/) that provides support for [Sign in with Apple](https://developer.apple.com/sign-in-with-apple/).

Sign in with Apple follows the [OIDC](https://openid.net/) standard but uses some unusual parts of the protocol which are not implemented yet in Keycloak. Those specificities are:
* Apple sends the Authentication Response as a POST request if scopes were requested;
* User data (email, first name and last name) is received in the body of the authentication response—there is no Userinfo endpoint;
* User data is provided only the first time the user authorizes the client on his Apple account;
* The Token Request must be authentified by a JWT token signed by a specific private key.

The present extension addresses all these requirements.

## Installation

1. Download the latest release of the provider JAR file [here](https://github.com/BenjaminFavre/keycloak-apple-social-identity-provider/releases).
1. Install the provider JAR file following Keycloak instructions [there](https://www.keycloak.org/docs/latest/server_development/index.html#using-the-keycloak-deployer).

## Configuration

In Keycloak admin console:
1. Add an identity provider and select *Apple*.
1. Fill *Client secret* with the base 64 content of your private key file (trim delimiters and new lines).

   e.g., if your private key is:
   
       -----BEGIN PRIVATE KEY-----
       Rp6vMlHPYTHnyucsPvFk8gTzdYtTueMbmVznAtkUKhD9HPcI3bLKDrr0b2mNJLfS
       tsyvhbpyMUIpaffKQcY7IUuM20ecYBjiyjkLuX5eDQUInWUINfCCyXQnNdSU4K1j
       2z4IJrvacQz1PFrL0Tj4lt72jSxikzMBHWsGdFyT90bx0R26GR4YCudKxltozVrK
       PsUC1cdy
       -----END PRIVATE KEY-----
   
   then you should set *Client secret* with:
   
       Rp6vMlHPYTHnyucsPvFk8gTzdYtTueMbmVznAtkUKhD9HPcI3bLKDrr0b2mNJLfStsyvhbpyMUIpaffKQcY7IUuM20ecYBjiyjkLuX5eDQUInWUINfCCyXQnNdSU4K1j2z4IJrvacQz1PFrL0Tj4lt72jSxikzMBHWsGdFyT90bx0R26GR4YCudKxltozVrKPsUC1cdy

1. Fill *Team ID* and *Key ID* with corresponding values found in Apple Developer console.
1. Set Default Scopes to 'openid%20name%20email' to retrieve email, firstname and lastname from apple.

## Theming

The [Apple Human Interface Guidelines](https://developer.apple.com/design/human-interface-guidelines/sign-in-with-apple/overview/buttons/) are quite strict about how the *Sign in with Apple* button looks. This includes:

1. Words: *Sign in with Apple*, *Sign up with Apple*, and *Continue with Apple* are the only valid options
2. The colour must be black on white, or white on black
3. The logo must be of an appropriate size

To achieve this:

1. We've added the *Display name* to the provider, and we use *Continue with Apple* to capture the sign up and sign in flows (config required in admin). **We now just insert the title text using the template for consistency between all social logins**
2. In `theme.properties` for your instance add `kcFormSocialAccountListButtonClass=pf-c-button pf-m-control pf-m-block kc-social-item kc-social-black` and `kcCommonLogoIdP=kc-social-provider-logo kc-social-black` and add a `kc-social-black` style to your custom CSS file  
3. In `theme.properties` for your instance add `kcLogoIdP-apple=fa fa-apple` to set the classes on the signup button to show the logo via Font Awesome

This has not yet been approved by Apple, but is closer than the out of the box.
