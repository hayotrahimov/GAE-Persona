GAE-Persona
-----

GAE-Persona is a Google App Engine sample app showing one way to use Mozilla Persona for sign-in.  It uses Python 2.7, Twitter Bootstrap, NDB, Webapp2, and Django templates.

For details on Mozilla Persona, see: [http://www.mozilla.org/en-US/persona/](http://www.mozilla.org/en-US/persona/)

A direct link to the developer page: [https://developer.mozilla.org/en-US/docs/Persona](https://developer.mozilla.org/en-US/docs/Persona)

#### License

MIT License.

#### Lots of Room For Improvement

**Webapp2 Auth**

I didn't have time to look into integrating Persona directly into Webapp2 Auth.  Someone has probably already done this or is working on it.

**Site name and logo in signin box**

If SSL is used (this sample does not) then you can add a website name and logo to the Persona login box.
[http://identity.mozilla.com/post/27122712140/new-feature-adding-your-websites-name-and-logo-to-the](http://identity.mozilla.com/post/27122712140/new-feature-adding-your-websites-name-and-logo-to-the)

#### Tips

This is very important, from the Quick Setup:
>You must call this function on every page with a login or logout button. To support Persona enhancements like automatic login and global logout for your users, you should call this function on every page of your site.

>Persona will compare the email address you've passed into loggedInUser with its own knowledge of whether a user is currently logged in, and who they are. If these don't match, it may automatically invoke onlogin or onlogout on page load.

Pay attention to this as well, also from the Quick Setup:
> A user has logged out! Here you need to:
> Tear down the user's session by redirecting the user or making a call to your backend.
> Also, make sure loggedInUser will get set to null on the next page load.
> (That's a literal JavaScript null. Not false, 0, or undefined. null.)

#### Caveat Emptor

Your mileage may vary.