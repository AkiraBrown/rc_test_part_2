## Folder Structure

```
root
│
├── client (React frontend)
│ ├── package.json
│ └── node_modules
│
├── server (Node.js backend)
│ ├── package.json
│ └── node_modules
│
└── package.json (root)
```

## How to Run This Application (At the ROOT of the FOLDER)

Follow these steps:

1. Install dependencies for the client and server:

```
   npm run install:client
   npm run install:server
```

2. In the server folder create a `.env` file. Inside the .env file three variables are needed

```
SECRET_KEY= <Create a Secret key here>
USER_PASSWORD= <Create a password for our user>
PORT=3001
```

3. Start the application:

```
   npm run start
```

Once running, both the client and server will be available:

Visit http://localhost:3000 to see the React app.\
Visit http://localhost:3001/testing to view the server app.\

Your task: Secure the application and make sure the JWT token is working as intended for both Frontend and backend.

Please refer to the documentation here
[Click here for the project explanation](https://docs.google.com/document/d/1O0_NXUNg1DCVsgmcZxPbaTT08gDkOI6q_6iVAACAjq4/edit?usp=sharing)

If you have any questions, please slack me or email me at pak@pursuit.org

## Securing Against JWT Auth Vulnerabilities

### Problem

JWT tokens are a popular method for authentication and authorization between a server and a client. However if not properly secured by the server it can allow attackers to forge their own authorized server request and acquire sensitive information.

### how does JWT Tokens work

JWT tokens work by creating three separate components. These components are:

- Header
- Payload
- Signature

The header comprises of the hashing algorithm to be used in the signing of the token and the other is the type of token it is. In this case it's a JWT token.

```JSON
{
   "alg": "HS256",
   "typ": "JWT"
}
```

The next part of the token is called the `payload`. The payload contains the information about the user that the the client can use to interact with the application. This can include, user_id, email and etc. This information is referred to claims. Claims have three categories:

- Registered Claims: Predetermined claims that contain information such as expiration (exp), issuer (iss) and etc.
- Private Claims: custom claims that exchange information between the client and the server.
- Public Claims: Claims that can be defined at will by who's using the token.

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

The last part of the payload is the signature. The signature requires the base64 encoded header, the encoded payload and a secret in order to create the signature. This signature is hashed; traditionally with SHA256 but can be hashed with any other algorithm e.g SHA384, SHA512. With all 3 parts, they are put together to make a JWT Token. This token is what we use for authenticating a user but also authorizing a user to carry out a request.

### Hashing?

Hashing is a one way method that shifts/scrambles a series of characters a number of times. As mentioned Hashing is only one way so you can't "Un-hash" a hashed string however it doesn't make it impervious to being discovered. This process is called cracking.

Cracking is when you take all possible english (interchangeable with target language) characters and re-hash those characters until it matches the same hashed string we have on hand. Attackers may use tools such as [HashCat](https://hashcat.net/hashcat/) in order to crack hashes but another key component is required to run these calculations continuously. This component is called a GPU(Graphical Processing Unit). Other than rendering out visual outputs and training AI models, GPU's are also very effective at running mathematical calculations.

### So how do we protect against this?

1. Password/Secret Complexity: Ever wonder why every site you signup to asks for a password that has a minimum length of 8 characters, contains special characters, upper and lowercase letters and has numbers? Simple, it takes longer to crack. The complexity has direct correlation in the [Time-To-Crack](https://www.hivesystems.com/blog/are-your-passwords-in-the-green). For example, if we looked at the Time-To-Crack of a common hashing algorithm like Bcrypt we see that by follow those standard rules for signup it would take a hacker 7 years using 12 of the most powerful graphics cards on the market at the time of writing this. Considering each card cost around $2000 each I'm confident to say there aren't many hacking entities that have that kind of money to throw at cracking passwords.
   ![Bcrypt Time To Crack](https://images.squarespace-cdn.com/content/5ffe234606e5ec7bfc57a7a3/1719499399309-7FRIR5QNH5P4VHC1AGGP/Hive+Systems+Password+Table+-+2024+Rectangular.png?format=1500w&content-type=image%2Fpng)

2. Hashing Algorithm

As previously mentioned in the complexity section, increasing the length and special characters raise the time-to-crack of the password exponentially, but another factor that comes into play is the algorithm used to hash the password/secret. Different algorithms have different time-to-crack and should always be factored in when considering how to hash a secret/password.

_Random Note:_ Considering hackers have to assume that user passwords only comprise of the characters found on an English keyboard, would it make it significantly harder for a password to be cracked if a user uses the emoji keyboard as well in their password complexity?

### Time To Secure (Server)

The first major vulnerability I noticed in the server/app.js was the `secretKey` variable. This variable is what we use to verify tokens and create tokens for users and by hard-coded the value as seen here leaves the secret open to github when push our code.

```javascript
const secretKey = "supersecretKey";
```

To fix this we use install a package called `dotenv`. This package is responsible for getting the environment variables that are stored in the `.env` file and apply them at runtime. Here's what it would look like.

```javascript
require("dotenv").config();
// Other Code ...
const secretKey = process.env.SECRET_KEY;
```

Using dotenv is good practice to hide API keys, secrets and other configurations that is needed for an application to work without exposing it to threat actors. This solution is commonplace amongst smaller productions, however at the enterprise level organizations opt to use secrets managers to add an additional level of security with their application.

Secrets managers are a way to monitor use of secrets and authorization of the secrets. Cloud platforms such as Google Cloud Platform and AWS provide secrets managers so that large organizations can enable developers to use API keys without exposing those keys to just anyone developer. It also makes it easier to revoke access to keys and monitor unauthorized use of keys. We didn't implement this because for this project we're not working with a large team of developers and implementing the system takes considerable work.

The next problem I identified is in the signing of the tokens. When we sign a token, we always provide an expiration time with the token. This is in case the token get's stolen, that token is unlikely to be used to impersonate the user the token was stolen from. This is because the expiration time invalidates the token after a set amount of time from when it's created.

```javascript
const token = jwt.sign({ id: user.id, username: user.username }, secretKey, {
  expiresIn: "3m",
});
res.json({ token });
```

In this code we apply an expiration time of 3 minutes from when the token is created until it's no longer valid.

Even though we don't have a database to store user information we can still secure the hard coded user password on the `users` variable.

```javascript
const users = [{ id: 1, username: "admin", password: "password" }];
```

The issue with this is...

1. There's no complexity in the password
2. Never Hard code a password
3. NEVER store a password in plain text

In this case the last point is contradictory since we're storing it in plain text on an environment variable, however at scale we would have a signup form to create the hashed password and store it within a database. Since we only have one user, there isn't really a need for a whole database to store the one users credentials but in an actual application, if you as the developer is ever able to see the users actual password out of a database then there's a major problem. To implement hashing for passwords we use a package called `bcryptjs`

```javascript
const bcrypt = require("bcryptjs");
//Other code ...
const hashedPassword = bcrypt.hashSync(process.env.USER_PASSWORD, 10);
const users = [{ id: 1, username: "admin", password: hashedPassword }];
```

What's happening in this code is that we're using the password in the `.env` file and hashing it 10 times using bcrypt. We then store it in the users variable for later use when a user is to login.

```javascript
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (user && bcrypt.compareSync(password, user.password)) {
    const token = jwt.sign(
      { id: user.id, username: user.username },
      secretKey,
      { expiresIn: "3m" }
    );
    res.json({ token });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});
```

In this code, when a user is logging in we first locate the user in the database and grab their hashed password. We then check if we found the user at that we were able to get the correct password from the user submission. This is done by hashing the password provided by the user and comparing it against the hashed password we have stored. Once that's done we've authenticated that the user is who they say they are and can send them a valid token.

The next security to implement is token verification on the `/protected` route. For this we'll be using an additional package called `cookie-parser`. The reason for this is so that we can access the cookie object out of the request header and grab the JWT Token to use for verification. This is not mandatory and in actual fact you could use the request authorization header to acquire JWT tokens depending on how you formulate the request to the server.

```js
const cookieParser = require("cookie-parser");
app.use(cookieParser());
//Code...
app.get("/protected", (req, res) => {
  const token = req.cookies.jwtToken;
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Forbidden" });
    }
    res.json({ message: "Welcome to the protected route!", decoded });
  });
});
```

When using cookies, they take in strings, which causes some complications when attempting to take it back out of request headers, so we use `cookie-parser` to turn that request header into an object so that we can access all the cookies appended to the requests as an object. One of the cookies is the JWT Token we sign when the user logged into the app, so we use the `jwt.verify` function to check that the token is the same one we signed for with the `secretKey` we made earlier. That's how we confirm that a user is authorized to access routes on our server.

## Time To Secure (Client)

In the process of reviewing how to secure the client; a key piece of research arose regarding where to store my JWT Token. When I first learned how to do JWT Authentication I used to use the Local storage api to store Tokens which is actually a bad practice. This is because local storage has significantly less security features compared to cookies. Unlike local storage, cookies:

- Sent with each request
- Expiration time can be set
- Shared Between Subdomains
- Can be Encrypted
- **Must be sent over HTTPS protocol** [Link](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security)

The last point is the most important to the security of the frontend. A cookie with the `HttpOnly` attribute can only be sent across the https protocol which protects it from man-in-the-middle attacks. To do this we use `js-cookie` to set cookies when the server signs the token and `jwt-decode` to decode the token we only need to do it for the expiration time so that when we store the token in cookies we use the expiration time.

```js
const response = await axios.post("http://localhost:3001/login", {
  username,
  password,
});
setMessage(`Success! Jwt token => ${response.data.token}`);
Cookie.set("jwtToken", response.data.token, {
  secure: true,
  expires: jwtDecode(response.data.token).exp,
  sameSite: "Strict",
});
```

We are taking the response and setting a cookie called jwtToken. Unlike local storage, cookies take in a string and can be secured by enforcing it to be only sent with https requests at production. This is done by setting the secure option to `true` and also setting the expiration time of the cookie so that it becomes invalid after 3 minutes. This protects in the event that the cookie is stolen and an attacker wanted to use the cookie to send forged authorized requests.

```js
<label>Username:</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            pattern="[A-Za-z0-9\s]+"
            required
          />
        </div>
        <br />
        <div>
          <label>Password:</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={8}
            title="Need a minimum length of 8"
          />
        </div>
```

We also applied a pattern attribute to the username input and a `minlength` of 8 for best practices. The pattern attribute on the username only accepts alphanumeric characters so that users cannot submit malicious code into the input form via username input. However, even if an attacker were to send some malicious code like a SQL injection or code injection, there's no database to interact with.

# Check Tokens (Frontend)

```js
function checkToken() {
  const jwtToken = Cookie.get("jwtToken");
  if (jwtToken) {
    const decodedToken = jwtDecode(jwtToken);
    const currentTime = Date.now() / 1000;
    if (decodedToken.exp < currentTime) {
      Cookie.remove("jwtToken");
      return false;
    } else {
      return true;
    }
  }
}
```

The purpose of this function is to check if there already exists a token in the users' cookies and check if the cookie is expired. If the cookie is expired then we remove the cookie. This ensures that the cookie is removed at expiration time. By running this check we can use it to persist a user's logged in state by returning false or true if the cookie is there.

```js
useEffect(() => {
  if (checkToken()) {
    handleProtected();
  }
}, []);
async function handleProtected() {
  try {
    const response = await axios.get("http://localhost:3001/protected", {
      headers: {
        Authorization: `Bearer ${Cookie.get("jwtToken")}`,
      },
      withCredentials: true,
    });
    setMessage(response.data.message);
  } catch (error) {
    console.log(error);
    setMessage("Bad Token: ", error);
  }
}
```

When paired with a `useEffect` we can automatically send a request to the `/protected` route on our server by using the stored cookie as authorization to access that route.

### But Couldn't an attacker potentially access this route too?

If an attacker was to take a users token and apply it into their cookies, then yes they can. Which is the reason why we've set the expiration time of the cookie for 3 minutes. This is a really short time frame for an attacker to wait for a stolen cookie to reach them and use that cookie to get access to the user's information.

### Sources

- [jsonwebtoken NPM](https://www.npmjs.com/package/jsonwebtoken)
- [OWASP Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [Hashing Algorithms](https://jscrambler.com/blog/hashing-algorithms)
- [Local Storage vs Cookies](https://www.geeksforgeeks.org/local-storage-vs-cookies/)
- [Okta Hashing Algorithms](https://www.okta.com/identity-101/hashing-algorithms/)
- [Auth0 JSON Web Tokens](https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/)
- [PortSwigger Authentication](https://portswigger.net/web-security/authentication)
